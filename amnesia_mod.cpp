
#include <cstdio>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <cstdint>
#include <string>
#include <memory>

/*
This injects code which makes Amnesia call cSoundHandler::Stop for every possible flashback dialogue line
which could be playing during a map transition in a speedrun. It passes cSoundHandler::Stop a hardcoded std::string
object which is located at the 64th byte of a virtual page allocated with VirtualAllocEx. The memory layout of std::string
objects in Amnesia is:
bytes 0-16: SSO buffer, or ptr to character array plus 12 leftover bytes if the string is too big for SSO
bytes 16-20: string size
bytes 20-24: string capacity
*/

typedef LONG(__stdcall* NTFUNCTION)(HANDLE);

const wchar_t steamName[] = L"Amnesia.exe";
const wchar_t nosteamName[] = L"Amnesia_NoSteam.exe";
const size_t extraMemorySize = 4096;

class ProcessHelper
{
public:

    std::unique_ptr<unsigned char[]> buffer;
    size_t memoryOffset = 0;
    size_t bytesLeft = 0;
    HANDLE amnesiaHandle = nullptr;
    uint32_t amnesiaMemoryLocation = (uint32_t)-1;
    DWORD pageSize = 0;
    int bufferPosition = 0;

    ProcessHelper(const ProcessHelper& fhelper) = delete;
    ProcessHelper& operator=(ProcessHelper other) = delete;
    ProcessHelper(ProcessHelper&&) = delete;
    ProcessHelper& operator=(ProcessHelper&&) = delete;

    ProcessHelper(DWORD pid)
    {
        amnesiaHandle = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_SUSPEND_RESUME,
            false,
            pid
        );

        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        pageSize = sysInfo.dwPageSize;
        buffer = std::make_unique<unsigned char[]>(pageSize);
        bufferPosition = pageSize; // this initial value lets the first read happen on the first call to getByte
    }

    ~ProcessHelper()
    {
        if (amnesiaHandle != nullptr)
        {
            CloseHandle(amnesiaHandle);
        }
    }

    bool checkIfPathIsToAmnesia(const std::wstring& filepathBuffer)
    {
        // if L'\\' isn't found, filenamePosition will increase from npos to 0
        size_t filenamePosition = filepathBuffer.find_last_of(L'\\') + 1;
        int filenameSize = wcslen(&filepathBuffer[filenamePosition]);

        if ((filenameSize != (sizeof(steamName) / sizeof(wchar_t)) - 1 && filenameSize != (sizeof(nosteamName) / sizeof(wchar_t)) - 1)
            || (wcscmp(&filepathBuffer[filenamePosition], steamName) != 0 && wcscmp(&filepathBuffer[filenamePosition], nosteamName) != 0))
        {
            return false;
        }

        return true;
    }

    bool checkIfProcessIsAmnesia()
    {
        std::wstring filepathBuffer(512 - 1, L'\0'); // - 1 because a character is used for a null terminator on modern implementations

        DWORD queryFullProcessImageNameResult = 0;
        if (amnesiaHandle != nullptr) // this check gets rid of warning C6387
        {
            while (queryFullProcessImageNameResult == 0)
            {
                DWORD filepathBufferSize = filepathBuffer.size() - 1; // - 1 because writing to filepathBuffer.size() position is undefined
                queryFullProcessImageNameResult = QueryFullProcessImageName(amnesiaHandle, 0, &filepathBuffer[0], &filepathBufferSize);
                if (queryFullProcessImageNameResult == 0)
                {
                    DWORD errorNumber = GetLastError();
                    if (errorNumber == 122) // buffer too small error
                    {
                        filepathBuffer.clear();
                        filepathBuffer.resize(((filepathBufferSize + 2) * 2) - 1, L'\0'); // resizing to the next power of 2
                    }
                    else
                    {
                        printf("error when using GetModuleBaseName: %d\n", GetLastError());
                        return false;
                    }
                }

                if (filepathBufferSize >= 32767) // this should never happen
                {
                    printf("ERROR: file path size from QueryFullProcessImageName somehow exceeded 32767 characters\n");
                    return false;
                }
            }
        }

        // if L'\\' isn't found, filenamePosition will increase from npos to 0
        if (!checkIfPathIsToAmnesia(filepathBuffer))
        {
            printf("process name wasn't Amnesia.exe or Amnesia_NoSteam.exe when checking it using GetModuleBaseName: %ls\n", &filepathBuffer[0]);
            return false;
        }

        return true;
    }

    bool findExecutableMemoryLocation()
    {
        std::wstring filepathBuffer(512 - 1, L'\0'); // - 1 because a character is used for a null terminator on modern implementations

        uint32_t queryAddress = 0;
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQueryEx(amnesiaHandle, (LPCVOID)queryAddress, &mbi, sizeof(mbi)) == 0) // checking if VirtualQueryEx works
        {
            printf("error when using VirtualQueryEx: %d\n", GetLastError());
            return false;
        }

        // finding start of Amnesia.exe or Amnesia_NoSteam.exe memory
        DWORD filepathBufferSize = 0;
        DWORD charactersWritten = 0;
        size_t filepathLength = (size_t)-1;
        do
        {
            if (queryAddress != 0) // this check gets rid of warning C6387
            {
                do
                {
                    filepathBufferSize = filepathBuffer.size() - 1; // - 1 because writing to filepathBuffer.size() position is undefined
                    charactersWritten = GetMappedFileName(
                        amnesiaHandle,
                        (LPVOID)queryAddress,
                        &filepathBuffer[0],
                        filepathBufferSize
                    );

                    if (filepathBufferSize == charactersWritten)
                    {
                        if (filepathBufferSize >= 32767) // this should never happen
                        {
                            continue;
                        }

                        filepathBuffer.clear();
                        filepathBuffer.resize(((filepathBufferSize + 2) * 2) - 1, L'\0'); // resizing to the next power of 2
                    }
                } while (filepathBufferSize == charactersWritten); // if this is true then filepathBuffer wasn't big enough
            }

            if (checkIfPathIsToAmnesia(filepathBuffer))
            {
                filepathLength = charactersWritten;
                break;
            }

            queryAddress += mbi.RegionSize;
        } while (VirtualQueryEx(amnesiaHandle, (LPCVOID)queryAddress, &mbi, sizeof(mbi)) != 0);

        if (filepathLength == (size_t)-1)
        {
            printf("couldn't find Amnesia.exe or Amnesia_NoSteam.exe memory location\n");
            return false;
        }

        // finding the .text area
        std::wstring filepathBufferCopy = filepathBuffer;

        do
        {
            if (mbi.Protect == PAGE_EXECUTE_READ)
            {
                amnesiaMemoryLocation = queryAddress;
                bytesLeft = mbi.RegionSize;
                memoryOffset = queryAddress - pageSize; // this will overflow to 0 on the first call to getByte
                return true;
            }

            if (queryAddress != 0) // this check gets rid of warning C6387
            {
                charactersWritten = GetMappedFileName(
                    amnesiaHandle,
                    (LPVOID)queryAddress,
                    &filepathBuffer[0],
                    filepathBufferSize
                );
            }

            if (charactersWritten != filepathLength || filepathBuffer != filepathBufferCopy) // no longer looking at exe memory
            {
                break;
            }

            queryAddress += mbi.RegionSize;
        } while (VirtualQueryEx(amnesiaHandle, (LPCVOID)queryAddress, &mbi, sizeof(mbi)) != 0);

        printf("couldn't find .text area in Amnesia.exe or Amnesia_NoSteam.exe memory\n");
        return false;
    }

    bool getByte(unsigned char& b)
    {
        if (bytesLeft == 0)
        {
            return false;
        }

        if (bufferPosition == pageSize)
        {
            bufferPosition = 0;
            memoryOffset += pageSize;
            bool readSucceeded = ReadProcessMemory(
                amnesiaHandle,
                (LPCVOID)memoryOffset,
                (LPVOID)buffer.get(),
                pageSize,
                nullptr
            );

            if (!readSucceeded)
            {
                printf("ProcessHelper ReadProcessMemory error in getByte: %d\nat memory address: %zu\n", GetLastError(), memoryOffset);
                return false;
            }
        }

        b = buffer[bufferPosition];
        bufferPosition++;
        bytesLeft--;

        return true;
    }
};

struct SavedInstructions
{
    unsigned char beforeFadeOutAllBytes[7]{};
    uint32_t stopFunctionLocation = 0;
    uint32_t beforeFadeOutAllLocation = 0;
};

DWORD findAmnesiaPid()
{
    PROCESSENTRY32 processEntry{};
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        printf("error when using CreateToolhelp32Snapshot: %d\n", GetLastError());
        return (DWORD)-1;
    }

    if (!Process32First(snapshot, &processEntry))
    {
        printf("error when using Process32First: %d\n", GetLastError());
        CloseHandle(snapshot);
        return (DWORD)-1;
    }

    do
    {
        if (wcscmp(processEntry.szExeFile, steamName) == 0 || wcscmp(processEntry.szExeFile, nosteamName) == 0)
        {
            CloseHandle(snapshot);
            return processEntry.th32ProcessID;
        }
    } while (Process32Next(snapshot, &processEntry));

    CloseHandle(snapshot);
    printf("couldn't find amnesia process\n");
    return (DWORD)-1;
}

bool findNtFunctions(NTFUNCTION& NtSuspendProcess, NTFUNCTION& NtResumeProcess)
{
    HMODULE ntdllHandle = GetModuleHandle(L"ntdll.dll");
    if (!ntdllHandle)
    {
        printf("WARNING: error using GetModuleHandle to find ntdll.dll: %d\nAmnesia won't be suspended during code injection\n", GetLastError());
        return false;
    }

    NtSuspendProcess = (NTFUNCTION)GetProcAddress(ntdllHandle, "NtSuspendProcess");
    if (!NtSuspendProcess)
    {
        printf("WARNING: error using GetProcAddress to find NtSuspendProcess: %d\nAmnesia won't be suspended during code injection\n", GetLastError());
        return false;
    }

    NtResumeProcess = (NTFUNCTION)GetProcAddress(ntdllHandle, "NtResumeProcess");
    if (!NtResumeProcess)
    {
        printf("WARNING: error using GetProcAddress to find NtResumeProcess: %d\nAmnesia won't be suspended during code injection\n", GetLastError());
        return false;
    }

    return true;
}

void addNewValueToMemorySlice(unsigned char* memorySlice, size_t size, unsigned char newEndValue)
{
    for (size_t i = 0; i < size - 1; i++)
    {
        memorySlice[i] = memorySlice[i + 1];
    }
    memorySlice[size - 1] = newEndValue;
}

// this is fast enough for the size of the game
// if it needs to be faster, try making memorySlice a circular buffer
bool findInstructions(SavedInstructions& si, ProcessHelper& ph)
{
    unsigned char b = 0;
    unsigned char memorySlice[10]{}; // give this the size of the longest byte pattern

    for (int i = 1; i < sizeof(memorySlice); i++)
    {
        if (!ph.getByte(b))
        {
            return false;
        }
        memorySlice[i] = b;
    }

    for (size_t i = 0; (ph.getByte(b)) && (si.stopFunctionLocation == 0 || si.beforeFadeOutAllLocation == 0); i++)
    {
        addNewValueToMemorySlice(memorySlice, sizeof(memorySlice), b);

        if (memorySlice[0] == 0xf6 && memorySlice[1] == 0x74 && memorySlice[7] == 0x75 && memorySlice[9] == 0x80)
        {
            si.stopFunctionLocation = ph.amnesiaMemoryLocation + i - 16;
        }
        else if (memorySlice[0] == 0x40 && memorySlice[2] == 0x8b && memorySlice[3] == 0x40 && memorySlice[6] == 0x01)
        {
            i += 8;
            si.beforeFadeOutAllLocation = ph.amnesiaMemoryLocation + i;
            for (int n = 0; n < 8; n++)
            {
                ph.getByte(b);
                addNewValueToMemorySlice(memorySlice, sizeof(memorySlice), b);
            }

            if (memorySlice[0] == 0xe9) // amnesia is already injected
            {
                printf("amnesia is already injected\n");
                return false;
            }
            
            memcpy(si.beforeFadeOutAllBytes, memorySlice, sizeof(si.beforeFadeOutAllBytes));
        }
    }

    if (si.stopFunctionLocation != 0 && si.beforeFadeOutAllLocation != 0)
    {
        return true;
    }

    printf("couldn't find all instruction locations\n");

    return false;
}

// writing the flashback name text and sizes which will be put in the virtual page(s)
// in this function, size limits shouldn't be exceeded unless the user alters flashback_names.txt, so the checks are only a precaution
uint32_t setFlashbackNames(unsigned char* forExtraMemory)
{
    unsigned char flashbackNameBuffer[56]{}; // last 8 bytes are used to store size.

    std::unique_ptr<unsigned char[]> textFileBuffer = std::make_unique<unsigned char[]>(extraMemorySize);

    uint32_t startOffset = 128; // 64 for CPU instructions, 64 for std::string

    FILE* f = nullptr;
    errno_t errorCode = fopen_s(&f, "flashback_names.txt", "rb");
    if (!f)
    {
        printf("error when using fopen_s to open flashback_names.txt: %d\n", GetLastError());
        return 0;
    }

    size_t charactersRead = fread(textFileBuffer.get(), 1, extraMemorySize, f);
    if (charactersRead == extraMemorySize)
    {
        printf("WARNING: only the first 4096 bytes of flashback_names.txt were read\n");
    }

    uint32_t flashbackNames = 0;

    for (size_t i = 0; i < charactersRead && startOffset < extraMemorySize; i++)
    {
        uint32_t nameSize = 0;

        // nameSize < sizeof(flashbackNameBuffer) - 1 because the name needs to be null terminated
        for (;i < charactersRead && nameSize < sizeof(flashbackNameBuffer) - 1 && textFileBuffer[i] != '\n'; i++)
        {
            if (textFileBuffer[i] == '\r')
            {
                continue;
            }

            flashbackNameBuffer[nameSize] = textFileBuffer[i];
            nameSize++;
        }

        if (nameSize >= sizeof(flashbackNameBuffer))
        {
            printf("flashback name too long, maximum length is %zu\n", sizeof(flashbackNameBuffer) - 1);
            return 0;
        }
        else if (startOffset + 64 >= extraMemorySize)
        {
            printf("too many flashback names in flashback_names.txt\n");
            return 0;
        }
        else if (nameSize > 0)
        {
            memcpy(&forExtraMemory[startOffset], flashbackNameBuffer, nameSize);
            memcpy(&forExtraMemory[startOffset + 56], &nameSize, sizeof(nameSize));
            memset(flashbackNameBuffer, 0, sizeof(flashbackNameBuffer));
            startOffset += 64;
            flashbackNames++;
        }
    }

    if (flashbackNames == 0)
    {
        printf("no flashback names found in flashback_names.txt\n");
    }

    return flashbackNames;
}

bool injectInstructions(SavedInstructions& si, ProcessHelper& ph, uint32_t extraMemoryLocation)
{
    unsigned char instructionBytes[64] = {
        // jmp destination from before calling cSoundHandler::FadeOutAll
        0xd9, 0x1c, 0x24,                         // 0000 // fstp dword ptr [esp] // copied
        0x6a, 0x01,                               // 0003 // push 0x01 // copied
        0x8b, 0xc8,                               // 0005 // mov ecx, eax // copied
        0x53,                                     // 0007 // push ebx // stack depth +4
        0x57,                                     // 0008 // push edi // stack depth +8
        0x51,                                     // 0009 // push ecx // cSoundHandler object // stack depth +12
        0xbb, 0x00, 0x00, 0x00, 0x00,             // 0010 // mov ebx, start of first flashback name // check
        0x90,                                     // 0015 // nop so loop is aligned on byte 16
        // start of loop
        0x89, 0x1d, 0x00, 0x00, 0x00, 0x00,       // 0016 // mov [string object ptr location], ebx // ptr to characters // check
        0x8b, 0x7b, 0x38,                         // 0022 // mov edi, dword ptr [ebx + 0x38] // string size
        0x89, 0x3d, 0x00, 0x00, 0x00, 0x00,       // 0025 // mov dword ptr [string object size location], edi // check
        0x68, 0x00, 0x00, 0x00, 0x00,             // 0031 // push string object ptr location // stack depth +16 // check
        0xe8, 0x00, 0x00, 0x00, 0x00,             // 0036 // call cSoundHandler::Stop // stack depth +12
        0x8b, 0x0c, 0x24,                         // 0041 // mov ecx, dword ptr [esp] // cSoundHandler object
        0x83, 0xc3, 0x40,                         // 0044 // add ebx, 0x40 // start of next string data
        0x81, 0xfb, 0x00, 0x00, 0x00, 0x00,       // 0047 // cmp ebx, end of flashback names // check
        0x75, 0xd9,                               // 0053 // jnz -0x27
        // end of loop

        0x59,                                     // 0055 // pop ecx // stack depth +8
        0x5f,                                     // 0056 // pop edi // stack depth +4
        0x5b,                                     // 0057 // pop ebx // stack depth +0
        0xe9, 0x00, 0x00, 0x00, 0x00,             // 0058 // jmp to before calling cSoundHandler::FadeOutAll, 0048baad
    };

    unsigned char jmpInstruction[sizeof(si.beforeFadeOutAllBytes)] = {0xe9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90};

    std::unique_ptr<unsigned char[]> forExtraMemory = std::make_unique<unsigned char[]>(extraMemorySize);

    uint32_t stdStringCapacity = 63; // std::string capacity
    memcpy(&forExtraMemory[84], &stdStringCapacity, sizeof(uint32_t));

    uint32_t flashbackNames = setFlashbackNames(forExtraMemory.get());
    if (flashbackNames == 0)
    {
        return false;
    }

    uint32_t stringObjectPtrLocation = extraMemoryLocation + 64;
    memcpy(&instructionBytes[18], &stringObjectPtrLocation, sizeof(uint32_t));
    memcpy(&instructionBytes[32], &stringObjectPtrLocation, sizeof(uint32_t));

    uint32_t stringObjectSizeLocation = extraMemoryLocation + 80;
    memcpy(&instructionBytes[27], &stringObjectSizeLocation, sizeof(uint32_t));

    uint32_t firstFlashbackNameLocation = extraMemoryLocation + 128;
    memcpy(&instructionBytes[11], &firstFlashbackNameLocation, sizeof(uint32_t));

    uint32_t endOfFlashbackNames = extraMemoryLocation + 128 + (flashbackNames * 64);
    memcpy(&instructionBytes[49], &endOfFlashbackNames, sizeof(uint32_t));

    memcpy(&instructionBytes[0], si.beforeFadeOutAllBytes, sizeof(si.beforeFadeOutAllBytes));

    uint32_t stopFunctionOffset = si.stopFunctionLocation - (extraMemoryLocation + 41);
    memcpy(&instructionBytes[37], &stopFunctionOffset, sizeof(stopFunctionOffset));

    uint32_t fadeOutAllOffset = (si.beforeFadeOutAllLocation + sizeof(si.beforeFadeOutAllBytes)) - (extraMemoryLocation + 63);
    memcpy(&instructionBytes[59], &fadeOutAllOffset, sizeof(fadeOutAllOffset));

    memcpy(forExtraMemory.get(), instructionBytes, sizeof(instructionBytes));

    SIZE_T bytesWritten = 0;
    bool wpmSucceeded = false;

    wpmSucceeded = WriteProcessMemory(
        ph.amnesiaHandle,
        (LPVOID)extraMemoryLocation,
        (LPCVOID)forExtraMemory.get(),
        extraMemorySize,
        nullptr
    );

    if (!wpmSucceeded)
    {
        printf("error when calling WriteProcessMemory to write to allocated virtual page(s): %d\n", GetLastError());
        return false;
    }

    uint32_t offsetFromCheckMapChange = (extraMemoryLocation + 0) - (si.beforeFadeOutAllLocation + 5);
    memcpy(&jmpInstruction[1], &offsetFromCheckMapChange, sizeof(offsetFromCheckMapChange));

    wpmSucceeded = WriteProcessMemory(
        ph.amnesiaHandle,
        (LPVOID)si.beforeFadeOutAllLocation,
        (LPCVOID)jmpInstruction,
        sizeof(si.beforeFadeOutAllBytes),
        &bytesWritten
    );

    if (bytesWritten < sizeof(si.beforeFadeOutAllBytes))
    {
        printf("JMP INSTRUCTION ONLY PARTIALLY WRITTEN IN CHECKMAPCHANGE\nRESTART AMNESIA OR IT WILL CRASH ON MAP CHANGE\nerror: %d\n", GetLastError());
        return false;
    }
    else if (!wpmSucceeded)
    {
        printf("error when calling WriteProcessMemory to write jmp instruction in CheckMapChange: %d\n", GetLastError());
        return false;
    }

    return true;
}

bool injectWhileSuspended(ProcessHelper& ph)
{
    if (!ph.findExecutableMemoryLocation())
    {
        return false;
    }
    size_t executableRegionSize = ph.bytesLeft;

    SavedInstructions si;

    if (!findInstructions(si, ph))
    {
        return false;
    }

    LPVOID extraMemoryLocation = VirtualAllocEx(
        ph.amnesiaHandle,
        nullptr,
        extraMemorySize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (extraMemoryLocation == nullptr)
    {
        printf("error when using VirtualAllocEx: %d\n", GetLastError());
        return false;
    }

    if (!injectInstructions(si, ph, (uint32_t)extraMemoryLocation))
    {
        bool extraMemoryFreed = VirtualFreeEx(
            ph.amnesiaHandle,
            extraMemoryLocation,
            0,
            MEM_RELEASE
        );
        if (!extraMemoryFreed)
        {
            printf("WARNING: error when using VirtualFreeEx: %d\ncouldn't release VirtualAllocEx memory\n", GetLastError());
        }

        return false;
    }
    else
    {
        FlushInstructionCache(ph.amnesiaHandle, (LPCVOID)ph.amnesiaMemoryLocation, executableRegionSize);
    }

    printf("amnesia has been injected\n");
    return true;
}

int main()
{
    // LiveSplit uses these functions, so they must be safe enough even though they're undocumented
    NTFUNCTION NtSuspendProcess = nullptr;
    NTFUNCTION NtResumeProcess = nullptr;

    DWORD amnesiaPid = findAmnesiaPid();

    if (amnesiaPid == (DWORD)-1)
    {
        printf("you can now close this window\n");
        char C6031WarningVariable = getchar();
        return EXIT_FAILURE;
    }

    ProcessHelper ph(amnesiaPid);

    if (!ph.checkIfProcessIsAmnesia())
    {
        printf("you can now close this window\n");
        char C6031WarningVariable = getchar();
        return EXIT_FAILURE;
    }

    bool ntFunctionsFound = findNtFunctions(NtSuspendProcess, NtResumeProcess);

    if (ntFunctionsFound)
    {
        NtSuspendProcess(ph.amnesiaHandle);
    }

    bool injectionSucceeded = injectWhileSuspended(ph);

    if (ntFunctionsFound)
    {
        NtResumeProcess(ph.amnesiaHandle);
    }
    
    printf("you can now close this window\n");
    char C6031WarningVariable = getchar();

    return injectionSucceeded ? EXIT_SUCCESS : EXIT_FAILURE;
}
