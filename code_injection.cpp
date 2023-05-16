
#include <cstdio>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <cstdint>
#include <string>
#include <memory>

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
    unsigned char gettingSoundHandler[14]{};
    unsigned char beforeFadeOutAllBytes[7]{};
    unsigned char sleepCallBytes[6]{};
    unsigned char loadEndBytes[5]{};
    uint32_t stopFunctionLocation = 0;
    uint32_t isPlayingLocation = 0;
    uint32_t beforeFadeOutAllLocation = 0;
    uint32_t loadEndLocation = 0;
    bool isSteamVersion = false;
};

DWORD findAmnesiaPid(SavedInstructions& si)
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
        if ((si.isSteamVersion = (wcscmp(processEntry.szExeFile, steamName) == 0)) || wcscmp(processEntry.szExeFile, nosteamName) == 0)
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
    unsigned char memorySlice[16]{}; // give this at least the size of the longest byte pattern

    for (int i = 1; i < sizeof(memorySlice); i++)
    {
        if (!ph.getByte(b))
        {
            return false;
        }
        memorySlice[i] = b;
    }

    int locationsFound = 0;
    bool isv = si.isSteamVersion; // on the steam version, the first mov instruction is 6 bytes long instead of 5
    for (size_t i = 0; ph.getByte(b) && locationsFound < 5; i++)
    {
        addNewValueToMemorySlice(memorySlice, sizeof(memorySlice), b);

        if (memorySlice[0] == 0xf6 && memorySlice[1] == 0x74 && memorySlice[7] == 0x75 && memorySlice[9] == 0x80)
        {
            locationsFound += 1;
            si.stopFunctionLocation = ph.amnesiaMemoryLocation + i - 16;
        }
        else if (memorySlice[0] == 0x48 && memorySlice[8] == 0xd0 && memorySlice[9] == 0x5d)
        {
            locationsFound += 1;
            si.isPlayingLocation = ph.amnesiaMemoryLocation + i - 17;
        }
        else if (memorySlice[0] == 0x75 && memorySlice[2] == 0x56 && memorySlice[4] == 0x15 && memorySlice[9] == 0x8b)
        {
            locationsFound += 1;
            memcpy(si.sleepCallBytes, &memorySlice[3], sizeof(si.sleepCallBytes));
        }
        else if (
            (memorySlice[5] == 0xff && memorySlice[6] == 0x50 && memorySlice[8] == 0xe8 && memorySlice[13] == 0x2b)
            || (si.isSteamVersion && memorySlice[5] == 0xff && memorySlice[6] == 0xd0 && memorySlice[7] == 0xe8 && memorySlice[13] == 0x45))
        {
            locationsFound += 1;
            si.loadEndLocation = ph.amnesiaMemoryLocation + i;

            if (memorySlice[0] == 0xe9) // amnesia is already injected
            {
                printf("amnesia is already injected\n");
                return false;
            }

            memcpy(si.loadEndBytes, memorySlice, sizeof(si.loadEndBytes));
        }
        else if (memorySlice[8 + isv] == 0x40 && memorySlice[10 + isv] == 0x8b && memorySlice[11 + isv] == 0x40 && memorySlice[14 + isv] == 0x01)
        {
            locationsFound += 1;
            memcpy(si.gettingSoundHandler, memorySlice, sizeof(si.gettingSoundHandler));

            i += 16 + isv;
            si.beforeFadeOutAllLocation = ph.amnesiaMemoryLocation + i;
            for (int n = 0; n < 16 + isv; n++)
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

    if (
        si.stopFunctionLocation != 0
        && si.isPlayingLocation != 0
        && si.beforeFadeOutAllLocation != 0
        && si.loadEndLocation != 0
        && si.sleepCallBytes[0] != 0)
    {
        return true;
    }

    printf("couldn't find all instruction locations: %d\n", locationsFound);
    printf("%d\n%d\n%d\n%d\n%u\n", si.stopFunctionLocation, si.isPlayingLocation, si.beforeFadeOutAllLocation, si.loadEndLocation, si.sleepCallBytes[0]);
    return false;
}

// writing the flashback name text and sizes which will be put in the virtual page(s)
// in this function, size limits shouldn't be exceeded unless the user alters the txt file, so the checks are only a precaution
uint32_t setFlashbackNames(unsigned char* forExtraMemory, uint32_t startOffset, const char* filename)
{
    unsigned char flashbackNameBuffer[56]{}; // last 8 bytes are used to store size.

    std::unique_ptr<unsigned char[]> textFileBuffer = std::make_unique<unsigned char[]>(extraMemorySize);

    FILE* f = nullptr;
    errno_t errorCode = fopen_s(&f, filename, "rb");
    if (!f)
    {
        printf("error when using fopen_s to open %s: %d\n", filename, GetLastError());
        return 0;
    }

    size_t charactersRead = fread(textFileBuffer.get(), 1, extraMemorySize, f);
    if (charactersRead == extraMemorySize)
    {
        printf("WARNING: only the first 4096 bytes of %s are read\n", filename);
    }

    uint32_t flashbackNames = 0;

    for (size_t i = 0; i < charactersRead && startOffset < extraMemorySize; i++)
    {
        uint32_t nameSize = 0;

        // nameSize < sizeof(flashbackNameBuffer) - 1 because the name needs to be null terminated
        for (; i < charactersRead && nameSize < sizeof(flashbackNameBuffer) - 1 && textFileBuffer[i] != '\n'; i++)
        {
            if (textFileBuffer[i] == '\r')
            {
                continue;
            }

            flashbackNameBuffer[nameSize] = textFileBuffer[i];
            nameSize++;
        }

        if (nameSize == 0) // empty line
        {
            continue;
        }
        else if (nameSize >= sizeof(flashbackNameBuffer) || nameSize < 16)
        {
            // sso happens at sizes less than 16. None of the flashbacks should have names less than 16.
            printf("flashback name too %s, maximum length is %zu, minimum length is 16\n", nameSize < 16 ? "small" : "large", sizeof(flashbackNameBuffer) - 1);
            return 0;
        }
        else if (startOffset + 64 >= extraMemorySize)
        {
            printf("too many flashback names in %s, 4096 byte limit can't be exceeded\n", filename);
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
        printf("no flashback names found in %s\n", filename);
    }

    return flashbackNames;
}

bool injectSkipInstructions(SavedInstructions& si, ProcessHelper& ph, uint32_t extraMemoryLocation)
{
    // this is jumped to before a call instruction, so the caller-saved registers should already be saved
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
        0x90,
    };

    unsigned char jmpInstruction[sizeof(si.beforeFadeOutAllBytes)] = { 0xe9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90 };

    std::unique_ptr<unsigned char[]> forExtraMemory = std::make_unique<unsigned char[]>(extraMemorySize);

    uint32_t stdStringCapacity = 63; // std::string capacity
    memcpy(&forExtraMemory[sizeof(instructionBytes) + 20], &stdStringCapacity, sizeof(uint32_t));

    uint32_t startOffset = sizeof(instructionBytes) + 64; // 64 bytes used for std::string object + padding
    uint32_t flashbackNames = setFlashbackNames(forExtraMemory.get(), startOffset, "flashback_names.txt");
    if (flashbackNames == 0)
    {
        return false;
    }

    uint32_t stringObjectPtrLocation = extraMemoryLocation + sizeof(instructionBytes);
    memcpy(&instructionBytes[18], &stringObjectPtrLocation, sizeof(uint32_t));
    memcpy(&instructionBytes[32], &stringObjectPtrLocation, sizeof(uint32_t));

    uint32_t stringObjectSizeLocation = extraMemoryLocation + sizeof(instructionBytes) + 16;
    memcpy(&instructionBytes[27], &stringObjectSizeLocation, sizeof(uint32_t));

    uint32_t firstFlashbackNameLocation = extraMemoryLocation + startOffset;
    memcpy(&instructionBytes[11], &firstFlashbackNameLocation, sizeof(uint32_t));

    uint32_t endOfFlashbackNames = extraMemoryLocation + startOffset + (flashbackNames * 64);
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

bool injectWaitInstructions(SavedInstructions& si, ProcessHelper& ph, uint32_t extraMemoryLocation)
{
    // this is jumped to before a call instruction, so the caller-saved registers should already be saved
    unsigned char instructionBytes[128] = {
        0x53,                                     // 0000 // push ebx // stack depth +4
        0x57,                                     // 0001 // push edi // stack depth +8
        0x56,                                     // 0002 // push esi // stack depth +12
        0x51,                                     // 0003 // push ecx // steam version copied instructions need ecx // stack depth +16
        0x51,                                     // 0004 // push ecx // dummy push // stack depth +20
        0x51,                                     // 0005 // push ecx // dummy push // stack depth +24

        // jmp destination from near the end of the map load
        // starting with 13-14 bytes to get the cSoundHandler object in eax
        // the last byte is a nop instruction because the NoSteam version only uses 13 bytes to get the cSoundHandler object
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, // 0006 // getting cSoundHandler object

        0x8b, 0xc8,                               // 0020 // mov ecx, eax // moving cSoundHandler object to ecx
        0x51,                                     // 0022 // push ecx // cSoundHandler object // stack depth +28
        0xbb, 0x00, 0x00, 0x00, 0x00,             // 0023 // mov ebx, start of first flashback name
        0x31, 0xf6,                               // 0028 // xor esi, esi
        0x90, 0x90,                               // 0030 // nops so loop is aligned on byte 32
        // start of loop
        0x89, 0x1d, 0x00, 0x00, 0x00, 0x00,       // 0032 // mov [string object ptr location], ebx // ptr to characters
        0x8b, 0x7b, 0x38,                         // 0038 // mov edi, dword ptr [ebx + 0x38] // string size
        0x89, 0x3d, 0x00, 0x00, 0x00, 0x00,       // 0041 // mov dword ptr [string object size location], edi
        0x8b, 0x0c, 0x24,                         // 0047 // mov ecx, dword ptr [esp] // cSoundHandler object
        0x68, 0x00, 0x00, 0x00, 0x00,             // 0050 // push string object ptr location // stack depth +32
        0xe8, 0x00, 0x00, 0x00, 0x00,             // 0055 // call cSoundHandler::IsPlaying // stack depth +28
        0x09, 0xc6,                               // 0060 // or esi, eax
        0x83, 0xc3, 0x40,                         // 0062 // add ebx, 0x40 // start of next string data
        0x81, 0xfb, 0x00, 0x00, 0x00, 0x00,       // 0065 // cmp ebx, end of flashback names
        0x75, 0xd7,                               // 0071 // jnz -41
        0x83, 0xfe, 0x00,                         // 0073 // cmp esi, 0
        0x74, 0x10,                               // 0076 // jz 16
        0x56,                                     // 0078 // push esi // stack depth +32 // esi should be 1 here
        0xff, 0x15, 0x00, 0x00, 0x00, 0x00,       // 0079 // call Sleep // stack depth +28
        0xbb, 0x00, 0x00, 0x00, 0x00,             // 0085 // mov ebx, start of first flashback name
        0x31, 0xf6,                               // 0090 // xor esi, esi
        0x74, 0xc2,                               // 0092 // jz -62
        // end of loop

        0x83, 0xc4, 0x0c,                         // 0094 // add esp, 12 // stack depth +16
        0x59,                                     // 0097 // pop ecx // stack depth +12
        0x5e,                                     // 0098 // pop esi // stack depth +8
        0x5f,                                     // 0099 // pop edi // stack depth +4
        0x5b,                                     // 0100 // pop ebx // stack depth +0
        0x00, 0x00, 0x00, 0x00, 0x00,             // 0101 // copied instructions
        0xe9, 0x00, 0x00, 0x00, 0x00,             // 0106 // jmp to end of load
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    };

    unsigned char jmpInstruction[sizeof(si.beforeFadeOutAllBytes)] = { 0xe9, 0x00, 0x00, 0x00, 0x00 };

    std::unique_ptr<unsigned char[]> forExtraMemory = std::make_unique<unsigned char[]>(extraMemorySize);

    uint32_t stdStringCapacity = 63; // std::string capacity
    memcpy(&forExtraMemory[sizeof(instructionBytes) + 20], &stdStringCapacity, sizeof(uint32_t));

    uint32_t startOffset = sizeof(instructionBytes) + 64; // 64 bytes used for std::string object + padding
    uint32_t flashbackNames = setFlashbackNames(forExtraMemory.get(), startOffset, "flashback_names.txt");
    if (flashbackNames == 0)
    {
        return false;
    }

    memcpy(&instructionBytes[6], si.gettingSoundHandler, sizeof(si.gettingSoundHandler) - !(si.isSteamVersion));

    uint32_t stringObjectPtrLocation = extraMemoryLocation + sizeof(instructionBytes);
    memcpy(&instructionBytes[34], &stringObjectPtrLocation, sizeof(uint32_t));
    memcpy(&instructionBytes[51], &stringObjectPtrLocation, sizeof(uint32_t));

    uint32_t stringObjectSizeLocation = extraMemoryLocation + sizeof(instructionBytes) + 16;
    memcpy(&instructionBytes[43], &stringObjectSizeLocation, sizeof(uint32_t));

    uint32_t firstFlashbackNameLocation = extraMemoryLocation + startOffset;
    memcpy(&instructionBytes[24], &firstFlashbackNameLocation, sizeof(uint32_t));
    memcpy(&instructionBytes[86], &firstFlashbackNameLocation, sizeof(uint32_t));

    uint32_t endOfFlashbackNames = extraMemoryLocation + startOffset + (flashbackNames * 64);
    memcpy(&instructionBytes[67], &endOfFlashbackNames, sizeof(uint32_t));

    memcpy(&instructionBytes[79], si.sleepCallBytes, sizeof(si.sleepCallBytes));

    memcpy(&instructionBytes[101], si.loadEndBytes, sizeof(si.loadEndBytes));

    uint32_t isPlayingOffset = si.isPlayingLocation - (extraMemoryLocation + 60);
    memcpy(&instructionBytes[56], &isPlayingOffset, sizeof(isPlayingOffset));

    uint32_t loadEndOffset = (si.loadEndLocation + sizeof(si.loadEndBytes)) - (extraMemoryLocation + 111);
    memcpy(&instructionBytes[107], &loadEndOffset, sizeof(loadEndOffset));

    //memset(&instructionBytes[0], 0x90, 101);

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

    uint32_t offsetFromCheckMapChange = (extraMemoryLocation + 0) - (si.loadEndLocation + 5);
    memcpy(&jmpInstruction[1], &offsetFromCheckMapChange, sizeof(offsetFromCheckMapChange));

    wpmSucceeded = WriteProcessMemory(
        ph.amnesiaHandle,
        (LPVOID)si.loadEndLocation,
        (LPCVOID)jmpInstruction,
        sizeof(si.loadEndBytes),
        &bytesWritten
    );

    //for (int i = 0; i < 111; i++) printf("%d ", instructionBytes[i]); printf("\n");

    if (bytesWritten < sizeof(si.loadEndBytes))
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

bool injectWhileSuspended(ProcessHelper& ph, SavedInstructions& si, bool skipFlashbacks)
{
    if (!ph.findExecutableMemoryLocation())
    {
        return false;
    }
    size_t executableRegionSize = ph.bytesLeft;

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

    bool injectionSucceeded = false;
    if (skipFlashbacks)
    {
        injectionSucceeded = injectSkipInstructions(si, ph, (uint32_t)extraMemoryLocation);
    }
    else
    {
        injectionSucceeded = injectWaitInstructions(si, ph, (uint32_t)extraMemoryLocation);
    }

    if (!injectionSucceeded)
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

    printf("amnesia has been injected\n");
    return true;
}

DWORD codeInjectionMain(bool skipFlashbacks)
{
    // LiveSplit uses these functions, so they must be safe enough even though they're undocumented
    NTFUNCTION NtSuspendProcess = nullptr;
    NTFUNCTION NtResumeProcess = nullptr;

    SavedInstructions si;

    DWORD amnesiaPid = findAmnesiaPid(si);

    if (amnesiaPid == (DWORD)-1)
    {
        printf("you can now close this window\n");
        return (DWORD)-1;
    }

    ProcessHelper ph(amnesiaPid);

    if (!ph.checkIfProcessIsAmnesia())
    {
        printf("you can now close this window\n");
        return (DWORD)-1;
    }

    bool ntFunctionsFound = findNtFunctions(NtSuspendProcess, NtResumeProcess);

    if (ntFunctionsFound)
    {
        NtSuspendProcess(ph.amnesiaHandle);
    }

    bool injectionSucceeded = injectWhileSuspended(ph, si, skipFlashbacks);

    if (ntFunctionsFound)
    {
        NtResumeProcess(ph.amnesiaHandle);
    }

    return injectionSucceeded ? amnesiaPid : (DWORD)-1;
}
