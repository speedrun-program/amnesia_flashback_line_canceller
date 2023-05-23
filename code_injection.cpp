
#include <cstdio>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <cstdint>
#include <string>
#include <memory>
#include <stdexcept>

#include "file_helper.h"
#include "process_helper.h"

typedef LONG(__stdcall* NTFUNCTION)(HANDLE);

const wchar_t steamName[] = L"Amnesia.exe";
const wchar_t nosteamName[] = L"Amnesia_NoSteam.exe";
const char flashbackNameFile[] = "flashback_names.txt";
const uint32_t flashbackSkipInstructionsSize = 128;
const uint32_t flashbackWaitInstructionsSize = 128;

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

DWORD searchUsingSnapshotHandle(SavedInstructions& si, PROCESSENTRY32& processEntry, HANDLE snapshot)
{
    if (!Process32First(snapshot, &processEntry))
    {
        printf("error when using Process32First: %d\n", GetLastError());
        return (DWORD)-1;
    }

    do
    {
        if ((si.isSteamVersion = (wcscmp(processEntry.szExeFile, steamName) == 0)) || wcscmp(processEntry.szExeFile, nosteamName) == 0)
        {
            return processEntry.th32ProcessID;
        }
    } while (Process32Next(snapshot, &processEntry));

    return (DWORD)-1;
}

DWORD findAmnesiaPid(SavedInstructions& si)
{
    DWORD amnesiaPid = (DWORD)-1;

    PROCESSENTRY32 processEntry{};
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        printf("error when using CreateToolhelp32Snapshot: %d\n", GetLastError());
        return amnesiaPid;
    }
    amnesiaPid = searchUsingSnapshotHandle(si, processEntry, snapshot);
    CloseHandle(snapshot);

    if (amnesiaPid == (DWORD)-1)
    {
        printf("couldn't find amnesia process\n");
    }

    return amnesiaPid;
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

    for (size_t i = 1; i < sizeof(memorySlice); i++)
    {
        if (!ph.getByte(b))
        {
            return false;
        }
        memorySlice[i] = b;
    }

    size_t locationsFound = 0; // if this ends up being greater than 5, there were duplicate injection location patterns
    bool isv = si.isSteamVersion; // on the steam version, the first mov instruction is 6 bytes long instead of 5

    // finding where to write to and copy from in amnesia's memory based on instruction byte patterns
    for (size_t i = 0; ph.getByte(b); i++)
    {
        addNewValueToMemorySlice(memorySlice, sizeof(memorySlice), b);

        if (memorySlice[0] == 0xf6 && memorySlice[1] == 0x74 && memorySlice[7] == 0x75 && memorySlice[9] == 0x80)
        {
            locationsFound++;
            si.stopFunctionLocation = ph.processMemoryLocation + i - 16;
        }
        else if (memorySlice[0] == 0x48 && memorySlice[8] == 0xd0 && memorySlice[9] == 0x5d)
        {
            locationsFound++;
            si.isPlayingLocation = ph.processMemoryLocation + i - 17;
        }
        else if (memorySlice[0] == 0x75 && memorySlice[2] == 0x56 && memorySlice[4] == 0x15 && memorySlice[9] == 0x8b)
        {
            locationsFound++;
            memcpy(si.sleepCallBytes, &memorySlice[3], sizeof(si.sleepCallBytes));
        }
        else if (
            (memorySlice[5] == 0xff && memorySlice[6] == 0x50 && memorySlice[8] == 0xe8 && memorySlice[13] == 0x2b)
            || (si.isSteamVersion && memorySlice[5] == 0xff && memorySlice[6] == 0xd0 && memorySlice[7] == 0xe8 && memorySlice[13] == 0x45))
        {
            locationsFound++;
            si.loadEndLocation = ph.processMemoryLocation + i;

            if (memorySlice[0] == 0xe9) // the jump instruction is already there, so amnesia must have already been injected
            {
                printf("amnesia is already injected\n");
                return false;
            }

            memcpy(si.loadEndBytes, memorySlice, sizeof(si.loadEndBytes));
        }
        else if (memorySlice[8 + isv] == 0x40 && memorySlice[10 + isv] == 0x8b && memorySlice[11 + isv] == 0x40 && memorySlice[14 + isv] == 0x01)
        {
            locationsFound++;
            memcpy(si.gettingSoundHandler, memorySlice, sizeof(si.gettingSoundHandler));

            i += (size_t)16 + isv;
            si.beforeFadeOutAllLocation = ph.processMemoryLocation + i;
            for (size_t n = 0; n < 16 + isv; n++)
            {
                ph.getByte(b);
                addNewValueToMemorySlice(memorySlice, sizeof(memorySlice), b);
            }

            if (memorySlice[0] == 0xe9) // the jump instruction is already there, so amnesia must have already been injected
            {
                printf("amnesia is already injected\n");
                return false;
            }

            memcpy(si.beforeFadeOutAllBytes, memorySlice, sizeof(si.beforeFadeOutAllBytes));
        }
    }

    bool allLocationsFound = (
        si.stopFunctionLocation != 0
        && si.isPlayingLocation != 0
        && si.beforeFadeOutAllLocation != 0
        && si.loadEndLocation != 0
        && si.sleepCallBytes[0] != 0
    );
    if (locationsFound > 5 || (locationsFound == 5 && !allLocationsFound))
    {
        printf("error: duplicate injection location patterns found\n");
        return false;
    }
    else if (allLocationsFound)
    {
        return true;
    }

    printf("couldn't find all instruction locations\n");
    return false;
}

// this needs to be done to find how much memory to allocate for the virtual pages
void preprocessFlashbackNames(FileHelper<char>& fh, uint32_t& howManyNames, uint32_t& longestName)
{
    char ch = '\0';

    uint32_t currentNameLength = 0;

    while (fh.getCharacter(ch))
    {
        if (ch == '\r') // windows puts this at the end of lines
        {
            continue;
        }
        else if (ch == '\n')
        {
            if (currentNameLength > longestName)
            {
                longestName = currentNameLength;
            }
            howManyNames += currentNameLength > 0;
            currentNameLength = 0;
        }
        else
        {
            currentNameLength++;
        }
    }

    // last line
    if (currentNameLength > longestName)
    {
        longestName = currentNameLength;
    }
    howManyNames += currentNameLength > 0;

    fh.resetFile();
}

bool setFlashbackNames(unsigned char* forExtraMemory, FileHelper<char>& fh, uint32_t startOffset, uint32_t spacePerName, uint32_t extraMemorySize)
{
    char ch = '\0';
    uint32_t writeOffset = startOffset;
    uint32_t nameSize = 0;

    while (fh.getCharacter(ch))
    {
        if (ch == '\r') // windows puts this at the end of lines
        {
            continue;
        }
        else if (ch == '\n')
        {
            if (nameSize > 0)
            {
                memcpy(&forExtraMemory[writeOffset + spacePerName - 8], &nameSize, sizeof(nameSize));
                writeOffset += spacePerName;
                nameSize = 0;
            }
        }
        else
        {
            if (nameSize == spacePerName - 9) // this shouldn't ever happen, flashback line names shouldn't need to be long enough to cause this
            {
                printf("a flashback line name was longer than expected, possibly because of integer overflow\n");
                return false;
            }
            else if (writeOffset + nameSize >= extraMemorySize) // this also shouldn't ever happen, there shouldn't need to be enough to cause this
            {
                printf("there were more flashback line names than expected, possibly because of integer overflow\n");
                return false;
            }

            forExtraMemory[writeOffset + nameSize] = (unsigned int)ch;
            nameSize++;
        }
    }
    if (nameSize > 0)
    {
        memcpy(&forExtraMemory[writeOffset + spacePerName - 8], &nameSize, sizeof(nameSize));
    }

    return true;
}

bool injectSkipInstructions(
    unsigned char* forExtraMemory,
    SavedInstructions& si,
    ProcessHelper& ph,
    uint32_t howManyNames,
    uint32_t spacePerName,
    uint32_t extraMemoryLocation,
    uint32_t extraMemorySize)
{
    // this is jumped to before a call instruction, so the caller-saved registers should already be saved
    unsigned char flashbackSkipInstructions[flashbackSkipInstructionsSize] = {
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
        0x8b, 0xbb, 0x00, 0x00, 0x00, 0x00,       // 0022 // mov edi, dword ptr [ebx + spacePerName - 8] // flashback name size
        0x89, 0x3d, 0x00, 0x00, 0x00, 0x00,       // 0028 // mov dword ptr [string object size location], edi // check
        0x68, 0x00, 0x00, 0x00, 0x00,             // 0034 // push string object ptr location // stack depth +16 // check
        0xe8, 0x00, 0x00, 0x00, 0x00,             // 0039 // call cSoundHandler::Stop // stack depth +12
        0x8b, 0x0c, 0x24,                         // 0044 // mov ecx, dword ptr [esp] // cSoundHandler object
        0x81, 0xc3, 0x00, 0x00, 0x00, 0x00,       // 0047 // add ebx, spacePerName // start of next string data
        0x81, 0xfb, 0x00, 0x00, 0x00, 0x00,       // 0053 // cmp ebx, end of flashback names // check
        0x75, 0xd3,                               // 0059 // jnz -45
        // end of loop

        0x59,                                     // 0061 // pop ecx // stack depth +8
        0x5f,                                     // 0062 // pop edi // stack depth +4
        0x5b,                                     // 0063 // pop ebx // stack depth +0
        0xe9, 0x00, 0x00, 0x00, 0x00,             // 0064 // jmp to before calling cSoundHandler::FadeOutAll, 0048baad
        0x90,                                     // 0069 // nop
    };

    unsigned char jmpInstruction[sizeof(si.beforeFadeOutAllBytes)] = {0xe9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90};

    uint32_t stdStringCapacity = spacePerName - 1;
    memcpy(&forExtraMemory[sizeof(flashbackSkipInstructions) + 20], &stdStringCapacity, sizeof(uint32_t));

    uint32_t startOffset = sizeof(flashbackSkipInstructions) + 64; // 64 bytes used for std::string object + padding

    memcpy(&flashbackSkipInstructions[0], si.beforeFadeOutAllBytes, sizeof(si.beforeFadeOutAllBytes));

    uint32_t firstFlashbackNameLocation = extraMemoryLocation + startOffset;
    memcpy(&flashbackSkipInstructions[11], &firstFlashbackNameLocation, sizeof(uint32_t));

    uint32_t stringObjectPtrLocation = extraMemoryLocation + sizeof(flashbackSkipInstructions);
    memcpy(&flashbackSkipInstructions[18], &stringObjectPtrLocation, sizeof(uint32_t));
    memcpy(&flashbackSkipInstructions[35], &stringObjectPtrLocation, sizeof(uint32_t));

    uint32_t flashbackNameSizeOffset = spacePerName - 8;
    memcpy(&flashbackSkipInstructions[24], &flashbackNameSizeOffset, sizeof(uint32_t));

    uint32_t stringObjectSizeLocation = extraMemoryLocation + sizeof(flashbackSkipInstructions) + 16;
    memcpy(&flashbackSkipInstructions[30], &stringObjectSizeLocation, sizeof(uint32_t));

    uint32_t stopFunctionOffset = si.stopFunctionLocation - (extraMemoryLocation + 44);
    memcpy(&flashbackSkipInstructions[40], &stopFunctionOffset, sizeof(stopFunctionOffset));

    memcpy(&flashbackSkipInstructions[49], &spacePerName, sizeof(spacePerName));

    uint32_t endOfFlashbackNames = extraMemoryLocation + startOffset + (howManyNames * spacePerName);
    memcpy(&flashbackSkipInstructions[55], &endOfFlashbackNames, sizeof(uint32_t));

    uint32_t fadeOutAllOffset = (si.beforeFadeOutAllLocation + sizeof(si.beforeFadeOutAllBytes)) - ((size_t)extraMemoryLocation + 69);
    memcpy(&flashbackSkipInstructions[65], &fadeOutAllOffset, sizeof(fadeOutAllOffset));

    memset(&flashbackSkipInstructions[70], 0xcc, sizeof(flashbackSkipInstructions) - 70); // int3

    memcpy(forExtraMemory, flashbackSkipInstructions, sizeof(flashbackSkipInstructions));

    SIZE_T bytesWritten = 0;
    bool wpmSucceeded = false;

    wpmSucceeded = WriteProcessMemory(
        ph.processHandle,
        (LPVOID)extraMemoryLocation,
        (LPCVOID)forExtraMemory,
        extraMemorySize,
        nullptr
    );

    if (!wpmSucceeded)
    {
        printf("error when calling WriteProcessMemory to write to allocated virtual page(s): %d\nat memory address: %u\n", GetLastError(), extraMemoryLocation);
        return false;
    }

    uint32_t offsetFromCheckMapChange = (extraMemoryLocation + 0) - (si.beforeFadeOutAllLocation + 5);
    memcpy(&jmpInstruction[1], &offsetFromCheckMapChange, sizeof(offsetFromCheckMapChange));

    wpmSucceeded = WriteProcessMemory(
        ph.processHandle,
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
        printf("error when calling WriteProcessMemory to write jmp instruction in CheckMapChange: %d\nat memory address: %u\n", GetLastError(), si.beforeFadeOutAllLocation);
        return false;
    }

    return true;
}

bool injectWaitInstructions(
    unsigned char* forExtraMemory,
    SavedInstructions& si,
    ProcessHelper& ph,
    uint32_t howManyNames,
    uint32_t spacePerName,
    uint32_t extraMemoryLocation,
    uint32_t extraMemorySize)
{
    // this is jumped to before a call instruction, so the caller-saved registers should already be saved
    unsigned char flashbackWaitInstructions[flashbackWaitInstructionsSize] = {
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
        0x8b, 0xbb, 0x00, 0x00, 0x00, 0x00,       // 0038 // mov edi, dword ptr [ebx + spacePerName - 8] // flashback name size
        0x89, 0x3d, 0x00, 0x00, 0x00, 0x00,       // 0044 // mov dword ptr [string object size location], edi
        0x8b, 0x0c, 0x24,                         // 0050 // mov ecx, dword ptr [esp] // cSoundHandler object
        0x68, 0x00, 0x00, 0x00, 0x00,             // 0053 // push string object ptr location // stack depth +32
        0xe8, 0x00, 0x00, 0x00, 0x00,             // 0058 // call cSoundHandler::IsPlaying // stack depth +28
        0x09, 0xc6,                               // 0063 // or esi, eax
        0x81, 0xc3, 0x00, 0x00, 0x00, 0x00,       // 0065 // add ebx, spacePerName // start of next string data
        0x81, 0xfb, 0x00, 0x00, 0x00, 0x00,       // 0071 // cmp ebx, end of flashback names
        0x75, 0xd1,                               // 0077 // jnz -47
        0x83, 0xfe, 0x00,                         // 0079 // cmp esi, 0
        0x74, 0x10,                               // 0082 // jz 16
        0x56,                                     // 0084 // push esi // stack depth +32 // esi should be 1 here
        0xff, 0x15, 0x00, 0x00, 0x00, 0x00,       // 0085 // call Sleep // stack depth +28
        0xbb, 0x00, 0x00, 0x00, 0x00,             // 0091 // mov ebx, start of first flashback name
        0x31, 0xf6,                               // 0096 // xor esi, esi
        0x74, 0xbc,                               // 0098 // jz -68
        // end of loop

        0x83, 0xc4, 0x0c,                         // 0100 // add esp, 12 // stack depth +16
        0x59,                                     // 0103 // pop ecx // stack depth +12
        0x5e,                                     // 0104 // pop esi // stack depth +8
        0x5f,                                     // 0105 // pop edi // stack depth +4
        0x5b,                                     // 0106 // pop ebx // stack depth +0
        0x00, 0x00, 0x00, 0x00, 0x00,             // 0107 // copied instructions
        0xe9, 0x00, 0x00, 0x00, 0x00,             // 0112 // jmp to end of load
        0x90,                                     // 0117 // nop
    };

    unsigned char jmpInstruction[sizeof(si.beforeFadeOutAllBytes)] = {0xe9, 0x00, 0x00, 0x00, 0x00};

    uint32_t stdStringCapacity = spacePerName - 1;
    memcpy(&forExtraMemory[sizeof(flashbackWaitInstructions) + 20], &stdStringCapacity, sizeof(uint32_t));

    uint32_t startOffset = sizeof(flashbackWaitInstructions) + 64; // 64 bytes used for std::string object + padding

    memcpy(&flashbackWaitInstructions[6], si.gettingSoundHandler, sizeof(si.gettingSoundHandler) - !(si.isSteamVersion));

    uint32_t firstFlashbackNameLocation = extraMemoryLocation + startOffset;
    memcpy(&flashbackWaitInstructions[24], &firstFlashbackNameLocation, sizeof(uint32_t));
    memcpy(&flashbackWaitInstructions[92], &firstFlashbackNameLocation, sizeof(uint32_t));

    uint32_t stringObjectPtrLocation = extraMemoryLocation + sizeof(flashbackWaitInstructions);
    memcpy(&flashbackWaitInstructions[34], &stringObjectPtrLocation, sizeof(uint32_t));
    memcpy(&flashbackWaitInstructions[54], &stringObjectPtrLocation, sizeof(uint32_t));

    uint32_t flashbackNameSizeOffset = spacePerName - 8;
    memcpy(&flashbackWaitInstructions[40], &flashbackNameSizeOffset, sizeof(uint32_t));

    uint32_t stringObjectSizeLocation = extraMemoryLocation + sizeof(flashbackWaitInstructions) + 16;
    memcpy(&flashbackWaitInstructions[46], &stringObjectSizeLocation, sizeof(uint32_t));

    uint32_t isPlayingOffset = si.isPlayingLocation - (extraMemoryLocation + 63);
    memcpy(&flashbackWaitInstructions[59], &isPlayingOffset, sizeof(isPlayingOffset));

    memcpy(&flashbackWaitInstructions[67], &spacePerName, sizeof(spacePerName));

    uint32_t endOfFlashbackNames = extraMemoryLocation + startOffset + (howManyNames * spacePerName);
    memcpy(&flashbackWaitInstructions[73], &endOfFlashbackNames, sizeof(uint32_t));

    memcpy(&flashbackWaitInstructions[85], si.sleepCallBytes, sizeof(si.sleepCallBytes));

    memcpy(&flashbackWaitInstructions[107], si.loadEndBytes, sizeof(si.loadEndBytes));

    uint32_t loadEndOffset = (si.loadEndLocation + sizeof(si.loadEndBytes)) - ((size_t)extraMemoryLocation + 117);
    memcpy(&flashbackWaitInstructions[113], &loadEndOffset, sizeof(loadEndOffset));

    memset(&flashbackWaitInstructions[118], 0xcc, sizeof(flashbackWaitInstructions) - 118); // int3

    memcpy(forExtraMemory, flashbackWaitInstructions, sizeof(flashbackWaitInstructions));

    SIZE_T bytesWritten = 0;
    bool wpmSucceeded = false;

    wpmSucceeded = WriteProcessMemory(
        ph.processHandle,
        (LPVOID)extraMemoryLocation,
        (LPCVOID)forExtraMemory,
        extraMemorySize,
        nullptr
    );

    if (!wpmSucceeded)
    {
        printf("error when calling WriteProcessMemory to write to allocated virtual page(s): %d\nat memory address: %u\n", GetLastError(), extraMemoryLocation);
        return false;
    }

    uint32_t offsetFromCheckMapChange = (extraMemoryLocation + 0) - (si.loadEndLocation + 5);
    memcpy(&jmpInstruction[1], &offsetFromCheckMapChange, sizeof(offsetFromCheckMapChange));

    wpmSucceeded = WriteProcessMemory(
        ph.processHandle,
        (LPVOID)si.loadEndLocation,
        (LPCVOID)jmpInstruction,
        sizeof(si.loadEndBytes),
        &bytesWritten
    );

    if (bytesWritten < sizeof(si.loadEndBytes))
    {
        printf("JMP INSTRUCTION ONLY PARTIALLY WRITTEN IN CHECKMAPCHANGE\nRESTART AMNESIA OR IT WILL CRASH ON MAP CHANGE\nerror: %d\n", GetLastError());
        return false;
    }
    else if (!wpmSucceeded)
    {
        printf("error when calling WriteProcessMemory to write jmp instruction in CheckMapChange: %d\nat memory address: %u\n", GetLastError(), si.loadEndLocation);
        return false;
    }

    return true;
}

bool injectWhileSuspended(ProcessHelper& ph, SavedInstructions& si, LPVOID& extraMemoryLocation, bool skipFlashbacks)
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

    uint32_t howManyNames = 0;
    uint32_t longestName = 0;
    uint32_t spacePerName = 0;
    uint32_t nameAreaOffset = 0;
    uint32_t extraMemorySize = 0;
    std::unique_ptr<unsigned char[]> forExtraMemory;

    // FileHelper<char> object is only used in this area, so this scope is used so it doesn't stay allocated longer than it's needed
    {
        FileHelper<char> fh(flashbackNameFile);
        preprocessFlashbackNames(fh, howManyNames, longestName);

        if (howManyNames == 0)
        {
            printf("no flashback line names found in %s\n", flashbackNameFile);
            return false;
        }

        spacePerName = (((longestName + 9) / 64) + (((longestName + 9) % 64) != 0)) * 64; // 8 bytes to store name size, 1 byte for null character
        nameAreaOffset = (skipFlashbacks ? flashbackSkipInstructionsSize : flashbackWaitInstructionsSize) + 64; // 64 bytes to store string object plus padding
        extraMemorySize = nameAreaOffset + (spacePerName * howManyNames);

        forExtraMemory = std::make_unique<unsigned char[]>(extraMemorySize);

        if (!setFlashbackNames(forExtraMemory.get(), fh, nameAreaOffset, spacePerName, extraMemorySize))
        {
            return false;
        }
    }

    extraMemoryLocation = VirtualAllocEx(
        ph.processHandle,
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
        injectionSucceeded = injectSkipInstructions(forExtraMemory.get(), si, ph, howManyNames, spacePerName, (uint32_t)extraMemoryLocation, extraMemorySize);
    }
    else
    {
        injectionSucceeded = injectWaitInstructions(forExtraMemory.get(), si, ph, howManyNames, spacePerName, (uint32_t)extraMemoryLocation, extraMemorySize);
    }

    if (!injectionSucceeded)
    {
        bool extraMemoryFreed = VirtualFreeEx(
            ph.processHandle,
            extraMemoryLocation,
            0,
            MEM_RELEASE
        );
        extraMemoryLocation = nullptr;
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
    LPVOID extraMemoryLocation = nullptr; // this is here so the virtual pages can be released in the catch block if an unexpected error happens
    HANDLE amnesiaHandle = nullptr; // needed when catching exception

    try
    {
        // LiveSplit uses these functions, so they're probably safe to use even though they're undocumented
        NTFUNCTION NtSuspendProcess = nullptr;
        NTFUNCTION NtResumeProcess = nullptr;

        SavedInstructions si;

        DWORD amnesiaPid = findAmnesiaPid(si);

        if (amnesiaPid == (DWORD)-1)
        {
            return (DWORD)-1;
        }

        ProcessHelper ph(amnesiaPid, (si.isSteamVersion ? steamName : nosteamName));

        amnesiaHandle = ph.processHandle;

        bool ntFunctionsFound = findNtFunctions(NtSuspendProcess, NtResumeProcess);

        if (ntFunctionsFound)
        {
            NtSuspendProcess(ph.processHandle);
        }

        bool injectionSucceeded = injectWhileSuspended(ph, si, extraMemoryLocation, skipFlashbacks);

        if (ntFunctionsFound)
        {
            NtResumeProcess(ph.processHandle);
        }

        return injectionSucceeded ? amnesiaPid : (DWORD)-1;
    }
    catch (const std::runtime_error& e)
    {
        char const* fixC4101Warning = e.what();
        printf("unexpected error: %s\n", fixC4101Warning);

        if (extraMemoryLocation)
        {
            bool extraMemoryFreed = VirtualFreeEx(
                amnesiaHandle,
                extraMemoryLocation,
                0,
                MEM_RELEASE
            );
            extraMemoryLocation = nullptr;
            if (!extraMemoryFreed)
            {
                printf("WARNING: error when using VirtualFreeEx: %d\ncouldn't release VirtualAllocEx memory\n", GetLastError());
            }
        }
    }

    return (DWORD)-1;
}
