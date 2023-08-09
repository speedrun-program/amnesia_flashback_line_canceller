
#include <cstdio>
#include <climits>
#include <mutex>
#include <thread>
#include <vector>
#include <memory>
#include <cstring>
#include <charconv>
#include <stdexcept>
#include <string_view>
#include <unordered_map>

#ifdef _WIN32
// easyhook.h installed with NuGet
// https://easyhook.github.io/documentation.html
#include <easyhook.h>
#include <windows.h>
using wcharOrChar = wchar_t; // file paths are UTF-16LE on Windows
using svType = std::wstring_view;
#define cmpFunction wcscmp
#else
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
using wcharOrChar = char;
using svType = std::string_view;
#define cmpFunction strcmp
static auto originalFopen = reinterpret_cast<FILE * (*)(const char* path, const char* mode)>(dlsym(RTLD_NEXT, "fopen"));
static auto originalFreopen = reinterpret_cast<FILE * (*)(const char* path, const char* mode, FILE * stream)>(dlsym(RTLD_NEXT, "freopen"));
static auto originalFopen64 = reinterpret_cast<FILE * (*)(const char* path, const char* mode)>(dlsym(RTLD_NEXT, "fopen64"));
static auto originalFreopen64 = reinterpret_cast<FILE * (*)(const char* path, const char* mode, FILE * stream)>(dlsym(RTLD_NEXT, "freopen64"));
#endif

using uPtrType = std::unique_ptr<wcharOrChar[]>;
using vectorType = std::vector<wcharOrChar>;

#ifdef _WIN32
wcharOrChar toolPath[300]{};
size_t toolPathLength = 0;
wcharOrChar delaysFileName[] = L"files_and_delays.txt";
wcharOrChar logFileName[] = L"dll_error_log.txt";
bool pathSuccessfullySent = false;
#else
wcharOrChar delaysFileName[] = "files_and_delays.txt";
wcharOrChar logFileName[] = "so_error_log.txt";
#endif

// using multiple cpp files made exe bigger, so definitions are in this header
#include "shared.h"

#ifdef _WIN32
static NTSTATUS WINAPI NtCreateFileHook(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength)
{
    static MapAndMutex mapAndMutexObject;

    const wchar_t* path = (const wchar_t*)(ObjectAttributes->ObjectName->Buffer);
    int pathEndIndex = (ObjectAttributes->ObjectName->Length) / sizeof(wchar_t);
    int filenameIndex = pathEndIndex - 1;

    for (; filenameIndex >= 0 && path[filenameIndex] != '\\'; filenameIndex--);

    filenameIndex++; // moving past '\\' character or to 0 if no '\\' was found
    auto it = mapAndMutexObject.fileMap.find(
        svType(path + filenameIndex,
        (size_t)pathEndIndex - filenameIndex)
    );

    if (it != mapAndMutexObject.fileMap.end())
    {
        mapAndMutexObject.delayFile(it->second);
    }
    
    return NtCreateFile(
        FileHandle,
        DesiredAccess,
        ObjectAttributes,
        IoStatusBlock,
        AllocationSize,
        FileAttributes,
        ShareAccess,
        CreateDisposition,
        CreateOptions,
        EaBuffer,
        EaLength
    );
}

extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo);

void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo)
{
    size_t dataSize = inRemoteInfo->UserDataSize;
    if (dataSize > sizeof(wchar_t))
    {
        wchar_t maxPathSize = (sizeof(toolPath) / sizeof(wchar_t)) - (sizeof(delaysFileName) / sizeof(wchar_t));
        wchar_t* sentPath = (wchar_t*)(inRemoteInfo->UserData);
        wchar_t sentPathSize = sentPath[0];

        if (dataSize == sizeof(toolPath) || sentPathSize < maxPathSize)
        {
            // microsoft documentation says not to use functions like memcpy when the DLL is being loaded
            for (wchar_t i = 0; i < sentPathSize; i++)
            {
                toolPath[i] = sentPath[i + 1];
            }

            toolPathLength = sentPathSize;
            pathSuccessfullySent = true;
        }
    }

    HOOK_TRACE_INFO hHook1 = {nullptr};
    HMODULE moduleHandle = GetModuleHandle(TEXT("ntdll"));

    if (moduleHandle)
    {
        LhInstallHook(
            GetProcAddress(moduleHandle, "NtCreateFile"),
            NtCreateFileHook,
            nullptr,
            &hHook1
        );
    }

    ULONG ACLEntries[1] = {0};
    LhSetExclusiveACL(ACLEntries, 1, &hHook1);
}
#else

static void sharedPathCheckingFunction(const char* path)
{
    static MapAndMutex mapAndMutexObject;
    
    int filenameIndex = -1;
    int pathEndIndex = 0;

    for (; path[pathEndIndex] != '\0'; pathEndIndex++)
    {
        if (path[pathEndIndex] == '/')
        {
            filenameIndex = pathEndIndex;
        }
    }

    filenameIndex++; // moving past '/' character or to 0 if no '/' was found
    auto it = mapAndMutexObject.fileMap.find(
        svType(path + filenameIndex,
            (size_t)pathEndIndex - filenameIndex)
    );

    if (it != mapAndMutexObject.fileMap.end())
    {
        mapAndMutexObject.delayFile(it->second);
    }
}

FILE* fopen(const char* path, const char* mode)
{
    sharedPathCheckingFunction(path);

    return originalFopen(path, mode);
}

FILE* freopen(const char* path, const char* mode, FILE* stream)
{
    sharedPathCheckingFunction(path);

    return originalFreopen(path, mode, stream);
}

FILE* fopen64(const char* path, const char* mode)
{
    sharedPathCheckingFunction(path);

    return originalFopen64(path, mode);
}

FILE* freopen64(const char* path, const char* mode, FILE* stream)
{
    sharedPathCheckingFunction(path);

    return originalFreopen64(path, mode, stream);
}
#endif
