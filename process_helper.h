
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <windows.h>
#include <psapi.h>

class ProcessHelper
{
public:
    const wchar_t* processName = nullptr;
    std::unique_ptr<unsigned char[]> buffer;
    HANDLE processHandle = nullptr;
    uint32_t memoryOffset = 0;
    uint32_t bytesLeft = 0;
    uint32_t processMemoryLocation = (uint32_t)-1;
    DWORD pageSize = 0;
    DWORD bufferPosition = 0;

    ProcessHelper(const ProcessHelper& fhelper) = delete;
    ProcessHelper& operator=(ProcessHelper other) = delete;
    ProcessHelper(ProcessHelper&&) = delete;
    ProcessHelper& operator=(ProcessHelper&&) = delete;

    ProcessHelper(const DWORD pid, const wchar_t* processNameCString)
    {
        processHandle = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_SUSPEND_RESUME,
            false,
            pid
        );

        if (processHandle == nullptr)
        {
            printf("ProcessHelper couldn't get process handle for %ls with PID %u:\n", processName, pid);
            throw std::runtime_error("ProcessHelper OpenProcess failure in constructor");
        }

        processName = processNameCString;
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        pageSize = sysInfo.dwPageSize;

        if (!checkIfProcessIsCorrect())
        {
            throw std::runtime_error("OpenProcess opened an unexpected process");
        }

        buffer = std::make_unique<unsigned char[]>(pageSize);
        bufferPosition = pageSize; // this initial value lets the first read happen on the first call to getByte
    }

    ~ProcessHelper()
    {
        if (processHandle != nullptr)
        {
            CloseHandle(processHandle);
        }
    }

    bool checkIfProcessIsCorrect() const
    {
        DWORD filepathBufferSize = 512;
        std::unique_ptr<wchar_t[]> filepathBuffer;

        DWORD queryFullProcessImageNameResult = 0;
        if (processHandle != nullptr) // this check gets rid of warning C6387
        {
            while (queryFullProcessImageNameResult == 0)
            {
                filepathBuffer = std::make_unique<wchar_t[]>(filepathBufferSize);
                DWORD charactersWritten = filepathBufferSize - 1; // decremented for null character

                queryFullProcessImageNameResult = QueryFullProcessImageName(processHandle, 0, filepathBuffer.get(), &charactersWritten);
                if (queryFullProcessImageNameResult == 0)
                {
                    DWORD errorNumber = GetLastError();
                    if (errorNumber == 122) // buffer too small error
                    {
                        filepathBufferSize *= 2;
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

        wchar_t* filename = wcsrchr(filepathBuffer.get(), L'\\');
        filename = (filename != nullptr) ? filename + 1 : filepathBuffer.get();
        if (wcscmp(filename, processName) != 0)
        {
            printf("unexpected process name when checking it using GetModuleBaseName: %ls\n", filepathBuffer.get());
            return false;
        }

        return true;
    }

    bool findExecutableMemoryLocation()
    {
        DWORD filepathBufferSize = 512;
        std::unique_ptr<wchar_t[]> filepathBuffer = std::make_unique<wchar_t[]>(filepathBufferSize);

        uint32_t queryAddress = 0;
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQueryEx(processHandle, (LPCVOID)queryAddress, &mbi, sizeof(mbi)) == 0) // checking if VirtualQueryEx works
        {
            printf("error when using VirtualQueryEx: %d\n", GetLastError());
            return false;
        }
        
        // finding start of process memory
        DWORD charactersWritten = 0;
        size_t filepathLength = (size_t)-1;
        do
        {
            if (queryAddress != 0) // this check gets rid of warning C6387
            {
                bool filePathCopied = false;
                while (!filePathCopied)
                {
                    charactersWritten = GetMappedFileName(
                        processHandle,
                        (LPVOID)queryAddress,
                        filepathBuffer.get(),
                        filepathBufferSize - 1 // - 1 so there's always a L'\0' at the end
                    );
                    if (filepathBufferSize >= 32767) // this should never happen
                    {
                        break;
                    }
                    else if (filepathBufferSize - 1 == charactersWritten)
                    {
                        filepathBufferSize *= 2;
                        filepathBuffer = std::make_unique<wchar_t[]>(filepathBufferSize);
                    }
                    else
                    {
                        filePathCopied = true;
                    }
                }
            }
            
            wchar_t* filename = wcsrchr(filepathBuffer.get(), L'\\');
            filename = (filename != nullptr) ? filename + 1 : filepathBuffer.get();
            if (wcscmp(filename, processName) == 0)
            {
                filepathLength = charactersWritten;
                break;
            }

            queryAddress += mbi.RegionSize;
        } while (VirtualQueryEx(processHandle, (LPCVOID)queryAddress, &mbi, sizeof(mbi)) != 0);

        if (filepathLength == (size_t)-1)
        {
            printf("couldn't find process memory location\n");
            return false;
        }
        
        // finding the .text area
        std::unique_ptr<wchar_t[]> filepathBufferCopy = std::make_unique<wchar_t[]>(filepathBufferSize);
        memcpy(filepathBufferCopy.get(), filepathBuffer.get(), filepathBufferSize * sizeof(wchar_t));
        
        do
        {
            if (mbi.Protect == PAGE_EXECUTE_READ)
            {
                processMemoryLocation = queryAddress;
                bytesLeft = mbi.RegionSize;
                memoryOffset = queryAddress - pageSize; // this will overflow to 0 on the first call to getByte
                return true;
            }

            if (queryAddress != 0) // this check gets rid of warning C6387
            {
                charactersWritten = GetMappedFileName(
                    processHandle,
                    (LPVOID)queryAddress,
                    &filepathBuffer[0],
                    filepathBufferSize
                );
            }

            // no longer looking at exe memory
            if (charactersWritten != filepathLength || wcscmp(filepathBuffer.get(), filepathBufferCopy.get()) != 0)
            {
                break;
            }

            queryAddress += mbi.RegionSize;
        } while (VirtualQueryEx(processHandle, (LPCVOID)queryAddress, &mbi, sizeof(mbi)) != 0);

        printf("couldn't find .text area in process memory\n");
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
                processHandle,
                (LPCVOID)memoryOffset,
                (LPVOID)buffer.get(),
                pageSize,
                nullptr
            );

            if (!readSucceeded)
            {
                printf("ProcessHelper ReadProcessMemory error in getByte: %d\nat memory address: %u\n", GetLastError(), memoryOffset);
                return false;
            }
        }

        b = buffer[bufferPosition];
        bufferPosition++;
        bytesLeft--;

        return true;
    }
};
