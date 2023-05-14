
#include <tchar.h>
#include <iostream>
#include <format>
#include <climits>
// easyhook.h installed with NuGet
// https://easyhook.github.io/documentation.html
#include <easyhook.h>
#include <Windows.h>
#include <tlhelp32.h>

// QueryFullProcessImageName doesn't work with easyhook, so this is in a different cpp file
#include "code_injection.h"

#ifdef COMPILE_FOR_AMNESIA
DWORD findAmnesiaPid()
{
	const wchar_t steamName[] = L"Amnesia.exe";
	const wchar_t nosteamName[] = L"Amnesia_NoSteam.exe";

	PROCESSENTRY32 processEntry{};
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
	{
		std::printf("error when using CreateToolhelp32Snapshot: %d\n", GetLastError());
		return (DWORD)-1;
	}

	if (!Process32First(snapshot, &processEntry))
	{
		std::printf("error when using Process32First: %d\n", GetLastError());
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
	std::printf("couldn't find amnesia process\n");
	return (DWORD)-1;
}
#endif

void getExitInput()
{
	int ch = 0;
#ifndef COMPILE_FOR_AMNESIA
	for (; ch != '\n'; ch = std::getchar());
#endif
	std::printf("Press Enter to exit\n");
	ch = std::getchar();
}

bool readSettings(FILE* f, bool& skipFlashbacks, bool& delayFiles)
{
	char buffer[35]{};

	size_t charactersRead = fread(buffer, 1, 34, f);
	if (
		charactersRead < 34
		|| strncmp(buffer, "skip flashbacks: ", 17) != 0
		|| strncmp(&buffer[18], ", delay files: ", 15) != 0)
	{
		printf("%zu %d %d", charactersRead, strncmp(buffer, "skip flashbacks: ", 17), strncmp(&buffer[18], "delay files: ", 15));
		return false;
	}

	if (buffer[17] != 'y' && buffer[17] != 'Y' && buffer[17] != 'n' && buffer[17] != 'N')
	{
		printf("skip flashback setting needs to be either y or n\n");
		return false;
	}
	skipFlashbacks = (buffer[17] == 'y' || buffer[17] == 'Y');

	if (buffer[33] != 'y' && buffer[33] != 'Y' && buffer[33] != 'n' && buffer[33] != 'N')
	{
		printf("delay files setting needs to be either y or n\n");
		return false;
	}
	delayFiles = (buffer[33] == 'y' || buffer[33] == 'Y');

	return true;
}

int _tmain(int argc, _TCHAR* argv[])
{
	WCHAR* dllToInject32 = nullptr;
	WCHAR* dllToInject64 = nullptr;
	_TCHAR* applicationName = argv[0];
	DWORD binaryType = 0;
	BOOL getBinaryTypeResult = GetBinaryType(applicationName, &binaryType);

	if (getBinaryTypeResult == 0 || (binaryType != 0 && binaryType != 6))
	{
		std::printf("ERROR: This exe wasn't identified as 32-bit or as 64-bit\n");
		getExitInput();
		return EXIT_FAILURE;
	}
	else if (binaryType == 0)
	{
		dllToInject32 = (WCHAR*)L"load_extender_32.dll";
	}
	else
	{
		dllToInject64 = (WCHAR*)L"load_extender_64.dll";
	}

#ifdef COMPILE_FOR_AMNESIA
	bool skipFlashbacks = false;
	bool delayFiles = false;

	FILE* f = nullptr;
	if (fopen_s(&f, "settings.txt", "rb") != 0 || !f)
	{
		std::printf("error when using fopen_s to open settings.txt for reading: %d\n", GetLastError());
		getExitInput();
		return EXIT_FAILURE;
	}
	bool settingsReadSuccessfully = readSettings(f, skipFlashbacks, delayFiles);
	fclose(f);
	f = nullptr;

	if (!settingsReadSuccessfully)
	{
		if (fopen_s(&f, "settings.txt", "wb") != 0 || !f)
		{
			std::printf("error when using fopen_s to open settings.txt for writing: %d\n", GetLastError());
			getExitInput();
			return EXIT_FAILURE;
		}

		char correctSettingsText[] = "skip flashbacks: n, delay files: n";
		fwrite(correctSettingsText, 1, 34, f);
		fclose(f);
		f = nullptr;

		printf("settings.txt couldn't be read and was reset\n");
	}

	printf("flashbacks %s be skipped\nfiles %s be delayed\n", skipFlashbacks ? "will" : "won't", delayFiles ? "will" : "won't");

	DWORD pid = codeInjectionMain(skipFlashbacks);
	if (pid == (DWORD)-1)
	{
		getExitInput();
		return EXIT_FAILURE;
	}

	if (!delayFiles)
	{
		getExitInput();
		return EXIT_SUCCESS;
	}

#else
	std::printf("Enter the process Id: ");
	DWORD pid = 0;
	std::cin >> pid;
#endif
	
	NTSTATUS errorCode = RhInjectLibrary(
		pid,                     // The process to inject into
		0,                       // ThreadId to wake up upon injection
		EASYHOOK_INJECT_DEFAULT,
		dllToInject32,           // 32-bit
		dllToInject64,           // 64-bit
		nullptr,                 // data to send to injected DLL entry point
		0                        // size of data to send
	);

	if (errorCode != 0)
	{
		std::printf("RhInjectLibrary failed with error code = %d\n", errorCode);
		PWCHAR errorMessage = RtlGetLastErrorString();
		std::printf("%ls\n", errorMessage);
		getExitInput();
		return EXIT_FAILURE;
	}

	std::printf("Library injected successfully.\n");
	getExitInput();
	return EXIT_SUCCESS;
}
