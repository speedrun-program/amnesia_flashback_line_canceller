
#include <tchar.h>
#include <cstdio>
#include <climits>
// easyhook.h installed with NuGet
// https://easyhook.github.io/documentation.html
#include <easyhook.h>
#include <windows.h>
#include <tlhelp32.h>

// QueryFullProcessImageName doesn't work with easyhook, so this is in a different cpp file
#include "code_injection.h"

void getExitInput()
{
	int ch = 0;
	printf("Press Enter to exit\n");
	ch = getchar();
}

bool readSettings(FILE* f, bool& skipFlashbacks, bool& delayFiles)
{
	char buffer[35]{}; // the file should say "skip flashbacks: x, delay files: x", with either x being either y or n

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
	bool skipFlashbacks = false;
	bool delayFiles = false;

	FILE* f = nullptr;
	if (fopen_s(&f, "settings.txt", "rb") != 0 || !f)
	{
		printf("error when using fopen_s to open settings.txt for reading: %d\n", GetLastError());
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
			printf("error when using fopen_s to open settings.txt for writing: %d\n", GetLastError());
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

	WCHAR* dllToInject32 = nullptr;
	WCHAR* dllToInject64 = nullptr;

	// the first wchar_t is used to store the size of the path so the DLL can check if it got fully sent
	wchar_t pathBuffer[300]{};

	// - 1 for null character
	DWORD getModuleFileNameResult = GetModuleFileName(nullptr, &pathBuffer[1], (sizeof(pathBuffer) / sizeof(wchar_t)) - 1);

	// - 2 for the size character at the start and the null character
	if (getModuleFileNameResult >= (sizeof(pathBuffer) / sizeof(wchar_t)) - 2)
	{
		printf("this executable's file path was too long to be stored. It needs to be less than %zu characters\n", (sizeof(pathBuffer) / sizeof(wchar_t)) - 2);
	}

	DWORD binaryType = 0;
	BOOL getBinaryTypeResult = GetBinaryType(&pathBuffer[1], &binaryType);

	if (getBinaryTypeResult == 0 || (binaryType != 0 && binaryType != 6))
	{
		printf("ERROR: This exe wasn't identified as 32-bit or as 64-bit\n");
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

	wchar_t delaysFileName[] = L"files_and_delays.txt";
	wchar_t maxPathSize = ((sizeof(pathBuffer) - sizeof(delaysFileName)) / sizeof(wchar_t)) - 1; // - 1 for the size character at the start

	wchar_t pathSize = 0;
	for (wchar_t i = 1; pathBuffer[i] != '\0'; i++)
	{
		if (pathBuffer[i] == L'\\')
		{
			pathSize = i; // since i starts at 1, this size will include the last backslash
		}
	}

	if (pathSize == 0)
	{
		printf("failed to find any backslashes in file path\ncan't delay files\n");
		getExitInput();
		return EXIT_FAILURE;
	}

	if (pathSize >= maxPathSize)
	{
		printf("the file path to this executable is too long, it needs to be less than %d characters\ncan't delay files\n", maxPathSize);
		getExitInput();
		return EXIT_FAILURE;
	}

	pathBuffer[pathSize + 1] = L'\0';
	pathBuffer[0] = pathSize;
	
	NTSTATUS errorCode = RhInjectLibrary(
		pid,                      // The process to inject into
		0,                        // ThreadId to wake up upon injection
		EASYHOOK_INJECT_DEFAULT,
		dllToInject32,            // 32-bit
		dllToInject64,            // 64-bit
		pathBuffer,               // data to send to injected DLL entry point
		sizeof(pathBuffer)        // size of data to send
	);

	if (errorCode != 0)
	{
		printf("RhInjectLibrary failed with error code = %d\n", errorCode);
		PWCHAR errorMessage = RtlGetLastErrorString();
		printf("%ls\n", errorMessage);
		getExitInput();
		return EXIT_FAILURE;
	}

	printf("Library injected successfully.\n");
	getExitInput();
	return EXIT_SUCCESS;
}
