#include "injector.h"

bool ManualMapDll(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize) {
	BYTE* pTargetBase = nullptr;
	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, FileSize + 0x8000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!pTargetBase) {
		printf("Failed Allocating Memory!");
		return false;
	}

	DWORD oldp = 0;
	VirtualProtectEx(hProc, pTargetBase, FileSize + 0x8000, PAGE_EXECUTE_READWRITE, &oldp);

	if (!WriteProcessMemory(hProc, pTargetBase, pSrcData, FileSize, nullptr)) {
		printf("Failed Writing File Header!\n");
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}
	printf("Mapped DLL @ %X\n", pTargetBase);

	//pTargetBase + 0x1E000 = Address of LoadLibraryA Import Call
	if (!WriteProcessMemory(hProc, pTargetBase + 0x1E000, LoadLibraryAShellCode, 0x2000, nullptr)) {
		printf("Failed Writing Shellcode 0x01!\n");
		return false;
	}

	//pTargetBase + 0x1ED7A = Address of MessageBoxA Import Call
	if (!WriteProcessMemory(hProc, pTargetBase + 0x1ED7A, MessageBoxAShellCode, 0x2000, nullptr)) {
		printf("Failed Writing Shellcode 0x02!\n");
		return false;
	}

	MANUAL_MAPPING_DATA data{ 0 };
	data.pbase = pTargetBase;
	data.fdwReasonParam = DLL_PROCESS_ATTACH;
	data.reservedParam = 0;

	//Mapping params
	BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!MappingDataAlloc) {
		printf("Failed Allocating Memory For Mapping Data!\n");
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	if (!WriteProcessMemory(hProc, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
		printf("Failed Writing Mapping Data!\n");
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		return false;
	}

	//Shell code
	void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode) {
		printf("Failed Memory Alloc For Shellcode!\n");
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		return false;
	}

	if (!WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr)) {
		printf("Failed Writing Shellcode 0x03!\n");
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return false;
	}

	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), MappingDataAlloc, 0, nullptr);
	if (!hThread) {
		printf("Failed Creating Thread!\n");
		VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
		return false;
	}
	CloseHandle(hThread);

	printf("Thread Created @ %p\n", pShellcode);
	return true;
}

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData) {
	BYTE* pBase = pData->pbase;
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + 0x1000); // Address of EP  (Entry Point)
	_DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);
}

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void __stdcall MessageBoxAShellCode(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR  Buffer;
	} UNICODE_STRING, * PUNICODE_STRING;

	typedef unsigned char BYTE;
	typedef BYTE* PBYTE;
	typedef int (WINAPI* MessageBoxA_t)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

	PBYTE pPEB = (PBYTE)__readgsqword(0x60);
	PBYTE pLdr = *(PBYTE*)(pPEB + 0x18);
	PBYTE pModuleList = *(PBYTE*)(pLdr + 0x10);
	PBYTE pModule = *(PBYTE*)pModuleList;
	HMODULE User32 = NULL;

	while (pModule != pModuleList) {
		PBYTE pBaseAddress = *(PBYTE*)(pModule + 0x30);
		PUNICODE_STRING pModuleName = (PUNICODE_STRING)(pModule + 0x58);

		if (pModuleName->Buffer == NULL) {
			return;
		}

		char moduleName[256] = { 0 };
		int count = 0;
		wchar_t* buffer = pModuleName->Buffer;

		for (USHORT i = 0; i < pModuleName->Length / sizeof(wchar_t); ++i) {
			wchar_t wc = buffer[i];
			if (wc < 0x80 && count < sizeof(moduleName) - 1) {
				moduleName[count++] = (char)wc;
			}
		}

		if (count == 10 &&
			(moduleName[0] | 0x20) == 'u' &&
			(moduleName[1] | 0x20) == 's' &&
			(moduleName[2] | 0x20) == 'e' &&
			(moduleName[3] | 0x20) == 'r' &&
			(moduleName[4] | 0x20) == '3' &&
			(moduleName[5] | 0x20) == '2' &&
			(moduleName[6] | 0x20) == '.' &&
			(moduleName[7] | 0x20) == 'd' &&
			(moduleName[8] | 0x20) == 'l' &&
			(moduleName[9] | 0x20) == 'l') {
			User32 = (HMODULE)pBaseAddress;
			break;
		}

		pModule = *(PBYTE*)pModule;
	}

	if (!User32) {
		return;
	}

	PBYTE pBaseAddress = (PBYTE)User32;
	MessageBoxA_t MessageBoxAPtr = (MessageBoxA_t)(pBaseAddress + 0x7A3B0);//User32 Base address + 0x7A3B0 = MessageBoxA import address

	if (MessageBoxAPtr) {
		MessageBoxAPtr(hWnd, lpText, lpCaption, uType);
	}
}

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
void __stdcall LoadLibraryAShellCode(LPCSTR lpLibFileName) {
	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR  Buffer;
	} UNICODE_STRING, * PUNICODE_STRING;

	typedef unsigned char BYTE;
	typedef BYTE* PBYTE;
	typedef HMODULE(*LoadLibraryA_t)(LPCSTR lpLibFileName);

	PBYTE pPEB = (PBYTE)__readgsqword(0x60);
	PBYTE pLdr = *(PBYTE*)(pPEB + 0x18);
	PBYTE pModuleList = *(PBYTE*)(pLdr + 0x10);
	PBYTE pModule = *(PBYTE*)pModuleList;
	HMODULE Kernel32 = NULL;

	while (pModule != pModuleList) {
		PBYTE pBaseAddress = *(PBYTE*)(pModule + 0x30);
		PUNICODE_STRING pModuleName = (PUNICODE_STRING)(pModule + 0x58);

		if (pModuleName->Buffer == NULL) {
			return;
		}

		char moduleName[256] = { 0 };
		int count = 0;
		wchar_t* buffer = pModuleName->Buffer;

		for (USHORT i = 0; i < pModuleName->Length / sizeof(wchar_t); ++i) {
			wchar_t wc = buffer[i];
			if (wc < 0x80 && count < sizeof(moduleName) - 1) {
				moduleName[count++] = (char)wc;
			}
		}

		if (count == 12 &&
			(moduleName[0] | 0x20) == 'k' &&
			(moduleName[1] | 0x20) == 'e' &&
			(moduleName[2] | 0x20) == 'r' &&
			(moduleName[3] | 0x20) == 'n' &&
			(moduleName[4] | 0x20) == 'e' &&
			(moduleName[5] | 0x20) == 'l' &&
			(moduleName[6] | 0x20) == '3' &&
			(moduleName[7] | 0x20) == '2' &&
			(moduleName[8] | 0x20) == '.' &&
			(moduleName[9] | 0x20) == 'd' &&
			(moduleName[10] | 0x20) == 'l' &&
			(moduleName[11] | 0x20) == 'l') {
			Kernel32 = (HMODULE)pBaseAddress;
			break;
		}

		pModule = *(PBYTE*)pModule;
	}

	if (!Kernel32) {
		return;
	}

	PBYTE pBaseAddress = (PBYTE)Kernel32;
	LoadLibraryA_t LoadLibraryAPtr = LoadLibraryA_t(pBaseAddress + 0x192C0);//kernel32 base address + 0x192C0 = LoadLibrary import address

	if (LoadLibraryAPtr) {
		LoadLibraryAPtr(lpLibFileName);
	}
}