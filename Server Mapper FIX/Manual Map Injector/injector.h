#pragma once
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <fstream>

using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);
struct MANUAL_MAPPING_DATA {
	BYTE* pbase;
	DWORD fdwReasonParam;
	LPVOID reservedParam;
};

bool ManualMapDll(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize);
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData);
void __stdcall LoadLibraryAShellCode(LPCSTR lpLibFileName);
void __stdcall MessageBoxAShellCode(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);