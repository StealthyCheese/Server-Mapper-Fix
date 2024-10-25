#include "injector.h"

DWORD GetProcessIdByName(const std::wstring& name) {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return 0; // Handle error if necessary
	}

	if (Process32First(snapshot, &entry) == TRUE) {
		do {
			if (_wcsicmp(entry.szExeFile, name.c_str()) == 0) {
				CloseHandle(snapshot); // Clean up
				return entry.th32ProcessID;
			}
		} while (Process32Next(snapshot, &entry) == TRUE);
	}

	CloseHandle(snapshot);
	return 0;
}

int wmain(int argc, wchar_t* argv[], wchar_t* envp[]) {

	const char* dllPath = "test.bin";
	DWORD PID = GetProcessIdByName(L"winver.exe");
	if (PID == 0) {
		printf("Process not found\n");
		system("pause");
		return -1;
	}
	printf("Process pid: %d\n", PID);

	TOKEN_PRIVILEGES priv = { 0 };
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

		CloseHandle(hToken);
	}

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProc) {
		DWORD Err = GetLastError();
		printf("OpenProcess failed: 0x%X\n", Err);
		system("PAUSE");
		return -2;
	}

	if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES) {
		printf("Dll file doesn't exist\n");
		CloseHandle(hProc);
		system("PAUSE");
		return -4;
	}

	std::ifstream File(dllPath, std::ios::binary | std::ios::ate);

	if (File.fail()) {
		printf("Opening the file failed: %X\n", (DWORD)File.rdstate());
		File.close();
		CloseHandle(hProc);
		system("PAUSE");
		return -5;
	}

	auto FileSize = File.tellg();
	if (FileSize < 0x1000) {
		printf("Filesize invalid.\n");
		File.close();
		CloseHandle(hProc);
		system("PAUSE");
		return -6;
	}

	BYTE * pSrcData = new BYTE[(UINT_PTR)FileSize];
	if (!pSrcData) {
		printf("Can't allocate dll file.\n");
		File.close();
		CloseHandle(hProc);
		system("PAUSE");
		return -7;
	}

	File.seekg(0, std::ios::beg);
	File.read((char*)(pSrcData), FileSize);
	File.close();

	printf("Mapping...\n");
	if (!ManualMapDll(hProc, pSrcData, FileSize)) {
		delete[] pSrcData;
		CloseHandle(hProc);
		printf("Error while mapping.\n");
		system("PAUSE");
		return -8;
	}
	delete[] pSrcData;

	CloseHandle(hProc);
	printf("OK\n");
	system("PAUSE");
	return 0;
}
