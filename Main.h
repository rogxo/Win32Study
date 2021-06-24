#pragma once
#include"Windows.h"
#include"stdio.h"
#include"tlhelp32.h"
#include"stdlib.h"

BOOL GetWndPid(LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD& dwPid);
BOOL GetSnapshotPid(const WCHAR ProcessName[MAX_PATH], DWORD& dwPid);
DWORD GetProcessModuleBaseAddress(DWORD dwPid, const WCHAR ModuleName[MAX_MODULE_NAME32 + 1]);
BOOL RemoteThreadDllInject(const WCHAR* ProcessName);


BOOL MyLoadLibrary(const WCHAR DllName[MAX_PATH])
{
	typedef void (*func)(LPCWSTR);
	HMODULE hDll = LoadLibrary(DllName);
	if (hDll == NULL)
	{
		return FALSE;
	}
	func f = (func)GetProcAddress(hDll, "MyMessageBox");
	f(L"CAONIMA");
	return TRUE;
}

BOOL RemoteThreadDllInject(const WCHAR* ProcessName)
{
	DWORD dwPid = 0;
	GetSnapshotPid(ProcessName, dwPid);
	LPCWSTR dllpath = L"C:\\Users\\Administrator\\Desktop\\TFHack.dll";
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hProcess == NULL)
	{
		//printf("OpenProcess()  ERROR_CODE=%x\n", GetLastError());
		return FALSE;
	}
	LPVOID VMAddress = VirtualAllocEx(hProcess, NULL, ((wcslen(dllpath) + 1) * 2), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (VMAddress == NULL)
	{
		//printf("VirtualAllocEx()  ERROR_CODE=%x\n", GetLastError());
		return FALSE;
	}
	WriteProcessMemory(hProcess, VMAddress, dllpath, ((wcslen(dllpath) + 1) * 2), NULL);
	//FARPROC fAddress = GetProcAddress(GetModuleHandle(L"KERNEL32.dll"), "LoadLibraryW");
	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryW, VMAddress, 0, NULL);
	if (hRemoteThread == NULL)
	{
		//printf("CreateRemoteThread()  ERROR_CODE=%x\n", GetLastError());
		return FALSE;
	}
	WaitForSingleObject(hRemoteThread, 2000);
	VirtualFreeEx(hProcess, VMAddress, NULL, MEM_RELEASE);
	CloseHandle(hProcess);
	CloseHandle(hRemoteThread);
	return TRUE;
}

DWORD GetProcessModuleBaseAddress(DWORD dwPid, const WCHAR ModuleName[MAX_MODULE_NAME32 + 1])
{
	HANDLE hProcessModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);
	if (hProcessModuleSnap == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot() Fail! ERROR_CODE=%x", GetLastError());
		return FALSE;
	}
	MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
	if (!Module32First(hProcessModuleSnap, &me32))
	{
		CloseHandle(hProcessModuleSnap);
		return 0;
	}
	do {
		//wprintf(L"ModuleName=%s\tBaseAddress=%p\n",me32.szModule,me32.modBaseAddr);
		if (!wcscmp(ModuleName, me32.szModule))
		{
			//wprintf(L"ModuleName=%s\tBaseAddress=%p\n", me32.szModule, me32.modBaseAddr);
			return (DWORD)me32.modBaseAddr;
		}
	} while (Module32Next(hProcessModuleSnap, &me32));
	return 0;
}


BOOL GetWndPid(LPCWSTR lpClassName, LPCWSTR lpWindowName,DWORD &dwPid)
{
	HWND hWnd = FindWindow(lpClassName, lpWindowName);
	if (hWnd == NULL)
	{
		return FALSE;
	}
	GetWindowThreadProcessId(hWnd, &dwPid);
	return TRUE;
}


BOOL GetSnapshotPid(const WCHAR ProcessName[MAX_PATH], DWORD& dwPid)
{
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		//printf("CreateToolhelp32Snapshot() Fail! ERROR_CODE=%x\n", GetLastError());
		return FALSE;
	}
	PROCESSENTRY32 pe32;
	ZeroMemory(&pe32, sizeof(pe32));
	pe32.dwSize = sizeof(pe32);
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return FALSE;
	}
	do {
		if (!wcscmp(pe32.szExeFile, ProcessName))
		{
			dwPid = pe32.th32ProcessID;
			return TRUE;
		}
	} while (Process32Next(hProcessSnap, &pe32));
	return FALSE;
}