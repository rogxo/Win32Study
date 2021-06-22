#include"windows.h"
#include"stdio.h"
#include"tlhelp32.h"
#include"stdlib.h"

BOOL MyLoadLibrary()
{
	typedef void (*func)(LPCWSTR);
	HMODULE hDll = LoadLibrary(L"Dll2.dll");
	if (hDll == NULL)
	{
		return FALSE;
	}
	func f = (func)GetProcAddress(hDll, "MyMessageBox");
	f(L"CAONIMA");
	return TRUE;
}

DWORD GetWndPid(LPCWSTR lpClassName,LPCWSTR lpWindowName)
{
	DWORD pid;
	HWND hWnd = FindWindow(lpClassName,lpWindowName);
	GetWindowThreadProcessId(hWnd, &pid);
	return pid;
}

DWORD GetSnapshotPid(WCHAR ProcessName[MAX_PATH])
{
	DWORD pid=0;
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot() Fail! ERROR_CODE=%x\n",GetLastError());
		return FALSE;
	}
	PROCESSENTRY32 pe32;
	ZeroMemory(&pe32, sizeof(pe32));
	pe32.dwSize = sizeof(pe32);
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		printf("Process32First() Fail\n");
		return FALSE;
	}
	do {
		if (!wcscmp(pe32.szExeFile,ProcessName))
		{
			pid = pe32.th32ProcessID;
			printf("Pid=%d\n", pid);
			return pid;
		}
	} while (Process32Next(hProcessSnap, &pe32));
	return 0;
}
DWORD GetProcessModuleBaseAddress(DWORD pid,WCHAR ModuleName[MAX_MODULE_NAME32+1])
{
	HANDLE hProcessModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (hProcessModuleSnap == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot() Fail! ERROR_CODE=%x", GetLastError());
		return FALSE;
	}
	MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
	if (!Module32First(hProcessModuleSnap,&me32))
	{
		CloseHandle(hProcessModuleSnap);
		printf("Module32First() Fail");
		return FALSE;
	}
	do {
		//wprintf(L"ModuleName=%s\tBaseAddress=%p\n",me32.szModule,me32.modBaseAddr);
		if (!wcscmp(ModuleName,me32.szModule))
		{
			wprintf(L"ModuleName=%s\tBaseAddress=%p\n",me32.szModule,me32.modBaseAddr);
			return (DWORD)me32.modBaseAddr;
		}
	} while (Module32Next(hProcessModuleSnap, &me32));
	return 0;
}

BOOL DllInject()
{
	DWORD pid = GetSnapshotPid((WCHAR *)L"SFGame.exe");
	//LPCWSTR dllpath = L"E:\\project\\VSProject\\Dll2\\Debug\\Dll2.dll";
	LPCWSTR dllpath = L"C:\\Users\\Administrator\\Desktop\\TFHack.dll";
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
	if (hProcess == NULL)
	{
		printf("OpenProcess()  ERROR_CODE=%x\n", GetLastError());
		return FALSE;
	}
	LPVOID VMAddress = VirtualAllocEx(hProcess,NULL, ((wcslen(dllpath) + 1) * 2),MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
	if (VMAddress == NULL)
	{
		printf("VirtualAllocEx()  ERROR_CODE=%x\n", GetLastError());
		return FALSE;
	}
	WriteProcessMemory(hProcess, VMAddress, dllpath, ((wcslen(dllpath)+1)*2), NULL);
	FARPROC fAddress = GetProcAddress(GetModuleHandle(L"KERNEL32.dll"), "LoadLibraryW");
	HANDLE hRemoteThread = CreateRemoteThread(hProcess,NULL,NULL,(LPTHREAD_START_ROUTINE)fAddress,VMAddress,0,NULL);
	if (hRemoteThread == NULL)
	{
		printf("CreateRemoteThread()  ERROR_CODE=%x\n", GetLastError());
		return FALSE;
	}
	WaitForSingleObject(hRemoteThread, 2000);
	VirtualFreeEx(hProcess, VMAddress,((wcslen(dllpath) + 1) * 2), MEM_RELEASE);
	CloseHandle(hProcess);
	CloseHandle(hRemoteThread);
	return TRUE;
}
BOOL TestTF()
{
	DWORD pid = GetSnapshotPid((WCHAR*)L"SFGame.exe");
	DWORD dwBaseAddress=GetProcessModuleBaseAddress(pid, (WCHAR*)L"SFGame.exe");
	DWORD dwTempAddress = 0;
	DWORD dwRetNum = 0;
	DWORD dwTemp=-1;
	DWORD AmmoNumber = 66;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	while (TRUE)
	{
		printf("%x\n", dwBaseAddress);
		ReadProcessMemory(hProcess, (LPVOID)((DWORD)(dwBaseAddress + 0x013ED5C4)), &dwTempAddress, 4,&dwRetNum);
		printf("%x\n", dwTempAddress);
		ReadProcessMemory(hProcess, (LPCVOID)(dwTempAddress + 0x228), &dwTempAddress, 4, &dwRetNum);
		printf("%x\n", dwTempAddress);
		ReadProcessMemory(hProcess, (LPCVOID)(dwTempAddress + 0x40C), &dwTempAddress, 4, &dwRetNum);
		printf("%x\n", dwTempAddress);
		ReadProcessMemory(hProcess, (LPVOID)(dwTempAddress + 0x358), &dwTemp, 4, &dwRetNum);
		printf("%d\n",dwTemp);
		WriteProcessMemory(hProcess, (LPVOID)(dwTempAddress + 0x358), &AmmoNumber, 4, NULL);
		Sleep(0);
		system("CLS");
	}
	return TRUE;
}

int main(int argc,char*argv[],char* envp)
{
	//DllInject();
	TestTF();
	return 0;
}
