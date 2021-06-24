#include "Main.h"

BOOL TestTF()
{
	DWORD dwPid=GetProcessPid(L"SFGame.exe");
	DWORD dwBaseAddress=GetProcessModuleBaseAddress(dwPid,L"SFGame.exe");
	DWORD dwTempAddress = 0;
	SIZE_T dwRetNum = 0;
	DWORD dwTemp=-1;
	DWORD AmmoNumber = 66;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
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
		Sleep(50);
		system("CLS");
	}
	return TRUE;
}

int main(int argc,char*argv[],char* envp)
{
	if(RemoteThreadDllInject(L"SFGame.exe",L"SpeedHack_2.dll"))
		printf("SUCCESS");
}
