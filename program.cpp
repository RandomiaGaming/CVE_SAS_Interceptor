#include <windows.h>
#include <iostream>
#include <conio.h>
#include <tlhelp32.h>
using namespace std;

void PressAnyKey() {
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);

	DWORD originalConsoleMode;
	GetConsoleMode(hStdin, &originalConsoleMode);

	SetConsoleMode(hStdin, originalConsoleMode & ~ENABLE_ECHO_INPUT);

	(void)_getch();

	SetConsoleMode(hStdin, originalConsoleMode);
}

DWORD GetWinlogonPID() {
	DWORD processID = 0;
	const WCHAR* processName = L"winlogon.exe";

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe32)) {
		do {
			if (lstrcmp(pe32.szExeFile, processName) == 0) {
				processID = pe32.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}
	else {
		return 0;
	}

	CloseHandle(hSnapshot);
	return processID;
}

bool BreakWinlogon() {
	DWORD processID = GetWinlogonPID();

	if (!DebugActiveProcess(processID)) {
		return false;
	}

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	if (hProcess == NULL) {
		DebugActiveProcessStop(processID);
		return false;
	}

	if (!DebugBreakProcess(hProcess)) {
		CloseHandle(hProcess);
		DebugActiveProcessStop(processID);
		return false;
	}

	cout << "Successfully paused execution of winlogon.exe" << endl;
	cout << "Ctrl + Alt + Del (SAS) should be intercepted." << endl;
	cout << "Press any key to resume winlogon.exe." << endl;
	cout << "WARNING: Do not close this program without resuming winlogon.exe first. It will crash your computer!" << endl;

	PressAnyKey();

	CloseHandle(hProcess);
	DebugActiveProcessStop(processID);

	return true;
}

bool TakeSEDebugPrivilege() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tokenPrivileges;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		return false;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
		CloseHandle(hToken);
		return false;
	}

	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luid;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		CloseHandle(hToken);
		return false;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		CloseHandle(hToken);
		return false;
	}

	CloseHandle(hToken);
	return true;
}

bool IsAdmin()
{
	BOOL isAdmin = FALSE;
	PSID adminGroup = NULL;
	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

	if (AllocateAndInitializeSid(&ntAuthority, 2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&adminGroup))
	{
		if (!CheckTokenMembership(NULL, adminGroup, &isAdmin))
		{
			isAdmin = FALSE;
		}
		FreeSid(adminGroup);
	}

	return isAdmin;
}

bool RelaunchAsAdmin()
{
	TCHAR szPath[MAX_PATH];
	if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath)))
	{
		SHELLEXECUTEINFO sei = { sizeof(sei) };
		sei.lpVerb = L"runas";
		sei.lpFile = szPath;
		sei.hwnd = NULL;
		sei.nShow = SW_NORMAL;
		return ShellExecuteEx(&sei);
	}
}

int main() {
	if (!IsAdmin()) {
		if (!RelaunchAsAdmin()) {
			cerr << "ERROR: Administrator access is required to pause winlogon.exe." << endl;
			return 1;
		}
		else {
			cout << "Restarting as administrator with UAC." << endl;
			return 0;
		}
	}
	if (!TakeSEDebugPrivilege()) {
		cerr << "ERROR: Failed to get debugging privlages." << endl;
		return 1;
	}

	if (!BreakWinlogon()) {
		cerr << "ERROR: Failed to pause execution of winlogon.exe." << endl;
		return 1;
	}

	return 0;
}