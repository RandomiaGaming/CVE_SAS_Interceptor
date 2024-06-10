#include <windows.h>
#include <iostream>
#include <conio.h>
#include <tlhelp32.h>
using namespace std;

void PressAnyKey() {
	// Get a handle to the console.
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);

	// Get the original console mode.
	DWORD originalConsoleMode;
	GetConsoleMode(hStdin, &originalConsoleMode);

	// Set the console mode to not echo typed characters to the screen.
	SetConsoleMode(hStdin, originalConsoleMode & ~ENABLE_ECHO_INPUT);

	// Wait for the user to type a character.
	(void)_getch();

	// Restore the original console mode and return.
	SetConsoleMode(hStdin, originalConsoleMode);
}

DWORD GetWinlogonPID() {
	// Create a snapshot.
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	// Search through running processes using the snapshot.
	Process32First(snapshot, &processEntry);
	do {
		// If the current process is winlogon.exe return its PID.
		if (lstrcmp(processEntry.szExeFile, L"winlogon.exe") == 0) {
			DWORD winlogonPID = processEntry.th32ProcessID;
			CloseHandle(snapshot);
			return winlogonPID;
		}
	} while (Process32Next(snapshot, &processEntry));

	// Cleanup and return 0 because winlogon.exe could not be found.
	CloseHandle(snapshot);
	return 0;
}

void BreakWinlogon() {
	DWORD winlogonPID = GetWinlogonPID();

	// Attach debugger to winlogon
	DebugActiveProcess(winlogonPID);

	// Open process handle to winlogon
	HANDLE winlogonHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, winlogonPID);

	// Break winlogon
	DebugBreakProcess(winlogonHandle);

	cout << "Successfully paused execution of winlogon.exe" << endl;
	cout << "Ctrl + Alt + Del (SAS) should be intercepted." << endl;
	cout << "Press any key to resume winlogon.exe." << endl;
	cout << "WARNING: Do not close this program without resuming winlogon.exe first. It will crash your computer!" << endl;

	PressAnyKey();

	// Detach debugger
	DebugActiveProcessStop(winlogonPID);

	// Free handle
	CloseHandle(winlogonHandle);
}

void TakeSEDebugPrivilege() {
	// Get the current process token.
	HANDLE currentToken = NULL;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &currentToken);

	// Lookup the SE_Debug_Privilage luid.
	LUID debugPrivilageLUID;
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &debugPrivilageLUID);

	// Grant ourselves the SE_Debug_Privilage.
	TOKEN_PRIVILEGES tokenPrivileges;
	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = debugPrivilageLUID;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(currentToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

	// Cleanup and return.
	CloseHandle(currentToken);
}

BOOL IsAdmin()
{
	// Try to get the admin group SID. If that fails return false.
	PSID adminGroup = NULL;
	SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(&ntAuthority, 2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&adminGroup))
	{
		return FALSE;
	}

	// Try to figure out if we are in the admins groups. If that fails return false.
	BOOL output = FALSE;
	if (!CheckTokenMembership(NULL, adminGroup, &output))
	{
		FreeSid(adminGroup);
		return FALSE;
	}

	// Return the result of the check above.
	return output;
}

void RelaunchAsAdmin()
{
	// Get the path to the current exe
	TCHAR szPath[MAX_PATH];
	GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath));

	// Create a shell execute info to launch the current exe with a UAC prompt.
	SHELLEXECUTEINFO sei = { sizeof(SHELLEXECUTEINFO) };
	sei.lpVerb = L"runas";
	sei.lpFile = szPath;
	sei.nShow = SW_NORMAL;

	// Launch the shell execute info with the shell.
	ShellExecuteEx(&sei);
}

int main() {
	if (!IsAdmin()) {
		RelaunchAsAdmin();
		return 0;
	}

	TakeSEDebugPrivilege();

	BreakWinlogon();

	return 0;
}