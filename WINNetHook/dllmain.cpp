// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <windows.h>
#include <detours.h>
#include <WinInet.h>
#include "CDMLogInfo.h"

#pragma comment(lib,"detours.lib") 
#pragma comment( lib, "WinInet.lib")

static CCDMLogInfo* g_log = NULL;
static BOOL (WINAPI* PFN_HttpSendRequestW)(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength ) = HttpSendRequestW;  
static BOOL (WINAPI* PFN_HttpSendRequestExW)( __in HINTERNET hRequest, __in_opt LPINTERNET_BUFFERSW lpBuffersIn, __out_opt LPINTERNET_BUFFERSW lpBuffersOut, __in DWORD dwFlags, __in_opt DWORD_PTR dwContext) = HttpSendRequestExW;
static BOOL (WINAPI* PFN_HttpSendRequestA)(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength ) = HttpSendRequestA;  
static BOOL (WINAPI* PFN_HttpSendRequestExA)( __in HINTERNET hRequest, __in_opt LPINTERNET_BUFFERSA lpBuffersIn, __out_opt LPINTERNET_BUFFERSA lpBuffersOut, __in DWORD dwFlags, __in_opt DWORD_PTR dwContext) = HttpSendRequestExA;  

static LONG dwSlept = 0;
static DWORD (WINAPI * TrueSleepEx)(DWORD dwMilliseconds, BOOL bAlertable) = SleepEx;

BOOL WINAPI Hook_HttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength ){
	g_log->SetNotify("Hook_HttpSendRequestW////////////////");
	BOOL result = PFN_HttpSendRequestW(hRequest, lpszHeaders,dwHeadersLength,lpOptional,dwOptionalLength);	
	return result;
}

BOOL WINAPI Hook_HttpSendRequestExW( __in HINTERNET hRequest, __in_opt LPINTERNET_BUFFERSW lpBuffersIn, __out_opt LPINTERNET_BUFFERSW lpBuffersOut, __in DWORD dwFlags, __in_opt DWORD_PTR dwContext){	
	g_log->SetNotify("HttpSendRequestExW////////////////");
	BOOL result = PFN_HttpSendRequestExW(hRequest, lpBuffersIn, lpBuffersOut, dwFlags,dwContext);	
	return result;
}

BOOL WINAPI Hook_HttpSendRequestA(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength ){
	g_log->SetNotify("Hook_HttpSendRequestA////////////////");
	BOOL result = PFN_HttpSendRequestA(hRequest, lpszHeaders,dwHeadersLength,lpOptional,dwOptionalLength);	
	return result;
}

BOOL WINAPI Hook_HttpSendRequestExA( __in HINTERNET hRequest, __in_opt LPINTERNET_BUFFERSA lpBuffersIn, __out_opt LPINTERNET_BUFFERSA lpBuffersOut, __in DWORD dwFlags, __in_opt DWORD_PTR dwContext){	
	g_log->SetNotify("HttpSendRequestExA////////////////");
	BOOL result = PFN_HttpSendRequestExA(hRequest, lpBuffersIn, lpBuffersOut, dwFlags,dwContext);	
	return result;
}

DWORD WINAPI TimedSleepEx(DWORD dwMilliseconds, BOOL bAlertable)
{
    DWORD dwBeg = GetTickCount();
    DWORD ret = TrueSleepEx(dwMilliseconds, bAlertable);
    DWORD dwEnd = GetTickCount();

    InterlockedExchangeAdd(&dwSlept, dwEnd - dwBeg);

	g_log->SetNotify("++++++++++++++++++++++++++");
    return ret;
}

void AttachWinnet(){
	 g_log = CCDMLogInfo::GetInstance("c:\\hook.log");	
	 if(HttpSendRequestExW != NULL){
		  g_log->SetNotify("HttpSendRequestExW not NULL");
	 }
	 DetourAttach(&(PVOID&)PFN_HttpSendRequestW, Hook_HttpSendRequestW);
	 DetourAttach(&(PVOID&)PFN_HttpSendRequestExW, Hook_HttpSendRequestExW);
	 DetourAttach(&(PVOID&)PFN_HttpSendRequestA, Hook_HttpSendRequestA);
	 DetourAttach(&(PVOID&)PFN_HttpSendRequestExA, Hook_HttpSendRequestExA);

	 DetourAttach(&(PVOID&)TrueSleepEx, TimedSleepEx);
}

void DetachWinnet(){
	 if(g_log != NULL){
		 g_log->Release();
		 g_log = NULL;
	 }

	 DetourDetach(&(PVOID&)PFN_HttpSendRequestW, Hook_HttpSendRequestW);
	 DetourDetach(&(PVOID&)PFN_HttpSendRequestExW, Hook_HttpSendRequestExW);
	 DetourDetach(&(PVOID&)PFN_HttpSendRequestA, Hook_HttpSendRequestA);
	 DetourDetach(&(PVOID&)PFN_HttpSendRequestExA, Hook_HttpSendRequestExA);

	 DetourDetach(&(PVOID&)TrueSleepEx, TimedSleepEx);
}



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  dwReason,
                       LPVOID lpReserved
					 )
{
	 if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH) {
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
		AttachWinnet();
        LONG error = DetourTransactionCommit();
		 if (error == NO_ERROR) {
            g_log->SetNotify("Attach succeed !");
        }
        else {
             g_log->SetNotify("Attach failed !");
        }
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
		DetachWinnet();
        DetourTransactionCommit();
    }
    return TRUE;

}

