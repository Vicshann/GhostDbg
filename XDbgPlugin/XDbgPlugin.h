
#pragma once
 

#include <intrin.h>
#include "Utils.h"
#include "UniHook.h"
#include "FormatPE.h"
#include "GhostDbg.hpp"
#include "InjDllLdr.hpp"

//====================================================================================
#define CFGSECNAME "Parameters"
#define XDBGPLG_VER		 1
#define XDBGPLG_NAME     "GhostDbg"
#define XDBGPLG_BUILD    __DATE__ " - " __TIME__

#define MENU_ID_ENABLED		1
#define MENU_ID_ABOUT		2
#define MENU_ID_CHK_CANINJ  3
#define MENU_ID_CHK_CANINJNEW 4
#define MENU_ID_DBGCLIENT   16

//====================================================================================

//====================================================================================


void _stdcall LoadConfiguration(void);
void _stdcall SaveConfiguration(void);
int  _stdcall EnablePlugin(void);
int  _stdcall DisablePlugin(void);

int _stdcall LoadDbgClienConfig(void);
int _stdcall SetSingleConfig(UINT CfgID, UINT CfgType, PVOID CfgAddr);

DWORD WINAPI IPCQueueThread(LPVOID lpThreadParameter);

//------------------------------------------------------------------------------------
BOOL  WINAPI ProcDebugActiveProcess(DWORD dwProcessId);
BOOL  WINAPI ProcDebugActiveProcessStop(DWORD dwProcessId);
BOOL  WINAPI ProcWaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds);
BOOL  WINAPI ProcContinueDebugEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus);
BOOL  WINAPI ProcDebugBreakProcess(HANDLE Process);
BOOL  WINAPI ProcTerminateProcess(HANDLE hProcess, UINT uExitCode);
BOOL  WINAPI ProcCreateProcessA(LPCSTR lpApplicationName,LPSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,LPCSTR lpCurrentDirectory,LPSTARTUPINFOA lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation);
BOOL  WINAPI ProcCreateProcessW(LPCWSTR lpApplicationName,LPWSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation);

NTSTATUS NTAPI ProcNtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
NTSTATUS NTAPI ProcNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
NTSTATUS NTAPI ProcNtFlushVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, PIO_STATUS_BLOCK IoStatus);
NTSTATUS NTAPI ProcNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
NTSTATUS NTAPI ProcNtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI ProcNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI ProcNtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
NTSTATUS NTAPI ProcNtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);
NTSTATUS NTAPI ProcNtGetContextThread(HANDLE ThreadHandle, PCONTEXT Context);
NTSTATUS NTAPI ProcNtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context);
NTSTATUS NTAPI ProcNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferLength, PSIZE_T ReturnLength);
NTSTATUS NTAPI ProcNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferLength, PSIZE_T ReturnLength);
NTSTATUS NTAPI ProcNtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus);;
NTSTATUS NTAPI ProcNtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
NTSTATUS NTAPI ProcNtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
NTSTATUS NTAPI ProcNtClose(HANDLE Handle);
//------------------------------------------------------------------------------------

//====================================================================================
