
#pragma once
 
#include <intrin.h>
#include <Windows.h>
#include "Utils.h"
#include "UniHook.hpp"
#include "json.h"
#include "FormatPE.h"
#include "CompileTime.hpp"
#include "InjDllLdr.hpp"
#include "GhostDbg.hpp"

//====================================================================================
#define CFGFILE    ".InjLib.jsn"
#define LOGFILE    ".InjLib.log"

//====================================================================================
void _stdcall LoadConfiguration(void);
void _stdcall SaveConfiguration(int BinFmt=-1);
void _stdcall UnInitApplication(void);
bool _stdcall InitApplication(void);
int  _stdcall DbgUsrReqCallback(ShMem::CMessageIPC::SMsgHdr* Req, PVOID ArgA, UINT ArgB);
//------------------------------------------------------------------------------------
bool _cdecl ProcExpDispBefore(volatile PVOID ArgA, volatile PVOID ArgB, volatile PVOID ArgC, volatile PVOID ArgD, volatile PVOID RetVal);
bool _cdecl ProcExpDispAfter(volatile PVOID ArgA, volatile PVOID ArgB, volatile PVOID ArgC, volatile PVOID ArgD, volatile PVOID RetVal);
//__declspec(noreturn) VOID NTAPI ProcRtlRestoreContext(PCONTEXT ContextRecord, PEXCEPTION_RECORD ExceptionRecord);
//__declspec(noreturn) void _fastcall ProcKiUserExceptionDispatcher(void);
//__declspec(noreturn) void NTAPI ProcLdrInitializeThunk(PVOID ArgA, PVOID ArgB, PVOID ArgC, PVOID ArgD);
NTSTATUS NTAPI ProcNtContinue(PCONTEXT ContextRecord, BOOLEAN TestAlert);
//NTSTATUS NTAPI ProcNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);
NTSTATUS NTAPI ProcNtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus);
NTSTATUS NTAPI ProcNtGetContextThread(HANDLE ThreadHandle, PCONTEXT Context);
NTSTATUS NTAPI ProcNtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context);
NTSTATUS NTAPI ProcNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);
NTSTATUS NTAPI ProcNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
//====================================================================================
