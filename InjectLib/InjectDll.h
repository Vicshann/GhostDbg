
#pragma once
 
#include <intrin.h>
#include "Utils.h"
#include "json.h"
#include "UniHook.h"
#include "FormatPE.h"
#include "GhostDbg.hpp"
#include "InjDllLdr.hpp"

//====================================================================================
#define CFGFILE    "InjLib.jsn"
#define LOGFILE    " - InjLib.log"

//====================================================================================
void _stdcall LoadConfiguration(void);
void _stdcall SaveConfiguration(int BinFmt=-1);
void _stdcall UnInitApplication(void);
bool _stdcall InitApplication(void);
int  _stdcall DbgUsrReqCallback(ShMem::CMessageIPC::SMsgHdr* Req, PVOID ArgA, UINT ArgB);
//------------------------------------------------------------------------------------
//__declspec(noreturn) VOID NTAPI ProcRtlRestoreContext(PCONTEXT ContextRecord, PEXCEPTION_RECORD ExceptionRecord);
//__declspec(noreturn) void _fastcall ProcKiUserExceptionDispatcher(void);
//__declspec(noreturn) void NTAPI ProcLdrInitializeThunk(PVOID ArgA, PVOID ArgB, PVOID ArgC, PVOID ArgD);
BOOLEAN  NTAPI ProcRtlDispatchException(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT ContextRecord);
NTSTATUS NTAPI ProcNtContinue(PCONTEXT ContextRecord, BOOLEAN TestAlert);
NTSTATUS NTAPI ProcNtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus);
NTSTATUS NTAPI ProcNtGetContextThread(HANDLE ThreadHandle, PCONTEXT Context);
NTSTATUS NTAPI ProcNtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context);
NTSTATUS NTAPI ProcNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);
NTSTATUS NTAPI ProcNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
//====================================================================================
