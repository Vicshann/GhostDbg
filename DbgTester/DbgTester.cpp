
#include "DbgTester.h"


volatile HINSTANCE hInstance; 
volatile bool BreakWrk = false;

BYTE  DllPath[MAX_PATH];
BYTE  ExePath[MAX_PATH];
BYTE  StartUpDir[MAX_PATH];
//------------------------------------------------------------------------------------------------------------
DWORD WINAPI TstMainThread(LPVOID lpThreadParameter)
{          
 HMODULE hLib = LoadLibraryA((LPSTR)&DllPath);
// HMODULE hLibV = LoadLibraryA("XEDParse.dll");
 while(!BreakWrk)  // Breakpoints test loop
  {
   UINT Len = lstrlenA((LPSTR)&StartUpDir);
   Sleep(500 + (Len & 0x0F));
  }
 return 0;
}
//====================================================================================
void _stdcall SysMain(DWORD UnkArg)
{
 SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX);	 // Crash silently an error happens
 hInstance = GetModuleHandleA(NULL);
 GetModuleFileNameA(hInstance,(LPSTR)&ExePath,sizeof(ExePath)); 
 lstrcpyA((LPSTR)&StartUpDir, (LPSTR)&ExePath);  
// TrimFilePath((LPSTR)&StartUpDir);     // This causes x64dbg to crash in 'dbghelp.dll!AddressMap::getSectionLength(unsigned long)' while loading DbgTester.pdb
    int slctr = lstrlenA((LPSTR)&StartUpDir);
    while(--slctr >= 0){if((StartUpDir[slctr] == 0x2F)||(StartUpDir[slctr] == 0x5C)){StartUpDir[slctr+1] = 0; break;}}
 lstrcpyA((LPSTR)&DllPath, (LPSTR)&StartUpDir);
 lstrcatA((LPSTR)&DllPath, "injlib.dll");

// CONTEXT ctx;
 HANDLE hThread = CreateThread(NULL,0,&TstMainThread,(PVOID)0x1123344,CREATE_SUSPENDED,NULL);   //   CREATE_SUSPENDED
  ResumeThread(hThread);
// memset(&ctx,0,sizeof(ctx));
// ctx.ContextFlags = CONTEXT_CONTROL|CONTEXT_INTEGER;
// GetThreadContext(hThread, &ctx);

 WaitForSingleObject(hThread,INFINITE);
 CloseHandle(hThread);
 ExitProcess(0);  
}
//---------------------------------------------------------------------------
