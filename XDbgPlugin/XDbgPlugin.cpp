/*
  Copyright (c) 2018 Victor Sheinmann, Vicshann@gmail.com

  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
  to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
  and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 
*/

#include "XDbgPlugin.h" 
#include "_plugins.h"


#pragma comment(linker,"/ENTRY:DLLMain")
#pragma comment(linker,"/NODEFAULTLIB")


typedef ShMem  SHM;     
typedef GhDbg  XNI;

// ---------- SETTINGS ------------------
bool PLogOnly    = false;        // Just log usage of Debug API  
bool PEnabled    = false;
bool AllowInject = false;        // Allow to load inject DLL into target process. Else only processes with injected DLLs will be visible
bool AllowInjNew = false;
UINT InjFlags    = InjLdr::mfInjMap|InjLdr::mfRunRMTH;
UINT WaitForInj  = 3000;
//---------------------------------------
                                 
PHOOK(ProcNtClose) HookNtClose;        
PHOOK(ProcNtOpenThread) HookNtOpenThread;
PHOOK(ProcNtOpenProcess) HookNtOpenProcess;    
PHOOK(ProcNtFlushVirtualMemory) HookNtFlushVirtualMemory;                                            
PHOOK(ProcNtQueryVirtualMemory) HookNtQueryVirtualMemory;
PHOOK(ProcNtProtectVirtualMemory) HookNtProtectVirtualMemory;                    
PHOOK(ProcNtQueryInformationThread) HookNtQueryInformationThread;
PHOOK(ProcNtQueryInformationProcess) HookNtQueryInformationProcess;                                                  
PHOOK(ProcNtGetContextThread) HookNtGetContextThread;
PHOOK(ProcNtSetContextThread) HookNtSetContextThread;
PHOOK(ProcNtReadVirtualMemory) HookNtReadVirtualMemory;
PHOOK(ProcNtWriteVirtualMemory) HookNtWriteVirtualMemory;
PHOOK(ProcNtTerminateThread) HookNtTerminateThread;
PHOOK(ProcNtSuspendThread) HookNtSuspendThread;
PHOOK(ProcNtResumeThread) HookNtResumeThread;
PHOOK(ProcNtDuplicateObject) HookNtDuplicateObject;
  
PHOOK(ProcDebugActiveProcess) HookDebugActiveProcess; 
PHOOK(ProcDebugActiveProcessStop) HookDebugActiveProcessStop;
PHOOK(ProcWaitForDebugEvent) HookWaitForDebugEvent;   
PHOOK(ProcContinueDebugEvent) HookContinueDebugEvent; 
PHOOK(ProcDebugBreakProcess) HookDebugBreakProcess;
PHOOK(ProcTerminateProcess) HookTerminateProcess;
PHOOK(ProcCreateProcessA) HookCreateProcessA;
PHOOK(ProcCreateProcessW) HookCreateProcessW;


volatile bool BreakWrk = false;
SHM::CMessageIPC* DbgIPC = NULL;
XNI::CThreadList* ThList = NULL;
HMODULE hInst = NULL;
DWORD  DbgProcID = 0;       
HWND   hXDbgWnd = NULL;
int PluginHandle = -1;
int DbgCliMenu = -1;
bool HooksInstalled = false;
bool DbgCliFlags[32];   // Because there is no function to request a menu item`s checked state in X64DBG  :(


void (_cdecl* plugin_registercallback)(int pluginHandle, CBTYPE cbType, CBPLUGIN cbPlugin);
void (_cdecl* plugin_menuentrysetchecked)(int pluginHandle, int hEntry,bool checked);
//void (_cdecl* plugin_menuentrysetname)(int pluginHandle, int hEntry, const char* name);    // Broken!
bool (_cdecl* plugin_menuaddseparator)(int hMenu);
bool (_cdecl* plugin_menuclear)(int hMenu);
int  (_cdecl* plugin_menuadd)(int hMenu, const char* title);
int  (_cdecl* plugin_menuaddentry)(int hMenu, int entry, const char* title);
void (_cdecl* plugin_menuseticon)(int hMenu, const ICONDATA* icon);
void (_cdecl* plugin_logprintf)(const char* format, ...);

BYTE  StartUpDir[MAX_PATH];
BYTE  CfgFilePath[MAX_PATH];
BYTE  WorkFolder[MAX_PATH];

//===========================================================================
BOOL APIENTRY DLLMain(HMODULE hModule, DWORD ReasonCall, LPVOID lpReserved) 
{	
 switch (ReasonCall)	    
  {			 
   case DLL_PROCESS_ATTACH:
    {    
     hInst = hModule;
     GetModuleFileName((HMODULE)hModule,(LPSTR)&StartUpDir,sizeof(StartUpDir));        
	 lstrcpyA((LPSTR)&WorkFolder, (LPSTR)&StartUpDir);

#ifndef NOLOG
     lstrcpyA((LPSTR)&LogFilePath,(LPSTR)&WorkFolder);
     lstrcpyA(GetFileExt((LPSTR)&LogFilePath),"log");
#endif
     lstrcpyA((LPSTR)&CfgFilePath,(LPSTR)&WorkFolder);
     lstrcpyA(GetFileExt((LPSTR)&CfgFilePath),"ini");
	
     LoadConfiguration();	
	 if(LogMode & lmCons){AllocConsole();/*SetWinConsoleSizes(1000, 500, 1000, 500);*/}
	 LOGMSG("Starting up... (Time=%08X), Owner='%s'", (DWORD)GetTime64(),(LPSTR)&StartUpDir);	
     TrimFilePath((LPSTR)&StartUpDir);
     LOGMSG("WorkFolder: %s", (LPSTR)&WorkFolder);
     LOGMSG("StartUpDir: %s", (LPSTR)&StartUpDir);  
    }
     break;									
   case DLL_THREAD_ATTACH:
     break; 
   case DLL_THREAD_DETACH:
     break;
   case DLL_PROCESS_DETACH: 
     DisablePlugin();
	 break;
   default : return false;  
  }
 return true;
}
//====================================================================================
void _stdcall LoadConfiguration(void)
{                  
 LogMode                = RefreshINIValueInt(CFGSECNAME,"LogMode",   LogMode,  (LPSTR)&CfgFilePath);
 PLogOnly               = RefreshINIValueInt(CFGSECNAME,"PLogOnly",  PLogOnly, (LPSTR)&CfgFilePath);
 PEnabled               = RefreshINIValueInt(CFGSECNAME,"PEnabled",  PEnabled, (LPSTR)&CfgFilePath);
 AllowInject            = RefreshINIValueInt(CFGSECNAME,"AllowInject",  AllowInject, (LPSTR)&CfgFilePath); 
 AllowInjNew            = RefreshINIValueInt(CFGSECNAME,"AllowInjNew",  AllowInjNew, (LPSTR)&CfgFilePath);     
 InjFlags               = RefreshINIValueInt(CFGSECNAME,"InjectFlags",  InjFlags, (LPSTR)&CfgFilePath); 
 WaitForInj             = RefreshINIValueInt(CFGSECNAME,"WaitForInj",  WaitForInj, (LPSTR)&CfgFilePath); 
}
//------------------------------------------------------------------------------------
void _stdcall SaveConfiguration(void)
{
 SetINIValueInt(CFGSECNAME, "LogMode", LogMode, (LPSTR)&CfgFilePath);
 SetINIValueInt(CFGSECNAME, "PLogOnly", PLogOnly, (LPSTR)&CfgFilePath);
 SetINIValueInt(CFGSECNAME, "PEnabled", PEnabled, (LPSTR)&CfgFilePath);
 SetINIValueInt(CFGSECNAME, "AllowInject", AllowInject, (LPSTR)&CfgFilePath);
 SetINIValueInt(CFGSECNAME, "AllowInjNew", AllowInjNew, (LPSTR)&CfgFilePath);
 SetINIValueInt(CFGSECNAME, "InjectFlags", InjFlags, (LPSTR)&CfgFilePath);
 SetINIValueInt(CFGSECNAME, "WaitForInj", WaitForInj, (LPSTR)&CfgFilePath);
}
//------------------------------------------------------------------------------------
void _cdecl MenuHandler(CBTYPE Type, PLUG_CB_MENUENTRY *info)
{
 if(info->hEntry >= MENU_ID_DBGCLIENT)
  {
   UINT CfgIdx = info->hEntry - MENU_ID_DBGCLIENT; 
   DbgCliFlags[CfgIdx] = !DbgCliFlags[CfgIdx];
   SetSingleConfig(CfgIdx, XNI::dtBool, &DbgCliFlags[CfgIdx]);   // Set config
   return;
  }
 switch(info->hEntry) 
  {
   case MENU_ID_ENABLED:
     if(PEnabled)DisablePlugin();
      else EnablePlugin();
     PEnabled = !PEnabled;                            // No way to change the menu item`s text?    // plugin_menuentrysetname(PluginHandle,MENU_ID_ENABLED,(PEnabled)?("DISABLE"):("ENABLE"));   
     SaveConfiguration();
    break;
   case MENU_ID_CHK_CANINJ:
     AllowInject = !AllowInject;
     SaveConfiguration();
    break;
   case MENU_ID_CHK_CANINJNEW:
     AllowInjNew = !AllowInjNew;
     SaveConfiguration();
    break;
   case MENU_ID_ABOUT: 
     {  
      char Hdr[64];                                     // XDBGPLG_BUILD
      char About[128]; 
      wsprintfA(Hdr,"%s v%u.0",XDBGPLG_NAME,XDBGPLG_VER);
      wsprintfA(About,"Build: %s\nAuthor: Vicshann\nEmail: vicshann@gmail.com",XDBGPLG_BUILD);
      MessageBoxA(hXDbgWnd, About, Hdr, MB_OK | MB_ICONINFORMATION);
     }
    break;
  }
}
//------------------------------------------------------------------------------------
extern "C" __declspec(dllexport) bool _cdecl pluginit(PLUG_INITSTRUCT* initStruct)
{
 DBGMSG("Enter");

#ifdef _M_X64
 HMODULE pXDbgLib = GetModuleHandleA("x64dbg.dll");
#else
 HMODULE pXDbgLib = GetModuleHandleA("x32dbg.dll");
#endif

 *(FARPROC*)&plugin_registercallback    = GetProcAddress(pXDbgLib, "_plugin_registercallback");
 *(FARPROC*)&plugin_menuentrysetchecked = GetProcAddress(pXDbgLib, "_plugin_menuentrysetchecked");
// *(FARPROC*)&plugin_menuentrysetname    = GetProcAddress(pXDbgLib, "_plugin_menuentrysetname");
 *(FARPROC*)&plugin_menuaddseparator    = GetProcAddress(pXDbgLib, "_plugin_menuaddseparator");
 *(FARPROC*)&plugin_menuaddentry        = GetProcAddress(pXDbgLib, "_plugin_menuaddentry");
 *(FARPROC*)&plugin_menuseticon         = GetProcAddress(pXDbgLib, "_plugin_menuseticon"); 
 *(FARPROC*)&plugin_menuclear           = GetProcAddress(pXDbgLib, "_plugin_menuclear"); 
 *(FARPROC*)&plugin_menuadd             = GetProcAddress(pXDbgLib, "_plugin_menuadd"); 
 *(FARPROC*)&plugin_logprintf           = GetProcAddress(pXDbgLib, "_plugin_logprintf");        

 PluginHandle = initStruct->pluginHandle;
 initStruct->pluginVersion = XDBGPLG_VER;
 lstrcpyA(initStruct->pluginName, XDBGPLG_NAME);
 initStruct->sdkVersion = PLUG_SDKVERSION;
 plugin_registercallback(initStruct->pluginHandle, CB_MENUENTRY, (CBPLUGIN)MenuHandler);
 DBGMSG("Exit");
 return true;
}
//------------------------------------------------------------------------------------
extern "C" __declspec(dllexport) bool _cdecl plugstop()
{
 DBGMSG("Enter");
 DisablePlugin();
 DBGMSG("Exit");
 return true;
}
//------------------------------------------------------------------------------------
extern "C" __declspec(dllexport) void _cdecl plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
 DBGMSG("Enter");
 plugin_logprintf("%s Loaded. Build: %s\n",XDBGPLG_NAME,XDBGPLG_BUILD);
 hXDbgWnd = setupStruct->hwndDlg;
 plugin_menuaddentry(setupStruct->hMenu, MENU_ID_ENABLED, "Enabled");
 plugin_menuaddentry(setupStruct->hMenu, MENU_ID_CHK_CANINJ, "Allow Injection");   // Open Process
 plugin_menuaddentry(setupStruct->hMenu, MENU_ID_CHK_CANINJNEW, "Allow Inject New");  // Create Process
// plugin_menuaddentry(setupStruct->hMenu, MENU_ID_CHK_CANINJ, "Allow Ejection");    // On Detach, if DLL ha been injected
 plugin_menuaddseparator(setupStruct->hMenu);
 DbgCliMenu = plugin_menuadd(setupStruct->hMenu, "Client Config");
 plugin_menuaddseparator(setupStruct->hMenu);
 plugin_menuaddentry(setupStruct->hMenu, MENU_ID_ABOUT, "About");
    
 plugin_menuentrysetchecked(PluginHandle,MENU_ID_ENABLED,PEnabled);
 plugin_menuentrysetchecked(PluginHandle,MENU_ID_CHK_CANINJ,AllowInject);
 plugin_menuentrysetchecked(PluginHandle,MENU_ID_CHK_CANINJNEW,AllowInjNew);

 ICONDATA ico;
 UINT ResSize = 0;
 ico.data = GetResource(hInst, "MAINICON", RT_RCDATA, &ResSize);
 ico.size = ResSize; 
 plugin_menuseticon(setupStruct->hMenu, &ico);
 if(PEnabled)EnablePlugin();
 DBGMSG("Exit");
}
//------------------------------------------------------------------------------------
int _stdcall EnablePlugin(void)
{
 if(HooksInstalled)return 0;
 DBGMSG("Enter");
 BreakWrk       = false;
 HooksInstalled = true;  
              
 HookNtClose.SetHook("NtClose","ntdll.dll");
 HookNtOpenThread.SetHook("NtOpenThread","ntdll.dll");
 HookNtOpenProcess.SetHook("NtOpenProcess","ntdll.dll");  
 HookNtFlushVirtualMemory.SetHook("NtFlushVirtualMemory","ntdll.dll");
 HookNtQueryVirtualMemory.SetHook("NtQueryVirtualMemory","ntdll.dll"); 
 HookNtProtectVirtualMemory.SetHook("NtProtectVirtualMemory","ntdll.dll");  
 HookNtQueryInformationThread.SetHook("NtQueryInformationThread","ntdll.dll");
 HookNtQueryInformationProcess.SetHook("NtQueryInformationProcess","ntdll.dll");
 HookNtTerminateThread.SetHook("NtTerminateThread","ntdll.dll");
 HookNtSuspendThread.SetHook("NtSuspendThread","ntdll.dll");
 HookNtResumeThread.SetHook("NtResumeThread","ntdll.dll");
 HookNtSetContextThread.SetHook("NtSetContextThread","ntdll.dll");
 HookNtGetContextThread.SetHook("NtGetContextThread","ntdll.dll");
 HookNtReadVirtualMemory.SetHook("NtReadVirtualMemory","ntdll.dll");
 HookNtWriteVirtualMemory.SetHook("NtWriteVirtualMemory","ntdll.dll");
 HookNtDuplicateObject.SetHook("NtDuplicateObject","ntdll.dll");

 HookDebugActiveProcess.SetHook("DebugActiveProcess","kernel32.dll");
 HookDebugActiveProcessStop.SetHook("DebugActiveProcessStop","kernel32.dll");
 HookContinueDebugEvent.SetHook("ContinueDebugEvent","kernel32.dll");
 HookWaitForDebugEvent.SetHook("WaitForDebugEvent","kernel32.dll");
 HookDebugBreakProcess.SetHook("DebugBreakProcess","kernel32.dll");
 HookTerminateProcess.SetHook("TerminateProcess","kernel32.dll");
 HookCreateProcessA.SetHook("CreateProcessA","kernel32.dll");
 HookCreateProcessW.SetHook("CreateProcessW","kernel32.dll");

 ThList = new XNI::CThreadList;
 DbgIPC = new SHM::CMessageIPC;
 DBGMSG("Exit");
 plugin_logprintf("%s Enabled\n",XDBGPLG_NAME);
 return 0;
}
//------------------------------------------------------------------------------------
int _stdcall DisablePlugin(void)
{
 if(!HooksInstalled)return 0;
 DBGMSG("Enter");
 BreakWrk       = true;
 HooksInstalled = false;
 HookNtClose.Remove();
 HookNtOpenThread.Remove();
 HookNtOpenProcess.Remove();
 HookNtFlushVirtualMemory.Remove();
 HookNtQueryVirtualMemory.Remove();
 HookNtProtectVirtualMemory.Remove();
 HookNtQueryInformationThread.Remove();
 HookNtQueryInformationProcess.Remove();  
 HookNtTerminateThread.Remove();
 HookNtSuspendThread.Remove();
 HookNtResumeThread.Remove();
 HookNtSetContextThread.Remove();
 HookNtGetContextThread.Remove();
 HookNtReadVirtualMemory.Remove();
 HookNtWriteVirtualMemory.Remove();
 HookNtDuplicateObject.Remove();

 HookDebugActiveProcess.Remove();
 HookDebugActiveProcessStop.Remove();
 HookContinueDebugEvent.Remove();
 HookWaitForDebugEvent.Remove();
 HookDebugBreakProcess.Remove();
 HookTerminateProcess.Remove();
 HookCreateProcessA.Remove();
 HookCreateProcessW.Remove();

 SHM::CMessageIPC* TmpIPC = DbgIPC;
 DbgIPC = NULL;
 delete(TmpIPC);     // WaitForDebugEvent is finished before this?
 XNI::CThreadList* TmpLst = ThList;
 ThList = NULL;
 delete(TmpLst);

 DBGMSG("Exit");
 plugin_logprintf("%s Disabled\n",XDBGPLG_NAME);
 return 0;
}
//------------------------------------------------------------------------------------
int _stdcall LoadDbgClienConfig(void)
{
 SHM::CArgPack<> api;
 SHM::CArgPack<> apo;
 DBGMSG("Enter");
 plugin_menuclear(DbgCliMenu);
 if(DbgIPC->ExchangeMsg(XNI::miDbgGetConfigs,XNI::mtUsrReq, &api, &apo) < 0)return -1;
 for(;;)
  {
   char Name[128];
   UINT Hint   = sizeof(Name);   // On input it is size of name
   UINT ValLen = 0;
   PBYTE Ptr   = apo.PopBlkEx(&ValLen,Name,&Hint);
   if(!Ptr)break;   // No more configs
   UINT CfgIdx = 0;
   UINT Type   = XNI::CDbgClient::ReadCfgItemID(Hint, &CfgIdx);
   if(Type & XNI::dtBool)
    {     
     plugin_menuaddentry(DbgCliMenu, MENU_ID_DBGCLIENT+CfgIdx, Name);
     plugin_menuentrysetchecked(PluginHandle,MENU_ID_DBGCLIENT+CfgIdx,*(bool*)Ptr);
     DbgCliFlags[CfgIdx] = *(bool*)Ptr;
    }
     else if(Type & XNI::dtNull)plugin_menuaddseparator(DbgCliMenu);
  }
 return 0;
}
//------------------------------------------------------------------------------------
int _stdcall SetSingleConfig(UINT CfgID, UINT CfgType, PVOID CfgAddr)
{
 DBGMSG("CfgID=%u, CfgType=%u",CfgID,CfgType);
 SHM::CArgPack<> api;
 SHM::CArgPack<> apo;
 UINT ValLen = 0;
 if(CfgType & (XNI::dtBool|XNI::dtBYTE))ValLen = 1;
 else if(CfgType & XNI::dtWORD)ValLen  = 2;
 else if(CfgType & XNI::dtDWORD)ValLen = 4;
 else if(CfgType & XNI::dtQWORD)ValLen = 8;
 api.PushBlkEx(ValLen, CfgAddr, NULL, XNI::CDbgClient::MakeCfgItemID(CfgID,CfgType));
 if(DbgIPC->ExchangeMsg(XNI::miDbgSetConfigs,XNI::mtUsrReq, &api, &apo) < 0)return -1;
 return 0;
}
//------------------------------------------------------------------------------------
int _stdcall InjectProcess(HANDLE hProcess, DWORD ProcessID)
{
 CArr<BYTE> DllData;
 BYTE DllPath[MAX_PATH];
 UINT Flags   = InjFlags|InjLdr::mfRawMod|fmCryHdr|fmCryImp|fmCryExp|fmCryRes;    // TODO: Inject method to cfg (Separated)
 UINT ResSize = 0;
 PVOID InjLib = NULL;
 lstrcpyA((LPSTR)&DllPath, (LPSTR)&StartUpDir);
 lstrcatA((LPSTR)&DllPath,"injlib.dll");        // Store this name in some global definition?
 HANDLE hFile = CreateFileA((LPSTR)&DllPath,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(hFile != INVALID_HANDLE_VALUE)
  {
   DWORD Result   = 0;
   ResSize = GetFileSize(hFile,NULL);
   DllData.Resize(ResSize);
   if(ResSize)ReadFile(hFile,DllData.Data(),ResSize,&Result,NULL);
   CloseHandle(hFile);
   InjLib = DllData.Data();
   DBGMSG("InjLib loaded from file: %s",(LPSTR)&DllPath);
   plugin_logprintf("InjLib loaded from file: %s\n",(LPSTR)&DllPath);
  }
   else InjLib = GetResource(hInst, "InjLib", RT_RCDATA, &ResSize);
 if(!InjLib || !ResSize){DBGMSG("No InjLib found!"); return -1;}
 bool POpened = (hProcess == NULL);
 if(POpened)hProcess = InjLdr::OpenRemoteProcess(ProcessID, Flags);
 if(!hProcess)return -2;  
 int res = InjLdr::InjModuleIntoProcessAndExec(hProcess, InjLib, ResSize, Flags);
 if(POpened)CloseHandle(hProcess);    
 if(res < 0)return -3;
 for(int ctr=WaitForInj;ctr > 0;ctr-=100)
  {      
   Sleep(100);
   if(SHM::CMessageIPC::IsExistForID(ProcessID))break;
  }
 if(!SHM::CMessageIPC::IsExistForID(ProcessID))return FALSE;
 return 0;
}
//------------------------------------------------------------------------------------
BOOL _stdcall ProcessCreateInjWrk(LPPROCESS_INFORMATION lpProcessInformation)
{
 int ires = InjectProcess(lpProcessInformation->hProcess, lpProcessInformation->dwProcessId);
 CloseHandle(lpProcessInformation->hThread);
 CloseHandle(lpProcessInformation->hProcess);
 if(ires < 0){DBGMSG("Failed to inject a new process: %08X(%u)",lpProcessInformation->dwProcessId,lpProcessInformation->dwProcessId); return FALSE;}
 if(lpProcessInformation->dwProcessId != DbgIPC->GetID())DbgIPC->Disconnect();      // Has been connected to some other process
 if(DbgIPC->Connect((DWORD)lpProcessInformation->dwProcessId, 0, true) < 0){DBGMSG("Connect failed: %08X(%u)",lpProcessInformation->dwProcessId,lpProcessInformation->dwProcessId); return FALSE;}
 DbgProcID = lpProcessInformation->dwProcessId;
 lpProcessInformation->hProcess = XNI::CDbgClient::UintToFakeHandle(lpProcessInformation->dwProcessId);      // All communication with a target process is only through IPC 
 lpProcessInformation->hThread  = NULL;      // TODO: Get it from target`s DbgClient
 SHM::CArgPack<> api;
 SHM::CArgPack<> apo;
 api.PushArg(lpProcessInformation->dwProcessId);
 if(DbgIPC->ExchangeMsg(XNI::miDebugActiveProcess,XNI::mtDbgReq, &api, &apo) < 0)return FALSE;
 BOOL res = FALSE;
 apo.PopArg(res);
 LoadDbgClienConfig();
 plugin_logprintf("Main thread is in suspended state\n");
 return res;
}
//------------------------------------------------------------------------------------


//====================================================================================
//
//                          HOOKED SUPPORT FUNCTIONS
//
//------------------------------------------------------------------------------------
// Opening a Process/Thread is forbidden besause some nasty AntiCheat can track this
//
NTSTATUS NTAPI ProcNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{    
 bool HaveMapping = SHM::CMessageIPC::IsExistForID((DWORD)ClientId->UniqueProcess);                                
 if(PLogOnly || !ClientId || !ProcessHandle || (!HaveMapping && AllowInject))    // Injection(optional) moved to DebugActiveProcess because opening a process is done after DebugActiveProcess  
  {
   NTSTATUS Res = HookNtOpenProcess.OrigProc(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
   HANDLE   Hnd = (ProcessHandle)?(*ProcessHandle):(INVALID_HANDLE_VALUE);
   DBGMSG("StatusA=%08X, ProcessHandle=%08X, DesiredAccess=%08X, UniqueProcess=%08X, UniqueThread=%08X",Res,Hnd,DesiredAccess,(ClientId)?(ClientId->UniqueProcess):(0),(ClientId)?(ClientId->UniqueThread):(0));
   return Res;
  }
 if(!HaveMapping)return STATUS_UNSUCCESSFUL;   // Debugger will try to open every process. Do not show processes without already injected DLLs
 if((DWORD)ClientId->UniqueProcess != DbgIPC->GetID())DbgIPC->Disconnect();      // Has been connected to some other process
 if(DbgIPC->Connect((DWORD)ClientId->UniqueProcess, 0, true) < 0){DBGMSG("Connect failed: %08X(%u)",ClientId->UniqueProcess,ClientId->UniqueProcess); return STATUS_UNSUCCESSFUL;}
 DbgProcID = (DWORD)ClientId->UniqueProcess;
 *ProcessHandle = XNI::CDbgClient::UintToFakeHandle((DWORD)ClientId->UniqueProcess);      // All communication with a target process is only through IPC 
 DBGMSG("FakeProcessHandle=%08X, DesiredAccess=%08X, UniqueProcess=%08X, UniqueThread=%08X",*ProcessHandle,DesiredAccess,ClientId->UniqueProcess,ClientId->UniqueThread);
 return STATUS_SUCCESS;
}
//------------------------------------------------------------------------------------
NTSTATUS NTAPI ProcNtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
 HANDLE hTh = NULL;  
 if(PLogOnly || !DbgProcID || !ClientId || !ThreadHandle || !(hTh = ThList->GetHandleByIndex(ThList->FindThreadIdxInList(NULL, (DWORD)ClientId->UniqueThread, NULL))))
  {
   NTSTATUS Res = HookNtOpenThread.OrigProc(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
   HANDLE   Hnd = (ThreadHandle)?(*ThreadHandle):(INVALID_HANDLE_VALUE);
   DBGMSG("Status=%08X, ThreadHandle=%08X, DesiredAccess=%08X, UniqueProcess=%08X, UniqueThread=%08X",Res,Hnd,DesiredAccess,(ClientId)?(ClientId->UniqueProcess):(0),(ClientId)?(ClientId->UniqueThread):(0));
   return Res;
  }
 *ThreadHandle = hTh;
 DBGMSG("FakeThreadHandle=%08X, DesiredAccess=%08X, UniqueProcess=%08X, UniqueThread=%08X",hTh,DesiredAccess,ClientId->UniqueProcess,ClientId->UniqueThread);
 return STATUS_SUCCESS;
}
//------------------------------------------------------------------------------------
NTSTATUS NTAPI ProcNtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options)
{                                                  
 if(PLogOnly || !TargetHandle || !XNI::CDbgClient::IsFakeHandle(SourceHandle))
  {
   NTSTATUS Res = HookNtDuplicateObject.OrigProc(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
   HANDLE   Hnd = (TargetHandle)?(*TargetHandle):(INVALID_HANDLE_VALUE);
   DBGMSG("Status=%08X, TargetHandle=%08X, SourceHandle=%08X, SourceProcessHandle=%08X, TargetProcessHandle=%08X, DesiredAccess=%08X, HandleAttributes=%08X, Options=%08X",Res,Hnd,SourceHandle,SourceProcessHandle,TargetProcessHandle,DesiredAccess,HandleAttributes,Options);
   return Res;
  } 
 *TargetHandle = SourceHandle;        
 DBGMSG("FakeHandle=%08X(%08X), SourceProcessHandle=%08X, TargetProcessHandle=%08X, DesiredAccess=%08X, HandleAttributes=%08X, Options=%08X",SourceHandle,*TargetHandle,SourceProcessHandle,TargetProcessHandle,DesiredAccess,HandleAttributes,Options);
 return STATUS_SUCCESS;
}
//------------------------------------------------------------------------------------
NTSTATUS NTAPI ProcNtClose(HANDLE Handle)
{                                          
 if(PLogOnly || !XNI::CDbgClient::IsFakeHandle(Handle))return HookNtClose.OrigProc(Handle);
 DBGMSG("FakeHandle=%08X",Handle);      // Closing some fake handle
 return STATUS_SUCCESS;
}
//------------------------------------------------------------------------------------
BOOL WINAPI ProcCreateProcessA(LPCSTR lpApplicationName,LPSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,LPCSTR lpCurrentDirectory,LPSTARTUPINFOA lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation)
{
 DBGMSG("dwCreationFlags=%08X, lpApplicationName='%s',lpCommandLine='%s',",dwCreationFlags,lpApplicationName?lpApplicationName:"",lpCommandLine?lpCommandLine:"");
 bool ForDebug = AllowInjNew && (dwCreationFlags & (DEBUG_PROCESS|DEBUG_ONLY_THIS_PROCESS));
 if(ForDebug)
  {
   dwCreationFlags &= ~(DEBUG_PROCESS|DEBUG_ONLY_THIS_PROCESS);
   dwCreationFlags |= CREATE_SUSPENDED;
  }
 BOOL res = HookCreateProcessA.OrigProc(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
 if(res && ForDebug && lpProcessInformation)res = ProcessCreateInjWrk(lpProcessInformation); 
 return res;
}
//------------------------------------------------------------------------------------
BOOL WINAPI ProcCreateProcessW(LPCWSTR lpApplicationName,LPWSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation)
{
 DBGMSG("dwCreationFlags=%08X, lpApplicationName='%ls',lpCommandLine='%ls',",dwCreationFlags,lpApplicationName?lpApplicationName:L"",lpCommandLine?lpCommandLine:L"");
 bool ForDebug = AllowInjNew && (dwCreationFlags & (DEBUG_PROCESS|DEBUG_ONLY_THIS_PROCESS));
 if(ForDebug)
  {
   dwCreationFlags &= ~(DEBUG_PROCESS|DEBUG_ONLY_THIS_PROCESS);
   dwCreationFlags |= CREATE_SUSPENDED;
  }
 BOOL res = HookCreateProcessW.OrigProc(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation); 
 if(res && ForDebug && lpProcessInformation)res = ProcessCreateInjWrk(lpProcessInformation);
 return res;
}
//------------------------------------------------------------------------------------


//====================================================================================
//
//                            HOOKED DEBUG WINAPI
//
//------------------------------------------------------------------------------------
// When a debugger attached, a debuggee must send events for all threads and modules (CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT..., LOAD_DLL_DEBUG_EVENT...)
//
BOOL WINAPI ProcWaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds)
{                                           
 DBGMSG("lpDebugEvent=%p, dwMilliseconds=%u",lpDebugEvent,dwMilliseconds);
 if(PLogOnly || !DbgProcID)
  {
   BOOL res = HookWaitForDebugEvent.OrigProc(lpDebugEvent, dwMilliseconds);
   if(res){DBGMSG("dwDebugEventCode=%08X, dwProcessId=%08X, dwThreadId=%08X, BASE: %p",lpDebugEvent->dwDebugEventCode,lpDebugEvent->dwProcessId,lpDebugEvent->dwThreadId,lpDebugEvent->u.LoadDll.lpBaseOfDll);}
   return res;
  }
 while(!BreakWrk && DbgIPC->IsOtherConnections())          // If debugger kills this thread while the buffer is still locked what will happen?
  { 
   SHM::CMessageIPC::SMsgHdr* Cmd = DbgIPC->GetMsg();
   if(!Cmd)continue;       // Timeout and still no message
//   DBGMSG("MsgType=%04X, MsgID=%04X, DataID=%08X, Sequence=%08X, DataSize=%08X",Cmd->MsgType,Cmd->MsgID,Cmd->DataID,Cmd->Sequence,Cmd->DataSize);   // DISABLED: Other threaads will spam IPC with ReadVirtualMemory requests no mattter which tab is opened
   if((Cmd->MsgType != XNI::mtDbgRsp)||(Cmd->MsgID != XNI::miWaitForDebugEvent)||(Cmd->DataSize < sizeof(XNI::DbgEvtEx)))continue;   // Not a Response (All debug events are sent as Response without Request)
   XNI::DbgEvtEx* Evt = (XNI::DbgEvtEx*)&Cmd->Data;
   DBGMSG("Code=%u, ThreadID=%08X(%u)",Evt->dwDebugEventCode,Evt->dwThreadId,Evt->dwThreadId);
   switch(Evt->dwDebugEventCode)
    {
     case EXCEPTION_DEBUG_EVENT:
      {
       // Nothing to do for now
      }
      break;
     case CREATE_THREAD_DEBUG_EVENT:
      {
       ThList->AddThreadToList(Evt->dwThreadId,Evt->u.CreateThread.hThread, false);    // NOTE: Watch for CloseHandle for thread handles
       DBGMSG("CREATE_THREAD_DEBUG_EVENT: hThread=%08X, dwThreadId=%u",Evt->u.CreateThread.hThread,Evt->dwThreadId);
      }
      break;
     case CREATE_PROCESS_DEBUG_EVENT:
      {                             
       ThList->AddThreadToList(Evt->dwThreadId,Evt->u.CreateProcessInfo.hThread, false);   // This fake handle is an encoded index in client`s thread list
       DBGMSG("CREATE_PROCESS_DEBUG_EVENT: hProcess=%08X, hThread=%08X, dwThreadId=%u",Evt->u.CreateProcessInfo.hProcess,Evt->u.CreateProcessInfo.hThread,Evt->dwThreadId);
      }
      break;
     case EXIT_THREAD_DEBUG_EVENT:
      {
       ThList->RemoveThreadFromList(Evt->dwThreadId);
      }
      break;
     case EXIT_PROCESS_DEBUG_EVENT:
      {
       if(DbgProcID == Evt->dwProcessId)DbgProcID = 0;
       if(DbgIPC)DbgIPC->Disconnect();
      }
      break;
     case LOAD_DLL_DEBUG_EVENT:
      {
       DBGMSG("LOAD_DLL_DEBUG_EVENT: DllBase=%p, dwThreadId=%u",Evt->u.LoadDll.lpBaseOfDll, Evt->dwThreadId);
      }
      break;
     case UNLOAD_DLL_DEBUG_EVENT:
      {
       DBGMSG("UNLOAD_DLL_DEBUG_EVENT: DllBase=%p, dwThreadId=%u",Evt->u.UnloadDll.lpBaseOfDll, Evt->dwThreadId);
      }
      break;
     case OUTPUT_DEBUG_STRING_EVENT:
      {
       // Unused
      }
      break;
     case RIP_EVENT:
      {
       // Unused
      }
      break;

     default: {DBGMSG("Unknown DebugEventCode: %u",Evt->dwDebugEventCode);}
    }
   memcpy(lpDebugEvent,&Cmd->Data,sizeof(DEBUG_EVENT));
   DbgIPC->EndMsg();   // Unlock shared buffer
   return TRUE;        // Other events will wait untiiiil another call to WaitForDebugEvent
  }
 DbgProcID = 0;      // No DebugActiveProcessStop is called when WaitForDebugEvent is failed
 DbgIPC->EndMsg();   // Unlock shared buffer if it is still locked
 DbgIPC->Disconnect();
 plugin_menuclear(DbgCliMenu);
 return FALSE;
}
//------------------------------------------------------------------------------------
BOOL WINAPI ProcDebugActiveProcess(DWORD dwProcessId)     // Thes will make a debuggee to prepare bunch of events for WaitForDebugEvent (CREATE_PROCESS_DEBUG_EVENT,CREATE_THREAD_DEBUG_EVENT,LOAD_DLL_DEBUG_EVENT) 
{
 DBGMSG("dwProcessId=%08X",dwProcessId);
 if(PLogOnly || !DbgIPC)return HookDebugActiveProcess.OrigProc(dwProcessId);
 if(dwProcessId != DbgIPC->GetID())DbgIPC->Disconnect();      // Has been connected to some other process
 if(!SHM::CMessageIPC::IsExistForID(dwProcessId))
  {
   if(AllowInject)
    {
     if(InjectProcess(NULL, dwProcessId) < 0)return FALSE;    
    }
     else return FALSE;
  }
 if(DbgIPC->Connect(dwProcessId, 0, true) < 0)return FALSE;
 DbgProcID = dwProcessId;
 SHM::CArgPack<> api;
 SHM::CArgPack<> apo;
 api.PushArg(dwProcessId);
 if(DbgIPC->ExchangeMsg(XNI::miDebugActiveProcess,XNI::mtDbgReq, &api, &apo) < 0)return FALSE;
 BOOL res = FALSE;
 apo.PopArg(res);
 LoadDbgClienConfig();
 return res;
}
//------------------------------------------------------------------------------------
BOOL WINAPI ProcDebugActiveProcessStop(DWORD dwProcessId)    // Doesn`t called a first time you do Detach because TitanEngine wants a SystemBreakpoint (FirstBPX - a first BP which is not in its list) 
{
 DBGMSG("dwProcessId=%08X",dwProcessId);
 if(PLogOnly || !DbgIPC || !DbgProcID)return HookDebugActiveProcessStop.OrigProc(dwProcessId);
 if(DbgProcID == dwProcessId)DbgProcID = 0;
 SHM::CArgPack<> api;
 api.PushArg(dwProcessId);
 int res = DbgIPC->ExchangeMsg(XNI::miDebugActiveProcessStop,XNI::mtDbgReq, &api, NULL);
 DbgIPC->ExchangeMsg(XNI::miDbgDetachNtfy,XNI::mtUsrReq, &api, NULL);
 DbgIPC->Disconnect();
 return (res >= 0);   
}
//------------------------------------------------------------------------------------
BOOL WINAPI ProcContinueDebugEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus)
{
 DBGMSG("dwProcessId=%08X, dwThreadId=%08X, dwContinueStatus=%08X",dwProcessId,dwThreadId,dwContinueStatus);
 if(PLogOnly || !DbgIPC || !DbgProcID)return HookContinueDebugEvent.OrigProc(dwProcessId, dwThreadId, dwContinueStatus);
 SHM::CArgPack<> api;
 SHM::CArgPack<> apo;
 api.PushArg(dwContinueStatus);
 api.PushArg(dwThreadId);
 api.PushArg(dwProcessId);
 if(DbgIPC->ExchangeMsg(XNI::miContinueDebugEvent,XNI::mtDbgReq, &api, &apo) < 0)return FALSE;
 BOOL res = FALSE;
 apo.PopArg(res);
 return res;
}
//------------------------------------------------------------------------------------
BOOL WINAPI ProcDebugBreakProcess(HANDLE hProcess)     // Does ntdll.RtlpCreateUserThreadEx on remote DbgUserBreakPoint
{
 DBGMSG("hProcess=%p",hProcess);
 if(PLogOnly || !DbgIPC || !XNI::CDbgClient::IsFakeHandle(hProcess))return HookDebugBreakProcess.OrigProc(hProcess);
 SHM::CArgPack<> api;
 SHM::CArgPack<> apo;
 api.PushArg(hProcess);
 if(DbgIPC->ExchangeMsg(XNI::miDebugBreakProcess,XNI::mtDbgReq, &api, &apo) < 0)return FALSE;
 BOOL res = FALSE;
 apo.PopArg(res);
 return res;
}
//------------------------------------------------------------------------------------
BOOL WINAPI ProcTerminateProcess(HANDLE hProcess, UINT uExitCode)
{
 DBGMSG("hProcess=%p, uExitCode=%08X",hProcess,uExitCode);
 if(PLogOnly || !DbgIPC || !XNI::CDbgClient::IsFakeHandle(hProcess))return HookTerminateProcess.OrigProc(hProcess, uExitCode);
 SHM::CArgPack<> api;
 SHM::CArgPack<> apo;
 api.PushArg(uExitCode);
 api.PushArg(hProcess);
 if(DbgIPC->ExchangeMsg(XNI::miTerminateProcess,XNI::mtDbgReq, &api, &apo) < 0)return FALSE;
 BOOL res = FALSE;
 apo.PopArg(res);
 return res;
}
//------------------------------------------------------------------------------------
NTSTATUS NTAPI ProcNtGetContextThread(HANDLE ThreadHandle, PCONTEXT Context)
{                     
 DBGMSG("ThreadHandle=%p, Context=%p",ThreadHandle,Context);
 if(PLogOnly || !DbgIPC || !XNI::CDbgClient::IsFakeHandle(ThreadHandle) || !ThList->IsThreadInList(0,ThreadHandle))return HookNtGetContextThread.OrigProc(ThreadHandle, Context); 
 NTSTATUS Status;
 SHM::CArgPack<sizeof(CONTEXT)+sizeof(HANDLE)> api;
 SHM::CArgPack<> apo;
 api.PushArg(*Context);   // InOut
 api.PushArg(ThreadHandle);
 if(DbgIPC->ExchangeMsg(XNI::miGetThreadContext,XNI::mtDbgReq, &api, &apo) < 0)return STATUS_UNSUCCESSFUL;
 apo.PopArg(Status);
 apo.PopArg(*Context);
 return Status;
}
//------------------------------------------------------------------------------------
NTSTATUS NTAPI ProcNtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context)
{
 DBGMSG("ThreadHandle=%p, Context=%p",ThreadHandle,Context);
 if(PLogOnly || !DbgIPC || !XNI::CDbgClient::IsFakeHandle(ThreadHandle) || !ThList->IsThreadInList(0,ThreadHandle))return HookNtSetContextThread.OrigProc(ThreadHandle, Context);
 NTSTATUS Status;
 SHM::CArgPack<sizeof(CONTEXT)+sizeof(HANDLE)> api;
 SHM::CArgPack<> apo;
 api.PushArg(*Context);
 api.PushArg(ThreadHandle);
 if(DbgIPC->ExchangeMsg(XNI::miSetThreadContext,XNI::mtDbgReq, &api, &apo) < 0)return STATUS_UNSUCCESSFUL;
 apo.PopArg(Status);
 return Status;
}
//------------------------------------------------------------------------------------
NTSTATUS NTAPI ProcNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferLength, PSIZE_T ReturnLength)
{
 DBGMSG("ProcessHandle=%p, BaseAddress=%p, Buffer=%p, BufferLength=%08X, ReturnLength=%p",ProcessHandle,BaseAddress,Buffer,BufferLength,ReturnLength);
 if(PLogOnly || !DbgIPC || !XNI::CDbgClient::IsFakeHandle(ProcessHandle))return HookNtReadVirtualMemory.OrigProc(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
 SIZE_T RetLen = 0;
 NTSTATUS Status;
 SHM::CArgPack<> api;
 SHM::CArgPack<> apo;
 api.PushArg(BufferLength);
 api.PushArg(BaseAddress);
 api.PushArg(ProcessHandle);
 if(DbgIPC->ExchangeMsg(XNI::miReadVirtualMemory,XNI::mtDbgReq, &api, &apo) < 0)return STATUS_UNSUCCESSFUL;
 apo.PopArg(Status);
 apo.PopArg(RetLen);
 apo.PopBlk(BufferLength,Buffer);      // Always exchange an entire buffer?
 if(ReturnLength)*ReturnLength = RetLen;
 return Status;
}
//------------------------------------------------------------------------------------
NTSTATUS NTAPI ProcNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferLength, PSIZE_T ReturnLength)
{
 DBGMSG("ProcessHandle=%p, BaseAddress=%p, Buffer=%p, BufferLength=%08X, ReturnLength=%p",ProcessHandle,BaseAddress,Buffer,BufferLength,ReturnLength);
 if(PLogOnly || !DbgIPC || !XNI::CDbgClient::IsFakeHandle(ProcessHandle))return HookNtWriteVirtualMemory.OrigProc(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
 SIZE_T RetLen = 0;
 NTSTATUS Status;
 SHM::CArgPack<1024> api;
 SHM::CArgPack<> apo;
 api.PushBlk(BufferLength, Buffer);
 api.PushArg(BufferLength);
 api.PushArg(BaseAddress);
 api.PushArg(ProcessHandle);
 if(DbgIPC->ExchangeMsg(XNI::miWriteVirtualMemory,XNI::mtDbgReq, &api, &apo) < 0)return STATUS_UNSUCCESSFUL;
 apo.PopArg(Status);
 apo.PopArg(RetLen);
 if(ReturnLength)*ReturnLength = RetLen;
 return Status;
}
//------------------------------------------------------------------------------------
NTSTATUS NTAPI ProcNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
{
 DBGMSG("ProcessHandle=%p, BaseAddress=%p, RegionSize=%08X, NewProtect=%08X",ProcessHandle,(BaseAddress)?(*BaseAddress):(NULL),(RegionSize)?(*RegionSize):(0),NewProtect);
 if(PLogOnly || !DbgIPC || !XNI::CDbgClient::IsFakeHandle(ProcessHandle) || !BaseAddress || !RegionSize)return HookNtProtectVirtualMemory.OrigProc(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
 NTSTATUS Status;
 ULONG OldProt;
 SHM::CArgPack<> api;
 SHM::CArgPack<> apo;
 api.PushArg(NewProtect);
 api.PushArg(*RegionSize);
 api.PushArg(*BaseAddress);
 api.PushArg(ProcessHandle);
 if(DbgIPC->ExchangeMsg(XNI::miProtectVirtualMemory,XNI::mtDbgReq, &api, &apo) < 0)return STATUS_UNSUCCESSFUL;
 apo.PopArg(Status);
 apo.PopArg(*RegionSize);
 apo.PopArg(*BaseAddress);
 apo.PopArg(OldProt);
 if(OldProtect)*OldProtect = OldProt; 
 return Status;
}
//------------------------------------------------------------------------------------
NTSTATUS NTAPI ProcNtFlushVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, PIO_STATUS_BLOCK IoStatus)     // Used by WriteProcessMemory
{                                       
 DBGMSG("ProcessHandle=%p, BaseAddress=%p, RegionSize=%08X",ProcessHandle,(BaseAddress)?(*BaseAddress):(NULL),(RegionSize)?(*RegionSize):(0));
 if(PLogOnly || !DbgIPC || !XNI::CDbgClient::IsFakeHandle(ProcessHandle) || !BaseAddress || !RegionSize)return HookNtFlushVirtualMemory.OrigProc(ProcessHandle, BaseAddress, RegionSize, IoStatus);
 NTSTATUS Status;
 SHM::CArgPack<> api;
 SHM::CArgPack<> apo;
 api.PushArg(*RegionSize);
 api.PushArg(*BaseAddress);
 api.PushArg(ProcessHandle);
 if(DbgIPC->ExchangeMsg(XNI::miFlushVirtualMemory,XNI::mtDbgReq, &api, &apo) < 0)return STATUS_UNSUCCESSFUL;
 apo.PopArg(Status);
 apo.PopArg(*RegionSize);
 apo.PopArg(*BaseAddress);
 apo.PopArg(*IoStatus);
 return Status;
}
//------------------------------------------------------------------------------------
NTSTATUS NTAPI ProcNtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
{
 DBGMSG("ThreadHandle=%p",ThreadHandle);
 if(PLogOnly || !DbgIPC || !XNI::CDbgClient::IsFakeHandle(ThreadHandle) || !ThList->IsThreadInList(0,ThreadHandle)){return HookNtResumeThread.OrigProc(ThreadHandle,PreviousSuspendCount);}
 ULONG SuspCtr = 0;
 NTSTATUS Status;
 SHM::CArgPack<> api;
 SHM::CArgPack<> apo;
 api.PushArg(ThreadHandle);
 if(DbgIPC->ExchangeMsg(XNI::miSuspendThread,XNI::mtDbgReq, &api, &apo) < 0){return STATUS_UNSUCCESSFUL;}
 apo.PopArg(Status);
 apo.PopArg(SuspCtr);
 if(PreviousSuspendCount)*PreviousSuspendCount = SuspCtr;
 return Status;
}
//------------------------------------------------------------------------------------
NTSTATUS NTAPI ProcNtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
{
 DBGMSG("ThreadHandle=%p",ThreadHandle);
 if(PLogOnly || !DbgIPC || !XNI::CDbgClient::IsFakeHandle(ThreadHandle) || !ThList->IsThreadInList(0,ThreadHandle))return HookNtResumeThread.OrigProc(ThreadHandle,PreviousSuspendCount);
 ULONG SuspCtr = 0;
 NTSTATUS Status;
 SHM::CArgPack<> api;
 SHM::CArgPack<> apo;
 api.PushArg(ThreadHandle);
 if(DbgIPC->ExchangeMsg(XNI::miResumeThread,XNI::mtDbgReq, &api, &apo) < 0)return STATUS_UNSUCCESSFUL;
 apo.PopArg(Status);
 apo.PopArg(SuspCtr);
 if(PreviousSuspendCount)*PreviousSuspendCount = SuspCtr;
 return Status;
}
//------------------------------------------------------------------------------------
NTSTATUS NTAPI ProcNtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus)
{
 DBGMSG("ThreadHandle=%p, ExitStatus=%08X",ThreadHandle,ExitStatus);   
 if(PLogOnly || !DbgIPC || !XNI::CDbgClient::IsFakeHandle(ThreadHandle) || !ThList->IsThreadInList(0,ThreadHandle))return HookNtTerminateThread.OrigProc(ThreadHandle, ExitStatus);
 NTSTATUS Status;
 SHM::CArgPack<> api;
 SHM::CArgPack<> apo;
 api.PushArg(ExitStatus);
 api.PushArg(ThreadHandle);
 if(DbgIPC->ExchangeMsg(XNI::miTerminateThread,XNI::mtDbgReq, &api, &apo) < 0)return STATUS_UNSUCCESSFUL;   
 apo.PopArg(Status);
 return Status;
}
//------------------------------------------------------------------------------------
NTSTATUS NTAPI ProcNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)   // May be called from anywhere, especially from psapi.dll
{                                            
 DBGMSG("ProcessHandle=%08X, ProcessInformationClass=%u, ProcessInformationLength=%08X",ProcessHandle,ProcessInformationClass,ProcessInformationLength);
 if(PLogOnly || !DbgIPC || !XNI::CDbgClient::IsFakeHandle(ProcessHandle))return HookNtQueryInformationProcess.OrigProc(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);  
 ULONG RetLen = 0;
 NTSTATUS Status;
 SHM::CArgPack<> api;
 SHM::CArgPack<1024> apo;
 api.PushArg(ProcessInformationLength);
 api.PushArg(ProcessInformationClass);
 api.PushArg(ProcessHandle);
 if(DbgIPC->ExchangeMsg(XNI::miQueryInformationProcess,XNI::mtDbgReq, &api, &apo) < 0)return STATUS_UNSUCCESSFUL;
 apo.PopArg(Status);
 apo.PopArg(RetLen);
 apo.PopBlk(ProcessInformationLength,ProcessInformation);    // Full buffer exchange
 if(ReturnLength)*ReturnLength = RetLen;
 if(Status || !RetLen)return Status;
 switch(ProcessInformationClass)            
  {
   case ProcessBasicInformation:
   case ProcessWow64Information:
    break;
   case ProcessImageFileName:
   case ProcessImageFileNameWin32:
    {
     UNICODE_STRING* str = (UNICODE_STRING*)ProcessInformation;
     str->Buffer = (PWSTR)&((PBYTE)ProcessInformation)[sizeof(UNICODE_STRING)];      // Change Ptr to our address space
    }
    break;

   default:
       DBGMSG("Untested information class!");
//       DebugBreak();
  }                   
 return Status;
}
//------------------------------------------------------------------------------------
NTSTATUS NTAPI ProcNtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength)   // Used by GetThreadSelectorEntry
{                                
 DBGMSG("ThreadHandle=%08X, ThreadInformationClass=%u, ThreadInformationLength=%08X",ThreadHandle,ThreadInformationClass,ThreadInformationLength);
 if(PLogOnly || !DbgIPC || !XNI::CDbgClient::IsFakeHandle(ThreadHandle))return HookNtQueryInformationThread.OrigProc(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);  
 ULONG RetLen = 0;
 NTSTATUS Status;
 SHM::CArgPack<> api;
 SHM::CArgPack<1024> apo;
 api.PushArg(ThreadInformationLength);
 api.PushArg(ThreadInformationClass);
 api.PushArg(ThreadHandle);
 if(DbgIPC->ExchangeMsg(XNI::miQueryInformationThread,XNI::mtDbgReq, &api, &apo) < 0)return STATUS_UNSUCCESSFUL;
 apo.PopArg(Status);
 apo.PopArg(RetLen);
 apo.PopBlk(ThreadInformationLength,ThreadInformation);    // Full buffer exchange
 if(ReturnLength)*ReturnLength = RetLen;
 if(Status || !RetLen)return Status;
 switch(ThreadInformationClass)            
  {
   case ThreadBasicInformation:
   case ThreadCycleTime:
   case ThreadTimes:
    break;

   default:
       DBGMSG("Untested information class!");
//       DebugBreak();
  }                   
 return Status;
}
//------------------------------------------------------------------------------------
NTSTATUS NTAPI ProcNtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength)
{                                        
 DBGMSG("ProcessHandle=%08X, BaseAddress=%p, MemoryInformationClass=%u, MemoryInformation=%p, MemoryInformationLength=%08X, ReturnLength=%p",ProcessHandle,BaseAddress,MemoryInformationClass,MemoryInformation,MemoryInformationLength,ReturnLength);
 if(PLogOnly || !DbgIPC || !XNI::CDbgClient::IsFakeHandle(ProcessHandle))return HookNtQueryVirtualMemory.OrigProc(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
 SIZE_T RetLen = 0;
 NTSTATUS Status;
 SHM::CArgPack<> api;
 SHM::CArgPack<1024> apo;
 api.PushArg(MemoryInformationLength);
 api.PushArg(MemoryInformationClass);
 api.PushArg(BaseAddress);
 api.PushArg(ProcessHandle);
 if(DbgIPC->ExchangeMsg(XNI::miQueryVirtualMemory,XNI::mtDbgReq, &api, &apo) < 0)return STATUS_UNSUCCESSFUL;
 apo.PopArg(Status);
 apo.PopArg(RetLen);
 apo.PopBlk(MemoryInformationLength,MemoryInformation);    // Full buffer exchange
 if(ReturnLength)*ReturnLength = RetLen;
 if(Status || !RetLen)return Status;
 switch(MemoryInformationClass)            
  {
   case MemoryBasicInformation:
    break;
   case MemoryMappedFilenameInformation:
    {
     UNICODE_STRING* str = (UNICODE_STRING*)MemoryInformation;
     str->Buffer = (PWSTR)&((PBYTE)MemoryInformation)[sizeof(UNICODE_STRING)];      // Change Ptr to our address space
    }
    break;
          
   default:
       DBGMSG("Untested information class!");
//       DebugBreak();
  }                   
 return Status;
}
//====================================================================================


