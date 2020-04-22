/*
  Copyright (c) 2020 Victor Sheinmann, Vicshann@gmail.com

  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
  to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
  and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 
*/

#include "InjectDll.h" 

//#pragma comment(linker,"/MERGE:.rdata=.text")    // .idata can be only there
//#pragma comment(linker,"/MERGE:.data=.text") 
//#pragma comment(linker,"/MERGE:.idata=.text")
//#pragma comment(linker, "/SECTION:.text,EWR")    // .text; .bss; .pdata; .idata; .reloc  // GhostDbg can cut off after BSS (It does imports and relocs and PDATA is unused)
#pragma comment(linker,"/MERGE:.data=.rdata")      // Now: .text; .bss; .rdata; .pdata; .reloc   // rdata will not be writable - fixed manually for a separate DLL release
//#pragma comment(linker,"/MERGE:.text=.rdata")    // Creates .xdata section 
//#pragma comment(linker, "/SECTION:.rdata,WR")    // Any attampt to make it writable will create .xdata section 

#pragma comment(linker,"/ENTRY:DLLMain")
#pragma comment(linker,"/NODEFAULTLIB")
    

// ---------- SETTINGS ------------------
UINT IPCSize = 0x100000;    // 1Mb (Enough when Req-Rsp removed)
//bool HideDllProxy = true;
//bool HideDllProxyDsk = true;
bool SuspMainThAtLd = false;        // Suspend main thread when loaded by GInjer
bool RstDskHiddenProxy = true;
bool AllowEjectOnDetach = false;
//---------------------------------------
//PHOOK(ProcRtlRestoreContext) HookRtlRestoreContext; 
//PHOOK(ProcKiUserExceptionDispatcher) HookKiUserExceptionDispatcher;
//PHOOK(ProcLdrInitializeThunk) HookLdrInitializeThunk;
//PHOOK(ProcRtlDispatchException) HookRtlDispatchException;
PHOOK(ProcNtUnmapViewOfSection) HookNtUnmapViewOfSection;     
PHOOK(ProcNtMapViewOfSection) HookNtMapViewOfSection;
PHOOK(ProcNtGetContextThread) HookNtGetContextThread;
PHOOK(ProcNtSetContextThread) HookNtSetContextThread;
PHOOK(ProcNtTerminateThread)  HookNtTerminateThread;
PHOOK(ProcNtTerminateProcess) HookNtTerminateProcess;                          
PHOOK(ProcNtContinue) HookNtContinue;

SHookLdrpInitialize       LdrpInitHook;
SHookRtlDispatchException ExpDispHook;
DWORD   ModInjFlags = 0;  // If 0 then the module is loaded normally(With loader)   // -1 if the module is hidden or a proxy
//BYTE ProxyEncKey = 0;
//PBYTE ProxyDllCopy = NULL;
//DWORD ProxyDllSize = 0;
GhDbg::CDbgClient* Dbg = NULL;
HANDLE  hIpcTh      = NULL;
DWORD   MainThId    = 0;
DWORD   LastThID    = -1;
DWORD   LastExcThID = 0;;    // Helps to reduce overhead of NtContinue hook

//LPSTR   LibPathName = NULL;     // TODO: Add an option to not use a detectable hooks ("No detectable hooks")

PBYTE   ThisLibBase = NULL;
//SIZE_T  ThisLibSize = 0;

PBYTE   MainExeBase = NULL;
//SIZE_T  MainExeSize = 0;

alignas(16) BYTE ArrDbgClient[sizeof(GhDbg::CDbgClient)];

wchar_t SysDirPath[MAX_PATH];
wchar_t StartUpDir[MAX_PATH];
wchar_t CfgFilePath[MAX_PATH];
wchar_t WorkFolder[MAX_PATH];
//===========================================================================
/*
 NOTE: Only a SystemService(sysenter/int2E) type of functions is allowed to be used 

 Can be loaded by: XDbgPlugin, GInjer, A target process somehow

 Injector can load a DLL with LdrLoadDll or as '(HMODULE)Mod->ModuleBase, DLL_REFLECTIVE_LOAD, Mod'
 Ginjer injects from a main thread
*/
// Reflective load:
//     hModule    = Module Base
//     ReasonCall = 15
//     lpReserved = SInjModDesc*  (Can be used to find SBlkDescr*)
//===========================================================================
BOOL APIENTRY DLLMain(HMODULE hModule, DWORD ReasonCall, LPVOID lpReserved)  // ReasonCall and lpReserved is invalid for mfRunUAPC,mfRunRMTH,mfRunThHij
{
 SModDesc* ModDesc = ModDescFromCurTh();        // NULL if loaded not by GInjer  // NOTE: GInjer uses main thread
 SBlkDesc* BlkDesc = AddrToBlkDesc(ModDesc);
 SLdrDesc* LdrDesc = GetCurLdrDesc(BlkDesc); 
 UINT   RemThFlags = (DWORD)hModule & InjLdr::RemThModMarker;      // DLLMain has been passed to CreateRemoteThread/APC/ExistingThread (Where is only one argument available)  // Normal HMODULE would be aligned at 0x1000   
#ifdef _DEBUG
 if(ModDesc){LdrLogInit(ModDesc); LDRLOG("Hello from %08X: %ls", ModDesc->Flags, &ModDesc->ModulePath);}
#endif
 if(RemThFlags || (ReasonCall >= DLL_REFLECTIVE_LOAD))  // NOTE: Variables get read in conditions even if these conditions is skipped   // Either an own thread or APC callback of an existing thread  // ReasonCall may be already outside of stack(Remote Thread)!
  {  
   DWORD InjFlg = (RemThFlags?RemThFlags:(ReasonCall & InjLdr::RemThModMarker)) << 24;   // ReasonCall = (Flags >> 24)|0x100  //  mfRunUAPC,mfRunRMTH,mfRunThHij,mfRawRMTH
   bool NotOwnThread  = (InjFlg & (InjLdr::mfRunUAPC|InjLdr::mfRunThHij));
   bool NotReusableTh = ModDesc || NotOwnThread;
   if(InjFlg & InjLdr::mfRunUAPC)   // Cannot reuse these threads
    {
     //
     // TODO: Prevent multi-entering from different threads when APC or Hijack injection method used
     //
    }
   if(ModDesc)hModule = (HMODULE)InjLdr::ReflectiveRelocateSelf(hModule, (LdrDesc)?((PVOID)LdrDesc->NtDllBase):(NULL));  // Allocate to a new buffer  // Loaded by GInjer                       
     else hModule = (HMODULE)InjLdr::PEImageInitialize(hModule);      // Relocate in current buffer (Must be large enough)       // Loaded by a Debugger plugin
   if(!NotReusableTh)hIpcTh = NtCurrentThread;   // Can be changed later, before Start, if needed   // A reusable injected remote thread  // Assign globals after relocation
   if(ModDesc && !NotOwnThread)MainThId = NtCurrentThreadId();    // Main thread by GInjer
   ReasonCall  = DLL_PROCESS_ATTACH;
   ModInjFlags = InjFlg;   // Injected with
  } 
   else MainThId = NtCurrentThreadId();   // Injected from a Main Thread or loaded normally
 switch(ReasonCall)	    
  {			 
   case DLL_PROCESS_ATTACH:
    {
     wchar_t DllDirPath[MAX_PATH];
     ThisLibBase  = (PBYTE)hModule;
	 MainExeBase  = (PBYTE)NNTDLL::GetModuleBaseLdr(NULL); // GetModuleHandleA(NULL);
//     LibPathName  = (LPSTR)&SysDirPath;
//     ThisLibSize  = GetRealModuleSize(ThisLibBase);
//     MainExeSize  = GetRealModuleSize(MainExeBase);
            
     NNTDLL::GetModuleNameLdr(hModule,DllDirPath,countof(DllDirPath));    //  GetModuleFileNameW((HMODULE)hModule,DllDirPath,countof(DllDirPath));        
//     GetSystemDirectoryW(SysDirPath,countof(SysDirPath));   // Get it from PEB?
     NSTR::StrCnat(SysDirPath, L"\\");
     NSTR::StrCnat(SysDirPath,GetFileName(DllDirPath));
     NNTDLL::GetModuleNameLdr(MainExeBase,StartUpDir,countof(StartUpDir));    //  GetModuleFileNameW((HMODULE)MainExeBase,StartUpDir,countof(StartUpDir));        
        
	 NSTR::StrCopy(WorkFolder, StartUpDir);
     TrimFilePath(WorkFolder);
//     NSTR::StrCnat((LPSTR)&WorkFolder,".LOGS\\");
#ifndef NOLOG
     NSTR::StrCopy(LogFilePath, WorkFolder);
	 NSTR::StrCnat(LogFilePath, GetFileName(StartUpDir));
     NSTR::StrCnat(LogFilePath, ctENCSA(LOGFILE));
#endif
     NSTR::StrCopy(CfgFilePath, WorkFolder);
     NSTR::StrCnat(CfgFilePath, GetFileName(StartUpDir));
     NSTR::StrCnat(CfgFilePath, ctENCSA(CFGFILE));	

//     CreateDirectoryPath(WorkFolder);
     LoadConfiguration();
	 DBGMSG("Starting up... (Time=%016X), Owner='%ls'", SysTimeToTime64(NNTDLL::GetSystemTime()), &StartUpDir);
	 DBGMSG("RemThFlags=%08X, hIpcTh=%p, ModDesc=%p, hModule=%p, lpReserved=%p, ModInjFlags=%08X, MainThId=%u", RemThFlags, hIpcTh, ModDesc, hModule, lpReserved, ModInjFlags, MainThId);
     TrimFilePath(StartUpDir);
     DBGMSG("WorkFolder: %ls", &WorkFolder);
     DBGMSG("StartUpDir: %ls", &StartUpDir);
     DBGMSG("SysDirPath: %ls", &SysDirPath);

/*     {
      NTSTATUS stat = GhDbg::CDbgClient::CreateIpcThread(&hIpcTh, NULL, TRUE);   // <<<<<<<<< TEST !!!!!!!!!!!!
     }  */
/*     BOOL dres = true;
     if(!ModInjected && HideDllProxy)    // NOTE: NO MORE DLL PROXY NEEDED
      {
       PVOID EntryPT = NULL;
       PVOID NewBase = NULL;
       hIpcTh = CreateThread(NULL,0,&GhDbg::CDbgClient::IPCQueueThread,NULL,CREATE_SUSPENDED,NULL);   // Some anticheats prevent creation of threads outside of any module
       if(InjLdr::HideSelfProxyDll(hModule, GetModuleHandleA(ctENCSA("ntdll.dll")), (LPSTR)&SysDirPath, &NewBase, &EntryPT) > 0)   // Are imports from our proxy DLL is already resolved by loader at this point?
        {
         DBGMSG("Calling EP of a real DLL: Base=%p, EP=%p",hModule,EntryPT);
         dres = ((decltype(DLLMain)*)EntryPT)(hModule, ReasonCall, lpReserved);   // Pass DLL_PROCESS_ATTACH notification
         hModule = (HMODULE)NewBase;
         if(HideDllProxyDsk && DllDirPath[0])
          {
           DBGMSG("Hiding from disk...");
           if(RstDskHiddenProxy)
            {
             ProxyEncKey = (GetTickCount() >> 3) | 0x80;
             HANDLE hFile = CreateFileA((LPSTR)&DllDirPath,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
             if(hFile != INVALID_HANDLE_VALUE)
              {
               DWORD Result = 0;
               ProxyDllSize = GetFileSize(hFile,NULL);
               ProxyDllCopy = (PBYTE)VirtualAlloc(NULL,ProxyDllSize+MAX_PATH,MEM_COMMIT,PAGE_EXECUTE_READWRITE);  
               if(!ProxyDllSize || !ProxyDllCopy || !ReadFile(hFile,ProxyDllCopy,ProxyDllSize,&Result,NULL) || !Result){VirtualFree(ProxyDllCopy,0,MEM_RELEASE); ProxyDllCopy=NULL;}
               CloseHandle(hFile);
               ProxyDllSize = Result;
               memcpy(&ProxyDllCopy[ProxyDllSize],&DllDirPath,MAX_PATH);
               for(UINT ctr=0,total=ProxyDllSize+MAX_PATH;ctr < total;ctr++)ProxyDllCopy[ctr] = EncryptByteWithCtr(ProxyDllCopy[ctr], ProxyEncKey, ctr);             
              }
             if(ProxyDllCopy)      
              {
               HookNtTerminateProcess.SetHook("NtTerminateProcess","ntdll.dll");
              }
            }
           DeleteFileA((LPSTR)&DllDirPath);     // It is no longer mapped
           DBGMSG("Done hiding from disk!");
          }
        }
       DBGMSG("Done hiding!");
      } */
     if(!InitApplication())return false; 
     if(ModInjFlags & InjLdr::mfRunRMTH){DBGMSG("Terminating injected thread(this): %u", NtCurrentThreadId()); NtTerminateThread(NtCurrentThread,0);}     // Stack frame may be incorrect
     return true;  //dres;
    }
     break;									
   case DLL_THREAD_ATTACH:
     if(Dbg && Dbg->IsActive())Dbg->TryAddCurrThread();  //Dbg->Report_CREATE_THREAD_DEBUG_EVENT(NtCurrentThreadId());     // For a simple testing
     break; 
   case DLL_THREAD_DETACH:
     if(Dbg && Dbg->IsActive())Dbg->Report_EXIT_THREAD_DEBUG_EVENT(NtCurrentTeb(),0);     // For a simple testing
     break;
   case DLL_PROCESS_DETACH: 
     if(Dbg && Dbg->IsActive())Dbg->Report_EXIT_PROCESS_DEBUG_EVENT(NtCurrentTeb(),0);      // For a simple testing
     UnInitApplication();     
	 break;

   default : return false;  
  }
 return true;
}
//====================================================================================
void _stdcall LoadConfiguration(void)   // Avoid any specific file access here for now
{ 
#ifdef _DEBUG
   LogMode = lmFile;
   // NSTR::StrCopy(LogFilePath, "C:\\TEST\\_LogMy.txt");
#endif

/* CJSonItem Root;
 CMiniStr  str;
 str.FromFile(CfgFilePath);
 bool BinFmt = (str.Length())?(CJSonItem::IsBinaryEncrypted(str.c_data()) >= 0):(0);
 DBGMSG("Loading config(Bin=%u): %ls", BinFmt, &CfgFilePath);
 if(str.Length())Root.FromString(str);
 CJSonItem* Params = EnsureJsnParam(jsObject, "Parameters", &Root);  
 LogMode       = EnsureJsnParam((int)LogMode,       "LogMode",       Params)->GetValInt();     // lmCons;//
 IPCSize       = EnsureJsnParam(IPCSize,            "IPCSize",       Params)->GetValInt(); 
 SuspMainThAtLd = EnsureJsnParam(SuspMainThAtLd,     "SuspMainThAtLd",    Params)->GetValBol(); 
 //HideDllProxy  = EnsureJsnParam(HideDllProxy,         "HideDllProxy",    Params)->GetValBol(); 
 //HideDllProxyDsk = EnsureJsnParam(HideDllProxyDsk,         "HideDllProxyDsk",    Params)->GetValBol(); 
 AllowEjectOnDetach = EnsureJsnParam(AllowEjectOnDetach,         "AllowEjectOnDetach",    Params)->GetValBol();  
// if(LogMode & lmCons){AllocConsole();}                                      // SetWinConsoleSizes(1000, 500, 1000, 500);

 CJSonItem* DbgParams = EnsureJsnParam(jsObject, "DbgClient", &Root);   
 if(Dbg)
  {
   Dbg->HideDbgState = EnsureJsnParam(Dbg->HideDbgState,        "HideDbgState",   DbgParams)->GetValBol(); 
   Dbg->AllowPrTerm  = EnsureJsnParam(Dbg->AllowPrTerm,         "AllowPrTerm",    DbgParams)->GetValBol(); 
   Dbg->AllowThTerm  = EnsureJsnParam(Dbg->AllowThTerm,         "AllowThTerm",    DbgParams)->GetValBol(); 
   Dbg->OnlyOwnSwBP  = EnsureJsnParam(Dbg->OnlyOwnSwBP,         "OnlyOwnSwBP",    DbgParams)->GetValBol(); 
   Dbg->OnlyOwnHwBP  = EnsureJsnParam(Dbg->OnlyOwnHwBP,         "OnlyOwnHwBP",    DbgParams)->GetValBol(); 
   Dbg->OnlyOwnTF    = EnsureJsnParam(Dbg->OnlyOwnTF,           "OnlyOwnTF",      DbgParams)->GetValBol(); 
   Dbg->SwBpVal      = EnsureJsnParam((UINT)Dbg->SwBpVal,       "SwBpVal",        DbgParams)->GetValBol(); 
  }
 DBGMSG("Saving config(Bin=%u): %ls", BinFmt, &CfgFilePath);
 str.Clear();
 if(BinFmt)Root.ToBinary(str,true);
 Root.ToString(str,true);
 str.ToFile(CfgFilePath);  */
}
//------------------------------------------------------------------------------------
void _stdcall SaveConfiguration(int BinFmt)
{
/* CJSonItem Root;
 CMiniStr  str;
 str.FromFile(CfgFilePath);
 bool VBinFmt = (str.Length() || (BinFmt < 0))?(CJSonItem::IsBinaryEncrypted(str.c_data()) >= 0):(BinFmt > 0);
 DBGMSG("Loading config(Bin=%u): %ls", VBinFmt, &CfgFilePath);
 if(str.Length())Root.FromString(str);
 CJSonItem* Params = EnsureJsnParam(jsObject, "Parameters", &Root);  
 LogMode       = SetJsnParamValue((int)LogMode,       "LogMode",       Params)->GetValInt();
 IPCSize       = SetJsnParamValue(IPCSize,            "IPCSize",       Params)->GetValInt();  
 SuspMainThAtLd  = SetJsnParamValue(SuspMainThAtLd,   "SuspMainThAtLd",    Params)->GetValBol(); 
 //HideDllProxy       = SetJsnParamValue(HideDllProxy,         "HideDllProxy",    Params)->GetValBol(); 
 //HideDllProxyDsk       = SetJsnParamValue(HideDllProxyDsk,         "HideDllProxyDsk",    Params)->GetValBol(); 
 AllowEjectOnDetach       = SetJsnParamValue(AllowEjectOnDetach,         "AllowEjectOnDetach",    Params)->GetValBol();   
     
 CJSonItem* DbgParams = EnsureJsnParam(jsObject, "DbgClient", &Root);   
 if(Dbg)
  {
   SetJsnParamValue(Dbg->HideDbgState,        "HideDbgState",   DbgParams)->GetValBol(); 
   SetJsnParamValue(Dbg->AllowPrTerm,         "AllowPrTerm",    DbgParams)->GetValBol(); 
   SetJsnParamValue(Dbg->AllowThTerm,         "AllowThTerm",    DbgParams)->GetValBol(); 
   SetJsnParamValue(Dbg->OnlyOwnSwBP,         "OnlyOwnSwBP",    DbgParams)->GetValBol(); 
   SetJsnParamValue(Dbg->OnlyOwnHwBP,         "OnlyOwnHwBP",    DbgParams)->GetValBol(); 
   SetJsnParamValue(Dbg->OnlyOwnTF,           "OnlyOwnTF",      DbgParams)->GetValBol(); 
   SetJsnParamValue((UINT)Dbg->SwBpVal,       "SwBpVal",        DbgParams)->GetValBol(); 
  }
 DBGMSG("Saving config(Bin=%u): %ls", BinFmt, &CfgFilePath);
 str.Clear();
 if(VBinFmt)Root.ToBinary(str,true);
 Root.ToString(str,true);
 str.ToFile(CfgFilePath);   */
}
//------------------------------------------------------------------------------------
bool _stdcall InitApplication(void)
{
 DBGMSG("Enter");
 if(GhDbg::CDbgClient::IsExistForID(NtCurrentProcessId())){DBGMSG("Already injected!"); return false;}

/*#ifdef _AMD64_
 HookRtlRestoreContext.SetHook("RtlRestoreContext","ntdll.dll");     // NtContinue
#endif
 HookKiUserExceptionDispatcher.SetHook("KiUserExceptionDispatcher","ntdll.dll");    
 HookLdrInitializeThunk.SetHook("LdrInitializeThunk","ntdll.dll");     */

 Dbg = new ((void*)&ArrDbgClient) GhDbg::CDbgClient(ThisLibBase);
 Dbg->UsrReqCallback = &DbgUsrReqCallback;
////////// LoadConfiguration();
 DBGMSG("IPC created: IPCSize=%u",IPCSize);
 PVOID pNtDll = GetNtDllBaseFast(); 
 DBGMSG("NtDllBase: %p",pNtDll);
 HookNtMapViewOfSection.SetHook(GetProcAddr(pNtDll, ctENCSA("NtMapViewOfSection")));         // For DLLs list
 HookNtUnmapViewOfSection.SetHook(GetProcAddr(pNtDll, ctENCSA("NtUnmapViewOfSection")));     // For DLLs list
 HookNtGetContextThread.SetHook(GetProcAddr(pNtDll, ctENCSA("NtGetContextThread")));         // For DRx hiding
 HookNtSetContextThread.SetHook(GetProcAddr(pNtDll, ctENCSA("NtSetContextThread")));         // For DRx hiding
 HookNtTerminateThread.SetHook(GetProcAddr(pNtDll, ctENCSA("NtTerminateThread")));           // For Thread list update
 HookNtTerminateProcess.SetHook(GetProcAddr(pNtDll, ctENCSA("NtTerminateProcess")));         // Importand for latest Windows 10 bugs
 HookNtContinue.SetHook(GetProcAddr(pNtDll, ctENCSA("NtContinue")));                         // For Thread list update   // TODO: Replace with LdrInitializeThunk hook
 ExpDispHook.SetHook(ProcExpDispBefore, ProcExpDispAfter);                          // Debugger core function
 LdrpInitHook.SetHook(ProcLdrpInitialize);                                          // Optional: HookNtContinue can do the job but threads will be reported after initialization
 DBGMSG("Hooks set: hIpcTh=%p, MainThId=%u",hIpcTh, MainThId);  
 Dbg->Start(IPCSize, hIpcTh, NULL, MainThId, (hIpcTh != NtCurrentThread)?NtCurrentThreadId():0);     // Start it from DLL Main to avoid of similair DLL being loaded again    // Exclude current temporary thread
 DBGMSG("IPC started");
 return true;
}                                               
//------------------------------------------------------------------------------------
void _stdcall UnInitApplication(void)
{   
 DBGMSG("Enter");
 if(Dbg)Dbg->~CDbgClient();   //  delete(Dbg);  // Compiler will ALWAYS put an unused call to operator DELETE here if called 'Dbg->~CDbgClient()' in Release build if not specified '/MTd'(Multi-Threaded Debug) but it will define '_DEBUG to 1'!
 DBGMSG("IPC destroyed");
 HookNtContinue.Remove();
 HookNtTerminateThread.Remove();
 HookNtTerminateProcess.Remove();
 HookNtUnmapViewOfSection.Remove();
 HookNtMapViewOfSection.Remove(); 
 HookNtSetContextThread.Remove();
 HookNtGetContextThread.Remove();
 LdrpInitHook.Remove();
 ExpDispHook.Remove();
 DBGMSG("Hooks removed");
}
//------------------------------------------------------------------------------------
int _fastcall DbgUsrReqCallback(ShMem::CMessageIPC::SMsgHdr* Req, PVOID ArgA, UINT ArgB)
{
 if(Req->MsgID == GhDbg::miDbgGetConfigs)
  {
   ShMem::CArgPack<>* apo = (ShMem::CArgPack<>*)ArgA;   
//   apo->PushArgEx(HideDllProxy, "Hide Proxy DLL (After Restart)", GhDbg::CDbgClient::MakeCfgItemID(++ArgB,GhDbg::dtBool));  
//   apo->PushArgEx(HideDllProxyDsk, "Hide Proxy DLL on Disk (After Restart)", GhDbg::CDbgClient::MakeCfgItemID(++ArgB,GhDbg::dtBool));  
   if(!ModInjFlags)apo->PushArgEx(AllowEjectOnDetach, ctENCSA("Allow Eject On Detach"), GhDbg::CDbgClient::MakeCfgItemID(++ArgB,GhDbg::dtBool));    
   if(!ModInjFlags){bool Nons = false; apo->PushArgEx(Nons, ctENCSA("Eject"), GhDbg::CDbgClient::MakeCfgItemID(++ArgB,GhDbg::dtBool));}    
   return ArgB;
  }
 if(Req->MsgID == GhDbg::miDbgSetConfigs)
  {
   UINT CfgIdx = 0;
   UINT Type   = GhDbg::CDbgClient::ReadCfgItemID(ArgB, &CfgIdx);
   if(ArgA)
    {
     switch(CfgIdx)                            // New Process Injection
      {  
//       case 1:
//         HideDllProxy = *(bool*)ArgA;
//        break;
//       case 2:
//         HideDllProxyDsk = *(bool*)ArgA;
//        break;
       case 1:
         AllowEjectOnDetach = *(bool*)ArgA;
        break;
       case 2:  
         if(!ModInjFlags)
          {
           DBGMSG("Ejecting by user!");
           UnInitApplication();
           DBGMSG("Uninit done. Unmapping...");
           NtTerminateThread(NtCurrentThread, 0);       //// InjLdr::UnmapAndTerminateSelf(ThisLibBase);  // TODO: Self unmap or deallocate        
          }
        break;
      }
    }
   SaveConfiguration();
   return 0;
  }
 if(Req->MsgID == GhDbg::miDbgDetachNtfy)
  {
   if(AllowEjectOnDetach && !ModInjFlags)
    {
     DBGMSG("Ejecting on Detach!");
     UnInitApplication();
     DBGMSG("Uninit done. Unmapping...");
     NtTerminateThread(NtCurrentThread, 0);   //// InjLdr::UnmapAndTerminateSelf(ThisLibBase);    // TODO: Self unmap or deallocate
    }
  }
 return 0;
}
//====================================================================================
//                           Debugger support
//------------------------------------------------------------------------------------
// x32:  [ESP]   = EXCEPTION_RECORD*    // Get it with '_ReturnAddress()'
//       [ESP+4] = CONTEXT*
//
// x64:  CONTEXT           // sizeof(CONTEXT) is 0x04E8  // Size of this block is 0x04F0 (On Win7 and Win10 x64) (Aligned to 16?)
//       EXCEPTION_RECORD
//
/*__declspec(noreturn) void _fastcall ProcKiUserExceptionDispatcher(void)  
{
 PBYTE FramePtr = (PBYTE)_AddressOfReturnAddress();   // No return address on stack    // Must match value of ESP on enter to this function
#ifdef _AMD64_
 PCONTEXT Context = (PCONTEXT)FramePtr;
 PEXCEPTION_RECORD ExceptionRecord = (PEXCEPTION_RECORD)&FramePtr[0x4F0];       // AlignFrwd(sizeof(CONTEXT),16)]  ??????????????????????????
#else
 PCONTEXT Context = (PCONTEXT)((PVOID*)FramePtr)[1];
 PEXCEPTION_RECORD ExceptionRecord = (PEXCEPTION_RECORD)((PVOID*)FramePtr)[0];
#endif 
 //
 HookKiUserExceptionDispatcher.OrigProc();     // Must be tail optimized - Requires optimization to be enabled (O1,O2,Ox)
}
//------------------------------------------------------------------------------------
__declspec(noreturn) VOID NTAPI ProcRtlRestoreContext(PCONTEXT ContextRecord, PEXCEPTION_RECORD ExceptionRecord)
{                    
 if(Dbg && Dbg->IsActive())Dbg->DebugThreadLoad(NtCurrentThreadId(), ContextRecord);
 HookRtlRestoreContext.OrigProc(ContextRecord, ExceptionRecord);   
} 
//------------------------------------------------------------------------------------
void NTAPI ProcLdrInitializeThunk(PVOID ArgA, PVOID ArgB, PVOID ArgC, PVOID ArgD)
{
 if(Dbg && Dbg->IsActive())Dbg->GetThread(NtCurrentThreadId());      
 HookLdrInitializeThunk.OrigProc(ArgA, ArgB, ArgC, ArgD);     // Must be tail optimized - Requires optimization to be enabled (O1,O2,Ox)
}  */
//------------------------------------------------------------------------------------
void _stdcall ProcLdrpInitialize(volatile PCONTEXT Ctx, volatile PVOID NtDllBase)
{
 DBGMSG("RetAddr=%p, Ctx=%p, NtDllBase=%p",_ReturnAddress(),Ctx,NtDllBase); 
// if(Dbg && Dbg->IsActive()){LastThID = NtCurrentThreadId(); Dbg->TryAddCurrThread();}   // LastThID prevents TryAddCurrThread from ProcNtContinue
}
//------------------------------------------------------------------------------------
/* x64
RSP+00 = RetAddr
RSP+08 = RCX
RSP+10 = RDX
RSP+18 = R8
RSP+20 = R9

      mov     rcx, rsp
      add     rcx, 4F0h       ; EXCEPTION_RECORD ExceptionRecord
      mov     rdx, rsp        ; PCONTEXT ContextRecord
      call    RtlDispatchException     // Reserved space for 4 arguments is in beginning of CONTEXT on x64!
// Can`t hook it as usual. Too many dirty tricks are used with SEH, VEH and stack unwinding 
// It may be called recursievly with RtlRaiseStatus
*/                                                                                    
bool _cdecl ProcExpDispBefore(volatile PVOID ArgA, volatile PVOID ArgB, volatile PVOID ArgC, volatile PVOID ArgD, volatile PVOID RetVal)
{
// DBGMSG("Code=%08X, Addr=%p, FCtx=%08X",((PEXCEPTION_RECORD)ArgA)->ExceptionCode, ((PEXCEPTION_RECORD)ArgA)->ExceptionAddress, ((PCONTEXT)ArgB)->ContextFlags);     
 DWORD ThID = LastExcThID = NtCurrentThreadId();
 if(!Dbg || !Dbg->IsActive() || Dbg->IsDbgThreadID(ThID))return true;
 if(Dbg->HandleException(ThID, (PEXCEPTION_RECORD)ArgA, (PCONTEXT)ArgB)){RetVal = (PVOID)TRUE; /*DBGMSG("Handled!");*/ return false;}    // Handled by a debugger
 if(!Dbg->HideDbgState)return true;

// CONTEXT ForgedCtx;      // No debugger context hiding for now :(                      // Can it be detected that this is a copy of original CONTEXT and have a different address on stack?
// memcpy(&ForgedCtx,ContextRecord,sizeof(CONTEXT));
// Dbg->DebugThreadLoad(ThID, &ForgedCtx);       // Load any previous DRx modifications from internal buffer     
// BOOLEAN res = HookRtlDispatchException.OrigProc(ExceptionRecord, &ForgedCtx);
 return true;
}
//------------------------------------------------------------------------------------
bool _cdecl ProcExpDispAfter(volatile PVOID ArgA, volatile PVOID ArgB, volatile PVOID ArgC, volatile PVOID ArgD, volatile PVOID RetVal)
{
// DBGMSG("Exiting!");      
// Dbg->DebugThreadSave(ThID, &ForgedCtx);  // Save any modifications to DRx in a separate struct    // NOTE: It is rare that a AntiDebug check will use an exception handlers to check DRx?
// Dbg->DebugRstExcContext(ContextRecord, &ForgedCtx);
 return true;
}
//------------------------------------------------------------------------------------
// SEC_FILE             0x0800000     
// SEC_IMAGE            0x1000000     
// SEC_PROTECTED_IMAGE  0x2000000  
//
// Normal Dll map: AllocationType=00800000[MEM_ROTATE], Win32Protect=00000004[PAGE_READWRITE]    // Win10
//
// WinXPx32: ZwMapViewOfSection(v88, -1, (int)&v89, 0, 0, 0, (int)&v86, 1, 0, 4);
// Win7x64:  ZwMapViewOfSection(v9, -1i64, v13, 0i64, 0i64, 0i64, v12, 1, v10, 4);
//
NTSTATUS NTAPI ProcNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect)    // NOTE: A detectable hook!
{                
 NTSTATUS res = HookNtMapViewOfSection.OrigProc(SectionHandle,ProcessHandle,BaseAddress,ZeroBits,CommitSize,SectionOffset,ViewSize,InheritDisposition,AllocationType,Win32Protect);    // May return STATUS_IMAGE_NOT_AT_BASE
 if((res >= 0) && BaseAddress && *BaseAddress && ViewSize && *ViewSize)      // && Dbg && Dbg->IsActive() && GhDbg::IsCurrentProcess(ProcessHandle) && IsValidPEHeaderBlk(*BaseAddress, Dbg->IsMemAvailable(*BaseAddress)))    // Try to get the module`s name?
  {            
   DBGMSG("Module: Status=%08X, SectionHandle=%p, BaseAddress=%p, ViewSize=%08X, AllocationType=%08X, Win32Protect=%08X",res,SectionHandle,*BaseAddress,*ViewSize,AllocationType,Win32Protect);     
   if(Dbg && Dbg->IsActive() && (Win32Protect == PAGE_READWRITE) && NNTDLL::IsCurrentProcess(ProcessHandle) && IsValidPEHeaderBlk(*BaseAddress, Dbg->IsMemAvailable(*BaseAddress)))   // <<< Duplicate mapping causes BPs to be set again and never removed if this module is already loaded(If this is not caused by LdrLoadDll)!
    {
     Dbg->Report_LOAD_DLL_DEBUG_INFO(NtCurrentTeb(), *BaseAddress);  // NOTE: This is done before PE configuration by LdrLoadDll  // Events:TLS Callbacks must be disabled or xg4dbg will crash in 'cbLoadDll{ auto modInfo = ModInfoFromAddr(duint(base));}' (because it won`t check for NULL) if this mapping will be unmapped too soon
    }
  } 
//   else {DBGMSG("Status=%08X, SectionHandle=%p, ViewSize=%08X, AllocationType=%08X, Win32Protect=%08X",res,SectionHandle,ViewSize,AllocationType,Win32Protect);}
 return res;
}
//------------------------------------------------------------------------------------
NTSTATUS NTAPI ProcNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress)   // NOTE: A detectable hook!
{
 if(NNTDLL::IsCurrentProcess(ProcessHandle) && IsValidPEHeaderBlk(BaseAddress, Dbg->IsMemAvailable(BaseAddress)))
  {
   DBGMSG("BaseAddress=%p",BaseAddress);    
   if(Dbg && Dbg->IsActive() && Dbg->IsOtherConnections())Dbg->Report_UNLOAD_DLL_DEBUG_EVENT(NtCurrentTeb(), BaseAddress); 
  }                                            
 return HookNtUnmapViewOfSection.OrigProc(ProcessHandle,BaseAddress);
}
//------------------------------------------------------------------------------------
// Called at start of a thread(After initialization) and at return from APC/Exception
// Protect CONTEXT here? Can be used separately from any kernel callback?  // Is someone using it for current thread`s CONTEXT modification(DRx corruption)?
// On Win10 x64 it is called by RtlRestoreContext for normal exceptions but it is not used on Win7 x64  
// On x32 it is called from LdrInitializeThunk when a new thread created (User mode thread`s entry point) 
// LdrInitializeThunk exits with NtContinue
// Hooking LdrInitializeThunk is hard
//
NTSTATUS NTAPI ProcNtContinue(PCONTEXT ContextRecord, BOOLEAN TestAlert)   // NOTE: A detectable hook!     // NOTE: Too much overhead of exception processing with this(Twice 'GetThread' on breakpoints)
{
 DWORD CurrThID = NtCurrentThreadId();
 if(Dbg && (CurrThID != LastThID) && (CurrThID != LastExcThID) && Dbg->IsActive()){LastThID=CurrThID; Dbg->TryAddCurrThread();}      // Report this thread if it is not in list yet
 return HookNtContinue.OrigProc(ContextRecord, TestAlert);   // Will not return
}
//------------------------------------------------------------------------------------
// ProcessHandle is NULL then terminates all threads, except a current one 
// RtlExitUserProcess: NtTerminateProcess(NULL), NtTerminateProcess(NtCurrentProcess)
// On Win 10 (2019) some suspended threads won`t be terminated!
//   Some race condition with NtSuspendThread and NtTerminateProcess when called from different threads at almost same time? 
//   And they will be suspended when reporting i.e. DLL_UNLOAD, but GhostDbg thread already dead and can`t unfreeze these threads
// Could be a useful feature of NtSuspendProcess ;)
NTSTATUS NTAPI ProcNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus)  
{
 DBGMSG("ProcessHandle=%p, ExitStatus=%08X",ProcessHandle,ExitStatus); 
/* if(RstDskHiddenProxy && ProxyDllCopy)   // Restore the Proxy Dll on disk
  {   
   BYTE DllPath[MAX_PATH];
   for(UINT ctr=0,total=ProxyDllSize+MAX_PATH;ctr < total;ctr++)ProxyDllCopy[ctr] = DecryptByteWithCtr(ProxyDllCopy[ctr], ProxyEncKey, ctr);
   memcpy(&DllPath,&ProxyDllCopy[ProxyDllSize],MAX_PATH);
   HANDLE hFile = CreateFileA((LPSTR)&DllPath,GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
   if(hFile != INVALID_HANDLE_VALUE)
    {
     DWORD Result = 0;
     WriteFile(hFile,ProxyDllCopy,ProxyDllSize,&Result,NULL);
     CloseHandle(hFile);
     VirtualFree(ProxyDllCopy,0,MEM_RELEASE); 
     ProxyDllCopy = NULL;
     DBGMSG("ProxyDll Restored: %s", (LPSTR)&DllPath);
    }
  } */
 if(Dbg && Dbg->IsActive() && (!ProcessHandle || (ProcessHandle == NtCurrentProcess))) 
  {   
   if(!ProcessHandle)Dbg->Report_EXIT_PROCESS_DEBUG_EVENT(NtCurrentTeb(),0);   // (ProcessHandle==NULL) will terminate all other threads, including GhostDbg
     else UnInitApplication();     // Do not report EXIT_PROCESS_DEBUG_EVENT second time!
  }
 return HookNtTerminateProcess.OrigProc(ProcessHandle, ExitStatus);
} 
//------------------------------------------------------------------------------------
// Exit from a thread`s proc will also end up here  
// ThreadHandle is NULL for a current thread; NtCurrentThread is also works
NTSTATUS NTAPI ProcNtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus)   // NOTE: A detectable hook!
{
 PTEB teb = NULL;
 DBGMSG("ThreadHandle=%p",ThreadHandle); 
 if(Dbg && Dbg->IsActive() && (teb=NNTDLL::GetCurrProcessTEB(ThreadHandle))){ Dbg->Report_EXIT_THREAD_DEBUG_EVENT(teb,ExitStatus); } 
 DBGMSG("Terminating: %p, %u",teb,(teb?(UINT)teb->ClientId.UniqueThread:0)); 
 return HookNtTerminateThread.OrigProc(ThreadHandle, ExitStatus);   // TODO: Just call our own NtTerminateThread 
}
//------------------------------------------------------------------------------------    
NTSTATUS NTAPI ProcNtGetContextThread(HANDLE ThreadHandle, PCONTEXT Context)    // NOTE: A detectable hook!
{  
 ULONG ThID;
 NTSTATUS res = HookNtGetContextThread.OrigProc(ThreadHandle, Context);    // TODO: Just call our own NtGetContextThread(What if it is hooked by someone)?
 if(!res && Dbg && Dbg->IsActive() && Dbg->HideDbgState && (ThID=NNTDLL::GetCurrProcessThreadID(ThreadHandle)))Dbg->DebugThreadLoad(ThID, Context);   // Load into CONTEXT a previously saved DRx instead of currently read ones
 return res;
}
//------------------------------------------------------------------------------------    
NTSTATUS NTAPI ProcNtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context)    // NOTE: A detectable hook!   // Do not let DRx to be changed by this
{
 ULONG ThID;
 if(!Dbg || !Dbg->IsActive() || !Dbg->HideDbgState || !(ThID=NNTDLL::GetCurrProcessThreadID(ThreadHandle)))return HookNtSetContextThread.OrigProc(ThreadHandle, Context);   // TODO: Just call our own NtSetContextThread
 CONTEXT FCtx;      // Copy of CONTEXT where CONTEXT_DEBUG_REGISTERS is removed (CONTEXT_DEBUG_REGISTERS must be preserved in original Context in case it may be checked)
 Dbg->DebugThreadSave(ThID, Context);    // Save any magic numbers which may be stored in debug registers to detect a debugger
 memcpy(&FCtx,Context,sizeof(CONTEXT));
 FCtx.ContextFlags &= ~0x00000010;   // CONTEXT_DEBUG_REGISTERS     // TF is allowed to change? 
 return HookNtSetContextThread.OrigProc(ThreadHandle, &FCtx);   // TODO: Just call our own NtSetContextThread(What if it is hooked by someone)?
}
//------------------------------------------------------------------------------------      


#pragma optimize( "", off )

#pragma code_seg()

//====================================================================================
//								 WRAPPER FUNCTIONS
//------------------------------------------------------------------------------------
namespace ProxyExport    // NOTE: THIS WILL BE REMOVED (Use GInjer for injection)
{
// winspool.drv
/*APIWRAPPER(LibPathName, GetDefaultPrinterA)
APIWRAPPER(LibPathName, AbortPrinter)
APIWRAPPER(LibPathName, AddFormA)
APIWRAPPER(LibPathName, AddFormW)
APIWRAPPER(LibPathName, AddJobA)
APIWRAPPER(LibPathName, AddJobW)
APIWRAPPER(LibPathName, AddMonitorA)
APIWRAPPER(LibPathName, AddMonitorW)
APIWRAPPER(LibPathName, AddPortA)
APIWRAPPER(LibPathName, AddPortExA)
APIWRAPPER(LibPathName, AddPortExW)
APIWRAPPER(LibPathName, AddPortW)
APIWRAPPER(LibPathName, AddPrintProcessorA)
APIWRAPPER(LibPathName, AddPrintProcessorW)
APIWRAPPER(LibPathName, AddPrintProvidorA)
APIWRAPPER(LibPathName, AddPrintProvidorW)
APIWRAPPER(LibPathName, AddPrinterA)
APIWRAPPER(LibPathName, AddPrinterConnection2A)
APIWRAPPER(LibPathName, AddPrinterConnection2W)
APIWRAPPER(LibPathName, AddPrinterConnectionA)
APIWRAPPER(LibPathName, AddPrinterConnectionW)
APIWRAPPER(LibPathName, AddPrinterDriverA)
APIWRAPPER(LibPathName, AddPrinterDriverExA)
APIWRAPPER(LibPathName, AddPrinterDriverExW)
APIWRAPPER(LibPathName, AddPrinterDriverW)
APIWRAPPER(LibPathName, AddPrinterW)
APIWRAPPER(LibPathName, AdvancedDocumentPropertiesA)
APIWRAPPER(LibPathName, AdvancedDocumentPropertiesW)
APIWRAPPER(LibPathName, AdvancedSetupDialog)
APIWRAPPER(LibPathName, CheckSignatureInFile)
APIWRAPPER(LibPathName, ClosePrinter)
APIWRAPPER(LibPathName, CloseSpoolFileHandle)
APIWRAPPER(LibPathName, CommitSpoolData)
APIWRAPPER(LibPathName, ConfigurePortA)
APIWRAPPER(LibPathName, ConfigurePortW)
APIWRAPPER(LibPathName, ConnectToPrinterDlg)
APIWRAPPER(LibPathName, ConvertAnsiDevModeToUnicodeDevmode)
APIWRAPPER(LibPathName, ConvertUnicodeDevModeToAnsiDevmode)
APIWRAPPER(LibPathName, CorePrinterDriverInstalledA)
APIWRAPPER(LibPathName, CorePrinterDriverInstalledW)
APIWRAPPER(LibPathName, CreatePrintAsyncNotifyChannel)
APIWRAPPER(LibPathName, CreatePrinterIC)
APIWRAPPER(LibPathName, DeleteFormA)
APIWRAPPER(LibPathName, DeleteFormW)
APIWRAPPER(LibPathName, DeleteMonitorA)
APIWRAPPER(LibPathName, DeleteMonitorW)
APIWRAPPER(LibPathName, DeletePortA)
APIWRAPPER(LibPathName, DeletePortW)
APIWRAPPER(LibPathName, DeletePrintProcessorA)
APIWRAPPER(LibPathName, DeletePrintProcessorW)
APIWRAPPER(LibPathName, DeletePrintProvidorA)
APIWRAPPER(LibPathName, DeletePrintProvidorW)
APIWRAPPER(LibPathName, DeletePrinter)
APIWRAPPER(LibPathName, DeletePrinterConnectionA)
APIWRAPPER(LibPathName, DeletePrinterConnectionW)
APIWRAPPER(LibPathName, DeletePrinterDataA)
APIWRAPPER(LibPathName, DeletePrinterDataExA)
APIWRAPPER(LibPathName, DeletePrinterDataExW)
APIWRAPPER(LibPathName, DeletePrinterDataW)
APIWRAPPER(LibPathName, DeletePrinterDriverA)
APIWRAPPER(LibPathName, DeletePrinterDriverExA)
APIWRAPPER(LibPathName, DeletePrinterDriverExW)
APIWRAPPER(LibPathName, DeletePrinterDriverPackageA)
APIWRAPPER(LibPathName, DeletePrinterDriverPackageW)
APIWRAPPER(LibPathName, DeletePrinterDriverW)
APIWRAPPER(LibPathName, DeletePrinterIC)
APIWRAPPER(LibPathName, DeletePrinterKeyA)
APIWRAPPER(LibPathName, DeletePrinterKeyW)
APIWRAPPER(LibPathName, DevQueryPrint)
APIWRAPPER(LibPathName, DevQueryPrintEx)
APIWRAPPER(LibPathName, DeviceCapabilitiesA)
APIWRAPPER(LibPathName, DeviceCapabilitiesW)
APIWRAPPER(LibPathName, DeviceMode)
APIWRAPPER(LibPathName, DevicePropertySheets)
APIWRAPPER(LibPathName, DocumentEvent)
APIWRAPPER(LibPathName, DocumentPropertiesA)
APIWRAPPER(LibPathName, DocumentPropertiesW)
APIWRAPPER(LibPathName, DocumentPropertySheets)
APIWRAPPER(LibPathName, EndDocPrinter)
APIWRAPPER(LibPathName, EndPagePrinter)
APIWRAPPER(LibPathName, EnumFormsA)
APIWRAPPER(LibPathName, EnumFormsW)
APIWRAPPER(LibPathName, EnumJobsA)
APIWRAPPER(LibPathName, EnumJobsW)
APIWRAPPER(LibPathName, EnumMonitorsA)
APIWRAPPER(LibPathName, EnumMonitorsW)
APIWRAPPER(LibPathName, EnumPortsA)
APIWRAPPER(LibPathName, EnumPortsW)
APIWRAPPER(LibPathName, EnumPrintProcessorDatatypesA)
APIWRAPPER(LibPathName, EnumPrintProcessorDatatypesW)
APIWRAPPER(LibPathName, EnumPrintProcessorsA)
APIWRAPPER(LibPathName, EnumPrintProcessorsW)
APIWRAPPER(LibPathName, EnumPrinterDataA)
APIWRAPPER(LibPathName, EnumPrinterDataExA)
APIWRAPPER(LibPathName, EnumPrinterDataExW)
APIWRAPPER(LibPathName, EnumPrinterDataW)
APIWRAPPER(LibPathName, EnumPrinterDriversA)
APIWRAPPER(LibPathName, EnumPrinterDriversW)
APIWRAPPER(LibPathName, EnumPrinterKeyA)
APIWRAPPER(LibPathName, EnumPrinterKeyW)
APIWRAPPER(LibPathName, EnumPrintersA)
APIWRAPPER(LibPathName, EnumPrintersW)
APIWRAPPER(LibPathName, ExtDeviceMode)
APIWRAPPER(LibPathName, FindClosePrinterChangeNotification)
APIWRAPPER(LibPathName, FindFirstPrinterChangeNotification)
APIWRAPPER(LibPathName, FindNextPrinterChangeNotification)
APIWRAPPER(LibPathName, FlushPrinter)
APIWRAPPER(LibPathName, FreePrinterNotifyInfo)
APIWRAPPER(LibPathName, GetCorePrinterDriversA)
APIWRAPPER(LibPathName, GetCorePrinterDriversW)
APIWRAPPER(LibPathName, GetDefaultPrinterW)
APIWRAPPER(LibPathName, GetFormA)
APIWRAPPER(LibPathName, GetFormW)
APIWRAPPER(LibPathName, GetJobA)
APIWRAPPER(LibPathName, GetJobW)
APIWRAPPER(LibPathName, GetPrintExecutionData)
APIWRAPPER(LibPathName, GetPrintProcessorDirectoryA)
APIWRAPPER(LibPathName, GetPrintProcessorDirectoryW)
APIWRAPPER(LibPathName, GetPrinterA)
APIWRAPPER(LibPathName, GetPrinterDataA)
APIWRAPPER(LibPathName, GetPrinterDataExA)
APIWRAPPER(LibPathName, GetPrinterDataExW)
APIWRAPPER(LibPathName, GetPrinterDataW)
APIWRAPPER(LibPathName, GetPrinterDriver2A)
APIWRAPPER(LibPathName, GetPrinterDriver2W)
APIWRAPPER(LibPathName, GetPrinterDriverA)
APIWRAPPER(LibPathName, GetPrinterDriverDirectoryA)
APIWRAPPER(LibPathName, GetPrinterDriverDirectoryW)
APIWRAPPER(LibPathName, GetPrinterDriverPackagePathA)
APIWRAPPER(LibPathName, GetPrinterDriverPackagePathW)
APIWRAPPER(LibPathName, GetPrinterDriverW)
APIWRAPPER(LibPathName, GetPrinterW)
APIWRAPPER(LibPathName, GetSpoolFileHandle)
APIWRAPPER(LibPathName, InstallPrinterDriverFromPackageA)
APIWRAPPER(LibPathName, InstallPrinterDriverFromPackageW)
APIWRAPPER(LibPathName, IsValidDevmodeA)
APIWRAPPER(LibPathName, IsValidDevmodeW)
APIWRAPPER(LibPathName, OpenPrinter2A)
APIWRAPPER(LibPathName, OpenPrinter2W)
APIWRAPPER(LibPathName, OpenPrinterA)
APIWRAPPER(LibPathName, OpenPrinterW)
APIWRAPPER(LibPathName, PerfClose)
APIWRAPPER(LibPathName, PerfCollect)
APIWRAPPER(LibPathName, PerfOpen)
APIWRAPPER(LibPathName, PlayGdiScriptOnPrinterIC)
APIWRAPPER(LibPathName, PrinterMessageBoxA)
APIWRAPPER(LibPathName, PrinterMessageBoxW)
APIWRAPPER(LibPathName, PrinterProperties)
APIWRAPPER(LibPathName, QueryColorProfile)
APIWRAPPER(LibPathName, QueryRemoteFonts)
APIWRAPPER(LibPathName, QuerySpoolMode)
APIWRAPPER(LibPathName, ReadPrinter)
APIWRAPPER(LibPathName, RegisterForPrintAsyncNotifications)
APIWRAPPER(LibPathName, ReportJobProcessingProgress)
APIWRAPPER(LibPathName, ResetPrinterA)
APIWRAPPER(LibPathName, ResetPrinterW)
APIWRAPPER(LibPathName, ScheduleJob)
APIWRAPPER(LibPathName, SeekPrinter)
APIWRAPPER(LibPathName, SetDefaultPrinterA)
APIWRAPPER(LibPathName, SetDefaultPrinterW)
APIWRAPPER(LibPathName, SetFormA)
APIWRAPPER(LibPathName, SetFormW)
APIWRAPPER(LibPathName, SetJobA)
APIWRAPPER(LibPathName, SetJobW)
APIWRAPPER(LibPathName, SetPortA)
APIWRAPPER(LibPathName, SetPortW)
APIWRAPPER(LibPathName, SetPrinterA)
APIWRAPPER(LibPathName, SetPrinterDataA)
APIWRAPPER(LibPathName, SetPrinterDataExA)
APIWRAPPER(LibPathName, SetPrinterDataExW)
APIWRAPPER(LibPathName, SetPrinterDataW)
APIWRAPPER(LibPathName, SetPrinterW)
APIWRAPPER(LibPathName, SplDriverUnloadComplete)
APIWRAPPER(LibPathName, SpoolerDevQueryPrintW)
APIWRAPPER(LibPathName, SpoolerPrinterEvent)
APIWRAPPER(LibPathName, StartDocDlgA)
APIWRAPPER(LibPathName, StartDocDlgW)
APIWRAPPER(LibPathName, StartDocPrinterA)
APIWRAPPER(LibPathName, StartDocPrinterW)
APIWRAPPER(LibPathName, StartPagePrinter)
APIWRAPPER(LibPathName, SystemFunction035)
APIWRAPPER(LibPathName, UnRegisterForPrintAsyncNotifications)
APIWRAPPER(LibPathName, UploadPrinterDriverPackageA)
APIWRAPPER(LibPathName, UploadPrinterDriverPackageW)
APIWRAPPER(LibPathName, WaitForPrinterChange)
APIWRAPPER(LibPathName, WritePrinter)
APIWRAPPER(LibPathName, XcvDataW) */

// cryptsp.dll
/*APIWRAPPER(LibPathName, CryptAcquireContextA)
APIWRAPPER(LibPathName, CryptAcquireContextW)
APIWRAPPER(LibPathName, CryptContextAddRef)
APIWRAPPER(LibPathName, CryptCreateHash)
APIWRAPPER(LibPathName, CryptDecrypt)
APIWRAPPER(LibPathName, CryptDeriveKey)
APIWRAPPER(LibPathName, CryptDestroyHash)
APIWRAPPER(LibPathName, CryptDestroyKey)
APIWRAPPER(LibPathName, CryptDuplicateHash)
APIWRAPPER(LibPathName, CryptDuplicateKey)
APIWRAPPER(LibPathName, CryptEncrypt)
APIWRAPPER(LibPathName, CryptEnumProviderTypesA)
APIWRAPPER(LibPathName, CryptEnumProviderTypesW)
APIWRAPPER(LibPathName, CryptEnumProvidersA)
APIWRAPPER(LibPathName, CryptEnumProvidersW)
APIWRAPPER(LibPathName, CryptExportKey)
APIWRAPPER(LibPathName, CryptGenKey)
APIWRAPPER(LibPathName, CryptGenRandom)
APIWRAPPER(LibPathName, CryptGetDefaultProviderA)
APIWRAPPER(LibPathName, CryptGetDefaultProviderW)
APIWRAPPER(LibPathName, CryptGetHashParam)
APIWRAPPER(LibPathName, CryptGetKeyParam)
APIWRAPPER(LibPathName, CryptGetProvParam)
APIWRAPPER(LibPathName, CryptGetUserKey)
APIWRAPPER(LibPathName, CryptHashData)
APIWRAPPER(LibPathName, CryptHashSessionKey)
APIWRAPPER(LibPathName, CryptImportKey)
APIWRAPPER(LibPathName, CryptReleaseContext)
APIWRAPPER(LibPathName, CryptSetHashParam)
APIWRAPPER(LibPathName, CryptSetKeyParam)
APIWRAPPER(LibPathName, CryptSetProvParam)
APIWRAPPER(LibPathName, CryptSetProviderA)
APIWRAPPER(LibPathName, CryptSetProviderExA)
APIWRAPPER(LibPathName, CryptSetProviderExW)
APIWRAPPER(LibPathName, CryptSetProviderW)
APIWRAPPER(LibPathName, CryptSignHashA)
APIWRAPPER(LibPathName, CryptSignHashW)
APIWRAPPER(LibPathName, CryptVerifySignatureA)
APIWRAPPER(LibPathName, CryptVerifySignatureW)  */

// version.dll
/*APIWRAPPER(LibPathName, GetFileVersionInfoA)
APIWRAPPER(LibPathName, GetFileVersionInfoByHandle)
APIWRAPPER(LibPathName, GetFileVersionInfoExA)
APIWRAPPER(LibPathName, GetFileVersionInfoExW)
APIWRAPPER(LibPathName, GetFileVersionInfoSizeA)
APIWRAPPER(LibPathName, GetFileVersionInfoSizeExA)
APIWRAPPER(LibPathName, GetFileVersionInfoSizeExW)
APIWRAPPER(LibPathName, GetFileVersionInfoSizeW)
APIWRAPPER(LibPathName, GetFileVersionInfoW)
APIWRAPPER(LibPathName, VerFindFileA)
APIWRAPPER(LibPathName, VerFindFileW)
APIWRAPPER(LibPathName, VerInstallFileA)
APIWRAPPER(LibPathName, VerInstallFileW)
APIWRAPPER(LibPathName, VerLanguageNameA)
APIWRAPPER(LibPathName, VerLanguageNameW)
APIWRAPPER(LibPathName, VerQueryValueA)
APIWRAPPER(LibPathName, VerQueryValueW) */ 

}  
//====================================================================================


