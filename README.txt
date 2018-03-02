
Noninvasive debugging plugin for X64Dbg

You can rename injlib.dll as version, cryptsp, winspool and place it in some application`s directory before starting it.
X64DBG->Options->Preferences->Events:TLS Callbacks must be unchecked.
Limitations: You should not set any breakpoints to a WinAPI that is used by a debugger client itself.

Have fun :)


----------------------------------
Author: Vicshann
Email: vicshann@gmail.com
