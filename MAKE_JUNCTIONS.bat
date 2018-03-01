rem DO NOT RUN THIS FROM A NETWORK DRIVE!
rem For a new versions of VisualStudio which place their special files in ".vs" directory
rem Every solution must have an unique name
rem Do not forget to define PRJBUILDDIR and COMMONSRCDIR environment variales
rem Please do not make a copy of the Common folder. Always keep it in one place. 
rem Link each project to it and make a backup with an entire project folder to have a working copy.

if not defined PRJBUILDDIR goto NoBuild
if not defined COMMONSRCDIR goto NoCommon

for /f "delims=" %%F in ('dir "%~dp0*.sln" /b /o-n') do set sln_name=%%F
if not defined sln_name goto NoSlnFile
ECHO sln_name

SET  sln_fldr=%sln_name:~0,-4%
ECHO sln_fldr

set build_dir=%PRJBUILDDIR%\%sln_fldr%
ECHO build_dir

set vs_dir=%PRJBUILDDIR%\.vs
ECHO vs_dir

mkdir %vs_dir%
mkdir %build_dir%

mklink /J ".\.vs" "%vs_dir%"
mklink /J ".\BUILD" "%build_dir%"
mklink /J ".\COMMON" "%COMMONSRCDIR%"

if defined BACKUPSRCDIR (
mklink /J "%BACKUPSRCDIR%\%sln_fldr%" "%~dp0"
)

ECHO "Success!"
goto Exit

:NoSlnFile
ECHO "No solution file!"
goto Exit

:NoCommon
ECHO "No common folder EVAR!"
goto Exit

:NoBuild
ECHO "No build folder EVAR!"

:Exit
pause