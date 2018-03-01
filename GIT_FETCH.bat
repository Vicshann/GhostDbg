rem 'git_dir' EVAR may be set to specify location of '.git' folder for current console session

set remote_repo="https://github.com/Vicshann/GhostDbg.git"
ECHO remote_repo

set git_local=%~dp0.git

if not defined GITCMMNDIR goto NoBuild

for /f "delims=" %%F in ('dir "%~dp0*.sln" /b /o-n') do set sln_name=%%F
if not defined sln_name goto NoSlnFile
ECHO sln_name

SET  sln_fldr=%sln_name:~0,-4%
ECHO sln_fldr

set git_lfldr=%GITCMMNDIR%\%sln_fldr%
ECHO git_lfldr

rmdir "%git_local%"
if exist "%git_local%" goto GitExist

rmdir "%git_lfldr%"
if exist "%git_lfldr%" (
ECHO "GIT objects is still present in the directory - restoring link"
mklink /J "%git_local%" "%git_lfldr%"
goto Exit
)

mkdir "%git_lfldr%"
mklink /J "%git_local%" "%git_lfldr%"

git init
git fetch %remote_repo%
git pull %remote_repo%

ECHO "Success!"
goto Exit

:NoSlnFile
ECHO "No solution file!"
goto Exit

:GitExist
ECHO "GIT folder already exist and not empty!"
goto Exit

:NoBuild
ECHO "No git object folder EVAR!"

:Exit
pause