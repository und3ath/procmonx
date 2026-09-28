@echo off
rem Configure + build + test with the Windows SDK pinned. vcvars64 defaults to
rem the newest installed SDK; 10.0.28000.0 here is a partial install (no
rem gdi32/fltlib .lib), so linking fails unless 10.0.26100.0 is selected.
setlocal
if "%PMX_SDK%"=="" set PMX_SDK=10.0.26100.0
set VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat
if not exist "%VCVARS%" (
  for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set VCVARS=%%i\VC\Auxiliary\Build\vcvars64.bat
)
call "%VCVARS%" %PMX_SDK% >nul || exit /b 1
cmake -S "%~dp0." -B "%~dp0build" -G Ninja || exit /b 1
cmake --build "%~dp0build" || exit /b 1
if /i "%1"=="test" ctest --test-dir "%~dp0build" --output-on-failure || exit /b 1
