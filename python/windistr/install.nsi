!define PRODUCT_NAME "Python crypto suite"
!define PRODUCT_VERSION "1.0"
!define PRODUCT_PUBLISHER "Andrew Rodionoff <rodionov_a@astralnalog.ru>"
!define PRODUCT_WEB_SITE "http://www.astralnalog.ru"

; MUI 1.67 compatible ------
!include "MUI.nsh"

; MUI Settings
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "English"

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "setup.exe"
InstallDir "$PROGRAMFILES\PythonCryptoAPI"

Function .onInit
System::Call 'kernel32::CreateMutexA(i 0, i 0, t "myMutex") i .r1 ?e'
Pop $R0

StrCmp $R0 0 +3
    MessageBox MB_OK|MB_ICONEXCLAMATION "The installer is already running."
    Abort
FunctionEnd

Section "MainSection" SEC01
  SetOutPath "$INSTDIR"
  SetOverwrite ifnewer
  File /r "pkgs"
SectionEnd

Section "Python" SEC02
  ExecWait 'msiexec /package "$INSTDIR\pkgs\python-2.7.5.msi" /quiet'
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "path"
  WriteRegStr HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "path" "$0;c:\python27;c:\python27\scripts"
SectionEnd

Section "Setuptools" SEC03
  ExecWait "$INSTDIR\pkgs\setuptools-0.9.1.win32-py2.7.exe"
SectionEnd

Section "Pip" SEC04
  ExecWait "$INSTDIR\pkgs\pip-1.3.1.win32-py2.7.exe"
SectionEnd

Section "PyCrypto" SEC05
  ; this is not a "quiet" install
  ExecWait '$INSTDIR\pkgs\pycrypto-2.6.win32-py2.7.exe'
SectionEnd

Section "Fabric" SEC06
  ; this is not a "quiet" install
    ExecWait '$INSTDIR\pkgs\Fabric-1.6.1.win32.exe'
SectionEnd

Section "SQLAlchemy" SEC07
  ExecWait "$INSTDIR\pkgs\SQLAlchemy-0.8.2.win32-py2.7.exe"
SectionEnd

Section "Pyasn1" SEC08
  ; this is not a "quiet" install
  ExecWait '$INSTDIR\pkgs\pyasn1-0.1.7.win32.exe'
SectionEnd

Section "Pyasn1_modules" SEC09
  ; this is not a "quiet" install
  ExecWait '$INSTDIR\pkgs\pyasn1-modules-0.0.5.win32.exe'
SectionEnd

Section "Cprocsp" SEC10
  ; this is not a "quiet" install
  ExecWait '$INSTDIR\pkgs\python2.7-cprocsp-0.2.win32-py2.7.exe'
SectionEnd

Section "Mock" SEC11
  ; this is not a "quiet" install
  ExecWait '$INSTDIR\pkgs\mock-1.0.1.win32.exe'
SectionEnd

Section "Spyne" SEC12
  ; this is not a "quiet" install
  ExecWait '$INSTDIR\pkgs\spyne-2.10.8.win32.exe'
SectionEnd

Section "Tornado" SEC13
  ; this is not a "quiet" install
  ExecWait '$INSTDIR\pkgs\tornado-3.1.win32-py2.7.exe'
SectionEnd

Section "Nose" SEC14
  ; this is not a "quiet" install
  ExecWait '$INSTDIR\ pkgs\nose-1.3.0.win32-py2.7.exe'
SectionEnd
