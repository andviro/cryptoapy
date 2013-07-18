!define PRODUCT_NAME "CryptoService"
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
  File /r "service"
  File /r "mingw"

  SetOutPath "$INSTDIR\service"
  createShortCut "$SMPROGRAMS\Run CryptoService.lnk" "$INSTDIR\service\server.py"
  SetOutPath "$INSTDIR"

  writeUninstaller $INSTDIR\uninstall.exe

  SetRebootFlag true
SectionEnd

# uninstaller section start
section "uninstall"
 
    # first, delete the uninstaller
    delete "$INSTDIR\uninstall.exe"
 
    # second, remove the link from the start menu
    delete "$SMPROGRAMS\Run CryptoService.lnk"

# uninstaller section end
sectionEnd


Section "Python" SEC02
  ExecWait 'msiexec /package "$INSTDIR\pkgs\python-2.7.5.msi" /passive ALLUSERS=1'
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "path"
  WriteRegStr HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "path" "$0;$INSTDIR\mingw;c:\Python27;c:\Python27\scripts"
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

Section "Paramiko" SEC06
  ; this is not a "quiet" install
  ExecWait '$INSTDIR\pkgs\paramiko-1.10.1.win32.exe'
SectionEnd

Section "Fabric" SEC07
  ; this is not a "quiet" install
    ExecWait '$INSTDIR\pkgs\Fabric-1.6.1.win32.exe'
SectionEnd

Section "SQLAlchemy" SEC08
  ExecWait "$INSTDIR\pkgs\SQLAlchemy-0.8.2.win32-py2.7.exe"
SectionEnd

Section "Psycopg" SEC09
  ExecWait "$INSTDIR\pkgs\psycopg2-2.5.1.win32-py2.7-pg9.2.4-release.exe"
SectionEnd

Section "Pyasn1" SEC10
  ; this is not a "quiet" install
  ExecWait '$INSTDIR\pkgs\pyasn1-0.1.7.win32.exe'
SectionEnd

Section "Pyasn1_modules" SEC11
  ; this is not a "quiet" install
  ExecWait '$INSTDIR\pkgs\pyasn1-modules-0.0.5.win32.exe'
SectionEnd

Section "Cprocsp" SEC12
  ; this is not a "quiet" install
  ExecWait '$INSTDIR\pkgs\python2.7-cprocsp-0.2.win32-py2.7.exe'
SectionEnd

Section "Mock" SEC13
  ; this is not a "quiet" install
  ExecWait '$INSTDIR\pkgs\mock-1.0.1.win32.exe'
SectionEnd

Section "Spyne" SEC14
  ; this is not a "quiet" install
  ExecWait '$INSTDIR\pkgs\spyne-2.10.8.win32.exe'
SectionEnd

Section "Tornado" SEC15
  ; this is not a "quiet" install
  ExecWait '$INSTDIR\pkgs\tornado-3.1.win32-py2.7.exe'
SectionEnd

Section "Nose" SEC16
  ; this is not a "quiet" install
  ExecWait '$INSTDIR\pkgs\nose-1.3.0.win32-py2.7.exe'
SectionEnd

Section "Decorator" SEC17
  ; this is not a "quiet" install
  ExecWait '$INSTDIR\pkgs\decorator-3.4.0.win32.exe'
SectionEnd

Section "Lxml" SEC18
  ; this is not a "quiet" install
  ExecWait '$INSTDIR\pkgs\lxml-3.2.1.win32-py2.7.exe'
SectionEnd

Section "Lxml" SEC19
  ; this is not a "quiet" install
  ExecWait '$INSTDIR\pkgs\pytz-2013b.win32-py2.7.exe'
SectionEnd

Section "VCredist" SEC20
  ; this is not a "quiet" install
  ExecWait '$INSTDIR\pkgs\vcredist_x86.exe'
SectionEnd
