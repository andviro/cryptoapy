cd python
fab swig
python setup.py bdist_wininst
REM copy dist\*.exe windistr\pkgs\
REM move dist\*.exe "%HOMEPATH%\Dropbox\Public"
REM cd windistr
REM "c:\Program Files\NSIS\makensis.exe" install.nsi
REM move setup.exe "%HOMEPATH%\Dropbox\Public"
