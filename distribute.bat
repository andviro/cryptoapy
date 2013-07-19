cd python
fab swig
python setup.py bdist_wininst
copy dist\*.exe windistr\pkgs\
move dist\*.exe "%HOMEPATH%\Dropbox\Public"
cd windistr
"c:\Program Files\NSIS\makensis.exe" install.nsi
move setup.exe "%HOMEPATH%\Dropbox\Public"
