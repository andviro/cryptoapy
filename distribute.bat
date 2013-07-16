cd python
python setup.py bdist_wininst
copy dist\*.exe windistr\pkgs\
copy dist\*.exe "%HOMEPATH%\Dropbox\Public"
cd windistr
"c:\Program Files\NSIS\makensis.exe" install.nsi
copy setup.exe "%HOMEPATH%\Dropbox\Public"
