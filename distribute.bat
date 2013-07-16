cd python
python setup.py bdist_wininst
copy dist\*.exe windistr\pkgs\
cd windistr
"c:\Program Files\NSIS\makensis.exe" install.nsi
