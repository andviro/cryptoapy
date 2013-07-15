cd cpp
mingw32-make ARCH=ia32 clean all
cd ..\python
fab rebuild
python setup.py bdist_wininst
