cd cpp
mingw32-make clean all
cd ..\python
fab rebuild
python setup.py bdist_wininst
