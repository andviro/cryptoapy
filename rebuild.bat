cd cpp
mingw32-make DEBUG=1 clean all
cd ..\python
fab rebuild
