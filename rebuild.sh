#!/bin/sh
cd cpp
make clean all
cd ../python
fab rebuild
