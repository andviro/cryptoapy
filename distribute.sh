cd python
fab swig
python setup.py bdist_rpm
mv dist/*.rpm ..
