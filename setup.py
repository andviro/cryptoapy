#!/usr/bin/env python
#-*- coding: utf-8 -*-
from setuptools import setup, Extension
try:
    import multiprocessing
except ImportError:
    pass

csp = Extension('cprocsp._csp',
                sources=['cprocsp/csp.i'],
                swig_opts=[
                    '-c++',
                    '-DUNIX',
                    '-DCP_IOVEC_USE_SYSTEM',
                    '-DHAVE_LIMITS_H',
                    '-DHAVE_STDINT_H',
                    '-DSIZEOF_VOID_P=4',
                    '-I/opt/cprocsp/include',
                    '-I/opt/cprocsp/include/cpcsp',
                    '-I/opt/cprocsp/include/asn1c/rtsrc',
                    '-I/opt/cprocsp/include/asn1data',
                ],
                include_dirs=[
                    '/opt/cprocsp/include',
                    '/opt/cprocsp/include/cpcsp',
                    '/opt/cprocsp/include/asn1c/rtsrc',
                    '/opt/cprocsp/include/asn1data',
                ],
                library_dirs=['/opt/cprocsp/lib/ia32'],
                libraries=['pthread', 'asn1data', 'ssp', 'capi10', 'capi20'],
                extra_compile_args=[
                    '-DUNIX',
                    '-DHAVE_LIMITS_H',
                    '-DHAVE_STDINT_H',
                    '-DSIZEOF_VOID_P=4',
                    '-DCP_IOVEC_USE_SYSTEM',
                ],)

setup(name='cprocsp',
      version='0.1',
      ext_modules=[csp],
      packages=['cprocsp'],
      py_modules=['cprocsp.csp'],
      test_suite='nose.collector',
      setup_requires=['nose>=1.0'],
      )
