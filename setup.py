#!/usr/bin/env python
#-*- coding: utf-8 -*-
from setuptools import setup, Extension
from platform import architecture

try:
    import multiprocessing
except ImportError:
    pass

if architecture()[0] == '32bit':
    arch = 'ia32'
    size = '4'
else:
    arch = 'amd64'
    size = '8'

csp = Extension('cprocsp._csp',
                sources=['cprocsp/csp_wrap.cxx'],
                include_dirs=[
                    '/opt/cprocsp/include',
                    '/opt/cprocsp/include/cpcsp',
                    '/opt/cprocsp/include/asn1c/rtsrc',
                    '/opt/cprocsp/include/asn1data',
                ],
                library_dirs=['/opt/cprocsp/lib/{0}'.format(arch)],
                libraries=['pthread',
                           'asn1data',
                           'ssp',
                           'capi20'],
                extra_compile_args=[
                    '-DUNIX',
                    '-DHAVE_LIMITS_H',
                    '-DHAVE_STDINT_H',
                    '-DSIZEOF_VOID_P={0}'.format(size),
                    '-DCP_IOVEC_USE_SYSTEM',
                ],)

setup(name='cprocsp',
      version='0.1',
      ext_modules=[csp],
      packages=['cprocsp'],
      py_modules=['cprocsp.csp', 'cprocsp.rdn'],
      test_suite='nose.collector',
      setup_requires=['nose>=1.0'],
      )
