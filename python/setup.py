#!/usr/bin/env python
#-*- coding: utf-8 -*-
from distutils.core import setup, Extension, Command
from platform import architecture
import sys
import os
import platform

try:
    import bdist_nsi
    have_nsis = True
except ImportError:
    have_nsis = False
    pass


major, minor = sys.version_info[:2]

if architecture()[0] == '32bit':
    arch = 'ia32'
    size = '4'
else:
    arch = 'amd64'
    size = '8'

try:
    import nose
except ImportError:
    nose = None


class TestCommand(Command):
    """Custom distutils command to run the test suite."""

    user_options = []

    def initialize_options(self):
        self._dir = os.getcwd()

    def finalize_options(self):
        pass

    def run(self):
        """Run the test suite with nose."""
        if not nose:
            print('W: nose package not found')
            return True
        return nose.core.run(argv=["", '-v', os.path.join(self._dir, 'tests')])

cmdclass = {'test': TestCommand}

include_dirs = ['../cpp/include']
library_dirs = ['../cpp']
libraries = []
extra_compile_args = ['-DSIZEOF_VOID_P={0}'.format(size)]

if platform.system() == 'Windows':
    include_dirs += [
        './',
        './cprocsp/',
    ]
    libraries += ['crypt32', 'pthread']
else:
    include_dirs += [
        '/opt/cprocsp/include',
        '/opt/cprocsp/include/cpcsp',
        '/opt/cprocsp/include/asn1c/rtsrc',
        '/opt/cprocsp/include/asn1data',
    ]
    library_dirs += ['/opt/cprocsp/lib/{0}'.format(arch)]
    libraries += ['asn1data',
                  'ssp',
                  'capi20']
    extra_compile_args += [
        '-DUNIX',
        '-DHAVE_LIMITS_H',
        '-DHAVE_STDINT_H',
        '-DCP_IOVEC_USE_SYSTEM',
    ]


csp = Extension('cprocsp._csp',
                sources=[
                    'cprocsp/csp_wrap.cxx',
                ],
                extra_objects=['../cpp/libcsp.a'],
                include_dirs=include_dirs,
                library_dirs=library_dirs,
                libraries=libraries,
                extra_compile_args=extra_compile_args,)


options = {}
if have_nsis:
    nsis_options = {}  # your nsis options
    options.update({
        'bdist_nsi': nsis_options,
    })

setup(name='python{major}.{minor}-cprocsp'.format(major=major, minor=minor),
      version='0.2',
      requires=['pyasn1', 'pyasn1_modules'],
      ext_modules=[csp],
      packages=['cprocsp'],
      py_modules=['cprocsp.csp', 'cprocsp.rdn', 'cprocsp.cryptoapi',
                  'cprocsp.filetimes'],
      cmdclass=cmdclass,
      options=options,
      )
