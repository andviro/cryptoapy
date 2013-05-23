#!/usr/bin/env python
#-*- coding: utf-8 -*-

from fabric.api import run, env, local, settings, cd, put, lcd
from platform import architecture
import os

env.user = 'andrew'
env.hosts = ['report.keydisk.ru:10722']
project_dir = os.path.abspath(os.path.dirname(__file__))
remote_dir = '/home/{0}/devel/cpro-py'.format(env.user)
# env.key_filename = [r"c:\Documents and Settings\rodionov\.ssh\id_rsa.key"]

archive = '/tmp/cprocsp.tgz'
files = 'cprocsp tests setup.py'
remote_void_size = 8
void_size = 4 if architecture()[0] == '32bit' else 8


def swig(size):
    with lcd(project_dir):
        sources = ['cprocsp/csp.i']
        swig_binary = 'swig'
        swig_opts = [
            '-python',
            '-builtin',
            '-c++',
            '-DUNIX',
            '-DCP_IOVEC_USE_SYSTEM',
            '-DHAVE_LIMITS_H',
            '-DHAVE_STDINT_H',
            '-DSIZEOF_VOID_P={0}'.format(size),
            '-I/opt/cprocsp/include',
            '-I/opt/cprocsp/include/cpcsp',
            '-I/opt/cprocsp/include/asn1c/rtsrc',
            '-I/opt/cprocsp/include/asn1data',
        ]
        local(swig_binary + ' ' + ' '.join(swig_opts) + ' ' + ' '.join(sources))


def test():
    with lcd(project_dir):
        local("python setup.py test -v")


def prepare():
    with lcd(project_dir):
        test()
        swig(remote_void_size)
        local("tar -cvzf {0} {1}".format(archive, files))


def deploy():
    with settings(warn_only=True):
        if run("test -d {0}".format(remote_dir)).failed:
            run("mkdir -p {0}".format(remote_dir))
    put(archive, '/tmp/')
    with cd(remote_dir):
        run("tar -xvzf {0}".format(archive))
        run("python setup.py bdist --format=rpm")


def rebuild():
    with lcd(project_dir):
        swig(void_size)
        local("python setup.py build")
        test()