#!/usr/bin/env python
#-*- coding: utf-8 -*-

from fabric.api import run, env, local, settings, cd, put
from platform import architecture
import os
import platform

env.user = 'andrew'
env.hosts = ['report.keydisk.ru:10722']
project_dir = os.path.abspath(os.path.dirname(__file__))
remote_dir = '/home/{0}/devel/cpro-py'.format(env.user)
if platform.system() == 'Windows':
    env.key_filename = [r"c:\Documents and Settings\rodionov\.ssh\id_rsa.key"]

archive = '/tmp/cprocsp.tgz'
files = 'cprocsp tests setup.py'
remote_void_size = 8
void_size = 4 if architecture()[0] == '32bit' else 8


def swig(size=void_size):
    sources = ['cprocsp/csp.i']
    swig_opts = [
        '-python',
        '-py3',
        '-builtin',
        '-c++',
        '-Icpp/include',
        '-DSIZEOF_VOID_P={0}'.format(size),
    ]
    if platform.system() == 'Windows':
        swig_binary = "c:\dev\swigwin-2.0.10\swig.exe"
    else:
        swig_binary = 'swig'
        swig_opts.append('-DUNIX',)
    local(swig_binary + ' ' + ' '.join(swig_opts) + ' ' + ' '.join(sources))
    target = os.path.join(project_dir, 'cprocsp/csp.py')
    if (os.path.exists(target)):
        content = open(target).read()
        with open(target, 'w') as f:
            f.write('# coding: utf-8\n')
            f.write(content)


def test(pyversion=''):
    local("python{0} setup.py build_ext --inplace".format(pyversion))
    local("python{0} setup.py test".format(pyversion))


def build(pyversion=''):
    local("python{0} setup.py build".format(pyversion))


def build_rpm(pyversion=''):
    local("python{0} setup.py bdist --format=rpm".format(pyversion))

def build_wininst(pyversion=''):
    local("python{0} setup.py bdist --format=wininst".format(pyversion))

def prepare(pyversion=''):
    test(pyversion)
    swig(remote_void_size)
    local("tar -cvzf {0} {1}".format(archive, files))


def cleanup():
    local("rm -rf dist build *.egg-info")


def deploy(pyversion=''):
    prepare(pyversion)
    with settings(warn_only=True):
        if run("test -d {0}".format(remote_dir)).failed:
            run("mkdir -p {0}".format(remote_dir))
    put(archive, '/tmp/')
    with cd(remote_dir):
        run("tar -xvzf {0}".format(archive))
        run("python{ver} setup.py bdist --format=rpm".format(ver=pyversion))


def rebuild(pyversion=''):
    cleanup()
    swig()
    local("python{0} setup.py build_ext --inplace".format(pyversion))
    #test(pyversion)
