#!/usr/bin/env python
#-*- coding: utf-8 -*-

from cprocsp import csp
from timeit import Timer
import os
from uuid import uuid4
import subprocess as sub

data = os.urandom(1024 * 10)
signname = os.path.join('/tmp', uuid4().hex)
bufname = os.path.join('/tmp', uuid4().hex)

ctx = csp.Context(
    "test",
    csp.PROV_GOST_2001_DH,
    0,
)
cs = csp.CertStore(ctx, "MY")
cert = list(cs)[0]

mess = csp.CryptMsg(ctx)
mess.add_signer_cert(cert)


def sign_with_cprocsp():
    global signname, data
    open(signname, 'wb').write(data)
    buf = open(bufname, 'wb')
    if sub.call(['/opt/cprocsp/bin/ia32/cryptcp',
                 '-dir', '/tmp', '-signf', '-nochain', '-cert',
                 '-der', signname], stderr=sub.STDOUT, stdout=buf):
        assert False
    sign = open(signname + '.sgn', 'rb').read()
    return len(sign)


def sign_with_csplib():
    global signname, data
    sig = mess.sign_data(data)
    return len(sig)


def main():
    global sign_with_csplib, sign_with_cprocsp
    csplib_tmr = Timer('sign_with_csplib()', setup="from __main__ import sign_with_csplib")
    cmdline_tmr = Timer('sign_with_cprocsp()', setup="from __main__ import sign_with_cprocsp")
    t_cmdline = min(cmdline_tmr.repeat(number=100,))
    t_csplib = min(csplib_tmr.repeat(number=100,))
    if os.path.exists(signname):
        os.unlink(signname)
        os.unlink(signname + '.sgn')
    if os.path.exists(bufname):
        os.unlink(bufname)
    print t_cmdline, t_csplib


if __name__ == "__main__":
    main()
