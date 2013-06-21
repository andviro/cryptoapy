#!/usr/bin/env python
#-*- coding: utf-8 -*-

from cprocsp import csp

ctxname = None


def setup():
    global ctxname
    ctxname = 'test'
    ctx = csp.Context(ctxname, csp.PROV_GOST_2001_DH, 0, "Crypto-Pro HSM CSP")
    if ctx is None:
        ctx = csp.Context(
            r'{0}'.format(ctxname), csp.PROV_GOST_2001_DH,
            csp.CRYPT_NEWKEYSET, "Crypto-Pro HSM CSP")
    store = csp.CertStore(ctx, "MY")
    for cert in store:
        print(cert.name())
        print(cert.issuer())
    c = csp.Cert.self_sign(ctx, b'CN=test')
    print c.name()
    print c.issuer()
    print c.thumbprint()
    c2 = store.add_cert(c)


if __name__ == "__main__":
    setup()
