#!/usr/bin/env python
#-*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from cprocsp import csp
from base64 import b64encode

#ctxname = None
ctxname = b'test'
#provider = b"Crypto-Pro HSM CSP"
provider = None


def main():
    global ctxname
    ctx = csp.Context(ctxname, csp.PROV_GOST_2001_DH, 0 | csp.CRYPT_SILENT,
                      provider)
    print(1, ctx)
    if ctx is None:
        print('creating context:', ctxname)
        ctx = csp.Context(
            b'{0}'.format(ctxname), csp.PROV_GOST_2001_DH,
            csp.CRYPT_NEWKEYSET | csp.CRYPT_SILENT, provider)
        assert ctx
        print('created context:', ctx)
    req = csp.CertRequest(ctx, b'CN=test10')
    req.set_usage(0xf0)
    print(2)
    req.add_eku(csp.szOID_PKIX_KP_EMAIL_PROTECTION)
    print(3)
    data = req.get_data()
    print(4)
    print(len(data), 'bytes generated')
    print(5)
    print(6)
    open('req_my.req', 'wb').write(b64encode(req.get_data()))
    print(7)

if __name__ == "__main__":
    main()
