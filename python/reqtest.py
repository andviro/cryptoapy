#!/usr/bin/env python
#-*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals

from cprocsp import csp
from base64 import b64encode

#ctxname = None
ctxname = b'test'
provider = b"Crypto-Pro HSM CSP"
#provider = None


def main():
    global ctxname
    ctx = csp.Context(ctxname, csp.PROV_GOST_2001_DH, 0 | csp.CRYPT_SILENT,
                      provider)
    req = csp.CertRequest(ctx, b'CN=test')
    req.add_eku(csp.szOID_PKIX_KP_EMAIL_PROTECTION)
    data = req.get_data()
    print(len(data), 'bytes generated')
    req.set_usage(0xff)
    open('request.req', 'wb').write(b64encode(req.get_data()))

if __name__ == "__main__":
    main()
