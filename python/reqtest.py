#!/usr/bin/env python
#-*- coding: utf-8 -*-


from cprocsp import csp
from base64 import b64encode

#ctxname = None
ctxname = 'test'
provider = "Crypto-Pro HSM CSP"
#provider = None


def main():
    global ctxname
    ctx = csp.Context(ctxname, csp.PROV_GOST_2001_DH, 0 | csp.CRYPT_SILENT,
                      provider)
    print(1)
    req = csp.CertRequest(ctx, b'CN=test')
    req.add_eku(csp.szOID_PKIX_KP_EMAIL_PROTECTION)
    print(2)
    data = req.get_data()
    print(3)
    print len(data)
    open('request.req', 'wb').write(b64encode(req.get_data()))

if __name__ == "__main__":
    main()
