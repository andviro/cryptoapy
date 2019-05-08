#!/usr/bin/env python
#-*- coding: utf-8 -*-
from cprocsp import csp, PROV_GOST


#ctxname = 'test2'
ctxname = b'csp_test_keyset'
#provider = "Crypto-Pro HSM CSP"
provider = None


def main():
    global ctxname
    ctx = csp.Crypt(ctxname, csp.PROV_GOST_2012_256, 0 | csp.CRYPT_SILENT, provider)
    if not ctx:
        print('Container', ctxname, 'not found!')
        return
    print(ctx.name())
    print(ctx.prov_name())
    print(ctx.uniq_name())
    print(ctx.prov_type())
#      cdata = open('/media/sf___devel/certnew(1).cer', 'rb').read()
#      newc = csp.Cert(cdata)
#      newc.bind(ctx)
#      cs = csp.CertStore(ctx, "MY")
#      cs.add_cert(newc)
#      for c in cs:
#          print c.name()


if __name__ == "__main__":
    main()
