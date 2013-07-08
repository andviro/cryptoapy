#!/usr/bin/env python
#-*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function
from cprocsp import csp


#ctxname = 'test2'
ctxname = b'test'
#provider = "Crypto-Pro HSM CSP"
provider = None


def main():
    global ctxname
    ctx = csp.Context(ctxname, csp.PROV_GOST_2001_DH, 0 | csp.CRYPT_SILENT,
                      provider)
    msg = csp.CryptMsg(ctx)
    cs = csp.CertStore(ctx, b"My")
    rec_c = list(cs.find_by_name(b'test'))[0]
    print(rec_c.name())
    msg.add_recipient_cert(rec_c)
    data = msg.encrypt_data(b'Test byte string')
    print(len(data))
    return_data = msg.decrypt_data(data)
    print(return_data)
    #msg.add_signer_cert(rec_c)
    signed = msg.sign_data(b'Test signed data', rec_c)
    print(len(signed))
    print(1)
    msg2 = csp.CryptMsg(signed, ctx)
    print(2)
    print(msg2.verify_sign(0))
    print(3)
    detached = msg.sign_data(b'Test signed data', rec_c, True)
    print(4)
    print(len(detached))
    print(5)
    sig = csp.Signature(detached, ctx)
    print(6)
    print(sig.verify_data(b'Test signed data', 0))
    print(7)
    print(sig.verify_data(b'Test zigned Data', 0))


if __name__ == "__main__":
    main()
