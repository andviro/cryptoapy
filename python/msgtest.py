#!/usr/bin/env python
#-*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function
from cprocsp import csp


# ctxname = 'test2'
ctxname = b'123456789abcdef'
# provider = "Crypto-Pro HSM CSP"
provider = None
silent = csp.CRYPT_SILENT


def main():
    global ctxname
    try:
        ctx = csp.Crypt(b'{0}'.format(ctxname), csp.PROV_GOST_2001_DH, 0 | silent, provider)
    except:
        ctx = None
    if ctx is None:
        ctx = csp.Crypt(
            b'{0}'.format(ctxname), csp.PROV_GOST_2001_DH, csp.CRYPT_NEWKEYSET | silent, provider)
    msg = csp.CryptMsg(ctx)
    cs = csp.CertStore(ctx, b"My")

    rec_c = list(cs.find_by_name(b'123456789abcdef'))[0]
    wrong_c = list(cs.find_by_name(b'test'))[0]
    print(rec_c.name())

    msg.add_recipient(rec_c)
    data = msg.encrypt_data(b'Test byte string')
    print(len(data))

    cs2 = csp.CertStore()
    cs2.add_cert(wrong_c)
    encrypted = csp.CryptMsg(data)
    return_data = encrypted.decrypt(cs2)
    print(return_data)

    signed = msg.sign_data(b'Test signed data', rec_c)
    print(len(signed))

    print(1)
    msg2 = csp.CryptMsg(signed, ctx)
    print(2)
    print(msg2.verify(0))
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
