#!/usr/bin/env python
#-*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function
from cprocsp import csp
from binascii import hexlify, unhexlify


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
    ci = csp.CertInfo(rec_c)
    print(ci.name(), ci.issuer(), hexlify(ci.serial()))

    msg.add_recipient(rec_c)
    data = msg.encrypt_data(b'Test byte string')
    print(len(data))

    #rec_c = list(cs.find_by_name(b'test'))[0]
    cs2 = csp.CertStore()
    cs2.add_cert(rec_c)
    encrypted = csp.CryptMsg(data)
    print('type:', encrypted.get_type())
    print('data:', encrypted.get_data())
    return_data = encrypted.decrypt(cs2)
    print(return_data)

    signed = msg.sign_data(b'Test signed data', rec_c)
    print(len(signed))

    msg2 = csp.CryptMsg(signed, ctx)
    info = csp.CertInfo(msg2, 0)
    print('version:', info.version())
    print('type:', msg2.get_type())
    print(msg2.verify(0))
    detached = msg.sign_data(b'Test signed data', rec_c, True)
    print(len(detached))
    sig = csp.Signature(detached, ctx)
    print(sig.verify_data(b'Test signed data', 0))
    print(sig.verify_data(b'Test zigned Data', 0))
    sig2 = csp.CryptMsg(open('tests/data1.p7s', 'rb').read())
    print('sig type:', sig2.get_type())
    print('sig data:', sig2.get_data())


if __name__ == "__main__":
    main()
