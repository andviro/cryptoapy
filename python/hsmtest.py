#!/usr/bin/env python
#-*- coding: utf-8 -*-


from cprocsp import csp
from base64 import b64encode

ctxname = None


ctxname = 'test2'


def main():
    global ctxname
    ctx = csp.Context(ctxname, csp.PROV_GOST_2001_DH, 0 | csp.CRYPT_SILENT, "Crypto-Pro HSM CSP")
    if ctx is None:
        print 'creating context:', ctxname
        ctx = csp.Context(
            r'\\.\hsm\{0}'.format(ctxname), csp.PROV_GOST_2001_DH,
            csp.CRYPT_NEWKEYSET | csp.CRYPT_SILENT, "Crypto-Pro HSM CSP")
        print 'created context:', ctx
    else:
        print 'container', ctx.uniq_name(), 'exists'
    key = ctx.get_key()
    if key is None:
        print 'creating signature key'
        key = ctx.create_key(csp.CRYPT_EXPORTABLE)
    ekey = ctx.get_key(csp.AT_KEYEXCHANGE)
    if ekey is None:
        print 'creating exchange key'
        ekey = ctx.create_key(csp.CRYPT_EXPORTABLE, csp.AT_KEYEXCHANGE)

    has_cert = True
    store = csp.CertStore(ctx, "MY")
    if not len(list(store.find_by_name('test3'))):
        try:
            c = csp.Cert.self_sign(ctx, b'CN=test3')
            store.add_cert(c)
            print 'Added test cert'
        except SystemError:
            print 'Self-signed certs are not supported'
            has_cert = False
    else:
        print 'cert already exists'

    if has_cert:
        cert = list(store.find_by_name('test3'))[0]
        print cert.name()
        mess = csp.CryptMsg(ctx)
        mess.add_signer_cert(cert)
        data = mess.sign_data(b'hurblewurble', True)
        print 'length of signature:', len(data)
        sgn = csp.Signature(data)
        for n in range(sgn.num_signers):
            if sgn.verify_data(b'hurblewurble', n):
                print 'sign', n, 'correct'
            else:
                print 'sign', n, 'failed!'

    req = csp.CertRequest(ctx, b'CN=test3')
    data = req.get_data()
    print len(data)
    open('request.req', 'wb').write(b64encode(req.get_data()))

if __name__ == "__main__":
    main()
