#!/usr/bin/env python
#-*- coding: utf-8 -*-


from cprocsp import csp
from base64 import b64encode

ctxname = None


ctxname = 'test7'
#provider = "Crypto-Pro HSM CSP"
provider = "Crypto-Pro CSP"
provider = None
#silent = csp.CRYPT_SILENT
silent = 0


def main():
    global ctxname
    try:
        ctx = csp.Context(r'{0}'.format(ctxname), csp.PROV_GOST_2001_DH, 0 | silent, provider)
    except:
        ctx = None
    if ctx is None:
        print 'creating context:', ctxname
        ctx = csp.Context(
            r'{0}'.format(ctxname), csp.PROV_GOST_2001_DH, csp.CRYPT_NEWKEYSET | silent, provider)
        print 'created context:', ctx.uniq_name()
    else:
        print 'container', ctx.uniq_name(), 'exists'

    ctx.set_password(b'zhopa')
    try:
        key = ctx.get_key()
    except ValueError:
        key = None

    if key is None:
        print 'creating signature key'
        key = ctx.create_key(csp.CRYPT_EXPORTABLE, csp.AT_SIGNATURE)

    try:
        ekey = ctx.get_key(csp.AT_KEYEXCHANGE)
    except ValueError:
        ekey = None

    if ekey is None:
        print 'creating exchange key'
        ekey = ctx.create_key(csp.CRYPT_EXPORTABLE, csp.AT_KEYEXCHANGE)

    has_cert = True
    store = csp.CertStore(ctx, "MY")
    if not len(list(store.find_by_name('test4'))):
        try:
            c = csp.Cert.self_sign(ctx, b'CN=test4')
            store.add_cert(c)
            print 'Added test cert'
        except SystemError:
            print 'Self-signed certs are not supported'
            has_cert = False
    else:
        print 'cert already exists'

    if has_cert:
        cert = list(store.find_by_name('test4'))[0]
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
