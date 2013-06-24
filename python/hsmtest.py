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
    store.add_cert(c)


def test_extract_cert():
    '''
    Метод `Cert.extract()` возвращает закодированный сертификат в виде байтовой строки.
    '''
    cs = csp.CertStore(None, "MY")
    cert = list(cs)[0]
    cdata = cert.extract()
    assert len(cdata)
    return cdata


def test_cert_from_data():
    '''
    Конструктор `Cert(s)`, при передаче ему байтовой строки `s`, декодирует и
    загружает из нее новый экземпляр сертификата, не сохраненный в хранилище.
    При необходимости его можно туда добавить функцией `CertStore.add_cert()`.
    '''
    cdata = test_extract_cert()
    print '!!!', len(cdata)
    newc = csp.Cert(cdata)
    print '!!!', newc
    memstore = csp.CertStore()
    c = memstore.add_cert(newc)
    l = list(memstore.find_by_name(''))
    for z in csp.CertStore(None, "MY"):
        print z.name()
    c2 = c.duplicate()
    print "!!!", c
    print '!!!', len(list(memstore))
    for c in memstore:
        c.remove_from_store()


def main():
    my = csp.CertStore(None, "MY")
    cert = list(my)[0]

    cs = csp.CertStore()

    # метод `CertStore.add_cert(c)` добавляет сертификат `c` в хранилище.
    cs.add_cert(cert)

    assert len(list(cs))


if __name__ == "__main__":
    main()
