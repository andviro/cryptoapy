# coding: utf-8

from cprocsp import csp
from nose.tools import raises
from base64 import b64encode

enc_type = csp.X509_ASN_ENCODING | csp.PKCS_7_ASN_ENCODING
flags = 0


def _context_simple():
    context = csp.Crypt(
        None,
        csp.PROV_GOST_2001_DH,
        csp.CRYPT_VERIFYCONTEXT,
    )
    assert context
    return context


def test_context_named():
    ur''' Работает при наличии в системе контейнера 'test'.
    Необходимо его предварительно создать командой:

    csptestf -keyset -newkeyset -cont '\\.\hdimage\test'

    '''
    context = csp.Crypt(
        "test",
        csp.PROV_GOST_2001_DH,
        0,
    )
    assert context


@raises(SystemError)
def test_context_bad():
    csp.Crypt(
        "some_wrong_ctx",
        csp.PROV_GOST_2001_DH,
        0,
    )


def test_store():
    cs = csp.CertStore(None, "MY")
    assert cs


def test_store_in_context():
    context = _context_simple()
    cs = csp.CertStore(context, "MY")
    assert cs


def test_store_iter():
    ur''' Работает при наличии в системе как минимум одного сертификата.

    Тестовый сертификат создается следующим образом:

    Запрос на сертификат

        cryptcp -creatrqst -cont '\\.\hdimage\test' -provtype 75 -nokeygen -dn 'E=test@localhost.localdomain,CN=test' -both ~/req

    Затем следует получить сертификат вручную от тестового УЦ по адресу: http://www.cryptopro.ru/certsrv

    И установить сохраненный сертификат в хранилище:

        cryptcp -instcert -cont '\\.\hdimage\test' ИмяФайла.cert'''

    cs = csp.CertStore(None, "MY")
    assert len(list(cs))


def _cert_thumb():
    cs = csp.CertStore(None, "MY")
    thumbs = [cert.thumbprint() for cert in cs]
    assert thumbs
    return thumbs[0]


def _cert_name():
    cs = csp.CertStore(None, "MY")
    name = list(cert.get_name() for cert in cs)[0]
    return name


def test_cert_find_by_thumb():
    thumb = _cert_thumb()
    cs = csp.CertStore(None, "MY")
    res = list(cs.find_by_thumb(thumb))
    assert len(res)


def test_cert_find_by_name():
    name = _cert_name()
    cs = csp.CertStore(None, "MY")
    res = list(cs.find_by_name(name))
    assert len(res)
