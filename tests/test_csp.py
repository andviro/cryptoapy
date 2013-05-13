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
    assert cs
    certs = list(cs)
    assert len(certs)


def _cert_thumb():
    cs = csp.CertStore(None, "MY")
    thumbs = [cert.thumbprint() for cert in cs]
    assert thumbs
    return thumbs[0]


def test_cert_find_by_thumb():
    thumb = _cert_thumb()
    cs = csp.CertStore(None, "MY")
    res = list(cs.find_by_thumb(thumb))
    assert len(res)


"""
def _cert_find():
    hcert = _cert_open_system()

    CERT_FIND_SUBJECT_STR_A = (csp.CERT_COMPARE_NAME_STR_A << csp.CERT_COMPARE_SHIFT |
                               csp.CERT_INFO_SUBJECT_FLAG)

    cert_ctx = csp.CertFindCertificateInStore(
        hcert,
        enc_type,
        0,
        CERT_FIND_SUBJECT_STR_A,
        "test",
        None)
    assert cert_ctx, u"Certificate 'test' not found"
    return cert_ctx


def _cert_private_key():
    ur''' Работает при наличии в контейнере 'test' тестового сертификата.
    Запрос на сертификат создается командой:

    cryptcp -creatrqst -cont '\\.\hdimage\test' -provtype 75 -nokeygen -dn 'E=test@localhost.localdomain,CN=test' -both ~/req

    Затем следует получить сертификат вручную от тестового УЦ по адресу: http://www.cryptopro.ru/certsrv

    И установить сохраненный сертификат в хранилище:

    cryptcp -instcert -cont '\\.\hdimage\test' ИмяФайла.cert


    '''
    cert_ctx = _cert_find()
    flag, hprov, keytype, release = csp.CryptAcquireCertificatePrivateKey(
        cert_ctx, 0, None)
    assert flag, u"Couldn't get certificate private key"
    return cert_ctx, hprov, keytype


def test_sign_msg():
    cert_ctx, hprov, keytype = _cert_private_key()
    signer_info = csp.CMSG_SIGNER_ENCODE_INFO()
    assert signer_info and signer_info.cbSize, u"Couldn't construct signer_info"

    hashalg = csp.CRYPT_ALGORITHM_IDENTIFIER()
    assert hashalg
    hashalg.pszObjId = csp.szOID_CP_GOST_R3411
    hashalg.Parameters = csp.CRYPTOAPI_BLOB()
    hashalg.Parameters.cbData = 0
    hashalg.Parameters.pbData = None
    signer_info.pCertInfo = cert_ctx.pCertInfo
    signer_info.hCryptProv = hprov
    signer_info.dwKeySpec = keytype
    signer_info.HashAlgorithm = hashalg
    signer_info.pvHashAuxInfo = None

    cert_blob = csp.CRYPTOAPI_BLOB()
    cert_blob.cbData = cert_ctx.cbCertEncoded
    cert_blob.pbData = cert_ctx.pbCertEncoded

    signed_info = csp.CMSG_SIGNED_ENCODE_INFO()
    signed_info.cSigners = 1
    signed_info.rgSigners = signer_info
    signed_info.cCertEncoded = 0
    signed_info.rgCertEncoded = None
    signed_info.rgCrlEncoded = None

    n = csp.CryptMsgCalculateEncodedLength(
        enc_type,
        flags,
        csp.CMSG_SIGNED,
        signed_info,
        None,
        100)
    assert n, u"Couldn't determine encoded message size"
    """
