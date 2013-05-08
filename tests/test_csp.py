# coding: utf-8

from cprocsp import csp

enc_type = csp.X509_ASN_ENCODING | csp.PKCS_7_ASN_ENCODING
flags = 0


def test_context_simple():
    flag, ctx = csp.CryptAcquireContext(
        None,
        None,
        csp.PROV_GOST_2001_DH,
        csp.CRYPT_VERIFYCONTEXT,
    )
    assert flag
    assert csp.CryptReleaseContext(ctx, 0)


def test_container_named():
    ur''' Работает при наличии в системе контейнера 'test'.
    Необходимо его предварительно создать командой:

    csptestf -keyset -newkeyset -cont '\\.\hdimage\test'

    '''
    flag, ctx = csp.CryptAcquireContext(
        "test",
        None,
        csp.PROV_GOST_2001_DH,
        0,
    )
    assert flag
    assert csp.CryptReleaseContext(ctx, 0)


def _cert_open_system():
    hcert = csp.CertOpenSystemStore(0, "MY")
    assert hcert, u"Could'nt open certificate store"
    return hcert


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
    flag, hprov, keytype, release = csp.CryptAcquireCertificatePrivateKey(cert_ctx, 0, None)
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
