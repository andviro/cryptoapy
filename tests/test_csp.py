# coding: utf-8

from cprocsp import csp


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
    ur''' Работает при наличии в системе контейнера 'test'. Необходимо его
    предварительно создать командой:

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


def test_cert_open_system():
    hcert = csp.CertOpenSystemStore(0, "MY")
    assert hcert


def test_cert_find():
    ur''' Работает при наличии в системе контейнера 'test' и тестового сертификата в нем.
    Запрос на сертификат создается командой:

    cryptcp -creatrqst -cont '\\.\hdimage\test' -provtype 75 -nokeygen -dn 'E=test@localhost.localdomain,CN=test' -both ~/req

    Затем следует получить сертификат вручную от тестового УЦ по адресу: http://www.cryptopro.ru/certsrv

    И установить сохраненный сертификат в хранилище:

    cryptcp -instcert -cont '\\.\hdimage\test' ИмяФайла.cert


    '''
    hcert = csp.CertOpenSystemStore(0, "MY")
    assert hcert, u"Could'nt open certificate store!"
    enc_type = csp.X509_ASN_ENCODING | csp.PKCS_7_ASN_ENCODING

    CERT_FIND_SUBJECT_NAME = (csp.CERT_COMPARE_NAME << csp.CERT_COMPARE_SHIFT |
                              csp.CERT_INFO_SUBJECT_FLAG)
    cert_ctx = csp.CertFindCertificateInStore(
        hcert,
        enc_type,
        0,
        CERT_FIND_SUBJECT_NAME,
        "test",
        None)

    assert cert_ctx
