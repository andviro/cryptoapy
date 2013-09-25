# coding: utf-8
from __future__ import unicode_literals, print_function

from cprocsp import cryptoapi, certutils, csp
import sys
from binascii import hexlify

from . import case_path, test_local, test_container, get_test_thumb, test_cn

if sys.version_info >= (3,):
        unicode = str
else:
        unicode = unicode


def test_address_oid():
    cert = open(case_path('fss.cer'), 'rb').read()
    info = cryptoapi.cert_info(cert)
    assert 'Subject' in info
    subj = dict(info['Subject'])
    assert subj['2.5.4.16'] == '107139, Орликов переулок, дом 3А'


def test_encode_address():
    testaddr = [('2.5.4.16', '107139, Орликов переулок, дом 3А')]
    att = certutils.Attributes(testaddr)
    att2 = certutils.Attributes.load(att.encode())
    assert att2.decode() == testaddr


def test_encrypt_for_certs():
    certs = [open(case_path(x), 'rb').read() for x in ('res1.cer', 'res2.cer', 'res3.cer')]
    data = open(case_path('res.bin'), 'rb').read()
    res = cryptoapi.encrypt(certs, data)
    assert res


def test_create_request():
    req = cryptoapi.create_request(test_container, {}, test_local)
    assert req is not None and len(req)


def test_get_certificate():
    cert_by_thumb = cryptoapi.get_certificate(get_test_thumb())
    cert_by_name = cryptoapi.get_certificate(name=test_cn)
    assert cert_by_thumb == cert_by_name

msg = b'Ahahahahahahahahahahahahahahaahahahahhahahahahah!!!!!!111111'


def test_signing():
    thumb = get_test_thumb()
    cert = cryptoapi.get_certificate(thumb)

    signed_data = cryptoapi.sign(thumb, msg, True)
    assert signed_data
    signed_and_encrypted = cryptoapi.sign_and_encrypt(thumb, [cert], msg)
    assert signed_and_encrypted
    return signed_data


def test_verifying():
    thumb = get_test_thumb()
    cert = cryptoapi.get_certificate(thumb)
    cs = csp.CertStore(None, b'My')
    wrong_certs = list(x.extract() for x in cs if hexlify(x.thumbprint()) != thumb)

    sig = cryptoapi.sign(thumb, msg, False)
    assert sig
    assert cryptoapi.check_signature(cert, sig, msg)
    assert not cryptoapi.check_signature(cert, sig, msg[:-1])
    assert cryptoapi.check_signature(None, sig, msg)
    assert not cryptoapi.check_signature(None, sig, msg[:-1])
    if len(wrong_certs):
        assert not any(cryptoapi.check_signature(c, sig, msg) for c in
                       wrong_certs)


def test_encrypt_decrypt():
    thumb = get_test_thumb()
    cert = cryptoapi.get_certificate(thumb)
    cs = csp.CertStore(None, b'My')
    wrong_thumbs = list(t for t in (hexlify(c.thumbprint()) for c in cs) if t != thumb)

    encrypted_data = cryptoapi.encrypt([cert], msg)
    assert encrypted_data
    decrypted_data = cryptoapi.decrypt(encrypted_data, thumb)
    assert msg == decrypted_data

    bad_thumbs = []
    for th in wrong_thumbs[:1]:
        try:
            cryptoapi.decrypt(encrypted_data, th)
        except:
            bad_thumbs.append(th)
    assert bad_thumbs == wrong_thumbs[:1]


def test_pkcs7_info():
    pkcs_msg = test_signing()
    info = cryptoapi.pkcs7_info(pkcs_msg)
    assert info
    assert info['ContentType'] == 'signedData'
    assert info['Content'] == msg


def test_cert_info():
    thumb = get_test_thumb()
    cert = cryptoapi.get_certificate(thumb)
    ci = cryptoapi.cert_info(cert)
    assert ci
    assert ci['Thumbprint'] == thumb
