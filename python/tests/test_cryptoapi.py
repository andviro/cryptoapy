# coding: utf-8
from __future__ import unicode_literals, print_function

from cprocsp import cryptoapi, certutils, csp
import sys
from binascii import hexlify
from datetime import datetime

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
    req_params = {
        u'SubjectAltName': [(u'ediPartyName', '9876543210')],
        # req_params = {u'SubjectAltName': [(u'ediPartyName', ('9876543210', 'asldkj'))],
        # req_params = {u'SubjectAltName': [(u'directoryName',
        # [(u'2.5.4.6', u'RU')])],
        u'ValidTo': datetime(2014, 7, 30, 10, 19, 31),
        u'KeyUsage': ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment'],
        u'CertificatePolicies': [(u'1.2.643.100.113.1', [])],
        u'Attributes':
        [(u'1.2.643.100.1', u'1023501490880'),
         (u'2.5.4.9',
         u'\u0425\u043e\u043b\u044c\u0437\u0443\u043d\u043e\u0432\u0430 \u0443\u043b 2   2'),
         (u'1.2.643.3.131.1.1', u'009800811710'),
         (u'2.5.4.6', u'RU'),
         (u'2.5.4.7',
         u'\u0417\u0435\u043b\u0435\u043d\u043e\u0433\u0440\u0430\u0434'),
         (u'2.5.4.8',
         u'77 \u0433. \u041c\u043e\u0441\u043a\u0432\u0430'),
         (u'2.5.4.10',
         u'\u0442\u0435\u0441\u0442\u0410\u043d\u0434\u0440\u043e\u043c\u0435\u0434\u0430'),
         (u'2.5.4.3',
         u'\u0442\u0435\u0441\u0442\u0410\u043d\u0434\u0440\u043e\u043c\u0435\u0434\u0430'),
         (u'2.5.4.4',
         u'\u0410\u043a\u0438\u043c\u043e\u0432\u0430'),
         #(u'2.5.4.42', u'\u0410\u043d\u0430\u0441\u0442\u0430\u0441\u0438\u044f \u041f\u0435\u0442\u0440\u043e\u0432\u043d\u0430'),
         (u'2.5.4.42',
         u'\u0410\u043d\u0430\u0441\u0442\u0430\u0441\u0438\u044f'),
         (u'2.5.4.12',
         u'\u0413\u0435\u043d\u0435\u0440\u0430\u043b\u044c\u043d\u044b\u0439 \u0434\u0438\u0440\u0435\u043a\u0442\u043e\u0440'),
         (u'1.2.643.100.3', u'02209709525')],
        u'EKU': [u'1.3.6.1.5.5.7.3.2', u'1.3.6.1.5.5.7.3.4'],
        u'ValidFrom': datetime(2013, 7, 30, 10, 19, 31)}
    req = cryptoapi.create_request(test_container, req_params, test_local)
    assert req is not None and len(req)
    open('test_request.req', 'wb').write(req)


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
