# coding: utf-8
from __future__ import unicode_literals, print_function

from pyasn1_modules.rfc2459 import id_at_commonName as CN
from cprocsp import cryptoapi, certutils, csp
import sys
from binascii import hexlify
from datetime import datetime, timedelta
import os

from . import case_path, test_local, test_container,\
    get_test_thumb, test_cn, test_provider

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
    our_cert = cryptoapi.get_certificate(name=test_cn)
    certs.append(our_cert)
    data = open(case_path('res.bin'), 'rb').read()
    res = cryptoapi.encrypt(certs, data)
    assert res


def test_create_request(provider=None):
    req_params = {
        'SubjectAltName': [('ediPartyName', '9876543210')],
        # req_params = {'SubjectAltName': [('ediPartyName', ('9876543210', 'asldkj'))],
        # req_params = {'SubjectAltName': [('directoryName',
        # [('2.5.4.6', 'R')])],
        'KeyUsage': ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment'],
        'CertificatePolicies': [('1.2.643.100.113.1', [])],
        'Attributes':
        [
            ('1.2.643.100.1', '1111111111111'),
            ('2.5.4.9', 'Лизюкова ул 3   3'),
            ('1.2.643.3.131.1.1', '000000000000'),
            ('2.5.4.6', 'R'),
            ('2.5.4.7', 'Воронеж'),
            ('2.5.4.8', '36 г. Воронеж'),
            ('2.5.4.10', 'тестБегемот'),
            ('2.5.4.3', 'тестБегемот'),
            ('2.5.4.4', 'Иванов'),
            # ('2.5.4.42', 'Иван Иванович'),
            ('2.5.4.42', 'Иван'),
            ('2.5.4.12', 'Гениальный директор'),
            ('1.2.643.100.3', '22222222222')
        ],
        'EK': ['1.3.6.1.5.5.7.3.2', '1.3.6.1.5.5.7.3.4'],
        'ValidFrom': datetime.now(),
        'ValidTo': datetime.now() + timedelta(days=365),
    }
    req = cryptoapi.create_request(test_container, req_params, test_local,
                                   provider)
    assert req is not None and len(req)


def test_request_valid_time():
    req_params = dict(Attributes=[(CN, test_cn)],
                      ValidFrom=datetime.now(),
                      ValidTo=datetime.now() + timedelta(days=30),
                      KeyUsage=['dataEncipherment', 'nonRepudiation',
                                'keyEncipherment', 'digitalSignature'],
                      EKU=[csp.szOID_PKIX_KP_EMAIL_PROTECTION,
                           csp.szOID_PKIX_KP_CLIENT_AUTH])
    request1 = cryptoapi.create_request(test_container, req_params, local=test_local)
    del req_params['ValidFrom']
    del req_params['ValidTo']
    request2 = cryptoapi.create_request(test_container, req_params, local=test_local)
    assert b"\x06\x0A\x2A\x85\x03\x02\x04\x01\x01\x01\x01\x02" in request1
    assert b"\x06\x0A\x2A\x85\x03\x02\x04\x01\x01\x01\x01\x02" not in request2


def test_force_provider():
    return test_create_request(provider=test_provider)


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
    certs = []
    for x in ('res1.cer',):
        certs.append(open(case_path(x), 'rb').read())
    certs.append(cert)
    wrong_thumbs = list(t for t in (hexlify(c.thumbprint()) for c in cs) if t != thumb)

    encrypted_data = cryptoapi.encrypt(certs, msg)
    open('encrypted_data.bin', 'wb').write(encrypted_data)
    assert encrypted_data
    decrypted_data = cryptoapi.decrypt(encrypted_data, thumb)
    assert msg == decrypted_data

    bad_thumbs = []
    for th in wrong_thumbs[:1]:
        try:
            cryptoapi.decrypt(encrypted_data, th)
        except Exception:
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


def test_cert_key_id():
    thumb = get_test_thumb()
    cert = cryptoapi.get_certificate(thumb)
    si = cryptoapi.cert_subject_id(cert)
    assert si


def test_hash_digest_empty():
    data = b''
    h = cryptoapi.Hash(data)
    digest_str = h.digest().encode('base64').rstrip()
    assert digest_str == 'mB5fPKMMhBSHgw+E+0M+E6wRAVabnBNYSsSDI0zWVsA='


def test_hash_sign_verify():
    data = os.urandom(1024)
    bad_data = os.urandom(1024)
    thumb = get_test_thumb()
    cert = cryptoapi.get_certificate(thumb)

    h = cryptoapi.SignedHash(thumb, data)
    sig = h.sign()

    good = cryptoapi.Hash(data)
    assert good.verify(cert, sig)

    bad = cryptoapi.Hash(bad_data)
    assert not bad.verify(cert, sig)


def test_hmac():
    key = b'1234'
    data = b'The quick brown fox jumps over the lazy dog'
    mac = cryptoapi.HMAC(key, data)
    assert mac.hexdigest() == '7b61bdd0c74c9eb391c640ccff001ff0ac533bcdff2e0f063e453c2eb8d7508d'


def test_pkcs7_info_from_file():
    pkcs_msg = open(case_path('msg.bin'), 'rb').read()
    info = cryptoapi.pkcs7_info(pkcs_msg)
    print(info)
    assert info
    assert info['ContentType'] == 'envelopedData'
