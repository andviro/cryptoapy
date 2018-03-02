# coding: utf-8
from __future__ import unicode_literals, print_function

from pyasn1_modules.rfc2459 import id_at_commonName as CN
from cprocsp import cryptoapi, certutils, csp
import sys
from binascii import hexlify
from base64 import b64decode
from datetime import datetime, timedelta
import os

from . import case_path, test_local, test_container,\
    get_test_thumb, test_cn, test_provider

if sys.version_info >= (3,):
    unicode = str
else:
    unicode = unicode

TEST_ALL = os.environ.get('TEST_ALL', None)


def test_autopem():
    pem = b'''-----BEGIN CERTIFICATE-----
MIIBfDCCATagAwIBAgIJAK94OSlzVBsWMA0GCSqGSIb3DQEBBQUAMBYxFDASBgNV
BAMTC3BlbS5pbnZhbGlkMB4XDTEzMDcxNzE0NDAyMFoXDTIzMDcxNTE0NDAyMFow
FjEUMBIGA1UEAxMLcGVtLmludmFsaWQwTDANBgkqhkiG9w0BAQEFAAM7ADA4AjEA
vtIM2QADJDHcqxZugx7MULbenrNUFrmoMDfEaedYveWY3wBxOw642L4nFWxN/fwL
AgMBAAGjdzB1MB0GA1UdDgQWBBQ4O0ZSUfTA6C+Y+QZ3MpeMhysxYjBGBgNVHSME
PzA9gBQ4O0ZSUfTA6C+Y+QZ3MpeMhysxYqEapBgwFjEUMBIGA1UEAxMLcGVtLmlu
dmFsaWSCCQCveDkpc1QbFjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAAzEA
XwKIF+Kf4OhcqbdQp253HG2KBt/WZwvNLo/bBlkrGYwfacbGuWT8nKJG70ujdKKf
-----END CERTIFICATE-----'''

    cert = certutils.autopem(pem)
    assert len(cert) == 384


def test_address_oid():
    cert = open(case_path('fss.cer'), 'rb').read()
    info = cryptoapi.cert_info(cert)
    assert 'Subject' in info
    subj = dict(info['Subject'])
    print(repr(subj['2.5.4.16']), type(subj['2.5.4.16']))
    assert subj['2.5.4.16'] == u'107139, Орликов переулок, дом 3А'


def test_bmp_strings_in_cert():
    cert = open(case_path('fns.cer'), 'rb').read()
    info = cryptoapi.cert_info(cert)
    print(repr(info['Subject']))
    assert info['Subject'] == [
        ('1.2.643.100.1', '1047797083861'),
        ('1.2.643.3.131.1.1', '007733535730'),
        ('1.2.840.113549.1.9.1', 'mi51@m9965.nalog.ru'),
        ('2.5.4.6', 'RU'),
        ('2.5.4.8', 'Москва'),
        ('2.5.4.7', 'Москва'),
        ('2.5.4.10', 'МИ ФНС России по ЦОД'),
        ('2.5.4.3', 'МИ ФНС России по ЦОД'),
        ('2.5.4.9', 'Походный проезд домовладение 3')
    ]


def test_encode_attributes():
    testattrs = [
        ('1.2.643.100.1', '1111111111111'),
        ('2.5.4.9', 'Лизюкова ул 3   3'),
        ('2.5.4.16', '000000, Не дом и не улица'),
        ('1.2.643.3.131.1.1', '000000000000'),
        ('2.5.4.6', 'R'),
        ('2.5.4.7', 'Воронеж'),
        ('2.5.4.8', '36 г. Воронеж'),
        ('2.5.4.10', 'тестБегемот'),
        ('2.5.4.3', 'тестБегемот'),
        ('2.5.4.4', 'Иванов'),
        ('2.5.4.42', 'Иван'),
        ('2.5.4.12', 'Гениальный директор'),
        ('1.2.643.100.3', '22222222222')
    ]

    att = certutils.Attributes(testattrs).encode()
    open('testattrs.der', 'wb').write(att)
    print(hexlify(att))
    assert att == b64decode(
        '''MIIBiDEYMBYGBSqFA2QBEg0xMTExMTExMTExMTExMSQwIgYDVQQJDBvQm9C40LfRjtC60L7QstCw
           INGD0LsgMyAgIDMxMTAvBgNVBBAwKAwmMDAwMDAwLCDQndC1INC00L7QvCDQuCDQvdC1INGD0LvQ
           uNGG0LAxGjAYBggqhQMDgQMBARIMMDAwMDAwMDAwMDAwMQowCAYDVQQGEwFSMRcwFQYDVQQHDA7Q
           ktC+0YDQvtC90LXQtjEeMBwGA1UECAwVMzYg0LMuINCS0L7RgNC+0L3QtdC2MR8wHQYDVQQKDBbR
           gtC10YHRgtCR0LXQs9C10LzQvtGCMR8wHQYDVQQDDBbRgtC10YHRgtCR0LXQs9C10LzQvtGCMRUw
           EwYDVQQEDAzQmNCy0LDQvdC+0LIxETAPBgNVBCoMCNCY0LLQsNC9MS4wLAYDVQQMDCXQk9C10L3Q
           uNCw0LvRjNC90YvQuSDQtNC40YDQtdC60YLQvtGAMRYwFAYFKoUDZAMSCzIyMjIyMjIyMjIy''')
    att2 = certutils.Attributes.load(att)
    print(att2.decode())
    assert att2.decode() == testattrs


def test_encrypt_for_certs():
    certs = [open(case_path(x), 'rb').read()
             for x in ('res1.cer', 'res2.cer', 'res3.cer')]
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
    request1 = cryptoapi.create_request(
        test_container, req_params, local=test_local)
    del req_params['ValidFrom']
    del req_params['ValidTo']
    request2 = cryptoapi.create_request(
        test_container, req_params, local=test_local)
    assert b"\x06\x0A\x2A\x85\x03\x02\x04\x01\x01\x01\x01\x02" in request1
    assert b"\x06\x0A\x2A\x85\x03\x02\x04\x01\x01\x01\x01\x02" not in request2


def test_request_fields_encoding():
    req_params = dict(Attributes=[(CN, test_cn), ('1.2.643.100.5', '111111111111111')],
                      ValidFrom=datetime.now(),
                      ValidTo=datetime.now() + timedelta(days=30),
                      KeyUsage=['dataEncipherment', 'nonRepudiation',
                                'keyEncipherment', 'digitalSignature'],
                      EKU=[csp.szOID_PKIX_KP_EMAIL_PROTECTION,
                           csp.szOID_PKIX_KP_CLIENT_AUTH])
    request = cryptoapi.create_request(
        test_container, req_params, local=test_local)
    assert b"\x30\x18\x06\x05\x2A\x85\x03\x64\x05\x12\x0F\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31\x31" in request


def test_force_provider():
    return test_create_request(provider=test_provider)


def test_get_certificate():
    cert_by_thumb = cryptoapi.get_certificate(get_test_thumb())
    cert_by_name = cryptoapi.get_certificate(name=test_cn)
    assert cert_by_thumb == cert_by_name


def test_get_certificate_cont_provider():
    cert_by_thumb = cryptoapi.get_certificate(
        get_test_thumb(), cont=test_container, provider=test_provider)
    cert_by_name = cryptoapi.get_certificate(
        name=test_cn, cont=test_container, provider=test_provider)
    assert cert_by_thumb == cert_by_name


def test_bind_to_container():
    cert = cryptoapi.get_certificate(get_test_thumb())
    assert cert
    assert cryptoapi.bind_cert_to_key(test_container, cert, local=test_local, store=True)
    c = cryptoapi.get_certificate(cont=test_container)
    assert c == cert


msg = b'Ahahahahahahahahahahahahahahaahahahahhahahahahah!!!!!!111111'


def test_signing():
    thumb = get_test_thumb()
    cert = cryptoapi.get_certificate(thumb)

    signed_data = cryptoapi.sign(thumb, msg, True)
    assert signed_data
    signed_and_encrypted = cryptoapi.sign_and_encrypt(thumb, [cert], msg)
    assert signed_and_encrypted
    return signed_data


def test_signing_cont_provider():
    thumb = get_test_thumb()
    cert = cryptoapi.get_certificate(thumb, cont=test_container,
                                     provider=test_provider)

    signed_data = cryptoapi.sign(thumb, msg, True, cont=test_container,
                                 provider=test_provider)
    assert signed_data

    signed_and_encrypted = cryptoapi.sign_and_encrypt(
        thumb, [cert], msg, cont=test_container, provider=test_provider)
    assert signed_and_encrypted
    return signed_data


def _test_verifying():
    thumb = get_test_thumb()
    cert = cryptoapi.get_certificate(thumb)
    cs = csp.CertStore(None, b'My')
    wrong_certs = list(x.extract()
                       for x in cs if hexlify(x.thumbprint()) != thumb)

    sig = cryptoapi.sign(thumb, msg, False)
    assert sig
    assert cryptoapi.check_signature(cert, sig, msg)
    assert not cryptoapi.check_signature(cert, sig, msg[:-1])
    assert cryptoapi.check_signature(None, sig, msg)
    assert not cryptoapi.check_signature(None, sig, msg[:-1])
    if len(wrong_certs):
        assert not any(cryptoapi.check_signature(c, sig, msg) for c in
                       wrong_certs)
    return sig


def test_check_signature():
    sig = _test_verifying()
    assert cryptoapi.check_signature(
        None, sig, msg, cont=test_container, provider=test_provider)
    assert not cryptoapi.check_signature(
        None, sig, msg[:-1], cont=test_container, provider=test_provider)


def test_encrypt_decrypt():
    thumb = get_test_thumb()
    cert = cryptoapi.get_certificate(thumb)
    cs = csp.CertStore(None, b'My')
    certs = []
    for x in ('res1.cer',):
        certs.append(open(case_path(x), 'rb').read())
    certs.append(cert)
    wrong_thumbs = list(t for t in (hexlify(c.thumbprint())
                                    for c in cs) if t != thumb)

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


def test_encrypt_decrypt_cont_provider():
    cert = cryptoapi.get_certificate(None, cont=test_container,
                                     provider=test_provider)
    certs = [cert]
    encrypted_data = cryptoapi.encrypt(certs, msg)
    assert encrypted_data

    decrypted_data = cryptoapi.decrypt(
        encrypted_data, None, cont=test_container, provider=test_provider)
    assert msg == decrypted_data


def test_get_key():
    key = cryptoapi.get_key(cont=test_container, provider=test_provider)
    assert len(key) == 66, 'Invalid public key blob size'


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
    assert ci.get('PublicKeyAlgorithm')
    assert ci.get('SignatureAlgorithm')


def test_cert_key_id():
    thumb = get_test_thumb()
    cert = cryptoapi.get_certificate(thumb)
    si = cryptoapi.cert_subject_id(cert)
    assert si


def test_hash_digest_empty():
    data = b''
    length = 0 if test_cn.endswith('2012') else 2001
    h = cryptoapi.Hash(data, length=length)
    digest_str = hexlify(h.digest())
    print(digest_str)
    if length == 2001:
        assert digest_str == b'981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0'
        return
    assert digest_str == b'3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb'


def test_hash_sign_verify():
    data = os.urandom(1024)
    bad_data = os.urandom(1024)
    thumb = get_test_thumb()
    cert = cryptoapi.get_certificate(thumb)
    length = 0 if test_cn.endswith('2012') else 2001

    h = cryptoapi.SignedHash(thumb, data)
    sig = h.sign()

    good = cryptoapi.Hash(data, length=length)
    assert good.verify(cert, sig)

    bad = cryptoapi.Hash(bad_data, length=length)
    assert not bad.verify(cert, sig)


def test_hash_sign_verify_cont_provider():
    data = os.urandom(1024)
    bad_data = os.urandom(1024)
    length = 0 if test_cn.endswith('2012') else 2001

    h = cryptoapi.SignedHash(None, data, cont=test_container,
                             provider=test_provider)
    sig = h.sign()

    cert = cryptoapi.get_certificate(None, cont=test_container,
                                     provider=test_provider)
    assert cert
    good = cryptoapi.Hash(data, length=length)
    assert good.verify(cert, sig)
    bad = cryptoapi.Hash(bad_data, length=length)
    assert not bad.verify(cert, sig)


def test_hmac():
    key = b'1234'
    data = b'The quick brown fox jumps over the lazy dog'
    mac = cryptoapi.HMAC(key, data)
    print(mac.hexdigest())
    assert mac.hexdigest() == b'3e7dea7f2384b6c5a3d0e24aaa29c05e89ddd762145030ec22c71a6db8b2c1f4'


def test_pkcs7_info_from_file():
    pkcs_msg = open(case_path('msg.bin'), 'rb').read()
    info = cryptoapi.pkcs7_info(pkcs_msg)
    print(info)
    assert info
    assert info['ContentType'] == 'envelopedData'


def test_gen_remove_key():
    if TEST_ALL is None:
        return
    assert cryptoapi.gen_key('test_container_temp'), 'Could not generate key'
    key_exists = True
    assert cryptoapi.remove_key('test_container_temp'), 'Could not remove key'
    try:
        key = cryptoapi.get_key('test_container_temp')
        assert not key
    except (SystemError, ValueError):
        key_exists = False
    assert not key_exists
