# coding: utf-8
from __future__ import unicode_literals, print_function

from cprocsp import cryptoapi, certutils
import sys

from . import case_path

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
