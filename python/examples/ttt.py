#!/usr/bin/env python
#-*- coding: utf-8 -*-
# from pyasn1.codec.der import decoder
# from pyasn1_modules import pem, rfc2459
import sys
from datetime import datetime, timedelta
from pyasn1_modules.rfc2459 import id_at_commonName as CN, id_at_givenName as GN

sys.path.insert(0, '..')
from cprocsp import csp, cryptoapi

cont = b'123456789abcdefj'

# substrate = pem.readPemFromFile(open('...', 'rb'))
req_params = dict(Attributes=[(CN, cont), (GN, 'Вася')],
                  KeyUsage=['dataEncipherment', 'digitalSignature'],
                  EKU=[csp.szOID_PKIX_KP_EMAIL_PROTECTION,
                       csp.szOID_PKIX_KP_CLIENT_AUTH],
                  CertificatePolicies=[('1.2.643.100.113.1', []),
                                       ('1.2.643.100.113.2', [])],
                  RawExtensions=[],
                  ValidFrom=datetime.utcnow(),

                  SubjectAltName=[('directoryName',
                                   [('1.2.643.3.141.1.1', '123123456')])],
                  ValidTo=datetime.now() + timedelta(days=31))


def tease(s):
    for f in range(10):
        cs = csp.CertStore(None, "MY")
        lst = list(cs)
        print(len(lst))
        del lst
        del cs
    for n in range(10):
        cc = csp.Cert(s)
        print(list(cc.eku()))
        del cc
    for n in range(100):
        cont = b'123456789abcdefj'
        ctx = csp.Crypt(cont, 75, 0)
        del ctx
        req = cryptoapi.create_request(cont, req_params)
        del req
        del cont


substrate = open('cer_test.cer', 'rb').read()
for i in range(10):
    tease(substrate)
# cert = decoder.decode(substrate, asn1Spec=rfc2459.Certificate())[0]
# print(cert.prettyPrint())
