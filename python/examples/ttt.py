#!/usr/bin/env python
#-*- coding: utf-8 -*-
# from pyasn1.codec.der import decoder
# from pyasn1_modules import pem, rfc2459
import sys

sys.path.insert(0, '..')
from cprocsp import csp

# substrate = pem.readPemFromFile(open('...', 'rb'))


def tease(s):
    for n in range(10):
        cc = csp.Cert(s)
        print(list(cc.eku()))
        del cc

substrate = open('cer_test.cer', 'rb').read()
for i in range(10):
    tease(substrate)
# cert = decoder.decode(substrate, asn1Spec=rfc2459.Certificate())[0]
# print(cert.prettyPrint())
