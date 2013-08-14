#!/usr/bin/env python
#-*- coding: utf-8 -*-
# from pyasn1.codec.der import decoder
# from pyasn1_modules import pem, rfc2459
import sys
from datetime import datetime, timedelta
from pyasn1_modules.rfc2459 import id_at_commonName as CN, id_at_givenName as GN
from base64 import b64encode

sys.path.insert(0, '..')
from cprocsp import csp, cryptoapi

cont = b'123456789abcdefj'

req_params = {u'SubjectAltName': [(u'ediPartyName', '9876543210')],
              u'ValidTo': datetime(2014, 7, 30, 10, 19, 31),
              u'KeyUsage': ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment'],
              u'CertificatePolicies': [(u'1.2.643.100.113.1', [])],
              u'Attributes': [(u'1.2.643.100.1', u'1023501490880'),
                              (u'2.5.4.9',
                               u'\u0425\u043e\u043b\u044c\u0437\u0443\u043d\u043e\u0432\u0430 \u0443\u043b 2   2'),
                              (u'1.2.643.3.131.1.1', u'009800811710'),
                              (u'2.5.4.6', u'RU'),
                              (u'2.5.4.7',
                               u'\u0417\u0435\u043b\u0435\u043d\u043e\u0433\u0440\u0430\u0434'),
                              (u'2.5.4.8', u'77 \u0433. \u041c\u043e\u0441\u043a\u0432\u0430'),
                              (u'2.5.4.10',
                               u'\u0442\u0435\u0441\u0442\u0410\u043d\u0434\u0440\u043e\u043c\u0435\u0434\u0430'),
                              (u'2.5.4.3',
                               u'\u0442\u0435\u0441\u0442\u0410\u043d\u0434\u0440\u043e\u043c\u0435\u0434\u0430'),
                              (u'2.5.4.4', u'\u0410\u043a\u0438\u043c\u043e\u0432\u0430'),
                              #(u'2.5.4.42', u'\u0410\u043d\u0430\u0441\u0442\u0430\u0441\u0438\u044f \u041f\u0435\u0442\u0440\u043e\u0432\u043d\u0430'),
                              (u'2.5.4.42',
                               u'\u0410\u043d\u0430\u0441\u0442\u0430\u0441\u0438\u044f'),
                              (u'2.5.4.12',
                               u'\u0413\u0435\u043d\u0435\u0440\u0430\u043b\u044c\u043d\u044b\u0439 \u0434\u0438\u0440\u0435\u043a\u0442\u043e\u0440'),
                              (u'1.2.643.100.3', u'02209709525')],
              u'EKU': [u'1.3.6.1.5.5.7.3.2', u'1.3.6.1.5.5.7.3.4'],
              u'ValidFrom': datetime(2013, 7, 30, 10, 19, 31)}

# substrate = pem.readPemFromFile(open('...', 'rb'))

req = cryptoapi.create_request(cont, req_params)
open('testreq.req', 'wb').write(b64encode(req))
open('testreq.bin', 'wb').write(req)
