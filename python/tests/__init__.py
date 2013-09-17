#!/usr/bin/env python
#-*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function
import os
from base64 import b64encode

from pyasn1_modules.rfc2459 import id_at_commonName as CN
from cprocsp import csp, cryptoapi

test_local = True
test_provider = b"Crypto-Pro HSM CSP" if not test_local else None
test_container = b'csp_test_keyset_hsm' if not test_local else b'csp_test_keyset'
test_cn = b'CSP Test certificate' if test_local else b'HSM CSP Test certificate'
test_cer_fn = 'test_cer.cer'
test_req_fn = 'test_req.req'
test_thumb = None


def case_path(pth):
    basepath = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(basepath, pth)


def setup_package():
    '''
    Создание тестового ключевого контейнера и сертификата.
    '''
    global test_thumb
    assert cryptoapi.gen_key(test_container, local=test_local)
    cs = csp.CertStore(None, b"MY")
    certs = list(cs.find_by_name(test_cn))
    if not certs:
        if not os.path.isfile(test_cer_fn):
            req_params = dict(Attributes=[(CN, test_cn)],
                              KeyUsage=['dataEncipherment', 'nonRepudiation',
                                        'keyEncipherment', 'digitalSignature'],
                              EKU=[csp.szOID_PKIX_KP_EMAIL_PROTECTION,
                                   csp.szOID_PKIX_KP_CLIENT_AUTH],
                              # CertificatePolicies=[('1.2.643.100.113.1', []),
                              #('1.2.643.100.113.2', [])],
                              )
            request = cryptoapi.create_request(test_container, req_params,
                                               local=test_local)
            open(test_req_fn, 'wb').write(b64encode(request))
            print('''
Creating certificate request in file '{req}'. Submit request to
CA and save certificate in file '{cer}'. Then re-run tests.
            '''.format(req=test_req_fn, cer=test_cer_fn))
            assert False
        else:
            cert = open(test_cer_fn, 'rb').read()
            test_thumb = cryptoapi.bind_cert_to_key(test_container, cert,
                                                    local=test_local)


def teardown_package():
    '''
    Прибиение временных файлов.
    '''
    pass
