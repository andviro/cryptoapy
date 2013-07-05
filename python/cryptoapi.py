#!/usr/bin/env python
#-*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function
from cprocsp import csp
from uuid import uuid4
from base64 import b64encode

import platform


def gen_key(cont, local=True, silent=False):
    '''
    Создание контейнера и двух пар ключей в нем

    :cont: Имя контейнера (строка)
    :local: Если True, контейнер создается в локальном хранилище по умолчанию
    :silent: Если True, включает режим без диалоговых окон. Без аппаратного датчика случайных
        чисел в таком режиме контейнер создать невозможно!
        По умолчанию silent=False
    :returns: True, если операция успешна

    '''
    silent_flag = csp.CRYPT_SILENT if silent else 0
    provider = "Crypto-Pro HSM CSP" if not local else None

    try:
        ctx = csp.Context(cont, csp.PROV_GOST_2001_DH, silent_flag, provider)
    except (ValueError, SystemError):

        if platform.system() == 'Linux' and local:
            cont = bytes(r'\\.\HDIMAGE\{0}'.format(cont))

        ctx = csp.Context(cont, csp.PROV_GOST_2001_DH, csp.CRYPT_NEWKEYSET |
                          silent_flag, provider)

    ctx.set_password(b'')
    ctx.set_password(b'', csp.AT_KEYEXCHANGE)
    try:
        key = ctx.get_key()
    except ValueError:
        key = ctx.create_key(csp.CRYPT_EXPORTABLE, csp.AT_SIGNATURE)

    assert key, 'NULL signature key'

    try:
        ekey = ctx.get_key(csp.AT_KEYEXCHANGE)
    except ValueError:
        ekey = ctx.create_key(csp.CRYPT_EXPORTABLE, csp.AT_KEYEXCHANGE)

    assert ekey, 'NULL exchange key'
    return True


def remove_key(cont, local=True):
    '''
    Удаление контейнера

    :cont: Имя контейнера
    :local: Если True, контейнер создается в локальном хранилище по умолчанию
    :returns: True, если операция успешна

    '''
    provider = "Crypto-Pro HSM CSP" if not local else None
    csp.Context(cont, csp.PROV_GOST_2001_DH, csp.CRYPT_DELETEKEYSET, provider)
    return True


def create_request(cont, descriptor, local=True):
    """Создание запроса на сертификат

    :cont: Имя контейнера
    :descriptor: параметры запроса (пока просто Subject string)
    :local: Если True, работа идет с локальным хранилищем
    :returns: строка base64, пустая строка в случае ошибки (???)

    """
    provider = "Crypto-Pro HSM CSP" if not local else None
    ctx = csp.Context(cont, csp.PROV_GOST_2001_DH, 0, provider)
    req = csp.CertRequest(ctx, b'CN=test')
    req.add_eku(csp.szOID_PKIX_KP_EMAIL_PROTECTION)
    req.set_usage(csp.CERT_DIGITAL_SIGNATURE_KEY_USAGE
                  | csp.CERT_DATA_ENCIPHERMENT_KEY_USAGE
                  | csp.CERT_NON_REPUDIATION_KEY_USAGE)
    return b64encode(req.get_data())

if __name__ == '__main__':
    cont = b'test_cont'
    print(gen_key(cont))
    print(create_request(cont, 'CN=test'))
    #print(remove_key(cont))
