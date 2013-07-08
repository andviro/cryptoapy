#!/usr/bin/env python
#-*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function
from cprocsp import csp, rdn
from base64 import b64encode, b64decode

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
        ctx = csp.Crypt(cont, csp.PROV_GOST_2001_DH, silent_flag, provider)
    except (ValueError, SystemError):

        if platform.system() == 'Linux' and local:
            cont = bytes(r'\\.\HDIMAGE\{0}'.format(cont))

        ctx = csp.Crypt(cont, csp.PROV_GOST_2001_DH, csp.CRYPT_NEWKEYSET |
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
    csp.Crypt(cont, csp.PROV_GOST_2001_DH, csp.CRYPT_DELETEKEYSET, provider)
    return True


def create_request(cont, descriptor, local=True):
    """Создание запроса на сертификат

    :cont: Имя контейнера
    :descriptor: параметры запроса (пока просто Subject string)
    :local: Если True, работа идет с локальным хранилищем
    :returns: строка base64, пустая строка в случае ошибки (???)

    """
    provider = "Crypto-Pro HSM CSP" if not local else None
    ctx = csp.Crypt(cont, csp.PROV_GOST_2001_DH, 0, provider)
    req = csp.CertRequest(ctx, descriptor)
    req.add_eku(csp.szOID_PKIX_KP_EMAIL_PROTECTION)
    req.set_usage(0xf0)
    return b64encode(req.get_data())


def bind_cert_to_key(cont, cert, local=True):
    """Привязка сертификата к закрытому ключу в контейнере

    :cont: Имя контейнера
    :cert: Сертификат, закодированный в строку base64
    :local: Если True, работа идет с локальным хранилищем
    :returns: отпечаток сертификата в виде строки

    """
    provider = "Crypto-Pro HSM CSP" if not local else None
    ctx = csp.Crypt(cont, csp.PROV_GOST_2001_DH, 0, provider)
    cert = ''.join(x for x in cert.splitlines() if not x.startswith('---'))
    cdata = b64decode(cert)
    newc = csp.Cert(cdata)
    newc.bind(ctx)
    cs = csp.CertStore(ctx, b"MY")
    cs.add_cert(newc)
    return b64encode(newc.thumbprint())


def get_certificate(thumb):
    """Поиск сертификатов по отпечатку

    :thumb: отпечаток, возвращенный функцией `bind_cert_to_key`
    :returns: сертификат, закодированный в base64

    """
    cs = csp.CertStore(None, b"MY")
    res = list(cs.find_by_thumb(b64decode(thumb)))
    assert len(res)
    cert = res[0]
    return b64encode(cert.extract())


def get_certificate_props(cert):
    """Пока возвращает Subject string раскодированный в словарь

    :thumb: отпечаток, возвращенный функцией `bind_cert_to_key`
    :returns: словарь

    """
    cert = ''.join(x for x in cert.splitlines() if not x.startswith('---'))
    cdata = b64decode(cert)
    newc = csp.Cert(cdata)
    return rdn.RDN(unicode(newc.name(), 'windows-1251'))


def sign(cert, data, include_data, local=True):
    """Подписывание данных сертификатом

    :cert: сертификат, закодированный в base64
    :data: бинарные данные, закодированные в base64
    :include_data: булев флаг, если True -- данные прицепляются вместе с подписью
    :local: Если True, работа идет с локальным хранилищем
    :returns: данные и/или подпись, закодированные в base64

    """
    provider = "Crypto-Pro HSM CSP" if not local else None

    #ctx = csp.Crypt(b'test_cont', csp.PROV_GOST_2001_DH, 0, provider)
    cert = ''.join(x for x in cert.splitlines() if not x.startswith('---'))
    cdata = b64decode(cert)
    signcert_thumb = csp.Cert(cdata).thumbprint()
    cs = csp.CertStore(None, b"MY")
    signcert = list(cs.find_by_thumb(signcert_thumb))[0]
    mess = csp.CryptMsg()
    #mess.add_signer_cert(signcert)
    sign_data = mess.sign_data(b64decode(data), signcert, include_data)
    return b64encode(sign_data)


def check_signature(cert, sig, data, local=True):
    """Проверка подписи под данными

    :cert: сертификат, закодированный в base64
    :data: бинарные данные, закодированные в base64
    :sig: данные подписи в base64
    :local: Если True, работа идет с локальным хранилищем
    :returns: True или False

    """
    provider = "Crypto-Pro HSM CSP" if not local else None
    ctx = csp.Crypt(None, csp.PROV_GOST_2001_DH, csp.CRYPT_VERIFYCONTEXT |
                    csp.CRYPT_SILENT, provider)
    sign = csp.Signature(b64decode(sig), ctx)
    cert = ''.join(x for x in cert.splitlines() if not x.startswith('---'))
    data = b64decode(data)
    cdata = b64decode(cert)
    cert_thumb = csp.Cert(cdata).thumbprint()
    print(1)
    cs = csp.CertStore(sign)
    print(2)
    if cert_thumb not in set(x.thumbprint() for x in cs):
        return False
    for n in range(sign.num_signers()):
        if not sign.verify_data(data, n):
            return False
    return True


def encrypt(certs, data):
    """Шифрование данных на сертификатах получателей

    :certs: список сертификатов в base64
    :data: данные в base64
    :returns: шифрованные данные в base64

    """
    bin_data = b64decode(data)
    msg = csp.CryptMsg()
    for c in certs:
        certdata = ''.join(x for x in c.splitlines() if not x.startswith('---'))
        cert = csp.Cert(b64decode(certdata))
        msg.add_recipient(cert)
    encrypted = msg.encrypt_data(bin_data)
    return b64encode(encrypted)

def decrypt(data):
    """Дешифрование данных из сообщения

    :data: данные в base64
    :returns: шифрованные данные в base64

    """
    print(1)
    ctx = csp.Crypt(b'test', csp.PROV_GOST_2001_DH, 0, None)
    print(2)
    bin_data = b64decode(data)
    print(3)
    msg = csp.CryptMsg(bin_data, ctx)
    print(4)
    decrypted = msg.decrypt()
    print(decrypted)
    print(5)
    return b64encode(decrypted)


if __name__ == '__main__':
    cont = b'123456789abcdef'
    print(gen_key(cont))
    req = create_request(cont, b'CN=123456789abcdef')
    print(req)
    open('cer_test.req', 'wb').write(req)
    thumb = bind_cert_to_key(cont, b64encode(open('cer_test.cer').read()))
    cert = get_certificate(thumb)
    print(get_certificate_props(cert))
    data = b64encode('Ahaahahahah!!!')
    wrong_data = b64encode('Ahaahahahah???')
    signdata = sign(cert, data, True)
    print(check_signature(cert, signdata, data))
    #print(check_signature(cert, signdata, wrong_data))
    msg = b64encode('Hello, dolly!')
    encmsg = encrypt([cert], msg)
    print(encmsg)
    decmsg = decrypt(encmsg)
    print(b64decode(decmsg))

    # print(remove_key(cont))
