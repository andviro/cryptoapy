#!/usr/bin/env python
#-*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import csp
from certutils import Attributes, CertValidity, KeyUsage, EKU, CertExtensions, SubjectAltName, CertificatePolicies

import platform
from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify
from filetimes import filetime_from_dec
from datetime import datetime, timedelta


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
    csp.Crypt.remove(cont, csp.PROV_GOST_2001_DH, provider)
    return True


def create_request(cont, params, local=True):
    """Создание запроса на сертификат

    :cont: Имя контейнера
    :params: Параметры запроса в виде словаря следующего вида:
        {
        'Attributes' : список пар [('OID', 'значение'), ...],
        'CertificatePolicies' : список вида [(OID, [(квалификатор, значение), ...]), ... ]
            OID - идент-р политики
            квалификатор - OID
            значение - произвольная информация в base64
        'ValidFrom' : Дата начала действия (объект `datetime`),
        'ValidTo' : Дата окончания действия (объект `datetime`),
        'EKU' : список OIDов,
        'SubjectAltName' : список вида [(тип, значение), (тип, значение), ]
            где значение в зависимости от типа:
                'directoryName' : [('OID', 'строка'), ...]
                'dNSName' : строка
                'uniformResourceIdentifier' : строка
                'iPAddress' : строка
                'registeredID' : строка
        'KeyUsage' : список строк ['digitalSignature', 'nonRepudiation', ...]
        }
    :local: Если True, работа идет с локальным хранилищем
    :returns: строка base64, пустая строка в случае ошибки (???)

    """

    provider = "Crypto-Pro HSM CSP" if not local else None
    ctx = csp.Crypt(cont, csp.PROV_GOST_2001_DH, 0, provider)
    req = csp.CertRequest(ctx, )
    req.set_subject(Attributes(params.get('Attributes', '')).encode())
    validity = CertValidity(params.get('ValidFrom', datetime.now()),
                            params.get('ValidTo',
                                       datetime.now() + timedelta(days=30)))
    eku = EKU(params.get('EKU', []))
    usage = KeyUsage(params.get('KeyUsage', []))
    altname = SubjectAltName(params.get('SubjectAltName', []))
    pols = CertificatePolicies(params.get('CertificatePolicies', []))
    ext_attr = CertExtensions([usage,
                               eku,
                               altname,
                               pols,
                               ])
    validity.add_to(req)
    ext_attr.add_to(req)
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
    return hexlify(newc.thumbprint())


def get_certificate(thumb):
    """Поиск сертификатов по отпечатку

    :thumb: отпечаток, возвращенный функцией `bind_cert_to_key`
    :returns: сертификат, закодированный в base64

    """
    cs = csp.CertStore(None, b"MY")
    res = list(cs.find_by_thumb(unhexlify(thumb)))
    assert len(res)
    cert = res[0]
    return b64encode(cert.extract())


def sign(cert, data, include_data):
    """Подписывание данных сертификатом

    :cert: сертификат, закодированный в base64
    :data: бинарные данные, закодированные в base64
    :include_data: булев флаг, если True -- данные прицепляются вместе с подписью
    :returns: данные и/или подпись, закодированные в base64

    """
    cert = ''.join(x for x in cert.splitlines() if not x.startswith('---'))
    cdata = b64decode(cert)
    signcert_thumb = csp.Cert(cdata).thumbprint()
    cs = csp.CertStore(None, b"MY")
    store_lst = list(cs.find_by_thumb(signcert_thumb))
    assert len(store_lst), 'Unable to find signing cert in system store'
    signcert = store_lst[0]
    mess = csp.CryptMsg()
    # mess.add_signer_cert(signcert)
    sign_data = mess.sign_data(b64decode(data), signcert, include_data)
    return b64encode(sign_data)


def sign_and_encrypt(signcert, certs, data):
    """Подписывание данных сертификатом

    :cert: сертификат подписывания, закодированный в base64
    :certs: список сертификатов получателей
    :data: бинарные данные, закодированные в base64
    :returns: данные и подпись, зашифрованные и закодированные в base64

    """
    cert = ''.join(x for x in signcert.splitlines() if not x.startswith('---'))
    cdata = b64decode(cert)
    signcert_thumb = csp.Cert(cdata).thumbprint()
    cs = csp.CertStore(None, b"MY")
    signcert = list(cs.find_by_thumb(signcert_thumb))[0]
    mess = csp.CryptMsg()
    for c in certs:
        certdata = ''.join(x for x in c.splitlines() if not x.startswith('---'))
        cert = csp.Cert(b64decode(certdata))
        mess.add_recipient(cert)
    sign_data = mess.sign_data(b64decode(data), signcert)
    encrypted = mess.encrypt_data(sign_data)
    return b64encode(encrypted)


def check_signature(cert, sig, data):
    """Проверка подписи под данными

    :cert: сертификат, закодированный в base64
    :data: бинарные данные, закодированные в base64
    :sig: данные подписи в base64
    :local: Если True, работа идет с локальным хранилищем
    :returns: True или False

    """
    sign = csp.Signature(b64decode(sig))
    cert = ''.join(x for x in cert.splitlines() if not x.startswith('---'))
    data = b64decode(data)
    cert = csp.Cert(b64decode(cert))
    icert = csp.CertInfo(cert)
    cissuer = icert.issuer()
    cserial = icert.serial()
    for i in range(sign.num_signers()):
        isign = csp.CertInfo(sign, i)
        if (cissuer == isign.issuer() and
                cserial == isign.serial()):
            return sign.verify_data(data, i)
    return False


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


def decrypt(data, thumb):
    """Дешифрование данных из сообщения

    :thumb: отпечаток сертификата для расшифровки
    :data: данные в base64
    :returns: шифрованные данные в base64

    """
    cs = csp.CertStore(None, b"MY")
    certs = list(cs.find_by_thumb(unhexlify(thumb)))
    assert len(certs), 'Certificate for thumbprint not found'
    decrcs = csp.CertStore()
    decrcs.add_cert(certs[0])
    bin_data = b64decode(data)
    msg = csp.CryptMsg(bin_data)
    decrypted = msg.decrypt(decrcs)
    return b64encode(decrypted)


def pkcs7_info(data):
    """Информация о сообщении в формате PKCS7

    :data: данные в base64
    :returns: словарь с информацией следующего вида:
    {
        'type' : 'тип сообщения',
        'data' : 'содержимое сообщения' # (если оно не зашифровано)
        'signers' : [(issuer1, serial1), (issuer2, serial2) ...]
        'certs' : [cert1, cert2, ...] # сертификаты в base64
    }

    """
    bin_data = b64decode(data)
    msg = csp.CryptMsg(bin_data)
    res = dict(data=msg.get_data(), type=msg.get_type(), signers=[])
    res['certs'] = list(b64encode(x.extract()) for x in csp.CertStore(msg))
    for i in range(msg.num_signers()):
        info = csp.CertInfo(msg, i)
        res['signers'].append((unicode(info.issuer(), 'cp1251', 'replace'),
                               hexlify(info.serial())))
    return res


def cert_info(cert):
    """Информация о сертификате

    :cert: сертификат в base64
    :returns: словарь с информацией следующего вида:
    {
        'Version' : версия сертификата,
        'ValidFrom' : ДатаНачала (тип datetime),
        'ValidTo' : ДатаОкончания (тип datetime),
        'Issuer': Издатель,
        'UseToSign':ИспользоватьДляПодписи,
        'UseToEncrypt' :ИспользоватьДляШифрования,
        'Thumbprint': Отпечаток,
        'SerialNumber': СерийныйНомер,
        'Subject': Субъект,
        'Extensions': [Item, Item, ...]
    }

    """
    cert = ''.join(x for x in cert.splitlines() if not x.startswith('---'))
    cert = csp.Cert(b64decode(cert))
    info = csp.CertInfo(cert)
    res = dict(
        Version=info.version(),
        ValidFrom=filetime_from_dec(info.not_before()),
        ValidTo=filetime_from_dec(info.not_after()),
        Issuer=unicode(info.issuer(), 'cp1251', 'replace'),
        Thumbprint=hexlify(cert.thumbprint()),
        UseToSign=bool(info.usage() & csp.CERT_DIGITAL_SIGNATURE_KEY_USAGE),
        UseToEncrypt=bool(info.usage() & csp.CERT_DATA_ENCIPHERMENT_KEY_USAGE),
        SerialNumber=hexlify(info.serial()),
        Subject=unicode(info.name(), 'cp1251', 'replace'),
        Extensions=list(cert.eku()),
    )
    return res