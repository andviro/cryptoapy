# coding: utf-8
from __future__ import unicode_literals, print_function

import sys
sys.path.insert(0, '..')
from cprocsp import cryptoapi, csp

from pyasn1_modules.rfc2459 import id_at_commonName as CN, id_at_givenName as GN
from datetime import datetime, timedelta
from base64 import b64encode


# Генерация ключевого контейера
cont = b'123456789abcdef'
print('key generated:', cryptoapi.gen_key(cont))

# Запрос на серт
req_params = dict(Attributes=[(CN, '123456789abcdef'), (GN, 'Вася')],
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
req = cryptoapi.create_request(cont, req_params)
print('request data:', b64encode(req))
open('cer_test.req', 'wb').write(b64encode(req))
open('cer_test.der', 'wb').write(req)

# Импорт серта из файла (требуется отправить запрос в УЦ и сохранить
# полученный серт в файл 'cer_test.cer')
certdata = open('cer_test.cer', 'rb').read()
print(cryptoapi.cert_info(certdata))
thumb = cryptoapi.bind_cert_to_key(cont, certdata)
print('bound cert thumb:', thumb)

# Получение данных о сертификате
cert = cryptoapi.get_certificate(thumb)
print(cryptoapi.cert_info(cert))
cert2 = open('cer_test.cer', 'rb').read()
print(cryptoapi.cert_info(cert2))


# Подписывание данных
data = b'Ahaahahahah!!!'
wrong_data = b'Ahaahahahah???'
signdata = cryptoapi.sign(thumb, data, False)
open('detached.p7s', 'wb').write(signdata)
signmsg = cryptoapi.sign(thumb, data, True)
open('signedmsg.p7s', 'wb').write(signmsg)

# Информация о PKSC7 - сообщении
print('sign info:', cryptoapi.pkcs7_info(signdata))
print('msg info:', cryptoapi.pkcs7_info(signmsg))

# Проверка отсоединенной подписи
print('verify "{0}":'.format(data), cryptoapi.check_signature(cert, signdata, data))
print('verify "{0}":'.format(wrong_data), cryptoapi.check_signature(cert, signdata, wrong_data))

# Шифрование данных
message = b'Hello, dolly!'
msg = message
encmsg = cryptoapi.encrypt([cert], msg)
open('encrypted.p7s', 'wb').write(encmsg)
print('encrypted len of "{0}":'.format(message), len(encmsg))

# Расшифровка данных
decmsg = cryptoapi.decrypt(encmsg, thumb)
print('decrypted:', decmsg)

# Комбинированное подписывание и шифрование
sencdata = cryptoapi.sign_and_encrypt(thumb, [cert], data)
print('signed and encrypted len:', len(sencdata))
print('info of s_a_e:', cryptoapi.pkcs7_info(sencdata))

# Удаление контейнера
# Закомментировано, чтобы каждый раз не создавать ключи снова
#print(cryptoapi.remove_key(cont))
