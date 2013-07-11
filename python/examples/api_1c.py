# coding: utf-8
from __future__ import unicode_literals, print_function

import sys
sys.path.insert(0, '..')
from cprocsp import cryptoapi, csp

from pyasn1_modules.rfc2459 import id_at_commonName as CN, id_at_givenName as GN
from datetime import datetime, timedelta
from base64 import b64decode, b64encode


# Генерация ключевого контейера
cont = b'123456789abcdef'
print('key generated:', cryptoapi.gen_key(cont))

# Запрос на серт
req_params = dict(Attributes=[(CN, b'123456789abcdef')],
                  KeyUsage=['dataEncipherment', 'digitalSignature'],
                  EKU=[csp.szOID_PKIX_KP_EMAIL_PROTECTION,
                       csp.szOID_PKIX_KP_CLIENT_AUTH],
                  ValidFrom=datetime.utcnow(),
                  SubjectAltName=[('directoryName', [(GN, 'Вася')])],
                  ValidTo=datetime.now() + timedelta(days=31))
req = cryptoapi.create_request(cont, req_params)
print('request data:', req)
open('cer_test.req', 'wb').write(req)
open('cer_test.der', 'wb').write(b64decode(req))

# Импорт серта из файла (требуется отправить запрос в УЦ и сохранить
# полученный серт в файл 'cer_test.cer')
certdata = open('cer_test.cer', 'rb').read()
thumb = cryptoapi.bind_cert_to_key(cont, b64encode(certdata))
print('bound cert thumb:', thumb)

# Получение данных о сертификате
cert = cryptoapi.get_certificate(thumb)
print(cryptoapi.cert_info(cert))

# Подписывание данных
data = b64encode('Ahaahahahah!!!')
wrong_data = b64encode('Ahaahahahah???')
signdata = cryptoapi.sign(cert, data, True)

# Информация о PKSC7 - сообщении
print('sign info:', cryptoapi.pkcs7_info(signdata))

# Проверка отсоединенной подписи
print('verify "{0}":'.format(data), cryptoapi.check_signature(cert, signdata, data))
print('verify "{0}":'.format(wrong_data), cryptoapi.check_signature(cert, signdata, wrong_data))

# Шифрование данных
message = 'Hello, dolly!'
msg = b64encode(message)
encmsg = cryptoapi.encrypt([cert], msg)
print('encrypted len of "{0}":'.format(message), len(encmsg))

# Расшифровка данных
decmsg = cryptoapi.decrypt(encmsg, thumb)
print('decrypted:', b64decode(decmsg))

# Комбинированное подписывание и шифрование
sencdata = cryptoapi.sign_and_encrypt(cert, [cert], data)
print('signed and encrypted len:', len(sencdata))
print('info of s_a_e:', cryptoapi.pkcs7_info(sencdata))

# Удаление контейнера
# Закомментировано, чтобы каждый раз не создавать ключи снова
# print(cryptoapi.remove_key(cont))
