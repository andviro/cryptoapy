# coding: utf-8
from __future__ import unicode_literals, print_function

import sys
sys.path.insert(0, '..')
from cprocsp import cryptoapi, csp

from pyasn1_modules.rfc2459 import id_at_commonName as CN, id_at_givenName as GN
from datetime import datetime, timedelta
from base64 import b64encode, b64decode


# Генерация ключевого контейера
cont = b'123456789abcdefj'
print('key generated:', cryptoapi.gen_key(cont))

# Запрос на серт
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
cert = b64decode('''
MIIFgzCCA2ugAwIBAgIJANaJNbHYaE1HMA0GCSqGSIb3DQEBBQUAMFgxCzAJBgNV
BAYTAlJVMQ8wDQYDVQQIDAZNb3Njb3cxDzANBgNVBAcMBk1vc2NvdzEPMA0GA1UE
CgwGTXlEZWFsMRYwFAYDVQQDDA1Nb3Njb3cgTXlEZWFsMB4XDTEzMDcxNjA3MTIx
M1oXDTE0MDcxNjA3MTIxM1owWDELMAkGA1UEBhMCUlUxDzANBgNVBAgMBk1vc2Nv
dzEPMA0GA1UEBwwGTW9zY293MQ8wDQYDVQQKDAZNeURlYWwxFjAUBgNVBAMMDU1v
c2NvdyBNeURlYWwwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDEqx3b
pbaAv5Uju7RlDJUwATH3ENmD5mh7rK/WCOdC42lM5Of95N9w9vmn8475NM2iIlu/
l+ZNJFNF2StNyhsY25b0k3T4RRgI3Q84fNCu7RVKTsjAQIAlsz7MjSMd8wcWbDjt
4oUIt4yosNkSy9QGqkZUuhGVlwznbS2uumRqNKsw7TmAEnkleQmOJ2/hE/O2EDw9
+ESyStFhP5EesT1T+phqn4j6WPkZX1enU5Fc5fkkPJ1Vo+aeTEoUuTdTnPJ2ubp3
4W4x7X+dDbqX4QHEQoOpREDR3SwXJif7+morqr/a4syNJp6R/EjaQOvdsxQE/WgA
IHQvO7ycq+bS1usjHXZY4UeTvcaSmEEawiwda5suyZf+Ruzz8EWBWLOd3fAah2r0
gmIRg5Iphi/O8u6KCmW8cuM0PYQm/JYPxPVSeZ7/OyZgeq3JVKNrRgINv+gEokzQ
PxvL8fPl1Yn4KV0sWch8Fus5sVfiCjtpQGiIjq6YaIgvnLgBt/NsNo0/7nIbkw3e
vwIgkmZnxORoHxDAuNsCKkje5lm3ZKtg9dLgV16a3z93t/po5VEZ2vMgCMrxR39I
Hvn/Os/qSbFrOWRdZ6N8yvZ/VFh66Kk672W6pZN6HzWoGYxKfHrz9RfRw0LQi9EL
Wwk8csf8qVB0r8OSdrD42C86uhUgQA4vLX12kwIDAQABo1AwTjAdBgNVHQ4EFgQU
APnowangqlt0QemUHV/hwHMqaUYwHwYDVR0jBBgwFoAUAPnowangqlt0QemUHV/h
wHMqaUYwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAgEAnZnRDY536FZy
33+SYF901+AC0NGbdQO+xvOQbjpE1GDFAzd7vMJRspqeP9hRo6XY/kvr1HV/1S6c
479GlJ6Mg9J70lrYffFnGaPPIS5XwkajDcblBlIu+maCGhs7Sa0t1rxr49y8KhgI
XCKZ0fzlK+ugbu5Y5yFn38BclLuFVj43b/vuwL+b186wGW58ElUf/ZHJbpgJxCwv
N2FnXO7v+gnP10ntibniL7Cp4ReKE0oFTqWROmLzx02pxgx5PLoqtmxvlm8BWldp
+S/9lhDKkyokP6zChDsGJcKCr7sQO+56hoCGAtbnxJMjP+eFc0tNpnb+XaV74IZS
Cgat5T/cbWXR7I6/PEH24V50BLMaKdkWpBFUqcp6SuDdAldaalsatE6bh4++B+/n
5byRPXdMlfil3yCuTMv+X6Q1rl/k2UgJLnOVmAtCPEoCZH8WygrmwOL9+vc1dIln
W2efdeK7NBJvvURGGcuX6e8qHMkO2dHat8IiNu/Lnn5qdjMhM7j7LF7+AMepuAtv
wQkEwiwDdwuF7Z3OcMrKPuBN5ZomzX/JfqndPsQgQoSrkExZIuJnb7m8CmSSVYTI
IARll6ANjFyQA3XeQFL2QU95atxEcUyNeXtYqU7tNzTcxv7359/brWiT6zEeFSgf
hq9rCdBSh2PAJEWSOuaxY4u+FpBck1Y=
''')
print('Пашин серт:', cryptoapi.cert_info(cert))

cert = b64decode('''
MIICcTCCAdoCCQDaOkZmhEPhDDANBgkqhkiG9w0BAQUFADB9MQswCQYDVQQGEwJS
VTEPMA0GA1UECAwGS2FsdWdhMQ8wDQYDVQQHDAZLYWx1Z2ExDzANBgNVBAoMBkFz
dHJhbDEaMBgGA1UEAwwRcmVwb3J0LmtleWRpc2sucnUxHzAdBgkqhkiG9w0BCQEW
EG5hbG9nQGthbHVnYS5uZXQwHhcNMTIwODA5MjAzNDA0WhcNMTMwODA5MjAzNDA0
WjB9MQswCQYDVQQGEwJSVTEPMA0GA1UECAwGS2FsdWdhMQ8wDQYDVQQHDAZLYWx1
Z2ExDzANBgNVBAoMBkFzdHJhbDEaMBgGA1UEAwwRcmVwb3J0LmtleWRpc2sucnUx
HzAdBgkqhkiG9w0BCQEWEG5hbG9nQGthbHVnYS5uZXQwgZ8wDQYJKoZIhvcNAQEB
BQADgY0AMIGJAoGBALI9HTuwEzzMfYJcWEpUaNOvZbXrIMTnCgIPuA86s5NPmtgw
MxeZ75v9gX4pOaLVY2xyfYriolT0NiOl9ygVYEjEm8gJ6zk4MwdwNF1FAl9GKDLb
9f/UdWCHtkIL+ldjnDvTBRSjxr6VIirRjWjP9tUk0qXJ8LXzWekzcQutCn4RAgMB
AAEwDQYJKoZIhvcNAQEFBQADgYEASDol+eFmjJDy1QTQmCjUxAzCe/dFyEEE2jdw
Z8EXcQTVUwhVRMVEkg3NgFEKP0c5Uk3xvsLMAmCTL81XrN6yxQ5fw803n2MccHxt
D+GMk60nncLKIOlzaNWzX3lHzOod8dYmXmDHN4BaBf8ZN7H0UyHJzCidJhgG57Q0
21FyXaQ=
''')
print('RSA серт:', cryptoapi.cert_info(cert))


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
