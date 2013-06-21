# coding: utf-8

from cprocsp import csp, rdn
# from nose.tools import raises
from uuid import uuid4
import subprocess as sub
import os
import sys
from base64 import b64encode
from platform import architecture

if sys.version_info >= (3,):
        unicode = str
else:
        unicode = unicode


signname = None

if architecture()[0] == '32bit':
    arch = 'ia32'
else:
    arch = 'amd64'


def setup():
    ctx = csp.Context('test', csp.PROV_GOST_2001_DH, 0)
    if ctx is None:
        ctx = csp.Context(r'\\.\hdimage\test', csp.PROV_GOST_2001_DH, csp.CRYPT_NEWKEYSET)
    assert ctx
    name = ctx.name()
    assert name == 'new_test'

    key = ctx.get_key()
    if key is None:
        key = ctx.create_key(csp.CRYPT_EXPORTABLE)
    ekey = ctx.get_key(csp.AT_KEYEXCHANGE)
    if ekey is None:
        ekey = ctx.create_key(csp.CRYPT_EXPORTABLE, csp.AT_KEYEXCHANGE)
    assert ekey
    return name


def teardown():
    '''
    Прибиение временных файлов.
    '''
    global signname
    if os.path.exists(signname):
        os.unlink(signname)
        os.unlink(signname + '.sgn')


def test_context_simple():
    '''
    Контест создается функцией `Context()`. Первым параметром передается
    строка-имя контейнера ключей. Второй параметр -- тип провайдера, третий --
    флаги. Контейнер без имени является контейнером пользователя по умолчанию.
    Результатом функции является экземпляр класса `Crypt()` или `None`, если
    именованный контейнер не найден.

    '''
    context = csp.Context(
        None,
        csp.PROV_GOST_2001_DH,
        csp.CRYPT_VERIFYCONTEXT,
    )
    assert context
    return context


def test_context_named_keystore():
    '''
    Подключение к именованному контейнеру. Если контейнер с данным именем не
    найден, будет возвращено `None`.
    '''
    context = csp.Context(
        "test",
        csp.PROV_GOST_2001_DH,
        0,
    )
    assert context
    return context


#def test_context_named_provider():
    #'''
    #Подключение к криптопровайдеру по идентификатору имени. Использует
    #необязательный четвертый параметр функции `Context()`, в котором передается
    #строка с именем провайдера.
    #'''
    #context = csp.Context(
        #None,
        #csp.PROV_GOST_2001_DH,
        #0,
        #'Crypto-Pro HSM CSP'
    #)
    #assert context
    #return context


def test_context_not_found():
    ctx = csp.Context(
        "some_wrong_ctx",
        csp.PROV_GOST_2001_DH,
        0,
    )
    assert not ctx


def test_export_import_pubkey():
    '''
    Функция `Crypt.get_key(keytype=csp.AT_SIGNATURE)` возвращает одну из двух пар открытый/закрытый
    ключ, связанных с контекстом. Необязательный параметр `keytype` по
    умолчанию обеспечивает извлечение ключей подписи. Может также принимать
    значение `csp.AT_KEYEXCHANGE`, для извлечения ключей обмена. Результатом
    функции является либо экземпляр класса `Key()` либо `None`, если хранилище
    не содержит ключей.

    Функция `Key.encode(cryptkey=None)` экспортирует ключ во внутренний
    бинарный формат для передачи по каналам данных. Необязательный параметр
    `cryptkey` задает открытый ключ получателя. При его использовании
    экспортируется закрытая половина ключа в зашифрованном для получателя виде.
    Без этого параметра экспортируется незашифрованный открытый ключ.

    Функция `Crypt.import_key(k, decrypt)` связывает ключ `k` с контекстом
    криптопровайдера. Параметр `k` содержит блоб для передачи ключа во
    внутреннем формате. Необязательный второй параметр `decrypt` задает объект
    `Key` для расшифровки закрытого ключа.

    '''
    context = csp.Context("test", csp.PROV_GOST_2001_DH, 0)

    recipient = csp.Context(None, csp.PROV_GOST_2001_DH, csp.CRYPT_VERIFYCONTEXT)

    sk = context.get_key()
    assert sk

    pk = recipient.import_key(sk.encode())
    assert pk


def test_create_named_container():
    '''
    Новый контейнер ключей может быть создан вызовом функции `Context` с
    флагом `csp.CRYPT_NEWKEYSET`. Первый параметр должен при этом содержать
    полное имя создаваемого контейнера. Хранилище ключей создается пустым.

    Идентифицирует контейнер имя, которое возвращается функцией `Crypt.name()`.

    Создать ключ в новом хранилище можно функцией `Crypt.create_key(flags, keyspec)`.
    Параметр `flags` может принимать значение `csp.CRYPT_EXPORTABLE`, что
    делает ключ извлекаемым или `0`, тогда ключ нельзя будет экспортировать
    функцией `Key.encode()`. Параметр `keyspec` принимает значение
    `csp.AT_KEYEXCHANGE` или `csp.AT_SIGNATURE`.

    '''
    ctx = csp.Context('new_test', csp.PROV_GOST_2001_DH, 0)
    if ctx is None:
        ctx = csp.Context(r'\\.\hdimage\new_test', csp.PROV_GOST_2001_DH, csp.CRYPT_NEWKEYSET)
    assert ctx
    name = ctx.name()
    assert name == 'new_test'

    key = ctx.get_key()
    if key is None:
        key = ctx.create_key(csp.CRYPT_EXPORTABLE)
    ekey = ctx.get_key(csp.AT_KEYEXCHANGE)
    if ekey is None:
        ekey = ctx.create_key(csp.CRYPT_EXPORTABLE, csp.AT_KEYEXCHANGE)
    assert ekey
    return name


def test_export_import_private_key():
    name = test_create_named_container()
    sender = csp.Context(name, csp.PROV_GOST_2001_DH, 0)
    receiver = csp.Context("test", csp.PROV_GOST_2001_DH, 0)

    rec_key = receiver.get_key(csp.AT_KEYEXCHANGE)
    assert rec_key
    sender_key = sender.get_key(csp.AT_KEYEXCHANGE)
    assert sender_key

    receiver_pub = sender.import_key(rec_key.encode(), sender_key)
    assert receiver_pub
    # sender_priv = sender_key.encode_key(receiver_pub)

    # receiver_new_key = receiver.import_key(sender_priv, rec_key)
    # assert receiver_new_key

    # Для удаления ключевого контейнера функции `csp.Context()` в числе флагов
    # передается `csp.CRYPT_DELETEKEYSET`. При этом она возвращает `None`, т.к.
    # контекст не с чем связывать.
    res = csp.Context(name, csp.PROV_GOST_2001_DH, csp.CRYPT_DELETEKEYSET)
    assert res is None


def test_store():
    '''
    Открытие системного хранилища сертификатов.
    '''
    cs = csp.CertStore(None, "MY")
    assert cs


def test_store_in_context():
    '''
    Первый параметр позволяет связать хранилище с контекстом провайдера.
    '''
    context = test_context_simple()
    cs = csp.CertStore(context, "MY")
    assert cs


def test_store_iter():
    '''
    Итерация по контейнеру перебирает все хранящиеся в нем сертификаты.
    '''
    cs = csp.CertStore(None, "MY")
    for c in cs:
        assert c


def test_duplicate_cert():
    '''
    Метод `Cert.duplicate()` создает веременную копию серта, не сохраняемую в
    хранилище.
    '''
    cs = csp.CertStore(None, "MY")
    for c in cs:
        cdup = c.duplicate()
        print((b64encode(c.thumbprint())))
        print((b64encode(cdup.thumbprint())))


def test_extract_cert():
    '''
    Метод `Cert.extract()` возвращает закодированный сертификат в виде байтовой строки.
    '''
    cs = csp.CertStore(None, "MY")
    cert = list(cs)[0]
    cdata = cert.extract()
    assert len(cdata)
    return cdata


def test_cert_from_data():
    '''
    Конструктор `Cert(s)`, при передаче ему байтовой строки `s`, декодирует и
    загружает из нее новый экземпляр сертификата, не сохраненный в хранилище.
    При необходимости его можно туда добавить функцией `CertStore.add_cert()`.
    '''
    cdata = test_extract_cert()
    print(len(cdata))
    newc = csp.Cert(cdata)
    assert newc
    memstore = csp.CertStore()
    memstore.add_cert(newc)
    assert len(list(memstore)) == 1


def _cert_thumb():
    '''
    Метод `Cert.thumb()` возвращает отпечаток сертификата в виде бинарной
    строки. Для перевода в обычную строку, может потребоваться кодирование в
    base64.
    '''
    cs = csp.CertStore(None, "MY")
    thumbs = [cert.thumbprint() for cert in cs]
    assert thumbs
    return thumbs[0]


def test_cert_name():
    '''
    Метод `Cert.name()` возвращает строку с RDN сертификата в виде бинарной
    строки. Для дальнейшей работы с ней может потребоваться модуль `RDN` и ее
    перекодирование в unicode.
    '''
    cs = csp.CertStore(None, "MY")
    names = list(cert.name() for cert in cs)
    print((names))
    assert all(name for name in names)


def test_cert_issuer():
    '''
    Метод `Cert.issuer()` возвращает информацию о том, кто выдал сертификат,
    работает аналогично `Cert.name()`.
    '''
    cs = csp.CertStore(None, "MY")
    issuers = list(cert.issuer() for cert in cs)
    print((issuers))
    assert all(s for s in issuers)


def test_cert_find_by_thumb():
    '''
    Метод `CertStore.find_by_thumb(s)` перечисляет все сертификаты с
    отпечатком, равным байтовой строке `s`.
    '''
    thumb = _cert_thumb()
    cs = csp.CertStore(None, "MY")
    res = list(cs.find_by_thumb(thumb))
    assert len(res)


def test_cert_find_by_name():
    '''
    Метод `CertStore.find_by_name(s)` перечисляет все сертификаты, в RDN которых
    так или иначе встречается байтовая строка `s`.
    '''
    name = b'test'
    cs = csp.CertStore(None, "MY")
    res = list(cs.find_by_name(name))
    assert len(res)


def test_memory_store():
    '''
    Хранилище сертификатов может быть создано в памяти вызовом конструктора
    `CertStore()` без параметров.

    '''
    my = csp.CertStore(None, "MY")
    cert = list(my)[0]

    cs = csp.CertStore()

    # метод `CertStore.add_cert(c)` добавляет сертификат `c` в хранилище.
    cs.add_cert(cert)

    assert len(list(cs))
    # хранилище в памяти не сохраняется в постоянной памяти после уничтожения
    # объекта.


def test_cert_not_found():
    cs = csp.CertStore(None, "MY")
    res = list(cs.find_by_thumb(b'x' * 20))
    assert not len(res)


def test_cert_name_not_found():
    cs = csp.CertStore(None, "MY")
    res = list(cs.find_by_name(b'some wrong name'))
    assert not len(res)


def test_cert_sign_algorithm():
    '''
    Метод `Cert.sign_algorithm()` возвращает идентификатор алгоритма ЭЦП.
    '''
    cs = csp.CertStore(None, "MY")
    cert = list(cs)[0]
    assert cert.sign_algorithm() == '1.2.643.2.2.3'


def _msg_decode():
    '''
    Конструктор сообщения `CryptMsg(s[, c])` инициализируется бинарной строкой с
    PKCS7 или DER сообщением. При создании сообщение автоматически
    декодируется. Второй, необязательный, параметр `c` задает контекст
    криптопровайдера. По умолчанию, неявно создается контекст для проверки ЭЦП.
    '''
    with open('tests/logical.cms', 'rb') as f:
        testdata = f.read()
    msg = csp.CryptMsg(testdata)
    return msg


def test_sign_data():
    '''
    При создании нового пустого сообщения, конструктору передается либо
    контекст, либо конструктор вызывается без параметров.

    Метод `CryptMsg.add_signer_cert(c)` сохраняет в сообщении сертификат `c`,
    которым будет подписано сообщение. Таким образом можно добавлять несколько
    подписантов и их сертификатов.

    Метод `CryptMsg.sign_data(s)` создает сообщение, закодированное в PKCS7,
    подписанное всеми сертификатами из списка. Подписи и сертификаты входят в
    байтовую строку, которая возвращается функцией.
    '''
    ctx = csp.Context(
        "test",
        csp.PROV_GOST_2001_DH,
        0,
    )
    cs = csp.CertStore(ctx, "MY")
    cert = list(cs)[0]
    mess = csp.CryptMsg(ctx)
    mess.add_signer_cert(cert)
    data = mess.sign_data(b'hurblewurble')
    assert len(data)
    return data


def test_detached_sign():
    '''
    Второй необязательный параметр `detach` функции CryptMsg.sign_data()`
    управляет режимом подписывания. При вызове со значение `True` функция
    подписи вернет не полное подписанное сообщение, а только подпись, которую
    можно хранить отдельно от подписанных ей данных.
    '''
    ctx = csp.Context(
        "test",
        csp.PROV_GOST_2001_DH,
        0,
    )
    assert ctx
    cs = csp.CertStore(ctx, "MY")
    cert = list(cs)[0]
    mess = csp.CryptMsg(ctx)
    mess.add_signer_cert(cert)
    data = mess.sign_data(b'hurblewurble', True)
    assert len(data)
    return data


def test_msg_signatures():
    '''

    Поле `CryptMsg.num_signers` содержит количество подписантов сообщения.

    Функция `CryptMsg.get_nth_signer_info(n)` возвращает структуру, уникально
    идентифицирующую сертификат `n`-го подписанта. По ней можно получить
    сертификат подписанта, либо из хранилища в сообщении, либо из системного
    хранилища.  Для этого служит функция `CertStore.get_cert_by_info()`. Если
    сертификата нет в хранилище, функция возвращает `None`.

    Полученный таким образом сертификат `c` можно использовать для проверки
    подписи под сообщением с помощью функции `CryptMsg.verify_cert(c)`. Функция
    возвращает `True`, если для данного сертификата соответствующая ему подпись
    верна.

    Для упрощения обработки сертификатов, функция `CryptMsg.signer_certs()`
    перечисляет сертификаты всех подписантов сообщения.

    '''
    ctx = csp.Context(
        None,
        csp.PROV_GOST_2001_DH,
        csp.CRYPT_VERIFYCONTEXT,
    )
    testdata = test_sign_data()
    # testdata = open('tests/logical.cms', 'rb').read()

    # загрузка сообщения из блоба данных
    msg = csp.CryptMsg(testdata, ctx)
    del testdata
    # сведения о раскодированном сообщении
    print(msg.type)
    print(msg.num_signers)
    print(len(msg.get_data()))

    # Идентификационная информация для 1-го подписанта.
    psi = msg.get_nth_signer_info(0)
    assert psi
    my = csp.CertStore(msg)
    sys_my = csp.CertStore(None, "MY")

    # Из сообщения можно извлечь сертификат по этой информации
    verify_cert = my.get_cert_by_info(psi)
    t1 = verify_cert.thumbprint()
    verify_cert = my.get_cert_by_info(psi)

    # Сертификат можно извлечь так же из системного хранилища, если он там
    # есть.
    same_cert = sys_my.get_cert_by_info(psi)
    t2 = same_cert.thumbprint()
    assert t1 == t2

    # разнообразные проверки подписей через сертификаты
    print(verify_cert.name())
    assert msg.verify_cert(verify_cert)
    ns = list(c.name() for c in msg.signer_certs())
    assert len(ns)
    cs = list(csp.CertStore(msg))
    print([(msg.verify_cert(x), x.name()) for x in cs])
    assert all(msg.verify_cert(c) for c in cs)


def test_detached_sign2():
    '''
    Класс `Signature` наследует всю функциональность `CryptMsg`, но
    ориентирован на работу с отсоединенными подписями. Поэтому метод
    `Signature.sign_data()` по умолчанию возвращает отсоединенную подпись.
    '''
    ctx = csp.Context(
        "test",
        csp.PROV_GOST_2001_DH,
        0,
    )
    assert ctx
    cs = csp.CertStore(ctx, "MY")
    cert = list(cs)[0]

    # создание новой (пустой) отсоединенной подписи
    sgn = csp.Signature(ctx)
    sgn.add_signer_cert(cert)

    # подписывание данных экземпляром `Signature` по умолчанию дает
    # отсоединенную подпись.
    data = sgn.sign_data(b'hurblewurble')
    assert len(data)
    return data


def test_cert_from_detached():
    '''
    Конструктору хранилища сертификатов `CertStore(msg)` можно передать экземпляр
    класса `CryptMsg` или `Signature`. Через это хранилище можно извлекать
    хранящиеся в сообщении или подписи сертификаты.
    '''
    data = test_detached_sign()
    sgn = csp.Signature(data)
    cs = csp.CertStore(sgn)
    assert len(list(cs))


def test_verify_with_detached():
    '''
    Поле `Signature.num_signers`, также как и `CryptMsg.num_signers` содержит
    количество подписантов сообщения.

    Метод `Signature.verify_data(d, n)` проверяет для отсоединенных данных `d`
    подпись `n`-го подписанта.
    '''
    data = test_detached_sign2()
    sgn = csp.Signature(data)
    for n in range(sgn.num_signers):
        assert sgn.verify_data(b'hurblewurble', n)


def test_verify_with_detached2():
    '''
    Проверка отсоединенной подписи, созданной через командную строку.
    '''
    with open(signname, 'rb') as f:
        data = f.read()
    with open(signname + '.sgn', 'rb') as f:
        signdata = f.read()
    sgn = csp.Signature(signdata)
    for n in range(sgn.num_signers):
        assert sgn.verify_data(data, n)


def test_verify_with_detached_bad():
    '''
    Если для `n`-го подписанта подпись под данными не бьется, функция
    `Signature.verify_data()` возвращает `False`.
    '''
    data = test_detached_sign()
    sgn = csp.Signature(data)
    for n in range(sgn.num_signers):
        assert not sgn.verify_data(b'hUrblEwurBle', n)


def test_verify_with_detached_bad2():
    data = os.urandom(1024)
    with open(signname + '.sgn', 'rb') as f:
        signdata = f.read()
    sgn = csp.Signature(signdata)
    for n in range(sgn.num_signers):
        assert not sgn.verify_data(data, n)


def test_verify_file():
    names = ('data1', 'data2')
    for name in names:
        with open('tests/{0}.bin'.format(name), 'rb') as f:
            data = f.read()
        with open('tests/{0}.p7s'.format(name), 'rb') as f:
            sigdata = f.read()
        sign = csp.Signature(sigdata)
        print(sign.num_signers)
        for c in csp.CertStore(sign):
            print(unicode(c.name()))
            print(unicode(c.issuer()))
            print(b64encode(c.thumbprint()))
        assert all(sign.verify_data(data, n) for n in range(sign.num_signers))


def test_rdn():
    dn = '''1.2.643.3.141.1.2 = \\#0C0430303030 , 1.2.643.3.141.1.1="#0C0A30303030303030303030",
    1.2.643.3.131.1.1="#0C0A36363939303030303030", E=fedotov@skbkontur.ru,
    C=RU, S=66 Свердловская область + L=Екатеринбург, O=ЗАО ПФ СКБ Контур, OU=0,
    CN=Федотов Алексей Николаевич,
    1.2.840.113549.1.9.2="#0C21363639393030303030302D3636393930313030312D363630393033303338363334",
    T=Инженер-программист, SN=Федотов Алексей Николаевич
    '''
    assert len(dict(rdn.read_rdn(dn))) == 13


def test_cert_rdn():
    '''
    В модуле `cprocsp.rdn` определен класс для парсинга записей в формате RDN
    для облегчения доступа к данным о сертификате. Конструктор `rdn.RDN`
    инициализируется строкой и возвращает словарь. Для Python 3 необходимо
    предварительно преобразовать строку в unicode.

    '''
    cs = csp.CertStore(None, "MY")
    for c in cs:
        assert 'CN' in rdn.RDN(unicode(c.name(), 'windows-1251'))
        assert 'CN' in rdn.RDN(unicode(c.issuer(), 'windows-1251'))


def test_encrypt_data():
    '''
    Шифрование сообщения представлено методом `CryptMsg.encrypt_data(s)`, где
    `s` -- бинарная строка. Результатом является шифрованный блок бинарных
    данных. Предварительно необходимо задать один или более сертификатов
    получателя функцией `CryptMsg.add_recipient_cert(cert)`. В Python 3
    необходимо перевести шифруемую строку в какую-нибудь 8-битную кодировку.
    '''
    cs = csp.CertStore(None, "MY")
    re_cert = list(cs)[0]
    msg = csp.CryptMsg()
    msg.add_recipient_cert(re_cert)
    data = msg.encrypt_data(b'murblehurblewurble')
    assert data
    return data


def test_decrypt_data():
    '''
    Зашифрованный блок данных можно передавать по незащищенному каналу.
    Расшифровка производится созданием пустого экземпляра `CryptMsg` и вызовом
    от него функции `CryptMsg.decrypt_data(data)`, где `data` -- бинарная
    строка с шифрованными данными. Пустое сообщение можно создать вызовом
    коструктора без параметрое, либо передать конструктору контекст
    криптопровайдера. Тогда ключи расшифровки будут извлекаться из хранилища
    ключей для этого контекста.

    '''
    data = test_encrypt_data()
    print(data)
    msg = csp.CryptMsg()
    assert msg
    res = msg.decrypt_data(data)
    print(res)
    assert res == b'murblehurblewurble'


def test_add_remove_cert():
    '''
    Метод `CertStore.add_cert(cert) добавляет сертификат `cert` в хранилище.
    Объект сертификата может быть загружен из сообщения, взят из другого
    хранилища или получен дублированием с помощью функции `Cert.duplicate()`.

    Если экземпляр сертификата привязан к хранилищу, его можно удалить оттуда
    вызовом метода `Cert.remove_from_store()`. При этом им можно продолжать
    пользоваться, пока он не будет удален из памяти.

    '''
    my = csp.CertStore(None, "MY")
    n1 = len(list(my))
    with open('tests/logical.cms', 'rb') as f:
        testdata = f.read()
    msg = csp.CryptMsg(testdata)
    ids = []
    for crt in csp.CertStore(msg):
        print(crt.name())
        print(crt.issuer())
        my.add_cert(crt)
        my.add_cert(crt.duplicate())
        ids.append(crt.thumbprint())
    assert len(ids)
    assert len(list(my)) == n1 + len(ids) * 2
    for cert_id in ids:
        cs = list(my.find_by_thumb(cert_id))
        # копии хранятся в хранилище и удаляются независимо друг от друга, хотя
        # имеют одинаковый отпечаток
        assert len(cs) == 2
        for cert in cs:
            cert.remove_from_store()
    assert len(list(my)) == n1
