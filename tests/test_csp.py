# coding: utf-8

from cprocsp import csp, rdn
from nose.tools import raises
from uuid import uuid4
import subprocess as sub
import os
from base64 import b64encode
from platform import architecture

signname = None

if architecture()[0] == '32bit':
    arch = 'ia32'
else:
    arch = 'amd64'


def setup_module():
    global signname
    signname = os.path.join('/tmp', uuid4().hex)
    open(signname, 'wb').write(os.urandom(1024))
    if sub.call(['/opt/cprocsp/bin/{0}/cryptcp'.format(arch),
                 '-dir', '/tmp', '-signf', '-nochain', '-cert', '-der', signname]):
        assert False


def teardown_module():
    global signname
    if os.path.exists(signname):
        os.unlink(signname)
        os.unlink(signname + '.sgn')


def test_context_simple():
    context = csp.Context(
        None,
        csp.PROV_GOST_2001_DH,
        csp.CRYPT_VERIFYCONTEXT,
    )
    assert context
    return context


def test_context_named():
    ur''' Работает при наличии в системе контейнера 'test'.
    Необходимо его предварительно создать командой:

    csptestf -keyset -newkeyset -cont '\\.\hdimage\test'

    '''
    context = csp.Context(
        "test",
        csp.PROV_GOST_2001_DH,
        0,
    )
    assert context
    return context


def test_context_not_found():
    ctx = csp.Context(
        "some_wrong_ctx",
        csp.PROV_GOST_2001_DH,
        0,
    )
    assert not ctx


def test_store():
    cs = csp.CertStore(None, "MY")
    assert cs


def test_store_in_context():
    context = test_context_simple()
    cs = csp.CertStore(context, "MY")
    assert cs


def test_store_iter():
    ur''' Работает при наличии в системе как минимум одного сертификата.

    Тестовый сертификат создается следующим образом:

    Запрос на сертификат

        cryptcp -creatrqst -cont '\\.\hdimage\test' -provtype 75 -nokeygen -dn 'E=test@localhost.localdomain,CN=test' -both ~/req

    Затем следует получить сертификат вручную от тестового УЦ по адресу: http://www.cryptopro.ru/certsrv

    И установить сохраненный сертификат в хранилище:

        cryptcp -instcert -cont '\\.\hdimage\test' ИмяФайла.cert'''

    cs = csp.CertStore(None, "MY")
    for c in cs:
        assert c


def test_duplicate_cert():
    cs = csp.CertStore(None, "MY")
    for c in cs:
        cdup = c.duplicate()
        print b64encode(c.thumbprint())
        print b64encode(cdup.thumbprint())


def _cert_thumb():
    cs = csp.CertStore(None, "MY")
    thumbs = [cert.thumbprint() for cert in cs]
    assert thumbs
    return thumbs[0]


def test_cert_name():
    cs = csp.CertStore(None, "MY")
    names = list(cert.name() for cert in cs)
    print names
    assert all(name for name in names)


def test_cert_issuer():
    cs = csp.CertStore(None, "MY")
    issuers = list(cert.issuer() for cert in cs)
    print issuers
    assert all(s for s in issuers)


def test_cert_find_by_thumb():
    thumb = _cert_thumb()
    cs = csp.CertStore(None, "MY")
    res = list(cs.find_by_thumb(thumb))
    assert len(res)


def test_cert_find_by_name():
    name = 'test'
    cs = csp.CertStore(None, "MY")
    res = list(cs.find_by_name(name))
    assert len(res)


def test_memory_store():
    my = csp.CertStore(None, "MY")
    cert = list(my)[0]

    cs = csp.CertStore()
    cs.add_cert(cert)

    assert len(list(cs))


def test_cert_not_found():
    cs = csp.CertStore(None, "MY")
    res = list(cs.find_by_thumb('x' * 20))
    assert not len(res)


def test_cert_name_not_found():
    cs = csp.CertStore(None, "MY")
    res = list(cs.find_by_name('some wrong name'))
    assert not len(res)


def test_cert_sign_algorithm():
    cs = csp.CertStore(None, "MY")
    cert = list(cs)[0]
    assert cert.sign_algorithm() == '1.2.643.2.2.3'


def _msg_decode():
    testdata = open('tests/logical.cms', 'rb').read()
    msg = csp.CryptMsg(testdata)
    return msg


def test_sign_data():
    ctx = csp.Context(
        "test",
        csp.PROV_GOST_2001_DH,
        0,
    )
    cs = csp.CertStore(ctx, "MY")
    cert = list(cs)[0]
    mess = csp.CryptMsg(ctx)
    mess.add_signer_cert(cert)
    data = mess.sign_data('hurblewurble')
    assert len(data)
    return data


def test_detached_sign():
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
    data = mess.sign_data('hurblewurble', True)
    assert len(data)
    return data


def test_cert_from_detached():
    data = test_detached_sign()
    sgn = csp.Signature(data)
    cs = csp.CertStore(sgn)
    assert len(list(cs))


def test_verify_with_detached():
    data = test_detached_sign()
    sgn = csp.Signature(data)
    for n in range(sgn.num_signers):
        assert sgn.verify_data('hurblewurble', n)


def test_verify_with_detached2():
    data = open(signname, 'rb').read()
    signdata = open(signname + '.sgn', 'rb').read()
    sgn = csp.Signature(signdata)
    for n in range(sgn.num_signers):
        assert sgn.verify_data(data, n)


def test_verify_with_detached_bad():
    data = test_detached_sign()
    sgn = csp.Signature(data)
    for n in range(sgn.num_signers):
        assert not sgn.verify_data('hUrblEwurBle', n)


def test_verify_with_detached_bad2():
    data = os.urandom(1024)
    signdata = open(signname + '.sgn', 'rb').read()
    sgn = csp.Signature(signdata)
    for n in range(sgn.num_signers):
        assert not sgn.verify_data(data, n)


def test_msg_signatures():
    ctx = csp.Context(
        None,
        csp.PROV_GOST_2001_DH,
        csp.CRYPT_VERIFYCONTEXT,
    )
    testdata = test_sign_data()
    # testdata = open('tests/logical.cms', 'rb').read()
    msg = csp.CryptMsg(testdata, ctx)
    del testdata
    print msg.type
    print msg.num_signers
    print len(msg.get_data())

    psi = msg.get_nth_signer_info(0)
    assert psi
    my = csp.CertStore(msg)
    verify_cert = my.get_cert_by_info(psi)

    print verify_cert.name()
    assert msg.verify_cert(verify_cert)
    ns = list(c.name() for c in msg.signer_certs())
    assert len(ns)
    cs = list(csp.CertStore(msg))
    print [(msg.verify_cert(x), x.name()) for x in cs]
    assert all(msg.verify_cert(c) for c in cs)


def test_verify_file():
    names = ('data1', 'data2')
    for name in names:
        data = open('tests/{0}.bin'.format(name), 'rb').read()
        sigdata = open('tests/{0}.p7s'.format(name), 'rb').read()
        sign = csp.Signature(sigdata)
        print sign.num_signers
        for c in csp.CertStore(sign):
            print unicode(c.name(), 'windows-1251')
            print unicode(c.issuer(), 'windows-1251')
            print b64encode(c.thumbprint())
        assert all(sign.verify_data(data, n) for n in range(sign.num_signers))


def test_rdn():
    dn = u'''1.2.643.3.141.1.2 = \\#0C0430303030 , 1.2.643.3.141.1.1="#0C0A30303030303030303030",
    1.2.643.3.131.1.1="#0C0A36363939303030303030", E=fedotov@skbkontur.ru,
    C=RU, S=66 Свердловская область + L=Екатеринбург, O=ЗАО ПФ СКБ Контур, OU=0,
    CN=Федотов Алексей Николаевич,
    1.2.840.113549.1.9.2="#0C21363639393030303030302D3636393930313030312D363630393033303338363334",
    T=Инженер-программист, SN=Федотов Алексей Николаевич
    '''
    assert len(dict(rdn.read_rdn(dn))) == 13


def test_cert_rdn():
    cs = csp.CertStore(None, "MY")
    for c in cs:
        assert 'CN' in rdn.RDN(c.name())
        assert 'CN' in rdn.RDN(c.issuer())


def test_encrypt_data():
    cs = csp.CertStore(None, "MY")
    re_cert = list(cs)[0]
    msg = csp.CryptMsg()
    msg.add_recipient_cert(re_cert)
    data = msg.encrypt_data('murblehurblewurble')
    assert data
    return data


def test_decrypt_data():
    data = test_encrypt_data()
    print data
    msg = csp.CryptMsg()
    assert msg
    res = msg.decrypt_data(data)
    print res
    assert res == 'murblehurblewurble'


def test_add_remove_cert():
    my = csp.CertStore(None, "MY")
    n1 = len(list(my))
    testdata = open('tests/logical.cms', 'rb').read()
    msg = csp.CryptMsg(testdata)
    ids = []
    for crt in csp.CertStore(msg):
        print crt.name()
        print crt.issuer()
        my.add_cert(crt)
        my.add_cert(crt.duplicate())
        ids.append(crt.thumbprint())
    assert len(ids)
    assert len(list(my)) == n1 + len(ids) * 2
    for cert_id in ids:
        cs = list(my.find_by_thumb(cert_id))
        assert len(cs) == 2
        for cert in cs:
            cert.remove_from_store()
    assert len(list(my)) == n1


def test_export_import_pubkey():
    context = csp.Context("test", csp.PROV_GOST_2001_DH, 0)

    recipient = csp.Context(None, csp.PROV_GOST_2001_DH, csp.CRYPT_VERIFYCONTEXT)

    sk = context.get_key()
    assert sk

    pk = recipient.import_key(str(sk))
    assert pk


def test_create_named_container():
    ctx = csp.Context(r'\\.\hdimage\new', csp.PROV_GOST_2001_DH, 0)
    if ctx is None:
        ctx = csp.Context(r'\\.\hdimage\new', csp.PROV_GOST_2001_DH, csp.CRYPT_NEWKEYSET)
    assert ctx
    name = ctx.name()
    assert name == 'new'

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

    receiver_pub = sender.import_key(str(rec_key), sender_key)
    assert receiver_pub
    #sender_priv = sender_key.encode_key(receiver_pub)

    #receiver_new_key = receiver.import_key(sender_priv, rec_key)
    #assert receiver_new_key
