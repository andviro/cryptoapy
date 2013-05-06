# coding: utf-8

from cprocsp import csp


def test_context():
    flag, ctx = csp.CryptAcquireContext(
        None,
        None,
        csp.PROV_GOST_2001_DH,
        csp.CRYPT_VERIFYCONTEXT,
    )
    assert flag
    assert csp.CryptReleaseContext(ctx, 0)
