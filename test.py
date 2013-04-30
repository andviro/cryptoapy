# file: test.py

import csp


def test_constants():
    print "ICONST  =", csp.ICONST, "(should be 42)"
    print "FCONST  =", csp.FCONST, "(should be 2.1828)"
    print "CCONST  =", csp.CCONST, "(should be 'x')"
    print "CCONST2 =", csp.CCONST2, "(this should be on a new line)"
    print "SCONST  =", csp.SCONST, "(should be 'Hello World')"
    print "SCONST2 =", csp.SCONST2, "(should be '\"Hello World\"')"
    print "EXPR    =", csp.EXPR, "(should be 48.5484)"
    print "iconst  =", csp.iconst, "(should be 37)"
    print "fconst  =", csp.fconst, "(should be 3.14)"

    try:
        print "EXTERN = ", csp.EXTERN, "(Arg! This shouldn't print anything)"
    except AttributeError:
        print "EXTERN isn't defined (good)"

    try:
        print "FOO    = ", csp.FOO, "(Arg! This shouldn't print anything)"
    except AttributeError:
        print "FOO isn't defined (good)"
