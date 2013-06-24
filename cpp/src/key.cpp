#include "common.hpp"
#include "key.hpp"

Key::Key(Crypt *pctx, HCRYPTKEY hk) throw(CSPException) {
    parent = pctx;
    parent->ref();
    hkey = hk;
    LOG("new key\n");
}

Key::~Key() throw(CSPException) {
    LOG("release key\n");
    if (hkey) {
        bool res = CryptDestroyKey(hkey);
        if (!res) {
            //throw CSPException("Couldn't destroy key");
        }
    }
    parent->unref();
}

void Key::encode(BYTE **s, DWORD *slen, Key *cryptkey) throw(CSPException) {
    HCRYPTKEY expkey;
    DWORD blobtype;
    if (cryptkey) {
        expkey = cryptkey -> hkey;
        blobtype = SIMPLEBLOB;
    } else {
        expkey = 0;
        blobtype = PUBLICKEYBLOB;
    }

    if(!CryptExportKey( hkey, expkey, blobtype, 0, NULL, slen)) {
        throw CSPException("Error computing key blob length");
    }

    *s = (BYTE *)malloc(*slen);

    if(!CryptExportKey( hkey, expkey, blobtype, 0, (BYTE *)*s, slen)) {
        free((void *)*s);
        throw CSPException("Error exporting key blob");
    }
};

