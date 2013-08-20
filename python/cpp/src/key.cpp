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
            throw CSPException("~Key:Couldn't destroy key");
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
        throw CSPException("Key.encode: Error computing key blob length");
    }

    *s = (BYTE *)malloc(*slen);

    if(!CryptExportKey( hkey, expkey, blobtype, 0, (BYTE *)*s, slen)) {
        free((void *)*s);
        throw CSPException("Key.encode: Error exporting key blob");
    }
};

void Key::store_cert(Cert *c) throw (CSPException) {
    if (!c || !c->pcert) {
        throw CSPException("Key.store_cert: invalid certificate");
    }
    if (!CryptSetKeyParam(hkey, KP_CERTIFICATE, (const BYTE*) c->pcert->pbCertEncoded, 0)) {
        throw CSPException("Key.store_cert: couldn't set key parameter");
    }
}
