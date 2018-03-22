#include "common.hpp"
#include "key.hpp"

Key::Key(RCObj *pctx, HCRYPTKEY hk) throw(CSPException) {
    parent = pctx;
    parent->ref();
    hkey = hk;
    LOG("Key()\n");
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
    LOG("Key.encode(%p)\n", cryptkey);
    HCRYPTKEY expkey;
    DWORD blobtype;
    if (cryptkey) {
        expkey = cryptkey -> hkey;
        blobtype = PLAINTEXTKEYBLOB;
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


ALG_ID Key::alg_id() throw (CSPException) {
    ALG_ID res;
    DWORD size = sizeof(res);
    if(!CryptGetKeyParam(hkey, KP_ALGID, (BYTE*)&res, &size, 0))
    {
        DWORD err = GetLastError();
        throw CSPException("Key.alg_id: couldn't get key algorithm ID", err);
    }
    return res;
}


void Key::extract_cert(BYTE **s, DWORD *slen) throw (CSPException) {
    if(!CryptGetKeyParam( 
        hkey, 
        KP_CERTIFICATE, 
        NULL, 
        slen, 
        0))
    {
        DWORD err = GetLastError();
        throw CSPException("Key.extract_cert: couldn't get certificate blob length", err);
    }

    *s = (BYTE*)malloc(*slen);

    if(!*s) {
        throw CSPException("Key.extract_cert: memory allocation error");
    }

    //--------------------------------------------------------------------
    // Копирование параметров ключа в BLOB.

    if(!CryptGetKeyParam( 
        hkey, 
        KP_CERTIFICATE, 
        *s, 
        slen, 
        0))
    {
        DWORD err = GetLastError();
        throw CSPException("Key.extract_cert: couldn't copy certificate blob", err);
    }
}


void Key::encrypt(BYTE *STRING, DWORD LENGTH, BYTE **s, DWORD *slen) throw(CSPException)
{
    LOG("Key::encrypt(%p, %u)\n", STRING, LENGTH);
    LOG("    getting encrypted data size\n");
    // Вызов функции CryptEncryptMessage.
    if(!CryptEncrypt( hkey, NULL, true, 0, NULL, slen, LENGTH)) {
        DWORD err = GetLastError();
        LOG("    error getting encrypted data size %x\n", err);
        throw CSPException("Key.encrypt: Getting buffer size failed.", err);
    }
    LOG("    encrypted data size is %u\n", *slen);
    // Распределение памяти под возвращаемый BLOB.
    *s = (BYTE*)malloc(*slen);
    if(!*s) {
        DWORD err = GetLastError();
        throw CSPException("Key.encrypt: Memory allocation error while encrypting.", err);
    }
    LOG("    encrypting data\n");
    // Повторный вызов функции CryptEncryptMessage для зашифрования содержимого.
    if(!CryptEncrypt( hkey, NULL, true, 0, *s, slen, LENGTH)) {
        DWORD err = GetLastError();
        LOG("    encryption error %x\n", err);
        free((void *)*s);
        throw CSPException("Key.encrypt: Encryption failed.", err);
    }
    LOG("    encrypted succesfully\n");
}
