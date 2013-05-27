/* vim: ft=swig
*/

%inline %{
class Key {
    HCRYPTKEY hkey;
    Crypt *parent;
public:
    Key(Crypt *pctx, HCRYPTKEY hk) throw(CSPException) {
        parent = pctx;
        parent->ref();
        hkey = hk;
        LOG("new key\n");
    };
    ~Key() throw(CSPException) {
        LOG("release key\n");
        if (hkey) {
            bool res = CryptDestroyKey(hkey);
            if (!res) {
                throw CSPException("Couldn't destroy key");
            }
        }
        parent->unref();
    };

    void encode(BYTE **s, DWORD *slen, Key *cryptkey=NULL) throw(CSPException) {
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

    friend class Crypt;
};

%}

%{
Key *Crypt::get_key(DWORD keyspec) throw(CSPException) {
    HCRYPTKEY hkey = 0;
    if(!CryptGetUserKey(hprov, keyspec, &hkey)) { 
        if (GetLastError() == (DWORD) NTE_NO_KEY) {
            return NULL;
        } else {
            throw CSPException("Couldn't acquire user pub key");
        }
    }
    return new Key(this, hkey);
}

Key *Crypt::create_key(DWORD flags, DWORD keyspec) throw(CSPException) {
    HCRYPTKEY hkey = 0;
    if(!CryptGenKey(hprov, keyspec, flags, &hkey)) { 
        throw CSPException("Couldn't create key pair");
    }
    return new Key(this, hkey);
}

Key *Crypt::import_key(BYTE *STRING, DWORD LENGTH, Key *decrypt) throw(CSPException) {
    HCRYPTKEY hkey = 0;
    HCRYPTKEY decrkey = decrypt? decrypt->hkey : 0;

    if(!CryptImportKey(hprov, STRING, LENGTH, decrkey, 0, &hkey)) {
        throw CSPException("Couldn't import public key blob");
    }
    return new Key(this, hkey);
}
%}
