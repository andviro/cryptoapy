/* vim: ft=swig
*/
%feature("python:slot", "tp_str", functype="reprfunc") Key::to_string;

%inline %{
class Key {
    HCRYPTKEY hkey;
    Crypt *parent;
public:
    Key(Crypt *pctx, HCRYPTKEY hk) throw(CSPException) {
        parent = pctx;
        parent->ref();
        hkey = hk;
        /*puts("release key");*/
    };
    ~Key() throw(CSPException) {
        /*puts("release key");*/
        if (hkey) {
            /*printf("Free ctx %x\n", hprov);*/
            bool res = CryptDestroyKey(hkey);
            if (!res) {
                throw CSPException("Couldn't destroy key");
            }
        }
        parent->unref();
    };

    void to_string(char **s, DWORD *slen) throw(CSPException) {
        encode_key(s, slen, NULL);
    }

    void encode_key(char **s, DWORD *slen, Key *cryptkey=NULL) throw(CSPException) {
        HCRYPTKEY expkey;
        DWORD blobtype;
        if (cryptkey) {
            expkey = cryptkey -> hkey;
            blobtype = PRIVATEKEYBLOB;
        } else {
            expkey = 0;
            blobtype = PUBLICKEYBLOB;
        }
        
        if(!CryptExportKey( hkey, expkey, blobtype, 0, NULL, slen)) {
            throw CSPException("Error computing key blob length");
        }

        *s = (char *)malloc(*slen);

        if(!CryptExportKey( hkey, expkey, blobtype, 0, (BYTE *)*s, slen)) {
            throw CSPException("Error exporting key blob");
        }
    };

    friend class Crypt;
};

%}

%{
Key *Crypt::get_sign_key() throw(CSPException) {
    HCRYPTKEY hkey = 0;
    if(!CryptGetUserKey(hprov, AT_SIGNATURE, &hkey)) { 
        throw CSPException("Couldn't acquire user pub key");
    }
    return new Key(this, hkey);
}

Key *Crypt::import_key(char *STRING, size_t LENGTH, Key *decrypt) throw(CSPException) {
    HCRYPTKEY hkey = 0;
    HCRYPTKEY decrkey = decrypt? decrypt->hkey : 0;

    if(!CryptImportKey(hprov, (BYTE *)STRING, LENGTH, decrkey, 0, &hkey)) {
        throw CSPException("Couldn't import public key blob");
    }
    return new Key(this, hkey);
}
%}
