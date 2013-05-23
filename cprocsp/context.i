/* vim: ft=swig
*/
%feature("ref") Crypt "if ($this) $this->ref();"
%feature("unref") Crypt "if ($this) $this->unref();"
%newobject Crypt::get_sign_key;
%newobject Crypt::import_key;
%newobject Context;

%inline %{
class Key;

class Crypt : public RCObj {
    HCRYPTPROV hprov;

    Crypt(HCRYPTPROV hp) throw(CSPException) {
        hprov = hp;
        printf("New ctx %x\n", hprov);
    };
public:

    ~Crypt() throw(CSPException) {
        printf("Free ctx %x\n", hprov);
        if (hprov) {
            bool res = CryptReleaseContext(hprov, 0);
            if (!res) {
                throw CSPException("Couldn't release context");
            }
        }
    };

    char *name() {
        char *s;
        DWORD slen;
        if(!CryptGetProvParam( hprov, PP_CONTAINER, NULL, &slen, 0)) 
        {
            throw CSPException("Couldn't determine container name length");
        } 
        
        s=(char *)malloc((slen + 1)*sizeof(CHAR));
        
        if(!CryptGetProvParam( hprov, PP_CONTAINER, (BYTE *)s, &slen, 0)) 
        {
            free(s);
            throw CSPException("Couldn't get container name");
        } 
        return s;
    }

    Key *create_key(DWORD flags, DWORD keyspec=AT_SIGNATURE) throw(CSPException);
    Key *get_key(DWORD keyspec=AT_SIGNATURE) throw(CSPException);
    Key *import_key(char *STRING, size_t LENGTH, Key *decrypt=NULL) throw(CSPException);
    friend class CryptMsg;
    friend class CertStore;
    friend Crypt *Context(LPCSTR ,DWORD , DWORD) throw (CSPException);
};

%}

%{
Crypt *Context(LPCSTR container, DWORD type, DWORD flags) throw(CSPException) {
    HCRYPTPROV hp;
    Crypt *res;

    if (!CryptAcquireContext(&hp, container, NULL, type, flags)) {
        switch (GetLastError()) {
            case NTE_BAD_KEYSET_PARAM: return NULL;
            default: throw CSPException("Couldn't acquire context");
        }
    }
    res = new Crypt(hp);
    return res;
};

%}
