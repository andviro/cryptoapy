#include "common.hpp"
#include "context.hpp"
#include "key.hpp"

Crypt::~Crypt() throw(CSPException) {
    LOG("Crypt::~Crypt(%p)\n", this);
    if (hprov) {
        bool res = CryptReleaseContext(hprov, 0);
        if (!res) {
            DWORD err = GetLastError();
            LOG("Crypt::~Crypt(%p): error %x\n", this, err);
            throw CSPException("Couldn't release context", err);
        }
    }
    LOG("    Freed ctx %p (%x)\n", this, hprov);
}

DWORD Crypt::prov_type() {
    DWORD slen, type;
    if(!CryptGetProvParam( hprov, PP_PROVTYPE, NULL, &slen, 0)) {
        throw CSPException("Couldn't determine provider type data length");
    }

    if(slen != sizeof(DWORD)) {
        throw CSPException("Wrong size for binary data", -1);
    }

    if(!CryptGetProvParam( hprov, PP_PROVTYPE, (BYTE *)&type, &slen, 0)) {
        throw CSPException("Couldn't get provider type");
    }
    return type;
}

char *Crypt::prov_name() {
    char *s;
    DWORD slen;
    if(!CryptGetProvParam( hprov, PP_NAME, NULL, &slen, 0)) {
        throw CSPException("Couldn't determine provider name length");
    }

    s=new char[slen + 1];

    if(!CryptGetProvParam( hprov, PP_NAME, (BYTE *)s, &slen, 0)) {
        delete[] s;
        throw CSPException("Couldn't get provider name");
    }
    return s;
}

char *Crypt::name() {
    char *s;
    DWORD slen;
    if(!CryptGetProvParam( hprov, PP_CONTAINER, NULL, &slen, 0)) {
        throw CSPException("Couldn't determine container name length");
    }

    s=new char[slen + 1];

    if(!CryptGetProvParam( hprov, PP_CONTAINER, (BYTE *)s, &slen, 0)) {
        delete[] s;
        throw CSPException("Couldn't get container name");
    }
    return s;
}

char *Crypt::uniq_name() {
    char *s;
    DWORD slen;
    if(!CryptGetProvParam( hprov, PP_UNIQUE_CONTAINER, NULL, &slen, 0)) {
        throw CSPException("Couldn't determine container unique name length");
    }

    s=new char[slen + 1];

    if(!CryptGetProvParam( hprov, PP_UNIQUE_CONTAINER, (BYTE *)s, &slen, 0)) {
        delete[] s;
        throw CSPException("Couldn't get container unique name");
    }
    return s;
}

Crypt *Context(char *container, DWORD type, DWORD flags, char *name) throw(CSPException, CSPNotFound)
{
    HCRYPTPROV hp;
    Crypt *res;

    LOG("Context(%s, %u, %x, %s)\n", container, type, flags, name);
    /*printf("%x\n", flags);*/
    if (!CryptAcquireContext(&hp, container, name, type, flags)) {
        DWORD err = GetLastError();
        switch (err) {
        case NTE_KEYSET_NOT_DEF:
            throw CSPNotFound("Keyset not defined", err);
        case NTE_BAD_KEYSET_PARAM:
            throw CSPNotFound("Bad keyset parameters or container not found", err);
        default:
            throw CSPException("Couldn't acquire context", err);
        }
    }
    if (flags & CRYPT_DELETEKEYSET) {
        res = NULL;
    } else {
        res = new Crypt(hp);
    }
    return res;
};

Key *Crypt::get_key(DWORD keyspec) throw(CSPException)
{
    HCRYPTKEY hkey = 0;
    if(!CryptGetUserKey(hprov, keyspec, &hkey)) {
        DWORD err = GetLastError();
        if (err == NTE_NO_KEY) {
            throw CSPNotFound("Key not found", err);
        } else {
            throw CSPException("Couldn't acquire user pub key", err);
        }
    }
    return new Key(this, hkey);
}

Key *Crypt::create_key(DWORD flags, DWORD keyspec) throw(CSPException)
{
    HCRYPTKEY hkey = 0;
    if(!CryptGenKey(hprov, keyspec, flags, &hkey)) {
        throw CSPException("Couldn't create key pair");
    }
    return new Key(this, hkey);
}

Key *Crypt::import_key(BYTE *STRING, DWORD LENGTH, Key *decrypt) throw(CSPException)
{
    HCRYPTKEY hkey = 0;
    HCRYPTKEY decrkey = decrypt? decrypt->hkey : 0;

    if(!CryptImportKey(hprov, STRING, LENGTH, decrkey, 0, &hkey)) {
        throw CSPException("Couldn't import public key blob");
    }
    return new Key(this, hkey);
}
