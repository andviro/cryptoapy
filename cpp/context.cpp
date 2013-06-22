#include "common.hpp"
#include "context.hpp"

Crypt::~Crypt() throw(CSPException) {
    if (hprov) {
        bool res = CryptReleaseContext(hprov, 0);
        if (!res) {
            DWORD err = GetLastError();
            LOG("error ctx %x\n", err);
            throw CSPException("Couldn't release context", err);
        }
    }
    LOG("Free ctx %lu\n", hprov);
}

char *Crypt::name() {
    char *s;
    DWORD slen;
    if(!CryptGetProvParam( hprov, PP_CONTAINER, NULL, &slen, 0)) {
        throw CSPException("Couldn't determine container name length");
    }

    s=(char *)malloc((slen + 1)*sizeof(CHAR));

    if(!CryptGetProvParam( hprov, PP_CONTAINER, (BYTE *)s, &slen, 0)) {
        free(s);
        throw CSPException("Couldn't get container name");
    }
    return s;
}

Crypt *Context(char *container, DWORD type, DWORD flags, char *name) throw(CSPException)
{
    HCRYPTPROV hp;
    Crypt *res;

    /*printf("%x\n", flags);*/
    if (!CryptAcquireContext(&hp, container, name, type, flags)) {
        DWORD err = GetLastError();
        switch (err) {
        case NTE_KEYSET_NOT_DEF:
        case NTE_BAD_KEYSET_PARAM:
            return NULL;
        default:
            throw CSPException("Couldn't acquire context");
        }
    }
    if (flags & CRYPT_DELETEKEYSET) {
        res = NULL;
    } else {
        res = new Crypt(hp);
    }
    return res;
};
