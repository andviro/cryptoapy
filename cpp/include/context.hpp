#ifndef CONTEXT_HPP_INCLUDED
#define CONTEXT_HPP_INCLUDED

#include "rcobj.hpp"
#include "except.hpp"

class Key;

class Crypt : public RCObj
{
    HCRYPTPROV hprov;

    Crypt(HCRYPTPROV hp) throw(CSPException) {
        hprov = hp;
        LOG("Crypt::Crypt(): %p (%lx)\n", this, hprov);
    };
public:

    ~Crypt() throw(CSPException);

    char *name();
    char *uniq_name();
    char *prov_name();
    DWORD prov_type();

    Key *create_key(DWORD flags, DWORD keyspec=AT_SIGNATURE) throw(CSPException);

    Key *get_key(DWORD keyspec=AT_SIGNATURE) throw(CSPException, CSPNotFound);

    Key *import_key(BYTE *STRING, DWORD LENGTH, Key *decrypt=NULL) throw(CSPException);

    friend class Cert;
    friend class CryptMsg;
    friend class CertStore;
    friend class CertRequest;
    friend Crypt *Context(char *, DWORD , DWORD, char*) throw (CSPException, CSPNotFound);
};

Crypt *Context(char *container, DWORD type, DWORD flags, char *name=NULL) throw(CSPException, CSPNotFound);

#endif
