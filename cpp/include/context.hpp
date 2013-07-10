#ifndef CONTEXT_HPP_INCLUDED
#define CONTEXT_HPP_INCLUDED

#include "rcobj.hpp"
#include "except.hpp"

class Key;

class Crypt : public RCObj
{
    HCRYPTPROV hprov;
    char *cont_name;
    char *pr_name;

public:

    Crypt (char *container, DWORD type, DWORD flags, char *name=NULL) throw(CSPException, CSPNotFound);
    ~Crypt() throw(CSPException);

    char *name();
    char *uniq_name();
    char *prov_name();
    DWORD prov_type();

    Key *create_key(DWORD flags, DWORD keyspec=AT_SIGNATURE) throw(CSPException);

    Key *get_key(DWORD keyspec=AT_SIGNATURE) throw(CSPException, CSPNotFound);

    Key *import_key(BYTE *STRING, DWORD LENGTH, Key *decrypt=NULL) throw(CSPException);

    void set_password(BYTE *STRING, DWORD LENGTH, DWORD keyspec=AT_SIGNATURE) throw(CSPException);

    static void remove(char *container, DWORD type, char *name) throw(CSPException, CSPNotFound);

    friend class Cert;
    friend class CryptMsg;
    friend class Signature;
    friend class CertStore;
    friend class CertRequest;
};


#endif
