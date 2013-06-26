#ifndef CERT_HPP_INCLUDED
#define CERT_HPP_INCLUDED

#include "except.hpp"
#include "rcobj.hpp"

void test_input(BYTE* STRING, DWORD LENGTH, BYTE **s, DWORD *slen);

class CertStore;
class Crypt;
class CryptMsg;
class Cert
{
private:
    PCCERT_CONTEXT pcert;
    CertStore *parent;

    void init() {
        parent = NULL;
    }

    void decode_name_blob(PCERT_NAME_BLOB pNameBlob, BYTE **s, DWORD *slen);
public:
    Cert* duplicate() throw(CSPException);

    void remove_from_store() throw(CSPException);

    Cert(PCCERT_CONTEXT pc, CertStore *parent=NULL) throw(CSPException);

    Cert(BYTE* STRING, DWORD LENGTH) throw(CSPException);

    static Cert *self_sign(Crypt *ctx, BYTE *STRING, DWORD LENGTH)  throw(CSPException);

    static void request(Crypt *ctx, BYTE *STRING, DWORD LENGTH, BYTE **s, DWORD *slen, DWORD keyspec=AT_SIGNATURE) throw(CSPException);

    ~Cert() throw(CSPException);

    void extract(BYTE **s, DWORD *slen) throw(CSPException);

    void thumbprint(BYTE **s, DWORD *slen) throw(CSPException);

    char *sign_algorithm();

    void name(BYTE **s, DWORD *slen) throw(CSPException);

    void issuer(BYTE **s, DWORD *slen) throw(CSPException);

    friend class CryptMsg;
    friend class CertStore;
};

class CertIter
{
public:
    CertStore *parent;
    bool iter;
    PCCERT_CONTEXT pcert;

    CertIter(CertStore *p) throw (CSPException);

    CertIter *__iter__() {
        return this;
    }

    virtual ~CertIter() throw (CSPException);

    virtual Cert *next() throw (Stop_Iteration, CSPException);
};

class CertFind : public CertIter
{
public:
    CRYPT_HASH_BLOB chb;
    CRYPT_HASH_BLOB *param;
    DWORD enctype, findtype;

    CertFind(CertStore *p, DWORD et, DWORD ft, BYTE *STRING, DWORD LENGTH);

    virtual ~CertFind() throw (CSPException);

    CertFind(CertStore *p, DWORD et, BYTE *name);

    virtual Cert *next() throw (Stop_Iteration, CSPException);
};


class CertStore : public RCObj
{
private:
    Crypt *ctx;
    CryptMsg *msg;
    HCERTSTORE hstore;

    void init();
public:

    CertStore(CryptMsg *parent) throw(CSPException);

    CertStore() throw(CSPException);

    CertStore(Crypt *parent, LPCTSTR protocol) throw(CSPException);

    ~CertStore() throw(CSPException);

    CertIter *__iter__() throw(CSPException);

    CertFind *find_by_thumb(BYTE *STRING, DWORD LENGTH) throw(CSPException);

    CertFind *find_by_name(BYTE *STRING, DWORD LENGTH) throw(CSPException);

    Cert *get_cert_by_info(CERT_INFO *psi) throw(CSPException);

    Cert *add_cert(Cert *c) throw(CSPException);


    friend class CryptMsg;
    friend class CertIter;
    friend class CertFind;
};

#endif