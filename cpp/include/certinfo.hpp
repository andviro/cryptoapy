#ifndef CERTINFO_HPP_INCLUDED
#define CERTINFO_HPP_INCLUDED

#include "common.hpp"
#include "cert.hpp"
#include "msg.hpp"

class Cert;
class CertStore;
class CryptMsg;
class CertInfo
{
public:
    CertInfo (Cert  *c) throw(CSPException);
    CertInfo(CryptMsg *m, DWORD idx) throw (CSPException);
    virtual ~CertInfo () throw(CSPException);

    DWORD version();
    void issuer(BYTE **s, DWORD *slen) throw(CSPException);
    void name(BYTE **s, DWORD *slen) throw(CSPException);
    char *sign_algorithm();
    void serial(BYTE **s, DWORD *slen) throw(CSPException);


private:
    void decode_name_blob(PCERT_NAME_BLOB pNameBlob, BYTE **s, DWORD *slen);
    void init();
    CERT_INFO *psi;
    Cert *cert;
    CryptMsg *msg;

    friend class CertStore;
};


#endif
