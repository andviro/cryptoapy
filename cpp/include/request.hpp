#ifndef REQUEST_HPP_INCLUDED
#define REQUEST_HPP_INCLUDED

#include "except.hpp"

class Crypt;

class CertRequest
{
    DWORD            cbNameEncoded;
    BYTE*            pbNameEncoded;
    CERT_REQUEST_INFO   CertReqInfo;
    CRYPT_ALGORITHM_IDENTIFIER SigAlg;
    CERT_PUBLIC_KEY_INFO *pbPublicKeyInfo;
    DWORD cbPublicKeyInfo;
    Crypt *ctx;
    CERT_ENHKEY_USAGE CertEnhKeyUsage;
    public:
        CertRequest(Crypt *ctx, BYTE *STRING=NULL, DWORD LENGTH=0) throw (CSPException);
        void set_name(BYTE *STRING, DWORD LENGTH) throw (CSPException);
        void get_data(BYTE **s, DWORD *slen) throw (CSPException);
        void set_usage(bool auth=true, bool sign=true, bool encrypt=true) throw (CSPException);
        ~CertRequest() throw (CSPException);
};
#endif
