#ifndef REQUEST_HPP_INCLUDED
#define REQUEST_HPP_INCLUDED

#include "except.hpp"
#include "rcobj.hpp"

class Crypt;

class CertExtensions;
class ExtKeyUsage;
class KeyUsage;
class CertRequest
{
    DWORD            cbNameEncoded;
    BYTE*            pbNameEncoded;
    CERT_REQUEST_INFO   CertReqInfo;
    CRYPT_ALGORITHM_IDENTIFIER SigAlg;
    CERT_PUBLIC_KEY_INFO *pbPublicKeyInfo;
    DWORD cbPublicKeyInfo;
    Crypt *ctx;
    CRYPT_ATTR_BLOB attr_blobs[1];
    CRYPT_ATTRIBUTE ext_attr;
    CertExtensions *exts;
    ExtKeyUsage *eku;
    KeyUsage *ku;
    public:
        CertRequest(Crypt *ctx, BYTE *STRING=NULL, DWORD LENGTH=0) throw (CSPException);
        void set_name(BYTE *STRING, DWORD LENGTH) throw (CSPException);
        void get_data(BYTE **s, DWORD *slen) throw (CSPException);
        //void set_usage_bit(BYTE usage) throw (CSPException);
        ~CertRequest() throw (CSPException);
        void add_eku(LPCSTR oid) throw (CSPException);
};

#endif
