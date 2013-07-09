#ifndef EXT_HPP_INCLUDED
#define EXT_HPP_INCLUDED
#include "common.hpp"
#include "except.hpp"
#include <vector>

class EncodedObject
{
private:
    LPVOID struct_info;
    LPCSTR struct_type;
protected:
    EncodedObject();
    void set_struct(LPVOID info, LPCSTR type);
    void encode(BYTE **s, DWORD *slen);
};

class CertInfo;
class CertExtension : protected EncodedObject
{
private:
    CERT_EXTENSION data;
    bool created;
    CertInfo *parent;
public:
    CertExtension(LPCSTR oid, bool critical=FALSE);
    CertExtension(CERT_EXTENSION *pext, CertInfo *p) throw(CSPException);
    virtual ~CertExtension();
    CERT_EXTENSION *get_data();
    //
    void oid(BYTE **s, DWORD *slen);

    friend class CertExtensions;
    friend class CertRequest;
};

class KeyUsage : public CertExtension
{
private:
    CRYPT_BIT_BLOB key_usage;
    BYTE ByteKeyUsage;
public:
    KeyUsage();
    virtual ~KeyUsage();
    void set_usage(BYTE attr);
    void reset_usage(BYTE attr);
};

class ExtKeyUsage : public CertExtension
{
private:
    CERT_ENHKEY_USAGE usage_data;
public:
    ExtKeyUsage();
    virtual ~ExtKeyUsage();
    void add_usage_oid(LPCSTR oid);
    friend class CertRequest;
};

class CertExtensions : protected EncodedObject
{
private:
    std::vector<CertExtension *> exts;
    CERT_EXTENSIONS cexts;
public:
    CertExtensions();
    virtual ~CertExtensions();
    void encode(BYTE **s, DWORD *slen);
    void add(CertExtension *e);
};
#endif //EXT_HPP_INCLUDED
