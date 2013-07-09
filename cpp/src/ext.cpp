#include "ext.hpp"
#include "certinfo.hpp"

EncodedObject::EncodedObject()
{
    struct_info = NULL;
    struct_type = NULL;
}

void EncodedObject::set_struct(LPVOID info, LPCSTR type)
{
    LOG("EncodedObject::set_struct(%p, %x)\n", info, type );
    struct_info = info;
    struct_type = type;
}

void EncodedObject::encode(BYTE **s, DWORD *slen)
{
    LOG("EncodedObject::encode()\n");
    if (!CryptEncodeObject(MY_ENC_TYPE,
                           struct_type,
                           struct_info,
                           NULL,
                           slen)) {
        throw(CSPException("Couldn't determine encoded object size"));
    }

    *s = (LPBYTE)malloc(*slen);

    if(!CryptEncodeObject(MY_ENC_TYPE,
                          struct_type,
                          (LPVOID)struct_info,
                          *s,
                          slen)) {
        throw(CSPException("Couldn't encode object"));
    }
}

CertExtension::CertExtension(LPCSTR oid, bool critical)
    :parent(NULL)
{
    LOG("CertExtension::CertExtension(%s, %i)\n", oid, critical);
    ZeroMemory(&data, sizeof(data));
    data.pszObjId = (LPSTR)oid;
    data.fCritical = critical;
    created = TRUE;
}

CertExtension::CertExtension(CERT_EXTENSION *pext, CertInfo *p) throw(CSPException)
    : parent(p)
{
    LOG("CertExtension::CertExtension(%p)\n", pext);
    if (parent)
        parent->ref();
    memcpy(&data, pext, sizeof(CERT_EXTENSION));
    created = FALSE;
}

CertExtension::~CertExtension()
{
    LOG("CertExtension::~CertExtension(%p)\n", this);
    if (created && data.Value.pbData) {
        free(data.Value.pbData);
        data.Value.pbData = NULL;
    }
    if (parent)
        parent->unref();
}


CERT_EXTENSION *CertExtension::get_data()
{
    LOG("CertExtension::get_data()\n");
    if (data.Value.pbData) {
        free(data.Value.pbData);
        data.Value.pbData = NULL;
    }
    encode(&data.Value.pbData, &data.Value.cbData);
    return &data;
}

void CertExtension::oid(BYTE **s, DWORD *slen) {
    LOG("CertExtension::oid() = %p\n", data.pszObjId);
    *slen = strlen(data.pszObjId);
    *s = (BYTE *)strdup(data.pszObjId);
}

KeyUsage::KeyUsage() : CertExtension(szOID_KEY_USAGE, TRUE)
{
    ZeroMemory(&key_usage, sizeof(key_usage));
    ByteKeyUsage = 0x0;
    key_usage.cbData=1;
    key_usage.pbData=&ByteKeyUsage;
    set_struct((void *)&key_usage, X509_KEY_USAGE);
}

KeyUsage::~KeyUsage()
{
}

void KeyUsage::set_usage(BYTE attr)
{
    ByteKeyUsage |= attr;
}

void KeyUsage::reset_usage(BYTE attr)
{
    ByteKeyUsage &= ~attr;
}

ExtKeyUsage::ExtKeyUsage() : CertExtension(szOID_ENHANCED_KEY_USAGE, FALSE)
{
    ZeroMemory(&usage_data, sizeof(usage_data));
    set_struct(&usage_data, X509_ENHANCED_KEY_USAGE);
}

ExtKeyUsage::~ExtKeyUsage()
{
    if (usage_data.rgpszUsageIdentifier) {
        free(usage_data.rgpszUsageIdentifier);
        usage_data.rgpszUsageIdentifier = NULL;
    }
}

void ExtKeyUsage::add_usage_oid(LPCSTR oid)
{
    LOG("ExtKeyUsage::add_usage_oid(%s)\n", oid);
    if (oid) {
        usage_data.rgpszUsageIdentifier = (LPSTR*)realloc(usage_data.rgpszUsageIdentifier,
                                          sizeof(LPSTR)*(usage_data.cUsageIdentifier + 1));
        usage_data.rgpszUsageIdentifier[usage_data.cUsageIdentifier] = (LPSTR)oid;
        usage_data.cUsageIdentifier++;
    }
}

CertExtensions::CertExtensions()
{
    LOG("CertExtensions::CertExtensions()\n");
    ZeroMemory(&cexts, sizeof(cexts));
    set_struct(&cexts, X509_EXTENSIONS);
}

CertExtensions::~CertExtensions()
{
}

void CertExtensions::encode(BYTE **s, DWORD *slen)
{
    LOG("CertExtensions::encode()\n");
    cexts.cExtension = exts.size();
    cexts.rgExtension = new CERT_EXTENSION[cexts.cExtension];
    try {
        std::vector<CertExtension *>::const_iterator cii;
        int idx = 0;
        for(cii=exts.begin(); cii!=exts.end(); cii++) {
            memcpy(&cexts.rgExtension[idx], (*cii)->get_data(), sizeof(CERT_EXTENSION));
            idx ++;
        }
        EncodedObject::encode(s, slen);
    } catch (...) {
        delete[] cexts.rgExtension;
        throw;
    }
    delete[] cexts.rgExtension;
}

void CertExtensions::add(CertExtension *e)
{
    LOG("CertExtensions::add(%p)\n", e);
    if (e) {
        exts.push_back(e);
    }
}
