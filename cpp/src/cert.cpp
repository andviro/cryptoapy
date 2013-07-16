#include "common.hpp"
#include "context.hpp"
#include "msg.hpp"
#include "cert.hpp"
#include "certinfo.hpp"

void CertStore::init()
{
    ctx = NULL;
    msg = NULL;
    hstore = 0;
    LOG("CertStore::init %p\n", this);
}

Cert* Cert::duplicate() throw(CSPException)
{
    LOG("Cert::duplicate %p\n", pcert);
    PCCERT_CONTEXT pc = CertDuplicateCertificateContext(pcert);
    LOG("    into %p\n", pc);
    return new Cert(pc, parent);
}


Cert::Cert(BYTE* STRING, DWORD LENGTH) throw(CSPException) : parent(NULL)
{
    LOG("Cert::Cert(str)\n");
    pcert = CertCreateCertificateContext(MY_ENC_TYPE, STRING, LENGTH);
    LOG("    created cert: %p\n", pcert);
    if (!pcert) {
        throw CSPException("Couldn't decode certificate blob");
    }
}

Cert *Cert::self_sign(Crypt *ctx, BYTE *STRING, DWORD LENGTH)  throw(CSPException)
{
    LOG("Cert::self_sign\n");
#ifdef UNIX
    throw CSPException("Self-signed certificates are not implemented on Unix", 1);
#else
    CERT_NAME_BLOB issuer;
    bool res;

    res = CertStrToName(
              MY_ENC_TYPE,
              (LPSTR)STRING,
              CERT_OID_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
              NULL,
              NULL,
              &issuer.cbData,
              NULL );

    if (!res) {
        throw CSPException("Couldn't determine encoded info size");
    }

    issuer.pbData = (BYTE*) malloc(issuer.cbData);

    res = CertStrToName(
              MY_ENC_TYPE,
              (LPSTR)STRING,
              CERT_OID_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
              NULL,
              issuer.pbData,
              &issuer.cbData,
              NULL );

    if (!res) {
        free(issuer.pbData);
        throw CSPException("Couldn't encode cert info");
    }

    CRYPT_ALGORITHM_IDENTIFIER algid;
    DWORD hasi = sizeof(algid);
    memset(&algid, 0, hasi);
    algid.pszObjId = (char *)szOID_CP_GOST_R3411;

    PCCERT_CONTEXT pc = CertCreateSelfSignCertificate(ctx->hprov,
                        &issuer,
                        0,
                        NULL,
                        &algid,
                        NULL,
                        NULL,
                        NULL);

    if (!pc) {
        free(issuer.pbData);
        throw CSPException("Couldn't acquire self-signed certificate");
    }

    free(issuer.pbData);
    return new Cert(pc);
#endif
}

void Cert::extract(BYTE **s, DWORD *slen) throw(CSPException)
{
    LOG("Cert::extract\n");
    *slen = pcert->cbCertEncoded;
    *s = (BYTE *)malloc(*slen);
    memcpy(*s, pcert->pbCertEncoded, *slen);
}

void Cert::thumbprint(BYTE **s, DWORD *slen) throw(CSPException)
{
    LOG("Cert::thumbprint\n");
    if(!CertGetCertificateContextProperty(pcert, CERT_HASH_PROP_ID, NULL, slen)) {
        LOG("    Error: %p\n", pcert);
        throw CSPException("Couldn't get certificate hash size");
    }
    *s = (BYTE *)malloc(*slen);
    if(!CertGetCertificateContextProperty(pcert, CERT_HASH_PROP_ID, (void *)*s, slen)) {
        free((void *)*s);
        throw CSPException("Couldn't get certificate thumbprint");
    }
}
CertFind::CertFind(CertStore *p, DWORD et, DWORD ft, BYTE *STRING, DWORD LENGTH) : CertIter(p)
{
    LOG("CertFind::CertFind(%p, %u, %u, %u)\n", p, et, ft, LENGTH);
    enctype = et;
    findtype = ft;
    chb.pbData = (BYTE *)malloc(LENGTH);
    memcpy(chb.pbData, STRING, LENGTH);
    chb.cbData = LENGTH;
    param = &chb;
}


CertFind::CertFind(CertStore *p, DWORD et, BYTE *name) : CertIter(p)
{
    LOG("CertFind::CertFind(%p, %u, %s)\n", p, et, name);
    enctype = et;
    findtype = CERT_FIND_SUBJECT_STR;
    param = (CRYPT_HASH_BLOB *)strdup((const char *)name);
}

CertStore::CertStore() throw(CSPException)
{
    LOG("CertStore::CertStore()\n");
    init();
    hstore = CertOpenStore(CERT_STORE_PROV_MEMORY, MY_ENC_TYPE, 0, CERT_STORE_CREATE_NEW_FLAG,NULL);
    if (!hstore) {
        throw CSPException("Couldn't create memory store");
    }
}

CertStore::CertStore(Crypt *parent, LPCTSTR protocol) throw(CSPException)
{
    LOG("CertStore::CertStore(%p, %s)\n", parent, protocol);
    HCRYPTPROV hprov = 0;
    init();
    if (parent) {
        ctx = parent;
        ctx->ref();
        hprov = ctx->hprov;
    }
    hstore = CertOpenStore(
                 CERT_STORE_PROV_SYSTEM_A,          // The store provider type
                 0,                               // The encoding type is
                                                    // not needed
                 hprov,                            // Use the default HCRYPTPROV
                                                    // Set the store location in a
                                                    // registry location
                 CERT_STORE_NO_CRYPT_RELEASE_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
                 protocol                            // The store name as a Unicode
                                                    // string
             );
    if (!hstore) {
        throw CSPException("Couldn't open certificate store");
    }
}

Cert *CertStore::get_cert_by_info(CertInfo *ci) throw(CSPException, CSPNotFound)
{
    PCCERT_CONTEXT res;
    LOG("CertStore::get_cert_by_info(%p)\n", ci);
    if (!ci) {
        throw CSPNotFound("NULL cert info", -1);
    }
    res = CertGetSubjectCertificateFromStore(hstore, MY_ENC_TYPE, ci->psi);
    if (!res) {
        DWORD err = GetLastError();
        if (err == (DWORD)CRYPT_E_NOT_FOUND) {
            throw CSPNotFound("Subject cert not found", err);
        }
        throw CSPException("Error getting subject certificate from store", err);
    }
    return new Cert(res, this);
}

Cert *CertStore::add_cert(Cert *c) throw(CSPException)
{
    LOG("CertStore::add_cert(%p)\n", c->pcert);
    PCCERT_CONTEXT copy;
    if (c && !CertAddCertificateContextToStore(hstore, c->pcert,
            CERT_STORE_ADD_REPLACE_EXISTING, &copy)) {
        DWORD err = GetLastError();
        switch (err) {
            case CRYPT_E_EXISTS:
                throw CSPException("Matching or newer cerificate already exist in store", err);
            default:
                throw CSPException("Couldn't add cert to store");
        }
    }
    return new Cert(copy, this);
}

CertIter *CertStore::__iter__() throw(CSPException)
{
    return new CertIter(this);
}

CertFind *CertStore::find_by_thumb(BYTE *STRING, DWORD LENGTH) throw(CSPException)
{
    return new CertFind(this, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, CERT_FIND_HASH, STRING, LENGTH);
}

CertFind *CertStore::find_by_name(BYTE *STRING, DWORD LENGTH) throw(CSPException)
{
    return new CertFind(this, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, STRING);
}

CertIter::CertIter(CertStore *p) throw (CSPException) : parent(p)
{
    LOG("CertIter::CertIter(%p)\n", p);
    if (parent) {
        parent->ref();
    }
    iter = true;
    pcert = NULL;
}

CertIter::~CertIter() throw (CSPException)
{
    LOG("CertIter::~CertIter()\n");
    if (parent) {
        parent->unref();
    }
}

CertFind::~CertFind() throw (CSPException)
{
    LOG("CertFind::~CertFind()\n");
    if (findtype == CERT_FIND_SUBJECT_STR) {
        if (param) {
            free(param);
        }
    } else {
        if (chb.pbData) {
            free(chb.pbData);
        }
    }
}


Cert *CertIter::next() throw (Stop_Iteration, CSPException)
{
    LOG("CertIter::next()\n");
    if (!iter) {
        LOG("    Stop iter\n");
        throw Stop_Iteration();
    }
    pcert = CertEnumCertificatesInStore(parent->hstore, pcert);
    LOG("    Found next cert %p\n", pcert);
    if (pcert) {
        PCCERT_CONTEXT pc = CertDuplicateCertificateContext(pcert);
        LOG("    Duplicated cert into %p\n", pc);
        LOG("    parent: %p\n", parent);
        return new Cert(pc, parent);
    } else {
        iter = false;
        LOG("    Stop iter\n");
        throw Stop_Iteration();
    }
}

Cert *CertFind::next() throw (Stop_Iteration, CSPException)
{
    LOG("CertFind::next(%x, %p)\n", findtype, param);
    if (!iter) {
        LOG("    Stopped find\n");
        throw Stop_Iteration();
    }
    pcert = CertFindCertificateInStore(parent->hstore, enctype, 0, findtype, param, pcert);
    LOG("    Found next cert %p\n", pcert);
    if (pcert) {
        return new Cert(CertDuplicateCertificateContext(pcert), parent);
    } else {
        iter = false;
        LOG("    Stopped find\n");
        throw Stop_Iteration();
    }
}

Cert::Cert(PCCERT_CONTEXT pc, CertStore *parent) throw(CSPException) : parent(parent)
{
    LOG("Cert::Cert(%p, %p)\n", pc, parent);
    if (!pc) {
        throw CSPException("Invalid certificate context");
    }
    if (parent) {
        parent->ref();
    }
    pcert = pc;
}

Cert::~Cert() throw(CSPException)
{
    LOG("Cert::~Cert(%p)\n", pcert);
    if (pcert && !CertFreeCertificateContext(pcert)) {
        throw CSPException("Couldn't free certificate context");
    }
    if (parent) {
        parent->unref();
    }
    LOG("Deleted cert: %p\n", pcert);
}

void Cert::remove_from_store() throw(CSPException)
{
    LOG("Cert::remove_from_store(): cert=%p parent=%p\n", pcert, parent);
    PCCERT_CONTEXT pc = CertDuplicateCertificateContext(pcert);
    if (!pc) {
        throw CSPException("Couldn't duplicate cert context");
    }
    if(!CertDeleteCertificateFromStore(pc)) {
        throw CSPException("Couldn't remove certificate");
    }
    //if (parent) {
    //parent->unref();
    //parent = NULL;
    //}
}

CertStore::CertStore(CryptMsg *parent) throw(CSPException)
{
    LOG("CertStore::CertStore(%p)\n", parent);
    init();
    msg = parent;
    if (!msg) {
        DWORD err = GetLastError();
        LOG("Error init message store, %x\n",err);
        throw CSPException("Invalid message for cert store", err);
    }
    msg->ref();
    hstore = CertOpenStore(CERT_STORE_PROV_MSG, MY_ENC_TYPE, 0, 0, msg->get_handle());
    if (!hstore) {
        throw CSPException("Couldn't open message certificate store");
    }
}

CertStore::~CertStore() throw(CSPException)
{
    LOG("CertStore::~CertStore(%p)\n", this);
    if (hstore) {
        if (!CertCloseStore(hstore, CERT_CLOSE_STORE_CHECK_FLAG)) {
            DWORD err = GetLastError();
            LOG("Error freeing store: %x\n", err);
            throw CSPException("Couldn't properly close certificate store", err);
        }
    }
    if (msg) {
        msg->unref();
    }
    if (ctx) {
        ctx->unref();
    }
    LOG("Deleted store %p\n", this);
}

void Cert::bind(Crypt *ctx, DWORD keyspec) {
    CRYPT_KEY_PROV_INFO ckpi;
    wchar_t w_ctx_name[1000];
    wchar_t w_prov_name[1000];
    ZeroMemory(&ckpi, sizeof(ckpi));
    ckpi.pwszContainerName = w_ctx_name;
    ckpi.pwszProvName = w_prov_name;

    char *ctx_name, *prov_name;

    ctx_name = ctx->uniq_name();
    mbstowcs(ckpi.pwszContainerName, ctx_name, 1000);
    try {
        prov_name = ctx->prov_name();
    } catch (...) {
        free(ctx_name);
        throw;
    }
    mbstowcs(ckpi.pwszProvName, prov_name, 1000);
    ckpi.dwProvType = ctx->prov_type();
    ckpi.dwFlags = CERT_SET_KEY_PROV_HANDLE_PROP_ID;
    ckpi.dwKeySpec = keyspec;

    if (!CertSetCertificateContextProperty(pcert, CERT_KEY_PROV_INFO_PROP_ID, 0, &ckpi)) {
        DWORD err = GetLastError();
        throw CSPException("Couldn't set certificate context property", err);
    }
    delete[] prov_name;
    delete[] ctx_name;
}

EKUIter *Cert::eku() throw(CSPException) {
   EKUIter *res = new EKUIter(this);
   if (!CertGetEnhancedKeyUsage(pcert, 0, NULL, &res->cbsize)) {
       res->pekus = NULL;
       res->cbsize = 0;
       return res;
   }

   res->pekus = (CERT_ENHKEY_USAGE *)malloc(res->cbsize);

   if (!CertGetEnhancedKeyUsage(pcert, 0, res->pekus, &res->cbsize)) {
       free(res->pekus);
       res->pekus= NULL;
       res->cbsize = 0;
   }
   return res;
}


EKUIter::EKUIter (Cert *c)
    :parent(c)
{
    if (parent)
        parent -> ref();

    pekus = NULL;
    i = 0;
    cbsize = 0;
}

void EKUIter::next (BYTE **s, DWORD *slen) throw (CSPException, Stop_Iteration)
{
    LOG("EKUIter::next()\n");
    if (!pekus || i >= pekus->cUsageIdentifier) {
        LOG("    Stop iter\n");
        throw Stop_Iteration();
    }
    *s = (BYTE *)strdup((char *)pekus->rgpszUsageIdentifier[i]);
    *slen = strlen((char *)*s);
    i ++;
}


EKUIter::~EKUIter ()
{
    if (pekus) {
        free(pekus);
    }
    if (parent)
        parent -> unref();
}
