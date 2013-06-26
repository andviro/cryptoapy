#include "common.hpp"
#include "context.hpp"
#include "msg.hpp"
#include "cert.hpp"

void test_input(BYTE* STRING, DWORD LENGTH, BYTE **s, DWORD *slen)
{
    printf("<%s>, %lu\n", STRING, LENGTH);
    *s = STRING;
    *slen = LENGTH;
}

void CertStore::init()
{
    ctx = NULL;
    msg = NULL;
    hstore = 0;
    LOG("CertStore::init %p\n", this);
}

void Cert::decode_name_blob(PCERT_NAME_BLOB pNameBlob, BYTE **s, DWORD *slen)
{
    DWORD flags = CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG;
    LOG("Cert::decode_name_blob %p\n", pNameBlob);

    *slen = CertNameToStr( X509_ASN_ENCODING, pNameBlob, flags, NULL, 0);
    if (*slen <= 1) {
        throw CSPException("Wrong size for blob decoded data");
    }

    *s = (BYTE *)malloc(*slen);

    *slen = CertNameToStr(X509_ASN_ENCODING, pNameBlob, flags, (char *)*s, *slen);

    if (*slen <= 1) {
        free(*s);
        throw CSPException("Couldn't decode cert blob");
    }
    (*slen)--;
}

Cert* Cert::duplicate() throw(CSPException)
{
    LOG("Cert::duplicate %p\n", pcert);
    PCCERT_CONTEXT pc = CertDuplicateCertificateContext(pcert);
    LOG("    into %p\n", pc);
    return new Cert(pc, parent);
};


Cert::Cert(BYTE* STRING, DWORD LENGTH) throw(CSPException) : parent(NULL)
{
    LOG("Cert::Cert(str)\n");
    pcert = CertCreateCertificateContext(MY_ENC_TYPE, STRING, LENGTH);
    LOG("    created cert: %p\n", pcert);
    if (!pcert) {
        throw CSPException("Couldn't decode certificate blob");
    }
};

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
};

char *Cert::sign_algorithm()
{
    LOG("Cert::sign_algorithm\n");
    return pcert->pCertInfo->SignatureAlgorithm.pszObjId;
}

void Cert::name(BYTE **s, DWORD *slen) throw(CSPException)
{
    LOG("Cert::name()\n");
    decode_name_blob(&pcert->pCertInfo->Subject, s, slen);
};

void Cert::issuer(BYTE **s, DWORD *slen) throw(CSPException)
{
    LOG("Cert::issuer()\n");
    decode_name_blob(&pcert->pCertInfo->Issuer, s, slen);
};

CertFind::CertFind(CertStore *p, DWORD et, DWORD ft, BYTE *STRING, DWORD LENGTH) : CertIter(p)
{
    LOG("CertFind::CertFind(%p, %u, %u, %u)\n", p, et, ft, LENGTH);
    enctype = et;
    findtype = ft;
    chb.pbData = (BYTE *)malloc(LENGTH);
    memcpy(chb.pbData, STRING, LENGTH);
    chb.cbData = LENGTH;
    param = &chb;
};


CertFind::CertFind(CertStore *p, DWORD et, BYTE *name) : CertIter(p)
{
    LOG("CertFind::CertFind(%p, %u, %s)\n", p, et, name);
    enctype = et;
    findtype = CERT_FIND_SUBJECT_STR;
    param = (CRYPT_HASH_BLOB *)strdup((const char *)name);
};

CertStore::CertStore() throw(CSPException)
{
    LOG("CertStore::CertStore()\n");
    init();
    hstore = CertOpenStore(CERT_STORE_PROV_MEMORY, MY_ENC_TYPE, 0, CERT_STORE_CREATE_NEW_FLAG,NULL);
    if (!hstore) {
        throw CSPException("Couldn't create memory store");
    }
};

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
};

Cert *CertStore::get_cert_by_info(CERT_INFO *psi) throw(CSPException)
{
    PCCERT_CONTEXT res;
    LOG("CertStore::get_cert_by_info(%p)\n", psi);
    res = CertGetSubjectCertificateFromStore(hstore, MY_ENC_TYPE, psi);
    if (!res) {
        DWORD err = GetLastError();
        if (err == CRYPT_E_NOT_FOUND) {
            return NULL;
        }
        throw CSPException("Error gettin subject certificate from store", err);
    }
    return new Cert(res, this);
};

Cert *CertStore::add_cert(Cert *c) throw(CSPException)
{
    LOG("CertStore::add_cert(%p)\n", c->pcert);
    PCCERT_CONTEXT copy;
    if (c && !CertAddCertificateContextToStore(hstore, c->pcert,
            CERT_STORE_ADD_ALWAYS, &copy)) {
        throw CSPException("Couldn't add cert to store");
    }
    return new Cert(copy, this);
};

CertIter *CertStore::__iter__() throw(CSPException)
{
    return new CertIter(this);
};

CertFind *CertStore::find_by_thumb(BYTE *STRING, DWORD LENGTH) throw(CSPException)
{
    return new CertFind(this, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, CERT_FIND_HASH, STRING, LENGTH);
};

CertFind *CertStore::find_by_name(BYTE *STRING, DWORD LENGTH) throw(CSPException)
{
    return new CertFind(this, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, STRING);
};

CertIter::CertIter(CertStore *p) throw (CSPException) : parent(p)
{
    LOG("CertIter::CertIter(%p)\n", p);
    if (parent) {
        parent->ref();
    }
    iter = true;
    pcert = NULL;
};

CertIter::~CertIter() throw (CSPException)
{
    LOG("CertIter::~CertIter()\n");
    if (parent) {
        parent->unref();
    }
};

CertFind::~CertFind() throw (CSPException)
{
    LOG("CertFind::~CertFind()\n");
    if (findtype == CERT_FIND_SUBJECT_STR) {
        if (param) {
            LOG("hohoho\n");
            free(param);
        }
    } else {
        if (chb.pbData) {
            LOG("hahaha\n");
            free(chb.pbData);
        }
    }
};


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
};

Cert *CertFind::next() throw (Stop_Iteration, CSPException)
{
    LOG("CertFind::next()\n");
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
};

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
    if (!CertFreeCertificateContext(pcert)) {
        throw CSPException("Couldn't free certificate context");
    }
    if (parent) {
        parent->unref();
    }
    LOG("Deleted cert: %p\n", pcert);
};

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
    if (msg) {
        msg->ref();
    }
    hstore = CertOpenStore(CERT_STORE_PROV_MSG, MY_ENC_TYPE, 0, 0, msg->hmsg);
    if (!hstore) {
        throw CSPException("Couldn't open message certificate store");
    }
};

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
};


void Cert::request(Crypt *ctx, BYTE *STRING, DWORD LENGTH,
                   BYTE **s, DWORD *slen, DWORD keyspec) throw(CSPException)
{
    DWORD            cbNameEncoded;
    BYTE*            pbNameEncoded = NULL;
    CERT_REQUEST_INFO   CertReqInfo;
    CertStrToName(
        MY_ENC_TYPE,
        (LPCSTR) STRING,
        //CERT_OID_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
        CERT_OID_NAME_STR,
        NULL,
        NULL,
        &cbNameEncoded,
        NULL );
    pbNameEncoded = (BYTE*) malloc( cbNameEncoded );
    CertStrToName(
        MY_ENC_TYPE,
        (LPCSTR) STRING,
        //CERT_OID_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
        CERT_OID_NAME_STR,
        NULL,
        pbNameEncoded,
        &cbNameEncoded,
        NULL );
    CertReqInfo.Subject.cbData = cbNameEncoded;
    CertReqInfo.Subject.pbData = pbNameEncoded;
    CertReqInfo.cAttribute = 0;
    CertReqInfo.rgAttribute = NULL;
    CertReqInfo.dwVersion = CERT_REQUEST_V1;

    DWORD cbPublicKeyInfo;
    CryptExportPublicKeyInfo( ctx->hprov, keyspec,
                              MY_ENC_TYPE, NULL, &cbPublicKeyInfo );

    CERT_PUBLIC_KEY_INFO *pbPublicKeyInfo = (CERT_PUBLIC_KEY_INFO*) LocalAlloc( LPTR, cbPublicKeyInfo );
    CryptExportPublicKeyInfo( ctx->hprov, keyspec,
                              MY_ENC_TYPE, pbPublicKeyInfo, &cbPublicKeyInfo );

    CertReqInfo.SubjectPublicKeyInfo = *pbPublicKeyInfo;

    CRYPT_ALGORITHM_IDENTIFIER SigAlg;
    ZeroMemory(&SigAlg, sizeof(SigAlg));
    //SigAlg.pszObjId = szOID_OIWSEC_sha1;
    SigAlg.pszObjId = (char *)szOID_CP_GOST_R3411;

    CryptSignAndEncodeCertificate(
        ctx->hprov, AT_KEYEXCHANGE, MY_ENC_TYPE,
        X509_CERT_REQUEST_TO_BE_SIGNED, &CertReqInfo,
        &SigAlg, NULL, NULL, slen );

    *s = (BYTE *)malloc(*slen);

    CryptSignAndEncodeCertificate(
        ctx->hprov, AT_KEYEXCHANGE, MY_ENC_TYPE,
        X509_CERT_REQUEST_TO_BE_SIGNED, &CertReqInfo,
        &SigAlg, NULL, *s, slen );
}