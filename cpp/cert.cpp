#include "common.hpp"
#include "context.hpp"
#include "cert.hpp"

void CertStore::init() {
    ctx = NULL;
    msg = NULL;
    hstore = 0;
    LOG("init store\n");
}

void Cert::decode_name_blob(PCERT_NAME_BLOB pNameBlob, BYTE **s, DWORD *slen)
{
    DWORD flags = CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG;

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
    PCCERT_CONTEXT pc = CertDuplicateCertificateContext(pcert);
    return new Cert(pc, parent);
};


Cert::Cert(BYTE* STRING, DWORD LENGTH) throw(CSPException) : parent(NULL)
{
    pcert = CertCreateCertificateContext(MY_ENC_TYPE, STRING, LENGTH);
    if (!pcert) {
        throw CSPException("Couldn't decode certificate blob");
    }
    LOG("New cert %p\n", pcert);
};

Cert *Cert::self_sign(Crypt *ctx, BYTE *STRING, DWORD LENGTH)  throw(CSPException)
{
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
    *slen = pcert->cbCertEncoded;
    *s = (BYTE *)malloc(*slen);
    memcpy(*s, pcert->pbCertEncoded, *slen);
}

void Cert::thumbprint(BYTE **s, DWORD *slen) throw(CSPException)
{
    if(!CertGetCertificateContextProperty(pcert, CERT_HASH_PROP_ID, NULL, slen)) {
        LOG("Error: %p\n", pcert);
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
    return pcert->pCertInfo->SignatureAlgorithm.pszObjId;
}

void Cert::name(BYTE **s, DWORD *slen) throw(CSPException)
{
    decode_name_blob(&pcert->pCertInfo->Subject, s, slen);
};

void Cert::issuer(BYTE **s, DWORD *slen) throw(CSPException)
{
    decode_name_blob(&pcert->pCertInfo->Issuer, s, slen);
};

CertFind::CertFind(CertStore *p, DWORD et, DWORD ft, BYTE *STRING, DWORD LENGTH) : CertIter(p)
{
    enctype = et;
    findtype = ft;
    chb.pbData = (BYTE *)malloc(LENGTH);
    memcpy(chb.pbData, STRING, LENGTH);
    chb.cbData = LENGTH;
    param = &chb;
    LOG("Started find %i-%i-%i\n", et, ft, LENGTH);
};


CertFind::CertFind(CertStore *p, DWORD et, BYTE *name) : CertIter(p)
{
    enctype = et;
    findtype = CERT_FIND_SUBJECT_STR;
    param = (CRYPT_HASH_BLOB *)strdup((const char *)name);

    LOG("Started find %i-'%s'\n", et, name);
};

CertStore::CertStore() throw(CSPException)
{
    init();
    hstore = CertOpenStore(CERT_STORE_PROV_MEMORY, MY_ENC_TYPE, 0, CERT_STORE_CREATE_NEW_FLAG,NULL);
    if (!hstore) {
        throw CSPException("Couldn't create memory store");
    }
};

CertStore::CertStore(Crypt *parent, LPCTSTR protocol) throw(CSPException)
{
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

CertIter::CertIter(CertStore *p) throw (CSPException)
{
    parent = p;
    parent->ref();
    iter = true;
    pcert = NULL;
    LOG("Started iter\n");
};

CertIter::~CertIter() throw (CSPException)
{
    parent->unref();
};

CertFind::~CertFind() throw (CSPException)
{
    if (findtype == CERT_FIND_SUBJECT_STR) {
        if (param) {
            free(param);
        }
    } else {
        if (chb.pbData) {
            free(chb.pbData);
        }
    }
};


Cert *CertIter::next() throw (Stop_Iteration, CSPException)
{
    if (!iter) {
        LOG("Stop iter\n");
        throw Stop_Iteration();
    }
    pcert = CertEnumCertificatesInStore(parent->hstore, pcert);
    if (pcert) {
        return new Cert(CertDuplicateCertificateContext(pcert), parent);
    } else {
        iter = false;
        LOG("Stop iter\n");
        throw Stop_Iteration();
    }
};

Cert *CertFind::next() throw (Stop_Iteration, CSPException)
{
    if (!iter) {
        LOG("Stopped find\n");
        throw Stop_Iteration();
    }
    pcert = CertFindCertificateInStore(parent->hstore, enctype, 0, findtype, param, pcert);
    if (pcert) {
        LOG("Next find %lu %lu '%s'\n", enctype, findtype, param);
        return new Cert(CertDuplicateCertificateContext(pcert), parent);
    } else {
        iter = false;
        LOG("Stopped find\n");
        throw Stop_Iteration();
    }
};

Cert::Cert(PCCERT_CONTEXT pc, CertStore *parent) throw(CSPException) : parent(parent)
{
    if (!pc) {
        throw CSPException("Invalid certificate context");
    }
    if (parent) {
        parent->ref();
    }
    pcert = pc;
    LOG("New cert %p\n", pcert);
}

Cert::~Cert() throw(CSPException)
{
    if (!CertFreeCertificateContext(pcert)) {
        throw CSPException("Couldn't free certificate context");
    }
    if (parent) {
        parent->unref();
    }
    LOG("Freed cert %p\n", pcert);
};

void Cert::remove_from_store() throw(CSPException)
{
    PCCERT_CONTEXT pc = CertDuplicateCertificateContext(pcert);
    if (!pc) {
        throw CSPException("Couldn't duplicate cert context");
    }
    if(!CertDeleteCertificateFromStore(pc)) {
        throw CSPException("Couldn't remove certificate");
    }
    if (parent) {
        parent->unref();
        parent = NULL;
    }
}
