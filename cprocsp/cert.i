/* vim: ft=swig
*/
%newobject Cert::name();
%newobject Cert::duplicate();
%newobject Cert::extract();
%newobject CertStore::__iter__();
%feature("ref") CertStore "$this->ref();"
%feature("unref") CertStore "$this->unref();"

%inline %{
class Cert {
private:
    PCCERT_CONTEXT pcert;
    void decode_name_blob(PCERT_NAME_BLOB pNameBlob, BYTE **s, DWORD *slen) {
        DWORD flags = CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG;

        *slen = CertNameToStr( X509_ASN_ENCODING, pNameBlob, flags, NULL, 0);
        if (*slen <= 1)
            throw CSPException("Wrong size for blob decoded data");

        *s = (BYTE *)malloc(*slen);

        *slen = CertNameToStr(X509_ASN_ENCODING, pNameBlob, flags, (char *)*s, *slen);

        if (*slen <= 1) {
            free(*s);
            throw CSPException("Couldn't decode cert blob");
        }
    }

public:
    Cert* duplicate() throw(CSPException) {
        PCCERT_CONTEXT pc = CertDuplicateCertificateContext(pcert);
        return new Cert(pc);
    };


    void remove_from_store() throw(CSPException) {
        PCCERT_CONTEXT pc = CertDuplicateCertificateContext(pcert);
        if (!pc) {
            throw CSPException("Couldn't duplicate cert context");
        }
        if(!CertDeleteCertificateFromStore(pc))   
        {
            throw CSPException("Couldn't remove certificate");
        }
    }

    Cert(PCCERT_CONTEXT pc) throw(CSPException) {
        if (!pc) {
            throw CSPException("Invalid certificate context");
        }
        pcert = pc;
        LOG("New cert %x\n", pcert);
    };

    Cert(BYTE* STRING, DWORD LENGTH) throw(CSPException) {
        pcert = CertCreateCertificateContext(MY_ENC_TYPE, STRING, LENGTH);
        if (!pcert) {
            throw CSPException("Couldn't decode certificate blob");
        }
    };

    ~Cert() throw(CSPException){
        if (!CertFreeCertificateContext(pcert)) {
            throw CSPException("Couldn't free certificate context");
        }
        LOG("Freed cert %x\n", pcert);
    };

    void extract(BYTE **s, DWORD *slen) throw(CSPException) {
        *slen = pcert->cbCertEncoded;
        *s = (BYTE *)malloc(*slen);
        memcpy(*s, pcert->pbCertEncoded, *slen);
    }

    void thumbprint(BYTE **s, DWORD *slen) throw(CSPException) {
        if(!CertGetCertificateContextProperty(pcert, CERT_HASH_PROP_ID, NULL, slen)) {
            LOG("Error: %x\n", pcert);
            throw CSPException("Couldn't get certificate hash size");
        }
        *s = (BYTE *)malloc(*slen);
        if(!CertGetCertificateContextProperty(pcert, CERT_HASH_PROP_ID, (void *)*s, slen)) {
            free((void *)*s);
            throw CSPException("Couldn't get certificate thumbprint");
        }
    };

    char *sign_algorithm() {
        return pcert->pCertInfo->SignatureAlgorithm.pszObjId;
    }

    void name(BYTE **s, DWORD *slen) throw(CSPException) {
        decode_name_blob(&pcert->pCertInfo->Subject, s, slen);
    };

    void issuer(BYTE **s, DWORD *slen) throw(CSPException) {
        decode_name_blob(&pcert->pCertInfo->Issuer, s, slen);
    };

    friend class CryptMsg;
    friend class CertStore;
};
%}

%feature("python:slot", "tp_iter", functype="getiterfunc") CertStore::__iter__;
%feature("python:slot", "tp_iter", functype="getiterfunc") CertIter::__iter__;
%feature("python:slot", "tp_iternext", functype="iternextfunc") CertIter::next;
%newobject CertIter::next();

%inline %{
class CertStore;

class CertIter {
public:
    CertStore *parent;
    bool iter;
    PCCERT_CONTEXT pcert;

    CertIter(CertStore *p) throw (CSPException);

    CertIter *__iter__() { return this; }

    virtual ~CertIter() throw (CSPException);

    virtual Cert *next() throw (Stop_Iteration, CSPException);
};

class CertFind : public CertIter {
public:
    CRYPT_HASH_BLOB chb;
    CRYPT_HASH_BLOB *param;
    DWORD enctype, findtype;

    CertFind(CertStore *p, DWORD et, DWORD ft, BYTE *STRING, DWORD LENGTH) : CertIter(p) {
        enctype = et;
        findtype = ft;
        chb.pbData = STRING;
        chb.cbData = LENGTH;
        param = &chb;
        LOG("Started find %i-%i-%i\n", et, ft, LENGTH);
    };

    CertFind(CertStore *p, DWORD et, BYTE *name) : CertIter(p) {
        enctype = et;
        findtype = CERT_FIND_SUBJECT_STR;
        param = (CRYPT_HASH_BLOB *)name;

        LOG("Started find %i-'%s'\n", et, name);
    };

    virtual Cert *next() throw (Stop_Iteration, CSPException);
};

class CryptMsg ;
class CertStore : public RCObj {
private:
    Crypt *ctx;
    CryptMsg *msg;
    HCERTSTORE hstore;

    void init() {
        ctx = NULL;
        msg = NULL;
        hstore = 0;
    }
public:

    CertStore(CryptMsg *parent) throw(CSPException);

    CertStore() throw(CSPException) {
        init();
        hstore = CertOpenStore(CERT_STORE_PROV_MEMORY, MY_ENC_TYPE, 0, CERT_STORE_CREATE_NEW_FLAG,NULL);
        if (!hstore) {
            throw CSPException("Couldn't create memory store");
        }
    };

    CertStore(Crypt *parent, LPCTSTR protocol) throw(CSPException) {
        HCRYPTPROV hprov = 0;
        init();
        if (parent) {
            ctx = parent;
            ctx->ref();
            LOG("ctx ref: %p\n", ctx);
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
        LOG("Opened store\n");
    };

    ~CertStore() throw(CSPException);

    CertIter *__iter__() throw(CSPException) {
        return new CertIter(this);
    };

    CertFind *find_by_thumb(BYTE *STRING, DWORD LENGTH) throw(CSPException) {
        return new CertFind(this, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, CERT_FIND_HASH, STRING, LENGTH);
    };

    CertFind *find_by_name(BYTE *STRING, DWORD LENGTH) throw(CSPException) {
        return new CertFind(this, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, STRING);
    };

    Cert *get_cert_by_info(CERT_INFO *psi) throw(CSPException) {
        PCCERT_CONTEXT res;
        res = CertGetSubjectCertificateFromStore(hstore, MY_ENC_TYPE, psi);
        if (!res) {
            if (GetLastError() == (DWORD) CRYPT_E_NOT_FOUND) {
                return NULL;
            }
            throw CSPException("Error gettin subject certificate from store");
        }
        return new Cert(res);
    };

    void add_cert(Cert *c) throw(CSPException) {
        if (c && !CertAddCertificateContextToStore(hstore, c->pcert, CERT_STORE_ADD_ALWAYS, NULL)) {
            throw CSPException("Couldn't add cert to store");
        }
    };
    friend class CryptMsg;
    friend class CertIter;
    friend class CertFind;
};


CertIter::CertIter(CertStore *p) throw (CSPException) {
    parent = p;
    parent->ref();
    iter = true;
    pcert = NULL;
    LOG("Started iter\n");
};

CertIter::~CertIter() throw (CSPException) {
    parent->unref();
};

Cert *CertIter::next() throw (Stop_Iteration, CSPException) {
    if (!iter) {
        LOG("Stop iter\n");
        throw Stop_Iteration();
    }
    pcert = CertEnumCertificatesInStore(parent->hstore, pcert);
    if (pcert) {
        return new Cert(CertDuplicateCertificateContext(pcert));
    } else {
        iter = false;
        LOG("Stop iter\n");
        throw Stop_Iteration();
    }
};

Cert *CertFind::next() throw (Stop_Iteration, CSPException) {
    if (!iter) {
        LOG("Stopped find\n");
        throw Stop_Iteration();
    }
    pcert = CertFindCertificateInStore(parent->hstore, enctype, 0, findtype, param, pcert);
    if (pcert) {
        LOG("Next find %i %i\n", enctype, findtype);
        return new Cert(CertDuplicateCertificateContext(pcert));
    } else {
        iter = false;
        LOG("Stopped find\n");
        throw Stop_Iteration();
    }
};

%}

