// vim: ft=swig

%newobject CryptMsg::get_nth_signer_info;

typedef struct _CERT_INFO {
    DWORD                       dwVersion;
    CRYPT_INTEGER_BLOB          SerialNumber;
    CRYPT_ALGORITHM_IDENTIFIER  SignatureAlgorithm;
    CERT_NAME_BLOB              Issuer;
    FILETIME                    NotBefore;
    FILETIME                    NotAfter;
    CERT_NAME_BLOB              Subject;
    CERT_PUBLIC_KEY_INFO        SubjectPublicKeyInfo;
    CRYPT_BIT_BLOB              IssuerUniqueId;
    CRYPT_BIT_BLOB              SubjectUniqueId;
    DWORD                       cExtension;
    PCERT_EXTENSION             rgExtension;
} CERT_INFO, *PCERT_INFO;

%extend _CERT_INFO {
    ~_CERT_INFO() {
        free($self);
    }
}
%newobject SignerIter::next;
%feature("python:slot", "tp_iter", functype="getiterfunc") SignerIter::__iter__;
%feature("python:slot", "tp_iternext", functype="iternextfunc") SignerIter::next;
%feature("ref") CryptMsg "$this->ref();"
%feature("unref") CryptMsg "$this->unref();"

%inline %{

class SignerIter;

class CryptMsg : public RCObj {
private:
    Crypt *cprov;
    CRYPT_ALGORITHM_IDENTIFIER hash_alg;
    CRYPT_ALGORITHM_IDENTIFIER encrypt_alg;
    CMSG_SIGNED_ENCODE_INFO *sign_info;
    CRYPT_ENCRYPT_MESSAGE_PARA *encrypt_para;
    PCCERT_CONTEXT *recipient_certs;
    HCRYPTMSG hmsg;
    bool *release_flags;
    void msg_init(Crypt *ctx) throw(CSPException);
public:
    CertStore *certs;
    DWORD num_signers;
    DWORD num_recipients;
    DWORD type;

    // инициализация сообщения для декодирования
    CryptMsg(BYTE *STRING, DWORD LENGTH, Crypt *ctx=NULL) throw(CSPException);

    // инициализация сообщения для кодирования
    // данные добавляются потом методом .update
    CryptMsg(Crypt *ctx=NULL) throw(CSPException);

    ~CryptMsg() throw(CSPException);

    CERT_INFO *get_nth_signer_info(DWORD idx);

    SignerIter *signer_certs();

    bool verify_cert(Cert *c) throw(CSPException) {
        return CryptMsgControl(hmsg, 0, CMSG_CTRL_VERIFY_SIGNATURE, c->pcert->pCertInfo);
    }
    void get_data(BYTE **s, DWORD *slen) throw(CSPException);
    void add_signer_cert(Cert *c) throw(CSPException);
    void add_recipient_cert(Cert *c) throw(CSPException);
    void encrypt_data(BYTE *STRING, DWORD LENGTH, BYTE **s, DWORD *slen) throw(CSPException);
    void decrypt_data(BYTE *STRING, DWORD LENGTH, BYTE **s, DWORD *slen) throw(CSPException);
    virtual void sign_data(BYTE *STRING, DWORD LENGTH, BYTE **s, DWORD *slen, bool detach=0) throw(CSPException);

    friend class SignerIter;
    friend class CertStore;
};

class SignerIter {
private:
    CryptMsg *owner;
    DWORD idx;
public:

    SignerIter(CryptMsg* o);

    virtual ~SignerIter() {
        if (owner) owner->unref();
    }

    SignerIter *__iter__();

    virtual Cert *next() throw (Stop_Iteration, CSPException);
};

%}

%{
void CryptMsg::msg_init(Crypt *ctx) throw(CSPException) {
    LOG("init msg\n");
    hmsg = NULL;
    certs = NULL;
    num_signers = 0;
    release_flags = NULL;
    type = 0;
    cprov = ctx;
    if (ctx) {
        ctx->ref();
    }

    DWORD hasi = sizeof(hash_alg);
    memset(&hash_alg, 0, hasi);
    hash_alg.pszObjId = (char *)szOID_CP_GOST_R3411;  

    DWORD esi = sizeof(encrypt_alg);
    memset(&encrypt_alg, 0, esi);
    encrypt_alg.pszObjId = (char *)szOID_CP_GOST_28147;  

    recipient_certs = NULL;
    num_recipients = 0;
    encrypt_para = NULL;
    sign_info = NULL;

}

CryptMsg::CryptMsg(Crypt *ctx) throw(CSPException) {
    msg_init(ctx);
}

void CryptMsg::add_recipient_cert(Cert *c) throw(CSPException) {
    recipient_certs = (PCCERT_CONTEXT *) realloc(recipient_certs, sizeof(PCCERT_CONTEXT) * (num_recipients + 1));
    recipient_certs[num_recipients] = c->pcert;
    num_recipients ++;
}

void CryptMsg::encrypt_data(BYTE *STRING, DWORD LENGTH, BYTE **s, DWORD *slen) throw(CSPException) {
    if (!encrypt_para) {
        DWORD szp = sizeof(CRYPT_ENCRYPT_MESSAGE_PARA);
        encrypt_para = (CRYPT_ENCRYPT_MESSAGE_PARA *)malloc(szp);
        memset(encrypt_para, 0, szp);
        encrypt_para->cbSize = szp;
        encrypt_para->dwMsgEncodingType = MY_ENC_TYPE;
        encrypt_para->hCryptProv = cprov? cprov->hprov : 0;
        encrypt_para->ContentEncryptionAlgorithm = encrypt_alg;
    }

    if(!CryptEncryptMessage(
        encrypt_para,
        num_recipients,
        recipient_certs,
        STRING,
        LENGTH,
        NULL,
        slen))
    {
        throw CSPException("Cannot acquire encrypted blob size");
    }

    *s = (BYTE *) malloc(*slen);

    if(!CryptEncryptMessage(
        encrypt_para,
        num_recipients,
        recipient_certs,
        STRING,
        LENGTH,
        *s,
        slen))
    {
        free((void *)*s);
        throw CSPException("Encryption failed");
    }
}

void CryptMsg::decrypt_data(BYTE *STRING, DWORD LENGTH, BYTE **s, DWORD *slen) throw(CSPException) {
    CRYPT_DECRYPT_MESSAGE_PARA  decrypt_para;
    CertStore store(cprov, "MY");

    memset(&decrypt_para, 0, sizeof(CRYPT_DECRYPT_MESSAGE_PARA));
    decrypt_para.cbSize = sizeof(CRYPT_DECRYPT_MESSAGE_PARA);
    decrypt_para.dwMsgAndCertEncodingType = MY_ENC_TYPE;
    decrypt_para.cCertStore = 1;
    decrypt_para.rghCertStore = &store.hstore;

    if(!CryptDecryptMessage(
        &decrypt_para,
        STRING,
        LENGTH,
        NULL,
        slen,
        NULL))
    {
        throw CSPException("Cannot acquire decrypted blob size");
    }

    *s = (BYTE *) malloc(*slen);

    if(!CryptDecryptMessage(
        &decrypt_para,
        STRING,
        LENGTH,
        *s,
        slen,
        NULL))
    {
        free((void *)*s);
        throw CSPException("Decryption failed");
    }
}

void CryptMsg::add_signer_cert(Cert *c) throw(CSPException) {
    CMSG_SIGNER_ENCODE_INFO *signer_info = NULL;
    CERT_BLOB *signer_cert = NULL;
    DWORD ssi = sizeof(CMSG_SIGNER_ENCODE_INFO);
    DWORD ssb = sizeof(CERT_BLOB);
    HCRYPTPROV      hprov = cprov? cprov->hprov : 0;
    DWORD keytype = AT_KEYEXCHANGE;
    BOOL do_release;

    if (!CryptAcquireCertificatePrivateKey(c->pcert,
            0,
            NULL,
            &hprov,
            &keytype,
            &do_release)) 
    {
        throw CSPException("Cannot acquire signer certificate private key");
    }

    if (!sign_info) {
        DWORD szi = sizeof(CMSG_SIGNED_ENCODE_INFO);
        sign_info = (CMSG_SIGNED_ENCODE_INFO *)malloc(szi);
        memset(sign_info, 0, szi);
        sign_info->cbSize = szi;
    }

    sign_info->cSigners += 1;
    sign_info->cCertEncoded = sign_info->cSigners;
    sign_info->rgSigners = (PCMSG_SIGNER_ENCODE_INFO) realloc(sign_info->rgSigners, ssi * sign_info->cSigners);
    sign_info->rgCertEncoded = (CERT_BLOB *) realloc(sign_info->rgCertEncoded, ssb * sign_info->cCertEncoded);;
    release_flags = (bool *) realloc(release_flags, sizeof(bool) * sign_info->cSigners);
    release_flags[sign_info->cSigners - 1] = do_release;

    signer_info = &(sign_info->rgSigners[sign_info->cSigners - 1]);
    memset(signer_info, 0, ssi);
    signer_info->cbSize = ssi;

    signer_cert = &(sign_info->rgCertEncoded[sign_info->cSigners - 1]);
    memset(signer_cert, 0, ssb);
    signer_cert->cbData = c->pcert->cbCertEncoded;
    signer_cert->pbData = c->pcert->pbCertEncoded;

    signer_info->pCertInfo = c->pcert->pCertInfo;
    signer_info->hCryptProv = hprov;
    signer_info->dwKeySpec = keytype;
    signer_info->HashAlgorithm = hash_alg;
    signer_info->pvHashAuxInfo = NULL;
}

void CryptMsg::get_data(BYTE **s, DWORD *slen) throw(CSPException) {
    if(!CryptMsgGetParam(
                hmsg,                      /* Handle to the message*/
                CMSG_CONTENT_PARAM,        /* Parameter type*/
                0,                         /* Index*/
                NULL,             /* Pointer to the blob*/
                slen))
    {          /* Size of the blob*/
        throw CSPException("Couldn't get decoded data size");
    }
    *s = (BYTE *) malloc(*slen);
    if(!CryptMsgGetParam(
                hmsg,                      /* Handle to the message*/
                CMSG_CONTENT_PARAM,        /* Parameter type*/
                0,                         /* Index*/
                *s,             /* Pointer to the blob*/
                slen))
    {          /* Size of the blob*/
        free((void *)*s);
        throw CSPException("Couldn't get decoded data");
    }
}

void CryptMsg::sign_data(BYTE *STRING, DWORD LENGTH, BYTE **s, DWORD *slen, bool detach) throw(CSPException) {
    if (hmsg) {
        if (!CryptMsgClose(hmsg)) {
            throw CSPException("Couldn't close previous message");
        }
    }

    *slen = CryptMsgCalculateEncodedLength(
        MY_ENC_TYPE,               /* Message encoding type*/
        0,                  /* Flags*/
        CMSG_SIGNED,            /* Message type*/
        sign_info,   /* Pointer to structure*/
        NULL,                   /* Inner content object ID*/
        (DWORD)LENGTH);                /* Size of content*/

    if (! *slen) {
        free((void *)*s);
        throw CSPException("Getting cbEncodedBlob length failed.");
    }

    *s = (BYTE *) malloc(*slen);

    hmsg = CryptMsgOpenToEncode(
                MY_ENC_TYPE,                     /* Encoding type*/
                detach? CMSG_DETACHED_FLAG : 0,  /* Flags (CMSG_DETACHED_FLAG )*/
                CMSG_SIGNED,            /* Message type*/
                sign_info,   /* Pointer to structure*/
                NULL,                   /* Inner content object ID*/
                NULL);                  /* Stream information (not used)*/

    if(!hmsg) {
        free((void *)*s);
        throw CSPException("Couldn't initialize message");
    }

    if(!CryptMsgUpdate(
        hmsg,               /* Handle to the message*/
        STRING,            /* Pointer to the content*/
        LENGTH,     /* Size of the content*/
        1))
    {            /* Last call*/
        throw CSPException("Couldn't set message data");
    }

    if(!CryptMsgGetParam(
                hmsg,                      /* Handle to the message*/
                CMSG_CONTENT_PARAM,        /* Parameter type*/
                0,                         /* Index*/
                *s,             /* Pointer to the blob*/
                slen))
    {          /* Size of the blob*/
        free((void *)*s);
        throw CSPException("Couldn't get signed data");
    }
}

CryptMsg::CryptMsg(BYTE *STRING, DWORD LENGTH, Crypt *ctx) throw(CSPException) {
    DWORD temp = sizeof(DWORD);

    msg_init(ctx);

    hmsg = CryptMsgOpenToDecode(MY_ENC_TYPE, 0, 0, ctx? ctx->hprov : 0, NULL, NULL);
    if (!hmsg) {
        throw CSPException("Couldn't initialize message");
    }
    if (!CryptMsgUpdate(hmsg, (const BYTE *)STRING, LENGTH, 1)) {
        throw CSPException("Couldn't decode message");
    }

    if (!CryptMsgGetParam(hmsg, CMSG_TYPE_PARAM, 0, &this->type, &temp)) {
        throw CSPException("Couldn't get message type");
    }

    certs = new CertStore(this);

    if (!CryptMsgGetParam(hmsg, CMSG_SIGNER_COUNT_PARAM, 0, &num_signers, &temp)) {
        throw CSPException("Couldn't get message signer count");
    }

    /*temp = sizeof(cai);*/
    /*if (!CryptMsgGetParam(hmsg, CMSG_HASH_ALGORITHM_PARAM, 0, &cai, &temp)) {*/
        /*throw CSPException("Couldn't get message hash algorithm");*/
    /*}*/
    /*puts(cai.pszObjId);*/


};

CryptMsg::~CryptMsg() throw(CSPException) {
    LOG("close msg\n");
    if (cprov)
        cprov->unref();
    if (sign_info) {
        if(sign_info->rgSigners) {
            for (unsigned i=0; i<sign_info->cSigners; i++) {
                PCMSG_SIGNER_ENCODE_INFO ssi = &(sign_info->rgSigners[i]);
                if (ssi && release_flags[i]) {
                    CryptReleaseContext(ssi->hCryptProv, 0);
                }
            }
            free(sign_info->rgSigners);
        }
        free(sign_info);
        if (release_flags) {
            free(release_flags);
        }
    }

    if(hmsg && !CryptMsgClose(hmsg)) {
        throw CSPException("Couldn't close message");
    }


};

CERT_INFO *CryptMsg::get_nth_signer_info(DWORD idx) {
    DWORD spsi;
    CERT_INFO *psi;

    if (!CryptMsgGetParam(hmsg, CMSG_SIGNER_CERT_INFO_PARAM, idx, NULL, &spsi)) {
        throw CSPException("Couldn't get signer info size");
    }
    psi = (CERT_INFO *) malloc(spsi);
    /*LOG("psi:%i\n", spsi);*/
    if (!CryptMsgGetParam(hmsg, CMSG_SIGNER_CERT_INFO_PARAM, idx, psi, &spsi)) {
        throw CSPException("Couldn't get signer info data");
    }
    return psi;
}

SignerIter *CryptMsg::signer_certs() {
    return new SignerIter(this);
};



SignerIter *SignerIter::__iter__() { return this; };

SignerIter::SignerIter(CryptMsg* o) {
    owner = o;
    owner->ref();
    idx = 0;
};

Cert *SignerIter::next() throw (Stop_Iteration, CSPException) {
    CERT_INFO *psi;
    Cert *res = NULL;

    if (idx >= owner->num_signers) {
        throw Stop_Iteration();
    }

    psi = owner->get_nth_signer_info(idx);
    try {
        res = owner->certs->get_cert_by_info(psi);
    }
    catch (...) {
        free(psi);
        throw;
    }
    idx++;
    free(psi);
    return res;
};

CertStore::CertStore(CryptMsg *parent) throw(CSPException) {
    init();
    if (!parent) {
        throw CSPException("Invalid message for cert store");
    }
    msg = parent;
    msg->ref();
    hstore = CertOpenStore(CERT_STORE_PROV_MSG, MY_ENC_TYPE, 0, 0, msg->hmsg);
    if (!hstore) {
        throw CSPException("Couldn't open message certificate store");
    }
};

CertStore::~CertStore() throw(CSPException) {
    LOG("begin store free");
    if (hstore) {
        if (!CertCloseStore(hstore, CERT_CLOSE_STORE_CHECK_FLAG)) {
            throw CSPException("Couldn't properly close certificate store");
        }
    }
    LOG("end store free");
    if (msg) {
        LOG("msg free: %p\n", msg);
        msg->unref();
    }
    if (ctx) {
        LOG("ctx free: %p\n", ctx);
        ctx->unref();
    }
    LOG("Freed store\n");
};


%}
