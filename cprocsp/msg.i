// vim: ft=swig

%cstring_output_allocate_size(char **s, DWORD *slen, free(*$1));

%newobject CryptMsg::get_nth_signer_info(DWORD idx);

%inline %{

class SignerIter;

class CryptMsg {
public:
    HCRYPTMSG hmsg;
    CertStore *certs;
    DWORD num_signers;
    DWORD type;
    Crypt *cprov;
    CMSG_SIGNED_ENCODE_INFO *sign_info;
    CRYPT_ALGORITHM_IDENTIFIER  hash_alg;

    // инициализация сообщения для декодирования
    CryptMsg(char *STRING, size_t LENGTH, Crypt *ctx=NULL) throw(CSPException);

    // инициализация сообщения для кодирования
    // данные добавляются потом методом .update
    CryptMsg(Crypt *ctx=NULL) throw(CSPException);

    ~CryptMsg() throw(CSPException);

    PCERT_INFO get_nth_signer_info(DWORD idx);

    SignerIter *signer_certs();

    bool verify_cert(Cert *c) throw(CSPException) {
        bool res = CryptMsgControl(hmsg, 0, CMSG_CTRL_VERIFY_SIGNATURE, c->pcert->pCertInfo);
        if (!res) {
            throw CSPException("Signature error");
        }
        return res;
    }
    void get_data(char **s, DWORD *slen) throw(CSPException);

    void add_signer_cert(Cert *c) throw(CSPException);
    void sign_data(char *STRING, size_t LENGTH, char **s, DWORD *slen, bool detach=0) throw(CSPException);
};

class SignerIter {
private:
    CryptMsg *owner;
    DWORD idx;
public:

    SignerIter(CryptMsg* o);

    SignerIter *__iter__();

    virtual Cert *next() throw (Stop_Iteration, CSPException);
};

%}

%{
CryptMsg::CryptMsg(Crypt *ctx) throw(CSPException) {
    hmsg = NULL;
    certs = NULL;
    num_signers = 0;
    type = 0;
    cprov = ctx;
    size_t szi = sizeof(CMSG_SIGNED_ENCODE_INFO);

    sign_info = (CMSG_SIGNED_ENCODE_INFO *)malloc(szi);
    memset(sign_info, 0, szi);
    sign_info->cbSize = szi;

    DWORD hasi = sizeof(hash_alg);
    memset(&hash_alg, 0, hasi);
    hash_alg.pszObjId = szOID_CP_GOST_R3411;  
}

void CryptMsg::add_signer_cert(Cert *c) throw(CSPException) {
    CMSG_SIGNER_ENCODE_INFO *signer_info = NULL;
    CERT_BLOB *signer_cert = NULL;
    size_t ssi = sizeof(CMSG_SIGNER_ENCODE_INFO);
    size_t ssb = sizeof(CERT_BLOB);
    HCRYPTPROV      hprov = 0;
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


    sign_info->cSigners += 1;
    sign_info->cCertEncoded = sign_info->cSigners;
    sign_info->rgSigners = (PCMSG_SIGNER_ENCODE_INFO) realloc(sign_info->rgSigners, ssi * sign_info->cSigners);
    sign_info->rgCertEncoded = (CERT_BLOB *) realloc(sign_info->rgCertEncoded, ssb * sign_info->cCertEncoded);;

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

void CryptMsg::get_data(char **s, DWORD *slen) throw(CSPException) {
    if(!CryptMsgGetParam(
                hmsg,                      /* Handle to the message*/
                CMSG_CONTENT_PARAM,        /* Parameter type*/
                0,                         /* Index*/
                NULL,             /* Pointer to the blob*/
                slen))
    {          /* Size of the blob*/
        throw CSPException("Couldn't get decoded data size");
    }
    *s = (char *) malloc(*slen);
    if(!CryptMsgGetParam(
                hmsg,                      /* Handle to the message*/
                CMSG_CONTENT_PARAM,        /* Parameter type*/
                0,                         /* Index*/
                *s,             /* Pointer to the blob*/
                slen))
    {          /* Size of the blob*/
        throw CSPException("Couldn't get decoded data");
    }
}

void CryptMsg::sign_data(char *STRING, size_t LENGTH, char **s, DWORD *slen, bool detach) throw(CSPException) {
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
        throw CSPException("Getting cbEncodedBlob length failed.");
    }

    *s = (char *) malloc(*slen);

    hmsg = CryptMsgOpenToEncode(
                MY_ENC_TYPE,                     /* Encoding type*/
                detach? CMSG_DETACHED_FLAG : 0,  /* Flags (CMSG_DETACHED_FLAG )*/
                CMSG_SIGNED,            /* Message type*/
                sign_info,   /* Pointer to structure*/
                NULL,                   /* Inner content object ID*/
                NULL);                  /* Stream information (not used)*/

    if(!hmsg) {
        throw CSPException("Couldn't initialize message");
    }

    if(!CryptMsgUpdate(
        hmsg,               /* Handle to the message*/
        (BYTE *)STRING,            /* Pointer to the content*/
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
        throw CSPException("Couldn't get signed data");
    }
}

CryptMsg::CryptMsg(char *STRING, size_t LENGTH, Crypt *ctx) throw(CSPException) {
    HCERTSTORE hstore = NULL;
    DWORD temp = sizeof(DWORD);
    CRYPT_ALGORITHM_IDENTIFIER cai;
    memset(&cai, 0, sizeof(cai));
    sign_info = NULL;

    hmsg = CryptMsgOpenToDecode(MY_ENC_TYPE, 0, 0, ctx? ctx->hprov : NULL, NULL, NULL);
    if (!hmsg) {
        throw CSPException("Couldn't initialize message");
    }
    if (!CryptMsgUpdate(hmsg, (const BYTE *)STRING, LENGTH, 1)) {
        throw CSPException("Couldn't decode message");
    }

    if (!CryptMsgGetParam(hmsg, CMSG_TYPE_PARAM, 0, &this->type, &temp)) {
        throw CSPException("Couldn't get message type");
    }

    hstore = CertOpenStore(CERT_STORE_PROV_MSG, MY_ENC_TYPE, NULL, 0, hmsg);
    if (!hstore) {
        throw CSPException("Couldn't open message certificate store");
    }
    certs = new CertStore(hstore);

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
    if (sign_info) {
        if(sign_info->rgSigners) {
            for (int i=0; i<sign_info->cSigners; i++) {
                PCMSG_SIGNER_ENCODE_INFO ssi = &(sign_info->rgSigners[i]);
                if (ssi) {
                    CryptReleaseContext(ssi->hCryptProv, 0);
                }
            }
            free(sign_info->rgSigners);
        }
        free(sign_info);
    }

    if(hmsg && !CryptMsgClose(hmsg)) {
        throw CSPException("Couldn't close message");
    }
};

PCERT_INFO CryptMsg::get_nth_signer_info(DWORD idx) {
    DWORD spsi;
    PCERT_INFO psi;

    if (!CryptMsgGetParam(hmsg, CMSG_SIGNER_CERT_INFO_PARAM, idx, NULL, &spsi)) {
        throw CSPException("Couldn't get signer info size");
    }
    psi = (PCERT_INFO) malloc(spsi);
    /*printf("psi:%i\n", spsi);*/
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
    idx = 0;
};

Cert *SignerIter::next() throw (Stop_Iteration, CSPException) {
    PCERT_INFO psi;
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


%}