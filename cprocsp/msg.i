// vim: ft=swig

%newobject CryptMsg::get_nth_signer_info;
%inline %{

class SignerIter;

class CryptMsg {
public:
    HCRYPTMSG hmsg;
    CertStore *certs;
    DWORD num_signers;
    DWORD type;
    Crypt *cprov;

    CryptMsg(char *STRING, size_t LENGTH, Crypt *ctx=NULL) throw(CSPException);

    ~CryptMsg() throw(CSPException);

    PCERT_INFO get_nth_signer_info(DWORD idx);

    SignerIter *signer_certs();

    bool verify_nth_sign(int n) throw(CSPException) {
        bool res;
        CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA para;
        PCERT_INFO pci = get_nth_signer_info(n);
        Cert *c = certs->get_cert_by_info(pci);

        memset(&para, 0, sizeof(para));
        para.cbSize = sizeof(para);
        para.dwSignerIndex = n;
        para.dwSignerType = CMSG_VERIFY_SIGNER_CERT;
        para.pvSigner = (void *)c->pcert;
        res = CryptMsgControl(hmsg, 0, CMSG_CTRL_VERIFY_SIGNATURE_EX, &para);
        if (!res) {
            throw CSPException("Signature error");
        }
        return res;
    }

    bool verify_by_info(PCERT_INFO psi) throw(CSPException) {
        printf("1 %p\n", psi);
        bool res = CryptMsgControl(hmsg, 0, CMSG_CTRL_VERIFY_SIGNATURE, psi);
        puts("2");
        if (!res) {
            throw CSPException("Signature error");
        }
        puts("3");
        return res;
    }

    bool verify_cert(Cert *c) throw(CSPException) {
        bool res = CryptMsgControl(hmsg, 0, CMSG_CTRL_VERIFY_SIGNATURE, c->pcert->pCertInfo);
        if (!res) {
            throw CSPException("Signature error");
        }
        return res;
    }
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
CryptMsg::CryptMsg(char *STRING, size_t LENGTH, Crypt *ctx) throw(CSPException) {
    HCERTSTORE hstore = NULL;
    DWORD temp = sizeof(DWORD);
    CRYPT_ALGORITHM_IDENTIFIER cai;
    memset(&cai, 0, sizeof(cai));

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
    printf("psi:%i\n", spsi);
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
    return res;
};


%}
