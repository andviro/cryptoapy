// vim: ft=swig

%inline %{
#define MY_ENC_TYPE (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

/*class SignerIter {*/
    /*HCRYPTMSG hmsg;*/
/*public:*/
    /*bool iter;*/
    /*DWORD idx, maxidx;*/

    /*SignerIter(HCRYPTMSG hm, int num) : hmsg(hm), maxidx(num) {*/
        /*idx = 0;*/
    /*};*/

    /*SignerIter *__iter__() {*/
        /*return this;*/
    /*};*/

    /*virtual Cert *next() throw (Stop_Iteration) {*/
        /*PCERT_INFO psi;*/
        /*DWORD spsi;*/

        /*if (!iter) {*/
            /*puts("Stop iter");*/
            /*throw Stop_Iteration();*/
        /*}*/

        /*pSignerCertInfo = (PCERT_INFO) malloc(cbSignerCertInfo)*/

        /*pcert = CertEnumCertificatesInStore(hstore, pcert);*/
        /*if (pcert) {*/
            /*puts("Next iter");*/
            /*return new Cert(pcert);*/
        /*} else {*/
            /*iter = false;*/
            /*puts("Stop iter");*/
            /*throw Stop_Iteration();*/
        /*}*/
    /*};*/
/*};*/


class CryptMsg {
HCRYPTMSG hmsg;
public:
    CertStore *certs;
    DWORD num_signers;

    CryptMsg(char *STRING, size_t LENGTH) throw(CSPException) {
        HCERTSTORE hstore = NULL;
        DWORD temp = sizeof(DWORD);

        hmsg = CryptMsgOpenToDecode(MY_ENC_TYPE, 0, 0, NULL, NULL, NULL);
        if (!hmsg) {
            throw CSPException("Couldn't initialize message");
        }
        if (!CryptMsgUpdate(hmsg, (const BYTE *)STRING, LENGTH, 1)) {
            throw CSPException("Couldn't decode message");
        }
        hstore = CertOpenStore(CERT_STORE_PROV_MSG, MY_ENC_TYPE, NULL, 0, hmsg);
        if (!hstore) {
            throw CSPException("Couldn't open message certificate store");
        }
        certs = new CertStore(hstore);
        if (!CryptMsgGetParam(hmsg, CMSG_SIGNER_COUNT_PARAM, 0, &num_signers, &temp)) {
            throw CSPException("Couldn't get message signer count");
        }
    };

    ~CryptMsg() throw(CSPException) {
        if(hmsg && !CryptMsgClose(hmsg)) {
            throw CSPException("Couldn't close message");
        }

    };

};

%}
