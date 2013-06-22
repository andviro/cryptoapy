#ifndef MSG_HPP_INCLUDED
#define MSG_HPP_INCLUDED

#include "context.hpp"
#include "except.hpp"
#include "cert.hpp"

class SignerIter;
class CryptMsg : public RCObj
{
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

    bool verify_cert(Cert *c) throw(CSPException);
    void get_data(BYTE **s, DWORD *slen) throw(CSPException);
    void add_signer_cert(Cert *c) throw(CSPException);
    void add_recipient_cert(Cert *c) throw(CSPException);
    void encrypt_data(BYTE *STRING, DWORD LENGTH, BYTE **s, DWORD *slen) throw(CSPException);
    void decrypt_data(BYTE *STRING, DWORD LENGTH, BYTE **s, DWORD *slen) throw(CSPException);
    virtual void sign_data(BYTE *STRING, DWORD LENGTH, BYTE **s, DWORD *slen, bool detach=0) throw(CSPException);

    friend class SignerIter;
    friend class CertStore;
};

class SignerIter
{
private:
    CryptMsg *owner;
    DWORD idx;
public:

    SignerIter(CryptMsg* o);

    virtual ~SignerIter() {
        if (owner) {
            owner->unref();
        }
    }

    SignerIter *__iter__();

    virtual Cert *next() throw (Stop_Iteration, CSPException);
};

#endif
