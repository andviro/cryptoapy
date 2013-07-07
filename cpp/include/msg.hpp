#ifndef MSG_HPP_INCLUDED
#define MSG_HPP_INCLUDED

#include "context.hpp"
#include "except.hpp"
#include "cert.hpp"
#include <vector>

class SignerIter;
class CryptMsg : public RCObj
{
private:
    Crypt *cprov;
    std::vector<Cert *> signers;
    std::vector<Cert *> recipients;
    void init(Crypt *ctx) throw(CSPException);
protected:
    BYTE *data;
    DWORD data_length;
public:
    // инициализация сообщения для декодирования
    CryptMsg(BYTE *STRING, DWORD LENGTH, Crypt *ctx=NULL) throw(CSPException);

    // инициализация сообщения для кодирования
    CryptMsg(Crypt *ctx=NULL) throw(CSPException);

    virtual ~CryptMsg() throw(CSPException);
    bool verify_cert(Cert *c) throw(CSPException);
    void get_data(BYTE **s, DWORD *slen) throw(CSPException);
    void add_signer_cert(Cert *c) throw(CSPException);
    void add_recipient_cert(Cert *c) throw(CSPException);
    void encrypt_data(BYTE *STRING, DWORD LENGTH, BYTE **s, DWORD *slen) throw(CSPException);
    void decrypt_data(BYTE *STRING, DWORD LENGTH, BYTE **s, DWORD *slen) throw(CSPException);
    virtual void sign_data(BYTE *STRING, DWORD LENGTH, BYTE **s, DWORD *slen,
            Cert *signer, bool detach=0) throw(CSPException);
    bool verify_sign(int n) throw(CSPException);

    friend class CertStore;
};

#endif
