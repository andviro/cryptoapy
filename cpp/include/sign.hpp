#ifndef SIGN_HPP_INCLUDED
#define SIGN_HPP_INCLUDED

#include "msg.hpp"

class Signature : public CryptMsg
{
    BYTE *raw_msg;
    DWORD raw_size;
public:
    Signature(Crypt *ctx=NULL) throw(CSPException) : CryptMsg(ctx) {
        raw_size = 0;
        raw_msg = NULL;
    }

    Signature(BYTE *STRING, DWORD LENGTH, Crypt *ctx=NULL) throw(CSPException);

    bool verify_data(BYTE *STRING, DWORD LENGTH, int n) throw(CSPException);

    void sign_data(BYTE *STRING, DWORD LENGTH, BYTE **s, DWORD *slen, bool detach=1) throw(CSPException) {
        CryptMsg::sign_data(STRING, LENGTH, s, slen, detach);
    }

    virtual ~Signature() throw(CSPException);
};

#endif
