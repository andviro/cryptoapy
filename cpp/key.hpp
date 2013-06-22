#ifndef KEY_HPP_INCLUDED
#define KEY_HPP_INCLUDED

#include "context.hpp"
#include "except.hpp"

class Key
{
    HCRYPTKEY hkey;
    Crypt *parent;
public:
    Key(Crypt *pctx, HCRYPTKEY hk) throw(CSPException);

    ~Key() throw(CSPException);

    void encode(BYTE **s, DWORD *slen, Key *cryptkey=NULL) throw(CSPException);

    friend class Crypt;
};

#endif
