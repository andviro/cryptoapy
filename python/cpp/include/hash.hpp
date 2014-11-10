#ifndef HASH_HPP_INCLUDED
#define HASH_HPP_INCLUDED

#include "common.hpp"
#include "rcobj.hpp"
#include "except.hpp"

class Crypt;
class Hash : public RCObj
{
private:
    HCRYPTHASH hhash;
    Crypt *parent;
    void init(Crypt *ctx) throw(CSPException);
protected:
    //
public:
    // инициализация хеша начальными данными
    Hash(Crypt *ctx, BYTE *STRING, DWORD LENGTH) throw(CSPException);
    // инициализация пустого хеша
    Hash(Crypt *ctx) throw(CSPException);

    virtual ~Hash() throw(CSPException);

    void digest(BYTE **s, DWORD *slen) throw(CSPException);
    void update(BYTE *STRING, DWORD LENGTH) throw(CSPException);
    void sign(DWORD dwKeyspec, BYTE **s, DWORD *slen) throw(CSPException);

    friend class Crypt;
};

#endif
