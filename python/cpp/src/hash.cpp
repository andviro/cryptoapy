#include "hash.hpp"
#include "context.hpp"

void Hash::init(Crypt *ctx) throw(CSPException)
{
    parent = ctx;
    parent->ref();
    if(!CryptCreateHash(
        parent->hprov, // hProv
        CALG_GR3411, 
        0, 
        0, 
        &hhash)) 
    {
        throw CSPException("Hash::init() failed");
    }
}


Hash::Hash(Crypt *ctx, BYTE *STRING, DWORD LENGTH) throw(CSPException)
{
    init(ctx);
    this->update(STRING, LENGTH);
}

Hash::Hash(Crypt *ctx) throw(CSPException)
{
    init(ctx);
}

Hash::~Hash() throw(CSPException)
{
    if (hhash && !CryptDestroyHash(hhash)) {
        throw CSPException("~Hash: Couldn't release handle");
    }
    parent->unref();
}

void Hash::digest(BYTE **s, DWORD *slen) throw(CSPException) 
{
    DWORD n = sizeof(DWORD);
    if (!CryptGetHashParam(hhash, HP_HASHSIZE, (PBYTE)slen, &n, 0)) {
        throw CSPException("Hash.digest(): Couldn't determine hash size");
    }
    *s = (BYTE*)malloc(*slen);
    if (!CryptGetHashParam(hhash, HP_HASHVAL, *s, slen, 0)) {
        DWORD err = GetLastError();
        free((void *)*s);
        throw CSPException("Hash.digest(): Couldn't get hash value", err);
    }
}

void Hash::update(BYTE *STRING, DWORD LENGTH) throw(CSPException)
{
    if(!CryptHashData(
        hhash, 
        STRING, 
        LENGTH, 
        0)) 
    {
        throw CSPException("Hash::update() failed");
    }
}
