#include "common.hpp"
#include "cspinfo.hpp"

// XXX нужно автоопределение необходимости этого
//
inline WORD Reverse16(WORD value)
{
    return (((value & 0x00FF) << 8) |
            ((value & 0xFF00) >> 8));
}

inline DWORD Reverse32(DWORD value) 
{
    return (((value & 0x000000FF) << 24) |
            ((value & 0x0000FF00) <<  8) |
            ((value & 0x00FF0000) >>  8) |
            ((value & 0xFF000000) >> 24));
}

CSPInfo::CSPInfo(Crypt *c) throw(CSPException) {
    LOG("Crypt.prov_info()\n");
    if (c == NULL) {
        return;
    }
    DWORD slen;

    if(!CryptGetProvParam( c->hprov, PP_INFO, NULL, &slen, 0)) {
        throw CSPException("CSPInfo: Couldn't determine provider info length");
    }
    if (slen < CSP_INFO_SIZE) {
        throw CSPException("CSPInfo: Structure size too small");
    }

    data = new CSP_INFO;

    if(!CryptGetProvParam( c->hprov, PP_INFO, (BYTE *)data, &slen, 0)) {
        delete data;
        throw CSPException("CSPInfo: Couldn't get provider info");
    }
}

CSPInfo::~CSPInfo() {
    if (data != NULL) {
        delete data;
    }
}

void CSPInfo::bytes(BYTE **s, DWORD *slen) {
    *slen = (DWORD) CSP_INFO_SIZE;
    *s = (BYTE *)malloc(*slen);
    memcpy((void *)*s, (void *)data, *slen);
}

DWORD CSPInfo::free_space() {
    if (data == NULL) {
        return -1;
    }
    return Reverse32(data->future[CSP_INFO_FREE_SPACE]);
}

DWORD CSPInfo::number_ul() {
    if (data == NULL) {
        return -1;
    }
    return Reverse32(data->future[CSP_INFO_NUMBER_UL]);
}

DWORD CSPInfo::number_signs() {
    if (data == NULL) {
        return -1;
    }
    return Reverse32(data->future[CSP_INFO_NUMBER_SIGNS]);
}

DWORD CSPInfo::number_changes() {
    if (data == NULL) {
        return -1;
    }
    return Reverse32(data->future[CSP_INFO_KCARDS_CHANGES]);
}

DWORD CSPInfo::number_kcards() {
    if (data == NULL) {
        return -1;
    }
    return Reverse32(data->future[CSP_INFO_NUMBER_KCARDS]);
}

DWORD CSPInfo::number_keys() {
    if (data == NULL) {
        return -1;
    }
    return Reverse32(data->future[CSP_INFO_NUMBER_KEYS]);
}

DWORD CSPInfo::keys_remaining() {
    if (data == NULL) {
        return -1;
    }
    return Reverse32(data->keys_remaining);
}


DWORD CSPInfo::time() {
    if (data == NULL) {
        return -1;
    }
    return Reverse32(data->time);
}

WORD CSPInfo::version() {
    if (data == NULL) {
        return -1;
    }
    return Reverse16(data->version);
}
