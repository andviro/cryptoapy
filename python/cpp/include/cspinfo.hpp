#ifndef CSPINFO_HPP_INCLUDED
#define CSPINFO_HPP_INCLUDED
#include "common.hpp"
#include "except.hpp"
#include "context.hpp"

class CSPInfo
{
private:
    CSP_INFO *data;
public:
    CSPInfo(Crypt*) throw(CSPException);
    virtual ~CSPInfo();

    DWORD free_space();
    DWORD number_ul();
    DWORD number_signs();
    DWORD number_changes();
    DWORD number_kcards();
    DWORD number_keys();
    DWORD keys_remaining();
    DWORD time();
    void bytes(BYTE **s, DWORD *slen);
    WORD version();
};

#endif //CSPINFO_HPP_INCLUDED
