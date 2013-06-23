#ifndef EXCEPT_HPP_INCLUDED
#define EXCEPT_HPP_INCLUDED

class CSPException {
public:
    char msg[256];
    CSPException(const char *m, DWORD code=0);
};

class Stop_Iteration {
};

#endif
