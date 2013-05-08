/* vim: ft=swig
*/

%module csp
%include "typemaps.i"

%define ZEROED_STRUCT(type)
%extend type {
_ ## type() {
    size_t sz = sizeof(type);
    type *res = malloc(sz);
    memset(res, 0, sz);
    res->cbSize = sz;
    return res;
}
};
%enddef

%{
#include <stdio.h>
#ifdef _WIN32
#   include <windows.h>
#   include <wincrypt.h>
#else
#   include <stdlib.h>
#   include <string.h>
#   include <CSP_WinDef.h>
#   include <CSP_WinCrypt.h>
#endif
#include <WinCryptEx.h>
%}

%include "wintypes.i"
%include "defines.i"
%include "common.i"
%include <WinCryptEx.h>
%include "errors.i"
%include "context.i"
%include "cert.i"
%include "msg.i"
/*%include "hash.i"*/
/*%include "sign.i"*/
