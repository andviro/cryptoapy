/* vim: ft=swig
*/

%module csp
%include "typemaps.i"
%include "exception.i"
%include "cstring.i"

/*%define ZEROED_STRUCT(type)*/
/*%extend type {*/
/*_ ## type() {*/
    /*size_t sz = sizeof(type);*/
    /*type *res = (type) malloc(sz);*/
    /*memset(res, 0, sz);*/
    /*res->cbSize = sz;*/
    /*return res;*/
/*}*/
/*};*/
/*%enddef*/

%inline %{
class Stop_Iteration {
};
%}


%typemap(throws) Stop_Iteration %{
  PyErr_SetNone(PyExc_StopIteration);
  SWIG_fail;
%}

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
%{
#define MY_ENC_TYPE (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
%}
%include "context.i"
%include "cert.i"
%include "msg.i"
/*%include "hash.i"*/
/*%include "sign.i"*/
