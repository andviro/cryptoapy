/* vim: ft=swig
*/

%module csp
%include "typemaps.i"

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
%include <WinCryptEx.h>
%include "errors.i"
%include "context.i"
%include "cert.i"
/*%include "hash.i"*/
/*%include "sign.i"*/
