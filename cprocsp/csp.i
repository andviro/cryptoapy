/* vim: ft=swig
*/
%define DOCSTRING
"

"
%enddef

%module(docstring=DOCSTRING) csp
%include "typemaps.i"
%include "exception.i"
%include "cstring.i"
%feature("autodoc", "2");


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
%include "extra_defs.i"
%include "common.i"
%include "errors.i"
%include "context.i"
%include "cert.i"
%include "msg.i"
%include "sign.i"
/*%include "hash.i"*/
