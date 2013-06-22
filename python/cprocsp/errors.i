/* vim: ft=swig
*/
%typemap(throws) CSPException %{
  PyErr_SetString(PyExc_SystemError, $1.msg);
  SWIG_fail;
%}

%inline %{
class CSPException {
public:
    char msg[256];
    CSPException(const char *m, DWORD code=0) {
        if (!code)
            code = GetLastError();
        snprintf(msg, 256, "%s (0x%x)", m, code);
    }
};

%}
