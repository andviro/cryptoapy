/* vim: ft=swig
*/
%inline %{
class CSPException {
public:
    int code;
    char msg[256];
    CSPException(const char *m) {
        code = GetLastError();
        strncpy(msg, m, 256);
    }
};

%}
