/* vim: ft=swig
*/

%inline %{
class Crypt {
public:
    HCRYPTPROV hprov = 0;
    Crypt(LPCSTR container, DWORD type, DWORD flags) throw(CSPException) {
        bool res = CryptAcquireContext(&hprov, container, NULL, type, flags);
        if (!res) {
            throw CSPException("Couldn't acquire context");
        }
        /*printf("New ctx %x\n", hprov);*/
    };
    ~Crypt() throw(CSPException) {
        if (hprov) {
            /*printf("Free ctx %x\n", hprov);*/
            bool res = CryptReleaseContext(hprov, 0);
            if (!res) {
                throw CSPException("Couldn't release context");
            }
        }
    };
};

%}
