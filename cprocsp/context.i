/* vim: ft=swig
*/
%feature("ref") Crypt "$this->ref();"
%feature("unref") Crypt "$this->unref();"
%newobject Crypt::get_sign_key;
%newobject Crypt::import_key;

%inline %{
class Key;

class Crypt {
    int refcount;
public:
    HCRYPTPROV hprov;
    Crypt(LPCSTR container, DWORD type, DWORD flags) throw(CSPException) {
        refcount = 0;
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

    int ref() {
        refcount++;
        return refcount;
    }

    int unref() {
        refcount--;
        if (refcount <= 0) {
            delete this;
            return 0;
        }
        return refcount;
    }

    Key *get_sign_key() throw(CSPException);
    Key *import_key(char *STRING, size_t LENGTH, Key *decrypt=NULL) throw(CSPException);
};

%}

