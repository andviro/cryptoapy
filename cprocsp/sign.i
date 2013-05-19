/* vim: ft=swig
*/
%inline %{

class Signature : public CryptMsg {
    BYTE *raw_msg;
    DWORD raw_size;
public:
    Signature(char *STRING, size_t LENGTH, Crypt *ctx=NULL)
        throw(CSPException) : CryptMsg(STRING, LENGTH, ctx)
    {
        raw_msg = (BYTE *)malloc(LENGTH);
        memcpy(raw_msg, STRING, LENGTH);
        raw_size = LENGTH;
    }

    bool verify_data(char *STRING, size_t LENGTH, int n) throw(CSPException) {
        CRYPT_VERIFY_MESSAGE_PARA msg_para;
        msg_para.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
        msg_para.dwMsgAndCertEncodingType = MY_ENC_TYPE;
        msg_para.hCryptProv = NULL;
        msg_para.pfnGetSignerCertificate = NULL;
        msg_para.pvGetArg = NULL;
        return CryptVerifyDetachedMessageSignature(&msg_para, n, raw_msg,
            raw_size, 1, (const BYTE **)&STRING, (DWORD *)&LENGTH, NULL);
    }

    ~Signature() throw(CSPException) {
        if (raw_msg) {
            free(raw_msg);
        }
    }
};

%}
