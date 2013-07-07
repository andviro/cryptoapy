#include "common.hpp"
#include "sign.hpp"

bool Signature::verify_data(BYTE *STRING, DWORD LENGTH, int n) throw(CSPException)
{
    CRYPT_VERIFY_MESSAGE_PARA msg_para;
    msg_para.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
    msg_para.dwMsgAndCertEncodingType = MY_ENC_TYPE;
    msg_para.hCryptProv = 0;
    msg_para.pfnGetSignerCertificate = NULL;
    msg_para.pvGetArg = NULL;
    return CryptVerifyDetachedMessageSignature(&msg_para, n, data,
            data_length, 1, (const BYTE **)&STRING, (DWORD *)&LENGTH, NULL);
}
