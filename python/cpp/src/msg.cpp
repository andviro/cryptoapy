#include "common.hpp"
#include "msg.hpp"

using namespace std;
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)


HCRYPTMSG CryptMsg::get_handle() throw (CSPException) {
    LOG("CryptMsg::get_handle()\n");
    if (hmsg) {
        return hmsg;
    }
    hmsg = CryptMsgOpenToDecode(MY_ENC_TYPE, 0, 0, cprov? cprov->hprov:0, NULL, NULL);
    if (!hmsg) {
        throw CSPException("Couldn't open message for decode");
    }
    if ( !CryptMsgUpdate(hmsg, data, data_length, TRUE) ) {
        throw CSPException("Couldn't update message");
    }
    return hmsg;
}

int CryptMsg::num_signers() throw(CSPException) {
    LOG("CryptMsg::num_signers()\n");
    if (data && data_length) {
        return CryptGetMessageSignerCount(MY_ENCODING_TYPE, data, data_length);
    } else {
        return 0;
    }
}

bool CryptMsg::verify(DWORD n) throw(CSPException)
{
    CRYPT_VERIFY_MESSAGE_PARA VerifyParams;
    DWORD res, msg_size = 0;
    LOG("CryptMsg::verify(%lu)\n", n);

    // Initialize the VerifyParams data structure.
    ZeroMemory(&VerifyParams, sizeof(VerifyParams));
    VerifyParams.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
    VerifyParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
    if (cprov) {
        VerifyParams.hCryptProv = cprov->hprov;
    }

    res = CryptVerifyMessageSignature(
              &VerifyParams,
              n,
              data,
              data_length,
              NULL,
              &msg_size,
              NULL);
    LOG("    verification result: %lu, %lu\n", n, msg_size);
    return res && msg_size;
}

void CryptMsg::init(Crypt *ctx) throw(CSPException)
{
    cprov = ctx;
    data = NULL;
    data_length = 0;
    hmsg = 0;
    if (ctx) {
        ctx->ref();
    }
    LOG("    initialized msg: %p\n", this);

}

CryptMsg::CryptMsg(BYTE *STRING, DWORD LENGTH, Crypt *ctx) throw(CSPException)
{
    LOG("CryptMsg::CryptMsg(%p, %lu, %p)\n", STRING, LENGTH, ctx);
    init(ctx);
    data = new BYTE[LENGTH];
    data_length = LENGTH;
    memcpy(data, STRING, LENGTH);
};

CryptMsg::CryptMsg(Crypt *ctx) throw(CSPException)
{
    LOG("CryptMsg::CryptMsg(%p)\n", ctx);
    init(ctx);
}

void CryptMsg::add_recipient(Cert *c) throw(CSPException)
{
    if (c) {
        c->ref();
        recipients.push_back(c);
    }
}

void CryptMsg::encrypt_data(BYTE *STRING, DWORD LENGTH, BYTE **s, DWORD *slen) throw(CSPException)
{
    CRYPT_ALGORITHM_IDENTIFIER EncryptAlgorithm;
    CRYPT_ENCRYPT_MESSAGE_PARA EncryptParams;
    DWORD nrecs = recipients.size();
    PCCERT_CONTEXT *pRecipientCert = new PCCERT_CONTEXT[nrecs];
    vector<Cert *>::const_iterator cii;
    int i = 0;
    for(cii=recipients.begin(); cii!=recipients.end(); cii++) {
        pRecipientCert[i] = (*cii)->pcert;
    }

    // Инициализация структуры с нулем.
    memset(&EncryptAlgorithm, 0, sizeof(CRYPT_ALGORITHM_IDENTIFIER));
    //EncryptAlgorithm.pszObjId = OID_CipherVar_Default;
    EncryptAlgorithm.pszObjId = (LPSTR)szOID_CP_GOST_28147;

    // Инициализация структуры CRYPT_ENCRYPT_MESSAGE_PARA.
    memset(&EncryptParams, 0, sizeof(CRYPT_ENCRYPT_MESSAGE_PARA));
    EncryptParams.cbSize =  sizeof(CRYPT_ENCRYPT_MESSAGE_PARA);
    EncryptParams.dwMsgEncodingType = MY_ENCODING_TYPE;
    if (cprov) {
        EncryptParams.hCryptProv = cprov->hprov;
    }
    EncryptParams.ContentEncryptionAlgorithm = EncryptAlgorithm;

    // Вызов функции CryptEncryptMessage.
    if(!CryptEncryptMessage(
                &EncryptParams,
                nrecs,
                pRecipientCert,
                STRING,
                LENGTH,
                NULL,
                slen)) {
        DWORD err = GetLastError();
        delete[] pRecipientCert;
        throw CSPException("Getting EncrypBlob size failed.", err);
    }
    // Распределение памяти под возвращаемый BLOB.
    *s = (BYTE*)malloc(*slen);

    if(!*s) {
        DWORD err = GetLastError();
        delete[] pRecipientCert;
        throw CSPException("Memory allocation error while encrypting.", err);
    }

    // Повторный вызов функции CryptEncryptMessage для зашифрования содержимого.
    if(!CryptEncryptMessage(
                &EncryptParams,
                nrecs,
                pRecipientCert,
                STRING,
                LENGTH,
                *s,
                slen)) {
        DWORD err = GetLastError();
        delete[] pRecipientCert;
        free((void *)*s);
        throw CSPException("Encryption failed.", err);
    }
    delete[] pRecipientCert;
}

void CryptMsg::decrypt(BYTE **s, DWORD *slen, CertStore *store) throw(CSPException, CSPNotFound)
{
    CRYPT_DECRYPT_MESSAGE_PARA  decryptParams;
    //   Инициализация структуры CRYPT_DECRYPT_MESSAGE_PARA.
    memset(&decryptParams, 0, sizeof(CRYPT_DECRYPT_MESSAGE_PARA));
    decryptParams.cbSize = sizeof(CRYPT_DECRYPT_MESSAGE_PARA);
    decryptParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
    decryptParams.cCertStore = 1;
    decryptParams.rghCertStore = &store->hstore;

    //  Расшифрование сообщения

    //  Вызов фнукции CryptDecryptMessage для получения возвращаемого размера данных.
    if(!CryptDecryptMessage(
                &decryptParams,
                data,
                data_length,
                NULL,
                slen,
                NULL)) {
        DWORD err = GetLastError();
        switch (err) {
            case CRYPT_E_NO_DECRYPT_CERT:
                throw CSPNotFound( "No certificate for decryption", err);
            default:
                throw CSPException( "Error getting decrypted message size", err);
        }
    }

    // Выделение памяти под возвращаемые расшифрованные данные.
    *s = (BYTE*)malloc(*slen);
    if(!*s) {
        DWORD err = GetLastError();
        throw CSPException( "Memory allocation error while decrypting", err);
    }
    // Вызов функции CryptDecryptMessage для расшифрования данных.
    if(!CryptDecryptMessage(
                &decryptParams,
                data,
                data_length,
                *s,
                slen,
                NULL)) {
        DWORD err = GetLastError();
        free((void *)*s);
        throw CSPException( "Error decrypting the message", err);
    }
}

//void CryptMsg::add_signer(Cert *c) throw(CSPException)
//{
    //if (c) {
        //c->ref();
        //signers.push_back(c);
    //}
//}

bool CryptMsg::verify_cert(Cert *c) throw(CSPException)
{
    HCRYPTMSG hmsg = get_handle();
    return CryptMsgControl(hmsg, 0, CMSG_CTRL_VERIFY_SIGNATURE, c->pcert->pCertInfo);
}

DWORD CryptMsg::get_type() throw(CSPException)
{
    DWORD type = 0, temp = sizeof(DWORD);
    HCRYPTMSG hmsg = get_handle();
    if (!CryptMsgGetParam(hmsg, CMSG_TYPE_PARAM, 0, &type, &temp)) {
        throw CSPException("Couldn't get message type");
    }
    return type;
}

void CryptMsg::get_data(BYTE **s, DWORD *slen) throw(CSPException)
{
    HCRYPTMSG hmsg = get_handle();
    if(!CryptMsgGetParam(
                hmsg,                      /* Handle to the message*/
                CMSG_CONTENT_PARAM,        /* Parameter type*/
                0,                         /* Index*/
                NULL,             /* Pointer to the blob*/
                slen)) {
        /* Size of the blob*/
        throw CSPException("Couldn't get decoded data size");
    }
    *s = (BYTE *) malloc(*slen);
    if(!CryptMsgGetParam(
                hmsg,                      /* Handle to the message*/
                CMSG_CONTENT_PARAM,        /* Parameter type*/
                0,                         /* Index*/
                *s,             /* Pointer to the blob*/
                slen)) {
        /* Size of the blob*/
        free((void *)*s);
        throw CSPException("Couldn't get decoded data");
    }
}

void CryptMsg::sign_data(BYTE *STRING, DWORD LENGTH, BYTE **s, DWORD *slen, Cert *signer, bool detach) throw(CSPException)
{
    LOG("CryptMsg::sign_data(%p, %u, %p, %i)\n", STRING, LENGTH, signer, detach);
    CRYPT_SIGN_MESSAGE_PARA  SigParams;
    ZeroMemory(&SigParams, sizeof(SigParams));
    PCCERT_CONTEXT pCert = signer->pcert;

    const BYTE* DataArray[] = { STRING };
    DWORD SizeArray[] = { LENGTH };

    // Initialize the signature structure.
    SigParams.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
    SigParams.dwMsgEncodingType = MY_ENCODING_TYPE;
    SigParams.pSigningCert = pCert;
    //SigParams.HashAlgorithm.pszObjId = szOID_RSA_SHA1RSA;
    SigParams.HashAlgorithm.pszObjId = (LPSTR)szOID_CP_GOST_R3411;
    SigParams.HashAlgorithm.Parameters.cbData = 0;

    SigParams.cMsgCert = 1;
    SigParams.rgpMsgCert = &pCert;
    LOG("1\n");

    // First, get the size of the signed BLOB.
    if(!CryptSignMessage(
                &SigParams,
                detach,
                1,
                DataArray,
                SizeArray,
                NULL,
                slen)) {
        DWORD err = GetLastError();
        throw CSPException("Getting signed BLOB size failed", err);
    }
    LOG("2 %u\n", *slen);

    // Allocate memory for the signed BLOB.
    *s = (BYTE *)malloc(*slen);
    LOG("2a\n");
    if(!*s) {
        LOG("2b\n");
        DWORD err = GetLastError();
        LOG("2c\n");
        throw CSPException("Memory allocation error while signing", err);
    }
    LOG("3\n");

    // Get the signed message BLOB.
    if(!CryptSignMessage(
                &SigParams,
                detach,
                1,
                DataArray,
                SizeArray,
                *s,
                slen)) {
        DWORD err = GetLastError();
        free((void *)*s);
        throw CSPException("Error getting signed BLOB", err);
    }
    LOG("4\n");
}

CryptMsg::~CryptMsg() throw(CSPException)
{
    LOG("CryptMsg::~CryptMsg(%p)\n", this);
    vector<Cert *>::const_iterator cii;
    //for(cii=signers.begin(); cii!=signers.end(); cii++) {
        //if (*cii)
            //(*cii)->unref();
    //}
    for(cii=recipients.begin(); cii!=recipients.end(); cii++) {
        if (*cii)
            (*cii)->unref();
    }
    if (cprov) {
        cprov->unref();
    }
    if (data) {
        delete[] data;
    }
    if (hmsg && !CryptMsgClose(hmsg)) {
        throw CSPException("Couldn't close message");
    }

};