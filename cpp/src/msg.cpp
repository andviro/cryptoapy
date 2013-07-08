#include "common.hpp"
#include "msg.hpp"

using namespace std;
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)


int CryptMsg::num_signers() throw(CSPException) {
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
    LOG("CryptMsg::verify_sign(%lu)\n", n);

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
    if (ctx) {
        ctx->ref();
    }
    data = NULL;
    data_length = 0;
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
    EncryptAlgorithm.pszObjId = szOID_CP_GOST_28147;

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
    printf("slen: %i\n", *slen);

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
        throw CSPException("Encryption failed.", err);
    }
    printf("slen: %i\n", *slen);
    delete[] pRecipientCert;
}

void CryptMsg::decrypt(BYTE **s, DWORD *slen) throw(CSPException)
{
    HCERTSTORE hStoreHandle = 0;      // дескриптор хранилища сертификатов
    hStoreHandle = CertOpenSystemStore(cprov? cprov->hprov:0, "MY");
    if(!hStoreHandle) {
        throw CSPException( "Error getting store handle.");
    }

    CRYPT_DECRYPT_MESSAGE_PARA  decryptParams;
    //   Инициализация структуры CRYPT_DECRYPT_MESSAGE_PARA.
    memset(&decryptParams, 0, sizeof(CRYPT_DECRYPT_MESSAGE_PARA));
    decryptParams.cbSize = sizeof(CRYPT_DECRYPT_MESSAGE_PARA);
    decryptParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
    decryptParams.cCertStore = 1;
    decryptParams.rghCertStore = &hStoreHandle;

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
        CertCloseStore( hStoreHandle, CERT_CLOSE_STORE_FORCE_FLAG );
        throw CSPException( "Error getting decrypted message size", err);
    }

    // Выделение памяти под возвращаемые расшифрованные данные.
    *s = (BYTE*)malloc(*slen);
    if(!*s) {
        DWORD err = GetLastError();
        CertCloseStore( hStoreHandle, CERT_CLOSE_STORE_FORCE_FLAG );
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
        CertCloseStore( hStoreHandle, CERT_CLOSE_STORE_FORCE_FLAG );
        free(*s);
        throw CSPException( "Error decrypting the message", err);
    }
    CertCloseStore( hStoreHandle, CERT_CLOSE_STORE_FORCE_FLAG );
}

//void CryptMsg::add_signer_cert(Cert *c) throw(CSPException)
//{
    //if (c) {
        //c->ref();
        //signers.push_back(c);
    //}
//}

void CryptMsg::get_data(BYTE **s, DWORD *slen) throw(CSPException)
{
}

void CryptMsg::sign_data(BYTE *STRING, DWORD LENGTH, BYTE **s, DWORD *slen, Cert *signer, bool detach) throw(CSPException)
{
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
    SigParams.HashAlgorithm.pszObjId = szOID_CP_GOST_R3411;
    SigParams.HashAlgorithm.Parameters.cbData = 0;

    SigParams.cMsgCert = 1;
    SigParams.rgpMsgCert = &pCert;

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

    // Allocate memory for the signed BLOB.
    *s = (BYTE *)malloc(*slen);
    if(!*s) {
        DWORD err = GetLastError();
        throw CSPException("Memory allocation error while signing", err);
    }

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
        throw CSPException("Error getting signed BLOB", err);
    }
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
};
