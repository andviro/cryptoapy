#include "common.hpp"
#include "context.hpp"
#include "request.hpp"
#include "ext.hpp"
#include <vector>

using namespace std;


CertRequest::CertRequest(Crypt *ctx, BYTE *STRING, DWORD LENGTH) throw (CSPException) : ctx(ctx) {
    LOG("CertRequest::CertRequest(%p, %s)\n", ctx, STRING);
    if (ctx) {
        ctx -> ref();
    } else {
        throw CSPException("Null key container can not generate requests", -1);
    }
    cbNameEncoded = 0;
    pbNameEncoded = NULL;

    ZeroMemory(&CertReqInfo, sizeof(CertReqInfo));
    CertReqInfo.dwVersion = CERT_REQUEST_V1;

    ZeroMemory(&SigAlg, sizeof(SigAlg));
    SigAlg.pszObjId = (char *)szOID_CP_GOST_R3411_R3410EL;

    pbPublicKeyInfo = NULL;
    bool res = CryptExportPublicKeyInfo( ctx->hprov, AT_KEYEXCHANGE, MY_ENC_TYPE,
            NULL, &cbPublicKeyInfo );
    if (!res) {
        throw CSPException("Couldn't determine exported key info length");
    }
    pbPublicKeyInfo = (CERT_PUBLIC_KEY_INFO*) malloc( cbPublicKeyInfo );
    res = CryptExportPublicKeyInfo( ctx->hprov, AT_KEYEXCHANGE,
                              MY_ENC_TYPE, pbPublicKeyInfo, &cbPublicKeyInfo );
    if (!res) {
        throw CSPException("Couldn't export public key info");
    }
    CertReqInfo.SubjectPublicKeyInfo = *pbPublicKeyInfo;
    if (STRING && LENGTH) {
        set_name(STRING, LENGTH);
    }
    CertReqInfo.cAttribute = 0;
    CertReqInfo.rgAttribute = NULL;
}

CertRequest::~CertRequest() throw (CSPException) {
    LOG("CertRequest::~CertRequest(%p)\n", this);
    if (ctx) {
        ctx -> unref();
    }
    if (CertReqInfo.Subject.pbData) {
        free(CertReqInfo.Subject.pbData);
    }
    if (pbPublicKeyInfo) {
        free(pbPublicKeyInfo);
    }
}

void CertRequest::set_name(BYTE *STRING, DWORD LENGTH) throw (CSPException) {
    LOG("CertRequest::set_name(%s)\n", STRING);

    bool res = CertStrToName(
        MY_ENC_TYPE,
        (LPCSTR) STRING,
        //CERT_OID_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
        CERT_OID_NAME_STR,
        NULL,
        NULL,
        &CertReqInfo.Subject.cbData,
        NULL );
    if(!res) {
        throw CSPException("Couldn't determine encoded name length");
    }

    if (CertReqInfo.Subject.pbData) {
        free(CertReqInfo.Subject.pbData);
        CertReqInfo.Subject.pbData = NULL;
    }

    CertReqInfo.Subject.pbData = (BYTE *)malloc(CertReqInfo.Subject.cbData);

    res = CertStrToName(
        MY_ENC_TYPE,
        (LPCSTR) STRING,
        //CERT_OID_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
        CERT_OID_NAME_STR,
        NULL,
        CertReqInfo.Subject.pbData,
        &CertReqInfo.Subject.cbData,
        NULL );
    if(!res) {
        throw CSPException("Couldn't encode subject name string");
    }
}

void CertRequest::get_data(BYTE **s, DWORD *slen) throw (CSPException) {
    //
    // XXX
    //
    LOG("CertRequest::get_data()\n");

    bool res = CryptSignAndEncodeCertificate(
        ctx->hprov, AT_KEYEXCHANGE, MY_ENC_TYPE,
        X509_CERT_REQUEST_TO_BE_SIGNED, &CertReqInfo,
        &SigAlg, NULL, NULL, slen );
    if(!res) {
        throw CSPException("Couldn't determine encoded request size");
    }

    *s = (BYTE *)malloc(*slen);

    res = CryptSignAndEncodeCertificate(
        ctx->hprov, AT_KEYEXCHANGE, MY_ENC_TYPE,
        X509_CERT_REQUEST_TO_BE_SIGNED, &CertReqInfo,
        &SigAlg, NULL, *s, slen );

    if(!res) {
        throw CSPException("Couldn't encode certificate request");
    }
}
