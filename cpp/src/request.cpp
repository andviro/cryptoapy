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
    //
    // XXX
    //
    LOG("    begin init extensions\n");
    ZeroMemory(attr_blobs, sizeof(attr_blobs));
    LOG("    zeroed %i of %i bytes of attr blobs\n", sizeof(attr_blobs), sizeof(CRYPT_ATTR_BLOB)*2);
    ext_attr.pszObjId = (LPSTR) szOID_CERT_EXTENSIONS;
    ext_attr.cValue = 1;
    ext_attr.rgValue = attr_blobs;

    LOG("    new exts\n");
    exts = new CertExtensions();
    LOG("    new eku\n");
    eku = new ExtKeyUsage();
    LOG("    new ku\n");
    ku = new KeyUsage();
    LOG("    add ku\n");
    exts->add(ku);
    LOG("    add eku\n");
    exts->add(eku);
    LOG("    set rgAttribute\n");
    CertReqInfo.cAttribute = 1;
    CertReqInfo.rgAttribute = &ext_attr;
}

void CertRequest::set_usage(BYTE usage) throw (CSPException) {
    ku -> set_usage(usage);
}

void CertRequest::reset_usage(BYTE usage) throw (CSPException) {
    ku -> reset_usage(usage);
}

void CertRequest::add_eku(LPCSTR oid) throw (CSPException) {
    eku -> add_usage_oid(oid);
}

CertRequest::~CertRequest() throw (CSPException) {
    LOG("CertRequest::~CertRequest(%p)\n", this);
    delete eku;
    delete ku;
    delete exts;

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
    exts->encode(&attr_blobs[0].pbData, &attr_blobs[0].cbData);

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

    free(attr_blobs[0].pbData);
    ZeroMemory(attr_blobs, sizeof(attr_blobs));

    if(!res) {
        throw CSPException("Couldn't encode certificate request");
    }
}
