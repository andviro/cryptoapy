#include "common.hpp"
#include "context.hpp"
#include "request.hpp"

CertRequest::CertRequest(Crypt *ctx, BYTE *STRING, DWORD LENGTH) throw (CSPException) : ctx(ctx) {
    if (ctx)
        ctx -> ref();
    cbNameEncoded = 0;
    pbNameEncoded = NULL;

    ZeroMemory(&CertReqInfo, sizeof(CertReqInfo));
    CertReqInfo.dwVersion = CERT_REQUEST_V1;

    ZeroMemory(&SigAlg, sizeof(SigAlg));
    SigAlg.pszObjId = (char *)szOID_CP_GOST_R3411_R3410EL;

    pbPublicKeyInfo = NULL;
    bool res = CryptExportPublicKeyInfo( ctx->hprov, AT_SIGNATURE, MY_ENC_TYPE,
            NULL, &cbPublicKeyInfo );
    if (!res) {
        throw CSPException("Couldn't determine exported key info length");
    }
    pbPublicKeyInfo = (CERT_PUBLIC_KEY_INFO*) malloc( cbPublicKeyInfo );
    res = CryptExportPublicKeyInfo( ctx->hprov, AT_SIGNATURE,
                              MY_ENC_TYPE, pbPublicKeyInfo, &cbPublicKeyInfo );
    if (!res) {
        throw CSPException("Couldn't export public key info");
    }
    CertReqInfo.SubjectPublicKeyInfo = *pbPublicKeyInfo;
    if (STRING && LENGTH) {
        set_name(STRING, LENGTH);
    }

    ZeroMemory(&CertEnhKeyUsage, sizeof(CertEnhKeyUsage));
    //set_usage();
}

CertRequest::~CertRequest() throw (CSPException) {
    if (ctx) {
        ctx -> unref();
    }
    if (pbNameEncoded) {
        delete[] pbNameEncoded;
    }
    if (pbPublicKeyInfo) {
        free(pbPublicKeyInfo);
    }
    if (CertEnhKeyUsage.rgpszUsageIdentifier) {
        free(CertEnhKeyUsage.rgpszUsageIdentifier);
    }
}

void CertRequest::set_usage(bool auth, bool sign, bool encrypt) throw (CSPException) {
    if (CertEnhKeyUsage.rgpszUsageIdentifier) {
        free(CertEnhKeyUsage.rgpszUsageIdentifier);
        CertEnhKeyUsage.rgpszUsageIdentifier = NULL;
    }
    CertEnhKeyUsage.cUsageIdentifier = 0;
    if (auth) {
        CertEnhKeyUsage.rgpszUsageIdentifier = (LPSTR*)realloc(CertEnhKeyUsage.rgpszUsageIdentifier,
                sizeof(LPSTR)*(CertEnhKeyUsage.cUsageIdentifier + 1));
        CertEnhKeyUsage.rgpszUsageIdentifier[CertEnhKeyUsage.cUsageIdentifier] = szOID_PKIX_KP_CLIENT_AUTH;
        CertEnhKeyUsage.cUsageIdentifier++;
    }
}


void CertRequest::set_name(BYTE *STRING, DWORD LENGTH) throw (CSPException) {
    bool res = CertStrToName(
        MY_ENC_TYPE,
        (LPCSTR) STRING,
        //CERT_OID_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
        CERT_OID_NAME_STR,
        NULL,
        NULL,
        &cbNameEncoded,
        NULL );
    if(!res) {
        throw CSPException("Couldn't determine encoded name length");
    }

    if (pbNameEncoded) {
        delete[] pbNameEncoded;
        pbNameEncoded = NULL;
    }
    
    pbNameEncoded = new BYTE[cbNameEncoded];
    res = CertStrToName(
        MY_ENC_TYPE,
        (LPCSTR) STRING,
        //CERT_OID_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
        CERT_OID_NAME_STR,
        NULL,
        pbNameEncoded,
        &cbNameEncoded,
        NULL );
    if(!res) {
        throw CSPException("Couldn't encode subject name string");
    }
    CertReqInfo.Subject.cbData = cbNameEncoded;
    CertReqInfo.Subject.pbData = pbNameEncoded;
}

void CertRequest::get_data(BYTE **s, DWORD *slen) throw (CSPException) {
    bool res = CryptSignAndEncodeCertificate(
        ctx->hprov, AT_SIGNATURE, MY_ENC_TYPE,
        X509_CERT_REQUEST_TO_BE_SIGNED, &CertReqInfo,
        &SigAlg, NULL, NULL, slen );
    if(!res) {
        throw CSPException("Couldn't determine encoded request size");
    }

    *s = (BYTE *)malloc(*slen);

    res = CryptSignAndEncodeCertificate(
        ctx->hprov, AT_SIGNATURE, MY_ENC_TYPE,
        X509_CERT_REQUEST_TO_BE_SIGNED, &CertReqInfo,
        &SigAlg, NULL, *s, slen );

    if(!res) {
        throw CSPException("Couldn't encode certificate request");
    }
}

/*
 *
 *
 *
 *
 *
CERT_EXTENSION CertExtEnhKeyUsage = {0};
bResult = CryptEncodeObject(MY_ENCODING_TYPE,
X509_ENHANCED_KEY_USAGE,
(LPVOID)&CertEnhKeyUsage,
NULL,
&CertExtEnhKeyUsage.Value.cbData);
CertExtEnhKeyUsage.Value.pbData = (LPBYTE)malloc(CertExtEnhKeyUsage.Value.cbData);
//кодируем
bResult = CryptEncodeObject(MY_ENCODING_TYPE,
X509_ENHANCED_KEY_USAGE,
(LPVOID)&CertEnhKeyUsage,
CertExtEnhKeyUsage.Value.pbData,
&CertExtEnhKeyUsage.Value.cbData);

free(CertEnhKeyUsage.rgpszUsageIdentifier);

CERT_EXTENSIONS CertExtentions;
CertExtEnhKeyUsage.pszObjId = szOID_ENHANCED_KEY_USAGE;
CertExtEnhKeyUsage.fCritical = FALSE;
CertExtentions.cExtension = 1;
CertExtentions.rgExtension = &CertExtEnhKeyUsage;

CRYPT_ATTR_BLOB CertAttrBlob = {0, NULL};
bResult = CryptEncodeObject(
MY_ENCODING_TYPE,
szOID_CERT_EXTENSIONS,
&CertExtentions,
NULL,
&CertAttrBlob.cbData);

CertAttrBlob.pbData = (LPBYTE)malloc(CertAttrBlob.cbData);
bResult = CryptEncodeObject(
MY_ENCODING_TYPE,
szOID_CERT_EXTENSIONS,
&CertExtentions,
CertAttrBlob.pbData,
&CertAttrBlob.cbData);

free(CertExtEnhKeyUsage.Value.pbData);

CRYPT_ATTRIBUTE rgAttrib = {szOID_CERT_EXTENSIONS, 1, &CertAttrBlob};
CertReqInfo.cAttribute = 1;
CertReqInfo.rgAttribute = &rgAttrib;
//
//
//
//
//
//
//
//
void Cert::request() throw(CSPException)
{

    //
    // fill CERT_PRIVATE_KEY_VALIDITY
    //
    FILETIME ftBegin(...), ftEnd(...);
    CERT_PRIVATE_KEY_VALIDITY CertPrivateKeyValitity;
    CertPrivateKeyValitity.NotBefore = ftBegin;
    CertPrivateKeyValitity.NotAfter = ftEnd;

    // fill CRYPT_BIT_BLOB
    BYTE bRepudiation[2] = {(CERT_NON_REPUDIATION_KEY_USAGE | CERT_DIGITAL_SIGNATURE_KEY_USAGE | CERT_DATA_ENCIPHERMENT_KEY_USAGE), 0};

    CRYPT_BIT_BLOB CryptBitBlob;
    CryptBitBlob.cbData = 2;
    CryptBitBlob.pbData = bRepudiation;
    CryptBitBlob.cUnusedBits = 0;

    DWORD dwHashSize(0);
    bReturn = CryptHashPublicKeyInfo(hCryptProv, CALG_SHA1, 0, PKCS_7_ASN_ENCODING, pbPublicKeyInfo, NULL, &dwHashSize);

    BYTE* pbHashVal = new BYTE[dwHashSize];
    bReturn = CryptHashPublicKeyInfo(hCryptProv, CALG_SHA1, 0, PKCS_7_ASN_ENCODING, pbPublicKeyInfo, pbHashVal, &dwHashSize);


    // fill CRYPT_DATA_BLOB
    CRYPT_DATA_BLOB CryptDataBlob;
    CryptDataBlob.cbData = dwHashSize;
    CryptDataBlob.pbData = pbHashVal;

    // fill CERT_KEY_ATTRIBUTES_INFO
    CERT_KEY_ATTRIBUTES_INFO CertKeyAttrInfo;
    CertKeyAttrInfo.pPrivateKeyUsagePeriod = &CertPrivateKeyValitity;
    CertKeyAttrInfo.IntendedKeyUsage = CryptBitBlob;
    CertKeyAttrInfo.KeyId = CryptDataBlob;


    DWORD cbKeyAttrEncoded(0);

    bReturn = CryptEncodeObject(
    PKCS_7_ASN_ENCODING // Encoding type
    , X509_KEY_ATTRIBUTES // Structure type
    , &CertKeyAttrInfo // Address of CERT_KEY_ATTRIBUTES_INFO structure
    , NULL // pbEncoded
    , &cbKeyAttrEncoded); // pbEncoded size


    //-------------------------------------------------------------------
    // Allocate memory for the encoded struct.
    BYTE* pbKeyAttrEncoded(NULL);

    pbKeyAttrEncoded = (BYTE*)malloc(cbKeyAttrEncoded);

    //-------------------------------------------------------------------
    // Call CryptEncodeObject to do the actual encoding of the struct.

    bReturn = CryptEncodeObject(
    PKCS_7_ASN_ENCODING // Encoding type
    , X509_KEY_ATTRIBUTES // Structure type
    , &CertKeyAttrInfo // Address of CERT_KEY_ATTRIBUTES_INFO structure
    , pbKeyAttrEncoded // pbEncoded
    , &cbKeyAttrEncoded); // pbEncoded size



    // fill CRYPTOAPI_BLOB
    CRYPT_OBJID_BLOB CryptObjidBlob;
    CryptObjidBlob.cbData = cbKeyAttrEncoded;
    CryptObjidBlob.pbData = pbKeyAttrEncoded;


    CERT_EXTENSION CertExtension[] =
    {
    {
    szOID_KEY_ATTRIBUTES,
    TRUE,
    CryptObjidBlob
    }
    };


    CERT_EXTENSIONS CertExtensions;
    CertExtensions.cExtension = 1;
    CertExtensions.rgExtension = &CertExtension[0];


    DWORD cbCertExtensionsEncoded(0);

    bReturn = CryptEncodeObject(
    PKCS_7_ASN_ENCODING // Encoding type
    , X509_EXTENSIONS // Structure type
    , &CertExtensions // Address of CERT_EXTENSIONS structure
    , NULL // pbEncoded
    , &cbCertExtensionsEncoded); // pbEncoded size

    //-------------------------------------------------------------------
    // Allocate memory for the encoded struct.
    BYTE* pbCertExtensionsEncoded(NULL);

    pbCertExtensionsEncoded = (BYTE*)malloc(cbCertExtensionsEncoded);

    //-------------------------------------------------------------------
    // Call CryptEncodeObject to do the actual encoding of the struct.

    bReturn = CryptEncodeObject(
    PKCS_7_ASN_ENCODING // Encoding type
    , X509_EXTENSIONS // Structure type
    , &CertExtensions // Address of CERT_EXTENSIONS structure
    , pbCertExtensionsEncoded // pbEncoded
    , &cbCertExtensionsEncoded); // pbEncoded size
    ////////////////////////////////////////////////////////////////////////

    // fill CRYPTOAPI_BLOB
    CRYPT_ATTR_BLOB AttributesBlobArr[] =
    {
    {
    cbCertExtensionsEncoded,
    pbCertExtensionsEncoded
    }
    };

    // fill CRYPT_ATTRIBUTE
    CRYPT_ATTRIBUTE CryptAttribute;
    CryptAttribute.pszObjId = szOID_CERT_EXTENSIONS;
    CryptAttribute.cValue = 1;
    CryptAttribute.rgValue = AttributesBlobArr;
}
*/
