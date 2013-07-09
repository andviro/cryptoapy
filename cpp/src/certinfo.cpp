#include "certinfo.hpp"

void CertInfo::init()
{
    psi = NULL;
    msg = NULL;
    cert = NULL;
}

CertInfo::CertInfo(Cert *c) throw (CSPException)
{
    LOG("CertInfo::CertInfo(%p)\n", c);
    init();
    cert = c;
    if(!cert) {
        throw CSPException("NULL certificate has no info");
    }
    cert->ref();
    psi = cert->pcert->pCertInfo;
}

CertInfo::CertInfo(CryptMsg *m, DWORD idx) throw (CSPException)
{
    LOG("CertInfo::CertInfo(%p, %u)\n", m, idx);
    init();
    msg = m;
    if(!msg) {
        throw CSPException("NULL message has no info");
    }
    msg->ref();
    DWORD spsi;
    HCRYPTMSG hmsg = msg->get_handle();

    if (!CryptMsgGetParam(hmsg, CMSG_SIGNER_CERT_INFO_PARAM, idx, NULL, &spsi)) {
        throw CSPException("Couldn't get signer info size");
    }
    psi = (CERT_INFO *) malloc(spsi);
    if (!CryptMsgGetParam(hmsg, CMSG_SIGNER_CERT_INFO_PARAM, idx, psi, &spsi)) {
        throw CSPException("Couldn't get signer info data");
    }
}

CertInfo::~CertInfo () throw(CSPException)
{
    LOG("CertInfo::~CertInfo(%p)\n", this);
    if (msg) {
        msg -> unref();
        if (psi) {
            free((void *)psi);
        }
    }
    if (cert) {
        cert -> unref();
    }
}

DWORD CertInfo::version()
{
    return psi->dwVersion;
}

char *CertInfo::sign_algorithm()
{
    LOG("CertInfo::sign_algorithm\n");
    return psi->SignatureAlgorithm.pszObjId;
}

void CertInfo::name(BYTE **s, DWORD *slen) throw(CSPException)
{
    LOG("CertInfo::name()\n");
    if (msg) {
        throw CSPException("Message signer info may not contain subject name", -1);
    }
    decode_name_blob(&psi->Subject, s, slen);
}

void CertInfo::issuer(BYTE **s, DWORD *slen) throw(CSPException)
{
    LOG("CertInfo::issuer()\n");
    decode_name_blob(&psi->Issuer, s, slen);
}

void CertInfo::serial(BYTE **s, DWORD *slen) throw(CSPException)
{
    *slen = psi->SerialNumber.cbData;
    *s = (BYTE *)malloc(*slen);
    memcpy(*s, psi->SerialNumber.pbData, *slen);
}

void CertInfo::decode_name_blob(PCERT_NAME_BLOB pNameBlob, BYTE **s, DWORD *slen)
{
    DWORD flags = CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG;
    LOG("CertInfo::decode_name_blob %p\n", pNameBlob);

    *slen = CertNameToStr( X509_ASN_ENCODING, pNameBlob, flags, NULL, 0);
    if (*slen <= 1) {
        throw CSPException("Wrong size for blob decoded data");
    }

    *s = (BYTE *)malloc(*slen);

    *slen = CertNameToStr(X509_ASN_ENCODING, pNameBlob, flags, (char *)*s, *slen);

    if (*slen <= 1) {
        free(*s);
        throw CSPException("Couldn't decode cert blob");
    }
    (*slen)--;
}
