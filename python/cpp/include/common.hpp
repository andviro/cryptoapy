#ifndef COMMON_HPP_INCLUDED
#define COMMON_HPP_INCLUDED

#include <stdio.h>
#ifdef _WIN32
#   include <windows.h>
#   include <wincrypt.h>
#else
#   include <stdlib.h>
#   include <string.h>
#   include <CSP_WinDef.h>
#   include <CSP_WinCrypt.h>
#endif
#include <WinCryptEx.h>
#include <stdarg.h>

#define MY_ENC_TYPE (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define ENCRYPT_OID szOID_CP_GOST_28147
void debug_log(char *s, ...);
#ifdef DEBUG_LOG
#    define LOG debug_log
#else
#    define LOG(...)
#endif

#define CERTSIGN_OID szOID_CP_GOST_R3411_12_256_R3410

#endif
