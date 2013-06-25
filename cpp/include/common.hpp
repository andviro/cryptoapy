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

static void debug_log(char *s, ...) {
    va_list ap;
    va_start(ap, s);
    FILE *fp = fopen("debug.log", "a");
    vfprintf(fp, s, ap);
    va_end(ap);
    fclose(fp);
}

#define MY_ENC_TYPE (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
//#define LOG debug_log
#define LOG(...)

#endif
