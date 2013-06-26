/*
 * Copyright(C) 2000-2006 ������ ���
 *
 * ���� ���� �������� ����������, ����������
 * �������������� �������� ������-���.
 *
 * ����� ����� ����� ����� �� ����� ���� �����������,
 * ����������, ���������� �� ������ �����,
 * ������������ ��� �������������� ����� ��������,
 * ���������������, �������� �� ���� � ��� ��
 * ����� ������������ ������� ��� ����������������
 * ���������� ���������� � ��������� ������-���.
 */

/*!
 * \file $RCSfile: WinCryptEx.h,v $
 * \version $Revision: 1.267 $
 * \date $Date: 2010/08/02 09:15:16 $
 * \author $Author: raa $
 *
 * \brief ��������� ������-��� CSP, ���������� � WinCrypt.h.
 */

#ifndef _WINCRYPTEX_H_INCLUDED
#define _WINCRYPTEX_H_INCLUDED

#ifndef _WINCRYPTEX_USE_EXTERNAL_TYPES

#ifdef UNIX
#include "CSP_WinCrypt.h"
#else // UNIX
#include <wincrypt.h>
#endif // UNIX

#endif // _WINCRYPTEX_USE_EXTERNAL_TYPES

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// ����� ����������� ��� � CSP 1.1
#define CP_DEF_PROV_A "Crypto-Pro Cryptographic Service Provider"
#define CP_DEF_PROV_W L"Crypto-Pro Cryptographic Service Provider"
#ifdef UNICODE
#define CP_DEF_PROV CP_DEF_PROV_W
#else //!UNICODE
#define CP_DEF_PROV CP_DEF_PROV_A
#endif //!UNICODE

// ����� ����������� ��� � CSP 2.0
#define CP_GR3410_94_PROV_A "Crypto-Pro GOST R 34.10-94 Cryptographic Service Provider"
#define CP_GR3410_94_PROV_W L"Crypto-Pro GOST R 34.10-94 Cryptographic Service Provider"
#ifdef UNICODE
#define CP_GR3410_94_PROV CP_GR3410_94_PROV_W
#else //!UNICODE
#define CP_GR3410_94_PROV CP_GR3410_94_PROV_A
#endif //!UNICODE

#define CP_GR3410_2001_PROV_A "Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider"
#define CP_GR3410_2001_PROV_W L"Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider"
#ifdef UNICODE
#define CP_GR3410_2001_PROV CP_GR3410_2001_PROV_W
#else //!UNICODE
#define CP_GR3410_2001_PROV CP_GR3410_2001_PROV_A
#endif //!UNICODE

#define CP_GR3410_2001_HSM_LOCAL_PROV_A "Crypto-Pro GOST R 34.10-2001 HSM Local CSP"
#define CP_GR3410_2001_HSM_LOCAL_PROV_W L"Crypto-Pro GOST R 34.10-2001 HSM Local CSP"
#ifdef UNICODE
#define CP_GR3410_2001_HSM_LOCAL_PROV CP_GR3410_2001_HSM_LOCAL_PROV_W
#else //!UNICODE
#define CP_GR3410_2001_HSM_LOCAL_PROV CP_GR3410_2001_HSM_LOCAL_PROV_A
#endif //!UNICODE

#define CP_KC1_GR3410_94_PROV_A "Crypto-Pro GOST R 34.10-94 KC1 CSP"
#define CP_KC1_GR3410_94_PROV_W L"Crypto-Pro GOST R 34.10-94 KC1 CSP"
#ifdef UNICODE
#define CP_KC1_GR3410_94_PROV CP_KC1_GR3410_94_PROV_W
#else //!UNICODE
#define CP_KC1_GR3410_94_PROV CP_KC1_GR3410_94_PROV_A
#endif //!UNICODE

#define CP_KC1_GR3410_2001_PROV_A "Crypto-Pro GOST R 34.10-2001 KC1 CSP"
#define CP_KC1_GR3410_2001_PROV_W L"Crypto-Pro GOST R 34.10-2001 KC1 CSP"
#ifdef UNICODE
#define CP_KC1_GR3410_2001_PROV CP_KC1_GR3410_2001_PROV_W
#else //!UNICODE
#define CP_KC1_GR3410_2001_PROV CP_KC1_GR3410_2001_PROV_A
#endif //!UNICODE

#define CP_KC2_GR3410_94_PROV_A "Crypto-Pro GOST R 34.10-94 KC2 CSP"
#define CP_KC2_GR3410_94_PROV_W L"Crypto-Pro GOST R 34.10-94 KC2 CSP"
#ifdef UNICODE
#define CP_KC2_GR3410_94_PROV CP_KC2_GR3410_94_PROV_W
#else //!UNICODE
#define CP_KC2_GR3410_94_PROV CP_KC2_GR3410_94_PROV_A
#endif //!UNICODE

#define CP_KC2_GR3410_2001_PROV_A "Crypto-Pro GOST R 34.10-2001 KC2 CSP"
#define CP_KC2_GR3410_2001_PROV_W L"Crypto-Pro GOST R 34.10-2001 KC2 CSP"
#ifdef UNICODE
#define CP_KC2_GR3410_2001_PROV CP_KC2_GR3410_2001_PROV_W
#else //!UNICODE
#define CP_KC2_GR3410_2001_PROV CP_KC2_GR3410_2001_PROV_A
#endif //!UNICODE

#define PH_GR3410_94_PROV_A "Phoenix-CS GOST R 34.10-94 Cryptographic Service Provider"
#define PH_GR3410_94_PROV_W L"Phoenix-CS GOST R 34.10-94 Cryptographic Service Provider"
#ifdef UNICODE
#define PH_GR3410_94_PROV PH_GR3410_94_PROV_W
#else //!UNICODE
#define PH_GR3410_94_PROV PH_GR3410_94_PROV_A
#endif //!UNICODE

#define PH_GR3410_2001_PROV_A "Phoenix-CS GOST R 34.10-2001 Cryptographic Service Provider"
#define PH_GR3410_2001_PROV_W L"Phoenix-CS GOST R 34.10-2001 Cryptographic Service Provider"
#ifdef UNICODE
#define PH_GR3410_2001_PROV PH_GR3410_2001_PROV_W
#else //!UNICODE
#define PH_GR3410_2001_PROV PH_GR3410_2001_PROV_A
#endif //!UNICODE

#define CP_KC1_GR3410_2001_MAGISTRA_PROV_A "GOST R 34.10-2001 Magistra CSP"
#define CP_KC1_GR3410_2001_MAGISTRA_PROV_W L"GOST R 34.10-2001 Magistra CSP"
#ifdef UNICODE
#define CP_KC1_GR3410_2001_MAGISTRA_PROV CP_KC1_GR3410_2001_MAGISTRA_PROV_W
#else //!UNICODE
#define CP_KC1_GR3410_2001_MAGISTRA_PROV CP_KC1_GR3410_2001_MAGISTRA_PROV_A
#endif //!UNICODE

#define CP_KC1_GR3410_2001_RUTOKEN_PROV_A "GOST R 34.10-2001 Rutoken CSP"
#define CP_KC1_GR3410_2001_RUTOKEN_PROV_W L"GOST R 34.10-2001 Rutoken CSP"
#ifdef UNICODE
#define CP_KC1_GR3410_2001_RUTOKEN_PROV CP_KC1_GR3410_2001_RUTOKEN_PROV_W
#else //!UNICODE
#define CP_KC1_GR3410_2001_RUTOKEN_PROV CP_KC1_GR3410_2001_RUTOKEN_PROV_A
#endif //!UNICODE

#define CP_KC1_GR3410_2001_ETOKEN_PROV_A "GOST R 34.10-2001 eToken CSP"
#define CP_KC1_GR3410_2001_ETOKEN_PROV_W L"GOST R 34.10-2001 eToken CSP"
#ifdef UNICODE
#define CP_KC1_GR3410_2001_ETOKEN_PROV CP_KC1_GR3410_2001_ETOKEN_PROV_W
#else //!UNICODE
#define CP_KC1_GR3410_2001_ETOKEN_PROV CP_KC1_GR3410_2001_ETOKEN_PROV_A
#endif //!UNICODE

#define CP_KC1_GR3410_2001_FLASH_PROV_A "Crypto-Pro Flash Drive KC1 CSP"
#define CP_KC1_GR3410_2001_FLASH_PROV_W L"Crypto-Pro Flash Drive KC1 CSP"
#ifdef UNICODE
#define CP_KC1_GR3410_2001_FLASH_PROV CP_KC1_GR3410_2001_FLASH_PROV_W
#else //!UNICODE
#define CP_KC1_GR3410_2001_FLASH_PROV CP_KC1_GR3410_2001_FLASH_PROV_A
#endif //!UNICODE

#define CP_KC1_GR3410_2001_REGISTRY_PROV_A "Crypto-Pro Registry KC1 CSP"
#define CP_KC1_GR3410_2001_REGISTRY_PROV_W L"Crypto-Pro Registry KC1 CSP"
#ifdef UNICODE
#define CP_KC1_GR3410_2001_REGISTRY_PROV CP_KC1_GR3410_2001_REGISTRY_PROV_W
#else //!UNICODE
#define CP_KC1_GR3410_2001_REGISTRY_PROV CP_KC1_GR3410_2001_REGISTRY_PROV_A
#endif //!UNICODE

/*
 * ???? ���� ��������� PROV_GOST_DH �������� ��������������,
 * �.�. PROV_GOST_DH == 2 == PROV_RSA_SIG
 * ����������� PROV_GOST_94_DH ��� PROV_GOST_2001_DH
 */
#define PROV_GOST_DH 2

/*+
 * �� 09.07.01 � Platform SDK ��������� ������������������
 * CSP - PROV_RSA_AES == 24
 *
 * � ������ ���  PROV_GOST_* ��� ��������� ����� �� ��������� [53..89]
 */
//#pragma deprecated("PROV_GOST_94_DH")
#define PROV_GOST_94_DH 71
#define PROV_GOST_2001_DH 75

/* �������������� ���� �����������.
 * � Platform SDK ���������� ������ CRYPT_ASN_ENCODING (1),
 * CRYPT_NDR_ENCODING (2) � �������� ���� 0x10000 (PKCS7). */
#define CRYPT_XER_ENCODING (8)

/* �������������� ����� AcquireContext. ���������� ��������� ����������������. */
#define CRYPT_GENERAL				0x00004000
#define CRYPT_TOKEN_SHARED			0x00008000
#define CRYPT_NOSERIALIZE			0x00010000 // ������� � 3.6.5327, �� ����� ��� 0x8000
#define CRYPT_REBOOT				0x00020000
/*
 * // dwFlags definitions for CryptAcquireContext
 * #define CRYPT_VERIFYCONTEXT			0xF0000000
 * #define CRYPT_NEWKEYSET			0x00000008
 * #define CRYPT_DELETEKEYSET			0x00000010
 * #define CRYPT_MACHINE_KEYSET			0x00000020
 * #define CRYPT_SILENT				0x00000040
 * #if (NTDDI_VERSION >= NTDDI_WINLH)
 * #define CRYPT_DEFAULT_CONTAINER_OPTIONAL	0x00000080
 * #endif //(NTDDI_VERSION >= NTDDI_WINLH)
 *... 
 * //  The following define must not collide with any of the
 * //  CryptAcquireContext dwFlag defines.
 * //-------------------------------------------------------
 * #define CERT_SET_KEY_PROV_HANDLE_PROP_ID	0x00000001
 * #define CERT_SET_KEY_CONTEXT_PROP_ID		0x00000001
 */

/* �������������� ����� CryptMsgOpenToEncode � CryptMsgControl, ������������
 * ��������� ��� ������������ ������� CAdES-BES. */
#define CPCMSG_CADES_STRICT		    (0x00000100)
#define CPCMSG_CADES_DISABLE                (0x00000200)
#define CPCMSG_CADES_DISABLE_CERT_SEARCH    (0x00000400)

/* �������������� ����� CryptSignMessage, ������������
 * ��������� ��� ������������ ������� CAdES-BES. */
#define CPCRYPT_MESSAGE_CADES_STRICT	    (CPCMSG_CADES_STRICT)
#define CPCRYPT_MESSAGE_CADES_DISABLE	    (CPCMSG_CADES_DISABLE)

/* ???? ���� CryptGenKey, ������������ ����, ������������ �������� � ���.*/
#define CRYPT_ECCNEGATIVE	0x00000400 

/* ������ ���������� ������ EKE */
#define CRYPT_MODE_EKEXOR	11
#define CRYPT_MODE_EKEECADD	12

/* ��������� ���������������� ������ */
#define USERKEY_KEYEXCHANGE			AT_KEYEXCHANGE
#define USERKEY_SIGNATURE			AT_SIGNATURE

/* Algorithm types */
#define ALG_TYPE_GR3410				(7 << 9)
/* GR3411 sub-ids */
#define ALG_SID_GR3411				30
#define ALG_SID_GR3411_HASH			39
#define ALG_SID_GR3411_HASH34			40
/* G28147 sub_ids */
#define ALG_SID_G28147				30
#define ALG_SID_PRODIVERS			38
#define ALG_SID_RIC1DIVERS			40
/* Export Key sub_id */
#define ALG_SID_PRO_EXP				31
#define ALG_SID_SIMPLE_EXP			32
/* Hash sub ids */
#define ALG_SID_G28147_MAC			31
#define ALG_SID_TLS1_MASTER_HASH		32

/* GOST_DH sub ids */
#define ALG_SID_DH_EX_SF			30
#define ALG_SID_DH_EX_EPHEM			31
#define ALG_SID_PRO_AGREEDKEY_DH		33
#define ALG_SID_PRO_SIMMETRYKEY			34
#define ALG_SID_GR3410				30
#define ALG_SID_GR3410EL			35
#define ALG_SID_DH_EL_SF			36
#define ALG_SID_DH_EL_EPHEM			37
#define ALG_SID_GR3410_94_ESDH			39
#define ALG_SID_GR3410_01_ESDH			40
/* EKE sub ids*/
#define ALG_SID_EKE_CIPHER			41
#define ALG_SID_EKE_EXPORTPUBLIC		42
#define ALG_SID_EKEVERIFY_HASH			43
#define ALG_SID_AGREED_DEMASK			44

#define AT_KEYEXCHANGE_FKC		   0x80000001
#define AT_SIGNATURE_FKC		   0x80000002

#define CALG_GR3411 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411)

#define CALG_GR3411_HMAC \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_HASH)
#define CALG_GR3411_HMAC34 \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_HASH34)

#define CALG_G28147_MAC \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_G28147_MAC)

#define CALG_G28147_IMIT \
    CALG_G28147_MAC

#define CALG_GR3410 \
    (ALG_CLASS_SIGNATURE | ALG_TYPE_GR3410 | ALG_SID_GR3410)

#define CALG_GR3410EL \
    (ALG_CLASS_SIGNATURE | ALG_TYPE_GR3410 | ALG_SID_GR3410EL)

#define CALG_G28147 \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_G28147)

#define CALG_DH_EX_SF \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EX_SF)

#define CALG_DH_EX_EPHEM \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EX_EPHEM)

#define CALG_DH_EX \
    CALG_DH_EX_SF

#define CALG_DH_EL_SF \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EL_SF)

#define CALG_DH_EL_EPHEM \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EL_EPHEM)

#define CALG_GR3410_94_ESDH \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_GR3410_94_ESDH)

#define CALG_GR3410_01_ESDH \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_GR3410_01_ESDH)

#define CALG_PRO_AGREEDKEY_DH \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_BLOCK | ALG_SID_PRO_AGREEDKEY_DH)

#define CALG_PRO_EXPORT \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_PRO_EXP)

#define CALG_SIMPLE_EXPORT \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_SIMPLE_EXP)

#define CALG_SIMMETRYKEY \
    CALG_G28147
    /* (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_SIMMETRYKEY) */

#define CALG_TLS1_MASTER_HASH \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_TLS1_MASTER_HASH)

#define CALG_TLS1_MAC_KEY \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_MAC_KEY)

#define CALG_TLS1_ENC_KEY \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_ENC_KEY)

#define CALG_PRO_DIVERS \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_PRODIVERS)
#define CALG_RIC_DIVERS \
    (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_RIC1DIVERS)
#define CALG_OSCAR_DIVERS CALG_RIC_DIVERS

#define CALG_EKE_CIPHER \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_BLOCK | ALG_SID_EKE_CIPHER)
#define CALG_EKEVERIFY_HASH \
    (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_EKEVERIFY_HASH)

#define CALG_AGREED_DEMASK \
    (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_BLOCK | ALG_SID_AGREED_DEMASK)



#define CRYPT_ALG_PARAM_OID_GROUP_ID            20


#define CRYPT_PROMIX_MODE	0x00000001
#define CRYPT_SIMPLEMIX_MODE	0x00000000
#define CRYPT_MIXDUPLICATE	0x00000002

/*��� ��������� ����� ��� �������������� ������ � �������
    ������� CPImportKey � ������ ����� ������� CALG_PRO_EXPORT*/
#define DIVERSKEYBLOB	0x70

/*��� ��������� ����� ��� �������� ���������� � ��������� ������� FKC*/
#define HASHPUBLICKEYEXBLOB 0x71

/* �������������� ��������� ���������������� */
#define PP_LAST_ERROR 90
#define PP_ENUMOIDS_EX 91
#define PP_HASHOID 92
#define PP_CIPHEROID 93
#define PP_SIGNATUREOID 94
#define PP_DHOID 95
#define PP_RESERVED1 96
#define PP_BIO_STATISTICA_LEN 97
//#pragma deprecated("PP_REBOOT")
#define PP_REBOOT 98
/*��������� �������� ������������ ��� ������� �� ���������, �������� �� WIN32*/
/*#define PP_ANSILASTERROR 99*/
#define PP_RANDOM 100
/*#define PP_DRVCONTAINER	101*/
#define PP_MUTEX_ARG	102
#define PP_ENUM_HASHOID 103
#define PP_ENUM_CIPHEROID 104
#define PP_ENUM_SIGNATUREOID 105
#define PP_ENUM_DHOID	106
#define PP_SET_PIN 107
#define PP_CHANGE_PIN 108
#define PP_HCRYPTPROV 109
#define PP_SELECT_CONTAINER 110
#define PP_FQCN 111
#define PP_CHECKPUBLIC 112
#define PP_ADMIN_CHECKPUBLIC 113
#define PP_ENUMREADERS 114
#define PP_CACHE_SIZE 115
#define PP_NK_SYNC 117
#define PP_INFO 118
#define PP_PIN_INFO 120
#define PP_PASSWD_TERM 123
#define PP_SAME_MEDIA 124
#define PP_DELETE_KEYSET 125
#define PP_DELETE_SAVED_PASSWD 126
#define PP_VERSION_TIMESTAMP 127
#define PP_SECURITY_LEVEL 129
#define PP_FAST_CODE_FUNCS 131
#define PP_CONTAINER_EXTENSION 132
#define PP_ENUM_CONTAINER_EXTENSION 133
#define PP_CONTAINER_EXTENSION_DEL 134
#define PP_CONTAINER_DEFAULT 135
#define PP_LCD_QUERY 136
#define PP_ENUM_LOG 137
#define PP_VERSION_EX 138
#define PP_FAST_CODE_FLAGS 139
#define PP_ENCRYPTION_CARRIER 140
#define PP_DELETE_SHORTCUT 141

#define PP_FKC				141
#define PP_FRIENDLY_NAME		142
#define PP_FKC_DH_CHECK			143

/* ����, ������������ ��� ������������ ������������, ��� ��������� ����� ��������
   */
#define CRYPT_MEDIA 0x20
/* ����, ������������ ��� ������������ �����������, ��� ���������:
    Fully Qualified Container Name */
#define CRYPT_FQCN 0x10
/* ����, ������������ ��� ������������ �����������, ��� ����������
    ��������� ���������� ���� ����������� ����� �������� �������.
    � ������ ���������� ���������� ������ ��� ���������� �����,
    ����� ����������� ������ ���������� ������� ��� ����������. */
#define CRYPT_UNIQUE 0x08

/* ���� ������������ ��� ������������ ������� �������,
   ��� ���������� ������������ � ���������� �������. */
#define CRYPT_FINISH 0x04

/* ����, ��� ������ PP_DELETE_ERROR � �������� ���������� ������������
    �� ����� ������ ��������� �� ������. */
#define CRYPT_DELETEKEYSET_PART 0x1

/* ����� ������������ ������������, ���������� ���������� �������� � �����������. 
   ������������ � ���� ASCIIZ-������. */
#define ERR_CRYPT_MEDIA_NO_MEDIA "NO_MEDIA"

/* ����� ������������ ������������, ����������, ��� �������� ��-���. ��� ���-�����������. 
   ������������ � ���� ASCIIZ-������. */
#define ERR_CRYPT_MEDIA_NO_FKC "NO_FKC"

/* ����� ������������ ������������, ����������, ��� �������� ���. ��� ��-���-�����������.
   ������������ � ���� ASCIIZ-������. */
#define ERR_CRYPT_MEDIA_FKC "IS_FKC"

/* ����� ������������ ������������, ���������� ���������� ����������� ������ �������� (������������� ��������).
   ������������ � ���� ASCIIZ-������. */
#define ERR_CRYPT_MEDIA_NO_UNIQUE "NO_UNIQUE"

/* �������������� ��������� ������� ���� */
#define HP_HASHSTARTVECT 0x0008
#define HP_HASHCOPYVAL	 0x0009
#define HP_OID 0x000a
#define HP_OPEN 0x000B
#define HP_KEYMIXSTART 0x0011
#define HP_OPAQUEBLOB 0x000C

#define HP_R2_SIGN 0x000D
#define HP_R_SIGN 0x000E
#define HP_S2_SIGN 0x000F
#define HP_KEYSPEC_SIGN 0x0010

/* �������������� ��������� ����� */
#define KP_SV		KP_IV
#define KP_MIXMODE	101
#define KP_MIXSTART	0x800000e0
#define KP_OID		102
#define KP_HASHOID	103
#define KP_CIPHEROID	104
#define KP_SIGNATUREOID 105
#define KP_DHOID	106
#define KP_KC1EXPORT	0x800000f0
/* Token Interfase NEW */
#define KP_MULX		0x800000f1
#define KP_MULX_INVERS  0x800000f2
#define KP_ADDX		0x800000f3
#define KP_SUBX		0x800000f4
#define KP_ECADD	0x800000f5
#define KP_ECSUB	0x800000f6
#define KP_SYNCRO	0x800000f7
#define KP_DELTA	0x800000f8

#define KP_DEMASKPUBLIC	0x800000f9

/* FKC KP_...  to delete */
#define KP_TOKENRECOVERY	0x800001fb
/* End FKC KP_...  to delete */

/* CRYPT_PRIVATE_KEYS_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_PRIVATE_KEYS_V1 "1.2.643.2.2.37.1"
#define szOID_CP_GOST_PRIVATE_KEYS_V2 "1.2.643.2.2.37.2"
#define szOID_CP_GOST_PRIVATE_KEYS_V2_FULL "1.2.643.2.2.37.2.1"
#define szOID_CP_GOST_PRIVATE_KEYS_V2_PARTOF "1.2.643.2.2.37.2.2"

/* CRYPT_HASH_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_R3411 "1.2.643.2.2.9"

/* CRYPT_ENCRYPT_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_28147 "1.2.643.2.2.21"

/* CRYPT_PUBKEY_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_R3410 "1.2.643.2.2.20"
#define szOID_CP_GOST_R3410EL "1.2.643.2.2.19"
#define szOID_CP_DH_EX "1.2.643.2.2.99"
#define szOID_CP_DH_EL "1.2.643.2.2.98"
#define szOID_CP_GOST_R3410_94_ESDH "1.2.643.2.2.97"
#define szOID_CP_GOST_R3410_01_ESDH "1.2.643.2.2.96"

/* CRYPT_SIGN_ALG_OID_GROUP_ID */
#define szOID_CP_GOST_R3411_R3410 "1.2.643.2.2.4"
#define szOID_CP_GOST_R3411_R3410EL "1.2.643.2.2.3"

/* CRYPT_ENHKEY_USAGE_OID_GROUP_ID */
#define szOID_KP_TLS_PROXY "1.2.643.2.2.34.1"
#define szOID_KP_RA_CLIENT_AUTH "1.2.643.2.2.34.2"
#define szOID_KP_WEB_CONTENT_SIGNING "1.2.643.2.2.34.3"
#define szOID_KP_RA_ADMINISTRATOR "1.2.643.2.2.34.4"
#define szOID_KP_RA_OPERATOR "1.2.643.2.2.34.5"

/* Our well-known policy ID */
#define szOID_CEP_BASE_PERSONAL	"1.2.643.2.2.38.1"
#define szOID_CEP_BASE_NETWORK	"1.2.643.2.2.38.2"

/* OIDs for HASH */
#define szOID_GostR3411_94_TestParamSet			"1.2.643.2.2.30.0"
#define szOID_GostR3411_94_CryptoProParamSet		"1.2.643.2.2.30.1"	/* ���� � 34.11-94, ��������� �� ��������� */
#define szOID_GostR3411_94_CryptoPro_B_ParamSet		"1.2.643.2.2.30.2"
#define szOID_GostR3411_94_CryptoPro_C_ParamSet		"1.2.643.2.2.30.3"
#define szOID_GostR3411_94_CryptoPro_D_ParamSet		"1.2.643.2.2.30.4"

/* OIDs for Crypt */
#define szOID_Gost28147_89_TestParamSet			"1.2.643.2.2.31.0"
#define szOID_Gost28147_89_CryptoPro_A_ParamSet		"1.2.643.2.2.31.1"	/* ���� 28147-89, ��������� �� ��������� */
#define szOID_Gost28147_89_CryptoPro_B_ParamSet		"1.2.643.2.2.31.2"	/* ���� 28147-89, ��������� ���������� 1 */
#define szOID_Gost28147_89_CryptoPro_C_ParamSet		"1.2.643.2.2.31.3" 	/* ���� 28147-89, ��������� ���������� 2 */
#define szOID_Gost28147_89_CryptoPro_D_ParamSet		"1.2.643.2.2.31.4"	/* ���� 28147-89, ��������� ���������� 3 */
#define szOID_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet	"1.2.643.2.2.31.5"	/* ���� 28147-89, ��������� ����� 1.1 */
#define szOID_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet	"1.2.643.2.2.31.6"	/* ���� 28147-89, ��������� ����� 1.0 */
#define szOID_Gost28147_89_CryptoPro_RIC_1_ParamSet	"1.2.643.2.2.31.7"	/* ���� 28147-89, ��������� ��� 1 */

/* OID for Signature 1024*/
#define szOID_GostR3410_94_CryptoPro_A_ParamSet		"1.2.643.2.2.32.2" 	/*VerbaO*/
#define szOID_GostR3410_94_CryptoPro_B_ParamSet		"1.2.643.2.2.32.3"
#define szOID_GostR3410_94_CryptoPro_C_ParamSet		"1.2.643.2.2.32.4"
#define szOID_GostR3410_94_CryptoPro_D_ParamSet		"1.2.643.2.2.32.5"

/* OID for Signature 512*/
#define szOID_GostR3410_94_TestParamSet			"1.2.643.2.2.32.0" 	/*Test*/

/* OID for DH 1024*/
#define szOID_GostR3410_94_CryptoPro_XchA_ParamSet	"1.2.643.2.2.33.1"
#define szOID_GostR3410_94_CryptoPro_XchB_ParamSet	"1.2.643.2.2.33.2"
#define szOID_GostR3410_94_CryptoPro_XchC_ParamSet	"1.2.643.2.2.33.3"

/* OID for EC signature */
#define szOID_GostR3410_2001_TestParamSet		"1.2.643.2.2.35.0"      /* ���� � 34.10-2001, �������� ��������� */
#define szOID_GostR3410_2001_CryptoPro_A_ParamSet	"1.2.643.2.2.35.1"	/* ���� � 34.10-2001, ��������� �� ��������� */
#define szOID_GostR3410_2001_CryptoPro_B_ParamSet	"1.2.643.2.2.35.2"	/* ���� � 34.10-2001, ��������� ����� 2.x */
#define szOID_GostR3410_2001_CryptoPro_C_ParamSet	"1.2.643.2.2.35.3"	/* ���� � 34.10-2001, ��������� ������� 1 */

/* OID for EC DH */
#define szOID_GostR3410_2001_CryptoPro_XchA_ParamSet	"1.2.643.2.2.36.0"	/* ���� � 34.10-2001, ��������� ������ �� ��������� */
#define szOID_GostR3410_2001_CryptoPro_XchB_ParamSet 	"1.2.643.2.2.36.1"	/* ���� � 34.10-2001, ��������� ������ 1 */

/* OIDs for private key container extensions */
/* ���������� ����������. �������������� ������� � CSP 3.6 */
#define szOID_CryptoPro_private_keys_extension_intermediate_store "1.2.643.2.2.37.3.1"
#define szOID_CryptoPro_private_keys_extension_signature_trust_store "1.2.643.2.2.37.3.2"
#define szOID_CryptoPro_private_keys_extension_exchange_trust_store "1.2.643.2.2.37.3.3"
#define szOID_CryptoPro_private_keys_extension_container_friendly_name "1.2.643.2.2.37.3.4"

/* OIDs for certificate and CRL extensions */
/* ����� ������������� CRL � ������������ ��������. */
#define szOID_CryptoPro_extensions_certificate_and_crl_matching_technique "1.2.643.2.2.49.1"

/* OIDs for signing certificate attributes */
/* ������ ��������� ��� �������� �������������� ����������� ����� ������� */
#define szCPOID_RSA_SMIMEaaSigningCertificate "1.2.840.113549.1.9.16.2.12"
#define szCPOID_RSA_SMIMEaaSigningCertificateV2 "1.2.840.113549.1.9.16.2.47"
#define szCPOID_RSA_SMIMEaaETSotherSigCert "1.2.840.113549.1.9.16.2.19"

/* GUIDs for extending CryptEncodeObject/CryptDecodeObject functionality */
/* ����� ���������� ���������������, ������������ ��� ���������� ����������������
   ������� CryptEncodeObject/CryptDecodeObject */
#define szCPGUID_RSA_SMIMEaaSigningCertificateEncode "{272ED084-4C55-42A9-AD88-A1502D9ED755}"
#define szCPGUID_RSA_SMIMEaaSigningCertificateV2Encode "{42AB327A-BE56-4899-9B81-1BF2F3C5E154}"
#define szCPGUID_RSA_SMIMEaaETSotherSigCertEncode "{410F6306-0ADE-4485-80CC-462DEB3AD109}"
#define szCPGUID_PRIVATEKEY_USAGE_PERIOD_Encode "{E36FC6F5-4880-4CB7-BA51-1FCD92CA1453}"

/*! \cond pkivalidator */
/* GUIDs for extending CertVerifyCertificateChainPolicy functionality */
/* ����� ���������� ���������������, ������������ ��� ���������� ����������������
   ������� CertVerifyCertificateChainPolicy */
#define CPCERT_CHAIN_POLICY_PRIVATEKEY_USAGE_PERIOD "{C03D5610-26C8-4B6F-9549-245B5B3AB743}"
#define CPCERT_CHAIN_POLICY_SIGNATURE "{B52FF66F-13A5-402C-B958-A3A6B5300FB6}"
#define CPCERT_CHAIN_POLICY_TIMESTAMP_SIGNING "{AF74EE92-A059-492F-9B4B-EAD239B22A1B}"
#define CPCERT_CHAIN_POLICY_OCSP_SIGNING "{A4CC781E-04E9-425C-AAFD-1D74DA8DFAF6}"
/** \endcond */

/*! \cond csp */
/* �������� ��� ������������� � ������� 3.0*/
#define OID_HashVar_Default	szOID_GostR3411_94_CryptoProParamSet
#define OID_HashTest		szOID_GostR3411_94_TestParamSet
#define OID_HashVerbaO		szOID_GostR3411_94_CryptoProParamSet
#define OID_HashVar_1		szOID_GostR3411_94_CryptoPro_B_ParamSet
#define OID_HashVar_2		szOID_GostR3411_94_CryptoPro_C_ParamSet
#define OID_HashVar_3		szOID_GostR3411_94_CryptoPro_D_ParamSet

#define OID_CipherVar_Default	szOID_Gost28147_89_CryptoPro_A_ParamSet
#define OID_CryptTest		szOID_Gost28147_89_TestParamSet
#define OID_CipherVerbaO	szOID_Gost28147_89_CryptoPro_A_ParamSet
#define OID_CipherVar_1		szOID_Gost28147_89_CryptoPro_B_ParamSet
#define OID_CipherVar_2		szOID_Gost28147_89_CryptoPro_C_ParamSet
#define OID_CipherVar_3		szOID_Gost28147_89_CryptoPro_D_ParamSet
#define OID_CipherOSCAR		szOID_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet
#define OID_CipherTestHash	szOID_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet
#define OID_CipherRIC1		szOID_Gost28147_89_CryptoPro_RIC_1_ParamSet

#define OID_SignDH128VerbaO	szOID_GostR3410_94_CryptoPro_A_ParamSet
#define OID_Sign128Var_1	szOID_GostR3410_94_CryptoPro_B_ParamSet
#define OID_Sign128Var_2	szOID_GostR3410_94_CryptoPro_C_ParamSet
#define OID_Sign128Var_3	szOID_GostR3410_94_CryptoPro_D_ParamSet
#define OID_DH128Var_1		szOID_GostR3410_94_CryptoPro_XchA_ParamSet
#define OID_DH128Var_2		szOID_GostR3410_94_CryptoPro_XchB_ParamSet
#define OID_DH128Var_3		szOID_GostR3410_94_CryptoPro_XchC_ParamSet

#define OID_Sg64_Test		szOID_GostR3410_94_TestParamSet

#define OID_ECCTest3410		szOID_GostR3410_2001_TestParamSet
#define OID_ECCSignDHPRO	szOID_GostR3410_2001_CryptoPro_A_ParamSet
#define OID_ECCSignDHOSCAR	szOID_GostR3410_2001_CryptoPro_B_ParamSet
#define OID_ECCSignDHVar_1	szOID_GostR3410_2001_CryptoPro_C_ParamSet

#define OID_ECCDHPRO		szOID_GostR3410_2001_CryptoPro_XchA_ParamSet
#define OID_ECCDHPVar_1		szOID_GostR3410_2001_CryptoPro_XchB_ParamSet

/* �������� ��� ������������� � ������� 1.1*/
#define OID_SipherVerbaO	szOID_Gost28147_89_CryptoPro_A_ParamSet
#define OID_SipherVar_1		szOID_Gost28147_89_CryptoPro_B_ParamSet
#define OID_SipherVar_2		szOID_Gost28147_89_CryptoPro_C_ParamSet
#define OID_SipherVar_3		szOID_Gost28147_89_CryptoPro_D_ParamSet
#define OID_SipherVar_Default	szOID_Gost28147_89_CryptoPro_A_ParamSet

#define X509_GR3410_PARAMETERS ((LPCSTR) 5001)
#define OBJ_ASN1_CERT_28147_ENCRYPTION_PARAMETERS ((LPCSTR) 5007)

#define CP_GOST_R3411_ALGORITHM "GOST R 34.11-94"
#define CP_GOST_28147_ALGORITHM "GOST 28147-89"
#define CP_GOST_R3410_ALGORITHM "GOST R 34.10-94"
#define CP_GOST_R3410EL_ALGORITHM "GOST R 34.10-2001"
#define CP_GOST_HMAC_ALGORITHM "HMAC GOST 28147-89"

#define CP_GOST_R3410_ALGORITHM "GOST R 34.10-94"
#define CP_GOST_R3410EL_ALGORITHM "GOST R 34.10-2001"


#define CP_PRIMITIVE_PROVIDER   L"Crypto-Pro Primitive Provider"
#define BCRYPT_CP_GOST_R3411_ALGORITHM L#CP_GOST_R3411_ALGORITHM
#define BCRYPT_CP_GOST_28147_ALGORITHM L#CP_GOST_28147_ALGORITHM
#define BCRYPT_CP_GOST_R3410_ALGORITHM L#CP_GOST_R3410_ALGORITHM
#define BCRYPT_CP_GOST_R3410EL_ALGORITHM L#CP_GOST_R3410EL_ALGORITHM


/* ����� �������� ���������� � �������� ������ �� ���� ���� 28147-89, ����-����� ����� ������ �������� IV ��� ����������.*/
/*! \ingroup ProCSPData
*  \brief ����� �������� ���������� � �������� ������ �� ���� ���� 28147-89, ����-����� ����� ������ �������� IV ��� ����������
*/
#define CRYPT_MODE_CBCSTRICT	1 

/* ����� �������� ���������� � �������� ������ �� ���� ���� 28147-89, �������� RFC 4357.*/
/*! \ingroup ProCSPData
*  \brief ����� �������� ���������� � �������� ������ �� ���� ���� 28147-89, �������� RFC 4357
*/
#define CRYPT_MODE_CBCRFC4357	31 

/* ����� ���������� "������������" �� ���� 28147-89.*/
/*! \ingroup ProCSPData
 *  \brief ����� ���������� "�������������" �� ���� 28147-89
 */
#define CRYPT_MODE_CNT          3      // GOST 28147-89 in "gammirovanie" (counter) mode

/* ����� ���������� "������������" �� ���� 28147-89.*/
/*! \ingroup ProCSPData
 *  \brief ����� ���������� "�������������" �� ���� 28147-89 
 *   � ������ �������� ��������� ������
 */
#define CRYPT_MODE_CNTPACKET       0x80000100 | CRYPT_MODE_CNT

/* ����� ���������� ����� ��� ���� 28147-89, ������� � ������.*/
/*! \ingroup ProCSPData
 *  \brief ����� � ������ ����� ���� 28147-89 � �������� ������
 * ���� � 34.10-94 � ���� � 34.10-2001.
 */
#define SECRET_KEY_LEN		32

/*! \ingroup ProCSPData
 *  \brief ����� � ������ ����� ���� 28147-89
 * \sa SECRET_KEY_LEN
 */
#define G28147_KEYLEN        SECRET_KEY_LEN

/*! \ingroup ProCSPData
 *  \brief ����� � ������ ������������ ��� �������/��������
 */
#define EXPORT_IMIT_SIZE		4

/*! \ingroup ProCSPData
 *  \brief �����  � ������ ������� ������������ ���������
 */
#define SEANCE_VECTOR_LEN		8

/*! \ingroup ProCSPData
*  \brief ������������ ����������� ����� ����� ��������� ����������
*/
#define MAX_CONTAINER_NAME_LEN		260

/* ��������� � ��������� ��� ���� �������� ������� �*/
/* ��������� ������������� ������*/

/*! \ingroup ProCSPData
 *  \brief ������� ������ ���� � 34.10-94 � ���� � 34.10-2001
 */
#define GR3410_1_MAGIC			0x3147414D
#define GR3410_2_MAGIC			GR3410_1_MAGIC//0x3145474a

#define DH_1_MAGIC			GR3410_1_MAGIC
#define DH_2_MAGIC			GR3410_1_MAGIC
#define DH_3_MAGIC			GR3410_1_MAGIC

/*! \ingroup ProCSPData
 *  \brief ������� ������ ���� 28147-89 � ������ ������ TLS
 */
#define G28147_MAGIC			0x374a51fd
#define SIMPLEBLOB_MAGIC		G28147_MAGIC
#define G28147_OPAQUEMAGIC		0x374a51fe
/*! \ingroup ProCSPData
 *  \brief ������� ��������� ����� ������� �������������� �����
 */
#define DIVERS_MAGIC			0x31564944

/*! \ingroup ProCSPData
 *  \brief ������� �������� ������ ��������� �����
 */
#define BLOB_VERSION			(BYTE)0x20


/* ����������� ��� */
/*! \ingroup ProCSPData
 * \brief ���������� ������ ������������.
 */
#define VER_TYPE_DEBUG 1
/*! \ingroup ProCSPData
* \brief �������� ������ ������������.
*/
#define VER_TYPE_RELEASE 0

/*! \ingroup ProCSPData
* \brief ����������� IA32.
*/
#define VER_ARCH_IA32	    0
/*! \ingroup ProCSPData
* \brief ����������� IA64.
*/
#define VER_ARCH_IA64	    1
/*! \ingroup ProCSPData
* \brief ����������� Sparc32.
*/
#define VER_ARCH_SPARC32    2
/*! \ingroup ProCSPData
* \brief ����������� Sparc64.
*/
#define VER_ARCH_SPARC64    3
/*! \ingroup ProCSPData
* \brief ����������� AMD64.
*/
#define VER_ARCH_AMD64	    4
/*! \ingroup ProCSPData
* \brief ����������� ARM.
*/
#define VER_ARCH_ARM	    5
/*! \ingroup ProCSPData
* \brief ����������� PowerPC32.
*/
#define VER_ARCH_PPC32      6
/*! \ingroup ProCSPData
* \brief ����������� PowerPC64.
*/
#define VER_ARCH_PPC64      7


/*! \ingroup ProCSPData
* \brief �� Windows.
*/
#define VER_OS_WINDOWS 0
/*! \ingroup ProCSPData
* \brief �� Solaris.
*/
#define VER_OS_SOLARIS 1
/*! \ingroup ProCSPData
* \brief �� FreeBSD.
*/
#define VER_OS_FREEBSD 2
/*! \ingroup ProCSPData
* \brief �� Linux.
*/
#define VER_OS_LINUX   3
/*! \ingroup ProCSPData
* \brief �� AIX.
*/
#define VER_OS_AIX     4

/*! \ingroup ProCSPData
 *
 * \brief ��������� ��������� ������ ����, ����, ��� ������,
 * ���������� ����������� � ��, ��� ������� ������������ �������.
 */
typedef struct _PROV_PP_VERSION_EX {
    DWORD PKZI_Build;	/*!< ������ ����. */
    DWORD SKZI_Build;	/*!< ������ ����. */
    DWORD TypeDebRel;	/*!< ��� ������: VER_TYPE_DEBUG, VER_TYPE_RELEASE. */
    DWORD Architecture;	/*!< ���������� �����������: VER_ARCH_IA32, 
			 * VER_ARCH_IA64, VER_ARCH_SPARC32, VER_ARCH_SPARC64,
			 * VER_ARCH_AMD64, VER_ARCH_ARM, VER_ARCH_PPC32,
			 * VER_ARCH_PPC64.
			 */
    DWORD OS;		/*!< ��� ��: VER_OS_WINDOWS, VER_OS_SOLARIS,
			 * VER_OS_FREEBSD, VER_OS_LINUX, VER_OS_AIX.
			 */
} PROV_PP_VERSION_EX;


/* ����������� ��� ��������� SIMPLEBLOB*/
/* ��������� SIMPLEBLOB*/
/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� CRYPT_SIMPLEBLOB_HEADER �������� ����������� ��������� BLOBHEADER �
 * ��������� � ������ ���� \b pbData ��������� ����� ���� SIMPLEBLOB ��� ������ "��������� CSP".
 *
 * \req_wincryptex
 * \sa _PUBLICKEYSTRUC
 * \sa PCRYPT_SIMPLEBLOB
 * \sa CPExportKey
 * \sa CPGetKeyParam
 */
typedef struct _CRYPT_SIMPLEBLOB_HEADER {
    BLOBHEADER BlobHeader;
                    /*!< ����� ��������� ��������� �����. ���������� �������� �����
                     * ������������ � �������� �����. ��. \ref _PUBLICKEYSTRUC.
                     */
    DWORD Magic;
                    /*!< ������� ������ �� ���� 28147-89 ��� ������ ������ TLS,
                     * ��������������� � \ref G28147_MAGIC.
                     */
    ALG_ID EncryptKeyAlgId;
                    /*!< ���������� �������� �������� �����. ���� �������� ��������
                     * ���������� ����� ��������. ��. \ref #CPGetKeyParam.
                     */
} CRYPT_SIMPLEBLOB_HEADER;
/*!
 * \ingroup ProCSPData
 *
 * \brief ��������������� (�. �. ���������������� ���������) CRYPT_SIMPLEBLOB ��������� ��������� �������� ����
 * ���� SIMPLEBLOB ��� ������ "��������� CSP". 
 *
 * \req_wincryptex
 * \sa CRYPT_SIMPLEBLOB_HEADER
 * \sa CPExportKey
 * \sa CPGetKeyParam
 */
typedef struct _CRYPT_SIMPLEBLOB {
    CRYPT_SIMPLEBLOB_HEADER tSimpleBlobHeader;
                    /*!< ����� ��������� ��������� ����� ���� SIMPLEBLOB "��������� CSP".
                     */
    BYTE    bSV[SEANCE_VECTOR_LEN];
                    /*!< ������ ������������ ��� ��������� CALG_PRO_EXPORT.
                     * ��. \ref SEANCE_VECTOR_LEN.
                     */
    BYTE    bEncryptedKey[G28147_KEYLEN];
                    /*!< ������������� ���� ���� 28147-89.
                     * ��. \ref G28147_KEYLEN.
                     */
    BYTE    bMacKey[EXPORT_IMIT_SIZE];
                    /*!< ������������ �� ���� 28147-89 �� ����. ��������������
                     * �� ������������ � ����������� ����� �������������.
                     * ��. \ref EXPORT_IMIT_SIZE.
                     */
    BYTE    bEncryptionParamSet[1];
                    /*!< �������� ASN1 ��������� � DER ���������, ������������
                     * ��������� ���������� ���������� ���� 28147-89:
                     * \code
                     *      encryptionParamSet
                     *          OBJECT IDENTIFIER (
                     *              id-Gost28147-89-TestParamSet |      -- Only for tests use
                     *              id-Gost28147-89-CryptoPro-A-ParamSet |
                     *              id-Gost28147-89-CryptoPro-B-ParamSet |
                     *              id-Gost28147-89-CryptoPro-C-ParamSet |
                     *              id-Gost28147-89-CryptoPro-D-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-A-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-B-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-C-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-D-ParamSet
                     * \endcode
                     */
}   CRYPT_SIMPLEBLOB, *PCRYPT_SIMPLEBLOB;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������������� (�. �. ���������������� ���������) CRYPT_OPAQUEBLOB ��������� ��������� �������� ����
 * ���� OPAQUEKEYLOB ��� ������ "��������� CSP". 
 *
 * \req_wincryptex
 * \sa CRYPT_SIMPLEBLOB_HEADER
 * \sa CPExportKey
 * \sa CPImportKey
 */
typedef struct _CRYPT_OPAQUEBLOB {
    CRYPT_SIMPLEBLOB_HEADER tSimpleBlobHeader;
                    /*!< ����� ��������� ��������� ����� ���� SIMPLEBLOB "��������� CSP".
                     */
    BYTE    bSV[SEANCE_VECTOR_LEN];
                    /*!< ������ ������������ ��� ��������� CALG_PRO_EXPORT.
                     * ��. \ref SEANCE_VECTOR_LEN.
                     */
    BYTE    bEncryptedKey[G28147_KEYLEN];
                    /*!< ������������� ���� ���� 28147-89.
                     * ��. \ref G28147_KEYLEN.
                     */
    BYTE    bMacKey[EXPORT_IMIT_SIZE];
                    /*!< ������������ �� ���� 28147-89 �� ����. ��������������
                     * �� ������������ � ����������� ����� �������������.
                     * ��. \ref EXPORT_IMIT_SIZE.
                     */
    BYTE    bEncryptedInitKey[G28147_KEYLEN];
                    /*!< ������������� ���� ���� 28147-89.
                     * ��. \ref G28147_KEYLEN.
                     */
    BYTE    bMacInitKey[EXPORT_IMIT_SIZE];
                    /*!< ������������ �� ���� 28147-89 �� ����. ��������������
                     * �� ������������ � ����������� ����� �������������.
                     * ��. \ref EXPORT_IMIT_SIZE.
                     */
      /*����������� ����*/
   BYTE    bCurrentIV[SEANCE_VECTOR_LEN];
                    /*!< ������ ������������ ���������.
                     * ��. \ref SEANCE_VECTOR_LEN.
                     */
    BYTE    bChainBlock[8];
                    /*!< ���� ����������. ������������� ����� ������� �� ������ ����������.
                     *
                     */
    BYTE    bAccCiphertextLen[sizeof(DWORD)];
                    /*!< ����������� ����� ������������ ������.
                     *
                     */
    BYTE    bCipherMode[sizeof(DWORD)];
    BYTE    bMixMode[sizeof(DWORD)];
    BYTE    bFlags[4];
    BYTE    bPaddingMode[sizeof(DWORD)];
    BYTE    bAlgId[sizeof(ALG_ID)];
    BYTE    bCommonFlags[4];
    BYTE    bCheckSum[sizeof(DWORD)];
    BYTE    bEncryptionParamSet[1];
                    /*!< �������� ASN1 ��������� � DER ���������, ������������
                     * ��������� ���������� ���������� ���� 28147-89:
                     * \code
                     *      encryptionParamSet
                     *          OBJECT IDENTIFIER (
                     *              id-Gost28147-89-TestParamSet |      -- Only for tests use
                     *              id-Gost28147-89-CryptoPro-A-ParamSet |
                     *              id-Gost28147-89-CryptoPro-B-ParamSet |
                     *              id-Gost28147-89-CryptoPro-C-ParamSet |
                     *              id-Gost28147-89-CryptoPro-D-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-A-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-B-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-C-ParamSet |
                     *              id-Gost28147-89-CryptoPro-Simple-D-ParamSet
                     * \endcode
                     */
}   CRYPT_OPAQUEBLOB, *PCRYPT_OPAQUEBLOB;


typedef struct _CRYPT_OPAQUEHASHBLOB {
    CRYPT_SIMPLEBLOB_HEADER tSimpleBlobHeader;
                    /*!< ����� ��������� ��������� ����� ���� SIMPLEBLOB "��������� CSP".
                     */
   BYTE    ImitVal[8];
   BYTE    bCurrKey[G28147_KEYLEN];
                    /*!< ������������� ���� ���� 28147-89.
                     * ��. \ref G28147_KEYLEN.
                     */
      /*����������� ����*/
    BYTE    bChainBlock[8];
                    /*!< ���� ����������. ������������� ����� ������� �� ������ ����������.
                     *
                     */
    BYTE    bAccCiphertextLen[sizeof(DWORD)];
                    /*!< ����������� ����� ������������ ������.
                     *
                     */
    BYTE    bFlags[4];
    BYTE    bMixMode[sizeof(DWORD)];
    BYTE    bHFlags[4];
    BYTE    bCheckSum[sizeof(DWORD)];
}   CRYPT_OPAQUEHASHBLOB;


/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� CRYPT_PUBKEYPARAM �������� ������� ������
 * �� ���� � 34.10-94 ��� ���� � 34.10-2001.
 *
 * \req_wincryptex
 * \sa CRYPT_PUBKEY_INFO_HEADER
 * \sa CPExportKey
 * \sa CPGetKeyParam
 */
typedef struct _CRYPT_PUBKEYPARAM {
    DWORD Magic;
                    /*!< ������� ������ �� ���� � 34.10-94 ��� ���� � 34.10-2001
                     * ��������������� � \ref GR3410_1_MAGIC.
                     */
    DWORD BitLen;
                    /*!< ����� ��������� ����� � �����.
                     */
} CRYPT_PUBKEYPARAM, *LPCRYPT_PUBKEYPARAM;

/* ��������� PUBLICKEYBLOB � PRIVATEKEYBLOB*/
/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� CRYPT_PUBKEY_INFO_HEADER �������� ���������
 * ����� ��������� ����� ��� ����� �������� ����
 * �� ���� � 34.10-94 ��� ���� � 34.10-2001.
 *
 * \req_wincryptex
 * \sa _PUBLICKEYSTRUC
 * \sa CRYPT_PUBKEYPARAM
 * \sa CPExportKey
 * \sa CPGetKeyParam
 */
typedef struct _CRYPT_PUBKEY_INFO_HEADER {
    BLOBHEADER BlobHeader;
                    /*!< ����� ��������� ��������� �����. ���������� ��� ��� � �������� �����
                     * ������������ � �������� �����. ��� �������� ������ ��������
                     * ����� ������, ���� CALG_GR3410, ���� CALG_GR3410EL. ��� ��������
                     * ��� �������� �������� � ����������. ��. \ref _PUBLICKEYSTRUC.
                     */
    CRYPT_PUBKEYPARAM KeyParam;
                    /*!< �������� ������� � ������ ������ ���� � 34.10-94 � ���� � 34.10-2001.
                     */
} CRYPT_PUBKEY_INFO_HEADER;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������������� CRYPT_PUBLICKEYBLOB ��������� ��������� �������� ����
 * ���� PUBLICKEYBLOB ��� ������ "��������� CSP". 
 *
 * \req_wincryptex
 * \sa CRYPT_PUBKEY_INFO_HEADER
 * \sa CPExportKey
 * \sa CPGetKeyParam
 */
typedef struct _CRYPT_PUBLICKEYBLOB {
    CRYPT_PUBKEY_INFO_HEADER tPublicKeyParam;
                    /*!< ����� ��������� ��������� ����� ���� PUBLICKEYBLOB "��������� CSP".
                     */
    BYTE    bASN1GostR3410_94_PublicKeyParameters[1/*������������*/];
                    /*!< �������� ASN1 ��������� � DER ���������, ������������
                     * ��������� ��������� �����, ��� ������� ������
                     * GostR3410-2001-PublicKeyParameters � GostR3410-94-PublicKeyParameters
                     * CPPK [RFC 4491] � CPALGS [RFC 4357].
                     */
    BYTE    bPublicKey[1/*������������*/];
                    /*!< �������� �������� ���� � ������� ������������� (ASN1 DER)
                     * ��� ������� ������ GostR3410-2001-PublicKey � GostR3410-94-PublicKey
                     * CPPK [RFC 4491].
                     * ����� ������� ����� tPublicKeyParam.KeyParam.BitLen/8.
                     */
}   CRYPT_PUBLICKEYBLOB, *PCRYPT_PUBLICKEYBLOB;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������������� CRYPT_PRIVATEKEYBLOB ��������� ��������� �������� ����
 * ���� PRIVATEKEYBLOB ��� ������ "��������� CSP".
 *
 * \req_wincryptex
 * \sa CRYPT_PUBKEY_INFO_HEADER
 * \sa CPExportKey
 * \sa CPGetKeyParam
 */
typedef struct _CRYPT_PRIVATEKEYBLOB {
    CRYPT_PUBKEY_INFO_HEADER tPublicKeyParam;
                    /*!< ����� ��������� ��������� ����� ���� PRIVATEKEYBLOB "��������� CSP".
                     */
    BYTE    bExportedKeys[1/* ������ ������.*/];
	/*
	KeyTransferContent ::=
	SEQUENCE {
	    encryptedPrivateKey  GostR3410EncryptedKey,
	    privateKeyParameters PrivateKeyParameters,
	}
	KeyTransfer ::=
	SEQUENCE {
	    keyTransferContent       KeyTransferContent,
	    hmacKeyTransferContent   Gost28147HMAC
	}
	*/
}   CRYPT_PRIVATEKEYBLOB, *PCRYPT_PRIVATEKEYBLOB;

/* ����������� ��� ��������� DIVERSBLOB*/
/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� CRYPT_DIVERSBLOBHEADER ��������� ����
 * ���� DIVERSBLOB ��� ��������� �������������� ������ ��������� CSP.
 *
 * \req_wincryptex
 * \sa CRYPT_DIVERSBLOB
 * \sa CPImportKey
 */
typedef struct _CRYPT_DIVERSBLOBHEADER {
    BLOBHEADER BlobHeader;
                /*!< ����� ��������� �����, ����������������3� ����.
                 *  ���������� �������� ����������������� �����.
                 */
    ALG_ID      aiDiversAlgId;
                /*!< ���������� �������� �������������� �����.
                 */
    DWORD       dwDiversMagic;
                /*!< ������� �������������� �����,
                 * ��������������� � \ref DIVERS_MAGIC.
                 */
   /*    BYTE        *pbDiversData;
                !< ��������� �� ������, �� ������� ����������������� ����.
                 */
    DWORD       cbDiversData;
                /*!< ����� ������, �� ������� ����������������� ����.
                 */
} CRYPT_DIVERSBLOBHEADER, *LPCRYPT_DIVERSBLOBHEADER;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� CRYPT_DIVERSBLOB ��������� ����
 * ���� DIVERSBLOB ��� ��������� �������������� ������ ��������� CSP.
 *
 * \req_wincryptex
 * \sa CRYPT_DIVERSBLOBHEADER
 * \sa CPImportKey
 */
typedef struct _CRYPT_DIVERSBLOB {
    CRYPT_DIVERSBLOBHEADER DiversBlobHeader;
                /*!< ����� ��������� �����, ����������������� ����.
                 *  ���������� �������� ����������������� �����.
                 */
    BYTE        bDiversData[1/*������ ���������� �����: [4..40] ������*/];
                /*!< ������, �� ������� ����������������� ����.
                 */
} CRYPT_DIVERSBLOB, *LPCRYPT_DIVERSBLOB;

/*! \brief ��� ������: ������ ��� pin */
#define CRYPT_PIN_PASSWD 0
/*! \brief ��� ������: ��� ���������� ������������
     ������������ ��� ����������. */
#define CRYPT_PIN_ENCRYPTION 1
/*! \brief ��� ������: �������� ���������� �� ����� �� HANDLE.
     ������������ ����� �����������. */
#define CRYPT_PIN_NK 2
/*! \brief ��� ������: ���������� */
#define CRYPT_PIN_UNKNOWN 3
/*! \brief ��� ������: ��� � �������� ���������� � ����. */
#define CRYPT_PIN_QUERY 4
/*! \brief ��� ������: �������� ������. */
#define CRYPT_PIN_CLEAR 5
/*! \brief ��� ������: ������������ ���������� �������. */
#define CRYPT_PIN_HARDWARE_PROTECTION 6
/*! \brief ��� ������: ������ ��� FKC ����������, ��� �������������� �� EKE */
#define CRYPT_PIN_FKC_EKE 	7

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� �������� ���������� ��� ������� ������ ����������
 *
 * \req_wincryptex
 * \sa CPSetProvParam
 */
typedef struct _CRYPT_PIN_NK_PARAM {
    short n; /*!< ���������� ������������ ������. */
    short k; /*!< ���������� ������ ��� ��������. */
    DWORD *parts; /*!< 32-������ ���������� �������������� ������ ����������. */
} CRYPT_PIN_NK_PARAM;

/*!
 * \brief ��������� �������� ������, pin-����, ����� ����������,
 *  HANDLE ���������� ��� ����� ������.
 */
typedef union _CRYPT_PIN_SOURCE {
    char *passwd; /*!< ������, PIN-���, ��� ����������. */
    DWORD prov; /*!< 32-������ ���������� ������������� ����������. */
    CRYPT_PIN_NK_PARAM nk_handles; /*!< �������� �� NK �� ��������������� */
} CRYPT_PIN_SOURCE;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� �������� ���������� ���:
 *  1) ����� ������ ����������,
 *  2) �������� ������� ������� � ���������� (���, handle, ������), �� ����� ��������
 *     ����������� ���������� ������� ����������.
 *
 * \req_wincryptex
 * \sa CPSetProvParam
 */
typedef struct _CRYPT_PIN_PARAM {
    BYTE type;
    /*!< ��� ������.
 *  CRYPT_PIN_PASSWD - ������ ��� PIN,
 *  CRYPT_PIN_ENCRYPTION - HANDLE ���������� ������������.
 *  CRYPT_PIN_QUERY - ��� � �������� ���������� � ����,
 *  CRYPT_PIN_CLEAR - �������� ������.
 *  CRYPT_PIN_NK - ������� �� ����� k �� n
 */
     CRYPT_PIN_SOURCE dest; /*!< ������ ���������������� ���� */
} CRYPT_PIN_PARAM;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� ��������� ���������� � ���������� ������������ �� �����.
 *
 * \req_wincryptex
 * \sa CPGetProvParam
 */
typedef struct _CRYPT_NK_INFO_PARAM {
    short n; /*!< ���������� ������, �� ������� �������� ���������. */
    short k; /*!< ���������� ������, ����������� ��� ��������� ������. */
    char parts[1]; /*!< ������������������ n ASCIIZ �����. */
} CRYPT_NK_INFO_PARAM;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� ��� ��������� ���������� � ������ �� ���������.
 *
 * \req_wincryptex
 * \sa CPGetProvParam
 */
typedef struct _CRYPT_PASSWD_INFO_PARAM {
    unsigned min_passwd_length; /*!< ����������� ���������� ������ ������. */
    unsigned max_passwd_length; /*!< ������������ ���������� ������ ������. */
    unsigned passwd_type; /*!< ��� ������. */
} CRYPT_PASSWD_INFO_PARAM;

#define CSP_INFO_SIZE sizeof(CSP_INFO)

/*!
* \ingroup ProCSPData
*
* \brief ��������� ��� ��������� ���������� � ������ �� ���������.
*
* \req_wincryptex
* \sa CPGetProvParam, CRYPT_PASSWD_INFO_PARAM, CRYPT_NK_INFO_PARAM
*/
typedef union _CRYPT_PIN_INFO_SOURCE {
    CRYPT_PASSWD_INFO_PARAM passwd;
    CRYPT_NK_INFO_PARAM nk_info;
    char encryption[1];
} CRYPT_PIN_INFO_SOURCE;

/*!
* \ingroup ProCSPData
*
* \brief ��������� ��� ��������� ���������� � ������ �� ���������.
*
* \req_wincryptex
* \sa CPGetProvParam, CRYPT_PIN_INFO_SOURCE
*/
typedef struct _CRYPT_PIN_INFO {
    BYTE type; /*!< ��� ������.
 *  CRYPT_PIN_UNKNOWN - ��� ����������
 *  CRYPT_PIN_PASSWD - ������ ��� PIN,
 *  CRYPT_PIN_ENCRYPTION - HANDLE ���������� ������������.
 *  CRYPT_PIN_NK - ������� �� ����� k �� n
 *  CRYPT_PIN_HARDWARE_PROTECTION - ��� ������ ������������ ���������� �������
 */
     CRYPT_PIN_INFO_SOURCE dest; /*!< ������ ���������������� ���� */
} CRYPT_PIN_INFO;

#define PROVIDER_TYPE_FKC_MAGISTRA 1


/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� ��������� ���������� � ������ ���������� ��� �������������� �� EKE
 *
 * \req_wincryptex
 * \sa CPSetProvParam
 */
typedef struct _CRYPT_FKC_EKE_AUTH_INFO_PARAM {
    unsigned min_passwd_length; /*!< ����������� ���������� ������ ������. */
    unsigned max_passwd_length; /*!< ������������ ���������� ������ ������. */
    unsigned count_eke; /*!< ������� ���������� �������� EKE. */
    unsigned count_dh; /*!< ������� ���������� �������� �����-��������. */
    unsigned count_sig; /*!< ������� ���������� �������� �������. */
    unsigned count_err; /*!< ������� ���������� ������. */
    unsigned count_cerr; /*!< ������� ���������� ���������������� ������. */
    char fname[1]; /*!< UTF8Z-������ �������������� �����. */
} CRYPT_FKC_EKE_AUTH_INFO_PARAM;

typedef union _CRYPT_FKC_PIN_INFO_SOURCE {
    CRYPT_PIN_INFO_SOURCE passwd; /*!< ������� ������. */
    CRYPT_FKC_EKE_AUTH_INFO_PARAM eke_passwd; /*!< ������ �� EKE. */
} CRYPT_FKC_PIN_INFO_SOURCE;

typedef struct _CRYPT_FKC_PIN_INFO {
    BYTE type;
    /*!< ��� ������.
     *  CRYPT_PIN_FKC_EKE - ������ ���������� FKC ���������� �� EKE.
     *  ������ ���� ��� � CSP.
     */
     CRYPT_FKC_PIN_INFO_SOURCE dest; /*!< ������ ���������������� ���� */
} CRYPT_FKC_PIN_INFO;

/*!
 * \ingroup ProCSPData
 *
 * \brief �������� ��������� "�������� ��������� ����� � �������� �����-��������".
 * ��� ��������� ��������� ���������� ���������� ���� DWORD. 
 *
 * \req_wincryptex
 * \sa CPGetProvParam
 * \sa CPSetProvParam
 * \sa CRYPT_FKC_DH_CHECK
 */
typedef enum _CRYPT_FKC_DH_CHECK_VAL
{
    dh_check_disable = 1, /*!< �������� ��������� ����� �� �������������� */
    dh_check_enable = 2 /*!< �������� ��������� ����� �������������� */
} CRYPT_FKC_DH_CHECK_VAL;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� ��� ��������� ������� �������� ��������� �����.
 * �������� � ������������� �������� "�������� ��������� ����� � �������� �����-��������"
 * ��� ����������� FKC ( PP_FKC_DH_CHECK ). 
 *
 * \req_wincryptex
 * \sa CPGetProvParam
 * \sa CPSetProvParam
 */
typedef struct _CRYPT_FKC_DH_CHECK
{
    CRYPT_FKC_DH_CHECK_VAL checkdh; /* �������� ��������� */
    BOOL is_writable; /*!< ����� �� ���������� ��������� ����� �������� */
} CRYPT_FKC_DH_CHECK;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� ��� ��������� � ��������� �������� ����������� �����������.
 *
 * \req_wincryptex
 * \sa CPGetProvParam
 * \sa CPSetProvParam
 */
typedef struct _CRYPT_CACHE_SIZE {
    DWORD cache_size; /*!< ������ ����. */
    DWORD max_cache_size; /*!< ������������ ������ ����. */
    BOOL is_writable; /*!< ��. CACHE_RO  */
} CRYPT_CACHE_SIZE;

/*!
* \ingroup ProCSPData
*
* \brief ���� � ����������� � �����������, �������������� �����
* ��������������� ���������������.
*
* \req_wincryptex
* \sa CPGetProvParam
*/
typedef struct _CRYPT_ENUMREADER_INFO {
    char    szNickName[1]; /*!< NickName ����������� - NULL-��������������� ������. */
    char    szName[1]; /*!< ��� ����������� - NULL-��������������� ������. */
    DWORD   Flags; /*!< ����� �����������. */
} CRYPT_ENUMREADER_INFO;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� �������� ���������� ��� ��������� � ��������� ����������� �������� ��������� R ��� ��� 
 *  �� ���� ��������������� ��������� ��������.
 *
 * \sa CPGetHashParam
 * \sa CPSetHashParam
 */
typedef struct _CRYPT_HASH_BLOB_EX {
    CRYPT_PUBKEY_INFO_HEADER tPublicKeyParam;
    BYTE    pbData [2*SECRET_KEY_LEN];
} CRYPT_HASH_BLOB_EX, *PCRYPT_HASH_BLOB_EX;

/*!
 * \ingroup ProCSPData
 *
 * \brief ��������� �������� ���������� ������� ����������� �� ��������� CALG_EKEVERIFY_HASH.
 * 
 *
 * \sa CPGetKeyParam
 * \sa CPSetKeyParam
 */
typedef struct _TOKEN_VERIFYDATA {
    BYTE e_[3*SECRET_KEY_LEN];
    BYTE xQ_ab[SECRET_KEY_LEN];
    BYTE xQ_pw[SECRET_KEY_LEN];
    DWORD Verify;
} TOKEN_VERIFYDATA,*PTOKEN_VERIFYDATA;

#define CSP_INFO_FREE_SPACE	(0)	/* ��������� ����� �� /var � bytes */
#define CSP_INFO_NUMBER_UL	(1)	/* "\\local\\number_UL" --- ���������� ���������� ������ �� */
#define CSP_INFO_NUMBER_SIGNS	(2)     /* "\\local\\number_signs" --- ���������� �������� ������� */
#define CSP_INFO_KCARDS_CHANGES	(3)     /* "\\local\\Kcard_changes" --- ���������� ���� ���� ������ "�" */
#define CSP_INFO_NUMBER_KCARDS	(4)     /* "\\local\\number_Kcard_sessions" --- ���������� ���������� � ��������� ��� ���� ������ "�" */
#define CSP_INFO_NUMBER_KEYS	(5)     /* "\\local\\number_keys" --- ���������� ����������  */
#define CSP_INFO_FUTURE_SIZE	(10)
typedef struct
{
  WORD version;		/* ������ ��������� */
  DWORD time;		/* time_t */
  DWORD keys_remaining;	/* ������� ���� */
  DWORD future[CSP_INFO_FUTURE_SIZE];
} CSP_INFO;

/* ����� ���������� ����� ��� ���� 28147, ������� � ������.*/

#define CPC_FAST_CODE_DEFAULT	0
#define CPC_FAST_CODE_NO	1
#define CPC_FAST_CODE_USER	2

#ifdef UNIX
#ifdef __GNUC__
#define CPCAPI __attribute__((regparm(0)))
#else // __GNUC__
#define CPCAPI
#endif // __GNUC__
#else // UNIX
#define CPCAPI __cdecl
#endif // UNIX


/*!
 * \ingroup ProCSPData
 * \brief �������� ������� ������� FPU � ������ ���� ��.
 * 
 *  ������� ������ ������������ ������ FPU (��������
 *  �������� ��������� MMX (ST) � XMM ). �� ����������
 *  ����� ��� ���������� ���������, ��� ������, 
 *  ��� �������, ������������ �������������� ��������,
 *  �������������� �� �����, � �������������� ���������,
 *  �� ������� ����� ������ � ���������������� �������.
 *
 * \param buf [in] ������������� �����, ��������������� ����������� ��� ����������
 *  �������������� ���������.
 *
 * \param sz [in] ������ ������, ����������� ����������� ��� ����������
 *  �������������� ���������.
 *
 * \param bl_len [in] ������ ������, �������������� ��������, �����������
 * ���������� ���������.
 * 
 * \param op_type [in] ��� �������, ����������� ���������� ���������.
 * ��� ����� ���� ����� �� �������:<br>
 * <table><tr><th>
 * �������� \e op_type
 * </th><th>
 *      ��� �������
 * </th></tr><tr><td>
 * #CSP_OPERATION_CIPHER1
 * </td><td>
 *      ������������������ ������� ���������� �� ���� 28147-89
 * </td></tr><tr><td>
 * #CSP_OPERATION_CIPHER2
 * </td><td>
 *      �������������� ������� ���������� �� ���� 28147-89
 * </td></tr><tr><td>
 * #CSP_OPERATION_IMIT
 * </td><td>
 *      ������� ��������� ������������ �� ���� 28147-89
 * </td></tr><tr><td>
 * #CSP_OPERATION_HASH
 * </td><td>
 *      ������� ����������� �� ���� � 34.11-94
 * </td></tr></table>
 *
 * \return ��������� ������� ������������ FPU.
 *
 * \retval TRUE ������ ������������ ��� �����������. 
 * � ���� ������ ��������� ������� �������, ������������
 * MMX ��� SSE, � ����� ��� - ������� \ref CPC_Kernel_Fpu_End_Callback .
 * ��������� ���� ������� ���������� �������� � ������� ����������,
 * � ��� ���������������� ������� FPU ���������� ��� ��� ������� ����������,
 * ��� � ���������� �������������� ������. 
 * \retval FALSE ������ �� ��� �����������. � ���� ������
 * ��������� ������� �������, ������������ ������ ����������� �����
 * ���������� (�������������).
 * \sa CPC_FAST_CODE
 * \sa CPC_Kernel_Fpu_End_Callback
 * \sa CPSetProvParam()
 * \sa CPCSetProvParam()
 */
typedef BOOL CPCAPI CPC_Kernel_Fpu_Begin_Callback(
    /* [in] */ BYTE * buf,
    /* [in] */ size_t sz,
    /* [in] */DWORD bl_len,
    /* [in] */DWORD op_type);


/*!
 * \ingroup ProCSPData
 * \brief �������� ������� ������������ FPU � ������ ���� ��.
 * 
 *  ������� ������ ������������ ������������ FPU (��������������
 *  �������� ��������� MMX (ST) � XMM ). �� ���������� ����� 
 *  ��� ���������� ���������, ��� ������, ��� �������, ��������������
 *  � ���������� �������������� ��������, � ������������� ����� ������ 
 *  ������� \ref CPC_Kernel_Fpu_Begin_Callback .
 *
 * \param buf [in] �����, ��������������� ����������� ��� ����������
 *  �������������� ���������. � ��� ������ ���� ��������� ���������
 *  ������������ ������� \ref CPC_Kernel_Fpu_Begin_Callback .
 *
 * \param sz [in] ������ ������, ����������� ����������� ��� ����������
 *  �������������� ���������.
 *
 * \param op_type [in] ��� �������, ����������� ���������� ���������.
 * ��� ����� ���� ����� �� �������:<br>
 * <table><tr><th>
 * �������� \e op_type
 * </th><th>
 *      ��� �������
 * </th></tr><tr><td>
 * #CSP_OPERATION_CIPHER1
 * </td><td>
 *      ������������������ ������� ���������� �� ���� 28147-89
 * </td></tr><tr><td>
 * #CSP_OPERATION_CIPHER2
 * </td><td>
 *      �������������� ������� ���������� �� ���� 28147-89
 * </td></tr><tr><td>
 * #CSP_OPERATION_IMIT
 * </td><td>
 *      ������� ��������� ������������ �� ���� 28147-89
 * </td></tr><tr><td>
 * #CSP_OPERATION_HASH
 * </td><td>
 *      ������� ����������� �� ���� � 34.11-94
 * </td></tr></table>
 *
 * \return ��������� ������������ ������������ FPU.
 *
 * \retval TRUE ������������ ������������ ���� ������������. 
 * \retval FALSE ������������ �� ���� ������������. 
 *
 * \sa CPC_FAST_CODE_
 * \sa CPC_Kernel_Fpu_Begin_Callback
 * \sa CPSetProvParam()
 * \sa CPCSetProvParam()
 */
typedef BOOL CPCAPI CPC_Kernel_Fpu_End_Callback(
    /* [in] */ BYTE * buf,
    /* [in] */ size_t sz,
    /* [in] */ DWORD op_type);

/*!
 *  \ingroup ProCPCData
 *
 *  \brief ��������� ������������� SSE2.
 *
 *  �� ���������� Intel Pentium 4 ����� ������� ��������� ����������
 *  ���������� � ����������� �� ���� ������������� ���������� ���������� MMX � SSE2.
 *  ��������� ������� SSE2 �������������� � ������� ������ ���������.
 *  
 *  ����������������� �������, ������������ ���������� MMX � SSE2, ������� � 
 *  ��������� ������:
 *  <table><tr><th>
 * ������������� ������
 * </th><th>
 *      ������
 * </th></tr><tr><td>
 * #CSP_OPERATION_CIPHER1
 * </td><td>
 *      ������������������ ������� ���������� �� ���� 28147-89.
 *	��� ��� ���������� ������ ��������� ���������� MMX.
 * </td></tr><tr><td>
 * #CSP_OPERATION_CIPHER2
 * </td><td>
 *      �������������� ������� ���������� �� ���� 28147-89.
 *	��� ��� ���������� ������ ��������� ���������� MMX.
 * </td></tr><tr><td>
 * #CSP_OPERATION_IMIT
 * </td><td>
 *      ������� ��������� ������������ �� ���� 28147-89.
 *	��� ��� ���������� ������ ��������� ���������� MMX.
 * </td></tr><tr><td>
 * #CSP_OPERATION_HASH
 * </td><td>
 *      ������� ����������� �� ���� � 34.11-94.
 *	��� ��� ���������� ��������� ���������� MMX � SSE2.
 * </td></tr><tr><td>
 * #CSP_OPERATION_MULT
 * </td><td>
 *      ������� ��������� � ���� �� ������ P (����������� � ���������� ������� 
 *	� �����-��������).
 *	��� ��� ���������� ��������� ���������� MMX � SSE2.
 * </td></tr></table>
 * ������������ ������� ������������� ��� ������������ ��������� ���������� 
 * ������� ������� ����� �������� ���������� �������. ����� ��������� ������� 
 * ���������� � ����� ������� �������� �����, ��� ���������� ����� 
 * ��������������� ������� ������� MMX � SSE.
 *
 * � ����� � ������� ������������� ���������� �������� �� ���� ����������� 
 * ����������� x86 � �������� x86 �� ������������ x64 � IA64, ��� ����������� 
 * ������� ����������, ����� �� ������� ������� � ������� ����� �������� ������� 
 * �� ���������� ����������, � ���������� �������� ����, ��������� ������  � �.�. 
 *
 * ��������� ��������� �� ������������� �������� �������� ��������� �������
 * ����� � ������� ������ SetProvParam (PP_FAST_CODE_FUNCS), � ������� ����������
 * ������ ���������, ����, �� ������ CPC, ��� ������������� ������������������ 
 * ������, ����� �������� ������ ��������� � ������������� ����������, ���
 * ��� ������������� ���������������� � ���������������� ������, ����� ���������
 * ����� ������������ ������ ������� � ������ � ������� ������� csptest, �
 * ����������� '-speed -type ALL -mode REG'. ����� ����� ������� ����� � ������
 * ��� ��� �������� � �������� '/Parameters/MMXFuncs'.
 * 
 * � ���������� ���� ��� ������ ������������� ������� MMX:
 * 1. ����� ����������� ���������, ����������� �������� ����������������.
 * 2. ���������, ��������� ������ �� ������� ������������� �������.
 * 3. ���������, ��������������� ������������� � ������� ������� SetProvParam.
 * ������ �� ��� ��� ������ ����� ������� Crypt � CP ��������������� �� �������,
 * ���, ���� ������ ���������� ��� �������� �����������, ��� ��������� 
 * ����������� ���������, ���������� ����������� ��� ������ �������. 
 * ��� ������ �� ������ CPC ������ ��������� ���������� ������������� ��� �������������
 * ����������, ��� ������������� ��������� ������������ ��� ���������� ���������.
 *
 * ��� ��������� ������ ��������� ������� ��������� � ����� ������ ��������, 
 * �������� �� �� ������ ���������� ������������� ����� ������� ������� MMX � SSE,
 * �, ���� ����������� ����, ��������� ������. � ������ ����, ����� ����,
 * ����� ������� ������ �������, ������������ MMX ��� SSE2, ����� �����������
 * ����� callback'� ������� FPU, � �� ������������� ��� ����� �������������� ������
 * � ������ ��������� �������, ����� ���� ����� ������ callback ������� 
 * ������������ FPU. ���� ������ �� ������, ����� ����������� �������������
 * ��� �������.
 *
 * \sa CPC_CONFIG_
 */
typedef struct _CPC_FAST_CODE {
    DWORD UsesFunctions;
		/*!< ������������ ��������, ����� ���� ����� CPC_FAST_CODE_DEFAULT,
		 *   CPC_FAST_CODE_NO, CPC_FAST_CODE_USER.
		 * <table><tr><th>
		 * ��������� ��������:</th><th>�������������:
		 * </th>
		 * </tr>
		 * <tr><td>
		 * CPC_FAST_CODE_DEFAULT</td>
			<td>������������ ��������� ������� �� ���������.
		 * 	</td></tr>
		 * <tr><td>
		 * CPC_FAST_CODE_NO</td><td>������������ ��������� ������� ������������� �������.
		 * </td></tr>
		 * <tr><td>
		 * CPC_FAST_CODE_USER</td><td>������������ ��������� ������� �������, ���������� 
		 * ���������� UsedMask.
		 * </td></tr>
		 * </table>
		 */
    CPC_Kernel_Fpu_Begin_Callback * cp_kernel_fpu_begin;
		/*!< ��������� �� ������� ������� FPU.
		 *   ����������� � ������ ����. ������ ��������� �� ������� ������� FPU,
		 *   ������� ����� �������� �������, ������������ ���������� MMX � SSE.
		 *   ��������������� ������ ��� UsesFunctions == CPC_FAST_CODE_USER.
		 *   ��. \ref CPC_Kernel_Fpu_Begin_Callback
		 *   
		 */
    CPC_Kernel_Fpu_End_Callback *cp_kernel_fpu_end;
		/*!< ��������� �� ������� ������������ FPU.
		 *   ����������� � ������ ����. ������ ��������� �� ������� ������������
		 *   FPU. 
		 *   ������������ ������ ��� UsesFunctions == CPC_FAST_CODE_USER.
		 *   ��. \ref CPC_Kernel_Fpu_End_Callback
		 */
    DWORD  Kernel_Buf_Size;
		/*!< ������ �������������� ������, ������� ����� ������������ � ������� 
		 *   ������� � ������������� FPU ��� ���������� ���������. ������������ 
		 *   ������ ��� UsesFunctions == CPC_FAST_CODE_USER.
		 *   �������� �� ����� ��������� 1024.
		 *   ��. \ref CPC_Kernel_Fpu_Begin_Callback , \ref CPC_Kernel_Fpu_End_Callback
		 */
    DWORD   UsedMask;
		/*!< �����, �������� ��������� ������� �������. �������� ���������� 
		 *   ������ ��������������� ������� �������, ������������ ��������� ����������, 
		 *   ������� ������� �������� � ���������������� (��. ����). � ����������������
		 *   ������ � ��� ���������� ����� ��������� ��������� ���� ���� �������,
		 *   � ������ ���� - ����, ����� ������ ��������� �� ������ P. 
		 */
} CPC_FAST_CODE;

/*! \ingroup ProCSPData
 * \defgroup ProCSPDataFast ������������� ����
 * �������� �������������� ���� �� ����� ������� (� �������������� SSE2).
 *
 * ��� ������������� � ������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS), � ��������� pbData ������������
 * �����, ������������ ����� ���������� �� ���������� ��� �������.
 * ��������, ����� ������� ��������� �� ���������� ���, ����������
 * �� ������ \e dwFlags.
 *
 * ���� �������� ���� CRYPT_FAST_CODE_GET_SETFN, ��� ������
 * \ref CSP_FAST_CODE_GET_SETFN ����� ���������� � 1, ���� ��������� ����� ������������
 * ������� ���, � 0 - �����. ���� ���������� ���� CRYPT_FAST_CODE_ALL_FUNCTIONS,
 * ����� ����������� ��� �������, � �� ������ ����� ����������� ��� �����
 * \ref CSP_FAST_CODE_E_ECB, \ref CSP_FAST_CODE_E_CBC, \ref CSP_FAST_CODE_E_CNT,
 * \ref CSP_FAST_CODE_E_CFB, \ref CSP_FAST_CODE_D_ECB, \ref CSP_FAST_CODE_D_CBC,
 * \ref CSP_FAST_CODE_D_CNT, \ref CSP_FAST_CODE_D_CFB, \ref CSP_FAST_CODE_MD_ECB,
 * \ref CSP_FAST_CODE_GR3411SP, \ref CSP_FAST_CODE_GR3411H, \ref CSP_FAST_CODE_GR3411HV,
 * \ref CSP_FAST_CODE_HASH, \ref CSP_FAST_CODE_IMIT, \ref CSP_FAST_CODE_MULT,
 * � 1, ���� ��������������� ������� ���������� ������� ���, � 0 - �����.
 * � ������ ������������ ������� ������ �����  CRYPT_FAST_CODE_ALL_FUNCTIONS
 * ������������ CRYPT_FAST_CODE_ALL_USER_FUNCTIONS, � � ������ ���� �� -
 * CRYPT_FAST_CODE_ALL_KERNEL_FUNCTIONS. �� ������ ���� \ref CSP_FAST_CODE_GET_FN ���������� � 1,
 * ���� ������� ��� �������� �� ���� ��������� ��������, � 0 ���� ���� �� ����
 * �� ��������� ������� �� ���������.
 * ��������� ����������� ������ ������������.
 *
 * \sa #CPGetProvParam (PP_FAST_CODE_FLAGS)
 * \{
 */

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ����������� ������� ������ ������������� ������� �������.
 */
#define CSP_FAST_CODE_GET_FN	(1<<28)


/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� �����������, ����� �� ��������� .
 *  ��������� ������� ��� �� ������ ������.
 */
#define CSP_FAST_CODE_GET_SETFN	(1<<27)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ����, ��� ��������, ����� ���
 *  ����������� � ������� ������������ �� ECB
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_E_ECB	(1)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ����, ��� ��������, ����� ���
 *  ����������� � ������� ������������ �� CBC
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_E_CBC	(1<<1)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ����, ��� ��������, ����� ���
 *  ����������� � ������� ������������ �� CNT
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_E_CNT	(1<<2)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ����, ��� ��������, ����� ���
 *  ����������� � ������� ������������� �� CNT
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_D_CNT	(1<<2)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ����, ��� ��������, ����� ���
 *  ����������� � ������� ������������ �� CFB
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_E_CFB	(1<<3)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ����, ��� ��������, ����� ���
 *  ����������� � ������� ������������� �� ECB
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_D_ECB	(1<<4)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ����, ��� ��������, ����� ���
 *  ����������� � ������� ������������� �� CBC
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_D_CBC	(1<<5)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ����, ��� ��������, ����� ���
 *  ����������� � ������� ������������� �� CFB
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_D_CFB	(1<<6)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ����, ��� ��������, ����� ���
 *  ����������� � ������� ������������ �����
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_MD_ECB	(1<<7)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ����, ��� ��������, ����� ���
 *  ����������� � ���������� ������� �����������.
 *  ���� ��������������� ������ � ������ ���� ��.
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_GR3411SP	(1<<8)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ����, ��� ��������, ����� ���
 *  ����������� � ������� �����������.
 *  ���� ��������������� ������ � ������ ���� ��.
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_GR3411H	(1<<9)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ����, ��� ��������, ����� ���
 *  ����������� � ������� �������� ����.
 *  ���� ��������������� ������ � ������ ���� ��.
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_GR3411HV	(1<<10)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ����, ��� ��������, ����� ���
 *  ����������� � ������� ���-��������������.
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_HASH	(1<<11)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ����, ��� ��������, ����� ���
 *  ����������� � ������� ��������� ������������.
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_IMIT	(1<<12)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ����, ��� ��������, ����� ���
 *  ����������� � ������� ���������.
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_MULT	(1<<13)

/*!
 *  \brief ����, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ������������ ��� ����, ��� ��������, ����� ��� �����������
 *  � �������� ��������� � UNIX-��������� ��������.
 *  ����� 1 � ������ �������� ���� ������ �������,
 *  � 0 �����.
 */
#define CSP_FAST_CODE_MULT_ATT	(1<<13)

/*!
 *  \brief ����� ������, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ���������� ��� ����� ������� ������������.
 */
#define CSP_FAST_CODE_ALL_ENCRYPT (CSP_FAST_CODE_E_ECB|CSP_FAST_CODE_E_CBC|CSP_FAST_CODE_E_CNT|CSP_FAST_CODE_E_CFB)

/*!
 *  \brief ����� ������, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ���������� ��� ����� ������� �������������.
 */
#define CSP_FAST_CODE_ALL_DECRYPT (CSP_FAST_CODE_D_ECB|CSP_FAST_CODE_D_CBC|CSP_FAST_CODE_D_CNT|CSP_FAST_CODE_D_CFB)

/*!
 *  \brief ����� ������, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ���������� ��� ����� ������� �����������.
 */
#define CSP_FAST_CODE_ALL_HASH (CSP_FAST_CODE_HASH|CSP_FAST_CODE_GR3411SP|CSP_FAST_CODE_GR3411H|CSP_FAST_CODE_GR3411HV)

/*!
 *  \brief ����� ������, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ���������� ��� ����� ������� ���������.
 */
#define CSP_FAST_CODE_ALL_MULT (CSP_FAST_CODE_MULT|CSP_FAST_CODE_MULT_ATT)

/*!
 *  \brief ����� ������, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ���������� ��� ����� ������� ����������.
 */
#define CSP_FAST_CODE_ALL_CRYPT (CSP_FAST_CODE_ALL_ENCRYPT|CSP_FAST_CODE_ALL_DECRYPT|CSP_FAST_CODE_MD_ECB|CSP_FAST_CODE_IMIT)

/*!
 *  \brief ����� ������, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ���������� ��� ����� ������������� ������� ����������������.
 */
#define CSP_FAST_CODE_ALL_FUNCTIONS (CSP_FAST_CODE_ALL_CRYPT|CSP_FAST_CODE_ALL_HASH|CSP_FAST_CODE_ALL_MULT)

/*!
 *  \brief ����� ������, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ���������� ��� ����� ������������� �������
 *  ���������������� ������ ���� ��.
 */
#define CSP_FAST_CODE_ALL_KERNEL_FUNCTIONS (CSP_FAST_CODE_ALL_CRYPT|CSP_FAST_CODE_ALL_HASH)

/*!
 *  \brief ����� ������, ������������ �������� \ref CPGetProvParam (PP_FAST_CODE_FLAGS).
 *  ���������� ��� ����� ������������� �������
 *  ���������������� ����������������� ������.
 */
#define CSP_FAST_CODE_ALL_USER_FUNCTIONS (CSP_FAST_CODE_ALL_CRYPT|CSP_FAST_CODE_HASH|CSP_FAST_CODE_ALL_MULT)


/*!
 * \brief ����, ������������ ��� ������ \ref CPGetProvParam (PP_FAST_CODE_FLAGS), ����������� ������� ����
 *  ��� ���� ������� ���������� � ������ ���� ��.
 */
#define CRYPT_FAST_CODE_ALL_KERNEL_FUNCTIONS	1

/*!
 * \brief ����, ������������ ��� ������ \ref CPGetProvParam (PP_FAST_CODE_FLAGS), ����������� ������� ����
 * ��� ���� ������� ���������� � ������ ������������.
 */
#define CRYPT_FAST_CODE_ALL_USER_FUNCTIONS	2

/*!
 * \brief ����, ������������ ��� ������ \ref CPGetProvParam (PP_FAST_CODE_FLAGS), ����������� ������� ����
 * ��� ���� ������� ����������.
 */
#define CRYPT_FAST_CODE_ALL_FUNCTIONS		(CRYPT_FAST_CODE_ALL_KERNEL_FUNCTIONS|CRYPT_FAST_CODE_ALL_USER_FUNCTIONS)

/*!
 * \brief ����, ������������ ��� ������ \ref CPGetProvParam (PP_FAST_CODE_FLAGS), �����������
 * ��������� ����������� ����������.
 */
#define CRYPT_FAST_CODE_GET_SETFN		8


/*!
 *  \brief ��������� �������� �������� ��������� ������� \ref CPC_Kernel_Fpu_Begin_Callback .
 *  ������� � ���, ��� ������ ������� FPU ��������� � ������� ����������������� ����������.
 *  ����� ������ �������� �������������� ������ ������� ������������������� ����������, 
 *  ������������ ���������� MMX.
 */
#define CSP_OPERATION_CIPHER1	(CSP_FAST_CODE_E_CFB | CSP_FAST_CODE_E_CBC)

/*!
 *  \brief ��������� �������� �������� ��������� ������� \ref CPC_Kernel_Fpu_Begin_Callback .
 *  ������� � ���, ��� ������ ������� FPU ��������� � ������� ��������������� ����������.
 *  ����� ������ �������� �������������� ������ ������� ��������������� ����������, 
 *  ������������ ���������� MMX.
 */
#define CSP_OPERATION_CIPHER2	(CSP_FAST_CODE_E_ECB | CSP_FAST_CODE_E_CNT | CSP_FAST_CODE_D_ECB | CSP_FAST_CODE_D_CBC | CSP_FAST_CODE_D_CNT | CSP_FAST_CODE_D_CFB | CSP_FAST_CODE_MD_ECB)

/*!
 *  \brief ��������� �������� �������� ��������� ������� \ref CPC_Kernel_Fpu_Begin_Callback .
 *  ������� � ���, ��� ������ ������� FPU ��������� � ������� ��������� ������������.
 *  ����� ������ �������� �������������� ������ ������� ��������� ������������, 
 *  ������������ ���������� MMX.
 */
#define CSP_OPERATION_IMIT	(CSP_FAST_CODE_IMIT)

/*!
 *  \brief ��������� �������� �������� ��������� ������� \ref CPC_Kernel_Fpu_Begin_Callback .
 *  ������� � ���, ��� ������ ������� FPU ��������� � ������� ���������� ����. � ������ ������
 *  ���������� ��������� �� ������ �������� ST0 - ST7, �� � XMM0 - XMM7.
 *  ����� ������ �������� �������������� ������ ������� ������������, 
 *  ������������ ���������� MMX � SSE2.
 */
#define CSP_OPERATION_HASH	(CSP_FAST_CODE_ALL_HASH)

/*!
 *  \brief ������� ����� ��� ���������/���������� ���� MMX � ������� ���������.
 *  ������ �������� �������������� ������ ������� ��������� �� ������ P, 
 *  ������������ ���������� MMX � SSE2. ����������� ������ � ���������������� ������.
 */
#define CSP_OPERATION_MULT	(CSP_FAST_CODE_ALL_MULT)

/*!
 *  \brief ������� ����� ��� ���������/���������� ���� MMX �� ���� ��������.
 *  ������ �������� ���������� ����� ���� ��������������� ������� �������,
 *  ������������ MMX � SSE2.
 */
#define CSP_OPERATION_ALL	(CSP_OPERATION_MULT | CSP_OPERATION_HASH | CSP_OPERATION_IMIT | CSP_OPERATION_CIPHER2 | CSP_OPERATION_CIPHER1)

/*!
 *  \brief ������� �����, ���������� �������������� ��������� �������. �����������, ���� 
 *  ����� ���������� ����� ������� �� ��������� ��� ������� ����������.
 */
#define CSP_OPERATION_UNDEF	(0xFFFFFFFF)


/*! \} */

typedef struct _CRYPT_LCD_QUERY_PARAM {
  const char *message;
} CRYPT_LCD_QUERY_PARAM;


//Deprecated Defines
#if !(defined(CPCSP_C_SOURCE ) && CPCSP_C_SOURCE - 0 < 36) 
#undef CP_GR3410_94_PROV
#undef CP_KC1_GR3410_94_PROV
#undef CP_KC2_GR3410_94_PROV
#undef PH_GR3410_94_PROV

#undef PROV_GOST_DH
#undef PROV_GOST_94_DH
#endif

#if !defined(CPCSP_USE_NON_STANDART_OIDS) && !(defined(CPCSP_C_SOURCE ) && CPCSP_C_SOURCE - 0 < 36) 

/* Deprecated cipher mode*/
#undef CRYPT_MODE_CBC 

/* OIDs for HASH */
#undef szOID_GostR3411_94_TestParamSet
#undef szOID_GostR3411_94_CryptoPro_B_ParamSet
#undef szOID_GostR3411_94_CryptoPro_C_ParamSet
#undef szOID_GostR3411_94_CryptoPro_D_ParamSet

/* OIDs for Crypt */
#undef szOID_Gost28147_89_TestParamSet
#undef szOID_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet
#undef szOID_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet
#undef szOID_Gost28147_89_CryptoPro_RIC_1_ParamSet

/* OID for Signature 1024*/
#undef szOID_GostR3410_94_CryptoPro_A_ParamSet
#undef szOID_GostR3410_94_CryptoPro_B_ParamSet
#undef szOID_GostR3410_94_CryptoPro_C_ParamSet
#undef szOID_GostR3410_94_CryptoPro_D_ParamSet

/* OID for Signature 512*/
#undef szOID_GostR3410_94_TestParamSet

/* OID for DH 1024*/
#undef szOID_GostR3410_94_CryptoPro_XchA_ParamSet
#undef szOID_GostR3410_94_CryptoPro_XchB_ParamSet
#undef szOID_GostR3410_94_CryptoPro_XchC_ParamSet

/* OID for EC signature */
#undef szOID_GostR3410_2001_TestParamSet

#endif



/*! \defgroup ProCSPEx �������������� ��������� � �����������
 *\ingroup ProCSP
 * ������ ������ �������� ����������� ��������������� � ����������,
 * ������������ � ���������������� "��������� CSP".
 *
 * \{
 */

/*! \page DP1 �������������� ���������� ����������������
 *
 * <table>
 * <tr><th>�������������</th><th>�������� ��������������</th></tr>
 * <tr><td>CALG_GR3411</td><td>������������� ��������� ����������� �� ���� � 34.11-94.</td></tr>
 * <tr><td>CALG_G28147_MAC</td><td>������������� ��������� ����������� �� ���� 28147-89.</td></tr>
 * <tr><td>CALG_G28147_IMIT </td><td>�� �� �����, ��� � CALG_G28147_MAC (���������� ������).</td></tr>
 * <tr><td> CALG_GR3410 </td><td> ������������� ��������� ��� �� ���� � 34.10-94. </td></tr>
 * <tr><td> CALG_GR3410EL </td><td> ������������� ��������� ��� �� ���� � 34.10-2001.</td></tr>
 * <tr><td>CALG_G28147</td><td>������������� ��������� ���������� �� ���� 28147-89. </td></tr>
 * <tr><td>CALG_DH_EX_SF </td><td>������������� ��������� ������ ������ �� �����-�������� �� ���� ��������� ����� ������������. </td></tr>
 * <tr><td>CALG_DH_EX_EPHEM </td><td>������������� CALG_DH_EX ��������� ������ ������ �� �����-�������� �� ���� ��������� ����� ��������� ����. �������� ���� ���������� �� ���� � 34.10 94.</td></tr>
 * <tr><td>CALG_DH_EX </td><td>������������� CALG_DH_EX ��������� ������ ������ �� �����-�������� �� ���� ��������� ����� ������������. �������� ���� ���������� �� ���� � 34.10 94. </td></tr>
 * <tr><td>CALG_DH_EL_SF </td><td>������������� ��������� ������ ������ �� �����-�������� �� ���� ��������� ����� ������������. �������� ���� ���������� �� ���� � 34.10 2001.</td></tr>
 * <tr><td> CALG_DH_EL_EPHEM</td><td> ������������� ��������� ������ ������ �� �����-�������� �� ���� ��������� ����� ��������� ����. �������� ���� ���������� �� ���� � 34.10 2001.</td></tr>
 * <tr><td>CALG_PRO_AGREEDKEY_DH</td><td>������������� ��������� ��������� ����� ������ ����� �� �����-��������. </td></tr>
 * <tr><td>CALG_PRO_EXPORT </td><td> ������������� ��������� ����������� �������� �����.</td></tr>
 * <tr><td>CALG_SIMPLE_EXPORT </td><td>������������� ��������� �������� �������� �����. </td></tr>
 * <tr><td>CALG_SIMMETRYKEY </td><td> ������������� ��������� ���������� �� ���� 28147-89.</td></tr>
 * <tr><td> CALG_TLS1_MASTER_HASH</td><td>������������� ��������� ��������� ������� MASTER_HASH ��������� TLS 1.0.</td></tr>
 * <tr><td> CALG_TLS1_MAC_KEY</td><td>������������� ��������� ��������� ����� ����������� ��������� TLS 1.0. </td></tr>
 * <tr><td>CALG_TLS1_ENC_KEY </td><td> ������������� ��������� ��������� ����� ���������� ��������� TLS 1.0.</td></tr>
 * <tr><td> CALG_PRO_DIVERS</td><td>������������� ��������� ��������� �������������� �����.</td></tr>
 * <tr><td> CALG_RIC_DIVERS</td><td>������������� ��������� ��� �������������� �����. </td></tr>
 *</table>
 */

/*! \page DP2 ������ ����������
 * <table>
 * <tr><th>��������</th><th>�������� ���������</th></tr>
 * <tr><td>CRYPT_PROMIX_MODE </td><td>������� ������� ����������/������������� �� ���� 28147-89 � ��������������� ����� ����� ������ 1 �� �������������� ���������� </td></tr>
 * <tr><td>CRYPT_SIMPLEMIX_MODE </td><td>������� ������� ����������/������������� �� ���� 28147-89 ��� �������������� ����� � �������� ��������� ����������</td></tr>
 *</table>
*/

/*! \page DP3 ��������� ����������������
 * <table>
 * <tr><th>��������</th><th>�������� ���������</th></tr>
 * <tr><td>PP_ENUMOIDS_EX</td><td>�������� �������� ��������������� ��������, ������������ � ����������������</td></tr>
 * <tr><td>PP_HASHOID</td><td>�������� �/��� ������������� �������� � ���������� OID ���� ������ ������� ����������� ���� � 34.11-94 ��� ������������ ������������������ ���������</td></tr>
 * <tr><td>PP_CIPHEROID</td><td>�������� �/��� ������������� �������� � ���������� OID ���� ������ ��������� ���������� ���� 28147-89 ��� ������������ ������������������ ��������� </td></tr>
 * <tr><td>PP_SIGNATUREOID</td><td>�������� �/��� ������������� �������� � ���������� OID ���������� �������� ������� ��� ������������ ������������������ ��������� </td></tr>
 * <tr><td>PP_DHOID </td><td>�������� �/��� ������������� �������� � ���������� OID ���������� ��������� �����-�������� ��� ������������ ������������������ ���������  </td></tr>
 * <tr><td>PP_CHECKPUBLIC </td><td>���� �������� ��������� �����. ���� ���� ����������, �������������� �������� �������������� ������� ��������� ����� </td></tr>
 * <tr><td>PP_RANDOM</td><td>�������� �/��� ������������� ���� ���� SIMPLEBLOB ��� ������������� ��� � �������� ����������</td></tr>
 * <tr><td>PP_DRVCONTAINER </td><td>�������� ��������� (handle) ���������� � ��������</td></tr>
 * <tr><td>PP_MUTEX_ARG</td><td>�������������� ������������� ������� ���������������� � ���������� ����������</td></tr>
 * <tr><td>PP_ENUM_HASHOID</td><td>�������� �������� ��������������� ����������������� ��������, ��������� � �������� ����������� </td></tr>
 * <tr><td>PP_ENUM_CIPHEROID</td><td>�������� �������� ��������������� ����������������� ��������, ��������� � �������� ����������  </td></tr>
 * <tr><td>PP_ENUM_SIGNATUREOID</td><td>�������� �������� ��������������� ����������������� ��������, ��������� � �������� �������� �������</td></tr>
 * <tr><td>PP_ENUM_DHOID</td><td>�������� �������� ��������������� ����������������� ��������, ��������� � ���������� �����-��������  </td></tr>
 *</table>
*/

/*! \page DP4 ��������� �������������� �������� ������
 * <table>
 * <tr><th>��������</th><th>�������� ���������</th></tr>
 * <tr><td>DIVERSKEYBLOB</td><td>��� ��������� ����� ��� �������������� ������ � �������
    ������� CPImportKey � ������ CALG_PRO_EXPORT</td></tr>
 *</table>
*/

/*! \page DP5 �������������� ��������� ������� �����������
 * <table>
 * <tr><th>��������</th><th>�������� ���������</th></tr>
 * <tr><td>HP_HASHSTARTVECT</td><td>��������� ������ ������� �����������, ��������������� �����������</td></tr>
 * <tr><td>HP_OID</td><td>������ ���� ������ ������� �����������</td></tr>
 *</table>
*/

/*! \page DP6 �������������� ��������� ������
 * <table>
 * <tr><th>��������</th><th>�������� ���������</th></tr>
 * <tr><td>KP_IV </td><td>��������� ������ ������������� ��������� ���������� ���� 28147-89</td></tr>
 * <tr><td>KP_MIXMODE</td><td>���������� ������������� �������������� ����� ����� ��������� 1�� ���������� � ������� ����������/������������� � ���������� ������������ ��������� ���� 28147-89 </td></tr>
 * <tr><td>KP_OID</td><td>������ ���� ������ ������� �����������</td></tr>
 * <tr><td>KP_HASHOID</td><td>������������� ���� ������ ������� ����������� ���� � 34.11-94</td></tr>
 * <tr><td>KP_CIPHEROID</td><td>������������� ���� ������ ��������� ���������� ���� 28147-89</td></tr>
 * <tr><td>KP_SIGNATUREOID</td><td>������������� ���������� �������� �������</td></tr>
 * <tr><td>KP_DHOID</td><td>������������� ���������� ��������� �����-��������</td></tr>
 *</table>
*/

/*! \page DP8 ��������� �������������� ����������������� ���������� ����������
 * <table>
 * <tr><th>��������</th><th>������</th><th>�������� ���������</th></tr>
 * <tr><td>szOID_CP_GOST_28147</td><td>"1.2.643.2.2.21"</td><td>�������� ���������� ���� 28147-89</td></tr>
 * <tr><td>szOID_CP_GOST_R3411</td><td>"1.2.643.2.2.9"</td><td>������� ����������� ���� � 34.11-94</td></tr>
 * <tr><td>szOID_CP_GOST_R3410</td><td>"1.2.643.2.2.20"</td><td>�������� ���� � 34.10-94, ������������ ��� ��������/������� ������</td></tr>
 * <tr><td>szOID_CP_GOST_R3410EL</td><td>"1.2.643.2.2.19"</td><td>�������� ���� � 34.10-2001, ������������ ��� ��������/������� ������</td></tr>
 * <tr><td>szOID_CP_DH_EX</td><td>"1.2.643.2.2.99"</td><td>�������� �����-�������� �� ���� ������������� �������</td></tr>
 * <tr><td>szOID_CP_DH_EL</td><td>"1.2.643.2.2.98"</td><td>�������� �����-�������� �� ���� ������������� ������</td></tr>
 * <tr><td>szOID_CP_GOST_R3411_R3410</td><td>"1.2.643.2.2.4"</td><td>�������� �������� ������� ���� � 34.10-94</td></tr>
 * <tr><td>szOID_CP_GOST_R3411_R3410EL</td><td>"1.2.643.2.2.3"</td><td>�������� �������� ������� ���� � 34.10-2001</td></tr>
 * <tr><td>szOID_KP_TLS_PROXY</td><td>"1.2.643.2.2.34.1"</td><td>����� TLS-�������</td></tr>
 * <tr><td>szOID_KP_RA_CLIENT_AUTH</td><td>"1.2.643.2.2.34.2"</td><td>������������� ������������ �� ������ �����������</td></tr>
 * <tr><td>szOID_KP_WEB_CONTENT_SIGNING</td><td>"1.2.643.2.2.34.3"</td><td>������� ����������� ������� ��������</td></tr>
 *</table>
*/

/*! \ingroup ProCSPEx
 * \page CP_PARAM_OIDS �������������� ����������������� ���������� ����������
 * <table>
 * <tr><th>��������</th><th>������</th><th>�������� ���������</th></tr>
 * <tr><td>szOID_GostR3411_94_TestParamSet</td><td>"1.2.643.2.2.30.0"</td><td>�������� ���� ������</td></tr>
 * <tr><td>szOID_GostR3411_94_CryptoProParamSet</td><td>"1.2.643.2.2.30.1"</td><td>���� ������ ������� ����������� �� ���������, ������� "�����-�"</td></tr>
 * <tr><td>szOID_GostR3411_94_CryptoPro_B_ParamSet</td><td>"1.2.643.2.2.30.2"</td><td>���� ������ ������� �����������, ������� 1</td></tr>
 * <tr><td>szOID_GostR3411_94_CryptoPro_C_ParamSet</td><td>"1.2.643.2.2.30.3"</td><td>���� ������ ������� �����������, ������� 2</td></tr>
 * <tr><td>szOID_GostR3411_94_CryptoPro_D_ParamSet</td><td>"1.2.643.2.2.30.4"</td><td>���� ������ ������� �����������, ������� 3</td></tr>
 * <tr><td>szOID_Gost28147_89_TestParamSet</td><td>"1.2.643.2.2.31.0"</td><td>�������� ���� ������ ��������� ����������</td></tr>
 * <tr><td>szOID_Gost28147_89_CryptoPro_A_ParamSet</td><td>"1.2.643.2.2.31.1"</td><td>���� ������ ��������� ���������� �� ���������, ������� "�����-�"</td></tr>
 * <tr><td>szOID_Gost28147_89_CryptoPro_B_ParamSet</td><td>"1.2.643.2.2.31.2"</td><td>���� ������ ��������� ����������,������� 1</td></tr>
 * <tr><td>szOID_Gost28147_89_CryptoPro_C_ParamSet</td><td>"1.2.643.2.2.31.3"</td><td>���� ������ ��������� ����������,������� 2</td></tr>
 * <tr><td>szOID_Gost28147_89_CryptoPro_D_ParamSet</td><td>"1.2.643.2.2.31.4"</td><td>���� ������ ��������� ����������,������� 3</td></tr>
 * <tr><td>szOID_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet</td><td>"1.2.643.2.2.31.5" </td><td>���� ������, ������� ����� ���������</tr>
 * <tr><td>szOID_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet</td><td>"1.2.643.2.2.31.6" </td><td>���� ������, ������������ ��� ���������� � ������������</td></tr>
 * <tr><td>szOID_GostR3410_94_CryptoPro_A_ParamSet</td><td>"1.2.643.2.2.32.2"</td><td>��������� P,Q,A �������� ������� ���� � 34.10-94, ������� "�����-�". ����� �������������� ����� � ��������� �����-��������</td></tr>
 * <tr><td>szOID_GostR3410_94_CryptoPro_B_ParamSet</td><td>"1.2.643.2.2.32.3"</td><td>��������� P,Q,A �������� ������� ���� � 34.10-94, ������� 1. ����� �������������� ����� � ��������� �����-��������</td></tr>
 * <tr><td>szOID_GostR3410_94_CryptoPro_C_ParamSet</td><td>"1.2.643.2.2.32.4"</td><td>��������� P,Q,A �������� ������� ���� � 34.10-94, ������� 2. ����� �������������� ����� � ��������� �����-��������</td></tr>
 * <tr><td>szOID_GostR3410_94_CryptoPro_D_ParamSet</td><td>"1.2.643.2.2.32.5"</td><td>��������� P,Q,A �������� ������� ���� � 34.10-94, ������� 3. ����� �������������� ����� 2 ��������� �����-��������</td></tr>
 * <tr><td>szOID_GostR3410_94_CryptoPro_XchA_ParamSet</td><td>"1.2.643.2.2.33.1" </td><td>��������� P,Q,A ��������� �����-�������� �� ���� ���������������� �������, ������� 1</td></tr>
 * <tr><td>szOID_GostR3410_94_CryptoPro_XchB_ParamSet</td><td>"1.2.643.2.2.33.2" </td><td>��������� P,Q,A ��������� �����-�������� �� ���� ���������������� �������, ������� 2</td></tr>
 * <tr><td>szOID_GostR3410_94_CryptoPro_XchC_ParamSet</td><td>"1.2.643.2.2.33.3" </td><td>��������� P,Q,A ��������� �����-�������� �� ���� ���������������� �������, ������� 3</td></tr>
 * <tr><td>szOID_GostR3410_2001_TestParamSet</td><td>"1.2.643.2.2.35.0"</td><td>�������� ��������� a, b, p,q, (x,y) ��������� ���� � 34.10-2001 </td></tr>
 * <tr><td>szOID_GostR3410_2001_CryptoPro_A_ParamSet</td><td>"1.2.643.2.2.35.1"</td><td>��������� a, b, p,q, (x,y) �������� ������� � ��������� �����-�������� �� ���� ��������� ���� � 34.10-2001, ������� ���������������� </td></tr>
 * <tr><td>szOID_GostR3410_2001_CryptoPro_B_ParamSet</td><td>"1.2.643.2.2.35.2"</td><td>��������� a, b, p,q, (x,y) �������� ������� � ��������� �����-�������� �� ���� ��������� ���� � 34.10-2001, ������� ����� ���������</td></tr>
 * <tr><td>szOID_GostR3410_2001_CryptoPro_C_ParamSet</td><td>"1.2.643.2.2.35.2"</td><td>��������� a, b, p,q, (x,y) �������� ������� � ��������� �����-�������� �� ���� ��������� ���� � 34.10-2001, ������� 1</td></tr>
 * <tr><td>szOID_GostR3410_2001_CryptoPro_XchA_ParamSet</td><td>"1.2.643.2.2.36.0"</td><td> ��������� a, b, p,q, (x,y) ��������� �����-�������� �� ���� ��������� ���� � 34.10-2001, ������� ����������������. ������������ �� �� ���������, ��� � � ��������������� szOID_GostR3410_2001_CryptoPro_A_ParamSet</td></tr>
 * <tr><td>szOID_GostR3410_2001_CryptoPro_XchB_ParamSet</td><td>"1.2.643.2.2.35.3"</td><td>��������� a, b, p,q, (x,y) �������� ������� � ��������� �����-�������� �� ���� ��������� ���� � 34.10-2001, ������� 1</td></tr>
 *</table>
 *
*/

/*! \} */

/*! 
 * \ingroup ProCSPData
 *
 * \brief ���� � ��������������� ���������������� � �����������.
 *
 * \req_wincryptex
 * \sa CPGetProvParam
 */
typedef struct _CONTAINER_EXTENSION {
    BOOL bCritical; /*!< ���� ������������ ����������. */
    DWORD cbExtension; /*!< ����� ������ � pbExtension. */
    BYTE pbExtension[1]; /*!< ������. */
    char sOid[1]; /*!< ������ � OID-�� ���������� (������������� ���������). */
} CONTAINER_EXTENSION;

//������ ��� ����������� � wincrypt.h
#ifdef CERT_FIND_SUBJECT_STR
#   undef CERT_FIND_SUBJECT_STR
#   undef CERT_FIND_ISSUER_STR
#   ifdef _UNICODE
#	define CERT_FIND_SUBJECT_STR	CERT_FIND_SUBJECT_STR_W
#	define CERT_FIND_ISSUER_STR	CERT_FIND_ISSUER_STR_W
#   else
#	define CERT_FIND_SUBJECT_STR	CERT_FIND_SUBJECT_STR_A
#	define CERT_FIND_ISSUER_STR	CERT_FIND_ISSUER_STR_A
#   endif // !UNICODE
#endif

#if !defined(_DDK_DRIVER_)

typedef struct _CPESS_CERT_ID {
    CRYPT_HASH_BLOB CertHash;
    CERT_ISSUER_SERIAL_NUMBER IssuerSerial;
} CPESS_CERT_ID, *PCPESS_CERT_ID;

typedef struct _CPESS_CERT_IDV2 {
    CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
    CRYPT_HASH_BLOB CertHash;
    CERT_ISSUER_SERIAL_NUMBER IssuerSerial;
} CPESS_CERT_IDV2, *PCPESS_CERT_IDV2,
  CPOTHER_CERT_ID, *PCPOTHER_CERT_ID;

typedef struct _CPCMSG_SIGNING_CERTIFICATE {
    DWORD cCert;
    CPESS_CERT_ID* rgCert;
    DWORD cPolicy;
    CERT_POLICY_INFO* rgPolicy;
} CPCMSG_SIGNING_CERTIFICATE, *PCPCMSG_SIGNING_CERTIFICATE;

typedef struct _CPCMSG_SIGNING_CERTIFICATEV2 {
    DWORD cCert;
    CPESS_CERT_IDV2* rgCert;
    DWORD cPolicy;
    CERT_POLICY_INFO* rgPolicy;
} CPCMSG_SIGNING_CERTIFICATEV2, *PCPCMSG_SIGNING_CERTIFICATEV2;

typedef struct _CPCMSG_OTHER_SIGNING_CERTIFICATE {
    DWORD cCert;
    CPOTHER_CERT_ID* rgCert;
    DWORD cPolicy;
    CERT_POLICY_INFO* rgPolicy;
} CPCMSG_OTHER_SIGNING_CERTIFICATE, *PCPCMSG_OTHER_SIGNING_CERTIFICATE; 

typedef struct _CPCERT_PRIVATEKEY_USAGE_PERIOD {
    FILETIME *pNotBefore;
    FILETIME *pNotAfter;
} CPCERT_PRIVATEKEY_USAGE_PERIOD, *PCPCERT_PRIVATEKEY_USAGE_PERIOD;
/*! \endcond */

#define CPPRIVATEKEY_USAGE_PERIOD_CERT_CHAIN_POLICY_SKIP_END_CERT_FLAG	    (0x00010000)
#define CPTIMESTAMP_SIGNING_CERT_CHAIN_POLICY_IGNORE_NOT_CRITICAL_EKU_FLAG  (0x00020000)
#define CPTIMESTAMP_SIGNING_CERT_CHAIN_POLICY_IGNORE_NOT_ONE_EKU_FLAG	    (0x00040000)

typedef struct _CPPRIVATEKEY_USAGE_PERIOD_EXTRA_CERT_CHAIN_POLICY_PARA {
    DWORD cbSize; 
    FILETIME* pPrivateKeyUsedTime; 
} CPPRIVATEKEY_USAGE_PERIOD_EXTRA_CERT_CHAIN_POLICY_PARA,
*PCPPRIVATEKEY_USAGE_PERIOD_EXTRA_CERT_CHAIN_POLICY_PARA,
CPSIGNATURE_EXTRA_CERT_CHAIN_POLICY_PARA,
*PCPSIGNATURE_EXTRA_CERT_CHAIN_POLICY_PARA,
CPTIMESTAMP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA,
*PCPTIMESTAMP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA;

#define CPCERT_TRUST_PRIVATE_KEY_IS_NOT_TIME_VALID	    (0x00000001)
#define CPCERT_TRUST_PRIVATE_KEY_IS_NOT_TIME_VALID_FOR_CRL  (0x00000002)
#define CPCERT_TRUST_IS_NOT_CRITICAL_EKU		    (0x00000004)
#define CPCERT_TRUST_IS_NOT_ONE_EKU			    (0x00000008)
#define CPCERT_TRUST_IS_NOT_VALID_FOR_USAGE		    (CERT_TRUST_IS_NOT_VALID_FOR_USAGE)
							 // (0x00000010)
#define CPCERT_TRUST_IS_NOT_VALID_BY_KEYUSAGE		    (0x00000020)
#define CPCERT_TRUST_IS_NOT_VALID_FOR_OCSP_SIGNING	    (0x00000040)

typedef struct _CPPRIVATEKEY_USAGE_PERIOD_EXTRA_CERT_CHAIN_POLICY_STATUS {
    DWORD cbSize; 
    DWORD dwError; 
    LONG lChainIndex; 
    LONG lElementIndex; 
} CPPRIVATEKEY_USAGE_PERIOD_EXTRA_CERT_CHAIN_POLICY_STATUS,
*PCPPRIVATEKEY_USAGE_PERIOD_EXTRA_CERT_CHAIN_POLICY_STATUS,
CPSIGNATURE_EXTRA_CERT_CHAIN_POLICY_STATUS,
*PCPSIGNATURE_EXTRA_CERT_CHAIN_POLICY_STATUS,
CPTIMESTAMP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS,
*PCPTIMESTAMP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS;

typedef struct _CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS {
    DWORD cbSize;
    DWORD dwError;
    LONG lChainIndex;
    LONG lElementIndex;
    BOOL fNoCheck;
    BOOL* rgCertIdStatus;
} CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS,
*PCPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_STATUS;

#ifndef OCSP_REQUEST_V1

typedef struct _OCSP_CERT_ID {
    CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;  // Normally SHA1
    CRYPT_HASH_BLOB             IssuerNameHash; // Hash of encoded name
    CRYPT_HASH_BLOB             IssuerKeyHash;  // Hash of PublicKey bits
    CRYPT_INTEGER_BLOB          SerialNumber;
} OCSP_CERT_ID, *POCSP_CERT_ID;
#define OCSP_REQUEST_V1     0
#endif

typedef struct _CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA {
    DWORD cbSize;
    FILETIME* pPrivateKeyUsedTime;
    DWORD cCertId;
    POCSP_CERT_ID rgCertId;
} CPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA,
*PCPOCSP_SIGNING_EXTRA_CERT_CHAIN_POLICY_PARA;
/*! \cond csp  */

#endif /*!defined(_DDK_DRIVER_)*/

#ifdef __cplusplus
}
#endif // __cplusplus

/*****************************************************
		    CRYPT_PACKET 
******************************************************/
/*! \ingroup ProCSPData
 * \defgroup CryptPacket  ���������� � ����������� ������
 *
 * ����� - ��������� �������� ������, ���������� �� ������� ���������� 
 * CPEncrypt(), CPCEncrypt(),CPDecrypt(), CPCDecrypt().
 * ����� ������� �� �����:
 * <table><tr><th>
 * ���� 
 * </th><th>
 *      ��������
 * </th></tr><tr><td>
 * ������������� ������ (DIVERSBLOB)
 * </td><td>
 *      ������������ ����, ���������� ���� �������������� ����� ���������� � ����������� �� ��������� CALG_PRO_DIVERS.
 * </td></tr><tr><td>
 * ��������� ������ (HEADER)
 * </td><td>
 *      ������������ ���� ����� �� ����� 255 ����. �� ���������, ���������� ���-�������� hHash.
 * </td></tr><tr><td>
 * ������ ������������� (IV)
 * </td><td>
 *      ������������ ����, ���������� ������ ������������� ���������� ������. �� ���������, ���������� �����������.
 * </td></tr><tr><td>
 * ���� ������ (PAYLOAD)
 * </td><td>
 *      ������������ ����, ��������� � ����������.
 * </td></tr><tr><td>
 * ������� (TRAILER)
 * </td><td>
 *      ������������ ���� ����� �� ����� 254 ����. �� ���������, ���������� ���-�������� hHash.
 * </td></tr><tr><td>
 * �������� ������� ����������� ������ (HASH)
 * </td><td>
 *      ������������ ����, ����� ���� �����������. 
 * </td></tr>
 * </table> 
 *
 * ��� ���������� ������� �������������� ������ ����������: CRYPT_MODE_CNT, CRYPT_MODE_CFB, CRYPT_MODE_CBCSTRICT.
 * �� ���� ������� ���������� ����� ���� ������������ �����: CRYPT_PROMIX_MODE, CRYPT_SIMPLEMIX_MODE.
 *
 * � �������� ������ ���������� ����� ������� ������� ����������.
 *
 * � ������ CBC ����� ����� ��������� ������ ������ ���� ������ 8, ����� ������ ���� ������� 8 ����� 
 * ������� ���������� �������� IOVEC, � ��������� ������ ������������ ������ NTE_BAD_DATA. 
 * ������ �������������� � ����������� ������� �����, ������� � ������ CBC ������������.
 *
 * ����� CP_CHP_IV_RANDOM, CP_CHP_IV_USER, CP_CHP_HASH_PACKET ������������� ��� ��������� 
 * ������� � ������� � ��������� ���������� ������� ���������� �������, � ��������� ������� �������.
 *
 * ����� CP_CHP_IV_CHAIN, CP_CHP_HASH_CHAIN, CP_CHP_HASH_NONE  ������������� ��� ��������� ������� � �������,
 * ������������� �������� ���� ������� � ���������� ������������������.
 *
 * � ��������� ������� ��������� ������� ������������� ������� ��������� �������:
 * <table><tr><th>
 * �������� ������
 * </th><th>
 *      ������� � ����������� ������
 * </th></tr><tr><td>
 * CRYPT_SIMPLEMIX_MODE ��������� � CP_CHP_IV_RANDOM, 
 * CRYPT_SIMPLEMIX_MODE ��������� � CP_CHP_IV_USER
 * </td><td>
 *	��������� ������� ����� ����������� � ������������� ������ Final=FALSE.
 *	����� ������, �������������� �� ����� �����, ��������� 4�. 
 * </td></tr><tr><td>
 * CRYPT_PROMIX_MODE ��������� � CP_CHP_IV_RANDOM, 
 * CRYPT_PROMIX_MODE ��������� � CP_CHP_IV_USER
 * </td><td>
 *	��������� ������� ������ ����������� � ������������� ������ Final=TRUE.
 *	����� ������, �������������� �� ����� �����,  ��������� 4� ���� ������ ������� < 4096.
 * </td></tr><tr><td>
 * CRYPT_SIMPLEMIX_MODE ��������� � CP_CHP_IV_CHAIN
 * </td><td>
 *	��������� ������ � ������ Final=TRUE �������� ���������� ��������� ������� �������.
 * 	��������� ������ � ������ Final=FALSE �������� ����������� ��������� ������� �������.
 *	�� ����� ����� ��������������� ����� ���� ���������� ��������� ������� �������.
 *	����� ������, �������������� �� ����� �����, ��������� 4�.
 * </td></tr><tr><td>
 * CRYPT_PROMIX_MODE ��������� � CP_CHP_IV_CHAIN
 * </td><td>
 *	��������� ������ � ������ Final=TRUE �������� ���������� ��������� ������� �������.
 * 	��������� ������ � ������ Final=FALSE �������� ����������� ��������� ������� �������.
 *	�� ����� ����� ����� �������������� ������� ����� �� ����� 128000�. 
 *	���������� ������� ���������� 4096.
 * </td></tr>
 * </table>
 * 
 * �� ���� ������� ������ ������� ����������� ����� ���������� ��������� ������ 
 * ����������� ��� ��������� ���������� ������. 
 * ��� ����, � ������ CP_CHP_HASH_CHAIN � CP_CHP_HASH_NONE ������ ������ ��� ����������� ����������� ������, 
 * � ������ CP_CHP_HASH_PACKET ������ ���������������.
 *
 * ��� ������������� ������ � ������ ��� ��������� � ������, ����������� � ������������  
 * �������� HASH, ������������� � ������� ������, � ����� ������������ ���������, ������� CPDecrypt() 
 * ���������� ������ (FALSE), ������� CPCDecrypt() � GetLastError() ���������� NTE_BAD_HASH, 
 * ������ ������� ����������� ��������� CPDecrypt(), CPCDecrypt() �� ����������������. 
 * � ���� ������ ���������� ����� �������� ������������ �������� HASH
 * ������� CPGetHashParam() � ������ ������� ������� � ���������� ��������������� ������
 * (��������: �����, �������������� � ������ CP_CHP_HASH_CHAIN, ������ ���� ������; 
 * �����, �������������� � ������ CP_CHP_HASH_PACKET ����� ���� ���������). 
 * � ������ ����������� ��������� ������ ���������� ������ ������� (������� �����) ������ ������� �����������.
 *
 * �� ������� ���������� ������� ���������� � ����������� ����� ����� ���� ����������� ��� �������, 
 * ������������ ���������� pbData � ������ cbData, ��� � �������� IOVEC �����/������, 
 * ������������ ���������� pbData �� ������� ������� �������� \ref CSP_iovec � ������ ��������� ������� cbData.
 * ����� ������������� ��������� ����� ������������� �����/������ ������������ ������ CP_CRYPT_DATA_IOVEC, 
 * � ��������� ������ ���� ����� CP_CRYPT_DATA_IOVEC �������� ���������� �������� ���������.
 *
 *
 * ���������:
 *
 *   1. � ������ hHash=0, �������� ������� ����������� �� ��������������.
 *
 *   2.	������������� ������ � ���� IOVEC �������� ����������� �� ������������� � ���� ������.
 *      ������� �����, ��� IOVEC ������������ ������, � �������� ��������� ������ ���������� �� ������.
 *
 *   3.	������������ ���������� ��������� IOVEC ������� �� ����������. 
 * ����� ���������� ������ ������������� ����������� ������������ 16 ��������� IOVEC.
 *
 *   4. ���� ����� �������� IOVEC >= 0.
 *
 *
 * ��������� ������ � ������� ��������� ����� ������ ������������ 
 * ���������� ������ ��������� dwFlags, 
 * ������������� ��������� OR; �������� ������ ��������, �� ��� 
 * ��������� �������� ����� ���������. ��� ������������ ������ 
 * ������������� ������������ ������ CP_CHP().
 *
 * \sa #CPEncrypt (CP_CRYPT_HASH_PACKET)
 * \sa #CPDecrypt (CP_CRYPT_HASH_PACKET)
 * \sa #CP_CHP()
 * \{
 */

/*!
 *  \brief ���� - ������� �������� ��������� ������, ������ ���� ����������, ���� ������������ ��������� ������,
 *  � ��������� ������ dwFlags ����� ���� ����� ����, ��� ������������ ��������� �������� ������ ������. 
 */
#define CP_CRYPT_HASH_PACKET		(0x80)
/*!
 *  \brief ���� ���������� ������� ��������� ������ ������ - ����������� (�����������) ����� ����������.
 */
#define CP_CHP_HASH_ENCRYPT		(0x00)
/*!
 *  \brief ���� ���������� ������� ��������� ������ ������ - ���������� ����� ����������� (�����������).
 */
#define CP_CHP_ENCRYPT_HASH		(0x10)
/*!
 *  \brief ���� ����������� ������� ������������� (IV). ���� ����������, IV ������� �� ���������� ������ � ����������. 
 *	 ���� �� ����������, IV ,���� ������������ � ������, ������� �� ���������� ������, �� �� ����������.
 */
#define CP_CHP_IV_HEADER		(0x08)
/*!
 *  \brief ���� �������������� ����� ���������� � ����������� �� ��������� CALG_PRO_DIVERS. 
 *  ���� ������������ ������������� ������ � ����� ������, ���� �������������� ������ ����������� 
 *  � ������� ������ � ��� ������.
 *  ���� ������������ ������������� ������ � ����� ������� �����-������, 
 *  ���� �������������� ������ ������������ � ������ ���������� ������� �������.
 */
#define CP_CHP_STARTMIX			(0x04)
/*!
 *  \brief ����� ���������� IV. ������������ ����� ���� �� 2 ��������� ���. 
 *  ������� �������� ���� ������������� CP_CHP_IV_CHAIN.
 *  ��������� �������� ������������� CP_CHP_IV_USER, CP_CHP_IV_RANDOM.
 *  ����� ���� ���������� ������ ���� �� ������ CP_CHP_IV_CHAIN, CP_CHP_IV_USER, CP_CHP_IV_RANDOM.
 */
#define CP_CHP_IV_MASK			(0x300) 
/*!
 *  \brief  ���� ���� ����������, IV ������������ �������� CPEncrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) 
 *  (CPCEncrypt()) � ��������� � �����. ������� CPDecrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) (CPCEncrypt())
 *  ��������� IV �� ������. 
 */
#define CP_CHP_IV_RANDOM		(0x100)
/*!
 *  \brief  ���� ���� ����������, ���������� ������������ IV � �����, 
 *  ������� CPEncrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) (CPCEncrypt()), 
 *  CPDecrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) (CPCEncrypt()) ��������� IV �� ������. 
 */
#define CP_CHP_IV_USER			(0x200)
/*!
 *  \brief  ���� ���� ����������, �������� CPEncrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) (CPCEncrypt()), 
 *  CPDecrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) (CPCDecrypt()) �������� IV ������ �� ��������� �����.
 */
#define CP_CHP_IV_CHAIN			(0x000)
/*!
 *  \brief ����� ���������� ��������� ���-������� ������. ������������ ����� ���� �� 2 ��������� ���. 
 *  ������� �������� ���� ������������� CP_CHP_HASH_NONE.
 *  ��������� �������� ������������� CP_CHP_HASH_CHAIN, CP_CHP_HASH_PACKET.
 *  ����� ���� ���������� ������ ���� �� ������ CP_CHP_HASH_NONE, CP_CHP_HASH_CHAIN, CP_CHP_HASH_PACKET.
 */
 #define CP_CHP_HASH_MASK		(0xC00)
/*!
 *  \brief  ���� ���� ����������, ������� ����������� ������������� �� ���� ����� �������. 
 *  � ����� �������� ���-������� �� ���������.
 */
#define CP_CHP_HASH_NONE		(0x000)
/*!
 *  \brief  ���� ���� ����������, ������� ����������� ������������� �� ����� �������, 
 *  ������� �������� ���-������� ��������������� � ����� ��������� 
 *  CPEncrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_HASH_CHAIN...,...) (CPCEncrypt()).
 *  ������� CPDecrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) (CPCDecrypt()) ����������
 *  ����������� �������� ���-������� �� ���������, ���������� �� ������,
 *  � � ������ ����������� ���������� ������ NTE_BAD_HASH.
 */
#define CP_CHP_HASH_CHAIN		(0x400)
/*!
 *  \brief  ���� ���� ����������, ������� ����������� ������������� �� �����, 
 *  �������� ���-������� ��������������� � ����� ��������� 
 *  CPEncrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_HASH_CHAIN...,...) (CPCEncrypt()).
 *  ������� CPDecrypt(...,CP_CRYPT_HASH_PACKET|CP_CHP_IV_CHAIN...,...) (CPCDecrypt()) ����������
 *  ����������� �������� ���-������� �� ���������, ���������� �� ������,
 *  � � ������ ����������� ���������� ������ NTE_BAD_HASH.
 */
#define CP_CHP_HASH_PACKET		(0x800)
/*!
 *  \brief ����� ������� �������� ���-������� � ������� ������ (4 ������), ���������������� � �����.
 *  ��������� ��������: 1 (��� �����������) �� 1 �� 8 (��� ���-������� �� ���� �34.11-94 � HMAC).
 */
#define CP_CHP_HASH_SIZE_MASK		(0xF000)
/*!
 *  \brief ����� ������� �������� � ������, �������� 0 - 254 �������� ����� ��������, 
 *  ��������  255 ��������: ����� �������� 0, �������� ���-������� � ������ ���������.
 */
#define CP_CHP_TRAILER_MASK		(0xFF0000)

/*!
 *  \brief ����� ������� ��������� � ������, ������ ����� ���������� �������� 0 - 255. 
 */
#define CP_CHP_HEADER_MASK		(0xFF000000)

/*! \brief ������ ��� ������������ ��������� dwFlags (������) �������
 *  CPEncrypt() � CPDecrypt()
 *
 *  ����� (dwFlags) ����������� �� ������ ���������� ������:
 *  - ������ ������� ���������� ���-������� � ��������� �������������;
 *  - ������� ���������;
 *  - ������� "������";
 *  - ������� �������� ���-�������.
 */
#define CP_CHP(Flags,HeaderByteSize,TrailerByteSize,HashDWordSize) (\
            (Flags)|CP_CRYPT_HASH_PACKET|\
            (((HeaderByteSize)<<CP_CHP_HEADER_SHIFT)&CP_CHP_HEADER_MASK)|\
            (((TrailerByteSize)<<CP_CHP_TRAILER_SHIFT)&CP_CHP_TRAILER_MASK)|\
            (((HashDWordSize)<<CP_CHP_HASH_SIZE_SHIFT)&CP_CHP_HASH_SIZE_MASK)\
        )
/*! \} */

/*! \ingroup ProCSPData
 * \defgroup PacketMacros ��������������� ������� �������� ��������� ������
 *
 *  � �������� ������� ����������� ����������:
 *  - �������� f ������������ dwFlags;
 *  - �������� d ������������ ��������� �� �����, ���������� �����;
 *  - �������� l ������������ ����� ������.
 *
 * \{
 */

/*!
 *  \brief ����� ���� ��� ����� CP_CHP_HASH_SIZE_MASK. 
 */
#define CP_CHP_HASH_SIZE_SHIFT		(12)
/*!
 *  \brief ����� ���� ��� ����� CP_CHP_TRAILER_MASK. 
 */
#define CP_CHP_TRAILER_SHIFT		(16)
/*!
 *  \brief ����� ���� ��� ����� CP_CHP_HEADER_MASK. 
 */
#define CP_CHP_HEADER_SHIFT		(24)
/* 
    Aplication Packet (A-Packet, �-�����)
    ��������� �-������
    IV
    IV ������������ � �-������ ������ �����, ����� �� ��������� ��� ����������,
    �.�. IV ���� RANDOM ��� USER ������������ � �-������.
    ���� CP_CHP_IV_HEADER ����������, IV ������ � ������ ������ � ������ � ���� ������ IV ����������.
    ���� CP_CHP_IV_HEADER �� ����������, IV �� ������ � ������ ������ � ������ �������������� � �-������.
    IV ���� RANDOM ��������������� � �-����� � ����������� �� ���� ��������� Encrypt()/Decrypt().
    IV ���� USER ��������������� � �-����� �����������, ����������� �� ���� ��������� Encrypt()/Decrypt().
    IV ���� CHAIN ��������������� ����������� �� ���� �������� SetKeyParam(...,KP_IV,...), 
    � �-����� IV ���� CHAIN �� ������.

*/
/*!
 *  \brief ������ ���� IV � ������. 
 */
#define CP_CHP_IV_SIZE(f) (((f)&CP_CHP_IV_MASK)?(SEANCE_VECTOR_LEN):(0))

/*internal
 *  \brief ����� ��������� �� ���������.
 *      p - ���������
 *      w - ��������
 */
#define _CP_CHP_ADD_(p,w) \
	    ((void *)(((char *)p) + (w)))
#define _CP_CHP_SUB_(p,w) \
	    ((void *)(((char *)p) - (w)))


/*internal
 *  \brief �������� ������ ������.
 *	d - ��������� �� �����
 *      l - ����� ������
 *      p - �������������� ��������� �� ���� ������
 *      w - ����� ����
 */
#define _CP_CHP_SAFE_CHECK_(d,l,p,w)					\
	    (NULL != (d) && (size_t)(w) <= (size_t)(l) &&		\
	     (void *)(d) <= (void *)(p) &&					\
	     _CP_CHP_ADD_((p),(w)) <= _CP_CHP_ADD_((d),(l))		\
		? (p)							\
		: NULL							\
	    )

/*!
 *  \brief ��������� �� ���� IV � ������. 
 */
#define CP_CHP_IV_DATA(f,d,l) _CP_CHP_SAFE_CHECK_((d),(l),		\
		_CP_CHP_ADD_((d),					\
		    (((f)&CP_CHP_HEADER_MASK)>>CP_CHP_HEADER_SHIFT)),	\
		CP_CHP_IV_SIZE(f)					\
	    )

/*  
    HEADER
    � ������ ������ ������� IV � ���������� ����� � IV.
    ����� ������� ������ ����������� 
    HashData(...,CP_CHP_HEADER_DATA(dwFlags,pbData,dwDataLen),CP_CHP_HEADER_SIZE(dwFlags));
*/
/*!
 *  \brief ��������� �� ���� ��������� � ������, ���� ��������� ������������. 
 */
#define CP_CHP_HEADER_DATA(f,d,l) _CP_CHP_SAFE_CHECK_((d),(l),		\
					(d), CP_CHP_PUREHEADER_SIZE(f))
/*!
 *  \brief ������ ���� ��������� ������. 
 */
#define CP_CHP_PUREHEADER_SIZE(f)					\
			(((f)&CP_CHP_HEADER_MASK)>>CP_CHP_HEADER_SHIFT)
/*!
 *  \brief ������ ����������� ���� ��������� ������ � ���� IV (���� IV ����������). 
 */
#define CP_CHP_HEADER_SIZE(f)	    (CP_CHP_PUREHEADER_SIZE(f) +	\
					(((f)&CP_CHP_IV_HEADER)		\
					? CP_CHP_IV_SIZE(f)		\
					: 0))

/*!
 *  \brief ��������� ������ ���� ��������� ������ � ���� IV. 
 */
#define CP_CHP_REALHEADER_SIZE(f)   (CP_CHP_PUREHEADER_SIZE(f) +		\
					CP_CHP_IV_SIZE(f))
/*  
    HASH
    �������� ���� ������������ � �-������ ������ ��� ����� CHAIN � PACKET.
    ��� ���� ���� PACKET ���� CHAIN ������� Encrypt() ��������� � ������������� �������� ���� � �����, 
    ������� Decrypt() ��������� �������� ���� � ���������� ��� �� ��������� �� ������, 
    � ������ ����������� ������������ ������ NTE_BAD_HASH (CRYPT_E_HASH_VALUE). 
    ���������� ���� ����� �������� �������� ���� �� ����� ������� ������� GetHashParam(...,HP_HASHVAL,...).
    ��� ���� NONE �������������� �����������, ��� �������� � �-������� ����������.
    �������� ���� ����� ������������, ����� ���� CP_CHP_TRAILER_MASK ����������� � 0xff.
*/

/*!
 *  \brief ������ ���� �������� ���-�������. 
 */
#define CP_CHP_HASH_SIZE(f)						\
		(sizeof(DWORD)*						\
		    (((f)&CP_CHP_HASH_MASK)				\
		    ?((f&CP_CHP_HASH_SIZE_MASK)>>CP_CHP_HASH_SIZE_SHIFT)\
		    :0))
/*!
 *  \brief ��������� �� ���� �������� ���-������� � ������, ���� ���� ������������. 
 */
#define CP_CHP_HASH_DATA(f,d,l)	_CP_CHP_SAFE_CHECK_((d),(l),		\
		_CP_CHP_ADD_((d), (l)-CP_CHP_HASH_SIZE(f)),		\
		CP_CHP_HASH_SIZE(f)					\
	    )

/*!
 *  \brief ����� ����������� ���� ������(� ������, ����� ���� IV ����������). 
 */
#define CP_CHP_HASH_LEN(f,l) (l-CP_CHP_HASH_SIZE(f))
/*!
 *  \brief ����� ������� ����������� ���� (� ������, ����� ���� IV �� ����������). 
 */
#define CP_CHP_HASH_LEN_1(f)  CP_CHP_PUREHEADER_SIZE(f)


/*!
 *  \brief ������ ���� ��������. 
 */
#define CP_CHP_TRAILER_SIZE(f)						\
		    ((((f)&CP_CHP_TRAILER_MASK)==CP_CHP_TRAILER_MASK)	\
		    ?(0)						\
		    :(((f)&CP_CHP_TRAILER_MASK)>>CP_CHP_TRAILER_SHIFT))	\
/*!
 *  \brief ��������� �� ���� �������� � ������, ���� ���� ������������. 
 */
#define CP_CHP_TRAILER_DATA(f,d,l)  _CP_CHP_SAFE_CHECK_((d),(l),	\
		_CP_CHP_SUB_(CP_CHP_HASH_DATA((f),(d),(l)),		\
					CP_CHP_TRAILER_SIZE(f)),	\
		CP_CHP_TRAILER_SIZE(f)					\
	    )

/*!
 *  \brief ������ ���� ������. 
 */
#define CP_CHP_PAYLOAD_SIZE(f,l) ((l) -					\
				    CP_CHP_REALHEADER_SIZE(f) -		\
				    CP_CHP_TRAILER_SIZE(f) -		\
				    CP_CHP_HASH_SIZE(f))

/*!
 *  \brief ������ ���������� ���� ������. 
 */
#define CP_CHP_CIPHER_SIZE(f,l) (					\
		(l) -							\
		CP_CHP_REALHEADER_SIZE(f) -				\
		CP_CHP_TRAILER_SIZE(f) -				\
		((((f)&CP_CHP_TRAILER_MASK)==CP_CHP_TRAILER_MASK)	\
		    ?(0)						\
		    :(CP_CHP_HASH_SIZE(f)))				\
	    )
/*!
 *  \brief ��������� �� ��������� ���� ������. 
 */
#define CP_CHP_CIPHER_DATA(f,d,l)   _CP_CHP_SAFE_CHECK_((d),(l),	\
		_CP_CHP_ADD_((d), CP_CHP_REALHEADER_SIZE(f)),		\
		CP_CHP_CIPHER_SIZE(f,l)					\
	    )

/*!
 *  \brief ��������� �� ������ ���������� ���� ������ (� ������, ����� ���� IV �� ����������). 
 */
#define CP_CHP_HASH_DATA_2(f,d,l)   CP_CHP_CIPHER_DATA((f),(d),(l))

/*!
 *  \brief ����� ������� ����������� ���� ������ (� ������, ����� ���� IV �� ����������). 
 */
#define CP_CHP_HASH_LEN_2(f,l)  (					\
		CP_CHP_CIPHER_SIZE(f,l) + CP_CHP_TRAILER_SIZE(f) -	\
		((((f)&CP_CHP_TRAILER_MASK)==CP_CHP_TRAILER_MASK)	\
		    ?(CP_CHP_HASH_SIZE(f))				\
		    :(0))						\
	    )

/*! \} */


/*! \ingroup ProCSPData
 * \defgroup CryptIOvec  ������ ����� ������
 *
 * ������� (� ��������) ������ ������� ���������� CPEncrypt(), 
 * CPCEncrypt(), CPDecrypt(), CPCDecrypt(),
 * ���� � ��������� dwFlags ������ ����� CP_CRYPT_HASH_PACKET � 
 * CP_CRYPT_DATA_IOVEC,
 * � ����� ������� ������ ������� ����������� CPHashData() � 
 * CPCHashData(),
 * ���� � ��������� dwFlags ����� ���� CP_HASH_DATA_IOVEC, ����� ���� 
 * ������������ � ����� ������� ����� ������. 
 * � ���� ������ ������ �������������� �������� �������� #CSP_iovec.
 * ������������������ �������� � ������� ������ ��������������� 
 * ������������������ ���������� ������ � ������.
 * 
 */

#if !defined(UNIX)
    ///*
    // * WinSock 2 extension -- WSABUF and QOS struct, include qos.h
    // * to pull in FLOWSPEC and related definitions
    // */
    //
    //typedef struct _WSABUF {
    //    u_long      len;     /* the length of the buffer */
    //    char FAR *  buf;     /* the pointer to the buffer */
    //} WSABUF, FAR * LPWSABUF;
    //
    //������ ���������� � IDL (�� C:\WINDDK\6001.18001\inc\api\ws2def.h)
    //typedef struct _WSABUF {
    //	ULONG len;     /* the length of the buffer */
    //	__field_bcount(len) CHAR FAR *buf; /* the pointer to the buffer */
    //} WSABUF, FAR * LPWSABUF;
    
    #ifndef RPC_CSP_iovec
    #define RPC_CSP_iovec

	//typedef struct _WSABUF {
	//	ULONG len;     /* the length of the buffer */
	//	[size_is (len)] CHAR FAR *buf; /* the pointer to the buffer */
	//} WSABUF, FAR * LPWSABUF;

	typedef CHAR *CSPiov_ptr_type;
	typedef ULONG CSPiov_len_type;

	#if !defined(CP_IOVEC_USE_SYSTEM) || defined(DOCUMENTATION_ONLY)
		// TODO: ��� ��� ���������, ���� �����, ����� ������ 
		// ������������ ��������� ��������
	    /*! \ingroup CryptIOvec
	    *
	    * \brief C�������� ���������� ������������� ��������� ������ 
	    *	      �� ������� ����������.
	    *
	    * \note �� ������ ���������� ������������ �� ���� Windows CSP_iovec 
	    * �������� �������� ��� WSABUF, 
	    * ������� ��� ������������� CSP_iovec ��������� 
	    * "#include <Winsock2.h>".
	    *
	    * \note �� ������ ���������� ������������ � POSIX 
	    * (Linux/Solaris/AIX/FreeBSD) �������� CSP_iovec �������� �������� 
	    * ��� struct iovec, ������� ��� ������������� CSP_iovec ��������� 
	    * "#include <sys/uio.h>".
	    */
	    typedef struct CSP_iovec_ {
		CSPiov_len_type CSPiov_len; /*!< ����� ��������� ������ � ������. */
		CSPiov_ptr_type CSPiov_ptr; /*!< ��������� �� �������� ������. */
	    } CSP_iovec;
	#endif
	#if !defined(CSP_LITE) && !defined(CP_IOVEC_USE_SYSTEM)
		// �� ������ ���������� ���������� ��������� ��
		// ������, �������������� �����������, ���������� 
		// ������������� ������� ���� � ������������
	    #define CSP_iovec	    WSABUF
	    #define CSPiov_len	    len
	    #define CSPiov_ptr	    buf
	#endif 

	/*! \ingroup CryptIOvec
	 *
	 * \brief ����������� ���������� ����� ���������� � 
	 *        ������������� ������ �������� ����� ������.
	 * 
	 */
	#define CSP_UIO_MAXIOV 		(1024-16)

	/*! \ingroup CryptIOvec
	 *
	 * \brief ����������� ���������� ����� ���������� ��� 
	 *        ������������� ���������� ������ ���� ��� � 
	 *        �������� ������������ ������������.
	 * 
	 */
    	#define CSP_KERNEL_UIO_MAXIOV	(1024-16)

    #endif /* RPC_CSP_iovec */
#else
    // Gnu lib
    //   #define UIO_MAXIOV      1024
    //                                                                               
    //   /* Structure for scatter/gather I/O.  */
    //   struct iovec
    //     {
    //        void *iov_base;     /* Pointer to data.  */
    //        size_t iov_len;     /* Length of data.  */                                    };
    //     };

    #if defined(SOLARIS) && !defined(_XPG4_2) && !defined(CSP_LITE)
        #include <sys/types.h>
    	typedef caddr_t CSPiov_ptr_type;
	#if defined(_LP64)
	    typedef size_t CSPiov_len_type;
	#else
	    typedef long CSPiov_len_type;
	#endif
    #else
	typedef void* CSPiov_ptr_type;
	typedef size_t CSPiov_len_type;
    #endif

    #if !defined(CP_IOVEC_USE_SYSTEM) || defined(DOCUMENTATION_ONLY)
	    // TODO: ��� ��� ���������, ���� �����, ����� ������ 
	    // ������������ ��������� ��������
	typedef struct CSP_iovec_ {
	    CSPiov_ptr_type CSPiov_ptr; /*!<��������� �� �������� ������.*/
	    CSPiov_len_type CSPiov_len; /*!<����� ��������� ������ � ������.*/
	} CSP_iovec;
    #endif
    #if !defined(CSP_LITE) && !defined(CP_IOVEC_USE_SYSTEM)
	    // �� ������ ���������� ���������� ��������� �� ��� 
	    // ��������� �������������� � ����������� �/� ��.
	    // ������, �������������� �����������, ���������� 
	    // ������������� ������� ���� � ������������ ��� �����
	    // ����� ����������� ������������ "��������" ���� � ������ ������������.
	#define CSP_iovec	    struct iovec
	#define CSPiov_ptr	    iov_base
	#define CSPiov_len	    iov_len
    #endif 

    #define CSP_UIO_MAXIOV 		(IOV_MAX-2)
    #define CSP_KERNEL_UIO_MAXIOV	(1024-16)
#endif

/*! \ingroup CryptIOvec
 *
 * \brief �������� �� ������������������� ���� �����.
 * 
 */
#define CSP_UIOV_MAXBAD_LEN ((CSPiov_len_type)0x7fffFFFF)

/*! \ingroup CryptIOvec
 *
 * \brief ������ ���������� ��������� �� �������� ������ � ������� n � ������� ����� ������.
 *
 * ���������:
 * - p - ��������� �� ������ ������� � ������� �������� CSP_iovec;
 * - n - ����� ��������� � ������� ����� ������.
 */
#define IOVEC_PTR(p,n) (((CSP_iovec*)p)[n].CSPiov_ptr)
/*! \ingroup CryptIOvec
 *
 * \brief ������ ���������� ����� ��������� ������ � ������� n � ������� ����� ������.
 *
 * ���������:
 * - p - ��������� �� ������ ������� � ������� �������� CSP_iovec;
 * - n - ����� ��������� � ������� ����� ������.
 */
#define IOVEC_LEN(p,n) (((CSP_iovec*)p)[n].CSPiov_len)
/*! \ingroup CryptIOvec
 *
 *  \brief ���� - ������� ������������� ������ � ����� ������� �����/������. 
 *  ��� ������� CPEncrypt(), CPCEncrypt(),CPDecrypt(), CPCDecrypt() ����
 *  ������ ���� ����������, ���� ������������ ������������� ������ � ����� ������� �����/������,
 *  � ��������� ������ ����� �������������� �������. ��. \ref CryptPacket
 */
#define CP_CRYPT_DATA_IOVEC		(0x2)
/*! \ingroup CryptIOvec
 *
 *  \brief ���� ��������� dwFlags - ������� ������������� ������ � ����� ������� �����/������ 
 *  ��� ������� CPHashData() � CPCHashData(). ������ ���� ����������, ���� ������������ 
 *  ������������� ������ � ����� ������� �����/������, � ��������� ������ ������ �������������� �������. 
 */
#define CP_HASH_DATA_IOVEC		CP_CRYPT_DATA_IOVEC

#endif /* _WINCRYPTEX_H_INCLUDED */
/** \endcond */