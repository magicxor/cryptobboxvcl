// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbwincrypt.pas' rev: 21.00

#ifndef SbwincryptHPP
#define SbwincryptHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Windows.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbrandom.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------
#include <wincrypt.h>

namespace Sbwincrypt
{
//-- type declarations -------------------------------------------------------
typedef System::PByte *PPBYTE;

struct CRYPTOAPI_BLOB;
typedef CRYPTOAPI_BLOB *PCRYPTOAPI_BLOB;

struct CRYPTOAPI_BLOB
{
	
public:
	unsigned cbData;
	System::Byte *pbData;
};


typedef CRYPTOAPI_BLOB CRYPT_INTEGER_BLOB;

typedef CRYPTOAPI_BLOB *PCRYPT_INTEGER_BLOB;

typedef CRYPTOAPI_BLOB CRYPT_UINT_BLOB;

typedef CRYPTOAPI_BLOB *PCRYPT_UINT_BLOB;

typedef CRYPTOAPI_BLOB CRYPT_OBJID_BLOB;

typedef CRYPTOAPI_BLOB *PCRYPT_OBJID_BLOB;

typedef CRYPTOAPI_BLOB CERT_NAME_BLOB;

typedef CRYPTOAPI_BLOB *PCERT_NAME_BLOB;

typedef CRYPTOAPI_BLOB CERT_RDN_VALUE_BLOB;

typedef CRYPTOAPI_BLOB *PCERT_RDN_VALUE_BLOB;

typedef CRYPTOAPI_BLOB CERT_BLOB;

typedef CRYPTOAPI_BLOB *PCERT_BLOB;

typedef CRYPTOAPI_BLOB CRL_BLOB;

typedef CRYPTOAPI_BLOB *PCRL_BLOB;

typedef CRYPTOAPI_BLOB DATA_BLOB;

typedef CRYPTOAPI_BLOB *PDATA_BLOB;

typedef CRYPTOAPI_BLOB CRYPT_DATA_BLOB;

typedef CRYPTOAPI_BLOB *PCRYPT_DATA_BLOB;

typedef CRYPTOAPI_BLOB CRYPT_HASH_BLOB;

typedef CRYPTOAPI_BLOB *PCRYPT_HASH_BLOB;

typedef CRYPTOAPI_BLOB CRYPT_DIGEST_BLOB;

typedef CRYPTOAPI_BLOB *PCRYPT_DIGEST_BLOB;

typedef CRYPTOAPI_BLOB CRYPT_DER_BLOB;

typedef CRYPTOAPI_BLOB *PCRYPT_DER_BLOB;

typedef CRYPTOAPI_BLOB CRYPT_ATTR_BLOB;

typedef CRYPTOAPI_BLOB *PCRYPT_ATTR_BLOB;

struct CRYPT_BIT_BLOB;
typedef CRYPT_BIT_BLOB *PCRYPT_BIT_BLOB;

struct CRYPT_BIT_BLOB
{
	
public:
	unsigned cbData;
	System::Byte *pbData;
	unsigned cUnusedBits;
};


struct CRYPT_ALGORITHM_IDENTIFIER;
typedef CRYPT_ALGORITHM_IDENTIFIER *PCRYPT_ALGORITHM_IDENTIFIER;

struct CRYPT_ALGORITHM_IDENTIFIER
{
	
public:
	char *pszObjId;
	CRYPTOAPI_BLOB Parameters;
};


struct CERT_PUBLIC_KEY_INFO
{
	
public:
	CRYPT_ALGORITHM_IDENTIFIER Algorithm;
	CRYPT_BIT_BLOB PublicKey;
};


typedef CERT_PUBLIC_KEY_INFO *PCERT_PUBLIC_KEY_INFO;

struct CERT_EXTENSION
{
	
public:
	char *pszObjId;
	BOOL fCritical;
	CRYPTOAPI_BLOB Value;
};


typedef CERT_EXTENSION *PCERT_EXTENSION;

struct CERT_INFO;
typedef CERT_INFO *PCERT_INFO;

struct CERT_INFO
{
	
public:
	unsigned dwVersion;
	CRYPTOAPI_BLOB SerialNumber;
	CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
	CRYPTOAPI_BLOB Issuer;
	_FILETIME NotBefore;
	_FILETIME NotAfter;
	CRYPTOAPI_BLOB Subject;
	CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
	CRYPT_BIT_BLOB IssuerUniqueId;
	CRYPT_BIT_BLOB SubjectUniqueId;
	unsigned cExtension;
	CERT_EXTENSION *rgExtension;
};


typedef char * LPAWSTR;

typedef void * HCERTSTORE;

typedef void * *PHCERTSTORE;

struct CERT_CONTEXT;
typedef CERT_CONTEXT *PCERT_CONTEXT;

struct CERT_CONTEXT
{
	
public:
	unsigned dwCertEncodingType;
	System::Byte *pbCertEncoded;
	unsigned cbCertEncoded;
	CERT_INFO *pCertInfo;
	void *hCertStore;
};


typedef CERT_CONTEXT *PCCERT_CONTEXT;

typedef PCCERT_CONTEXT *PPCCERT_CONTEXT;

struct CRYPTUI_VIEWCERTIFICATE_STRUCT
{
	
public:
	unsigned dwSize;
	HWND hwndParent;
	unsigned dwFlags;
	System::WideChar *szTitle;
	CERT_CONTEXT *pCertContext;
	char *rgszPurposes;
	unsigned cPurposes;
	void *Union;
	BOOL fpCryptProviderDataTrustedUsage;
	unsigned idxSigner;
	unsigned idxCert;
	BOOL fCounterSigner;
	unsigned idxCounterSigner;
	unsigned cStores;
	void * *rghStores;
	unsigned cPropSheetPages;
	void *rgPropSheetPages;
	unsigned nStartPage;
};


typedef CRYPTUI_VIEWCERTIFICATE_STRUCT *PCRYPTUI_VIEWCERTIFICATE_STRUCT;

typedef CRYPTUI_VIEWCERTIFICATE_STRUCT *PCCRYPTUI_VIEWCERTIFICATE_STRUCT;

struct CRYPTUI_SELECTCERTIFICATE_STRUCT
{
	
public:
	unsigned dwSize;
	HWND hwndParent;
	unsigned dwFlags;
	System::WideChar *szTitle;
	unsigned dwDontUseColumn;
	System::WideChar *szDisplayString;
	void *pFilterCallback;
	void *pDisplayCallback;
	void *pvCallbackData;
	unsigned cDisplayStores;
	void * *rghDisplayStores;
	unsigned cStores;
	void * *rghStores;
	unsigned cPropSheetPages;
	void *rgPropSheetPages;
	void *hSelectedCertStore;
};


typedef CRYPTUI_SELECTCERTIFICATE_STRUCT *PCRYPTUI_SELECTCERTIFICATE_STRUCT;

typedef CRYPTUI_SELECTCERTIFICATE_STRUCT *PCCRYPTUI_SELECTCERTIFICATE_STRUCT;

typedef unsigned HCRYPTPROV;

typedef unsigned *PHCRYPTPROV;

typedef unsigned HCRYPTKEY;

typedef unsigned *PHCRYPTKEY;

typedef unsigned HCRYPTHASH;

typedef unsigned *PHCRYPTHASH;

typedef _CERT_SYSTEM_STORE_INFO TCertSystemStoreInfo;

typedef PCERT_SYSTEM_STORE_INFO PCertSystemStoreInfo;

typedef _CRYPT_ATTRIBUTE CRYPT_ATTRIBUTE;

typedef _PROV_ENUMALGS *PPROV_ENUMALGS;

struct _CRYPT_OID_FUNC_ENTRY
{
	
public:
	char *pszOID;
	void *pvFuncAddr;
};


typedef _CRYPT_OID_FUNC_ENTRY *PCRYPT_OID_FUNC_ENTRY;

struct _CERT_STORE_PROV_INFO
{
	
public:
	unsigned cbSize;
	unsigned cStoreProvFunc;
	void *rgpvStoreProvFunc;
	void *hStoreProv;
	unsigned dwStoreProvFlags;
	void *hStoreProvFuncAddr2;
};


typedef PFN_CERT_ENUM_SYSTEM_STORE PfnCertEnumSystemStore;

typedef BOOL __stdcall (*TCertEnumSystemStore)(unsigned dwFlags, void * pvSystemStoreLocationPara, void * pvArg, PFN_CERT_ENUM_SYSTEM_STORE pfnEnum);

typedef BOOL __stdcall (*TCertEnumPhysicalStore)(void * pvSystemStore, unsigned dwFlags, void * pvArg, PFN_CERT_ENUM_PHYSICAL_STORE pfnEnum);

typedef BOOL __stdcall (*TCryptSignMessage)(PCRYPT_SIGN_MESSAGE_PARA pSignPara, BOOL fDetachedSignature, unsigned cToBeSigned, const PPBYTE rgpbToBeSigned, PDWORD rgcbToBeSigned, System::PByte pbSignedBlob, PDWORD pcbSignedBlob);

typedef System::WideChar * __stdcall (*TCryptFindLocalizedName)(const System::WideChar * pwszCryptName);

typedef BOOL __stdcall (*TCryptAcquireCertificatePrivateKey)(PCCERT_CONTEXT pCert, unsigned dwFlags, void * pvReserved, PHCRYPTPROV phCryptProv, PDWORD pdwKeySpec, PBOOL pfCallerFreeProv);

typedef void * PLPSTR;

typedef void * PPCERT_INFO;

typedef void * PPVOID;

typedef void * PPCCTL_CONTEXT;

typedef void * PPCCRL_CONTEXT;

typedef void * HCRYPTMSG;

struct CTL_USAGE
{
	
public:
	unsigned cUsageIdentifier;
	void *rgpszUsageIdentifier;
};


typedef CTL_USAGE *PCTL_USAGE;

struct CTL_ENTRY
{
	
public:
	CRYPTOAPI_BLOB SubjectIdentifier;
	unsigned cAttribute;
	_CRYPT_ATTRIBUTE *rgAttribute;
};


typedef CTL_ENTRY *PCTL_ENTRY;

struct CRL_ENTRY
{
	
public:
	CRYPTOAPI_BLOB SerialNumber;
	_FILETIME RevocationDate;
	unsigned cExtension;
	CERT_EXTENSION *rgExtension;
};


typedef CRL_ENTRY *PCRL_ENTRY;

struct CTL_INFO
{
	
public:
	unsigned dwVersion;
	CTL_USAGE SubjectUsage;
	CRYPTOAPI_BLOB ListIdentifier;
	CRYPTOAPI_BLOB SequenceNumber;
	_FILETIME ThisUpdate;
	_FILETIME NextUpdate;
	CRYPT_ALGORITHM_IDENTIFIER SubjectAlgorithm;
	unsigned cCTLEntry;
	CTL_ENTRY *rgCTLEntry;
	unsigned cExtension;
	CERT_EXTENSION *rgExtension;
};


typedef CTL_INFO *PCTL_INFO;

struct CRL_INFO
{
	
public:
	unsigned dwVersion;
	CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
	CRYPTOAPI_BLOB Issuer;
	_FILETIME ThisUpdate;
	_FILETIME NextUpdate;
	unsigned cCRLEntry;
	CRL_ENTRY *rgCRLEntry;
	unsigned cExtension;
	CERT_EXTENSION *rgExtension;
};


typedef CRL_INFO *PCRL_INFO;

struct CRL_CONTEXT
{
	
public:
	unsigned dwCertEncodingType;
	System::Byte *pbCrlEncoded;
	unsigned cbCrlEncoded;
	CRL_INFO *pCrlInfo;
	void *hCertStore;
};


typedef CRL_CONTEXT *PCRL_CONTEXT;

typedef CRL_CONTEXT *PCCRL_CONTEXT;

struct CTL_CONTEXT
{
	
public:
	unsigned dwMsgAndCertEncodingType;
	System::Byte *pbCtlEncoded;
	unsigned cbCtlEncoded;
	CTL_INFO *pCtlInfo;
	void *hCertStore;
	void *hCryptMsg;
	System::Byte *pbCtlContent;
	unsigned cbCtlContent;
};


typedef CTL_CONTEXT *PCTL_CONTEXT;

typedef CTL_CONTEXT *PCCTL_CONTEXT;

struct CERT_STORE_PROV_FIND_INFO
{
	
public:
	unsigned cbSize;
	unsigned dwMsgAndCertEncodingType;
	unsigned dwFindFlags;
	unsigned dwFindType;
	void *pvFindPara;
};


typedef CERT_STORE_PROV_FIND_INFO *PCERT_STORE_PROV_FIND_INFO;

typedef CERT_STORE_PROV_FIND_INFO CCERT_STORE_PROV_FIND_INFO;

typedef CERT_STORE_PROV_FIND_INFO *PCCERT_STORE_PROV_FIND_INFO;

struct _GUID
{
	
public:
	unsigned Data1;
	System::Word Data2;
	System::Word Data3;
	StaticArray<System::Byte, 8> Data4;
};


typedef _GUID GUID;

typedef _GUID *PGUID;

struct HMAC_INFO
{
	
public:
	unsigned HashAlgid;
	System::Byte *pbInnerString;
	unsigned cbInnerString;
	System::Byte *pbOuterString;
	unsigned cbOuterString;
};


typedef unsigned *ULONG_PTR;

typedef ULONG_PTR NCRYPT_HANDLE;

typedef ULONG_PTR *PNCRYPT_HANDLE;

typedef ULONG_PTR NCRYPT_PROV_HANDLE;

typedef ULONG_PTR *PNCRYPT_PROV_HANDLE;

typedef ULONG_PTR NCRYPT_KEY_HANDLE;

typedef ULONG_PTR *PNCRYPT_KEY_HANDLE;

typedef ULONG_PTR NCRYPT_HASH_HANDLE;

typedef ULONG_PTR *PNCRYPT_HASH_HANDLE;

typedef ULONG_PTR NCRYPT_SECRET_HANDLE;

typedef ULONG_PTR *PNCRYPT_SECRET_HANDLE;

typedef unsigned SECURITY_STATUS;

struct NCryptBuffer
{
	
public:
	unsigned cbBuffer;
	unsigned BufferType;
	void *pvBuffer;
};


typedef NCryptBuffer *PNCryptBuffer;

struct NCryptBufferDesc
{
	
public:
	unsigned ulVersion;
	unsigned cBuffers;
	NCryptBuffer *pBuffers;
};


typedef NCryptBufferDesc *PNCryptBufferDesc;

struct NCryptAlgorithmName
{
	
public:
	System::WideChar *pszName;
	unsigned dwClass;
	unsigned dwAlgOperations;
	unsigned dwFlags;
};


typedef NCryptAlgorithmName *PNCryptAlgorithmName;

typedef PNCryptAlgorithmName *PPNCryptAlgorithmName;

struct NCryptKeyName
{
	
public:
	System::WideChar *pszName;
	System::WideChar *pszAlgid;
	unsigned dwLegacyKeySpec;
	unsigned dwFlags;
};


typedef NCryptKeyName *PNCryptKeyName;

typedef PNCryptKeyName *PPNCryptKeyName;

struct NCryptProviderName
{
	
public:
	System::WideChar *pszName;
	System::WideChar *pszComment;
};


typedef NCryptProviderName *PNCryptProviderName;

typedef PNCryptProviderName *PPNCryptProviderName;

struct BCRYPT_PKCS1_PADDING_INFO
{
	
public:
	System::WideChar *pszAlgId;
};


typedef void * *PPointer;

//-- var, const, procedure ---------------------------------------------------
#define CRYPT_OID_OPEN_STORE_PROV_FUNC L"CertDllOpenStoreProv"
#define szOID_RSA_MD5 L"1.2.840.113549.2.5"
#define MS_DEF_PROV L"Microsoft Base Cryptographic Provider v1.0"
#define MS_ENHANCED_PROV L"Microsoft Enhanced Cryptographic Provider v1.0"
#define MS_ENH_DSS_DH_PROV L"Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Pr"\
	L"ovider"
#define MS_DEF_RSA_SIG_PROV L"Microsoft RSA Signature Cryptographic Provider"
#define MS_DEF_RSA_SCHANNEL_PROV L"Microsoft RSA SChannel Cryptographic Provider"
#define MS_ENHANCED_RSA_SCHANNEL_PROV L"Microsoft Enhanced RSA SChannel Cryptographic Provider"
#define MS_DEF_DSS_PROV L"Microsoft Base DSS Cryptographic Provider"
#define MS_DEF_DSS_DH_PROV L"Microsoft Base DSS and Diffie-Hellman Cryptographic Provid"\
	L"er"
#define MS_ENH_RSA_AES_PROV L"Microsoft Enhanced RSA and AES Cryptographic Provider"
#define MS_ENH_RSA_AES_PROV_XP L"Microsoft Enhanced RSA and AES Cryptographic Provider (Pro"\
	L"totype)"
#define MS_SCARD_PROV L"Microsoft Base Smart Card Crypto Provider"
#define MS_STRONG_PROV L"Microsoft Strong Cryptographic Provider"
#define MS_DEF_DH_SCHANNEL_PROV L"Microsoft DH SChannel Cryptographic Provider"
#define CP_GR3410_94_PROV L"Crypto-Pro GOST R 34.10-94 Cryptographic Service Provider"
#define CP_GR3410_2001_PROV L"Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provide"\
	L"r"
#define BCRYPT_SHA1_ALGORITHM L"SHA1"
#define BCRYPT_SHA256_ALGORITHM L"SHA256"
#define BCRYPT_SHA384_ALGORITHM L"SHA384"
#define BCRYPT_SHA512_ALGORITHM L"SHA512"
#define BCRYPT_MD2_ALGORITHM L"MD2"
#define BCRYPT_MD5_ALGORITHM L"MD5"
extern "C" void * __stdcall CertOpenSystemStore(unsigned hProv, System::WideChar * szSubsystemProtocol);
extern "C" PCCERT_CONTEXT __stdcall CertFindCertificateInStore(void * hCertStore, unsigned dwCertEncodingType, unsigned dwFindFlags, unsigned dwFindType, const void * pvFindPara, PCCERT_CONTEXT pPrevCertContext);
extern "C" BOOL __stdcall CertCloseStore(void * hCertStore, unsigned dwFlags);
extern "C" BOOL __stdcall CertAddEncodedCertificateToStore(void * hCertStore, unsigned dwCertEncodingType, const System::PByte pbCertEncoded, unsigned cbCertEncoded, unsigned dwAddDisposition, PCCERT_CONTEXT &ppCertContext);
extern "C" BOOL __stdcall CertFreeCertificateContext(PCCERT_CONTEXT pCertContext);
extern "C" BOOL __stdcall CertDeleteCertificateFromStore(PCCERT_CONTEXT pCertContext);
extern "C" PCCERT_CONTEXT __stdcall CertEnumCertificatesInStore(void * hCertStore, PCCERT_CONTEXT pPrevCertContext);
extern "C" PCCERT_CONTEXT __stdcall CertDuplicateCertificateContext(PCCERT_CONTEXT pCertContext);
extern "C" void * __stdcall CertOpenStore(char * lpszStoreProvider, unsigned dwMsgAndCertEncodingType, unsigned hCryptProv, unsigned dwFlags, const void * pvPara);
extern "C" BOOL __stdcall CertGetCertificateContextProperty(PCCERT_CONTEXT pCertContext, unsigned dwPropId, void * pvData, PDWORD pcbData);
extern "C" BOOL __stdcall CertSetCertificateContextProperty(PCCERT_CONTEXT pCertContext, unsigned dwPropId, unsigned dwFlags, void * pvData);
extern "C" BOOL __stdcall CryptDecryptMessage(PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara, System::PByte pbEncryptedBlob, unsigned cbEncryptedBlob, System::PByte pbDecrypted, PDWORD pcbDecrypted, PPCCERT_CONTEXT ppXchgCert);
extern "C" BOOL __stdcall CryptDecrypt(unsigned hKey, unsigned hHash, BOOL Final, unsigned dwFlags, System::PByte pbData, unsigned &pdwDataLen);
extern "C" BOOL __stdcall CryptEncrypt(unsigned hKey, unsigned hHash, BOOL Final, unsigned dwFlags, System::PByte pbData, unsigned &pdwDataLen, unsigned dwBufLen);
extern "C" BOOL __stdcall CryptDuplicateKey(unsigned hKey, PDWORD pdwReserved, unsigned dwFlags, unsigned &phKey);
extern "C" PCCERT_CONTEXT __stdcall CertCreateCertificateContext(unsigned dwCertEncodingType, const System::PByte pbCertEncoded, unsigned cbCertEncoded);
extern "C" BOOL __stdcall CryptAcquireContext(PHCRYPTPROV hProv, System::WideChar * pszContainer, System::WideChar * pszProvider, unsigned dwProvType, unsigned dwFlags);
extern "C" BOOL __stdcall CryptContextAddRef(unsigned hProv, PDWORD pdwReserved, unsigned dwFlags);
extern "C" BOOL __stdcall CryptGetUserKey(unsigned hProv, unsigned dwKeySpec, PHCRYPTKEY phUserKey);
extern "C" BOOL __stdcall CryptDestroyKey(unsigned hKey);
extern "C" BOOL __stdcall CryptReleaseContext(unsigned hProv, unsigned dwFlags);
extern "C" BOOL __stdcall CryptExportKey(unsigned hKey, unsigned hExpKey, unsigned dwBlobType, unsigned dwFlags, System::PByte pbData, PDWORD pdwDataLen);
extern "C" BOOL __stdcall CryptImportKey(unsigned hProv, System::PByte pbData, unsigned dwDataLen, unsigned hPubKey, unsigned dwFlags, PHCRYPTKEY phKey);
extern "C" BOOL __stdcall CryptCreateHash(unsigned hProv, unsigned AlgId, unsigned hKey, unsigned dwFlags, PHCRYPTHASH phHash);
extern "C" BOOL __stdcall CryptHashData(unsigned hHash, System::PByte pbData, unsigned dwDataLen, unsigned dwFlags);
extern "C" BOOL __stdcall CryptVerifySignature(unsigned hHash, System::PByte pbSignature, unsigned dwSigLen, unsigned hPubKey, System::WideChar * sDescription, unsigned dwFlags);
extern "C" BOOL __stdcall CryptSetHashParam(unsigned hHash, unsigned dwParam, System::PByte pbData, unsigned dwFlags);
extern "C" BOOL __stdcall CryptGetHashParam(unsigned hHash, unsigned dwParam, System::PByte pbData, unsigned &pdwDataLen, unsigned dwFlags);
extern "C" BOOL __stdcall CryptSignHash(unsigned hHash, unsigned dwKeySpec, System::WideChar * sDescription, unsigned dwFlags, System::PByte pbSignature, PDWORD pdwSigLen);
extern "C" BOOL __stdcall CryptDestroyHash(unsigned hHash);
extern "C" BOOL __stdcall CryptGetProvParam(unsigned hProv, unsigned dwParam, System::PByte pbData, PDWORD pwdDataLen, unsigned dwFlags);
extern "C" BOOL __stdcall CryptRegisterOIDFunction(unsigned dwEncodingType, char * pszFuncName, char * pszOID, System::WideChar * pwszDll, char * pszOverrideFuncName);
extern "C" BOOL __stdcall CryptUnregisterOIDFunction(unsigned dwEncodingType, char * pszFuncName, char * pszOID);
extern "C" BOOL __stdcall CryptInstallOIDFunctionAddress(unsigned hModule, unsigned dwEncodingType, char * pszFuncName, unsigned cFuncEntry, PCRYPT_OID_FUNC_ENTRY rgFuncEntry, unsigned dwFlags);
extern "C" HRESULT __stdcall CoCreateGuid(PGUID guid);
extern "C" BOOL __stdcall CryptSetProvParam(unsigned hProv, unsigned dwParam, System::PByte pbData, unsigned dwFlags);
extern "C" BOOL __stdcall CryptSetKeyParam(unsigned hKey, unsigned dwParam, System::PByte pbData, unsigned dwFlags);
extern "C" BOOL __stdcall CryptGetKeyParam(unsigned hKey, unsigned dwParam, System::PByte pbData, PDWORD pdwDataLen, unsigned dwFlags);
extern "C" BOOL __stdcall CryptDeriveKey(unsigned hProv, unsigned Algid, unsigned hBaseData, unsigned dwFlags, PHCRYPTKEY phKey);
extern "C" BOOL __stdcall CryptGenKey(unsigned hProv, unsigned Algid, unsigned dwFlags, PHCRYPTKEY phKey);
extern PACKAGE BOOL __stdcall CryptUIDlgViewCertificate(PCCRYPTUI_VIEWCERTIFICATE_STRUCT pCertViewInfo, PBOOL pfPropertiesChanged);
extern PACKAGE PCCERT_CONTEXT __stdcall CryptUIDlgSelectCertificate(PCCRYPTUI_SELECTCERTIFICATE_STRUCT pcsc);
extern PACKAGE BOOL __stdcall CryptUIWizImport(unsigned dwFlags, HWND hwndParent, System::WideChar * pwszWizardTitle, void * pImportSrc, void * hDestCertStore);
extern PACKAGE unsigned __stdcall NCryptCreatePersistedKey(ULONG_PTR hProvider, PNCRYPT_KEY_HANDLE phKey, System::WideChar * pszAlgId, System::WideChar * pszKeyName, unsigned dwLegacyKeySpec, unsigned dwFlags);
extern PACKAGE unsigned __stdcall NCryptDecrypt(ULONG_PTR hKey, System::PByte pbInput, unsigned cbInput, void * pPaddingInfo, System::PByte pbOutput, unsigned cbOutput, PDWORD pcbResult, unsigned dwFlags);
extern PACKAGE unsigned __stdcall NCryptDeleteKey(ULONG_PTR hKey, unsigned dwFlags);
extern PACKAGE unsigned __stdcall NCryptDeriveKey(ULONG_PTR hSharedSecret, System::WideChar * pwszKDF, PNCryptBufferDesc pParameterList, System::PByte pbDerivedKey, unsigned cbDerivedKey, PDWORD pcbResult, unsigned dwFlags);
extern PACKAGE unsigned __stdcall NCryptEncrypt(ULONG_PTR hKey, System::PByte pbInput, unsigned cbInput, void * pPaddingInfo, System::PByte pbOutput, unsigned cbOutput, PDWORD pcbResult, unsigned dwFlags);
extern PACKAGE unsigned __stdcall NCryptEnumAlgorithms(ULONG_PTR hProvider, unsigned dwAlgOperations, PDWORD pdwAlgCount, PPNCryptAlgorithmName ppAlgList, unsigned dwFlags);
extern PACKAGE unsigned __stdcall NCryptEnumKeys(ULONG_PTR hProvider, System::WideChar * pszScope, PPNCryptKeyName ppKeyName, PPointer ppEnumState, unsigned dwFlags);
extern PACKAGE unsigned __stdcall NCryptEnumStorageProviders(PDWORD pdwProviderCount, PPNCryptProviderName ppProviderList, unsigned dwFlags);
extern PACKAGE unsigned __stdcall NCryptExportKey(ULONG_PTR hKey, ULONG_PTR hExportKey, System::WideChar * pszBlobType, PNCryptBufferDesc pParameterList, System::PByte pbOutput, unsigned cbOutput, PDWORD pcbResult, unsigned dwFlags);
extern PACKAGE unsigned __stdcall NCryptFinalizeKey(ULONG_PTR hKey, unsigned dwFlags);
extern PACKAGE unsigned __stdcall NCryptFreeBuffer(void * pvInput);
extern PACKAGE unsigned __stdcall NCryptFreeObject(ULONG_PTR hObject);
extern PACKAGE unsigned __stdcall NCryptGetProperty(ULONG_PTR hObject, System::WideChar * pszProperty, System::PByte pbOutput, unsigned cbOutput, PDWORD pcbResult, unsigned dwFlags);
extern PACKAGE unsigned __stdcall NCryptImportKey(ULONG_PTR hProvider, ULONG_PTR hImportKey, System::WideChar * pszBlobType, PNCryptBufferDesc pParameterList, PNCRYPT_KEY_HANDLE phKey, System::PByte pbData, unsigned cbData, unsigned dwFlags);
extern PACKAGE unsigned __fastcall NCryptIsAlgSupported(ULONG_PTR hProvider, System::WideChar * pszAlgId, unsigned dwFlags);
extern PACKAGE BOOL __stdcall NCryptIsKeyHandle(ULONG_PTR hKey);
extern PACKAGE unsigned __stdcall NCryptKeyDerivation(ULONG_PTR hProvider, ULONG_PTR hKey, System::WideChar * pswzDerivedKeyAlg, unsigned cbDerivedKeyLength, PNCryptBufferDesc pParameterList, PNCRYPT_KEY_HANDLE phDerivedKey, unsigned dwFlags);
extern PACKAGE unsigned __stdcall NCryptNotifyChangeKey(ULONG_PTR hProvider, Windows::PHandle phEvent, unsigned dwFlags);
extern PACKAGE unsigned __stdcall NCryptOpenKey(ULONG_PTR hProvider, PNCRYPT_KEY_HANDLE phKey, System::WideChar * pszKeyName, unsigned dwLegacyKeySpec, unsigned dwFlags);
extern PACKAGE unsigned __stdcall NCryptOpenStorageProvider(PNCRYPT_PROV_HANDLE phProvider, System::WideChar * pszProviderName, unsigned dwFlags);
extern PACKAGE unsigned __stdcall NCryptSecretAgreement(ULONG_PTR hPrivKey, ULONG_PTR hPubKey, PNCRYPT_SECRET_HANDLE phSecret, unsigned dwFlags);
extern PACKAGE unsigned __stdcall NCryptSetProperty(ULONG_PTR hObject, System::WideChar * pszProperty, System::PByte pbInput, unsigned cbInput, unsigned dwFlags);
extern PACKAGE unsigned __stdcall NCryptSignHash(ULONG_PTR hKey, void * pPaddingInfo, System::PByte pbHashValue, unsigned cbHashValue, System::PByte pbSignature, unsigned cbSignature, PDWORD pcbResult, unsigned dwFlags);
extern PACKAGE unsigned __stdcall NCryptTranslateHandle(PNCRYPT_PROV_HANDLE phProvider, PNCRYPT_KEY_HANDLE phKey, unsigned hLegacyProv, unsigned hLegacyKey, unsigned dwLegacyKeySpec, unsigned dwFlags);
extern PACKAGE unsigned __stdcall NCryptVerifySignature(ULONG_PTR hKey, void * pPaddingInfo, System::PByte pbHashValue, unsigned cbHashValue, System::PByte pbSignature, unsigned cbSignature, unsigned dwFlags);
extern PACKAGE BOOL __stdcall CryptSignMessage(PCRYPT_SIGN_MESSAGE_PARA pSignPara, BOOL fDetachedSignature, unsigned cToBeSigned, const PPBYTE rgpbToBeSigned, PDWORD rgcbToBeSigned, System::PByte pbSignedBlob, PDWORD pcbSignedBlob);
extern PACKAGE BOOL __stdcall CryptAcquireCertificatePrivateKey(PCCERT_CONTEXT pCert, unsigned dwFlags, void * pvReserved, PHCRYPTPROV phCryptProv, PDWORD pdwKeySpec, PBOOL pfCallerFreeProv);
extern PACKAGE BOOL __stdcall CertEnumSystemStore(unsigned dwFlags, void * pvSystemStoreLocationPara, void * pvArg, PFN_CERT_ENUM_SYSTEM_STORE pfnEnum);
extern PACKAGE BOOL __stdcall CertEnumPhysicalStore(void * pvSystemStore, unsigned dwFlags, void * pvArg, PFN_CERT_ENUM_PHYSICAL_STORE pfnEnum);
extern PACKAGE void __fastcall GetProcedureAddress(void * &P, const System::UnicodeString ModuleName, System::AnsiString ProcName);
extern PACKAGE System::WideChar * __stdcall CryptFindLocalizedName(const System::WideChar * pwszCryptName);

}	/* namespace Sbwincrypt */
using namespace Sbwincrypt;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbwincryptHPP
