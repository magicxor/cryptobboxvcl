(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

(*$HPPEMIT '#include <wincrypt.h>'*)

unit SBWinCrypt;

interface

{$ifdef SB_HAS_WINCRYPT}

uses
  SBTypes,
  SBUtils,
  {$ifdef WIN32}
  Windows,
   {$endif}
  SysUtils,
  SBRandom,
  SBConstants;



type

  {$ifdef VCL60}
  {$EXTERNALSYM HCRYPTOIDFUNCADDR}
   {$endif}
  HCRYPTOIDFUNCADDR = pointer;

  {$ifdef VCL60}
  {$EXTERNALSYM HCERTSTOREPROV}
   {$endif}
  HCERTSTOREPROV = pointer;

  PPBYTE = ^PBYTE;
  PCRYPTOAPI_BLOB = ^CRYPTOAPI_BLOB;
  {$EXTERNALSYM HANDLE}
  HANDLE = THandle;

  CRYPTOAPI_BLOB = record
    cbData : DWORD;
    pbData : PBYTE;
  end;
  CRYPT_INTEGER_BLOB            =  CRYPTOAPI_BLOB;
  PCRYPT_INTEGER_BLOB           = ^CRYPT_INTEGER_BLOB;
  CRYPT_UINT_BLOB               =  CRYPTOAPI_BLOB;
  PCRYPT_UINT_BLOB              = ^CRYPT_UINT_BLOB;
  CRYPT_OBJID_BLOB              =  CRYPTOAPI_BLOB;
  PCRYPT_OBJID_BLOB             = ^CRYPT_OBJID_BLOB;
  CERT_NAME_BLOB                =  CRYPTOAPI_BLOB;
  PCERT_NAME_BLOB               = ^CERT_NAME_BLOB;
  CERT_RDN_VALUE_BLOB           =  CRYPTOAPI_BLOB;
  PCERT_RDN_VALUE_BLOB          = ^CERT_RDN_VALUE_BLOB;
  CERT_BLOB                     =  CRYPTOAPI_BLOB;
  PCERT_BLOB                    = ^CERT_BLOB;
  CRL_BLOB                      =  CRYPTOAPI_BLOB;
  PCRL_BLOB                     = ^CRL_BLOB;
  DATA_BLOB                     =  CRYPTOAPI_BLOB;
  PDATA_BLOB                    = ^DATA_BLOB;
  CRYPT_DATA_BLOB               =  CRYPTOAPI_BLOB;
  PCRYPT_DATA_BLOB              = ^CRYPT_DATA_BLOB;
  CRYPT_HASH_BLOB               =  CRYPTOAPI_BLOB;
  PCRYPT_HASH_BLOB              = ^CRYPT_HASH_BLOB;
  CRYPT_DIGEST_BLOB             =  CRYPTOAPI_BLOB;
  PCRYPT_DIGEST_BLOB            = ^CRYPT_DIGEST_BLOB;
  CRYPT_DER_BLOB                =  CRYPTOAPI_BLOB;
  PCRYPT_DER_BLOB               = ^CRYPT_DER_BLOB;
  CRYPT_ATTR_BLOB               =  CRYPTOAPI_BLOB;
  PCRYPT_ATTR_BLOB              = ^CRYPT_ATTR_BLOB;
  PCRYPT_BIT_BLOB = ^CRYPT_BIT_BLOB;

  CRYPT_BIT_BLOB =  record
    cbData      :DWORD;
    pbData      :PBYTE;
    cUnusedBits :DWORD;
  end;

  PCRYPT_ALGORITHM_IDENTIFIER = ^CRYPT_ALGORITHM_IDENTIFIER;
  CRYPT_ALGORITHM_IDENTIFIER =  record
    pszObjId   :LPSTR;
    Parameters :CRYPT_OBJID_BLOB;
  end;

  CERT_PUBLIC_KEY_INFO =  record
    Algorithm :CRYPT_ALGORITHM_IDENTIFIER;
    PublicKey :CRYPT_BIT_BLOB;
  end;
  PCERT_PUBLIC_KEY_INFO = ^CERT_PUBLIC_KEY_INFO;
  
  CERT_EXTENSION =  record
    pszObjId : LPSTR;
    fCritical :BOOL;
    Value :CRYPT_OBJID_BLOB;
  end;
  PCERT_EXTENSION = ^CERT_EXTENSION;


  PCERT_INFO = ^CERT_INFO;
  CERT_INFO =  record
    dwVersion              :DWORD;
    SerialNumber           :CRYPT_INTEGER_BLOB;
    SignatureAlgorithm     :CRYPT_ALGORITHM_IDENTIFIER;
    Issuer                 :CERT_NAME_BLOB;
    NotBefore              :TFILETIME;
    NotAfter               :TFILETIME;
    Subject                :CERT_NAME_BLOB;
    SubjectPublicKeyInfo   :CERT_PUBLIC_KEY_INFO;
    IssuerUniqueId         :CRYPT_BIT_BLOB;
    SubjectUniqueId        :CRYPT_BIT_BLOB;
    cExtension             :DWORD;
    rgExtension            :PCERT_EXTENSION;
  end;
  
  {$externalsym PVOID}
  PVOID = Pointer;

  {$externalsym LONG}
  LONG  = DWORD;

  LPAWSTR = PAnsiChar;
  HCERTSTORE = PVOID;
  PHCERTSTORE = ^HCERTSTORE;
  PCERT_CONTEXT = ^CERT_CONTEXT;
  
  CERT_CONTEXT = record
    dwCertEncodingType :DWORD;
    pbCertEncoded :PBYTE;
    cbCertEncoded :DWORD;
    pCertInfo :PCERT_INFO;
    hCertStore :HCERTSTORE;
  end;

  PCCERT_CONTEXT = ^CERT_CONTEXT;
  PPCCERT_CONTEXT = ^PCCERT_CONTEXT;

  {$ifdef SB_HAS_CRYPTUI}
  CRYPTUI_VIEWCERTIFICATE_STRUCT = record
    dwSize : DWORD;
    hwndParent : HWND;
    dwFlags : DWORD;
    szTitle : LPWSTR;
    pCertContext : PCCERT_CONTEXT;
    rgszPurposes : LPSTR;
    cPurposes : DWORD;
    // not used
    Union : Pointer;
    fpCryptProviderDataTrustedUsage : BOOL;
    idxSigner : DWORD;
    idxCert : DWORD;
    fCounterSigner : BOOL;
    idxCounterSigner : DWORD;
    cStores : DWORD;
    rghStores : PHCERTSTORE;
    cPropSheetPages : DWORD;
    rgPropSheetPages :  Pointer ;
    nStartPage : DWORD;
  end;
  PCRYPTUI_VIEWCERTIFICATE_STRUCT = ^CRYPTUI_VIEWCERTIFICATE_STRUCT;
  PCCRYPTUI_VIEWCERTIFICATE_STRUCT = ^CRYPTUI_VIEWCERTIFICATE_STRUCT;
  
  CRYPTUI_SELECTCERTIFICATE_STRUCT = record
    dwSize : DWORD;
    hwndParent : HWND;
    dwFlags : DWORD;
    szTitle : LPWSTR;
    dwDontUseColumn : DWORD;
    szDisplayString : LPWSTR;
    pFilterCallback :  Pointer ;
    pDisplayCallback :  Pointer ;
    pvCallbackData :  Pointer ;
    cDisplayStores : DWORD;
    rghDisplayStores : PHCERTSTORE;
    cStores : DWORD;
    rghStores : PHCERTSTORE;
    cPropSheetPages : DWORD;
    rgPropSheetPages :  Pointer ;
    hSelectedCertStore : HCERTSTORE;
  end;
  PCRYPTUI_SELECTCERTIFICATE_STRUCT = ^CRYPTUI_SELECTCERTIFICATE_STRUCT;
  PCCRYPTUI_SELECTCERTIFICATE_STRUCT = ^CRYPTUI_SELECTCERTIFICATE_STRUCT;
   {$endif SB_HAS_CRYPTUI}

  {$ifdef BUILDER_USED}
  {$EXTERNALSYM HCRYPTPROV}
   {$endif}
  HCRYPTPROV  =   {$ifndef WIN64}ULONG {$else}UInt64 {$endif} ;
  {$ifdef BUILDER_USED}
  {$EXTERNALSYM PHCRYPTPROV}
   {$endif}
  PHCRYPTPROV = ^HCRYPTPROV;
  {$ifdef BUILDER_USED}
  {$EXTERNALSYM HCRYPTKEY}
   {$endif}
  HCRYPTKEY   =   {$ifndef WIN64}ULONG {$else}UInt64 {$endif} ;
  {$ifdef BUILDER_USED}
  {$EXTERNALSYM PHCRYPTKEY}
   {$endif}
  PHCRYPTKEY  = ^HCRYPTKEY;
  {$ifdef BUILDER_USED}
  {$EXTERNALSYM HCRYPTHASH}
   {$endif}
  HCRYPTHASH  =   {$ifndef WIN64}ULONG {$else}UInt64 {$endif} ;
  {$ifdef BUILDER_USED}
  {$EXTERNALSYM PHCRYPTHASH}
   {$endif}
  PHCRYPTHASH = ^HCRYPTHASH;

  {$ifdef BUILDER_USED}
  {$HPPEMIT 'typedef unsigned long *PHCRYPTPROV;'}
  {$HPPEMIT 'typedef unsigned long *PHCRYPTKEY;'}
  {$HPPEMIT 'typedef unsigned long *PHCRYPTHASH;'}
   {$endif}

  {$ifdef VCL60}
  {$EXTERNALSYM _CERT_SYSTEM_STORE_INFO}
   {$endif}
  _CERT_SYSTEM_STORE_INFO =  record
    cbSize: DWORD;
  end;

  {$ifdef VCL60}
  {$EXTERNALSYM CERT_SYSTEM_STORE_INFO}
   {$endif}
  CERT_SYSTEM_STORE_INFO =  _CERT_SYSTEM_STORE_INFO;

  {$ifdef VCL60}
  {$EXTERNALSYM PCERT_SYSTEM_STORE_INFO}
   {$endif}
  PCERT_SYSTEM_STORE_INFO = ^CERT_SYSTEM_STORE_INFO;
  TCertSystemStoreInfo =  CERT_SYSTEM_STORE_INFO;

  PCertSystemStoreInfo = PCERT_SYSTEM_STORE_INFO;

  {$ifdef VCL60}
  {$EXTERNALSYM _CRYPT_KEY_PROV_INFO}
   {$endif}
  _CRYPT_KEY_PROV_INFO = record
    pwszContainerName : PWideChar;
    pwszProvName : PWideChar;
    dwProvType : DWORD;
    dwFlags : DWORD;
    cProvParam : DWORD;
    rgProvParam :  pointer ;
    dwKeySpec : DWORD;
  end;
  {$ifdef VCL60}
  {$EXTERNALSYM CRYPT_KEY_PROV_INFO}
   {$endif}
  CRYPT_KEY_PROV_INFO =  _CRYPT_KEY_PROV_INFO;
  {$ifdef VCL60}
  {$EXTERNALSYM PCRYPT_KEY_PROV_INFO}
   {$endif}
  PCRYPT_KEY_PROV_INFO = ^CRYPT_KEY_PROV_INFO;

  {$ifdef VCL60}
  {$EXTERNALSYM _CRYPT_ATTRIBUTE}
   {$endif}
  _CRYPT_ATTRIBUTE = record
    pszObjId : PAnsiChar;
    cValue : DWORD;
    rgValue : PCRYPT_ATTR_BLOB;
  end;
  CRYPT_ATTRIBUTE =  _CRYPT_ATTRIBUTE;

  {$ifdef VCL60}
  {$EXTERNALSYM PCRYPT_ATTRIBUTE}
   {$endif}
  PCRYPT_ATTRIBUTE = ^_CRYPT_ATTRIBUTE;

  {$ifdef VCL60}
  {$EXTERNALSYM _CRYPT_SIGN_MESSAGE_PARA}
   {$endif}
  _CRYPT_SIGN_MESSAGE_PARA = record
     cbSize : DWORD;
     dwMsgEncodingType : DWORD;
     pSigningCert : PCCERT_CONTEXT;
     HashAlgorithm : CRYPT_ALGORITHM_IDENTIFIER;
     pvHashAuxInfo : pointer;
     cMsgCert : DWORD;
     rgpMsgCert : PPCCERT_CONTEXT;
     cMsgCrl : DWORD;
     rgpMsgCrl : PPCCERT_CONTEXT;
     cAuthAttr : DWORD;
     rgAuthAttr : PCRYPT_ATTRIBUTE;
     cUnauthAttr : DWORD;
     rgUnauthAttr : PCRYPT_ATTRIBUTE;
     dwFlags : DWORD;
     dwInnerContentType : DWORD;
     HashEncryptionAlgorithm : CRYPT_ALGORITHM_IDENTIFIER ;
     pvHashEncryptionAuxInfo : pointer;
  end;
  {$ifdef VCL60}
  {$EXTERNALSYM CRYPT_SIGN_MESSAGE_PARA}
   {$endif}
  CRYPT_SIGN_MESSAGE_PARA =  _CRYPT_SIGN_MESSAGE_PARA;

  {$ifdef VCL60}
  {$EXTERNALSYM PCRYPT_SIGN_MESSAGE_PARA}
   {$endif}
  PCRYPT_SIGN_MESSAGE_PARA = ^_CRYPT_SIGN_MESSAGE_PARA;

  {$ifdef VCL60}
  {$EXTERNALSYM _CRYPT_DECRYPT_MESSAGE_PARA}
   {$endif}
  _CRYPT_DECRYPT_MESSAGE_PARA = record
    cbSize : DWORD;
    dwMsgAndCertEncodingType : DWORD;
    cCertStore : DWORD;
    rghCertStore : PHCERTSTORE;
  end;
  {$ifdef VCL60}
  {$EXTERNALSYM CRYPT_DECRYPT_MESSAGE_PARA}
   {$endif}
  CRYPT_DECRYPT_MESSAGE_PARA =  _CRYPT_DECRYPT_MESSAGE_PARA;
  {$ifdef VCL60}
  {$EXTERNALSYM PCRYPT_DECRYPT_MESSAGE_PARA}
   {$endif}
  PCRYPT_DECRYPT_MESSAGE_PARA = ^_CRYPT_DECRYPT_MESSAGE_PARA;

  {$ifdef VCL60}
  {$EXTERNALSYM _ALG_ID}
   {$endif}
  _ALG_ID =  longword;
  {$ifdef VCL60}
  {$EXTERNALSYM ALG_ID}
   {$endif}
  ALG_ID =  _ALG_ID;

  {$ifdef VCL60}
  {$EXTERNALSYM _PROV_ENUMALGS}
   {$endif}
  _PROV_ENUMALGS = record
    aiAlgId : ALG_ID;
    dwBitLen : DWORD;
    dwNameLen : DWORD;
    szName : array[0..19] of AnsiChar;
  end;
  {$ifdef VCL60}
  {$EXTERNALSYM PROV_ENUMALGS}
   {$endif}
  PROV_ENUMALGS =  _PROV_ENUMALGS;
  {$ifdef VCL60}
  {$EXTERNALSYM PROV_ENUMALGS}
   {$endif}
  PPROV_ENUMALGS = ^_PROV_ENUMALGS;


  _CRYPT_OID_FUNC_ENTRY = record
    pszOID : PAnsiChar;
    pvFuncAddr : Pointer;
  end;
  {$ifdef VCL60}
  {$EXTERNALSYM CRYPT_OID_FUNC_ENTRY}
   {$endif}
  CRYPT_OID_FUNC_ENTRY =  _CRYPT_OID_FUNC_ENTRY;
  {$ifdef VCL60}
  {$EXTERNALSYM CRYPT_OID_FUNC_ENTRY}
   {$endif}
  PCRYPT_OID_FUNC_ENTRY = ^_CRYPT_OID_FUNC_ENTRY;

  _CERT_STORE_PROV_INFO = record
    cbSize : DWORD;
    cStoreProvFunc : DWORD;
    rgpvStoreProvFunc : pointer;
    hStoreProv : HCERTSTOREPROV;
    dwStoreProvFlags : DWORD;
    hStoreProvFuncAddr2 : HCRYPTOIDFUNCADDR;
  end;
  {$ifdef VCL60}
  {$EXTERNALSYM CERT_STORE_PROV_INFO}
   {$endif}
  CERT_STORE_PROV_INFO =  _CERT_STORE_PROV_INFO;
  {$ifdef VCL60}
  {$EXTERNALSYM PCERT_STORE_PROV_INFO}
   {$endif}
  PCERT_STORE_PROV_INFO = ^_CERT_STORE_PROV_INFO;

  {$ifdef VCL60}
  {$EXTERNALSYM PFN_CERT_ENUM_SYSTEM_STORE}
   {$endif}
  PFN_CERT_ENUM_SYSTEM_STORE = function (pvSystemStore: Pointer;
    dwFlags: DWORD; pStoreInfo: PCERT_SYSTEM_STORE_INFO; pvReserved: Pointer;
    pvArg: Pointer): BOOL; stdcall;
  PfnCertEnumSystemStore = PFN_CERT_ENUM_SYSTEM_STORE;

  TCertEnumSystemStore = function(dwFlags: DWORD; pvSystemStoreLocationPara: Pointer;
    pvArg: Pointer; pfnEnum: PFN_CERT_ENUM_SYSTEM_STORE): BOOL; stdcall;

  {$ifdef VCL60}
  {$EXTERNALSYM PFN_CERT_ENUM_PHYSICAL_STORE}
   {$endif}
  PFN_CERT_ENUM_PHYSICAL_STORE = function (pvSystemStore: pointer;
    dwFlags : DWORD; pwszStoreName : PWideChar; pStoreInfo : PCERT_SYSTEM_STORE_INFO;
    pvReserver : pointer; pvArg : pointer) : BOOL; stdcall;

  TCertEnumPhysicalStore = function(pvSystemStore : pointer; dwFlags: DWORD;
    pvArg: Pointer; pfnEnum: PFN_CERT_ENUM_PHYSICAL_STORE): BOOL; stdcall;

  TCryptSignMessage = function(pSignPara : PCRYPT_SIGN_MESSAGE_PARA; fDetachedSignature : BOOL;
    cToBeSigned : DWORD; const rgpbToBeSigned : PPBYTE; rgcbToBeSigned : PDWORD;
    pbSignedBlob : PBYTE; pcbSignedBlob : PDWORD) : BOOL; stdcall;

  TCryptFindLocalizedName = function(const pwszCryptName : PWideChar) : PWideChar; stdcall;

  TCryptAcquireCertificatePrivateKey = function(pCert : PCCERT_CONTEXT; dwFlags : DWORD;
    pvReserved : pointer; phCryptProv : PHCRYPTPROV; pdwKeySpec : PDWORD;
    pfCallerFreeProv : PBOOL): BOOL; stdcall;

  //-----------------------------------------------------------------------------
    // Type support for a pointer to an array of pointer (type **name)
    PLPSTR          = Pointer; // type for a pointer to Array of pointer a type
    PPCERT_INFO     = Pointer; // type for a pointer to Array of pointer a type
    PPVOID          = Pointer; // type for a pointer to Array of pointer a type
    PPCCTL_CONTEXT  = Pointer; // type for a pointer to Array of pointer a type
    PPCCRL_CONTEXT  = Pointer; // type for a pointer to Array of pointer a type
  //-----------------------------------------------------------------------------
  HCRYPTMSG = Pointer;

  PCTL_USAGE =^CTL_USAGE;
  CTL_USAGE =  record
    cUsageIdentifier :DWORD;
    rgpszUsageIdentifier :PLPSTR;      // array of pszObjId
  end;

  CTL_ENTRY =  record
    SubjectIdentifier :CRYPT_DATA_BLOB;    // For example, its hash
    cAttribute        :DWORD;
    rgAttribute       :PCRYPT_ATTRIBUTE;   // OPTIONAL
  end;
  PCTL_ENTRY = ^CTL_ENTRY;


  CRL_ENTRY =  record
    SerialNumber :CRYPT_INTEGER_BLOB;
    RevocationDate :TFILETIME;
    cExtension :DWORD;
    rgExtension :PCERT_EXTENSION;
  end;
  PCRL_ENTRY = ^CRL_ENTRY;

  CTL_INFO =  record
    dwVersion           :DWORD;
    SubjectUsage        :CTL_USAGE;
    ListIdentifier      :CRYPT_DATA_BLOB;     // OPTIONAL
    SequenceNumber      :CRYPT_INTEGER_BLOB;  // OPTIONAL
    ThisUpdate          :TFILETIME;
    NextUpdate          :TFILETIME;           // OPTIONAL
    SubjectAlgorithm    :CRYPT_ALGORITHM_IDENTIFIER;
    cCTLEntry           :DWORD;
    rgCTLEntry          :PCTL_ENTRY;          // OPTIONAL
    cExtension          :DWORD;
    rgExtension         :PCERT_EXTENSION;     // OPTIONAL
  end;
  PCTL_INFO = ^CTL_INFO;

  CRL_INFO =  record
    dwVersion           :DWORD;
    SignatureAlgorithm  :CRYPT_ALGORITHM_IDENTIFIER;
    Issuer              :CERT_NAME_BLOB;
    ThisUpdate          :TFILETIME;
    NextUpdate          :TFILETIME;
    cCRLEntry           :DWORD;
    rgCRLEntry          :PCRL_ENTRY;
    cExtension          :DWORD;
    rgExtension         :PCERT_EXTENSION;
  end;
  PCRL_INFO = ^CRL_INFO;

  CRL_CONTEXT =  record
    dwCertEncodingType :DWORD;
    pbCrlEncoded :PBYTE;
    cbCrlEncoded :DWORD;
    pCrlInfo     :PCRL_INFO;
    hCertStore   :HCERTSTORE;
  end;
  PCRL_CONTEXT = ^CRL_CONTEXT;
  PCCRL_CONTEXT = ^CRL_CONTEXT;

  CTL_CONTEXT =  record
    dwMsgAndCertEncodingType :DWORD;
    pbCtlEncoded :PBYTE;
    cbCtlEncoded :DWORD;
    pCtlInfo     :PCTL_INFO;
    hCertStore   :HCERTSTORE;
    hCryptMsg    :HCRYPTMSG;
    pbCtlContent :PBYTE;
    cbCtlContent :DWORD;
  end;
  PCTL_CONTEXT = ^CTL_CONTEXT;
  PCCTL_CONTEXT = ^CTL_CONTEXT;

  CERT_STORE_PROV_FIND_INFO =  record
    cbSize : DWORD ;
    dwMsgAndCertEncodingType : DWORD;
    dwFindFlags : DWORD;
    dwFindType : DWORD;
    pvFindPara : Pointer;
  end;

  PCERT_STORE_PROV_FIND_INFO = ^CERT_STORE_PROV_FIND_INFO;
  CCERT_STORE_PROV_FIND_INFO =  CERT_STORE_PROV_FIND_INFO;
  PCCERT_STORE_PROV_FIND_INFO = ^CERT_STORE_PROV_FIND_INFO;

  {$ifdef B_5_UP}
  {$EXTERNALSYM _GUID}
   {$endif}
  _GUID =  record
    Data1 : DWORD;
    Data2 : WORD;
    Data3 : WORD;
    Data4 : array  [0..7]  of BYTE;
  end;

  {$ifdef B_5_UP}
  {$EXTERNALSYM GUID}
   {$endif}
  GUID =  _GUID;
  PGUID = ^_GUID;
  // IntPtr = ^integer;


  HMAC_INFO =  record
    HashAlgid : ALG_ID;
    pbInnerString :  PBYTE ;
    cbInnerString : DWORD;
    pbOuterString :  PBYTE ;
    cbOuterString : DWORD;
  end;

  {$ifdef BUILDER_USED}
  {$EXTERNALSYM ULONG_PTR}
   {$endif}
  ULONG_PTR =  ^ULONG;
  {$ifdef BUILDER_USED}
  {$EXTERNALSYM NCRYPT_HANDLE}
   {$endif}
  NCRYPT_HANDLE  =  ULONG_PTR;
  PNCRYPT_HANDLE = ^NCRYPT_HANDLE;
  {$ifdef BUILDER_USED}
  {$EXTERNALSYM NCRYPT_PROV_HANDLE}
   {$endif}
  NCRYPT_PROV_HANDLE  =  ULONG_PTR;
  PNCRYPT_PROV_HANDLE = ^NCRYPT_PROV_HANDLE;
  {$ifdef BUILDER_USED}
  {$EXTERNALSYM NCRYPT_KEY_HANDLE}
   {$endif}
  NCRYPT_KEY_HANDLE  =  ULONG_PTR;
  PNCRYPT_KEY_HANDLE = ^NCRYPT_KEY_HANDLE;
  {$ifdef BUILDER_USED}
  {$EXTERNALSYM NCRYPT_HASH_HANDLE}
   {$endif}
  NCRYPT_HASH_HANDLE  =  ULONG_PTR;
  PNCRYPT_HASH_HANDLE = ^NCRYPT_HASH_HANDLE;
  {$ifdef BUILDER_USED}
  {$EXTERNALSYM NCRYPT_SECRET_HANDLE}
   {$endif}
  NCRYPT_SECRET_HANDLE  =  ULONG_PTR;
  PNCRYPT_SECRET_HANDLE = ^NCRYPT_SECRET_HANDLE;
  {$ifdef BUILDER_USED}
  {$EXTERNALSYM SECURITY_STATUS}
   {$endif}
  SECURITY_STATUS =  LONG;

  NCryptBuffer =  record
    cbBuffer : ULONG;
    BufferType : ULONG;
    pvBuffer :  pointer ;
  end;
  PNCryptBuffer = ^NCryptBuffer;

  NCryptBufferDesc =  record
    ulVersion : ULONG;
    cBuffers : ULONG;
    pBuffers :  PNCryptBuffer ;
  end;
  PNCryptBufferDesc = ^NCryptBufferDesc;

  NCryptAlgorithmName =  record
    pszName :  PWideChar ;
    dwClass : DWORD;
    dwAlgOperations : DWORD;
    dwFlags : DWORD;
  end;
  PNCryptAlgorithmName = ^NCryptAlgorithmName;
  PPNCryptAlgorithmName = ^PNCryptAlgorithmName;

  NCryptKeyName =  record
    pszName :  PWideChar ;
    pszAlgid :  PWideChar ;
    dwLegacyKeySpec : DWORD;
    dwFlags : DWORD;
  end;
  PNCryptKeyName = ^NCryptKeyName;
  PPNCryptKeyName = ^PNCryptKeyName;

  NCryptProviderName =  record
    pszName :  PWideChar ;
    pszComment :  PWideChar ;
  end;
  PNCryptProviderName = ^NCryptProviderName;
  PPNCryptProviderName = ^PNCryptProviderName;

  BCRYPT_PKCS1_PADDING_INFO =  record
    pszAlgId :  PWideChar ;
  end;

  PPointer = ^pointer;

  // SB_JAVA

const
  {$externalsym  CERT_STORE_ADD_NEW}
  CERT_STORE_ADD_NEW = 1;
  {$externalsym  CERT_STORE_ADD_REPLACE_EXISTING}
  CERT_STORE_ADD_REPLACE_EXISTING = 3;
  {$externalsym  CERT_STORE_ADD_ALWAYS}
  CERT_STORE_ADD_ALWAYS = 4;
  {$externalsym CERT_STORE_READONLY_FLAG}
  CERT_STORE_READONLY_FLAG = $00008000;

  {$externalsym  CRYPT_ASN_ENCODING}
  CRYPT_ASN_ENCODING  = $00000001;
  {$externalsym  CRYPT_NDR_ENCODING}
  CRYPT_NDR_ENCODING = $00000002;

  {$externalsym CRYPT_E_UNKNOWN_ALGO}
  CRYPT_E_UNKNOWN_ALGO = $80091002;

  {$externalsym CRYPT_E_EXISTS}
  CRYPT_E_EXISTS = $80092005;

  {$externalsym  X509_ASN_ENCODING}
  X509_ASN_ENCODING = $00000001;

  {$externalsym  X509_NDR_ENCODING}
  X509_NDR_ENCODING = $00000002;

  {$externalsym  PKCS_7_ASN_ENCODING}
  PKCS_7_ASN_ENCODING = $00010000;

  {$externalsym  PKCS_7_NDR_ENCODING}
  PKCS_7_NDR_ENCODING = $00020000;

  {$externalsym  CERT_INFO_VERSION_FLAG}
  CERT_INFO_VERSION_FLAG                 = 1;

  {$externalsym  CERT_INFO_SERIAL_NUMBER_FLAG}
  CERT_INFO_SERIAL_NUMBER_FLAG           = 2;

  {$externalsym  CERT_INFO_SIGNATURE_ALGORITHM_FLAG}
  CERT_INFO_SIGNATURE_ALGORITHM_FLAG     = 3;

  {$externalsym  CERT_INFO_ISSUER_FLAG}
  CERT_INFO_ISSUER_FLAG                  = 4;

  {$externalsym  CERT_INFO_NOT_BEFORE_FLAG}
  CERT_INFO_NOT_BEFORE_FLAG              = 5;

  {$externalsym  CERT_INFO_NOT_AFTER_FLAG}
  CERT_INFO_NOT_AFTER_FLAG               = 6;

  {$externalsym  CERT_INFO_SUBJECT_FLAG}
  CERT_INFO_SUBJECT_FLAG                 = 7;

  {$externalsym  CERT_INFO_SUBJECT_PUBLIC_KEY_INFO_FLAG}
  CERT_INFO_SUBJECT_PUBLIC_KEY_INFO_FLAG = 8;

  {$externalsym  CERT_INFO_ISSUER_UNIQUE_ID_FLAG}
  CERT_INFO_ISSUER_UNIQUE_ID_FLAG        = 9;

  {$externalsym  CERT_INFO_SUBJECT_UNIQUE_ID_FLAG}
  CERT_INFO_SUBJECT_UNIQUE_ID_FLAG       = 10;

  {$externalsym  CERT_INFO_EXTENSION_FLAG}
  CERT_INFO_EXTENSION_FLAG               = 11;

  {$externalsym  CERT_COMPARE_SHIFT}
  CERT_COMPARE_SHIFT = 16;

  {$externalsym  CERT_COMPARE_ANY}
  CERT_COMPARE_ANY = 0;

  {$externalsym  CERT_COMPARE_SHA1_HASH}
  CERT_COMPARE_SHA1_HASH = 1;

  {$externalsym  CERT_COMPARE_NAME}
  CERT_COMPARE_NAME = 2;

  {$externalsym  CERT_COMPARE_ATTR}
  CERT_COMPARE_ATTR = 3;

  {$externalsym  CERT_COMPARE_MD5_HASH}
  CERT_COMPARE_MD5_HASH  = 4;

  {$externalsym  CERT_COMPARE_PROPERTY}
  CERT_COMPARE_PROPERTY = 5;

  {$externalsym CERT_COMPARE_PUBLIC_KEY}
  CERT_COMPARE_PUBLIC_KEY = 6;

  {$externalsym CERT_COMPARE_HASH}
  CERT_COMPARE_HASH = CERT_COMPARE_SHA1_HASH;

  {$externalsym CERT_COMPARE_NAME_STR_A}
  CERT_COMPARE_NAME_STR_A = 7;

  {$externalsym CERT_COMPARE_NAME_STR_W}
  CERT_COMPARE_NAME_STR_W = 8;

  {$externalsym CERT_COMPARE_KEY_SPEC}
  CERT_COMPARE_KEY_SPEC = 9;

  {$externalsym CERT_COMPARE_ENHKEY_USAGE}
  CERT_COMPARE_ENHKEY_USAGE = 10;

  {$externalsym CERT_COMPARE_CTL_USAGE}
  CERT_COMPARE_CTL_USAGE = CERT_COMPARE_ENHKEY_USAGE;

  {$externalsym CERT_FIND_ANY}
  CERT_FIND_ANY = (CERT_COMPARE_ANY shl CERT_COMPARE_SHIFT);

  {$externalsym CERT_FIND_SHA1_HASH}
  CERT_FIND_SHA1_HASH = (CERT_COMPARE_SHA1_HASH shl CERT_COMPARE_SHIFT);

  {$externalsym CERT_FIND_MD5_HASH}
  CERT_FIND_MD5_HASH = (CERT_COMPARE_MD5_HASH shl CERT_COMPARE_SHIFT);

  {$externalsym CERT_FIND_HASH}
  CERT_FIND_HASH = CERT_FIND_SHA1_HASH;

  {$externalsym CERT_FIND_PROPERTY}
  CERT_FIND_PROPERTY = (CERT_COMPARE_PROPERTY shl CERT_COMPARE_SHIFT);

  {$externalsym CERT_FIND_PUBLIC_KEY}
  CERT_FIND_PUBLIC_KEY = (CERT_COMPARE_PUBLIC_KEY shl CERT_COMPARE_SHIFT);

  {$externalsym CERT_FIND_SUBJECT_NAME}
  CERT_FIND_SUBJECT_NAME = (CERT_COMPARE_NAME shl CERT_COMPARE_SHIFT or CERT_INFO_SUBJECT_FLAG);

  {$externalsym CERT_FIND_SUBJECT_ATTR}
  CERT_FIND_SUBJECT_ATTR = (CERT_COMPARE_ATTR shl CERT_COMPARE_SHIFT or  CERT_INFO_SUBJECT_FLAG);

  {$externalsym CERT_FIND_ISSUER_NAME}
  CERT_FIND_ISSUER_NAME = (CERT_COMPARE_NAME shl CERT_COMPARE_SHIFT or  CERT_INFO_ISSUER_FLAG);

  {$externalsym CERT_FIND_ISSUER_ATTR}
  CERT_FIND_ISSUER_ATTR = (CERT_COMPARE_ATTR shl CERT_COMPARE_SHIFT or   CERT_INFO_ISSUER_FLAG);

  {$externalsym CERT_FIND_SUBJECT_STR_A}
  CERT_FIND_SUBJECT_STR_A =  (CERT_COMPARE_NAME_STR_A shl CERT_COMPARE_SHIFT or   CERT_INFO_SUBJECT_FLAG);

  {$externalsym CERT_FIND_SUBJECT_STR_W}
  CERT_FIND_SUBJECT_STR_W =  (CERT_COMPARE_NAME_STR_W shl CERT_COMPARE_SHIFT or   CERT_INFO_SUBJECT_FLAG);

  {$externalsym CERT_FIND_SUBJECT_STR}
  CERT_FIND_SUBJECT_STR = CERT_FIND_SUBJECT_STR_W;

  {$externalsym CERT_FIND_ISSUER_STR_A}
  CERT_FIND_ISSUER_STR_A = (CERT_COMPARE_NAME_STR_A shl CERT_COMPARE_SHIFT or  CERT_INFO_ISSUER_FLAG);

  {$externalsym CERT_FIND_ISSUER_STR_W}
  CERT_FIND_ISSUER_STR_W =  (CERT_COMPARE_NAME_STR_W shl CERT_COMPARE_SHIFT or  CERT_INFO_ISSUER_FLAG);

  {$externalsym CERT_FIND_ISSUER_STR}
  CERT_FIND_ISSUER_STR = CERT_FIND_ISSUER_STR_W;

  {$externalsym CERT_FIND_KEY_SPEC}
  CERT_FIND_KEY_SPEC = (CERT_COMPARE_KEY_SPEC shl CERT_COMPARE_SHIFT);

  {$externalsym CERT_FIND_ENHKEY_USAGE}
  CERT_FIND_ENHKEY_USAGE = (CERT_COMPARE_ENHKEY_USAGE shl CERT_COMPARE_SHIFT);

  {$externalsym CERT_FIND_CTL_USAGE}
  CERT_FIND_CTL_USAGE = CERT_FIND_ENHKEY_USAGE;

  {$externalsym CERT_SYSTEM_STORE_LOCATION_MASK}
  CERT_SYSTEM_STORE_LOCATION_MASK  = $00FF0000;
  {$EXTERNALSYM CERT_SYSTEM_STORE_LOCATION_MASK}
  CERT_SYSTEM_STORE_LOCATION_SHIFT = 16;
  {$EXTERNALSYM CERT_SYSTEM_STORE_LOCATION_SHIFT}
  CERT_SYSTEM_STORE_CURRENT_USER_ID  = 1;
  {$EXTERNALSYM CERT_SYSTEM_STORE_CURRENT_USER_ID}
  CERT_SYSTEM_STORE_LOCAL_MACHINE_ID = 2;
  {$EXTERNALSYM CERT_SYSTEM_STORE_LOCAL_MACHINE_ID}
  CERT_SYSTEM_STORE_CURRENT_SERVICE_ID = 4;
  {$EXTERNALSYM CERT_SYSTEM_STORE_CURRENT_SERVICE_ID}
  CERT_SYSTEM_STORE_SERVICES_ID        = 5;
  {$EXTERNALSYM CERT_SYSTEM_STORE_SERVICES_ID}
  CERT_SYSTEM_STORE_USERS_ID = 6;
  {$EXTERNALSYM CERT_SYSTEM_STORE_USERS_ID}
  CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY_ID = 7;
  {$EXTERNALSYM CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY_ID}
  CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY_ID = 8;
  {$EXTERNALSYM CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY_ID}
  CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID = 9;
  {$EXTERNALSYM CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID}
  CERT_SYSTEM_STORE_CURRENT_USER    = (CERT_SYSTEM_STORE_CURRENT_USER_ID shl CERT_SYSTEM_STORE_LOCATION_SHIFT);
  {$EXTERNALSYM CERT_SYSTEM_STORE_CURRENT_USER}
  CERT_SYSTEM_STORE_LOCAL_MACHINE   = (CERT_SYSTEM_STORE_LOCAL_MACHINE_ID shl CERT_SYSTEM_STORE_LOCATION_SHIFT);
  {$EXTERNALSYM CERT_SYSTEM_STORE_LOCAL_MACHINE}
  CERT_SYSTEM_STORE_CURRENT_SERVICE = (CERT_SYSTEM_STORE_CURRENT_SERVICE_ID shl CERT_SYSTEM_STORE_LOCATION_SHIFT);
  {$EXTERNALSYM CERT_SYSTEM_STORE_CURRENT_SERVICE}
  CERT_SYSTEM_STORE_SERVICES        = (CERT_SYSTEM_STORE_SERVICES_ID shl CERT_SYSTEM_STORE_LOCATION_SHIFT);
  {$EXTERNALSYM CERT_SYSTEM_STORE_SERVICES}
  CERT_SYSTEM_STORE_USERS           = (CERT_SYSTEM_STORE_USERS_ID shl CERT_SYSTEM_STORE_LOCATION_SHIFT);
  {$EXTERNALSYM CERT_SYSTEM_STORE_USERS}
  CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY   = (CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY_ID shl CERT_SYSTEM_STORE_LOCATION_SHIFT);
  {$EXTERNALSYM CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY}
  CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE = (CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID shl CERT_SYSTEM_STORE_LOCATION_SHIFT);
  {$EXTERNALSYM CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE}
  CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY = (CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY_ID shl CERT_SYSTEM_STORE_LOCATION_SHIFT);
  {$EXTERNALSYM CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY}
  CERT_STORE_OPEN_EXISTING_FLAG     = $00004000;
  {$EXTERNALSYM CERT_STORE_OPEN_EXISTING_FLAG}
  CERT_STORE_CREATE_NEW_FLAG        = $00002000;
  {$EXTERNALSYM CERT_STORE_CREATE_NEW_FLAG}
  CERT_STORE_DELETE_FLAG            = $00000010;
  {$EXTERNALSYM CERT_STORE_DELETE_FLAG}


  CRYPT_OID_OPEN_STORE_PROV_FUNC        = 'CertDllOpenStoreProv';

  {$EXTERNALSYM CERT_STORE_PROV_PHYSICAL}
  CERT_STORE_PROV_PHYSICAL              = 14;
  {$EXTERNALSYM CERT_KEY_PROV_INFO_PROP_ID}
  CERT_KEY_PROV_INFO_PROP_ID            = 2;
  {$EXTERNALSYM CERT_KEY_CONTEXT_PROP_ID}
  CERT_KEY_CONTEXT_PROP_ID              = 5;
  {$EXTERNALSYM CERT_KEY_SPEC_PROP_ID}
  CERT_KEY_SPEC_PROP_ID                 = 6;
  {$EXTERNALSYM CERT_FRIENDLY_NAME_PROP_ID}
  CERT_FRIENDLY_NAME_PROP_ID            = 11;

  {$EXTERNALSYM AT_KEYEXCHANGE}
  AT_KEYEXCHANGE                        = 1;
  {$EXTERNALSYM AT_SIGNATURE}
  AT_SIGNATURE                          = 2;
  {$EXTERNALSYM PUBLICKEYBLOB}
  PUBLICKEYBLOB                      = 6;
  {$EXTERNALSYM PRIVATEKEYBLOB}
  PRIVATEKEYBLOB                        = 7;
  {$EXTERNALSYM PLAINTEXTKEYBLOB}
  PLAINTEXTKEYBLOB                      = 8;
  {$EXTERNALSYM CRYPT_SILENT}
  CRYPT_SILENT                          = $40;
  {$EXTERNALSYM CRYPT_MESSAGE_SILENT_KEYSET_FLAG}
  CRYPT_MESSAGE_SILENT_KEYSET_FLAG      = $40;
  szOID_RSA_MD5                         = '1.2.840.113549.2.5';

  {$EXTERNALSYM CRYPT_MODE_CBC}
  CRYPT_MODE_CBC          = 1;
  {$EXTERNALSYM CRYPT_MODE_ECB}
  CRYPT_MODE_ECB          = 2;
  {$EXTERNALSYM CRYPT_MODE_OFB}
  CRYPT_MODE_OFB          = 3;
  {$EXTERNALSYM CRYPT_MODE_CFB}
  CRYPT_MODE_CFB          = 4;
  {$EXTERNALSYM CRYPT_MODE_CTS}
  CRYPT_MODE_CTS          = 5;

  {$EXTERNALSYM ALG_CLASS_HASH}
  ALG_CLASS_HASH                        = 4 shl 13;
  {$EXTERNALSYM ALG_CLASS_KEY_EXCHANGE}
  ALG_CLASS_KEY_EXCHANGE                = 5 shl 13;
  {$EXTERNALSYM ALG_CLASS_SIGNATURE}
  ALG_CLASS_SIGNATURE                   = 1 shl 13;
  {$EXTERNALSYM ALG_CLASS_MSG_ENCRYPT}
  ALG_CLASS_MSG_ENCRYPT                 = 2 shl 13;

  {$EXTERNALSYM ALG_TYPE_ANY}
  ALG_TYPE_ANY                          = 0;
  {$EXTERNALSYM ALG_TYPE_DH}
  ALG_TYPE_DH                           = 5 shl 9;
  {$EXTERNALSYM ALG_TYPE_DSS}
  ALG_TYPE_DSS                          = 1 shl 9;
  {$EXTERNALSYM ALG_TYPE_RSA}
  ALG_TYPE_RSA                          = 2 shl 9;
  {$EXTERNALSYM ALG_TYPE_SECURECHANNEL}
  ALG_TYPE_SECURECHANNEL                = 6 shl 9;

  { CryptoPro CSP GOST constant }
  {$EXTERNALSYM ALG_TYPE_GR3410}
  ALG_TYPE_GR3410 = 7 shl 9;

  {$EXTERNALSYM ALG_SID_SSL3SHAMD5}
  ALG_SID_SSL3SHAMD5                    = 8;
  {$EXTERNALSYM ALG_SID_SHA1}
  ALG_SID_SHA1                          = 4;
  {$EXTERNALSYM ALG_SID_MD2}
  ALG_SID_MD2                           = 1;
  {$EXTERNALSYM ALG_SID_MD4}
  ALG_SID_MD4                           = 2;
  {$EXTERNALSYM ALG_SID_MD5}
  ALG_SID_MD5                           = 3;
  {$EXTERNALSYM ALG_SID_MAC}
  ALG_SID_MAC                           = 5;
  {$EXTERNALSYM CALG_SSL3_SHAMD5}
  CALG_SSL3_SHAMD5                      = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SSL3SHAMD5;
  {$EXTERNALSYM CALG_SHA1}
  CALG_SHA1                             = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA1;
  {$EXTERNALSYM CALG_MAC}
  CALG_MAC                              = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_MAC;
  {$EXTERNALSYM CALG_MD2}
  CALG_MD2                              = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_MD2;
  {$EXTERNALSYM CALG_MD4}
  CALG_MD4                              = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_MD4;
  {$EXTERNALSYM CALG_MD5}
  CALG_MD5                              = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_MD5;
  {$EXTERNALSYM ALG_SID_AES}
  ALG_SID_AES                           = 17;
  {$EXTERNALSYM ALG_SID_AES_128}
  ALG_SID_AES_128                       = 14;
  {$EXTERNALSYM ALG_SID_AES_192}
  ALG_SID_AES_192                       = 15;
  {$EXTERNALSYM ALG_SID_AES_256}
  ALG_SID_AES_256                       = 16;
  {$EXTERNALSYM ALG_SID_SHA_256}
  ALG_SID_SHA_256                       = 12;
  {$EXTERNALSYM ALG_SID_SHA_384}
  ALG_SID_SHA_384                       = 13;
  {$EXTERNALSYM ALG_SID_SHA_512}
  ALG_SID_SHA_512                       = 14;
  {$EXTERNALSYM ALG_SID_DH_EPHEM}
  ALG_SID_DH_EPHEM                      = 2;
  {$EXTERNALSYM ALG_SID_DSS_ANY}
  ALG_SID_DSS_ANY                       = 0;
  {$EXTERNALSYM ALG_SID_RSA_ANY}
  ALG_SID_RSA_ANY                       = 0;
  {$EXTERNALSYM ALG_SID_SHA}
  ALG_SID_SHA                           = 4;
  {$EXTERNALSYM ALG_SID_ANY}
  ALG_SID_ANY                           = 0;
  {$EXTERNALSYM ALG_SID_3DES_112}
  ALG_SID_3DES_112                      = 9;
  {$EXTERNALSYM ALG_SID_DESX}
  ALG_SID_DESX                          = 4;
  {$EXTERNALSYM ALG_SID_SEAL}
  ALG_SID_SEAL                          = 2;
  {$EXTERNALSYM ALG_SID_DH_SANDF}
  ALG_SID_DH_SANDF                      = 1;
  {$EXTERNALSYM ALG_SID_AGREED_KEY_ANY}
  ALG_SID_AGREED_KEY_ANY                = 3;
  {$EXTERNALSYM ALG_SID_KEA}
  ALG_SID_KEA                           = 4;
  {$EXTERNALSYM ALG_SID_SKIPJACK}
  ALG_SID_SKIPJACK                      = 10;
  {$EXTERNALSYM ALG_SID_TEK}
  ALG_SID_TEK                           = 11;
  {$EXTERNALSYM ALG_SID_CYLINK_MEK}
  ALG_SID_CYLINK_MEK                    = 12;
  {$EXTERNALSYM ALG_SID_SSL3_MASTER}
  ALG_SID_SSL3_MASTER                   = 1;
  {$EXTERNALSYM ALG_SID_SCHANNEL_MASTER_HASH}
  ALG_SID_SCHANNEL_MASTER_HASH          = 2;
  {$EXTERNALSYM ALG_SID_SCHANNEL_MAC_KEY}
  ALG_SID_SCHANNEL_MAC_KEY              = 3;
  {$EXTERNALSYM ALG_SID_SCHANNEL_ENC_KEY}
  ALG_SID_SCHANNEL_ENC_KEY              = 7;
  {$EXTERNALSYM ALG_SID_PCT1_MASTER}
  ALG_SID_PCT1_MASTER                   = 4;
  {$EXTERNALSYM ALG_SID_SSL2_MASTER}
  ALG_SID_SSL2_MASTER                   = 5;
  {$EXTERNALSYM ALG_SID_TLS1_MASTER}
  ALG_SID_TLS1_MASTER                   = 6;
  {$EXTERNALSYM ALG_SID_RC5}
  ALG_SID_RC5                           = 13;
  {$EXTERNALSYM ALG_SID_HMAC}
  ALG_SID_HMAC                          = 9;
  {$EXTERNALSYM ALG_SID_TLS1PRF}
  ALG_SID_TLS1PRF                       = 10;
  {$EXTERNALSYM ALG_SID_HASH_REPLACE_OWF}
  ALG_SID_HASH_REPLACE_OWF              = 11;

  { CryptoPro CSP GOST constants }
  {$EXTERNALSYM ALG_SID_GR3411}
  ALG_SID_GR3411 = 30;
  {$EXTERNALSYM ALG_SID_GR3410}
  ALG_SID_GR3410 = 30;
  {$EXTERNALSYM ALG_SID_GR3410EL}
  ALG_SID_GR3410EL = 35;
  {$EXTERNALSYM ALG_SID_G28147}
  ALG_SID_G28147 = 30;
  {$EXTERNALSYM ALG_SID_PRODIVERS}
  ALG_SID_PRODIVERS = 38;
  {$EXTERNALSYM ALG_SID_PRO_EXP}  
  ALG_SID_PRO_EXP = 31;  
  
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_3DES}
   {$endif}
  CALG_3DES                             = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_3DES;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_AES}
   {$endif}
  CALG_AES                              = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_AES;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_AES_128}
   {$endif}
  CALG_AES_128                          = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_AES_128;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_AES_192}
   {$endif}
  CALG_AES_192                          = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_AES_192;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_AES_256}
   {$endif}
  CALG_AES_256                          = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_AES_256;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_SHA_256}
   {$endif}
  CALG_SHA_256                          = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA_256;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_SHA_384}
   {$endif}
  CALG_SHA_384                          = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA_384;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_SHA_512}
   {$endif}
  CALG_SHA_512                          = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA_512;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_DH_EPHEM}
   {$endif}
  CALG_DH_EPHEM                         = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_DH or ALG_SID_DH_EPHEM;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_DSS_SIGN}
   {$endif}
  CALG_DSS_SIGN                         = ALG_CLASS_SIGNATURE or ALG_TYPE_DSS or ALG_SID_DSS_ANY;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_RSA_KEYX}
   {$endif}
  CALG_RSA_KEYX                         = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_RSA or ALG_SID_RSA_ANY;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_RSA_SIGN}
   {$endif}
  CALG_RSA_SIGN                         = ALG_CLASS_SIGNATURE or ALG_TYPE_RSA or ALG_SID_RSA_ANY;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_SHA}
   {$endif}
  CALG_SHA                              = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_NO_SIGN}
   {$endif}
  CALG_NO_SIGN                          = ALG_CLASS_SIGNATURE or ALG_TYPE_ANY or ALG_SID_ANY;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_3DES_112}
   {$endif}
  CALG_3DES_112                         = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_3DES_112;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_DESX}
   {$endif}
  CALG_DESX                             = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_DESX;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_SEAL}
   {$endif}
  CALG_SEAL                             = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_STREAM or ALG_SID_SEAL;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_DH_SF}
   {$endif}
  CALG_DH_SF                            = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_DH or ALG_SID_DH_SANDF;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_AGREEDKEY_ANY}
   {$endif}
  CALG_AGREEDKEY_ANY                    = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_DH or ALG_SID_AGREED_KEY_ANY;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_KEA_KEYX}
   {$endif}
  CALG_KEA_KEYX                         = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_DH or ALG_SID_KEA;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_HUGHES_MD5}
   {$endif}
  CALG_HUGHES_MD5                       = ALG_CLASS_KEY_EXCHANGE or ALG_TYPE_ANY or ALG_SID_MD5;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_SKIPJACK}
   {$endif}
  CALG_SKIPJACK                         = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_SKIPJACK;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_TEK}
   {$endif}
  CALG_TEK                              = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_TEK;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_CYLINK_MEK}
   {$endif}
  CALG_CYLINK_MEK                       = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_CYLINK_MEK;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_SSL3_MASTER}
   {$endif}
  CALG_SSL3_MASTER                      = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_SSL3_MASTER;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_SCHANNEL_MASTER_HASH}
   {$endif}
  CALG_SCHANNEL_MASTER_HASH             = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_SCHANNEL_MASTER_HASH;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_SCHANNEL_MAC_KEY}
   {$endif}
  CALG_SCHANNEL_MAC_KEY                 = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_SCHANNEL_MAC_KEY;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_SCHANNEL_ENC_KEY}
   {$endif}
  CALG_SCHANNEL_ENC_KEY                 = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_SCHANNEL_ENC_KEY;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_PCT1_MASTER}
   {$endif}
  CALG_PCT1_MASTER                      = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_PCT1_MASTER;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_SSL2_MASTER}
   {$endif}
  CALG_SSL2_MASTER                      = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_SSL2_MASTER;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_TLS1_MASTER}
   {$endif}
  CALG_TLS1_MASTER                      = ALG_CLASS_MSG_ENCRYPT or ALG_TYPE_SECURECHANNEL or ALG_SID_TLS1_MASTER;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_RC5}
   {$endif}
  CALG_RC5                              = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_RC5;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_HMAC}
   {$endif}
  CALG_HMAC                             = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_HMAC;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_TLS1PRF}
   {$endif}
  CALG_TLS1PRF                          = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_TLS1PRF;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_HASH_REPLACE_OWF}
   {$endif}
  CALG_HASH_REPLACE_OWF                 = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_HASH_REPLACE_OWF;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_ECDH}
   {$endif}
  CALG_ECDH                             = $0000aa05;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_ECDSA}
   {$endif}
  CALG_ECDSA                            = $00002203;

  { CryptoPro CSP GOST constants }
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_GR3411}
   {$endif}
  CALG_GR3411 = ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_GR3411;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_GR3410}
   {$endif}
  CALG_GR3410 = ALG_CLASS_SIGNATURE or ALG_TYPE_GR3410 or ALG_SID_GR3410;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_GR3410EL}
   {$endif}
  CALG_GR3410EL = ALG_CLASS_SIGNATURE or ALG_TYPE_GR3410 or ALG_SID_GR3410EL;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_G28147}
   {$endif}
  CALG_G28147 = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_G28147;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_PRO_DIVERS}
   {$endif}
  CALG_PRO_DIVERS = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_PRODIVERS;
  {$ifdef VCL60}
  {$EXTERNALSYM CALG_PRO_EXPORT}
   {$endif}
  CALG_PRO_EXPORT = ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_PRO_EXP;

  {$EXTERNALSYM HP_HASHSIZE}
  HP_HASHSIZE                           = $0004;

  {$EXTERNALSYM HP_HASHVAL}
  HP_HASHVAL                            = $0002;

  {$EXTERNALSYM HP_HMAC_INFO}
  HP_HMAC_INFO                          = $0005;

  {$EXTERNALSYM KP_KEYLEN}
  KP_KEYLEN                             = 9;

  {$EXTERNALSYM KP_ALGID}
  KP_ALGID                              = 7;

  {$EXTERNALSYM KP_BLOCKLEN}
  KP_BLOCKLEN                           = 8;

  {$EXTERNALSYM KP_PERMISSIONS}
  KP_PERMISSIONS                        = 6;

  {$EXTERNALSYM KP_CERTIFICATE}
  KP_CERTIFICATE                        = 26;

  {$EXTERNALSYM CRYPT_E_UNEXPECTED_MSG_TYPE}
  CRYPT_E_UNEXPECTED_MSG_TYPE           = $8009200A;
  {$EXTERNALSYM _NTE_BAD_ALGID}
  _NTE_BAD_ALGID                        = $80090008;
  {$EXTERNALSYM CRYPT_E_NO_DECRYPT_CERT}
  CRYPT_E_NO_DECRYPT_CERT               = $8009200C;
  {$EXTERNALSYM CRYPT_IPSEC_HMAC_KEY}
  CRYPT_IPSEC_HMAC_KEY                  = $00000100;

  {$EXTERNALSYM NTE_BAD_SIGNATURE}
  NTE_BAD_SIGNATURE                     = $80090006;

  {$EXTERNALSYM PP_ENUMALGS}
  PP_ENUMALGS                           = 1;
  {$EXTERNALSYM PP_ENUMCONTAINERS}
  PP_ENUMCONTAINERS                     = 2;
  {$EXTERNALSYM PP_KEYEXCHANGE_PIN}
  PP_KEYEXCHANGE_PIN                    = 32;
  {$EXTERNALSYM PP_SIGNATURE_PIN}
  PP_SIGNATURE_PIN                      = 33;
  {$EXTERNALSYM CRYPT_FIRST}
  CRYPT_FIRST                           = 1;
  {$EXTERNALSYM CRYPT_NEXT}
  CRYPT_NEXT                            = 2;

  {$EXTERNALSYM CRYPT_EXPORTABLE}
  CRYPT_EXPORTABLE                      = 1;
  {$EXTERNALSYM CRYPT_USER_PROTECTED}
  CRYPT_USER_PROTECTED                  = 2;
  {$EXTERNALSYM CRYPT_NO_SALT}
  CRYPT_NO_SALT                         = 16;
  {$EXTERNALSYM CRYPT_VERIFYCONTEXT}
  CRYPT_VERIFYCONTEXT                   = $F0000000;

  {$EXTERNALSYM PROV_RSA}
  PROV_RSA                              = 1;
  {$EXTERNALSYM PROV_DSS}
  PROV_DSS                              = 3;
  {$EXTERNALSYM PROV_SSL}
  PROV_SSL                              = 6;
  {$EXTERNALSYM PROV_RSA_SCHANNEL}
  PROV_RSA_SCHANNEL                     = 12;
  {$EXTERNALSYM PROV_RSA_SIG}
  PROV_RSA_SIG                          = 2;
  {$EXTERNALSYM PROV_DSS_DH}
  PROV_DSS_DH                           = 13;
  {$EXTERNALSYM PROV_DH_SCHANNEL}
  PROV_DH_SCHANNEL                      = 18;
  {$EXTERNALSYM PROV_RSA_AES}
  PROV_RSA_AES                          = 24;
  {$EXTERNALSYM PROV_RSA_FULL}
  PROV_RSA_FULL                         = 1;
  {$EXTERNALSYM PROV_EC_ECDSA_SIG}
  PROV_EC_ECDSA_SIG                     = 14;
  {$EXTERNALSYM PROV_EC_ECNRA_SIG}
  PROV_EC_ECNRA_SIG                     = 15;
  {$EXTERNALSYM PROV_EC_ECDSA_FULL}
  PROV_EC_ECDSA_FULL                    = 16;
  {$EXTERNALSYM PROV_EC_ECNRA_FULL}
  PROV_EC_ECNRA_FULL                    = 17;
  // CryptoPro GOST CSP
  {$EXTERNALSYM PROV_GOST_94_DH}
  PROV_GOST_94_DH                       = 71;
  {$EXTERNALSYM PROV_GOST_2001_DH}
  PROV_GOST_2001_DH                     = 75;

  {$EXTERNALSYM CRYPT_NEWKEYSET}
  CRYPT_NEWKEYSET                       = 8;
  {$EXTERNALSYM CRYPT_MACHINE_KEYSET}
  CRYPT_MACHINE_KEYSET                  = 32;
  {$EXTERNALSYM CRYPT_DELETEKEYSET}
  CRYPT_DELETEKEYSET                    = $00000010;

  {$EXTERNALSYM CERT_KEY_PROV_HANDLE_PROP_ID}
  CERT_KEY_PROV_HANDLE_PROP_ID          = 1;

  {$EXTERNALSYM CERT_STORE_PROV_MSG}
  CERT_STORE_PROV_MSG                   = $00000001;
  {$EXTERNALSYM CERT_STORE_PROV_MEMORY}
  CERT_STORE_PROV_MEMORY                = $00000002;
  {$EXTERNALSYM CERT_STORE_PROV_FILE}
  CERT_STORE_PROV_FILE                  = $00000003;
  {$EXTERNALSYM CERT_STORE_PROV_REG}
  CERT_STORE_PROV_REG                   = $00000004;
  {$EXTERNALSYM CERT_STORE_PROV_PKCS7}
  CERT_STORE_PROV_PKCS7                 = $00000005;
  {$EXTERNALSYM CERT_STORE_PROV_SERIALIZED}
  CERT_STORE_PROV_SERIALIZED            = $00000006;
  {$EXTERNALSYM CERT_STORE_PROV_FILENAME_A}
  CERT_STORE_PROV_FILENAME_A            = $00000007;
  {$EXTERNALSYM CERT_STORE_PROV_FILENAME_W}
  CERT_STORE_PROV_FILENAME_W            = $00000008;
  {$EXTERNALSYM CERT_STORE_PROV_FILENAME}
  CERT_STORE_PROV_FILENAME              = CERT_STORE_PROV_FILENAME_W;
  {$EXTERNALSYM CERT_STORE_PROV_SYSTEM_A}
  CERT_STORE_PROV_SYSTEM_A              = $00000009;
  {$EXTERNALSYM CERT_STORE_PROV_SYSTEM_W}
  CERT_STORE_PROV_SYSTEM_W              = $0000000A;
  {$EXTERNALSYM CERT_STORE_PROV_SYSTEM}
  CERT_STORE_PROV_SYSTEM                = CERT_STORE_PROV_SYSTEM_W;
  {$EXTERNALSYM CERT_STORE_PROV_LDAP_W}
  CERT_STORE_PROV_LDAP_W                = $00000010;
  {$EXTERNALSYM CERT_STORE_PROV_LDAP}
  CERT_STORE_PROV_LDAP                  = CERT_STORE_PROV_LDAP_W;
  {$EXTERNALSYM CRYPT_MACHINE_DEFAULT}
  CRYPT_MACHINE_DEFAULT                 = $00000001;
  {$EXTERNALSYM CRYPT_USER_DEFAULT}
  CRYPT_USER_DEFAULT                    = $00000002;

  {$EXTERNALSYM PP_NAME}
  PP_NAME                               = 4;


  MS_DEF_PROV                             = 'Microsoft Base Cryptographic Provider v1.0';
  MS_ENHANCED_PROV                        = 'Microsoft Enhanced Cryptographic Provider v1.0';
  MS_ENH_DSS_DH_PROV                      = 'Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider';
  MS_DEF_RSA_SIG_PROV                     = 'Microsoft RSA Signature Cryptographic Provider';
  MS_DEF_RSA_SCHANNEL_PROV                = 'Microsoft RSA SChannel Cryptographic Provider';
  MS_ENHANCED_RSA_SCHANNEL_PROV           = 'Microsoft Enhanced RSA SChannel Cryptographic Provider';
  MS_DEF_DSS_PROV                         = 'Microsoft Base DSS Cryptographic Provider';
  MS_DEF_DSS_DH_PROV                      = 'Microsoft Base DSS and Diffie-Hellman Cryptographic Provider';
  MS_ENH_RSA_AES_PROV                     = 'Microsoft Enhanced RSA and AES Cryptographic Provider';
  MS_ENH_RSA_AES_PROV_XP                  = 'Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)';
  MS_SCARD_PROV                           = 'Microsoft Base Smart Card Crypto Provider';
  MS_STRONG_PROV                          = 'Microsoft Strong Cryptographic Provider';
  MS_DEF_DH_SCHANNEL_PROV                 = 'Microsoft DH SChannel Cryptographic Provider';
  { CryptoPro CSP }
  CP_GR3410_94_PROV                       = 'Crypto-Pro GOST R 34.10-94 Cryptographic Service Provider';
  CP_GR3410_2001_PROV                     = 'Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider';
  {CP_GOST_R3410_1994_KC1_PROV             = 'Crypto-Pro GOST R 34.10-94 KC1 CSP';
  CP_GOST_R3410_2001_KC1_PROV             = 'Crypto-Pro GOST R 34.10-2001 KC1 CSP';
  CP_GOST_R3410_1994_KC2_PROV             = 'Crypto-Pro GOST R 34.10-94 KC2 CSP';
  CP_GOST_R3410_2001_KC2_PROV             = 'Crypto-Pro GOST R 34.10-2001 KC2 CSP';}

  BCRYPT_SHA1_ALGORITHM                   = 'SHA1';
  BCRYPT_SHA256_ALGORITHM                 = 'SHA256';
  BCRYPT_SHA384_ALGORITHM                 = 'SHA384';
  BCRYPT_SHA512_ALGORITHM                 = 'SHA512';
  BCRYPT_MD2_ALGORITHM                    = 'MD2';
  BCRYPT_MD5_ALGORITHM                    = 'MD5';

  {$EXTERNALSYM BCRYPT_PAD_NONE}
  BCRYPT_PAD_NONE                         = $00000001;
  {$EXTERNALSYM BCRYPT_PAD_PKCS1}
  BCRYPT_PAD_PKCS1                        = $00000002;  // BCryptEncrypt/Decrypt BCryptSignHash/VerifySignature
  {$EXTERNALSYM BCRYPT_PAD_OAEP}
  BCRYPT_PAD_OAEP                         = $00000004;  // BCryptEncrypt/Decrypt
  {$EXTERNALSYM BCRYPT_PAD_PSS}
  BCRYPT_PAD_PSS                          = $00000008;  // BCryptSignHash/VerifySignature

  {$EXTERNALSYM NCRYPT_PAD_PKCS1_FLAG}
  NCRYPT_PAD_PKCS1_FLAG                   = BCRYPT_PAD_PKCS1;

  // SB_JAVA
  
function CertOpenSystemStore(hProv :HCRYPTPROV;
                             szSubsystemProtocol :PChar):HCERTSTORE ; stdcall;

function CertFindCertificateInStore(hCertStore :HCERTSTORE;
                                    dwCertEncodingType :DWORD;
                                    dwFindFlags :DWORD;
                                    dwFindType :DWORD;
                              const pvFindPara :PVOID;
                                    pPrevCertContext :PCCERT_CONTEXT
                                    ):PCCERT_CONTEXT ; stdcall;

function CertCloseStore(hCertStore :HCERTSTORE; dwFlags :DWORD):BOOL ; stdcall;

function CertEnumSystemStore(dwFlags: DWORD; pvSystemStoreLocationPara: Pointer;
  pvArg: Pointer; pfnEnum: PFN_CERT_ENUM_SYSTEM_STORE): BOOL; stdcall;

function CertAddEncodedCertificateToStore(hCertStore :HCERTSTORE;
                                          dwCertEncodingType :DWORD;
                                    const pbCertEncoded :PBYTE;
                                          cbCertEncoded :DWORD;
                                          dwAddDisposition :DWORD;
                                      var ppCertContext :PCCERT_CONTEXT):BOOL ; stdcall;

function CertFreeCertificateContext(pCertContext :PCCERT_CONTEXT):BOOL ; stdcall;

function CertDeleteCertificateFromStore(pCertContext :PCCERT_CONTEXT):BOOL ; stdcall;

function CertEnumCertificatesInStore(hCertStore : HCERTSTORE; pPrevCertContext :
  PCCERT_CONTEXT) : PCCERT_CONTEXT; stdcall;

function CertDuplicateCertificateContext(pCertContext : PCCERT_CONTEXT) : PCCERT_CONTEXT; stdcall;

function CertEnumPhysicalStore(pvSystemStore : pointer; dwFlags : DWORD; pvArg :
  pointer; pfnEnum : PFN_CERT_ENUM_PHYSICAL_STORE) : BOOL; stdcall;

function CertOpenStore(lpszStoreProvider : PAnsiChar; dwMsgAndCertEncodingType : DWORD;
  hCryptProv : HCRYPTPROV; dwFlags : DWORD; const pvPara : pointer) : HCERTSTORE; stdcall;

function CertGetCertificateContextProperty(pCertContext : PCCERT_CONTEXT; dwPropId : DWORD;
  pvData : pointer; pcbData : PDWORD) : BOOL; stdcall;

function CertSetCertificateContextProperty(pCertContext : PCCERT_CONTEXT;
  dwPropId : DWORD; dwFlags : DWORD; pvData  : Pointer) : BOOL; stdcall;

function CryptAcquireContext(hProv : PHCRYPTPROV; pszContainer : PChar;
  pszProvider : PChar; dwProvType : DWORD; dwFlags : DWORD) : BOOL; stdcall;

function CryptContextAddRef(hProv : HCRYPTPROV; pdwReserved : PDWORD; dwFlags : DWORD): BOOL; stdcall;

function CryptGetUserKey(hProv : HCRYPTPROV; dwKeySpec : DWORD; phUserKey : PHCRYPTKEY) : BOOL; stdcall;

function CryptDestroyKey(hKey : HCRYPTKEY) : BOOL; stdcall;

function CryptReleaseContext(hProv : HCRYPTPROV; dwFlags : DWORD) : BOOL; stdcall;

function CryptExportKey(hKey : HCRYPTKEY; hExpKey : HCRYPTKEY; dwBlobType : DWORD;
  dwFlags : DWORD; pbData : PBYTE; pdwDataLen : PDWORD) : BOOL; stdcall;

function CryptImportKey(hProv : HCRYPTPROV; pbData : PBYTE; dwDataLen : DWORD;
  hPubKey : HCRYPTKEY; dwFlags : DWORD; phKey : PHCRYPTKEY) : BOOL; stdcall;

{$ifndef NET_CF}
function CryptSignMessage(pSignPara : PCRYPT_SIGN_MESSAGE_PARA; fDetachedSignature : BOOL;
  cToBeSigned : DWORD; const rgpbToBeSigned : PPBYTE; rgcbToBeSigned : PDWORD;
  pbSignedBlob : PBYTE; pcbSignedBlob : PDWORD) : BOOL; stdcall;
 {$endif}

function CryptAcquireCertificatePrivateKey(pCert : PCCERT_CONTEXT; dwFlags : DWORD;
  pvReserved : pointer; phCryptProv : PHCRYPTPROV; pdwKeySpec : PDWORD;
  pfCallerFreeProv : PBOOL): BOOL; stdcall;

function CryptCreateHash(hProv : HCRYPTPROV; AlgId : ALG_ID; hKey : HCRYPTKEY;
  dwFlags : DWORD; phHash : PHCRYPTHASH) : BOOL; stdcall;

function CryptSetHashParam(hHash : HCRYPTHASH; dwParam : DWORD; pbData : PBYTE;
  dwFlags : DWORD) : BOOL; stdcall;

function CryptGetHashParam(hHash : HCRYPTHASH; dwParam : DWORD; pbData : PBYTE;
  var pdwDataLen : DWORD; dwFlags : DWORD) : BOOL; stdcall;

function CryptSignHash(hHash : HCRYPTHASH; dwKeySpec : DWORD; sDescription : PChar;
  dwFlags : DWORD; pbSignature : PBYTE; pdwSigLen : PDWORD) : BOOL; stdcall;

function CryptDestroyHash(hHash : HCRYPTHASH) : BOOL; stdcall;

function CryptHashData(hHash : HCRYPTHASH; pbData : PByte; dwDataLen : DWORD;
  dwFlags : DWORD) : BOOL; stdcall;

function CryptVerifySignature(hHash : HCRYPTHASH; pbSignature : PByte; dwSigLen : DWORD;
  hPubKey : HCRYPTKEY; sDescription : PChar; dwFlags : DWORD): BOOL; stdcall;

{$ifndef NET_CF}
function CryptFindLocalizedName(const pwszCryptName : PWideChar) : PWideChar; stdcall;

function CryptDecryptMessage(pDecryptPara : PCRYPT_DECRYPT_MESSAGE_PARA;
  pbEncryptedBlob : PBYTE; cbEncryptedBlob : DWORD; pbDecrypted : PBYTE;
  pcbDecrypted : PDWORD; ppXchgCert : PPCCERT_CONTEXT) : BOOL; stdcall;
 {$endif}

function CryptDecrypt(hKey : HCRYPTKEY; hHash : HCRYPTHASH; Final: BOOL;
  dwFlags : DWORD; pbData : PBYTE; var pdwDataLen : DWORD): BOOL; stdcall;

function CryptEncrypt(hKey : HCRYPTKEY; hHash : HCRYPTHASH; Final: BOOL;
  dwFlags : DWORD; pbData : PBYTE; var pdwDataLen : DWORD; dwBufLen : DWORD): BOOL; stdcall;

function CryptDuplicateKey(hKey : HCRYPTKEY; pdwReserved: PDWORD;
  dwFlags : DWORD; var phKey : HCRYPTKEY): BOOL; stdcall;

function CertCreateCertificateContext(dwCertEncodingType : DWORD;
  const pbCertEncoded : PBYTE; cbCertEncoded : DWORD) : PCCERT_CONTEXT; stdcall;

function CryptGetProvParam(hProv : HCRYPTPROV; dwParam : DWORD; pbData : PBYTE;
  pwdDataLen : PDWORD; dwFlags : DWORD) : BOOL; stdcall;

function CryptGetKeyParam(hKey : HCRYPTKEY; dwParam : DWORD; pbData : PBYTE;
  pdwDataLen : PDWORD; dwFlags : DWORD): BOOL; stdcall;

function CryptDeriveKey(hProv : HCRYPTPROV; Algid : ALG_ID; hBaseData : HCRYPTHASH;
  dwFlags : DWORD; phKey : PHCRYPTKEY) : BOOL; stdcall;

function CryptGenKey(hProv : HCRYPTPROV; Algid : ALG_ID; dwFlags : DWORD;
  phKey : PHCRYPTKEY): BOOL; stdcall;

{$ifndef NET_CF}
function CryptRegisterOIDFunction(dwEncodingType : DWORD; pszFuncName : PAnsiChar;
  pszOID : PAnsiChar; pwszDll : PWideChar; pszOverrideFuncName : PAnsiChar) : BOOL; stdcall;

function CryptUnregisterOIDFunction(dwEncodingType : DWORD; pszFuncName : PAnsiChar;
  pszOID : PAnsiChar) : BOOL; stdcall;
 {$endif}

function CryptInstallOIDFunctionAddress(hModule : HModule; dwEncodingType : DWORD;
  pszFuncName : PAnsiChar; cFuncEntry : DWORD; rgFuncEntry : PCRYPT_OID_FUNC_ENTRY;
  dwFlags : DWORD) : BOOL; stdcall;

function CoCreateGuid(guid : PGUID) : HRESULT; stdcall;


procedure GetProcedureAddress(var P: Pointer; const ModuleName: string; ProcName: AnsiString);

function CryptSetProvParam(hProv : HCRYPTPROV; dwParam: DWORD; pbData : PBYTE;
  dwFlags : DWORD): BOOL; stdcall;
function CryptSetKeyParam(hKey : HCRYPTKEY; dwParam: DWORD; pbData : PBYTE;
  dwFlags : DWORD): BOOL; stdcall;

{$ifdef SB_HAS_CRYPTUI}
function CryptUIDlgViewCertificate(pCertViewInfo: PCCRYPTUI_VIEWCERTIFICATE_STRUCT;
  pfPropertiesChanged: PBOOL): BOOL; stdcall;

function CryptUIDlgSelectCertificate(pcsc: PCCRYPTUI_SELECTCERTIFICATE_STRUCT): PCCERT_CONTEXT; stdcall;

function CryptUIWizImport(dwFlags: DWORD; hwndParent: HWND; pwszWizardTitle: PWideChar; pImportSrc: Pointer; hDestCertStore: HCERTSTORE): BOOL; stdcall;
 {$endif SB_HAS_CRYPTUI}

{$ifdef SB_HAS_CNG}
function NCryptCreatePersistedKey(hProvider : NCRYPT_PROV_HANDLE;
  phKey : PNCRYPT_KEY_HANDLE; pszAlgId : PWideChar; pszKeyName : PWideChar;
  dwLegacyKeySpec : DWORD; dwFlags : DWORD): SECURITY_STATUS; stdcall;

function NCryptDecrypt(hKey : NCRYPT_KEY_HANDLE; pbInput : PBYTE; cbInput : DWORD;
  pPaddingInfo : pointer; pbOutput : PBYTE; cbOutput : DWORD; pcbResult : PDWORD;
  dwFlags : DWORD) : SECURITY_STATUS; stdcall;

function NCryptDeleteKey(hKey : NCRYPT_KEY_HANDLE; dwFlags : DWORD): SECURITY_STATUS; stdcall;

function NCryptDeriveKey(hSharedSecret: NCRYPT_SECRET_HANDLE; pwszKDF : PWideChar;
  pParameterList : PNCryptBufferDesc; pbDerivedKey : PBYTE; cbDerivedKey : DWORD;
  pcbResult : PDWORD; dwFlags : ULONG): SECURITY_STATUS; stdcall;

function NCryptEncrypt(hKey : NCRYPT_KEY_HANDLE; pbInput : PBYTE; cbInput : DWORD;
  pPaddingInfo: pointer; pbOutput : PBYTE; cbOutput : DWORD; pcbResult : PDWORD;
  dwFlags : DWORD): SECURITY_STATUS; stdcall;

function NCryptEnumAlgorithms(hProvider : NCRYPT_PROV_HANDLE; dwAlgOperations : DWORD;
  pdwAlgCount : PDWORD; ppAlgList : PPNCryptAlgorithmName; dwFlags : DWORD): SECURITY_STATUS; stdcall;

function NCryptEnumKeys(hProvider : NCRYPT_PROV_HANDLE; pszScope : PWideChar;
  ppKeyName : PPNCryptKeyName; ppEnumState : PPointer; dwFlags : DWORD): SECURITY_STATUS; stdcall;

function NCryptEnumStorageProviders(pdwProviderCount : PDWORD; ppProviderList : PPNCryptProviderName;
  dwFlags : DWORD): SECURITY_STATUS; stdcall;

function NCryptExportKey(hKey: NCRYPT_KEY_HANDLE; hExportKey: NCRYPT_KEY_HANDLE;
  pszBlobType: PWideChar; pParameterList: PNCryptBufferDesc; pbOutput : PByte;
  cbOutput : DWORD; pcbResult : PDWORD; dwFlags : DWORD): SECURITY_STATUS; stdcall;

function NCryptFinalizeKey(hKey : NCRYPT_KEY_HANDLE; dwFlags : DWORD): SECURITY_STATUS; stdcall;

function NCryptFreeBuffer(pvInput : pointer): SECURITY_STATUS; stdcall;

function NCryptFreeObject(hObject : NCRYPT_HANDLE): SECURITY_STATUS; stdcall;

function NCryptGetProperty(hObject : NCRYPT_HANDLE; pszProperty : PWideChar;
  pbOutput : PBYTE; cbOutput : DWORD; pcbResult: PDWORD; dwFlags : DWORD): SECURITY_STATUS; stdcall;

function NCryptImportKey(hProvider : NCRYPT_PROV_HANDLE; hImportKey : NCRYPT_KEY_HANDLE;
  pszBlobType : PWideChar; pParameterList : PNCryptBufferDesc; phKey : PNCRYPT_KEY_HANDLE;
  pbData : PBYTE; cbData : DWORD; dwFlags : DWORD): SECURITY_STATUS; stdcall;

function NCryptIsAlgSupported(hProvider : NCRYPT_PROV_HANDLE; pszAlgId : PWideChar;
  dwFlags : DWORD): SECURITY_STATUS;

function NCryptIsKeyHandle(hKey : NCRYPT_KEY_HANDLE): BOOL; stdcall;

function NCryptKeyDerivation(hProvider : NCRYPT_PROV_HANDLE; hKey : NCRYPT_KEY_HANDLE;
  pswzDerivedKeyAlg : PWideChar; cbDerivedKeyLength : DWORD; pParameterList : PNCryptBufferDesc;
  phDerivedKey : PNCRYPT_KEY_HANDLE; dwFlags : ULONG): SECURITY_STATUS; stdcall;

function NCryptNotifyChangeKey(hProvider: NCRYPT_PROV_HANDLE; phEvent : PHANDLE;
  dwFlags : DWORD): SECURITY_STATUS; stdcall;

function NCryptOpenKey(hProvider : NCRYPT_PROV_HANDLE; phKey : PNCRYPT_KEY_HANDLE;
  pszKeyName : PWideChar; dwLegacyKeySpec : DWORD; dwFlags : DWORD): SECURITY_STATUS; stdcall;

function NCryptOpenStorageProvider(phProvider : PNCRYPT_PROV_HANDLE;
  pszProviderName : PWideChar; dwFlags : DWORD): SECURITY_STATUS; stdcall;

function NCryptSecretAgreement(hPrivKey : NCRYPT_KEY_HANDLE; hPubKey : NCRYPT_KEY_HANDLE;
  phSecret : PNCRYPT_SECRET_HANDLE; dwFlags : DWORD): SECURITY_STATUS; stdcall;

function NCryptSetProperty(hObject : NCRYPT_HANDLE; pszProperty : PWideChar;
  pbInput : PBYTE; cbInput : DWORD; dwFlags : DWORD): SECURITY_STATUS; stdcall;

function NCryptSignHash(hKey : NCRYPT_KEY_HANDLE; pPaddingInfo : pointer;
  pbHashValue : PBYTE; cbHashValue : DWORD; pbSignature : PBYTE; cbSignature : DWORD;
  pcbResult : PDWORD; dwFlags : DWORD): SECURITY_STATUS; stdcall;

function NCryptTranslateHandle(phProvider : PNCRYPT_PROV_HANDLE;
  phKey : PNCRYPT_KEY_HANDLE; hLegacyProv : HCRYPTPROV; hLegacyKey : HCRYPTKEY;
  dwLegacyKeySpec : DWORD; dwFlags : DWORD): SECURITY_STATUS; stdcall;

function NCryptVerifySignature(hKey: NCRYPT_KEY_HANDLE; pPaddingInfo : pointer;
  pbHashValue : PBYTE; cbHashValue : DWORD; pbSignature : PBYTE; cbSignature : DWORD;
  dwFlags : DWORD): SECURITY_STATUS; stdcall;
 {$endif SB_HAS_CNG}

 {$endif SB_HAS_WINCRYPT}

implementation

{$ifdef SB_HAS_WINCRYPT}


const
  {$ifndef NET_CF}
  CRYPT32     = 'crypt32.dll';
  OLE32       = 'ole32.dll';
  ADVAPI32    = 'advapi32.dll';
  KERNEL32    = 'kernel32.dll';
  NCRYPT      = 'ncrypt.dll';
  {$ifdef SB_HAS_CRYPTUI}
  CRYPTUI     = 'cryptui.dll';
   {$endif}
   {$else}
  CRYPT32     = 'crypt32.dll';
  OLE32       = 'ole32.dll';
  COREDLL     = 'coredll.dll';
   {$endif}

function CertOpenSystemStore; external  CRYPT32 name {$ifdef SB_UNICODE_VCL}'CertOpenSystemStoreW' {$else}'CertOpenSystemStoreA' {$endif} ;
function CertFindCertificateInStore; external  CRYPT32 name 'CertFindCertificateInStore' ;
function CertCloseStore; external CRYPT32 name 'CertCloseStore';
function CertAddEncodedCertificateToStore; external  CRYPT32 name 'CertAddEncodedCertificateToStore' ;
function CertFreeCertificateContext; external  CRYPT32 name 'CertFreeCertificateContext' ;
function CertDeleteCertificateFromStore; external  CRYPT32 name 'CertDeleteCertificateFromStore' ;
function CertEnumCertificatesInStore; external  CRYPT32 name 'CertEnumCertificatesInStore' ;
function CertDuplicateCertificateContext; external  CRYPT32 name 'CertDuplicateCertificateContext' ;
function CertOpenStore; external  CRYPT32 name 'CertOpenStore' ;
function CertGetCertificateContextProperty; external  CRYPT32 name 'CertGetCertificateContextProperty' ;
function CertSetCertificateContextProperty; external  CRYPT32 name 'CertSetCertificateContextProperty' ;
function CryptDecryptMessage; external  CRYPT32 name 'CryptDecryptMessage' ;
function CryptDecrypt; external  ADVAPI32 name 'CryptDecrypt' ;
function CryptEncrypt; external  ADVAPI32 name 'CryptEncrypt' ;
function CryptDuplicateKey; external  ADVAPI32 name 'CryptDuplicateKey' ;
function CertCreateCertificateContext; external  CRYPT32 name 'CertCreateCertificateContext' ;

function CryptAcquireContext; external  ADVAPI32 name {$ifdef SB_UNICODE_VCL}'CryptAcquireContextW' {$else}'CryptAcquireContextA' {$endif} ;
function CryptContextAddRef; external  ADVAPI32 name 'CryptContextAddRef' ;
function CryptGetUserKey; external  ADVAPI32 name 'CryptGetUserKey' ;
function CryptDestroyKey; external  ADVAPI32 name 'CryptDestroyKey' ;
function CryptReleaseContext; external  ADVAPI32 name 'CryptReleaseContext' ;
function CryptExportKey; external  ADVAPI32 name 'CryptExportKey' ;
function CryptImportKey; external  ADVAPI32 name 'CryptImportKey' ;
function CryptCreateHash; external  ADVAPI32 name 'CryptCreateHash' ;
function CryptHashData; external  ADVAPI32 name 'CryptHashData' ;
function CryptVerifySignature; external  ADVAPI32 name {$ifdef SB_UNICODE_VCL}'CryptVerifySignatureW' {$else}'CryptVerifySignatureA' {$endif} ;
function CryptSetHashParam; external  ADVAPI32 name 'CryptSetHashParam' ;
function CryptGetHashParam; external  ADVAPI32 name 'CryptGetHashParam' ;
function CryptSignHash; external  ADVAPI32 name {$ifdef SB_UNICODE_VCL}'CryptSignHashW' {$else}'CryptSignHashA' {$endif} ;
function CryptDestroyHash; external  ADVAPI32 name 'CryptDestroyHash' ;
function CryptGetProvParam; external  ADVAPI32 name 'CryptGetProvParam' ;
function CryptRegisterOIDFunction; external  CRYPT32 name 'CryptRegisterOIDFunction' ;
function CryptUnregisterOIDFunction; external  CRYPT32 name 'CryptUnregisterOIDFunction' ;
function CryptInstallOIDFunctionAddress; external  CRYPT32 name 'CryptInstallOIDFunctionAddress' ;
function CoCreateGuid; external  OLE32 name 'CoCreateGuid' ;
function CryptSetProvParam; external  ADVAPI32 name 'CryptSetProvParam' ;
function CryptSetKeyParam; external ADVAPI32 name 'CryptSetKeyParam';
function CryptGetKeyParam; external ADVAPI32 name 'CryptGetKeyParam';
function CryptDeriveKey; external ADVAPI32 name 'CryptDeriveKey';
function CryptGenKey; external ADVAPI32 name 'CryptGenKey';
(*
function NCryptCreatePersistedKey; external NCRYPT name 'NCryptCreatePersistedKey';
function NCryptDecrypt; external NCRYPT name 'NCryptDecrypt';
function NCryptDeleteKey; external NCRYPT name 'NCryptDeleteKey';
function NCryptDeriveKey; external NCRYPT name 'NCryptDeriveKey';
function NCryptEncrypt; external NCRYPT name 'NCryptEncrypt';
function NCryptEnumAlgorithms; external NCRYPT name 'NCryptEnumAlgorithms';
function NCryptEnumKeys; external NCRYPT name 'NCryptEnumKeys';
function NCryptEnumStorageProviders; external NCRYPT name 'NCryptEnumStorageProviders';
function NCryptExportKey; external NCRYPT name 'NCryptExportKey';
function NCryptFinalizeKey; external NCRYPT name 'NCryptFinalizeKey';
function NCryptFreeBuffer; external NCRYPT name 'NCryptFreeBuffer';
function NCryptFreeObject; external NCRYPT name 'NCryptFreeObject';
function NCryptGetProperty; external NCRYPT name 'NCryptGetProperty';
function NCryptImportKey; external NCRYPT name 'NCryptImportKey';
function NCryptIsAlgSupported; external NCRYPT name 'NCryptIsAlgSupported';
function NCryptIsKeyHandle; external NCRYPT name 'NCryptIsKeyHandle';
function NCryptNotifyChangeKey; external NCRYPT name 'NCryptNotifyChangeKey';
function NCryptOpenKey; external NCRYPT name 'NCryptOpenKey';
function NCryptOpenStorageProvider; external NCRYPT name 'NCryptOpenStorageProvider';
function NCryptSecretAgreement; external NCRYPT name 'NCryptSecretAgreement';
function NCryptSetProperty; external NCRYPT name 'NCryptSetProperty';
function NCryptSignHash; external NCRYPT name 'NCryptSignHash';
function NCryptTranslateHandle; external NCRYPT name 'NCryptTranslateHandle';
function NCryptVerifySignature; external NCRYPT name 'NCryptVerifySignature';
function NCryptKeyDerivation; external NCRYPT name 'NCryptKeyDerivation';
*)


{$ifdef SB_HAS_CRYPTUI}

var
  _CryptUIDlgViewCertificate :  pointer ;
  _CryptUIDlgSelectCertificate :  pointer ;
  _CryptUIWizImport :  pointer ;

type
  TSBCryptUIDlgViewCertificate = function(pCertViewInfo: PCCRYPTUI_VIEWCERTIFICATE_STRUCT;
    pfPropertiesChanged: PBOOL): BOOL; stdcall;

  TSBCryptUIDlgSelectCertificate = function(pcsc: PCCRYPTUI_SELECTCERTIFICATE_STRUCT): PCCERT_CONTEXT; stdcall;

  TSBCryptUIWizImport = function(dwFlags: DWORD; hwndParent: HWND; pwszWizardTitle: PWideChar; pImportSrc: 
    Pointer; hDestCertStore: HCERTSTORE): BOOL; stdcall;

function CryptUIDlgViewCertificate(pCertViewInfo: PCCRYPTUI_VIEWCERTIFICATE_STRUCT;
    pfPropertiesChanged: PBOOL): BOOL;
begin
  GetProcedureAddress(_CryptUIDlgViewCertificate, CRYPTUI, 'CryptUIDlgViewCertificateW');
  if (_CryptUIDlgViewCertificate =  nil ) then
    Result :=  false 
  else
    Result :=
    TSBCryptUIDlgViewCertificate(_CryptUIDlgViewCertificate)
    (pCertViewInfo, pfPropertiesChanged);
end;

function CryptUIDlgSelectCertificate(pcsc: PCCRYPTUI_SELECTCERTIFICATE_STRUCT): PCCERT_CONTEXT;
begin
  GetProcedureAddress(_CryptUIDlgSelectCertificate, CRYPTUI, 'CryptUIDlgSelectCertificateW');
  if (_CryptUIDlgSelectCertificate =  nil ) then
    Result :=  nil 
  else
    Result :=
    TSBCryptUIDlgSelectCertificate(_CryptUIDlgSelectCertificate)
    (pcsc);
end;

function CryptUIWizImport(dwFlags: DWORD; hwndParent: HWND; pwszWizardTitle: PWideChar; pImportSrc: Pointer; 
  hDestCertStore: HCERTSTORE): BOOL;
begin
  GetProcedureAddress(_CryptUIWizImport, CRYPTUI, 'CryptUIWizImport');
  if (_CryptUIWizImport =  nil ) then
    Result :=  false 
  else
    Result :=
    TSBCryptUIWizImport(_CryptUIWizImport)
    (dwFlags, hwndParent, pwszWizardTitle, pImportSrc, hDestCertStore);
end;

 {$endif SB_HAS_CRYPTUI}

{$ifdef SB_HAS_CNG}

var
  _NCryptCreatePersistedKey :  pointer ;
  _NCryptDecrypt :  pointer ;
  _NCryptDeleteKey :  pointer ;
  _NCryptDeriveKey :  pointer ;
  _NCryptEncrypt :  pointer ;
  _NCryptEnumAlgorithms :  pointer ;
  _NCryptEnumKeys :  pointer ;
  _NCryptEnumStorageProviders :  pointer ;
  _NCryptExportKey :  pointer ;
  _NCryptFinalizeKey :  pointer ;
  _NCryptFreeBuffer :  pointer ;
  _NCryptFreeObject :  pointer ;
  _NCryptGetProperty :  pointer ;
  _NCryptImportKey :  pointer ;
  _NCryptIsAlgSupported :  pointer ;
  _NCryptIsKeyHandle :  pointer ;
  _NCryptNotifyChangeKey :  pointer ;
  _NCryptOpenKey :  pointer ;
  _NCryptOpenStorageProvider :  pointer ;
  _NCryptSecretAgreement :  pointer ;
  _NCryptSetProperty :  pointer ;
  _NCryptSignHash :  pointer ;
  _NCryptTranslateHandle :  pointer ;
  _NCryptVerifySignature :  pointer ;
  _NCryptKeyDerivation :  pointer ;

type
  TSBNCryptCreatePersistedKey = function(hProvider : NCRYPT_PROV_HANDLE;
    phKey : PNCRYPT_KEY_HANDLE; pszAlgId : PWideChar; pszKeyName : PWideChar;
    dwLegacyKeySpec : DWORD; dwFlags : DWORD): SECURITY_STATUS; stdcall;

  TSBNCryptDecrypt = function(hKey : NCRYPT_KEY_HANDLE; pbInput : PBYTE; cbInput : DWORD;
  pPaddingInfo : pointer; pbOutput : PBYTE; cbOutput : DWORD; pcbResult : PDWORD;
  dwFlags : DWORD) : SECURITY_STATUS; stdcall;

  TSBNCryptDeleteKey = function(hKey : NCRYPT_KEY_HANDLE; dwFlags : DWORD): SECURITY_STATUS; stdcall;

  TSBNCryptDeriveKey = function(hSharedSecret: NCRYPT_SECRET_HANDLE; pwszKDF : PWideChar;
  pParameterList : PNCryptBufferDesc; pbDerivedKey : PBYTE; cbDerivedKey : DWORD;
  pcbResult : PDWORD; dwFlags : ULONG): SECURITY_STATUS; stdcall;

  TSBNCryptEncrypt = function(hKey : NCRYPT_KEY_HANDLE; pbInput : PBYTE; cbInput : DWORD;
  pPaddingInfo: pointer; pbOutput : PBYTE; cbOutput : DWORD; pcbResult : PDWORD;
  dwFlags : DWORD): SECURITY_STATUS; stdcall;

  TSBNCryptEnumAlgorithms = function(hProvider : NCRYPT_PROV_HANDLE; dwAlgOperations : DWORD;
  pdwAlgCount : PDWORD; ppAlgList : PPNCryptAlgorithmName; dwFlags : DWORD): SECURITY_STATUS; stdcall;

  TSBNCryptEnumKeys = function(hProvider : NCRYPT_PROV_HANDLE; pszScope : PWideChar;
  ppKeyName : PPNCryptKeyName; ppEnumState : PPointer; dwFlags : DWORD): SECURITY_STATUS; stdcall;

  TSBNCryptEnumStorageProviders = function(pdwProviderCount : PDWORD; ppProviderList : PPNCryptProviderName;
  dwFlags : DWORD): SECURITY_STATUS; stdcall;

  TSBNCryptExportKey = function(hKey: NCRYPT_KEY_HANDLE; hExportKey: NCRYPT_KEY_HANDLE;
  pszBlobType: PWideChar; pParameterList: PNCryptBufferDesc; pbOutput : PByte;
  cbOutput : DWORD; pcbResult : PDWORD; dwFlags : DWORD): SECURITY_STATUS; stdcall;

  TSBNCryptFinalizeKey = function(hKey : NCRYPT_KEY_HANDLE; dwFlags : DWORD): SECURITY_STATUS; stdcall;

  TSBNCryptFreeBuffer = function(pvInput : pointer): SECURITY_STATUS; stdcall;

  TSBNCryptFreeObject = function(hObject : NCRYPT_HANDLE): SECURITY_STATUS; stdcall;

  TSBNCryptGetProperty = function(hObject : NCRYPT_HANDLE; pszProperty : PWideChar;
  pbOutput : PBYTE; cbOutput : DWORD; pcbResult: PDWORD; dwFlags : DWORD): SECURITY_STATUS; stdcall;

  TSBNCryptImportKey = function(hProvider : NCRYPT_PROV_HANDLE; hImportKey : NCRYPT_KEY_HANDLE;
  pszBlobType : PWideChar; pParameterList : PNCryptBufferDesc; phKey : PNCRYPT_KEY_HANDLE;
  pbData : PBYTE; cbData : DWORD; dwFlags : DWORD): SECURITY_STATUS; stdcall;

  TSBNCryptIsAlgSupported = function(hProvider : NCRYPT_PROV_HANDLE; pszAlgId : PWideChar;
  dwFlags : DWORD): SECURITY_STATUS;

  TSBNCryptIsKeyHandle = function(hKey : NCRYPT_KEY_HANDLE): BOOL; stdcall;

  TSBNCryptKeyDerivation = function(hProvider : NCRYPT_PROV_HANDLE; hKey : NCRYPT_KEY_HANDLE;
  pswzDerivedKeyAlg : PWideChar; cbDerivedKeyLength : DWORD; pParameterList : PNCryptBufferDesc;
  phDerivedKey : PNCRYPT_KEY_HANDLE; dwFlags : ULONG): SECURITY_STATUS; stdcall;

  TSBNCryptNotifyChangeKey = function(hProvider: NCRYPT_PROV_HANDLE; phEvent : PHANDLE;
  dwFlags : DWORD): SECURITY_STATUS; stdcall;

  TSBNCryptOpenKey = function(hProvider : NCRYPT_PROV_HANDLE; phKey : PNCRYPT_KEY_HANDLE;
  pszKeyName : PWideChar; dwLegacyKeySpec : DWORD; dwFlags : DWORD): SECURITY_STATUS; stdcall;

  TSBNCryptOpenStorageProvider = function(phProvider : PNCRYPT_PROV_HANDLE;
  pszProviderName : PWideChar; dwFlags : DWORD): SECURITY_STATUS; stdcall;

  TSBNCryptSecretAgreement = function(hPrivKey : NCRYPT_KEY_HANDLE; hPubKey : NCRYPT_KEY_HANDLE;
  phSecret : PNCRYPT_SECRET_HANDLE; dwFlags : DWORD): SECURITY_STATUS; stdcall;

  TSBNCryptSetProperty = function(hObject : NCRYPT_HANDLE; pszProperty : PWideChar;
  pbInput : PBYTE; cbInput : DWORD; dwFlags : DWORD): SECURITY_STATUS; stdcall;

  TSBNCryptSignHash = function(hKey : NCRYPT_KEY_HANDLE; pPaddingInfo : pointer;
  pbHashValue : PBYTE; cbHashValue : DWORD; pbSignature : PBYTE; cbSignature : DWORD;
  pcbResult : PDWORD; dwFlags : DWORD): SECURITY_STATUS; stdcall;

  TSBNCryptTranslateHandle = function(phProvider : PNCRYPT_PROV_HANDLE;
  phKey : PNCRYPT_KEY_HANDLE; hLegacyProv : HCRYPTPROV; hLegacyKey : HCRYPTKEY;
  dwLegacyKeySpec : DWORD; dwFlags : DWORD): SECURITY_STATUS; stdcall;

  TSBNCryptVerifySignature = function(hKey: NCRYPT_KEY_HANDLE; pPaddingInfo : pointer;
  pbHashValue : PBYTE; cbHashValue : DWORD; pbSignature : PBYTE; cbSignature : DWORD;
  dwFlags : DWORD): SECURITY_STATUS; stdcall;

function NCryptCreatePersistedKey(hProvider : NCRYPT_PROV_HANDLE;
  phKey : PNCRYPT_KEY_HANDLE; pszAlgId : PWideChar; pszKeyName : PWideChar;
  dwLegacyKeySpec : DWORD; dwFlags : DWORD): SECURITY_STATUS;
begin
  GetProcedureAddress(_NCryptCreatePersistedKey, NCRYPT, 'NCryptCreatePersistedKey');
  if (_NCryptCreatePersistedKey =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptCreatePersistedKey(_NCryptCreatePersistedKey)
    (hProvider, phKey, pszAlgId, pszKeyName, dwLegacyKeySpec, dwFlags);
end;

function NCryptDecrypt(hKey : NCRYPT_KEY_HANDLE; pbInput : PBYTE; cbInput : DWORD;
  pPaddingInfo : pointer; pbOutput : PBYTE; cbOutput : DWORD; pcbResult : PDWORD;
  dwFlags : DWORD) : SECURITY_STATUS; 
begin
  GetProcedureAddress(_NCryptDecrypt, NCRYPT, 'NCryptDecrypt');
  if (_NCryptDecrypt =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptDecrypt(_NCryptDecrypt)
    (hKey, pbInput, cbInput, pPaddingInfo, pbOutput, cbOutput, pcbResult, dwFlags);
end;

function NCryptDeleteKey(hKey : NCRYPT_KEY_HANDLE; dwFlags : DWORD): SECURITY_STATUS; 
begin
  GetProcedureAddress(_NCryptDeleteKey, NCRYPT, 'NCryptDeleteKey');
  if (_NCryptDeleteKey =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptDeleteKey(_NCryptDeleteKey)
    (hKey, dwFlags);
end;

function NCryptDeriveKey(hSharedSecret: NCRYPT_SECRET_HANDLE; pwszKDF : PWideChar;
  pParameterList : PNCryptBufferDesc; pbDerivedKey : PBYTE; cbDerivedKey : DWORD;
  pcbResult : PDWORD; dwFlags : ULONG): SECURITY_STATUS; 
begin
  GetProcedureAddress(_NCryptDeriveKey, NCRYPT, 'NCryptDeriveKey');
  if (_NCryptDeriveKey =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptDeriveKey(_NCryptDeriveKey)
    (hSharedSecret, pwszKDF, pParameterList, pbDerivedKey, cbDerivedKey,
      pcbResult, dwFlags);
end;

function NCryptEncrypt(hKey : NCRYPT_KEY_HANDLE; pbInput : PBYTE; cbInput : DWORD;
  pPaddingInfo: pointer; pbOutput : PBYTE; cbOutput : DWORD; pcbResult : PDWORD;
  dwFlags : DWORD): SECURITY_STATUS; 
begin
  GetProcedureAddress(_NCryptEncrypt, NCRYPT, 'NCryptEncrypt');
  if (_NCryptEncrypt =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptEncrypt(_NCryptEncrypt)
    (hKey, pbInput, cbInput, pPaddingInfo, pbOutput, cbOutput, pcbResult, dwFlags);
end;

function NCryptEnumAlgorithms(hProvider : NCRYPT_PROV_HANDLE; dwAlgOperations : DWORD;
  pdwAlgCount : PDWORD; ppAlgList : PPNCryptAlgorithmName; dwFlags : DWORD): SECURITY_STATUS; 
begin
  GetProcedureAddress(_NCryptEnumAlgorithms, NCRYPT, 'NCryptEnumAlgorithms');
  if (_NCryptEnumAlgorithms =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptEnumAlgorithms(_NCryptEnumAlgorithms)
    (hProvider, dwAlgOperations, pdwAlgCount, ppAlgList, dwFlags);
end;

function NCryptEnumKeys(hProvider : NCRYPT_PROV_HANDLE; pszScope : PWideChar;
  ppKeyName : PPNCryptKeyName; ppEnumState : PPointer; dwFlags : DWORD): SECURITY_STATUS; 
begin
  GetProcedureAddress(_NCryptEnumKeys, NCRYPT, 'NCryptEnumKeys');
  if (_NCryptEnumKeys =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptEnumKeys(_NCryptEnumKeys)
    (hProvider, pszScope, ppKeyName, ppEnumState, dwFlags);
end;

function NCryptEnumStorageProviders(pdwProviderCount : PDWORD; ppProviderList : PPNCryptProviderName;
  dwFlags : DWORD): SECURITY_STATUS; 
begin
  GetProcedureAddress(_NCryptEnumStorageProviders, NCRYPT, 'NCryptEnumStorageProviders');
  if (_NCryptEnumStorageProviders =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptEnumStorageProviders(_NCryptEnumStorageProviders)
    (pdwProviderCount, ppProviderList, dwFlags);
end;

function NCryptExportKey(hKey: NCRYPT_KEY_HANDLE; hExportKey: NCRYPT_KEY_HANDLE;
  pszBlobType: PWideChar; pParameterList: PNCryptBufferDesc; pbOutput : PByte;
  cbOutput : DWORD; pcbResult : PDWORD; dwFlags : DWORD): SECURITY_STATUS; 
begin
  GetProcedureAddress(_NCryptExportKey, NCRYPT, 'NCryptExportKey');
  if (_NCryptExportKey =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptExportKey(_NCryptExportKey)
    (hKey, hExportKey, pszBlobType, pParameterList, pbOutput, cbOutput, pcbResult,
      dwFlags);
end;

function NCryptFinalizeKey(hKey : NCRYPT_KEY_HANDLE; dwFlags : DWORD): SECURITY_STATUS; 
begin
  GetProcedureAddress(_NCryptFinalizeKey, NCRYPT, 'NCryptFinalizeKey');
  if (_NCryptFinalizeKey =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptFinalizeKey(_NCryptFinalizeKey)
    (hKey, dwFlags);
end;

function NCryptFreeBuffer(pvInput : pointer): SECURITY_STATUS; 
begin
  GetProcedureAddress(_NCryptFreeBuffer, NCRYPT, 'NCryptFreeBuffer');
  if (_NCryptFreeBuffer =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptFreeBuffer(_NCryptFreeBuffer)
    (pvInput);
end;

function NCryptFreeObject(hObject : NCRYPT_HANDLE): SECURITY_STATUS; 
begin
  GetProcedureAddress(_NCryptFreeObject, NCRYPT, 'NCryptFreeObject');
  if (_NCryptFreeObject =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptFreeObject(_NCryptFreeObject)
    (hObject);
end;

function NCryptGetProperty(hObject : NCRYPT_HANDLE; pszProperty : PWideChar;
  pbOutput : PBYTE; cbOutput : DWORD; pcbResult: PDWORD; dwFlags : DWORD): SECURITY_STATUS; 
begin
  GetProcedureAddress(_NCryptGetProperty, NCRYPT, 'NCryptGetProperty');
  if (_NCryptGetProperty =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptGetProperty(_NCryptGetProperty)
    (hObject, pszProperty, pbOutput, cbOutput, pcbResult, dwFlags);
end;

function NCryptImportKey(hProvider : NCRYPT_PROV_HANDLE; hImportKey : NCRYPT_KEY_HANDLE;
  pszBlobType : PWideChar; pParameterList : PNCryptBufferDesc; phKey : PNCRYPT_KEY_HANDLE;
  pbData : PBYTE; cbData : DWORD; dwFlags : DWORD): SECURITY_STATUS; 
begin
  GetProcedureAddress(_NCryptImportKey, NCRYPT, 'NCryptImportKey');
  if (_NCryptImportKey =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptImportKey(_NCryptImportKey)
    (hProvider, hImportKey, pszBlobType, pParameterList, phKey, pbData, cbData, dwFlags);
end;

function NCryptIsAlgSupported(hProvider : NCRYPT_PROV_HANDLE; pszAlgId : PWideChar;
  dwFlags : DWORD): SECURITY_STATUS;
begin
  GetProcedureAddress(_NCryptIsAlgSupported, NCRYPT, 'NCryptIsAlgSupported');
  if (_NCryptIsAlgSupported =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptIsAlgSupported(_NCryptIsAlgSupported)
    (hProvider, pszAlgId, dwFlags);
end;

function NCryptIsKeyHandle(hKey : NCRYPT_KEY_HANDLE): BOOL; 
begin
  GetProcedureAddress(_NCryptIsKeyHandle, NCRYPT, 'NCryptIsKeyHandle');
  if (_NCryptIsKeyHandle =  nil ) then
    Result :=  false 
  else
    Result := 
    TSBNCryptIsKeyHandle(_NCryptIsKeyHandle)
    (hKey);
end;

function NCryptKeyDerivation(hProvider : NCRYPT_PROV_HANDLE; hKey : NCRYPT_KEY_HANDLE;
  pswzDerivedKeyAlg : PWideChar; cbDerivedKeyLength : DWORD; pParameterList : PNCryptBufferDesc;
  phDerivedKey : PNCRYPT_KEY_HANDLE; dwFlags : ULONG): SECURITY_STATUS; 
begin
  GetProcedureAddress(_NCryptKeyDerivation, NCRYPT, 'NCryptKeyDerivation');
  if (_NCryptKeyDerivation =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptKeyDerivation(_NCryptKeyDerivation)
    (hProvider, hKey, pswzDerivedKeyAlg, cbDerivedKeyLength, pParameterList,
      phDerivedKey, dwFlags);
end;

function NCryptNotifyChangeKey(hProvider: NCRYPT_PROV_HANDLE; phEvent : PHANDLE;
  dwFlags : DWORD): SECURITY_STATUS; 
begin
  GetProcedureAddress(_NCryptNotifyChangeKey, NCRYPT, 'NCryptNotifyChangeKey');
  if (_NCryptNotifyChangeKey =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptNotifyChangeKey(_NCryptNotifyChangeKey)
    (hProvider, phEvent, dwFlags);
end;

function NCryptOpenKey(hProvider : NCRYPT_PROV_HANDLE; phKey : PNCRYPT_KEY_HANDLE;
  pszKeyName : PWideChar; dwLegacyKeySpec : DWORD; dwFlags : DWORD): SECURITY_STATUS; 
begin
  GetProcedureAddress(_NCryptOpenKey, NCRYPT, 'NCryptOpenKey');
  if (_NCryptOpenKey =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptOpenKey(_NCryptOpenKey)
    (hProvider, phKey, pszKeyName, dwLegacyKeySpec, dwFlags);
end;


function NCryptOpenStorageProvider(phProvider : PNCRYPT_PROV_HANDLE;
  pszProviderName : PWideChar; dwFlags : DWORD): SECURITY_STATUS; 
begin
  GetProcedureAddress(_NCryptOpenStorageProvider, NCRYPT, 'NCryptOpenStorageProvider');
  if (_NCryptOpenStorageProvider =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptOpenStorageProvider(_NCryptOpenStorageProvider)
    (phProvider, pszProviderName, dwFlags);
end;


function NCryptSecretAgreement(hPrivKey : NCRYPT_KEY_HANDLE; hPubKey : NCRYPT_KEY_HANDLE;
  phSecret : PNCRYPT_SECRET_HANDLE; dwFlags : DWORD): SECURITY_STATUS; 
begin
  GetProcedureAddress(_NCryptSecretAgreement, NCRYPT, 'NCryptSecretAgreement');
  if (_NCryptSecretAgreement =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptSecretAgreement(_NCryptSecretAgreement)
    (hPrivKey, hPubKey, phSecret, dwFlags);
end;

function NCryptSetProperty(hObject : NCRYPT_HANDLE; pszProperty : PWideChar;
  pbInput : PBYTE; cbInput : DWORD; dwFlags : DWORD): SECURITY_STATUS; 
begin
  GetProcedureAddress(_NCryptSetProperty, NCRYPT, 'NCryptSetProperty');
  if (_NCryptSetProperty =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptSetProperty(_NCryptSetProperty)
    (hObject, pszProperty, pbInput, cbInput, dwFlags);
end;

function NCryptSignHash(hKey : NCRYPT_KEY_HANDLE; pPaddingInfo : pointer;
  pbHashValue : PBYTE; cbHashValue : DWORD; pbSignature : PBYTE; cbSignature : DWORD;
  pcbResult : PDWORD; dwFlags : DWORD): SECURITY_STATUS; 
begin
  GetProcedureAddress(_NCryptSignHash, NCRYPT, 'NCryptSignHash');
  if (_NCryptSignHash =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptSignHash(_NCryptSignHash)
    (hKey, pPaddingInfo, pbHashValue, cbHashValue, pbSignature, cbSignature,
      pcbResult, dwFlags);
end;

function NCryptTranslateHandle(phProvider : PNCRYPT_PROV_HANDLE;
  phKey : PNCRYPT_KEY_HANDLE; hLegacyProv : HCRYPTPROV; hLegacyKey : HCRYPTKEY;
  dwLegacyKeySpec : DWORD; dwFlags : DWORD): SECURITY_STATUS; 
begin
  GetProcedureAddress(_NCryptTranslateHandle, NCRYPT, 'NCryptTranslateHandle');
  if (_NCryptTranslateHandle =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptTranslateHandle(_NCryptTranslateHandle)
    (phProvider, phKey, hLegacyProv, hLegacyKey, dwLegacyKeySpec, dwFlags);
end;

function NCryptVerifySignature(hKey: NCRYPT_KEY_HANDLE; pPaddingInfo : pointer;
  pbHashValue : PBYTE; cbHashValue : DWORD; pbSignature : PBYTE; cbSignature : DWORD;
  dwFlags : DWORD): SECURITY_STATUS; 
begin
  GetProcedureAddress(_NCryptVerifySignature, NCRYPT, 'NCryptVerifySignature');
  if (_NCryptVerifySignature =  nil ) then
    Result := $ffffffff
  else
    Result := 
    TSBNCryptVerifySignature(_NCryptVerifySignature)
    (hKey, pPaddingInfo, pbHashValue, cbHashValue, pbSignature, cbSignature, dwFlags);
end;

 {$endif SB_HAS_CNG}



var
  _CertEnumSystemStore: Pointer;
  _CertEnumPhysicalStore: Pointer;
  _CryptSignMessage: Pointer;
  _CryptFindLocalizedName : pointer;
  _CryptAcquireCertificatePrivateKey : pointer;

function CryptSignMessage(pSignPara : PCRYPT_SIGN_MESSAGE_PARA; fDetachedSignature : BOOL;
  cToBeSigned : DWORD; const rgpbToBeSigned : PPBYTE; rgcbToBeSigned : PDWORD;
  pbSignedBlob : PBYTE; pcbSignedBlob : PDWORD) : BOOL; stdcall;
begin
  GetProcedureAddress(_CryptSignMessage, crypt32, 'CryptSignMessage');
  if _CryptSignMessage = nil then
    Result := false
  else
    Result := TCryptSignMessage(_CryptSignMessage)(pSignPara, fDetachedSignature,
      cToBeSigned, rgpbToBeSigned, rgcbToBeSigned, pbSignedBlob, pcbSignedBlob);
end;

function CryptAcquireCertificatePrivateKey(pCert : PCCERT_CONTEXT; dwFlags : DWORD;
  pvReserved : pointer; phCryptProv : PHCRYPTPROV; pdwKeySpec : PDWORD;
  pfCallerFreeProv : PBOOL): BOOL; stdcall;
begin
  GetProcedureAddress(_CryptAcquireCertificatePrivateKey, crypt32, 'CryptAcquireCertificatePrivateKey');
  if _CryptAcquireCertificatePrivateKey = nil then
    Result := false
  else
    Result := TCryptAcquireCertificatePrivateKey(_CryptAcquireCertificatePrivateKey)(
      pCert, dwFlags, pvReserved, phCryptProv, pdwKeySpec, pfCallerFreeProv);
end;

function CertEnumSystemStore(dwFlags: DWORD; pvSystemStoreLocationPara: Pointer;
  pvArg: Pointer; pfnEnum: PFN_CERT_ENUM_SYSTEM_STORE): BOOL; stdcall;
begin
  GetProcedureAddress(_CertEnumSystemStore, crypt32, 'CertEnumSystemStore');
  if _CertEnumSystemStore = nil then
    Result := false
  else
    Result := TCertEnumSystemStore(_CertEnumSystemStore)(dwFlags, pvSystemStoreLocationPara, pvArg, pfnEnum);
end;

function CertEnumPhysicalStore(pvSystemStore : pointer; dwFlags : DWORD; pvArg :
  pointer; pfnEnum : PFN_CERT_ENUM_PHYSICAL_STORE): BOOL; stdcall;
begin
  GetProcedureAddress(_CertEnumPhysicalStore, crypt32, 'CertEnumPhysicalStore');
  if _CertEnumPhysicalStore = nil then
    Result := false
  else
    Result := TCertEnumPhysicalStore(_CertEnumPhysicalStore)(pvSystemStore,
      dwFlags, pvArg, pfnEnum);
end;


procedure GetProcedureAddress(var P: Pointer; const ModuleName: string; ProcName: AnsiString);
var ModuleHandle : HMODULE;
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  if P = nil then
  begin
    ModuleHandle := GetModuleHandle({$ifdef SB_WINCE}PWideChar {$else}PChar {$endif}(ModuleName));
    if ModuleHandle = 0 then
    begin
      ModuleHandle := LoadLibrary({$ifdef SB_WINCE}PWideChar {$else}PChar {$endif}(ModuleName));
      if ModuleHandle = 0 then Exit;
    end;
    P := GetProcAddress(ModuleHandle, {$ifdef SB_WINCE}PWideChar {$else}PAnsiChar {$endif}(ProcName));
  end;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

function CryptFindLocalizedName(const pwszCryptName : PWideChar) : PWideChar; stdcall;
const
  Ptr : Pointer = nil;
begin
  GetProcedureAddress(_CryptFindLocalizedName, crypt32, 'CryptFindLocalizedName');
  if _CryptFindLocalizedName = nil then
    Result := nil
  else
    Result := TCryptFindLocalizedName(_CryptFindLocalizedName)(pwszCryptName);
end;

{$ifdef NET_CF_1_0}
function NewGuid(): System.GUID;
const
  VariantByte = 8;
  VariantByteMask = $3f;
  VariantByteShift = 6;
  VariantStandard = 2;
  VersionByte = 7;
  VersionByteMask = $f;
  VersionByteShift = 4;
  VersionRandom = 4;
var
  bits: ByteArray;
begin
  SetLength(bits, 16);
  SBRndGenerate(bits, 16);
  bits[VariantByte] := (bits[VariantByte] and VariantByteMask) or (VariantStandard shl VariantByteShift);
  bits[VersionByte] := (bits[VersionByte] and VersionByteMask) or (VersionRandom shl VersionByteShift);
  Result := System.GUID.Create(bits);
end;
 {$endif}


  // SB_JAVA 
 {$endif} // SB_WIN_CRYPT

end.



