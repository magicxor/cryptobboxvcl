(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBCryptoProvWin32;

interface

uses
  {$ifdef SB_WINDOWS}
  Windows,
   {$endif}
  Classes,
  SysUtils,
  SBCryptoProv,
  SBCryptoProvUtils,
  SBCryptoProvRS,
  SBSharedResource,
  SBMSKeyBlob,
  SBASN1Tree,
  SBRSA,
  SBDSA,
  {$ifdef SB_WINDOWS_OR_NET_OR_JAVA}
  SBWinCrypt,
   {$endif}
  SBConstants,
  SBTypes,
  SBUtils,
  SBRandom,
  SBStrUtils;


{$ifdef SB_WINDOWS_OR_NET_OR_JAVA}
{$ifdef SB_HAS_WINCRYPT}

type
  TElWin32CryptoProviderOptions =  class(TElCustomCryptoProviderOptions)
  protected
    FUseForPublicKeyOperations : boolean;
    FUseForSymmetricKeyOperations : boolean;
    FUseForHashingOperations : boolean;
    FUseForNonPrivateOperations : boolean;
    FThreadSafe : boolean;
    FUseBaseCSP : boolean;
    FUseStrongCSP : boolean;
    FUseEnhancedCSP : boolean;
    FUseAESCSP : boolean;
    FUseDSSCSP : boolean;
    FUseBaseDSSDHCSP : boolean;
    FUseEnhancedDSSDHCSP : boolean;
    FUseRSASchannelCSP : boolean;
    FUseRSASignatureCSP : boolean;
    FUseECDSASigCSP : boolean;
    FUseECNRASigCSP : boolean;
    FUseECDSAFullCSP : boolean;
    FUseECNRAFullCSP : boolean;
    FUseDHSchannelCSP : boolean;
    FUseCPGOST : boolean;
    FFIPSMode : boolean;
    FCacheKeyContexts : boolean;
    FStorePublicKeysInMemoryContainers : boolean;
    FForceEnhancedCSPForLongKeys : boolean;
    FAutoSelectEnhancedCSP : boolean;
    FTryAlternativeKeySpecOnFailure : boolean;
    FGenerateExportablePrivateKeys : boolean;
    FUseLocalMachineAccount : boolean;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure Init; override;
  public
    procedure Assign(Options : TElCustomCryptoProviderOptions); override;
    property UseForPublicKeyOperations : boolean read FUseForPublicKeyOperations
      write FUseForPublicKeyOperations;
    property UseForSymmetricKeyOperations : boolean read FUseForSymmetricKeyOperations
      write FUseForSymmetricKeyOperations;
    property UseForHashingOperations : boolean read FUseForHashingOperations
      write FUseForHashingOperations;
    property UseForNonPrivateOperations : boolean read FUseForNonPrivateOperations
      write FUseForNonPrivateOperations;
    property ThreadSafe : boolean read FThreadSafe write FThreadSafe;
    property UseBaseCSP : boolean read FUseBaseCSP write FUseBaseCSP;
    property UseStrongCSP : boolean read FUseStrongCSP write FUseStrongCSP;
    property UseEnhancedCSP : boolean read FUseEnhancedCSP write FUseEnhancedCSP;
    property UseAESCSP : boolean read FUseAESCSP write FUseAESCSP;
    property UseDSSCSP : boolean read FUseDSSCSP write FUseDSSCSP;
    property UseBaseDSSDHCSP : boolean read FUseBaseDSSDHCSP write FUseBaseDSSDHCSP;
    property UseEnhancedDSSDHCSP : boolean read FUseEnhancedDSSDHCSP write FUseEnhancedDSSDHCSP;
    property UseRSASchannelCSP : boolean read FUseRSASchannelCSP write FUseRSASchannelCSP;
    property UseRSASignatureCSP : boolean read FUseRSASignatureCSP write FUseRSASignatureCSP;
    property UseECDSASigCSP : boolean read FUseECDSASigCSP write FUseECDSASigCSP;
    property UseECNRASigCSP : boolean read FUseECNRASigCSP write FUseECNRASigCSP;
    property UseECDSAFullCSP : boolean read FUseECDSAFullCSP write FUseECDSAFullCSP;
    property UseECNRAFullCSP : boolean read FUseECNRAFullCSP write FUseECNRAFullCSP;
    property UseDHSchannelCSP : boolean read FUseDHSchannelCSP write FUseDHSchannelCSP;
    property UseCPGOST : boolean read FUseCPGOST write FUseCPGOST;
    property FIPSMode : boolean read FFIPSMode write FFIPSMode;
    property CacheKeyContexts : boolean read FCacheKeyContexts write FCacheKeyContexts;
    property StorePublicKeysInMemoryContainers : boolean read FStorePublicKeysInMemoryContainers
      write FStorePublicKeysInMemoryContainers;
    property ForceEnhancedCSPForLongKeys : boolean read FForceEnhancedCSPForLongKeys
      write FForceEnhancedCSPForLongKeys;
    property AutoSelectEnhancedCSP : boolean read FAutoSelectEnhancedCSP
      write FAutoSelectEnhancedCSP;
    property TryAlternativeKeySpecOnFailure : boolean read FTryAlternativeKeySpecOnFailure
      write FTryAlternativeKeySpecOnFailure;
    property GenerateExportablePrivateKeys : boolean read FGenerateExportablePrivateKeys
      write FGenerateExportablePrivateKeys;
    property UseLocalMachineAccount : boolean read FUseLocalMachineAccount
      write FUseLocalMachineAccount;
  end;

  function Win32CryptoProvider : TElCustomCryptoProvider;  overload;   function Win32CryptoProvider(OptionsTemplate : TElWin32CryptoProviderOptions): TElCustomCryptoProvider;  overload; 
type
  TElWin32CryptoProvider =  class(TElExternalCryptoProvider)
  protected
    FKeys : TElList;
    FContexts : TElList;
    FLock : TElSharedResource;
    FTryEnhancedCryptoProvider : boolean;
    FNativeSizeCalculation : boolean;
    FWindowHandle :  HWND ;
    FProviderInfos : TElList;
    FLastSigningError : string;
    FLastSigningErrorCode : DWORD;

    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function AddProviderInfo(Handle : HCRYPTPROV; const Name : string;
      FIPSCompliant : boolean): boolean;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure RefreshProviderInfos;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure ClearProviderInfos;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure ClearKeys();
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure ClearContexts();
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function InternalCreateKey(const AlgOID : ByteArray;
      const AlgParams : ByteArray; Params : TElCPParameters  =  nil): TElCustomCryptoKey;
    function TrySignHash(Context : TElCustomCryptoContext; Hash : HCRYPTHASH;
      KeySpec : DWORD; OutBuf : pointer; var OutBufSize : integer): boolean;
    function DecryptPKI(Context : TElCustomCryptoContext; Buffer: pointer;
      Size: integer; OutBuffer: pointer; var OutSize : integer): boolean;
    function DecryptPKIOAEP(Context : TElCustomCryptoContext; Buffer: pointer;
      Size: integer; OutBuffer: pointer; var OutSize : integer): boolean;
    function SignPKI(Context : TElCustomCryptoContext; Buffer: pointer;
      Size: integer; OutBuffer: pointer; var OutSize : integer): boolean;
    function SignPKIPSS(Context : TElCustomCryptoContext; Buffer: pointer;
      Size: integer; OutBuffer: pointer; var OutSize : integer): boolean;
    function VerifyPKI(Context : TElCustomCryptoContext; HashBuffer : pointer;
      HashSize: integer; SigBuffer : pointer; SigSize : integer): integer;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function TryDecodeASN1EncodedHash( HashBuffer : pointer; HashSize : integer ;
      var DefHashAlgorithm : integer): ByteArray;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function ReturnCryptoProviderManager: TElCustomCryptoProviderManager;
  protected
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function CreateOptions : TElCustomCryptoProviderOptions; override;
  public
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure Init(); override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure Deinit(); override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    class procedure SetAsDefault; override;

    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function IsAlgorithmSupported(Algorithm : integer; Mode : integer) : boolean; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function IsAlgorithmSupported(const AlgOID, AlgParams : ByteArray;
      Mode : integer): boolean; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function IsOperationSupported(Operation : integer; Algorithm : integer;
      Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters): boolean; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function IsOperationSupported(Operation : integer; const AlgOID, AlgParams : ByteArray;
      Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters): boolean; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetAlgorithmProperty(Algorithm : integer; Mode : integer;
      const PropID : ByteArray): ByteArray; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetAlgorithmProperty(const AlgOID, AlgParams : ByteArray;
      Mode : integer; const PropID : ByteArray): ByteArray; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetAlgorithmClass(Algorithm : integer): integer; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetAlgorithmClass(const AlgOID, AlgParams : ByteArray): integer; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetDefaultInstance : TElCustomCryptoProvider; override;

    // key management functions
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function CreateKey(Algorithm : integer; Mode : integer;
      Params : TElCPParameters  =  nil): TElCustomCryptoKey; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function CreateKey(const AlgOID : ByteArray; const AlgParams : ByteArray;
      Params : TElCPParameters  =  nil): TElCustomCryptoKey; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function CloneKey(Key : TElCustomCryptoKey) : TElCustomCryptoKey; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure ReleaseKey(var Key : TElCustomCryptoKey); override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure DeleteKey(var Key : TElCustomCryptoKey); override;
    function DecryptKey(EncKey : pointer; EncKeySize : integer; const EncKeyAlgOID,
      EncKeyAlgParams : ByteArray; Key : TElCustomCryptoKey; const KeyAlgOID,
      KeyAlgParams : ByteArray; Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil): TElCustomCryptoKey; override;

    // encryption and signing functions
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function EncryptInit(Algorithm : integer; Mode : integer; Key : TElCustomCryptoKey;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil) : TElCustomCryptoContext; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function EncryptInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
      Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil): TElCustomCryptoContext; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function DecryptInit(Algorithm : integer; Mode : integer; Key : TElCustomCryptoKey;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil) : TElCustomCryptoContext; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function DecryptInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
      Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil): TElCustomCryptoContext; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function SignInit(Algorithm : integer; Key : TElCustomCryptoKey;
      Detached : boolean; Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil) : TElCustomCryptoContext; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function SignInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
      Key : TElCustomCryptoKey; Detached : boolean; Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil): TElCustomCryptoContext; override;
    function VerifyInit(Algorithm : integer; Key : TElCustomCryptoKey;
      SigBuffer : pointer; SigSize : integer; Params : TElCPParameters = nil;
      ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil) : TElCustomCryptoContext; override;
    function VerifyInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
      Key : TElCustomCryptoKey; SigBuffer : pointer; SigSize : integer; Params : TElCPParameters = nil;
      ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil) : TElCustomCryptoContext; override;
    procedure EncryptUpdate(Context : TElCustomCryptoContext; InBuffer : pointer;
      InSize : integer; OutBuffer : pointer; var OutSize : integer;
      Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil); override;
    procedure DecryptUpdate(Context : TElCustomCryptoContext; InBuffer : pointer;
      InSize : integer; OutBuffer : pointer; var OutSize : integer;
      Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil); override;
    procedure SignUpdate(Context : TElCustomCryptoContext; InBuffer : pointer;
      InSize : integer; OutBuffer: pointer; var OutSize: integer;
      Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil); override;
    procedure VerifyUpdate(Context : TElCustomCryptoContext; InBuffer : pointer;
      InSize : integer; OutBuffer: pointer; var OutSize : integer;
      Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil); override;
    procedure EncryptFinal(Context : TElCustomCryptoContext; Buffer : pointer;
      var Size : integer; Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil); override;
    procedure DecryptFinal(Context : TElCustomCryptoContext; Buffer : pointer;
      var Size : integer; Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil); override;
    procedure SignFinal(Context : TElCustomCryptoContext; Buffer : pointer;
      var Size : integer; Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil); override;
    function VerifyFinal(Context : TElCustomCryptoContext; Buffer : pointer;
      var Size : integer; Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil): integer; override;

    // hash functions
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function HashInit(Algorithm : integer; Key : TElCustomCryptoKey;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil): TElCustomCryptoContext; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function HashInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
      Key : TElCustomCryptoKey; Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil): TElCustomCryptoContext; override;
    procedure HashUpdate(Context : TElCustomCryptoContext; Buffer : pointer;
      Size : integer; Params : TElCPParameters = nil;
      ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil); override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function HashFinal(Context : TElCustomCryptoContext; Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil): ByteArray; override;

    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure ReleaseCryptoContext(var Context : TElCustomCryptoContext); override;

    // key storage functions
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function CreateKeyStorage(Persistent: boolean; Params : TElCPParameters  =  nil): TElCustomCryptoKeyStorage; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure ReleaseKeyStorage(var KeyStorage : TElCustomCryptoKeyStorage); override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure DeleteKeyStorage(var KeyStorage : TElCustomCryptoKeyStorage); override;

    // randomizer functions
    procedure RandomInit(BaseData: pointer; BaseDataSize: integer; Params : TElCPParameters = nil); override;
    procedure RandomSeed(Data: pointer; DataSize: integer); override;
    procedure RandomGenerate(Buffer: pointer; Size: integer); override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function RandomGenerate(MaxValue: integer): integer; override;

    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetProviderProp(const PropID : ByteArray; const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =  nil {$endif}): ByteArray; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure SetProviderProp(const PropID : ByteArray; const Value : ByteArray); override;

    // public properties
    property TryEnhancedCryptoProvider : boolean read FTryEnhancedCryptoProvider
      write FTryEnhancedCryptoProvider;
    property NativeSizeCalculation : boolean read FNativeSizeCalculation
      write FNativeSizeCalculation;
  end;

  EElWin32CryptoProviderError =  class(EElCryptoProviderError);

  {$ifdef SB_HAS_CNG}
  TElCNGCryptoProviderHandleInfo = class
  protected
    FHandle : NCRYPT_PROV_HANDLE;
    FRefCount : integer;
  public
    constructor Create(Handle : NCRYPT_PROV_HANDLE);
  end;
  

  TElCNGCryptoProviderHandleManager = class
  protected
    FList : TElList;
    FCS : TElSharedResource;
  public
    constructor Create;
     destructor  Destroy; override;

    function OpenCNGStorageProvider(var phProvider : HCRYPTPROV;
      pszProviderName : PWideChar; dwFlags : DWORD): SECURITY_STATUS; overload;
    function OpenCNGStorageProvider( var phProvider : NCRYPT_PROV_HANDLE ;
      pszProviderName :  PWideChar ; dwFlags : DWORD): SECURITY_STATUS;  overload; 
      
    procedure FreeCNGStorageProvider(hProvider : HCRYPTPROV);
    procedure CNGStorageProviderAddRef(hProvider : HCRYPTPROV);
  end;
   {$endif}

 {$endif SB_HAS_WINCRYPT}
 {$endif SB_WINDOWS_OR_NET_OR_JAVA}

implementation

{$ifdef SB_WINDOWS_OR_NET_OR_JAVA}
{$ifdef SB_HAS_WINCRYPT}

uses
  SBCryptoProvManager, SBPKCS7, SBPKCS7Utils;

// singleton instance
var
  Win32CryptoProv : TElCustomCryptoProvider  = nil ;

const
  {$EXTERNALSYM ERROR_CANCELLED}
  ERROR_CANCELLED = 1223;

{$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
 {$else}
var
 {$endif}

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS OFF}
 {$endif}

  CALG_RSA_KEYX_ID      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$00#$a4#$00#$00 {$endif}; 
  CALG_DES_ID           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$01#$66#$00#$00 {$endif}; 
  CALG_3DES_ID          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$03#$66#$00#$00 {$endif}; 
  CALG_RC2_ID           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$02#$66#$00#$00 {$endif}; 
  CALG_RC4_ID           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$01#$68#$00#$00 {$endif}; 
  CALG_AES_128_ID       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$0E#$66#$00#$00 {$endif}; 
  CALG_AES_192_ID       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$0F#$66#$00#$00 {$endif}; 
  CALG_AES_256_ID       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$10#$66#$00#$00 {$endif}; 
  CALG_AES_ID           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$11#$66#$00#$00 {$endif}; 
  BLOB_ID_AND_RESERVED  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$01#$02#$00#$00 {$endif}; 

  SB_ALGSCHEME_PKCS1    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'pkcs#1' {$endif}; 
  SB_ALGSCHEME_PKCS5    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'pkcs#5' {$endif}; 
  SB_ALGSCHEME_OAEP     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'oaep' {$endif}; 
  SB_ALGSCHEME_PSS      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'pss' {$endif}; 

  SB_KEYPROP_RSA_KEYFORMAT_PKCS1 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'pkcs#1' {$endif}; 


const

//  KP_EFFECTIVE_KEYLEN   : DWORD {$ifndef SB_NET}={$else}:={$endif} 19; {$ifdef SB_NET}readonly;{$endif}
  KP_IV                 : DWORD  =  1; 
  KP_MODE               : DWORD  =  4; 
  KP_MODE_BITS          : DWORD  =  5; 

  SB_MAX_OPRESULT_SIZE  : integer  =  16384; // in bytes

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS ON}
 {$endif}

type
  TSBWin32CryptoContextType = (cctUndefined, cctSymCrypto, cctPKICrypto, cctHash);
  TSBWin32CryptoContextOperation = (ccoUndefined, ccoEncrypt, ccoDecrypt, ccoSign,
    ccoVerify, ccoSignDetached, ccoVerifyDetached, ccoHash);

  TElWin32AlgorithmInfo = class
  protected
    FAlgorithm : integer;
    FWin32Algorithm : integer;
    FBits : integer;
    FCanGenerate : boolean;
    FCanEncrypt : boolean;
    FCanSign : boolean;
    FCanDigest : boolean;
    FCanKex : boolean;
    FDefaultKeySize : integer;
    FDefaultBlockSize : integer;
    FName : string;
    FFIPSCompliant : boolean;
  end;

  TElWin32ProviderInfo = class(TSBDisposableBase)
  protected
    FProviderType : integer;
    FProviderName : string;
    FProvHandle : HCRYPTPROV;
    FSupportedAlgorithms: TElList;
    FReleaseProvHandle : boolean;
    FFIPSCompliant : boolean;
    FSecCriticalDisposed : boolean;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure RefreshSupportedAlgorithms;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure ClearSupportedAlgorithms;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function AcquireProvider: boolean;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure ReleaseProvider;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function IsAlgorithmSupported(Alg : integer; Mode: integer; Operation: integer; FIPSCompliancyNeeded : boolean): boolean;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetAlgorithmInfo(Alg : integer; Mode : integer; Operation: integer; FIPSCompliancyNeeded : boolean; KeySize : integer  =  0): TElWin32AlgorithmInfo;
  public
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    constructor Create;  overload; 
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    constructor Create(ProvType: integer; const ProvName : string; AutoRefresh : boolean;
      FIPSCompliant : boolean);  overload; 
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function Init(ProvType: integer; const ProvName : string; AutoRefresh : boolean;
      FIPSCompliant : boolean): boolean;
    destructor Destroy; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure Refresh;
  end;

  TElWin32CryptoKey = class(TElCustomCryptoKey)
  protected
    FCertContext :   PCCERT_CONTEXT  ;
    FPrivateKeyBlob : ByteArray;
    FPublicKeyBlob : ByteArray;
    FRawPublicKey : boolean;
    FRSAM : ByteArray;
    FRSAE : ByteArray;
    FDSAP : ByteArray;
    FDSAQ : ByteArray;
    FDSAG : ByteArray;
    FDSAY : ByteArray;
    FAlgorithm : integer;
    FHandle : HCRYPTKEY;                          // CryptoAPI key handle (NULL if FCNGKey is true)
    FProv : HCRYPTPROV;                           // CryptoAPI OR CNG provider handle
    //FCNGKey : boolean;                          // a flag indicating whether the contained object is a CNG key
    {$ifdef SB_HAS_CNG}
    FCNGKeyHandle : NCRYPT_KEY_HANDLE;          // CNG key handle (NULL if FCNGKey is false)
     {$endif}
    FCachedProv : HCRYPTPROV;                     // cached CryptoAPI or CNG provider handle
    FCachedAESProv : HCRYPTPROV;                 // cached CryptoAPI extended provider handle (not used with CNG keys)
    FCachedKeySpec : DWORD;
    {$ifdef SB_HAS_CNG}
    //FCachedIsCNGKey : boolean;                  // a flag indicating whether the cached object is a CNG key
    FCachedCNGKeyHandle : NCRYPT_KEY_HANDLE;    // cached CNG key handle
     {$endif}
    FValue : ByteArray;
    FIV : ByteArray;
    FReleaseProv : boolean;
    FProvType : integer;
    FProvName : string;
    FContName : string;
    FUserProvName : string;
    FUserContName : string;
    FKeyExchangePIN : ByteArray;
    FSignaturePIN : ByteArray;
    FImportedPrivateKey : boolean;
    FGeneratedPrivateKey : boolean;
    FReleaseContainer : boolean;
    FDoPersistentiate : boolean;
    FLastKeySpec : DWORD;
    FLastPubKeySpec : DWORD;
    FSecCriticalDisposed : boolean;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function LoadPrivateKeyFromWin32(CheckPresenseOnly: boolean  =  false): boolean;
    function GetContextAndStore(var CertStore: HCERTSTORE): PCCERT_CONTEXT;
    function LoadPrivateKeyFromContext(Context: PCCERT_CONTEXT; CheckPresenseOnly : boolean = false): boolean;
    function LoadPrivateKeyFromKey(Prov: HCRYPTPROV; Key: HCRYPTKEY; CheckPresenseOnly : boolean = false): boolean;
    function LoadPublicKeyFromKey(Prov: HCRYPTPROV; Key: HCRYPTKEY): boolean;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function AcquireCertificateContext(var Prov : HCRYPTPROV; var CNGKeyHandle : NCRYPT_KEY_HANDLE;
      CheckPresenseOnly : boolean  =  false): boolean;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function AcquireCertificateContextAES(var Prov : HCRYPTPROV): boolean;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function AcquireKeyContextAES(var Prov : HCRYPTPROV): boolean;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function AcquireCertificateContextPub(var Prov : HCRYPTPROV): boolean;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function ObtainCertificateContext(var Prov : HCRYPTPROV; var KeySpec : DWORD;
      var CNGKeyHandle : NCRYPT_KEY_HANDLE; CheckPresenseOnly : boolean; UseCache : boolean): boolean;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure RefreshPublicKeyValues();
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure TrimParams;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure AcquireKeyObject(AlgInfo : TElWin32AlgorithmInfo; Mode : integer; Prov : HCRYPTPROV);
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure CreatePrivateKeyContainer(ProvType: integer; const ProvName: string;
      const ContainerName: string  =  '';
      InMemoryContainer : boolean  =  false);
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure DestroyPrivateKeyContainer;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure UpdateDSAPublicKey();
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function IsContextCachingEnabled(): boolean;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function SubstituteRSAProviderIfNeeded(Info : TElWin32ProviderInfo; KeyBits : integer): TElWin32ProviderInfo;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure GenerateRSAKeyPair(Bits : integer; Params : TElCPParameters);
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure SetProvPINs(Prov : HCRYPTPROV);
    {$ifdef SB_HAS_CNG}
    function IsCNGKey(): boolean;
    function CachedIsCNGKey(): boolean;
     {$endif}
  protected
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetIsPublic: boolean; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetIsSecret: boolean; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetIsExportable: boolean; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetIsPersistent: boolean; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetIsValid: boolean; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetBits : integer; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetAlgorithm : integer; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetKeyStorage : TElCustomCryptoKeyStorage; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetMode : integer; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure SetMode(Value : integer); override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetIV : ByteArray; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure SetIV(const Value : ByteArray); override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetValue : ByteArray; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure SetValue(const Value : ByteArray); override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecurityCritical]
     {$endif}
    procedure SetProvPIN(Prov : HCRYPTPROV; PinParamConst : DWORD; const Value: ByteArray);
  public
    constructor Create(CryptoProvider : TElCustomCryptoProvider); override;
    destructor Destroy; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure Reset; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure Generate(Bits : integer;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil); override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure ChangeAlgorithm(Algorithm : integer); override;
    procedure ImportPublic(Buffer: pointer; Size: integer; Params : TElCPParameters = nil); override;
    procedure ImportSecret(Buffer: pointer; Size: integer; Params : TElCPParameters = nil); override;
    procedure ExportPublic(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil); override;
    procedure ExportSecret(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil); override;
    procedure ImportRSAPrivateKey(Buffer: pointer; Size: integer;
      IntoCurrentContainer: boolean  =  false;
      Prot : boolean  =  false;
      Exportable : boolean  =  false);
    procedure ImportDSAPrivateKey(Buffer: pointer; Size: integer);
    procedure ImportRSAPublicKey(Buffer: pointer; Size: integer);
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoKey; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function ClonePublic(Params : TElCPParameters  =  nil) : TElCustomCryptoKey; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure ClearPublic; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure ClearSecret; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetKeyProp(const PropID : ByteArray; const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =  nil {$endif}): ByteArray; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure SetKeyProp(const PropID : ByteArray; const Value : ByteArray); override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure PrepareForEncryption(MultiUse : boolean  =  false); override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure PrepareForSigning(MultiUse : boolean  =  false); override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure CancelPreparation; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function AsyncOperationFinished : boolean; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function Equals(Source : TElCustomCryptoKey; PublicOnly : boolean;
      Params : TElCPParameters  =  nil): boolean; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure Persistentiate; override;
  end;

  // TODO: try to export private key if possible (or optionally?) to prevent
  // errors caused by internal decryption

  TElWin32CryptoContext = class(TElCustomCryptoContext)
  protected
    FAlgorithm : integer;
    FKey : TElCustomCryptoKey;
    FSpool : ByteArray;
    FOtherSpool : ByteArray;
    FSignSource : ByteArray;
    FContextType : TSBWin32CryptoContextType;
    FHashAlgorithm : integer;
    FInputIsHash : boolean;
    FHashFuncOID : ByteArray;
    FHashContext : TElCustomCryptoContext;
    FOperation : TSBWin32CryptoContextOperation;
    FUseOAEP : boolean;
    FUsePSS : boolean;
    FProvHandle : HCRYPTPROV;
    FHashHandle : HCRYPTHASH;
    FExtraHashHandle : HCRYPTHASH;
    FKeyHandle : HCRYPTKEY;
    FOperationDone : boolean;
    FOperationResult : integer;
    FSignature : ByteArray;
    FPadding : integer;
    FUseAlgorithmPrefix : boolean;
    FSecCriticalDisposed : boolean;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetAlgorithm : integer; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetAlgorithmClass : integer; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetKeySize : integer; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure SetKeySize(Value: integer); override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetBlockSize : integer; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure SetBlockSize(Value: integer); override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetDigestSize : integer; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure SetDigestSize(Value : integer); override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetMode : integer; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure SetMode(Value : integer); override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetPadding : integer; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure SetPadding(Value : integer); override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure Init(Params : TElCPParameters);
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure PrepareOperation();
  public
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    constructor Create(Algorithm : integer; Mode : integer; Key : TElCustomCryptoKey;
      Operation : TSBWin32CryptoContextOperation; Prov : TElCustomCryptoProvider;
      Params : TElCPParameters);  overload; 
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    constructor Create(const AlgOID, AlgParams : ByteArray; Mode : integer; Key : TElCustomCryptoKey;
      Operation : TSBWin32CryptoContextOperation; Prov : TElCustomCryptoProvider;
      Params : TElCPParameters);  overload; 
    destructor Destroy; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function EstimateOutputSize(InSize: Int64): Int64; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function Clone(Params : TElCPParameters  =  nil): TElCustomCryptoContext; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetContextProp(const PropID : ByteArray; const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =  nil {$endif}): ByteArray; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure SetContextProp(const PropID : ByteArray; const Value : ByteArray); override;
  end;

resourcestring
  SWin32Error = 'Win32 error: %d';
  SFailedToAcquireProviderContext = 'Failed to acquire provider context. Provider type: %d, name: %s.';
  SSigningFailedInfo = 'Signing failed: %s';
  SFailedToImportSymmetricKey = 'Failed to import symmetric key material';
  SFailedToAcquireKeyContext = 'Failed to acquire key context';
  SBadKeyProvInfo = 'Bad key provider info';
  SFailedToCloneCNGKey = 'Failed to clone CNG key handle';
  SProviderRequiresElevatedPermissions = 'TElWin32CryptoProvider requires elevated permissions';
  
{$ifdef SB_HAS_CNG}
var
  G_CNGCryptoProviderHandleManager : TElCNGCryptoProviderHandleManager  =  nil;

function CNGCryptoProviderHandleManager(): TElCNGCryptoProviderHandleManager;
begin
  if G_CNGCryptoProviderHandleManager = nil then
    G_CNGCryptoProviderHandleManager := TElCNGCryptoProviderHandleManager.Create();
  Result := G_CNGCryptoProviderHandleManager;
end;
 {$endif}

const
  PP_CLIENT_HWND = 1;
  SB_DEF_KEY_CONTAINER = '_5D84F7E9_CB41_448C_8EBC_3745E989BB00';
  
  NCRYPT_PROVIDER_HANDLE_PROPERTY : WideString = 'Provider Handle';
  NCRYPT_NAME_PROPERTY : WideString = 'Name';
  NCRYPT_LENGTH_PROPERTY : WideString = 'Length';
  
////////////////////////////////////////////////////////////////////////////////
// Miscellaneous utility functions

{$ifdef SB_HAS_CNG}
{$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
[SecurityCritical]
 {$endif}
function DuplicateCNGProviderContext(Prov : NCRYPT_PROV_HANDLE): NCRYPT_PROV_HANDLE;
var
  Size :  DWORD ;
  Buf : ByteArray;
begin
  Result := nil;
  NCryptGetProperty(Prov,  PWideChar (NCRYPT_NAME_PROPERTY),
      nil  , 0,  @ Size, 0);
  SetLength(Buf, Size);
  if NCryptGetProperty(Prov,  PWideChar (NCRYPT_NAME_PROPERTY),
     @Buf[0] , Size,  @ Size, 0) <> ERROR_SUCCESS then
    Exit;
  CNGCryptoProviderHandleManager().OpenCNGStorageProvider(Result,
     PWideChar(@Buf[0]) , 0);
end;
 {$endif}



{$ifdef SB_HAS_CNG}
{$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
[SecurityCritical]
 {$endif}
function DuplicateCNGKeyHandle(Handle : NCRYPT_KEY_HANDLE): NCRYPT_KEY_HANDLE;
var
  Size :  DWORD ;
  Buf : ByteArray;
  ProvHandle : NCRYPT_PROV_HANDLE;
begin
  Result :=   nil  ;
  Size := 0;
  NCryptGetProperty(Handle,  PWideChar (NCRYPT_PROVIDER_HANDLE_PROPERTY),
      nil  , 0,  @ Size, 0);
  SetLength(Buf, Size);
  if NCryptGetProperty(Handle,  PWideChar (NCRYPT_PROVIDER_HANDLE_PROPERTY),
     @Buf[0] , Size,  @ Size, 0) <> ERROR_SUCCESS then
    Exit;
  SBMove(Buf[0], ProvHandle, SizeOf(ProvHandle));
  Size := 0;
  NCryptGetProperty(Handle,  PWideChar (NCRYPT_NAME_PROPERTY),
      nil  , 0,  @ Size, 0);
  SetLength(Buf, Size);
  if NCryptGetProperty(Handle,  PWideChar (NCRYPT_NAME_PROPERTY),
     @Buf[0] , Size,  @ Size, 0) <> ERROR_SUCCESS then
    Exit;
  NCryptOpenKey(ProvHandle,  @ Result,  PWideChar(@Buf[0]) , 0, 0);
end;
 {$endif SB_HAS_CNG}

{$ifdef SB_HAS_CNG}
////////////////////////////////////////////////////////////////////////////////
// TElCNGCryptoProviderHandleManager class

constructor TElCNGCryptoProviderHandleInfo.Create(Handle : NCRYPT_PROV_HANDLE);
begin
  inherited Create;
  FHandle := Handle;
  FRefCount := 1;
end;

constructor TElCNGCryptoProviderHandleManager.Create;
begin
  inherited;
  FList := TElList.Create();
  FCS := TElSharedResource.Create();
end;

 destructor  TElCNGCryptoProviderHandleManager.Destroy;
var
  I : integer;
begin
  for I := 0 to FList.Count - 1 do
    TElCNGCryptoProviderHandleInfo(FList[I]). Free ;
  FList.Clear;
  FreeAndNil(FList);
  FreeAndNil(FCS);
  inherited;
end;

{$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
[SecuritySafeCritical]
 {$endif}
function TElCNGCryptoProviderHandleManager.OpenCNGStorageProvider( var phProvider : HCRYPTPROV ;
  pszProviderName :  PWideChar ; dwFlags : DWORD): SECURITY_STATUS;
var
  Handle : NCRYPT_PROV_HANDLE;
  Info : TElCNGCryptoProviderHandleInfo;
  //Prov : {$ifndef SB_JAVA}HCRYPTPROV{$else}ULONG_PTR_Ref{$endif};
begin
  Handle :=  nil ;
  Result := NCryptOpenStorageProvider( @ Handle, pszProviderName, dwFlags);
  if Result = ERROR_SUCCESS then
  begin
    phProvider := HCRYPTPROV(Handle);
    Info := TElCNGCryptoProviderHandleInfo.Create(Handle);
    FCS.WaitToWrite();
    try
      FList.Add(Info);
    finally
      FCS.Done();
    end;
  end;
end;

function TElCNGCryptoProviderHandleManager.OpenCNGStorageProvider(var phProvider : NCRYPT_PROV_HANDLE;
  pszProviderName : PWideChar; dwFlags : DWORD): SECURITY_STATUS;
var
  Prov : HCRYPTPROV;
begin
  Result := OpenCNGStorageProvider(Prov, pszProviderName, dwFlags);
  if Result = ERROR_SUCCESS then
    phProvider := NCRYPT_PROV_HANDLE(Prov);
end;


procedure TElCNGCryptoProviderHandleManager.FreeCNGStorageProvider(hProvider : HCRYPTPROV);
var
  I : integer;
begin
  FCS.WaitToWrite();
  try
    for I := 0 to FList.Count - 1 do
      if HCRYPTPROV(TElCNGCryptoProviderHandleInfo(FList[I]).FHandle) = hProvider then
      begin
        Dec(TElCNGCryptoProviderHandleInfo(FList[I]).FRefCount);
        if TElCNGCryptoProviderHandleInfo(FList[I]).FRefCount = 0 then
        begin
          NCryptFreeObject(TElCNGCryptoProviderHandleInfo(FList[I]).FHandle);
          FList. Delete (I);
        end;
        Break;
      end;
  finally
    FCS.Done();
  end;
end;

procedure TElCNGCryptoProviderHandleManager.CNGStorageProviderAddRef(hProvider : HCRYPTPROV);
var
  I : integer;
begin
  FCS.WaitToWrite();
  try
    for I := 0 to FList.Count - 1 do
      if HCRYPTPROV(TElCNGCryptoProviderHandleInfo(FList[I]).FHandle) = hProvider then
      begin
        Inc(TElCNGCryptoProviderHandleInfo(FList[I]).FRefCount);
        Break;
      end;
  finally
    FCS.Done();
  end;
end;

 {$endif}
////////////////////////////////////////////////////////////////////////////////
// TElWin32CryptoKey class

constructor TElWin32CryptoKey.Create(CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
  FCertContext := nil;
  FHandle := 0;
  FProv := 0;
  FReleaseProv := true;
  FReleaseContainer := false;
  FCachedProv := 0;
  FCachedAESProv := 0;
  FCachedKeySpec := 0;
  {$ifdef SB_HAS_CNG}
  FCachedCNGKeyHandle :=  nil ;
  FCNGKeyHandle :=  nil ;
   {$endif}
  FSecCriticalDisposed := false;
  Reset;
end;

destructor TElWin32CryptoKey.Destroy;
begin
  Reset;
  inherited;
end;


function TElWin32CryptoKey.AcquireCertificateContext(var Prov : HCRYPTPROV;
  var CNGKeyHandle : NCRYPT_KEY_HANDLE; CheckPresenseOnly : boolean  =  false): boolean;
var
  Buffer : pointer;
  ProvInfo : PCRYPT_KEY_PROV_INFO;
  {$ifndef SB_UNICODE_VCL}
  ProvName, ContName : PAnsiChar;
  LenProvName, LenContName : integer;
   {$endif}
  Sz :  DWORD ;
  {$ifdef SB_UNICODE_VCL}
  pwszProvName, pwszContName : PWideChar;
   {$endif}
begin
  Result := false;
  if FCertContext = nil then
    Exit;
  Sz := 0;
  CertGetCertificateContextProperty(FCertContext, CERT_KEY_PROV_INFO_PROP_ID, nil, @Sz);
  GetMem(Buffer, Sz);
  try
    if CertGetCertificateContextProperty(FCertContext, CERT_KEY_PROV_INFO_PROP_ID, Buffer, @Sz) then
    begin
      ProvInfo := PCRYPT_KEY_PROV_INFO(Buffer);
      if ProvInfo.dwProvType <> 0 then // CryptoAPI "legacy" key
      begin
        {$ifndef SB_UNICODE_VCL}
        if Length(FUserProvName) = 0 then
          LenProvName := WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszProvName{'Microsoft Enhanced Cryptographic Provider v1.0'}, -1, nil, 0, nil, nil)
        else
          LenProvName := Length(FUserProvName) + 1;
        GetMem(ProvName, LenProvName);
        if Length(FUserContName) = 0 then
          LenContName := WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszContainerName, -1, nil, 0, nil, nil)
        else
          LenContName := Length(FUserContName) + 1;
        GetMem(ContName, LenContName);
         {$endif}
        try
          {$ifndef SB_UNICODE_VCL}
          if Length(FUserProvName) = 0 then
            WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszProvName{'Microsoft Enhanced Cryptographic Provider v1.0'}, -1, ProvName, LenProvName, nil, nil)
          else
            StrPCopy(ProvName, FUserProvName);
          if Length(FUserContName) = 0 then
            WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszContainerName, -1, ContName, LenContName, nil, nil)
          else
            StrPCopy(ContName, FUserContName);
           {$endif}
          if not CheckPresenseOnly then
          begin
            {$ifndef SB_UNICODE_VCL}
            Result := CryptAcquireContext(@Prov, ContName, ProvName, ProvInfo.dwProvType, ProvInfo.dwFlags);
             {$else}
            if Length(FUserProvName) > 0 then
              pwszProvName := PWideChar(FUserProvName)
            else
              pwszProvName := ProvInfo.pwszProvName;
            if Length(FUserProvName) > 0 then
              pwszContName := PWideChar(FUserContName)
            else
              pwszContName := ProvInfo.pwszContainerName;
            Result := CryptAcquireContext(@Prov, pwszContName, pwszProvName, ProvInfo.dwProvType, ProvInfo.dwFlags);
             {$endif}
            if Result then
              SetProvPINs(Prov);
          end
          else
            Result := true;
        finally
          {$ifndef SB_UNICODE_VCL}
          FreeMem(ProvName);
          FreeMem(ContName);
           {$endif}
        end;
        FLastKeySpec := ProvInfo.dwKeySpec;
      {$ifdef SB_HAS_CNG}	
      end
      else // CNG key
      begin
        if not CheckPresenseOnly then
        begin
          if CNGCryptoProviderHandleManager().OpenCNGStorageProvider( Prov , ProvInfo.pwszProvName, 0) = ERROR_SUCCESS then
          begin
            if NCryptOpenKey(NCRYPT_PROV_HANDLE(Prov),  @ CNGKeyHandle,
              ProvInfo.pwszContainerName, 0, ProvInfo.dwFlags) = ERROR_SUCCESS then
            begin
              Result := true;
              SetProvPINs(Prov);
            end
            else
            begin
              CNGCryptoProviderHandleManager().FreeCNGStorageProvider(Prov);
              Prov := 0;
            end;
          end;
        end
        else
          Result := true;
       {$endif}  
      end;
    end;
  finally
    FreeMem(Buffer);
  end;
end;

function TElWin32CryptoKey.AcquireCertificateContextAES(var Prov : HCRYPTPROV): boolean;
var
  Buffer : pointer;
  ProvInfo : PCRYPT_KEY_PROV_INFO;
  {$ifndef SB_UNICODE_VCL}
  ProvName, ContName : PAnsiChar;
  LenProvName, LenContName : integer;
   {$endif}
  Sz :  DWORD ;
  {$ifdef SB_UNICODE_VCL}
  pwszContName : PWideChar;
   {$endif}
begin
  Result := false;
  if FCertContext = nil then
    Exit;
  Sz := 0;
  CertGetCertificateContextProperty(FCertContext, CERT_KEY_PROV_INFO_PROP_ID, nil, @Sz);
  GetMem(Buffer, Sz);
  try
    if CertGetCertificateContextProperty(FCertContext, CERT_KEY_PROV_INFO_PROP_ID, Buffer, @Sz) then
    begin
      ProvInfo := PCRYPT_KEY_PROV_INFO(Buffer);
      {$ifndef SB_UNICODE_VCL}
      if Length(FUserProvName) = 0 then
        LenProvName := WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszProvName{'Microsoft Enhanced Cryptographic Provider v1.0'}, -1, nil, 0, nil, nil)
      else
        LenProvName := Length(FUserProvName) + 1;
      if Length(FUserContName) = 0 then
        LenContName := WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszContainerName, -1, nil, 0, nil, nil)
      else
        LenContName := Length(FUserContName) + 1;
      GetMem(ProvName, LenProvName);
      GetMem(ContName, LenContName);
       {$endif}
      try
        {$ifndef SB_UNICODE_VCL}
        if Length(FUserProvName) = 0 then
          WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszProvName{'Microsoft Enhanced Cryptographic Provider v1.0'}, -1, ProvName, LenProvName, nil, nil)
        else
          StrPCopy(ProvName, FUserProvName);
        if Length(FUserContName) = 0 then
          WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszContainerName, -1, ContName, LenContName, nil, nil)
        else
          StrPCopy(ContName, FUserContName);
         {$endif}
        {$ifndef SB_UNICODE_VCL}
        Result := CryptAcquireContext(@Prov, ContName, nil, PROV_RSA_AES, ProvInfo.dwFlags)
         {$else}
        if Length(FUserContName) = 0 then
          pwszContName := ProvInfo.pwszContainerName
        else
          pwszContName := PWideChar(FUserContName);
        Result := CryptAcquireContext(@Prov, pwszContName, nil, PROV_RSA_AES, ProvInfo.dwFlags)
         {$endif}
      finally
        {$ifndef SB_UNICODE_VCL}
        FreeMem(ProvName);
        FreeMem(ContName);
         {$endif}
      end;
      FLastKeySpec := ProvInfo.dwKeySpec;
      if Result then
        SetProvPINs(Prov);
    end;
  finally
    FreeMem(Buffer);
  end;
end;

function TElWin32CryptoKey.AcquireKeyContextAES(var Prov : HCRYPTPROV): boolean;
begin


  {$ifndef SB_UNICODE_VCL}
  Result := CryptAcquireContext(@Prov, PChar(FContName), nil, PROV_RSA_AES, 0);
   {$else ifndef SB_UNICODE_VCL}
  Result := CryptAcquireContext(@Prov, PWideChar(FContName), nil, PROV_RSA_AES, 0);
   {$endif ifndef SB_UNICODE_VCL}


  FLastKeySpec := AT_SIGNATURE;
  if Result then
    SetProvPINs(Prov);

end;

function TElWin32CryptoKey.AcquireCertificateContextPub(var Prov : HCRYPTPROV): boolean;
var
  Buffer : pointer;
  ProvInfo : PCRYPT_KEY_PROV_INFO;
  {$ifndef SB_UNICODE_VCL}
  ProvName, ContName : PAnsiChar;
  LenProvName, LenContName : integer;
   {$else}
  pwszContName, pwszProvName : PWideChar;
   {$endif}
  Sz :  DWORD ;
begin
  Result := false;
  if FCertContext = nil then
    Exit;
  Sz := 0;
  CertGetCertificateContextProperty(FCertContext, CERT_KEY_PROV_INFO_PROP_ID, nil, @Sz);
  GetMem(Buffer, Sz);
  try
    if CertGetCertificateContextProperty(FCertContext, CERT_KEY_PROV_INFO_PROP_ID, Buffer, @Sz) then
    begin
      ProvInfo := PCRYPT_KEY_PROV_INFO(Buffer);
      {$ifndef SB_UNICODE_VCL}
      if Length(FUserProvName) = 0 then
        LenProvName := WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszProvName{'Microsoft Enhanced Cryptographic Provider v1.0'}, -1, nil, 0, nil, nil)
      else
        LenProvName := Length(FUserProvName) + 1;
      if Length(FUserContName) = 0 then
        LenContName := WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszContainerName, -1, nil, 0, nil, nil)
      else
        LenContName := Length(FUserContName) + 1;
      GetMem(ProvName, LenProvName);
      GetMem(ContName, LenContName);
       {$endif}
      try
        {$ifndef SB_UNICODE_VCL}
        if Length(FUserProvName) = 0 then
          WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszProvName{'Microsoft Enhanced Cryptographic Provider v1.0'}, -1, ProvName, LenProvName, nil, nil)
        else
          StrPCopy(ProvName, FUserProvName);
        if Length(FUserContName) = 0 then
          WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszContainerName, -1, ContName, LenContName, nil, nil)
        else
          StrPCopy(ContName, FUserContName);
        Result := CryptAcquireContext(@Prov, ContName, ProvName, ProvInfo.dwProvType, 0);
         {$else}
        if Length(FUserContName) = 0 then
          pwszContName := ProvInfo.pwszContainerName
        else
          pwszContName := PWideChar(FUserContName);
        if Length(FUserProvName) = 0 then
          pwszProvName := ProvInfo.pwszProvName
        else
          pwszProvName := PWideChar(FUserProvName);
        Result := CryptAcquireContext(@Prov, pwszContName, pwszProvName, ProvInfo.dwProvType, 0);
         {$endif}
      finally
        {$ifndef SB_UNICODE_VCL}
        FreeMem(ProvName);
        FreeMem(ContName);
         {$endif}
      end;
      FLastPubKeySpec := ProvInfo.dwKeySpec;
      if Result then
        SetProvPINs(Prov);
    end;
  finally
    FreeMem(Buffer);
  end;
end;

function TElWin32CryptoKey.ObtainCertificateContext(var Prov : HCRYPTPROV;
  var KeySpec : DWORD; var CNGKeyHandle : NCRYPT_KEY_HANDLE; CheckPresenseOnly : boolean; UseCache : boolean): boolean;
begin
  CNGKeyHandle :=  nil ;
  
  if CheckPresenseOnly or (not UseCache) then
  begin
    Result := AcquireCertificateContext(Prov, CNGKeyHandle, CheckPresenseOnly);
    if Result then
      KeySpec := FLastKeySpec;
  end
  else
  begin
    if FCachedProv <> 0 then
    begin
      Prov := FCachedProv;
      KeySpec := FCachedKeySpec;
      {$ifdef SB_HAS_CNG}
      if not CachedIsCNGKey() then
       {$endif}
      begin
        // increasing the reference counter of the cached context,
        // as it will be freed by the context requesting code
        CryptContextAddRef(Prov,  nil , 0);
      end
      {$ifdef SB_HAS_CNG}
      else
      begin
        CNGKeyHandle := FCachedCNGKeyHandle;
        CNGCryptoProviderHandleManager().CNGStorageProviderAddRef(Prov);
      end
       {$endif}
	  ;
      Result := true;
    end
    else
    begin
      Result := AcquireCertificateContext(Prov, CNGKeyHandle, CheckPresenseOnly);
      if Result and (Prov <> 0) then
      begin
        KeySpec := FLastKeySpec;
        FCachedProv := Prov;
        {$ifdef SB_HAS_CNG}
        FCachedCNGKeyHandle := CNGKeyHandle;
        if not CachedIsCNGKey() then
         {$endif}
        begin
          // increasing the reference counter of the acquired context for the cached instance,
          // as it will be freed by the context requesting code
          CryptContextAddRef(Prov,  nil , 0);
        end
        {$ifdef SB_HAS_CNG}
        else
          CNGCryptoProviderHandleManager().CNGStorageProviderAddRef(Prov)
         {$endif}
		;
        // setting the provinfo's keyspec for future use
        FCachedKeySpec := FLastKeySpec;
      end;
    end;
  end;
end;

function TElWin32CryptoKey.IsContextCachingEnabled(): boolean;
begin
  if FCryptoProvider is TElWin32CryptoProvider then
    Result := TElWin32CryptoProviderOptions(TElWin32CryptoProvider(FCryptoProvider).Options).FCacheKeyContexts
  else
    Result := false;
end;

function TElWin32CryptoKey.GetIsPublic: boolean;
begin
  Result := true;
end;

function TElWin32CryptoKey.GetIsSecret: boolean;
var
  Key : HCRYPTKEY;
  Prov : HCRYPTPROV;
  CNGKeyHandle : NCRYPT_KEY_HANDLE;
  ErrCode : boolean;
begin
  if FCertContext <> nil then
  begin
    Prov := 0;
    {$ifdef SB_HAS_CNG}
    CNGKeyHandle :=  nil ;
     {$endif}
    if AcquireCertificateContext(Prov, CNGKeyHandle, true) then 
    begin
      if Prov <> 0 then
      begin
        {$ifdef SB_HAS_CNG}
        if CNGKeyHandle =  nil  then
         {$endif}
        begin
          try
            ErrCode := CryptGetUserKey(Prov, AT_SIGNATURE, @Key) or CryptGetUserKey(Prov, AT_KEYEXCHANGE, @Key);
            Result := ErrCode;
            if Result then
              CryptDestroyKey(Key);
          finally
            CryptReleaseContext(Prov, 0);
          end;
        end
        {$ifdef SB_HAS_CNG}
        else
        begin
          // considering a CNG key is secret if it has been opened correctly
          Result := true;
          NCryptFreeObject(CNGKeyHandle);
          CNGCryptoProviderHandleManager().FreeCNGStorageProvider(Prov);
        end
         {$endif}
		;
      end
      else // some crypto tokens do not provide access to certificate contexts, while the key does exist
        Result := true;
    end
    else
      Result := false;
  end
  else if (FHandle <> 0) and (Length(FContName) > 0) then
  begin
    Result := FImportedPrivateKey or FGeneratedPrivateKey;
  end
  else
    Result := false;
end;

function TElWin32CryptoKey.GetIsExportable: boolean;
begin
  if Length(FPrivateKeyBlob) > 0 then
    Result := true
  else
    Result := LoadPrivateKeyFromWin32(true);
end;

function TElWin32CryptoKey.GetIsPersistent: boolean;
begin
  Result := true;
end;

function TElWin32CryptoKey.GetIsValid: boolean;
begin
  Result := true;
end;

function TElWin32CryptoKey.GetBits : integer;
var
  Key : HCRYPTKEY;
  KeyLen, KeyLenLen : DWORD;
  Prov : HCRYPTPROV;
  CNGKeyHandle : NCRYPT_KEY_HANDLE;
  ErrCode : boolean;
  KS : DWORD;
begin
  Prov := 0;
  CNGKeyHandle :=  nil ;

  Result := 0;
  KS := 0;
  if IsSymmetricKeyAlgorithm(FAlgorithm) then
  begin
    if FHandle <> 0 then
    begin
      KeyLenLen := SizeOf(DWORD);
      if CryptGetKeyParam(FHandle, KP_KEYLEN, @KeyLen, @KeyLenLen, 0) then
        Result :=  KeyLen 
      else
        Result := Length(FValue) shl 3;
    end
    else
      Result := Length(FValue) shl 3;
  end
  else
  begin
    if Length(FPublicKeyBlob) > 0 then
    begin
      if FAlgorithm = SB_ALGORITHM_PK_RSA then
        Result := Length(FRSAM) shl 3
      else if FAlgorithm = SB_ALGORITHM_PK_DSA then
        Result := Length(FDSAP) shl 3
    end
    else if (Length(FContName) > 0) and (FHandle <> 0) then
    begin
      KeyLenLen := SizeOf(DWORD);
      CryptGetKeyParam(FHandle, KP_KEYLEN, @KeyLen, @KeyLenLen, 0);
      Result :=  KeyLen ;
    end
    //else if AcquireCertificateContext(Prov) then 
    else 
    if ObtainCertificateContext(Prov, KS, CNGKeyHandle, false, IsContextCachingEnabled()) then 
    begin
      {$ifdef SB_HAS_CNG}
      if CNGKeyHandle =  nil  then
       {$endif}
      begin
        try
          ErrCode := CryptGetUserKey(Prov, AT_SIGNATURE, @Key) or CryptGetUserKey(Prov, AT_KEYEXCHANGE, @Key);
          if ErrCode then
          begin
            KeyLenLen := SizeOf(DWORD);
            CryptGetKeyParam(Key, KP_KEYLEN, @KeyLen, @KeyLenLen, 0);
            Result :=  KeyLen ;
            CryptDestroyKey(Key);
          end;
        finally
          if Prov <> 0 then
            CryptReleaseContext(Prov, 0);
        end;
      end
      {$ifdef SB_HAS_CNG}
      else
      begin
        KeyLenLen := SizeOf(DWORD);
        if NCryptGetProperty(CNGKeyHandle,  PWideChar (NCRYPT_LENGTH_PROPERTY),
           @  KeyLen , KeyLenLen,  @ KeyLenLen, 0) = ERROR_SUCCESS then
        begin
          Result :=  KeyLen ;
        end
        else
          Result := 0;
        NCryptFreeObject(CNGKeyHandle);
        CNGCryptoProviderHandleManager().FreeCNGStorageProvider(Prov);
      end
       {$endif}
      ;
    end;
  end;

end;

function TElWin32CryptoKey.GetAlgorithm : integer;
begin
  Result := FAlgorithm;
end;

function TElWin32CryptoKey.GetKeyStorage : TElCustomCryptoKeyStorage;
begin
  Result := nil;
end;

function TElWin32CryptoKey.GetMode : integer;
begin
  raise EElWin32CryptoProviderError.Create(SFeatureNotAvailable);
end;

procedure TElWin32CryptoKey.SetMode(Value : integer);
begin
  raise EElWin32CryptoProviderError.Create(SFeatureNotAvailable);
end;

function TElWin32CryptoKey.GetIV : ByteArray;
begin
  Result := FIV;
end;

procedure TElWin32CryptoKey.SetIV(const Value : ByteArray);
begin
  // TODO: CNG
  if FHandle <> 0 then
  begin
    if Length(Value) >= 8 then
      CryptSetKeyParam(FHandle, KP_IV, @Value[0], 0);
  end;
  FIV := CloneArray(Value);
end;

function TElWin32CryptoKey.GetValue : ByteArray;
begin
  Result := FValue;
end;

procedure TElWin32CryptoKey.SetValue(const Value : ByteArray);
begin
  FValue := CloneArray(Value);
end;

procedure TElWin32CryptoKey.SetProvPIN(Prov : HCRYPTPROV; PinParamConst : DWORD;
  const Value: ByteArray);
var
  lpszPin : ByteArray;
begin
  SetLength(lpszPin, Length(Value) + 1);
  SBMove(Value, 0, lpszPin, 0, Length(Value));
  lpszPin[Length(lpszPin) - 1] := 0;

  // not checking return code here to be liberal to buggy CSP's
  CryptSetProvParam(Prov, PinParamConst,
    @lpszPin[0],
    0);
end;

{$ifdef SB_HAS_CNG}
function TElWin32CryptoKey.IsCNGKey(): boolean;
begin
  // A key is either represented by a single HCRYPTPROV (CryptoAPI key)
  // or by a (NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE) pair (CNG key).
  // This method returns True if both FProv and FCNGKeyHandle are non-zero.
  // Otherwise the key is considered to be a generic CryptoAPI key.
  Result := (FProv <> 0) and (FCNGKeyHandle <>  nil );
end;

function TElWin32CryptoKey.CachedIsCNGKey(): boolean;
begin
  // see comment in IsCNGKey()
  Result := (FCachedProv <> 0) and (FCachedCNGKeyHandle <>  nil );
end;
 {$endif SB_HAS_CNG}

procedure TElWin32CryptoKey.SetProvPINs(Prov : HCRYPTPROV);
begin
  if Length(FKeyExchangePIN) > 0 then
    SetProvPIN(Prov, PP_KEYEXCHANGE_PIN, FKeyExchangePIN);
  if Length(FSignaturePIN) > 0 then
    SetProvPIN(Prov, PP_SIGNATURE_PIN, FSignaturePIN);
end;

procedure TElWin32CryptoKey.Reset;
begin
  if FCertContext <> nil then
  begin
    CertFreeCertificateContext(FCertContext);
    FCertContext := nil;
  end;
  if FHandle <> 0 then
  begin
    CryptDestroyKey(FHandle);
    FHandle := 0;
  end;
  if FProv <> 0 then
  begin
    if FReleaseProv then
    begin
      {$ifdef SB_HAS_CNG}
      if IsCNGKey() then
        CNGCryptoProviderHandleManager().FreeCNGStorageProvider(FProv)
      else
       {$endif}
        CryptReleaseContext(FProv, 0);
    end;
    FProv := 0;
  end;
  // this checkup must be executed AFTER any IsCNGKey() call within the method,
  // as IsCNGKey() uses the value of FCNGKeyHandle
  {$ifdef SB_HAS_CNG}
  if (FCNGKeyHandle <>  nil ) then
  begin
    NCryptFreeObject(FCNGKeyHandle);
    FCNGKeyHandle :=  nil ;
  end;
   {$endif}
  if FCachedProv <> 0 then
  begin
    {$ifdef SB_HAS_CNG}
    if CachedIsCNGKey() then
      CNGCryptoProviderHandleManager().FreeCNGStorageProvider(FCachedProv)
    else
     {$endif}
      CryptReleaseContext(FCachedProv, 0);
    FCachedProv := 0;
  end;
  {$ifdef SB_HAS_CNG}
  if (FCachedCNGKeyHandle <>  nil ) then
  begin
    NCryptFreeObject(FCachedCNGKeyHandle);
    FCachedCNGKeyHandle :=  nil ;
  end;
   {$endif}
  if FCachedAESProv <> 0 then
  begin
    CryptReleaseContext(FCachedAESProv, 0);
    FCachedAESProv := 0;
  end;
  FCachedKeySpec := 0;
  if FReleaseContainer and (Length(FContName) > 0) then
    DestroyPrivateKeyContainer();
  FContName := '';
  FUserContName := '';
  FUserProvName := '';
  SetLength(FPrivateKeyBlob, 0);
  SetLength(FPublicKeyBlob, 0);
  FRawPublicKey := false;
  FAlgorithm := SB_ALGORITHM_UNKNOWN;
  FCertContext := nil;
  FHandle := 0;
  FProv := 0;
  FImportedPrivateKey := false;
  FGeneratedPrivateKey := false;
  FDoPersistentiate := false;
  SetLength(FKeyExchangePIN, 0);
  SetLength(FSignaturePIN, 0);
end;

procedure TElWin32CryptoKey.GenerateRSAKeyPair(Bits : integer; Params : TElCPParameters);
var
  Found : boolean;
  Success : boolean;
  Info : TElWin32ProviderInfo;
  I : integer;
  hKey : HCRYPTKEY;
  dwFlags{, Perms} : DWORD;
  Ops : TElWin32CryptoProviderOptions;
  err : integer;
  UserProvName, UserContName : string;
begin
  UserContName := FUserContName;
  UserProvName := FUserProvName;
  Reset;
  FAlgorithm := SB_ALGORITHM_PK_RSA;
  // searching for suitable cryptographic provider
  Found := false;
  Info := nil;
  for I := 0 to TElWin32CryptoProvider(FCryptoProvider).FProviderInfos.Count - 1 do
  begin
    Info := TElWin32ProviderInfo(TElWin32CryptoProvider(FCryptoProvider).FProviderInfos[I]);
    if TElWin32CryptoProviderOptions(FCryptoProvider.Options).FFIPSMode and (not Info.FFIPSCompliant) then
      Continue;
    if Info.IsAlgorithmSupported(SB_ALGORITHM_PK_RSA, 0, SB_OPTYPE_NONE,
      TElWin32CryptoProviderOptions(FCryptoProvider.Options).FFIPSMode) then
    begin
      Found := true;
      Break;
    end;
  end;
  if not Found then
    raise EElWin32CryptoProviderError.CreateFmt(SUnsupportedAlgorithmInt, [(SB_ALGORITHM_PK_RSA)]);
  Info := SubstituteRSAProviderIfNeeded(Info, Bits);
  // We create a separate container for each keypair
  if Length(UserProvName) = 0 then
    UserProvName := Info.FProviderName;
  CreatePrivateKeyContainer(Info.FProviderType, UserProvName{Info.FProviderName}{''}, UserContName);
  Success := false;
  try
    dwFlags := (Bits and $ffff) shl 16;
    Ops := TElWin32CryptoProviderOptions(FCryptoProvider.Options);
    //if Ops.FGenerateExportablePrivateKeys then
    //  dwFlags := dwFlags or CRYPT_EXPORTABLE;
      dwFlags := dwFlags or CRYPT_EXPORTABLE;
    hKey := 0;
    Success := CryptGenKey(FProv, CALG_RSA_SIGN, dwFlags,  @ hKey) ;
    if not Success then
    begin
      err := GetLastError;
      raise EElWin32CryptoProviderError.CreateFmt(SWin32Error, [(err)]);
    end;
    // exporting the generated key
    LoadPrivateKeyFromKey(FProv, hKey, false);
    // importing key back
    FReleaseProv := false;
    FReleaseContainer := false;
    ImportRSAPrivateKey(@FPrivateKeyBlob[0], Length(FPrivateKeyBlob), true,
      false, Ops.FGenerateExportablePrivateKeys);
    //FHandle := hKey;
    //FReleaseProv := true;
    // refreshing key values
    FGeneratedPrivateKey := true;
    FRawPublicKey := true;
    if Ops.FGenerateExportablePrivateKeys then
      LoadPrivateKeyFromKey(FProv, FHandle, false);
    LoadPublicKeyFromKey(FProv, FHandle);
    RefreshPublicKeyValues();
    Success := true;
  finally
    if not Success then
      DestroyPrivateKeyContainer();
  end;
end;

procedure TElWin32CryptoKey.Generate(Bits : integer;
  Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil);
var
  Alg : integer;
begin
  if IsSymmetricKeyAlgorithm(FAlgorithm) then
  begin
    Alg := FAlgorithm;
    Reset;
    FAlgorithm := Alg;
    SetLength(FValue, Bits shr 3);
    SBRndGenerate(@FValue[0], Length(FValue));
  end
  else if FAlgorithm = SB_ALGORITHM_PK_RSA then
  begin
    GenerateRSAKeyPair(Bits, Params);
  end
  else
    raise EElWin32CryptoProviderError.Create(SFeatureNotAvailable);
end;

procedure TElWin32CryptoKey.ChangeAlgorithm(Algorithm : integer);
begin
  raise EElWin32CryptoProviderError.Create(SFeatureNotAvailable);
end;

function TElWin32CryptoKey.SubstituteRSAProviderIfNeeded(Info : TElWin32ProviderInfo; KeyBits : integer): TElWin32ProviderInfo;
var
  VerInfo : OSVERSIONINFO;
  SubstNeeded : boolean;
  I : integer;
  SubstInfo : TElWin32ProviderInfo;
  OSVer : cardinal;
begin
  Result := Info;
  if (KeyBits > 1024) and ((TElWin32CryptoProviderOptions(FCryptoProvider.Options).FForceEnhancedCSPForLongKeys) or
    (TElWin32CryptoProviderOptions(FCryptoProvider.Options).FAutoSelectEnhancedCSP)) and
    (TElWin32CryptoProviderOptions(FCryptoProvider.Options).FUseEnhancedCSP) then
  begin
    if (Info.FProviderType = PROV_RSA_FULL) and (Info.FProviderName = MS_DEF_PROV) then
    begin
      SubstNeeded := false;
      if TElWin32CryptoProviderOptions(FCryptoProvider.Options).FAutoSelectEnhancedCSP then
      begin
        {$ifndef SB_WINRT}
        ZeroMemory(@VerInfo, SizeOf(OSVERSIONINFO));
        VerInfo.dwOSVersionInfoSize := SizeOf(OSVERSIONINFO);
        if GetVersionEx(VerInfo) then
          OSVer := VerInfo.dwMajorVersion
        else
          OSVer := 0;
        if OSVer >= 6 then // Vista, Server 2008, Windows 7
          SubstNeeded := true;
         {$else}
        SubstNeeded := false;
         {$endif}
      end
      else if TElWin32CryptoProviderOptions(FCryptoProvider.Options).FForceEnhancedCSPForLongKeys then
        SubstNeeded := true;
      if SubstNeeded then
      begin
        for I := 0 to TElWin32CryptoProvider(FCryptoProvider).FProviderInfos.Count - 1 do
        begin
          SubstInfo := TElWin32ProviderInfo(TElWin32CryptoProvider(FCryptoProvider).FProviderInfos[I]);
          if (SubstInfo.FProviderType = PROV_RSA_FULL) and (SubstInfo.FProviderName = MS_ENHANCED_PROV) then
          begin
            Result := SubstInfo;
            Break;
          end;
        end;
      end;
    end;
  end;
end;

procedure TElWin32CryptoKey.ImportPublic(Buffer: pointer; Size: integer; Params : TElCPParameters = nil);
begin
  SetLength(FPublicKeyBlob, Size);
  SBMove(Buffer^, FPublicKeyBlob[0], Length(FPublicKeyBlob));
  if (FHandle <> 0) then
  begin
    CryptDestroyKey(FHandle);
    FHandle := 0;
  end;
  if (FProv <> 0) and (FReleaseProv) then
  begin
    CryptReleaseContext(FProv, 0);
  end;
  FProv := 0;
  if FReleaseContainer and (Length(FContName) > 0) then
    DestroyPrivateKeyContainer;
  FImportedPrivateKey := false;
  FGeneratedPrivateKey := false;
  if FAlgorithm = SB_ALGORITHM_PK_RSA then
    ImportRSAPublicKey(Buffer, Size);
  RefreshPublicKeyValues();
end;

procedure TElWin32CryptoKey.ImportSecret(Buffer: pointer; Size: integer; Params : TElCPParameters = nil);
var
  Alg : integer;
  LKey, LIV : ByteArray;
begin

  
  if IsSymmetricKeyAlgorithm(FAlgorithm) then
  begin
    InternalImportPublic(Buffer, Size, Alg, LKey, LIV);
    FAlgorithm := Alg;
    SetValue(LKey);
    SetIV(LIV);
  end
  else
  begin
    SetLength(FPrivateKeyBlob, Size);
    SBMove(Buffer^, FPrivateKeyBlob[0], Length(FPrivateKeyBlob));
    if (FHandle <> 0) then
    begin
      CryptDestroyKey(FHandle);
      FHandle := 0;
    end;
    if (FProv <> 0) and (FReleaseProv) then
    begin
      CryptReleaseContext(FProv, 0);
    end;
    FProv := 0;
    if FReleaseContainer and (Length(FContName) > 0) then
      DestroyPrivateKeyContainer;
    if FAlgorithm = SB_ALGORITHM_PK_RSA then
      ImportRSAPrivateKey(Buffer, Size)
    else if FAlgorithm = SB_ALGORITHM_PK_DSA then
      ImportDSAPrivateKey(Buffer, Size);
    FImportedPrivateKey := true;
  end;

end;

procedure TElWin32CryptoKey.ImportRSAPrivateKey(Buffer: pointer; Size: integer;
  IntoCurrentContainer: boolean  =  false;
  Prot : boolean  =  false;
  Exportable : boolean  =  false);
var
  M, E, D, P, Q, DP, DQ, U : ByteArray;
  MSize, ESize, DSize, PSize, QSize, DPSize, DQSize, USize : integer;
  I : integer;
  Info : TElWin32ProviderInfo;
  Found : boolean;
  BlobSize : integer;
  BlobBuf : ByteArray;
  Key : HCRYPTKEY;
  err : integer;
  BC : integer;
  Flags : DWORD;
begin

  // checking if the key is correct
  MSize := 0;
  SBRSA.DecodePrivateKey(Buffer, Size, nil, MSize, nil, ESize, nil, DSize,
    nil, PSize, nil, QSize, nil, DPSize, nil, DQSize, nil, USize);
  SetLength(M, MSize);
  SetLength(E, ESize);
  SetLength(D, DSize);
  SetLength(P, PSize);
  SetLength(Q, QSize);
  SetLength(DP, DPSize);
  SetLength(DQ, DQSize);
  SetLength(U, USize);
  if not SBRSA.DecodePrivateKey(Buffer, Size, @M[0], MSize, @E[0], ESize, @D[0], DSize,
    @P[0], PSize, @Q[0], QSize, @DP[0], DPSize, @DQ[0], DQSize, @U[0], USize) then
    raise EElWin32CryptoProviderError.Create(SInvalidKeyFormat);
  SetLength(M, MSize);
  SetLength(E, ESize);
  BC := BufferBitCount( @M[0] , Length(M));
  if not IntoCurrentContainer then
  begin
    // searching for suitable cryptographic provider
    Found := false;
    Info := nil;
    for I := 0 to TElWin32CryptoProvider(FCryptoProvider).FProviderInfos.Count - 1 do
    begin
      Info := TElWin32ProviderInfo(TElWin32CryptoProvider(FCryptoProvider).FProviderInfos[I]);
      if TElWin32CryptoProviderOptions(FCryptoProvider.Options).FFIPSMode and (not Info.FFIPSCompliant) then
        Continue;
      if Info.IsAlgorithmSupported(SB_ALGORITHM_PK_RSA, 0, SB_OPTYPE_NONE,
        TElWin32CryptoProviderOptions(FCryptoProvider.Options).FFIPSMode) then
      begin
        Found := true;
        Break;
      end;
    end;
    if not Found then
      raise EElWin32CryptoProviderError.CreateFmt(SUnsupportedAlgorithmInt, [(SB_ALGORITHM_PK_RSA)]);
    Info := SubstituteRSAProviderIfNeeded(Info, BC);
    // We create a separate container for each keypair
    CreatePrivateKeyContainer(Info.FProviderType, Info.FProviderName);
  end;
  // forming key blob
  BlobSize := 0;
  SBMSKeyBlob.WriteMSKeyBlob(Buffer, Size, nil, BlobSize, SB_KEY_BLOB_RSA);
  SetLength(BlobBuf, BlobSize);
  if not SBMSKeyBlob.WriteMSKeyBlob(Buffer, Size, @BlobBuf[0], BlobSize, SB_KEY_BLOB_RSA) then
    raise EElWin32CryptoProviderError.Create(SInvalidKeyFormat);
  SetLength(BlobBuf, BlobSize);
  // importing the key
  Flags := 0;
  if Exportable then
    Flags := Flags or CRYPT_EXPORTABLE;
  if Prot then
    Flags := Flags or CRYPT_USER_PROTECTED;
  if not CryptImportKey(FProv, @BlobBuf[0], Length(BlobBuf), 0,
    Flags, @Key) then
  begin
    err := GetLastError;
    raise EElWin32CryptoProviderError.CreateFmt(SWin32Error, [(err)]);
  end;
  FHandle := Key;
  if not IntoCurrentContainer then // do not change the flag for existing container
    FReleaseProv := true;
  FRSAM := CloneArray(M);
  FRSAE := CloneArray(E);

end;

procedure TElWin32CryptoKey.ImportDSAPrivateKey(Buffer: pointer; Size: integer);
var
  P, Q, G, Y, X : ByteArray;
  PSize, QSize, GSize, YSize, XSize : integer;
  I : integer;
  Info : TElWin32ProviderInfo;
  Found : boolean;
  BlobSize : integer;
  BlobBuf : ByteArray;
  Key : HCRYPTKEY;
  err : integer;
begin

  // checking if the key is correct
  PSize := 0;
  SBDSA.DecodePrivateKey(Buffer, Size, nil, PSize, nil, QSize, nil, GSize,
    nil, YSize, nil, XSize);
  SetLength(P, PSize);
  SetLength(Q, QSize);
  SetLength(G, GSize);
  SetLength(Y, YSize);
  SetLength(X, XSize);
  if not SBDSA.DecodePrivateKey(Buffer, Size, @P[0], PSize, @Q[0], QSize, @G[0], GSize,
    @Y[0], YSize, @X[0], XSize) then
    raise EElWin32CryptoProviderError.Create(SInvalidKeyFormat);
  SetLength(P, PSize);
  SetLength(Q, QSize);
  SetLength(G, GSize);
  SetLength(Y, YSize);
  SetLength(X, XSize);
  // searching for suitable cryptographic provider
  Found := false;
  Info := nil;
  for I := 0 to TElWin32CryptoProvider(FCryptoProvider).FProviderInfos.Count - 1 do
  begin
    Info := TElWin32ProviderInfo(TElWin32CryptoProvider(FCryptoProvider).FProviderInfos[I]);
    if TElWin32CryptoProviderOptions(FCryptoProvider.Options).FFIPSMode and (not Info.FFIPSCompliant) then
      Continue; 
    if Info.IsAlgorithmSupported(SB_ALGORITHM_PK_DSA, 0, SB_OPTYPE_NONE,
      TElWin32CryptoProviderOptions(FCryptoProvider.Options).FFIPSMode) then
    begin
      Found := true;
      Break;
    end;
  end;
  if not Found then
    raise EElWin32CryptoProviderError.CreateFmt(SUnsupportedAlgorithmInt, [(SB_ALGORITHM_PK_DSA)]);
  // We create a separate container for each keypair
  CreatePrivateKeyContainer(Info.FProviderType, Info.FProviderName);
  // forming key blob
  BlobSize := 0;
  SBMSKeyBlob.WriteMSKeyBlob(Buffer, Size, nil, BlobSize, SB_KEY_BLOB_DSS);
  SetLength(BlobBuf, BlobSize);
  if not SBMSKeyBlob.WriteMSKeyBlob(Buffer, Size, @BlobBuf[0], BlobSize, SB_KEY_BLOB_DSS) then
    raise EElWin32CryptoProviderError.Create(SInvalidKeyFormat);
  SetLength(BlobBuf, Size);
  // importing the key
  if not CryptImportKey(FProv, @BlobBuf[0], Length(BlobBuf), 0,
    0, @Key) then
  begin
    err := GetLastError;
    raise EElWin32CryptoProviderError.CreateFmt(SWin32Error, [(err)]);
  end;
  FHandle := Key;
  FReleaseProv := true;
  // forming DSA public values
  FDSAP := CloneArray(P);
  FDSAQ := CloneArray(Q);
  FDSAG := CloneArray(G);
  FDSAY := CloneArray(Y);

end;

procedure TElWin32CryptoKey.ImportRSAPublicKey(Buffer: pointer; Size: integer);
var
  M, E : ByteArray;
  MSize, ESize : integer;
  I : integer;
  Info : TElWin32ProviderInfo;
  Found : boolean;
  BlobSize : integer;
  BlobBuf : ByteArray;
  Key : HCRYPTKEY;
  err : integer;
  AlgID : ByteArray;
  CanonicalKeyBlob : ByteArray;
  BC : integer;
  UserProvName : string;
begin

  // checking if the key is correct
  MSize := 0;
  ESize := 0;
  SBRSA.DecodePublicKey(Buffer, Size, nil, MSize, nil, ESize, AlgID, true);
  SetLength(M, MSize);
  SetLength(E, ESize);
  if not SBRSA.DecodePublicKey(Buffer, Size, @M[0], MSize, @E[0], ESize, AlgID, true) then
  begin
    MSize := 0;
    ESize := 0;
    SBRSA.DecodePublicKey(Buffer, Size, nil, MSize, nil, ESize, AlgID, false);
    SetLength(M, MSize);
    SetLength(E, ESize);
    if not SBRSA.DecodePublicKey(Buffer, Size, @M[0], MSize, @E[0], ESize, AlgID, false) then
      raise EElWin32CryptoProviderError.Create(SInvalidKeyFormat);
    SetLength(M, MSize);
    SetLength(E, ESize);
    // converting key blob to canonical form, accepted by SBMSKeyBlob
    BlobSize := 0;
    SBRSA.EncodePublicKey(@M[0], MSize, @E[0], ESize, EmptyArray, nil, BlobSize, true);
    SetLength(CanonicalKeyBlob, BlobSize);
    SBRSA.EncodePublicKey(@M[0], MSize, @E[0], ESize, EmptyArray, @CanonicalKeyBlob[0], BlobSize, true);
    SetLength(CanonicalKeyBlob, BlobSize);
  end
  else
    CanonicalKeyBlob := CloneArray(Buffer, Size);
  SetLength(M, MSize);
  SetLength(E, ESize);
  BC := BufferBitCount( @M[0] , Length(M));
  // searching for suitable cryptographic provider
  Found := false;
  Info := nil;
  for I := 0 to TElWin32CryptoProvider(FCryptoProvider).FProviderInfos.Count - 1 do
  begin
    Info := TElWin32ProviderInfo(TElWin32CryptoProvider(FCryptoProvider).FProviderInfos[I]);
    if TElWin32CryptoProviderOptions(FCryptoProvider.Options).FFIPSMode and (not Info.FFIPSCompliant) then
      Continue;
    if Info.IsAlgorithmSupported(SB_ALGORITHM_PK_RSA, 0, SB_OPTYPE_NONE,
      TElWin32CryptoProviderOptions(FCryptoProvider.Options).FFIPSMode) then
    begin
      Found := true;
      Break;
    end;
  end;
  if not Found then
    raise EElWin32CryptoProviderError.CreateFmt(SUnsupportedAlgorithmInt, [(SB_ALGORITHM_PK_RSA)]);
  Info := SubstituteRSAProviderIfNeeded(Info, BC);
  // forming key blob
  BlobSize := 0;
  SBMSKeyBlob.WriteMSPublicKeyBlob(@CanonicalKeyBlob[0], Length(CanonicalKeyBlob),
    nil, BlobSize, SB_KEY_BLOB_RSA);
  SetLength(BlobBuf, BlobSize);
  if not SBMSKeyBlob.WriteMSPublicKeyBlob(@CanonicalKeyBlob[0], Length(CanonicalKeyBlob),
    @BlobBuf[0], BlobSize, SB_KEY_BLOB_RSA) then
    raise EElWin32CryptoProviderError.Create(SInvalidKeyFormat);
  SetLength(BlobBuf, BlobSize);
  // We create a separate container for each keypair
  if Length(FUserProvName) > 0 then
    UserProvName := FUserProvName
  else
    UserProvName := Info.FProviderName;
  CreatePrivateKeyContainer(Info.FProviderType, UserProvName{Info.FProviderName}, FUserContName,
    TElWin32CryptoProviderOptions(FCryptoProvider.Options).FStorePublicKeysInMemoryContainers);
  // importing the key
  if not CryptImportKey(FProv, @BlobBuf[0], Length(BlobBuf), 0,
    0, @Key) then
  begin
    err := GetLastError;
    raise EElWin32CryptoProviderError.CreateFmt(SWin32Error, [(err)]);
  end;
  FHandle := Key;
  FReleaseProv := true;
  FRSAM := CloneArray(M);
  FRSAE := CloneArray(E);

end;

procedure TElWin32CryptoKey.UpdateDSAPublicKey();
var
  Found : boolean;
  Info : TElWin32ProviderInfo;
  I : integer;
  BlobSize : integer;
  BlobBuf : ByteArray;
  Key : HCRYPTKEY;
  err : Integer;
  UserProvName : string;
begin
  

  if (Length(FDSAP) > 0) and (Length(FDSAQ) > 0) and (Length(FDSAG) > 0) and (Length(FDSAY) > 0) then
  begin
    if (FHandle <> 0) then
    begin
      CryptDestroyKey(FHandle);
      FHandle := 0;
    end;
    if (FProv <> 0) and (FReleaseProv) then
    begin
      CryptReleaseContext(FProv, 0);
    end;
    FProv := 0;
    if FReleaseContainer and (Length(FContName) > 0) then
      DestroyPrivateKeyContainer;
    // searching for suitable cryptographic provider
    Found := false;
    Info := nil;
    for I := 0 to TElWin32CryptoProvider(FCryptoProvider).FProviderInfos.Count - 1 do
    begin
      Info := TElWin32ProviderInfo(TElWin32CryptoProvider(FCryptoProvider).FProviderInfos[I]);
      if TElWin32CryptoProviderOptions(FCryptoProvider.Options).FFIPSMode and (not Info.FFIPSCompliant) then
        Continue;
      if Info.IsAlgorithmSupported(SB_ALGORITHM_PK_DSA, 0, SB_OPTYPE_NONE,
        TElWin32CryptoProviderOptions(FCryptoProvider.Options).FFIPSMode) then
      begin
        Found := true;
        Break;
      end;
    end;
    if not Found then
      raise EElWin32CryptoProviderError.CreateFmt(SUnsupportedAlgorithmInt, [(SB_ALGORITHM_PK_RSA)]);
    // forming key blob
    BlobSize := 0;
    SBMSKeyBlob.WriteMSDSSPublicKeyBlob(@FDSAP[0], Length(FDSAP), @FDSAQ[0],
      Length(FDSAQ), @FDSAG[0], Length(FDSAG), @FDSAY[0], Length(FDSAY),
      nil, BlobSize);
    SetLength(BlobBuf, BlobSize);
    if not SBMSKeyBlob.WriteMSDSSPublicKeyBlob(@FDSAP[0], Length(FDSAP), @FDSAQ[0],
      Length(FDSAQ), @FDSAG[0], Length(FDSAG), @FDSAY[0], Length(FDSAY),
      @BlobBuf[0], BlobSize) then
      raise EElWin32CryptoProviderError.Create(SInvalidKeyFormat);
    SetLength(BlobBuf, BlobSize);
    // We create a separate container for each keypair
    if Length(FUserProvName) > 0 then
      UserProvName := FUserProvName
    else
      UserProvName := Info.FProviderName;
    CreatePrivateKeyContainer(Info.FProviderType, UserProvName{Info.FProviderName}, FUserContName,
      TElWin32CryptoProviderOptions(FCryptoProvider.Options).FStorePublicKeysInMemoryContainers);
    // importing the key
    if not CryptImportKey(FProv, @BlobBuf[0], Length(BlobBuf), 0,
      0, @Key) then
    begin
      err := GetLastError;
      raise EElWin32CryptoProviderError.CreateFmt(SWin32Error, [(err)]);
    end;
    FHandle := Key;
    FReleaseProv := true;
    FImportedPrivateKey := false;
    FGeneratedPrivateKey := false;
  end;

end;


procedure TElWin32CryptoKey.ExportPublic(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil);
begin
  if IsSymmetricKeyAlgorithm(FAlgorithm) then
  begin
    InternalExportPublic(FAlgorithm, FValue, FIV, Buffer, Size);
  end
  else
  begin
    if (Size = 0) or (Buffer = nil) then
      Size := Length(FPublicKeyBlob)
    else
    begin
      if Size >= Length(FPublicKeyBlob) then
      begin
        Size := Length(FPublicKeyBlob);
        SBMove(FPublicKeyBlob[0], Buffer^, Size);
      end
      else
        raise EElWin32CryptoProviderError.Create(SBufferTooSmall);
    end;
  end;
end;

procedure TElWin32CryptoKey.ExportSecret(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil);
begin
  if IsExportable then
  begin
    if Length(FPrivateKeyBlob) = 0 then
      LoadPrivateKeyFromWin32();
    if (Size = 0) or (Buffer = nil) then
      Size := Length(FPrivateKeyBlob)
    else
    begin
      if Size >= Length(FPrivateKeyBlob) then
      begin
        Size := Length(FPrivateKeyBlob);
        SBMove(FPrivateKeyBlob[0], Buffer^, Size);
      end
      else
        raise EElWin32CryptoProviderError.Create(SBufferTooSmall);
    end;
  end
  else
    Size := 0;
end;

function TElWin32CryptoKey.Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoKey;
var
  Ctx :   PCCERT_CONTEXT  ;
  Key : TElWin32CryptoKey;
  hKey : HCRYPTKEY;
begin
  Result := CryptoProvider.CreateKey(FAlgorithm, 0, Params);
  Key := TElWin32CryptoKey(Result);
  Key.FPrivateKeyBlob := CloneArray(FPrivateKeyBlob);
  Key.FPublicKeyBlob := CloneArray(FPublicKeyBlob);
  Key.FRawPublicKey := FRawPublicKey;
  Key.FRSAM := CloneArray(FRSAM);
  Key.FRSAE := CloneArray(FRSAE);
  Key.FDSAP := CloneArray(FDSAP);
  Key.FDSAQ := CloneArray(FDSAQ);
  Key.FDSAG := CloneArray(FDSAG);
  Key.FDSAY := CloneArray(FDSAY);
  if FCertContext <> nil then
  begin
    Ctx := CertDuplicateCertificateContext(FCertContext);
    Result.SetKeyProp(SB_KEYPROP_WIN32_CERTCONTEXT, GetBufferFromPointer(Ctx));
  end;
  if FHandle <> 0 then
  begin
    CryptDuplicateKey(FHandle,  nil , 0, hKey);
    Key.FHandle := hKey;
  end;
  if FProv <> 0 then
  begin
    Key.FProv := FProv;
    Key.FReleaseProv := FReleaseProv;
    {$ifdef SB_HAS_CNG}
    Key.FCNGKeyHandle := FCNGKeyHandle;
     {$endif}
    if FReleaseProv then
    begin
      // duplicating context for the new key object
      {$ifdef SB_HAS_CNG}
      if IsCNGKey() then
      begin
        CNGCryptoProviderHandleManager().CNGStorageProviderAddRef(FProv);
        Key.FCNGKeyHandle := DuplicateCNGKeyHandle(FCNGKeyHandle);
        if (Key.FCNGKeyHandle =  nil ) then
          raise EElWin32CryptoProviderError.Create(SFailedToCloneCNGKey);
      end
      else
       {$endif}
        CryptContextAddRef(FProv,  nil , 0);
    end;
  end;
  if FCachedProv <> 0 then
  begin
    {$ifdef SB_HAS_CNG}  
    if Key.IsCNGKey() then
    begin
      Key.FCachedProv := FCachedProv;
      CNGCryptoProviderHandleManager().CNGStorageProviderAddRef(FCachedProv);
    end
    else
     {$endif}
    begin
      Key.FCachedProv := FCachedProv;
      CryptContextAddRef(FCachedProv,  nil , 0);
    end;

    Key.FCachedKeySpec := FCachedKeySpec;
  end;
  if FCachedAESProv <> 0 then
  begin
    Key.FCachedAESProv := FCachedAESProv;
    CryptContextAddRef(FCachedAESProv,  nil , 0);
  end;
  {$ifdef SB_HAS_CNG}  
  if FCachedCNGKeyHandle <>  nil  then
  begin
    Key.FCachedCNGKeyHandle := DuplicateCNGKeyHandle(FCachedCNGKeyHandle);
    if (Key.FCachedCNGKeyHandle =  nil ) then
      raise EElWin32CryptoProviderError.Create(SFailedToCloneCNGKey);
  end;
   {$endif}
  Key.FValue := CloneArray(FValue);
  Key.FIV := CloneArray(FIV);
  Key.FProvType := FProvType;
  Key.FProvName := FProvName;
  Key.FContName := FContName;
  Key.FUserContName := FUserContName;
  Key.FUserProvName := FUserProvName;
  Key.FReleaseContainer := false;
  Key.FImportedPrivateKey := FImportedPrivateKey;
  Key.FGeneratedPrivateKey := FGeneratedPrivateKey;
  Key.FDoPersistentiate := FDoPersistentiate;
  Key.FKeyExchangePIN := CloneArray(FKeyExchangePIN);
  Key.FSignaturePIN := CloneArray(FSignaturePIN);
end;

function TElWin32CryptoKey.Equals(Source : TElCustomCryptoKey; PublicOnly : boolean;
      Params : TElCPParameters  =  nil): boolean;
var B,B1:ByteArray;
begin
  Result := false;
  if Self.Algorithm <> Source.Algorithm then exit;
  Result := true;
  if (Source.IsSecret and (not Source.IsExportable)) or
     (Self.IsSecret and (not Self.IsExportable)) then
      raise EElWin32CryptoProviderError.Create(SFailedToExportSecretKey);
  if Algorithm = SB_ALGORITHM_PK_RSA then
  begin
      Result := Result and
        (Self.GetKeyProp(SB_KEYPROP_MGF_ALGORITHM) = Source.GetKeyProp(SB_KEYPROP_MGF_ALGORITHM)) and
        (Self.GetKeyProp(SB_KEYPROP_KEYFORMAT) = Source.GetKeyProp(SB_KEYPROP_KEYFORMAT));
      B := Source.GetKeyProp(SB_KEYPROP_RSA_M);
      Result := Result and (Length(B) = Length(FRSAM)) and
           (CompareMem(@FRSAM[0], @B[0], Length(FRSAM)))
           ;
      B := Source.GetKeyProp(SB_KEYPROP_RSA_E);
      Result := Result and (Length(B) = Length(FRSAE)) and
           (CompareMem(@FRSAE[0], @B[0], Length(FRSAE)))
           ;
      B := Source.GetKeyProp(SB_KEYPROP_RSA_D);
      B1 := Self.GetKeyProp(SB_KEYPROP_RSA_D);
      Result := Result and (Length(B) = Length(B1)) and
           (CompareMem(@B1[0], @B[0], Length(B1)))
           ;
  end
  else
  if Algorithm = SB_ALGORITHM_PK_DSA then
  begin
      B := Source.GetKeyProp(SB_KEYPROP_DSA_P);
      Result := Result and (Length(B) = Length(FDSAP)) and
           (CompareMem(@FDSAP[0], @B[0], Length(FDSAP)))
           ;
      B := Source.GetKeyProp(SB_KEYPROP_DSA_Q);
      Result := Result and (Length(B) = Length(FDSAQ)) and
           (CompareMem(@FDSAQ[0], @B[0], Length(FDSAQ)))
           ;
      B := Source.GetKeyProp(SB_KEYPROP_DSA_G);
      Result := Result and (Length(B) = Length(FDSAG)) and
           (CompareMem(@FDSAG[0], @B[0], Length(FDSAG)))
           ;
      B := Source.GetKeyProp(SB_KEYPROP_DSA_X);
      B1 := Self.GetKeyProp(SB_KEYPROP_DSA_X);
      Result := Result and (Length(B) = Length(B1)) and
           (CompareMem(@B1[0], @B[0], Length(B1)))
           ;
      B := Source.GetKeyProp(SB_KEYPROP_DSA_Y);
      Result := Result and (Length(B) = Length(FDSAY)) and
           (CompareMem(@FDSAY[0], @B[0], Length(FDSAY)))
           ;
  end
  else
    Result := false;
end;

procedure TElWin32CryptoKey.Persistentiate;
begin
  FDoPersistentiate := true;
end;

function TElWin32CryptoKey.ClonePublic(Params : TElCPParameters  =  nil) : TElCustomCryptoKey;
begin
  Result := Clone(Params);
end;

procedure TElWin32CryptoKey.ClearPublic;
begin
  Reset;
end;

procedure TElWin32CryptoKey.ClearSecret;
begin
  if FHandle <> 0 then
  begin
    CryptDestroyKey(FHandle);
    FHandle := 0;
  end;
  SetLength(FPrivateKeyBlob, 0);
end;

function TrimParam(const Par : ByteArray) : ByteArray;
var
  Index : integer;
begin
  Index := 0;
  while (Index < Length(Par)) and (Par[Index] = 0) do
    Inc(Index);
  Result := Copy(Par, Index, Length(Par) - Index);
  if Length(Result) = 0 then
  begin
    SetLength(Result, 1);
    Result[0] := 0;
  end;
end;

function TElWin32CryptoKey.GetKeyProp(const PropID : ByteArray; const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =  nil {$endif}): ByteArray;
var
  MSize, ESize, DSize : integer;
  M, E, D : ByteArray;
begin
  if CompareContent(PropID, SB_KEYPROP_WIN32_CERTCONTEXT) then
  begin
    Result := GetBufferFromPointer(FCertContext);
  end
  else if CompareContent(PropID, SB_KEYPROP_WIN32_CONTAINERNAME) then
  begin
    if Length(FContName) > 0 then
      Result := StrToUTF8(FContName)
    else
    if Length(FUserContName) > 0 then
      Result := StrToUTF8(FUserContName)
    else
      Result := Default;
  end
  else if CompareContent(PropID, SB_KEYPROP_WIN32_PROVIDERNAME) then
  begin
    if Length(FProvName) > 0 then
      Result := StrToUTF8(FProvName)
    else
    if Length(FUserProvName) > 0 then
      Result := StrToUTF8(FUserProvName)
    else
      Result := Default;
  end
  else if CompareContent(PropID, SB_KEYPROP_WIN32_KEYEXCHANGEPIN) then
  begin
    Result := FKeyExchangePIN;
  end
  else if CompareContent(PropID, SB_KEYPROP_WIN32_SIGNATUREPIN) then
  begin
    Result := FSignaturePIN;
  end
  else if CompareContent(PropID, SB_KEYPROP_RSA_RAWKEY) then
  begin
    Result := GetBufferFromBool(FRawPublicKey);
  end
  else if CompareContent(PropID, SB_KEYPROP_RSA_M) then
  begin
    Result := CloneArray(FRSAM);
  end
  else if CompareContent(PropID, SB_KEYPROP_RSA_E) then
  begin
    Result := CloneArray(FRSAE);
  end
  else if CompareContent(PropID, SB_KEYPROP_RSA_D) then
  begin
    if IsExportable then
    begin
      MSize := 0;
      ESize := 0;
      DSize := 0;
      SBRSA.DecodePrivateKey(@FPrivateKeyBlob[0], Length(FPrivateKeyBlob),
        nil, MSize, nil, ESize, nil, DSize);

      if (MSize <= 0) or (ESize <= 0) or (DSize <= 0) then
      begin
        Result := Default;
        Exit;
      end;

      SetLength(M, MSize);
      SetLength(E, ESize);
      SetLength(D, DSize);
      SBRSA.DecodePrivateKey(@FPrivateKeyBlob[0], Length(FPrivateKeyBlob),
        @M[0], MSize, @E[0], ESize, @D[0], DSize);
      SetLength(D, DSize);
      Result := D;
    end
    else
      Result := Default;
  end
  else if CompareContent(PropID, SB_KEYPROP_DSA_P) then
  begin
    Result := CloneArray(FDSAP)
  end
  else if CompareContent(PropID, SB_KEYPROP_DSA_Q) then
  begin
    Result := CloneArray(FDSAQ)
  end
  else if CompareContent(PropID, SB_KEYPROP_DSA_G) then
  begin
    Result := CloneArray(FDSAG)
  end
  else if CompareContent(PropID, SB_KEYPROP_DSA_Y) then
  begin
    Result := CloneArray(FDSAY)
  end
  else if CompareContent(PropID, SB_KEYPROP_DSA_QBITS) then
  begin
    Result := GetBufferFromInteger(Length(FDSAQ) shl 3);
  end
  else if CompareContent(PropID, SB_KEYPROP_KEYFORMAT) then
  begin
    Result := SB_KEYPROP_RSA_KEYFORMAT_PKCS1;
  end
  else if CompareContent(PropID, SB_KEYPROP_HASH_ALGORITHM) then
  begin
    Result := SB_OID_SHA1;
  end
  else
    Result := Default;
end;

procedure TElWin32CryptoKey.SetKeyProp(const PropID : ByteArray; const Value : ByteArray);
begin
  if CompareContent(PropID, SB_KEYPROP_WIN32_CERTCONTEXT) then
  begin
    FCertContext := GetPointerFromBuffer(Value);
     ;
  end
  else if CompareContent(PropID, SB_KEYPROP_RSA_RAWKEY) then
  begin
    FRawPublicKey := GetBoolFromBuffer(Value);
  end
  else if CompareContent(PropID, SB_KEYPROP_WIN32_CONTAINERNAME) then
  begin
    FUserContName := UTF8ToStr(Value);
  end
  else if CompareContent(PropID, SB_KEYPROP_WIN32_PROVIDERNAME) then
  begin
    FUserProvName := UTF8ToStr(Value);
  end
  else if CompareContent(PropID, SB_KEYPROP_WIN32_KEYEXCHANGEPIN) then
  begin
    if not CompareContent(FKeyExchangePIN, Value) then
    begin
      FKeyExchangePIN := CloneArray(Value);
      if FProv <> 0 then
        SetProvPIN(FProv, PP_KEYEXCHANGE_PIN, Value);
      if FCachedProv <> 0 then
        SetProvPIN(FCachedProv, PP_KEYEXCHANGE_PIN, Value);
      if FCachedAESProv <> 0 then
        SetProvPIN(FCachedAESProv, PP_KEYEXCHANGE_PIN, Value);
    end;
  end
  else if CompareContent(PropID, SB_KEYPROP_WIN32_SIGNATUREPIN) then
  begin
    if not CompareContent(FSignaturePIN, Value) then
    begin
      FSignaturePIN := CloneArray(Value);
      if FProv <> 0 then
        SetProvPIN(FProv, PP_SIGNATURE_PIN, Value);
      if FCachedProv <> 0 then
        SetProvPIN(FCachedProv, PP_SIGNATURE_PIN, Value);
      if FCachedAESProv <> 0 then
        SetProvPIN(FCachedAESProv, PP_SIGNATURE_PIN, Value);
    end;
  end
  else if CompareContent(PropID, SB_KEYPROP_DSA_P) then
  begin
    FDSAP := TrimParam(CloneArray(Value));
    UpdateDSAPublicKey();
  end
  else if CompareContent(PropID, SB_KEYPROP_DSA_Q) then
  begin
    FDSAQ := TrimParam(CloneArray(Value));
    UpdateDSAPublicKey();
  end
  else if CompareContent(PropID, SB_KEYPROP_DSA_G) then
  begin
    FDSAG := TrimParam(CloneArray(Value));
    UpdateDSAPublicKey();
  end
  else if CompareContent(PropID, SB_KEYPROP_DSA_Y) then
  begin
    FDSAY := TrimParam(CloneArray(Value));
    UpdateDSAPublicKey();
  end
end;

function TElWin32CryptoKey.LoadPrivateKeyFromWin32(CheckPresenseOnly: boolean  =  false): boolean;
var
  CertStore: HCERTSTORE;
  hCert: PCCERT_CONTEXT;
begin
  Result := false;
  hCert := GetContextAndStore(CertStore);
  if hCert = nil then
    Exit;
  Result := LoadPrivateKeyFromContext(hCert, CheckPresenseOnly);
end;

function TElWin32CryptoKey.GetContextAndStore(var CertStore: HCERTSTORE): PCCERT_CONTEXT;
begin
  Result := FCertContext;
  if Result <> nil then
    CertStore := Result.hCertStore;
end;

function TElWin32CryptoKey.LoadPrivateKeyFromContext(Context: PCCERT_CONTEXT;
  CheckPresenseOnly : boolean = false): boolean;
var
  Prov: HCRYPTPROV;
  CNGKeyHandle : NCRYPT_KEY_HANDLE;
  Key: HCRYPTKEY;
  KS, AltKS : DWORD;
begin
  Result := false;
  KS := 0;
  Prov := 0;
  CNGKeyHandle :=  nil ;
  //if AcquireCertificateContext(Prov) then 
  if ObtainCertificateContext(Prov, KS, CNGKeyHandle, false, IsContextCachingEnabled()) then
  begin
    if KS = AT_SIGNATURE then
      AltKS := AT_KEYEXCHANGE
    else
      AltKS := AT_SIGNATURE;
    try
      if CryptGetUserKey(Prov, KS,  @ Key)  then
      begin
        try
          Result := LoadPrivateKeyFromKey(Prov, Key, CheckPresenseOnly);
        finally
          CryptDestroyKey(Key);
        end;
      end
      else
        if CryptGetUserKey(Prov, AltKS,  @ Key)  then
      begin
        try
          Result := LoadPrivateKeyFromKey(Prov, Key, CheckPresenseOnly);
        finally
          CryptDestroyKey(Key);
        end;
      end;
    finally
      if Prov <> 0 then
        CryptReleaseContext(Prov, 0);
    end;
  end;
end;

function TElWin32CryptoKey.LoadPrivateKeyFromKey(Prov : HCRYPTPROV; Key: HCRYPTKEY;
  CheckPresenseOnly : boolean = false): boolean;
var
  KeyLen:  DWORD ;
  KeyBuf, EncKeyBuf: Windows.PBYTE;
  LenEnc: integer;
  BT, ErrCode: integer;
  SessKey : HCRYPTKEY;
  Hash : HCRYPTHASH;
  Password : ByteArray;
  algid : ALG_ID;
begin
  SetLength(Password, 0);
  Result := true;
  KeyLen := 0;
  SetLastError(0);

  SessKey := 0;
  if (FAlgorithm = SB_ALGORITHM_PK_GOST_R3410_1994) or (FAlgorithm = SB_ALGORITHM_PK_GOST_R3410_1994) then
  begin
    CryptCreateHash(Prov, CALG_GR3411, 0, 0,  @Hash );
    Password := BytesOfString('password');
    CryptHashData(Hash, @Password[0], Length(Password), 0);
    algid := CALG_PRO_EXPORT;
    CryptSetKeyParam(SessKey, KP_ALGID, @algid, 0);
  end;

  if not (CryptExportKey(Key, SessKey, PRIVATEKEYBLOB, 0,  nil ,  @ KeyLen) ) then
  begin
    //ErrCode := GetLastError;
    result := false;
    exit;
  end;
  {$ifndef NET_CF} // in .Net CF for non-exportable private keys the KeyLen is not zero
  if CheckPresenseOnly then
  begin
    Result := KeyLen > 0;
    Exit;
  end;
   {$endif}
  GetMem(KeyBuf, KeyLen);
  try
    if CryptExportKey(Key, SessKey, PRIVATEKEYBLOB, 0, KeyBuf,  @ KeyLen)  then
    begin
      LenEnc := 0;
      ParseMSKeyBlob(KeyBuf, KeyLen, nil, LenEnc, BT);
      GetMem(EncKeyBuf, LenEnc);
      try
        ErrCode := ParseMSKeyBlob(KeyBuf, KeyLen, EncKeyBuf, LenEnc, BT);
        if ErrCode = 0 then
        begin
          SetLength(FPrivateKeyBlob, LenEnc);
          SBMove(EncKeyBuf^, FPrivateKeyBlob[0], Length(FPrivateKeyBlob));
        end
        else
          Result := false;
      finally
        FreeMem(EncKeyBuf);
      end;
    end
    else
    begin
      Result := false;
    end;
  finally
    FreeMem(KeyBuf);
  end;
end;

function TElWin32CryptoKey.LoadPublicKeyFromKey(Prov: HCRYPTPROV; Key: HCRYPTKEY): boolean;
var
  KeyLen:  DWORD ;
  KeyBuf, EncKeyBuf: Windows.PBYTE;
  LenEnc: integer;
  BT, ErrCode: integer;
  //SessKey : HCRYPTKEY;
  //Hash : HCRYPTHASH;
  Password : ByteArray;
  //algid : ALG_ID;
begin
  Password := EmptyArray;
  Result := true;
  KeyLen := 0;

  if not (CryptExportKey(Key, 0, PUBLICKEYBLOB, 0,  nil ,  @ KeyLen) ) then
  begin
    result := false;
    exit;
  end;
  GetMem(KeyBuf, KeyLen);
  try
    if CryptExportKey(Key, 0, PUBLICKEYBLOB, 0, KeyBuf,  @ KeyLen)  then
    begin
      LenEnc := 0;
      ParseMSKeyBlob(KeyBuf, KeyLen, nil, LenEnc, BT);
      GetMem(EncKeyBuf, LenEnc);
      try
        ErrCode := ParseMSKeyBlob(KeyBuf, KeyLen, EncKeyBuf, LenEnc, BT);
        if ErrCode = 0 then
        begin
          SetLength(FPublicKeyBlob, LenEnc);
          SBMove(EncKeyBuf^, FPublicKeyBlob[0], Length(FPublicKeyBlob));
        end
        else
          Result := false;
      finally
        FreeMem(EncKeyBuf);
      end;
    end
    else
    begin
      Result := false;
    end;
  finally
    FreeMem(KeyBuf);
  end;
end;

procedure TElWin32CryptoKey.RefreshPublicKeyValues();
var
  MSize, ESize : integer;
  AlgID : ByteArray;
  Tag : TElASN1ConstrainedTag;
  Succ : boolean;
begin
  if Length(FPublicKeyBlob) > 0 then
  begin
    if Algorithm = SB_ALGORITHM_PK_RSA then
    begin
      MSize := 0;
      ESize := 0;
      SBRSA.DecodePublicKey(@FPublicKeyBlob[0], Length(FPublicKeyBlob), nil,
        MSize, nil, ESize, AlgID, FRawPublicKey);

      if (MSize <= 0) or (ESize <= 0) then
      begin
        SetLength(FRSAM, 0);
        SetLength(FRSAE, 0);
        Exit;
      end;

      SetLength(FRSAM, MSize);
      SetLength(FRSAE, ESize);
      if SBRSA.DecodePublicKey(@FPublicKeyBlob[0], Length(FPublicKeyBlob), @FRSAM[0],
        MSize, @FRSAE[0], ESize, AlgID, FRawPublicKey) then
      begin
        SetLength(FRSAM, MSize);
        SetLength(FRSAE, ESize);
        TrimParams;
      end
      else
      begin
        SetLength(FRSAM, 0);
        SetLength(FRSAE, 0);
      end;
    end
    else if Algorithm = SB_ALGORITHM_PK_DSA then
    begin
      Tag := TElASN1ConstrainedTag.CreateInstance();
      try
        Succ := false;
        if Tag.LoadFromBuffer(@FPublicKeyBlob[0], Length(FPublicKeyBlob)) then
        begin
          if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_INTEGER, false)) then
          begin
            FDSAY := TElASN1SimpleTag(Tag.GetField(0)).Content;
            Succ := true;
          end;
        end;
        if not Succ then
          SetLength(FDSAY, 0);
      finally
        FreeAndNil(Tag);
      end;
    end;
  end;
end;

procedure TElWin32CryptoKey.TrimParams;
begin
  FRSAM := TrimParam(FRSAM);
  FRSAE := TrimParam(FRSAE);
  FDSAP := TrimParam(FDSAP);
  FDSAQ := TrimParam(FDSAQ);
  FDSAG := TrimParam(FDSAG);
  FDSAY := TrimParam(FDSAY);
end;

procedure TElWin32CryptoKey.PrepareForEncryption(MultiUse : boolean  =  false);
begin
  raise EElWin32CryptoProviderError.Create(SUnsupportedFeature);
end;

procedure TElWin32CryptoKey.PrepareForSigning(MultiUse : boolean  =  false);
begin
  raise EElWin32CryptoProviderError.Create(SUnsupportedFeature);
end;

procedure TElWin32CryptoKey.CancelPreparation;
begin
  ;
end;

function TElWin32CryptoKey.AsyncOperationFinished : boolean;
begin
  Result := false;
end;

procedure TElWin32CryptoKey.AcquireKeyObject(AlgInfo : TElWin32AlgorithmInfo;
  Mode : integer; Prov : HCRYPTPROV);
var
  KeyBlob : ByteArray;
  hKey : HCRYPTKEY;
  KeyLen : integer;
  ConvMode : DWORD;
  function ConvertMode(SBBMode : integer): DWORD;
  begin
    case SBBMode of
      SB_SYMENC_MODE_CBC,
      SB_SYMENC_MODE_DEFAULT:
        Result := CRYPT_MODE_CBC;
      SB_SYMENC_MODE_CFB8:
        Result := CRYPT_MODE_CFB;
      SB_SYMENC_MODE_ECB:
        Result := CRYPT_MODE_ECB;
      else
        Result := 0;
    end;
  end;
begin
  if IsSymmetricKeyAlgorithm(AlgInfo.FAlgorithm) then
  begin
    if FHandle <> 0 then
      CryptDestroyKey(FHandle);
    FHandle := 0;
    // forming key blob
    KeyLen := Length(FValue);
    SetLength(KeyBlob, 12 + KeyLen);
    KeyBlob[0] := PLAINTEXTKEYBLOB;
    KeyBlob[1] := 2; // CryptoAPI version
    KeyBlob[2] := 0; // reserved 1
    KeyBlob[3] := 0; // reserved 2
    KeyBlob[4] := AlgInfo.FWin32Algorithm and $ff;
    KeyBlob[5] := (AlgInfo.FWin32Algorithm shr 8) and $ff;
    KeyBlob[6] := (AlgInfo.FWin32Algorithm shr 16) and $ff;
    KeyBlob[7] := (AlgInfo.FWin32Algorithm shr 24) and $ff;
    KeyBlob[8] := KeyLen and $ff;
    KeyBlob[9] := (KeyLen shr 8) and $ff;
    KeyBlob[10] := (KeyLen shr 16) and $ff;
    KeyBlob[11] := (KeyLen shr 24) and $ff;
    SBMove(FValue[0], KeyBlob[12], KeyLen);
    hKey := 0;        
    if not CryptImportKey(Prov, @KeyBlob[0], Length(KeyBlob), 0, 0, @hKey) then
    begin
      KeyLen := GetLastError();
      raise EElWin32CryptoProviderError.CreateFmt(SWin32Error, [(KeyLen)]);
    end;
    // setting IV if necessary
    if (not (Mode in [SB_SYMENC_MODE_ECB, SB_SYMENC_MODE_BLOCK])) and (Length(FIV) > 0) then
    begin
      CryptSetKeyParam(hKey, KP_IV, @FIV[0], 0);
      ConvMode := ConvertMode(Mode);
      CryptSetKeyParam(hKey, KP_MODE, @ConvMode, 0);
    end
    else
    begin
      ConvMode := CRYPT_MODE_ECB;
      CryptSetKeyParam(hKey, KP_MODE, @ConvMode, 0);
    end;
    FHandle := hKey;
    FProv := Prov;
    FReleaseProv := false;
  end;
end;

procedure TElWin32CryptoKey.CreatePrivateKeyContainer(ProvType: integer;
  const ProvName: string; const ContainerName: string  =  '';
  InMemoryContainer : boolean  =  false);
var
  RndSeq : ByteArray;
  Flags : DWORD;
begin
  if (FProv <> 0) and (FReleaseProv) then
  begin
    CryptReleaseContext(FProv, 0);
  end;
  if Length(ContainerName) = 0 then
  begin
    SetLength(RndSeq, 16);
    SBRndGenerate(@RndSeq[0], Length(RndSeq));
    FContName := 'SBB' + BinaryToString(@RndSeq[0], Length(RndSeq));
  end
  else
    FContName := ContainerName;
  Flags := CRYPT_NEWKEYSET;
  if InMemoryContainer then
  begin
    Flags := Flags or CRYPT_VERIFYCONTEXT;
    FContName := '';
  end;
  if TElWin32CryptoProviderOptions(FCryptoProvider.Options).FUseLocalMachineAccount then
    Flags := Flags or CRYPT_MACHINE_KEYSET;
  if not CryptAcquireContext(@FProv, PChar(FContName), PChar(ProvName), ProvType, Flags) then
    raise EElWin32CryptoProviderError.CreateFmt(SFailedToAcquireProviderContext, [ProvType, ProvName]);
  SetProvPINs(FProv);
  FProvType := ProvType;
  FProvName := ProvName;
  FReleaseContainer := true;
  FDoPersistentiate := false;
end;

procedure TElWin32CryptoKey.DestroyPrivateKeyContainer;
var
  Fake : HCRYPTPROV;
  Modifier : DWORD;
begin
  // closing context handle
  if (FProv <> 0) and (FReleaseProv) then
  begin
    CryptReleaseContext(FProv, 0);
    FProv := 0;
  end;
  // closing cached context handle if needed
  if (FCachedProv <> 0) then
  begin
    CryptReleaseContext(FCachedProv, 0);
    FCachedProv := 0;
  end;
  if (FCachedAESProv <> 0) then
  begin
    CryptReleaseContext(FCachedAESProv, 0);
    FCachedAESProv := 0;
  end;
  FCachedKeySpec := 0;
  // deleting the context
  if TElWin32CryptoProviderOptions(FCryptoProvider.Options).UseLocalMachineAccount then
    Modifier := CRYPT_MACHINE_KEYSET
  else
    Modifier := 0;
  if Length(FContName) <> 0 then
  begin
    if not FDoPersistentiate then
    begin
      CryptAcquireContext(@Fake, PChar(FContName), PChar(FProvName), FProvType, CRYPT_DELETEKEYSET or Modifier);
    end;
    FContName := '';
    FProvName := '';
    FReleaseContainer := false;
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// TElWin32CryptoProvider class

procedure TElWin32CryptoProvider.ClearKeys();
var
  I : integer;
begin
  FLock.WaitToWrite();
  try
    for I := 0 to FKeys.Count - 1 do
      TElCustomCryptoKey(FKeys[I]). Free ;
    FKeys.Clear;
  finally
    FLock.Done();
  end;
end;

procedure TElWin32CryptoProvider.ClearContexts();
var
  I : integer;
begin
  FLock.WaitToWrite();
  try
    for I := 0 to FContexts.Count - 1 do
      TElCustomCryptoContext(FContexts[I]). Free ;
    FContexts.Clear;
  finally
    FLock.Done();
  end;
end;

procedure TElWin32CryptoProvider.Init();
begin
  {$ifdef SILVERLIGHT}
  if not SBUtils.ElevatedPermissionsAvailable then
    raise EElWin32CryptoProviderError.Create(SProviderRequiresElevatedPermissions);
   {$endif}
  FKeys := TElList.Create();
  FContexts := TElList.Create();
  FLock := TElSharedResource.Create();
  FTryEnhancedCryptoProvider := true;
  FNativeSizeCalculation := false;
  FWindowHandle := 0;
  FProviderInfos := TElList.Create();
  FLastSigningError := '';
  FLastSigningErrorCode := 0;
  RefreshProviderInfos;
end;

procedure TElWin32CryptoProvider.Deinit();
begin
  ClearKeys();
  ClearContexts();
  ClearProviderInfos();
  FreeAndNil(FKeys);
  FreeAndNil(FContexts);
  FreeAndNil(FLock);
  FreeAndNil(FProviderInfos);
end;

function TElWin32CryptoProvider.IsAlgorithmSupported(Algorithm : integer; Mode : integer) : boolean;
var
  Ops : TElWin32CryptoProviderOptions;
  I, J : integer;
  ProvInfo : TElWin32ProviderInfo;
  IsMAC, IsBaseSym : boolean;
  NoHashAlgSpecified : boolean;
begin
  // FIPS-approved algorithms: Triple-DES, AES, SHA-1, SHA-256, SHA-384, SHA-512, HMAC,
  // RSA and FIPS186-2 General Purpose random generator.
  // RSAENH supports the following non-FIPS approved algorithms: X9.31 RSA key-pair generation,
  // DES, RC4, RC2, MD2, MD4, and MD5

  Algorithm := NormalizeAlgorithmConstant(Algorithm);

  Ops := TElWin32CryptoProviderOptions(FOptions);
  if (IsSymmetricKeyAlgorithm(Algorithm) and (not Ops.FUseForSymmetricKeyOperations)) or
    ((IsHashAlgorithm(Algorithm) or IsMACAlgorithm(Algorithm)) and (not Ops.FUseForHashingOperations)) or
    ((IsPublicKeyAlgorithm(Algorithm)) and (not Ops.FUseForPublicKeyOperations)) then
  begin
    Result := false;
    Exit;
  end;
  // checking if the algorithm is supported by the system
  Result := false;
  if IsMACAlgorithm(Algorithm) then
  begin
    IsMAC := true;
    NoHashAlgSpecified := Algorithm = SB_ALGORITHM_HMAC;
    Algorithm := GetHashAlgorithmByHMACAlgorithm(Algorithm);
  end
  else
  begin
    IsMAC := false;
    NoHashAlgSpecified := false;
  end;
  if IsSymmetricKeyAlgorithm(Algorithm) and (not (Mode in [SB_SYMENC_MODE_DEFAULT, SB_SYMENC_MODE_CBC, SB_SYMENC_MODE_BLOCK])) then
    Exit;
  
  IsBaseSym := Algorithm = SB_ALGORITHM_CNT_SYMMETRIC;
  for I := 0 to FProviderInfos.Count - 1 do
  begin
    ProvInfo := TElWin32ProviderInfo(FProviderInfos[I]);
    if Ops.FFIPSMode and (not ProvInfo.FFIPSCompliant) then
      Continue;
    if IsMac and NoHashAlgSpecified then
    begin
      if ProvInfo.IsAlgorithmSupported(SB_ALGORITHM_HMAC, 0, 0, Ops.FFIPSMode) then
      begin
        Result := true;
        Break;
      end;
    end;
    for J := 0 to ProvInfo.FSupportedAlgorithms.Count - 1 do
    begin
      if (TElWin32AlgorithmInfo(ProvInfo.FSupportedAlgorithms[J]).FAlgorithm = Algorithm) and
        ((not IsMAC) or (ProvInfo.IsAlgorithmSupported(SB_ALGORITHM_HMAC, 0, 0, Ops.FFIPSMode))) and
        ((not Ops.FFIPSMode) or (TElWin32AlgorithmInfo(ProvInfo.FSupportedAlgorithms[J]).FFIPSCompliant)) then
      begin
        Result := true;
        Break;
      end;
      if IsBaseSym then
      begin
        if IsSymmetricKeyAlgorithm(TElWin32AlgorithmInfo(ProvInfo.FSupportedAlgorithms[J]).FAlgorithm) then
        begin
          Result := true;
          Break;
        end;
      end;
    end;
    if Result then
      Break;
  end;
  //Result := (Algorithm = SB_ALGORITHM_PK_RSA) or (Algorithm = SB_ALGORITHM_PK_DSA);
end;

function TElWin32CryptoProvider.IsAlgorithmSupported(const AlgOID, AlgParams : ByteArray;
  Mode : integer): boolean;
begin
  Result := IsAlgorithmSupported(GetAlgorithmByOID(AlgOID, true), Mode);
end;

function TElWin32CryptoProvider.IsOperationSupported(Operation : integer; Algorithm : integer;
  Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters): boolean;
var
  Ops : TElWin32CryptoProviderOptions;
  I : integer;
begin
  // checking if the cryptoprovider is configured to support the operation
  Ops := TElWin32CryptoProviderOptions(FOptions);
  if (IsSymmetricKeyAlgorithm(Algorithm) and (not Ops.FUseForSymmetricKeyOperations)) or
    ((IsHashAlgorithm(Algorithm) or IsMACAlgorithm(Algorithm)) and (not Ops.FUseForHashingOperations)) or
    ((IsPublicKeyAlgorithm(Algorithm)) and (not Ops.FUseForPublicKeyOperations)) or
    ((IsPublicKeyAlgorithm(Algorithm)) and (Operation in [SB_OPTYPE_ENCRYPT, SB_OPTYPE_VERIFY, SB_OPTYPE_VERIFY_DETACHED]) and (not Ops.FUseForNonPrivateOperations)) then
  begin
    Result := false;
    Exit;
  end;
  Result := false;
  for I := 0 to FProviderInfos.Count - 1 do
  begin
    if Ops.FFIPSMode and (not TElWin32ProviderInfo(FProviderInfos[I]).FFIPSCompliant) then
      Continue;
    // checking if the operation is supported by the system
    if Operation = SB_OPTYPE_KEY_CREATE then
    begin
      if TElWin32ProviderInfo(FProviderInfos[I]).IsAlgorithmSupported(Algorithm, Mode, SB_OPTYPE_NONE,
        Ops.FFIPSMode) then
      begin
        Result := true;
        Exit;
      end;
    end
    else
    begin
      if TElWin32ProviderInfo(FProviderInfos[I]).IsAlgorithmSupported(Algorithm, Mode, Operation,
        Ops.FFIPSMode) then
      begin
        Result := true;
        Break;
      end;
    end;
  end;
  Result := Result and ((Key = nil) or (Key is TElWin32CryptoKey) or (IsMACAlgorithm(Algorithm)));
  //Result :=
  //  ((Operation in [SB_OPTYPE_DECRYPT, SB_OPTYPE_SIGN_DETACHED, SB_OPTYPE_KEY_DECRYPT]) and (Key is TElWin32CryptoKey) and ((Key.IsSecret) or (TElWin32CryptoKey(Key).FHandle <> 0))) or
  //  ((Operation = SB_OPTYPE_KEY_CREATE) and ((Algorithm = SB_ALGORITHM_PK_RSA) or (Algorithm = SB_ALGORITHM_PK_DSA)));
end;

function TElWin32CryptoProvider.IsOperationSupported(Operation : integer; const AlgOID, AlgParams : ByteArray;
  Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters): boolean;
begin
  Result := IsOperationSupported(Operation, GetAlgorithmByOID(AlgOID, true), 0,
    Key, Params);
end;

function TElWin32CryptoProvider.GetAlgorithmProperty(Algorithm : integer; Mode : integer;
  const PropID : ByteArray): ByteArray;
var
  I : integer;
  Info : TElWin32AlgorithmInfo;
begin
  if IsAlgorithmSupported(Algorithm, Mode) then
  begin
    Result := EmptyArray;
    if CompareContent(PropID, SB_ALGPROP_DEFAULT_KEY_SIZE) or
      CompareContent(PropID, SB_ALGPROP_BLOCK_SIZE) or
      CompareContent(PropID, SB_ALGPROP_DIGEST_SIZE) then
    begin
      for I := 0 to FProviderInfos.Count - 1 do
      begin
        Info := TElWin32ProviderInfo(FProviderInfos[I]).GetAlgorithmInfo(Algorithm, Mode, 0, false);
        if Info <> nil then
        begin
          if CompareContent(PropID, SB_ALGPROP_DEFAULT_KEY_SIZE) then
            Result := GetBufferFromInteger(Info.FDefaultKeySize)
          else if CompareContent(PropID, SB_ALGPROP_BLOCK_SIZE) then
            Result := GetBufferFromInteger(Info.FDefaultBlockSize)
          else if CompareContent(PropID, SB_ALGPROP_DIGEST_SIZE) then
            Result := GetBufferFromInteger(Info.FBits);
          Break;
        end;
      end;
    end;
  end
  else
    Result := ReturnCryptoProviderManager.GetAlgorithmProperty(Algorithm, Mode, PropID);
end;

function TElWin32CryptoProvider.GetAlgorithmProperty(const AlgOID, AlgParams : ByteArray;
  Mode : integer; const PropID : ByteArray): ByteArray;
var
  I : integer;
  Info : TElWin32AlgorithmInfo;
  Algorithm : integer;
begin
  if IsAlgorithmSupported(AlgOID, AlgParams, Mode) then
  begin
    Result := EmptyArray;
    if CompareContent(PropID, SB_ALGPROP_DEFAULT_KEY_SIZE) or
      CompareContent(PropID, SB_ALGPROP_BLOCK_SIZE) then
    begin
      Algorithm := GetAlgorithmByOID(AlgOID);
      for I := 0 to FProviderInfos.Count - 1 do
      begin
        Info := TElWin32ProviderInfo(FProviderInfos[I]).GetAlgorithmInfo(Algorithm, Mode, 0, false);
        if Info <> nil then
        begin
          if CompareContent(PropID, SB_ALGPROP_DEFAULT_KEY_SIZE) then
            Result := GetBufferFromInteger(Info.FDefaultKeySize)
          else if CompareContent(PropID, SB_ALGPROP_BLOCK_SIZE) then
            Result := GetBufferFromInteger(Info.FDefaultBlockSize);
          Break;
        end;
      end;
    end;
  end
  else
    Result := ReturnCryptoProviderManager.GetAlgorithmProperty(AlgOID, AlgParams, Mode, PropID);
end;

function TElWin32CryptoProvider.GetAlgorithmClass(Algorithm : integer): integer;
begin
  if IsAlgorithmSupported(Algorithm, 0) then
    Result := SB_ALGCLASS_PUBLICKEY
  else
    Result := ReturnCryptoProviderManager.GetAlgorithmClass(Algorithm);
end;

function TElWin32CryptoProvider.GetAlgorithmClass(const AlgOID, AlgParams : ByteArray): integer;
begin
  if IsAlgorithmSupported(AlgOID, AlgParams, 0) then
    Result := SB_ALGCLASS_PUBLICKEY
  else
    Result := ReturnCryptoProviderManager.GetAlgorithmClass(AlgOID, AlgParams);
end;

function TElWin32CryptoProvider.CreateKey(Algorithm : integer; Mode : integer;
  Params : TElCPParameters  =  nil): TElCustomCryptoKey;
begin
  if IsAlgorithmSupported(Algorithm, Mode) then
  begin
    Result := TElWin32CryptoKey.Create(Self);
    TElWin32CryptoKey(Result).FAlgorithm := Algorithm;
    if FOptions.StoreKeys then
    begin
      FLock.WaitToWrite();
      try
        FKeys.Add(Result);
      finally
        FLock.Done();
      end;
    end;
  end
  else
    raise EElWin32CryptoProviderError.CreateFmt(SUnsupportedAlgorithmInt, [(Algorithm)]);
end;

function TElWin32CryptoProvider.CreateKey(const AlgOID : ByteArray; const AlgParams : ByteArray;
  Params : TElCPParameters  =  nil): TElCustomCryptoKey;
begin
  if IsAlgorithmSupported(AlgOID, AlgParams, 0) then
  begin
    Result := TElWin32CryptoKey.Create(Self);
    TElWin32CryptoKey(Result).FAlgorithm := GetAlgorithmByOID(AlgOID);
    if FOptions.StoreKeys then
    begin
      FLock.WaitToWrite();
      try
        FKeys.Add(Result);
      finally
        FLock.Done();
      end;
    end;
  end
  else
    raise EElWin32CryptoProviderError.CreateFmt(SUnsupportedAlgorithmStr, [(OIDToStr(AlgOID))])
end;

function TElWin32CryptoProvider.InternalCreateKey(const AlgOID : ByteArray; const AlgParams : ByteArray;
  Params : TElCPParameters  =  nil): TElCustomCryptoKey;
begin
  // This method performs does exactly the same as CreateKey does.
  // The only difference is the absense of algorithm checkup.
  // It is used internally to create an imported symmetric key object
  // (the provider does not 'officially' support algorithms other than RSA
  // and DSA, so CreateKey throws an exception if any other algorithm is used)
  Result := TElWin32CryptoKey.Create(Self);
  TElWin32CryptoKey(Result).FAlgorithm := GetAlgorithmByOID(AlgOID);
  if FOptions.StoreKeys then
  begin
    FLock.WaitToWrite();
    try
      FKeys.Add(Result);
    finally
      FLock.Done();
    end;
  end;
end;

function TElWin32CryptoProvider.CloneKey(Key : TElCustomCryptoKey) : TElCustomCryptoKey;
//var
//  Index : integer;
begin
  if not OwnsObject(Key) then
    raise EElWin32CryptoProviderError.Create(SInvalidKeyMaterial);
  (*
  FLock.WaitToRead();
  try
    Index := FKeys.IndexOf(Key);
  finally
    FLock.Done();
  end;
  if Index < 0 then
    raise EElWin32CryptoProviderError.Create(SInvalidKeyMaterial);
  *)
  Result := Key.Clone();
  if FOptions.StoreKeys then
  begin
    FLock.WaitToWrite();
    try
      // CreateKey may add the key object to the list so we have to check this
      if FKeys.IndexOf(Result) < 0 then
        FKeys.Add(Result);
    finally
      FLock.Done();
    end;
  end;
end;

procedure TElWin32CryptoProvider.ReleaseKey(var Key : TElCustomCryptoKey);
var
  Index : integer;
begin
  if OwnsObject(Key) then
  begin
    FLock.WaitToWrite();
    try
      Index := FKeys.IndexOf(Key);
      if Index >= 0 then
        FKeys. Delete (Index);
    finally
      FLock.Done();
    end;
    FreeAndNil(Key);       
  end;
end;

procedure TElWin32CryptoProvider.DeleteKey(var Key : TElCustomCryptoKey);
begin
  raise EElWin32CryptoProviderError.Create(SFeatureNotAvailable);
end;

function TElWin32CryptoProvider.DecryptKey(EncKey : pointer; EncKeySize : integer; const EncKeyAlgOID,
  EncKeyAlgParams : ByteArray; Key : TElCustomCryptoKey; const KeyAlgOID,
  KeyAlgParams : ByteArray; Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil): TElCustomCryptoKey;

  function GetWin32AlgorithmByOID(const OID : ByteArray): ByteArray;
  var
    Alg : integer;
  begin
    Alg := GetAlgorithmByOID(OID, true);
    case Alg of
      SB_ALGORITHM_PK_RSA :
        Result := CALG_RSA_KEYX_ID;
      SB_ALGORITHM_CNT_DES :
        Result := CALG_DES_ID;
      SB_ALGORITHM_CNT_3DES :
        Result := CALG_3DES_ID;
      SB_ALGORITHM_CNT_RC2 :
        Result := CALG_RC2_ID;
      SB_ALGORITHM_CNT_RC4 :
        Result := CALG_RC4_ID;
      SB_ALGORITHM_CNT_AES128 :
        Result := CALG_AES_128_ID;
      SB_ALGORITHM_CNT_AES192 :
        Result := CALG_AES_192_ID;
      SB_ALGORITHM_CNT_AES256 :
        Result := CALG_AES_256_ID;
      else
        raise EElWin32CryptoProviderError.CreateFmt(SUnsupportedAlgorithmStr, [(OIDToStr(OID))]);
    end;
  end;

var
  I : integer;
  CertContext :   PCCERT_CONTEXT  ;
  Prov: HCRYPTPROV;
  CNGKeyHandle : NCRYPT_KEY_HANDLE;
  hKey : HCRYPTKEY;
  DataLen :  cardinal ;
  WinKey, SymKey : TElWin32CryptoKey;
  Success : BOOL;
  dwKeySpec : DWORD;
  PKAlgID, SymAlgID : ByteArray;
  RotatedKey : ByteArray;
  Blob : ByteArray;
  hSymKey : HCRYPTKEY;
  AlgKeyLen : integer;
  AlgIV : ByteArray;
  Pars : TElCPParameters;
  KS : DWORD;
begin
  if not (Key is TElWin32CryptoKey) then
    raise EElWin32CryptoProviderError.Create(SUnsupportedKeyMaterial);

  WinKey := TElWin32CryptoKey(Key);
  CertContext := WinKey.FCertContext;
  if not Assigned(CertContext) then
    raise EElWin32CryptoProviderError.Create(SUnsupportedKeyMaterial);

  Success :=  false ;
  Result := nil;
  KS := 0;
  Prov := 0;
  CNGKeyHandle :=  nil ;
  //if WinKey.AcquireCertificateContext(Prov) then
  if WinKey.ObtainCertificateContext(Prov, KS, CNGKeyHandle, false, WinKey.IsContextCachingEnabled()) then
  begin
    try
      DataLen := SizeOf(DWORD);
      if not CertGetCertificateContextProperty(CertContext, CERT_KEY_SPEC_PROP_ID, @dwKeySpec, @DataLen) then
        dwKeySpec := AT_KEYEXCHANGE or AT_SIGNATURE;
      if CryptGetUserKey(Prov, dwKeySpec, @hKey) then
      begin
        try
          // forming key blob
          PKAlgID := GetWin32AlgorithmByOID(GetOIDByAlgorithm(WinKey.Algorithm));
          SymAlgID := GetWin32AlgorithmByOID(EncKeyAlgOID);
          SetLength(RotatedKey, EncKeySize);
          for I := 1 to EncKeySize do
            PByte(@RotatedKey[I])^ := PByteArray(EncKey)[EncKeySize - I];

          Blob := SBConcatMultipleArrays([
            BLOB_ID_AND_RESERVED, SymAlgID, PKAlgID, RotatedKey]);

          // importing the key
          Success := CryptImportKey(Prov, @Blob[0], Length(Blob), hKey, CRYPT_NO_SALT, @hSymKey);
          if Success =  false  then
            raise EElWin32CryptoProviderError.Create(SKeyDecryptionFailed);

          // extracting algorithm parameters (such as IV and effective key length)
          ExtractSymmetricCipherParams(EncKeyAlgOID, EncKeyAlgParams, AlgKeyLen,
            AlgIV);

          // creating TElCPParameters object and passing it to CreateKey()
          Pars := TElCPParameters.Create();
          try
            // creating symmetric key object
            if CompareContent(EncKeyAlgOID, SB_OID_RC2_CBC) then
              Pars.Add(SB_KEYPROP_EFFECTIVE_KEY_LENGTH, GetBufferFromInteger(AlgKeyLen));
            //SymKey := TElWin32CryptoKey(CreateKey(EncKeyAlgOID, EncKeyAlgParams, Pars));
            SymKey := TElWin32CryptoKey(InternalCreateKey(EncKeyAlgOID, EncKeyAlgParams, Pars));
            SymKey.FCertContext := nil;
            SymKey.FHandle := hSymKey;
            SymKey.FProv := Prov;
            SymKey.FReleaseProv := true;
            if not CompareContent(EncKeyAlgOID, SB_OID_RC4) then
              SymKey.IV := AlgIV;
          finally
            FreeAndNil(Pars);
          end;
          Result := SymKey;
        finally
          CryptDestroyKey(hKey);
        end;
      end;
    finally
      if  not Success  then
      begin
        if Prov <> 0 then
          CryptReleaseContext(Prov, 0);
      end;
    end;
  end
  else
    raise EElWin32CryptoProviderError.Create(SKeyDecryptionFailed);
end;

function TElWin32CryptoProvider.EncryptInit(Algorithm : integer; Mode : integer; Key : TElCustomCryptoKey;
  Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil) : TElCustomCryptoContext;
var
  ProvHandle : HCRYPTPROV;
  AlgInfo : TElWin32AlgorithmInfo;
  I : integer;
  //dwDataLen : DWORD;
  //R : integer;
  KeySize : integer;
begin
  if IsOperationSupported(SB_OPTYPE_ENCRYPT, Algorithm, Mode, Key, Params) then
  begin
    if not (Key is TElWin32CryptoKey) then
      raise EElWin32CryptoProviderError.Create(SUnsupportedKeyMaterial);
    // getting the provider to use
    ProvHandle := 0;
    AlgInfo := nil;
    if IsSymmetricKeyAlgorithm(Algorithm) then
      KeySize := Key.Bits
    else
      KeySize := 0;
    for I := 0 to FProviderInfos.Count - 1 do
    begin
      AlgInfo := TElWin32ProviderInfo(FProviderInfos[I]).GetAlgorithmInfo(Algorithm, Mode, SB_OPTYPE_ENCRYPT,
        TElWin32CryptoProviderOptions(Options).FFIPSMode, KeySize);
      if AlgInfo <> nil then
      begin
        ProvHandle := TElWin32ProviderInfo(FProviderInfos[I]).FProvHandle;
        Break;
      end;
    end;
    if ProvHandle = 0 then
      raise EElWin32CryptoProviderError.Create(SUnsupportedOperation);
    TElWin32CryptoKey(Key).AcquireKeyObject(AlgInfo, Mode, ProvHandle);
    Result := TElWin32CryptoContext.Create(Algorithm, Mode, Key, ccoEncrypt, Self, Params);
    if FOptions.StoreKeys then
    begin
      FLock.WaitToWrite();
      try
        FContexts.Add(Result);
      finally
        FLock.Done();
      end;
    end;
  end
  else
    raise EElWin32CryptoProviderError.Create(SUnsupportedOperation);
end;

function TElWin32CryptoProvider.EncryptInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
  Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil): TElCustomCryptoContext;
begin
  Result := EncryptInit(GetAlgorithmByOID(AlgOID, true), Mode, Key, Params,
    ProgressFunc, ProgressData);
end;

function TElWin32CryptoProvider.DecryptInit(Algorithm : integer; Mode : integer; Key : TElCustomCryptoKey;
  Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil) : TElCustomCryptoContext;
var
  ProvHandle : HCRYPTPROV;
  AlgInfo : TElWin32AlgorithmInfo;
  I : integer;
  KeySize : integer;
begin
  if IsOperationSupported(SB_OPTYPE_DECRYPT, Algorithm, Mode, Key, Params) then
  begin
    if not (Key is TElWin32CryptoKey) then
      raise EElWin32CryptoProviderError.Create(SUnsupportedKeyMaterial);
    // getting the provider to use
    ProvHandle := 0;
    AlgInfo := nil;
    if IsSymmetricKeyAlgorithm(Algorithm) then
      KeySize := Key.Bits
    else
      KeySize := 0;
    for I := 0 to FProviderInfos.Count - 1 do
    begin
      AlgInfo := TElWin32ProviderInfo(FProviderInfos[I]).GetAlgorithmInfo(Algorithm, Mode, SB_OPTYPE_ENCRYPT,
        TElWin32CryptoProviderOptions(Options).FFIPSMode, KeySize);
      if AlgInfo <> nil then
      begin
        ProvHandle := TElWin32ProviderInfo(FProviderInfos[I]).FProvHandle;
        Break;
      end;
    end;
    if ProvHandle = 0 then
      raise EElWin32CryptoProviderError.Create(SUnsupportedOperation);
    TElWin32CryptoKey(Key).AcquireKeyObject(AlgInfo, Mode, ProvHandle);
    Result := TElWin32CryptoContext.Create(Algorithm, Mode, Key, ccoDecrypt, Self, Params);
    if FOptions.StoreKeys then
    begin
      FLock.WaitToWrite();
      try
        FContexts.Add(Result);
      finally
        FLock.Done();
      end;
    end;
  end
  else
    raise EElWin32CryptoProviderError.Create(SUnsupportedOperation);
end;

function TElWin32CryptoProvider.DecryptInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
  Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil): TElCustomCryptoContext;
var
  ProvHandle : HCRYPTPROV;
  AlgInfo : TElWin32AlgorithmInfo;
  I : integer;
  KeySize : integer;
  AlgId : integer;
begin
  if IsOperationSupported(SB_OPTYPE_DECRYPT, AlgOID, AlgParams, Mode, Key, Params) then
  begin
    if not (Key is TElWin32CryptoKey) then
      raise EElWin32CryptoProviderError.Create(SUnsupportedKeyMaterial);
    // getting the provider to use
    ProvHandle := 0;
    AlgInfo := nil;
    AlgId := GetAlgorithmByOID(AlgOID);
    if IsSymmetricKeyAlgorithm(AlgId) then
      KeySize := Key.Bits
    else
      KeySize := 0;
    for I := 0 to FProviderInfos.Count - 1 do
    begin
      AlgInfo := TElWin32ProviderInfo(FProviderInfos[I]).GetAlgorithmInfo(AlgId, Mode, SB_OPTYPE_ENCRYPT,
        TElWin32CryptoProviderOptions(Options).FFIPSMode, KeySize);
      if AlgInfo <> nil then
      begin
        ProvHandle := TElWin32ProviderInfo(FProviderInfos[I]).FProvHandle;
        Break;
      end;
    end;
    if ProvHandle = 0 then
      raise EElWin32CryptoProviderError.Create(SUnsupportedOperation);
    TElWin32CryptoKey(Key).AcquireKeyObject(AlgInfo, Mode, ProvHandle);
    Result := TElWin32CryptoContext.Create(AlgOID, AlgParams, Mode, Key, ccoDecrypt, Self, Params);
    if FOptions.StoreKeys then
    begin
      FLock.WaitToWrite();
      try
        FContexts.Add(Result);
      finally
        FLock.Done();
      end;
    end;
  end
  else
    raise EElWin32CryptoProviderError.Create(SUnsupportedOperation);
end;

function TElWin32CryptoProvider.SignInit(Algorithm : integer; Key : TElCustomCryptoKey;
  Detached : boolean; Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil) : TElCustomCryptoContext;
begin
  if IsOperationSupported(SB_OPTYPE_SIGN_DETACHED, Algorithm, 0, Key, Params) then
  begin
    if not Detached then
      raise EElWin32CryptoProviderError.Create(SFeatureNotAvailable);
    Result := TElWin32CryptoContext.Create(Algorithm, 0, Key, ccoSignDetached, Self, Params);
    if FOptions.StoreKeys then
    begin
      FLock.WaitToWrite();
      try
        FContexts.Add(Result);
      finally
        FLock.Done();
      end;
    end;
  end
  else
    raise EElWin32CryptoProviderError.Create(SUnsupportedOperation);
  // TODO: check that HashAlgorithm is supported by Win32
end;

function TElWin32CryptoProvider.SignInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
  Key : TElCustomCryptoKey; Detached : boolean; Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil): TElCustomCryptoContext;
begin
  if IsOperationSupported(SB_OPTYPE_SIGN_DETACHED, AlgOID, AlgParams, 0, Key, Params) then
  begin
    if not Detached then
      raise EElWin32CryptoProviderError.Create(SFeatureNotAvailable);
    Result := TElWin32CryptoContext.Create(AlgOID, AlgParams, 0, Key, ccoSignDetached, Self, Params);
    if FOptions.StoreKeys then
    begin
      FLock.WaitToWrite();
      try
        FContexts.Add(Result);
      finally
        FLock.Done();
      end;
    end;
  end
  else
    raise EElWin32CryptoProviderError.Create(SUnsupportedOperation);
  // TODO: check that HashAlgorithm is supported by Win32
end;

function TElWin32CryptoProvider.VerifyInit(Algorithm : integer; Key : TElCustomCryptoKey;
  SigBuffer : pointer; SigSize : integer; Params : TElCPParameters = nil;
  ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil) : TElCustomCryptoContext;
var
  ProvHandle : HCRYPTPROV;
  AlgInfo : TElWin32AlgorithmInfo;
  I : integer;
begin
  if IsOperationSupported(SB_OPTYPE_VERIFY_DETACHED, Algorithm, 0, Key, Params) then
  begin
    if not (Key is TElWin32CryptoKey) then
      raise EElWin32CryptoProviderError.Create(SUnsupportedKeyMaterial);
    // getting the provider to use
    ProvHandle := 0;
    for I := 0 to FProviderInfos.Count - 1 do
    begin
      AlgInfo := TElWin32ProviderInfo(FProviderInfos[I]).GetAlgorithmInfo(Algorithm, 0,
        SB_OPTYPE_VERIFY_DETACHED, TElWin32CryptoProviderOptions(Options).FFIPSMode);
      if AlgInfo <> nil then
      begin
        ProvHandle := TElWin32ProviderInfo(FProviderInfos[I]).FProvHandle;
        Break;
      end;
    end;
    if ProvHandle = 0 then
      raise EElWin32CryptoProviderError.Create(SUnsupportedOperation);
    Result := TElWin32CryptoContext.Create(Algorithm, 0, Key, ccoVerifyDetached, Self, Params);
    TElWin32CryptoContext(Result).FSignature := CloneArray(SigBuffer, SigSize);
    if FOptions.StoreKeys then
    begin
      FLock.WaitToWrite();
      try
        FContexts.Add(Result);
      finally
        FLock.Done();
      end;
    end;
  end
  else
    raise EElWin32CryptoProviderError.Create(SUnsupportedOperation);
end;

function TElWin32CryptoProvider.VerifyInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
  Key : TElCustomCryptoKey; SigBuffer : pointer; SigSize : integer; Params : TElCPParameters = nil;
  ProgressFunc : TSBProgressFunc = nil;
  ProgressData : pointer = nil) : TElCustomCryptoContext;
begin
  Result := VerifyInit(GetAlgorithmByOID(AlgOID, true), Key, SigBuffer, SigSize,
    Params, ProgressFunc, ProgressData);
end;

procedure TElWin32CryptoProvider.EncryptUpdate(Context : TElCustomCryptoContext; InBuffer : pointer;
  InSize : integer; OutBuffer : pointer; var OutSize : integer;
  Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
  ProgressData : pointer = nil);
var
  Ctx : TElWin32CryptoContext;
  EncLen :  DWORD ;
  R : integer;
  SpoolLen, ProcLen, OldLen : integer;
begin
  if (Context is TElWin32CryptoContext) then
  begin
    Ctx := TElWin32CryptoContext(Context);
    if Ctx.FContextType = cctSymCrypto then
    begin
      // checking output size
      EncLen := InSize;
      CryptEncrypt(Ctx.FKeyHandle, 0,  false , 0,   nil  , EncLen, 0);
      if (OutBuffer = nil) or (OutSize = 0) then
      begin
        // just a size request, exiting
        OutSize := EncLen;
        // a small correction of ours: for the sake of speed, we copy the input buffer
        // to the output buffer prior to encrypting it, that's why we need to
        // have an output buffer of at least the same size as the input buffer
        // + size of the cached input data
        if OutSize < InSize + Length(Ctx.FSpool) then
          OutSize := InSize + Length(Ctx.FSpool);
        Exit;
      end;
      // doing encryption
      if Ctx.FAlgorithm <> SB_ALGORITHM_CNT_RC4 then
      begin
        SpoolLen := Length(Ctx.FSpool);
        if OutSize < InSize + SpoolLen then
          raise EElWin32CryptoProviderError.Create(SBufferTooSmall);
        if InSize + SpoolLen < Ctx.BlockSize then
        begin
          SetLength(Ctx.FSpool, InSize + SpoolLen);
          SBMove(InBuffer^, Ctx.FSpool[SpoolLen], InSize);
          OutSize := 0;
        end
        else
        begin
          ProcLen := ((SpoolLen + InSize) div Ctx.BlockSize) * Ctx.BlockSize;
          if SpoolLen > 0 then
            SBMove(Ctx.FSpool[0], OutBuffer^, SpoolLen);
          SBMove(InBuffer^, PByteArray(OutBuffer)[SpoolLen], ProcLen - SpoolLen);
          SetLength(Ctx.FSpool, InSize + SpoolLen - ProcLen);
          SBMove(PByteArray(InBuffer)[ProcLen - SpoolLen], Ctx.FSpool[0], Length(Ctx.FSpool));
          EncLen := ProcLen;
          if CryptEncrypt(Ctx.FKeyHandle, 0, false, 0, OutBuffer, EncLen, OutSize) then
            OutSize := EncLen
          else
          begin
            R := GetLastError();
            raise EElWin32CryptoProviderError.CreateFmt(SWin32Error, [(R)]);
          end;
        end;
      end
      else
      begin
        SBMove(InBuffer^, OutBuffer^, InSize);
        EncLen := InSize;
        if CryptEncrypt(Ctx.FKeyHandle, 0, false, 0, OutBuffer, EncLen, OutSize) then
          OutSize := EncLen
        else
        begin
          R := GetLastError();
          raise EElWin32CryptoProviderError.CreateFmt(SWin32Error, [(R)]);
        end;
      end;
    end
    else if Ctx.FContextType = cctPKICrypto then
    begin
      if OutBuffer <> nil then
      begin
        OldLen := Length(Ctx.FSpool);
        SetLength(Ctx.FSpool, OldLen + InSize);
        SBMove(InBuffer^, Ctx.FSpool[OldLen], InSize);
        OutSize := 0;
      end
      else
        OutSize := 1; // fake value (to prevent second user from passing 0/nil to a second call)
    end;
  end
  else
    raise EElWin32CryptoProviderError.Create(SInvalidContext);
end;

procedure TElWin32CryptoProvider.DecryptUpdate(Context : TElCustomCryptoContext; InBuffer : pointer;
  InSize : integer; OutBuffer : pointer; var OutSize : integer; Params : TElCPParameters = nil;
  ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil);
var
  OldLen : integer;
  Ctx : TElWin32CryptoContext;
  //dwDataLen : DWORD;
  //B : BOOL;
  //ReturnSize, ChunkSize : integer;
  //CurrIndex : integer;
  EncLen :  DWORD ;
  SpoolLen, ProcLen : DWORD;
  R : integer;
  OutOffset : integer;
begin
  if not (Context is TElWin32CryptoContext) then
    raise EElWin32CryptoProviderError.Create(SInvalidContext);
    
  Ctx := TElWin32CryptoContext(Context);
  if TElWin32CryptoContext(Context).FContextType = cctPKICrypto then
  begin
    // actual decryption is done in DecryptFinal
    if OutBuffer <> nil then
    begin
      OldLen := Length(Ctx.FSpool);
      SetLength(Ctx.FSpool, OldLen + InSize);
      SBMove(InBuffer^, Ctx.FSpool[OldLen], InSize);
      OutSize := 0;
    end
    else
      OutSize := 1;
  end
  else if (Ctx.FKey is TElWin32CryptoKey) and (TElWin32CryptoKey(Ctx.FKey).FHandle <> 0) then
  begin
    // checking output size
    EncLen := InSize;
    if (OutBuffer = nil) or (OutSize = 0) then
    begin
      // just a size request, exiting
      if Ctx.FAlgorithm <> SB_ALGORITHM_CNT_RC4 then
        OutSize := ((Length(Ctx.FOtherSpool) + InSize) div Ctx.BlockSize) * Ctx.BlockSize
      else
        OutSize := InSize;
      // a small correction of ours: for the sake of speed, we copy the input buffer
      // to the output buffer prior to encrypting it, that's why we need to
      // have an output buffer of at least the same size as the input buffer
      // + size of the cached input data
      //if OutSize < InSize + Length(Ctx.FOtherSpool) then
      //  OutSize := InSize + Length(Ctx.FOtherSpool);
      Exit;
    end;
    // doing decryption
    if Ctx.FAlgorithm <> SB_ALGORITHM_CNT_RC4 then
    begin
      SpoolLen := Length(Ctx.FOtherSpool);
      if OutSize < ((InSize + integer(SpoolLen)) div Ctx.BlockSize) * Ctx.BlockSize then
        raise EElWin32CryptoProviderError.Create(SBufferTooSmall);
      if InSize + integer(SpoolLen) < Ctx.BlockSize then
      begin
        SetLength(Ctx.FOtherSpool, InSize + integer(SpoolLen));
        SBMove(InBuffer^, Ctx.FOtherSpool[SpoolLen], InSize);
        OutSize := 0;
      end
      else
      begin
        // we have enough input data to decrypt at least one block
        // performing decryption in three steps:
        ProcLen := ((integer(SpoolLen) + InSize) div Ctx.BlockSize) * Ctx.BlockSize;
        if Ctx.Padding = SB_SYMENC_PADDING_PKCS5 then
        begin
          // (a) copying the already decrypted and cached data block to the beginning of the output buffer
          OutOffset := Length(Ctx.FSpool);
          SBMove(Ctx.FSpool[0], OutBuffer^, OutOffset);
          // (b) decrypting all the available data except the last block
          SBMove(Ctx.FOtherSpool[0], PByteArray(OutBuffer)[OutOffset], SpoolLen);
          SBMove(InBuffer^, PByteArray(OutBuffer)[OutOffset + integer(SpoolLen)],
            integer(ProcLen) - integer(SpoolLen) - Ctx.BlockSize);
          EncLen := integer(ProcLen) - Ctx.BlockSize;
        end
        else
        begin
          // (a) no padding, thus no data is cached internally. Decrypting all the data we can do.
          OutOffset := 0;
          SBMove(Ctx.FOtherSpool[0], PByteArray(OutBuffer)[OutOffset], SpoolLen);
          SBMove(InBuffer^, PByteArray(OutBuffer)[OutOffset + integer(SpoolLen)],
            integer(ProcLen) - integer(SpoolLen));
          EncLen := ProcLen;
        end;
        if CryptDecrypt(Ctx.FKeyHandle, 0, false, 0,
          @PByteArray(OutBuffer)[OutOffset], EncLen) then
        begin
          OutSize := integer(EncLen) + OutOffset;
          if Ctx.Padding = SB_SYMENC_PADDING_PKCS5 then
          begin
            // (c) decrypting the last block separately
            SetLength(Ctx.FSpool, Ctx.BlockSize);
            SBMove(PByteArray(InBuffer)[integer(ProcLen) - integer(SpoolLen) - Ctx.BlockSize], Ctx.FSpool[0],
              Ctx.BlockSize);
            EncLen := Ctx.BlockSize;
            if not CryptDecrypt(Ctx.FKeyHandle, 0, false, 0,
              @Ctx.FSpool[0], EncLen) then
            begin
              R := GetLastError();
              raise EElWin32CryptoProviderError.CreateFmt(SWin32Error, [(R)]);
            end;
          end;
          // copying trailer to the spool
          if InSize - integer(ProcLen) + integer(SpoolLen) > 0 then
          begin
            SetLength(Ctx.FOtherSpool, InSize - integer(ProcLen) + integer(SpoolLen));
            SBMove(PByteArray(InBuffer)[ProcLen - SpoolLen], Ctx.FOtherSpool[0],
              InSize - integer(ProcLen) + integer(SpoolLen));
          end
          else
            SetLength(Ctx.FOtherSpool, 0);
        end
        else
        begin
          R := GetLastError();
          raise EElWin32CryptoProviderError.CreateFmt(SWin32Error, [(R)]);
        end;
      end;
    end
    else
    begin
      SBMove(InBuffer^, OutBuffer^, InSize);
      EncLen := InSize;
      if CryptDecrypt(Ctx.FKeyHandle, 0, false, 0,
        OutBuffer, EncLen) then
        OutSize := InSize
      else
      begin
        R := GetLastError();
        raise EElWin32CryptoProviderError.CreateFmt(SWin32Error, [(R)]);
      end;
    end;
  end
  else
    raise EElWin32CryptoProviderError.Create(SUnsupportedOperation);
end;

procedure TElWin32CryptoProvider.SignUpdate(Context : TElCustomCryptoContext; InBuffer : pointer;
  InSize : integer; OutBuffer: pointer; var OutSize: integer;
  Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
  ProgressData : pointer = nil);
var
  OldLen : integer;
  Ctx : TElWin32CryptoContext;
begin
  if not (Context is TElWin32CryptoContext) then
    raise EElWin32CryptoProviderError.Create(SInvalidContext);
  if TElWin32CryptoContext(Context).FContextType = cctPKICrypto then
  begin
    // actual signing is done in SignFinal
    if OutBuffer <> nil then
    begin
      Ctx := TElWin32CryptoContext(Context);
      if Ctx.FInputIsHash then
      begin
        OldLen := Length(Ctx.FSpool);
        SetLength(Ctx.FSpool, OldLen + InSize);
        SBMove(InBuffer^, Ctx.FSpool[OldLen], InSize);
        OutSize := 0;
      end
      else
      begin
        Ctx.FHashContext.CryptoProvider.HashUpdate(Ctx.FHashContext, InBuffer, InSize, Params);
        OutSize := 0;
      end;
    end
    else
      OutSize := 1;
  end;
end;

procedure TElWin32CryptoProvider.VerifyUpdate(Context : TElCustomCryptoContext; InBuffer : pointer;
  InSize : integer; OutBuffer: pointer; var OutSize : integer;
  Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
  ProgressData : pointer = nil);
var
  OldLen : integer;
  Ctx : TElWin32CryptoContext;
begin
  if not (Context is TElWin32CryptoContext) then
    raise EElWin32CryptoProviderError.Create(SInvalidContext);
  if TElWin32CryptoContext(Context).FContextType = cctPKICrypto then
  begin
    // actual validation is done in VerifyFinal
    if OutBuffer <> nil then
    begin
      Ctx := TElWin32CryptoContext(Context);
      if Ctx.FInputIsHash then
      begin
        OldLen := Length(Ctx.FSpool);
        SetLength(Ctx.FSpool, OldLen + InSize);
        SBMove(InBuffer^, Ctx.FSpool[OldLen], InSize);
        OutSize := 0;
      end
      else
      begin
        Ctx.FHashContext.CryptoProvider.HashUpdate(Ctx.FHashContext, InBuffer, InSize, Params);
        OutSize := 0;
      end;
    end
    else
      OutSize := 1;
  end;
end;

procedure TElWin32CryptoProvider.EncryptFinal(Context : TElCustomCryptoContext; Buffer : pointer;
  var Size : integer; Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
  ProgressData : pointer = nil);
var
  Ctx : TElWin32CryptoContext;
  SpoolLen, EncLen : DWORD;
  R, I : integer;
  B : byte;
  KeyHandle : HCRYPTKEY;
  ProvHandle : HCRYPTPROV;
  ReleaseObjs : boolean;
  KS, AltKS : DWORD;
begin
  ProvHandle := 0;
  if (Context is TElWin32CryptoContext) then
  begin
    Ctx := TElWin32CryptoContext(Context);
    if Ctx.FContextType = cctSymCrypto then
    begin
      // checking output size
      if Ctx.FAlgorithm <> SB_ALGORITHM_CNT_RC4 then
      begin
        SpoolLen := Length(Ctx.FSpool);
        EncLen := SpoolLen;
        CryptEncrypt(Ctx.FKeyHandle, 0,  true , 0, 
            nil  , EncLen, 0);
      end
      else
        EncLen := 0;
        
      if (Buffer = nil) or (Size = 0) then
      begin
        // just a size request, exiting
        if EncLen <> 0 then
          Size := EncLen
        else
          Size := 1; // returning fake 1 value if zero output is expected
        Exit;
      end;
      // doing encryption
      if Ctx.FAlgorithm <> SB_ALGORITHM_CNT_RC4 then
      begin
        if SpoolLen > 0 then
          SBMove(Ctx.FSpool[0], Buffer^, SpoolLen);
        if CryptEncrypt(Ctx.FKeyHandle, 0, true, 0, Buffer, SpoolLen, Size) then
        begin
          Size := SpoolLen;
          SetLength(Ctx.FSpool, 0);
        end
        else
        begin
          R := GetLastError();
          raise EElWin32CryptoProviderError.CreateFmt(SWin32Error, [(R)]);
        end;
      end
      else
        Size := 0;
    end
    else if Ctx.FContextType = cctPKICrypto then
    begin
      // source data has been accumulated in the FSpool
      // requesting output size
      SpoolLen := Length(Ctx.FSpool);
      EncLen := SpoolLen;
      // obtaining encryption key
      KeyHandle := TElWin32CryptoKey(Ctx.FKey).FHandle;
      if KeyHandle = 0 then
      begin
        // key handle is 0 if certificate is used
        TElWin32CryptoKey(Ctx.FKey).AcquireCertificateContextPub(ProvHandle);
        if ProvHandle <> 0 then
        begin
          KS := TElWin32CryptoKey(Ctx.FKey).FLastPubKeySpec;
          if KS = AT_SIGNATURE then
            AltKS := AT_KEYEXCHANGE 
          else
            AltKS := AT_SIGNATURE;
          if not (CryptGetUserKey(ProvHandle, KS,  @ KeyHandle) ) then
          begin
            if not (CryptGetUserKey(ProvHandle, AltKS,  @ KeyHandle) ) then
              KeyHandle := 0;
          end;
        end;
        ReleaseObjs := true;
      end
      else
        ReleaseObjs := false;
      try
        CryptEncrypt(KeyHandle, 0,  true , 0,  nil , EncLen, Size);
        if (Buffer = nil) or (Size = 0) then
        begin
          // just a size request, exiting
          if EncLen <> 0 then
            Size := EncLen
          else
            Size := 1; // returning fake 1 value if zero output is expected
          Exit;
        end;
        if SpoolLen > 0 then
        begin
          SBMove(Ctx.FSpool[0], Buffer^, SpoolLen);
        end;
        if CryptEncrypt(KeyHandle, 0, true, 0, Buffer, SpoolLen, Size) then
        begin
          Size := SpoolLen;
          SetLength(Ctx.FSpool, 0);
          for I := 0 to (Size shr 1) - 1 do
          begin
            B := PByteArray(Buffer)[I];
            PByteArray(Buffer)[I] := PByteArray(Buffer)[Size - I - 1];
            PByteArray(Buffer)[Size - I - 1] := B;
          end;
        end
        else
        begin
          R := GetLastError();
          raise EElWin32CryptoProviderError.CreateFmt(SWin32Error, [(R)]);
        end;
      finally
        if ReleaseObjs then
        begin
          if KeyHandle <> 0 then
            CryptDestroyKey(KeyHandle);
          if ProvHandle <> 0 then
          begin
            CryptReleaseContext(ProvHandle, 0);
          end;
        end;
      end;
    end;
  end
  else
    raise EElWin32CryptoProviderError.Create(SInvalidContext);
end;

procedure TElWin32CryptoProvider.DecryptFinal(Context : TElCustomCryptoContext; Buffer : pointer;
  var Size : integer; Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
  ProgressData :  pointer   =  nil);
var
  Ctx : TElWin32CryptoContext;
  OutSize : integer;
  PadSize : integer;
  Len : integer;
  I : integer;
  B : boolean;
begin
  if not (Context is TElWin32CryptoContext) then
    raise EElWin32CryptoProviderError.Create(SInvalidContext);
  Ctx := TElWin32CryptoContext(Context);
  if Ctx.FContextType = cctPKICrypto then
  begin
    OutSize := 0;
    DecryptPKI(Ctx, @Ctx.FSpool[0], Length(Ctx.FSpool), nil, OutSize);
    if Buffer = nil then
    begin
      Size := OutSize;
      if Size = 0 then
        Size := 1;
    end
    else
    begin
      if Size < OutSize then
        raise EElWin32CryptoProviderError.Create(SBufferTooSmall);
      B := DecryptPKI(Ctx, @Ctx.FSpool[0], Length(Ctx.FSpool), Buffer, Size);
      if not B then
        raise EElWin32CryptoProviderError.Create(SDecryptionFailed);
    end;
  end
  else if (Ctx.FKey is TElWin32CryptoKey) and (TElWin32CryptoKey(Ctx.FKey).FHandle <> 0) then
  begin
    if (Size = 0) then
      Size := Length(Ctx.FSpool)
    else if Length(Ctx.FSpool) > 0 then
    begin
      PadSize := Ctx.FSpool[Length(Ctx.FSpool) - 1];
      Len := Length(Ctx.FSpool);
      if PadSize > Len then
        raise EElWin32CryptoProviderError.Create(SInvalidPadding);
      for I := 0 to PadSize - 1 do
        if Ctx.FSpool[Len - I - 1] <> PadSize then
          raise EElWin32CryptoProviderError.Create(SInvalidPadding);
      Size := Len - PadSize;
      SBMove(Ctx.FSpool[0], Buffer^, Size);
    end
    else
      Size := 0;
  end
  else
    Size := 0;
end;

procedure TElWin32CryptoProvider.SignFinal(Context : TElCustomCryptoContext; Buffer : pointer;
  var Size : integer; Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
  ProgressData : pointer = nil);
var
  Ctx : TElWin32CryptoContext;
  OutSize : integer;
  HashResult : ByteArray;
  B : boolean;
begin
  if not (Context is TElWin32CryptoContext) then
    raise EElWin32CryptoProviderError.Create(SInvalidContext);

  if TElWin32CryptoContext(Context).FContextType = cctPKICrypto then
  begin
    Ctx := TElWin32CryptoContext(Context);
    if Length(Ctx.FSignSource) = 0 then
    begin
      if Ctx.FInputIsHash then
        Ctx.FSignSource := (Ctx.FSpool)
      else
      begin
        if Ctx.FHashContext <> nil then
        begin
          HashResult := Ctx.FHashContext.CryptoProvider.HashFinal(Ctx.FHashContext, nil);
          if Assigned(Ctx.FHashContext.CryptoProvider) then
            Ctx.FHashContext.CryptoProvider.ReleaseCryptoContext(Ctx.FHashContext);
        end
        else
          HashResult := EmptyArray;
        Ctx.FSignSource := CloneArray(HashResult);
      end;
    end;

    if FNativeSizeCalculation then
    begin
      OutSize := 0;
      SignPKI(Ctx, @Ctx.FSignSource[0], Length(Ctx.FSignSource), nil, OutSize);
    end
    else
    begin
      OutSize := SB_MAX_OPRESULT_SIZE; // the maximal size acceptable by the implementation in this mode
      if Context.Algorithm = SB_ALGORITHM_PK_DSA then
        Inc(OutSize, 16);
    end;
    if Buffer = nil then
    begin
      Size := OutSize;
      if Size = 0 then
        Size := 1;
    end
    else
    begin
      if Size < OutSize then
        raise EElWin32CryptoProviderError.Create(SBufferTooSmall);    
      B := SignPKI(Ctx, @Ctx.FSignSource[0], Length(Ctx.FSignSource), Buffer, Size);
      if not B then
        raise EElWin32CryptoProviderError.CreateFmt(SSigningFailedInfo, [(FLastSigningError)]);
    end;
  end;
end;

function TElWin32CryptoProvider.VerifyFinal(Context : TElCustomCryptoContext; Buffer : pointer;
  var Size : integer; Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
  ProgressData : pointer = nil): integer;
var
  Ctx : TElWin32CryptoContext;
  HashResult : ByteArray;
begin
  if not (Context is TElWin32CryptoContext) then
    raise EElWin32CryptoProviderError.Create(SInvalidContext);
  if TElWin32CryptoContext(Context).FContextType = cctPKICrypto then
  begin
    Ctx := TElWin32CryptoContext(Context);
    if Ctx.FOperationDone then
      Result := Ctx.FOperationResult
    else
    begin
      if Length(Ctx.FSignSource) = 0 then
      begin
        if Ctx.FInputIsHash then
          Ctx.FSignSource := (Ctx.FSpool)
        else
        begin
          if Ctx.FHashContext <> nil then
          begin
            HashResult := (Ctx.FHashContext.CryptoProvider.HashFinal(Ctx.FHashContext, nil));
            if Assigned(Ctx.FHashContext.CryptoProvider) then
              Ctx.FHashContext.CryptoProvider.ReleaseCryptoContext(Ctx.FHashContext);
          end
          else
            HashResult := EmptyArray;
          Ctx.FSignSource := CloneArray(HashResult);
        end;
      end;
      Result := VerifyPKI(Ctx, @Ctx.FSignSource[0], Length(Ctx.FSignSource),
        @Ctx.FSignature[0], Length(Ctx.FSignature));
      Ctx.FOperationResult := Result;
      Ctx.FOperationDone := true;
    end;
  end
  else
    Result := SB_VR_FAILURE;
end;

function TElWin32CryptoProvider.HashInit(Algorithm : integer; Key : TElCustomCryptoKey;
  Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil): TElCustomCryptoContext;
var
  I : integer;
  ProvHandle : HCRYPTPROV;
  AlgInfo : TElWin32AlgorithmInfo;
  hHash : HCRYPTHASH;
  hKey : HCRYPTKEY;
  Blob : ByteArray;
  KeyLen : integer;
  R : integer;
  HmacInfo : HMAC_INFO;
begin
  if IsOperationSupported(SB_OPTYPE_HASH, Algorithm, 0, Key, Params) then
  begin
    // getting the provider to use
    ProvHandle := 0;
    AlgInfo := nil;
    for I := 0 to FProviderInfos.Count - 1 do
    begin
      AlgInfo := TElWin32ProviderInfo(FProviderInfos[I]).GetAlgorithmInfo(Algorithm, 0, SB_OPTYPE_HASH,
        TElWin32CryptoProviderOptions(Options).FFIPSMode);
      if AlgInfo <> nil then
      begin
        ProvHandle := TElWin32ProviderInfo(FProviderInfos[I]).FProvHandle;
        Break;
      end;
    end;
    if ProvHandle = 0 then
      raise EElWin32CryptoProviderError.Create(SUnsupportedOperation);
    Result := TElWin32CryptoContext.Create(Algorithm, 0, Key, ccoHash, Self, Params);
    FLock.WaitToWrite();
    try
      if FOptions.StoreKeys then
        FContexts.Add(Result);
      if not IsMACAlgorithm(Algorithm) then
      begin
        if AlgInfo.FAlgorithm <> SB_ALGORITHM_DGST_SSL3 then
        begin
          hHash := 0;
          if CryptCreateHash(ProvHandle, AlgInfo.FWin32Algorithm, 0, 0,  @ hHash)  then
          begin
            TElWin32CryptoContext(Result).FProvHandle := ProvHandle;
            TElWin32CryptoContext(Result).FHashHandle := hHash;
          end;
        end
        else
        begin
          // According to MSDN (http://msdn.microsoft.com/en-us/library/aa379865(VS.85).aspx),
          // CALG_SSL3_SHAMD5 digest should be calculated manually
          // using separate SHA1 and MD5 hash contexts, i.e. we cannot pass
          // CALG_SSL3_SHAMD5 as a hash algorithm directly
          hHash := 0;
          if CryptCreateHash(ProvHandle, CALG_MD5, 0, 0,  @ hHash)  then
          begin
            TElWin32CryptoContext(Result).FProvHandle := ProvHandle;
            TElWin32CryptoContext(Result).FHashHandle := hHash;
          end;
          hHash := 0;
          if CryptCreateHash(ProvHandle, CALG_SHA1, 0, 0,  @ hHash) then
            TElWin32CryptoContext(Result).FExtraHashHandle := hHash;
        end;
      end
      else
      begin
        // According to the document published by Microsoft
        // (http://csrc.nist.gov/cryptval/140-1/140sp/140sp382.pdf ), we should
        // use CALG_RC2 as the key algorithm of PLAINTEXTKEYBLOB, and import the
        // blob by CryptImportKey() with the flag CRYPT_IPSEC_HMAC_KEY specified.
        // Creating key object
        KeyLen := Length(Key.Value);
        SetLength(Blob, 8 { PLAINTEXTKEYBLOB header } + 4 { Length prefix } + KeyLen);
        Blob[0] := 8; // PLAINTEXTKEYBLOB id
        Blob[1] := 2; // Version
        Blob[2] := 0; // Reserved
        Blob[3] := 0; // Reserved
        Blob[4] := CALG_RC2 and $ff;
        Blob[5] := (CALG_RC2 shr 8) and $ff;
        Blob[6] := (CALG_RC2 shr 16) and $ff;
        Blob[7] := (CALG_RC2 shr 24) and $ff;
        Blob[8] := KeyLen and $ff;
        Blob[9] := (KeyLen shr 8) and $ff;
        Blob[10] := (KeyLen shr 16) and $ff;
        Blob[11] := (KeyLen shr 24) and $ff;
        SBMove(Key.Value, 0, Blob, 12, KeyLen);

        if CryptImportKey(ProvHandle, @Blob[0], Length(Blob), 0, CRYPT_IPSEC_HMAC_KEY, @hKey) then
        begin
          // Creating hash object
          if CryptCreateHash(ProvHandle, CALG_HMAC, hKey, 0,  @ hHash)  then
          begin
            HmacInfo.HashAlgid := AlgInfo.FWin32Algorithm;
            HmacInfo.cbInnerString := 0;
            HmacInfo.cbOuterString := 0;
            HmacInfo.pbInnerString :=  nil ;
            HmacInfo.pbOuterString :=  nil ;
            CryptSetHashParam(hHash, HP_HMAC_INFO, @HmacInfo, 0);
            TElWin32CryptoContext(Result).FProvHandle := ProvHandle;
            TElWin32CryptoContext(Result).FHashHandle := hHash;
            TElWin32CryptoContext(Result).FKeyHandle := hKey;
          end
          else
          begin
            R := GetLastError();
            raise EElWin32CryptoProviderError.CreateFmt(SWin32Error, [(R)]);
          end;
        end
        else
        begin
          R := GetLastError();
          raise EElWin32CryptoProviderError.CreateFmt(SWin32Error, [(R)]);
        end;
      end;
    finally
      FLock.Done();
    end;
  end
  else
    raise EElWin32CryptoProviderError.Create(SUnsupportedOperation);
end;

function TElWin32CryptoProvider.HashInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
  Key : TElCustomCryptoKey; Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil): TElCustomCryptoContext;
var
  Alg : integer;
begin
  Alg := GetHashAlgorithmByOID(AlgOID);
  if Alg = SB_ALGORITHM_UNKNOWN then
    raise EElWin32CryptoProviderError.CreateFmt(SUnsupportedAlgorithmStr, [(OIDToStr(AlgOID))]);
  Result := HashInit(Alg, Key, Params, ProgressFunc, ProgressData);
end;

procedure TElWin32CryptoProvider.HashUpdate(Context : TElCustomCryptoContext; Buffer : pointer;
  Size : integer; Params : TElCPParameters = nil;
  ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil);
var
  Ctx : TElWin32CryptoContext;
  R : integer;
begin
  if not (Context is TElWin32CryptoContext) then
    raise EElWin32CryptoProviderError.Create(SInvalidContext);
  Ctx := TElWin32CryptoContext(Context);
  if not CryptHashData(Ctx.FHashHandle, Buffer, Size, 0) then
  begin
    R := GetLastError();
    raise EElWin32CryptoProviderError.CreateFmt(SWin32Error, [(R)]);
  end;
  if Ctx.FExtraHashHandle <> 0 then
  begin
    if not CryptHashData(Ctx.FExtraHashHandle, Buffer, Size, 0) then
    begin
      R := GetLastError();
      raise EElWin32CryptoProviderError.CreateFmt(SWin32Error, [(R)]);
    end;
  end;
end;

function TElWin32CryptoProvider.HashFinal(Context : TElCustomCryptoContext; Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil): ByteArray;
var
  Ctx : TElWin32CryptoContext;
  R : integer;
  HashLen : DWORD;
  dataLen :  DWORD ;
  Len : DWORD;
begin
  if not (Context is TElWin32CryptoContext) then
    raise EElWin32CryptoProviderError.Create(SInvalidContext);
  Ctx := TElWin32CryptoContext(Context);
  dataLen := 4;
  CryptGetHashParam(Ctx.FHashHandle, HP_HASHSIZE, Windows.PByte(@HashLen), dataLen, 0);
  SetLength(Result, HashLen);
  dataLen := HashLen;
  
  if not CryptGetHashParam(Ctx.FHashHandle, HP_HASHVAL, @Result[0], dataLen, 0) then
  begin
    R := GetLastError();
    raise EElWin32CryptoProviderError.CreateFmt(SWin32Error, [(R)]);
  end;
  if Ctx.FExtraHashHandle <> 0 then
  begin
    dataLen := 4;
    CryptGetHashParam(Ctx.FExtraHashHandle, HP_HASHSIZE, Windows.PByte(@HashLen), dataLen, 0);
    Len := Length(Result);
    SetLength(Result, Len + HashLen);
    dataLen := HashLen;
    if not CryptGetHashParam(Ctx.FExtraHashHandle, HP_HASHVAL, @Result[Len + 1], dataLen, 0) then
    begin
      R := GetLastError();
      raise EElWin32CryptoProviderError.CreateFmt(SWin32Error, [(R)]);
    end;
  end;
end;

procedure TElWin32CryptoProvider.ReleaseCryptoContext(var Context : TElCustomCryptoContext);
var
  Index : integer;
begin
  if (not (Context is TElWin32CryptoContext)) or (not (Context.CryptoProvider = Self)) then
    raise EElWin32CryptoProviderError.Create(SInvalidContext);
  FLock.WaitToWrite();
  try
    Index := FContexts.IndexOf(Context);
    if Index >= 0 then
      FContexts. Delete (Index);
  finally
    FLock.Done();
  end;
  FreeAndNil(Context);
end;

function TElWin32CryptoProvider.CreateKeyStorage(Persistent: boolean; Params : TElCPParameters  =  nil): TElCustomCryptoKeyStorage;
begin
  raise EElWin32CryptoProviderError.Create(SFeatureNotAvailable);
end;

procedure TElWin32CryptoProvider.ReleaseKeyStorage(var KeyStorage : TElCustomCryptoKeyStorage);
begin
  raise EElWin32CryptoProviderError.Create(SFeatureNotAvailable);
end;

procedure TElWin32CryptoProvider.DeleteKeyStorage(var KeyStorage : TElCustomCryptoKeyStorage);
begin
  raise EElWin32CryptoProviderError.Create(SFeatureNotAvailable);
end;

procedure TElWin32CryptoProvider.RandomInit(BaseData: pointer; BaseDataSize: integer; Params : TElCPParameters = nil);
begin
  raise EElWin32CryptoProviderError.Create(SUnsupportedOperation);
end;

procedure TElWin32CryptoProvider.RandomSeed(Data: pointer; DataSize: integer);
begin
  raise EElWin32CryptoProviderError.Create(SUnsupportedOperation);
end;

procedure TElWin32CryptoProvider.RandomGenerate(Buffer: pointer; Size: integer);
begin
  raise EElWin32CryptoProviderError.Create(SUnsupportedOperation);
end;

function TElWin32CryptoProvider.RandomGenerate(MaxValue: integer): integer;
begin
  raise EElWin32CryptoProviderError.Create(SUnsupportedOperation);
end;

function TElWin32CryptoProvider.GetProviderProp(const PropID : ByteArray; const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =  nil {$endif}): ByteArray;
begin
  {$ifdef SB_HAS_CRYPTUI} 
  if CompareContent(PropID, SB_PROVPROP_WINDOW_HANDLE) then
    Result := GetBufferFromInteger(FWindowHandle)
  else
   {$endif}
    Result := inherited GetProviderProp(PropID, Default);
end;

procedure TElWin32CryptoProvider.SetProviderProp(const PropID : ByteArray; const Value : ByteArray);
var
  Wnd :  HWND ;
  R : boolean;
  LastError : integer;
begin
  {$ifdef SB_HAS_CRYPTUI} 
  if CompareContent(PropID, SB_PROVPROP_WINDOW_HANDLE) then
  begin
    Wnd := GetIntegerPropFromBuffer(Value);
    R := CryptSetProvParam(0, PP_CLIENT_HWND, @Wnd, 0);
    if R then
      FWindowHandle := Wnd
    else
    begin
      LastError := GetLastError();
      raise EElCryptoProviderError.CreateFmt(SWin32Error, [LastError]);
    end;
  end
  else
   {$endif}
    inherited;
end;

function TElWin32CryptoProvider.DecryptPKI(Context : TElCustomCryptoContext;
  Buffer: pointer; Size: integer; OutBuffer: pointer; var OutSize : integer): boolean;
const
  BaseProvName: string = 'Microsoft Base Cryptographic Provider v1.0';
  EnhProvName: string = 'Microsoft Enhanced Cryptographic Provider v1.0';
var
  I : integer;
  BufConv : ByteArray;
  CertContext :   PCCERT_CONTEXT  ;
  Sz :   integer  ;
  Buf :   pointer  ;
  ProvInfo:  PCRYPT_KEY_PROV_INFO ;
  {$ifndef SB_UNICODE_VCL}
  LenProvName, LenContName: integer;
  ProvName, ContName:  PAnsiChar ;
   {$endif}
  {$ifdef SB_UNICODE_VCL}
  pwszContName, pwszProvName : PWideChar;
   {$endif}
  //EnhProvName: string;
  Prov: HCRYPTPROV;
  hKey : HCRYPTKEY;
  DataLen :  cardinal ;
  Ctx : TElWin32CryptoContext;
  CertBasedKey : boolean;
  {$ifdef SB_HAS_CNG}
  CNGKey : boolean;
  CNGKeyHandle : NCRYPT_KEY_HANDLE;
  CNGOutputBuf : ByteArray;
  CNGOutputBufSize :  DWORD ;
   {$endif}
  {$ifdef SB_HAS_CNG}
  R : integer;
   {$endif}
begin
  if not (Context is TElWin32CryptoContext) then
    raise EElWin32CryptoProviderError.Create(SInvalidContext);

  Ctx := TElWin32CryptoContext(Context);

  if Ctx.FUseOAEP then
  begin
    Result := DecryptPKIOAEP(Context, Buffer, Size,
      OutBuffer, OutSize);
    Exit;
  end;

  Result := false;
  if OutSize < ((Ctx.FKey.Bits - 1) shr 3) + 1 then
  begin
    OutSize := ((Ctx.FKey.Bits - 1) shr 3) + 1;
    Exit;
  end;
  

  // converting buffer from big-endian to little-endian format (legacy CryptoAPI use only)
  SetLength(BufConv, Size);
  for I := 0 to Size - 1 do
    BufConv[I] := PByteArray(Buffer)[Size - I - 1];

  {$ifdef SB_HAS_CNG}
  CNGKey := false;
  CNGKeyHandle :=  nil ;
  CNGOutputBuf := EmptyArray;
   {$endif}
  
  CertContext := nil;
  if TElWin32CryptoKey(Ctx.FKey).FCertContext <> nil then
  begin
    CertContext := TElWin32CryptoKey(Ctx.FKey).FCertContext;
    CertBasedKey := true;
  end
  else
    CertBasedKey := false;

  if CertBasedKey then
  begin
    if (TElWin32CryptoProviderOptions(FOptions).FCacheKeyContexts) and (TElWin32CryptoKey(Ctx.FKey).FCachedProv <> 0) then
    begin
      {$ifdef SB_HAS_CNG}
      if not TElWin32CryptoKey(Ctx.FKey).CachedIsCNGKey() then
       {$endif}
      begin
        if FWindowHandle <> 0 then
          CryptSetProvParam(TElWin32CryptoKey(Ctx.FKey).FCachedProv, PP_CLIENT_HWND, @FWindowHandle, 0);
        if CryptGetUserKey(TElWin32CryptoKey(Ctx.FKey).FCachedProv, TElWin32CryptoKey(Ctx.FKey).FCachedKeySpec, @hKey) then
        begin
          DataLen := Length(BufConv);
          if CryptDecrypt(hKey, 0, true, 0, @BufConv[0], DataLen) then
          begin
            SBMove(BufConv[0], OutBuffer^, DataLen);
            OutSize := DataLen;
            Result := true;
          end;
          CryptDestroyKey(hKey);
        end;
        // we do not release the provider handle here (as it is taken from the cache and should be left there intact)
      end
      {$ifdef SB_HAS_CNG}
      else
      begin
        // there is a CNG key in the cache
        // TODO: set WindowHandle prov param (and check in other places)
        CNGOutputBufSize := OutSize;
        SetLength(CNGOutputBuf, CNGOutputBufSize);
        try
          try
            R := NCryptDecrypt(TElWin32CryptoKey(Ctx.FKey).FCachedCNGKeyHandle,
               Buffer , Size,
                nil  ,
               @CNGOutputBuf[0] ,
              CNGOutputBufSize,  @ CNGOutputBufSize, NCRYPT_PAD_PKCS1_FLAG);
          finally
          end;
        finally
        end;
        if R = ERROR_SUCCESS then
        begin
          OutSize := CNGOutputBufSize;
          SBMove(CNGOutputBuf[0], OutBuffer^, OutSize);
          Result := true;
        end
        else
        begin
          FLastSigningErrorCode := R;
          FLastSigningError := Format(SWin32Error, [(R)]);
        end;
      end
	   {$endif}
    ;
    end
    else
    begin
      CertGetCertificateContextProperty(CertContext, CERT_KEY_PROV_INFO_PROP_ID, 
          nil  ,  @ Sz);
      GetMem(Buf, Sz);
      if CertGetCertificateContextProperty(CertContext, CERT_KEY_PROV_INFO_PROP_ID, Buf,  @ Sz)  then
      begin
        // trying default key container provider
        Prov := 0;
        ProvInfo := PCRYPT_KEY_PROV_INFO(Buf);
        if ProvInfo.dwProvType <> 0 then
        begin        
          {$ifndef SB_UNICODE_VCL}
          if Length(TElWin32CryptoKey(Ctx.FKey).FUserProvName) = 0 then
            LenProvName := WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszProvName, -1, nil, 0, nil, nil)
          else
            LenProvName := Length(TElWin32CryptoKey(Ctx.FKey).FUserProvName) + 1;
          if Length(TElWin32CryptoKey(Ctx.FKey).FUserContName) = 0 then
            LenContName := WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszContainerName, -1, nil, 0, nil, nil)
          else
            LenContName := Length(TElWin32CryptoKey(Ctx.FKey).FUserContName) + 1;
          GetMem(ProvName, LenProvName);
          GetMem(ContName, LenContName);
          if Length(TElWin32CryptoKey(Ctx.FKey).FUserProvName) = 0 then
            WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszProvName, -1, ProvName, LenProvName, nil, nil)
          else
            StrPCopy(ProvName, TElWin32CryptoKey(Ctx.FKey).FUserProvName);
          if Length(TElWin32CryptoKey(Ctx.FKey).FUserContName) = 0 then
            WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszContainerName, -1, ContName, LenContName, nil, nil)
          else
            StrPCopy(ContName, TElWin32CryptoKey(Ctx.FKey).FUserContName);
          if CryptAcquireContext(@Prov, ContName, ProvName, ProvInfo.dwProvType, ProvInfo.dwFlags {or
            CRYPT_SILENT}) then
           {$else}
          if Length(TElWin32CryptoKey(Ctx.FKey).FUserContName) = 0 then
            pwszContName := ProvInfo.pwszContainerName
          else
            pwszContName := PWideChar(TElWin32CryptoKey(Ctx.FKey).FUserContName);
          if Length(TElWin32CryptoKey(Ctx.FKey).FUserProvName) = 0 then
            pwszProvName := ProvInfo.pwszProvName
          else
            pwszProvName := PWideChar(TElWin32CryptoKey(Ctx.FKey).FUserProvName);
          if CryptAcquireContext(@Prov, pwszContName, pwszProvName,
            ProvInfo.dwProvType, ProvInfo.dwFlags) then
           {$endif}
          begin            
            TElWin32CryptoKey(Ctx.FKey).SetProvPINs(Prov);
            if FWindowHandle <> 0 then
              CryptSetProvParam(Prov, PP_CLIENT_HWND, @FWindowHandle, 0);
            if CryptGetUserKey(Prov, ProvInfo.dwKeySpec, @hKey) then
            begin
              DataLen := Length(BufConv);
              if CryptDecrypt(hKey, 0, true, 0, @BufConv[0], DataLen) then
              begin
                SBMove(BufConv[0], OutBuffer^, DataLen);
                OutSize := DataLen;
                Result := true;
              end;
              CryptDestroyKey(hKey);
            end;
            // caching obtained context if needed
            if (TElWin32CryptoProviderOptions(FOptions).FCacheKeyContexts) then
            begin
              TElWin32CryptoKey(Ctx.FKey).FCachedProv := Prov;
              TElWin32CryptoKey(Ctx.FKey).FCachedKeySpec := ProvInfo.dwKeySpec;
            end
            else
            begin
              if Prov <> 0 then
              begin
                CryptReleaseContext(Prov, 0);
              end;
            end;
          end;

          // trying enhanced provider if it is enabled
          if (not Result) and (FTryEnhancedCryptoProvider) and
            {$ifdef SB_UNICODE_VCL}
            (ProvInfo.pwszProvName = BaseProvName) then
             {$else}
            (ProvName = BaseProvName) then
             {$endif}
          begin
            {$ifndef SB_UNICODE_VCL}
            if CryptAcquireContext(@Prov, ContName, PChar(EnhProvName), ProvInfo.dwProvType, ProvInfo.dwFlags {or
              CRYPT_SILENT}) then
             {$else}
            if CryptAcquireContext(@Prov, ProvInfo.pwszContainerName, PChar(EnhProvName), ProvInfo.dwProvType, ProvInfo.dwFlags) then
             {$endif}
            begin
              TElWin32CryptoKey(Ctx.FKey).SetProvPINs(Prov);
              if FWindowHandle <> 0 then
                CryptSetProvParam(Prov, PP_CLIENT_HWND, @FWindowHandle, 0);
              if CryptGetUserKey(Prov, ProvInfo.dwKeySpec, @hKey) then
              begin
                DataLen := Length(BufConv);
                if CryptDecrypt(hKey, 0, true, 0, @BufConv[0], DataLen) then
                begin
                  SBMove(BufConv[0], OutBuffer^, DataLen);
                  OutSize := DataLen;
                  Result := true;
                end;
                CryptDestroyKey(hKey);
              end;
              // optionally caching the obtained provider context
              if (TElWin32CryptoProviderOptions(FOptions).FCacheKeyContexts) then
              begin
                TElWin32CryptoKey(Ctx.FKey).FCachedProv := Prov;
                TElWin32CryptoKey(Ctx.FKey).FCachedKeySpec := ProvInfo.dwKeySpec;
              end
              else
              begin
                if Prov <> 0 then
                begin
                  CryptReleaseContext(Prov, 0);
                end;
              end;
            end;
          end;
          {$ifndef SB_UNICODE_VCL}
          FreeMem(ProvName);
          FreeMem(ContName);
           {$endif}
        end
        {$ifdef SB_HAS_CNG}  
        else // CNG key
        begin
          if CNGCryptoProviderHandleManager().OpenCNGStorageProvider( Prov , ProvInfo.pwszProvName, 0) = ERROR_SUCCESS then
          begin
            if NCryptOpenKey(NCRYPT_PROV_HANDLE(Prov),  @ CNGKeyHandle,
              ProvInfo.pwszContainerName, 0, ProvInfo.dwFlags) = ERROR_SUCCESS then
            begin
              TElWin32CryptoKey(Ctx.FKey).SetProvPINs(Prov);
              CNGOutputBufSize := OutSize;
              SetLength(CNGOutputBuf, CNGOutputBufSize);
              try
                try
                  R := NCryptDecrypt(CNGKeyHandle,  Buffer , Size,
                      nil  ,
                     @CNGOutputBuf[0] ,
                    CNGOutputBufSize,  @ CNGOutputBufSize, NCRYPT_PAD_PKCS1_FLAG);
                finally
                end;
              finally
              end;
              if R = ERROR_SUCCESS then
              begin
                OutSize := CNGOutputBufSize;
                SBMove(CNGOutputBuf[0], OutBuffer^, OutSize);
                Result := true;
              end
              else
              begin
                FLastSigningErrorCode := R;
                FLastSigningError := Format(SWin32Error, [(R)]);
              end;

              if TElWin32CryptoProviderOptions(FOptions).FCacheKeyContexts and
                (TElWin32CryptoKey(Ctx.FKey).FCachedProv = 0) then
              begin
                TElWin32CryptoKey(Ctx.FKey).FCachedProv := Prov;
                TElWin32CryptoKey(Ctx.FKey).FCachedKeySpec := 0;
                TElWin32CryptoKey(Ctx.FKey).FCachedAESProv := 0;
                TElWin32CryptoKey(Ctx.FKey).FCachedCNGKeyHandle := CNGKeyHandle;
              end
              else
              begin
                NCryptFreeObject(CNGKeyHandle);
                CNGCryptoProviderHandleManager().FreeCNGStorageProvider(Prov);
              end;
            end
            else
            begin
              CNGCryptoProviderHandleManager().FreeCNGStorageProvider(Prov);
              Prov := 0;
            end;
          end;
        end
		 {$endif}
		;
      end;
      FreeMem(Buf);
    end;
  end
  else
  begin
    if FWindowHandle <> 0 then
      CryptSetProvParam(Prov, PP_CLIENT_HWND, @FWindowHandle, 0);
    DataLen := Length(BufConv);
    {$ifdef SB_HAS_CNG}
    CNGKey := TElWin32CryptoKey(Ctx.FKey).IsCNGKey();
    if not CNGKey then
     {$endif}
    begin
      if CryptDecrypt(TElWin32CryptoKey(Ctx.FKey).FHandle, 0, true, 0, @BufConv[0], DataLen) then
      begin
        SBMove(BufConv[0], OutBuffer^, DataLen);
        OutSize := DataLen;
        Result := true;
      end;
    end
   {$ifdef SB_HAS_CNG}  
    else
    begin
      CNGOutputBufSize := OutSize;
      SetLength(CNGOutputBuf, CNGOutputBufSize);
      try
        try
          R := NCryptDecrypt(TElWin32CryptoKey(Ctx.FKey).FCNGKeyHandle,
             Buffer , Size,
              nil  ,
             @CNGOutputBuf[0] ,
            CNGOutputBufSize,  @ CNGOutputBufSize, NCRYPT_PAD_PKCS1_FLAG);
        finally
        end;
      finally
      end;
      if R = ERROR_SUCCESS then
      begin
        OutSize := CNGOutputBufSize;
        SBMove(CNGOutputBuf[0], OutBuffer^, OutSize);
        Result := true;
      end
      else
      begin
        FLastSigningErrorCode := R;
        FLastSigningError := Format(SWin32Error, [(R)]);
      end;
    end
     {$endif}
    ;
  end;
end;

function TElWin32CryptoProvider.DecryptPKIOAEP(Context : TElCustomCryptoContext;
  Buffer: pointer; Size: integer; OutBuffer: pointer; var OutSize : integer): boolean;
var
  CryptoKey : TElCustomCryptoKey;
  Prov : TElCustomCryptoProvider;
  Sz : integer;
  KeyBlob : ByteArray;
  Pars : TElCPParameters;
  WinCtx : TElWin32CryptoContext;
  EstSize : integer;

  procedure SetupParams;
  begin
    Pars.Add(SB_CTXPROP_USE_ALGORITHM_PREFIX, GetBufferFromBool(true));
    Pars.Add(SB_CTXPROP_HASH_ALGORITHM, GetOIDByAlgorithm(WinCtx.FHashAlgorithm));
    Pars.Add(SB_CTXPROP_USE_ALGORITHM_PREFIX, GetBufferFromBool(WinCtx.FInputIsHash));
    Pars.Add(SB_CTXPROP_HASH_FUNC_OID, WinCtx.FHashFuncOID);
    Pars.Add(SB_CTXPROP_ALGORITHM_SCHEME, SB_ALGSCHEME_OAEP);
  end;

begin
  Result := false;
  EstSize := TElWin32CryptoContext(Context).FKey.Bits shr 3 + 1;
  if (OutSize < EstSize) then
  begin
    OutSize := EstSize;
    Exit;
  end;
  WinCtx := TElWin32CryptoContext(Context);
  if not WinCtx.FKey.IsExportable then
    raise EElWin32CryptoProviderError.Create(SFailedToExportSecretKey);
  //Prov := DefaultCryptoProvider;
  Pars := TElCPParameters.Create();
  try
    SetupParams;
    Prov := ReturnCryptoProviderManager.GetSuitableProvider(SB_OPTYPE_DECRYPT, SB_ALGORITHM_PK_RSA,
      0, WinCtx.FKey, Pars);
    CryptoKey := Prov.CreateKey(SB_ALGORITHM_PK_RSA, 0);
    try
      Sz := 0;
      WinCtx.FKey.ExportSecret( nil , Sz);
      SetLength(KeyBlob, Sz);
      WinCtx.FKey.ExportSecret( @KeyBlob[0] , Sz);
      CryptoKey.ImportSecret( @KeyBlob[0] , Sz);
      Prov.Decrypt(SB_ALGORITHM_PK_RSA, 0, CryptoKey, Buffer, Size,
        OutBuffer, OutSize, Pars);
      Result := true;
    finally
      Prov.ReleaseKey(CryptoKey);
    end;
  finally
    FreeAndNil(Pars);
  end;
end;

function TElWin32CryptoProvider.TrySignHash(Context : TElCustomCryptoContext;
  Hash : HCRYPTHASH; KeySpec : DWORD; OutBuf : pointer;
  var OutBufSize : integer): boolean;
var
  Sz :  DWORD ;
  TmpBuf : ByteArray;
  TmpBufSize : integer;
  I : integer;
  BB : Byte;
begin
  Sz := 0;
  if FNativeSizeCalculation then
  begin
    Result := CryptSignHash(Hash, KeySpec, nil, 0, nil, @Sz);
  end
  else
  begin
    // setting enough output buffer size to fit the output of the signature
    Sz := SB_MAX_OPRESULT_SIZE;
    Result := true;
  end;
  if Result then
  begin
    if Context.Algorithm = SB_ALGORITHM_PK_DSA then
      Inc(Sz, 16);
    if OutBufSize < integer(Sz) then
    begin
      OutBufSize := Sz;
      Result := false;
    end
    else
    begin
      SetLength(TmpBuf, Sz);
      Result := CryptSignHash(Hash, KeySpec, nil, 0, @TmpBuf[0], @Sz);
      if not Result then
      begin
        FLastSigningErrorCode := GetLastError();
        FLastSigningError := Format(SWin32Error, [(FLastSigningErrorCode)]);
        OutBufSize := 0;
        Exit;
      end;

      if Context.Algorithm <> SB_ALGORITHM_PK_DSA then
      begin
        for I := 0 to Sz - 1 do
           PByteArray (OutBuf)[I] := TmpBuf[integer(Sz) - I - 1];
        OutBufSize := Sz;
      end
      else
      begin
        if Sz = 40 then
        begin
          for I := 0 to (Sz shr 1) - 1 do
          begin
            BB := TmpBuf[integer(Sz) - I - 1];
            TmpBuf[integer(Sz) - I - 1] := TmpBuf[I];
            TmpBuf[I] := BB;
          end;
          TmpBufSize := 0;
          SBDSA.EncodeSignature(@TmpBuf[20], 20, @TmpBuf[0], 20, nil, TmpBufSize);
          SetLength(TmpBuf, TmpBufSize);
          SBDSA.EncodeSignature(@TmpBuf[20], 20, @TmpBuf[0], 20, @TmpBuf[0], TmpBufSize);
          if TmpBufSize <= OutBufSize then
          begin
            SBMove(TmpBuf[0], OutBuf^, TmpBufSize);
            OutBufSize := TmpBufSize;
          end
          else
          begin
            OutBufSize := TmpBufSize;
            Result := false
          end;
        end
        else
        begin
          if integer(Sz) <= OutBufSize then
          begin
            OutBufSize := Sz;
            SBMove(TmpBuf[0], OutBuf^, OutBufSize);
          end
          else
          begin
            OutBufSize := Sz;
            Result := false;
          end;
        end;
      end;
    end;
  end
  else
    OutBufSize := 0;
end;

function TElWin32CryptoProvider.SignPKI(Context : TElCustomCryptoContext;
  Buffer: pointer; Size: integer; OutBuffer: pointer; var OutSize : integer): boolean;
var
  Ctx : TElWin32CryptoContext;
  Win32AlgID : cardinal;
  hHash: HCRYPTHASH;
  Prov, AESProv: HCRYPTPROV;
  CertContext: PCCERT_CONTEXT;
  Buf: pointer;
  ProvInfo: PCRYPT_KEY_PROV_INFO;
  PaddingInfoPtr : pointer;
  {$ifndef SB_UNICODE_VCL}
  LenProvName, LenContName: integer;
  ProvName, ContName: PAnsiChar;
   {$endif}
  {$ifdef SB_UNICODE_VCL}
  pwszProvName, pwszContName : PWideChar;
   {$endif}
  RealSize : integer;
  Sz:  DWORD ;
  CertBasedKey : boolean;
  ReleaseCtx : boolean;
  RealHash : ByteArray;
  KeySpec, AltKeySpec : DWORD;
  AESProvNeeded : boolean;
  HR : boolean;
  {$ifdef SB_HAS_CNG}  
  CNGKey : boolean;
  CNGKeyHandle : NCRYPT_KEY_HANDLE;
   {$endif}
  PaddingInfo : BCRYPT_PKCS1_PADDING_INFO;
  Win32AlgName : {$ifdef SB_ANSI_VCL}WideString {$else}string {$endif};
  Res, Pad : DWORD;
  {$ifdef SB_HAS_CNG}
  TmpUInt : DWORD;
   {$endif}
begin
  
  if not (Context is TElWin32CryptoContext) then
    raise EElWin32CryptoProviderError.Create(SInvalidContext);

  Ctx := TElWin32CryptoContext(Context);
  if Ctx.FUsePSS then
  begin
    Result := SignPKIPSS(Context, Buffer, Size,
      OutBuffer, OutSize);
    Exit;
  end;

  Result := false;
  FLastSigningError := '';
  FLastSigningErrorCode := 0;

  // see the comment in the implementation of the VerifyPKI() method for the details
  if not Ctx.FUseAlgorithmPrefix then
    RealHash := TryDecodeASN1EncodedHash( Buffer, Size , Ctx.FHashAlgorithm)
  else
    RealHash := CloneArray(Buffer, Size);

  KeySpec := 0;
  AltKeySpec := 0;
  ReleaseCtx := false;
  CertContext := nil;
  {$ifdef SB_HAS_CNG}
  CNGKey := false;
  CNGKeyHandle :=  nil ;
   {$endif}

  if TElWin32CryptoKey(Ctx.FKey).FCertContext <> nil then
  begin
    CertContext := TElWin32CryptoKey(Ctx.FKey).FCertContext;
    CertBasedKey := true;
  end
  else
    CertBasedKey := false;

  case Ctx.FHashAlgorithm of
    SB_ALGORITHM_DGST_SHA1 :
    begin
      Win32AlgID := CALG_SHA1;
      Win32AlgName := BCRYPT_SHA1_ALGORITHM;
    end;
    SB_ALGORITHM_DGST_MD2 :
    begin
      Win32AlgID := CALG_MD2;
      Win32AlgName := BCRYPT_MD2_ALGORITHM;
    end;
    SB_ALGORITHM_DGST_MD5 :
    begin
      Win32AlgID := CALG_MD5;
      Win32AlgName := BCRYPT_MD5_ALGORITHM;
    end;
    SB_ALGORITHM_DGST_SSL3 :
    begin
      Win32AlgID := CALG_SSL3_SHAMD5;
      Win32AlgName := '';
    end;
    SB_ALGORITHM_DGST_SHA256 :
    begin
      Win32AlgID := CALG_SHA_256;
      Win32AlgName := BCRYPT_SHA256_ALGORITHM;
    end;
    SB_ALGORITHM_DGST_SHA384 :
    begin
      Win32AlgID := CALG_SHA_384;
      Win32AlgName := BCRYPT_SHA384_ALGORITHM;
    end;
    SB_ALGORITHM_DGST_SHA512 :
    begin
      Win32AlgID := CALG_SHA_512;
      Win32AlgName := BCRYPT_SHA512_ALGORITHM;
    end;
  else
    raise EElWin32CryptoProviderError.CreateFmt(SUnsupportedHashAlgorithmInt, [(Ctx.FHashAlgorithm)]);
  end;
  AESProvNeeded := (Ctx.FHashAlgorithm = SB_ALGORITHM_DGST_SHA256) or
    (Ctx.FHashAlgorithm = SB_ALGORITHM_DGST_SHA384) or (Ctx.FHashAlgorithm = SB_ALGORITHM_DGST_SHA512);
  AESProv := 0;

  Prov := 0;
  if CertBasedKey then
  begin
    if (TElWin32CryptoProviderOptions(FOptions).FCacheKeyContexts) and (TElWin32CryptoKey(Ctx.FKey).FCachedProv <> 0) then
    begin
      Prov := TElWin32CryptoKey(Ctx.FKey).FCachedProv;
      if AESProvNeeded then
      begin
        AESProv := TElWin32CryptoKey(Ctx.FKey).FCachedAESProv;
        if AESProv = 0 then
        begin
          if TElWin32CryptoKey(Ctx.FKey).AcquireCertificateContextAES(AESProv) then
            TElWin32CryptoKey(Ctx.FKey).FCachedAESProv := AESProv;
        end;
      end;
      KeySpec := TElWin32CryptoKey(Ctx.FKey).FCachedKeySpec;
      if KeySpec = AT_SIGNATURE then
        AltKeySpec := AT_KEYEXCHANGE
      else
        AltKeySpec := AT_SIGNATURE;
      {$ifdef SB_HAS_CNG}
      CNGKey := TElWin32CryptoKey(Ctx.FKey).CachedIsCNGKey();
      CNGKeyHandle := TElWin32CryptoKey(Ctx.FKey).FCachedCNGKeyHandle;
       {$endif}
      ReleaseCtx := false;
    end
    else
    begin
      CertGetCertificateContextProperty(CertContext, CERT_KEY_PROV_INFO_PROP_ID,   nil  ,  @ Sz);
      GetMem(Buf, Sz);
      try
        if CertGetCertificateContextProperty(CertContext, CERT_KEY_PROV_INFO_PROP_ID, Buf,  @ Sz)  then
        begin
          ProvInfo := PCRYPT_KEY_PROV_INFO(Buf);
          if (ProvInfo.dwProvType <> 0) then // CryptoAPI ("legacy") key
          begin
            {$ifndef SB_UNICODE_VCL}
            if Length(TElWin32CryptoKey(Ctx.FKey).FUserProvName) = 0 then
              LenProvName := WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszProvName, -1, nil, 0, nil, nil)
            else
              LenProvName := Length(TElWin32CryptoKey(Ctx.FKey).FUserProvName) + 1;
            if Length(TElWin32CryptoKey(Ctx.FKey).FUserContName) = 0 then
              LenContName := WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszContainerName, -1, nil, 0, nil, nil)
            else
              LenContName := Length(TElWin32CryptoKey(Ctx.FKey).FUserContName) + 1;
            GetMem(ProvName, LenProvName);
            GetMem(ContName, LenContName);
             {$endif}
            try
              {$ifndef SB_UNICODE_VCL}
              if Length(TElWin32CryptoKey(Ctx.FKey).FUserProvName) = 0 then
                WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszProvName, -1, ProvName, LenProvName, nil, nil)
              else
                StrPCopy(ProvName, TElWin32CryptoKey(Ctx.FKey).FUserProvName);
              if Length(TElWin32CryptoKey(Ctx.FKey).FUserContName) = 0 then
                WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszContainerName, -1, ContName, LenContName, nil, nil)
              else
                StrPCopy(ContName, TElWin32CryptoKey(Ctx.FKey).FUserContName);


              if CryptAcquireContext(@Prov, ContName, ProvName, ProvInfo.dwProvType, ProvInfo.dwFlags {or
                CRYPT_SILENT}) then
               {$else}
              if Length(TElWin32CryptoKey(Ctx.FKey).FUserContName) = 0 then
                pwszContName := ProvInfo.pwszContainerName
              else
                pwszContName := PWideChar(TElWin32CryptoKey(Ctx.FKey).FUserContName);
              if Length(TElWin32CryptoKey(Ctx.FKey).FUserProvName) = 0 then
                pwszProvName := ProvInfo.pwszProvName
              else
                pwszProvName := PWideChar(TElWin32CryptoKey(Ctx.FKey).FUserProvName);
              if CryptAcquireContext(@Prov, pwszContName, pwszProvName,
                ProvInfo.dwProvType, ProvInfo.dwFlags) then
               {$endif}
              begin
                TElWin32CryptoKey(Ctx.FKey).SetProvPINs(Prov);
                ReleaseCtx := true;
              end
              else
              begin
              end;
              if AESProvNeeded then
              begin
                {$ifndef SB_UNICODE_VCL}
                CryptAcquireContext(@AESProv, ContName, nil, PROV_RSA_AES, ProvInfo.dwFlags);
                 {$else}
                CryptAcquireContext(@AESProv, pwszContName{ProvInfo.pwszContainerName}, nil, PROV_RSA_AES, ProvInfo.dwFlags);
                 {$endif}
                if AESProv <> 0 then
                  TElWin32CryptoKey(Ctx.FKey).SetProvPINs(AESProv);
              end;
            finally
              {$ifndef SB_UNICODE_VCL}
              FreeMem(ProvName);
              FreeMem(ContName);
               {$endif}
            end;
            KeySpec := ProvInfo.dwKeySpec;
            if KeySpec = AT_SIGNATURE then
              AltKeySpec := AT_KEYEXCHANGE
            else
              AltKeySpec := AT_SIGNATURE;
          end
          {$ifdef SB_HAS_CNG}  
          else // CNG key
          begin
            if CNGCryptoProviderHandleManager().OpenCNGStorageProvider( Prov , ProvInfo.pwszProvName, 0) = ERROR_SUCCESS then
            begin
              if NCryptOpenKey(NCRYPT_PROV_HANDLE(Prov),  @ CNGKeyHandle, ProvInfo.pwszContainerName, 0, ProvInfo.dwFlags) = ERROR_SUCCESS then
              begin
                TElWin32CryptoKey(Ctx.FKey).SetProvPINs(Prov);
                CNGKey := true;
                ReleaseCtx := true;
              end
              else
              begin
                CNGCryptoProviderHandleManager().FreeCNGStorageProvider(Prov);
                Prov := 0;
              end;
            end;
          end
         {$endif}
        ;
        end;
      finally
        FreeMem(Buf);
      end;
    end;
  end
  else
  begin
    {$ifdef SB_HAS_CNG}
    CNGKey := TElWin32CryptoKey(Ctx.FKey).IsCNGKey();
     {$endif}
    Prov := TElWin32CryptoKey(Ctx.FKey).FProv;

    if AESProvNeeded then
    begin
      AESProv := TElWin32CryptoKey(Ctx.FKey).FCachedAESProv;
      if AESProv = 0 then
      begin
        if TElWin32CryptoKey(Ctx.FKey).AcquireKeyContextAES(AESProv) then
          TElWin32CryptoKey(Ctx.FKey).FCachedAESProv := AESProv;
      end;
    end;

    {$ifdef SB_HAS_CNG}
    if CNGKey then
      CNGKeyHandle := TElWin32CryptoKey(Ctx.FKey).FCNGKeyHandle
    else
     {$endif}
    begin
      KeySpec := AT_KEYEXCHANGE;
      AltKeySpec := AT_SIGNATURE;
    end;
  end;

  if (Prov = 0) then
  begin
    if (AESProv <> 0) then
    begin
      CryptReleaseContext(AESProv, 0);
    end;
    FLastSigningError := SFailedToAcquireKeyContext;
    Exit;
  end;
  try
    {$ifdef SB_HAS_CNG}
    if not CNGKey then
     {$endif}
    begin
      if FWindowHandle <> 0 then
      begin
        if CryptSetProvParam(Prov, PP_CLIENT_HWND, Windows.PByte(@FWindowHandle), 0) then
          FWindowHandle := FWindowHandle and $ffffffff;
      end;
      HR := CryptCreateHash(Prov, Win32AlgID, 0, 0,  @ hHash) ;
      if (not HR) and (AESProvNeeded) and (AESProv <> 0) then
        HR := CryptCreateHash(AESProv, Win32AlgID, 0, 0,  @ hHash) ;
      if HR then
      begin
        if CryptSetHashParam(hHash, HP_HASHVAL, @RealHash[0], 0) then
        begin
          RealSize := OutSize;
          Result := TrySignHash(Context, hHash, KeySpec, OutBuffer, OutSize);
          if (not Result) and (OutSize = 0) and
            (FLastSigningErrorCode <> ERROR_CANCELLED) and
            (TElWin32CryptoProviderOptions(FOptions).FTryAlternativeKeySpecOnFailure) then
          begin
            OutSize := RealSize;
            Result := TrySignHash(Context, hHash, AltKeySpec, OutBuffer, OutSize);
          end;
        end;
        CryptDestroyHash(hHash);
      end
      else
      begin
        FLastSigningErrorCode := GetLastError();
        FLastSigningError := Format(SWin32Error, [(FLastSigningErrorCode)]);
      end;
    end
    {$ifdef SB_HAS_CNG}
    else // CNG key
    begin
      // TODO: Window handle assignment
      // TODO: PaddingInfo: add support for non-existing algorithm prefix
      PaddingInfo.pszAlgId := @Win32AlgName[StringStartOffset];
      if Ctx.FUseAlgorithmPrefix then
      begin
        Pad := BCRYPT_PAD_PKCS1;
        PaddingInfoPtr := @PaddingInfo;
      end
      else
      begin
        Pad := BCRYPT_PAD_NONE;
        PaddingInfoPtr := nil;
      end;
      Res := NCryptSignHash(CNGKeyHandle, @PaddingInfo, @RealHash[0], Length(RealHash),
        OutBuffer, OutSize, @RealSize, Pad);
      if Res <> ERROR_SUCCESS then
      begin
        FLastSigningErrorCode := Res;
        FLastSigningError := Format(SWin32Error, [(Res)]);
      end
      else
      begin
        OutSize := RealSize;
        Result := true;
      end;
    end
     {$endif}
    ;
  finally
    if (TElWin32CryptoProviderOptions(FOptions).FCacheKeyContexts) and (TElWin32CryptoKey(Ctx.FKey).FCachedProv = 0) and
      (ReleaseCtx) then
    begin
      // caching the obtained context
      TElWin32CryptoKey(Ctx.FKey).FCachedProv := Prov;
      TElWin32CryptoKey(Ctx.FKey).FCachedKeySpec := KeySpec;
      TElWin32CryptoKey(Ctx.FKey).FCachedAESProv := AESProv;
      {$ifdef SB_HAS_CNG}
      TElWin32CryptoKey(Ctx.FKey).FCachedCNGKeyHandle := CNGKeyHandle;
       {$endif}
    end
    else
    begin
      if ReleaseCtx then
      begin
       	{$ifdef SB_HAS_CNG}
        if not CNGKey then
       	 {$endif}
        begin
          if Prov <> 0 then
            CryptReleaseContext(Prov, 0);
        end
       	{$ifdef SB_HAS_CNG}
        else
        begin
          NCryptFreeObject(CNGKeyHandle);
          CNGCryptoProviderHandleManager().FreeCNGStorageProvider(Prov);
        end
       	 {$endif};
      end;
      if TElWin32CryptoProviderOptions(FOptions).FCacheKeyContexts then
        TElWin32CryptoKey(Ctx.FKey).FCachedAESProv := AESProv
      else
      begin
        if AESProv <> 0 then
          CryptReleaseContext(AESProv, 0);
      end;
    end;
  end;
end;

function TElWin32CryptoProvider.TryDecodeASN1EncodedHash( HashBuffer : pointer; HashSize : integer ;
  var DefHashAlgorithm : integer): ByteArray;
var
  Tag, Seq : TElASN1ConstrainedTag;
  AlgID, AlgPars : ByteArray;
  Alg : integer;
begin
  Result := CloneArray(HashBuffer,  HashSize );
  Tag := TElASN1ConstrainedTag.CreateInstance();
  try
    if not Tag.LoadFromBuffer(HashBuffer , HashSize ) then
      Exit;
    if (Tag.Count <> 1) or (not Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      Exit;
    Seq := TElASN1ConstrainedTag(Tag.GetField(0));
    if (Seq.Count <> 2) or (not Seq.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) or
      (not Seq.GetField(1).CheckType(SB_ASN1_OCTETSTRING, false)) then
      Exit;
    if ProcessAlgorithmIdentifier(Seq.GetField(0), AlgID, AlgPars) <> 0 then
      Exit;
    Alg := GetAlgorithmByOID(AlgID, true);
    if not IsHashAlgorithm(Alg) then
      Alg := GetHashAlgorithmBySigAlgorithm(Alg);
    // assigning the default algorithm only if we 'know' the algorithm contained
    // in the prefix
    if Alg <> SB_ALGORITHM_UNKNOWN then
      DefHashAlgorithm := Alg;
    Result := TElASN1SimpleTag(Seq.GetField(1)).Content;
  finally
    FreeAndNil(Tag);
  end;
end;

function TElWin32CryptoProvider.VerifyPKI(Context : TElCustomCryptoContext; HashBuffer : pointer;
  HashSize: integer; SigBuffer : pointer; SigSize : integer): integer;
var
  Ctx : TElWin32CryptoContext;
  Sig : ByteArray;
  I : integer;
  R, S : ByteArray;
  RSize, SSize : integer;
  Len : integer;
  Win32AlgID : cardinal;
  hHash : HCRYPTHASH;
  Err : integer;
  KeyHandle : HCRYPTKEY;
  Res : integer;
  Prov : HCRYPTPROV;
  ReleaseProv : boolean;
  ReleaseKey : boolean;
  RealHash : ByteArray;
  KS, AltKS : DWORD;
begin
  if not (Context is TElWin32CryptoContext) then
    raise EElWin32CryptoProviderError.Create(SInvalidContext);

  Result := SB_VR_FAILURE;

  Ctx := TElWin32CryptoContext(Context);

  // converting signature value to CryptoAPI format
  if Context.Algorithm <> SB_ALGORITHM_PK_DSA then
  begin
    // rotating signature value
    SetLength(Sig, SigSize);
    for I := 0 to SigSize - 1 do
      Sig[I] := PByteArray(SigBuffer)[SigSize - I - 1];
    // ---On the use of FUseAlgorithmPrefix field---
    // (set by the SB_CTXPROP_USE_ALGORITHM_PREFIX context property)
    // This context property is set to true (the default value) if the using
    // class wants the cryptoprovider to prepend the OID of the hash algorithm
    // to the hash value being signed.
    // This property can be set to false in two cases: (a) the using code needs
    // to omit the prefix in the signature at all, (b) the using code has added the
    // prefix to the hash before passing it to cryptoprovider, so the prefix
    // does not need to be added by the cryptoprovider.
    // To handle both situations correctly (as we need to assign the exact hash
    // value to Win32 HCRYPTHASH object), we analyse the structure of the provided
    // hash value and check if it fits the DigestInfo ASN.1 structure
    // defined in the declaration of the EMSA-PKCS1-v1_5-ENCODE encoding method.
    if not Ctx.FUseAlgorithmPrefix then
      RealHash := TryDecodeASN1EncodedHash(HashBuffer,  HashSize,  Ctx.FHashAlgorithm)
    else
      RealHash := CloneArray(HashBuffer,  HashSize );
  end
  else
  begin
    RSize := 0;
    SSize := 0;
    SBDSA.DecodeSignature(SigBuffer, SigSize, nil, RSize, nil, SSize);
    SetLength(R, RSize);
    SetLength(S, SSize);
    if not SBDSA.DecodeSignature(SigBuffer, SigSize, @R[0], RSize, @S[0], SSize) then
      raise EElWin32CryptoProviderError.Create(SBadSignatureFormatting);
    R := TrimParam(R);
    S := TrimParam(S);
    SetLength(Sig, 40);
    FillChar(Sig[0], Length(Sig), 0);
    Len := Length(R);
    for I := 0 to Len - 1 do
      Sig[I] := R[Len - I - 1];
    Len := Length(S);
    for I := 0 to Len - 1 do
      Sig[20 + I] := S[Len - I - 1];
    RealHash := CloneArray(HashBuffer , HashSize );
  end;
  // creating hash object
  case Ctx.FHashAlgorithm of
    SB_ALGORITHM_DGST_SHA1 : Win32AlgID := CALG_SHA1;
    SB_ALGORITHM_DGST_MD2 : Win32AlgID := CALG_MD2;
    SB_ALGORITHM_DGST_MD5 : Win32AlgID := CALG_MD5;
    SB_ALGORITHM_DGST_SSL3 : Win32AlgID := CALG_SSL3_SHAMD5;
    SB_ALGORITHM_DGST_SHA256 : Win32AlgID := CALG_SHA_256;
    SB_ALGORITHM_DGST_SHA384 : Win32AlgID := CALG_SHA_384;
    SB_ALGORITHM_DGST_SHA512 : Win32AlgID := CALG_SHA_512;
  else
    raise EElWin32CryptoProviderError.CreateFmt(SUnsupportedHashAlgorithmInt, [(Ctx.FHashAlgorithm)]);
  end;
  Err := 0;
  // checking if the provider is acquired (raw keys)
  Prov := TElWin32CryptoKey(Ctx.FKey).FProv;
  if Prov <> 0 then
  begin
    ReleaseProv := false;
    KS := TElWin32CryptoKey(Ctx.FKey).FCachedKeySpec;
    if not (KS in [AT_SIGNATURE, AT_KEYEXCHANGE]) then
      KS := AT_SIGNATURE;
  end
  else
  begin
    // acquiring provider (certificates)
    TElWin32CryptoKey(Ctx.FKey).AcquireCertificateContextPub(Prov);
    KS := TElWin32CryptoKey(Ctx.FKey).FLastPubKeySpec;
    ReleaseProv := true;
  end;
  if KS = AT_SIGNATURE then
    AltKS := AT_KEYEXCHANGE
  else
    AltKS := AT_SIGNATURE;
  try
    if CryptCreateHash(Prov, Win32AlgID, 0, 0,  @ hHash)  then
    begin
      try
        if CryptSetHashParam(hHash, HP_HASHVAL, @RealHash[0], 0) then
        begin
          KeyHandle := TElWin32CryptoKey(Ctx.FKey).FHandle;
          if KeyHandle <> 0 then
            ReleaseKey := false
          else
          begin
            // no key handle available (certificates)
            KeyHandle := 0;
            if not (CryptGetUserKey(Prov, KS,  @ KeyHandle) ) then
            begin
              if not (CryptGetUserKey(Prov, AltKS,  @ KeyHandle) ) then
                KeyHandle := 0;         
            end;
            ReleaseKey := KeyHandle <> 0;
          end;
          try
            if CryptVerifySignature(hHash, @Sig[0], Length(Sig), KeyHandle, nil, 0) then
              Result := SB_VR_SUCCESS
            else
            begin
              Res := GetLastError();
              if cardinal(Res) = NTE_BAD_SIGNATURE then
                Result := SB_VR_INVALID_SIGNATURE
              else
                Err := Res;
            end;
          finally
            if ReleaseKey then
              CryptDestroyKey(KeyHandle);
          end;
        end
        else
        begin
          Err := GetLastError();
        end;
      finally
        CryptDestroyHash(hHash);
      end;
    end
    else
    begin
      Err := GetLastError();
    end;
  finally
    if ReleaseProv then
    begin
      if Prov <> 0 then
        CryptReleaseContext(Prov, 0);
    end;
  end;

  if Err <> 0 then
    raise EElWin32CryptoProviderError.CreateFmt(SWin32Error, [(Err)]);
end;

function TElWin32CryptoProvider.SignPKIPSS(Context : TElCustomCryptoContext;
  Buffer: pointer; Size: integer; OutBuffer: pointer; var OutSize : integer): boolean;
var
  CryptoKey : TElCustomCryptoKey;
  Prov : TElCustomCryptoProvider;
  Sz : integer;
  KeyBlob : ByteArray;
  Pars : TElCPParameters;
  WinCtx : TElWin32CryptoContext;
  EstSize : integer;

  procedure SetupParams;
  begin
    Pars.Add(SB_CTXPROP_USE_ALGORITHM_PREFIX, GetBufferFromBool(true));
    Pars.Add(SB_CTXPROP_HASH_ALGORITHM, GetOIDByAlgorithm(WinCtx.FHashAlgorithm));
    Pars.Add(SB_CTXPROP_INPUT_IS_HASH, GetBufferFromBool(true));
    Pars.Add(SB_CTXPROP_HASH_FUNC_OID, WinCtx.FHashFuncOID);
    Pars.Add(SB_CTXPROP_ALGORITHM_SCHEME, SB_ALGSCHEME_PSS);
  end;

begin
  Result := false;
  EstSize := TElWin32CryptoContext(Context).FKey.Bits shr 3 + 1;
  if (OutSize < EstSize) then
  begin
    OutSize := EstSize;
    Exit;
  end;
  WinCtx := TElWin32CryptoContext(Context);
  if not WinCtx.FKey.IsExportable then
    raise EElWin32CryptoProviderError.Create(SFailedToExportSecretKey);
  //Prov := DefaultCryptoProvider;
  Pars := TElCPParameters.Create();
  try
    SetupParams;
    Prov := ReturnCryptoProviderManager.GetSuitableProvider(SB_OPTYPE_SIGN_DETACHED,
      SB_ALGORITHM_PK_RSA, 0, WinCtx.FKey, Pars);
    CryptoKey := Prov.CreateKey(SB_ALGORITHM_PK_RSA, 0);
    try
      Sz := 0;
      WinCtx.FKey.ExportSecret( nil , Sz);
      SetLength(KeyBlob, Sz);
      WinCtx.FKey.ExportSecret( @KeyBlob[0] , Sz);
      CryptoKey.ImportSecret( @KeyBlob[0] , Sz);
      Prov.Sign(SB_ALGORITHM_PK_RSA, CryptoKey, true, Buffer, Size,
        OutBuffer, OutSize, Pars);
      Result := true;
    finally
      Prov.ReleaseKey(CryptoKey);
    end;
  finally
    FreeAndNil(Pars);
  end;
end;

class procedure TElWin32CryptoProvider.SetAsDefault;
begin
  DoSetAsDefault(TElWin32CryptoProvider);
end;

function TElWin32CryptoProvider.GetDefaultInstance : TElCustomCryptoProvider;
begin
  if Win32CryptoProv = nil then
  begin
    Win32CryptoProv := TElWin32CryptoProvider.Create( nil );
    RegisterGlobalObject(Win32CryptoProv);
  end;
  Result := Win32CryptoProv;
end;

function TElWin32CryptoProvider.CreateOptions : TElCustomCryptoProviderOptions;
begin
  Result := TElWin32CryptoProviderOptions.Create();
end;

function TElWin32CryptoProvider.AddProviderInfo(Handle : HCRYPTPROV; const Name : string;
  FIPSCompliant : boolean): boolean;
var
  ProvInfo : TElWin32ProviderInfo;
begin
  ProvInfo := TElWin32ProviderInfo.Create();
  Result := ProvInfo.Init(Handle, Name, true, FIPSCompliant);
  if Result then
    FProviderInfos.Add(ProvInfo)
  else
  begin
    FreeAndNil(ProvInfo);
  end;
end;

procedure TElWin32CryptoProvider.RefreshProviderInfos;
var
  Ops : TElWin32CryptoProviderOptions;
begin
  ClearProviderInfos;
  Ops := TElWin32CryptoProviderOptions(Options);
  // adding default CSPs
  if Ops.FUseBaseCSP then
    AddProviderInfo(PROV_RSA_FULL, MS_DEF_PROV, false);
  if Ops.FUseStrongCSP then
    AddProviderInfo(PROV_RSA_FULL, MS_STRONG_PROV, false);
  if Ops.FUseEnhancedCSP then
    AddProviderInfo(PROV_RSA_FULL, MS_ENHANCED_PROV, true);
  if Ops.FUseAESCSP then
  begin
    if not AddProviderInfo(PROV_RSA_AES, MS_ENH_RSA_AES_PROV, true) then
      AddProviderInfo(PROV_RSA_AES, MS_ENH_RSA_AES_PROV_XP, true)
  end;
  if Ops.FUseDSSCSP then
    AddProviderInfo(PROV_DSS, MS_DEF_DSS_PROV, false);
  if Ops.FUseBaseDSSDHCSP then
    AddProviderInfo(PROV_DSS_DH, MS_DEF_DSS_DH_PROV, false);
  if Ops.FUseEnhancedDSSDHCSP then
    AddProviderInfo(PROV_DSS_DH, MS_ENH_DSS_DH_PROV, true);
  if Ops.FUseRSASchannelCSP then
    AddProviderInfo(PROV_RSA_SCHANNEL, MS_DEF_RSA_SCHANNEL_PROV, false);
  if Ops.FUseRSASignatureCSP then
    AddProviderInfo(PROV_RSA_SIG, MS_DEF_RSA_SIG_PROV, false);
  if Ops.FUseECDSASigCSP then
    AddProviderInfo(PROV_EC_ECDSA_SIG, '', false);
  if Ops.FUseECNRASigCSP then
    AddProviderInfo(PROV_EC_ECNRA_SIG, '', false);
  if Ops.FUseECDSAFullCSP then
    AddProviderInfo(PROV_EC_ECDSA_FULL, '', false);
  if Ops.FUseECNRAFullCSP then
    AddProviderInfo(PROV_EC_ECNRA_FULL, '', false);
  if Ops.FUseDHSchannelCSP then
    AddProviderInfo(PROV_DH_SCHANNEL, MS_DEF_DH_SCHANNEL_PROV, false);
  if Ops.FUseCPGOST then
  begin
    AddProviderInfo(PROV_GOST_94_DH, CP_GR3410_94_PROV, false);
    AddProviderInfo(PROV_GOST_2001_DH, CP_GR3410_2001_PROV, false);
    {AddProviderInfo(PROV_GOST_94_DH, CP_GOST_R3410_1994_KC1_PROV, false);
    AddProviderInfo(PROV_GOST_94_DH, CP_GOST_R3410_1994_KC2_PROV, false);
    AddProviderInfo(PROV_GOST_2001_DH, CP_GOST_R3410_2001_KC1_PROV, false);
    AddProviderInfo(PROV_GOST_2001_DH, CP_GOST_R3410_2001_KC2_PROV, false);}   
  end;  
end;

procedure TElWin32CryptoProvider.ClearProviderInfos;
var
  I : integer;
begin
  for I := 0 to FProviderInfos.Count - 1 do
    TElWin32ProviderInfo(FProviderInfos[I]). Free ;
  FProviderInfos.Clear;
end;

function TElWin32CryptoProvider.ReturnCryptoProviderManager: TElCustomCryptoProviderManager;
begin
  if FCryptoProviderManager <> nil then
    Result := FCryptoProviderManager
  else
    Result := DefaultCryptoProviderManager;
end;

////////////////////////////////////////////////////////////////////////////////
// TElWin32CryptoContext class

constructor TElWin32CryptoContext.Create(Algorithm : integer; Mode : integer;
  Key : TElCustomCryptoKey; Operation : TSBWin32CryptoContextOperation;
  Prov : TElCustomCryptoProvider; Params : TElCPParameters);
begin
  inherited Create;
  FKey := Key;
  FAlgorithm := Algorithm;
  FOperation := Operation;
  FProvider := Prov;
  FUseOAEP := false;
  FUsePSS := false;
  FProvHandle := 0;
  FHashHandle := 0;
  FExtraHashHandle := 0;
  FKeyHandle := 0;
  FHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
  SetLength(FSpool, 0);
  SetLength(FOtherSpool, 0);
  FOperationDone := false;
  FOperationResult := SB_VR_FAILURE;
  FPadding := SB_SYMENC_PADDING_PKCS5;
  FUseAlgorithmPrefix := true;
  FSecCriticalDisposed := false;
  Init(Params);
end;

constructor TElWin32CryptoContext.Create(const AlgOID, AlgParams : ByteArray;
  Mode : integer; Key : TElCustomCryptoKey; Operation : TSBWin32CryptoContextOperation;
  Prov : TElCustomCryptoProvider; Params : TElCPParameters);
var
  Alg : integer;
begin
  inherited Create;
  Alg := GetAlgorithmByOID(AlgOID, true);
  FKey := Key;
  FAlgorithm := Alg;
  FOperation := Operation;
  FProvider := Prov;
  FUseOAEP := false;
  FUsePSS := false;
  FProvHandle := 0;
  FHashHandle := 0;
  FExtraHashHandle := 0;
  FKeyHandle := 0;
  FHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
  SetLength(FSpool, 0);
  SetLength(FOtherSpool, 0);
  FOperationDone := false;
  FOperationResult := SB_VR_FAILURE;
  FPadding := SB_SYMENC_PADDING_PKCS5;
  FUseAlgorithmPrefix := true;
  FSecCriticalDisposed := false;
  Init(Params);
end;

destructor TElWin32CryptoContext.Destroy;
begin
  if Assigned(FHashContext) and Assigned(FHashContext.CryptoProvider) then
    FHashContext.CryptoProvider.ReleaseCryptoContext(FHashContext);
  if FHashHandle <> 0 then
    CryptDestroyHash(FHashHandle);
  if FExtraHashHandle <> 0 then
    CryptDestroyHash(FExtraHashHandle);
  if FKeyHandle <> 0 then
    CryptDestroyKey(FKeyHandle);
  inherited;
end;


procedure TElWin32CryptoContext.Init(Params : TElCPParameters);
var
  I : integer;
begin
  if IsPublicKeyAlgorithm(FAlgorithm) then
    FContextType := cctPKICrypto
  else if IsSymmetricKeyAlgorithm(FAlgorithm) then
    FContextType := cctSymCrypto
  else if IsHashAlgorithm(FAlgorithm) or IsMACAlgorithm(FAlgorithm) then
    FContextType := cctHash
  else
    FContextType := cctUndefined;
  if Params <> nil then
  begin
    for I := 0 to Params.Count - 1 do
      SetContextProp(Params.OIDs[I], Params.Values[I]);
  end;
  FHashContext := nil;
  PrepareOperation();
end;

procedure TElWin32CryptoContext.PrepareOperation();
var
  HelperProv : TElCustomCryptoProvider;
  keyCopy : HCRYPTKEY;
begin
  if (FOperation in [ccoSignDetached,
    ccoVerifyDetached]) and (not FInputIsHash) then
  begin
    HelperProv := TElWin32CryptoProvider(FProvider).ReturnCryptoProviderManager.GetSuitableProvider(SB_OPTYPE_HASH,
      FHashAlgorithm, 0, nil, nil);
    FHashContext := HelperProv.HashInit(FHashAlgorithm, nil, nil)
  end;
  if (FContextType in [cctSymCrypto,
    cctHash]) and (FKey <> nil) and
    (FKey is TElWin32CryptoKey) and (TElWin32CryptoKey(FKey).FHandle <> 0) then
  begin
    // creating a copy of the passed key
    if not (CryptDuplicateKey(TElWin32CryptoKey(FKey).FHandle,  nil , 0, keyCopy) ) then
      raise EElWin32CryptoProviderError.CreateFmt(SWin32Error, [(GetLastError())]);
    FKeyHandle := keyCopy;
  end;
end;

function TElWin32CryptoContext.GetAlgorithm : integer;
begin
  Result := FAlgorithm;
end;

function TElWin32CryptoContext.GetAlgorithmClass : integer;
begin
  Result := FProvider.GetAlgorithmClass(FAlgorithm);
end;

function TElWin32CryptoContext.EstimateOutputSize(InSize: Int64): Int64;
begin
  // TODO (low priority): just a stub
  Result := {InSize}SB_MAX_OPRESULT_SIZE + 256;
end;

function TElWin32CryptoContext.GetKeySize : integer;
begin
  if Assigned(FKey) then
    Result := FKey.Bits
  else
    Result := 0;
end;

procedure TElWin32CryptoContext.SetKeySize(Value: integer);
begin
  raise EElWin32CryptoProviderError.Create(SCannotModifyReadonlyProperty);
end;

function TElWin32CryptoContext.GetBlockSize : integer;
var
  Data : DWORD;
  DataLen :  DWORD ;
begin
  if (FKey is TElWin32CryptoKey) and (TElWin32CryptoKey(FKey).FHandle <> 0) then
  begin
    DataLen := 4;
    if CryptGetKeyParam(TElWin32CryptoKey(FKey).FHandle, KP_BLOCKLEN, @Data, @DataLen, 0) then
      Result :=  Data  shr 3
    else
      Result := 0;
  end
  else
    Result := 0;
end;

procedure TElWin32CryptoContext.SetBlockSize(Value: integer);
begin
  raise EElWin32CryptoProviderError.Create(SCannotModifyReadonlyProperty);
end;

function TElWin32CryptoContext.GetDigestSize : integer;
begin
  raise EElWin32CryptoProviderError.Create(SFeatureNotAvailable);
end;

procedure TElWin32CryptoContext.SetDigestSize(Value : integer);
begin
  raise EElWin32CryptoProviderError.Create(SFeatureNotAvailable);
end;

function TElWin32CryptoContext.GetMode : integer;
begin
  Result := 0;
end;

procedure TElWin32CryptoContext.SetMode(Value : integer);
begin
  raise EElWin32CryptoProviderError.Create(SCannotModifyReadonlyProperty);
end;

function TElWin32CryptoContext.GetPadding : integer;
begin
  Result := FPadding;//SB_SYMENC_PADDING_PKCS5;
end;

procedure TElWin32CryptoContext.SetPadding(Value : integer);
begin
  if FContextType = cctSymCrypto then
    FPadding := Value
  else
    raise EElWin32CryptoProviderError.Create(SNotASymmetricCipherContext);
end;

function TElWin32CryptoContext.GetContextProp(const PropID : ByteArray; const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =  nil {$endif}): ByteArray;
begin
  if CompareContent(PropID, SB_CTXPROP_USE_ALGORITHM_PREFIX) then
    Result := GetBufferFromBool(true)
  else if CompareContent(PropID, SB_CTXPROP_HASH_ALGORITHM) then
    Result := GetOIDByAlgorithm(FHashAlgorithm)
  else if CompareContent(PropID, SB_CTXPROP_INPUT_IS_HASH) then
    Result := GetBufferFromBool(FInputIsHash)
  else if CompareContent(PropID, SB_CTXPROP_HASH_FUNC_OID) then
    Result := CloneArray(FHashFuncOID)
  else if CompareContent(PropID, SB_CTXPROP_ALGORITHM_SCHEME) then
  begin
    if FUseOAEP then
      Result := SB_ALGSCHEME_OAEP
    else if FUsePSS then
      Result := SB_ALGSCHEME_PSS
    else
      Result := SB_ALGSCHEME_PKCS1;
  end
  else
    Result := Default;
end;

procedure TElWin32CryptoContext.SetContextProp(const PropID : ByteArray; const Value : ByteArray);
begin
  if CompareContent(PropID, SB_CTXPROP_HASH_ALGORITHM) then
  begin
    if Length(Value) > 0 then
      FHashAlgorithm := GetAlgorithmByOID(Value);
  end
  else if CompareContent(PropID, SB_CTXPROP_INPUT_IS_HASH) then
  begin
    FInputIsHash := GetBoolFromBuffer(Value);
  end
  else if CompareContent(PropID, SB_CTXPROP_HASH_FUNC_OID) then
  begin
    FHashFuncOID := CloneArray(Value);
  end
  else if CompareContent(PropID, SB_CTXPROP_USE_ALGORITHM_PREFIX) then
  begin
    // a comment to this field can be found in the implementation of VerifyPKI() method
    FUseAlgorithmPrefix := GetBoolFromBuffer(Value);
  end
  else if CompareContent(PropID, SB_CTXPROP_PADDING_TYPE) then
  begin
    if (FContextType = cctSymCrypto) then
    begin
      if CompareContent(Value, SB_ALGSCHEME_PKCS5) then
        Padding := SB_SYMENC_PADDING_PKCS5
      else
      if Length(Value) = 0 then
        Padding := SB_SYMENC_PADDING_NONE
      else
        raise EElWin32CryptoProviderError.CreateFmt(SUnsupportedPropertyValue, 
          [ BinaryToString(Value) ]);
    end
    else
      raise EElWin32CryptoProviderError.Create(SNotASymmetricCipherContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_ALGORITHM_SCHEME) then
  begin
    if CompareContent(Value, SB_ALGSCHEME_PKCS1) then
    begin
      FUsePSS := false;
      FUseOAEP := false;
    end
    else if CompareContent(Value, SB_ALGSCHEME_OAEP) then
    begin
      FUsePSS := false;
      FUseOAEP := true;
    end
    else if CompareContent(Value, SB_ALGSCHEME_PSS) then
    begin
      FUsePSS := true;
      FUseOAEP := false;
    end
    else
      raise EElWin32CryptoProviderError.CreateFmt(SUnsupportedPropertyValue, [ BinaryToString(Value) ]);
  end;
end;

function TElWin32CryptoContext.Clone(Params : TElCPParameters  =  nil): TElCustomCryptoContext;
begin
  raise EElWin32CryptoProviderError.Create(SCannotCloneContext);
end;

////////////////////////////////////////////////////////////////////////////////
// TElWin32CryptoProviderOptions class

procedure TElWin32CryptoProviderOptions.Init;
begin
  inherited;
  FUseForPublicKeyOperations := true;
  FUseForSymmetricKeyOperations := false;
  FUseForHashingOperations := false;
  FUseForNonPrivateOperations := false;
  FThreadSafe := false;
  FUseBaseCSP := true;
  FUseStrongCSP := true;
  FUseEnhancedCSP := true;
  FUseAESCSP := true;
  FUseDSSCSP := true;
  FUseBaseDSSDHCSP := true;
  FUseEnhancedDSSDHCSP := true;
  FUseRSASchannelCSP := true;
  FUseRSASignatureCSP := false;
  FUseECDSASigCSP := false;
  FUseECNRASigCSP := false;
  FUseECDSAFullCSP := false;
  FUseECNRAFullCSP := false;
  FUseDHSchannelCSP := true;
  FUseCPGOST := true;
  FFIPSMode := false;
  FCacheKeyContexts := false;
  FStorePublicKeysInMemoryContainers := true;
  FForceEnhancedCSPForLongKeys := false;
  FAutoSelectEnhancedCSP := true;
  FTryAlternativeKeySpecOnFailure := true;
  FGenerateExportablePrivateKeys := false;
  FUseLocalMachineAccount := false;
end;

procedure TElWin32CryptoProviderOptions.Assign(Options : TElCustomCryptoProviderOptions);
begin
  inherited;
  if Options is TElWin32CryptoProviderOptions then
  begin
    FUseForPublicKeyOperations := TElWin32CryptoProviderOptions(Options).FUseForPublicKeyOperations;
    FUseForSymmetricKeyOperations := TElWin32CryptoProviderOptions(Options).FUseForSymmetricKeyOperations;
    FUseForHashingOperations := TElWin32CryptoProviderOptions(Options).FUseForHashingOperations;
    FUseForNonPrivateOperations := TElWin32CryptoProviderOptions(Options).FUseForNonPrivateOperations;
    FThreadSafe := TElWin32CryptoProviderOptions(Options).FThreadSafe;
    FUseBaseCSP := TElWin32CryptoProviderOptions(Options).FUseBaseCSP;
    FUseStrongCSP := TElWin32CryptoProviderOptions(Options).FUseStrongCSP;
    FUseEnhancedCSP := TElWin32CryptoProviderOptions(Options).FUseEnhancedCSP;
    FUseAESCSP := TElWin32CryptoProviderOptions(Options).FUseAESCSP;
    FUseDSSCSP := TElWin32CryptoProviderOptions(Options).FUseDSSCSP;
    FUseBaseDSSDHCSP := TElWin32CryptoProviderOptions(Options).FUseBaseDSSDHCSP;
    FUseEnhancedDSSDHCSP := TElWin32CryptoProviderOptions(Options).FUseEnhancedDSSDHCSP;
    FUseRSASchannelCSP := TElWin32CryptoProviderOptions(Options).FUseRSASchannelCSP;
    FUseRSASignatureCSP := TElWin32CryptoProviderOptions(Options).FUseRSASignatureCSP;
    FUseECDSASigCSP := TElWin32CryptoProviderOptions(Options).FUseECDSASigCSP;
    FUseECNRASigCSP := TElWin32CryptoProviderOptions(Options).FUseECNRASigCSP;
    FUseECDSAFullCSP := TElWin32CryptoProviderOptions(Options).FUseECDSAFullCSP;
    FUseECNRAFullCSP := TElWin32CryptoProviderOptions(Options).FUseECNRAFullCSP;
    FUseDHSchannelCSP := TElWin32CryptoProviderOptions(Options).FUseDHSchannelCSP;
    FUseCPGOST := TElWin32CryptoProviderOptions(Options).FUseCPGOST;
    FFIPSMode := TElWin32CryptoProviderOptions(Options).FFIPSMode;
    FCacheKeyContexts := TElWin32CryptoProviderOptions(Options).FCacheKeyContexts;
    FStorePublicKeysInMemoryContainers := TElWin32CryptoProviderOptions(Options).FStorePublicKeysInMemoryContainers;
    FForceEnhancedCSPForLongKeys := TElWin32CryptoProviderOptions(Options).FForceEnhancedCSPForLongKeys;
    FAutoSelectEnhancedCSP := TElWin32CryptoProviderOptions(Options).FAutoSelectEnhancedCSP;
    FTryAlternativeKeySpecOnFailure := TElWin32CryptoProviderOptions(Options).FTryAlternativeKeySpecOnFailure;
    FGenerateExportablePrivateKeys := TElWin32CryptoProviderOptions(Options).FGenerateExportablePrivateKeys;
    FUseLocalMachineAccount := TElWin32CryptoProviderOptions(Options).FUseLocalMachineAccount;
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// TElWin32ProviderInfo class

constructor TElWin32ProviderInfo.Create;
begin
  inherited;
  FProviderType := 0;
  FProviderName := '';
  FSupportedAlgorithms := TElList.Create();
  FReleaseProvHandle := true;
  FProvHandle := 0;
  FFIPSCompliant := false;
  FSecCriticalDisposed := false;
end;

constructor TElWin32ProviderInfo.Create(ProvType: integer; const ProvName : string;
  AutoRefresh : boolean; FIPSCompliant : boolean);
begin
  inherited Create;
  FProviderType := ProvType;
  FProviderName := ProvName;
  FReleaseProvHandle := true;
  FSupportedAlgorithms := TElList.Create();
  FFIPSCompliant := FIPSCompliant;
  FSecCriticalDisposed := false;
  if AutoRefresh then
  begin
    if not AcquireProvider then
      raise EElWin32CryptoProviderError.CreateFmt(SFailedToAcquireProviderContext,
        [(FProviderType), (FProviderName)]);
    Refresh;
  end;
end;

function TElWin32ProviderInfo.Init(ProvType: integer; const ProvName : string;
  AutoRefresh : boolean; FIPSCompliant : boolean): boolean;
begin
  FProviderType := ProvType;
  FProviderName := ProvName;
  FReleaseProvHandle := true;
  //FSupportedAlgorithms := TElList.Create();
  FFIPSCompliant := FIPSCompliant;
  if AutoRefresh then
  begin
    Result := AcquireProvider();
    if Result then
      Refresh;
  end
  else
    Result := true;
end;

destructor TElWin32ProviderInfo.Destroy;
begin
  ClearSupportedAlgorithms;
  FreeAndNil(FSupportedAlgorithms);
  if FReleaseProvHandle and (FProvHandle <> 0) then
    ReleaseProvider;
  inherited;
end;


function TElWin32ProviderInfo.AcquireProvider: boolean;
begin
  if (FProvHandle <> 0) and (FReleaseProvHandle) then
    ReleaseProvider;
  if not CryptAcquireContext(@FProvHandle, nil, PChar(FProviderName),
    FProviderType, CRYPT_VERIFYCONTEXT) then
    Result := false
  else
    Result := true;
end;

procedure TElWin32ProviderInfo.ReleaseProvider;
begin
  if (FProvHandle <> 0) and (FReleaseProvHandle) then
  begin
    CryptReleaseContext(FProvHandle, 0);
  end;
  FProvHandle := 0;
end;

procedure TElWin32ProviderInfo.ClearSupportedAlgorithms;
var
  I : integer;
begin
  for I := 0 to FSupportedAlgorithms.Count - 1 do
    TElWin32AlgorithmInfo(FSupportedAlgorithms[I]). Free ;
  FSupportedAlgorithms.Clear;
end;

procedure TElWin32ProviderInfo.Refresh;
begin
  RefreshSupportedAlgorithms;
end;

const
  SB_ALGCAP_GENERATE = 1;
  SB_ALGCAP_ENCRYPT = 2;
  SB_ALGCAP_SIGN = 4;
  SB_ALGCAP_DIGEST = 8;
  SB_ALGCAP_KEX = 16;

procedure TElWin32ProviderInfo.RefreshSupportedAlgorithms;
var
  P: pointer;
  Len:  DWORD ;
  procedure ProcessAlgorithm(Alg : PROV_ENUMALGS);
  const
    AlgCount = 50;
    AlgsWin32 : array[0..AlgCount - 1] of integer =  ( 
      CALG_MD2, CALG_MD4, CALG_MD5, CALG_SHA, CALG_SHA1, CALG_MAC,
      CALG_RSA_SIGN, CALG_DSS_SIGN, CALG_NO_SIGN, CALG_RSA_KEYX,
      CALG_DES, CALG_3DES_112, CALG_3DES, CALG_DESX, CALG_RC2, CALG_RC4,
      CALG_SEAL, CALG_DH_SF, CALG_DH_EPHEM, CALG_AGREEDKEY_ANY, CALG_KEA_KEYX,
      CALG_HUGHES_MD5, CALG_SKIPJACK, CALG_TEK, CALG_CYLINK_MEK, CALG_SSL3_SHAMD5,
      CALG_SSL3_MASTER, CALG_SCHANNEL_MASTER_HASH, CALG_SCHANNEL_MAC_KEY,
      CALG_SCHANNEL_ENC_KEY, CALG_PCT1_MASTER, CALG_SSL2_MASTER, CALG_TLS1_MASTER,
      CALG_RC5, CALG_HMAC, CALG_TLS1PRF, CALG_HASH_REPLACE_OWF, CALG_AES_128,
      CALG_AES_192, CALG_AES_256, CALG_AES, CALG_SHA_256, CALG_SHA_384, CALG_SHA_512,
      CALG_ECDH, CALG_ECDSA,
      { CryptoPro GOST algorithms }
      CALG_GR3411, CALG_G28147, CALG_GR3410, CALG_GR3410EL
     ) ;
    AlgsSBB : array[0..AlgCount - 1] of integer =  ( 
      SB_ALGORITHM_DGST_MD2, SB_ALGORITHM_UNKNOWN, SB_ALGORITHM_DGST_MD5,
      SB_ALGORITHM_DGST_SHA1, SB_ALGORITHM_DGST_SHA1, SB_ALGORITHM_UNKNOWN,
      SB_ALGORITHM_PK_RSA, SB_ALGORITHM_PK_DSA, SB_ALGORITHM_UNKNOWN,
      SB_ALGORITHM_PK_RSA, SB_ALGORITHM_CNT_DES, SB_ALGORITHM_UNKNOWN,
      SB_ALGORITHM_CNT_3DES, SB_ALGORITHM_UNKNOWN, SB_ALGORITHM_CNT_RC2,
      SB_ALGORITHM_CNT_RC4, SB_ALGORITHM_UNKNOWN, SB_ALGORITHM_UNKNOWN,
      SB_ALGORITHM_PK_DH, SB_ALGORITHM_UNKNOWN, SB_ALGORITHM_UNKNOWN,
      SB_ALGORITHM_DGST_MD5, SB_ALGORITHM_UNKNOWN, SB_ALGORITHM_UNKNOWN,
      SB_ALGORITHM_UNKNOWN, SB_ALGORITHM_DGST_SSL3,
      SB_ALGORITHM_UNKNOWN, SB_ALGORITHM_UNKNOWN, SB_ALGORITHM_UNKNOWN,
      SB_ALGORITHM_UNKNOWN, SB_ALGORITHM_UNKNOWN, SB_ALGORITHM_UNKNOWN,
      SB_ALGORITHM_UNKNOWN, SB_ALGORITHM_UNKNOWN, SB_ALGORITHM_HMAC,
      SB_ALGORITHM_UNKNOWN, SB_ALGORITHM_UNKNOWN, SB_ALGORITHM_CNT_AES128,
      SB_ALGORITHM_CNT_AES192, SB_ALGORITHM_CNT_AES256, SB_ALGORITHM_CNT_AES128,
      SB_ALGORITHM_DGST_SHA256, SB_ALGORITHM_DGST_SHA384, SB_ALGORITHM_DGST_SHA512,
      SB_ALGORITHM_PK_ECDH, SB_ALGORITHM_PK_ECDSA,
      { CryptoPro GOST algorithms }
      SB_ALGORITHM_DGST_GOST_R3411_1994, SB_ALGORITHM_CNT_GOST_28147_1989,
      SB_ALGORITHM_PK_GOST_R3410_1994, SB_ALGORITHM_PK_GOST_R3410_2001
     ) ;
    AlgCapabs : array[0..AlgCount - 1] of integer =  ( 
      SB_ALGCAP_DIGEST,
      SB_ALGCAP_DIGEST,
      SB_ALGCAP_DIGEST,
      SB_ALGCAP_DIGEST,
      SB_ALGCAP_DIGEST,
      SB_ALGCAP_DIGEST,
      SB_ALGCAP_SIGN or SB_ALGCAP_GENERATE,
      SB_ALGCAP_SIGN or SB_ALGCAP_GENERATE,
      SB_ALGCAP_SIGN,
      SB_ALGCAP_ENCRYPT or SB_ALGCAP_SIGN or SB_ALGCAP_GENERATE, // check: RSA_KEYX might not be used for signing
      SB_ALGCAP_ENCRYPT or SB_ALGCAP_GENERATE,
      SB_ALGCAP_ENCRYPT or SB_ALGCAP_GENERATE,
      SB_ALGCAP_ENCRYPT or SB_ALGCAP_GENERATE,
      SB_ALGCAP_ENCRYPT or SB_ALGCAP_GENERATE,
      SB_ALGCAP_ENCRYPT or SB_ALGCAP_GENERATE,
      SB_ALGCAP_ENCRYPT or SB_ALGCAP_GENERATE,
      SB_ALGCAP_ENCRYPT or SB_ALGCAP_GENERATE,
      SB_ALGCAP_KEX,
      SB_ALGCAP_KEX,
      SB_ALGCAP_KEX,
      SB_ALGCAP_KEX,
      SB_ALGCAP_DIGEST,
      SB_ALGCAP_ENCRYPT or SB_ALGCAP_GENERATE,
      SB_ALGCAP_ENCRYPT or SB_ALGCAP_GENERATE,
      SB_ALGCAP_ENCRYPT or SB_ALGCAP_GENERATE,
      SB_ALGCAP_DIGEST,
      SB_ALGCAP_DIGEST, // check: SSL3 algorithms might be used as signing ones
      SB_ALGCAP_DIGEST,
      SB_ALGCAP_DIGEST,
      SB_ALGCAP_DIGEST,
      SB_ALGCAP_DIGEST,
      SB_ALGCAP_DIGEST,
      SB_ALGCAP_DIGEST,
      SB_ALGCAP_ENCRYPT or SB_ALGCAP_GENERATE,
      SB_ALGCAP_DIGEST,
      SB_ALGCAP_DIGEST,
      SB_ALGCAP_DIGEST,
      SB_ALGCAP_ENCRYPT or SB_ALGCAP_GENERATE,
      SB_ALGCAP_ENCRYPT or SB_ALGCAP_GENERATE,
      SB_ALGCAP_ENCRYPT or SB_ALGCAP_GENERATE,
      SB_ALGCAP_ENCRYPT or SB_ALGCAP_GENERATE,
      SB_ALGCAP_DIGEST,
      SB_ALGCAP_DIGEST,
      SB_ALGCAP_DIGEST,
      SB_ALGCAP_KEX,
      SB_ALGCAP_SIGN or SB_ALGCAP_GENERATE,
      { CryptoPro GOST algorithms }
      SB_ALGCAP_DIGEST, SB_ALGCAP_ENCRYPT or SB_ALGCAP_GENERATE,
      SB_ALGCAP_SIGN or SB_ALGCAP_GENERATE, SB_ALGCAP_SIGN or SB_ALGCAP_GENERATE
     ) ;
    AlgKeySizes : array[0..AlgCount - 1] of integer =  ( 
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 16, 24, 8, 16, 16, 16, 0, 0, 0, 0,
      0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 16, 24, 32, 16, 0, 0, 0,
      0, 0,
      { CryptoPro GOST algorithms }
      0, 32, 0, 0
     ) ;
    AlgBlockSizes : array[0..AlgCount - 1] of integer =  ( 
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 8, 0, 8, 0, 0, 0, 0,
      0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 16, 16, 16, 16,
      0, 0, 0, 0, 0,
      { CryptoPro GOST algorithms }
      0, 8, 0, 0
     ) ;
    AlgFIPSCompliancies : array[0..AlgCount - 1] of boolean =  ( 
      false, false, false, true, true, {CALG_MAC}false,
      true, true, false, true, false, false, true, false, false, false,
      false, false, false, false, false, false, false, false, false, false,
      false, false, false, false, false, false, false, false, true, false, false,
      true, true, true, true, true, true, true, false, false,
      { CryptoPro GOST algorithms }
      false, false, false, false
     ) ;
  var
    I : integer;
    Info : TElWin32AlgorithmInfo;
    Nm : ByteArray;
  begin
    for I := 0 to AlgCount - 1 do
    begin
      if integer(Alg.aiAlgId) = AlgsWin32[I] then
      begin
        Info := TElWin32AlgorithmInfo.Create();
        Info.FAlgorithm := AlgsSBB[I];
        Info.FWin32Algorithm := AlgsWin32[I];
        // CryptoAPI returns 56 and 168 key sizes for DES and 3DES key respectively,
        // so we have to manually adjust them
        if integer(Alg.aiAlgId) = CALG_DES then
          Info.FBits := 64
        else if integer(Alg.aiAlgId) = CALG_3DES then
          Info.FBits := 192
        else
          Info.FBits := Alg.dwBitLen;
        Info.FCanGenerate := (AlgCapabs[I] and SB_ALGCAP_GENERATE) = SB_ALGCAP_GENERATE;
        Info.FCanEncrypt := (AlgCapabs[I] and SB_ALGCAP_ENCRYPT) = SB_ALGCAP_ENCRYPT;
        Info.FCanSign := (AlgCapabs[I] and SB_ALGCAP_SIGN) = SB_ALGCAP_SIGN;
        Info.FCanDigest := (AlgCapabs[I] and SB_ALGCAP_DIGEST) = SB_ALGCAP_DIGEST;
        Info.FCanKex := (AlgCapabs[I] and SB_ALGCAP_KEX) = SB_ALGCAP_KEX;
        Info.FDefaultKeySize := AlgKeySizes[I];
        Info.FDefaultBlockSize := AlgBlockSizes[I];
        Info.FFIPSCompliant := AlgFIPSCompliancies[I];
        SetLength(Nm, Alg.dwNameLen);
        SBMove(Alg.szName[0], Nm[0], Length(Nm));
        Info.FName := StringOfBytes(Nm);
        FSupportedAlgorithms.Add(Info);
        Break;
      end;
    end;
  end;
begin
  ClearSupportedAlgorithms;
  
  Len := 0;

  if (CryptGetProvParam(FProvHandle, PP_ENUMALGS,   nil  ,  @ Len, CRYPT_FIRST))  then
  begin
    GetMem(P, Len);
    try
      CryptGetProvParam(FProvHandle, PP_ENUMALGS, P, @Len, CRYPT_FIRST);
      ProcessAlgorithm(PPROV_ENUMALGS(P)^);

      while (CryptGetProvParam(FProvHandle, PP_ENUMALGS, P, @Len, 0)) do
        ProcessAlgorithm(PPROV_ENUMALGS(P)^); 
    finally
      FreeMem(P);
    end;
  end;
end;

function TElWin32ProviderInfo.GetAlgorithmInfo(Alg : integer; Mode : integer; Operation: integer;
  FIPSCompliancyNeeded : boolean; KeySize : integer  =  0): TElWin32AlgorithmInfo;
var
  I : integer;
  Info : TElWin32AlgorithmInfo;
  B : boolean;                  
begin
  Result := nil;
  Info := nil;
  if IsMACAlgorithm(Alg) then
  begin
    // checking if we support MAC algorithm at all
    B := false;
    for I := 0 to FSupportedAlgorithms.Count - 1 do
    begin
      Info := TElWin32AlgorithmInfo(FSupportedAlgorithms[I]);
      if (Info.FWin32Algorithm = CALG_HMAC) and ((not FIPSCompliancyNeeded) or (Info.FFIPSCompliant)) then
      begin
        B := true;
        Break;
      end;
    end;
    if not B then
      Exit;
    if Alg = SB_ALGORITHM_HMAC then // no hash algorithm is specified
    begin
      Result := Info;
      Exit;
    end;
    Alg := GetHashAlgorithmByHMACAlgorithm(Alg);
  end;
  for I := 0 to FSupportedAlgorithms.Count - 1 do
  begin
    Info := TElWin32AlgorithmInfo(FSupportedAlgorithms[I]);
    if Info.FAlgorithm = Alg then
    begin
      if (Operation in [SB_OPTYPE_NONE, SB_OPTYPE_KEY_CREATE]) or
        ((Operation in [SB_OPTYPE_ENCRYPT, SB_OPTYPE_DECRYPT, SB_OPTYPE_KEY_DECRYPT]) and (Info.FCanEncrypt or Info.FCanKex)) or
        ((Operation in [SB_OPTYPE_SIGN_DETACHED, SB_OPTYPE_VERIFY_DETACHED]) and (Info.FCanSign)) or
        ((Operation = SB_OPTYPE_HASH) and (Info.FCanDigest)) or
        ((Operation = SB_OPTYPE_KEY_GENERATE) and (Info.FCanGenerate)) or
        ((Operation = SB_OPTYPE_RANDOM)) then
      begin
        if ((not IsSymmetricKeyAlgorithm(Alg)) or (KeySize = 0) or
          (Info.FBits = 0) or (KeySize <= Info.FBits)) and
          ((not FIPSCompliancyNeeded) or (Info.FFIPSCompliant)) then
        begin
          Result := Info;
          Break;
        end;
      end;
    end;
  end;
end;

function TElWin32ProviderInfo.IsAlgorithmSupported(Alg : integer; Mode : integer;
  Operation: integer; FIPSCompliancyNeeded : boolean): boolean;
begin
  Result := GetAlgorithmInfo(Alg, Mode, Operation, FIPSCompliancyNeeded) <> nil;
end;

////////////////////////////////////////////////////////////////////////////////
// Other

function Win32CryptoProvider : TElCustomCryptoProvider;
begin
  if Win32CryptoProv = nil then
  begin
    Win32CryptoProv := TElWin32CryptoProvider.Create( nil );
    RegisterGlobalObject(Win32CryptoProv);
  end;
  Result := Win32CryptoProv;
end;

function Win32CryptoProvider(OptionsTemplate : TElWin32CryptoProviderOptions): TElCustomCryptoProvider;
begin
  if Win32CryptoProv = nil then
  begin
    Win32CryptoProv := TElWin32CryptoProvider.Create(OptionsTemplate , nil );
    RegisterGlobalObject(Win32CryptoProv);
  end;
  Result := Win32CryptoProv;
end;

initialization

  {$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
  CALG_RSA_KEYX_ID      := CreateByteArrayConst(#$00#$a4#$00#$00);
  CALG_DES_ID           := CreateByteArrayConst(#$01#$66#$00#$00);
  CALG_3DES_ID          := CreateByteArrayConst(#$03#$66#$00#$00);
  CALG_RC2_ID           := CreateByteArrayConst(#$02#$66#$00#$00);
  CALG_RC4_ID           := CreateByteArrayConst(#$01#$68#$00#$00);
  CALG_AES_128_ID       := CreateByteArrayConst(#$0E#$66#$00#$00);
  CALG_AES_192_ID       := CreateByteArrayConst(#$0F#$66#$00#$00);
  CALG_AES_256_ID       := CreateByteArrayConst(#$10#$66#$00#$00);
  CALG_AES_ID           := CreateByteArrayConst(#$11#$66#$00#$00);
  BLOB_ID_AND_RESERVED  := CreateByteArrayConst(#$01#$02#$00#$00);

  SB_ALGSCHEME_PKCS1    := CreateByteArrayConst('pkcs#1');
  SB_ALGSCHEME_PKCS5    := CreateByteArrayConst('pkcs#5');
  SB_ALGSCHEME_OAEP     := CreateByteArrayConst('oaep');
  SB_ALGSCHEME_PSS      := CreateByteArrayConst('pss');
  SB_KEYPROP_RSA_KEYFORMAT_PKCS1 := CreateByteArrayConst('pkcs#1');
   {$endif}


 {$endif SB_HAS_WINCRYPT}
 {$endif SB_WINDOWS_OR_NET_OR_JAVA}

end.
