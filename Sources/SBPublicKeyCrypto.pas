(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$i SecBbox.inc}

unit SBPublicKeyCrypto;

interface

uses
{$ifdef WIN32}
  Windows,
 {$else}
  //{$ifndef FPC}Libc,{$endif}
 {$endif}                                         
  Classes,
  SysUtils,
  {$ifdef SB_UNICODE_VCL}
  SBStringList,
   {$endif}
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBEncoding,
  SBMath,
  SBConstants,
  SBRSA,
  SBDSA,
  SBElgamal,
  SBPEM,
  {$ifndef SB_NO_SRP}
  SBSRP,
   {$endif}
  SBASN1Tree,
{$ifdef SB_HAS_WINCRYPT}
  SBWinCrypt,
 {$endif}
  SBCustomCrypto,
  SBCryptoProv,
  //SBCryptoProvDefault,
  SBCryptoProvManager,
  SBCryptoProvUtils,
  SBASN1,
  SBAlgorithmIdentifier;

type
  SB_CK_ULONG =   LongWord ;

  TSBAsyncOperationFinishedEvent =  procedure(Sender:  TObject ;
    Success: boolean) of object;

  TSBKeyStoreFormat = 
   (ksfRaw, ksfPKCS8);

  TElPublicKeyMaterial = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElPublicKeyMaterial = TElPublicKeyMaterial;
   {$endif}

  // responsible for public (and private) key material storing
  TElPublicKeyMaterial = class(TElKeyMaterial)
  protected
    FBusy : boolean;
    FProvider : TElCustomCryptoProvider;
    FProviderManager : TElCustomCryptoProviderManager;
    FStoreFormat : TSBKeyStoreFormat;
    FAsyncOperationFinished : boolean;
    FAsyncOperationSucceeded : boolean;
    FAsyncOperationError : string;
    FOnAsyncOperationFinished : TSBAsyncOperationFinishedEvent;
    FWorkingThread :  TThread ;
    
    function IsPEM( Buffer: pointer;
        Size: integer): boolean;
    {$ifndef SB_PGPSFX_STUB}
    procedure InternalGenerate(Bits : integer); virtual;
    procedure OnThreadTerminate(Sender: TObject);
     {$endif SB_PGPSFX_STUB}
    
    {$ifdef SB_HAS_WINCRYPT}
    function GetCertHandle :   PCCERT_CONTEXT  ;
    procedure SetCertHandle(Value:   PCCERT_CONTEXT  );
    function GetKeyExchangePIN() : string;
    procedure SetKeyExchangePIN(const Value: string);
    function GetSignaturePIN() : string;
    procedure SetSignaturePIN(const Value: string);
     {$endif}
    function GetKeyHandle : SB_CK_ULONG;
    procedure SetKeyHandle(Value : SB_CK_ULONG);
    function GetSessionHandle : SB_CK_ULONG;
    procedure SetSessionHandle(Value : SB_CK_ULONG);
    function GetValid : boolean; override;
    function GetIsPublicKey : boolean;
    function GetIsSecretKey : boolean;
    function GetExportable : boolean; override;
    

    procedure SetOnAsyncOperationFinished(Value : TSBAsyncOperationFinishedEvent);
    function GetAsyncOperationFinished : boolean; virtual;
  public
    constructor Create(Prov : TElCustomCryptoProvider  = nil );  overload;  virtual;
    constructor Create(Manager: TElCustomCryptoProviderManager; Prov : TElCustomCryptoProvider);  overload;  virtual;
     destructor  Destroy; override;
    class function GetMaxPublicKeySize(Prov : TElCustomCryptoProvider): integer;

    procedure AssignCryptoKey(Key : TElCustomCryptoKey); override;
    {$ifndef SB_PGPSFX_STUB}
    procedure Generate(Bits : integer); override;
     {$endif SB_PGPSFX_STUB}
    
    procedure LoadPublic(Buffer: pointer; Size: integer); overload; virtual;
    procedure LoadSecret(Buffer: pointer; Size: integer); overload; virtual;
    procedure SavePublic(Buffer: pointer; var Size: integer); overload; virtual;
    procedure SaveSecret(Buffer: pointer; var Size: integer); overload; virtual;
    
    procedure LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); virtual;
    procedure SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); virtual;
    
    procedure LoadPublic(Stream : TElInputStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});  overload; 
    procedure LoadSecret(Stream : TElInputStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});  overload; 
    procedure SavePublic(Stream : TElOutputStream);  overload;  virtual;
    procedure SaveSecret(Stream : TElOutputStream);  overload;  virtual;
    procedure Save(Stream : TElOutputStream); override;
    procedure Load(Stream : TElInputStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}); override;
    
    {$ifndef SB_PGPSFX_STUB}
    procedure LoadFromXML(const Str: string); virtual;
    function SaveToXML(IncludePrivateKey: Boolean  =  False): string; virtual;
     {$endif SB_PGPSFX_STUB}

    function Clone : TElKeyMaterial; override;
    function  Equals(Source : TElKeyMaterial; PublicOnly : boolean): boolean; override;
    procedure ClearSecret; virtual;
    procedure ClearPublic; virtual;
    procedure Clear;
    {$ifndef SB_PGPSFX_STUB}
    procedure BeginGenerate(Bits : integer);
    procedure EndGenerate;
    procedure CancelAsyncOperation;
    procedure PrepareForEncryption(MultiUse : boolean  =  false); virtual;
    procedure PrepareForSigning(MultiUse : boolean  =  false); virtual;
     {$endif SB_PGPSFX_STUB}
    property PublicKey : boolean read GetIsPublicKey;
    property SecretKey : boolean read GetIsSecretKey;
    {$ifdef SB_HAS_WINCRYPT}
    property CertHandle :   PCCERT_CONTEXT   read GetCertHandle write SetCertHandle;
    property KeyExchangePIN : string read GetKeyExchangePIN write SetKeyExchangePIN;
    property SignaturePIN : string read GetSignaturePIN write SetSignaturePIN;
     {$endif}
    property KeyHandle : SB_CK_ULONG read GetKeyHandle write SetKeyHandle;
    property SessionHandle : SB_CK_ULONG read GetSessionHandle write SetSessionHandle;
    property Busy : boolean read FBusy;
    property StoreFormat : TSBKeyStoreFormat read FStoreFormat write FStoreFormat;
    property AsyncOperationFinished : boolean read GetAsyncOperationFinished;
    property OnAsyncOperationFinished : TSBAsyncOperationFinishedEvent read
      FOnAsyncOperationFinished write SetOnAsyncOperationFinished;
  end;

  TSBPublicKeyOperation = 
   (pkoEncrypt, pkoDecrypt, pkoSign, pkoSignDetached,
    pkoVerify, pkoVerifyDetached, pkoDecryptKey);

  TSBPublicKeyVerificationResult = 
   (pkvrSuccess, pkvrInvalidSignature, pkvrKeyNotFound,
    pkvrFailure);
  TSBPublicKeyCryptoEncoding =  (pkeBinary, pkeBase64);
  

  TElPublicKeyCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElPublicKeyCrypto = TElPublicKeyCrypto;
   {$endif}

  // base class for other public key encryption classes. Do not instantiate.
  TElPublicKeyCrypto = class(TElCustomCrypto)
  protected
    FKeyMaterial : TElPublicKeyMaterial;
    FOutput : ByteArray;
    FOutputStream : TElOutputStream;
    FOutputIsStream : boolean;
    FInputIsHash : boolean;
    FInputEncoding : TSBPublicKeyCryptoEncoding;
    FOutputEncoding : TSBPublicKeyCryptoEncoding;
    FInB64Ctx : TSBBase64Context;
    FOutB64Ctx : TSBBase64Context;
    FInputSpool : ByteArray;
    FBusy : boolean;
    FAsyncOperationFinished : boolean;
    FOnAsyncOperationFinished : TSBAsyncOperationFinishedEvent;
    FCryptoProvider : TElCustomCryptoProvider;
    FCryptoProviderManager : TElCustomCryptoProviderManager;
    FContext : TElCustomCryptoContext;
    FAsyncOperationSucceeded : boolean;
    FAsyncOperationError : string;
    FAsyncOperation : TSBPublicKeyOperation;
    FVerificationResult : TSBPublicKeyVerificationResult;
    FWorkingThread :  TThread ;
    FHashAlg : integer;
    procedure AdjustContextProps(Params: TElCPParameters); virtual;
    procedure SaveContextProps; virtual;
    procedure DecodeInput(InData : pointer; InSize : integer);
    procedure OnThreadTerminate(Sender: TObject);
    { internal routines for public-key operations }
    {$ifndef SB_PGPSFX_STUB}
    procedure InternalEncrypt;  overload; 
     {$endif SB_PGPSFX_STUB}
    procedure InternalDecrypt;  overload; 
    {$ifndef SB_PGPSFX_STUB}
    procedure InternalSign;  overload; 
    procedure InternalSignDetached;  overload; 
     {$endif SB_PGPSFX_STUB}
    function InternalVerify: TSBPublicKeyVerificationResult;  overload; 
    function InternalVerifyDetached: TSBPublicKeyVerificationResult;  overload; 

    {$ifndef SB_PGPSFX_STUB}
    procedure InternalEncrypt(InStream : TElInputStream; OutStream : TElOutputStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});  overload; 
     {$endif SB_PGPSFX_STUB}
    procedure InternalDecrypt(InStream : TElInputStream; OutStream : TElOutputStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});  overload; 
    {$ifndef SB_PGPSFX_STUB}
    procedure InternalSign(InStream : TElInputStream; OutStream : TElOutputStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});  overload; 
    procedure InternalSignDetached(InStream : TElInputStream; OutStream : TElOutputStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});  overload; 
     {$endif SB_PGPSFX_STUB}
    function InternalVerify(InStream : TElInputStream; OutStream : TElOutputStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}): TSBPublicKeyVerificationResult;  overload; 
    function InternalVerifyDetached(InStream : TElInputStream; SigStream : TElInputStream;
      InCount : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif};
      SigCount : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}): TSBPublicKeyVerificationResult;  overload; 

    {$ifndef SB_PGPSFX_STUB}
    procedure SignInit(Detached: boolean); virtual;
    procedure SignUpdate( Buffer: pointer;
        Size: integer); virtual;
    procedure SignFinal; virtual;
    procedure EncryptInit; virtual;
    procedure EncryptUpdate( Buffer: pointer;
        Size: integer); virtual;
    procedure EncryptFinal; virtual;
     {$endif SB_PGPSFX_STUB}
    procedure DecryptInit; virtual;
    procedure DecryptUpdate( Buffer: pointer;
        Size: integer); virtual;
    procedure DecryptFinal; virtual;
    procedure VerifyInit(Detached: boolean;  Signature: pointer;
        SigSize: integer); virtual;
    procedure VerifyUpdate( Buffer: pointer;  Size: integer); virtual;
    function VerifyFinal : TSBPublicKeyVerificationResult; virtual;
    function EstimateOutputSize( InBuffer: pointer;
        InSize: integer;
      Operation : TSBPublicKeyOperation): integer; virtual;
    procedure WriteToOutput( Buffer: pointer;
        Size: integer); virtual;
    procedure Reset; 
    class function IsAlgorithmSupported(Alg: integer): boolean;  overload;  virtual;
    class function IsAlgorithmSupported(const OID: ByteArray): boolean;  overload;  virtual;
    class function GetName() : string; virtual;
    class function GetDescription() : string; virtual;
    function GetSuitableCryptoProvider(Operation : TSBPublicKeyOperation;
      Algorithm : integer; Pars : TElCPParameters) : TElCustomCryptoProvider; virtual;
      
      
    function GetSupportsEncryption: boolean; virtual;
    function GetSupportsSigning: boolean; virtual;
    procedure SetKeyMaterial(Material : TElPublicKeyMaterial); virtual;
    procedure SetInputIsHash(Value : boolean);
    procedure SetInputEncoding(Value : TSBPublicKeyCryptoEncoding);
    procedure SetOutputEncoding(Value : TSBPublicKeyCryptoEncoding);
    procedure SetOnAsyncOperationFinished(Value : TSBAsyncOperationFinishedEvent);
    function GetHashAlgorithm : integer;
    procedure SetHashAlgorithm(Value: integer);
  public
    constructor Create(const OID : ByteArray; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  virtual;
    constructor Create(Alg : integer; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  virtual;
    constructor Create(CryptoProvider : TElCustomCryptoProvider  = nil );  overload;  virtual;
    constructor Create(const OID : ByteArray; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  virtual;
    constructor Create(Alg : integer; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  virtual;
    constructor Create(Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  virtual;
     destructor  Destroy; override;

    procedure LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); virtual;
    procedure SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); virtual;
    {$ifndef SB_PGPSFX_STUB}
    procedure Encrypt(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
      var OutSize: integer); overload;
     {$endif SB_PGPSFX_STUB}
    procedure Decrypt(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
      var OutSize: integer); overload;
    {$ifndef SB_PGPSFX_STUB}
    procedure Sign(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
      var OutSize: integer); overload;
    procedure SignDetached(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
      var OutSize: integer); overload;
     {$endif SB_PGPSFX_STUB}
    // TODO: consider possible verification results
    function Verify(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
      var OutSize: integer): TSBPublicKeyVerificationResult; overload;
    function VerifyDetached(InBuffer: pointer; InSize: integer; SigBuffer: pointer;
      SigSize: integer): TSBPublicKeyVerificationResult; overload;
    
    {$ifndef SB_PGPSFX_STUB}
    procedure Encrypt(InStream : TElInputStream; OutStream : TElOutputStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});  overload; 
     {$endif SB_PGPSFX_STUB}
    procedure Decrypt(InStream : TElInputStream; OutStream : TElOutputStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});  overload; 
    {$ifndef SB_PGPSFX_STUB}
    procedure Sign(InStream : TElInputStream; OutStream : TElOutputStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});  overload; 
    procedure SignDetached(InStream : TElInputStream; OutStream : TElOutputStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});  overload; 
     {$endif SB_PGPSFX_STUB}
    function Verify(InStream : TElInputStream; OutStream : TElOutputStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}): TSBPublicKeyVerificationResult;  overload; 
    function VerifyDetached(InStream : TElInputStream; SigStream : TElInputStream;
      InCount : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif};
      SigCount : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}): TSBPublicKeyVerificationResult;  overload; 
    
    function DecryptKey(EncKey : pointer; EncKeySize : integer; const EncKeyAlgOID,
      EncKeyAlgParams : ByteArray): TElKeyMaterial; virtual;
    { asynchronous operations }
    procedure BeginEncrypt(InBuffer: pointer; InSize: integer); overload;
    function EndEncrypt(OutBuffer: pointer; var OutSize: integer) : boolean; overload;
    procedure BeginDecrypt(InBuffer: pointer; InSize: integer); overload;
    function EndDecrypt(OutBuffer: pointer; var OutSize: integer) : boolean; overload;
    procedure BeginSign(InBuffer: pointer; InSize: integer); overload;
    function EndSign(OutBuffer: pointer; var OutSize: integer) : boolean; overload;
    procedure BeginSignDetached(InBuffer: pointer; InSize: integer); overload;
    function EndSignDetached(OutBuffer: pointer; var OutSize: integer) : boolean; overload;
    procedure BeginVerify(InBuffer: pointer; InSize: integer); overload;
    function EndVerify(OutBuffer: pointer; var OutSize: integer;
      var VerificationResult: TSBPublicKeyVerificationResult) : boolean; overload;
    procedure BeginVerifyDetached(InBuffer: pointer; InSize: integer;
      SigBuffer: pointer; SigSize: integer); overload;
    procedure BeginEncrypt(InStream : TElInputStream; OutStream : TElOutputStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});  overload; 
    procedure EndEncrypt;  overload; 
    procedure BeginDecrypt(InStream : TElInputStream; OutStream : TElOutputStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});  overload; 
    procedure EndDecrypt;  overload; 
    procedure BeginSign(InStream : TElInputStream; OutStream : TElOutputStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});  overload; 
    procedure EndSign;  overload; 
    procedure BeginSignDetached(InStream : TElInputStream; OutStream : TElOutputStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});  overload; 
    procedure EndSignDetached;  overload; 
    procedure BeginVerify(InStream : TElInputStream; OutStream : TElOutputStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});  overload; 
    function EndVerify : TSBPublicKeyVerificationResult;  overload; 
    procedure BeginVerifyDetached(InStream : TElInputStream; SigStream : TElInputStream;
      InCount : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif};
      SigCount : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});  overload; 
    function EndVerifyDetached : TSBPublicKeyVerificationResult;  overload; 
    
    procedure CancelAsyncOperation;
    property KeyMaterial : TElPublicKeyMaterial read FKeyMaterial write SetKeyMaterial;
    property SupportsEncryption : boolean read GetSupportsEncryption;
    property SupportsSigning : boolean read GetSupportsSigning;
    property InputIsHash : boolean read FInputIsHash write SetInputIsHash;
    property InputEncoding : TSBPublicKeyCryptoEncoding read FInputEncoding write SetInputEncoding;
    property OutputEncoding : TSBPublicKeyCryptoEncoding read FOutputEncoding write SetOutputEncoding;
    property Busy : boolean read FBusy;
    property HashAlgorithm : integer read GetHashAlgorithm write SetHashAlgorithm;
    property AsyncOperationFinished : boolean read FAsyncOperationFinished;
    property OnAsyncOperationFinished : TSBAsyncOperationFinishedEvent read
      FOnAsyncOperationFinished write SetOnAsyncOperationFinished;
  end;

  TElPublicKeyCryptoClass =  class of TElPublicKeyCrypto;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElPublicKeyCryptoClass = TElPublicKeyCryptoClass;
   {$endif}

  // responsible for storing RSA key material
  TSBRSAKeyFormat = 
    (rsaPKCS1, rsaOAEP, rsaPSS, rsaX509);
    

  TElRSAKeyMaterial = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElRSAKeyMaterial = TElRSAKeyMaterial;
   {$endif}

  TElRSAKeyMaterial = class(TElPublicKeyMaterial)
  protected
    FKeyFormat : TSBRSAKeyFormat;
    FPassphrase : string;
    FPEMEncode : boolean;
    procedure Reset;
    {$ifndef SB_PGPSFX_STUB}
    procedure InternalGenerate(Bits : integer); override;
     {$endif SB_PGPSFX_STUB}

    function GetM : ByteArray;
    function GetE : ByteArray;
    function GetD : ByteArray;
    function GetValid : boolean; override;
    function GetBits : integer; override;
    procedure SetPassphrase(const Value : string);
    procedure SetPEMEncode(Value : boolean);
    procedure SetStrLabel(const Value : string);
    procedure SetSaltSize(Value : integer);
    procedure SetMGFAlgorithm(Value : integer);
    procedure SetTrailerField(Value : integer);
    procedure SetHashAlgorithm(Value : integer);
    procedure SetRawPublicKey(Value : boolean);
    function GetStrLabel: string;
    function GetSaltSize : integer;
    function GetMGFAlgorithm : integer;
    function GetTrailerField : integer;
    function GetHashAlgorithm : integer;
    function GetRawPublicKey : boolean;
  public
    constructor Create(Prov : TElCustomCryptoProvider  = nil ); override;
    constructor Create(Manager: TElCustomCryptoProviderManager; Prov : TElCustomCryptoProvider); override;
     destructor  Destroy; override;
    procedure Assign(Source: TElKeyMaterial); override;
    procedure LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); override;
    procedure SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); override;
    procedure LoadPublic(Buffer: pointer; Size: integer); override;
    procedure LoadSecret(Buffer: pointer; Size: integer); override;
    procedure LoadPublic(Modulus : pointer; ModulusSize : integer;
      Exponent : pointer; ExponentSize : integer); overload;
    procedure SavePublic(Buffer: pointer; var Size: integer); override;
    procedure SaveSecret(Buffer: pointer; var Size: integer); override;
    {$ifndef SB_PGPSFX_STUB}
    procedure LoadFromXML(const Str: string); override;
    function SaveToXML(IncludePrivateKey: Boolean  =  False): string; override;
     {$endif SB_PGPSFX_STUB}
    
    function EncodePublicKey(PublicModulus : pointer; PublicModulusSize : integer;
      PublicExponent : pointer; PublicExponentSize : integer; const AlgID: ByteArray;
      OutBuffer : pointer; var OutSize : integer; InnerValuesOnly : boolean = false) : boolean; overload;
    function EncodePrivateKey(PublicModulus : pointer; PublicModulusSize : integer;
      PublicExponent : pointer; PublicExponentSize : integer; PrivateExponent :
      pointer; PrivateExponentSize : integer; OutBuffer : pointer; var OutSize : integer) : boolean; overload;
    function EncodePrivateKey(N : pointer; NSize : integer;
      E : pointer; ESize : integer; D : pointer; DSize : integer; P : pointer;
      PSize : integer; Q : pointer; QSize : integer; DP : pointer;
      DPSize : integer; DQ : pointer; DQSize : integer; QInv : pointer;
      QInvSize : integer; OutBuffer : pointer; var OutSize : integer) : boolean; overload;
    function EncodePrivateKey(N : pointer; NSize : integer;
      E : pointer; ESize : integer; D : pointer; DSize : integer; P : pointer;
      PSize : integer; Q : pointer; QSize : integer; OutBuffer : pointer;
      var OutSize : integer) : boolean; overload;
    function DecodePrivateKey(Blob : pointer; BlobSize : integer;
      N : pointer; var NSize : integer; E : pointer; var ESize : integer;
      D : pointer; var DSize : integer; P : pointer; var PSize : integer;
      Q : pointer; var QSize : integer; DP : pointer; var DPSize : integer;
      DQ : pointer; var DQSize : integer; QInv : pointer; var QInvSize : integer) : boolean;

    class function WritePSSParams(HashAlgorithm : integer;
      SaltSize : integer; MGFAlgorithm : integer; TrailerField : integer) : ByteArray;
    class function ReadPSSParams(InBuffer :  pointer;  InBufferSize : integer;
      var HashAlgorithm, SaltSize, MGF, MGFHashAlgorithm, TrailerField : TSBInteger) : boolean;
    class function WriteOAEPParams(HashAlgorithm, MGFHashAlgorithm : integer;
      const StrLabel : string) : ByteArray;
    class function ReadOAEPParams(InBuffer :  pointer;  InBufferSize : integer;
      var HashAlgorithm, MGFHashAlgorithm : TSBInteger; var StrLabel : TSBString) : boolean;

    function Clone : TElKeyMaterial; override;
    function  Equals(Source : TElKeyMaterial; PublicOnly : boolean): boolean; override;
    procedure ClearSecret; override;
    procedure ClearPublic; override;
    property KeyFormat : TSBRSAKeyFormat read FKeyFormat write FKeyFormat;
    property Passphrase : string read FPassphrase write SetPassphrase;
    property PEMEncode : boolean read FPEMEncode write SetPEMEncode;
    property StrLabel : string read GetStrLabel write SetStrLabel; //for RSA-OAEP
    property SaltSize : integer read GetSaltSize write SetSaltSize; //for RSA-PSS
    property MGFAlgorithm : integer read GetMGFAlgorithm write SetMGFAlgorithm; //for RSA-PSS
    property TrailerField : integer read GetTrailerField write SetTrailerField; //for RSA-PSS
    property HashAlgorithm : integer read GetHashAlgorithm write SetHashAlgorithm; //for RSA-PSS/OAEP
    property RawPublicKey : boolean read GetRawPublicKey write SetRawPublicKey;
    property PublicModulus : ByteArray read GetM;
    property PublicExponent : ByteArray read GetE;
    property PrivateExponent : ByteArray read GetD;
  end;

  // responsible for RSA encryption and signing
  TSBRSAPublicKeyCryptoType = 
    (rsapktPKCS1, rsapktOAEP, rsapktPSS, rsapktSSL3);

  TElRSAPublicKeyCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElRSAPublicKeyCrypto = TElRSAPublicKeyCrypto;
   {$endif}

  TElRSAPublicKeyCrypto = class(TElPublicKeyCrypto)
  protected
    FOID : ByteArray;
    FSupportsEncryption : boolean;
    FSupportsSigning : boolean;
    FCryptoType : TSBRSAPublicKeyCryptoType;
    FUseAlgorithmPrefix : boolean;
    FSpool : ByteArray;
    FHashFuncOID : ByteArray;
    FSaltSize : integer;
    FTrailerField : integer;
    FMGFAlgorithm : integer;
    FStrLabel : string;
    procedure AdjustContextProps(Params : TElCPParameters); override;

    {$ifndef SB_PGPSFX_STUB}
    procedure SignInit(Detached: boolean); override;
    procedure SignUpdate( Buffer: pointer;
        Size: integer); override;
    procedure SignFinal; override;
    procedure EncryptInit; override;
    procedure EncryptUpdate( Buffer: pointer;
        Size: integer); override;
    procedure EncryptFinal; override;
     {$endif SB_PGPSFX_STUB}
    procedure DecryptInit; override;
    procedure DecryptUpdate( Buffer: pointer;
        Size: integer); override;
    procedure DecryptFinal; override;
    procedure VerifyInit(Detached: boolean;  Signature: pointer;
        SigSize: integer); override;
    procedure VerifyUpdate( Buffer: pointer;  Size: integer); override;
    function VerifyFinal : TSBPublicKeyVerificationResult; override;
    function EstimateOutputSize( InBuffer: pointer;
        InSize: integer;
      Operation : TSBPublicKeyOperation): integer; override;
    class function IsAlgorithmSupported(Alg: integer): boolean;  overload;  override;
    class function IsAlgorithmSupported(const OID: ByteArray): boolean;  overload;  override;
    class function GetName() : string; override;
    class function GetDescription() : string; override;
    procedure Reset; 
    

    function GetSupportsEncryption: boolean; override;
    function GetSupportsSigning: boolean; override;
    procedure SetKeyMaterial(Material : TElPublicKeyMaterial); override;
    procedure SetCryptoType(Value : TSBRSAPublicKeyCryptoType);
    procedure SetUseAlgorithmPrefix(Value : boolean);
    procedure SetHashFuncOID(const Value : ByteArray);
    function GetSaltSize : integer;
    procedure SetSaltSize(Value: integer);
    function GetStrLabel : string;
    procedure SetStrLabel(const Value : string);
    function GetTrailerField : integer;
    procedure SetTrailerField(Value : integer);
    function GetMGFAlgorithm : integer;
    procedure SetMGFAlgorithm(Value : integer);
  public
    constructor Create(const OID : ByteArray; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Alg : integer; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(CryptoProvider : TElCustomCryptoProvider  = nil );  overload;  override;
    constructor Create(const OID : ByteArray; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Alg : integer; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
     destructor  Destroy; override;
    procedure LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); override;
    procedure SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); override;
    function DecryptKey(EncKey : pointer; EncKeySize : integer; const EncKeyAlgOID,
      EncKeyAlgParams : ByteArray): TElKeyMaterial; override;
    property CryptoType : TSBRSAPublicKeyCryptoType read FCryptoType write SetCryptoType;
    property UseAlgorithmPrefix : boolean read FUseAlgorithmPrefix write SetUseAlgorithmPrefix;
    property HashFuncOID : ByteArray read FHashFuncOID write SetHashFuncOID;
    property SaltSize : integer read GetSaltSize write SetSaltSize;
    property StrLabel : string read GetStrLabel write SetStrLabel; 
    property TrailerField : integer read GetTrailerField write SetTrailerField;
    property MGFAlgorithm : integer read GetMGFAlgorithm write SetMGFAlgorithm;
  end;

  // responsible for storing DSA key material
  TSBDSAKeyFormat =  (dsaFIPS, dsaX509);

  TElDSAKeyMaterial = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElDSAKeyMaterial = TElDSAKeyMaterial;
   {$endif}

  TElDSAKeyMaterial = class(TElPublicKeyMaterial)
  protected
    FKeyFormat : TSBDSAKeyFormat;
    FPassphrase : string;
    FPEMEncode : boolean;
    procedure Reset;
  protected
    {$ifndef SB_PGPSFX_STUB}
    procedure InternalGenerate(Bits : integer);  overload;  override;
    procedure InternalGenerate(PBits, QBits : integer);   reintroduce;  overload;  virtual;
     {$endif SB_PGPSFX_STUB}
    function GetValid : boolean; override;
    function GetBits : integer; override;
    function GetQBits : integer;
    function GetHashAlgorithm : integer;
    procedure SetHashAlgorithm(Value : integer);
    procedure SetPassphrase(const Value : string);
    procedure SetPEMEncode(Value : boolean);
    procedure SetStrictKeyValidation(Value : boolean);
    function GetStrictKeyValidation: boolean;
    function GetP : ByteArray;
    function GetQ : ByteArray;
    function GetG : ByteArray;
    function GetX : ByteArray;
    function GetY : ByteArray;
    procedure SetP(const Value : ByteArray);
    procedure SetQ(const Value : ByteArray);
    procedure SetG(const Value : ByteArray);
    procedure SetY(const Value : ByteArray);
    procedure SetX(const Value : ByteArray);
  public
    constructor Create(Prov : TElCustomCryptoProvider  = nil ); override;
    constructor Create(Manager: TElCustomCryptoProviderManager; Prov : TElCustomCryptoProvider); override;
     destructor  Destroy; override;
    procedure Assign(Source : TElKeyMaterial); override;
    procedure LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); override;
    procedure SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); override;
    {$ifndef SB_PGPSFX_STUB}
    procedure Generate(Bits : integer);  overload;  override;
    procedure Generate(PBits, QBits : integer);   reintroduce;  overload;  virtual;
    procedure BeginGenerate(PBits, QBits : integer);   reintroduce;  overload;  virtual;
     {$endif SB_PGPSFX_STUB}
    procedure LoadSecret(Buffer: pointer; Size: integer); override;
    procedure SaveSecret(Buffer: pointer; var Size: integer); override;
    procedure LoadPublic(Buffer: pointer; Size: integer); override;
    procedure SavePublic(Buffer: pointer; var Size: integer); override;
    procedure ImportPublicKey(P : pointer; PSize : integer; Q : pointer;
      QSize : integer; G : pointer; GSize : integer; Y : pointer; YSize : integer);
    procedure ExportPublicKey(P : pointer; var PSize : integer;
      Q : pointer; var QSize : integer; G : pointer; var GSize : integer;
      Y : pointer; var YSize : integer);
    {$ifndef SB_PGPSFX_STUB}
    procedure LoadFromXML(const Str: string); override;
    function SaveToXML(IncludePrivateKey: Boolean  =  False): string; override;
     {$endif SB_PGPSFX_STUB}

    function EncodePrivateKey(P : pointer; PSize : integer;
      Q : pointer; QSize : integer; G : pointer; GSize : integer; Y : pointer;
      YSize : integer; X : pointer; XSize : integer; OutBuffer : pointer;
      var OutSize : integer) : boolean; overload;
    function DecodePrivateKey(Blob : pointer; BlobSize : integer;
      P : pointer; var PSize : integer; Q : pointer; var QSize : integer;
      G : pointer; var GSize : integer; Y : pointer; var YSize : integer;
      X : pointer; var XSize : integer) : boolean;

    function Clone : TElKeyMaterial; override;
    function  Equals(Source : TElKeyMaterial; PublicOnly : boolean): boolean; override;
    procedure ClearSecret; override;
    procedure ClearPublic; override;
    property KeyFormat : TSBDSAKeyFormat read FKeyFormat;
    property QBits : integer read GetQBits;
    property HashAlgorithm : integer read GetHashAlgorithm write SetHashAlgorithm;
    property Passphrase : string read FPassphrase write SetPassphrase;
    property PEMEncode : boolean read FPEMEncode write SetPEMEncode;
    property StrictKeyValidation : boolean read GetStrictKeyValidation
      write SetStrictKeyValidation;
    property P : ByteArray read GetP write SetP;
    property Q : ByteArray read GetQ write SetQ;
    property G : ByteArray read GetG write SetG;
    property Y : ByteArray read GetY write SetY;
    property X : ByteArray read GetX write SetX;
  end;

  TElDSAPublicKeyCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElDSAPublicKeyCrypto = TElDSAPublicKeyCrypto;
   {$endif}

  TElDSAPublicKeyCrypto = class(TElPublicKeyCrypto)
  protected
    FOID : ByteArray;
    FSpool : ByteArray;
    {$ifndef SB_PGPSFX_STUB}
    procedure SignInit(Detached: boolean); override;
    procedure SignUpdate( Buffer: pointer;
        Size: integer); override;
    procedure SignFinal; override;
     {$endif SB_PGPSFX_STUB}
    procedure VerifyInit(Detached: boolean;  Signature: pointer;
        SigSize: integer); override;
    procedure VerifyUpdate( Buffer: pointer;
        Size: integer); override;
    function VerifyFinal : TSBPublicKeyVerificationResult; override;
    function EstimateOutputSize( InBuffer: pointer;
        InSize: integer;
      Operation : TSBPublicKeyOperation): integer; override;
    class function IsAlgorithmSupported(Alg: integer): boolean;  overload;  override;
    class function IsAlgorithmSupported(const OID: ByteArray): boolean;  overload;  override;
    class function GetName() : string; override;
    class function GetDescription() : string; override;
    procedure Reset; 
    procedure AdjustContextProps(Params : TElCPParameters); override;
    

    function GetSupportsEncryption: boolean; override;
    function GetSupportsSigning: boolean; override;
    procedure SetKeyMaterial(Material : TElPublicKeyMaterial); override;
  public
    constructor Create(const OID : ByteArray; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Alg : integer; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(CryptoProvider : TElCustomCryptoProvider  = nil );  overload;  override;
    constructor Create(const OID : ByteArray; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Alg : integer; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
     destructor  Destroy; override;
    procedure LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); override;
    procedure SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); override;
    
    procedure EncodeSignature(R : pointer; RSize : integer; S : pointer; SSize : integer;
      Sig : pointer; var SigSize : integer);
    procedure DecodeSignature(Sig : pointer; SigSize : integer; R : pointer;
      var RSize : integer; S : pointer; var SSize : integer);
  end;

  {$ifdef SB_HAS_ECC}
  TElECKeyMaterial = class(TElPublicKeyMaterial)
  protected
    FSpecifiedCurve : boolean;
    FImplicitCurve : boolean;
    {$ifndef SB_PGPSFX_STUB}
    procedure InternalGenerate(Bits : integer);   reintroduce;  overload;  override;
     {$endif}
    function GetValid : boolean; override;
    function GetBits : integer; override;
    function GetFieldBits : integer;
    function GetHashAlgorithm : integer;
    function GetRecommendedHashAlgorithm : integer;
    procedure SetHashAlgorithm(Value : integer);
    function GetA : ByteArray;
    procedure SetA(const Value : ByteArray);
    function GetB : ByteArray;
    procedure SetB(const Value : ByteArray);
    function GetP : ByteArray;
    procedure SetP(const Value : ByteArray);
    function GetN : ByteArray;
    procedure SetN(const Value : ByteArray);
    function GetH : integer;
    procedure SetH(Value : integer);
    function GetX : ByteArray;
    procedure SetX(const Value : ByteArray);
    function GetY : ByteArray;
    procedure SetY(const Value : ByteArray);
    function GetQX : ByteArray;
    procedure SetQX(const Value : ByteArray);
    function GetQY : ByteArray;
    procedure SetQY(const Value : ByteArray);
    function GetQ : ByteArray;
    procedure SetQ(const Value : ByteArray);
    function GetD : ByteArray;
    procedure SetD(const Value : ByteArray);
    function GetBase : ByteArray;
    procedure SetBase(const Value : ByteArray);
    function GetCurve : integer;
    procedure SetCurve(Value : integer);
    function GetCurveOID : ByteArray;
    procedure SetCurveOID(const Value : ByteArray);
    function GetSeed : ByteArray;
    procedure SetSeed(const Value : ByteArray);
    function GetFieldType : integer;
    procedure SetFieldType(Value : integer);
    function GetM : integer;
    procedure SetM(Value : integer);
    function GetK1 : integer;
    procedure SetK1(Value : integer);
    function GetK2 : integer;
    procedure SetK2(Value : integer);
    function GetK3 : integer;
    procedure SetK3(Value : integer);
    function GetCompressPoints : boolean;
    procedure SetCompressPoints(Value : boolean);
    function GetHybridPoints : boolean;
    procedure SetHybridPoints(Value : boolean);
  public
    constructor Create(Prov : TElCustomCryptoProvider  = nil ); override;
    constructor Create(Manager: TElCustomCryptoProviderManager; Prov : TElCustomCryptoProvider); override;
    
     destructor  Destroy; override;

    procedure Assign(Source : TElKeyMaterial); override;

    {$ifndef SB_PGPSFX_STUB}
    procedure Generate;   reintroduce;  overload;  virtual;
     {$endif}
    procedure LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); override;
    procedure SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); override;
    procedure LoadSecret(Buffer: pointer; Size: integer); override;
    procedure SaveSecret(Buffer: pointer; var Size: integer); override;
    procedure LoadPublic(Buffer: pointer; Size: integer); override;
    procedure SavePublic(Buffer: pointer; var Size: integer); override;
    procedure ImportPublicKey(QX : pointer; QXSize : integer;
      QY : pointer; QYSize : integer);
    procedure ExportPublicKey(QX : pointer; var QXSize : integer;
      QY : pointer; var QYSize : integer);
    function Clone : TElKeyMaterial; override;
    function  Equals(Source : TElKeyMaterial; PublicOnly : boolean): boolean; override;
    procedure ClearSecret; override;
    procedure ClearPublic; override;

    property CompressPoints : boolean read GetCompressPoints write SetCompressPoints;
    property HybridPoints : boolean read GetHybridPoints write SetHybridPoints;
    property FieldType : integer read GetFieldType write SetFieldType;
    property FieldBits : integer read GetFieldBits;
    property M : integer read GetM write SetM;
    property K1 : integer read GetK1 write SetK1;
    property K2 : integer read GetK2 write SetK2;
    property K3 : integer read GetK3 write SetK3;
    property HashAlgorithm : integer read GetHashAlgorithm write SetHashAlgorithm;
    property RecommendedHashAlgorithm : integer read GetRecommendedHashAlgorithm;
    property D : ByteArray read GetD write SetD;
    property N : ByteArray read GetN write SetN;
    property H : Integer read GetH write SetH;
    property A : ByteArray read GetA write SetA;
    property B : ByteArray read GetB write SetB;
    property X : ByteArray read GetX write SetX;
    property Y : ByteArray read GetY write SetY;
    property Q : ByteArray read GetQ write SetQ;
    property QX : ByteArray read GetQX write SetQX;
    property QY : ByteArray read GetQY write SetQY;
    property Base : ByteArray read GetBase write SetBase;
    property P : ByteArray read GetP write SetP;
    property Curve : integer read GetCurve write SetCurve;
    property CurveOID : ByteArray read GetCurveOID write SetCurveOID;
    property SpecifiedCurve : boolean read FSpecifiedCurve write FSpecifiedCurve;
    property ImplicitCurve : boolean read FImplicitCurve write FImplicitCurve;
    property Seed : ByteArray read GetSeed write SetSeed;
  end;

  TElECDSAPublicKeyCrypto = class(TElPublicKeyCrypto)
  protected
    FOID : ByteArray;
    FSpool : ByteArray;

    {$ifndef SB_PGPSFX_STUB}
    procedure SignInit(Detached: boolean); override;
    procedure SignUpdate( Buffer: pointer;
        Size: integer); override;
    procedure SignFinal; override;
     {$endif}
    
    procedure VerifyInit(Detached: boolean;  Signature: pointer;
        SigSize: integer); override;
    procedure VerifyUpdate( Buffer: pointer;
        Size: integer); override;
    function VerifyFinal : TSBPublicKeyVerificationResult; override;
    function EstimateOutputSize( InBuffer: pointer;
        InSize: integer;
      Operation : TSBPublicKeyOperation): integer; override;
    class function IsAlgorithmSupported(Alg: integer): boolean;  overload;  override;
    class function IsAlgorithmSupported(const OID: ByteArray): boolean;  overload;  override;
    class function GetName() : string; override;
    class function GetDescription() : string; override;
    procedure Reset; 
    procedure AdjustContextProps(Params : TElCPParameters); override;
    
    
    function GetSupportsEncryption: boolean; override;
    function GetSupportsSigning: boolean; override;
    procedure SetKeyMaterial(Material : TElPublicKeyMaterial); override;
  public
    constructor Create(const OID : ByteArray; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Alg : integer; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(CryptoProvider : TElCustomCryptoProvider  = nil );  overload;  override;
    constructor Create(const OID : ByteArray; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Alg : integer; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
     destructor  Destroy; override;
    procedure LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); override;
    procedure SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); override;

    procedure EncodeSignature(R : pointer; RSize : integer; S : pointer; SSize : integer;
      Sig : pointer; var SigSize : integer);
    procedure DecodeSignature(Sig : pointer; SigSize : integer; R : pointer;
      var RSize : integer; S : pointer; var SSize : integer);
  end;

  TElECDHPublicKeyCrypto = class(TElPublicKeyCrypto)
  protected
    FSpool : ByteArray;
    {$ifndef SB_PGPSFX_STUB}
    procedure EncryptInit; override;
    procedure EncryptUpdate( Buffer: pointer;
        Size: integer); override;
    procedure EncryptFinal; override;
     {$endif}
    
    procedure DecryptInit; override;
    procedure DecryptUpdate( Buffer: pointer;
        Size: integer); override;
    procedure DecryptFinal; override;
    function EstimateOutputSize( InBuffer: pointer;
        InSize: integer;
      Operation : TSBPublicKeyOperation): integer; override;
    class function IsAlgorithmSupported(Alg: integer): boolean;  overload;  override;
    class function IsAlgorithmSupported(const OID: ByteArray): boolean;  overload;  override;
    class function GetName() : string; override;
    class function GetDescription() : string; override;
    

    function GetSupportsEncryption: boolean; override;
    function GetSupportsSigning: boolean; override;
    procedure SetKeyMaterial(Material : TElPublicKeyMaterial); override;
  public
    constructor Create(CryptoProvider : TElCustomCryptoProvider  = nil );  overload;  override;
    constructor Create(const OID : ByteArray; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Alg : integer; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(const OID : ByteArray; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Alg : integer; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
     destructor  Destroy; override;
    procedure LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); override;
    procedure SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); override;    
  end;

   {$endif} //SB_HAS_ECC

{$ifndef SB_NO_DH}
  TSBDHKeyFormat =  (dhRaw, dhX509);

  TElDHKeyMaterial = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElDHKeyMaterial = TElDHKeyMaterial;
   {$endif}

  TElDHKeyMaterial =  class(TElPublicKeyMaterial)
  protected
    //FCert : TElX509Certificate;
    FKeyFormat : TSBDHKeyFormat;
    procedure Reset;
    procedure InternalGenerate(Bits : integer); override;    
    function GetValid : boolean; override;
    function GetBits : integer; override;
    function GetP : ByteArray;
    function GetG : ByteArray;
    function GetX : ByteArray;
    function GetY : ByteArray;
    function GetPeerY : ByteArray;
    procedure SetP(const Value : ByteArray);
    procedure SetG(const Value : ByteArray);
    procedure SetX(const Value : ByteArray);
    procedure SetY(const Value : ByteArray);
    procedure SetPeerY(const Value : ByteArray);
  public
    constructor Create(Prov : TElCustomCryptoProvider  = nil ); override;
    constructor Create(Manager : TElCustomCryptoProviderManager; Prov : TElCustomCryptoProvider); override;
     destructor  Destroy; override;
    procedure LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); override;
    procedure SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); override;
    // loads opponent's public key
    procedure LoadPublic(P : pointer; PSize : integer; G : pointer; GSize : integer;
      Y : pointer; YSize : integer); overload;
    procedure SavePublic(Buffer: pointer; var Size: integer); override;
    procedure SaveSecret(Buffer: pointer; var Size: integer); override;
    procedure LoadSecret(Buffer: pointer; Size: integer); override;
    // loads opponent's Y value
    procedure LoadPeerY(Y : pointer; YSize : integer);
    procedure LoadFromXML(const Str: string); override;
    function SaveToXML(IncludePrivateKey: Boolean  =  False): string; override;
    procedure Assign(Source : TElKeyMaterial); override;
    function Clone : TElKeyMaterial; override;
    function  Equals(Source : TElKeyMaterial; PublicOnly : boolean): boolean; override;
    procedure ClearSecret; override;
    procedure ClearPublic; override;
    property KeyFormat : TSBDHKeyFormat read FKeyFormat;
    property P : ByteArray read GetP write SetP;
    property G : ByteArray read GetG write SetG;
    property X : ByteArray read GetX write SetX;
    property Y : ByteArray read GetY write SetY;
    property PeerY : ByteArray read GetPeerY write SetPeerY;
  end;

  TSBDHPublicKeyCryptoType = 
    (dhpktPKCS1, dhpktRaw);

  TElDHPublicKeyCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElDHPublicKeyCrypto = TElDHPublicKeyCrypto;
   {$endif}

  TElDHPublicKeyCrypto = class(TElPublicKeyCrypto)
  protected
    FSpool : ByteArray;
    FCryptoType : TSBDHPublicKeyCryptoType;
    procedure EncryptInit; override;
    procedure EncryptUpdate( Buffer: pointer;
        Size: integer); override;
    procedure EncryptFinal; override;
    procedure DecryptInit; override;
    procedure DecryptUpdate( Buffer: pointer;
        Size: integer); override;
    procedure DecryptFinal; override;
    function EstimateOutputSize( InBuffer: pointer;
        InSize: integer;
      Operation : TSBPublicKeyOperation): integer; override;
    class function IsAlgorithmSupported(Alg: integer): boolean;  overload;  override;
    class function IsAlgorithmSupported(const OID: ByteArray): boolean;  overload;  override;
    class function GetName() : string; override;
    class function GetDescription() : string; override;
    
    
    procedure SetCryptoType(Value : TSBDHPublicKeyCryptoType);
    function GetSupportsEncryption: boolean; override;
    function GetSupportsSigning: boolean; override;
    procedure SetKeyMaterial(Material : TElPublicKeyMaterial); override;
  public
    constructor Create(CryptoProvider : TElCustomCryptoProvider  = nil );  overload;  override;
    constructor Create(const OID : ByteArray; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Alg : integer; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(const OID : ByteArray; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Alg : integer; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
     destructor  Destroy; override;
    procedure LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); override;
    procedure SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); override;

    property CryptoType : TSBDHPublicKeyCryptoType read FCryptoType write SetCryptoType;
  end;
 {$endif SB_NO_DH}

  { ElGamal key material and public key crypt classes }

  TElElGamalKeyMaterial = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElElGamalKeyMaterial = TElElGamalKeyMaterial;
   {$endif}

  TElElGamalKeyMaterial = class(TElPublicKeyMaterial)
  protected
    procedure Reset;
    {$ifndef SB_PGPSFX_STUB}
    procedure InternalGenerate(Bits : integer); override;
     {$endif SB_PGPSFX_STUB}
    function GetValid : boolean; override;
    function GetBits : integer; override;
    function GetP : ByteArray;
    function GetG : ByteArray;
    function GetY : ByteArray;
    function GetX : ByteArray;
  public
    constructor Create(Prov : TElCustomCryptoProvider  = nil ); override;
    constructor Create(Manager: TElCustomCryptoProviderManager; Prov : TElCustomCryptoProvider); override;
     destructor  Destroy; override;
    procedure Assign(Source: TElKeyMaterial); override;
    function Clone : TElKeyMaterial; override;
    procedure LoadPublic(P : pointer; PSize : integer; G : pointer;
      GSize : integer; Y : pointer; YSize : integer);
    procedure LoadSecret(P : pointer; PSize : integer; G : pointer;
      GSize : integer; Y : pointer; YSize : integer; X : pointer; XSize : integer);
    procedure SavePublic(Buffer: pointer; var Size: integer); override;
    procedure SaveSecret(Buffer: pointer; var Size: integer); override;
    {$ifndef SB_PGPSFX_STUB}
    procedure LoadFromXML(const Str: string); override;
    function SaveToXML(IncludePrivateKey: Boolean  =  False): string; override;
     {$endif SB_PGPSFX_STUB}
    function  Equals(Source : TElKeyMaterial; PublicOnly : boolean): boolean; override;
    procedure ClearSecret; override;
    procedure ClearPublic; override;
    property P : ByteArray read GetP;
    property G : ByteArray read GetG;
    property Y : ByteArray read GetY;
    property X : ByteArray read GetX;
  end;

  TElElGamalPublicKeyCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElElGamalPublicKeyCrypto = TElElGamalPublicKeyCrypto;
   {$endif}

  TElElGamalPublicKeyCrypto = class(TElPublicKeyCrypto)
  protected
    FSpool : ByteArray;
    procedure AdjustContextProps(Params : TElCPParameters); override;
    {$ifndef SB_PGPSFX_STUB}
    procedure SignInit(Detached: boolean); override;
    procedure SignUpdate( Buffer: pointer;
        Size: integer); override;
    procedure SignFinal; override;
    procedure EncryptInit; override;
    procedure EncryptUpdate( Buffer: pointer;
        Size: integer); override;
    procedure EncryptFinal; override;
     {$endif SB_PGPSFX_STUB}
    procedure DecryptInit; override;
    procedure DecryptUpdate( Buffer: pointer;
        Size: integer); override;
    procedure DecryptFinal; override;
    procedure VerifyInit(Detached: boolean;  Signature: pointer;
        SigSize: integer); override;
    procedure VerifyUpdate( Buffer: pointer;  Size: integer); override;
    function VerifyFinal : TSBPublicKeyVerificationResult; override;
    function EstimateOutputSize( InBuffer: pointer;
        InSize: integer;
      Operation : TSBPublicKeyOperation): integer; override;
    class function IsAlgorithmSupported(Alg: integer): boolean;  overload;  override;
    class function IsAlgorithmSupported(const OID: ByteArray): boolean;  overload;  override;
    class function GetName() : string; override;
    class function GetDescription() : string; override;
    procedure Reset; 
    
    
    function GetSupportsEncryption: boolean; override;
    function GetSupportsSigning: boolean; override;
    procedure SetKeyMaterial(Material : TElPublicKeyMaterial); override;
  public
    constructor Create(const OID : ByteArray; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Alg : integer; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(CryptoProvider : TElCustomCryptoProvider  = nil );  overload;  override;
    constructor Create(const OID : ByteArray; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Alg : integer; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
     destructor  Destroy; override;

    procedure EncodeResult(A : pointer; ASize : integer; B : pointer; BSize : integer;
      Blob : pointer; var BlobSize : integer);
    procedure DecodeResult(Blob : pointer; BlobSize : integer; A : pointer;
      var ASize : integer; B : pointer; var BSize : integer);
  end;

  {$ifndef SB_NO_SRP}
  TElSRPKeyMaterial =  class(TElPublicKeyMaterial)
  protected
    FSRPContext:TSRPContext;

    function GetSalt:ByteArray;
    function GetN:ByteArray;
    function GetG:ByteArray;
    function GetX:ByteArray;
    function GetA:ByteArray;
    function GetK:ByteArray;
    function GetA_small:ByteArray;
    function GetB:ByteArray;
    function GetB_small:ByteArray;
    function GetV:ByteArray;
    function GetU:ByteArray;
    function GetS:ByteArray;
  public
    constructor Create(Prov : TElCustomCryptoProvider  = nil ); override;
    constructor Create(Manager : TElCustomCryptoProviderManager; Prov : TElCustomCryptoProvider); override;
     destructor  Destroy; override;
    procedure Assign(Source : TElKeyMaterial); override;
    function LoadPublic(N:ByteArray; G: ByteArray; Salt:ByteArray; V:ByteArray):boolean; overload; 
    function LoadPublic(Buffer : Pointer; Len: LongInt):boolean; reintroduce; overload; 

    function Clone : TElKeyMaterial; override;

    property Salt    : ByteArray read GetSalt;
    property N       : ByteArray read GetN;
    property G       : ByteArray read GetG;
    property X       : ByteArray read GetX;
    property A       : ByteArray read GetA;
    property K       : ByteArray read GetK;
    property A_small : ByteArray read GetA_small;
    property B       : ByteArray read GetB;
    property B_small : ByteArray read GetB_small;
    property V       : ByteArray read GetV;
    property U       : ByteArray read GetU;
    property S       : ByteArray read GetS;
  end;

  TElSRPPublicKeyCrypto = class(TElPublicKeyCrypto)
  protected
    class function IsAlgorithmSupported(Alg: integer): boolean;  overload;  override;
    class function IsAlgorithmSupported(const OID: ByteArray): boolean;  overload;  override;
    class function GetName() : string; override;
    class function GetDescription() : string; override;
    
    
    function GetSupportsEncryption: boolean; override;
    function GetSupportsSigning: boolean; override;
    procedure SetKeyMaterial(Material : TElPublicKeyMaterial); override;
  public
    constructor Create(CryptoProvider : TElCustomCryptoProvider  = nil );  overload;  override;
    constructor Create(const OID : ByteArray; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Alg : integer; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(const OID : ByteArray; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;   override;
    constructor Create(Alg : integer; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    procedure GetServerKey(const Buffer:ByteArray; Index:integer; Len:integer; var Master:ByteArray);
    procedure GetClientKeyParam(const UserName,UserPassword:string; var A:ByteArray);
  end;
   {$endif}

  {$ifdef SB_HAS_GOST}
  { GOST key material and public key crypto classes }

  TElGOST94KeyMaterial = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElGOST94KeyMaterial = TElGOST94KeyMaterial;
   {$endif}

  TElGOST94KeyMaterial = class(TElPublicKeyMaterial)
  protected
    procedure Reset;
    procedure InternalGenerate(Bits : integer); override;
    function GetValid : boolean; override;
    function GetBits : integer; override;
    function GetP : ByteArray;
    function GetQ : ByteArray;
    function GetA : ByteArray;
    function GetX : ByteArray;
    procedure SetX(const Value : ByteArray);
    function GetY : ByteArray;
    procedure SetY(const Value : ByteArray);
    function GetProp(PropID: ByteArray) : ByteArray;
    function GetParamSet : ByteArray;
    procedure SetParamSet(const Value : ByteArray);
    function GetDigestParamSet : ByteArray;
    procedure SetDigestParamSet(const Value : ByteArray);
    function GetEncryptionParamSet : ByteArray;
    procedure SetEncryptionParamSet(const Value : ByteArray);
  public
    constructor Create(Prov : TElCustomCryptoProvider  = nil ); override;
    constructor Create(Manager : TElCustomCryptoProviderManager; Prov : TElCustomCryptoProvider); override;
     destructor  Destroy; override;
    procedure Assign(Source: TElKeyMaterial); override;
    function Clone : TElKeyMaterial; override;
    procedure LoadSecret(Buffer: pointer; Size: integer); override;
    procedure SaveSecret(Buffer: pointer; var Size: integer); override;
    procedure LoadPublic(Buffer: pointer; Size: integer); override;
    procedure SavePublic(Buffer: pointer; var Size: integer); override;
    procedure LoadPublic(P : pointer; PSize : integer; Q : pointer;
      QSize : integer; A : pointer; ASize : integer; Y : pointer; YSize : integer);   overload; 
    procedure LoadSecret(P : pointer; PSize : integer; Q : pointer;
      QSize : integer; A : pointer; ASize : integer; Y : pointer; YSize : integer;
      X : pointer; XSize : integer);   overload; 
    procedure LoadPublic(const P : ByteArray; PIndex, PSize : integer;
      const Q : ByteArray; QIndex, QSize : integer;
      const A : ByteArray; AIndex, ASize : integer;
      const Y : ByteArray; YIndex, YSize : integer);   overload; 
    procedure LoadSecret(const P : ByteArray; PIndex, PSize : integer;
      const Q : ByteArray; QIndex, QSize : integer;
      const A : ByteArray; AIndex, ASize : integer;
      const Y : ByteArray; YIndex, YSize : integer;
      const X : ByteArray; XIndex, XSize : integer);   overload; 
    procedure LoadFromXML(const Str: string); override;
    function SaveToXML(IncludePrivateKey: Boolean  =  False): string; override;
    function  Equals(Source : TElKeyMaterial; PublicOnly : boolean): boolean; override;
    procedure ClearSecret; override;
    procedure ClearPublic; override;

    procedure LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); override;
    procedure SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); override;    

    property P : ByteArray read GetP;
    property Q : ByteArray read GetQ;
    property A : ByteArray read GetA;
    property Y : ByteArray read GetY write SetY;
    property X : ByteArray read GetX write SetX;
    property ParamSet : ByteArray read GetParamSet write SetParamSet;
    property DigestParamSet : ByteArray read GetDigestParamSet write SetDigestParamSet;
    property EncryptionParamSet : ByteArray read GetEncryptionParamSet write SetEncryptionParamSet;
  end;

  TElGOST94PublicKeyCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElGOST94PublicKeyCrypto = TElGOST94PublicKeyCrypto;
   {$endif}

  TElGOST94PublicKeyCrypto = class(TElPublicKeyCrypto)
  protected
    FSpool : ByteArray;
    procedure AdjustContextProps(Params : TElCPParameters); override;
    procedure SignInit(Detached: boolean); override;
    procedure SignUpdate( Buffer: pointer;
        Size: integer); override;
    procedure SignFinal; override;
    procedure VerifyInit(Detached: boolean;  Signature: pointer;
        SigSize: integer); override;
    procedure VerifyUpdate( Buffer: pointer;  Size: integer); override;
    function VerifyFinal : TSBPublicKeyVerificationResult; override;
    function EstimateOutputSize( InBuffer: pointer;
        InSize: integer;
      Operation : TSBPublicKeyOperation): integer; override;
    class function IsAlgorithmSupported(Alg: integer): boolean;  overload;  override;
    class function IsAlgorithmSupported(const OID: ByteArray): boolean;  overload;  override;
    class function GetName() : string; override;
    class function GetDescription() : string; override;
    procedure Reset; 
    
    
    function GetSupportsEncryption: boolean; override;
    function GetSupportsSigning: boolean; override;
    procedure SetKeyMaterial(Material : TElPublicKeyMaterial); override;
  public
    constructor Create(const OID : ByteArray; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Alg : integer; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(CryptoProvider : TElCustomCryptoProvider  = nil );  overload;  override;
    constructor Create(const OID : ByteArray; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;   override;
    constructor Create(Alg : integer; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
     destructor  Destroy; override;
  end;

  {$ifdef SB_HAS_ECC}
  TElGOST2001KeyMaterial = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElGOST2001KeyMaterial = TElGOST2001KeyMaterial;
   {$endif}

  TElGOST2001KeyMaterial = class(TElPublicKeyMaterial)
  protected
    procedure Reset;
    procedure InternalGenerate(Bits : integer);   reintroduce;  overload;  override;
    function GetBits : integer; override;
    function GetValid : boolean; override;
    function GetQ : ByteArray;
    procedure SetQ(const Value : ByteArray);
    function GetD : ByteArray;
    procedure SetD(const Value : ByteArray);
    function GetParamSet : ByteArray;
    procedure SetParamSet(const Value : ByteArray);
    function GetDigestParamSet : ByteArray;
    procedure SetDigestParamSet(const Value : ByteArray);
    function GetEncryptionParamSet : ByteArray;
    procedure SetEncryptionParamSet(const Value : ByteArray);
  public
    constructor Create(Prov : TElCustomCryptoProvider  = nil ); override;
    constructor Create(Manager : TElCustomCryptoProviderManager; Prov : TElCustomCryptoProvider); override;    
     destructor  Destroy; override;
    procedure Assign(Source : TElKeyMaterial); override;
    procedure Generate;   reintroduce;  overload;  virtual;
    procedure LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); override;
    procedure SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier); override;
    procedure LoadSecret(Buffer: pointer; Size: integer); override;
    procedure SaveSecret(Buffer: pointer; var Size: integer); override;
    procedure LoadPublic(Buffer: pointer; Size: integer); override;
    procedure SavePublic(Buffer: pointer; var Size: integer); override;
    function Clone : TElKeyMaterial; override;
    function  Equals(Source : TElKeyMaterial; PublicOnly : boolean): boolean; override;
    procedure ClearSecret; override;
    procedure ClearPublic; override;

    property Q : ByteArray read GetQ write SetQ;
    property D : ByteArray read GetD write SetD;

    property ParamSet : ByteArray read GetParamSet write SetParamSet;
    property DigestParamSet : ByteArray read GetDigestParamSet write SetDigestParamSet;
    property EncryptionParamSet : ByteArray read GetEncryptionParamSet write SetEncryptionParamSet;
  end;

  TElGOST2001PublicKeyCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElGOST2001PublicKeyCrypto = TElGOST2001PublicKeyCrypto;
   {$endif}

  TElGOST2001PublicKeyCrypto = class(TElPublicKeyCrypto)
  protected
    FSpool : ByteArray;
    FUKM : ByteArray;
    FEphemeralKey : ByteArray;
    FCEKMAC : ByteArray;

    procedure AdjustContextProps(Params : TElCPParameters); override;
    procedure SaveContextProps; override;

    procedure SignInit(Detached: boolean); override;
    procedure SignUpdate( Buffer: pointer;
        Size: integer); override;
    procedure SignFinal; override;
    procedure VerifyInit(Detached: boolean;  Signature: pointer;
        SigSize: integer); override;
    procedure VerifyUpdate( Buffer: pointer;  Size: integer); override;
    function VerifyFinal : TSBPublicKeyVerificationResult; override;

    procedure EncryptInit; override;
    procedure EncryptUpdate( Buffer: pointer;
        Size: integer); override;
    procedure EncryptFinal; override;
    procedure DecryptInit; override;
    procedure DecryptUpdate( Buffer: pointer;
        Size: integer); override;
    procedure DecryptFinal; override;

    function EstimateOutputSize( InBuffer: pointer;
        InSize: integer;
      Operation : TSBPublicKeyOperation): integer; override;
    class function IsAlgorithmSupported(Alg: integer): boolean;  overload;  override;
    class function IsAlgorithmSupported(const OID: ByteArray): boolean;  overload;  override;
    class function GetName() : string; override;
    class function GetDescription() : string; override;
    procedure Reset; 
    
    
    function GetSupportsEncryption: boolean; override;
    function GetSupportsSigning: boolean; override;
    procedure SetKeyMaterial(Material : TElPublicKeyMaterial); override;
    procedure SetUKM(const V : ByteArray);
    procedure SetEphemeralKey(const V : ByteArray);
    procedure SetCEKMAC(const V : ByteArray);
  public
    constructor Create(const OID : ByteArray; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Alg : integer; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(CryptoProvider : TElCustomCryptoProvider  = nil );  overload;  override;
    constructor Create(const OID : ByteArray; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;   override;
    constructor Create(Alg : integer; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
     destructor  Destroy; override;
    property UKM : ByteArray read FUKM write SetUKM;
    property CEKMAC : ByteArray read FCEKMAC write SetCEKMAC;
    property EphemeralKey : ByteArray read FEphemeralKey write SetEphemeralKey;
  end;
   {$endif}

   {$endif SB_HAS_GOST}

  // responsible for creation of ElPublicKeyEncryption classes

  TElPublicKeyCryptoFactory = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElPublicKeyCryptoFactory = TElPublicKeyCryptoFactory;
   {$endif}

  TElPublicKeyCryptoFactory = class
  private
    FRegisteredClasses:   TElList;  
    FCryptoProvider : TElCustomCryptoProvider;
    FCryptoProviderManager : TElCustomCryptoProviderManager;
    procedure RegisterDefaultClasses;

    function GetRegisteredClass(Index: integer) : TElPublicKeyCryptoClass;
    function GetRegisteredClassCount: integer;
  public
    constructor Create(CryptoProvider : TElCustomCryptoProvider  =  nil);  overload; 
    constructor Create(Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload; 
     destructor  Destroy; override;

    function CreateKeyInstance(Buffer : pointer; Size : integer;
      const Password : string {$ifdef HAS_DEF_PARAMS} =  '' {$endif}) : TElPublicKeyMaterial; overload;
    
    function CreateKeyInstance(Stream : TElInputStream;
      const Password : string {$ifdef HAS_DEF_PARAMS} =  '' {$endif};
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}) : TElPublicKeyMaterial;  overload; 
    
    function CreateKeyInstance(Alg : integer): TElPublicKeyMaterial;  overload; 

    procedure RegisterClass(Cls : TElPublicKeyCryptoClass);
    function CreateInstance(const OID : ByteArray): TElPublicKeyCrypto;  overload; 
    function CreateInstance(Alg : integer): TElPublicKeyCrypto;  overload; 
    function IsAlgorithmSupported(const OID : ByteArray): boolean;  overload; 
    function IsAlgorithmSupported(Alg : integer): boolean;  overload; 
    
    property RegisteredClasses[Index: integer] : TElPublicKeyCryptoClass
      read GetRegisteredClass;
    
    property RegisteredClassCount : integer read GetRegisteredClassCount;
  end;

  EElPublicKeyCryptoError =  class(ESecureBlackboxError);
  EElPublicKeyCryptoAsyncError =  class(EElPublicKeyCryptoError);

implementation

uses
  SBSymmetricCrypto{$ifndef SB_PGPSFX_STUB}, SBPKCS8 {$endif};

{$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
 {$else}
var
 {$endif}

  SB_ALGSCHEME_PKCS1 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'pkcs#1' {$endif}; 
  SB_ALGSCHEME_OAEP : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'oaep' {$endif}; 
  SB_ALGSCHEME_PSS : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'pss' {$endif}; 

  SB_PKC_BUFFER_SIZE : integer  =  {$ifdef SB_CONSTRAINED_DEVICE}65536 {$else}262144 {$endif};

type
  {$ifndef SB_PGPSFX_STUB}
  TElPublicKeyMaterialWorkingThread = class( TThread )
   private 
    FSuccess : boolean;
    FBits : integer;
    FQBits : integer;
    FOwner : TElPublicKeyMaterial;
    FErrorMessage : string;
    procedure ProgressHandler(Total, Current : Int64; Data :  pointer ;
      var Cancel : TSBBoolean);
  protected
    procedure Execute; override;
  public
    constructor Create(CreateSuspended: boolean);  overload;     constructor Create(Owner: TElPublicKeyMaterial);  reintroduce;   overload; 
    property Success : boolean read FSuccess;
    property Bits : integer read FBits write FBits;
    property QBits : integer read FQBits write FQBits;
    property ErrorMessage : string read FErrorMessage;
  end;
   {$endif SB_PGPSFX_STUB}

  TElPublicKeyCryptoWorkingThread = class( TThread )
   private 
    FSuccess : boolean;
    FOwner : TElPublicKeyCrypto;
    FOperation : TSBPublicKeyOperation;
    FInStream : TElInputStream;
    FOutStream : TElOutputStream;
    FSigStream : TElInputStream;
    FCount : integer;
    FSigCount : integer;
    FVerificationResult : TSBPublicKeyVerificationResult;
    FStreamInput : boolean;
    FErrorMessage : string;
    procedure ProgressHandler(Total, Current : Int64; Data :  pointer ;
      var Cancel : TSBBoolean);
  protected
    procedure Execute; override;
  public
    constructor Create(CreateSuspended: boolean);  overload;     constructor Create(Owner: TElPublicKeyCrypto);  reintroduce;   overload; 
    property InStream : TElInputStream read FInStream write FInStream;
    property OutStream : TElOutputStream read FOutStream write FOutStream;
    property SigStream : TElInputStream read FSigStream write FSigStream;
    property Count : integer read FCount write FCount;
    property SigCount : integer read FSigCount write FSigCount;
    property Operation : TSBPublicKeyOperation read FOperation write FOperation;
    property VerificationResult : TSBPublicKeyVerificationResult read
      FVerificationResult;
    property StreamInput : boolean read FStreamInput write FStreamInput;
    property ErrorMessage : string read FErrorMessage;
    property Success : boolean read FSuccess;  
  end;

resourcestring
  SUnsupportedOperation = 'Unsupported operation';
  SBufferTooSmall = 'Output buffer is too small';
  SInternalError = 'Internal error';
  SUnsupportedAlgorithm = 'Unsupported algorithm: %s';
  SUnsupportedAlgorithmInt = 'Unsupported algorithm: %d';
//  SKeyGenerationFailed = 'Key generation failed';
  SNotASigningAlgorithm = 'Algorithm does not support signing';
//  SNotAnEncryptionAlgorithm = 'Algorithm does not support encryption';
  SFailedBase64Encode = 'Encode to Base64 failed.';
  SFailedBase64Decode = 'Decode from Base64 failed.';
  SInvalidPEM = 'Invalid PEM data';
  SInvalidXML = 'Invalid XML string';
  SPEMWriteError = 'PEM write error';
  SInvalidKeyMaterialType = 'Invalid key material type';
  SInvalidPublicKey = 'Invalid public key';
  SInvalidSecretKey = 'Invalid secret key';
  SInvalidPassphrase = 'Invalid passphrase';
  SInputTooLong = 'Input is too long';
  SPublicKeyNotFound = 'Public key not found';
  SSecretKeyNotFound = 'Secret key not found';
  SBadKeyMaterial = 'Bad key material';
//  SEncryptionFailed = 'Encryption failed';
//  SDecryptionFailed = 'Decryption failed';
//  SSigningFailed = 'Signing failed';
//  SUnsupportedEncryptionType = 'Unsupported encryption type';
//  SBadSignatureFormatting = 'Bad signature formatting';
  SOnlyDetachedSigningSupported = 'Only detached signatures are supported';
//  SNotImplemented = 'Not implemented';
//  SUnsupportedCertType = 'Unsupported certificate type';
//  SInvalidSignatureEncoding = 'Invalid signature encoding';
//  SInvalidEncoding = 'Invalid encoding';
  SInvalidBase64Encoding = 'Invalid Base64 encoding';
//  SInvalidInput = 'Invalid input';
//  SInvalidPadding = 'Invalid padding';
//  SKeyMaterialNotInitialized = 'Key material is not initialized';
  SUnsupportedKeyMaterial = 'Unsupported key material';
  SAsyncOperationFailed = 'Async operation failed';
  SAsyncOperationPending = 'Async operation pending';
  SNoAsyncOperationPending = 'No async operation pending';
  SIncorrectFunctionCall = 'Incorrect function call';
  SInvalidKeyParameters = 'Invalid key parameters';
  SInvalidAlgorithmIdentifier = 'Invalid algorithm identifier';

(*
// auxiliary routines

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
*)

function ConvertToBase64String(const Buf: ByteArray): string;
var
  InBuf, OutBuf: ByteArray;
  OutSize: Integer;
  i, n: Integer;
begin
  i := 0;
  n := Length(Buf);
  while (i < n) and (Buf[i] = 0) do
    Inc(i);

  // remove zeros
  if i > 0 then
  begin
    n := n - i;
    SetLength(InBuf, n);
    if n > 0 then
      SBMove(Buf[i], InBuf[0], n);
  end
  else
    InBuf := CloneArray(Buf);

  if Length(InBuf) = 0 then
  begin
    Result := '';
    Exit;
  end;

  OutSize := 0;
  Base64Encode(@InBuf[0], Length(InBuf), nil, OutSize, False);
  SetLength(OutBuf, OutSize);
  if not Base64Encode(@InBuf[0], Length(InBuf), @OutBuf[0], OutSize, False) then
    raise EElPublicKeyCryptoError.Create(SFailedBase64Encode);

  SetLength(OutBuf, OutSize);
  Result := StringOfBytes(OutBuf);
  ReleaseArrays(InBuf, OutBuf);
end;

function ConvertFromBase64String(const S: string): ByteArray;
var
  InBuf: ByteArray;
  i, k, OutSize: Integer;
begin
  if Length(S) = 0 then
  begin
    Result := nil;
    Exit;
  end;

  SetLength(InBuf, Length(S));
  k := 0;
  for i := StringStartOffset to Length(S) - StringStartInvOffset do
    if (Byte(S[i]) > 32)  then
    begin
      InBuf[k] := Byte(S[i]);
      Inc(k);
    end;

  SetLength(InBuf, k);

  OutSize := 0;
  Base64Decode(@InBuf[0], Length(InBuf), nil, OutSize);
  SetLength(Result, OutSize);
  if Base64Decode(@InBuf[0], Length(InBuf), @Result[0], OutSize) <> BASE64_DECODE_OK then
    raise EElPublicKeyCryptoError.Create(SFailedBase64Decode);

  SetLength(Result, OutSize);
  ReleaseArray(InBuf);
end;

type
  TXMLParamNames = array of string;
  TXMLParamValues = array of ByteArray;


function ParseXmlString(const Str: string; const KeyValueName: string; const ParamNames: array of string): TXMLParamValues;

  function RemoveXmlComments(const Str: string): string;
  var
    i, k: Integer;
  begin
    Result := Str;
    i := StringIndexOf(Result, '<!--');

    while i >= StringStartOffset do
    begin
      k := StringIndexOf(Result, '-->');
      if (k < StringStartOffset) or (k < i) then
        raise EElPublicKeyCryptoError.Create(SInvalidXML);

      Result := StringSubstring(Result, StringStartOffset, i - StringStartOffset) + StringSubstring(Result, k + 3);
      i := StringIndexOf(Result, '<!--');
    end;
  end;

  function ParseXmlElement(const Str: string; var LocalName: string; var CurPos: Integer): string;
  var
    i, k: Integer;
    s: string;
  begin
    i := CurPos;
    while (i < Length(Str) - StringStartInvOffset) and (Str[i] <> '<') do
      Inc(i);

    if i >= Length(Str) - StringStartInvOffset then
    begin
      CurPos := i;
      LocalName := '';
      Result := '';
      Exit;
    end;

    Inc(i);
    CurPos := i;
    k := -1;
    while (i < Length(Str) - StringStartInvOffset) and
          (Ord(Str[i]) > 32) and (Str[i] <> '>') and (Str[i] <> '/') do
    begin
      Inc(i);
      if Str[i] = ':' then
      begin
        if k >= 0 then
          raise EElPublicKeyCryptoError.Create(SInvalidXML);
        k := i;
      end;
    end;

    if i = CurPos then
      raise EElPublicKeyCryptoError.Create(SInvalidXML);

    s := StringSubstring(Str, CurPos, i - CurPos);
    if k >= 0 then
      LocalName := StringSubstring(Str, k + 1, i - k - 1)
    else
      LocalName := s;

    while (i < Length(Str) - StringStartInvOffset) and
          (Str[i] <> '>') and (Str[i] <> '/') do
      Inc(i);

    if i >= Length(Str) - StringStartInvOffset then
      raise EElPublicKeyCryptoError.Create(SInvalidXML);

    if Str[i] = '/' then
    begin
      Inc(i);
      if (i >= Length(Str) - StringStartInvOffset) or (Str[i] <> '>') then
        raise EElPublicKeyCryptoError.Create(SInvalidXML);

      Result := '';
      CurPos := i + 1;
      Exit;
    end;

    k := StringIndexOf(Str, '</' + s + '>');
    if k < i then
      raise EElPublicKeyCryptoError.Create(SInvalidXML);

    Result := StringSubstring(Str, i + 1, k - i - 1);

    CurPos := k + Length(s) + 3;
  end;

var
  s, LocalName, Value: string;
  i, k: Integer;
begin
  s := RemoveXmlComments(Str);
  k := StringStartOffset;
  s := ParseXmlElement(s, LocalName, k);
  if LocalName <> KeyValueName then
    raise EElPublicKeyCryptoError.Create(SInvalidXML);

  SetLength(Result, Length(ParamNames));
  k := StringStartOffset;
  while k < Length(s) - StringStartInvOffset do
  begin
    Value := ParseXmlElement(s, LocalName, k);
    for i := 0 to Length(ParamNames) - 1 do
      if LocalName = ParamNames[i] then
      begin
        Result[i] := ConvertFromBase64String(Value);
        Break;
      end;
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// TElPublicKeyMaterialWorkingThread

{$ifndef SB_PGPSFX_STUB}
procedure TElPublicKeyMaterialWorkingThread.ProgressHandler(Total, Current : Int64;
  Data :  pointer ; var Cancel : TSBBoolean);
begin
  Cancel := Terminated;
end;

procedure TElPublicKeyMaterialWorkingThread.Execute;
begin
  FSuccess := false;
  try
    if (FOwner is TElDSAKeyMaterial) and (FQBits <> 0) then
      TElDSAKeyMaterial(FOwner).InternalGenerate(FBits, FQBits)
    else
      FOwner.InternalGenerate(FBits);

    FSuccess := true;
  except
    on E : Exception do FErrorMessage := E. Message ;
  end;

  FOwner.OnThreadTerminate(Self);
end;

constructor TElPublicKeyMaterialWorkingThread.Create(CreateSuspended: boolean);
begin
  inherited Create(CreateSuspended);

  FSuccess := false;
  FBits := 0;
  FQBits := 0;
  FErrorMessage := '';
  FOwner := nil;
end;

constructor TElPublicKeyMaterialWorkingThread.Create(Owner: TElPublicKeyMaterial);
begin
  Create(true);
  FOwner := Owner;
end;
 {$endif SB_PGPSFX_STUB}

////////////////////////////////////////////////////////////////////////////////
// TElPublicKeyCryptoWorkingThread

procedure TElPublicKeyCryptoWorkingThread.ProgressHandler(Total, Current : Int64;
  Data :  pointer ;
  var Cancel : TSBBoolean);
begin
  Cancel := Terminated;
end;

procedure TElPublicKeyCryptoWorkingThread.Execute;
begin
  FSuccess := false;
  FErrorMessage := '';
  try
    if not FStreamInput then
    begin
      {$ifndef SB_PGPSFX_STUB}
      if FOperation = pkoEncrypt then
        FOwner.InternalEncrypt
      else
       {$endif SB_PGPSFX_STUB}
      if FOperation = pkoDecrypt then
        FOwner.InternalDecrypt
      else
      {$ifndef SB_PGPSFX_STUB}
      if FOperation = pkoSign then
        FOwner.InternalSign
      else
      if FOperation = pkoSignDetached then
        FOwner.InternalSignDetached
      else
       {$endif SB_PGPSFX_STUB}
      if FOperation = pkoVerify then
        FVerificationResult := FOwner.InternalVerify
      else
      if FOperation = pkoVerifyDetached then
        FVerificationResult := FOwner.InternalVerifyDetached;        
    end
    else
    begin
      {$ifndef SB_PGPSFX_STUB}
      if FOperation = pkoEncrypt then
        FOwner.InternalEncrypt(FInStream, FOutStream, FCount)
      else
       {$endif SB_PGPSFX_STUB}
      if FOperation = pkoDecrypt then
        FOwner.InternalDecrypt(FInStream, FOutStream, FCount)
      else
      {$ifndef SB_PGPSFX_STUB}
      if FOperation = pkoSign then
        FOwner.InternalSign(FInStream, FOutStream, FCount)
      else
      if FOperation = pkoSignDetached then
        FOwner.InternalSignDetached(FInStream, FOutStream, FCount)
      else
       {$endif SB_PGPSFX_STUB}
      if FOperation = pkoVerify then
        FVerificationResult := FOwner.InternalVerify(FInStream, FOutStream, FCount)
      else
      if FOperation = pkoVerifyDetached then
        FVerificationResult := FOwner.InternalVerifyDetached(FInStream, FSigStream, FCount, FSigCount);        
    end;
    FSuccess := true;
  except
    on E : Exception do FErrorMessage := E. Message ;
  end;
  FOwner.OnThreadTerminate(Self);
end;

constructor TElPublicKeyCryptoWorkingThread.Create(CreateSuspended: boolean);
begin
  inherited Create(CreateSuspended);
  FOwner := nil;
  FInStream := nil;
  FOutStream := nil;
  FSigStream := nil;
  FStreamInput := false;
  FSuccess := false;
  FErrorMessage := '';
end;

constructor TElPublicKeyCryptoWorkingThread.Create(Owner: TElPublicKeyCrypto);
begin
  Create(true);
  FOwner := Owner;
end;

////////////////////////////////////////////////////////////////////////////////
// TElPublicKeyMaterial class

constructor TElPublicKeyMaterial.Create(Prov : TElCustomCryptoProvider);
begin
  inherited Create;
  if Prov = nil then
    Prov := DefaultCryptoProviderManager.DefaultCryptoProvider;
    //Prov := DefaultCryptoProvider;
  FProvider := Prov;
  FKey := nil;
  FBusy := false;
  FAsyncOperationFinished := false;
  FAsyncOperationSucceeded := false;
  FOnAsyncOperationFinished := nil;
  FAsyncOperationError := '';
  FWorkingThread := nil;
  FStoreFormat := ksfRaw;
end;

constructor TElPublicKeyMaterial.Create(Manager: TElCustomCryptoProviderManager;
  Prov : TElCustomCryptoProvider); 
begin
  inherited Create;
  if Prov = nil then
  begin
    if Manager = nil then
      Manager := DefaultCryptoProviderManager;
    Prov := Manager.DefaultCryptoProvider;
  end;
  FProvider := Prov;
  FProviderManager := Manager;
  FKey := nil;
  FBusy := false;
  FAsyncOperationFinished := false;
  FAsyncOperationSucceeded := false;
  FOnAsyncOperationFinished := nil;
  FAsyncOperationError := '';
  FWorkingThread := nil;
  FStoreFormat := ksfRaw;
end;


 destructor  TElPublicKeyMaterial.Destroy;
begin
  if Assigned(FKey) then
    FProvider.ReleaseKey(FKey);
  inherited;
end;

class function TElPublicKeyMaterial.GetMaxPublicKeySize(Prov : TElCustomCryptoProvider): integer;
begin
  if Prov = nil then
    Prov := DefaultCryptoProviderManager.DefaultCryptoProvider;
    //Prov := DefaultCryptoProvider;
  Result := Prov.Options.MaxPublicKeySize;
end;

procedure TElPublicKeyMaterial.SetOnAsyncOperationFinished(Value : TSBAsyncOperationFinishedEvent);
begin
  if FBusy then Exit;
  FOnAsyncOperationFinished := Value;
end;

function TElPublicKeyMaterial.IsPEM( Buffer: pointer;
    Size: integer): boolean;
var
  Ptr: ^byte;
begin
  Ptr := Buffer;
  while (Size > 0) and (Ptr^ in [9, 10, 13, 32]) do
  begin
    Inc(Ptr);
    Dec(Size);
  end;
  Result := (Size > Length(FiveDashesByteArray)) and (CompareMem(Buffer, @FiveDashesByteArray[0],
    Length(FiveDashesByteArray)));
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElPublicKeyMaterial.InternalGenerate(Bits : integer);
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;
 {$endif SB_PGPSFX_STUB}

procedure TElPublicKeyMaterial.AssignCryptoKey(Key : TElCustomCryptoKey);
begin
  if Assigned(FProvider) and Assigned(FKey) then
    FProvider.ReleaseKey(Key);
  FKey := Key.CryptoProvider.CloneKey(Key);
  FProvider := Key.CryptoProvider;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElPublicKeyMaterial.Generate(Bits : integer);
begin
  if FBusy then Exit;
  InternalGenerate(Bits);
end;

procedure TElPublicKeyMaterial.BeginGenerate(Bits : integer);
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);

  FAsyncOperationFinished := false;
  FAsyncOperationSucceeded := false;
  FBusy := true;
  FWorkingThread := TElPublicKeyMaterialWorkingThread.Create(Self);
  TElPublicKeyMaterialWorkingThread(FWorkingThread).Bits := Bits;
  FWorkingThread.FreeOnTerminate := true;
  FWorkingThread.Resume;
end;

procedure TElPublicKeyMaterial.EndGenerate;
begin
  if not FBusy then
    raise EElPublicKeyCryptoError.Create(SNoAsyncOperationPending);

  while not FAsyncOperationFinished do
    Sleep(50);

  FBusy := false;
  if not FAsyncOperationSucceeded then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationFailed);
end;

procedure TElPublicKeyMaterial.CancelAsyncOperation;
begin
  if FBusy and Assigned(FWorkingThread) then
  begin
    FWorkingThread.Terminate;
    while not FAsyncOperationFinished do
      Sleep(50);
  end
  else
    FKey.CancelPreparation;

  FBusy := false;
end;

procedure TElPublicKeyMaterial.PrepareForEncryption(MultiUse : boolean  =  false);
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);
  FKey.PrepareForEncryption(MultiUse);
end;

procedure TElPublicKeyMaterial.PrepareForSigning(MultiUse : boolean  =  false);
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);
  FKey.PrepareForSigning(MultiUse);
end;
 {$endif SB_PGPSFX_STUB}

{$ifndef SB_PGPSFX_STUB}
procedure TElPublicKeyMaterial.OnThreadTerminate(Sender : TObject);
begin
  FAsyncOperationSucceeded := TElPublicKeyMaterialWorkingThread(FWorkingThread).Success;
  FAsyncOperationError := TElPublicKeyMaterialWorkingThread(FWorkingThread).ErrorMessage;

  if Assigned(FOnAsyncOperationFinished) then
    FOnAsyncOperationFinished(Self, FAsyncOperationSucceeded);

  FAsyncOperationFinished := true;
  FWorkingThread := nil;
end;
 {$endif SB_PGPSFX_STUB}

procedure TElPublicKeyMaterial.LoadPublic(Buffer: pointer; Size: integer);
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

procedure TElPublicKeyMaterial.LoadSecret(Buffer: pointer; Size: integer);
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

procedure TElPublicKeyMaterial.SavePublic(Buffer: pointer; var Size: integer);
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

procedure TElPublicKeyMaterial.SaveSecret(Buffer: pointer; var Size: integer);
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

procedure TElPublicKeyMaterial.LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

procedure TElPublicKeyMaterial.SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

procedure TElPublicKeyMaterial.LoadPublic(Stream : TElInputStream;
  Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
var
  Buf : ByteArray;
begin
  if Count = 0 then
    Count :=  Stream.Size  - Stream.Position;
  SetLength(Buf, Count);
  Count := Stream.Read(Buf [0] , Count);
  LoadPublic( @Buf[0] , Count);
end;

procedure TElPublicKeyMaterial.LoadSecret(Stream : TElInputStream;
  Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
var
  Buf : ByteArray;
begin
  try
    if Count = 0 then
      Count :=  Stream.Size  - Stream.Position;
    SetLength(Buf, Count);
    Count := Stream.Read(Buf [0] , Count);
    LoadSecret( @Buf[0] , Count);
  finally
    ReleaseArray(Buf, true);
  end;
end;

procedure TElPublicKeyMaterial.SavePublic(Stream : TElOutputStream);
var
  Buf : ByteArray;
  Size : TSBInteger;
begin
  Size := 0;
  SavePublic( nil , Size);
  SetLength(Buf, Size);
  SavePublic( @Buf[0] , Size);
  Stream.Write(Buf [0] , Size);
end;

procedure TElPublicKeyMaterial.SaveSecret(Stream : TElOutputStream);
var
  Buf : ByteArray;
  Size : TSBInteger;
begin
  Size := 0;
  SaveSecret( nil , Size);
  SetLength(Buf, Size);
  SaveSecret( @Buf[0] , Size);
  Stream.Write(Buf [0] , Size);
  ReleaseArray(Buf, true);
end;

procedure TElPublicKeyMaterial.Save(Stream : TElOutputStream);
begin
  if SecretKey then
    SaveSecret(Stream)
  else
    SavePublic(Stream);
end;

procedure TElPublicKeyMaterial.Load(Stream : TElInputStream;
  Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
var
  OldPos : integer;
  B : boolean;
begin
  OldPos := Stream.Position;
  // trying to load secret key
  B := true;
  try
    LoadSecret(Stream, Count);
  except
    B := false;
  end;
  // trying to load public key
  if not B then
  begin
    Stream.Position := OldPos;
    LoadPublic(Stream, Count);
  end;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElPublicKeyMaterial.LoadFromXML(const Str: string);
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

function TElPublicKeyMaterial.SaveToXML(IncludePrivateKey: Boolean  =  False): string;
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;
 {$endif SB_PGPSFX_STUB}

function TElPublicKeyMaterial.GetValid : boolean;
begin
  Result := false;
end;

function TElPublicKeyMaterial.GetIsPublicKey : boolean;
begin
  if Assigned(FKey) then
    Result := FKey.IsPublic
  else
    Result := false;
end;

function TElPublicKeyMaterial.GetIsSecretKey : boolean;
begin
  if Assigned(FKey) then
    Result := FKey.IsSecret
  else
    Result := false;
end;

function TElPublicKeyMaterial.Clone :  TElKeyMaterial ;
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

function  TElPublicKeyMaterial.Equals(Source : TElKeyMaterial; PublicOnly : boolean): boolean;
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

function TElPublicKeyMaterial.GetExportable : boolean;
begin
  if Assigned(FKey) then
    Result := FKey.IsExportable
  else
    Result := false;
end;

procedure TElPublicKeyMaterial.ClearSecret;
begin
  ;
end;

procedure TElPublicKeyMaterial.ClearPublic;
begin
  ;
end;

procedure TElPublicKeyMaterial.Clear;
begin
  ClearPublic;
  ClearSecret;
end;

{$ifdef SB_HAS_WINCRYPT}
function TElPublicKeyMaterial.GetCertHandle :   PCCERT_CONTEXT  ;
begin
  Result := GetPointerFromBuffer(FKey.GetKeyProp(SB_KEYPROP_WIN32_CERTCONTEXT, EmptyArray));
end;

procedure TElPublicKeyMaterial.SetCertHandle(Value:   PCCERT_CONTEXT  );
begin
  FKey.SetKeyProp(SB_KEYPROP_WIN32_CERTCONTEXT, GetBufferFromPointer(Value));
end;

function TElPublicKeyMaterial.GetKeyExchangePIN() : string;
begin
  Result := UTF8ToStr(FKey.GetKeyProp(SB_KEYPROP_WIN32_KEYEXCHANGEPIN, EmptyArray));
end;

procedure TElPublicKeyMaterial.SetKeyExchangePIN(const Value: string);
begin
  FKey.SetKeyProp(SB_KEYPROP_WIN32_KEYEXCHANGEPIN, StrToUTF8(Value));
end;

function TElPublicKeyMaterial.GetSignaturePIN() : string;
begin
  Result := UTF8ToStr(FKey.GetKeyProp(SB_KEYPROP_WIN32_SIGNATUREPIN, EmptyArray));
end;

procedure TElPublicKeyMaterial.SetSignaturePIN(const Value: string);
begin
  FKey.SetKeyProp(SB_KEYPROP_WIN32_SIGNATUREPIN, StrToUTF8(Value));
end;                                        
 {$endif}


function TElPublicKeyMaterial.GetKeyHandle : SB_CK_ULONG;
begin
  Result := GetInt64PropFromBuffer(FKey.GetKeyProp(SB_KEYPROP_PKCS11_KEY_HANDLE, EmptyArray));
end;

procedure TElPublicKeyMaterial.SetKeyHandle(Value : SB_CK_ULONG);
begin
  FKey.SetKeyProp(SB_KEYPROP_PKCS11_KEY_HANDLE, GetBufferFromInt64(Value));
end;

function TElPublicKeyMaterial.GetSessionHandle : SB_CK_ULONG;
begin
  Result := GetInt64PropFromBuffer(FKey.GetKeyProp(SB_KEYPROP_PKCS11_SESSION_HANDLE, EmptyArray));
end;

procedure TElPublicKeyMaterial.SetSessionHandle(Value : SB_CK_ULONG);
begin
  FKey.SetKeyProp(SB_KEYPROP_PKCS11_SESSION_HANDLE, GetBufferFromInt64(Value));
end;

function TElPublicKeyMaterial.GetAsyncOperationFinished : boolean;
begin
  Result := FAsyncOperationFinished;
  {$ifndef SB_PGPSFX_STUB}
  if not Result then
    Result := FKey.AsyncOperationFinished;
   {$endif SB_PGPSFX_STUB}
end;

////////////////////////////////////////////////////////////////////////////////
// TElPublicKeyCrypto class

constructor TElPublicKeyCrypto.Create(const OID : ByteArray; CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
   Create (CryptoProvider);
end;


constructor TElPublicKeyCrypto.Create(Alg : integer; CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
   Create (CryptoProvider);
end;

constructor TElPublicKeyCrypto.Create(CryptoProvider : TElCustomCryptoProvider  = nil );
begin
  inherited Create;

  FKeyMaterial := nil;
  FInputEncoding := pkeBinary;
  FOutputEncoding := pkeBinary;
  FBusy := false;
  FAsyncOperationFinished := false;
  FAsyncOperationSucceeded := false;
  FOnAsyncOperationFinished := nil;
  FWorkingThread := nil;
  FAsyncOperationError := '';
  FCryptoProvider := CryptoProvider;
end;

constructor TElPublicKeyCrypto.Create(const OID : ByteArray; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
   Create (Manager, CryptoProvider);
end;

constructor TElPublicKeyCrypto.Create(Alg : integer; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
   Create (Manager, CryptoProvider);
end;

constructor TElPublicKeyCrypto.Create(Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create;

  FKeyMaterial := nil;
  FInputEncoding := pkeBinary;
  FOutputEncoding := pkeBinary;
  FBusy := false;
  FAsyncOperationFinished := false;
  FAsyncOperationSucceeded := false;
  FOnAsyncOperationFinished := nil;
  FWorkingThread := nil;
  FAsyncOperationError := '';
  FCryptoProvider := CryptoProvider;
  FCryptoProviderManager := Manager;
end;

 // SB_JAVA

 destructor  TElPublicKeyCrypto.Destroy;
begin
  if Assigned(FContext) and Assigned(FContext.CryptoProvider) then
    FContext.CryptoProvider.ReleaseCryptoContext(FContext);
  inherited;
end;

procedure TElPublicKeyCrypto.LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  ;
end;

procedure TElPublicKeyCrypto.SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  ;
end;

function TElPublicKeyCrypto.GetSuitableCryptoProvider(Operation : TSBPublicKeyOperation;
  Algorithm : integer; Pars : TElCPParameters) : TElCustomCryptoProvider;
  function ConvertOpType(OpType : TSBPublicKeyOperation): integer;
  begin
    case OpType of
      pkoEncrypt : Result := SB_OPTYPE_ENCRYPT;
      pkoDecrypt : Result := SB_OPTYPE_DECRYPT;
      pkoSign : Result := SB_OPTYPE_SIGN;
      pkoSignDetached : Result := SB_OPTYPE_SIGN_DETACHED;
      pkoVerify : Result := SB_OPTYPE_VERIFY;
      pkoVerifyDetached : Result := SB_OPTYPE_VERIFY_DETACHED;
      pkoDecryptKey : Result := SB_OPTYPE_KEY_DECRYPT;
    else
      Result := SB_OPTYPE_NONE;
    end;
  end;
var
  OpType : integer;
  KM : TElCustomCryptoKey;
begin
  OpType := ConvertOpType(Operation);
  if Assigned(FKeyMaterial) then
    KM := FKeyMaterial.FKey
  else
    KM := nil;
  // highest priority: cryptoprovider that is explicitly assigned to the crypto object
  if Assigned(FCryptoProvider) and (FCryptoProvider.IsOperationSupported(OpType, Algorithm, 0, KM, Pars)) then
    Result := FCryptoProvider
  // 2nd priority level: cryptoprovidermanager assigned
  else if Assigned(FCryptoProviderManager) then
  begin
    // if some provider is assigned to the key material object, checking
    // if it suits the settings of assigned cryptoprovidermanager. If it does,
    // returning it. If it doesn't, obtaining the suitable provider from the
    // assigned manager
    if Assigned(FKeyMaterial) and Assigned(FKeyMaterial.FProvider) and
      FCryptoProviderManager.IsProviderAllowed(FKeyMaterial.FProvider) and
      (FKeyMaterial.FProvider.IsOperationSupported(OpType, Algorithm, 0, KM, Pars)) then
      Result := FKeyMaterial.FProvider
    else
      Result := FCryptoProviderManager.GetSuitableProvider(OpType, Algorithm, 0, KM, Pars);
  end
  // 3rd priority level: cryptoprovider of the key material object
  else if Assigned(FKeyMaterial) and Assigned(FKeyMaterial.FProvider) and
    (FKeyMaterial.FProvider.IsOperationSupported(OpType, Algorithm, 0, KM, Pars)) then
    Result := FKeyMaterial.FProvider
  else
  // other cases: provider returned by the default cryptoprovidermanager
  begin
    Result := DefaultCryptoProviderManager.GetSuitableProvider(OpType, Algorithm, 0, KM, Pars);
  end;
end;

function TElPublicKeyCrypto.GetSupportsEncryption: boolean;
begin
  {$ifdef FPC}
  result := false;
   {$endif}
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

function TElPublicKeyCrypto.GetSupportsSigning: boolean;
begin
  {$ifdef FPC}
  result := false;
   {$endif}
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

class function TElPublicKeyCrypto.IsAlgorithmSupported(Alg: integer): boolean;
begin
  Result := false;
end;

class function TElPublicKeyCrypto.IsAlgorithmSupported(const OID: ByteArray): boolean;
begin
  Result := false;
end;

procedure TElPublicKeyCrypto.DecodeInput(InData : pointer; InSize : integer);
var
  OutSize, I : integer;
  Res : boolean;
begin
  if FInputEncoding = pkeBinary
  then
  begin
    SetLength(FInputSpool, InSize);
    SBMove(InData^, FInputSpool[0], InSize);
  end
  else
  begin
    B64InitializeDecoding(FInB64Ctx);
    OutSize := 0;
    B64Decode(FInB64Ctx, InData, InSize, nil, OutSize);
    SetLength(FInputSpool, OutSize);
    if not B64Decode(FInB64Ctx, InData, InSize, @FInputSpool[0], OutSize) then
      raise EElPublicKeyCryptoError.Create(SInvalidBase64Encoding);
    I := 0;
    Res := B64FinalizeDecoding(FInB64Ctx, nil, I);
    if I > 0 then
    begin
      SetLength(FInputSpool, OutSize + I);
      Res := B64FinalizeDecoding(FInB64Ctx, @FInputSpool[OutSize], I);
    end;

    if not Res then
      raise EElPublicKeyCryptoError.Create(SInvalidBase64Encoding);
  end;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElPublicKeyCrypto.SignInit(Detached: boolean);
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

procedure TElPublicKeyCrypto.SignUpdate( Buffer: pointer;
   Size: integer);
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

procedure TElPublicKeyCrypto.SignFinal;
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

procedure TElPublicKeyCrypto.EncryptInit;
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

procedure TElPublicKeyCrypto.EncryptUpdate( Buffer: pointer;
   Size: integer);
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

procedure TElPublicKeyCrypto.EncryptFinal;
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;
 {$endif SB_PGPSFX_STUB}

procedure TElPublicKeyCrypto.DecryptInit;
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

procedure TElPublicKeyCrypto.DecryptUpdate( Buffer: pointer;
   Size: integer);
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

procedure TElPublicKeyCrypto.DecryptFinal;
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

procedure TElPublicKeyCrypto.VerifyInit(Detached: boolean;  Signature: pointer;
    SigSize: integer);
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

procedure TElPublicKeyCrypto.VerifyUpdate( Buffer: pointer;  Size: integer);
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

function TElPublicKeyCrypto.VerifyFinal: TSBPublicKeyVerificationResult;
begin
  {$ifdef FPC}
  result := pkvrFailure;
   {$endif}
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

function TElPublicKeyCrypto.EstimateOutputSize( InBuffer: pointer;
    InSize: integer;
  Operation : TSBPublicKeyOperation): integer;
begin
  {$ifdef FPC}
  result := 0;
   {$endif}
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

procedure TElPublicKeyCrypto.WriteToOutput( Buffer: pointer;
    Size: integer);
var
  OldLen, OutSize : integer;
  TmpBuf : ByteArray;
begin
  if FOutputEncoding = pkeBase64 then
  begin
    OutSize := 0;
    B64Encode(FOutB64Ctx, Buffer, Size, nil, OutSize);
    SetLength(TmpBuf, OutSize);
    B64Encode(FOutB64Ctx, Buffer, Size, @TmpBuf[0], OutSize);

    if FOutputIsStream then
      FOutputStream.Write( TmpBuf[0] , OutSize)
    else
    begin
      OldLen := Length(FOutput);
      SetLength(FOutput, OldLen + OutSize);
      SBMove(TmpBuf[0], FOutput[OldLen], OutSize);
    end;
    ReleaseArray(TmpBuf);
  end
  else
  begin
    if FOutputIsStream then
      FOutputStream.Write( Buffer^ , Size)
    else
    begin
      OldLen := Length(FOutput);
      SetLength(FOutput, OldLen + Size);
      SBMove(Buffer^, FOutput[OldLen], Size);
    end;
  end;
end;

procedure TElPublicKeyCrypto.Reset;
begin
  SetLength(FOutput, 0);
  FOutputStream := nil;
  FOutputIsStream := false;
  if Assigned(FContext) and Assigned(FContext.CryptoProvider) then
    FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElPublicKeyCrypto.InternalEncrypt;
var
  Needed, I : integer;
begin
  SetLength(FOutput, 0);
  if FOutputEncoding = pkeBase64 then
    B64InitializeEncoding(FOutB64Ctx, 0, emNone);

  EncryptInit;
  try
    EncryptUpdate(@FInputSpool[0], Length(FInputSpool));
  finally
    EncryptFinal;
  end;

  if FOutputEncoding = pkeBase64 then
  begin
    Needed := 0;
    I := Length(FOutput);

    B64FinalizeEncoding(FOutB64Ctx, nil, Needed);

    SetLength(FOutput, I + Needed);

    B64FinalizeEncoding(FOutB64Ctx, @FOutput[I], Needed);
    
    if FOutputIsStream then
    begin
      FOutputStream.Write(FOutput[0], Length(FOutput));
      SetLength(FOutput, 0);
    end;
  end;
end;

procedure TElPublicKeyCrypto.Encrypt(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
  var OutSize: integer);
var
  Needed : integer;
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);

  if not SupportsEncryption then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.PublicKey) then
    raise EElPublicKeyCryptoError.Create(SPublicKeyNotFound);

  DecodeInput(InBuffer, InSize);

  Needed := EstimateOutputSize(@FInputSpool[0], Length(FInputSpool), pkoEncrypt);

  SetLength(FOutput, 0);
  if FOutputEncoding = pkeBase64 then
    Needed := (Needed + 2) div 3 * 4;

  if (Needed > OutSize) then
  begin
    if OutSize = 0 then
    begin
       OutSize  := Needed;
      Exit;
    end
    else
      raise EElPublicKeyCryptoError.Create(SBufferTooSmall);
  end;

  FOutputIsStream := false;

  InternalEncrypt;

  if Length(FOutput) > OutSize then
    raise EElPublicKeyCryptoError.Create(SInternalError);

   OutSize  := Length(FOutput);
  SBMove(FOutput[0], OutBuffer^, OutSize);
end;
 {$endif SB_PGPSFX_STUB}

procedure TElPublicKeyCrypto.InternalDecrypt;
var
  Needed, I : integer;
begin
  SetLength(FOutput, 0);
  if FOutputEncoding = pkeBase64 then
    B64InitializeEncoding(FOutB64Ctx, 0, emNone);

  DecryptInit;
  try
    DecryptUpdate(@FInputSpool[0], Length(FInputSpool));
  finally
    DecryptFinal;
  end;

  if FOutputEncoding = pkeBase64 then
  begin
    Needed := 0;
    I := Length(FOutput);

    B64FinalizeEncoding(FOutB64Ctx, nil, Needed);

    SetLength(FOutput, I + Needed);

    B64FinalizeEncoding(FOutB64Ctx, @FOutput[I], Needed);
    
    if FOutputIsStream then
    begin
      FOutputStream.Write(FOutput[0], Length(FOutput));
      SetLength(FOutput, 0);
    end;
  end;
end;

procedure TElPublicKeyCrypto.Decrypt(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
  var OutSize: integer);
var
  Needed : integer;
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);

  if not SupportsEncryption then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.SecretKey) then
    raise EElPublicKeyCryptoError.Create(SSecretKeyNotFound);

  DecodeInput(InBuffer, InSize);

  Needed := EstimateOutputSize(@FInputSpool[0], Length(FInputSpool), pkoDecrypt);

  if FOutputEncoding = pkeBase64 then
    Needed := (Needed + 2) div 3 * 4;

  if (Needed > OutSize) then
  begin
    if OutSize = 0 then
    begin
       OutSize  := Needed;
      Exit;
    end
    else
      raise EElPublicKeyCryptoError.Create(SBufferTooSmall);
  end;

  FOutputIsStream := false;

  InternalDecrypt;

  if Length(FOutput) > OutSize then
    raise EElPublicKeyCryptoError.Create(SInternalError);
   OutSize  := Length(FOutput);
  SBMove(FOutput[0], OutBuffer^, OutSize);
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElPublicKeyCrypto.InternalSign;
var
  Needed, I : integer;
begin
  SetLength(FOutput, 0);
  if FOutputEncoding = pkeBase64 then
    B64InitializeEncoding(FOutB64Ctx, 0, emNone);

  SignInit(false);
  try
    SignUpdate(@FInputSpool[0], Length(FInputSpool));
  finally
    SignFinal;
  end;

  if FOutputEncoding = pkeBase64 then
  begin
    Needed := 0;
    I := Length(FOutput);

    B64FinalizeEncoding(FOutB64Ctx, nil, Needed);

    SetLength(FOutput, I + Needed);

    B64FinalizeEncoding(FOutB64Ctx, @FOutput[I], Needed);
    
    if FOutputIsStream then
    begin
      FOutputStream.Write(FOutput[0], Length(FOutput));
      SetLength(FOutput, 0);
    end;
  end;
end;

procedure TElPublicKeyCrypto.Sign(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
  var OutSize: integer);
var
  Needed : integer;
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);

  if not SupportsSigning then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.SecretKey) then
    raise EElPublicKeyCryptoError.Create(SSecretKeyNotFound);

  DecodeInput(InBuffer, InSize);

  Needed := EstimateOutputSize(@FInputSpool[0], Length(FInputSpool), pkoSign);

  if FOutputEncoding = pkeBase64 then
    Needed := (Needed + 2) div 3 * 4;

  if (Needed > OutSize) then
  begin
    if OutSize = 0 then
    begin
       OutSize  := Needed;
      Exit;
    end
    else
      raise EElPublicKeyCryptoError.Create(SBufferTooSmall);
  end;

  FOutputIsStream := false;

  InternalSign;

  if Length(FOutput) > OutSize then
    raise EElPublicKeyCryptoError.Create(SInternalError);
    
   OutSize  := Length(FOutput);
  SBMove(FOutput[0], OutBuffer^, OutSize);
end;

procedure TElPublicKeyCrypto.InternalSignDetached;
var
  Needed, I : integer;
begin
  SetLength(FOutput, 0);
  if FOutputEncoding = pkeBase64 then
    B64InitializeEncoding(FOutB64Ctx, 0, emNone);

  SignInit(true);
  try
    SignUpdate(@FInputSpool[0], Length(FInputSpool));
  finally
    SignFinal;
  end;

  if FOutputEncoding = pkeBase64 then
  begin
    Needed := 0;
    I := Length(FOutput);

    B64FinalizeEncoding(FOutB64Ctx, nil, Needed);

    SetLength(FOutput, I + Needed);

    B64FinalizeEncoding(FOutB64Ctx, @FOutput[I], Needed);
    
    if FOutputIsStream then
    begin
      FOutputStream.Write(FOutput[0], Length(FOutput));
      SetLength(FOutput, 0);
    end;
  end;
end;

procedure TElPublicKeyCrypto.SignDetached(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
  var OutSize: integer);
var
  Needed : integer;
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);

    
  if not SupportsSigning then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.SecretKey) then
    raise EElPublicKeyCryptoError.Create(SSecretKeyNotFound);

  if not FInputIsHash then
    DecodeInput(InBuffer, InSize)
  else
  begin
    SetLength(FInputSpool, InSize);
    SBMove(InBuffer^, FInputSpool[0], InSize);
  end;

  Needed := EstimateOutputSize(@FInputSpool[0], Length(FInputSpool), pkoSignDetached);
  if FOutputEncoding = pkeBase64 then
    Needed := (Needed + 2) div 3 * 4;

  if (Needed > OutSize) then
  begin
    if OutSize = 0 then
    begin
       OutSize  := Needed;
      Exit;
    end
    else
      raise EElPublicKeyCryptoError.Create(SBufferTooSmall);
  end;

  FOutputIsStream := false;

  InternalSignDetached;

  if Length(FOutput) > OutSize then
    raise EElPublicKeyCryptoError.Create(SInternalError);

   OutSize  := Length(FOutput);
  SBMove(FOutput[0], OutBuffer^, OutSize);
end;
 {$endif SB_PGPSFX_STUB}

function TElPublicKeyCrypto.InternalVerify : TSBPublicKeyVerificationResult;
var
  Needed, I : integer;
begin
  SetLength(FOutput, 0);
  if FOutputEncoding = pkeBase64 then
    B64InitializeEncoding(FOutB64Ctx, 0, emNone);

  try
    VerifyInit(false, nil, 0);
  except
    on E : EElCryptoProviderInvalidSignatureError do
    begin
      Result := pkvrInvalidSignature;
      Exit;
    end;
    on E : Exception do
      raise;
  end;

  try
    VerifyUpdate(@FInputSpool[0], Length(FInputSpool));
  finally
    Result := VerifyFinal;
  end;

  if FOutputEncoding = pkeBase64 then
  begin
    Needed := 0;
    I := Length(FOutput);

    B64FinalizeEncoding(FOutB64Ctx, nil, Needed);

    SetLength(FOutput, I + Needed);

    B64FinalizeEncoding(FOutB64Ctx, @FOutput[I], Needed);
    
    if FOutputIsStream then
    begin
      FOutputStream.Write(FOutput[0], Length(FOutput));
      SetLength(FOutput, 0);
    end;
  end;
end;

function TElPublicKeyCrypto.Verify(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
  var OutSize: integer): TSBPublicKeyVerificationResult;
var
  Needed : integer;
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);

  if not SupportsSigning then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.PublicKey) then
    raise EElPublicKeyCryptoError.Create(SPublicKeyNotFound);

  DecodeInput(InBuffer, InSize);

  Needed := EstimateOutputSize(@FInputSpool[0], Length(FInputSpool), pkoSignDetached);

  if FOutputEncoding = pkeBase64 then
    Needed := (Needed + 2) div 3 * 4;

  if (Needed > OutSize) then
  begin
    if OutSize = 0 then
    begin
      OutSize := Needed;
      Result := pkvrFailure;
      Exit;
    end
    else
      raise EElPublicKeyCryptoError.Create(SBufferTooSmall);
  end;

  FOutputIsStream := false;

  Result := InternalVerify;

  if Length(FOutput) > OutSize then
    raise EElPublicKeyCryptoError.Create(SInternalError);

  OutSize := Length(FOutput);
  SBMove(FOutput[0], OutBuffer^, OutSize);
end;

function TElPublicKeyCrypto.InternalVerifyDetached: TSBPublicKeyVerificationResult;
begin
  try
    VerifyUpdate(@FInputSpool[0], Length(FInputSpool));
  finally
    Result := VerifyFinal;
  end;
end;

function TElPublicKeyCrypto.VerifyDetached(InBuffer: pointer; InSize: integer;
  SigBuffer: pointer; SigSize: integer): TSBPublicKeyVerificationResult;
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);

  if not SupportsSigning then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.PublicKey) then
    raise EElPublicKeyCryptoError.Create(SPublicKeyNotFound);

  DecodeInput(SigBuffer, SigSize);

  try
    VerifyInit(true, @FInputSpool[0], Length(FInputSpool));
  except
    on E : EElCryptoProviderInvalidSignatureError do
    begin
      Result := pkvrInvalidSignature;
      Exit;
    end;
    on E : Exception do
      raise;
  end;

  if not FInputIsHash then
    DecodeInput(InBuffer, InSize)
  else
  begin
    SetLength(FInputSpool, InSize);
    SBMove(InBuffer^, FInputSpool[0], InSize);
  end;

  Result := InternalVerifyDetached;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElPublicKeyCrypto.InternalEncrypt(InStream : TElInputStream; OutStream : TElOutputStream;
  Count: integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
var
  Read : integer;
  Buf : ByteArray;
begin
  FOutputStream := OutStream;
  FOutputIsStream := true;

  if Count = 0 then
    Count := InStream. Size  - InStream.Position;

  SetLength(Buf, Count);
  Read := InStream.Read(Buf [0] , Count);

  DecodeInput(Buf, Read);
  ReleaseArray(Buf);
  
  InternalEncrypt;
end;
 {$endif SB_PGPSFX_STUB}

{$ifndef SB_PGPSFX_STUB}
procedure TElPublicKeyCrypto.Encrypt(InStream : TElInputStream; OutStream : TElOutputStream;
  Count: integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);

  if not SupportsEncryption then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.PublicKey) then
    raise EElPublicKeyCryptoError.Create(SPublicKeyNotFound);

  EstimateOutputSize(nil, Count, pkoEncrypt);

  InternalEncrypt(InStream, OutStream, Count);
end;
 {$endif SB_PGPSFX_STUB}

procedure TElPublicKeyCrypto.InternalDecrypt(InStream : TElInputStream; OutStream : TElOutputStream;
  Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
var
  Read : integer;
  Buf : ByteArray;
begin
  FOutputStream := OutStream;
  FOutputIsStream := true;

  if Count = 0 then
    Count := InStream. Size  - InStream.Position;

  SetLength(Buf, Count);
  Read := InStream.Read(Buf [0] , Count);
  
  DecodeInput(Buf, Read);
  ReleaseArray(Buf);

  InternalDecrypt;
end;

procedure TElPublicKeyCrypto.Decrypt(InStream : TElInputStream; OutStream : TElOutputStream;
  Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);

  if not SupportsEncryption then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.SecretKey) then
    raise EElPublicKeyCryptoError.Create(SSecretKeyNotFound);

  EstimateOutputSize(nil, Count, pkoDecrypt);

  InternalDecrypt(InStream, OutStream, Count);
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElPublicKeyCrypto.InternalSign(InStream : TElInputStream; OutStream : TElOutputStream;
  Count: integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
var
  Read, OutSize: integer;
  Buf: ByteArray;
begin
  if Count = 0 then
    Count := InStream. Size  - InStream.Position;

  EstimateOutputSize(nil, Count, pkoSign);

  FOutputStream := OutStream;
  FOutputIsStream := true;

  if (FInputEncoding = pkeBase64) then
    B64InitializeDecoding(FInB64Ctx);

  if FOutputEncoding = pkeBase64 then
    B64InitializeEncoding(FOutB64Ctx, 0, emNone);

  SignInit(false);
  SetLength(Buf, SB_PKC_BUFFER_SIZE);
  try
    while Count > 0 do
    begin
      Read := InStream.Read(Buf [0] , Min(Length(Buf), Count));
      if (FInputEncoding = pkeBase64) then
      begin
        OutSize := 0;
        B64Decode(FInB64Ctx,  @Buf[0], Read, nil, OutSize);
        SetLength(FInputSpool, OutSize);
        if not B64Decode(FInB64Ctx,  @Buf[0], Read, @FInputSpool[0], OutSize) then
          raise EElPublicKeyCryptoError.Create(SInvalidBase64Encoding);

        SignUpdate( @FInputSpool[0] , OutSize);
      end
      else
        SignUpdate( @Buf[0] , Read);

      Dec(Count, Read);
    end;

    if (FInputEncoding = pkeBase64) then
    begin
      OutSize := 0;
      B64FinalizeDecoding(FInB64Ctx,  nil, OutSize);
      SetLength(FInputSpool, OutSize);
      if not B64FinalizeDecoding(FInB64Ctx,  @FInputSpool[0], OutSize) then
        raise EElPublicKeyCryptoError.Create(SInvalidBase64Encoding);

      if OutSize > 0 then
        SignUpdate( @FInputSpool[0] , OutSize);
    end;
  finally
    SignFinal;

    ReleaseArray(Buf);

    if FOutputEncoding = pkeBase64 then
    begin
      OutSize := 0;

      B64FinalizeEncoding(FOutB64Ctx, nil, OutSize);

      SetLength(FOutput, OutSize);

      if OutSize > 0 then
      begin
        SetLength(FOutput, OutSize);

        B64FinalizeEncoding(FOutB64Ctx, @FOutput[0], OutSize);

        FOutputStream.Write(FOutput[0], OutSize);
      end;  
    end;
  end;
end;

procedure TElPublicKeyCrypto.Sign(InStream : TElInputStream; OutStream : TElOutputStream;
  Count: integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);

  if not SupportsSigning then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (FKeyMaterial = nil) or (not FKeyMaterial.SecretKey) then
    raise EElPublicKeyCryptoError.Create(SSecretKeyNotFound);

  InternalSign(InStream, OutStream, Count);
end;

procedure TElPublicKeyCrypto.InternalSignDetached(InStream : TElInputStream; OutStream : TElOutputStream;
  Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
var
  Read, OutSize: integer;
  Buf: ByteArray;
begin
  if Count = 0 then
    Count := InStream. Size  - InStream.Position;

  EstimateOutputSize(nil, Count,
    pkoSignDetached);

  FOutputStream := OutStream;
  FOutputIsStream := true;

  if (not FInputIsHash) and (FInputEncoding = pkeBase64) then
    B64InitializeDecoding(FInB64Ctx);

  SetLength(FOutput, 0);
  if FOutputEncoding = pkeBase64 then
    B64InitializeEncoding(FOutB64Ctx, 0, emNone);

  SignInit(true);
  SetLength(Buf, SB_PKC_BUFFER_SIZE);
  try
    while Count > 0 do
    begin
      Read := InStream.Read(Buf [0] , Min(Length(Buf), Count));
      if (not FInputIsHash) and (FInputEncoding = pkeBase64) then
      begin
        OutSize := 0;
        B64Decode(FInB64Ctx,  @Buf[0], Read, nil, OutSize);
        SetLength(FInputSpool, OutSize);
        if not B64Decode(FInB64Ctx,  @Buf[0], Read, @FInputSpool[0], OutSize) then
          raise EElPublicKeyCryptoError.Create(SInvalidBase64Encoding);

        SignUpdate( @FInputSpool[0] , OutSize);
      end
      else
        SignUpdate( @Buf[0] , Read);

      Dec(Count, Read);
    end;

    if (not FInputIsHash) and (FInputEncoding = pkeBase64) then
    begin
      OutSize := 0;
      B64FinalizeDecoding(FInB64Ctx,  nil, OutSize);
      SetLength(FInputSpool, OutSize);
      if not B64FinalizeDecoding(FInB64Ctx,  @FInputSpool[0], OutSize) then
        raise EElPublicKeyCryptoError.Create(SInvalidBase64Encoding);

      if OutSize > 0 then
        SignUpdate( @FInputSpool[0] , OutSize);
    end;
  finally
    SignFinal;

    ReleaseArray(Buf);

    if FOutputEncoding = pkeBase64 then
    begin
      OutSize := 0;

      B64FinalizeEncoding(FOutB64Ctx, nil, OutSize);

      if OutSize > 0 then
      begin
        SetLength(FOutput, OutSize);

        B64FinalizeEncoding(FOutB64Ctx, @FOutput[0], OutSize);

        FOutputStream.Write(FOutput[0], OutSize);
      end;  
    end;
  end;
end;

procedure TElPublicKeyCrypto.SignDetached(InStream : TElInputStream; OutStream : TElOutputStream;
  Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);

  if not SupportsSigning then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (FKeyMaterial = nil) or (not FKeyMaterial.SecretKey) then
    raise EElPublicKeyCryptoError.Create(SSecretKeyNotFound);

  InternalSignDetached(InStream, OutStream, Count);
end;
 {$endif SB_PGPSFX_STUB}

function TElPublicKeyCrypto.InternalVerify(InStream : TElInputStream; OutStream : TElOutputStream;
  Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}): TSBPublicKeyVerificationResult;
var
  Read, OutSize: integer;
  Buf: ByteArray;
begin
  if Count = 0 then
    Count := InStream. Size  - InStream.Position;

  FOutputStream := OutStream;
  FOutputIsStream := true;

  if FInputEncoding = pkeBase64 then
    B64InitializeDecoding(FInB64Ctx);

  if FOutputEncoding = pkeBase64 then
    B64InitializeEncoding(FOutB64Ctx, 0, emNone);

  VerifyInit(false, nil, 0);
  SetLength(Buf, SB_PKC_BUFFER_SIZE);
  try
    while Count > 0 do
    begin
      Read := InStream.Read(Buf [0] , Min(Length(Buf), Count));
      if FInputEncoding = pkeBase64 then
      begin
        OutSize := 0;
        B64Decode(FInB64Ctx,  @Buf[0], Read, nil, OutSize);
        SetLength(FInputSpool, OutSize);
        if not B64Decode(FInB64Ctx,  @Buf[0], Read, @FInputSpool[0], OutSize) then
          raise EElPublicKeyCryptoError.Create(SInvalidBase64Encoding);

        VerifyUpdate( @FInputSpool[0] , OutSize);
      end
      else
        VerifyUpdate( @Buf[0] , Read);

      Dec(Count, Read);
    end;

    if FInputEncoding = pkeBase64 then
    begin
      OutSize := 0;
      B64FinalizeDecoding(FInB64Ctx,  nil, OutSize);
      SetLength(FInputSpool, OutSize);
      if not B64FinalizeDecoding(FInB64Ctx,  @FInputSpool[0], OutSize) then
        raise EElPublicKeyCryptoError.Create(SInvalidBase64Encoding);

      if OutSize > 0 then
        VerifyUpdate( @FInputSpool[0] , OutSize);
    end;
  finally
    Result := VerifyFinal;

    ReleaseArray(Buf);

    if FOutputEncoding = pkeBase64 then
    begin
      OutSize := 0;

      B64FinalizeEncoding(FOutB64Ctx, nil, OutSize);

      if OutSize > 0 then
      begin
        SetLength(FOutput, OutSize);

        B64FinalizeEncoding(FOutB64Ctx, @FOutput[0], OutSize);

        FOutputStream.Write(FOutput[0], OutSize);
      end;  
    end;
  end;
end;

function TElPublicKeyCrypto.Verify(InStream : TElInputStream; OutStream : TElOutputStream;
  Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}): TSBPublicKeyVerificationResult;
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);

  if not SupportsSigning then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (FKeyMaterial = nil) or (not FKeyMaterial.PublicKey) then
    raise EElPublicKeyCryptoError.Create(SPublicKeyNotFound);

  Result := InternalVerify(InStream, OutStream, Count);
end;

function TElPublicKeyCrypto.InternalVerifyDetached(InStream : TElInputStream; SigStream : TElInputStream;
  InCount : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}; SigCount: integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}): TSBPublicKeyVerificationResult;
var
  Read, OutSize: integer;
  Buf: ByteArray;
  DecodePlaintext : boolean;
begin
  if InCount = 0 then
    InCount := InStream. Size  - InStream.Position;

  if SigCount = 0 then
    SigCount := SigStream. Size  - SigStream.Position;
    
  SetLength(Buf, SigCount);
  SigStream.Read(Buf [0] , SigCount);
  DecodeInput( @Buf[0] , SigCount);

  if (not FInputIsHash) and (FInputEncoding = pkeBase64) then
    B64InitializeDecoding(FInB64Ctx);

  VerifyInit(true,  @FInputSpool[0] ,
    Length(FInputSpool));

  DecodePlaintext := false; // II20140113: we should not decode InStream here, as it always contains unencoded to-be-signed data

  SetLength(Buf, SB_PKC_BUFFER_SIZE);
  try
    while InCount > 0 do
    begin
      Read := InStream.Read(Buf [0] , Min(Length(Buf), InCount));
      if DecodePlaintext then // (II20140113) (not FInputIsHash) and (FInputEncoding = {$ifdef CHROME}TSBPublicKeyCryptoEncoding.{$endif}pkeBase64) then
      begin
        OutSize := 0;
        B64Decode(FInB64Ctx,  @Buf[0], Read, nil, OutSize);
        SetLength(FInputSpool, OutSize);
        if not B64Decode(FInB64Ctx,  @Buf[0], Read, @FInputSpool[0], OutSize) then
          raise EElPublicKeyCryptoError.Create(SInvalidBase64Encoding);

        VerifyUpdate( @FInputSpool[0] , OutSize);
      end
      else
        VerifyUpdate( @Buf[0] , Read);

      Dec(InCount, Read);
    end;

    if DecodePlaintext then // (II20140113) (not FInputIsHash) and (FInputEncoding = {$ifdef CHROME}TSBPublicKeyCryptoEncoding.{$endif}pkeBase64) then
    begin
      OutSize := 0;
      B64FinalizeDecoding(FInB64Ctx,  nil, OutSize);
      SetLength(FInputSpool, OutSize);
      if not B64FinalizeDecoding(FInB64Ctx,  @FInputSpool[0], OutSize) then
        raise EElPublicKeyCryptoError.Create(SInvalidBase64Encoding);

      if OutSize > 0 then
        VerifyUpdate( @FInputSpool[0] , OutSize);
    end;
  finally
    Result := VerifyFinal;
    ReleaseArray(Buf);
  end;
end;

function TElPublicKeyCrypto.VerifyDetached(InStream : TElInputStream; SigStream : TElInputStream;
  InCount : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}; SigCount: integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}): TSBPublicKeyVerificationResult;
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);

  if not SupportsSigning then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (FKeyMaterial = nil) or (not FKeyMaterial.PublicKey) then
    raise EElPublicKeyCryptoError.Create(SPublicKeyNotFound);

  Result := InternalVerifyDetached(InStream, SigStream, InCount, SigCount);
end;

procedure TElPublicKeyCrypto.CancelAsyncOperation;
begin
  if FBusy and Assigned(FWorkingThread) then
  begin
    FWorkingThread.Terminate;
    while not FAsyncOperationFinished do
      Sleep(50);
  end;

  FBusy := false;
end;

procedure TElPublicKeyCrypto.BeginEncrypt(InBuffer: pointer; InSize: integer);
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);
  if not SupportsEncryption then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.PublicKey) then
    raise EElPublicKeyCryptoError.Create(SPublicKeyNotFound);

  DecodeInput(InBuffer, InSize);

  EstimateOutputSize(@FInputSpool[0], Length(FInputSpool), pkoEncrypt);

  FBusy := true;
  FOutputIsStream := false;
  FAsyncOperationFinished := false;
  FAsyncOperationSucceeded := false;
  FAsyncOperationError := '';
  FAsyncOperation := pkoEncrypt;

  FWorkingThread := TElPublicKeyCryptoWorkingThread.Create(Self);
  TElPublicKeyCryptoWorkingThread(FWorkingThread).StreamInput := false;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Operation := pkoEncrypt;
  FWorkingThread.FreeOnTerminate := true;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Resume;
end;

function TElPublicKeyCrypto.EndEncrypt(OutBuffer: pointer; var OutSize: integer) : boolean;
begin
  if not FBusy then
    raise EElPublicKeyCryptoError.Create(SNoAsyncOperationPending);
  if FOutputIsStream or (FAsyncOperation <> pkoEncrypt) then
    raise EElPublicKeyCryptoError.Create(SIncorrectFunctionCall);

  while not FAsyncOperationFinished do
    Sleep(50);

  Result := false;  
  if not FAsyncOperationSucceeded then
  begin
    FBusy := false;

    if Length(FAsyncOperationError) > 0 then
      raise EElPublicKeyCryptoAsyncError.Create(FAsyncOperationError)
    else
      raise EElPublicKeyCryptoAsyncError.Create(SAsyncOperationFailed);
  end
  else
  begin
    if OutSize < Length(FOutput) then
    begin
      if OutSize = 0 then
      begin
        OutSize := Length(FOutput);
        Exit;
      end
      else
        raise EElPublicKeyCryptoError.Create(SBufferTooSmall);
    end
    else
    begin
      SBMove(FOutput[0], OutBuffer^, Length(FOutput));
      OutSize := Length(FOutput);
      FBusy := false;
      Result := true;
    end;
  end;
end;

procedure TElPublicKeyCrypto.BeginDecrypt(InBuffer: pointer; InSize: integer);
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);
  if not SupportsEncryption then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.SecretKey) then
    raise EElPublicKeyCryptoError.Create(SSecretKeyNotFound);

  DecodeInput(InBuffer, InSize);

  EstimateOutputSize(@FInputSpool[0], Length(FInputSpool), pkoDecrypt);

  FBusy := true;
  FOutputIsStream := false;
  FAsyncOperationFinished := false;
  FAsyncOperationSucceeded := false;
  FAsyncOperationError := '';
  FAsyncOperation := pkoDecrypt;

  FWorkingThread := TElPublicKeyCryptoWorkingThread.Create(Self);
  TElPublicKeyCryptoWorkingThread(FWorkingThread).StreamInput := false;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Operation := pkoDecrypt;
  FWorkingThread.FreeOnTerminate := true;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Resume;
end;

function TElPublicKeyCrypto.EndDecrypt(OutBuffer: pointer; var OutSize: integer) : boolean;
begin
  if not FBusy then
    raise EElPublicKeyCryptoError.Create(SNoAsyncOperationPending);
  if FOutputIsStream or (FAsyncOperation <> pkoDecrypt) then
    raise EElPublicKeyCryptoError.Create(SIncorrectFunctionCall);

  while not FAsyncOperationFinished do
    Sleep(50);

  Result := false;  
  if not FAsyncOperationSucceeded then
  begin
    FBusy := false;

    if Length(FAsyncOperationError) > 0 then
      raise EElPublicKeyCryptoAsyncError.Create(FAsyncOperationError)
    else
      raise EElPublicKeyCryptoAsyncError.Create(SAsyncOperationFailed);
  end
  else
  begin
    if OutSize < Length(FOutput) then
    begin
      if OutSize = 0 then
      begin
        OutSize := Length(FOutput);
        Exit;
      end
      else
        raise EElPublicKeyCryptoError.Create(SBufferTooSmall);
    end
    else
    begin
      SBMove(FOutput[0], OutBuffer^, Length(FOutput));
      OutSize := Length(FOutput);
      FBusy := false;
      Result := true;
    end;
  end;
end;

procedure TElPublicKeyCrypto.BeginSign(InBuffer: pointer; InSize: integer);
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);
  if not SupportsSigning then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.SecretKey) then
    raise EElPublicKeyCryptoError.Create(SSecretKeyNotFound);

  DecodeInput(InBuffer, InSize);

  EstimateOutputSize(@FInputSpool[0], Length(FInputSpool), pkoSign);

  FBusy := true;
  FOutputIsStream := false;
  FAsyncOperationFinished := false;
  FAsyncOperationSucceeded := false;
  FAsyncOperationError := '';
  FAsyncOperation := pkoSign;

  FWorkingThread := TElPublicKeyCryptoWorkingThread.Create(Self);
  TElPublicKeyCryptoWorkingThread(FWorkingThread).StreamInput := false;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Operation := pkoSign;
  FWorkingThread.FreeOnTerminate := true;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Resume;
end;

function TElPublicKeyCrypto.EndSign(OutBuffer: pointer; var OutSize: integer) : boolean;
begin
  if not FBusy then
    raise EElPublicKeyCryptoError.Create(SNoAsyncOperationPending);
  if FOutputIsStream or (FAsyncOperation <> pkoSign) then
    raise EElPublicKeyCryptoError.Create(SIncorrectFunctionCall);

  while not FAsyncOperationFinished do
    Sleep(50);

  Result := false;  
  if not FAsyncOperationSucceeded then
  begin
    FBusy := false;

    if Length(FAsyncOperationError) > 0 then
      raise EElPublicKeyCryptoAsyncError.Create(FAsyncOperationError)
    else
      raise EElPublicKeyCryptoAsyncError.Create(SAsyncOperationFailed);
  end
  else
  begin
    if OutSize < Length(FOutput) then
    begin
      if OutSize = 0 then
      begin
        OutSize := Length(FOutput);
        Exit;
      end
      else
        raise EElPublicKeyCryptoError.Create(SBufferTooSmall);
    end
    else
    begin
      SBMove(FOutput[0], OutBuffer^, Length(FOutput));
      OutSize := Length(FOutput);
      FBusy := false;
      Result := true;
    end;
  end;
end;

procedure TElPublicKeyCrypto.BeginSignDetached(InBuffer: pointer; InSize: integer);
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);
  if not SupportsSigning then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.SecretKey) then
    raise EElPublicKeyCryptoError.Create(SSecretKeyNotFound);

  DecodeInput(InBuffer, InSize);

  EstimateOutputSize(@FInputSpool[0], Length(FInputSpool), pkoSignDetached);

  FBusy := true;
  FOutputIsStream := false;
  FAsyncOperationFinished := false;
  FAsyncOperationSucceeded := false;
  FAsyncOperationError := '';
  FAsyncOperation := pkoSignDetached;

  FWorkingThread := TElPublicKeyCryptoWorkingThread.Create(Self);
  TElPublicKeyCryptoWorkingThread(FWorkingThread).StreamInput := false;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Operation := pkoSignDetached;
  FWorkingThread.FreeOnTerminate := true;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Resume;
end;

function TElPublicKeyCrypto.EndSignDetached(OutBuffer: pointer; var OutSize: integer) : boolean;
begin
  if not FBusy then
    raise EElPublicKeyCryptoError.Create(SNoAsyncOperationPending);
  if FOutputIsStream or (FAsyncOperation <> pkoSignDetached) then
    raise EElPublicKeyCryptoError.Create(SIncorrectFunctionCall);

  while not FAsyncOperationFinished do
    Sleep(50);

  Result := false;  
  if not FAsyncOperationSucceeded then
  begin
    FBusy := false;

    if Length(FAsyncOperationError) > 0 then
      raise EElPublicKeyCryptoAsyncError.Create(FAsyncOperationError)
    else
      raise EElPublicKeyCryptoAsyncError.Create(SAsyncOperationFailed);
  end
  else
  begin
    if OutSize < Length(FOutput) then
    begin
      if OutSize = 0 then
      begin
        OutSize := Length(FOutput);
        Exit;
      end
      else
        raise EElPublicKeyCryptoError.Create(SBufferTooSmall);
    end
    else
    begin
      SBMove(FOutput[0], OutBuffer^, Length(FOutput));
      OutSize := Length(FOutput);
      FBusy := false;
      Result := true;
    end;
  end;
end;

procedure TElPublicKeyCrypto.BeginVerify(InBuffer: pointer; InSize: integer);
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);
  if not SupportsSigning then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.PublicKey) then
    raise EElPublicKeyCryptoError.Create(SPublicKeyNotFound);

  DecodeInput(InBuffer, InSize);

  EstimateOutputSize(@FInputSpool[0], Length(FInputSpool), pkoVerify);

  FBusy := true;
  FOutputIsStream := false;
  FAsyncOperationFinished := false;
  FAsyncOperationSucceeded := false;
  FAsyncOperationError := '';
  FAsyncOperation := pkoVerify;

  FWorkingThread := TElPublicKeyCryptoWorkingThread.Create(Self);
  TElPublicKeyCryptoWorkingThread(FWorkingThread).StreamInput := false;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Operation := pkoVerify;
  FWorkingThread.FreeOnTerminate := true;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Resume;
end;

function TElPublicKeyCrypto.EndVerify(OutBuffer: pointer; var OutSize: integer;
  var VerificationResult: TSBPublicKeyVerificationResult) : boolean;
begin
  if not FBusy then
    raise EElPublicKeyCryptoError.Create(SNoAsyncOperationPending);
  if FOutputIsStream or (FAsyncOperation <> pkoVerify)then
    raise EElPublicKeyCryptoError.Create(SIncorrectFunctionCall);

  while not FAsyncOperationFinished do
    Sleep(50);

  Result := false;
  if not FAsyncOperationSucceeded then
  begin
    FBusy := false;

    if Length(FAsyncOperationError) > 0 then
      raise EElPublicKeyCryptoAsyncError.Create(FAsyncOperationError)
    else
      raise EElPublicKeyCryptoAsyncError.Create(SAsyncOperationFailed);
  end
  else
  begin
    if OutSize < Length(FOutput) then
    begin
      if OutSize = 0 then
      begin
        OutSize := Length(FOutput);
        Exit;
      end
      else
        raise EElPublicKeyCryptoError.Create(SBufferTooSmall);
    end
    else
    begin
      SBMove(FOutput[0], OutBuffer^, Length(FOutput));
      OutSize := Length(FOutput);
      VerificationResult := FVerificationResult;
      FBusy := false;
      Result := true;
    end;
  end;
end;

procedure TElPublicKeyCrypto.BeginVerifyDetached(InBuffer: pointer; InSize: integer;
  SigBuffer: pointer; SigSize: integer);
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);
  if not SupportsSigning then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.PublicKey) then
    raise EElPublicKeyCryptoError.Create(SPublicKeyNotFound);

  DecodeInput(SigBuffer, SigSize);

  VerifyInit(true, @FInputSpool[0], Length(FInputSpool));

  if not FInputIsHash then
    DecodeInput(InBuffer, InSize)
  else
  begin
    SetLength(FInputSpool, InSize);
    SBMove(InBuffer^, FInputSpool[0], InSize);
  end;

  FBusy := true;
  FOutputIsStream := false;
  FAsyncOperationFinished := false;
  FAsyncOperationSucceeded := false;
  FAsyncOperationError := '';
  FAsyncOperation := pkoVerifyDetached;

  FWorkingThread := TElPublicKeyCryptoWorkingThread.Create(Self);
  TElPublicKeyCryptoWorkingThread(FWorkingThread).StreamInput := false;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Operation := pkoVerifyDetached;
  FWorkingThread.FreeOnTerminate := true;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Resume;
end;

procedure TElPublicKeyCrypto.BeginEncrypt(InStream : TElInputStream; OutStream : TElOutputStream;
  Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);
  if not SupportsEncryption then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.PublicKey) then
    raise EElPublicKeyCryptoError.Create(SPublicKeyNotFound);

  EstimateOutputSize(nil, Count, pkoEncrypt);

  FBusy := true;
  FOutputIsStream := true;
  FAsyncOperationFinished := false;
  FAsyncOperationSucceeded := false;
  FAsyncOperationError := '';
  FAsyncOperation := pkoEncrypt;

  FWorkingThread := TElPublicKeyCryptoWorkingThread.Create(Self);
  TElPublicKeyCryptoWorkingThread(FWorkingThread).StreamInput := true;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).InStream := InStream;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).OutStream := OutStream;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Count := Count;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Operation := pkoEncrypt;
  FWorkingThread.FreeOnTerminate := true;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Resume;
end;

procedure TElPublicKeyCrypto.EndEncrypt;
begin
  if not FBusy then
    raise EElPublicKeyCryptoError.Create(SNoAsyncOperationPending);
  if (not FOutputIsStream) or (FAsyncOperation <> pkoEncrypt) then
    raise EElPublicKeyCryptoError.Create(SIncorrectFunctionCall);

  while not FAsyncOperationFinished do
    Sleep(50);

  if not FAsyncOperationSucceeded then
  begin
    FBusy := false;

    if Length(FAsyncOperationError) > 0 then
      raise EElPublicKeyCryptoAsyncError.Create(FAsyncOperationError)
    else
      raise EElPublicKeyCryptoAsyncError.Create(SAsyncOperationFailed);
  end
end;

procedure TElPublicKeyCrypto.BeginDecrypt(InStream : TElInputStream; OutStream : TElOutputStream;
  Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);
  if not SupportsEncryption then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.SecretKey) then
    raise EElPublicKeyCryptoError.Create(SSecretKeyNotFound);

  EstimateOutputSize(nil, Count, pkoDecrypt);

  FBusy := true;
  FOutputIsStream := true;
  FAsyncOperationFinished := false;
  FAsyncOperationSucceeded := false;
  FAsyncOperationError := '';
  FAsyncOperation := pkoDecrypt;

  FWorkingThread := TElPublicKeyCryptoWorkingThread.Create(Self);
  TElPublicKeyCryptoWorkingThread(FWorkingThread).StreamInput := true;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).InStream := InStream;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).OutStream := OutStream;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Count := Count;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Operation := pkoDecrypt;
  FWorkingThread.FreeOnTerminate := true;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Resume;
end;

procedure TElPublicKeyCrypto.EndDecrypt;
begin
  if not FBusy then
    raise EElPublicKeyCryptoError.Create(SNoAsyncOperationPending);
  if (not FOutputIsStream) or (FAsyncOperation <> pkoDecrypt) then
    raise EElPublicKeyCryptoError.Create(SIncorrectFunctionCall);

  while not FAsyncOperationFinished do
    Sleep(50);

  if not FAsyncOperationSucceeded then
  begin
    FBusy := false;

    if Length(FAsyncOperationError) > 0 then
      raise EElPublicKeyCryptoAsyncError.Create(FAsyncOperationError)
    else
      raise EElPublicKeyCryptoAsyncError.Create(SAsyncOperationFailed);
  end
end;

procedure TElPublicKeyCrypto.BeginSign(InStream : TElInputStream; OutStream : TElOutputStream;
  Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);
  if not SupportsSigning then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.SecretKey) then
    raise EElPublicKeyCryptoError.Create(SSecretKeyNotFound);

  EstimateOutputSize(nil, Count, pkoSign);

  FBusy := true;
  FOutputIsStream := true;
  FAsyncOperationFinished := false;
  FAsyncOperationSucceeded := false;
  FAsyncOperationError := '';
  FAsyncOperation := pkoSign;

  FWorkingThread := TElPublicKeyCryptoWorkingThread.Create(Self);
  TElPublicKeyCryptoWorkingThread(FWorkingThread).StreamInput := true;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).InStream := InStream;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).OutStream := OutStream;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Count := Count;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Operation := pkoSign;
  FWorkingThread.FreeOnTerminate := true;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Resume;
end;

procedure TElPublicKeyCrypto.EndSign;
begin
  if not FBusy then
    raise EElPublicKeyCryptoError.Create(SNoAsyncOperationPending);
  if (not FOutputIsStream) or (FAsyncOperation <> pkoSign) then
    raise EElPublicKeyCryptoError.Create(SIncorrectFunctionCall);

  while not FAsyncOperationFinished do
    Sleep(50);

  if not FAsyncOperationSucceeded then
  begin
    FBusy := false;

    if Length(FAsyncOperationError) > 0 then
      raise EElPublicKeyCryptoAsyncError.Create(FAsyncOperationError)
    else
      raise EElPublicKeyCryptoAsyncError.Create(SAsyncOperationFailed);
  end
end;

procedure TElPublicKeyCrypto.BeginSignDetached(InStream : TElInputStream; OutStream : TElOutputStream;
  Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);
  if not SupportsSigning then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.SecretKey) then
    raise EElPublicKeyCryptoError.Create(SSecretKeyNotFound);

  EstimateOutputSize(nil, Count, pkoSignDetached);

  FBusy := true;
  FOutputIsStream := true;
  FAsyncOperationFinished := false;
  FAsyncOperationSucceeded := false;
  FAsyncOperationError := '';
  FAsyncOperation := pkoSignDetached;

  FWorkingThread := TElPublicKeyCryptoWorkingThread.Create(Self);
  TElPublicKeyCryptoWorkingThread(FWorkingThread).StreamInput := true;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).InStream := InStream;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).OutStream := OutStream;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Count := Count;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Operation := pkoSignDetached;
  FWorkingThread.FreeOnTerminate := true;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Resume;
end;

procedure TElPublicKeyCrypto.EndSignDetached;
begin
  if not FBusy then
    raise EElPublicKeyCryptoError.Create(SNoAsyncOperationPending);
  if (not FOutputIsStream) or (FAsyncOperation <> pkoSignDetached) then
    raise EElPublicKeyCryptoError.Create(SIncorrectFunctionCall);

  while not FAsyncOperationFinished do
    Sleep(50);

  if not FAsyncOperationSucceeded then
  begin
    FBusy := false;

    if Length(FAsyncOperationError) > 0 then
      raise EElPublicKeyCryptoAsyncError.Create(FAsyncOperationError)
    else
      raise EElPublicKeyCryptoAsyncError.Create(SAsyncOperationFailed);
  end
end;

procedure TElPublicKeyCrypto.BeginVerify(InStream : TElInputStream; OutStream : TElOutputStream;
  Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);
  if not SupportsSigning then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.PublicKey) then
    raise EElPublicKeyCryptoError.Create(SPublicKeyNotFound);

  EstimateOutputSize(nil, Count, pkoVerify);

  FBusy := true;
  FOutputIsStream := true;
  FAsyncOperationFinished := false;
  FAsyncOperationSucceeded := false;
  FAsyncOperationError := '';
  FAsyncOperation := pkoVerify;

  FWorkingThread := TElPublicKeyCryptoWorkingThread.Create(Self);
  TElPublicKeyCryptoWorkingThread(FWorkingThread).StreamInput := true;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).InStream := InStream;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).OutStream := OutStream;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Count := Count;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Operation := pkoVerify;
  FWorkingThread.FreeOnTerminate := true;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Resume;
end;

function TElPublicKeyCrypto.EndVerify : TSBPublicKeyVerificationResult;
begin
  if not FBusy then
    raise EElPublicKeyCryptoError.Create(SNoAsyncOperationPending);
  if (not FOutputIsStream) or (FAsyncOperation <> pkoVerify) then
    raise EElPublicKeyCryptoError.Create(SIncorrectFunctionCall);

  while not FAsyncOperationFinished do
    Sleep(50);

  if not FAsyncOperationSucceeded then
  begin
    FBusy := false;

    if Length(FAsyncOperationError) > 0 then
      raise EElPublicKeyCryptoAsyncError.Create(FAsyncOperationError)
    else
      raise EElPublicKeyCryptoAsyncError.Create(SAsyncOperationFailed);
  end
  else
    Result := FVerificationResult;
end;

procedure TElPublicKeyCrypto.BeginVerifyDetached(InStream : TElInputStream; SigStream : TElInputStream;
  InCount : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif};
  SigCount : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
begin
  if FBusy then
    raise EElPublicKeyCryptoError.Create(SAsyncOperationPending);
  if not SupportsSigning then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.PublicKey) then
    raise EElPublicKeyCryptoError.Create(SPublicKeyNotFound);

  FBusy := true;
  FOutputIsStream := true;
  FAsyncOperationFinished := false;
  FAsyncOperationSucceeded := false;
  FAsyncOperationError := '';
  FAsyncOperation := pkoVerifyDetached;

  FWorkingThread := TElPublicKeyCryptoWorkingThread.Create(Self);
  TElPublicKeyCryptoWorkingThread(FWorkingThread).StreamInput := true;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).InStream := InStream;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).SigStream := SigStream;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Count := InCount;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).SigCount := SigCount;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Operation := pkoVerifyDetached;
  FWorkingThread.FreeOnTerminate := true;
  TElPublicKeyCryptoWorkingThread(FWorkingThread).Resume;
end;

function TElPublicKeyCrypto.EndVerifyDetached : TSBPublicKeyVerificationResult;
begin
  if not FBusy then
    raise EElPublicKeyCryptoError.Create(SNoAsyncOperationPending);
  if (FAsyncOperation <> pkoVerifyDetached) then
    raise EElPublicKeyCryptoError.Create(SIncorrectFunctionCall);

  while not FAsyncOperationFinished do
    Sleep(50);

  if not FAsyncOperationSucceeded then
  begin
    FBusy := false;

    if Length(FAsyncOperationError) > 0 then
      raise EElPublicKeyCryptoAsyncError.Create(FAsyncOperationError)
    else
      raise EElPublicKeyCryptoAsyncError.Create(SAsyncOperationFailed);
  end
  else
  begin
    Result := FVerificationResult;
    FBusy := false;
  end;
end;

procedure TElPublicKeyCrypto.OnThreadTerminate(Sender : TObject);
begin
  FAsyncOperationSucceeded := TElPublicKeyCryptoWorkingThread(FWorkingThread).Success;
  FAsyncOperationError := TElPublicKeyCryptoWorkingThread(FWorkingThread).ErrorMessage;
  FVerificationResult := TElPublicKeyCryptoWorkingThread(FWorkingThread).VerificationResult;

  if Assigned(FOnAsyncOperationFinished) then
    FOnAsyncOperationFinished(Self, FAsyncOperationSucceeded);

  FAsyncOperationFinished := true;
  FWorkingThread := nil;
end;

class function TElPublicKeyCrypto.GetName() : string;
begin
  Result := 'Empty';
end;

class function TElPublicKeyCrypto.GetDescription() : string;
begin
  Result := 'Base class for public key encryption. Do not instantiate.';
end;

procedure TElPublicKeyCrypto.SetKeyMaterial(Material : TElPublicKeyMaterial);
begin
  if FBusy then Exit;

  FKeyMaterial := Material;
end;

procedure TElPublicKeyCrypto.SetInputIsHash(Value : boolean);
begin
  if FBusy then Exit;
  
  FInputIsHash := Value;
  if FContext <> nil then                                                       
    FContext.SetContextProp(SB_CTXPROP_INPUT_IS_HASH, GetBufferFromBool(Value));
end;

procedure TElPublicKeyCrypto.SetInputEncoding(Value : TSBPublicKeyCryptoEncoding);
begin
  if FBusy then Exit;

  FInputEncoding := Value;
end;

procedure TElPublicKeyCrypto.SetOutputEncoding(Value : TSBPublicKeyCryptoEncoding);
begin
  if FBusy then Exit;

  FOutputEncoding := Value;
end;

procedure TElPublicKeyCrypto.SetOnAsyncOperationFinished(Value : TSBAsyncOperationFinishedEvent);
begin
  if FBusy then Exit;

  FOnAsyncOperationFinished := Value;
end;

function TElPublicKeyCrypto.DecryptKey(EncKey : pointer; EncKeySize : integer;
  const EncKeyAlgOID, EncKeyAlgParams : ByteArray): TElKeyMaterial;
begin
  raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

procedure TElPublicKeyCrypto.AdjustContextProps(Params : TElCPParameters);
begin
  Params.Add(SB_CTXPROP_INPUT_IS_HASH, GetBufferFromBool(FInputIsHash));
end;

procedure TElPublicKeyCrypto.SaveContextProps;
begin
  ;
end;

function TElPublicKeyCrypto.GetHashAlgorithm: integer;
begin
  if FBusy then
  begin
    Result := SB_ALGORITHM_UNKNOWN;
    Exit;
  end;

  if Assigned(FContext) then
    Result := GetAlgorithmByOID(FContext.GetContextProp(SB_CTXPROP_HASH_ALGORITHM))
  else
    Result := FHashAlg;
end;

procedure TElPublicKeyCrypto.SetHashAlgorithm(Value : integer);
begin
  if FBusy then Exit;

  FHashAlg := Value;
  if Assigned(FContext) then
    FContext.SetContextProp(SB_CTXPROP_HASH_ALGORITHM, GetOIDByHashAlgorithm(Value));
end;

////////////////////////////////////////////////////////////////////////////////
// TElPublicKeyCryptoFactory class

constructor TElPublicKeyCryptoFactory.Create(CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited Create;
  FRegisteredClasses :=   TElList.Create;  
  RegisterDefaultClasses;
  FCryptoProvider := CryptoProvider;
end;

constructor TElPublicKeyCryptoFactory.Create(Manager: TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider); 
begin
  inherited Create;
  FRegisteredClasses :=   TElList.Create;  
  RegisterDefaultClasses;
  FCryptoProvider := CryptoProvider;
  FCryptoProviderManager := Manager;
end;

 destructor  TElPublicKeyCryptoFactory.Destroy;
begin
  FreeAndNil(FRegisteredClasses);
  inherited;
end;

procedure TElPublicKeyCryptoFactory.RegisterDefaultClasses;
begin
  RegisterClass(TElRSAPublicKeyCrypto);
  RegisterClass(TElDSAPublicKeyCrypto);
  {$ifndef SB_NO_DH}
  RegisterClass(TElDHPublicKeyCrypto);
   {$endif SB_NO_DH}
  RegisterClass(TElElgamalPublicKeyCrypto);
  {$ifdef SB_HAS_ECC}
  RegisterClass(TElECDSAPublicKeyCrypto);
   {$endif}
  {$ifdef SB_HAS_GOST}
  RegisterClass(TElGOST94PublicKeyCrypto);
  {$ifdef SB_HAS_ECC}
  RegisterClass(TElGOST2001PublicKeyCrypto);
   {$endif}
   {$endif}
end;

procedure TElPublicKeyCryptoFactory.RegisterClass(Cls : TElPublicKeyCryptoClass);
begin
  FRegisteredClasses.Add((Cls));
end;

function TElPublicKeyCryptoFactory.CreateInstance(const OID : ByteArray): TElPublicKeyCrypto;
var
  I : integer;
  Cls : TElPublicKeyCryptoClass;
begin
  Result := nil;
  for I := 0 to FRegisteredClasses.Count - 1 do
  begin
    Cls := TElPublicKeyCryptoClass(FRegisteredClasses[I]);
    if Cls.IsAlgorithmSupported(OID) then 
    begin
      // II20070806: Added OID parameter
      Result :=  Cls.Create (OID, FCryptoProviderManager, FCryptoProvider);
      Break;
    end;
  end;
end;

function TElPublicKeyCryptoFactory.CreateInstance(Alg : integer): TElPublicKeyCrypto;
var
  I : integer;
  Cls : TElPublicKeyCryptoClass;
begin
  Result := nil;
  for I := 0 to FRegisteredClasses.Count - 1 do
  begin
    Cls := TElPublicKeyCryptoClass(FRegisteredClasses[I]);
    if Cls.IsAlgorithmSupported(Alg) then
    begin
      Result :=  Cls.Create (Alg, FCryptoProviderManager, FCryptoProvider);
      Break;
    end;
  end;
end;

function TElPublicKeyCryptoFactory.IsAlgorithmSupported(const OID : ByteArray): boolean;
var
  I : integer;
begin
  Result := false;
  for I := 0 to FRegisteredClasses.Count - 1 do
  begin
    if TElPublicKeyCryptoClass(FRegisteredClasses[I]).IsAlgorithmSupported(OID) then
    begin
      Result := true;
      Break;
    end;
  end;
end;

function TElPublicKeyCryptoFactory.IsAlgorithmSupported(Alg : integer): boolean;
var
  I : integer;
begin
  Result := false;
  for I := 0 to FRegisteredClasses.Count - 1 do
  begin
    if TElPublicKeyCryptoClass(FRegisteredClasses[I]).IsAlgorithmSupported(Alg) then
    begin
      Result := true;
      Break;
    end;
  end;
end;

function TElPublicKeyCryptoFactory.GetRegisteredClass(Index: integer) : TElPublicKeyCryptoClass;
begin
  Result := TElPublicKeyCryptoClass(FRegisteredClasses[Index]);
end;

function TElPublicKeyCryptoFactory.GetRegisteredClassCount: integer;
begin
  Result := FRegisteredClasses.Count;
end;

function TElPublicKeyCryptoFactory.CreateKeyInstance(Buffer : pointer; Size : integer;
  const Password : string {$ifdef HAS_DEF_PARAMS}= '' {$endif}) : TElPublicKeyMaterial;
var
  Key : TElPublicKeyMaterial;
  //Res : integer;
begin
  Key := TElRSAKeyMaterial.Create;

  try
    TElRSAKeyMaterial(Key).Passphrase := Password;
    try
      Key.LoadSecret(Buffer, Size);
    except
      Key.LoadPublic(Buffer, Size);
    end;

    Result := Key;
    Exit;
  except
    FreeAndNil(Key);
  end;

  Key := TElDSAKeyMaterial.Create;

  try
    TElDSAKeyMaterial(Key).Passphrase := Password;
    try
      Key.LoadSecret(Buffer, Size);
    except
      Key.LoadPublic(Buffer, Size);
    end;

    Result := Key;
    Exit;
  except
    FreeAndNil(Key);
  end;

  Result := nil;
end;

function TElPublicKeyCryptoFactory.CreateKeyInstance(Stream : TElInputStream;
  const Password : string {$ifdef HAS_DEF_PARAMS} =  '' {$endif};
  Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}) : TElPublicKeyMaterial;
var
  Buf : ByteArray;
begin
  if Count = 0 then
    Count :=  Stream.Size  - Stream.Position;
  SetLength(Buf, Count);
  Count := Stream.Read(Buf [0] , Count);
  Result := CreateKeyInstance( @Buf[0] , Count);
  ReleaseArray(Buf);
end;

function TElPublicKeyCryptoFactory.CreateKeyInstance(Alg : integer): TElPublicKeyMaterial;
begin
  Alg := NormalizeAlgorithmConstant(Alg);
  case Alg of
    SB_ALGORITHM_PK_RSA : Result := TElRSAKeyMaterial.Create(FCryptoProviderManager, FCryptoProvider);
    SB_ALGORITHM_PK_DSA : Result := TElDSAKeyMaterial.Create(FCryptoProviderManager, FCryptoProvider);
    {$ifndef SB_PGPSFX_STUB}
    SB_ALGORITHM_PK_DH : Result := TElDHKeyMaterial.Create(FCryptoProviderManager, FCryptoProvider);
     {$endif SB_PGPSFX_STUB}
    SB_ALGORITHM_PK_ELGAMAL : Result := TElElGamalKeyMaterial.Create(FCryptoProviderManager, FCryptoProvider);
    {$ifdef SB_HAS_ECC}
    SB_ALGORITHM_PK_EC,
    SB_ALGORITHM_PK_ECDSA : Result := TElECKeyMaterial.Create(FCryptoProviderManager, FCryptoProvider);
     {$endif}
    {$ifdef SB_HAS_GOST}
    SB_ALGORITHM_PK_GOST_R3410_1994 : Result := TElGOST94KeyMaterial.Create(FCryptoProviderManager, FCryptoProvider);
    {$ifdef SB_HAS_ECC}
    SB_ALGORITHM_PK_GOST_R3410_2001 : Result := TElGOST2001KeyMaterial.Create(FCryptoProvider);
     {$endif}        
     {$endif}
  else
    Result := nil;
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// TElRSAKeyMaterial

constructor TElRSAKeyMaterial.Create(Prov : TElCustomCryptoProvider  = nil );
begin
  inherited;
  Reset;
  FKey := FProvider.CreateKey(SB_ALGORITHM_PK_RSA, 0, nil);
  FPassphrase := '';
  FKeyFormat := rsaPKCS1;
  FStoreFormat := ksfRaw;
end;

constructor TElRSAKeyMaterial.Create(Manager: TElCustomCryptoProviderManager; Prov : TElCustomCryptoProvider);
begin
  inherited;
  Reset;
  FKey := FProvider.CreateKey(SB_ALGORITHM_PK_RSA, 0, nil);
  FPassphrase := '';
  FKeyFormat := rsaPKCS1;
  FStoreFormat := ksfRaw;
end;


 destructor  TElRSAKeyMaterial.Destroy;
begin
  inherited;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElRSAKeyMaterial.InternalGenerate(Bits : integer);
var
  ProgressFunc : TSBProgressFunc;
begin
  if Assigned(FWorkingThread) then
    ProgressFunc := TElPublicKeyMaterialWorkingThread(FWorkingThread).ProgressHandler
  else
    ProgressFunc := nil;

  FKey.Generate(Bits, nil, ProgressFunc);
end;
 {$endif SB_PGPSFX_STUB}

{$ifndef SB_PGPSFX_STUB}
procedure TElRSAKeyMaterial.LoadFromXML(const Str: string);
var
  v: TXMLParamValues;
  OutBuf: ByteArray;
  OutSize: Integer;
  OutSize2 : TSBInteger; 
begin
  Clear;
  v := ParseXmlString(Str, 'RSAKeyValue', ['Modulus', 'Exponent', 'D', 'P', 'Q', 'DP', 'DQ', 'InverseQ']);
  if (Length(v) <> 8) or (Length(v[0]) = 0) or (Length(v[1]) = 0) then
    raise EElPublicKeyCryptoError.Create(SInvalidXML);

  OutSize := 0;
  OutSize2 := 0;
  
  if (Length(v[5]) > 0) or (Length(v[6]) > 0) or (Length(v[7]) > 0) then
  begin
    SBRSA.EncodePrivateKey(@v[0][0], Length(v[0]), @v[1][0], Length(v[1]), @v[2][0], Length(v[2]),
      @v[3][0], Length(v[3]), @v[4][0], Length(v[4]), @v[5][0], Length(v[5]), @v[6][0], Length(v[6]),
      @v[7][0], Length(v[7]), nil, OutSize);
    SetLength(OutBuf, OutSize);
    if not SBRSA.EncodePrivateKey(@v[0][0], Length(v[0]), @v[1][0], Length(v[1]), @v[2][0], Length(v[2]),
       @v[3][0], Length(v[3]), @v[4][0], Length(v[4]), @v[5][0], Length(v[5]), @v[6][0], Length(v[6]),
       @v[7][0], Length(v[7]), @OutBuf[0], OutSize) then
      raise EElPublicKeyCryptoError.Create(SInvalidSecretKey);

    FKey.ImportSecret( @OutBuf[0] , OutSize, nil);
  end
  else if (Length(v[3]) > 0) or (Length(v[4]) > 0) then
  begin
    EncodePrivateKey(@v[0][0], Length(v[0]), @v[1][0], Length(v[1]), @v[2][0], Length(v[2]),
      @v[3][0], Length(v[3]), @v[4][0], Length(v[4]), nil, OutSize2);
    SetLength(OutBuf, OutSize2);
    if not EncodePrivateKey(@v[0][0], Length(v[0]), @v[1][0], Length(v[1]), @v[2][0], Length(v[2]),
       @v[3][0], Length(v[3]), @v[4][0], Length(v[4]), @OutBuf[0], OutSize2) then
      raise EElPublicKeyCryptoError.Create(SInvalidSecretKey);

    FKey.ImportSecret( @OutBuf[0] , OutSize2, nil);
  end
  else if Length(v[2]) > 0 then
  begin
    SBRSA.EncodePrivateKey(@v[0][0], Length(v[0]), @v[1][0], Length(v[1]), @v[2][0], Length(v[2]), nil, OutSize);
    SetLength(OutBuf, OutSize);
    if not SBRSA.EncodePrivateKey(@v[0][0], Length(v[0]), @v[1][0], Length(v[1]), @v[2][0], Length(v[2]), @OutBuf[0], OutSize) then
      raise EElPublicKeyCryptoError.Create(SInvalidSecretKey);

    FKey.ImportSecret( @OutBuf[0] , OutSize, nil);
  end
  else
  begin
    SBRSA.EncodePublicKey(@v[0][0], Length(v[0]), @v[1][0], Length(v[1]), SB_OID_RSAENCRYPTION, nil, OutSize);
    SetLength(OutBuf, OutSize);
    if not SBRSA.EncodePublicKey(@v[0][0], Length(v[0]), @v[1][0], Length(v[1]), SB_OID_RSAENCRYPTION, @OutBuf[0], OutSize) then
      raise EElPublicKeyCryptoError.Create(SInvalidPublicKey);

    FKey.ImportPublic( @OutBuf[0] , OutSize, nil);
  end;
  ReleaseArray(OutBuf);
end;
 {$endif SB_PGPSFX_STUB}

procedure TElRSAKeyMaterial.LoadPublic(Buffer: pointer; Size: integer);
var
  PlainKey :  pointer ;
  PlainSize : integer;
  Header : string;
  R : integer;
  Decoded : ByteArray;
begin
  Reset;
  // checking if the key is PEM-enveloped
  if IsPEM(Buffer, Size) then
  begin
    PlainSize := 0;
    SBPEM.Decode(Buffer, Size, nil, FPassphrase, PlainSize, Header);
    SetLength(Decoded, PlainSize);
    R := SBPEM.Decode(Buffer, Size, @Decoded[0], FPassphrase, PlainSize, Header);
    PlainKey := @Decoded[0];
    if R <> 0 then
      raise EElPublicKeyCryptoError.Create(SInvalidPEM);
  end
  else
  begin
    PlainKey := Buffer;
    PlainSize := Size;
  end;
  FKey.ImportPublic(PlainKey, PlainSize, nil);
end;

procedure TElRSAKeyMaterial.LoadPublic(Modulus : pointer; ModulusSize : integer;
  Exponent : pointer; ExponentSize : integer);
var
  BlobSize : integer;
  Blob : ByteArray;
begin
  BlobSize := 0;
  SBRSA.EncodePublicKey(Modulus, ModulusSize, Exponent, ExponentSize,
    SB_OID_RSAENCRYPTION, nil, BlobSize);
  SetLength(Blob, BlobSize);
  SBRSA.EncodePublicKey(Modulus, ModulusSize, Exponent, ExponentSize,
    SB_OID_RSAENCRYPTION, @Blob[0], BlobSize);
  LoadPublic(@Blob[0], BlobSize);
end;

procedure TElRSAKeyMaterial.LoadSecret(Buffer: pointer; Size: integer);
var
  PlainKey : ByteArray;
  PlainSize : integer;
  Header : string;
  R : integer;
  {$ifndef SB_PGPSFX_STUB}
  KeyPKCS8 : TElPKCS8PrivateKey;
   {$endif}
  HashAlg, MGFAlg, MGFHashAlg, SSize, Trailer : TSBInteger;
  SLabel : TSBString;
begin
  Reset;


  FKeyFormat := rsaPKCS1;
  FStoreFormat := ksfRaw;
  // checking if the key is PEM-enveloped
  if IsPEM(Buffer, Size) then
  begin
    PlainSize := 0;
    SBPEM.Decode(Buffer, Size, nil, FPassphrase, PlainSize, Header);
    SetLength(PlainKey, PlainSize);
    R := SBPEM.Decode(Buffer, Size, @PlainKey[0], FPassphrase, PlainSize, Header);
    if R <> 0 then
    begin
      case R of
        PEM_DECODE_RESULT_INVALID_PASSPHRASE :
          raise EElPublicKeyCryptoError.Create(SInvalidPassphrase);
        else
          raise EElPublicKeyCryptoError.Create(SInvalidPEM);
      end;
    end
  end
  else
  begin
    SetLength(PlainKey, Size);
    SBMove(Buffer^, PlainKey[0], Size);
    PlainSize := Size;
  end;

  { trying PKCS#8 }
  {$ifndef SB_PGPSFX_STUB}
  KeyPKCS8 := TElPKCS8PrivateKey.Create;

  try
    R := KeyPKCS8.LoadFromBuffer(@PlainKey[0], PlainSize, FPassphrase);

    if R = SB_PKCS8_ERROR_OK then
    begin
      R := GetPKAlgorithmByOID(KeyPKCS8.KeyAlgorithm);

      if not ((R = SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION) or
        (R = SB_CERT_ALGORITHM_ID_RSAPSS) or (R = SB_CERT_ALGORITHM_ID_RSAOAEP))
      then
        raise EElPublicKeyCryptoError.Create(SUnsupportedAlgorithm);

      PlainSize := Length(KeyPKCS8.KeyMaterial);
      SetLength(PlainKey, PlainSize);
      SBMove(KeyPKCS8.KeyMaterial[0], PlainKey[0], PlainSize);
      FKey.ImportSecret(PlainKey, PlainSize);

      if R = SB_CERT_ALGORITHM_ID_RSAPSS then
      begin
        ReadPSSParams(@KeyPKCS8.KeyAlgorithmParams[0],
          Length(KeyPKCS8.KeyAlgorithmParams),
          HashAlg, SSize, MGFAlg, MGFHashAlg, Trailer);
        Self.SaltSize := SSize;
        Self.HashAlgorithm := HashAlg;
        FKeyFormat := rsaPSS;
      end
      else if R = SB_CERT_ALGORITHM_ID_RSAOAEP then
      begin
        ReadOAEPParams(@KeyPKCS8.KeyAlgorithmParams[0],
          Length(KeyPKCS8.KeyAlgorithmParams),
          HashAlg, MGFHashAlg, SLabel);
        Self.StrLabel := SLabel;
        Self.HashAlgorithm := HashAlg;
        FKeyFormat := rsaOAEP;
      end;

      FStoreFormat := ksfPKCS8;
      Exit;
    end
    else if R = SB_PKCS8_ERROR_INVALID_PASSWORD then
      raise EElPublicKeyCryptoError.Create(SInvalidPassphrase);
  finally
    FreeAndNil(KeyPKCS8);
  end;
   {$endif SB_PGPSFX_STUB}

  // trying to load a key as plain RSA key
  FKey.ImportSecret(PlainKey, PlainSize);
end;

procedure TElRSAKeyMaterial.SavePublic(Buffer: pointer; var Size: integer);
var
  OutSize : TSBInteger;
  PublicKeyBlob : ByteArray;
begin
  OutSize := 0;
  FKey.ExportPublic( nil , OutSize, nil);
  SetLength(PublicKeyBlob, OutSize);
  FKey.ExportPublic( @PublicKeyBlob[0] , OutSize);
  SetLength(PublicKeyBlob, OutSize);
  {$ifndef SB_PGPSFX_STUB}
  if PEMEncode then
  begin
    OutSize := 0;
    SBPEM.Encode(@PublicKeyBlob[0], Length(PublicKeyBlob), nil, OutSize,
      'PUBLIC KEY', false, '');
    if OutSize <= Size then
    begin
      if not SBPEM.Encode(@PublicKeyBlob[0], Length(PublicKeyBlob), Buffer, Size,
        'PUBLIC KEY', false, '') then
        raise EElPublicKeyCryptoError.Create(SPEMWriteError);
    end
    else if Size = 0 then
      Size := OutSize
    else
      raise EElPublicKeyCryptoError.Create(SBufferTooSmall);
  end
  else
   {$endif}
  begin
    if Size = 0 then
      Size := Length(PublicKeyBlob)
    else if Size < Length(PublicKeyBlob) then
      raise EElPublicKeyCryptoError.Create(SBufferTooSmall)
    else
    begin
      Size := Length(PublicKeyBlob);
      SBMove(PublicKeyBlob[0], Buffer^, Size);
    end;
  end;
end;

procedure TElRSAKeyMaterial.SaveSecret(Buffer: pointer; var Size: integer);
var
  OutSize : TSBInteger;
  Encrypt : boolean;
  KeyBlob : ByteArray;
  {$ifndef SB_PGPSFX_STUB}
  PKCS8Key : TElPKCS8PrivateKey;
   {$endif}
begin
  OutSize := 0;
  FKey.ExportSecret( nil , OutSize, nil);
  SetLength(KeyBlob, OutSize);
  FKey.ExportSecret( @KeyBlob[0] , OutSize, nil);
  SetLength(KeyBlob, OutSize);

  {$ifndef SB_PGPSFX_STUB}
  if FStoreFormat = ksfPKCS8 then
  begin
    PKCS8Key := TElPKCS8PrivateKey.Create;
    PKCS8Key.UseNewFeatures := true;
    PKCS8Key.SymmetricAlgorithm := SB_ALGORITHM_CNT_3DES;

    PKCS8Key.KeyMaterial := KeyBlob;
    
    if FKeyFormat = rsaOAEP then
    begin
      PKCS8Key.KeyAlgorithm := SB_OID_RSAOAEP;
      PKCS8Key.KeyAlgorithmParams := WriteOAEPParams(HashAlgorithm, HashAlgorithm, StrLabel);
    end
    else if FKeyFormat = rsaPSS then
    begin
      PKCS8Key.KeyAlgorithm := SB_OID_RSAPSS;
      PKCS8Key.KeyAlgorithmParams := WritePSSParams(HashAlgorithm, SaltSize, SB_CERT_MGF1, 1);
    end
    else
    begin
      PKCS8Key.KeyAlgorithm := SB_OID_RSAENCRYPTION;
      PKCS8Key.KeyAlgorithmParams := WriteNULL;
    end;

    OutSize := 0;
    PKCS8Key.SaveToBuffer(nil, OutSize, FPassphrase, false);
    SetLength(KeyBlob, OutSize);
    PKCS8Key.SaveToBuffer(@KeyBlob[0], OutSize, FPassphrase, false);
    SetLength(KeyBlob, OutSize);
  end;
   {$endif SB_PGPSFX_STUB}

  {$ifndef SB_PGPSFX_STUB}
  if PEMEncode then
  begin
    OutSize := 0;
    Encrypt := Length(FPassphrase) > 0;

    SBPEM.Encode(@KeyBlob[0], Length(KeyBlob), nil, OutSize,
      'RSA PRIVATE KEY', Encrypt, FPassphrase);

    if OutSize <= Size then
    begin
      if not SBPEM.Encode(@KeyBlob[0], Length(KeyBlob), Buffer, Size,
        'RSA PRIVATE KEY', Encrypt, FPassphrase) then
        raise EElPublicKeyCryptoError.Create(SPEMWriteError);
    end
    else if Size = 0 then
      Size := OutSize
    else
      raise EElPublicKeyCryptoError.Create(SBufferTooSmall);
  end
  else
   {$endif}
  begin
    if Size = 0 then
      Size := Length(KeyBlob)
    else if Size < Length(KeyBlob) then
      raise EElPublicKeyCryptoError.Create(SBufferTooSmall)
    else
    begin
      Size := Length(KeyBlob);
      SBMove(KeyBlob[0], Buffer^, Size);
    end
  end;
end;

{$ifndef SB_PGPSFX_STUB}
function TElRSAKeyMaterial.SaveToXML(IncludePrivateKey: Boolean  =  False): string;
var
  KeyBlob, M, E, D, P, Q, DP, DQ, InverseQ: ByteArray;
  OutSize, MSize, ESize, DSize, PSize, QSize, DPSize, DQSize, InverseQSize: Integer;
begin


  Result := '';
  if IncludePrivateKey and SecretKey then
  begin
    OutSize := 0;
    FKey.ExportSecret( nil , OutSize, nil);
    SetLength(KeyBlob, OutSize);
    FKey.ExportSecret( @KeyBlob[0] , OutSize, nil);
    SetLength(KeyBlob, OutSize);

    if OutSize <= 0 then
      raise EElPublicKeyCryptoError.Create(SInvalidSecretKey);

    MSize := 0;
    ESize := 0;
    DSize := 0;
    PSize := 0;
    QSize := 0;
    DPSize := 0;
    DQSize := 0;
    InverseQSize := 0;
    SBRSA.DecodePrivateKey(@KeyBlob[0], OutSize, nil, MSize, nil, ESize, nil, DSize,
      nil, PSize, nil, QSize, nil, DPSize, nil, DQSize, nil, InverseQSize);
    SetLength(M, MSize);
    SetLength(E, ESize);
    SetLength(D, DSize);
    SetLength(P, PSize);
    SetLength(Q, QSize);
    SetLength(DP, DPSize);
    SetLength(DQ, DQSize);
    SetLength(InverseQ, InverseQSize);
    if SBRSA.DecodePrivateKey(@KeyBlob[0], OutSize, @M[0], MSize, @E[0], ESize, @D[0], DSize,
      @P[0], PSize, @Q[0], QSize, @DP[0], DPSize, @DQ[0], DQSize, @InverseQ[0], InverseQSize) then
    begin
      SetLength(M, MSize);
      SetLength(E, ESize);
      SetLength(D, DSize);
      SetLength(P, PSize);
      SetLength(Q, QSize);
      SetLength(DP, DPSize);
      SetLength(DQ, DQSize);
      SetLength(InverseQ, InverseQSize);
      Result := Format('<RSAKeyValue><Modulus>%s</Modulus><Exponent>%s</Exponent><D>%s</D><P>%s</P><Q>%s</Q><DP>%s</DP><DQ>%s</DQ><InverseQ>%s</InverseQ></RSAKeyValue>',
         [(ConvertToBase64String(M)),
          (ConvertToBase64String(E)),
          (ConvertToBase64String(D)),
          (ConvertToBase64String(P)),
          (ConvertToBase64String(Q)),
          (ConvertToBase64String(DP)),
          (ConvertToBase64String(DQ)),
          (ConvertToBase64String(InverseQ))]);
    end
    else
    begin
      Result := Format('<RSAKeyValue><Modulus>%s</Modulus><Exponent>%s</Exponent><D>%s</D></RSAKeyValue>',
         [(ConvertToBase64String(PublicModulus)),
          (ConvertToBase64String(PublicExponent)),
          (ConvertToBase64String(PrivateExponent))]);
    end;
  end
  else if PublicKey then
  begin
    Result := Format('<RSAKeyValue><Modulus>%s</Modulus><Exponent>%s</Exponent></RSAKeyValue>',
       [(ConvertToBase64String(PublicModulus)),
        (ConvertToBase64String(PublicExponent))]);
  end;


end;
 {$endif SB_PGPSFX_STUB}

procedure TElRSAKeyMaterial.LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  if AlgorithmIdentifier is TElRSAAlgorithmIdentifier then
  begin
    KeyFormat := rsaPKCS1;
  end
  else if AlgorithmIdentifier is TElRSAPSSAlgorithmIdentifier then
  begin
    KeyFormat := rsaPSS;
    HashAlgorithm := TElRSAPSSAlgorithmIdentifier(AlgorithmIdentifier).HashAlgorithm;
    MGFAlgorithm := TElRSAPSSAlgorithmIdentifier(AlgorithmIdentifier).MGF;
    SaltSize := TElRSAPSSAlgorithmIdentifier(AlgorithmIdentifier).SaltSize;
    TrailerField := TElRSAPSSAlgorithmIdentifier(AlgorithmIdentifier).TrailerField;
  end
  else if AlgorithmIdentifier is TElRSAOAEPAlgorithmIdentifier then
  begin
    KeyFormat := rsaOAEP;
    HashAlgorithm := TElRSAOAEPAlgorithmIdentifier(AlgorithmIdentifier).HashAlgorithm;
    MGFAlgorithm := TElRSAOAEPAlgorithmIdentifier(AlgorithmIdentifier).MGF;
    StrLabel := TElRSAOAEPAlgorithmIdentifier(AlgorithmIdentifier).StrLabel;
  end
  else
    raise EElPublicKeyCryptoError.Create(SInvalidKeyParameters);
end;

procedure TElRSAKeyMaterial.SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  if AlgorithmIdentifier is TElRSAAlgorithmIdentifier then
  begin
  end
  else if AlgorithmIdentifier is TElRSAPSSAlgorithmIdentifier then
  begin
    TElRSAPSSAlgorithmIdentifier(AlgorithmIdentifier).HashAlgorithm := HashAlgorithm;
    TElRSAPSSAlgorithmIdentifier(AlgorithmIdentifier).MGF := MGFAlgorithm;
    TElRSAPSSAlgorithmIdentifier(AlgorithmIdentifier).MGFHashAlgorithm := HashAlgorithm;
    TElRSAPSSAlgorithmIdentifier(AlgorithmIdentifier).SaltSize := SaltSize;
    TElRSAPSSAlgorithmIdentifier(AlgorithmIdentifier).TrailerField := TrailerField;
  end
  else if AlgorithmIdentifier is TElRSAOAEPAlgorithmIdentifier then
  begin
    TElRSAOAEPAlgorithmIdentifier(AlgorithmIdentifier).HashAlgorithm := HashAlgorithm;
    TElRSAOAEPAlgorithmIdentifier(AlgorithmIdentifier).MGF := MGFAlgorithm;
    TElRSAOAEPAlgorithmIdentifier(AlgorithmIdentifier).MGFHashAlgorithm := HashAlgorithm;
    TElRSAOAEPAlgorithmIdentifier(AlgorithmIdentifier).StrLabel := StrLabel;
  end
  else
    raise EElPublicKeyCryptoError.Create(SInvalidKeyParameters);
end;

function TElRSAKeyMaterial.GetValid : boolean;
begin
  Result := FKey.IsValid;
end;

procedure TElRSAKeyMaterial.SetPassphrase(const Value : string);
begin
  if FBusy then Exit;
  
  FPassphrase := Value;
end;

procedure TElRSAKeyMaterial.SetPEMEncode(Value : boolean);
begin
  if FBusy then Exit;

  FPEMEncode := Value;
end;

procedure TElRSAKeyMaterial.SetStrLabel(const Value : string);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_STRLABEL, BytesOfString(Value));
end;

procedure TElRSAKeyMaterial.SetSaltSize(Value : integer);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_SALT_SIZE, GetBufferFromInteger(Value));
end;

procedure TElRSAKeyMaterial.SetHashAlgorithm(Value : integer);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_HASH_ALGORITHM, GetOIDByHashAlgorithm(Value));
end;

procedure TElRSAKeyMaterial.SetMGFAlgorithm(Value : integer);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_MGF_ALGORITHM, GetOIDByAlgorithm(Value));
end;

procedure TElRSAKeyMaterial.SetTrailerField(Value : integer);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_TRAILER_FIELD, GetBufferFromInteger(Value));
end;

procedure TElRSAKeyMaterial.SetRawPublicKey(Value : boolean);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_RSA_RAWKEY, GetBufferFromBool(Value)); 
end;

function TElRSAKeyMaterial.GetStrLabel: string;
begin
  Result := StringOfBytes(FKey.GetKeyProp(SB_KEYPROP_STRLABEL));
end;

function TElRSAKeyMaterial.GetSaltSize : integer;
begin
  Result := GetIntegerPropFromBuffer(FKey.GetKeyProp(SB_KEYPROP_SALT_SIZE));
end;

function TElRSAKeyMaterial.GetHashAlgorithm : integer;
begin
  Result := GetHashAlgorithmByOID(FKey.GetKeyProp(SB_KEYPROP_HASH_ALGORITHM));
end;

function TElRSAKeyMaterial.GetMGFAlgorithm : integer;
begin
  Result := GetAlgorithmByOID(FKey.GetKeyProp(SB_KEYPROP_MGF_ALGORITHM));
end;

function TElRSAKeyMaterial.GetTrailerField : integer;
begin
  Result := GetIntegerPropFromBuffer(FKey.GetKeyProp(SB_KEYPROP_TRAILER_FIELD));
end;

function TElRSAKeyMaterial.GetRawPublicKey : boolean;
begin
  Result := GetBoolFromBuffer(FKey.GetKeyProp(SB_KEYPROP_RSA_RAWKEY));
end;

function TElRSAKeyMaterial.GetM : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_RSA_M);
end;

function TElRSAKeyMaterial.GetE : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_RSA_E);
end;

function TElRSAKeyMaterial.GetD : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_RSA_D);
end;

procedure TElRSAKeyMaterial.Reset;
begin
  FPEMEncode := false;
  FKeyFormat := rsaPKCS1;
  FStoreFormat := ksfRaw;
end;

function TElRSAKeyMaterial.GetBits : integer;
begin
  Result := FKey.Bits;
end;

procedure TElRSAKeyMaterial.Assign(Source: TElKeyMaterial);
var
  t: TElRSAKeyMaterial;
begin
  if not (Source is TElRSAKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SInvalidKeyMaterialType);

  t := TElRSAKeyMaterial(Source);

  FPassphrase := t.FPassphrase;
  FPEMEncode := TElRSAKeyMaterial(Source).FPEMEncode;
  FKeyFormat := TElRSAKeyMaterial(Source).FKeyFormat;
  FStoreFormat := TElRSAKeyMaterial(Source).FStoreFormat;
  FProvider.ReleaseKey(FKey);    

  FKey := TElRSAKeyMaterial(Source).FKey.CryptoProvider.CloneKey(TElRSAKeyMaterial(Source).FKey);
  //FKey := TElRSAKeyMaterial(Source).FKey.Clone(nil);
  FProvider := TElRSAKeyMaterial(Source).FProvider;
  FProviderManager := TElRSAKeyMaterial(Source).FProviderManager;
end;

function TElRSAKeyMaterial.Clone :  TElKeyMaterial ;
var
  Res : TElKeyMaterial;
begin
  Res := TElRSAKeyMaterial.Create(FProvider);
  Res.Assign(Self);
  Result := Res;
end;

function TElRSAKeyMaterial.Equals(Source : TElKeyMaterial; PublicOnly : boolean): boolean;
var
  B, B1: ByteArray;
begin
  SetLength(B, 0);
  SetLength(B1, 0);
  Result := false;
  if not (Source is TElRSAKeyMaterial) then exit;
  if (Self.Key.IsPublic <> Source.Key.IsPublic) then exit;
  if (Self.Key.IsSecret and Source.Key.IsSecret) and (not PublicOnly) then
  begin
      Result := Self.Key.Equals(Source.Key, false, nil);
      exit;
  end;

  Result := true;
  Result := Result and
    (Self.GetMGFAlgorithm = TElRSAKeyMaterial(Source).GetMGFAlgorithm) and
    (Self.KeyFormat = TElRSAKeyMaterial(Source).KeyFormat);
  B := TElRSAKeyMaterial(Source).GetM;
  B1 := Self.GetM;
  Result := Result and (Length(B) = Length(B1)) and
       (CompareMem(@B1[0], @B[0], Length(B1)))
       ;
  B := TElRSAKeyMaterial(Source).GetE;
  B1 := Self.GetE;
  Result := Result and (Length(B) = Length(B1)) and
       (CompareMem(@B1[0], @B[0], Length(B1)))
       ;
  ReleaseArrays(B, B1);
end;

procedure TElRSAKeyMaterial.ClearSecret;
begin
  FKey.ClearSecret;
end;

procedure TElRSAKeyMaterial.ClearPublic;
begin
  FKey.ClearPublic;
end;

function TElRSAKeyMaterial.EncodePublicKey(PublicModulus : pointer; PublicModulusSize : integer;
  PublicExponent : pointer; PublicExponentSize : integer; const AlgID: ByteArray;
  OutBuffer : pointer; var OutSize : integer; InnerValuesOnly : boolean = false) : boolean;
begin
  Result := SBRSA.EncodePublicKey(PublicModulus, PublicModulusSize, PublicExponent, PublicExponentSize,
    AlgID, OutBuffer, OutSize, InnerValuesOnly);
end;

function TElRSAKeyMaterial.EncodePrivateKey(PublicModulus : pointer; PublicModulusSize : integer;
  PublicExponent : pointer; PublicExponentSize : integer; PrivateExponent :
  pointer; PrivateExponentSize : integer; OutBuffer : pointer; var OutSize : integer) : boolean;
begin
  Result := SBRSA.EncodePrivateKey(PublicModulus, PublicModulusSize, PublicExponent, PublicExponentSize,
    PrivateExponent, PrivateExponentSize, OutBuffer, OutSize);
end;

function TElRSAKeyMaterial.EncodePrivateKey(N : pointer; NSize : integer;
  E : pointer; ESize : integer; D : pointer; DSize : integer; P : pointer;
  PSize : integer; Q : pointer; QSize : integer; OutBuffer : pointer; var OutSize : integer) : boolean;
var
  LD, LP, LQ, LDP, LDQ, LU, LTmp : PLInt;
  TDP, TDQ, TU, TD : ByteArray;
  TDPSize, TDQSize, TUSize, TDSize : integer;
begin
  LCreate(LD);
  LCreate(LP);
  LCreate(LQ);
  LCreate(LDP);
  LCreate(LDQ);
  LCreate(LU);
  LCreate(LTmp);

  try
    PointerToLInt(LP, P, PSize);
    PointerToLInt(LQ, Q, QSize);

    if DSize = 0 then
    begin
      { Calculating D }
      LCopy(LDP, LP);
      LCopy(LDQ, LQ);
      LDec(LDP);
      LDec(LDQ);
      LMult(LDP, LDQ, LTmp); // LTmp = (Q - 1) * (P - 1)
      PointerToLInt(LDP, E, ESize);
      LGCD(LDP, LTmp, LDQ, LD);
    end
    else
    begin
      PointerToLInt(LD, D, DSize);
    end;

    LGCD(LQ, LP, LTmp, LU); // U = CRT COEFFICIENT OF Q MOD P
    LDec(LP);
    LDec(LQ);
    LModEx(LD, LP, LDP); // DP = D mod (P - 1)
    LModEx(LD, LQ, LDQ); // DQ = D mod (Q - 1)

    TDPSize := LDP.Length * 4;
    TDQSize := LDQ.Length * 4;
    TUSize := LU.Length * 4;
    TDSize := LD.Length * 4;
    SetLength(TDP, TDPSize);
    SetLength(TDQ, TDQSize);
    SetLength(TU, TUSize);
    SetLength(TD, TDSize);

    LIntToPointer(LDP, @TDP[0], TDPSize);
    LIntToPointer(LDQ, @TDQ[0], TDQSize);
    LIntToPointer(LU, @TU[0], TUSize);
    LIntToPointer(LD, @TD[0], TDSize);

    Result := Self.EncodePrivateKey(N, NSize, E, ESize, @TD[0], TDSize, P, PSize,
      Q, QSize, @TDP[0], TDPSize, @TDQ[0], TDQSize, @TU[0], TUSize, OutBuffer, OutSize);
  finally
    LDestroy(LD);
    LDestroy(LP);
    LDestroy(LQ);
    LDestroy(LDP);
    LDestroy(LDQ);
    LDestroy(LU);
    LDestroy(LTmp);
  end;
end;

function TElRSAKeyMaterial.EncodePrivateKey(N : pointer; NSize : integer;
  E : pointer; ESize : integer; D : pointer; DSize : integer; P : pointer;
  PSize : integer; Q : pointer; QSize : integer; DP : pointer;
  DPSize : integer; DQ : pointer; DQSize : integer; QInv : pointer;
  QInvSize : integer; OutBuffer : pointer; var OutSize : integer) : boolean;
begin
  Result := SBRSA.EncodePrivateKey(N, NSize, E, ESize, D, DSize, P, PSize, Q, QSize,
    DP, DPSize, DQ, DQSize, QInv, QInvSize, OutBuffer, OutSize);
end;

function TElRSAKeyMaterial.DecodePrivateKey(Blob : pointer; BlobSize : integer;
  N : pointer; var NSize : integer; E : pointer; var ESize : integer;
  D : pointer; var DSize : integer; P : pointer; var PSize : integer;
  Q : pointer; var QSize : integer; DP : pointer; var DPSize : integer;
  DQ : pointer; var DQSize : integer; QInv : pointer; var QInvSize : integer) : boolean;
begin
  Result := SBRSA.DecodePrivateKey(Blob, BlobSize, N, NSize, E, ESize, D, DSize, P, PSize,
    Q, QSize, DP, DPSize, DQ, DQSize, QInv, QInvSize);
end;


class function TElRSAKeyMaterial.WritePSSParams(HashAlgorithm : integer ;
  SaltSize : integer; MGFAlgorithm : integer; TrailerField : integer) : ByteArray;
var
  Tag : TElASN1SimpleTag;
  cTag, aTag : TElASN1ConstrainedTag;
  Size : integer;
begin
  Result := EmptyArray;

  if MGFAlgorithm <> SB_CERT_MGF1 then Exit;

  cTag := TElASN1ConstrainedTag.CreateInstance;
  try
    cTag.TagId := SB_ASN1_SEQUENCE;

    { hash algorithm }

    if HashAlgorithm <> SB_ALGORITHM_DGST_SHA1 then
    begin
      aTag := TElASN1ConstrainedTag(cTag.GetField(cTag.AddField(True)));
      aTag.TagId := SB_ASN1_A0;
      aTag := TElASN1ConstrainedTag(aTag.GetField(aTag.AddField(true)));

      aTag.TagId := SB_ASN1_SEQUENCE;

      Tag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(false)));
      Tag.TagId := SB_ASN1_OBJECT;
      Tag.Content := GetOIDByHashAlgorithm(HashAlgorithm);
      Tag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(false)));
      Tag.TagId := SB_ASN1_NULL;
    end;

    { MGF }

    if (HashAlgorithm <> SB_ALGORITHM_DGST_SHA1) then
    begin
      aTag := TElASN1ConstrainedTag(cTag.GetField(cTag.AddField(True)));
      aTag.TagId := SB_ASN1_A1;
      aTag := TElASN1ConstrainedTag(aTag.GetField(aTag.AddField(true)));

      aTag.TagId := SB_ASN1_SEQUENCE;
      Tag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(False)));
      Tag.TagId := SB_ASN1_OBJECT;
      Tag.Content := SB_OID_MGF1;
      aTag := TElASN1ConstrainedTag(aTag.GetField(aTag.AddField(True)));
      aTag.TagId := SB_ASN1_SEQUENCE;
      Tag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(false)));
      Tag.TagId := SB_ASN1_OBJECT;
      Tag.Content := GetOIDByHashAlgorithm(HashAlgorithm);
      Tag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(false)));
      Tag.TagId := SB_ASN1_NULL;
    end;

    { SaltSize }

    aTag := TElASN1ConstrainedTag(cTag.GetField(cTag.AddField(true)));
    aTag.TagId := SB_ASN1_A2;
    Tag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(False)));
    Tag.TagId := SB_ASN1_INTEGER;
    ASN1WriteInteger(Tag, SaltSize);

    { TrailerField}

    if TrailerField <> 1 then
    begin
      aTag := TElASN1ConstrainedTag(cTag.GetField(cTag.AddField(true)));
      aTag.TagId := SB_ASN1_A3;
      Tag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(False)));
      Tag.TagId := SB_ASN1_INTEGER;
      ASN1WriteInteger(Tag, TrailerField);
    end;

    Size := 0;
    cTag.SaveToBuffer(nil, Size);

    SetLength(Result, Size);
    if not cTag.SaveToBuffer(@Result[0], Size) then
      Result := EmptyArray
    else
      SetLength(Result, Size);

  finally
    FreeAndNil(cTag);
  end;               end;


class function TElRSAKeyMaterial.ReadPSSParams(InBuffer :  pointer;  InBufferSize : integer;
  var HashAlgorithm, SaltSize, MGF, MGFHashAlgorithm, TrailerField : TSBInteger) : boolean;
var
  CTag, STag, ATag : TElASN1ConstrainedTag;
  Index,TagNum : integer;
begin
  Result := false;
  HashAlgorithm := SB_ALGORITHM_DGST_SHA1;
  SaltSize := 20;
  MGF := SB_CERT_MGF1;
  MGFHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
  TrailerField := 1;

  CTag := TElASN1ConstrainedTag.CreateInstance;
  try
    CTag.LoadFromBuffer(InBuffer, InBufferSize);
    if (CTag.Count <> 1) then Exit;

    if CTag.GetField(0).CheckType(SB_ASN1_NULL, false) then
    begin
      Result := true;
      Exit;
    end;

    if not CTag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true) then Exit;
    STag := TElASN1ConstrainedTag(CTag.GetField(0));
    if STag.Count > 3 then Exit;

    Index := 0;
    TagNum := 0;

    while (Index < 4) and (TagNum < STag.Count) do
    begin
      ATag := TElASN1ConstrainedTag(STag.GetField(TagNum));
      Inc(TagNum);

      if (not ATag.IsConstrained) or (ATag.Count <> 1) then Exit;

      if (ATag.TagId = SB_ASN1_A0) then
      begin
        if Index > 0 then Exit;
        { hash algorithm }

        if not ATag.GetField(0).IsConstrained then Exit;
        ATag := TElASN1ConstrainedTag(ATag.GetField(0));

        if (ATag.Count > 2) or (ATag.Count < 1) then Exit;
        if (not ATag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) then Exit;
        if (ATag.Count > 1) and (not ATag.GetField(1).CheckType(SB_ASN1_NULL, false)) then
          Exit;

        HashAlgorithm := GetHashAlgorithmByOID(TElASN1SimpleTag(ATag.GetField(0)).Content);

        Index := 1;
      end
      else if (ATag.TagId = SB_ASN1_A1) then
      begin
        if Index > 1 then Exit;
        { MGF }
        if not ATag.GetField(0).IsConstrained then Exit;
        ATag := TElASN1ConstrainedTag(ATag.GetField(0));
        if (ATag.Count <> 2) or
          (not ATag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) or
          (not ATag.GetField(1).CheckType(SB_ASN1_SEQUENCE, true))
        then
          Exit;

        if not CompareContent(TElASN1SimpleTag(ATag.GetField(0)).Content, SB_OID_MGF1)
        then
          Exit;

        ATag := TElASN1ConstrainedTag(ATag.GetField(1));

        if (ATag.Count > 2) or (ATag.Count < 1) then Exit;
        if (not ATag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) then Exit;
        if (ATag.Count > 1) and (not ATag.GetField(1).CheckType(SB_ASN1_NULL, false)) then
          Exit;

        MGFHashAlgorithm := GetHashAlgorithmByOID(TElASN1SimpleTag(ATag.GetField(0)).Content);

        Index := 2;
      end
      else if ATag.TagId = SB_ASN1_A2 then
      begin
        if Index > 2 then Exit;
        { Salt size }
        if not ATag.GetField(0).CheckType(SB_ASN1_INTEGER, false) then Exit;

        SaltSize := ASN1ReadInteger(TElASN1SimpleTag(ATag.GetField(0)));

        Index := 3;
      end
      else if ATag.TagId = SB_ASN1_A3 then
      begin
        if Index > 3 then Exit;
        { trailer }
        if not ATag.GetField(0).CheckType(SB_ASN1_INTEGER, false) then Exit;

        TrailerField := ASN1ReadInteger(TElASN1SimpleTag(ATag.GetField(0)));

        if TrailerField <> 1 then Exit; //only this type currently declared.

        Index := 4;
      end
      else
        Exit;
    end;

    Result := true;
  finally
    FreeAndNil(CTag);
  end;
end;

class function TElRSAKeyMaterial.WriteOAEPParams(HashAlgorithm, MGFHashAlgorithm : integer;
  const StrLabel : string) : ByteArray;
var
  Tag : TElASN1SimpleTag;
  cTag, aTag : TElASN1ConstrainedTag;
  Size : integer;
begin
  Result := EmptyArray;

  cTag := TElASN1ConstrainedTag.CreateInstance;
  try
    cTag.TagId := SB_ASN1_SEQUENCE;

    { hash algorithm }

    if HashAlgorithm <> SB_ALGORITHM_DGST_SHA1 then
    begin
      aTag := TElASN1ConstrainedTag(cTag.GetField(cTag.AddField(True)));
      aTag.TagId := SB_ASN1_A0;
      aTag := TElASN1ConstrainedTag(aTag.GetField(aTag.AddField(true)));

      aTag.TagId := SB_ASN1_SEQUENCE;

      Tag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(false)));
      Tag.TagId := SB_ASN1_OBJECT;
      Tag.Content := GetOIDByHashAlgorithm(HashAlgorithm);
      Tag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(false)));
      Tag.TagId := SB_ASN1_NULL;
    end;

    { MGF }

    if (HashAlgorithm <> SB_ALGORITHM_DGST_SHA1) then
    begin
      aTag := TElASN1ConstrainedTag(cTag.GetField(cTag.AddField(True)));
      aTag.TagId := SB_ASN1_A1;
      aTag := TElASN1ConstrainedTag(aTag.GetField(aTag.AddField(true)));

      aTag.TagId := SB_ASN1_SEQUENCE;
      Tag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(False)));
      Tag.TagId := SB_ASN1_OBJECT;
      Tag.Content := SB_OID_MGF1;
      aTag := TElASN1ConstrainedTag(aTag.GetField(aTag.AddField(True)));
      aTag.TagId := SB_ASN1_SEQUENCE;
      Tag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(false)));
      Tag.TagId := SB_ASN1_OBJECT;
      Tag.Content := GetOIDByHashAlgorithm(HashAlgorithm);
      Tag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(false)));
      Tag.TagId := SB_ASN1_NULL;
    end;

    { label source }

    if StrLabel <> '' then
    begin
      aTag := TElASN1ConstrainedTag(cTag.GetField(cTag.AddField(True)));
      aTag.TagId := SB_ASN1_A2;
      aTag := TElASN1ConstrainedTag(aTag.GetField(aTag.AddField(true)));

      aTag.TagId := SB_ASN1_SEQUENCE;
      Tag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(False)));
      Tag.TagId := SB_ASN1_OBJECT;
      Tag.Content := SB_OID_OAEP_SRC_SPECIFIED;
      Tag := TElASN1SimpleTag(aTag.GetField(aTag.AddField(False)));
      Tag.TagId := SB_ASN1_OCTETSTRING;
      Tag.Content := BytesOfString(StrLabel);
    end;

    Size := 0;

    if cTag.Count = 0 then
      Result := WriteNULL
    else
    begin
      cTag.SaveToBuffer(nil, Size);

      SetLength(Result, Size);
      if not cTag.SaveToBuffer(@Result[0], Size) then
        Result := EmptyArray
      else
        SetLength(Result, Size);
    end;
  finally
    FreeAndNil(cTag);
  end;
end;

class function TElRSAKeyMaterial.ReadOAEPParams(InBuffer :  pointer;  InBufferSize : integer;
  var HashAlgorithm, MGFHashAlgorithm : TSBInteger; var StrLabel : TSBString) : boolean;
var
  ATag, CTag, STag : TElASN1ConstrainedTag;
  //Tag : TElASN1SimpleTag;
  Index, TagNum : integer;
begin
  HashAlgorithm := SB_ALGORITHM_DGST_SHA1;
  MGFHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
  StrLabel := '';
  Result := false;
  CTag := TElASN1ConstrainedTag.CreateInstance;

  try
    if not CTag.LoadFromBuffer(InBuffer, InBufferSize) then
      Exit;

    if CTag.Count <> 1 then Exit;

    if CTag.GetField(0).CheckType(SB_ASN1_NULL, false) then
    begin
      Result := true;
      Exit;
    end;

    if not CTag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true) then Exit;
    STag := TElASN1ConstrainedTag(CTag.GetField(0));
    if STag.Count > 3 then Exit;

    Index := 0;
    TagNum := 0;

    while (Index < 3) and (TagNum < STag.Count) do
    begin
      ATag := TElASN1ConstrainedTag(STag.GetField(TagNum));
      Inc(TagNum);

      if (not ATag.IsConstrained) or (ATag.Count <> 1) then Exit;

      if (ATag.TagId = SB_ASN1_A0) then
      begin
        if Index > 0 then Exit;
        { hash algorithm }

        if not ATag.GetField(0).IsConstrained then Exit;
        ATag := TElASN1ConstrainedTag(ATag.GetField(0));
        if (ATag.Count > 2) or (ATag.Count < 1) then Exit;
        if (not ATag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) then Exit;
        if (ATag.Count > 1) and (not ATag.GetField(1).CheckType(SB_ASN1_NULL, false)) then
          Exit;

        HashAlgorithm := GetHashAlgorithmByOID(TElASN1SimpleTag(ATag.GetField(0)).Content);

        Index := 1;
      end
      else if (ATag.TagId = SB_ASN1_A1) then
      begin
        if Index > 1 then Exit;
        { MGF }
        if not ATag.GetField(0).IsConstrained then Exit;
        ATag := TElASN1ConstrainedTag(ATag.GetField(0));
        if (ATag.Count <> 2) or
          (not ATag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) or
          (not ATag.GetField(1).CheckType(SB_ASN1_SEQUENCE, true))
        then
          Exit;

        if not CompareContent(TElASN1SimpleTag(ATag.GetField(0)).Content, SB_OID_MGF1)
        then
          Exit;

        ATag := TElASN1ConstrainedTag(ATag.GetField(1));

        if (ATag.Count > 2) or (ATag.Count < 1) then Exit;
        if (not ATag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) then Exit;
        if (ATag.Count > 1) and (not ATag.GetField(1).CheckType(SB_ASN1_NULL, false)) then
          Exit;

        MGFHashAlgorithm := GetHashAlgorithmByOID(TElASN1SimpleTag(ATag.GetField(0)).Content);

        Index := 2;
      end
      else if ATag.TagId = SB_ASN1_A2 then
      begin
        if Index > 2 then Exit;
        { label source algorithm }

        if not ATag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true) then Exit;
        ATag := TElASN1ConstrainedTag(ATag.GetField(0));
        if (ATag.Count <> 2) or
          (not ATag.GetField(0).CheckType(SB_ASN1_OBJECT, false))
        then
          Exit;

        if not CompareContent(TElASN1SimpleTag(ATag.GetField(0)).Content, SB_OID_OAEP_SRC_SPECIFIED)
        then
          Exit;

        if not ATag.GetField(1).CheckType(SB_ASN1_OCTETSTRING, false) then Exit;
        StrLabel := StringOfBytes(TElASN1SimpleTag(ATag.GetField(1)).Content);

        Index := 3;
      end
      else
        Exit;
    end;

    Result := true;
  finally
    FreeAndNil(CTag);
  end;
end;


////////////////////////////////////////////////////////////////////////////////
// TElRSAPublicKeyCrypto class

constructor TElRSAPublicKeyCrypto.Create(const OID : ByteArray; CryptoProvider : TElCustomCryptoProvider);
begin
   Create (OID, nil, CryptoProvider);
  (*
  inherited Create(CryptoProvider);

  Reset;
  FHashFuncOID := EmptyArray;
  FOID := OID;
  FSaltSize := 0;
  FMGFAlgorithm := 0;
  FTrailerField := 0;

  if CompareContent(OID, SB_OID_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA1_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_MD2_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_MD5_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA1_RSA) or
    CompareContent(OID, SB_OID_SHA224_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA256_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA384_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA512_RSAENCRYPTION) then
  begin
    FSupportsSigning := true;
    FSupportsEncryption := true;
    FCryptoType := {$ifdef SB_NET}TSBRSAPublicKeyCryptoType.{$endif}rsapktPKCS1;
  end
  else
  if CompareContent(OID, SB_OID_RSAPSS) then
  begin
    FSupportsSigning := true;
    FSupportsEncryption := false;
    FCryptoType := {$ifdef SB_NET}TSBRSAPublicKeyCryptoType.{$endif}rsapktPSS;
  end
  else
  if CompareContent(OID, SB_OID_RSAOAEP) then
  begin
    FSupportsSigning := false;
    FSupportsEncryption := true;
    FCryptoType := {$ifdef SB_NET}TSBRSAPublicKeyCryptoType.{$endif}rsapktOAEP;
  end
  else
  {$ifdef SB_VCL}
    raise EElPublicKeyCryptoError.CreateFmt(SUnsupportedAlgorithm, [OIDToStr(OID)]);
  {$else}
    raise EElPublicKeyCryptoError.Create(System.String.Format(SUnsupportedAlgorithm, [OIDToStr(OID)]));
  {$endif}
  FHashAlg := GetHashAlgorithmBySigAlgorithm(GetAlgorithmByOID(OID));
  *)
end;

constructor TElRSAPublicKeyCrypto.Create(Alg : integer; CryptoProvider : TElCustomCryptoProvider);
begin
   Create (Alg, nil, CryptoProvider);
  (*
  inherited Create(CryptoProvider);

  Reset;
  FHashFuncOID := EmptyArray;
  FOID := EmptyArray;
  if Alg in [SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_MD2_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_MD5_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA1_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA224_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA256_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA384_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA512_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_RSASIGNATURE_RIPEMD160] then
  begin
    FSupportsSigning := true;
    FSupportsEncryption := true;
    FOID := GetOIDByPKAlgorithm(Alg);
    if Length(FOID) = 0 then
      FOID := GetOIDBySigAlgorithm(Alg);
    FCryptoType := {$ifdef SB_NET}TSBRSAPublicKeyCryptoType.{$endif}rsapktPKCS1;  
  end
  else if Alg = SB_CERT_ALGORITHM_ID_RSAPSS then
  begin
    FSupportsSigning := true;
    FSupportsEncryption := false;
    FOID := SB_OID_RSAPSS;
    FCryptoType := {$ifdef SB_NET}TSBRSAPublicKeyCryptoType.{$endif}rsapktPSS;
  end
  else if Alg = SB_CERT_ALGORITHM_ID_RSAOAEP then
  begin
    FSupportsSigning := false;
    FSupportsEncryption := true;
    FOID := SB_OID_RSAOAEP;
    FCryptoType := {$ifdef SB_NET}TSBRSAPublicKeyCryptoType.{$endif}rsapktOAEP;
  end;

  if CompareContent(FOID, EmptyArray) then
  {$ifdef SB_VCL}
    raise EElPublicKeyCryptoError.CreateFmt(SUnsupportedAlgorithmInt, [Alg]);
  {$else}
    raise EElPublicKeyCryptoError.Create(System.String.Format(SUnsupportedAlgorithmInt, [Alg]));
  {$endif}
  FHashAlg := GetHashAlgorithmBySigAlgorithm(Alg);
  *)
end;


constructor TElRSAPublicKeyCrypto.Create(CryptoProvider : TElCustomCryptoProvider  = nil );
begin
  Create(SB_OID_RSAENCRYPTION, CryptoProvider);
  FHashFuncOID := EmptyArray;
end;


constructor TElRSAPublicKeyCrypto.Create(const OID : ByteArray; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create(Manager, CryptoProvider);
  Reset;
  FHashFuncOID := EmptyArray;
  FOID := OID;
  FSaltSize := 0;
  FMGFAlgorithm := 0;
  FTrailerField := 0;

  if CompareContent(OID, SB_OID_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA1_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA1_RSAENCRYPTION2) or
    CompareContent(OID, SB_OID_MD2_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_MD5_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA1_RSA) or
    CompareContent(OID, SB_OID_SHA224_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA256_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA384_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA512_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_RSASIGNATURE_RIPEMD160_ISO9796) then
  begin
    FSupportsSigning := true;
    FSupportsEncryption := true;
    FCryptoType := rsapktPKCS1;
  end
  else
  if CompareContent(OID, SB_OID_RSAPSS) then
  begin
    FSupportsSigning := true;
    FSupportsEncryption := false;
    FCryptoType := rsapktPSS;
  end
  else
  if CompareContent(OID, SB_OID_RSAOAEP) then
  begin
    FSupportsSigning := false;
    FSupportsEncryption := true;
    FCryptoType := rsapktOAEP;
  end
  else
    raise EElPublicKeyCryptoError.CreateFmt(SUnsupportedAlgorithm, [OIDToStr(OID)]);
  FHashAlg := GetHashAlgorithmBySigAlgorithm(GetAlgorithmByOID(OID));
end;

constructor TElRSAPublicKeyCrypto.Create(Alg : integer; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create(Manager, CryptoProvider);
  Reset;
  FHashFuncOID := EmptyArray;
  FOID := EmptyArray;
  if Alg in [SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_MD2_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_MD5_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA1_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA224_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA256_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA384_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA512_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_RSASIGNATURE_RIPEMD160,
    SB_CERT_ALGORITHM_WHIRLPOOL_RSA_ENCRYPTION] then
  begin
    FSupportsSigning := true;
    FSupportsEncryption := true;
    FOID := GetOIDByPKAlgorithm(Alg);
    if Length(FOID) = 0 then
      FOID := GetOIDBySigAlgorithm(Alg);
    FCryptoType := rsapktPKCS1;  
  end
  else if Alg = SB_CERT_ALGORITHM_ID_RSAPSS then
  begin
    FSupportsSigning := true;
    FSupportsEncryption := false;
    FOID := SB_OID_RSAPSS;
    FCryptoType := rsapktPSS;
  end
  else if Alg = SB_CERT_ALGORITHM_ID_RSAOAEP then
  begin
    FSupportsSigning := false;
    FSupportsEncryption := true;
    FOID := SB_OID_RSAOAEP;
    FCryptoType := rsapktOAEP;
  end;

  if CompareContent(FOID, EmptyArray) then
    raise EElPublicKeyCryptoError.CreateFmt(SUnsupportedAlgorithmInt, [Alg]);
  FHashAlg := GetHashAlgorithmBySigAlgorithm(Alg);
end;

constructor TElRSAPublicKeyCrypto.Create(Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  Create(SB_OID_RSAENCRYPTION, Manager, CryptoProvider);
  FHashFuncOID := EmptyArray;
end;

 // SB_JAVA}

procedure TElRSAPublicKeyCrypto.LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  if AlgorithmIdentifier is TElRSAAlgorithmIdentifier then
  begin
    HashAlgorithm := TElRSAAlgorithmIdentifier(AlgorithmIdentifier).HashAlgorithm;
  end
  else if AlgorithmIdentifier is TElRSAOAEPAlgorithmIdentifier then
  begin
    HashAlgorithm := TElRSAOAEPAlgorithmIdentifier(AlgorithmIdentifier).HashAlgorithm;
    StrLabel := TElRSAOAEPAlgorithmIdentifier(AlgorithmIdentifier).StrLabel;
    MGFAlgorithm := TElRSAOAEPAlgorithmIdentifier(AlgorithmIdentifier).MGF;
  end
  else if AlgorithmIdentifier is TElRSAPSSAlgorithmIdentifier then
  begin
    HashAlgorithm := TElRSAPSSAlgorithmIdentifier(AlgorithmIdentifier).HashAlgorithm;
    SaltSize := TElRSAPSSAlgorithmIdentifier(AlgorithmIdentifier).SaltSize;
    TrailerField := TElRSAPSSAlgorithmIdentifier(AlgorithmIdentifier).TrailerField;
    MGFAlgorithm := TElRSAPSSAlgorithmIdentifier(AlgorithmIdentifier).MGF;
  end
  else
    raise EElPublicKeyCryptoError.Create(SInvalidAlgorithmIdentifier);
end;

procedure TElRSAPublicKeyCrypto.SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  if AlgorithmIdentifier is TElRSAAlgorithmIdentifier then
  begin
    TElRSAAlgorithmIdentifier(AlgorithmIdentifier).HashAlgorithm := HashAlgorithm;
  end
  else if AlgorithmIdentifier is TElRSAOAEPAlgorithmIdentifier then
  begin
    TElRSAOAEPAlgorithmIdentifier(AlgorithmIdentifier).HashAlgorithm := HashAlgorithm;
    TElRSAOAEPAlgorithmIdentifier(AlgorithmIdentifier).StrLabel := StrLabel;
    TElRSAOAEPAlgorithmIdentifier(AlgorithmIdentifier).MGF := MGFAlgorithm;
  end
  else if AlgorithmIdentifier is TElRSAPSSAlgorithmIdentifier then
  begin
    TElRSAPSSAlgorithmIdentifier(AlgorithmIdentifier).HashAlgorithm := HashAlgorithm;
    TElRSAPSSAlgorithmIdentifier(AlgorithmIdentifier).SaltSize := SaltSize;
    TElRSAPSSAlgorithmIdentifier(AlgorithmIdentifier).TrailerField := TrailerField;
    TElRSAPSSAlgorithmIdentifier(AlgorithmIdentifier).MGF := MGFAlgorithm;
  end
  else
    raise EElPublicKeyCryptoError.Create(SInvalidAlgorithmIdentifier);
end;


procedure TElRSAPublicKeyCrypto.Reset;
begin
  FSupportsEncryption := false;
  FSupportsSigning := false;
  FInputIsHash := false;
  FUseAlgorithmPrefix := true;
  FCryptoType := rsapktPKCS1;
  FInputEncoding := pkeBinary;
  FOutputEncoding := pkeBinary;
  FHashFuncOID := EmptyArray;
  FSaltSize := 0;
  FMGFAlgorithm := 0;
  FTrailerField := 0;
  FStrLabel := '';
end;

 destructor  TElRSAPublicKeyCrypto.Destroy;
begin
  inherited;
end;

function TElRSAPublicKeyCrypto.GetSupportsEncryption: boolean;
begin
  Result := FSupportsEncryption;
end;

function TElRSAPublicKeyCrypto.GetSupportsSigning: boolean;
begin
  Result := FSupportsSigning;
end;

procedure TElRSAPublicKeyCrypto.SetKeyMaterial(Material : TElPublicKeyMaterial);
begin
  if FBusy then Exit;

  if not (Material is TElRSAKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial)
  else
    FKeyMaterial := Material;
end;

procedure TElRSAPublicKeyCrypto.SetCryptoType(Value : TSBRSAPublicKeyCryptoType);
begin
  if FBusy then Exit;

  FCryptoType := Value;

  FSupportsEncryption := true;
  FSupportsSigning := true;

  if Value = rsapktPSS then
    FSupportsEncryption := false
  else if Value = rsapktOAEP then
    FSupportsSigning := false
  else if Value = rsapktSSL3 then
  begin
    if Assigned(FContext) then
      FContext.SetContextProp(SB_CTXPROP_HASH_ALGORITHM, SB_OID_SSL3);
  end;

  if Assigned(FContext) then
  begin
    if FCryptoType = rsapktOAEP then
      FContext.SetContextProp(SB_CTXPROP_ALGORITHM_SCHEME, SB_ALGSCHEME_OAEP)
    else if FCryptoType = rsapktPSS then
      FContext.SetContextProp(SB_CTXPROP_ALGORITHM_SCHEME, SB_ALGSCHEME_PSS)
    else if FCryptoType = rsapktPKCS1 then
      FContext.SetContextProp(SB_CTXPROP_ALGORITHM_SCHEME, SB_ALGSCHEME_PKCS1);
  end;
end;

procedure TElRSAPublicKeyCrypto.SetUseAlgorithmPrefix(Value : boolean);
begin
  if FBusy then Exit;

  FUseAlgorithmPrefix := Value;
  if FContext <> nil then
    FContext.SetContextProp(SB_CTXPROP_USE_ALGORITHM_PREFIX, GetBufferFromBool(Value));
end;

procedure TElRSAPublicKeyCrypto.SetHashFuncOID(const Value : ByteArray);
begin
  if FBusy then Exit;

  FHashFuncOID := CloneArray(Value);
  if FContext <> nil then
    FContext.SetContextProp(SB_CTXPROP_HASH_FUNC_OID, Value);
end;

function TElRSAPublicKeyCrypto.GetSaltSize : integer;
begin
  Result := FSaltSize;
  if FBusy then Exit;

  if FContext <> nil then
  begin
    FSaltSize := GetIntegerPropFromBuffer(FContext.GetContextProp(SB_CTXPROP_SALT_SIZE));
    Result := FSaltSize;
  end;
end;

procedure TElRSAPublicKeyCrypto.SetSaltSize(Value: integer);
begin
  if FBusy then Exit;

  FSaltSize := Value;
  if FContext <> nil then
    FContext.SetContextProp(SB_CTXPROP_SALT_SIZE, GetBufferFromInteger(FSaltSize));
end;

function TElRSAPublicKeyCrypto.GetStrLabel : string;
begin
  Result := FStrLabel;
  if FBusy then Exit;

  if FContext <> nil then
  begin
    FStrLabel := StringOfBytes(FContext.GetContextProp(SB_CTXPROP_STR_LABEL));
    Result := FStrLabel;
  end;
end;

procedure TElRSAPublicKeyCrypto.SetStrLabel(const Value : string);
begin
  if FBusy then Exit;

  FStrLabel := Value;
  if FContext <> nil then
    FContext.SetContextProp(SB_CTXPROP_STR_LABEL, BytesOfString(FStrLabel));
end;

function TElRSAPublicKeyCrypto.GetTrailerField : integer;
begin
  Result := FTrailerField;
  if FBusy then Exit;

  if FContext <> nil then
  begin
    FTrailerField := GetIntegerPropFromBuffer(FContext.GetContextProp(SB_CTXPROP_TRAILER_FIELD));
    Result := FTrailerField;
  end;
end;

procedure TElRSAPublicKeyCrypto.SetTrailerField(Value: integer);
begin
  if FBusy then Exit;

  FTrailerField := Value;
  if FContext <> nil then
    FContext.SetContextProp(SB_CTXPROP_TRAILER_FIELD, GetBufferFromInteger(FTrailerField));
end;

function TElRSAPublicKeyCrypto.GetMGFAlgorithm : integer;
begin
  Result := FMGFAlgorithm;
  if FBusy then Exit;

  if FContext <> nil then
  begin
    FMGFAlgorithm := GetAlgorithmByOID(FContext.GetContextProp(SB_CTXPROP_MGF_ALGORITHM));
    Result := FMGFAlgorithm;
  end;
end;

procedure TElRSAPublicKeyCrypto.SetMGFAlgorithm(Value: integer);
begin
  if FBusy then Exit;

  FMGFAlgorithm := Value;
  if FContext <> nil then
    FContext.SetContextProp(SB_CTXPROP_MGF_ALGORITHM, GetOIDByAlgorithm(FMGFAlgorithm));
end;

procedure TElRSAPublicKeyCrypto.AdjustContextProps(Params : TElCPParameters);
begin
  inherited;
  Params.Add(SB_CTXPROP_USE_ALGORITHM_PREFIX, GetBufferFromBool(FUseAlgorithmPrefix));
  Params.Add(SB_CTXPROP_HASH_FUNC_OID, FHashFuncOID);
  if FCryptoType <> rsapktSSL3 then
  begin
    Params.Add(SB_CTXPROP_HASH_ALGORITHM, GetOIDByHashAlgorithm(FHashAlg));
    if FCryptoType = rsapktOAEP then
      Params.Add(SB_CTXPROP_ALGORITHM_SCHEME, SB_ALGSCHEME_OAEP)
    else if FCryptoType = rsapktPSS then
    begin
      Params.Add(SB_CTXPROP_ALGORITHM_SCHEME, SB_ALGSCHEME_PSS);
      if FSaltSize <> 0 then
        Params.Add(SB_CTXPROP_SALT_SIZE, GetBufferFromInteger(FSaltSize));
      if FTrailerField <> 0 then
        Params.Add(SB_CTXPROP_TRAILER_FIELD, GetBufferFromInteger(FTrailerField));
      if FMGFAlgorithm <> 0 then
        Params.Add(SB_CTXPROP_MGF_ALGORITHM, GetOIDByAlgorithm(FMGFAlgorithm));
    end
    else if FCryptoType = rsapktPKCS1 then
      Params.Add(SB_CTXPROP_ALGORITHM_SCHEME, SB_ALGSCHEME_PKCS1);
  end
  else
    Params.Add(SB_CTXPROP_HASH_ALGORITHM, SB_OID_SSL3);
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElRSAPublicKeyCrypto.SignInit(Detached: boolean);
var
  Params : TElCPParameters;
begin
  if not FSupportsSigning then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if not (FKeyMaterial is TElRSAKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  if not FKeyMaterial.SecretKey then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  if not Detached then
    raise EElPublicKeyCryptoError.Create(SOnlyDetachedSigningSupported);
  SetLength(FSpool, 0);
  Params := TElCPParameters.Create;
  try
    AdjustContextProps(Params);
    FContext := GetSuitableCryptoProvider(pkoSignDetached, SB_ALGORITHM_PK_RSA, Params).SignInit(
      SB_ALGORITHM_PK_RSA, FKeyMaterial.FKey, Detached, Params
    );
  finally
    FreeAndNil(Params);
  end;
end;

procedure TElRSAPublicKeyCrypto.SignUpdate(Buffer: pointer; Size: integer);
var
  OutSize, OldLen : integer;
  Prov : TElCustomCryptoProvider;
begin
  Prov := FContext.CryptoProvider;
  //Prov := GetSuitableCryptoProvider();
  OutSize := 0;
  Prov.SignUpdate(FContext, Buffer, Size, nil, OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.SignUpdate(FContext, Buffer, Size, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
end;

procedure TElRSAPublicKeyCrypto.SignFinal;
var
  SigSize, OldLen : integer;
  Prov : TElCustomCryptoProvider;
  ProgressFunc : TSBProgressFunc;
begin
  if Assigned(FWorkingThread) then
    ProgressFunc := TElPublicKeyCryptoWorkingThread(FWorkingThread).ProgressHandler
  else
    ProgressFunc := nil;
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  SigSize := 0;
  Prov.SignFinal(FContext, nil, SigSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + SigSize);
  Prov.SignFinal(FContext, @FSpool[OldLen], SigSize);
  SetLength(FSpool, OldLen + SigSize);  
  WriteToOutput(@FSpool[0], OldLen + SigSize);
  FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;

procedure TElRSAPublicKeyCrypto.EncryptInit;
var
  Params : TElCPParameters;
begin
  if not (FKeyMaterial is TElRSAKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  if not FSupportsEncryption then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  SetLength(FSpool, 0);
  Params := TElCPParameters.Create();
  try
    AdjustContextProps(Params);
    FContext := GetSuitableCryptoProvider(pkoEncrypt, SB_ALGORITHM_PK_RSA, Params).EncryptInit(
      SB_ALGORITHM_PK_RSA, 0, FKeyMaterial.FKey, Params
    );
  finally
    FreeAndNil(Params);
  end;
end;

procedure TElRSAPublicKeyCrypto.EncryptUpdate(Buffer: pointer; Size: integer);
var
  OutSize, OldLen : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.EncryptUpdate(FContext, Buffer, Size, nil, OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.EncryptUpdate(FContext, Buffer, Size, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
end;

procedure TElRSAPublicKeyCrypto.EncryptFinal;
var
  SigSize, OldLen : integer;
  Prov : TElCustomCryptoProvider;
  ProgressFunc : TSBProgressFunc;
begin
  if Assigned(FWorkingThread) then
    ProgressFunc := TElPublicKeyCryptoWorkingThread(FWorkingThread).ProgressHandler
  else
    ProgressFunc := nil;
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  SigSize := 0;
  Prov.EncryptFinal(FContext, nil, SigSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + SigSize);
  Prov.EncryptFinal(FContext, @FSpool[OldLen], SigSize);
  SetLength(FSpool, OldLen + SigSize);
  WriteToOutput(@FSpool[0], OldLen + SigSize);
  FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;
 {$endif SB_PGPSFX_STUB}

procedure TElRSAPublicKeyCrypto.DecryptInit;
var
  Params : TElCPParameters;
begin
  if not FSupportsEncryption then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if not (FKeyMaterial is TElRSAKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  if not FKeyMaterial.SecretKey then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  SetLength(FSpool, 0);
  Params := TElCPParameters.Create;
  try
    AdjustContextProps(Params);
    FContext := GetSuitableCryptoProvider(pkoDecrypt, SB_ALGORITHM_PK_RSA, Params).DecryptInit(
      SB_ALGORITHM_PK_RSA, 0, FKeyMaterial.FKey, Params
    );
  finally
    FreeAndNil(Params);
  end;
end;

procedure TElRSAPublicKeyCrypto.DecryptUpdate(Buffer: pointer; Size: integer);
var
  OutSize, OldLen : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.DecryptUpdate(FContext, Buffer, Size, nil, OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.DecryptUpdate(FContext, Buffer, Size, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
end;

procedure TElRSAPublicKeyCrypto.DecryptFinal;
var
  SigSize, OldLen : integer;
  Prov : TElCustomCryptoProvider;
  ProgressFunc : TSBProgressFunc;
begin
  if Assigned(FWorkingThread) then
    ProgressFunc := TElPublicKeyCryptoWorkingThread(FWorkingThread).ProgressHandler
  else
    ProgressFunc := nil;
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  SigSize := 0;
  Prov.DecryptFinal(FContext, nil, SigSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + SigSize);
  Prov.DecryptFinal(FContext, @FSpool[OldLen], SigSize);
  SetLength(FSpool, OldLen + SigSize);
  WriteToOutput(@FSpool[0], OldLen + SigSize);
  FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;

procedure TElRSAPublicKeyCrypto.VerifyInit(Detached: boolean; Signature: pointer;
  SigSize: integer);
var
  Params : TElCPParameters;
begin
  if not (FKeyMaterial is TElRSAKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  if not FKeyMaterial.PublicKey then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  if not FSupportsSigning then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  SetLength(FSpool, 0);
  Params := TElCPParameters.Create();
  try
    AdjustContextProps(Params);
    FContext := GetSuitableCryptoProvider(pkoVerifyDetached, SB_ALGORITHM_PK_RSA, Params).VerifyInit(
      SB_ALGORITHM_PK_RSA, FKeyMaterial.FKey, Signature, 
      SigSize, Params
    );
  finally
    FreeAndNil(Params);
  end;
end;

procedure TElRSAPublicKeyCrypto.VerifyUpdate(Buffer: pointer; Size: integer);
var
  OldLen, OutSize : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.VerifyUpdate(FContext, Buffer, Size,
     nil , OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.VerifyUpdate(FContext, Buffer, Size,
     @FSpool[OldLen] , OutSize);
  SetLength(FSpool, OldLen + OutSize);
end;

function TElRSAPublicKeyCrypto.VerifyFinal : TSBPublicKeyVerificationResult;
var
  OutSize, OldLen : integer;
  R : integer;
  Prov : TElCustomCryptoProvider;
  ProgressFunc : TSBProgressFunc;
begin
  if Assigned(FWorkingThread) then
    ProgressFunc := TElPublicKeyCryptoWorkingThread(FWorkingThread).ProgressHandler
  else
    ProgressFunc := nil;
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.VerifyFinal(FContext, nil, OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  R := Prov.VerifyFinal(FContext, @FSpool[OldLen], OutSize);
  case R of
    SB_VR_SUCCESS:
      Result := pkvrSuccess;
    SB_VR_INVALID_SIGNATURE:
      Result := pkvrInvalidSignature;
    SB_VR_KEY_NOT_FOUND:
      Result := pkvrKeyNotFound;
    else
      Result := pkvrFailure;
  end;
  FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;

function TElRSAPublicKeyCrypto.EstimateOutputSize(InBuffer: pointer; InSize: integer;
  Operation : TSBPublicKeyOperation): integer;
begin
  if (Operation in [pkoVerify, pkoSign]) and
     (CryptoType in [rsapktPKCS1, rsapktPSS]) then
    raise EElPublicKeyCryptoError.Create(SOnlyDetachedSigningSupported);
  if not (KeyMaterial is TElRSAKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);

  if (Operation in [pkoEncrypt, pkoDecrypt]) and
    (InSize > KeyMaterial.Bits shr 3) then
    raise EElPublicKeyCryptoError.Create(SInputTooLong);
  if (Operation = pkoSign) and (InputIsHash) and
    (InSize > (KeyMaterial.Bits shr 3) - 11) then
    raise EElPublicKeyCryptoError.Create(SInputTooLong);
  Result := (KeyMaterial.Bits + 7) shr 3;
end;

class function TElRSAPublicKeyCrypto.IsAlgorithmSupported(Alg: integer): boolean;
begin
  Result := (Alg in [
    SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_MD2_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_MD5_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA1_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA224_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA256_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA384_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA512_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_ID_RSAPSS,
    SB_CERT_ALGORITHM_ID_RSAOAEP
  ]) or (Alg = SB_ALGORITHM_PK_RSA);
end;

class function TElRSAPublicKeyCrypto.IsAlgorithmSupported(const OID: ByteArray): boolean;
begin
  // TODO: pass to crypto provider (and check symmetric crypto for similar things too)
  Result := CompareContent(OID, SB_OID_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_MD2_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_MD5_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA1_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA1_RSAENCRYPTION2) or
    CompareContent(OID, SB_OID_SHA224_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA256_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA384_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA512_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_RSAPSS) or
    CompareContent(OID, SB_OID_RSAOAEP) or
    CompareContent(OID, SB_OID_RSASIGNATURE_RIPEMD160_ISO9796);
end;

class function TElRSAPublicKeyCrypto.GetName() : string;
begin
  Result := 'RSA';
end;

class function TElRSAPublicKeyCrypto.GetDescription() : string;
begin
  Result := 'Implements base RSA encrypting and signing functionality';
end;

function TElRSAPublicKeyCrypto.DecryptKey(EncKey : pointer; EncKeySize : integer;
  const EncKeyAlgOID, EncKeyAlgParams : ByteArray): TElKeyMaterial;
var
  Prov : TElCustomCryptoProvider;
  DecryptedKey : TElCustomCryptoKey;
begin
  Prov := GetSuitableCryptoProvider(pkoDecryptKey, SB_ALGORITHM_PK_RSA, nil); // TODO: check
  DecryptedKey := Prov.DecryptKey(EncKey, EncKeySize, EncKeyAlgOID, EncKeyAlgParams,
    KeyMaterial.FKey, GetOIDByAlgorithm(KeyMaterial.FKey.Algorithm), EmptyArray, nil);
  if DecryptedKey.CryptoProvider.GetAlgorithmClass(DecryptedKey.Algorithm) in
    [SB_ALGCLASS_BLOCK, SB_ALGCLASS_STREAM] then
  begin                              
    Result := TElSymmetricKeyMaterial.Create(DecryptedKey );
  end
  else
  begin
    DecryptedKey.CryptoProvider.ReleaseKey(DecryptedKey);
    raise EElPublicKeyCryptoError.Create(SUnsupportedKeyMaterial);
  end;
end;

////////////////////////////////////////////////////////////////////////////////
//  TElDSAKeyMaterial class

constructor TElDSAKeyMaterial.Create(Prov : TElCustomCryptoProvider  = nil );
begin
  inherited;
  FKey := FProvider.CreateKey(SB_ALGORITHM_PK_DSA, 0, nil);
  FKeyFormat := dsaFIPS;
  FKey.SetKeyProp(SB_KEYPROP_DSA_STRICT_VALIDATION, GetBufferFromBool(false));
  FPassphrase := '';
end;

constructor TElDSAKeyMaterial.Create(Manager: TElCustomCryptoProviderManager;
  Prov : TElCustomCryptoProvider);
begin
  inherited;
  FKey := FProvider.CreateKey(SB_ALGORITHM_PK_DSA, 0, nil);
  FKeyFormat := dsaFIPS;
  FKey.SetKeyProp(SB_KEYPROP_DSA_STRICT_VALIDATION, GetBufferFromBool(false));
  FPassphrase := '';
end;


 destructor  TElDSAKeyMaterial.Destroy;
begin
  inherited;
end;

procedure TElDSAKeyMaterial.Reset;
begin
  FPEMEncode := false;
  FKeyFormat := dsaFIPS;
  FStoreFormat := ksfRaw;
end;

function TElDSAKeyMaterial.GetValid : boolean;
begin
  Result := FKey.IsValid;
end;

function TElDSAKeyMaterial.GetBits : integer;
begin
  Result := FKey.Bits;
end;

function TElDSAKeyMaterial.GetQBits : integer;
begin
  Result := GetIntegerPropFromBuffer(FKey.GetKeyProp(SB_KEYPROP_DSA_QBITS));
end;

function TElDSAKeyMaterial.GetHashAlgorithm : integer;
begin
  Result := GetAlgorithmByOID(FKey.GetKeyProp(SB_KEYPROP_HASH_ALGORITHM));
end;

procedure TElDSAKeyMaterial.SetHashAlgorithm(Value : integer);
begin
  FKey.SetKeyProp(SB_KEYPROP_HASH_ALGORITHM, GetOIDByHashAlgorithm(Value));
end;

procedure TElDSAKeyMaterial.SetPassphrase(const Value : string);
begin
  if FBusy then Exit;

  FPassphrase := Value;
end;

procedure TElDSAKeyMaterial.SetPEMEncode(Value : boolean);
begin
  if FBusy then Exit;

  FPEMEncode := Value;
end;

procedure TElDSAKeyMaterial.SetStrictKeyValidation(Value : boolean);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_DSA_STRICT_VALIDATION, GetBufferFromBool(Value));
end;

function TElDSAKeyMaterial.GetStrictKeyValidation: boolean;
begin
  Result := GetBoolFromBuffer(FKey.GetKeyProp(SB_KEYPROP_DSA_STRICT_VALIDATION));
end;

function TElDSAKeyMaterial.GetP : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_DSA_P);
end;

function TElDSAKeyMaterial.GetQ : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_DSA_Q);
end;

function TElDSAKeyMaterial.GetG : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_DSA_G);
end;

function TElDSAKeyMaterial.GetX : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_DSA_X);
end;

function TElDSAKeyMaterial.GetY : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_DSA_Y);
end;

procedure TElDSAKeyMaterial.SetP(const Value : ByteArray);
begin
  FKey.SetKeyProp(SB_KEYPROP_DSA_P, Value);
end;

procedure TElDSAKeyMaterial.SetQ(const Value : ByteArray);
begin
  FKey.SetKeyProp(SB_KEYPROP_DSA_Q, Value);
end;

procedure TElDSAKeyMaterial.SetG(const Value : ByteArray);
begin
  FKey.SetKeyProp(SB_KEYPROP_DSA_G, Value);
end;

procedure TElDSAKeyMaterial.SetY(const Value : ByteArray);
begin
  FKey.SetKeyProp(SB_KEYPROP_DSA_Y, Value);
end;

procedure TElDSAKeyMaterial.SetX(const Value : ByteArray);
begin
  FKey.SetKeyProp(SB_KEYPROP_DSA_X, Value);
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElDSAKeyMaterial.InternalGenerate(PBits, QBits : integer);
var
  Pars : TElCPParameters;
  ProgressFunc : TSBProgressFunc;
begin
  if Assigned(FWorkingThread) then
    ProgressFunc := TElPublicKeyMaterialWorkingThread(FWorkingThread).ProgressHandler
  else
    ProgressFunc := nil;
  Pars := TElCPParameters.Create();
  try
    Pars.Add(SB_KEYPROP_DSA_QBITS, GetBufferFromInteger(QBits));
    FKey.Generate(PBits, Pars, ProgressFunc);
  finally
    FreeAndNil(Pars);
  end;
end;

procedure TElDSAKeyMaterial.InternalGenerate(Bits : integer);
begin
  InternalGenerate(Bits, 0);
end;
 {$endif SB_PGPSFX_STUB}

{$ifndef SB_PGPSFX_STUB}
procedure TElDSAKeyMaterial.Generate(PBits, QBits : integer);
begin
  if FBusy then Exit;
  InternalGenerate(PBits, QBits);
end;

procedure TElDSAKeyMaterial.Generate(Bits : integer);
begin
  if FBusy then Exit;
  InternalGenerate(Bits);
end;

procedure TElDSAKeyMaterial.BeginGenerate(PBits, QBits : integer);
begin
  if FBusy then Exit;

  FAsyncOperationFinished := false;
  FAsyncOperationSucceeded := false;
  FBusy := true;
  FWorkingThread := TElPublicKeyMaterialWorkingThread.Create(Self);
  TElPublicKeyMaterialWorkingThread(FWorkingThread).Bits := PBits;
  TElPublicKeyMaterialWorkingThread(FWorkingThread).QBits := QBits;
  FWorkingThread.FreeOnTerminate := true;
  FWorkingThread.Resume;
end;
 {$endif SB_PGPSFX_STUB}

{$ifndef SB_PGPSFX_STUB}
procedure TElDSAKeyMaterial.LoadFromXML(const Str: string);
var
  v: TXMLParamValues;
  OutBuf: ByteArray;
  OutSize: Integer;
begin
  Clear;
  v := ParseXmlString(Str, 'DSAKeyValue', ['P', 'Q', 'G', 'Y', 'X']);
  if (Length(v) <> 5) or (Length(v[0]) = 0) or (Length(v[1]) = 0) or
     (Length(v[2]) = 0) or (Length(v[3]) = 0) then
    raise EElPublicKeyCryptoError.Create(SInvalidXML);

  OutSize := 0;
  if Length(v[4]) > 0 then
  begin
    SBDSA.EncodePrivateKey(@v[0][0], Length(v[0]), @v[1][0], Length(v[1]), @v[2][0], Length(v[2]),
      @v[3][0], Length(v[3]), @v[4][0], Length(v[4]), nil, OutSize);
    SetLength(OutBuf, OutSize);
    if not SBDSA.EncodePrivateKey(@v[0][0], Length(v[0]), @v[1][0], Length(v[1]), @v[2][0], Length(v[2]),
       @v[3][0], Length(v[3]), @v[4][0], Length(v[4]), @OutBuf[0], OutSize) then
      raise EElPublicKeyCryptoError.Create(SInvalidSecretKey);

    FKey.ImportSecret( @OutBuf[0] , OutSize, nil);
    ReleaseArray(OutBuf);
  end
  else
  begin
    ImportPublicKey(@v[0][0], Length(v[0]), @v[1][0], Length(v[1]), @v[2][0], Length(v[2]),
       @v[3][0], Length(v[3]));
  end;
end;
 {$endif SB_PGPSFX_STUB}

procedure TElDSAKeyMaterial.LoadSecret( Buffer: pointer;
    Size: integer);
var
  PlainKey : ByteArray;
  PlainSize : integer;
  Header : string;
  R : integer;
begin
  Reset;

  FKeyFormat := dsaFIPS;
  FStoreFormat := ksfRaw;
  // checking if the key is PEM-enveloped
  if IsPEM(Buffer, Size) then
  begin
    PlainSize := 0;
    SBPEM.Decode(Buffer, Size, nil, FPassphrase, PlainSize, Header);
    SetLength(PlainKey, PlainSize);
    R := SBPEM.Decode(Buffer, Size, @PlainKey[0], FPassphrase, PlainSize, Header);
    if R <> 0 then
    begin
      case R of
        PEM_DECODE_RESULT_INVALID_PASSPHRASE :
          raise EElPublicKeyCryptoError.Create(SInvalidPassphrase);
        else
          raise EElPublicKeyCryptoError.Create(SInvalidPEM);
      end;
    end
  end
  else
  begin
    SetLength(PlainKey, Size);
    SBMove(Buffer^, PlainKey[0], Size);
    PlainSize := Size;
  end;

  // trying to load a key as plain DSA key
  FKey.ImportSecret(PlainKey, PlainSize);
end;

procedure TElDSAKeyMaterial.SaveSecret( Buffer: pointer;
   var Size: TSBInteger);
var
  OutSize : integer;
  Encrypt : boolean;
  KeyBlob : ByteArray;
  {$ifndef SB_PGPSFX_STUB}
  PKCS8Key : TElPKCS8PrivateKey;
   {$endif}
  List : array of ByteArray;
  Item : ByteArray;
begin
  OutSize := 0;

  {$ifndef SB_PGPSFX_STUB}
  if (FStoreFormat = ksfPKCS8) and (SecretKey) then
  begin
    PKCS8Key := TElPKCS8PrivateKey.Create;
    PKCS8Key.UseNewFeatures := true;
    PKCS8Key.SymmetricAlgorithm := SB_ALGORITHM_CNT_3DES;

    SetLength(List, 3);
    List[0] := WriteInteger(Self.P);
    List[1] := WriteInteger(Self.Q);
    List[2] := WriteInteger(Self.G);
    
    Item := WriteArraySequence(List);

    PKCS8Key.KeyAlgorithm := SB_OID_DSA;
    PKCS8Key.KeyAlgorithmParams := Item;

    PKCS8Key.KeyMaterial := WriteInteger(X);
    
    OutSize := 0;
    PKCS8Key.SaveToBuffer(nil, OutSize, FPassphrase, false);
    SetLength(KeyBlob, OutSize);
    PKCS8Key.SaveToBuffer(@KeyBlob[0], OutSize, FPassphrase, false);
    SetLength(KeyBlob, OutSize);
  end;
   {$endif}

  if FStoreFormat = ksfRaw then
  begin
    FKey.ExportSecret( nil , OutSize, nil);
    SetLength(KeyBlob, OutSize);
    FKey.ExportSecret( @KeyBlob[0] , OutSize, nil);
    SetLength(KeyBlob, OutSize);
  end;

  {$ifndef SB_PGPSFX_STUB}
  if PEMEncode then
  begin
    OutSize := 0;
    Encrypt := Length(FPassphrase) > 0;
    SBPEM.Encode(@KeyBlob[0], Length(KeyBlob), nil, OutSize,
      'DSA PRIVATE KEY', Encrypt, FPassphrase);
    if OutSize <= Size then
    begin
      if not SBPEM.Encode(@KeyBlob[0], Length(KeyBlob), Buffer, Size,
        'DSA PRIVATE KEY', Encrypt, FPassphrase) then
        raise EElPublicKeyCryptoError.Create(SPEMWriteError);
    end
    else if Size = 0 then
      Size := OutSize
    else
      raise EElPublicKeyCryptoError.Create(SBufferTooSmall);
  end
  else
   {$endif}
  begin
    if Size = 0 then
      Size := Length(KeyBlob)
    else if Size < Length(KeyBlob) then
      raise EElPublicKeyCryptoError.Create(SBufferTooSmall)
    else
    begin
      Size := Length(KeyBlob);
      SBMove(KeyBlob[0], Buffer^, Size);
    end
  end;
  ReleaseArray(KeyBlob);
end;

{$ifndef SB_PGPSFX_STUB}
function TElDSAKeyMaterial.SaveToXML(IncludePrivateKey: Boolean  =  False): string;
begin
  Result := '';
  if IncludePrivateKey and SecretKey then
  begin
    Result := Format('<DSAKeyValue><P>%s</P><Q>%s</Q><G>%s</G><Y>%s</Y><X>%s</X></DSAKeyValue>',
       [(ConvertToBase64String(P)),
        (ConvertToBase64String(Q)),
        (ConvertToBase64String(G)),
        (ConvertToBase64String(Y)),
        (ConvertToBase64String(X))]);
  end
  else if PublicKey then
  begin
    Result := Format('<DSAKeyValue><P>%s</P><Q>%s</Q><G>%s</G><Y>%s</Y></DSAKeyValue>',
       [(ConvertToBase64String(P)),
        (ConvertToBase64String(Q)),
        (ConvertToBase64String(G)),
        (ConvertToBase64String(Y))]);
  end;
end;
 {$endif SB_PGPSFX_STUB}

procedure TElDSAKeyMaterial.ImportPublicKey(P : pointer; PSize : integer; Q : pointer;
  QSize : integer; G : pointer; GSize : integer; Y : pointer; YSize : integer);
begin
  FKey.SetKeyProp(SB_KEYPROP_DSA_P, CloneArray(P, PSize));
  FKey.SetKeyProp(SB_KEYPROP_DSA_Q, CloneArray(Q, QSize));
  FKey.SetKeyProp(SB_KEYPROP_DSA_G, CloneArray(G, GSize));
  FKey.SetKeyProp(SB_KEYPROP_DSA_Y, CloneArray(Y, YSize));
  FKey.SetKeyProp(SB_KEYPROP_DSA_X, EmptyArray);
end;

procedure TElDSAKeyMaterial.ExportPublicKey(P : pointer; var PSize : integer;
  Q : pointer; var QSize : integer; G : pointer; var GSize : integer;
  Y : pointer; var YSize : integer);
var
  VP, VQ, VG, VY : ByteArray;
begin
  VP := FKey.GetKeyProp(SB_KEYPROP_DSA_P);
  VQ := FKey.GetKeyProp(SB_KEYPROP_DSA_Q);
  VG := FKey.GetKeyProp(SB_KEYPROP_DSA_G);
  VY := FKey.GetKeyProp(SB_KEYPROP_DSA_Y);
  if PSize = 0 then
  begin
    PSize := Length(VP);
    QSize := Length(VQ);
    GSize := Length(VG);
    YSize := Length(VY);
    Exit;
  end;

  if (Length(VP) < PSize) or (Length(VQ) < QSize) or (Length(VG) < GSize) or
    (Length(VY) < YSize)
  then
    raise EElPublicKeyCryptoError.Create(SBufferTooSmall);

  PSize := Length(VP);
  QSize := Length(VQ);
  GSize := Length(VG);
  YSize := Length(VY);

  SBMove(VP[0], P^, PSize);
  SBMove(VQ[0], Q^, QSize);
  SBMove(VG[0], G^, GSize);
  SBMove(VY[0], Y^, YSize);
end;

procedure TElDSAKeyMaterial.LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  if (AlgorithmIdentifier is TElDSAAlgorithmIdentifier) then
  begin
    if AlgorithmIdentifier.Algorithm = SB_CERT_ALGORITHM_ID_DSA then
    begin
      P := TElDSAAlgorithmIdentifier(AlgorithmIdentifier).P;
      Q := TElDSAAlgorithmIdentifier(AlgorithmIdentifier).Q;
      G := TElDSAAlgorithmIdentifier(AlgorithmIdentifier).G;
    end  
  end
  else
    raise EElPublicKeyCryptoError.Create(SInvalidKeyParameters);
end;

procedure TElDSAKeyMaterial.SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  if AlgorithmIdentifier is TElDSAAlgorithmIdentifier then
  begin
    if AlgorithmIdentifier.Algorithm = SB_CERT_ALGORITHM_ID_DSA then
    begin
      TElDSAAlgorithmIdentifier(AlgorithmIdentifier).P := P;
      TElDSAAlgorithmIdentifier(AlgorithmIdentifier).Q := Q;
      TElDSAAlgorithmIdentifier(AlgorithmIdentifier).G := G;
    end  
  end
  else
    raise EElPublicKeyCryptoError.Create(SInvalidKeyParameters);
end;

procedure TElDSAKeyMaterial.Assign(Source : TElKeyMaterial);
begin
  if not (Source is TElDSAKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SInvalidKeyMaterialType);
  FKeyFormat := TElDSAKeyMaterial(Source).FKeyFormat;
  FPassphrase := TElDSAKeyMaterial(Source).FPassphrase;
  FPEMEncode := TElDSAKeyMaterial(Source).FPEMEncode;
  FProvider.ReleaseKey(FKey);
  //FKey := TElDSAKeyMaterial(Source).FKey.Clone();
  FKey := TElDSAKeyMaterial(Source).FKey.CryptoProvider.CloneKey(TElDSAKeyMaterial(Source).FKey);
  FProvider := TElDSAKeyMaterial(Source).FProvider;
  FProviderManager := TElDSAKeyMaterial(Source).FProviderManager;
end;

function TElDSAKeyMaterial.Clone :  TElKeyMaterial ;
var
  Res : TElKeyMaterial;
begin
  Res := TElDSAKeyMaterial.Create(FProvider);
  Res.Assign(Self);
  Result := Res;
end;

function TElDSAKeyMaterial.Equals(Source : TElKeyMaterial; PublicOnly : boolean): boolean;
var
  B, B1:ByteArray;
begin
  Result := false;
  SetLength(B, 0);
  SetLength(B1, 0);
  if not (Source is TElDSAKeyMaterial) then exit;
  if (Self.Key.IsPublic <> Source.Key.IsPublic) then exit;
  if (Self.Key.IsSecret and Source.Key.IsSecret) and (not PublicOnly) then
  begin
      Result := Self.Key.Equals(Source.Key, false,nil);
      exit;
  end;

  Result := true;
  B := TElDSAKeyMaterial(Source).GetP;
  B1 := Self.GetP;
  Result := Result and (Length(B) = Length(B1)) and
       (CompareMem(@B1[0], @B[0], Length(B1)))
       ;
  B := TElDSAKeyMaterial(Source).GetQ;
  B1 := Self.GetQ;
  Result := Result and (Length(B) = Length(B1)) and
       (CompareMem(@B1[0], @B[0], Length(B1)))
       ;
  B := TElDSAKeyMaterial(Source).GetG;
  B1 := Self.GetG;
  Result := Result and (Length(B) = Length(B1)) and
       (CompareMem(@B1[0], @B[0], Length(B1)))
       ;
  B := TElDSAKeyMaterial(Source).GetY;
  B1 := Self.GetY;
  Result := Result and (Length(B) = Length(B1)) and
       (CompareMem(@B1[0], @B[0], Length(B1)))
       ;
end;

procedure TElDSAKeyMaterial.ClearSecret;
begin
  FKey.ClearSecret;
end;

procedure TElDSAKeyMaterial.ClearPublic;
begin
  FKey.ClearPublic;
end;

procedure TElDSAKeyMaterial.LoadPublic( Buffer: pointer;
    Size: integer);
var
  cTag, ParsSec : TElASN1ConstrainedTag;
  RawBuf : ByteArray;
  P, Q, G, Y : ByteArray;
  Err, RawSize, TagID : integer;
  Header : string;
  Succ : boolean;
begin
  FKeyFormat := dsaFIPS;
  FStoreFormat := ksfRaw;

  if IsPEM(Buffer, Size) then
  begin
    Succ := false;

    RawSize := Size;
    SetLength(RawBuf, RawSize);

    Err := SBPEM.Decode(Buffer, Size, @RawBuf[0], '', RawSize, Header);
    if Err <> 0 then
      raise EElPublicKeyCryptoError.Create(SInvalidPublicKey, Err);

    SetLength(RawBuf, RawSize);

    cTag := TElASN1ConstrainedTag.CreateInstance;
    try
      if not cTag.LoadFromBuffer(RawBuf, RawSize) then
        raise EElPublicKeyCryptoError.Create(SInvalidPublicKey);

      if (cTag.Count = 1) and (cTag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) and
        (TElASN1ConstrainedTag(cTag.GetField(0)).Count = 2) and
        (TElASN1ConstrainedTag(cTag.GetField(0)).GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) and
        (TElASN1ConstrainedTag(cTag.GetField(0)).GetField(1).CheckType(SB_ASN1_BITSTRING, false)) then
      begin
        ParsSec := TElASN1ConstrainedTag(TElASN1ConstrainedTag(cTag.GetField(0)).GetField(0));
        if (ParsSec.Count = 2) and (ParsSec.GetField(0).CheckType(SB_ASN1_OBJECT, false)) and
          (ParsSec.GetField(1).CheckType(SB_ASN1_SEQUENCE, true)) and
          (CompareContent(TElASN1SimpleTag(ParsSec.GetField(0)).Content, SB_OID_DSA)) then
        begin
          ParsSec := TElASN1ConstrainedTag(ParsSec.GetField(1));
          if (ParsSec.Count = 3) and (ParsSec.GetField(0).CheckType(SB_ASN1_INTEGER, false)) and
            (ParsSec.GetField(1).CheckType(SB_ASN1_INTEGER, false)) and
            (ParsSec.GetField(2).CheckType(SB_ASN1_INTEGER, false)) then
          begin
            // Key format OK, extracting the values
            P := TElASN1SimpleTag(ParsSec.GetField(0)).Content;
            Q := TElASN1SimpleTag(ParsSec.GetField(1)).Content;
            G := TElASN1SimpleTag(ParsSec.GetField(2)).Content;
            Y := TElASN1SimpleTag(TElASN1ConstrainedTag(cTag.GetField(0)).GetField(1)).Content;
            if Length(Y) > 0 then
            begin
              Y := CloneArray(Y, 1, Length(Y) - 1);
              Y := ASN1ReadSimpleValue(Y, TagID);
              Succ := true;
            end;
          end;
        end;
      end;

      if Succ then
      begin
        ImportPublicKey(@P[0], Length(P), @Q[0], Length(Q), @G[0], Length(G), @Y[0], Length(Y));
      end
      else
        raise EElPublicKeyCryptoError.Create(SInvalidPublicKey);
    finally
      ReleaseArrays(RawBuf, P, Q, G, Y);
      ReleaseString(Header);
      FreeAndNil(cTag);
    end;
  end
  else
  begin
    cTag := TElASN1ConstrainedTag.CreateInstance;
    try
      if not cTag.LoadFromBuffer(Buffer, Size) then
        raise EElPublicKeyCryptoError.Create(SInvalidPublicKey);

      if (cTag.Count <> 1) or (not cTag.GetField(0).CheckType(SB_ASN1_INTEGER, false)) then
        raise EElPublicKeyCryptoError.Create(SInvalidPublicKey);

      FKey.SetKeyProp(SB_KEYPROP_DSA_Y, TElASN1SimpleTag(cTag.GetField(0)).Content);
    finally
      FreeAndNil(cTag);
    end;
  end;
end;


procedure TElDSAKeyMaterial.SavePublic(Buffer: pointer; var Size: integer);
var
  Tag : TElASN1SimpleTag;
  Y : ByteArray;
  RealSize : integer;
begin
  Tag := TElASN1SimpleTag.CreateInstance();
  try
    Tag.TagId := SB_ASN1_INTEGER;
    Y := FKey.GetKeyProp(SB_KEYPROP_DSA_Y);
    Tag.Content := Y;
    RealSize := 0;
    Tag.SaveToBuffer( nil , RealSize);
    if (Size = 0) or (Buffer = nil) then
      Size := RealSize
    else
    begin
      if RealSize <= Size then
      begin
        Tag.SaveToBuffer(Buffer, Size)
      end
      else
        raise EElPublicKeyCryptoError.Create(SBufferTooSmall);
    end;
  finally
    FreeAndNil(Tag);
  end;
end; 

function TElDSAKeyMaterial.EncodePrivateKey(P : pointer; PSize : integer;
  Q : pointer; QSize : integer; G : pointer; GSize : integer; Y : pointer;
  YSize : integer; X : pointer; XSize : integer;
  OutBuffer : pointer; var OutSize : integer) : boolean;
begin
  Result := SBDSA.EncodePrivateKey(P, PSize, Q, QSize, G, GSize, Y, YSize, X, XSize, OutBuffer, OutSize);
end;

function TElDSAKeyMaterial.DecodePrivateKey(Blob : pointer; BlobSize : integer;
  P : pointer; var PSize : integer; Q : pointer; var QSize : integer;
  G : pointer; var GSize : integer; Y : pointer; var YSize : integer;
  X : pointer; var XSize : integer) : boolean;
begin
  Result := SBDSA.DecodePrivateKey(Blob, BlobSize, P, PSize, Q, QSize,
    G, GSize, Y, YSize, X, XSize);
end;


////////////////////////////////////////////////////////////////////////
//  TElDSAPublicKeyCrypto class

function TElDSAPublicKeyCrypto.GetSupportsEncryption: boolean;
begin
  Result := false;
end;

function TElDSAPublicKeyCrypto.GetSupportsSigning: boolean;
begin
  Result := true;
end;

procedure TElDSAPublicKeyCrypto.SetKeyMaterial(Material : TElPublicKeyMaterial);
begin
  if FBusy then Exit;

  if not (Material is TElDSAKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial)
  else
    FKeyMaterial := Material;
end;

procedure TElDSAPublicKeyCrypto.LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  if AlgorithmIdentifier is TElDSAAlgorithmIdentifier then
  begin
    HashAlgorithm := AlgorithmIdentifier.SignatureHashAlgorithm;
  end
  else
    raise EElPublicKeyCryptoError.Create(SInvalidAlgorithmIdentifier);
end;

procedure TElDSAPublicKeyCrypto.SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  if AlgorithmIdentifier is TElDSAAlgorithmIdentifier then
  begin
    ;
  end
  else
    raise EElPublicKeyCryptoError.Create(SInvalidAlgorithmIdentifier);
end;

procedure TElDSAPublicKeyCrypto.EncodeSignature(R : pointer; RSize : integer; S : pointer; SSize : integer;
  Sig : pointer; var SigSize : integer);
begin
  SBDSA.EncodeSignature(R, RSize, S, SSize, Sig, SigSize);
end;

procedure TElDSAPublicKeyCrypto.DecodeSignature(Sig : pointer; SigSize : integer; R : pointer;
  var RSize : integer; S : pointer; var SSize : integer);
begin
  SBDSA.DecodeSignature(Sig, SigSize, R, RSize, S, SSize);
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElDSAPublicKeyCrypto.SignInit(Detached: boolean);
var
  Params : TElCPParameters;
  Op : TSBPublicKeyOperation;
begin
  if not (FKeyMaterial is TElDSAKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  if not FKeyMaterial.SecretKey then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  SetLength(FSpool, 0);
  Params := TElCPParameters.Create();
  try
    AdjustContextProps(Params);
    if Detached then Op := pkoSignDetached else Op := pkoSign;
    FContext := GetSuitableCryptoProvider(Op, SB_ALGORITHM_PK_DSA, Params).SignInit(
      SB_ALGORITHM_PK_DSA, FKeyMaterial.FKey, Detached, Params
    );
  finally
    FreeAndNil(Params);
  end;
end;

procedure TElDSAPublicKeyCrypto.SignUpdate( Buffer: pointer;
    Size: integer);
var
  OldLen, OutSize : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.SignUpdate(FContext, Buffer, Size, nil, OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.SignUpdate(FContext, Buffer, Size, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
end;

procedure TElDSAPublicKeyCrypto.SignFinal;
var
  SigSize, OldLen : integer;
  Prov : TElCustomCryptoProvider;
  ProgressFunc : TSBProgressFunc;
begin
  if Assigned(FWorkingThread) then
    ProgressFunc := TElPublicKeyCryptoWorkingThread(FWorkingThread).ProgressHandler
  else
    ProgressFunc := nil;
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  SigSize := 0;
  Prov.SignFinal(FContext, nil, SigSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + SigSize);
  Prov.SignFinal(FContext, @FSpool[OldLen], SigSize);
  SetLength(FSpool, OldLen + SigSize);
  WriteToOutput(@FSpool[0], Length(FSpool));
  FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;
 {$endif SB_PGPSFX_STUB}

procedure TElDSAPublicKeyCrypto.VerifyInit(Detached: boolean;  Signature: pointer;
    SigSize: integer);
var
  Params : TElCPParameters;
  Op : TSBPublicKeyOperation;
begin
  if not (FKeyMaterial is TElDSAKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  if not FKeyMaterial.PublicKey then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  SetLength(FSpool, 0);
  Params := TElCPParameters.Create();
  try
    AdjustContextProps(Params);
    if Detached then Op := pkoVerifyDetached else Op := pkoVerify;
    FContext := GetSuitableCryptoProvider(Op, SB_ALGORITHM_PK_DSA, Params).VerifyInit(
      SB_ALGORITHM_PK_DSA, FKeyMaterial.FKey, Signature, 
      SigSize, Params
    );
  finally
    FreeAndNil(Params);
  end;
end;

procedure TElDSAPublicKeyCrypto.VerifyUpdate( Buffer: pointer;
   Size: integer);
var
  OutSize, OldLen : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.VerifyUpdate(FContext, Buffer, Size, nil, OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.VerifyUpdate(FContext, Buffer, Size, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
end;

function TElDSAPublicKeyCrypto.VerifyFinal : TSBPublicKeyVerificationResult;
var
  R : integer;
  OutSize, OldLen : integer;
  Prov : TElCustomCryptoProvider;
  ProgressFunc : TSBProgressFunc;
begin
  if Assigned(FWorkingThread) then
    ProgressFunc := TElPublicKeyCryptoWorkingThread(FWorkingThread).ProgressHandler
  else
    ProgressFunc := nil;
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.VerifyFinal(FContext,  nil , OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  R := Prov.VerifyFinal(FContext, @FSpool[OldLen], OutSize);
  case R of
    SB_VR_SUCCESS :
      Result := pkvrSuccess;
    SB_VR_INVALID_SIGNATURE :
      Result := pkvrInvalidSignature;
    SB_VR_KEY_NOT_FOUND :
      Result := pkvrKeyNotFound;
    else
      Result := pkvrFailure;
  end;
  SetLength(FSpool, OldLen + OutSize);
  WriteToOutput(@FSpool[0], Length(FSpool));
  FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;

function TElDSAPublicKeyCrypto.EstimateOutputSize( InBuffer: pointer;
    InSize: integer;
  Operation : TSBPublicKeyOperation): integer;
var
  Params : TElCPParameters;
  CPEstSize : integer;
  Ctx : TElCustomCryptoContext;
begin
  if (Operation in [pkoEncrypt, pkoDecrypt,
    pkoSign, pkoVerify]) then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  if not (KeyMaterial is TElDSAKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SInvalidKeyMaterialType);
  if (Operation = pkoSignDetached) and
     (not FKeyMaterial.SecretKey) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);

  if Operation = pkoSignDetached then
    Result := (TElDSAKeyMaterial(FKeyMaterial).QBits shr 3) shl 1 + 16
  else
    Result := 0;

  CPEstSize := 0;
  Params := TElCPParameters.Create();
  try
    AdjustContextProps(Params);
    try
      {$ifndef SB_PGPSFX_STUB}
      Ctx := GetSuitableCryptoProvider(pkoSignDetached,
        SB_ALGORITHM_PK_DSA, Params).SignInit(
        SB_ALGORITHM_PK_DSA, FKeyMaterial.FKey, true, Params
      );
      try
        CPEstSize := Ctx.EstimateOutputSize(InSize);
      finally
        Ctx.CryptoProvider.ReleaseCryptoContext(Ctx);
      end;
       {$else}
      raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
       {$endif}
    except
      ; // just ignoring cryptoprovider's exception, it just can not support size estimation
    end;
  finally
    FreeAndNil(Params);
  end;

  if CPEstSize > Result then
    Result := CPEstSize;
end;

class function TElDSAPublicKeyCrypto.IsAlgorithmSupported(Alg: integer): boolean;
begin
  Result := (Alg in [SB_CERT_ALGORITHM_ID_DSA, SB_CERT_ALGORITHM_ID_DSA_SHA1]) or
    (Alg = SB_ALGORITHM_PK_DSA);
end;

class function TElDSAPublicKeyCrypto.IsAlgorithmSupported(const OID: ByteArray): boolean;
begin
  Result := CompareContent(OID, SB_OID_DSA) or CompareContent(OID, SB_OID_DSA_SHA1);
end;

class function TElDSAPublicKeyCrypto.GetName() : string;
begin
  Result := 'DSA';
end;

class function TElDSAPublicKeyCrypto.GetDescription() : string;
begin
  Result := 'Implements DSA signing functionality';
end;

procedure TElDSAPublicKeyCrypto.Reset;
begin
  FInputIsHash := false;
  FInputEncoding := pkeBinary;
  FOutputEncoding := pkeBinary;
end;

constructor TElDSAPublicKeyCrypto.Create(const OID : ByteArray; CryptoProvider:
  TElCustomCryptoProvider  =  nil);
//var
//  Alg, HashAlg : integer;
begin
   Create (OID, nil, CryptoProvider);
  (*
  inherited Create(CryptoProvider);
  FOID := OID;

  if not IsAlgorithmSupported(OID) then
  {$ifdef SB_VCL}
    raise EElPublicKeyCryptoError.CreateFmt(SUnsupportedAlgorithm, [OIDToStr(OID)]);
  {$else}
    raise EElPublicKeyCryptoError.Create(System.String.Format(SUnsupportedAlgorithm, [OIDToStr(OID)]));
  {$endif}
  Alg := GetAlgorithmByOID(OID);
  HashAlg := GetHashAlgorithmBySigAlgorithm(Alg);
  if HashAlg <> SB_ALGORITHM_UNKNOWN then
    FHashAlg := HashAlg;
  *)
end;

constructor TElDSAPublicKeyCrypto.Create(Alg : integer; CryptoProvider : TElCustomCryptoProvider  =  nil);
//var
//  HashAlg : integer;
begin
   Create (Alg, nil, CryptoProvider);
  (*
  inherited Create(CryptoProvider);

  FOID := EmptyArray;

  if IsAlgorithmSupported(Alg) then
  begin
    FOID := GetOIDByPKAlgorithm(Alg);
    if Length(FOID) = 0 then
      FOID := GetOIDBySigAlgorithm(Alg);
  end;
  HashAlg := GetHashAlgorithmBySigAlgorithm(Alg);
  if HashAlg <> SB_ALGORITHM_UNKNOWN then
    FHashAlg := HashAlg;
  if CompareContent(FOID, EmptyArray) then
  {$ifdef SB_VCL}
    raise EElPublicKeyCryptoError.CreateFmt(SUnsupportedAlgorithmInt, [Alg]);
  {$else}
    raise EElPublicKeyCryptoError.Create(System.String.Format(SUnsupportedAlgorithmInt, [Alg]));
  {$endif}
  *)
end;

constructor TElDSAPublicKeyCrypto.Create(CryptoProvider : TElCustomCryptoProvider  = nil );
begin
   Create (SB_OID_DSA, CryptoProvider);
  FHashAlg := SB_ALGORITHM_DGST_SHA1;
end;

constructor TElDSAPublicKeyCrypto.Create(const OID : ByteArray;
  Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
var
  Alg, HashAlg : integer;
begin
  inherited Create(Manager, CryptoProvider);
  FOID := OID;

  if not IsAlgorithmSupported(OID) then
    raise EElPublicKeyCryptoError.CreateFmt(SUnsupportedAlgorithm, [OIDToStr(OID)]);
  Alg := GetAlgorithmByOID(OID);
  HashAlg := GetHashAlgorithmBySigAlgorithm(Alg);
  if HashAlg <> SB_ALGORITHM_UNKNOWN then
    FHashAlg := HashAlg;
end;

constructor TElDSAPublicKeyCrypto.Create(Alg : integer; Manager: TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
var
  HashAlg : integer;
begin
  inherited Create(Manager, CryptoProvider);
  FOID := EmptyArray;

  if IsAlgorithmSupported(Alg) then
  begin
    FOID := GetOIDByPKAlgorithm(Alg);
    if Length(FOID) = 0 then
      FOID := GetOIDBySigAlgorithm(Alg);
  end;
  HashAlg := GetHashAlgorithmBySigAlgorithm(Alg);
  if HashAlg <> SB_ALGORITHM_UNKNOWN then
    FHashAlg := HashAlg;
  if CompareContent(FOID, EmptyArray) then
    raise EElPublicKeyCryptoError.CreateFmt(SUnsupportedAlgorithmInt, [Alg]);
end;

constructor TElDSAPublicKeyCrypto.Create(Manager: TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  Create(SB_OID_DSA, Manager, CryptoProvider);
  FHashAlg := SB_ALGORITHM_DGST_SHA1;
end;


 // SB_JAVA}

procedure TElDSAPublicKeyCrypto.AdjustContextProps(Params : TElCPParameters);
begin
  inherited;
  Params.Add(SB_CTXPROP_HASH_ALGORITHM, GetOIDByAlgorithm(HashAlgorithm));
end;

 destructor  TElDSAPublicKeyCrypto.Destroy;
begin
  inherited;
end;

////////////////////////////////////////////////////////////////////////////////
// TElECKeyMaterial class

{$ifdef SB_HAS_ECC}
function TElECKeyMaterial.GetValid : boolean;
begin
  Result := FKey.IsValid;
end;

function TElECKeyMaterial.GetBits : integer;
begin
  Result := FKey.Bits;
end;

function TElECKeyMaterial.GetFieldBits : integer;
begin
  Result := GetIntegerPropFromBuffer(FKey.GetKeyProp(SB_KEYPROP_EC_FIELD_BITS));
end;

function TElECKeyMaterial.GetHashAlgorithm : integer;
begin
  Result := GetAlgorithmByOID(FKey.GetKeyProp(SB_KEYPROP_HASH_ALGORITHM));
end;

function TElECKeyMaterial.GetRecommendedHashAlgorithm : integer;
var
  n : integer;
  NParam : ByteArray;
begin
  NParam := Self.N;
  if Length(NParam) > 0 then
    n := BufferBitCount( @NParam[0] , Length(NParam))
  else
  begin
    Result := SB_ALGORITHM_UNKNOWN;
    Exit;
  end;

  if (n < 224) then
    Result := SB_ALGORITHM_DGST_SHA1
  else if (n < 256) then
    Result := SB_ALGORITHM_DGST_SHA224
  else if (n < 384) then
    Result := SB_ALGORITHM_DGST_SHA256
  else if (n < 512) then
    Result := SB_ALGORITHM_DGST_SHA384
  else
    Result := SB_ALGORITHM_DGST_SHA512;
end;

procedure TElECKeyMaterial.SetHashAlgorithm(Value : integer);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_HASH_ALGORITHM, GetOIDByHashAlgorithm(Value));
end;

function TElECKeyMaterial.GetA : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_EC_A);
end;

procedure TElECKeyMaterial.SetA(const Value : ByteArray);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_EC_A, Value);
end;

function TElECKeyMaterial.GetB : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_EC_B);
end;

procedure TElECKeyMaterial.SetB(const Value : ByteArray);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_EC_B, Value);
end;

function TElECKeyMaterial.GetP : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_EC_P);
end;

procedure TElECKeyMaterial.SetP(const Value : ByteArray);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_EC_FIELD_TYPE_INT, GetBufferFromInteger(SB_EC_FLD_TYPE_FP));

  FKey.SetKeyProp(SB_KEYPROP_EC_P, Value);
end;

function TElECKeyMaterial.GetN : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_EC_N);
end;

procedure TElECKeyMaterial.SetN(const Value : ByteArray);
begin
  if FBusy then Exit;
  FKey.SetKeyProp(SB_KEYPROP_EC_N, Value);
end;

function TElECKeyMaterial.GetSeed : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_EC_SEED);
end;

procedure TElECKeyMaterial.SetSeed(const Value : ByteArray);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_EC_SEED, Value);
end;

function TElECKeyMaterial.GetH : integer;
begin
  Result := GetIntegerPropFromBuffer(FKey.GetKeyProp(SB_KEYPROP_EC_H));
end;

procedure TElECKeyMaterial.SetH(Value : integer);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_EC_H, GetBufferFromInteger(Value));
end;

function TElECKeyMaterial.GetFieldType : integer;
begin
  Result := GetIntegerPropFromBuffer(FKey.GetKeyProp(SB_KEYPROP_EC_FIELD_TYPE_INT));
end;

procedure TElECKeyMaterial.SetFieldType(Value : integer);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_EC_FIELD_TYPE_INT, GetBufferFromInteger(Value));
end;

function TElECKeyMaterial.GetM : integer;
begin
  Result := GetIntegerPropFromBuffer(FKey.GetKeyProp(SB_KEYPROP_EC_M));
end;

procedure TElECKeyMaterial.SetM(Value : integer);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_EC_M, GetBufferFromInteger(Value));
end;

function TElECKeyMaterial.GetK1 : integer;
begin
  Result := GetIntegerPropFromBuffer(FKey.GetKeyProp(SB_KEYPROP_EC_K1));
end;

procedure TElECKeyMaterial.SetK1(Value : integer);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_EC_K1, GetBufferFromInteger(Value));
end;

function TElECKeyMaterial.GetK2 : integer;
begin
  Result := GetIntegerPropFromBuffer(FKey.GetKeyProp(SB_KEYPROP_EC_K2));
end;

procedure TElECKeyMaterial.SetK2(Value : integer);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_EC_K2, GetBufferFromInteger(Value));
end;

function TElECKeyMaterial.GetK3 : integer;
begin
  Result := GetIntegerPropFromBuffer(FKey.GetKeyProp(SB_KEYPROP_EC_K3));
end;

procedure TElECKeyMaterial.SetK3(Value : integer);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_EC_K3, GetBufferFromInteger(Value));
end;

function TElECKeyMaterial.GetX : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_EC_X);
end;

function TElECKeyMaterial.GetQX : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_EC_QX);
end;

function TElECKeyMaterial.GetQ : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_EC_Q);
end;

function TElECKeyMaterial.GetD : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_EC_D);
end;

function TElECKeyMaterial.GetCompressPoints : boolean;
begin
  Result := GetBoolFromBuffer(FKey.GetKeyProp(SB_KEYPROP_EC_COMPRESS_POINTS));
end;

procedure TElECKeyMaterial.SetCompressPoints(Value : boolean);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_EC_COMPRESS_POINTS, GetBufferFromBool(Value));
end;

function TElECKeyMaterial.GetHybridPoints : boolean;
begin
  Result := GetBoolFromBuffer(FKey.GetKeyProp(SB_KEYPROP_EC_HYBRID_POINTS));
end;

procedure TElECKeyMaterial.SetHybridPoints(Value : boolean);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_EC_HYBRID_POINTS, GetBufferFromBool(Value));
end;

procedure TElECKeyMaterial.SetX(const Value : ByteArray);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_EC_X, Value);
end;

procedure TElECKeyMaterial.SetQX(const Value : ByteArray);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_EC_QX, Value);
end;

procedure TElECKeyMaterial.SetQ(const Value : ByteArray);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_EC_Q, Value);
end;

procedure TElECKeyMaterial.SetD(const Value : ByteArray);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_EC_D, Value);
end;

function TElECKeyMaterial.GetY : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_EC_Y);
end;

function TElECKeyMaterial.GetQY : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_EC_QY);
end;

procedure TElECKeyMaterial.SetY(const Value : ByteArray);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_EC_Y, Value);
end;

procedure TElECKeyMaterial.SetQY(const Value : ByteArray);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_EC_QY, Value);
end;

function TElECKeyMaterial.GetBase : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_EC_BP);
end;

procedure TElECKeyMaterial.SetBase(const Value : ByteArray);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_EC_BP, Value);
end;

function TElECKeyMaterial.GetCurve : integer;
begin
  Result := GetIntegerPropFromBuffer(FKey.GetKeyProp(SB_KEYPROP_EC_CURVE_INT));
end;

procedure TElECKeyMaterial.SetCurve(Value : integer);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_EC_CURVE_INT, GetBufferFromInteger(Value));
end;

function TElECKeyMaterial.GetCurveOID : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_EC_CURVE);
end;

procedure TElECKeyMaterial.SetCurveOID(const Value : ByteArray);
begin
  if FBusy then Exit;

  FKey.SetKeyProp(SB_KEYPROP_EC_CURVE, Value);
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElECKeyMaterial.InternalGenerate(Bits : integer);
begin
  FKey.Generate(0);
end;
 {$endif}

 destructor  TElECKeyMaterial.Destroy;
begin
  inherited;
end;

constructor TElECKeyMaterial.Create(Prov : TElCustomCryptoProvider  = nil );
begin
  inherited;

  FKey := FProvider.CreateKey(SB_ALGORITHM_PK_EC, 0, nil);
  FSpecifiedCurve := false;
  FImplicitCurve := false;
end;

constructor TElECKeyMaterial.Create(Manager: TElCustomCryptoProviderManager;
  Prov : TElCustomCryptoProvider);
begin
  inherited;

  FKey := FProvider.CreateKey(SB_ALGORITHM_PK_EC, 0, nil);
  FSpecifiedCurve := false;
  FImplicitCurve := false;
end;


procedure TElECKeyMaterial.Assign(Source : TElKeyMaterial);
begin
  if not (Source is TElECKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SInvalidKeyMaterialType);

  FProvider.ReleaseKey(FKey);
  FKey := TElECKeyMaterial(Source).FKey.CryptoProvider.CloneKey(TElECKeyMaterial(Source).FKey);
  FSpecifiedCurve := TElECKeyMaterial(Source).SpecifiedCurve;
  FImplicitCurve := TElECKeyMaterial(Source).ImplicitCurve;
  FProvider := TElECKeyMaterial(Source).FProvider;
  FProviderManager := TElECKeyMaterial(Source).FProviderManager;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElECKeyMaterial.Generate;
begin
  if FBusy then Exit;

  InternalGenerate(0);
end;
 {$endif}

procedure TElECKeyMaterial.LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
var
  AlgID : TElECAlgorithmIdentifier;
begin
  if AlgorithmIdentifier is TElECAlgorithmIdentifier then
  begin
    AlgID := TElECAlgorithmIdentifier(AlgorithmIdentifier);

    ImplicitCurve := false;
    SpecifiedCurve := false;
    HashAlgorithm := AlgID.HashAlgorithm;

    if AlgID.ImplicitCurve then
    begin
      ImplicitCurve := true;
      Exit;
    end
    else if AlgID.SpecifiedCurve then
    begin
      SpecifiedCurve := true;
      CompressPoints := AlgID.CompressPoints;
      HybridPoints := AlgID.HybridPoints;
      FieldType := AlgID.FieldType;

      if AlgID.FieldType = SB_EC_FLD_TYPE_FP then
        P := AlgID.P
      else if AlgID.FieldType = SB_EC_FLD_TYPE_F2MP then
      begin
        M := AlgID.M;
        K1 := AlgID.K1;
        K2 := AlgID.K2;
        K3 := AlgID.K3;
      end
      else
        raise EElPublicKeyCryptoError.Create(SInvalidKeyParameters);

      N := AlgID.N;
      H := AlgID.H;
      A := AlgID.A;
      B := AlgID.B;
      Base := AlgID.Base;
      Seed := AlgID.Seed;
    end
    else // named curve
      CurveOID := AlgID.Curve;
  end
  {$ifdef SB_HAS_GOST}
  else if AlgorithmIdentifier.Algorithm = SB_CERT_ALGORITHM_GOST_R3410_2001 then
  begin
    CurveOID := TElGOST3410AlgorithmIdentifier(AlgorithmIdentifier).PublicKeyParamSet;
  end
   {$endif}
  else
    raise EElPublicKeyCryptoError.Create(SInvalidKeyParameters);
end;

procedure TElECKeyMaterial.SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
var
  AlgID : TElECAlgorithmIdentifier;
begin
  if AlgorithmIdentifier is TElECDSAAlgorithmIdentifier then
  begin
    if AlgorithmIdentifier.Algorithm = SB_CERT_ALGORITHM_RECOMMENDED_ECDSA then
      TElECDSAAlgorithmIdentifier(AlgorithmIdentifier).HashAlgorithm := RecommendedHashAlgorithm;
  end
  else if (AlgorithmIdentifier is TElECAlgorithmIdentifier) then
  begin
    AlgID := TElECAlgorithmIdentifier(AlgorithmIdentifier);

    { filling up all the fields anyway }
    AlgID.CompressPoints := CompressPoints;
    AlgID.HybridPoints := HybridPoints;
    AlgID.FieldType := FieldType;

    if FieldType = SB_EC_FLD_TYPE_FP then
      AlgID.P := P
    else if FieldType = SB_EC_FLD_TYPE_F2MP then
    begin
      AlgID.M := M;
      AlgID.K1 := K1;
      AlgID.K2 := K2;
      AlgID.K3 := K3;
    end
    else
      raise EElPublicKeyCryptoError.Create(SInvalidKeyParameters);

    AlgID.Curve := CurveOID;
    AlgID.Base := Base;
    AlgID.X := X;
    AlgID.Y := Y;
    AlgID.A := A;
    AlgID.B := B;
    AlgID.N := N;
    AlgID.H := H;
    AlgID.Seed := Seed;

    if ImplicitCurve then
    begin
      AlgID.ImplicitCurve := true;
      AlgID.SpecifiedCurve := false;
    end
    else if SpecifiedCurve then
    begin
      AlgID.SpecifiedCurve := true;
      AlgID.ImplicitCurve := false;
    end
    else
    begin
      AlgID.ImplicitCurve := false;
      AlgID.SpecifiedCurve := false;
    end;

    AlgID.HashAlgorithm := HashAlgorithm;
  end
  else
    raise EElPublicKeyCryptoError.Create(SInvalidKeyParameters);
end;

procedure TElECKeyMaterial.LoadSecret(Buffer: pointer; Size: integer);
begin
  FKey.ImportSecret(Buffer, Size);
end;

procedure TElECKeyMaterial.SaveSecret(Buffer: pointer; var Size: integer);
begin
  FKey.ExportSecret(Buffer, Size);
end;

procedure TElECKeyMaterial.LoadPublic(Buffer: pointer; Size: integer);
begin
  FKey.ImportPublic(Buffer, Size);
end;

procedure TElECKeyMaterial.SavePublic(Buffer: pointer; var Size: integer);
begin
  FKey.ExportPublic(Buffer, Size);
end;

procedure TElECKeyMaterial.ImportPublicKey(QX : pointer; QXSize : integer; QY : pointer; QYSize : integer);
var
  BufQX, BufQY : ByteArray;
begin
  SetLength(BufQX, QXSize);
  SetLength(BufQY, QYSize);
  SBMove(QX^, BufQX[0], QXSize);
  SBMove(QY^, BufQY[0], QYSize);
  FKey.SetKeyProp(SB_KEYPROP_EC_QX, BufQX);
  FKey.SetKeyProp(SB_KEYPROP_EC_QY, BufQY);
  ReleaseArrays(BufQX, BufQY);
end;

procedure TElECKeyMaterial.ExportPublicKey(QX : pointer; var QXSize : integer; QY : pointer; var QYSize : integer);
var
  BufQX, BufQY : ByteArray;
begin
  BufQX := FKey.GetKeyProp(SB_KEYPROP_EC_QX);
  BufQY := FKey.GetKeyProp(SB_KEYPROP_EC_QY);

  if (Length(BufQX) > QXSize) or (Length(BufQY) > QYSize) then
  begin
    QXSize := Length(BufQX);
    QYSize := Length(BufQY);
    Exit;
  end;

  QXSize := Length(BufQX);
  QYSize := Length(BufQY);

  SBMove(BufQX[0], QX^, QXSize);
  SBMove(BufQY[0], QY^, QYSize);

  ReleaseArrays(BufQX, BufQY);
end;

function TElECKeyMaterial.Clone :  TElKeyMaterial ;
var
  Res : TElKeyMaterial;
begin
  Res := TElECKeyMaterial.Create(FProvider);
  Res.Assign(Self);
  Result := Res;
end;

function TElECKeyMaterial.Equals(Source : TElKeyMaterial; PublicOnly : boolean): boolean;
var
  B, B1: ByteArray;
begin
  Result := false;

  SetLength(B, 0);
  SetLength(B1, 0);
  if not (Source is TElECKeyMaterial) then exit;
  if (Self.Key.IsPublic <> Source.Key.IsPublic) then exit;
  if (Self.Key.IsSecret and Source.Key.IsSecret) and (not PublicOnly) then
  begin
    Result := Self.Key.Equals(Source.Key, true, nil);
    Exit;
  end;

  if (Length(CurveOID) > 0) then
    Result := CompareContent(CurveOID, TElECKeyMaterial(Source).CurveOID)
  else
  begin
    { comparing domain parameters }
    Result := FieldType = TElECKeyMaterial(Source).FieldType;

    if FieldType = SB_EC_FLD_TYPE_FP then
    begin
      B := TElECKeyMaterial(Source).P;
      B1 := Self.P;
      Result := Result and (Length(B) = Length(B1)) and
         (CompareMem(@B1[0], @B[0], Length(B1)))
         ;
    end
    else
    begin
      Result := Result and (M = TElECKeyMaterial(Source).M);
      Result := Result and (K1 = TElECKeyMaterial(Source).K1);
      if K2 > 0 then
      begin
        Result := Result and (K2 = TElECKeyMaterial(Source).K2);
        Result := Result and (K3 = TElECKeyMaterial(Source).K3);
      end;
    end;

    B := TElECKeyMaterial(Source).A;
    B1 := Self.A;
    Result := Result and (Length(B) = Length(B1)) and
       (CompareMem(@B1[0], @B[0], Length(B1)))
       ;
    B := TElECKeyMaterial(Source).B;
    B1 := Self.B;
    Result := Result and (Length(B) = Length(B1)) and
       (CompareMem(@B1[0], @B[0], Length(B1)))
       ;
    B := TElECKeyMaterial(Source).N;
    B1 := Self.N;
    Result := Result and (Length(B) = Length(B1)) and
       (CompareMem(@B1[0], @B[0], Length(B1)))
       ;
    B := TElECKeyMaterial(Source).X;
    B1 := Self.X;
    Result := Result and (Length(B) = Length(B1)) and
       (CompareMem(@B1[0], @B[0], Length(B1)))
       ;
    B := TElECKeyMaterial(Source).Y;
    B1 := Self.Y;
    Result := Result and (Length(B) = Length(B1)) and
       (CompareMem(@B1[0], @B[0], Length(B1)))
       ;

    Result := Result and (H = TElECKeyMaterial(Source).H);
  end;

  B := TElECKeyMaterial(Source).QX;
  B1 := Self.QX;
  Result := Result and (Length(B) = Length(B1)) and
     (CompareMem(@B1[0], @B[0], Length(B1)))
     ;

  B := TElECKeyMaterial(Source).QY;
  B1 := Self.QY;
  Result := Result and (Length(B) = Length(B1)) and
     (CompareMem(@B1[0], @B[0], Length(B1)))
     ;

  ReleaseArrays(B, B1);

  // no secret key comparision - 'cause for different secret keys public also differs  
end;

procedure TElECKeyMaterial.ClearSecret;
begin
  FKey.ClearSecret;
end;

procedure TElECKeyMaterial.ClearPublic;
begin
  FKey.ClearPublic;
end;

////////////////////////////////////////////////////////////////////////////////
// TElECDSAPublicKeyCrypto class

function TElECDSAPublicKeyCrypto.GetSupportsEncryption: boolean;
begin
  Result := false;
end;

function TElECDSAPublicKeyCrypto.GetSupportsSigning: boolean;
begin
  Result := true;
end;

procedure TElECDSAPublicKeyCrypto.SetKeyMaterial(Material : TElPublicKeyMaterial);
begin
  if FBusy then Exit;

  if not (Material is TElECKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial)
  else
    FKeyMaterial := Material;
end;

procedure TElECDSAPublicKeyCrypto.LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  if AlgorithmIdentifier is TElECDSAAlgorithmIdentifier then
  begin
    HashAlgorithm := TElECDSAAlgorithmIdentifier(AlgorithmIdentifier).HashAlgorithm;
  end
  else
    raise EElPublicKeyCryptoError.Create(SInvalidAlgorithmIdentifier);
end;

procedure TElECDSAPublicKeyCrypto.SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  if AlgorithmIdentifier is TElECDSAAlgorithmIdentifier then
  begin
    TElECDSAAlgorithmIdentifier(AlgorithmIdentifier).HashAlgorithm := HashAlgorithm;
  end
  else
    raise EElPublicKeyCryptoError.Create(SInvalidAlgorithmIdentifier);
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElECDSAPublicKeyCrypto.SignInit(Detached: boolean);
var
  Params : TElCPParameters;
begin
  if not (FKeyMaterial is TElECKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);

  if not FKeyMaterial.SecretKey then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
    
  SetLength(FSpool, 0);
  Params := TElCPParameters.Create();
  try
    AdjustContextProps(Params);
    FContext := GetSuitableCryptoProvider(pkoSignDetached, SB_ALGORITHM_PK_ECDSA, Params).SignInit(SB_ALGORITHM_PK_ECDSA, FKeyMaterial.FKey, Detached,
      Params);
  finally
    FreeAndNil(Params);
  end;
end;

procedure TElECDSAPublicKeyCrypto.SignUpdate( Buffer: pointer;
    Size: integer);
var
  OldLen, OutSize : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.SignUpdate(FContext, Buffer, Size, nil, OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.SignUpdate(FContext, Buffer, Size, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
end;

procedure TElECDSAPublicKeyCrypto.SignFinal;
var
  SigSize, OldLen : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  SigSize := 0;
  Prov.SignFinal(FContext, nil, SigSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + SigSize);
  Prov.SignFinal(FContext, @FSpool[OldLen], SigSize);
  SetLength(FSpool, OldLen + SigSize);
  WriteToOutput(@FSpool[0], Length(FSpool));
  FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;
 {$endif}

procedure TElECDSAPublicKeyCrypto.VerifyInit(Detached: boolean;  Signature: pointer;
    SigSize: integer);
var
  Params : TElCPParameters;
begin
  if not (FKeyMaterial is TElECKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  if not FKeyMaterial.PublicKey then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
    
  SetLength(FSpool, 0);
  Params := TElCPParameters.Create();
  try
    AdjustContextProps(Params);
    FContext := GetSuitableCryptoProvider(pkoVerifyDetached, SB_ALGORITHM_PK_ECDSA, Params).VerifyInit(SB_ALGORITHM_PK_ECDSA, FKeyMaterial.FKey,
      Signature, SigSize, Params);
  finally
    FreeAndNil(Params);
  end;
end;

procedure TElECDSAPublicKeyCrypto.VerifyUpdate( Buffer: pointer;
    Size: integer);
var
  OutSize, OldLen : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.VerifyUpdate(FContext, Buffer, Size, nil, OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.VerifyUpdate(FContext, Buffer, Size, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
end;

function TElECDSAPublicKeyCrypto.VerifyFinal : TSBPublicKeyVerificationResult;
var
  R : integer;
  OutSize, OldLen : integer;
  Prov : TElCustomCryptoProvider;
  //ProgressFunc : TSBProgressFunc;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.VerifyFinal(FContext,  nil , OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  R := Prov.VerifyFinal(FContext, @FSpool[OldLen], OutSize);
  case R of
    SB_VR_SUCCESS :
      Result := pkvrSuccess;
    SB_VR_INVALID_SIGNATURE :
      Result := pkvrInvalidSignature;
    SB_VR_KEY_NOT_FOUND :
      Result := pkvrKeyNotFound;
    else
      Result := pkvrFailure;
  end;
  SetLength(FSpool, OldLen + OutSize);
  WriteToOutput(@FSpool[0], Length(FSpool));
  FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;

function TElECDSAPublicKeyCrypto.EstimateOutputSize( InBuffer: pointer;
    InSize: integer;
  Operation : TSBPublicKeyOperation): integer;
begin
  if (Operation in [pkoEncrypt, pkoDecrypt,
    pkoSign, pkoVerify]) then
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);

  if not (KeyMaterial is TElECKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SInvalidKeyMaterialType);
  if (Operation = pkoSignDetached) and
     (not FKeyMaterial.SecretKey) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);

  if Operation = pkoSignDetached then
  begin
    // in some cases the value of N is unknown
    Result := Length(TElECKeyMaterial(FKeyMaterial).N) shl 1 + 16;
    if Result = 16 then
      Result := 8192;
  end
  else
    Result := 0;
end;

class function TElECDSAPublicKeyCrypto.IsAlgorithmSupported(Alg: integer): boolean;
begin
  Result := (Alg in [SB_CERT_ALGORITHM_SHA1_ECDSA, SB_CERT_ALGORITHM_RECOMMENDED_ECDSA,
    SB_CERT_ALGORITHM_SHA224_ECDSA, SB_CERT_ALGORITHM_SHA256_ECDSA,
    SB_CERT_ALGORITHM_SHA384_ECDSA, SB_CERT_ALGORITHM_SHA512_ECDSA,
    SB_CERT_ALGORITHM_SPECIFIED_ECDSA,
    SB_CERT_ALGORITHM_SHA1_ECDSA_PLAIN, SB_CERT_ALGORITHM_SHA224_ECDSA_PLAIN,
    SB_CERT_ALGORITHM_SHA256_ECDSA_PLAIN, SB_CERT_ALGORITHM_SHA384_ECDSA_PLAIN,
    SB_CERT_ALGORITHM_SHA512_ECDSA_PLAIN, SB_CERT_ALGORITHM_RIPEMD160_ECDSA_PLAIN
    ]);
end;

class function TElECDSAPublicKeyCrypto.IsAlgorithmSupported(const OID: ByteArray): boolean;
begin
  Result := CompareContent(OID, SB_OID_ECDSA_SHA1) or
    CompareContent(OID, SB_OID_ECDSA_RECOMMENDED) or
    CompareContent(OID, SB_OID_ECDSA_SHA224) or
    CompareContent(OID, SB_OID_ECDSA_SHA256) or
    CompareContent(OID, SB_OID_ECDSA_SHA384) or
    CompareContent(OID, SB_OID_ECDSA_SHA512) or
    CompareContent(OID, SB_OID_ECDSA_SPECIFIED) or
    CompareContent(OID, SB_OID_EC_KEY) or
    CompareContent(OID, SB_OID_ECDSA_PLAIN_SHA1) or
    CompareContent(OID, SB_OID_ECDSA_PLAIN_SHA224) or
    CompareContent(OID, SB_OID_ECDSA_PLAIN_SHA256) or
    CompareContent(OID, SB_OID_ECDSA_PLAIN_SHA384) or
    CompareContent(OID, SB_OID_ECDSA_PLAIN_SHA512) or
    CompareContent(OID, SB_OID_ECDSA_PLAIN_RIPEMD160);
end;

class function TElECDSAPublicKeyCrypto.GetName() : string;
begin
  Result := 'ECDSA';
end;

class function TElECDSAPublicKeyCrypto.GetDescription() : string;
begin
  Result := 'Implements ECDSA signing functionality';
end;

procedure TElECDSAPublicKeyCrypto.Reset;
begin
  FInputIsHash := false;
  FInputEncoding := pkeBinary;
  FOutputEncoding := pkeBinary;
end;

procedure TElECDSAPublicKeyCrypto.AdjustContextProps(Params : TElCPParameters);
begin
  inherited;

  if CompareContent(FOID, SB_OID_ECDSA_RECOMMENDED) and (Assigned(FKeyMaterial)) then
    FHashAlg := TElECKeyMaterial(FKeyMaterial).RecommendedHashAlgorithm;

  if CompareContent(FOID, SB_OID_ECDSA_PLAIN_SHA1) or
    CompareContent(FOID, SB_OID_ECDSA_PLAIN_SHA224) or
    CompareContent(FOID, SB_OID_ECDSA_PLAIN_SHA256) or
    CompareContent(FOID, SB_OID_ECDSA_PLAIN_SHA384) or
    CompareContent(FOID, SB_OID_ECDSA_PLAIN_SHA512) or
    CompareContent(FOID, SB_OID_ECDSA_PLAIN_RIPEMD160)
  then
    Params.Add(SB_CTXPROP_EC_PLAIN_ECDSA, GetBufferFromBool(true))
  else
    Params.Add(SB_CTXPROP_EC_PLAIN_ECDSA, GetBufferFromBool(false));

  Params.Add(SB_CTXPROP_HASH_ALGORITHM, GetOIDByAlgorithm(FHashAlg));
end;

 destructor  TElECDSAPublicKeyCrypto.Destroy;
begin
  inherited;
end;

constructor TElECDSAPublicKeyCrypto.Create(const OID : ByteArray;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
   Create (OID, nil, CryptoProvider);
  (*
  inherited Create(CryptoProvider);

  if not IsAlgorithmSupported(OID) then
  {$ifdef SB_VCL}
    raise EElPublicKeyCryptoError.CreateFmt(SUnsupportedAlgorithm, [OIDToStr(OID)]);
  {$else}
    raise EElPublicKeyCryptoError.Create(System.String.Format(SUnsupportedAlgorithm, [OIDToStr(OID)]));
  {$endif}

  FOID := OID;
  FHashAlg := GetHashAlgorithmBySigAlgorithm(GetSigAlgorithmByOID(OID));
  *)
end;
  
constructor TElECDSAPublicKeyCrypto.Create(Alg : integer;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
//var
//  OID : ByteArray;
begin
   Create (Alg, nil, CryptoProvider);
  (*
  OID := GetOIDByPKAlgorithm(Alg);
  if Length(OID) = 0 then
    OID := GetOIDBySigAlgorithm(Alg);

  Create(OID, CryptoProvider);
  *)
end;
  
constructor TElECDSAPublicKeyCrypto.Create(CryptoProvider : TElCustomCryptoProvider  = nil );
begin
   Create (SB_OID_ECDSA_SHA1, CryptoProvider);
end;

constructor TElECDSAPublicKeyCrypto.Create(const OID : ByteArray; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create(Manager, CryptoProvider);
  if not IsAlgorithmSupported(OID) then
    raise EElPublicKeyCryptoError.CreateFmt(SUnsupportedAlgorithm, [OIDToStr(OID)]);

  FOID := OID;
  FHashAlg := GetHashAlgorithmBySigAlgorithm(GetSigAlgorithmByOID(OID));
end;

constructor TElECDSAPublicKeyCrypto.Create(Alg : integer; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
var
  OID : ByteArray;
begin
  OID := GetOIDByPKAlgorithm(Alg);
  if Length(OID) = 0 then
    OID := GetOIDBySigAlgorithm(Alg);

  Create(OID, Manager, CryptoProvider);
end;

constructor TElECDSAPublicKeyCrypto.Create(Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
   Create (SB_OID_ECDSA_SHA1, Manager, CryptoProvider);
end;


 // SB_JAVA

procedure TElECDSAPublicKeyCrypto.EncodeSignature(R : pointer; RSize : integer; S : pointer; SSize : integer;
  Sig : pointer; var SigSize : integer);
begin
  SBDSA.EncodeSignature(R, RSize, S, SSize, Sig, SigSize);
end;

procedure TElECDSAPublicKeyCrypto.DecodeSignature(Sig : pointer; SigSize : integer; R : pointer;
  var RSize : integer; S : pointer; var SSize : integer);
begin
  SBDSA.DecodeSignature(Sig, SigSize, R, RSize, S, SSize);
end;

////////////////////////////////////////////////////////////////////////////////
// TElECDHPublicKeyCrypto class

constructor TElECDHPublicKeyCrypto.Create(CryptoProvider : TElCustomCryptoProvider  = nil );
begin
  inherited Create(CryptoProvider);
end;

constructor TElECDHPublicKeyCrypto.Create(const OID : ByteArray; CryptoProvider :
  TElCustomCryptoProvider  =  nil);
var
  Manager : TElCustomCryptoProviderManager;
begin
  Manager := nil;
  Create(Manager, CryptoProvider);
end;

constructor TElECDHPublicKeyCrypto.Create(Alg : integer; CryptoProvider : TElCustomCryptoProvider  =  nil);
var
  Manager : TElCustomCryptoProviderManager;
begin
  Manager := nil;
  Create(Manager, CryptoProvider);
end;

constructor TElECDHPublicKeyCrypto.Create(const OID : ByteArray;
  Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
   Create (Manager, CryptoProvider);
end;

constructor TElECDHPublicKeyCrypto.Create(Alg : integer;
  Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
   Create (Manager, CryptoProvider);
end;

constructor TElECDHPublicKeyCrypto.Create(Manager: TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create(Manager, CryptoProvider);
end;


 // SB_JAVA

 destructor  TElECDHPublicKeyCrypto.Destroy;
begin
  inherited;
end;

procedure TElECDHPublicKeyCrypto.LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  if AlgorithmIdentifier is TElECAlgorithmIdentifier then
  begin
    ;
  end
  else
    raise EElPublicKeyCryptoError.Create(SInvalidAlgorithmIdentifier);
end;

procedure TElECDHPublicKeyCrypto.SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  if AlgorithmIdentifier is TElECAlgorithmIdentifier then
  begin
    ;
  end
  else
    raise EElPublicKeyCryptoError.Create(SInvalidAlgorithmIdentifier);
end;

function TElECDHPublicKeyCrypto.GetSupportsEncryption: boolean;
begin
  Result := true; // emulating key exchange via encryption
end;

function TElECDHPublicKeyCrypto.GetSupportsSigning: boolean;
begin
  Result := false;
end;

procedure TElECDHPublicKeyCrypto.SetKeyMaterial(Material : TElPublicKeyMaterial);
begin
  if FBusy then Exit;

  if not (Material is TElECKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  FKeyMaterial := Material;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElECDHPublicKeyCrypto.EncryptInit;
var
  Params : TElCPParameters;
begin
  if not Assigned(FKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  if not FKeyMaterial.PublicKey then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  SetLength(FSpool, 0);
  Params := TElCPParameters.Create();
  try
    AdjustContextProps(Params);
    FContext := GetSuitableCryptoProvider(pkoEncrypt, SB_ALGORITHM_PK_ECDH, Params).EncryptInit(
      SB_ALGORITHM_PK_ECDH, 0, FKeyMaterial.FKey, Params
    );
  finally
    FreeAndNil(Params);
  end;
end;

procedure TElECDHPublicKeyCrypto.EncryptUpdate( Buffer: pointer;
    Size: integer);
var
  OldLen, OutSize: integer;
  Prov : TElCustomCryptoProvider;
begin
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.EncryptUpdate(FContext, Buffer, Size, nil, OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.EncryptUpdate(FContext, Buffer, Size, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
end;

procedure TElECDHPublicKeyCrypto.EncryptFinal;
var
  OutSize, OldLen : integer;
  Prov : TElCustomCryptoProvider;
begin
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.EncryptFinal(FContext,  nil , OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OutSize + OldLen);
  Prov.EncryptFinal(FContext, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OutSize + OldLen);
  WriteToOutput(@FSpool[0], Length(FSpool));
  FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;
 {$endif}

procedure TElECDHPublicKeyCrypto.DecryptInit;
var
  Params : TElCPParameters;
begin
  if not Assigned(FKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  {if not FKeyMaterial.SecretKey then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);}
  SetLength(FSpool, 0);
  Params := TElCPParameters.Create();
  try
    AdjustContextProps(Params);
    FContext := GetSuitableCryptoProvider(pkoDecrypt, SB_ALGORITHM_PK_ECDH, Params).DecryptInit(
      SB_ALGORITHM_PK_ECDH, 0, FKeyMaterial.FKey, Params
    );
  finally
    FreeAndNil(Params);
  end;
end;

procedure TElECDHPublicKeyCrypto.DecryptUpdate( Buffer: pointer;
    Size: integer);
var
  OldLen, OutSize: integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider;
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.DecryptUpdate(FContext, Buffer, Size, nil, OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.DecryptUpdate(FContext, Buffer, Size, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
end;

procedure TElECDHPublicKeyCrypto.DecryptFinal;
var
  OutSize, OldLen : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.DecryptFinal(FContext,  nil , OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.DecryptFinal(FContext, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
  WriteToOutput(@FSpool[0], Length(FSpool));
  FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;

function TElECDHPublicKeyCrypto.EstimateOutputSize( InBuffer: pointer;
    InSize: integer;
  Operation : TSBPublicKeyOperation): integer;
var
  FLen : integer;
begin
  if (Operation in [pkoVerify,
    pkoSign]) then
    raise EElPublicKeyCryptoError.Create(SNotASigningAlgorithm);
  if not (KeyMaterial is TElECKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);

  FLen := TElECKeyMaterial(FKeyMaterial).FieldBits;
  FLen := (FLen + 7) shr 3;
  if Operation = pkoEncrypt then
    Result := FLen shl 1 + 1
  else
    Result := FLen;
end;

class function TElECDHPublicKeyCrypto.IsAlgorithmSupported(Alg: integer): boolean;
begin
  Result := Alg = SB_ALGORITHM_PK_ECDH;
end;

class function TElECDHPublicKeyCrypto.IsAlgorithmSupported(const OID: ByteArray): boolean;
begin
  Result := false;
end;

class function TElECDHPublicKeyCrypto.GetName() : string;
begin
  Result := 'ECDH';
end;

class function TElECDHPublicKeyCrypto.GetDescription() : string;
begin
  Result := 'Implements base ECDH key exchange functionality';
end;

 {$endif} //SB_HAS_ECC

////////////////////////////////////////////////////////////////////////////////
// TElDHKeyMaterial class

{$ifndef SB_NO_DH}
constructor TElDHKeyMaterial.Create(Prov : TElCustomCryptoProvider  = nil );
begin
  inherited;
  FKey := FProvider.CreateKey(SB_ALGORITHM_PK_DH, 0);
  Reset;
end;

constructor TElDHKeyMaterial.Create(Manager : TElCustomCryptoProviderManager; Prov : TElCustomCryptoProvider);
begin
  inherited;
  FKey := FProvider.CreateKey(SB_ALGORITHM_PK_DH, 0);
  Reset;
end;


 destructor  TElDHKeyMaterial.Destroy;
begin
  inherited;
end;

procedure TElDHKeyMaterial.Reset;
begin
  FKeyFormat := dhRaw;
  FStoreFormat := ksfRaw;
end;

function TElDHKeyMaterial.GetValid : boolean;
begin
  Result := true;
end;

function TElDHKeyMaterial.GetBits : integer;
begin
  Result := FKey.Bits;
end;

function TElDHKeyMaterial.GetP : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_DH_P);
end;

function TElDHKeyMaterial.GetG : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_DH_G);
end;

function TElDHKeyMaterial.GetX : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_DH_X);
end;

function TElDHKeyMaterial.GetY : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_DH_Y);
end;

function TElDHKeyMaterial.GetPeerY : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_DH_PEER_Y);
end;

procedure TElDHKeyMaterial.SetP(const Value : ByteArray);
begin
  FKey.SetKeyProp(SB_KEYPROP_DH_P, Value);
end;

procedure TElDHKeyMaterial.SetG(const Value : ByteArray);
begin
  FKey.SetKeyProp(SB_KEYPROP_DH_G, Value);
end;

procedure TElDHKeyMaterial.SetX(const Value : ByteArray);
begin
  FKey.SetKeyProp(SB_KEYPROP_DH_X, Value);
end;

procedure TElDHKeyMaterial.SetY(const Value : ByteArray);
begin
  FKey.SetKeyProp(SB_KEYPROP_DH_Y, Value);
end;

procedure TElDHKeyMaterial.SetPeerY(const Value : ByteArray);
begin
  FKey.SetKeyProp(SB_KEYPROP_DH_PEER_Y, Value);
end;                                  

procedure TElDHKeyMaterial.LoadFromXML(const Str: string);
var
  v: TXMLParamValues;
begin
  Clear;
  v := ParseXmlString(Str, 'DHKeyValue', ['P', 'G', 'Y', 'X', 'Generator', 'Public']);
  if Length(v) <> 6 then
    raise EElPublicKeyCryptoError.Create(SInvalidXML);

  // Generator -> G
  if Length(v[1]) = 0 then
    v[1] := v[4];

  // Public -> Y
  if Length(v[2]) = 0 then
    v[2] := v[5];

  if (Length(v[0]) = 0) or (Length(v[1]) = 0) or (Length(v[2]) = 0) then
    raise EElPublicKeyCryptoError.Create(SInvalidXML);

  if Length(v[4]) > 0 then
  begin
    // todo
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
  end
  else
  begin
    LoadPublic(@v[0][0], Length(v[0]), @v[1][0], Length(v[1]), @v[2][0], Length(v[2]));
  end;
end;

procedure TElDHKeyMaterial.LoadPublic(P : pointer; PSize : integer; G : pointer; GSize : integer;
  Y : pointer; YSize : integer);
begin
  FKey.SetKeyProp(SB_KEYPROP_DH_P, CloneArray(P, PSize));
  FKey.SetKeyProp(SB_KEYPROP_DH_G, CloneArray(G, GSize));
  FKey.SetKeyProp(SB_KEYPROP_DH_PEER_Y, CloneArray(Y, YSize));
end;

procedure TElDHKeyMaterial.LoadSecret(Buffer: pointer; Size: integer);
begin
  FKey.ImportSecret(Buffer, Size);
end;

procedure TElDHKeyMaterial.SavePublic(Buffer: pointer; var Size: integer);
var
  Tag : TElASN1SimpleTag;
  Y : ByteArray;
  RealSize : integer;
begin
  Tag := TElASN1SimpleTag.CreateInstance();
  try
    Tag.TagId := SB_ASN1_INTEGER;
    Y := FKey.GetKeyProp(SB_KEYPROP_DH_Y);
    Tag.Content := Y;
    RealSize := 0;
    Tag.SaveToBuffer( nil , RealSize);
    if (Size = 0) or (Buffer = nil) then
      Size := RealSize
    else
    begin
      if RealSize <= Size then
      begin
        Tag.SaveToBuffer(Buffer, Size)
      end
      else
        raise EElPublicKeyCryptoError.Create(SBufferTooSmall);
    end;
  finally
    FreeAndNil(Tag);
  end;
end;

procedure TElDHKeyMaterial.SaveSecret(Buffer: pointer; var Size: integer);
begin
  FKey.ExportSecret(Buffer, Size);
end;

function TElDHKeyMaterial.SaveToXML(IncludePrivateKey: Boolean  =  False): string;
begin
  Result := '';
  if IncludePrivateKey and SecretKey then
  begin
    Result := Format('<DHKeyValue><P>%s</P><Q>%s</Q><G>%s</G><Y>%s</Y><X>%s</X></DHKeyValue>',
       [(ConvertToBase64String(P)),
        (ConvertToBase64String(G)),
        (ConvertToBase64String(Y)),
        (ConvertToBase64String(X))]);
  end
  else if PublicKey then
  begin
    Result := Format('<DHKeyValue><P>%s</P><G>%s</G><Y>%s</Y></DHKeyValue>',
       [(ConvertToBase64String(P)),
        (ConvertToBase64String(G)),
        (ConvertToBase64String(Y))]);
  end;
end;

procedure TElDHKeyMaterial.LoadPeerY(Y : pointer; YSize : integer);
begin
  FKey.SetKeyProp(SB_KEYPROP_DH_PEER_Y, CloneArray(Y, YSize));
end;

procedure TElDHKeyMaterial.LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  if AlgorithmIdentifier is TElDHAlgorithmIdentifier then
  begin
    P := TElDHAlgorithmIdentifier(AlgorithmIdentifier).P;
    G := TElDHAlgorithmIdentifier(AlgorithmIdentifier).G;
  end
  else
    raise EElPublicKeyCryptoError.Create(SInvalidKeyParameters);
end;

procedure TElDHKeyMaterial.SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
var
  Q : ByteArray;
begin
  if AlgorithmIdentifier is TElDHAlgorithmIdentifier then
  begin
    TElDHAlgorithmIdentifier(AlgorithmIdentifier).P := P;
    TElDHAlgorithmIdentifier(AlgorithmIdentifier).G := G;
    SetLength(Q, 1);
    Q[0] := 2;
    TElDHAlgorithmIdentifier(AlgorithmIdentifier).Q := Q;
  end
  else
    raise EElPublicKeyCryptoError.Create(SInvalidKeyParameters);
end;

procedure TElDHKeyMaterial.InternalGenerate(Bits : integer);
var
  ProgressFunc : TSBProgressFunc;
begin
  if Assigned(FWorkingThread) then
    ProgressFunc := TElPublicKeyMaterialWorkingThread(FWorkingThread).ProgressHandler
  else
    ProgressFunc := nil;
  Reset;
  FKey.Generate(Bits);
end;

procedure TElDHKeyMaterial.Assign(Source : TElKeyMaterial);
var
  KM : TElDHKeyMaterial;
begin
  if not (Source is TElDHKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SInvalidKeyMaterialType);
  KM := TElDHKeyMaterial(Source);
  FProvider.ReleaseKey(FKey);
  //FKey := KM.FKey.Clone();
  FKey := KM.FKey.CryptoProvider.CloneKey(KM.FKey);
  FKeyFormat := KM.FKeyFormat;
  FProvider := TElDHKeyMaterial(Source).FProvider;
  FProviderManager := TElDHKeyMaterial(Source).FProviderManager;
end;

function TElDHKeyMaterial.Clone :  TElKeyMaterial ;
var
  Res : TElKeyMaterial;
begin
  Res := TElDHKeyMaterial.Create(FProvider);
  Res.Assign(Self);
  Result := Res;
end;

function TElDHKeyMaterial.Equals(Source : TElKeyMaterial; PublicOnly : boolean): boolean;
var
  B, B1: ByteArray;
begin
  Result := false;
  SetLength(B, 0);
  SetLength(B1, 0);
  if not (Source is TElDHKeyMaterial) then exit;
  if (Self.Key.IsPublic <> Source.Key.IsPublic) then exit;
  if (Self.Key.IsSecret and Source.Key.IsSecret) and (not PublicOnly) then
  begin
      Result := Self.Key.Equals(Source.Key, false, nil);
      exit;
  end;

  Result := true;
  B := TElDHKeyMaterial(Source).GetG;
  B1 := Self.GetG;
  Result := Result and (Length(B) = Length(B1)) and
       (CompareMem(@B1[0], @B[0], Length(B1)))
       ;
  B := TElDHKeyMaterial(Source).GetP;
  B1 := Self.GetP;
  Result := Result and (Length(B) = Length(B1)) and
       (CompareMem(@B1[0], @B[0], Length(B1)))
       ;
  B := TElDHKeyMaterial(Source).GetY;
  B1 := Self.GetY;
  Result := Result and (Length(B) = Length(B1)) and
       (CompareMem(@B1[0], @B[0], Length(B1)))
       ;
end;

procedure TElDHKeyMaterial.ClearSecret;
begin
  FKey.ClearSecret;
end;

procedure TElDHKeyMaterial.ClearPublic;
begin
  FKey.ClearPublic;
end;
 {$endif SB_NO_DH}

////////////////////////////////////////////////////////////////////////////////
// TElDHPublicKeyCrypto class

{$ifndef SB_NO_DH}
constructor TElDHPublicKeyCrypto.Create(CryptoProvider : TElCustomCryptoProvider  = nil );
begin
  inherited Create(CryptoProvider);
  FCryptoType := dhpktRaw;
end;

constructor TElDHPublicKeyCrypto.Create(const OID : ByteArray; CryptoProvider :
  TElCustomCryptoProvider  =  nil);
begin
   Create (CryptoProvider);
end;

constructor TElDHPublicKeyCrypto.Create(Alg : integer; CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
   Create (CryptoProvider);
end;

constructor TElDHPublicKeyCrypto.Create(const OID : ByteArray; Manager: TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
   Create (Manager, CryptoProvider);
end;

constructor TElDHPublicKeyCrypto.Create(Alg : integer; Manager: TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
   Create (Manager, CryptoProvider);
end;

constructor TElDHPublicKeyCrypto.Create(Manager: TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create(Manager, CryptoProvider);
  FCryptoType := dhpktRaw;
end;


 // SB_JAVA

 destructor  TElDHPublicKeyCrypto.Destroy;
begin
  inherited;
end;

procedure TElDHPublicKeyCrypto.LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  if AlgorithmIdentifier is TElDHAlgorithmIdentifier then
  begin
    ;
  end
  else
    raise EElPublicKeyCryptoError.Create(SInvalidAlgorithmIdentifier);
end;

procedure TElDHPublicKeyCrypto.SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  if AlgorithmIdentifier is TElDHAlgorithmIdentifier then
  begin
    ;
  end
  else
    raise EElPublicKeyCryptoError.Create(SInvalidAlgorithmIdentifier);
end;

function TElDHPublicKeyCrypto.GetSupportsEncryption: boolean;
begin
  Result := true; // emulating key exchange via encryption
end;

function TElDHPublicKeyCrypto.GetSupportsSigning: boolean;
begin
  Result := false;
end;

procedure TElDHPublicKeyCrypto.SetKeyMaterial(Material : TElPublicKeyMaterial);
begin
  if FBusy then Exit;

  if not (Material is TElDHKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  FKeyMaterial := Material;
end;

procedure TElDHPublicKeyCrypto.SetCryptoType(Value : TSBDHPublicKeyCryptoType);
begin
  if FBusy then Exit;

  FCryptoType := Value;
end;

procedure TElDHPublicKeyCrypto.EncryptInit;
var
  Params : TElCPParameters;
begin
  if not Assigned(FKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  if not FKeyMaterial.PublicKey then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  SetLength(FSpool, 0);
  Params := TElCPParameters.Create();
  try
    AdjustContextProps(Params);
    FContext := GetSuitableCryptoProvider(pkoEncrypt, SB_ALGORITHM_PK_DH, Params).EncryptInit(
      SB_ALGORITHM_PK_DH, 0, FKeyMaterial.FKey, Params
    );
  finally
    FreeAndNil(Params);
  end;
end;

procedure TElDHPublicKeyCrypto.EncryptUpdate( Buffer: pointer;
    Size: integer);
var
  OldLen, OutSize: integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.EncryptUpdate(FContext, Buffer, Size, nil, OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.EncryptUpdate(FContext, Buffer, Size, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
end;

procedure TElDHPublicKeyCrypto.EncryptFinal;
var
  OutSize, OldLen : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.EncryptFinal(FContext,  nil , OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OutSize + OldLen);
  Prov.EncryptFinal(FContext, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OutSize + OldLen);
  WriteToOutput(@FSpool[0], Length(FSpool));
  FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;

procedure TElDHPublicKeyCrypto.DecryptInit;
var
  Params : TElCPParameters;
begin
  if not Assigned(FKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  {if not FKeyMaterial.SecretKey then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);}
  SetLength(FSpool, 0);
  Params := TElCPParameters.Create();
  try
    AdjustContextProps(Params);
    FContext := GetSuitableCryptoProvider(pkoDecrypt, SB_ALGORITHM_PK_DH, Params).DecryptInit(
      SB_ALGORITHM_PK_DH, 0, FKeyMaterial.FKey, Params
    );
  finally
    FreeAndNil(Params);
  end;
end;

procedure TElDHPublicKeyCrypto.DecryptUpdate( Buffer: pointer;
    Size: integer);
var
  OldLen, OutSize: integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider;
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.DecryptUpdate(FContext, Buffer, Size, nil, OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.DecryptUpdate(FContext, Buffer, Size, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
end;

procedure TElDHPublicKeyCrypto.DecryptFinal;
var
  OutSize, OldLen : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.DecryptFinal(FContext,  nil , OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.DecryptFinal(FContext, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
  WriteToOutput(@FSpool[0], Length(FSpool));
  FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;

function TElDHPublicKeyCrypto.EstimateOutputSize( InBuffer: pointer;
    InSize: integer;
  Operation : TSBPublicKeyOperation): integer;
begin
  if (Operation in [pkoVerify,
    pkoSign]) then
    raise EElPublicKeyCryptoError.Create(SNotASigningAlgorithm);
  if not (KeyMaterial is TElDHKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  if (Operation in [pkoEncrypt, pkoDecrypt]) and
    (InSize > FKeyMaterial.Bits shr 3) then
    raise EElPublicKeyCryptoError.Create(SInputTooLong);
  Result := FKeyMaterial.Bits shr 3;
end;

class function TElDHPublicKeyCrypto.IsAlgorithmSupported(Alg: integer): boolean;
begin
  Result := Alg = SB_ALGORITHM_PK_DH;
end;

class function TElDHPublicKeyCrypto.IsAlgorithmSupported(const OID: ByteArray): boolean;
begin
  Result := false;
end;

class function TElDHPublicKeyCrypto.GetName() : string;
begin
  Result := 'DH';
end;

class function TElDHPublicKeyCrypto.GetDescription() : string;
begin
  Result := 'Implements base DH key exchange functionality';
end;
 {$endif SB_NO_DH}

////////////////////////////////////////////////////////////////////////////////
// ElGamal classes
procedure TElElGamalKeyMaterial.Reset;
begin
  FStoreFormat := ksfRaw;
end;

function TElElGamalKeyMaterial.GetValid : boolean;
begin
  Result := FKey.IsValid;
end;

function TElElGamalKeyMaterial.GetBits : integer;
begin
  Result := FKey.Bits;
end;

function TElElGamalKeyMaterial.GetP : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_ELGAMAL_P);
end;

function TElElGamalKeyMaterial.GetG : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_ELGAMAL_G);
end;

function TElElGamalKeyMaterial.GetY : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_ELGAMAL_Y);
end;

function TElElGamalKeyMaterial.GetX : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_ELGAMAL_X);
end;

constructor TElElGamalKeyMaterial.Create(Prov : TElCustomCryptoProvider);
begin
  inherited;
  Reset;
  FKey := FProvider.CreateKey(SB_ALGORITHM_PK_ELGAMAL, 0);
end;

constructor TElElGamalKeyMaterial.Create(Manager: TElCustomCryptoProviderManager;
  Prov : TElCustomCryptoProvider);
begin
  inherited;
  Reset;
  FKey := FProvider.CreateKey(SB_ALGORITHM_PK_ELGAMAL, 0);
end;


 destructor  TElElGamalKeyMaterial.Destroy;
begin
  inherited Destroy;
end;

procedure TElElGamalKeyMaterial.Assign(Source: TElKeyMaterial);
begin
  if not (Source is TElElGamalKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SInvalidKeyMaterialType);
  FProvider.ReleaseKey(FKey);
  //FKey := TElElgamalKeyMaterial(Source).FKey.Clone();
  FKey := TElElgamalKeyMaterial(Source).FKey.CryptoProvider.CloneKey(TElElgamalKeyMaterial(Source).FKey);
  FProvider := TElElgamalKeyMaterial(Source).FProvider;
  FProviderManager := TElElgamalKeyMaterial(Source).FProviderManager;
end;

function TElElGamalKeyMaterial.Clone :  TElKeyMaterial ;
var
  Res : TElKeyMaterial;
begin
  Res := TElElGamalKeyMaterial.Create(FProvider);
  Res.Assign(Self);
  Result := Res;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElElGamalKeyMaterial.InternalGenerate(Bits : integer);
var
  ProgressFunc : TSBProgressFunc;
begin
  if Assigned(FWorkingThread) then
    ProgressFunc := TElPublicKeyMaterialWorkingThread(FWorkingThread).ProgressHandler
  else
    ProgressFunc := nil;
  FKey.Generate(Bits);
end;
 {$endif SB_PGPSFX_STUB}

{$ifndef SB_PGPSFX_STUB}
procedure TElElGamalKeyMaterial.LoadFromXML(const Str: string);
var
  v: TXMLParamValues;
begin
  Clear;
  v := ParseXmlString(Str, 'ElGamalKeyValue', ['P', 'G', 'Y', 'X', 'Generator', 'Public']);
  if Length(v) <> 6 then
    raise EElPublicKeyCryptoError.Create(SInvalidXML);

  // Generator -> G
  if Length(v[1]) = 0 then
    v[1] := v[4];

  // Public -> Y
  if Length(v[2]) = 0 then
    v[2] := v[5];

  if (Length(v[0]) = 0) or (Length(v[1]) = 0) or (Length(v[2]) = 0) then
    raise EElPublicKeyCryptoError.Create(SInvalidXML);

  if Length(v[3]) > 0 then
  begin
    LoadSecret(@v[0][0], Length(v[0]), @v[1][0], Length(v[1]), @v[2][0], Length(v[2]),
      @v[3][0], Length(v[3]));
  end
  else
  begin
    LoadPublic(@v[0][0], Length(v[0]), @v[1][0], Length(v[1]), @v[2][0], Length(v[2]));
  end;
end;
 {$endif SB_PGPSFX_STUB}

procedure TElElGamalKeyMaterial.LoadPublic(P : pointer; PSize : integer; G : pointer;
  GSize : integer; Y : pointer; YSize : integer);
begin
  FKey.SetKeyProp(SB_KEYPROP_ELGAMAL_P, CloneArray(P, PSize));
  FKey.SetKeyProp(SB_KEYPROP_ELGAMAL_G, CloneArray(G, GSize));
  FKey.SetKeyProp(SB_KEYPROP_ELGAMAL_Y, CloneArray(Y, YSize));
  FKey.SetKeyProp(SB_KEYPROP_ELGAMAL_X, EmptyArray);
end;

procedure TElElGamalKeyMaterial.LoadSecret(P : pointer; PSize : integer; G : pointer;
  GSize : integer; Y : pointer; YSize : integer; X : pointer; XSize : integer);
begin
  FKey.SetKeyProp(SB_KEYPROP_ELGAMAL_P, CloneArray(P, PSize));
  FKey.SetKeyProp(SB_KEYPROP_ELGAMAL_G, CloneArray(G, GSize));
  FKey.SetKeyProp(SB_KEYPROP_ELGAMAL_Y, CloneArray(Y, YSize));
  FKey.SetKeyProp(SB_KEYPROP_ELGAMAL_X, CloneArray(X, XSize));
end;

{$ifndef SB_PGPSFX_STUB}
function TElElGamalKeyMaterial.SaveToXML(IncludePrivateKey: Boolean  =  False): string;
begin
  Result := '';
  if IncludePrivateKey and SecretKey then
  begin
    Result := Format('<ElGamalKeyValue><P>%s</P><G>%s</G><Y>%s</Y><X>%s</X></ElGamalKeyValue>',
       [(ConvertToBase64String(P)),
        (ConvertToBase64String(G)),
        (ConvertToBase64String(Y)),
        (ConvertToBase64String(X))]);
  end
  else if PublicKey then
  begin
    Result := Format('<ElGamalKeyValue><P>%s</P><G>%s</G><Y>%s</Y></ElGamalKeyValue>',
       [(ConvertToBase64String(P)),
        (ConvertToBase64String(G)),
        (ConvertToBase64String(Y))]);
  end;
end;
 {$endif SB_PGPSFX_STUB}

function TElElGamalKeyMaterial.Equals(Source : TElKeyMaterial; PublicOnly : boolean): boolean;
var
  B, B1: ByteArray;
begin
  Result := false;
  SetLength(B, 0);
  SetLength(B1, 0);
  if not (Source is TElElGamalKeyMaterial) then exit;
  if (Self.Key.IsPublic <> Source.Key.IsPublic) then exit;
  if (Self.Key.IsSecret and Source.Key.IsSecret) and (not PublicOnly) then
  begin
      Result := Self.Key.Equals(Source.Key, false, nil);
      exit;
  end;

  Result := true;
  B := TElElGamalKeyMaterial(Source).GetG;
  B1 := Self.GetG;
  Result := Result and (Length(B) = Length(B1)) and
       (CompareMem(@B1[0], @B[0], Length(B1)))
       ;
  B := TElElGamalKeyMaterial(Source).GetP;
  B1 := Self.GetP;
  Result := Result and (Length(B) = Length(B1)) and
       (CompareMem(@B1[0], @B[0], Length(B1)))
       ;
  B := TElElGamalKeyMaterial(Source).GetY;
  B1 := Self.GetY;
  Result := Result and (Length(B) = Length(B1)) and
       (CompareMem(@B1[0], @B[0], Length(B1)))
       ;
end;

procedure TElElGamalKeyMaterial.ClearSecret;
begin
  FKey.ClearSecret;
end;
                                                   
procedure TElElGamalKeyMaterial.ClearPublic;
begin
  FKey.ClearPublic;
end;

procedure TElElGamalKeyMaterial.SavePublic(Buffer: pointer; var Size: integer);
var
  OutSize : integer;
  PublicKeyBlob : ByteArray;
begin
  OutSize := 0;
  FKey.ExportPublic( nil , OutSize, nil);
  SetLength(PublicKeyBlob, OutSize);
  FKey.ExportPublic( @PublicKeyBlob[0] , OutSize);
  SetLength(PublicKeyBlob, OutSize);
  
  if Size = 0 then
    Size := Length(PublicKeyBlob)
  else if Size < Length(PublicKeyBlob) then
    raise EElPublicKeyCryptoError.Create(SBufferTooSmall)
  else
  begin
    Size := Length(PublicKeyBlob);
    SBMove(PublicKeyBlob[0], Buffer^, Size);
  end;
end;

procedure TElElGamalKeyMaterial.SaveSecret(Buffer: pointer; var Size: integer);
var
  OutSize : integer;
  SecretKeyBlob : ByteArray;
begin
  OutSize := 0;
  FKey.ExportSecret( nil , OutSize, nil);
  SetLength(SecretKeyBlob, OutSize);
  FKey.ExportSecret( @SecretKeyBlob[0] , OutSize);
  SetLength(SecretKeyBlob, OutSize);
  
  if Size = 0 then
    Size := Length(SecretKeyBlob)
  else if Size < Length(SecretKeyBlob) then
    raise EElPublicKeyCryptoError.Create(SBufferTooSmall)
  else
  begin
    Size := Length(SecretKeyBlob);
    SBMove(SecretKeyBlob[0], Buffer^, Size);
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// TElElGamalPublicKeyCrypto class

function TElElGamalPublicKeyCrypto.GetSupportsEncryption: boolean;
begin
  Result := true;
end;

function TElElGamalPublicKeyCrypto.GetSupportsSigning: boolean;
begin
  Result := true;
end;

procedure TElElGamalPublicKeyCrypto.SetKeyMaterial(Material : TElPublicKeyMaterial);
begin
  if FBusy then Exit;

  if not (Material is TElElgamalKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SInvalidKeyMaterialType);
  FKeyMaterial := Material;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElElGamalPublicKeyCrypto.SignInit(Detached: boolean);
var
  Params : TElCPParameters;
  Op : TSBPublicKeyOperation;
begin
  if not Assigned(FKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  SetLength(FSpool, 0);
  Params := TElCPParameters.Create();
  try
    AdjustContextProps(Params);
    if Detached then Op := pkoSignDetached else Op := pkoSign;
    FContext := GetSuitableCryptoProvider(Op, SB_ALGORITHM_PK_ELGAMAL, Params).SignInit(
      SB_ALGORITHM_PK_ELGAMAL, FKeyMaterial.FKey, Detached, Params
    );
  finally
    FreeAndNil(Params);
  end;
end;

procedure TElElGamalPublicKeyCrypto.SignUpdate( Buffer: pointer;
    Size: integer);
var
  OldLen, OutSize : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.SignUpdate(FContext, Buffer, Size, nil, OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.SignUpdate(FContext, Buffer, Size, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
end;

procedure TElElGamalPublicKeyCrypto.SignFinal;
var
  OldLen, OutSize : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider;
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.SignFinal(FContext,  nil , OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.SignFinal(FContext, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
  WriteToOutput(@FSpool[0], Length(FSpool));
  FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;

procedure TElElGamalPublicKeyCrypto.EncryptInit;
var
  Params : TElCPParameters;
begin
  if not Assigned(FKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  if not FKeyMaterial.PublicKey then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  SetLength(FSpool, 0);
  Params := TElCPParameters.Create();
  try
    AdjustContextProps(Params);
    FContext := GetSuitableCryptoProvider(pkoEncrypt, SB_ALGORITHM_PK_ELGAMAL, Params).EncryptInit(
      SB_ALGORITHM_PK_ELGAMAL, 0, FKeyMaterial.FKey, Params
    );
  finally
    FreeAndNil(Params);
  end;
end;

procedure TElElGamalPublicKeyCrypto.EncryptUpdate( Buffer: pointer;
    Size: integer);
var
  OldLen, OutSize: integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.EncryptUpdate(FContext, Buffer, Size, nil, OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.EncryptUpdate(FContext, Buffer, Size, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
end;

procedure TElElGamalPublicKeyCrypto.EncryptFinal;
var
  OutSize, OldLen : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.EncryptFinal(FContext,  nil , OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.EncryptFinal(FContext, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
  WriteToOutput(@FSpool[0], Length(FSpool));
  FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;
 {$endif SB_PGPSFX_STUB}

procedure TElElGamalPublicKeyCrypto.DecryptInit;
var
  Params : TElCPParameters;
begin
  if not Assigned(FKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  if not (FKeyMaterial.SecretKey) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  SetLength(FSpool, 0);
  Params := TElCPParameters.Create();
  try
    AdjustContextProps(Params);
    FContext := GetSuitableCryptoProvider(pkoDecrypt, SB_ALGORITHM_PK_ELGAMAL, Params).DecryptInit(
      SB_ALGORITHM_PK_ELGAMAL, 0, FKeyMaterial.FKey, Params
    );
  finally
    FreeAndNil(Params);
  end;
end;

procedure TElElGamalPublicKeyCrypto.DecryptUpdate( Buffer: pointer;
    Size: integer);
var
  OldLen, OutSize: integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.DecryptUpdate(FContext, Buffer, Size, nil, OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.DecryptUpdate(FContext, Buffer, Size, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
end;

procedure TElElGamalPublicKeyCrypto.DecryptFinal;
var
  OldLen, OutSize : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.DecryptFinal(FContext,  nil , OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.DecryptFinal(FContext, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
  WriteToOutput(@FSpool[0], Length(FSpool));
  FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;

procedure TElElGamalPublicKeyCrypto.VerifyInit(Detached: boolean;
   Signature: pointer;  SigSize: integer);
var
  Params : TElCPParameters;
  Op : TSBPublicKeyOperation;
begin
  if not Assigned(FKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  if not FKeyMaterial.PublicKey then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  SetLength(FSpool, 0);
  Params := TElCPParameters.Create();
  try
    AdjustContextProps(Params);
    if Detached then Op := pkoVerifyDetached else Op := pkoVerify;
    FContext := GetSuitableCryptoProvider(Op, SB_ALGORITHM_PK_ELGAMAL, Params).VerifyInit(
      SB_ALGORITHM_PK_ELGAMAL, FKeyMaterial.FKey, Signature, 
      SigSize, Params
    );
  finally
    FreeAndNil(Params);
  end;
end;

procedure TElElGamalPublicKeyCrypto.VerifyUpdate( Buffer: pointer;  Size: integer);
var
  OldLen, OutSize : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.VerifyUpdate(FContext, Buffer, Size, nil, OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.VerifyUpdate(FContext, Buffer, Size, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
end;

function TElElGamalPublicKeyCrypto.VerifyFinal : TSBPublicKeyVerificationResult;
var
  OutSize, OldLen : integer;
  R : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.VerifyFinal(FContext,  nil , OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  R := Prov.VerifyFinal(FContext, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
  case R of
    SB_VR_SUCCESS:
      Result := pkvrSuccess;
    SB_VR_INVALID_SIGNATURE:
      Result := pkvrInvalidSignature;
    SB_VR_KEY_NOT_FOUND:
      Result := pkvrKeyNotFound;
    else
      Result := pkvrFailure;
  end;
  FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;

function TElElGamalPublicKeyCrypto.EstimateOutputSize( InBuffer: pointer;
    InSize: integer;
  Operation : TSBPublicKeyOperation): integer;
begin
  Result := 0;
  if not (KeyMaterial is TElElgamalKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);

  if (Operation = pkoEncrypt) and
    (InSize > Length(TElElgamalKeyMaterial(KeyMaterial).P)) then
    raise EElPublicKeyCryptoError.Create(SInputTooLong);

  if (Operation in [pkoEncrypt,
    pkoSignDetached]) then
    Result := Length(TElElgamalKeyMaterial(KeyMaterial).P) shl 1 + 16
  else if Operation = pkoDecrypt then
    Result := Length(TElElgamalKeyMaterial(KeyMaterial).P)
  else if Operation = pkoVerify then
    Result := 0;
end;

class function TElElgamalPublicKeyCrypto.IsAlgorithmSupported(const OID: ByteArray): boolean;
begin
  Result := false;
end;

class function TElElGamalPublicKeyCrypto.IsAlgorithmSupported(Alg: integer): boolean;
begin
  Result := (Alg = SB_CERT_ALGORITHM_ID_ELGAMAL) or (Alg = SB_ALGORITHM_PK_ELGAMAL);
end;

class function TElElGamalPublicKeyCrypto.GetName() : string;
begin
  Result := 'Elgamal';
end;

class function TElElGamalPublicKeyCrypto.GetDescription() : string;
begin
  Result := 'Implements Elgamal signing and encryption operations.';
end;

procedure TElElGamalPublicKeyCrypto.Reset;
begin
  FInputIsHash := true;
  FInputEncoding := pkeBinary;
  FOutputEncoding := pkeBinary;
  FHashAlg := SB_ALGORITHM_DGST_SHA1;
end;

procedure TElElGamalPublicKeyCrypto.AdjustContextProps(Params : TElCPParameters);
begin
  inherited;
  Params.Add(SB_CTXPROP_HASH_ALGORITHM, GetOIDByHashAlgorithm(FHashAlg));
end;

constructor TElElGamalPublicKeyCrypto.Create(const OID : ByteArray; CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited Create(CryptoProvider);
  
  if not IsAlgorithmSupported(OID) then
    raise EElPublicKeyCryptoError.Create(SUnsupportedAlgorithm);

  FHashAlg := SB_ALGORITHM_DGST_SHA1;
end;

constructor TElElGamalPublicKeyCrypto.Create(Alg : integer; CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited Create(CryptoProvider);
  
  if not IsAlgorithmSupported(Alg) then
    raise EElPublicKeyCryptoError.Create(SUnsupportedAlgorithm);

  FHashAlg := SB_ALGORITHM_DGST_SHA1;
end;

constructor TElElGamalPublicKeyCrypto.Create(CryptoProvider : TElCustomCryptoProvider  = nil );
begin
   Create (SB_CERT_ALGORITHM_ID_ELGAMAL, CryptoProvider);
end;

constructor TElElGamalPublicKeyCrypto.Create(const OID : ByteArray;
  Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create(Manager, CryptoProvider);
  if not IsAlgorithmSupported(OID) then
    raise EElPublicKeyCryptoError.Create(SUnsupportedAlgorithm);

  FHashAlg := SB_ALGORITHM_DGST_SHA1;
end;

constructor TElElGamalPublicKeyCrypto.Create(Alg : integer;
  Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create(Manager, CryptoProvider);
  if not IsAlgorithmSupported(Alg) then
    raise EElPublicKeyCryptoError.Create(SUnsupportedAlgorithm);

  FHashAlg := SB_ALGORITHM_DGST_SHA1;
end;

constructor TElElGamalPublicKeyCrypto.Create(Manager: TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
   Create (SB_CERT_ALGORITHM_ID_ELGAMAL, Manager, CryptoProvider);
end;



 destructor  TElElGamalPublicKeyCrypto.Destroy;
begin
  inherited;
end;

procedure TElElgamalPublicKeyCrypto.EncodeResult(A : pointer; ASize : integer; B : pointer; BSize : integer;
  Blob : pointer; var BlobSize : integer);
begin
  SBElgamal.EncodeResult(A, ASize, B, BSize, Blob, BlobSize);
end;

procedure TElElgamalPublicKeyCrypto.DecodeResult(Blob : pointer; BlobSize : integer; A : pointer;
  var ASize : integer; B : pointer; var BSize : integer);
begin
  SBElgamal.DecodeResult(Blob, BlobSize, A, ASize, B, BSize);
end;

{$ifndef SB_NO_SRP}
////////////////////////////////////////////////////////////////////////////////
// TElSRPKeyMaterial class

constructor TElSRPKeyMaterial.Create(Prov : TElCustomCryptoProvider  = nil );
begin
  inherited;
  SBSRP.SrpInitContext(FSRPContext);
end;

constructor TElSRPKeyMaterial.Create(Manager : TElCustomCryptoProviderManager; Prov : TElCustomCryptoProvider);
begin
  inherited;
  SBSRP.SrpInitContext(FSRPContext);
end; 


 destructor  TElSRPKeyMaterial.Destroy;
begin
  SBSRP.SrpDestroyContext(FSRPContext);
  inherited;
end;

function TElSRPKeyMaterial.GetSalt:ByteArray;
begin
  Result := LIntToBytes(FSrpContext.Salt);
end;

function TElSRPKeyMaterial.GetN:ByteArray;
begin
  Result := LIntToBytes(FSrpContext.N);
end;

function TElSRPKeyMaterial.GetG:ByteArray;
begin
  Result := LIntToBytes(FSrpContext.G);
end;

function TElSRPKeyMaterial.GetX:ByteArray;
begin
  Result := LIntToBytes(FSrpContext.X);
end;

function TElSRPKeyMaterial.GetA:ByteArray;
begin
  Result := LIntToBytes(FSrpContext.A);
end;

function TElSRPKeyMaterial.GetK:ByteArray;
begin
  Result := LIntToBytes(FSrpContext.K);
end;

function TElSRPKeyMaterial.GetA_small:ByteArray;
begin
  Result := LIntToBytes(FSrpContext.A_small);
end;

function TElSRPKeyMaterial.GetB:ByteArray;
begin
  Result := LIntToBytes(FSrpContext.B);
end;

function TElSRPKeyMaterial.GetB_small:ByteArray;
begin
  Result := LIntToBytes(FSrpContext.B_small);
end;

function TElSRPKeyMaterial.GetV:ByteArray;
begin
  Result := LIntToBytes(FSrpContext.V);
end;

function TElSRPKeyMaterial.GetU:ByteArray;
begin
  Result := LIntToBytes(FSrpContext.U);
end;

function TElSRPKeyMaterial.GetS:ByteArray;
begin
  Result := LIntToBytes(FSrpContext.S);
end;

procedure TElSRPKeyMaterial.Assign(Source : TElKeyMaterial);
var
  KM : TElSRPKeyMaterial;
  //BA:ByteArray;
begin
  if not (Source is TElSRPKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SInvalidKeyMaterialType);
  KM := TElSRPKeyMaterial(Source);

  LInitBytes(FSrpContext.N, KM.N);
  LInitBytes(FSrpContext.Salt, KM.Salt);
  LInitBytes(FSrpContext.G, KM.G);
  LInitBytes(FSrpContext.X, KM.X);
  LInitBytes(FSrpContext.A, KM.A);
  LInitBytes(FSrpContext.K, KM.K);
  LInitBytes(FSrpContext.A_small, KM.A_small);
  LInitBytes(FSrpContext.B, KM.B);
  LInitBytes(FSrpContext.B_small, KM.B_small);
  LInitBytes(FSrpContext.V, KM.V);
  LInitBytes(FSrpContext.U, KM.U);
  LInitBytes(FSrpContext.S, KM.S);
  FSrpContext.Initialized:=true;
end;

function TElSRPKeyMaterial.Clone :  TElKeyMaterial ;
var
  Res : TElKeyMaterial;
begin
  Res := TElDHKeyMaterial.Create(FProvider);
  Res.Assign(Self);
  Result := Res;
end;

function TElSRPKeyMaterial.LoadPublic(N:ByteArray; G: ByteArray; Salt:ByteArray; V:ByteArray):boolean;
begin
  LInitBytes(FSrpContext.N, N);
  LInitBytes(FSrpContext.Salt, Salt);
  LInitBytes(FSrpContext.G, G);
  LInitBytes(FSrpContext.V, V);
  SbSrp.SrpServerInit(FSRPContext);
  Result:=true;
end;

function TElSRPKeyMaterial.LoadPublic(Buffer : Pointer; Len: LongInt):boolean;
var
  TmpSize, Offset:integer;
  TmpBytes: ByteArray;
  B: Boolean;
begin
  Offset := 0;
  B := true;

  if Offset + 2 > Len then
    B := false;

  TmpSize := 0;
  if B then
  begin
    TmpSize := (PByteArray(Buffer)[0+Offset] shl 8) or PByteArray(Buffer)[1+Offset];
    SetLength(TmpBytes, TmpSize);
    If TmpSize + Offset + 2 > Len then
      B := false;
  end;
  if B then
  begin
    SBMove(PByteArray(Buffer)[2+Offset], TmpBytes[0], TmpSize);
    LInit(FSrpContext.N,BinaryToString(@TmpBytes[0],TmpSize));
  end;

  Offset:=Offset+TmpSize+2;
  if Offset+2>Len then
    B:=false;

  if B then
  begin
    TmpSize := (PByteArray(Buffer)[0+Offset] shl 8) or PByteArray(Buffer)[1+Offset];
    SetLength(TmpBytes, TmpSize);
    if TmpSize+Offset+2>Len then
      B:=false;
  end;
  if B then
  begin
    SBMove(PByteArray(Buffer)[2+Offset], TmpBytes[0], TmpSize);
    LInit(FSrpContext.G,BinaryToString(@TmpBytes[0],TmpSize));
  end;

  Offset:=Offset+TmpSize+2;
  if Offset+2>Len then
    B:=false;

  if B then
  begin
    TmpSize := PByteArray(Buffer)[0+Offset];
    SetLength(TmpBytes, TmpSize);
    If TmpSize+Offset+1>Len then
          B:=false;
  end;
  if B then
  begin
    SBMove(PByteArray(Buffer)[1+Offset], TmpBytes[0], TmpSize);
    LInit(FSrpContext.Salt,BinaryToString(@TmpBytes[0],TmpSize));
  end;

  Offset:=Offset+TmpSize+1;
  if Offset+2>Len then
    B:=false;

  if B then
  begin
    TmpSize := (PByteArray(Buffer)[0+Offset] shl 8) or PByteArray(Buffer)[1+Offset];
    SetLength(TmpBytes, TmpSize);
    If TmpSize+Offset+2>Len then
      B:=false;
  end;
  if B then
  begin
    SBMove(PByteArray(Buffer)[2+Offset], TmpBytes[0], TmpSize);
    LInit(FSrpContext.B,BinaryToString(@TmpBytes[0],TmpSize));
  end;
  Result:=B;
end;

////////////////////////////////////////////////////////////////////////////////
// TElSRPPublicKeyCrypto class

constructor TElSRPPublicKeyCrypto.Create(CryptoProvider : TElCustomCryptoProvider  = nil );
begin
  inherited Create(CryptoProvider);
end;

constructor TElSRPPublicKeyCrypto.Create(const OID : ByteArray; CryptoProvider :
  TElCustomCryptoProvider  =  nil);
begin
   Create (CryptoProvider);
end;

constructor TElSRPPublicKeyCrypto.Create(Alg : integer; CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
   Create (CryptoProvider);
end;

constructor TElSRPPublicKeyCrypto.Create(const OID : ByteArray;
  Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
   Create (Manager, CryptoProvider);
end;

constructor TElSRPPublicKeyCrypto.Create(Alg : integer; Manager: TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
   Create (Manager, CryptoProvider);
end;

constructor TElSRPPublicKeyCrypto.Create(Manager: TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;


 // SB_JAVA

function TElSRPPublicKeyCrypto.GetSupportsEncryption: boolean;
begin
  Result := false; // emulating key exchange via encryption
end;

function TElSRPPublicKeyCrypto.GetSupportsSigning: boolean;
begin
  Result := false;
end;

procedure TElSRPPublicKeyCrypto.SetKeyMaterial(Material : TElPublicKeyMaterial);
begin
  if FBusy then Exit;

  if not (Material is TElSRPKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  FKeyMaterial := Material;
end;

class function TElSRPPublicKeyCrypto.IsAlgorithmSupported(Alg: integer): boolean;
begin
  Result := Alg = SB_ALGORITHM_PK_SRP;
end;

class function TElSRPPublicKeyCrypto.IsAlgorithmSupported(const OID: ByteArray): boolean;
begin
  Result := false;
end;

class function TElSRPPublicKeyCrypto.GetName() : string;
begin
  Result := 'SRP';
end;

class function TElSRPPublicKeyCrypto.GetDescription() : string;
begin
  Result := 'Implements base SRP key exchange functionality';
end;

procedure TElSRPPublicKeyCrypto.GetServerKey(const Buffer:ByteArray; Index:integer; Len:integer; var Master:ByteArray);
var TmpBuf:ByteArray;
    SKM:TElSRPKeyMaterial;
begin
    SetLength(TmpBuf,Len);
    SKM:=TElSRPKeyMaterial(FKeyMaterial);
    SBMove(Buffer[Index],TmpBuf[0],Len);
    LInit(SKM.FSRPContext.A,BinaryToString(@TmpBuf[0],Len));
     ;
    SBSRP.SrpGetServerKey(SKM.FSRPContext);
    Len:=Length(SKM.S);
    SetLength(Master,Len);
    SBMove(SKM.GetS[0],Master[0],Len);
end;

procedure TElSRPPublicKeyCrypto.GetClientKeyParam(const UserName,UserPassword:string; var A:ByteArray);
var Len:integer;
    SKM:TElSRPKeyMaterial;
begin
    SKM:=TElSRPKeyMaterial(FKeyMaterial);
    SrpGetA(Username,UserPassword,SKM.FSRPContext);
    SrpGetClientKey(SKM.FSRPContext);
    Len:=Length(SKM.A);
    SetLength(A,Len);
    SBMove(SKM.A[0],A[0],Len);
end;
 {$endif}

{$ifdef SB_HAS_GOST}

////////////////////////////////////////////////////////////////////////////////
//  TElGOST94KeyMaterial class

constructor TElGOST94KeyMaterial.Create(Prov : TElCustomCryptoProvider);
begin
  inherited;
  Reset;
  FKey := FProvider.CreateKey(SB_ALGORITHM_PK_GOST_R3410_1994, 0);
end;

constructor TElGOST94KeyMaterial.Create(Manager : TElCustomCryptoProviderManager; Prov : TElCustomCryptoProvider);
begin
  inherited;
  Reset;
  FKey := FProvider.CreateKey(SB_ALGORITHM_PK_GOST_R3410_1994, 0);
end;


 destructor  TElGOST94KeyMaterial.Destroy;
begin
  inherited;
end;

procedure TElGOST94KeyMaterial.Reset;
begin
  FStoreFormat := ksfRaw;
end;

function TElGOST94KeyMaterial.GetValid : boolean;
begin
  Result := FKey.IsValid;
end;

function TElGOST94KeyMaterial.GetBits : integer;
begin
  Result := FKey.Bits;
end;

function TElGOST94KeyMaterial.GetProp(PropID: ByteArray) : ByteArray;
begin
  Result := FKey.GetKeyProp(PropID);
end;

function TElGOST94KeyMaterial.GetP : ByteArray;
begin
  Result := GetProp(SB_KEYPROP_GOST_R3410_1994_P);
end;

function TElGOST94KeyMaterial.GetQ : ByteArray;
begin
  Result := GetProp(SB_KEYPROP_GOST_R3410_1994_Q);
end;

function TElGOST94KeyMaterial.GetA : ByteArray;
begin
  Result := GetProp(SB_KEYPROP_GOST_R3410_1994_A);
end;

function TElGOST94KeyMaterial.GetX : ByteArray;
begin
  Result := GetProp(SB_KEYPROP_GOST_R3410_1994_X);
end;

procedure TElGOST94KeyMaterial.SetX(const Value : ByteArray);
begin
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_1994_X, Value);
end;

function TElGOST94KeyMaterial.GetY : ByteArray;
begin
  Result := GetProp(SB_KEYPROP_GOST_R3410_1994_Y);
end;

procedure TElGOST94KeyMaterial.SetY(const Value : ByteArray);
begin
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_1994_Y, Value);
end;

function TElGOST94KeyMaterial.GetParamSet : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_GOST_R3410_PARAMSET);
end;

procedure TElGOST94KeyMaterial.SetParamSet(const Value : ByteArray);
begin
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_PARAMSET, Value);
end;

function TElGOST94KeyMaterial.GetDigestParamSet : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_GOST_R3410_DIGEST_PARAMSET);
end;

procedure TElGOST94KeyMaterial.SetDigestParamSet(const Value : ByteArray);
begin
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_DIGEST_PARAMSET, Value);
end;

function TElGOST94KeyMaterial.GetEncryptionParamSet : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_GOST_R3410_ENCRYPTION_PARAMSET);
end;

procedure TElGOST94KeyMaterial.SetEncryptionParamSet(const Value : ByteArray);
begin
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_ENCRYPTION_PARAMSET, Value);
end;

procedure TElGOST94KeyMaterial.Assign(Source: TElKeyMaterial);
begin
  if not (Source is TElGOST94KeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SInvalidKeyMaterialType);
  FProvider.ReleaseKey(FKey);

  FKey := TElGOST94KeyMaterial(Source).FKey.CryptoProvider.CloneKey(TElGOST94KeyMaterial(Source).FKey);
  FProvider := TElGOST94KeyMaterial(Source).FProvider;
  FProviderManager := TElGOST94KeyMaterial(Source).FProviderManager;
end;

function TElGOST94KeyMaterial.Clone :  TElKeyMaterial ;
var
  Res : TElKeyMaterial;
begin
  Res := TElGOST94KeyMaterial.Create(FProvider);
  Res.Assign(Self);
  Result := Res;
end;

procedure TElGOST94KeyMaterial.InternalGenerate(Bits : integer);
var
  ProgressFunc : TSBProgressFunc;
begin
  if Assigned(FWorkingThread) then
    ProgressFunc := TElPublicKeyMaterialWorkingThread(FWorkingThread).ProgressHandler
  else
    ProgressFunc := nil;

  FKey.Generate(Bits, nil, ProgressFunc);
end;

procedure TElGOST94KeyMaterial.LoadPublic(P : pointer; PSize : integer; Q : pointer;
  QSize : integer; A : pointer; ASize : integer; Y : pointer; YSize : integer);
begin
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_1994_P, CloneArray(P, PSize));
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_1994_Q, CloneArray(Q, QSize));
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_1994_A, CloneArray(A, ASize));
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_1994_Y, CloneArray(Y, YSize));
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_1994_X, EmptyArray);
end;

procedure TElGOST94KeyMaterial.LoadSecret(P : pointer; PSize : integer; Q : pointer;
  QSize : integer; A : pointer; ASize : integer; Y : pointer; YSize : integer;
  X : pointer; XSize : integer);
begin
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_1994_P, CloneArray(P, PSize));
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_1994_Q, CloneArray(Q, QSize));
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_1994_A, CloneArray(A, ASize));
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_1994_Y, CloneArray(Y, YSize));
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_1994_X, CloneArray(X, XSize));
end;

procedure TElGOST94KeyMaterial.LoadPublic(const P : ByteArray; PIndex, PSize : integer;
  const Q : ByteArray; QIndex, QSize : integer;
  const A : ByteArray; AIndex, ASize : integer;
  const Y : ByteArray; YIndex, YSize : integer);
begin
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_1994_P, CloneArray(@P[PIndex], PSize));
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_1994_Q, CloneArray(@Q[QIndex], QSize));
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_1994_A, CloneArray(@A[AIndex], ASize));
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_1994_Y, CloneArray(@Y[YIndex], YSize));
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_1994_X, EmptyArray);
end;

procedure TElGOST94KeyMaterial.LoadSecret(const P : ByteArray; PIndex, PSize : integer;
      const Q : ByteArray; QIndex, QSize : integer;
      const A : ByteArray; AIndex, ASize : integer;
      const Y : ByteArray; YIndex, YSize : integer;
      const X : ByteArray; XIndex, XSize : integer);
begin
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_1994_P, CloneArray(@P[PIndex], PSize));
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_1994_Q, CloneArray(@Q[QIndex], QSize));
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_1994_A, CloneArray(@A[AIndex], ASize));
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_1994_Y, CloneArray(@Y[YIndex], YSize));
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_1994_X, CloneArray(@X[XIndex], XSize));
end;

procedure TElGOST94KeyMaterial.LoadSecret(Buffer: pointer; Size: integer);
begin
  FKey.ImportSecret(Buffer, Size);
end;

procedure TElGOST94KeyMaterial.SaveSecret(Buffer: pointer; var Size: integer);
begin
  FKey.ExportSecret(Buffer, Size);
end;

procedure TElGOST94KeyMaterial.LoadPublic(Buffer: pointer; Size: integer);
begin
  FKey.ImportPublic(Buffer, Size);
end;

procedure TElGOST94KeyMaterial.SavePublic(Buffer: pointer; var Size: integer);
begin
  FKey.ExportPublic(Buffer, Size);
end;

procedure TElGOST94KeyMaterial.LoadFromXML(const Str: string);
var
  v: TXMLParamValues;
begin
  Clear;
  v := ParseXmlString(Str, 'GOSTKeyValue', ['P', 'Q', 'A', 'Y', 'X']);
  if Length(v) <> 5 then
    raise EElPublicKeyCryptoError.Create(SInvalidXML);

  if (Length(v[0]) = 0) or (Length(v[1]) = 0)
      or (Length(v[2]) = 0) or (Length(v[3]) = 0) then
    raise EElPublicKeyCryptoError.Create(SInvalidXML);

  if Length(v[4]) > 0 then
  begin
    LoadSecret(v[0], 0, Length(v[0]), v[1], 0, Length(v[1]), v[2], 0, Length(v[2]),
      v[3], 0, Length(v[3]), v[4], 0, Length(v[4]));
  end
  else
  begin
    LoadPublic(v[0], 0, Length(v[0]), v[1], 0, Length(v[1]), v[2], 0, Length(v[2]),
    v[3], 0, Length(v[3]));
  end;
end;

function TElGOST94KeyMaterial.SaveToXML(IncludePrivateKey: Boolean  =  False): string;
begin
  Result := '';
  if IncludePrivateKey and SecretKey then
  begin
    Result := Format('<GOSTKeyValue><P>%s</P><Q>%s</Q><A>%s</A><Y>%s</Y><X>%s</X></GOSTKeyValue>',
       [(ConvertToBase64String(P)),
        (ConvertToBase64String(Q)),
        (ConvertToBase64String(A)),
        (ConvertToBase64String(Y)),
        (ConvertToBase64String(X))]);
  end
  else if PublicKey then
  begin
    Result := Format('<GOSTKeyValue><P>%s</P><Q>%s</Q><A>%s</A><Y>%s</Y></GOSTKeyValue>',
       [(ConvertToBase64String(P)),
        (ConvertToBase64String(Q)),
        (ConvertToBase64String(A)),
        (ConvertToBase64String(Y))]);
  end;
end;

function  TElGOST94KeyMaterial.Equals(Source : TElKeyMaterial; PublicOnly : boolean): boolean;
begin
  Result := FKey.Equals(Source.Key, PublicOnly, nil);
end;

procedure TElGOST94KeyMaterial.ClearSecret;
begin
  FKey.ClearSecret;
end;

procedure TElGOST94KeyMaterial.ClearPublic;
begin
  FKey.ClearPublic;
end;

procedure TElGOST94KeyMaterial.LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  if (AlgorithmIdentifier is TElGOST3411WithGOST3410AlgorithmIdentifier) then
    Exit;

  if not (AlgorithmIdentifier is TElGOST3410AlgorithmIdentifier) then
    raise EElPublicKeyCryptoError.Create(SInvalidKeyParameters);

  ParamSet := TElGOST3410AlgorithmIdentifier(AlgorithmIdentifier).PublicKeyParamSet;
  DigestParamSet := TElGOST3410AlgorithmIdentifier(AlgorithmIdentifier).DigestParamSet;
  EncryptionParamSet := TElGOST3410AlgorithmIdentifier(AlgorithmIdentifier).EncryptionParamSet;  
end;

procedure TElGOST94KeyMaterial.SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  if not (AlgorithmIdentifier is TElGOST3410AlgorithmIdentifier) then
    raise EElPublicKeyCryptoError.Create(SInvalidKeyParameters);

  TElGOST3410AlgorithmIdentifier(AlgorithmIdentifier).PublicKeyParamSet := ParamSet;
  TElGOST3410AlgorithmIdentifier(AlgorithmIdentifier).DigestParamSet := DigestParamSet;
  TElGOST3410AlgorithmIdentifier(AlgorithmIdentifier).EncryptionParamSet := EncryptionParamSet;
end;

////////////////////////////////////////////////////////////////////////////////
// TElGOST94PublicKeyCrypto class

function TElGOST94PublicKeyCrypto.GetSupportsEncryption: boolean;
begin
  Result := False;
end;

function TElGOST94PublicKeyCrypto.GetSupportsSigning: boolean;
begin
  Result := true;
end;

procedure TElGOST94PublicKeyCrypto.SetKeyMaterial(Material : TElPublicKeyMaterial);
begin
  if FBusy then Exit;

  if not (Material is TElGOST94KeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SInvalidKeyMaterialType);
  FKeyMaterial := Material;
end;

procedure TElGOST94PublicKeyCrypto.SignInit(Detached: boolean);
var
  Params : TElCPParameters;
  Op : TSBPublicKeyOperation;
begin
  if not Assigned(FKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  SetLength(FSpool, 0);
  Params := TElCPParameters.Create();
  try
    AdjustContextProps(Params);
    if Detached then Op := pkoSignDetached else Op := pkoSign;
    FContext := GetSuitableCryptoProvider(Op, SB_ALGORITHM_PK_GOST_R3410_1994, Params).SignInit(
      SB_ALGORITHM_PK_GOST_R3410_1994, FKeyMaterial.FKey, Detached, Params
    );
  finally
    FreeAndNil(Params);
  end;
end;

procedure TElGOST94PublicKeyCrypto.SignUpdate( Buffer: pointer;
    Size: integer);
var
  OldLen, OutSize : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.SignUpdate(FContext, Buffer, Size, nil, OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.SignUpdate(FContext, Buffer, Size, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
end;

procedure TElGOST94PublicKeyCrypto.SignFinal;
var
  OldLen, OutSize : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider;
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.SignFinal(FContext,  nil , OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.SignFinal(FContext, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
  WriteToOutput(@FSpool[0], Length(FSpool));
  FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;

procedure TElGOST94PublicKeyCrypto.VerifyInit(Detached: boolean;
   Signature: pointer;  SigSize: integer);
var
  Params : TElCPParameters;
  Op : TSBPublicKeyOperation;
begin
  if not Assigned(FKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  if not FKeyMaterial.PublicKey then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  SetLength(FSpool, 0);
  Params := TElCPParameters.Create();
  try
    AdjustContextProps(Params);
    if Detached then Op := pkoVerifyDetached else Op := pkoVerify;
    FContext := GetSuitableCryptoProvider(Op, SB_ALGORITHM_PK_GOST_R3410_1994, Params).VerifyInit(
      SB_ALGORITHM_PK_GOST_R3410_1994, FKeyMaterial.FKey, Signature, 
      SigSize, Params
    );
  finally
    FreeAndNil(Params);
  end;
end;

procedure TElGOST94PublicKeyCrypto.VerifyUpdate( Buffer: pointer;  Size: integer);
var
  OldLen, OutSize : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.VerifyUpdate(FContext, Buffer, Size, nil, OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.VerifyUpdate(FContext, Buffer, Size, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
end;

function TElGOST94PublicKeyCrypto.VerifyFinal : TSBPublicKeyVerificationResult;
var
  OutSize, OldLen : integer;
  R : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.VerifyFinal(FContext,  nil , OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  R := Prov.VerifyFinal(FContext, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
  case R of
    SB_VR_SUCCESS:
      Result := pkvrSuccess;
    SB_VR_INVALID_SIGNATURE:
      Result := pkvrInvalidSignature;
    SB_VR_KEY_NOT_FOUND:
      Result := pkvrKeyNotFound;
    else
      Result := pkvrFailure;
  end;
  FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;

function TElGOST94PublicKeyCrypto.EstimateOutputSize( InBuffer: pointer;
    InSize: integer;
  Operation : TSBPublicKeyOperation): integer;
begin
  if not (KeyMaterial is TElGOST94KeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);

  if (Operation = pkoEncrypt) and
    (InSize > Length(TElGOST94KeyMaterial(KeyMaterial).P)) then
    raise EElPublicKeyCryptoError.Create(SInputTooLong);

  if (Operation = pkoSignDetached) then
    Result := Length(TElGOST94KeyMaterial(KeyMaterial).P) shl 1 + 16
  else if Operation = pkoVerify then
    Result := 0
  else
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation);
end;

class function TElGOST94PublicKeyCrypto.IsAlgorithmSupported(const OID: ByteArray): boolean;
begin
  Result := IsAlgorithmSupported(GetAlgorithmByOID(OID));
end;

class function TElGOST94PublicKeyCrypto.IsAlgorithmSupported(Alg: integer): boolean;
begin
  Result := (Alg = SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_1994) or (Alg = SB_ALGORITHM_PK_GOST_R3410_1994);
end;

class function TElGOST94PublicKeyCrypto.GetName() : string;
begin
  Result := 'GOST R 34.10-1994';
end;

class function TElGOST94PublicKeyCrypto.GetDescription() : string;
begin
  Result := 'Implements GOST 34.10-94 digital signature operations.';
end;

procedure TElGOST94PublicKeyCrypto.Reset;
begin
  FInputIsHash := true;
  FInputEncoding := pkeBinary;
  FOutputEncoding := pkeBinary;
  FHashAlg := SB_ALGORITHM_DGST_GOST_R3411_1994;
end;

procedure TElGOST94PublicKeyCrypto.AdjustContextProps(Params : TElCPParameters);
begin
  inherited;
  Params.Add(SB_CTXPROP_HASH_ALGORITHM, GetOIDByHashAlgorithm(FHashAlg));
end;

constructor TElGOST94PublicKeyCrypto.Create(const OID : ByteArray; CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited Create(CryptoProvider);
 
  if not IsAlgorithmSupported(OID) then
    raise EElPublicKeyCryptoError.Create(SUnsupportedAlgorithm);

  FHashAlg := SB_ALGORITHM_DGST_GOST_R3411_1994;
end;

constructor TElGOST94PublicKeyCrypto.Create(const OID : ByteArray; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create(CryptoProvider);
  
  if not IsAlgorithmSupported(OID) then
    raise EElPublicKeyCryptoError.Create(SUnsupportedAlgorithm);

  FHashAlg := SB_ALGORITHM_DGST_GOST_R3411_1994;
end;

constructor TElGOST94PublicKeyCrypto.Create(Alg : integer; CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited Create(CryptoProvider);
  
  if not IsAlgorithmSupported(Alg) then
    raise EElPublicKeyCryptoError.Create(SUnsupportedAlgorithm);

  FHashAlg := SB_ALGORITHM_DGST_GOST_R3411_1994;
end;

constructor TElGOST94PublicKeyCrypto.Create(Alg : integer; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create(CryptoProvider);
  
  if not IsAlgorithmSupported(Alg) then
    raise EElPublicKeyCryptoError.Create(SUnsupportedAlgorithm);

  FHashAlg := SB_ALGORITHM_DGST_GOST_R3411_1994;
end;

constructor TElGOST94PublicKeyCrypto.Create(CryptoProvider : TElCustomCryptoProvider  = nil );
begin
   Create (SB_CERT_ALGORITHM_GOST_R3410_1994, CryptoProvider);
end;

constructor TElGOST94PublicKeyCrypto.Create(Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
   Create (CryptoProvider);
end;



 destructor  TElGOST94PublicKeyCrypto.Destroy;
begin
  inherited;
end;

{$ifdef SB_HAS_ECC}
////////////////////////////////////////////////////////////////////////////////
//  TElGOST2001KeyMaterial class

constructor TElGOST2001KeyMaterial.Create(Prov : TElCustomCryptoProvider);
begin
  inherited;
  Reset;
  FKey := FProvider.CreateKey(SB_ALGORITHM_PK_GOST_R3410_2001, 0);
end;

constructor TElGOST2001KeyMaterial.Create(Manager : TElCustomCryptoProviderManager; Prov : TElCustomCryptoProvider);
begin
  inherited;
  Reset;
  FKey := FProvider.CreateKey(SB_ALGORITHM_PK_GOST_R3410_2001, 0);
end;


 destructor  TElGOST2001KeyMaterial.Destroy;
begin
  inherited;
end;

procedure TElGOST2001KeyMaterial.Reset;
begin
  FStoreFormat := ksfRaw;
end;

function TElGOST2001KeyMaterial.GetValid : boolean;
begin
  Result := FKey.IsValid;
end;

function TElGOST2001KeyMaterial.GetBits : integer;
begin
  Result := FKey.Bits;
end;

function TElGOST2001KeyMaterial.GetParamSet : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_GOST_R3410_PARAMSET);
end;

procedure TElGOST2001KeyMaterial.SetParamSet(const Value : ByteArray);
begin
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_PARAMSET, Value);
end;

function TElGOST2001KeyMaterial.GetDigestParamSet : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_GOST_R3410_DIGEST_PARAMSET);
end;

procedure TElGOST2001KeyMaterial.SetDigestParamSet(const Value : ByteArray);
begin
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_DIGEST_PARAMSET, Value);
end;

function TElGOST2001KeyMaterial.GetEncryptionParamSet : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_GOST_R3410_ENCRYPTION_PARAMSET);
end;

procedure TElGOST2001KeyMaterial.SetEncryptionParamSet(const Value : ByteArray);
begin
  FKey.SetKeyProp(SB_KEYPROP_GOST_R3410_ENCRYPTION_PARAMSET, Value);
end;

function TElGOST2001KeyMaterial.GetQ : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_EC_Q, EmptyArray);
end;

procedure TElGOST2001KeyMaterial.SetQ(const Value : ByteArray);
begin
  FKey.SetKeyProp(SB_KEYPROP_EC_Q, Value);
end;

function TElGOST2001KeyMaterial.GetD : ByteArray;
begin
  Result := FKey.GetKeyProp(SB_KEYPROP_EC_D, EmptyArray);
end;

procedure TElGOST2001KeyMaterial.SetD(const Value : ByteArray);
begin
  FKey.SetKeyProp(SB_KEYPROP_EC_D, Value);
end;


procedure TElGOST2001KeyMaterial.Assign(Source: TElKeyMaterial);
begin
  if not (Source is TElGOST2001KeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SInvalidKeyMaterialType);
  FProvider.ReleaseKey(FKey);

  FKey := TElGOST2001KeyMaterial(Source).FKey.CryptoProvider.CloneKey(TElGOST2001KeyMaterial(Source).FKey);
end;

function TElGOST2001KeyMaterial.Clone :  TElKeyMaterial ;
var
  Res : TElKeyMaterial;
begin
  Res := TElGOST2001KeyMaterial.Create(FProvider);
  Res.Assign(Self);
  Result := Res;
end;

procedure TElGOST2001KeyMaterial.InternalGenerate(Bits : integer);
var
  ProgressFunc : TSBProgressFunc;
begin
  if Assigned(FWorkingThread) then
    ProgressFunc := TElPublicKeyMaterialWorkingThread(FWorkingThread).ProgressHandler
  else
    ProgressFunc := nil;

  FKey.Generate(Bits, nil, ProgressFunc);
end;

procedure TElGOST2001KeyMaterial.Generate;
begin
  InternalGenerate(0);
end;

procedure TElGOST2001KeyMaterial.LoadSecret(Buffer: pointer; Size: integer);
begin
  FKey.ImportSecret(Buffer, Size);
end;

procedure TElGOST2001KeyMaterial.SaveSecret(Buffer: pointer; var Size: integer);
begin
  FKey.ExportSecret(Buffer, Size);
end;

procedure TElGOST2001KeyMaterial.LoadPublic(Buffer: pointer; Size: integer);
begin
  FKey.ImportPublic(Buffer, Size);
end;

procedure TElGOST2001KeyMaterial.SavePublic(Buffer: pointer; var Size: integer);
begin
  FKey.ExportPublic(Buffer, Size);
end;

function TElGOST2001KeyMaterial.Equals(Source : TElKeyMaterial; PublicOnly : boolean): boolean;
begin
  Result := FKey.Equals(Source.Key, PublicOnly, nil);
end;

procedure TElGOST2001KeyMaterial.ClearSecret;
begin
  FKey.ClearSecret;
end;

procedure TElGOST2001KeyMaterial.ClearPublic;
begin
  FKey.ClearPublic;
end;

procedure TElGOST2001KeyMaterial.LoadParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  if (AlgorithmIdentifier is TElGOST3411WithGOST3410AlgorithmIdentifier) then
    Exit;

  if not (AlgorithmIdentifier is TElGOST3410AlgorithmIdentifier) then
    raise EElPublicKeyCryptoError.Create(SInvalidKeyParameters);

  ParamSet := TElGOST3410AlgorithmIdentifier(AlgorithmIdentifier).PublicKeyParamSet;
  DigestParamSet := TElGOST3410AlgorithmIdentifier(AlgorithmIdentifier).DigestParamSet;
  EncryptionParamSet := TElGOST3410AlgorithmIdentifier(AlgorithmIdentifier).EncryptionParamSet;  
end;

procedure TElGOST2001KeyMaterial.SaveParameters(AlgorithmIdentifier : TElAlgorithmIdentifier);
begin
  if not (AlgorithmIdentifier is TElGOST3410AlgorithmIdentifier) then
    raise EElPublicKeyCryptoError.Create(SInvalidKeyParameters);

  TElGOST3410AlgorithmIdentifier(AlgorithmIdentifier).PublicKeyParamSet := ParamSet;
  TElGOST3410AlgorithmIdentifier(AlgorithmIdentifier).DigestParamSet := DigestParamSet;
  TElGOST3410AlgorithmIdentifier(AlgorithmIdentifier).EncryptionParamSet := EncryptionParamSet;
end;

////////////////////////////////////////////////////////////////////////////////
// TElGOST2001PublicKeyCrypto class

function TElGOST2001PublicKeyCrypto.GetSupportsEncryption: boolean;
begin
  Result := true;
end;

function TElGOST2001PublicKeyCrypto.GetSupportsSigning: boolean;
begin
  Result := true;
end;

procedure TElGOST2001PublicKeyCrypto.SetKeyMaterial(Material : TElPublicKeyMaterial);
begin
  if FBusy then Exit;

  if not (Material is TElGOST2001KeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SInvalidKeyMaterialType);
  FKeyMaterial := Material;
end;

procedure TElGOST2001PublicKeyCrypto.SetUKM(const V : ByteArray);
begin
  FUKM := CloneArray(V);
end;

procedure TElGOST2001PublicKeyCrypto.SetEphemeralKey(const V : ByteArray);
begin
  FEphemeralKey := CloneArray(V);
end;

procedure TElGOST2001PublicKeyCrypto.SetCEKMAC(const V : ByteArray);
begin
  FCEKMAC := CloneArray(V);
end;

procedure TElGOST2001PublicKeyCrypto.SignInit(Detached: boolean);
var
  Params : TElCPParameters;
  Op : TSBPublicKeyOperation;
begin
  if not Assigned(FKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  if not FKeyMaterial.SecretKey then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  SetLength(FSpool, 0);
  Params := TElCPParameters.Create();
  try
    AdjustContextProps(Params);
    if Detached then Op := pkoSignDetached else Op := pkoSign;
    FContext := GetSuitableCryptoProvider(Op, SB_ALGORITHM_PK_GOST_R3410_2001, Params).SignInit(
      SB_ALGORITHM_PK_GOST_R3410_2001, FKeyMaterial.FKey, Detached, Params
    );
  finally
    FreeAndNil(Params);
  end;
end;

procedure TElGOST2001PublicKeyCrypto.SignUpdate( Buffer: pointer;
    Size: integer);
var
  OldLen, OutSize : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.SignUpdate(FContext, Buffer, Size, nil, OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.SignUpdate(FContext, Buffer, Size, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
end;

procedure TElGOST2001PublicKeyCrypto.SignFinal;
var
  OldLen, OutSize : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider;
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.SignFinal(FContext,  nil , OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.SignFinal(FContext, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
  WriteToOutput(@FSpool[0], Length(FSpool));
  FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;

procedure TElGOST2001PublicKeyCrypto.VerifyInit(Detached: boolean;
   Signature: pointer;  SigSize: integer);
var
  Params : TElCPParameters;
  Op : TSBPublicKeyOperation;
begin
  if not Assigned(FKeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  if not FKeyMaterial.PublicKey then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  SetLength(FSpool, 0);
  Params := TElCPParameters.Create();
  try
    AdjustContextProps(Params);
    if Detached then Op := pkoVerifyDetached else Op := pkoVerify;
    FContext := GetSuitableCryptoProvider(Op, SB_ALGORITHM_PK_GOST_R3410_2001, Params).VerifyInit(
      SB_ALGORITHM_PK_GOST_R3410_2001, FKeyMaterial.FKey, Signature, 
      SigSize, Params
    );
  finally
    FreeAndNil(Params);
  end;
end;

procedure TElGOST2001PublicKeyCrypto.VerifyUpdate( Buffer: pointer;  Size: integer);
var
  OldLen, OutSize : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.VerifyUpdate(FContext, Buffer, Size, nil, OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.VerifyUpdate(FContext, Buffer, Size, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
end;

function TElGOST2001PublicKeyCrypto.VerifyFinal : TSBPublicKeyVerificationResult;
var
  OutSize, OldLen : integer;
  R : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.VerifyFinal(FContext,  nil , OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  R := Prov.VerifyFinal(FContext, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
  case R of
    SB_VR_SUCCESS:
      Result := pkvrSuccess;
    SB_VR_INVALID_SIGNATURE:
      Result := pkvrInvalidSignature;
    SB_VR_KEY_NOT_FOUND:
      Result := pkvrKeyNotFound;
    else
      Result := pkvrFailure;
  end;
  FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;

procedure TElGOST2001PublicKeyCrypto.EncryptInit;
var
  Params : TElCPParameters;
begin
  if not (FKeyMaterial is TElGOST2001KeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  if not FKeyMaterial.SecretKey then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
    
  SetLength(FSpool, 0);
  Params := TElCPParameters.Create();
  try
    AdjustContextProps(Params);
    FContext := GetSuitableCryptoProvider(pkoEncrypt, SB_ALGORITHM_PK_GOST_R3410_2001, Params).EncryptInit(
      SB_ALGORITHM_PK_GOST_R3410_2001, 0, FKeyMaterial.FKey, Params);
  finally
    FreeAndNil(Params);
  end;
end;

procedure TElGOST2001PublicKeyCrypto.EncryptUpdate( Buffer: pointer;   Size: integer);
var
  OutSize, OldLen : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.EncryptUpdate(FContext, Buffer, Size, nil, OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.EncryptUpdate(FContext, Buffer, Size, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
end;

procedure TElGOST2001PublicKeyCrypto.EncryptFinal;
var
  SigSize, OldLen : integer;
  Prov : TElCustomCryptoProvider;
  ProgressFunc : TSBProgressFunc;
begin
  if Assigned(FWorkingThread) then
    ProgressFunc := TElPublicKeyCryptoWorkingThread(FWorkingThread).ProgressHandler
  else
    ProgressFunc := nil;
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  SigSize := 0;
  Prov.EncryptFinal(FContext, nil, SigSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + SigSize);
  Prov.EncryptFinal(FContext, @FSpool[OldLen], SigSize);
  SetLength(FSpool, OldLen + SigSize);
  WriteToOutput(@FSpool[0], OldLen + SigSize);

  SaveContextProps;
  
  FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;

procedure TElGOST2001PublicKeyCrypto.DecryptInit;
var
  Params : TElCPParameters;
begin
  if not (FKeyMaterial is TElGOST2001KeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  if not FKeyMaterial.SecretKey then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);
  SetLength(FSpool, 0);
  Params := TElCPParameters.Create;
  try
    AdjustContextProps(Params);
    FContext := GetSuitableCryptoProvider(pkoDecrypt, SB_ALGORITHM_PK_GOST_R3410_2001, Params).DecryptInit(
      SB_ALGORITHM_PK_GOST_R3410_2001, 0, FKeyMaterial.FKey, Params);
  finally
    FreeAndNil(Params);
  end;
end;

procedure TElGOST2001PublicKeyCrypto.DecryptUpdate( Buffer: pointer;   Size: integer);
var
  OutSize, OldLen : integer;
  Prov : TElCustomCryptoProvider;
begin
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  OutSize := 0;
  Prov.DecryptUpdate(FContext, Buffer, Size, nil, OutSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + OutSize);
  Prov.DecryptUpdate(FContext, Buffer, Size, @FSpool[OldLen], OutSize);
  SetLength(FSpool, OldLen + OutSize);
end;

procedure TElGOST2001PublicKeyCrypto.DecryptFinal;
var
  SigSize, OldLen : integer;
  Prov : TElCustomCryptoProvider;
  ProgressFunc : TSBProgressFunc;
begin
  if Assigned(FWorkingThread) then
    ProgressFunc := TElPublicKeyCryptoWorkingThread(FWorkingThread).ProgressHandler
  else
    ProgressFunc := nil;
  //Prov := GetSuitableCryptoProvider();
  Prov := FContext.CryptoProvider;
  SigSize := 0;
  Prov.DecryptFinal(FContext, nil, SigSize);
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + SigSize);
  Prov.DecryptFinal(FContext, @FSpool[OldLen], SigSize);
  SetLength(FSpool, OldLen + SigSize);
  WriteToOutput(@FSpool[0], OldLen + SigSize);
  FContext.CryptoProvider.ReleaseCryptoContext(FContext);
end;

function TElGOST2001PublicKeyCrypto.EstimateOutputSize( InBuffer: pointer;
    InSize: integer;
  Operation : TSBPublicKeyOperation): integer;
begin
  if not (KeyMaterial is TElGOST2001KeyMaterial) then
    raise EElPublicKeyCryptoError.Create(SBadKeyMaterial);

  if (Operation = pkoSignDetached) then
    Result := 64
  else if Operation = pkoVerify then
    Result := 0
  else if Operation = pkoEncrypt then
    Result := 32
  else if Operation = pkoDecrypt then
    Result := 32
  else
    raise EElPublicKeyCryptoError.Create(SUnsupportedOperation); 
end;

class function TElGOST2001PublicKeyCrypto.IsAlgorithmSupported(const OID: ByteArray): boolean;
begin
  Result := IsAlgorithmSupported(GetAlgorithmByOID(OID));
end;

class function TElGOST2001PublicKeyCrypto.IsAlgorithmSupported(Alg: integer): boolean;
begin
  Result := (Alg = SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_2001) or (Alg = SB_CERT_ALGORITHM_GOST_R3410_2001) or (Alg = SB_ALGORITHM_PK_GOST_R3410_2001);
end;

class function TElGOST2001PublicKeyCrypto.GetName() : string;
begin
  Result := 'GOST R 34.10-2001';
end;

class function TElGOST2001PublicKeyCrypto.GetDescription() : string;
begin
  Result := 'Implements GOST 34.10-2001 digital signature and key derivation operations.';
end;

procedure TElGOST2001PublicKeyCrypto.Reset;
begin
  FInputIsHash := true;
  FInputEncoding := pkeBinary;
  FOutputEncoding := pkeBinary;
  FHashAlg := SB_ALGORITHM_DGST_GOST_R3411_1994;
  SetLength(FUKM, 0);
  SetLength(FEphemeralKey, 0);
  SetLength(FCEKMAC, 0);
end;

procedure TElGOST2001PublicKeyCrypto.AdjustContextProps(Params : TElCPParameters);
begin
  inherited;
  Params.Add(SB_CTXPROP_HASH_ALGORITHM, GetOIDByHashAlgorithm(FHashAlg));
  if Length(FUKM) > 0 then
    Params.Add(SB_CTXPROP_GOST3410_UKM, FUKM);
  if Length(FEphemeralKey) > 0 then
    Params.Add(SB_CTXPROP_GOST3410_EPHEMERAL_KEY, FEphemeralKey);
  if Length(FCEKMAC) > 0 then
    Params.Add(SB_CTXPROP_GOST3410_CEK_MAC, FCEKMAC);
end;

procedure TElGOST2001PublicKeyCrypto.SaveContextProps;
begin
  inherited;

  FUKM := CloneArray(FContext.GetContextProp(SB_CTXPROP_GOST3410_UKM));
  FEphemeralKey := CloneArray(FContext.GetContextProp(SB_CTXPROP_GOST3410_EPHEMERAL_KEY));
  FCEKMAC := CloneArray(FContext.GetContextProp(SB_CTXPROP_GOST3410_CEK_MAC));
end;

constructor TElGOST2001PublicKeyCrypto.Create(const OID : ByteArray; CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited Create(CryptoProvider);
  
  if not IsAlgorithmSupported(OID) then
    raise EElPublicKeyCryptoError.Create(SUnsupportedAlgorithm);

  FHashAlg := SB_ALGORITHM_DGST_GOST_R3411_1994;
end;

constructor TElGOST2001PublicKeyCrypto.Create(Alg : integer; CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited Create(CryptoProvider);
  
  if not IsAlgorithmSupported(Alg) then
    raise EElPublicKeyCryptoError.Create(SUnsupportedAlgorithm);

  FHashAlg := SB_ALGORITHM_DGST_GOST_R3411_1994;
end;

constructor TElGOST2001PublicKeyCrypto.Create(CryptoProvider : TElCustomCryptoProvider  = nil );
begin
   Create (SB_ALGORITHM_PK_GOST_R3410_2001, CryptoProvider);
end;

constructor TElGOST2001PublicKeyCrypto.Create(const OID : ByteArray; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create(Manager, CryptoProvider);
  if not IsAlgorithmSupported(OID) then
    raise EElPublicKeyCryptoError.Create(SUnsupportedAlgorithm);

  FHashAlg := SB_ALGORITHM_DGST_GOST_R3411_1994;
end;

constructor TElGOST2001PublicKeyCrypto.Create(Alg : integer; Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create(Manager, CryptoProvider);
  if not IsAlgorithmSupported(Alg) then
    raise EElPublicKeyCryptoError.Create(SUnsupportedAlgorithm);

  FHashAlg := SB_ALGORITHM_DGST_GOST_R3411_1994;
end;

constructor TElGOST2001PublicKeyCrypto.Create(Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
   Create (SB_ALGORITHM_PK_GOST_R3410_2001, Manager, CryptoProvider);
end;



 // SB_JAVA

 destructor  TElGOST2001PublicKeyCrypto.Destroy;
begin
  inherited;
end;

 {$endif SB_HAS_ECC}

 {$endif SB_HAS_GOST}

initialization

  begin
    {$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
    SB_ALGSCHEME_PKCS1 := BytesOfString('pkcs#1');
    SB_ALGSCHEME_OAEP := BytesOfString('oaep');
    SB_ALGSCHEME_PSS := BytesOfString('pss');
     {$endif}
  end;


end.
