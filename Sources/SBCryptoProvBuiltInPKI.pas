(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBCryptoProvBuiltInPKI;

interface

uses
  SBStreams,
  Classes,
  SysUtils,
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBConstants,
  SBCryptoProv,
  SBCryptoProvUtils,
  SBCryptoProvBuiltIn,
  SBCryptoProvBuiltInHash,
  SBCryptoProvRS,
  SBRSA,
  SBDSA,
  {$ifdef SB_HAS_ECC}
  SBECDSA,
  SBECCommon,
  SBECMath,
   {$endif}
  {$ifdef SB_HAS_GOST}
  SBGOSTCommon,
  SBGOST2814789,
  SBGOST341094,
  SBGOST341001,
   {$endif}
  SBElgamal,
  SBMath,
  {$ifndef SB_NO_PKIASYNC}
  SBPKIAsync,
   {$endif SB_NO_PKIASYNC}
  SBASN1,
  SBASN1Tree;

type
  TSBBuiltInRSACryptoKeyFormat = (rsaPKCS1, rsaOAEP, rsaPSS);
  TElBuiltInRSACryptoKey = class(TElBuiltInCryptoKey)
  private
    FKeyBlob : ByteArray;
    FPublicKeyBlob : ByteArray;
    FM : ByteArray;
    FE : ByteArray;
    FD : ByteArray;
    FPassphrase : string;
    FPEMEncode : boolean;
    FStrLabel : ByteArray;
    FSaltSize : integer;
    FHashAlgorithm : integer;
    FMGFAlgorithm : integer;
    FTrailerField : integer;
    FSecretKey : boolean;
    FPublicKey : boolean;
    FKeyFormat : TSBBuiltInRSACryptoKeyFormat;
    FRawPublicKey : boolean;
    procedure RecalculatePublicKeyBlob(RawPublicKey : boolean);
    procedure TrimParams;
  protected
    FAntiTimingParams : TElRSAAntiTimingParams;
  protected
    function GetIsPublic: boolean; override;
    function GetIsSecret: boolean; override;
    function GetIsExportable: boolean; override;
    function GetIsPersistent: boolean; override;
    function GetIsValid: boolean; override;
    function GetBits : integer; override;
    function GetAlgorithm : integer; override;
    function GetKeyStorage : TElCustomCryptoKeyStorage; override;
    procedure InitAntiTimingParams;
  public
    constructor Create(CryptoProvider : TElCustomCryptoProvider); override; 
     destructor  Destroy; override;
    procedure Reset; override;
    {$ifndef SB_PGPSFX_STUB}
    procedure Generate(Bits : integer;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil); override;
     {$endif SB_PGPSFX_STUB}
    procedure ImportPublic(Buffer: pointer; Size: integer; Params : TElCPParameters = nil); override;
    procedure ImportSecret(Buffer: pointer; Size: integer; Params : TElCPParameters = nil); override;
    procedure ExportPublic(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil); override;
    procedure ExportSecret(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil); override;
    function Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoKey; override;
    function ClonePublic(Params : TElCPParameters  =  nil) : TElCustomCryptoKey; override;
    procedure ClearPublic; override;
    procedure ClearSecret; override;
    function GetKeyProp(const PropID : ByteArray; const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif}  {$endif}): ByteArray; override;
    procedure SetKeyProp(const PropID : ByteArray; const Value : ByteArray); override;
    function Equals(Source : TElCustomCryptoKey; PublicOnly : boolean;
      Params : TElCPParameters  =  nil): boolean; override;

  end;

  TElBuiltInDSACryptoKey = class(TElBuiltInCryptoKey)
  private
    FPublicKey : boolean;
    FSecretKey : boolean;
    FKeyBlob : ByteArray;
    FP : ByteArray;
    FQ : ByteArray;
    FG : ByteArray;
    FY : ByteArray;
    FX : ByteArray;
    FStrictKeyValidation : boolean;
    FHashAlgorithm : integer;
    {$ifndef SB_NO_PKIASYNC}
    FToken : TElPublicKeyComputationToken;
    FReleaseToken : boolean;
     {$endif}
    procedure TrimParams;
    procedure Generate(PBits, QBits : integer);   reintroduce;  overload; 
  protected
    function GetIsPublic: boolean; override;
    function GetIsSecret: boolean; override;
    function GetIsExportable: boolean; override;
    function GetIsPersistent: boolean; override;
    function GetIsValid: boolean; override;
    function GetBits : integer; override;
    function GetAlgorithm : integer; override;
    function GetKeyStorage : TElCustomCryptoKeyStorage; override;
  public
    constructor Create(CryptoProvider : TElCustomCryptoProvider); override; 
     destructor  Destroy; override;
    procedure Reset; override;

    {$ifndef SB_PGPSFX_STUB}
    procedure Generate(Bits : integer;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil);  overload;  override;
     {$endif SB_PGPSFX_STUB}

    procedure ImportPublic(Buffer: pointer; Size: integer; Params : TElCPParameters = nil); override;
    procedure ImportSecret(Buffer: pointer; Size: integer; Params : TElCPParameters = nil); override;
    procedure ExportPublic(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil); override;
    procedure ExportSecret(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil); override;
    function Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoKey; override;
    function ClonePublic(Params : TElCPParameters  =  nil) : TElCustomCryptoKey; override;
    procedure ClearPublic; override;
    procedure ClearSecret; override;
    function GetKeyProp(const PropID : ByteArray; const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif}  {$endif}): ByteArray; override;
    procedure SetKeyProp(const PropID : ByteArray; const Value : ByteArray); override;
    {$ifndef SB_NO_PKIASYNC}
    procedure PrepareForSigning(MultiUse : boolean  =  false); override;
    procedure CancelPreparation; override;
    function AsyncOperationFinished : boolean; override;
     {$endif}
    function Equals(Source : TElCustomCryptoKey; PublicOnly : boolean;
      Params : TElCPParameters  =  nil): boolean; override;
  end;

  TElBuiltInElgamalCryptoKey = class(TElBuiltInCryptoKey)
  private
    FP : ByteArray;
    FG : ByteArray;
    FY : ByteArray;
    FX : ByteArray;
    FPublicKey : boolean;
    FSecretKey : boolean;
    {$ifndef SB_NO_PKIASYNC}
    FToken : TElPublicKeyComputationToken;
    FReleaseToken : boolean;
     {$endif SB_NO_PKIASYNC}
    procedure TrimParams;
  protected
    function GetIsPublic: boolean; override;
    function GetIsSecret: boolean; override;
    function GetIsExportable: boolean; override;
    function GetIsPersistent: boolean; override;
    function GetIsValid: boolean; override;
    function GetBits : integer; override;
    function GetAlgorithm : integer; override;
    function GetKeyStorage : TElCustomCryptoKeyStorage; override;
  public
    constructor Create(CryptoProvider : TElCustomCryptoProvider); override; 
     destructor  Destroy; override;
    {$ifndef SB_PGPSFX_STUB}
    procedure Generate(Bits : integer;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil); override;
     {$endif SB_PGPSFX_STUB}
    procedure Reset; override;
    procedure ImportPublic(Buffer: pointer; Size: integer; Params : TElCPParameters = nil); override;
    procedure ImportSecret(Buffer: pointer; Size: integer; Params : TElCPParameters = nil); override;
    procedure ExportPublic(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil); override;
    procedure ExportSecret(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil); override;
    function Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoKey; override;
    function ClonePublic(Params : TElCPParameters  =  nil) : TElCustomCryptoKey; override;
    procedure ClearPublic; override;
    procedure ClearSecret; override;
    function GetKeyProp(const PropID : ByteArray; const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif}  {$endif}): ByteArray; override;
    procedure SetKeyProp(const PropID : ByteArray; const Value : ByteArray); override;
    {$ifndef SB_NO_PKIASYNC}
    procedure PrepareForEncryption(MultiUse : boolean  =  false); override;
    procedure PrepareForSigning(MultiUse : boolean  =  false); override;
    procedure CancelPreparation; override;
    function AsyncOperationFinished : boolean; override;
     {$endif SB_NO_PKIASYNC}
    function Equals(Source : TElCustomCryptoKey; PublicOnly : boolean;
      Params : TElCPParameters  =  nil): boolean; override;

  end;

  {$ifndef SB_NO_DH}
  TElBuiltInDHCryptoKey =  class(TElBuiltInCryptoKey)
  private
    FP : ByteArray; // modulus
    FG : ByteArray; // generator
    FX : ByteArray; // our secret value
    FY : ByteArray; // our public value
    FPeerY : ByteArray; // opponent's public value
    FSecretKey : boolean;
    FPublicKey : boolean;
  protected
    function GetIsPublic: boolean; override;
    function GetIsSecret: boolean; override;
    function GetIsExportable: boolean; override;
    function GetIsPersistent: boolean; override;
    function GetIsValid: boolean; override;
    function GetBits : integer; override;
    function GetAlgorithm : integer; override;
    function GetKeyStorage : TElCustomCryptoKeyStorage; override;
    
    procedure ExternalGenerate(Bits : integer; var P, G, X, Y : ByteArray);
    function ExternalGenerationSupported : boolean;
  public
    constructor Create(CryptoProvider : TElCustomCryptoProvider); override; 
     destructor  Destroy; override;
    procedure Generate(Bits : integer;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil); override;
    procedure Reset; override;
    procedure ImportPublic(Buffer: pointer; Size: integer; Params : TElCPParameters = nil); override;
    procedure ImportSecret(Buffer: pointer; Size: integer; Params : TElCPParameters = nil); override;
    procedure ExportPublic(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil); override;
    procedure ExportSecret(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil); override;
    function Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoKey; override;
    function ClonePublic(Params : TElCPParameters  =  nil) : TElCustomCryptoKey; override;
    procedure ClearPublic; override;
    procedure ClearSecret; override;
    function GetKeyProp(const PropID : ByteArray; const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif}  {$endif}): ByteArray; override;
    procedure SetKeyProp(const PropID : ByteArray; const Value : ByteArray); override;
    function Equals(Source : TElCustomCryptoKey; PublicOnly : boolean;
      Params : TElCPParameters  =  nil): boolean; override;
  end;
   {$endif SB_NO_DH}

  {$ifdef SB_HAS_ECC}
  TElBuiltInECCryptoKey = class(TElBuiltInCryptoKey)
  private
    FPublicKey : boolean;
    FSecretKey : boolean;
    FQX : ByteArray;
    FQY : ByteArray;
    FQ : ByteArray; 
    FD : ByteArray;
    FDomainParameters : TElECDomainParameters;
    FCompressPoints : boolean;
    FHybridPoints : boolean;

    FStrictKeyValidation : boolean;
    FHashAlgorithm : integer;

    function CheckDomainParameters : boolean;
  protected
    function GetIsPublic: boolean; override;
    function GetIsSecret: boolean; override;
    function GetIsExportable: boolean; override;
    function GetIsPersistent: boolean; override;
    function GetIsValid: boolean; override;
    function GetAlgorithm : integer; override;
    function GetKeyStorage : TElCustomCryptoKeyStorage; override;
    function GetBits : integer; override;
    
  public
    constructor Create(CryptoProvider : TElCustomCryptoProvider); override; 
     destructor  Destroy; override;
    procedure Reset; override;

    {$ifndef SB_PGPSFX_STUB}
    procedure Generate(Bits : integer;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil); override;
     {$endif}

    {$ifndef SB_PGPSFX_STUB}
    procedure ImportPublic(Buffer: pointer; Size: integer; Params : TElCPParameters = nil); override;
    procedure ImportSecret(Buffer: pointer; Size: integer; Params : TElCPParameters = nil); override;
    procedure ExportPublic(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil); override;
    procedure ExportSecret(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil); override;
     {$endif}
    
    function Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoKey; override;
    function ClonePublic(Params : TElCPParameters  =  nil) : TElCustomCryptoKey; override;
    procedure ClearPublic; override;
    procedure ClearSecret; override;
    function GetKeyProp(const PropID : ByteArray; const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif}  {$endif}): ByteArray; override;
    procedure SetKeyProp(const PropID : ByteArray; const Value : ByteArray); override;
    {$ifndef SB_NO_PKIASYNC}
    function AsyncOperationFinished : boolean; override;
     {$endif}
    
    function Equals(Source : TElCustomCryptoKey; PublicOnly : boolean;
      Params : TElCPParameters  =  nil): boolean; override;
  end;  
   {$endif} //SB_HAS_ECC

  {$ifdef SB_HAS_GOST}
  TElBuiltInGOST341094CryptoKey = class(TElBuiltInCryptoKey)
  private
    FP : ByteArray;
    FQ : ByteArray;
    FA : ByteArray;
    FY : ByteArray;
    FX : ByteArray;
    FC : ByteArray;
    FD : ByteArray;
    Fx0 : cardinal;
    FParamSet : ByteArray;
    FDigestParamSet : ByteArray;
    FEncryptionParamSet : ByteArray;
    FPublicKey : boolean;
    FSecretKey : boolean;
    procedure TrimParams;
  protected
    function GetIsPublic: boolean; override;
    function GetIsSecret: boolean; override;
    function GetIsExportable: boolean; override;
    function GetIsPersistent: boolean; override;
    function GetIsValid: boolean; override;
    function GetBits : integer; override;
    function GetAlgorithm : integer; override;
    function GetKeyStorage : TElCustomCryptoKeyStorage; override;
    procedure LoadParamset(const Paramset : ByteArray);
  public
    constructor Create(CryptoProvider : TElCustomCryptoProvider); override; 
     destructor  Destroy; override;
    procedure Generate(Bits : integer;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil); override;
    procedure Reset; override;
    procedure ImportPublic(Buffer: pointer; Size: integer; Params : TElCPParameters = nil); override;
    procedure ImportSecret(Buffer: pointer; Size: integer; Params : TElCPParameters = nil); override;
    procedure ExportPublic(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil); override;
    procedure ExportSecret(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil); override;
    function Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoKey; override;
    function ClonePublic(Params : TElCPParameters  =  nil) : TElCustomCryptoKey; override;
    procedure ClearPublic; override;
    procedure ClearSecret; override;
    function GetKeyProp(const PropID : ByteArray; const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif}  {$endif}): ByteArray; override;
    procedure SetKeyProp(const PropID : ByteArray; const Value : ByteArray); override;
    function Equals(Source : TElCustomCryptoKey; PublicOnly : boolean;
      Params : TElCPParameters  =  nil): boolean; override;
  end;

  {$ifdef SB_HAS_ECC}
  TElBuiltInGOST34102001CryptoKey = class(TElBuiltInCryptoKey)
  private
    FPublicKey : boolean;
    FSecretKey : boolean;
    FQX : ByteArray;
    FQY : ByteArray;
    FQ : ByteArray;
    FD : ByteArray;
    FDomainParameters : TElECDomainParameters;
    FParamSet : ByteArray;
    FDigestParamSet : ByteArray;
    FEncryptionParamSet : ByteArray;

    procedure LoadParamset(const Paramset : ByteArray);
  protected
    function GetIsPublic: boolean; override;
    function GetIsSecret: boolean; override;
    function GetIsExportable: boolean; override;
    function GetIsPersistent: boolean; override;
    function GetIsValid: boolean; override;
    function GetAlgorithm : integer; override;
    function GetKeyStorage : TElCustomCryptoKeyStorage; override;
    function GetBits : integer; override;
  public
    constructor Create(CryptoProvider : TElCustomCryptoProvider); override; 
     destructor  Destroy; override;
    procedure Reset; override;
    procedure Generate(Bits : integer;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil); override;
    procedure ImportPublic(Buffer: pointer; Size: integer; Params : TElCPParameters = nil); override;
    procedure ImportSecret(Buffer: pointer; Size: integer; Params : TElCPParameters = nil); override;
    procedure ExportPublic(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil); override;
    procedure ExportSecret(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil); override;
    function Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoKey; override;
    function ClonePublic(Params : TElCPParameters  =  nil) : TElCustomCryptoKey; override;
    procedure ClearPublic; override;
    procedure ClearSecret; override;
    function Equals(Source : TElCustomCryptoKey; PublicOnly : boolean;
      Params : TElCPParameters  =  nil): boolean; override;
    function GetKeyProp(const PropID : ByteArray; const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif}  {$endif}): ByteArray; override;
    procedure SetKeyProp(const PropID : ByteArray; const Value : ByteArray); override;
  end;
   {$endif} //SB_HAS_ECC
   {$endif} //SB_HAS_GOST

  TSBBuiltInPublicKeyOperation = 
   (pkoEncrypt, pkoDecrypt, pkoSign, pkoSignDetached,
    pkoVerify, pkoVerifyDetached);

  // base class for other public key encryption classes. Do not instantiate.
  TElBuiltInPublicKeyCrypto = class
  protected
    FKeyMaterial : TElCustomCryptoKey;
    FOutput : ByteArray;
    FOutputStream : TElStream;
    FOutputIsStream : boolean;
    FFinished : boolean;
    FInputIsHash : boolean;
    FCryptoProvider : TElCustomCryptoProvider;
  protected
    function GetSupportsEncryption: boolean; virtual;
    function GetSupportsSigning: boolean; virtual;
    procedure SetKeyMaterial(Material : TElCustomCryptoKey); virtual;
    procedure WriteToOutput( Buffer: pointer;
        Size: integer); virtual;
    procedure Reset; virtual;
    procedure PrepareForOperation; virtual;
    class function IsAlgorithmSupported(Alg: integer): boolean;  overload;  virtual;
    class function IsAlgorithmSupported(const OID: ByteArray): boolean;  overload;  virtual;
    class function GetName() : string; virtual;
    class function GetDescription() : string; virtual;
  public
    constructor Create(const OID : ByteArray);  overload;  virtual;
    constructor Create(Alg : integer);  overload;  virtual;
    constructor Create;  overload;  virtual;
     destructor  Destroy; override;
    {$ifndef SB_PGPSFX_STUB}
    procedure SignInit(Detached: boolean); virtual;
    procedure SignUpdate( Buffer: pointer;
        Size: integer); virtual;
    procedure SignFinal(Buffer: pointer; var Size: integer); virtual;
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
    function VerifyFinal : integer; virtual;
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
    function Verify(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
      var OutSize: integer): integer; overload;
    function VerifyDetached(InBuffer: pointer; InSize: integer; SigBuffer: pointer;
      SigSize: integer): integer; overload;
    {$ifndef SB_PGPSFX_STUB}
    procedure Encrypt(InStream, OutStream : TElStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});  overload; 
     {$endif SB_PGPSFX_STUB}
    procedure Decrypt(InStream, OutStream : TElStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});  overload; 
    {$ifndef SB_PGPSFX_STUB}
    procedure Sign(InStream, OutStream : TElStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});  overload; 
    procedure SignDetached(InStream, OutStream : TElStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});  overload; 
     {$endif SB_PGPSFX_STUB}
    function Verify(InStream, OutStream : TElStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}): integer;  overload; 
    function VerifyDetached(InStream, SigStream : TElStream;
      InCount : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif};
      SigCount : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}): integer;  overload; 
    function EstimateOutputSize( InBuffer: pointer;
        InSize: Int64;
      Operation : TSBBuiltInPublicKeyOperation): Int64;  overload;  virtual;
    function EstimateOutputSize(InSize: Int64; Operation: TSBBuiltInPublicKeyOperation): Int64;  overload;  virtual;

    property KeyMaterial : TElCustomCryptoKey read FKeyMaterial write SetKeyMaterial;
    property SupportsEncryption : boolean read GetSupportsEncryption;
    property SupportsSigning : boolean read GetSupportsSigning;
    property InputIsHash : boolean read FInputIsHash write FInputIsHash;
  end;

  TElBuiltInPublicKeyCryptoClass =  class of TElBuiltInPublicKeyCrypto;

  TSBBuiltInRSAPublicKeyCryptoType = 
    (rsapktPKCS1, rsapktOAEP, rsapktPSS, rsapktSSL3);

  TElBuiltInRSAPublicKeyCrypto = class(TElBuiltInPublicKeyCrypto)
  private
    FOID : ByteArray;
    FSupportsEncryption : boolean;
    FSupportsSigning : boolean;
    FCryptoType : TSBBuiltInRSAPublicKeyCryptoType;
    FUseAlgorithmPrefix : boolean;
    FSpool : ByteArray;
    FHashFunction : TElBuiltInHashFunction;
    FSignature : ByteArray;
    FHashFuncOID : ByteArray;
    FHashAlgorithm : integer;
    FMGFAlgorithm : integer;
    FSaltSize : integer;
    FTrailerField : integer;
    function GetUsedHashFunction: integer;
    function GetUsedHashFunctionOID: ByteArray;
    procedure SetHashFuncOID(const V : ByteArray);
    function AddAlgorithmPrefix(const Hash: ByteArray): ByteArray;
    function RemoveAlgorithmPrefix(const Value: ByteArray; var HashAlg : ByteArray;
      var HashPar : ByteArray): ByteArray;
    function GetAntiTimingParams(KM : TElCustomCryptoKey): TElRSAAntiTimingParams;
  protected
    function GetSupportsEncryption: boolean; override;
    function GetSupportsSigning: boolean; override;
    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;
    procedure SetCryptoType(Value : TSBBuiltInRSAPublicKeyCryptoType);
    class function IsAlgorithmSupported(Alg: integer): boolean;  overload;  override;
    class function IsAlgorithmSupported(const OID: ByteArray): boolean;  overload;  override;
    class function GetName() : string; override;
    class function GetDescription() : string; override;
    procedure WriteToOutput( Buffer: pointer;
        Size: integer); override;
    procedure Reset; override;
    function AlgorithmPrefixNeeded: boolean;
  public
    constructor Create(const OID : ByteArray);  overload;  override;
    constructor Create(Alg : integer);  overload;  override;
    constructor Create;  overload;  override;
     destructor  Destroy; override;
    {$ifndef SB_PGPSFX_STUB}
    procedure SignInit(Detached: boolean); override;
    procedure SignUpdate( Buffer: pointer;
        Size: integer); override;
    procedure SignFinal(Buffer: pointer; var Size: integer); override;
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
    function VerifyFinal : integer; override;
    function EstimateOutputSize( InBuffer: pointer;
        InSize: Int64;
      Operation : TSBBuiltInPublicKeyOperation): Int64; override;
    property CryptoType : TSBBuiltInRSAPublicKeyCryptoType read FCryptoType
      write SetCryptoType;
    property UseAlgorithmPrefix : boolean read FUseAlgorithmPrefix write FUseAlgorithmPrefix;
    property HashFuncOID : ByteArray read FHashFuncOID write SetHashFuncOID;
    property HashAlgorithm : integer read FHashAlgorithm write FHashAlgorithm;
    property SaltSize : integer read FSaltSize write FSaltSize;
    property MGFAlgorithm : integer read FMGFAlgorithm write FMGFAlgorithm;
    property TrailerField : integer read FTrailerField write FTrailerField;
  end;

  TElBuiltInDSAPublicKeyCrypto = class(TElBuiltInPublicKeyCrypto)
  protected
    FOID : ByteArray;
    FSpool : ByteArray;
    FHashFunction : TElBuiltInHashFunction;
    FSignature : ByteArray;
    function GetUsedHashFunction: integer;
  protected
    function GetSupportsEncryption: boolean; override;
    function GetSupportsSigning: boolean; override;
    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;
    class function IsAlgorithmSupported(Alg: integer): boolean;  overload;  override;
    class function IsAlgorithmSupported(const OID: ByteArray): boolean;  overload;  override;
    class function GetName() : string; override;
    class function GetDescription() : string; override;
    procedure WriteToOutput( Buffer: pointer;
        Size: integer); override;
    procedure Reset; override;
  public
    constructor Create(const OID : ByteArray);  overload;  override;
    constructor Create(Alg : integer);  overload;  override;
    constructor Create;  overload;  override;
     destructor  Destroy; override;
    procedure EncodeSignature(R : pointer; RSize : integer; S : pointer; SSize : integer;
      Sig : pointer; var SigSize : integer);
    procedure DecodeSignature(Sig : pointer; SigSize : integer; R : pointer;
      var RSize : integer; S : pointer; var SSize : integer);
    {$ifndef SB_PGPSFX_STUB}
    procedure SignInit(Detached: boolean); override;
    procedure SignUpdate( Buffer: pointer;
        Size: integer); override;
    procedure SignFinal(Buffer: pointer; var Size: integer); override;
     {$endif SB_PGPSFX_STUB}
    procedure VerifyInit(Detached: boolean;  Signature: pointer;
        SigSize: integer); override;
    procedure VerifyUpdate( Buffer: pointer;
        Size: integer); override;
    function VerifyFinal : integer; override;
    function EstimateOutputSize( InBuffer: pointer;
        InSize: Int64;
      Operation : TSBBuiltInPublicKeyOperation): Int64; override;
  end;

  TElBuiltInElgamalPublicKeyCrypto = class(TElBuiltInPublicKeyCrypto)
  private
    FSpool : ByteArray;
    FHashFunction : TElBuiltInHashFunction;
    FSignature : ByteArray;
    FHashAlgorithm : integer;
  protected
    function GetSupportsEncryption: boolean; override;
    function GetSupportsSigning: boolean; override;
    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;
    class function IsAlgorithmSupported(Alg: integer): boolean;  overload;  override;
    class function IsAlgorithmSupported(const OID: ByteArray): boolean;  overload;  override;
    class function GetName() : string; override;
    class function GetDescription() : string; override;
    procedure WriteToOutput( Buffer: pointer;
        Size: integer); override;
    procedure Reset; override; 
  public
    constructor Create(const OID : ByteArray);  overload;  override;
    constructor Create(Alg : integer);  overload;  override;
    constructor Create;  overload;  override;
     destructor  Destroy; override;
    {$ifndef SB_PGPSFX_STUB}
    procedure SignInit(Detached: boolean); override;
    procedure SignUpdate( Buffer: pointer;
        Size: integer); override;
    procedure SignFinal(Buffer: pointer; var Size: integer); override;
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
    function VerifyFinal : integer; override;
    function EstimateOutputSize( InBuffer: pointer;
        InSize: Int64;
      Operation : TSBBuiltInPublicKeyOperation): Int64; override;
    property HashAlgorithm : integer read FHashAlgorithm write FHashAlgorithm;
  end;

  {$ifndef SB_NO_DH}
  TElBuiltInDHPublicKeyCrypto = class(TElBuiltInPublicKeyCrypto)
  private
    FSpool : ByteArray;
  protected
    function GetSupportsEncryption: boolean; override;
    function GetSupportsSigning: boolean; override;
    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;
    class function IsAlgorithmSupported(Alg: integer): boolean;  overload;  override;
    class function IsAlgorithmSupported(const OID: ByteArray): boolean;  overload;  override;
    class function GetName() : string; override;
    class function GetDescription() : string; override;
    procedure WriteToOutput( Buffer: pointer;
        Size: integer); override;
    procedure Reset; override;
  public
    constructor Create(const OID : ByteArray);  overload;  override;
    constructor Create(Alg : integer);  overload;  override;
    constructor Create;  overload;  override;
     destructor  Destroy; override;
    procedure EncryptInit; override;
    procedure EncryptUpdate( Buffer: pointer;
        Size: integer); override;
    procedure EncryptFinal; override;
    procedure DecryptInit; override;
    procedure DecryptUpdate( Buffer: pointer;
        Size: integer); override;
    procedure DecryptFinal; override;
    function EstimateOutputSize( InBuffer: pointer;
        InSize: Int64;
      Operation : TSBBuiltInPublicKeyOperation): Int64; override;
  end;
   {$endif SB_NO_DH}

  {$ifdef SB_HAS_ECC}
  TElBuiltInECDSAPublicKeyCrypto = class(TElBuiltInPublicKeyCrypto)
  protected
    FOID : ByteArray;
    FHashAlgorithm : integer;
    FSpool : ByteArray;
    FHashFunction : TElBuiltInHashFunction;
    FSignature : ByteArray;
    FPlainECDSA : boolean;
    function GetUsedHashFunction: integer;
  protected
    function GetSupportsEncryption: boolean; override;
    function GetSupportsSigning: boolean; override;
    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;
    class function IsAlgorithmSupported(Alg: integer): boolean;  overload;  override;
    class function IsAlgorithmSupported(const OID: ByteArray): boolean;  overload;  override;
    class function GetName() : string; override;
    class function GetDescription() : string; override;
    procedure WriteToOutput( Buffer: pointer;
        Size: integer); override;
    procedure Reset; override;
  public
    constructor Create(const OID : ByteArray);  overload;  override;
    constructor Create(Alg : integer);  overload;  override;
    constructor Create;  overload;  override;
     destructor  Destroy; override;
    procedure EncodeSignature(R : pointer; RSize : integer; S : pointer; SSize : integer;
      Sig : pointer; var SigSize : integer);
    procedure DecodeSignature(Sig : pointer; SigSize : integer; R : pointer;
      var RSize : integer; S : pointer; var SSize : integer);

    {$ifndef SB_PGPSFX_STUB}
    procedure SignInit(Detached: boolean); override;
    procedure SignUpdate( Buffer: pointer;
        Size: integer); override;
    procedure SignFinal(Buffer: pointer; var Size: integer); override;
     {$endif}
    
    procedure VerifyInit(Detached: boolean;  Signature: pointer;
        SigSize: integer); override;
    procedure VerifyUpdate( Buffer: pointer;
        Size: integer); override;
    function VerifyFinal : integer; override;
    function EstimateOutputSize( InBuffer: pointer;
        InSize: Int64;
      Operation : TSBBuiltInPublicKeyOperation): Int64; override;
    property HashAlgorithm : integer read FHashAlgorithm write FHashAlgorithm;
    property PlainECDSA : boolean read FPlainECDSA write FPlainECDSA;  
  end; 

  TElBuiltInECDHPublicKeyCrypto = class(TElBuiltInPublicKeyCrypto)
  protected
    FSpool : ByteArray;
    function GetSupportsEncryption: boolean; override;
    function GetSupportsSigning: boolean; override;
    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;
    class function IsAlgorithmSupported(Alg: integer): boolean;  overload;  override;
    class function IsAlgorithmSupported(const OID: ByteArray): boolean;  overload;  override;
    class function GetName() : string; override;
    class function GetDescription() : string; override;
    procedure WriteToOutput( Buffer: pointer;
        Size: integer); override;
    procedure Reset; override;
  public
    constructor Create(const OID : ByteArray);  overload;  override;
    constructor Create(Alg : integer);  overload;  override;
    constructor Create;  overload;  override;
     destructor  Destroy; override;

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
        InSize: Int64;
      Operation : TSBBuiltInPublicKeyOperation): Int64; override;
  end;
   {$endif}  //SB_HAS_ECC

  {$ifdef SB_HAS_GOST}
  TElBuiltInGOST94PublicKeyCrypto = class(TElBuiltInPublicKeyCrypto)
  private
    FSpool : ByteArray;
    FHashFunction : TElBuiltInHashFunction;
    FSignature : ByteArray;
    FHashAlgorithm : integer;
  protected
    procedure Param_to_PLInt(const PropID: ByteArray; var Res: PLInt);
    function GetSupportsEncryption: boolean; override;
    function GetSupportsSigning: boolean; override;
    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;
    class function IsAlgorithmSupported(Alg: integer): boolean;  overload;  override;
    class function IsAlgorithmSupported(const OID: ByteArray): boolean;  overload;  override;
    class function GetName() : string; override;
    class function GetDescription() : string; override;
    procedure WriteToOutput( Buffer: pointer;
        Size: integer); override;
    procedure Reset; override;
  public
    constructor Create(const OID : ByteArray);  overload;  override;
    constructor Create(Alg : integer);  overload;  override;
    constructor Create;  overload;  override;
     destructor  Destroy; override;
    procedure SignInit(Detached: boolean); override;
    procedure SignUpdate( Buffer: pointer;
        Size: integer); override;
    procedure SignFinal(Buffer: pointer; var Size: integer); override;

    procedure VerifyInit(Detached: boolean;  Signature: pointer;
        SigSize: integer); override;
    procedure VerifyUpdate( Buffer: pointer;  Size: integer); override;
    function VerifyFinal : integer; override;
    function EstimateOutputSize( InBuffer: pointer;
        InSize: Int64;
      Operation : TSBBuiltInPublicKeyOperation): Int64; override;
    property HashAlgorithm : integer read FHashAlgorithm write FHashAlgorithm;
  end;

  {$ifdef SB_HAS_ECC}
  TElBuiltInGOST2001PublicKeyCrypto = class(TElBuiltInPublicKeyCrypto)
  private
    FSpool : ByteArray;
    FHashFunction : TElBuiltInHashFunction;
    FSignature : ByteArray;
    FHashAlgorithm : integer;
    FUKM : ByteArray;
    FEphemeralKey : ByteArray;
    FCEKMAC : ByteArray;
  protected
    function GetSupportsEncryption: boolean; override;
    function GetSupportsSigning: boolean; override;
    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;
    class function IsAlgorithmSupported(Alg: integer): boolean;  overload;  override;
    class function IsAlgorithmSupported(const OID: ByteArray): boolean;  overload;  override;
    class function GetName() : string; override;
    class function GetDescription() : string; override;
    procedure WriteToOutput( Buffer: pointer;
        Size: integer); override;
    procedure Reset; override;
    function DeriveKEK : ByteArray;
    procedure SetUKM(const V : ByteArray);
    procedure SetCEKMAC(const V : ByteArray);
    procedure SetEphemeralKey(const V : ByteArray);
  public
    constructor Create(const OID : ByteArray);  overload;  override;
    constructor Create(Alg : integer);  overload;  override;
    constructor Create;  overload;  override;
     destructor  Destroy; override;

    { encryption/decryption actually is key derivation }
    procedure EncryptInit; override;
    procedure EncryptUpdate( Buffer: pointer;
        Size: integer); override;
    procedure EncryptFinal; override;
    procedure DecryptInit; override;
    procedure DecryptUpdate( Buffer: pointer;
        Size: integer); override;
    procedure DecryptFinal; override;
    procedure SignInit(Detached: boolean); override;
    procedure SignUpdate( Buffer: pointer;
        Size: integer); override;
    procedure SignFinal(Buffer: pointer; var Size: integer); override;

    procedure VerifyInit(Detached: boolean;  Signature: pointer;
        SigSize: integer); override;
    procedure VerifyUpdate( Buffer: pointer;  Size: integer); override;
    function VerifyFinal : integer; override;
    function EstimateOutputSize( InBuffer: pointer;
        InSize: Int64;
      Operation : TSBBuiltInPublicKeyOperation): Int64; override;
    property HashAlgorithm : integer read FHashAlgorithm write FHashAlgorithm;
    property UKM : ByteArray read FUKM write SetUKM;
    property CEKMAC : ByteArray read FCEKMAC write SetCEKMAC;
    property EphemeralKey : ByteArray read FEphemeralKey write SetEphemeralKey;     
  end;
   {$endif SB_HAS_ECC}

   {$endif SB_HAS_GOST}

implementation

uses
  SBRDN,
  SBRandom;


{$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
 {$else}
var
 {$endif}

  SB_KEYPROP_RSA_KEYFORMAT_PKCS1 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'pkcs#1' {$endif}; 
  SB_KEYPROP_RSA_KEYFORMAT_OAEP : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'oaep' {$endif}; 
  SB_KEYPROP_RSA_KEYFORMAT_PSS : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'pss' {$endif}; 

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

////////////////////////////////////////////////////////////////////////////////
// TElBuiltInRSACryptoKey class

constructor TElBuiltInRSACryptoKey.Create(CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
  FAntiTimingParams := TElRSAAntiTimingParams.Create();
  Reset;
  FRawPublicKey := false;
end;

 destructor  TElBuiltInRSACryptoKey.Destroy;
begin
  FreeAndNil(FAntiTimingParams);
  inherited;
end;

procedure TElBuiltInRSACryptoKey.Reset;
begin
  inherited;
  FPublicKey := false;
  FSecretKey := false;
  SetLength(FKeyBlob, 0);
  SetLength(FPublicKeyBlob, 0);
  SetLength(FM, 0);
  SetLength(FE, 0);
  SetLength(FD, 0);
  FPEMEncode := false;
  FHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
  FStrLabel := EmptyArray;
  FSaltSize := 20;
  FMGFAlgorithm := SB_CERT_MGF1;
  FTrailerField := 1;
  FKeyFormat := rsaPKCS1;
  FAntiTimingParams.Reset;
end;

procedure TElBuiltInRSACryptoKey.InitAntiTimingParams;
begin
  FAntiTimingParams.Init(FM, FE);
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInRSACryptoKey.Generate(Bits : integer;
  Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil);
var
  MSize, ESize, DSize, BSize : integer;
  UseExtGenerator : boolean;
  BoolRes : boolean;
begin
  if (FCryptoProvider <> nil) and (FCryptoProvider.Options.MaxPublicKeySize > 0)
    and (Bits > FCryptoProvider.Options.MaxPublicKeySize) then
    raise EElBuiltInCryptoProviderError.Create(SPublicKeyTooLong);
  if (FCryptoProvider is TElBuiltInCryptoProvider) then
    UseExtGenerator := TElBuiltInCryptoProviderOptions(TElBuiltInCryptoProvider(FCryptoProvider).Options).UsePlatformKeyGeneration and ((SBRSA.ExternalGenerationSupported) or (not TElBuiltInCryptoProviderOptions(TElBuiltInCryptoProvider(FCryptoProvider).Options).RollbackToBuiltInKeyGeneration))
  else
    UseExtGenerator := false;

  Reset;
  MSize := 0;
  ESize := 0;
  DSize := 0;
  BSize := 0;
  if UseExtGenerator then
    SBRSA.ExternalGenerate(Bits, nil, MSize, nil, ESize, nil, DSize, nil, BSize)
  else
    SBRSA.Generate(Bits, nil, MSize, nil, ESize, nil, DSize, nil, BSize);
  SetLength(FM, MSize);
  SetLength(FE, ESize);
  SetLength(FD, DSize);
  SetLength(FKeyBlob, BSize);
  if UseExtGenerator then
    BoolRes :=
    SBRSA.ExternalGenerate(Bits, @FM[0], MSize, @FE[0], ESize, @FD[0], DSize,
      @FKeyBlob[0], BSize)
  else
    BoolRes :=
    SBRSA.Generate(Bits, @FM[0], MSize, @FE[0], ESize, @FD[0], DSize,
      @FKeyBlob[0], BSize);
  if not BoolRes then
    raise EElCryptoProviderError.Create(SInternalError);
  SetLength(FM, MSize);
  SetLength(FE, ESize);
  SetLength(FD, DSize);
  SetLength(FKeyBlob, BSize);
  TrimParams;
  FSecretKey := true;
  FPublicKey := true;
  RecalculatePublicKeyBlob(false);
  InitAntiTimingParams;
end;
 {$endif SB_PGPSFX_STUB}

procedure TElBuiltInRSACryptoKey.ImportPublic(Buffer: pointer; Size: integer; Params : TElCPParameters = nil);
var
  PMSize, PESize : integer;
  AlgID : ByteArray;
begin

  Reset;
  PMSize := 0;
  PESize := 0;
  SBRSA.DecodePublicKey(Buffer, Size, nil, PMSize, nil, PESize, AlgID, FRawPublicKey);

  if (PMSize <= 0) or (PESize <= 0) then
    raise EElCryptoKeyError.Create(SInvalidPublicKey);

  SetLength(FM, PMSize);
  SetLength(FE, PESize);
  if SBRSA.DecodePublicKey(Buffer, Size, @FM[0], PMSize, @FE[0], PESize, AlgID, FRawPublicKey) then
  begin
    FPublicKey := true;
    SetLength(FPublicKeyBlob, Size);
    SBMove(Buffer^, FPublicKeyBlob[0], Length(FPublicKeyBlob));
    TrimParams;
    InitAntiTimingParams;
  end
  else
    raise EElCryptoKeyError.Create(SInvalidPublicKey);

end;

procedure TElBuiltInRSACryptoKey.ImportSecret(Buffer: pointer; Size: integer; Params : TElCPParameters = nil);
var
  PMSize, PESize, PDSize : integer;
begin

  Reset;
  PMSize := 0;
  PESize := 0;
  PDSize := 0;
  SBRSA.DecodePrivateKey(Buffer, Size, nil, PMSize, nil, PESize, nil,
    PDSize);

  if (PMSize <= 0) or (PESize <= 0) or (PDSize <= 0) then
    raise EElCryptoKeyError.Create(SInvalidSecretKey);

  SetLength(FM, PMSize);
  SetLength(FE, PESize);
  SetLength(FD, PDSize);
  if SBRSA.DecodePrivateKey(Buffer, Size, @FM[0], PMSize, @FE[0], PESize,
    @FD[0], PDSize) then
  begin
    FPublicKey := true;
    FSecretKey := true;
    SetLength(FKeyBlob, Size);
    SBMove(Buffer^, FKeyBlob[0], Length(FKeyBlob));
    TrimParams;
    RecalculatePublicKeyBlob(false);
    InitAntiTimingParams;
  end
  else
    raise EElCryptoKeyError.Create(SInvalidSecretKey);

end;

procedure TElBuiltInRSACryptoKey.ExportPublic(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil);
begin
  RecalculatePublicKeyBlob(FRawPublicKey);
  if Size = 0 then
    Size := Length(FPublicKeyBlob)
  else if Size < Length(FPublicKeyBlob) then
    raise EElCryptoKeyError.Create(SBufferTooSmall)
  else
  begin
    Size := Length(FPublicKeyBlob);
    SBMove(FPublicKeyBlob[0], Buffer^, Size);
  end;
end;

procedure TElBuiltInRSACryptoKey.ExportSecret(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil);
begin
  if Size = 0 then
    Size := Length(FKeyBlob)
  else if Size < Length(FKeyBlob) then
    raise EElCryptoKeyError.Create(SBufferTooSmall)
  else
  begin
    Size := Length(FKeyBlob);
    SBMove(FKeyBlob[0], Buffer^, Size);
  end
end;

function TElBuiltInRSACryptoKey.Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoKey;
var
  Res : TElBuiltInRSACryptoKey;
begin
  Res := TElBuiltInRSACryptoKey.Create(FCryptoProvider);
  Res.FKeyBlob := CloneArray(FKeyBlob);
  Res.FPublicKeyBlob := CloneArray(FPublicKeyBlob);
  Res.FM := CloneArray(FM);
  Res.FE := CloneArray(FE);
  Res.FD := CloneArray(FD);
  Res.FPassphrase := FPassphrase;
  Res.FPEMEncode := FPEMEncode;
  Res.FStrLabel := CloneArray(FStrLabel);
  Res.FSaltSize := FSaltSize;
  Res.FHashAlgorithm := FHashAlgorithm;
  Res.FMGFAlgorithm := FMGFAlgorithm;
  Res.FTrailerField := FTrailerField;
  Res.FPublicKey := FPublicKey;
  Res.FSecretKey := FSecretKey;
  Res.RecalculatePublicKeyBlob(false);
  Res.InitAntiTimingParams;
  Result := Res;
end;

function TElBuiltInRSACryptoKey.Equals(Source : TElCustomCryptoKey; PublicOnly : boolean;
      Params : TElCPParameters  =  nil): boolean;
var
  B : ByteArray;
begin

  Result := false;
  if Self.Algorithm <> Source.Algorithm then exit;
  Result := true;
  Result := Result and
    (Self.GetKeyProp(SB_KEYPROP_MGF_ALGORITHM) = Source.GetKeyProp(SB_KEYPROP_MGF_ALGORITHM)) and
    (Self.GetKeyProp(SB_KEYPROP_KEYFORMAT) = Source.GetKeyProp(SB_KEYPROP_KEYFORMAT));
  B := Source.GetKeyProp(SB_KEYPROP_RSA_M);
  Result := Result and  (Length(FM) = Length(B)) and
     (CompareMem(@FM[0], @B[0], Length(FM)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_RSA_E);
  Result := Result and  (Length(FE) = Length(B)) and
     (CompareMem(@FE[0], @B[0], Length(FE)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_RSA_D);
  Result := Result and  (Length(FD) = Length(B)) and
     (CompareMem(@FD[0], @B[0], Length(FD)))
     ;

end;

function TElBuiltInRSACryptoKey.ClonePublic(Params : TElCPParameters  =  nil) : TElCustomCryptoKey;
var
  Res : TElBuiltInRSACryptoKey;
begin
  Res := TElBuiltInRSACryptoKey.Create(FCryptoProvider);
  Res.FPublicKeyBlob := CloneArray(FPublicKeyBlob);
  Res.FM := CloneArray(FM);
  Res.FE := CloneArray(FE);
  Res.FD := CloneArray(FD);
  Res.FPassphrase := FPassphrase;
  Res.FPEMEncode := FPEMEncode;
  Res.FStrLabel := CloneArray(FStrLabel);
  Res.FSaltSize := FSaltSize;
  Res.FHashAlgorithm := FHashAlgorithm;
  Res.FMGFAlgorithm := FMGFAlgorithm;
  Res.FTrailerField := FTrailerField;
  Res.FPublicKey := FPublicKey;
  Res.FSecretKey := false;
  Res.RecalculatePublicKeyBlob(false);
  Res.InitAntiTimingParams;
  Result := Res;
end;

function TElBuiltInRSACryptoKey.GetIsPublic: boolean;
begin
  Result := FPublicKey;
end;

function TElBuiltInRSACryptoKey.GetIsSecret: boolean;
begin
  Result := FSecretKey;
end;

function TElBuiltInRSACryptoKey.GetIsExportable: boolean;
begin
  Result := true;
end;

function TElBuiltInRSACryptoKey.GetIsPersistent: boolean;
begin
  Result := false;
end;

function TElBuiltInRSACryptoKey.GetIsValid: boolean;
begin
  if FSecretKey then
    Result := SBRSA.IsValidKey(@FKeyBlob[0], Length(FKeyBlob))
  else
    Result := true;
end;

function TElBuiltInRSACryptoKey.GetBits : integer;
begin
  Result := Length(FM) shl 3;
end;

function TElBuiltInRSACryptoKey.GetAlgorithm : integer;
begin
  Result := SB_ALGORITHM_PK_RSA;
end;

procedure TElBuiltInRSACryptoKey.RecalculatePublicKeyBlob(RawPublicKey : boolean);
var
  OutSize : integer;
begin
  OutSize := 0;
  SBRSA.EncodePublicKey(@FM[0], Length(FM), @FE[0], Length(FE), SB_OID_RSAENCRYPTION,
    nil, OutSize);
  SetLength(FPublicKeyBlob, OutSize);
  if not SBRSA.EncodePublicKey(@FM[0], Length(FM), @FE[0], Length(FE), SB_OID_RSAENCRYPTION,
    @FPublicKeyBlob[0], OutSize, RawPublicKey) then
    raise EElCryptoKeyError.Create(SInternalError);
  SetLength(FPublicKeyBlob, OutSize);
end;

procedure TElBuiltInRSACryptoKey.TrimParams;
begin
  FM := TrimParam(FM);
  FE := TrimParam(FE);
  if Length(FD) > 0 then
    FD := TrimParam(FD);
end;

function TElBuiltInRSACryptoKey.GetKeyStorage : TElCustomCryptoKeyStorage;
begin
  Result := nil;
end;

function TElBuiltInRSACryptoKey.GetKeyProp(const PropID : ByteArray;
  const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif}  {$endif}): ByteArray;
begin
  if CompareContent(PropID, SB_KEYPROP_KEYFORMAT) then
  begin
    case FKeyFormat of
      rsaPKCS1 : Result := SB_KEYPROP_RSA_KEYFORMAT_PKCS1;
      rsaOAEP : Result := SB_KEYPROP_RSA_KEYFORMAT_OAEP;
      rsaPSS : Result := SB_KEYPROP_RSA_KEYFORMAT_PSS;
    else
      Result := EmptyArray;
    end;
  end
  else if CompareContent(PropID, SB_KEYPROP_HASH_ALGORITHM) then
  begin
    Result := GetOIDByHashAlgorithm(FHashAlgorithm);
  end
  else if CompareContent(PropID, SB_KEYPROP_MGF_ALGORITHM) then
  begin
    Result := GetOIDByAlgorithm(FMGFAlgorithm);
  end
  else if CompareContent(PropID, SB_KEYPROP_TRAILER_FIELD) then
  begin
    Result := GetBufferFromInteger(FTrailerField);
  end
  else if CompareContent(PropID, SB_KEYPROP_SALT_SIZE) then
  begin
    Result := GetBufferFromInteger(FSaltSize);
  end
  else if CompareContent(PropID, SB_KEYPROP_STRLABEL) then
  begin
    Result := CloneArray(FStrLabel);
  end
  else if CompareContent(PropID, SB_KEYPROP_RSA_RAWKEY) then
  begin
    Result := GetBufferFromBool(FRawPublicKey)
  end
  else if CompareContent(PropID, SB_KEYPROP_RSA_M) then
  begin
    Result := CloneArray(FM);
  end
  else if CompareContent(PropID, SB_KEYPROP_RSA_E) then
  begin
    Result := CloneArray(FE);
  end
  else if CompareContent(PropID, SB_KEYPROP_RSA_D) then
  begin
    Result := CloneArray(FD);
  end
  else
    Result := Default; 
end;

procedure TElBuiltInRSACryptoKey.SetKeyProp(const PropID : ByteArray; const Value : ByteArray);
begin
  if CompareContent(PropID, SB_KEYPROP_KEYFORMAT) then
  begin
    if CompareContent(Value, SB_KEYPROP_RSA_KEYFORMAT_PKCS1) then
      FKeyFormat := rsaPKCS1
    else if CompareContent(Value, SB_KEYPROP_RSA_KEYFORMAT_OAEP) then
      FKeyFormat := rsaOAEP
    else if CompareContent(Value, SB_KEYPROP_RSA_KEYFORMAT_PSS) then
      FKeyFormat := rsaPSS
    else
      FKeyFormat := rsaPKCS1;
  end
  else if CompareContent(PropID, SB_KEYPROP_HASH_ALGORITHM) then
  begin
    FHashAlgorithm := GetHashAlgorithmByOID(Value);
  end
  else if CompareContent(PropID, SB_KEYPROP_MGF_ALGORITHM) then
  begin
    FMGFAlgorithm := GetAlgorithmByOID(Value);
  end
  else if CompareContent(PropID, SB_KEYPROP_TRAILER_FIELD) then
  begin
    FTrailerField := GetIntegerPropFromBuffer(Value);
  end
  else if CompareContent(PropID, SB_KEYPROP_SALT_SIZE) then
  begin
    FSaltSize := GetIntegerPropFromBuffer(Value);
  end
  else if CompareContent(PropID, SB_KEYPROP_STRLABEL) then
  begin
    FStrLabel := CloneArray(Value);
  end
  else if CompareContent(PropID, SB_KEYPROP_RSA_RAWKEY) then
  begin
    FRawPublicKey := GetBoolFromBuffer(Value, false); 
  end
  else if CompareContent(PropID, SB_KEYPROP_RSA_M) then
  begin
    FM := CloneArray(Value);
    FPublicKey := (Length(FM) > 0) and (Length(FE) > 0);
    RecalculatePublicKeyBlob(FRawPublicKey);
    InitAntiTimingParams;
  end
  else if CompareContent(PropID, SB_KEYPROP_RSA_E) then
  begin
    FE := CloneArray(Value);
    FPublicKey := (Length(FM) > 0) and (Length(FE) > 0);
    RecalculatePublicKeyBlob(FRawPublicKey);
    InitAntiTimingParams;
  end
  else if CompareContent(PropID, SB_KEYPROP_RSA_D) then
  begin
    FD := CloneArray(Value);
    FSecretKey := (Length(FM) > 0) and (Length(FE) > 0) and (Length(FD) > 0);
  end;
end;

procedure TElBuiltInRSACryptoKey.ClearPublic;
begin
  Reset;
end;

procedure TElBuiltInRSACryptoKey.ClearSecret;
begin
  SetLength(FKeyBlob, 0);
  FD := EmptyArray;
  FSecretKey := false;
end;

////////////////////////////////////////////////////////////////////////////////
// TElBuiltInDSACryptoKey class

constructor TElBuiltInDSACryptoKey.Create(CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
  Reset;
end;

 destructor  TElBuiltInDSACryptoKey.Destroy;
begin
  {$ifndef SB_NO_PKIASYNC}
  if Assigned(FToken) then
    FreeAndNil(FToken);
   {$endif SB_NO_PKIASYNC}
  inherited;
end;

procedure TElBuiltInDSACryptoKey.Reset;
begin
  inherited;
  FPublicKey := false;
  FSecretKey := false;
  SetLength(FKeyBlob, 0);
  SetLength(FP, 0);
  SetLength(FQ, 0);
  SetLength(FG, 0);
  SetLength(FY, 0);
  SetLength(FX, 0);
  FStrictKeyValidation := false;
  FHashAlgorithm := 0;
  {$ifndef SB_NO_PKIASYNC}
  if Assigned(FToken) then
    FreeAndNil(FToken);
   {$endif SB_NO_PKIASYNC}
end;

procedure TElBuiltInDSACryptoKey.Generate(PBits, QBits : integer);
var
  PSize, QSize, GSize, YSize, XSize, BlSize : integer;
  UseExtGenerator, BoolRes : boolean;
begin
  if (FCryptoProvider <> nil) and (FCryptoProvider.Options.MaxPublicKeySize > 0)
    and (PBits > FCryptoProvider.Options.MaxPublicKeySize) then
    raise EElBuiltInCryptoProviderError.Create(SPublicKeyTooLong);
  if (FCryptoProvider is TElBuiltInCryptoProvider) then
    UseExtGenerator := TElBuiltInCryptoProviderOptions(TElBuiltInCryptoProvider(FCryptoProvider).Options).UsePlatformKeyGeneration and ((SBDSA.ExternalGenerationSupported) or (not TElBuiltInCryptoProviderOptions(TElBuiltInCryptoProvider(FCryptoProvider).Options).RollbackToBuiltInKeyGeneration))
  else
    UseExtGenerator := false;
  PSize := 0;
  QSize := 0;
  GSize := 0;
  YSize := 0;
  XSize := 0;
  BlSize := 0;
  if UseExtGenerator then
    SBDSA.ExternalGenerateEx(PBits, QBits, nil, PSize, nil, QSize, nil, GSize, nil, YSize, nil, XSize)
  else
    SBDSA.GenerateEx(PBits, QBits, nil, PSize, nil, QSize, nil, GSize, nil, YSize, nil, XSize);

  SetLength(FP, PSize);
  SetLength(FQ, QSize);
  SetLength(FG, GSize);
  SetLength(FY, YSize);
  SetLength(FX, XSize);

  if UseExtGenerator then
    BoolRes :=
      SBDSA.ExternalGenerateEx(PBits, QBits, @FP[0], PSize, @FQ[0], QSize, @FG[0], GSize,
        @FY[0], YSize, @FX[0], XSize)
  else
    BoolRes :=
      SBDSA.GenerateEx(PBits, QBits, @FP[0], PSize, @FQ[0], QSize, @FG[0], GSize,
        @FY[0], YSize, @FX[0], XSize);
  if not BoolRes then
    raise EElBuiltInCryptoProviderError.Create(SKeyGenerationFailed);

  SBDSA.EncodePrivateKey(@FP[0], PSize, @FQ[0], QSize, @FG[0], GSize, @FY[0], YSize,
    @FX[0], XSize, nil, BlSize);
  SetLength(FKeyBlob, BlSize);
  SBDSA.EncodePrivateKey(@FP[0], PSize, @FQ[0], QSize, @FG[0], GSize, @FY[0], YSize,
    @FX[0], XSize, @FKeyBlob[0], BlSize);

  SetLength(FP, PSize);
  SetLength(FQ, QSize);
  SetLength(FG, GSize);
  SetLength(FY, YSize);
  SetLength(FX, XSize);
  SetLength(FKeyBlob, BlSize);
  FSecretKey := true;
  FPublicKey := true;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInDSACryptoKey.Generate(Bits : integer;
  Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil);
var
  I : integer;
  QBits : integer;
begin
  if (FCryptoProvider <> nil) and (FCryptoProvider.Options.MaxPublicKeySize > 0)
    and (Bits > FCryptoProvider.Options.MaxPublicKeySize) then
    raise EElBuiltInCryptoProviderError.Create(SPublicKeyTooLong);

  QBits := 0;
  if Params <> nil then
  begin
    for I := 0 to Params.Count - 1 do
      if CompareContent(Params.OIDs[I], SB_KEYPROP_DSA_QBITS) then
      begin
        QBits := GetIntegerPropFromBuffer(Params.Values[I]);
        Break;
      end;
  end;

  I := 0;
//  if FHashAlgorithm = 0 then
//  else
  if FHashAlgorithm = SB_ALGORITHM_DGST_SHA1 then
    I := 160
  else if FHashAlgorithm = SB_ALGORITHM_DGST_SHA224 then
    I := 224
  else if FHashAlgorithm = SB_ALGORITHM_DGST_SHA256 then
    I := 256
  else if FHashAlgorithm = SB_ALGORITHM_DGST_SHA384 then
    I := 384
  else if FHashAlgorithm = SB_ALGORITHM_DGST_SHA512 then
    I := 512;

  if QBits = 0 then QBits := I;    

  if QBits = 0 then
  begin
    if (Bits <= 1024) then
      QBits := 160
    else if (Bits <= 2048) then
      QBits := 256
    else if (Bits <= 3072) then
      QBits := 256
    else if (Bits <= 8192) then
      QBits := 384
    else
      QBits := 512;
  end;

  Generate(Bits, QBits);
end;
 {$endif SB_PGPSFX_STUB}

procedure TElBuiltInDSACryptoKey.ImportPublic(Buffer: pointer; Size: integer; Params : TElCPParameters = nil);
var
  Tag : TElASN1ConstrainedTag;
  Succ : boolean;
begin
  // DSA public key is just an ASN.1 encoding of Y value (Y: INTEGER)
  Tag := TElASN1ConstrainedTag.CreateInstance();
  try
    Succ := false;
    if Tag.LoadFromBuffer(Buffer, Size) then
    begin
      if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_INTEGER, false)) then
      begin
        FY := TElASN1SimpleTag(Tag.GetField(0)).Content;
        Succ := true;
      end;
    end;
    if not Succ then
      raise EElBuiltInCryptoProviderError.Create(SInvalidPublicKey);
  finally
    FreeAndNil(Tag);
  end;
end;

procedure TElBuiltInDSACryptoKey.ImportSecret(Buffer: pointer; Size: integer; Params : TElCPParameters = nil);
var
  PSize, QSize, GSize, YSize, XSize : integer;
begin

  // trying to load a key as plain DSA key
  PSize := 0;
  QSize := 0;
  GSize := 0;
  YSize := 0;
  XSize := 0;
  SBDSA.DecodePrivateKey(Buffer, Size, nil, PSize, nil, QSize, nil,
    GSize, nil, YSize, nil, XSize);

  if (PSize <= 0) or (QSize <= 0) or (GSize <= 0) or (YSize <= 0) or (XSize <= 0) then
    raise EElCryptoKeyError.Create(SInvalidSecretKey);

  SetLength(FP, PSize);
  SetLength(FQ, QSize);
  SetLength(FG, GSize);
  SetLength(FY, YSize);
  SetLength(FX, XSize);

  if SBDSA.DecodePrivateKey(Buffer, Size, @FP[0], PSize, @FQ[0], QSize,
    @FG[0], GSize, @FY[0], YSize, @FX[0], XSize) then
  begin
    FPublicKey := true;
    FSecretKey := true;
    SetLength(FKeyBlob, Size);
    SBMove(Buffer^, FKeyBlob[0], Length(FKeyBlob));
    TrimParams;
  end
  else
    raise EElCryptoKeyError.Create(SInvalidSecretKey);

end;

procedure TElBuiltInDSACryptoKey.ExportPublic(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil);
var
  Tag : TElASN1SimpleTag;
  EstSize : integer;
begin
  Tag := TElASN1SimpleTag.CreateInstance();
  try
    Tag.TagID := SB_ASN1_INTEGER;
    Tag.Content := (FY);
    EstSize := 0;
    Tag.SaveToBuffer( nil , EstSize);
    if EstSize < Size then
    begin
      Tag.SaveToBuffer(Buffer, Size);
    end
    else if Size = 0 then
    begin
      Size := EstSize;
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SBufferTooSmall);
  finally
    FreeAndNil(Tag);

  end;
end;

procedure TElBuiltInDSACryptoKey.ExportSecret(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil);
begin
  if Size = 0 then
    Size := Length(FKeyBlob)
  else if Size < Length(FKeyBlob) then
    raise EElCryptoKeyError.Create(SBufferTooSmall)
  else
  begin
    Size := Length(FKeyBlob);
    SBMove(FKeyBlob[0], Buffer^, Size);
  end
end;

function TElBuiltInDSACryptoKey.Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoKey;
var
  Res : TElBuiltInDSACryptoKey;
begin
  Res := TElBuiltInDSACryptoKey.Create(FCryptoProvider);
  Res.FKeyBlob := CloneArray(FKeyBlob);
  Res.FP := CloneArray(FP);
  Res.FQ := CloneArray(FQ);
  Res.FG := CloneArray(FG);
  Res.FY := CloneArray(FY);
  Res.FX := CloneArray(FX);
  Res.FPublicKey := FPublicKey;
  Res.FSecretKey := FSecretKey;
  Res.FHashAlgorithm := FHashAlgorithm;
  Res.FStrictKeyValidation := FStrictKeyValidation;
    
  Result := Res;
end;

function TElBuiltInDSACryptoKey.Equals(Source : TElCustomCryptoKey; PublicOnly : boolean;
      Params : TElCPParameters  =  nil): boolean;

var
  B:ByteArray;
begin

  Result := false;
  if Self.Algorithm <> Source.Algorithm then exit;
  Result := true;
  B := Source.GetKeyProp(SB_KEYPROP_DSA_P);
  Result := Result and
     (CompareMem(@FP[0], @B[0], Length(FP)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_DSA_Q);
  Result := Result and  (Length(FQ) = Length(B)) and
     (CompareMem(@FQ[0], @B[0], Length(FQ)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_DSA_G);
  Result := Result and (Length(FG) = Length(B)) and
     (CompareMem(@FG[0], @B[0], Length(FG)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_DSA_X);
  Result := Result and (Length(FX) = Length(B)) and
     (CompareMem(@FX[0], @B[0], Length(FX)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_DSA_Y);
  Result := Result and (Length(FY) = Length(B)) and
     (CompareMem(@FY[0], @B[0], Length(FY)))
     ;

end;

function TElBuiltInDSACryptoKey.ClonePublic(Params : TElCPParameters  =  nil) : TElCustomCryptoKey;
var
  Res : TElBuiltInDSACryptoKey;
begin
  Result := Clone(Params);
  Res := TElBuiltInDSACryptoKey(Result);
  Res.FX := EmptyArray;
  Res.FSecretKey := false;
end;

function TElBuiltInDSACryptoKey.GetIsPublic: boolean;
begin
  Result := FPublicKey;
end;

function TElBuiltInDSACryptoKey.GetIsSecret: boolean;
begin
  Result := FSecretKey;
end;

function TElBuiltInDSACryptoKey.GetIsExportable: boolean;
begin
  Result := true;
end;

function TElBuiltInDSACryptoKey.GetIsPersistent: boolean;
begin
  Result := false;
end;

function TElBuiltInDSACryptoKey.GetIsValid: boolean;
begin
  if FSecretKey then
    Result := SBDSA.IsValidKey(@FP[0], Length(FP), @FQ[0], Length(FQ), @FG[0],
    Length(FG), @FY[0], Length(FY), @FX[0], Length(FX), true, FStrictKeyValidation)
  else
    Result := SBDSA.IsValidKey(@FP[0], Length(FP), @FQ[0], Length(FQ), @FG[0],
    Length(FG), @FY[0], Length(FY), nil, 0, false, FStrictKeyValidation);
end;

function TElBuiltInDSACryptoKey.GetBits : integer;
begin
  Result := Length(FP) shl 3;
end;

function TElBuiltInDSACryptoKey.GetAlgorithm : integer;
begin
  Result := SB_ALGORITHM_PK_DSA;
end;

function TElBuiltInDSACryptoKey.GetKeyStorage : TElCustomCryptoKeyStorage;
begin
  Result := nil;
end;

procedure TElBuiltInDSACryptoKey.TrimParams;
begin
  FP := TrimParam(FP);
  FQ := TrimParam(FQ);
  FG := TrimParam(FG);
  FY := TrimParam(FY);
  if Length(FX) > 0 then
    FX := TrimParam(FX);
end;

function TElBuiltInDSACryptoKey.GetKeyProp(const PropID : ByteArray;
  const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif}  {$endif}): ByteArray;
var
  B : integer;
begin
  if CompareContent(PropID, SB_KEYPROP_DSA_STRICT_VALIDATION) then
    Result := GetBufferFromBool(FStrictKeyValidation)
  else if CompareContent(PropID, SB_KEYPROP_HASH_ALGORITHM) then
  begin
    if FHashAlgorithm = 0 then
    begin
      B := Length(TrimParam(FQ)) shl 3;
      if B <= 160 then
        FHashAlgorithm := SB_ALGORITHM_DGST_SHA1
      else if B <= 224 then
        FHashAlgorithm := SB_ALGORITHM_DGST_SHA224
      else if B <= 256 then
        FHashAlgorithm := SB_ALGORITHM_DGST_SHA256
      else if B <= 384 then
        FHashAlgorithm := SB_ALGORITHM_DGST_SHA384
      else
        FHashAlgorithm := SB_ALGORITHM_DGST_SHA512;
    end;

    Result := GetOIDByHashAlgorithm(FHashAlgorithm);
  end
  else if CompareContent(PropID, SB_KEYPROP_DSA_P) then
    Result := CloneArray(FP)
  else if CompareContent(PropID, SB_KEYPROP_DSA_Q) then
    Result := CloneArray(FQ)
  else if CompareContent(PropID, SB_KEYPROP_DSA_G) then
    Result := CloneArray(FG)
  else if CompareContent(PropID, SB_KEYPROP_DSA_X) then
    Result := CloneArray(FX)
  else if CompareContent(PropID, SB_KEYPROP_DSA_Y) then
    Result := CloneArray(FY)
  else if CompareContent(PropID, SB_KEYPROP_DSA_QBITS) then
    Result := GetBufferFromInteger(Length(FQ) shl 3)
  else
    Result := Default;
end;

procedure TElBuiltInDSACryptoKey.SetKeyProp(const PropID : ByteArray; const Value : ByteArray);
begin
  if CompareContent(PropID, SB_KEYPROP_DSA_STRICT_VALIDATION) then
    FStrictKeyValidation := GetBoolFromBuffer(Value, false)
  else if CompareContent(PropID, SB_KEYPROP_HASH_ALGORITHM) then
    FHashAlgorithm := GetHashAlgorithmByOID(Value)
  else if CompareContent(PropID, SB_KEYPROP_DSA_P) then
    FP := CloneArray(Value)
  else if CompareContent(PropID, SB_KEYPROP_DSA_Q) then
    FQ := CloneArray(Value)
  else if CompareContent(PropID, SB_KEYPROP_DSA_G) then
    FG := CloneArray(Value)
  else if CompareContent(PropID, SB_KEYPROP_DSA_X) then
    FX := CloneArray(Value)
  else if CompareContent(PropID, SB_KEYPROP_DSA_Y) then
    FY := CloneArray(Value)
  else if CompareContent(PropID, SB_KEYPROP_DSA_QBITS) then
    raise EElBuiltInCryptoProviderError.Create(SCannotModifyReadOnlyProperty);
  FPublicKey := (Length(FP) > 0) and (Length(FQ) > 0) and (Length(FG) > 0) and
    (Length(FY) > 0);
  FSecretKey := (Length(FP) > 0) and (Length(FQ) > 0) and (Length(FG) > 0) and
    (Length(FX) > 0);
  // FSecretKey := FPublicKey and (Length(FX) > 0);
  // changed to comply with Java cryptoprovider interfaces
end;

procedure TElBuiltInDSACryptoKey.ClearPublic;
begin
  Reset;
end;

procedure TElBuiltInDSACryptoKey.ClearSecret;
begin
  FX := EmptyArray;
  FSecretKey := false;
end;

{$ifndef SB_NO_PKIASYNC}
procedure TElBuiltInDSACryptoKey.PrepareForSigning(MultiUse : boolean  =  false);
var
  DSAP, DSAQ, DSAG : PLInt;
begin
  if FToken <> nil then
    raise EElBuiltInCryptoProviderError.Create(SKeyAlreadyPrepared);
  if (FCryptoProvider <> nil) and (FCryptoProvider.Options.MaxPublicKeySize > 0)
    and (Bits > FCryptoProvider.Options.MaxPublicKeySize) then
    raise EElBuiltInCryptoProviderError.Create(SPublicKeyTooLong);
  LCreate(DSAP);
  LCreate(DSAQ);
  LCreate(DSAG);
  try
    PointerToLInt(DSAP, @FP[0], Length(FP));
    PointerToLInt(DSAQ, @FQ[0], Length(FQ));
    PointerToLInt(DSAG, @FG[0], Length(FG));
    FToken := GetGlobalAsyncCalculator().BeginDSASigning(DSAP, DSAQ, DSAG);
    FReleaseToken := not MultiUse;
  finally
    LDestroy(DSAP);
    LDestroy(DSAQ);
    LDestroy(DSAG);
  end;
end;

procedure TElBuiltInDSACryptoKey.CancelPreparation;
begin
  if Assigned(FToken) then
  begin
    try
      FToken.Cancel;
    finally
      FreeAndNil(FToken);
    end;
  end;
end;

function TElBuiltInDSACryptoKey.AsyncOperationFinished : boolean;
begin
  if Assigned(FToken) then
    Result := FToken.Finished
  else
    Result := false;
end;
 {$endif SB_NO_PKIASYNC}

////////////////////////////////////////////////////////////////////////////////
// TElBuiltInElgamalCryptoKey class

constructor TElBuiltInElgamalCryptoKey.Create(CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
  Reset;
end;

 destructor  TElBuiltInElgamalCryptoKey.Destroy;
begin
  inherited;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInElgamalCryptoKey.Generate(Bits : integer;
  Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil);
var
  LP, LG, LY, LX : PLInt;
  Size : integer;
  UseExtGenerator : boolean;
  BoolRes : boolean;
begin
  if (FCryptoProvider <> nil) and (FCryptoProvider.Options.MaxPublicKeySize > 0)
    and (Bits > FCryptoProvider.Options.MaxPublicKeySize) then
    raise EElBuiltInCryptoProviderError.Create(SPublicKeyTooLong);
  if (FCryptoProvider is TElBuiltInCryptoProvider) then
    UseExtGenerator := TElBuiltInCryptoProviderOptions(TElBuiltInCryptoProvider(FCryptoProvider).Options).UsePlatformKeyGeneration and ((SBElgamal.ExternalGenerationSupported) or (not TElBuiltInCryptoProviderOptions(TElBuiltInCryptoProvider(FCryptoProvider).Options).RollbackToBuiltInKeyGeneration))
  else
    UseExtGenerator := false;
  LCreate(LP);
  LCreate(LG);
  LCreate(LY);
  LCreate(LX);
  try
    if UseExtGenerator then
      BoolRes := SBElgamal.ExternalGenerate(Bits, LP, LG, LX, LY)
    else
      BoolRes := SBElgamal.Generate(Bits, LP, LG, LX, LY);
    if not BoolRes then
      raise EElBuiltInCryptoProviderError.Create(SKeyGenerationFailed);
    SetLength(FP, LP.Length * 4);
    SetLength(FG, LG.Length * 4);
    SetLength(FX, LX.Length * 4);
    SetLength(FY, LY.Length * 4);
    Size := Length(FP);
    LIntToPointer(LP, @FP[0], Size);
    Size := Length(FG);
    LIntToPointer(LG, @FG[0], Size);
    Size := Length(FY);
    LIntToPointer(LY, @FY[0], Size);
    Size := Length(FX);
    LIntToPointer(LX, @FX[0], Size);
    FSecretKey := true;
    FPublicKey := true;
    TrimParams;
  finally
    LDestroy(LP);
    LDestroy(LG);
    LDestroy(LY);
    LDestroy(LX);
  end;
end;
 {$endif SB_PGPSFX_STUB}

procedure TElBuiltInElgamalCryptoKey.Reset;
begin
  inherited;
  SetLength(FP, 0);
  SetLength(FG, 0);
  SetLength(FY, 0);
  SetLength(FX, 0);
  FPublicKey := false;
  FSecretKey := false;
end;

procedure TElBuiltInElgamalCryptoKey.ImportPublic(Buffer: pointer; Size: integer; Params : TElCPParameters = nil);
begin
  // TODO
end;

procedure TElBuiltInElgamalCryptoKey.ImportSecret(Buffer: pointer; Size: integer; Params : TElCPParameters = nil);
begin
  // TODO
end;

procedure TElBuiltInElgamalCryptoKey.ExportPublic(Buffer: pointer; var Size: integer;
  Params : TElCPParameters = nil);
var
  Buf : ByteArray;
  Sz : integer;
begin
  Sz := 0;
  SBElGamal.EncodePublicKey(@FP[0], Length(FP), @FG[0], Length(FG), @FY[0], Length(FY), nil, Sz);
  SetLength(Buf, Sz);
  SBElGamal.EncodePublicKey(@FP[0], Length(FP), @FG[0], Length(FG), @FY[0], Length(FY), Buf, Sz);
  SetLength(Buf, Sz);
  
  if Size = 0 then
    Size := Length(Buf)
  else if Size < Length(Buf) then
    raise EElCryptoKeyError.Create(SBufferTooSmall)
  else
  begin
    Size := Length(Buf);
    SBMove(Buf[0], Buffer^, Size);
  end;
  ReleaseArray(Buf);
end;

procedure TElBuiltInElgamalCryptoKey.ExportSecret(Buffer: pointer; var Size: integer;
  Params : TElCPParameters = nil);
var
  Buf : ByteArray;
  Sz : integer;
begin
  Sz := 0;
  SBElGamal.EncodePrivateKey(@FP[0], Length(FP), @FG[0], Length(FG), @FX[0], Length(FX), nil, Sz);
  SetLength(Buf, Sz);
  SBElGamal.EncodePrivateKey(@FP[0], Length(FP), @FG[0], Length(FG), @FX[0], Length(FX), Buf, Sz);
  SetLength(Buf, Sz);
  
  if Size = 0 then
    Size := Length(Buf)
  else if Size < Length(Buf) then
    raise EElCryptoKeyError.Create(SBufferTooSmall)
  else
  begin
    Size := Length(Buf);
    SBMove(Buf[0], Buffer^, Size);
  end;
  ReleaseArray(Buf);
end;

function TElBuiltInElgamalCryptoKey.Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoKey;
var
  Res : TElBuiltInElgamalCryptoKey;
begin
  Res := TElBuiltInElgamalCryptoKey.Create(FCryptoProvider);
  Res.FP := CloneArray(FP);
  Res.FG := CloneArray(FG);
  Res.FY := CloneArray(FY);
  Res.FX := CloneArray(FX);
  Res.FSecretKey := FSecretKey;
  Res.FPublicKey := FPublicKey;
  Result := Res;
end;

function TElBuiltInElgamalCryptoKey.Equals(Source : TElCustomCryptoKey; PublicOnly : boolean;
      Params : TElCPParameters  =  nil): boolean;

var
  B : ByteArray;
begin

  Result := false;
  if Self.Algorithm <> Source.Algorithm then exit;
  Result := true;
  B := Source.GetKeyProp(SB_KEYPROP_ELGAMAL_P);
  Result := Result and
     (CompareMem(@FP[0], @B[0], Length(FP)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_ELGAMAL_G);
  Result := Result and (Length(FG) = Length(B)) and
     (CompareMem(@FG[0], @B[0], Length(FG)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_ELGAMAL_X);
  Result := Result and (Length(FX) = Length(B)) and
     (CompareMem(@FX[0], @B[0], Length(FX)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_ELGAMAL_Y);
  Result := Result and (Length(FY) = Length(B)) and
     (CompareMem(@FY[0], @B[0], Length(FY)))
     ;

end;

function TElBuiltInElgamalCryptoKey.ClonePublic(Params : TElCPParameters  =  nil) : TElCustomCryptoKey;
var
  Res : TElBuiltInElgamalCryptoKey;
begin
  Result := Clone(Params);
  Res := TElBuiltInElgamalCryptoKey(Result);
  Res.FX := EmptyArray;
  Res.FSecretKey := false;
end;

function TElBuiltInElgamalCryptoKey.GetKeyProp(const PropID : ByteArray;
  const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif}  {$endif}): ByteArray;
begin
  if CompareContent(PropID, SB_KEYPROP_ELGAMAL_P) then
    Result := CloneArray(FP)
  else if CompareContent(PropID, SB_KEYPROP_ELGAMAL_G) then
    Result := CloneArray(FG)
  else if CompareContent(PropID, SB_KEYPROP_ELGAMAL_X) then
    Result := CloneArray(FX)
  else if CompareContent(PropID, SB_KEYPROP_ELGAMAL_Y) then
    Result := CloneArray(FY)
  else
    Result := Default;
end;

procedure TElBuiltInElgamalCryptoKey.SetKeyProp(const PropID : ByteArray; const Value : ByteArray);
  procedure ReAdjustKeyFlags;
  begin
    FPublicKey := (Length(FP) > 0) and (Length(FG) > 0) and (Length(FY) > 0);
    FSecretKey := (Length(FP) > 0) and (Length(FG) > 0) and (Length(FX) > 0);
    //FSecretKey := FPublicKey and (Length(FX) > 0); changed to comply JCE interfaces
  end;
begin
  if CompareContent(PropID, SB_KEYPROP_ELGAMAL_P) then
  begin
    FP := CloneArray(Value);
    ReAdjustKeyFlags;
  end
  else if CompareContent(PropID, SB_KEYPROP_ELGAMAL_G) then
  begin
    FG := CloneArray(Value);
    ReAdjustKeyFlags;
  end
  else if CompareContent(PropID, SB_KEYPROP_ELGAMAL_X) then
  begin
    FX := CloneArray(Value);
    ReAdjustKeyFlags;
  end
  else if CompareContent(PropID, SB_KEYPROP_ELGAMAL_Y) then
  begin
    FY := CloneArray(Value);
    ReAdjustKeyFlags;
  end;
end;

procedure TElBuiltInElgamalCryptoKey.TrimParams;
begin
  TrimParam(FP);
  TrimParam(FG);
  TrimParam(FY);
  if FSecretKey then
    TrimParam(FX);
end;

function TElBuiltInElgamalCryptoKey.GetIsPublic: boolean;
begin
  Result := FPublicKey;
end;

function TElBuiltInElgamalCryptoKey.GetIsSecret: boolean;
begin
  Result := FSecretKey;
end;

function TElBuiltInElgamalCryptoKey.GetIsExportable: boolean;
begin
  Result := true;
end;

function TElBuiltInElgamalCryptoKey.GetIsPersistent: boolean;
begin
  Result := false;
end;

function TElBuiltInElgamalCryptoKey.GetIsValid: boolean;
begin
  Result := true;
end;

function TElBuiltInElgamalCryptoKey.GetBits : integer;
begin
  Result := Length(FP) shl 3;
end;

function TElBuiltInElgamalCryptoKey.GetAlgorithm : integer;
begin
  Result := SB_ALGORITHM_PK_ELGAMAL;
end;

function TElBuiltInElgamalCryptoKey.GetKeyStorage : TElCustomCryptoKeyStorage;
begin
  Result := nil;
end;

procedure TElBuiltInElgamalCryptoKey.ClearPublic;
begin
  Reset;
end;

procedure TElBuiltInElgamalCryptoKey.ClearSecret;
begin
  FX := EmptyArray;
  FSecretKey := false;
end;

{$ifndef SB_NO_PKIASYNC}
procedure TElBuiltInElgamalCryptoKey.PrepareForEncryption(MultiUse: boolean  =  false);
var
  P, G, Y : PLInt;
begin
  if FToken <> nil then
    raise EElBuiltInCryptoProviderError.Create(SKeyAlreadyPrepared);
  if (FCryptoProvider <> nil) and (FCryptoProvider.Options.MaxPublicKeySize > 0)
    and (Bits > FCryptoProvider.Options.MaxPublicKeySize) then
    raise EElBuiltInCryptoProviderError.Create(SPublicKeyTooLong);
  LCreate(P);
  LCreate(G);
  LCreate(Y);
  try
    PointerToLInt(P, @FP[0], Length(FP));
    PointerToLInt(G, @FG[0], Length(FG));
    PointerToLInt(Y, @FY[0], Length(FY));
    FToken := GetGlobalAsyncCalculator().BeginElgamalEncryption(P, G, Y);
    FReleaseToken := not MultiUse;
  finally
    LDestroy(P);
    LDestroy(G);
    LDestroy(Y);
  end;
end;

procedure TElBuiltInElgamalCryptoKey.PrepareForSigning(MultiUse: boolean  =  false);
var
  EGP, EGG : PLInt;
begin
  if FToken <> nil then
    raise EElBuiltInCryptoProviderError.Create(SKeyAlreadyPrepared);
  if (FCryptoProvider <> nil) and (FCryptoProvider.Options.MaxPublicKeySize > 0)
    and (Bits > FCryptoProvider.Options.MaxPublicKeySize) then
    raise EElBuiltInCryptoProviderError.Create(SPublicKeyTooLong);
  LCreate(EGP);
  LCreate(EGG);
  try
    PointerToLInt(EGP, @FP[0], Length(FP));
    PointerToLInt(EGG, @FG[0], Length(FG));
    FToken := GetGlobalAsyncCalculator().BeginElgamalSigning(EGP, EGG);
    FReleaseToken := not MultiUse;
  finally
    LDestroy(EGP);
    LDestroy(EGG);
  end;
end;

procedure TElBuiltInElgamalCryptoKey.CancelPreparation;
begin
  if Assigned(FToken) then
  begin
    try
      FToken.Cancel;
    finally
      FreeAndNil(FToken);
    end;
  end;
end;

function TElBuiltInElgamalCryptoKey.AsyncOperationFinished : boolean;
begin
  if Assigned(FToken) then
    Result := FToken.Finished
  else
    Result := false;
end;
 {$endif SB_NO_PKIASYNC}

////////////////////////////////////////////////////////////////////////////////
// TElBuiltInDHCryptoKey class

{$ifndef SB_NO_DH}
constructor TElBuiltInDHCryptoKey.Create(CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
  Reset;
end;

 destructor  TElBuiltInDHCryptoKey.Destroy;
begin
  inherited;
end;


procedure TElBuiltInDHCryptoKey.ExternalGenerate(Bits : integer; var P, G, X, Y : ByteArray);
begin
  // For each platform, implement its own IntExternalGenerate<PLATFORM> method
  // (e.g. IntExternalGenerateWP8) with the same signature and delegate the call
  // to it from here. Arrange calls to methods for different platforms with conditional defines.
  raise ESecureBlackboxError.Create('Method not implemented for the active platform: TElBuiltInDHCryptoKey.ExternalGenerate()');
end;

function TElBuiltInDHCryptoKey.ExternalGenerationSupported : boolean;
begin
  Result := false;
end;

procedure TElBuiltInDHCryptoKey.Generate(Bits : integer;
  Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil);
var
  P, G, X, Y : PLInt;
  PSize, GSize, XSize, YSize : integer;
  UseExtGenerator : boolean;
begin
  if (FCryptoProvider <> nil) and (FCryptoProvider.Options.MaxPublicKeySize > 0)
    and (Bits > FCryptoProvider.Options.MaxPublicKeySize) then
    raise EElBuiltInCryptoProviderError.Create(SPublicKeyTooLong);
  Reset;

  if (FCryptoProvider is TElBuiltInCryptoProvider) then
    UseExtGenerator := TElBuiltInCryptoProviderOptions(TElBuiltInCryptoProvider(FCryptoProvider).Options).UsePlatformKeyGeneration and ((Self.ExternalGenerationSupported) or (not TElBuiltInCryptoProviderOptions(TElBuiltInCryptoProvider(FCryptoProvider).Options).RollbackToBuiltInKeyGeneration))
  else
    UseExtGenerator := false;

  if UseExtGenerator then
    ExternalGenerate(Bits, FP, FG, FX, FY)
  else
  begin
    LCreate(P);
    LCreate(G);
    LCreate(X);
    LCreate(Y);
    try
      LGenPrime(P, Bits shr 5{$ifndef HAS_DEF_PARAMS}, false {$endif});
      LInit(G, '2');
      SBRndGenerateLInt(X, Bits shr 5);
      X.Digits[1] := X.Digits[1] and $FFFFFF00;
      LMModPower(G, X, P, Y);
      GSize := G.Length shl 2;
      SetLength(FG, GSize);
      XSize := X.Length shl 2;
      SetLength(FX, XSize);
      PSize := P.Length shl 2;
      SetLength(FP, PSize);
      YSize := Y.Length shl 2;
      SetLength(FY, YSize);
      LIntToPointer(G, @FG[0], GSize);
      LIntToPointer(X, @FX[0], XSize);
      LIntToPointer(P, @FP[0], PSize);
      LIntToPointer(Y, @FY[0], YSize);
      SetLength(FG, GSize);
      SetLength(FX, XSize);
      SetLength(FP, PSize);
      SetLength(FY, YSize);
    finally
      LDestroy(P);
      LDestroy(G);
      LDestroy(X);
      LDestroy(Y);
    end;
  end;
  FPublicKey := true;
  FSecretKey := true;
end;

procedure TElBuiltInDHCryptoKey.Reset;
begin
  inherited;
  SetLength(FP, 0);
  SetLength(FG, 0);
  SetLength(FY, 0);
  SetLength(FPeerY, 0);
  SetLength(FX, 0);
  FPublicKey := false;
  FSecretKey := false;
end;

procedure TElBuiltInDHCryptoKey.ImportPublic(Buffer: pointer; Size: integer; Params : TElCPParameters = nil);
begin
  // TODO
end;

procedure TElBuiltInDHCryptoKey.ImportSecret(Buffer: pointer; Size: integer; Params : TElCPParameters = nil);
begin
  SetLength(FX, Size);
  SBMove(Buffer^, FX[0], Length(FX));
  FSecretKey := true;
end;

procedure TElBuiltInDHCryptoKey.ExportPublic(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil);
begin
  // TODO
end;

procedure TElBuiltInDHCryptoKey.ExportSecret(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil);
begin
  if Size = 0 then
    Size := Length(FX)
  else
  begin
    if Size < Length(FX) then
      raise EElBuiltInCryptoProviderError.Create(SBufferTooSmall)
    else
    begin
      Size := Length(FX);
      SBMove(FX[0], Buffer^, Size);
    end;
  end;
end;

function TElBuiltInDHCryptoKey.Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoKey;
var
  Res : TElBuiltInDHCryptoKey;
begin
  Res := TElBuiltInDHCryptoKey.Create(FCryptoProvider);
  Res.FP := CloneArray(FP);
  Res.FG := CloneArray(FG);
  Res.FX := CloneArray(FX);
  Res.FY := CloneArray(FY);
  Res.FPeerY := CloneArray(FPeerY);
  Res.FPublicKey := FPublicKey;
  Res.FSecretKey := FSecretKey;
  Result := Res;
end;

function TElBuiltInDHCryptoKey.Equals(Source : TElCustomCryptoKey; PublicOnly : boolean;
  Params : TElCPParameters  =  nil): boolean;

var
  B : ByteArray;
begin

  Result := false;
  if Self.Algorithm <> Source.Algorithm then exit;
  Result := true;
  B := Source.GetKeyProp(SB_KEYPROP_DH_P);
  Result := Result and (Length(FP) = Length(B)) and
     (CompareMem(@FP[0], @B[0], Length(FP)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_DH_G);
  Result := Result and (Length(FG) = Length(B)) and
     (CompareMem(@FG[0], @B[0], Length(FG)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_DH_Y);
  Result := Result and (Length(FY) = Length(B)) and
     (CompareMem(@FY[0], @B[0], Length(FY)))
     ;

end;

function TElBuiltInDHCryptoKey.ClonePublic(Params : TElCPParameters  =  nil) : TElCustomCryptoKey;
var
  Res : TElBuiltInDHCryptoKey;
begin
  Res := TElBuiltInDHCryptoKey(Clone(Params));
  Res.FX := EmptyArray;
  Res.FSecretKey := false;
  Result := Res;
end;

function TElBuiltInDHCryptoKey.GetKeyProp(const PropID : ByteArray;
  const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif}  {$endif}): ByteArray;
begin
  if CompareContent(PropID, SB_KEYPROP_DH_P) then
    Result := CloneArray(FP)
  else if CompareContent(PropID, SB_KEYPROP_DH_G) then
    Result := CloneArray(FG)
  else if CompareContent(PropID, SB_KEYPROP_DH_X) then
    Result := CloneArray(FX)
  else if CompareContent(PropID, SB_KEYPROP_DH_Y) then
    Result := CloneArray(FY)
  else if CompareContent(PropID, SB_KEYPROP_DH_PEER_Y) then
    Result := CloneArray(FPeerY)
  else
    Result := Default;
end;

procedure TElBuiltInDHCryptoKey.SetKeyProp(const PropID : ByteArray; const Value : ByteArray);
begin
  if CompareContent(PropID, SB_KEYPROP_DH_P) then
    FP := CloneArray(Value)
  else if CompareContent(PropID, SB_KEYPROP_DH_G) then
    FG := CloneArray(Value)
  else if CompareContent(PropID, SB_KEYPROP_DH_X) then
    FX := CloneArray(Value)
  else if CompareContent(PropID, SB_KEYPROP_DH_Y) then
    FY := CloneArray(Value)
  else if CompareContent(PropID, SB_KEYPROP_DH_PEER_Y) then
    FPeerY := CloneArray(Value);
  FPublicKey := (Length(FP) > 0) and (Length(FG) > 0) and ((Length(FY) > 0) or (Length(FPeerY) > 0));
  FSecretKey := FPublicKey and ((Length(FX) > 0) or (Length(FPeerY) > 0));
end;

function TElBuiltInDHCryptoKey.GetIsPublic: boolean;
begin
  Result := FPublicKey;
end;

function TElBuiltInDHCryptoKey.GetIsSecret: boolean;
begin
  Result := FSecretKey;
end;

function TElBuiltInDHCryptoKey.GetIsExportable: boolean;
begin
  Result := true;
end;

function TElBuiltInDHCryptoKey.GetIsPersistent: boolean;
begin
  Result := false;
end;

function TElBuiltInDHCryptoKey.GetIsValid: boolean;
begin
  Result := true;
end;

function TElBuiltInDHCryptoKey.GetBits : integer;
begin
  Result := Length(FP) shl 3;
end;

function TElBuiltInDHCryptoKey.GetAlgorithm : integer;
begin
  Result := SB_ALGORITHM_PK_DH;
end;

function TElBuiltInDHCryptoKey.GetKeyStorage : TElCustomCryptoKeyStorage;
begin
  Result := nil;
end;

procedure TElBuiltInDHCryptoKey.ClearPublic;
begin
  Reset;
end;

procedure TElBuiltInDHCryptoKey.ClearSecret;
begin
  FX := EmptyArray;
  FSecretKey := false;
end;
 {$endif SB_NO_DH}

////////////////////////////////////////////////////////////////////////////////
//  TElBuiltInECCryptoKey class
{$ifdef SB_HAS_ECC}

 destructor  TElBuiltInECCryptoKey.Destroy;
begin
  FreeAndNil(FDomainParameters);
  inherited;
end;

function TElBuiltInECCryptoKey.CheckDomainParameters : boolean;
begin
  Result := FDomainParameters.Check;
end;

function TElBuiltInECCryptoKey.GetBits: integer;
begin
  Result := FDomainParameters.SubgroupBits;
end;
                              
function TElBuiltInECCryptoKey.GetIsPublic: boolean;
begin
  Result := FPublicKey and CheckDomainParameters;
end;

function TElBuiltInECCryptoKey.GetIsSecret: boolean;
begin
  Result := FSecretKey and CheckDomainParameters;
end;

function  TElBuiltInECCryptoKey.GetIsExportable: boolean;
begin
  Result := true;
end;

function TElBuiltInECCryptoKey.GetIsPersistent: boolean;
begin
  Result := false;
end;

function TElBuiltInECCryptoKey.GetIsValid: boolean;
var
  D, QX, QY : pointer;
begin
  Result := CheckDomainParameters;

  if Result then
  begin
    if FPublicKey then
    begin
      Result := Result and (Length(FQX) > 0);
      Result := Result and (Length(FQY) > 0);
    end;

    if FSecretKey then
      Result := Result and (Length(FD) > 0);

    if Result and FStrictKeyValidation then
      begin
        if FSecretKey then
          D := @FD[0]
        else
          D := nil;

        if FPublicKey then
        begin
          QX := @FQX[0];
          QY := @FQY[0];
        end
        else
        begin
          QX := nil;
          QY := nil;
        end;

        Result := Result and SBECCommon.ValidateKey(FDomainParameters,
          D, Length(FD), QX, Length(FQX), QY, Length(FQY));
      end;
  end;
end;

function TElBuiltInECCryptoKey.GetAlgorithm : integer;
begin
  Result := SB_ALGORITHM_PK_EC;
end;

function TElBuiltInECCryptoKey.GetKeyStorage : TElCustomCryptoKeyStorage;
begin
  Result := nil;
end;

constructor TElBuiltInECCryptoKey.Create(CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create(CryptoProvider);

  FDomainParameters := TElECDomainParameters.Create;
  Reset;
end;

procedure TElBuiltInECCryptoKey.Reset;
begin
  FPublicKey := false;
  FSecretKey := false;
  FDomainParameters.Reset;
  SetLength(FD, 0);
  SetLength(FQX, 0);
  SetLength(FQY, 0);
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInECCryptoKey.Generate(Bits : integer; Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil);
var
  QxSize, QySize, DSize, i : integer;
  UseExtGenerator : boolean;
  BoolRes : boolean;
begin
  if Assigned(Params) then
    for i := 0 to Params.Count - 1 do
      SetKeyProp(Params.OIDs[i], Params.Values[i]);

  FPublicKey := false;
  FSecretKey := false;

  if not CheckDomainParameters then
    raise EElBuiltInCryptoProviderError.Create(SInvalidECDomainParameters);

  if (FCryptoProvider is TElBuiltInCryptoProvider) then
    UseExtGenerator := TElBuiltInCryptoProviderOptions(TElBuiltInCryptoProvider(FCryptoProvider).Options).UsePlatformKeyGeneration and ((SBECDSA.ExternalGenerationSupported) or (not TElBuiltInCryptoProviderOptions(TElBuiltInCryptoProvider(FCryptoProvider).Options).RollbackToBuiltInKeyGeneration))
  else
    UseExtGenerator := false;

  DSize := 0;

  if UseExtGenerator then
    SBECDSA.ExternalGenerateEx(@FDomainParameters.A[0], Length(FDomainParameters.A),
      @FDomainParameters.B[0], Length(FDomainParameters.B), @FDomainParameters.X[0],
      Length(FDomainParameters.X), @FDomainParameters.Y[0], Length(FDomainParameters.Y),
      @FDomainParameters.N[0], Length(FDomainParameters.N), @FDomainParameters.P[0],
      Length(FDomainParameters.P), FDomainParameters.Curve, FDomainParameters.CurveOID,
      FDomainParameters.FieldType, FDomainParameters.Field,
      nil, DSize, nil, QxSize, nil, QySize)
  else
    SBECDSA.GenerateEx(@FDomainParameters.A[0], Length(FDomainParameters.A),
      @FDomainParameters.B[0], Length(FDomainParameters.B), @FDomainParameters.X[0],
      Length(FDomainParameters.X), @FDomainParameters.Y[0], Length(FDomainParameters.Y),
      @FDomainParameters.N[0], Length(FDomainParameters.N), @FDomainParameters.P[0],
      Length(FDomainParameters.P), FDomainParameters.FieldType, FDomainParameters.Field,
      nil, DSize, nil, QxSize, nil, QySize);

  SetLength(FD, DSize);
  SetLength(FQX, QxSize);
  SetLength(FQY, QySize);

  if UseExtGenerator then
    BoolRes :=
      SBECDSA.ExternalGenerateEx(@FDomainParameters.A[0], Length(FDomainParameters.A),
      @FDomainParameters.B[0], Length(FDomainParameters.B), @FDomainParameters.X[0],
      Length(FDomainParameters.X), @FDomainParameters.Y[0], Length(FDomainParameters.Y),
      @FDomainParameters.N[0], Length(FDomainParameters.N), @FDomainParameters.P[0],
      Length(FDomainParameters.P), FDomainParameters.Curve, FDomainParameters.CurveOID,
      FDomainParameters.FieldType, FDomainParameters.Field,
      @FD[0], DSize, @FQX[0], QxSize, @FQY[0], QySize)
  else
    BoolRes :=
      SBECDSA.GenerateEx(@FDomainParameters.A[0], Length(FDomainParameters.A),
      @FDomainParameters.B[0], Length(FDomainParameters.B), @FDomainParameters.X[0],
      Length(FDomainParameters.X), @FDomainParameters.Y[0], Length(FDomainParameters.Y),
      @FDomainParameters.N[0], Length(FDomainParameters.N), @FDomainParameters.P[0],
      Length(FDomainParameters.P), FDomainParameters.FieldType, FDomainParameters.Field,
      @FD[0], DSize, @FQX[0], QxSize, @FQY[0], QySize);
  if not BoolRes then
    raise EElBuiltInCryptoProviderError.Create(SKeyGenerationFailed);

  SetLength(FD, DSize);
  SetLength(FQX, QxSize);    
  SetLength(FQY, QySize);
  SetLength(FQ, 0); // will be filled in Export/ImportPublic call
  FPublicKey := true;
  FSecretKey := true;
end;
 {$endif SB_PGPSFX_STUB}

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInECCryptoKey.ImportPublic(Buffer: pointer; Size: integer; Params : TElCPParameters = nil);
var
  PubKey : ByteArray;
  i : integer;
begin

  if Assigned(Params) then
    for i := 0 to Params.Count - 1 do
      SetKeyProp(Params.OIDs[i], Params.Values[i]);

  ClearPublic;

  SetLength(PubKey, Size);
  SBMove(Buffer^, PubKey[0], Size);

  SetKeyProp(SB_KEYPROP_EC_Q, PubKey);

end;

procedure TElBuiltInECCryptoKey.ImportSecret(Buffer: pointer; Size: integer; Params : TElCPParameters = nil);
var
  cTag, cTag1 : TElASN1ConstrainedTag;
  SecKey, PubKey : ByteArray;
  i : integer;
begin
  if Assigned(Params) then
    for i := 0 to Params.Count - 1 do
      SetKeyProp(Params.OIDs[i], Params.Values[i]);

  ClearSecret;

  cTag := TElASN1ConstrainedTag.CreateInstance;

  try

    if not cTag.LoadFromBuffer(Buffer , Size ) then
      raise EElCryptoKeyError.Create(SInvalidSecretKey);

    if (cTag.Count <> 1) then
      raise EElCryptoKeyError.Create(SInvalidSecretKey);

    cTag1 := TElASN1ConstrainedTag(cTag.GetField(0));

    if (not cTag1.CheckType(SB_ASN1_SEQUENCE, true)) or (cTag1.Count < 2) or
      (not cTag1.GetField(0).CheckType(SB_ASN1_INTEGER, false)) or
      (not cTag1.GetField(1).CheckType(SB_ASN1_OCTETSTRING, false))
    then
      raise EElCryptoKeyError.Create(SInvalidSecretKey);

    { checking version }
    i := ASN1ReadInteger(TElASN1SimpleTag(cTag1.GetField(0)));
    if i <> 1 then
      raise EElCryptoKeyError.Create(SInvalidSecretKey);
    { copying secret key }
    SecKey := CloneArray(TElASN1SimpleTag(cTag1.GetField(1)).Content);
    SetKeyProp(SB_KEYPROP_EC_D, SecKey);
    FSecretKey := true;

    if (cTag1.Count > 2) then
      for i := 2 to cTag1.Count - 1 do
        if (cTag1.GetField(i).CheckType(SB_ASN1_A1, true)) then
        begin
          { copying public key }
          cTag1 := TElASN1ConstrainedTag(cTag1.GetField(i));
          if (not cTag1.Count = 1) or (not cTag1.GetField(0).CheckType(SB_ASN1_BITSTRING, false))
          then
            raise EElCryptoKeyError.Create(SInvalidSecretKey);

          PubKey := TrimLeadingZeros(TElASN1SimpleTag(cTag1.GetField(0)).Content);
          SetKeyProp(SB_KEYPROP_EC_Q, PubKey);
          FPublicKey := true;
          Break;
        end;
  finally
    FreeAndNil(cTag);

  end;
end;

procedure TElBuiltInECCryptoKey.ExportPublic(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil);
var
  PubKey : ByteArray;
begin

  if not FPublicKey then
  begin
    Size := 0;
    Exit;
  end;

  PubKey := GetKeyProp(SB_KEYPROP_EC_Q);

  if Length(PubKey) > Size then
  begin
    Size := Length(PubKey);
    Exit;
  end;

  Size := Length(PubKey);
  SBMove(PubKey[0], Buffer^, Size);

end;

procedure TElBuiltInECCryptoKey.ExportSecret(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil);
var
  SecKey, PubKey : ByteArray;
  Tmp : ByteArray;
  cTag, cTag1 : TElASN1ConstrainedTag;
begin
  if not FSecretKey then
  begin
    Size := 0;
    Exit;
  end;

  SecKey := GetKeyProp(SB_KEYPROP_EC_D);
  Tmp := GetKeyProp(SB_KEYPROP_EC_Q);
  SetLength(PubKey, Length(Tmp) + 1);
  PubKey[0] := byte(0);
  SBMove(Tmp[0], PubKey[0 + 1], Length(Tmp));

  cTag := TElASN1ConstrainedTag.CreateInstance;

  try
    cTag.AddField(true);
    cTag1 := TElASN1ConstrainedTag(cTag.GetField(0));
    cTag1.TagId := SB_ASN1_SEQUENCE;
    { version }
    cTag1.AddField(false);
    ASN1WriteInteger(TElASN1SimpleTag(cTag1.GetField(0)), 1);
    { secret key }
    cTag1.AddField(false);
    cTag1.GetField(1).TagId := SB_ASN1_OCTETSTRING;
    TElASN1SimpleTag(cTag1.GetField(1)).Content := CloneArray(SecKey);
    { public key }
    cTag1.AddField(true);
    cTag1.GetField(2).TagId := SB_ASN1_A1;
    cTag1 := TElASN1ConstrainedTag(cTag1.GetField(2));
    cTag1.AddField(false);
    cTag1.GetField(0).TagId := SB_ASN1_BITSTRING;
    TElASN1SimpleTag(cTag1.GetField(0)).Content := PubKey;

    cTag.GetField(0).SaveToBuffer(Buffer, Size);
  finally
    FreeAndNil(cTag);

  end;
end;
 {$endif SB_PGPSFX_STUB}

function TElBuiltInECCryptoKey.Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoKey;
var
  Res : TElBuiltInECCryptoKey;
begin
  Res := TElBuiltInECCryptoKey.Create(FCryptoProvider);
  Res.FPublicKey := FPublicKey;
  Res.FSecretKey := FSecretKey;
  if Length(FDomainParameters.CurveOID) > 0 then
    Res.FDomainParameters.CurveOID := CloneArray(FDomainParameters.CurveOID);


  if (FDomainParameters.Curve = SB_EC_CUSTOM) and (Length(FDomainParameters.CurveOID) = 0) then
  begin
    Res.FDomainParameters.Field := FDomainParameters.Field;
    Res.FDomainParameters.FieldType := FDomainParameters.FieldType;

    if FDomainParameters.FieldType = SB_EC_FLD_TYPE_FP then
      Res.FDomainParameters.P := CloneArray(FDomainParameters.P)
    else
    begin
      Res.FDomainParameters.M := FDomainParameters.M;
      Res.FDomainParameters.K1 := FDomainParameters.K1;
      Res.FDomainParameters.K2 := FDomainParameters.K2;
      Res.FDomainParameters.K3 := FDomainParameters.K3;
    end;  

    Res.FDomainParameters.A := CloneArray(FDomainParameters.A);
    Res.FDomainParameters.B := CloneArray(FDomainParameters.B);
    Res.FDomainParameters.N := CloneArray(FDomainParameters.N);
    Res.FDomainParameters.X := CloneArray(FDomainParameters.X);
    Res.FDomainParameters.Y := CloneArray(FDomainParameters.Y);
    Res.FDomainParameters.H := FDomainParameters.H;
    Res.FDomainParameters.Seed := CloneArray(FDomainParameters.Seed);
  end;

  Res.FQX := CloneArray(FQX);
  Res.FQY := CloneArray(FQY);
  Res.FQ := CloneArray(FQ);
  Res.FD := CloneArray(FD);
  Res.FStrictKeyValidation := FStrictKeyValidation;
  Res.FHashAlgorithm := FHashAlgorithm;

  Result := Res;
end;

function TElBuiltInECCryptoKey.Equals(Source : TElCustomCryptoKey;PublicOnly : boolean;
      Params : TElCPParameters  =  nil):boolean;
var
  B : ByteArray;
begin

  Result := false;
  if Self.Algorithm <> Source.Algorithm then exit;
  
  Result := (Self.GetKeyProp(SB_KEYPROP_EC_CURVE_INT) = Source.GetKeyProp(SB_KEYPROP_EC_CURVE_INT));
  B := Source.GetKeyProp(SB_KEYPROP_EC_P);
  Result := Result and (Length(FDomainParameters.P) = Length(B)) and
     (CompareMem(@FDomainParameters.P[0], @B[0], Length(FDomainParameters.P)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_EC_A);
  Result := Result and (Length(FDomainParameters.A) = Length(B)) and
     (CompareMem(@FDomainParameters.A[0], @B[0], Length(FDomainParameters.A)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_EC_B);
  Result := Result and (Length(FDomainParameters.B) = Length(B)) and
     (CompareMem(@FDomainParameters.B[0], @B[0], Length(FDomainParameters.B)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_EC_N);
  Result := Result and (Length(FDomainParameters.N) = Length(B)) and
     (CompareMem(@FDomainParameters.N[0], @B[0], Length(FDomainParameters.N)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_EC_X);
  Result := Result and (Length(FDomainParameters.X) = Length(B)) and
     (CompareMem(@FDomainParameters.X[0], @B[0], Length(FDomainParameters.X)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_EC_Y);
  Result := Result and (Length(FDomainParameters.Y) = Length(B)) and
     (CompareMem(@FDomainParameters.Y[0], @B[0], Length(FDomainParameters.Y)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_EC_D);
  Result := Result and (Length(FD) = Length(B)) and
     (CompareMem(@FD[0], @B[0], Length(FD)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_EC_QX);
  Result := Result and (Length(FQX) = Length(B)) and
     (CompareMem(@FQX[0], @B[0], Length(FQX)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_EC_QY);
  Result := Result and (Length(FQY) = Length(B)) and
     (CompareMem(@FQY[0], @B[0], Length(FQY)))
     ;

end;

function TElBuiltInECCryptoKey.ClonePublic(Params : TElCPParameters  =  nil) : TElCustomCryptoKey;
begin
  Result := Clone(Params);
  TElBuiltInECCryptoKey(Result).FSecretKey := false;
  TElBuiltInECCryptoKey(Result).FD := EmptyArray;
end;

procedure TElBuiltInECCryptoKey.ClearPublic;
begin
  FPublicKey := false;
  SetLength(FQX, 0);
  SetLength(FQY, 0);
end;

procedure TElBuiltInECCryptoKey.ClearSecret;
begin
  FSecretKey := false;
  SetLength(FD, 0);
end;

function TElBuiltInECCryptoKey.GetKeyProp(const PropID : ByteArray; const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif}  {$endif}): ByteArray;
var
  BufSize : integer;
begin
  if Length(Default) > 0 then
    Result := CloneArray(Default)
  else
    Result := EmptyArray;

  if CompareContent(PropID, SB_KEYPROP_EC_CURVE) then
    Result := CloneArray(FDomainParameters.CurveOID)
  else if CompareContent(PropID, SB_KEYPROP_EC_CURVE_INT) then
    Result := GetBufferFromInteger(FDomainParameters.Curve)
  else if CompareContent(PropID, SB_KEYPROP_EC_FIELD) then
  begin
    if FDomainParameters.Field = SB_EC_FLD_CUSTOM then
      Result := SB_OID_FLD_CUSTOM;
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_FIELD_INT) then
    Result := GetBufferFromInteger(FDomainParameters.Field)
  else if CompareContent(PropID, SB_KEYPROP_EC_FIELD_BITS) then
    Result := GetBufferFromInteger(FDomainParameters.GetFieldBits)
  else if CompareContent(PropID, SB_KEYPROP_EC_SUBGROUP_BITS) then
    Result := GetBufferFromInteger(FDomainParameters.GetSubgroupBits)
  else if CompareContent(PropID, SB_KEYPROP_EC_FIELD_TYPE) then
  begin
    if FDomainParameters.FieldType = SB_EC_FLD_TYPE_FP then
      Result := SB_OID_FLD_TYPE_FP
    else if FDomainParameters.FieldType = SB_EC_FLD_TYPE_F2MP then
      Result := SB_OID_FLD_TYPE_F2M;
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_FIELD_TYPE_INT) then
    Result := GetBufferFromInteger(FDomainParameters.FieldType)
  else if CompareContent(PropID, SB_KEYPROP_EC_H) then
    Result := GetBufferFromInteger(FDomainParameters.H)
  else if CompareContent(PropID, SB_KEYPROP_EC_K1) then
    Result := GetBufferFromInteger(FDomainParameters.K1)
  else if CompareContent(PropID, SB_KEYPROP_EC_K2) then
    Result := GetBufferFromInteger(FDomainParameters.K2)
  else if CompareContent(PropID, SB_KEYPROP_EC_K3) then
    Result := GetBufferFromInteger(FDomainParameters.K3)
  else if CompareContent(PropID, SB_KEYPROP_EC_M) then
    Result := GetBufferFromInteger(FDomainParameters.M)
  else if CompareContent(PropID, SB_KEYPROP_EC_P) then
  begin
    if Length(FDomainParameters.P) > 0 then
      Result := CloneArray(FDomainParameters.P);
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_A) then
  begin
    if Length(FDomainParameters.A) > 0 then
      Result := CloneArray(FDomainParameters.A);
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_B) then
  begin
    if Length(FDomainParameters.B) > 0 then
      Result := CloneArray(FDomainParameters.B);
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_N) then
  begin
    if Length(FDomainParameters.N) > 0 then
      Result := CloneArray(FDomainParameters.N);
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_X) then
  begin
    if Length(FDomainParameters.X) > 0 then
      Result := CloneArray(FDomainParameters.X);
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_Y) then
  begin
    if Length(FDomainParameters.Y) > 0 then
      Result := CloneArray(FDomainParameters.Y);
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_BP) then
  begin
    if (Length(FDomainParameters.X) > 0) and (Length(FDomainParameters.Y) > 0) then
    begin
      BufSize := 0;

      SBECCommon.PointToBuffer(@FDomainParameters.X[0], Length(FDomainParameters.X),
        @FDomainParameters.Y[0], Length(FDomainParameters.Y), FDomainParameters, nil, BufSize, FCompressPoints, FHybridPoints);

      if (BufSize = 0) then Exit;

      SetLength(Result, BufSize);
      SBECCommon.PointToBuffer(@FDomainParameters.X[0], Length(FDomainParameters.X),
        @FDomainParameters.Y[0], Length(FDomainParameters.Y), FDomainParameters,
        @Result[0], BufSize, FCompressPoints, FHybridPoints);

      SetLength(Result, BufSize);
    end
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_QX) then
  begin
    if FPublicKey and (Length(FQX) > 0) then
      Result := CloneArray(FQX);
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_QY) then
  begin
    if FPublicKey and (Length(FQY) > 0) then
      Result := CloneArray(FQY);
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_Q) then
  begin
    if FPublicKey and ((Length(FQX) > 0)) and (Length(FQY) > 0) then
    begin
      if Length(FQ) > 0 then
      begin
        SetLength(Result, Length(FQ));
        SBMove(FQ[0], Result[0], Length(FQ));
        Exit;
      end;

      BufSize := 0;

      SBECCommon.PointToBuffer(@FQX[0], Length(FQX), @FQY[0], Length(FQY),
        FDomainParameters, nil, BufSize, FCompressPoints, FHybridPoints);

      if (BufSize = 0) then Exit;

      SetLength(Result, BufSize);

      SBECCommon.PointToBuffer(@FQX[0], Length(FQX), @FQY[0], Length(FQY),
        FDomainParameters, @Result[0], BufSize, FCompressPoints, FHybridPoints);

      SetLength(Result, BufSize);
      SetLength(FQ, BufSize);
      SBMove(Result[0], FQ[0], BufSize);
    end
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_SEED) then
   Result := CloneArray(FDomainParameters.Seed)
  else if CompareContent(PropID, SB_KEYPROP_EC_D) then
  begin
    if FSecretKey and (Length(FD) > 0) then
      Result := CloneArray(FD);
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_COMPRESS_POINTS) then
  begin
    Result := GetBufferFromBool(FCompressPoints);
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_HYBRID_POINTS) then
  begin
    Result := GetBufferFromBool(FHybridPoints);
  end
  else if CompareContent(PropID, SB_KEYPROP_HASH_ALGORITHM) then
    Result := GetOIDByHashAlgorithm(FHashAlgorithm)
  else
    raise EElCryptoProviderError.Create(SInvalidKeyProperty);
end;

procedure TElBuiltInECCryptoKey.SetKeyProp(const PropID : ByteArray; const Value : ByteArray);
var
  XSize, YSize : integer;
  X, Y : ByteArray;
  Bt : byte;
begin
  if CompareContent(PropID, SB_KEYPROP_EC_CURVE) then
  begin
    FDomainParameters.CurveOID := Value;
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_CURVE_INT) then
  begin
    FDomainParameters.Curve := GetIntegerPropFromBuffer(Value);
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_FIELD) then
  begin
    if CompareContent(Value, SB_OID_FLD_CUSTOM) then
      FDomainParameters.Field := SB_EC_FLD_CUSTOM
    else
      raise EElBuiltInCryptoProviderError.Create(SUnknownField);
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_FIELD_INT) then
  begin
    FDomainParameters.Field := GetIntegerPropFromBuffer(Value);
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_FIELD_TYPE) then
  begin
    if CompareContent(Value, SB_OID_FLD_TYPE_FP) then
      FDomainParameters.FieldType := SB_EC_FLD_TYPE_FP
    else if CompareContent(Value, SB_OID_FLD_TYPE_F2M) then
      FDomainParameters.FieldType := SB_EC_FLD_TYPE_F2MP
    else
      raise EElBuiltInCryptoProviderError.Create(SUnknownField);
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_FIELD_TYPE_INT) then
  begin
    FDomainParameters.FieldType := GetIntegerPropFromBuffer(Value);
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_P) then
    FDomainParameters.P := CloneArray(Value)
  else if CompareContent(PropID, SB_KEYPROP_EC_M) then
    FDomainParameters.M := GetIntegerPropFromBuffer(Value)
  else if CompareContent(PropID, SB_KEYPROP_EC_K1) then
    FDomainParameters.K1 := GetIntegerPropFromBuffer(Value)
  else if CompareContent(PropID, SB_KEYPROP_EC_K2) then
    FDomainParameters.K2 := GetIntegerPropFromBuffer(Value)
  else if CompareContent(PropID, SB_KEYPROP_EC_K3) then
    FDomainParameters.K3 := GetIntegerPropFromBuffer(Value)
  else if CompareContent(PropID, SB_KEYPROP_EC_A) then
    FDomainParameters.A := CloneArray(Value)
  else if CompareContent(PropID, SB_KEYPROP_EC_B) then
    FDomainParameters.B := CloneArray(Value)
  else if CompareContent(PropID, SB_KEYPROP_EC_N) then
    FDomainParameters.N := CloneArray(Value)
  else if CompareContent(PropID, SB_KEYPROP_EC_H) then
    FDomainParameters.H := GetIntegerPropFromBuffer(Value)
  else if CompareContent(PropID, SB_KEYPROP_EC_X) then
    FDomainParameters.X := CloneArray(Value)
  else if CompareContent(PropID, SB_KEYPROP_EC_Y) then
    FDomainParameters.Y := CloneArray(Value)
  else if CompareContent(PropID, SB_KEYPROP_EC_SEED) then
    FDomainParameters.Seed := CloneArray(Value)
  else if CompareContent(PropID, SB_KEYPROP_EC_BP) then
  begin
    XSize := 0;
    YSize := 0;

    SBECCommon.BufferToPoint(@Value[0], Length(Value), FDomainParameters, nil, XSize, nil, YSize);

    if (XSize = 0) or (YSize = 0) then
      raise EElBuiltInCryptoProviderError.Create(SUnsupportedPropertyValue);

    SetLength(X, XSize);
    SetLength(Y, YSize);

    SBECCommon.BufferToPoint(@Value[0], Length(Value), FDomainParameters, @X[0], XSize, @Y[0], YSize);

    SetLength(X, XSize);
    SetLength(Y, YSize);

    FDomainParameters.X := X;
    FDomainParameters.Y := Y;
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_QX) then
  begin
    FQX := CloneArray(Value);
    FPublicKey := (Length(FQX) > 0) and (Length(FQY) > 0);
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_QY) then
  begin
    FQY := CloneArray(Value);
    FPublicKey := (Length(FQX) > 0) and (Length(FQY) > 0);
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_Q) then
  begin
    XSize := 0;
    YSize := 0;

    if Length(Value) < 1 then Exit;

    Bt := Value[0];

    SBECCommon.BufferToPoint(@Value[0], Length(Value), FDomainParameters, nil, XSize, nil, YSize);

    if (XSize = 0) or (YSize = 0) then
      raise EElBuiltInCryptoProviderError.Create(SUnsupportedPropertyValue);

    SetLength(FQX, XSize);
    SetLength(FQY, YSize);

    SBECCommon.BufferToPoint(@Value[0], Length(Value), FDomainParameters, @FQX[0], XSize, @FQY[0], YSize);

    SetLength(FQX, XSize);
    SetLength(FQY, YSize);

    FPublicKey := (Length(FQX) > 0) and (Length(FQY) > 0);

    SetLength(FQ, Length(Value));
    SBMove(Value[0], FQ[0], Length(Value));

    if (Bt = 2) or (Bt = 3) then
      FCompressPoints := true
    else if (Bt = 6) or (Bt = 7) then
    begin
      FCompressPoints := true;
      FHybridPoints := true;
    end
    else
    begin
      FCompressPoints := false;
      FHybridPoints := false;
    end;
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_D) then
  begin
    FD := CloneArray(Value);
    FSecretKey := Length(FD) > 0;
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_COMPRESS_POINTS) then
  begin
    FCompressPoints := GetBoolFromBuffer(Value);
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_HYBRID_POINTS) then
  begin
    FHybridPoints := GetBoolFromBuffer(Value);
  end
  else if CompareContent(PropID, SB_KEYPROP_HASH_ALGORITHM) then
    FHashAlgorithm := GetHashAlgorithmByOID(Value)
  else
    raise EElCryptoProviderError.Create(SInvalidKeyProperty);
  ReleaseArray(X);
  ReleaseArray(Y);
end;

{$ifndef SB_NO_PKIASYNC}
function TElBuiltInECCryptoKey.AsyncOperationFinished : boolean;
begin
  Result := false;
end;
 {$endif}

 {$endif}

{$ifdef SB_HAS_GOST}
////////////////////////////////////////////////////////////////////////////////
// TElBuiltInGOST94CryptoKey class

constructor TElBuiltInGOST341094CryptoKey.Create(CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
  Reset;
end;

 destructor  TElBuiltInGOST341094CryptoKey.Destroy;
begin
  inherited;
end;

procedure LIntToByteArray(const V: PLInt; var Arr: ByteArray);
var
  Size: integer;
begin
  Size := V.Length * 4;
  SetLength(Arr, Size);
  LIntToPointer(V, @Arr[0], Size);
end;

procedure TElBuiltInGOST341094CryptoKey.LoadParamset(const Paramset : ByteArray);
var
  T : integer;
begin
  if CompareContent(Paramset, SB_OID_GOST_R3410_1994_PARAM_CP_TEST) then
  begin
    T := SB_GOSTR3410_94_TestParamSet_T shr 3;
    SetLength(FP, T);
    SetLength(FQ, 32);
    SetLength(FA, T);

    StringToBinary(SB_GOSTR3410_94_TestParamSet_P, @FP[0], T);
    StringToBinary(SB_GOSTR3410_94_TestParamSet_A, @FA[0], T);
    T := 32;
    StringToBinary(SB_GOSTR3410_94_TestParamSet_Q, @FQ[0], T);
  end
  else if CompareContent(Paramset, SB_OID_GOST_R3410_1994_PARAM_CP_A) then
  begin
    T := SB_GOSTR3410_94_CryptoPro_A_ParamSet_T shr 3;
    SetLength(FP, T);
    SetLength(FQ, 32);
    SetLength(FA, T);

    StringToBinary(SB_GOSTR3410_94_CryptoPro_A_ParamSet_P, @FP[0], T);
    StringToBinary(SB_GOSTR3410_94_CryptoPro_A_ParamSet_A, @FA[0], T);
    T := 32;
    StringToBinary(SB_GOSTR3410_94_CryptoPro_A_ParamSet_Q, @FQ[0], T);
  end
  else if CompareContent(Paramset, SB_OID_GOST_R3410_1994_PARAM_CP_B) then
  begin
    T := SB_GOSTR3410_94_CryptoPro_B_ParamSet_T shr 3;
    SetLength(FP, T);
    SetLength(FQ, 32);
    SetLength(FA, T);

    StringToBinary(SB_GOSTR3410_94_CryptoPro_B_ParamSet_P, @FP[0], T);
    StringToBinary(SB_GOSTR3410_94_CryptoPro_B_ParamSet_A, @FA[0], T);
    T := 32;
    StringToBinary(SB_GOSTR3410_94_CryptoPro_B_ParamSet_Q, @FQ[0], T);
  end
  else if CompareContent(Paramset, SB_OID_GOST_R3410_1994_PARAM_CP_C) then
  begin
    T := SB_GOSTR3410_94_CryptoPro_C_ParamSet_T shr 3;
    SetLength(FP, T);
    SetLength(FQ, 32);
    SetLength(FA, T);

    StringToBinary(SB_GOSTR3410_94_CryptoPro_C_ParamSet_P, @FP[0], T);
    StringToBinary(SB_GOSTR3410_94_CryptoPro_C_ParamSet_A, @FA[0], T);
    T := 32;
    StringToBinary(SB_GOSTR3410_94_CryptoPro_C_ParamSet_Q, @FQ[0], T);
  end
  else if CompareContent(Paramset, SB_OID_GOST_R3410_1994_PARAM_CP_D) then
  begin
    T := SB_GOSTR3410_94_CryptoPro_D_ParamSet_T shr 3;
    SetLength(FP, T);
    SetLength(FQ, 32);
    SetLength(FA, T);

    StringToBinary(SB_GOSTR3410_94_CryptoPro_D_ParamSet_P, @FP[0], T);
    StringToBinary(SB_GOSTR3410_94_CryptoPro_D_ParamSet_A, @FA[0], T);
    T := 32;
    StringToBinary(SB_GOSTR3410_94_CryptoPro_D_ParamSet_Q, @FQ[0], T);
  end
  else if CompareContent(Paramset, SB_OID_GOST_R3410_1994_PARAM_CP_XCHA) then
  begin
    T := SB_GOSTR3410_94_CryptoPro_XCHA_ParamSet_T shr 3;
    SetLength(FP, T);
    SetLength(FQ, 32);
    SetLength(FA, T);

    StringToBinary(SB_GOSTR3410_94_CryptoPro_XCHA_ParamSet_P, @FP[0], T);
    StringToBinary(SB_GOSTR3410_94_CryptoPro_XCHA_ParamSet_A, @FA[0], T);
    T := 32;
    StringToBinary(SB_GOSTR3410_94_CryptoPro_XCHA_ParamSet_Q, @FQ[0], T);
  end
  else if CompareContent(Paramset, SB_OID_GOST_R3410_1994_PARAM_CP_XCHB) then
  begin
    T := SB_GOSTR3410_94_CryptoPro_XCHB_ParamSet_T shr 3;
    SetLength(FP, T);
    SetLength(FQ, 32);
    SetLength(FA, T);

    StringToBinary(SB_GOSTR3410_94_CryptoPro_XCHB_ParamSet_P, @FP[0], T);
    StringToBinary(SB_GOSTR3410_94_CryptoPro_XCHB_ParamSet_A, @FA[0], T);
    T := 32;
    StringToBinary(SB_GOSTR3410_94_CryptoPro_XCHB_ParamSet_Q, @FQ[0], T);
  end
  else if CompareContent(Paramset, SB_OID_GOST_R3410_1994_PARAM_CP_XCHC) then
  begin
    T := SB_GOSTR3410_94_CryptoPro_XCHC_ParamSet_T shr 3;
    SetLength(FP, T);
    SetLength(FQ, 32);
    SetLength(FA, T);

    StringToBinary(SB_GOSTR3410_94_CryptoPro_XCHC_ParamSet_P, @FP[0], T);
    StringToBinary(SB_GOSTR3410_94_CryptoPro_XCHC_ParamSet_A, @FA[0], T);
    T := 32;
    StringToBinary(SB_GOSTR3410_94_CryptoPro_XCHC_ParamSet_Q, @FQ[0], T);
  end
  else
    raise EElCryptoKeyError.Create(SInvalidPropertyValue);
end;

procedure TElBuiltInGOST341094CryptoKey.Generate(Bits : integer;
  Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil);
var
  LP, LQ, LA, LY, LX : PLInt;
  i : integer;
begin
  if (FCryptoProvider <> nil) and (FCryptoProvider.Options.MaxPublicKeySize > 0)
    and (Bits > FCryptoProvider.Options.MaxPublicKeySize) then
    raise EElBuiltInCryptoProviderError.Create(SPublicKeyTooLong);

  if Assigned(Params) then
    for i := 0 to Params.Count - 1 do
      SetKeyProp(Params.OIDs[i], Params.Values[i]);

  LCreate(LP);
  LCreate(LQ);
  LCreate(LA);
  LCreate(LY);
  LCreate(LX);
  try
    if (Length(FP) = 0) or (Length(FQ) = 0) or (Length(FA) = 0) then
      raise EElBuiltInCryptoProviderError.Create(SKeyGenerationFailed);

    PointerToLInt(LP, @FP[0], Length(FP));
    PointerToLInt(LQ, @FQ[0], Length(FQ));
    PointerToLInt(LA, @FA[0], Length(FA));

    TElGOSTSigner.Generate_Keys(LP, LQ, LA, LX, LY);

    LIntToByteArray(LX, FX);
    LIntToByteArray(LY, FY);

    FSecretKey := true;
    FPublicKey := true;
    TrimParams;
  finally
    LDestroy(LP);
    LDestroy(LQ);
    LDestroy(LA);
    LDestroy(LY);
    LDestroy(LX);
  end;
end;

procedure TElBuiltInGOST341094CryptoKey.Reset;
begin
  inherited;
  SetLength(FP, 0);
  SetLength(FQ, 0);
  SetLength(FA, 0);
  SetLength(FY, 0);
  SetLength(FX, 0);
  SetLength(FC, 0);
  SetLength(FD, 0);
  Fx0 := 0;
  FParamSet := SB_OID_GOST_R3410_1994_PARAM_CP_A;
  LoadParamset(FParamset);
  FDigestParamSet := SB_OID_GOST_R3411_1994_PARAM_CP;
  FEncryptionParamSet := SB_OID_GOST_28147_1989_PARAM_CP_A;

  FPublicKey := false;
  FSecretKey := false;
end;

procedure TElBuiltInGOST341094CryptoKey.ImportPublic(Buffer: pointer; Size: integer; Params : TElCPParameters = nil);
begin
  SetLength(FY, Size);
  if Size > 0 then
  begin
    SBMove(Buffer^, FY[0], Size);
    FY := ChangeByteOrder(FY);
    FPublicKey := true;
  end;  
end;

procedure TElBuiltInGOST341094CryptoKey.ImportSecret(Buffer: pointer; Size: integer; Params : TElCPParameters = nil);
begin
  SetLength(FX, Size);
  if Size > 0 then
  begin
    SBMove(Buffer^, FX[0], Size);
    FX := ChangeByteOrder(FX);
    FSecretKey := true;
  end;
end;

procedure TElBuiltInGOST341094CryptoKey.ExportPublic(Buffer: pointer; var Size: integer;
  Params : TElCPParameters = nil);
var
  TmpY : ByteArray;
begin

  SetLength(TmpY, 0);
  if Size < Length(FY) then
  begin
    Size := Length(FY);
    Exit;
  end;

  Size := Length(FY);
  TmpY := ChangeByteOrder(FY);

  if Length(FY) > 0 then
    SBMove(TmpY[0], Buffer^, Size);

end;

procedure TElBuiltInGOST341094CryptoKey.ExportSecret(Buffer: pointer; var Size: integer;
  Params : TElCPParameters = nil);
var
  TmpX : ByteArray;
begin

  SetLength(TmpX, 0);
  if Size < Length(FX) then
  begin
    Size := Length(FX);
    Exit;
  end;

  Size := Length(FX);
  TmpX := ChangeByteOrder(FX);

  if Length(FX) > 0 then
    SBMove(TmpX[0], Buffer^, Size);

end;

function TElBuiltInGOST341094CryptoKey.Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoKey;
var
  Res : TElBuiltInGOST341094CryptoKey;
begin
  Res := TElBuiltInGOST341094CryptoKey.Create(FCryptoProvider);
  Res.FP := CloneArray(FP);
  Res.FQ := CloneArray(FQ);
  Res.FA := CloneArray(FA);
  Res.FY := CloneArray(FY);
  Res.FX := CloneArray(FX);
  Res.FSecretKey := FSecretKey;
  Res.FPublicKey := FPublicKey;
  Res.FParamSet := CloneArray(FParamSet);
  Res.FDigestParamSet := CloneArray(FDigestParamSet);
  Res.FEncryptionParamSet := CloneArray(FEncryptionParamSet);
  Result := Res;
end;

function TElBuiltInGOST341094CryptoKey.Equals(Source : TElCustomCryptoKey; PublicOnly : boolean;
      Params : TElCPParameters  =  nil): boolean;
var
  B : ByteArray;
begin

  Result := false;
  if Self.Algorithm <> Source.Algorithm then exit;
  Result := true;
  B := Source.GetKeyProp(SB_KEYPROP_GOST_R3410_1994_P);
  Result := Result and
     (CompareMem(@FP[0], @B[0], Length(FP)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_GOST_R3410_1994_Q);
  Result := Result and (Length(FQ) = Length(B)) and
     (CompareMem(@FQ[0], @B[0], Length(FQ)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_GOST_R3410_1994_A);
  Result := Result and (Length(FA) = Length(B)) and
     (CompareMem(@FA[0], @B[0], Length(FA)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_GOST_R3410_1994_X);
  Result := Result and (Length(FX) = Length(B)) and
     (CompareMem(@FX[0], @B[0], Length(FX)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_GOST_R3410_1994_Y);
  Result := Result and (Length(FY) = Length(B)) and
     (CompareMem(@FY[0], @B[0], Length(FY)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_GOST_R3410_PARAMSET);
  Result := Result and CompareContent(B, FParamSet);
  B := Source.GetKeyProp(SB_KEYPROP_GOST_R3410_DIGEST_PARAMSET);
  Result := Result and CompareContent(B, FDigestParamSet);
  B := Source.GetKeyProp(SB_KEYPROP_GOST_R3410_ENCRYPTION_PARAMSET);
  Result := Result and CompareContent(B, FEncryptionParamSet);

end;

function TElBuiltInGOST341094CryptoKey.ClonePublic(Params : TElCPParameters  =  nil) : TElCustomCryptoKey;
var
  Res : TElBuiltInGOST341094CryptoKey;
begin
  Result := Clone(Params);
  Res := TElBuiltInGOST341094CryptoKey(Result);
  Res.ClearSecret;
end;

function TElBuiltInGOST341094CryptoKey.GetKeyProp(const PropID : ByteArray;
  const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif}  {$endif}): ByteArray;
begin
  if CompareContent(PropID, SB_KEYPROP_GOST_R3410_1994_P) then
    Result := CloneArray(FP)
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_1994_Q) then
    Result := CloneArray(FQ)
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_1994_A) then
    Result := CloneArray(FA)
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_1994_X) then
    Result := CloneArray(FX)
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_1994_Y) then
    Result := CloneArray(FY)
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_1994_C) then
    Result := CloneArray(FC)
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_1994_D) then
    Result := CloneArray(FD)
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_1994_X0) then
    Result := GetBufferFromInteger(FX0)
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_PARAMSET) then
    Result := CloneArray(FParamSet)
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_DIGEST_PARAMSET) then
    Result := CloneArray(FDigestParamSet)
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_ENCRYPTION_PARAMSET) then
    Result := CloneArray(FEncryptionParamSet)
  else
    Result := Default;
end;

procedure TElBuiltInGOST341094CryptoKey.SetKeyProp(const PropID : ByteArray; const Value : ByteArray);
  procedure ReAdjustKeyFlags;
  begin
    FPublicKey := (Length(FP) > 0) and (Length(FQ) > 0) and (Length(FA) > 0) and (Length(FY) > 0);
    FSecretKey := (Length(FP) > 0) and (Length(FQ) > 0) and (Length(FA) > 0) and (Length(FX) > 0);
    //FSecretKey := FPublicKey and (Length(FX) > 0); changed to comply JCE interfaces
  end;
begin
  if CompareContent(PropID, SB_KEYPROP_GOST_R3410_1994_P) then
  begin
    FP := CloneArray(Value);
    ReAdjustKeyFlags;
  end
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_1994_Q) then
  begin
    FQ := CloneArray(Value);
    ReAdjustKeyFlags;
  end
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_1994_A) then
  begin
    FA := CloneArray(Value);
    ReAdjustKeyFlags;
  end
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_1994_X) then
  begin
    FX := CloneArray(Value);
    ReAdjustKeyFlags;
  end
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_1994_Y) then
  begin
    FY := CloneArray(Value);
    ReAdjustKeyFlags;
  end
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_1994_C) then
  begin
    FC := CloneArray(Value);
    ReAdjustKeyFlags;
  end
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_1994_D) then
  begin
    FD := CloneArray(Value);
    ReAdjustKeyFlags;
  end
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_1994_X0) then
  begin
    FX0 := GetIntegerPropFromBuffer(Value);
    ReAdjustKeyFlags;
  end
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_PARAMSET) then
  begin
    FParamSet := CloneArray(Value);
    LoadParamset(Value);
    ReAdjustKeyFlags;
  end
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_DIGEST_PARAMSET) then
  begin
    FDigestParamSet := CloneArray(Value);
  end
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_ENCRYPTION_PARAMSET) then
  begin
    FEncryptionParamSet := CloneArray(Value);
  end;
end;

procedure TElBuiltInGOST341094CryptoKey.TrimParams;
begin
  TrimParam(FP);
  TrimParam(FQ);
  TrimParam(FA);
  TrimParam(FY);
  if FSecretKey then
    TrimParam(FX);
end;

function TElBuiltInGOST341094CryptoKey.GetIsPublic: boolean;
begin
  Result := FPublicKey;
end;

function TElBuiltInGOST341094CryptoKey.GetIsSecret: boolean;
begin
  Result := FSecretKey;
end;

function TElBuiltInGOST341094CryptoKey.GetIsExportable: boolean;
begin
  Result := true;
end;

function TElBuiltInGOST341094CryptoKey.GetIsPersistent: boolean;
begin
  Result := false;
end;

function TElBuiltInGOST341094CryptoKey.GetIsValid: boolean;
begin
  Result := true;
end;

function TElBuiltInGOST341094CryptoKey.GetBits : integer;
begin
  Result := Length(FP) shl 3;
end;

function TElBuiltInGOST341094CryptoKey.GetAlgorithm : integer;
begin
  Result := SB_ALGORITHM_PK_GOST_R3410_1994;
end;

function TElBuiltInGOST341094CryptoKey.GetKeyStorage : TElCustomCryptoKeyStorage;
begin
  Result := nil;
end;

procedure TElBuiltInGOST341094CryptoKey.ClearPublic;
begin
  Reset;
end;

procedure TElBuiltInGOST341094CryptoKey.ClearSecret;
begin
  FX := EmptyArray;
  FSecretKey := false;
end;

{$ifdef SB_HAS_ECC}
////////////////////////////////////////////////////////////////////////////////
// TElBuiltInGOST34102001CryptoKey class

constructor TElBuiltInGOST34102001CryptoKey.Create(CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;

  FDomainParameters := TElECDomainParameters.Create;
  Reset;
end;

 destructor  TElBuiltInGOST34102001CryptoKey.Destroy;
begin
  FreeAndNil(FDomainParameters);
  inherited;
end;

procedure TElBuiltInGOST34102001CryptoKey.LoadParamset(const Paramset : ByteArray);
begin
  if CompareContent(Paramset, SB_OID_EC_GOST_CP_TEST) or
    CompareContent(Paramset, SB_OID_EC_GOST_CP_A) or
    CompareContent(Paramset, SB_OID_EC_GOST_CP_B) or
    CompareContent(Paramset, SB_OID_EC_GOST_CP_C) or
    CompareContent(Paramset, SB_OID_EC_GOST_CP_XCHA) or
    CompareContent(Paramset, SB_OID_EC_GOST_CP_XCHB)
  then
    FDomainParameters.CurveOID := Paramset
  else
    raise EElCryptoKeyError.Create(SInvalidPropertyValue);
end;

procedure TElBuiltInGOST34102001CryptoKey.Generate(Bits : integer;
  Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil);
var
  QxSize, QySize, DSize, i : integer;
begin
  if Assigned(Params) then
    for i := 0 to Params.Count - 1 do
      SetKeyProp(Params.OIDs[i], Params.Values[i]);

  FPublicKey := false;
  FSecretKey := false;

  if Length(FParamSet) = 0 then
    raise EElBuiltInCryptoProviderError.Create(SInvalidECDomainParameters);

  DSize := 0;

  SBGOST341001.Generate(@FDomainParameters.A[0], Length(FDomainParameters.A),
    @FDomainParameters.B[0], Length(FDomainParameters.B), @FDomainParameters.X[0],
    Length(FDomainParameters.X), @FDomainParameters.Y[0], Length(FDomainParameters.Y),
    @FDomainParameters.N[0], Length(FDomainParameters.N), @FDomainParameters.P[0],
    Length(FDomainParameters.P), FDomainParameters.Field,
    nil, DSize, nil, QxSize, nil, QySize);

  SetLength(FD, DSize);
  SetLength(FQX, QxSize);
  SetLength(FQY, QySize);

  if not SBGOST341001.Generate(@FDomainParameters.A[0], Length(FDomainParameters.A),
    @FDomainParameters.B[0], Length(FDomainParameters.B), @FDomainParameters.X[0],
    Length(FDomainParameters.X), @FDomainParameters.Y[0], Length(FDomainParameters.Y),
    @FDomainParameters.N[0], Length(FDomainParameters.N), @FDomainParameters.P[0],
    Length(FDomainParameters.P), FDomainParameters.Field,
    @FD[0], DSize, @FQX[0], QxSize, @FQY[0], QySize)
  then
    raise EElBuiltInCryptoProviderError.Create(SKeyGenerationFailed);

  SetLength(FD, DSize);
  SetLength(FQX, QxSize);    
  SetLength(FQY, QySize);
  SetLength(FQ, 0); // will be filled in Export/ImportPublic call
  FPublicKey := true;
  FSecretKey := true;
end;

procedure TElBuiltInGOST34102001CryptoKey.Reset;
begin
  inherited;
  SetLength(FQ, 0);
  SetLength(FQX, 0);
  SetLength(FQY, 0);
  SetLength(FD, 0);

  FParamSet := SB_OID_EC_GOST_CP_A;  
  LoadParamset(SB_OID_EC_GOST_CP_A);
  FDigestParamSet := SB_OID_GOST_R3411_1994_PARAM_CP;
  FEncryptionParamSet := SB_OID_GOST_28147_1989_PARAM_CP_A;
  FPublicKey := false;
  FSecretKey := false;
end;

procedure TElBuiltInGOST34102001CryptoKey.ImportPublic(Buffer: pointer; Size: integer; Params : TElCPParameters = nil);
var
  PubKey : ByteArray;
  i : integer;
begin

  if Assigned(Params) then
    for i := 0 to Params.Count - 1 do
      SetKeyProp(Params.OIDs[i], Params.Values[i]);

  ClearPublic;

  SetLength(PubKey, Size);
  SBMove(Buffer^, PubKey[0], Size);

  SetKeyProp(SB_KEYPROP_EC_Q, PubKey);

end;

procedure TElBuiltInGOST34102001CryptoKey.ImportSecret(Buffer: pointer; Size: integer; Params : TElCPParameters = nil);
var
  Value : ByteArray;
  i : integer;
begin

  if Assigned(Params) then
    for i := 0 to Params.Count - 1 do
      SetKeyProp(Params.OIDs[i], Params.Values[i]);

  ClearSecret;

  SetLength(Value, Size);
  if Size > 0 then
  begin
    SBMove(Buffer^, Value[0], Size);
    SetKeyProp(SB_KEYPROP_EC_D, ChangeByteOrder(Value));
  end;

end;

procedure TElBuiltInGOST34102001CryptoKey.ExportPublic(Buffer: pointer; var Size: integer;
  Params : TElCPParameters = nil);
var
  TmpX, TmpY, PubKey : ByteArray;
begin

  if not FPublicKey then
  begin
    Size := 0;
    Exit;
  end;

  TmpX := ChangeByteOrder(GetKeyProp(SB_KEYPROP_EC_QX));
  TmpY := ChangeByteOrder(GetKeyProp(SB_KEYPROP_EC_QY));

  if Length(TmpX) + Length(TmpY) > Size then
  begin
    Size := Length(TmpX) + Length(TmpY);
    Exit;
  end;

  SetLength(PubKey, Length(TmpX) + Length(TmpY));
  SBMove(TmpX[0], PubKey[0], Length(TmpX));
  SBMove(TmpY[0], PubKey[0 + Length(TmpX)], Length(TmpY));

  Size := Length(PubKey);
  SBMove(PubKey[0], Buffer^, Size);

end;

procedure TElBuiltInGOST34102001CryptoKey.ExportSecret(Buffer: pointer; var Size: integer;
  Params : TElCPParameters = nil);
var
  SecKey : ByteArray;
begin

  if not FSecretKey then
  begin
    Size := 0;
    Exit;
  end;

  SecKey := ChangeByteOrder(GetKeyProp(SB_KEYPROP_EC_D));

  if Length(SecKey) > Size then
  begin
    Size := Length(SecKey);
    Exit;
  end;

  Size := Length(SecKey);
  SBMove(SecKey[0], Buffer^, Size);

end;

function TElBuiltInGOST34102001CryptoKey.Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoKey;
var
  Res : TElBuiltInGOST34102001CryptoKey;
begin
  Res := TElBuiltInGOST34102001CryptoKey.Create(FCryptoProvider);
  Res.FD := CloneArray(FD);
  Res.FQ := CloneArray(FQ);
  Res.FQX := CloneArray(FQX);
  Res.FQY := CloneArray(FQY);
  Res.FSecretKey := FSecretKey;
  Res.FPublicKey := FPublicKey;
  Res.FParamSet := CloneArray(FParamSet);
  Res.LoadParamset(Res.FParamSet);
  Res.FDigestParamSet := CloneArray(FDigestParamSet);
  Res.FEncryptionParamSet := CloneArray(FEncryptionParamSet);
  Result := Res;
end;

function TElBuiltInGOST34102001CryptoKey.Equals(Source : TElCustomCryptoKey; PublicOnly : boolean;
  Params : TElCPParameters  =  nil): boolean;
var
  B : ByteArray;
begin

  Result := false;
  if Self.Algorithm <> Source.Algorithm then exit;
  Result := true;
  B := Source.GetKeyProp(SB_KEYPROP_EC_D);
  Result := Result and (Length(FD) = Length(B)) and
     (CompareMem(@FD[0], @B[0], Length(FD)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_EC_QX);
  Result := Result and (Length(FQX) = Length(B)) and
     (CompareMem(@FQX[0], @B[0], Length(FQX)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_EC_QY);
  Result := Result and (Length(FQY) = Length(B)) and
     (CompareMem(@FQY[0], @B[0], Length(FQY)))
     ;
  B := Source.GetKeyProp(SB_KEYPROP_GOST_R3410_PARAMSET);
  Result := Result and CompareContent(B, FParamSet);
  B := Source.GetKeyProp(SB_KEYPROP_GOST_R3410_DIGEST_PARAMSET);
  Result := Result and CompareContent(B, FDigestParamSet);
  B := Source.GetKeyProp(SB_KEYPROP_GOST_R3410_ENCRYPTION_PARAMSET);
  Result := Result and CompareContent(B, FEncryptionParamSet);

end;

function TElBuiltInGOST34102001CryptoKey.ClonePublic(Params : TElCPParameters  =  nil) : TElCustomCryptoKey;
var
  Res : TElBuiltInGOST34102001CryptoKey;
begin
  Result := Clone(Params);
  Res := TElBuiltInGOST34102001CryptoKey(Result);
  Res.ClearSecret;
end;

function TElBuiltInGOST34102001CryptoKey.GetKeyProp(const PropID : ByteArray;
  const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif}  {$endif}): ByteArray;
var
  TmpX, TmpY : ByteArray;
begin
  SetLength(TmpX, 0);
  SetLength(TmpY, 0);
  if CompareContent(PropID, SB_KEYPROP_EC_CURVE) then
  begin
    if Length(FParamSet) > 0 then
      Result := CloneArray(FParamSet)
    else
      Result := Default;
  end
  else
  if CompareContent(PropID, SB_KEYPROP_EC_CURVE_INT) then
    Result := GetBufferFromInteger(FDomainParameters.Curve)
  else
  if CompareContent(PropID, SB_KEYPROP_EC_FIELD) then
  begin
    if FDomainParameters.Field = SB_EC_FLD_CUSTOM then
      Result := SB_OID_FLD_CUSTOM;
  end
  else
  if CompareContent(PropID, SB_KEYPROP_EC_FIELD_INT) then
    Result := GetBufferFromInteger(FDomainParameters.Field)
  else
  if CompareContent(PropID, SB_KEYPROP_EC_FIELD_BITS) then
    Result := GetBufferFromInteger(FDomainParameters.GetFieldBits)
  else
  if CompareContent(PropID, SB_KEYPROP_EC_SUBGROUP_BITS) then
    Result := GetBufferFromInteger(FDomainParameters.GetSubgroupBits)
  else
  if CompareContent(PropID, SB_KEYPROP_EC_QX) then
    Result := CloneArray(FQX)

  else
  if CompareContent(PropID, SB_KEYPROP_EC_QY) then
    Result := CloneArray(FQY)

  else
  if CompareContent(PropID, SB_KEYPROP_EC_Q) then
  begin
    SetLength(FQ, Length(FQX) + Length(FQY));
    TmpX := FQX;
    TmpY := FQY;

    SBMove(TmpX, 0, FQ, 0, Length(TmpX));
    SBMove(TmpY, 0, FQ, Length(TmpX), Length(TmpY));
    Result := CloneArray(FQ);
  end
  else
  if CompareContent(PropID, SB_KEYPROP_EC_D) then
    Result := CloneArray(FD)
  else
  if CompareContent(PropID, SB_KEYPROP_EC_P) then
  begin
    if Length(FDomainParameters.P) > 0 then
      Result := CloneArray(FDomainParameters.P);
  end
  else
  if CompareContent(PropID, SB_KEYPROP_EC_A) then
  begin
    if Length(FDomainParameters.A) > 0 then
      Result := CloneArray(FDomainParameters.A);
  end
  else
  if CompareContent(PropID, SB_KEYPROP_EC_B) then
  begin
    if Length(FDomainParameters.B) > 0 then
      Result := CloneArray(FDomainParameters.B);
  end
  else
  if CompareContent(PropID, SB_KEYPROP_EC_N) then
  begin
    if Length(FDomainParameters.N) > 0 then
      Result := CloneArray(FDomainParameters.N);
  end
  else
  if CompareContent(PropID, SB_KEYPROP_EC_X) then
  begin
    if Length(FDomainParameters.X) > 0 then
      Result := CloneArray(FDomainParameters.X);
  end
  else
  if CompareContent(PropID, SB_KEYPROP_EC_Y) then
  begin
    if Length(FDomainParameters.Y) > 0 then
      Result := CloneArray(FDomainParameters.Y);
  end
  else
  if CompareContent(PropID, SB_KEYPROP_GOST_R3410_PARAMSET) then
    Result := CloneArray(FParamSet)
  else
  if CompareContent(PropID, SB_KEYPROP_GOST_R3410_DIGEST_PARAMSET) then
    Result := CloneArray(FDigestParamSet)
  else
  if CompareContent(PropID, SB_KEYPROP_GOST_R3410_ENCRYPTION_PARAMSET) then
    Result := CloneArray(FEncryptionParamSet)
  else
    Result := Default;
  ReleaseArray(TmpX);
  ReleaseArray(TmpY);
end;

procedure TElBuiltInGOST34102001CryptoKey.SetKeyProp(const PropID : ByteArray; const Value : ByteArray);
begin
  if CompareContent(PropID, SB_KEYPROP_EC_CURVE) then
  begin
    FParamSet := CloneArray(Value);
    LoadParamset(FParamSet);
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_QX) then
  begin
    FQX := CloneArray(Value);
    if Length(FQY) > 0 then
      FPublicKey := true;
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_QY) then
  begin
    FQY := CloneArray(Value);

    if Length(FQX) > 0 then
      FPublicKey := true;
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_Q) then
  begin
    if Length(Value) <> 64 then
      raise EElCryptoKeyError.Create(SInvalidPropertyValue);

    SetLength(FQ, Length(Value));
    SetLength(FQX, Length(Value) shr 1);
    SetLength(FQY, Length(Value) shr 1);
    SBMove(Value, 0, FQ, 0, Length(Value));
    SBMove(Value, 0, FQX, 0, Length(FQX));
    SBMove(Value, Length(FQX), FQY, 0, Length(FQY));
    FQX := ChangeByteOrder(FQX);
    FQY := ChangeByteOrder(FQY);
    FPublicKey := true;
  end
  else if CompareContent(PropID, SB_KEYPROP_EC_D) then
  begin
    FD := CloneArray(Value);
    FSecretKey := true;
  end  
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_PARAMSET) then
  begin
    FParamSet := CloneArray(Value);
    LoadParamset(FParamSet);
  end
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_DIGEST_PARAMSET) then
  begin
    FDigestParamSet := CloneArray(Value);
  end
  else if CompareContent(PropID, SB_KEYPROP_GOST_R3410_ENCRYPTION_PARAMSET) then
  begin
    FEncryptionParamSet := CloneArray(Value);
  end;
end;

function TElBuiltInGOST34102001CryptoKey.GetIsPublic: boolean;
begin
  Result := FPublicKey;
end;

function TElBuiltInGOST34102001CryptoKey.GetIsSecret: boolean;
begin
  Result := FSecretKey;
end;

function TElBuiltInGOST34102001CryptoKey.GetIsExportable: boolean;
begin
  Result := true;
end;

function TElBuiltInGOST34102001CryptoKey.GetIsPersistent: boolean;
begin
  Result := false;
end;

function TElBuiltInGOST34102001CryptoKey.GetIsValid: boolean;
var
  D, QX, QY : pointer;
begin
  Result := FDomainParameters.Check;

  if Result then
  begin
    if FPublicKey then
    begin
      Result := Result and (Length(FQX) > 0);
      Result := Result and (Length(FQY) > 0);
    end;

    if FSecretKey then
      Result := Result and (Length(FD) > 0);

    if Result then
      begin
        if FSecretKey then
          D := @FD[0]
        else
          D := nil;

        if FPublicKey then
        begin
          QX := @FQX[0];
          QY := @FQY[0];
        end
        else
        begin
          QX := nil;
          QY := nil;
        end;

        Result := Result and SBECCommon.ValidateKey(FDomainParameters,
          D, Length(FD), QX, Length(FQX), QY, Length(FQY));
      end;
  end;
end;

function TElBuiltInGOST34102001CryptoKey.GetBits : integer;
begin
  Result := 512;
end;

function TElBuiltInGOST34102001CryptoKey.GetAlgorithm : integer;
begin
  Result := SB_ALGORITHM_PK_GOST_R3410_2001;
end;

function TElBuiltInGOST34102001CryptoKey.GetKeyStorage : TElCustomCryptoKeyStorage;
begin
  Result := nil;
end;

procedure TElBuiltInGOST34102001CryptoKey.ClearPublic;
begin
  Reset;
end;

procedure TElBuiltInGOST34102001CryptoKey.ClearSecret;
begin
  FD := EmptyArray;
  FSecretKey := false;
end;
 {$endif}
 {$endif} //SB_HAS_GOST

////////////////////////////////////////////////////////////////////////////////
// TElBuiltInPublicKeyCrypto class

constructor TElBuiltInPublicKeyCrypto.Create(const OID : ByteArray);
begin
  Create;
end;

constructor TElBuiltInPublicKeyCrypto.Create(Alg : integer);
begin
  Create;
end;

constructor TElBuiltInPublicKeyCrypto.Create;
begin
  inherited Create;
end;

 destructor  TElBuiltInPublicKeyCrypto.Destroy;
begin
  inherited;
end;

function TElBuiltInPublicKeyCrypto.GetSupportsEncryption: boolean;
begin
  {$ifdef FPC}
  result := false;
   {$endif}
  raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
end;

function TElBuiltInPublicKeyCrypto.GetSupportsSigning: boolean;
begin
  {$ifdef FPC}
  result := false;
   {$endif}
  raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
end;

class function TElBuiltInPublicKeyCrypto.IsAlgorithmSupported(Alg: integer): boolean;
begin
  Result := false;
end;

class function TElBuiltInPublicKeyCrypto.IsAlgorithmSupported(const OID: ByteArray): boolean;
begin
  Result := false;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInPublicKeyCrypto.SignInit(Detached: boolean);
begin
  raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
end;

procedure TElBuiltInPublicKeyCrypto.SignUpdate( Buffer: pointer;
   Size: integer);
begin
  raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
end;

procedure TElBuiltInPublicKeyCrypto.SignFinal(Buffer: pointer; var Size: integer);
begin
  raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
end;

procedure TElBuiltInPublicKeyCrypto.EncryptInit;
begin
  raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
end;

procedure TElBuiltInPublicKeyCrypto.EncryptUpdate( Buffer: pointer;
   Size: integer);
begin
  raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
end;

procedure TElBuiltInPublicKeyCrypto.EncryptFinal;
begin
  raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
end;
 {$endif SB_PGPSFX_STUB}

procedure TElBuiltInPublicKeyCrypto.DecryptInit;
begin
  raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
end;

procedure TElBuiltInPublicKeyCrypto.DecryptUpdate( Buffer: pointer;
   Size: integer);
begin
  raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
end;

procedure TElBuiltInPublicKeyCrypto.DecryptFinal;
begin
  raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
end;

procedure TElBuiltInPublicKeyCrypto.VerifyInit(Detached: boolean;  Signature: pointer;
    SigSize: integer);
begin
  raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
end;

procedure TElBuiltInPublicKeyCrypto.VerifyUpdate( Buffer: pointer;  Size: integer);
begin
  raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
end;

function TElBuiltInPublicKeyCrypto.VerifyFinal: integer;
begin
  {$ifdef FPC}
  result := 0;
   {$endif}
  raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
end;

function TElBuiltInPublicKeyCrypto.EstimateOutputSize( InBuffer: pointer;
    InSize: Int64;
  Operation : TSBBuiltInPublicKeyOperation): Int64;
begin
  {$ifdef FPC}
  result := 0;
   {$endif}
  raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
end;

function TElBuiltInPublicKeyCrypto.EstimateOutputSize(InSize: Int64; Operation:
  TSBBuiltInPublicKeyOperation): Int64;
begin
  Result := EstimateOutputSize( nil , InSize, Operation);
end;

procedure TElBuiltInPublicKeyCrypto.WriteToOutput( Buffer: pointer;
    Size: integer);
var
  OldLen : integer;
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

procedure TElBuiltInPublicKeyCrypto.Reset;
begin
  SetLength(FOutput, 0);
  FOutputStream := nil;
  FOutputIsStream := false;
  FFinished := false;
end;

procedure TElBuiltInPublicKeyCrypto.PrepareForOperation;
begin
  SetLength(FOutput, 0);
  FOutputStream := nil;
  FOutputIsStream := false;
  FFinished := false;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInPublicKeyCrypto.Encrypt(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
  var OutSize: integer);
var
  Needed : integer;
begin  
  if not SupportsEncryption then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.IsPublic) then
    raise EElBuiltInCryptoProviderError.Create(SPublicKeyNotFound);
  PrepareForOperation;       
  Needed := EstimateOutputSize(InBuffer, InSize,
    pkoEncrypt);
  if (Needed > OutSize) then
  begin
    if OutSize = 0 then
    begin
      OutSize := Needed;
      Exit;
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SBufferTooSmall);
  end;
  EncryptInit();
  try
    EncryptUpdate(InBuffer, InSize);
  finally
    EncryptFinal();
  end;
  if Length(FOutput) > OutSize then
    raise EElBuiltInCryptoProviderError.Create(SInternalError);
  OutSize := Length(FOutput);
  SBMove(FOutput[0], OutBuffer^, OutSize);
end;
 {$endif SB_PGPSFX_STUB}

procedure TElBuiltInPublicKeyCrypto.Decrypt(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
  var OutSize: integer);
var
  Needed : integer;
begin
  if not SupportsEncryption then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.IsSecret) then
    raise EElBuiltInCryptoProviderError.Create(SSecretKeyNotFound);
  PrepareForOperation;
  Needed := EstimateOutputSize(InBuffer, InSize,
    pkoDecrypt);
  if (Needed > OutSize) then
  begin
    if OutSize = 0 then
    begin
      OutSize := Needed;
      Exit;
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SBufferTooSmall);
  end;
  DecryptInit();
  try
    DecryptUpdate(InBuffer, InSize);
  finally
    DecryptFinal();
  end;
  if Length(FOutput) > OutSize then
    raise EElBuiltInCryptoProviderError.Create(SInternalError);
  OutSize := Length(FOutput);
  SBMove(FOutput[0], OutBuffer^, OutSize);
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInPublicKeyCrypto.Sign(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
  var OutSize: integer);
var
  Needed : integer;
begin
  if not SupportsSigning then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.IsSecret) then
    raise EElBuiltInCryptoProviderError.Create(SSecretKeyNotFound);
  PrepareForOperation;
  Needed := EstimateOutputSize(InBuffer, InSize,
    pkoSign);
  if (Needed > OutSize) then
  begin
    if OutSize = 0 then
    begin
      OutSize := Needed;
      Exit;
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SBufferTooSmall);
  end;
  SignInit(false);
  try
    SignUpdate(InBuffer, InSize);
  finally
    SignFinal(OutBuffer, OutSize);
  end;
  if Length(FOutput) > OutSize then
    raise EElBuiltInCryptoProviderError.Create(SInternalError);
end;

procedure TElBuiltInPublicKeyCrypto.SignDetached(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
  var OutSize: integer);
var
  Needed : integer;
begin
  if not SupportsSigning then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.IsSecret) then
    raise EElBuiltInCryptoProviderError.Create(SSecretKeyNotFound);
  PrepareForOperation;
  Needed := EstimateOutputSize(InBuffer, InSize,
    pkoSignDetached);
  if (Needed > OutSize) then
  begin
    if OutSize = 0 then
    begin
      OutSize := Needed;
      Exit;
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SBufferTooSmall);
  end;
  SignInit(true);
  try
    SignUpdate(InBuffer, InSize);
  finally
    SignFinal(OutBuffer, OutSize);
  end;
  if Length(FOutput) > OutSize then
    raise EElBuiltInCryptoProviderError.Create(SInternalError);
end;
 {$endif SB_PGPSFX_STUB}

function TElBuiltInPublicKeyCrypto.Verify(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
  var OutSize: integer): integer;
var
  Needed : integer;
begin
  if not SupportsSigning then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.IsPublic) then
    raise EElBuiltInCryptoProviderError.Create(SPublicKeyNotFound);
  PrepareForOperation;
  Needed := EstimateOutputSize(InBuffer, InSize,
    pkoVerify);
  if (Needed > OutSize) then
  begin
    if OutSize = 0 then
    begin
      OutSize := Needed;
      Result := SB_VR_FAILURE;
      Exit;
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SBufferTooSmall);
  end;
  VerifyInit(false, nil, 0);
  try
    VerifyUpdate(InBuffer, InSize);
  finally
    Result := VerifyFinal();
  end;
  if Length(FOutput) > OutSize then
    raise EElBuiltInCryptoProviderError.Create(SInternalError);
  OutSize := Length(FOutput);
  SBMove(FOutput[0], OutBuffer^, OutSize);
end;

function TElBuiltInPublicKeyCrypto.VerifyDetached(InBuffer: pointer; InSize: integer;
  SigBuffer: pointer; SigSize: integer): integer;
begin
  if not SupportsSigning then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.IsPublic) then
    raise EElBuiltInCryptoProviderError.Create(SPublicKeyNotFound);
  VerifyInit(true, SigBuffer, SigSize);
  try
    VerifyUpdate(InBuffer, InSize);
  finally
    Result := VerifyFinal();
  end;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInPublicKeyCrypto.Encrypt(InStream, OutStream : TElStream;
  Count: integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
var
  Read : integer;
  Buf :  array [0..4095]  of byte ;
begin
  if not SupportsEncryption then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.IsPublic) then
    raise EElBuiltInCryptoProviderError.Create(SPublicKeyNotFound);
  {$ifdef SB_NET_OR_JAVA}
  SetLength(Buf, 4096);
   {$endif}
  PrepareForOperation;
  if Count = 0 then
    Count := InStream. Size  - InStream.Position;
  EstimateOutputSize(nil, Count, pkoEncrypt);
  FOutputStream := OutStream;
  FOutputIsStream := true;
  EncryptInit();
  try
    while Count > 0 do
    begin
      Read := InStream.Read(Buf [0] , Min(Length(Buf), Count));
      EncryptUpdate( @Buf[0] , Read);
      Dec(Count, Read);
    end;
  finally
    EncryptFinal();
  end;
end;
 {$endif SB_PGPSFX_STUB}

procedure TElBuiltInPublicKeyCrypto.Decrypt(InStream, OutStream : TElStream;
  Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
var
  Read : integer;
  Buf :  array [0..4095]  of byte ;
begin
  if not SupportsEncryption then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
  if (FKeyMaterial = nil) or (not FKeyMaterial.IsSecret) then
    raise EElBuiltInCryptoProviderError.Create(SSecretKeyNotFound);
  {$ifdef SB_NET_OR_JAVA}
  SetLength(Buf, 4096);
   {$endif}
  PrepareForOperation;
  if Count = 0 then
    Count := InStream. Size  - InStream.Position;
  EstimateOutputSize(nil, Count, pkoDecrypt);
  FOutputStream := OutStream;
  FOutputIsStream := true;
  DecryptInit();
  try
    while Count > 0 do
    begin
      Read := InStream.Read(Buf [0] , Min(Length(Buf), Count));
      DecryptUpdate( @Buf[0] , Read);
      Dec(Count, Read);
    end;
  finally
    DecryptFinal();
  end;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInPublicKeyCrypto.Sign(InStream, OutStream : TElStream;
  Count: integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
var
  Read: integer;
  Buf:  array [0..4095]  of byte ;
begin
  if not SupportsSigning then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
  if (FKeyMaterial = nil) or (not FKeyMaterial.IsSecret) then
    raise EElBuiltInCryptoProviderError.Create(SSecretKeyNotFound);
  {$ifdef SB_NET_OR_JAVA}
  SetLength(Buf, 4096);
   {$endif}
  PrepareForOperation;
  if Count = 0 then
    Count := InStream. Size  - InStream.Position;
  EstimateOutputSize(nil, Count, pkoSign);
  FOutputStream := OutStream;
  FOutputIsStream := true;
  SignInit(false);
  try
    while Count > 0 do
    begin
      Read := InStream.Read(Buf [0] , Min(Length(Buf), Count));
      SignUpdate( @Buf[0] , Read);
      Dec(Count, Read);
    end;
  finally
    Read := 0;
    SignFinal( nil , Read);
  end;
end;

procedure TElBuiltInPublicKeyCrypto.SignDetached(InStream, OutStream : TElStream;
  Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
var
  Read : integer;
  Buf :  array [0..4095]  of byte ;
begin
  if not SupportsSigning then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
  if (FKeyMaterial = nil) or (not FKeyMaterial.IsSecret) then
    raise EElBuiltInCryptoProviderError.Create(SSecretKeyNotFound);
  {$ifdef SB_NET_OR_JAVA}
  SetLength(Buf, 4096);
   {$endif}
  PrepareForOperation;
  if Count = 0 then
    Count := InStream. Size  - InStream.Position;
  EstimateOutputSize(nil, Count, pkoSignDetached);
  FOutputStream := OutStream;
  FOutputIsStream := true;
  SignInit(true);
  try
    while Count > 0 do
    begin
      Read := InStream.Read(Buf [0] , Min(Length(Buf), Count));
      SignUpdate( @Buf[0] , Read);
      Dec(Count, Read);
    end;
  finally
    Read := 0;
    SignFinal( nil , Read);
  end;
end;
 {$endif SB_PGPSFX_STUB}

function TElBuiltInPublicKeyCrypto.Verify(InStream, OutStream : TElStream;
  Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}): integer;
var
  Read : integer;
  Buf :  array [0..4095]  of byte ;
begin
  if not SupportsSigning then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
  if (FKeyMaterial = nil) or (not FKeyMaterial.IsPublic) then
    raise EElBuiltInCryptoProviderError.Create(SPublicKeyNotFound);
  {$ifdef SB_NET_OR_JAVA}
  SetLength(Buf, 4096);
   {$endif}
  PrepareForOperation;
  if Count = 0 then
    Count := InStream. Size  - InStream.Position;
  EstimateOutputSize(nil, Count, pkoVerify);
  FOutputStream := OutStream;
  FOutputIsStream := true;
  VerifyInit(false, nil, 0);
  try
    while Count > 0 do
    begin
      Read := InStream.Read(Buf [0] , Min(Length(Buf), Count));
      VerifyUpdate( @Buf[0] , Read);
      Dec(Count, Read);
    end;
  finally
    Result := VerifyFinal();
  end;
end;

function TElBuiltInPublicKeyCrypto.VerifyDetached(InStream, SigStream : TElStream;
  InCount : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}; SigCount: integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}): integer;
var
  Read : integer;
  Buf :  array [0..4095]  of byte ;
  SigBuf : ByteArray;
begin

  if not SupportsSigning then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
  if (FKeyMaterial = nil) or (not FKeyMaterial.IsPublic) then
    raise EElBuiltInCryptoProviderError.Create(SPublicKeyNotFound);
  {$ifdef SB_NET_OR_JAVA}
  SetLength(Buf, 4096);
   {$endif}
  PrepareForOperation;
  if InCount = 0 then
    InCount := InStream. Size  - InStream.Position;
  if SigCount = 0 then
    SigCount := SigStream. Size  - SigStream.Position;
  SetLength(SigBuf, SigCount);
  SigStream.Read(SigBuf [0] , SigCount);
  VerifyInit(true,  @SigBuf[0] , SigCount);
  try
    while InCount > 0 do
    begin
      Read := InStream.Read(Buf [0] , Min(Length(Buf), InCount));
      VerifyUpdate( @Buf[0] , Read);
      Dec(InCount, Read);
    end;
  finally
    Result := VerifyFinal();
  end;

end;

class function TElBuiltInPublicKeyCrypto.GetName() : string;
begin
  Result := 'Empty';
end;

class function TElBuiltInPublicKeyCrypto.GetDescription() : string;
begin
  Result := 'Base class for public key encryption. Do not instantiate.';
end;

procedure TElBuiltInPublicKeyCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  FKeyMaterial := Material;
end;

////////////////////////////////////////////////////////////////////////////////
// TElBuiltInRSAPublicKeyCrypto class

constructor TElBuiltInRSAPublicKeyCrypto.Create(const OID : ByteArray);
begin
  inherited Create;
  Reset;
  FHashAlgorithm := SB_ALGORITHM_UNKNOWN;
  FOID := OID;
  if CompareContent(OID, SB_OID_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA1_RSAENCRYPTION) or
    CompareContent(OID, SB_OID_SHA1_RSAENCRYPTION2) or
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
    raise EElBuiltInCryptoProviderError.CreateFmt(SUnsupportedAlgorithmStr, [OIDToStr(OID)]);
end;

constructor TElBuiltInRSAPublicKeyCrypto.Create(Alg : integer);
begin
  inherited Create;
  Reset;
  FHashAlgorithm := SB_ALGORITHM_UNKNOWN;
  
  FOID := EmptyArray;
  if Alg in [SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_MD2_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_MD5_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA1_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA224_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA256_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA384_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA512_RSA_ENCRYPTION] then
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
    raise EElBuiltInCryptoProviderError.CreateFmt(SUnsupportedAlgorithmInt, [Alg]);
end;

constructor TElBuiltInRSAPublicKeyCrypto.Create;
begin
  Create(SB_OID_RSAENCRYPTION);
  FHashFuncOID := EmptyArray;
  FSaltSize := 0;
end;

procedure TElBuiltInRSAPublicKeyCrypto.Reset;
begin
  inherited;
  FSupportsEncryption := true;
  FSupportsSigning := true;
  FInputIsHash := false;
  FUseAlgorithmPrefix := true;
  FCryptoType := rsapktPKCS1;
  FSaltSize := 0;
  FHashFuncOID := EmptyArray;
  FMGFAlgorithm := 0;
  FTrailerField := 0;
end;

 destructor  TElBuiltInRSAPublicKeyCrypto.Destroy;
begin
  if FHashFunction <> nil then
    FreeAndNil(FHashFunction);
  inherited;
end;

function TElBuiltInRSAPublicKeyCrypto.GetSupportsEncryption: boolean;
begin
  Result := FSupportsEncryption;
end;

function TElBuiltInRSAPublicKeyCrypto.GetSupportsSigning: boolean;
begin
  Result := FSupportsSigning;
end;

procedure TElBuiltInRSAPublicKeyCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if Material.Algorithm <> SB_ALGORITHM_PK_RSA then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);
  FKeyMaterial := Material;
end;

procedure TElBuiltInRSAPublicKeyCrypto.SetCryptoType(Value : TSBBuiltInRSAPublicKeyCryptoType);
begin
  FCryptoType := Value;

  FSupportsEncryption := true;
  FSupportsSigning := true;

  if Value = rsapktPSS then
  begin
    FSupportsEncryption := false;
    FOID := SB_OID_RSAPSS;
  end
  else if Value = rsapktOAEP then
  begin
    FSupportsSigning := false;
    FOID := SB_OID_RSAOAEP;
  end
  else
    FOID := SB_OID_RSAENCRYPTION;
end;

function TElBuiltInRSAPublicKeyCrypto.GetAntiTimingParams(KM : TElCustomCryptoKey): TElRSAAntiTimingParams;
begin
  if (KM.CryptoProvider is TElBuiltInCryptoProvider) and (KM is TElBuiltInRSACryptoKey) and
    (TElBuiltInCryptoProviderOptions(TElBuiltInCryptoProvider(KM.CryptoProvider).Options).UseTimingAttackProtection) and
    (TElBuiltInRSACryptoKey(KM).FAntiTimingParams.Initialized) then
    Result := TElBuiltInRSACryptoKey(KM).FAntiTimingParams
  else
    Result := nil;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInRSAPublicKeyCrypto.SignInit(Detached: boolean);
begin
  if not FSupportsSigning then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
  if not FKeyMaterial.IsSecret then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  SetLength(FSpool, 0);
  if not FInputIsHash then
    FHashFunction := TElBuiltInHashFunction.Create(GetUsedHashFunction);
end;

procedure TElBuiltInRSAPublicKeyCrypto.SignUpdate(Buffer: pointer; Size: integer);
var
  OldLen : integer;
begin
  if not FSupportsSigning then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);

  if FInputIsHash then
  begin
    OldLen := Length(FSpool);
    SetLength(FSpool, OldLen + Size);
    SBMove(Buffer^, FSpool[OldLen], Size);
  end
  else
    FHashFunction.Update(Buffer, Size);
end;

procedure TElBuiltInRSAPublicKeyCrypto.SignFinal(Buffer: pointer; var Size : integer);
var
  Hash : ByteArray;
  SigSize : integer;
  Sig : ByteArray;
  KeyFormat : ByteArray;
  HashAlg : integer;
  SaltSize, TrField, MGFAlg, BlobSize : integer;
  KeyBlob : ByteArray;
{$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
  DEF_SALT_SIZE : ByteArray = #0#0#0#20;
 {$else}
  DEF_SALT_SIZE : ByteArray;
 {$endif}
begin
  if not FSupportsSigning then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);

  {$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
  DEF_SALT_SIZE := CreateByteArrayConst(#0#0#0#20);
   {$endif}


  if not FFinished then
  begin
    if FInputIsHash then
    begin
      SetLength(Hash, Length(FSpool));
      SBMove(FSpool[0], Hash[0], Length(Hash));
    end
    else
    begin
      Hash := FHashFunction.Finish;
      FreeAndNil(FHashFunction);
    end;

    BlobSize := 0;
    FKeyMaterial.ExportSecret( nil , BlobSize);
    SetLength(KeyBlob, BlobSize);
    FKeyMaterial.ExportSecret( @KeyBlob[0] , BlobSize);
    if FCryptoType = rsapktPSS then
    begin
      KeyFormat := FKeyMaterial.GetKeyProp(SB_KEYPROP_KEYFORMAT, SB_KEYPROP_RSA_KEYFORMAT_PKCS1);
      if (not (CompareContent(KeyFormat, SB_KEYPROP_RSA_KEYFORMAT_PKCS1))) and
        (not (CompareContent(KeyFormat, SB_KEYPROP_RSA_KEYFORMAT_PSS))) then
        raise EElBuiltInCryptoProviderError.Create(SInvalidKeyMaterialType);
      SigSize := 0;
      if BlobSize > 0 then
      begin
        if FHashAlgorithm <> SB_ALGORITHM_UNKNOWN then
          HashAlg := FHashAlgorithm
        else
          HashAlg := GetHashAlgorithmByOID(FKeyMaterial.GetKeyProp(SB_KEYPROP_HASH_ALGORITHM, EmptyArray));
        if FSaltSize = 0 then
          SaltSize := GetIntegerPropFromBuffer(FKeyMaterial.GetKeyProp(SB_KEYPROP_SALT_SIZE, DEF_SALT_SIZE))
        else
          SaltSize := FSaltSize;

        if FTrailerField = 0 then  
          TrField := GetIntegerPropFromBuffer(FKeyMaterial.GetKeyProp(SB_KEYPROP_TRAILER_FIELD))
        else
          TrField := FTrailerField;

        if FMGFAlgorithm = 0 then
          MGFAlg := GetAlgorithmByOID(FKeyMaterial.GetKeyProp(SB_KEYPROP_MGF_ALGORITHM, EmptyArray))
        else
          MGFAlg := FMGFAlgorithm;

        if (TrField <> 1) or (MGFAlg <> SB_CERT_MGF1) then
          raise EElBuiltInCryptoProviderError.CreateFmt(SUnsupportedPropertyValue, [IntToStr(TrField) + '/' + IntToStr(MGFAlg)]);

      
        SBRSA.SignPSS(@Hash[0], Length(Hash), HashAlg, SaltSize,
          @KeyBlob[0], BlobSize, nil, SigSize, GetAntiTimingParams(FKeyMaterial));
        SetLength(Sig, SigSize);
        if not SBRSA.SignPSS(@Hash[0], Length(Hash), HashAlg, SaltSize,
          @KeyBlob[0], BlobSize, @Sig[0], SigSize, GetAntiTimingParams(FKeyMaterial))
        then
          raise EElBuiltInCryptoProviderError.Create(SSigningFailed);
      end
      else
        raise EElBuiltInCryptoProviderError.Create(SSecretKeyNotFound);
      WriteToOutput( @Sig[0] , SigSize);
    end
    else
    begin
      KeyFormat := FKeyMaterial.GetKeyProp(SB_KEYPROP_KEYFORMAT, SB_KEYPROP_RSA_KEYFORMAT_PKCS1);
      if not (CompareContent(KeyFormat, SB_KEYPROP_RSA_KEYFORMAT_PKCS1)) then
        raise EElBuiltInCryptoProviderError.Create(SInvalidKeyMaterialType);

      if CryptoType <> rsapktSSL3 then
      begin
        if FUseAlgorithmPrefix and AlgorithmPrefixNeeded then
          Hash := AddAlgorithmPrefix(Hash);
      end;

      SigSize := 0;

      if BlobSize > 0 then
      begin
        SBRSA.Sign(@Hash[0], Length(Hash), @KeyBlob[0], BlobSize, nil,
          SigSize, GetAntiTimingParams(FKeyMaterial));
        SetLength(Sig, SigSize);
        if not SBRSA.Sign(@Hash[0], Length(Hash), @KeyBlob[0], BlobSize,
          @Sig[0], SigSize, GetAntiTimingParams(FKeyMaterial)) then
          raise EElBuiltInCryptoProviderError.Create(SSigningFailed);
      end
      else
        raise EElBuiltInCryptoProviderError.Create(SSecretKeyNotFound);
      WriteToOutput( @Sig[0] , SigSize);
    end;
    FFinished := true;
  end;
  if not FOutputIsStream then
  begin
    if Buffer = nil then
      Size := Length(FOutput)
    else
    begin
      if Size >= Length(FOutput) then
      begin
        Size := Length(FOutput);
        SBMove(FOutput[0], Buffer^, Size);
      end
      else
        raise EElBuiltInCryptoProviderError.Create(SBufferTooSmall);
    end;
  end;

end;

procedure TElBuiltInRSAPublicKeyCrypto.EncryptInit;
begin
  if not FSupportsEncryption then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);

  SetLength(FSpool, 0);
end;

procedure TElBuiltInRSAPublicKeyCrypto.EncryptUpdate(Buffer: pointer; Size: integer);
var
  OldLen: integer;
begin
  if not FSupportsEncryption then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);

  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + Size);
  SBMove(Buffer^, FSpool[OldLen], Size);
end;

procedure TElBuiltInRSAPublicKeyCrypto.EncryptFinal;
var
  OutSize : integer;
  OutBuf : ByteArray;
  LabelPtr : pointer;
  KeyFormat : ByteArray;
  HashAlg : integer;
  StrLabel : ByteArray;
  RSAM, RSAE : ByteArray;
begin
  if not FSupportsEncryption then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);


  SetLength(StrLabel, 0);
  if FCryptoType = rsapktOAEP then
  begin
    KeyFormat := FKeyMaterial.GetKeyProp(SB_KEYPROP_KEYFORMAT, SB_KEYPROP_RSA_KEYFORMAT_PKCS1);
    if (not (CompareContent(KeyFormat, SB_KEYPROP_RSA_KEYFORMAT_PKCS1))) and
      (not (CompareContent(KeyFormat, SB_KEYPROP_RSA_KEYFORMAT_OAEP))) then
      raise EElBuiltInCryptoProviderError.Create(SInvalidKeyMaterialType);

    OutSize := 0;

    StrLabel := FKeyMaterial.GetKeyProp(SB_KEYPROP_STRLABEL, EmptyArray);
    if Length(StrLabel) = 0 then
      LabelPtr := nil
    else
      LabelPtr := @StrLabel[0];

    //HashAlg := GetHashAlgorithmByOID(FKeyMaterial.GetKeyProp(SB_KEYPROP_HASH_ALGORITHM, EmptyArray));
    HashAlg := HashAlgorithmByMGF1(GetAlgorithmByOID(FKeyMaterial.GetKeyProp(SB_KEYPROP_MGF_ALGORITHM, EmptyArray)));

    RSAM := FKeyMaterial.GetKeyProp(SB_KEYPROP_RSA_M, EmptyArray);
    RSAE := FKeyMaterial.GetKeyProp(SB_KEYPROP_RSA_E, EmptyArray);
    SBRSA.EncryptOAEP(@FSpool[0], Length(FSpool), @RSAM[0], Length(RSAM),
      @RSAE[0], Length(RSAE), LabelPtr, Length(StrLabel), HashAlg, nil, OutSize);
    SetLength(OutBuf, OutSize);
    if not SBRSA.EncryptOAEP(@FSpool[0], Length(FSpool), @RSAM[0], Length(RSAM),
      @RSAE[0], Length(RSAE), LabelPtr, Length(StrLabel), HashAlg, @OutBuf[0], OutSize)
    then
      raise EElBuiltInCryptoProviderError.Create(SEncryptionFailed);
    WriteToOutput( @OutBuf[0] , OutSize);
  end
  else
  begin
    KeyFormat := FKeyMaterial.GetKeyProp(SB_KEYPROP_KEYFORMAT, SB_KEYPROP_RSA_KEYFORMAT_PKCS1);
    if (not (CompareContent(KeyFormat, SB_KEYPROP_RSA_KEYFORMAT_PKCS1))) then
      raise EElBuiltInCryptoProviderError.Create(SInvalidKeyMaterialType);

    RSAM := FKeyMaterial.GetKeyProp(SB_KEYPROP_RSA_M, EmptyArray);
    RSAE := FKeyMaterial.GetKeyProp(SB_KEYPROP_RSA_E, EmptyArray);
    OutSize := 0;
    SBRSA.Encrypt(@FSpool[0], Length(FSpool), @RSAM[0], Length(RSAM),
      @RSAE[0], Length(RSAE), nil, OutSize);
    SetLength(OutBuf, OutSize);
    if not SBRSA.Encrypt(@FSpool[0], Length(FSpool), @RSAM[0], Length(RSAM),
      @RSAE[0], Length(RSAE), @OutBuf[0], OutSize) then
      raise EElBuiltInCryptoProviderError.Create(SEncryptionFailed);
    WriteToOutput( @OutBuf[0] , OutSize);
  end;

end;
 {$endif SB_PGPSFX_STUB}

procedure TElBuiltInRSAPublicKeyCrypto.DecryptInit;
begin
  if not FSupportsEncryption then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
  if not FKeyMaterial.IsSecret then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);
  SetLength(FSpool, 0);
end;

procedure TElBuiltInRSAPublicKeyCrypto.DecryptUpdate(Buffer: pointer; Size: integer);
var
  OldLen: integer;
begin
  if not FSupportsEncryption then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);

  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + Size);
  SBMove(Buffer^, FSpool[OldLen], Size);
end;

procedure TElBuiltInRSAPublicKeyCrypto.DecryptFinal;
var
  OutSize : integer;
  OutBuf : ByteArray;
  RealPtr, LabelPtr : pointer;
  RealSize : integer;
  KeyFormat : ByteArray;
  StrLabel : ByteArray;
  HashAlg : integer;
  KeyBlob : ByteArray;
  BlobSize : integer;
begin
  if not FSupportsEncryption then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);


  RealPtr := @FSpool[0];
  RealSize := Length(FSpool);

  BlobSize := 0;
  FKeyMaterial.ExportSecret( nil , BlobSize);
  SetLength(KeyBlob, BlobSize);
  FKeyMaterial.ExportSecret( @KeyBlob[0] , BlobSize);

  {$ifndef SB_PGPSFX_STUB}
  if FCryptoType = rsapktOAEP then
  begin
    KeyFormat := FKeyMaterial.GetKeyProp(SB_KEYPROP_KEYFORMAT, SB_KEYPROP_RSA_KEYFORMAT_PKCS1);

    if (not (CompareContent(KeyFormat, SB_KEYPROP_RSA_KEYFORMAT_PKCS1))) and
      (not (CompareContent(KeyFormat, SB_KEYPROP_RSA_KEYFORMAT_OAEP))) then
      raise EElBuiltInCryptoProviderError.Create(SInvalidKeyMaterialType);

    OutSize := 0;

    StrLabel := FKeyMaterial.GetKeyProp(SB_KEYPROP_STRLABEL);
    if Length(StrLabel) = 0 then
      LabelPtr := nil
    else
      LabelPtr := @StrLabel[0];

    if BlobSize > 0 then
    begin
      HashAlg := HashAlgorithmByMGF1(GetAlgorithmByOID(FKeyMaterial.GetKeyProp(SB_KEYPROP_MGF_ALGORITHM, EmptyArray)));

      SBRSA.DecryptOAEP(RealPtr, RealSize, @KeyBlob[0], BlobSize, LabelPtr,
        Length(StrLabel), HashAlg, nil, OutSize, GetAntiTimingParams(FKeyMaterial));
      SetLength(OutBuf, OutSize);
      if not SBRSA.DecryptOAEP(RealPtr, RealSize, @KeyBlob[0], BlobSize, LabelPtr,
        Length(StrLabel), HashAlg, @OutBuf[0], OutSize, GetAntiTimingParams(FKeyMaterial))
      then
         raise EElBuiltInCryptoProviderError.Create(SDecryptionFailed);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SSecretKeyNotFound);
    WriteToOutput( @OutBuf[0] , OutSize);
  end
  else
   {$endif SB_PGPSFX_STUB}
  begin
    KeyFormat := FKeyMaterial.GetKeyProp(SB_KEYPROP_KEYFORMAT, SB_KEYPROP_RSA_KEYFORMAT_PKCS1);

    if (not (CompareContent(KeyFormat, SB_KEYPROP_RSA_KEYFORMAT_PKCS1))) then
      raise EElBuiltInCryptoProviderError.Create(SInvalidKeyMaterialType);

    OutSize := 0;
    if BlobSize > 0 then
    begin
      SBRSA.Decrypt(RealPtr, RealSize, @KeyBlob[0], BlobSize, nil, OutSize, GetAntiTimingParams(FKeyMaterial));
      SetLength(OutBuf, OutSize);
      if not SBRSA.Decrypt(RealPtr, RealSize, @KeyBlob[0], BlobSize, @OutBuf[0], OutSize, GetAntiTimingParams(FKeyMaterial)) then
        raise EElBuiltInCryptoProviderError.Create(SDecryptionFailed);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SSecretKeyNotFound);
    WriteToOutput( @OutBuf[0] , OutSize);
  end;

end;

procedure TElBuiltInRSAPublicKeyCrypto.VerifyInit(Detached: boolean; Signature: pointer;
  SigSize: integer);
var
  HashSize : integer;
  Hash, HashAlg, HashPar : ByteArray;
  RealSigPtr : pointer;
  RealSigSize : integer;
  KeyFormat : ByteArray;
  RSAM, RSAE : ByteArray;
  PrefixAlg : integer;
begin
  if not FSupportsSigning then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
  if not FKeyMaterial.IsPublic then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);



  SetLength(FSpool, 0);
  KeyFormat := FKeyMaterial.GetKeyProp(SB_KEYPROP_KEYFORMAT, SB_KEYPROP_RSA_KEYFORMAT_PKCS1);
  if CryptoType in [rsapktPKCS1,
    rsapktSSL3] then
  begin
    if (not (CompareContent(KeyFormat, SB_KEYPROP_RSA_KEYFORMAT_PKCS1))) then
      raise EElBuiltInCryptoProviderError.Create(SInvalidKeyMaterialType);

    RealSigPtr := Signature;
    RealSigSize := SigSize;
    HashSize := 0;
    RSAM := FKeyMaterial.GetKeyProp(SB_KEYPROP_RSA_M, EmptyArray);
    RSAE := FKeyMaterial.GetKeyProp(SB_KEYPROP_RSA_E, EmptyArray);
    SBRSA.Decrypt(RealSigPtr, RealSigSize, @RSAM[0], Length(RSAM), @RSAE[0],
      Length(RSAE), nil, HashSize, nil { this is verification, no need for anti timing params} );
    SetLength(Hash, HashSize);
    if SBRSA.Decrypt(RealSigPtr, RealSigSize, @RSAM[0], Length(RSAM), @RSAE[0],
      Length(RSAE), @Hash[0], HashSize, nil) then
    begin
      SetLength(Hash, HashSize);
      if CryptoType <> rsapktSSL3 then
      begin
        if UseAlgorithmPrefix then
        begin
          Hash := RemoveAlgorithmPrefix(Hash, HashAlg, HashPar);
          PrefixAlg := GetHashAlgorithmByOID(HashAlg);
          if PrefixAlg = SB_ALGORITHM_UNKNOWN then
          begin
            PrefixAlg := GetSigAlgorithmByOID(HashAlg);
            if PrefixAlg <> SB_ALGORITHM_UNKNOWN then
              PrefixAlg := GetHashAlgorithmBySigAlgorithm(PrefixAlg); // some software products use wrong OIDs
          end;
          if FHashAlgorithm = SB_ALGORITHM_UNKNOWN then
            FHashAlgorithm := PrefixAlg
          else if FHashAlgorithm <> PrefixAlg then
            raise EElBuiltInCryptoProviderError.CreateFmt(SHashAlgorithmMismatch, [PrefixAlg]);
        end
        else
          HashAlg := GetUsedHashFunctionOID;
      end;

      SetLength(FSignature, Length(Hash));
      SBMove(Hash[0], FSignature[0], Length(Hash));
    end
    else
    begin
      SetLength(FSignature, 0);
      raise EElCryptoProviderInvalidSignatureError.Create(SInvalidSignature);
    end;
  end
  else
  if CryptoType = rsapktPSS then
  begin
    if (not (CompareContent(KeyFormat, SB_KEYPROP_RSA_KEYFORMAT_PKCS1))) and
      (not (CompareContent(KeyFormat, SB_KEYPROP_RSA_KEYFORMAT_PSS))) then
      raise EElBuiltInCryptoProviderError.Create(SInvalidKeyMaterialType);

    SetLength(FSignature, SigSize);
    SBMove(Signature^, FSignature[0], SigSize);
    HashAlg := GetUsedHashFunctionOID;  
  end
  else                                                                   
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedEncryptionType);
  if not FInputIsHash then
    FHashFunction := TElBuiltInHashFunction.Create(HashAlg);

end;

procedure TElBuiltInRSAPublicKeyCrypto.VerifyUpdate(Buffer: pointer; Size: integer);
var
  OldLen : integer;
begin
  if FInputIsHash then
  begin
    OldLen := Length(FSpool);
    SetLength(FSpool, OldLen + Size);
    SBMove(Buffer^, FSpool[OldLen], Size);
  end
  else
    FHashFunction.Update(Buffer, Size);
end;

function TElBuiltInRSAPublicKeyCrypto.VerifyFinal : integer;
var
  Hash : ByteArray;
  KeyFormat : ByteArray;
  HashAlg : integer;
  SaltSize, MGFAlg, TrField : integer;
  RSAM, RSAE : ByteArray;
  Prop : ByteArray;
{$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
  DEF_SALT_SIZE : ByteArray = #0#0#0#20;
 {$else}
  DEF_SALT_SIZE : ByteArray;
 {$endif}
begin
  if not FSupportsSigning then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);

  {$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
  DEF_SALT_SIZE := CreateByteArrayConst(#0#0#0#20);
   {$endif}


  if not FInputIsHash then
  begin
    Hash := FHashFunction.Finish;
    FreeAndNil(FHashFunction);
  end
  else
  begin
    SetLength(Hash, Length(FSpool));
    SBMove(FSpool[0], Hash[0], Length(FSpool));
  end;

  KeyFormat := FKeyMaterial.GetKeyProp(SB_KEYPROP_KEYFORMAT, SB_KEYPROP_RSA_KEYFORMAT_PKCS1);
  if CryptoType in [rsapktPKCS1,
    rsapktSSL3] then
  begin
    if (not (CompareContent(KeyFormat, SB_KEYPROP_RSA_KEYFORMAT_PKCS1))) then
      raise EElBuiltInCryptoProviderError.Create(SInvalidKeyMaterialType);

    if (Length(FSignature) > 0) and (Length(Hash) = Length(FSignature)) and
       (CompareMem(@Hash[0], @FSignature[0], Length(Hash)))
    then
      Result := SB_VR_SUCCESS
    else
      Result := SB_VR_INVALID_SIGNATURE;
  end
  {$ifndef SB_PGPSFX_STUB}
  else
  if CryptoType = rsapktPSS then
  begin
    if (not (CompareContent(KeyFormat, SB_KEYPROP_RSA_KEYFORMAT_PKCS1))) and
      (not (CompareContent(KeyFormat, SB_KEYPROP_RSA_KEYFORMAT_PSS))) then
      raise EElBuiltInCryptoProviderError.Create(SInvalidKeyMaterialType);
    if HashAlgorithm = SB_ALGORITHM_UNKNOWN then
      HashAlg := GetHashAlgorithmByOID(FKeyMaterial.GetKeyProp(SB_KEYPROP_HASH_ALGORITHM, EmptyArray))
    else
      HashAlg := HashAlgorithm;
    if FSaltSize = 0 then
      SaltSize := GetIntegerPropFromBuffer(FKeyMaterial.GetKeyProp(SB_KEYPROP_SALT_SIZE, DEF_SALT_SIZE))
    else
      SaltSize := FSaltSize;

    if FMGFAlgorithm = 0 then
    begin
      Prop := FKeyMaterial.GetKeyProp(SB_KEYPROP_MGF_ALGORITHM, EmptyArray);
      if Length(Prop) > 0 then
        MGFAlg := GetAlgorithmByOID(Prop)
      else
        MGFAlg := SB_CERT_MGF1; // using the default value if it is not possible to get the real value
    end                        
    else
      MGFAlg := FMGFAlgorithm;

    if FTrailerField = 0 then
    begin
      Prop := FKeyMaterial.GetKeyProp(SB_KEYPROP_TRAILER_FIELD);
      if Length(Prop) > 0 then
        TrField := GetIntegerPropFromBuffer(Prop)
      else
        TrField := 1;
    end
    else
      TrField := FTrailerField;

    if (TrField <> 1) or (MGFAlg <> SB_CERT_MGF1) then
      raise EElBuiltInCryptoProviderError.CreateFmt(SUnsupportedPropertyValue, [IntToStr(TrField) + '/' + IntToStr(MGFAlg)]);

    RSAM := FKeyMaterial.GetKeyProp(SB_KEYPROP_RSA_M, EmptyArray);
    RSAE := FKeyMaterial.GetKeyProp(SB_KEYPROP_RSA_E, EmptyArray);
    if SBRSA.VerifyPSS(@Hash[0], Length(Hash), HashAlg, SaltSize,
      @RSAM[0], Length(RSAM), @RSAE[0], Length(RSAE), @FSignature[0], Length(FSignature))
    then
      Result := SB_VR_SUCCESS
    else
      Result := SB_VR_INVALID_SIGNATURE;
  end
   {$endif SB_PGPSFX_STUB}
  else
    raise EElBuiltInCryptoProviderError.CreateFmt(SUnsupportedAlgorithmStr, ['']);

end;

function TElBuiltInRSAPublicKeyCrypto.EstimateOutputSize(InBuffer: pointer; InSize: Int64;
  Operation : TSBBuiltInPublicKeyOperation): Int64;
var
  RealSize : integer;
  RSAM : ByteArray;
begin
  if (Operation in [pkoVerify, pkoSign]) and
     (CryptoType in [rsapktPKCS1, rsapktPSS]) then
    raise EElBuiltInCryptoProviderError.Create(SOnlyDetachedSigningSupported);

  RealSize := InSize;
  RSAM := FKeyMaterial.GetKeyProp(SB_KEYPROP_RSA_M, EmptyArray);
  if (Operation in [pkoEncrypt, pkoDecrypt]) and
    (RealSize > Length(RSAM)) then
    raise EElBuiltInCryptoProviderError.Create(SInputTooLong);
  if (Operation = pkoSign) and (InputIsHash) and
    (RealSize > Length(RSAM) - 11) then
    raise EElBuiltInCryptoProviderError.Create(SInputTooLong);
  Result := Length(RSAM);
end;

class function TElBuiltInRSAPublicKeyCrypto.IsAlgorithmSupported(Alg: integer): boolean;
begin
  Result := Alg in [
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
  ];
end;

class function TElBuiltInRSAPublicKeyCrypto.IsAlgorithmSupported(const OID: ByteArray): boolean;
begin
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
    CompareContent(OID, SB_OID_RSAOAEP);
end;

function TElBuiltInRSAPublicKeyCrypto.GetUsedHashFunction: integer;
var
  HashAlg : integer;
begin
  if FHashAlgorithm <> SB_ALGORITHM_UNKNOWN then
    Result := FHashAlgorithm
  else
  begin
    if CryptoType <> rsapktPSS then
    begin
      if CompareContent(FOID, SB_OID_RSAENCRYPTION) then
        Result := SB_ALGORITHM_DGST_SHA1
      else if CompareContent(FOID, SB_OID_MD2_RSAENCRYPTION) then
        Result := SB_ALGORITHM_DGST_MD2
      else if CompareContent(FOID, SB_OID_MD5_RSAENCRYPTION) then
        Result := SB_ALGORITHM_DGST_MD5
      else if CompareContent(FOID, SB_OID_SHA1_RSAENCRYPTION) or CompareContent(FOID, SB_OID_SHA1_RSAENCRYPTION2) then
        Result := SB_ALGORITHM_DGST_SHA1
      else if CompareContent(FOID, SB_OID_SHA224_RSAENCRYPTION) then
        Result := SB_ALGORITHM_DGST_SHA224
      else if CompareContent(FOID, SB_OID_SHA256_RSAENCRYPTION) then
        Result := SB_ALGORITHM_DGST_SHA256
      else if CompareContent(FOID, SB_OID_SHA384_RSAENCRYPTION) then
        Result := SB_ALGORITHM_DGST_SHA384
      else if CompareContent(FOID, SB_OID_SHA512_RSAENCRYPTION) then
        Result := SB_ALGORITHM_DGST_SHA512
      else
        Result := SB_ALGORITHM_UNKNOWN;
    end
    else
    begin
      if CompareContent(FOID, SB_OID_RSAPSS) or CompareContent(FOID, SB_OID_RSAOAEP) then
      begin
        if Assigned(FKeyMaterial) then
        begin
          HashAlg := GetHashAlgorithmByOID(FKeyMaterial.GetKeyProp(SB_KEYPROP_HASH_ALGORITHM, EmptyArray));
          Result := HashAlg;
        end
        else
          Result := SB_ALGORITHM_DGST_SHA1;
      end
      else
        Result := SB_ALGORITHM_UNKNOWN;
    end;
  end;
end;

function TElBuiltInRSAPublicKeyCrypto.GetUsedHashFunctionOID: ByteArray;
begin
  if Length(FHashFuncOID) > 0 then
    Result := CloneArray(FHashFuncOID)
  else
    Result := GetOIDByHashAlgorithm(GetUsedHashFunction);
end;

function TElBuiltInRSAPublicKeyCrypto.AddAlgorithmPrefix(const Hash: ByteArray): ByteArray;
var
  HashFuncOID : ByteArray;
begin
  HashFuncOID := GetUsedHashFunctionOID;
  (*
  Result := AnsiChar(#$06) + AnsiChar(Length(HashFuncOID)) + HashFuncOID; // HashFunction: OID
  Result := Result + #$05#$00; // HashFunction: params
  Result := AnsiChar(#$30) + AnsiChar(Length(Result)) + Result; // AlgorithmIdentifier SEQUENCE
  Result := Result + #$04 + AnsiChar(Length(Hash)) + Hash; // adding hash value
  Result := AnsiChar(#$30) + AnsiChar(Length(Result)) + Result; // the outmost SEQUENCE
  *)
  Result := SBConcatArrays(BytesOfString(#$06 + Chr(Length(HashFuncOID))), HashFuncOID);
  Result := SBConcatArrays(Result, BytesOfString(#$05#$00));
  Result := SBConcatArrays(BytesOfString(#$30 + Chr(Length(Result))), Result);
  Result := SBConcatArrays(Result, SBConcatArrays(BytesOfString(#$04 + Chr(Length(Hash))), Hash));
  Result := SBConcatArrays(BytesOfString(#$30 + Chr(Length(Result))), Result);

end;

function TElBuiltInRSAPublicKeyCrypto.RemoveAlgorithmPrefix(const Value: ByteArray;
  var HashAlg : ByteArray; var HashPar : ByteArray): ByteArray;
var
  Tag, TagSeq : TElASN1ConstrainedTag;
  Processed : boolean;
  Size : integer;
begin
  Processed := false;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if Tag.LoadFromBuffer( @Value[0] , Length(Value)) then
    begin
      if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      begin
        TagSeq := TElASN1ConstrainedTag(Tag.GetField(0));
        if (TagSeq.Count = 2) and (TagSeq.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) and
          (TagSeq.GetField(1).CheckType(SB_ASN1_OCTETSTRING, false)) then
        begin
          Result := TElASN1SimpleTag(TagSeq.GetField(1)).Content;
          TagSeq := TElASN1ConstrainedTag(TagSeq.GetField(0));
          if (TagSeq.Count <= 2) and (TagSeq.GetField(0).CheckType(SB_ASN1_OBJECT, false)) then
          begin
            HashAlg := TElASN1SimpleTag(TagSeq.GetField(0)).Content;
            if (TagSeq.Count = 2) then
            begin
              Size := 0;
              TagSeq.GetField(1).SaveToBuffer( nil , Size);
              SetLength(HashPar, Size);
              TagSeq.GetField(1).SaveToBuffer( @HashPar[0] , Size);
              SetLength(HashPar, Size);
            end
            else
              SetLength(HashPar, 0);
            Processed := true;
          end;
        end;
      end;
    end;
  finally
    FreeAndNil(Tag);
  end;
  if not Processed then
    raise EElBuiltInCryptoProviderError.Create(SBadSignatureFormatting);
end;

procedure TElBuiltInRSAPublicKeyCrypto.SetHashFuncOID(const V : ByteArray);
begin
  FHashFuncOID := CloneArray(V);
end;

class function TElBuiltInRSAPublicKeyCrypto.GetName() : string;
begin
  Result := 'RSA';
end;

class function TElBuiltInRSAPublicKeyCrypto.GetDescription() : string;
begin
  Result := 'Implements base RSA encrypting and signing functionality';
end;

procedure TElBuiltInRSAPublicKeyCrypto.WriteToOutput(Buffer: pointer; Size: integer);
begin
  inherited WriteToOutput(Buffer, Size)
end;

function TElBuiltInRSAPublicKeyCrypto.AlgorithmPrefixNeeded: boolean;
begin
  // CryptoAPI's CryptSignHash and PKCS#11 token add hash algorithm prefix themselves,
  // so we need to suppress prefix generation in this case
  Result := true;
end;

////////////////////////////////////////////////////////////////////////////////
// TElBuiltInDSAPublicKeyCrypto class

 destructor  TElBuiltInDSAPublicKeyCrypto.Destroy;
begin
  if FHashFunction <> nil then
    FreeAndNil(FHashFunction);
  inherited;
end;

function TElBuiltInDSAPublicKeyCrypto.GetUsedHashFunction: integer;
var
  HashAlg : ByteArray;
begin
  if Assigned(FKeyMaterial) then
  begin
    HashAlg := FKeyMaterial.GetKeyProp(SB_KEYPROP_HASH_ALGORITHM, EmptyArray);
    Result := GetHashAlgorithmByOID(HashAlg);
    if Result = SB_ALGORITHM_UNKNOWN then
      Result := SB_ALGORITHM_DGST_SHA1;
  end
  else
    Result := SB_ALGORITHM_UNKNOWN;
end;

function TElBuiltInDSAPublicKeyCrypto.GetSupportsEncryption: boolean;
begin
  Result := false;
end;

function TElBuiltInDSAPublicKeyCrypto.GetSupportsSigning: boolean;
begin
  Result := true;
end;

procedure TElBuiltInDSAPublicKeyCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if Material.Algorithm <> SB_ALGORITHM_PK_DSA then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);
  FKeyMaterial := Material;
end;

procedure TElBuiltInDSAPublicKeyCrypto.EncodeSignature(R : pointer; RSize : integer; S : pointer; SSize : integer;
  Sig : pointer; var SigSize : integer);
begin
  SBDSA.EncodeSignature(R, RSize, S, SSize, Sig, SigSize);
end;

procedure TElBuiltInDSAPublicKeyCrypto.DecodeSignature(Sig : pointer; SigSize : integer; R : pointer;
  var RSize : integer; S : pointer; var SSize : integer);
begin
  SBDSA.DecodeSignature(Sig, SigSize, R, RSize, S, SSize);
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInDSAPublicKeyCrypto.SignInit(Detached: boolean);
begin
  if not FKeyMaterial.IsSecret then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  SetLength(FSpool, 0);
  if not FInputIsHash then
    FHashFunction := TElBuiltInHashFunction.Create(GetUsedHashFunction);
end;

procedure TElBuiltInDSAPublicKeyCrypto.SignUpdate( Buffer: pointer;
    Size: integer);
var
  OldLen : integer;
begin
  if FInputIsHash then
  begin
    OldLen := Length(FSpool);
    SetLength(FSpool, OldLen + Size);
    SBMove(Buffer^, FSpool[OldLen], Size);
  end
  else
    FHashFunction.Update(Buffer,  Size);
end;

procedure TElBuiltInDSAPublicKeyCrypto.SignFinal(Buffer: pointer; var Size: integer);
var
  Hash : ByteArray;
  RSize, SSize, SigSize : integer;
  R, S, Sig : ByteArray;
  DSAP, DSAQ, DSAG, DSAX : ByteArray;
  DSAXLInt, DSARLInt, DSASLInt : PLInt;
begin

  if not FFinished then
  begin
    if FInputIsHash then
    begin
      SetLength(Hash, Length(FSpool));
      SBMove(FSpool[0], Hash[0], Length(Hash));
    end
    else
    begin
      Hash := FHashFunction.Finish;
      FreeAndNil(FHashFunction);
    end;

    {$ifndef SB_NO_PKIASYNC}
    if (not (FKeyMaterial is TElBuiltInDSACryptoKey)) or
      (TElBuiltInDSACryptoKey(FKeyMaterial).FToken = nil) then
     {$endif}
    begin

      RSize := 0;
      SSize := 0;

      DSAP := FKeyMaterial.GetKeyProp(SB_KEYPROP_DSA_P);
      DSAQ := FKeyMaterial.GetKeyProp(SB_KEYPROP_DSA_Q);
      DSAG := FKeyMaterial.GetKeyProp(SB_KEYPROP_DSA_G);
      DSAX := FKeyMaterial.GetKeyProp(SB_KEYPROP_DSA_X);

      SBDSA.SignEx(@Hash[0], Length(Hash), @DSAP[0], Length(DSAP), @DSAQ[0], Length(DSAQ),
        @DSAG[0], Length(DSAG), @DSAX[0], Length(DSAX), nil, RSize, nil, SSize);

      SetLength(R, RSize);
      SetLength(S, SSize);

      if not SBDSA.SignEx(@Hash[0], Length(Hash), @DSAP[0], Length(DSAP), @DSAQ[0], Length(DSAQ),
        @DSAG[0], Length(DSAG), @DSAX[0], Length(DSAX), @R[0], RSize, @S[0], SSize)
      then
        raise EElBuiltInCryptoProviderError.Create(SSigningFailed);
    {$ifndef SB_NO_PKIASYNC}
    end
    else
    begin
      try
        LCreate(DSAXLInt);
        LCreate(DSARLInt);
        LCreate(DSASLInt);
        try
          DSAX := FKeyMaterial.GetKeyProp(SB_KEYPROP_DSA_X);
          PointerToLInt(DSAXLInt, @DSAX[0], Length(DSAX));
          GetGlobalAsyncCalculator().EndDSASigning(TElBuiltInDSACryptoKey(FKeyMaterial).FToken,
            DSAXLInt, @Hash[0], Length(Hash), DSARLInt, DSASLInt);
          RSize := DSARLInt.Length * 4;
          SSize := DSASLInt.Length * 4;
          SetLength(R, RSize);
          SetLength(S, SSize);
          LIntToPointer(DSARLInt, @R[0], RSize);
          LIntToPointer(DSASLInt, @S[0], SSize);
        finally
          LDestroy(DSAXLInt);
          LDestroy(DSARLInt);
          LDestroy(DSASLInt);
        end;
      finally
        if TElBuiltInDSACryptoKey(FKeyMaterial).FReleaseToken then
          FreeAndNil(TElBuiltInDSACryptoKey(FKeyMaterial).FToken);
      end;
     {$endif}
    end;

    SigSize := 0;
    SBDSA.EncodeSignature(@R[0], RSize, @S[0], SSize, nil, SigSize);
    SetLength(Sig, SigSize);

    if not SBDSA.EncodeSignature(@R[0], RSize, @S[0], SSize, @Sig[0], SigSize)
    then
      raise EElBuiltInCryptoProviderError.Create(SSigningFailed);

    WriteToOutput( @Sig[0] , SigSize);
    FFinished := true;
  end;

  if not FOutputIsStream then
  begin
    if Buffer = nil then
      Size := Length(FOutput)
    else
    begin
      if Size >= Length(FOutput) then
      begin
        Size := Length(FOutput);
        SBMove(FOutput[0], Buffer^, Size);
      end
      else
        raise EElBuiltInCryptoProviderError.Create(SBufferTooSmall);
    end;
  end;


end;
 {$endif SB_PGPSFX_STUB}

procedure TElBuiltInDSAPublicKeyCrypto.VerifyInit(Detached: boolean;  Signature: pointer;
    SigSize: integer);
var
  RealSigPtr :  pointer ;
  RealSigSize : integer;
begin
  if not FKeyMaterial.IsPublic then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);


  SetLength(FSpool, 0);

  RealSigPtr := Signature;
  RealSigSize := SigSize;

  SetLength(FSignature, RealSigSize);
  SBMove(RealSigPtr^, FSignature[0], RealSigSize);

  if not FInputIsHash then
    FHashFunction := TElBuiltInHashFunction.Create(GetUsedHashFunction);


end;

procedure TElBuiltInDSAPublicKeyCrypto.VerifyUpdate( Buffer: pointer;
   Size: integer);
var
  OldLen : integer;
begin
  if FInputIsHash then
  begin
    OldLen := Length(FSpool);
    SetLength(FSpool, OldLen + Size);
    SBMove(Buffer^, FSpool[OldLen], Size);
  end
  else
    FHashFunction.Update(Buffer, Size);
end;

function TElBuiltInDSAPublicKeyCrypto.VerifyFinal : integer;
var
  R, S : ByteArray;
  RSize, SSize : integer;
  Hash : ByteArray;
  DSAP, DSAQ, DSAG, DSAY : ByteArray;
begin
  if not (FKeyMaterial.IsPublic) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);


  if not FInputIsHash then
  begin
    Hash := FHashFunction.Finish;
    FreeAndNil(FHashFunction);
  end
  else
  begin
    SetLength(Hash, Length(FSpool));
    SBMove(FSpool[0], Hash[0], Length(FSpool));
    SetLength(FSpool, 0);
  end;

  if Length(FSignature) <= 0 then
  begin
    Result := SB_VR_INVALID_SIGNATURE;
    Exit;  
  end;

  RSize := 0;
  SSize := 0;
  SBDSA.DecodeSignature(@FSignature[0], Length(FSignature), nil, RSize, nil, SSize);

  if (RSize <= 0) or (SSize <= 0) then
  begin
    Result := SB_VR_INVALID_SIGNATURE;
    Exit;
  end;

  SetLength(R, RSize);
  SetLength(S, SSize);

  if not SBDSA.DecodeSignature(@FSignature[0], Length(FSignature), @R[0], RSize, @S[0], SSize)
  then
  begin
    Result := SB_VR_INVALID_SIGNATURE;
    Exit;
  end;

  SetLength(R, RSize);
  SetLength(S, SSize);

  DSAP := FKeyMaterial.GetKeyProp(SB_KEYPROP_DSA_P);
  DSAQ := FKeyMaterial.GetKeyProp(SB_KEYPROP_DSA_Q);
  DSAG := FKeyMaterial.GetKeyProp(SB_KEYPROP_DSA_G);
  DSAY := FKeyMaterial.GetKeyProp(SB_KEYPROP_DSA_Y);

  if SBDSA.ValidateSignature(@Hash[0], Length(Hash), @DSAP[0], Length(DSAP),
    @DSAQ[0], Length(DSAQ), @DSAG[0], Length(DSAG), @DSAY[0], Length(DSAY),
    @R[0], RSize, @S[0], SSize)
  then
    Result := SB_VR_SUCCESS
  else
    Result := SB_VR_INVALID_SIGNATURE; 

end;

function TElBuiltInDSAPublicKeyCrypto.EstimateOutputSize( InBuffer: pointer;
    InSize: Int64;
  Operation : TSBBuiltInPublicKeyOperation): Int64;
var
  QBits : integer;
begin
  if (Operation in [pkoEncrypt,
    pkoDecrypt,
    pkoVerify]) then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
  if (Operation = pkoSign) and
     (not FKeyMaterial.IsSecret) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  QBits := GetIntegerPropFromBuffer(FKeyMaterial.GetKeyProp(SB_KEYPROP_DSA_QBITS), 160);
  Result := (QBits shr 3) shl 1 + 16;
end;

class function TElBuiltInDSAPublicKeyCrypto.IsAlgorithmSupported(Alg: integer): boolean;
begin
  Result := Alg in [SB_CERT_ALGORITHM_ID_DSA, SB_CERT_ALGORITHM_ID_DSA_SHA1];
end;

class function TElBuiltInDSAPublicKeyCrypto.IsAlgorithmSupported(const OID: ByteArray): boolean;
begin
  Result := CompareContent(OID, SB_OID_DSA) or CompareContent(OID, SB_OID_DSA_SHA1);
end;

class function TElBuiltInDSAPublicKeyCrypto.GetName() : string;
begin
  Result := 'DSA';
end;

class function TElBuiltInDSAPublicKeyCrypto.GetDescription() : string;
begin
  Result := 'Implements DSA signing functionality';
end;

procedure TElBuiltInDSAPublicKeyCrypto.WriteToOutput( Buffer: pointer;
    Size: integer);
begin
  inherited WriteToOutput(Buffer, Size)
end;

procedure TElBuiltInDSAPublicKeyCrypto.Reset;
begin
  inherited;
  FInputIsHash := false;
end;

constructor TElBuiltInDSAPublicKeyCrypto.Create(const OID : ByteArray);
begin
  inherited Create;
  FOID := OID;

  if not IsAlgorithmSupported(OID) then
    raise EElBuiltInCryptoProviderError.CreateFmt(SUnsupportedAlgorithmStr, [OIDToStr(OID)]);
end;

constructor TElBuiltInDSAPublicKeyCrypto.Create(Alg : integer);
begin
  inherited Create;

  FOID := EmptyArray;

  if IsAlgorithmSupported(Alg) then
  begin
    FOID := GetOIDByPKAlgorithm(Alg);
    if Length(FOID) = 0 then
      FOID := GetOIDBySigAlgorithm(Alg);
  end;
  if CompareContent(FOID, EmptyArray) then
    raise EElBuiltInCryptoProviderError.CreateFmt(SUnsupportedAlgorithmInt, [Alg]);
end;

constructor TElBuiltInDSAPublicKeyCrypto.Create;
begin
  Create(SB_OID_DSA);
end;

////////////////////////////////////////////////////////////////////////////////
// TElBuiltInECDSAPublicKeyCrypto class
{$ifdef SB_HAS_ECC}

 destructor  TElBuiltInECDSAPublicKeyCrypto.Destroy;
begin
  if FHashFunction <> nil then
    FreeAndNil(FHashFunction);
  inherited;
end;

function TElBuiltInECDSAPublicKeyCrypto.GetUsedHashFunction: integer;
var
  KeyBits : integer;
begin
  Result := SB_ALGORITHM_UNKNOWN;
  
  if FHashAlgorithm <> SB_ALGORITHM_UNKNOWN then
    Result := FHashAlgorithm
  else
  begin
    if CompareContent(FOID, SB_OID_ECDSA_SHA1) then
      Result := SB_ALGORITHM_DGST_SHA1
    else if CompareContent(FOID, SB_OID_ECDSA_SHA224) then
      Result := SB_ALGORITHM_DGST_SHA224
    else if CompareContent(FOID, SB_OID_ECDSA_SHA256) then
      Result := SB_ALGORITHM_DGST_SHA256
    else if CompareContent(FOID, SB_OID_ECDSA_SHA384) then
      Result := SB_ALGORITHM_DGST_SHA384
    else if CompareContent(FOID, SB_OID_ECDSA_SHA512) then
      Result := SB_ALGORITHM_DGST_SHA512
    else if CompareContent(FOID, SB_OID_ECDSA_RECOMMENDED) then
    begin
      if not Assigned(FKeyMaterial) then
      begin
        Result := SB_ALGORITHM_UNKNOWN;
        Exit;
      end;

      KeyBits := TElBuiltInECCryptoKey(FKeyMaterial).Bits;

      if KeyBits <= 160 then
        Result := SB_ALGORITHM_DGST_SHA1
      else if KeyBits <= 224 then
        Result := SB_ALGORITHM_DGST_SHA224
      else if KeyBits <= 256 then
        Result := SB_ALGORITHM_DGST_SHA256
      else if KeyBits <= 384 then
        Result := SB_ALGORITHM_DGST_SHA384
      else if KeyBits <= 512 then
        Result := SB_ALGORITHM_DGST_SHA512
      else
        Result := SB_ALGORITHM_UNKNOWN;
    end
    else if CompareContent(FOID, SB_OID_ECDSA_PLAIN_SHA1) then
      Result := SB_ALGORITHM_DGST_SHA1
    else if CompareContent(FOID, SB_OID_ECDSA_PLAIN_SHA224) then
      Result := SB_ALGORITHM_DGST_SHA224
    else if CompareContent(FOID, SB_OID_ECDSA_PLAIN_SHA256) then
      Result := SB_ALGORITHM_DGST_SHA256
    else if CompareContent(FOID, SB_OID_ECDSA_PLAIN_SHA384) then
      Result := SB_ALGORITHM_DGST_SHA384
    else if CompareContent(FOID, SB_OID_ECDSA_PLAIN_SHA512) then
      Result := SB_ALGORITHM_DGST_SHA512
    else if CompareContent(FOID, SB_OID_ECDSA_PLAIN_RIPEMD160) then
      Result := SB_ALGORITHM_DGST_RIPEMD160;
  end
end;

function TElBuiltInECDSAPublicKeyCrypto.GetSupportsEncryption: boolean;
begin
  Result := false;
end;

function TElBuiltInECDSAPublicKeyCrypto.GetSupportsSigning: boolean;
begin
  Result := true;
end;

procedure TElBuiltInECDSAPublicKeyCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if not (Material is TElBuiltInECCryptoKey) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  FKeyMaterial := Material;
end;

class function TElBuiltInECDSAPublicKeyCrypto.IsAlgorithmSupported(Alg: integer): boolean;
begin
  Result := Alg = SB_ALGORITHM_PK_ECDSA;
end;

class function TElBuiltInECDSAPublicKeyCrypto.IsAlgorithmSupported(const OID: ByteArray): boolean;
begin
  Result := false;

  if CompareContent(OID, SB_OID_ECDSA_SHA1) or
    CompareContent(OID, SB_OID_ECDSA_SHA256) or
    CompareContent(OID, SB_OID_ECDSA_SHA384) or
    CompareContent(OID, SB_OID_ECDSA_SHA512) or
    CompareContent(OID, SB_OID_ECDSA_RECOMMENDED) or
    CompareContent(OID, SB_OID_ECDSA_PLAIN_SHA1) or
    CompareContent(OID, SB_OID_ECDSA_PLAIN_SHA224) or
    CompareContent(OID, SB_OID_ECDSA_PLAIN_SHA256) or
    CompareContent(OID, SB_OID_ECDSA_PLAIN_SHA384) or
    CompareContent(OID, SB_OID_ECDSA_PLAIN_SHA512) or
    CompareContent(OID, SB_OID_ECDSA_PLAIN_RIPEMD160)                    
  then
    Result := true;
end;

class function TElBuiltInECDSAPublicKeyCrypto.GetName : string;
begin
  Result := 'ECDSA';
end;

class function TElBuiltInECDSAPublicKeyCrypto.GetDescription : string;
begin
  Result := 'Implements ECDSA signing functionality'
end;

procedure TElBuiltInECDSAPublicKeyCrypto.WriteToOutput( Buffer: pointer;
    Size: integer);
begin
  inherited WriteToOutput(Buffer, Size);
end;

procedure TElBuiltInECDSAPublicKeyCrypto.Reset;
begin
  inherited;

  FHashAlgorithm := SB_ALGORITHM_UNKNOWN;
  FOID := EmptyArray;
  FInputIsHash := false;
end;

constructor TElBuiltInECDSAPublicKeyCrypto.Create(const OID : ByteArray);
begin
  inherited Create;

  Reset;
  FOID := CloneArray(OID);
  FPlainECDSA := false;

  if not IsAlgorithmSupported(OID) then
    raise EElBuiltInCryptoProviderError.CreateFmt(SUnsupportedAlgorithmStr, [OIDToStr(OID)]);
end;

constructor TElBuiltInECDSAPublicKeyCrypto.Create(Alg : integer);
begin
  inherited Create;

  Reset;
  FHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
  FPlainECDSA := false;  

  if not IsAlgorithmSupported(Alg) then
    raise EElBuiltInCryptoProviderError.CreateFmt(SUnsupportedAlgorithmInt, [Alg]);
end;

constructor TElBuiltInECDSAPublicKeyCrypto.Create;
begin
  Create(SB_ALGORITHM_PK_ECDSA);
end;

procedure TElBuiltInECDSAPublicKeyCrypto.EncodeSignature(R : pointer; RSize : integer; S : pointer; SSize : integer;
  Sig : pointer; var SigSize : integer);
begin
  SBDSA.EncodeSignature(R, RSize, S, SSize, Sig, SigSize);
end;

procedure TElBuiltInECDSAPublicKeyCrypto.DecodeSignature(Sig : pointer; SigSize : integer; R : pointer;
  var RSize : integer; S : pointer; var SSize : integer);
begin
  SBDSA.DecodeSignature(Sig, SigSize, R, RSize, S, SSize);
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInECDSAPublicKeyCrypto.SignInit(Detached: boolean);
begin
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.IsSecret) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  SetLength(FSpool, 0);
  if not FInputIsHash then
    FHashFunction := TElBuiltInHashFunction.Create(GetUsedHashFunction);
end;

procedure TElBuiltInECDSAPublicKeyCrypto.SignUpdate(
   Buffer: pointer;   Size: integer);
var
  OldLen : integer;
begin
  if FInputIsHash then
  begin
    OldLen := Length(FSpool);
    SetLength(FSpool, OldLen + Size);
    SBMove(Buffer^, FSpool[OldLen], Size);
  end
  else
    FHashFunction.Update(Buffer,  Size);
end;          

procedure TElBuiltInECDSAPublicKeyCrypto.SignFinal(Buffer: pointer; var Size: integer);
var
  Hash : ByteArray;
  RSize, SSize, SigSize : integer;
  R, S, Sig : ByteArray;
  N, D, A, B, P, X, Y : ByteArray;
  Fld, FldType, Flag : integer;
begin
  
  if not FFinished then
  begin
    if FInputIsHash then
    begin
      SetLength(Hash, Length(FSpool));
      SBMove(FSpool[0], Hash[0], Length(Hash));
    end
    else
    begin
      Hash := FHashFunction.Finish;
      FreeAndNil(FHashFunction);
    end;

    N := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_N);
    P := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_P);
    D := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_D);
    A := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_A);
    B := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_B);
    X := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_X);
    Y := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_Y);
    Fld := GetIntegerPropFromBuffer(FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_FIELD_INT));
    FldType := GetIntegerPropFromBuffer(FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_FIELD_TYPE_INT));
    if FPlainECDSA then
      Flag := SB_ECDSA_WRAP_MOD_N
    else
      Flag := 0;

    if (Length(N) = 0) or (Length(D) = 0) or (Length(A) = 0) or (Length(B) = 0) or
      (Length(X) = 0) or (Length(Y) = 0) or (Length(P) = 0)
    then
      raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

    RSize := 0;
    SSize := 0;
    SBECDSA.SignEx(@Hash[0], Length(Hash), @D[0], Length(D), @A[0], Length(A),
      @B[0], Length(B), @X[0], Length(X), @Y[0], Length(Y), @N[0], Length(N),
      @P[0], Length(P), FldType, Fld, Flag, nil, RSize, nil, SSize);

    if (RSize = 0) or (SSize = 0) then
      raise EElBuiltInCryptoProviderError.Create(SSigningFailed);

    SetLength(R, RSize);
    SetLength(S, SSize);

    if not SBECDSA.SignEx(@Hash[0], Length(Hash), @D[0], Length(D), @A[0], Length(A),
      @B[0], Length(B), @X[0], Length(X), @Y[0], Length(Y), @N[0], Length(N),
      @P[0], Length(P), FldType, Fld, Flag, @R[0], RSize, @S[0], SSize)
    then
      raise EElBuiltInCryptoProviderError.Create(SSigningFailed);

    if FPlainECDSA then
    begin
      SigSize := RSize + SSize;
      SetLength(Sig, SigSize);
      SBMove(R[0], Sig[0], RSize);
      SBMove(S[0], Sig[RSize], SSize);
    end
    else
    begin
      SigSize := 0;
      Self.EncodeSignature(@R[0], RSize, @S[0], SSize, nil, SigSize);
      SetLength(Sig, SigSize);

      Self.EncodeSignature(@R[0], RSize, @S[0], SSize, @Sig[0], SigSize);
    end;  

    if SigSize = 0 then
      raise EElBuiltInCryptoProviderError.Create(SSigningFailed);

    WriteToOutput( @Sig[0] , SigSize);
    FFinished := true;
  end;

  if not FOutputIsStream then
  begin
    if Buffer = nil then
      Size := Length(FOutput)
    else
    begin
      if Size >= Length(FOutput) then
      begin
        Size := Length(FOutput);
        SBMove(FOutput[0], Buffer^, Size);
      end
      else
        raise EElBuiltInCryptoProviderError.Create(SBufferTooSmall);
    end;
  end;

end;
 {$endif}

procedure TElBuiltInECDSAPublicKeyCrypto.VerifyInit(Detached: boolean;  Signature: pointer;
    SigSize: integer);
var
  RealSigPtr :  pointer ;
  RealSigSize : integer;
begin
  if (not Assigned(FKeyMaterial)) or (not FKeyMaterial.IsPublic) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);


  SetLength(FSpool, 0);

  RealSigPtr := Signature;
  RealSigSize := SigSize;

  SetLength(FSignature, RealSigSize);
  SBMove(RealSigPtr^, FSignature[0], RealSigSize);

  if not FInputIsHash then
    FHashFunction := TElBuiltInHashFunction.Create(GetUsedHashFunction);

end;

procedure TElBuiltInECDSAPublicKeyCrypto.VerifyUpdate( Buffer: pointer;
    Size: integer);
var
  OldLen : integer;
begin
  if FInputIsHash then
  begin
    OldLen := Length(FSpool);
    SetLength(FSpool, OldLen + Size);
    SBMove(Buffer^, FSpool[OldLen], Size);
  end
  else
    FHashFunction.Update(Buffer, Size);
end;

function TElBuiltInECDSAPublicKeyCrypto.VerifyFinal : integer;
var
  R, S : ByteArray;
  RSize, SSize : integer;
  Fld, FldType, Flag : integer;
  Hash : ByteArray;
  N, QX, QY, A, B, P, X, Y : ByteArray;
begin
  if not (FKeyMaterial.IsPublic) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);


  if not FInputIsHash then
  begin
    Hash := FHashFunction.Finish;
    FreeAndNil(FHashFunction);
  end
  else
  begin
    SetLength(Hash, Length(FSpool));
    SBMove(FSpool[0], Hash[0], Length(FSpool));
    SetLength(FSpool, 0);
  end;

  if Length(FSignature) <= 0 then
  begin
    Result := SB_VR_INVALID_SIGNATURE;
    Exit;
  end;

  if FPlainECDSA then
  begin
    RSize := Length(FSignature) shr 1;
    SSize := Length(FSignature) - RSize;
    SetLength(R, RSize);
    SetLength(S, SSize);
    SBMove(FSignature[0], R[0], RSize);
    SBMove(FSignature[RSize], S[0], SSize);
    Flag := SB_ECDSA_WRAP_MOD_N;
  end
  else
  begin
    Flag := 0;
    RSize := 0;
    SSize := 0;
    Self.DecodeSignature(@FSignature[0], Length(FSignature), nil, RSize, nil, SSize);

    if (RSize <= 0) or (SSize <= 0) then
    begin
      Result := SB_VR_INVALID_SIGNATURE;
      Exit;
    end;

    SetLength(R, RSize);
    SetLength(S, SSize);

    Self.DecodeSignature(@FSignature[0], Length(FSignature), @R[0], RSize, @S[0], SSize);

    if (RSize <= 0) or (SSize <= 0) then
    begin
      Result := SB_VR_INVALID_SIGNATURE;
      Exit;
    end;

    SetLength(R, RSize);
    SetLength(S, SSize);
  end;

  N := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_N);
  P := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_P);
  A := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_A);
  B := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_B);
  X := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_X);
  Y := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_Y);
  QX := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_QX);
  QY := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_QY);
  Fld := GetIntegerPropFromBuffer(FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_FIELD_INT));
  FldType := GetIntegerPropFromBuffer(FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_FIELD_TYPE_INT));

  if (Length(QX) = 0) or (Length(QY) = 0) or (Length(N) = 0) or (Length(A) = 0) or (Length(B) = 0) or
    (Length(X) = 0) or (Length(Y) = 0) or (Length(P) = 0)
  then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  if SBECDSA.VerifyEx(@Hash[0], Length(Hash), @QX[0], Length(QX), @QY[0], Length(QY),
    @R[0], Length(R), @S[0], Length(S), @A[0], Length(A), @B[0], Length(B),
    @X[0], Length(X), @Y[0], Length(Y), @N[0], Length(N), @P[0], Length(P),
    FldType, Fld, Flag)
  then
    Result := SB_VR_SUCCESS
  else
    Result := SB_VR_INVALID_SIGNATURE;

end;

function TElBuiltInECDSAPublicKeyCrypto.EstimateOutputSize( InBuffer: pointer;
    InSize: Int64;
  Operation : TSBBuiltInPublicKeyOperation): Int64;
begin
  if (Operation in [pkoEncrypt,
    pkoDecrypt])
  then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);


  if (Operation = pkoVerify) then
  begin
    Result := 0;
    Exit;
  end;

  if (Operation = pkoSign) and
     (not FKeyMaterial.IsSecret) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  Result := GetIntegerPropFromBuffer(FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_N));
  if Result > 0 then
    Result := Result shl 1 + 16;
end;

////////////////////////////////////////////////////////////////////////////////
// TElBuiltInECDHPublicKeyCrypto

constructor TElBuiltInECDHPublicKeyCrypto.Create(const OID : ByteArray);
begin
  inherited Create;
end;

constructor TElBuiltInECDHPublicKeyCrypto.Create(Alg : integer);
begin
  inherited Create;
end;

constructor TElBuiltInECDHPublicKeyCrypto.Create;
begin
  inherited Create;
end;

 destructor  TElBuiltInECDHPublicKeyCrypto.Destroy;
begin
  inherited;
end;


{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInECDHPublicKeyCrypto.EncryptInit;
begin
  if not Assigned(FKeyMaterial) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);
  if not FKeyMaterial.IsPublic then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  SetLength(FSpool, 0);
end;

procedure TElBuiltInECDHPublicKeyCrypto.EncryptUpdate( Buffer: pointer;
    Size: integer);
var
  OldLen: integer;
begin
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + Size);
  SBMove(Buffer^, FSpool[OldLen], Size);
end;

procedure TElBuiltInECDHPublicKeyCrypto.EncryptFinal;
var
  Res : ByteArray;
begin
  { just a public key }
  Res := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_Q);
  if Length(Res) = 0 then
    raise EElBuiltInCryptoProviderError.Create(SInvalidPublicKey);
  WriteToOutput(@Res[0], Length(Res));
  ReleaseArray(Res);
end;
 {$endif}

procedure TElBuiltInECDHPublicKeyCrypto.DecryptInit;
begin
  if not Assigned(FKeyMaterial) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);
  if not FKeyMaterial.IsSecret then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  SetLength(FSpool, 0);
end;

procedure TElBuiltInECDHPublicKeyCrypto.DecryptUpdate( Buffer: pointer;
    Size: integer);
var
  OldLen: integer;
begin
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + Size);
  SBMove(Buffer^, FSpool[OldLen], Size);
end;

procedure TElBuiltInECDHPublicKeyCrypto.DecryptFinal;
var
  Res, X, Y, A, B, D, P, N : ByteArray;
  LX, LY, LA, LB, LD, LP, LN, LX1, LY1 : PLInt;
  XSize, YSize : integer;
  Fld, FldType : integer;
begin
  // if input data is empty, then using stored X value as encrypted data
  if Length(FSpool) < 1 then
    raise EElBuiltInCryptoProviderError.Create(SInvalidInputSize);



  XSize := 0;
  YSize := 0;
  SBECCommon.BufferToPoint(@FSpool[0], Length(FSpool), TElBuiltInECCryptoKey(FKeyMaterial).FDomainParameters,
    nil, XSize, nil, YSize);
  SetLength(X, XSize);
  SetLength(Y, YSize);

  if not SBECCommon.BufferToPoint(@FSpool[0], Length(FSpool), TElBuiltInECCryptoKey(FKeyMaterial).FDomainParameters,
    @X[0], XSize, @Y[0], YSize)
  then
    raise EElBuiltInCryptoProviderError.Create(SDecryptionFailed);

  N := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_N);
  D := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_D);
  P := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_P);
  A := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_A);
  B := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_B);
  Fld := GetIntegerPropFromBuffer(FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_FIELD_INT));
  FldType := GetIntegerPropFromBuffer(FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_FIELD_TYPE_INT));

  LCreate(LX);
  LCreate(LY);
  LCreate(LP);
  LCreate(LA);
  LCreate(LB);
  LCreate(LD);
  LCreate(LN);
  LCreate(LX1);
  LCreate(LY1);

  try
    PointerToLInt(LX,  @X[0] , Length(X));
    PointerToLInt(LY,  @Y[0] , Length(Y));
    PointerToLInt(LN,  @N[0] , Length(N));
    PointerToLInt(LD,  @D[0] , Length(D));
    PointerToLInt(LP,  @P[0] , Length(P));
    PointerToLInt(LA,  @A[0] , Length(A));
    PointerToLInt(LB,  @B[0] , Length(B));

    if FldType = SB_EC_FLD_TYPE_FP then
      ECPFpExpJA(LX, LY, LP, LA, LD, LX1, LY1, Fld)
    else if FldType = SB_EC_FLD_TYPE_F2MP then
      ECPF2mPExpLDA(LX, LY, LA, LB, LP, LD, LX1, LY1, Fld)
    else
      raise EElECError.Create(SDecryptionFailed);

    { ECDH used in TLS - X-coordinate of the result }

    XSize := LX1.Length * 4;
    SetLength(Res, XSize);
    LIntToPointer(LX1, @Res[0], XSize);
    YSize := TElBuiltInECCryptoKey(FKeyMaterial).FDomainParameters.FieldBits;
    YSize := (YSize + 7) shr 3;
    WriteToOutput(@Res[0 + XSize - YSize], YSize);
  finally
    LDestroy(LX);
    LDestroy(LY);
    LDestroy(LA);
    LDestroy(LB);
    LDestroy(LP);
    LDestroy(LD);
    LDestroy(LN);
    LDestroy(LX1);
    LDestroy(LY1);
  end;

end;

function TElBuiltInECDHPublicKeyCrypto.EstimateOutputSize( InBuffer: pointer;
    InSize: Int64;
  Operation : TSBBuiltInPublicKeyOperation): Int64;
var
  PLen : integer;
begin
  if (Operation in [pkoVerify,
    pkoSign]) then
    raise EElBuiltInCryptoProviderError.Create(SNotASigningAlgorithm);
  if (KeyMaterial.Algorithm <> SB_ALGORITHM_PK_EC) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  PLen := TElBuiltInECCryptoKey(FKeyMaterial).FDomainParameters.FieldBits;
  PLen := (PLen + 7) shr 3;

  if Operation = pkoEncrypt then
    Result := PLen shl 1 + 1
  else if Operation = pkoDecrypt then
    Result := PLen
  else
    Result := 0;
end;

function TElBuiltInECDHPublicKeyCrypto.GetSupportsEncryption: boolean;
begin
  Result := true;
end;

function TElBuiltInECDHPublicKeyCrypto.GetSupportsSigning: boolean;
begin
  Result := false;
end;

procedure TElBuiltInECDHPublicKeyCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if Material.Algorithm <> SB_ALGORITHM_PK_EC then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);
  FKeyMaterial := Material;
end;

class function TElBuiltInECDHPublicKeyCrypto.IsAlgorithmSupported(Alg: integer): boolean;
begin
  Result := Alg = SB_ALGORITHM_PK_ECDH;
end;

class function TElBuiltInECDHPublicKeyCrypto.IsAlgorithmSupported(const OID: ByteArray): boolean;
begin
  Result := false;
end;

class function TElBuiltInECDHPublicKeyCrypto.GetName() : string;
begin
  Result := 'ECDH';
end;

class function TElBuiltInECDHPublicKeyCrypto.GetDescription() : string;
begin
  Result := 'Implements ECDH key exchange algorithm';
end;

procedure TElBuiltInECDHPublicKeyCrypto.WriteToOutput( Buffer: pointer;
    Size: integer);
begin
  inherited WriteToOutput(Buffer, Size);
end;

procedure TElBuiltInECDHPublicKeyCrypto.Reset;
begin
  inherited;
  SetLength(FSpool, 0);
end;

 {$endif} //SB_HAS_ECC

////////////////////////////////////////////////////////////////////////////////
// TElBuiltInElgamalPublicKeyCrypto class

constructor TElBuiltInElgamalPublicKeyCrypto.Create(const OID : ByteArray);
begin
  inherited Create;

  if not IsAlgorithmSupported(OID) then
    raise EElBuiltInCryptoProviderError.CreateFmt(SUnsupportedAlgorithmStr, [OIDToStr(OID)]);

  FHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
end;
 
constructor TElBuiltInElgamalPublicKeyCrypto.Create(Alg : integer);
begin
  inherited Create;

  if not IsAlgorithmSupported(Alg) then
    raise EElBuiltInCryptoProviderError.CreateFmt(SUnsupportedAlgorithmInt, [Alg]);

  FHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
end;
 
constructor TElBuiltInElgamalPublicKeyCrypto.Create;
begin
  Create(SB_ALGORITHM_PK_ELGAMAL);
end;

 destructor  TElBuiltInElgamalPublicKeyCrypto.Destroy;
begin
  if FHashFunction <> nil then
    FreeAndNil(FHashFunction);
  inherited;
end;

function TElBuiltInElgamalPublicKeyCrypto.GetSupportsEncryption: boolean;
begin
  Result := true;
end;

function TElBuiltInElgamalPublicKeyCrypto.GetSupportsSigning: boolean;
begin
  Result := true;
end;

procedure TElBuiltInElgamalPublicKeyCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if Material.Algorithm <> SB_ALGORITHM_PK_ELGAMAL then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);
  FKeyMaterial := Material;
end;

class function TElBuiltInElgamalPublicKeyCrypto.IsAlgorithmSupported(Alg: integer): boolean;
begin
  Result := Alg = SB_ALGORITHM_PK_ELGAMAL;
end;

class function TElBuiltInElgamalPublicKeyCrypto.IsAlgorithmSupported(const OID: ByteArray): boolean;
begin
  Result := false;
end;

class function TElBuiltInElgamalPublicKeyCrypto.GetName() : string;
begin
  Result := 'Elgamal';
end;

class function TElBuiltInElgamalPublicKeyCrypto.GetDescription() : string;
begin
  Result := 'Implements Elgamal encryption and signing functions'; 
end;

procedure TElBuiltInElgamalPublicKeyCrypto.WriteToOutput( Buffer: pointer;
    Size: integer);
begin
  inherited WriteToOutput(Buffer, Size);
end;

procedure TElBuiltInElgamalPublicKeyCrypto.Reset;
begin
  inherited;
  FInputIsHash := true;
  FHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInElgamalPublicKeyCrypto.SignInit(Detached: boolean);
begin
  if not Assigned(FKeyMaterial) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  SetLength(FSpool, 0);
  if not FInputIsHash then
    FHashFunction := TElBuiltInHashFunction.Create(FHashAlgorithm);
end;

procedure TElBuiltInElgamalPublicKeyCrypto.SignUpdate( Buffer: pointer;
    Size: integer);
var
  OldLen : integer;
begin
  if FInputIsHash then
  begin
    OldLen := Length(FSpool);
    SetLength(FSpool, OldLen + Size);
    SBMove(Buffer^, FSpool[OldLen], Size);
  end
  else
    FHashFunction.Update(Buffer, Size);
end;

procedure TElBuiltInElgamalPublicKeyCrypto.SignFinal(Buffer: pointer; var Size: integer);
var
  Hash : ByteArray;
  SigSize : integer;
  TmpR, TmpS, Sig : ByteArray;
  M, P, G, X, R, S : PLInt;
  PV, GV, XV : ByteArray;
begin

  if not FFinished then
  begin
    if FInputIsHash then
    begin
      SetLength(Hash, Length(FSpool));
      SBMove(FSpool[0], Hash[0], Length(Hash));
    end
    else
    begin
      Hash := FHashFunction.Finish;
      FreeAndNil(FHashFunction);
    end;

    LCreate(P);
    LCreate(G);
    LCreate(X);
    LCreate(R);
    LCreate(S);
    LCreate(M);

    try
      {$ifndef SB_NO_PKIASYNC}
      if (not (KeyMaterial is TElBuiltInElgamalCryptoKey)) or
        (TElBuiltInElgamalCryptoKey(KeyMaterial).FToken = nil) then
       {$endif}
      begin
        PV := KeyMaterial.GetKeyProp(SB_KEYPROP_ELGAMAL_P, EmptyArray);
        XV := KeyMaterial.GetKeyProp(SB_KEYPROP_ELGAMAL_X, EmptyArray);
        GV := KeyMaterial.GetKeyProp(SB_KEYPROP_ELGAMAL_G, EmptyArray);
        PointerToLInt(M, @Hash[0], Length(Hash));
        PointerToLInt(P, @PV[0], Length(PV));
        PointerToLInt(G, @GV[0], Length(GV));
        PointerToLInt(X, @XV[0], Length(XV));

        SBElGamal.Sign(M, P, G, X, R, S);
      {$ifndef SB_NO_PKIASYNC}
      end
      else
      begin
        XV := KeyMaterial.GetKeyProp(SB_KEYPROP_ELGAMAL_X, EmptyArray);
        PointerToLInt(X, @XV[0], Length(XV));
        PointerToLInt(M, @Hash[0], Length(Hash));
        try
          GetGlobalAsyncCalculator().EndElgamalSigning(TElBuiltInElgamalCryptoKey(KeyMaterial).FToken,
            X, M, R, S);
        finally
          if TElBuiltInElgamalCryptoKey(KeyMaterial).FReleaseToken then
            FreeAndNil(TElBuiltInElgamalCryptoKey(KeyMaterial).FToken);
        end;
       {$endif} 
      end;

      SetLength(TmpR, R.Length * 4);
      SetLength(TmpS, S.Length * 4);
      SigSize := Length(TmpR);
      LIntToPointer(R, @TmpR[0], SigSize);
      SigSize := Length(TmpS);
      LIntToPointer(S, @TmpS[0], SigSize);
      SigSize := 0;

      SBElGamal.EncodeResult(@TmpR[0], Length(TmpR), @TmpS[0], Length(TmpS), nil, SigSize);
      SetLength(Sig, SigSize);
      SBElGamal.EncodeResult(@TmpR[0], Length(TmpR), @TmpS[0], Length(TmpS), @Sig[0], SigSize);

      WriteToOutput( @Sig[0] , SigSize);
    finally
      LDestroy(P);
      LDestroy(G);
      LDestroy(X);
      LDestroy(R);
      LDestroy(S);
      LDestroy(M);
    end;
    FFinished := true;
  end;
  if not FOutputIsStream then
  begin
    if Buffer = nil then
      Size := Length(FOutput)
    else
    begin
      if Size >= Length(FOutput) then
      begin
        Size := Length(FOutput);
        SBMove(FOutput[0], Buffer^, Size);
      end
      else
        raise EElBuiltInCryptoProviderError.Create(SBufferTooSmall);
    end;
  end;

end;

procedure TElBuiltInElgamalPublicKeyCrypto.EncryptInit;
begin
  if not Assigned(FKeyMaterial) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);
  if not FKeyMaterial.IsPublic then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);
  SetLength(FSpool, 0);
end;

procedure TElBuiltInElgamalPublicKeyCrypto.EncryptUpdate( Buffer: pointer;
    Size: integer);
var
  OldLen: integer;
begin
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + Size);
  SBMove(Buffer^, FSpool[OldLen], Size);
end;

procedure TElBuiltInElgamalPublicKeyCrypto.EncryptFinal;
var
  RealSize : integer;
  OutSize : integer;
  TmpA, TmpB, OutBuf : ByteArray;
  M, P, G, Y, A, B : PLInt;
  PV, GV, YV : ByteArray;
begin

  LCreate(M);
  LCreate(P);
  LCreate(G);
  LCreate(Y);
  LCreate(A);
  LCreate(B);

  try
    {$ifndef SB_NO_PKIASYNC}
    if (not (KeyMaterial is TElBuiltInElgamalCryptoKey)) or
      (TElBuiltInElgamalCryptoKey(KeyMaterial).FToken = nil) then
     {$endif}
    begin
      PV := KeyMaterial.GetKeyProp(SB_KEYPROP_ELGAMAL_P, EmptyArray);
      GV := KeyMaterial.GetKeyProp(SB_KEYPROP_ELGAMAL_G, EmptyArray);
      YV := KeyMaterial.GetKeyProp(SB_KEYPROP_ELGAMAL_Y, EmptyArray);
      PointerToLInt(M, @FSpool[0], Length(FSpool));
      PointerToLInt(P, @PV[0], Length(PV));
      PointerToLInt(G, @GV[0], Length(GV));
      PointerToLInt(Y, @YV[0], Length(YV));

      SBElgamal.Encrypt(M, P, G, Y, A, B);
    {$ifndef SB_NO_PKIASYNC}
    end
    else
    begin
      try
        PointerToLInt(M, @FSpool[0], Length(FSpool));
        GetGlobalAsyncCalculator().EndElgamalEncryption(TElBuiltInElgamalCryptoKey(KeyMaterial).FToken,
          M, A, B);
      finally
        if TElBuiltInElgamalCryptoKey(KeyMaterial).FReleaseToken then
          FreeAndNil(TElBuiltInElgamalCryptoKey(KeyMaterial).FToken);
      end;
     {$endif}
    end;

    SetLength(TmpA, A.Length * 4);
    SetLength(TmpB, B.Length * 4);
    RealSize := Length(TmpA);
    LIntToPointer(A, @TmpA[0], RealSize);
    RealSize := Length(TmpB);
    LIntToPointer(B, @TmpB[0], RealSize);

    OutSize := 0;
    SBElgamal.EncodeResult(@TmpA[0], Length(TmpA), @TmpB[0], Length(TmpB), nil, OutSize);
    SetLength(OutBuf, OutSize);
    SBElgamal.EncodeResult(@TmpA[0], Length(TmpA), @TmpB[0], Length(TmpB), @OutBuf[0], OutSize);

    WriteToOutput( @OutBuf[0] , OutSize);
  finally
    LDestroy(M);
    LDestroy(P);
    LDestroy(G);
    LDestroy(Y);
    LDestroy(A);
    LDestroy(B);
  end;

end;
 {$endif SB_PGPSFX_STUB}

procedure TElBuiltInElgamalPublicKeyCrypto.DecryptInit;
begin
  if not Assigned(FKeyMaterial) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);
  if not (FKeyMaterial.IsSecret) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);
  SetLength(FSpool, 0);
end;

procedure TElBuiltInElgamalPublicKeyCrypto.DecryptUpdate( Buffer: pointer;
    Size: integer);
var
  OldLen: integer;
begin
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + Size);
  SBMove(Buffer^, FSpool[OldLen], Size);
end;

procedure TElBuiltInElgamalPublicKeyCrypto.DecryptFinal;
var
  ASize, BSize, OutSize : integer;
  TmpA, TmpB, OutBuf : ByteArray;
  M, P, G, X, A, B : PLInt;
  PV, GV, XV : ByteArray;
begin

  LCreate(M);
  LCreate(P);
  LCreate(G);
  LCreate(X);
  LCreate(A);
  LCreate(B);

  try
    PV := KeyMaterial.GetKeyProp(SB_KEYPROP_ELGAMAL_P, EmptyArray);
    GV := KeyMaterial.GetKeyProp(SB_KEYPROP_ELGAMAL_G, EmptyArray);
    XV := KeyMaterial.GetKeyProp(SB_KEYPROP_ELGAMAL_X, EmptyArray);
    PointerToLInt(M, @FSpool[0], Length(FSpool));
    PointerToLInt(P, @PV[0], Length(PV));
    PointerToLInt(G, @GV[0], Length(GV));
    PointerToLInt(X, @XV[0], Length(XV));

    ASize := 0;
    BSize := 0;
    SBElgamal.DecodeResult(@FSpool[0], Length(FSpool), nil, ASize, nil, BSize);
    SetLength(TmpA, ASize);
    SetLength(TmpB, BSize);
    SBElgamal.DecodeResult(@FSpool[0], Length(FSpool), @TmpA[0], ASize, @TmpB[0], BSize);

    PointerToLInt(A, @TmpA[0], ASize);
    PointerToLInt(B, @TmpB[0], BSize);

    SBElgamal.Decrypt(P, G, X, A, B, M);

    OutSize := M.Length * 4;
    SetLength(OutBuf, OutSize);
    LIntToPointer(M, @OutBuf[0], OutSize);
    WriteToOutput( @OutBuf[0] , OutSize);
  finally
    LDestroy(M);
    LDestroy(P);
    LDestroy(G);
    LDestroy(X);
    LDestroy(A);
    LDestroy(B);
  end;

end;

procedure TElBuiltInElgamalPublicKeyCrypto.VerifyInit(Detached: boolean;  Signature: pointer;
    SigSize: integer);
begin
  if not Assigned(FKeyMaterial) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);
  if not FKeyMaterial.IsPublic then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  SetLength(FSpool, 0);

  SetLength(FSignature, SigSize);
  SBMove(Signature^, FSignature[0], SigSize);

  if not FInputIsHash then
    FHashFunction := TElBuiltInHashFunction.Create(FHashAlgorithm);
end;

procedure TElBuiltInElgamalPublicKeyCrypto.VerifyUpdate( Buffer: pointer;  Size: integer);
var
  OldLen : integer;
begin
  if FInputIsHash then
  begin
    OldLen := Length(FSpool);
    SetLength(FSpool, OldLen + Size);
    SBMove(Buffer^, FSpool[OldLen], Size);
  end
  else
    FHashFunction.Update(Buffer, Size);
end;

function TElBuiltInElgamalPublicKeyCrypto.VerifyFinal : integer;
var
  ASize, BSize : integer;
  TmpA, TmpB : ByteArray;
  Hash : ByteArray;
  M, P, G, Y, A, B : PLInt;
  PV, GV, YV : ByteArray;
begin

  if not FInputIsHash then
  begin
    Hash := FHashFunction.Finish;
    FreeAndNil(FHashFunction);
  end
  else
  begin
    SetLength(Hash, Length(FSpool));
    SBMove(FSpool[0], Hash[0], Length(FSpool));
  end;

  LCreate(M);
  LCreate(P);
  LCreate(G);
  LCreate(Y);
  LCreate(A);
  LCreate(B);

  try
    PV := KeyMaterial.GetKeyProp(SB_KEYPROP_ELGAMAL_P, EmptyArray);
    GV := KeyMaterial.GetKeyProp(SB_KEYPROP_ELGAMAL_G, EmptyArray);
    YV := KeyMaterial.GetKeyProp(SB_KEYPROP_ELGAMAL_Y, EmptyArray);
    PointerToLInt(M, @FSpool[0], Length(FSpool));
    PointerToLInt(P, @PV[0], Length(PV));
    PointerToLInt(G, @GV[0], Length(GV));
    PointerToLInt(Y, @YV[0], Length(YV));

    ASize := 0;
    BSize := 0;
    SBElgamal.DecodeResult(@FSignature[0], Length(FSignature), nil, ASize, nil, BSize);
    SetLength(TmpA, ASize);
    SetLength(TmpB, BSize);
    if not SBElgamal.DecodeResult(@FSignature[0], Length(FSignature), @TmpA[0], ASize, @TmpB[0], BSize) then
    begin
      Result := SB_VR_INVALID_SIGNATURE;
      Exit;
    end;

    PointerToLInt(A, @TmpA[0], ASize);
    PointerToLInt(B, @TmpB[0], BSize);
    PointerToLInt(M, @Hash[0], Length(Hash));

    if SBElgamal.Verify(M, P, G, Y, A, B) then
      Result := SB_VR_SUCCESS
    else
      Result := SB_VR_INVALID_SIGNATURE;
  finally
    LDestroy(M);
    LDestroy(P);
    LDestroy(G);
    LDestroy(Y);
    LDestroy(A);
    LDestroy(B);
  end;

end;

function TElBuiltInElgamalPublicKeyCrypto.EstimateOutputSize( InBuffer: pointer;
    InSize: Int64;
  Operation : TSBBuiltInPublicKeyOperation): Int64;
var
  PLen : integer;
begin
  Result := 0;
  if KeyMaterial.Algorithm <> SB_ALGORITHM_PK_ELGAMAL then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  PLen := KeyMaterial.Bits shr 3;
  if (Operation = pkoEncrypt) and
    (InSize > PLen) then
    raise EElBuiltInCryptoProviderError.Create(SInputTooLong);

  if (Operation in [pkoEncrypt,
    pkoSignDetached]) then
    Result := PLen shl 1 + 16
  else if Operation = pkoDecrypt then
    Result := PLen
  else if Operation = pkoVerify then
    Result := 0;
end;

////////////////////////////////////////////////////////////////////////////////
// TElBuiltInDHPublicKeyCrypto class

{$ifndef SB_NO_DH}
constructor TElBuiltInDHPublicKeyCrypto.Create(const OID : ByteArray);
begin
  inherited Create;
end;

constructor TElBuiltInDHPublicKeyCrypto.Create(Alg : integer);
begin
  inherited Create;
end;

constructor TElBuiltInDHPublicKeyCrypto.Create;
begin
  inherited Create;
end;

 destructor  TElBuiltInDHPublicKeyCrypto.Destroy;
begin
  inherited;
end;

procedure TElBuiltInDHPublicKeyCrypto.EncryptInit;
begin
  if not Assigned(FKeyMaterial) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);
  if not FKeyMaterial.IsPublic then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  SetLength(FSpool, 0);
end;

procedure TElBuiltInDHPublicKeyCrypto.EncryptUpdate( Buffer: pointer;
    Size: integer);
var
  OldLen: integer;
begin
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + Size);
  SBMove(Buffer^, FSpool[OldLen], Size);
end;

procedure TElBuiltInDHPublicKeyCrypto.EncryptFinal;
var
  G, X, P, R : PLInt;
  Res : ByteArray;
  Size : integer;
  FmtSource : ByteArray;
  GV, XV, PV : ByteArray;
begin

  // if input data is empty, then using stored X value as data to be encrypted
  SetLength(FmtSource, 0);
  LCreate(G);
  LCreate(X);
  LCreate(P);
  LCreate(R);
  try
    GV := KeyMaterial.GetKeyProp(SB_KEYPROP_DH_G, EmptyArray);
    XV := KeyMaterial.GetKeyProp(SB_KEYPROP_DH_X, EmptyArray);
    PV := KeyMaterial.GetKeyProp(SB_KEYPROP_DH_P, EmptyArray);
    PointerToLInt(G, @GV[0], Length(GV));
    if Length(FSpool) <> 0 then
      PointerToLInt(X, @FSpool[0], Length(FSpool))
    else
      PointerToLInt(X, @XV[0], Length(XV));
    PointerToLInt(P, @PV[0], Length(PV));
    LMModPower(G, X, P, R);
    Size := R.Length * 4;
    SetLength(Res, Size);
    LIntToPointer(R, @Res[0], Size);
    WriteToOutput(@Res[0], Size);
  finally
    LDestroy(G);
    LDestroy(X);
    LDestroy(P);
    LDestroy(R);
  end;

end;

procedure TElBuiltInDHPublicKeyCrypto.DecryptInit;
begin
  if not Assigned(FKeyMaterial) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);
  if not FKeyMaterial.IsSecret then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  SetLength(FSpool, 0);
end;

procedure TElBuiltInDHPublicKeyCrypto.DecryptUpdate( Buffer: pointer;
    Size: integer);
var
  OldLen: integer;
begin
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + Size);
  SBMove(Buffer^, FSpool[OldLen], Size);
end;

procedure TElBuiltInDHPublicKeyCrypto.DecryptFinal;
var
  Y, X, P, R : PLInt;
  Res : ByteArray;
  Size : integer;
  FmtSource : ByteArray;
  PV, PeerYV, XV : ByteArray;
begin

  // if input data is empty, then using stored X value as encrypted data
  SetLength(FmtSource, 0);
  LCreate(Y);
  LCreate(X);
  LCreate(P);
  LCreate(R);
  try
    PV := KeyMaterial.GetKeyProp(SB_KEYPROP_DH_P, EmptyArray);
    PeerYV := KeyMaterial.GetKeyProp(SB_KEYPROP_DH_PEER_Y, EmptyArray);
    PointerToLInt(Y, @PeerYV[0], Length(PeerYV));
    if Length(FSpool) <> 0 then
      PointerToLInt(X, @FSpool[0], Length(FSpool))
    else
    begin
      XV := KeyMaterial.GetKeyProp(SB_KEYPROP_DH_X, EmptyArray);
      PointerToLInt(X, @XV[0], Length(XV));
    end;
    PointerToLInt(P, @PV[0], Length(PV));
    LMModPower(Y, X, P, R);
    Size := R.Length * 4;
    SetLength(Res, Size);
    LIntToPointer(R, @Res[0], Size);
    WriteToOutput(@Res[0], Size);
  finally
    LDestroy(Y);
    LDestroy(X);
    LDestroy(P);
    LDestroy(R);
  end;

end;

function TElBuiltInDHPublicKeyCrypto.EstimateOutputSize( InBuffer: pointer;
    InSize: Int64;
  Operation : TSBBuiltInPublicKeyOperation): Int64;
var
  PLen : integer;
begin
  PLen := KeyMaterial.Bits shr 3;
  if (Operation in [pkoVerify,
    pkoSign]) then
    raise EElBuiltInCryptoProviderError.Create(SNotASigningAlgorithm);
  if (KeyMaterial.Algorithm <> SB_ALGORITHM_PK_DH) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);
  if (Operation in [pkoEncrypt, pkoDecrypt]) and
    (InSize > PLen) then
    raise EElBuiltInCryptoProviderError.Create(SInputTooLong);
  Result := PLen;
end;

function TElBuiltInDHPublicKeyCrypto.GetSupportsEncryption: boolean;
begin
  Result := true;
end;

function TElBuiltInDHPublicKeyCrypto.GetSupportsSigning: boolean;
begin
  Result := false;
end;

procedure TElBuiltInDHPublicKeyCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if Material.Algorithm <> SB_ALGORITHM_PK_DH then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);
  FKeyMaterial := Material;
end;

class function TElBuiltInDHPublicKeyCrypto.IsAlgorithmSupported(Alg: integer): boolean;
begin
  Result := Alg = SB_ALGORITHM_PK_DH;
end;

class function TElBuiltInDHPublicKeyCrypto.IsAlgorithmSupported(const OID: ByteArray): boolean;
begin
  Result := false;
end;

class function TElBuiltInDHPublicKeyCrypto.GetName() : string;
begin
  Result := 'DH';
end;

class function TElBuiltInDHPublicKeyCrypto.GetDescription() : string;
begin
  Result := 'Implements Diffie-Hellman key exchange algorithm';
end;

procedure TElBuiltInDHPublicKeyCrypto.WriteToOutput( Buffer: pointer;
    Size: integer);
begin
  inherited WriteToOutput(Buffer, Size);
end;

procedure TElBuiltInDHPublicKeyCrypto.Reset;
begin
  inherited;
  SetLength(FSpool, 0);
end;
 {$endif SB_NO_DH}

{$ifdef SB_HAS_GOST}
////////////////////////////////////////////////////////////////////////////////
// TElBuiltInGOST94PublicKeyCrypto class

constructor TElBuiltInGOST94PublicKeyCrypto.Create(const OID : ByteArray);
begin
  inherited Create;

  if not IsAlgorithmSupported(OID) then
    raise EElBuiltInCryptoProviderError.CreateFmt(SUnsupportedAlgorithmStr, [OIDToStr(OID)]);

  FHashAlgorithm := SB_ALGORITHM_DGST_GOST_R3411_1994;
end;

constructor TElBuiltInGOST94PublicKeyCrypto.Create(Alg : integer);
begin
  inherited Create;

  if not IsAlgorithmSupported(Alg) then
    raise EElBuiltInCryptoProviderError.CreateFmt(SUnsupportedAlgorithmInt, [Alg]);

  FHashAlgorithm := SB_ALGORITHM_DGST_GOST_R3411_1994;
end;

constructor TElBuiltInGOST94PublicKeyCrypto.Create;
begin
  Create(SB_ALGORITHM_PK_GOST_R3410_1994);
end;

 destructor  TElBuiltInGOST94PublicKeyCrypto.Destroy;
begin
  if FHashFunction <> nil then
    FreeAndNil(FHashFunction);
  inherited;
end;

function TElBuiltInGOST94PublicKeyCrypto.GetSupportsEncryption: boolean;
begin
  Result := False;
end;

function TElBuiltInGOST94PublicKeyCrypto.GetSupportsSigning: boolean;
begin
  Result := true;
end;

procedure TElBuiltInGOST94PublicKeyCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if Material.Algorithm <> SB_ALGORITHM_PK_GOST_R3410_1994 then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);
  FKeyMaterial := Material;
end;

class function TElBuiltInGOST94PublicKeyCrypto.IsAlgorithmSupported(Alg: integer): boolean;
begin
  Result := (Alg = SB_ALGORITHM_PK_GOST_R3410_1994);
end;

class function TElBuiltInGOST94PublicKeyCrypto.IsAlgorithmSupported(const OID: ByteArray): boolean;
begin
  Result := false;
end;

class function TElBuiltInGOST94PublicKeyCrypto.GetName() : string;
begin
  Result := 'GOST3410_94';
end;

class function TElBuiltInGOST94PublicKeyCrypto.GetDescription() : string;
begin
  Result := 'Implements GOST 34.10-94 signing functions';
end;

procedure TElBuiltInGOST94PublicKeyCrypto.WriteToOutput( Buffer: pointer;
    Size: integer);
begin
  inherited WriteToOutput(Buffer, Size);
end;

procedure TElBuiltInGOST94PublicKeyCrypto.Reset;
begin
  inherited;
  FInputIsHash := true;
  FHashAlgorithm := SB_ALGORITHM_DGST_GOST_R3411_1994;
end;

procedure TElBuiltInGOST94PublicKeyCrypto.SignInit(Detached: boolean);
var
  Params : TElCPParameters;
begin
  if not Assigned(FKeyMaterial) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  SetLength(FSpool, 0);
  if not FInputIsHash then
  begin
    Params := TElCPParameters.Create;
    try
      Params.Add(SB_CTXPROP_GOSTR3411_1994_PARAMSET, TElBuiltInGOST341094CryptoKey(FKeyMaterial).FDigestParamSet);
      FHashFunction := TElBuiltInHashFunction.Create(FHashAlgorithm, Params);
    finally
      FreeAndNil(Params);
    end;
  end;  
end;

procedure TElBuiltInGOST94PublicKeyCrypto.SignUpdate( Buffer: pointer;
    Size: integer);
var
  OldLen : integer;
begin
  if FInputIsHash then
  begin
    OldLen := Length(FSpool);
    SetLength(FSpool, OldLen + Size);
    SBMove(Buffer^, FSpool[OldLen], Size);
  end
  else
    FHashFunction.Update(Buffer, Size);
end;

procedure TElBuiltInGOST94PublicKeyCrypto.Param_to_PLInt(const PropID: ByteArray; var Res: PLInt);
var
  V: ByteArray;
begin
  V := KeyMaterial.GetKeyProp(PropID, EmptyArray);
  PointerToLInt(Res, @V[0], Length(V));
end;

procedure TElBuiltInGOST94PublicKeyCrypto.SignFinal(Buffer: pointer; var Size: integer);
var
  SigSize : integer;
  Hash, Sig : ByteArray;
  P, Q, A, X : PLInt;
  StartIndex : integer;
begin
  try
  StartIndex := 0;
  SetLength(Sig, 0);
  if not FFinished then
  begin
    if FInputIsHash then
    begin
      SetLength(Hash, Length(FSpool));
      SBMove(FSpool, 0, Hash, 0, Length(Hash));
    end
    else
    begin
      Hash := FHashFunction.Finish;
      FreeAndNil(FHashFunction);
    end;

    Hash := ChangeByteOrder(Hash);

    LCreate(P);
    LCreate(Q);
    LCreate(A);
    LCreate(X);

    try
      Param_to_PLInt(SB_KEYPROP_GOST_R3410_1994_P, P);
      Param_to_PLInt(SB_KEYPROP_GOST_R3410_1994_Q, Q);
      Param_to_PLInt(SB_KEYPROP_GOST_R3410_1994_A, A);
      Param_to_PLInt(SB_KEYPROP_GOST_R3410_1994_X, X);
      Sig := TElGOSTSigner.Sign(Hash, P, Q, A, X);

      SigSize := Length(Sig);

      WriteToOutput( @Sig[0] , SigSize);
    finally
      LDestroy(P);
      LDestroy(Q);
      LDestroy(A);
      LDestroy(X);
    end;
    FFinished := true;
  end;
  if not FOutputIsStream then
  begin
    if Buffer = nil then
      Size := Length(FOutput)
    else
    begin
      if Size >= Length(FOutput) then
      begin
        Size := Length(FOutput);
        SBMove(FOutput, 0, Buffer, StartIndex, Size);
      end
      else
        raise EElBuiltInCryptoProviderError.Create(SBufferTooSmall);
    end;
  end;

  finally
    ReleaseArrays(Hash, Sig);
  end;
end;

procedure TElBuiltInGOST94PublicKeyCrypto.VerifyInit(Detached: boolean;  Signature: pointer;
    SigSize: integer);
var
  Params : TElCPParameters;
begin
  if not Assigned(FKeyMaterial) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);
  if not FKeyMaterial.IsPublic then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  SetLength(FSpool, 0);

  SetLength(FSignature, SigSize);
  SBMove(Signature^, FSignature[0], SigSize);

  if not FInputIsHash then
  begin
    Params := TElCPParameters.Create;
    try
      Params.Add(SB_CTXPROP_GOSTR3411_1994_PARAMSET, TElBuiltInGOST341094CryptoKey(FKeyMaterial).FDigestParamSet);
      FHashFunction := TElBuiltInHashFunction.Create(FHashAlgorithm, Params);
    finally
      FreeAndNil(Params);
    end;
  end;
end;

procedure TElBuiltInGOST94PublicKeyCrypto.VerifyUpdate( Buffer: pointer;  Size: integer);
var
  OldLen : integer;
begin
  if FInputIsHash then
  begin
    OldLen := Length(FSpool);
    SetLength(FSpool, OldLen + Size);
    SBMove(Buffer^, FSpool[OldLen], Size);
  end
  else
    FHashFunction.Update(Buffer, Size);
end;

function TElBuiltInGOST94PublicKeyCrypto.VerifyFinal : integer;
var
  Hash : ByteArray;
  P, Q, A, Y : PLInt;
begin
  try

  if not FInputIsHash then
  begin
    Hash := FHashFunction.Finish;
    FreeAndNil(FHashFunction);
  end
  else
  begin
    SetLength(Hash, Length(FSpool));
    SBMove(FSpool, 0, Hash, 0, Length(FSpool));
  end;

  Hash := ChangeByteOrder(Hash);

  LCreate(P);
  LCreate(Q);
  LCreate(A);
  LCreate(Y);

  try
    Param_to_PLInt(SB_KEYPROP_GOST_R3410_1994_P, P);
    Param_to_PLInt(SB_KEYPROP_GOST_R3410_1994_Q, Q);
    Param_to_PLInt(SB_KEYPROP_GOST_R3410_1994_A, A);
    Param_to_PLInt(SB_KEYPROP_GOST_R3410_1994_Y, Y);

    if  TElGOSTSigner.Verify(Hash, FSignature, P, Q, A, Y)  then
      Result := SB_VR_SUCCESS
    else
      Result := SB_VR_INVALID_SIGNATURE;

  finally
    LDestroy(P);
    LDestroy(Q);
    LDestroy(A);
    LDestroy(Y);
  end;

  finally
    ReleaseArray(Hash);
  end;
end;

function TElBuiltInGOST94PublicKeyCrypto.EstimateOutputSize( InBuffer: pointer;
    InSize: Int64;
  Operation : TSBBuiltInPublicKeyOperation): Int64;
var
  PLen : integer;
begin
  Result := 0;
  if KeyMaterial.Algorithm <> SB_ALGORITHM_PK_GOST_R3410_1994 then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  PLen := KeyMaterial.Bits shr 3;

  if (Operation = pkoEncrypt)   then
    Result := 0
  else if Operation = pkoSignDetached then
    Result := PLen
  else if Operation = pkoSign then
    Result := PLen
  else if Operation = pkoDecrypt then
    Result := 0
  else if Operation = pkoVerify then
    Result := 0;
end;

{$ifdef SB_HAS_ECC}
////////////////////////////////////////////////////////////////////////////////
// TElBuiltInGOST2001PublicKeyCrypto class

constructor TElBuiltInGOST2001PublicKeyCrypto.Create(const OID : ByteArray);
begin
  inherited Create;

  if not IsAlgorithmSupported(OID) then
    raise EElBuiltInCryptoProviderError.CreateFmt(SUnsupportedAlgorithmStr, [OIDToStr(OID)]);

  FHashAlgorithm := SB_ALGORITHM_DGST_GOST_R3411_1994;
end;

constructor TElBuiltInGOST2001PublicKeyCrypto.Create(Alg : integer);
begin
  inherited Create;

  if not IsAlgorithmSupported(Alg) then
    raise EElBuiltInCryptoProviderError.CreateFmt(SUnsupportedAlgorithmInt, [Alg]);

  FHashAlgorithm := SB_ALGORITHM_DGST_GOST_R3411_1994;
end;

constructor TElBuiltInGOST2001PublicKeyCrypto.Create;
begin
  Create(SB_ALGORITHM_PK_GOST_R3410_2001);
end;

 destructor  TElBuiltInGOST2001PublicKeyCrypto.Destroy;
begin
  if FHashFunction <> nil then
    FreeAndNil(FHashFunction);
  inherited;
end;

function TElBuiltInGOST2001PublicKeyCrypto.GetSupportsEncryption: boolean;
begin
  Result := true;
end;

function TElBuiltInGOST2001PublicKeyCrypto.GetSupportsSigning: boolean;
begin
  Result := true;
end;

procedure TElBuiltInGOST2001PublicKeyCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if not (Material is TElBuiltInGOST34102001CryptoKey) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  FKeyMaterial := Material;
end;

class function TElBuiltInGOST2001PublicKeyCrypto.IsAlgorithmSupported(Alg: integer): boolean;
begin
  Result := (Alg = SB_ALGORITHM_PK_GOST_R3410_2001);
end;

class function TElBuiltInGOST2001PublicKeyCrypto.IsAlgorithmSupported(const OID: ByteArray): boolean;
begin
  Result := false;
end;

class function TElBuiltInGOST2001PublicKeyCrypto.GetName() : string;
begin
  Result := 'GOST3410_2001';
end;

class function TElBuiltInGOST2001PublicKeyCrypto.GetDescription() : string;
begin
  Result := 'Implements GOST 34.10-2001 signing and key derivation functions';
end;

procedure TElBuiltInGOST2001PublicKeyCrypto.WriteToOutput( Buffer: pointer;
    Size: integer);
begin
  inherited WriteToOutput(Buffer, Size);
end;

procedure TElBuiltInGOST2001PublicKeyCrypto.Reset;
begin
  inherited;
  FInputIsHash := true;
  FHashAlgorithm := SB_ALGORITHM_DGST_GOST_R3411_1994;
end;

{ implements VKO GOST R 34.10-2001 KEK derivation algorithm, RFC 4357}
function TElBuiltInGOST2001PublicKeyCrypto.DeriveKEK : ByteArray;
var
  HashFunc : TElBuiltInHashFunction;
  Fld, RSize, SSize : integer;
  A, B, P, N, X, Y, D, KEK : ByteArray;
  UkmR, QX, QY, R, S : ByteArray;
begin
  if (Length(FUKM) <> 8) or (Length(FEphemeralKey) <> 64) then
    raise EElBuiltInCryptoProviderError.Create(SInvalidPropertyValue);

  try

  { input is ephemeral public key or other party public key }
  SetLength(QX, 32);
  SetLength(QY, 32);
  SBMove( FEphemeralKey[0], QX[0] , 32);
  SBMove( FEphemeralKey[32], QY[0] , 32);
  QX := ChangeByteOrder(QX);
  QY := ChangeByteOrder(QY);
  { ukm is stored in big-endian }
  UkmR := ChangeByteOrder(FUKM);

  { curve parameters }
  N := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_N);
  P := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_P);
  D := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_D);
  A := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_A);
  B := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_B);
  X := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_X);
  Y := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_Y);
  Fld := GetIntegerPropFromBuffer(FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_FIELD_INT));


  RSize := Length(N);
  SSize := Length(N);
  SetLength(R, RSize);
  SetLength(S, SSize);

  if not SBGOST341001.DeriveKey(@UkmR[0], Length(UkmR), @D[0], Length(D), @QX[0], Length(QX), @QY[0], Length(QY),
    @A[0], Length(A), @B[0], Length(B),
    @X[0], Length(X), @Y[0], Length(Y),
    @N[0], Length(N), @P[0], Length(P), Fld,
    @R[0], RSize, @S[0], SSize) then
    raise EElBuiltInCryptoProviderError.Create(SKEKDerivationFailed);

  SetLength(R, RSize);
  SetLength(S, SSize);
  SetLength(S, RSize + SSize);
  SBMove( R[0], S[SSize] , RSize);
  S := ChangeByteOrder(S); // the same format as in public key storage is used

  HashFunc := TElBuiltInHashFunction.Create(SB_ALGORITHM_DGST_GOST_R3411_1994);
  try
    HashFunc.SetHashFunctionProp(SB_CTXPROP_GOSTR3411_1994_PARAMSET, FKeyMaterial.GetKeyProp(SB_KEYPROP_GOST_R3410_DIGEST_PARAMSET));
    HashFunc.Update( @S[0] , Length(S));
    KEK := HashFunc.Finish;
  finally
    FreeAndNil(HashFunc);
  end;

  Result := KEK;

  finally
    ReleaseArray(A);
    ReleaseArray(B);
    ReleaseArray(P);
    ReleaseArray(N);
    ReleaseArray(X);
    ReleaseArray(Y);
    ReleaseArray(D);
    ReleaseArray(KEK);
    ReleaseArray(UkmR);
    ReleaseArray(QX);
    ReleaseArray(QY);
    ReleaseArray(R);
    ReleaseArray(S);
  end;
end;

procedure TElBuiltInGOST2001PublicKeyCrypto.SetUKM(const V : ByteArray);
begin
  FUKM := CloneArray(V);
end;

procedure TElBuiltInGOST2001PublicKeyCrypto.SetCEKMAC(const V : ByteArray);
begin
  FCEKMAC := CloneArray(V);
end;

procedure TElBuiltInGOST2001PublicKeyCrypto.SetEphemeralKey(const V : ByteArray);
begin
  FEphemeralKey := CloneArray(V);
end;

procedure TElBuiltInGOST2001PublicKeyCrypto.EncryptInit;
begin
  if not Assigned(FKeyMaterial) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);
  if not FKeyMaterial.IsSecret then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  SetLength(FSpool, 0);
end;

procedure TElBuiltInGOST2001PublicKeyCrypto.EncryptUpdate( Buffer: pointer;   Size: integer);
var
  OldLen: integer;
begin
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + Size);
  SBMove(Buffer^, FSpool[OldLen], Size);
end;

procedure TElBuiltInGOST2001PublicKeyCrypto.EncryptFinal;
var
  KEK, WCEK, MAC : ByteArray;
  WCEKSize, MACSize : integer;
begin
  if (Length(FSpool) <> 32) then
    raise EElBuiltInCryptoProviderError.Create(SInvalidPropertyValue);


  { probably we'll need predefined UKM }  
  if Length(FUKM) = 0 then
  begin
    SetLength(FUKM, 8);
    SBRndGenerate( @FUKM[0] , 8);
  end;

  KEK := DeriveKEK;

  WCEKSize := 32;
  MACSize := 4;
  SetLength(WCEK, WCEKSize);
  SetLength(MAC, MACSize);

  if not SBGOST2814789.KeyWrapCryptoPro(FUKM, FSpool, KEK, WCEK, WCEKSize, MAC, MACSize) then
    raise EElBuiltInCryptoProviderError.Create(SEncryptionFailed);

  FCEKMAC := MAC;  
  WriteToOutput( @WCEK[0] , WCEKSize);
end;

procedure TElBuiltInGOST2001PublicKeyCrypto.DecryptInit;
begin
  if not Assigned(FKeyMaterial) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);
  if not FKeyMaterial.IsSecret then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  SetLength(FSpool, 0);
end;

procedure TElBuiltInGOST2001PublicKeyCrypto.DecryptUpdate( Buffer: pointer;   Size: integer);
var
  OldLen: integer;
begin
  OldLen := Length(FSpool);
  SetLength(FSpool, OldLen + Size);
  SBMove(Buffer^, FSpool[OldLen], Size);
end;

procedure TElBuiltInGOST2001PublicKeyCrypto.DecryptFinal;
var
  KEK, CEK : ByteArray;
  CEKSize : integer;
begin
  if (Length(FCEKMAC) <> 4) or (Length(FSpool) <> 32) then
    raise EElBuiltInCryptoProviderError.Create(SInvalidPropertyValue);


  KEK := DeriveKEK;

  SetLength(CEK, 32);
  CEKSize := 32;

  if not SBGOST2814789.KeyUnwrapCryptoPro(FUKM, FSpool, KEK, FCEKMAC, CEK, CEKSize) then
    raise EElBuiltInCryptoProviderError.Create(SDecryptionFailed);

  WriteToOutput( @CEK[0] , CEKSize);
end;

procedure TElBuiltInGOST2001PublicKeyCrypto.SignInit(Detached: boolean);
var
  Params : TElCPParameters;
begin
  if not Assigned(FKeyMaterial) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);
  if not FKeyMaterial.IsSecret then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  SetLength(FSpool, 0);
  if not FInputIsHash then
  begin
    Params := TElCPParameters.Create;
    try
      Params.Add(SB_CTXPROP_GOSTR3411_1994_PARAMSET, TElBuiltInGOST34102001CryptoKey(FKeyMaterial).FDigestParamSet);
      FHashFunction := TElBuiltInHashFunction.Create(FHashAlgorithm, Params);
    finally
      FreeAndNil(Params);
    end;
  end;
end;

procedure TElBuiltInGOST2001PublicKeyCrypto.SignUpdate( Buffer: pointer;
    Size: integer);
var
  OldLen : integer;
begin
  if FInputIsHash then
  begin
    OldLen := Length(FSpool);
    SetLength(FSpool, OldLen + Size);
    SBMove(Buffer^, FSpool[OldLen], Size);
  end
  else
    FHashFunction.Update(Buffer, Size);
end;

procedure TElBuiltInGOST2001PublicKeyCrypto.SignFinal(Buffer: pointer; var Size: integer);
var
  Hash: ByteArray;
  Fld, SigSize, RSize, SSize : integer;
  Sig : ByteArray;
  A, B, P, N, X, Y, D : ByteArray;
  R, S : ByteArray;
begin

  if not FFinished then
  begin
    if FInputIsHash then
    begin
      SetLength(Hash, Length(FSpool));
      SBMove(FSpool[0], Hash[0], Length(Hash));
    end
    else
    begin
      Hash := FHashFunction.Finish;
      FreeAndNil(FHashFunction);
    end;

    Hash := ChangeByteOrder(Hash);

    N := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_N);
    P := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_P);
    D := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_D);
    A := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_A);
    B := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_B);
    X := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_X);
    Y := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_Y);
    Fld := GetIntegerPropFromBuffer(FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_FIELD_INT));

    if (Length(N) = 0) or (Length(D) = 0) or (Length(A) = 0) or (Length(B) = 0) or
      (Length(X) = 0) or (Length(Y) = 0) or (Length(P) = 0)
    then
      raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

    RSize := 0;
    SSize := 0;
    SBGOST341001.Sign(@Hash[0], Length(Hash), @D[0], Length(D), @A[0], Length(A),
      @B[0], Length(B), @X[0], Length(X), @Y[0], Length(Y), @N[0], Length(N),
      @P[0], Length(P), Fld, nil, RSize, nil, SSize);

    if (RSize = 0) or (SSize = 0) then
      raise EElBuiltInCryptoProviderError.Create(SSigningFailed);

    SetLength(R, RSize);
    SetLength(S, SSize);

    if not SBGOST341001.Sign(@Hash[0], Length(Hash), @D[0], Length(D), @A[0], Length(A),
      @B[0], Length(B), @X[0], Length(X), @Y[0], Length(Y), @N[0], Length(N),
      @P[0], Length(P), Fld, @R[0], RSize, @S[0], SSize)
    then
      raise EElBuiltInCryptoProviderError.Create(SSigningFailed);

    if (RSize = 0) or (SSize = 0) then
      raise EElBuiltInCryptoProviderError.Create(SSigningFailed);

    SigSize := 64; // 512 bits
    SetLength(Sig, SigSize);
    FillChar( Sig[0] , 64, 0);
    SBMove( S[0], Sig[32 - SSize] , SSize);
    SBMove( R[0], Sig[64 - RSize] , RSize);

    WriteToOutput( @Sig[0] , SigSize);
    FFinished := true;
  end;
  if not FOutputIsStream then
  begin
    if Buffer = nil then
      Size := Length(FOutput)
    else
    begin
      if Size >= Length(FOutput) then
      begin
        Size := Length(FOutput);
        SBMove(FOutput[0], Buffer^, Size);
      end
      else
        raise EElBuiltInCryptoProviderError.Create(SBufferTooSmall);
    end;
  end;

end;

procedure TElBuiltInGOST2001PublicKeyCrypto.VerifyInit(Detached: boolean;  Signature: pointer;
    SigSize: integer);
var
  Params : TElCPParameters;
begin
  if not Assigned(FKeyMaterial) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);
  if not FKeyMaterial.IsPublic then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  SetLength(FSpool, 0);

  SetLength(FSignature, SigSize);
  SBMove(Signature^, FSignature[0], SigSize);

  if not FInputIsHash then
  begin
    Params := TElCPParameters.Create;
    try
      Params.Add(SB_CTXPROP_GOSTR3411_1994_PARAMSET, TElBuiltInGOST34102001CryptoKey(FKeyMaterial).FDigestParamSet);
      FHashFunction := TElBuiltInHashFunction.Create(FHashAlgorithm, Params);
    finally
      FreeAndNil(Params);
    end;
  end;  
end;

procedure TElBuiltInGOST2001PublicKeyCrypto.VerifyUpdate( Buffer: pointer;  Size: integer);
var
  OldLen : integer;
begin
  if FInputIsHash then
  begin
    OldLen := Length(FSpool);
    SetLength(FSpool, OldLen + Size);
    SBMove(Buffer^, FSpool[OldLen], Size);
  end
  else
    FHashFunction.Update(Buffer, Size);
end;

function TElBuiltInGOST2001PublicKeyCrypto.VerifyFinal : integer;
var
  R, S : ByteArray;
  RSize, SSize : integer;
  Fld : integer;
  Hash : ByteArray;
  N, QX, QY, A, B, P, X, Y : ByteArray;
begin

  if not FInputIsHash then
  begin
    Hash := FHashFunction.Finish;
    FreeAndNil(FHashFunction);
  end
  else
  begin
    SetLength(Hash, Length(FSpool));
    SBMove(FSpool[0], Hash[0], Length(FSpool));
  end;

  if Length(FSignature) <> 64 then
  begin
    Result := SB_VR_INVALID_SIGNATURE;
    Exit;
  end;

  Hash := ChangeByteOrder(Hash);

  RSize := 32;
  SSize := 32;
  SetLength(R, RSize);
  SetLength(S, SSize);

  SBMove( FSignature[0], S[0] , 32);
  SBMove( FSignature[32], R[0] , 32);

  N := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_N);
  P := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_P);
  A := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_A);
  B := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_B);
  X := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_X);
  Y := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_Y);
  QX := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_QX);
  QY := FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_QY);

  Fld := GetIntegerPropFromBuffer(FKeyMaterial.GetKeyProp(SB_KEYPROP_EC_FIELD_INT));

  if (Length(QX) = 0) or (Length(QY) = 0) or (Length(N) = 0) or (Length(A) = 0) or (Length(B) = 0) or
    (Length(X) = 0) or (Length(Y) = 0) or (Length(P) = 0)
  then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  if SBGOST341001.Verify(@Hash[0], Length(Hash), @QX[0], Length(QX),
    @QY[0], Length(QY),
    @R[0], Length(R), @S[0], Length(S), @A[0], Length(A),
    @B[0], Length(B),
    @X[0], Length(X), @Y[0], Length(Y),
    @N[0], Length(N), @P[0], Length(P), Fld)
  then
    Result := SB_VR_SUCCESS
  else
    Result := SB_VR_INVALID_SIGNATURE;

end;

function TElBuiltInGOST2001PublicKeyCrypto.EstimateOutputSize( InBuffer: pointer;
    InSize: Int64;
  Operation : TSBBuiltInPublicKeyOperation): Int64;
begin
  if not (KeyMaterial is TElBuiltInGOST34102001CryptoKey) then
    raise EElBuiltInCryptoProviderError.Create(SBadKeyMaterial);

  if (Operation = pkoVerify)   then
    Result := 0
  else if Operation = pkoSignDetached then
    Result := 64
  else if Operation = pkoEncrypt then
    Result := 32
  else if Operation = pkoDecrypt then
    Result := 32
  else
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
end;

 {$endif SB_HAS_ECC}
 {$endif SB_HAS_GOST}

{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
initialization

  SB_KEYPROP_RSA_KEYFORMAT_PKCS1 := BytesOfString('pkcs#1');
  SB_KEYPROP_RSA_KEYFORMAT_OAEP := BytesOfString('oaep');
  SB_KEYPROP_RSA_KEYFORMAT_PSS := BytesOfString('pss');

 {$endif}
end.
