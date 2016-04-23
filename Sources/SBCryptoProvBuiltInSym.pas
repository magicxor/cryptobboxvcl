(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$i SecBbox.inc}

unit SBCryptoProvBuiltInSym;

interface

uses
  SBCryptoProv,
  SBCryptoProvBuiltIn,
  SBCryptoProvUtils,
  SBCryptoProvRS,
  Classes,
  SysUtils,
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBAES,
  SBBlowfish,
  SBTwofish,
  SBASN1,
  SBASN1Tree,
  SBCAST128,
  {$ifndef SB_NO_RC2}SBRC2, {$endif}
  {$ifndef SB_NO_RC4}SBRC4, {$endif}
  {$ifndef SB_NO_SEED}SBSeed, {$endif}
  {$ifndef SB_NO_RABBIT}SBRabbit, {$endif}
  {$ifndef SB_NO_DES}SBDES,  {$endif}
  {$ifndef SB_NO_CAMELLIA}SBCamellia, {$endif}
  {$ifdef SB_HAS_GOST}SBGOSTCommon, SBGOST2814789, {$endif}
  {$ifndef SB_NO_SERPENT}SBSerpent, {$endif}
  SBSHA2,
  SBConstants;

type

  TElBuiltInSymmetricCryptoKey = class(TElBuiltInCryptoKey)
  private
    FAlgorithm : integer;
  protected
    function GetBits : integer; override;
    function GetAlgorithm : integer; override;
    function GetIsPublic: boolean; override;
    function GetIsSecret: boolean; override;
    function GetIsExportable: boolean; override;
    function GetIsPersistent: boolean; override;
    function GetIsValid: boolean; override;
    function GetKeyStorage : TElCustomCryptoKeyStorage; override;
  public
    constructor Create(CryptoProvider : TElCustomCryptoProvider);  overload;  override; 
    constructor Create(CryptoProvider : TElCustomCryptoProvider;
      const AlgOID, AlgParams : ByteArray);   reintroduce;  overload; 
    {$ifndef SB_PGPSFX_STUB}
    procedure Generate(Bits : integer;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil); override;
    procedure GenerateIV(Bits : integer); virtual;
     {$endif SB_PGPSFX_STUB}
    procedure ImportPublic(Buffer: pointer; Size: integer; Params : TElCPParameters = nil); override;
    procedure ImportSecret(Buffer: pointer; Size: integer; Params : TElCPParameters = nil); override;
    procedure ExportPublic(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil); override;
    procedure ExportSecret(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil); override;
    procedure ChangeAlgorithm(Algorithm : integer); override;
    procedure Reset; override;
    function Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoKey; override;
    function ClonePublic(Params : TElCPParameters  =  nil) : TElCustomCryptoKey; override;
    procedure ClearPublic; override;
    procedure ClearSecret; override;
    function GetKeyProp(const PropID : ByteArray; const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif}  {$endif}): ByteArray; override;
    procedure SetKeyProp(const PropID : ByteArray; const Value : ByteArray); override;
    function Equals(Source : TElCustomCryptoKey; PublicOnly : boolean;
      Params : TElCPParameters  =  nil): boolean; override;
  end;

  TSBBuiltInSymmetricCryptoMode = 
    (cmDefault, cmECB, cmCBC, cmCTR, cmCFB8, cmCCM, cmGCM);

  TSBBuiltInSymmetricCipherPadding =  (cpNone, cpPKCS5);
  TSBBuiltInSymmetricCryptoOperation =  (coNone, coEncryption, coDecryption);
  TSBSymmetricCryptoProcessingFunction = procedure(Buffer, OutBuffer : pointer; Size : integer) of object;

  {.$define SB_GCM_8BIT}

  TSBGCMContext =  record
    IV0, IV1, IV2, IV3 : cardinal;
    H0, H1 : UInt64;
    Y0, Y1 : UInt64;
    Ctr0, Ctr1 : UInt64;
    ASize : UInt64;
    PSize : UInt64;
    {$ifdef SB_GCM_8BIT}
    HTable : array  [0..511]  of UInt64;
     {$else}
    HTable : array  [0..31]  of UInt64;
     {$endif}
  end;

  TElBuiltInSymmetricCrypto = class
  protected
    FKeyMaterial : TElCustomCryptoKey;
    FMode : TSBBuiltInSymmetricCryptoMode;
    FAssociatedData : boolean; // we are working with associated data or payload data, for AEAD only
    FNonce : ByteArray;
    FGCMCtx : TSBGCMContext;
    FGCMH : ByteArray; // GCM GHASH key
    FAEADY : ByteArray; // GCM/CCM current 'hash' value
    FAEADCtr0 : ByteArray; // GCM/CCM start counter, current coutner is stored in FVector
    FAEADASize : Int64; // processed associated data size
    FAEADPSize : Int64; // processed payload (encrypted) data size
    FAssociatedDataSize : Int64; // total associated data size, it needs to be known before CCM encryption
    FPayloadSize : Int64; // total payload data size, it needs to be known before CCM encryption
    FTagSize : integer; // length of AEAD authentication tag
    FOperation : TSBBuiltInSymmetricCryptoOperation;
    FCTRLittleEndian : boolean;
    FInternalEncryptFunction : TSBSymmetricCryptoProcessingFunction;
    FInternalDecryptFunction : TSBSymmetricCryptoProcessingFunction;

    FKeySize : integer;
    FBlockSize : integer;
    FPadding : TSBBuiltInSymmetricCipherPadding;
    FVector : ByteArray;
    FBytesLeft : integer;
    FTail : ByteArray;
    FPadBytes : ByteArray;
    FOID : ByteArray;
    FOnProgress : TSBProgressEvent;
  protected
    function DoProgress(Total, Current : Int64): boolean;
    procedure SetKeyMaterial(Material : TElCustomCryptoKey); virtual;
    procedure SetAssociatedData(Value : boolean);
    function AddPadding(Block : pointer; Size : integer) : ByteArray;
    function EstimatedOutputSize(InputSize : integer; Encrypt : boolean) : integer;
    procedure SetNonce(const V : ByteArray);

    procedure BlockToUInts8(const Buf : ByteArray;  var  B0, B1 : cardinal);
    procedure BlockToUints16(const Buf : ByteArray;  var  B0, B1, B2, B3 : cardinal);
    procedure UIntsToBlock8(const B0, B1 : cardinal; Buf : ByteArray);
    procedure UIntsToBlock16(const B0, B1, B2, B3 : cardinal; Buf : ByteArray);
    procedure IncrementCounter8(var C0, C1 : cardinal);
    procedure IncrementCounter16(var C0, C1, C2, C3 : cardinal);
    procedure EncryptBlock8(var B0, B1 : cardinal); virtual;
    procedure EncryptBlock16(var B0, B1, B2, B3 : cardinal); virtual;
    procedure EncryptBlock(var B : UInt64);  overload; 
    procedure EncryptBlock(var B0, B1 : UInt64);  overload; 
    procedure DecryptBlock8(var B0, B1 : cardinal); virtual;
    procedure DecryptBlock16(var B0, B1, B2, B3 : cardinal); virtual;
    procedure EncryptBlockArr(const Src : ByteArray; var Dest : ByteArray);
    procedure DecryptBlockArr(const Src : ByteArray; var Dest : ByteArray);
    procedure GHASHInit;
    procedure GHASHUpdate(const Buf : ByteArray);

    procedure InternalEncryptInit; // initialize InternalEncrypt - setup FInternalEncryptFunction
    procedure InternalEncryptECB8(Buffer, OutBuffer : pointer; Size : integer); virtual; // ECB mode for 64 bit block cipher
    procedure InternalEncryptECB16(Buffer, OutBuffer : pointer; Size : integer); virtual; // ECB mode for 128 bit block cipher
    procedure InternalEncryptCBC8(Buffer, OutBuffer : pointer; Size : integer); virtual; // CBC mode for 64 bit block cipher
    procedure InternalEncryptCBC16(Buffer, OutBuffer : pointer; Size : integer); virtual; // CBC mode for 128 bit block cipher
    procedure InternalEncryptCTR8(Buffer, OutBuffer : pointer; Size : integer); virtual; // CTR mode for 64 bit block cipher
    procedure InternalEncryptCTR16(Buffer, OutBuffer : pointer; Size : integer); virtual; // CTR mode for 128 bit block cipher
    procedure InternalEncryptCFB88(Buffer, OutBuffer : pointer; Size : integer); virtual; // CFB mode for 64 bit block cipher
    procedure InternalEncryptCFB816(Buffer, OutBuffer : pointer; Size : integer); virtual; // CFB mode for 128 bit block cipher
    procedure InternalEncryptGCM(Buffer, OutBuffer : pointer; Size : integer); virtual; // AEAD-GCM mode, only for 128 bit block cipher
    procedure InternalEncryptCCM(Buffer, OutBuffer : pointer; Size : integer); virtual; // AEAD-CCM mode, only for 128 bit block cipher

    procedure InternalDecryptInit; // initialize InternalDecrypt - setup FInternalDecryptFunction
    procedure InternalDecryptECB8(Buffer, OutBuffer : pointer; Size : integer); virtual;
    procedure InternalDecryptECB16(Buffer, OutBuffer : pointer; Size : integer); virtual;
    procedure InternalDecryptCBC8(Buffer, OutBuffer : pointer; Size : integer); virtual;
    procedure InternalDecryptCBC16(Buffer, OutBuffer : pointer; Size : integer); virtual;
    procedure InternalDecryptCFB88(Buffer, OutBuffer : pointer; Size : integer); virtual;
    procedure InternalDecryptCFB816(Buffer, OutBuffer : pointer; Size : integer); virtual;
    procedure InternalDecryptGCM(Buffer, OutBuffer : pointer; Size : integer); virtual;
    procedure InternalDecryptCCM(Buffer, OutBuffer : pointer; Size : integer); virtual;

    procedure EncryptStreamBlock(Buffer, OutBuffer : pointer; Size : integer); virtual;
    procedure DecryptStreamBlock(Buffer, OutBuffer : pointer; Size : integer); virtual;

    procedure ExpandKeyForEncryption; virtual;
    procedure ExpandKeyForDecryption; virtual;
    procedure InitializeGCM; virtual;
    procedure InitializeCCM; virtual;

    class function IsAlgorithmSupported(AlgID : integer) : boolean;  overload;  virtual;
    class function IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;  overload;  virtual;
    class function StreamCipher : boolean; virtual;
    function GetIsStreamCipher : boolean; virtual;
    class procedure GetDefaultKeyAndBlockLengths(AlgID : integer; var KeyLen : integer;
      var BlockLen : integer);  overload;  virtual;
    class procedure GetDefaultKeyAndBlockLengths(const OID : ByteArray; var KeyLen : integer;
      var BlockLen : integer);  overload;  virtual;

  public
    constructor Create(AlgID : integer;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  virtual;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  virtual;
    constructor Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  virtual;
     destructor  Destroy; override;

    procedure InitializeEncryption; virtual;
    procedure InitializeDecryption; virtual;
    procedure Encrypt(InBuffer: pointer; InSize : integer; OutBuffer: pointer;
      var OutSize : integer); overload;
    procedure Encrypt(InStream, OutStream: TStream); overload;
    procedure EncryptUpdate(InBuffer: pointer; InSize : integer; OutBuffer: pointer;
      var OutSize : integer);
    procedure FinalizeEncryption(OutBuffer : pointer; var OutSize : integer); virtual;
    procedure Decrypt(InBuffer: pointer; InSize : integer; OutBuffer: pointer;
      var OutSize : integer); overload;
    procedure Decrypt(InStream, OutStream: TStream; InCount: integer = 0); overload;
    procedure DecryptUpdate(InBuffer: pointer; InSize : integer; OutBuffer: pointer;
      var OutSize : integer); overload;
    procedure FinalizeDecryption(OutBuffer : pointer; var OutSize : integer); virtual;
    property KeyMaterial : TElCustomCryptoKey read FKeyMaterial write SetKeyMaterial;
    property AssociatedData : boolean read FAssociatedData write SetAssociatedData;
    property AssociatedDataSize : Int64 read FAssociatedDataSize write FAssociatedDataSize;
    property PayloadSize : Int64 read FPayloadSize write FPayloadSize;
    property Nonce : ByteArray read FNonce write SetNonce;
    property TagSize : integer read FTagSize write FTagSize;
    property Mode : TSBBuiltInSymmetricCryptoMode read FMode;
    property BlockSize : integer read FBlockSize;
    property KeySize : integer read FKeySize;
    property Padding : TSBBuiltInSymmetricCipherPadding read FPadding write FPadding;
    property CTRLittleEndian : boolean read FCTRLittleEndian write FCTRLittleEndian;
    property IsStreamCipher : boolean read GetIsStreamCipher;
    property OnProgress : TSBProgressEvent read FOnProgress write FOnProgress;
  end;

  TElBuiltInSymmetricCryptoClass =  class of TElBuiltInSymmetricCrypto;

  TElBuiltInSymmetricCryptoFactory = class
  protected
    FRegisteredClasses:   TElList;  
    procedure RegisterDefaultClasses; virtual;
    function GetRegisteredClass(Index: integer) : TElBuiltInSymmetricCryptoClass;
    function GetRegisteredClassCount: integer;
  public
    constructor Create;
     destructor  Destroy; override;
    procedure RegisterClass(Cls : TElBuiltInSymmetricCryptoClass);
    function CreateInstance(const OID : ByteArray;
      Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault):
      TElBuiltInSymmetricCrypto;  overload; 
    function CreateInstance(Alg : integer;
      Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault):
      TElBuiltInSymmetricCrypto;  overload; 
    function IsAlgorithmSupported(const OID : ByteArray): boolean;  overload; 
    function IsAlgorithmSupported(Alg : integer): boolean;  overload; 
    function GetDefaultKeyAndBlockLengths(Alg : integer; var KeyLen : integer;
      var BlockLen : integer): boolean;  overload; 
    function GetDefaultKeyAndBlockLengths(const OID: ByteArray; var KeyLen : integer;
      var BlockLen : integer): boolean;  overload; 
    property RegisteredClasses[Index: integer] : TElBuiltInSymmetricCryptoClass
      read GetRegisteredClass;
    property RegisteredClassCount : integer read GetRegisteredClassCount;
  end;

  TElBuiltInIdentitySymmetricCrypto = class(TElBuiltInSymmetricCrypto)
  protected
    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;

    procedure EncryptStreamBlock(Buffer, OutBuffer : pointer; Size : integer); override;
    procedure DecryptStreamBlock(Buffer, OutBuffer: pointer; Size : integer); override;
    procedure ExpandKeyForEncryption; override;
    procedure ExpandKeyForDecryption; override;

    class function StreamCipher : boolean; override;
    class function IsAlgorithmSupported(AlgID : integer) : boolean;  overload;  override;
    class function IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(AlgID : integer; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(const OID : ByteArray; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
  public
    constructor Create(AlgID : integer;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
  end;

  {$ifndef SB_NO_RC4}
  TElBuiltInRC4SymmetricCrypto = class(TElBuiltInSymmetricCrypto)
  protected
    FSkipKeyStreamBytes : integer;
    FContext : TRC4Context;
    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;
    procedure EncryptStreamBlock(Buffer, OutBuffer : pointer; Size : integer); override;
    procedure DecryptStreamBlock(Buffer, OutBuffer: pointer; Size : integer); override;
    procedure ExpandKeyForEncryption; override;
    procedure ExpandKeyForDecryption; override;

    class function StreamCipher : boolean; override;
    class function IsAlgorithmSupported(AlgID : integer) : boolean;  overload;  override;
    class function IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(AlgID : integer; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(const OID : ByteArray; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
  public
    constructor Create(AlgID : integer;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;

    procedure InitializeEncryption; override;
    procedure InitializeDecryption; override;

    property SkipKeystreamBytes : integer read FSkipKeystreamBytes
      write FSkipKeystreamBytes;
  end;
   {$endif}

  {$ifdef SB_HAS_GOST}
  TElBuiltInGOST28147SymmetricCrypto = class(TElBuiltInSymmetricCrypto)
  protected
    fGOST: TElGOST;
    FProcessedBlocks : integer;
    FUseKeyMeshing : boolean;
    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;
    procedure DoKeyMeshing(var IV0, IV1 : cardinal);    
    procedure EncryptBlock8(var B0, B1 : cardinal); override;
    procedure DecryptBlock8(var B0, B1 : cardinal); override;
    procedure ExpandKeyForEncryption; override;
    procedure ExpandKeyForDecryption; override;

    class function IsAlgorithmSupported(AlgID : integer) : boolean;  overload;  override;
    class function IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(AlgID : integer; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(const OID : ByteArray; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
    procedure InitializeCipher();
    procedure SetParamSet(const Value : ByteArray);
    procedure SetSBoxes(const Value : ByteArray);
  public
     destructor  Destroy; override;
  
    constructor Create(AlgID : integer;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;

    property ParamSet : ByteArray write SetParamSet;
    property SBoxes : ByteArray write SetSBoxes;
    property UseKeyMeshing : boolean read FUseKeyMeshing write FUseKeyMeshing;
  end;
   {$endif SB_HAS_GOST}

  EElSymmetricCryptoError =  class(ESecureBlackboxError);

const
  SYMMETRIC_BLOCK_SIZE = 16384;
  SYMMETRIC_DEFAULT_MODE = cmCBC;

implementation

uses
  SBRandom;

type
  TElBuiltInAESSymmetricCrypto = class(TElBuiltInSymmetricCrypto)
  protected
    FKey128 : TAESExpandedKey128;
    FKey192 : TAESExpandedKey192;
    FKey256 : TAESExpandedKey256;

    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;
    procedure EncryptBlock16(var B0, B1, B2, B3 : cardinal); override;
    procedure DecryptBlock16(var B0, B1, B2, B3 : cardinal); override;
    procedure ExpandKeyForEncryption; override;
    procedure ExpandKeyForDecryption; override;

    class function IsAlgorithmSupported(AlgID : integer) : boolean;  overload;  override;
    class function IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(AlgID : integer; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(const OID : ByteArray; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;

  public
    constructor Create(AlgID : integer;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
  end;

  TElBuiltInBlowfishSymmetricCrypto = class(TElBuiltInSymmetricCrypto)
  protected
    FContext : TSBBlowfishContext;

    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;
    procedure EncryptBlock8(var B0, B1 : cardinal); override;
    procedure DecryptBlock8(var B0, B1 : cardinal); override;
    procedure ExpandKeyForEncryption; override;
    procedure ExpandKeyForDecryption; override;

    class function IsAlgorithmSupported(AlgID : integer) : boolean;  overload;  override;
    class function IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(AlgID : integer; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(const OID : ByteArray; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
  public
    constructor Create(AlgID : integer;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
  end;

  TElBuiltInTwofishSymmetricCrypto = class(TElBuiltInSymmetricCrypto)
  protected
    FKey : TTwofishExpandedKey;

    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;
    procedure EncryptBlock16(var B0, B1, B2, B3 : cardinal); override;
    procedure DecryptBlock16(var B0, B1, B2, B3 : cardinal); override;
    procedure ExpandKeyForEncryption; override;
    procedure ExpandKeyForDecryption; override;
    
    class function IsAlgorithmSupported(AlgID : integer) : boolean;  overload;  override;
    class function IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(AlgID : integer; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(const OID : ByteArray; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
  public
    constructor Create(AlgID : integer;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
  end;

  TElBuiltInCAST128SymmetricCrypto = class(TElBuiltInSymmetricCrypto)
  protected
    FKey : TCAST128ExpandedKey;
    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;
    procedure EncryptBlock8(var B0, B1 : cardinal); override;
    procedure DecryptBlock8(var B0, B1 : cardinal); override;
    procedure ExpandKeyForEncryption; override;
    procedure ExpandKeyForDecryption; override;
    
    class function IsAlgorithmSupported(AlgID : integer) : boolean;  overload;  override;
    class function IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(AlgID : integer; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(const OID : ByteArray; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
  public
    constructor Create(AlgID : integer;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
  end;

  {$ifndef SB_NO_RC2}
  TElBuiltInRC2SymmetricCrypto = class(TElBuiltInSymmetricCrypto)
  protected
    FKey : TRC2ExpandedKey;
    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;
    procedure EncryptBlock8(var B0, B1 : cardinal); override;
    procedure DecryptBlock8(var B0, B1 : cardinal); override;
    procedure ExpandKeyForEncryption; override;
    procedure ExpandKeyForDecryption; override;

    class function IsAlgorithmSupported(AlgID : integer) : boolean;  overload;  override;
    class function IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(AlgID : integer; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(const OID : ByteArray; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
  public
    constructor Create(AlgID : integer;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
  end;
   {$endif}

  {$ifndef SB_NO_DES}
  TElBuiltInDESSymmetricCrypto = class(TElBuiltInSymmetricCrypto)
  protected
    FKey : TDESExpandedKey;
    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;
    procedure EncryptBlock8(var B0, B1 : cardinal); override;
    procedure DecryptBlock8(var B0, B1 : cardinal); override;
    procedure ExpandKeyForEncryption; override;
    procedure ExpandKeyForDecryption; override;
    
    class function IsAlgorithmSupported(AlgID : integer) : boolean;  overload;  override;
    class function IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(AlgID : integer; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(const OID : ByteArray; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
  public
    constructor Create(AlgID : integer;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
  end;

  TElBuiltIn3DESSymmetricCrypto = class(TElBuiltInSymmetricCrypto)
  protected
    FKey1, FKey2, FKey3 : TDESExpandedKey;

    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;
    procedure EncryptBlock8(var B0, B1 : cardinal); override;
    procedure DecryptBlock8(var B0, B1 : cardinal); override;
    procedure ExpandKeyForEncryption; override;
    procedure ExpandKeyForDecryption; override;
    
    class function IsAlgorithmSupported(AlgID : integer) : boolean;  overload;  override;
    class function IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(AlgID : integer; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(const OID : ByteArray; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
  public
    constructor Create(AlgID : integer;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
  end;
   {$endif}

  {$ifndef SB_NO_CAMELLIA}
  TElBuiltInCamelliaSymmetricCrypto = class(TElBuiltInSymmetricCrypto)
  protected
    FKey : TSBCamelliaExpandedKey;

    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;
    procedure EncryptBlock16(var B0, B1, B2, B3 : cardinal); override;
    procedure DecryptBlock16(var B0, B1, B2, B3 : cardinal); override;
    procedure ExpandKeyForEncryption; override;
    procedure ExpandKeyForDecryption; override;
    
    class function IsAlgorithmSupported(AlgID : integer) : boolean;  overload;  override;
    class function IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(AlgID : integer; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(const OID : ByteArray; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
  public
    constructor Create(AlgID : integer;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
  end;
   {$endif}

  {$ifndef SB_NO_SERPENT}
  TElBuiltInSerpentSymmetricCrypto = class(TElBuiltInSymmetricCrypto)
  protected
    FKey : {$ifndef B_X}TSerpentExpandedKey {$else}TSerpentExpandedKeyEx {$endif};

    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;
    procedure EncryptBlock16(var B0, B1, B2, B3 : cardinal); override;
    procedure DecryptBlock16(var B0, B1, B2, B3 : cardinal); override;
    procedure ExpandKeyForEncryption; override;
    procedure ExpandKeyForDecryption; override;
    
    class function IsAlgorithmSupported(AlgID : integer) : boolean;  overload;  override;
    class function IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(AlgID : integer; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(const OID : ByteArray; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
  public
    constructor Create(AlgID : integer;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
  end;
   {$endif SB_NO_SERPENT}

  {$ifndef SB_NO_SEED}
  TElBuiltInSEEDSymmetricCrypto = class(TElBuiltInSymmetricCrypto)
  protected
    FKey : TSEEDKey;
    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;
    procedure EncryptBlock16(var B0, B1, B2, B3 : cardinal); override;
    procedure DecryptBlock16(var B0, B1, B2, B3 : cardinal); override;
    procedure ExpandKeyForEncryption; override;
    procedure ExpandKeyForDecryption; override;
    
    class function IsAlgorithmSupported(AlgID : integer) : boolean;  overload;  override;
    class function IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(AlgID : integer; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(const OID : ByteArray; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
  public
    constructor Create(AlgID : integer;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
  end;
   {$endif}

  {$ifndef SB_NO_RABBIT}
  TElBuiltInRabbitSymmetricCrypto = class(TElBuiltInSymmetricCrypto)
  protected
    FContext : Rabbit_Context;
    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;
    procedure EncryptBlock16(var B0, B1, B2, B3 : cardinal); override;
    procedure DecryptBlock16(var B0, B1, B2, B3 : cardinal); override;
    procedure ExpandKeyForEncryption; override;
    procedure ExpandKeyForDecryption; override;
    
    class function IsAlgorithmSupported(AlgID : integer) : boolean;  overload;  override;
    class function IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(AlgID : integer; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(const OID : ByteArray; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
  public
    constructor Create(AlgID : integer;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
  end;
   {$endif}

////////////////////////////////////////////////////////////////////////////////
// AEAD GCM/CCM helper functions
procedure GCMInc32(var Buffer, OutBuffer : ByteArray);  overload; 
var
  i : integer;
  C : cardinal;
begin
  if (Length(Buffer) < 4) or (Length(OutBuffer) <> Length(Buffer)) then
    Exit;

  C := Buffer[15] + Buffer[14] shl 8 + Buffer[13] shl 16 + Buffer[12] shl 24 + 1;

  GetBytes32(C, OutBuffer, 12);
  (*
  OutBuffer[15] := C and $ff;
  OutBuffer[14] := (C shr 8) and $ff;
  OutBuffer[13] := (C shr 16) and $ff;
  OutBuffer[12] := (C shr 24) and $ff;
  *)
  if Buffer <> OutBuffer then
    for i := 0 to 11 do
      OutBuffer[i] := Buffer[i];
end;

procedure CCMInc24(var Buffer, OutBuffer : ByteArray);
var
  i : integer;
  C : cardinal;
begin
  if (Length(Buffer) <> 16) or (Length(OutBuffer) <> Length(Buffer)) then
    Exit;

  C := Buffer[15] or (Buffer[14] shl 8) or (Buffer[13] shl 16) + 1;
  OutBuffer[15] := C and $ff;
  OutBuffer[14] := (C shr 8) and $ff;
  OutBuffer[13] := (C shr 16) and $ff;

  if Buffer <> OutBuffer then
    for i := 0 to 12 do
      OutBuffer[i] := Buffer[i];
end;

function BitCount(A : Int64) : integer;
begin
  Result := 0;
  while (A > 0) do
  begin
    A := A shr 1;
    Inc(Result);
  end;
end;


////////////////////////////////////////////////////////////////////////////////
// TElBuiltInSymmetricCryptoKey class

constructor TElBuiltInSymmetricCryptoKey.Create(CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
  FAlgorithm := 0;
end;

constructor TElBuiltInSymmetricCryptoKey.Create(CryptoProvider : TElCustomCryptoProvider;
  const AlgOID, AlgParams : ByteArray);
var
  AlgKeyLen : integer;
  AlgIV : ByteArray;
begin
  inherited Create(CryptoProvider);
  FAlgorithm := GetAlgorithmByOID(AlgOID);
  // processing algorithm parameters
  if ExtractSymmetricCipherParams(AlgOID, AlgParams, AlgKeyLen, AlgIV) then
    IV := AlgIV;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInSymmetricCryptoKey.Generate(Bits : integer;
  Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil);
var
  FKey : ByteArray;
begin
  if Bits mod 8 <> 0 then
    raise EElSymmetricCryptoError.Create(SInvalidInputSize);

  SetLength(FKey, Bits shr 3);
  SBRandom.SBRndGenerate(@FKey[0], Bits shr 3);
  Value := FKey;
end;

procedure TElBuiltInSymmetricCryptoKey.GenerateIV(Bits : integer);
var
  FIV : ByteArray;
begin
  if Bits mod 8 <> 0 then
    raise EElSymmetricCryptoError.Create(SInvalidInputSize);

  SetLength(FIV, Bits shr 3);
  SBRandom.SBRndGenerate(@FIV[0], Bits shr 3);
  IV := FIV;
end;
 {$endif SB_PGPSFX_STUB}

{ Save/Load routines }
{ format : <word algorithm><word KeySize><key><word IVsize><IV><SHA-256 hash of all previous data>
  all numbers are big-endian }

procedure TElBuiltInSymmetricCryptoKey.ImportPublic(Buffer : pointer; Size : integer;
  Params : TElCPParameters = nil);
var
  MinSize, MaxSize, NeedIVSize : integer;
  Alg : word;
  KeySize, IVSize : integer;
  Hash, OrigHash : TMessageDigest256;
  FKey, FIV : ByteArray;
begin
  if Size < 38 then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);


  Alg := PByteArray(Buffer)^[0] shl 8 + PByteArray(Buffer)^[1];
  KeySize := PByteArray(Buffer)^[2] shl 8 + PByteArray(Buffer)^[3];

  if (Size < 38 + KeySize) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  MinSize := 1;
  MaxSize := 56;
  NeedIVSize := 0;

  case Alg of
    SB_ALGORITHM_CNT_RC4 :
      begin
        MinSize := 1;
        MaxSize := 32;
        NeedIVSize := 0;
      end;
    SB_ALGORITHM_CNT_DES :
      begin
        MinSize := 8;
        MaxSize := 8;
        NeedIVSize := 8;
      end;
    SB_ALGORITHM_CNT_3DES :
      begin
        MinSize := 24;
        MaxSize := 24;
        NeedIVSize := 8;
      end;
    SB_ALGORITHM_CNT_RC2 :
      begin
        MinSize := 1;
        MaxSize := 16;
        NeedIVSize := 8;
      end;
    SB_ALGORITHM_CNT_AES128 :
      begin
        MinSize := 16;
        MaxSize := 16;
        NeedIVSize := 16;        
      end;
    SB_ALGORITHM_CNT_AES192 :
      begin
        MinSize := 24;
        MaxSize := 24;
        NeedIVSize := 16;
      end;
    SB_ALGORITHM_CNT_AES256 :
      begin
        MinSize := 32;
        MaxSize := 32;
        NeedIVSize := 16;        
      end;
    SB_ALGORITHM_CNT_BLOWFISH :
      begin
        MinSize := 4;
        MaxSize := 56;
        NeedIVSize := 8;        
      end;
    SB_ALGORITHM_CNT_TWOFISH :
      begin
        MinSize := 16;
        MaxSize := 32;
        NeedIVSize := 16;
      end;
    SB_ALGORITHM_CNT_CAMELLIA :
      begin
        MinSize := 16;
        MaxSize := 32;
        NeedIVSize := 16;
      end;
    SB_ALGORITHM_CNT_CAST128 :
      begin
        MinSize := 16;
        MaxSize := 16;
        NeedIVSize := 8;
      end;
    SB_ALGORITHM_CNT_IDEA :
      begin
        MinSize := 16;
        MaxSize := 16;
        NeedIVSize := 8;
      end;
    SB_ALGORITHM_CNT_SERPENT :
      begin
        MinSize := 16;
        MaxSize := 32;
        NeedIVSize := 16;
      end;    
   end;

   if (KeySize < MinSize) or (KeySize > MaxSize) then
     raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

   IVSize := PByteArray(Buffer)^[4 + KeySize] shl 8 + PByteArray(Buffer)^[5 + KeySize];

   if ((IVSize <> NeedIVSize) and (IVSize <> 0)) or (Size < 38 + KeySize + IVSize) then
     raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

   SBMove(PByteArray(Buffer)^[6 + KeySize + IVSize], Hash, 32);
   OrigHash := SBSHA2.HashSHA256(Buffer, 6 + KeySize + IVSize);

   if not CompareMem(@Hash, @OrigHash, 32) then
     raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

   FAlgorithm := Alg;

   SetLength(FKey, KeySize);
   SetLength(FIV, IVSize);

   SBMove(PByteArray(Buffer)^[4], FKey[0], KeySize);
   SBMove(PByteArray(Buffer)^[6 + KeySize], FIV[0], IVSize);
   Value := FKey;
   IV := FIV;

end;

procedure TElBuiltInSymmetricCryptoKey.ImportSecret(Buffer: pointer; Size: integer; Params : TElCPParameters = nil);
begin
  ImportPublic(Buffer, Size, Params);
end;

procedure TElBuiltInSymmetricCryptoKey.ExportPublic(Buffer : pointer; var Size : integer;
  Params : TElCPParameters = nil);
var
  KeySize, IVSize : integer;
  Hash : TMessageDigest256;
begin

  if Size <  38 + Length(Value) + Length(IV) then
  begin
    if Size = 0 then
    begin
      Size := 38 + Length(Value) + Length(IV);
      Exit
    end
    else
      raise EElSymmetricCryptoError.Create(SBufferTooSmall);
  end
  else
    Size := 38 + Length(Value) + Length(IV);

  KeySize := Length(Value);
  IVSize := Length(IV);

  PByteArray(Buffer)^[0] := (FAlgorithm shr 8) and $ff;
  PByteArray(Buffer)^[1] := FAlgorithm and $ff;
  PByteArray(Buffer)^[2] := (KeySize shr 8) and $ff;
  PByteArray(Buffer)^[3] := KeySize and $ff;

  SBMove(Value[0], PByteArray(Buffer)^[4], KeySize);
  PByteArray(Buffer)^[4 + KeySize] := (IVSize shr 8) and $ff;
  PByteArray(Buffer)^[5 + KeySize] := IVSize and $ff;
  SBMove(IV[0], PByteArray(Buffer)^[6 + KeySize], IVSize);

  Hash := SBSHA2.HashSHA256(Buffer, Size - 32);
  SBMove(Hash, PByteArray(Buffer)^[6 + KeySize + IVSize], 32);

end;

procedure TElBuiltInSymmetricCryptoKey.ExportSecret(Buffer: pointer; var Size: integer;
  Params : TElCPParameters = nil);
begin
  ExportPublic(Buffer, Size, Params);
end;

function TElBuiltInSymmetricCryptoKey.GetBits : integer;
begin
  Result := Length(Value) shl 3;
end;

function TElBuiltInSymmetricCryptoKey.GetAlgorithm : integer;
begin
  Result := FAlgorithm;
end;

function TElBuiltInSymmetricCryptoKey.GetIsPublic: boolean;
begin
  Result := true;
end;

function TElBuiltInSymmetricCryptoKey.GetIsSecret: boolean;
begin
  Result := true;
end;

function TElBuiltInSymmetricCryptoKey.GetIsExportable: boolean;
begin
  Result := true;
end;

function TElBuiltInSymmetricCryptoKey.GetIsPersistent: boolean;
begin
  Result := false;
end;

function TElBuiltInSymmetricCryptoKey.GetIsValid: boolean;
begin
  Result := true;
end;

function TElBuiltInSymmetricCryptoKey.GetKeyStorage : TElCustomCryptoKeyStorage;
begin
  Result := nil;
end;

procedure TElBuiltInSymmetricCryptoKey.Reset;
begin
  FMode := 0;
  SetLength(FIV, 0);
  SetLength(FValue, 0);
end;

function TElBuiltInSymmetricCryptoKey.Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoKey;
begin
  if not (FCryptoProvider is TElBuiltInCryptoProvider) then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedCryptoProvider);
  Result := TElBuiltInSymmetricCryptoKey.Create(FCryptoProvider);
  TElBuiltInSymmetricCryptoKey(Result).Mode := FMode;
  TElBuiltInSymmetricCryptoKey(Result).IV := FIV;
  TElBuiltInSymmetricCryptoKey(Result).Value := FValue;
end;

function TElBuiltInSymmetricCryptoKey.Equals(Source : TElCustomCryptoKey; PublicOnly : boolean;
      Params : TElCPParameters  =  nil): boolean;
var
  B : ByteArray;
begin
  Result := false;
  SetLength(B, 0);
  if Self.Algorithm <> Source.Algorithm then exit;
  Result := true;
  B := TElBuiltInSymmetricCryptoKey(Source).Value;
  Result := Result and (Length(B) = Length(FValue)) and
     (CompareMem(@FValue[0], @B[0], Length(FValue)))
     ;
  B := TElBuiltInSymmetricCryptoKey(Source).IV;
  Result := Result and (Length(B) = Length(FIV)) and
     (CompareMem(@FIV[0], @B[0], Length(FIV)))
     ;
  ReleaseArray(B);
end;

function TElBuiltInSymmetricCryptoKey.ClonePublic(Params : TElCPParameters  =  nil) : TElCustomCryptoKey;
begin
  Result := Clone(Params);
end;

function TElBuiltInSymmetricCryptoKey.GetKeyProp(const PropID : ByteArray;
  const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif}  {$endif}): ByteArray;
begin
  Result := EmptyArray;
end;

procedure TElBuiltInSymmetricCryptoKey.SetKeyProp(const PropID : ByteArray; const Value : ByteArray);
begin
  ;
end;

procedure TElBuiltInSymmetricCryptoKey.ChangeAlgorithm(Algorithm : integer);
begin
  FAlgorithm := Algorithm;
end;

procedure TElBuiltInSymmetricCryptoKey.ClearPublic;
begin
  ;
end;

procedure TElBuiltInSymmetricCryptoKey.ClearSecret;
begin
  ;
end;

////////////////////////////////////////////////////////////////////////////////
// TElBuiltInSymmetricCrypto class

constructor TElBuiltInSymmetricCrypto.Create(AlgID : integer;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  inherited Create; //.NET cannot compile without this line
  raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmInt, [AlgID]));
end;

constructor TElBuiltInSymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  inherited Create;
  raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]));
end;

constructor TElBuiltInSymmetricCrypto.Create(Mode : TSBBuiltInSymmetricCryptoMode   =  cmDefault );
begin
  inherited Create;

  if IsStreamCipher then
  begin
    FMode := cmDefault;
    FBlockSize := 1;
  end
  else
  begin
    if Mode = cmDefault then
      Mode := SYMMETRIC_DEFAULT_MODE;

    FMode := Mode;
    FBlockSize := 0;
  end;

  FAssociatedData := false;
  FTagSize := FBlockSize;
  FKeyMaterial := nil;
  FOID := EmptyArray;
  FKeySize := 0;
  FCTRLittleEndian := false;
  FOperation := coNone;
end;

 destructor  TElBuiltInSymmetricCrypto.Destroy;
begin
  inherited;
end;

function TElBuiltInSymmetricCrypto.DoProgress(Total, Current : Int64): boolean;
var
  Cancel : TSBBoolean;
begin
  Cancel := false;
  if Assigned(FOnProgress) then
    FOnProgress(Self, Total, Current, Cancel);
  Result := not (Cancel);
end;

procedure TElBuiltInSymmetricCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if FKeySize > 0 then
    if Length(Material.Value) <> FKeySize then
      raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);


  if not IsStreamCipher then
  begin
    if FBlockSize > 0 then
      if not ((Length(Material.IV) = FBlockSize) or (Length(Material.IV) = 0)) then
        raise EElSymmetricCryptoError.Create(SNoIVInKeyMaterial);
    if (Length(Material.IV) = 0) and
       not (FMode in [cmDefault, cmECB,
       cmGCM, cmCCM ])
    then
      raise EElSymmetricCryptoError.Create(SNoIVInKeyMaterial);
  end;

  FKeyMaterial := Material;

  if (not IsStreamCipher) and (Length(Material.IV) > 0) then
    FBlockSize := Length(Material.IV);
  if Length(Material.Value) > 0 then
    FKeySize := Length(Material.Value);

  // put all key- and IV- checks, including inherited call, in descendant classes.
end;

procedure TElBuiltInSymmetricCrypto.SetAssociatedData(Value : boolean);
var
  OldSize, NewSize, i : integer;
begin
  if (FMode = cmGCM) or
    (FMode = cmCCM) then
  begin
    if (FAssociatedData) and (not Value) then
    begin
      if Length(FTail) > 0 then
      begin
        if FOperation = coEncryption then
        begin
          OldSize := Length(FTail);
          SetLength(FTail, FBlockSize);
          for i := OldSize to FBlockSize - 1 do
            FTail[i] := 0;

          FInternalEncryptFunction(@FTail[0], nil, FBlockSize);
          SetLength(FTail, 0);
        end
        else if FOperation = coDecryption then
        begin
          OldSize := Length(FTail);
          NewSize := ((Length(FTail) + FBlockSize - 1) div FBlockSize) * FBlockSize;
          SetLength(FTail, NewSize);
          for i := OldSize to NewSize - 1 do
            FTail[i] := 0;

          FInternalDecryptFunction(@FTail[0], nil, NewSize);
          SetLength(FTail, 0);
        end;
      end;
      FAssociatedData := false;
    end
    else if (not FAssociatedData) and Value then
      raise EElBuiltInCryptoProviderError.Create(SInvalidPropertyValue);
  end
  else
    raise EElBuiltInCryptoProviderError.Create(SInvalidCipherMode);
end;

class function TElBuiltInSymmetricCrypto.IsAlgorithmSupported(AlgID : integer) : boolean;
begin
  Result := false;
end;

class function TElBuiltInSymmetricCrypto.IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;
begin
  Result := false;
end;

class function TElBuiltInSymmetricCrypto.StreamCipher : boolean;
begin
  Result := false;
  { override for stream ciphers }
end;

function TElBuiltInSymmetricCrypto.GetIsStreamCipher : boolean;
begin
  Result := StreamCipher;
end;

function TElBuiltInSymmetricCrypto.EstimatedOutputSize(InputSize : integer; Encrypt : boolean) : integer;
begin
  if IsStreamCipher then
  begin
    Result := InputSize;
    Exit;
  end;

  if (FMode = cmCTR) or
    (FMode = cmCFB8)
  then
  begin
    Result := InputSize;
    Exit;
  end;

  if Encrypt then
  begin
    if FPadding = cpPKCS5 then
      Result := InputSize + FBlockSize - InputSize mod FBlockSize
    else if FPadding = cpNone then
      Result := InputSize
    else
      raise EElSymmetricCryptoError.Create(SInternalException);
  end
  else
  begin
    if FPadding = cpPKCS5 then
      Result := InputSize
    else if FPadding = cpNone then
      Result := InputSize
    else
      raise EElSymmetricCryptoError.Create(SInternalException);
  end;
end;

procedure TElBuiltInSymmetricCrypto.SetNonce(const V : ByteArray);
begin
  FNonce := CloneArray(V);
end;

procedure TElBuiltInSymmetricCrypto.ExpandKeyForEncryption;
begin
  ;
end;

procedure TElBuiltInSymmetricCrypto.ExpandKeyForDecryption;
begin
  ;
end;

procedure TElBuiltInSymmetricCrypto.InitializeCCM;
var
  i, n : integer;
  TmpBuf : ByteArray;
begin

  if FBlockSize <> 16 then
    raise EElBuiltInCryptoProviderError.Create(SInvalidCipherMode);

  n := Length(FNonce);
  if (n < 7) or (n > 13) then
    raise EElBuiltInCryptoProviderError.Create(SInvalidKeyMaterial);

  if not (FTagSize in [4, 6, 8, 10, 12, 14, 16]) then
    raise EElBuiltInCryptoProviderError.Create(SInvalidPropertyValue);

  if BitCount(FPayloadSize) > (15 - n) shl 3 then
    raise EElBuiltInCryptoProviderError.Create(SInvalidInputSize);

  SetLength(TmpBuf, 16);

  { formatting B0 }
  TmpBuf[0] := ((FTagSize - 2) shl 2) or (14 - n);
  for i := 0 to n - 1 do
    TmpBuf[i + 1] := FNonce[i];

  for i := n + 1 to 15 do
    TmpBuf[i] := FPayloadSize shr ((15 - i) shl 3);

  if FAssociatedDataSize > 0 then
  begin
    TmpBuf[0] := TmpBuf[0] or $40;

    FAssociatedData := true;

    if FAssociatedDataSize < $ff00 then
    begin
      SetLength(FTail, 2);
      GetBytes16(FAssociatedDataSize, FTail, 0);
      (*
      FTail[0] := (FAssociatedDataSize shr 8) and $ff;
      FTail[1] := FAssociatedDataSize and $ff;
      *)
    end
    else if FAssociatedDataSize <= $ffffffff then
    begin
      SetLength(FTail, 6);
      FTail[0] := $ff;
      FTail[1] := $fe;
      GetBytes32(FAssociatedDataSize, FTail, 2);
      (*
      FTail[2] := (FAssociatedDataSize shr 24) and $ff;
      FTail[3] := (FAssociatedDataSize shr 16) and $ff;
      FTail[4] := (FAssociatedDataSize shr 8) and $ff;
      FTail[5] := FAssociatedDataSize and $ff;
      *)
    end
    else
    begin
      SetLength(FTail, 10);
      FTail[0] := $ff;
      FTail[1] := $ff;

      GetBytes64(FAssociatedDataSize, FTail, 2);
      (*
      FTail[2] := (FAssociatedDataSize shr 56) and $ff;
      FTail[3] := (FAssociatedDataSize shr 48) and $ff;
      FTail[4] := (FAssociatedDataSize shr 40) and $ff;
      FTail[5] := (FAssociatedDataSize shr 32) and $ff;
      FTail[6] := (FAssociatedDataSize shr 24) and $ff;
      FTail[7] := (FAssociatedDataSize shr 16) and $ff;
      FTail[8] := (FAssociatedDataSize shr 8) and $ff;
      FTail[9] := FAssociatedDataSize and $ff;
      *)
    end;
  end
  else
    FAssociatedData := false;

  SetLength(FAEADY, 16);
  EncryptBlockArr(TmpBuf, FAEADY);

  { counter blocks formatting }
  SetLength(FAEADCtr0, 16);

  FAEADCtr0[0] := TmpBuf[0] and 7;
  for i := 0 to n - 1 do
    FAEADCtr0[i + 1] := FNonce[i];
  for i := n + 1 to 15 do
    FAEADCtr0[i] := 0;
  SetLength(FVector, 16);
  CCMInc24(FAEADCtr0, FVector);

end;

{$ifdef SB_GCM_8BIT}
procedure TElBuiltInSymmetricCrypto.GHASHInit;
var
  V0, V1 : UInt64;
  Flg : boolean;
  i, j : integer;
begin
  { 8-bit hash table precalculation }


  FGCMCtx.HTable[0] := 0;
  FGCMCtx.HTable[1] := 0;
  V0 := FGCMCtx.H0;
  V1 := FGCMCtx.H1;

  FGCMCtx.HTable[128 * 2] := V0;
  FGCMCtx.HTable[128 * 2 + 1] := V1;

  for i := 7 downto 1 do
  begin
    Flg := (V1 and 1) <> 0;
    V1 := (V0 shl 63) or (V1 shr 1);
    V0 := (V0 shr 1);
    if (Flg) then
      V0 := V0 xor $E100000000000000;

    FGCMCtx.HTable[1 shl i] := V0;
    FGCMCtx.HTable[1 shl i + 1] := V1;
  end;

  i := 2;

  while i < 256 do
  begin
    V0 := FGCMCtx.HTable[i shl 1];
    V1 := FGCMCtx.HTable[(i shl 1) + 1];

    for j := 1 to i - 1 do
    begin
      FGCMCtx.HTable[(i + j) shl 1] := V0 xor FGCMCtx.HTable[j shl 1];
      FGCMCtx.HTable[((i + j) shl 1) + 1] := V1 xor FGCMCtx.HTable[(j shl 1) + 1];
    end;

    i := i shl 1;
  end;
end;

const GCM_REM_BITS : array [0..255] of UInt64 = (
  $0000000000000000, $01C2000000000000, $0384000000000000, $0246000000000000,
  $0708000000000000, $06CA000000000000, $048C000000000000, $054E000000000000,
	$0E10000000000000, $0FD2000000000000, $0D94000000000000, $0C56000000000000,
	$0918000000000000, $08DA000000000000, $0A9C000000000000, $0B5E000000000000,
	$1C20000000000000, $1DE2000000000000, $1FA4000000000000, $1E66000000000000,
	$1B28000000000000, $1AEA000000000000, $18AC000000000000, $196E000000000000,
	$1230000000000000, $13F2000000000000, $11B4000000000000, $1076000000000000,
	$1538000000000000, $14FA000000000000, $16BC000000000000, $177E000000000000,
	$3840000000000000, $3982000000000000, $3BC4000000000000, $3A06000000000000,
	$3F48000000000000, $3E8A000000000000, $3CCC000000000000, $3D0E000000000000,
	$3650000000000000, $3792000000000000, $35D4000000000000, $3416000000000000,
	$3158000000000000, $309A000000000000, $32DC000000000000, $331E000000000000,
	$2460000000000000, $25A2000000000000, $27E4000000000000, $2626000000000000,
	$2368000000000000, $22AA000000000000, $20EC000000000000, $212E000000000000,
	$2A70000000000000, $2BB2000000000000, $29F4000000000000, $2836000000000000,
	$2D78000000000000, $2CBA000000000000, $2EFC000000000000, $2F3E000000000000,
	$7080000000000000, $7142000000000000, $7304000000000000, $72C6000000000000,
	$7788000000000000, $764A000000000000, $740C000000000000, $75CE000000000000,
	$7E90000000000000, $7F52000000000000, $7D14000000000000, $7CD6000000000000,
	$7998000000000000, $785A000000000000, $7A1C000000000000, $7BDE000000000000,
	$6CA0000000000000, $6D62000000000000, $6F24000000000000, $6EE6000000000000,
	$6BA8000000000000, $6A6A000000000000, $682C000000000000, $69EE000000000000,
	$62B0000000000000, $6372000000000000, $6134000000000000, $60F6000000000000,
	$65B8000000000000, $647A000000000000, $663C000000000000, $67FE000000000000,
	$48C0000000000000, $4902000000000000, $4B44000000000000, $4A86000000000000,
	$4FC8000000000000, $4E0A000000000000, $4C4C000000000000, $4D8E000000000000,
	$46D0000000000000, $4712000000000000, $4554000000000000, $4496000000000000,
	$41D8000000000000, $401A000000000000, $425C000000000000, $439E000000000000,
	$54E0000000000000, $5522000000000000, $5764000000000000, $56A6000000000000,
	$53E8000000000000, $522A000000000000, $506C000000000000, $51AE000000000000,
	$5AF0000000000000, $5B32000000000000, $5974000000000000, $58B6000000000000,
	$5DF8000000000000, $5C3A000000000000, $5E7C000000000000, $5FBE000000000000,
	$E100000000000000, $E0C2000000000000, $E284000000000000, $E346000000000000,
	$E608000000000000, $E7CA000000000000, $E58C000000000000, $E44E000000000000,
	$EF10000000000000, $EED2000000000000, $EC94000000000000, $ED56000000000000,
	$E818000000000000, $E9DA000000000000, $EB9C000000000000, $EA5E000000000000,
	$FD20000000000000, $FCE2000000000000, $FEA4000000000000, $FF66000000000000,
	$FA28000000000000, $FBEA000000000000, $F9AC000000000000, $F86E000000000000,
	$F330000000000000, $F2F2000000000000, $F0B4000000000000, $F176000000000000,
	$F438000000000000, $F5FA000000000000, $F7BC000000000000, $F67E000000000000,
	$D940000000000000, $D882000000000000, $DAC4000000000000, $DB06000000000000,
	$DE48000000000000, $DF8A000000000000, $DDCC000000000000, $DC0E000000000000,
	$D750000000000000, $D692000000000000, $D4D4000000000000, $D516000000000000,
	$D058000000000000, $D19A000000000000, $D3DC000000000000, $D21E000000000000,
	$C560000000000000, $C4A2000000000000, $C6E4000000000000, $C726000000000000,
	$C268000000000000, $C3AA000000000000, $C1EC000000000000, $C02E000000000000,
	$CB70000000000000, $CAB2000000000000, $C8F4000000000000, $C936000000000000,
	$CC78000000000000, $CDBA000000000000, $CFFC000000000000, $CE3E000000000000,
	$9180000000000000, $9042000000000000, $9204000000000000, $93C6000000000000,
	$9688000000000000, $974A000000000000, $950C000000000000, $94CE000000000000,
	$9F90000000000000, $9E52000000000000, $9C14000000000000, $9DD6000000000000,
	$9898000000000000, $995A000000000000, $9B1C000000000000, $9ADE000000000000,
	$8DA0000000000000, $8C62000000000000, $8E24000000000000, $8FE6000000000000,
	$8AA8000000000000, $8B6A000000000000, $892C000000000000, $88EE000000000000,
	$83B0000000000000, $8272000000000000, $8034000000000000, $81F6000000000000,
	$84B8000000000000, $857A000000000000, $873C000000000000, $86FE000000000000,
	$A9C0000000000000, $A802000000000000, $AA44000000000000, $AB86000000000000,
	$AEC8000000000000, $AF0A000000000000, $AD4C000000000000, $AC8E000000000000,
	$A7D0000000000000, $A612000000000000, $A454000000000000, $A596000000000000,
	$A0D8000000000000, $A11A000000000000, $A35C000000000000, $A29E000000000000,
	$B5E0000000000000, $B422000000000000, $B664000000000000, $B7A6000000000000,
	$B2E8000000000000, $B32A000000000000, $B16C000000000000, $B0AE000000000000,
	$BBF0000000000000, $BA32000000000000, $B874000000000000, $B9B6000000000000,
	$BCF8000000000000, $BD3A000000000000, $BF7C000000000000, $BEBE000000000000
);
 {$else}
procedure TElBuiltInSymmetricCrypto.GHASHInit;
var
  V0, V1 : UInt64;
  Flg : boolean;
begin
  { 4-bit hash table precalculation }


  FGCMCtx.HTable[0] := 0;
  FGCMCtx.HTable[1] := 0;
  V0 := FGCMCtx.H0;
  V1 := FGCMCtx.H1;

  FGCMCtx.HTable[8 * 2] := V0;
  FGCMCtx.HTable[8 * 2 + 1] := V1;
  Flg := (V1 and 1) <> 0;
  V1 := (V0 shl 63) or (V1 shr 1);
  V0 := (V0 shr 1);
  if (Flg) then
    V0 := V0 xor $E100000000000000;

  FGCMCtx.HTable[4 * 2] := V0;
  FGCMCtx.HTable[4 * 2 + 1] := V1;
  Flg := (V1 and 1) <> 0;
  V1 := (V0 shl 63) or (V1 shr 1);
  V0 := (V0 shr 1);
  if (Flg) then
    V0 := V0 xor $E100000000000000;

  FGCMCtx.HTable[2 * 2] := V0;
  FGCMCtx.HTable[2 * 2 + 1] := V1;
  Flg := (V1 and 1) <> 0;
  V1 := (V0 shl 63) or (V1 shr 1);
  V0 := (V0 shr 1);
  if (Flg) then
    V0 := V0 xor $E100000000000000;

  FGCMCtx.HTable[1 * 2] := V0;
  FGCMCtx.HTable[1 * 2 + 1] := V1;

  FGCMCtx.HTable[3 * 2] := V0 xor FGCMCtx.HTable[2 * 2];
  FGCMCtx.HTable[3 * 2 + 1] := V1 xor FGCMCtx.HTable[2 * 2 + 1];
  V0 := FGCMCtx.HTable[4 * 2];
  V1 := FGCMCtx.HTable[4 * 2 + 1];
  FGCMCtx.HTable[5 * 2] := V0 xor FGCMCtx.HTable[1 * 2];
  FGCMCtx.HTable[5 * 2 + 1] := V1 xor FGCMCtx.HTable[1 * 2 + 1];
  FGCMCtx.HTable[6 * 2] := V0 xor FGCMCtx.HTable[2 * 2];
  FGCMCtx.HTable[6 * 2 + 1] := V1 xor FGCMCtx.HTable[2 * 2 + 1];
  FGCMCtx.HTable[7 * 2] := V0 xor FGCMCtx.HTable[3 * 2];
  FGCMCtx.HTable[7 * 2 + 1] := V1 xor FGCMCtx.HTable[3 * 2 + 1];
  V0 := FGCMCtx.HTable[8 * 2];
  V1 := FGCMCtx.HTable[8 * 2 + 1];
  FGCMCtx.HTable[9 * 2] := V0 xor FGCMCtx.HTable[1 * 2];
  FGCMCtx.HTable[9 * 2 + 1] := V1 xor FGCMCtx.HTable[1 * 2 + 1];
  FGCMCtx.HTable[10 * 2] := V0 xor FGCMCtx.HTable[2 * 2];
  FGCMCtx.HTable[10 * 2 + 1] := V1 xor FGCMCtx.HTable[2 * 2 + 1];
  FGCMCtx.HTable[11 * 2] := V0 xor FGCMCtx.HTable[3 * 2];
  FGCMCtx.HTable[11 * 2 + 1] := V1 xor FGCMCtx.HTable[3 * 2 + 1];
  FGCMCtx.HTable[12 * 2] := V0 xor FGCMCtx.HTable[4 * 2];
  FGCMCtx.HTable[12 * 2 + 1] := V1 xor FGCMCtx.HTable[4 * 2 + 1];
  FGCMCtx.HTable[13 * 2] := V0 xor FGCMCtx.HTable[5 * 2];
  FGCMCtx.HTable[13 * 2 + 1] := V1 xor FGCMCtx.HTable[5 * 2 + 1];
  FGCMCtx.HTable[14 * 2] := V0 xor FGCMCtx.HTable[6 * 2];
  FGCMCtx.HTable[14 * 2 + 1] := V1 xor FGCMCtx.HTable[6 * 2 + 1];
  FGCMCtx.HTable[15 * 2] := V0 xor FGCMCtx.HTable[7 * 2];
  FGCMCtx.HTable[15 * 2 + 1] := V1 xor FGCMCtx.HTable[7 * 2 + 1];
end;

const GCM_REM_BITS : array [0..15] of UInt64 = (
	$0000000000000000, $1C20000000000000, $3840000000000000, $2460000000000000,
	$7080000000000000, $6CA0000000000000, $48C0000000000000, $54E0000000000000,
	$E100000000000000, $FD20000000000000, $D940000000000000, $C560000000000000,
	$9180000000000000, $8DA0000000000000, $A9C0000000000000, $B5E0000000000000);
 {$endif}


{$ifdef SB_GCM_8BIT}
procedure TElBuiltInSymmetricCrypto.GHASHUpdate(const Buf : ByteArray);
var
  Y : ByteArray;
  Z0, Z1 : UInt64;
  n, rem : cardinal;
  i : integer;
begin
  SetLength(Y, 16);
  GetByteArrayFromInt64BE(FGCMCtx.Y0, Y, 0);
  GetByteArrayFromInt64BE(FGCMCtx.Y1, Y, 8);
  Z0 := 0;
  Z1 := 0;
  n := (Y[15] xor Buf[15]) shl 1;
  i := 15;

  while True do
  begin
    Z0 := Z0 xor FGCMCtx.HTable[n];
    Z1 := Z1 xor FGCMCtx.HTable[n + 1];

    if i = 0 then
      Break;

    Dec(i);
    rem := Z1 and $ff;
    Z1 := (Z0 shl 56) or (Z1 shr 8);
    Z0 := (Z0 shr 8) xor GCM_REM_BITS[rem];
  end;

  FGCMCtx.Y0 := Z0;
  FGCMCtx.Y1 := Z1;
end;

 {$else}
procedure TElBuiltInSymmetricCrypto.GHASHUpdate(const Buf : ByteArray);
var
  Y : ByteArray;
  Z0, Z1 : UInt64;
  nlo, nhi, rem : cardinal;
  i : integer;
begin
  SetLength(Y, 16);
  GetByteArrayFromInt64BE(FGCMCtx.Y0, Y, 0);
  GetByteArrayFromInt64BE(FGCMCtx.Y1, Y, 8);

  nlo := Y[15] xor Buf[15];
  nhi := (nlo shr 4) shl 1;
  nlo := (nlo and $f) shl 1;
  Z0 := FGCMCtx.HTable[nlo];
  Z1 := FGCMCtx.HTable[nlo + 1];
  i := 15;

  while true do
  begin
    rem := Z1 and $f;
    Z1 := (Z0 shl 60) or (Z1 shr 4);
    Z0 := (Z0 shr 4) xor GCM_REM_BITS[rem];

    Z0 := Z0 xor FGCMCtx.HTable[nhi];
    Z1 := Z1 xor FGCMCtx.HTable[nhi + 1];

    Dec(i);
    if (i < 0) then
      break;

    nlo := Y[i] xor Buf[i];
    nhi := (nlo shr 4) shl 1;
    nlo := (nlo and $f) shl 1;

    rem := Z1 and $f;
    Z1 := (Z0 shl 60) or (Z1 shr 4);
    Z0 := (Z0 shr 4) xor GCM_REM_BITS[rem];

    Z0 := Z0 xor FGCMCtx.HTable[nlo];
    Z1 := Z1 xor FGCMCtx.HTable[nlo + 1];
  end;

  FGCMCtx.Y0 := Z0;
  FGCMCtx.Y1 := Z1;
end;
 {$endif}

procedure TElBuiltInSymmetricCrypto.InitializeGCM;
var
  TmpBuf{, Buf2} : ByteArray;
  i, n : integer;
begin
  if FBlockSize <> 16 then
    raise EElBuiltInCryptoProviderError.Create(SInvalidCipherMode);


  FGCMCtx.H0 := 0;
  FGCMCtx.H1 := 0;
  FGCMCtx.Y0 := 0;
  FGCMCtx.Y1 := 0;
  EncryptBlock(FGCMCtx.H0, FGCMCtx.H1);
  FGCMCtx.H0 := SwapInt64(FGCMCtx.H0);
  FGCMCtx.H1 := SwapInt64(FGCMCtx.H1);
  GHASHInit;

  if Length(FNonce) = 12 then
  begin
    FGCMCtx.Ctr0 := GetInt64BEFromByteArray(FNonce, 0);
    FGCMCtx.Ctr1 := (UInt64(FNonce[8]) shl 56) or (UInt64(FNonce[9]) shl 48) or (UInt64(FNonce[10]) shl 40) or (UInt64(FNonce[11]) shl 32) or (UInt64(1));
  end
  else
  begin
    n := ((Length(FNonce) + 15) shr 4) shl 4;
    SetLength(TmpBuf, n + 16);
    SBMove(FNonce[0], TmpBuf[0], Length(FNonce));
    for i := Length(FNonce) to n + 16 - 1 do
      TmpBuf[i] := 0;
    i := Length(TmpBuf) - 1;
    n := Length(FNonce) shl 3;
    while (n > 0) do
    begin
      TmpBuf[i] := n and $ff;
      Dec(i);
      n := n shr 8;
    end;

    i := 0;
    while (i < Length(TmpBuf) - 1) do
    begin
      GHASHUpdate(SubArray(TmpBuf, i, 16));
      Inc(i, 16);
    end;

    FGCMCtx.Ctr0 := FGCMCtx.Y0;
    FGCMCtx.Ctr1 := FGCMCtx.Y1;
    FGCMCtx.Y0 := 0;
    FGCMCtx.Y1 := 0;
  end;

  FGCMCtx.IV0 := SwapUInt32(FGCMCtx.Ctr0 shr 32);
  FGCMCtx.IV1 := SwapUInt32(FGCMCtx.Ctr0 and $ffffffff);
  FGCMCtx.IV2 := SwapUInt32(FGCMCtx.Ctr1 shr 32);
  FGCMCtx.IV3 := SwapUInt32(FGCMCtx.Ctr1 and $ffffffff);
  FGCMCtx.IV3 := SwapUInt32(SwapUInt32(FGCMCtx.IV3) + 1);
  
  FGCMCtx.ASize := 0;
  FGCMCtx.PSize := 0;
  FAssociatedData := true;

end;

procedure TElBuiltInSymmetricCrypto.InitializeEncryption;
begin
  SetLength(FVector, Length(FKeyMaterial.IV));
  if Length(FVector) > 0 then
    SBMove(FKeyMaterial.IV[0], FVector[0], Length(FVector));
  SetLength(FTail, 0);

  if (FMode = cmCTR) or
    (FMode = cmCFB8)
  then
    FBytesLeft := FBlockSize;

  ExpandKeyForEncryption;
  InternalEncryptInit;

  FOperation := coEncryption;    
  { must be called as inherited in descendant classes }
end;

procedure TElBuiltInSymmetricCrypto.InternalEncryptInit;
begin
  if IsStreamCipher then
    Exit
  else if (FMode = cmECB) and (FBlockSize = 8) then
    FInternalEncryptFunction :=  InternalEncryptECB8 
  else if (FMode = cmECB) and (FBlockSize = 16) then
    FInternalEncryptFunction :=  InternalEncryptECB16 
  else if (FMode = cmCBC) and (FBlockSize = 8) then
    FInternalEncryptFunction :=  InternalEncryptCBC8 
  else if (FMode = cmCBC) and (FBlockSize = 16) then
    FInternalEncryptFunction :=  InternalEncryptCBC16 
  else if (FMode = cmCTR) and (FBlockSize = 8) then
    FInternalEncryptFunction :=  InternalEncryptCTR8 
  else if (FMode = cmCTR) and (FBlockSize = 16) then
    FInternalEncryptFunction :=  InternalEncryptCTR16 
  else if (FMode = cmCFB8) and (FBlockSize = 8) then
    FInternalEncryptFunction :=  InternalEncryptCFB88 
  else if (FMode = cmCFB8) and (FBlockSize = 16) then
    FInternalEncryptFunction :=  InternalEncryptCFB816 
  else if (FMode = cmGCM) and (FBlockSize = 16) then
  begin
    FInternalEncryptFunction :=  InternalEncryptGCM ;
    InitializeGCM;
  end
  else
  if (FMode = cmCCM) then
  begin
    FInternalEncryptFunction :=  InternalEncryptCCM ;
    InitializeCCM;
  end
  else
    raise EElSymmetricCryptoError.Create(SInvalidCipherMode);
end;

procedure TElBuiltInSymmetricCrypto.InternalEncryptECB8(Buffer, OutBuffer : pointer; Size : integer);
var
  Index, Count : integer;
  B0, B1 : cardinal;
begin
  Count := Size div FBlockSize;

  for Index := 0 to Count - 1 do
  begin
    B0 := PLongWord(Buffer)^;
    B1 := PLongWord(PtrUInt(Buffer) + 4)^;
    Inc(PtrUInt(Buffer), 8);

    EncryptBlock8(B0, B1);

    PLongWord(OutBuffer)^ := B0;
    PLongWord(PtrUInt(OutBuffer) + 4)^ := B1;
    Inc(PtrUInt(OutBuffer), 8);
  end;
end;

procedure TElBuiltInSymmetricCrypto.InternalEncryptECB16(Buffer, OutBuffer : pointer; Size : integer);
var
  Index, Count : integer;
  B0, B1, B2, B3 : cardinal;
begin
  Count := Size div FBlockSize;

  for Index := 0 to Count - 1 do
  begin
    B0 := PLongWord(Buffer)^;
    B1 := PLongWord(PtrUInt(Buffer) + 4)^;
    B2 := PLongWord(PtrUInt(Buffer) + 8)^;
    B3 := PLongWord(PtrUInt(Buffer) + 12)^;
    Inc(PtrUInt(Buffer), 16);

    EncryptBlock16(B0, B1, B2, B3);

    PLongWord(OutBuffer)^ := B0;
    PLongWord(PtrUInt(OutBuffer) + 4)^ := B1;
    PLongWord(PtrUInt(OutBuffer) + 8)^ := B2;
    PLongWord(PtrUInt(OutBuffer) + 12)^ := B3;
    Inc(PtrUInt(OutBuffer), 16);
  end;
end;

procedure TElBuiltInSymmetricCrypto.InternalEncryptCBC8(Buffer, OutBuffer : pointer; Size : integer);
var
  Index, Count : integer;
  IV0, IV1 : cardinal;
begin
  if Length(FVector) <> FBlockSize then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  Count := Size div FBlockSize;
  BlockToUInts8(FVector, IV0, IV1);

  for Index := 0 to Count - 1 do
  begin
    IV0 := IV0 xor PLongWord(Buffer)^;
    IV1 := IV1 xor PLongWord(PtrUInt(Buffer) + 4)^;
    Inc(PtrUInt(Buffer), 8);

    EncryptBlock8(IV0, IV1);

    PLongWord(OutBuffer)^ := IV0;
    PLongWord(PtrUInt(OutBuffer) + 4)^ := IV1;
    Inc(PtrUInt(OutBuffer), 8);
  end;

  UIntsToBlock8(IV0, IV1, FVector);
end;

procedure TElBuiltInSymmetricCrypto.InternalEncryptCBC16(Buffer, OutBuffer : pointer; Size : integer);
var
  Index, Count : integer;
  IV0, IV1, IV2, IV3 : cardinal;
begin
  if Length(FVector) <> FBlockSize then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  Count := Size div FBlockSize;
  BlockToUInts16(FVector, IV0, IV1, IV2, IV3);

  for Index := 0 to Count - 1 do
  begin
    IV0 := IV0 xor PLongWord(Buffer)^;
    IV1 := IV1 xor PLongWord(PtrUInt(Buffer) + 4)^;
    IV2 := IV2 xor PLongWord(PtrUInt(Buffer) + 8)^;
    IV3 := IV3 xor PLongWord(PtrUInt(Buffer) + 12)^;
    Inc(PtrUInt(Buffer), 16);

    EncryptBlock16(IV0, IV1, IV2, IV3);
    
    PLongWord(OutBuffer)^ := IV0;
    PLongWord(PtrUInt(OutBuffer) + 4)^ := IV1;
    PLongWord(PtrUInt(OutBuffer) + 8)^ := IV2;
    PLongWord(PtrUInt(OutBuffer) + 12)^ := IV3;
    Inc(PtrUInt(OutBuffer), 16);
  end;

  UIntsToBlock16(IV0, IV1, IV2, IV3, FVector);
end;

procedure TElBuiltInSymmetricCrypto.InternalEncryptCTR8(Buffer, OutBuffer : pointer; Size : integer);
var
  Index, Count : integer;
  IV0, IV1, B0, B1 : cardinal;
begin
  if Length(FVector) <> FBlockSize then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  BlockToUInts8(FVector, IV0, IV1);

  if FBytesLeft < FBlockSize then
  begin
    Count := Min(FBytesLeft, Size);
    for Index := 0 to Count - 1 do
      PByteArray(OutBuffer)^[Index] := PByteArray(Buffer)^[Index] xor FTail[FBlockSize - FBytesLeft + Index];

    Dec(FBytesLeft, Count);
    Inc( PtrUInt(OutBuffer) , Count);
    Inc( PtrUInt(Buffer) , Count);
    Dec(Size, Count);

    if FBytesLeft = 0 then
    begin
      { incrementing counter }
      if FCTRLittleEndian and (IV0 < $ffffffff) then
        Inc(IV0)
      else if (not FCTRLittleEndian) and (IV1 < $ff000000) then
        Inc(IV1, $1000000)
      else
        IncrementCounter8(IV0, IV1); // one call per 256 blocks is ok for performance

      FBytesLeft := FBlockSize;
    end;
  end;

  Count := Size div FBlockSize;

  for Index := 0 to Count - 1 do
  begin
    B0 := IV0;
    B1 := IV1;
    EncryptBlock8(B0, B1);

    PLongWord(OutBuffer)^ := B0 xor PLongWord(Buffer)^;
    PLongWord(PtrUInt(OutBuffer) + 4)^ := B1 xor PLongWord(PtrUInt(Buffer) + 4)^;
    Inc(PtrUInt(Buffer), 8);
    Inc(PtrUInt(OutBuffer), 8);

    { incrementing counter }
    if FCTRLittleEndian and (IV0 < $ffffffff) then
      Inc(IV0)
    else if (not FCTRLittleEndian) and (IV1 < $ff000000) then
      Inc(IV1, $1000000)
    else
      IncrementCounter8(IV0, IV1); // one call per 256 blocks is ok for performance
  end;

  Dec(Size, Integer(Count) * FBlockSize);

  if Size > 0 then
  begin
    B0 := IV0;
    B1 := IV1;
    EncryptBlock8(B0, B1);
    SetLength(FTail, FBlockSize);
    UIntsToBlock8(B0, B1, FTail);

    for Index := 0 to Size - 1 do
      PByteArray(OutBuffer)^[Index] := PByteArray(Buffer)^[Index] xor FTail[Index];

    FBytesLeft := FBlockSize - Size;

    if FBytesLeft = 0 then
    begin
      { incrementing counter }
      if FCTRLittleEndian and (IV0 < $ffffffff) then
        Inc(IV0)
      else if (not FCTRLittleEndian) and (IV1 < $ff000000) then
        Inc(IV1, $1000000)
      else
        IncrementCounter8(IV0, IV1); // one call per 256 blocks is ok for performance

      FBytesLeft := FBlockSize;  
    end;
  end;

  UIntsToBlock8(IV0, IV1, FVector);
end;

procedure TElBuiltInSymmetricCrypto.InternalEncryptCTR16(Buffer, OutBuffer : pointer; Size : integer);
var
  Index, Count : integer;
  IV0, IV1, IV2, IV3, B0, B1, B2, B3: cardinal;
begin
  if Length(FVector) <> FBlockSize then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  BlockToUInts16(FVector, IV0, IV1, IV2, IV3);

  if FBytesLeft < FBlockSize then
  begin
    Count := Min(FBytesLeft, Size);
    for Index := 0 to Count - 1 do
      PByteArray(OutBuffer)^[Index] := PByteArray(Buffer)^[Index] xor FTail[FBlockSize - FBytesLeft + Index];

    Dec(FBytesLeft, Count);
    Inc( PtrUInt(OutBuffer) , Count);
    Inc( PtrUInt(Buffer) , Count);
    Dec(Size, Count);

    if FBytesLeft = 0 then
    begin
      { incrementing counter }
      if FCTRLittleEndian and (IV0 < $ffffffff) then
        Inc(IV0)
      else if (not FCTRLittleEndian) and (IV3 < $ff000000) then
        Inc(IV3, $1000000)
      else
        IncrementCounter16(IV0, IV1, IV2, IV3); // one call per 256 blocks is ok for performance

      FBytesLeft := FBlockSize;
    end;
  end;

  Count := Size div FBlockSize;

  for Index := 0 to Count - 1 do
  begin
    B0 := IV0;
    B1 := IV1;
    B2 := IV2;
    B3 := IV3;
    EncryptBlock16(B0, B1, B2, B3);

    PLongWord(OutBuffer)^ := B0 xor PLongWord(Buffer)^;
    PLongWord(PtrUInt(OutBuffer) + 4)^ := B1 xor PLongWord(PtrUInt(Buffer) + 4)^;
    PLongWord(PtrUInt(OutBuffer) + 8)^ := B2 xor PLongWord(PtrUInt(Buffer) + 8)^;
    PLongWord(PtrUInt(OutBuffer) + 12)^ := B3 xor PLongWord(PtrUInt(Buffer) + 12)^;

    Inc(PtrUInt(Buffer), 16);
    Inc(PtrUInt(OutBuffer), 16);

    { incrementing counter }
    if FCTRLittleEndian and (IV0 < $ffffffff) then
      Inc(IV0)
    else if (not FCTRLittleEndian) and (IV3 < $ff000000) then
      Inc(IV3, $1000000)
    else
      IncrementCounter16(IV0, IV1, IV2, IV3); // one call per 256 blocks is ok for performance
  end;

  Dec(Size, Integer(Count) * FBlockSize);

  if Size > 0 then
  begin
    B0 := IV0;
    B1 := IV1;
    B2 := IV2;
    B3 := IV3;

    EncryptBlock16(B0, B1, B2, B3);
    SetLength(FTail, FBlockSize);
    UIntsToBlock16(B0, B1, B2, B3, FTail);

    for Index := 0 to Size - 1 do
      PByteArray(OutBuffer)^[Index] := PByteArray(Buffer)^[Index] xor FTail[Index];

    FBytesLeft := FBlockSize - Size;

    if FBytesLeft = 0 then
    begin
      { incrementing counter }
      if FCTRLittleEndian and (IV0 < $ffffffff) then
        Inc(IV0)
      else if (not FCTRLittleEndian) and (IV3 < $ff000000) then
        Inc(IV3, $1000000)
      else
        IncrementCounter16(IV0, IV1, IV2, IV3); // one call per 256 blocks is ok for performance

      FBytesLeft := FBlockSize;  
    end;
  end;

  UIntsToBlock16(IV0, IV1, IV2, IV3, FVector);
end;

procedure TElBuiltInSymmetricCrypto.InternalEncryptCFB88(Buffer, OutBuffer : pointer; Size : integer);
var
  Index, Count : integer;
  IV0, IV1 : cardinal;
begin
  if Length(FVector) <> FBlockSize then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  if FBytesLeft < FBlockSize then
  begin
    Count := Min(FBytesLeft, Size);
    for Index := 0 to Count - 1 do
      PByteArray(OutBuffer)^[Index] := PByteArray(Buffer)^[Index] xor FVector[Index];

    for Index := 0 to FBlockSize - Integer(Count) - 1 do
      FVector[Index] := FVector[Index + Integer(Count)];

    for Index := FBlockSize - Integer(Count) to FBlockSize - 1 do
      FVector[Index] := PByteArray(OutBuffer)^[Index - FBlockSize + Integer(Count)];

    Dec(FBytesLeft, Count);
    Inc( PtrUInt(OutBuffer) , Count);
    Inc( PtrUInt(Buffer) , Count);
    Dec(Size, Count);
    if FBytesLeft = 0 then
      FBytesLeft := FBlockSize;
  end;

  BlockToUInts8(FVector, IV0, IV1);
  Count := Size div FBlockSize;

  for Index := 0 to Count - 1 do
  begin
    EncryptBlock8(IV0, IV1);
    IV0 := IV0 xor PLongWord(Buffer)^;
    IV1 := IV1 xor PLongWord(PtrUInt(Buffer) + 4)^;
    PLongWord(OutBuffer)^ := IV0;
    PLongWord(PtrUInt(OutBuffer) + 4)^ := IV1;
    Inc(PtrUInt(Buffer), 8);
    Inc(PtrUInt(OutBuffer), 8);
  end;

  Dec(Size, Integer(Count) * FBlockSize);

  if Size > 0 then
  begin
    EncryptBlock8(IV0, IV1);
    UIntsToBlock8(IV0, IV1, FVector);

    for Index := 0 to Size - 1 do
      PByteArray(OutBuffer)^[Index] := PByteArray(Buffer)^[Index] xor FVector[Index];

    for Index := 0 to FBlockSize - Size - 1 do
      FVector[Index] := FVector[Index + Size];

    for Index := FBlockSize - Size to FBlockSize - 1 do
      FVector[Index] := PByteArray(OutBuffer)^[Index + Size - FBlockSize];

    Dec(FBytesLeft, Size);
    if FBytesLeft = 0 then FBytesLeft := FBlockSize;
  end
  else
    UIntsToBlock8(IV0, IV1, FVector);
end;

procedure TElBuiltInSymmetricCrypto.InternalEncryptCFB816(Buffer, OutBuffer : pointer; Size : integer);
var
  Index, Count : integer;
  IV0, IV1, IV2, IV3 : cardinal;
begin
  if Length(FVector) <> FBlockSize then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  if FBytesLeft < FBlockSize then
  begin
    Count := Min(FBytesLeft, Size);
    for Index := 0 to Count - 1 do
      PByteArray(OutBuffer)^[Index] := PByteArray(Buffer)^[Index] xor FVector[Index];

    for Index := 0 to FBlockSize - Integer(Count) - 1 do
      FVector[Index] := FVector[Index + Integer(Count)];

    for Index := FBlockSize - Integer(Count) to FBlockSize - 1 do
      FVector[Index] := PByteArray(OutBuffer)^[Index + Count - FBlockSize];

    Dec(FBytesLeft, Count);
    Inc( PtrUInt(OutBuffer) , Count);
    Inc( PtrUInt(Buffer) , Count);
    Dec(Size, Count);
    if FBytesLeft = 0 then
      FBytesLeft := FBlockSize;
  end;

  BlockToUInts16(FVector, IV0, IV1, IV2, IV3);
  Count := Size div FBlockSize;

  for Index := 0 to Count - 1 do
  begin
    EncryptBlock16(IV0, IV1, IV2, IV3);
    IV0 := IV0 xor PLongWord(Buffer)^;
    IV1 := IV1 xor PLongWord(PtrUInt(Buffer) + 4)^;
    IV2 := IV2 xor PLongWord(PtrUInt(Buffer) + 8)^;
    IV3 := IV3 xor PLongWord(PtrUInt(Buffer) + 12)^;
    PLongWord(OutBuffer)^ := IV0;
    PLongWord(PtrUInt(OutBuffer) + 4)^ := IV1;
    PLongWord(PtrUInt(OutBuffer) + 8)^ := IV2;
    PLongWord(PtrUInt(OutBuffer) + 12)^ := IV3;
    Inc(PtrUInt(Buffer), 16);
    Inc(PtrUInt(OutBuffer), 16);
  end;

  Dec(Size, Integer(Count) * FBlockSize);

  if Size > 0 then
  begin
    EncryptBlock16(IV0, IV1, IV2, IV3);
    UIntsToBlock16(IV0, IV1, IV2, IV3, FVector);

    for Index := 0 to Size - 1 do
      PByteArray(OutBuffer)^[Index] := PByteArray(Buffer)^[Index] xor FVector[Index];

    for Index := 0 to FBlockSize - Size - 1 do
      FVector[Index] := FVector[Index + Size];

    for Index := FBlockSize - Size to FBlockSize - 1 do
      FVector[Index] := PByteArray(OutBuffer)^[Index + Size - FBlockSize];

    Dec(FBytesLeft, Size);
    if FBytesLeft = 0 then FBytesLeft := FBlockSize;
  end
  else
    UIntsToBlock16(IV0, IV1, IV2, IV3, FVector);
end;

procedure TElBuiltInSymmetricCrypto.InternalEncryptGCM(Buffer, OutBuffer : pointer; Size : integer);
var
  Count, Index : integer;
  Block : ByteArray;
  IV0, IV1, IV2, IV3 : cardinal;
begin
  Count := Size div FBlockSize;
  SetLength(Block, FBlockSize);

  if not FAssociatedData then
    for Index := 0 to Count - 1 do
    begin
      IV0 := FGCMCtx.IV0;
      IV1 := FGCMCtx.IV1;
      IV2 := FGCMCtx.IV2;
      IV3 := FGCMCtx.IV3;
      EncryptBlock16(IV0, IV1, IV2, IV3);
      UIntsToBlock16(IV0, IV1, IV2, IV3, Block);
      PLongWord(OutBuffer)^ := PLongWord(@Block[0])^ xor PLongWord(Buffer)^;
      PLongWord(PtrUInt(OutBuffer) + 4)^ := PLongWord(@Block[4])^ xor PLongWord(PtrUInt(Buffer) + 4)^;
      PLongWord(PtrUInt(OutBuffer) + 8)^ := PLongWord(@Block[8])^ xor PLongWord(PtrUInt(Buffer) + 8)^;
      PLongWord(PtrUInt(OutBuffer) + 12)^ := PLongWord(@Block[12])^ xor PLongWord(PtrUInt(Buffer) + 12)^;
      SBMove(OutBuffer^, Block[0], FBlockSize);
      Inc(PtrUInt(Buffer), 16);
      Inc(PtrUInt(OutBuffer), 16);

      FGCMCtx.IV3 := SwapUInt32(SwapUInt32(FGCMCtx.IV3) + 1);
      GHASHUpdate(Block);
    end
  else
  begin
    for Index := 0 to Count - 1 do
    begin
      SBMove(Buffer^, Block[0], FBlockSize);
      //B0 := GetInt64BEFromByteArray(Block, 0);
      //B1 := GetInt64BEFromByteArray(Block, 8);
      GHASHUpdate(Block);
      Inc(PtrUInt(Buffer), FBlockSize);
    end;
  end;
  ReleaseArray(Block);
end;

procedure TElBuiltInSymmetricCrypto.InternalEncryptCCM(Buffer, OutBuffer : pointer; Size : integer);
var
  Index, Count : integer;
  Block : ByteArray;
  Y0, Y1, Y2, Y3 : cardinal;
  BufPtr :  pointer ;
begin
  Count := Size div FBlockSize;
  SetLength(Block, FBlockSize);

  { feeding data to 'hash' context }
  BufPtr :=  Buffer ;
  BlockToUints16(FAEADY, Y0, Y1, Y2, Y3);

  for Index := 0 to Count - 1 do
  begin
    Y0 := Y0 xor PLongWord(BufPtr)^;
    Y1 := Y1 xor PLongWord(PtrUInt(BufPtr) + 4)^;
    Y2 := Y2 xor PLongWord(PtrUInt(BufPtr) + 8)^;
    Y3 := Y3 xor PLongWord(PtrUInt(BufPtr) + 12)^;
    Inc(PtrUInt(BufPtr), 16);
    EncryptBlock16(Y0, Y1, Y2, Y3);
  end;

  UIntsToBlock16(Y0, Y1, Y2, Y3, FAEADY);

  { encrypting if data is payload }

  if not FAssociatedData then
    for Index := 0 to Count - 1 do
    begin
      BlockToUInts16(FVector, Y0, Y1, Y2, Y3);
      EncryptBlock16(Y0, Y1, Y2, Y3);
      PLongWord(OutBuffer)^ := Y0 xor PLongWord(Buffer)^;
      PLongWord(PtrUInt(OutBuffer) + 4)^ := Y1 xor PLongWord(PtrUInt(Buffer) + 4)^;
      PLongWord(PtrUInt(OutBuffer) + 8)^ := Y2 xor PLongWord(PtrUInt(Buffer) + 8)^;
      PLongWord(PtrUInt(OutBuffer) + 12)^ := Y3 xor PLongWord(PtrUInt(Buffer) + 12)^;
      Inc(PtrUInt(Buffer), 16);
      Inc(PtrUInt(OutBuffer), 16);
      CCMInc24(FVector, FVector);
    end;

  ReleaseArray(Block);
end;

procedure TElBuiltInSymmetricCrypto.EncryptUpdate(InBuffer: pointer; InSize : integer; OutBuffer: pointer;
  var OutSize : integer);
var
  EstimatedSize, OldSize, Count, Size : integer;
  InBufPtr, OutBufPtr : pointer;
begin
  // not doing anything for empty chunks of data
  if InSize = 0 then
  begin
    OutSize := 0;
    Exit;
  end;

  if IsStreamCipher or
    (FMode = cmCFB8) or
    (FMode = cmCTR)
  then
    EstimatedSize := InSize
  else if ((FMode = cmGCM) or
    (FMode = cmCCM)) and FAssociatedData then
  begin
    EstimatedSize := 0;
  end
  else
  begin
    Count := InSize + Length(FTail);
    EstimatedSize := Count - Count mod FBlockSize;
  end;

  (*if (EstimatedSize > 0) and ((OutBuffer = nil) or (OutSize = 0)) then
  begin
    OutSize := EstimatedSize;
    Exit;
  end;*)
  if ((OutBuffer = nil) or (OutSize = 0)) then
  begin
    // this is an "estimation" call, exiting without performing any job
    if (EstimatedSize = 0) then
      OutSize := 1 // a fake value to prevent user from passing zero size to a second call (otherwise their second call will be treated as another "estimation" call)
    else
      OutSize := EstimatedSize;
    Exit;
  end;

  if OutSize < EstimatedSize then
    raise EElSymmetricCryptoError.Create(SBufferTooSmall);

  if (FMode = cmCCM) then
  begin
    if FAssociatedData then
      FAEADASize := FAEADASize + InSize
    else
      FAEADPSize := FAEADPSize + InSize;
  end
  else if (FMode = cmGCM) then
  begin
    if FAssociatedData then
      Inc(FGCMCtx.ASize, InSize)
    else
      Inc(FGCMCtx.PSize, InSize);
  end;

  if IsStreamCipher then
  begin
    EncryptStreamBlock(InBuffer, OutBuffer, InSize);
    OutSize := InSize;
    Exit;
  end;

  if (FMode = cmCFB8) or
    (FMode = cmCTR) then
  begin
    FInternalEncryptFunction(InBuffer, OutBuffer, InSize);
    OutSize := InSize;
    Exit;
  end;

  InBufPtr := InBuffer;
  OutBufPtr := OutBuffer;

  OldSize := Length(FTail);

  if InSize + OldSize < FBlockSize then
  begin
    SetLength(FTail, OldSize + InSize);
    SBMove(InBuffer^, FTail[OldSize], InSize);
    Count := 0;
  end
  else
  if OldSize > 0 then
  begin
    SetLength(FTail, FBlockSize);
    Size := FBlockSize - OldSize;
    SBMove(InBuffer^, FTail[OldSize], Size);
    FInternalEncryptFunction(@FTail[0], OutBuffer, FBlockSize);
    InBufPtr := Pointer(PtrUInt(InBuffer) + Cardinal(Size));
    OutBufPtr := Pointer(PtrUInt(OutBuffer) + Cardinal(FBlockSize));
    Count := (InSize - Size) div FBlockSize;
    SetLength(FTail, (InSize - Size) mod FBlockSize);
    if Length(FTail) > 0 then
      SBMove(Pointer(PtrUInt(InBuffer) + Cardinal(Size) + Cardinal(Count * FBlockSize))^, FTail[0], Length(FTail));
  end
  else
  begin
    if FAssociatedData then
      Count := InSize div FBlockSize
    else
      Count := EstimatedSize div FBlockSize;
      
    SetLength(FTail, InSize mod FBlockSize);
    if Length(FTail) > 0 then
      SBMove(Pointer(PtrUInt(InBuffer) + Cardinal(Count * FBlockSize))^, FTail[0], Length(FTail));
  end;

  if Count > 0 then
    FInternalEncryptFunction(InBufPtr, OutBufPtr, Count * FBlockSize);
    
  OutSize := EstimatedSize;
end;


procedure TElBuiltInSymmetricCrypto.Encrypt(InBuffer: pointer; InSize : integer; OutBuffer: pointer;
  var OutSize : integer);
var
  EstimatedSize : integer;
  Count, OutCount : Integer;
  PtrIn, PtrOut :  ^byte ;
  TotalIn : integer;
const
  CHUNK_SIZE : integer = 65536;
begin
  if (not IsStreamCipher) and ((InSize mod FBlockSize) <> 0) and
     (FPadding = cpNone) and
     ((FMode = cmECB) or
      (FMode = cmCBC))
  then
    raise EElSymmetricCryptoError.Create(SInvalidPadding);

  EstimatedSize := EstimatedOutputSize(InSize, true);

  (*if (OutSize = 0) then
  begin
    OutSize := EstimatedSize;
    Exit;
  end;*)
  if ((OutBuffer = nil) or (OutSize = 0)) then
  begin
    // this is an "estimation" call, exiting without performing any job
    if EstimatedSize = 0 then
      OutSize := 1 // a fake value to prevent user from passing zero size to a second call (otherwise their second call will be treated as another "estimation" call)
    else
      OutSize := EstimatedSize;
    Exit;
  end;

  if (OutSize < EstimatedSize) then
    raise EElSymmetricCryptoError.Create(SBufferTooSmall);

  InitializeEncryption;
  PtrIn :=  InBuffer ;
  PtrOut :=  OutBuffer ;
  TotalIn := InSize;
  while InSize > 0 do
  begin
    Count := Min(CHUNK_SIZE, InSize);
    OutCount := OutSize;
    EncryptUpdate(PtrIn, Count, PtrOut, OutCount);
    Inc(PtrIn, Count);
    Inc(PtrOut, OutCount);
    Dec(InSize, Count);
    Dec(OutSize, OutCount);
    if not DoProgress(TotalIn, TotalIn - InSize) then
      raise EElSymmetricCryptoError.Create(SInterruptedByUser);
  end;
  FinalizeEncryption(PtrOut, OutSize);
  Inc(PtrOut, OutSize);
  OutSize := PtrUInt(PtrOut) - PtrUInt(OutBuffer);
end;

procedure TElBuiltInSymmetricCrypto.Encrypt(InStream : TElInputStream; OutStream: TElOutputStream);
var
  BytesLeft, Size, OutSize : integer;
  Buffer, OutBuffer : ByteArray;
begin

  BytesLeft := InStream. Size  - InStream.Position;

  if not IsStreamCipher then
  begin
    if ((BytesLeft mod FBlockSize) <> 0) and (FPadding = cpNone)
      and ((FMode = cmECB) or
           (FMode = cmCBC))
    then
      raise EElSymmetricCryptoError.Create(SInvalidPadding);
  end;    

  SetLength(Buffer, SYMMETRIC_BLOCK_SIZE);
  SetLength(OutBuffer, SYMMETRIC_BLOCK_SIZE);

  InitializeEncryption;

  while BytesLeft > 0 do begin
    Size := InStream.Read(Buffer[0], Min(SYMMETRIC_BLOCK_SIZE, BytesLeft));
    

    Dec(BytesLeft, Size);
    OutSize := SYMMETRIC_BLOCK_SIZE;
    EncryptUpdate(@Buffer[0], Size, @OutBuffer[0], OutSize);
    OutStream.Write(OutBuffer[0], OutSize);
  end;

  OutSize := SYMMETRIC_BLOCK_SIZE;
  FinalizeEncryption(@OutBuffer[0], OutSize);
  if OutSize > 0 then
    OutStream.Write(OutBuffer[0], OutSize);

end;

procedure TElBuiltInSymmetricCrypto.FinalizeEncryption(OutBuffer : pointer; var OutSize : integer);
var
  PadBytes, TmpBuf, ABuf : ByteArray;
  EstSize, Sz, i : integer;
  IV0, IV1, IV2, IV3 : cardinal;
begin

  PadBytes := EmptyArray;

  if IsStreamCipher then
  begin
    OutSize := 0;
    Exit;
  end;

  if (FMode = cmCTR) or
    (FMode = cmCFB8) then
  begin
    { no padding required }
    SetLength(FTail, 0);
    OutSize := 0;
    Exit;
  end
  else if (FMode = cmGCM) then
  begin
    EstSize := FTagSize;
    if (not FAssociatedData) then
      EstSize := EstSize + Length(FTail);

    (*if (OutBuffer = nil) or (OutSize < EstSize) then
    begin
      OutSize := EstSize;
      Exit;
    end;*)
    if ((OutBuffer = nil) or (OutSize = 0)) then
    begin
      // this is an "estimation" call, exiting without performing any job
      if EstSize = 0 then
        OutSize := 1 // a fake value to prevent user from passing zero size to a second call (otherwise their second call will be treated as another "estimation" call)
      else
        OutSize := EstSize;
      Exit;
    end;

    { encrypting and returning tail bytes }
    if Length(FTail) > 0 then
    begin
      Sz := Length(FTail);
      SetLength(FTail, 16);
      SetLength(TmpBuf, 16);

      for i := Sz to 15 do
        FTail[i] := 0;

      if FAssociatedData then
      begin
        GHASHUpdate(FTail);
        Sz := 0;
      end
      else
      begin
        IV0 := FGCMCtx.IV0;
        IV1 := FGCMCtx.IV1;
        IV2 := FGCMCtx.IV2;
        IV3 := FGCMCtx.IV3;
        EncryptBlock16(IV0, IV1, IV2, IV3);
        UIntsToBlock16(IV0, IV1, IV2, IV3, TmpBuf);

        for i := 0 to Sz - 1 do
          FTail[i] := FTail[i] xor TmpBuf[i];
        SBMove(FTail[0], OutBuffer^, Sz);
        for i := Sz to 15 do
          FTail[i] := 0;
        GHASHUpdate(FTail);
      end
    end
    else
      Sz := 0;

    { adding ALen & PLen to GHASH }
    SetLength(TmpBuf, 16);
    SetLength(ABuf, 16);

    FGCMCtx.ASize := FGCMCtx.ASize shl 3;
    FGCMCtx.PSize := FGCMCtx.PSize shl 3;

    GetByteArrayFromInt64BE(FGCMCtx.ASize, TmpBuf, 0);
    GetByteArrayFromInt64BE(FGCMCtx.PSize, TmpBuf, 8);
    GHASHUpdate(TmpBuf);

    GetByteArrayFromInt64BE(FGCMCtx.Ctr0, ABuf, 0);
    GetByteArrayFromInt64BE(FGCMCtx.Ctr1, ABuf, 8);

    EncryptBlockArr(ABuf, TmpBuf);

    GetByteArrayFromInt64BE(FGCMCtx.Y0, ABuf, 0);
    GetByteArrayFromInt64BE(FGCMCtx.Y1, ABuf, 8);

    for i := 0 to 15 do
      ABuf[i] := TmpBuf[i] xor ABuf[i];

    SBMove(ABuf[0], PByteArray(OutBuffer)^[Sz], FTagSize);
    OutSize := Sz + FTagSize;
    FOperation := coNone;
    Exit;
  end
  else if (FMode = cmCCM) then
  begin
    if (FAEADASize <> FAssociatedDataSize) or (FAEADPSize <> FPayloadSize) then
      raise EElBuiltInCryptoProviderError.Create(SInvalidInputSize);

    EstSize := FTagSize;
    if (not FAssociatedData) then
      EstSize := EstSize + Length(FTail);

    (*if (OutBuffer = nil) or (OutSize < EstSize) then
    begin
      OutSize := EstSize;
      Exit;
    end;*)
    if ((OutBuffer = nil) or (OutSize = 0)) then
    begin
      // this is an "estimation" call, exiting without performing any job
      if EstSize = 0 then
        OutSize := 1 // a fake value to prevent user from passing zero size to a second call (otherwise their second call will be treated as another "estimation" call)
      else
        OutSize := EstSize;
      Exit;
    end;

    if Length(FTail) > 0 then
    begin
      Sz := Length(FTail);
      SetLength(FTail, 16);
      SetLength(TmpBuf, 16);
      for i := Sz to FBlockSize - 1 do
        FTail[i] := 0;
      FInternalEncryptFunction(@FTail[0], @TmpBuf[0], FBlockSize);
      if not FAssociatedData then
        SBMove(TmpBuf[0], OutBuffer^, Sz)
      else
        Sz := 0;
    end
    else
      Sz := 0;

    SetLength(TmpBuf, 16);
    EncryptBlockArr(FAEADCtr0, TmpBuf);
    for i := 0 to 15 do
      FAEADY[i] := FAEADY[i] xor TmpBuf[i];

    SBMove(FAEADY[0], PByteArray(OutBuffer)^[Sz], FTagSize);
    OutSize := Sz + FTagSize;
    FOperation := coNone;
    Exit;
  end;

  { encrypting tail bytes, if are }
  if FPadding = cpPKCS5 then
  begin
    (*if OutBuffer = nil then
    begin
      OutSize := BlockSize;
      Exit;
    end;*)
    if ((OutBuffer = nil) or (OutSize = 0)) then
    begin
      // this is an "estimation" call, exiting without performing any job
      OutSize := BlockSize;
      Exit;
    end;
    if Length(FTail) = 0 then
      PadBytes := AddPadding(nil, 0)
    else
      PadBytes := AddPadding(@FTail[0], Length(FTail));
    SetLength(FTail, 0);

    EncryptUpdate(@PadBytes[0], Length(PadBytes), OutBuffer, OutSize);
  end
  else if Length(FTail) = 0 then
    OutSize := 0
  else
    raise EElSymmetricCryptoError.Create(SInvalidPadding);
  FOperation := coNone;    


  { must be called as inherited; in descendant classes }
end;

procedure TElBuiltInSymmetricCrypto.InitializeDecryption;
begin
  SetLength(FVector, Length(FKeyMaterial.IV));

  if Length(FVector) > 0 then
    SBMove(FKeyMaterial.IV[0], FVector[0], Length(FVector));

  if (FMode = cmCTR) or
    (FMode = cmCFB8)
  then
    FBytesLeft := FBlockSize;

  SetLength(FTail, 0);
  SetLength(FPadBytes, 0);

  if (FMode = cmCBC) or
    (FMode = cmECB)
  then
    ExpandKeyForDecryption
  else
    ExpandKeyForEncryption;

  InternalDecryptInit;
  FOperation := coDecryption;
end;

procedure TElBuiltInSymmetricCrypto.InternalDecryptInit;
begin
  if IsStreamCipher then
    Exit
  else if (FMode = cmECB) and (FBlockSize = 8) then
    FInternalDecryptFunction :=  InternalDecryptECB8 
  else if (FMode = cmECB) and (FBlockSize = 16) then
    FInternalDecryptFunction :=  InternalDecryptECB16 
  else if (FMode = cmCBC) and (FBlockSize = 8) then
    FInternalDecryptFunction :=  InternalDecryptCBC8 
  else if (FMode = cmCBC) and (FBlockSize = 16) then
    FInternalDecryptFunction :=  InternalDecryptCBC16 
  else if (FMode = cmCTR) and (FBlockSize = 8) then
    FInternalDecryptFunction :=  InternalEncryptCTR8  // for CTR mode operation is the same as encryption
  else if (FMode = cmCTR) and (FBlockSize = 16) then
    FInternalDecryptFunction :=  InternalEncryptCTR16 
  else if (FMode = cmCFB8) and (FBlockSize = 8) then
    FInternalDecryptFunction :=  InternalDecryptCFB88 
  else if (FMode = cmCFB8) and (FBlockSize = 16) then
    FInternalDecryptFunction :=  InternalDecryptCFB816 
  else if (FMode = cmGCM) and (FBlockSize = 16) then
  begin
    FInternalDecryptFunction :=  InternalDecryptGCM ;
    InitializeGCM;
  end
  else if (FMode = cmCCM) then
  begin
    FInternalDecryptFunction :=  InternalDecryptCCM ;
    InitializeCCM;
  end
  else if (FMode = cmDefault) and (IsStreamCipher) then
    FInternalDecryptFunction := nil
  else
    raise EElSymmetricCryptoError.Create(SInvalidCipherMode);
end;

procedure TElBuiltInSymmetricCrypto.DecryptUpdate(InBuffer: pointer; InSize : integer;
  OutBuffer: pointer; var OutSize : integer);
var
  EstimatedSize, OldSize, Count, Size, OutBytes : integer;
  InBufPtr, OutBufPtr : pointer;
begin
  // not doing anything for empty chunks of data
  if InSize = 0 then
  begin
    OutSize := 0;
    Exit;
  end;

  if IsStreamCipher then
    EstimatedSize := InSize
  else
  if (FMode = cmCTR) or
    (FMode = cmCFB8)
  then
    EstimatedSize := InSize
  else if (FMode = cmCCM) or
    (FMode = cmGCM)
  then
    EstimatedSize := 0 // all data is returned in FinalizeDecryption
  else
  begin
    Count := InSize + Length(FTail);
    EstimatedSize := Count - Count mod FBlockSize;
  end;

  (*if (OutSize = 0) and (EstimatedSize > 0) then
  begin
    OutSize := EstimatedSize;
    Exit;
  end;*)
  if ((OutBuffer = nil) or (OutSize = 0)) then
  begin
    // this is an "estimation" call, exiting without performing any job
    if EstimatedSize = 0 then
      OutSize := 1 // a fake value to prevent user from passing zero size to a second call (otherwise their second call will be treated as another "estimation" call)
    else
      OutSize := EstimatedSize;
    Exit;
  end;

  if OutSize < EstimatedSize then
    raise EElSymmetricCryptoError.Create(SBufferTooSmall);

  if (FMode = cmCCM) then
  begin
    if FAssociatedData then
      FAEADASize := FAEADASize + InSize
    else
      FAEADPSize := FAEADPSize + InSize;
  end
  else if (FMode = cmGCM) then
  begin
    if FAssociatedData then
      Inc(FGCMCtx.ASize, InSize)
    else
      Inc(FGCMCtx.PSize, InSize)    
  end;

  if IsStreamCipher then
  begin
    DecryptStreamBlock(InBuffer, OutBuffer, InSize);
    OutSize := InSize;
    Exit;
  end;

  if (FMode = cmCTR) or
    (FMode = cmCFB8)
  then
  begin
    FInternalDecryptFunction(InBuffer, OutBuffer, InSize);
    OutSize := InSize;
    Exit;
  end
  else if (FMode = cmCCM) or
    (FMode = cmGCM)
  then
  begin
    OldSize := Length(FTail);
    SetLength(FTail, OldSize + InSize);
    { for GCM/CCM all data will be decrypted in .FinalizeDecryption method }
    SBMove(InBuffer^, FTail[OldSize], InSize);
    OutSize := 0;
    Exit;
  end;

  OldSize := Length(FTail);
  OutBytes := 0;

  InBufPtr := InBuffer;
  OutBufPtr := OutBuffer;

  if InSize + OldSize < FBlockSize then
  begin
    SetLength(FTail, OldSize + InSize);
    SBMove(InBuffer^, FTail[OldSize], InSize);
    Count := 0;
  end
  else
  if OldSize > 0 then
  begin
    SetLength(FTail, FBlockSize);
    Size := FBlockSize - OldSize;
    SBMove(InBuffer^, FTail[OldSize], Size);

    if (FPadding <> cpNone) then
    begin
      if Length(FPadBytes) > 0 then
      begin
        SBMove(FPadBytes[0], OutBuffer^, FBlockSize);
        Inc(OutBytes, FBlockSize);
      end
      else
        SetLength(FPadBytes, FBlockSize);

      FInternalDecryptFunction(@FTail[0], @FPadBytes[0], FBlockSize);
    end
    else
    begin
      FInternalDecryptFunction(@FTail[0], OutBuffer, FBlockSize);
      Inc(OutBytes, FBlockSize);
    end;

    InBufPtr := Pointer(PtrUInt(InBuffer) + Cardinal(Size));
    OutBufPtr := Pointer(PtrUInt(OutBuffer) + Cardinal(OutBytes));

    Count := (InSize - Size) div FBlockSize;
    SetLength(FTail, (InSize - Size) mod FBlockSize);
    if Length(FTail) > 0 then
      SBMove(Pointer(PtrUInt(InBufPtr) + Cardinal(Count * FBlockSize))^, FTail[0], Length(FTail));
  end
  else
  begin
    InBufPtr := InBuffer;
    OutBufPtr := OutBuffer;
    Count := EstimatedSize div FBlockSize;
    SetLength(FTail, InSize mod FBlockSize);
    if Length(FTail) > 0 then
      SBMove(Pointer(PtrUInt(InBuffer) + Cardinal(Count * FBlockSize))^, FTail[0], Length(FTail));
  end;

  if Count > 0 then
  begin
    { dealing with last block of decrypted data, which can represent padding }
    if FPadding <> cpNone then
    begin
      if Length(FPadBytes) > 0 then
      begin
        SBMove(FPadBytes[0], OutBufPtr^, FBlockSize);
        OutBufPtr := Pointer(PtrUInt(OutBufPtr) + Cardinal(FBlockSize));

        Inc(OutBytes, FBlockSize);
      end
      else
        SetLength(FPadBytes, FBlockSize);

      if Count > 1 then
      begin
        FInternalDecryptFunction(InBufPtr, OutBufPtr, (Count - 1) * FBlockSize);
        InBufPtr := Pointer(PtrUInt(InBufPtr) + Cardinal((Count - 1) * FBlockSize));
        Inc(OutBytes, (Count - 1) * FBlockSize);
      end;
      FInternalDecryptFunction(InBufPtr, @FPadBytes[0], FBlockSize);
    end
    else
    begin
      FInternalDecryptFunction(InBufPtr, OutBufPtr, Count * FBlockSize);
      Inc(OutBytes, Count * FBlockSize);
    end;
  end;
  OutSize := OutBytes;
end;

procedure TElBuiltInSymmetricCrypto.InternalDecryptECB8(Buffer, OutBuffer : pointer; Size : integer);
var
  Index, Count : integer;
  B0, B1 : cardinal;
begin
  Count := Size div FBlockSize;

  for Index := 0 to Count - 1 do
  begin
    B0 := PLongWord(Buffer)^;
    B1 := PLongWord(PtrUInt(Buffer) + 4)^;
    Inc(PtrUInt(Buffer), 8);

    DecryptBlock8(B0, B1);

    PLongWord(OutBuffer)^ := B0;
    PLongWord(PtrUInt(OutBuffer) + 4)^ := B1;
    Inc(PtrUInt(OutBuffer), 8);
  end;
end;

procedure TElBuiltInSymmetricCrypto.InternalDecryptECB16(Buffer, OutBuffer : pointer; Size : integer);
var
  Index, Count : integer;
  B0, B1, B2, B3 : cardinal;
begin
  Count := Size div FBlockSize;

  for Index := 0 to Count - 1 do
  begin
    B0 := PLongWord(Buffer)^;
    B1 := PLongWord(PtrUInt(Buffer) + 4)^;
    B2 := PLongWord(PtrUInt(Buffer) + 8)^;
    B3 := PLongWord(PtrUInt(Buffer) + 12)^;
    Inc(PtrUInt(Buffer), 16);

    DecryptBlock16(B0, B1, B2, B3);

    PLongWord(OutBuffer)^ := B0;
    PLongWord(PtrUInt(OutBuffer) + 4)^ := B1;
    PLongWord(PtrUInt(OutBuffer) + 8)^ := B2;
    PLongWord(PtrUInt(OutBuffer) + 12)^ := B3;
    Inc(PtrUInt(OutBuffer), 16);
  end;
end;

procedure TElBuiltInSymmetricCrypto.InternalDecryptCBC8(Buffer, OutBuffer : pointer; Size : integer);
var
  Index, Count : integer;
  C0, C1, B0, B1, IV0, IV1 : cardinal;
begin
  if Length(FVector) <> FBlockSize then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  Count := Size div FBlockSize;
  BlockToUInts8(FVector, IV0, IV1);

  for Index := 0 to Count - 1 do
  begin
    B0 := PLongWord(Buffer)^;
    B1 := PLongWord(PtrUInt(Buffer) + 4)^;
    C0 := B0;
    C1 := B1;
    DecryptBlock8(B0, B1);
    PLongWord(OutBuffer)^ := IV0 xor B0;
    PLongWord(PtrUInt(OutBuffer) + 4)^ := IV1 xor B1;
    IV0 := C0;
    IV1 := C1;
    Inc(PtrUInt(Buffer), 8);
    Inc(PtrUInt(OutBuffer), 8);
  end;

  UIntsToBlock8(IV0, IV1, FVector);
end;

procedure TElBuiltInSymmetricCrypto.InternalDecryptCBC16(Buffer, OutBuffer : pointer; Size : integer);
var
  Index, Count : integer;
  C0, C1, C2, C3, B0, B1, B2, B3, IV0, IV1, IV2, IV3 : cardinal;
begin
  if Length(FVector) <> FBlockSize then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  Count := Size div FBlockSize;
  BlockToUInts16(FVector, IV0, IV1, IV2, IV3);

  for Index := 0 to Count - 1 do
  begin
    B0 := PLongWord(Buffer)^;
    B1 := PLongWord(PtrUInt(Buffer) + 4)^;
    B2 := PLongWord(PtrUInt(Buffer) + 8)^;
    B3 := PLongWord(PtrUInt(Buffer) + 12)^;
    C0 := B0;
    C1 := B1;
    C2 := B2;
    C3 := B3;
    DecryptBlock16(B0, B1, B2, B3);
    PLongWord(OutBuffer)^ := IV0 xor B0;
    PLongWord(PtrUInt(OutBuffer) + 4)^ := IV1 xor B1;
    PLongWord(PtrUInt(OutBuffer) + 8)^ := IV2 xor B2;
    PLongWord(PtrUInt(OutBuffer) + 12)^ := IV3 xor B3;
    IV0 := C0;
    IV1 := C1;
    IV2 := C2;
    IV3 := C3;
    Inc(PtrUInt(Buffer), 16);
    Inc(PtrUInt(OutBuffer), 16);
  end;

  UIntsToBlock16(IV0, IV1, IV2, IV3, FVector);
end;

procedure TElBuiltInSymmetricCrypto.InternalDecryptCFB88(Buffer, OutBuffer : pointer; Size : integer);
var
  Index, Count : integer;
  B0, B1, IV0, IV1 : cardinal;
begin
  if Length(FVector) <> FBlockSize then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  if FBytesLeft < FBlockSize then
  begin
    Count := Min(FBytesLeft, Size);
    for Index := 0 to Count - 1 do
      PByteArray(OutBuffer)^[Index] := PByteArray(Buffer)^[Index] xor FVector[Index];

    for Index := 0 to FBlockSize - Integer(Count) - 1 do
      FVector[Index] := FVector[Index + Integer(Count)];

    for Index := FBlockSize - Integer(Count) to FBlockSize - 1 do
      FVector[Index] := PByteArray(Buffer)^[Index  + Integer(Count) - FBlockSize];

    Dec(FBytesLeft, Count);
    Inc( PtrUInt(OutBuffer) , Count);
    Inc( PtrUInt(Buffer) , Count);
    Dec(Size, Count);
    if FBytesLeft = 0 then
      FBytesLeft := FBlockSize;
  end;

  BlockToUInts8(FVector, IV0, IV1);
  Count := Size div FBlockSize;

  for Index := 0 to Count - 1 do
  begin
    EncryptBlock8(IV0, IV1);
    B0 := PLongWord(Buffer)^;
    B1 := PLongWord(PtrUInt(Buffer) + 4)^;
    PLongWord(OutBuffer)^ := IV0 xor B0;
    PLongWord(PtrUInt(OutBuffer) + 4)^ := IV1 xor B1;
    IV0 := B0;
    IV1 := B1;
    Inc(PtrUInt(Buffer), 8);
    Inc(PtrUInt(OutBuffer), 8);
  end;

  Dec(Size, Integer(Count) * FBlockSize);

  if Size > 0 then
  begin
    EncryptBlock8(IV0, IV1);
    UIntsToBlock8(IV0, IV1, FVector);

    for Index := 0 to Size - 1 do
      PByteArray(OutBuffer)^[Index] := PByteArray(Buffer)^[Index] xor FVector[Index];

    for Index := 0 to FBlockSize - Size - 1 do
      FVector[Index] := FVector[Index + Size];

    for Index := FBlockSize - Size to FBlockSize - 1 do
      FVector[Index] := PByteArray(Buffer)^[Index + Size - FBlockSize];

    Dec(FBytesLeft, Size);
    if FBytesLeft = 0 then FBytesLeft := FBlockSize;
  end
  else
    UIntsToBlock8(IV0, IV1, FVector);
end;

procedure TElBuiltInSymmetricCrypto.InternalDecryptCFB816(Buffer, OutBuffer : pointer; Size : integer);
var
  Index, Count : integer;
  B0, B1, B2, B3, IV0, IV1, IV2, IV3: cardinal;
begin
  if Length(FVector) <> FBlockSize then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  if FBytesLeft < FBlockSize then
  begin
    Count := Min(FBytesLeft, Size);
    for Index := 0 to Count - 1 do
      PByteArray(OutBuffer)^[Index] := PByteArray(Buffer)^[Index] xor FVector[Index];

    for Index := 0 to FBlockSize - Integer(Count) - 1 do
      FVector[Index] := FVector[Index + Integer(Count)];

    for Index := FBlockSize - Integer(Count) to FBlockSize - 1 do
      FVector[Index] := PByteArray(Buffer)^[Index  + Integer(Count) - FBlockSize];

    Dec(FBytesLeft, Count);
    Inc( PtrUInt(OutBuffer) , Count);
    Inc( PtrUInt(Buffer) , Count);
    Dec(Size, Count);
    if FBytesLeft = 0 then
      FBytesLeft := FBlockSize;
  end;

  BlockToUInts16(FVector, IV0, IV1, IV2, IV3);
  Count := Size div FBlockSize;

  for Index := 0 to Count - 1 do
  begin
    EncryptBlock16(IV0, IV1, IV2, IV3);
    B0 := PLongWord(Buffer)^;
    B1 := PLongWord(PtrUInt(Buffer) + 4)^;
    B2 := PLongWord(PtrUInt(Buffer) + 8)^;
    B3 := PLongWord(PtrUInt(Buffer) + 12)^;

    PLongWord(OutBuffer)^ := IV0 xor B0;
    PLongWord(PtrUInt(OutBuffer) + 4)^ := IV1 xor B1;
    PLongWord(PtrUInt(OutBuffer) + 8)^ := IV2 xor B2;
    PLongWord(PtrUInt(OutBuffer) + 12)^ := IV3 xor B3;

    IV0 := B0;
    IV1 := B1;
    IV2 := B2;
    IV3 := B3;
    Inc(PtrUInt(Buffer), 16);
    Inc(PtrUInt(OutBuffer), 16);
  end;

  Dec(Size, Integer(Count) * FBlockSize);

  if Size > 0 then
  begin
    EncryptBlock16(IV0, IV1, IV2, IV3);
    UIntsToBlock16(IV0, IV1, IV2, IV3, FVector);

    for Index := 0 to Size - 1 do
      PByteArray(OutBuffer)^[Index] := PByteArray(Buffer)^[Index] xor FVector[Index];

    for Index := 0 to FBlockSize - Size - 1 do
      FVector[Index] := FVector[Index + Size];

    for Index := FBlockSize - Size to FBlockSize - 1 do
      FVector[Index] := PByteArray(Buffer)^[Index + Size - FBlockSize];

    Dec(FBytesLeft, Size);
    if FBytesLeft = 0 then FBytesLeft := FBlockSize;
  end
  else
    UIntsToBlock16(IV0, IV1, IV2, IV3, FVector);
end;

procedure TElBuiltInSymmetricCrypto.InternalDecryptGCM(Buffer, OutBuffer : pointer; Size : integer);
var
  Index, Count : integer;
  Block : ByteArray;
  IV0, IV1, IV2, IV3 : cardinal;
begin
  Count := Size div FBlockSize;
  SetLength(Block, FBlockSize);

  if not FAssociatedData then
  begin
    for Index := 0 to Count - 1 do
    begin
      SBMove(Buffer^, Block[0], FBlockSize);
      GHASHUpdate(Block);

      IV0 := FGCMCtx.IV0;
      IV1 := FGCMCtx.IV1;
      IV2 := FGCMCtx.IV2;
      IV3 := FGCMCtx.IV3;
      EncryptBlock16(IV0, IV1, IV2, IV3);
      UIntsToBlock16(IV0, IV1, IV2, IV3, Block);
      PLongWord(OutBuffer)^ := PLongWord(@Block[0])^ xor PLongWord(Buffer)^;
      PLongWord(PtrUInt(OutBuffer) + 4)^ := PLongWord(@Block[4])^ xor PLongWord(PtrUInt(Buffer) + 4)^;
      PLongWord(PtrUInt(OutBuffer) + 8)^ := PLongWord(@Block[8])^ xor PLongWord(PtrUInt(Buffer) + 8)^;
      PLongWord(PtrUInt(OutBuffer) + 12)^ := PLongWord(@Block[12])^ xor PLongWord(PtrUInt(Buffer) + 12)^;
      Inc(PtrUInt(Buffer), 16);
      Inc(PtrUInt(OutBuffer), 16);
      FGCMCtx.IV3 := SwapUInt32(SwapUInt32(FGCMCtx.IV3) + 1);
    end
  end
  else
  begin
    for Index := 0 to Count - 1 do
    begin
      SBMove(Buffer^, Block[0], FBlockSize);
      GHASHUpdate(Block);
      Inc(PtrUInt(Buffer), 16);
    end;
  end;
  ReleaseArray(Block);
end;

procedure TElBuiltInSymmetricCrypto.InternalDecryptCCM(Buffer, OutBuffer : pointer; Size : integer);
var
  Index, Count : integer;
  Block : ByteArray;
  IV0, IV1, IV2, IV3 : cardinal;
begin
  Count := Size div FBlockSize;
  SetLength(Block, FBlockSize);

  if not FAssociatedData then
  begin
    { decrypting if data is payload }
    for Index := 0 to Count - 1 do
    begin
      BlockToUInts16(FVector, IV0, IV1, IV2, IV3);
      EncryptBlock16(IV0, IV1, IV2, IV3);
      IV0 := IV0 xor PLongWord(Buffer)^;
      IV1 := IV1 xor PLongWord(PtrUInt(Buffer) + 4)^;
      IV2 := IV2 xor PLongWord(PtrUInt(Buffer) + 8)^;
      IV3 := IV3 xor PLongWord(PtrUInt(Buffer) + 12)^;

      PLongWord(OutBuffer)^ := IV0;
      PLongWord(PtrUInt(OutBuffer) + 4)^ := IV1;
      PLongWord(PtrUInt(OutBuffer) + 8)^ := IV2;
      PLongWord(PtrUInt(OutBuffer) + 12)^ := IV3;

      IV0 := IV0 xor PLongWord(@FAEADY[0])^;
      IV1 := IV1 xor PLongWord(@FAEADY[4])^;
      IV2 := IV2 xor PLongWord(@FAEADY[8])^;
      IV3 := IV3 xor PLongWord(@FAEADY[12])^;

      Inc(PtrUInt(Buffer), 16);
      Inc(PtrUInt(OutBuffer), 16);
      EncryptBlock16(IV0, IV1, IV2, IV3);
      UIntsToBlock16(IV0, IV1, IV2, IV3, FAEADY);
      CCMInc24(FVector, FVector);
    end;
  end
  else
  begin
    { feeding data to 'hash' context }
    for Index := 0 to Count - 1 do
    begin
      IV0 := PLongWord(@FAEADY[0])^ xor PLongWord(Buffer)^;
      IV1 := PLongWord(@FAEADY[4])^ xor PLongWord(PtrUInt(Buffer) + 4)^;
      IV2 := PLongWord(@FAEADY[8])^ xor PLongWord(PtrUInt(Buffer) + 8)^;
      IV3 := PLongWord(@FAEADY[12])^ xor PLongWord(PtrUInt(Buffer) + 12)^;
      Inc(PtrUInt(Buffer), 16);
      EncryptBlock16(IV0, IV1, IV2, IV3);
      UIntsToBlock16(IV0, IV1, IV2, IV3, FAEADY);
    end;
  end;
  ReleaseArray(Block);
end;


procedure TElBuiltInSymmetricCrypto.Decrypt(InBuffer: pointer; InSize : integer; OutBuffer: pointer;
  var OutSize : integer);
var
  EstimatedSize, Count : integer;
begin
  if (not IsStreamCipher) and ((InSize mod FBlockSize) <> 0)
    and ((FMode = cmECB) or 
         (FMode = cmCBC))
  then
    raise EElSymmetricCryptoError.Create(SInvalidInputSize);


  EstimatedSize := EstimatedOutputSize(InSize, false);
  (*if (OutSize = 0) then
  begin
    OutSize := EstimatedSize;
    Exit;
  end;*)
  if ((OutBuffer = nil) or (OutSize = 0)) then
  begin
    // this is an "estimation" call, exiting without performing any job
    if EstimatedSize = 0 then
      OutSize := 1 // a fake value to prevent user from passing zero size to a second call (otherwise their second call will be treated as another "estimation" call)
    else
      OutSize := EstimatedSize;
    Exit;
  end;
  if (OutSize < EstimatedSize) then
    raise EElSymmetricCryptoError.Create(SBufferTooSmall);

  InitializeDecryption;
  Count := OutSize;
  DecryptUpdate(InBuffer, InSize, OutBuffer, Count);
  Dec(OutSize, Count);
  FinalizeDecryption(Pointer(PtrUInt(OutBuffer) + Cardinal(Count)), OutSize);
  Inc(OutSize, Count);
end;

procedure TElBuiltInSymmetricCrypto.Decrypt(InStream : TElInputStream; OutStream: TElOutputStream;
  InCount : integer  =  0);
var
  BytesLeft, Size, OutSize, Processed : integer;
  Buffer, OutBuffer : ByteArray;
begin

  if InCount = 0 then
    BytesLeft := InStream. Size  - InStream.Position
  else
    BytesLeft := Min(InCount, InStream. Size  - InStream.Position);

  if (not IsStreamCipher) and ((BytesLeft mod FBlockSize) <> 0) and
    ((FMode = cmECB) or 
     (FMode = cmCBC))
  then
    raise EElSymmetricCryptoError.Create(SInvalidPadding);

  SetLength(Buffer, SYMMETRIC_BLOCK_SIZE);
  SetLength(OutBuffer, SYMMETRIC_BLOCK_SIZE);
  Processed := 0;

  InitializeDecryption;

  if not DoProgress(BytesLeft + Processed, Processed) then
    raise EElSymmetricCryptoError.Create(SInterruptedByUser);

  while BytesLeft > 0 do begin
    Size := InStream.Read(Buffer[0], Min(SYMMETRIC_BLOCK_SIZE, BytesLeft));
    
    
    Dec(BytesLeft, Size);
    OutSize := SYMMETRIC_BLOCK_SIZE;
    DecryptUpdate(@Buffer[0], Size, @OutBuffer[0], OutSize);
    OutStream.Write(OutBuffer[0], OutSize);
    Inc(Processed, Size);
    if not DoProgress(BytesLeft + Processed, Processed) then
      raise EElSymmetricCryptoError.Create(SInterruptedByUser);
  end;

  OutSize := SYMMETRIC_BLOCK_SIZE;
  FinalizeDecryption(@OutBuffer[0], OutSize);
  if OutSize > 0 then
    OutStream.Write(OutBuffer[0], OutSize);
  if not DoProgress(Processed, Processed) then
    raise EElSymmetricCryptoError.Create(SInterruptedByUser);

end;

procedure TElBuiltInSymmetricCrypto.FinalizeDecryption(OutBuffer : pointer; var OutSize : integer);
var
  EstimatedSize, Size, i: integer;
  Block, Tag, OutArr, ABuf : ByteArray;
begin

  if IsStreamCipher then begin
    OutSize := 0;
    Exit;
  end;

  if (FMode = cmCTR) or
    (FMode = cmCFB8) then
  begin
    { no padding }
    SetLength(FTail, 0);
    OutSize := 0;
    Exit;
  end
  else if (FMode = cmCCM) then
  begin
    EstimatedSize := Length(FTail) - FTagSize;
    (*if OutSize < EstimatedSize then
    begin
      OutSize := EstimatedSize;
      Exit;
    end;*)
    if ((OutBuffer = nil) or (OutSize = 0)) then
    begin
      // this is an "estimation" call, exiting without performing any job
      if EstimatedSize = 0 then
        OutSize := 1 // a fake value to prevent user from passing zero size to a second call (otherwise their second call will be treated as another "estimation" call)
      else
        OutSize := EstimatedSize;
      Exit;
    end;

    if (FAEADASize <> FAssociatedDataSize) or (FAEADPSize <> FPayloadSize + FTagSize) then
    begin
      OutSize := -1;
      Exit;
    end;

    SetLength(Tag, FTagSize);
    SetLength(Block, FBlockSize);
    SBMove(FTail[EstimatedSize], Tag[0], FTagSize);

    Size := EstimatedSize - EstimatedSize mod FBlockSize;
    SetLength(OutArr, EstimatedSize);
    FInternalDecryptFunction(@FTail[0], @OutArr[0], Size);

    if EstimatedSize mod FBlockSize > 0 then
    begin
      EncryptBlockArr(FVector, Block);
      for i := 0 to EstimatedSize mod FBlockSize - 1 do
      begin
        OutArr[Size + i] := FTail[Size + i] xor Block[i];
        Block[i] := FAEADY[i] xor OutArr[Size + i];
      end;
      for i := EstimatedSize mod FBlockSize to FBlockSize - 1 do
        Block[i] := FAEADY[i];

      EncryptBlockArr(Block, FAEADY);
    end;

    EncryptBlockArr(FAEADCtr0, Block);

    for i := 0 to FBlockSize - 1 do
      FAEADY[i] := FAEADY[i] xor Block[i];

    if CompareMem(@FAEADY[0], @Tag[0], FTagSize) then
    begin
      SBMove(OutArr[0], OutBuffer^, EstimatedSize);
      OutSize := EstimatedSize;
    end
    else
      OutSize := -1;
    Exit;
  end
  else if (FMode = cmGCM) then
  begin
    EstimatedSize := Length(FTail) - FTagSize;
    (*if OutSize < EstimatedSize then
    begin
      OutSize := EstimatedSize;
      Exit;
    end;*)
    if ((OutBuffer = nil) or (OutSize = 0)) then
    begin
      // this is an "estimation" call, exiting without performing any job
      if EstimatedSize = 0 then
        OutSize := 1 // a fake value to prevent user from passing zero size to a second call (otherwise their second call will be treated as another "estimation" call)
      else
        OutSize := EstimatedSize;
      Exit;
    end;

    SetLength(Tag, FTagSize);
    SetLength(Block, FBlockSize);
    SetLength(ABuf, FBlockSize);    
    SBMove(FTail[EstimatedSize], Tag[0], FTagSize);
    Size := ((EstimatedSize + FBlockSize - 1) div FBlockSize) * FBlockSize;
    SetLength(FTail, Size);
    for i := EstimatedSize to Size - 1 do
      FTail[i] := 0;
    SetLength(OutArr, Size);
    FInternalDecryptFunction(@FTail[0], @OutArr[0], Size);

    FGCMCtx.ASize := FGCMCtx.ASize shl 3;
    FGCMCtx.PSize := (FGCMCtx.PSize - FTagSize) shl 3;

    GetByteArrayFromInt64BE(FGCMCtx.ASize, Block, 0);
    GetByteArrayFromInt64BE(FGCMCtx.PSize, Block, 8);
    GHASHUpdate(Block);

    GetByteArrayFromInt64BE(FGCMCtx.Ctr0, ABuf, 0);
    GetByteArrayFromInt64BE(FGCMCtx.Ctr1, ABuf, 8);
    EncryptBlockArr(ABuf, Block);

    GetByteArrayFromInt64BE(FGCMCtx.Y0, ABuf, 0);
    GetByteArrayFromInt64BE(FGCMCtx.Y1, ABuf, 8);

    for i := 0 to 15 do
      ABuf[i] := ABuf[i] xor Block[i];

    if CompareMem(@ABuf[0], @Tag[0], FTagSize) then
    begin
      SBMove(OutArr[0], OutBuffer^, EstimatedSize);
      OutSize := EstimatedSize;
    end
    else
      OutSize := -1;
    Exit;
  end;

  if (Length(FTail) > 0) and ((FPadding <> cpNone) or
    (FMode = cmCBC) or
    (FMode = cmECB))
  then
    raise EElSymmetricCryptoError.Create(SInvalidPadding);

  if FPadding = cpNone then
  begin
    if Length(FTail) > 0 then
    begin
      if (OutBuffer = nil) or (OutSize = 0) then
      begin
        OutSize := Length(FTail);
        Exit;
      end
      else
        if OutSize < Length(FTail) then
          raise EElSymmetricCryptoError.Create(SBufferTooSmall);

      OutSize := Length(FTail);
      SetLength(FTail, FBlockSize);
      SetLength(Block, FBlockSize);
      FInternalDecryptFunction(@FTail[0], @Block[0], FBlockSize);
      SBMove(Block[0], OutBuffer^, OutSize);
    end
    else
      OutSize := 0;
  end
  else if Length(FPadBytes) > 0 then
  begin
    if FPadding = cpNone then
      EstimatedSize := FBlockSize
    else if FPadding = cpPKCS5 then
      EstimatedSize := FBlockSize - FPadBytes[FBlockSize - 1]
    else
      raise EElSymmetricCryptoError.Create(SInternalException);

    if (EstimatedSize < 0) or
       (EstimatedSize > FBlockSize) then
      raise EElSymmetricCryptoError.Create(SInvalidPadding); 

    (*if OutSize = 0 then
    begin
      OutSize := EstimatedSize;
      Exit;
    end;*)
    if ((OutBuffer = nil) or (OutSize = 0)) then
    begin
      // this is an "estimation" call, exiting without performing any job
      if EstimatedSize = 0 then
        OutSize := 1 // a fake value to prevent user from passing zero size to a second call (otherwise their second call will be treated as another "estimation" call)
      else
        OutSize := EstimatedSize;
      Exit;
    end;
    if OutSize < EstimatedSize then
      raise EElSymmetricCryptoError.Create(SBufferTooSmall);

    OutSize := EstimatedSize;
    SBMove(FPadBytes[0], OutBuffer^, EstimatedSize);
    SetLength(FPadBytes, 0);
  end
  else
    OutSize := 0;

  FOperation := coNone;    

   
  { must be called as inherited; in descendant classes }
end;

function TElBuiltInSymmetricCrypto.AddPadding(Block : pointer; Size : integer) : ByteArray;
var
  Index : integer;
begin
  if Size >= FBlockSize then
    raise EElSymmetricCryptoError.Create(SInternalError);

  if FPadding = cpNone then
  begin
    SetLength(Result, Size);
    if Size > 0 then
      SBMove(Block^, Result[0], Size);
  end
  else if FPadding = cpPKCS5 then
  begin
    SetLength(Result, FBlockSize);
    SBMove(Block^, Result[0], Size);
    for Index := Size to FBlockSize - 1 do
      Result[Index] := FBlockSize - Size;
  end
  else
    raise EElSymmetricCryptoError.Create(SInternalError);
end;

procedure TElBuiltInSymmetricCrypto.IncrementCounter8(var C0, C1 : cardinal);
var
  Buf : ByteArray;
  Index : integer;
begin
  if not FCTRLittleEndian then
  begin
    SetLength(Buf, 8);
    UIntsToBlock8(C0, C1, Buf);
    for Index := 7 downto 0 do
      if (Buf[Index] = $ff) then
        Buf[Index] := 0
      else
      begin
        Inc(Buf[Index]);
        Break;
      end;
    BlockToUInts8(Buf, C0, C1);
    ReleaseArray(Buf);
  end
  else
  begin
    if (C0 < $ffffffff) then
      Inc(C0)
    else
    begin
      C0 := 0;
      Inc(C1);
    end;
  end;
end;

procedure TElBuiltInSymmetricCrypto.IncrementCounter16(var C0, C1, C2, C3 : cardinal);
var
  Buf : ByteArray;
  Index : integer;
begin
  if not FCTRLittleEndian then
  begin
    SetLength(Buf, 16);
    UIntsToBlock16(C0, C1, C2, C3, Buf);
    for Index := 15 downto 0 do
      if (Buf[Index] = $ff) then
        Buf[Index] := 0
      else
      begin
        Inc(Buf[Index]);
        Break;
      end;
    BlockToUInts16(Buf, C0, C1, C2, C3);
    ReleaseArray(Buf);
  end
  else
  begin
    Inc(C0);
    if C0 = 0 then
    begin
      Inc(C1);
      if (C1 = 0) then
      begin
        Inc(C2);
        if C2 = 0 then
          Inc(C3);
      end
    end;
  end;
end;

procedure TElBuiltInSymmetricCrypto.BlockToUInts8(const Buf : ByteArray;  var  B0, B1 : cardinal);
begin
  B0 := Buf[0] or (Buf[1] shl 8) or (Buf[2] shl 16) or (Buf[3] shl 24);
  B1 := Buf[4] or (Buf[5] shl 8) or (Buf[6] shl 16) or (Buf[7] shl 24);
end;

procedure TElBuiltInSymmetricCrypto.BlockToUints16(const Buf : ByteArray;  var  B0, B1, B2, B3 : cardinal);
begin
  B0 := Buf[0] or (Buf[1] shl 8) or (Buf[2] shl 16) or (Buf[3] shl 24);
  B1 := Buf[4] or (Buf[5] shl 8) or (Buf[6] shl 16) or (Buf[7] shl 24);
  B2 := Buf[8] or (Buf[9] shl 8) or (Buf[10] shl 16) or (Buf[11] shl 24);
  B3 := Buf[12] or (Buf[13] shl 8) or (Buf[14] shl 16) or (Buf[15] shl 24);
end;

procedure TElBuiltInSymmetricCrypto.UIntsToBlock8(const B0, B1 : cardinal; Buf : ByteArray);
begin
  Buf[0] := B0 and $ff;
  Buf[1] := (B0 shr 8) and $ff;
  Buf[2] := (B0 shr 16) and $ff;
  Buf[3] := (B0 shr 24) and $ff;
  Buf[4] := B1 and $ff;
  Buf[5] := (B1 shr 8) and $ff;
  Buf[6] := (B1 shr 16) and $ff;
  Buf[7] := (B1 shr 24) and $ff;
end;

procedure TElBuiltInSymmetricCrypto.UIntsToBlock16(const B0, B1, B2, B3 : cardinal; Buf : ByteArray);
begin
  Buf[0] := B0 and $ff;
  Buf[1] := (B0 shr 8) and $ff;
  Buf[2] := (B0 shr 16) and $ff;
  Buf[3] := (B0 shr 24) and $ff;
  Buf[4] := B1 and $ff;
  Buf[5] := (B1 shr 8) and $ff;
  Buf[6] := (B1 shr 16) and $ff;
  Buf[7] := (B1 shr 24) and $ff;
  Buf[8] := B2 and $ff;
  Buf[9] := (B2 shr 8) and $ff;
  Buf[10] := (B2 shr 16) and $ff;
  Buf[11] := (B2 shr 24) and $ff;
  Buf[12] := B3 and $ff;
  Buf[13] := (B3 shr 8) and $ff;
  Buf[14] := (B3 shr 16) and $ff;
  Buf[15] := (B3 shr 24) and $ff;
end;

procedure TElBuiltInSymmetricCrypto.EncryptBlock(var B : UInt64);
var
  B0, B1 : cardinal;
begin
  { now just a wrapper - should be properly implemented when moving to 64-bit math }
  B0 := B and $ffffffff;
  B1 := B shr 32;
  EncryptBlock8(B0, B1);
  B := B0 or (UInt64(B1) shl 32);
end;

procedure TElBuiltInSymmetricCrypto.EncryptBlock(var B0, B1 : UInt64);
var
  B00, B01, B10, B11 : cardinal;
begin
  { now just a wrapper - should be properly implemented when moving to 64-bit math }
  B00 := B0 and $ffffffff;
  B01 := B0 shr 32;
  B10 := B1 and $ffffffff;
  B11 := B1 shr 32;
  EncryptBlock16(B00, B01, B10, B11);
  B0 := B00 or (UInt64(B01) shl 32);
  B1 := B10 or (UInt64(B11) shl 32);
end;

procedure TElBuiltInSymmetricCrypto.EncryptBlock8(var B0, B1 : cardinal);
begin
  { should be overriden for 64-bit ciphers }
end;

procedure TElBuiltInSymmetricCrypto.EncryptBlock16(var B0, B1, B2, B3 : cardinal);
begin
  { should be overriden for 128-bit ciphers }
end;

procedure TElBuiltInSymmetricCrypto.DecryptBlock8(var B0, B1 : cardinal);
begin
  { should be overriden for 64-bit ciphers }
end;

procedure TElBuiltInSymmetricCrypto.DecryptBlock16(var B0, B1, B2, B3 : cardinal);
begin
  { should be overriden for 128-bit ciphers }
end;

procedure TElBuiltInSymmetricCrypto.EncryptBlockArr(const Src : ByteArray; var Dest : ByteArray);
var
  B0, B1, B2, B3 : cardinal;
begin
  if BlockSize = 8 then
  begin
    BlockToUInts8(Src, B0, B1);
    EncryptBlock8(B0, B1);
    UIntsToBlock8(B0, B1, Dest);
  end
  else if BlockSize = 16 then
  begin
    BlockToUInts16(Src, B0, B1, B2, B3);
    EncryptBlock16(B0, B1, B2, B3);
    UIntsToBlock16(B0, B1, B2, B3, Dest);
  end;
end;

procedure TElBuiltInSymmetricCrypto.DecryptBlockArr(const Src : ByteArray; var Dest : ByteArray);
var
  B0, B1, B2, B3 : cardinal;
begin
  if BlockSize = 8 then
  begin
    BlockToUInts8(Src, B0, B1);
    DecryptBlock8(B0, B1);
    UIntsToBlock8(B0, B1, Dest);
  end
  else if BlockSize = 16 then
  begin
    BlockToUInts16(Src, B0, B1, B2, B3);
    DecryptBlock16(B0, B1, B2, B3);
    UIntsToBlock16(B0, B1, B2, B3, Dest);
  end;
end;

procedure TElBuiltInSymmetricCrypto.EncryptStreamBlock(Buffer, OutBuffer : pointer; Size : integer);
begin
  //for stream ciphers, must be overriden in derived classes
end;

procedure TElBuiltInSymmetricCrypto.DecryptStreamBlock(Buffer, OutBuffer : pointer; Size : integer);
begin
  //for stream ciphers, must be overriden in derived classes
end;

class procedure TElBuiltInSymmetricCrypto.GetDefaultKeyAndBlockLengths(AlgID : integer;
  var KeyLen : integer; var BlockLen : integer); 
begin
  KeyLen := 0;
  BlockLen := 0;
end;

class procedure TElBuiltInSymmetricCrypto.GetDefaultKeyAndBlockLengths(const OID : ByteArray;
  var KeyLen : integer; var BlockLen : integer); 
begin
  KeyLen := 0;
  BlockLen := 0;
end;

////////////////////////////////////////////////////////////////////////////////
//  TElSymmetricCryptoFactory

constructor TElBuiltInSymmetricCryptoFactory.Create;
begin
  inherited;

  FRegisteredClasses :=   TElList.Create;  
  RegisterDefaultClasses;
end;

 destructor  TElBuiltInSymmetricCryptoFactory.Destroy;
begin
  FreeAndNil(FRegisteredClasses);
  inherited;
end;

procedure TElBuiltInSymmetricCryptoFactory.RegisterDefaultClasses;
begin
  RegisterClass(TElBuiltInAESSymmetricCrypto);
  RegisterClass(TElBuiltInIdentitySymmetricCrypto);
  RegisterClass(TElBuiltInBlowfishSymmetricCrypto);
  RegisterClass(TElBuiltInTwofishSymmetricCrypto);
  RegisterClass(TElBuiltInCAST128SymmetricCrypto);
  {$ifndef SB_NO_RC2}RegisterClass(TElBuiltInRC2SymmetricCrypto); {$endif}
  {$ifndef SB_NO_RC4}RegisterClass(TElBuiltInRC4SymmetricCrypto); {$endif}
  {$ifndef SB_NO_SEED}RegisterClass(TElBuiltInSEEDSymmetricCrypto); {$endif}
  {$ifndef SB_NO_RABBIT}RegisterClass(TElBuiltInRabbitSymmetricCrypto); {$endif}
  {$ifndef SB_NO_DES}RegisterClass(TElBuiltInDESSymmetricCrypto);
  RegisterClass(TElBuiltIn3DESSymmetricCrypto); {$endif}
  {$ifndef SB_NO_CAMELLIA}RegisterClass(TElBuiltInCamelliaSymmetricCrypto); {$endif}
  {$ifndef SB_NO_SERPENT}RegisterClass(TElBuiltInSerpentSymmetricCrypto); {$endif}
  {$ifdef SB_HAS_GOST}
  RegisterClass(TElBuiltInSymmetricCryptoClass(TElBuiltInGOST28147SymmetricCrypto));
   {$endif}
end;

function TElBuiltInSymmetricCryptoFactory.GetRegisteredClass(Index: integer) : TElBuiltInSymmetricCryptoClass;
begin
  Result := TElBuiltInSymmetricCryptoClass(FRegisteredClasses[Index]);
end;

function TElBuiltInSymmetricCryptoFactory.GetRegisteredClassCount: integer;
begin
  Result := FRegisteredClasses.Count;
end;

procedure TElBuiltInSymmetricCryptoFactory.RegisterClass(Cls : TElBuiltInSymmetricCryptoClass);
begin
  FRegisteredClasses.Add((Cls));
end;

function TElBuiltInSymmetricCryptoFactory.CreateInstance(const OID : ByteArray;
  Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault): TElBuiltInSymmetricCrypto;
var
  I : integer;
  Cls : TElBuiltInSymmetricCryptoClass;
begin
  Result := nil;
  for I := 0 to FRegisteredClasses.Count - 1 do
  begin
    Cls := TElBuiltInSymmetricCryptoClass(FRegisteredClasses[I]);
    if Cls.IsAlgorithmSupported(OID) then
    begin
      Result :=  Cls.Create (OID, Mode);
      Break;
    end;
  end;
end;

function TElBuiltInSymmetricCryptoFactory.CreateInstance(Alg : integer;
  Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault): TElBuiltInSymmetricCrypto;
var
  I : integer;
  Cls : TElBuiltInSymmetricCryptoClass;
begin
  Result := nil;
  for I := 0 to FRegisteredClasses.Count - 1 do
  begin
    Cls := TElBuiltInSymmetricCryptoClass(FRegisteredClasses[I]);
    if Cls.IsAlgorithmSupported(Alg) then
    begin
      Result :=  Cls.Create (Alg, Mode);
      Break;
    end;
  end;
end;

function TElBuiltInSymmetricCryptoFactory.IsAlgorithmSupported(const OID : ByteArray): boolean;
var
  I : integer;
begin
  Result := false;
  for I := 0 to FRegisteredClasses.Count - 1 do
  begin
    if TElBuiltInSymmetricCryptoClass(FRegisteredClasses[I]).IsAlgorithmSupported(OID) then
    begin
      Result := true;
      Break;
    end;
  end;
end;

function TElBuiltInSymmetricCryptoFactory.IsAlgorithmSupported(Alg : integer): boolean;
var
  I : integer;
begin
  Result := false;
  for I := 0 to FRegisteredClasses.Count - 1 do
  begin
    if TElBuiltInSymmetricCryptoClass(FRegisteredClasses[I]).IsAlgorithmSupported(Alg) then
    begin
      Result := true;
      Break;
    end;
  end;
end;

function TElBuiltInSymmetricCryptoFactory.GetDefaultKeyAndBlockLengths(Alg : integer;
  var KeyLen : integer; var BlockLen : integer): boolean;
var
  I : integer;
begin
  Result := false;
  for I := 0 to FRegisteredClasses.Count - 1 do
  begin
    if TElBuiltInSymmetricCryptoClass(FRegisteredClasses[I]).IsAlgorithmSupported(Alg) then
    begin
      TElBuiltInSymmetricCryptoClass(FRegisteredClasses[I]).GetDefaultKeyAndBlockLengths(Alg,
        KeyLen, BlockLen);
      Result := true;
      Break;
    end;
  end;
end;

function TElBuiltInSymmetricCryptoFactory.GetDefaultKeyAndBlockLengths(const OID: ByteArray;
  var KeyLen : integer; var BlockLen : integer): boolean;
var
  I : integer;
begin
  Result := false;
  for I := 0 to FRegisteredClasses.Count - 1 do
  begin
    if TElBuiltInSymmetricCryptoClass(FRegisteredClasses[I]).IsAlgorithmSupported(OID) then
    begin
      TElBuiltInSymmetricCryptoClass(FRegisteredClasses[I]).GetDefaultKeyAndBlockLengths(OID,
        KeyLen, BlockLen);
      Result := true;
      Break;
    end;
  end;
end;

////////////////////////////////////////////////////////////////////////////////
//  TElAESSymmetricCrypto

procedure TElBuiltInAESSymmetricCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if not (Length(Material.IV) in [0, 16]) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);
  if not (Length(Material.Value) in [16, 24, 32]) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  inherited;
end;

procedure TElBuiltInAESSymmetricCrypto.EncryptBlock16(var B0, B1, B2, B3 : cardinal);
begin
  if FKeySize = 16 then
    SBAES.Encrypt128(B0, B1, B2, B3, FKey128)
  else if FKeySize = 24 then
    SBAES.Encrypt192(B0, B1, B2, B3, FKey192)
  else if FKeySize = 32 then
    SBAES.Encrypt256(B0, B1, B2, B3, FKey256);
end;

procedure TElBuiltInAESSymmetricCrypto.DecryptBlock16(var B0, B1, B2, B3 : cardinal);
begin
  if FKeySize = 16 then
    SBAES.Decrypt128(B0, B1, B2, B3, FKey128)
  else if FKeySize = 24 then
    SBAES.Decrypt192(B0, B1, B2, B3, FKey192)
  else if FKeySize = 32 then
    SBAES.Decrypt256(B0, B1, B2, B3, FKey256);
end;

class function TElBuiltInAESSymmetricCrypto.IsAlgorithmSupported(AlgID : integer) : boolean;
begin
  if (AlgID = SB_ALGORITHM_CNT_AES128) or
    (AlgID = SB_ALGORITHM_CNT_AES192) or
    (AlgID = SB_ALGORITHM_CNT_AES256)
  then
    Result := true
  else
    Result := false;
end;

class function TElBuiltInAESSymmetricCrypto.IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;
begin
  if CompareContent(AlgOID, SB_OID_AES128_CBC) or
    CompareContent(AlgOID, SB_OID_AES192_CBC) or
    CompareContent(AlgOID, SB_OID_AES256_CBC)
  then
    Result := true
  else
    Result := false;
end;

constructor TElBuiltInAESSymmetricCrypto.Create(AlgID : integer;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  if AlgID = SB_ALGORITHM_CNT_AES128 then
  begin
    inherited Create(Mode);
    FKeySize := 16;
  end
  else if AlgID = SB_ALGORITHM_CNT_AES192 then
  begin
    inherited Create(Mode);
    FKeySize := 24;
  end
  else if AlgID = SB_ALGORITHM_CNT_AES256 then
  begin
    inherited Create(Mode);
    FKeySize := 32;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmInt, [AlgID]));
  end;
  FBlockSize := 16;
end;

constructor TElBuiltInAESSymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin

  if CompareContent(AlgOID, SB_OID_AES128_CBC) then
  begin
    if not (Mode in [cmDefault,
                     cmCBC]) then
      raise EElSymmetricCryptoError.Create(SInvalidCipherMode);

    inherited Create(cmCBC);
    FOID := AlgOID;
    FKeySize := 16;
  end
  else if CompareContent(AlgOID, SB_OID_AES192_CBC) then
  begin
    if not (Mode in [cmDefault,
                     cmCBC]) then
      raise EElSymmetricCryptoError.Create(SInvalidCipherMode);

    inherited Create(cmCBC);
    FOID := AlgOID;
    FKeySize := 24;
  end
  else if CompareContent(AlgOID, SB_OID_AES256_CBC) then
  begin
    if not (Mode in [cmDefault,
                     cmCBC]) then
      raise EElSymmetricCryptoError.Create(SInvalidCipherMode);

    inherited Create(cmCBC);
    FOID := AlgOID;
    FKeySize := 32;
  end
  else
  begin
    inherited Create;
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]));
  end;
  FBlockSize := 16;
end;

constructor TElBuiltInAESSymmetricCrypto.Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  Create(SB_ALGORITHM_CNT_AES128, Mode);
end;

procedure TElBuiltInAESSymmetricCrypto.ExpandKeyForEncryption;
begin
  if FKeySize = 16 then
    SBAES.ExpandKeyForEncryption128(PAESKey128(@FKeyMaterial.Value[0])^, FKey128)
  else if FKeySize = 24 then
    SBAES.ExpandKeyForEncryption192(PAESKey192(@FKeyMaterial.Value[0])^, FKey192)
  else if FKeySize = 32 then
    SBAES.ExpandKeyForEncryption256(PAESKey256(@FKeyMaterial.Value[0])^, FKey256);
end;

procedure TElBuiltInAESSymmetricCrypto.ExpandKeyForDecryption;
begin
  if FKeySize = 16 then
  begin
    SBAES.ExpandKeyForEncryption128(PAESKey128(@FKeyMaterial.Value[0])^, FKey128);
    SBAES.ExpandKeyForDecryption128(FKey128);
  end
  else if FKeySize = 24 then
  begin
    SBAES.ExpandKeyForEncryption192(PAESKey192(@FKeyMaterial.Value[0])^, FKey192);
    SBAES.ExpandKeyForDecryption192(FKey192);
  end
  else if FKeySize = 32 then
  begin
    SBAES.ExpandKeyForEncryption256(PAESKey256(@FKeyMaterial.Value[0])^, FKey256);
    SBAES.ExpandKeyForDecryption256(FKey256);
  end;
end;

class procedure TElBuiltInAESSymmetricCrypto.GetDefaultKeyAndBlockLengths(AlgID : integer;
  var KeyLen : integer; var BlockLen : integer);
begin
  case AlgID of
    SB_ALGORITHM_CNT_AES128:
    begin
      KeyLen := 16;
      BlockLen := 16;
    end;
    SB_ALGORITHM_CNT_AES192:
    begin
      KeyLen := 24;
      BlockLen := 16;
    end;
    SB_ALGORITHM_CNT_AES256:
    begin
      KeyLen := 32;
      BlockLen := 16;
    end;
    else
    begin
      KeyLen := 0;
      BlockLen := 0;
    end;
  end;
end;

class procedure TElBuiltInAESSymmetricCrypto.GetDefaultKeyAndBlockLengths(const OID : ByteArray;
  var KeyLen : integer; var BlockLen : integer); 
begin
  if CompareContent(OID, SB_OID_AES128_CBC) then
  begin
    KeyLen := 16;
    BlockLen := 16;
  end
  else if CompareContent(OID, SB_OID_AES128_CBC) then
  begin
    KeyLen := 24;
    BlockLen := 16;
  end
  else if CompareContent(OID, SB_OID_AES128_CBC) then
  begin
    KeyLen := 32;
    BlockLen := 16;
  end
  else
  begin
    KeyLen := 0;
    BlockLen := 0;
  end;
end;

////////////////////////////////////////////////////////////////////////////////
//  TElBlowfishSymmetricCrypto

procedure TElBuiltInBlowfishSymmetricCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if not (Length(Material.IV) in [0, 8]) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);
  if (Length(Material.Value) < 4) or (Length(Material.Value) > 56) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  inherited;
end;

procedure TElBuiltInBlowfishSymmetricCrypto.EncryptBlock8(var B0, B1 : cardinal);
var
  L, R : cardinal;
begin
  { current Blowfish implementation works in big-endian mode, while in cryptoproviders we use little-endian }
  { consider rewriting Blowfish to remove this code overhead }
  L := B0;
  R := B1;
  L := (L shr 24) or ((L shr 8) and $ff00) or ((L shl 8) and $ff0000) or (L shl 24);
  R := (R shr 24) or ((R shr 8) and $ff00) or ((R shl 8) and $ff0000) or (R shl 24);

  SBBlowfish.EncryptBlock(FContext, L, R);

  { reversing byte order to little endian }
  B0 := (L shr 24) or ((L shr 8) and $ff00) or ((L shl 8) and $ff0000) or (L shl 24);
  B1 := (R shr 24) or ((R shr 8) and $ff00) or ((R shl 8) and $ff0000) or (R shl 24);
end;

procedure TElBuiltInBlowfishSymmetricCrypto.DecryptBlock8(var B0, B1 : cardinal);
var
  L, R : cardinal;
begin
  { current Blowfish implementation works in big-endian mode, while in cryptoproviders we use little-endian }
  { consider rewriting Blowfish to remove this code overhead }
  L := B0;
  R := B1;
  L := (L shr 24) or ((L shr 8) and $ff00) or ((L shl 8) and $ff0000) or (L shl 24);
  R := (R shr 24) or ((R shr 8) and $ff00) or ((R shl 8) and $ff0000) or (R shl 24);

  SBBlowfish.DecryptBlock(FContext, L, R);

  { reversing byte order to little endian }
  B0 := (L shr 24) or ((L shr 8) and $ff00) or ((L shl 8) and $ff0000) or (L shl 24);
  B1 := (R shr 24) or ((R shr 8) and $ff00) or ((R shl 8) and $ff0000) or (R shl 24);
end;

class function TElBuiltInBlowfishSymmetricCrypto.IsAlgorithmSupported(AlgID : integer) : boolean;
begin
  if (AlgID = SB_ALGORITHM_CNT_BLOWFISH) then
    Result := true
  else
    Result := false;
end;

class function TElBuiltInBlowfishSymmetricCrypto.IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;
begin
  Result := CompareContent(AlgOID, SB_OID_BLOWFISH_CBC);
end;

constructor TElBuiltInBlowfishSymmetricCrypto.Create(AlgID : integer;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  if AlgID = SB_ALGORITHM_CNT_BLOWFISH then
  begin
    inherited Create(Mode);
    FBlockSize := 8;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmInt, [AlgID]));
  end;
end;

constructor TElBuiltInBlowfishSymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  if CompareContent(AlgOID, SB_OID_BLOWFISH_CBC) then
  begin
    if not (Mode in [cmDefault,
                     cmCBC]) then
      raise EElSymmetricCryptoError.Create(SInvalidCipherMode);

    inherited Create(cmCBC);
    FOID := AlgOID;
    FBlockSize := 8;
    FKeySize := 16;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]));
  end;
end;

constructor TElBuiltInBlowfishSymmetricCrypto.Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  Create(SB_ALGORITHM_CNT_BLOWFISH, Mode);
end;

procedure TElBuiltInBlowfishSymmetricCrypto.ExpandKeyForEncryption;
begin
  SBBlowfish.Initialize(FContext, FKeyMaterial.Value);
end;

procedure TElBuiltInBlowfishSymmetricCrypto.ExpandKeyForDecryption;
begin
  SBBlowfish.Initialize(FContext, FKeyMaterial.Value);
end;

class procedure TElBuiltInBlowfishSymmetricCrypto.GetDefaultKeyAndBlockLengths(AlgID : integer;
  var KeyLen : integer; var BlockLen : integer);
begin
  KeyLen := 16;
  BlockLen := 8;
end;

class procedure TElBuiltInBlowfishSymmetricCrypto.GetDefaultKeyAndBlockLengths(const OID : ByteArray;
  var KeyLen : integer; var BlockLen : integer);
begin
  KeyLen := 16;
  BlockLen := 8;
end;

////////////////////////////////////////////////////////////////////////////////
//  TElTwofishSymmetricCrypto

procedure TElBuiltInTwofishSymmetricCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if not (Length(Material.IV) in [0, 16]) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);
  if not (Length(Material.Value) in [16, 24, 32]) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  inherited;
end;

procedure TElBuiltInTwofishSymmetricCrypto.EncryptBlock16(var B0, B1, B2, B3 : cardinal);
begin
  SBTwofish.EncryptBlock(FKey, B0, B1, B2, B3);
end;

procedure TElBuiltInTwofishSymmetricCrypto.DecryptBlock16(var B0, B1, B2, B3 : cardinal);
begin
  SBTwofish.DecryptBlock(FKey, B0, B1, B2, B3);
end;

class function TElBuiltInTwofishSymmetricCrypto.IsAlgorithmSupported(AlgID : integer) : boolean;
begin
  if (AlgID = SB_ALGORITHM_CNT_TWOFISH) or (AlgID = SB_ALGORITHM_CNT_TWOFISH128)
    or (AlgID = SB_ALGORITHM_CNT_TWOFISH192) or (AlgID = SB_ALGORITHM_CNT_TWOFISH256)
  then
    Result := true
  else
    Result := false;
end;

class function TElBuiltInTwofishSymmetricCrypto.IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;
begin
  Result := false;
end;

constructor TElBuiltInTwofishSymmetricCrypto.Create(AlgID : integer;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  if AlgID = SB_ALGORITHM_CNT_TWOFISH then
  begin
    inherited Create(Mode);
    FBlockSize := 16;
  end
  else if AlgID = SB_ALGORITHM_CNT_TWOFISH128 then
  begin
    inherited Create(Mode);
    FKeySize := 16;
    FBlockSize := 16;
  end
  else if AlgID = SB_ALGORITHM_CNT_TWOFISH192 then
  begin
    inherited Create(Mode);
    FKeySize := 24;
    FBlockSize := 16;
  end
  else if AlgID = SB_ALGORITHM_CNT_TWOFISH256 then
  begin
    inherited Create(Mode);
    FKeySize := 32;
    FBlockSize := 16;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmInt, [AlgID]));
  end;
end;

constructor TElBuiltInTwofishSymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  { no OID's for Twofish found }
  inherited Create;
  raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]));
end;

constructor TElBuiltInTwofishSymmetricCrypto.Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  Create(SB_ALGORITHM_CNT_TWOFISH, Mode);
end;

procedure TElBuiltInTwofishSymmetricCrypto.ExpandKeyForEncryption;
begin
  SBTwofish.ExpandKey(FKeyMaterial.Value, FKey);
end;

procedure TElBuiltInTwofishSymmetricCrypto.ExpandKeyForDecryption;
begin
  SBTwofish.ExpandKey(FKeyMaterial.Value, FKey);
end;

class procedure TElBuiltInTwofishSymmetricCrypto.GetDefaultKeyAndBlockLengths(AlgID : integer;
  var KeyLen : integer; var BlockLen : integer);
begin
  if AlgID = SB_ALGORITHM_CNT_TWOFISH128 then
  begin
    KeyLen := 16;
    BlockLen := 16;
  end
  else if AlgID = SB_ALGORITHM_CNT_TWOFISH192 then
  begin
    KeyLen := 24;
    BlockLen := 16;
  end
  else if AlgID = SB_ALGORITHM_CNT_TWOFISH256 then
  begin
    KeyLen := 32;
    BlockLen := 16;
  end
  else
  begin
    KeyLen := 0;
    if AlgID = SB_ALGORITHM_CNT_TWOFISH then
      BlockLen := 16
    else
      BlockLen := 0;
  end;
end;

class procedure TElBuiltInTwofishSymmetricCrypto.GetDefaultKeyAndBlockLengths(const OID : ByteArray;
  var KeyLen : integer; var BlockLen : integer);
begin
  KeyLen := 16;
  BlockLen := 16;
end;

////////////////////////////////////////////////////////////////////////////////
//  TElCAST128SymmetricCrypto

procedure TElBuiltInCAST128SymmetricCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if not (Length(Material.IV) in [0, 8]) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);
  if (Length(Material.Value) <> 16)then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  inherited;
end;

procedure TElBuiltInCAST128SymmetricCrypto.EncryptBlock8(var B0, B1 : cardinal);
begin
  SBCAST128.Encrypt16(B0, B1, FKey);
end;

procedure TElBuiltInCAST128SymmetricCrypto.DecryptBlock8(var B0, B1 : cardinal);
begin
  SBCAST128.Decrypt16(B0, B1, FKey);
end;

class function TElBuiltInCAST128SymmetricCrypto.IsAlgorithmSupported(AlgID : integer) : boolean;
begin
  if (AlgID = SB_ALGORITHM_CNT_CAST128) then
    Result := true
  else
    Result := false;
end;

class function TElBuiltInCAST128SymmetricCrypto.IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;
begin
  Result := CompareContent(AlgOID, SB_OID_CAST5_CBC);
end;

constructor TElBuiltInCAST128SymmetricCrypto.Create(AlgID : integer;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  if AlgID = SB_ALGORITHM_CNT_CAST128 then
  begin
    inherited Create(Mode);
    FBlockSize := 8;
    FKeySize := 16;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmInt, [AlgID]));
  end;
end;

constructor TElBuiltInCAST128SymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  if CompareContent(AlgOID, SB_OID_CAST5_CBC) then
  begin
    if not (Mode in [cmDefault,
                     cmCBC]) then
      raise EElSymmetricCryptoError.Create(SInvalidCipherMode);
    inherited Create(cmCBC);
    FOID := AlgOID;
    FBlockSize := 8;
    FKeySize := 16;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]));
  end;
end;

constructor TElBuiltInCAST128SymmetricCrypto.Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  Create(SB_ALGORITHM_CNT_CAST128, Mode);
end;

procedure TElBuiltInCAST128SymmetricCrypto.ExpandKeyForEncryption;
begin
  SBCAST128.ExpandKey(PCAST128Key(@FKeyMaterial.Value[0])^, FKey);
end;

procedure TElBuiltInCAST128SymmetricCrypto.ExpandKeyForDecryption;
begin
  SBCAST128.ExpandKey(PCAST128Key(@FKeyMaterial.Value[0])^, FKey);
end;

class procedure TElBuiltInCAST128SymmetricCrypto.GetDefaultKeyAndBlockLengths(AlgID : integer;
  var KeyLen : integer; var BlockLen : integer);
begin
  KeyLen := 16;
  BlockLen := 8;
end;

class procedure TElBuiltInCAST128SymmetricCrypto.GetDefaultKeyAndBlockLengths(const OID : ByteArray;
  var KeyLen : integer; var BlockLen : integer);
begin
  KeyLen := 16;
  BlockLen := 8;
end;

////////////////////////////////////////////////////////////////////////////////
//  TElRC2SymmetricCrypto

{$ifndef SB_NO_RC2}
procedure TElBuiltInRC2SymmetricCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if not (Length(Material.IV) in [0, 8]) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);
  if (Length(Material.Value) < 1) or (Length(Material.Value) > 16) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  inherited;
end;

procedure TElBuiltInRC2SymmetricCrypto.EncryptBlock8(var B0, B1 : cardinal);
begin
  SBRC2.Encrypt(B0, B1, FKey);
end;

procedure TElBuiltInRC2SymmetricCrypto.DecryptBlock8(var B0, B1 : cardinal);
begin
  SBRC2.Decrypt(B0, B1, FKey);
end;

class function TElBuiltInRC2SymmetricCrypto.IsAlgorithmSupported(AlgID : integer) : boolean;
begin
  if (AlgID = SB_ALGORITHM_CNT_RC2) then
    Result := true
  else
    Result := false;
end;

class function TElBuiltInRC2SymmetricCrypto.IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;
begin
  if CompareContent(AlgOID, SB_OID_RC2_CBC) then
    Result := true
  else
    Result := false;
end;

constructor TElBuiltInRC2SymmetricCrypto.Create(AlgID : integer;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  if AlgID = SB_ALGORITHM_CNT_RC2 then
  begin
    inherited Create(Mode);
    FBlockSize := 8;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmInt, [AlgID]));
  end;
end;

constructor TElBuiltInRC2SymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  if CompareContent(AlgOID, SB_OID_RC2_CBC) then
  begin
    if not (Mode in [cmDefault,
                     cmCBC]) then
      raise EElSymmetricCryptoError.Create(SInvalidCipherMode);

    inherited Create(cmCBC);
    FOID := AlgOID;
    FBlockSize := 8;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]));
  end;
end;

constructor TElBuiltInRC2SymmetricCrypto.Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  Create(SB_ALGORITHM_CNT_RC2, Mode);
end;



procedure TElBuiltInRC2SymmetricCrypto.ExpandKeyForEncryption;
begin

  SBRC2.ExpandKey(TRC2Key(FKeyMaterial.Value), FKey);
end;

procedure TElBuiltInRC2SymmetricCrypto.ExpandKeyForDecryption;
begin

  SBRC2.ExpandKey(TRC2Key(FKeyMaterial.Value), FKey);
end;

class procedure TElBuiltInRC2SymmetricCrypto.GetDefaultKeyAndBlockLengths(AlgID : integer;
  var KeyLen : integer; var BlockLen : integer);
begin
  KeyLen := 16;
  BlockLen := 8;
end;

class procedure TElBuiltInRC2SymmetricCrypto.GetDefaultKeyAndBlockLengths(const OID : ByteArray;
  var KeyLen : integer; var BlockLen : integer);
begin
  KeyLen := 16;
  BlockLen := 8;
end;

 {$endif}

////////////////////////////////////////////////////////////////////////////////
//  TElRC4SymmetricCrypto

{$ifndef SB_NO_RC4}
class function TElBuiltInRC4SymmetricCrypto.StreamCipher : boolean;
begin
  Result := true;
end;

procedure TElBuiltInRC4SymmetricCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if (Length(Material.Value) < 1) or (Length(Material.Value) > 32) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  inherited;
end;

procedure TElBuiltInRC4SymmetricCrypto.EncryptStreamBlock(Buffer, OutBuffer : pointer; Size : integer);
begin
  SBRC4.Encrypt(FContext, Buffer, OutBuffer, Size)
end;

procedure TElBuiltInRC4SymmetricCrypto.DecryptStreamBlock(Buffer, OutBuffer: pointer; Size : integer);
begin
  SBRC4.Decrypt(FContext, Buffer, OutBuffer, Size)
end;

class function TElBuiltInRC4SymmetricCrypto.IsAlgorithmSupported(AlgID : integer) : boolean;
begin
  if (AlgID = SB_ALGORITHM_CNT_RC4) then
    Result := true
  else
    Result := false;
end;

class function TElBuiltInRC4SymmetricCrypto.IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;
begin
  if CompareContent(AlgOID, SB_OID_RC4) then
    Result := true
  else
    Result := false;
end;

constructor TElBuiltInRC4SymmetricCrypto.Create(AlgID : integer;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  if AlgID = SB_ALGORITHM_CNT_RC4 then
  begin
    if Mode <> cmDefault then
      raise EElSymmetricCryptoError.Create(SInvalidCipherMode);

    inherited Create(Mode);
    FBlockSize := 1;
    FSkipKeyStreamBytes := 0;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmInt, [AlgID]));
  end;
end;

constructor TElBuiltInRC4SymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  if CompareContent(AlgOID, SB_OID_RC4) then
  begin
    if not (Mode in [cmDefault]) then
      raise EElSymmetricCryptoError.Create(SInvalidCipherMode);
    inherited Create(cmDefault);
    FOID := AlgOID;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]));
  end;
end;

constructor TElBuiltInRC4SymmetricCrypto.Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  Create(SB_ALGORITHM_CNT_RC4, Mode);
end;

procedure TElBuiltInRC4SymmetricCrypto.ExpandKeyForEncryption;
begin
  SBRC4.Initialize(FContext, TRC4Key(FKeyMaterial.Value));
end;

procedure TElBuiltInRC4SymmetricCrypto.ExpandKeyForDecryption;
begin
  SBRC4.Initialize(FContext, TRC4Key(FKeyMaterial.Value));
end;

procedure TElBuiltInRC4SymmetricCrypto.InitializeEncryption;
var
  Buf, OutBuf : ByteArray;
begin
  inherited InitializeEncryption;

  if FSkipKeyStreamBytes > 0 then
  begin
    SetLength(Buf, FSkipKeyStreamBytes);
    SetLength(OutBuf, FSkipKeyStreamBytes);
    SBRC4.Encrypt(FContext, @Buf[0], @OutBuf[0], FSkipKeyStreamBytes);
  end;
end;

procedure TElBuiltInRC4SymmetricCrypto.InitializeDecryption;
var
  Buf, OutBuf : ByteArray;
begin
  inherited InitializeDecryption;

  if FSkipKeyStreamBytes > 0 then
  begin
    SetLength(Buf, FSkipKeyStreamBytes);
    SetLength(OutBuf, FSkipKeyStreamBytes);
    SBRC4.Decrypt(FContext, @Buf[0], @OutBuf[0], FSkipKeyStreamBytes);
  end;
end;

class procedure TElBuiltInRC4SymmetricCrypto.GetDefaultKeyAndBlockLengths(AlgID : integer;
  var KeyLen : integer; var BlockLen : integer);
begin
  KeyLen := 16;
  BlockLen := 0;
end;

class procedure TElBuiltInRC4SymmetricCrypto.GetDefaultKeyAndBlockLengths(const OID : ByteArray;
  var KeyLen : integer; var BlockLen : integer);
begin
  KeyLen := 16;
  BlockLen := 0;
end;

 {$endif}

////////////////////////////////////////////////////////////////////////////////
//  TElDESSymmetricCrypto

{$ifndef SB_NO_DES}
procedure TElBuiltInDESSymmetricCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if not (Length(Material.IV) in [0, 8]) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);
  if (Length(Material.Value) <> 8) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  inherited;
end;

procedure TElBuiltInDESSymmetricCrypto.EncryptBlock8(var B0, B1 : cardinal);
begin
  SBDES.Encrypt(B0, B1, FKey);
end;

procedure TElBuiltInDESSymmetricCrypto.DecryptBlock8(var B0, B1 : cardinal);
begin
  SBDES.Encrypt(B0, B1, FKey);
end;

class function TElBuiltInDESSymmetricCrypto.IsAlgorithmSupported(AlgID : integer) : boolean;
begin
  if (AlgID = SB_ALGORITHM_CNT_DES) then
    Result := true
  else
    Result := false;
end;

class function TElBuiltInDESSymmetricCrypto.IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;
begin
  Result := CompareContent(AlgOID, SB_OID_DES_CBC);
end;

constructor TElBuiltInDESSymmetricCrypto.Create(AlgID : integer;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  if AlgID = SB_ALGORITHM_CNT_DES then
  begin
    inherited Create(Mode);
    FBlockSize := 8;
    FKeySize := 8;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmInt, [AlgID]));
  end;
end;

constructor TElBuiltInDESSymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  if CompareContent(AlgOID, SB_OID_DES_CBC) then
  begin
    if not (Mode in [cmDefault,
                     cmCBC]) then
      raise EElSymmetricCryptoError.Create(SInvalidCipherMode);

    inherited Create(cmCBC);
    FOID := AlgOID;
    FBlockSize := 8;
    FKeySize := 8;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]));
  end;
end;

constructor TElBuiltInDESSymmetricCrypto.Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  Create(SB_ALGORITHM_CNT_DES, Mode);
end;

procedure TElBuiltInDESSymmetricCrypto.ExpandKeyForEncryption;
begin
  SBDES.ExpandKeyForEncryption(FKeyMaterial.Value, FKey);
end;

procedure TElBuiltInDESSymmetricCrypto.ExpandKeyForDecryption;
begin
  SBDES.ExpandKeyForDecryption(FKeyMaterial.Value, FKey);
end;

class procedure TElBuiltInDESSymmetricCrypto.GetDefaultKeyAndBlockLengths(AlgID : integer;
  var KeyLen : integer; var BlockLen : integer);
begin
  KeyLen := 8;
  BlockLen := 8;
end;

class procedure TElBuiltInDESSymmetricCrypto.GetDefaultKeyAndBlockLengths(const OID : ByteArray;
  var KeyLen : integer; var BlockLen : integer);
begin
  KeyLen := 8;
  BlockLen := 8;
end;
 {$endif}

////////////////////////////////////////////////////////////////////////////////
//  TEl3DESSymmetricCrypto

{$ifndef SB_NO_DES}
procedure TElBuiltIn3DESSymmetricCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if not (Length(Material.IV) in [0, 8]) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);
  if (Length(Material.Value) <> 24) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  inherited;
end;

procedure TElBuiltIn3DESSymmetricCrypto.EncryptBlock8(var B0, B1 : cardinal);
begin
  SBDES.EncryptEDE(B0, B1, FKey1, FKey2, FKey3);
end;

procedure TElBuiltIn3DESSymmetricCrypto.DecryptBlock8(var B0, B1 : cardinal);
begin
  SBDES.EncryptEDE(B0, B1, FKey1, FKey2, FKey3);
end;

class function TElBuiltIn3DESSymmetricCrypto.IsAlgorithmSupported(AlgID : integer) : boolean;
begin
  if (AlgID = SB_ALGORITHM_CNT_3DES) then
    Result := true
  else
    Result := false;
end;

class function TElBuiltIn3DESSymmetricCrypto.IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;
begin
  Result := CompareContent(AlgOID, SB_OID_DES_EDE3_CBC);
end;

constructor TElBuiltIn3DESSymmetricCrypto.Create(AlgID : integer;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  if AlgID = SB_ALGORITHM_CNT_3DES then
  begin
    inherited Create(Mode);
    FBlockSize := 8;
    FKeySize := 24;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmInt, [AlgID]));
  end;
end;

constructor TElBuiltIn3DESSymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  if CompareContent(AlgOID, SB_OID_DES_EDE3_CBC) then
  begin
    if not (Mode in [cmDefault,
                     cmCBC]) then
      raise EElSymmetricCryptoError.Create(SInvalidCipherMode);

    inherited Create(cmCBC);
    FOID := AlgOID;
    FBlockSize := 8;
    FKeySize := 24;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]));
  end;
end;

constructor TElBuiltIn3DESSymmetricCrypto.Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  Create(SB_ALGORITHM_CNT_3DES, Mode);
end;

procedure TElBuiltIn3DESSymmetricCrypto.ExpandKeyForEncryption;
var
  Key1, Key2, Key3 : ByteArray;
begin
  Key1 := SubArray(FKeyMaterial.Value, 0, 8);
  Key2 := SubArray(FKeyMaterial.Value, 8, 8);
  Key3 := SubArray(FKeyMaterial.Value, 16, 8);

  SBDES.ExpandKeyForEncryption(Key1, FKey1);
  SBDES.ExpandKeyForDecryption(Key2, FKey2);
  SBDES.ExpandKeyForEncryption(Key3, FKey3);
end;

procedure TElBuiltIn3DESSymmetricCrypto.ExpandKeyForDecryption;
var
  Key1, Key2, Key3 : ByteArray;
begin
  Key3 := SubArray(FKeyMaterial.Value, 0, 8);
  Key2 := SubArray(FKeyMaterial.Value, 8, 8);
  Key1 := SubArray(FKeyMaterial.Value, 16, 8);

  SBDES.ExpandKeyForDecryption(Key1, FKey1);
  SBDES.ExpandKeyForEncryption(Key2, FKey2);
  SBDES.ExpandKeyForDecryption(Key3, FKey3);
end;

class procedure TElBuiltIn3DESSymmetricCrypto.GetDefaultKeyAndBlockLengths(AlgID : integer;
  var KeyLen : integer; var BlockLen : integer);
begin
  KeyLen := 24;
  BlockLen := 8;
end;

class procedure TElBuiltIn3DESSymmetricCrypto.GetDefaultKeyAndBlockLengths(const OID : ByteArray;
  var KeyLen : integer; var BlockLen : integer);
begin
  KeyLen := 24;
  BlockLen := 8;
end;

 {$endif}


////////////////////////////////////////////////////////////////////////////////
//  TElCamelliaSymmetricCrypto

{$ifndef SB_NO_CAMELLIA}

procedure TElBuiltInCamelliaSymmetricCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if not (Length(Material.IV) in [0, 16]) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);
  if not (Length(Material.Value) in [16, 24, 32]) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  inherited;
end;

procedure TElBuiltInCamelliaSymmetricCrypto.EncryptBlock16(var B0, B1, B2, B3 : cardinal);
begin
  SBCamellia.EncryptBlock(B0, B1, B2, B3, FKey, FKeySize > 16);
end;

procedure TElBuiltInCamelliaSymmetricCrypto.DecryptBlock16(var B0, B1, B2, B3 : cardinal);
begin
  SBCamellia.EncryptBlock(B0, B1, B2, B3, FKey, FKeySize > 16);
end;

class function TElBuiltInCamelliaSymmetricCrypto.IsAlgorithmSupported(AlgID : integer) : boolean;
begin
  if (AlgID = SB_ALGORITHM_CNT_CAMELLIA) or
    (AlgID = SB_ALGORITHM_CNT_CAMELLIA128) or
    (AlgID = SB_ALGORITHM_CNT_CAMELLIA192) or
    (AlgID = SB_ALGORITHM_CNT_CAMELLIA256) then
    Result := true
  else
    Result := false;
end;

class function TElBuiltInCamelliaSymmetricCrypto.IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;
begin
  Result := CompareContent(AlgOID, SB_OID_CAMELLIA128_CBC) or
    CompareContent(AlgOID, SB_OID_CAMELLIA192_CBC) or
    CompareContent(AlgOID, SB_OID_CAMELLIA256_CBC);
end;

constructor TElBuiltInCamelliaSymmetricCrypto.Create(AlgID : integer;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  if AlgID = SB_ALGORITHM_CNT_CAMELLIA then
  begin
    inherited Create(Mode);
    FKeySize := 0;
    FBlockSize := 16;
  end
  else if AlgID = SB_ALGORITHM_CNT_CAMELLIA128 then
  begin
    inherited Create(Mode);
    FBlockSize := 16;
    FKeySize := 16;
  end
  else if AlgID = SB_ALGORITHM_CNT_CAMELLIA192 then
  begin
    inherited Create(Mode);
    FBlockSize := 16;
    FKeySize := 24;
  end
  else if AlgID = SB_ALGORITHM_CNT_CAMELLIA256 then
  begin
    inherited Create(Mode);
    FBlockSize := 16;
    FKeySize := 32;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmInt, [AlgID]));
  end;
end;

constructor TElBuiltInCamelliaSymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  if CompareContent(AlgOID, SB_OID_CAMELLIA128_CBC) then
  begin
    if not (Mode in [cmDefault,
                     cmCBC]) then
      raise EElSymmetricCryptoError.Create(SInvalidCipherMode);
    inherited Create(cmCBC);
    FOID := AlgOID;
    FBlockSize := 16;
    FKeySize := 16;
  end
  else if CompareContent(AlgOID, SB_OID_CAMELLIA192_CBC) then
  begin
    if not (Mode in [cmDefault,
                     cmCBC]) then
      raise EElSymmetricCryptoError.Create(SInvalidCipherMode);
    inherited Create(cmCBC);
    FOID := AlgOID;
    FBlockSize := 16;
    FKeySize := 24;
  end
  else if CompareContent(AlgOID, SB_OID_CAMELLIA256_CBC) then
  begin
    if not (Mode in [cmDefault,
                     cmCBC]) then
      raise EElSymmetricCryptoError.Create(SInvalidCipherMode);
    inherited Create(cmCBC);
    FOID := AlgOID;
    FBlockSize := 16;
    FKeySize := 32;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]));
  end;
end;

constructor TElBuiltInCamelliaSymmetricCrypto.Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  Create(SB_ALGORITHM_CNT_CAMELLIA, Mode);
end;

procedure TElBuiltInCamelliaSymmetricCrypto.ExpandKeyForEncryption;
begin
  SBCamellia.ExpandKeyForEncryption(FKeyMaterial.Value, FKey);
end;

procedure TElBuiltInCamelliaSymmetricCrypto.ExpandKeyForDecryption;
begin
  SBCamellia.ExpandKeyForDecryption(FKeyMaterial.Value, FKey)
end;

class procedure TElBuiltInCamelliaSymmetricCrypto.GetDefaultKeyAndBlockLengths(AlgID : integer;
  var KeyLen : integer; var BlockLen : integer);
begin
  if AlgID = SB_ALGORITHM_CNT_CAMELLIA128 then
    KeyLen := 16
  else if AlgID = SB_ALGORITHM_CNT_CAMELLIA192 then
    KeyLen := 24
  else if AlgID = SB_ALGORITHM_CNT_CAMELLIA256 then
    KeyLen := 32
  else
    KeyLen := 0;
  BlockLen := 16;
end;

class procedure TElBuiltInCamelliaSymmetricCrypto.GetDefaultKeyAndBlockLengths(const OID : ByteArray;
  var KeyLen : integer; var BlockLen : integer);
begin
  if CompareContent(OID, SB_OID_CAMELLIA128_CBC) then
    KeyLen := 16
  else if CompareContent(OID, SB_OID_CAMELLIA192_CBC) then
    KeyLen := 24
  else if CompareContent(OID, SB_OID_CAMELLIA256_CBC) then
    KeyLen := 32
  else
    KeyLen := 0;
  BlockLen := 16;
end;

 {$endif}

////////////////////////////////////////////////////////////////////////////////
//  TElSerpentSymmetricCrypto

{$ifndef SB_NO_SERPENT}
procedure TElBuiltInSerpentSymmetricCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if not (Length(Material.IV) in [0, 16]) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);
  if not (Length(Material.Value) in [16, 24, 32]) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  inherited;
end;

procedure TElBuiltInSerpentSymmetricCrypto.EncryptBlock16(var B0, B1, B2, B3 : cardinal);
begin
  SBSerpent.EncryptBlock(B0, B1, B2, B3, FKey);
end;

procedure TElBuiltInSerpentSymmetricCrypto.DecryptBlock16(var B0, B1, B2, B3 : cardinal);
begin
  SBSerpent.DecryptBlock(B0, B1, B2, B3, FKey);
end;

class function TElBuiltInSerpentSymmetricCrypto.IsAlgorithmSupported(AlgID : integer) : boolean;
begin
  if (AlgID = SB_ALGORITHM_CNT_SERPENT) or (AlgID = SB_ALGORITHM_CNT_SERPENT128) or (AlgID = SB_ALGORITHM_CNT_SERPENT192) or
    (AlgID = SB_ALGORITHM_CNT_SERPENT256) then
    Result := true
  else
    Result := false;
end;

class function TElBuiltInSerpentSymmetricCrypto.IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;
begin
  Result := CompareContent(AlgOID, SB_OID_SERPENT128_CBC) or CompareContent(AlgOID, SB_OID_SERPENT192_CBC) or
    CompareContent(AlgOID, SB_OID_SERPENT256_CBC);
end;

constructor TElBuiltInSerpentSymmetricCrypto.Create(AlgID : integer;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  if AlgID = SB_ALGORITHM_CNT_SERPENT then
  begin
    inherited Create(Mode);
    FKeySize := 0;
    FBlockSize := 16;
  end
  else if AlgID = SB_ALGORITHM_CNT_SERPENT128 then
  begin
    inherited Create(Mode);
    FKeySize := 16;
    FBlockSize := 16;
  end
  else if AlgID = SB_ALGORITHM_CNT_SERPENT192 then
  begin
    inherited Create(Mode);
    FKeySize := 24;
    FBlockSize := 16;
  end
  else if AlgID = SB_ALGORITHM_CNT_SERPENT256 then
  begin
    inherited Create(Mode);
    FKeySize := 32;
    FBlockSize := 16;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmInt, [AlgID]));
  end;  
end;

constructor TElBuiltInSerpentSymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  //inherited Create(Mode);

  if CompareContent(AlgOID, SB_OID_SERPENT128_CBC) then
  begin
    if not (Mode in [cmDefault,
     cmCBC]) then
      raise EElSymmetricCryptoError.Create(SInvalidCipherMode);

    inherited Create(cmCBC);

    FKeySize := 16;
    FBlockSize := 16;
  end
  else if CompareContent(AlgOID, SB_OID_SERPENT192_CBC) then
  begin
    if not (Mode in [cmDefault,
     cmCBC]) then
      raise EElSymmetricCryptoError.Create(SInvalidCipherMode);

    inherited Create(cmCBC);
    FKeySize := 24;
    FBlockSize := 16;
  end
  else if CompareContent(AlgOID, SB_OID_SERPENT256_CBC) then
  begin
    if not (Mode in [cmDefault,
     cmCBC]) then
      raise EElSymmetricCryptoError.Create(SInvalidCipherMode);

    inherited Create(cmCBC);
    FKeySize := 32;
    FBlockSize := 16;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]));
  end;
end;

constructor TElBuiltInSerpentSymmetricCrypto.Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  Create(SB_ALGORITHM_CNT_SERPENT128, Mode);
end;

procedure TElBuiltInSerpentSymmetricCrypto.ExpandKeyForEncryption;
begin
  SBSerpent.ExpandKey(TSerpentKey(FKeyMaterial.Value), FKey);
end;

procedure TElBuiltInSerpentSymmetricCrypto.ExpandKeyForDecryption;
begin
  SBSerpent.ExpandKey(TSerpentKey(FKeyMaterial.Value), FKey)
end;

class procedure TElBuiltInSerpentSymmetricCrypto.GetDefaultKeyAndBlockLengths(AlgID : integer;
  var KeyLen : integer; var BlockLen : integer);
begin
  case AlgID of
    SB_ALGORITHM_CNT_SERPENT128:
    begin
      KeyLen := 16;
      BlockLen := 16;
    end;
    SB_ALGORITHM_CNT_SERPENT192:
    begin
      KeyLen := 24;
      BlockLen := 16;
    end;
    SB_ALGORITHM_CNT_SERPENT256:
    begin
      KeyLen := 32;
      BlockLen := 16;
    end;
    else
    begin
      KeyLen := 0;
      if AlgID = SB_ALGORITHM_CNT_SERPENT then
        BlockLen := 16
      else
        BlockLen := 0;
    end;
  end;
end;

class procedure TElBuiltInSerpentSymmetricCrypto.GetDefaultKeyAndBlockLengths(const OID : ByteArray;
  var KeyLen : integer; var BlockLen : integer);
begin
  if CompareContent(OID, SB_OID_SERPENT128_CBC) then
  begin
    KeyLen := 16;
    BlockLen := 16;
  end
  else if CompareContent(OID, SB_OID_SERPENT192_CBC) then
  begin
    KeyLen := 24;
    BlockLen := 16;
  end
  else if CompareContent(OID, SB_OID_SERPENT256_CBC) then
  begin
    KeyLen := 32;
    BlockLen := 16;
  end
  else
  begin
    KeyLen := 0;
    BlockLen := 0;
  end;
end;
 {$endif SB_NO_SERPENT}

////////////////////////////////////////////////////////////////////////////////
//  TElSEEDSymmetricCrypto

{$ifndef SB_NO_SEED}
procedure TElBuiltInSEEDSymmetricCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if (Length(Material.Value) <> 16) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  SBMove(Material.Value[0], FKey, 16);
  inherited;
end;

procedure TElBuiltInSEEDSymmetricCrypto.EncryptBlock16(var B0, B1, B2, B3 : cardinal);
begin
  SBSEED.SeedCoding(B0, B1, B2, B3, FKey, SEED_ENCODE);
end;

procedure TElBuiltInSEEDSymmetricCrypto.DecryptBlock16(var B0, B1, B2, B3 : cardinal);
begin
  SBSEED.SeedCoding(B0, B1, B2, B3, FKey, SEED_DECODE);
end;

class function TElBuiltInSEEDSymmetricCrypto.IsAlgorithmSupported(AlgID : integer) : boolean;
begin
  if (AlgID = SB_ALGORITHM_CNT_SEED) then
    Result := true
  else
    Result := false;
end;

class function TElBuiltInSEEDSymmetricCrypto.IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;
begin
  Result := CompareContent(AlgOID, SB_OID_SEED);
end;

constructor TElBuiltInSEEDSymmetricCrypto.Create(AlgID : integer;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  if AlgID = SB_ALGORITHM_CNT_SEED then
  begin
    inherited Create(Mode);
    FBlockSize := 16;
    FKeySize := 16;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmInt, [AlgID]));
  end;
end;

constructor TElBuiltInSEEDSymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  if CompareContent(AlgOID, SB_OID_SEED) then
  begin
    if not (Mode in [cmDefault,
                     cmCBC]) then
      raise EElSymmetricCryptoError.Create(SInvalidCipherMode);

    inherited Create(cmCBC);
    FOID := AlgOID;
    FBlockSize := 16;
    FKeySize := 16;
//    FKey := new TSEEDKey(16);
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]));
  end;
end;

constructor TElBuiltInSEEDSymmetricCrypto.Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  Create(SB_ALGORITHM_CNT_SEED, Mode);
end;

class procedure TElBuiltInSEEDSymmetricCrypto.GetDefaultKeyAndBlockLengths(AlgID : integer;
  var KeyLen : integer; var BlockLen : integer);
begin
  KeyLen := 16;
  BlockLen := 16;
end;

class procedure TElBuiltInSEEDSymmetricCrypto.GetDefaultKeyAndBlockLengths(const OID : ByteArray;
  var KeyLen : integer; var BlockLen : integer);
begin
  KeyLen := 16;
  BlockLen := 16;
end;

procedure TElBuiltInSEEDSymmetricCrypto.ExpandKeyForEncryption;
begin
  ;
end;

procedure TElBuiltInSEEDSymmetricCrypto.ExpandKeyForDecryption;
begin
  ;
end;

 {$endif}


////////////////////////////////////////////////////////////////////////////////
//  TElRabbitSymmetricCrypto

{$ifndef SB_NO_RABBIT}
procedure TElBuiltInRabbitSymmetricCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if (Length(Material.Value) <> 16) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);
  if not (Length(Material.IV) in [0, 16]) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  SBRabbit.Rabbit_Init(FContext,Material.Value);
  if Length(Material.IV)<>0 then
	SbRabbit.Rabbit_IVInit(FContext,Material.IV);
  inherited;
end;

procedure TElBuiltInRabbitSymmetricCrypto.EncryptBlock16(var B0, B1, B2, B3 : cardinal);
var
  InBuf, OutBuf : ByteArray;
begin
  { rabbit cipher should be completely rewritten }
  SetLength(InBuf, 16);
  SetLength(OutBuf, 16);
  UIntsToBlock16(B0, B1, B2, B3, InBuf);
  SBRabbit.Rabbit_Cipher(FContext, InBuf, OutBuf);
  BlockToUints16(OutBuf, B0, B1, B2, B3);
  ReleaseArray(InBuf);
  ReleaseArray(OutBuf);
end;

procedure TElBuiltInRabbitSymmetricCrypto.DecryptBlock16(var B0, B1, B2, B3 : cardinal);
var
  InBuf, OutBuf : ByteArray;
begin
  { rabbit cipher should be completely rewritten }
  SetLength(InBuf, 16);
  SetLength(OutBuf, 16);
  UIntsToBlock16(B0, B1, B2, B3, InBuf);
  SBRabbit.Rabbit_Cipher(FContext, InBuf, OutBuf);
  BlockToUints16(OutBuf, B0, B1, B2, B3);
  ReleaseArray(InBuf);
  ReleaseArray(OutBuf);
end;

class function TElBuiltInRabbitSymmetricCrypto.IsAlgorithmSupported(AlgID : integer) : boolean;
begin
  if (AlgID = SB_ALGORITHM_CNT_RABBIT) then
    Result := true
  else
    Result := false;
end;

class function TElBuiltInRabbitSymmetricCrypto.IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;
begin
  Result := CompareContent(AlgOID, SB_OID_RABBIT);
end;

constructor TElBuiltInRabbitSymmetricCrypto.Create(AlgID : integer;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  if AlgID = SB_ALGORITHM_CNT_RABBIT then
  begin
    inherited Create(Mode);
    FBlockSize := 16;
    FKeySize := 16;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmInt, [AlgID]));
  end;
end;

constructor TElBuiltInRabbitSymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  if CompareContent(AlgOID, SB_OID_RABBIT) then
  begin
    if not (Mode in [cmDefault,
                     cmCBC]) then
      raise EElSymmetricCryptoError.Create(SInvalidCipherMode);

    inherited Create(cmCBC);
    FOID := AlgOID;
    FBlockSize := 16;
    FKeySize := 16;
//    FKey := new TSEEDKey(16);
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]));
  end;
end;

constructor TElBuiltInRabbitSymmetricCrypto.Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  Create(SB_ALGORITHM_CNT_RABBIT, Mode);
end;

class procedure TElBuiltInRabbitSymmetricCrypto.GetDefaultKeyAndBlockLengths(AlgID : integer;
  var KeyLen : integer; var BlockLen : integer);
begin
  KeyLen := 16;
  BlockLen := 16;
end;

class procedure TElBuiltInRabbitSymmetricCrypto.GetDefaultKeyAndBlockLengths(const OID : ByteArray;
  var KeyLen : integer; var BlockLen : integer);
begin
  KeyLen := 16;
  BlockLen := 16;
end;

procedure TElBuiltInRabbitSymmetricCrypto.ExpandKeyForEncryption;
begin
  ;
end;

procedure TElBuiltInRabbitSymmetricCrypto.ExpandKeyForDecryption;
begin
  ;
end;

 {$endif}

{$ifdef SB_HAS_GOST}
////////////////////////////////////////////////////////////////////////////////
// TElBuiltInGOSTSymmetricCrypto class
procedure TElBuiltInGOST28147SymmetricCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if not (Length(Material.IV) in [0, 8]) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);
  if (Length(Material.Value) <> TElGOST.KeySize) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  inherited;
end;

procedure TElBuiltInGOST28147SymmetricCrypto.DoKeyMeshing(var IV0, IV1 : cardinal);
var
  NewKey, OldIV, NewIV, C : ByteArray;
  i, OutLen : integer;
begin
  SetLength(NewKey, 32);
  SetLength(OldIV, 8);  
  SetLength(NewIV, 8);
  SetLength(C, 32);
  SBMove(SB_GOST_CRYPTOPRO_KEYMESH_C[0], C[0], 32);

  for i := 0 to 3 do
    fGOST.Decrypt_Block(C, i shl 3, 8, NewKey, OutLen, i shl 3);

  fGOST.Reset;
  fGOST.Key := NewKey;
  fGOST.Mode := GOSTMode_ECB;


  UIntsToBlock8(IV0, IV1, OldIV);
  fGOST.Encrypt_Block(OldIV, 0, 8, NewIV, OutLen, 0);
  BlockToUInts8(NewIV, IV0, IV1);
end;

procedure TElBuiltInGOST28147SymmetricCrypto.EncryptBlock8(var B0, B1 : cardinal);
begin
  if FUseKeyMeshing then
  begin
    if (FProcessedBlocks = 128) and (FMode = cmCFB8) then
    begin
      { for CFB mode only IV is encrypted, so IV is the input to this method, and we can change it and key here }

      DoKeyMeshing(B0, B1);
      FProcessedBlocks := 0;
    end;

    FProcessedBlocks := FProcessedBlocks + 1;
  end;

  fGOST.EncryptBlock(B0, B1);

  (*SetLength(InBuf, 8);
  SetLength(OutBuf, 8);
  UIntsToBlock8(B0, B1, InBuf);

  fGOST.Encrypt_Block(InBuf, 0, BlockSize, OutBuf, OutLen, 0);
  BlockToUInts8(OutBuf, B0, B1);*)
end;

procedure TElBuiltInGOST28147SymmetricCrypto.DecryptBlock8(var B0, B1 : cardinal);
begin
  if FUseKeyMeshing then
  begin
    if (FProcessedBlocks = 128) and (FMode = cmCFB8) then
    begin
      { for CFB mode only IV is encrypted, so IV is the input to this method, and we can change it and key here }
      { if key meshing will be needed for other modes, we should override Internal<Encrypt|Decrypt><cipherMode>8 functions }
      
      DoKeyMeshing(B0, B1);
      FProcessedBlocks := 0;
    end;

    FProcessedBlocks := FProcessedBlocks + 1;
  end;

  fGOST.DecryptBlock(B0, B1);

  (*SetLength(InBuf, 8);
  SetLength(OutBuf, 8);
  UIntsToBlock8(B0, B1, InBuf);

  fGOST.Decrypt_Block(InBuf, 0, BlockSize, OutBuf, OutLen, 0);
  BlockToUInts8(OutBuf, B0, B1);*)
end;

class function TElBuiltInGOST28147SymmetricCrypto.IsAlgorithmSupported(AlgID : integer) : boolean;
begin
  if (AlgID = SB_ALGORITHM_CNT_GOST_28147_1989) then
    Result := true
  else
    Result := false;
end;

class function TElBuiltInGOST28147SymmetricCrypto.IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;
begin
  Result := CompareContent(AlgOID, SB_OID_GOST_28147_1989);
end;

constructor TElBuiltInGOST28147SymmetricCrypto.Create(AlgID : integer;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  inherited Create(Mode);

  if AlgID = SB_ALGORITHM_CNT_GOST_28147_1989 then
  begin
    fGost := TElGOST.Create;
    FBlockSize := TElGOST.BlockSize;
    FKeySize := TElGOST.KeySize;
    FUseKeyMeshing := false;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmInt, [AlgID]));
  end;
end;

constructor TElBuiltInGOST28147SymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  inherited Create(Mode);

  if CompareContent(AlgOID, SB_OID_GOST_28147_1989) then
  begin
    fGost := TElGOST.Create;
    FOID := AlgOID;
    FBlockSize := TElGOST.BlockSize;
    FKeySize := TElGOST.KeySize;
    FUseKeyMeshing := false;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]));
  end;
end;

constructor TElBuiltInGOST28147SymmetricCrypto.Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  Create(SB_ALGORITHM_CNT_GOST_28147_1989, Mode);
end;

 destructor  TElBuiltInGOST28147SymmetricCrypto.Destroy;
begin
  if Assigned(fGOST) then
    FreeAndNil(fGOST);
  inherited;
end;

procedure TElBuiltInGOST28147SymmetricCrypto.InitializeCipher();
begin
  if  Assigned(fGOST) then
    fGOST.Reset()
  else
    fGOST := TElGOST.Create();

  fGOST.Mode := GOSTMode_ECB;
  fGOST.Key := FKeyMaterial.Value;
  fGOST.IV := FKeyMaterial.IV;
end;

procedure TElBuiltInGOST28147SymmetricCrypto.SetParamSet(const Value : ByteArray);
var
  SBoxes : string;
begin
  if not Assigned(fGOST) then
    raise EElSymmetricCryptoError.Create(SInvalidContext);

  if CompareContent(Value, SB_OID_GOST_28147_1989_PARAM_CP_TEST) then
    SBoxes := SB_GOST28147_89_TestParamSet
  else if CompareContent(Value, SB_OID_GOST_28147_1989_PARAM_CP_A) then
    SBoxes := SB_GOST28147_89_CryptoPro_A_ParamSet
  else if CompareContent(Value, SB_OID_GOST_28147_1989_PARAM_CP_B) then
    SBoxes := SB_GOST28147_89_CryptoPro_B_ParamSet
  else if CompareContent(Value, SB_OID_GOST_28147_1989_PARAM_CP_C) then
    SBoxes := SB_GOST28147_89_CryptoPro_C_ParamSet
  else if CompareContent(Value, SB_OID_GOST_28147_1989_PARAM_CP_D) then
    SBoxes := SB_GOST28147_89_CryptoPro_D_ParamSet
  else
    raise EElBuiltInCryptoProviderError.Create(SInvalidPropertyValue);

  fGOST.Init(TElGOST.MakeSubstBlock(SBoxes));
end;

procedure TElBuiltInGOST28147SymmetricCrypto.SetSBoxes(const Value : ByteArray);
begin
  if Length(Value) <> 128 then
    raise EElBuiltInCryptoProviderError.Create(SInvalidPropertyValue);
  fGOST.Init(TElGOST.MakeSubstBlock(string(Value)));
end;                             

procedure TElBuiltInGOST28147SymmetricCrypto.ExpandKeyForEncryption;
begin
  InitializeCipher();
  FProcessedBlocks := 0;
end;

procedure TElBuiltInGOST28147SymmetricCrypto.ExpandKeyForDecryption;
begin
  InitializeCipher();
  FProcessedBlocks := 0;
end;

class procedure TElBuiltInGOST28147SymmetricCrypto.GetDefaultKeyAndBlockLengths(AlgID : integer;
  var KeyLen : integer; var BlockLen : integer);
begin
  KeyLen := TElGOST.KeySize;
  BlockLen := TElGOST.BlockSize;
end;

class procedure TElBuiltInGOST28147SymmetricCrypto.GetDefaultKeyAndBlockLengths(const OID : ByteArray;
  var KeyLen : integer; var BlockLen : integer);
begin
  KeyLen := TElGOST.KeySize;
  BlockLen := TElGOST.BlockSize;
end;
 {$endif SB_HAS_GOST}


////////////////////////////////////////////////////////////////////////////////
// TElBuiltInIdentitySymmetricCrypto class

constructor TElBuiltInIdentitySymmetricCrypto.Create(AlgID : integer;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  inherited Create(Mode);
  FKeySize := 0;
  FBlockSize := 1;
end;

constructor TElBuiltInIdentitySymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  inherited Create(Mode);
  FKeySize := 0;
  FBlockSize := 1;
end;

constructor TElBuiltInIdentitySymmetricCrypto.Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  inherited Create(Mode);
  FKeySize := 0;
  FBlockSize := 1;
end;

procedure TElBuiltInIdentitySymmetricCrypto.ExpandKeyForEncryption;
begin
  ;
end;

procedure TElBuiltInIdentitySymmetricCrypto.ExpandKeyForDecryption;
begin
  ;
end;

procedure TElBuiltInIdentitySymmetricCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  FKeyMaterial := Material;
end;

procedure TElBuiltInIdentitySymmetricCrypto.EncryptStreamBlock(Buffer, OutBuffer : pointer; Size : integer);
begin
  SBMove(Buffer^, OutBuffer^, Size);
end;

procedure TElBuiltInIdentitySymmetricCrypto.DecryptStreamBlock(Buffer, OutBuffer: pointer; Size : integer);
begin
  SBMove(Buffer^, OutBuffer^, Size);
end;

class function TElBuiltInIdentitySymmetricCrypto.StreamCipher : boolean;
begin
  Result := true;
end;

class function TElBuiltInIdentitySymmetricCrypto.IsAlgorithmSupported(AlgID : integer) : boolean;
begin
  Result := (AlgID = SB_ALGORITHM_CNT_IDENTITY);
end;

class function TElBuiltInIdentitySymmetricCrypto.IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;
begin
  Result := CompareContent(AlgOID, SB_OID_IDENTITY);
end;

class procedure TElBuiltInIdentitySymmetricCrypto.GetDefaultKeyAndBlockLengths(AlgID : integer; var KeyLen : integer;
  var BlockLen : integer);
begin
  KeyLen := 0;
  BlockLen := 0;
end;

class procedure TElBuiltInIdentitySymmetricCrypto.GetDefaultKeyAndBlockLengths(const OID : ByteArray; var KeyLen : integer;
  var BlockLen : integer);
begin
  KeyLen := 0;
  BlockLen := 0;
end;

end.
