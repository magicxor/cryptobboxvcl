(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$i SecBbox.inc}

unit SBSymmetricCrypto;

interface

uses
  SBCustomCrypto,
  {$ifdef WIN32}
  Windows,
 {$else}
  //{$ifndef FPC}Libc,{$endif}
 {$endif}
  Classes,
  SysUtils,
  SBTypes,
  SBUtils,
  SBStrUtils,
{$ifdef SB_HAS_WINCRYPT}
  SBWinCrypt,
 {$endif}
  SBSHA2,
  SBCryptoProv,
  SBCryptoProvManager,
  //SBCryptoProvDefault,
  SBCryptoProvUtils,
  SBCryptoProvRS,
  SBConstants,
  SBRandom;

type

  TElSymmetricKeyMaterial = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElSymmetricKeyMaterial = TElSymmetricKeyMaterial;
   {$endif}

  TElSymmetricKeyMaterial = class(TElKeyMaterial)
  private
{$ifdef SB_HAS_WINCRYPT}
    FWin32Handle : HCRYPTKEY;
    FWin32Prov : HCRYPTPROV;
 {$endif}
    //FKey : TElCustomCryptoKey;
    FProvider : TElCustomCryptoProvider;
    FProviderManager : TElCustomCryptoProviderManager;

    procedure SetKey(const Value : ByteArray);
    procedure SetIV(const Value : ByteArray);
    function GetKey : ByteArray;
    function GetIV : ByteArray;
  protected
    procedure Reset;

    function GetBits : integer; override;
    function GetAlgorithm : integer; override;
    function GetValid : boolean; override;
    procedure SetAlgorithm(Value: integer);
  public
    constructor Create(Prov : TElCustomCryptoProvider  =  nil);  overload;  virtual;
    constructor Create(Key : TElCustomCryptoKey; Prov : TElCustomCryptoProvider  =  nil);  overload;  virtual;
    constructor Create(Manager : TElCustomCryptoProviderManager; Prov : TElCustomCryptoProvider);  overload;  virtual;
    constructor Create(Key : TElCustomCryptoKey; Manager : TElCustomCryptoProviderManager; Prov : TElCustomCryptoProvider);  overload;  virtual;
     destructor  Destroy; override;
    {$ifndef SB_PGPSFX_STUB}
    procedure Generate(Bits : integer); override;
    procedure GenerateIV(Bits : integer); virtual;
    procedure DeriveKey(Bits : integer; const Password : string);  overload; 
    procedure DeriveKey(Bits : integer; const Password : string; const Salt : string);  overload; 
    procedure DeriveKey(Bits : integer; const Password : string; const Salt : ByteArray);  overload; 
    procedure DeriveKey(Bits : integer; const Password : string; const Salt : ByteArray; Iterations : integer);  overload; 

     {$endif SB_PGPSFX_STUB}
    procedure Load(Buffer : pointer; var Size : integer); reintroduce; overload; virtual;
    procedure Save(Buffer : pointer; var Size : integer); reintroduce; overload; virtual;
    procedure Load(Stream : TStream; Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}); overload; override;
    procedure Save(Stream : TStream); overload; override;
    {$ifdef SB_HAS_WINCRYPT}
    function ImportEncryptedSymmetricKeyWin32(const EncryptedKey : ByteArray;
      SymAlgorithm, PKAlgorithm : integer; const SymAlgParams: ByteArray;
      hProv : HCRYPTPROV; hUserKey : HCRYPTKEY): boolean;
     {$endif}
    procedure Persistentiate; override;
    property Key : ByteArray read GetKey write SetKey;
    property IV : ByteArray read GetIV write SetIV;
    property Algorithm : integer read GetAlgorithm write SetAlgorithm;
  end;

  TSBSymmetricCryptoMode = 
    (cmDefault, cmECB, cmCBC, cmCTR, cmCFB8, cmGCM, cmCCM);

  TSBSymmetricCipherPadding =  (cpNone, cpPKCS5);
  

  TElSymmetricCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElSymmetricCrypto = TElSymmetricCrypto;
   {$endif}

  TElSymmetricCrypto = class(TElCustomCrypto)
  private
    FKeyMaterial : TElSymmetricKeyMaterial;
    FOnProgress : TSBProgressEvent;
    FCryptoProvider : TElCustomCryptoProvider;
    FCryptoProviderManager : TElCustomCryptoProviderManager;
    FAlgID : integer;
    FAlgOID : ByteArray;
    FMode : TSBSymmetricCryptoMode;
    FContext : TElCustomCryptoContext;
    FPadding : TSBSymmetricCipherPadding;
    FCTRLittleEndian : boolean;
    FNonce : ByteArray;
    FTagSize : integer;
    FAssociatedDataSize : integer;
    FPayloadSize : integer;

    function GetMode : TSBSymmetricCryptoMode;
    function GetBlockSize : integer;
    function GetKeySize : integer;
    function GetPadding : TSBSymmetricCipherPadding;
    procedure SetPadding(Value : TSBSymmetricCipherPadding);
    function GetCTRLittleEndian : boolean;
    procedure SetCTRLittleEndian(Value : boolean);
    function GetNonce : ByteArray;
    procedure SetNonce(const Value : ByteArray);
    function GetTagSize : integer;
    procedure SetTagSize(Value : integer);
    function GetAssociatedDataSize : integer;
    procedure SetAssociatedDataSize(Value : integer);
    function GetPayloadSize : integer;
    procedure SetPayloadSize(Value : integer);
    function GetAssociatedData : boolean;
    procedure SetAssociatedData(Value : boolean);

  protected
    function DoProgress(Total, Current : Int64): boolean;
    procedure SetKeyMaterial(Material : TElSymmetricKeyMaterial); virtual;
    function GetNetIsStreamCipher : boolean; virtual;
  protected
    class function IsAlgorithmSupported(AlgID : integer; CryptoProvider : TElCustomCryptoProvider  =  nil) : boolean;  overload;  virtual;
    class function IsAlgorithmSupported(const AlgOID : ByteArray; CryptoProvider : TElCustomCryptoProvider  =  nil) : boolean;  overload;  virtual;

    class procedure GetDefaultKeyAndBlockLengths(AlgID : integer; var KeyLen : integer;
      var BlockLen : integer; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  virtual;
    class procedure GetDefaultKeyAndBlockLengths(const OID : ByteArray; var KeyLen : integer;
      var BlockLen : integer; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  virtual;

    class function IsAlgorithmSupported(AlgID : integer; Manager : TElCustomCryptoProviderManager;
      CryptoProvider : TElCustomCryptoProvider) : boolean;  overload;  virtual;
    class function IsAlgorithmSupported(const AlgOID : ByteArray; Manager : TElCustomCryptoProviderManager;
      CryptoProvider : TElCustomCryptoProvider) : boolean;  overload;  virtual;
    class procedure GetDefaultKeyAndBlockLengths(AlgID : integer; var KeyLen : integer;
      var BlockLen : integer; Manager : TElCustomCryptoProviderManager;
      CryptoProvider : TElCustomCryptoProvider);  overload;  virtual;
    class procedure GetDefaultKeyAndBlockLengths(const OID : ByteArray; var KeyLen : integer;
      var BlockLen : integer; Manager : TElCustomCryptoProviderManager;
      CryptoProvider : TElCustomCryptoProvider);  overload;  virtual;
    function EstimatedOutputSize(InputSize : integer; Encrypt : boolean) : integer;
    procedure Init; virtual;
    function GetSuitableCryptoProvider : TElCustomCryptoProvider; virtual;
  public
    constructor Create(AlgID : integer;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  virtual;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  virtual;
    constructor Create(Mode : TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  virtual;

    constructor Create(AlgID : integer;
      Mode: TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager;
      CryptoProvider : TElCustomCryptoProvider);  overload;  virtual;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager;
      CryptoProvider : TElCustomCryptoProvider);  overload;  virtual;
    constructor Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager;
      CryptoProvider : TElCustomCryptoProvider);  overload;  virtual;

     destructor  Destroy; override;
    {$ifndef SB_PGPSFX_STUB}
    procedure InitializeEncryption; virtual;
     {$endif SB_PGPSFX_STUB}
    procedure InitializeDecryption; virtual;
    {$ifndef SB_PGPSFX_STUB}
    procedure Encrypt(InBuffer: pointer; InSize : integer; OutBuffer: pointer;
      var OutSize : integer); overload;
    procedure Encrypt(InStream, OutStream: TStream); overload;
    procedure EncryptUpdate(InBuffer: pointer; InSize : integer; OutBuffer: pointer;
      var OutSize : integer);
    procedure FinalizeEncryption(OutBuffer : pointer; var OutSize : integer); virtual;
    procedure EncryptAEAD(AssociatedData : pointer; ADataSize : integer;
      InBuffer : pointer; InSize : integer; OutBuffer : pointer; var OutSize : integer); virtual;
     {$endif SB_PGPSFX_STUB}
    procedure Decrypt(InBuffer: pointer; InSize : integer; OutBuffer: pointer;
      var OutSize : integer); overload;
    procedure DecryptAEAD(AssociatedData : pointer; ADataSize : integer;
      InBuffer : pointer; InSize : integer; OutBuffer : pointer; var OutSize : integer); virtual;
    procedure Decrypt(InStream, OutStream: TStream; InCount: integer = 0); overload;
    procedure DecryptUpdate(InBuffer: pointer; InSize : integer; OutBuffer: pointer;
      var OutSize : integer); overload;
    {$ifdef SB_HAS_WINCRYPT}
    procedure DecryptUpdateWin32(InBuffer: pointer; InSize : integer; OutBuffer: pointer;
      var OutSize : integer);
     {$endif SB_HAS_WINCRYPT}
    procedure FinalizeDecryption(OutBuffer : pointer; var OutSize : integer); virtual;

    class function Decrypt(AlgID: integer; const Key, IV: ByteArray;
      Mode: TSBSymmetricCryptoMode; Buffer: Pointer; Size: integer): ByteArray; overload;
    {$ifndef SB_PGPSFX_STUB}
    class function Encrypt(AlgID: integer; const Key, IV: ByteArray;
      Mode: TSBSymmetricCryptoMode; Buffer: Pointer; Size: integer): ByteArray; overload;
     {$endif}

    property AlgID : integer read FAlgID;
    property KeyMaterial : TElSymmetricKeyMaterial read FKeyMaterial write SetKeyMaterial;
    property Mode : TSBSymmetricCryptoMode read GetMode;
    property BlockSize : integer read GetBlockSize;
    property KeySize : integer read GetKeySize;
    property Padding : TSBSymmetricCipherPadding read GetPadding write SetPadding;
    property CTRLittleEndian : boolean read GetCTRLittleEndian write SetCTRLittleEndian;
    property Nonce : ByteArray read GetNonce write SetNonce;
    property TagSize : integer read GetTagSize write SetTagSize;
    property AssociatedDataSize : integer read GetAssociatedDataSize write SetAssociatedDataSize;
    property PayloadSize : integer read GetPayloadSize write SetPayloadSize;
    property AssociatedData : boolean read GetAssociatedData write SetAssociatedData;
    property IsStreamCipher : boolean read GetNetIsStreamCipher;
    property CryptoProvider : TElCustomCryptoProvider read FCryptoProvider
      write FCryptoProvider;
    property CryptoProviderManager : TElCustomCryptoProviderManager read FCryptoProviderManager
      write FCryptoProviderManager;
    property OnProgress : TSBProgressEvent read FOnProgress write FOnProgress;
  end;

  TElSymmetricCryptoClass =  class of TElSymmetricCrypto;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElSymmetricCryptoClass = TElSymmetricCryptoClass;
   {$endif}

  TElSymmetricCryptoFactory = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElSymmetricCryptoFactory = TElSymmetricCryptoFactory;
   {$endif}

  TElSymmetricCryptoFactory = class
  private
    FCryptoProvider : TElCustomCryptoProvider;
    FCryptoProviderManager : TElCustomCryptoProviderManager;
  public
    constructor Create; 
    destructor Destroy; override;

    function CreateInstance(const OID : ByteArray;
      Mode : TSBSymmetricCryptoMode  =  cmDefault):
      TElSymmetricCrypto;  overload; 
    function CreateInstance(Alg : integer;
      Mode : TSBSymmetricCryptoMode  =  cmDefault):
      TElSymmetricCrypto;  overload; 
    function IsAlgorithmSupported(const OID : ByteArray): boolean;  overload; 
    function IsAlgorithmSupported(Alg : integer): boolean;  overload; 
    function GetDefaultKeyAndBlockLengths(Alg : integer; var KeyLen : integer;
      var BlockLen : integer): boolean;  overload; 
    function GetDefaultKeyAndBlockLengths(const OID: ByteArray; var KeyLen : integer;
      var BlockLen : integer): boolean;  overload; 

    property CryptoProvider : TElCustomCryptoProvider read FCryptoProvider write FCryptoProvider;
    property CryptoProviderManager : TElCustomCryptoProviderManager read FCryptoProviderManager write FCryptoProviderManager;
  end;

  TElAESSymmetricCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElAESSymmetricCrypto = TElAESSymmetricCrypto;
   {$endif}

  TElAESSymmetricCrypto = class(TElSymmetricCrypto)
  public
    constructor Create(AlgID : integer;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager; 
      CryptoProvider : TElCustomCryptoProvider);  overload;  override;
  end;

  TElBlowfishSymmetricCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElBlowfishSymmetricCrypto = TElBlowfishSymmetricCrypto;
   {$endif}

  TElBlowfishSymmetricCrypto = class(TElSymmetricCrypto)
  public
    constructor Create(AlgID : integer;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager; 
      CryptoProvider : TElCustomCryptoProvider);  overload;  override;
  end;

  TElTwofishSymmetricCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElTwofishSymmetricCrypto = TElTwofishSymmetricCrypto;
   {$endif}

  TElTwofishSymmetricCrypto = class(TElSymmetricCrypto)
  public
    constructor Create(AlgID : integer;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager; 
      CryptoProvider : TElCustomCryptoProvider);  overload;  override;
  end;

  {$ifndef SB_NO_IDEA}

  TElIDEASymmetricCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElIDEASymmetricCrypto = TElIDEASymmetricCrypto;
   {$endif}

  TElIDEASymmetricCrypto = class(TElSymmetricCrypto)
  public
    constructor Create(AlgID : integer;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager; 
      CryptoProvider : TElCustomCryptoProvider);  overload;  override;
  end;
   {$endif}

  TElCAST128SymmetricCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCAST128SymmetricCrypto = TElCAST128SymmetricCrypto;
   {$endif}

  TElCAST128SymmetricCrypto = class(TElSymmetricCrypto)
  public
    constructor Create(AlgID : integer;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override; 
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager; 
      CryptoProvider : TElCustomCryptoProvider);  overload;  override;
  end;

  {$ifndef SB_NO_RC2}

  TElRC2SymmetricCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElRC2SymmetricCrypto = TElRC2SymmetricCrypto;
   {$endif}

  TElRC2SymmetricCrypto = class(TElSymmetricCrypto)
  public
    constructor Create(AlgID : integer;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager; 
      CryptoProvider : TElCustomCryptoProvider);  overload;  override;
  end;
   {$endif}

  {$ifndef SB_NO_RC4}

  TElRC4SymmetricCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElRC4SymmetricCrypto = TElRC4SymmetricCrypto;
   {$endif}

  TElRC4SymmetricCrypto = class(TElSymmetricCrypto)
  private
    FSkipKeystreamBytes : integer;
    function GetSkipKeystreamBytes : integer;
    procedure SetSkipKeystreamBytes(Value: integer);
  protected
    procedure Init; override;
  public
    constructor Create(AlgID : integer;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager; 
      CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    {$ifndef SB_PGPSFX_STUB}
    procedure InitializeEncryption; override;
     {$endif}
    procedure InitializeDecryption; override;
    property SkipKeystreamBytes : integer read GetSkipKeystreamBytes
      write SetSkipKeystreamBytes;
  end;
   {$endif}

  {$ifndef SB_NO_DES}

  TElDESSymmetricCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElDESSymmetricCrypto = TElDESSymmetricCrypto;
   {$endif}

  TElDESSymmetricCrypto = class(TElSymmetricCrypto)
  public
    constructor Create(AlgID : integer;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager; 
      CryptoProvider : TElCustomCryptoProvider);  overload;  override;
  end;

  TEl3DESSymmetricCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  El3DESSymmetricCrypto = TEl3DESSymmetricCrypto;
   {$endif}

  TEl3DESSymmetricCrypto = class(TElSymmetricCrypto)
  public
    constructor Create(AlgID : integer;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager; 
      CryptoProvider : TElCustomCryptoProvider);  overload;  override;
  end;
   {$endif}

  {$ifndef SB_NO_CAMELLIA}

  TElCamelliaSymmetricCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCamelliaSymmetricCrypto = TElCamelliaSymmetricCrypto;
   {$endif}

  TElCamelliaSymmetricCrypto = class(TElSymmetricCrypto)
  public
    constructor Create(AlgID : integer;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager; 
      CryptoProvider : TElCustomCryptoProvider);  overload;  override;
  end;
   {$endif}

  TElSerpentSymmetricCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElSerpentSymmetricCrypto = TElSerpentSymmetricCrypto;
   {$endif}

  TElSerpentSymmetricCrypto = class(TElSymmetricCrypto)
  public
    constructor Create(AlgID : integer;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager; 
      CryptoProvider : TElCustomCryptoProvider);  overload;  override;
  end;

  {$ifndef SB_NO_SEED}

  TElSEEDSymmetricCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElSEEDSymmetricCrypto = TElSEEDSymmetricCrypto;
   {$endif}

  TElSEEDSymmetricCrypto = class(TElSymmetricCrypto)
  public
    constructor Create(AlgID : integer;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager; 
      CryptoProvider : TElCustomCryptoProvider);  overload;  override;
  end;
   {$endif}

  {$ifndef SB_NO_RABBIT}

  TElRabbitSymmetricCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElRabbitSymmetricCrypto = TElRabbitSymmetricCrypto;
   {$endif}

  TElRabbitSymmetricCrypto = class(TElSymmetricCrypto)
  public
    constructor Create(AlgID : integer;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override; 
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager; 
      CryptoProvider : TElCustomCryptoProvider);  overload;  override;
  end;
   {$endif}

  {$ifdef SB_HAS_GOST}
  TElGOST28147SymmetricCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElGOST28147SymmetricCrypto = TElGOST28147SymmetricCrypto;
   {$endif}

  TElGOST28147SymmetricCrypto = class(TElSymmetricCrypto)
  private
    FParamSet : ByteArray;
    FSBoxes : ByteArray;
    FUseKeyMeshing : boolean;
    function GetParamSet : ByteArray;
    procedure SetParamSet(const Value : ByteArray);
    function GetSBoxes : ByteArray;
    procedure SetSBoxes(const Value : ByteArray);
    function GetUseKeyMeshing : boolean;
    procedure SetUseKeyMeshing(Value : boolean);
  protected
    procedure Init; override;
  public
    constructor Create(AlgID : integer;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager; 
      CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    procedure InitializeEncryption; override;
    procedure InitializeDecryption; override;      

    property ParamSet : ByteArray read GetParamSet write SetParamSet;
    property SBoxes : ByteArray read GetSBoxes write SetSBoxes;
    property UseKeyMeshing : boolean read GetUseKeyMeshing write SetUseKeyMeshing;
  end;
   {$endif}

  TElIdentitySymmetricCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElIdentitySymmetricCrypto = TElIdentitySymmetricCrypto;
   {$endif}

  TElIdentitySymmetricCrypto = class(TElSymmetricCrypto)
  public
    constructor Create(AlgID : integer;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode  =  cmDefault;
      CryptoProvider : TElCustomCryptoProvider  =  nil);  overload;  override;
    constructor Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload;  override;
    constructor Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager; 
      CryptoProvider : TElCustomCryptoProvider);  overload;  override;
  end;

  EElSymmetricCryptoError =  class(ESecureBlackboxError);

// TODO: add checkups for FContext <> nil

implementation

uses
  SBASN1Tree{$ifndef SB_PGPSFX_STUB}, SBPKCS5 {$endif};

const
  SYMMETRIC_BLOCK_SIZE = 16384;
  SYMMETRIC_DEFAULT_MODE = cmCBC;

resourcestring
  SOutputBufferTooSmall = 'Output buffer too small';
  SUnsupportedAlgorithmInt = 'Unsupported algorithm %d';
  SUnsupportedAlgorithm = 'Unsupported algorithm %d';
  SCryptoProviderError = 'Crypto provider error %d';
  SUseAnotherConstructor = 'This constructor is pure virtual, please use another one';
  SCryptoAlreadyInitialized = 'Symmetric crypto is already initialized';
  SInternalException = 'Internal exception';
  SInvalidKeyFormat = 'Invalid key format';
  SKeyMaterialIsNotSet = 'Key material is not set';

(*

{$ifndef SB_NET}
const
{$else}
var
{$endif}

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS OFF}
{$endif}

  CALG_RSA_KEYX_ID      : TByteArrayConst {$ifndef SB_NET}={$else}:={$endif} #$00#$a4#$00#$00; {$ifdef SB_NET}readonly;{$endif}
  CALG_DES_ID           : TByteArrayConst {$ifndef SB_NET}={$else}:={$endif} #$01#$66#$00#$00; {$ifdef SB_NET}readonly;{$endif}
  CALG_3DES_ID          : TByteArrayConst {$ifndef SB_NET}={$else}:={$endif} #$03#$66#$00#$00; {$ifdef SB_NET}readonly;{$endif}
  CALG_RC2_ID           : TByteArrayConst {$ifndef SB_NET}={$else}:={$endif} #$02#$66#$00#$00; {$ifdef SB_NET}readonly;{$endif}
  CALG_RC4_ID           : TByteArrayConst {$ifndef SB_NET}={$else}:={$endif} #$01#$68#$00#$00; {$ifdef SB_NET}readonly;{$endif}
  CALG_AES_128_ID       : TByteArrayConst {$ifndef SB_NET}={$else}:={$endif} #$0E#$66#$00#$00; {$ifdef SB_NET}readonly;{$endif}
  CALG_AES_192_ID       : TByteArrayConst {$ifndef SB_NET}={$else}:={$endif} #$0F#$66#$00#$00; {$ifdef SB_NET}readonly;{$endif}
  CALG_AES_256_ID       : TByteArrayConst {$ifndef SB_NET}={$else}:={$endif} #$10#$66#$00#$00; {$ifdef SB_NET}readonly;{$endif}
  CALG_AES_ID           : TByteArrayConst {$ifndef SB_NET}={$else}:={$endif} #$11#$66#$00#$00; {$ifdef SB_NET}readonly;{$endif}
  BLOB_ID_AND_RESERVED  : TByteArrayConst {$ifndef SB_NET}={$else}:={$endif} #$01#$02#$00#$00; {$ifdef SB_NET}readonly;{$endif}

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS ON}
{$endif}

*)

function ConvertSymmetricCryptoMode(Value : TSBSymmetricCryptoMode): integer;  overload; 
begin
  case Value of
    cmECB : Result := SB_SYMENC_MODE_BLOCK;
    cmCBC : Result := SB_SYMENC_MODE_CBC;
    cmCTR : Result := SB_SYMENC_MODE_CTR;
    cmCFB8 : Result := SB_SYMENC_MODE_CFB8;
    cmCCM : Result := SB_SYMENC_MODE_CCM;
    cmGCM : Result := SB_SYMENC_MODE_GCM;
  else
    Result := SB_SYMENC_MODE_DEFAULT;
  end;
end;

function ConvertSymmetricCryptoMode(Value : integer): TSBSymmetricCryptoMode;  overload; 
begin
  case Value of
    SB_SYMENC_MODE_BLOCK : Result := cmECB;
    SB_SYMENC_MODE_CBC : Result := cmCBC;
    SB_SYMENC_MODE_CTR : Result := cmCTR;
    SB_SYMENC_MODE_CFB8 : Result := cmCFB8;
    SB_SYMENC_MODE_CCM : Result := cmCCM;
    SB_SYMENC_MODE_GCM : Result := cmGCM;
  else
    Result := cmDefault;
  end;
end;

function ConvertSymmetricCipherPadding(Padding : TSBSymmetricCipherPadding) : integer;  overload; 
begin
  case Padding of
    cpPKCS5 : Result := SB_SYMENC_PADDING_PKCS5;
  else
    Result := SB_SYMENC_PADDING_NONE;
  end;
end;

function ConvertSymmetricCipherPadding(Padding : integer): TSBSymmetricCipherPadding;  overload; 
begin
  case Padding of
    SB_SYMENC_PADDING_PKCS5 : Result := cpPKCS5;
  else
    Result := cpNone;
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// TElSymmetricKeyMaterial class

constructor TElSymmetricKeyMaterial.Create(Prov : TElCustomCryptoProvider  =  nil);
begin
  inherited Create;
  {$ifdef SB_HAS_WINCRYPT}
  FWin32Handle := 0;
  FWin32Prov := 0;
   {$endif}
  if Prov = nil then
    Prov := DefaultCryptoProviderManager.{$ifndef BUILDER_USED}GetSuitableProvider {$else}GetSuitableProvider3 {$endif}(SB_ALGORITHM_CNT_SYMMETRIC, 0);
    //Prov := DefaultCryptoProvider;
  FKey := Prov.CreateKey(SB_ALGORITHM_CNT_SYMMETRIC, 0, nil);
  FProvider := Prov;
end;

constructor TElSymmetricKeyMaterial.Create(Key : TElCustomCryptoKey;
  Prov : TElCustomCryptoProvider  =  nil);
begin
  inherited Create;
  {$ifdef SB_HAS_WINCRYPT}
  FWin32Handle := 0;
  FWin32Prov := 0;
   {$endif}
  if Prov = nil then
    Prov := Key.CryptoProvider;
  FKey := Key;
  FProvider := Prov;
end;

constructor TElSymmetricKeyMaterial.Create(Manager : TElCustomCryptoProviderManager;
  Prov : TElCustomCryptoProvider);
begin
  inherited Create;
  {$ifdef SB_HAS_WINCRYPT}
  FWin32Handle := 0;
  FWin32Prov := 0;
   {$endif}
  if Prov = nil then
  begin
    if Manager = nil then
      Manager := DefaultCryptoProviderManager;
    Prov := Manager.{$ifndef BUILDER_USED}GetSuitableProvider {$else}GetSuitableProvider3 {$endif}(SB_ALGORITHM_CNT_SYMMETRIC, 0);
  end;
  FKey := Prov.CreateKey(SB_ALGORITHM_CNT_SYMMETRIC, 0, nil);
  FProvider := Prov;
  FProviderManager := Manager;       
end;

constructor TElSymmetricKeyMaterial.Create(Key : TElCustomCryptoKey;
  Manager : TElCustomCryptoProviderManager; Prov : TElCustomCryptoProvider);
begin
  inherited Create;
  {$ifdef SB_HAS_WINCRYPT}
  FWin32Handle := 0;
  FWin32Prov := 0;
   {$endif}
  if Prov = nil then
    Prov := Key.CryptoProvider;
  FKey := Key;
  FProvider := Prov;
  FProviderManager := Manager;
end;

 destructor  TElSymmetricKeyMaterial.Destroy;
begin
  Reset;
  if FKey <> nil then
    FKey.CryptoProvider.ReleaseKey(FKey);
  inherited;
end;


procedure TElSymmetricKeyMaterial.SetKey(const Value : ByteArray);
begin
  FKey.Value := CloneArray(Value);
end;

procedure TElSymmetricKeyMaterial.SetIV(const Value : ByteArray);
begin
  FKey.IV := CloneArray(Value);
end;

function TElSymmetricKeyMaterial.GetKey : ByteArray;
begin
  Result := FKey.Value;
end;

function TElSymmetricKeyMaterial.GetIV : ByteArray;
begin
  Result := FKey.IV;
end;

function TElSymmetricKeyMaterial.GetAlgorithm : integer;
begin
  Result := FKey.Algorithm;
end;

procedure TElSymmetricKeyMaterial.SetAlgorithm(Value: integer);
begin
  FKey.ChangeAlgorithm(Value);
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElSymmetricKeyMaterial.Generate(Bits : integer);
begin
  FKey.Generate(Bits);
end;

procedure TElSymmetricKeyMaterial.GenerateIV(Bits : integer);
var
  Tmp : ByteArray;
begin
  if Bits mod 8 <> 0 then
    raise EElSymmetricCryptoError.Create(SInvalidInputSize);
  SetLength(Tmp, Bits shr 3);
  SBRandom.SBRndGenerate(@Tmp[0], Bits shr 3);
  IV := Tmp;
end;

procedure TElSymmetricKeyMaterial.DeriveKey(Bits : integer; const Password : string);
begin
  DeriveKey(Bits, Password, '');
end;

procedure TElSymmetricKeyMaterial.DeriveKey(Bits : integer; const Password : string; const Salt : string);
var
  PBE : TElPKCS5PBE;
  Key : ByteArray;
begin
  PBE := TElPKCS5PBE.Create(SB_ALGORITHM_CNT_AES128 {doesn't matter as we do not intend to do any encryption}, SB_ALGORITHM_DGST_SHA256, true);
  try
    PBE.Salt := {$ifndef SB_ANSI_VCL}StrToUTF8 {$else}BytesOfString {$endif}(Salt);
    Key := PBE.DeriveKey(Password, Bits);
    SetKey((Key));
  finally
    FreeAndNil(PBE);
  end;
end;

procedure TElSymmetricKeyMaterial.DeriveKey(Bits : integer; const Password : string; const Salt : ByteArray);
var
  PBE : TElPKCS5PBE;
  Key : ByteArray;
begin
  PBE := TElPKCS5PBE.Create(SB_ALGORITHM_CNT_AES128 {doesn't matter as we do not intend to do any encryption}, SB_ALGORITHM_DGST_SHA256, true);
  try
    PBE.Salt := Salt;
    Key := PBE.DeriveKey(Password, Bits);
    SetKey((Key));
  finally
    FreeAndNil(PBE);
  end;
end;

procedure TElSymmetricKeyMaterial.DeriveKey(Bits : integer; const Password : string; const Salt : ByteArray; Iterations : integer);
var
  PBE : TElPKCS5PBE;
  Key : ByteArray;
begin
  PBE := TElPKCS5PBE.Create(SB_ALGORITHM_CNT_AES128 {doesn't matter as we do not intend to do any encryption}, SB_ALGORITHM_DGST_SHA256, true);
  try
    PBE.Salt := Salt;
    PBE.IterationCount := Iterations;
    Key := PBE.DeriveKey(Password, Bits);
    SetKey((Key));
  finally
    FreeAndNil(PBE);
  end;
end;

 {$endif SB_PGPSFX_STUB}

{ Save/Load routines }
{ format : <word algorithm><word KeySize><key><word IVsize><IV><SHA-256 hash of all previous data>
  all numbers are big-endian }

procedure TElSymmetricKeyMaterial.Load(Buffer : pointer; var Size : integer);
begin
  FKey.ImportSecret(Buffer, Size);
end;

procedure TElSymmetricKeyMaterial.Save(Buffer : pointer; var Size : integer);
begin
  FKey.ExportSecret(Buffer, Size);
end;                    

procedure TElSymmetricKeyMaterial.Load(Stream :  TStream ; Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
var
  Size, KeySize, IVSize : integer;
  InSize : Int64;
  Buf : ByteArray;
begin

  if Count = 0 then
    InSize := Stream. Size  - Stream.Position
  else
    InSize := Count;

  if InSize < 38 then
    raise EElSymmetricCryptoError.Create(SInvalidKeyFormat);

  SetLength(Buf, 4);
  try
    Stream.Read( Buf[0] , 4);
    KeySize := Buf[2] shl 8 + Buf[3];

    if InSize < 38 + KeySize then
      raise EElSymmetricCryptoError.Create(SInvalidKeyFormat);

    SetLength(Buf, 6 + KeySize);
    Stream.Read( Buf[4] , KeySize + 2);
    IVSize := Buf[4 + KeySize] shl 8 + Buf[5 + KeySize];

    if InSize < 38 + KeySize + IVSize then
      raise EElSymmetricCryptoError.Create(SInvalidKeyFormat);

    SetLength(Buf, 38 + KeySize + IVSize);
    Stream.Read( Buf[6 + KeySize] , IVSize + 32);

    Size := 38 + KeySize + IVSize;
    Load( @Buf[0] , Size);

  finally
    ReleaseArray(Buf);
  end;
end;

procedure TElSymmetricKeyMaterial.Save(Stream : TElOutputStream);
var
  Buf : ByteArray;
  Size : integer;
begin
  Size := 0;

   Save( nil , Size);
  SetLength(Buf, Size);
   Save( @Buf[0] , Size);

  Stream.Write( Buf[0] , Size);

  ReleaseArray(Buf);
end;

function TElSymmetricKeyMaterial.GetBits : integer;
begin
  Result := FKey.Bits;
end;

function TElSymmetricKeyMaterial.GetValid : boolean;
begin
  Result := true;
end;             

{$ifdef SB_HAS_WINCRYPT}
function TElSymmetricKeyMaterial.ImportEncryptedSymmetricKeyWin32(const EncryptedKey : ByteArray;
  SymAlgorithm, PKAlgorithm : integer; const SymAlgParams: ByteArray;
  hProv : HCRYPTPROV; hUserKey : HCRYPTKEY): boolean;
(*var
  PKAlgID, SymAlgID : ByteArray;
  Blob : ByteArray;
  RotatedKey : ByteArray;
  hSymKey : HCRYPTKEY;
  dwValue : DWORD;
  IV : ByteArray;
  KeyLen : integer;
  {$ifndef SB_VCL}
  B : BOOL;
  DwBuf : ByteArray;
  BlobPin : GCHandle;
  {$endif}*)
begin
  (*
  // If the method succeeds, the passed hProv value is kept by
  // the TElSymmetricKeyMaterial object and released later (so the caller should
  // not release them).
  // If the method fails, the caller should free hProv object.
  Reset;
  Result := false;
  // forming key blob
  if PKAlgorithm = SB_ALGORITHM_PK_RSA then
    PKAlgID := CALG_RSA_KEYX_ID
  else
    Exit;
  case SymAlgorithm of
    SB_ALGORITHM_CNT_DES :
      SymAlgID := CALG_DES_ID;
    SB_ALGORITHM_CNT_3DES :
      SymAlgID := CALG_3DES_ID;
    SB_ALGORITHM_CNT_RC2 :
      SymAlgID := CALG_RC2_ID;
    SB_ALGORITHM_CNT_RC4 :
      SymAlgID := CALG_RC4_ID;
    SB_ALGORITHM_CNT_AES128 :
      SymAlgID := CALG_AES_128_ID;
    SB_ALGORITHM_CNT_AES192 :
      SymAlgID := CALG_AES_192_ID;
    SB_ALGORITHM_CNT_AES256 :
      SymAlgID := CALG_AES_256_ID;
    else
      Exit;
  end;
  RotatedKey := RotateInteger(EncryptedKey);
  Blob := BLOB_ID_AND_RESERVED + SymAlgID;
  Blob := TByteArrayConst(Blob) + PKAlgID;
  Blob := TByteArrayConst(Blob) + RotatedKey;
  // calling cryptimportkey
  {$ifdef SB_VCL}
  if not CryptImportKey(hProv, @Blob[1], Length(Blob), hUserKey, CRYPT_NO_SALT, @hSymKey) then
  {$else}
  BlobPin := GCHandle.Alloc(Blob, GCHandleType.Pinned);
  try
    B := CryptImportKey(hProv, Marshal.UnsafeAddrOfPinnedArrayElement(Blob, 0),
      Length(Blob), hUserKey, CRYPT_NO_SALT, hSymKey);
  finally
    BlobPin.Free;
  end;
  if B = {$ifdef SB_NET}0{$else}false{$endif} then
  {$endif}
    Exit;
  FWin32Handle := hSymKey;
  FWin32Prov := hProv;
  Result := true;
  // setting necessary params (IV for block ciphers, effective keylen for RC2 and RC4)
  if (SymAlgorithm = SB_ALGORITHM_CNT_RC2) then
  begin
    // setting effective key length
    if ExtractRC2KeyParameters(SymAlgParams, KeyLen, IV) then
    begin
      dwValue := KeyLen;
      {$ifdef SB_VCL}
      CryptSetKeyParam(hSymKey, KP_EFFECTIVE_KEYLEN, @dwValue, 0);
      {$else}
      SetLength(dwBuf, 4);
      dwBuf[0] := dwValue and $ff;
      dwBuf[1] := (dwValue shr 8) and $ff;
      dwBuf[2] := (dwValue shr 16) and $ff;
      dwBuf[3] := (dwValue shr 24) and $ff;
      BlobPin := GCHandle.Alloc(dwBuf, GCHandleType.Pinned);
      try
        CryptSetKeyParam(hSymKey, KP_EFFECTIVE_KEYLEN, Marshal.UnsafeAddrOfPinnedArrayElement(dwBuf, 0),
          0);
      finally
        BlobPin.Free;
      end;
      {$endif}
    end;
  end
  else if (SymAlgorithm <> SB_ALGORITHM_CNT_RC4) then
    ExtractIV(SymAlgParams, IV);
  if SymAlgorithm <> SB_ALGORITHM_CNT_RC4 then
  begin
    if Length(IV) >= 8 then
    {$ifdef SB_VCL}
      CryptSetKeyParam(hSymKey, KP_IV, @IV[1], 0);
    {$else}
    begin
      BlobPin := GCHandle.Alloc(IV, GCHandleType.Pinned);
      try
        CryptSetKeyParam(hSymKey, KP_IV, Marshal.UnsafeAddrOfPinnedArrayElement(IV, 0),
          0);
      finally
        BlobPin.Free;
      end;
    end;
    {$endif}
  end;
  SetLength(FIV, Length(IV));
  {$ifdef SB_VCL}
  SBMove(IV[1], FIV[0], Length(FIV));
  {$else}
  SBMove(IV, 0, FIV, 0, Length(FIV));
  {$endif}
  *)
  Result := false;
end;
 {$endif}

procedure TElSymmetricKeyMaterial.Reset;
begin
  {$ifdef SB_HAS_WINCRYPT}
  if FWin32Handle <> 0 then
  begin
    CryptDestroyKey(FWin32Handle);
    FWin32Handle := 0;
  end;
  if FWin32Prov <> 0 then
  begin
    CryptReleaseContext(FWin32Prov, 0);
    FWin32Prov := 0;
  end;
   {$endif}
end;

procedure TElSymmetricKeyMaterial.Persistentiate;
begin
  FKey.Persistentiate;
end;

////////////////////////////////////////////////////////////////////////////////
// TElSymmetricCrypto class

constructor TElSymmetricCrypto.Create(AlgID : integer;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited Create;
  FCryptoProvider := CryptoProvider;
  if not GetSuitableCryptoProvider.IsAlgorithmSupported(AlgID, ConvertSymmetricCryptoMode(Mode)) then
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmInt, [AlgID]));

  FContext := nil;  
  FAlgID := AlgID;
  FMode := Mode;
  FAlgOID := EmptyArray;
  FNonce := EmptyArray;
  FTagSize := 16;
  FPayloadSize := 0;
  FAssociatedDataSize := 0;

  Init;
end;

constructor TElSymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited Create;
  FCryptoProvider := CryptoProvider;
  if not GetSuitableCryptoProvider.IsAlgorithmSupported(AlgOID, EmptyArray, ConvertSymmetricCryptoMode(Mode)) then
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]));

  FContext := nil;  
  FAlgID := SB_ALGORITHM_UNKNOWN;
  FMode := Mode;
  FAlgOID := AlgOID;
  Init;
end;

constructor TElSymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited Create;
  FCryptoProvider := CryptoProvider;

  if IsStreamCipher then
  begin
    FMode := cmDefault;
  end
  else
  begin
    if Mode = cmDefault then
      Mode := SYMMETRIC_DEFAULT_MODE;

    FMode := Mode;
  end;

  FContext := nil;
  FKeyMaterial := nil;
  FAlgOID := EmptyArray;
  FAlgID := SB_ALGORITHM_UNKNOWN;
  Init;
end;


constructor TElSymmetricCrypto.Create(AlgID : integer;
  Mode: TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create;
  FCryptoProvider := CryptoProvider;
  FCryptoProviderManager := Manager;
  if not GetSuitableCryptoProvider.IsAlgorithmSupported(AlgID, ConvertSymmetricCryptoMode(Mode)) then
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmInt, [AlgID]));

  FContext := nil;  
  FAlgID := AlgID;
  FMode := Mode;
  FAlgOID := EmptyArray;
  Init;
end;

constructor TElSymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create;
  FCryptoProvider := CryptoProvider;
  FCryptoProviderManager := Manager;
  if not GetSuitableCryptoProvider.IsAlgorithmSupported(AlgOID, EmptyArray, ConvertSymmetricCryptoMode(Mode)) then
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]));

  FContext := nil;
  FAlgID := SB_ALGORITHM_UNKNOWN;
  FMode := Mode;
  FAlgOID := AlgOID;
  Init;
end;

constructor TElSymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create;
  FCryptoProvider := CryptoProvider;
  FCryptoProviderManager := Manager;

  if IsStreamCipher then
  begin
    FMode := cmDefault;
  end
  else
  begin
    if Mode = cmDefault then
      Mode := SYMMETRIC_DEFAULT_MODE;

    FMode := Mode;
  end;

  FContext := nil;
  FKeyMaterial := nil;
  FAlgOID := EmptyArray;
  FAlgID := SB_ALGORITHM_UNKNOWN;
  Init;
end;

 destructor  TElSymmetricCrypto.Destroy;
begin
  if Assigned(FContext) and Assigned(FContext.CryptoProvider) then
    FContext.CryptoProvider.ReleaseCryptoContext(FContext);
  inherited;
end;


{$ifndef SB_PGPSFX_STUB}
class function TElSymmetricCrypto.Encrypt(AlgID: integer; const Key, IV: ByteArray;
  Mode: TSBSymmetricCryptoMode; Buffer: Pointer; Size: integer): ByteArray;
var
  Factory: TElSymmetricCryptoFactory;
  Crypto: TElSymmetricCrypto;
  KM: TElSymmetricKeyMaterial;
  Sz: integer;
begin
  Result := EmptyArray;
  
  Factory := TElSymmetricCryptoFactory.Create;
  try
    KM := TElSymmetricKeyMaterial.Create;
    try
      Crypto := Factory.CreateInstance(AlgID, Mode);
      try
        KM.Key := Key;
        KM.IV := IV;
        
        Crypto.KeyMaterial := KM;
        
        Sz := 0;
         Crypto.Encrypt(Buffer,  Size ,
           nil , Sz);
        SetLength(Result, Sz);
         Crypto.Encrypt(Buffer,  Size ,
           @Result[0] , Sz);
        SetLength(Result, Sz);
      finally
        FreeAndNil(Crypto);
      end;
    finally
      FreeAndNil(KM);
    end;
  finally
    FreeAndNil(Factory);
  end;
end;
 {$endif}

class function TElSymmetricCrypto.Decrypt(AlgID: integer; const Key, IV: ByteArray;
  Mode: TSBSymmetricCryptoMode; Buffer: Pointer; Size: integer): ByteArray;
var
  Factory: TElSymmetricCryptoFactory;
  Crypto: TElSymmetricCrypto;
  KM: TElSymmetricKeyMaterial;
  Sz: integer;
begin
  Result := EmptyArray;
  
  Factory := TElSymmetricCryptoFactory.Create;
  try
    KM := TElSymmetricKeyMaterial.Create;
    try
      Crypto := Factory.CreateInstance(AlgID, Mode);
      try
        KM.Key := Key;
        KM.IV := IV;
        
        Crypto.KeyMaterial := KM;
        
        Sz := 0;
         Crypto.Decrypt(Buffer,  Size ,
           nil , Sz);
        SetLength(Result, Sz);
         Crypto.Decrypt(Buffer,  Size ,
           @Result[0] , Sz);
        SetLength(Result, Sz);
      finally
        FreeAndNil(Crypto);
      end;
    finally
      FreeAndNil(KM);
    end;
  finally
    FreeAndNil(Factory);
  end;
end;

procedure TElSymmetricCrypto.Init;
begin
  FPadding := cpPKCS5;
  FCTRLittleEndian := false;
end;

function TElSymmetricCrypto.DoProgress(Total, Current : Int64): boolean;
var
  Cancel : TSBBoolean;
begin
  Cancel := false;
  if Assigned(FOnProgress) then
    FOnProgress(Self, Total, Current, Cancel);
  Result := not Cancel;
end;

procedure TElSymmetricCrypto.SetKeyMaterial(Material : TElSymmetricKeyMaterial);
begin
  FKeyMaterial := Material;
end;

function TElSymmetricCrypto.GetMode : TSBSymmetricCryptoMode;
begin
  Result := ConvertSymmetricCryptoMode(FContext.Mode);
end;

function TElSymmetricCrypto.GetBlockSize : integer;
var
  Val : ByteArray;
begin
  if FContext <> nil then
    Result := FContext.BlockSize
  else
  begin
    // retrieving key size from crypto provider
    if Length(FAlgOID) > 0 then
      Val := GetSuitableCryptoProvider.GetAlgorithmProperty(FAlgOID, EmptyArray,
        ConvertSymmetricCryptoMode(FMode), SB_ALGPROP_BLOCK_SIZE)
    else
      Val := GetSuitableCryptoProvider.GetAlgorithmProperty(FAlgID,
        ConvertSymmetricCryptoMode(FMode), SB_ALGPROP_BLOCK_SIZE);
    Result := GetIntegerPropFromBuffer(Val);
  end;
end;

function TElSymmetricCrypto.GetKeySize : integer;
var
  Val : ByteArray;
begin
  if FContext <> nil then
    Result := FContext.KeySize
  else
  begin
    // retrieving key size from crypto provider
    if Length(FAlgOID) > 0 then
      Val := GetSuitableCryptoProvider.GetAlgorithmProperty(FAlgOID, EmptyArray,
        ConvertSymmetricCryptoMode(FMode), SB_ALGPROP_DEFAULT_KEY_SIZE)
    else
      Val := GetSuitableCryptoProvider.GetAlgorithmProperty(FAlgID, 
        ConvertSymmetricCryptoMode(FMode), SB_ALGPROP_DEFAULT_KEY_SIZE);
    Result := GetIntegerPropFromBuffer(Val);
  end;
end;

function TElSymmetricCrypto.GetNonce : ByteArray;
begin
  if Assigned(FContext) then
    Result := FContext.GetContextProp(SB_CTXPROP_AEAD_NONCE)
  else
    Result := FNonce;
end;

procedure TElSymmetricCrypto.SetNonce(const Value : ByteArray);
begin
  FNonce := CloneArray(Value);
  if Assigned(FContext) then
    FContext.SetContextProp(SB_CTXPROP_AEAD_NONCE, Value);
end;

function TElSymmetricCrypto.GetTagSize : integer;
begin
  if Assigned(FContext) then
    Result := GetIntegerPropFromBuffer(FContext.GetContextProp(SB_CTXPROP_AEAD_TAG_SIZE))
  else
    Result := FTagSize;
end;

procedure TElSymmetricCrypto.SetTagSize(Value : integer);
begin
  FTagSize := Value;
  if Assigned(FContext) then
    FContext.SetContextProp(SB_CTXPROP_AEAD_TAG_SIZE, GetBufferFromInteger(Value));
end;

function TElSymmetricCrypto.GetAssociatedDataSize : integer;
begin
  if Assigned(FContext) then
    Result := GetIntegerPropFromBuffer(FContext.GetContextProp(SB_CTXPROP_CCM_ASSOCIATED_DATA_SIZE))
  else
    Result := FAssociatedDataSize;
end;

procedure TElSymmetricCrypto.SetAssociatedDataSize(Value : integer);
begin
  FAssociatedDataSize := Value;
  if Assigned(FContext) then
    FContext.SetContextProp(SB_CTXPROP_CCM_ASSOCIATED_DATA_SIZE, GetBufferFromInteger(Value));
end;

function TElSymmetricCrypto.GetPayloadSize : integer;
begin
  if Assigned(FContext) then
    Result := GetIntegerPropFromBuffer(FContext.GetContextProp(SB_CTXPROP_CCM_PAYLOAD_SIZE))
  else
    Result := FPayloadSize;
end;

procedure TElSymmetricCrypto.SetPayloadSize(Value : integer);
begin
  FPayloadSize := Value;
  if Assigned(FContext) then
    FContext.SetContextProp(SB_CTXPROP_CCM_PAYLOAD_SIZE, GetBufferFromInteger(Value));
end;

function TElSymmetricCrypto.GetAssociatedData : boolean;
begin
  if Assigned(FContext) then
    Result := GetBoolFromBuffer(FContext.GetContextProp(SB_CTXPROP_AEAD_ASSOCIATED_DATA))
  else
    Result := false;
end;

procedure TElSymmetricCrypto.SetAssociatedData(Value : boolean);
begin
  if Assigned(FContext) then
    FContext.SetContextProp(SB_CTXPROP_AEAD_ASSOCIATED_DATA, GetBufferFromBool(Value));
end;


function TElSymmetricCrypto.GetPadding : TSBSymmetricCipherPadding;
begin
  if FContext <> nil then
    Result := ConvertSymmetricCipherPadding(FContext.Padding)
  else
    Result := FPadding;
end;

procedure TElSymmetricCrypto.SetPadding(Value : TSBSymmetricCipherPadding);
begin
  if FContext <> nil then
    FContext.Padding := ConvertSymmetricCipherPadding(Value)
  else
    FPadding := Value;
end;

function TElSymmetricCrypto.GetCTRLittleEndian : boolean;
begin
  if FContext <> nil then
    Result := GetBoolFromBuffer(FContext.GetContextProp(SB_CTXPROP_CTR_LITTLE_ENDIAN))
  else
    Result := FCTRLittleEndian;
end;

procedure TElSymmetricCrypto.SetCTRLittleEndian(Value : boolean);
begin
  if FContext <> nil then
    FContext.SetContextProp(SB_CTXPROP_CTR_LITTLE_ENDIAN, GetBufferFromBool(Value))
  else
    FCTRLittleEndian := Value;
end;


function TElSymmetricCrypto.EstimatedOutputSize(InputSize : integer; Encrypt : boolean) : integer;
var
  BlockSize : integer;
begin
  if IsStreamCipher then
  begin
    Result := InputSize;
    Exit;
  end;

  if (FMode = cmCFB8) or
    (FMode = cmCTR)
  then
  begin
    Result := InputSize;
    Exit;
  end;

  if Assigned(FContext) then
    BlockSize := FContext.BlockSize
  else
  begin
    if Length(FAlgOID) > 0 then
      BlockSize := GetIntegerPropFromBuffer(GetSuitableCryptoProvider.GetAlgorithmProperty(FAlgOID,
        EmptyArray, 0, SB_ALGPROP_BLOCK_SIZE))
    else
      BlockSize := GetIntegerPropFromBuffer(GetSuitableCryptoProvider.GetAlgorithmProperty(FAlgID,
        0, SB_ALGPROP_BLOCK_SIZE));
  end;
  if Encrypt then
  begin
    if Padding = cpPKCS5 then
      Result := InputSize + BlockSize - InputSize mod BlockSize
    else if Padding = cpNone then
      Result := InputSize
    else
      raise EElSymmetricCryptoError.Create(SInternalException);
  end
  else
  begin
    if Padding = cpPKCS5 then
      Result := InputSize
    else if Padding = cpNone then
      Result := InputSize
    else
      raise EElSymmetricCryptoError.Create(SInternalException);
  end;
end;

class function TElSymmetricCrypto.IsAlgorithmSupported(AlgID : integer;
  CryptoProvider : TElCustomCryptoProvider  =  nil) : boolean;
begin
  if CryptoProvider = nil then
    Result := DefaultCryptoProviderManager.IsAlgorithmSupported(AlgID, 0)
    //CryptoProvider := DefaultCryptoProvider;
  else
    Result := CryptoProvider.IsAlgorithmSupported(AlgID, 0);
end;

class function TElSymmetricCrypto.IsAlgorithmSupported(const AlgOID : ByteArray;
  CryptoProvider : TElCustomCryptoProvider  =  nil) : boolean;
begin
  if CryptoProvider = nil then
    Result := DefaultCryptoProviderManager.IsAlgorithmSupported(AlgOID, EmptyArray, 0)
    //CryptoProvider := DefaultCryptoProvider;
  else
    Result := CryptoProvider.IsAlgorithmSupported(AlgOID, EmptyArray, 0);
end;

class function TElSymmetricCrypto.IsAlgorithmSupported(AlgID : integer; Manager : TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider) : boolean;
begin
  if CryptoProvider = nil then
  begin
    if Manager <> nil then
      Result := Manager.IsAlgorithmSupported(AlgID, 0)
    else
      Result := DefaultCryptoProviderManager.IsAlgorithmSupported(AlgID, 0);
  end
  else
    Result := CryptoProvider.IsAlgorithmSupported(AlgID, 0);
end;

class function TElSymmetricCrypto.IsAlgorithmSupported(const AlgOID : ByteArray; Manager : TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider) : boolean;
begin
  if CryptoProvider = nil then
  begin
    if Manager <> nil then
      Result := Manager.IsAlgorithmSupported(AlgOID, EmptyArray, 0)
    else
      Result := DefaultCryptoProviderManager.IsAlgorithmSupported(AlgOID, EmptyArray, 0);
  end
  else
    Result := CryptoProvider.IsAlgorithmSupported(AlgOID, EmptyArray, 0);
end;

function TElSymmetricCrypto.GetNetIsStreamCipher : boolean;
begin
  if Assigned(FContext) then
    Result := FContext.AlgorithmClass = SB_ALGCLASS_STREAM
  else
  begin
    if Length(FAlgOID) > 0 then
      Result := GetSuitableCryptoProvider.GetAlgorithmClass(FAlgOID, EmptyArray) = SB_ALGCLASS_STREAM
    else
      Result := GetSuitableCryptoProvider.GetAlgorithmClass(FAlgID) = SB_ALGCLASS_STREAM;
  end;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElSymmetricCrypto.InitializeEncryption;
var
  Params : TElCPParameters;
begin
  if Assigned(FContext) and Assigned(FContext.CryptoProvider) then
    FContext.CryptoProvider.ReleaseCryptoContext(FContext);

  if not Assigned(FKeyMaterial) then
    raise EElSymmetricCryptoError.Create(SKeyMaterialIsNotSet);

  Params := TElCPParameters.Create;

  try
    if (FMode = cmCCM) or
      (FMode = cmGCM) then
    begin
      Params.Add(SB_CTXPROP_AEAD_NONCE, FNonce);
      Params.Add(SB_CTXPROP_AEAD_TAG_SIZE, GetBufferFromInteger(FTagSize));

      if FMode = cmCCM then
      begin
        Params.Add(SB_CTXPROP_CCM_ASSOCIATED_DATA_SIZE, GetBufferFromInteger(FAssociatedDataSize));
        Params.Add(SB_CTXPROP_CCM_PAYLOAD_SIZE, GetBufferFromInteger(FPayloadSize));
      end;
    end;
    {$ifndef SB_NO_RC4}
    if (Self is TElRC4SymmetricCrypto) and (TElRC4SymmetricCrypto(Self).SkipKeystreamBytes > 0) then
      Params.Add(SB_CTXPROP_SKIP_KEYSTREAM_BYTES, GetBufferFromInteger(TElRC4SymmetricCrypto(Self).SkipKeystreamBytes));
     {$endif}

    if Length(FAlgOID) = 0 then
      FContext := GetSuitableCryptoProvider.EncryptInit(FAlgID, ConvertSymmetricCryptoMode(FMode), FKeyMaterial.FKey, Params)
    else
      FContext := GetSuitableCryptoProvider.EncryptInit(FAlgOID, EmptyArray, ConvertSymmetricCryptoMode(FMode), FKeyMaterial.FKey, Params);
  finally
    FreeAndNil(Params);
  end;
  FContext.Padding := ConvertSymmetricCipherPadding(FPadding);
  FContext.SetContextProp(SB_CTXPROP_CTR_LITTLE_ENDIAN, GetBufferFromBool(FCTRLittleEndian));
end;

procedure TElSymmetricCrypto.EncryptUpdate(InBuffer: pointer; InSize : integer; OutBuffer: pointer;
  var OutSize : integer);
begin
  GetSuitableCryptoProvider.EncryptUpdate(FContext, InBuffer, InSize, OutBuffer,
  OutSize, nil);
end;

procedure TElSymmetricCrypto.Encrypt(InBuffer: pointer; InSize : integer; OutBuffer: pointer;
  var OutSize : integer);
var
  EstimatedSize : integer;
  Count, OutCount : Integer;
  PtrIn, PtrOut :  ^byte ;
  TotalIn : integer;
const
  CHUNK_SIZE : integer = 65536;
begin
  EstimatedSize := EstimatedOutputSize(InSize, true);

  if (OutSize = 0) then
  begin
     OutSize  := EstimatedSize;
    Exit;
  end;
  if (OutSize < EstimatedSize) then
    raise EElSymmetricCryptoError.Create(SOutputBufferTooSmall);

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

procedure TElSymmetricCrypto.EncryptAEAD(AssociatedData : pointer; ADataSize : integer;
  InBuffer: pointer; InSize : integer; OutBuffer: pointer; var OutSize : integer);
var
  EstimatedSize : integer;
  Count, OutCount : Integer;
  PtrIn, PtrOut :  ^byte ;
  TotalIn : integer;
  TmpBuf : ByteArray;
const
  CHUNK_SIZE : integer = 65536;
begin
  if (FMode <> cmCCM) and
    (FMode <> cmGCM)
  then
    raise EElSymmetricCryptoError.Create(SInvalidCipherMode);

  EstimatedSize := InSize + FTagSize;

  if (OutSize = 0) then
  begin
     OutSize  := EstimatedSize;
    Exit;
  end;
  if (OutSize < EstimatedSize) then
    raise EElSymmetricCryptoError.Create(SOutputBufferTooSmall);

  if (FMode = cmCCM) then
  begin
    AssociatedDataSize := ADataSize;
    PayloadSize := InSize;
  end;

  InitializeEncryption;
  TotalIn := ADataSize + InSize;

  if ADataSize > 0 then
  begin
    SetLength(TmpBuf, 1);
    OutCount := 1;
    PtrIn :=  AssociatedData ;
    PtrOut :=  @TmpBuf[0] ;

    while ADataSize > 0 do
    begin
      Count := Min(CHUNK_SIZE, ADataSize);
      EncryptUpdate(PtrIn, Count, PtrOut, OutCount);
      Inc(PtrIn, Count);
      Dec(ADataSize, Count);
      if not DoProgress(TotalIn, TotalIn - ADataSize) then
        raise EElSymmetricCryptoError.Create(SInterruptedByUser);
    end;
  end;

  Self.AssociatedData := false;

  PtrIn :=  InBuffer ;
  PtrOut :=  OutBuffer ;  
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

procedure TElSymmetricCrypto.Encrypt(InStream : TElInputStream; OutStream: TElOutputStream);
var
  Size, OutSize : integer;
  Processed, BytesLeft : Int64;
  Buffer, OutBuffer : ByteArray;
begin

  BytesLeft := InStream. Size  - InStream.Position;
  Processed := 0;

  SetLength(Buffer, SYMMETRIC_BLOCK_SIZE);
  SetLength(OutBuffer, SYMMETRIC_BLOCK_SIZE);

  InitializeEncryption;

  if not DoProgress(BytesLeft + Processed, Processed) then
    raise EElSymmetricCryptoError.Create(SInterruptedByUser);
  while BytesLeft > 0 do begin
    Size := InStream.Read(Buffer[0], Min(SYMMETRIC_BLOCK_SIZE, BytesLeft));
    
    
    Dec(BytesLeft, Size);
    OutSize := SYMMETRIC_BLOCK_SIZE;
    EncryptUpdate(@Buffer[0], Size, @OutBuffer[0], OutSize);
    OutStream.Write(OutBuffer[0], OutSize);
    Inc(Processed, Size);
    if not DoProgress(BytesLeft + Processed, Processed) then
      raise EElSymmetricCryptoError.Create(SInterruptedByUser);
  end;

  OutSize := SYMMETRIC_BLOCK_SIZE;
  FinalizeEncryption(@OutBuffer[0], OutSize);
  if OutSize > 0 then
    OutStream.Write(OutBuffer[0], OutSize);
  if not DoProgress(Processed, Processed) then 
    raise EElSymmetricCryptoError.Create(SInterruptedByUser);

end;


procedure TElSymmetricCrypto.FinalizeEncryption(OutBuffer : pointer; var OutSize : integer);
begin
  GetSuitableCryptoProvider.EncryptFinal(FContext, OutBuffer, OutSize, nil);
end;

 {$endif SB_PGPSFX_STUB}

procedure TElSymmetricCrypto.DecryptAEAD(AssociatedData : pointer; ADataSize : integer;
  InBuffer: pointer; InSize : integer; OutBuffer: pointer; var OutSize : integer);
var
  EstimatedSize : integer;
  Count, OutCount : Integer;
  PtrIn, PtrOut :  ^byte ;
  TmpBuf : ByteArray;
  TotalIn : integer;
const
  CHUNK_SIZE : integer = 65536;
begin
  if (FMode <> cmCCM) and
    (FMode <> cmGCM)
  then
    raise EElSymmetricCryptoError.Create(SInvalidCipherMode);

  EstimatedSize := InSize - FTagSize;

  if (OutSize = 0) then
  begin
     OutSize  := EstimatedSize;
    Exit;
  end;
  if (OutSize < EstimatedSize) then
    raise EElSymmetricCryptoError.Create(SOutputBufferTooSmall);

  if (FMode = cmCCM) then
  begin
    AssociatedDataSize := ADataSize;
    PayloadSize := InSize;
  end;

  InitializeDecryption;
  TotalIn := ADataSize + InSize;

  if ADataSize > 0 then
  begin
    SetLength(TmpBuf, 1);
    OutCount := 1;
    PtrIn :=  AssociatedData ;
    PtrOut :=  @TmpBuf[0] ;

    while ADataSize > 0 do
    begin
      Count := Min(CHUNK_SIZE, ADataSize);
      DecryptUpdate(PtrIn, Count, PtrOut, OutCount);
      Inc(PtrIn, Count);
      Dec(ADataSize, Count);
      if not DoProgress(TotalIn, TotalIn - ADataSize) then
        raise EElSymmetricCryptoError.Create(SInterruptedByUser);
    end;
  end;

  Self.AssociatedData := false;

  PtrIn :=  InBuffer ;
  PtrOut :=  OutBuffer ;  
  while InSize > 0 do
  begin
    Count := Min(CHUNK_SIZE, InSize);
    OutCount := OutSize;
    DecryptUpdate(PtrIn, Count, PtrOut, OutCount);
    Inc(PtrIn, Count);
    Inc(PtrOut, OutCount);
    Dec(InSize, Count);
    Dec(OutSize, OutCount);
    if not DoProgress(TotalIn, TotalIn - InSize) then
      raise EElSymmetricCryptoError.Create(SInterruptedByUser);
  end;

  FinalizeDecryption(PtrOut, OutSize);
  Inc(PtrOut, OutSize);
  OutSize := PtrUInt(PtrOut) - PtrUInt(OutBuffer);
  
end;

procedure TElSymmetricCrypto.InitializeDecryption;
var
  Params : TElCPParameters;
begin
  if Assigned(FContext) and Assigned(FContext.CryptoProvider) then
    FContext.CryptoProvider.ReleaseCryptoContext(FContext);

  if not Assigned(FKeyMaterial) then
    raise EElSymmetricCryptoError.Create(SKeyMaterialIsNotSet);

  Params := TElCPParameters.Create;


  try
    if (FMode = cmCCM) or
      (FMode = cmGCM) then
    begin
      Params.Add(SB_CTXPROP_AEAD_NONCE, FNonce);
      Params.Add(SB_CTXPROP_AEAD_TAG_SIZE, GetBufferFromInteger(FTagSize));

      if FMode = cmCCM then
      begin
        Params.Add(SB_CTXPROP_CCM_ASSOCIATED_DATA_SIZE, GetBufferFromInteger(FAssociatedDataSize));
        Params.Add(SB_CTXPROP_CCM_PAYLOAD_SIZE, GetBufferFromInteger(FPayloadSize));
      end;
    end;

    {$ifndef SB_NO_RC4}
    if (Self is TElRC4SymmetricCrypto) and (TElRC4SymmetricCrypto(Self).SkipKeystreamBytes > 0) then
    begin
      Params.Add(SB_CTXPROP_SKIP_KEYSTREAM_BYTES, GetBufferFromInteger(TElRC4SymmetricCrypto(Self).SkipKeystreamBytes));
    end;
     {$endif} 

    if Length(FAlgOID) = 0 then
      FContext := GetSuitableCryptoProvider.DecryptInit(FAlgID, ConvertSymmetricCryptoMode(FMode), FKeyMaterial.FKey, Params)
    else
      FContext := GetSuitableCryptoProvider.DecryptInit(FAlgOID, EmptyArray, ConvertSymmetricCryptoMode(FMode), FKeyMaterial.FKey, Params);
  finally
    FreeAndNil(Params);
  end;

  FContext.Padding := ConvertSymmetricCipherPadding(FPadding);
  FContext.SetContextProp(SB_CTXPROP_CTR_LITTLE_ENDIAN, GetBufferFromBool(FCTRLittleEndian));
end;

{$ifdef SB_HAS_WINCRYPT}
procedure TElSymmetricCrypto.DecryptUpdateWin32(InBuffer: pointer; InSize : integer;
  OutBuffer: pointer; var OutSize : integer);
var
  dwDataLen :  DWORD ;
begin
  dwDataLen := InSize;
  if CryptDecrypt(FKeyMaterial.FWin32Handle, 0, false, 0, InBuffer, dwDataLen) then
  begin
    SBMove(InBuffer^, OutBuffer^, dwDataLen);
    OutSize := dwDataLen;
  end
  else
    raise EElSymmetricCryptoError.CreateFmt(SCryptoProviderError, [(GetLastError)]);
end;
 {$endif}

procedure TElSymmetricCrypto.DecryptUpdate(InBuffer: pointer; InSize : integer;
  OutBuffer: pointer; var OutSize : integer);
begin
  GetSuitableCryptoProvider.DecryptUpdate(FContext, InBuffer, InSize,
    OutBuffer, OutSize, nil);
end;

procedure TElSymmetricCrypto.Decrypt(InBuffer: pointer; InSize : integer; OutBuffer : pointer;
  var OutSize : integer);
var
  EstimatedSize, Count : integer;
begin
  EstimatedSize := EstimatedOutputSize(InSize, false);
  if (OutSize = 0) then
  begin
     OutSize  := EstimatedSize;
    Exit;
  end;
  if (OutSize < EstimatedSize) then
    raise EElSymmetricCryptoError.Create(SOutputBufferTooSmall);

  InitializeDecryption;
  Count := OutSize;
  DecryptUpdate(InBuffer, InSize, OutBuffer, Count);
  Dec(OutSize, Count);
  FinalizeDecryption(Pointer(PtrUInt(OutBuffer) + Cardinal(Count)), OutSize);
  Inc(OutSize, Count);
  
end;

procedure TElSymmetricCrypto.Decrypt(InStream : TElInputStream; OutStream: TElOutputStream;
  InCount : integer  =  0);
var
  Size, OutSize : integer;
  BytesLeft, Processed : Int64;
  Buffer, OutBuffer : ByteArray;
begin

  if InCount = 0 then
    BytesLeft := InStream. Size  - InStream.Position
  else
    BytesLeft := Min(InCount, InStream. Size  - InStream.Position);

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


procedure TElSymmetricCrypto.FinalizeDecryption(OutBuffer : pointer; var OutSize : integer);
begin
  GetSuitableCryptoProvider.DecryptFinal(FContext, OutBuffer, OutSize);
end;

class procedure TElSymmetricCrypto.GetDefaultKeyAndBlockLengths(AlgID : integer;
  var KeyLen : integer; var BlockLen : integer;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  if CryptoProvider = nil then
    //CryptoProvider := DefaultCryptoProvider;
    CryptoProvider := DefaultCryptoProviderManager.{$ifndef BUILDER_USED}GetSuitableProvider {$else}GetSuitableProvider3 {$endif}(AlgID, 0);  
  KeyLen := GetIntegerPropFromBuffer(CryptoProvider.GetAlgorithmProperty(AlgID, 0, SB_ALGPROP_DEFAULT_KEY_SIZE));
  BlockLen := GetIntegerPropFromBuffer(CryptoProvider.GetAlgorithmProperty(AlgID, 0, SB_ALGPROP_BLOCK_SIZE));
end;

class procedure TElSymmetricCrypto.GetDefaultKeyAndBlockLengths(const OID : ByteArray;
  var KeyLen : integer; var BlockLen : integer;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  if CryptoProvider = nil then
    //CryptoProvider := DefaultCryptoProvider;
    CryptoProvider := DefaultCryptoProviderManager.{$ifndef BUILDER_USED}GetSuitableProvider {$else}GetSuitableProvider4 {$endif}(OID, EmptyArray, 0);
  KeyLen := GetIntegerPropFromBuffer(CryptoProvider.GetAlgorithmProperty(OID, EmptyArray, 0, SB_ALGPROP_DEFAULT_KEY_SIZE));
  BlockLen := GetIntegerPropFromBuffer(CryptoProvider.GetAlgorithmProperty(OID, EmptyArray, 0, SB_ALGPROP_BLOCK_SIZE));
end;

class procedure TElSymmetricCrypto.GetDefaultKeyAndBlockLengths(AlgID : integer;
  var KeyLen : integer; var BlockLen : integer;
  Manager : TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  if CryptoProvider = nil then
  begin
    if Manager = nil then
      Manager := DefaultCryptoProviderManager;
    CryptoProvider := Manager.{$ifndef BUILDER_USED}GetSuitableProvider {$else}GetSuitableProvider3 {$endif}(AlgID, 0);
  end;
  KeyLen := GetIntegerPropFromBuffer(CryptoProvider.GetAlgorithmProperty(AlgID, 0, SB_ALGPROP_DEFAULT_KEY_SIZE));
  BlockLen := GetIntegerPropFromBuffer(CryptoProvider.GetAlgorithmProperty(AlgID, 0, SB_ALGPROP_BLOCK_SIZE));
end;

class procedure TElSymmetricCrypto.GetDefaultKeyAndBlockLengths(const OID : ByteArray; 
  var KeyLen : integer; var BlockLen : integer;
  Manager : TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  if CryptoProvider = nil then
  begin
    if Manager = nil then
      Manager := DefaultCryptoProviderManager;
    CryptoProvider := Manager.{$ifndef BUILDER_USED}GetSuitableProvider {$else}GetSuitableProvider4 {$endif}(OID, EmptyArray, 0);
  end;
  KeyLen := GetIntegerPropFromBuffer(CryptoProvider.GetAlgorithmProperty(OID, EmptyArray, 0, SB_ALGPROP_DEFAULT_KEY_SIZE));
  BlockLen := GetIntegerPropFromBuffer(CryptoProvider.GetAlgorithmProperty(OID, EmptyArray, 0, SB_ALGPROP_BLOCK_SIZE));
end;

function TElSymmetricCrypto.GetSuitableCryptoProvider : TElCustomCryptoProvider;
begin
  if Assigned(FCryptoProvider) then
    Result := FCryptoProvider
  else if Assigned(FCryptoProviderManager) then
  begin
    if Assigned(FKeyMaterial) and Assigned(FKeyMaterial.FProvider) and
      (FCryptoProviderManager.IsProviderAllowed(FKeyMaterial.FProvider)) then
      Result := FKeyMaterial.FProvider
    else
      Result := FCryptoProviderManager.DefaultCryptoProvider;
  end
  else if Assigned(FKeyMaterial) and Assigned(FKeyMaterial.FProvider) then
    Result := FKeyMaterial.FProvider
  else
    Result := DefaultCryptoProviderManager.DefaultCryptoProvider
end;

////////////////////////////////////////////////////////////////////////////////
// TElRC4SymmetricCrypto class

{$ifndef SB_NO_RC4}

constructor TElRC4SymmetricCrypto.Create(AlgID : integer;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElRC4SymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElRC4SymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
  FAlgID := SB_ALGORITHM_CNT_RC4;
  FMode := cmDefault;
end;

constructor TElRC4SymmetricCrypto.Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElRC4SymmetricCrypto.Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElRC4SymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

function TElRC4SymmetricCrypto.GetSkipKeystreamBytes : integer;
begin
  Result := FSkipKeystreamBytes;
end;

procedure TElRC4SymmetricCrypto.SetSkipKeystreamBytes(Value: integer);
begin
  FSkipKeystreamBytes := Value;
end;

procedure TElRC4SymmetricCrypto.Init;
begin
  inherited;
  FSkipKeystreamBytes := 0;
end;

{$ifndef SB_PGPSFX_STUB}  
procedure TElRC4SymmetricCrypto.InitializeEncryption;
begin
  inherited;
end;
 {$endif}

procedure TElRC4SymmetricCrypto.InitializeDecryption;
begin
  inherited;
end;
 {$endif}

////////////////////////////////////////////////////////////////////////////////
// TElBlowfishSymmetricCrypto class


constructor TElBlowfishSymmetricCrypto.Create(AlgID : integer;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElBlowfishSymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElBlowfishSymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
  FAlgID := SB_ALGORITHM_CNT_BLOWFISH;
end;

constructor TElBlowfishSymmetricCrypto.Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElBlowfishSymmetricCrypto.Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElBlowfishSymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

////////////////////////////////////////////////////////////////////////////////
// TElAESSymmetricCrypto class

constructor TElAESSymmetricCrypto.Create(AlgID : integer;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElAESSymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElAESSymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
  FAlgID := SB_ALGORITHM_CNT_AES128;
end;


constructor TElAESSymmetricCrypto.Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElAESSymmetricCrypto.Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElAESSymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

////////////////////////////////////////////////////////////////////////////////
// TElTwofishSymmetricCrypto class


constructor TElTwofishSymmetricCrypto.Create(AlgID : integer;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElTwofishSymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElTwofishSymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
  FAlgID := SB_ALGORITHM_CNT_TWOFISH;
end;

constructor TElTwofishSymmetricCrypto.Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElTwofishSymmetricCrypto.Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElTwofishSymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

////////////////////////////////////////////////////////////////////////////////
// TElIDEASymmetricCrypto class


{$ifndef SB_NO_IDEA}
constructor TElIDEASymmetricCrypto.Create(AlgID : integer;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElIDEASymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElIDEASymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
  if not GetSuitableCryptoProvider.IsAlgorithmSupported(SB_ALGORITHM_CNT_IDEA,
    ConvertSymmetricCryptoMode(Mode)) then
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmInt, [AlgID]));
  FAlgID := SB_ALGORITHM_CNT_IDEA;
end;

constructor TElIDEASymmetricCrypto.Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElIDEASymmetricCrypto.Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElIDEASymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;
 {$endif}

////////////////////////////////////////////////////////////////////////////////
// TElCAST128SymmetricCrypto class


constructor TElCAST128SymmetricCrypto.Create(AlgID : integer;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElCAST128SymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElCAST128SymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
  FAlgID := SB_ALGORITHM_CNT_CAST128;
end;

constructor TElCAST128SymmetricCrypto.Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElCAST128SymmetricCrypto.Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElCAST128SymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

////////////////////////////////////////////////////////////////////////////////
// TElRC2SymmetricCrypto class

{$ifndef SB_NO_RC2}

constructor TElRC2SymmetricCrypto.Create(AlgID : integer;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElRC2SymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElRC2SymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
  FAlgID := SB_ALGORITHM_CNT_RC2;
end;

constructor TElRC2SymmetricCrypto.Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElRC2SymmetricCrypto.Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElRC2SymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;
 {$endif}

////////////////////////////////////////////////////////////////////////////////
// TElDESSymmetricCrypto class


constructor TElDESSymmetricCrypto.Create(AlgID : integer;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElDESSymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElDESSymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
  FAlgID := SB_ALGORITHM_CNT_DES;
end;

constructor TElDESSymmetricCrypto.Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElDESSymmetricCrypto.Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElDESSymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

////////////////////////////////////////////////////////////////////////////////
// TEl3DESSymmetricCrypto class


constructor TEl3DESSymmetricCrypto.Create(AlgID : integer;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TEl3DESSymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TEl3DESSymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
  FAlgID := SB_ALGORITHM_CNT_3DES;
end;

constructor TEl3DESSymmetricCrypto.Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TEl3DESSymmetricCrypto.Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TEl3DESSymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

////////////////////////////////////////////////////////////////////////////////
// TElSerpentSymmetricCrypto class


constructor TElSerpentSymmetricCrypto.Create(AlgID : integer;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElSerpentSymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElSerpentSymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
  FAlgID := SB_ALGORITHM_CNT_SERPENT;
end;

constructor TElSerpentSymmetricCrypto.Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElSerpentSymmetricCrypto.Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElSerpentSymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

////////////////////////////////////////////////////////////////////////////////
// TElCamelliaSymmetricCrypto class

{$ifndef SB_NO_CAMELLIA}

constructor TElCamelliaSymmetricCrypto.Create(AlgID : integer;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElCamelliaSymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElCamelliaSymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
  FAlgID := SB_ALGORITHM_CNT_CAMELLIA;
end;

constructor TElCamelliaSymmetricCrypto.Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElCamelliaSymmetricCrypto.Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElCamelliaSymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;
 {$endif}

////////////////////////////////////////////////////////////////////////////////
// TElSeedSymmetricCrypto class

{$ifndef SB_NO_SEED}

constructor TElSeedSymmetricCrypto.Create(AlgID : integer;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElSeedSymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElSeedSymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
  FAlgID := SB_ALGORITHM_CNT_SEED;
end;

constructor TElSeedSymmetricCrypto.Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElSeedSymmetricCrypto.Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElSeedSymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;
 {$endif}

////////////////////////////////////////////////////////////////////////////////
// TElRabbitSymmetricCrypto class

{$ifndef SB_NO_RABBIT}

constructor TElRabbitSymmetricCrypto.Create(AlgID : integer;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElRabbitSymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElRabbitSymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
  FAlgID := SB_ALGORITHM_CNT_RABBIT;
end;

constructor TElRabbitSymmetricCrypto.Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElRabbitSymmetricCrypto.Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElRabbitSymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;
 {$endif}

////////////////////////////////////////////////////////////////////////////////
// TElGOST28147SymmetricCrypto

{$ifdef SB_HAS_GOST}

constructor TElGOST28147SymmetricCrypto.Create(AlgID : integer;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElGOST28147SymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
end;

constructor TElGOST28147SymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited;
  FAlgID := SB_ALGORITHM_CNT_GOST_28147_1989;
end;

constructor TElGOST28147SymmetricCrypto.Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElGOST28147SymmetricCrypto.Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElGOST28147SymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;


procedure TElGOST28147SymmetricCrypto.Init;
begin
  inherited;

  FParamSet := EmptyArray;
  FSBoxes := EmptyArray;
  FUseKeyMeshing := false;
end;

function TElGOST28147SymmetricCrypto.GetParamSet : ByteArray;
begin
  Result := CloneArray(FParamSet);
end;

procedure TElGOST28147SymmetricCrypto.SetParamSet(const Value : ByteArray);
begin
  FParamSet := CloneArray(Value);

  if Assigned(FContext) and (Length(FParamSet) > 0) then
    FContext.SetContextProp(SB_CTXPROP_GOST28147_1989_PARAMSET, FParamSet);  
end;

function TElGOST28147SymmetricCrypto.GetSBoxes : ByteArray;
begin
  Result := CloneArray(FSBoxes);
end;

procedure TElGOST28147SymmetricCrypto.SetSBoxes(const Value : ByteArray);
begin
  FSBoxes := CloneArray(Value);

  if Assigned(FContext) and (Length(FSBoxes) > 0) then
    FContext.SetContextProp(SB_CTXPROP_GOST28147_1989_PARAMETERS, FSBoxes);
end;

function TElGOST28147SymmetricCrypto.GetUseKeyMeshing : boolean;
begin
  Result := FUseKeyMeshing;
end;

procedure TElGOST28147SymmetricCrypto.SetUseKeyMeshing(Value : boolean);
begin
  FUseKeyMeshing := Value;
  if Assigned(FContext) then
    FContext.SetContextProp(SB_CTXPROP_GOST28147_1989_USE_KEY_MESHING, GetBufferFromBool(FUseKeyMeshing));
end;

procedure TElGOST28147SymmetricCrypto.InitializeEncryption;
var
  Parameters : TElCPParameters;
begin
  { we are not using inhereted since we need to pass some parameters to EncryptInit }
  if Assigned(FContext) and Assigned(FContext.CryptoProvider) then
    FContext.CryptoProvider.ReleaseCryptoContext(FContext);

  if not Assigned(FKeyMaterial) then
    raise EElSymmetricCryptoError.Create(SKeyMaterialIsNotSet);

  Parameters := TElCPParameters.Create;
  if Length(FParamSet) > 0 then
    Parameters.Add(SB_CTXPROP_GOST28147_1989_PARAMSET, FParamSet);
  if Length(FSBoxes) > 0 then
    Parameters.Add(SB_CTXPROP_GOST28147_1989_PARAMETERS, FSBoxes);
  Parameters.Add(SB_CTXPROP_GOST28147_1989_USE_KEY_MESHING, GetBufferFromBool(FUseKeyMeshing));

  try  
    if Length(FAlgOID) = 0 then
      FContext := GetSuitableCryptoProvider.EncryptInit(FAlgID, ConvertSymmetricCryptoMode(FMode), FKeyMaterial.FKey, Parameters)
    else
      FContext := GetSuitableCryptoProvider.EncryptInit(FAlgOID, EmptyArray, ConvertSymmetricCryptoMode(FMode), FKeyMaterial.FKey, Parameters);
    FContext.Padding := ConvertSymmetricCipherPadding(FPadding);
  finally
    FreeAndNil(Parameters);
  end;
end;

procedure TElGOST28147SymmetricCrypto.InitializeDecryption;
var
  Parameters : TElCPParameters;
begin
  { we are not using inhereted since we need to pass some parameters to EncryptInit }
  if Assigned(FContext) and Assigned(FContext.CryptoProvider) then
    FContext.CryptoProvider.ReleaseCryptoContext(FContext);

  if not Assigned(FKeyMaterial) then
    raise EElSymmetricCryptoError.Create(SKeyMaterialIsNotSet);

  Parameters := TElCPParameters.Create;
  if Length(FParamSet) > 0 then
    Parameters.Add(SB_CTXPROP_GOST28147_1989_PARAMSET, FParamSet);
  if Length(FSBoxes) > 0 then
    Parameters.Add(SB_CTXPROP_GOST28147_1989_PARAMETERS, FSBoxes);
  Parameters.Add(SB_CTXPROP_GOST28147_1989_USE_KEY_MESHING, GetBufferFromBool(FUseKeyMeshing));    

  try
    if Length(FAlgOID) = 0 then
      FContext := GetSuitableCryptoProvider.DecryptInit(FAlgID, ConvertSymmetricCryptoMode(FMode), FKeyMaterial.FKey, Parameters)
    else
      FContext := GetSuitableCryptoProvider.DecryptInit(FAlgOID, EmptyArray, ConvertSymmetricCryptoMode(FMode), FKeyMaterial.FKey, Parameters);
  finally
    FreeAndNil(Parameters);
  end;
  FContext.Padding := ConvertSymmetricCipherPadding(FPadding);
end;
 {$endif}

////////////////////////////////////////////////////////////////////////////////
// TElIdentitySymmetricCrypto class

 
constructor TElIdentitySymmetricCrypto.Create(AlgID : integer;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited Create(SB_ALGORITHM_CNT_IDENTITY, Mode);
end;

constructor TElIdentitySymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited Create(SB_ALGORITHM_CNT_IDENTITY, Mode);
end;

constructor TElIdentitySymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode   = cmDefault ;
  CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited Create(SB_ALGORITHM_CNT_IDENTITY, Mode);
end;

constructor TElIdentitySymmetricCrypto.Create(AlgID : integer; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElIdentitySymmetricCrypto.Create(const AlgOID : ByteArray; Mode: TSBSymmetricCryptoMode;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

constructor TElIdentitySymmetricCrypto.Create(Mode : TSBSymmetricCryptoMode; Manager : TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited;
end;

////////////////////////////////////////////////////////////////////////////////
//  TElSymmetricCryptoFactory class

constructor TElSymmetricCryptoFactory.Create;
begin
  inherited;
end;

destructor TElSymmetricCryptoFactory.Destroy;
begin
  inherited;
end;

function TElSymmetricCryptoFactory.CreateInstance(const OID : ByteArray;
  Mode : TSBSymmetricCryptoMode   = cmDefault ): TElSymmetricCrypto;
var
  Prov : TElCustomCryptoProvider;
  Manager : TElCustomCryptoProviderManager;
begin
  if FCryptoProvider <> nil then
    Prov := FCryptoProvider
  else
  begin
    if FCryptoProviderManager = nil then
      Manager := DefaultCryptoProviderManager
    else
      Manager := FCryptoProviderManager;
    Prov := Manager.{$ifndef BUILDER_USED}GetSuitableProvider {$else}GetSuitableProvider4 {$endif}(OID, EmptyArray, ConvertSymmetricCryptoMode(Mode));
  end;
  if Prov.IsAlgorithmSupported(OID, EmptyArray, ConvertSymmetricCryptoMode(Mode)) then
  begin
    {$ifdef SB_HAS_GOST}
    if CompareContent(OID, SB_OID_GOST_28147_1989) then
      Result := TElGOST28147SymmetricCrypto.Create(OID, Mode, FCryptoProvider)
    else
     {$endif}
    {$ifndef SB_NO_RC4}
    if CompareContent(OID, SB_OID_RC4) then
      Result := TElRC4SymmetricCrypto.Create(OID, Mode, FCryptoProvider)
    else
     {$endif}
      Result := TElSymmetricCrypto.Create(OID, Mode, FCryptoProvider{nil}) // passing nil to constructor to force Crypto use KeyMaterial's crypto provider if CryptoProvider is not assigned
  end
  else
    Result := nil;
end;

function TElSymmetricCryptoFactory.CreateInstance(Alg : integer;
  Mode : TSBSymmetricCryptoMode   = cmDefault ): TElSymmetricCrypto;
var
  Prov : TElCustomCryptoProvider;
  Manager : TElCustomCryptoProviderManager;
begin
  Manager := nil;
  if FCryptoProvider <> nil then
    Prov := FCryptoProvider
  else
  begin
    if FCryptoProviderManager = nil then
      Manager := DefaultCryptoProviderManager
    else
      Manager := FCryptoProviderManager;
    Prov := Manager.{$ifndef BUILDER_USED}GetSuitableProvider {$else}GetSuitableProvider3 {$endif}(Alg, ConvertSymmetricCryptoMode(Mode));
  end;
  if (Prov <> nil) and Prov.IsAlgorithmSupported(Alg, ConvertSymmetricCryptoMode(Mode)) then
  begin
    {$ifdef SB_HAS_GOST}
    if Alg = SB_ALGORITHM_CNT_GOST_28147_1989 then
      Result := TElGOST28147SymmetricCrypto.Create(Alg, Mode, Manager, Prov)
    else
     {$endif}
    {$ifndef SB_NO_RC4}
    if Alg = SB_ALGORITHM_CNT_RC4 then
      Result := TElRC4SymmetricCrypto.Create(Alg, Mode, Manager, Prov)
    else { all other algorithms has no parameters }
     {$endif}
      Result := TElSymmetricCrypto.Create(Alg, Mode, Manager, Prov{nil})
  end  
  else
    Result := nil;
end;

function TElSymmetricCryptoFactory.IsAlgorithmSupported(const OID : ByteArray): boolean;
//var
//  Prov : TElCustomCryptoProvider;
begin
  {if FCryptoProvider <> nil then
    Prov := FCryptoProvider
  else
    Prov := DefaultCryptoProvider;}
  if FCryptoProvider <> nil then
    Result := FCryptoProvider.IsAlgorithmSupported(OID, EmptyArray, 0)
  else
  begin
    if FCryptoProviderManager <> nil then
      Result := FCryptoProviderManager.IsAlgorithmSupported(OID, EmptyArray, 0)
    else
      Result := DefaultCryptoProviderManager.IsAlgorithmSupported(OID, EmptyArray, 0);
  end;
end;

function TElSymmetricCryptoFactory.IsAlgorithmSupported(Alg : integer): boolean;
//var
//  Prov : TElCustomCryptoProvider;
begin
  {if FCryptoProvider <> nil then
    Prov := FCryptoProvider
  else
    Prov := DefaultCryptoProvider;}
  if FCryptoProvider <> nil then
    Result := FCryptoProvider.IsAlgorithmSupported(Alg, 0)
  else
  begin
    if FCryptoProviderManager <> nil then
      Result := FCryptoProviderManager.IsAlgorithmSupported(Alg, 0)
    else
      Result := DefaultCryptoProviderManager.IsAlgorithmSupported(Alg, 0);
  end;
end;

function TElSymmetricCryptoFactory.GetDefaultKeyAndBlockLengths(Alg : integer;
  var KeyLen : integer; var BlockLen : integer
   ): boolean;
var
  Prov : TElCustomCryptoProvider;
  Manager : TElCustomCryptoProviderManager;
begin
  if FCryptoProvider <> nil then
    Prov := FCryptoProvider
  else
  begin
    if FCryptoProviderManager <> nil then
      Manager := FCryptoProviderManager
    else
      Manager := DefaultCryptoProviderManager;
    Prov := Manager.{$ifndef BUILDER_USED}GetSuitableProvider {$else}GetSuitableProvider3 {$endif}(Alg, 0);
  end;
    //Prov := DefaultCryptoProvider;
  KeyLen := GetIntegerPropFromBuffer(Prov.GetAlgorithmProperty(Alg, 0, SB_ALGPROP_DEFAULT_KEY_SIZE));
  BlockLen := GetIntegerPropFromBuffer(Prov.GetAlgorithmProperty(Alg, 0, SB_ALGPROP_BLOCK_SIZE));
  Result := true;
end;

function TElSymmetricCryptoFactory.GetDefaultKeyAndBlockLengths(const OID: ByteArray;
  var KeyLen : integer; var BlockLen : integer
   ): boolean;
var
  Prov : TElCustomCryptoProvider;
  Manager : TElCustomCryptoProviderManager;
begin
  if FCryptoProvider <> nil then
    Prov := FCryptoProvider
  else
  begin
    if FCryptoProviderManager <> nil then
      Manager := FCryptoProviderManager
    else
      Manager := DefaultCryptoProviderManager;
    Prov := Manager.{$ifndef BUILDER_USED}GetSuitableProvider {$else}GetSuitableProvider4 {$endif}(OID, EmptyArray, 0);
  end;
    //Prov := DefaultCryptoProvider;
  KeyLen := GetIntegerPropFromBuffer(Prov.GetAlgorithmProperty(OID, EmptyArray, 0, SB_ALGPROP_DEFAULT_KEY_SIZE));
  BlockLen := GetIntegerPropFromBuffer(Prov.GetAlgorithmProperty(OID, EmptyArray, 0, SB_ALGPROP_BLOCK_SIZE));
  Result := true;
end;


end.
