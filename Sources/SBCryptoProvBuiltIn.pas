(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBCryptoProvBuiltIn;      

interface

uses
{$ifdef WIN32}
  Windows,
 {$else}
  //{$ifndef FPC}Libc,{$endif}
 {$endif}
  Classes,
  SysUtils,
  SBCryptoProv,
  SBCryptoProvRS,
  SBConstants,
  SBRandom,
  SBSharedResource,
  SBTypes,
  SBUtils,
  SBStrUtils;


// TODO: pass error codes to Exception.Creates
// TODO: investigate KeyFormat key property (either here and in public key crypto) and its necessity

type
  TElBuiltInCryptoProviderOptions =  class(TElCustomCryptoProviderOptions)
  protected
    FUsePlatformKeyGeneration : boolean;
    FRollbackToBuiltInKeyGeneration : boolean;
    FUseTimingAttackProtection : boolean;
    procedure Init; override;
  public
    procedure Assign(Options : TElCustomCryptoProviderOptions); override;
    property UsePlatformKeyGeneration : boolean read FUsePlatformKeyGeneration
      write FUsePlatformKeyGeneration;
    property RollbackToBuiltInKeyGeneration : boolean read FRollbackToBuiltInKeyGeneration
      write FRollbackToBuiltInKeyGeneration;
    property UseTimingAttackProtection : boolean read FUseTimingAttackProtection
      write FUseTimingAttackProtection;
  end;

type
  TElBuiltInCryptoKey =  class(TElCustomCryptoKey)
  protected
    FMode : integer;
    FIV : ByteArray;
    FValue : ByteArray;

    function GetMode : integer; override;
    procedure SetMode(Value : integer); override;
    function GetIV : ByteArray; override;
    procedure SetIV(const Value : ByteArray); override;
    function GetValue : ByteArray; override;
    procedure SetValue(const Value : ByteArray); override;

  public
     destructor  Destroy; override;  
    procedure Reset; override;
    procedure ChangeAlgorithm(Algorithm : integer); override;
    {$ifndef SB_PGPSFX_STUB}
    procedure PrepareForEncryption(MultiUse : boolean  =  false); override;
    procedure PrepareForSigning(MultiUse : boolean  =  false); override;
    procedure CancelPreparation; override;
    function AsyncOperationFinished : boolean; override;
     {$endif SB_PGPSFX_STUB}
    function Equals(Source : TElCustomCryptoKey;PublicOnly : boolean;
      Params : TElCPParameters  =  nil): boolean; override;
    procedure Persistentiate; override;
  end;

  TElBuiltInCryptoProvider =  class(TElBlackboxCryptoProvider)
  private
    FKeys : TElList;
    FContexts : TElList;
    FRandom : TElRandom;
    FRandomAccess : TElSharedResource;
    FLock : TElSharedResource;
    procedure ClearKeys();
    procedure ClearContexts();
    function InternalCreateKey(Algorithm: integer; Mode : integer; const AlgOID,
      AlgParams : ByteArray; Params : TElCPParameters  =  nil): TElCustomCryptoKey;
    {$ifndef SB_PGPSFX_STUB}
    procedure InternalEncryptInit(Context : TElCustomCryptoContext);
     {$endif SB_PGPSFX_STUB}
    procedure InternalDecryptInit(Context : TElCustomCryptoContext);
    {$ifndef SB_PGPSFX_STUB}
    procedure InternalSignInit(Context : TElCustomCryptoContext; Detached : boolean);
     {$endif SB_PGPSFX_STUB}
    procedure InternalVerifyInit(Context : TElCustomCryptoContext; SigBuffer : pointer;
      SigSize : integer);
    procedure RandomSeedTime;
  protected
    function CreateSymmetricCryptoFactory : TObject; virtual;
  protected
    function CreateOptions : TElCustomCryptoProviderOptions; override;
  public
    procedure Init(); override;
    procedure Deinit(); override;
    class procedure SetAsDefault; override;

    function IsAlgorithmSupported(Algorithm : integer; Mode : integer) : boolean; override;
    function IsAlgorithmSupported(const AlgOID, AlgParams : ByteArray;
      Mode : integer): boolean; override;
    function IsOperationSupported(Operation : integer; Algorithm : integer;
      Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters): boolean; override;
    function IsOperationSupported(Operation : integer; const AlgOID, AlgParams : ByteArray;
      Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters): boolean; override;
    function GetAlgorithmProperty(Algorithm : integer; Mode : integer;
      const PropID : ByteArray): ByteArray; override;
    function GetAlgorithmProperty(const AlgOID, AlgParams : ByteArray;
      Mode : integer; const PropID : ByteArray): ByteArray; override;
    function GetAlgorithmClass(Algorithm : integer): integer; override;
    function GetAlgorithmClass(const AlgOID, AlgParams : ByteArray): integer; override;
    function GetDefaultInstance : TElCustomCryptoProvider; override;

    // key management functions
    function CreateKey(Algorithm : integer; Mode : integer;
      Params : TElCPParameters  =  nil): TElCustomCryptoKey; override;
    function CreateKey(const AlgOID : ByteArray; const AlgParams : ByteArray;
      Params : TElCPParameters  =  nil): TElCustomCryptoKey; override;
    function CloneKey(Key : TElCustomCryptoKey) : TElCustomCryptoKey; override;
    procedure ReleaseKey(var Key : TElCustomCryptoKey); override;
    procedure DeleteKey(var Key : TElCustomCryptoKey); override;
    function DecryptKey(EncKey : pointer; EncKeySize : integer; const EncKeyAlgOID,
      EncKeyAlgParams : ByteArray; Key : TElCustomCryptoKey; const KeyAlgOID,
      KeyAlgParams : ByteArray; Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil): TElCustomCryptoKey; override;

    // encryption and signing functions
    {$ifndef SB_PGPSFX_STUB}
    function EncryptInit(Algorithm : integer; Mode : integer; Key : TElCustomCryptoKey;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil) : TElCustomCryptoContext; override;
    function EncryptInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
      Mode : integer; Key : TElCustomCryptoKey;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil): TElCustomCryptoContext; override;
     {$endif SB_PGPSFX_STUB}
    function DecryptInit(Algorithm : integer; Mode : integer; Key : TElCustomCryptoKey;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil) : TElCustomCryptoContext; override;
    function DecryptInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
      Mode : integer; Key : TElCustomCryptoKey;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil): TElCustomCryptoContext; override;
    {$ifndef SB_PGPSFX_STUB}
    function SignInit(Algorithm : integer; Key : TElCustomCryptoKey;
      Detached : boolean;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil) : TElCustomCryptoContext; override;
    function SignInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
      Key : TElCustomCryptoKey; Detached : boolean;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil): TElCustomCryptoContext; override;
     {$endif SB_PGPSFX_STUB}
    function VerifyInit(Algorithm : integer; Key : TElCustomCryptoKey;
      SigBuffer : pointer; SigSize : integer; Params : TElCPParameters = nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil) : TElCustomCryptoContext; override;
    function VerifyInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
      Key : TElCustomCryptoKey; SigBuffer : pointer; SigSize : integer;
      Params : TElCPParameters = nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil) : TElCustomCryptoContext; override;
    {$ifndef SB_PGPSFX_STUB}
    procedure EncryptUpdate(Context : TElCustomCryptoContext; InBuffer : pointer;
      InSize : integer; OutBuffer : pointer; var OutSize : integer;
      Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil); override;
     {$endif SB_PGPSFX_STUB}
    procedure DecryptUpdate(Context : TElCustomCryptoContext; InBuffer : pointer;
      InSize : integer; OutBuffer : pointer; var OutSize : integer;
      Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil); override;
    {$ifndef SB_PGPSFX_STUB}
    procedure SignUpdate(Context : TElCustomCryptoContext; InBuffer : pointer;
      InSize : integer; OutBuffer: pointer; var OutSize: integer;
      Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil); override;
     {$endif SB_PGPSFX_STUB}
    procedure VerifyUpdate(Context : TElCustomCryptoContext; InBuffer : pointer;
      InSize : integer; OutBuffer: pointer; var OutSize : integer;
      Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil); override;
    {$ifndef SB_PGPSFX_STUB}
    procedure EncryptFinal(Context : TElCustomCryptoContext; Buffer : pointer;
      var Size : integer; Params : TElCPParameters = nil;
      ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil); override;
     {$endif SB_PGPSFX_STUB}
    procedure DecryptFinal(Context : TElCustomCryptoContext; Buffer : pointer;
      var Size : integer; Params : TElCPParameters = nil;
      ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil); override;
    {$ifndef SB_PGPSFX_STUB}
    procedure SignFinal(Context : TElCustomCryptoContext; Buffer : pointer;
      var Size : integer; Params : TElCPParameters = nil;
      ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil); override;
     {$endif SB_PGPSFX_STUB}
    function VerifyFinal(Context : TElCustomCryptoContext; Buffer : pointer;
      var Size : integer; Params : TElCPParameters = nil;
      ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil): integer; override;

    // hash functions
    function HashInit(Algorithm : integer; Key : TElCustomCryptoKey;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil): TElCustomCryptoContext; override;
    function HashInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
      Key : TElCustomCryptoKey;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil): TElCustomCryptoContext; override;
    procedure HashUpdate(Context : TElCustomCryptoContext; Buffer : pointer;
      Size : integer; Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil); override;
    function HashFinal(Context : TElCustomCryptoContext;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil): ByteArray; override;

    procedure ReleaseCryptoContext(var Context : TElCustomCryptoContext); override;

    // key storage functions
    function CreateKeyStorage(Persistent: boolean; Params : TElCPParameters  =  nil): TElCustomCryptoKeyStorage; override;
    procedure ReleaseKeyStorage(var KeyStorage : TElCustomCryptoKeyStorage); override;
    procedure DeleteKeyStorage(var KeyStorage : TElCustomCryptoKeyStorage); override;

    // randomizer functions
    procedure RandomInit(BaseData: pointer; BaseDataSize: integer; Params : TElCPParameters = nil); override;
    procedure RandomSeed(Data: pointer; DataSize: integer); override;
    procedure RandomGenerate(Buffer: pointer; Size: integer); override;
    function RandomGenerate(MaxValue: integer): integer; override;
  end;

  EElBuiltInCryptoProviderError =  class(EElCryptoProviderError);

function BuiltInCryptoProvider : TElCustomCryptoProvider; 

implementation

uses
  SBCryptoProvUtils, SBCryptoProvBuiltInSym, SBCryptoProvBuiltInHash,
  SBCryptoProvBuiltInPKI{, SBCryptoProvDefault};

var
  BuiltInCryptoProv : TElCustomCryptoProvider;


{$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
 {$else}
var
 {$endif}

  SB_ALGSCHEME_PKCS1 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'pkcs#1' {$endif}; 
  SB_ALGSCHEME_PKCS5 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'pkcs#5' {$endif}; 
  SB_ALGSCHEME_OAEP : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'oaep' {$endif}; 
  SB_ALGSCHEME_PSS : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'pss' {$endif}; 

type
  TSBBuiltInCryptoContextType = (cctUndefined, cctSymCrypto, cctPKICrypto, cctHash);
  TSBBuiltInCryptoContextOperation = (ccoUndefined, ccoEncrypt, ccoDecrypt, ccoSign,
    ccoVerify, ccoSignDetached, ccoVerifyDetached, ccoHash);
  TElBuiltInCryptoContext = class(TElCustomCryptoContext)
  protected
    FContextType : TSBBuiltInCryptoContextType;
    FHashFunction : TElBuiltInHashFunction;
    FSymCrypto : TElBuiltInSymmetricCrypto;
    FPKICrypto : TElBuiltInPublicKeyCrypto;
    FSpool : ByteArray;
    FAlgorithm : integer;
    FOperation : TSBBuiltInCryptoContextOperation;
    procedure CheckKeyLength(Key : TElCustomCryptoKey);
  protected
    function GetAlgorithm : integer; override;
    function GetAlgorithmClass : integer; override;
    procedure Init(Algorithm: integer; Mode: integer; Key: TElCustomCryptoKey;
      Params : TElCPParameters);
    function GetKeySize : integer; override;
    procedure SetKeySize(Value: integer); override;
    function GetBlockSize : integer; override;
    procedure SetBlockSize(Value: integer); override;
    function GetDigestSize : integer; override;
    procedure SetDigestSize(Value : integer); override;
    function GetMode : integer; override;
    procedure SetMode(Value : integer); override;
    function GetPadding : integer; override;
    procedure SetPadding(Value : integer); override;
  public
    constructor Create(Algorithm : integer; Mode : integer; Key : TElCustomCryptoKey;
      Prov : TElCustomCryptoProvider; Params : TElCPParameters);  overload; 
    constructor Create(const AlgOID, AlgParams : ByteArray; Mode : integer;
      Key : TElCustomCryptoKey; Prov : TElCustomCryptoProvider;
      Params : TElCPParameters);  overload; 
     destructor  Destroy; override;
    function EstimateOutputSize(InSize: Int64): Int64; override;
    function Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoContext; override;
    function GetContextProp(const PropID : ByteArray; const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif}  {$endif}): ByteArray; override;
    procedure SetContextProp(const PropID : ByteArray; const Value : ByteArray); override;
  end;

////////////////////////////////////////////////////////////////////////////////
// Auxiliary functions

function ConvertSymmetricCipherMode(Mode : TSBBuiltInSymmetricCryptoMode) : integer;  overload; 
begin
  case Mode of
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

function ConvertSymmetricCipherMode(Mode : integer): TSBBuiltInSymmetricCryptoMode;  overload; 
begin
  case Mode of
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

function ConvertSymmetricCipherPadding(Padding : TSBBuiltInSymmetricCipherPadding) : integer;  overload; 
begin
  case Padding of
    cpPKCS5 : Result := SB_SYMENC_PADDING_PKCS5;
  else
    Result := SB_SYMENC_PADDING_NONE;
  end;
end;

function ConvertSymmetricCipherPadding(Padding : integer): TSBBuiltInSymmetricCipherPadding;  overload; 
begin
  case Padding of
    SB_SYMENC_PADDING_PKCS5 : Result := cpPKCS5;
  else
    Result := cpNone;
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// TElBuiltInCryptoKey implementation

 destructor  TElBuiltInCryptoKey.Destroy;
begin
  ReleaseArray(FIV);
  ReleaseArray(FValue);
  inherited;
end;

function TElBuiltInCryptoKey.GetMode : integer;
begin
  Result := FMode;
end;

procedure TElBuiltInCryptoKey.SetMode(Value : integer);
begin
  FMode := Value;
end;

function TElBuiltInCryptoKey.GetIV : ByteArray;
begin
  Result := FIV;
end;

procedure TElBuiltInCryptoKey.SetIV(const Value : ByteArray);
begin
  FIV := CloneArray(Value);
end;

function TElBuiltInCryptoKey.GetValue : ByteArray;
begin
  Result := FValue;
end;

procedure TElBuiltInCryptoKey.SetValue(const Value : ByteArray);
begin
  FValue := CloneArray(Value);
end;

procedure TElBuiltInCryptoKey.ChangeAlgorithm(Algorithm : integer);
begin
  raise EElCryptoProviderError.Create(SCannotChangeAlgorithm);
end;

procedure TElBuiltInCryptoKey.Reset;
begin
  ;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInCryptoKey.PrepareForEncryption(MultiUse : boolean  =  false);
begin
  raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
end;

procedure TElBuiltInCryptoKey.PrepareForSigning(MultiUse : boolean  =  false);
begin
  raise EElBuiltInCryptoProviderError.Create(SUnsupportedOperation);
end;

procedure TElBuiltInCryptoKey.CancelPreparation;
begin
  ;
end;

function TElBuiltInCryptoKey.AsyncOperationFinished : boolean;
begin
  Result := false;
end;
 {$endif SB_PGPSFX_STUB}

function TElBuiltInCryptoKey.Equals(Source : TElCustomCryptoKey; PublicOnly : boolean;
      Params : TElCPParameters  =  nil): boolean;
begin
  raise EElBuiltInCryptoProviderError.Create(SMethodNotImplemented);
end;

procedure TElBuiltInCryptoKey.Persistentiate;
begin
  ;
end;

////////////////////////////////////////////////////////////////////////////////
// TElBuiltInCryptoProvider implementation

procedure TElBuiltInCryptoProvider.Init();
begin
  FKeys := TElList.Create();
  FContexts := TElList.Create();
  FRandom := TElRandom.Create();
  FRandomAccess := TElSharedResource.Create();
  FLock := TElSharedResource.Create();
end;

procedure TElBuiltInCryptoProvider.Deinit();
begin
  ClearKeys();
  ClearContexts();
  FreeAndNil(FKeys);
  FreeAndNil(FContexts);
  FreeAndNil(FRandom);
  FreeAndNil(FRandomAccess);
  FreeAndNil(FLock);
end;

function TElBuiltInCryptoProvider.IsAlgorithmSupported(Algorithm : integer;
  Mode : integer) : boolean;
var
  Fac : TElBuiltInSymmetricCryptoFactory;
begin
  if IsSymmetricKeyAlgorithm(Algorithm) then
  begin
    if Algorithm = SB_ALGORITHM_CNT_SYMMETRIC then
      Result := true
    else
    begin
      Fac := TElBuiltInSymmetricCryptoFactory(CreateSymmetricCryptoFactory());
      try
        Result := Fac.IsAlgorithmSupported(Algorithm);
      finally
        FreeAndNil(Fac);
      end;
    end;
  end
  else if IsHashAlgorithm(Algorithm) or IsMACAlgorithm(Algorithm) then
  begin
    if Algorithm = SB_ALGORITHM_HMAC then
      Result := true
    else
      Result := TElBuiltInHashFunction.IsAlgorithmSupported(Algorithm);
  end
  else if IsPublicKeyAlgorithm(Algorithm) then
    Result := (Algorithm = SB_ALGORITHM_PK_RSA) or (Algorithm = SB_ALGORITHM_PK_DSA) or
      (Algorithm = SB_ALGORITHM_PK_ELGAMAL) or (Algorithm = SB_ALGORITHM_PK_DH)
      {$ifdef SB_HAS_ECC}or (Algorithm = SB_ALGORITHM_PK_ECDSA) or (Algorithm = SB_ALGORITHM_PK_ECDH) or
      (Algorithm = SB_ALGORITHM_PK_EC) {$endif}
      {$ifdef SB_HAS_GOST} or (Algorithm = SB_ALGORITHM_PK_GOST_R3410_1994)
      {$ifdef SB_HAS_ECC} or (Algorithm = SB_ALGORITHM_PK_GOST_R3410_2001) {$endif}
       {$endif}
  else
    Result := false;
end;

function TElBuiltInCryptoProvider.IsAlgorithmSupported(const AlgOID, AlgParams : ByteArray;
  Mode : integer): boolean;
var
  Alg : integer;
begin
  Alg := GetAlgorithmByOID(AlgOID, true);
  if Alg <> SB_ALGORITHM_UNKNOWN then
    Result := IsAlgorithmSupported(Alg, Mode)
  else
    Result := false;
end;

function TElBuiltInCryptoProvider.IsOperationSupported(Operation : integer; Algorithm : integer;
  Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters): boolean;
begin
  if IsAlgorithmIndependentOperation(Operation) then
    Result := (Operation <> SB_OPTYPE_KEYSTORAGE_CREATE)
  else if Operation in [SB_OPTYPE_SIGN, SB_OPTYPE_VERIFY] then // only detached operations are supported
    Result := false
  else if IsAlgorithmSupported(Algorithm, Mode) then
  begin
    if IsKeyDrivenOperation(Operation) then
    begin
      if Assigned(Key) then
      begin
        if IsSecretKeyOperation(Operation) then
          Result := Key.IsSecret and Key.IsExportable
        else
          Result := true;
        if Result then
        begin
          if Operation in [SB_OPTYPE_ENCRYPT, SB_OPTYPE_DECRYPT] then
            Result := (Algorithm <> SB_ALGORITHM_PK_DSA) and
              (Algorithm <> SB_ALGORITHM_PK_ECDSA);
        end;
      end
      else
        Result := false;
    end
    else
      Result := true;
  end
  else
    Result := false;
end;

function TElBuiltInCryptoProvider.IsOperationSupported(Operation : integer;
  const AlgOID, AlgParams : ByteArray; Mode : integer; Key : TElCustomCryptoKey;
  Params : TElCPParameters): boolean;
var
  Alg : integer;
begin
  Alg := GetAlgorithmByOID(AlgOID, true);
  Result := IsOperationSupported(Operation, Alg, Mode, Key, Params);
end;

function TElBuiltInCryptoProvider.GetAlgorithmProperty(Algorithm : integer; Mode : integer;
  const PropID : ByteArray): ByteArray;
var
  Fac : TElBuiltInSymmetricCryptoFactory;
  KeyLen, BlockLen : integer;
begin
  if IsHashAlgorithm(Algorithm) or IsMACAlgorithm(Algorithm) then
  begin
    if CompareContent(PropID, SB_ALGPROP_DIGEST_SIZE) then
      Result := SBCryptoProvUtils.GetBufferFromInteger(SBUtils.GetDigestSizeBits(Algorithm))
    else
      raise EElCryptoProviderError.CreateFmt(SUnknownAlgorithmProperty, [BinaryToString(PropID)]);
  end
  else if IsSymmetricKeyAlgorithm(Algorithm) then
  begin
    Fac := TElBuiltInSymmetricCryptoFactory(CreateSymmetricCryptoFactory());
    try
      if CompareContent(PropID, SB_ALGPROP_DEFAULT_KEY_SIZE) then
      begin
        Fac.GetDefaultKeyAndBlockLengths(Algorithm, KeyLen, BlockLen);
        Result := GetBufferFromInteger(KeyLen);
      end
      else if CompareContent(PropID, SB_ALGPROP_BLOCK_SIZE) then
      begin
        Fac.GetDefaultKeyAndBlockLengths(Algorithm, KeyLen, BlockLen);
        Result := GetBufferFromInteger(BlockLen);
      end;
    finally
      FreeAndNil(Fac);
    end;
  end
  else
    raise EElCryptoProviderError.CreateFmt(SUnsupportedAlgorithmInt, [Algorithm]);
end;

function TElBuiltInCryptoProvider.GetAlgorithmProperty(const AlgOID, AlgParams : ByteArray;
  Mode : integer; const PropID : ByteArray): ByteArray;
var
  Alg : integer;
begin
  Alg := GetAlgorithmByOID(AlgOID, true);
  if Alg <> SB_ALGORITHM_UNKNOWN then
    Result := GetAlgorithmProperty(Alg, Mode, PropID)
  else
    raise EElCryptoProviderError.CreateFmt(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]);
end;

function TElBuiltInCryptoProvider.GetAlgorithmClass(Algorithm : integer): integer;
begin
  if IsSymmetricKeyAlgorithm(Algorithm) then
  begin
    if (Algorithm = SB_ALGORITHM_CNT_RC4) or (Algorithm = SB_ALGORITHM_CNT_IDENTITY) then
      Result := SB_ALGCLASS_STREAM
    else
      Result := SB_ALGCLASS_BLOCK;
  end
  else if IsPublicKeyAlgorithm(Algorithm) then
    Result := SB_ALGCLASS_PUBLICKEY
  else if IsHashAlgorithm(Algorithm) or IsMACAlgorithm(Algorithm) then
    Result := SB_ALGCLASS_HASH
  else
    Result := SB_ALGCLASS_NONE;
end;

function TElBuiltInCryptoProvider.GetAlgorithmClass(const AlgOID, AlgParams : ByteArray): integer;
var
  Alg : integer;
begin
  Alg := GetAlgorithmByOID(AlgOID, true);
  if Alg <> SB_ALGORITHM_UNKNOWN then
    Result := GetAlgorithmClass(Alg)
  else
    Result := SB_ALGCLASS_NONE;
end; 

procedure TElBuiltInCryptoProvider.ClearContexts();
var
  I : integer;
begin
  FLock.WaitToWrite();
  try
    for I := 0 to FContexts.Count - 1 do
    begin
      DoDestroyObject((FContexts[I]));
      TElCustomCryptoContext(FContexts[I]). Free ;
    end;
    FContexts.Clear;
  finally
    FLock.Done();
  end;
end;

procedure TElBuiltInCryptoProvider.ClearKeys();
var
  I : integer;
begin
  FLock.WaitToWrite();
  try
    for I := 0 to FKeys.Count - 1 do
    begin
      DoDestroyObject((FKeys[I]));
      TElCustomCryptoKey(FKeys[I]). Free ;
    end;
    FKeys.Clear;
  finally
    FLock.Done();
  end;
end;

// Key management routines

function TElBuiltInCryptoProvider.CreateKey(Algorithm : integer; Mode : integer;
  Params : TElCPParameters  =  nil): TElCustomCryptoKey;
begin
  Result := InternalCreateKey(Algorithm, Mode, EmptyArray, EmptyArray, Params);
end;

function TElBuiltInCryptoProvider.CreateKey(const AlgOID : ByteArray; const AlgParams : ByteArray;
  Params : TElCPParameters  =  nil): TElCustomCryptoKey;
begin
  Result := InternalCreateKey(SB_ALGORITHM_UNKNOWN, 0, AlgOID, AlgParams, Params);
end;

function TElBuiltInCryptoProvider.InternalCreateKey(Algorithm: integer; Mode : integer;
  const AlgOID, AlgParams : ByteArray; Params : TElCPParameters  =  nil): TElCustomCryptoKey;
var
  OID : ByteArray;
  I : integer;
begin
  if Algorithm = SB_ALGORITHM_UNKNOWN then
    Algorithm := GetAlgorithmByOID(AlgOID);
  if Algorithm = SB_ALGORITHM_PK_RSA then
    Result := TElBuiltInRSACryptoKey.Create(Self)
  else
  if Algorithm = SB_ALGORITHM_PK_DSA then
    Result := TElBuiltInDSACryptoKey.Create(Self)
  else
  if Algorithm = SB_ALGORITHM_PK_ELGAMAL then
    Result := TElBuiltInElgamalCryptoKey.Create(Self)
  {$ifndef SB_NO_DH}
  else
  if Algorithm = SB_ALGORITHM_PK_DH then
    Result := TElBuiltInDHCryptoKey.Create(Self)
   {$endif SB_NO_DH}
  {$ifdef SB_HAS_ECC}
  else
  if Algorithm = SB_ALGORITHM_PK_EC then
    Result := TElBuiltInECCryptoKey.Create(Self)
   {$endif}
  {$ifdef SB_HAS_GOST}
  else if Algorithm = SB_ALGORITHM_PK_GOST_R3410_1994 then
    Result := TElBuiltInGOST341094CryptoKey.Create(Self)
  {$ifdef SB_HAS_ECC}
  else if Algorithm = SB_ALGORITHM_PK_GOST_R3410_2001 then
    Result := TElBuiltInGOST34102001CryptoKey.Create(Self)
   {$endif} 
   {$endif}
  else if IsSymmetricKeyAlgorithm(Algorithm) then
  begin
    if Length(AlgOID) > 0 then
      OID := CloneArray(AlgOID)
    else
      OID := GetOIDByAlgorithm(Algorithm);
    Result := TElBuiltInSymmetricCryptoKey.Create(Self, OID, AlgParams)
  end
  else if IsMACAlgorithm(Algorithm) then
  begin
    Result := TElBuiltInMACKey.Create(Self)
  end
  else
    raise EElBuiltInCryptoProviderError.CreateFmt(SUnsupportedAlgorithmInt, [Algorithm]);
  TElBuiltInCryptoKey(Result).Mode := Mode;
  if Assigned(Params) then
    for I := 0 to Params.Count - 1 do
      Result.SetKeyProp(Params.OIDs[I], Params.Values[I]);
  if FOptions.StoreKeys then
  begin
    FLock.WaitToWrite();
    try
      FKeys.Add(Result);
    finally
      FLock.Done();
    end;
  end;
  DoCreateObject(Result);
end;

function TElBuiltInCryptoProvider.CloneKey(Key : TElCustomCryptoKey) : TElCustomCryptoKey;
//var
//  Index : integer;
begin
  if not OwnsObject(Key) then
    raise EElBuiltInCryptoProviderError.Create(SInvalidKeyMaterial);
  (*
  FLock.WaitToRead();
  try
    Index := FKeys.IndexOf(Key);
  finally
    FLock.Done();
  end;
  if Index < 0 then
    raise EElBuiltInCryptoProviderError.Create(SInvalidKeyMaterial);
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
  DoCreateObject(Result);
end;

procedure TElBuiltInCryptoProvider.ReleaseKey(var Key : TElCustomCryptoKey);
var
  Index : integer;
begin
  if OwnsObject(Key) then
  begin
    DoDestroyObject(Key);
    // We always look for the key in the list, as it might have been created
    // at some stage when the Options.StoreKeys property was true.
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

procedure TElBuiltInCryptoProvider.DeleteKey(var Key : TElCustomCryptoKey);
begin
  // removing a key from corresponding key storage
  // ...
  ReleaseKey(Key);
end;

function TElBuiltInCryptoProvider.DecryptKey(EncKey : pointer; EncKeySize : integer; const EncKeyAlgOID,
  EncKeyAlgParams : ByteArray; Key : TElCustomCryptoKey; const KeyAlgOID,
  KeyAlgParams : ByteArray; Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil): TElCustomCryptoKey;
var
  Sz : integer;
  Buf : ByteArray;
begin
  if IsOperationSupported(SB_OPTYPE_KEY_DECRYPT, KeyAlgOID, KeyAlgParams, 0,
    Key, Params) then
  begin
    Sz := 0;
    Decrypt(KeyAlgOID, KeyAlgParams, 0, Key, EncKey, EncKeySize,  nil ,
      Sz, Params);
    SetLength(Buf, Sz);
    Decrypt(KeyAlgOID, KeyAlgParams, 0, Key, EncKey, EncKeySize, @Buf[0], Sz, Params,
      ProgressFunc, ProgressData);
    SetLength(Buf, Sz);
    Result := CreateKey(EncKeyAlgOID, EncKeyAlgParams, Params);
    Result.Value := Buf;
  end
  else
    raise EElBuiltInCryptoProviderError.Create(SDecryptionFailed);
end;

// Encryption and signing routines

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInCryptoProvider.InternalEncryptInit(Context : TElCustomCryptoContext);
var
  Ctx : TElBuiltInCryptoContext;
begin
  if TElBuiltInCryptoContext(Context).FContextType = cctSymCrypto then
    TElBuiltInCryptoContext(Context).FSymCrypto.InitializeEncryption()
  else if TElBuiltInCryptoContext(Context).FContextType = cctPKICrypto then
  begin
    // actual encryption is done in EncryptFinal method
    Ctx := TElBuiltInCryptoContext(Context);
    SetLength(Ctx.FSpool, 0);
  end
  else
    raise EElBuiltInCryptoProviderError.Create(SInvalidAlgorithm);
  TElBuiltInCryptoContext(Context).FOperation := ccoEncrypt;
end;
 {$endif SB_PGPSFX_STUB}

procedure TElBuiltInCryptoProvider.InternalDecryptInit(Context : TElCustomCryptoContext);
var
  Ctx : TElBuiltInCryptoContext;
begin
  if TElBuiltInCryptoContext(Context).FContextType = cctSymCrypto then
    TElBuiltInCryptoContext(Context).FSymCrypto.InitializeDecryption()
  else if TElBuiltInCryptoContext(Context).FContextType = cctPKICrypto then
  begin
    // actual decryption is done in DecryptFinal method
    Ctx := TElBuiltInCryptoContext(Context);
    SetLength(Ctx.FSpool, 0);
  end
  else
    raise EElBuiltInCryptoProviderError.Create(SInvalidAlgorithm);
  TElBuiltInCryptoContext(Context).FOperation := ccoDecrypt;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInCryptoProvider.InternalSignInit(Context : TElCustomCryptoContext;
  Detached : boolean);
begin
  if TElBuiltInCryptoContext(Context).FContextType = cctPKICrypto then
    TElBuiltInCryptoContext(Context).FPKICrypto.SignInit(Detached)
  else
    raise EElBuiltInCryptoProviderError.Create(SInvalidAlgorithm);
  if Detached then
    TElBuiltInCryptoContext(Context).FOperation := ccoSignDetached
  else
    TElBuiltInCryptoContext(Context).FOperation := ccoSign;
end;
 {$endif SB_PGPSFX_STUB}

procedure TElBuiltInCryptoProvider.InternalVerifyInit(Context : TElCustomCryptoContext;
  SigBuffer : pointer; SigSize : integer);
begin
  if TElBuiltInCryptoContext(Context).FContextType = cctPKICrypto then
    TElBuiltInCryptoContext(Context).FPKICrypto.VerifyInit(SigSize = 0, SigBuffer, SigSize)
  else
    raise EElBuiltInCryptoProviderError.Create(SInvalidAlgorithm);
  if SigSize = 0 then
    TElBuiltInCryptoContext(Context).FOperation := ccoVerify
  else
    TElBuiltInCryptoContext(Context).FOperation := ccoVerifyDetached;
end;

{$ifndef SB_PGPSFX_STUB}
function TElBuiltInCryptoProvider.EncryptInit(Algorithm : integer; Mode : integer; Key : TElCustomCryptoKey;
  Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil) : TElCustomCryptoContext;
begin
  if IsAlgorithmSupported(Algorithm, Mode) then
  begin
    Result := TElBuiltInCryptoContext.Create(Algorithm, Mode, Key, Self, Params);
    try
      InternalEncryptInit(Result);
    except
      FreeAndNil(Result);
      raise;
    end;
    if FOptions.StoreKeys then
    begin
      FLock.WaitToWrite();
      try
        FContexts.Add(Result);
      finally
        FLock.Done();
      end;
    end;
    DoCreateObject(Result);
  end
  else
    raise EElCryptoProviderError.CreateFmt(SUnsupportedAlgorithmInt, [Algorithm]);
end;

function TElBuiltInCryptoProvider.EncryptInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
  Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil): TElCustomCryptoContext;
begin
  if IsAlgorithmSupported(AlgOID, AlgParams, Mode) then
  begin
    Result := TElBuiltInCryptoContext.Create(AlgOID, AlgParams, Mode, Key, Self, Params);
    try
      InternalEncryptInit(Result);
    except
      FreeAndNil(Result);
      raise;
    end;
    if FOptions.StoreKeys then
    begin
      FLock.WaitToWrite();
      try
        FContexts.Add(Result);
      finally
        FLock.Done();
      end;
    end;
    DoCreateObject(Result);
  end
  else
    raise EElCryptoProviderError.CreateFmt(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]);
end;
 {$endif SB_PGPSFX_STUB}

function TElBuiltInCryptoProvider.DecryptInit(Algorithm : integer; Mode : integer; Key : TElCustomCryptoKey;
  Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil) : TElCustomCryptoContext;
begin
  if IsAlgorithmSupported(Algorithm, Mode) then
  begin
    Result := TElBuiltInCryptoContext.Create(Algorithm, Mode, Key, Self, Params);
    try
      InternalDecryptInit(Result);
    except
      FreeAndNil(Result);
      raise;
    end;
    if FOptions.StoreKeys then
    begin
      FLock.WaitToWrite();
      try
        FContexts.Add(Result);
      finally
        FLock.Done();
      end;
    end;
    DoCreateObject(Result);
  end
  else
    raise EElCryptoProviderError.CreateFmt(SUnsupportedAlgorithmInt, [Algorithm]);
end;

function TElBuiltInCryptoProvider.DecryptInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
  Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil): TElCustomCryptoContext;
begin
  if IsAlgorithmSupported(AlgOID, AlgParams, Mode) then
  begin
    Result := TElBuiltInCryptoContext.Create(AlgOID, AlgParams, Mode, Key, Self, Params);
    try
      InternalDecryptInit(Result);
    except
      FreeAndNil(Result);
      raise;
    end;
    if FOptions.StoreKeys then
    begin
      FLock.WaitToWrite();
      try
        FContexts.Add(Result);
      finally
        FLock.Done();
      end;
    end;
    DoCreateObject(Result);
  end
  else
    raise EElCryptoProviderError.CreateFmt(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]);
end;

{$ifndef SB_PGPSFX_STUB}
function TElBuiltInCryptoProvider.SignInit(Algorithm : integer; Key : TElCustomCryptoKey;
  Detached : boolean; Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil) : TElCustomCryptoContext;
begin
  if IsAlgorithmSupported(Algorithm, 0) then
  begin
    Result := TElBuiltInCryptoContext.Create(Algorithm, 0, Key, Self, Params);
    try
      InternalSignInit(Result, Detached);
    except
      FreeAndNil(Result);
      raise;
    end;
    if FOptions.StoreKeys then
    begin
      FLock.WaitToWrite();
      try
        FContexts.Add(Result);
      finally
        FLock.Done();
      end;
    end;
    DoCreateObject(Result);
  end
  else
    raise EElCryptoProviderError.CreateFmt(SUnsupportedAlgorithmInt, [Algorithm]);
end;

function TElBuiltInCryptoProvider.SignInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
  Key : TElCustomCryptoKey; Detached : boolean; Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil): TElCustomCryptoContext;
begin
  if IsAlgorithmSupported(AlgOID, AlgParams, 0) then
  begin
    Result := TElBuiltInCryptoContext.Create(AlgOID, AlgParams, 0, Key, Self, Params);
    try
      InternalSignInit(Result, Detached);
    except
      FreeAndNil(Result);
      raise;
    end;
    if FOptions.StoreKeys then
    begin
      FLock.WaitToWrite();
      try
        FContexts.Add(Result);
      finally
        FLock.Done();
      end;
    end;
    DoCreateObject(Result);
  end
  else
    raise EElCryptoProviderError.CreateFmt(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]);
end;
 {$endif SB_PGPSFX_STUB}

function TElBuiltInCryptoProvider.VerifyInit(Algorithm : integer; Key : TElCustomCryptoKey;
  SigBuffer : pointer; SigSize : integer; Params : TElCPParameters = nil;
  ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil) : TElCustomCryptoContext;
begin
  if IsAlgorithmSupported(Algorithm, 0) then
  begin
    Result := TElBuiltInCryptoContext.Create(Algorithm, 0, Key, Self, Params);
    try
      InternalVerifyInit(Result, SigBuffer, SigSize);
    except
      FreeAndNil(Result);
      raise;
    end;
    if FOptions.StoreKeys then
    begin
      FLock.WaitToWrite();
      try
        FContexts.Add(Result);
      finally
        FLock.Done();
      end;
    end;
    DoCreateObject(Result);
  end
  else
    raise EElCryptoProviderError.CreateFmt(SUnsupportedAlgorithmInt, [Algorithm]);
end;

function TElBuiltInCryptoProvider.VerifyInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
  Key : TElCustomCryptoKey; SigBuffer : pointer; SigSize : integer; Params : TElCPParameters = nil;
  ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil) : TElCustomCryptoContext;
begin
  if IsAlgorithmSupported(AlgOID, AlgParams, 0) then
  begin
    Result := TElBuiltInCryptoContext.Create(AlgOID, AlgParams, 0, Key, Self, Params);
    try
      InternalVerifyInit(Result, SigBuffer, SigSize);
    except
      FreeAndNil(Result);
      raise;
    end;
    if FOptions.StoreKeys then
    begin
      FLock.WaitToWrite();
      try
        FContexts.Add(Result);
      finally
        FLock.Done();
      end;
    end;
    DoCreateObject(Result);
  end
  else
    raise EElCryptoProviderError.CreateFmt(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]);
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInCryptoProvider.EncryptUpdate(Context : TElCustomCryptoContext; InBuffer : pointer;
  InSize : integer; OutBuffer : pointer; var OutSize : integer;
  Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
  ProgressData : pointer = nil);
var
  OldLen : integer;
  Ctx : TElBuiltInCryptoContext;
begin
  if (Context is TElBuiltInCryptoContext) then
  begin
    if TElBuiltInCryptoContext(Context).FContextType = cctSymCrypto then
      TElBuiltInCryptoContext(Context).FSymCrypto.EncryptUpdate(InBuffer,
        InSize,
        OutBuffer,
        OutSize)
    else if TElBuiltInCryptoContext(Context).FContextType = cctPKICrypto then
    begin
      // actual encryption is done in EncryptFinal
      Ctx := TElBuiltInCryptoContext(Context);
      if OutBuffer <> nil then
      begin
        OldLen := Length(Ctx.FSpool);
        SetLength(Ctx.FSpool, OldLen + InSize);
        SBMove(InBuffer^, Ctx.FSpool[OldLen], InSize);
        OutSize := 0;
      end
      else
        OutSize := 1; // fake value (to prevent second user from passing 0/nil to a second call)
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
  end
  else
    raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
end;
 {$endif SB_PGPSFX_STUB}

procedure TElBuiltInCryptoProvider.DecryptUpdate(Context : TElCustomCryptoContext; InBuffer : pointer;
  InSize : integer; OutBuffer : pointer; var OutSize : integer;
  Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
  ProgressData : pointer = nil);
var
  OldLen : integer;
  Ctx : TElBuiltInCryptoContext;
begin
  if (Context is TElBuiltInCryptoContext) then
  begin
    if TElBuiltInCryptoContext(Context).FContextType = cctSymCrypto then
      TElBuiltInCryptoContext(Context).FSymCrypto.DecryptUpdate(InBuffer,
        InSize,
        OutBuffer,
        OutSize)
    else if TElBuiltInCryptoContext(Context).FContextType = cctPKICrypto then
    begin
      // actual decryption is done in DecryptFinal
      if OutBuffer <> nil then
      begin
        Ctx := TElBuiltInCryptoContext(Context);
        OldLen := Length(Ctx.FSpool);
        SetLength(Ctx.FSpool, OldLen + InSize);
        SBMove(InBuffer^, Ctx.FSpool[OldLen], InSize);
        OutSize := 0;
      end
      else
        OutSize := 1;
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
  end
  else
    raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInCryptoProvider.SignUpdate(Context : TElCustomCryptoContext; InBuffer : pointer;
  InSize : integer; OutBuffer: pointer; var OutSize : integer; Params : TElCPParameters = nil;
  ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil);
begin
  if (Context is TElBuiltInCryptoContext) then
  begin
    if TElBuiltInCryptoContext(Context).FContextType = cctPKICrypto then
    begin
      if OutBuffer <> nil then
      begin
        TElBuiltInCryptoContext(Context).FPKICrypto.SignUpdate(InBuffer, InSize);
        OutSize := 0;
      end
      else
        OutSize := 1;
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
  end
  else
    raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
end;
 {$endif SB_PGPSFX_STUB}

procedure TElBuiltInCryptoProvider.VerifyUpdate(Context : TElCustomCryptoContext; InBuffer : pointer;
  InSize : integer; OutBuffer : pointer; var OutSize : integer; Params : TElCPParameters = nil;
  ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil);
begin
  if (Context is TElBuiltInCryptoContext) then
  begin
    if TElBuiltInCryptoContext(Context).FContextType = cctPKICrypto then
    begin
      if OutBuffer <> nil then
      begin
        TElBuiltInCryptoContext(Context).FPKICrypto.VerifyUpdate(InBuffer, InSize);
        OutSize := 0;
      end
      else
        OutSize := 1;
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
  end
  else
    raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInCryptoProvider.EncryptFinal(Context : TElCustomCryptoContext; Buffer : pointer;
  var Size : integer; Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
  ProgressData : pointer = nil);
var
  OutSize : integer;
  Ctx : TElBuiltInCryptoContext;
begin

  if (Context is TElBuiltInCryptoContext) then
  begin
    if TElBuiltInCryptoContext(Context).FContextType = cctSymCrypto then
      TElBuiltInCryptoContext(Context).FSymCrypto.FinalizeEncryption(Buffer, Size)
    else if TElBuiltInCryptoContext(Context).FContextType = cctPKICrypto then
    begin
      Ctx := TElBuiltInCryptoContext(Context);
      OutSize := 0;
      Ctx.FPKICrypto.Encrypt(@Ctx.FSpool[0], Length(Ctx.FSpool), nil, OutSize);
      if Buffer = nil then
      begin
        Size := OutSize;
        if Size = 0 then
          Size := 1;
      end
      else
      begin
        if Size < OutSize then
          raise EElBuiltInCryptoProviderError.Create(SBufferTooSmall);
        TElBuiltInCryptoContext(Context).FPKICrypto.Encrypt(@TElBuiltInCryptoContext(Context).FSpool[0],
          Length(TElBuiltInCryptoContext(Context).FSpool), Buffer, Size);
      end;
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
  end
  else
    raise EElBuiltInCryptoProviderError.Create(SInvalidContext);

end;
 {$endif SB_PGPSFX_STUB}

procedure TElBuiltInCryptoProvider.DecryptFinal(Context : TElCustomCryptoContext; Buffer : pointer;
  var Size : integer; Params : TElCPParameters = nil;
  ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil);
var
  OutSize : integer;
  Ctx : TElBuiltInCryptoContext;
begin

  if (Context is TElBuiltInCryptoContext) then
  begin
    if TElBuiltInCryptoContext(Context).FContextType = cctSymCrypto then
      TElBuiltInCryptoContext(Context).FSymCrypto.FinalizeDecryption(Buffer, Size)
    else if TElBuiltInCryptoContext(Context).FContextType = cctPKICrypto then
    begin
      Ctx := TElBuiltInCryptoContext(Context);
      OutSize := 0;
      Ctx.FPKICrypto.Decrypt(@Ctx.FSpool[0], Length(Ctx.FSpool), nil, OutSize);
      if Buffer = nil then
      begin
        Size := OutSize;
        if Size = 0 then
          Size := 1;
      end
      else
      begin
        if Size < OutSize then
          raise EElBuiltInCryptoProviderError.Create(SBufferTooSmall);
        Ctx.FPKICrypto.Decrypt(@Ctx.FSpool[0], Length(Ctx.FSpool), Buffer, Size);
      end;
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
  end
  else
    raise EElBuiltInCryptoProviderError.Create(SInvalidContext);

end;

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInCryptoProvider.SignFinal(Context : TElCustomCryptoContext; Buffer : pointer;
  var Size : integer; Params : TElCPParameters = nil;
  ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil);
var
  OutSize : integer;
begin

  if (Context is TElBuiltInCryptoContext) then
  begin
    if TElBuiltInCryptoContext(Context).FContextType = cctPKICrypto then
    begin
      OutSize := 0;
      TElBuiltInCryptoContext(Context).FPKICrypto.SignFinal( nil , OutSize);
      if Buffer = nil then
      begin
        Size := OutSize;
        if Size = 0 then
          Size := 1;
      end
      else
      begin
        if Size < OutSize then
          raise EElBuiltInCryptoProviderError.Create(SBufferTooSmall);
        TElBuiltInCryptoContext(Context).FPKICrypto.SignFinal(Buffer, Size);
      end;
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
  end
  else
    raise EElBuiltInCryptoProviderError.Create(SInvalidContext);

end;
 {$endif SB_PGPSFX_STUB}

function TElBuiltInCryptoProvider.VerifyFinal(Context : TElCustomCryptoContext;
  Buffer : pointer; var Size : integer; Params : TElCPParameters = nil;
  ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil): integer;
begin
  if (Context is TElBuiltInCryptoContext) then
  begin
    if TElBuiltInCryptoContext(Context).FContextType = cctPKICrypto then
    begin
      if Buffer <> nil then
      begin
        Result := TElBuiltInCryptoContext(Context).FPKICrypto.VerifyFinal();
        Size := 0;
      end
      else
      begin
        Result := SB_VR_FAILURE;
        Size := 1;
      end;
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
  end
  else
    raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
end;

// Hash calculation routines

function TElBuiltInCryptoProvider.HashInit(Algorithm : integer; Key : TElCustomCryptoKey;
  Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil): TElCustomCryptoContext;
begin
  if IsAlgorithmSupported(Algorithm, 0) then
  begin
    if not IsHashAlgorithm(Algorithm) and not IsMACAlgorithm(Algorithm) then
      raise EElBuiltInCryptoProviderError.CreateFmt(SUnsupportedHashAlgorithmInt, [Algorithm]);

    Result := TElBuiltInCryptoContext.Create(Algorithm, 0, Key, Self, Params);
    if FOptions.StoreKeys then
    begin
      FLock.WaitToWrite();
      try
        FContexts.Add(Result);
      finally
        FLock.Done();
      end;
    end;
    DoCreateObject(Result);
  end
  else
    raise EElCryptoProviderError.CreateFmt(SUnsupportedAlgorithmInt, [Algorithm]);
end;

function TElBuiltInCryptoProvider.HashInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
  Key : TElCustomCryptoKey; Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil): TElCustomCryptoContext;
var
  Alg: Integer;
begin
  if IsAlgorithmSupported(AlgOID, AlgParams, 0) then
  begin
    Alg := GetAlgorithmByOID(AlgOID, true);
    if not IsHashAlgorithm(Alg) and not IsMACAlgorithm(Alg) and (Alg <> SB_ALGORITHM_UNKNOWN) then
      raise EElBuiltInCryptoProviderError.CreateFmt(SUnsupportedHashAlgorithmInt, [Alg]);

    Result := TElBuiltInCryptoContext.Create(AlgOID, AlgParams, 0, Key, Self, Params);
    if FOptions.StoreKeys then
    begin
      FLock.WaitToWrite();
      try
        FContexts.Add(Result);
      finally
        FLock.Done();
      end;
    end;
    DoCreateObject(Result);
  end
  else
    raise EElCryptoProviderError.CreateFmt(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]);
end;

procedure TElBuiltInCryptoProvider.HashUpdate(Context : TElCustomCryptoContext;
  Buffer : pointer; Size : integer; Params : TElCPParameters = nil;
  ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil);
begin
  if (Context is TElBuiltInCryptoContext) then
  begin
    if TElBuiltInCryptoContext(Context).FContextType <> cctHash then
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
    TElBuiltInCryptoContext(Context).FHashFunction.Update(Buffer, Size);
  end
  else
    raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
end;

function TElBuiltInCryptoProvider.HashFinal(Context : TElCustomCryptoContext;
  Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil): ByteArray;
begin
  if (Context is TElBuiltInCryptoContext) then
  begin
    if TElBuiltInCryptoContext(Context).FContextType <> cctHash then
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
    Result := CloneArray(TElBuiltInCryptoContext(Context).FHashFunction.Finish);
  end
  else
    raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
end;

procedure TElBuiltInCryptoProvider.ReleaseCryptoContext(var Context : TElCustomCryptoContext);
var
  Index : integer;
begin
  if (Context is TElBuiltInCryptoContext) and (Context.CryptoProvider = Self) then
  begin
    FLock.WaitToWrite();
    try
      Index := FContexts.IndexOf(Context);
      if Index >= 0 then
        FContexts. Delete (Index);
    finally
      FLock.Done();
    end;
    DoDestroyObject(Context);
    FreeAndNil(Context);
  end
  else
    raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
end;       

function TElBuiltInCryptoProvider.CreateKeyStorage(Persistent: boolean;
  Params : TElCPParameters  =  nil): TElCustomCryptoKeyStorage;
begin
  Result := nil;
end;

procedure TElBuiltInCryptoProvider.ReleaseKeyStorage(var KeyStorage : TElCustomCryptoKeyStorage);
begin

end;

procedure TElBuiltInCryptoProvider.DeleteKeyStorage(var KeyStorage : TElCustomCryptoKeyStorage);
begin

end;

procedure TElBuiltInCryptoProvider.RandomInit(BaseData: pointer; BaseDataSize: integer;
  Params : TElCPParameters = nil);
begin
  FRandomAccess.WaitToWrite;
  try
    FreeAndNil(FRandom);
    FRandom := TElRandom.Create();
    RandomSeed(BaseData, BaseDataSize);
    RandomSeedTime;
  finally
    FRandomAccess.Done;
  end;
end;

procedure TElBuiltInCryptoProvider.RandomSeedTime;
var
  C : cardinal;
  D :  double ;
  A :  array[0..47] of byte ;
begin
  

  C := SBRndTimeSeed;

  D := Now;
  SBMove(C, A[0], 4);
  SBMove(D, A[4], 8);
  SBMove(C, A[12], 4);
  SBMove(D, A[16], 8);
  SBMove(C, A[24], 4);
  SBMove(D, A[28], 8);
  SBMove(C, A[36], 4);
  SBMove(D, A[40], 8);
  RandomSeed(@A[0], 48);

end;

procedure TElBuiltInCryptoProvider.RandomSeed(Data: pointer; DataSize: integer);
begin
  FRandomAccess.WaitToWrite();
  try
    FRandom.Seed(Data, DataSize);
  finally
    FRandomAccess.Done;
  end;
end;

procedure TElBuiltInCryptoProvider.RandomGenerate(Buffer: pointer; Size: integer);
begin
  FRandomAccess.WaitToWrite();
  try
    FRandom.Generate(Buffer, Size);
  finally
    FRandomAccess.Done;
  end;
end;

function TElBuiltInCryptoProvider.RandomGenerate(MaxValue: integer): integer;
begin
  FRandomAccess.WaitToWrite;
  try
    FRandom.Generate(@Result, 4);
    if MaxValue <> 0 then
      Result := Result mod MaxValue;
  finally
    FRandomAccess.Done;
  end;
end;

function TElBuiltInCryptoProvider.CreateSymmetricCryptoFactory : TObject;
begin
  // descendants of this method should create instances of either TElBuiltInSymmetricCryptoFactory class
  // or its descendants.  
  {$ifndef SB_HAS_MEMORY_MANAGER}
  Result := TElBuiltInSymmetricCryptoFactory.Create();
   {$else}
  Result := TObject(MemoryManager.AcquireObject(JLClass(TElBuiltInSymmetricCryptoFactory)));
   {$endif}
end;

class procedure TElBuiltInCryptoProvider.SetAsDefault;
begin
  DoSetAsDefault(TElBuiltInCryptoProvider);
end;

function TElBuiltInCryptoProvider.GetDefaultInstance : TElCustomCryptoProvider;
begin
  if BuiltInCryptoProv = nil then
  begin
    BuiltInCryptoProv := TElBuiltInCryptoProvider.Create({$ifndef SB_NO_COMPONENT}nil {$endif});
    RegisterGlobalObject(BuiltInCryptoProv);
  end;
  Result := BuiltInCryptoProv;
end;

function TElBuiltInCryptoProvider.CreateOptions : TElCustomCryptoProviderOptions;
begin
  Result := TElBuiltInCryptoProviderOptions.Create();
end;

////////////////////////////////////////////////////////////////////////////////
// TElBuiltInCryptoContext class

constructor TElBuiltInCryptoContext.Create(Algorithm : integer; Mode : integer;
  Key: TElCustomCryptoKey; Prov : TElCustomCryptoProvider; Params : TElCPParameters);
begin
  inherited Create;
  FProvider := Prov;
  Init(Algorithm, Mode, Key, Params);
end;

constructor TElBuiltInCryptoContext.Create(const AlgOID, AlgParams : ByteArray;
  Mode : integer; Key : TElCustomCryptoKey; Prov : TElCustomCryptoProvider;
  Params : TElCPParameters);
var
  Alg : integer;
begin
  inherited Create;
  FProvider := Prov;
  Alg := GetAlgorithmByOID(AlgOID, true);
  if Alg <> SB_ALGORITHM_UNKNOWN then
  begin
    if IsSymmetricKeyAlgorithm(Alg) then
    begin
      //Mode := SB_SYMENC_MODE_CBC;
    end;
    Init(Alg, Mode, Key, Params);
  end
  else
    raise EElBuiltInCryptoProviderError.CreateFmt(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]);
end;

procedure TElBuiltInCryptoContext.Init(Algorithm: integer; Mode: integer;
  Key: TElCustomCryptoKey; Params : TElCPParameters);
var
  SymFac : TElBuiltInSymmetricCryptoFactory;
  I : integer;
begin
  FContextType := cctUndefined;
  FOperation := ccoUndefined;
  if IsSymmetricKeyAlgorithm(Algorithm) then
  begin
    if not (FProvider is TElBuiltInCryptoProvider) then
      raise EElBuiltInCryptoProviderError.Create(SInvalidCryptoProvider);
    SymFac := TElBuiltInSymmetricCryptoFactory(TElBuiltInCryptoProvider(FProvider).CreateSymmetricCryptoFactory());
    try
      FSymCrypto := SymFac.CreateInstance(Algorithm, ConvertSymmetricCipherMode(Mode));
      FContextType := cctSymCrypto;
      FSymCrypto.KeyMaterial := Key;
    finally
      FreeAndNil(SymFac);
    end;
  end
  else if IsPublicKeyAlgorithm(Algorithm) then
  begin
    CheckKeyLength(Key);
    case Algorithm of
      SB_ALGORITHM_PK_RSA :
        FPKICrypto := TElBuiltInRSAPublicKeyCrypto.Create();
      SB_ALGORITHM_PK_DSA :
        FPKICrypto := TElBuiltInDSAPublicKeyCrypto.Create();
      SB_ALGORITHM_PK_ELGAMAL :
        FPKICrypto := TElBuiltInElgamalPublicKeyCrypto.Create();
      {$ifndef SB_NO_DH}
      SB_ALGORITHM_PK_DH :
        FPKICrypto := TElBuiltInDHPublicKeyCrypto.Create();
       {$endif SB_NO_DH}
      {$ifdef SB_HAS_ECC}
      SB_ALGORITHM_PK_ECDSA :
        FPKICrypto := TElBuiltInECDSAPublicKeyCrypto.Create();
      SB_ALGORITHM_PK_ECDH :
        FPKICrypto := TElBuiltInECDHPublicKeyCrypto.Create();
       {$endif}
      {$ifdef SB_HAS_GOST}
      SB_ALGORITHM_PK_GOST_R3410_1994 :
        FPKICrypto := TElBuiltInGOST94PublicKeyCrypto.Create();
      {$ifdef SB_HAS_ECC}
      SB_ALGORITHM_PK_GOST_R3410_2001 :
        FPKICrypto := TElBuiltInGOST2001PublicKeyCrypto.Create();
       {$endif}
       {$endif}
    else
      FPKICrypto := nil;
    end;
    FContextType := cctPKICrypto;
    FPKICrypto.KeyMaterial := Key;
  end
  else if IsHashAlgorithm(Algorithm) then
  begin
    FHashFunction := TElBuiltInHashFunction.Create(Algorithm);
    FContextType := cctHash;
    FOperation := ccoHash;
  end
  else if IsMACAlgorithm(Algorithm) then
  begin
    if not (Key is TElBuiltInMACKey) then
      raise EElBuiltInCryptoProviderError.Create(SInvalidKeyMaterial);
    FHashFunction := TElBuiltInHashFunction.Create(Algorithm, Params, Key);
    FContextType := cctHash;
    FOperation := ccoHash;
  end
  else
    raise EElBuiltInCryptoProviderError.CreateFmt(SUnsupportedAlgorithmInt, [Algorithm]);
  FAlgorithm := Algorithm;
  if Params <> nil then
  begin
    for I := 0 to Params.Count - 1 do
      SetContextProp(Params.OIDs[I], Params.Values[I]);
  end;
end;

 destructor  TElBuiltInCryptoContext.Destroy;
begin
  if FContextType = cctSymCrypto then
    FreeAndNil(FSymCrypto)
  else if FContextType = cctPKICrypto then
    FreeAndNil(FPKICrypto)
  else if FContextType = cctHash then
    FreeAndNil(FHashFunction);
  inherited;
end;

function TElBuiltInCryptoContext.GetAlgorithm : integer;
begin
  Result := FAlgorithm;
end;

function TElBuiltInCryptoContext.GetAlgorithmClass : integer;
begin
  Result := FProvider.GetAlgorithmClass(FAlgorithm);
end;

function TElBuiltInCryptoContext.EstimateOutputSize(InSize: Int64): Int64;
var
  Op : TSBBuiltInPublicKeyOperation;
begin
  if FContextType = cctSymCrypto then
  begin
    Result := (((InSize - 1) div FSymCrypto.BlockSize) + 1) * FSymCrypto.BlockSize;
    if (FOperation = ccoEncrypt) and (Padding = SB_SYMENC_PADDING_PKCS5) then
      Result := Result + FSymCrypto.BlockSize;
  end
  else if FContextType = cctPKICrypto then
  begin
    case FOperation of
      ccoEncrypt : Op := pkoEncrypt;
      ccoDecrypt : Op := pkoDecrypt;
      ccoSign : Op := pkoSign;
      ccoVerify : Op := pkoVerify;
      ccoSignDetached : Op := pkoSignDetached;
      ccoVerifyDetached : Op := pkoVerifyDetached;
    else
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
    end;
    Result := FPKICrypto.EstimateOutputSize(InSize, Op);
  end
  else if FContextType = cctHash then
    Result := FHashFunction.GetDigestSizeBits(FHashFunction.Algorithm) shr 3
  else
    raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
end;

function TElBuiltInCryptoContext.GetKeySize : integer;
begin
  if FContextType = cctSymCrypto then
    Result := FSymCrypto.KeySize
  else if (FContextType = cctPKICrypto) and
    (Assigned(FPKICrypto.KeyMaterial)) then
    Result := FPKICrypto.KeyMaterial.Bits
  else
    Result := 0;
end;

procedure TElBuiltInCryptoContext.SetKeySize(Value: integer);
begin
  raise EElBuiltInCryptoProviderError.Create(SCannotChangeROProperty);
end;

function TElBuiltInCryptoContext.GetBlockSize : integer;
begin
  if FContextType = cctSymCrypto then
    Result := FSymCrypto.BlockSize
  else
    raise EElBuiltInCryptoProviderError.Create(SNotASymmetricCipherContext);
end;

procedure TElBuiltInCryptoContext.SetBlockSize(Value: integer);
begin
  raise EElBuiltInCryptoProviderError.Create(SCannotChangeROProperty);
end;
 
function TElBuiltInCryptoContext.GetDigestSize : integer;
begin
  if FContextType = cctHash then
    Result := FHashFunction.GetDigestSizeBits(FHashFunction.Algorithm)
  else
    raise EElBuiltInCryptoProviderError.Create(SNotAHashContext);
end;

procedure TElBuiltInCryptoContext.SetDigestSize(Value : integer);
begin
  raise EElBuiltInCryptoProviderError.Create(SCannotChangeROProperty);
end;
 
function TElBuiltInCryptoContext.GetMode : integer;
begin
  if FContextType = cctSymCrypto then
    Result := ConvertSymmetricCipherMode(FSymCrypto.Mode)
  else
    raise EElBuiltInCryptoProviderError.Create(SNotASymmetricCipherContext);
end;

procedure TElBuiltInCryptoContext.SetMode(Value : integer);
begin
  raise EElBuiltInCryptoProviderError.Create(SCannotChangeROProperty);
end;

function TElBuiltInCryptoContext.GetPadding : integer;
begin
  if FContextType = cctSymCrypto then
    Result := ConvertSymmetricCipherPadding(FSymCrypto.Padding)
  else
    raise EElBuiltInCryptoProviderError.Create(SNotASymmetricCipherContext);
end;

procedure TElBuiltInCryptoContext.SetPadding(Value : integer);
begin
  if FContextType = cctSymCrypto then
    FSymCrypto.Padding := ConvertSymmetricCipherPadding(Value)
  else
    raise EElBuiltInCryptoProviderError.Create(SNotASymmetricCipherContext);
end;

function TElBuiltInCryptoContext.GetContextProp(const PropID : ByteArray;
  const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif}  {$endif}): ByteArray;
begin
  Result := EmptyArray;
  if FContextType = cctHash then
  begin
    Result := FHashFunction.GetHashFunctionProp(PropID, Default);
    Exit;
  end;

  {$ifndef SB_NO_RC4}
  if CompareContent(PropID, SB_CTXPROP_SKIP_KEYSTREAM_BYTES) then
  begin
    if (FContextType = cctSymCrypto) and (FSymCrypto is TElBuiltInRC4SymmetricCrypto) then
    begin
      Result := GetBufferFromInteger(TElBuiltInRC4SymmetricCrypto(FSymCrypto).SkipKeystreamBytes);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SNotARC4Context);
  end
  else
   {$endif}
  if CompareContent(PropID, SB_CTXPROP_CTR_LITTLE_ENDIAN) then
  begin
    if (FContextType = cctSymCrypto) then
    begin
      Result := GetBufferFromBool(FSymCrypto.CTRLittleEndian);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SNotASymmetricCipherContext);
  end
  else
  if CompareContent(PropID, SB_CTXPROP_PADDING_TYPE) then
  begin
    if (FContextType = cctSymCrypto) then
    begin
      if Padding = SB_SYMENC_PADDING_PKCS5 then
        Result := CloneArray(SB_ALGSCHEME_PKCS5)
      else
        Result := EmptyArray;
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SNotASymmetricCipherContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_AEAD_NONCE) then
  begin
    if (FContextType = cctSymCrypto) then
    begin
      if (FSymCrypto.Mode = cmCCM) or
        (FSymCrypto.Mode = cmGCM)
      then
        Result := CloneArray(FSymCrypto.Nonce)
      else
        raise EElBuiltInCryptoProviderError.Create(SInvalidCipherMode);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SNotASymmetricCipherContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_AEAD_TAG_SIZE) then
  begin
    if (FContextType = cctSymCrypto) then
    begin
      if (FSymCrypto.Mode = cmCCM) or
        (FSymCrypto.Mode = cmGCM)
      then
        Result := GetBufferFromInteger(FSymCrypto.TagSize)
      else
        raise EElBuiltInCryptoProviderError.Create(SInvalidCipherMode);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SNotASymmetricCipherContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_AEAD_ASSOCIATED_DATA) then
  begin
    if (FContextType = cctSymCrypto) then
    begin
      if (FSymCrypto.Mode = cmCCM) or
        (FSymCrypto.Mode = cmGCM)
      then
        Result := GetBufferFromBool(FSymCrypto.AssociatedData)
      else
        raise EElBuiltInCryptoProviderError.Create(SInvalidCipherMode);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SNotASymmetricCipherContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_CCM_ASSOCIATED_DATA_SIZE) then
  begin
    if (FContextType = cctSymCrypto) then
    begin
      if (FSymCrypto.Mode = cmCCM) then
        Result := GetBufferFromInteger(FSymCrypto.AssociatedDataSize)
      else
        raise EElBuiltInCryptoProviderError.Create(SInvalidCipherMode);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SNotASymmetricCipherContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_CCM_PAYLOAD_SIZE) then
  begin
    if (FContextType = cctSymCrypto) then
    begin
      if (FSymCrypto.Mode = cmCCM) then
        Result := GetBufferFromInteger(FSymCrypto.PayloadSize)
      else
        raise EElBuiltInCryptoProviderError.Create(SInvalidCipherMode);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SNotASymmetricCipherContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_USE_ALGORITHM_PREFIX) then
  begin
    if (FContextType = cctPKICrypto) and (FPKICrypto is TElBuiltInRSAPublicKeyCrypto) then
    begin
      Result := GetBufferFromBool(TElBuiltInRSAPublicKeyCrypto(FPKICrypto).UseAlgorithmPrefix);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SNotARSAContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_INPUT_IS_HASH) then
  begin
    if (FContextType = cctPKICrypto) then
    begin
      Result := GetBufferFromBool(TElBuiltInPublicKeyCrypto(FPKICrypto).InputIsHash);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SNotAPKIContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_HASH_ALGORITHM) then
  begin
    if (FContextType = cctPKICrypto) then
    begin
      if FPKICrypto is TElBuiltInRSAPublicKeyCrypto then
      begin
        // TODO (low priority): instead of rsapktSSL3 crypto type, use
        // SB_ALGORITHM_DGST_SSL3 hash algorithm
        if TElBuiltInRSAPublicKeyCrypto(FPKICrypto).CryptoType = rsapktSSL3 then
          Result := SB_OID_SSL3
        else
          Result := GetOIDByHashAlgorithm(TElBuiltInRSAPublicKeyCrypto(FPKICrypto).HashAlgorithm);
      end
      else if FPKICrypto is TElBuiltInElgamalPublicKeyCrypto then
      begin
        Result := GetOIDByHashAlgorithm(TElBuiltInElgamalPublicKeyCrypto(FPKICrypto).HashAlgorithm);
      end
      {$ifdef SB_HAS_ECC}
      else if FPKICrypto is TElBuiltInECDSAPublicKeyCrypto then
      begin
        Result := GetOIDByHashAlgorithm(TElBuiltInECDSAPublicKeyCrypto(FPKICrypto).HashAlgorithm);
      end
       {$endif}
    end;
  end
  else if CompareContent(PropID, SB_CTXPROP_HASH_FUNC_OID) then
  begin
    if (FContextType = cctPKICrypto) then
    begin
      if FPKICrypto is TElBuiltInRSAPublicKeyCrypto then
      begin
        Result := CloneArray(TElBuiltInRSAPublicKeyCrypto(FPKICrypto).HashFuncOID);
      end
      else
        raise EElBuiltInCryptoProviderError.Create(SNotARSAContext);
    end;
  end
  else if CompareContent(PropID, SB_CTXPROP_ALGORITHM_SCHEME) then
  begin
    if (FContextType = cctPKICrypto) then
    begin
      if FPKICrypto is TElBuiltInRSAPublicKeyCrypto then
      begin
        if TElBuiltInRSAPublicKeyCrypto(FPKICrypto).CryptoType = rsapktOAEP then
          Result := SB_ALGSCHEME_OAEP
        else if TElBuiltInRSAPublicKeyCrypto(FPKICrypto).CryptoType = rsapktPSS then
          Result := SB_ALGSCHEME_PSS
        else
          Result := SB_ALGSCHEME_PKCS1;
      end
      else
        raise EElBuiltInCryptoProviderError.Create(SNotARSAContext);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_SALT_SIZE) then
  begin
    if (FContextType = cctPKICrypto) then
    begin
      if FPKICrypto is TElBuiltInRSAPublicKeyCrypto then
        Result := GetBufferFromInteger(TElBuiltInRSAPublicKeyCrypto(FPKICrypto).SaltSize)
      else
        raise EElBuiltInCryptoProviderError.Create(SNotARSAContext);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_TRAILER_FIELD) then
  begin
    if (FContextType = cctPKICrypto) then
    begin
      if FPKICrypto is TElBuiltInRSAPublicKeyCrypto then
        Result := GetBufferFromInteger(TElBuiltInRSAPublicKeyCrypto(FPKICrypto).TrailerField)
      else
        raise EElBuiltInCryptoProviderError.Create(SNotARSAContext);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_MGF_ALGORITHM) then
  begin
    if (FContextType = cctPKICrypto) then
    begin
      if FPKICrypto is TElBuiltInRSAPublicKeyCrypto then
        Result := GetOIDByAlgorithm(TElBuiltInRSAPublicKeyCrypto(FPKICrypto).MGFAlgorithm)
      else
        raise EElBuiltInCryptoProviderError.Create(SNotARSAContext);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
  end
  {$ifdef SB_HAS_ECC}
  else if CompareContent(PropID, SB_CTXPROP_EC_PLAIN_ECDSA) then
  begin
    if (FContextType = cctPKICrypto) then
    begin
      if FPKICrypto is TElBuiltInECDSAPublicKeyCrypto then
        Result := GetBufferFromBool(TElBuiltInECDSAPublicKeyCrypto(FPKICrypto).PlainECDSA)
      else
        raise EElBuiltInCryptoProviderError.Create(SNotAECDSAContext);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
  end
   {$endif}
  {$ifdef SB_HAS_GOST}
  else if CompareContent(PropID, SB_CTXPROP_GOST3410_UKM) then
  begin
    if (FContextType = cctPKICrypto) then
    begin
      if FPKICrypto is TElBuiltInGOST2001PublicKeyCrypto then
        Result :=  {$ifndef SB_BUFFERTYPE_IS_BYTEARRAY}StringOfBytes {$else}CloneArray {$endif} (TElBuiltInGOST2001PublicKeyCrypto(FPKICrypto).UKM)
      else
        raise EElBuiltInCryptoProviderError.Create(SNotAGOST2001Context);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_GOST3410_EPHEMERAL_KEY) then
  begin
    if (FContextType = cctPKICrypto) then
    begin
      if FPKICrypto is TElBuiltInGOST2001PublicKeyCrypto then
        Result :=  {$ifndef SB_BUFFERTYPE_IS_BYTEARRAY}StringOfBytes {$else}CloneArray {$endif} (TElBuiltInGOST2001PublicKeyCrypto(FPKICrypto).EphemeralKey)
      else
        raise EElBuiltInCryptoProviderError.Create(SNotAGOST2001Context);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_GOST3410_CEK_MAC) then
  begin
    if (FContextType = cctPKICrypto) then
    begin
      if FPKICrypto is TElBuiltInGOST2001PublicKeyCrypto then
        Result :=  {$ifndef SB_BUFFERTYPE_IS_BYTEARRAY}StringOfBytes {$else}CloneArray {$endif} (TElBuiltInGOST2001PublicKeyCrypto(FPKICrypto).CEKMAC)
      else
        raise EElBuiltInCryptoProviderError.Create(SNotAGOST2001Context);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
  end
   {$endif}
  else
    Result := Default;
end;

procedure TElBuiltInCryptoContext.SetContextProp(const PropID : ByteArray; const Value : ByteArray);
var
  Val : integer;
  BoolVal : boolean;
begin
  if FContextType = cctHash then
  begin
    FHashFunction.SetHashFunctionProp(PropID, Value);
    Exit;
  end;

  {$ifndef SB_NO_RC4}
  if CompareContent(PropID, SB_CTXPROP_SKIP_KEYSTREAM_BYTES) then
  begin
    if (FContextType = cctSymCrypto) and (FSymCrypto is TElBuiltInRC4SymmetricCrypto) then
    begin
      Val := GetIntegerPropFromBuffer(Value);
      TElBuiltInRC4SymmetricCrypto(FSymCrypto).SkipKeystreamBytes := Val;
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SNotARC4Context);
  end
  else
   {$endif}
  if CompareContent(PropID, SB_CTXPROP_CTR_LITTLE_ENDIAN) then
  begin
    if (FContextType = cctSymCrypto) then
    begin
      BoolVal := GetBoolFromBuffer(Value);
      FSymCrypto.CTRLittleEndian := BoolVal;
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SNotASymmetricCipherContext);
  end
  else
  {$ifdef SB_HAS_GOST}
  if CompareContent(PropID, SB_CTXPROP_GOST28147_1989_PARAMSET) then
  begin
    if (FContextType = cctSymCrypto) and (FSymCrypto is TElBuiltInGOST28147SymmetricCrypto) then
      TElBuiltInGOST28147SymmetricCrypto(FSymCrypto).ParamSet := Value
    else
      raise EElBuiltInCryptoProviderError.Create(SNotAGOST89Context);
  end
  else
  if CompareContent(PropID, SB_CTXPROP_GOST28147_1989_PARAMETERS) then
  begin
    if (FContextType = cctSymCrypto) and (FSymCrypto is TElBuiltInGOST28147SymmetricCrypto) then
      TElBuiltInGOST28147SymmetricCrypto(FSymCrypto).SBoxes := Value
    else
      raise EElBuiltInCryptoProviderError.Create(SNotAGOST89Context);
  end
  else if CompareContent(PropID, SB_CTXPROP_GOST28147_1989_USE_KEY_MESHING) then
  begin
    if (FContextType = cctSymCrypto) and (FSymCrypto is TElBuiltInGOST28147SymmetricCrypto) then
      TElBuiltInGOST28147SymmetricCrypto(FSymCrypto).UseKeyMeshing := GetBoolFromBuffer(Value)
    else
      raise EElBuiltInCryptoProviderError.Create(SNotAGOST89Context);
  end
  else
  if CompareContent(PropID, SB_CTXPROP_GOST3410_UKM) then
  begin
    if (FContextType = cctPKICrypto) and (FPKICrypto is TElBuiltInGOST2001PublicKeyCrypto) then
      TElBuiltInGOST2001PublicKeyCrypto(FPKICrypto).UKM := Value
    else
      raise EElBuiltInCryptoProviderError.Create(SNotAGOST2001Context);
  end
  else
  if CompareContent(PropID, SB_CTXPROP_GOST3410_EPHEMERAL_KEY) then
  begin
    if (FContextType = cctPKICrypto) and (FPKICrypto is TElBuiltInGOST2001PublicKeyCrypto) then
      TElBuiltInGOST2001PublicKeyCrypto(FPKICrypto).EphemeralKey := Value
    else
      raise EElBuiltInCryptoProviderError.Create(SNotAGOST2001Context);
  end
  else
  if CompareContent(PropID, SB_CTXPROP_GOST3410_CEK_MAC) then
  begin
    if (FContextType = cctPKICrypto) and (FPKICrypto is TElBuiltInGOST2001PublicKeyCrypto) then
      TElBuiltInGOST2001PublicKeyCrypto(FPKICrypto).CEKMAC := Value
    else
      raise EElBuiltInCryptoProviderError.Create(SNotAGOST2001Context);
  end
  else
   {$endif}
  if CompareContent(PropID, SB_CTXPROP_AEAD_NONCE) then
  begin
    if (FContextType = cctSymCrypto) then
    begin
      if (FSymCrypto.Mode = cmCCM) or
        (FSymCrypto.Mode = cmGCM)
      then
        FSymCrypto.Nonce := CloneArray(Value)
      else
        raise EElBuiltInCryptoProviderError.Create(SInvalidCipherMode);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SNotASymmetricCipherContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_AEAD_TAG_SIZE) then
  begin
    if (FContextType = cctSymCrypto) then
    begin
      if (FSymCrypto.Mode = cmCCM) or
        (FSymCrypto.Mode = cmGCM)
      then
        FSymCrypto.TagSize := GetIntegerPropFromBuffer(Value)
      else
        raise EElBuiltInCryptoProviderError.Create(SInvalidCipherMode);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SNotASymmetricCipherContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_AEAD_ASSOCIATED_DATA) then
  begin
    if (FContextType = cctSymCrypto) then
    begin
      if (FSymCrypto.Mode = cmCCM) or
        (FSymCrypto.Mode = cmGCM)
      then
        FSymCrypto.AssociatedData := GetBoolFromBuffer(Value)
      else
        raise EElBuiltInCryptoProviderError.Create(SInvalidCipherMode);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SNotASymmetricCipherContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_CCM_ASSOCIATED_DATA_SIZE) then
  begin
    if (FContextType = cctSymCrypto) then
    begin
      if (FSymCrypto.Mode = cmCCM) then
        FSymCrypto.AssociatedDataSize := GetIntegerPropFromBuffer(Value)
      else
        raise EElBuiltInCryptoProviderError.Create(SInvalidCipherMode);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SNotASymmetricCipherContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_CCM_PAYLOAD_SIZE) then
  begin
    if (FContextType = cctSymCrypto) then
    begin
      if (FSymCrypto.Mode = cmCCM) then
        FSymCrypto.PayloadSize := GetIntegerPropFromBuffer(Value)
      else
        raise EElBuiltInCryptoProviderError.Create(SInvalidCipherMode);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SNotASymmetricCipherContext);
  end
  else
  if CompareContent(PropID, SB_CTXPROP_PADDING_TYPE) then
  begin
    if (FContextType = cctSymCrypto) then
    begin
      if CompareContent(Value, BytesOfString('pkcs#5')) then
        Padding := SB_SYMENC_PADDING_PKCS5
      else if Length(Value) = 0 then
        Padding := SB_SYMENC_PADDING_NONE
      else
        raise EElBuiltInCryptoProviderError.CreateFmt(SUnsupportedPropertyValue, [BinaryToString(Value)]);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SNotASymmetricCipherContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_USE_ALGORITHM_PREFIX) then
  begin
    if (FContextType = cctPKICrypto) and (FPKICrypto is TElBuiltInRSAPublicKeyCrypto) then
    begin
      BoolVal := GetBoolFromBuffer(Value);
      TElBuiltInRSAPublicKeyCrypto(FPKICrypto).UseAlgorithmPrefix := BoolVal;
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SNotARSAContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_INPUT_IS_HASH) then
  begin
    if (FContextType = cctPKICrypto) then
    begin
      BoolVal := GetBoolFromBuffer(Value);
      TElBuiltInPublicKeyCrypto(FPKICrypto).InputIsHash := BoolVal;
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SNotAPKIContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_HASH_ALGORITHM) then
  begin
    if (FContextType = cctPKICrypto) then
    begin
      if FPKICrypto is TElBuiltInRSAPublicKeyCrypto then
      begin
        // TODO (low priority): instead of rsapktSSL3 crypto type, use
        // SB_ALGORITHM_DGST_SSL3 hash algorithm
        if CompareContent(Value, SB_OID_SSL3) then
          TElBuiltInRSAPublicKeyCrypto(FPKICrypto).CryptoType := rsapktSSL3
        else
        begin
          TElBuiltInRSAPublicKeyCrypto(FPKICrypto).CryptoType := rsapktPKCS1;
          TElBuiltInRSAPublicKeyCrypto(FPKICrypto).HashAlgorithm := GetHashAlgorithmByOID(Value);
        end;
      end
      else if FPKICrypto is TElBuiltInElgamalPublicKeyCrypto then
        TElBuiltInElgamalPublicKeyCrypto(FPKICrypto).HashAlgorithm := GetHashAlgorithmByOID(Value)
      {$ifdef SB_HAS_ECC}
      else if FPKICrypto is TElBuiltInECDSAPublicKeyCrypto then
        TElBuiltInECDSAPublicKeyCrypto(FPKICrypto).HashAlgorithm := GetHashAlgorithmByOID(Value)
       {$endif}
      {$ifdef SB_HAS_GOST}
      else if FPKICrypto is TElBuiltInGOST94PublicKeyCrypto then
        TElBuiltInGOST94PublicKeyCrypto(FPKICrypto).HashAlgorithm := GetHashAlgorithmByOID(Value)
      {$ifdef SB_HAS_ECC}
      else if FPKICrypto is TElBuiltInGOST2001PublicKeyCrypto then
        TElBuiltInGOST2001PublicKeyCrypto(FPKICrypto).HashAlgorithm := GetHashAlgorithmByOID(Value)
       {$endif}  
       {$endif}
    end;
  end
  else if CompareContent(PropID, SB_CTXPROP_HASH_FUNC_OID) then
  begin
    if (FContextType = cctPKICrypto) then
    begin
      if FPKICrypto is TElBuiltInRSAPublicKeyCrypto then
      begin
        TElBuiltInRSAPublicKeyCrypto(FPKICrypto).HashFuncOID := Value;
      end
      else
        raise EElBuiltInCryptoProviderError.Create(SNotARSAContext);
    end;
  end
  else if CompareContent(PropID, SB_CTXPROP_ALGORITHM_SCHEME) then
  begin
    if (FContextType = cctPKICrypto) then
    begin
      if FPKICrypto is TElBuiltInRSAPublicKeyCrypto then
      begin
        if CompareContent(Value, SB_ALGSCHEME_PKCS1) then
          TElBuiltInRSAPublicKeyCrypto(FPKICrypto).CryptoType := rsapktPKCS1
        else if CompareContent(Value, SB_ALGSCHEME_OAEP) then
          TElBuiltInRSAPublicKeyCrypto(FPKICrypto).CryptoType := rsapktOAEP
        else if CompareContent(Value, SB_ALGSCHEME_PSS) then
          TElBuiltInRSAPublicKeyCrypto(FPKICrypto).CryptoType := rsapktPSS
        else
          raise EElBuiltInCryptoProviderError.CreateFmt(SUnsupportedPropertyValue, [BinaryToString(Value)]);
      end
      else
        raise EElBuiltInCryptoProviderError.Create(SNotARSAContext);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_SALT_SIZE) then
  begin
    if (FContextType = cctPKICrypto) then
    begin
      if FPKICrypto is TElBuiltInRSAPublicKeyCrypto then
        TElBuiltInRSAPublicKeyCrypto(FPKICrypto).SaltSize := GetIntegerPropFromBuffer(Value)
      else
        raise EElBuiltInCryptoProviderError.Create(SNotARSAContext);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_TRAILER_FIELD) then
  begin
    if (FContextType = cctPKICrypto) then
    begin
      if FPKICrypto is TElBuiltInRSAPublicKeyCrypto then
        TElBuiltInRSAPublicKeyCrypto(FPKICrypto).TrailerField := GetIntegerPropFromBuffer(Value)
      else
        raise EElBuiltInCryptoProviderError.Create(SNotARSAContext);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
  end
  else if CompareContent(PropID, SB_CTXPROP_MGF_ALGORITHM) then
  begin
    if (FContextType = cctPKICrypto) then
    begin
      if FPKICrypto is TElBuiltInRSAPublicKeyCrypto then
        TElBuiltInRSAPublicKeyCrypto(FPKICrypto).MGFAlgorithm := GetAlgorithmByOID(Value)
      else
        raise EElBuiltInCryptoProviderError.Create(SNotARSAContext);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
  end
  {$ifdef SB_HAS_ECC}
  else if CompareContent(PropID, SB_CTXPROP_EC_PLAIN_ECDSA) then
  begin
      if FPKICrypto is TElBuiltInECDSAPublicKeyCrypto then
        TElBuiltInECDSAPublicKeyCrypto(FPKICrypto).PlainECDSA := GetBoolFromBuffer(Value)
      else
        raise EElBuiltInCryptoProviderError.Create(SNotAECDSAContext);
  end
   {$endif}
  ;
end;

function TElBuiltInCryptoContext.Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoContext;
var
  Ctx : TElBuiltInCryptoContext;
begin
  if FContextType = cctHash then
  begin
    Result := FProvider.HashInit(FAlgorithm, FHashFunction.KeyMaterial);
    if Result is TElBuiltInCryptoContext then
    begin
      Ctx := TElBuiltInCryptoContext(Result);         
      FreeAndNil(Ctx.FHashFunction);
      Ctx.FHashFunction := (FHashFunction.Clone());
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SInvalidContext);
  end
  else
    raise EElBuiltInCryptoProviderError.Create(SCannotCloneContext);
end;

procedure TElBuiltInCryptoContext.CheckKeyLength(Key : TElCustomCryptoKey);
begin
  if FProvider <> nil then
  begin
    if (FProvider.Options.MaxPublicKeySize > 0) and (Key.Bits > FProvider.Options.MaxPublicKeySize) then
      raise EElBuiltInCryptoProviderError.Create(SPublicKeyTooLong);
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// TElBuiltInCryptoProviderOptions class

procedure TElBuiltInCryptoProviderOptions.Init;
begin
  inherited;
  {$ifdef WP8}
  FUsePlatformKeyGeneration := true;
   {$else}
  FUsePlatformKeyGeneration := false;
   {$endif}
  FRollbackToBuiltInKeyGeneration := true;
  FUseTimingAttackProtection := true;
end;

procedure TElBuiltInCryptoProviderOptions.Assign(Options : TElCustomCryptoProviderOptions);
begin
  inherited;
  if Options is TElBuiltInCryptoProviderOptions then
  begin
    FUsePlatformKeyGeneration := TElBuiltInCryptoProviderOptions(Options).FUsePlatformKeyGeneration;
    FUseTimingAttackProtection := TElBuiltInCryptoProviderOptions(Options).FUseTimingAttackProtection;
    FRollbackToBuiltInKeyGeneration := TElBuiltInCryptoProviderOptions(Options).FRollbackToBuiltInKeyGeneration;
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// Other

function BuiltInCryptoProvider : TElCustomCryptoProvider;
begin
  if BuiltInCryptoProv = nil then
  begin
    BuiltInCryptoProv := TElBuiltInCryptoProvider.Create({$ifndef SB_NO_COMPONENT}nil {$endif});
    RegisterGlobalObject(BuiltInCryptoProv);
  end;
  Result := BuiltInCryptoProv;
end;

{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
initialization

  SB_ALGSCHEME_PKCS1 := BytesOfString('pkcs#1');
  SB_ALGSCHEME_PKCS5 := BytesOfString('pkcs#5');
  SB_ALGSCHEME_OAEP := BytesOfString('oaep');
  SB_ALGSCHEME_PSS := BytesOfString('pss');
 {$endif}
end.
