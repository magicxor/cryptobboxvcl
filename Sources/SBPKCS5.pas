(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBPKCS5;

interface

uses
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBASN1,
  SBASN1Tree,
  SBConstants,
  SysUtils,
  Classes,
  SBHashFunction,
  SBSymmetricCrypto;

type
  TSBPKCS5Version = 
    (sbP5v1, sbP5v2);
  
  TElPKCS5PBE = class
  private
    FAlgorithm : integer;
    FKeyLength : integer;
    FIterationCount : integer;
    FSalt : ByteArray;
    FKeyDerivationFunction: integer;
    FPseudoRandomFunction: integer;
    FPseudoRandomFunctionSize: integer;
    FHashFunction: integer;
    FIndex: integer;
    FIV : ByteArray;
    FEncryptionAlgorithm: ByteArray;
    FEncryptionAlgorithmParams: ByteArray;
    FSymmetricAlgorithm: ByteArray;
    FVersion : TSBPKCS5Version;
    procedure DeriveKeyKDF1(const Password: ByteArray; Size : integer; var Key: ByteArray);
    procedure DeriveKeyKDF2(const Password: ByteArray; Size : integer; var Key: ByteArray);
    function FindAlgIndexByOID(const OID : ByteArray): integer;
    procedure ProcessPBES1Params(const Params: ByteArray);
    procedure ProcessPBES2Params(const Params: ByteArray);
    procedure DecryptPBES1(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
      var OutSize : integer; const Password : string);
    procedure DecryptPBES2(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
      var OutSize : integer; const Password : string);
    procedure EncryptPBES1(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
      var OutSize : integer; const Password : string);
    procedure EncryptPBES2(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
      var OutSize : integer; const Password : string);
    procedure ProcessKDFParams(const OID: ByteArray; const Params: ByteArray);
    procedure ProcessPBKDF2Params(const Params: ByteArray);
    procedure ProcessESParams(const OID: ByteArray; const Params: ByteArray);
    function WriteESParams : ByteArray;
    function WriteES1Params : ByteArray;
    function WriteES2Params : ByteArray;
    function PRF(const Password: string; const Salt : ByteArray): ByteArray;
    function PRFHMAC(const Password: string; const Salt : ByteArray; Algorithm : integer): ByteArray;
    procedure SetSalt(const V : ByteArray);
    procedure SetPseudoRandomFunction(const Value : integer);
  public
    // use this constructor to create the PBE basing on PBE algorithm identifier and params
    constructor Create(const OID: ByteArray; const Params: ByteArray);  overload; 
    // use this constructor to create the PBE basing on STREAM and HASH algorithms
    constructor Create(StreamAlg: integer; HashAlg: integer; UseNewVersion : boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif});  overload; 
     destructor  Destroy; override;

    procedure Decrypt(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
      var OutSize : integer; const Password : string);
    procedure Encrypt(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
      var OutSize : integer; const Password : string);
    function DeriveKey(const Password : string; Bits : integer): ByteArray;
    function IsPRFSupported(Alg: integer) : boolean;
    class function IsAlgorithmSupported(Alg: integer) : boolean;  overload; 
    class function IsAlgorithmSupported(const OID: ByteArray): boolean;  overload; 
    class function GetAlgorithmByOID(const OID: ByteArray): integer;
    property Algorithm : integer read FAlgorithm;
    property Version : TSBPKCS5Version read FVersion;
    property EncryptionAlgorithmOID : ByteArray read FEncryptionAlgorithm;
    property EncryptionAlgorithmParams : ByteArray read FEncryptionAlgorithmParams;
    property Salt : ByteArray read FSalt write SetSalt;
    property IterationCount : integer read FIterationCount write FIterationCount;
    property PseudoRandomFunction : integer read FPseudoRandomFunction write SetPseudoRandomFunction;
  end;

  EElPKCS5Error =  class(ESecureBlackboxError);
  EElPKCS5UnsupportedError =  class(EElPKCS5Error);
  EElPKCS5InternalError =  class(EElPKCS5Error);
  EElPKCS5InvalidParameterError =  class(EElPKCS5Error);
  EElPKCS5InvalidPasswordError =  class(EElPKCS5Error);

implementation

uses
  SBPKCS7Utils,
  SBRC2,
  SBRandom;

resourcestring
  SUnsupportedAlgorithm = 'Unsupported algorithm: %s';

  SUnsupportedPRF = 'Unsupported pseudorandom function: %s';
  SInvalidParameters = 'Invalid parameters';
  SInternalError = 'Internal error';
  //SInvalidPassword = 'Invalid password';
  SDigestTooShort = 'Digest too short';
  SInvalidSaltOrIterationCount = 'Invalid salt or iteration count';
  
{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
var
  SB_PKCS5_SUPPORTED_OIDs : array of TByteArrayConst;
 {$endif}

const
  SB_PKCS5_SUPPORTED_COUNT = 7;
  SB_PKCS5_SUPPORTED_ALGs : array[0..SB_PKCS5_SUPPORTED_COUNT - 1] of integer = 
   ( 
    SB_ALGORITHM_P5_PBE_MD2_DES,
    SB_ALGORITHM_P5_PBE_MD5_DES,
    SB_ALGORITHM_P5_PBE_SHA1_DES,
    SB_ALGORITHM_P5_PBE_MD2_RC2,
    SB_ALGORITHM_P5_PBE_MD5_RC2,
    SB_ALGORITHM_P5_PBE_SHA1_RC2,
    SB_ALGORITHM_P5_PBES2
   ) ;
  
{$ifdef SB_UNICODE_VCL}
  {$WARNINGS OFF}
 {$endif}

  {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
  SB_PKCS5_SUPPORTED_OIDs : array{$ifndef SB_NO_NET_STATICARRAYS}[0..SB_PKCS5_SUPPORTED_COUNT - 1] {$endif} of TByteArrayConst =
   ( 
    {$ifndef SB_UNICODE_VCL}TByteArrayConst {$endif}(#$2a#$86#$48#$86#$f7#$0d#$01#$05#$01),
    #$2a#$86#$48#$86#$f7#$0d#$01#$05#$03,
    #$2a#$86#$48#$86#$f7#$0d#$01#$05#$0a,
    #$2a#$86#$48#$86#$f7#$0d#$01#$05#$04,
    #$2a#$86#$48#$86#$f7#$0d#$01#$05#$06,
    #$2a#$86#$48#$86#$f7#$0d#$01#$05#$0b,
    #$2a#$86#$48#$86#$f7#$0d#$01#$05#$0D
   ) ;
   {$endif}

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS ON}
 {$endif}

  SB_PKCS5_HASH_FUNCTIONS : array[0..SB_PKCS5_SUPPORTED_COUNT - 1] of integer = 
   ( 
    SB_ALGORITHM_DGST_MD2,
    SB_ALGORITHM_DGST_MD5,
    SB_ALGORITHM_DGST_SHA1,
    SB_ALGORITHM_DGST_MD2,
    SB_ALGORITHM_DGST_MD5,
    SB_ALGORITHM_DGST_SHA1,
    SB_ALGORITHM_UNKNOWN
   ) ;

  SB_PKCS5_BLOCK_FUNCTIONS : array[0..SB_PKCS5_SUPPORTED_COUNT - 1] of integer = 
   ( 
    SB_ALGORITHM_CNT_DES,
    SB_ALGORITHM_CNT_DES,
    SB_ALGORITHM_CNT_DES,
    SB_ALGORITHM_CNT_RC2,
    SB_ALGORITHM_CNT_RC2,
    SB_ALGORITHM_CNT_RC2,
    SB_ALGORITHM_UNKNOWN
   ) ;

  SB_PKCS5_PBES_FUNCTIONS : array[0..SB_PKCS5_SUPPORTED_COUNT - 1] of integer =
   ( 
    SB_ALGORITHM_P5_PBES1,
    SB_ALGORITHM_P5_PBES1,
    SB_ALGORITHM_P5_PBES1,
    SB_ALGORITHM_P5_PBES1,
    SB_ALGORITHM_P5_PBES1,
    SB_ALGORITHM_P5_PBES1,
    SB_ALGORITHM_P5_PBES2
   ) ;

  SB_PKCS5_PR_FUNCTIONS : array[0..4] of integer =
   ( 
    SB_ALGORITHM_MAC_HMACSHA1,
    SB_ALGORITHM_MAC_HMACSHA224,
    SB_ALGORITHM_MAC_HMACSHA256,
    SB_ALGORITHM_MAC_HMACSHA384,
    SB_ALGORITHM_MAC_HMACSHA512
   ) ;

constructor TElPKCS5PBE.Create(const OID: ByteArray; const Params: ByteArray);
begin
  inherited Create;
  FIndex := FindAlgIndexByOID(OID);
  if FIndex < 0 then
    raise EElPKCS5UnsupportedError.CreateFmt(SUnsupportedAlgorithm, [OIDToStr(OID)]);
  FEncryptionAlgorithm := OID;
  FEncryptionAlgorithmParams := Params;
  if SB_PKCS5_PBES_FUNCTIONS[FIndex] = SB_ALGORITHM_P5_PBES1 then
  begin
    ProcessPBES1Params(Params);
    FVersion := sbP5v1;
  end
  else if SB_PKCS5_PBES_FUNCTIONS[FIndex] = SB_ALGORITHM_P5_PBES2 then
  begin
    ProcessPBES2Params(Params);
    FVersion := sbP5v2;
  end
  else
    raise EElPKCS5UnsupportedError.CreateFmt(SUnsupportedAlgorithm, [IntToStr(SB_PKCS5_PBES_FUNCTIONS[FIndex])]);
end;

constructor TElPKCS5PBE.Create(StreamAlg: integer; HashAlg: integer; UseNewVersion : boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif});
var
  Tag : TElASN1ConstrainedTag;
begin
  inherited Create;
  if UseNewVersion then
  begin
    FIndex := 6;
    case StreamAlg of
      SB_ALGORITHM_CNT_DES:
      begin
        FKeyLength := 8;
        FSymmetricAlgorithm := SB_OID_DES_CBC;
        FAlgorithm := SB_ALGORITHM_CNT_DES;
      end;
      SB_ALGORITHM_CNT_3DES:
      begin
        FKeyLength := 24;
        FSymmetricAlgorithm := SB_OID_DES_EDE3_CBC;
        FAlgorithm := SB_ALGORITHM_CNT_3DES;
      end;
      SB_ALGORITHM_CNT_RC2:
      begin
        FKeyLength := 16;
        FSymmetricAlgorithm := SB_OID_RC2_CBC;
        FAlgorithm := SB_ALGORITHM_CNT_RC2;
      end;
      SB_ALGORITHM_CNT_AES128:
      begin
        FKeyLength := 16;
        FSymmetricAlgorithm := SB_OID_AES128_CBC;
        FAlgorithm := SB_ALGORITHM_CNT_AES128;
      end;
      SB_ALGORITHM_CNT_AES192:
      begin
        FKeyLength := 24;
        FSymmetricAlgorithm := SB_OID_AES192_CBC;
        FAlgorithm := SB_ALGORITHM_CNT_AES192;
      end;
      SB_ALGORITHM_CNT_AES256:
      begin
        FKeyLength := 32;
        FSymmetricAlgorithm := SB_OID_AES256_CBC;
        FAlgorithm := SB_ALGORITHM_CNT_AES256;
      end;
    else
      raise EElPKCS5UnsupportedError.CreateFmt(SUnsupportedAlgorithm, [IntToStr(StreamAlg)]);
    end;

    FKeyDerivationFunction := SB_ALGORITHM_P5_PBKDF2;
    FPseudoRandomFunction := SB_ALGORITHM_MAC_HMACSHA1;
    FPseudoRandomFunctionSize := 20;
    FHashFunction := SB_ALGORITHM_DGST_SHA1;
    SetLength(FIV, 8);
    SBRndGenerate(@FIV[0], 8);
    FVersion := sbP5v2;
    Tag := TElASN1ConstrainedTag.CreateInstance;
    try
      Tag.TagId := SB_ASN1_SEQUENCE;
    finally
      FreeAndNil(Tag);
    end;
  end
  else
  begin
    case StreamAlg of
      SB_ALGORITHM_CNT_DES:
      begin
        FKeyLength := 8;
        FSymmetricAlgorithm := SB_OID_DES_CBC;
        FAlgorithm := SB_ALGORITHM_CNT_DES;
        FIndex := 2;
      end;
      SB_ALGORITHM_CNT_RC2:
      begin
        FKeyLength := 16;
        FSymmetricAlgorithm := SB_OID_RC2_CBC;
        FAlgorithm := SB_ALGORITHM_CNT_RC2;
        FIndex := 5;
      end;
    else
      raise EElPKCS5UnsupportedError.CreateFmt(SUnsupportedAlgorithm, [IntToStr(StreamAlg)]);
    end;
    FKeyDerivationFunction := SB_ALGORITHM_P5_PBKDF1;
    FHashFunction := SB_ALGORITHM_DGST_SHA1;
    FVersion := sbP5v1;
  end;
  FEncryptionAlgorithm := SB_PKCS5_SUPPORTED_OIDs[FIndex];
  FIterationCount := 2048;
  SetLength(FSalt, 8);
  SBRndGenerate(@FSalt[0], 8);
  FEncryptionAlgorithmParams := WriteESParams;
end;

 destructor  TElPKCS5PBE.Destroy;
begin
  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  ReleaseArrays(FSalt, FIV, FEncryptionAlgorithm, FEncryptionAlgorithmParams,
    FSymmetricAlgorithm);
   {$endif}
  inherited;
end;

procedure TElPKCS5PBE.ProcessPBES1Params(const Params: ByteArray);
var
  Tag : TElASN1ConstrainedTag;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if not Tag.LoadFromBuffer(@Params[0], Length(Params)) then
      raise EElPKCS5InvalidParameterError.Create(SInvalidParameters);
    if (Tag.Count <> 1) or (not Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) or
      (TElASN1ConstrainedTag(Tag.GetField(0)).Count <> 2) or
      (not TElASN1ConstrainedTag(Tag.GetField(0)).GetField(0).CheckType(SB_ASN1_OCTETSTRING, false)) or
      (not TElASN1ConstrainedTag(Tag.GetField(0)).GetField(1).CheckType(SB_ASN1_INTEGER, false)) then
      raise EElPKCS5InvalidParameterError.Create(SInvalidParameters);
    FSalt := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(0)).Content;
    FIterationCount := ASN1ReadInteger(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(1)));
    if (Length(FSalt) <> 8) or (FIterationCount <= 0) then
      raise EElPKCS5InvalidParameterError.Create(SInvalidParameters);
    FHashFunction := SB_PKCS5_HASH_FUNCTIONS[FIndex];
    FAlgorithm := SB_PKCS5_BLOCK_FUNCTIONS[FIndex];
  finally
    FreeAndNil(Tag);
  end;
end;

procedure TElPKCS5PBE.ProcessPBES2Params(const Params: ByteArray);
var
  Tag : TElASN1ConstrainedTag;
  AlgIDTag : TElASN1ConstrainedTag;
  KDFOID, KDFParams : ByteArray;
  ESOID, ESParams : ByteArray;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if not Tag.LoadFromBuffer(@Params[0], Length(Params)) then
      raise EElPKCS5InvalidParameterError.Create(SInvalidParameters);
    if (Tag.Count <> 1) or (not Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) or
      (TElASN1ConstrainedTag(Tag.GetField(0)).Count <> 2) or
      (not TElASN1ConstrainedTag(Tag.GetField(0)).GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) or
      (not TElASN1ConstrainedTag(Tag.GetField(0)).GetField(1).CheckType(SB_ASN1_SEQUENCE, true)) then
      raise EElPKCS5InvalidParameterError.Create(SInvalidParameters);
    // keyDerivationFunc
    AlgIDTag := TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(0));
    if ProcessAlgorithmIdentifier(AlgIDTag, KDFOID, KDFParams {$ifndef HAS_DEF_PARAMS}, False {$endif}) <> 0 then
      raise EElPKCS5InvalidParameterError.Create(SInvalidParameters);
    // encryptionScheme
    AlgIDTag := TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(1));
    if ProcessAlgorithmIdentifier(AlgIDTag, ESOID, ESParams {$ifndef HAS_DEF_PARAMS}, False {$endif}) <> 0 then
      raise EElPKCS5InvalidParameterError.Create(SInvalidParameters);
    ProcessKDFParams(KDFOID, KDFParams);
    ProcessESParams(ESOID, ESParams);
  finally
    FreeAndNil(Tag);
    {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
    ReleaseArrays(KDFOID, KDFParams, ESOID, ESParams);
     {$endif}
  end;
end;

procedure TElPKCS5PBE.ProcessKDFParams(const OID: ByteArray; const Params: ByteArray);
begin
  if CompareContent(SB_OID_PBKDF2, OID) then
    ProcessPBKDF2Params(Params)
  else
    raise EElPKCS5UnsupportedError.CreateFmt(SUnsupportedAlgorithm, [OIDToStr(OID)]);
end;

procedure TElPKCS5PBE.ProcessPBKDF2Params(const Params: ByteArray);
var
  Tag, SeqTag : TElASN1ConstrainedTag;
  Index : integer;
  PRFOID, PRFParams : ByteArray;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if not Tag.LoadFromBuffer(@Params[0], Length(Params)) then
      raise EElPKCS5InvalidParameterError.Create(SInvalidParameters);
    if (Tag.Count <> 1) or (not Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      raise EElPKCS5InvalidParameterError.Create(SInvalidParameters);
    SeqTag := TElASN1ConstrainedTag(Tag.GetField(0));
    Index := 0;
    // salt
    if (Index >= SeqTag.Count) or (not SeqTag.GetField(Index).CheckType(SB_ASN1_OCTETSTRING, false)) then
      raise EElPKCS5InvalidParameterError.Create(SInvalidParameters);
    FSalt := TElASN1SimpleTag(SeqTag.GetField(Index)).Content;
    Inc(Index);
    // iteration count
    if (Index >= SeqTag.Count) or (not SeqTag.GetField(Index).CheckType(SB_ASN1_INTEGER, false)) then
      raise EElPKCS5InvalidParameterError.Create(SInvalidParameters);
    FIterationCount := ASN1ReadInteger(TElASN1SimpleTag(SeqTag.GetField(Index)));
    Inc(Index);
    // key length (optional)
    if (Index < SeqTag.Count) and (SeqTag.GetField(Index).CheckType(SB_ASN1_INTEGER, false)) then
    begin
      FKeyLength := ASN1ReadInteger(TElASN1SimpleTag(SeqTag.GetField(Index)));
      Inc(Index);
    end;
    // PRF
    if (Index < SeqTag.Count) and (SeqTag.GetField(Index).CheckType(SB_ASN1_SEQUENCE, true)) then
    begin
      if ProcessAlgorithmIdentifier(SeqTag.GetField(Index), PRFOID, PRFParams {$ifndef HAS_DEF_PARAMS}, False {$endif}) <> 0 then
        raise EElPKCS5InvalidParameterError.Create(SInvalidParameters);
      if not CompareContent(PRFOID, SB_OID_RSA_HMACSHA1) then
        raise EElPKCS5UnsupportedError.CreateFmt(SUnsupportedAlgorithm, [OIDToStr(PRFOID)]);
      Inc(Index);
    end
    else if Index >= SeqTag.Count then
    begin
      PRFOID := SB_OID_RSA_HMACSHA1;
      PRFParams := {$ifndef SB_BUFFERTYPE_IS_BYTEARRAY}TByteArrayConst {$else}BytesOfString {$endif}(#$05#$00);
    end;
    FPseudoRandomFunction := SB_ALGORITHM_MAC_HMACSHA1;
    FPseudoRandomFunctionSize := 20; // for HMAC-SHA1
    if Index < SeqTag.Count then
      raise EElPKCS5InvalidParameterError.Create(SInvalidParameters);
  finally
    FreeAndNil(Tag);
    {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
    ReleaseArrays(PRFOID, PRFParams);
     {$endif}
  end;
  FKeyDerivationFunction := SB_ALGORITHM_P5_PBKDF2;
end;

procedure TElPKCS5PBE.ProcessESParams(const OID: ByteArray; const Params: ByteArray);
var
  IV : ByteArray;
  KeySize, Alg : integer;
  Tag : TElASN1ConstrainedTag;
begin
    
  Alg := SBConstants.GetAlgorithmByOID(OID);

  if Alg = SB_ALGORITHM_UNKNOWN then
    raise EElPKCS5UnsupportedError.CreateFmt(SUnsupportedAlgorithm, [OIDToStr(OID)]);

  if Alg = SB_ALGORITHM_CNT_RC2 then
  begin
    if not SBRC2.ParseASN1Params(Params, IV, KeySize) then
      Exit;
    KeySize := KeySize shr 3;
  end
  else
  begin
    Tag := TElASN1ConstrainedTag.CreateInstance;
    try
      if not Tag.LoadFromBuffer(@Params[0], Length(Params)) then
        raise EElPKCS5UnsupportedError.Create(SInvalidParameters);
      if (Tag.Count <> 1) or (not Tag.GetField(0).CheckType(SB_ASN1_OCTETSTRING, false)) then
        raise EElPKCS5UnsupportedError.Create(SInvalidParameters);
      IV := CloneArray(TElASN1SimpleTag(Tag.GetField(0)).Content);
    finally
      FreeAndNil(Tag);
    end;

    if Alg = SB_ALGORITHM_CNT_DES then
      KeySize := 8
    else if Alg = SB_ALGORITHM_CNT_3DES then
      KeySize := 24
    else if Alg = SB_ALGORITHM_CNT_AES128 then
      KeySize := 16
    else if Alg = SB_ALGORITHM_CNT_AES192 then
      KeySize := 24
    else if Alg = SB_ALGORITHM_CNT_AES256 then
      KeySize := 32
    else
      raise EElPKCS5UnsupportedError.CreateFmt(SUnsupportedAlgorithm, [OIDToStr(OID)]);
  end;

  FKeyLength := KeySize;
  FIV := IV;
  FSymmetricAlgorithm := OID;
  FAlgorithm := Alg;
end;

function TElPKCS5PBE.WriteESParams : ByteArray;
begin
  if FVersion = sbP5v1 then
    Result := WriteES1Params
  else
    Result := WriteES2Params;
end;

function TElPKCS5PBE.WriteES1Params : ByteArray;
var
  Tag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  Size : integer;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    Tag.TagId := SB_ASN1_SEQUENCE;
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.TagId := SB_ASN1_OCTETSTRING;
    STag.Content := FSalt;
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.TagId := SB_ASN1_INTEGER;
    ASN1WriteInteger(STag, FIterationCount);
    Size := 0;
    Tag.SaveToBuffer( nil , Size);
    SetLength(Result, Size);
    Tag.SaveToBuffer( @Result[0] , Size);
    SetLength(Result, Size);
  finally
    FreeAndNil(Tag);
  end;
end;

function TElPKCS5PBE.WriteES2Params : ByteArray;
var
  Tag : TElASN1ConstrainedTag;
  CTag : TElASN1ConstrainedTag;
  ParamTag, AlgIDTag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  Params : ByteArray;
  Size : integer;
  Buf : ByteArray;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    Tag.TagId := SB_ASN1_SEQUENCE;
    // keyDerivationFunc
    if FKeyDerivationFunction = SB_ALGORITHM_P5_PBKDF2 then
    begin
      CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
      ParamTag := TElASN1ConstrainedTag.CreateInstance;
      try
        ParamTag.TagId := SB_ASN1_SEQUENCE;
        STag := TElASN1SimpleTag(ParamTag.GetField(ParamTag.AddField(false)));
        STag.TagId := SB_ASN1_OCTETSTRING;
        STag.Content := FSalt;
        STag := TElASN1SimpleTag(ParamTag.GetField(ParamTag.AddField(false)));
        STag.TagId := SB_ASN1_INTEGER;
        ASN1WriteInteger(STag, FIterationCount);
        AlgIDTag := TElASN1ConstrainedTag(ParamTag.GetField(ParamTag.AddField(true)));
        SaveAlgorithmIdentifier(AlgIDTag, SB_OID_RSA_HMACSHA1, {$ifndef SB_BUFFERTYPE_IS_BYTEARRAY}TByteArrayConst {$else}BytesOfString {$endif}('') {$ifndef HAS_DEF_PARAMS}, 0 {$endif});
        Size := 0;
        ParamTag.SaveToBuffer( nil , Size);
        SetLength(Buf, Size);
        ParamTag.SaveToBuffer( @Buf[0] , Size);
        SetLength(Buf, Size);
      finally
        FreeAndNil(ParamTag);
      end;
      SaveAlgorithmIdentifier(CTag, SB_OID_PBKDF2, Buf {$ifndef HAS_DEF_PARAMS}, 0 {$endif});
    end
    else
      raise EElPKCS5UnsupportedError.CreateFmt(SUnsupportedAlgorithm, [IntToStr(FKeyDerivationFunction)]);
    // encryptionScheme
    CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));

    if FAlgorithm = SB_ALGORITHM_CNT_RC2 then
      SBRC2.WriteASN1Params(FIV, FKeyLength shl 3, Params)
    else
      Params := SBConcatArrays($4, Byte(Length(FIV)), FIV);

    SaveAlgorithmIdentifier(CTag, FSymmetricAlgorithm, Params {$ifndef HAS_DEF_PARAMS}, 0 {$endif});
    Size := 0;
    Tag.SaveToBuffer( nil , Size);
    SetLength(Result, Size);
    Tag.SaveToBuffer( @Result[0] , Size);
    SetLength(Result, Size);
  finally
    FreeAndNil(Tag);
    {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
    ReleaseArray(Buf);
     {$endif}
  end;
end;

procedure TElPKCS5PBE.Decrypt(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
  var OutSize : integer; const Password : string);
begin
  CheckLicenseKey();
  if  (OutSize = 0) or (OutBuffer = nil)  then
    OutSize := InSize
  else
  begin
    if SB_PKCS5_PBES_FUNCTIONS[FIndex] = SB_ALGORITHM_P5_PBES1 then
      DecryptPBES1(InBuffer, InSize, OutBuffer, OutSize, Password)
    else
    if SB_PKCS5_PBES_FUNCTIONS[FIndex] = SB_ALGORITHM_P5_PBES2 then
      DecryptPBES2(InBuffer, InSize, OutBuffer, OutSize, Password)
    else
      raise EElPKCS5UnsupportedError.CreateFmt(SUnsupportedAlgorithm, [IntToStr(SB_PKCS5_PBES_FUNCTIONS[FIndex])]);
  end;
end;

procedure TElPKCS5PBE.Encrypt(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
  var OutSize : integer; const Password : string);
begin
  CheckLicenseKey();
  if  (OutSize = 0) or (OutBuffer = nil)  then
    OutSize := InSize + 32
  else
  begin
    if SB_PKCS5_PBES_FUNCTIONS[FIndex] = SB_ALGORITHM_P5_PBES1 then
      EncryptPBES1(InBuffer, InSize, OutBuffer, OutSize, Password)
    else
    if SB_PKCS5_PBES_FUNCTIONS[FIndex] = SB_ALGORITHM_P5_PBES2 then
      EncryptPBES2(InBuffer, InSize, OutBuffer, OutSize, Password)
    else
      raise EElPKCS5UnsupportedError.CreateFmt(SUnsupportedAlgorithm, [IntToStr(SB_PKCS5_PBES_FUNCTIONS[FIndex])]);
  end;
end;

function TElPKCS5PBE.DeriveKey(const Password : string; Bits : integer): ByteArray;
var
  Size : integer;
begin
  Size := (Bits - 1) shr 3 + 1;
  if FKeyDerivationFunction = SB_ALGORITHM_P5_PBKDF2 then
    DeriveKeyKDF2({$ifndef SB_ANSI_VCL}StrToUTF8 {$else}BytesOfString {$endif}(Password), Size, Result)
  else
    DeriveKeyKDF1({$ifndef SB_ANSI_VCL}StrToUTF8 {$else}BytesOfString {$endif}(Password), Size, Result);
end;

procedure TElPKCS5PBE.DecryptPBES1(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
  var OutSize : integer; const Password : string);
var
  Key : ByteArray;
  SCKey, SCIV : ByteArray;
  SymCrypto : TElSymmetricCrypto;
  SymKey : TElSymmetricKeyMaterial;
  Factory : TElSymmetricCryptoFactory;
begin
  DeriveKeyKDF1(BytesOfString(Password), 16, Key);

  Factory := TElSymmetricCryptoFactory.Create;
  SymKey := TElSymmetricKeyMaterial.Create;

  try
    SetLength(SCKey, 8);
    SetLength(SCIV, 8);

    SBMove(Key, 0 + 0, SCKey, 0, 8);
    SBMove(Key, 8 + 0, SCIV, 0, 8);

    SymCrypto := Factory.CreateInstance(FAlgorithm);

    if not Assigned(SymCrypto) then
      raise EElPKCS5UnsupportedError.CreateFmt(SUnsupportedAlgorithm, [IntToStr(SB_PKCS5_BLOCK_FUNCTIONS[FIndex])]);

    {$ifndef SB_BUFFERTYPE_IS_BYTEARRAY}
    SymKey.Key := BytesOfString(SCKey);
    SymKey.IV := BytesOfString(SCIV);
     {$else}
    SymKey.Key := SCKey;
    SymKey.IV := SCIV;
     {$endif}

    try
      SymCrypto.KeyMaterial := SymKey;

      SymCrypto.Decrypt(InBuffer, InSize, OutBuffer, OutSize);
    finally
      FreeAndNil(SymCrypto);
    end;
  finally
    FreeAndNil(Factory);
    FreeAndNil(SymKey);
    {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
    ReleaseArrays(Key, SCKey, SCIV);
     {$endif}
  end;
end;

procedure TElPKCS5PBE.DecryptPBES2(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
  var OutSize : integer; const Password : string);
var
  Key : ByteArray;
  SymCrypto : TElSymmetricCrypto;
  SymKey : TElSymmetricKeyMaterial;
  Factory : TElSymmetricCryptoFactory;
begin
  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  try
   {$endif}


  if FKeyDerivationFunction = SB_ALGORITHM_P5_PBKDF2 then
    DeriveKeyKDF2(BytesOfString(Password), FKeyLength, Key)
  else
    raise EElPKCS5UnsupportedError.CreateFmt(SUnsupportedAlgorithm, [IntToStr(FKeyDerivationFunction)]);

  Factory := TElSymmetricCryptoFactory.Create;
  SymKey := TElSymmetricKeyMaterial.Create;

  try
    SymCrypto := Factory.CreateInstance(FAlgorithm);

    if not Assigned(SymCrypto) then
      raise EElPKCS5UnsupportedError.CreateFmt(SUnsupportedAlgorithm, [IntToStr(SB_PKCS5_BLOCK_FUNCTIONS[FIndex])]);

    SymKey.Key := Key;
    SymKey.IV := FIV;
    
    SymCrypto.KeyMaterial := SymKey;

    try
      SymCrypto.Decrypt(InBuffer, InSize, OutBuffer, OutSize);
    finally
      FreeAndNil(SymCrypto);
    end;
  finally
    FreeAndNil(SymKey);
    FreeAndNil(Factory);
  end;

  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  finally
    ReleaseArray(Key);
  end;
   {$endif}
end;

procedure TElPKCS5PBE.EncryptPBES1(InBuffer: pointer; InSize: integer;
  OutBuffer: pointer; var OutSize : integer; const Password : string);
var
  Key : ByteArray;
  SCKey, SCIV : ByteArray;
  SymCrypto : TElSymmetricCrypto;
  SymKey : TElSymmetricKeyMaterial;
  Factory : TElSymmetricCryptoFactory;
begin
  try

  DeriveKeyKDF1(BytesOfString(Password), 16, Key);

  Factory := TElSymmetricCryptoFactory.Create;
  SymKey := TElSymmetricKeyMaterial.Create;

  try
    SetLength(SCKey, 8);
    SetLength(SCIV, 8);

    SBMove(Key, 0, SCKey, 0, 8);
    SBMove(Key, 8 + 0, SCIV, 0, 8);

    SymCrypto := Factory.CreateInstance(FAlgorithm);

    if not Assigned(SymCrypto) then
      raise EElPKCS5UnsupportedError.CreateFmt(SUnsupportedAlgorithm, [IntToStr(SB_PKCS5_BLOCK_FUNCTIONS[FIndex])]);

    SymKey.Key := SCKey;
    SymKey.IV := SCIV;

    try
      SymCrypto.KeyMaterial := SymKey;

      SymCrypto.Encrypt(InBuffer, InSize, OutBuffer, OutSize);
    finally
      FreeAndNil(SymCrypto);
    end;
  finally
    FreeAndNil(SymKey);
    FreeAndNil(Factory);
  end;

  finally
    ReleaseArray(Key);
  end;
end;

procedure TElPKCS5PBE.EncryptPBES2(InBuffer: pointer; InSize: integer;
  OutBuffer: pointer; var OutSize : integer; const Password : string);
var
  Key : ByteArray;
  SymCrypto : TElSymmetricCrypto;
  SymKey : TElSymmetricKeyMaterial;
  Factory : TElSymmetricCryptoFactory;
begin
  try

  if FKeyDerivationFunction = SB_ALGORITHM_P5_PBKDF2 then
    DeriveKeyKDF2(BytesOfString(Password), FKeyLength, Key)
  else
    raise EElPKCS5UnsupportedError.CreateFmt(SUnsupportedAlgorithm, [IntToStr(FKeyDerivationFunction)]);

  Factory := TElSymmetricCryptoFactory.Create;
  SymKey := TElSymmetricKeyMaterial.Create;

  try
    SymCrypto := Factory.CreateInstance(FAlgorithm);

    if not Assigned(SymCrypto) then
      raise EElPKCS5UnsupportedError.CreateFmt(SUnsupportedAlgorithm, [IntToStr(SB_PKCS5_BLOCK_FUNCTIONS[FIndex])]);

    SymKey.Key := Key;
    SymKey.IV := FIV;

    SymCrypto.KeyMaterial := SymKey;

    try
      SymCrypto.Encrypt(InBuffer, InSize, OutBuffer, OutSize);
    finally
      FreeAndNil(SymCrypto);
    end;
  finally
    FreeAndNil(SymKey);
    FreeAndNil(Factory);
  end;

  finally
    ReleaseArray(Key);
  end;
end;

procedure TElPKCS5PBE.DeriveKeyKDF1(const Password: ByteArray; Size : integer;
  var Key: ByteArray);
var
  DigestSize : integer;
  HashFunc : TElHashFunction;
  Data : ByteArray;
  I : integer;
begin
  try
    DigestSize := TElHashFunction.GetDigestSizeBits(FHashFunction);
  except
    on E : EElHashFunctionUnsupportedError do
      raise EElPKCS5UnsupportedError.Create(E.Message);
  end;
  if (DigestSize shr 3) < Size then
    raise EElPKCS5InternalError.Create(SDigestTooShort);
  if (Length(FSalt) <> 8) or (FIterationCount <= 0) then
    raise EElPKCS5InvalidParameterError.Create(SInvalidSaltOrIterationCount);
  try
    HashFunc := TElHashFunction.Create(FHashFunction);
  except
    on E : EElHashFunctionUnsupportedError do
      raise EElPKCS5UnsupportedError.Create(E.Message);
  end;
  try
    try
      Data := SBConcatArrays(Password, FSalt);

      for I := 0 to FIterationCount - 1 do
      begin
        HashFunc.Reset;
        HashFunc.Update(Data, 0, Length(Data));
        Data := HashFunc.Finish;
      end;
    finally
      FreeAndNil(HashFunc);
    end;
  except
    raise EElPKCS5InternalError.Create(SInternalError);
  end;
  SetLength(Data, Size);
  Key := Data;
end;

procedure TElPKCS5PBE.DeriveKeyKDF2(const Password: ByteArray; Size : integer;
  var Key: ByteArray);

var
  DigestSize: integer;
  Count : integer;
  I, K, J : integer;
  U, Chunk : ByteArray;
  Tmp : ByteArray;
begin
  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  try
   {$endif}

  try
    DigestSize := FPseudoRandomFunctionSize;
    Count := (Size - 1) div DigestSize + 1;
  except
    on E : EElHashFunctionUnsupportedError do
      raise EElPKCS5UnsupportedError.Create(E.Message);
  end;
  SetLength(Key, 0);
  for I := 1 to Count do
  begin
    SetLength(Chunk, DigestSize);
    FillChar(Chunk[0], DigestSize, 0);
    Tmp := GetBytes32(I);
    U := SBConcatArrays(FSalt, Tmp);
    ReleaseArray(Tmp); 
 
    for K := 0 to FIterationCount - 1 do
    begin
      U := PRF(StringOfBytes(Password), U);

      for J := 0 to Length(U) - 1 + 0 do
        PByte(@Chunk[J])^ := PByte(@Chunk[J])^ xor PByte(@U[J])^;
    end;
    Key := SBConcatArrays(Key, Chunk);
  end;
  SetLength(Key, Size);

  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  finally
    ReleaseArrays(U, Chunk);
  end;
   {$endif}
end;

function TElPKCS5PBE.PRF(const Password: string; const Salt : ByteArray): ByteArray;
begin
  if IsPRFSupported(FPseudoRandomFunction) then
  begin
    if IsMACAlgorithm(FPseudoRandomFunction) then
      Result := PRFHMAC(Password, Salt, FPseudoRandomFunction);
  end
  else
    raise EElPKCS5UnsupportedError.CreateFmt(SUnsupportedAlgorithm, [IntToStr(FPseudoRandomFunction)]);
end;

function TElPKCS5PBE.PRFHMAC(const Password: string; const Salt : ByteArray; Algorithm : integer): ByteArray;
var
  HashFunction : TElHashFunction;
  KM : TElHMACKeyMaterial;
begin
  KM := TElHMACKeyMaterial.Create;
  KM.Key := BytesOfString(Password);
  HashFunction := TElHashFunction.Create(Algorithm, KM);
  HashFunction.Update(@Salt[0], Length(Salt));
  Result := HashFunction.Finish;

  FreeAndNil(HashFunction);
  FreeAndNil(KM);
end;

procedure TElPKCS5PBE.SetSalt(const V : ByteArray);
begin
  FSalt := CloneArray(V);
end;

class function TElPKCS5PBE.IsAlgorithmSupported(Alg: integer) : boolean;
var
  I : integer;
begin
  Result := false;
  for I := 0 to SB_PKCS5_SUPPORTED_COUNT - 1 do
    if Alg = SB_PKCS5_SUPPORTED_ALGS[I] then
    begin
      Result := true;
      Break;
    end;
end;

class function TElPKCS5PBE.IsAlgorithmSupported(const OID: ByteArray): boolean;
var
  I : integer;
begin
  Result := false;
  for I := 0 to SB_PKCS5_SUPPORTED_COUNT - 1 do
    if CompareContent(OID, SB_PKCS5_SUPPORTED_OIDs[I]) then
    begin
      Result := true;
      Break;
    end;
end;

class function TElPKCS5PBE.GetAlgorithmByOID(const OID: ByteArray): integer;
var
  I : integer;
begin
  Result := SB_ALGORITHM_UNKNOWN;
  for I := 0 to SB_PKCS5_SUPPORTED_COUNT - 1 do
    if CompareContent(OID, SB_PKCS5_SUPPORTED_OIDs[I]) then
    begin
      Result := SB_PKCS5_SUPPORTED_ALGS[I];
      Break;
    end;
end;

function TElPKCS5PBE.FindAlgIndexByOID(const OID : ByteArray): integer;
var
  I : integer;
begin
  Result := -1;
  for I := 0 to SB_PKCS5_SUPPORTED_COUNT - 1 do
    if CompareContent(SB_PKCS5_SUPPORTED_OIDs[I], OID) then
    begin
      Result := I;
      Break;
    end;
end;

function TElPKCS5PBE.IsPRFSupported(Alg: integer) : boolean;
var
  I : integer;
begin
  Result := false;
  for I := 0 to Length(SB_PKCS5_PR_FUNCTIONS) - 1 do
    if Alg = SB_PKCS5_PR_FUNCTIONS[I] then
    begin
      Result := true;
      Break;
    end;
end;

procedure TElPKCS5PBE.SetPseudoRandomFunction(const Value : integer);
begin
  if FPseudoRandomFunction <> Value then
  begin
    if IsPRFSupported(Value) then
    begin
      FPseudoRandomFunction := Value;
      if IsMACAlgorithm(Value) then
        FPseudoRandomFunctionSize := TElHashFunction.GetDigestSizeBits(Value) div 8;
    end
    else
      raise EElPKCS5UnsupportedError.CreateFmt(SUnsupportedPRF, [IntToStr(Value)]);
  end;
end;

{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
initialization

  SetLength(SB_PKCS5_SUPPORTED_OIDs, SB_PKCS5_SUPPORTED_COUNT);
  
  SB_PKCS5_SUPPORTED_OIDs[0] := CreateByteArrayConst(#$2a#$86#$48#$86#$f7#$0d#$01#$05#$01);
  SB_PKCS5_SUPPORTED_OIDs[1] := CreateByteArrayConst(#$2a#$86#$48#$86#$f7#$0d#$01#$05#$03);
  SB_PKCS5_SUPPORTED_OIDs[2] := CreateByteArrayConst(#$2a#$86#$48#$86#$f7#$0d#$01#$05#$0a);
  SB_PKCS5_SUPPORTED_OIDs[3] := CreateByteArrayConst(#$2a#$86#$48#$86#$f7#$0d#$01#$05#$04);
  SB_PKCS5_SUPPORTED_OIDs[4] := CreateByteArrayConst(#$2a#$86#$48#$86#$f7#$0d#$01#$05#$06);
  SB_PKCS5_SUPPORTED_OIDs[5] := CreateByteArrayConst(#$2a#$86#$48#$86#$f7#$0d#$01#$05#$0b);
  SB_PKCS5_SUPPORTED_OIDs[6] := CreateByteArrayConst(#$2a#$86#$48#$86#$f7#$0d#$01#$05#$0D);
 {$endif}

end.

