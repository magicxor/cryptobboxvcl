(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBRSA;

interface

uses
  SBTypes,
  SBUtils,
  SBSharedResource,
  SBMath;


type
  TElRSAAntiTimingParams = class(TSBDisposableBase)
  protected
    FVI,
    FVF : PLInt;
    FRSAE,
    FRSAM : ByteArray;
    FInitialized : boolean;
    FPrepared : boolean;
    FSharedResource : TElSharedResource;
    procedure PrepareBlindingPair;
    procedure UpdateBlindingPair;
  public
    constructor Create();
     destructor  Destroy; override;
    procedure Init(const RSAM : ByteArray; const RSAE : ByteArray);
    procedure Reset;
    procedure GetNextBlindingPair(VI, VF : PLInt);
    property Initialized : boolean read FInitialized;
  end;               

function ValidateSignature(Hash : pointer; HashSize : integer; PublicModulus :
  pointer; PublicModulusSize : integer; PublicExponent : pointer;
  PublicExponentSize : integer; Signature : pointer; SignatureSize : integer) : boolean;

function ExtractSignedData(PublicModulus : pointer; PublicModulusSize : integer;
  PublicExponent : pointer;  PublicExponentSize : integer;
  Signature : pointer; SignatureSize : integer) : ByteArray;

{$ifndef SB_PGPSFX_STUB}
function Generate(Bits : integer; PublicModulus : pointer; var PublicModulusSize :
  integer; PublicExponent : pointer; var PublicExponentSize : integer;
  PrivateExponent : pointer; var PrivateExponentSize : integer) : boolean;  overload;  
function ExternalGenerate(Bits : integer; PublicModulus : pointer; var PublicModulusSize :
  integer; PublicExponent : pointer; var PublicExponentSize : integer;
  PrivateExponent : pointer; var PrivateExponentSize : integer) : boolean;  overload;  

function Generate(Bits : integer; PublicModulus : pointer; var PublicModulusSize :
  integer; PublicExponent : pointer; var PublicExponentSize : integer;
  PrivateExponent : pointer; var PrivateExponentSize : integer;
  PrivateKeyBlob : pointer; var PrivateKeyBlobSize : integer;
  ProgressFunc : TSBMathProgressFunc = nil; Data : pointer = nil) : boolean;  overload;  
function ExternalGenerate(Bits : integer; PublicModulus : pointer; var PublicModulusSize :
  integer; PublicExponent : pointer; var PublicExponentSize : integer;
  PrivateExponent : pointer; var PrivateExponentSize : integer;
  PrivateKeyBlob : pointer; var PrivateKeyBlobSize : integer;
  ProgressFunc : TSBMathProgressFunc = nil; Data : pointer = nil) : boolean;  overload;  
function ExternalGenerationSupported: boolean;

function Generate(Bits : integer; PublicModulus : PLInt; PublicExponent : PLInt;
  PrivateExponent: PLInt; P : PLInt; Q : PLInt; U : PLInt) : boolean;  overload;  
function ExternalGenerate(Bits : integer; PublicModulus : PLInt; PublicExponent : PLInt;
  PrivateExponent: PLInt; P : PLInt; Q : PLInt; U : PLInt) : boolean;  overload;  

function Sign(Hash : pointer; HashSize : integer; PublicModulus : pointer;
  PublicModulusSize : integer; PrivateExponent : pointer; PrivateExponentSize :
  integer; Signature : pointer; var SignatureSize : integer;
  AntiTimingParams : TElRSAAntiTimingParams) : boolean;  overload;  

function Sign(Hash : pointer; HashSize : integer; PrivateKeyBlob: pointer;
  PrivateKeyBlobSize : integer; Signature: pointer; var SignatureSize : integer;
  AntiTimingParams : TElRSAAntiTimingParams) : boolean;  overload;  

function Encrypt(InBuffer : pointer; InSize : integer; PublicModulus : pointer;
  PublicModulusSize : integer; PublicExponent : pointer; PublicExponentSize :
  integer; OutBuffer : pointer; var OutSize : integer) : boolean;  overload;  

function Encrypt(InBuffer : pointer; InSize : integer; OutBuffer: pointer;
  var OutSize : integer; PublicModulus : PLInt; PublicExponent : PLInt) : boolean;  overload;  
 {$endif SB_PGPSFX_STUB}

function Decrypt(InBuffer : pointer; InSize : integer; PublicModulus : pointer;
  PublicModulusSize : integer; PrivateExponent : pointer; PrivateExponentSize :
  integer; OutBuffer : pointer; var OutSize : integer;
  AntiTimingParams : TElRSAAntiTimingParams) : boolean;  overload;  

function Decrypt(InBuffer : pointer; InSize : integer; PrivateKeyBlob: pointer;
  PrivateKeyBlobSize : integer; OutBuffer: pointer; var OutSize : integer;
  AntiTimingParams : TElRSAAntiTimingParams) : boolean; overload;

function DecodePrivateKey(Buffer : pointer; Size : integer; PublicModulus :
  pointer; var PublicModulusSize : integer; PublicExponent : pointer; var
  PublicExponentSize : integer; PrivateExponent : pointer; var PrivateExponentSize :
  integer) : boolean; overload;

function DecodePrivateKey(Buffer : pointer; Size : integer; PublicModulus :
  pointer; var PublicModulusSize : integer; PublicExponent : pointer; var
  PublicExponentSize : integer; PrivateExponent : pointer; var PrivateExponentSize :
  integer; P : pointer; var PSize : integer; Q : pointer; var QSize : integer;
  E1 : pointer; var E1Size : integer; E2 : pointer; var E2Size : integer;
  U : pointer; var USize : integer) : boolean; overload;

function EncodePrivateKey(PublicModulus : pointer; PublicModulusSize : integer;
  PublicExponent : pointer; PublicExponentSize : integer; PrivateExponent :
  pointer; PrivateExponentSize : integer; Prime1 : pointer; Prime1Size : integer;
  Prime2 : pointer; Prime2Size : integer; Exponent1 : pointer; Exponent1Size :
  integer; Exponent2 : pointer; Exponent2Size : integer; Coef : pointer; CoefSize :
  integer; OutBuffer : pointer; var OutSize : integer) : boolean; overload;

function IsValidKey(Blob: pointer; BlobSize: integer) : boolean;

{$ifndef SB_PGPSFX_STUB}
function EncryptOAEP(InBuffer : pointer; InSize : integer; PublicModulus : pointer;
  PublicModulusSize : integer; PublicExponent : pointer; PublicExponentSize :
  integer; Salt: pointer; SaltSize: integer; HashAlg : integer; OutBuffer : pointer;
  var OutSize : integer) : boolean;
 {$endif SB_PGPSFX_STUB}

{$ifndef SB_PGPSFX_STUB}
function DecryptOAEP(InBuffer : pointer; InSize : integer; PublicModulus : pointer;
  PublicModulusSize : integer; PrivateExponent : pointer; PrivateExponentSize :
  integer; Salt: pointer; SaltSize : integer; HashAlg: integer; OutBuffer : pointer;
  var OutSize : integer; AntiTimingParams : TElRSAAntiTimingParams) : boolean; overload;

function DecryptOAEP(InBuffer : pointer; InSize : integer; Blob : pointer;
  BlobSize : integer; Salt: pointer; SaltSize : integer; HashAlg: integer; OutBuffer : pointer;
  var OutSize : integer; AntiTimingParams : TElRSAAntiTimingParams) : boolean; overload;
 {$endif SB_PGPSFX_STUB}

function DecodePublicKey(Buffer : pointer; Size : integer; PublicModulus : pointer;
  var PublicModulusSize: integer; PublicExponent : pointer; var PublicExponentSize:
  integer; var AlgID : ByteArray; InnerValuesOnly : boolean = false): boolean;

function EncodePublicKey(PublicModulus : pointer; PublicModulusSize : integer;
  PublicExponent : pointer; PublicExponentSize : integer; const AlgID: ByteArray;
  OutBuffer : pointer; var OutSize : integer; InnerValuesOnly : boolean = false) : boolean;


function EncodePrivateKey(PublicModulus : pointer; PublicModulusSize : integer;
  PublicExponent : pointer; PublicExponentSize : integer; PrivateExponent :
  pointer; PrivateExponentSize : integer; OutBuffer : pointer; var OutSize : integer) : boolean; overload;

{$ifndef SB_PGPSFX_STUB}
{ PKCS#1 RSASSA-PSS-SIGN }
function SignPSS(HashValue : pointer; HashValueSize : integer;
  HashAlgorithm : integer; SaltSize : integer; KeyBlob : pointer;
  KeyBlobSize : integer; Signature : pointer;
  var SignatureSize : integer; AntiTimingParams : TElRSAAntiTimingParams) : boolean; overload;
function SignPSS(HashValue : pointer; HashValueSize : integer;
  HashAlgorithm : integer; SaltSize : integer;
  PublicModulus : pointer; PublicModulusSize : integer;
  PublicExponent : pointer; PublicExponentSize : integer;  
  PrivateExponent : pointer; PrivateExponentSize : integer;
  Signature : pointer; var SignatureSize : integer; AntiTimingParams : TElRSAAntiTimingParams) : boolean; overload;
{ PKCS#1 RSASSA-PSS-VERIFY }
function VerifyPSS(HashValue : pointer; HashValueSize : integer;
  HashAlgorithm : integer; SaltSize : integer;
  PublicModulus : pointer; PublicModulusSize : integer;
  PublicExponent : pointer; PublicExponentSize : integer; Signature : pointer;
  SignatureSize : integer) : boolean;
 {$endif SB_PGPSFX_STUB}

function PerformExponentiation(Modulus: pointer; ModulusSize: integer;
  Exponent: pointer; ExponentSize: integer; InBuffer: pointer; InSize: integer;
  OutBuffer: pointer; var OutSize : integer; AntiTimingParams : TElRSAAntiTimingParams): boolean; overload;

function PerformExponentiation(Blob : pointer; BlobSize : integer;
  InBuffer: pointer; InSize: integer;
  OutBuffer: pointer; var OutSize : integer; AntiTimingParams : TElRSAAntiTimingParams): boolean; overload;

implementation

uses
   SysUtils, 
  SBASN1,
  SBASN1Tree,
  SBMD,
  SBRandom,
  SBConstants,
  SBStrUtils,
  //SBSHA, SBSHA2,
  SBHashFunction
  ;

function ValidateSignature(Hash : pointer; HashSize : integer; PublicModulus :
  pointer; PublicModulusSize : integer; PublicExponent : pointer;
  PublicExponentSize : integer; Signature : pointer; SignatureSize : integer) : boolean;
var
  X, E, M, Y : PLInt;
  TmpBuf : array of byte;
  Sz : integer;
begin
  LCreate(X);
  LCreate(E);
  LCreate(M);
  LCreate(Y);
  PointerToLInt(X, Signature , SignatureSize );
  PointerToLInt(E, PublicExponent , PublicExponentSize );
  PointerToLInt(M, PublicModulus , PublicModulusSize );
  LMModPower(X, E, M, Y);

  Sz := Y.Length * 4;
  SetLength(TmpBuf, Sz);

  LIntToPointer(Y, @TmpBuf[0], Sz);

  LDestroy(X);
  LDestroy(E);
  LDestroy(M);
  LDestroy(Y);

  SetLength(TmpBuf, Sz);
  if (Sz > PublicModulusSize) then
  begin
    // LIntToPointer returns value with length divisible by 4
    // Therefore it may contain prefix zeros if PublicModulusSize is
    // not divisible by 4
    SBMove(TmpBuf[Sz - PublicModulusSize], TmpBuf[0], PublicModulusSize);
    SetLength(TmpBuf, PublicModulusSize);
  end;

  Result := false;

  if ((Length(TmpBuf) < 2) or (TmpBuf[0] <> 0) or (TmpBuf[1] <> 1)) and (TmpBuf[0] <> 1) then
    Exit;

  if TmpBuf[0] = 1 then
    Sz := 1
  else
    Sz := 2;

  while (Sz < Length(TmpBuf)) and (TmpBuf[Sz] = $FF) do
    Inc(Sz);
  if (Sz >= Length(TmpBuf)) or (TmpBuf[Sz] <> 0) then
    Exit;
  Result := CompareMem(@TmpBuf[Length(TmpBuf) - HashSize], Hash, HashSize);
end;

function ExtractSignedData(PublicModulus : pointer; PublicModulusSize : integer;
  PublicExponent : pointer; PublicExponentSize : integer;
  Signature : pointer; SignatureSize : integer) : ByteArray;
var
  X, E, M, Y : PLInt;
  TmpBuf : ByteArray;
  Sz : integer;
begin
  LCreate(X);
  LCreate(E);
  LCreate(M);
  LCreate(Y);
  PointerToLInt(X, Signature , SignatureSize );
  PointerToLInt(E, PublicExponent , PublicExponentSize );
  PointerToLInt(M, PublicModulus , PublicModulusSize );
  LMModPower(X, E, M, Y);

  Sz := Y.Length shl 2;
  SetLength(TmpBuf, Sz);

  LIntToPointer(Y, @TmpBuf[0], Sz);

  LDestroy(X);
  LDestroy(E);
  LDestroy(M);
  LDestroy(Y);

  SetLength(TmpBuf, Sz);
  if (Sz > PublicModulusSize) then
  begin
    // LIntToPointer returns value with length divisible by 4
    // Therefore it may contain prefix zeros if PublicModulusSize is
    // not divisible by 4
    SBMove(TmpBuf[Sz - PublicModulusSize], TmpBuf[0], PublicModulusSize);
    SetLength(TmpBuf, PublicModulusSize);
  end;

  Result := EmptyArray;

  if ((Length(TmpBuf) < 2) or (TmpBuf[0] <> 0) or (TmpBuf[1] <> 1)) and (TmpBuf[0] <> 1) then
    Exit;

  if TmpBuf[0] = 1 then
    Sz := 1
  else
    Sz := 2;

  while (Sz < Length(TmpBuf)) and (TmpBuf[Sz] = $FF) do
    Inc(Sz);
  if (Sz >= Length(TmpBuf)) or (TmpBuf[Sz] <> 0) then
    Exit;

  Result := Copy(TmpBuf, Sz + 1, Length(TmpBuf) - Sz - 1);
end;


{$ifdef WP8}
procedure IntExternalGenerateWP8(Bits : integer; var PublicModulus, PublicExponent,
  PrivateExponent, P, Q, DP, DQ, U : ByteArray);
var
  CspPars : System.Security.Cryptography.CspParameters;
  TmpPart : string;
  Prov : System.Security.Cryptography.RSACryptoServiceProvider;
  RsaPars : System.Security.Cryptography.RSAParameters;
begin
  TmpPart := SBRndGenerate().ToString();
  CspPars := new System.Security.Cryptography.CspParameters;
  CspPars.KeyContainerName := 'sbbrsakey' + TmpPart;
  Prov := new System.Security.Cryptography.RSACryptoServiceProvider(Bits, CspPars);
  try
    Prov.PersistKeyInCsp := false;
    RsaPars := Prov.ExportParameters(true);
    PublicModulus := RsaPars.Modulus;
    PublicExponent := RsaPars.Exponent;
    PrivateExponent := RsaPars.D;
    P := RsaPars.P;
    Q := RsaPars.Q;
    DP := RsaPars.DP;
    DQ := RsaPars.DQ;
    U := RsaPars.InverseQ;
  finally
    Prov.Clear();
    Prov.Dispose();
  end;
end;
 {$endif}

procedure IntExternalGenerate(Bits : integer; var PublicModulus, PublicExponent,
  PrivateExponent, P, Q, DP, DQ, U : ByteArray);
begin
  // For each platform, implement its own IntExternalGenerate<PLATFORM> method
  // (e.g. IntExternalGenerateWP8) with the same signature and delegate the call
  // to it from here. Arrange calls to methods for different platforms with conditional defines.
  {$ifdef WP8}
  IntExternalGenerateWP8(Bits, PublicModulus, PublicExponent, PrivateExponent,
    P, Q, DP, DQ, U);
   {$else}
  raise ESecureBlackboxError.Create('Method not implemented for the active platform: SBRSA.IntExternalGenerate()');
   {$endif}
end;

{$ifndef SB_PGPSFX_STUB}
function Generate(Bits : integer; PublicModulus : pointer; var PublicModulusSize :
  integer; PublicExponent : pointer; var PublicExponentSize : integer;
  PrivateExponent : pointer; var PrivateExponentSize : integer) : boolean;
var
  P, Q, N, Phi, PDec, QDec : PLInt;
  Sz : integer;
begin
  Sz := Bits shr 3;
  if ((PublicModulusSize < Sz) or (PrivateExponentSize < Sz) or (PublicExponentSize < 4)) then
  begin
    PublicModulusSize := Sz;
    PrivateExponentSize := Sz;
    PublicExponentSize := Sz;
    Result := false;
    Exit;
  end;
  LCreate(P);
  LCreate(Q);
  LCreate(N);
  LCreate(Phi);
  LCreate(PDec);
  LCreate(QDec);
  LGenPrime(P, Bits shr 6 , true);
  LGenPrime(Q, Bits shr 6, true);
  LMult(P, Q, N);
  LSub(P, Phi, PDec);
  LSub(Q, Phi, QDec);
  LMult(PDec, QDec, Phi);
  LInit(PDec, '00010001');
  LGCD(PDec, Phi, P, QDec);
  LIntToPointer(N, PublicModulus, PublicModulusSize);
  LIntToPointer(PDec, PublicExponent, PublicExponentSize);
  LIntToPointer(QDec, PrivateExponent, PrivateExponentSize);
  LDestroy(P);
  LDestroy(Q);
  LDestroy(N);
  LDestroy(Phi);
  LDestroy(PDec);
  LDestroy(QDec);
  Result := true;
end;

function ExternalGenerationSupported: boolean;
begin
  // For each platform an appropriate value should be returned
  {$ifdef WP8}
  Result := true;
   {$else}
  Result := false;
   {$endif}
end;

function ExternalGenerate(Bits : integer; PublicModulus : pointer; var PublicModulusSize :
  integer; PublicExponent : pointer; var PublicExponentSize : integer;
  PrivateExponent : pointer; var PrivateExponentSize : integer) : boolean;
var
  FullLen : integer;
  RSAM, RSAE, RSAD, RSAP, RSAQ, RSADP, RSADQ, RSAU : ByteArray;
begin
  Result := false;
  FullLen := ((Bits - 1) shr 3) + 1;
  //HalfLen := ((FullLen - 1) shr 1) + 1;
  if ((PublicModulusSize < FullLen) or (PrivateExponentSize < FullLen) or (PublicExponentSize < 4)) then
  begin
    PublicModulusSize := FullLen;
    PrivateExponentSize := FullLen;
    PublicExponentSize := FullLen;
  end
  else
  begin
    try
      try
        IntExternalGenerate(Bits, RSAM, RSAE, RSAD, RSAP, RSAQ, RSADP, RSADQ, RSAU);
        PublicModulusSize := Length(RSAM);
        PublicExponentSize := Length(RSAE);
        PrivateExponentSize := Length(RSAD);
        Move(RSAM[0], PublicModulus^, PublicModulusSize);
        Move(RSAE[0], PublicExponent^, PublicExponentSize);
        Move(RSAD[0], PrivateExponent^, PrivateExponentSize);
        Result := true;
      finally
        ReleaseArrays(RSAM, RSAE, RSAD, RSAP, RSAQ, RSADP, RSADQ, RSAU);
      end;
    except
      Result := false;
    end;
  end;
end;

function Generate(Bits : integer; PublicModulus : PLInt; PublicExponent : PLInt;
  PrivateExponent: PLInt; P : PLInt; Q : PLInt; U : PLInt) : boolean;
var
  Phi, PDec, QDec, Tmp1: PLInt;
begin
  Result := (PublicModulus <> nil) and (PublicExponent <> nil) and
    (PrivateExponent <> nil) and (P <> nil) and (Q <> nil) and (U <> nil);
  if not Result then
    Exit;
  LCreate(Phi);
  LCreate(PDec);
  LCreate(QDec);
  LCreate(Tmp1);
  try
    LGenPrime(P, Bits shr 6, true);
    LGenPrime(Q, Bits shr 6, true);
    if LGreater(P, Q) then
    begin
      LCopy(Tmp1, P);
      LCopy(P, Q);
      LCopy(Q, Tmp1);
    end;
    LMult(P, Q, PublicModulus);
    LSub(P, Phi, PDec);
    LSub(Q, Phi, QDec);
    LMult(PDec, QDec, Phi);
    PublicExponent.Digits[1] := 65537;
    PublicExponent.Length := 1;
    LGCD(PublicExponent, Phi, Tmp1, PrivateExponent);
    LGCD(P, Q, Tmp1, U);
  finally
    LDestroy(Phi);
    LDestroy(PDec);
    LDestroy(QDec);
    LDestroy(Tmp1);
  end;
  Result := true;
end;

function ExternalGenerate(Bits : integer; PublicModulus : PLInt; PublicExponent : PLInt;
  PrivateExponent: PLInt; P : PLInt; Q : PLInt; U : PLInt) : boolean;
var
  RSAM, RSAE, RSAD, RSAP, RSAQ, RSADP, RSADQ, RSAU : ByteArray;
begin
  try
    IntExternalGenerate(Bits, RSAM, RSAE, RSAD, RSAP, RSAQ, RSADP, RSADQ, RSAU);
    try
      PointerToLInt(PublicModulus,  @RSAM[0], Length(RSAM) );
      PointerToLInt(PublicExponent,  @RSAE[0], Length(RSAE) );
      PointerToLInt(PrivateExponent,  @RSAD[0], Length(RSAD) );
      PointerToLInt(P,  @RSAP[0], Length(RSAP) );
      PointerToLInt(Q,  @RSAQ[0], Length(RSAQ) );
      PointerToLInt(U,  @RSAU[0], Length(RSAU) );
    finally
      ReleaseArrays(RSAM, RSAE, RSAD, RSAP, RSAQ, RSADP, RSADQ, RSAU);
    end;
    Result := true;
  except
    Result := false;
  end;
end;

function Generate(Bits : integer; PublicModulus : pointer; var PublicModulusSize :
  integer; PublicExponent : pointer; var PublicExponentSize : integer;
  PrivateExponent : pointer; var PrivateExponentSize : integer;
  PrivateKeyBlob : pointer; var PrivateKeyBlobSize : integer; ProgressFunc :
  TSBMathProgressFunc = nil; Data : pointer = nil) : boolean;
const
  ZeroTagContent: array [0..0] of Byte =   (0)  ;
var
  EstimatedBlobSize : integer;
  P, Q, N, Phi, PDec, QDec, Tmp1, Tmp2, Tmp3 : PLInt;
  Sz : integer;

  Tmp : ByteArray;

  Tag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
begin
  Sz := Bits shr 3;
  EstimatedBlobSize := (Sz shl 2) + (Sz shr 1 + 1) + 5 + 64;
  if ((PublicModulusSize < Sz) or (PrivateExponentSize < Sz) or (PublicExponentSize < 4) or
    (PrivateKeyBlobSize < EstimatedBlobSize)) then
  begin
    PublicModulusSize := Sz;
    PrivateExponentSize := Sz;
    PublicExponentSize := Sz;
    PrivateKeyBlobSize := EstimatedBlobSize;
    Result := false;
    Exit;
  end;
  LCreate(P);
  LCreate(Q);
  LCreate(N);
  LCreate(Phi);
  LCreate(PDec);
  LCreate(QDec);
  LCreate(Tmp1);
  LCreate(Tmp2);
  LCreate(Tmp3);
  try
    try
      LGenPrime(P, Bits shr 6, true, ProgressFunc, Data, true);
      LGenPrime(Q, Bits shr 6, true, ProgressFunc, Data, true);
    except
      Result := false;
      Exit;
    end;
    LMult(P, Q, N);
    LSub(P, Phi, PDec);
    LSub(Q, Phi, QDec);
    LMult(PDec, QDec, Phi);
    LInit(Tmp3, '00010001');
    LGCD(Tmp3, Phi, Tmp1, Tmp2);
    LIntToPointer(N, PublicModulus, PublicModulusSize);
    LIntToPointer(Tmp3, PublicExponent, PublicExponentSize);
    LIntToPointer(Tmp2, PrivateExponent, PrivateExponentSize);

    Tag := TElASN1ConstrainedTag.CreateInstance;
    try
      Tag.TagId := SB_ASN1_SEQUENCE;

      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      STag.TagId := SB_ASN1_INTEGER;
      STag.Content := GetByteArrayFromByte(0);

      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      STag.TagId := SB_ASN1_INTEGER;

      SetLength(Tmp, PublicModulusSize);
      SBMove(PublicModulus^, Tmp[0], Length(Tmp));
      if Ord(Tmp[0]) >= 128 then
        STag.Content := SBConcatArrays(GetByteArrayFromByte(0), Tmp)
      else
        STag.Content := CloneArray(Tmp);


      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      STag.TagId := SB_ASN1_INTEGER;
      SetLength(Tmp, PublicExponentSize);
      SBMove(PublicExponent^, Tmp[0], Length(Tmp));

      if Ord(Tmp[0]) >= 128 then
        STag.Content := SBConcatArrays(GetByteArrayFromByte(0), Tmp)
      else
        STag.Content := CloneArray(Tmp);

      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      STag.TagId := SB_ASN1_INTEGER;
      SetLength(Tmp, PrivateExponentSize);
      SBMove(PrivateExponent^, Tmp[0], Length(Tmp));
      if Ord(Tmp[0]) >= 128 then
        STag.Content := SBConcatArrays(GetByteArrayFromByte(0), Tmp)
      else
        STag.Content := CloneArray(Tmp);

      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      STag.TagId := SB_ASN1_INTEGER;
      Sz := P.Length shl 2;

      SetLength(Tmp, Sz);
      LIntToPointer(P, @Tmp[0], Sz);
      if Ord(Tmp[0]) >= 128 then
        STag.Content := SBConcatArrays(GetByteArrayFromByte(0), Tmp)
      else
        STag.Content := CloneArray(Tmp);

      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      STag.TagId := SB_ASN1_INTEGER;

      Sz := Q.Length shl 2;
      SetLength(Tmp, Sz);
      LIntToPointer(Q, @Tmp[0], Sz);
      if Ord(Tmp[0]) >= 128 then
        STag.Content := SBConcatArrays(GetByteArrayFromByte(0), Tmp)
      else
        STag.Content := CloneArray(Tmp);
      LMod(Tmp2, PDec, Tmp3);

      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      STag.TagId := SB_ASN1_INTEGER;

      Sz := Tmp3.Length shl 2;

      SetLength(Tmp, Sz);
      LIntToPointer(Tmp3, @Tmp[0], Sz);
      if Ord(Tmp[0]) >= 128 then
        STag.Content := SBConcatArrays(GetByteArrayFromByte(0), Tmp)
      else
        STag.Content := CloneArray(Tmp);
      LMod(Tmp2, QDec, Tmp3);

      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      STag.TagId := SB_ASN1_INTEGER;
      Sz := Tmp3.Length shl 2;

      SetLength(Tmp, Sz);
      LIntToPointer(Tmp3, @Tmp[0], Sz);
      if Ord(Tmp[0]) >= 128 then
        STag.Content := SBConcatArrays(GetByteArrayFromByte(0), Tmp)
      else
        STag.Content := CloneArray(Tmp);
      LGCD(Q, P, Tmp1, Tmp3);

      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      STag.TagId := SB_ASN1_INTEGER;
      Sz := Tmp3.Length shl 2;

      SetLength(Tmp, Sz);
      LIntToPointer(Tmp3, @Tmp[0], Sz);
      if Ord(Tmp[0]) >= 128 then
        STag.Content := SBConcatArrays(GetByteArrayFromByte(0), Tmp)
      else
        STag.Content := CloneArray(Tmp);

      Result := Tag.SaveToBuffer(PrivateKeyBlob, PrivateKeyBlobSize);
    finally
      FreeAndNil(Tag);
    end;
  finally
    LDestroy(P);
    LDestroy(Q);
    LDestroy(N);
    LDestroy(Phi);
    LDestroy(PDec);
    LDestroy(QDec);
    LDestroy(Tmp1);
    LDestroy(Tmp2);
    LDestroy(Tmp3);
  end;
end;

function ExternalGenerate(Bits : integer; PublicModulus : pointer; var PublicModulusSize :
  integer; PublicExponent : pointer; var PublicExponentSize : integer;
  PrivateExponent : pointer; var PrivateExponentSize : integer;
  PrivateKeyBlob : pointer; var PrivateKeyBlobSize : integer; ProgressFunc :
  TSBMathProgressFunc = nil; Data : pointer = nil) : boolean;
var
  RSAM, RSAE, RSAD, RSAP, RSAQ, RSADP, RSADQ, RSAU : ByteArray;
  Sz, EstimatedBlobSize : integer;
begin
  Sz := Bits shr 3;
  EstimatedBlobSize := (Sz * 4) + (Sz shr 1 + 1) + 5 + 64;
  if ((PublicModulusSize < Sz) or (PrivateExponentSize < Sz) or (PublicExponentSize < 4) or
    (PrivateKeyBlobSize < EstimatedBlobSize)) then
  begin
    PublicModulusSize := Sz;
    PrivateExponentSize := Sz;
    PublicExponentSize := Sz;
    PrivateKeyBlobSize := EstimatedBlobSize;
    Result := false;
    Exit;
  end;
  try
    IntExternalGenerate(Bits, RSAM, RSAE, RSAD, RSAP, RSAQ, RSADP, RSADQ, RSAU);
    try
      PublicModulusSize := Length(RSAM);
      Move(RSAM[0], PublicModulus^, PublicModulusSize);
      PublicExponentSize := Length(RSAE);
      Move(RSAE[0], PublicExponent^, PublicExponentSize);
      PrivateExponentSize := Length(RSAD);
      Move(RSAD[0], PrivateExponent^, PrivateExponentSize);
      Result := EncodePrivateKey(
         @RSAM[0], Length(RSAM) ,
         @RSAE[0], Length(RSAE) ,
         @RSAD[0], Length(RSAD) ,
         @RSAP[0], Length(RSAP) ,
         @RSAQ[0], Length(RSAQ) ,
         @RSADP[0], Length(RSADP) ,
         @RSADQ[0], Length(RSADQ) ,
         @RSAU[0], Length(RSAU) ,
        PrivateKeyBlob, PrivateKeyBlobSize);
    finally
      ReleaseArrays(RSAM, RSAE, RSAD, RSAP, RSAQ, RSADP, RSADQ, RSAU);
    end;
  except
    Result := false;
  end;
end;

function Sign(Hash : pointer; HashSize : integer; PublicModulus : pointer;
  PublicModulusSize : integer; PrivateExponent : pointer; PrivateExponentSize :
  integer; Signature : pointer; var SignatureSize : integer; AntiTimingParams : TElRSAAntiTimingParams) : boolean;
var
  TmpBuf : ByteArray;
  X, D, M, Y, VF, VI, Tmp : PLInt;
  I : integer;
  RealModulusSize : integer;
begin

  if SignatureSize < PublicModulusSize then
  begin
    SignatureSize := PublicModulusSize;
    Result := false;
    Exit;
  end;

  I := 0;
  while (PByteArray(PublicModulus)[I] = 0) and (I < PublicModulusSize) do
    Inc(I);
  RealModulusSize := PublicModulusSize - I;

  if HashSize > RealModulusSize - 11 then
  begin
    SignatureSize := 0;
    Result := false;
    Exit;
  end;

  SetLength(TmpBuf, RealModulusSize);
  SBMove(Hash^, TmpBuf[RealModulusSize - HashSize], HashSize);
  TmpBuf[0] := 0;
  TmpBuf[1] := 1;
  for I := 2 to RealModulusSize - HashSize - 2 do
    TmpBuf[I] := $FF;
  TmpBuf[RealModulusSize - HashSize - 1] := 0;
  LCreate(X);
  LCreate(Y);
  LCreate(D);
  LCreate(M);
  LCreate(VF);
  LCreate(VI);
  LCreate(Tmp);
  try
    PointerToLInt(X, @TmpBuf[0], Length(TmpBuf));
    PointerToLInt(D, PrivateExponent , PrivateExponentSize );
    PointerToLInt(M, PublicModulus , PublicModulusSize );
    if AntiTimingParams <> nil then
      AntiTimingParams.GetNextBlindingPair(VI, VF);
    // blinding the source
    LMult(X, VI, Tmp);
    LModEx(Tmp, M, X);
    // modular exponentiation
    LMModPower(X, D, M, Y);
    // unblinding the result
    LMult(Y, VF, Tmp);
    LModEx(Tmp,M, Y);
    LIntToPointer(Y, Signature, SignatureSize);
  finally
    LDestroy(X);
    LDestroy(Y);
    LDestroy(D);
    LDestroy(M);
    LDestroy(VF);
    LDestroy(VI);
    LDestroy(Tmp);
  end;
  Result := true;
end;

function Encrypt(InBuffer : pointer; InSize : integer; PublicModulus : pointer;
  PublicModulusSize : integer; PublicExponent : pointer; PublicExponentSize :
  integer; OutBuffer : pointer; var OutSize : integer) : boolean;
var
  X, E, M, Y : PLInt;
  Buf : array of byte;
  I : integer;
  RealModulusSize : integer;
begin
  RealModulusSize := PublicModulusSize;
  I := 0;
  while (RealModulusSize > 0) and
    (PByteArray(PublicModulus)[I] = 0)
  do
  begin
    Dec(RealModulusSize);
    Inc(I);
  end;

  if InSize > RealModulusSize - 11 then
  begin
    OutSize := 0;
    Result := false;
    Exit;
  end;

  if OutSize < PublicModulusSize then
  begin
    OutSize := PublicModulusSize;
    Result := false;
    Exit;
  end;
  SetLength(Buf, RealModulusSize);
  Buf[0] := 0;
  Buf[1] := 2;
  for I := 2 to Length(Buf) - InSize - 2 do
    {$ifdef EDI_BLACKBOX_UNIT_TEST}
    Buf[I] := ((I - 2) mod 255) + 1;
     {$else}
    Buf[I] := SBRndGenerate(255) + 1;
     {$endif}
  Buf[Length(Buf) - InSize - 1] := 0;
  SBMove(InBuffer^, Buf[Length(Buf) - InSize], InSize);
  LCreate(X);
  LCreate(E);
  LCreate(M);
  LCreate(Y);
  PointerToLInt(X, @Buf[0], Length(Buf));
  PointerToLInt(E, PublicExponent , PublicExponentSize );
  PointerToLInt(M, PublicModulus , PublicModulusSize );
  LMModPower(X, E, M, Y);
  LIntToPointerTrunc(Y, OutBuffer, OutSize);
  LDestroy(X);
  LDestroy(E);
  LDestroy(M);
  LDestroy(Y);
  Result := true;
end;

function Encrypt(InBuffer : pointer; InSize : integer; OutBuffer: pointer;
  var OutSize : integer; PublicModulus : PLInt; PublicExponent : PLInt) : boolean;
var
  Buf : array of byte;
  I, Len : integer;
  X, R : PLInt;
begin
  Result := false;
  { Checking for enough output size }
  if OutSize < PublicModulus.Length shl 2 then
  begin
    OutSize := PublicModulus.Length shl 2;
    Exit;
  end;
  Len := (LBitCount(PublicModulus) - 1) shr 3 + 1;
  { Check whether we may encrypt that data at all }
  if  InSize  > Len - 11 then
    Exit;

  SetLength(Buf, Len);
  Buf[0] := 0;
  Buf[1] := 2;
  for I := 2 to Length(Buf) -  InSize  - 2 do
    repeat
      Buf[I] := SBRndGenerate(256);//Random(255);
    until Buf[I] <> 0;
  Buf[Length(Buf) -  InSize  - 1] := 0;
  SBMove(InBuffer^, Buf[Length(Buf) - InSize], InSize);
  LCreate(X);
  LCreate(R);
  PointerToLInt(X, @Buf[0], Length(Buf));
  LMModPower(X, PublicExponent, PublicModulus, R);
  LDestroy(X);
  if R.Length shl 2 > OutSize then
  begin
    LDestroy(R);
    Exit;
  end;
  LIntToPointer(R, OutBuffer, OutSize);
  LDestroy(R);
  Result := true;
end;
 {$endif SB_PGPSFX_STUB}

function Decrypt(InBuffer : pointer; InSize : integer; PublicModulus : pointer;
  PublicModulusSize : integer; PrivateExponent : pointer; PrivateExponentSize :
  integer; OutBuffer : pointer; var OutSize : integer; AntiTimingParams : TElRSAAntiTimingParams) : boolean;
var
  X, D, M, Y, VI, VF, Tmp : PLInt;
  Buf : array of byte;
  I, K : integer;
begin
  Result := false;
  if OutSize < PublicModulusSize then
  begin
    OutSize := PublicModulusSize;
    Exit;
  end;
  LCreate(X);
  LCreate(D);
  LCreate(M);
  LCreate(Y);
  LCreate(VI);
  LCreate(VF);
  LCreate(Tmp);
  try
    PointerToLInt(X, InBuffer , InSize );
    PointerToLInt(D, PrivateExponent , PrivateExponentSize );
    PointerToLInt(M, PublicModulus , PublicModulusSize );
    if AntiTimingParams <> nil then
      AntiTimingParams.GetNextBlindingPair(VI, VF);
    // blinding the source
    LMult(X, VI, Tmp);
    LModEx(Tmp, M, X);
    // performing modular exponentiation
    LMModPower(X, D, M, Y);
    // unblinding the result
    LMult(Y, VF, Tmp);
    LModEx(Tmp, M, Y);
    I := Y.Length shl 2;
    SetLength(Buf, I);
    LIntToPointer(Y, @Buf[0], I);
  finally
    LDestroy(X);
    LDestroy(D);
    LDestroy(M);
    LDestroy(Y);
    LDestroy(VI);
    LDestroy(VF);
    LDestroy(Tmp);
  end;
  SetLength(Buf, I);
  if I < 2 then
  begin
    Exit;
  end;

  // correcting public modulus size (removing leading zeros)
  K := 0;
  while (K < PublicModulusSize) and (PByteArray(PublicModulus)[K] = 0) do
    Inc(K);
  Dec(PublicModulusSize, K);
  if (I > PublicModulusSize) then
  begin
    // LIntToPointer returns value with length divisible by 4
    // Therefore it may contain prefix zeros if PublicModulusSize is
    // not divisible by 4
    SBMove(Buf[I - PublicModulusSize], Buf[0], PublicModulusSize);
    SetLength(Buf, PublicModulusSize);
  end;
  if (I < PublicModulusSize) then
  begin
    SetLength(Buf, PublicModulusSize);
    SBMove(Buf[0], Buf[PublicModulusSize - I], I);
    FillChar(Buf[0], PublicModulusSize - I, 0);
  end;

  if (Buf[0] = $60) and (Buf[Length(Buf) - 1] = $BC) then
  begin
    // ISO 9796 padding: [$60] [0 0 0 ... 0 0] [1] [8 random bytes] [ hash ] [$BC]
    I := 1;
    while (I < Length(Buf)) and (Buf[I] = 0) do
      Inc(I);
      
    if Length(Buf) - I < 10 then
      Exit;

    Inc(I, 9);

    SBMove(Buf[I], OutBuffer^, Length(Buf) - I - 1);
    OutSize := Length(Buf) - I - 1;
    Result := true;
    Exit;
  end;

  if (Buf[0] <> 0) or ((Buf[1] <> 2) and (Buf[1] <> 1)) then
  begin
    Exit;
  end;
  I := 2;
  while (I < Length(Buf)) and (Buf[I] <> 0) do
    Inc(I);
  SBMove(Buf[I + 1], OutBuffer^, Length(Buf) - I - 1);
  OutSize := Length(Buf) - I - 1;
  Result := true;
end;

function DecodePrivateKey(Buffer : pointer; Size : integer; PublicModulus :
  pointer; var PublicModulusSize : integer; PublicExponent : pointer; var
  PublicExponentSize : integer; PrivateExponent : pointer; var PrivateExponentSize :
  integer) : boolean;
var
  EncodedKey : TElASN1ConstrainedTag;
  CTag : TElASN1ConstrainedTag;
  I : integer;
  TV : ByteArray;
begin
  Result := false;

  EncodedKey := TElASN1ConstrainedTag.CreateInstance;
  try
    if not EncodedKey.LoadFromBuffer(Buffer , Size ) then
      Exit;
    if (EncodedKey.Count < 1) or (EncodedKey.GetField(0).TagId <> SB_ASN1_SEQUENCE) or
      (not EncodedKey.GetField(0).IsConstrained) then
      Exit;

    CTag := TElASN1ConstrainedTag(EncodedKey.GetField(0));
    if (CTag.Count < 4) or (CTag.Count > 9) then
      Exit;

    for I := 0 to CTag.Count - 1 do
      if (CTag.GetField(I).TagId <> SB_ASN1_INTEGER) or
        (CTag.GetField(I).IsConstrained) then
        Exit;
     
    TV := TElASN1SimpleTag(CTag.GetField(0)).Content;
    if (Length(TV) <> 1) or (TV[0] <> byte(0)) then
      Exit;
    
    if (PublicModulusSize < Length(TElASN1SimpleTag(CTag.GetField(1)).Content)) or
      (PublicExponentSize < Length(TElASN1SimpleTag(CTag.GetField(2)).Content)) or
      (PrivateExponentSize < Length(TElASN1SimpleTag(CTag.GetField(3)).Content)) then
      Result := false
    else
      Result := true;
    PublicModulusSize := Length(TElASN1SimpleTag(CTag.GetField(1)).Content);
    PublicExponentSize := Length(TElASN1SimpleTag(CTag.GetField(2)).Content);
    PrivateExponentSize := Length(TElASN1SimpleTag(CTag.GetField(3)).Content);
    if Result then
    begin
      SBMove(TElASN1SimpleTag(CTag.GetField(1)).Content[0], PublicModulus^,
        PublicModulusSize);
      SBMove(TElASN1SimpleTag(CTag.GetField(2)).Content[0], PublicExponent^,
        PublicExponentSize);
      SBMove(TElASN1SimpleTag(CTag.GetField(3)).Content[0], PrivateExponent^,
        PrivateExponentSize);
    end;
  finally
    FreeAndNil(EncodedKey);
  end;
end;

function DecodePrivateKey(Buffer : pointer; Size : integer; PublicModulus :
  pointer; var PublicModulusSize : integer; PublicExponent : pointer; var
  PublicExponentSize : integer; PrivateExponent : pointer; var PrivateExponentSize :
  integer; P : pointer; var PSize : integer; Q : pointer; var QSize : integer;
  E1 : pointer; var E1Size : integer; E2 : pointer; var E2Size : integer;
  U : pointer; var USize : integer) : boolean;
var
  EncodedKey : TElASN1ConstrainedTag;
  CTag : TElASN1ConstrainedTag;
  I : integer;
  TV : ByteArray;
begin
  Result := false;

  EncodedKey := TElASN1ConstrainedTag.CreateInstance;
  try
    if not EncodedKey.LoadFromBuffer(Buffer , Size ) then
      Exit;
    if (EncodedKey.Count < 1) or (EncodedKey.GetField(0).TagId <> SB_ASN1_SEQUENCE) or
      (not EncodedKey.GetField(0).IsConstrained) then
      Exit;
    
    CTag := TElASN1ConstrainedTag(EncodedKey.GetField(0));
    if CTag.Count <> 9 then
      Exit;
    
    for I := 0 to 8 do
      if (CTag.GetField(I).TagId <> SB_ASN1_INTEGER) or
        (CTag.GetField(I).IsConstrained) then
        Exit;

    TV := TElASN1SimpleTag(CTag.GetField(0)).Content;
    if (Length(TV) <> 1) or (TV[0] <> byte(0)) then
      Exit;

    if (PublicModulusSize < Length(TElASN1SimpleTag(CTag.GetField(1)).Content)) or
      (PublicExponentSize < Length(TElASN1SimpleTag(CTag.GetField(2)).Content)) or
      (PrivateExponentSize < Length(TElASN1SimpleTag(CTag.GetField(3)).Content)) or
      (PSize < Length(TElASN1SimpleTag(CTag.GetField(4)).Content)) or
      (QSize < Length(TElASN1SimpleTag(CTag.GetField(5)).Content)) or
      (E1Size < Length(TElASN1SimpleTag(CTag.GetField(6)).Content)) or
      (E2Size < Length(TElASN1SimpleTag(CTag.GetField(7)).Content)) or
      (USize < Length(TElASN1SimpleTag(CTag.GetField(8)).Content)) then
      Result := false
    else
      Result := true;
    PublicModulusSize := Length(TElASN1SimpleTag(CTag.GetField(1)).Content);
    PublicExponentSize := Length(TElASN1SimpleTag(CTag.GetField(2)).Content);
    PrivateExponentSize := Length(TElASN1SimpleTag(CTag.GetField(3)).Content);
    PSize := Length(TElASN1SimpleTag(CTag.GetField(4)).Content);
    QSize := Length(TElASN1SimpleTag(CTag.GetField(5)).Content);
    E1Size := Length(TElASN1SimpleTag(CTag.GetField(6)).Content);
    E2Size := Length(TElASN1SimpleTag(CTag.GetField(7)).Content);
    USize := Length(TElASN1SimpleTag(CTag.GetField(8)).Content);
    if Result then
    begin
      SBMove(TElASN1SimpleTag(CTag.GetField(1)).Content[0], PublicModulus^,
        PublicModulusSize);
      SBMove(TElASN1SimpleTag(CTag.GetField(2)).Content[0], PublicExponent^,
        PublicExponentSize);
      SBMove(TElASN1SimpleTag(CTag.GetField(3)).Content[0], PrivateExponent^,
        PrivateExponentSize);
      SBMove(TElASN1SimpleTag(CTag.GetField(4)).Content[0], P^, PSize);
      SBMove(TElASN1SimpleTag(CTag.GetField(5)).Content[0], Q^, QSize);
      SBMove(TElASN1SimpleTag(CTag.GetField(6)).Content[0], E1^, E1Size);
      SBMove(TElASN1SimpleTag(CTag.GetField(7)).Content[0], E2^, E2Size);
      SBMove(TElASN1SimpleTag(CTag.GetField(8)).Content[0], U^, USize);
    end;
  finally
    FreeAndNil(EncodedKey);
  end;
end;

function EncodePrivateKey(PublicModulus : pointer; PublicModulusSize : integer;
  PublicExponent : pointer; PublicExponentSize : integer; PrivateExponent :
  pointer; PrivateExponentSize : integer; Prime1 : pointer; Prime1Size : integer;
  Prime2 : pointer; Prime2Size : integer; Exponent1 : pointer; Exponent1Size :
  integer; Exponent2 : pointer; Exponent2Size : integer; Coef : pointer;
  CoefSize : integer; OutBuffer : pointer; var OutSize : integer) : boolean;
var
  Tag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  TmpBuf : ByteArray;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  Tag.TagId := SB_ASN1_SEQUENCE;
  { version }
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;
  TmpBuf := GetByteArrayFromByte(0);
  STag.Content := TmpBuf;
  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  ReleaseArray(TmpBuf);
   {$endif}
  try
    { modulus }
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    asymWriteInteger(STag, PublicModulus , PublicModulusSize );
    { PublicExponent }
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    asymWriteInteger(STag, PublicExponent , PublicExponentSize );
    { PrivateExponent }
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    asymWriteInteger(STag, PrivateExponent , PrivateExponentSize );
    { Prime1 }
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    asymWriteInteger(STag, Prime1 , Prime1Size );
    { Prime2 }
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    asymWriteInteger(STag, Prime2 , Prime2Size );
    { Exponent1 }
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    asymWriteInteger(STag, Exponent1 , Exponent1Size );
    { Exponent2 }
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    asymWriteInteger(STag, Exponent2 , Exponent2Size );
    { Coef }
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    asymWriteInteger(STag, Coef , CoefSize );
    Result := Tag.SaveToBuffer(OutBuffer, OutSize);
  finally
    FreeAndNil(Tag);
  end;
end;

function EncodePrivateKey(PublicModulus : pointer; PublicModulusSize : integer;
  PublicExponent : pointer; PublicExponentSize : integer; PrivateExponent :
  pointer; PrivateExponentSize : integer; OutBuffer : pointer; var OutSize : integer) : boolean; overload;
var
  Tag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  TmpBuf : ByteArray;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  Tag.TagId := SB_ASN1_SEQUENCE;
  { version }
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;
  TmpBuf := GetByteArrayFromByte(0);
  STag.Content := TmpBuf;
  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  ReleaseArray(TmpBuf);
   {$endif}
  try
    { modulus }
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    asymWriteInteger(STag, PublicModulus , PublicModulusSize );
    { PublicExponent }
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    asymWriteInteger(STag, PublicExponent , PublicExponentSize );
    { PrivateExponent }
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    asymWriteInteger(STag, PrivateExponent , PrivateExponentSize );
    Result := Tag.SaveToBuffer(OutBuffer, OutSize);
  finally
    FreeAndNil(Tag);
  end;
end;

function Decrypt(InBuffer : pointer; InSize : integer; PrivateKeyBlob: pointer;
  PrivateKeyBlobSize : integer; OutBuffer: pointer; var OutSize : integer;
  AntiTimingParams : TElRSAAntiTimingParams) : boolean;
var
  CTag, Tag: TElASN1ConstrainedTag;
  I : integer;
  M, D, P, Q, dP, dQ, qInv, M1, M2, Enc, Dec, Tmp, VI, VF : PLInt;
  Buf : array of byte;
  ModVal : ByteArray;
  PublicModulusSize: integer;
begin
  Result := false;
  I := 0;
  
  LCreate(M);
  LCreate(D);
  LCreate(P);
  LCreate(Q);
  LCreate(dP);
  LCreate(dQ);
  LCreate(qInv);
  LCreate(M1);
  LCreate(M2);
  LCreate(Enc);
  LCreate(Dec);
  LCreate(Tmp);
  LCreate(VI);
  LCreate(VF);
  try
    Tag := TElASN1ConstrainedTag.CreateInstance;
    try
      if not Tag.LoadFromBuffer(PrivateKeyBlob, PrivateKeyBlobSize) then
        Exit;

      if (not Tag.GetField(0).IsConstrained) or (Tag.Count <> 1) then
        Exit;

      CTag := TElASN1ConstrainedTag(Tag.GetField(0));
      if CTag.Count <> 9 then
        Exit;

      for I := 0 to 8 do
        if (CTag.GetField(I).IsConstrained) or (CTag.GetField(I).TagId <> SB_ASN1_INTEGER) then
          Exit;

      if OutSize < Length(TElASN1SimpleTag(CTag.GetField(1)).Content) then
      begin
        OutSize := Length(TElASN1SimpleTag(CTag.GetField(1)).Content);
        Exit;
      end;

      PointerToLInt(M, @TElASN1SimpleTag(CTag.GetField(1)).Content[0],
        Length(TElASN1SimpleTag(CTag.GetField(1)).Content));
      ModVal := TElASN1SimpleTag(CTag.GetField(1)).Content;
      PointerToLInt(D, @TElASN1SimpleTag(CTag.GetField(3)).Content[0],
        Length(TElASN1SimpleTag(CTag.GetField(3)).Content));
      PointerToLInt(P, @TElASN1SimpleTag(CTag.GetField(4)).Content[0],
        Length(TElASN1SimpleTag(CTag.GetField(4)).Content));
      PointerToLInt(Q, @TElASN1SimpleTag(CTag.GetField(5)).Content[0],
        Length(TElASN1SimpleTag(CTag.GetField(5)).Content));
      PointerToLInt(dP, @TElASN1SimpleTag(CTag.GetField(6)).Content[0],
        Length(TElASN1SimpleTag(CTag.GetField(6)).Content));
      PointerToLInt(dQ, @TElASN1SimpleTag(CTag.GetField(7)).Content[0],
        Length(TElASN1SimpleTag(CTag.GetField(7)).Content));
      PointerToLInt(qInv, @TElASN1SimpleTag(CTag.GetField(8)).Content[0],
        Length(TElASN1SimpleTag(CTag.GetField(8)).Content));
      PointerToLInt(Enc, InBuffer, InSize);
    finally
      FreeAndNil(Tag);
    end;

    if AntiTimingParams <> nil then
      AntiTimingParams.GetNextBlindingPair(VI, VF);

    // blinding the source
    LMult(Enc, VI, Tmp);
    LModEx(Tmp, M, Enc);

    // performing RSA computation
    LMModPower(Enc, dP, P, M1);
    LMModPower(Enc, dQ, Q, M2);
    if LGreater(M1, M2) then
      LSub(M1, M2, Tmp)
    else
    begin
      LSub(M2, M1, Dec);
      if LGreater(P, Dec) then
        LSub(P, Dec, Tmp)
      else
      begin
        LModEx(Dec, P, Tmp);
        LSub(P, Tmp, Dec);
        LCopy(Tmp, Dec);
      end;
    end;
    LMult(Tmp, qInv, Dec);
    LModEx(Dec, P, Tmp);
    LMult(Tmp, Q, dQ);
    LAdd(M2, dQ, Dec);

    // unblinding the result
    LMult(Dec, VF, Tmp);
    LModEx(Tmp, M, Dec);

    I := Dec.Length shl 2;
    SetLength(Buf, I);
     LIntToPointerP (Dec, Buf, I);
  finally
    LDestroy(M);
    LDestroy(D);
    LDestroy(P);
    LDestroy(Q);
    LDestroy(dP);
    LDestroy(dQ);
    LDestroy(qInv);
    LDestroy(M1);
    LDestroy(M2);
    LDestroy(Enc);
    LDestroy(Dec);
    LDestroy(Tmp);
    LDestroy(VI);
    LDestroy(VF);
  end;

  SetLength(Buf, I);

  PublicModulusSize := Length(ModVal);
  if (I > PublicModulusSize) then
  begin
    // LIntToPointer returns value with length divisible by 4
    // Therefore it may contain prefix zeros if PublicModulusSize is
    // not divisible by 4
    SBMove(Buf[I - PublicModulusSize], Buf[0], PublicModulusSize);
    SetLength(Buf, PublicModulusSize);
  end;
  
  if (Buf[0] <> 0) or ((Buf[1] <> 2) and (Buf[1] <> 1)) then
  begin
    Result := false;
    Exit;
  end;
  I := 2;
  while (I < Length(Buf)) and (Buf[I] <> 0) do
    Inc(I);
  SBMove(Buf[I + 1], OutBuffer^, Length(Buf) - I - 1);
  OutSize := Length(Buf) - I - 1;
  Result := true;
end;

function Sign(Hash : pointer; HashSize : integer; PrivateKeyBlob: pointer;
  PrivateKeyBlobSize : integer; Signature: pointer; var SignatureSize : integer;
  AntiTimingParams : TElRSAAntiTimingParams) : boolean;
var
  CTag, Tag: TElASN1ConstrainedTag;
  I, SigSize : integer;
  M, D, P, Q, dP, dQ, qInv, M1, M2, Enc, Dec, Tmp, VF, VI : PLInt;
  Buf: ByteArray;
  Delta, ModLen : integer;
begin
  Result := false;

  LCreate(M);
  LCreate(D);
  LCreate(P);
  LCreate(Q);
  LCreate(dP);
  LCreate(dQ);
  LCreate(qInv);
  LCreate(M1);
  LCreate(M2);
  LCreate(Enc);
  LCreate(Dec);
  LCreate(Tmp);
  LCreate(VI);
  LCreate(VF);
  try
    Tag := TElASN1ConstrainedTag.CreateInstance;
    try
      if not Tag.LoadFromBuffer(PrivateKeyBlob, PrivateKeyBlobSize) then
        Exit;

      if (not Tag.GetField(0).IsConstrained) or (Tag.Count <> 1) then
        Exit;

      CTag := TElASN1ConstrainedTag(Tag.GetField(0));
      if CTag.Count <> 9 then
        Exit;

      for I := 0 to 8 do
        if (CTag.GetField(I).IsConstrained) or (CTag.GetField(I).TagId <> SB_ASN1_INTEGER) then
          Exit;

      { trimming M parameter since it can contain leading zero, which will cause invalid signature size }    
      Buf := TElASN1SimpleTag(CTag.GetField(1)).Content;
      I := 0;
      while (I < Length(Buf)) and (Buf[I] = 0) do
        Inc(I);
      Buf := Copy(Buf, I, Length(Buf) - I);  

      if SignatureSize < Length(Buf) then
      begin
        SignatureSize := Length(Buf);
        Exit;
      end
      else
        SigSize := Length(Buf);

      if HashSize > Length(TElASN1SimpleTag(CTag.GetField(1)).Content) - 11 then
      begin
        SignatureSize := 0;
        Result := false;
        Exit;
      end;

      PointerToLInt(M, @Buf[0], Length(Buf));
      PointerToLInt(D, @TElASN1SimpleTag(CTag.GetField(3)).Content[0],
        Length(TElASN1SimpleTag(CTag.GetField(3)).Content));
      PointerToLInt(P, @TElASN1SimpleTag(CTag.GetField(4)).Content[0],
        Length(TElASN1SimpleTag(CTag.GetField(4)).Content));
      PointerToLInt(Q, @TElASN1SimpleTag(CTag.GetField(5)).Content[0],
        Length(TElASN1SimpleTag(CTag.GetField(5)).Content));
      PointerToLInt(dP, @TElASN1SimpleTag(CTag.GetField(6)).Content[0],
        Length(TElASN1SimpleTag(CTag.GetField(6)).Content));
      PointerToLInt(dQ, @TElASN1SimpleTag(CTag.GetField(7)).Content[0],
        Length(TElASN1SimpleTag(CTag.GetField(7)).Content));
      PointerToLInt(qInv, @TElASN1SimpleTag(CTag.GetField(8)).Content[0],
        Length(TElASN1SimpleTag(CTag.GetField(8)).Content));
      Delta := 0;
      ModLen := Length(TElASN1SimpleTag(CTag.GetField(1)).Content);
      while (TElASN1SimpleTag(CTag.GetField(1)).Content[Delta + 0] = byte(0)) and (Delta < ModLen + 0) do
        Inc(Delta);
      SetLength(Buf, Length(TElASN1SimpleTag(CTag.GetField(1)).Content) - Delta);
      Buf[0] := 0;
      Buf[1] := 1;
      for I := 2 to Length(Buf) - HashSize - 2 do
        Buf[I] := 255;
      Buf[Length(Buf) - HashSize - 1] := 0;
      SBMove(Hash^, Buf[Length(Buf) - HashSize], HashSize);
      PointerToLInt(Enc, @Buf[0], Length(Buf));

    finally
      FreeAndNil(Tag);
    end;

    // blinding the source
    if AntiTimingParams <> nil then
      AntiTimingParams.GetNextBlindingPair(VI, VF);
    LMult(Enc, VI, Tmp);
    LModEx(Tmp, M, Enc);

    // performing RSA computation
    LMModPower(Enc, dP, P, M1);
    LMModPower(Enc, dQ, Q, M2);
    if LGreater(M1, M2) then
      LSub(M1, M2, Tmp)
    else
    begin
      LSub(M2, M1, Dec);
      if LGreater(P, Dec) then
        LSub(P, Dec, Tmp)
      else
      begin
        LModEx(Dec, P, Tmp);
        LSub(P, Tmp, Dec);
        LCopy(Tmp, Dec);
      end;
    end;
    LMult(Tmp, qInv, Dec);
    LModEx(Dec, P, Tmp);
    LMult(Tmp, Q, dQ);
    LAdd(M2, dQ, Dec);

    // unblinding the result
    LMult(Dec, VF, Tmp);
    LModEx(Tmp, M, Dec);

    if (SigSize and 3) = 0 then
      LIntToPointer(Dec, Signature, SignatureSize)
    else
    begin
      // For keys with bogus size
      I := Dec.Length shl 2;
      SetLength(Buf, I);
      LIntToPointer(Dec, Buf, I);
      SignatureSize := SigSize;
      SBMove(Buf[I - SignatureSize], Signature^, SignatureSize);
      SetLength(Buf, 0);
    end;

  finally
    LDestroy(M);
    LDestroy(D);
    LDestroy(P);
    LDestroy(Q);
    LDestroy(dP);
    LDestroy(dQ);
    LDestroy(qInv);
    LDestroy(M1);
    LDestroy(M2);
    LDestroy(Enc);
    LDestroy(Dec);
    LDestroy(Tmp);
    LDestroy(VI);
    LDestroy(VF);
  end;

  Result := true;
end;

function IsValidKey(Blob: pointer; BlobSize: integer) : boolean;
var
  M, E, D, P, Q, E1, E2, U : ByteArray;
  MSize, ESize, DSize, PSize, QSize, E1Size, E2Size, USize : integer;
  LE, LD, LP, LQ, LM, LTmp : PLInt;
begin
  Result := false;
  MSize := 0;
  ESize := 0;
  DSize := 0;
  PSize := 0;
  QSize := 0;
  E1Size := 0;
  E2Size := 0;
  USize := 0;
  DecodePrivateKey(Blob, BlobSize, nil, MSize, nil, ESize, nil, DSize,
    nil, PSize, nil, QSize, nil, E1Size, nil, E2Size, nil, USize);

  if (MSize <= 0) or (ESize <= 0) or (DSize <= 0) or (PSize <= 0) or (QSize <= 0) {or
     (E1Size <= 0) or (E2Size <= 0) or (USize <= 0)} then
    Exit;

  SetLength(M, MSize);
  SetLength(E, ESize);
  SetLength(D, DSize);
  SetLength(P, PSize);
  SetLength(Q, QSize);
  SetLength(E1, E1Size);
  SetLength(E2, E2Size);
  SetLength(U, USize);

  if not DecodePrivateKey(Blob,  BlobSize,  M, MSize, E, ESize, D, DSize,
    P, PSize, Q, QSize, E1, E1Size, E2, E2Size, U, USize) then
    Exit;

  LCreate(LD);
  LCreate(LE);
  LCreate(LP);
  LCreate(LQ);
  LCreate(LM);
  LCreate(LTmp);
  try
    PointerToLInt(LP, P , PSize );
    PointerToLInt(LQ, Q , QSize );
    // P and Q must be primes
    if (not LIsPrime(LP)) then
      Exit;
    if (not (LIsPrime(LQ))) then
      Exit;

    // P * Q == M
    PointerToLInt(LM, M , MSize );
    LMult(LP, LQ, LTmp);
    if not LEqual(LTmp, LM) then
      Exit;

    PointerToLInt(LD, D , DSize );
    PointerToLInt(LE, E , ESize );
      
    // D * E = 1 mod ((p-1)(q-1))
    LDec(LP);
    LDec(LQ);
    LMult(LP, LQ, LTmp);

    LMult(LD, LE, LM);
    LMod(LM, LTmp, LP);
    LDec(LP);
    Result := LNull(LP);
  finally
    LDestroy(LD);
    LDestroy(LE);
    LDestroy(LP);
    LDestroy(LQ);
    LDestroy(LM);
    LDestroy(LTmp);
  end;
end;

function MGF1(InBuffer: pointer; InSize : integer; Needed: integer; HashAlg : integer) : ByteArray;
var
  hLen : integer;
  I, OldLen : integer;
  //Cnt : array[0..3] of byte;
  HashInput : ByteArray;
  Hash : ByteArray;
  HashFunction :  TElHashFunction ;
begin
  SetLength(Result, 0);
  SetLength(Hash, 0);
  hLen :=  TElHashFunction .GetDigestSizeBits(HashAlg);
  if (hLen = -1) or (Needed = 0) then
    Exit;

  hLen := hLen shr 3;
  SetLength(HashInput,  InSize  + 4);

  SBMove(InBuffer^, HashInput[0], InSize);
  I := 0;

  HashFunction :=  TElHashFunction .Create(HashAlg);
  while Length(Result) < Needed do
  begin
    
    GetBytes32(I, HashInput,  InSize );

    HashFunction.Reset;
    HashFunction.Update(@HashInput[0], InSize + 4);
    Hash := HashFunction.Finish;

    OldLen := Length(Result);
    SetLength(Result, OldLen + hLen);
    SBMove(Hash[0], Result[OldLen], hLen);
    Inc(I);
    ReleaseArray(Hash);
  end;
  FreeAndNil(HashFunction);
  SetLength(Result, Needed);
end;

function PerformExponentiation(Modulus: pointer; ModulusSize: integer;
  Exponent: pointer; ExponentSize: integer; InBuffer: pointer; InSize: integer;
  OutBuffer: pointer; var OutSize : integer; AntiTimingParams : TElRSAAntiTimingParams): boolean;
var
  X, E, N, R, VI, VF, Tmp : PLInt;
begin
  if OutSize < ModulusSize then
  begin
    OutSize := ModulusSize;
    Result := false;
    Exit;
  end;
  LCreate(X);
  LCreate(E);
  LCreate(N);
  LCreate(R);
  LCreate(VI);
  LCreate(VF);
  LCreate(Tmp);
  try
    PointerToLInt(X, InBuffer, InSize);
    PointerToLInt(E, Exponent, ExponentSize);
    PointerToLInt(N, Modulus, ModulusSize);
    if AntiTimingParams <> nil then
      AntiTimingParams.GetNextBlindingPair(VI, VF);
    // blinding the source
    LMult(X, VI, Tmp);
    LModEx(Tmp, N, X);
    // performing RSA computation
    LMModPower(X, E, N, R);
    // unblinding the result
    LMult(R, VF, Tmp);
    LModEx(Tmp, N, R);
    LIntToPointer(R, OutBuffer, OutSize);
  finally
    LDestroy(X);
    LDestroy(E);
    LDestroy(N);
    LDestroy(R);
    LDestroy(VI);
    LDestroy(VF);
    LDestroy(Tmp);
  end;
  Result := true;
end;

function PerformExponentiation(Blob : pointer; BlobSize : integer;
  InBuffer: pointer; InSize: integer;
  OutBuffer: pointer; var OutSize : integer; AntiTimingParams : TElRSAAntiTimingParams): boolean;
var
  M, E, D, P, Q, E1, E2, U : ByteArray;
  MSize, ESize, DSize, PSize, QSize, E1Size, E2Size, USize : integer;
  LM, LD, LP, LQ, LdP, LdQ, LqInv, LM1, LM2, LEnc, LDec, LTmp, VI, VF : PLInt;
  I : integer;
  Buf : array of byte;
  ModVal : ByteArray;
  PublicModulusSize: integer;
begin
  Result := false;
  MSize := 0;
  ESize := 0;
  DSize := 0;
  PSize := 0;
  QSize := 0;
  E1Size := 0;
  E2Size := 0;
  USize := 0;
  DecodePrivateKey(Blob, BlobSize, nil, MSize, nil, ESize, nil, DSize, nil,
    PSize, nil, QSize, nil, E1Size, nil, E2Size, nil, USize);

  if (MSize <= 0) or (ESize <= 0) or (DSize <= 0) or (PSize <= 0) or (QSize <= 0) or
     (E1Size <= 0) or (E2Size <= 0) or (USize <= 0) then
    Exit;

  if OutSize < MSize then
  begin
    OutSize := MSize;
    Exit;
  end;
  SetLength(M, MSize);
  SetLength(E, ESize);
  SetLength(D, DSize);
  SetLength(P, PSize);
  SetLength(Q, QSize);
  SetLength(E1, E1Size);
  SetLength(E2, E2Size);
  SetLength(U, USize);
  if DecodePrivateKey(Blob, BlobSize, @M[0], MSize, @E[0], ESize, @D[0], DSize, @P[0],
    PSize, @Q[0], QSize, @E1[0], E1Size, @E2[0], E2Size, @U[0], USize) then
  begin
    LCreate(LM);
    LCreate(LD);
    LCreate(LP);
    LCreate(LQ);
    LCreate(LdP);
    LCreate(LdQ);
    LCreate(LqInv);
    LCreate(LM1);
    LCreate(LM2);
    LCreate(LEnc);
    LCreate(LDec);
    LCreate(LTmp);
    LCreate(VI);
    LCreate(VF);
    try
      ModVal := CloneArray(@M[0], MSize);
      PointerToLInt(LM,  @M[0] , MSize);
      PointerToLInt(LD,  @D[0] , DSize);
      PointerToLInt(LP,  @P[0] , PSize);
      PointerToLInt(LQ,  @Q[0] , QSize);
      PointerToLInt(LdP,  @E1[0] , E1Size);
      PointerToLInt(LdQ,  @E2[0] , E2Size);
      PointerToLInt(LqInv,  @U[0] , USize);
      PointerToLInt(LEnc, InBuffer, InSize);
      // blinding the source
      if AntiTimingParams <> nil then
        AntiTimingParams.GetNextBlindingPair(VI, VF);
      LMult(LEnc, VI, LTmp);
      LModEx(LTmp, LM, LEnc);
      // performing RSA computation
      LMModPower(LEnc, LdP, LP, LM1);
      LMModPower(LEnc, LdQ, LQ, LM2);
      if LGreater(LM1, LM2) then
        LSub(LM1, LM2, LTmp)
      else
      begin
        LSub(LM2, LM1, LDec);
        if LGreater(LP, LDec) then
          LSub(LP, LDec, LTmp)
        else
        begin
          LModEx(LDec, LP, LTmp);
          LSub(LP, LTmp, LDec);
          LCopy(LTmp, LDec);
        end;
      end;
      LMult(LTmp, LqInv, LDec);
      LModEx(LDec, LP, LTmp);
      LMult(LTmp, LQ, LdQ);
      LAdd(LM2, LdQ, LDec);
      // unblinding the result
      LMult(LDec, VF, LTmp);
      LModEx(LTmp, LM, LDec);
      
      I := LDec.Length * 4;
      SetLength(Buf, I);
      LIntToPointer(LDec,  @Buf[0] , I);
    finally
      LDestroy(LM);
      LDestroy(LD);
      LDestroy(LP);
      LDestroy(LQ);
      LDestroy(LdP);
      LDestroy(LdQ);
      LDestroy(LqInv);
      LDestroy(LM1);
      LDestroy(LM2);
      LDestroy(LEnc);
      LDestroy(LDec);
      LDestroy(LTmp);
      LDestroy(VI);
      LDestroy(VF);
    end;
    SetLength(Buf, I);

    PublicModulusSize := Length(ModVal);
    if (I > PublicModulusSize) then
    begin
      // LIntToPointer returns value with length divisible by 4
      // Therefore it may contain prefix zeros if PublicModulusSize is
      // not divisible by 4
      SBMove(Buf[I - PublicModulusSize], Buf[0], PublicModulusSize);
      SetLength(Buf, PublicModulusSize);
    end;
    OutSize := Min(Length(Buf), PublicModulusSize);
    SBMove(Buf[0], OutBuffer^, OutSize);
    Result := true;
  end
  else
    Result := false;
end;

function EncryptOAEP(InBuffer : pointer; InSize : integer; PublicModulus : pointer;
  PublicModulusSize : integer; PublicExponent : pointer; PublicExponentSize :
  integer; Salt : pointer; SaltSize : integer; HashAlg : integer;
  OutBuffer : pointer; var OutSize : integer) : boolean;
var
  hLen, padLen : integer;
  Hash : ByteArray;
  PS : ByteArray;
  DataBlock : ByteArray;
  Seed : ByteArray;
  DataMask, SeedMask : ByteArray;
  I : integer;
  EncSource : ByteArray;
  Ptr :  ^byte ;
  HashFunction :  TElHashFunction ;
begin
  Result := false;
  hLen := GetDigestSizeBits(HashAlg);
  if (hLen = -1) then
    Exit;
  SetLength(DataMask, 0);
  SetLength(SeedMask, 0);
  hLen := hLen shr 3;
  Ptr := PublicModulus;
  while (PublicModulusSize > 0) and ( Ptr^  = 0) do
  begin
    Inc(Ptr);
    Dec(PublicModulusSize);
  end;
  PublicModulus := Ptr;
  if InSize > PublicModulusSize - hLen shl 1 - 2 then
    Exit;
  if OutSize < PublicModulusSize then
  begin
    OutSize := PublicModulusSize;
    Exit;
  end;

  HashFunction :=  TElHashFunction .Create(HashAlg);
  HashFunction.Update(Salt, SaltSize);
  Hash := HashFunction.Finish;
  FreeAndNil(HashFunction);

  padLen := PublicModulusSize - InSize - hLen shl 1 - 2;

  SetLength(PS, padLen);
  FillChar(PS[0], padLen, 0);

  SetLength(DataBlock, hLen + padLen + InSize + 1);
  SBMove(Hash[0], DataBlock[0], hLen);
  SBMove(PS[0], DataBlock[hLen], padLen);
  DataBlock[hLen + padLen] := 1;
  SBMove(InBuffer^, DataBlock[hLen + padLen + 1], InSize);

  SetLength(Seed, hLen);

  repeat
    SBRndGenerate(@Seed[0], hLen);
    DataMask := MGF1(@Seed[0], hLen, PublicModulusSize - hLen - 1, HashAlg);
    for I := 0 to Length(DataBlock) - 1 do
      DataBlock[I] := DataBlock[I] xor DataMask[I];
    SeedMask := MGF1(@DataBlock[0], Length(DataBlock), hLen, HashAlg);
    for I := 0 to Length(Seed) - 1 do
      Seed[I] := Seed[I] xor SeedMask[I];

    if Seed[0] = 0 then // reverting data block to raw state
      for I := 0 to Length(DataBlock) - 1 do
        DataBlock[I] := DataBlock[I] xor DataMask[I];
  until Seed[0] <> 0; // avoiding first zero byte

  SetLength(EncSource, PublicModulusSize);

  EncSource[0] := 0;

  SBMove(Seed, 0, EncSource, 1, hLen);
  SBMove(DataBlock, 0, EncSource, 1 + hLen, Length(DataBlock));

  Result := PerformExponentiation(PublicModulus, PublicModulusSize, PublicExponent,
    PublicExponentSize, @EncSource[0], Length(EncSource), OutBuffer, OutSize, nil);
end;

function DecryptOAEP(InBuffer : pointer; InSize : integer; PublicModulus : pointer;
  PublicModulusSize : integer; PrivateExponent : pointer; PrivateExponentSize :
  integer; Salt: pointer; SaltSize : integer; HashAlg: integer; OutBuffer : pointer;
  var OutSize : integer; AntiTimingParams : TElRSAAntiTimingParams) : boolean;
var
  hLen : integer;
  Ptr :  ^byte ;
  DecBuffer : ByteArray;
  DecSize : integer;
  Hash : ByteArray;
  Seed : ByteArray;
  DataBlock : ByteArray;
  DataMask, SeedMask : ByteArray;
  I : integer;
  MsgHash : ByteArray;
  Size : integer;
  HashFunction :  TElHashFunction ;
begin
  Result := false;
  hLen := GetDigestSizeBits(HashAlg);
  if (hLen = -1) then
    Exit;
  hLen := hLen shr 3;
  if OutSize < PublicModulusSize - hLen shl 1 - 2 then
  begin
    OutSize := PublicModulusSize - hLen  shl 1 - 2;
    Exit;
  end;
  SetLength(DataMask, 0);
  SetLength(SeedMask, 0);
  Ptr :=  PublicModulus ;
  while (PublicModulusSize > 0) and ( Ptr^  = 0) do
  begin
    Inc(Ptr);
    Dec(PublicModulusSize);
  end;
  PublicModulus := Ptr;
  Ptr :=  InBuffer ;
  while (InSize > 0) and ( Ptr^  = 0) do
  begin
    Inc(Ptr);
    Dec(InSize);
  end;
  InBuffer := Ptr;
  if InSize > PublicModulusSize then
    Exit;

  if PublicModulusSize < hLen shl 1 + 2 then
    Exit;

  DecSize := (((PublicModulusSize - 1) shr 2) + 1) shl 2;
  SetLength(DecBuffer, DecSize);
  PerformExponentiation(PublicModulus, PublicModulusSize, PrivateExponent,
    PrivateExponentSize, InBuffer, InSize, @DecBuffer[0], DecSize, AntiTimingParams);

  Ptr :=  @DecBuffer[0] ;
  if (DecSize > 0) and ( Ptr^  = 0) then
  begin
    Inc(Ptr);
    Dec(DecSize);
  end;
  if DecSize > PublicModulusSize - 1 then
    Exit;

  HashFunction :=  TElHashFunction .Create(HashAlg);
  HashFunction.Update(Salt,  SaltSize);
  Hash := HashFunction.Finish;
  FreeAndNil(HashFunction);

  SetLength(Seed, hLen);
  SBMove(Ptr^, Seed[0], hLen);
  Inc(Ptr, hLen);

  SetLength(DataBlock, PublicModulusSize - hLen - 1);
  SBMove(Ptr^, DataBlock[0], Length(DataBlock));
  SeedMask := MGF1(@DataBlock[0], Length(DataBlock), hLen, HashAlg);
  for I := 0 to hLen - 1 do
    Seed[I] := Seed[I] xor SeedMask[I];
  DataMask := MGF1(@Seed[0], hLen, Length(DataBlock), HashAlg);
  for I := 0 to Length(DataBlock) - 1 do
    DataBlock[I] := DataBlock[I] xor DataMask[I];

  SetLength(MsgHash, hLen);
  SBMove(DataBlock[0], MsgHash[0], hLen);
  if (not CompareMem(@MsgHash[0], @Hash[0], hLen)) then
    Exit;
  Ptr := @DataBlock[hLen];
  Size := Length(DataBlock) - hLen;
  while (Size > 0) and ( Ptr^  = 0) do
  begin
    Inc(Ptr);
    Dec(Size);
  end;
  if (Size = 0) or ( Ptr^  <> 1) then
    Exit;
  Inc(Ptr);
  Dec(Size);
  OutSize := Size;
  SBMove(Ptr^, OutBuffer^, OutSize);
  Result := true;
end;

{$ifndef SB_PGPSFX_STUB}
function DecryptOAEP(InBuffer : pointer; InSize : integer; Blob : pointer;
  BlobSize : integer; Salt: pointer; SaltSize : integer; HashAlg: integer; OutBuffer : pointer;
  var OutSize : integer; AntiTimingParams : TElRSAAntiTimingParams) : boolean;
var
  hLen : integer;
  Ptr :  ^byte ;
  DecBuffer : ByteArray;
  DecSize : integer;
  Hash : ByteArray;
  Seed : ByteArray;
  DataBlock : ByteArray;
  DataMask, SeedMask : ByteArray;
  I : integer;
  MsgHash : ByteArray;
  Size : integer;
  HashFunction :  TElHashFunction ;
  PublicModulusSize, ESize, DSize : integer;
  PublicModulus, E, D : ByteArray;
begin
  Result := false;
  hLen := GetDigestSizeBits(HashAlg);
  if (hLen = -1) then
    Exit;
  SetLength(DataMask, 0);
  SetLength(SeedMask, 0);
  hLen := hLen shr 3;
  PublicModulusSize := 0;
  ESize := 0;
  DSize := 0;
  DecodePrivateKey(Blob, BlobSize, nil, PublicModulusSize, nil, ESize, nil, DSize);

  if (PublicModulusSize <= 0) or (ESize <= 0) or (DSize <= 0) then
    Exit;

  if OutSize < PublicModulusSize - hLen shl 1 - 2 then
  begin
    OutSize := PublicModulusSize - hLen shl 1 - 2;
    Exit;
  end;
  SetLength(PublicModulus, PublicModulusSize);
  SetLength(E, ESize);
  SetLength(D, DSize);
  DecodePrivateKey(Blob, BlobSize, @PublicModulus[0], PublicModulusSize, @E[0],
    ESize, @D[0], DSize);

  Ptr :=  @PublicModulus[0] ;
  while (PublicModulusSize > 0) and ( Ptr^  = 0) do
  begin
    Inc(Ptr);
    Dec(PublicModulusSize);
  end;

  if PublicModulusSize < hLen shl 1 + 2 then
    Exit;

  DecSize := (((PublicModulusSize - 1) shr 2) + 1) shl 2 + 1;
  SetLength(DecBuffer, DecSize);
  PerformExponentiation(Blob, BlobSize, InBuffer, InSize, @DecBuffer[0], DecSize,
    AntiTimingParams);
  
  // first byte of OAEP encoding should be zero
  Ptr :=  @DecBuffer[0] ;
  if (DecSize > 0) and ( Ptr^  = 0) then
  begin
    Inc(Ptr);
    Dec(DecSize);
  end;
  if DecSize > PublicModulusSize - 1 then
    Exit;

  HashFunction :=  TElHashFunction .Create(HashAlg);
  HashFunction.Update(Salt,  SaltSize);
  Hash := HashFunction.Finish;
  FreeAndNil(HashFunction);
  
  SetLength(Seed, hLen);
  SBMove(Ptr^, Seed[0], hLen);
  Inc(Ptr, hLen);

  SetLength(DataBlock, PublicModulusSize - hLen - 1);
  SBMove(Ptr^, DataBlock[0], Length(DataBlock));
  SeedMask := MGF1(@DataBlock[0], Length(DataBlock), hLen, HashAlg);
  for I := 0 to hLen - 1 do
    Seed[I] := Seed[I] xor SeedMask[I];
  DataMask := MGF1(@Seed[0], hLen, Length(DataBlock), HashAlg);
  for I := 0 to Length(DataBlock) - 1 do
    DataBlock[I] := DataBlock[I] xor DataMask[I];

  SetLength(MsgHash, hLen);
  SBMove(DataBlock[0], MsgHash[0], hLen);
  if (not CompareMem(@MsgHash[0], @Hash[0], hLen)) then
    Exit;
  Ptr := @DataBlock[hLen];
  Size := Length(DataBlock) - hLen;
  while (Size > 0) and ( Ptr^  = 0) do
  begin
    Inc(Ptr);
    Dec(Size);
  end;
  if (Size = 0) or ( Ptr^  <> 1) then
    Exit;
  Inc(Ptr);
  Dec(Size);
  OutSize := Size;
  SBMove(Ptr^, OutBuffer^, OutSize);
  Result := true;
end;
 {$endif SB_PGPSFX_STUB}

(*
{$ifdef SB_VCL}
function GetPublicKeySizeBits(PrivateKeyBlob : pointer;
  PrivateKeyBlobSize : integer) : integer; overload;
{$else}
function GetPublicKeySizeBits(const PrivateKeyBlob : ByteArray;
  PrivateKeyBlobStart, PrivateKeyBlobSize : integer) : integer;
{$endif}
var
  N, E, D : ByteArray;
  B : PLint;
  NSize, ESize, DSize : integer;
begin
  Result := 0;
  NSize := 0;
  ESize := 0;
  DSize := 0;

  {$ifdef SB_VCL}
  DecodePrivateKey(PrivateKeyBlob, PrivateKeyBlobSize, nil, NSize, nil,
    ESize, nil, DSize);
  {$else}
  DecodePrivateKey(PrivateKeyBlob, N, NSize, E, ESize, D, DSize);
  {$endif}  

  {$ifndef SB_NET}
  SetLength(N, NSize);
  SetLength(E, ESize);
  SetLength(D, DSize);
  {$else}
  N := new Byte[NSize];
  E := new Byte[ESize];
  D := new Byte[DSize];
  {$endif}

  if not DecodePrivateKey(PrivateKeyBlob, {$ifdef SB_VCL}
    PrivateKeyBlobSize,{$endif} N, NSize, E, ESize, D, DSize)
  then
    Exit;

  LCreate(B);
  PointerToLInt(B, N, NSize);
  Result := LBitCount(B);
  LDestroy(B);
end;
*)

{ PKCS#1 v2.1 RSASP1 signing primitive }
function SignRSASP1(EMessage : pointer; EMessageSize : integer;
  N : pointer; NSize : integer; E : pointer; ESize : integer; D : pointer;
  DSize : integer; Signature : pointer; var SignatureSize : integer;
  AntiTimingParams : TElRSAAntiTimingParams) : boolean;
var
  S : ByteArray;
  SSize, Index : integer;
  LN, LD, LM, LS, LVI, LVF, LTmp : PLInt;
begin
  Result := false;

  LCreate(LN);
  PointerToLInt(LN, N, NSize);
  SSize := (LBitCount(LN) + 7) shr 3;

  if SignatureSize < SSize then
  begin
    SignatureSize := SSize;
    LDestroy(LN);
    Exit;
  end;

  LCreate(LD);
  LCreate(LM);
  LCreate(LS);
  LCreate(LVI);
  LCreate(LVF);
  LCreate(LTmp);

  try
    PointerToLInt(LM, EMessage, EMessageSize);

    if LGreater(LN, LM) then
    begin
      PointerToLInt(LD, D, DSize);
      // blinding the source
      if AntiTimingParams <> nil then
        AntiTimingParams.GetNextBlindingPair(LVI, LVF);
      LMult(LM, LVI, LTmp);
      LModEx(LTmp, LN, LM);
      // performing RSA computation
      LMModPower(LM, LD, LN, LS);
      // unblinding the result
      LMult(LS, LVF, LTmp);
      LModEx(LTmp, LN, LS);
      
      SetLength(S, LS.Length  shl 2);
      Index := Length(S);
      LIntToPointer(LS, @S[0], Index);
      SBMove(S[Index - SSize], Signature^, SSize);
      SignatureSize := SSize;
      Result := true;
    end;
  finally
    LDestroy(LN);
    LDestroy(LD);
    LDestroy(LM);
    LDestroy(LS);
    LDestroy(LVI);
    LDestroy(LVF);
    LDestroy(LTmp);
  end;
end;

{ PKCS#1 v2.1 RSAVP1 signature verification }
function VerifyRSAVP1(Signature : pointer; SignatureSize : integer;
  PublicModulus : pointer; PublicModulusSize : integer;
  PublicExponent : pointer; PublicExponentSize : integer;
  EMessage : pointer; var EMessageSize : integer) : boolean;
begin
  Result := false;

  if EMessageSize < PublicModulusSize then
  begin
    EMessageSize := PublicModulusSize;
    Exit;
  end;

  Result := PerformExponentiation(PublicModulus, PublicModulusSize,
    PublicExponent, PublicExponentSize, Signature, SignatureSize,
    EMessage, EMessageSize, nil);
end;

{ PKCS#1 v2.1 EMSA-PSS-ENCODE }
function EncodePSS(HashValue : pointer; HashValueLen : integer;
  HashAlgorithm : integer; SaltLen : integer; mBits : integer;
  EMessage : pointer; var EMessageLen : integer) : boolean;
var
  Index, emLen, hLen : integer;
  MTemp, DB, DBMask : ByteArray;
  H : ByteArray;
  HashFunction :  TElHashFunction ;
  Salt : ByteArray;
begin
  Result := false;

  if not  TElHashFunction .IsAlgorithmSupported(HashAlgorithm) then
    Exit;

  SetLength(Salt, SaltLen);  
  if SaltLen > 0 then
    SBRndGenerate( @Salt[0] , SaltLen);

  emLen := (mBits + 7) shr 3;

  if emLen > EMessageLen then
  begin
    EMessageLen := emLen;
    Exit;
  end;

  if HashValueLen + SaltLen + 2 > emLen then
    Exit;

  SetLength(MTemp, 8 + SaltLen + HashValueLen);

  FillChar(MTemp [0] , 8, 0);
  SBMove(HashValue^, MTemp[8], HashValueLen);
  if SaltLen > 0 then
    SBMove(Salt[0], MTemp[8 + HashValueLen], SaltLen);

  hLen :=  TElHashFunction .GetDigestSizeBits(HashAlgorithm) shr 3;
  HashFunction :=  TElHashFunction .Create(HashAlgorithm);
  try
    HashFunction.Update(@MTemp[0], Length(MTemp));
    H := HashFunction.Finish;
  finally
    FreeAndNil(HashFunction);
  end;

  SetLength(DB, emLen - hLen - 1);
  SetLength(DBMask, emLen - hLen - 1);
  FillChar(DB[0], emLen - SaltLen - hLen - 2, 0);
  DB[emLen - SaltLen - hLen - 2] := $01;
  SBMove(Salt[0], DB[emLen - SaltLen - hLen - 1], SaltLen);
  DBMask := MGF1(@H[0], Length(H), emLen - hLen - 1, HashAlgorithm);

  for Index := 0 to emLen - hLen - 2 do
    DB[Index] := DB[Index] xor DBMask[Index];

  { setting leftmost bits to zero }
  for Index := 1 to emLen shl 3 - mBits do
    DB[0] := DB[0] and (not (1 shl (8 - Index)));

  SBMove(DB[0], EMessage^, emLen - hLen - 1);
  SBMove(H[0], PByteArray(EMessage)[emLen - hLen - 1], hLen);
  PByteArray(EMessage)[emLen - 1] := $bc;

  Result := true;
end;

function SignPSS(HashValue : pointer; HashValueSize : integer;
  HashAlgorithm : integer; SaltSize : integer;
  PublicModulus : pointer; PublicModulusSize : integer;
  PublicExponent : pointer; PublicExponentSize : integer;
  PrivateExponent : pointer; PrivateExponentSize : integer;
  Signature : pointer; var SignatureSize : integer; AntiTimingParams : TElRSAAntiTimingParams) : boolean;
var
  EMessage : ByteArray;
  EMessageLen : integer;
  mBits : integer;
  //SSize : integer;
  LN : PLInt;
begin
  Result := false;

  LCreate(LN);
  PointerToLInt(LN, PublicModulus, PublicModulusSize);
  mBits := LBitCount(LN);
  LDestroy(LN);

  if mBits = 0 then
  begin
    SignatureSize := 0;
    Exit;
  end;

  mBits := mBits - 1;

  EMessageLen := (mBits + 7) shr 3;

  if (EMessageLen <= 0) or (SignatureSize < EMessageLen) then
  begin
    if EMessageLen > 0 then SignatureSize := EMessageLen;
    Exit;
  end;

  SetLength(EMessage, EMessageLen);

  if not EncodePSS(HashValue, HashValueSize, HashAlgorithm, SaltSize, mBits,
    @EMessage[0], EMessageLen)
  then
    Exit;


  Result := SignRSASP1(@EMessage[0], EMessageLen, PublicModulus, PublicModulusSize,
    PublicExponent, PublicExponentSize, PrivateExponent, PrivateExponentSize,
    Signature, SignatureSize, AntiTimingParams);
end;

{$ifndef SB_PGPSFX_STUB}
function SignPSS(HashValue : pointer; HashValueSize : integer;
  HashAlgorithm : integer; SaltSize : integer; KeyBlob : pointer;
  KeyBlobSize : integer; Signature : pointer;
  var SignatureSize : integer; AntiTimingParams : TElRSAAntiTimingParams) : boolean;
var
  //EMessage : ByteArray;
  //EMessageLen : integer;
  //mBits : integer;
  N, E, D : ByteArray;
  NSize, ESize, DSize{, SSize} : integer;
begin
  Result := false;
  NSize := 0;
  ESize := 0;
  DSize := 0;
  DecodePrivateKey(KeyBlob, KeyBlobSize, nil, NSize, nil, ESize, nil, DSize);

  if (NSize <= 0) or (ESize <= 0) or (DSize <= 0) then
    Exit;

  SetLength(N, NSize);
  SetLength(E, ESize);
  SetLength(D, DSize);

  if not DecodePrivateKey(KeyBlob,  KeyBlobSize,  N, NSize, E, ESize, D, DSize)
  then
    Exit;

  Result := SignPSS(HashValue, HashValueSize, HashAlgorithm, SaltSize,
    @N[0], NSize, @E[0], ESize, @D[0], DSize, Signature, SignatureSize,
    AntiTimingParams);
end;

function VerifyPSS(HashValue : pointer; HashValueSize : integer;
  HashAlgorithm : integer; SaltSize : integer;
  PublicModulus : pointer; PublicModulusSize : integer;
  PublicExponent : pointer; PublicExponentSize : integer; Signature : pointer;
  SignatureSize : integer) : boolean;
var
  EMessage, DB, DBMask, H, Salt, TmpMessage : ByteArray;
  Index, hLen, emBits, emLen : integer;
  HashFunction :  TElHashFunction ;
  MHash : ByteArray;
  N : PLInt;
begin
  Result := false;

  if not  TElHashFunction .IsAlgorithmSupported(HashAlgorithm) then
    Exit;

  hLen :=  TElHashFunction .GetDigestSizeBits(HashAlgorithm) shr 3;

  if hLen <> HashValueSize then
    Exit;

  SetLength(DBMask, 0);
  LCreate(N);
  PointerToLInt(N, PublicModulus, PublicModulusSize);
  emBits := LBitCount(N);
  LDestroy(N);

  if emBits = 0 then
    Exit;

  Dec(emBits);  

  emLen := PublicModulusSize;
  SetLength(EMessage, emLen);

  if not VerifyRSAVP1(Signature, SignatureSize, PublicModulus, PublicModulusSize,
    PublicExponent, PublicExponentSize, @EMessage[0], emLen) then
    Exit;

  if emLen < hLen + SaltSize + 2 then
    Exit;

  if EMessage[emLen - 1] <> $bc then
    Exit;

  SetLength(DB, emLen - hLen - 1);
  SetLength(H, hLen);

  SBMove(EMessage[0], DB[0], emLen - hLen - 1);
  SBMove(EMessage[emLen - hLen - 1], H[0], hLen);

  DBMask := MGF1(@H[0], hLen, emLen - hLen - 1, HashAlgorithm);

  for Index := 1 to (emLen shl 3 - emBits) do
    if (DB[0] and (1 shl (8 - Index))) <> 0 then
      Exit;

  for Index := 0 to emLen - hLen - 2 do
    DB[Index] := DB[Index] xor DBMask[Index];

  for Index := 1 to emLen shl 3 - emBits do
    DB[0] := DB[0] and (not (1 shl (8 - Index)));

  for Index := 0 to emLen - hLen - SaltSize - 3 do
    if DB[Index] <> 0 then Exit;

  if DB[emLen - hLen - SaltSize - 2] <> $01 then Exit;

  SetLength(Salt, SaltSize);
  SetLength(TmpMessage, 8 + hLen + SaltSize);

  SBMove(DB[emLen - hLen - SaltSize - 1], Salt[0], SaltSize);
  FillChar(TmpMessage[0], 8, 0);
  SBMove(HashValue^, TmpMessage[8], hLen);
  if SaltSize > 0 then
    SBMove(Salt[0], TmpMessage[8 + hLen], SaltSize);

  HashFunction :=  TElHashFunction .Create(HashAlgorithm);
  try
    HashFunction.Update(@TmpMessage[0], 8 + SaltSize + hLen);
    MHash := HashFunction.Finish;
  finally
    FreeAndNil(HashFunction);
  end;

  if CompareMem(@H[0], @MHash[0], hLen) then
    Result := true
end;
 {$endif SB_PGPSFX_STUB}

function DecodePublicKey(Buffer : pointer; Size : integer; PublicModulus : pointer;
  var PublicModulusSize: integer; PublicExponent : pointer; var PublicExponentSize:
  integer; var AlgID : ByteArray; InnerValuesOnly : boolean  =  false): boolean;
var
  CTag, Tag : TElASN1ConstrainedTag;
  InnerTag : TElASN1ConstrainedTag;
  Buf : ByteArray;
  RealMSize, RealESize: integer;
begin
  Result := false;
  if not InnerValuesOnly then
  begin
    Tag := TElASN1ConstrainedTag.CreateInstance;
    try
      if (Tag.LoadFromBuffer(Buffer, Size )) then
      begin
        if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
        begin
          CTag := TElASN1ConstrainedTag(Tag.GetField(0));
          if (CTag.Count = 2) and (CTag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) and
            (CTag.GetField(1).CheckType(SB_ASN1_BITSTRING, false)) then
          begin
            if TElASN1ConstrainedTag(CTag.GetField(0)).GetField(0).CheckType(SB_ASN1_OBJECT, false) and
              CompareContent(TElASN1SimpleTag(TElASN1ConstrainedTag(CTag.GetField(0)).GetField(0)).Content,
                SB_OID_RSAENCRYPTION) then
            begin
              AlgID := TElASN1SimpleTag(TElASN1ConstrainedTag(CTag.GetField(0)).GetField(0)).Content;
              Buf := TElASN1SimpleTag(CTag.GetField(1)).Content;
              Buf := Copy(Buf, 0 + 1, Length(Buf) - 1);
              InnerTag := TElASN1ConstrainedTag.CreateInstance;
              try
                if InnerTag.LoadFromBuffer( @Buf[0], Length(Buf) ) then
                begin
                  if (InnerTag.Count = 1) and (InnerTag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
                  begin
                    CTag := TElASN1ConstrainedTag(InnerTag.GetField(0));
                    if (CTag.Count = 2) and (CTag.GetField(0).CheckType(SB_ASN1_INTEGER, false)) and
                      (CTag.GetField(0).CheckType(SB_ASN1_INTEGER, false)) then
                    begin
                      RealMSize := Length(TElASN1SimpleTag(CTag.GetField(0)).Content);
                      RealESize := Length(TElASN1SimpleTag(CTag.GetField(1)).Content);
                      if (PublicModulusSize < RealMSize) or (PublicExponentSize < RealESize) then
                      begin
                        PublicModulusSize := RealMSize;
                        PublicExponentSize := RealESize;
                        Exit;
                      end;
                      Buf := TElASN1SimpleTag(CTag.GetField(0)).Content;
                      PublicModulusSize := Length(Buf);
                      SBMove(Buf[0], PublicModulus^, PublicModulusSize);
                      Buf := TElASN1SimpleTag(CTag.GetField(1)).Content;
                      PublicExponentSize := Length(Buf);
                      SBMove(Buf[0], PublicExponent^, PublicExponentSize);
                      Result := true;
                    end;
                  end;
                end;
              finally
                FreeAndNil(InnerTag);
              end;
            end;
          end;
        end;
      end
    finally
      FreeAndNil(Tag);
    end;
  end
  else
  begin
    InnerTag := TElASN1ConstrainedTag.CreateInstance;
    try
      if InnerTag.LoadFromBuffer( Buffer, Size ) then
      begin
        if (InnerTag.Count = 1) and (InnerTag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
        begin
          CTag := TElASN1ConstrainedTag(InnerTag.GetField(0));
          if (CTag.Count = 2) and (CTag.GetField(0).CheckType(SB_ASN1_INTEGER, false)) and
            (CTag.GetField(0).CheckType(SB_ASN1_INTEGER, false)) then
          begin
            RealMSize := Length(TElASN1SimpleTag(CTag.GetField(0)).Content);
            RealESize := Length(TElASN1SimpleTag(CTag.GetField(1)).Content);
            if (PublicModulusSize < RealMSize) or (PublicExponentSize < RealESize) then
            begin
              PublicModulusSize := RealMSize;
              PublicExponentSize := RealESize;
              Exit;
            end;
            Buf := TElASN1SimpleTag(CTag.GetField(0)).Content;
            PublicModulusSize := Length(Buf);
            SBMove(Buf[0], PublicModulus^, PublicModulusSize);
            Buf := TElASN1SimpleTag(CTag.GetField(1)).Content;
            PublicExponentSize := Length(Buf);
            SBMove(Buf[0], PublicExponent^, PublicExponentSize);
            Result := true;
          end;
        end;
      end;
    finally
      FreeAndNil(InnerTag);
    end;
  end;
end;

function FormatIntegerValue(Buffer: pointer; Size: integer) : ByteArray;
begin
  if Size = 0 then
    Result := GetByteArrayFromByte(0)
  else
  if  PByte(Buffer)^  >= $80 then
  begin
    SetLength(Result, Size + 1);
    SBMove(Buffer^, Result[0 + 1], Size);
    Result[0] := byte(0);
  end
  else
  begin
    SetLength(Result, Size);
    SBMove(Buffer^, Result[0], Size);
  end;
end;

function EncodePublicKey(PublicModulus : pointer; PublicModulusSize : integer;
  PublicExponent : pointer; PublicExponentSize : integer; const AlgID : ByteArray;
  OutBuffer : pointer; var OutSize : integer; InnerValuesOnly : boolean = false) : boolean;
var
  Tag : TElASN1ConstrainedTag;
  InnerTag : TElASN1ConstrainedTag;
  SimpleTag : TElASN1SimpleTag;
  Buf : ByteArray;
  BufSize: integer;
begin
  Result := false;
  if not InnerValuesOnly then
  begin
    Tag := TElASN1ConstrainedTag.CreateInstance;
    try
      Tag.TagId := SB_ASN1_SEQUENCE;
      // forming alg-id sequence
      InnerTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
      InnerTag.TagId := SB_ASN1_SEQUENCE;
      SimpleTag := TElASN1SimpleTag(InnerTag.GetField(InnerTag.AddField(false)));
      SimpleTag.TagId := SB_ASN1_OBJECT;
      SimpleTag.Content := AlgID;
      SimpleTag := TElASN1SimpleTag(InnerTag.GetField(InnerTag.AddField(false)));
      SimpleTag.TagId := SB_ASN1_NULL;
      SimpleTag.Content := EmptyArray;
      // forming key material sequence
      InnerTag := TElASN1ConstrainedTag.CreateInstance;
      InnerTag.TagId := SB_ASN1_SEQUENCE;
      try
        SimpleTag := TElASN1SimpleTag(InnerTag.GetField(InnerTag.AddField(false)));
        SimpleTag.TagId := SB_ASN1_INTEGER;
        SimpleTag.Content := FormatIntegerValue(PublicModulus , PublicModulusSize );
        SimpleTag := TElASN1SimpleTag(InnerTag.GetField(InnerTag.AddField(false)));
        SimpleTag.TagId := SB_ASN1_INTEGER;
        SimpleTag.Content := FormatIntegerValue(PublicExponent , PublicExponentSize );
        BufSize := 0;
        InnerTag.SaveToBuffer( nil , BufSize);
        SetLength(Buf, BufSize);
        if not InnerTag.SaveToBuffer( @Buf[0] , BufSize) then
          Exit;
        SetLength(Buf, BufSize);

        // insert 0 at the beginning of the buffer
        Buf := SBConcatArrays(GetByteArrayFromByte(0), Buf);
      finally
        FreeAndNil(InnerTag);
      end;
      SimpleTag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      SimpleTag.TagId := SB_ASN1_BITSTRING;
      SimpleTag.Content := CloneArray(Buf);
      Result := Tag.SaveToBuffer(OutBuffer, OutSize);
    finally
      FreeAndNil(Tag);
    end;
  end
  else
  begin
    // forming key material sequence
    InnerTag := TElASN1ConstrainedTag.CreateInstance;
    InnerTag.TagId := SB_ASN1_SEQUENCE;
    try
      SimpleTag := TElASN1SimpleTag(InnerTag.GetField(InnerTag.AddField(false)));
      SimpleTag.TagId := SB_ASN1_INTEGER;
      SimpleTag.Content := FormatIntegerValue(PublicModulus , PublicModulusSize );
      SimpleTag := TElASN1SimpleTag(InnerTag.GetField(InnerTag.AddField(false)));
      SimpleTag.TagId := SB_ASN1_INTEGER;
      SimpleTag.Content := FormatIntegerValue(PublicExponent , PublicExponentSize );
      BufSize := 0;
      Result := InnerTag.SaveToBuffer(OutBuffer, OutSize);
    finally
      FreeAndNil(InnerTag);
    end;
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// TElRSAAntiTimingParams class

constructor TElRSAAntiTimingParams.Create();
begin
  inherited;
  LCreate(FVI);
  LCreate(FVF);
  SetLength(FRSAE, 0);
  SetLength(FRSAM, 0);
  FInitialized := false;
  FPrepared := false;
  FSharedResource := TElSharedResource.Create();
end;

 destructor  TElRSAAntiTimingParams.Destroy;
begin
  LDestroy(FVI);
  LDestroy(FVF);
  FreeAndNil(FSharedResource);
  ReleaseArrays(FRSAE, FRSAM);
  inherited;
end;

procedure TElRSAAntiTimingParams.Init(const RSAM : ByteArray; const RSAE : ByteArray);
begin
  FRSAM := CloneArray(RSAM);
  FRSAE := CloneArray(RSAE);
  FInitialized := true;
end;

procedure TElRSAAntiTimingParams.Reset;
begin
  FPrepared := false;
  FInitialized := false;
  LZero(FVI);
  LZero(FVF);
  SetLength(FRSAE, 0);
  SetLength(FRSAM, 0);
end;

procedure TElRSAAntiTimingParams.GetNextBlindingPair(VI, VF : PLInt);
begin
  if not FInitialized then
    raise ESecureBlackboxError.Create('Anti timing attack parameters are not initialized');
  FSharedResource.WaitToWrite;
  try
    if not FPrepared then
      PrepareBlindingPair;
    LCopy(VI, FVI);
    LCopy(VF, FVF);
    UpdateBlindingPair;
  finally
    FSharedResource.Done;
  end;
end;

procedure TElRSAAntiTimingParams.PrepareBlindingPair;
var
  LM, LE, LTmp1, LTmp2, LOne : PLInt;
begin
  LCreate(LM);
  LCreate(LE);
  LCreate(LTmp1);
  LCreate(LTmp2);
  LCreate(LOne);
  try
    PointerToLInt(LM,  @FRSAM[0], Length(FRSAM) );
    PointerToLInt(LE,  @FRSAE[0], Length(FRSAE) );
    while true do
    begin
      LGenerate(FVF, LM.Length - 1);
      LGCD(FVF, LM, LTmp1, LTmp2);
      if (LEqual(LTmp1, LOne)) then
        Break;
    end;
    LMModPower(LTmp2, LE, LM, FVI);
  finally
    LDestroy(LM);
    LDestroy(LE);
    LDestroy(LTmp1);
    LDestroy(LTmp2);
    LDestroy(LOne);
  end;
  FPrepared := true;
end;

procedure TElRSAAntiTimingParams.UpdateBlindingPair;
var
  LM, LTmp : PLInt;
begin
  LCreate(LM);
  LCreate(LTmp);
  try
    PointerToLInt(LM,  @FRSAM[0], Length(FRSAM) );
    LMult(FVI, FVI, LTmp);
    LModEx(LTmp, LM, FVI);
    LMult(FVF, FVF, LTmp);
    LModEx(LTmp, LM, FVF);
  finally
    LDestroy(LM);
    LDestroy(LTmp);
  end;
end;

end.
