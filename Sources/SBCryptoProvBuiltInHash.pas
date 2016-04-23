(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBCryptoProvBuiltInHash;

interface

uses
  SBConstants,
  SBTypes,
  SBUtils,
  SBStrUtils,
  SysUtils,
  Classes,
  SBCRC,
  SBMD,
  SBSHA,
  SBSHA2,
  SBRIPEMD,
  SBWhirlpool,
{$ifdef SB_HAS_GOST}
  SBGOSTCommon,
  SBGOST341194,
  SBGOST2814789,
 {$endif}
  {$ifndef SB_NO_UMAC}SBUMAC, {$endif}
  SBCryptoProv,
  SBCryptoProvRS,
  SBCryptoProvBuiltIn;


type
  TElBuiltInHashFunction = class
  private
    FAlgorithm: integer;
    {$ifndef SB_NO_MD2}
    FCtxMD2 : TMD2Context;
     {$endif}
    FCtxMD5 : TMD5Context;
    FCtxSHA1 : TSHA1Context;
    FCtxSHA256 : TSHA256Context;
    FCtxSHA512 : TSHA512Context;
    FCtxRMD160 : TRMD160Context;
    FCtxWhirlpool: TWhirlpoolContext;
    FCRC32 : LongWord;
    FDigest : ByteArray;
    FKeyMaterial : TElCustomCryptoKey;
    FUseHMAC : boolean;
    FHMACBlockSize : integer;
    {$ifndef SB_NO_UMAC}
    FCtxUMAC: TElUMAC;
     {$endif}
    {$ifdef SB_HAS_GOST}
    FCtxGOST: TElGOSTBase;
     {$endif}
    procedure InitializeDigest(Parameters : TElCPParameters  =  nil);
    procedure UpdateDigest(Buffer: pointer; Size: integer);
    procedure FinalizeDigest;
  public
    constructor Create(Algorithm: integer; Parameters : TElCPParameters  =  nil; Key : TElCustomCryptoKey  =  nil);  overload; 
    constructor Create(const OID : ByteArray; Parameters : TElCPParameters  =  nil; Key : TElCustomCryptoKey  =  nil);  overload; 

    procedure SetHashFunctionProp(const PropID, Value : ByteArray);
    function GetHashFunctionProp(const PropID : ByteArray; const Default : ByteArray) : ByteArray;

     destructor  Destroy; override;

    procedure Reset;
    procedure Update(Buffer: pointer; Size: integer); overload;
    procedure Update(Stream: TElInputStream; Count: Int64  =  0);  overload; 
    function Finish : ByteArray;
    function Clone : TElBuiltInHashFunction;
    property Algorithm: integer read FAlgorithm;
    property KeyMaterial : TElCustomCryptoKey read FKeyMaterial write FKeyMaterial;
    class function IsAlgorithmSupported(Algorithm: integer): boolean;  overload; 
    class function IsAlgorithmSupported(const OID : ByteArray): boolean;  overload; 
    class function GetDigestSizeBits(Algorithm: integer): integer;  overload; 
    class function GetDigestSizeBits(const OID : ByteArray): integer;  overload; 
  end;

  EElHashFunctionError =  class(EElCryptoProviderError);
  EElHashFunctionUnsupportedError =  class(EElHashFunctionError);

  TElBuiltInMACKey = class(TElBuiltInCryptoKey)
  protected
    FValue : ByteArray;
    FNonce : ByteArray;
    function GetIsPublic: boolean; override;
    function GetIsSecret: boolean; override;
    function GetIsExportable: boolean; override;
    function GetIsPersistent: boolean; override;
    function GetIsValid: boolean; override;
    function GetBits : integer; override;
    function GetAlgorithm : integer; override;
    function GetKeyStorage : TElCustomCryptoKeyStorage; override;
    function GetMode : integer; override;
    procedure SetMode(Value : integer); override;
    function GetIV : ByteArray; override;
    procedure SetIV(const Value : ByteArray); override;
    function GetValue : ByteArray; override;
    procedure SetValue(const Value : ByteArray); override;
  public
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
    procedure ChangeAlgorithm(Algorithm : integer); override;
    function Equals(Source : TElCustomCryptoKey; PublicOnly : boolean;
      Params : TElCPParameters  =  nil): boolean; override;
  end;

implementation

uses
  SBRandom;

constructor TElBuiltInHashFunction.Create(Algorithm: integer; Parameters : TElCPParameters  =  nil; Key : TElCustomCryptoKey  =  nil);
begin
  inherited Create;
  
  if IsAlgorithmSupported(Algorithm) then
  begin
    FAlgorithm := Algorithm;
    FUseHMAC := IsMacAlgorithm(FAlgorithm)
        and (FAlgorithm <> SB_ALGORITHM_UMAC32)
        and (FAlgorithm <> SB_ALGORITHM_UMAC64)
        and (FAlgorithm <> SB_ALGORITHM_UMAC96)
        and (FAlgorithm <> SB_ALGORITHM_UMAC128);
    FKeyMaterial := Key;
    {$ifdef SB_HAS_GOST}
    FCtxGOST := nil;
     {$endif}
    {$ifndef SB_NO_UMAC}
    FCtxUMAC := nil;
     {$endif}

    InitializeDigest(Parameters);
  end
  else
    raise EElHashFunctionUnsupportedError.CreateFmt(SUnsupportedAlgorithmInt, [Algorithm]);
end;

constructor TElBuiltInHashFunction.Create(const OID : ByteArray; Parameters : TElCPParameters  =  nil; Key : TElCustomCryptoKey  =  nil);
var
  Alg : integer;
begin
  Alg := GetHashAlgorithmByOID(OID);
  Create(Alg, Parameters, Key);
end;

 destructor  TElBuiltInHashFunction.Destroy;
begin
  {$ifndef SB_NO_UMAC}
  if Assigned(FCtxUMAC) then
    FreeAndNil(FCtxUMAC);
   {$endif}
  {$ifdef SB_HAS_GOST}
  if Assigned(FCtxGOST) then
    FreeAndNil(FCtxGOST);
   {$endif}
  inherited;
end;

procedure TElBuiltInHashFunction.InitializeDigest(Parameters : TElCPParameters  =  nil);
var
  M128 : TMessageDigest128;
  M160 : TMessageDigest160;
  M224 : TMessageDigest224;
  M256 : TMessageDigest256;
  M384 : TMessageDigest384;
  M512 : TMessageDigest512;
  Buf, KeyBuf : ByteArray;
  i : integer;
begin

  if FUseHMAC then
  begin
    if (FAlgorithm = SB_ALGORITHM_MAC_HMACSHA384) or
      (FAlgorithm = SB_ALGORITHM_MAC_HMACSHA512)
    then
      FHMACBlockSize := 128
    else
      FHMACBlockSize := 64;

    if not (FKeyMaterial is TElBuiltInMACKey) then
      raise EElHashFunctionError.Create(SInvalidKeyMaterial);
    if Length(FKeyMaterial.Value) > FHMACBlockSize then
    begin
      KeyBuf := CloneArray(FKeyMaterial.Value);

      case FAlgorithm of
        SB_ALGORITHM_MAC_HMACMD5 :
        begin
          M128 := HashMD5(@KeyBuf[0], Length(KeyBuf));
          SetLength(KeyBuf, 16);
          SBMove(M128, KeyBuf[0], 16);
        end;
        SB_ALGORITHM_MAC_HMACSHA1 :
        begin
          M160 := HashSHA1(@KeyBuf[0], Length(KeyBuf));
          SetLength(KeyBuf, 20);
          SBMove(M160, KeyBuf[0], 20);
        end;
      SB_ALGORITHM_MAC_HMACSHA224 :
        begin
          M224 := HashSHA224(@KeyBuf[0], Length(KeyBuf));
          SetLength(KeyBuf, 28);
          SBMove(M224, KeyBuf[0], 28);
        end;
      SB_ALGORITHM_MAC_HMACSHA256 :
        begin
          M256 := HashSHA256(@KeyBuf[0], Length(KeyBuf));
          SetLength(KeyBuf, 32);
          SBMove(M256, KeyBuf[0], 32);
        end;
      SB_ALGORITHM_MAC_HMACSHA384 :
        begin
          M384 := HashSHA384(@KeyBuf[0], Length(KeyBuf));
          SetLength(KeyBuf, 48);
          SBMove(M384, KeyBuf[0], 48);
        end;
      SB_ALGORITHM_MAC_HMACSHA512 :
        begin
          M512 := HashSHA512(@KeyBuf[0], Length(KeyBuf));
          SetLength(KeyBuf, 64);
          SBMove(M512, KeyBuf[0], 64);
        end;
      SB_ALGORITHM_MAC_HMACRIPEMD :
        begin
          M160 := HashRMD160(@KeyBuf[0], Length(KeyBuf));
          SetLength(KeyBuf, 20);
          SBMove(M160, KeyBuf[0], 20);
        end
      else
        raise EElHashFunctionUnsupportedError.CreateFmt(SUnsupportedAlgorithmInt, [FAlgorithm]);
      end;

      FKeyMaterial.Value := CloneArray(KeyBuf);
    end
    else
      KeyBuf := CloneArray(FKeyMaterial.Value);

    SetLength(Buf, FHMACBlockSize);
    FillChar(Buf[0], FHMACBlockSize, $36);
    for i := 0 to Length(KeyBuf) - 1 do
      Buf[i] := Buf[i] xor KeyBuf[i];
  end;

  case FAlgorithm of
    {$ifndef SB_NO_MD2}
    SB_ALGORITHM_DGST_MD2 : InitializeMD2(FCtxMD2);
     {$endif}
    SB_ALGORITHM_DGST_MD5 : InitializeMD5(FCtxMD5);
    SB_ALGORITHM_DGST_SHA1 : InitializeSHA1(FCtxSHA1);
    SB_ALGORITHM_DGST_SHA224 : InitializeSHA224(FCtxSHA256);
    SB_ALGORITHM_DGST_SHA256 : InitializeSHA256(FCtxSHA256);
    SB_ALGORITHM_DGST_SHA512 : InitializeSHA512(FCtxSHA512);
    SB_ALGORITHM_DGST_SHA384 : InitializeSHA384(FCtxSHA512);
    SB_ALGORITHM_DGST_RIPEMD160 : InitializeRMD160(FCtxRMD160);
    SB_ALGORITHM_DGST_WHIRLPOOL : InitializeWhirlpool(FCtxWhirlpool);
    SB_ALGORITHM_MAC_HMACMD5 :
      begin
        InitializeMD5(FCtxMD5);
        HashMD5(FCtxMD5, @Buf[0], FHMACBlockSize);
      end;
    SB_ALGORITHM_MAC_HMACSHA1 :
      begin
        InitializeSHA1(FCtxSHA1);
        HashSHA1(FCtxSHA1, @Buf[0], FHMACBlockSize);
      end;
    SB_ALGORITHM_MAC_HMACSHA224 :
      begin
        InitializeSHA224(FCtxSHA256);
        HashSHA224(FCtxSHA256, @Buf[0], FHMACBlockSize);
      end;
    SB_ALGORITHM_MAC_HMACSHA256 :
      begin
        InitializeSHA256(FCtxSHA256);
        HashSHA256(FCtxSHA256, @Buf[0], FHMACBlockSize);
      end;
    SB_ALGORITHM_MAC_HMACSHA384 :
      begin
        InitializeSHA384(FCtxSHA512);
        HashSHA384(FCtxSHA512, @Buf[0], FHMACBlockSize);
      end;
    SB_ALGORITHM_MAC_HMACSHA512 :
      begin
        InitializeSHA512(FCtxSHA512);
        HashSHA512(FCtxSHA512, @Buf[0], FHMACBlockSize);
      end;
    SB_ALGORITHM_MAC_HMACRIPEMD :
      begin
        InitializeRMD160(FCtxRMD160);
        HashRMD160(FCtxRMD160, @Buf[0], FHMACBlockSize);
      end;
    {$ifndef SB_NO_UMAC}
    SB_ALGORITHM_UMAC32:
      begin
        if Assigned(FCtxUMAC) then
          FreeAndNil(FCtxUMAC);
        FCtxUMAC := TElUMAC.Create(FKeyMaterial.Value, 4);
      end;
    SB_ALGORITHM_UMAC64:
      begin
        if Assigned(FCtxUMAC) then
          FreeAndNil(FCtxUMAC);
        FCtxUMAC := TElUMAC.Create(FKeyMaterial.Value, 8);
      end;
    SB_ALGORITHM_UMAC96:
      begin
        if Assigned(FCtxUMAC) then
          FreeAndNil(FCtxUMAC);
        FCtxUMAC := TElUMAC.Create(FKeyMaterial.Value, 12);
      end;
    SB_ALGORITHM_UMAC128:
      begin
        if Assigned(FCtxUMAC) then
          FreeAndNil(FCtxUMAC);
        FCtxUMAC := TElUMAC.Create(FKeyMaterial.Value, 16);
      end;
     {$endif SB_NO_UMAC}
    SB_ALGORITHM_DGST_SSL3 :
      begin
        InitializeSHA1(FCtxSHA1);
        InitializeMD5(FCtxMD5);
      end;
    {$ifdef SB_HAS_GOST}
    SB_ALGORITHM_DGST_GOST_R3411_1994:
      begin
        if not Assigned(FCtxGOST) then
          FCtxGOST := TElGOSTMD.Create();
      end;
    SB_ALGORITHM_MAC_GOST_28147_1989:
      begin
        if not Assigned(FCtxGOST) then
           FCtxGOST := TElGOST.Create();
        TElGOST(FCtxGOST).IV := FKeyMaterial.IV;
        TElGOST(FCtxGOST).Key := FKeyMaterial.Value;
        FCtxGOST.Reset();
      end;
      {$endif}
    SB_ALGORITHM_DGST_CRC32:
      begin
        FCRC32 := 0;
      end;
  else
    raise EElHashFunctionUnsupportedError.CreateFmt(SUnsupportedAlgorithmInt, [FAlgorithm]);
  end;

end;

procedure TElBuiltInHashFunction.UpdateDigest(Buffer: pointer; Size: integer);
begin

  case FAlgorithm of
    {$ifndef SB_NO_MD2}
    SB_ALGORITHM_DGST_MD2 :
    begin
      HashMD2(FCtxMD2, Buffer, Size);
    end;
     {$endif}
    SB_ALGORITHM_DGST_MD5, SB_ALGORITHM_MAC_HMACMD5 :
    begin
      HashMD5(FCtxMD5, Buffer, Size);
    end;
    SB_ALGORITHM_DGST_SHA1, SB_ALGORITHM_MAC_HMACSHA1 :
    begin
      HashSHA1(FCtxSHA1, Buffer, Size);
    end;
    SB_ALGORITHM_DGST_SHA224, SB_ALGORITHM_MAC_HMACSHA224 :
      HashSHA224(FCtxSHA256, Buffer,  Size );
    SB_ALGORITHM_DGST_SHA256, SB_ALGORITHM_MAC_HMACSHA256 :
      HashSHA256(FCtxSHA256, Buffer,  Size );
    SB_ALGORITHM_DGST_SHA512, SB_ALGORITHM_MAC_HMACSHA512 :
      HashSHA512(FCtxSHA512, Buffer,  Size );
    SB_ALGORITHM_DGST_SHA384, SB_ALGORITHM_MAC_HMACSHA384 :
      HashSHA384(FCtxSHA512, Buffer,  Size );
    SB_ALGORITHM_DGST_RIPEMD160, SB_ALGORITHM_MAC_HMACRIPEMD :
    begin
      HashRMD160(FCtxRMD160, Buffer, Size);
    end;
    SB_ALGORITHM_DGST_WHIRLPOOL:
      HashWhirlpool(FCtxWhirlpool, Buffer,  Size );
    {$ifndef SB_NO_UMAC}
    SB_ALGORITHM_UMAC32, SB_ALGORITHM_UMAC64, SB_ALGORITHM_UMAC96, SB_ALGORITHM_UMAC128:
    begin
      FCtxUMAC.Update(Buffer, Size);
    end;
     {$endif}
    SB_ALGORITHM_DGST_SSL3 :
    begin
      HashSHA1(FCtxSHA1, Buffer, Size);
      HashMD5(FCtxMD5, Buffer, Size);
   end;
    {$ifdef SB_HAS_GOST}
    SB_ALGORITHM_DGST_GOST_R3411_1994:
    begin
      TElGOSTMD(FCtxGOST).Update(Buffer, Size);
    end;
    SB_ALGORITHM_MAC_GOST_28147_1989:
    begin
      TElGOST(FCtxGOST).MAC_Block(Buffer, Size);
    end;
     {$endif}
    SB_ALGORITHM_DGST_CRC32:
      FCRC32 := SBCRC.CRC32(Buffer, Size, FCRC32)
  else
    raise EElHashFunctionUnsupportedError.CreateFmt(SUnsupportedAlgorithmInt, [FAlgorithm]);
  end;

end;

procedure TElBuiltInHashFunction.FinalizeDigest;
var
  M128 : TMessageDigest128;
  M160 : TMessageDigest160;
  M224 : TMessageDigest224;
  M256 : TMessageDigest256;
  M384 : TMessageDigest384;
  M512 : TMessageDigest512;
  Buf : ByteArray;
  i : integer;
begin

  if FUseHMAC then
  begin
    SetLength(Buf, FHMACBlockSize);
    FillChar(Buf[0], FHMACBlockSize, $5C);
    for i := 0 to Length(FKeyMaterial.Value) - 1 do
      Buf[i] := Buf[i] xor FKeyMaterial.Value[i];
  end;

  case FAlgorithm of
    {$ifndef SB_NO_MD2}
    SB_ALGORITHM_DGST_MD2 :
    begin
      M128 := FinalizeMD2(FCtxMD2);
      SetLength(FDigest, 16);
      SBMove(M128, FDigest[0], 16);
    end;
     {$endif}
    SB_ALGORITHM_DGST_MD5 :
    begin
      M128 := FinalizeMD5(FCtxMD5);
      SetLength(FDigest, 16);
      SBMove(M128, FDigest[0], 16);
    end;
    SB_ALGORITHM_DGST_SHA1 :
    begin
      M160 := FinalizeSHA1(FCtxSHA1);
      SetLength(FDigest, 20);
      SBMove(M160, FDigest[0], 20);
    end;
    SB_ALGORITHM_DGST_SHA224 :
    begin
      M224 := FinalizeSHA224(FCtxSHA256);
      SetLength(FDigest, 28);
      SBMove(M224, FDigest[0], 28);
    end;
    SB_ALGORITHM_DGST_SHA256 :
    begin
      M256 := FinalizeSHA256(FCtxSHA256);
      SetLength(FDigest, 32);
      SBMove(M256, FDigest[0], 32);
    end;
    SB_ALGORITHM_DGST_SHA512 :
    begin
      M512 := FinalizeSHA512(FCtxSHA512);
      SetLength(FDigest, 64);
      SBMove(M512, FDigest[0], 64);
    end;
    SB_ALGORITHM_DGST_SHA384 :
    begin
      M384 := FinalizeSHA384(FCtxSHA512);
      SetLength(FDigest, 48);
      SBMove(M384, FDigest[0], 48);
    end;
    SB_ALGORITHM_DGST_RIPEMD160 :
    begin
      M160 := FinalizeRMD160(FCtxRMD160);
      SetLength(FDigest, 20);
      SBMove(M160, FDigest[0], 20);
    end;
    SB_ALGORITHM_DGST_WHIRLPOOL:
    begin
      M512 := FinalizeWhirlpool(FCtxWhirlpool);
      SetLength(FDigest, 64);
      SBMove(M512, FDigest[0], 64);
    end;
    SB_ALGORITHM_MAC_HMACMD5 :
    begin
      M128 := FinalizeMD5(FCtxMD5);
      SetLength(FDigest, 16);
      SBMove(M128, FDigest[0], 16);
      InitializeMD5(FCtxMD5);
      HashMD5(FCtxMD5, @Buf[0], FHMACBlockSize);
      HashMD5(FCtxMD5, @FDigest[0], Length(FDigest));
      M128 := FinalizeMD5(FCtxMD5);
      SetLength(FDigest, 16);
      SBMove(M128, FDigest[0], 16);
    end;
    SB_ALGORITHM_MAC_HMACSHA1 :
    begin
      M160 := FinalizeSHA1(FCtxSHA1);
      SetLength(FDigest, 20);
      SBMove(M160, FDigest[0], 20);
      InitializeSHA1(FCtxSHA1);
      HashSHA1(FCtxSHA1, @Buf[0], FHMACBlockSize);
      HashSHA1(FCtxSHA1, @FDigest[0], Length(FDigest));
      M160 := FinalizeSHA1(FCtxSHA1);
      SetLength(FDigest, 20);
      SBMove(M160, FDigest[0], 20);
    end;
    SB_ALGORITHM_MAC_HMACSHA224 :
    begin
      M224 := FinalizeSHA224(FCtxSHA256);
      SetLength(FDigest, 28);
      SBMove(M224, FDigest[0], 28);
      InitializeSHA224(FCtxSHA256);
      HashSHA224(FCtxSHA256, @Buf[0], FHMACBlockSize);
      HashSHA224(FCtxSHA256, @FDigest[0], Length(FDigest));
      M224 := FinalizeSHA224(FCtxSHA256);
      SetLength(FDigest, 28);
      SBMove(M224, FDigest[0], 28);
    end;
    SB_ALGORITHM_MAC_HMACSHA256 :
    begin
      M256 := FinalizeSHA256(FCtxSHA256);
      SetLength(FDigest, 32);
      SBMove(M256, FDigest[0], 32);
      InitializeSHA256(FCtxSHA256);
      HashSHA256(FCtxSHA256, @Buf[0], FHMACBlockSize);
      HashSHA256(FCtxSHA256, @FDigest[0], Length(FDigest));
      M256 := FinalizeSHA256(FCtxSHA256);
      SetLength(FDigest, 32);
      SBMove(M256, FDigest[0], 32);
    end;
    SB_ALGORITHM_MAC_HMACSHA512 :
    begin
      M512 := FinalizeSHA512(FCtxSHA512);
      SetLength(FDigest, 64);
      SBMove(M512, FDigest[0], 64);
      InitializeSHA512(FCtxSHA512);
      HashSHA512(FCtxSHA512, @Buf[0], FHMACBlockSize);
      HashSHA512(FCtxSHA512, @FDigest[0], Length(FDigest));
      M512 := FinalizeSHA512(FCtxSHA512);
      SetLength(FDigest, 64);
      SBMove(M512, FDigest[0], 64);
    end;
    SB_ALGORITHM_MAC_HMACSHA384 :
    begin
      M384 := FinalizeSHA384(FCtxSHA512);
      SetLength(FDigest, 48);
      SBMove(M384, FDigest[0], 48);
      InitializeSHA384(FCtxSHA512);
      HashSHA384(FCtxSHA512, @Buf[0], FHMACBlockSize);
      HashSHA384(FCtxSHA512, @FDigest[0], Length(FDigest));
      M384 := FinalizeSHA384(FCtxSHA512);
      SetLength(FDigest, 48);
      SBMove(M384, FDigest[0], 48);
    end;
    SB_ALGORITHM_MAC_HMACRIPEMD :
    begin
      M160 := FinalizeRMD160(FCtxRMD160);
      SetLength(FDigest, 20);
      SBMove(M160, FDigest[0], 20);
      InitializeRMD160(FCtxRMD160);
      HashRMD160(FCtxRMD160, @Buf[0], FHMACBlockSize);
      HashRMD160(FCtxRMD160, @FDigest[0], Length(FDigest));
      M160 := FinalizeRMD160(FCtxRMD160);
      SetLength(FDigest, 20);
      SBMove(M160, FDigest[0], 20);
    end;
    {$ifndef SB_NO_UMAC}
    SB_ALGORITHM_UMAC32, SB_ALGORITHM_UMAC64, SB_ALGORITHM_UMAC96, SB_ALGORITHM_UMAC128:
    begin
      FCtxUMAC.Final(FKeyMaterial.IV, Buf);

      FDigest := CloneArray(@Buf[0], Length(Buf));
    end;
     {$endif}
    SB_ALGORITHM_DGST_SSL3 :
    begin
      M128 := FinalizeMD5(FCtxMD5);
      SetLength(FDigest, 16);
      SBMove(M128, FDigest[0], 16);
      M160 := FinalizeSHA1(FCtxSHA1);
      SetLength(FDigest, 36);
      SBMove(M160, FDigest[0 + 16], 20);
    end;          
    {$ifdef SB_HAS_GOST}
    SB_ALGORITHM_DGST_GOST_R3411_1994:
    begin
      TElGOSTMD(FCtxGOST).Final(Buf);
      FDigest := CloneArray(@Buf[0], Length(Buf));
    end;
    SB_ALGORITHM_MAC_GOST_28147_1989:
    begin
      TElGOST(FCtxGOST).MAC_Finalize(GetDigestSizeBits(FAlgorithm), Buf);
      FDigest := CloneArray(@Buf[0], Length(Buf));
    end;
     {$endif}
    SB_ALGORITHM_DGST_CRC32:
    begin
      SetLength(FDigest, 4);
      PLongWord(@FDigest[0])^ := FCRC32;
    end;
  else
    raise EElHashFunctionUnsupportedError.CreateFmt(SUnsupportedAlgorithmInt, [FAlgorithm]);
  end;

end;

class function TElBuiltInHashFunction.IsAlgorithmSupported(Algorithm: integer): boolean;
begin
  Result := GetDigestSizeBits(Algorithm) > 0;
end;

class function TElBuiltInHashFunction.IsAlgorithmSupported(const OID : ByteArray): boolean;
var
  Alg : integer;
begin
  Alg := GetHashAlgorithmByOID(OID);
  Result := IsAlgorithmSupported(Alg);
end;

class function TElBuiltInHashFunction.GetDigestSizeBits(Algorithm: integer): integer;
begin
  Result := SBUtils.GetDigestSizeBits(Algorithm);
  if Result < 0 then
    raise EElHashFunctionUnsupportedError.CreateFmt(SUnsupportedAlgorithmInt, [Algorithm]);
end;

class function TElBuiltInHashFunction.GetDigestSizeBits(const OID : ByteArray): integer;
var
  Alg : integer;
begin
  Alg := GetHashAlgorithmByOID(OID);
  if Alg <> SB_ALGORITHM_UNKNOWN then
    Result := GetDigestSizeBits(Alg)
  else
    raise EElHashFunctionUnsupportedError.CreateFmt(SUnsupportedAlgorithmStr, [OIDToStr(OID)]);
end;

procedure TElBuiltInHashFunction.Reset;
begin
  InitializeDigest;
end;

procedure TElBuiltInHashFunction.Update(Buffer: pointer; Size: integer);
begin
  UpdateDigest(Buffer,  Size );
end;

procedure TElBuiltInHashFunction.Update(Stream: TElInputStream;
  Count: Int64  =  0);
var
  Buf :   array[0..32767] of byte  ;
  Read : integer;
begin
  if Count = 0 then
    Count := Stream. Size  - Stream.Position
  else
    Count := Min(Count, Stream. Size  - Stream.Position);
  while Count > 0 do
  begin
    Read := Stream.Read(Buf[0], Min(Count, Length(Buf)));
    UpdateDigest(@Buf[0], Read);
    Dec(Count, Read);
  end;
end;

function TElBuiltInHashFunction.Finish : ByteArray;
begin
  FinalizeDigest;
  Result := CloneArray(FDigest);
end;

function TElBuiltInHashFunction.Clone :  TElBuiltInHashFunction ;
var
  Res : TElBuiltInHashFunction;
begin
  Res := TElBuiltInHashFunction.Create(FAlgorithm, nil, FKeyMaterial);
  Res.FAlgorithm := FAlgorithm;
  Res.FUseHMAC := FUseHMAC;
  Res.FHMACBlockSize := FHMACBlockSize;  
  {$ifndef SB_NO_MD2}
  SBMove(FCtxMD2, Res.FCtxMD2, SizeOf(TMD2Context));
   {$endif}
  SBMove(FCtxMD5, Res.FCtxMD5, SizeOf(TMD5Context));
  SBMove(FCtxSHA1, Res.FCtxSHA1, SizeOf(TSHA1Context));
  SBMove(FCtxSHA256, Res.FCtxSHA256, SizeOf(TSHA256Context));
  SBMove(FCtxSHA512, Res.FCtxSHA512, SizeOf(TSHA512Context));
  SBMove(FCtxRMD160, Res.FCtxRMD160, SizeOf(TRMD160Context));
  Res.FDigest := CloneArray(FDigest);

  InitializeWhirlpool(Res.FCtxWhirlpool);
  SBMove(FCtxWhirlpool.BitsHashed[0], Res.FCtxWhirlpool.BitsHashed[0], Length(FCtxWhirlpool.BitsHashed));
  SBMove(FCtxWhirlpool.Buffer[0], Res.FCtxWhirlpool.Buffer[0], Length(FCtxWhirlpool.Buffer));
  SBMove(FCtxWhirlpool.State[0], Res.FCtxWhirlpool.State[0], Length(FCtxWhirlpool.State) * SizeOf(FCtxWhirlpool.State[0]));
  Res.FCtxWhirlpool.BufferSize := FCtxWhirlpool.BufferSize;

  {$ifndef SB_NO_UMAC}
  if Assigned(FCtxUMAC) then
  begin
    if Assigned(Res.FCtxUMAC) then
      FreeAndNil(Res.FCtxUMAC);
    Res.FCtxUMAC := (FCtxUMAC.Clone());
  end;
   {$endif}

  {$ifdef SB_HAS_GOST}
  if Assigned(FCtxGOST) then
  begin
    if Assigned(Res.FCtxGOST) then
      FreeAndNil(Res.FCtxGOST);

    if Self.FCtxGOST is TElGOSTMD then
      Res.FCtxGOST := TElGOSTMD.Create
    else
      Res.FCtxGOST := TElGOST.Create;

    Res.FCtxGOST.Clone(FCtxGOST);
  end;
   {$endif}
  
  Result := Res;
end;

procedure TElBuiltInHashFunction.SetHashFunctionProp(const PropID, Value : ByteArray);
begin
  {$ifdef SB_HAS_GOST}
  if FAlgorithm = SB_ALGORITHM_DGST_GOST_R3411_1994 then
  begin
    if CompareContent(PropID, SB_CTXPROP_GOSTR3411_1994_PARAMSET) then
    begin
      if CompareContent(Value, SB_OID_GOST_R3411_1994_PARAM_CP_TEST) then
        FCtxGOST.Init(TElGOST.MakeSubstBlock(SB_GOSTR3411_94_TestParamSet))
      else if CompareContent(Value, SB_OID_GOST_R3411_1994_PARAM_CP) then
        FCtxGOST.Init(TElGOST.MakeSubstBlock(SB_GOSTR3411_94_CryptoProParamSet))
      else
        raise EElHashFunctionError.Create(SInvalidPropertyValue);
    end
    else if CompareContent(PropID, SB_CTXPROP_GOSTR3411_1994_PARAMETERS) then
    begin
      if Length(Value) <> 128 then
        raise EElHashFunctionError.Create(SInvalidPropertyValue);

      FCtxGOST.Init(TElGOST.MakeSubstBlock(string(Value)));
    end;
  end;
   {$endif}
end;

function TElBuiltInHashFunction.GetHashFunctionProp(const PropID : ByteArray;
  const Default : ByteArray) : ByteArray;
begin
  Result := Default;
end;

////////////////////////////////////////////////////////////////////////////////
// TElBuiltInHMACKeyMaterial class

 destructor  TElBuiltInMACKey.Destroy;
begin
  ReleaseArray(FValue);
  ReleaseArray(FNonce);
  inherited;
end;

procedure TElBuiltInMACKey.Reset;
begin
  SetLength(FValue, 0);
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElBuiltInMACKey.Generate(Bits : integer;
  Params : TElCPParameters  =  nil;
  ProgressFunc : TSBProgressFunc  =  nil;
  ProgressData :  pointer   =  nil);
begin
  SetLength(FValue, ((Bits - 1) shr 3) + 1);
  SBRndGenerate(@FValue[0], Length(FValue));
end;
 {$endif SB_PGPSFX_STUB}

function TElBuiltInMACKey.GetIsPublic: boolean;
begin
  Result := true;
end;

function TElBuiltInMACKey.GetIsSecret: boolean;
begin
  Result := false;
end;

function TElBuiltInMACKey.GetIsExportable: boolean;
begin
  Result := true;
end;

function TElBuiltInMACKey.GetIsPersistent: boolean;
begin
  Result := false;
end;

function TElBuiltInMACKey.GetIsValid: boolean;
begin
  Result := true;
end;

function TElBuiltInMACKey.GetBits : integer;
begin
  Result := Length(FValue) shl 3;
end;

function TElBuiltInMACKey.GetAlgorithm : integer;
begin
  Result := 0;
end;

function TElBuiltInMACKey.GetKeyStorage : TElCustomCryptoKeyStorage;
begin
  Result := nil;
end;

function TElBuiltInMACKey.GetMode : integer;
begin
  Result := 0;
end;

procedure TElBuiltInMACKey.SetMode(Value : integer);
begin
  ;
end;

function TElBuiltInMACKey.GetIV : ByteArray;
begin
  Result := FNonce;
end;

procedure TElBuiltInMACKey.SetIV(const Value : ByteArray);
begin
  FNonce := CloneArray(Value);
end;

function TElBuiltInMACKey.GetValue : ByteArray;
begin
  Result := FValue;
end;

procedure TElBuiltInMACKey.SetValue(const Value : ByteArray);
begin
  FValue := CloneArray(Value);
end;

procedure TElBuiltInMACKey.ImportPublic(Buffer: pointer; Size: integer; Params : TElCPParameters = nil);
begin
  SetLength(FValue, Size);
  SBMove(Buffer^, FValue[0], Size);
end;

procedure TElBuiltInMACKey.ImportSecret(Buffer: pointer; Size: integer; Params : TElCPParameters = nil);
begin
  ;
end;

procedure TElBuiltInMACKey.ExportPublic(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil);
begin
  if (Size = 0) or (Buffer = nil) then
    Size := Length(FValue)
  else
  begin
    if Size >= Length(FValue) then
    begin
      Size := Length(FValue);
      SBMove(FValue[0], Buffer^, Size);
    end
    else
      raise EElBuiltInCryptoProviderError.Create(SBufferTooSmall);
  end;
end;

procedure TElBuiltInMACKey.ExportSecret(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil);
begin
  Size := 0;
end;

function TElBuiltInMACKey.Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoKey;
begin
  if not (FCryptoProvider is TElBuiltInCryptoProvider) then
    raise EElBuiltInCryptoProviderError.Create(SUnsupportedCryptoProvider);
  Result := TElBuiltInMACKey.Create(FCryptoProvider);
  TElBuiltInMACKey(Result).Value := CloneArray(FValue);
  TElBuiltInMACKey(Result).FNonce := CloneArray(FNonce);
end;

function TElBuiltInMACKey.Equals(Source : TElCustomCryptoKey; PublicOnly : boolean;
      Params : TElCPParameters  =  nil): boolean;
var
  B: ByteArray;
begin

  Result := false;
  if Self.Algorithm <> Source.Algorithm then exit;
  SetLength(B, 0);
  Result := true;
  B := TElBuiltInMACKey(Source).Value;
  Result := Result and  (Length(FValue) = Length(B)) and
     (CompareMem(@FValue[0], @B[0], Length(FValue)))
     ;
  B := TElBuiltInMACKey(Source).FNonce;
  Result := Result and (Length(FNonce) = Length(B)) and
     (CompareMem(@FNonce[0], @B[0], Length(FNonce)))
     ;

end;

function TElBuiltInMACKey.ClonePublic(Params : TElCPParameters  =  nil) : TElCustomCryptoKey;
begin
  Result := Clone(Params);
end;

procedure TElBuiltInMACKey.ClearPublic;
begin
  Reset;
end;

procedure TElBuiltInMACKey.ClearSecret;
begin
  ;
end;

function TElBuiltInMACKey.GetKeyProp(const PropID : ByteArray; const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif}  {$endif}): ByteArray;
begin
  Result := Default;
end;

procedure TElBuiltInMACKey.SetKeyProp(const PropID : ByteArray; const Value : ByteArray);
begin
  ;
end;

procedure TElBuiltInMACKey.ChangeAlgorithm(Algorithm : integer);
begin
  ;
end;


end.
