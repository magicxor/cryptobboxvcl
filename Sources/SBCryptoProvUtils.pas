(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBCryptoProvUtils;

interface

uses
  SysUtils,
  SBCryptoProv,
  SBASN1,
  SBASN1Tree,
  SBTypes,
  SBUtils,
  SBConstants;


function CryptoProvGetBoolParam(Params : TElCPParameters; const Name : ByteArray;
  Default: boolean): boolean;
function GetIntegerPropFromBuffer(const Value : ByteArray;
  Default : integer  =  0): integer; 
function GetInt64PropFromBuffer(const Value : ByteArray;
  Default : integer  =  0): int64; 
function GetBufferFromInteger(Value : integer): ByteArray;
function GetBufferFromInt64(Value : Int64): ByteArray;
function GetBoolFromBuffer(const Value: ByteArray; Default : boolean  =  false) : boolean;
function GetBufferFromBool(Value : boolean): ByteArray;
function GetPointerFromBuffer(const Value : ByteArray):   pointer  ;
function GetBufferFromPointer(Value :   pointer  ): ByteArray;

function ExtractSymmetricCipherParams(const AlgOID, AlgParams: ByteArray;
  var KeyLen : integer; var IV : ByteArray): boolean;

function SerializeParams(Params : TElCPParameters): ByteArray;
function UnserializeParams(Buffer : pointer; Size : integer): TElCPParameters;

function IsKeyDrivenOperation(OpType : integer): boolean; 
function IsSecretKeyOperation(OpType : integer): boolean; 
function IsAlgorithmIndependentOperation(OpType : integer): boolean; 

implementation

const
  SB_BOOL_TRUE = 1;
  SB_BOOL_FALSE = 0;

const
  RC2Identifiers2KeyLength : array[0..255] of byte =  ( 
    $5D, $BE, $9B, $8B, $11, $99, $6E, $4D, $59, $F3, $85, $A6, $3F, $B7, $83, $C5,
    $E4, $73, $6B, $3A, $68, $5A, $C0, $47, $A0, $64, $34, $0C, $F1, $D0, $52, $A5,
    $B9, $1E, $96, $43, $41, $D8, $D4, $2C, $DB, $F8, $07, $77, $2A, $CA, $EB, $EF,
    $10, $1C, $16, $0D, $38, $72, $2F, $89, $C1, $F9, $80, $C4, $6D, $AE, $30, $3D,
    $CE, $20, $63, $FE, $E6, $1A, $C7, $B8, $50, $E8, $24, $17, $FC, $25, $6F, $BB,
    $6A, $A3, $44, $53, $D9, $A2, $01, $AB, $BC, $B6, $1F, $98, $EE, $9A, $A7, $2D,
    $4F, $9E, $8E, $AC, $E0, $C6, $49, $46, $29, $F4, $94, $8A, $AF, $E1, $5B, $C3,
    $B3, $7B, $57, $D1, $7C, $9C, $ED, $87, $40, $8C, $E2, $CB, $93, $14, $C9, $61,
    $2E, $E5, $CC, $F6, $5E, $A8, $5C, $D6, $75, $8D, $62, $95, $58, $69, $76, $A1,
    $4A, $B5, $55, $09, $78, $33, $82, $D7, $DD, $79, $F5, $1B, $0B, $DE, $26, $21,
    $28, $74, $04, $97, $56, $DF, $3C, $F0, $37, $39, $DC, $FF, $06, $A4, $EA, $42,
    $08, $DA, $B4, $71, $B0, $CF, $12, $7A, $4E, $FA, $6C, $1D, $84, $00, $C8, $7F,
    $91, $45, $AA, $2B, $C2, $B1, $8F, $D5, $BA, $F2, $AD, $19, $B2, $67, $36, $F7,
    $0F, $0A, $92, $7D, $E3, $9D, $E9, $90, $3E, $23, $27, $66, $13, $EC, $81, $15,
    $BD, $22, $BF, $9F, $7E, $A9, $51, $4B, $4C, $FB, $02, $D3, $70, $86, $31, $E7,
    $3B, $05, $03, $54, $60, $48, $65, $18, $D2, $CD, $5F, $32, $88, $0E, $35, $FD
   ) ;

function CryptoProvGetParamValue(Params : TElCPParameters; const Name : ByteArray): ByteArray;
var
  I : integer;
begin
  Result := EmptyArray;
  if Params <> nil then
  begin
    for I := 0 to Params.Count - 1 do
    begin
      if CompareContent(Params.OIDs[I], Name) then
      begin
        Result := CloneArray(Params.Values[I]);
        Break;
      end;
    end;
  end;
end;

function CryptoProvGetBoolParam(Params : TElCPParameters; const Name : ByteArray;
  Default: boolean): boolean;
var
  S : ByteArray;
begin
  S := CryptoProvGetParamValue(Params, Name);
  if Length(S) > 0 then
    Result := S[0] = byte(SB_BOOL_TRUE)
  else
    Result := Default;
end;

function GetIntegerPropFromBuffer(const Value : ByteArray;
  Default : integer  =  0): integer;
begin
  if Length(Value) = 4 then
    Result := (PByte(@Value[0])^ shl 24) or (PByte(@Value[0 + 1])^ shl 16) or
      (PByte(@Value[0 + 2])^ shl 8) or PByte(@Value[0 + 3])^
  else
    Result := Default;
end;

function GetInt64PropFromBuffer(const Value : ByteArray;
  Default : integer  =  0): int64;
begin
  if Length(Value) = 8 then
    Result := GetInt64BEFromByteArray(Value, 0)
  else
    Result := Default;
end;

function GetBufferFromInteger(Value : integer): ByteArray;
begin
  result := GetBytes32(Value);
end;

function GetBufferFromInt64(Value : int64): ByteArray;
begin
  result := GetBytes64(Value);
end;

function GetBoolFromBuffer(const Value: ByteArray; Default : boolean  =  false) : boolean;
begin
  if Length(Value) = 1 then
  begin
    if Value[0] = byte(SB_BOOL_TRUE) then
      Result := true
    else
    if Value[0] = byte(SB_BOOL_FALSE) then
      Result := false
    else
      Result := Default;
  end
  else
    Result := Default;
end;

function GetBufferFromBool(Value : boolean): ByteArray;
begin
  if Value then
    Result := GetByteArrayFromByte(SB_BOOL_TRUE)
  else
    Result := GetByteArrayFromByte(SB_BOOL_FALSE);
end;

function GetPointerFromBuffer(const Value : ByteArray):   pointer  ;
var
  V : Int64;
  I, K : integer;
begin
  V := 0;
  K := 0;
  for I := Length(Value) -1 downto 0 do
  begin
    V := V or (Int64(Value[I]) shl (K shl 3));
    Inc(K);
  end;
  Result := pointer(V);
end;

function GetBufferFromPointer(Value :   pointer  ): ByteArray;
var
  V : Int64;
  Tmp : ByteArray;
begin
  V := Int64(Value);
  Result := EmptyArray;
  while V > 0 do
  begin
    Tmp := Result;
    Result := SBConcatArrays(Byte(V and $ff), Tmp);
    ReleaseArray(Tmp);
    V := V shr 8;
  end;
  while Length(Result) < 8 do
  begin
    Tmp := Result;
    Result := SBConcatArrays(byte(0), Tmp);
    ReleaseArray(Tmp);
  end;
end;

function GetRC2KeyLengthByIdentifier(const Id : ByteArray) : cardinal;
begin
  if Length(Id) > 1 then
    Result := RC2Identifiers2KeyLength[PByte(@Id[Length(Id) - 1])^]
  else
  if Length(Id) = 1 then
    Result := RC2Identifiers2KeyLength[PByte(@Id[0])^]
  else
    Result := RC2Identifiers2KeyLength[0];
end;

function ExtractSymmetricCipherParams(const AlgOID, AlgParams: ByteArray;
  var KeyLen : integer; var IV : ByteArray): boolean;
var
  Alg : integer;
  Tag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
begin
  // RC4: no parameters
  // RC2: special processing (includes effective key length)
  // Other: IV OCTET STRING
  Result := false;
  Alg := GetAlgorithmByOID(AlgOID);
  KeyLen := 0;
  if Alg <> SB_ALGORITHM_CNT_RC4 then
  begin
    Tag := TElASN1ConstrainedTag.CreateInstance();
    try
      if Tag.LoadFromBuffer(@AlgParams[0], Length(AlgParams)) then
      begin
        if (Alg = SB_ALGORITHM_CNT_RC2) and (Tag.Count > 0) then
        begin
          if Tag.GetField(0).IsConstrained then
          begin
            if (Tag.GetField(0).TagId <> SB_ASN1_SEQUENCE) or (TElASN1ConstrainedTag(Tag.GetField(0)).Count <> 2) then
              Exit;
            if (TElASN1ConstrainedTag(Tag.GetField(0)).GetField(0).IsConstrained <> false) or
              (TElASN1ConstrainedTag(Tag.GetField(0)).GetField(1).IsConstrained <> false) then
              Exit;
            STag := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(0));
            if (STag.TagId <> SB_ASN1_INTEGER) then
              Exit;
            KeyLen := GetRC2KeyLengthByIdentifier(STag.Content);
            STag := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(1));
            if (STag.TagId <> SB_ASN1_OCTETSTRING) then
              Exit;
            if Length(STag.Content) <> 8 then
              Exit;
            SetLength(IV, 8);
            SBMove(STag.Content[0], IV[0], 8);
            Result := true;
          end
          else
          begin
            STag := TElASN1SimpleTag(Tag.GetField(0));
            if STag.TagId <> SB_ASN1_OCTETSTRING then
              Exit;
            if Length(STag.Content) <> 8 then
              Exit;
            KeyLen := 32;
            SetLength(IV, 8);
            SBMove(STag.Content[0], IV[0], 8);
            Result := true;
          end;
        end
        else
        begin
          if (Tag.Count > 0) and (Tag.GetField(0).CheckType(SB_ASN1_OCTETSTRING, false)) then
            IV := TElASN1SimpleTag(Tag.GetField(0)).Content;
          Result := true;
        end;
      end;
    finally
      FreeAndNil(Tag);
    end;
  end;

end;

function SerializeParams(Params : TElCPParameters): ByteArray;
var
  Tag : TElASN1ConstrainedTag;
  Size : integer;
begin
  if Params <> nil then
  begin
    Tag := TElASN1ConstrainedTag.CreateInstance();
    try
      Params.SaveToTag(Tag);
      Size := 0;
      Tag.SaveToBuffer( nil , Size);
      SetLength(Result, Size);
      Tag.SaveToBuffer( @Result[0] , Size);
      SetLength(Result, Size);
    finally
      FreeAndNil(Tag);
    end;
  end
  else
    Result := EmptyArray;
end;

function UnserializeParams(Buffer : pointer; Size : integer): TElCPParameters;
var
  Tag : TElASN1ConstrainedTag;
begin
  Result := nil;
  if (Buffer = nil) or (Size = 0) then
    Exit;
  Tag := TElASN1ConstrainedTag.CreateInstance();
  try
    if Tag.LoadFromBuffer(Buffer, Size) then
    begin
      if (Tag.Count > 0) and (Tag.GetField(0).IsConstrained) then
      begin
        try
          Result := TElCPParameters.Create();
          if not Result.LoadFromTag(TElASN1ConstrainedTag(Tag.GetField(0))) then
            FreeAndNil(Result);
        except
          FreeAndNil(Result);
        end;
      end;
    end;
  finally
    FreeAndNil(Tag);
  end;
end;


function IsKeyDrivenOperation(OpType : integer): boolean;
begin
  // This method is suitable for use in most of cryptoproviders. However,
  // if YOUR cryptoprovider implements special functionality
  // (e.g., encryption without a key), this method will not work correctly for you.
  Result := OpType in [SB_OPTYPE_ENCRYPT, SB_OPTYPE_DECRYPT, SB_OPTYPE_SIGN,
    SB_OPTYPE_SIGN_DETACHED, SB_OPTYPE_VERIFY, SB_OPTYPE_VERIFY_DETACHED,
    SB_OPTYPE_KEY_GENERATE, SB_OPTYPE_KEY_DECRYPT];
end;

function IsSecretKeyOperation(OpType : integer): boolean;
begin
  Result := OpType in [SB_OPTYPE_DECRYPT, SB_OPTYPE_SIGN,
    SB_OPTYPE_SIGN_DETACHED, SB_OPTYPE_KEY_DECRYPT];
end;

function IsAlgorithmIndependentOperation(OpType : integer): boolean;
begin
  Result := OpType in [SB_OPTYPE_NONE, SB_OPTYPE_RANDOM, SB_OPTYPE_KEYSTORAGE_CREATE];
end;

end.
