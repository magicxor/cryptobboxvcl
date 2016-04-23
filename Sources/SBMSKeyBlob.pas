(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBMSKeyBlob;

interface

uses
  SBTypes,
  SBUtils,
  SBAlgorithmIdentifier,
  SBConstants
  {$ifdef SB_HAS_GOST},
  SBGOST2814789
   {$endif}
  ;


const
  SB_MSKEYBLOB_ERROR_UNSUPPORTED_BLOB_TYPE      = Integer($2101);
  SB_MSKEYBLOB_ERROR_INVALID_FORMAT             = Integer($2102);
  SB_MSKEYBLOB_ERROR_UNSUPPORTED_VERSION        = Integer($2103);
  SB_MSKEYBLOB_ERROR_BUFFER_TOO_SMALL           = Integer($2104);
  SB_MSKEYBLOB_ERROR_NO_PRIVATE_KEY             = Integer($2105);
  SB_MSKEYBLOB_ERROR_UNSUPPORTED_ALGORITHM      = Integer($2106);

  SB_KEY_BLOB_RSA                               = 1;
  SB_KEY_BLOB_DSS                               = 2;

function WriteMSPublicKeyBlob(Buffer: pointer; Size: integer; OutBuffer: pointer;
  var OutSize : integer; BlobType : integer): boolean;
function WriteMSDSSPublicKeyBlob(P : pointer; PSize : integer; Q : pointer;
  QSize : integer; G : pointer; GSize : integer; Y : pointer; YSize : integer;
  OutBuffer : pointer; var OutSize : integer): boolean;

function ParseMSKeyBlob(Buffer : pointer; Size : integer; OutBuffer : pointer;
  var OutSize : integer; out BlobType : integer) : integer;

function WriteMSKeyBlob(Buffer : pointer; Size : integer; OutBuffer : pointer;
  var OutSize : integer; BlobType : byte) : boolean;
function WriteMSKeyBlobEx(Buffer : pointer; Size : integer; OutBuffer : pointer;
  var OutSize : integer; Algorithm : TElAlgorithmIdentifier) : boolean;

type
  EElMSKeyBlobError = class(ESecureBlackboxError);

implementation

uses
  SBRSA,
  SBDSA,
  SBASN1Tree,
  SysUtils,
  SBMath,
  SBStrUtils,
  SBRandom;

type
  PByte = ^byte;
  PWord = ^word;
  PLongword = ^cardinal;

const
  MS_SIMPLEKEYBLOB         = 1;
  MS_PUBLICKEYBLOB         = 6;
  MS_PRIVATEKEYBLOB        = 7;
  MS_PLAINTEXTKEYBLOB      = 8;
  MS_VERSION               = 2;
  MS_CP_VERSION            = $20; // CryptoPro key blob

function ParsePublicKeyStruc(Buffer : PByte; out BlobType : integer;
  out KeyAlg : cardinal) : integer;
begin
  if not (Buffer^ in [MS_SIMPLEKEYBLOB, MS_PUBLICKEYBLOB, MS_PRIVATEKEYBLOB,
    MS_PLAINTEXTKEYBLOB]) then
  begin
    Result := SB_MSKEYBLOB_ERROR_UNSUPPORTED_BLOB_TYPE;
    Exit;
  end;
  BlobType := Buffer^;
  Inc(Buffer);
  if (Buffer^ <> MS_VERSION) and (Buffer^ <> MS_CP_VERSION) then
  begin
    Result := SB_MSKEYBLOB_ERROR_UNSUPPORTED_VERSION;
    Exit;
  end;
  Inc(Buffer);
  if PWord(Buffer)^ <> 0 then
  begin
    Result := SB_MSKEYBLOB_ERROR_INVALID_FORMAT;
    Exit;
  end;
  Inc(Buffer, 2);
  KeyAlg := PLongword(Buffer)^;
  Result := 0;
end;

function ParseRSAPUBKEY(Buffer : PByte; BlobType : integer; out BitLen : cardinal;
  out PubExp : cardinal) : integer;
var
  Magic : cardinal;
begin
  Result := 0;
  Magic := PLongword(Buffer)^;
  if not (((Magic = $31415352) and (BlobType = MS_PUBLICKEYBLOB)) or
    ((Magic = $32415352) and (BlobType = MS_PRIVATEKEYBLOB))) then
  begin
    Result := SB_MSKEYBLOB_ERROR_INVALID_FORMAT;
    Exit;
  end;
  Inc(Buffer, 4);
  BitLen := PLongword(Buffer)^;
  Inc(Buffer, 4);
  PubExp := PLongword(Buffer)^;
end;

function WriteRSAPUBKEY(BlobType : integer; BitLen : cardinal; PubExp : cardinal;
  Buffer : pointer; var Size : integer): integer;
var
  Magic : cardinal;
  Needed : integer;
  Buf : PByte;
begin
  Needed := 12;
  if Size < Needed then
  begin
    Size := Needed;
    Result := SB_MSKEYBLOB_ERROR_BUFFER_TOO_SMALL;
    Exit;
  end;
  if BlobType = MS_PUBLICKEYBLOB then
    Magic := $31415352
  else if BlobType = MS_PRIVATEKEYBLOB then
    Magic := $32415352
  else
  begin
    Result := SB_MSKEYBLOB_ERROR_INVALID_FORMAT;
    Exit;
  end;
  Buf := Buffer;
  PLongword(Buf)^ := Magic;
  Inc(Buf, 4);
  PLongword(Buf)^ := BitLen;
  Inc(Buf, 4);
  PLongword(Buf)^ := PubExp;
  Size := Needed;
  Result := 0;
end;

function ParseDSSPUBKEY(Buffer : PByte; out BitLen : cardinal) : integer;
var
  Magic : cardinal;
begin
  Result := 0;
  Magic := PLongWord(Buffer)^;
  if (Magic <> $31535344) and (Magic <> $32535344) then
  begin
    Result := SB_MSKEYBLOB_ERROR_INVALID_FORMAT;
    Exit;
  end;
  Inc(Buffer, 4);
  BitLen := PLongWord(Buffer)^;
end;

function EncodeRSAPublicKey(Modulus : pointer; ModulusSize : integer; Exponent :
  pointer; ExponentSize : integer; OutBuffer : pointer; var OutSize : integer) :
  boolean;
var
  Tag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  S : ByteArray;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  Tag.TagId := SB_ASN1_SEQUENCE;
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;
  SetLength(S, ModulusSize);
  try
    SBMove(Modulus^, S[0], Length(S));
    if PByte(Modulus)^ >= $80 then
      S := SBConcatArrays(byte(0), S);

    STag.Content := S;
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.TagId := SB_ASN1_INTEGER;
    SetLength(S, ExponentSize);
    SBMove(Exponent^, S[0], Length(S));
    if PByte(Exponent)^ >= $80 then
      S := SBConcatArrays(byte(0), S);

    STag.Content := S;
    Result := Tag.SaveToBuffer(OutBuffer, OutSize);
  finally
    FreeAndNil(Tag);
  end;
end;

function DSS2PrivateKey(P : pointer; BytesInKey : integer; OutBuffer : pointer;
  var OutSize : integer) : integer;
var
  DP, DQ, DG, DX, DY : array of byte;
  I : integer;
  Ptr : ^byte;
  LA, LB, LC, LD : PLInt;
begin

  Ptr := P;
  SetLength(DP, BytesInKey);
  I := BytesInKey - 1;
  while I >= 0 do
  begin
    DP[I] := Ptr^;
    Inc(Ptr);
    Dec(I);
  end;
  SetLength(DQ, 20);
  I := 19;
  while I >= 0 do
  begin
    DQ[I] := Ptr^;
    Inc(Ptr);
    Dec(I);
  end;
  SetLength(DG, BytesInKey);
  I := BytesInKey - 1;
  while I >= 0 do
  begin
    DG[I] := Ptr^;
    Inc(Ptr);
    Dec(I);
  end;
  SetLength(DX, 20);
  I := 19;
  while I >= 0 do
  begin
    DX[I] := Ptr^;
    Inc(Ptr);
    Dec(I);
  end;
  { Checking whether we have enough space in output buffer}
  SetLength(DY, Length(DG) + 4);
  if not SBDSA.EncodePrivateKey(@DP[0], Length(DP), @DQ[0], Length(DQ), @DG[0],
    Length(DG), @DY[0], Length(DY), @DX[0], Length(DX), OutBuffer, OutSize) then
  begin
    Result := SB_MSKEYBLOB_ERROR_BUFFER_TOO_SMALL;
    Exit;
  end;
  { calculating Y }
  LCreate(LA);
  LCreate(LB);
  LCreate(LC);
  LCreate(LD);
  PointerToLInt(LA, @DX[0], Length(DX));
  PointerToLInt(LB, @DG[0], Length(DG));
  PointerToLInt(LC, @DP[0], Length(DP));
  LMModPower(LB, LA, LC, LD);
  SetLength(DY, LD^.Length shl 2);
  I := Length(DY);
  LIntToPointer(LD, @DY[0], I);
  LDestroy(LA);
  LDestroy(LB);
  LDestroy(LC);
  LDestroy(LD);
  if SBDSA.EncodePrivateKey(@DP[0], Length(DP), @DQ[0], Length(DQ), @DG[0],
    Length(DG), @DY[0], Length(DY), @DX[0], Length(DX), OutBuffer, OutSize) then
    Result := 0
  else
    Result := SB_MSKEYBLOB_ERROR_BUFFER_TOO_SMALL;

end;

function WriteDSSPrivateKey(Buffer: pointer; Size: integer; Dest : pointer) : integer;
var
  Ptr: ^byte;
  SizeP, SizeQ, SizeG, SizeY, SizeX : integer;
  BufP, BufQ, BufG, BufY, BufX : array of byte;
  I, Bits : integer;
begin

  Result := -1;
  SizeP := 0; SizeQ := 0; SizeG := 0; SizeX := 0; SizeY := 0;
  SBDSA.DecodePrivateKey(Buffer, Size, nil, SizeP, nil, SizeQ, nil, SizeG,
    nil, SizeY, nil, SizeX);
  if (SizeP <= 0) or (SizeQ <= 0) or (SizeG <= 0) or (SizeX <= 0) or (SizeY <= 0) then
    Exit;
  SetLength(BufP, SizeP);
  SetLength(BufQ, SizeQ);
  SetLength(BufG, SizeG);
  SetLength(BufY, SizeY);
  SetLength(BufX, SizeX);
  if not SBDSA.DecodePrivateKey(Buffer, Size, @BufP[0], SizeP, @BufQ[0], SizeQ, @BufG[0],
    SizeG, @BufY[0], SizeY, @BufX[0], SizeX) then
    Exit;
  SetLength(BufP, SizeP);
  SetLength(BufQ, SizeQ);
  SetLength(BufG, SizeG);
  SetLength(BufX, SizeX);
  while (BufP[0] = 0) do
    BufP := Copy(BufP, 1, Length(BufP));
  while (BufQ[0] = 0) and (Length(BufQ) > 20) do
    BufQ := Copy(BufQ, 1, Length(BufQ));
  while (BufG[0] = 0) and (Length(BufG) > Length(BufP)) do
    BufG := Copy(BufG, 1, Length(BufG));
  while (BufX[0] = 0) and (Length(BufX) > 20) do
    BufX := Copy(BufX, 1, Length(BufX));
  SizeP := Length(BufP);
  SizeQ := Length(BufQ);
  SizeG := Length(BufG);
  SizeX := Length(BufX);
  if (SizeG > SizeP) or (SizeQ > 20) or (SizeX > SizeQ) then
    Exit;
  Bits := SizeP shl 3;
  Ptr := Dest;
  PByteArray(Ptr)[0] := $44;
  PByteArray(Ptr)[1] := $53;
  PByteArray(Ptr)[2] := $53;
  PByteArray(Ptr)[3] := $32;
  PByteArray(Ptr)[4] := Bits and $ff;
  PByteArray(Ptr)[5] := (Bits shr 8) and $ff;
  PByteArray(Ptr)[6] := (Bits shr 16) and $ff;
  PByteArray(Ptr)[7] := (Bits shr 24) and $ff;
  Inc(Ptr, 8);
  // writing P
  for I := 0 to SizeP - 1 do
    PByteArray(Ptr)[I] := BufP[SizeP - I - 1];
  Inc(Ptr, SizeP);
  // writing Q
  for I := 0 to SizeQ - 1 do
    PByteArray(Ptr)[I] := BufQ[SizeQ - I - 1];
  Inc(Ptr, SizeQ);
  for I := 0 to 19 - SizeQ do
    PByteArray(Ptr)[I] := 0;
  Inc(Ptr, 20 - SizeQ);
  // writing G
  for I := 0 to SizeG - 1 do
    PByteArray(Ptr)[I] := BufG[SizeG - I - 1];
  Inc(Ptr, SizeG);
  for I := 0 to SizeP - SizeG - 1 do
    PByteArray(Ptr)[I] := 0;
  Inc(Ptr, SizeP - SizeG);
  // writing X
  for I := 0 to SizeX - 1 do
    PByteArray(Ptr)[I] := BufX[SizeX - I - 1];
  Inc(Ptr, SizeX);
  for I := 0 to 19 - SizeX do
    PByteArray(Ptr)[I] := 0;
  Inc(Ptr, 20 - SizeX);
  // writing seed
  PLongWord(Ptr)^ := $FFFFFFFF;
  Inc(Ptr, 4);
  for I := 0 to 19 do
    PByteArray(Ptr)[I] := SBRndGenerate(256);//Random(256);
  Inc(Ptr, 20);
  Result := PtrUInt(Ptr) - PtrUInt(Dest);

end;

function WriteRSAPrivateKey(Buffer: pointer; Size: integer; Dest : pointer) : integer;
var
  Ptr: ^byte;
  Tag : TElASN1ConstrainedTag;
  I, Bits : integer;
  TagS : TElASN1SimpleTag;
  S, T : ByteArray;
begin
  Result := -1;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if not Tag.LoadFromBuffer(Buffer, Size) then
      Exit;

    if (Tag.Count <> 1) or (not Tag.GetField(0).IsConstrained) or
      (TElASN1ConstrainedTag(Tag.GetField(0)).Count < 9) then
      Exit;

    for I := 0 to 8 do
      if TElASN1ConstrainedTag(Tag.GetField(0)).GetField(I).IsConstrained then
        Exit;

    TagS := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(1));
    S := TagS.Content;
    I := 0;
    while (I <= Length(S) - 1) and (S[I] = byte(0)) do
      Inc(I);
    S := CloneArray(S, I, Length(S) - I);
    Bits := Length(S) shl 3;
    Ptr := Dest;
    PByteArray(Ptr)[0] := $52;
    PByteArray(Ptr)[1] := $53;
    PByteArray(Ptr)[2] := $41;
    PByteArray(Ptr)[3] := $32;
    PByteArray(Ptr)[4] := Bits and $ff;
    PByteArray(Ptr)[5] := (Bits shr 8) and $ff;
    PByteArray(Ptr)[6] := (Bits shr 16) and $ff;
    PByteArray(Ptr)[7] := Bits shr 24;
    TagS := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(2));
    T := TagS.Content;
    if Length(T) > 4 then
      Exit;

    while Length(T) < 4 do
      T := SBConcatArrays(byte(0), T);
    PByteArray(Ptr)[8] := PByteArray(@T[0])[3];
    PByteArray(Ptr)[9] := PByteArray(@T[0])[2];
    PByteArray(Ptr)[10] := PByteArray(@T[0])[1];
    PByteArray(Ptr)[11] := PByteArray(@T[0])[0];
    Inc(Ptr, 12);
    // writing public modulus
    for I := 0 to Length(S) - 1 do
      PByteArray(Ptr)[I] := S[Length(S) - I - 1];
    Inc(Ptr, Length(S));
    // prime1
    TagS := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(4));
    T := TagS.Content;
    I := 0;
    while (I <= Length(T) - 1) and (T[I] = byte(0)) do
      Inc(I);
    T := CloneArray(T, I, Length(T) - I);
    while Length(T) < Bits shr 4 do
      T := SBConcatArrays(byte(0), T);

    for I := 0 to Length(T) - 1 do
      PByteArray(Ptr)[I] := T[Length(T) - I - 1];
    Inc(Ptr, Length(T));
    // prime2
    TagS := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(5));
    T := TagS.Content;
    I := 0;
    while (I <= Length(T) - 1) and (T[I] = byte(0)) do
      Inc(I);
    T := CloneArray(T, I, Length(T) - I);
    while Length(T) < Bits shr 4 do
      T := SBConcatArrays(byte(0), T);

    for I := 0 to Length(T) - 1 do
      PByteArray(Ptr)[I] := T[Length(T) - I - 1];

    Inc(Ptr, Length(T));
    // exponent1
    TagS := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(6));
    T := TagS.Content;
    I := 0;
    while (I <= Length(T) - 1) and (T[I] = byte(0)) do
      Inc(I);
    T := CloneArray(T, I, Length(T) - I);
    while Length(T) < Bits shr 4 do
      T := SBConcatArrays(byte(0), T);

    for I := 0 to Length(T) - 1 do
      PByteArray(Ptr)[I] := T[Length(T) - I - 1];
    Inc(Ptr, Length(T));
    // exponent2
    TagS := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(7));
    T := TagS.Content;
    I := 0;
    while (I <= Length(T) - 1) and (T[I] = byte(0)) do
      Inc(I);
    T := CloneArray(T, I, Length(T) - I);
    while Length(T) < Bits shr 4 do
      T := SBConcatArrays(byte(0), T);

    for I := 0 to Length(T) - 1 do
      PByteArray(Ptr)[I] := T[Length(T) - I - 1];
    Inc(Ptr, Length(T));
    // coeff
    TagS := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(8));
    T := TagS.Content;
    I := 0;
    while (I <= Length(T) - 1) and (T[I] = byte(0)) do
      Inc(I);
    T := CloneArray(T, I, Length(T) - I);
    while Length(T) < Bits shr 4 do
      T := SBConcatArrays(byte(0), T);

    for I := 0 to Length(T) - 1 do
      PByteArray(Ptr)[I] := T[Length(T) - I - 1];
    Inc(Ptr, Length(T));
    // priv exp
    TagS := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(3));
    T := TagS.Content;
    I := 0;
    while (I <= Length(T) - 1) and (T[I] = byte(0)) do
      Inc(I);
    T := CloneArray(T, I, Length(T) - 1);
    while Length(T) < Bits shr 3 do
      T := SBConcatArrays(byte(0), T);

    for I := 0 to Length(T) - 1 do
      PByteArray(Ptr)[I] := T[Length(T) - I - 1];
    Inc(Ptr, Length(T));
  finally
    FreeAndNil(Tag);
  end;
  Result := PtrUInt(Ptr) - PtrUInt(Dest);
end;

function EstimateBlobSize(Buffer: pointer; Size : integer; BlobType : byte) : integer;
var
  Tag : TElASN1ConstrainedTag;
  Sz : integer;
begin
  Result := 0;

  Tag := nil;
  try

    if BlobType = SB_KEY_BLOB_RSA then
    begin
      Tag := TElASN1ConstrainedTag.CreateInstance;

      if not Tag.LoadFromBuffer(Buffer, Size) then
        raise EElMSKeyBlobError.Create('');

      if (Tag.Count <> 1) or (not Tag.GetField(0).IsConstrained) then
        raise EElMSKeyBlobError.Create('');

      if TElASN1ConstrainedTag(Tag.GetField(0)).Count <> 9 then
        raise EElMSKeyBlobError.Create('');

      Sz := Length(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(1)).Content);
      Result := Sz * 5 + 16;
    end
    else
    if BlobType = SB_KEY_BLOB_DSS then
    begin
      Tag := TElASN1ConstrainedTag.CreateInstance;
      if not Tag.LoadFromBuffer(Buffer, Size) then
        raise EElMSKeyBlobError.Create('');

      if (Tag.Count <> 1) or (not Tag.GetField(0).IsConstrained) then
        raise EElMSKeyBlobError.Create('');

      if TElASN1ConstrainedTag(Tag.GetField(0)).Count <> 6 then
        raise EElMSKeyBlobError.Create('');

      Sz := Length(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(1)).Content);
      Result := Sz shl 1 + 96;
    end
    else
      Result := 0;
  finally
    if Tag <> nil then
     FreeAndNil(Tag);
  end;
end;

// ------------------------- HERE GO .NET FUNCTIONS ----------------------------


{$ifdef SB_HAS_GOST}
function WriteCPGOSTPrivateKey(Buffer: pointer; Size: integer;
  Dest : pointer; Algorithm : TElAlgorithmIdentifier) : integer;
var
  Tag, cTag : TElASN1ConstrainedTag;
  KeySize, MACSize : integer;
  UKM, MAC1, MAC2, Key, EncKey, KEK, DKEK, Buf : ByteArray;
const
  { hash of string 'password', for SB_OID_GOST_R3411_1994_PARAM_CP hash parameters }
  KEK_PASSWORD : array [0..31] of byte =
     ( $9D, $E7, $85, $F4, $79, $C3, $D3, $B2, $AB, $AB, $EF, $7F, $47, $38, $81, $7E,
     $10, $B6, $56, $F8, $54, $E6, $4D, $02, $3E, $C5, $89, $31, $D2, $46, $4D, $8F ) ;
begin
  if  Size  <> 32 then
  begin
    Result := 0;
    Exit;
  end;

  SetLength(UKM, 8);
  SetLength(MAC1, 4);
  SetLength(MAC2, 4);
  SetLength(Key, 32);
  SetLength(KEK, 32);
  SetLength(DKEK, 32);
  SetLength(EncKey, 32);

  SBRndGenerate(@UKM[0], 8);
  SBMove(Buffer^, Key[0], 32);
  SBMove(KEK_PASSWORD[0], KEK[0], 32);
  KeySize := 32;
  MACSize := 4;
  if not SBGOST2814789.KeyWrapCryptoPro(UKM, Key, KEK, EncKey, KeySize, MAC1, MACSize) then
  begin
    Result := 0;
    Exit;
  end;

  { we don't know yet which checksum is here }
  MAC2[0] := 0;
  MAC2[1] := 0;
  MAC2[2] := 0;
  MAC2[3] := 0;

  Tag := TElASN1ConstrainedTag.CreateInstance;
  Tag.TagId := SB_ASN1_SEQUENCE;
  try
    Tag.AddField(true);
    Tag.AddField(false);

    cTag := TElASN1ConstrainedTag(Tag.GetField(0));
    cTag.TagId := SB_ASN1_SEQUENCE;

    cTag.AddField(false);
    cTag.AddField(true);
    cTag.AddField(true);

    { UKM }
    TElASN1SimpleTag(cTag.GetField(0)).TagId := SB_ASN1_OCTETSTRING;
    TElASN1SimpleTag(cTag.GetField(0)).Content := (UKM);
    { Encrypted key }
    cTag := TElASN1ConstrainedTag(cTag.GetField(1));
    cTag.TagId := SB_ASN1_SEQUENCE;
    { key itself }
    cTag.AddField(false);
    cTag.GetField(0).TagId := SB_ASN1_OCTETSTRING;
    TElASN1SimpleTag(cTag.GetField(0)).Content := (EncKey);
    { MAC }
    cTag.AddField(false);
    cTag.GetField(1).TagId := SB_ASN1_OCTETSTRING;
    TElASN1SimpleTag(cTag.GetField(1)).Content := (MAC1);

    { A0 with key size and algorithm identifier }
    cTag := TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(2));
    cTag.TagId := SB_ASN1_A0;

    { key size ?}
    cTag.AddField(false);
    cTag.GetField(0).TagId := SB_ASN1_BITSTRING;
    TElASN1SimpleTag(cTag.GetField(0)).Content := {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}BytesOfString {$else}BufferType {$endif}(#$07#$80);

    { key algorithm identifier }
    cTag.AddField(true);
    Algorithm.SaveToTag(TElASN1ConstrainedTag(cTag.GetField(1)));

    { changing tag to A0, and removing hash paramset OID if needed }
    cTag.GetField(1).TagId := SB_ASN1_A0;
    if (TElASN1ConstrainedTag(cTag.GetField(1)).Count >= 2) and
      (TElASN1ConstrainedTag(TElASN1ConstrainedTag(cTag.GetField(1)).GetField(1)).Count = 3)
    then
      TElASN1ConstrainedTag(TElASN1ConstrainedTag(cTag.GetField(1)).GetField(1)).RemoveField(2);

    { saving MAC2 }
    TElASN1SimpleTag(Tag.GetField(1)).TagId := SB_ASN1_OCTETSTRING;
    TElASN1SimpleTag(Tag.GetField(1)).Content := (MAC2);

    KeySize := 0;
    Tag.SaveToBuffer( nil , KeySize);
    SetLength(Buf, KeySize);
    Tag.SaveToBuffer( @Buf[0] , KeySize);
    SetLength(Buf, KeySize);
  finally
    FreeAndNil(Tag);
  end;

  if KeySize <> 98 then
  begin
    Result := 0;
    Exit;
  end
  else
  begin
    SBMove(Buf[0], Dest^, KeySize);
    Result := 98;
  end;

end;
 {$endif}

function WriteMSKeyBlobEx(Buffer : pointer; Size : integer; OutBuffer : pointer;
  var OutSize : integer; Algorithm : TElAlgorithmIdentifier) : boolean;
const
  ALG_ID_CP_GOST3410 = $1E2E0000;
  ALG_ID_CP_GOST3410EL = $232E0000;
  CP_MAGIC = 'MAG1';
var
  Ptr : integer;
  OutBuf : ByteArray;
  Alg : cardinal;
begin

  SetLength(OutBuf, 0);
  if Algorithm is TElRSAAlgorithmIdentifier then
    Result := WriteMSKeyBlob(Buffer,  Size,  OutBuffer, OutSize, SB_KEY_BLOB_RSA)
  else if Algorithm is TElDSAAlgorithmIdentifier then
    Result := WriteMSKeyBlob(Buffer,  Size,  OutBuffer, OutSize, SB_KEY_BLOB_DSS)
  {$ifdef SB_HAS_GOST}  
  else if Algorithm is TElGOST3410AlgorithmIdentifier then
  begin
    if OutSize < 114 then
    begin
      OutSize := 114;
      Result := false;
      Exit;
    end;

    SetLength(OutBuf, 114);

    OutBuf[0] := 7;
    OutBuf[1] := 2;
    OutBuf[2] := 0;
    OutBuf[3] := 0;

    if CompareContent(Algorithm.AlgorithmOID, SB_OID_GOST_R3410_1994) then
      Alg := ALG_ID_CP_GOST3410
    else if CompareContent(Algorithm.AlgorithmOID, SB_OID_GOST_R3410_2001) then
      Alg := ALG_ID_CP_GOST3410EL
    else
      Alg := 0;

    OutBuf[4] := Alg shr 24;
    OutBuf[5] := (Alg shr 16) and $ff;
    OutBuf[6] := (Alg shr 8) and $ff;
    OutBuf[7] := Alg and $ff;
    OutBuf[8] := Ord(CP_MAGIC[1]);
    OutBuf[9] := Ord(CP_MAGIC[2]);
    OutBuf[10] := Ord(CP_MAGIC[3]);
    OutBuf[11] := Ord(CP_MAGIC[4]);
    OutBuf[12] := $20; // key size
    OutBuf[13] := 0;
    OutBuf[14] := 0;
    OutBuf[15] := 0;

    { next is ASN.1 encoding of encrypted GOST private key }
    Ptr := WriteCPGOSTPrivateKey(Buffer,  Size, @OutBuf[16] , Algorithm);
    
    if Ptr > 0 then
    begin
      OutSize := Ptr + 16;
      SBMove(OutBuf[0], OutBuffer^, OutSize);
      Result := true;
    end
    else
    begin
      Result := false;
      OutSize := 0;
    end;
  end
   {$endif}
  else
  begin
    Result := false;
    OutSize := 0;
    Exit;
  end;

end;

function ParseMSKeyBlob(Buffer : pointer; Size : integer; OutBuffer : pointer;
  var OutSize : integer; out BlobType : integer) : integer;
var
  P :  PByte; 
  KeyAlg, BitLen, PubExp : cardinal;
  PubExpBuf : array [0..3]  of byte;
  APubMod, APrivExp, APr1, APr2, AExp1, AExp2, ACoef : array of byte;
  UKM, KEK, Key, DKey, MAC, TmpBuf : ByteArray;
  I : integer;
const
  ALG_ID_RSA = $00A400;
  ALG_ID_RSA_SIG = $002400;
  ALG_ID_DSA = $002200;
  ALG_ID_CP_GOST3410 = $00002E1E;
  ALG_ID_CP_GOST3410EL = $00002E23;
  CP_MAGIC = 'MAG1';
  { hash of string 'password', for SB_OID_GOST_R3411_1994_PARAM_CP hash parameters }
  KEK_PASSWORD : array [0..31] of byte =
     ( $9D, $E7, $85, $F4, $79, $C3, $D3, $B2, $AB, $AB, $EF, $7F, $47, $38, $81, $7E,
     $10, $B6, $56, $F8, $54, $E6, $4D, $02, $3E, $C5, $89, $31, $D2, $46, $4D, $8F ) ;
begin
  
  

  SetLength(UKM, 0);
  SetLength(KEK, 0);
  SetLength(Key, 0);
  SetLength(DKey, 0);
  SetLength(MAC, 0);
  SetLength(TmpBuf, 0);
  if Size < 8 then
  begin
    Result := SB_MSKEYBLOB_ERROR_INVALID_FORMAT;
    Exit;
  end;

  P := Buffer;

  Result := ParsePublicKeyStruc(P, BlobType, KeyAlg);
  if Result <> 0 then
    Exit;
  Dec(Size, 8);
  Inc(P, 8);
  case BlobType of
    MS_PUBLICKEYBLOB, MS_PRIVATEKEYBLOB :
    begin
      if Size < 12 then
      begin
        Result := SB_MSKEYBLOB_ERROR_INVALID_FORMAT;
        Exit;
      end;
      if (KeyAlg = ALG_ID_RSA) or (KeyAlg = ALG_ID_RSA_SIG) then
      begin
        Result := ParseRSAPUBKEY(P, BlobType, BitLen, PubExp);
        if Result <> 0 then
          Exit;
        PubExpBuf[0] := PubExp shr 24;
        PubExpBuf[1] := (PubExp shr 16) and $FF;
        PubExpBuf[2] := (PubExp shr 8) and $FF;
        PubExpBuf[3] := PubExp and $FF;
        Dec(Size, 12);
        Inc(P, 12);
        if Size < integer(BitLen shr 3) then
        begin
          Result := SB_MSKEYBLOB_ERROR_INVALID_FORMAT;
          Exit;
        end;
        if BlobType = MS_PUBLICKEYBLOB then
        begin
          SetLength(APubMod, BitLen shr 3);
          for I := 0 to BitLen shr 3 - 1 do
            APubMod[I] := PByteArray(P)[integer(BitLen shr 3) - I - 1];
          if EncodeRSAPublicKey(@APubMod[0], BitLen shr 3, @PubExpBuf[0], 4, OutBuffer, OutSize) then
            Result := 0
          else
            Result := SB_MSKEYBLOB_ERROR_BUFFER_TOO_SMALL;
        end
        else
        begin
          if Size < integer(BitLen shr 1 + BitLen shr 4) then
          begin
            Result := SB_MSKEYBLOB_ERROR_INVALID_FORMAT;
            Exit;
          end;
          SetLength(APubMod, BitLen shr 3);
          SetLength(APrivExp, BitLen shr 3);
          SetLength(APr1, BitLen shr 4);
          SetLength(APr2, BitLen shr 4);
          SetLength(AExp1, BitLen shr 4);
          SetLength(AExp2, BitLen shr 4);
          SetLength(ACoef, BitLen shr 4);
          for I := 0 to BitLen shr 3 - 1 do
          begin
            APubMod[I] := PByteArray(P)[integer(BitLen shr 3) - I - 1];
            APrivExp[I] := PByteArray(P)[integer((BitLen shr 3) shl 1 + 5 * (BitLen shr 4)) - I - 1];
          end;
          for I := 0 to BitLen shr 4 - 1 do
          begin
            APr1[I] := PByteArray(P)[integer(BitLen shr 3 + BitLen shr 4) - I - 1];
            APr2[I] := PByteArray(P)[integer(BitLen shr 3 + (BitLen shr 4) shl 1) - I - 1];
            AExp1[I] := PByteArray(P)[integer(BitLen shr 3 + 3 * BitLen shr 4) - I - 1];
            AExp2[I] := PByteArray(P)[integer(BitLen shr 3 + (BitLen shr 4) shl 2) - I - 1];
            ACoef[I] := PByteArray(P)[integer(BitLen shr 3 + 5 * BitLen shr 4) - I - 1];
          end;
          if SBRSA.EncodePrivateKey(@APubMod[0], BitLen shr 3,
            @PubExpBuf[0], 4, @APrivExp[0], BitLen shr 3, @APr1[0], BitLen shr 4,
            @APr2[0], BitLen shr 4, @AExp1[0], BitLen shr 4, @AExp2[0], BitLen shr 4,
            @ACoef[0], BitLen shr 4, OutBuffer, OutSize)
          then
            Result := 0
          else
            Result := SB_MSKEYBLOB_ERROR_BUFFER_TOO_SMALL;
        end;
      end
      {$ifdef SB_HAS_GOST}
      else if KeyAlg = ALG_ID_DSA then
      begin
        ParseDSSPUBKEY(P, BitLen);
        Dec(Size, 8);
        Inc(P, 8);          // P[Size], Q[20], G[Size], X[20], [misc]
        I := BitLen shr 3;
        if Size < I shl 1 + 40 then
        begin
          Result := SB_MSKEYBLOB_ERROR_INVALID_FORMAT;
          Exit;
        end;
        Result := DSS2PrivateKey(P, I, OutBuffer, OutSize);
      end
      else if (KeyAlg = ALG_ID_CP_GOST3410) or (KeyAlg = ALG_ID_CP_GOST3410EL) then
      begin
        if OutSize < 32 then
        begin
          Result := SB_MSKEYBLOB_ERROR_BUFFER_TOO_SMALL;
          OutSize := 32;
          Exit;
        end;

        Result := SB_MSKEYBLOB_ERROR_INVALID_FORMAT;
        if (Size <> 106) then
          Exit;

        { checking for 'MAG1' }
        SetLength(TmpBuf, 4);
        SBMove(P^, TmpBuf[0], 4);
        Inc(P, 4);
        if not (CompareMem(TmpBuf, BytesOfString(CP_MAGIC), 4))then
          Exit;

        SBMove(P^, TmpBuf[0], 4);
        Inc(P, 4);

        { checking key size}
        if TmpBuf[0] <> $20 then
          Exit;

        { we are not parsing whole ASN.1 structure here, just loading needed chunks }
        SetLength(UKM, 8);
        SetLength(MAC, 4);
        SetLength(KEK, 32);
        SetLength(Key, 32);
        SetLength(DKey, 32);

        SBMove(PByteArray(P)^[6], UKM[0], 8);
        SBMove(PByteArray(P)^[18], Key[0], 32);
        SBMove(PByteArray(P)^[52], MAC[0], 4);
        SBMove(KEK_PASSWORD[0], KEK[0], 32);

        if not SBGOST2814789.KeyUnwrapCryptoPro(UKM, Key, KEK, MAC, DKey, Size) then
          Exit;

        SBMove(DKey[0], OutBuffer^, 32);
        OutSize := 32;
        Result := 0;        
      end
       {$endif};
    end;
    else
    begin
      if OutSize < Size then
        Result := SB_MSKEYBLOB_ERROR_BUFFER_TOO_SMALL
      else
      begin
        SBMove(Buffer^, OutBuffer^, Size);
        Result := 0;
      end;
      OutSize := Size;
    end;
  end;

end;

function WriteMSKeyBlob(Buffer : pointer; Size : integer; OutBuffer : pointer;
  var OutSize : integer; BlobType : byte) : boolean;
var
  Ptr :  ^byte ;
  Sz, EstSize : integer;
  alg : cardinal;
const
  ALG_ID_RSA = $00A40000;
  ALG_ID_DSA = $00220000;
begin
  // estimating size
  try
    EstSize := EstimateBlobSize(Buffer,  Size,  BlobType);
  except
    OutSize := 0;
    Result := false;
    Exit;
  end;

  if EstSize > OutSize then
  begin
    OutSize := EstSize;
    Result := false;
    Exit;
  end;

  Ptr := OutBuffer;
  PByteArray(Ptr)[0] := 7;
  PByteArray(Ptr)[1] := 2;
  PByteArray(Ptr)[2] := 0;
  PByteArray(Ptr)[3] := 0;
  // following 4 bytes is alg-id (rsa/dss)
  if BlobType = SB_KEY_BLOB_DSS then
    alg := ALG_ID_DSA
  else if BlobType = SB_KEY_BLOB_RSA then
    alg := ALG_ID_RSA
  else
    alg := 0;
  PByteArray(Ptr)[4] := alg shr 24;
  PByteArray(Ptr)[5] := (alg shr 16) and $ff;
  PByteArray(Ptr)[6] := (alg shr 8) and $ff;
  PByteArray(Ptr)[7] := alg and $ff;
  Inc(Ptr, 8);

  if alg = ALG_ID_DSA then
    Sz := WriteDSSPrivateKey(Buffer,  Size,  Ptr)
  else if alg = ALG_ID_RSA then
    Sz := WriteRSAPrivateKey(Buffer,  Size,  Ptr)
  else
    Sz := -1;

  if Sz <> -1 then
  begin
    OutSize := 8 + Sz;
    Result := true
  end
  else
    Result := false;
end;

function WriteMSPublicKeyBlob(Buffer: pointer; Size: integer; OutBuffer: pointer;
  var OutSize : integer; BlobType : integer): boolean;
var
  OrigPtr, Ptr : integer;
  Sz, EstSize : integer;
  alg : cardinal;
  M, E : ByteArray;
  MSize, ESize : integer;
  AlgID : ByteArray;
  PubExp : cardinal;
  I, ShlCoeff : integer;
const
  ALG_ID_RSA = $00A40000;
  ALG_ID_DSA = $00220000;
begin
  

  AlgID := EmptyArray;
  Result := false;
  // only RSA Blobs are supported by this function
  if BlobType <> SB_KEY_BLOB_RSA then
  begin
    OutSize := 0;
    Exit;
  end;
  // estimating size
  EstSize := 1024 + Size shl 1; 
  if EstSize > OutSize then
  begin
    OutSize := EstSize;
    Exit;
  end;
  Ptr :=  0 ;
  OrigPtr := Ptr;
  PByteArray(OutBuffer)[Ptr + 0] := 6;
  PByteArray(OutBuffer)[Ptr + 1] := 2;
  PByteArray(OutBuffer)[Ptr + 2] := 0;
  PByteArray(OutBuffer)[Ptr + 3] := 0;
  // following 4 bytes is alg-id (rsa/dss)
  if BlobType = SB_KEY_BLOB_DSS then
    alg := ALG_ID_DSA
  else if BlobType = SB_KEY_BLOB_RSA then
    alg := ALG_ID_RSA
  else
    alg := 0;
  PByteArray(OutBuffer)[Ptr + 4] := alg shr 24;
  PByteArray(OutBuffer)[Ptr + 5] := (alg shr 16) and $ff;
  PByteArray(OutBuffer)[Ptr + 6] := (alg shr 8) and $ff;
  PByteArray(OutBuffer)[Ptr + 7] := alg and $ff;
  Inc(Ptr, 8);
  if alg = ALG_ID_RSA then
  begin
    MSize := 0;
    SBRSA.DecodePublicKey(Buffer, Size, nil, MSize, nil, ESize, AlgID, true);
    SetLength(M, MSize);
    SetLength(E, ESize);
    if not SBRSA.DecodePublicKey(Buffer, Size, @M[0], MSize, @E[0], ESize, AlgID, true) then
      Exit;
    SetLength(M, MSize);
    M := TrimZeros(M);
    MSize := Length(M);
    PubExp := 0;
    I := ESize - 1;
    ShlCoeff := 0;
    while (I >= 0) do
    begin
      PubExp := PubExp or (E[I] shl ShlCoeff);
      Inc(ShlCoeff, 8);
      Dec(I);
    end;
    Sz := 12;
    WriteRSAPUBKEY(MS_PUBLICKEYBLOB, MSize shl 3, PubExp,
      @PByteArray(OutBuffer)[Ptr],
      Sz);
    Inc(Ptr, Sz);
    for I := 0 to MSize - 1 do
      PByteArray(OutBuffer)[Ptr + I] := M[MSize - I - 1];
    Inc(Ptr, MSize);
    OutSize := Ptr - OrigPtr;
    Result := true;
  end;

end;

function WriteMSDSSPublicKeyBlob(P : pointer; PSize : integer; Q : pointer;
  QSize : integer; G : pointer; GSize : integer; Y : pointer; YSize : integer;
  OutBuffer : pointer; var OutSize : integer): boolean;
var
  EstSize : integer;
  alg, bits, bytes : cardinal;
  Ptr, OrigPtr : integer;
  Idx : integer;
  I : integer;
const
  ALG_ID_DSA = $00220000;
  DSSMagic = $31535344;
begin
  Result := false;
  // estimating size
  EstSize := 1024 + PSize + QSize + GSize + YSize;
  if EstSize > OutSize then
  begin
    OutSize := EstSize;
    Exit;
  end;
  Ptr :=  0 ;
  OrigPtr := Ptr;
  PByteArray(OutBuffer)[Ptr + 0] := 6;
  PByteArray(OutBuffer)[Ptr + 1] := 2;
  PByteArray(OutBuffer)[Ptr + 2] := 0;
  PByteArray(OutBuffer)[Ptr + 3] := 0;
  // following 4 bytes is alg-id (rsa/dss)
  alg := ALG_ID_DSA;
  PByteArray(OutBuffer)[Ptr + 4] := alg shr 24;
  PByteArray(OutBuffer)[Ptr + 5] := (alg shr 16) and $ff;
  PByteArray(OutBuffer)[Ptr + 6] := (alg shr 8) and $ff;
  PByteArray(OutBuffer)[Ptr + 7] := alg and $ff;
  Inc(Ptr, 8);
  // DSSPUBKEY
  PByteArray(OutBuffer)[Ptr + 0] := DSSMagic and $ff;
  PByteArray(OutBuffer)[Ptr + 1] := (DSSMagic shr 8) and $ff;
  PByteArray(OutBuffer)[Ptr + 2] := (DSSMagic shr 16) and $ff;
  PByteArray(OutBuffer)[Ptr + 3] := (DSSMagic shr 24) and $ff;
  Idx := 0;
  while (Idx < PSize) and (PByteArray(P)[Idx] = 0) do
    Inc(Idx);
  bytes := (PSize - Idx);
  bits := bytes shl 3;
  PByteArray(OutBuffer)[Ptr + 4] := bits and $ff;
  PByteArray(OutBuffer)[Ptr + 5] := (bits shr 8) and $ff;
  PByteArray(OutBuffer)[Ptr + 6] := (bits shr 16) and $ff;
  PByteArray(OutBuffer)[Ptr + 7] := (bits shr 24) and $ff;
  Inc(Ptr, 8);
  // Key values
  FillChar(PByteArray(OutBuffer)[Ptr], Bytes * 3 + 20, 0);
  // P
  for I := 0 to bytes - 1 do
    PByteArray(OutBuffer)[Ptr + I] := PByteArray(P)[PSize - I - 1];
  Inc(Ptr, bytes);
  // Q
  for I := 0 to Min(19, QSize - 1) do
    PByteArray(OutBuffer)[Ptr + I] := PByteArray(Q)[QSize - I - 1];
  Inc(Ptr, 20);
  // G
  for I := 0 to Min(bytes, GSize) - 1 do
    PByteArray(OutBuffer)[Ptr + I] := PByteArray(G)[GSize - I - 1];
  Inc(Ptr, bytes);
  // Y
  for I := 0 to Min(bytes, YSize) - 1 do
    PByteArray(OutBuffer)[Ptr + I] := PByteArray(Y)[YSize - I - 1];
  Inc(Ptr, bytes);
  // DSSSEED
  // counter
  PByteArray(OutBuffer)[Ptr + 0] := $ff;
  PByteArray(OutBuffer)[Ptr + 1] := $ff;
  PByteArray(OutBuffer)[Ptr + 2] := $ff;
  PByteArray(OutBuffer)[Ptr + 3] := $ff;
  Inc(Ptr, 4);
  // seed
  FillChar(PByteArray(OutBuffer)[Ptr], 20, 0);
  Inc(Ptr, 20);
  OutSize := Ptr - OrigPtr;
  Result := true;
end;


end.
