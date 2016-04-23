(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBDSA;

interface

uses
  SBMath,
  SBConstants,
  SBHashFunction,
  SBTypes,
  SBStrUtils,
  SBUtils;


function ValidateSignature(Hash : pointer; HashSize : integer; P : pointer;
  PSize : integer; Q : pointer; QSize : integer; G : pointer; GSize : integer;
  Y : pointer; YSize : integer; R : pointer; RSize : integer; S : pointer;
  SSize : integer) : boolean;

function Generate(Bits : integer; P : pointer; var PSize : integer; Q : pointer;
  var QSize : integer; G : pointer; var GSize : integer; Y : pointer;
  var YSize : integer; X : pointer; var XSize : integer) : boolean;  overload;  

function ExternalGenerate(Bits : integer; P : pointer; var PSize : integer; Q : pointer;
  var QSize : integer; G : pointer; var GSize : integer; Y : pointer;
  var YSize : integer; X : pointer; var XSize : integer) : boolean;  overload;  

function Generate(Bits : integer; P : pointer; var PSize : integer; Q : pointer;
  var QSize : integer; G : pointer; var GSize : integer; Y : pointer;
  var YSize : integer; X : pointer; var XSize : integer; PrivateKeyBlob : pointer;
  var PrivateKeyBlobSize : integer; ProgressFunc : TSBMathProgressFunc = nil;
  Data : pointer = nil) : boolean;  overload;  

function ExternalGenerate(Bits : integer; P : pointer; var PSize : integer; Q : pointer;
  var QSize : integer; G : pointer; var GSize : integer; Y : pointer;
  var YSize : integer; X : pointer; var XSize : integer; PrivateKeyBlob : pointer;
  var PrivateKeyBlobSize : integer; ProgressFunc : TSBMathProgressFunc = nil;
  Data : pointer = nil) : boolean;  overload;  

function GenerateEx(PBits, QBits : integer; P : pointer; var PSize : integer; Q : pointer;
  var QSize : integer; G : pointer; var GSize : integer; Y : pointer;
  var YSize : integer; X : pointer; var XSize : integer;
  ProgressFunc : TSBMathProgressFunc = nil; Data : pointer = nil) : boolean;  overload;  

function ExternalGenerateEx(PBits, QBits : integer; P : pointer; var PSize : integer; Q : pointer;
  var QSize : integer; G : pointer; var GSize : integer; Y : pointer;
  var YSize : integer; X : pointer; var XSize : integer;
  ProgressFunc : TSBMathProgressFunc = nil; Data : pointer = nil) : boolean;  overload;  

function Sign(Hash : pointer; HashSize : integer; P : pointer; PSize : integer;
  Q : pointer; QSize : integer; G : pointer; GSize : integer; X : pointer;
  XSize : integer; R : pointer; var RSize : integer; S : pointer;
  var SSize : integer) : boolean;

function SignEx(Hash : pointer; HashSize : integer; P : pointer; PSize : integer;
  Q : pointer; QSize : integer; G : pointer; GSize : integer; X : pointer;
  XSize : integer; R : pointer; var RSize : integer; S : pointer;
  var SSize : integer) : boolean;

function DecodePrivateKey(Buffer : pointer; Size : integer; P : pointer;
  var PSize : integer; Q : pointer; var QSize : integer; G : pointer;
  var GSize : integer; Y : pointer; var YSize : integer; X : pointer;
  var XSize : integer) : boolean;

function EncodePrivateKey(P : pointer; PSize : integer; Q : pointer; QSize :
  integer; G : pointer; GSize : integer; Y : pointer; YSize : integer;
  X : pointer; XSize : integer; OutBuffer : pointer; var OutSize : integer) : boolean;

function EncodeSignature(R : pointer; RSize : integer; S : pointer; SSize :
  integer; Blob: pointer; var BlobSize : integer) : boolean;

function DecodeSignature(Blob : pointer; Size : integer; R : pointer;
  var RSize : integer; S : pointer; var SSize : integer) : boolean;

function IsValidKey(P : pointer; PSize : integer; Q : pointer; QSize : integer;
  G : pointer; GSize : integer; Y : pointer; YSize : integer;
  X : pointer; XSize : integer; Secret : boolean;
  StrictMode : boolean = false) : boolean;


function ExternalGenerationSupported : boolean; 

(*
procedure GenerateDSAQ(var Q: PLInt; var Seed: ByteArray); {$ifdef SB_NET}public;{$endif}
procedure GenerateDSAP(var P: PLInt; Q: PLInt; var RandCtx : TRC4RandomContext; var B: PLint; Bits: integer); {$ifdef SB_NET}public;{$endif}
*)

implementation

uses
   SysUtils, 
  SBASN1,
  SBASN1Tree,
  SBSHA,
  SBRandom;

function ValidateSignature(Hash : pointer; HashSize : integer; P : pointer;
  PSize : integer; Q : pointer; QSize : integer; G : pointer; GSize : integer;
  Y : pointer; YSize : integer; R : pointer; RSize : integer; S : pointer;
  SSize : integer) : boolean;
var
  LM, LP, LQ, LG, LY, LR, LS, LTmp, LW : PLInt;
  I : integer;
begin
  LCreate(LM);
  LCreate(LP);
  LCreate(LQ);
  LCreate(LG);
  LCreate(LY);
  LCreate(LR);
  LCreate(LS);
  LCreate(LTmp);
  LCreate(LW);
  try
     PointerToLIntP (LM, Hash , HashSize );
     PointerToLIntP (LP, P , PSize );
     PointerToLIntP (LQ, Q , QSize );
     PointerToLIntP (LG, G , GSize );
     PointerToLIntP (LY, Y , YSize );
     PointerToLIntP (LR, R , RSize );
     PointerToLIntP (LS, S , SSize );

    I := ((LBitCount(LM) + 7) shr 3) - ((LBitCount(LQ) + 7) shr 3);
    { case of Q smaller, than hash size }
    if I > 0 then
    begin
      LShrNum(LM, LTmp, I shl 3);
      LCopy(LM, LTmp);
    end;

    if LGreater(LQ, LP) or LGreater(LG, LP) or LGreater(LY, LP) or
      LGreater(LS, LP) or LGreater(LR, LP) then
    begin
      Result := false;
      Exit;
    end;

    LGCD(LS, LQ, LTmp, LW);
    LMult(LM, LW, LTmp);
    LMod(LTmp, LQ, LS);   // now LS contains U1
    LMult(LR, LW, LTmp);
    LMod(LTmp, LQ, LM);   // now LM contains U2
    LMModPower(LG, LS, LP, LTmp);
    LMModPower(LY, LM, LP, LG);   // now LG contains the result
    LMult(LG, LTmp, LS);
    LMod(LS, LP, LTmp);
    LMod(LTmp, LQ, LS);
    Result := LEqual(LS, LR);
  finally
    LDestroy(LM);
    LDestroy(LP);
    LDestroy(LQ);
    LDestroy(LG);
    LDestroy(LY);
    LDestroy(LR);
    LDestroy(LS);
    LDestroy(LTmp);
    LDestroy(LW);
  end;
end;

procedure GenerateDSAQ(var Q: PLInt; var Seed: ByteArray);
var
  FSeed: array [0..24]  of byte;
  U: array [0..19]  of byte;
  I: Word;
  M1601, M1602: TMessageDigest160;
begin

  SBRndSeedTime;
  for I := 0 to 24 do
    FSeed[I] := SBRndGenerate(256);
  M1601 := HashSHA1(@FSeed[0], 25);
  FSeed[24] := Seed[24] + 1;
  M1602 := HashSHA1(@FSeed[0], 25);

  for I := 0 to 19 do
    U[I] := PByteArray(@M1601)[I] xor PByteArray(@M1602)[I];

  U[0] := U[0] or $80;
  U[19] := U[19] or $01;

  PointerToLIntP(Q, @U[0], 20);
  SBMove(FSeed[0], Seed[0], 25);

end;

procedure GenerateDSAP(var P: PLInt; Q: PLInt; var B: PLint; Bits: integer);
var
  Tmp, One: PLInt;
begin
  LCreate(Tmp);
  LCreate(One);
  SBRndGenerateLInt(B, (Bits - 160) shr 3);
  B.Digits[1] := B.Digits[1] and $FFFFFFFE;
  LMult(Q, B, Tmp);
  LAdd(Tmp, One, P);
  LDestroy(Tmp);
  LDestroy(One);
end;


procedure IntExternalGenerate(PBits, QBits : integer; var P, Q, G, Y, X : ByteArray);
begin
  // For each platform, implement its own IntExternalGenerate<PLATFORM> method
  // (e.g. IntExternalGenerateWP8) with the same signature and delegate the call
  // to it from here. Arrange calls to methods for different platforms with conditional defines.
  raise ESecureBlackboxError.Create('Method not implemented for the active platform: SBDSA.IntExternalGenerate()');
end;

function ExternalGenerationSupported: boolean;
begin
  // For each platform an appropriate value should be returned
  Result := false;
end;

function Generate(Bits : integer; P : pointer; var PSize : integer; Q : pointer;
  var QSize : integer; G : pointer; var GSize : integer; Y : pointer;
  var YSize : integer; X : pointer; var XSize : integer) : boolean;
var
  LP, LQ, LG, LX, LY, H, Tmp, Cmp: PLInt;
  Seed: ByteArray;
  RandCtx: TRC4RandomContext;
//  I : integer;
begin
  SetLength(Seed, 25);

  if (PSize < (Bits shr 3)) or (YSize < (Bits shr 3)) or (GSize < (Bits shr 3)) or
    (XSize < (Bits shr 3)) or (QSize < 20) then
  begin
    PSize := Bits shr 3;
    YSize := PSize;
    GSize := PSize;
    XSize := PSize;
    QSize := 20;
    Result := false;
    Exit;
  end;
  LCreate(LQ);
  LCreate(LP);
  LCreate(LG);
  LCreate(LX);
  LCreate(LY);
  LCreate(H);
  LCreate(Tmp);
  LCreate(Cmp);
  LShlNum(Tmp, Cmp, Bits - 1);
  repeat
    GenerateDSAQ(LQ, Seed);
  until LIsPrime(LQ);
  LRC4Init(RandCtx);
  repeat
    GenerateDSAP(LP, LQ, Tmp, Bits);
  until (LGreater(LP, Cmp)) and (LIsPrime(LP));
  SBRndGenerateLInt(H, LP.length * 4 - integer(SBRndGenerate(LP.length shl 1)) - 1);
  LMModPower(H, Tmp, LP, LG);
  SBRndGenerateLInt(LX, 18);
  LMModPower(LG, LX, LP, LY);
  LIntToPointer(LP, P, PSize);
  LIntToPointer(LG, G, GSize);
  LIntToPointer(LQ, Q, QSize);
  LIntToPointer(LY, Y, YSize);
  LIntToPointer(LX, X, XSize);

  Result := true;
  LDestroy(Tmp);
  LDestroy(Cmp);
  LDestroy(H);
  LDestroy(LP);
  LDestroy(LQ);
  LDestroy(LG);
  LDestroy(LX);
  LDestroy(LY);
end;

function ExternalGenerate(Bits : integer; P : pointer; var PSize : integer; Q : pointer;
  var QSize : integer; G : pointer; var GSize : integer; Y : pointer;
  var YSize : integer; X : pointer; var XSize : integer) : boolean;
var
  DSAP, DSAQ, DSAG, DSAY, DSAX : ByteArray;
begin
  if (PSize < (Bits shr 3)) or (YSize < (Bits shr 3)) or (GSize < (Bits shr 3)) or
    (XSize < (Bits shr 3)) or (QSize < 20) then
  begin
    PSize := Bits shr 3;
    YSize := PSize;
    GSize := PSize;
    XSize := PSize;
    QSize := 20;
    Result := false;
  end
  else
  begin
    try
      try
        IntExternalGenerate(Bits, 160, DSAP, DSAQ, DSAG, DSAY, DSAX);
        PSize := Length(DSAP);
        QSize := Length(DSAQ);
        GSize := Length(DSAG);
        YSize := Length(DSAY);
        XSize := Length(DSAX);
        Move(DSAP[0], P^, PSize);
        Move(DSAQ[0], Q^, QSize);
        Move(DSAG[0], G^, GSize);
        Move(DSAY[0], Y^, YSize);
        Move(DSAX[0], X^, XSize);
        Result := true;
      finally
        ReleaseArrays(DSAP, DSAQ, DSAG, DSAY, DSAX);
      end;
    except
      Result := false;
    end;
  end;
end;

{ FIPS-186-3 - compatible generation routine }
function GenerateEx(PBits, QBits : integer; P : pointer; var PSize : integer; Q : pointer;
  var QSize : integer; G : pointer; var GSize : integer; Y : pointer;
  var YSize : integer; X : pointer; var XSize : integer;
  ProgressFunc : TSBMathProgressFunc = nil; Data : pointer = nil) : boolean;  overload;  
var
  LSeed, LP, LQ, LG, LX, LY, Tmp, LDQ, LC, L2: PLInt;
  Seed, HashBuf: ByteArray;
  HashRes: ByteArray;
  {Index, }I, J, HashLen, HashIter: integer;
  //RandCtx: TRC4RandomContext;
  HashFunction:  TElHashFunction ;
  Generated: boolean;
begin
  if (QBits > 512) or (QBits < 160) or ((PBits and 31) <> 0) or ((QBits and 7) <> 0) then
  begin
    Result := false;
    Exit;
  end;

  if (PSize < (PBits shr 3)) or (YSize < (PBits shr 3)) or (GSize < (PBits shr 3)) or
    (XSize < (QBits shr 3)) or (QSize < (QBits shr 3)) then
  begin
    PSize := PBits shr 3;
    QSize := QBits shr 3;
    YSize := PSize;
    GSize := PSize;
    XSize := QSize;
    Result := false;
    Exit;
  end;

  Result := false;

  LCreate(LQ);
  LCreate(LP);
  LCreate(LG);
  LCreate(LX);
  LCreate(LY);
  LCreate(LSeed);
  LCreate(Tmp);
  LCreate(L2);
  LCreate(LC);
  LCreate(LDQ);

  LShlNum(Tmp, L2, PBits - 1);

  if (QBits = 160) then
  begin
    HashLen := 20;
    HashFunction :=  TElHashFunction .Create(SB_ALGORITHM_DGST_SHA1);
  end
  else if (QBits <= 224) then
  begin
    HashLen := 28;
    HashFunction :=  TElHashFunction .Create(SB_ALGORITHM_DGST_SHA224);
  end
  else if (QBits <= 256) then
  begin
    HashLen := 32;
    HashFunction :=  TElHashFunction .Create(SB_ALGORITHM_DGST_SHA256);
  end
  { below are non-FIPS compliant values }
  else if (QBits <= 384) then
  begin
    HashLen := 48;
    HashFunction :=  TElHashFunction .Create(SB_ALGORITHM_DGST_SHA384);
  end
  else
  begin
    HashLen := 64;
    HashFunction :=  TElHashFunction .Create(SB_ALGORITHM_DGST_SHA512);
  end;

  SetLength(Seed, HashLen);

  Generated := false;

  while not Generated do
  begin
    { generating Q parameter }
    repeat
      HashFunction.Reset;
      SBRndGenerate(@Seed[0], HashLen);
      HashFunction.Update(Seed, 0, HashLen);
      HashRes := HashFunction.Finish;

      if HashLen shl 3 = QBits then
        PointerToLInt(LQ, @HashRes[0], HashLen)
      else
      begin
        PointerToLInt(Tmp, @HashRes[0], HashLen);
        LShrNum(Tmp, LQ, HashLen shl 3 - QBits);
      end;

      LQ.Digits[1] := LQ.Digits[1] or 1;
      LQ.Digits[(QBits + 31) shr 5] := LQ.Digits[(QBits + 31) shr 5] or (1 shl ((QBits - 1)and 31));

      if MathOperationCanceled(ProgressFunc, Data) then
        Exit;
    until LIsPrime(LQ);

    { generating P parameter }

    PointerToLInt(LSeed, @Seed[0], HashLen);
    HashIter := (PBits + HashLen shl 3 - 1) div (HashLen shl 3);

    SetLength(HashBuf, HashLen * HashIter);
    
    for I := 0 to 4095 do
    begin
      { generating PBits random integer }

      for J := 0 to HashIter - 1 do
      begin
        LInc(LSeed);

        if LSeed.Length > HashLen shr 2 then
        begin
          LSeed.Length := HashLen shr 2;
          LSeed.Digits[LSeed.Length + 1] := 0;
        end;

        LIntToPointer(LSeed, @Seed[0], HashLen);

        HashFunction.Reset;
        HashFunction.Update(@Seed[0], HashLen);
        HashRes := HashFunction.Finish;

        SBMove(HashRes[0], HashBuf[J * HashLen], HashLen);
      end;

      { making P PBits-1 long }
      PointerToLInt(Tmp, @HashBuf[0], HashIter * HashLen);
      LShrNum(Tmp, LP, (HashIter * HashLen) shl 3 - PBits + 1);

      { setting the higher bit of P, thus P becoming PBits long }
      LAdd(LP, L2, Tmp); // P := P + 2^(PBits - 1)

      { making P = 1 (mod 2Q) }
      LCopy(LDQ, LQ);
      LShl(LDQ); // LDQ := 2 * Q
      LMod(Tmp, LDQ, LC);
      LDec(LC); // LC := P (mod 2*Q) - 1;
      LSub(Tmp, LC, LP); // P = 1 (mod 2*Q);

      if Integer(LBitCount(LP)) < PBits - 1 then Continue;

      if LIsPrime(LP) then
      begin
        Generated := true;
        Break;
      end;

      if MathOperationCanceled(ProgressFunc, Data) then
        Exit;
    end;
  end;

  { generating G }
  LDiv(LP, LQ, LDQ, L2); //LDQ = (p-1)/q

  Generated := false;

  repeat
    SBRndGenerateLInt(L2, PBits shr 3);
    LMod(L2, LP, Tmp);

    LMModPower(Tmp, LDQ, LP, LG);

    if LBitCount(LG) > 1 then
      Generated := true;
  until Generated;

  { generating keypair }
  SBRndGenerateLInt(Tmp, PBits shr 3 + 8);
  LCopy(LDQ, LQ);
  LDec(LDQ);
  LMod(Tmp, LDQ, LX);
  LInc(LX); { 1 <= X <= Q-1 }
  LMModPower(LG, LX, LP, LY);

  LIntToPointer(LP, P, PSize);
  LIntToPointer(LG, G, GSize);
  LIntToPointer(LQ, Q, QSize);
  LIntToPointer(LY, Y, YSize);
  LIntToPointer(LX, X, XSize);

  Result := true;

  FreeAndNil(HashFunction);
  LDestroy(Tmp);
  LDestroy(L2);
  LDestroy(LDQ);
  LDestroy(LC);
  LDestroy(LP);
  LDestroy(LQ);
  LDestroy(LG);
  LDestroy(LX);
  LDestroy(LY);
  LDestroy(LSeed);
end;

function ExternalGenerateEx(PBits, QBits : integer; P : pointer; var PSize : integer; Q : pointer;
  var QSize : integer; G : pointer; var GSize : integer; Y : pointer;
  var YSize : integer; X : pointer; var XSize : integer;
  ProgressFunc : TSBMathProgressFunc = nil; Data : pointer = nil) : boolean;  overload;  
var
  DSAP, DSAQ, DSAG, DSAY, DSAX : ByteArray;
begin
  if (QBits > 512) or (QBits < 160) or ((PBits and 31) <> 0) or ((QBits and 7) <> 0) then
  begin
    Result := false;
    Exit;
  end;

  if (PSize < (PBits shr 3)) or (YSize < (PBits shr 3)) or (GSize < (PBits shr 3)) or
    (XSize < (QBits shr 3)) or (QSize < (QBits shr 3)) then
  begin
    PSize := PBits shr 3;
    QSize := QBits shr 3;
    YSize := PSize;
    GSize := PSize;
    XSize := QSize;
    Result := false;
    Exit;
  end;

  try
    try
      IntExternalGenerate(PBits, QBits, DSAP, DSAQ, DSAG, DSAY, DSAX);
      PSize := Length(DSAP);
      QSize := Length(DSAQ);
      GSize := Length(DSAG);
      YSize := Length(DSAY);
      XSize := Length(DSAX);
      Move(DSAP[0], P^, PSize);
      Move(DSAQ[0], Q^, QSize);
      Move(DSAG[0], G^, GSize);
      Move(DSAY[0], Y^, YSize);
      Move(DSAX[0], X^, XSize);
      Result := true;
    finally
      ReleaseArrays(DSAP, DSAQ, DSAG, DSAY, DSAX);
    end;
  except
    Result := false;
  end;
end;

function Generate(Bits : integer; P : pointer; var PSize : integer; Q : pointer;
  var QSize : integer; G : pointer; var GSize : integer; Y : pointer;
  var YSize : integer; X : pointer; var XSize : integer; PrivateKeyBlob : pointer;
  var PrivateKeyBlobSize : integer; ProgressFunc : TSBMathProgressFunc = nil;
  Data : pointer = nil) : boolean;
var
  LP, LQ, LG, LX, LY, H, Tmp, Cmp: PLInt;
  Seed: ByteArray;
  RandCtx: TRC4RandomContext;
  EstimatedBlobSize : integer;
  Sz : integer;
  Tag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  TmpBuf : ByteArray;
begin
  SetLength(Seed, 25);

  Sz := Bits shr 3;
  EstimatedBlobSize := Sz shl 2 + 21 + 64;
  if (PSize < Sz) or (YSize < Sz) or (GSize < Sz) or
    (XSize < Sz) or (QSize < 20) or (PrivateKeyBlobSize < EstimatedBlobSize) then
  begin
    PSize := Bits shr 3;
    YSize := PSize;
    GSize := PSize;
    XSize := PSize;
    QSize := 20;
    PrivateKeyBlobSize := EstimatedBlobSize;
    Result := false;
    Exit;
  end;
  Result := false;
  LCreate(LQ);
  LCreate(LP);
  LCreate(LG);
  LCreate(LX);
  LCreate(LY);
  LCreate(H);
  LCreate(Tmp);
  LCreate(Cmp);
  try
    LShlNum(Tmp, Cmp, Bits - 1);
    repeat
      GenerateDSAQ(LQ, Seed);
      if MathOperationCanceled(ProgressFunc, Data) then
        Exit;
    until LIsPrime(LQ);
    LRC4Init(RandCtx);
    repeat
      if MathOperationCanceled(ProgressFunc, Data) then
        Exit;
      GenerateDSAP(LP, LQ, Tmp, Bits);
    until (LGreater(LP, Cmp)) and (LIsPrime(LP));
    SBRndGenerateLInt(H, LP.length shl 2 - integer(SBRndGenerate(LP.length shl 1)) - 1);
    try
      LMModPower(H, Tmp, LP, LG, ProgressFunc, Data, true);
      SBRndGenerateLInt(LX, 18);
      LMModPower(LG, LX, LP, LY, ProgressFunc, Data, true);
    except
      Exit;
    end;
    LIntToPointer(LP, P, PSize);
    LIntToPointer(LG, G, GSize);
    LIntToPointer(LQ, Q, QSize);
    LIntToPointer(LY, Y, YSize);
    LIntToPointer(LX, X, XSize);
    Tag := TElASN1ConstrainedTag.CreateInstance;
    try
      Tag.TagId := SB_ASN1_SEQUENCE;
      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      STag.TagId := SB_ASN1_INTEGER;

      SetLength(TmpBuf, 1);
      TmpBuf[0] := byte(0);
      STag.Content := TmpBuf;
      ReleaseArray(TmpBuf);

      // Copy P

      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      STag.TagId := SB_ASN1_INTEGER;

      if PByte(P)^ >= 128 then
      begin
        SetLength(TmpBuf, PSize + 1);
        TmpBuf[0] := byte(0);
        SBMove(P^, TmpBuf[0 + 1], PSize);
      end
      else
      begin
        SetLength(TmpBuf, PSize);
        SBMove(P^, TmpBuf[0], PSize);
      end;
      STag.Content := TmpBuf;
      ReleaseArray(TmpBuf);

      // Copy Q

      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      STag.TagId := SB_ASN1_INTEGER;
      if PByte(Q)^ >= 128 then
      begin
        SetLength(TmpBuf, QSize + 1);
        TmpBuf[0] := byte(0);
        SBMove(Q^, TmpBuf[0 + 1], QSize);
      end
      else
      begin
        SetLength(TmpBuf, QSize);
        SBMove(Q^, TmpBuf[0], QSize);
      end;
      STag.Content := TmpBuf;
      ReleaseArray(TmpBuf);

      // Copy G

      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      STag.TagId := SB_ASN1_INTEGER;
      if PByte(G)^ >= 128 then
      begin
        SetLength(TmpBuf, GSize + 1);
        TmpBuf[0] := byte(0);
        SBMove(G^, TmpBuf[0 + 1], GSize);
      end
      else
      begin
        SetLength(TmpBuf, GSize);
        SBMove(G^, TmpBuf[0], GSize);
      end;
      STag.Content := TmpBuf;
      ReleaseArray(TmpBuf);

      // Copy Y

      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      STag.TagId := SB_ASN1_INTEGER;
      if PByte(Y)^ >= 128 then
      begin
        SetLength(TmpBuf, YSize + 1);
        TmpBuf[0] := byte(0);
        SBMove(Y^, TmpBuf[0 + 1], YSize);
      end
      else
      begin
        SetLength(TmpBuf, YSize);
        SBMove(Y^, TmpBuf[0], YSize);
      end;
      STag.Content := TmpBuf;
      ReleaseArray(TmpBuf);

      // Copy X

      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      STag.TagId := SB_ASN1_INTEGER;
      if PByte(X)^ >= 128 then
      begin
        SetLength(TmpBuf, XSize + 1);
        TmpBuf[0] := byte(0);
        SBMove(X^, TmpBuf[0 + 1], XSize);
      end
      else
      begin
        SetLength(TmpBuf, XSize);
        SBMove(X^, TmpBuf[0], XSize);
      end;
      STag.Content := TmpBuf;
      ReleaseArray(TmpBuf);

      Result := Tag.SaveToBuffer(PrivateKeyBlob, PrivateKeyBlobSize);
    finally
      FreeAndNil(Tag);
    end;
  finally
    LDestroy(Tmp);
    LDestroy(Cmp);
    LDestroy(H);
    LDestroy(LP);
    LDestroy(LQ);
    LDestroy(LG);
    LDestroy(LX);
    LDestroy(LY);
  end;
end;

function ExternalGenerate(Bits : integer; P : pointer; var PSize : integer; Q : pointer;
  var QSize : integer; G : pointer; var GSize : integer; Y : pointer;
  var YSize : integer; X : pointer; var XSize : integer; PrivateKeyBlob : pointer;
  var PrivateKeyBlobSize : integer; ProgressFunc : TSBMathProgressFunc = nil;
  Data : pointer = nil) : boolean;
var
  Sz, EstimatedBlobSize : integer;
  DSAP, DSAQ, DSAG, DSAY, DSAX : ByteArray;
begin
  Sz := Bits shr 3;
  EstimatedBlobSize := Sz * 4 + 21 + 64;
  if (PSize < Sz) or (YSize < Sz) or (GSize < Sz) or
    (XSize < Sz) or (QSize < 20) or (PrivateKeyBlobSize < EstimatedBlobSize) then
  begin
    PSize := Bits shr 3;
    YSize := PSize;
    GSize := PSize;
    XSize := PSize;
    QSize := 20;
    PrivateKeyBlobSize := EstimatedBlobSize;
    Result := false;
    Exit;
  end
  else
  begin
    try
      try
        IntExternalGenerate(Bits, 160, DSAP, DSAQ, DSAG, DSAY, DSAX);
        PSize := Length(DSAP);
        QSize := Length(DSAQ);
        GSize := Length(DSAG);
        YSize := Length(DSAY);
        XSize := Length(DSAX);
        Move(DSAP[0], P^, PSize);
        Move(DSAQ[0], Q^, QSize);
        Move(DSAG[0], G^, GSize);
        Move(DSAY[0], Y^, YSize);
        Move(DSAX[0], X^, XSize);
        EncodePrivateKey( @DSAP[0], PSize , 
           @DSAQ[0], QSize ,
           @DSAG[0], GSize ,
           @DSAY[0], YSize , 
           @DSAX[0], XSize , 
          PrivateKeyBlob, PrivateKeyBlobSize);
        Result := true;
      finally
        ReleaseArrays(DSAP, DSAQ, DSAG, DSAY, DSAX);
      end;
    except
      Result := false;
    end;
  end;
end;

function SignEx(Hash : pointer; HashSize : integer; P : pointer; PSize : integer;
  Q : pointer; QSize : integer; G : pointer; GSize : integer; X : pointer;
  XSize : integer; R : pointer; var RSize : integer; S : pointer;
  var SSize : integer) : boolean;
var
  LK, LK1, LR, LS, Tmp, LM, LP, LQ, LQ1, LG, LX : PLInt;
  I : integer;
begin
  if (RSize < QSize) or (SSize < QSize) then
  begin
    RSize := QSize;
    SSize := QSize;
    Result := false;
    Exit;
  end;

  LCreate(LK);
  LCreate(LR);
  LCreate(LS);
  LCreate(Tmp);
  LCreate(LP);
  LCreate(LQ);
  LCreate(LG);
  LCreate(LX);
  LCreate(LQ1);
  LCreate(LK1);
  LCreate(LM);

  try
    PointerToLInt(LP, P, PSize);
    PointerToLInt(LG, G, GSize);
    PointerToLInt(LQ, Q, QSize);
    PointerToLInt(LX, X, XSize);
    PointerToLInt(LM, Hash, HashSize);

    if LGreater(LG, LP) or LGreater(LQ, LP) or LGreater(LX, LP) or LGreater(LM, LP) then
    begin
      Result := false;
      Exit;
    end;

    I := ((LBitCount(LM) + 7) shr 3) - ((LBitCount(LQ) + 7) shr 3);
    if I > 0 then
    begin
      LShrNum(LM, Tmp, I shl 3);
      LCopy(LM, Tmp);
    end;

    LCopy(LQ1, LQ);
    LDec(LQ1);

    { generating k }
    SBRndGenerateLInt(Tmp, QSize + 8);
    LMod(Tmp, LQ1, LK);
    LInc(LK);

    { calculating k^-1 mod q}
    LGCD(LK, LQ, Tmp, LK1);

    { calculating R = (g^k mod p) mod q }
    LMModPower(LG, LK, LP, Tmp);
    LMod(Tmp, LQ, LR);

    { calculating S = (k^-1(m + x*r)) mod q }
    LMult(LX, LR, Tmp);
    LAdd(Tmp, LM, LS);
    LMult(LS, LK1, Tmp);
    LMod(Tmp, LQ, LS);

    RSize := QSize;
    SSize := QSize;

    LIntToPointer(LR, R, RSize);
    LIntToPointer(LS, S, SSize);

    Result := true;

  finally
    LDestroy(Tmp);
    LDestroy(LK);
    LDestroy(LR);
    LDestroy(LS);
    LDestroy(LP);
    LDestroy(LQ);
    LDestroy(LG);
    LDestroy(LX);
    LDestroy(LQ1);
    LDestroy(LK1);
    LDestroy(LM);
  end;
end;

function Sign(Hash : pointer; HashSize : integer; P : pointer; PSize : integer;
  Q : pointer; QSize : integer; G : pointer; GSize : integer; X : pointer;
  XSize : integer; R : pointer; var RSize : integer; S : pointer;
  var SSize : integer) : boolean;
var
  K, LR, DS, Tmp, ASign, EncSign, LP, LQ, LG, LX : PLInt;
begin
  if (RSize < 20) or (SSize < 20) then
  begin
    RSize := 20;
    SSize := 20;
    Result := false;
    Exit;
  end;
  LCreate(K);
  LCreate(LR);
  LCreate(DS);
  LCreate(Tmp);
  LCreate(ASign);
  LCreate(EncSign);
  LCreate(LP);
  LCreate(LQ);
  LCreate(LG);
  LCreate(LX);
  try
    PointerToLInt(LP, P , PSize );
    PointerToLInt(LG, G , GSize );
    PointerToLInt(LQ, Q , QSize );
    PointerToLInt(LX, X , XSize );

    if LGreater(LG, LP) or LGreater(LQ, LP) or LGreater(LX, LP) then
    begin
      Result := false;
      Exit;
    end;

    SBRndGenerateLInt(K, 18);
    LMModPower(LG, K, LP, Tmp);
    LMod(Tmp, LQ, LR);
    LMult(LX, LR, Tmp);
    PointerToLInt(ASign, Hash , HashSize );
    LAdd(Tmp, ASign, EncSign);
    LGCD(K, LQ, Tmp, ASign);
    LMult(ASign, EncSign, Tmp);
    LMod(Tmp, LQ, DS);
    RSize := 20;
    SSize := 20;
    LIntToPointer(LR, R, RSize);
    LIntToPointer(DS, S, SSize);
    Result := true;
  finally
    LDestroy(EncSign);
    LDestroy(ASign);
    LDestroy(Tmp);
    LDestroy(K);
    LDestroy(LR);
    LDestroy(DS);
    LDestroy(LP);
    LDestroy(LQ);
    LDestroy(LG);
    LDestroy(LX);
  end;
end;

function DecodePrivateKeyClassic(Buffer : pointer; Size : integer; P : pointer;
  var PSize : integer; Q : pointer; var QSize : integer; G : pointer;
  var GSize : integer; Y : pointer; var YSize : integer; X : pointer;
  var XSize : integer) : boolean;
var
  EncodedKey : TElASN1ConstrainedTag;
  CTag : TElASN1ConstrainedTag;
  I, PInd, QInd, GInd, YInd, XInd : integer;

  TV : ByteArray; // NO NEED for ReleaseArray

begin
  Result := false;
  EncodedKey := TElASN1ConstrainedTag.CreateInstance;
  try

    if not EncodedKey.LoadFromBuffer(Buffer , Size ) then
      raise ESecureBlackboxError.Create('');//Exit;
    if (EncodedKey.Count < 1) or (EncodedKey.GetField(0).TagId <> SB_ASN1_SEQUENCE) or
      (not EncodedKey.GetField(0).IsConstrained) then
      raise ESecureBlackboxError.Create('');//Exit;

    CTag := TElASN1ConstrainedTag(EncodedKey.GetField(0));
    if CTag.Count <> 6 then
      raise ESecureBlackboxError.Create('');//Exit;

    for I := 0 to 5 do
      if (CTag.GetField(I).TagId <> SB_ASN1_INTEGER) or
        (CTag.GetField(I).IsConstrained) then
        raise ESecureBlackboxError.Create('');//Exit;

    TV := TElASN1SimpleTag(CTag.GetField(0)).Content;
    if (Length(TV) <> 1) or (TV[0] <> byte(0)) then
      raise ESecureBlackboxError.Create('');//Exit;

    if (PSize < Length(TElASN1SimpleTag(CTag.GetField(1)).Content) - 1) or
      (QSize < Length(TElASN1SimpleTag(CTag.GetField(2)).Content) - 1) or
      (GSize < Length(TElASN1SimpleTag(CTag.GetField(3)).Content) - 1) or
      (YSize < Length(TElASN1SimpleTag(CTag.GetField(4)).Content) - 1) or
      (XSize < Length(TElASN1SimpleTag(CTag.GetField(5)).Content) - 1) then
      Result := false
    else
      Result := true;
      
    PSize := Length(TElASN1SimpleTag(CTag.GetField(1)).Content);
    QSize := Length(TElASN1SimpleTag(CTag.GetField(2)).Content);
    GSize := Length(TElASN1SimpleTag(CTag.GetField(3)).Content);
    YSize := Length(TElASN1SimpleTag(CTag.GetField(4)).Content);
    XSize := Length(TElASN1SimpleTag(CTag.GetField(5)).Content);
    if TElASN1SimpleTag(CTag.GetField(1)).Content[0] = byte(0) then
    begin
      PInd := 0 + 1;
      Dec(PSize);
    end
    else
      PInd := 0;
    if TElASN1SimpleTag(CTag.GetField(2)).Content[0] = byte(0) then
    begin
      QInd := 0 + 1;
      Dec(QSize);
    end
    else
      QInd := 0;
    if TElASN1SimpleTag(CTag.GetField(3)).Content[0] = byte(0) then
    begin
      GInd := 0 + 1;
      Dec(GSize);
    end
    else
      GInd := 0;
    if TElASN1SimpleTag(CTag.GetField(4)).Content[0] = byte(0) then
    begin
      YInd := 0 + 1;
      Dec(YSize);
    end
    else
      YInd := 0;
    if TElASN1SimpleTag(CTag.GetField(5)).Content[0] = byte(0) then
    begin
      XInd := 0 + 1;
      Dec(XSize);
    end
    else
      XInd := 0;
    if Result then
    begin
      SBMove(TElASN1SimpleTag(CTag.GetField(1)).Content[PInd], P^, PSize);
      SBMove(TElASN1SimpleTag(CTag.GetField(2)).Content[QInd], Q^, QSize);
      SBMove(TElASN1SimpleTag(CTag.GetField(3)).Content[GInd], G^, GSize);
      SBMove(TElASN1SimpleTag(CTag.GetField(4)).Content[YInd], Y^, YSize);
      SBMove(TElASN1SimpleTag(CTag.GetField(5)).Content[XInd], X^, XSize);
    end;
  finally
    FreeAndNil(EncodedKey);
  end;
end;

function DecodePrivateKeyJKS(Buffer : pointer; Size : integer; P : pointer;
  var PSize : integer; Q : pointer; var QSize : integer; G : pointer;
  var GSize : integer; Y : pointer; var YSize : integer; X : pointer;
  var XSize : integer) : boolean;
var
  EncodedKey : TElASN1ConstrainedTag;
  CTag, CSubTag : TElASN1ConstrainedTag;
  XTag : TElASN1ConstrainedTag;
  PInd, QInd, GInd, YInd, XInd : integer;
  KP, KG, KQ, KX, KY : ByteArray; // NO NEED for ReleaseArray
  LG, LP, LX, LY : PLInt;


begin
  // JKS DSA private has the following format:
  //   SEQUENCE
  //     INTEGER (00)
  //     SEQUENCE
  //       OBJECT dsaEncryption
  //       SEQUENCE
  //         INTEGER P
  //         INTEGER Q
  //         INTEGER G
  //     OCTETSTRING X
  Result := false;
  EncodedKey := TElASN1ConstrainedTag.CreateInstance;
  try
  
    if not EncodedKey.LoadFromBuffer(Buffer , Size ) then
      raise ESecureBlackboxError.Create('');                       
    if (EncodedKey.Count < 1) or (EncodedKey.GetField(0).TagId <> SB_ASN1_SEQUENCE) or
      (not EncodedKey.GetField(0).IsConstrained) then
      raise ESecureBlackboxError.Create('');

    CTag := TElASN1ConstrainedTag(EncodedKey.GetField(0));
    if (CTag.Count <> 3) or (not CTag.GetField(0).CheckType(SB_ASN1_INTEGER, false)) or
      (not CTag.GetField(1).CheckType(SB_ASN1_SEQUENCE, true) or
      (not CTag.GetField(2).CheckType(SB_ASN1_OCTETSTRING, false))) then
      raise ESecureBlackboxError.Create('');
    CSubTag := TElASN1ConstrainedTag(CTag.GetField(1));
    if (CSubTag.Count <> 2) or (not CSubTag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) or
      (not CSubTag.GetField(1).CheckType(SB_ASN1_SEQUENCE, true)) then 
      raise ESecureBlackboxError.Create('');
    if not CompareContent(TElASN1SimpleTag(CSubTag.GetField(0)).Content, SB_OID_DSA) then
      raise ESecureBlackboxError.Create('');
    CSubTag := TElASN1ConstrainedTag(CSubTag.GetField(1));
    if (CSubTag.Count <> 3) or (not CSubTag.GetField(0).CheckType(SB_ASN1_INTEGER, false)) or
      (not CSubTag.GetField(1).CheckType(SB_ASN1_INTEGER, false)) or
      (not CSubTag.GetField(2).CheckType(SB_ASN1_INTEGER, false)) then
      raise ESecureBlackboxError.Create('');
    KP := TElASN1SimpleTag(CSubTag.GetField(0)).Content;
    KQ := TElASN1SimpleTag(CSubTag.GetField(1)).Content;
    KG := TElASN1SimpleTag(CSubTag.GetField(2)).Content;
    KX := TElASN1SimpleTag(CTag.GetField(2)).Content;

    // X is represented as ASN.1-encoded integer record, so decoding it
    XTag := TElASN1ConstrainedTag.CreateInstance();
    try
      if not XTag.LoadFromBuffer(@KX[0], Length(KX)) then
        raise ESecureBlackboxError.Create('');
      if (XTag.Count <> 1) or (not XTag.GetField(0).CheckType(SB_ASN1_INTEGER, false)) then
        raise ESecureBlackboxError.Create('');
      KX := TElASN1SimpleTag(XTag.GetField(0)).Content;
    finally
      FreeAndNil(XTag);
    end;

    if (PSize < Length(KP)) or
      (QSize < Length(KQ)) or
      (GSize < Length(KG)) or
      (YSize < Length(KP)) or
      (XSize < Length(KX)) then
      Result := false
    else
      Result := true;

    PSize := Length(KP);
    QSize := Length(KQ);
    GSize := Length(KG);
    YSize := Length(KP);
    XSize := Length(KX);
    if Result then
    begin
      // calculating X
      LCreate(LG);
      LCreate(LX);
      LCreate(LP);
      LCreate(LY);
      try
        PointerToLInt(LG, @KG[0], GSize);
        PointerToLInt(LX, @KX[0], XSize);
        PointerToLInt(LP, @KP[0], PSize);
        LMModPower(LG, LX, LP, LY);
        YSize := LY.Length shl 2;
        SetLength(KY, YSize);
        LIntToPointer(LY, @KY[0], YSize);
        SetLength(KY, YSize);
      finally
        LDestroy(LG);
        LDestroy(LX);
        LDestroy(LP);
        LDestroy(LY);
      end;
      if KP[0] = byte(0) then
      begin
        PInd := 0 + 1;
        Dec(PSize);
      end
      else
        PInd := 0;
      if KQ[0] = byte(0) then
      begin
        QInd := 0 + 1;
        Dec(QSize);
      end
      else
        QInd := 0;
      if KG[0] = byte(0) then
      begin
        GInd := 0 + 1;
        Dec(GSize);
      end
      else
        GInd := 0;
      if KY[0] = byte(0) then
      begin
        YInd := 0 + 1;
        Dec(YSize);
      end
      else
        YInd := 0;
      if KX[0] = byte(0) then
      begin
        XInd := 0 + 1;
        Dec(XSize);
      end
      else
        XInd := 0;
      SBMove(KP[PInd], P^, PSize);
      SBMove(KQ[QInd], Q^, QSize);
      SBMove(KG[GInd], G^, GSize);
      SBMove(KY[YInd], Y^, YSize);
      SBMove(KX[XInd], X^, XSize);
    end;
  finally
    FreeAndNil(EncodedKey);
  end;
end;

function DecodePrivateKey(Buffer : pointer; Size : integer; P : pointer;
  var PSize : integer; Q : pointer; var QSize : integer; G : pointer;
  var GSize : integer; Y : pointer; var YSize : integer; X : pointer;
  var XSize : integer) : boolean;
begin
  try
    Result := DecodePrivateKeyClassic(Buffer , Size , P, PSize, Q, QSize, G, GSize,
      Y, YSize, X, XSize);
  except
    try
      Result := DecodePrivateKeyJKS(Buffer , Size , P, PSize, Q, QSize, G, GSize,
        Y, YSize, X, XSize);
    except
      Result := false;
      PSize := 0;
      QSize := 0;
      GSize := 0;
      YSize := 0;
      XSize := 0;
    end;
  end;
end;


function EncodePrivateKey(P : pointer; PSize : integer; Q : pointer; QSize :
  integer; G : pointer; GSize : integer; Y : pointer; YSize : integer;
  X : pointer; XSize : integer; OutBuffer : pointer; var OutSize : integer) : boolean;
var
  Tag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  Tag.TagId := SB_ASN1_SEQUENCE;
  { Version }
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;

  STag.Content := GetByteArrayFromByte(0);

  try
    { p }
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    asymWriteInteger(STag, P , PSize );
    { q }
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    asymWriteInteger(STag, Q , QSize );
    { g }
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    asymWriteInteger(STag, G , GSize );
    { y }
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    asymWriteInteger(STag, Y , YSize );
    { x }
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    asymWriteInteger(STag, X , XSize );

    Result := Tag.SaveToBuffer(OutBuffer, OutSize);
  finally
    FreeAndNil(Tag);
  end;
end;

function DecodeSignature(Blob : pointer; Size : integer; R : pointer;
  var RSize : integer; S : pointer; var SSize : integer) : boolean;
(*
var
  Tag, CTag : TElASN1ConstrainedTag;
  SR, SS : ByteArray;
  *)
begin
  Result := DecodeDSASignature(Blob, Size, R, RSize, S, SSize);
  (*
  Result := false;

  Tag := TElASN1ConstrainedTag.CreateInstance;
  {$ifdef SB_VCL}
  try
  {$endif}
    if Tag.LoadFromBuffer(Blob{$ifdef SB_VCL}, Size{$endif}) then
    begin
      if (not Tag.IsConstrained) or (TElASN1ConstrainedTag(Tag).Count <> 1) then
        Exit;

      CTag := TElASN1ConstrainedTag(Tag.GetField(0));
      if (CTag.TagID <> SB_ASN1_SEQUENCE) then
        Exit;

      if TElASN1ConstrainedTag(CTag).Count <> 2 then
        Exit;

      if (TElASN1ConstrainedTag(CTag).GetField(0).IsConstrained) or
        (TElASN1ConstrainedTag(CTag).GetField(1).IsConstrained) or
        (TElASN1ConstrainedTag(CTag).GetField(0).TagID <> SB_ASN1_INTEGER) or
        (TElASN1ConstrainedTag(CTag).GetField(1).TagID <> SB_ASN1_INTEGER) then
        Exit;

      SR := TElASN1SimpleTag(TElASN1ConstrainedTag(CTag).GetField(0)).Content;
      SS := TElASN1SimpleTag(TElASN1ConstrainedTag(CTag).GetField(1)).Content;
      if (Length(SR) > RSize) or (Length(SS) > SSize) then
      begin
        RSize := Length(SR);
        SSize := Length(SS);
        Exit;
      end;

      {$ifdef SB_VCL}
      SBMove(SR[1], R^, Length(SR));
      {$else}
      SBMove(SR, 0, R, 0, Length(SR));
      {$endif}
      RSize := Length(SR);
      {$ifdef SB_VCL}
      SBMove(SS[1], S^, Length(SS));
      {$else}
      SBMove(SS, 0, S, 0, Length(SS));
      {$endif}
      SSize := Length(SS);
      Result := true;
    end;
  {$ifdef SB_VCL}
  finally
    Tag.Free;
  end;
  {$endif}
  *)
end;

function EncodeSignature(R : pointer; RSize : integer; S : pointer; SSize :
  integer; Blob: pointer; var BlobSize : integer) : boolean;
(*
var
  EstSize : integer;
  BufR, BufS : ByteArray;
  Tag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  {$ifndef SB_VCL}
  RSize, SSize : integer;
  {$endif}
  *)
begin
  Result := EncodeDSASignature(R, RSize, S, SSize, Blob, BlobSize);
  (*
  {$ifndef SB_VCL}
  SSize := Length(S);
  RSize := Length(R);
  {$endif}
  EstSize := RSize + SSize + 16;
  if BlobSize < EstSize then
  begin
    BlobSize := EstSize;
    Result := false;
    Exit;
  end;
  {$ifdef SB_VCL}
  if PByte(R)^ >= $80 then
  begin
    SetLength(BufR, RSize + 1);
    SBMove(R^, BufR[2], RSize);
    BufR[1] := #0;
  end
  else
  begin
    SetLength(BufR, RSize);
    SBMove(R^, BufR[1], RSize);
  end;
  if PByte(S)^ >= $80 then
  begin
    SetLength(BufS, SSize + 1);
    SBMove(S^, BufS[2], SSize);
    BufS[1] := #0;
  end
  else
  begin
    SetLength(BufS, SSize);
    SBMove(S^, BufS[1], SSize);
  end;
  {$else}
  if R[0] >= $80 then
  begin
    {$ifndef SB_NET}
    SetLength(BufR, RSize + 1);
    {$else}
    BufR := new Byte[RSize + 1];
    {$endif}
    SBMove(R, 0, BufR, 1, RSize);
    BufR[0] := 0;
  end
  else
  begin
   {$ifndef SB_NET}
   SetLength(BufR, RSize);
   {$else}
   BufR := new Byte[RSize];
   {$endif}
   SBMove(R, 0, BufR, 0, RSize);
  end;
  if S[0] >= $80 then
  begin
    {$ifndef SB_NET}
    SetLength(BufS, SSize + 1);
    {$else}
    BufS := new Byte[SSize + 1];
    {$endif}
    SBMove(S, 0, BufS, 1, SSize);
    BufS[0] := 0;
  end
  else
  begin
    {$ifndef SB_NET}
    SetLength(BufS, SSize);
    {$else}
    BufS := new Byte[SSize];
    {$endif}
    SBMove(S, 0, BufS, 0, SSize);
  end;
  {$endif}
  Tag := TElASN1ConstrainedTag.CreateInstance;
  Tag.TagId := SB_ASN1_SEQUENCE;
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;
  STag.Content := BufR;
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;
  STag.Content := BufS;
  {$ifdef SB_VCL}
  try
  {$endif}
    Result := Tag.SaveToBuffer(Blob, BlobSize);
  {$ifdef SB_VCL}
  finally
    Tag.Free;
  end;
  {$endif}
  *)
end;


function IsValidKey(P : pointer; PSize : integer; Q : pointer; QSize : integer;
  G : pointer; GSize : integer; Y : pointer; YSize : integer; X : pointer; XSize : integer;
  Secret : boolean; StrictMode : boolean = false) : boolean;
var
  LP, LQ, LG, LY, LX, LTmp1 : PLInt;
  BCount : cardinal;
begin
  Result := false;
  LCreate(LP);
  LCreate(LQ);
  LCreate(LG);
  LCreate(LY);
  LCreate(LX);
  LCreate(LTmp1);

  try
    PointerToLInt(LP, P , PSize );
    PointerToLInt(LQ, Q , QSize );

    { checking that P and Q are primes }

    if StrictMode then
      if (not LIsPrime(LP)) or (not LIsPrime(LQ)) then
        Exit;

    if LBitCount(LQ) and 7 <> 0 then
      Exit;

    BCount := LBitCount(LP);
    if (BCount < 512) or ((BCount and 63) <> 0) then
      Exit;

    { checking that Q is a divisor of P-1 }
    LMod(LP, LQ, LTmp1);

    if not ((LTmp1.Length = 1) and (LTmp1.Digits[1] = 1)) then
      Exit;

    PointerToLInt(LG, G , GSize );

    { G must be smaller than P}
    if not LGreater(LP, LG) then
      Exit;

    { checking that G has order Q in Fp }
    if StrictMode then
    begin
      LMModPower(LG, LQ, LP, LTmp1);
      if (LTmp1.Length > 1) or (LTmp1.Digits[1] <> 1) then
        Exit;
    end;    

    PointerToLInt(LY, Y , YSize );
    { Y must be smaller than P }
    if not LGreater(LP, LY) then
      Exit;

    { for secret-key only check }  
    if Secret then
    begin
      PointerToLInt(LX, X , XSize );
      { X must be smaller than Q}
      if not LGreater(LQ, LX) then
        Exit;
      { checking that y = g^x (mod p) }

      if StrictMode then
      begin
        LMModPower(LG, LX, LP, LTmp1);

        if not LEqual(LTmp1, LY) then
          Exit;
      end;    
    end;

    Result := true;
  finally
    LDestroy(LP);
    LDestroy(LQ);
    LDestroy(LG);
    LDestroy(LY);
    LDestroy(LX);
    LDestroy(LTmp1);
  end;
end;

end.


