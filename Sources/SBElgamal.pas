(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBElgamal;

interface

uses
  SBMath,
  SBTypes,
  SBUtils,
  SBStrUtils
  ,
  SysUtils
  ,
  SBConstants
  ;


{$ifndef SB_PGPSFX_STUB}


function Generate(Bits : integer; P : PLInt; G : PLInt; X: PLInt; Y : PLInt;
  ProgressFunc : TSBMathProgressFunc  =  nil; Data :  pointer   =  nil) : boolean;  overload; function ExternalGenerate(Bits : integer; P : PLInt; G : PLInt; X: PLInt; Y : PLInt;
  ProgressFunc : TSBMathProgressFunc  =  nil; Data :  pointer   =  nil) : boolean;  overload; function ExternalGenerationSupported : boolean; 
function Encrypt(Src : PLInt; P : PLInt; G : PLInt; Y : PLInt; A : PLInt; B : PLInt) : boolean; 
 {$endif SB_PGPSFX_STUB}
function Decrypt(P : PLInt; G : PLInt; X : PLInt; A : PLInt; B : PLInt; Dest : PLInt) : boolean; 
{$ifndef SB_PGPSFX_STUB}
function Sign(Src : PLint; P : PLInt; G : PLInt; X : PLInt; A : PLint; B : PLInt) : boolean; 
 {$endif SB_PGPSFX_STUB}
function Verify(Src : PLInt; P : PLInt; G : PLInt; Y : PLInt; A : PLInt; B : PLInt) : boolean; 


function EncodeResult(R : pointer; RSize : integer; S : pointer; SSize :
  integer; Blob: pointer; var BlobSize : integer) : boolean;
function DecodeResult(Blob : pointer; Size : integer; R : pointer;
  var RSize : integer; S : pointer; var SSize : integer) : boolean;
function EncodePublicKey(P : pointer; PSize : integer;
  G : pointer; GSize : integer; Y : pointer; YSize : integer;
  OutBuffer : pointer; var OutSize : integer) : boolean;
function EncodePrivateKey(P : pointer; PSize : integer;
  G : pointer; GSize : integer; X : pointer; XSize : integer;
  OutBuffer : pointer; var OutSize : integer) : boolean;

implementation

uses 
  SBASN1, 
  SBASN1Tree,
  SBRandom;
  
const 
  SB_ELGAMAL_OID = '1.3.14.7.2.1.1';

function WienerQBits(PBits : integer) : integer;
const
  WienerMap : array[0..18, 0..1] of integer =
    ((512, 119), (768, 145), (1024, 165), (1280, 183), (1536, 198),
     (1792, 212), (2048, 225), (2304, 237), (2560, 249), (2816, 259),
     (3072, 269), (3328, 279), (3584, 288), (3840, 296), (4096, 305),
     (4352, 313), (4608, 320), (4864, 328), (5120, 335));
var
  i : integer;
begin
  for i := 0 to 18 do
    if PBits <= WienerMap[i, 0] then
    begin
      Result := WienerMap[i, 1];
      Exit;
    end;
  Result := PBits shr 3 + 200;
end;

{$ifndef SB_PGPSFX_STUB}


procedure IntExternalGenerate(Bits : integer; var P, G, X, Y : ByteArray);
begin
  // For each platform, implement its own IntExternalGenerate<PLATFORM> method
  // (e.g. IntExternalGenerateWP8) with the same signature and delegate the call
  // to it from here. Arrange calls to methods for different platforms with conditional defines.
  raise ESecureBlackboxError.Create('Method not implemented for the active platform: SBElgamal.IntExternalGenerate()');
end;

function ExternalGenerationSupported : boolean;
begin
  Result := false;
end;

function Generate(Bits : integer; P : PLInt; G : PLInt; X: PLInt; 
  Y : PLInt; 
  ProgressFunc : TSBMathProgressFunc; 
  Data :  pointer ) : boolean;

  function NextPermutation(var Data : ByteArray) : boolean;
  var
    i, j, l, c : integer;
  begin
    l := Length(Data);

    i := 0;

    while (i < l) and (Data[i] = 0) do Inc(i);

    c := 0;
    j := i;

    while (j < l) and (Data[j] <> 0) do
    begin
      Inc(c);
      Inc(j);
    end;

    if (j >= l) then
      Result := false //last permutation
    else
    begin
      Data[j] := Data[j - 1];
      for l := 0 to c - 2 do
        Data[l] := Data[l + i];
      for l := c - 1 to j - 1 do
        Data[l] := 0;
      Result := true;
    end;
  end;

var
  Perm : ByteArray;
  I, L, FPrimes, MinTries, MaxTries, GenPrimes : integer;
  QBits, FBits : integer;
  Primes : array of PLInt;
  Generated : boolean;
  Q, Tmp, P1, C, D : PLint;
begin
  Result := false;

  if Bits < 512 then Exit;

  QBits := WienerQBits(Bits);
  FPrimes := (Bits - QBits - 1) div QBits;
  FBits := (Bits - QBits - 1) div FPrimes;
  QBits := Bits - FBits * FPrimes;

  GenPrimes := 3 * FPrimes + 2; //arbitrary value
  if GenPrimes < 15 then GenPrimes := 15;

  SetLength(Primes, GenPrimes);
  SetLength(Perm, GenPrimes);

  LCreate(Q);
  LCreate(P1);
  LCreate(C);
  LCreate(D);
  LCreate(Tmp);
  for i := 0 to GenPrimes - 1 do
    LCreate(Primes[i]);

  try
    Generated := false;

    repeat
      try
        LGenPrimeEx(Q, QBits, false, ProgressFunc, Data, True);

        for i := 0 to GenPrimes - 1 do
          LGenPrimeEx(Primes[i], FBits, false, ProgressFunc, Data);
      except
        on E : EElMathException do Exit;
        on E : Exception do raise;
      end;

      for i := FPrimes to GenPrimes - 1 do Perm[i] := 0;
      for i := 0 to FPrimes - 1 do Perm[i] := 1;

      MinTries := 0;
      MaxTries := 0;

      repeat
        LMultSh(Q, 2, P);
        for i := 0 to GenPrimes - 1 do
          if Perm[i] = 1 then
          begin
            LMult(P, Primes[i], Tmp);
            LCopy(P, Tmp);
          end;

        LAdd(P, 1, P);

        L := LBitCount(P);

        if L < Bits then
        begin
          Inc(MinTries);
          if MinTries >= 20 then
          begin
            MinTries := 0;
            MaxTries := 0;
            Inc(QBits);

            try
              LGenPrimeEx(Q, QBits, false, ProgressFunc, Data, True);
            except
              on E : EElMathException do Exit;
              on E : Exception do raise;
            end;
          end;
        end;

        if L > Bits then
        begin
          Inc(MaxTries);
          if MaxTries >= 20 then
          begin
            MinTries := 0;
            MaxTries := 0;
            Dec(QBits);

            try
              LGenPrimeEx(Q, QBits, false, ProgressFunc, Data, True);
            except
              on E : EElMathException do Exit;
              on E : Exception do raise;
            end;
          end;
        end;

        try
          if (L = Bits) and (LIsPrime(P, ProgressFunc, Data, true)) then
            Generated := true;
        except
          on E : EElMathException do Exit;
          on E : Exception do raise;
        end;

      until Generated or (not NextPermutation(Perm));

    until Generated;


    Generated := false;

    LSub(P, 1, P1);

    L := 0;
    for i := 0 to GenPrimes - 1 do
      if Perm[i] = 1 then
      begin
        if i <> L then LSwap(Primes[L], Primes[i]);
        Inc(L);
      end;

    LSwap(Primes[L], Q);
    Primes[L + 1].Length := 1;
    Primes[L + 1].Digits[1] := 2;
    Inc(L, 2);

    G.Digits[1] := 4; //starting from 5
    G.Length := 1;


    repeat
      Inc(G.Digits[1]);

      for i := 0 to L - 1 do
      begin
        LDiv(P1, Primes[i], C, D);
        try
          LMModPower(G, C, P, D, ProgressFunc, Data, True);
        except
          on E : EElMathException do Exit;
          on E : Exception do raise;
        end;
        LTrim(D);
        if ((D.Length = 1) and (D.Digits[1] = 1)) then Break
        else if i = L - 1 then Generated := true;
      end;

    until Generated;


    SBRndGenerateLInt(X, (QBits shl 1) shr 3);
    while LGreater(X, P) do LShr(X);
    X.Digits[1] := X.Digits[1] or 1;
    try
      LMModPower(G, X, P, Y, ProgressFunc, Data, true);
    except
      on E : EElMathException do Exit;
      on E : Exception do raise;
    end;
    Result := true;
  finally
    ReleaseArray(Perm);
    LDestroy(C);
    LDestroy(D);
    LDestroy(Q);
    LDestroy(P1);
    LDestroy(Tmp);
    for i := 0 to GenPrimes - 1 do
      LDestroy(Primes[i]);
  end;
end;

function ExternalGenerate(Bits : integer; P : PLInt; G : PLInt; X: PLInt;
  Y : PLInt;
  ProgressFunc : TSBMathProgressFunc;
  Data :  pointer ) : boolean;
var
  EP, EG, EX, EY : ByteArray;
begin
  try
    IntExternalGenerate(Bits, EP, EG, EX, EY);
    try
      PointerToLInt(P,  @EP[0], Length(EP) );
      PointerToLInt(G,  @EG[0], Length(EG) );
      PointerToLInt(X,  @EX[0], Length(EX) );
      PointerToLInt(Y,  @EY[0], Length(EY) );
    finally
      ReleaseArrays(EP, EG, EX, EY);
    end;
    Result := true;
  except
    Result := false;
  end;
end;

function Encrypt(Src : PLInt; P : PLInt; G : PLInt; Y : PLInt; A : PLInt; B : PLInt) : boolean;
var
  K, T1, T2, T3, One : PLInt;
  KSize : integer;
  F : boolean;
begin
  if LGreater(Src, P) or LGreater(G, P) or LGreater(Y, P) then
  begin
    Result := false;
    Exit;
  end;

  LCreate(K);
  LCreate(T1);
  LCreate(T2);
  LCreate(T3);
  LCreate(One);
  try
    KSize := (WienerQBits(P.Length shl 5) + 31) shr 5;

    repeat
      LGenerate(K, KSize);
      K.Digits[1] := K.Digits[1] or 1;
      LSub(P, One, T2);
      LGCD(K, T2, T1, T3);
      F := (T1.Length = 1) and (T1.Digits[1] = 1);
    until F;

    LMModPower(G, K, P, A);
    LMModPower(Y, K, P, T1);
    LMult(T1, Src, T2);
    LModEx(T2, P, B);
    Result := true;
  finally
    LDestroy(K);
    LDestroy(T1);
    LDestroy(T2);
    LDestroy(T3);
    LDestroy(One);
  end;
end;
 {$endif SB_PGPSFX_STUB}

function Decrypt(P : PLInt; G : PLInt; X : PLInt; A : PLInt; B : PLInt; Dest : PLInt) : boolean;
var
  T1, T2 : PLInt;
begin
  if LGreater(G, P) or LGreater(X, P) or LGreater(A, P) or LGreater(B, P) then
  begin
    Result := false;
    Exit;
  end;
  LCreate(T1);
  LCreate(T2);
  try
    LGCD(A, P, T1, T2);
    LMModPower(T2, X, P, T1);
    LMult(B, T1, T2);
    LModEx(T2, P, Dest);
    Result := true;
  finally
    LDestroy(T1);
    LDestroy(T2);
  end;
end;

function Sign(Src : PLint; P : PLInt; G : PLInt; X : PLInt; A : PLint; B : PLInt) : boolean;
var
  K, KInv, T1, T2, T3, One : PLInt;
  F : boolean;
begin
  if LGreater(Src, P) or LGreater(G, P) or LGreater(X, P) then
  begin
    Result := false;
    Exit;
  end;
  LCreate(K);
  LCreate(KInv);
  LCreate(T1);
  LCreate(T2);
  LCreate(T3);
  LCreate(One);
  try
    LSub(P, One, T2);
    repeat
      LGenerate(K, P.Length);
      while LGreater(K, P) do
        LShr(K);
      K.Digits[1] := K.Digits[1] or 1;
      LGCD(K, T2, T1, KInv);
      F := (T1.Length = 1) and (T1.Digits[1] = 1);
    until F;
    LMModPower(G, K, P, A);
    LMult(A, X, T1);
    LModEx(T1, T2, T3);
    if not LGreater(Src, T3) then
      LAdd(Src, T2, T1)
    else
      LCopy(T1, Src);
    LSub(T1, T3, B);
    LMult(B, KInv, T1);
    LModEx(T1, T2, B);
    Result := true;
  finally
    LDestroy(K);
    LDestroy(KInv);
    LDestroy(T1);
    LDestroy(T2);
    LDestroy(T3);
    LDestroy(One);
  end;
end;

function Verify(Src : PLInt; P : PLInt; G : PLInt; Y : PLInt; A : PLInt; B : PLInt) : boolean;
var
  T1, T2, T3 : PLInt;
begin
  if LGreater(Src, P) or LGreater(G, P) or LGreater(Y, P) or LGreater(A, P) or
    LGreater(B, P) then
  begin
    Result := false;
    Exit;
  end;
  LCreate(T1);
  LCreate(T2);
  LCreate(T3);
  try
    LMModPower(Y, A, P, T1);
    LMModPower(A, B, P, T2);
    LMult(T1, T2, T3);
    LModEx(T3, P, T1);
    LMModPower(G, Src, P, T2);
    Result := LEqual(T2, T1);
  finally
    LDestroy(T1);
    LDestroy(T2);
    LDestroy(T3);
  end;
end;

function EncodeResult(R : pointer; RSize : integer; S : pointer; SSize :
  integer; Blob: pointer; var BlobSize : integer) : boolean;
var
  EstSize : integer;
  BufR, BufS : ByteArray;
  Tag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
begin
  EstSize := RSize + SSize + 16;
  if BlobSize < EstSize then
  begin
    BlobSize := EstSize;
    Result := false;
    Exit;
  end;
  if PByte(R)^ >= $80 then
  begin
    SetLength(BufR, RSize + 1);
    SBMove(R^, BufR[0 + 1], RSize);
    BufR[0] := byte(0);
  end
  else
  begin
    SetLength(BufR, RSize);
    SBMove(R^, BufR[0], RSize);
  end;

  if PByte(S)^ >= $80 then
  begin
    SetLength(BufS, SSize + 1);
    SBMove(S^, BufS[0 + 1], SSize);
    BufS[0] := byte(0);
  end
  else
  begin
    SetLength(BufS, SSize);
    SBMove(S^, BufS[0], SSize);
  end;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    Tag.TagId := SB_ASN1_SEQUENCE;
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.TagId := SB_ASN1_INTEGER;
    STag.Content := BufR;
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.TagId := SB_ASN1_INTEGER;
    STag.Content := BufS;
    Result := Tag.SaveToBuffer(Blob, BlobSize);
  finally
    FreeAndNil(Tag);
  end;
  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  ReleaseArray(BufR);
  ReleaseArray(BufS);
   {$endif}
end;

function DecodeResult(Blob : pointer; Size : integer; R : pointer;
  var RSize : integer; S : pointer; var SSize : integer) : boolean;
var
  Tag, CTag : TElASN1ConstrainedTag;
  SR, SS : ByteArray;
begin
  Result := false;

  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if Tag.LoadFromBuffer(Blob , Size ) then
    begin
      if (not Tag.IsConstrained) or (TElASN1ConstrainedTag(Tag).Count <> 1) then
        Exit;

      CTag := TElASN1ConstrainedTag(Tag.GetField(0));
      if (CTag.TagId <> SB_ASN1_SEQUENCE) then
        Exit;

      if TElASN1ConstrainedTag(CTag).Count <> 2 then
        Exit;

      if (TElASN1ConstrainedTag(CTag).GetField(0).IsConstrained) or
        (TElASN1ConstrainedTag(CTag).GetField(1).IsConstrained) or
        (TElASN1ConstrainedTag(CTag).GetField(0).TagId <> SB_ASN1_INTEGER) or
        (TElASN1ConstrainedTag(CTag).GetField(1).TagId <> SB_ASN1_INTEGER) then
        Exit;

      SR := TElASN1SimpleTag(TElASN1ConstrainedTag(CTag).GetField(0)).Content;
      SS := TElASN1SimpleTag(TElASN1ConstrainedTag(CTag).GetField(1)).Content;
      if (Length(SR) > RSize) or (Length(SS) > SSize) then
      begin
        RSize := Length(SR);
        SSize := Length(SS);
        Exit;
      end;

      SBMove(SR[0], R^, Length(SR));
      RSize := Length(SR);
      SBMove(SS[0], S^, Length(SS));
      SSize := Length(SS);
      Result := true;
    end;
  finally
    FreeAndNil(Tag);
    {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
    ReleaseArray(SR);
    ReleaseArray(SS);
     {$endif}
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
    SBMove(Buffer^, Result[1], Size);
    Result[0] := 0;
  end
  else
  begin
    SetLength(Result, Size);
    SBMove(Buffer^, Result[0], Size);
  end;
end;

function EncodePublicKey(P : pointer; PSize : integer;
  G : pointer; GSize : integer; Y : pointer; YSize : integer;
  OutBuffer : pointer; var OutSize : integer) : boolean;
var
  Tag : TElASN1ConstrainedTag;
  InnerTag : TElASN1ConstrainedTag;
  SimpleTag : TElASN1SimpleTag;
  Tmp : ByteArray;
  Sz : integer;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    Tag.TagId := SB_ASN1_SEQUENCE;

    InnerTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    InnerTag.TagId := SB_ASN1_SEQUENCE;
    
    SimpleTag := TElASN1SimpleTag(InnerTag.GetField(InnerTag.AddField(false)));
    SimpleTag.TagId := SB_ASN1_OBJECT;
    SimpleTag.Content := StrToOID(SB_ELGAMAL_OID);
    
    InnerTag := TElASN1ConstrainedTag(InnerTag.GetField(InnerTag.AddField(true)));
    InnerTag.TagId := SB_ASN1_SEQUENCE;

    SimpleTag := TElASN1SimpleTag(InnerTag.GetField(InnerTag.AddField(false)));
    SimpleTag.TagId := SB_ASN1_INTEGER;
    SimpleTag.Content := FormatIntegerValue(P , PSize );
    SimpleTag := TElASN1SimpleTag(InnerTag.GetField(InnerTag.AddField(false)));
    SimpleTag.TagId := SB_ASN1_INTEGER;
    SimpleTag.Content := FormatIntegerValue(G , GSize );
      
    SimpleTag := TElASN1SimpleTag.CreateInstance;
    try
      SimpleTag.TagId := SB_ASN1_INTEGER;
      SimpleTag.Content := FormatIntegerValue(Y , YSize );
      
      Sz := 0;
      SimpleTag.SaveToBuffer( @Tmp[0] , Sz);
      SetLength(Tmp, Sz);
      SimpleTag.SaveToBuffer( @Tmp[0] , Sz);
      SetLength(Tmp, Sz);
    finally
      FreeAndNil(SimpleTag);
    end;
    
    SimpleTag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    SimpleTag.TagId := SB_ASN1_BITSTRING;
    SimpleTag.Content := SBConcatArrays(0, Tmp);
    
    Result := Tag.SaveToBuffer(OutBuffer, OutSize);
  finally
    FreeAndNil(Tag);
  end;
end;

function EncodePrivateKey(P : pointer; PSize : integer;
  G : pointer; GSize : integer; X : pointer; XSize : integer;
  OutBuffer : pointer; var OutSize : integer) : boolean;
var
  Tag : TElASN1ConstrainedTag;
  InnerTag : TElASN1ConstrainedTag;
  SimpleTag : TElASN1SimpleTag;
  Tmp : ByteArray;
  Sz : integer;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    Tag.TagId := SB_ASN1_SEQUENCE;
    
    SimpleTag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    SimpleTag.TagId := SB_ASN1_INTEGER;
    ASN1WriteInteger(SimpleTag, 0);

    InnerTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    InnerTag.TagId := SB_ASN1_SEQUENCE;
    
    SimpleTag := TElASN1SimpleTag(InnerTag.GetField(InnerTag.AddField(false)));
    SimpleTag.TagId := SB_ASN1_OBJECT;
    SimpleTag.Content := StrToOID(SB_ELGAMAL_OID);
    
    InnerTag := TElASN1ConstrainedTag(InnerTag.GetField(InnerTag.AddField(true)));
    InnerTag.TagId := SB_ASN1_SEQUENCE;

    SimpleTag := TElASN1SimpleTag(InnerTag.GetField(InnerTag.AddField(false)));
    SimpleTag.TagId := SB_ASN1_INTEGER;
    SimpleTag.Content := FormatIntegerValue(P , PSize );
    SimpleTag := TElASN1SimpleTag(InnerTag.GetField(InnerTag.AddField(false)));
    SimpleTag.TagId := SB_ASN1_INTEGER;
    SimpleTag.Content := FormatIntegerValue(G , GSize );
    
    SimpleTag := TElASN1SimpleTag.CreateInstance;
    try
      SimpleTag.TagId := SB_ASN1_INTEGER;
      SimpleTag.Content := FormatIntegerValue(X , XSize );
      
      Sz := 0;
      SimpleTag.SaveToBuffer( @Tmp[0] , Sz);
      SetLength(Tmp, Sz);
      SimpleTag.SaveToBuffer( @Tmp[0] , Sz);
      SetLength(Tmp, Sz);
    finally
      FreeAndNil(SimpleTag);
    end;
    
    SimpleTag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    SimpleTag.TagId := SB_ASN1_BITSTRING;
    SimpleTag.Content := SBConcatArrays(0, Tmp);
    
    Result := Tag.SaveToBuffer(OutBuffer, OutSize);
  finally
    FreeAndNil(Tag);
  end;
end;

end.

