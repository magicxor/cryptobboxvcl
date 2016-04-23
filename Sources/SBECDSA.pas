(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBECDSA;

interface

uses
  SBConstants,
  SBMath,
  SBECMath,
  SBECCommon,
  SysUtils,
  SBTypes,
  SBStrUtils,
  SBUtils;
  //SBHashFunction;


function GenerateEx(A : pointer; ASize : integer; B : pointer; BSize : integer;
  X : pointer; XSize : integer; Y : pointer; YSize : integer; N : pointer; NSize : integer;
  P : pointer; PSize : integer; FldType, Fld : integer;
  D : pointer ; var DSize : integer; Qx : pointer; var QxSize : integer;
  Qy : pointer; var QySize : integer) : boolean;
function ExternalGenerateEx(A : pointer; ASize : integer; B : pointer; BSize : integer;
  X : pointer; XSize : integer; Y : pointer; YSize : integer; N : pointer; NSize : integer;
  P : pointer; PSize : integer; CurveID: integer; const CurveOID: ByteArray; FldType, Fld : integer;
  D : pointer ; var DSize : integer; Qx : pointer; var QxSize : integer;
  Qy : pointer; var QySize : integer) : boolean;
function SignEx(hash : pointer; hashSize : integer; d : pointer; dSize : integer;
  A : pointer; ASize : integer; B : pointer; BSize : integer;
  X : pointer; XSize : integer; Y : pointer; YSize : integer;
  N : pointer; NSize : integer; P : pointer; PSize : integer;
  FldType, Fld, Flag : integer;
  R : pointer; var RSize : integer; S : pointer; var SSize : integer) : boolean;
function VerifyEx(hash : pointer; hashSize : integer; Qx : pointer; QxSize : integer;
  Qy : pointer; QySize : integer; R : pointer; RSize : integer;
  S : pointer; SSize : integer;
  A : pointer; ASize : integer; B : pointer; BSize : integer;
  X : pointer; XSize : integer; Y : pointer; YSize : integer;
  N : pointer; NSize : integer; P : pointer; PSize : integer;
  FldType, Fld, Flags : integer) : boolean;
function ExternalGenerationSupported : boolean; 

implementation

resourcestring
  SInvalidECParameter = 'Invalid EC parameter';
  //SUnknownCurve = 'Unknown curve';
  SUnsupportedField = 'Unsupported field';
  //SInternalError = 'Internal error';
  

procedure IntExternalGenerate(const A, B, X, Y, N, P : ByteArray; CurveID: integer;
  const CurveOID: ByteArray; FldType, Fld : integer; out D, Qx, Qy : ByteArray);
begin
  // For each platform, implement its own IntExternalGenerate<PLATFORM> method
  // (e.g. IntExternalGenerateWP8) with the same signature and delegate the call
  // to it from here. Arrange calls to methods for different platforms with conditional defines.
  raise ESecureBlackboxError.Create('Method not implemented for the active platform: SBECDSA.IntExternalGenerate()');
end;

function ExternalGenerationSupported : boolean; 
begin
  Result := false;
end;

function GenerateEx(A : pointer; ASize : integer; B : pointer; BSize : integer;
  X : pointer; XSize : integer; Y : pointer; YSize : integer; N : pointer; NSize : integer;
  P : pointer; PSize : integer; FldType, Fld : integer;
  D : pointer ; var DSize : integer; Qx : pointer; var QxSize : integer;
  Qy : pointer; var QySize : integer) : boolean;
var
  LA, LB, LP, LX, LY, LN, LD, LQX, LQY, LTmp : PLInt;
  FldSize, NRSize : integer;
begin
  Result := false;

  NRSize := (BufferBitCount(N,  NSize ) + 7) shr 3;

  if FldType = SB_EC_FLD_TYPE_FP then
    FldSize := (BufferBitCount(P,  PSize ) + 7) shr 3
  else
    FldSize := (BufferBitCount(P,  PSize ) + 7 - 1) shr 3;

  if (DSize < NRSize) or (QxSize < FldSize) or (QySize < FldSize) then
  begin
    DSize := NRSize;
    QxSize := FldSize;
    QySize := FldSize;
    Exit;
  end;

  LCreate(LX);
  LCreate(LY);
  LCreate(LA);
  LCreate(LB);
  LCreate(LN);
  LCreate(LP);
  LCreate(LD);
  LCreate(LQX);
  LCreate(LQY);
  LCreate(LTmp);

  try
    PointerToLInt(LP, P,  PSize );
    PointerToLInt(LN, N,  NSize );      
    BufferToFieldElement(X,  XSize,  LX, LP);
    BufferToFieldElement(Y,  YSize,  LY, LP);
    BufferToFieldElement(A,  ASize,  LA, LP);
    BufferToFieldElement(B,  BSize,  LB, LP);

    repeat
      LGenerate(LTmp, LN.Length);
      LModEx(LTmp, LN, LD);
    until not LNull(LD);

    if FldType = SB_EC_FLD_TYPE_FP then
    begin
      ECPFpExpJA(LX, LY, LP, LA, LD, LQX, LQY, Fld);
      {$ifdef ECC_TEST_INCLUDED}
      if not ECPFpPointOnCurve(LX, LY, LA, LB, LP, Fld) then
        raise EElECMathError.Create(SInternalError);
      if not ECPFpPointOnCurve(LQX, LQY, LA, LB, LP, Fld) then
        raise EElECMathError.Create(SInternalError);
       {$endif}  
    end
    else if FldType = SB_EC_FLD_TYPE_F2MP then
    begin
      ECPF2mPExpLDA(LX, LY, LA, LB, LP, LD, LQX, LQY, Fld);
      {$ifdef ECC_TEST_INCLUDED}
      if not ECPF2mPPointOnCurve(LQX, LQY, LA, LB, LP, Fld) then
        raise EElECMathError.Create(SInternalError);
       {$endif}
    end
    else
      raise EElECError.Create(SUnsupportedField);
      
    LIntToPointerTrunc(LD, D, DSize);
    LIntToPointerTrunc(LQX, Qx, QxSize);
    LIntToPointerTrunc(LQY, Qy, QySize);

    Result := true;
  finally
    LDestroy(LX);
    LDestroy(LY);
    LDestroy(LA);
    LDestroy(LB);
    LDestroy(LN);
    LDestroy(LP);
    LDestroy(LD);
    LDestroy(LQX);
    LDestroy(LQY);
    LDestroy(LTmp);
  end;
end;

function ExternalGenerateEx(A : pointer; ASize : integer; B : pointer; BSize : integer;
  X : pointer; XSize : integer; Y : pointer; YSize : integer; N : pointer; NSize : integer;
  P : pointer; PSize : integer; CurveID: integer; const CurveOID: ByteArray; FldType, Fld : integer;
  D : pointer ; var DSize : integer; Qx : pointer; var QxSize : integer;
  Qy : pointer; var QySize : integer) : boolean;
var
  NRSize, FldSize : integer;
  EA, EB, EX, EY, EN, EP, ED, EQx, EQy : ByteArray;
begin

  Result := false;

  NRSize := (BufferBitCount(N,  NSize ) + 7) shr 3;

  if FldType = SB_EC_FLD_TYPE_FP then
    FldSize := (BufferBitCount(P,  PSize ) + 7) shr 3
  else
    FldSize := (BufferBitCount(P,  PSize ) + 7 - 1) shr 3;

  if (DSize < NRSize) or (QxSize < FldSize) or (QySize < FldSize) then
  begin
    DSize := NRSize;
    QxSize := FldSize;
    QySize := FldSize;
    Exit;
  end;

  try
    EA := CloneArray(A , ASize );
    EB := CloneArray(B , BSize );
    EX := CloneArray(X , XSize );
    EY := CloneArray(Y , YSize );
    EN := CloneArray(N , NSize );
    EP := CloneArray(P , PSize );
    try
      IntExternalGenerate(EA, EB, EX, EY, EN, EP, CurveID, CurveOID, FldType, Fld, ED, EQx, EQy);
      DSize := Length(ED);
      QxSize := Length(EQx);
      QySize := Length(EQy);
      Move(ED[0], D^, DSize);
      Move(EQx[0], Qx^, QxSize);
      Move(EQy[0], Qy^, QySize);
      Result := true;
    finally
      ReleaseArrays(EA, EB, EX, EY, EN, EP, ED, EQx, EQy);
    end;
  except
    Result := false;
  end;
end;

function SignEx(hash : pointer; hashSize : integer; d : pointer; dSize : integer;
  A : pointer; ASize : integer; B : pointer; BSize : integer;
  X : pointer; XSize : integer; Y : pointer; YSize : integer;
  N : pointer; NSize : integer; P : pointer; PSize : integer;
  FldType, Fld, Flag : integer;
  R : pointer; var RSize : integer; S : pointer; var SSize : integer) : boolean;
var
  NRSize, i : integer;
  LX, LY, LA, LB, LN, LP, LX1, LY1, LK, LK1, LTmp : PLInt;
  LHash, LD, LR, LS : PLInt;
begin
  Result := false;

  LCreate(LHash);
  LCreate(LX);
  LCreate(LY);
  LCreate(LA);
  LCreate(LB);
  LCreate(LN);
  LCreate(LP);
  LCreate(LD);
  LCreate(LR);
  LCreate(LS);
  LCreate(LX1);
  LCreate(LY1);
  LCreate(LK);
  LCreate(LK1);
  LCreate(LTmp);

  try
    PointerToLInt(LP, P,  PSize );
    PointerToLInt(LN, N,  NSize );
    BufferToFieldElement(X,  XSize,  LX, LP);
    BufferToFieldElement(Y,  YSize,  LY, LP);
    BufferToFieldElement(A,  ASize,  LA, LP);
    BufferToFieldElement(B,  BSize,  LB, LP);

    NRSize := (LBitCount(LN) + 7) shr 3;

    if ( DSize  > NRSize){ or (hashSize > NSize)} then
      raise EElECError.Create(SInvalidECParameter);

    if (SSize < NRSize) or (RSize < NRSize) then
    begin
      RSize := NRSize;
      SSize := NRSize;
      Exit;
    end;

    PointerToLInt(LHash, hash,  hashSize );
    PointerToLInt(LD, D,  DSize );

    { hash truncation }
    if (Flag and SB_ECDSA_WRAP_MOD_N) <> 0 then
    begin
      { for German ECDSA Plain hash is truncated via modular reduction }
      if LGreater(LN, LHash) then
      begin
        LModEx(LHash, LN, LTmp);
        LCopy(LHash, LTmp);
      end;
    end
    else
    begin
      i :=  hashSize   shl 3 - integer(LBitCount(LN));
      if i > 0 then
        LShrEx(LHash, i);
    end;        
      
    repeat
      { generating K from [1..N-1] }
      LGenerate(LK, (NRSize + 3) shr 2);
      LModEx(LK, LN, LTmp);

      if LNull(LTmp) then
        LAdd(LTmp, 1, LK)
      else
        LCopy(LK, LTmp);

      if FldType = SB_EC_FLD_TYPE_FP then
        ECPFpExpJA(LX, LY, LP, LA, LK, LX1, LY1, Fld)
      else if FldType = SB_EC_FLD_TYPE_F2MP then
        ECPF2mPExpLDA(LX, LY, LA, LB, LP, LK, LX1, LY1, Fld)
      else
        raise EElECError.Create(SUnsupportedField);

      LModEx(LX1, LN, LR);
    until not LNull(LR);

    LGCD(LK, LN, LTmp, LK1); // K1 = K^-1
    LMult(LD, LR, LY1); // Y1 = D * R
    LAdd(LY1, LHash, LX1); // X1 = Hash + D * R
    LMult(LX1, LK1, LY1); // Y1 = K^-1 * (Hash + D * R)
    LModEx(LY1, LN, LS); // S = K^-1 * (Hash + D * R) mod N

    LIntToPointerTrunc(LR, R, RSize);
    LIntToPointerTrunc(LS, S, SSize);

    Result := true;
  finally
    LDestroy(LHash);
    LDestroy(LX);
    LDestroy(LY);
    LDestroy(LA);
    LDestroy(LB);
    LDestroy(LN);
    LDestroy(LP);
    LDestroy(LD);
    LDestroy(LR);
    LDestroy(LS);
    LDestroy(LX1);
    LDestroy(LY1);
    LDestroy(LK);
    LDestroy(LK1);
    LDestroy(LTmp);
  end;
end;

function VerifyEx(hash : pointer; hashSize : integer; Qx : pointer; QxSize : integer;
  Qy : pointer; QySize : integer; R : pointer; RSize : integer;
  S : pointer; SSize : integer;
  A : pointer; ASize : integer; B : pointer; BSize : integer;
  X : pointer; XSize : integer; Y : pointer; YSize : integer;
  N : pointer; NSize : integer; P : pointer; PSize : integer;
  FldType, Fld, Flags : integer) : boolean;
var
  FldSize, i : integer;
  LX, LY, LA, LB, LN, LP, LX1, LY1, LX2, LY2, LU1, LU2, LTmp : PLInt;
  LHash, LQX, LQY, LR, LS, LS1 : PLInt;
begin
  Result := false;

  LCreate(LHash);
  LCreate(LX);
  LCreate(LY);
  LCreate(LA);
  LCreate(LB);
  LCreate(LN);
  LCreate(LP);
  LCreate(LQX);
  LCreate(LQY);
  LCreate(LR);
  LCreate(LS);
  LCreate(LS1);
  LCreate(LX1);
  LCreate(LY1);
  LCreate(LX2);
  LCreate(LY2);
  LCreate(LU1);
  LCreate(LU2);
  LCreate(LTmp);

  try
    PointerToLInt(LP, P,  PSize );
    PointerToLInt(LN, N,  NSize );      
    BufferToFieldElement(X,  XSize,  LX, LP);
    BufferToFieldElement(Y,  YSize,  LY, LP);
    BufferToFieldElement(A,  ASize,  LA, LP);
    BufferToFieldElement(B,  BSize,  LB, LP);

    FldSize := (LBitCount(LP) + 7) shr 3;
    if ( QxSize  > FldSize) or ( QySize  > FldSize) then
      Exit;

    BufferToFieldElement(QX,  QXSize,  LQX, LP);
    BufferToFieldElement(QY,  QYSize,  LQY, LP);
    PointerToLInt(LHash, hash,  hashSize );    
    PointerToLInt(LR, R,  RSize );
    PointerToLInt(LS, S,  SSize );

    { hash truncation }

    if (flags and SB_ECDSA_WRAP_MOD_N) <> 0 then
    begin
      { for German ECDSA Plain hash is truncated via modular reduction }
      if LGreater(LN, LHash) then
      begin
        LModEx(LHash, LN, LTmp);
        LCopy(LHash, LTmp);
      end;   
    end
    else
    begin
      { normal hash truncation - right shift }
      i :=  hashSize  shl 3 - integer(LBitCount(LN));
      if i > 0 then
        LShrEx(LHash, i);
    end;           

    if LGreater(LR, LN) or LGreater(LS, LN) or LNull(LR) or LNull(LS) then
      Exit;

    LGCD(LS, LN, LTmp, LS1); { S1 = S^-1 }
    LMult(LS1, LHash, LTmp);
    LModEx(LTmp, LN, LU1); { U1 = S^-1 * Hash mod N }
    LMult(LS1, LR, LTmp);
    LModEx(LTmp, LN, LU2); { U2 = S^-1 * R mod N }

    if FldType = SB_EC_FLD_TYPE_FP then
    begin
      {$ifdef ECC_TEST_INCLUDED}
      if not ECPFpPointOnCurve(LX, LY, LA, LB, LP, Fld) then
        raise EElECError.Create(SInternalError);
      if not ECPFpPointOnCurve(LQX, LQY, LA, LB, LP, Fld) then
        raise EElECError.Create(SInternalError);
       {$endif}

      ECPFpExpJA(LX, LY, LP, LA, LU1, LX1, LY1, Fld);
      ECPFpExpJA(LQX, LQY, LP, LA, LU2, LX2, LY2, Fld);
      ECPFpAdd(LX1, LY1, LX2, LY2, LP, LA, LX, LY, Fld);
    end
    else if FldType = SB_EC_FLD_TYPE_F2MP then
    begin
      {$ifdef ECC_TEST_INCLUDED}
      if not ECPF2mPPointOnCurve(LX, LY, LA, LB, LP, Fld) then
        raise EElECError.Create(SInternalError);
      if not ECPF2mPPointOnCurve(LQX, LQY, LA, LB, LP, Fld) then
        raise EElECError.Create(SInternalError);
       {$endif}

      ECPF2mPExpLDA(LX, LY, LA, LB, LP, LU1, LX1, LY1, Fld);
      ECPF2mPExpLDA(LQX, LQY, LA, LB, LP, LU2, LX2, LY2, Fld);
      ECPF2mPAdd(LX1, LY1, LX2, LY2, LA, LB, LP, LX, LY, Fld);
    end
    else
      raise EElECError.Create(SUnsupportedField);

    if LX.Length = 0 then Exit; // point on infinity

    LModEx(LX, LN, LTmp);

    Result := LEqual(LTmp, LR);
  finally
    LDestroy(LHash);
    LDestroy(LX);
    LDestroy(LY);
    LDestroy(LA);
    LDestroy(LB);
    LDestroy(LN);
    LDestroy(LP);
    LDestroy(LQX);
    LDestroy(LQY);
    LDestroy(LR);
    LDestroy(LS);
    LDestroy(LS1);
    LDestroy(LX1);
    LDestroy(LY1);
    LDestroy(LX2);
    LDestroy(LY2);
    LDestroy(LU1);
    LDestroy(LU2);
    LDestroy(LTmp);
  end;
end;

{$ifdef ECC_TEST_INCLUDED}
(*procedure TestECDSA;
var
  HashFunction : TElHashFunction;
  St : string;
  Hash : ByteArray;
  D, Qx, Qy, R, S : ByteArray;
  DSize, QxSize, QySize, RSize, SSize, Curve, i : integer;
  Res : boolean;
begin
  St := 'Hello, world!';
  HashFunction := TElHashFunction.Create(SB_ALGORITHM_DGST_SHA1);
  {$ifdef SB_VCL}
  HashFunction.Update(@St[1], Length(St));
  {$else}
  HashFunction.Update(BytesOfString(St), 0, Length(St));
  {$endif}
  Hash := HashFunction.Finish;
  FreeAndNil(HashFunction);

  for Curve := SB_EC_NIST_P192 to SB_EC_NIST_K571 do
    for i := 1 to 10 do
    begin
      DSize := 0;

      {$ifdef SB_VCL}
      Generate(nil, DSize, nil, QxSize, nil, QySize, Curve);
      {$else}
      Generate(D, DSize, Qx, QxSize, Qy, QySize, Curve);
      {$endif}
      SetLength(D, DSize);
      SetLength(Qx, QxSize);
      SetLength(Qy, QySize);
      {$ifdef SB_VCL}
      if not Generate(@D[0], DSize, @Qx[0], QxSize, @Qy[0], QySize, Curve) then
      {$else}
      if not Generate(D, DSize, Qx, QxSize, Qy, QySize, Curve) then
      {$endif}
        raise EElECError.Create('');
      SetLength(D, DSize);
      SetLength(Qx, QxSize);
      SetLength(Qy, QySize);

      RSize := 0;
      {$ifdef SB_VCL}
      Sign(@Hash[1], Length(Hash), @D[0], DSize, nil, RSize, nil, SSize, Curve);
      {$else}
      Sign(Hash, D, R, RSize, S, SSize, Curve);
      {$endif}
      SetLength(R, RSize);
      SetLength(S, SSize);
      {$ifdef SB_VCL}
      if not Sign(@Hash[1], Length(Hash), @D[0], DSize, @R[0], RSize, @S[0], SSize, Curve) then
      {$else}
      if not Sign(Hash, D, R, RSize, S, SSize, Curve) then
      {$endif}
        raise EElECError.Create('');
      SetLength(R, RSize);
      SetLength(S, SSize);

      {$ifdef SB_VCL}
      Res := Verify(@Hash[1], Length(Hash), @Qx[0], QxSize, @Qy[0], QySize, @R[0], RSize, @S[0], SSize, Curve);
      {$else}
      Res := Verify(Hash, Qx, Qy, R, S, Curve);
      {$endif}
      if not Res then
        raise EElECError.Create('');
    end;
end;*)
 {$endif}

end.
