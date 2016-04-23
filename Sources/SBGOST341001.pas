(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBGOST341001;

interface

uses
  //SBConstants,
  SBMath,
  SBECMath,
  SBECCommon,
  SysUtils,
  SBTypes,
  SBUtils;
  //SBHashFunction;


function Generate(A : pointer; ASize : integer; B : pointer; BSize : integer;
  X : pointer; XSize : integer; Y : pointer; YSize : integer; N : pointer; NSize : integer;
  P : pointer; PSize : integer; Fld : integer;
  D : pointer ; var DSize : integer; Qx : pointer; var QxSize : integer;
  Qy : pointer; var QySize : integer) : boolean;
function Sign(hash : pointer; hashSize : integer; d : pointer; dSize : integer;
  A : pointer; ASize : integer; B : pointer; BSize : integer;
  X : pointer; XSize : integer; Y : pointer; YSize : integer;
  N : pointer; NSize : integer; P : pointer; PSize : integer;
  Fld : integer;
  R : pointer; var RSize : integer; S : pointer; var SSize : integer) : boolean;
function Verify(hash : pointer; hashSize : integer; Qx : pointer; QxSize : integer;
  Qy : pointer; QySize : integer; R : pointer; RSize : integer;
  S : pointer; SSize : integer;
  A : pointer; ASize : integer; B : pointer; BSize : integer;
  X : pointer; XSize : integer; Y : pointer; YSize : integer;
  N : pointer; NSize : integer; P : pointer; PSize : integer;
  Fld : integer) : boolean;
function DeriveKey(ukm : pointer; ukmSize : integer; D : pointer; DSize : integer; // D - our private key
  Qx : pointer; QxSize : integer; Qy : pointer; QySize : integer; // Qxy - their public
  A : pointer; ASize : integer; B : pointer; BSize : integer;
  X : pointer; XSize : integer; Y : pointer; YSize : integer;
  N : pointer; NSize : integer; P : pointer; PSize : integer;
  Fld : integer;
  R : pointer; var RSize : integer; S : pointer; var SSize : integer) : boolean;

implementation

resourcestring
  SInvalidECParameter = 'Invalid EC parameter';
  //SUnknownCurve = 'Unknown curve';
  //SUnsupportedField = 'Unsupported field';
  //SInternalError = 'Internal error';

function Generate(A : pointer; ASize : integer; B : pointer; BSize : integer;
  X : pointer; XSize : integer; Y : pointer; YSize : integer; N : pointer; NSize : integer;
  P : pointer; PSize : integer; Fld : integer;
  D : pointer ; var DSize : integer; Qx : pointer; var QxSize : integer;
  Qy : pointer; var QySize : integer) : boolean;
var
  LA, LB, LP, LX, LY, LN, LD, LQX, LQY, LTmp : PLInt;
  FldSize, NRSize : integer;
begin
  Result := false;

  NRSize := (BufferBitCount(N,  NSize ) + 7) shr 3;
  FldSize := (BufferBitCount(P,  PSize ) + 7) shr 3;

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

    ECPFpExpJA(LX, LY, LP, LA, LD, LQX, LQY, Fld);
    {$ifdef ECC_TEST_INCLUDED}
    if not ECPFpPointOnCurve(LX, LY, LA, LB, LP, Fld) then
      raise EElECMathError.Create(SInternalError);
    if not ECPFpPointOnCurve(LQX, LQY, LA, LB, LP, Fld) then
      raise EElECMathError.Create(SInternalError);
     {$endif}

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

function Sign(hash : pointer; hashSize : integer; d : pointer; dSize : integer;
  A : pointer; ASize : integer; B : pointer; BSize : integer;
  X : pointer; XSize : integer; Y : pointer; YSize : integer;
  N : pointer; NSize : integer; P : pointer; PSize : integer;
  Fld : integer;
  R : pointer; var RSize : integer; S : pointer; var SSize : integer) : boolean;
var
  NRSize : integer;
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

    NRSize := (LBitCount(LN) + 7) shr 3;

    if ( DSize  > NRSize) then
      raise EElECError.Create(SInvalidECParameter);

    if (SSize < NRSize) or (RSize < NRSize) then
    begin
      RSize := NRSize;
      SSize := NRSize;
      Exit;
    end;

    BufferToFieldElement(X,  XSize,  LX, LP);
    BufferToFieldElement(Y,  YSize,  LY, LP);
    BufferToFieldElement(A,  ASize,  LA, LP);
    BufferToFieldElement(B,  BSize,  LB, LP);
    PointerToLInt(LD, D,  DSize );    
    PointerToLInt(LTmp, hash,  hashSize );

    { hash truncation }
    LModEx(LTmp, LN, LHash);
    if LNull(LHash) then
      LInc(LHash);
 
    repeat
      { generating K from [1..N-1] }
      LGenerate(LK, (NRSize + 3) shr 2);
      LModEx(LK, LN, LTmp);

      if LNull(LTmp) then
        LAdd(LTmp, 1, LK)
      else
        LCopy(LK, LTmp);

      ECPFpExpJA(LX, LY, LP, LA, LK, LX1, LY1, Fld);
      LModEx(LX1, LN, LR);
      
      if LNull(LR) then Continue;

      { LS = (R * D + K * Hash) mod N }
      LMult(LR, LD, LTmp);
      LMult(LK, LHash, LY1);
      LAdd(LTmp, LY1, LX1);
      LModEx(LX1, LN, LS);
      
      if not LNull(LS) then Break;      
    until false;

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

function DeriveKey(ukm : pointer; ukmSize : integer; D : pointer; DSize : integer; // D - our private key
  Qx : pointer; QxSize : integer; Qy : pointer; QySize : integer; // Qxy - their public
  A : pointer; ASize : integer; B : pointer; BSize : integer;
  X : pointer; XSize : integer; Y : pointer; YSize : integer;
  N : pointer; NSize : integer; P : pointer; PSize : integer;
  Fld : integer;
  R : pointer; var RSize : integer; S : pointer; var SSize : integer) : boolean;
var
  NRSize : integer;
  LX, LY, LA, LB, LN, LP, LK, LTmp : PLInt;
  LUkm, LD, LQx, LQy, LR, LS : PLInt;
begin
  Result := false;

  LCreate(LX);
  LCreate(LY);
  LCreate(LA);
  LCreate(LB);
  LCreate(LN);
  LCreate(LP);
  LCreate(LUkm);
  LCreate(LD);
  LCreate(LQx);
  LCreate(LQy);
  LCreate(LR);
  LCreate(LS);
  LCreate(LK);
  LCreate(LTmp);

  try
    PointerToLInt(LP, P,  PSize );
    PointerToLInt(LN, N,  NSize );      

    NRSize := (LBitCount(LN) + 7) shr 3;

    if ( DSize  > NRSize) then
      raise EElECError.Create(SInvalidECParameter);

    if (SSize < NRSize) or (RSize < NRSize) then
    begin
      RSize := NRSize;
      SSize := NRSize;
      Exit;
    end;

    BufferToFieldElement(X,  XSize,  LX, LP);
    BufferToFieldElement(Y,  YSize,  LY, LP);
    BufferToFieldElement(A,  ASize,  LA, LP);
    BufferToFieldElement(B,  BSize,  LB, LP);
    PointerToLInt(LD, D,  DSize );
    PointerToLInt(LUkm, Ukm,  ukmSize );
    BufferToFieldElement(QX,  QXSize,  LQX, LP);
    BufferToFieldElement(QY,  QYSize,  LQY, LP);

    {$ifdef ECC_TEST_INCLUDED}
    if not ECPFpPointOnCurve(LQX, LQY, LA, LB, LP, Fld) then
      raise EElECMathError.Create('');
     {$endif}

    { K = (ukm * d) mod n }
    LMult(LUkm, LD, LTmp);
    LModEx(LTmp, LN, LK);

    { (R, S) = (Qx, Qy) ^ (ukm * d) }
    ECPFpExpJA(LQx, LQy, LP, LA, LK, LR, LS, Fld);

    {$ifdef ECC_TEST_INCLUDED}
    if not ECPFpPointOnCurve(LR, LS, LA, LB, LP, Fld) then
      raise EElECMathError.Create('');
     {$endif}

    LIntToPointerTrunc(LR, R, RSize);
    LIntToPointerTrunc(LS, S, SSize);

    Result := true;
  finally
    LDestroy(LX);
    LDestroy(LY);
    LDestroy(LA);
    LDestroy(LB);
    LDestroy(LN);
    LDestroy(LP);
    LDestroy(LD);
    LDestroy(LUkm);
    LDestroy(LQX);
    LDestroy(LQY);
    LDestroy(LR);
    LDestroy(LS);
    LDestroy(LK);
    LDestroy(LTmp);
  end;
end;


function Verify(hash : pointer; hashSize : integer; Qx : pointer; QxSize : integer;
  Qy : pointer; QySize : integer; R : pointer; RSize : integer;
  S : pointer; SSize : integer;
  A : pointer; ASize : integer; B : pointer; BSize : integer;
  X : pointer; XSize : integer; Y : pointer; YSize : integer;
  N : pointer; NSize : integer; P : pointer; PSize : integer;
  Fld : integer) : boolean;
var
  FldSize : integer;
  LX, LY, LA, LB, LN, LP, LX1, LY1, LX2, LY2, LTmp, LZ1, LZ2 : PLInt;
  LHash, LHash1, LQX, LQY, LR, LS : PLInt;
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
  LCreate(LHash1);
  LCreate(LX1);
  LCreate(LY1);
  LCreate(LX2);
  LCreate(LY2);
  LCreate(LZ1);
  LCreate(LZ2);
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

    BufferToFieldElement(Qx,  QxSize,  LQX, LP);
    BufferToFieldElement(Qy,  QySize,  LQY, LP);
    PointerToLInt(LR, R,  RSize );
    PointerToLInt(LS, S,  SSize );

    PointerToLInt(LTmp, hash,  hashSize );
    LModEx(LTmp, LN, LHash);
    if LNull(LHash) then
      LInc(LHash);

    if LGreater(LR, LN) or LGreater(LS, LN) or LNull(LR) or LNull(LS) then
      Exit;

    LGCD(LHash, LN, LTmp, LHash1);
    LMult(LS, LHash1, LTmp);
    LModEx(LTmp, LN, LZ1); { LZ1 = S*Hash^-1 mod N }
    LMult(LR, LHash1, LZ2);
    LModEx(LZ2, LN, LTmp);
    LSub(LN, LTmp, LZ2); { LZ2 = - R * Hash^-1 mod N }

    {$ifdef ECC_TEST_INCLUDED}
    if not ECPFpPointOnCurve(LX, LY, LA, LB, LP, Fld) then
      raise EElECError.Create(SInternalError);
    if not ECPFpPointOnCurve(LQX, LQY, LA, LB, LP, Fld) then
      raise EElECError.Create(SInternalError);
     {$endif}

    ECPFpExpJA(LX, LY, LP, LA, LZ1, LX1, LY1, Fld);
    ECPFpExpJA(LQX, LQY, LP, LA, LZ2, LX2, LY2, Fld);
    ECPFpAdd(LX1, LY1, LX2, LY2, LP, LA, LX, LY, Fld);

    {$ifdef ECC_TEST_INCLUDED}
    if not ECPFpPointOnCurve(LX1, LY1, LA, LB, LP, Fld) then
      raise EElECError.Create(SInternalError);
    if not ECPFpPointOnCurve(LX2, LY2, LA, LB, LP, Fld) then
      raise EElECError.Create(SInternalError);
    if not ECPFpPointOnCurve(LX, LY, LA, LB, LP, Fld) then
      raise EElECError.Create(SInternalError);
     {$endif}

    if LX.Length = 0 then Exit; // point on infinity

    LModEx(LX, LN, LTmp);
    Result := LEqual(LTmp, LR);
  finally
    LDestroy(LHash);
    LDestroy(LHash1);
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
    LDestroy(LX1);
    LDestroy(LY1);
    LDestroy(LX2);
    LDestroy(LY2);
    LDestroy(LZ1);
    LDestroy(LZ2);
    LDestroy(LTmp);
  end;
end;

{$ifdef ECC_TEST_INCLUDED}
procedure TestECGOST;
var
  DomainParams : TElECDomainParameters;
  A, B, P, X, Y, N, D, QX, QY, R, S, Hash : ByteArray;
  DSize, QXSize, QYSize, RSize, SSize : integer;
  Curve, i : integer;
begin
  DomainParams := TElECDomainParameters.Create;
  SetLength(Hash, 32);
  for i := 1 to 31 do
    Hash[i] := i xor Hash[i - 1];


  for Curve := SB_EC_GOST_CP_TEST to SB_EC_GOST_CP_XCHB do
  begin
    Hash[0] := $77; //just random value

    DomainParams.Curve := Curve;
    A := DomainParams.A;
    B := DomainParams.B;
    P := DomainParams.P;
    X := DomainParams.X;
    Y := DomainParams.Y;
    N := DomainParams.N;

    DSize := 0;
    QXSize := 0;
    QYSize := 0;

    Generate(@A[0], Length(A), @B[0], Length(B), @X[0], Length(X), @Y[0], Length(Y),
      @N[0], Length(N), @P[0], Length(P), DomainParams.Field, nil, DSize, nil, QXSize, nil, QYSize);
    SetLength(D, DSize);
    SetLength(QX, QXSize);
    SetLength(QY, QYSize);
    if not Generate(@A[0], Length(A), @B[0], Length(B), @X[0], Length(X), @Y[0], Length(Y),
      @N[0], Length(N), @P[0], Length(P), DomainParams.Field, @D[0], DSize, @QX[0], QXSize, @QY[0], QYSize)
    then
      raise EElECError.Create(SInternalError);
    SetLength(D, DSize);
    SetLength(QX, QXSize);
    SetLength(QY, QYSize);

    RSize := 0;
    SSize := 0;

    Sign(@Hash[0], 32, @D[0], Length(D), @A[0], Length(A), @B[0], Length(B), @X[0],
      Length(X), @Y[0], Length(Y), @N[0], Length(N), @P[0], Length(P),
      DomainParams.Field, nil, RSize, nil, SSize);
    SetLength(R, RSize);
    SetLength(S, SSize);

    if not Sign(@Hash[0], 32, @D[0], Length(D), @A[0], Length(A), @B[0], Length(B), @X[0],
      Length(X), @Y[0], Length(Y), @N[0], Length(N), @P[0], Length(P),
      DomainParams.Field, @R[0], RSize, @S[0], SSize)
    then
      raise EElECError.Create(SInternalError);
    SetLength(R, RSize);
    SetLength(S, SSize);

    if not Verify(@Hash[0], Length(Hash), @QX[0], Length(QX), @QY[0], Length(QY),
      @R[0], Length(R), @S[0], Length(S), @A[0], Length(A), @B[0], Length(B), @X[0],
      Length(X), @Y[0], Length(Y), @N[0], Length(N), @P[0], Length(P),
      DomainParams.Field)
    then
      raise EElECError.Create(SInternalError);

    Hash[0] := $76;

    if Verify(@Hash[0], Length(Hash), @QX[0], Length(QX), @QY[0], Length(QY),
      @R[0], Length(R), @S[0], Length(S), @A[0], Length(A), @B[0], Length(B), @X[0],
      Length(X), @Y[0], Length(Y), @N[0], Length(N), @P[0], Length(P),
      SB_EC_FLD_CUSTOM)
    then
      raise EElECError.Create(SInternalError);    
  end;

  FreeAndNil(DomainParams);
end;
 {$endif}

end.
