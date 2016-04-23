(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBECMath;

interface
uses
  SBConstants,
  SBMath,
  SBTypes,
  SBUtils;


procedure GetFieldByP(var P : PLInt; var Field, FldType : integer); 
procedure GetBinaryFieldK(P : PLInt; var M, K1, K2, K3 : integer); 
procedure SetBinaryFieldK(var P : PLInt; M, K1, K2, K3 : integer); 

function ECPFpDecompress(yp : integer; X, A, B, P : PLInt; var Y : PLInt; Field : integer) : boolean;
function ECPF2mPDecompress(yp : integer; X, A, B, P : PLInt; var Y : PLInt; Field : integer) : boolean;
{ calculates lower bit of Y*X^-1, used in point compression }
function ECPF2mPGetYpBit(X, Y, P : PLInt; Field : integer) : integer;

{ filed Fp arithmetic }
procedure FpZero(var A : PLInt; P : PLint);
procedure FpOne(var A : PLInt; P : PLint);
procedure FpInt(var A : PLInt; P : PLint; C : cardinal);
function  FpCmp(A, B, P : PLInt) : integer;
procedure FpAdd(A, B, P : PLInt; var C : PLInt);
procedure FpSub(A, B, P : PLInt; var C : PLInt);
function  FpIsOne(A, P : PLInt) : boolean;
function  FpIsZero(A, P : PLInt) : boolean;
procedure FpReduce(var A : PLInt; P, T1, T2 : PLInt; Field : integer);
procedure FpMul(A, B, P, T1, T2 : PLInt; var C : PLInt; Field : integer);
procedure FpSqr(A, P, T1, T2 : PLInt; var C : PLInt; Field : integer);
procedure FpDiv2(A, P : PLInt; var C : PLInt);
procedure FpInv(A, P : PLInt; var C : PLInt; Field : integer);
procedure FpDiv(A, B, P : PLInt; var C : PLInt; Field : integer);

{ field F2m arithmetic }
procedure F2mPZero(var A : PLInt; P : PLint);
procedure F2mPOne(var A : PLInt; P : PLint);
function  F2mPIsZero(A, P : PLInt) : boolean;
function  F2mPIsOne(A, P : PLInt) : boolean;
function  F2mPCmp(A, B, P : PLInt) : integer;
procedure F2mPAdd(A, B, P : PLInt; var C : PLInt);
procedure F2mPReduce(var A : PLInt; P : PLInt; Field : integer);
procedure F2mPMul(A, B, P : PLInt; var T1, C : PLInt; Field : integer);
procedure F2mPSqr(A, P : PLInt; var C : PLInt; Field : integer);
procedure F2mPDivX(A, P : PLint; var C : PLInt);
procedure F2mPDiv(A, B, P : PLInt; var C : PLInt);
procedure F2mPInv(A, P : PLInt; var C : PLInt);

{ elliptic curve over Fp points arithmetic }
procedure ECPFpDouble(x1, y1, P, A : PLInt; var x3, y3 : PLInt; Field : integer); 
procedure ECPFpAdd(x1, y1, x2, y2, P, A : PLInt; var x3, y3 : PLInt; Field : integer); 
procedure ECPFpJDouble(X1, Y1, Z1, P : PLInt; var X3, Y3, Z3 : PLInt; Field : integer);  overload; 
procedure ECPFpJDouble(X1, Y1, Z1, P, A : PLInt; var X3, Y3, Z3 : PLInt; Field : integer);  overload; 
procedure ECPFpJAAdd(X1, Y1, Z1, x2, y2, P : PLInt; var X3, Y3, Z3 : PLInt; Field : integer); 
procedure ECPFpExpJA(x1, y1, P, A, n : PLInt; var xr, yr : PLInt; Field : integer); 
procedure ECPFpExp(x1, y1, P, A, n : PLInt; var xr, yr : PLInt; Field : integer); 
procedure ECPFpJ2A(X, Y, Z, P : PLInt; var xr, yr : PLInt; Field : integer); 
function ECPFpPointOnCurve(X, Y, A, B, P : PLInt; Field : integer) : boolean;

{ elliptic curve over F2m points arithmetic }
procedure ECPF2mPDouble(x1, y1, a, b, P : PLInt; var x3, y3 : PLInt; Field : integer); 
procedure ECPF2mPAdd(x1, y1, x2, y2, a, b, P : PLInt; var x3, y3 : PLInt; Field : integer); 
procedure ECPF2mPLDDouble(X1, Y1, Z1, a, b, P : PLInt; var X3, Y3, Z3 : PLInt; Field : integer); 
procedure ECPF2mPLDAAdd(X1, Y1, Z1, x2, y2, a, b, P : PLInt; var X3, Y3, Z3 : PLInt; Field : integer); 
procedure ECPF2mPExpLDA(x1, y1, a, b, P, n : PLInt; var xr, yr : PLInt; Field : integer); 
procedure ECPF2mPExp(x1, y1, a, b, P, n : PLInt; var xr, yr : PLInt; Field : integer); 
procedure ECPF2mPLD2A(X, Y, Z, P : PLInt; var xr, yr : PLInt; Field : integer); 
function ECPF2mPPointOnCurve(X, Y, A, B, P : PLInt; Field : integer) : boolean;

type
  EElECError = class(ESecureBlackboxError);
  EElECMathError = class(ESecureBlackboxError);

implementation

const
  { table for fast sqr in f2m }
  F2M_SQR_TABLE : array [0..255] of cardinal =
   ( 
     $0,    $1,    $4,    $5,   $10,   $11,   $14,   $15,
    $40,   $41,   $44,   $45,   $50,   $51,   $54,   $55,
   $100,  $101,  $104,  $105,  $110,  $111,  $114,  $115,
   $140,  $141,  $144,  $145,  $150,  $151,  $154,  $155,
   $400,  $401,  $404,  $405,  $410,  $411,  $414,  $415,
   $440,  $441,  $444,  $445,  $450,  $451,  $454,  $455,
   $500,  $501,  $504,  $505,  $510,  $511,  $514,  $515,
   $540,  $541,  $544,  $545,  $550,  $551,  $554,  $555,
  $1000, $1001, $1004, $1005, $1010, $1011, $1014, $1015,
  $1040, $1041, $1044, $1045, $1050, $1051, $1054, $1055,
  $1100, $1101, $1104, $1105, $1110, $1111, $1114, $1115,
  $1140, $1141, $1144, $1145, $1150, $1151, $1154, $1155,
  $1400, $1401, $1404, $1405, $1410, $1411, $1414, $1415,
  $1440, $1441, $1444, $1445, $1450, $1451, $1454, $1455,
  $1500, $1501, $1504, $1505, $1510, $1511, $1514, $1515,
  $1540, $1541, $1544, $1545, $1550, $1551, $1554, $1555,
  $4000, $4001, $4004, $4005, $4010, $4011, $4014, $4015,
  $4040, $4041, $4044, $4045, $4050, $4051, $4054, $4055,
  $4100, $4101, $4104, $4105, $4110, $4111, $4114, $4115,
  $4140, $4141, $4144, $4145, $4150, $4151, $4154, $4155,
  $4400, $4401, $4404, $4405, $4410, $4411, $4414, $4415,
  $4440, $4441, $4444, $4445, $4450, $4451, $4454, $4455,
  $4500, $4501, $4504, $4505, $4510, $4511, $4514, $4515,
  $4540, $4541, $4544, $4545, $4550, $4551, $4554, $4555,
  $5000, $5001, $5004, $5005, $5010, $5011, $5014, $5015,
  $5040, $5041, $5044, $5045, $5050, $5051, $5054, $5055,
  $5100, $5101, $5104, $5105, $5110, $5111, $5114, $5115,
  $5140, $5141, $5144, $5145, $5150, $5151, $5154, $5155,
  $5400, $5401, $5404, $5405, $5410, $5411, $5414, $5415,
  $5440, $5441, $5444, $5445, $5450, $5451, $5454, $5455,
  $5500, $5501, $5504, $5505, $5510, $5511, $5514, $5515,
  $5540, $5541, $5544, $5545, $5550, $5551, $5554, $5555
   ) ;

(*
{$ifndef SB_NET}
resourcestring
{$else}
const
{$endif}
  SUnknownField = 'Unknown field';
  SUnknownCurve = 'Unknown curve';
*)

procedure GetFieldByP(var P : PLInt; var Field, FldType : integer);
begin
  { should be implemented later }
  Field := SB_EC_FLD_CUSTOM;
  FldType := SB_EC_FLD_TYPE_UNKNOWN;
end;

procedure GetBinaryFieldK(P : PLInt; var M, K1, K2, K3 : integer);
var
  i, j : integer;
begin
  M := LBitCount(P) - 1;

  j := 0;

  for i := 1 to M - 1 do
    if LBitSet(P, i) then
    begin
      K1 := i;
      j := i + 1;
      Break;
    end;

  for i := j to M - 1 do
    if LBitSet(P, i) then
    begin
      K2 := i;
      j := i + 1;
      Break;
    end;

  for i := j to M - 1 do
    if LBitSet(P, i) then
    begin
      K3 := i;
      Break;
    end;
end;

procedure SetBinaryFieldK(var P : PLInt; M, K1, K2, K3 : integer);
var
  i : integer;
begin
  P.Length := (M + 32) shr 5;
  for i := 1 to P.Length do
    P.Digits[i] := 0;

  LSetBit(P, M, true);
  LSetBit(P, 0, true);

  if K1 > 0 then
    LSetBit(P, K1, true);
  if K2 > 0 then
    LSetBit(P, K2, true);
  if K3 > 0 then
    LSetBit(P, K3, true);
end;

{ NIST-recommended curves optimized modular reduction }

procedure NISTP192MOD(var A : PLInt; P, Tmp1, Tmp2 : PLInt);
var
  i : integer;
begin
  { p = 2^192-2^64-1 }

  {
   INPUT: An integer c = (c5, c4, c3, c2, c1, c0) in base 2^64 with 0 . c < p2
   192.
   OUTPUT: c mod p192.
   1. Define 192-bit integers:
   s1 = (c2, c1, c0), s2 = (0, c3, c3),
   s3 = (c4, c4,0), s4 = (c5, c5, c5).
   2. Return(s1 +s2+s3+s4 mod p192).
  }

  for i := A.Length + 1 to 12 do
    A.Digits[i] := 0;

  Tmp1.Digits[1] := A.Digits[1];
  Tmp1.Digits[2] := A.Digits[2];
  Tmp1.Digits[3] := A.Digits[3];
  Tmp1.Digits[4] := A.Digits[4];
  Tmp1.Digits[5] := A.Digits[5];
  Tmp1.Digits[6] := A.Digits[6];
  Tmp1.Length := 6;

  Tmp2.Digits[1] := A.Digits[7];
  Tmp2.Digits[2] := A.Digits[8];
  Tmp2.Digits[3] := A.Digits[7];
  Tmp2.Digits[4] := A.Digits[8];
  Tmp2.Length := 4;
  LAdd(Tmp1, Tmp2, Tmp1);

  Tmp2.Digits[1] := 0;
  Tmp2.Digits[2] := 0;
  Tmp2.Digits[3] := A.Digits[9];
  Tmp2.Digits[4] := A.Digits[10];
  Tmp2.Digits[5] := A.Digits[9];
  Tmp2.Digits[6] := A.Digits[10];
  Tmp2.Length := 6;
  LAdd(Tmp1, Tmp2, Tmp1);

  Tmp2.Digits[1] := A.Digits[11];
  Tmp2.Digits[2] := A.Digits[12];
  Tmp2.Digits[3] := A.Digits[11];
  Tmp2.Digits[4] := A.Digits[12];
  Tmp2.Digits[5] := A.Digits[11];
  Tmp2.Digits[6] := A.Digits[12];
  Tmp2.Length := 6;
  LAdd(Tmp1, Tmp2, Tmp1);

  i := Tmp1.Length;
  while (i > 0) and (Tmp1.Digits[i] = 0) do  Dec(i);
  Tmp1.Length := i;

  while LGreater(Tmp1, P) do
    LSub(Tmp1, P, Tmp1);

  LCopy(A, Tmp1);
end;

procedure NISTP224MOD(var A : PLInt; P, Tmp1, Tmp2 : PLInt);
var
  i : integer;
begin
  {
  INPUT: An integer c = (c13, . . ., c2, c1, c0) in base 2^32 with 0 . c < p2
  224.
  OUTPUT: c mod p224.
  1. Define 224-bit integers:
  s1 = (c6, c5, c4, c3, c2, c1, c0), s2 = (c10, c9, c8, c7,0,0,0),
  s3 = (0, c13, c12, c11,0,0,0), s4 = (c13, c12, c11, c10, c9, c8, c7),
  s5 = (0,0,0,0, c13, c12, c11).
  2. Return(s1 +s2+s3-s4-s5 mod p224).
  }

  for i := A.Length + 1 to 14 do
    A.Digits[i] := 0;

  Tmp1.Length := 7;
  Tmp2.Length := 7;

  { s1 }
  Tmp1.Digits[1] := A.Digits[1];
  Tmp1.Digits[2] := A.Digits[2];
  Tmp1.Digits[3] := A.Digits[3];
  Tmp1.Digits[4] := A.Digits[4];
  Tmp1.Digits[5] := A.Digits[5];
  Tmp1.Digits[6] := A.Digits[6];
  Tmp1.Digits[7] := A.Digits[7];

  { s2 }
  Tmp2.Digits[1] := 0;
  Tmp2.Digits[2] := 0;
  Tmp2.Digits[3] := 0;
  Tmp2.Digits[4] := A.Digits[8];
  Tmp2.Digits[5] := A.Digits[9];
  Tmp2.Digits[6] := A.Digits[10];
  Tmp2.Digits[7] := A.Digits[11];
  LAdd(Tmp1, Tmp2, Tmp1);

  { s3 }
  {Tmp2.Digits[1] := 0;
  Tmp2.Digits[2] := 0;
  Tmp2.Digits[3] := 0;}
  Tmp2.Digits[4] := A.Digits[12];
  Tmp2.Digits[5] := A.Digits[13];
  Tmp2.Digits[6] := A.Digits[14];
  Tmp2.Digits[7] := 0;
  LAdd(Tmp1, Tmp2, Tmp1);

  { s4 }

  Tmp2.Digits[1] := A.Digits[8];
  Tmp2.Digits[2] := A.Digits[9];
  Tmp2.Digits[3] := A.Digits[10];
  Tmp2.Digits[4] := A.Digits[11];
  Tmp2.Digits[5] := A.Digits[12];
  Tmp2.Digits[6] := A.Digits[13];
  Tmp2.Digits[7] := A.Digits[14];
  i := Tmp2.Length;
  while (i > 0) and (Tmp2.Digits[i] = 0) do Dec(i);
  Tmp2.Length := i;

  if LGreater(Tmp2, Tmp1) then LAdd(Tmp1, P, Tmp1);
  LSub(Tmp1, Tmp2, Tmp1);

  { s5 }
  Tmp2.Digits[1] := A.Digits[12];
  Tmp2.Digits[2] := A.Digits[13];
  Tmp2.Digits[3] := A.Digits[14];
  Tmp2.Digits[4] := 0;
  Tmp2.Digits[5] := 0;
  Tmp2.Digits[6] := 0;
  Tmp2.Digits[7] := 0;
  i := 3;
  while (i > 0) and (Tmp2.Digits[i] = 0) do  Dec(i);
  Tmp2.Length := i;

  if LGreater(Tmp2, Tmp1) then LAdd(Tmp1, P, Tmp1);
  LSub(Tmp1, Tmp2, Tmp1);

  i := Tmp1.Length;
  while (i > 0) and (Tmp1.Digits[i] = 0) do  Dec(i);
  Tmp1.Length := i;

  while LGreater(Tmp1, P) do
    LSub(Tmp1, P, Tmp1);

  LCopy(A, Tmp1);
end;

procedure NISTP256MOD(var A : PLInt; P, Tmp1, Tmp2 : PLInt);
var
  i : integer;
begin
  {
  p256 = 2^256 - 2^224 + 2^192 + 2^96 - 1
  INPUT: An integer c = (c15, . . ., c2, c1, c0) in base 2^32 with 0 < c < p256^2.
  OUTPUT: c mod p256.
  1. Define 256-bit integers s1-s9.
  2. Return(s1 + 2*s2 +2*s3+s4+s5-s6-s7-s8-s9 mod p256).
  }

  for i := A.Length + 1 to 16 do
    A.Digits[i] := 0;

  Tmp1.Length := 8;
  Tmp2.Length := 8;

  { s1 = (c7, c6, c5, c4, c3, c2, c1, c0)}
  Tmp1.Digits[1] := A.Digits[1];
  Tmp1.Digits[2] := A.Digits[2];
  Tmp1.Digits[3] := A.Digits[3];
  Tmp1.Digits[4] := A.Digits[4];
  Tmp1.Digits[5] := A.Digits[5];
  Tmp1.Digits[6] := A.Digits[6];
  Tmp1.Digits[7] := A.Digits[7];
  Tmp1.Digits[8] := A.Digits[8];

  { s2 = (c15, c14, c13, c12, c11,0,0,0)}
  Tmp2.Digits[1] := 0;
  Tmp2.Digits[2] := 0;
  Tmp2.Digits[3] := 0;
  Tmp2.Digits[4] := A.Digits[12];
  Tmp2.Digits[5] := A.Digits[13];
  Tmp2.Digits[6] := A.Digits[14];
  Tmp2.Digits[7] := A.Digits[15];
  Tmp2.Digits[8] := A.Digits[16];
  LAdd(Tmp1, Tmp2, Tmp1);
  LAdd(Tmp1, Tmp2, Tmp1);

  { s3 = (0, c15, c14, c13, c12,0,0,0)}
  {Tmp2.Digits[1] := 0;
  Tmp2.Digits[2] := 0;
  Tmp2.Digits[3] := 0;}
  Tmp2.Digits[4] := A.Digits[13];
  Tmp2.Digits[5] := A.Digits[14];
  Tmp2.Digits[6] := A.Digits[15];
  Tmp2.Digits[7] := A.Digits[16];
  Tmp2.Digits[8] := 0;
  LAdd(Tmp1, Tmp2, Tmp1);
  LAdd(Tmp1, Tmp2, Tmp1);

  { s4 = (c15, c14,0,0,0, c10, c9, c8)}

  Tmp2.Digits[1] := A.Digits[9];
  Tmp2.Digits[2] := A.Digits[10];
  Tmp2.Digits[3] := A.Digits[11];
  Tmp2.Digits[4] := 0;
  Tmp2.Digits[5] := 0;
  Tmp2.Digits[6] := 0;
  Tmp2.Digits[7] := A.Digits[15];
  Tmp2.Digits[8] := A.Digits[16];
  LAdd(Tmp1, Tmp2, Tmp1);

  { s5 = (c8, c13, c15, c14, c13, c11, c10, c9) }

  Tmp2.Digits[1] := A.Digits[10];
  Tmp2.Digits[2] := A.Digits[11];
  Tmp2.Digits[3] := A.Digits[12];
  Tmp2.Digits[4] := A.Digits[14];
  Tmp2.Digits[5] := A.Digits[15];
  Tmp2.Digits[6] := A.Digits[16];
  Tmp2.Digits[7] := A.Digits[14];
  Tmp2.Digits[8] := A.Digits[9];
  LAdd(Tmp1, Tmp2, Tmp1);

  { s6 = (c10, c8,0,0,0, c13, c12, c11) }

  Tmp2.Digits[1] := A.Digits[12];
  Tmp2.Digits[2] := A.Digits[13];
  Tmp2.Digits[3] := A.Digits[14];
  Tmp2.Digits[4] := 0;
  Tmp2.Digits[5] := 0;
  Tmp2.Digits[6] := 0;
  Tmp2.Digits[7] := A.Digits[9];
  Tmp2.Digits[8] := A.Digits[11];

  i := 8;
  while (i > 0) and (Tmp2.Digits[i] = 0) do Dec(i);
  Tmp2.Length := i;

  if LGreater(Tmp2, Tmp1) then LAdd(Tmp1, P, Tmp1);
  LSub(Tmp1, Tmp2, Tmp1);

  { s7 = (c11, c9,0,0, c15, c14, c13, c12) }

  Tmp2.Digits[1] := A.Digits[13];
  Tmp2.Digits[2] := A.Digits[14];
  Tmp2.Digits[3] := A.Digits[15];
  Tmp2.Digits[4] := A.Digits[16];
  Tmp2.Digits[5] := 0;
  Tmp2.Digits[6] := 0;
  Tmp2.Digits[7] := A.Digits[10];
  Tmp2.Digits[8] := A.Digits[12];

  i := 8;
  while (i > 0) and (Tmp2.Digits[i] = 0) do Dec(i);
  Tmp2.Length := i;

  if LGreater(Tmp2, Tmp1) then LAdd(Tmp1, P, Tmp1);
  LSub(Tmp1, Tmp2, Tmp1);

  { s8 = (c12,0, c10, c9, c8, c15, c14, c13) }

  Tmp2.Digits[1] := A.Digits[14];
  Tmp2.Digits[2] := A.Digits[15];
  Tmp2.Digits[3] := A.Digits[16];
  Tmp2.Digits[4] := A.Digits[9];
  Tmp2.Digits[5] := A.Digits[10];
  Tmp2.Digits[6] := A.Digits[11];
  Tmp2.Digits[7] := 0;
  Tmp2.Digits[8] := A.Digits[13];

  i := 8;
  while (i > 0) and (Tmp2.Digits[i] = 0) do Dec(i);
  Tmp2.Length := i;

  if LGreater(Tmp2, Tmp1) then LAdd(Tmp1, P, Tmp1);
  LSub(Tmp1, Tmp2, Tmp1);

  { s9 = (c13,0, c11, c10, c9,0, c15, c14) }

  Tmp2.Digits[1] := A.Digits[15];
  Tmp2.Digits[2] := A.Digits[16];
  Tmp2.Digits[3] := 0;
  Tmp2.Digits[4] := A.Digits[10];
  Tmp2.Digits[5] := A.Digits[11];
  Tmp2.Digits[6] := A.Digits[12];
  Tmp2.Digits[7] := 0;
  Tmp2.Digits[8] := A.Digits[14];

  i := 8;
  while (i > 0) and (Tmp2.Digits[i] = 0) do Dec(i);
  Tmp2.Length := i;

  if LGreater(Tmp2, Tmp1) then LAdd(Tmp1, P, Tmp1);
  LSub(Tmp1, Tmp2, Tmp1);

  i := Tmp1.Length;
  while (i > 0) and (Tmp1.Digits[i] = 0) do  Dec(i);
  Tmp1.Length := i;

  while LGreater(Tmp1, P) do
    LSub(Tmp1, P, Tmp1);

  LCopy(A, Tmp1);
end;

procedure NISTP384MOD(var A : PLInt; P, Tmp1, Tmp2 : PLInt);
var
  i : integer;
begin
  {
  Fast reduction modulo p384 = 2^384 - 2^128 - 2^96 + 2^32 - 1
  INPUT: An integer c = (c23, . . ., c2, c1, c0) in base 232 with 0 . c < p384*2.
  OUTPUT: c mod p384.
  1. Define 384-bit integers:
  2. Return(s1 +2s2 +s3+s4+s5+s6+s7.s8.s9 .s10 mod p384).
  }

  for i := A.Length + 1 to 24 do
    A.Digits[i] := 0;

  Tmp1.Length := 12;
  Tmp2.Length := 12;

  { s1 = (c11, c10, c9, c8, c7, c6, c5, c4, c3, c2, c1, c0)}
  Tmp1.Digits[1] := A.Digits[1];
  Tmp1.Digits[2] := A.Digits[2];
  Tmp1.Digits[3] := A.Digits[3];
  Tmp1.Digits[4] := A.Digits[4];
  Tmp1.Digits[5] := A.Digits[5];
  Tmp1.Digits[6] := A.Digits[6];
  Tmp1.Digits[7] := A.Digits[7];
  Tmp1.Digits[8] := A.Digits[8];
  Tmp1.Digits[9] := A.Digits[9];
  Tmp1.Digits[10] := A.Digits[10];
  Tmp1.Digits[11] := A.Digits[11];
  Tmp1.Digits[12] := A.Digits[12];

  { s2 = (0,0,0,0,0, c23, c22, c21,0,0,0,0)}
  Tmp2.Digits[1] := 0;
  Tmp2.Digits[2] := 0;
  Tmp2.Digits[3] := 0;
  Tmp2.Digits[4] := 0;
  Tmp2.Digits[5] := A.Digits[22];
  Tmp2.Digits[6] := A.Digits[23];
  Tmp2.Digits[7] := A.Digits[24];
  Tmp2.Digits[8] := 0;
  Tmp2.Digits[9] := 0;
  Tmp2.Digits[10] := 0;
  Tmp2.Digits[11] := 0;
  Tmp2.Digits[12] := 0;
  LAdd(Tmp1, Tmp2, Tmp1);
  LAdd(Tmp1, Tmp2, Tmp1);

  { s3 = (c23, c22, c21, c20, c19, c18, c17, c16, c15, c14, c13, c12)}
  Tmp2.Digits[1] := A.Digits[13];
  Tmp2.Digits[2] := A.Digits[14];
  Tmp2.Digits[3] := A.Digits[15];
  Tmp2.Digits[4] := A.Digits[16];
  Tmp2.Digits[5] := A.Digits[17];
  Tmp2.Digits[6] := A.Digits[18];
  Tmp2.Digits[7] := A.Digits[19];
  Tmp2.Digits[8] := A.Digits[20];
  Tmp2.Digits[9] := A.Digits[21];
  Tmp2.Digits[10] := A.Digits[22];
  Tmp2.Digits[11] := A.Digits[23];
  Tmp2.Digits[12] := A.Digits[24];
  LAdd(Tmp1, Tmp2, Tmp1);

  { s4 = (c20, c19, c18, c17, c16, c15, c14, c13, c12, c23, c22, c21)}
  Tmp2.Digits[1] := A.Digits[22];
  Tmp2.Digits[2] := A.Digits[23];
  Tmp2.Digits[3] := A.Digits[24];
  Tmp2.Digits[4] := A.Digits[13];
  Tmp2.Digits[5] := A.Digits[14];
  Tmp2.Digits[6] := A.Digits[15];
  Tmp2.Digits[7] := A.Digits[16];
  Tmp2.Digits[8] := A.Digits[17];
  Tmp2.Digits[9] := A.Digits[18];
  Tmp2.Digits[10] := A.Digits[19];
  Tmp2.Digits[11] := A.Digits[20];
  Tmp2.Digits[12] := A.Digits[21];
  LAdd(Tmp1, Tmp2, Tmp1);

  { s5 = (c19, c18, c17, c16, c15, c14, c13, c12, c20,0, c23,0) }
  Tmp2.Digits[1] := 0;
  Tmp2.Digits[2] := A.Digits[24];
  Tmp2.Digits[3] := 0;
  Tmp2.Digits[4] := A.Digits[21];
  Tmp2.Digits[5] := A.Digits[13];
  Tmp2.Digits[6] := A.Digits[14];
  Tmp2.Digits[7] := A.Digits[15];
  Tmp2.Digits[8] := A.Digits[16];
  Tmp2.Digits[9] := A.Digits[17];
  Tmp2.Digits[10] := A.Digits[18];
  Tmp2.Digits[11] := A.Digits[19];
  Tmp2.Digits[12] := A.Digits[20];
  LAdd(Tmp1, Tmp2, Tmp1);

  { s6 = (0,0,0,0, c23, c22, c21, c20,0,0,0,0) }

  //Tmp2.Digits[1] := 0;
  Tmp2.Digits[2] := 0;
  //Tmp2.Digits[3] := 0;
  Tmp2.Digits[4] := 0;
  Tmp2.Digits[5] := A.Digits[21];
  Tmp2.Digits[6] := A.Digits[22];
  Tmp2.Digits[7] := A.Digits[23];
  Tmp2.Digits[8] := A.Digits[24];
  Tmp2.Digits[9] := 0;
  Tmp2.Digits[10] := 0;
  Tmp2.Digits[11] := 0;
  Tmp2.Digits[12] := 0;
  LAdd(Tmp1, Tmp2, Tmp1);

  { s7 = (0,0,0,0,0,0, c23, c22, c21,0,0, c20) }

  Tmp2.Digits[1] := A.Digits[21];
  //Tmp2.Digits[2] := 0;
  //Tmp2.Digits[3] := 0;
  Tmp2.Digits[4] := A.Digits[22];
  Tmp2.Digits[5] := A.Digits[23];
  Tmp2.Digits[6] := A.Digits[24];
  Tmp2.Digits[7] := 0;
  Tmp2.Digits[8] := 0;
  {Tmp2.Digits[9] := 0;
  Tmp2.Digits[10] := 0;
  Tmp2.Digits[11] := 0;
  Tmp2.Digits[12] := 0;}
  LAdd(Tmp1, Tmp2, Tmp1);

  { s8 = (c22, c21, c20, c19, c18, c17, c16, c15, c14, c13, c12, c23) }

  Tmp2.Digits[1] := A.Digits[24];
  Tmp2.Digits[2] := A.Digits[13];
  Tmp2.Digits[3] := A.Digits[14];
  Tmp2.Digits[4] := A.Digits[15];
  Tmp2.Digits[5] := A.Digits[16];
  Tmp2.Digits[6] := A.Digits[17];
  Tmp2.Digits[7] := A.Digits[18];
  Tmp2.Digits[8] := A.Digits[19];
  Tmp2.Digits[9] := A.Digits[20];
  Tmp2.Digits[10] := A.Digits[21];
  Tmp2.Digits[11] := A.Digits[22];
  Tmp2.Digits[12] := A.Digits[23];

  i := 12;
  while (i > 0) and (Tmp2.Digits[i] = 0) do Dec(i);
  Tmp2.Length := i;

  if LGreater(Tmp2, Tmp1) then LAdd(Tmp1, P, Tmp1);
  LSub(Tmp1, Tmp2, Tmp1);

  { s9 = (0,0,0,0,0,0,0, c23, c22, c21, c20,0), }

  Tmp2.Digits[1] := 0;
  Tmp2.Digits[2] := A.Digits[21];
  Tmp2.Digits[3] := A.Digits[22];
  Tmp2.Digits[4] := A.Digits[23];
  Tmp2.Digits[5] := A.Digits[24];
  Tmp2.Digits[6] := 0;
  Tmp2.Digits[7] := 0;
  Tmp2.Digits[8] := 0;
  Tmp2.Digits[9] := 0;
  Tmp2.Digits[10] := 0;
  Tmp2.Digits[11] := 0;
  Tmp2.Digits[12] := 0;

  i := 12;
  while (i > 0) and (Tmp2.Digits[i] = 0) do Dec(i);
  Tmp2.Length := i;

  if LGreater(Tmp2, Tmp1) then LAdd(Tmp1, P, Tmp1);
  LSub(Tmp1, Tmp2, Tmp1);

  { s10 = (0,0,0,0,0,0,0, c23, c23,0,0,0) }

  //Tmp2.Digits[1] := 0;
  Tmp2.Digits[2] := 0;
  Tmp2.Digits[3] := 0;
  Tmp2.Digits[4] := A.Digits[24];
  {Tmp2.Digits[5] := A.Digits[24];
  Tmp2.Digits[6] := 0;
  Tmp2.Digits[7] := 0;
  Tmp2.Digits[8] := 0;
  Tmp2.Digits[9] := 0;
  Tmp2.Digits[10] := 0;
  Tmp2.Digits[11] := 0;
  Tmp2.Digits[12] := 0;}

  i := 12;
  while (i > 0) and (Tmp2.Digits[i] = 0) do Dec(i);
  Tmp2.Length := i;

  if LGreater(Tmp2, Tmp1) then LAdd(Tmp1, P, Tmp1);
  LSub(Tmp1, Tmp2, Tmp1);

  i := Tmp1.Length;
  while (i > 0) and (Tmp1.Digits[i] = 0) do  Dec(i);
  Tmp1.Length := i;

  while LGreater(Tmp1, P) do
    LSub(Tmp1, P, Tmp1);

  LCopy(A, Tmp1);
end;

procedure NISTP521MOD(var A : PLInt; P, Tmp1, Tmp2 : PLInt);
var
  i : integer;
begin
  {
  INPUT: An integer c = (c1041, . . ., c2, c1, c0) in base 2 with 0 . c < p2
  521.
  OUTPUT: c mod p521.
  1. Define 521-bit integers:
  s1 = (c1041, . . ., c523, c522, c521),
  s2 = (c520, . . ., c2, c1, c0).
  2. Return(s1 +s2 mod p521).
  }
  for i := A.Length + 1 to 35 do
    A.Digits[i] := 0;

  Tmp1.Length := 17;
  for i := 1 to 17 do
    Tmp1.Digits[i] := (A.Digits[i + 16] shr 9) or (A.Digits[i + 17] shl 23);

  A.Digits[17] := A.Digits[17] and $1ff;
  for i := 18 to 34 do A.Digits[i] := 0;
  A.Length := 17;
  LAdd(A, Tmp1, A);

  i := A.Length;
  while (i > 0) and (A.Digits[i] = 0) do  Dec(i);
  A.Length := i;

  while LGreater(A, P) do
    LSub(A, P, A);
end;

procedure NISTB163Reduce(var A : PLInt);
var
  T : cardinal;
  i : integer;
begin
  { f(z) = z^163 + z^7 + z^6 + z^3 + 1 }

  for i := 11 downto 7 do
  begin
    T := A.Digits[i];
    A.Digits[i - 6] := A.Digits[i - 6] xor (T shl 29);
    A.Digits[i - 5] := A.Digits[i - 5] xor (T shl 4) xor (T shl 3) xor T xor (T shr 3);
    A.Digits[i - 4] := A.Digits[i - 4] xor (T shr 28) xor (T shr 29);
  end;

  T := A.Digits[6] shr 3;
  A.Digits[1] := A.Digits[1] xor (T shl 7) xor (T shl 6) xor (T shl 3) xor T;
  A.Digits[2] := A.Digits[2] xor (T shr 25) xor (T shr 26);
  A.Digits[6] := A.Digits[6] and 7;

  for i := 7 to A.Length do
    A.Digits[i] := 0;

  A.Length := 6;
end;

procedure NISTB233Reduce(var A : PLInt);
var
  T : cardinal;
  i : integer;
begin
  { f(z) = z^233 + z^74 + 1}

  for i := 16 downto 9 do
  begin
    T := A.Digits[i];
    A.Digits[i - 8] := A.Digits[i - 8] xor (T shl 23);
    A.Digits[i - 7] := A.Digits[i - 7] xor (T shr 9);
    A.Digits[i - 5] := A.Digits[i - 5] xor (T shl 1);
    A.Digits[i - 4] := A.Digits[i - 4] xor (T shr 31);
  end;

  T := A.Digits[8] shr 9;
  A.Digits[1] := A.Digits[1] xor T;
  A.Digits[3] := A.Digits[3] xor (T shl 10);
  A.Digits[4] := A.Digits[4] xor (T shr 22);
  A.Digits[8] := A.Digits[8] and $1FF;

  for i := 9 to A.Length do
    A.Digits[i] := 0;

  A.Length := 8;
end;

procedure NISTB283Reduce(var A : PLInt);
var
  T : cardinal;
  i : integer;
begin
  { f(z) = z^283 + z^12 + z^7 + z^5 + 1 }

  for i := 18 downto 10 do
  begin
    T := A.Digits[i];
    A.Digits[i - 9] := A.Digits[i - 9] xor (T shl 5) xor (T shl 10) xor (T shl 12) xor (T shl 17);
    A.Digits[i - 8] := A.Digits[i - 8] xor (T shr 27) xor (T shr 22) xor (T shr 20) xor (T shr 15);
  end;

  T := A.Digits[9] shr 27;
  A.Digits[1] := A.Digits[1] xor T xor (T shl 5) xor (T shl 7) xor (T shl 12);
  A.Digits[9] := A.Digits[9] and $7FFFFFF;

  for i := 10 to A.Length do
    A.Digits[i] := 0;

  A.Length := 9;
end;

procedure NISTB409Reduce(var A : PLInt);
var
  T : cardinal;
  i : integer;
begin
  { f(z) = z^409 + z^87 + 1 }

  for i := 26 downto 14 do
  begin
    T := A.Digits[i];
    A.Digits[i - 13] := A.Digits[i - 13] xor (T shl 7);
    A.Digits[i - 12] := A.Digits[i - 12] xor (T shr 25);
    A.Digits[i - 11] := A.Digits[i - 11] xor (T shl 30);
    A.Digits[i - 10] := A.Digits[i - 10] xor (T shr 2);
  end;

  T := A.Digits[13] shr 25;
  A.Digits[1] := A.Digits[1] xor T;
  A.Digits[3] := A.Digits[3] xor (T shl 23);
  A.Digits[13] := A.Digits[13] and $1FFFFFF;

  for i := 14 to A.Length do
    A.Digits[i] := 0;

  A.Length := 13;
end;

procedure NISTB571Reduce(var A : PLInt);
var
  T : cardinal;
  i : integer;
begin
  { f(z) = z^571 + z^10 + z^5 + z^2 + 1 }

  for i := 36 downto 19 do
  begin
    T := A.Digits[i];
    A.Digits[i - 18] := A.Digits[i - 18] xor (T shl 5) xor (T shl 7) xor (T shl 10) xor (T shl 15);
    A.Digits[i - 17] := A.Digits[i - 17] xor (T shr 27) xor (T shr 25) xor (T shr 22) xor (T shr 17);
  end;

  T := A.Digits[18] shr 27;
  A.Digits[1] := A.Digits[1] xor T xor (T shl 2) xor (T shl 5) xor (T shl 10);
  A.Digits[18] := A.Digits[18] and $7FFFFFF;

  for i := 19 to A.Length do
    A.Digits[i] := 0;

  A.Length := 18;
end;

{ Field arithmetic }

{ Field Fp }

procedure FpZero(var A : PLInt; P : PLint);
begin
  A.Length := P.Length;
  FillChar(A.Digits[1], A.Length * 4, 0);
end;

procedure FpOne(var A : PLInt; P : PLint);
begin
  A.Length := P.Length;
  FillChar(A.Digits[2], (A.Length - 1) * 4, 0);
  A.Digits[1] := 1;
end;

procedure FpInt(var A : PLInt; P : PLint; C : cardinal);
begin
  A.Length := P.Length;
  FillChar(A.Digits[2], (A.Length - 1) * 4, 0);
  A.Digits[1] := C;
end;

{ returns 1, if A>B, 0 if A=B, and -1 if A<B }
function FpCmp(A, B, P : PLInt) : integer;
var
  i : integer;
begin
  for i := P.Length downto 1 do
    if A.Digits[i] < B.Digits[i] then
    begin
      Result := -1;
      Exit;
    end
    else if A.Digits[i] > B.Digits[i] then
    begin
      Result := 1;
      Exit;
    end;

  Result := 0;
end;

{ Addition. C could be the same as A, B }
procedure FpAdd(A, B, P : PLInt; var C : PLInt);
var
  i : integer;
  e, t : cardinal;
begin
  { addition itself }
  e := 0;
  for i := 1 to P.Length do
  begin
    { should be faster than 64-bit addition }
    t := (A.Digits[i] and $7fffffff) + (B.Digits[i] and $7fffffff) + e;
    e := (A.Digits[i] shr 31) + (B.Digits[i] shr 31) + (t shr 31);
    C.Digits[i] := (t and $7fffffff) or (e shl 31);
    e := e shr 1;
  end;

  { subtracting P, if sum is bigger }
  if (e <> 0) or (FpCmp(C, P, P) >= 0) then
  begin
    e := 0;

    for i := 1 to P.Length do
    begin
      t := P.Digits[i];

      if e <> 0 then
      begin
        if C.Digits[i] > t then e := 0;
        C.Digits[i] := C.Digits[i] - t - 1;
      end
      else
      begin
        if C.Digits[i] < t then e := not e;
        C.Digits[i] := C.Digits[i] - t;
      end;
    end;  
  end;

  C.Length := P.Length;
end;

{ C should not be B }
procedure FpSub(A, B, P : PLInt; var C : PLInt);
var
  i : integer;
  e1, e2, t, t2 : cardinal;
begin
  if FpCmp(A, B, P) < 0 then
  begin
    e1 := 0;
    e2 := 0;

    for i := 1 to P.Length do
    begin
      t := (A.Digits[i] and $7fffffff) + (P.Digits[i] and $7fffffff) + e1;
      e1 := (A.Digits[i] shr 31) + (P.Digits[i] shr 31) + (t shr 31);
      t := (t and $7fffffff) or (e1 shl 31);
      e1 := e1 shr 1;

      t2 := B.Digits[i];

      if e2 <> 0 then
      begin
        if t > t2 then e2 := 0;
        C.Digits[i] := t - t2 - 1;
      end
      else
      begin
        if t < t2 then e2 := not e2;
        C.Digits[i] := t - t2;
      end;
    end;
  end
  else
  begin
    e1 := 0;

    for i := 1 to P.Length do
    begin
      t := B.Digits[i];

      if e1 <> 0 then
      begin
        if A.Digits[i] > t then e1 := 0;
        C.Digits[i] := A.Digits[i] - t - 1;
      end
      else
      begin
        if A.Digits[i] < t then e1 := not e1;
        C.Digits[i] := A.Digits[i] - t;
      end;
    end;
  end;

  C.Length := P.Length;
end;

function FpIsOne(A, P : PLInt) : boolean;
var
  i : integer;
begin
  Result := false;

  if A.Digits[1] <> 1 then Exit;
  
  for i := 2 to P.Length do
    if A.Digits[i] <> 0 then Exit;

  Result := true;
end;

function FpIsZero(A, P : PLInt) : boolean;
var
  i : integer;
begin
  Result := false;

  for i := 1 to P.Length do
    if A.Digits[i] <> 0 then Exit;

  Result := true;
end;

{ T1, T2 - temporary variables }
procedure FpReduce(var A : PLInt; P, T1, T2 : PLInt; Field : integer);
var
  i : integer;
begin
  case Field of
    SB_EC_FLD_NIST_P192S : NISTP192MOD(A, P, T1, T2);
    SB_EC_FLD_NIST_P224S : NISTP224MOD(A, P, T1, T2);
    SB_EC_FLD_NIST_P256S : NISTP256MOD(A, P, T1, T2);
    SB_EC_FLD_NIST_P384 : NISTP384MOD(A, P, T1, T2);
    SB_EC_FLD_NIST_P521 : NISTP521MOD(A, P, T1, T2);
  else
    begin
      LModEx(A, P, T1);
      LCopy(A, T1);
    end;
  end;

  for i := A.Length + 1 to P.Length do
    A.Digits[i] := 0;
  A.Length := P.Length;
end;

{ T1, T2 - temporary variables }
procedure FpMul(A, B, P, T1, T2 : PLInt; var C : PLInt; Field : integer);
begin
  LMult(A, B, C);
  FpReduce(C, P, T1, T2, Field);
end;

{ T1, T2 - temporary variables }
procedure FpSqr(A, P, T1, T2 : PLInt; var C : PLInt; Field : integer);
begin
  { here should be written faster implementation }
  FpMul(A, A, P, T1, T2, C, Field);
end;

{ division by 2. C could be the same as A }
procedure FpDiv2(A, P : PLInt; var C : PLInt);
var
  i : integer;
  e, t : cardinal;
begin
  if (A.Digits[1] and 1) <> 0 then
  begin
    { adding P to A }
    e := 0;
    for i := 1 to P.Length do
    begin
      { must be faster than 64-bit operation }
      t := (A.Digits[i] and $7fffffff) + (P.Digits[i] and $7fffffff) + e;
      e := (A.Digits[i] shr 31) + (P.Digits[i] shr 31) + (t shr 31);
      C.Digits[i] := (t and $7fffffff) or (e shl 31);
      e := e shr 1;
    end;

    C.Digits[P.Length + 1] := e;

    for i := 1 to P.Length do
      C.Digits[i] := (C.Digits[i] shr 1) or (C.Digits[i + 1] shl 31);
  end
  else
  begin
    for i := 1 to P.Length - 1 do
      C.Digits[i] := (A.Digits[i] shr 1) or (A.Digits[i + 1] shl 31);
    C.Digits[P.Length] := A.Digits[P.Length] shr 1;
  end;

  C.Length := P.Length;
end;

procedure FpInv(A, P : PLInt; var C : PLInt; Field : integer);
var
  U, V, G1, G2 : PLInt;
begin
  LCreate(U);
  LCreate(V);
  LCreate(G1);
  LCreate(G2);

  LCopy(U, A);
  LCopy(V, P);

  FpOne(G1, P);
  FpZero(G2, P);

  while not (FpIsOne(U, P) or FpIsOne(V, P)) do
  begin
    while (U.Digits[1] and 1) = 0 do
    begin
      FpDiv2(U, P, U);
      FpDiv2(G1, P, G1);
    end;

    while (V.Digits[1] and 1) = 0 do
    begin
      FpDiv2(V, P, V);
      FpDiv2(G2, P, G2);
    end;

    if  FpCmp(U, V, P) >= 0 then
    begin
      FpSub(U, V, P, U);
      FpSub(G1, G2, P, G1);
    end
    else
    begin
      FpSub(V, U, P, V);
      FpSub(G2, G1, P, G2);
    end;
  end;

  if FpIsOne(U, P) then
    LCopy(C, G1)
  else
    LCopy(C, G2);

  C.Length := P.Length;

  LDestroy(U);
  LDestroy(V);
  LDestroy(G1);
  LDestroy(G2);
end;

procedure FpDiv(A, B, P : PLInt; var C : PLInt; Field : integer);
var
  U, V, G1, G2 : PLInt;
begin
  LCreate(U);
  LCreate(V);
  LCreate(G1);
  LCreate(G2);

  LCopy(U, B);
  LCopy(V, P);

  LCopy(G1, A);
  FpZero(G2, P);

  while not (FpIsOne(U, P) or FpIsOne(V, P)) do
  begin
    while (U.Digits[1] and 1) = 0 do
    begin
      FpDiv2(U, P, U);
      FpDiv2(G1, P, G1);
    end;

    while (V.Digits[1] and 1) = 0 do
    begin
      FpDiv2(V, P, V);
      FpDiv2(G2, P, G2);
    end;

    if  FpCmp(U, V, P) >= 0 then
    begin
      FpSub(U, V, P, U);
      FpSub(G1, G2, P, G1);
    end
    else
    begin
      FpSub(V, U, P, V);
      FpSub(G2, G1, P, G2);
    end;
  end;

  if FpIsOne(U, P) then
    LCopy(C, G1)
  else
    LCopy(C, G2);

  C.Length := P.Length;

  LDestroy(U);
  LDestroy(V);
  LDestroy(G1);
  LDestroy(G2);
end;

{ exponentiation. C should be different from A }
procedure FpExp(A, E, P : PLInt; var C : PLint);
var
  i : integer;
begin
  LMModPower(A, E, P, C);
  for i := C.Length + 1 to P.Length do
    C.Digits[i] := 0;
  C.Length := P.Length;
end;

procedure FpSlowLucasSequence(K, SP, SQ, P : PLInt; var U, V : PLInt; Field : integer);
var
  i : integer;
  U0, U1, U2, V0, V1, V2, T, T1, T2 : PLInt;
begin
  LCreate(U0);
  LCreate(U1);
  LCreate(U2);
  LCreate(V0);
  LCreate(V1);
  LCreate(V2);
  LCreate(T);
  LCreate(T1);
  LCreate(T2);

  FpZero(U0, P);
  FpOne(U1, P);
  FpOne(V0, P);
  FpAdd(V0, V0, P, V0);
  LCopy(V1, SP);

  try
    // we assuming that K.Length = 1
    for i := 2 to K.Digits[1] do
    begin
      FpMul(SP, U1, P, T1, T2, U2, Field);
      FpMul(SQ, U0, P, T1, T2, T, Field);
      FpSub(U2, T, P, U2);

      FpMul(SP, V1, P, T1, T2, V2, Field);
      FpMul(SQ, V0, P, T1, T2, T, Field);
      FpSub(V2, T, P, V2);

      LCopy(U0, U1);
      LCopy(U1, U2);
      LCopy(V0, V1);
      LCopy(V1, V2);
    end;

    LCopy(U, U1);
    LCopy(V, V1);
  finally
    LDestroy(U0);
    LDestroy(U1);
    LDestroy(U2);
    LDestroy(V0);
    LDestroy(V1);
    LDestroy(V2);
    LDestroy(T);
    LDestroy(T1);
    LDestroy(T2);
  end;
end;

function FpLucasSequence(K, SP, SQ, P : PLInt; var U, V : PLInt; Field : integer) : boolean;
var
  i{, j} : integer;
  D, T, T1, T2, T3 : PLInt;
begin
  Result := false;
  LCreate(D);
  LCreate(T);
  LCreate(T1);
  LCreate(T2);
  LCreate(T3);
  
  try
    FpOne(U, P);
    LCopy(V, SP);  // U = 1; V = SP

    FpSqr(SP, P, T1, T2, D, Field);
    FpAdd(SQ, SQ, P, T1);
    FpAdd(T1, T1, P, T1);
    FpSub(D, T1, P, D); // D = LP^2 - 4*LQ

    if FpIsZero(D, P) then
      Exit;

    for i := LBitCount(K) - 2 downto 0 do
    begin
      // (U,V) = (UV mod P, (V^2 + D*U^2) div 2 mod P)
      FpSqr(U, P, T1, T2, T, Field);
      FpMul(T, D, P, T1, T2, T3, Field);
      FpSqr(V, P, T1, T2, T, Field);
      FpAdd(T, T3, P, T1);
      FpDiv2(T1, P, T); // T = (V^2 + D*U^2) div 2 mod P

      FpMul(U, V, P, T1, T2, T3, Field);
      LCopy(U, T3);
      LCopy(V, T);

      if LBitSet(K, i) then
      begin
        // (U, V) = ((SP*U + V) div 2 mod P, (SP*V + D*U) div 2 mod P)
        FpMul(D, U, P, T1, T2, T, Field);
        FpMul(SP, V, P, T1, T2, T3, Field);
        FpAdd(T3, T, P, T1);
        FpDiv2(T1, P, T3); // T3 = (SP*V + D*U) div 2

        FpMul(SP, U, P, T1, T2, T, Field);
        FpAdd(T, V, P, T1);
        FpDiv2(T1, P, T); // T = (SP*U + V) div 2

        LCopy(U, T);
        LCopy(V, T3);
      end;
    end;
    Result := true;
  finally
    LDestroy(D);
    LDestroy(T);
    LDestroy(T1);
    LDestroy(T2);
    LDestroy(T3);
  end;
end;

{ calculates square root if exists, and returns true. Otherwise - false }
function FpSqrt(A, P : PLInt; var C : PLInt; Field : integer) : boolean;
var
  U, V, T1, T2, T3, T, LI, A2, LP, LQ, D, K : PLint;
  //i : integer;
begin
  Result := false;

  if (P.Digits[1] and 3) = 3 then
  begin
    LCreate(U);
    LCreate(T1);
    LCreate(T2);
    LCreate(T3);
    LCreate(T);

    try
      LCopy(T, P);
      LShrEx(T, 2);
      LInc(T); // T = P div 4 + 1, integer arithmetic 
      FpExp(A, T, P, U); // U = A^T = Sqrt(A)
      FpSqr(U, P, T1, T2, T3, Field);
      Result := FpCmp(A, T3, P) = 0;

      if Result then
        LCopy(C, U);
    finally
      LDestroy(T);
      LDestroy(T3);
      LDestroy(T2);
      LDestroy(T1);
      LDestroy(U);
    end;
  end
  else if (P.Digits[1] and 7) = 5 then
  begin
    LCreate(U);
    LCreate(T1);
    LCreate(T2);
    LCreate(T3);
    LCreate(T);
    LCreate(A2);
    LCreate(LI);

    try
      LCopy(T, P);
      LShrEx(T, 3); // T = P div 8, integer arithmetic

      FpAdd(A, A, P, A2);
      FpExp(A2, T, P, T3);
      FpSqr(T3, P, T1, T2, T, Field);
      FpMul(A2, T, P, T1, T2, LI, Field);
      FpOne(T1, P);
      FpSub(LI, T1, P, LI);
      FpMul(LI, T3, P, T1, T2, T, Field);
      FpMul(T, A, P, T1, T2, T3, Field);
      FpSqr(T3, P, T1, T2, T, Field);

      Result := FpCmp(T, A, P) = 0;

      if Result then
        LCopy(C, T3);
    finally
      LDestroy(LI);
      LDestroy(A2);
      LDestroy(T);
      LDestroy(T3);
      LDestroy(T2);
      LDestroy(T1);
      LDestroy(U);
    end;
  end
  else if (P.Digits[1] and 3) = 1 then // P = 4*U + 1
  begin
    LCreate(LP);
    LCreate(LQ);
    LCreate(T);
    LCreate(T1);
    LCreate(T2);
    LCreate(T3);
    LCreate(U);
    LCreate(V);
    LCreate(D);
    LCreate(K);

    try
      repeat
        LGenerate(LP, P.Length);
        FpReduce(LP, P, T1, T2, Field);
        LCopy(LQ, A);
        LCopy(K, P);
        LShr(K);
        LInc(K); // K = 2*U + 1, integer arithmetic

        if not FpLucasSequence(K, LP, LQ, P, U, V, Field) then
          Continue;

        FpSqr(V, P, T1, T2, T, Field);
        FpAdd(LQ, LQ, P, T3);
        FpAdd(T3, T3, P, T3);

        if FpCmp(T, T3, P) = 0 then
        begin
          Result := true;
          FpDiv2(V, P, C);
          Exit;
        end
        else
        begin
          // if U = +/-1 mod P, then another iteration, otherwise no square root
          if FpIsOne(U, P) then Continue
          else
          begin
            FpOne(T1, P);
            FpAdd(U, T1, P, T3);
            if not FpIsZero(T3, P) then
            begin
              Result := false;
              Exit
            end
            else
              Continue;
          end;
        end;

      until false;

    finally
      LDestroy(K);
      LDestroy(D);
      LDestroy(V);
      LDestroy(U);
      LDestroy(T3);
      LDestroy(T2);
      LDestroy(T1);
      LDestroy(T);
      LDestroy(LQ);
      LDestroy(LP);
    end;
  end;
end;


{ Field F2^m, polynomial basis. }

procedure F2mPZero(var A : PLInt; P : PLint);
begin
  A.Length := P.Length;
  FillChar(A.Digits[1], A.Length  shl 2, 0);
end;

procedure F2mPOne(var A : PLInt; P : PLint);
begin
  A.Length := P.Length;
  A.Digits[1] := 1;
  FillChar(A.Digits[2], (A.Length - 1) shl 2, 0);
end;

function F2mPIsZero(A, P : PLInt) : boolean;
var
  i : integer;
begin
  Result := false;

  for i := 1 to P.Length do
    if A.Digits[i] <> 0 then Exit;

  Result := true;
end;

function F2mPIsOne(A, P : PLInt) : boolean;
var
  i : integer;
begin
  Result := false;

  if A.Digits[1] <> 1 then Exit;
  for i := 2 to P.Length do
    if A.Digits[i] <> 0 then Exit;

  Result := true;
end;

{ Compares A and B; returns -1 if A < B; 0 if A = B and 1 if A > B }
function F2mPCmp(A, B, P : PLInt) : integer;
var
  i : integer;
begin
  for i := P.Length downto 1 do
    if A.Digits[i] < B.Digits[i] then
    begin
      Result := -1;
      Exit;
    end
    else if A.Digits[i] > B.Digits[i] then
    begin
      Result := 1;
      Exit;
    end;

  Result := 0;
end;

{ C could be equal to A or B }
procedure F2mPAdd(A, B, P : PLInt; var C : PLInt);
var
  i : integer;
begin
  C.Length := P.Length;
  { we assuming, that A & B are from field F2m, thus, are reduced modulo P }
  for i := 1 to C.Length do
    C.Digits[i] := A.Digits[i] xor B.Digits[i];
end;

procedure F2mPReduceCustom(var A : PLInt; P : PLInt);
var
  i, j, k, l : integer;
  T1 : PLInt;
begin
  LCreate(T1);
  
  l := LBitCount(P);
  k := integer(LBitCount(A)) - l;

  if k < 0 then
  begin
    A.Length := P.Length;
    Exit;
  end;

  LShlNum(P, T1, k);

  for i := k downto 1 do
  begin
    if LBitSet(A, i + l - 1) then
      for j := 1 to T1.Length do
        A.Digits[j] := A.Digits[j] xor T1.Digits[j];

    LShrEx(T1, 1);
  end;

  if LBitSet(A, l - 1) then
      for j := 1 to T1.Length do
        A.Digits[j] := A.Digits[j] xor T1.Digits[j];

  A.Length := P.Length;

  LDestroy(T1);
end;

procedure F2mPReduce(var A : PLInt; P : PLInt; Field : integer);
begin
  case Field of
    SB_EC_FLD_NIST_B163 : NISTB163Reduce(A);
    SB_EC_FLD_NIST_B233 : NISTB233Reduce(A);
    SB_EC_FLD_NIST_B283 : NISTB283Reduce(A);
    SB_EC_FLD_NIST_B409 : NISTB409Reduce(A);
    SB_EC_FLD_NIST_B571 : NISTB571Reduce(A);
  else
    F2mPReduceCustom(A, P);
  end;
end;

{ T1 - temporary variable }
procedure F2mPMul(A, B, P : PLInt; var T1, C : PLInt; Field : integer);
var
  i, j, k : integer;
  d : cardinal;
begin
  F2mPZero(C, P);

  { we assuming, that A & B are from field F2m, thus, are reduced modulo P }
  C.Length := A.Length shl 1 + 1;

  for i := 1 to A.Length shl 1 + 1 do
    C.Digits[i] := 0;

  LCopy(T1, A);

  { calculating direct product }
  d := 1;

  for i := 0 to 31 do
  begin
    for j := 1 to B.Length do
      if (B.Digits[j] and d) <> 0 then
        for k := 1 to T1.Length do
          C.Digits[k + j - 1] := C.Digits[k + j - 1] xor T1.Digits[k];

    LShl(T1);
    d := d shl 1;
  end;

  { performing reduction }
  F2mPReduce(C, P, Field);
end;

{ C should differ from A }
procedure F2mPSqr(A, P : PLInt; var C : PLInt; Field : integer);
var
  i : integer;
begin
  C.Length := A.Length shl 1;

  for i := 0 to A.Length - 1 do
  begin
    C.Digits[i shl 1 + 1] := F2M_SQR_TABLE[A.Digits[i + 1] and $ff] or (F2M_SQR_TABLE[(A.Digits[i + 1] shr 8) and $ff] shl 16);
    C.Digits[i shl 1 + 2] := F2M_SQR_TABLE[(A.Digits[i + 1] shr 16) and $ff] or (F2M_SQR_TABLE[(A.Digits[i + 1] shr 24) and $ff] shl 16);
  end;

  F2mPReduce(C, P, Field);
end;

{ division of polynomial A by X, with respect to reduction polynomial P }
procedure F2mPDivX(A, P : PLint; var C : PLInt);
var
  i : integer;
begin
  if (A.Digits[1] and 1) = 0 then
  begin
    for i := 1 to P.Length - 1 do
      C.Digits[i] := (A.Digits[i] shr 1) or (A.Digits[i + 1] shl 31);
    C.Digits[P.Length] := A.Digits[P.Length] shr 1;  
  end
  else
  begin
    for i := 1 to P.Length - 1 do
      C.Digits[i] := ((A.Digits[i] xor P.Digits[i]) shr 1) or ((A.Digits[i + 1] xor P.Digits[i + 1]) shl 31);
    C.Digits[P.Length] := (A.Digits[P.Length] xor P.Digits[P.Length]) shr 1;  
  end;
end;

procedure F2mPDiv(A, B, P : PLInt; var C : PLInt);
var
  U, V, G1, G2 : PLInt;
begin
  LCreate(U);
  LCreate(V);
  LCreate(G1);
  LCreate(G2);

  LCopy(U, B);
  LCopy(V, P);

  LCopy(G1, A);
  G1.Length := P.Length;
  F2mPZero(G2, P);

  while not (F2mPIsOne(U, P) or F2mPIsOne(V, P)) do
  begin
    while (U.Digits[1] and 1) = 0 do
    begin
      F2mPDivX(U, P, U);
      F2mPDivX(G1, P, G1);
    end;

    while (V.Digits[1] and 1) = 0 do
    begin
      F2mPDivX(V, P, V);
      F2mPDivX(G2, P, G2);
    end;

    if F2mPCmp(U, V, P) = 1 then
    begin
      F2mPAdd(U, V, P, U);
      F2mPAdd(G1, G2, P, G1);
    end
    else
    begin
      F2mPAdd(V, U, P, V);
      F2mPAdd(G2, G1, P, G2);
    end;
  end;

  if F2mPIsOne(U, P) then
    LCopy(C, G1)
  else
    LCopy(C, G2);

  LDestroy(U);
  LDestroy(V);
  LDestroy(G1);
  LDestroy(G2);
end;

procedure F2mPInv(A, P : PLInt; var C : PLInt);
var
  U, V, G1, G2 : PLInt;
begin
  LCreate(U);
  LCreate(V);
  LCreate(G1);
  LCreate(G2);

  LCopy(U, A);
  LCopy(V, P);

  F2mPOne(G1, P);
  F2mPZero(G2, P);

  while not (F2mPIsOne(U, P) or F2mPIsOne(V, P)) do
  begin
    while (U.Digits[1] and 1) = 0 do
    begin
      F2mPDivX(U, P, U);
      F2mPDivX(G1, P, G1);
    end;

    while (V.Digits[1] and 1) = 0 do
    begin
      F2mPDivX(V, P, V);
      F2mPDivX(G2, P, G2);
    end;

    if F2mPCmp(U, V, P) = 1 then
    begin
      F2mPAdd(U, V, P, U);
      F2mPAdd(G1, G2, P, G1);
    end
    else
    begin
      F2mPAdd(V, U, P, V);
      F2mPAdd(G2, G1, P, G2);
    end;
  end;

  if F2mPIsOne(U, P) then
    LCopy(C, G1)
  else
    LCopy(C, G2);

  LDestroy(U);
  LDestroy(V);
  LDestroy(G1);
  LDestroy(G2);
end;

{ calculates half-trace of field element A; C should differ from A }
procedure F2mPHalfTrace(A, P : PLInt; var C : PLInt; Field : integer);
var
  i, m : integer;
  T{, T1} : PLInt;
begin
  m := LBitCount(P);
  LCreate(T);
  LCopy(C, A);

  for i := 1 to (m - 1) shr 1 do
  begin
    F2mPSqr(C, P, T, Field);
    F2mPSqr(T, P, C, Field);
    F2mPAdd(C, A, P, C);
  end;

  LDestroy(T);
end;

{ exponentiation. Exponent E is not from F2mP, it is just integer. C should differ from A }
procedure F2mPExp(A, E, P : PLInt; var C : PLint; Field : integer);
var
  i : integer;
  T, T1 : PLInt;
begin
  LCreate(T);
  LCreate(T1);

  try
    LCopy(C, A);
    
    for i := LBitCount(E) - 2 downto 0 do
    begin
      F2mPSqr(C, P, T, Field);
      if LBitSet(E, i) then
        F2mPMul(T, A, P, T1, C, Field)
      else
        LCopy(C, T);
    end;
  finally
    LDestroy(T1);
    LDestroy(T);
  end;
end;

{ solves quadratic equation C^2 = A}
function F2mPSolveQE(A, P : PLint; var C : PLInt; Field : integer) : boolean;
var
  i, m : Integer;
  Z, W, T, T1, T2, T3 : PLInt;
begin
  Result := false;
  m := LBitCount(P) - 1;

  if (m and 1) = 1 then
  begin
    LCreate(Z);
    LCreate(T);

    try
      F2mPHalfTrace(A, P, Z, Field);
      F2mPSqr(Z, P, T, Field);
      F2mPAdd(T, Z, P, T);

      if F2mPCmp(A, T, P) = 0 then
      begin
        LCopy(C, Z);
        Result := true;
      end;
    finally
      LDestroy(T);
      LDestroy(Z);
    end;
  end
  else
  begin
    { possibly this code will not be executed ever, cause m is always odd, but we should be ready }
    LCreate(T);
    LCreate(T1);
    LCreate(T2);
    LCreate(T3);
    LCreate(Z);
    LCreate(W);
    try
      repeat
        LGenerate(T, P.Length);
        F2mPReduce(T, P, Field);
        F2mPZero(Z, P);
        LCopy(W, A);

        for i := 1 to m - 1 do
        begin
          F2mPSqr(W, P, T2, Field);
          F2mPMul(T, T2, P, T1, T3, Field);
          F2mPSqr(Z, P, T1, Field);
          F2mPAdd(T3, T1, P, Z); // Z = Z^2 + W^2 * T
          F2mPAdd(T2, A, P, W); // W = W^2 + A
        end;

        if not F2mPIsZero(W, P) then
          Exit;//no solution

        F2mPSqr(Z, P, T1, Field);
        F2mPAdd(T1, Z, P, T1);

        if not F2mPIsZero(T1, P) then
        begin
          LCopy(C, Z);
          Result := true;
          Break;
        end;
      until false;
    finally
      LDestroy(W);
      LDestroy(Z);
      LDestroy(T3);
      LDestroy(T2);
      LDestroy(T1);
      LDestroy(T);
    end;
  end;
end;


{ Elliptic curve points operations }
{ X.Length = 0 means point on identity }
{ Curve y^2 = x^3 - a*x + b, over the field Fp}

{ Point doubling, Jacobian coordinates, A = - 3 }
procedure ECPFpJDouble(X1, Y1, Z1, P : PLInt; var X3, Y3, Z3 : PLInt; Field : integer);
var
  T, T1, T2, T3, Tmp1, Tmp2 : PLInt;
begin
  if X1.Length = 0 then
  begin
    X3.Length := 0;
    Exit;
  end;

  LCreate(T);
  LCreate(T1);
  LCreate(T2);
  LCreate(T3);
  LCreate(Tmp1);
  LCreate(Tmp2);

  FpSqr(Z1, P, Tmp1, Tmp2, T, Field); { T = Z1^2 }
  FpSub(X1, T, P, T2); { T2 = X1 - Z1^2 }
  FpAdd(X1, T, P, T1); { T1 = X1 + Z1^2 }
  FpMul(T1, T2, P, Tmp1, Tmp2, T, Field); { T = (X1 - Z1^2) * (X1 + Z1^2) }
  FpAdd(T, T, P, Tmp1);
  FpAdd(Tmp1, T, P, T2); { T2 = 3 * (X1 - Z1^2) * (X1 + Z1^2) }
  FpAdd(Y1, Y1, P, T); { T = 2 * Y1 }
  FpMul(T, Z1, P, Tmp1, Tmp2, Z3, Field); { Z3 = 2 * Y1 * Z1 }
  FpSqr(T, P, Tmp1, Tmp2, Y3, Field); { Y3 = 4 * Y1^2 }
  FpMul(Y3, X1, P, Tmp1, Tmp2, T3, Field); { T3 = 4 * X1 * Y1^2 }
  FpSqr(Y3, P, Tmp1, Tmp2, T, Field);
  FpDiv2(T, P, Y3); { Y3 = 4 * Y1^4 }
  FpSqr(T2, P, Tmp1, Tmp2, T, Field); { T = 9 * (X1 - Z1^2)^2 * (X1 + Z1^2)^2 }
  FpAdd(T3, T3, P, T1); { T1 = 8 * X1 * Y1^2 }
  FpSub(T, T1, P, X3); { X3 = 9 * (X1 - Z1^2)^2 * (X1 + Z1^2)^2 - 8 * X1 * Y1^2 }
  FpSub(T3, X3, P, T);
  FpMul(T, T2, P, Tmp1, Tmp2, T1, Field); { T1 = (T3 - X3) * T2 }
  FpSub(T1, Y3, P, T);
  LCopy(Y3, T); { Y3 = T1 - Y3 }

  LDestroy(T);
  LDestroy(T1);
  LDestroy(T2);
  LDestroy(T3);
  LDestroy(Tmp1);
  LDestroy(Tmp2);
end;

{ Point doubling, Jacobian coordinates, A <> - 3 }
procedure ECPFpJDouble(X1, Y1, Z1, P, A : PLInt; var X3, Y3, Z3 : PLInt; Field : integer);
var
  T, T1, T2, T3, Tmp1, Tmp2 : PLInt;
begin
  if X1.Length = 0 then
  begin
    X3.Length := 0;
    Exit;
  end;

  LCreate(T);
  LCreate(T1);
  LCreate(T2);
  LCreate(T3);
  LCreate(Tmp1);
  LCreate(Tmp2);

  if not FpIsZero(A, P) then
  begin
    FpSqr(Z1, P, Tmp1, Tmp2, T, Field); { T = Z1^2 }
    FpSqr(T, P, Tmp1, Tmp2, T2, Field); { T2 = Z1^4 }
    FpMul(A, T2, P, Tmp1, Tmp2, T, Field); { T = A * Z1^4}
  end
  else
    FpZero(T, P);

  FpSqr(X1, P, Tmp1, Tmp2, T1, Field); { T1 = X1 ^ 2 }
  FpAdd(T1, T1, P, T2);
  FpAdd(T2, T1, P, T1); { T1 = 3 * X1 ^ 2 } 
  FpAdd(T, T1, P, T2); { T2 = 3 * X1^2 + A * Z^4} // here is the difference with A = -3
  FpAdd(Y1, Y1, P, T); { T = 2 * Y1 }
  FpMul(T, Z1, P, Tmp1, Tmp2, Z3, Field); { Z3 = 2 * Y1 * Z1 }
  FpSqr(T, P, Tmp1, Tmp2, Y3, Field); { Y3 = 4 * Y1^2 }
  FpMul(Y3, X1, P, Tmp1, Tmp2, T3, Field); { T3 = 4 * X1 * Y1^2 }
  FpSqr(Y3, P, Tmp1, Tmp2, T, Field);
  FpDiv2(T, P, Y3); { Y3 = 4 * Y1^4 }
  FpSqr(T2, P, Tmp1, Tmp2, T, Field); { T = 9 * (X1 - Z1^2)^2 * (X1 + Z1^2)^2 }
  FpAdd(T3, T3, P, T1); { T1 = 8 * X1 * Y1^2 }
  FpSub(T, T1, P, X3); { X3 = 9 * (X1 - Z1^2)^2 * (X1 + Z1^2)^2 - 8 * X1 * Y1^2 }
  FpSub(T3, X3, P, T);
  FpMul(T, T2, P, Tmp1, Tmp2, T1, Field); { T1 = (T3 - X3) * T2 }
  FpSub(T1, Y3, P, T);
  LCopy(Y3, T); { Y3 = T1 - Y3 }

  LDestroy(T);
  LDestroy(T1);
  LDestroy(T2);
  LDestroy(T3);
  LDestroy(Tmp1);
  LDestroy(Tmp2);
end;


{ Point addition; mixed affine-Jacobian coordinates }
procedure ECPFpJAAdd(X1, Y1, Z1, x2, y2, P : PLInt; var X3, Y3, Z3 : PLInt; Field : integer);
var
  T, T1, T2, T3, T4, Tmp1, Tmp2 : PLInt;
begin
  if x2.Length = 0 then
  begin
    LCopy(X3, X1);
    LCopy(Y3, Y1);
    LCopy(Z3, Z1);
    Exit;
  end;

  if X1.Length = 0 then
  begin
    LCopy(X3, x2);
    LCopy(Y3, y2);
    FpOne(Z3, P);
    Exit;
  end;

  LCreate(T);
  LCreate(T1);
  LCreate(T2);
  LCreate(T3);
  LCreate(T4);
  LCreate(Tmp1);
  LCreate(Tmp2);

  FpSqr(Z1, P, Tmp1, Tmp2, T1, Field); { T1 = Z1^2 }
  FpMul(T1, Z1, P, Tmp1, Tmp2, T2, Field); { T2 = Z1^3 }
  FpMul(T1, x2, P, Tmp1, Tmp2, T, Field);
  FpSub(T, X1, P, T1); { T1 = Z1^2 * x2 - X1 }
  FpMul(T2, y2, P, Tmp1, Tmp2, T, Field);
  FpSub(T, Y1, P, T2); { T2 = Z1^3 * y2 - Y1 }

  if FpIsZero(T1, P) then
    if FpIsZero(T2, P) then
    begin
      FpOne(T, P);
      ECPFpJDouble(x2, y2, T, P, X3, Y3, Z3, Field);
    end
    else
      X3.Length := 0
  else
  begin    
    FpMul(Z1, T1, P, Tmp1, Tmp2, Z3, Field); { Z3 = Z1^3 * x2 - X1 * Z1 }
    FpSqr(T1, P, Tmp1, Tmp2, T3, Field); { T3 = (Z1^2 * x2 - X1)^2 }
    FpMul(T3, T1, P, Tmp1, Tmp2, T4, Field); { T4 = (Z1^2 * x2 - X1)^3 }
    FpMul(T3, X1, P, Tmp1, Tmp2, T, Field);
    LCopy(T3, T); { T3 = X1 * (Z1^2 * x2 - X1)^2 }
    FpAdd(T3, T3, P, T1); { T1 = 2 * X1 * (Z1^2 * x2 - X1)^2 }
    FpSqr(T2, P, Tmp1, Tmp2, X3, Field); { X3 = (Z1^3 * y2 - Y1)^2 }
    FpSub(X3, T1, P, T);
    FpSub(T, T4, P, X3); { X3 = (Z1^3 * y2 - Y1)^2 - 2 * X1 * (Z1^2 * x2 - X1)^2 - (Z1^2 * x2 - X1)^3 }
    FpSub(T3, X3, P, T);
    FpMul(T, T2, P, Tmp1, Tmp2, T3, Field); { T3 = (X1 * (Z1^2 * x2 - X1)^2 - X3) * (Z1^3 * y2 - Y1) }
    FpMul(T4, Y1, P, Tmp1, Tmp2, T, Field);
    FpSub(T3, T, P, Y3); { Y3 = (X1 * (Z1^2 * x2 - X1)^2 - X3) * (Z1^3 * y2 - Y1) - Y1 * (Z1^2 * x2 - X1)^3}
  end;

  LDestroy(T);
  LDestroy(T1);
  LDestroy(T2);
  LDestroy(T3);
  LDestroy(T4);
  LDestroy(Tmp1);
  LDestroy(Tmp2);
end;

{ Point doubling; affine coordinates; }
procedure ECPFpDouble(x1, y1, P, A : PLInt; var x3, y3 : PLInt; Field : integer);
var
  T, T1, T2, T3, Tmp1, Tmp2, Tmp3 : PLInt;
begin
  if (x1.Length = 0) or FpIsZero(y1, P) then
  begin
    x3.Length := 0;
    Exit;
  end;

  LCreate(T);
  LCreate(T1);
  LCreate(T2);
  LCreate(T3);
  LCreate(Tmp1);
  LCreate(Tmp2);
  LCreate(Tmp3);

  FpSqr(x1, P, Tmp1, Tmp2, T, Field); { T = x1^2 }
  FpAdd(T, T, P, T1);
  FpAdd(T1, T, P, T2); { T2 = 3 * x1^2 }
  FpAdd(T2, A, P, T1); { T1 = 3 * x1^2 + A }
  FpAdd(y1, y1, P, T); { T = 2 * y1 }
  FpDiv(T1, T, P, T2, Field); { T2 = (3 * x1^2 + A)/(2 * y1) }
  FpSqr(T2, P, Tmp1, Tmp2, T, Field);
  FpAdd(x1, x1, P, T1);
  FpSub(T, T1, P, x3); { x3 = ((3 * x1^2 + A)/(2 * y1))^2 - 2 * x1 }
  FpSub(x1, x3, P, T);
  FpMul(T2, T, P, Tmp1, Tmp2, T1, Field); {T1 = ((3 * x1^2 + A)/(2 * y1)) * (x1 - x3) }
  FpSub(T1, y1, P, y3); { y3 = ((3 * x1^2 + A)/(2 * y1)) * (x1 - x3) - y1 }

  LDestroy(T);
  LDestroy(T1);
  LDestroy(T2);
  LDestroy(T3);
  LDestroy(Tmp1);
  LDestroy(Tmp2);
  LDestroy(Tmp3);
end;

{ Point addition; affine coordinates }
procedure ECPFpAdd(x1, y1, x2, y2, P, A : PLInt; var x3, y3 : PLInt; Field : integer);
var
  T, T1, T2, T3, Tmp1, Tmp2, Tmp3 : PLInt;
begin
  if x1.Length = 0 then
  begin
    LCopy(x3, x2);
    LCopy(y3, y2);
    Exit;
  end;

  if x2.Length = 0 then
  begin
    LCopy(x3, x1);
    LCopy(y3, y1);
    Exit;
  end;

  LCreate(T);
  LCreate(T1);
  LCreate(T2);
  LCreate(T3);
  LCreate(Tmp1);
  LCreate(Tmp2);
  LCreate(Tmp3);

  FpSub(X2, X1, P, T1); { T1 = X2 - X1 }
  FpSub(Y2, Y1, P, T2); { T2 = Y2 - Y1 }

  if FpIsZero(T1, P) then
    if FpIsZero(T2, P) then
      ECPFpDouble(x1, y1, P, A, x3, y3, Field)
    else
      x3.Length := 0
  else
  begin  
    FpDiv(T2, T1, P, T3, Field); { T3 = (Y2 - Y1) / (X2 - X1) }
    FpSqr(T3, P, Tmp1, Tmp2, T1, Field); { T1 = ((Y2 - Y1) / (X2 - X1)) ^ 2 }
    FpSub(T1, x1, P, T);
    FpSub(T, x2, P, x3); { x3 = ((Y2 - Y1) / (X2 - X1)) ^ 2 - x1 - x2 }
    FpSub(x1, x3, P, T1); { T1 = x1 - x3 }
    FpMul(T3, T1, P, Tmp1, Tmp2, T, Field); { T = ((Y2 - Y1) / (X2 - X1)) * (x1 - x3)}
    FpSub(T, y1, P, y3); { y3 = ((Y2 - Y1) / (X2 - X1)) * (x1 - x3) - y1 }
  end;

  LDestroy(T);
  LDestroy(T1);
  LDestroy(T2);
  LDestroy(T3);
  LDestroy(Tmp1);
  LDestroy(Tmp2);
  LDestroy(Tmp3);
end;

{ Jacobian to affine coordinates conversion }
procedure ECPFpJ2A(X, Y, Z, P : PLInt; var xr, yr : PLInt; Field : integer);
var
  T1, T2, T3, T4 : PLInt;
begin
  LCreate(T1);
  LCreate(T2);
  LCreate(T3);
  LCreate(T4);
  
  FpInv(Z, P, T1, Field); { T1 = Z^-1 }
  FpSqr(T1, P, T3, T4, T2, Field); { T2 = Z^-2 }
  FpMul(T1, T2, P, T3, T4, xr, Field); { xr = Z^-3 }
  FpMul(Y, xr, P, T3, T4, yr, Field); { yr = Y*Z^-3 }
  FpMul(X, T2, P, T3, T4, xr, Field); { xr = X*Z^-2 }

  LDestroy(T1);
  LDestroy(T2);
  LDestroy(T3);
  LDestroy(T4);
end;

{ Binary exponentiation, using mixed affine-Jacobian coordinates }
procedure ECPFpExpJA(x1, y1, P, A, n : PLInt; var xr, yr : PLInt; Field : integer);
var
  X2, Y2, Z2, X3, Y3, Z3 : PLInt;
  i : integer;
  AMinus3 : boolean;
begin
  LCreate(X2);
  LCreate(Y2);
  LCreate(Z2);
  LCreate(X3);
  LCreate(Y3);
  LCreate(Z3);

  FpInt(X2, P, 3);
  FpAdd(A, X2, P, X2);
  AMinus3 := FpIsZero(X2, P); // for A = -3 special processing

  X2.Length := 0; // point on infinity

  for i := LBitCount(n) - 1 downto 1 do
  begin
    if LBitSet(n, i) then
      ECPFpJAAdd(X2, Y2, Z2, x1, y1, P, X3, Y3, Z3, Field)
    else
    begin
      LCopy(X3, X2);
      LCopy(Y3, Y2);
      LCopy(Z3, Z2);
    end;

    if AMinus3 then
      ECPFpJDouble(X3, Y3, Z3, P, X2, Y2, Z2, Field)
    else
      ECPFpJDouble(X3, Y3, Z3, P, A, X2, Y2, Z2, Field);
  end;

  if LBitSet(n, 0) then
  begin
    ECPFpJAAdd(X2, Y2, Z2, x1, y1, P, X3, Y3, Z3, Field);

    LCopy(X2, X3);
    LCopy(Y2, Y3);
    LCopy(Z2, Z3);
  end;

  if (X2.Length = 0) or FpIsZero(Z2, P) then
  begin
    xr.Length := 0;
    FpZero(yr, P);
    Exit;
  end;

  ECPFpJ2A(X2, Y2, Z2, P, xr, yr, Field);

  LDestroy(X2);
  LDestroy(Y2);
  LDestroy(Z2);
  LDestroy(X3);
  LDestroy(Y3);
  LDestroy(Z3);
end;

{ Binary exponentiation, using affine coordinates }
procedure ECPFpExp(x1, y1, P, A, n : PLInt; var xr, yr : PLInt; Field : integer);
var
  X2, Y2, X3, Y3 : PLInt;
  i : integer;
begin
  LCreate(X2);
  LCreate(Y2);
  LCreate(X3);
  LCreate(Y3);

  X2.Length := 0; // point on infinity

  for i := LBitCount(n) - 1 downto 1 do
  begin
    if LBitSet(n, i) then
      ECPFpAdd(X2, Y2, x1, y1, P, A, X3, Y3, Field)
    else
    begin
      LCopy(X3, X2);
      LCopy(Y3, Y2);
    end;

    ECPFpDouble(X3, Y3, P, A, X2, Y2, Field);
  end;

  if LBitSet(n, 0) then
  begin
    ECPFpAdd(X2, Y2, x1, y1, P, A, X3, Y3, Field);

    LCopy(X2, X3);
    LCopy(Y2, Y3);
  end;

  LCopy(xr, X2);
  LCopy(yr, Y2);

  LDestroy(X2);
  LDestroy(Y2);
  LDestroy(X3);
  LDestroy(Y3);
end;

// tests, if point (X, Y) belongs to curve y^2 = x^3 + a*x + b
function ECPFpPointOnCurve(X, Y, A, B, P : PLInt; Field : integer) : boolean;
var
  T, T1, T2, T3 : PLInt;
begin
  LCreate(T);
  LCreate(T1);
  LCreate(T2);
  LCreate(T3);

  try
    FpSqr(X, P, T1, T2, T, Field);
    FpMul(T, X, P, T1, T2, T3, Field);
    FpMul(X, A, P, T1, T2, T, Field);
    FpAdd(T, T3, P, T);
    FpAdd(T, B, P, T);

    FpSqr(Y, P, T1, T2, T3, Field);

    Result := FpCmp(T, T3, P) = 0;
  finally
    LDestroy(T);
    LDestroy(T1);
    LDestroy(T2);
    LDestroy(T3);
  end;
end;

{ Curve y^2 + x*y = x^3 + a*x^2 + b over the binary extended field F2m }

{ Point doubling; Lopez-Dahab coordinates }
procedure ECPF2mPLDDouble(X1, Y1, Z1, a, b, P : PLInt; var X3, Y3, Z3 : PLInt; Field : integer);
var
  T, T1, T2, Tmp1 : PLInt;
begin
  if X1.Length = 0 then
  begin
    X3.Length := 0;
    Exit;
  end;

  LCreate(T);
  LCreate(T1);
  LCreate(T2);
  LCreate(Tmp1);

  F2mPSqr(Z1, P, T1, Field); { T1 = Z1^2 }
  F2mPSqr(X1, P, T2, Field); { T2 = X1^2 }
  F2mPMul(T1, T2, P, Tmp1, Z3, Field); { Z3 = X1^2 * Z1^2 }
  F2mPSqr(T2, P, X3, Field); { X3 = X1^4 }
  F2mPSqr(T1, P, T, Field);
  F2mPMul(b, T, P, Tmp1, T2, Field); { T2 = b * Z1^4 }
  F2mPAdd(X3, T2, P, X3); { X3 = X1^4 + b * Z1^4 }
  F2mPSqr(Y1, P, T1, Field); { T1 = Y1^2 }
  if F2mPIsOne(a, P) then
    F2mPAdd(T1, Z3, P, T1) { T1 = a * Z3 + Y1^2 }
  else if not F2mPIsZero(a, P) then
  begin
    F2mPMul(a, Z3, P, Tmp1, T, Field);
    F2mPAdd(T1, T, P, T1);
  end;

  F2mPAdd(T1, T2, P, T1); { T1 = a * Z3 + Y1^2 + b * Z1^4 }
  F2mPMul(X3, T1, P, Tmp1, Y3, Field); { Y3 = X3 * (a * Z3 + Y1^2 + b * Z1^4) }
  F2mPMul(T2, Z3, P, Tmp1, T1, Field); { T1 = b * Z1^4 * Z3 }
  F2mPAdd(Y3, T1, P, Y3); { Y3 = X3 * (a * Z3 + Y1^2 + b * Z1^4) + b * Z1^4 * Z3 }

  LDestroy(T);
  LDestroy(T1);
  LDestroy(T2);
  LDestroy(Tmp1);
end;

{ Point addition; Lopez-Dahab - affine coordinates }
procedure ECPF2mPLDAAdd(X1, Y1, Z1, x2, y2, a, b, P : PLInt; var X3, Y3, Z3 : PLInt; Field : integer);
var
  T1, T2, T3, T4, Tmp1 : PLInt;
begin
  if x2.Length = 0 then
  begin
    LCopy(X3, X1);
    LCopy(Y3, Y1);
    LCopy(Z3, Z1);
    Exit;
  end;

  if X1.Length = 0 then
  begin
    LCopy(X3, x2);
    LCopy(Y3, y2);
    F2mPOne(Z3, P);
    Exit;
  end;

  LCreate(T1);
  LCreate(T2);
  LCreate(T3);
  LCreate(T4);
  LCreate(Tmp1);

  F2mPMul(x2, Z1, P, Tmp1, T1, Field); { T1 = x2 * Z1 }
  F2mPSqr(Z1, P, T2, Field); { T2 = Z1^2 }
  F2mPAdd(T1, X1, P, X3); { X3 = B = X1 + x2 * Z1 }
  F2mPMul(Z1, X3, P, Tmp1, T1, Field); { T1 = Z1 * B }
  F2mPMul(T2, y2, P, Tmp1, T3, Field); { T3 = y2 * Z1^2 }
  F2mPAdd(Y1, T3, P, Y3); { Y3 = A = Y1 + y2 * Z1^2 }

  if F2mPIsZero(X3, P) then
    if F2mPIsZero(Y3, P) then
    begin
      F2mPOne(T1, P);
      ECPF2mPLDDouble(x2, y2, T1, a, b, P, X3, Y3, Z3, Field);
    end
    else
      X3.Length := 0
  else
  begin
    F2mPSqr(T1, P, Z3, Field); { Z3 = Z1^2 * (X1 + x2 * Z1)^2 }
    F2mPMul(T1, Y3, P, Tmp1, T3, Field); { T3 = Z1 * (X1 + x2 * Z1) * (Y1 + y2 * Z1^2) }
    if F2mPIsOne(a, P) then
      F2mPAdd(T1, T2, P, T1) { T1 = Z1 * (X1 + x2 * Z1) + a * Z1^2 }
    else if not F2mPIsZero(a, P) then
    begin
      F2mPMul(T2, a, P, Tmp1, T4, Field);
      F2mPAdd(T1, T4, P, T1);
    end;
    
    F2mPSqr(X3, P, T2, Field); { T2 = (X1 + x2 * Z1)^2 }
    F2mPMul(T1, T2, P, Tmp1, X3, Field); { X3 = (Z1 * (X1 + x2 * Z1) + a * Z1^2) * (X1 + x2 * Z1)^2}
    F2mPSqr(Y3, P, T2, Field); { T2 = (Y1 + y2 * Z1^2)^2 }
    F2mPAdd(X3, T2, P, X3); { X3 = X3 + (Y1 + y2 * Z1^2)^2 }
    F2mPAdd(X3, T3, P, X3); { X3 = X3 + Z1 * (X1 + x2 * Z1) * (Y1 + y2 * Z1^2) }
    F2mPMul(x2, Z3, P, Tmp1, T2, Field); { T2 = x2 * Z3 }
    F2mPAdd(T2, X3, P, T2); { T2 = T2 + X3 }
    F2mPSqr(Z3, P, T1, Field); { T1 = Z3^2 }
    F2mPAdd(T3, Z3, P, T3); { T3 = T3 + Z3 }
    F2mPMul(T2, T3, P, Tmp1, Y3, Field); { Y3 = T3 * T2 }
    F2mPAdd(x2, y2, P, T2); { T2 = x2 + y2 }
    F2mPMul(T1, T2, P, Tmp1, T3, Field); { T3 = T1 * T2 }
    F2mPAdd(Y3, T3, P, Y3); { Y3 = Y3 + T3 }
  end;

  LDestroy(T1);
  LDestroy(T2);
  LDestroy(T3);
  LDestroy(T4);
  LDestroy(Tmp1);
end;

{ Point doubling; affine coordinates }
procedure ECPF2mPDouble(x1, y1, a, b, P : PLInt; var x3, y3 : PLInt; Field : integer);
var
  T1, T2, Tmp1 : PLInt;
begin
  if (x1.Length = 0) or (F2mPIsZero(x1, P)) then
  begin
    x3.Length := 0;
    Exit;
  end;

  LCreate(T1);
  LCreate(T2);
  LCreate(Tmp1);

  F2mPDiv(y1, x1, P, T1); { T1 = y1/x1 }
  F2mPAdd(x1, T1, P, T1); { T1 = x1 + y1/x1 }
  F2mPSqr(T1, P, T2, Field); { T2 = (x1 + y1/x1)^2 }
  F2mPAdd(T1, T2, P, x3);
  F2mPAdd(x3, a, P, x3); { x3 = (x1 + y1/x1)^2 + (x1 + y1/x1) + a }
  F2mPSqr(x1, P, y3, Field); { y3 = x1^2 }
  F2mPMul(T1, x3, P, Tmp1, T2, Field); { T2 = x3 * (x1 + y1/x1) }
  F2mPAdd(y3, T2, P, y3);
  F2mPAdd(y3, x3, P, y3); { y3 = x1^2 + x3 * (x1 + y1/x1) + x3 }

  LDestroy(T1);
  LDestroy(T2);
  LDestroy(Tmp1);
end;

{ Point addition; affine coordinates }
procedure ECPF2mPAdd(x1, y1, x2, y2, a, b, P : PLInt; var x3, y3 : PLInt; Field : integer);
var
  T1, T2, T3, Tmp1 : PLInt;
begin
  if x2.Length = 0 then
  begin
    LCopy(x3, x1);
    LCopy(y3, y1);
    Exit;
  end;

  if x1.Length = 0 then
  begin
    LCopy(x3, x2);
    LCopy(y3, y2);
    Exit;
  end;

  LCreate(T1);
  LCreate(T2);
  LCreate(T3);
  LCreate(Tmp1);

  if F2mPCmp(x1, x2, P) = 0 then
  begin
    if F2mPCmp(y1, y2, P) = 0 then
      ECPF2mPDouble(x1, y1, a, b, P, x3, y3, Field)
    else
      x3.Length := 0
  end
  else
  begin
    F2mPAdd(x1, x2, P, T1); { T1 = x1 + x2 }
    F2mPAdd(y1, y2, P, T2); { T2 = y1 + y2 }
    F2mPDiv(T2, T1, P, T3); { T3 = (y1 + y2)/(x1 + x2) }
    F2mPSqr(T3, P, x3, Field); {x3 = (y1 + y2)^2/(x1 + x2)^2 }
    F2mPAdd(x3, T3, P, x3);
    F2mPAdd(x3, T1, P, x3);
    F2mPAdd(x3, a, P, x3); { x3 = (y1 + y2)^2/(x1 + x2)^2 + (y1 + y2)/(x1 + x2) + x1 + x2 + a }
    F2mPAdd(x1, x3, P, T1); { T1 = x1 + x3 }
    F2mPMul(T3, T1, P, Tmp1, y3, Field); { y3 = (y1 + y2)/(x1 + x2) * (x1 + x3) }
    F2mPAdd(y3, x3, P, y3);
    F2mPAdd(y3, y1, P, y3); { y3 = (y1 + y2)/(x1 + x2) * (x1 + x3) + x3 + y1 }
  end;  

  LDestroy(T1);
  LDestroy(T2);
  LDestroy(T3);
  LDestroy(Tmp1);
end;

{ Lopez-Dahab to affine coordinates conversion }
procedure ECPF2mPLD2A(X, Y, Z, P : PLInt; var xr, yr : PLInt; Field : integer);
var
  T1, T2, T3 : PLInt;
begin
  LCreate(T1);
  LCreate(T2);
  LCreate(T3);

  F2mPInv(Z, P, T1); { T1 = Z^-1 }
  F2mPSqr(T1, P, T2, Field); { T2 = Z^-2 }
  F2mPMul(X, T1, P, T3, xr, Field); { xr = X*Z^-1 }
  F2mPMul(Y, T2, P, T3, yr, Field); { yr = Y*Z^-2 }

  LDestroy(T1);
  LDestroy(T2);
  LDestroy(T3);
end;


{ Binary exponentiation, using mixed affine - Lopez-Dahab coordinates }
procedure ECPF2mPExpLDA(x1, y1, a, b, P, n : PLInt; var xr, yr : PLInt; Field : integer);
var
  X2, Y2, Z2, X3, Y3, Z3 : PLInt;
  i : integer;
begin
  LCreate(X2);
  LCreate(Y2);
  LCreate(Z2);
  LCreate(X3);
  LCreate(Y3);
  LCreate(Z3);

  X2.Length := 0; // point on infinity

  for i := LBitCount(n) - 1 downto 1 do
  begin
    if LBitSet(n, i) then
      ECPF2mPLDAAdd(X2, Y2, Z2, x1, y1, a, b, P, X3, Y3, Z3, Field)
    else
    begin
      LCopy(X3, X2);
      LCopy(Y3, Y2);
      LCopy(Z3, Z2);
    end;

    ECPF2mPLDDouble(X3, Y3, Z3, a, b, P, X2, Y2, Z2, Field);
  end;

  if LBitSet(n, 0) then
  begin
    ECPF2mPLDAAdd(X2, Y2, Z2, x1, y1, a, b, P, X3, Y3, Z3, Field);

    LCopy(X2, X3);
    LCopy(Y2, Y3);
    LCopy(Z2, Z3);
  end;

  if (X2.Length = 0) or FpIsZero(Z2, P) then
  begin
    xr.Length := 0;
    F2mPZero(yr, P);
    Exit;
  end;

  ECPF2mPLD2A(X2, Y2, Z2, P, xr, yr, Field);

  LDestroy(X2);
  LDestroy(Y2);
  LDestroy(Z2);
  LDestroy(X3);
  LDestroy(Y3);
  LDestroy(Z3);
end;

{ Binary exponentiation, using affine coordinates }
procedure ECPF2mPExp(x1, y1, a, b, P, n : PLInt; var xr, yr : PLInt; Field : integer);
var
  X2, Y2, X3, Y3 : PLInt;
  i : integer;
begin
  LCreate(X2);
  LCreate(Y2);
  LCreate(X3);
  LCreate(Y3);

  X2.Length := 0; // point on infinity 

  for i := LBitCount(n) - 1 downto 1 do
  begin
    if LBitSet(n, i) then
      ECPF2mPAdd(X2, Y2, x1, y1, a, b, P, X3, Y3, Field)
    else
    begin
      LCopy(X3, X2);
      LCopy(Y3, Y2);
    end;

    ECPF2mPDouble(X3, Y3, a, b, P, X2, Y2, Field);
  end;

  if LBitSet(n, 0) then
  begin
    ECPF2mPAdd(X2, Y2, x1, y1, a, b, P, X3, Y3, Field);

    LCopy(X2, X3);
    LCopy(Y2, Y3);
  end;

  LCopy(xr, X2);
  LCopy(yr, Y2);

  LDestroy(X2);
  LDestroy(Y2);
  LDestroy(X3);
  LDestroy(Y3);
end;

function ECPF2mPPointOnCurve(X, Y, A, B, P : PLInt; Field : integer) : boolean;
var
  T, T1, T2, T3 : PLInt;
begin
  LCreate(T);
  LCreate(T1);
  LCreate(T2);
  LCreate(T3);

  try
    F2mPSqr(X, P, T, Field);
    F2mPMul(T, A, P, T1, T2, Field);
    F2mPMul(T, X, P, T1, T3, Field);
    F2mPAdd(T2, T3, P, T);
    F2mPAdd(T, B, P, T);

    F2mPSqr(Y, P, T3, Field);
    F2mPMul(Y, X, P, T1, T2, Field);
    F2mPAdd(T2, T3, P, T3);

    Result := F2mPCmp(T, T3, P) = 0;
  finally
    LDestroy(T);
    LDestroy(T1);
    LDestroy(T2);
    LDestroy(T3);
  end;
end;

{ point compression related stuff }
function ECPF2mPGetYpBit(X, Y, P : PLInt; Field : integer) : integer;
var
  T, T1, C : PLInt;
begin
  LCreate(T);
  LCreate(T1);
  LCreate(C);

  if F2mPIsZero(X, P) then
  begin
    Result := 0;
    Exit;
  end;

  F2mPInv(X, P, T);
  F2mPMul(Y, T, P, T1, C, Field);
  Result := C.Digits[1] and 1;
  LDestroy(C);
  LDestroy(T1);
  LDestroy(T);
end;

function ECPFpDecompress(yp : integer; X, A, B, P : PLInt; var Y : PLInt; Field : integer) : boolean;
var
  T, T1, T2, T3, alpha : PLInt;
begin
  LCreate(T);
  LCreate(T1);
  LCreate(T2);
  LCreate(T3);
  LCreate(alpha);

  FpMul(X, X, P, T1, T2, T, Field);
  FpMul(T, X, P, T1, T2, alpha, Field); // alpha = X^3

  FpMul(A, X, P, T1, T2, T, Field);
  FpAdd(alpha, T, P, alpha); // alpha = X^3 + a*X
  FpAdd(alpha, B, P, alpha); // alpha = X^3 + a*X + b

  Result := FpSqrt(alpha, P, T, Field);
  
  if Result then
  begin
    if integer(T.Digits[1] and 1) <> yp then
      FpSub(P, T, P, Y)
    else
      LCopy(Y, T);
  end;

  LDestroy(alpha);
  LDestroy(T3);
  LDestroy(T2);
  LDestroy(T1);
  LDestroy(T);
end;

function ECPF2mPDecompress(yp : integer; X, A, B, P : PLInt; var Y : PLInt; Field : integer) : boolean;
var
  T, T1, T2, T3 : PLInt;
begin
  //Result := false;
  if F2mPIsZero(X, P) then
  begin
    LCreate(T);

    try
      LShlEx(T, LBitCount(P) - 1);
      F2mPExp(B, T, P, Y, Field);
      Result := true;
    finally
      LDestroy(T);
    end;
  end
  else
  begin
    LCreate(T);
    LCreate(T1);
    LCreate(T2);
    LCreate(T3);

    try
      F2mPInv(X, P, T);
      F2mPSqr(T, P, T1, Field);
      F2mPMul(T1, B, P, T2, T, Field);
      F2mPAdd(T, A, P, T);
      F2mPAdd(T, X, P, T); // T = X + A + B * X^-2

      Result := F2mPSolveQE(T, P, T1, Field);

      if Result then
      begin
        // Y = T1 * X
        if integer(T1.Digits[1] and 1) = yp then
          F2mPMul(T1, X, P, T2, Y, Field)
        else
        begin
          F2mPOne(T, P);
          F2mPAdd(T1, T, P, T1);
          F2mPMul(T1, X, P, T2, Y, Field);
        end;  
      end;  
    finally
      LDestroy(T);
      LDestroy(T1);
      LDestroy(T2);
      LDestroy(T3);
    end;
  end;
end;

{$ifdef ECC_TEST_INCLUDED}
(*
procedure TestF2mP;
var
  A, B, C, D, E, F, T1, T2, P : PLInt;
  Field, FldType : integer;
  i : integer;
begin
  LCreate(A);
  LCreate(B);
  LCreate(C);
  LCreate(D);
  LCreate(P);
  LCreate(T1);
  LCreate(T2);
  LCreate(E);
  LCreate(F);

  SBRndInit;

  for Field := SB_EC_FLD_NIST_B163 to SB_EC_FLD_NIST_B571 do
  begin
    GetFieldParams(Field, FldType, P);

    for i := 1 to 1000 do
    begin
      SBRndGenerateLInt(A, P.Length * 4);
      SBRndGenerateLInt(B, P.Length * 4);
      SBRndGenerateLInt(C, P.Length * 4);

      F2mPReduce(A, P, Field);
      F2mPReduce(B, P, Field);
      F2mPReduce(C, P, Field);

      { multiply/addition test }

      F2mPAdd(A, B, P, T2);
      F2mPMul(T2, C, P, T1, D, SB_EC_FLD_CUSTOM); { D = (A + B) * C }

      F2mPMul(A, C, P, T1, T2, Field);
      F2mPMul(B, C, P, T1, E, Field);
      F2mPAdd(E, T2, P, E); { E = A * C + B * C }

      if F2mPCmp(D, E, P) <> 0 then
        raise EElMathException.Create('');

      { multiply/squaring test }

      F2mPSqr(D, P, T2, Field);
      F2mPMul(D, D, P, T1, E, SB_EC_FLD_CUSTOM);

      if F2mPCmp(T2, E, P) <> 0 then
        raise EElMathException.Create('');

      { inversion test }
      F2mPInv(A, P, D);
      F2mPMul(A, D, P, T1, E, Field);
      if not F2mPIsOne(E, P) then
        raise EElMathException.Create('');

      { division test }
      F2mPDiv(A, B, P, D);
      F2mPMul(D, B, P, T1, E, Field);

      if F2mPCmp(E, A, P) <> 0 then
        raise EElMathException.Create('');
    end;
  end;  

  LDestroy(A);
  LDestroy(B);
  LDestroy(C);
  LDestroy(D);
  LDestroy(P);
  LDestroy(T1);
  LDestroy(T2);
  LDestroy(E);
  LDestroy(F);
end;

procedure TestFP;
var
  A, B, C, D, E, F, T, T1, T2, P : PLInt;
  Field, FldType : integer;
  i : integer;
begin
  LCreate(A);
  LCreate(B);
  LCreate(C);
  LCreate(D);
  LCreate(P);
  LCreate(T);
  LCreate(T1);
  LCreate(T2);
  LCreate(E);
  LCreate(F);

  SBRndInit;

  for Field := SB_EC_FLD_NIST_P192 to SB_EC_FLD_NIST_P521 do
  begin

    GetFieldParams(Field, FldType, P);

    for i := 1 to 1000 do
    begin
      SBRndGenerateLInt(A, P.Length * 4);
      SBRndGenerateLInt(B, P.Length * 4);
      SBRndGenerateLInt(C, P.Length * 4);

      FpReduce(A, P, T1, T, Field);
      FpReduce(B, P, T1, T, Field);
      FpReduce(C, P, T1, T, Field);

      { addition/subtraction test }
      FpAdd(A, B, P, T1);
      LAdd(A, B, T2);

      FpSub(T1, A, P, T);
      LSub(T1, A, D);

      if FpCmp(T, B, P) <> 0 then
        raise EElMathException.Create('');

      { multiply/addition test }

      FpAdd(A, B, P, T2);
      FpMul(T2, C, P, T1, T, D, SB_EC_FLD_CUSTOM); { D = (A + B) * C }

      FpMul(A, C, P, T1, T, T2, Field);
      FpMul(B, C, P, T1, T, E, Field);
      FpAdd(E, T2, P, E); { E = A * C + B * C }

      if FpCmp(D, E, P) <> 0 then
        raise EElMathException.Create('');

      { multiply/squaring test }

      FpSqr(D, P, T1, T, T2, Field);
      FpMul(D, D, P, T1, T, E, SB_EC_FLD_CUSTOM);

      if FpCmp(T2, E, P) <> 0 then
        raise EElMathException.Create('');

      { inversion test }
      FpInv(A, P, D, SB_EC_FLD_CUSTOM);
      FpMul(A, D, P, T1, T, E, Field);
      if not FpIsOne(E, P) then
        raise EElMathException.Create('');

      { division test }
      FpDiv(A, B, P, D, SB_EC_FLD_CUSTOM);
      FpMul(D, B, P, T1, T, E, Field);

      if FpCmp(E, A, P) <> 0 then
        raise EElMathException.Create('');
    end;
  end;

  LDestroy(A);
  LDestroy(B);
  LDestroy(C);
  LDestroy(D);
  LDestroy(P);
  LDestroy(T);
  LDestroy(T1);
  LDestroy(T2);
  LDestroy(E);
  LDestroy(F);
end;

procedure TestECPFp;
var
  ECX, ECY, ECN, ECP, ECA, ECB : PLInt;
  One, X1, X2, X3, Y1, Y2, Y3, Z1, Z2, Z3, xr1, yr1, xr2, yr2 : PLInt;
  Curve, i, Fld, FldType : integer;
begin
  LCreate(ECX);
  LCreate(ECY);
  LCreate(ECN);
  LCreate(ECP);
  LCreate(ECA);
  LCreate(ECB);
  LCreate(X1);
  LCreate(X2);
  LCreate(X3);
  LCreate(Y1);
  LCreate(Y2);
  LCreate(Y3);
  LCreate(Z1);
  LCreate(Z2);
  LCreate(Z3);
  LCreate(xr1);
  LCreate(xr2);
  LCreate(yr1);
  LCreate(yr2);
  LCreate(One);

  FpOne(One, ECP);

  for Curve := SB_EC_NIST_P192 to SB_EC_NIST_P521 do
  begin
    GetCurveField(Curve, Fld, FldType, ECP);
    GetCurveParams(Curve, ECX, ECY, ECN, ECA, ECB);

    { Jacobian, and affine-Jacobian points simple self-tests }

    X3.Length := 0;
    ECPFpJAAdd(X3, Y3, Z3, ECX, ECY, ECP, X1, Y1, Z1, Fld); { Q }
    ECPFpJAAdd(X1, Y1, Z1, ECX, ECY, ECP, X2, Y2, Z2, Fld); { 2*Q }
    ECPFpJDouble(X2, Y2, Z2, ECP, X3, Y3, Z3, Fld); { 4*Q }
    ECPFpJAAdd(X2, Y2, Z2, ECX, ECY, ECP, X1, Y1, Z1, Fld); { 3*Q }
    ECPFpJAAdd(X1, Y1, Z1, ECX, ECY, ECP, X2, Y2, Z2, Fld); { 4*Q }
    ECPFpJ2A(X3, Y3, Z3, ECP, xr1, yr1, Fld);
    ECPFpJ2A(X2, Y2, Z2, ECP, xr2, yr2, Fld);

    if (FpCmp(xr1, xr2, ECP) <> 0) or (FpCmp(yr1, yr2, ECP) <> 0) then
      raise EElMathException.Create('');

    ECPFpAdd(ECX, ECY, ECX, ECY, ECP, X1, Y1, Fld); { 2*Q }
    ECPFpAdd(X1, Y1, ECX, ECY, ECP, X2, Y2, Fld); { 3*Q }
    ECPFpAdd(X2, Y2, ECX, ECY, ECP, xr2, yr2, Fld); { 4*Q }
    ECPFpDouble(X1, Y1, ECP, X3, Y3, Fld); { 4*Q }

    if (FpCmp(xr2, X3, ECP) <> 0) or (FpCmp(yr2, Y3, ECP) <> 0) then
      raise EElMathException.Create('');

    if (FpCmp(xr1, xr2, ECP) <> 0) or (FpCmp(yr1, yr2, ECP) <> 0) then
      raise EElMathException.Create('');

    { elliptic curve order self-test }

    FpInt(Z3, ECP, SBRndGenerate(1000));
    X1.Length := 0;

    for i := 1 to Z3.Digits[1] do
    begin
      ECPFpJAAdd(X1, Y1, Z1, ECX, ECY, ECP, X2, Y2, Z2, Fld);
      LCopy(X1, X2);
      LCopy(Y1, Y2);
      LCopy(Z1, Z2);
    end;

    ECPFpJ2A(X1, Y1, Z1, ECP, X2, Y2, Fld);
    ECPFpExpJA(ECX, ECY, ECP, Z3, xr1, yr1, Fld);

    if (FpCmp(X2, xr1, ECP) <> 0) or (FpCmp(Y2, yr1, ECP) <> 0) then
      raise EElMathException.Create('');

    ECPFpExpJA(ECX, ECY, ECP, ECN, xr1, yr1, Fld);

    if xr1.Length > 0 then
      raise EElMathException.Create('');

    ECPFpExp(ECX, ECY, ECP, ECN, xr1, yr1, Fld);

    if xr1.Length > 0 then
      raise EElMathException.Create('');


    for i := 1 to 10 do
    begin
      SBRndGenerateLInt(X3, ECP.Length * 4);
      FpReduce(X3, ECP, Y3, Z3, Fld);

      ECPFpExpJA(ECX, ECY, ECP, X3, xr1, yr1, Fld);
      ECPFpExp(ECX, ECY, ECP, X3, xr2, yr2, Fld);

      if (FpCmp(xr1, xr2, ECP) <> 0) or (FpCmp(yr1, yr2, ECP) <> 0) then
        raise EElMathException.Create('');
    end;
  end;

  LDestroy(ECX);
  LDestroy(ECY);
  LDestroy(ECN);
  LDestroy(ECP);
  LDestroy(ECA);
  LDestroy(ECB);
  LDestroy(X1);
  LDestroy(X2);
  LDestroy(X3);
  LDestroy(Y1);
  LDestroy(Y2);
  LDestroy(Y3);
  LDestroy(Z1);
  LDestroy(Z2);
  LDestroy(Z3);
  LDestroy(xr1);
  LDestroy(xr2);
  LDestroy(yr1);
  LDestroy(yr2);
  LDestroy(One);
end;


procedure TestECPF2m;
var
  ECX, ECY, ECN, ECP, ECA, ECB : PLInt;
  One, X1, X2, X3, Y1, Y2, Y3, Z1, Z2, Z3, xr1, yr1, xr2, yr2 : PLInt;
  Curve, i, Fld, FldType : integer;
begin
  LCreate(ECX);
  LCreate(ECY);
  LCreate(ECN);
  LCreate(ECP);
  LCreate(ECA);
  LCreate(ECB);
  LCreate(X1);
  LCreate(X2);
  LCreate(X3);
  LCreate(Y1);
  LCreate(Y2);
  LCreate(Y3);
  LCreate(Z1);
  LCreate(Z2);
  LCreate(Z3);
  LCreate(xr1);
  LCreate(xr2);
  LCreate(yr1);
  LCreate(yr2);
  LCreate(One);

  F2mPOne(One, ECP);

  for Curve := SB_EC_NIST_B163 to SB_EC_NIST_K571 do
  begin
    GetCurveField(Curve, Fld, FldType, ECP);
    GetCurveParams(Curve, ECX, ECY, ECN, ECA, ECB);

    { Lopez-Dahab, and affine - Lopez-Dahab points simple self-tests }

    X3.Length := 0;
    ECPF2mPLDAAdd(X3, Y3, Z3, ECX, ECY, ECA, ECB, ECP, X1, Y1, Z1, Fld); { Q }
    ECPF2mPLDAAdd(X1, Y1, Z1, ECX, ECY, ECA, ECB, ECP, X2, Y2, Z2, Fld); { 2*Q }
    ECPF2mPLDDouble(X2, Y2, Z2, ECA, ECB, ECP, X3, Y3, Z3, Fld); { 4*Q }
    ECPF2mPLDAAdd(X2, Y2, Z2, ECX, ECY, ECA, ECB, ECP, X1, Y1, Z1, Fld); { 3*Q }
    ECPF2mPLDAAdd(X1, Y1, Z1, ECX, ECY, ECA, ECB, ECP, X2, Y2, Z2, Fld); { 4*Q }
    ECPF2mPLD2A(X3, Y3, Z3, ECP, xr1, yr1, Fld);
    ECPF2mPLD2A(X2, Y2, Z2, ECP, xr2, yr2, Fld);

    if (F2mPCmp(xr1, xr2, ECP) <> 0) or (F2mPCmp(yr1, yr2, ECP) <> 0) then
      raise EElMathException.Create('');

    ECPF2mPAdd(ECX, ECY, ECX, ECY, ECA, ECB, ECP, X1, Y1, Fld); { 2*Q }
    ECPF2mPAdd(X1, Y1, ECX, ECY, ECA, ECB, ECP, X2, Y2, Fld); { 3*Q }
    ECPF2mPAdd(X2, Y2, ECX, ECY, ECA, ECB, ECP, xr2, yr2, Fld); { 4*Q }
    ECPF2mPDouble(X1, Y1, ECA, ECB, ECP, X3, Y3, Fld); { 4*Q }

    if (F2mPCmp(xr2, X3, ECP) <> 0) or (F2mPCmp(yr2, Y3, ECP) <> 0) then
      raise EElMathException.Create('');

    if (F2mPCmp(xr1, xr2, ECP) <> 0) or (F2mPCmp(yr1, yr2, ECP) <> 0) then
      raise EElMathException.Create('');

    { elliptic curve order self-test }

    FpInt(Z3, ECP, SBRndGenerate(1000));
    X1.Length := 0;

    for i := 1 to Z3.Digits[1] do
    begin
      ECPF2mPLDAAdd(X1, Y1, Z1, ECX, ECY, ECA, ECB, ECP, X2, Y2, Z2, Fld);
      LCopy(X1, X2);
      LCopy(Y1, Y2);
      LCopy(Z1, Z2);
    end;

    ECPF2mPLD2A(X1, Y1, Z1, ECP, X2, Y2, Fld);

    X1.Length := 0;

    for i := 1 to Z3.Digits[1] do
    begin
      ECPF2mPAdd(X1, Y1, ECX, ECY, ECA, ECB, ECP, X3, Y3, Fld);
      LCopy(X1, X3);
      LCopy(Y1, Y3);
    end;

    LCopy(X3, X1);
    LCopy(Y3, Y1);

    if (F2mPCmp(X2, X3, ECP) <> 0) or (F2mPCmp(Y2, Y3, ECP) <> 0) then
      raise EElMathException.Create('');

    ECPF2mPExpLDA(ECX, ECY, ECA, ECB, ECP, Z3, xr1, yr1, Fld);
    ECPF2mPExp(ECX, ECY, ECA, ECB, ECP, Z3, xr2, yr2, Fld);

    if (F2mPCmp(X2, xr1, ECP) <> 0) or (F2mPCmp(Y2, yr1, ECP) <> 0) then
      raise EElMathException.Create('');

    if (F2mPCmp(xr2, X2, ECP) <> 0) or (F2mPCmp(yr2, Y2, ECP) <> 0) then
      raise EElMathException.Create('');


    ECPF2mPExpLDA(ECX, ECY, ECA, ECB, ECP, ECN, xr1, yr1, Fld);

    if xr1.Length > 0 then
      raise EElMathException.Create('');

    ECPF2mPExp(ECX, ECY, ECA, ECB, ECP, ECN, xr1, yr1, Fld);

    if xr1.Length > 0 then
      raise EElMathException.Create('');

    for i := 1 to 20 do
    begin
      SBRndGenerateLInt(X3, ECP.Length * 4);
      F2mPReduce(X3, ECP, Fld);

      ECPF2mPExpLDA(ECX, ECY, ECA, ECB, ECP, X3, xr1, yr1, Fld);
      ECPF2mPExp(ECX, ECY, ECA, ECB, ECP, X3, xr2, yr2, Fld);

      if (F2mPCmp(xr1, xr2, ECP) <> 0) or (F2mPCmp(yr1, yr2, ECP) <> 0) then
        raise EElMathException.Create('');
    end;
  end;

  LDestroy(ECX);
  LDestroy(ECY);
  LDestroy(ECN);
  LDestroy(ECP);
  LDestroy(ECA);
  LDestroy(ECB);
  LDestroy(X1);
  LDestroy(X2);
  LDestroy(X3);
  LDestroy(Y1);
  LDestroy(Y2);
  LDestroy(Y3);
  LDestroy(Z1);
  LDestroy(Z2);
  LDestroy(Z3);
  LDestroy(xr1);
  LDestroy(xr2);
  LDestroy(yr1);
  LDestroy(yr2);
  LDestroy(One);
end; *)
 {$endif}

end.
