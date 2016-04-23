(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit  SBGOST341094;

interface

uses
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBConstants,
  SBMath,
  SBGOSTCommon
  ;


type
  TElGOSTSignerBase = class//(TElGOSTBase)
  protected
    fSecretKey: PLInt;
    fPublicKey: PLInt;
    procedure SetSecretKey(const V: PLInt);
    procedure SetPublicKey(const V: PLInt);
  public
    constructor Create;
     destructor  Destroy; override;
    procedure AssignSecretKey(const HexStr: string);
    procedure AssignPublicKey(const HexStr: string);
    function  Sign(const Digest: ByteArray): ByteArray;
                 overload;  virtual; abstract;
    function  Verify(const Digest, Sign: ByteArray): Boolean;
                 overload;  virtual; abstract;
    procedure Generate_Keys();  overload;  virtual; abstract;
    property  SecretKey: PLInt read fSecretKey write SetSecretKey;
    property  PublicKey: PLInt read fPublicKey write SetPublicKey;
  end;

  //  GOST R 34.10-94 Signature Algorithm
  TElGOSTSigner = class(TElGOSTSignerBase)
  protected
    fP: PLInt;
    fQ: PLInt;
    fA: PLInt;
    procedure SetP(const V: PLInt);
    procedure SetQ(const V: PLInt);
    procedure SetA(const V: PLInt);
  public
    constructor Create;
     destructor   Destroy; override;
    procedure AssignP(const HexStr: string);
    procedure AssignQ(const HexStr: string);
    procedure AssignA(const HexStr: string);

    class function Check_Params(Bits: integer; const P, Q, A: PLInt; x0, c: TSBInt64): Boolean; 
    function  Generate_PQA(Bits: integer; TypeProc: integer; var x0, c: TSBInt64): Boolean;  overload; 
    class function  Generate_PQA(Bits: integer; TypeProc: integer; var x0, c: TSBInt64;
            var P, Q, A: PLInt): Boolean;  overload;  

    function  Generate_All(Bits: integer; TypeProc: integer; var x0, c: TSBInt64): Boolean;
    procedure Generate_Keys();  overload;  override;
    class procedure Generate_Keys(const P, Q, A: PLInt; var SecretKey, PublicKey: PLInt);
                   overload;  

    function  Sign(const Digest: ByteArray): ByteArray;
                   overload;  override;
    class function Sign(const Digest: ByteArray;
                const P, Q, A: string; const Key: string): ByteArray;
                   overload;  
    class function Sign(const Digest: ByteArray;
                const P, Q, A: PLInt; const Key: PLInt): ByteArray;
                   overload;  

    function  Verify(const Digest, Sign: ByteArray): Boolean;
                 overload;  override;
    class function  Verify(const Digest, Sign: ByteArray;
                const P, Q, A: PLInt; const Key: PLInt): Boolean;
                 overload;  

    property  P: PLInt read fP write SetP;
    property  Q: PLInt read fQ write SetQ;
    property  A: PLInt read fA write SetA;
  end;

{$ifdef GOST_TEST}
procedure Pub_Test;
 {$endif}

implementation

uses
  SysUtils,
  SBRandom;

type
  PLInt_Array = array of PLInt;

procedure SetLength_BI(var Arr: PLInt_Array; Size: integer);
var
  i, L: integer;
begin
  L := Length(Arr);

  if  Size = L  then
    exit
  else
  if  Size > L  then
  begin
    SetLength(Arr, Size);

    for i := L to Size - 1 do
      LCreate(Arr[i]);
  end
  else
  begin
    for i := Size to L - 1 do
      LDestroy(Arr[i]);

    SetLength(Arr, Size);
  end;
end;

procedure SetLength_BA(var Arr: ByteArray; Size: integer);
begin
  if  Length(Arr) <> Size  then
    SetLength(Arr, Size);
end;

procedure BufferTypeToPLInt(const Buf: ByteArray; var Res: PLInt);
begin
  PointerToLInt(Res, @Buf[1], Length(Buf));
end;

procedure BA_to_PLInt(const Arr: ByteArray; Offset, Size: integer;
            var Res: PLInt);
var IntArr : ByteArray;
begin
  IntArr := SBCopy(Arr, Offset, Size);
  PointerToLInt(Res, @IntArr[0], Size);
//  LInit(Res, BinaryToString(@SBCopy(Arr, Offset, Size)[0], Size));
end;

procedure PLInt_to_BA(const V: PLInt; const Arr: ByteArray; Offset, Size: integer);
var
  S: string;
  T: ByteArray;
  i, j, L: integer;
begin
  S := LToStr(V);
  i := Length(S) shr 1;
  SetLength_BA(T, i);
  StringToBinary(S, @T[0], i);

  if  i < Size then
    L := Size - i
  else
    L := 0;

  L := L + Offset - 1;

  for i := Offset to L do
    Arr[i] := 0;

  i := Offset + 32 - 1;
  Offset := L + 1;
  L := i;
  j := 0;

  for i := Offset to L do
  begin
    Arr[i] := T[j];
    inc(j);
  end;
end;

procedure LModPower(A, E, N: PLInt; var Res: PLInt);
begin
  LMModPower(A, E, N, Res, nil, nil, true);
end;

{-------   TElGOSTSignerBase  --------------}

constructor TElGOSTSignerBase.Create;
begin
  inherited Create();
end;

 destructor  TElGOSTSignerBase.Destroy;
begin
  LDestroy(fSecretKey);
  LDestroy(fPublicKey);
  inherited ;
end;

procedure TElGOSTSignerBase.SetSecretKey(const V: PLInt);
begin
  LCopy(fSecretKey, V);
end;

procedure TElGOSTSignerBase.SetPublicKey(const V: PLInt);
begin
  LCopy(fPublicKey, V);
end;

procedure TElGOSTSignerBase.AssignSecretKey(const HexStr: string);
begin
  LInit(fSecretKey, HexStr);
end;

procedure TElGOSTSignerBase.AssignPublicKey(const HexStr: string);
begin
  LInit(fPublicKey, HexStr);
end;

{-------   TElGOSTSigner  --------------}

constructor TElGOSTSigner.Create;
begin
  inherited Create();

  LCreate(fP);
  LCreate(fQ);
  LCreate(fA);
end;

 destructor  TElGOSTSigner.Destroy;
begin
  LDestroy(fP);
  LDestroy(fQ);
  LDestroy(fA);
  inherited ;
end;

procedure TElGOSTSigner.SetP(const V: PLInt);
begin
  LCopy(fP, V);
end;

procedure TElGOSTSigner.SetQ(const V: PLInt);
begin
  LCopy(fQ, V);
end;

procedure TElGOSTSigner.SetA(const V: PLInt);
begin
  LCopy(fA, V);
end;

procedure TElGOSTSigner.AssignP(const HexStr: string);
begin
  LInit(fP, HexStr);
end;

procedure TElGOSTSigner.AssignQ(const HexStr: string);
begin
  LInit(fQ, HexStr);
end;

procedure TElGOSTSigner.AssignA(const HexStr: string);
begin
  LInit(fA, HexStr);
end;

function  TElGOSTSigner.Sign(const Digest: ByteArray): ByteArray;
begin
  Result := Sign(Digest, P, Q, A, fSecretKey);
end;

class function  TElGOSTSigner.Sign(const Digest: ByteArray;
        const P, Q, A: string; const Key: string): ByteArray;
var
  iP, iQ, iA, iKey: PLInt;
begin
  LCreate(iP);
  LCreate(iQ);
  LCreate(iA);
  LCreate(iKey);

  try
    LInit(iP, P);
    LInit(iQ, Q);
    LInit(iA, A);
    LInit(iKey, Key);
    Result := Sign(Digest, iP, iQ, iA, iKey);
  finally
    LDestroy(iP);
    LDestroy(iQ);
    LDestroy(iA);
    LDestroy(iKey);
  end;
end;

class function TElGOSTSigner.Sign(const Digest: ByteArray;
        const P, Q, A: PLInt; const Key: PLInt): ByteArray;
var
  m, k, R, S: PLInt;
  V1, V2: PLInt;
begin
  Result := nil;
  LCreate(m);
  LCreate(k);
  LCreate(V1);
  LCreate(V2);
  LCreate(R);
  LCreate(S);

  try
    BA_to_PLInt(Digest, 0, Length(Digest), m);
    LModEx(m, Q, V1);

    if  LNull(V1)  then
      LInit(m, '1');

    while True do
    begin
      while True do
      begin
        LGenerate(k, Q.Length);
{$ifdef GOST_TEST}
        LInit(k, '90F3A564439242F5186EBB224C8E223811B7105C64E4F5390807E6362DF4C72A');
 {$endif}
        if  not LNull(k) and LGreater(Q, k) then
          break;
      end;

      LModPower(A, k, P, V1);
      LModEx(V1, Q, R);

      if  not LNull(R)  then
      begin
        LMult(Key, R, V1);
        LMult(k, m, V2);
        LAdd(V1, V2, k);
        LModEx(k, Q, S);

        if  not LNull(S)  then
          break;
      end;
    end;

    SetLength_BA(Result, 64);
    PLInt_to_BA(S, Result, 0, 32);
    PLInt_to_BA(R, Result, 32, 32);
  finally
    LDestroy(m);
    LDestroy(k);
    LDestroy(V1);
    LDestroy(V2);
    LDestroy(R);
    LDestroy(S);
  end;
end;

function  TElGOSTSigner.Verify(const Digest, Sign: ByteArray): Boolean;
begin
  Result := Verify(Digest, Sign, fP, fQ, fA, fPublicKey);
end;

class function  TElGOSTSigner.Verify(const Digest, Sign: ByteArray;
              const P, Q, A: PLInt; const Key: PLInt): Boolean;
var
  c0:  PLInt;
  m, S, R: PLInt;
  V, V1: PLInt;
  Z1, Z2, U: PLInt;
begin
  Result := False;

  if  (Length(Digest) <> 32) or (Length(Sign) <> 64)  then
    exit;

  LCreate(c0);
  LCreate(S);
  LCreate(R);
  LCreate(m);
  LCreate(V);
  LCreate(V1);
  LCreate(Z1);
  LCreate(Z2);
  LCreate(U);

  try
    BA_to_PLInt(Digest, 0, Length(Digest), m);
    BA_to_PLInt(Sign, 0, 32, S);
    BA_to_PLInt(Sign, 32, 32, R);
    LZero(c0);

    if  not LGreater(R, c0) or LGreater(R, Q)
        or not LGreater(S, c0) or LGreater(S, Q)  then
      exit;

    LModEx(m, Q, V1);

    if  LNull(V1)  then
      LInit(m, '1');

    LSub(Q, 2, V1);
    LModPower(m, V1, Q, V);

    LSub(Q, R, V1);
    LMult(V1, V, Z1);
    LModEx(Z1, Q, Z2);

    LMult(S, V, V1);
    LModEx(V1, Q, Z1);
    LModPower(A, Z1, P, V1);
    LModPower(Key, Z2, P, V);
    LMult(V, V1, m);
    LModEx(m, P, V1);
    LModEx(V1, Q, U);

    if  LEqual(U, R)  then
      Result := True;

  finally
    LDestroy(c0);
    LDestroy(S);
    LDestroy(R);
    LDestroy(m);
    LDestroy(V);
    LDestroy(V1);
    LDestroy(Z1);
    LDestroy(Z2);
    LDestroy(U);
  end;
end;

function  BigNum_to_Int(V: PLInt): UInt32;
var
  S: string;
begin
  S := LToStr(V);

  if  Length(S) > 8 then
    raise EElMathException.Create(sNumberTooLarge);

  Result := StrToInt('$' + S);
end;

procedure Check_X0_C(Bits: integer; var x0, c: TSBInt64);
var
  MM: TSBInt64;
begin
  MM := (TSBInt64(1) shl Bits);

  // Verify and perform condition: 0<x<2^Bits; 0<c<2^Bits; c - odd.
  while (x0 <= 0) or (cardinal(x0) > MM) do
    x0 := SBRndGenerate(MM);

  while (c <= 0) or (cardinal(c) > MM) or ((c mod 2) = 0) do
    c := SBRndGenerate(MM);
end;

function  Procedure_A(Bits, Size: integer; var x0, c: TSBInt64; var res_P, res_Q: PLInt): integer;
var
  aPow2: PLInt_Array;

  function  Pow2(N: integer): PLInt;
  var
    i, L: integer;
  begin
    L := Length(aPow2);

    if  N >= L  then
    begin
        SetLength(aPow2, N + 1);

      for i := L to N do
        aPow2[i] := nil;
    end;

    if  aPow2[N] = nil then
    begin
      LCreate(aPow2[N]);
      LShlEx(aPow2[N], N);
    end;

    Result := aPow2[N];
  end;

//label
//  Step5, Step6;
var
  cA, c2powN, c1, c2: PLInt;
  bC, V1, V2, V3, V4, V5, Ym, N: PLInt;
  y, p: PLInt_Array;
  t: array of integer;
  i, k: integer;
  s, m, rm: integer;
  Flag1: Boolean;
begin
  Check_X0_C(Bits, x0, c);
  LCreate(bC);
  LCreate(cA);
  LCreate(c1);
  LCreate(c2);
  LCreate(V1);
  LCreate(V2);
  LCreate(V3);
  LCreate(V4);
  LCreate(V5);
  LCreate(Ym);
  LCreate(N);

  try
    c2powN := Pow2(Bits);
    LInit(c2, '2');
    LInit(bC, IntToHex(c, 8));

    if  Bits = 16 then
      LInit(cA, IntToHex(19381, 4))
    else
      LInit(cA, IntToHex(97781173, 8));

    //  Step 1, 2
    SetLength(t, 1);
    SetLength_BI(y, 1);
    LInit(y[0], IntToHex(x0, 8));
    t[0] := Size;

    if  Bits = 16 then
      k := 17
    else
      k := 33;

    for i := 0 to 99999 do
      if  t[i] < k   then
        break
      else
      begin
        SetLength(t, Length(t) + 1);
        t[i + 1] := t[i] shr 1;
      end;

    s := Length(t) - 1;
    SetLength_BI(p, s + 1);

    // Step3
    if  Bits = 16 then
      LInit(p[s], '8003')         //  min prime number length 16 bit
    else
      LInit(p[s], '8000000B');    //  min prime number length 32 bit

    m := s - 1;

    while True do
    begin
      //  Step5
      Flag1 := True;
      rm := t[m] div Bits;  //step5
      SetLength_BI(y, rm + 1);

      while Flag1 do
      begin
        //  Step6
        LZero(Ym);

        for i := 0 to rm - 1 do
        begin
          LMult(y[i], cA, V1);
          LAdd(V1, bC, V2);
          LMod(V2, c2powN, y[i + 1]);
        end;

        for i := 0 to rm - 1 do
        begin
          LMult(y[i], Pow2(Bits * i), V1);
          LAdd(Ym, V1, V2);
          LCopy(Ym, V2);
        end;

        LCopy(y[0], y[rm]); //step 8

        // Step 9
        LDiv(Pow2(t[m] - 1), p[m + 1], V1, V2);
        LMult(Pow2(t[m] - 1), Ym, V2);
        LMult(Pow2(Bits * rm), p[m + 1], V3);
        LDiv(V2, V3, V4, V5);
        LAdd(V1, V4, N);

        if  not LEven(N)  then
          LAdd(N, 1, N);

        // Step 10
        k := 0;

        while True do //  Step 11
        begin
          LAdd(N, k, V1);
          LMult(p[m + 1], V1, V2);
          LAdd(V2, 1, p[m]);

          if  LGreater(p[m], Pow2(t[m])) then
            break;  //  goto Step6;

          LModPower(c2, V2, p[m], V3);
          LModPower(c2, V1, p[m], V4);

          if  LEqual(V3, c1) and not LEqual(V4, c1) then
          begin
            dec(m);

            if  m >= 0  then
            begin
              Flag1 := False;   //  goto Step5;
              break;
            end;

            Result := StrToInt('$' + LToStr(y[0]));
            LCopy(res_P, p[0]);
            LCopy(res_Q, p[1]);
            exit;
          end
          else
            inc(k, 2)
        end;
      end;
    end;

  finally
    SetLength_BI(y, 0);
    SetLength_BI(p, 0);
    SetLength_BI(aPow2, 0);
    LDestroy(bC);
    LDestroy(cA);
    LDestroy(c1);
    LDestroy(c2);
    LDestroy(V1);
    LDestroy(V2);
    LDestroy(V3);
    LDestroy(V4);
    LDestroy(V5);
    LDestroy(Ym);
    LDestroy(N);
  end;
end;

procedure Procedure_B(Bits: integer; var x0, c: TSBInt64; var res_P, res_Q: PLInt);
var
  aPow2: PLInt_Array;

  function  Pow2(N: integer): PLInt;
  var
    i, L: integer;
  begin
    L := Length(aPow2);

    if  N >= L  then
    begin
        SetLength(aPow2, N + 1);

      for i := L to N do
        aPow2[i] := nil;
    end;

    if  aPow2[N] = nil then
    begin
      LCreate(aPow2[N]);
      LShlEx(aPow2[N], N);
    end;

    Result := aPow2[N];
  end;

var
  cA: PLInt;
  c0, c1, c2: PLInt;
  bC, V1, V2, V3, V4, V5, Ym, N: PLInt;
  vN1, vN2: PLInt;
  Q, vQ1Q2: PLInt;
  y, p: PLInt_Array;
  i, k: integer;
  rm: integer;
  MM: TSBInt64;
  tp, N1: integer;
begin
  Check_X0_C(Bits, x0, c);
  LCreate(bC);
  LCreate(cA);
  LCreate(c0);
  LCreate(c1);
  LCreate(c2);
  LCreate(V1);
  LCreate(V2);
  LCreate(V3);
  LCreate(V4);
  LCreate(V5);
  LCreate(Ym);
  LCreate(N);
  LCreate(Q);
  LCreate(vQ1Q2);
  LCreate(vN1);
  LCreate(vN2);

  try
    if  Bits = 16 then
    begin
      LInit(cA, IntToHex(19381, 4));
      N1 := 63;
    end
    else
    begin
      LInit(cA, IntToHex(97781173, 8));
      N1 := 31;
    end;

    LInit(c0, '0');
    LInit(c1, '1');
    LInit(c2, '2');
    LInit(bC, IntToHex(c, 8));

    tp := 1024;

    MM := Procedure_A(Bits, 256, x0, c, res_Q, V1);
    rm := Procedure_A(Bits, 512, MM, c, Q, V1);

    LMult(res_Q, Q, vQ1Q2);
    LDiv(Pow2(tp - 1), vQ1Q2, vN1, V1);

    if  LGreater(V1, c0)  then
      LAdd(vN1, 1, vN1);

    LMult(vQ1Q2, Pow2(tp), vN2);
    SetLength_BI(y, 65);
    LInit(y[0], IntToHex(rm, 8));

    while True do
    begin
      //  3
      for i := 0 to N1 do
      begin
        LMult(y[i], cA, V1);
        LAdd(V1, bC, V2);
        LMod(V2, Pow2(Bits), y[i + 1]);
      end;

      //  4
      LZero(Ym);

      for i := 0 to N1 do
      begin
        LMult(y[i], Pow2(Bits * i), V1);
        LAdd(Ym, V1, V2);
        LCopy(Ym, V2);
      end;

      //  5
      LCopy(y[0], y[N1 + 1]);
      //  6
      LMult(Pow2(tp - 1), Ym, V1);
      LDiv(V1, vN2, V2, V3);
      LAdd(vN1, V2, N);

      if  not LEven(N)  then
        LAdd(N, 1, N);

      //  7
      k := 0;

      while True do
      begin
        LAdd(N, k, V1);
        LMult(vQ1Q2, V1, V2);
        LAdd(V2, 1, res_P);

        if  LGreater(res_P, Pow2(tp))  then
          break;

        LModPower(c2, V2, res_P, V3);
        LMult(V1, res_Q, V4);
        LModPower(c2, V4, res_P, V5);

        if  LEqual(V3, c1) and not LEqual(V5, c1)  then
          exit;

        inc(k, 2);
      end;
    end;

  finally
    SetLength_BI(y, 0);
    SetLength_BI(p, 0);
    SetLength_BI(aPow2, 0);
    LDestroy(bC);
    LDestroy(cA);
    LDestroy(c1);
    LDestroy(c2);
    LDestroy(V1);
    LDestroy(V2);
    LDestroy(V3);
    LDestroy(V4);
    LDestroy(V5);
    LDestroy(Ym);
    LDestroy(N);
    LDestroy(Q);
    LDestroy(vQ1Q2);
    LDestroy(vN1);
    LDestroy(vN2);
  end;
end;

procedure Procedure_C(const P, Q: PLInt; var A: PLInt);
var
  P_1, P_1DivQ, D, One: PLInt;
begin
  LCreate(P_1);
  LCreate(P_1DivQ);
  LCreate(D);
  LCreate(One);

  try
    LSub(P, 1, P_1);
    LDiv(P_1, Q, P_1DivQ, D);

    while True do
    begin
      LGenerate(D, P.Length);
{$ifdef GOST_TEST}
      LInit(D, '2');
 {$endif}      
      // 1 < d < p-1
      if  LGreater(D, One) and LGreater(P_1, D) then
      begin
        LModPower(D, P_1DivQ, P, A);

        if  not LEqual(A, One)  then
          exit;
      end;
    end;
  finally
    LDestroy(P_1);
    LDestroy(P_1DivQ);
    LDestroy(D);
    LDestroy(One);
  end;
end;

function  TElGOSTSigner.Generate_PQA(Bits: integer; TypeProc: integer; var x0, c: TSBInt64): Boolean;
begin
  Result := Generate_PQA(Bits, TypeProc, x0, c, fP, fQ, fA);
end;

class function  TElGOSTSigner.Generate_PQA(Bits: integer; TypeProc: integer; var x0, c: TSBInt64;
              var P, Q, A: PLInt): Boolean;
var
  kBits: integer;
begin
  Result := False;

  if  (TypeProc < 0) or (TypeProc > 1)  then
    TypeProc := 1;

  if  Bits = 512  then
    kBits := 16
  else
  if  Bits = 1024  then
    kBits := 32
  else
    exit;

  if  TypeProc = 0  then
    Procedure_A(kBits, Bits, x0, c, P, Q)
  else
    Procedure_B(kBits, x0, c, P, Q);

  Procedure_C(P, Q, A);

  Result := True;
end;

function  TElGOSTSigner.Generate_All(Bits: integer; TypeProc: integer; var x0, c: TSBInt64): Boolean;
begin
  Result := Generate_PQA(Bits, TypeProc, x0, c);

  if  Result  then
    Generate_Keys();
end;

procedure TElGOSTSigner.Generate_Keys();
begin
  Generate_Keys(fP, fQ, fA, fSecretKey, fPublicKey);
end;

class procedure TElGOSTSigner.Generate_Keys(const P, Q, A: PLInt; var SecretKey, PublicKey: PLInt);
begin
  while True do
  begin
    LGenerate(SecretKey, 8);
{$ifdef GOST_TEST}
    LInit(SecretKey, '3036314538303830343630454235324435324234314132373832433138443046');
 {$endif}
    if  not LNull(SecretKey) and LGreater(Q, SecretKey)  then
      break;
  end;

  LModPower(A, SecretKey, P, PublicKey);
end;

class function TElGOSTSigner.Check_Params(Bits: integer; const P, Q, A: PLInt;
              x0, c: TSBInt64): Boolean;
var
  vP, vQ, vA: PLInt;
begin
  Result := False;
  LCreate(vP);
  LCreate(vQ);
  LCreate(vA);
  try
    if  Generate_PQA(Bits, 0, x0, c, vP, vQ, vA)  then
    begin
      if  not LEqual(vP, P) or not LEqual(vQ, Q) then
        Generate_PQA(Bits, 1, x0, c, vP, vQ, vA);

      Result := LEqual(vP, P) and LEqual(vQ, Q);
    end;
  finally
    LDestroy(vP);
    LDestroy(vQ);
    LDestroy(vA);
  end;
end;

{$ifdef GOST_TEST}
procedure Pub_Test;
var
  P, Q, A, Sec_K, Pub_K: PLInt;
  S: string;
  sP, sQ, sA: string;
  x0, c: TSBInt64;
  Digest, Res: ByteArray;
  ii: integer;
  Xp, Yp, B, M: PLInt;
begin
  LCreate(P);
  LCreate(Q);
  LCreate(A);
  LCreate(Sec_K);
  LCreate(Pub_K);
  LCreate(Xp);
  LCreate(Yp);
  LCreate(M);
  LCreate(B);

  try
    LInit(P, '8000000000000000000000000000000000000000000000000000000000000431');
    LInit(A, '7');
    LInit(B, '5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E');
    LInit(M, '8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3');
    LInit(Q, '8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3');
    LInit(Xp, '2');
    LInit(Yp, '8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8');
    LInit(Sec_K, '7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28');

    ii := 32;
    SetLength_BA(Digest, ii);
    StringToBinary('3534454132454236443134453437313943363345374143423445413631454230', @Digest[0], ii);

    Res := TElECGOSTSigner.Sign(Digest, P, A, B, M, Q, Xp, Yp, Sec_K);




    x0 := StrToInt('$5EC9');
    c := StrToInt('$7341');

    TElGOSTSigner.Generate_PQA(512, 0, x0, c, P, Q, A);
    sP := LToStr(P);
    sQ := LToStr(Q);
    sA := LToStr(A);
    TElGOSTSigner.Generate_Keys(P, Q, A, Sec_K, Pub_K);
    sQ := LToStr(Sec_K);
    sA := LToStr(Pub_K);

    ii := 32;
    SetLength_BA(Digest, ii);
    StringToBinary('3534454132454236443134453437313943363345374143423445413631454230', @Digest[0], ii);

    Res := TElGOSTSigner.Sign(Digest, P, Q, A, Sec_K);

    if  TElGOSTSigner.Verify(Digest, Res, P, Q, A, Pub_K) then
      WriteLn('OK')
    else
      WriteLn('Fail');

{
    x0 := StrToInt('$5EC9');
    c := StrToInt('$7341');
}
{
    x0 := StrToInt('$3DFC46F1');
    c := StrToInt('$D');
}
{
    x0 := StrToInt('$A565');
    c := StrToInt('$538B');
Procedure_B(16, x0, c, P, Q);
}
    x0 := StrToInt('$3DFC46F1');
    c := StrToInt('$D');
    Procedure_B(32, x0, c, P, Q);

    S := LToStr(P);
    S := LToStr(Q);
{
    LInit(P, 'EE8172AE8996608FB69359B89EB82A69854510E2977A4D63BC97322CE5DC3386EA0A12B343E9190F23177539845839786BB0C345D165976EF2195EC9B1C379E3');
    LInit(Q, '98915E7EC8265EDFCDA31E88F24809DDB064BDC7285DD50D7289F0AC6F49DD2D');

    Procedure_C(P, Q, A);
    S := LToStr(A);
}
  finally
    LDestroy(P);
    LDestroy(Q);
    LDestroy(A);
  end;

end;
 {$endif}
end.