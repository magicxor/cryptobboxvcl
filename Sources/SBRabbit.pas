(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBRabbit;

interface

uses
  SBTypes,
  SBUtils,
  SBConstants
  ,
  SysUtils
  ;

type
  UInt32 = LongWord;
type
  UInt64 = Int64;

type
  UInt32Array8 = array[0..7] of UInt32;

type
  Rabbit_Instance =  packed  record
    X, C, K: UInt32Array8;
    Carry: Byte;
  end;

  Rabbit_Context =  packed  record
    Rabbit, Rabbit_Master: Rabbit_Instance;
  end;

//procedure _Rabbit_CounterSystem(var R: Rabbit_Instance);
//procedure _Rabbit_NextState(var R: Rabbit_Instance);

procedure Rabbit_Init(var Context: Rabbit_Context; const Key: ByteArray); 
procedure Rabbit_IVInit(var Context: Rabbit_Context; const IV_Key: ByteArray); 
procedure Rabbit_Cipher(var Context: Rabbit_Context; const Src: ByteArray; var Dst: ByteArray);

implementation

const
  WORDSIZE: UInt64 = $100000000;
  WORDMASK: UInt64 = $FFFFFFFF;

procedure _Rabbit_CounterSystem(var R: Rabbit_Instance);
const
  A: array[0..7] of UInt32 =  ( 
    $4D34D34D, $D34D34D3,
    $34D34D34, $4D34D34D,
    $D34D34D3, $34D34D34,
    $4D34D34D, $D34D34D3 ) ;

var
  Temp: UInt64;
  j: byte;
begin

  for j := 0 to 7 do
  begin
    Temp := UInt64(A[j]) + UInt64(R.C[j]) + UInt64(R.Carry);
    if (Temp >= WORDSIZE) then
      R.Carry := 1
    else
      R.Carry := 0;
    R.C[j] := Temp and WORDMASK;
  end;
end;

procedure _Rabbit_NextState(var R: Rabbit_Instance);

function G_Function(U, V: UInt32): UInt32;
  var
    Sq: UInt64;
  begin
    Sq := (UInt64(U) + UInt64(V)) mod WORDSIZE;
    Sq := Sq * Sq;
    U := (Sq shr 32) and WORDMASK;
    V := Sq and WORDMASK;
    Result := V xor U;
  end;

  function rrl(X: UInt32; Shift: byte): UInt32;
  begin
    Result := (X shl Shift) or (X shr (32 - Shift));
  end;

var
  G: UInt32Array8;
  j: integer;
begin
  for j := 0 to 7 do
    G[j] := G_Function(R.X[j], R.C[j]);
  R.X[0] := (UInt64(G[0]) + UInt64(rrl(G[7], 16)) + UInt64(rrl(G[6], 16))) mod WORDSIZE;
  R.X[1] := (UInt64(G[1]) + UInt64(rrl(G[0], 8)) + UInt64(G[7])) mod WORDSIZE;
  R.X[2] := (UInt64(G[2]) + UInt64(rrl(G[1], 16)) + UInt64(rrl(G[0], 16))) mod WORDSIZE;
  R.X[3] := (UInt64(G[3]) + UInt64(rrl(G[2], 8)) + UInt64(G[1])) mod WORDSIZE;
  R.X[4] := (UInt64(G[4]) + UInt64(rrl(G[3], 16)) + UInt64(rrl(G[2], 16))) mod WORDSIZE;
  R.X[5] := (UInt64(G[5]) + UInt64(rrl(G[4], 8)) + UInt64(G[3])) mod WORDSIZE;
  R.X[6] := (UInt64(G[6]) + UInt64(rrl(G[5], 16)) + UInt64(rrl(G[4], 16))) mod WORDSIZE;
  R.X[7] := (UInt64(G[7]) + UInt64(rrl(G[6], 8)) + UInt64(G[5])) mod WORDSIZE;
end;

procedure Rabbit_Cipher(var Context: Rabbit_Context; const Src: ByteArray; var Dst: ByteArray);

  procedure Extract(const R: Rabbit_Instance; const Src: ByteArray; var Dst: ByteArray; Start: UInt32);
  begin
    Dst[Start] := Src[Start] xor (((R.X[0] and $FFFF) xor (R.X[5] shr 16)) and $FF);
    Dst[Start + 1] := Src[Start + 1] xor ((((R.X[0] and $FFFF) xor (R.X[5] shr 16)) shr 8) and $FF);

    Dst[Start + 2] := Src[Start + 2] xor (((R.X[0] shr 16) xor (R.X[3] and $FFFF)) and $FF);
    Dst[Start + 3] := Src[Start + 3] xor ((((R.X[0] shr 16) xor (R.X[3] and $FFFF)) shr 8) and $FF);

    Dst[Start + 4] := Src[Start + 4] xor (((R.X[2] and $FFFF) xor (R.X[7] shr 16)) and $FF);
    Dst[Start + 5] := Src[Start + 5] xor ((((R.X[2] and $FFFF) xor (R.X[7] shr 16)) shr 8) and $FF);

    Dst[Start + 6] := Src[Start + 6] xor (((R.X[2] shr 16) xor (R.X[5] and $FFFF)) and $FF);
    Dst[Start + 7] := Src[Start + 7] xor ((((R.X[2] shr 16) xor (R.X[5] and $FFFF)) shr 8) and $FF);

    Dst[Start + 8] := Src[Start + 8] xor (((R.X[4] and $FFFF) xor (R.X[1] shr 16)) and $FF);
    Dst[Start + 9] := Src[Start + 9] xor ((((R.X[4] and $FFFF) xor (R.X[1] shr 16)) shr 8) and $FF);

    Dst[Start + 10] := Src[Start + 10] xor (((R.X[4] shr 16) xor (R.X[7] and $FFFF)) and $FF);
    Dst[Start + 11] := Src[Start + 11] xor ((((R.X[4] shr 16) xor (R.X[7] and $FFFF)) shr 8) and $FF);

    Dst[Start + 12] := Src[Start + 12] xor (((R.X[6] and $FFFF) xor (R.X[3] shr 16)) and $FF);
    Dst[Start + 13] := Src[Start + 13] xor ((((R.X[6] and $FFFF) xor (R.X[3] shr 16)) shr 8) and $FF);

    Dst[Start + 14] := Src[Start + 14] xor (((R.X[6] shr 16) xor (R.X[1] and $FFFF)) and $FF);
    Dst[Start + 15] := Src[Start + 15] xor ((((R.X[6] shr 16) xor (R.X[1] and $FFFF)) shr 8) and $FF);
  end;

var
  Len: UInt32;
  i: integer;
begin
  if Length(Dst) <> Length(Src) then
  begin
    raise Exception.Create('Source and Destination data vectors must have the same size!');
  end;

  if (Length(Dst) mod 16) <> 0 then
  begin
    raise Exception.Create('Destination data vector must have length based on 16!');
  end;
  Len := Length(Dst);
  for i := 1 to (Len shr 4) do
  begin
    _Rabbit_CounterSystem(Context.Rabbit);
    _Rabbit_NextState(Context.Rabbit);
    Extract(Context.Rabbit, Src, Dst, (i - 1) shl 4);
  end;

end;

procedure Rabbit_IVInit(var Context: Rabbit_Context; const IV_Key: ByteArray);

  procedure KeyIVInit(var R: Rabbit_Instance; const IV: ByteArray);
  begin
    R.C[0] := UInt32(R.C[0] xor ((UInt32(IV[0]) or (UInt32(IV[1]) shl 8) or (UInt32(IV[2]) shl 16) or (UInt32(IV[3]) shl 24))));
    R.C[1] := UInt32(R.C[1] xor ((UInt32(IV[2]) or (UInt32(IV[3]) shl 8) or (UInt32(IV[6]) shl 16) or (UInt32(IV[7]) shl 24))));
    R.C[2] := UInt32(R.C[2] xor ((UInt32(IV[4]) or (UInt32(IV[5]) shl 8) or (UInt32(IV[6]) shl 16) or (UInt32(IV[7]) shl 24))));
    R.C[3] := UInt32(R.C[3] xor ((UInt32(IV[0]) or (UInt32(IV[1]) shl 8) or (UInt32(IV[4]) shl 16) or (UInt32(IV[5]) shl 24))));
    R.C[4] := UInt32(R.C[4] xor ((UInt32(IV[0]) or (UInt32(IV[1]) shl 8) or (UInt32(IV[2]) shl 16) or (UInt32(IV[3]) shl 24))));
    R.C[5] := UInt32(R.C[5] xor ((UInt32(IV[2]) or (UInt32(IV[3]) shl 8) or (UInt32(IV[6]) shl 16) or (UInt32(IV[7]) shl 24))));
    R.C[6] := UInt32(R.C[6] xor ((UInt32(IV[4]) or (UInt32(IV[5]) shl 8) or (UInt32(IV[6]) shl 16) or (UInt32(IV[7]) shl 24))));
    R.C[7] := UInt32(R.C[7] xor ((UInt32(IV[0]) or (UInt32(IV[1]) shl 8) or (UInt32(IV[4]) shl 16) or (UInt32(IV[5]) shl 24))));
  end;

var
  i: byte;
begin
  if (Length(IV_Key) <> 16) then
  begin
    raise Exception.Create('IV-Key must be 16-bytes!');
  end;

  for i := 0 to 7 do
  begin
    Context.Rabbit.X[i] := Context.Rabbit_Master.X[i];
    Context.Rabbit.C[i] := Context.Rabbit_Master.C[i];
  end;
  Context.Rabbit.Carry := Context.Rabbit_Master.Carry;
  KeyIVInit(Context.Rabbit, IV_Key);
  for i := 1 to 4 do
  begin
    _Rabbit_CounterSystem(Context.Rabbit);
    _Rabbit_NextState(Context.Rabbit);
  end;
end;

procedure Rabbit_Init(var Context: Rabbit_Context; const Key: ByteArray);

  procedure KeyInit(var R: Rabbit_Instance);
  var
    j: byte;
  begin
    for j := 0 to 7 do
      if (j mod 2) = 1 then
      begin
        R.X[j] := ((UInt32(R.K[(j + 5) mod 8]) shl 16) or UInt32(R.K[(j + 4) mod 8])) and $FFFFFFFF;
        R.C[j] := ((UInt32(R.K[j]) shl 16) or UInt32(R.K[(j + 1) mod 8])) and $FFFFFFFF;
      end
      else
      begin
        R.X[j] := ((UInt32(R.K[(j + 1) mod 8]) shl 16) or UInt32(R.K[j])) and $FFFFFFFF;
        R.C[j] := ((UInt32(R.K[(j + 4) mod 8]) shl 16) or UInt32(R.K[(j + 5) mod 8])) and $FFFFFFFF;
      end;
  end;

var
  i: byte;
begin
  if (Length(Key) <> 16) then
  begin
    raise Exception.Create('Key must be 16-bytes!');
  end;


  for i := 0 to 7 do
    Context.Rabbit.K[i] := (Word(Key[i shl 1 + 1]) shl 8) or Word(Key[i shl 1]);

  Context.Rabbit.Carry := 0;
  KeyInit(Context.Rabbit);

  for i := 1 to 4 do
  begin
    _Rabbit_CounterSystem(Context.Rabbit);
    _Rabbit_NextState(Context.Rabbit);
  end;
  for i := 0 to 7 do
    Context.Rabbit.C[i] := Context.Rabbit.C[i] xor Context.Rabbit.X[(i + 4) mod 8];
  for i := 0 to 7 do
  begin
    Context.Rabbit_Master.X[i] := Context.Rabbit.X[i];
    Context.Rabbit_Master.C[i] := Context.Rabbit.C[i];
  end;
  Context.Rabbit_Master.Carry := Context.Rabbit.Carry;
end;

end.

