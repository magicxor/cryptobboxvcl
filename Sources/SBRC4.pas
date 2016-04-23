(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBRC4;

interface

uses
  SysUtils,
  SBTypes,
  SBConstants,
  SBUtils;

type

  TRC4Key =  array of byte;
  TRC4ExpandedKey = array[0..255] of byte;

  TRC4Context =  record
    L, K: Byte;
    TK: array  [0..255]  of byte;
  end;

// Key expansion routine

//procedure ExpandKey(const Key: TRC4Key; out ExpandedKey: TRC4ExpandedKey); {$ifdef SB_NET}public;{$endif}

// Chunks processing routines
procedure Initialize(var Context: TRC4Context; const Key: TRC4Key); 


function Encrypt(var Context: TRC4Context; Buf: pointer; OutBuf: Pointer;
  Size: cardinal): boolean; overload;
function Decrypt(var Context: TRC4Context; Buf: pointer; OutBuf: Pointer;
  Size: cardinal): boolean; overload;

function NFinalize(var Context: TRC4Context): boolean; 

// Memory processing routines
procedure Encrypt(InBuffer: pointer; const Size: integer;
  const ExpandedKey: TRC4ExpandedKey; OutBuffer: pointer); overload;
procedure Decrypt(InBuffer: pointer; const Size: integer;
  const ExpandedKey: TRC4ExpandedKey; OutBuffer: pointer); overload;

implementation



// Key expansion routine

procedure ExpandKey(const Key: TRC4Key; out ExpandedKey: TRC4ExpandedKey);
var
  I, J, KeySize: integer;
  TK: array[0..255] of byte;
  B: byte;
begin
  try
  KeySize := Length(Key);
  if (KeySize <= 0) or (KeySize > 32) then
    raise EElEncryptionError.CreateFmt(SInvalidKeySize, [KeySize shl 3]);

  I := 0;
  repeat
    ExpandedKey[I] := I;
    TK[I] := Key[I mod KeySize];
    ExpandedKey[I + 1] := I + 1;
    TK[I + 1] := Key[(I + 1) mod KeySize];
    ExpandedKey[I + 2] := I + 2;
    TK[I + 2] := Key[(I + 2) mod KeySize];
    ExpandedKey[I + 3] := I + 3;
    TK[I + 3] := Key[(I + 3) mod KeySize];
    ExpandedKey[I + 4] := I + 4;
    TK[I + 4] := Key[(I + 4) mod KeySize];
    ExpandedKey[I + 5] := I + 5;
    TK[I + 5] := Key[(I + 5) mod KeySize];
    ExpandedKey[I + 6] := I + 6;
    TK[I + 6] := Key[(I + 6) mod KeySize];
    ExpandedKey[I + 7] := I + 7;
    TK[I + 7] := Key[(I + 7) mod KeySize];
    Inc(I, 8);
  until I > 255;  
  except
    raise;
  end;
  I := 0;
  J := 0;
  repeat
    Inc(J, ExpandedKey[I] + TK[I]);
    J := Byte(J);
    B := ExpandedKey[I];
    ExpandedKey[I] := ExpandedKey[J];
    ExpandedKey[J] := B;
    Inc(J, ExpandedKey[I + 1] + TK[I + 1]);
    J := Byte(J);
    B := ExpandedKey[I + 1];
    ExpandedKey[I + 1] := ExpandedKey[J];
    ExpandedKey[J] := B;
    Inc(J, ExpandedKey[I + 2] + TK[I + 2]);
    J := Byte(J);
    B := ExpandedKey[I + 2];
    ExpandedKey[I + 2] := ExpandedKey[J];
    ExpandedKey[J] := B;
    Inc(J, ExpandedKey[I + 3] + TK[I + 3]);
    J := Byte(J);
    B := ExpandedKey[I + 3];
    ExpandedKey[I + 3] := ExpandedKey[J];
    ExpandedKey[J] := B;
    Inc(J, ExpandedKey[I + 4] + TK[I + 4]);
    J := Byte(J);
    B := ExpandedKey[I + 4];
    ExpandedKey[I + 4] := ExpandedKey[J];
    ExpandedKey[J] := B;
    Inc(J, ExpandedKey[I + 5] + TK[I + 5]);
    J := Byte(J);
    B := ExpandedKey[I + 5];
    ExpandedKey[I + 5] := ExpandedKey[J];
    ExpandedKey[J] := B;
    Inc(J, ExpandedKey[I + 6] + TK[I + 6]);
    J := Byte(J);
    B := ExpandedKey[I + 6];
    ExpandedKey[I + 6] := ExpandedKey[J];
    ExpandedKey[J] := B;
    Inc(J, ExpandedKey[I + 7] + TK[I + 7]);
    J := Byte(J);
    B := ExpandedKey[I + 7];
    ExpandedKey[I + 7] := ExpandedKey[J];
    ExpandedKey[J] := B;
    Inc(I, 8);
  until I > 255;
end;

procedure Initialize(var Context: TRC4Context; const Key: TRC4Key);
var
  ExKey: TRC4ExpandedKey;
begin
  ExpandKey(Key, ExKey);
  Context.L := 0;
  Context.K := 0;
  SBMove(ExKey, Context.TK, SizeOf(Context.TK));
end;

function Encrypt(var Context: TRC4Context; Buf: pointer; OutBuf: Pointer; Size:
  cardinal): boolean; overload;
var
  I: integer;
  K, L, T: byte;
begin

  K := Context.K;
  L := Context.L;

  for I := 0 to Size - 1 do
  begin
    Inc(K);
    T := Context.TK[K];
    Inc(L, T);
    Context.TK[K] := Context.TK[L];
    Context.TK[L] := T;
    Inc(T, Context.TK[K]);
    PByteArray(OutBuf)[I] := PByteArray(Buf)[I] xor Context.TK[T];
  end;

  Context.L := L;
  Context.K := K;
  Result := true;
end;

function Decrypt(var Context: TRC4Context; Buf: pointer; OutBuf: Pointer; Size:
  cardinal ): boolean; overload;
var
  I: integer;
  K, L, T: byte;
begin

  K := Context.K;
  L := Context.L;

  for I := 0 to Size - 1 do
  begin
    Inc(K);
    T := Context.TK[K];
    Inc(L, T);
    Context.TK[K] := Context.TK[L];
    Context.TK[L] := T;
    Inc(T, Context.TK[K]);
    PByteArray(OutBuf)[I] := PByteArray(Buf)[I] xor Context.TK[T];
  end;

  Context.L := L;
  Context.K := K;

  Result := true;
end;

function NFinalize(var Context: TRC4Context): boolean;
begin
  Result := true;
end;

// Memory processing routines

procedure Encrypt(InBuffer: pointer; const Size: integer;
  const ExpandedKey: TRC4ExpandedKey; OutBuffer: pointer);
var
  I: integer;
  K, L, T: byte;
  TK: array[0..255] of byte;
begin
  SBMove(ExpandedKey, TK, SizeOf(TK));
  K := 0;
  L := 0;
  for I := 0 to Size - 1 do
  begin
    Inc(K);
    T := TK[K];
    Inc(L, T);
    TK[K] := TK[L];
    TK[L] := T;
    Inc(T, TK[K]);
    PByteArray(OutBuffer)[I] := PByteArray(InBuffer)[I] xor TK[T];
  end;
end;

procedure Decrypt(InBuffer: pointer; const Size: integer;
  const ExpandedKey: TRC4ExpandedKey; OutBuffer: pointer);
var
  I: integer;
  K, L, T: byte;
  TK: array[0..255] of byte;
begin
  SBMove(ExpandedKey, TK, SizeOf(TK));
  K := 0;
  L := 0;
  for I := 0 to Size - 1 do
  begin
    Inc(K);
    T := TK[K];
    Inc(L, T);
    TK[K] := TK[L];
    TK[L] := T;
    Inc(T, TK[K]);
    PByteArray(OutBuffer)[I] := PByteArray(InBuffer)[I] xor TK[T];
  end;
end;


end.
