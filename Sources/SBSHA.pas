(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBSHA;

interface

uses
  Classes,
  SysUtils,
  SBTypes,
  SBUtils;

type

  TSHA1Context =  packed   record
    Size: int64;//cardinal;
    Buffer: array  [0..63]  of byte;
    LChunk: array  [0..79]  of LongWord;
    BufSize: cardinal;
    A, B, C, D, E: longword;
  end;

procedure InitializeSHA1(out Context: TSHA1Context); 

function HashSHA1(const S: ByteArray): TMessageDigest160; overload;
procedure HashSHA1(var Context: TSHA1Context; Chunk: pointer; Size: cardinal); overload;
function HashSHA1(Buffer: pointer; Size: cardinal): TMessageDigest160; overload;
procedure InternalSHA1(Chunk: PLongWordArray; var A, B, C, D, E: longword);

function FinalizeSHA1(var Context: TSHA1Context): TMessageDigest160; 


implementation

{$ifdef ActiveX_registered}
uses
  SBClientBase;
 {$endif}


procedure ProcessBlockSHA1(Chunk: pointer; var Context: TSHA1Context);
var
  A, B, C, D, E, T: longword;
  I: integer;
begin
  A := Context.A;
  B := Context.B;
  C := Context.C;
  D := Context.D;
  E := Context.E;


  for I := 0 to 15 do
  begin
    Context.LChunk[I] :=
      (PByteArray(Chunk)[I shl 2] shl 24) xor (PByteArray(Chunk)[I shl 2 + 1] shl 16) xor
      (PByteArray(Chunk)[I shl 2 + 2] shl 8) xor (PByteArray(Chunk)[I shl 2 + 3]);
  end;
  for I := 16 to 79 do
  begin
    T := Context.LChunk[I - 3] xor Context.LChunk[I - 8] xor Context.LChunk[I - 14]
      xor Context.LChunk[I - 16];
    Context.LChunk[I] := (T shl 1) xor (T shr 31);
  end;

  for I := 0 to 19 do
  begin
    T := ((A shl 5) or (A shr 27)) + E + Context.LChunk[I];
    Inc(T, ((B and C) or (not B and D)) + $5A827999);
    E := D;
    D := C;
    C := (B shl 30) or (B shr 2);
    B := A;
    A := T;
  end;

  for I := 20 to 39 do
  begin
    T := ((A shl 5) or (A shr 27)) + E + Context.LChunk[I];
    Inc(T, (B xor C xor D) + $6ED9EBA1);
    E := D;
    D := C;
    C := (B shl 30) or (B shr 2);
    B := A;
    A := T;
  end;

  for I := 40 to 59 do
  begin
    T := ((A shl 5) or (A shr 27)) + E + Context.LChunk[I];
    Inc(T, ((B and C) or (B and D) or (C and D)) + $8F1BBCDC);
    E := D;
    D := C;
    C := (B shl 30) or (B shr 2);
    B := A;
    A := T;
  end;

  for I := 60 to 79 do
  begin
    T := ((A shl 5) or (A shr 27)) + E + Context.LChunk[I];
    Inc(T, (B xor C xor D) + $CA62C1D6);
    E := D;
    D := C;
    C := (B shl 30) or (B shr 2);
    B := A;
    A := T;
  end;

  Inc(Context.A, A);
  Inc(Context.B, B);
  Inc(Context.C, C);
  Inc(Context.D, D);
  Inc(Context.E, E);
end;

procedure InternalSHA1(Chunk: PLongWordArray; var A, B, C, D, E: longword);
var
  SA, SB, SC, SD, SE: longword;
  T: longword;
  I: integer;
begin
  SA := A; SB := B; SC := C; SD := D; SE := E;

  for I := 0 to 19 do
  begin
    T := ((A shl 5) or (A shr 27)) + E + Chunk[I];
    Inc(T, ((B and C) or (not B and D)) + $5A827999);
    E := D;
    D := C;
    C := (B shl 30) or (B shr 2);
    B := A;
    A := T;
  end;

  for I := 20 to 39 do
  begin
    T := ((A shl 5) or (A shr 27)) + E + Chunk[I];
    Inc(T, (B xor C xor D) + $6ED9EBA1);
    E := D;
    D := C;
    C := (B shl 30) or (B shr 2);
    B := A;
    A := T;
  end;

  for I := 40 to 59 do
  begin
    T := ((A shl 5) or (A shr 27)) + E + Chunk[I];
    Inc(T, ((B and C) or (B and D) or (C and D)) + $8F1BBCDC);
    E := D;
    D := C;
    C := (B shl 30) or (B shr 2);
    B := A;
    A := T;
  end;

  for I := 60 to 79 do
  begin
    T := ((A shl 5) or (A shr 27)) + E + Chunk[I];
    Inc(T, (B xor C xor D) + $CA62C1D6);
    E := D;
    D := C;
    C := (B shl 30) or (B shr 2);
    B := A;
    A := T;
  end;

  Inc(A, SA); Inc(B, SB); Inc(C, SC); Inc(D, SD); Inc(E, SE);
end;

function HashSHA1(const S: ByteArray): TMessageDigest160;
begin
  Result := HashSHA1(@S[0], Length(S));
end;

function HashSHA1(Buffer: pointer; Size: cardinal): TMessageDigest160; overload;
var
  Ctx : TSHA1Context;
begin
  InitializeSHA1(Ctx);
  HashSHA1(Ctx, Buffer, Size);
  Result := FinalizeSHA1(Ctx);
end;


(*

{$ifdef SB_VCL}
procedure BlockSHA1(Buf: Pointer; var Context: TSHA1Context);
{$else}
procedure BlockSHA1(const Buf: ByteArray; var Context: TSHA1Context);
{$endif}
var
  J: byte;
  Temp: LongWord;
  Chunk: array[0..79] of longword;
begin
  {$ifdef SB_VCL}
  SBMove(Buf^, Chunk[0], 64);
  {$else}
  SBMove(Buf, 0, Chunk, 0, 64);
  {$endif}
  for J := 0 to 15 do
  begin
    Chunk[J] := ((Chunk[J] and $ff) shl 24) or ((Chunk[J] and $ff00) shl 8) or
      ((Chunk[J] and $ff0000) shr 8) or ((Chunk[J] and $ff000000) shr 24);
  end;
  for J := 16 to 79 do
  begin
    Temp := Chunk[J - 3] xor Chunk[J - 8] xor Chunk[J - 14] xor Chunk[J - 16];
    Chunk[J] := (Temp shl 1) or (Temp shr 31);
  end;
  InternalSHA1({$ifdef SB_VCL}@{$endif}Chunk, Context.A, Context.B, Context.C, Context.D, Context.E);
end;
*)

procedure InitializeSHA1(out Context: TSHA1Context);
begin
  Context.Size := 0;
  FillChar(Context.Buffer, SizeOf(Context.Buffer), 0);
  Context.BufSize := 0;
  Context.A := {$ifdef ActiveX_registered}Constant1 {$else}$67452301 {$endif};
  Context.B := $EFCDAB89;
  Context.C := $98BADCFE;
  Context.D := $10325476;
  Context.E := {$ifdef ActiveX_registered}Constant2 {$else}$C3D2E1F0 {$endif};
end;


procedure HashSHA1(var Context: TSHA1Context; Chunk: pointer; Size: cardinal); overload;
var
  Left, I: cardinal;
begin
  if Size = 0 then
    Exit;

  Inc(Context.Size, Size);
  if Context.BufSize > 0 then
  begin
    Left := 64 - Context.BufSize;
    if Left > Size then
    begin
      SBMove(Chunk^, Context.Buffer[Context.BufSize], Size);
      Inc(Context.BufSize, Size);
      Exit;
    end
    else
    begin
      SBMove(Chunk^, Context.Buffer[Context.BufSize], Left);

      {$ifdef D_16_UP}
      Chunk := Pointer(PtrUInt(Chunk) + Left);
       {$else}
      Inc(PtrUInt(Chunk), Left);
       {$endif}
      Dec(Size, Left);
      ProcessBlockSHA1(Pointer(@Context.Buffer), Context);
      Context.BufSize := 0;
    end;
  end;
  I := 0;
  while Size >= 64 do
  begin
    ProcessBlockSHA1(Pointer(PtrUInt(Chunk) + I), Context);
    Inc(I, 64);
    Dec(Size, 64);
  end;
  if Size > 0 then
  begin
    SBMove(Pointer(PtrUInt(Chunk) + I)^, Context.Buffer[0], Size);
    Context.BufSize := Size;
  end;
end;


function FinalizeSHA1(var Context: TSHA1Context): TMessageDigest160;
var
  Tail: array [0..127]  of byte;
  ToAdd, ToDo: cardinal;
  Count: int64;
  Temp: LongWord;
begin
  
  FillChar(Tail[0], SizeOf(Tail), 0);
  Count := Context.Size shl 3;

  if 56 - Integer(Context.BufSize) <= 0 then
    ToAdd := 120 - Context.BufSize
  else
    ToAdd := 56 - Context.BufSize;

  if Context.BufSize > 0 then
  begin
    SBMove(Context.Buffer[0], Tail[0], Context.BufSize);
  end;

  Temp := Count shr 32;
  Tail[ToAdd + Context.BufSize] := Temp shr 24;
  Tail[ToAdd + Context.BufSize + 1] := (Temp shr 16) and $ff;
  Tail[ToAdd + Context.BufSize + 2] := (Temp shr 8) and $ff;
  Tail[ToAdd + Context.BufSize + 3] := Temp and $ff;

  Temp := LongWord(Count);
  Tail[ToAdd + Context.BufSize + 4] := Temp shr 24;
  Tail[ToAdd + Context.BufSize + 5] := (Temp shr 16) and $ff;
  Tail[ToAdd + Context.BufSize + 6] := (Temp shr 8) and $ff;
  Tail[ToAdd + Context.BufSize + 7] := Temp and $ff;

  Tail[Context.BufSize] := $80;

  ToDo := Context.BufSize + ToAdd + 8;

  ProcessBlockSHA1(@Tail[0], Context);
  if ToDo > 64 then
    ProcessBlockSHA1(@Tail[64], Context);

  // finalizing
  Result.A := ((Context.A and $ff) shl 24) or ((Context.A and $ff00) shl 8) or
    ((Context.A and $ff0000) shr 8) or ((Context.A and $ff000000) shr 24);
  Result.B := ((Context.B and $ff) shl 24) or ((Context.B and $ff00) shl 8) or
    ((Context.B and $ff0000) shr 8) or ((Context.B and $ff000000) shr 24);
  Result.C := ((Context.C and $ff) shl 24) or ((Context.C and $ff00) shl 8) or
    ((Context.C and $ff0000) shr 8) or ((Context.C and $ff000000) shr 24);
  Result.D := ((Context.D and $ff) shl 24) or ((Context.D and $ff00) shl 8) or
    ((Context.D and $ff0000) shr 8) or ((Context.D and $ff000000) shr 24);
  Result.E := ((Context.E and $ff) shl 24) or ((Context.E and $ff00) shl 8) or
    ((Context.E and $ff0000) shr 8) or ((Context.E and $ff000000) shr 24);
end;

end.
