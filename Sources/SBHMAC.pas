
(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBHMAC;

interface

uses
  Classes,
  SysUtils, 
  SBTypes,
  SBUtils,
  SBSHA2,
  SBConstants
  ;

type

  TMACMD5Context =  packed   record
    NKey: array  [0..63]  of byte;
    iKey: array  [0..63]  of byte;
    oKey: array  [0..79]  of byte;
    Size: cardinal;
    Buffer: array  [0..63]  of byte;
    BufSize: cardinal;
    A, B, C, D: longword;
  end;

  TMACSHA1Context =  packed   record
    NKey: array  [0..63]  of byte;
    iKey: array  [0..63]  of byte;
    oKey: array  [0..83]  of byte;
    Size: cardinal;
    Buffer: array  [0..63]  of byte;
    BufSize: cardinal;
    A, B, C, D, E: longword;
  end;

  TMACSHA256Context =  packed   record
    oKey: array  [0..63]  of byte;
    Ctx : TSHA256Context;
  end;

  TMACSHA512Context =  packed   record
    oKey: array  [0..127]  of byte;
    Ctx : TSHA512Context;
  end;

  TMACSHA224Context = TMACSHA256Context;
  TMACSHA384Context = TMACSHA512Context;             

// HashMACMD5 functions
procedure InitializeMACMD5(var Context: TMACMD5Context; const Key: ByteArray); 
function FinalizeMACMD5(var Context: TMACMD5Context): TMessageDigest128; 
function HashMACMD5(const S: ByteArray; const Key: ByteArray): TMessageDigest128; overload;
function HashMACMD5(Stream: TStream; const Key: ByteArray; Count: cardinal = 0): TMessageDigest128; overload;
function HashMACMD5(Buffer: pointer; Size: cardinal; const Key: ByteArray): TMessageDigest128; overload;
procedure HashMACMD5(var Context: TMACMD5Context; Chunk: pointer; Size: cardinal); overload;

// HashMACSHA1 functions
procedure InitializeMACSHA1(var Context: TMACSHA1Context; const Key: ByteArray); 
function FinalizeMACSHA1(var Context: TMACSHA1Context): TMessageDigest160; 
function HashMACSHA1(Stream: TStream; const Key: ByteArray; Count: cardinal = 0): TMessageDigest160; overload;
function HashMACSHA1(Buffer: pointer; Size: cardinal; const Key: ByteArray): TMessageDigest160; overload;
procedure HashMACSHA1(var Context: TMACSHA1Context; Chunk: pointer; Size: cardinal); overload;
function HashMACSHA1(const S: ByteArray; const Key: ByteArray): TMessageDigest160; overload;

// HashMACSHA256 functions
procedure InitializeMACSHA256(var Context: TMACSHA256Context; const Key: ByteArray); 
function FinalizeMACSHA256(var Context: TMACSHA256Context): TMessageDigest256; 
procedure HashMACSHA256(var Context: TMACSHA256Context; Chunk: pointer; Size: integer);  overload; 
function HashMACSHA256(const S : ByteArray; const Key : ByteArray) : TMessageDigest256;  overload; 

// HashMACSHA512 functions
procedure InitializeMACSHA512(var Context: TMACSHA512Context; const Key: ByteArray); 
function FinalizeMACSHA512(var Context: TMACSHA512Context): TMessageDigest512; 
procedure HashMACSHA512(var Context: TMACSHA512Context; Chunk: pointer; Size: integer);  overload; 
function HashMACSHA512(const S : ByteArray; const Key : ByteArray): TMessageDigest512;  overload; 

// HashMACSHA224 functions
procedure InitializeMACSHA224(var Context: TMACSHA224Context; const Key: ByteArray); 
function FinalizeMACSHA224(var Context: TMACSHA224Context): TMessageDigest224; 
procedure HashMACSHA224(var Context: TMACSHA224Context; Chunk: pointer; Size: integer);  overload; 
function HashMACSHA224(const S : ByteArray; const Key : ByteArray): TMessageDigest224;  overload; 

// HashMACSHA512 functions
procedure InitializeMACSHA384(var Context: TMACSHA384Context; const Key: ByteArray); 
function FinalizeMACSHA384(var Context: TMACSHA384Context): TMessageDigest384; 
procedure HashMACSHA384(var Context: TMACSHA384Context; Chunk: pointer; Size: integer);  overload; 
function HashMACSHA384(const S : ByteArray; const Key : ByteArray): TMessageDigest384;  overload; 

implementation

uses
  SBMD,
  SBSHA;


////////////////////////////////////////////////////////////////////////////////
// HashMACMD5 functions

function HashMACMD5(const S: ByteArray; const Key: ByteArray): TMessageDigest128;
begin
  Result := HashMACMD5(@S[0], Length(S), Key);
end;

function HashMACMD5(Buffer: pointer; Size: cardinal; const Key: ByteArray): TMessageDigest128;
var
  Addon: array [0..127]  of byte;
  NKey, iKey: array[0..63] of byte;
  oKey: array [0..79]  of byte;
  Count64: int64;
  T, I, ToAdd: cardinal;
  A, B, C, D: longword;
  Chunk: PLongWordArray;
begin
  // normalizing the key
  FillChar(NKey, SizeOf(NKey), 0);
  if Length(Key) > 64 then
  begin
    Result := HashMD5(Key);
    SBMove(Result, NKey, SizeOf(Result));
  end
  else
    SBMove(Key[0], NKey, Length(Key));

  // creating the inner and outer keys
  for I := Low(Nkey) to High(NKey) do
  begin
    iKey[I] := NKey[I] xor $36;
    oKey[I] := NKey[I] xor $5C;
  end;
  // intializing
  A := $67452301; B := $EFCDAB89; C := $98BADCFE; D := $10325476;
  Count64 := (Size + SizeOf(iKey)) shl 3;
  FillChar(Addon, SizeOf(Addon), 0);
  // processing
  I := 0;
  T := Size mod 64;
  if 56 - Integer(T) <= 0 then
    ToAdd := 120 - T
  else
    ToAdd := 56 - T;
  Addon[T] := $80;

  SBMove(Pointer(PtrUInt(Buffer) + Size - T)^, Addon[0], T);
  PInt64(@Addon[ToAdd + T])^ := Count64;


  repeat
    // transforming
    if I = 0 then
      Chunk := @iKey[0]
    else
    if I <= Size then
      Chunk := Pointer(PtrUInt(Buffer) + I - 64)
    else
    if I <= Size + 64 then
      Chunk := @Addon[0]
    else
      Chunk := @Addon[64];
    InternalMD5(Chunk, A, B, C, D);
    Inc(I, 64);
  until I = Size + ToAdd + 72;
  PLongWord(@oKey[64])^ := A; PLongWord(@oKey[68])^ := B;
  PLongWord(@oKey[72])^ := C; PLongWord(@oKey[76])^ := D;
  Result := HashMD5(@oKey[0], SizeOf(oKey));
end;

procedure InitializeMACMD5(var Context: TMACMD5Context; const Key: ByteArray);
var
  Res: TMessageDigest128;
  I: cardinal;
begin
  Context.Size := 0;

  FillChar(Context.Buffer, SizeOf(Context.Buffer), 0);

  Context.BufSize := 0;
  FillChar(Context.NKey, SizeOf(Context.NKey), 0);

  if Length(Key) > 64 then
  begin
    Res := HashMD5(Key);
    SBMove(Res, Context.NKey, SizeOf(Res));
  end
  else
    SBMove(Key[0], Context.NKey, Length(Key));

  // creating the inner and outer keys
  for I := Low(Context.Nkey) to High(Context.NKey) do
  begin
    Context.iKey[I] := Context.NKey[I] xor $36;
    Context.oKey[I] := Context.NKey[I] xor $5C;
  end;
  // intializing
  Context.A := $67452301; Context.B := $EFCDAB89;
  Context.C := $98BADCFE; Context.D := $10325476;

  InternalMD5(@Context.iKey[0], Context.A, Context.B, Context.C, Context.D);
end;

procedure HashMACMD5(var Context: TMACMD5Context; Chunk: pointer; Size: cardinal);
var
  Left, I: cardinal;
begin
  if Size = 0 then
    exit;

  Inc(Context.Size, Size);

  if Context.BufSize > 0 then
  begin
    Left := 64 - Context.BufSize;
    if Left > Size then
    begin
      SBMove(Chunk^, Context.Buffer[Context.BufSize], Size);
      Inc(Context.BufSize, Size);
      exit;
    end
    else
    begin
      SBMove(Chunk^, Context.Buffer[Context.BufSize], Left);
      Inc(PtrUInt(Chunk), Left);
      Dec(Size, Left);
      InternalMD5(Pointer(@Context.Buffer), Context.A, Context.B, Context.C, Context.D);
      Context.BufSize := 0;
    end;
  end;
  I := 0;
  while Size >= 64 do
  begin
    InternalMD5(Pointer(PtrUInt(Chunk) + I), Context.A, Context.B, Context.C, Context.D);
    Inc(I, 64);
    Dec(Size, 64);
  end;
  if Size > 0 then
  begin
    SBMove(Pointer(PtrUInt(Chunk) + I)^, Context.Buffer[0], Size);
    Context.BufSize := Size;
  end;
end;


function FinalizeMACMD5(var Context: TMACMD5Context): TMessageDigest128;
var
  Tail: array[0..127] of byte;
  ToAdd, ToDo: cardinal;
  Count64: int64;
begin
  FillChar(Tail[0], SizeOf(Tail), 0);
  Count64 := (Context.Size + SizeOf(Context.iKey)) shl 3 {+64};
  if 56 - Integer(Context.BufSize) <= 0 then
    ToAdd := 120 - Context.BufSize
  else
    ToAdd := 56 - Context.BufSize;
  if Context.BufSize > 0 then
    SBMove(Context.Buffer[0], Tail[0], Context.BufSize);
  Tail[Context.BufSize] := $80;

  ToDo := Context.BufSize + ToAdd;

  PLongWord(@Tail[ToDo])^ := PLongWord(@Count64)^;
  Inc(ToDo, 4);
  PLongWord(@Tail[ToDo])^ := PLongWord(PtrUInt(@Count64) + 4)^;
  Inc(ToDo, 4);

  InternalMD5(@Tail[0], Context.A, Context.B, Context.C, Context.D);
  if ToDo > 64 then
    InternalMD5(@Tail[64], Context.A, Context.B, Context.C, Context.D);

  PLongWord(@Context.oKey[64])^ := Context.A;
  PLongWord(@Context.oKey[68])^ := Context.B;
  PLongWord(@Context.oKey[72])^ := Context.C;
  PLongWord(@Context.oKey[76])^ := Context.D;
  Result := HashMD5(@Context.oKey[0], SizeOf(Context.oKey));
end;

function HashMACMD5(Stream: TStream; const Key: ByteArray; Count: cardinal): TMessageDigest128;
var
  Buffer: array[0..4159] of byte;
  NKey, iKey: array[0..63] of byte;
  oKey: array[0..79] of byte;
  I, Read: integer;
  Count64: int64;
  Padded, Done: boolean;
  A, B, C, D: longword;
begin
  if Count = 0 then
  begin
    Stream.Position := 0;
    Count := Stream.Size;
  end
  else
    Count := Min(Cardinal(Stream.Size - Stream.Position), Count);

  // normalizing the key
  FillChar(NKey, SizeOf(NKey), 0);
  if Length(Key) > 64 then
  begin
    Result := HashMD5(Key);
    SBMove(Result, NKey, SizeOf(Result));
  end
  else
    SBMove(Key[0], NKey, Length(Key));

  // creating the inner and outer keys
  for I := Low(Nkey) to High(NKey) do
  begin
    iKey[I] := NKey[I] xor $36;
    oKey[I] := NKey[I] xor $5C;
  end;
  // intializing
  A := $67452301; B := $EFCDAB89; C := $98BADCFE; D := $10325476;
  Done := False;
  Padded := False;
  Count64 := Count + SizeOf(iKey);
  // processing
  repeat
    if not Padded then
    begin
      SBMove(iKey, Buffer, SizeOf(iKey));
      Read := Min(4096 - SizeOf(iKey), Cardinal(Count));

      Stream.ReadBuffer(Buffer[SizeOf(iKey)], Read);
      Dec(Count, Read);
      Inc(Read, SizeOf(iKey));
      Padded := True;
    end
    else
    begin
      Read := Min(4096, Count);
      Stream.ReadBuffer(Buffer, Read);
      Dec(Count, Read);
    end;
    if Read < 4096 then
    begin
      // the end of stream is reached
      Buffer[Read] := $80;
      Inc(Read);
      while (Read mod 64) <> 56 do
      begin
        Buffer[Read] := 0;
        Inc(Read);
      end;
      Count64 := Count64 shl 3;
      PInt64(@Buffer[Read])^ := Count64;
      Inc(Read, 8);
      Done := True;
    end;
    I := 0;
    repeat
      // transforming
      InternalMD5(@Buffer[I], A, B, C, D);
      Inc(I, 64);
    until I = Read;
  until Done;
  PLongWord(@oKey[64])^ := A; PLongWord(@oKey[68])^ := B;
  PLongWord(@oKey[72])^ := C; PLongWord(@oKey[76])^ := D;
  Result := HashMD5(@oKey[0], SizeOf(oKey));
end;

////////////////////////////////////////////////////////////////////////////////
// HashMACSHA1 functions

function HashMACSHA1(const S: ByteArray; const Key: ByteArray): TMessageDigest160;
begin
  Result := HashMACSHA1(@S[0], Length(S), Key);
end;

function HashMACSHA1(Buffer: pointer; Size: cardinal; const Key: ByteArray): TMessageDigest160;
var
  Addon: array[0..127] of byte;
  Chunk: array [0..79]  of longword;
  NKey, iKey: array[0..63] of byte;
  oKey: array [0..83]  of byte;
  T, I, J, ToAdd: cardinal;
  A, B, C, D, E: longword;
  Temp: longword;
  Count: int64;
  SrcP: PByteArray;
  DstP: PByteArray;
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  FillChar(Addon, SizeOf(Addon), 0);
  FillChar(NKey, SizeOf(NKey), 0);
  // normalizing the key
  if Length(Key) > 64 then
  begin
    Result := HashSHA1(Key);
    SBMove(Result, NKey, SizeOf(Result));
  end
  else
    SBMove(PAnsiChar(Key)^, NKey, Length(Key));

  // creating the inner and outer keys
  for I := Low(NKey) to High(NKey) do
  begin
    iKey[I] := NKey[I] xor $36;
    oKey[I] := NKey[I] xor $5C;
  end;
  // intializing
  A := $67452301; B := $EFCDAB89; C := $98BADCFE;
  D := $10325476; E := $C3D2E1F0;
  Count := (Size + SizeOf(iKey)) shl 3;
  // padding
  T := Size mod 64;
  if 56 - Integer(T) <= 0 then
    ToAdd := 120 - T
  else
    ToAdd := 56 - T;
  Addon[T] := $80;
  SBMove(Pointer(PtrUInt(Buffer) + Size - T)^, Addon[0], T);

  Temp := LongWord(Count shr 32);
  SrcP := @Temp;
  for j := 0 to 3 do
    Addon[ToAdd + T + j] := SrcP[3 - j];

  Temp := LongWord(Count);
  for j := 0 to 3 do
    Addon[ToAdd + T + 4 + j] := SrcP[3 - j];

  I := 0;
  repeat
    if I = 0 then
      SBMove(iKey[0], Chunk[0], 64)
    else
    if I <= Size then
      SBMove(Pointer(PtrUInt(Buffer) + I - 64)^, Chunk[0], 64)
    else
    if I <= Size + 64 then
      SBMove(Addon[0], Chunk[0], 64)
    else
      SBMove(Addon[64], Chunk[0], 64);

    // changing byte-order
    for J := 0 to 15 do
    begin
      Temp := Chunk[J];
      Chunk[J] := LongWord(SrcP[0] shl 24) or LongWord(SrcP[1] shl 16) or
                  LongWord(SrcP[2] shl 8) or LongWord(SrcP[3]);
    end;
    for J := 16 to 79 do
    begin
      Temp := Chunk[J - 3] xor Chunk[J - 8] xor Chunk[J - 14] xor Chunk[J - 16];
      Chunk[J] := (Temp shl 1) or (Temp shr 31);
    end;
    InternalSHA1(@Chunk, A, B, C, D, E);
    Inc(I, 64);
  until I = Size + ToAdd + 72;
  // finalizing

  SrcP := @A; DstP := @oKey[64];
  DstP[0] := SrcP[3];  DstP[1] := SrcP[2];
  DstP[2] := SrcP[1];  DstP[3] := SrcP[0];

  SrcP := @B;
  Inc(PtrUInt(DstP), 4);
  DstP[0] := SrcP[3]; DstP[1] := SrcP[2];
  DstP[2] := SrcP[1]; DstP[3] := SrcP[0];

  SrcP := @C;
  Inc(PtrUInt(DstP), 4);
  DstP[0] := SrcP[3]; DstP[1] := SrcP[2];
  DstP[2] := SrcP[1]; DstP[3] := SrcP[0];

  SrcP := @D; Inc(PtrUInt(DstP), 4);
  DstP[0] := SrcP[3]; DstP[1] := SrcP[2];
  DstP[2] := SrcP[1]; DstP[3] := SrcP[0];

  SrcP := @E; Inc(PtrUInt(DstP), 4);
  DstP[0] := SrcP[3]; DstP[1] := SrcP[2];
  DstP[2] := SrcP[1]; DstP[3] := SrcP[0];

  Result := HashSHA1(@oKey[0], SizeOf(oKey));
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

procedure BlockMACSHA1(Buf: Pointer; var Context: TMACSHA1Context);
var
  SrcP: PByteArray;
  J: Byte;
  Temp: LongWord;
  Chunk: array [0..79]  of longword;
begin

  SBMove(Buf^, Chunk[0], 64);

  SrcP := @Temp;
  for J := 0 to 15 do
  begin
    Temp := Chunk[J];
    Chunk[J] := LongWord(SrcP[0] shl 24) or LongWord(SrcP[1] shl 16) or
                LongWord(SrcP[2] shl 8) or LongWord(SrcP[3]);
  end;

  for J := 16 to 79 do
  begin
    Temp := Chunk[J - 3] xor Chunk[J - 8] xor Chunk[J - 14] xor Chunk[J - 16];
    Chunk[J] := (Temp shl 1) or (Temp shr 31);
  end;

  InternalSHA1( @ Chunk, Context.A, Context.B, Context.C, Context.D, Context.E);
end;

procedure InitializeMACSHA1(var Context: TMACSHA1Context; const Key : ByteArray);
var
  Res: TMessageDigest160;
  I: cardinal;
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  Context.Size := 0;
  FillChar(Context.Buffer, SizeOf(Context.Buffer), 0);
  FillChar(Context.NKey, SizeOf(Context.NKey), 0);


  Context.BufSize := 0;
  if Length(Key) > 64 then
  begin
    Res := HashSHA1(Key);
    SBMove(Res, Context.NKey, SizeOf(Res));
  end
  else
    SBMove(PAnsiChar(Key)^, Context.NKey, Length(Key));

  // creating the inner and outer keys
  for I := Low(Context.NKey) to High(Context.NKey) do
  begin
    Context.iKey[I] := Context.NKey[I] xor $36;
    Context.oKey[I] := Context.NKey[I] xor $5C;
  end;
  // intializing
  Context.A := $67452301; Context.B := $EFCDAB89; Context.C := $98BADCFE;
  Context.D := $10325476; Context.E := $C3D2E1F0;

  BlockMACSHA1(@Context.iKey[0], Context);
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

procedure HashMACSHA1(var Context: TMACSHA1Context; Chunk: pointer; Size: cardinal);  overload;  
var
  Left, I: cardinal;
begin
  if Size = 0 then
    exit;
  Inc(Context.Size, Size);
  if Context.BufSize > 0 then
  begin
    Left := 64 - Context.BufSize;
    if Left > Size then
    begin
      SBMove(Chunk^, Context.Buffer[Context.BufSize], Size);
      Inc(Context.BufSize, Size);
      exit;
    end
    else
    begin
      SBMove(Chunk^, Context.Buffer[Context.BufSize], Left);
      Inc(PtrUInt(Chunk), Left);
      Dec(Size, Left);
      BlockMACSHA1(Pointer(@Context.Buffer), Context);
      Context.BufSize := 0;
    end;
  end;
  I := 0;
  while Size >= 64 do
  begin
    BlockMACSHA1(Pointer(PtrUInt(Chunk) + I), Context);
    Inc(I, 64);
    Dec(Size, 64);
  end;
  if Size > 0 then
  begin
    SBMove(Pointer(PtrUInt(Chunk) + I)^, Context.Buffer[0], Size);
    Context.BufSize := Size;
  end;
end;

function FinalizeMACSHA1(var Context: TMACSHA1Context): TMessageDigest160;
var
  SrcP: PByteArray;
  j : cardinal;
  DstP: PByteArray;
  Tail: array[0..127] of byte;
  ToAdd, ToDo: cardinal;
  Count: int64;
  Temp: longword;
begin
  FillChar(Tail[0], SizeOf(Tail), 0);
  Count := (Context.Size + SizeOf(Context.iKey)) shl 3; //Context.Size * 8;

  if 56 - Integer(Context.BufSize) <= 0 then
    ToAdd := 120 - Context.BufSize
  else
    ToAdd := 56 - Context.BufSize;

  if Context.BufSize > 0 then
  begin
    SBMove(Context.Buffer[0], Tail[0], Context.BufSize);
  end;

  Temp := Count shr 32;

  SrcP := @Temp;
  for j := 0 to 3 do
    Tail[ToAdd + Context.BufSize + j] := SrcP[3 - j];

  Temp := LongWord(Count);
  for j := 0 to 3 do
    Tail[ToAdd + Context.BufSize + 4 + j] := SrcP[3 - j];

  Tail[Context.BufSize] := $80;

  ToDo := Context.BufSize + ToAdd + 8;

  BlockMACSHA1(@Tail[0], Context);
  if ToDo > 64 then
    BlockMACSHA1(@Tail[64], Context);

  // finalizing
  SrcP := @Context.A; DstP := @Context.oKey[64];
  DstP[0] := SrcP[3];  DstP[1] := SrcP[2];
  DstP[2] := SrcP[1];  DstP[3] := SrcP[0];

  SrcP := @Context.B;
  Inc(PtrUInt(DstP), 4);
  DstP[0] := SrcP[3]; DstP[1] := SrcP[2];
  DstP[2] := SrcP[1]; DstP[3] := SrcP[0];

  SrcP := @Context.C;
  Inc(PtrUInt(DstP), 4);
  DstP[0] := SrcP[3]; DstP[1] := SrcP[2];
  DstP[2] := SrcP[1]; DstP[3] := SrcP[0];

  SrcP := @Context.D; Inc(PtrUInt(DstP), 4);
  DstP[0] := SrcP[3]; DstP[1] := SrcP[2];
  DstP[2] := SrcP[1]; DstP[3] := SrcP[0];

  SrcP := @Context.E; Inc(PtrUInt(DstP), 4);
  DstP[0] := SrcP[3]; DstP[1] := SrcP[2];
  DstP[2] := SrcP[1]; DstP[3] := SrcP[0];
  Result := HashSHA1(@Context.oKey[0], SizeOf(Context.oKey));
end;

function HashMACSHA1(Stream: TStream; const Key: ByteArray; Count: cardinal): TMessageDigest160;
var
  NKey, iKey: array[0..63] of byte;
  oKey: array[0..83] of byte;
  I, J, Read: integer;
  A, B, C, D, E: longword;
  Done, Padded: boolean;
  Buffer: array[0..4159] of byte;
  Temp: array[0..79] of longword;
  Count64: int64;
  T  : longword;
  T2 : longword;

  SrcP, DstP: PByteArray;
begin
  if Count = 0 then
  begin
    Stream.Position := 0;
    Count := Stream.Size;
  end
  else
    Count := Min(Count, Cardinal(Stream.Size - Stream.Position));
  // Normalizing the key
  FillChar(NKey, SizeOf(NKey), 0);
  if Length(Key) > 64 then
  begin
    Result := HashSHA1(Key);
    SBMove(Result, NKey, SizeOf(Result));
  end
  else
    SBMove(Key[0], NKey, Length(Key));
  // Creating the inner and outer keys
  for I := Low(NKey) to High(NKey) do
  begin
    iKey[I] := NKey[I] xor $36;
    oKey[I] := NKey[I] xor $5C;
  end;
  // intializing
  Done := False;
  Padded := False;
  Count64 := 0;
  A := $67452301; B := $EFCDAB89; C := $98BADCFE;
  D := $10325476; E := $C3D2E1F0;
  // processing
  repeat
    if not Padded then
    begin
      SBMove(iKey, Buffer, SizeOf(iKey));
      Read := Min(4096 - SizeOf(iKey), Count);

      Stream.ReadBuffer(Buffer[SizeOf(iKey)], Read);
      Inc(Read, SizeOf(iKey));
      Inc(Count, SizeOf(iKey));
      Count64 := Count;
      Padded := True;
    end
    else
      Read := Stream.Read(Buffer, Min(4096, Count));
    Dec(Count, Read);
    if Read < 4096 then
    begin
      // the end of stream is reached
      Buffer[Read] := $80;
      Inc(Read);
      while (Read mod 64) <> 56 do
      begin
        Buffer[Read] := 0;
        Inc(Read);
      end;

      // changing byte-order

      T := (Read shr 2) - 1;
      SrcP := @T2;
      DstP := @Buffer;
      for J := 0 to T do
      begin
        T2 := PLongWord(DstP)^;
        DstP^[0] := SrcP^[3]; DstP^[1] := SrcP^[2];
        DstP^[2] := SrcP^[1]; DstP^[3] := SrcP^[0];
        Inc(PtrUInt(DstP), 4);
      end;
      Count64 := Count64 shl 3;
      PLongWord(@Buffer[Read])^ := LongWord(Count64 shr 32);
      Inc(Read, 4);
      PLongWord(@Buffer[Read])^ := LongWord(Count64);
      Inc(Read, 4);
      Done := True;
    end
    else
    begin
      // changing byte-order

      T := (Read shr 2) - 1;
      SrcP := @T2;
      DstP := @Buffer;
      for J := 0 to T do
      begin
        T2 := PLongWord(DstP)^;
        DstP^[0] := SrcP^[3]; DstP^[1] := SrcP^[2];
        DstP^[2] := SrcP^[1]; DstP^[3] := SrcP^[0];
        Inc(PtrUInt(DstP), 4);
      end;
    end;
    I := 0;
    repeat
      SBMove(Buffer[I], Temp, SizeOf(LongWord) * 16);
      for J := 16 to 79 do
      begin
        T := Temp[J - 3] xor Temp[J - 8] xor Temp[J - 14] xor Temp[J - 16];
        T := ((T shl 1) or (T shr 31));
        Temp[J] := T;
      end;
      InternalSHA1( @ Temp, A, B, C, D, E);
      Inc(I, SizeOf(LongWord) * 16);
    until I = Read;
  until Done;
  // finalizing


  PLongWord(@oKey[64])^ := A; PLongWord(@oKey[68])^ := B;
  PLongWord(@oKey[72])^ := C; PLongWord(@oKey[76])^ := D;
  PLongWord(@oKey[80])^ := E;
  Result := HashSHA1(@oKey[0], SizeOf(oKey));
end;


////////////////////////////////////////////////////////////////////////////////
// HashMACSHA256 functions

procedure InitializeMACSHA256(var Context: TMACSHA256Context; const Key: ByteArray);
var
  Res : TMessageDigest256;
  I : integer;
  NKey : array[0..63] of byte;
  iKey : array [0..63]  of byte;
begin
  FillChar(NKey, SizeOf(NKey), 0);

  if Length(Key) > 64 then
  begin
    Res := HashSHA256(Key);
    SBMove(Res, NKey, SizeOf(Res));
  end
  else
    SBMove(Key[0], NKey, Length(Key));

  for I := 0 to 63 do
  begin
    iKey[I] := NKey[I] xor $36;
    Context.oKey[I] := NKey[I] xor $5C;
  end;

  SBSHA2.InitializeSHA256(Context.Ctx);
  SBSHA2.HashSHA256(Context.Ctx, @iKey[0], Length(iKey));
end;

function FinalizeMACSHA256(var Context: TMACSHA256Context): TMessageDigest256;
var
  M256 : TMessageDigest256;
  Ctx : TSHA256Context;
begin
  M256 := SBSHA2.FinalizeSHA256(Context.Ctx);
  InitializeSHA256(Ctx);
  HashSHA256(Ctx, @Context.oKey[0], Length(Context.oKey));
  HashSHA256(Ctx, @M256, SizeOf(M256));
  Result := FinalizeSHA256(Ctx);
end;

procedure HashMACSHA256(var Context: TMACSHA256Context; Chunk: pointer; Size: integer);
begin
  SBSHA2.HashSHA256(Context.Ctx, Chunk, Size);
end;

function HashMACSHA256(const S : ByteArray; const Key : ByteArray) : TMessageDigest256;
var
  Context: TMACSHA256Context;
begin
  InitializeMACSHA256(Context, Key);
  HashMACSHA256(Context, @S[0], Length(S));
  Result := FinalizeMACSHA256(Context);
end;

////////////////////////////////////////////////////////////////////////////////
// HashMACSHA512 functions

procedure InitializeMACSHA512(var Context: TMACSHA512Context; const Key: ByteArray);
var
  Res : TMessageDigest512;
  I : integer;
  NKey : array[0..127] of byte;
  iKey : array [0..127]  of byte;
begin
  FillChar(NKey, SizeOf(NKey), 0);

  if Length(Key) > 128 then
  begin
    Res := HashSHA512(Key);
    SBMove(Res, NKey, SizeOf(Res));
  end
  else
    SBMove(Key[0], NKey, Length(Key));

  for I := 0 to 127 do
  begin
    iKey[I] := NKey[I] xor $36;
    Context.oKey[I] := NKey[I] xor $5C;
  end;

  SBSHA2.InitializeSHA512(Context.Ctx);
  SBSHA2.HashSHA512(Context.Ctx, @iKey[0], Length(iKey));
end;

function FinalizeMACSHA512(var Context: TMACSHA512Context): TMessageDigest512;
var
  M512 : TMessageDigest512;
  Ctx : TSHA512Context;
begin
  M512 := SBSHA2.FinalizeSHA512(Context.Ctx);
  InitializeSHA512(Ctx);
  HashSHA512(Ctx, @Context.oKey[0], Length(Context.oKey));
  HashSHA512(Ctx, @M512, SizeOf(M512));
  Result := FinalizeSHA512(Ctx);
end;

procedure HashMACSHA512(var Context: TMACSHA512Context; Chunk: pointer; Size: integer);
begin
  SBSHA2.HashSHA512(Context.Ctx, Chunk, Size);
end;

function HashMACSHA512(const S : ByteArray; const Key : ByteArray): TMessageDigest512;
var
  Context: TMACSHA512Context;
begin
  InitializeMACSHA512(Context, Key);
  HashMACSHA512(Context, @S[0], Length(S));
  Result := FinalizeMACSHA512(Context);
end;

////////////////////////////////////////////////////////////////////////////////
// HashMACSHA224 functions

procedure InitializeMACSHA224(var Context: TMACSHA224Context; const Key: ByteArray);
var
  Res : TMessageDigest224;
  I : integer;
  NKey : array[0..63] of byte;
  iKey : array [0..63]  of byte;
begin
  FillChar(NKey, SizeOf(NKey), 0);

  if Length(Key) > 64 then
  begin
    Res := HashSHA224(Key);
    SBMove(Res, NKey, SizeOf(Res));
  end
  else
    SBMove(Key[0], NKey, Length(Key));

  for I := 0 to 63 do
  begin
    iKey[I] := NKey[I] xor $36;
    Context.oKey[I] := NKey[I] xor $5C;
  end;

  SBSHA2.InitializeSHA224(Context.Ctx);
  SBSHA2.HashSHA224(Context.Ctx, @iKey[0], Length(iKey));
end;

function FinalizeMACSHA224(var Context: TMACSHA224Context): TMessageDigest224;
var
  M224 : TMessageDigest224;
  Ctx : TSHA256Context;
begin
  M224 := SBSHA2.FinalizeSHA224(Context.Ctx);
  InitializeSHA224(Ctx);
  HashSHA224(Ctx, @Context.oKey[0], Length(Context.oKey));
  HashSHA224(Ctx, @M224, SizeOf(M224));
  Result := FinalizeSHA224(Ctx);
end;

procedure HashMACSHA224(var Context: TMACSHA224Context; Chunk: pointer; Size: integer);
begin
  SBSHA2.HashSHA224(Context.Ctx, Chunk, Size);
end;

function HashMACSHA224(const S : ByteArray; const Key : ByteArray): TMessageDigest224;
var
  Context: TMACSHA224Context;
begin
  InitializeMACSHA224(Context, Key);
  HashMACSHA224(Context, @S[0], Length(S));
  Result := FinalizeMACSHA224(Context);
end;

////////////////////////////////////////////////////////////////////////////////
// HashMACSHA384 functions

procedure InitializeMACSHA384(var Context: TMACSHA384Context; const Key: ByteArray);
var
  Res : TMessageDigest384;
  I : integer;
  NKey : array[0..127] of byte;
  iKey : array [0..127]  of byte;
begin
  FillChar(NKey, SizeOf(NKey), 0);

  if Length(Key) > 128 then
  begin
    Res := HashSHA384(Key);
    SBMove(Res, NKey, SizeOf(Res));
  end
  else
    SBMove(Key[0], NKey, Length(Key));

  for I := 0 to 127 do
  begin
    iKey[I] := NKey[I] xor $36;
    Context.oKey[I] := NKey[I] xor $5C;
  end;

  SBSHA2.InitializeSHA384(Context.Ctx);
  SBSHA2.HashSHA384(Context.Ctx, @iKey[0], Length(iKey));
end;

function FinalizeMACSHA384(var Context: TMACSHA384Context): TMessageDigest384;
var
  M384 : TMessageDigest384;
  Ctx : TSHA384Context;
begin
  M384 := SBSHA2.FinalizeSHA384(Context.Ctx);
  InitializeSHA384(Ctx);
  HashSHA384(Ctx, @Context.oKey[0], Length(Context.oKey));
  HashSHA384(Ctx, @M384, SizeOf(M384));
  Result := FinalizeSHA384(Ctx);
end;

procedure HashMACSHA384(var Context: TMACSHA384Context; Chunk: pointer; Size: integer);
begin
  SBSHA2.HashSHA384(Context.Ctx, Chunk, Size);
end;

function HashMACSHA384(const S : ByteArray; const Key : ByteArray): TMessageDigest384;
var
  Context: TMACSHA384Context;
begin
  InitializeMACSHA384(Context, Key);
  HashMACSHA384(Context, @S[0], Length(S));
  Result := FinalizeMACSHA384(Context);
end;

end.
