(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBSHA2;

interface

uses
  SBTypes,
  SBUtils,
  SBMath,
  SBConstants;

type

  TSHA256Context =  packed   record
    Size: int64;
    Buffer: array  [0..63]  of byte;
    BufSize: cardinal;
    A, B, C, D, E, F, G, H: longword;
  end;

  TSHA512Context =  packed   record
    Size: int64;
    Buffer: array  [0..127]  of byte;
    BufSize: cardinal;
    A, B, C, D, E, F, G, H : TSBInt64;
  end;

  TSHA384Context =  TSHA512Context;

procedure InitializeSHA224(var Context: TSHA256Context); 
procedure HashSHA224(var Context: TSHA256Context; Chunk: pointer; Size: cardinal); overload;
function HashSHA224(Buffer: pointer; Size: cardinal): TMessageDigest224; overload;
function HashSHA224(const S: ByteArray): TMessageDigest224; overload;
function FinalizeSHA224(var Context: TSHA256Context): TMessageDigest224; 

procedure InitializeSHA256(var Context: TSHA256Context); 
procedure HashSHA256(var Context: TSHA256Context; Chunk: pointer; Size: cardinal); overload;
function HashSHA256(Buffer: pointer; Size: cardinal): TMessageDigest256; overload;
function HashSHA256(const S: ByteArray): TMessageDigest256; overload;
function FinalizeSHA256(var Context: TSHA256Context): TMessageDigest256; 

procedure InitializeSHA384(var Context: TSHA384Context); 
procedure HashSHA384(var Context: TSHA384Context; Chunk: pointer; Size: cardinal); overload;
function HashSHA384(Buffer: pointer; Size: cardinal): TMessageDigest384; overload;
function HashSHA384(const S: ByteArray): TMessageDigest384; overload;
function FinalizeSHA384(var Context: TSHA384Context): TMessageDigest384; 

procedure InitializeSHA512(var Context: TSHA512Context); 
procedure HashSHA512(var Context: TSHA512Context; Chunk: pointer; Size: cardinal); overload;
function HashSHA512(Buffer: pointer; Size: cardinal): TMessageDigest512; overload;
function HashSHA512(const S: ByteArray): TMessageDigest512; overload;
function FinalizeSHA512(var Context: TSHA512Context): TMessageDigest512; 

implementation

uses
  SysUtils;

const
  SHA256K : array[0..63] of longword =  ( 
    $428a2f98, $71374491, $b5c0fbcf, $e9b5dba5, $3956c25b, $59f111f1, $923f82a4, $ab1c5ed5,
    $d807aa98, $12835b01, $243185be, $550c7dc3, $72be5d74, $80deb1fe, $9bdc06a7, $c19bf174,
    $e49b69c1, $efbe4786, $0fc19dc6, $240ca1cc, $2de92c6f, $4a7484aa, $5cb0a9dc, $76f988da,
    $983e5152, $a831c66d, $b00327c8, $bf597fc7, $c6e00bf3, $d5a79147, $06ca6351, $14292967,
    $27b70a85, $2e1b2138, $4d2c6dfc, $53380d13, $650a7354, $766a0abb, $81c2c92e, $92722c85,
    $a2bfe8a1, $a81a664b, $c24b8b70, $c76c51a3, $d192e819, $d6990624, $f40e3585, $106aa070,
    $19a4c116, $1e376c08, $2748774c, $34b0bcb5, $391c0cb3, $4ed8aa4a, $5b9cca4f, $682e6ff3,
    $748f82ee, $78a5636f, $84c87814, $8cc70208, $90befffa, $a4506ceb, $bef9a3f7, $c67178f2
   ) ;

  SHA512K : array[0..79] of TSBInt64 =  ( 
    $428a2f98d728ae22, $7137449123ef65cd, TSBInt64($b5c0fbcfec4d3b2f), TSBInt64($e9b5dba58189dbbc),
    $3956c25bf348b538, $59f111f1b605d019, TSBInt64($923f82a4af194f9b), TSBInt64($ab1c5ed5da6d8118),
    TSBInt64($d807aa98a3030242), $12835b0145706fbe, $243185be4ee4b28c, $550c7dc3d5ffb4e2,
    $72be5d74f27b896f, TSBInt64($80deb1fe3b1696b1), TSBInt64($9bdc06a725c71235), TSBInt64($c19bf174cf692694),
    TSBInt64($e49b69c19ef14ad2), TSBInt64($efbe4786384f25e3), $0fc19dc68b8cd5b5, $240ca1cc77ac9c65,
    $2de92c6f592b0275, $4a7484aa6ea6e483, $5cb0a9dcbd41fbd4, $76f988da831153b5,
    TSBInt64($983e5152ee66dfab), TSBInt64($a831c66d2db43210), TSBInt64($b00327c898fb213f), TSBInt64($bf597fc7beef0ee4),
    TSBInt64($c6e00bf33da88fc2), TSBInt64($d5a79147930aa725), $06ca6351e003826f, $142929670a0e6e70,
    $27b70a8546d22ffc, $2e1b21385c26c926, $4d2c6dfc5ac42aed, $53380d139d95b3df,
    $650a73548baf63de, $766a0abb3c77b2a8, TSBInt64($81c2c92e47edaee6), TSBInt64($92722c851482353b),
    TSBInt64($a2bfe8a14cf10364), TSBInt64($a81a664bbc423001), TSBInt64($c24b8b70d0f89791), TSBInt64($c76c51a30654be30),
    TSBInt64($d192e819d6ef5218), TSBInt64($d69906245565a910), TSBInt64($f40e35855771202a), $106aa07032bbd1b8,
    $19a4c116b8d2d0c8, $1e376c085141ab53, $2748774cdf8eeb99, $34b0bcb5e19b48a8,
    $391c0cb3c5c95a63, $4ed8aa4ae3418acb, $5b9cca4f7763e373, $682e6ff3d6b2b8a3,
    $748f82ee5defb2fc, $78a5636f43172f60, TSBInt64($84c87814a1f0ab72), TSBInt64($8cc702081a6439ec),
    TSBInt64($90befffa23631e28), TSBInt64($a4506cebde82bde9), TSBInt64($bef9a3f7b2c67915), TSBInt64($c67178f2e372532b),
    TSBInt64($ca273eceea26619c), TSBInt64($d186b8c721c0c207), TSBInt64($eada7dd6cde0eb1e), TSBInt64($f57d4f7fee6ed178),
    $06f067aa72176fba, $0a637dc5a2c898a6, $113f9804bef90dae, $1b710b35131c471b,
    $28db77f523047d84, $32caab7b40c72493, $3c9ebe0a15c9bebc, $431d67c49c100d4c,
    $4cc5d4becb3e42b6, $597f299cfc657e2a, $5fcb6fab3ad6faec, $6c44198c4a475817
   ) ;
(*
  SHA512K : array[0..79] of {$ifndef SB_NET}Int64{$else}UInt64{$endif} = {$ifndef SB_NET}({$else}[{$endif}
    $428a2f98d728ae22, $7137449123ef65cd, $b5c0fbcfec4d3b2f, $e9b5dba58189dbbc,
    $3956c25bf348b538, $59f111f1b605d019, $923f82a4af194f9b, $ab1c5ed5da6d8118,
    $d807aa98a3030242, $12835b0145706fbe, $243185be4ee4b28c, $550c7dc3d5ffb4e2,
    $72be5d74f27b896f, $80deb1fe3b1696b1, $9bdc06a725c71235, $c19bf174cf692694,
    $e49b69c19ef14ad2, $efbe4786384f25e3, $0fc19dc68b8cd5b5, $240ca1cc77ac9c65,
    $2de92c6f592b0275, $4a7484aa6ea6e483, $5cb0a9dcbd41fbd4, $76f988da831153b5,
    $983e5152ee66dfab, $a831c66d2db43210, $b00327c898fb213f, $bf597fc7beef0ee4,
    $c6e00bf33da88fc2, $d5a79147930aa725, $06ca6351e003826f, $142929670a0e6e70,
    $27b70a8546d22ffc, $2e1b21385c26c926, $4d2c6dfc5ac42aed, $53380d139d95b3df,
    $650a73548baf63de, $766a0abb3c77b2a8, $81c2c92e47edaee6, $92722c851482353b,
    $a2bfe8a14cf10364, $a81a664bbc423001, $c24b8b70d0f89791, $c76c51a30654be30,
    $d192e819d6ef5218, $d69906245565a910, $f40e35855771202a, $106aa07032bbd1b8,
    $19a4c116b8d2d0c8, $1e376c085141ab53, $2748774cdf8eeb99, $34b0bcb5e19b48a8,
    $391c0cb3c5c95a63, $4ed8aa4ae3418acb, $5b9cca4f7763e373, $682e6ff3d6b2b8a3,
    $748f82ee5defb2fc, $78a5636f43172f60, $84c87814a1f0ab72, $8cc702081a6439ec,
    $90befffa23631e28, $a4506cebde82bde9, $bef9a3f7b2c67915, $c67178f2e372532b,
    $ca273eceea26619c, $d186b8c721c0c207, $eada7dd6cde0eb1e, $f57d4f7fee6ed178,
    $06f067aa72176fba, $0a637dc5a2c898a6, $113f9804bef90dae, $1b710b35131c471b,
    $28db77f523047d84, $32caab7b40c72493, $3c9ebe0a15c9bebc, $431d67c49c100d4c,
    $4cc5d4becb3e42b6, $597f299cfc657e2a, $5fcb6fab3ad6faec, $6c44198c4a475817
  {$ifndef SB_NET}){$else}]{$endif};
*)

type
  TSHA256Schedule = array[0..63] of longword;
  TSHA512Schedule = array[0..79] of TSBInt64;


////////////////////////////////////////////////////////////////////////////////
// SHA224 implementation

function SHADigest256To224(const Digest : TMessageDigest256) : TMessageDigest224;
begin
  Result.A1 := Digest.A1;
  Result.B1 := Digest.B1;
  Result.C1 := Digest.C1;
  Result.D1 := Digest.D1;
  Result.A2 := Digest.A2;
  Result.B2 := Digest.B2;
  Result.C2 := Digest.C2;
end;

procedure InitializeSHA224(var Context: TSHA256Context);
begin
  Context.Size := 0;
  FillChar(Context.Buffer, SizeOf(Context.Buffer), 0);
  Context.BufSize := 0;

  Context.A := $C1059ED8;
  Context.B := $367CD507;
  Context.C := $3070DD17;
  Context.D := $F70E5939;
  Context.E := $FFC00B31;
  Context.F := $68581511;
  Context.G := $64F98FA7;
  Context.H := $BEFA4FA4;
end;

function HashSHA224(const S: ByteArray): TMessageDigest224;
begin
  Result := HashSHA224(@S[0], Length(S));
end;

procedure HashSHA224(var Context: TSHA256Context; Chunk: pointer; Size: cardinal);
begin
  HashSHA256(Context, Chunk, Size);
end;

function HashSHA224(Buffer: pointer; Size: cardinal): TMessageDigest224;
var
  Ctx : TSHA256Context;
begin
  InitializeSHA224(Ctx);
  HashSHA224(Ctx, Buffer, Size);
  Result := FinalizeSHA224(Ctx);
end;

function FinalizeSHA224(var Context: TSHA256Context): TMessageDigest224;
begin
  Result := SHADigest256to224(FinalizeSHA256(Context));
end;

////////////////////////////////////////////////////////////////////////////////
// SHA256 implementation

procedure InitializeSHA256(var Context: TSHA256Context);
begin
  Context.Size := 0;
  FillChar(Context.Buffer, SizeOf(Context.Buffer), 0);
  Context.BufSize := 0;
  Context.A := $6A09E667;
  Context.B := $BB67AE85;
  Context.C := $3C6EF372;
  Context.D := $A54FF53A;
  Context.E := $510E527F;
  Context.F := $9B05688C;
  Context.G := $1F83D9AB;
  Context.H := $5BE0CD19;
end;

function HashSHA256(const S: ByteArray): TMessageDigest256;
begin
  Result := HashSHA256(@S[0], Length(S));
end;

procedure BlockSHA256(Buf: pointer; var Context : TSHA256Context; var Schedule : TSHA256Schedule);
var
  I : integer;
  A, B, C, D, E, F, G, H, T1, T2 : longword;
begin
  // preparing message schedule
  for I := 0 to 15 do
    Schedule[I] := SwapUInt32(PLongwordArray(Buf)[I]);
  for I := 16 to 63 do
    Schedule[I] :=
      ((((Schedule[I - 2] shr 17) or (Schedule[I - 2] shl 15)) xor
      ((Schedule[I - 2] shr 19) or (Schedule[I - 2] shl 13)) xor
      ((Schedule[I - 2] shr 10))) +
      (Schedule[I - 7]) +
      (((Schedule[I - 15] shr 7) or (Schedule[I - 15] shl 25)) xor
      ((Schedule[I - 15] shr 18) or (Schedule[I - 15] shl 14)) xor
      ((Schedule[I - 15] shr 3))) +
      (Schedule[I - 16]));
  // initializing working variables
  A := Context.A;
  B := Context.B;
  C := Context.C;
  D := Context.D;
  E := Context.E;
  F := Context.F;
  G := Context.G;
  H := Context.H;
  // performing main round loop
  for I := 0 to 63 do
  begin
    T1 := H;
    Inc(T1, ((E shr 6) or (E shl 26)) xor
      ((E shr 11) or (E shl 21)) xor
      ((E shr 25) or (E shl 7)));
    Inc(T1, ((E and F) xor ((not E) and G)));
    Inc(T1, SHA256K[I]);
    Inc(T1, Schedule[I]);
    T2 := (((A shr 2) or (A shl 30)) xor
      ((A shr 13) or (A shl 19)) xor
      ((A shr 22) or (A shl 10))) +
      ((A and B) xor (A and C) xor (B and C));
    H := G;
    G := F;
    F := E;
    E := D + T1;
    D := C;
    C := B;
    B := A;
    A := T1 + T2;
  end;
  // saving context variables
  Inc(Context.A, A);
  Inc(Context.B, B);
  Inc(Context.C, C);
  Inc(Context.D, D);
  Inc(Context.E, E);
  Inc(Context.F, F);
  Inc(Context.G, G);
  Inc(Context.H, H);
end;

procedure HashSHA256(var Context: TSHA256Context; Chunk: pointer; Size: cardinal);
var
  Needed : cardinal;
  Schedule : TSHA256Schedule;
begin
  if Size = 0 then
    Exit;
  Inc(Context.Size, Size);
  if Context.BufSize > 0 then
  begin
    Needed := 64 - Context.BufSize;
    if Needed > Size then
    begin
      SBMove(Chunk^, Context.Buffer[Context.BufSize], Size);
      Inc(Context.BufSize, Size);
      Exit;
    end
    else
    begin
      SBMove(Chunk^, Context.Buffer[Context.BufSize], Needed);
      BlockSHA256(@Context.Buffer[0], Context, Schedule);
      Context.BufSize := 0;
      Inc(PtrUInt(Chunk), Needed);
      Dec(Size, Needed);
    end;
  end;
  while Size >= 64 do
  begin
    BlockSHA256(Chunk, Context, Schedule);
    Inc(PtrUInt(Chunk), 64);
    Dec(Size, 64);
  end;
  Context.BufSize := Size;
  SBMove(Chunk^, Context.Buffer[0], Size);
end;

function HashSHA256(Buffer: pointer; Size: cardinal): TMessageDigest256;
var
  Ctx : TSHA256Context;
begin
  InitializeSHA256(Ctx);
  HashSHA256(Ctx, Buffer, Size);
  Result := FinalizeSHA256(Ctx);
end;

function FinalizeSHA256(var Context: TSHA256Context): TMessageDigest256;
var
  j: byte;
  SrcP: PByteArray;
  Tail: array [0..127]  of byte;
  ToAdd, ToDo: cardinal;
  Count: int64;
  Temp: LongWord;
  Schedule : TSHA256Schedule;
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
  SrcP := @Temp;
  for j := 0 to 3 do
    Tail[ToAdd + Context.BufSize + j] := SrcP[3 - j];

  Temp := LongWord(Count);
  for j := 0 to 3 do
    Tail[ToAdd + Context.BufSize + 4 + j] := SrcP[3 - j];

  Tail[Context.BufSize] := $80;

  ToDo := Context.BufSize + ToAdd + 8;

  BlockSHA256(@Tail[0], Context, Schedule);
  if ToDo > 64 then
    BlockSHA256(@Tail[64], Context, Schedule);

  // finalizing
  SrcP := @Context.A;
  Result.A1 := LongWord(SrcP[0] shl 24) or LongWord(SrcP[1] shl 16) or
              LongWord(SrcP[2] shl 8) or LongWord(SrcP[3]);
  SrcP := @Context.B;
  Result.B1 := LongWord(SrcP[0] shl 24) or LongWord(SrcP[1] shl 16) or
              LongWord(SrcP[2] shl 8) or LongWord(SrcP[3]);
  SrcP := @Context.C;
  Result.C1 := LongWord(SrcP[0] shl 24) or LongWord(SrcP[1] shl 16) or
              LongWord(SrcP[2] shl 8) or LongWord(SrcP[3]);
  SrcP := @Context.D;
  Result.D1 := LongWord(SrcP[0] shl 24) or LongWord(SrcP[1] shl 16) or
              LongWord(SrcP[2] shl 8) or LongWord(SrcP[3]);
  SrcP := @Context.E;
  Result.A2 := LongWord(SrcP[0] shl 24) or LongWord(SrcP[1] shl 16) or
              LongWord(SrcP[2] shl 8) or LongWord(SrcP[3]);

  SrcP := @Context.F;
  Result.B2 := LongWord(SrcP[0] shl 24) or LongWord(SrcP[1] shl 16) or
              LongWord(SrcP[2] shl 8) or LongWord(SrcP[3]);

  SrcP := @Context.G;
  Result.C2 := LongWord(SrcP[0] shl 24) or LongWord(SrcP[1] shl 16) or
              LongWord(SrcP[2] shl 8) or LongWord(SrcP[3]);

  SrcP := @Context.H;
  Result.D2 := LongWord(SrcP[0] shl 24) or LongWord(SrcP[1] shl 16) or
              LongWord(SrcP[2] shl 8) or LongWord(SrcP[3]);
end;

////////////////////////////////////////////////////////////////////////////////
// SHA512 implementation

procedure InitializeSHA512(var Context: TSHA512Context);
begin
  Context.Size := 0;
  FillChar(Context.Buffer, SizeOf(Context.Buffer), 0);
  Context.BufSize := 0;
  Context.A := $6a09e667f3bcc908;
  //Context.B := $bb67ae8584caa73b;
  Context.B := TSBInt64($bb67ae8584caa73b);
  Context.C := $3c6ef372fe94f82b;
  //Context.D := $a54ff53a5f1d36f1;
  Context.D := TSBInt64($a54ff53a5f1d36f1);
  Context.E := $510e527fade682d1;
  //Context.F := $9b05688c2b3e6c1f;
  Context.F := TSBInt64($9b05688c2b3e6c1f);
  Context.G := $1f83d9abfb41bd6b;
  //Context.H := $5be0cd19137e2179;
  Context.H := TSBInt64($5be0cd19137e2179);
end;

function HashSHA512(const S: ByteArray): TMessageDigest512;
begin
  Result := HashSHA512(@S[0], Length(S));
end;

procedure BlockSHA512(Buffer: pointer; var Context: TSHA512Context; var Schedule :
  TSHA512Schedule);
var
  I : integer;
  A, B, C, D, E, F, G, H : TSBInt64;
  T1, T2 : TSBInt64;
begin
  // preparing message schedule
  for I := 0 to 15 do
    Schedule[I] := SwapInt64(PInt64Array(Buffer)[I]);
  for I := 16 to 79 do
    Schedule[I] :=
      ((((Schedule[I - 2] shr 19) or (Schedule[I - 2] shl 45)) xor
      ((Schedule[I - 2] shr 61) or (Schedule[I - 2] shl 3)) xor
      ((Schedule[I - 2] shr 6))) +
      (Schedule[I - 7]) +
      (((Schedule[I - 15] shr 1) or (Schedule[I - 15] shl 63)) xor
      ((Schedule[I - 15] shr 8) or (Schedule[I - 15] shl 56)) xor
      ((Schedule[I - 15] shr 7))) +
      (Schedule[I - 16]));
  // initializing working variables
  A := Context.A;
  B := Context.B;
  C := Context.C;
  D := Context.D;
  E := Context.E;
  F := Context.F;
  G := Context.G;
  H := Context.H;
  // performing main round loop
  for I := 0 to 79 do
  begin
    T1 := H;
    Inc(T1, ((E shr 14) or (E shl 50)) xor
      ((E shr 18) or (E shl 46)) xor
      ((E shr 41) or (E shl 23)));
    Inc(T1, ((E and F) xor ((not E) and G)));
    Inc(T1, SHA512K[I]);
    Inc(T1, Schedule[I]);
    T2 := (((A shr 28) or (A shl 36)) xor
      ((A shr 34) or (A shl 30)) xor
      ((A shr 39) or (A shl 25))) +
      ((A and B) xor (A and C) xor (B and C));
    H := G;
    G := F;
    F := E;
    E := D + T1;
    D := C;
    C := B;
    B := A;
    A := T1 + T2;
  end;
  // saving context variables
  Inc(Context.A, A);
  Inc(Context.B, B);
  Inc(Context.C, C);
  Inc(Context.D, D);
  Inc(Context.E, E);
  Inc(Context.F, F);
  Inc(Context.G, G);
  Inc(Context.H, H);
end;

procedure HashSHA512(var Context: TSHA512Context; Chunk: pointer; Size: cardinal);
var
  Needed : cardinal;
  Schedule : TSHA512Schedule;
begin
  if Size = 0 then
    Exit;
  Inc(Context.Size, Size);
  if Context.BufSize > 0 then
  begin
    Needed := 128 - Context.BufSize;
    if Needed > Size then
    begin
      SBMove(Chunk^, Context.Buffer[Context.BufSize], Size);
      Inc(Context.BufSize, Size);
      Exit;
    end
    else
    begin
      SBMove(Chunk^, Context.Buffer[Context.BufSize], Needed);
      BlockSHA512(@Context.Buffer[0], Context, Schedule);
      Context.BufSize := 0;
      Inc(PtrUInt(Chunk), Needed);
      Dec(Size, Needed);
    end;
  end;
  while Size >= 128 do
  begin
    BlockSHA512(Chunk, Context, Schedule);
    Inc(PtrUInt(Chunk), 128);
    Dec(Size, 128);
  end;
  Context.BufSize := Size;
  SBMove(Chunk^, Context.Buffer[0], Size);
end;

function HashSHA512(Buffer: pointer; Size: cardinal): TMessageDigest512;
var
  Ctx : TSHA512Context;
begin
  InitializeSHA512(Ctx);
  HashSHA512(Ctx, Buffer, Size);
  Result := FinalizeSHA512(Ctx);
end;

function FinalizeSHA512(var Context: TSHA512Context): TMessageDigest512;
var
  j: byte;
  SrcP: PByteArray;
  Tail: array [0..255]  of byte;
  ToAdd, ToDo: cardinal;
  Count: Int64;
  Temp: Int64;
  Schedule : TSHA512Schedule;
begin
  
  FillChar(Tail[0], SizeOf(Tail), 0);
  Count := Context.Size shl 3;

  if 112 - Integer(Context.BufSize) <= 0 then
    ToAdd := 240 - Context.BufSize
  else
    ToAdd := 112 - Context.BufSize;

  if Context.BufSize > 0 then
  begin
    SBMove(Context.Buffer[0], Tail[0], Context.BufSize);
  end;
  Temp := Count shr 32;
  SrcP := @Temp;
  for j := 0 to 7 do
    Tail[ToAdd + Context.BufSize + j] := SrcP[7 - j];

  Temp := Int64(Count);
  for j := 0 to 7 do
    Tail[ToAdd + Context.BufSize + 8 + j] := SrcP[7 - j];

  Tail[Context.BufSize] := $80;

  ToDo := Context.BufSize + ToAdd + 16;

  BlockSHA512(@Tail[0], Context, Schedule);
  if ToDo > 128 then
    BlockSHA512(@Tail[128], Context, Schedule);

  // finalizing
  SrcP := @Context.A;
  Result.A1 := (TSBInt64(SrcP[0]) shl 56) or (TSBInt64(SrcP[1]) shl 48) or
    (TSBInt64(SrcP[2]) shl 40) or (TSBInt64(SrcP[3]) shl 32) or 
    (TSBInt64(SrcP[4]) shl 24) or (TSBInt64(SrcP[5]) shl 16) or 
    (TSBInt64(SrcP[6]) shl 8) or TSBInt64(SrcP[7]);
    
  SrcP := @Context.B;
  Result.B1 := (TSBInt64(SrcP[0]) shl 56) or (TSBInt64(SrcP[1]) shl 48) or
    (TSBInt64(SrcP[2]) shl 40) or (TSBInt64(SrcP[3]) shl 32) or 
    (TSBInt64(SrcP[4]) shl 24) or (TSBInt64(SrcP[5]) shl 16) or 
    (TSBInt64(SrcP[6]) shl 8) or TSBInt64(SrcP[7]);
    
  SrcP := @Context.C;
  Result.C1 := (TSBInt64(SrcP[0]) shl 56) or (TSBInt64(SrcP[1]) shl 48) or
    (TSBInt64(SrcP[2]) shl 40) or (TSBInt64(SrcP[3]) shl 32) or 
    (TSBInt64(SrcP[4]) shl 24) or (TSBInt64(SrcP[5]) shl 16) or 
    (TSBInt64(SrcP[6]) shl 8) or TSBInt64(SrcP[7]);

  SrcP := @Context.D;
  Result.D1 := (TSBInt64(SrcP[0]) shl 56) or (TSBInt64(SrcP[1]) shl 48) or
    (TSBInt64(SrcP[2]) shl 40) or (TSBInt64(SrcP[3]) shl 32) or 
    (TSBInt64(SrcP[4]) shl 24) or (TSBInt64(SrcP[5]) shl 16) or 
    (TSBInt64(SrcP[6]) shl 8) or TSBInt64(SrcP[7]);

  SrcP := @Context.E;
  Result.A2 := (TSBInt64(SrcP[0]) shl 56) or (TSBInt64(SrcP[1]) shl 48) or
    (TSBInt64(SrcP[2]) shl 40) or (TSBInt64(SrcP[3]) shl 32) or 
    (TSBInt64(SrcP[4]) shl 24) or (TSBInt64(SrcP[5]) shl 16) or 
    (TSBInt64(SrcP[6]) shl 8) or TSBInt64(SrcP[7]);
    
  SrcP := @Context.F;
  Result.B2 := (TSBInt64(SrcP[0]) shl 56) or (TSBInt64(SrcP[1]) shl 48) or
    (TSBInt64(SrcP[2]) shl 40) or (TSBInt64(SrcP[3]) shl 32) or 
    (TSBInt64(SrcP[4]) shl 24) or (TSBInt64(SrcP[5]) shl 16) or 
    (TSBInt64(SrcP[6]) shl 8) or TSBInt64(SrcP[7]);

  SrcP := @Context.G;
  Result.C2 := (TSBInt64(SrcP[0]) shl 56) or (TSBInt64(SrcP[1]) shl 48) or
    (TSBInt64(SrcP[2]) shl 40) or (TSBInt64(SrcP[3]) shl 32) or 
    (TSBInt64(SrcP[4]) shl 24) or (TSBInt64(SrcP[5]) shl 16) or 
    (TSBInt64(SrcP[6]) shl 8) or TSBInt64(SrcP[7]);

  SrcP := @Context.H;
  Result.D2 := (TSBInt64(SrcP[0]) shl 56) or (TSBInt64(SrcP[1]) shl 48) or
    (TSBInt64(SrcP[2]) shl 40) or (TSBInt64(SrcP[3]) shl 32) or 
    (TSBInt64(SrcP[4]) shl 24) or (TSBInt64(SrcP[5]) shl 16) or 
    (TSBInt64(SrcP[6]) shl 8) or TSBInt64(SrcP[7]);
end;

////////////////////////////////////////////////////////////////////////////////
// SHA384 implementation

procedure InitializeSHA384(var Context: TSHA384Context);
begin
  Context.Size := 0;
  FillChar(Context.Buffer, SizeOf(Context.Buffer), 0);
  Context.BufSize := 0;
  (*
  Context.A := $cbbb9d5dc1059ed8;
  Context.B := $629a292a367cd507;
  Context.C := $9159015a3070dd17;
  Context.D := $152fecd8f70e5939;
  Context.E := $67332667ffc00b31;
  Context.F := $8eb44a8768581511;
  Context.G := $db0c2e0d64f98fa7;
  Context.H := $47b5481dbefa4fa4;
  *)
  Context.A := TSBInt64($cbbb9d5dc1059ed8);
  Context.B := $629a292a367cd507;
  Context.C := TSBInt64($9159015a3070dd17);
  Context.D := $152fecd8f70e5939;
  Context.E := $67332667ffc00b31;
  Context.F := TSBInt64($8eb44a8768581511);
  Context.G := TSBInt64($db0c2e0d64f98fa7);
  Context.H := $47b5481dbefa4fa4;
end;

function HashSHA384(const S: ByteArray): TMessageDigest384;
begin
  Result := HashSHA384(@S[0], Length(S));
end;

procedure HashSHA384(var Context: TSHA384Context; Chunk: pointer; Size: cardinal);
begin
  HashSHA512(Context, Chunk, Size);
end;

function HashSHA384(Buffer: pointer; Size: cardinal): TMessageDigest384;
var
  Ctx : TSHA384Context;
begin
  InitializeSHA384(Ctx);
  HashSHA384(Ctx, Buffer, Size);
  Result := FinalizeSHA384(Ctx);
end;

function FinalizeSHA384(var Context: TSHA384Context): TMessageDigest384;
var
  Digest : TMessageDigest512;
begin
  Digest := FinalizeSHA512(Context);
  Result.A := Digest.A1;
  Result.B := Digest.B1;
  Result.C := Digest.C1;
  Result.D := Digest.D1;
  Result.E := Digest.A2;
  Result.F := Digest.B2;
end;

end.
