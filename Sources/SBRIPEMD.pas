(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBRIPEMD;

interface

uses
  SysUtils,
  SBTypes,
  SBConstants,
  SBUtils
;

type

  TRMD160Buffer = array [0..15] of longword;

  TRMD160Context =  packed   record
    Buffer : TRMD160Buffer;
    BufSize : cardinal;
    h1, h2, h3, h4, h5 : longword;
    MessageSizeLo, MessageSizeHi : longword; 
  end;

  procedure InitializeRMD160(var Context : TRMD160Context); 

  procedure HashRMD160(var Context : TRMD160Context;
    Chunk : pointer; Size : integer); overload;
  function  HashRMD160(Buffer : pointer;
    Size : integer) : TMessageDigest160; overload;
  function HashRMD160(const Buffer : string) : TMessageDigest160; overload;
  {$ifdef SB_UNICODE_VCL}
  function HashRMD160(const Buffer : ByteArray) : TMessageDigest160; overload;
   {$endif}

  function FinalizeRMD160(var Context : TRMD160Context) : TMessageDigest160; 

implementation

const
  // K and K' constants. K[j shr 4] used.
  RMD_K : array [0..4] of longword =
     ( 
    $00000000, $5A827999, $6ED9EBA1, $8F1BBCDC, $A953FD4E
     ) ;
  RMD_Kd : array [0..4] of longword =
     ( 
    $50A28BE6, $5C4DD124, $6D703EF3, $7A6D76E9, $00000000
     ) ;
  // selection of the message word, r and r'.
  RMD_r : array [0..79] of byte =
     ( 
     $0,$1,$2,$3,$4,$5,$6,$7,$8,$9,$A,$B,$C,$D,$E,$F,
     $7,$4,$D,$1,$A,$6,$F,$3,$C,$0,$9,$5,$2,$E,$B,$8,
     $3,$A,$E,$4,$9,$F,$8,$1,$2,$7,$0,$6,$D,$B,$5,$C,
     $1,$9,$B,$A,$0,$8,$C,$4,$D,$3,$7,$F,$E,$5,$6,$2,
     $4,$0,$5,$9,$7,$C,$2,$A,$E,$1,$3,$8,$B,$6,$F,$D
     ) ;
  RMD_rd : array [0..79] of byte =
     ( 
     $5,$E,$7,$0,$9,$2,$B,$4,$D,$6,$F,$8,$1,$A,$3,$C,
     $6,$B,$3,$7,$0,$D,$5,$A,$E,$F,$8,$C,$4,$9,$1,$2,
     $F,$5,$1,$3,$7,$E,$6,$9,$B,$8,$C,$2,$A,$0,$4,$D,
     $8,$6,$4,$1,$3,$B,$F,$0,$5,$C,$2,$D,$9,$7,$A,$E,
     $C,$F,$A,$4,$1,$5,$8,$7,$6,$2,$D,$E,$0,$3,$9,$B
     ) ;
  //amount of rotate left, s and s'
  RMD_s : array [0..79] of byte =
     ( 
     $B,$E,$F,$C,$5,$8,$7,$9,$B,$D,$E,$F,$6,$7,$9,$8,
     $7,$6,$8,$D,$B,$9,$7,$F,$7,$C,$F,$9,$B,$7,$D,$C,
     $B,$D,$6,$7,$E,$9,$D,$F,$E,$8,$D,$6,$5,$C,$7,$5,
     $B,$C,$E,$F,$E,$F,$9,$8,$9,$E,$5,$6,$8,$6,$5,$C,
     $9,$F,$5,$B,$6,$8,$D,$C,$5,$C,$D,$E,$B,$8,$5,$6
      ) ;
  RMD_sd : array [0..79] of byte =
     ( 
     $8,$9,$9,$B,$D,$F,$F,$5,$7,$7,$8,$B,$E,$E,$C,$6,
     $9,$D,$F,$7,$C,$8,$9,$B,$7,$7,$C,$7,$6,$F,$D,$B,
     $9,$7,$F,$B,$8,$6,$6,$E,$C,$D,$5,$E,$D,$D,$7,$5,
     $F,$5,$8,$B,$E,$E,$6,$E,$6,$9,$C,$9,$C,$5,$F,$8,
     $8,$5,$C,$9,$C,$5,$E,$6,$8,$D,$6,$5,$F,$D,$B,$B
      ) ;
  RMD_BLOCKSIZE = 64;   


procedure InitializeRMD160(var Context : TRMD160Context);
begin
  Context.BufSize := 0;
  Context.MessageSizeLo := 0;
  Context.MessageSizeHi := 0;
  Context.h1 := $67452301;
  Context.h2 := $EFCDAB89;
  Context.h3 := $98BADCFE;
  Context.h4 := $10325476;
  Context.h5 := $C3D2E1F0
end;

procedure HashBlockRMD160(var Context : TRMD160Context; var Chunk : TRMD160Buffer);
var
  A, Ad, B, Bd, C, Cd, D, Dd, E, Ed, T, I : longword;
begin
  (*
    f(j, x, y, z) = x XOR y XOR z                (0 <= j <= 15)
    f(j, x, y, z) = (x AND y) OR (NOT(x) AND z)  (16 <= j <= 31)
    f(j, x, y, z) = (x OR NOT(y)) XOR z          (32 <= j <= 47)
    f(j, x, y, z) = (x AND z) OR (y AND NOT(z))  (48 <= j <= 63)
    f(j, x, y, z) = x XOR (y OR NOT(z))          (64 <= j <= 79)
  *)

  A := Context.h1; B := Context.h2; C:= Context.h3;
  D := Context.h4; E := Context.h5;
  Ad := Context.h1; Bd := Context.h2; Cd := Context.h3;
  Dd := Context.h4; Ed := Context.h5;

  { Dividing into 5 steps. And each step has 16 iterations. }
  { Step 1. f(j, X, Y, Z) = X xor Y xor Z for 'left' part }
  {         f(j, x, y, z) = x XOR (y OR NOT(z)) for 'right' part }

  for I := 0 to 15 do
  begin
    T := (A + (B xor C xor D) + Chunk[RMD_r[I]] + RMD_K[0]);
    T := (T shl RMD_s[I]) or (T shr (32 - RMD_S[I])) + E;
    A := E; E := D; D := (C shl 10) or (C shr 22); C := B; B := T;

    T := (Ad + (Bd xor (Cd or (not Dd))) + Chunk[RMD_rd[I]] + RMD_Kd[0]);
    T := (T shl RMD_sd[I]) or (T shr (32 - RMD_Sd[I])) + Ed;
    Ad := Ed; Ed := Dd; Dd := (Cd shl 10) or (Cd shr 22); Cd := Bd; Bd := T;
  end;

  { Step 2. f(j, X, Y, Z) = (x AND y) OR (NOT(x) AND z) for 'left' part }
  {         f(j, x, y, z) = (x AND z) OR (y AND NOT(z)) for 'right' part }

  for I := 16 to 31 do
  begin
    T := (A + ((B and C) or ((not B) and D)) + Chunk[RMD_r[I]] + RMD_K[1]);
    T := (T shl RMD_s[I]) or (T shr (32 - RMD_S[I])) + E;
    A := E; E := D; D := (C shl 10) or (C shr 22); C := B; B := T;

    T := (Ad + ((Bd and Dd) or (Cd and (not Dd))) + Chunk[RMD_rd[I]] + RMD_Kd[1]);
    T := (T shl RMD_sd[I]) or (T shr (32 - RMD_Sd[I])) + Ed;
    Ad := Ed; Ed := Dd; Dd := (Cd shl 10) or (Cd shr 22); Cd := Bd; Bd := T;
  end;

  { Step 3. f(j, X, Y, Z) = (x OR NOT(y)) XOR z for 'left' part }
  {         f(j, x, y, z) = (x OR NOT(y)) XOR z for 'right' part }

  for I := 32 to 47 do
  begin
    T := (A + ((B or (not C)) xor D) + Chunk[RMD_r[I]] + RMD_K[2]);
    T := (T shl RMD_s[I]) or (T shr (32 - RMD_S[I])) + E;
    A := E; E := D; D := (C shl 10) or (C shr 22); C := B; B := T;

    T := (Ad + ((Bd or (not Cd)) xor Dd) + Chunk[RMD_rd[I]] + RMD_Kd[2]);
    T := (T shl RMD_sd[I]) or (T shr (32 - RMD_Sd[I])) + Ed;
    Ad := Ed; Ed := Dd; Dd := (Cd shl 10) or (Cd shr 22); Cd := Bd; Bd := T;
  end;

  { Step 4. f(j, X, Y, Z) = (x AND z) OR (y AND NOT(z)) for 'left' part }
  {         f(j, x, y, z) = (x AND y) OR (NOT(x) AND z) for 'right' part }

  for I := 48 to 63 do
  begin
    T := (A + ((B and D) or (C and (not D))) + Chunk[RMD_r[I]] + RMD_K[3]);
    T := (T shl RMD_s[I]) or (T shr (32 - RMD_S[I])) + E;
    A := E; E := D; D := (C shl 10) or (C shr 22); C := B; B := T;

    T := (Ad + ((Bd and Cd) or ((not Bd) and Dd)) + Chunk[RMD_rd[I]] + RMD_Kd[3]);
    T := (T shl RMD_sd[I]) or (T shr (32 - RMD_Sd[I])) + Ed;
    Ad := Ed; Ed := Dd; Dd := (Cd shl 10) or (Cd shr 22); Cd := Bd; Bd := T;
  end;

  { Step 5. f(j, X, Y, Z) = x XOR (y OR NOT(z)) for 'left' part }
  {         f(j, x, y, z) = x XOR y XOR z for 'right' part }

  for I := 64 to 79 do
  begin
    T := (A + (B xor (C or (not D))) + Chunk[RMD_r[I]] + RMD_K[4]);
    T := (T shl RMD_s[I]) or (T shr (32 - RMD_S[I])) + E;
    A := E; E := D; D := (C shl 10) or (C shr 22); C := B; B := T;

    T := (Ad + (Bd xor Cd xor Dd) + Chunk[RMD_rd[I]] + RMD_Kd[4]);
    T := (T shl RMD_sd[I]) or (T shr (32 - RMD_Sd[I])) + Ed;
    Ad := Ed; Ed := Dd; Dd := (Cd shl 10) or (Cd shr 22); Cd := Bd; Bd := T;
  end;

  { setting h[i] values }
  T := Context.h2 + C + Dd;
  Context.h2 := Context.h3 + D + Ed;
  Context.h3 := Context.h4 + E + Ad;
  Context.h4 := Context.h5 + A + Bd;
  Context.h5 := Context.h1 + B + Cd;
  Context.h1 := T;
end;

procedure HashRMD160(var Context : TRMD160Context; Chunk : pointer; Size : integer);
var
  Index : integer;
begin
  Index := 0;

  while Size - Index + integer(Context.BufSize) >= RMD_BLOCKSIZE do
  begin
    SBMove(PByteArray(Chunk)[Index], PByteArray(@Context.Buffer)[Context.BufSize],
      RMD_BLOCKSIZE - Context.BufSize);
    HashBlockRMD160(Context, Context.Buffer);

    Inc(Context.MessageSizeLo, RMD_BLOCKSIZE);
    if Context.MessageSizeLo < RMD_BLOCKSIZE then
      Inc(Context.MessageSizeHi);

    Inc(Index, RMD_BLOCKSIZE - Context.BufSize);
    Context.BufSize := 0;
  end;

  if Index < (Size) then
  begin
    SBMove(PByteArray(Chunk)[Index], PByteArray(@Context.Buffer)[Context.BufSize],
      Size - Index);
    Context.BufSize := integer(Context.BufSize) + Size - Index;
  end;
end;


function  HashRMD160(Buffer : pointer; Size : integer) : TMessageDigest160;
var
  Context : TRMD160Context;
begin
  InitializeRMD160(Context);
  HashRMD160(Context, Buffer, Size);
  Result := FinalizeRMD160(Context);
end;


function HashRMD160(const Buffer : string) : TMessageDigest160;
{$ifdef SB_UNICODE_VCL}
var
  Buf: ByteArray;
 {$endif}
begin
  if Length(Buffer) > 0 then
  begin
    {$ifndef SB_UNICODE_VCL}
    Result := HashRMD160(@Buffer[StringStartOffset], Length(Buffer));
     {$else}
    Buf := BytesOfString(Buffer);
    Result := HashRMD160(@Buf[0], Length(Buf));
     {$endif}
  end
  else
    Result := HashRMD160(nil, 0);
end;

{$ifdef SB_UNICODE_VCL}
function HashRMD160(const Buffer : ByteArray) : TMessageDigest160; overload;
begin
  if Length(Buffer) > 0 then
    Result := HashRMD160(@Buffer[0], Length(Buffer))
  else
    Result := HashRMD160(nil, 0);
end;
 {$endif}

function FinalizeRMD160(var Context : TRMD160Context) : TMessageDigest160;
begin
  { updating MessageSize }
  Inc(Context.MessageSizeLo, Context.BufSize);
  if (Context.MessageSizeLo < Context.BufSize) then
    Inc(Context.MessageSizeHi);

  { padding : 0x80, 0, 0, ..., LoDWORD(MessageSize), HiDWORD(MessageSize)}
  FillChar(PByteArray(@Context.Buffer[0])[Context.BufSize],
    RMD_BLOCKSIZE - Context.BufSize, 0);

  PByteArray(@Context.Buffer[0])[Context.BufSize] := $80;

  { message bits count must fit into hashing block }
  if Context.BufSize > RMD_BLOCKSIZE - 8 then
  begin
    HashBlockRMD160(Context, Context.Buffer);
    FillChar(Context.Buffer[0], RMD_BLOCKSIZE, 0);
  end;

  { writing message length - in bits }
  Context.Buffer[14] := longword(Context.MessageSizeLo shl 3 );
  Context.Buffer[15] := Context.MessageSizeLo shr 29 or Context.MessageSizeHi shl 3;
  HashBlockRMD160(Context, Context.Buffer);
  Result.A := Context.h1;
  Result.B := Context.h2;
  Result.C := Context.h3;
  Result.D := Context.h4;
  Result.E := Context.h5;

end;

end.
