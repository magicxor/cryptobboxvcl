(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBMD;

interface

uses
  SysUtils,
  SBConstants,
  SBTypes;

type

  TMD5Context =  packed  record
    Size: int64;
    Buffer: array  [0..63]  of byte;
    BufSize: cardinal;
    A, B, C, D: longword;
  end;

{$ifndef SB_NO_MD2}
  TMD2Context =  packed  record
    Size: int64;
    Checksum: array  [0..15]  of byte;
    Buffer: array  [0..15]  of byte;
    BufSize: integer;
    State : array  [0..15]  of byte;
  end;
 {$endif SB_NO_MD2}

procedure InitializeMD5(var Context: TMD5Context); 
function FinalizeMD5(var Context: TMD5Context): TMessageDigest128; 

function HashMD5(Buffer: pointer; Size: cardinal): TMessageDigest128; overload;
function HashMD5(const Buffer: ByteArray): TMessageDigest128;  overload; 
procedure HashMD5(var Context: TMD5Context; Chunk: pointer; Size: cardinal); overload;

procedure InternalMD5(Chunk: PLongWordArray; var A, B, C, D: longword);

{$ifndef SB_NO_MD2}
procedure InitializeMD2(var Context: TMD2Context); 
function FinalizeMD2(var Context: TMD2Context): TMessageDigest128; 
function HashMD2(Buffer: pointer; Size: cardinal): TMessageDigest128; overload;
function HashMD2(const S : ByteArray) : TMessageDigest128; overload;
procedure HashMD2(var Context: TMD2Context; Buffer: pointer; Size: integer); overload;
 {$endif SB_NO_MD2}

implementation

uses
{$ifdef ActiveX_registered}
  SBClientBase,
 {$endif}
  SBUtils;

{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS} // SB_JAVA or SB_DELPHI_MOBILE
var
  Padding: array[0..16] of ByteArray;
 {$else}
const
  Padding: array[1..16] of ByteArray =
    (
     #$01,
     #$02#$02,
     #$03#$03#$03,
     #$04#$04#$04#$04,
     #$05#$05#$05#$05#$05,
     #$06#$06#$06#$06#$06#$06,
     #$07#$07#$07#$07#$07#$07#$07,
     #$08#$08#$08#$08#$08#$08#$08#$08,
     #$09#$09#$09#$09#$09#$09#$09#$09#$09,
     #$0A#$0A#$0A#$0A#$0A#$0A#$0A#$0A#$0A#$0A,
     #$0B#$0B#$0B#$0B#$0B#$0B#$0B#$0B#$0B#$0B#$0B,
     #$0C#$0C#$0C#$0C#$0C#$0C#$0C#$0C#$0C#$0C#$0C#$0C,
     #$0D#$0D#$0D#$0D#$0D#$0D#$0D#$0D#$0D#$0D#$0D#$0D#$0D,
     #$0E#$0E#$0E#$0E#$0E#$0E#$0E#$0E#$0E#$0E#$0E#$0E#$0E#$0E,
     #$0F#$0F#$0F#$0F#$0F#$0F#$0F#$0F#$0F#$0F#$0F#$0F#$0F#$0F#$0F,
     #$10#$10#$10#$10#$10#$10#$10#$10#$10#$10#$10#$10#$10#$10#$10#$10);
 {$endif}


const
  S: array[0..255] of byte =
     ( 
      41,  46,  67, 201, 162, 216, 124,   1,  61,  54,  84, 161, 236, 240,   6,  19,
      98, 167,   5, 243, 192, 199, 115, 140, 152, 147,  43, 217, 188,  76, 130, 202,
      30, 155,  87,  60, 253, 212, 224,  22, 103,  66, 111,  24, 138,  23, 229,  18,
     190,  78, 196, 214, 218, 158, 222,  73, 160, 251, 245, 142, 187,  47, 238, 122,
     169, 104, 121, 145,  21, 178,   7,  63, 148, 194,  16, 137,  11,  34,  95,  33,
     128, 127,  93, 154,  90, 144,  50,  39,  53,  62, 204, 231, 191, 247, 151,   3,
     255,  25,  48, 179,  72, 165, 181, 209, 215,  94, 146,  42, 172,  86, 170, 198,
      79, 184,  56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116,   4, 241,
      69, 157, 112,  89, 100, 113, 135,  32, 134,  91, 207, 101, 230,  45, 168,   2,
      27,  96,  37, 173, 174, 176, 185, 246,  28,  70,  97, 105,  52,  64, 126,  15,
      85,  71, 163,  35, 221,  81, 175,  58, 195,  92, 249, 206, 186, 197, 234,  38,
      44,  83,  13, 110, 133,  40, 132,   9, 211, 223, 205, 244,  65, 129,  77,  82,
     106, 220,  55, 200, 108, 193, 171, 250,  36, 225, 123,   8,  12, 189, 177,  74,
     120, 136, 149, 139, 227,  99, 232, 109, 233, 203, 213, 254,  59,   0,  29,  57,
     242, 239, 183,  14, 102,  88, 208, 228, 166, 119, 114, 248, 235, 117,  75,  10,
      49,  68,  80, 180, 143, 237,  31,  26, 219, 153, 141,  51, 159,  17, 131,  20
     ) ;
  
{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
procedure InitializePadding;
var
  i , j  : integer;
begin
  for i := 1 to 16 do
  begin
    SetLength(Padding[i], i);
    for j := 0 to i - 1 do
      Padding[i][j] := i;
  end;
end;
 {$endif}


procedure InternalMD5(Chunk: PLongWordArray; var A, B, C, D: longword);
var
  SA, SB, SC, SD: longword;
begin
  SA := A; SB := B; SC := C; SD := D;

  // round 1
  Inc(A, ((B and C) or (not B and D)) + Chunk[0] + $D76AA478);
  A := ((A shl 7) or (A shr 25)) + B;
  Inc(D, ((A and B) or (not A and C)) + Chunk[1] + $E8C7B756);
  D := ((D shl 12) or (D shr 20)) + A;
  Inc(C, ((D and A) or (not D and B)) + Chunk[2] + $242070DB);
  C := ((C shl 17) or (C shr 15)) + D;
  Inc(B, ((C and D) or (not C and A)) + Chunk[3] + $C1BDCEEE);
  B := ((B shl 22) or (B shr 10)) + C;
  Inc(A, ((B and C) or (not B and D)) + Chunk[4] + $F57C0FAF);
  A := ((A shl 7) or (A shr 25)) + B;
  Inc(D, ((A and B) or (not A and C)) + Chunk[5] + $4787C62A);
  D := ((D shl 12) or (D shr 20)) + A;
  Inc(C, ((D and A) or (not D and B)) + Chunk[6] + $A8304613);
  C := ((C shl 17) or (C shr 15)) + D;
  Inc(B, ((C and D) or (not C and A)) + Chunk[7] + $FD469501);
  B := ((B shl 22) or (B shr 10)) + C;
  Inc(A, ((B and C) or (not B and D)) + Chunk[8] + $698098D8);
  A := ((A shl 7) or (A shr 25)) + B;
  Inc(D, ((A and B) or (not A and C)) + Chunk[9] + $8B44F7AF);
  D := ((D shl 12) or (D shr 20)) + A;
  Inc(C, ((D and A) or (not D and B)) + Chunk[10] + $FFFF5BB1);
  C := ((C shl 17) or (C shr 15)) + D;
  Inc(B, ((C and D) or (not C and A)) + Chunk[11] + $895CD7BE);
  B := ((B shl 22) or (B shr 10)) + C;
  Inc(A, ((B and C) or (not B and D)) + Chunk[12] + $6B901122);
  A := ((A shl 7) or (A shr 25)) + B;
  Inc(D, ((A and B) or (not A and C)) + Chunk[13] + $FD987193);
  D := ((D shl 12) or (D shr 20)) + A;
  Inc(C, ((D and A) or (not D and B)) + Chunk[14] + $A679438E);
  C := ((C shl 17) or (C shr 15)) + D;
  Inc(B, ((C and D) or (not C and A)) + Chunk[15] + $49B40821);
  B := ((B shl 22) or (B shr 10)) + C;
  // round 2
  Inc(A, ((B and D) or (C and not D)) + Chunk[1] + $F61E2562);
  A := ((A shl 5) or (A shr 27)) + B;
  Inc(D, ((A and C) or (B and not C)) + Chunk[6] + $C040B340);
  D := ((D shl 9) or (D shr 23)) + A;
  Inc(C, ((D and B) or (A and not B)) + Chunk[11] + $265E5A51);
  C := ((C shl 14) or (C shr 18)) + D;
  Inc(B, ((C and A) or (D and not A)) + Chunk[0] + $E9B6C7AA);
  B := ((B shl 20) or (B shr 12)) + C;
  Inc(A, ((B and D) or (C and not D)) + Chunk[5] + $D62F105D);
  A := ((A shl 5) or (A shr 27)) + B;
  Inc(D, ((A and C) or (B and not C)) + Chunk[10] + $2441453);
  D := ((D shl 9) or (D shr 23)) + A;
  Inc(C, ((D and B) or (A and not B)) + Chunk[15] + $D8A1E681);
  C := ((C shl 14) or (C shr 18)) + D;
  Inc(B, ((C and A) or (D and not A)) + Chunk[4] + $E7D3FBC8);
  B := ((B shl 20) or (B shr 12)) + C;
  Inc(A, ((B and D) or (C and not D)) + Chunk[9] + $21E1CDE6);
  A := ((A shl 5) or (A shr 27)) + B;
  Inc(D, ((A and C) or (B and not C)) + Chunk[14] + $C33707D6);
  D := ((D shl 9) or (D shr 23)) + A;
  Inc(C, ((D and B) or (A and not B)) + Chunk[3] + $F4D50D87);
  C := ((C shl 14) or (C shr 18)) + D;
  Inc(B, ((C and A) or (D and not A)) + Chunk[8] + $455A14ED);
  B := ((B shl 20) or (B shr 12)) + C;
  Inc(A, ((B and D) or (C and not D)) + Chunk[13] + $A9E3E905);
  A := ((A shl 5) or (A shr 27)) + B;
  Inc(D, ((A and C) or (B and not C)) + Chunk[2] + $FCEFA3F8);
  D := ((D shl 9) or (D shr 23)) + A;
  Inc(C, ((D and B) or (A and not B)) + Chunk[7] + $676F02D9);
  C := ((C shl 14) or (C shr 18)) + D;
  Inc(B, ((C and A) or (D and not A)) + Chunk[12] + $8D2A4C8A);
  B := ((B shl 20) or (B shr 12)) + C;
  // round 3
  Inc(A, (B xor C xor D) + Chunk[5] + $FFFA3942);
  A := B + ((A shl 4) or (A shr 28));
  Inc(D, (A xor B xor C) + Chunk[8] + $8771F681);
  D := A + ((D shl 11) or (D shr 21));
  Inc(C, (D xor A xor B) + Chunk[11] + $6D9D6122);
  C := D + ((C shl 16) or (C shr 16));
  Inc(B, (C xor D xor A) + Chunk[14] + $FDE5380C);
  B := C + ((B shl 23) or (B shr 9));
  Inc(A, (B xor C xor D) + Chunk[1] + $A4BEEA44);
  A := B + ((A shl 4) or (A shr 28));
  Inc(D, (A xor B xor C) + Chunk[4] + $4BDECFA9);
  D := A + ((D shl 11) or (D shr 21));
  Inc(C, (D xor A xor B) + Chunk[7] + $F6BB4B60);
  C := D + ((C shl 16) or (C shr 16));
  Inc(B, (C xor D xor A) + Chunk[10] + $BEBFBC70);
  B := C + ((B shl 23) or (B shr 9));
  Inc(A, (B xor C xor D) + Chunk[13] + $289B7EC6);
  A := B + ((A shl 4) or (A shr 28));
  Inc(D, (A xor B xor C) + Chunk[0] + $EAA127FA);
  D := A + ((D shl 11) or (D shr 21));
  Inc(C, (D xor A xor B) + Chunk[3] + $D4EF3085);
  C := D + ((C shl 16) or (C shr 16));
  Inc(B, (C xor D xor A) + Chunk[6] + $4881D05);
  B := C + ((B shl 23) or (B shr 9));
  Inc(A, (B xor C xor D) + Chunk[9] + $D9D4D039);
  A := B + ((A shl 4) or (A shr 28));
  Inc(D, (A xor B xor C) + Chunk[12] + $E6DB99E5);
  D := A + ((D shl 11) or (D shr 21));
  Inc(C, (D xor A xor B) + Chunk[15] + $1FA27CF8);
  C := D + ((C shl 16) or (C shr 16));
  Inc(B, (C xor D xor A) + Chunk[2] + $C4AC5665);
  B := C + ((B shl 23) or (B shr 9));
  // round 4
  Inc(A, (C xor (B or not D)) + Chunk[0] + $F4292244);
  A := B + ((A shl 6) or (A shr 26));
  Inc(D, (B xor (A or not C)) + Chunk[7] + $432AFF97);
  D := A + ((D shl 10) or (D shr 22));
  Inc(C, (A xor (D or not B)) + Chunk[14] + $AB9423A7);
  C := D + ((C shl 15) or (C shr 17));
  Inc(B, (D xor (C or not A)) + Chunk[5] + $FC93A039);
  B := C + ((B shl 21) or (B shr 11));
  Inc(A, (C xor (B or not D)) + Chunk[12] + $655B59C3);
  A := B + ((A shl 6) or (A shr 26));
  Inc(D, (B xor (A or not C)) + Chunk[3] + $8F0CCC92);
  D := A + ((D shl 10) or (D shr 22));
  Inc(C, (A xor (D or not B)) + Chunk[10] + $FFEFF47D);
  C := D + ((C shl 15) or (C shr 17));
  Inc(B, (D xor (C or not A)) + Chunk[1] + $85845DD1);
  B := C + ((B shl 21) or (B shr 11));
  Inc(A, (C xor (B or not D)) + Chunk[8] + $6FA87E4F);
  A := B + ((A shl 6) or (A shr 26));
  Inc(D, (B xor (A or not C)) + Chunk[15] + $FE2CE6E0);
  D := A + ((D shl 10) or (D shr 22));
  Inc(C, (A xor (D or not B)) + Chunk[6] + $A3014314);
  C := D + ((C shl 15) or (C shr 17));
  Inc(B, (D xor (C or not A)) + Chunk[13] + $4E0811A1);
  B := C + ((B shl 21) or (B shr 11));
  Inc(A, (C xor (B or not D)) + Chunk[4] + $F7537E82);
  A := B + ((A shl 6) or (A shr 26));
  Inc(D, (B xor (A or not C)) + Chunk[11] + $BD3AF235);
  D := A + ((D shl 10) or (D shr 22));
  Inc(C, (A xor (D or not B)) + Chunk[2] + $2AD7D2BB);
  C := D + ((C shl 15) or (C shr 17));
  Inc(B, (D xor (C or not A)) + Chunk[9] + $EB86D391);
  B := C + ((B shl 21) or (B shr 11));

  Inc(A, SA); Inc(B, SB); Inc(C, SC); Inc(D, SD);
end;

function HashMD5(const Buffer: ByteArray): TMessageDigest128;
begin
  Result := HashMD5( @Buffer[0] , Length(Buffer));
end;

function HashMD5(Buffer: pointer; Size: cardinal): TMessageDigest128;
var
  Count64: int64;
  T, I, ToAdd: cardinal;
  Addon: array[0..127] of byte;
  Chunk: PLongWordArray;
begin

  // intializing
  Result.A := {$ifdef ActiveX_registered}Constant1 {$else}$67452301 {$endif};
  Result.B := $EFCDAB89;
  Result.C := $98BADCFE;
  Result.D := $10325476;
  Count64 := Size shl 3;
  FillChar(Addon, SizeOf(Addon), 0);

  // processing
  T := Size mod 64;
  if 56 - Integer(T) <= 0 then
    ToAdd := 120 - T
  else
    ToAdd := 56 - T;
  Addon[T] := $80;

  SBMove(Pointer(PtrUInt(Buffer) + Size - T)^, Addon[0], T);
  PLongWord(@Addon[ToAdd + T])^ := PLongWord(@Count64)^;
  PLongWord(@Addon[ToAdd + T + 4])^ := PLongWord(PtrUInt(@Count64) + 4)^;


  I := 0;
  repeat
    // transforming
    if I + 64 <= Size then
      Chunk := Pointer(PtrUInt(Buffer) + I)
    else
      if I <= Size then
        Chunk := @Addon[0]
      else
        Chunk := @Addon[64];
    InternalMD5(Chunk, Result.A, Result.B, Result.C, Result.D);
    Inc(I, 64);
  until I = Size + ToAdd + 8;

end;

procedure InitializeMD5(var Context: TMD5Context);
begin
  Context.Size := 0;
  FillChar(Context.Buffer, SizeOf(Context.Buffer), 0);

  Context.BufSize := 0;
  Context.A := {$ifdef ActiveX_registered}Constant1 {$else}$67452301 {$endif};
  Context.B := $EFCDAB89;
  Context.C := $98BADCFE;
  Context.D := $10325476;
end;

procedure HashMD5(var Context: TMD5Context; Chunk: pointer; Size: cardinal);
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
      {$ifdef D_16_UP}
      Chunk := Pointer(PtrUInt(Chunk) + Left);
       {$else}
      Inc(PtrUInt(Chunk), Left);
       {$endif}
      Dec(Size, Left);

      InternalMD5(Pointer(@Context.Buffer), Context.A, Context.B,
        Context.C, Context.D);
      Context.BufSize := 0;
    end;
  end;
  I := 0;
  while Size >= 64 do
  begin
    InternalMD5(Pointer(PtrUInt(Chunk) + I), Context.A, Context.B,
      Context.C, Context.D);
    Inc(I, 64);
    Dec(Size, 64);
  end;
  if Size > 0 then
  begin
    SBMove(Pointer(PtrUInt(Chunk) + I)^, Context.Buffer[0], Size);
    Context.BufSize := Size;
  end;

end;

function FinalizeMD5(var Context: TMD5Context): TMessageDigest128;
var
  ToAdd, ToDo: cardinal;
  Size64: int64;
  Tail: array[0..127] of byte;
begin

  FillChar(Tail[0], SizeOf(Tail), 0);
  Size64 := Context.Size shl 3;
  if 56 - Integer(Context.BufSize) <= 0 then
    ToAdd := 120 - Context.BufSize
  else
    ToAdd := 56 - Context.BufSize;
  if Context.BufSize > 0 then
    SBMove(Context.Buffer[0], Tail[0], Context.BufSize);

  Tail[Context.BufSize] := $80;

  ToDo := Context.BufSize + ToAdd;

  PLongWord(@Tail[ToDo])^ := PLongWord(@Size64)^;
  Inc(ToDo, 4);
  PLongWord(@Tail[ToDo])^ := PLongWord(PtrUInt(@Size64) + 4)^;
  Inc(ToDo, 4);
  InternalMD5(@Tail[0], Context.A, Context.B, Context.C, Context.D);
  if ToDo > 64 then
    InternalMD5(@Tail[64], Context.A, Context.B, Context.C, Context.D);

  Result.A := Context.A; Result.B := Context.B;
  Result.C := Context.C; Result.D := Context.D;

end;

function HashMD2(Buffer: pointer; Size: cardinal) : TMessageDigest128;
var
  Addon: array [0..15] of byte;
  CheckSum: array [0..15] of byte;
  X: array [0..47] of byte;
  Chunk: PByteArray;
  I, ToAdd: cardinal;
  J, T : Cardinal;
  K, L : integer;
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  // initializing
  FillChar(X, SizeOf(X), 0);
  FillChar(CheckSum, SizeOf(CheckSum), 0);

  // processing
  ToAdd := Size mod 16;

  if ToAdd > 0 then
    SBMove(Pointer(PtrUInt(Buffer) + Size - ToAdd)^, Addon[0], ToAdd);
  SBMove(PByte(Padding[16 - ToAdd])^, Addon[ToAdd], 16 - ToAdd);
  L := 0;
  I := 0;
  repeat
    if I + 16 <= Size then
      Chunk := Pointer(PtrUInt(Buffer) + I)
    else
      Chunk := @Addon[0];
    for J := 0 to 15 do
    begin
      CheckSum[J] := CheckSum[J] xor S[Chunk^[J] xor L];
      L := CheckSum[J];
    end;
    Inc(I, 16);
  until I = Size + 16 - ToAdd;
  I := 0;
  repeat
    if I + 16 <= Size then
      Chunk := Pointer(PtrUInt(Buffer) + I)
    else
    if I <= Size then
      Chunk := @Addon[0]
    else
      Chunk := @CheckSum[0];
    for J := 0 to 15 do
    begin
      X[16 + J] := Chunk^[J];
      X[32 + J] := Chunk^[J] xor X[J];
    end;
    T := 0;
    for J := 0 to 17 do
    begin
      for K := 0 to 47 do
      begin
        T := X[K] xor S[T];
        X[K] := T;
      end;
      T := (T + J) and $FF;
    end;
    Inc(I, 16);
  until I = Size + 32 - ToAdd;
  // finalizing

  Result.A := PLongWord(@X[0])^; Result.B := PLongWord(@X[4])^;
  Result.C := PLongWord(@X[8])^; Result.D := PLongWord(@X[12])^;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

{$ifndef SB_NO_MD2}
function HashMD2(const S : ByteArray) : TMessageDigest128;
begin
  Result := HashMD2(@S[0], Length(S));
end;

procedure InitializeMD2(var Context: TMD2Context);
begin
  Context.Size := 0;
  FillChar(Context.Checksum[0], 16, 0);
  FillChar(Context.Buffer[0], 16, 0);
  FillChar(Context.State[0], 16, 0);
  Context.BufSize := 0;
end;

procedure MD2ProcessBlock(var Context: TMD2Context; Buffer: pointer);
var
  J, K : integer;
  T : integer;
  X : array[0..47] of byte;
begin
  SBMove(Context.State[0], X[0], 16);
  SBMove(Buffer^, X[16], 16);
  for J := 0 to 15 do
    X[32 + J] := Context.State[J] xor  PByteArray (Buffer)[J];
  T := 0;
  for J := 0 to 17 do
  begin
    for K := 0 to 47 do
    begin
      X[K] := X[K] xor S[T];
      T := X[K];
    end;
    T := (T + J) and $ff;
  end;
  SBMove(X[0], Context.State[0], 16);
  T := Context.Checksum[15];
  for J := 0 to 15 do
  begin
    Context.Checksum[J] := Context.Checksum[J] xor S[ PByteArray (Buffer)[J] xor T];
    T := Context.Checksum[J];
  end;
end;

function FinalizeMD2(var Context: TMD2Context): TMessageDigest128;
var
  ToAdd : integer;
  Checksum : array [0..15]  of byte;
begin

  // appending trailer
  ToAdd := 16 - Context.BufSize;
  HashMD2(Context, @Padding[ToAdd][0], Length(Padding[ToAdd]));
  // appending checksum
  SBMove(Context.Checksum[0], Checksum[0], 16);
  HashMD2(Context, @Checksum[0], 16);
  // result=x[0]..x[15]
  SBMove(Context.State[0], Result, 16);

end;

procedure HashMD2(var Context: TMD2Context; Buffer: pointer; Size: integer);
var
  Len : integer;
begin
  Inc(Context.Size, Size);
  // processing trailer of the previous block
  Len := Min(16 - Context.BufSize, Size);
  SBMove(Buffer^, Context.Buffer[Context.BufSize], Len);
  Inc(Context.BufSize, Len);
  if (Context.BufSize < 16) then
    // not enough data
    Exit;
  MD2ProcessBlock(Context, @Context.Buffer[0]);
  Context.BufSize := 0;
  // processing as much data as possible
  Buffer := @PByteArray(Buffer)[Len];
  Dec(Size, Len);
  while Size >= 16 do
  begin
    MD2ProcessBlock(Context, Buffer);
    Buffer := @PByteArray(Buffer)[16];
    Dec(Size, 16);
  end;
  // writing trailer to context
  SBMove(Buffer^, Context.Buffer[0], Size);
  Context.BufSize := Size;
end;
 {$endif SB_NO_MD2}

{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
initialization 
  InitializePadding;
 {$endif}

end.
