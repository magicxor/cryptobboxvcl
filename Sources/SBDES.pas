
(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$i SecBbox.inc}

unit SBDES;

interface

uses
  Classes,
  SysUtils,
  SBTypes,
  SBUtils;


const
  TDESBufferSize = 8;
  TDESKeySize = 8;
  TDESExpandedKeySize = 16 * 48;
  T3DESBufferSize = 8;
  T3DESKeySize = 24;
  T3DESExpandedKeySize = 16 * 48 * 3;

type
  TDESExpandedKey = array[0..31] of longword;

// Key expansion routine
procedure ExpandKeyForEncryption(const Key: ByteArray; var ExpandedKey : TDESExpandedKey); 
procedure ExpandKeyForDecryption(const Key: ByteArray; var ExpandedKey : TDESExpandedKey); 
// Block processing routines
procedure Encrypt(var B0, B1 : cardinal; const ExpandedKey : TDESExpandedKey); 
procedure EncryptEDE(var B0, B1 : cardinal; const Key1, Key2, Key3 : TDESExpandedKey); 
{ the code for decryption is the same as for encryption, difference is in key expansion }

implementation

const
  // permuted choice table (key) ported from C++
  PC1: array[0..55] of byte =   ( 
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,

    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
      ) ;

  // permuted choice key (table)
  PC2: array[0..47] of byte =   ( 
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32  ) ;

  // bit 0 is left-most in byte
  bytebit: array[0..7] of cardinal =   ( 
    {-$0100,} $0080, $040, $020, $010, $08, $04, $02, $01  ) ;

  // number left rotations of pc1 */
  totrot: array[0..15] of byte =   ( 
    1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28  ) ;

  S0 : array [0..63] of cardinal =   ( 
    $01010400, $00000000, $00010000, $01010404, $01010004, $00010404, $00000004, $00010000,
    $00000400, $01010400, $01010404, $00000400, $01000404, $01010004, $01000000, $00000004,
    $00000404, $01000400, $01000400, $00010400, $00010400, $01010000, $01010000, $01000404,
    $00010004, $01000004, $01000004, $00010004, $00000000, $00000404, $00010404, $01000000,
    $00010000, $01010404, $00000004, $01010000, $01010400, $01000000, $01000000, $00000400,
    $01010004, $00010000, $00010400, $01000004, $00000400, $00000004, $01000404, $00010404,
    $01010404, $00010004, $01010000, $01000404, $01000004, $00000404, $00010404, $01010400,
    $00000404, $01000400, $01000400, $00000000, $00010004, $00010400, $00000000, $01010004  ) ;

  S1 : array [0..63] of cardinal =   ( 
    $80108020, $80008000, $00008000, $00108020, $00100000, $00000020, $80100020, $80008020,
    $80000020, $80108020, $80108000, $80000000, $80008000, $00100000, $00000020, $80100020,
    $00108000, $00100020, $80008020, $00000000, $80000000, $00008000, $00108020, $80100000,
    $00100020, $80000020, $00000000, $00108000, $00008020, $80108000, $80100000, $00008020,
    $00000000, $00108020, $80100020, $00100000, $80008020, $80100000, $80108000, $00008000,
    $80100000, $80008000, $00000020, $80108020, $00108020, $00000020, $00008000, $80000000,
    $00008020, $80108000, $00100000, $80000020, $00100020, $80008020, $80000020, $00100020,
    $00108000, $00000000, $80008000, $00008020, $80000000, $80100020, $80108020, $00108000  ) ;

  S2 : array [0..63] of cardinal =   ( 
    $00000208, $08020200, $00000000, $08020008, $08000200, $00000000, $00020208, $08000200,
    $00020008, $08000008, $08000008, $00020000, $08020208, $00020008, $08020000, $00000208,
    $08000000, $00000008, $08020200, $00000200, $00020200, $08020000, $08020008, $00020208,
    $08000208, $00020200, $00020000, $08000208, $00000008, $08020208, $00000200, $08000000,
    $08020200, $08000000, $00020008, $00000208, $00020000, $08020200, $08000200, $00000000,
    $00000200, $00020008, $08020208, $08000200, $08000008, $00000200, $00000000, $08020008,
    $08000208, $00020000, $08000000, $08020208, $00000008, $00020208, $00020200, $08000008,
    $08020000, $08000208, $00000208, $08020000, $00020208, $00000008, $08020008, $00020200  ) ;

  S3 : array [0..63] of cardinal =   ( 
    $00802001, $00002081, $00002081, $00000080, $00802080, $00800081, $00800001, $00002001,
    $00000000, $00802000, $00802000, $00802081, $00000081, $00000000, $00800080, $00800001,
    $00000001, $00002000, $00800000, $00802001, $00000080, $00800000, $00002001, $00002080,
    $00800081, $00000001, $00002080, $00800080, $00002000, $00802080, $00802081, $00000081,
    $00800080, $00800001, $00802000, $00802081, $00000081, $00000000, $00000000, $00802000,
    $00002080, $00800080, $00800081, $00000001, $00802001, $00002081, $00002081, $00000080,
    $00802081, $00000081, $00000001, $00002000, $00800001, $00002001, $00802080, $00800081,
    $00002001, $00002080, $00800000, $00802001, $00000080, $00800000, $00002000, $00802080  ) ;

  S4 : array [0..63] of cardinal =   ( 
    $00000100, $02080100, $02080000, $42000100, $00080000, $00000100, $40000000, $02080000,
    $40080100, $00080000, $02000100, $40080100, $42000100, $42080000, $00080100, $40000000,
    $02000000, $40080000, $40080000, $00000000, $40000100, $42080100, $42080100, $02000100,
    $42080000, $40000100, $00000000, $42000000, $02080100, $02000000, $42000000, $00080100,
    $00080000, $42000100, $00000100, $02000000, $40000000, $02080000, $42000100, $40080100,
    $02000100, $40000000, $42080000, $02080100, $40080100, $00000100, $02000000, $42080000,
    $42080100, $00080100, $42000000, $42080100, $02080000, $00000000, $40080000, $42000000,
    $00080100, $02000100, $40000100, $00080000, $00000000, $40080000, $02080100, $40000100  ) ;

  S5 : array [0..63] of cardinal =   ( 
    $20000010, $20400000, $00004000, $20404010, $20400000, $00000010, $20404010, $00400000,
    $20004000, $00404010, $00400000, $20000010, $00400010, $20004000, $20000000, $00004010,
    $00000000, $00400010, $20004010, $00004000, $00404000, $20004010, $00000010, $20400010,
    $20400010, $00000000, $00404010, $20404000, $00004010, $00404000, $20404000, $20000000,
    $20004000, $00000010, $20400010, $00404000, $20404010, $00400000, $00004010, $20000010,
    $00400000, $20004000, $20000000, $00004010, $20000010, $20404010, $00404000, $20400000,
    $00404010, $20404000, $00000000, $20400010, $00000010, $00004000, $20400000, $00404010,
    $00004000, $00400010, $20004010, $00000000, $20404000, $20000000, $00400010, $20004010  ) ;

  S6 : array [0..63] of cardinal =   ( 
    $00200000, $04200002, $04000802, $00000000, $00000800, $04000802, $00200802, $04200800,
    $04200802, $00200000, $00000000, $04000002, $00000002, $04000000, $04200002, $00000802,
    $04000800, $00200802, $00200002, $04000800, $04000002, $04200000, $04200800, $00200002,
    $04200000, $00000800, $00000802, $04200802, $00200800, $00000002, $04000000, $00200800,
    $04000000, $00200800, $00200000, $04000802, $04000802, $04200002, $04200002, $00000002,
    $00200002, $04000000, $04000800, $00200000, $04200800, $00000802, $00200802, $04200800,
    $00000802, $04000002, $04200802, $04200000, $00200800, $00000000, $00000002, $04200802,
    $00000000, $00200802, $04200000, $00000800, $04000002, $04000800, $00000800, $00200002  ) ;

  S7 : array [0..63] of cardinal =   ( 
    $10001040, $00001000, $00040000, $10041040, $10000000, $10001040, $00000040, $10000000,
    $00040040, $10040000, $10041040, $00041000, $10041000, $00041040, $00001000, $00000040,
    $10040000, $10000040, $10001000, $00001040, $00041000, $00040040, $10040040, $10041000,
    $00001040, $00000000, $00000000, $10040040, $10000040, $10001000, $00041040, $00040000,
    $00041040, $00040000, $10041000, $00001000, $00000040, $10040040, $00001000, $00041040,
    $10001000, $00000040, $10000040, $10040000, $10040040, $10000000, $00040000, $10001040,
    $00000000, $10041040, $00040040, $10000040, $10040000, $10001000, $10001040, $00000000,
    $10041040, $00041000, $00041000, $00001040, $00001040, $00040040, $10000000, $10041000  ) ;


// Key expansion routine

procedure ExpandKeyForEncryption(const Key: ByteArray; var ExpandedKey : TDESExpandedKey);
var
  K: array[0..31] of cardinal;
  Buffer: array[0..56 + 56 + 8 - 1] of byte;
  pc1m: PByteArray;
  pcr: PByteArray;
  ks: PByteArray;
  i, j, l, m: Cardinal;
  A, B: Cardinal;
begin
  FillChar(Buffer[0], SizeOf(Buffer), 0);
  FillChar(K[0], SizeOf(K), 0);

  pc1m := @buffer; // place to modify pc1 into
  pcr := Pointer(PtrUInt(pc1m) + 56); // place to rotate pc1 into
  ks := Pointer(PtrUInt(pcr) + 56);

  for j := 0 to 55 do // convert pc1 to bits of key
  begin
    l := pc1[j] - 1; // integer bit location
    m := l and 07; // find bit
  // pc1m[j] := (key [l shr 3] and bytebit[m]) ? 1 : 0;
    if (key[l shr 3] and bytebit[m]) > 0 then
      pc1m[j] := 1
    else
      pc1m[j] := 0;
  end;

  for i := 0 to 15 do // key chunk for each iteration
  begin
    FillChar(ks^, 8, 0); // Clear key schedule
    for j := 0 to 55 do // rotate pc1 the right amount
    begin
   //pcr[j] := pc1m[(l=j+totrot[i])<(j<28? 28 : 56) ? l: l-28];
      if j < 28 then
        A := 28
      else
        A := 56;
      l := j + totrot[i];
      if l < A then
        B := l
      else
        B := l - 28;
      pcr[j] := pc1m[B];
    end;
    for j := 0 to 47 do
    begin
      if (pcr[pc2[j] - 1]) > 0 then
      begin
        l := j mod 6;
        ks[j div 6] := (ks[j div 6]) or (bytebit[l] shr 2);
      end;
    end;
    k[i shl 1] := (cardinal(ks[0]) shl 24)
      or (cardinal(ks[2]) shl 16)
      or (cardinal(ks[4]) shl 8)
      or (cardinal(ks[6]));
    k[i shl 1 + 1] := (cardinal(ks[1]) shl 24)
      or (cardinal(ks[3]) shl 16)
      or (cardinal(ks[5]) shl 8)
      or (cardinal(ks[7]));
  end;

  for i := 0 to 31 do
    ExpandedKey[i]  := k[i];
end;

procedure ExpandKeyForDecryption(const Key: ByteArray; var ExpandedKey : TDESExpandedKey);
var
  K: array[0..31] of cardinal;
  Buffer: array[0..56 + 56 + 8 - 1] of byte;
  pc1m: PByteArray;
  pcr: PByteArray;
  ks: PByteArray;
  i, j, l, m: Cardinal;
  A, B: Cardinal;
  swap: Cardinal;
begin
  FillChar(Buffer[0], SizeOf(Buffer), 0);
  FillChar(K[0], SizeOf(K), 0);

  pc1m := @buffer; // place to modify pc1 into
  pcr := Pointer(PtrUInt(pc1m) + 56); // place to rotate pc1 into
  ks := Pointer(PtrUInt(pcr) + 56);

  for j := 0 to 55 do // convert pc1 to bits of key
  begin
    l := pc1[j] - 1; // integer bit location
    m := l and 07; // find bit
  // pc1m[j] := (key [l shr 3] and bytebit[m]) ? 1 : 0;
    if (key[l shr 3] and bytebit[m]) > 0 then
      pc1m[j] := 1
    else
      pc1m[j] := 0;
  end;

  for i := 0 to 15 do // key chunk for each iteration
  begin
    fillChar(ks^, 8, 0); // Clear key schedule
    for j := 0 to 55 do // rotate pc1 the right amount
    begin
   //pcr[j] := pc1m[(l=j+totrot[i])<(j<28? 28 : 56) ? l: l-28];
      if j < 28 then
        A := 28
      else
        A := 56;
      l := j + totrot[i];
      if l < A then
        B := l
      else
        B := l - 28;
      pcr[j] := pc1m[B];
    end;
    for j := 0 to 47 do
    begin
      if (pcr[pc2[j] - 1]) > 0 then
      begin
        l := j mod 6;
        ks[j div 6] := (ks[j div 6]) or (bytebit[l] shr 2);
      end;
    end;
    k[i shl 1] := (cardinal(ks[0]) shl 24)
      or (cardinal(ks[2]) shl 16)
      or (cardinal(ks[4]) shl 8)
      or (cardinal(ks[6]));
    k[i shl 1 + 1] := (cardinal(ks[1]) shl 24)
      or (cardinal(ks[3]) shl 16)
      or (cardinal(ks[5]) shl 8)
      or (cardinal(ks[7]));
  end;

  for j := 0 to 7 do
  begin
    i := j shl 1;
    swap := k[i];
    k[i] := k[32 - 2 - i];
    k[32 - 2 - i] := swap;

    swap := k[i + 1];
    k[i + 1] := k[32 - 1 - i];
    k[32 - 1 - i] := swap;
  end;

  for i := 0 to 31 do
    ExpandedKey[i] := k[i];
end;

// procedures for DES and 3DES

function rotlFixed(x: Cardinal; y: word): Cardinal;
begin
  result := (x shl y) or (x shr (32 - y));
end;

function rotrFixed(x: Cardinal; y: word): Cardinal;
begin
  result := (x shr y) or (x shl (32 - y));
end;

function byteReverse(value: Cardinal): Cardinal;
begin
 // 5 instructions with rotate instruction, 9 without
  result := (rotrFixed(value, 8) and $FF00FF00) or (rotlFixed(value, 8) and
    $00FF00FF);
end;

procedure IPERM(var left, right: Cardinal);
var
  work: Cardinal;
begin
  right := (right shl 4) or (right shr 28);
  work := (left xor right) and $F0F0F0F0;
  left := left xor work;
  right := right xor work;
  right := (right shr 20) or (right shl 12);
  work := (left xor right) and $FFFF0000;
  left := left xor work;
  right := right xor work;
  right := (right shr 18) or (right shl 14);
  work := (left xor right) and $33333333;
  left := left xor work;
  right := right xor work;
  right := (right shr 6) or (right shl 26);
  work := (left xor right) and $00FF00FF;
  left := left xor work;
  right := right xor work;
  right := (right shl 9) or (right shr 23);
  work := (left xor right) and $AAAAAAAA;
  left := left xor work;
  left := (left shl 1) or (left shr 31);
  right := right xor work;
end;

procedure FPERM(var left, right: Cardinal);
var
  work: Cardinal;
begin
  right := (right shr 1) or (right shl 31);
  work := (left xor right) and $AAAAAAAA;
  right := right xor work;
  left := left xor work;
  left := (left shr 9) or (left shl 23);
  work := (left xor right) and $00FF00FF;
  right := right xor work;
  left := left xor work;
  left := (left shl 6) or (left shr 26);
  work := (left xor right) and $33333333;
  right := right xor work;
  left := left xor work;
  left := (left shl 18) or (left shr 14);
  work := (left xor right) and $FFFF0000;
  right := right xor work;
  left := left xor work;
  left := (left shl 20) or (left shr 12);
  work := (left xor right) and $F0F0F0F0;
  right := right xor work;
  left := left xor work;
  left := (left shr 4) or (left shl 28);
end;


procedure Encrypt(var B0, B1 : cardinal; const ExpandedKey : TDESExpandedKey);
var
  l, r, work: Cardinal;
  i: integer;
begin
  { DES implementation uses big-endian input, but cryptoproviders uses little-endian }
  l := (B0 shr 24) or ((B0 shr 8) and $ff00) or ((B0 shl 8) and $ff0000) or (B0 shl 24);
  r := (B1 shr 24) or ((B1 shr 8) and $ff00) or ((B1 shl 8) and $ff0000) or (B1 shl 24);

  { initial permutation }

  r := (r shl 4) or (r shr 28);
  work := (l xor r) and $F0F0F0F0;
  l := l xor work;
  r := r xor work;
  r := (r shr 20) or (r shl 12);
  work := (l xor r) and $FFFF0000;
  l := l xor work;
  r := r xor work;
  r := (r shr 18) or (r shl 14);
  work := (l xor r) and $33333333;
  l := l xor work;
  r := r xor work;
  r := (r shr 6) or (r shl 26);
  work := (l xor r) and $00FF00FF;
  l := l xor work;
  r := r xor work;
  r := (r shl 9) or (r shr 23);
  work := (l xor r) and $AAAAAAAA;
  l := l xor work;
  l := (l shl 1) or (l shr 31);
  r := r xor work;


  { 8 rounds }
  for i := 0 to 7 do
  begin
    work := (r shr 4) or (r shl 28) xor ExpandedKey[i shl 2 + 0];
    l := l xor S6[(work) and $3F] xor S4[(work shr 8) and $3F] xor S2[(work shr 16) and $3F] xor S0[(work shr 24) and $3F];
    work := r xor ExpandedKey[i shl 2 + 1];
    l := l xor S7[(work) and $3F] xor S5[(work shr 8) and $3F] xor S3[(work shr 16) and $3F] xor S1[(work shr 24) and $3F];
    work := (l shr 4) or (l shl 28) xor ExpandedKey[i shl 2 + 2];
    r := r xor S6[(work) and $3F] xor S4[(work shr 8) and $3F] xor S2[(work shr 16) and $3F] xor S0[(work shr 24) and $3F];
    work := l xor ExpandedKey[i shl 2 + 3];
    r := r xor S7[(work) and $3F] xor S5[(work shr 8) and $3F] xor S3[(work shr 16) and $3F] xor S1[(work shr 24) and $3F];
  end;

  { final permutation }
  r := (r shr 1) or (r shl 31);
  work := (l xor r) and $AAAAAAAA;
  r := r xor work;
  l := l xor work;
  l := (l shr 9) or (l shl 23);
  work := (l xor r) and $00FF00FF;
  r := r xor work;
  l := l xor work;
  l := (l shl 6) or (l shr 26);
  work := (l xor r) and $33333333;
  r := r xor work;
  l := l xor work;
  l := (l shl 18) or (l shr 14);
  work := (l xor r) and $FFFF0000;
  r := r xor work;
  l := l xor work;
  l := (l shl 20) or (l shr 12);
  work := (l xor r) and $F0F0F0F0;
  r := r xor work;
  l := l xor work;
  l := (l shr 4) or (l shl 28);

  B0 := (r shr 24) or ((r shr 8) and $ff00) or ((r shl 8) and $ff0000) or (r shl 24);
  B1 := (l shr 24) or ((l shr 8) and $ff00) or ((l shl 8) and $ff0000) or (l shl 24);
end;

procedure EncryptEDE(var B0, B1 : cardinal; const Key1, Key2, Key3 : TDESExpandedKey);
var
  l, r, work: Cardinal;
  i: integer;
begin
  { DES implementation uses big-endian input, but cryptoproviders uses little-endian }
  l := (B0 shr 24) or ((B0 shr 8) and $ff00) or ((B0 shl 8) and $ff0000) or (B0 shl 24);
  r := (B1 shr 24) or ((B1 shr 8) and $ff00) or ((B1 shl 8) and $ff0000) or (B1 shl 24);

  { initial permutation}
  r := (r shl 4) or (r shr 28);
  work := (l xor r) and $F0F0F0F0;
  l := l xor work;
  r := r xor work;
  r := (r shr 20) or (r shl 12);
  work := (l xor r) and $FFFF0000;
  l := l xor work;
  r := r xor work;
  r := (r shr 18) or (r shl 14);
  work := (l xor r) and $33333333;
  l := l xor work;
  r := r xor work;
  r := (r shr 6) or (r shl 26);
  work := (l xor r) and $00FF00FF;
  l := l xor work;
  r := r xor work;
  r := (r shl 9) or (r shr 23);
  work := (l xor r) and $AAAAAAAA;
  l := l xor work;
  l := (l shl 1) or (l shr 31);
  r := r xor work;

  { first key part }

  for i := 0 to 7 do
  begin
    work := (r shr 4) or (r shl 28) xor Key1[i shl 2 + 0];
    l := l xor S6[(work) and $3F] xor S4[(work shr 8) and $3F] xor S2[(work shr 16) and $3F] xor S0[(work shr 24) and $3F];
    work := r xor Key1[i shl 2 + 1];
    l := l xor S7[(work) and $3F] xor S5[(work shr 8) and $3F] xor S3[(work shr 16) and $3F] xor S1[(work shr 24) and $3F];
    work := (l shr 4) or (l shl 28) xor Key1[i shl 2 + 2];
    r := r xor S6[(work) and $3F] xor S4[(work shr 8) and $3F] xor S2[(work shr 16) and $3F] xor S0[(work shr 24) and $3F];
    work := l xor Key1[i shl 2 + 3];
    r := r xor S7[(work) and $3F] xor S5[(work shr 8) and $3F] xor S3[(work shr 16) and $3F] xor S1[(work shr 24) and $3F];
  end;

  { second key part }
  { intermediate IPERM/FPERM are skipped since they opposite to each other, only need to exchange l and r }
  work := l;
  l := r;
  r := work;

  for i := 0 to 7 do
  begin
    work := (r shr 4) or (r shl 28) xor Key2[i shl 2 + 0];
    l := l xor S6[(work) and $3F] xor S4[(work shr 8) and $3F] xor S2[(work shr 16) and $3F] xor S0[(work shr 24) and $3F];
    work := r xor Key2[i shl 2 + 1];
    l := l xor S7[(work) and $3F] xor S5[(work shr 8) and $3F] xor S3[(work shr 16) and $3F] xor S1[(work shr 24) and $3F];
    work := (l shr 4) or (l shl 28) xor Key2[i shl 2 + 2];
    r := r xor S6[(work) and $3F] xor S4[(work shr 8) and $3F] xor S2[(work shr 16) and $3F] xor S0[(work shr 24) and $3F];
    work := l xor Key2[i shl 2 + 3];
    r := r xor S7[(work) and $3F] xor S5[(work shr 8) and $3F] xor S3[(work shr 16) and $3F] xor S1[(work shr 24) and $3F];
  end;

  { third key part }
  work := l;
  l := r;
  r := work;

  for i := 0 to 7 do
  begin
    work := (r shr 4) or (r shl 28) xor Key3[i shl 2 + 0];
    l := l xor S6[(work) and $3F] xor S4[(work shr 8) and $3F] xor S2[(work shr 16) and $3F] xor S0[(work shr 24) and $3F];
    work := r xor Key3[i shl 2 + 1];
    l := l xor S7[(work) and $3F] xor S5[(work shr 8) and $3F] xor S3[(work shr 16) and $3F] xor S1[(work shr 24) and $3F];
    work := (l shr 4) or (l shl 28) xor Key3[i shl 2 + 2];
    r := r xor S6[(work) and $3F] xor S4[(work shr 8) and $3F] xor S2[(work shr 16) and $3F] xor S0[(work shr 24) and $3F];
    work := l xor Key3[i shl 2 + 3];
    r := r xor S7[(work) and $3F] xor S5[(work shr 8) and $3F] xor S3[(work shr 16) and $3F] xor S1[(work shr 24) and $3F];
  end;

  { final permutation }
  r := (r shr 1) or (r shl 31);
  work := (l xor r) and $AAAAAAAA;
  r := r xor work;
  l := l xor work;
  l := (l shr 9) or (l shl 23);
  work := (l xor r) and $00FF00FF;
  r := r xor work;
  l := l xor work;
  l := (l shl 6) or (l shr 26);
  work := (l xor r) and $33333333;
  r := r xor work;
  l := l xor work;
  l := (l shl 18) or (l shr 14);
  work := (l xor r) and $FFFF0000;
  r := r xor work;
  l := l xor work;
  l := (l shl 20) or (l shr 12);
  work := (l xor r) and $F0F0F0F0;
  r := r xor work;
  l := l xor work;
  l := (l shr 4) or (l shl 28);

  B0 := (r shr 24) or ((r shr 8) and $ff00) or ((r shl 8) and $ff0000) or (r shl 24);
  B1 := (l shr 24) or ((l shr 8) and $ff00) or ((l shl 8) and $ff0000) or (l shl 24);
end;

end.
