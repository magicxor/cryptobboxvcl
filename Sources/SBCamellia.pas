(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$i SecBbox.inc}

unit SBCamellia;

interface

uses 
  Classes,
  SysUtils,
  SBTypes,
  SBUtils,
  SBConstants;

type

  TCmInt64 =  array [0..1] of Cardinal;
  TCmInt128 =  array [0..3] of Cardinal;

  TSBCamelliaBuffer =  array [0..15] of byte;
   PSBCamelliaBuffer = ^TSBCamelliaBuffer; 
  TSBCamelliaKey =  ByteArray;

  TSBCamelliaExpandedKey =  record
    K : array [1..24] of TCmInt64;
    KE : array [1..6] of TCmInt64;
    KW : array [1..4] of TCmInt64;
  end;

  { Block processing routines }
  procedure EncryptBlock(var B0, B1, B2, B3 : cardinal; const Key : TSBCamelliaExpandedKey; LongKey : boolean); 
  function ExpandKeyForEncryption(const Key : TSBCamelliaKey; out EKey : TSBCamelliaExpandedKey) : boolean; 
  function ExpandKeyForDecryption(const Key : TSBCamelliaKey; out EKey : TSBCamelliaExpandedKey) : boolean; 

implementation

const
  { S-boxes }
  SBOX1 : array [0..255] of byte =
    ( 
     $70, $82, $2C, $EC, $B3, $27, $C0, $E5, $E4, $85, $57, $35, $EA, $0C, $AE, $41,
     $23, $EF, $6B, $93, $45, $19, $A5, $21, $ED, $0E, $4F, $4E, $1D, $65, $92, $BD,
     $86, $B8, $AF, $8F, $7C, $EB, $1F, $CE, $3E, $30, $DC, $5F, $5E, $C5, $0B, $1A,
     $A6, $E1, $39, $CA, $D5, $47, $5D, $3D, $D9, $01, $5A, $D6, $51, $56, $6C, $4D,
     $8B, $0D, $9A, $66, $FB, $CC, $B0, $2D, $74, $12, $2B, $20, $F0, $B1, $84, $99,
     $DF, $4C, $CB, $C2, $34, $7E, $76, $05, $6D, $B7, $A9, $31, $D1, $17, $04, $D7,
     $14, $58, $3A, $61, $DE, $1B, $11, $1C, $32, $0F, $9C, $16, $53, $18, $F2, $22,
     $FE, $44, $CF, $B2, $C3, $B5, $7A, $91, $24, $08, $E8, $A8, $60, $FC, $69, $50,
     $AA, $D0, $A0, $7D, $A1, $89, $62, $97, $54, $5B, $1E, $95, $E0, $FF, $64, $D2,
     $10, $C4, $00, $48, $A3, $F7, $75, $DB, $8A, $03, $E6, $DA, $09, $3F, $DD, $94,
     $87, $5C, $83, $02, $CD, $4A, $90, $33, $73, $67, $F6, $F3, $9D, $7F, $BF, $E2,
     $52, $9B, $D8, $26, $C8, $37, $C6, $3B, $81, $96, $6F, $4B, $13, $BE, $63, $2E,
     $E9, $79, $A7, $8C, $9F, $6E, $BC, $8E, $29, $F5, $F9, $B6, $2F, $FD, $B4, $59,
     $78, $98, $06, $6A, $E7, $46, $71, $BA, $D4, $25, $AB, $42, $88, $A2, $8D, $FA,
     $72, $07, $B9, $55, $F8, $EE, $AC, $0A, $36, $49, $2A, $68, $3C, $38, $F1, $A4,
     $40, $28, $D3, $7B, $BB, $C9, $43, $C1, $15, $E3, $AD, $F4, $77, $C7, $80, $9E
    ) ;

  SBOX2 : array [0..255] of byte =
    ( 
     $E0, $05, $58, $D9, $67, $4E, $81, $CB, $C9, $0B, $AE, $6A, $D5, $18, $5D, $82,
     $46, $DF, $D6, $27, $8A, $32, $4B, $42, $DB, $1C, $9E, $9C, $3A, $CA, $25, $7B,
     $0D, $71, $5F, $1F, $F8, $D7, $3E, $9D, $7C, $60, $B9, $BE, $BC, $8B, $16, $34,
     $4D, $C3, $72, $95, $AB, $8E, $BA, $7A, $B3, $02, $B4, $AD, $A2, $AC, $D8, $9A,
     $17, $1A, $35, $CC, $F7, $99, $61, $5A, $E8, $24, $56, $40, $E1, $63, $09, $33,
     $BF, $98, $97, $85, $68, $FC, $EC, $0A, $DA, $6F, $53, $62, $A3, $2E, $08, $AF,
     $28, $B0, $74, $C2, $BD, $36, $22, $38, $64, $1E, $39, $2C, $A6, $30, $E5, $44,
     $FD, $88, $9F, $65, $87, $6B, $F4, $23, $48, $10, $D1, $51, $C0, $F9, $D2, $A0,
     $55, $A1, $41, $FA, $43, $13, $C4, $2F, $A8, $B6, $3C, $2B, $C1, $FF, $C8, $A5,
     $20, $89, $00, $90, $47, $EF, $EA, $B7, $15, $06, $CD, $B5, $12, $7E, $BB, $29,
     $0F, $B8, $07, $04, $9B, $94, $21, $66, $E6, $CE, $ED, $E7, $3B, $FE, $7F, $C5,
     $A4, $37, $B1, $4C, $91, $6E, $8D, $76, $03, $2D, $DE, $96, $26, $7D, $C6, $5C,
     $D3, $F2, $4F, $19, $3F, $DC, $79, $1D, $52, $EB, $F3, $6D, $5E, $FB, $69, $B2,
     $F0, $31, $0C, $D4, $CF, $8C, $E2, $75, $A9, $4A, $57, $84, $11, $45, $1B, $F5,
     $E4, $0E, $73, $AA, $F1, $DD, $59, $14, $6C, $92, $54, $D0, $78, $70, $E3, $49,
     $80, $50, $A7, $F6, $77, $93, $86, $83, $2A, $C7, $5B, $E9, $EE, $8F, $01, $3D
    ) ;

  SBOX3 : array [0..255] of byte =
    ( 
     $38, $41, $16, $76, $D9, $93, $60, $F2, $72, $C2, $AB, $9A, $75, $06, $57, $A0,
     $91, $F7, $B5, $C9, $A2, $8C, $D2, $90, $F6, $07, $A7, $27, $8E, $B2, $49, $DE,
     $43, $5C, $D7, $C7, $3E, $F5, $8F, $67, $1F, $18, $6E, $AF, $2F, $E2, $85, $0D,
     $53, $F0, $9C, $65, $EA, $A3, $AE, $9E, $EC, $80, $2D, $6B, $A8, $2B, $36, $A6,
     $C5, $86, $4D, $33, $FD, $66, $58, $96, $3A, $09, $95, $10, $78, $D8, $42, $CC,
     $EF, $26, $E5, $61, $1A, $3F, $3B, $82, $B6, $DB, $D4, $98, $E8, $8B, $02, $EB,
     $0A, $2C, $1D, $B0, $6F, $8D, $88, $0E, $19, $87, $4E, $0B, $A9, $0C, $79, $11,
     $7F, $22, $E7, $59, $E1, $DA, $3D, $C8, $12, $04, $74, $54, $30, $7E, $B4, $28,
     $55, $68, $50, $BE, $D0, $C4, $31, $CB, $2A, $AD, $0F, $CA, $70, $FF, $32, $69,
     $08, $62, $00, $24, $D1, $FB, $BA, $ED, $45, $81, $73, $6D, $84, $9F, $EE, $4A,
     $C3, $2E, $C1, $01, $E6, $25, $48, $99, $B9, $B3, $7B, $F9, $CE, $BF, $DF, $71,
     $29, $CD, $6C, $13, $64, $9B, $63, $9D, $C0, $4B, $B7, $A5, $89, $5F, $B1, $17,
     $F4, $BC, $D3, $46, $CF, $37, $5E, $47, $94, $FA, $FC, $5B, $97, $FE, $5A, $AC,
     $3C, $4C, $03, $35, $F3, $23, $B8, $5D, $6A, $92, $D5, $21, $44, $51, $C6, $7D,
     $39, $83, $DC, $AA, $7C, $77, $56, $05, $1B, $A4, $15, $34, $1E, $1C, $F8, $52,
     $20, $14, $E9, $BD, $DD, $E4, $A1, $E0, $8A, $F1, $D6, $7A, $BB, $E3, $40, $4F
    ) ;

  SBOX4 : array [0..255] of byte =
    ( 
     $70, $2C, $B3, $C0, $E4, $57, $EA, $AE, $23, $6B, $45, $A5, $ED, $4F, $1D, $92, 
     $86, $AF, $7C, $1F, $3E, $DC, $5E, $0B, $A6, $39, $D5, $5D, $D9, $5A, $51, $6C, 
     $8B, $9A, $FB, $B0, $74, $2B, $F0, $84, $DF, $CB, $34, $76, $6D, $A9, $D1, $04, 
     $14, $3A, $DE, $11, $32, $9C, $53, $F2, $FE, $CF, $C3, $7A, $24, $E8, $60, $69, 
     $AA, $A0, $A1, $62, $54, $1E, $E0, $64, $10, $00, $A3, $75, $8A, $E6, $09, $DD, 
     $87, $83, $CD, $90, $73, $F6, $9D, $BF, $52, $D8, $C8, $C6, $81, $6F, $13, $63,
     $E9, $A7, $9F, $BC, $29, $F9, $2F, $B4, $78, $06, $E7, $71, $D4, $AB, $88, $8D,
     $72, $B9, $F8, $AC, $36, $2A, $3C, $F1, $40, $D3, $BB, $43, $15, $AD, $77, $80,
     $82, $EC, $27, $E5, $85, $35, $0C, $41, $EF, $93, $19, $21, $0E, $4E, $65, $BD,
     $B8, $8F, $EB, $CE, $30, $5F, $C5, $1A, $E1, $CA, $47, $3D, $01, $D6, $56, $4D,
     $0D, $66, $CC, $2D, $12, $20, $B1, $99, $4C, $C2, $7E, $05, $B7, $31, $17, $D7,
     $58, $61, $1B, $1C, $0F, $16, $18, $22, $44, $B2, $B5, $91, $08, $A8, $FC, $50,
     $D0, $7D, $89, $97, $5B, $95, $FF, $D2, $C4, $48, $F7, $DB, $03, $DA, $3F, $94,
     $5C, $02, $4A, $33, $67, $F3, $7F, $E2, $9B, $26, $37, $3B, $96, $4B, $BE, $2E,
     $79, $8C, $6E, $8E, $F5, $B6, $FD, $59, $98, $6A, $46, $BA, $25, $42, $A2, $FA,
     $07, $55, $EE, $0A, $49, $68, $38, $A4, $28, $7B, $C9, $C1, $E3, $F4, $C7, $9E
    ) ;

  Sigma1 : TCmInt64 = 
    ( 
     $3BCC908B, $A09E667F
    ) ;

  Sigma2 : TCmInt64 = 
    ( 
     $4CAA73B2, $B67AE858
    ) ;

  Sigma3 : TCmInt64 = 
    ( 
     $E94F82BE, $C6EF372F
    ) ;

  Sigma4 : TCmInt64 = 
    ( 
     $F1D36F1C, $54FF53A5
    ) ;

  Sigma5 : TCmInt64 = 
    ( 
     $DE682D1D, $10E527FA
    ) ;

  Sigma6 : TCmInt64 = 
    ( 
     $B3E6C1FD, $B05688C2
    ) ;

/////////////////////////////////////////////////////
// Internal routines

procedure CamelliaF(const I, KE : TCmInt64; out R : TCmInt64);
var
  X0, X1 : cardinal;
  T0, T1, T2, T3, T4, T5, T6, T7 : Byte;
  Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7 : Byte;
begin
  X0 := I[0] xor KE[0]; X1 := I[1] xor KE[1];

  {T0 := SBOX1[X1 shr 24];
  T1 := SBOX2[(X1 shr 16) and $ff];
  T2 := SBOX3[(X1 shr 8) and $ff];
  T3 := SBOX4[X1 and $ff];
  T4 := SBOX2[X0 shr 24];
  T5 := SBOX3[(X0 shr 16) and $ff];
  T6 := SBOX4[(X0 shr 8) and $ff];
  T7 := SBOX1[X0 and $ff];}
  T0 := SBOX1[Byte(X1 shr 24)];
  T1 := SBOX2[Byte(X1 shr 16)];
  T2 := SBOX3[Byte(X1 shr 8)];
  T3 := SBOX4[Byte(X1)];
  T4 := SBOX2[Byte(X0 shr 24)];
  T5 := SBOX3[Byte(X0 shr 16)];
  T6 := SBOX4[Byte(X0 shr 8)];
  T7 := SBOX1[Byte(X0)];


  Y0 := T0 xor T2 xor T3 xor T5 xor T6 xor T7;
  Y1 := T0 xor T1 xor T3 xor T4 xor T6 xor T7;
  Y2 := T0 xor T1 xor T2 xor T4 xor T5 xor T7;
  Y3 := T1 xor T2 xor T3 xor T4 xor T5 xor T6;
  Y4 := T0 xor T1 xor T5 xor T6 xor T7;
  Y5 := T1 xor T2 xor T4 xor T6 xor T7;
  Y6 := T2 xor T3 xor T4 xor T5 xor T7;
  Y7 := T0 xor T3 xor T4 xor T5 xor T6;

  R[0] := Y7 or (Y6 shl 8) or (Y5 shl 16) or (Y4 shl 24);
  R[1] := Y3 or (Y2 shl 8) or (Y1 shl 16) or (Y0 shl 24);
end;

procedure CamelliaFL(const I, KE : TCmInt64; out R : TCmInt64);
var
  x1, x2, k1, k2 : Cardinal;
begin
  x1 := I[1];
  x2 := I[0];
  k1 := KE[1];
  k2 := KE[0];

  x2 := x2 xor ( ((x1 and k1) shl 1) or ((x1 and k1) shr 31));
  x1 := x1 xor (x2 or k2);

  R[0] := x2;
  R[1] := x1;
end;

procedure CamelliaFLInv(const I, KE : TCmInt64; out R : TCmInt64);
var
  y1, y2, k1, k2 : Cardinal;
begin
  y1 := I[1];
  y2 := I[0];
  k1 := KE[1];
  k2 := KE[0];

  y1 := y1 xor (y2 or k2);
  y2 := y2 xor (((y1 and k1) shl 1) or ((y1 and k1) shr 31));
  
  R[0] := y2;
  R[1] := y1; 
end;

procedure CamelliaROL(var I : TCmInt128; Bits : integer);
var
  Ints : Cardinal;
  Res : TCmInt128;
  Index : Cardinal;
begin
  while Bits < 0 do Bits := Bits + 128;
  Bits := Bits mod 128;

  Ints := Bits shr 5;
  Bits := Bits and $1f;

  { Delphi doesn't want to make shl/shr to 32 bits on 32-bit ints ... }
  if Bits = 0 then
    for Index := 0 to 3 do
      Res[Index] := I[(Index + 4 - Ints) mod 4]
  else
    for Index := 0 to 3 do
      Res[Index] := (I[(Index + 4 - Ints) mod 4] shl Bits) or (I[(Index + 3 - Ints) mod 4] shr (32 - Bits));

  I := Res;
end;

procedure CamelliaSWAP(var I1, I2 : TCmInt64);
var
  Tmp : TCmInt64;
begin
  Tmp := I1;
  I1 := I2;
  I2 := Tmp;
end;


procedure EncryptBlock(var B0, B1, B2, B3 : cardinal; const Key : TSBCamelliaExpandedKey; LongKey : boolean);
var
  D1, D2, R : TCmInt64;
begin
  { camellia uses 64-bit big-endian input, while crypto providers use little-endian }
  D1[0] := (B1 shr 24) or ((B1 shr 8) and $ff00) or ((B1 shl 8) and $ff0000) or (B1 shl 24);
  D1[1] := (B0 shr 24) or ((B0 shr 8) and $ff00) or ((B0 shl 8) and $ff0000) or (B0 shl 24);
  D2[0] := (B3 shr 24) or ((B3 shr 8) and $ff00) or ((B3 shl 8) and $ff0000) or (B3 shl 24);
  D2[1] := (B2 shr 24) or ((B2 shr 8) and $ff00) or ((B2 shl 8) and $ff0000) or (B2 shl 24);

  D1[0] := D1[0] xor Key.KW[1  ,  0]; D1[1] := D1[1] xor Key.KW[1  ,  1];
  D2[0] := D2[0] xor Key.KW[2  ,  0]; D2[1] := D2[1] xor Key.KW[2  ,  1];

  CamelliaF(D1, Key.K[1 ], R);
  D2[0] := D2[0] xor R[0]; D2[1] := D2[1] xor R[1];
  CamelliaF(D2, Key.K[2], R);
  D1[0] := D1[0] xor R[0]; D1[1] := D1[1] xor R[1];
  CamelliaF(D1, Key.K[3], R);
  D2[0] := D2[0] xor R[0]; D2[1] := D2[1] xor R[1];
  CamelliaF(D2, Key.K[4], R);
  D1[0] := D1[0] xor R[0]; D1[1] := D1[1] xor R[1];
  CamelliaF(D1, Key.K[5], R);
  D2[0] := D2[0] xor R[0]; D2[1] := D2[1] xor R[1];
  CamelliaF(D2, Key.K[6], R);
  D1[0] := D1[0] xor R[0]; D1[1] := D1[1] xor R[1];

  CamelliaFL(D1, Key.KE[1], D1);
  CamelliaFLInv(D2, Key.KE[2], D2);

  CamelliaF(D1, Key.K[7], R);
  D2[0] := D2[0] xor R[0]; D2[1] := D2[1] xor R[1];
  CamelliaF(D2, Key.K[8], R);
  D1[0] := D1[0] xor R[0]; D1[1] := D1[1] xor R[1];
  CamelliaF(D1, Key.K[9], R);
  D2[0] := D2[0] xor R[0]; D2[1] := D2[1] xor R[1];
  CamelliaF(D2, Key.K[10], R);
  D1[0] := D1[0] xor R[0]; D1[1] := D1[1] xor R[1];
  CamelliaF(D1, Key.K[11], R);
  D2[0] := D2[0] xor R[0]; D2[1] := D2[1] xor R[1];
  CamelliaF(D2, Key.K[12], R);
  D1[0] := D1[0] xor R[0]; D1[1] := D1[1] xor R[1];

  CamelliaFL(D1, Key.KE[3], D1);
  CamelliaFLInv(D2, Key.KE[4], D2);

  CamelliaF(D1, Key.K[13], R);
  D2[0] := D2[0] xor R[0]; D2[1] := D2[1] xor R[1];
  CamelliaF(D2, Key.K[14], R);
  D1[0] := D1[0] xor R[0]; D1[1] := D1[1] xor R[1];
  CamelliaF(D1, Key.K[15], R);
  D2[0] := D2[0] xor R[0]; D2[1] := D2[1] xor R[1];
  CamelliaF(D2, Key.K[16], R);
  D1[0] := D1[0] xor R[0]; D1[1] := D1[1] xor R[1];
  CamelliaF(D1, Key.K[17], R);
  D2[0] := D2[0] xor R[0]; D2[1] := D2[1] xor R[1];
  CamelliaF(D2, Key.K[18], R);
  D1[0] := D1[0] xor R[0]; D1[1] := D1[1] xor R[1];

  if LongKey then
  begin
    CamelliaFL(D1, Key.KE[5], D1);
    CamelliaFLInv(D2, Key.KE[6], D2);

    CamelliaF(D1, Key.K[19], R);
    D2[0] := D2[0] xor R[0]; D2[1] := D2[1] xor R[1];
    CamelliaF(D2, Key.K[20], R);
    D1[0] := D1[0] xor R[0]; D1[1] := D1[1] xor R[1];
    CamelliaF(D1, Key.K[21], R);
    D2[0] := D2[0] xor R[0]; D2[1] := D2[1] xor R[1];
    CamelliaF(D2, Key.K[22], R);
    D1[0] := D1[0] xor R[0]; D1[1] := D1[1] xor R[1];
    CamelliaF(D1, Key.K[23], R);
    D2[0] := D2[0] xor R[0]; D2[1] := D2[1] xor R[1];
    CamelliaF(D2, Key.K[24], R);
    D1[0] := D1[0] xor R[0]; D1[1] := D1[1] xor R[1];
  end;

  D2[0] := D2[0] xor Key.KW[3  ,  0]; D2[1] := D2[1] xor Key.KW[3  ,  1];
  D1[0] := D1[0] xor Key.KW[4  ,  0]; D1[1] := D1[1] xor Key.KW[4  ,  1];

  { reversing byte order }
  B0 := (D2[1] shr 24) or ((D2[1] shr 8) and $ff00) or ((D2[1] shl 8) and $ff0000) or (D2[1] shl 24);
  B1 := (D2[0] shr 24) or ((D2[0] shr 8) and $ff00) or ((D2[0] shl 8) and $ff0000) or (D2[0] shl 24);
  B2 := (D1[1] shr 24) or ((D1[1] shr 8) and $ff00) or ((D1[1] shl 8) and $ff0000) or (D1[1] shl 24);
  B3 := (D1[0] shr 24) or ((D1[0] shr 8) and $ff00) or ((D1[0] shl 8) and $ff0000) or (D1[0] shl 24);
end;

function ExpandKeyForEncryption(const Key : TSBCamelliaKey; out EKey : TSBCamelliaExpandedKey) : boolean;
var
  KL, KR, KA, KB : TCmInt128;
  D1, D2 : TCmInt64;
  R : TCmInt64;
begin
  if (Length(Key) <> 16) and (Length(Key) <> 24) and (Length(Key) <> 32) then
  begin
    Result := false;
    Exit;
  end;

  KL[0] := Key[15] or (Key[14] shl 8) or (Key[13] shl 16) or (Key[12] shl 24);
  KL[1] := Key[11] or (Key[10] shl 8) or (Key[9] shl 16) or (Key[8] shl 24);
  KL[2] := Key[7] or (Key[6] shl 8) or (Key[5] shl 16) or (Key[4] shl 24);
  KL[3] := Key[3] or (Key[2] shl 8) or (Key[1] shl 16) or (Key[0] shl 24);

  if Length(Key) = 16 then
  begin
    KR[0] := 0;
    KR[1] := 0;
    KR[2] := 0;
    KR[3] := 0;
  end
  else if Length(Key) = 24 then
  begin
    KR[2] := Key[23] or (Key[22] shl 8) or (Key[21] shl 16) or (Key[20] shl 24);
    KR[3] := Key[19] or (Key[18] shl 8) or (Key[17] shl 16) or (Key[16] shl 24);
    KR[0] := not KR[2];
    KR[1] := not KR[3];
  end
  else if Length(Key) = 32 then
  begin
    KR[0] := Key[31] or (Key[30] shl 8) or (Key[29] shl 16) or (Key[28] shl 24);
    KR[1] := Key[27] or (Key[26] shl 8) or (Key[25] shl 16) or (Key[24] shl 24);
    KR[2] := Key[23] or (Key[22] shl 8) or (Key[21] shl 16) or (Key[20] shl 24);
    KR[3] := Key[19] or (Key[18] shl 8) or (Key[17] shl 16) or (Key[16] shl 24);
  end;

  D1[0] := KL[2] xor KR[2]; D1[1] := KL[3] xor KR[3];
  D2[0] := KL[0] xor KR[0]; D2[1] := KL[1] xor KR[1];

  CamelliaF(D1, Sigma1, R);
  D2[0] := D2[0] xor R[0]; D2[1] := D2[1] xor R[1];
  CamelliaF(D2, Sigma2, R);
  D1[0] := D1[0] xor R[0]; D1[1] := D1[1] xor R[1];

  D1[0] := D1[0] xor KL[2]; D1[1] := D1[1] xor KL[3];
  D2[0] := D2[0] xor KL[0]; D2[1] := D2[1] xor KL[1];

  CamelliaF(D1, Sigma3, R);
  D2[0] := D2[0] xor R[0]; D2[1] := D2[1] xor R[1];
  CamelliaF(D2, Sigma4, R);
  D1[0] := D1[0] xor R[0]; D1[1] := D1[1] xor R[1];

  KA[0] := D2[0]; KA[1] := D2[1];
  KA[2] := D1[0]; KA[3] := D1[1];

  D1[0] := KA[2] xor KR[2]; D1[1] := KA[3] xor KR[3];
  D2[0] := KA[0] xor KR[0]; D2[1] := KA[1] xor KR[1];

  CamelliaF(D1, Sigma5, R);
  D2[0] := D2[0] xor R[0]; D2[1] := D2[1] xor R[1];
  CamelliaF(D2, Sigma6, R);
  D1[0] := D1[0] xor R[0]; D1[1] := D1[1] xor R[1];

  KB[0] := D2[0]; KB[1] := D2[1];
  KB[2] := D1[0]; KB[3] := D1[1];


  if Length(Key) = 16 then
  begin
    EKey.KW[1  ,  0] := KL[2]; EKey.KW[1  ,  1] := KL[3];
    EKey.KW[2  ,  0] := KL[0]; EKey.KW[2  ,  1] := KL[1];
    EKey.K[1  ,  0] := KA[2]; EKey.K[1  ,  1] := KA[3];
    EKey.K[2  ,  0] := KA[0]; EKey.K[2  ,  1] := KA[1];
    CamelliaROL(KL, 15);
    CamelliaROL(KA, 15);
    EKey.K[3  ,  0] := KL[2]; EKey.K[3  ,  1] := KL[3];
    EKey.K[4  ,  0] := KL[0]; EKey.K[4  ,  1] := KL[1];
    EKey.K[5  ,  0] := KA[2]; EKey.K[5  ,  1] := KA[3];
    EKey.K[6  ,  0] := KA[0]; EKey.K[6  ,  1] := KA[1];
    CamelliaROL(KA, 15);
    EKey.KE[1  ,  0] := KA[2]; EKey.KE[1  ,  1] := KA[3];
    EKey.KE[2  ,  0] := KA[0]; EKey.KE[2  ,  1] := KA[1];
    CamelliaROL(KL, 30);
    EKey.K[7  ,  0] := KL[2]; EKey.K[7  ,  1] := KL[3];
    EKey.K[8  ,  0] := KL[0]; EKey.K[8  ,  1] := KL[1];
    CamelliaROL(KA, 15);
    EKey.K[9  ,  0] := KA[2]; EKey.K[9  ,  1] := KA[3];
    CamelliaROL(KL, 15);
    CamelliaROL(KA, 15);
    EKey.K[10  ,  0] := KL[0]; EKey.K[10  ,  1] := KL[1];
    EKey.K[11  ,  0] := KA[2]; EKey.K[11  ,  1] := KA[3];
    EKey.K[12  ,  0] := KA[0]; EKey.K[12  ,  1] := KA[1];
    CamelliaROL(KL, 17);
    EKey.KE[3  ,  0] := KL[2]; EKey.KE[3  ,  1] := KL[3];
    EKey.KE[4  ,  0] := KL[0]; EKey.KE[4  ,  1] := KL[1];
    CamelliaROL(KL, 17);
    CamelliaROL(KA, 34);
    EKey.K[13  ,  0] := KL[2]; EKey.K[13  ,  1] := KL[3];
    EKey.K[14  ,  0] := KL[0]; EKey.K[14  ,  1] := KL[1];
    EKey.K[15  ,  0] := KA[2]; EKey.K[15  ,  1] := KA[3];
    EKey.K[16  ,  0] := KA[0]; EKey.K[16  ,  1] := KA[1];
    CamelliaROL(KL, 17);
    CamelliaROL(KA, 17);
    EKey.K[17  ,  0] := KL[2]; EKey.K[17  ,  1] := KL[3];
    EKey.K[18  ,  0] := KL[0]; EKey.K[18  ,  1] := KL[1];
    EKey.KW[3  ,  0] := KA[2]; EKey.KW[3  ,  1] := KA[3];
    EKey.KW[4  ,  0] := KA[0]; EKey.KW[4  ,  1] := KA[1];
  end
  else
  begin
    EKey.KW[1  ,  0] := KL[2]; EKey.KW[1  ,  1] := KL[3];
    EKey.KW[2  ,  0] := KL[0]; EKey.KW[2  ,  1] := KL[1];
    EKey.K[1  ,  0] := KB[2]; EKey.K[1  ,  1] := KB[3];
    EKey.K[2  ,  0] := KB[0]; EKey.K[2  ,  1] := KB[1];
    CamelliaROL(KR, 15);
    CamelliaROL(KA, 15);
    EKey.K[3  ,  0] := KR[2]; EKey.K[3  ,  1] := KR[3];
    EKey.K[4  ,  0] := KR[0]; EKey.K[4  ,  1] := KR[1];
    EKey.K[5  ,  0] := KA[2]; EKey.K[5  ,  1] := KA[3];
    EKey.K[6  ,  0] := KA[0]; EKey.K[6  ,  1] := KA[1];
    CamelliaROL(KR, 15);
    EKey.KE[1  ,  0] := KR[2]; EKey.KE[1  ,  1] := KR[3];
    EKey.KE[2  ,  0] := KR[0]; EKey.KE[2  ,  1] := KR[1];
    CamelliaROL(KB, 30);
    EKey.K[7  ,  0] := KB[2]; EKey.K[7  ,  1] := KB[3];
    EKey.K[8  ,  0] := KB[0]; EKey.K[8  ,  1] := KB[1];
    CamelliaROL(KL, 45);
    EKey.K[9  ,  0] := KL[2]; EKey.K[9  ,  1] := KL[3];
    EKey.K[10  ,  0] := KL[0]; EKey.K[10  ,  1] := KL[1];
    CamelliaROL(KA, 30);
    EKey.K[11  ,  0] := KA[2]; EKey.K[11  ,  1] := KA[3];
    EKey.K[12  ,  0] := KA[0]; EKey.K[12  ,  1] := KA[1];
    CamelliaROL(KL, 15);
    EKey.KE[3  ,  0] := KL[2]; EKey.KE[3  ,  1] := KL[3];
    EKey.KE[4  ,  0] := KL[0]; EKey.KE[4  ,  1] := KL[1];
    CamelliaROL(KR, 30);
    CamelliaROL(KB, 30);
    EKey.K[13  ,  0] := KR[2]; EKey.K[13  ,  1] := KR[3];
    EKey.K[14  ,  0] := KR[0]; EKey.K[14  ,  1] := KR[1];
    EKey.K[15  ,  0] := KB[2]; EKey.K[15  ,  1] := KB[3];
    EKey.K[16  ,  0] := KB[0]; EKey.K[16  ,  1] := KB[1];
    CamelliaROL(KL, 17);
    EKey.K[17  ,  0] := KL[2]; EKey.K[17  ,  1] := KL[3];
    EKey.K[18  ,  0] := KL[0]; EKey.K[18  ,  1] := KL[1];
    CamelliaROL(KA, 32);
    EKey.KE[5  ,  0] := KA[2]; EKey.KE[5  ,  1] := KA[3];
    EKey.KE[6  ,  0] := KA[0]; EKey.KE[6  ,  1] := KA[1];
    CamelliaROL(KR, 34);
    CamelliaROL(KA, 17);    
    EKey.K[19  ,  0] := KR[2]; EKey.K[19  ,  1] := KR[3];
    EKey.K[20  ,  0] := KR[0]; EKey.K[20  ,  1] := KR[1];
    EKey.K[21  ,  0] := KA[2]; EKey.K[21  ,  1] := KA[3];
    EKey.K[22  ,  0] := KA[0]; EKey.K[22  ,  1] := KA[1];
    CamelliaROL(KL, 34);
    EKey.K[23  ,  0] := KL[2]; EKey.K[23  ,  1] := KL[3];
    EKey.K[24  ,  0] := KL[0]; EKey.K[24  ,  1] := KL[1];
    CamelliaROL(KB, 51);
    EKey.KW[3  ,  0] := KB[2]; EKey.KW[3  ,  1] := KB[3];
    EKey.KW[4  ,  0] := KB[0]; EKey.KW[4  ,  1] := KB[1];
  end;

  Result := true;
end;

function ExpandKeyForDecryption(const Key : TSBCamelliaKey; out EKey : TSBCamelliaExpandedKey) : boolean;
begin
  Result := ExpandKeyForEncryption(Key, EKey);

  if Result then
  begin
    if Length(Key) = 16 then
    begin
      CamelliaSWAP(EKey.KW[1], EKey.KW[3]);
      CamelliaSWAP(EKey.KW[2], EKey.KW[4]);
      CamelliaSWAP(EKey.K[1], EKey.K[18]);
      CamelliaSWAP(EKey.K[2], EKey.K[17]);
      CamelliaSWAP(EKey.K[3], EKey.K[16]);
      CamelliaSWAP(EKey.K[4], EKey.K[15]);
      CamelliaSWAP(EKey.K[5], EKey.K[14]);
      CamelliaSWAP(EKey.K[6], EKey.K[13]);
      CamelliaSWAP(EKey.K[7], EKey.K[12]);
      CamelliaSWAP(EKey.K[8], EKey.K[11]);
      CamelliaSWAP(EKey.K[9], EKey.K[10]);
      CamelliaSWAP(EKey.KE[1], EKey.KE[4]);
      CamelliaSWAP(EKey.KE[2], EKey.KE[3]);
    end
    else
    begin
      CamelliaSWAP(EKey.KW[1], EKey.KW[3]);
      CamelliaSWAP(EKey.KW[2], EKey.KW[4]);
      CamelliaSWAP(EKey.K[1], EKey.K[24]);
      CamelliaSWAP(EKey.K[2], EKey.K[23]);
      CamelliaSWAP(EKey.K[3], EKey.K[22]);
      CamelliaSWAP(EKey.K[4], EKey.K[21]);
      CamelliaSWAP(EKey.K[5], EKey.K[20]);
      CamelliaSWAP(EKey.K[6], EKey.K[19]);
      CamelliaSWAP(EKey.K[7], EKey.K[18]);
      CamelliaSWAP(EKey.K[8], EKey.K[17]);
      CamelliaSWAP(EKey.K[9], EKey.K[16]);
      CamelliaSWAP(EKey.K[10], EKey.K[15]);
      CamelliaSWAP(EKey.K[11], EKey.K[14]);
      CamelliaSWAP(EKey.K[12], EKey.K[13]);
      CamelliaSWAP(EKey.KE[1], EKey.KE[6]);
      CamelliaSWAP(EKey.KE[2], EKey.KE[5]);
      CamelliaSWAP(EKey.KE[3], EKey.KE[4]);
    end;
  end;
end;

end.
