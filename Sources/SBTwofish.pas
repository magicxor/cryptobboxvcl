
(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBTwofish;

interface

uses
  SBTypes,
  SBUtils,
  SBConstants;

type

  TTwofishExpandedKey =  record
    ExpandedKey : array  [0..39]  of cardinal;
    SBoxKey : array  [0..3]  of cardinal;
    SBox0 : array  [0..255]  of byte;
    SBox1 : array  [0..255]  of byte;
    SBox2 : array  [0..255]  of byte;
    SBox3 : array  [0..255]  of byte;
    KeyLen : integer;
  end;

{ block low-level routines }
procedure ExpandKey(const Key : ByteArray; var ExpandedKey : TTwofishExpandedKey); 
procedure EncryptBlock(const ExpandedKey : TTwofishExpandedKey; var B0, B1, B2, B3 : cardinal); 
procedure DecryptBlock(const ExpandedKey : TTwofishExpandedKey; var B0, B1, B2, B3 : cardinal); 

implementation

const
  P8x8 : array[0..1, 0..255] of byte =
   ( 
   ( 
  $A9, $67, $B3, $E8, $04, $FD, $A3, $76,
  $9A, $92, $80, $78, $E4, $DD, $D1, $38,
  $0D, $C6, $35, $98, $18, $F7, $EC, $6C,
  $43, $75, $37, $26, $FA, $13, $94, $48,
  $F2, $D0, $8B, $30, $84, $54, $DF, $23,
  $19, $5B, $3D, $59, $F3, $AE, $A2, $82,
  $63, $01, $83, $2E, $D9, $51, $9B, $7C,
  $A6, $EB, $A5, $BE, $16, $0C, $E3, $61,
  $C0, $8C, $3A, $F5, $73, $2C, $25, $0B,
  $BB, $4E, $89, $6B, $53, $6A, $B4, $F1,
  $E1, $E6, $BD, $45, $E2, $F4, $B6, $66,
  $CC, $95, $03, $56, $D4, $1C, $1E, $D7,
  $FB, $C3, $8E, $B5, $E9, $CF, $BF, $BA,
  $EA, $77, $39, $AF, $33, $C9, $62, $71,
  $81, $79, $09, $AD, $24, $CD, $F9, $D8,
  $E5, $C5, $B9, $4D, $44, $08, $86, $E7,
  $A1, $1D, $AA, $ED, $06, $70, $B2, $D2,
  $41, $7B, $A0, $11, $31, $C2, $27, $90,
  $20, $F6, $60, $FF, $96, $5C, $B1, $AB,
  $9E, $9C, $52, $1B, $5F, $93, $0A, $EF,
  $91, $85, $49, $EE, $2D, $4F, $8F, $3B,
  $47, $87, $6D, $46, $D6, $3E, $69, $64,
  $2A, $CE, $CB, $2F, $FC, $97, $05, $7A,
  $AC, $7F, $D5, $1A, $4B, $0E, $A7, $5A,
  $28, $14, $3F, $29, $88, $3C, $4C, $02,
  $B8, $DA, $B0, $17, $55, $1F, $8A, $7D,
  $57, $C7, $8D, $74, $B7, $C4, $9F, $72,
  $7E, $15, $22, $12, $58, $07, $99, $34,
  $6E, $50, $DE, $68, $65, $BC, $DB, $F8,
  $C8, $A8, $2B, $40, $DC, $FE, $32, $A4,
  $CA, $10, $21, $F0, $D3, $5D, $0F, $00,
  $6F, $9D, $36, $42, $4A, $5E, $C1, $E0
   ) ,
   ( 
  $75, $F3, $C6, $F4, $DB, $7B, $FB, $C8,
  $4A, $D3, $E6, $6B, $45, $7D, $E8, $4B,
  $D6, $32, $D8, $FD, $37, $71, $F1, $E1,
  $30, $0F, $F8, $1B, $87, $FA, $06, $3F,
  $5E, $BA, $AE, $5B, $8A, $00, $BC, $9D,
  $6D, $C1, $B1, $0E, $80, $5D, $D2, $D5,
  $A0, $84, $07, $14, $B5, $90, $2C, $A3,
  $B2, $73, $4C, $54, $92, $74, $36, $51,
  $38, $B0, $BD, $5A, $FC, $60, $62, $96,
  $6C, $42, $F7, $10, $7C, $28, $27, $8C,
  $13, $95, $9C, $C7, $24, $46, $3B, $70,
  $CA, $E3, $85, $CB, $11, $D0, $93, $B8,
  $A6, $83, $20, $FF, $9F, $77, $C3, $CC,
  $03, $6F, $08, $BF, $40, $E7, $2B, $E2,
  $79, $0C, $AA, $82, $41, $3A, $EA, $B9,
  $E4, $9A, $A4, $97, $7E, $DA, $7A, $17,
  $66, $94, $A1, $1D, $3D, $F0, $DE, $B3,
  $0B, $72, $A7, $1C, $EF, $D1, $53, $3E,
  $8F, $33, $26, $5F, $EC, $76, $2A, $49,
  $81, $88, $EE, $21, $C4, $1A, $EB, $D9,
  $C5, $39, $99, $CD, $AD, $31, $8B, $01,
  $18, $23, $DD, $1F, $4E, $2D, $F9, $48,
  $4F, $F2, $65, $8E, $78, $5C, $58, $19,
  $8D, $E5, $98, $57, $67, $7F, $05, $64,
  $AF, $63, $B6, $FE, $F5, $B7, $3C, $A5,
  $CE, $E9, $68, $44, $E0, $4D, $43, $69,
  $29, $2E, $AC, $15, $59, $A8, $0A, $9E,
  $6E, $47, $DF, $34, $35, $6A, $CF, $DC,
  $22, $C9, $C0, $9B, $89, $D4, $ED, $AB,
  $12, $A2, $0D, $52, $BB, $02, $2F, $A9,
  $D7, $61, $1E, $B4, $50, $04, $F6, $C2,
  $16, $25, $86, $56, $55, $09, $BE, $91
   ) 
   ) ;


  MDS : array [0..3, 0..7] of byte =
    ( 
     ( 
     $01, $A4, $55, $87, $5A, $58, $DB, $9E
     ) ,
     ( 
     $A4, $56, $82, $F3, $1E, $C6, $68, $E5
     ) ,
     ( 
     $02, $A1, $FC, $C1, $47, $AE, $3D, $19
     ) ,
     ( 
     $A4, $55, $87, $5A, $58, $DB, $9E, $03
     ) 
    ) ;

  Arr5B : array [0..255] of cardinal =
    ( 
    $00, $5B, $B6, $ED, $05, $5E, $B3, $E8, $0A, $51, $BC, $E7, $0F, $54, $B9, $E2,
    $14, $4F, $A2, $F9, $11, $4A, $A7, $FC, $1E, $45, $A8, $F3, $1B, $40, $AD, $F6,
    $28, $73, $9E, $C5, $2D, $76, $9B, $C0, $22, $79, $94, $CF, $27, $7C, $91, $CA,
    $3C, $67, $8A, $D1, $39, $62, $8F, $D4, $36, $6D, $80, $DB, $33, $68, $85, $DE,
    $50, $0B, $E6, $BD, $55, $0E, $E3, $B8, $5A, $01, $EC, $B7, $5F, $04, $E9, $B2,
    $44, $1F, $F2, $A9, $41, $1A, $F7, $AC, $4E, $15, $F8, $A3, $4B, $10, $FD, $A6,
    $78, $23, $CE, $95, $7D, $26, $CB, $90, $72, $29, $C4, $9F, $77, $2C, $C1, $9A,
    $6C, $37, $DA, $81, $69, $32, $DF, $84, $66, $3D, $D0, $8B, $63, $38, $D5, $8E,
    $A0, $FB, $16, $4D, $A5, $FE, $13, $48, $AA, $F1, $1C, $47, $AF, $F4, $19, $42,
    $B4, $EF, $02, $59, $B1, $EA, $07, $5C, $BE, $E5, $08, $53, $BB, $E0, $0D, $56,
    $88, $D3, $3E, $65, $8D, $D6, $3B, $60, $82, $D9, $34, $6F, $87, $DC, $31, $6A,
    $9C, $C7, $2A, $71, $99, $C2, $2F, $74, $96, $CD, $20, $7B, $93, $C8, $25, $7E,
    $F0, $AB, $46, $1D, $F5, $AE, $43, $18, $FA, $A1, $4C, $17, $FF, $A4, $49, $12,
    $E4, $BF, $52, $09, $E1, $BA, $57, $0C, $EE, $B5, $58, $03, $EB, $B0, $5D, $06,
    $D8, $83, $6E, $35, $DD, $86, $6B, $30, $D2, $89, $64, $3F, $D7, $8C, $61, $3A,
    $CC, $97, $7A, $21, $C9, $92, $7F, $24, $C6, $9D, $70, $2B, $C3, $98, $75, $2E
    ) ;

  ArrEF : array [0..255] of byte = 
    ( 
    $00, $EF, $B7, $58, $07, $E8, $B0, $5F, $0E, $E1, $B9, $56, $09, $E6, $BE, $51,
    $1C, $F3, $AB, $44, $1B, $F4, $AC, $43, $12, $FD, $A5, $4A, $15, $FA, $A2, $4D,
    $38, $D7, $8F, $60, $3F, $D0, $88, $67, $36, $D9, $81, $6E, $31, $DE, $86, $69,
    $24, $CB, $93, $7C, $23, $CC, $94, $7B, $2A, $C5, $9D, $72, $2D, $C2, $9A, $75,
    $70, $9F, $C7, $28, $77, $98, $C0, $2F, $7E, $91, $C9, $26, $79, $96, $CE, $21,
    $6C, $83, $DB, $34, $6B, $84, $DC, $33, $62, $8D, $D5, $3A, $65, $8A, $D2, $3D,
    $48, $A7, $FF, $10, $4F, $A0, $F8, $17, $46, $A9, $F1, $1E, $41, $AE, $F6, $19,
    $54, $BB, $E3, $0C, $53, $BC, $E4, $0B, $5A, $B5, $ED, $02, $5D, $B2, $EA, $05,
    $E0, $0F, $57, $B8, $E7, $08, $50, $BF, $EE, $01, $59, $B6, $E9, $06, $5E, $B1,
    $FC, $13, $4B, $A4, $FB, $14, $4C, $A3, $F2, $1D, $45, $AA, $F5, $1A, $42, $AD,
    $D8, $37, $6F, $80, $DF, $30, $68, $87, $D6, $39, $61, $8E, $D1, $3E, $66, $89,
    $C4, $2B, $73, $9C, $C3, $2C, $74, $9B, $CA, $25, $7D, $92, $CD, $22, $7A, $95,
    $90, $7F, $27, $C8, $97, $78, $20, $CF, $9E, $71, $29, $C6, $99, $76, $2E, $C1,
    $8C, $63, $3B, $D4, $8B, $64, $3C, $D3, $82, $6D, $35, $DA, $85, $6A, $32, $DD,
    $A8, $47, $1F, $F0, $AF, $40, $18, $F7, $A6, $49, $11, $FE, $A1, $4E, $16, $F9,
    $B4, $5B, $03, $EC, $B3, $5C, $04, $EB, $BA, $55, $0D, $E2, $BD, $52, $0A, $E5
    ) ;


function TwofishH(X : cardinal; L : pointer; KeySize : cardinal) : cardinal; register; overload;
var
  b0, b1, b2, b3, z0, z1, z2, z3 : Byte;
begin
  b0 := X and $ff;
  b1 := (X shr 8) and $ff;
  b2 := (X shr 16) and $ff;
  b3 := X shr 24;

  if KeySize > 192 then
  begin
    b0 := P8x8[1, b0] xor PByte(PtrUInt(L) + 12)^;
    b1 := P8x8[0, b1] xor PByte(PtrUInt(L) + 13)^;
    b2 := P8x8[0, b2] xor PByte(PtrUInt(L) + 14)^;
    b3 := P8x8[1, b3] xor PByte(PtrUInt(L) + 15)^;
  end;
  if KeySize > 128 then
  begin
    b0 := P8x8[1, b0] xor PByte(PtrUInt(L) + 8)^;
    b1 := P8x8[1, b1] xor PByte(PtrUInt(L) + 9)^;
    b2 := P8x8[0, b2] xor PByte(PtrUInt(L) + 10)^;
    b3 := P8x8[0, b3] xor PByte(PtrUInt(L) + 11)^;
  end;

  b0 := P8x8[0, b0] xor PByte(PtrUInt(L) + 4)^;
  b1 := P8x8[1, b1] xor PByte(PtrUInt(L) + 5)^;
  b2 := P8x8[0, b2] xor PByte(PtrUInt(L) + 6)^;
  b3 := P8x8[1, b3] xor PByte(PtrUInt(L) + 7)^;

  b0 := P8x8[1, P8x8[0, b0] xor PByte(L)^];
  b1 := P8x8[0, P8x8[0, b1] xor PByte(PtrUInt(L) + 1)^];
  b2 := P8x8[1, P8x8[1, b2] xor PByte(PtrUInt(L) + 2)^];
  b3 := P8x8[0, P8x8[1, b3] xor PByte(PtrUInt(L) + 3)^];

  z0 := b0 xor ArrEF[b1] xor Arr5B[b2] xor Arr5B[b3];
  z1 := Arr5B[b0] xor ArrEF[b1] xor ArrEF[b2] xor b3;
  z2 := ArrEF[b0] xor Arr5b[b1] xor b2 xor ArrEF[b3];
  z3 := ArrEF[b0] xor b1 xor ArrEF[b2] xor Arr5B[b3];

  Result := Cardinal(z0) or Cardinal(z1 shl 8) or Cardinal(z2 shl 16) or Cardinal(z3 shl 24);
end;

function TwofishCalculateSBoxes(X : cardinal; L : pointer; KeySize : cardinal) : cardinal; register;
var
  b0, b1, b2, b3 : Byte;
begin
  { precalculating permutations for H function }

  b0 := X and $ff;
  b1 := (X shr 8) and $ff;
  b2 := (X shr 16) and $ff;
  b3 := X shr 24;

  if KeySize > 192 then
  begin
    b0 := P8x8[1, b0] xor PByte(PtrUInt(L) + 12)^;
    b1 := P8x8[0, b1] xor PByte(PtrUInt(L) + 13)^;
    b2 := P8x8[0, b2] xor PByte(PtrUInt(L) + 14)^;
    b3 := P8x8[1, b3] xor PByte(PtrUInt(L) + 15)^;
  end;
  if KeySize > 128 then
  begin
    b0 := P8x8[1, b0] xor PByte(PtrUInt(L) + 8)^;
    b1 := P8x8[1, b1] xor PByte(PtrUInt(L) + 9)^;
    b2 := P8x8[0, b2] xor PByte(PtrUInt(L) + 10)^;
    b3 := P8x8[0, b3] xor PByte(PtrUInt(L) + 11)^;
  end;

  b0 := P8x8[0, b0] xor PByte(PtrUInt(L) + 4)^;
  b1 := P8x8[1, b1] xor PByte(PtrUInt(L) + 5)^;
  b2 := P8x8[0, b2] xor PByte(PtrUInt(L) + 6)^;
  b3 := P8x8[1, b3] xor PByte(PtrUInt(L) + 7)^;

  b0 := P8x8[1, P8x8[0, b0] xor PByte(L)^];
  b1 := P8x8[0, P8x8[0, b1] xor PByte(PtrUInt(L) + 1)^];
  b2 := P8x8[1, P8x8[1, b2] xor PByte(PtrUInt(L) + 2)^];
  b3 := P8x8[0, P8x8[1, b3] xor PByte(PtrUInt(L) + 3)^];

  Result := Cardinal(b0) or Cardinal(b1 shl 8) or Cardinal(b2 shl 16) or Cardinal(b3 shl 24);
end;

function TwofishH(X : cardinal; const Key : TTwofishExpandedKey) : cardinal;  register;   overload; 
var
  b0, b1, b2, b3, z0, z1, z2, z3 : Byte;
begin
  b0 := Key.SBox0[X and $ff];
  b1 := Key.SBox1[(X shr 8) and $ff];
  b2 := Key.SBox2[(X shr 16) and $ff];
  b3 := Key.SBox3[X shr 24];

  { P8x8 permutations are precalculated and stored in Key.SBoxes }

  z0 := b0 xor ArrEF[b1] xor Arr5B[b2] xor Arr5B[b3];
  z1 := Arr5B[b0] xor ArrEF[b1] xor ArrEF[b2] xor b3;
  z2 := ArrEF[b0] xor Arr5b[b1] xor b2 xor ArrEF[b3];
  z3 := ArrEF[b0] xor b1 xor ArrEF[b2] xor Arr5B[b3];

  Result := Cardinal(z0) or Cardinal(z1 shl 8) or Cardinal(z2 shl 16) or Cardinal(z3 shl 24);
end;

procedure EncryptBlock(const ExpandedKey : TTwofishExpandedKey; var B0, B1, B2, B3 : cardinal);
var
  R0, R1, R2, R3, T0, T1, F0, F1 : Cardinal;
begin
  { prewhitening }
  R0 := B0 xor ExpandedKey.ExpandedKey[0];
  R1 := B1 xor ExpandedKey.ExpandedKey[1];
  R2 := B2 xor ExpandedKey.ExpandedKey[2];
  R3 := B3 xor ExpandedKey.ExpandedKey[3];

  { 0 round }
  T0 := TwofishH(R0, ExpandedKey);
  T1 := (R1 shl 8) or (R1 shr 24);
  T1 := TwofishH(T1, ExpandedKey);
  F0 := (T0 + T1 + ExpandedKey.ExpandedKey[8]);
  F1 := (T0 + T1 shl 1 + ExpandedKey.ExpandedKey[9]);

  R2 := R2 xor F0;
  R2 := (R2 shr 1) or (R2 shl 31);
  R3 := (R3 shl 1) or (R3 shr 31) xor F1;

  { 1 round }
  T0 := TwofishH(R2, ExpandedKey);
  T1 := Cardinal(R3 shl 8) or (R3 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[10]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[11]);

  R0 := R0 xor F0;
  R0 := (R0 shr 1) or Cardinal(R0 shl 31);
  R1 := Cardinal(R1 shl 1) or (R1 shr 31) xor F1;

  { 2 round }
  T0 := TwofishH(R0, ExpandedKey);
  T1 := Cardinal(R1 shl 8) or (R1 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[12]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[13]);

  R2 := R2 xor F0;
  R2 := (R2 shr 1) or Cardinal(R2 shl 31);
  R3 := Cardinal(R3 shl 1) or (R3 shr 31) xor F1;

  { 3 round }
  T0 := TwofishH(R2, ExpandedKey);
  T1 := Cardinal(R3 shl 8) or (R3 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[14]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[15]);

  R0 := R0 xor F0;
  R0 := (R0 shr 1) or Cardinal(R0 shl 31);
  R1 := Cardinal(R1 shl 1) or (R1 shr 31) xor F1;

  { 4 round }
  T0 := TwofishH(R0, ExpandedKey);
  T1 := Cardinal(R1 shl 8) or (R1 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[16]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[17]);

  R2 := R2 xor F0;
  R2 := (R2 shr 1) or Cardinal(R2 shl 31);
  R3 := Cardinal(R3 shl 1) or (R3 shr 31) xor F1;

  { 5 round }
  T0 := TwofishH(R2, ExpandedKey);
  T1 := Cardinal(R3 shl 8) or (R3 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[18]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[19]);

  R0 := R0 xor F0;
  R0 := (R0 shr 1) or Cardinal(R0 shl 31);
  R1 := Cardinal(R1 shl 1) or (R1 shr 31) xor F1;

  { 6 round }
  T0 := TwofishH(R0, ExpandedKey);
  T1 := Cardinal(R1 shl 8) or (R1 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[20]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[21]);

  R2 := R2 xor F0;
  R2 := (R2 shr 1) or Cardinal(R2 shl 31);
  R3 := Cardinal(R3 shl 1) or (R3 shr 31) xor F1;

  { 7 round }
  T0 := TwofishH(R2, ExpandedKey);
  T1 := Cardinal(R3 shl 8) or (R3 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[22]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[23]);

  R0 := R0 xor F0;
  R0 := (R0 shr 1) or Cardinal(R0 shl 31);
  R1 := Cardinal(R1 shl 1) or (R1 shr 31) xor F1;

  { 8 round }
  T0 := TwofishH(R0, ExpandedKey);
  T1 := Cardinal(R1 shl 8) or (R1 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[24]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[25]);

  R2 := R2 xor F0;
  R2 := (R2 shr 1) or Cardinal(R2 shl 31);
  R3 := Cardinal(R3 shl 1) or (R3 shr 31) xor F1;

  { 9 round }
  T0 := TwofishH(R2, ExpandedKey);
  T1 := Cardinal(R3 shl 8) or (R3 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[26]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[27]);

  R0 := R0 xor F0;
  R0 := (R0 shr 1) or Cardinal(R0 shl 31);
  R1 := Cardinal(R1 shl 1) or (R1 shr 31) xor F1;

  { 10 round }
  T0 := TwofishH(R0, ExpandedKey);
  T1 := Cardinal(R1 shl 8) or (R1 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[28]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[29]);

  R2 := R2 xor F0;
  R2 := (R2 shr 1) or Cardinal(R2 shl 31);
  R3 := Cardinal(R3 shl 1) or (R3 shr 31) xor F1;

  { 11 round }
  T0 := TwofishH(R2, ExpandedKey);
  T1 := Cardinal(R3 shl 8) or (R3 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[30]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[31]);

  R0 := R0 xor F0;
  R0 := (R0 shr 1) or Cardinal(R0 shl 31);
  R1 := Cardinal(R1 shl 1) or (R1 shr 31) xor F1;

  { 12 round }
  T0 := TwofishH(R0, ExpandedKey);
  T1 := Cardinal(R1 shl 8) or (R1 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[32]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[33]);

  R2 := R2 xor F0;
  R2 := (R2 shr 1) or Cardinal(R2 shl 31);
  R3 := Cardinal(R3 shl 1) or (R3 shr 31) xor F1;

  { 13 round }
  T0 := TwofishH(R2, ExpandedKey);
  T1 := Cardinal(R3 shl 8) or (R3 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[34]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[35]);

  R0 := R0 xor F0;
  R0 := (R0 shr 1) or Cardinal(R0 shl 31);
  R1 := Cardinal(R1 shl 1) or (R1 shr 31) xor F1;

  { 14 round }
  T0 := TwofishH(R0, ExpandedKey);
  T1 := Cardinal(R1 shl 8) or (R1 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[36]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[37]);

  R2 := R2 xor F0;
  R2 := (R2 shr 1) or Cardinal(R2 shl 31);
  R3 := Cardinal(R3 shl 1) or (R3 shr 31) xor F1;

  { 15 round }
  T0 := TwofishH(R2, ExpandedKey);
  T1 := Cardinal(R3 shl 8) or (R3 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[38]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[39]);

  R0 := R0 xor F0;
  R0 := (R0 shr 1) or Cardinal(R0 shl 31);
  R1 := Cardinal(R1 shl 1) or (R1 shr 31) xor F1;

  B0 := R2 xor ExpandedKey.ExpandedKey[4];
  B1 := R3 xor ExpandedKey.ExpandedKey[5];
  B2 := R0 xor ExpandedKey.ExpandedKey[6];
  B3 := R1 xor ExpandedKey.ExpandedKey[7];
end;

procedure DecryptBlock(const ExpandedKey : TTwofishExpandedKey; var B0, B1, B2, B3 : cardinal);
var
  R0, R1, R2, R3, T0, T1, F0, F1 : Cardinal;
begin
  { prewhitening }
  R0 := B0 xor ExpandedKey.ExpandedKey[4];
  R1 := B1 xor ExpandedKey.ExpandedKey[5];
  R2 := B2 xor ExpandedKey.ExpandedKey[6];
  R3 := B3 xor ExpandedKey.ExpandedKey[7];

  {R0,R1 and R2,R3 are replaced from round to round - small optimization}

  { 15 round }
  T0 := TwofishH(R0, ExpandedKey);;
  T1 := Cardinal(R1 shl 8) or (R1 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[38]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[39]);

  R2 := (R2 shl 1) or Cardinal(R2 shr 31) xor F0;
  R3 := R3 xor F1;  
  R3 := Cardinal(R3 shr 1) or (R3 shl 31);

  { 14 round }
  T0 := TwofishH(R2, ExpandedKey);;
  T1 := Cardinal(R3 shl 8) or (R3 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[36]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[37]);

  R0 := (R0 shl 1) or Cardinal(R0 shr 31) xor F0;
  R1 := R1 xor F1;
  R1 := Cardinal(R1 shr 1) or (R1 shl 31);

  { 13 round }
  T0 := TwofishH(R0, ExpandedKey);;
  T1 := Cardinal(R1 shl 8) or (R1 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[34]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[35]);

  R2 := (R2 shl 1) or Cardinal(R2 shr 31) xor F0;
  R3 := R3 xor F1;
  R3 := Cardinal(R3 shr 1) or (R3 shl 31);

  { 12 round }
  T0 := TwofishH(R2, ExpandedKey);;
  T1 := Cardinal(R3 shl 8) or (R3 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[32]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[33]);

  R0 := (R0 shl 1) or Cardinal(R0 shr 31) xor F0;
  R1 := R1 xor F1;
  R1 := Cardinal(R1 shr 1) or (R1 shl 31);

  { 11 round }
  T0 := TwofishH(R0, ExpandedKey);;
  T1 := Cardinal(R1 shl 8) or (R1 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[30]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[31]);

  R2 := (R2 shl 1) or Cardinal(R2 shr 31) xor F0;
  R3 := R3 xor F1;
  R3 := Cardinal(R3 shr 1) or (R3 shl 31);

  { 10 round }
  T0 := TwofishH(R2, ExpandedKey);;
  T1 := Cardinal(R3 shl 8) or (R3 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[28]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[29]);

  R0 := (R0 shl 1) or Cardinal(R0 shr 31) xor F0;
  R1 := R1 xor F1;
  R1 := Cardinal(R1 shr 1) or (R1 shl 31);

  { 9 round }
  T0 := TwofishH(R0, ExpandedKey);;
  T1 := Cardinal(R1 shl 8) or (R1 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[26]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[27]);

  R2 := (R2 shl 1) or Cardinal(R2 shr 31) xor F0;
  R3 := R3 xor F1;
  R3 := Cardinal(R3 shr 1) or (R3 shl 31);

  { 8 round }
  T0 := TwofishH(R2, ExpandedKey);;
  T1 := Cardinal(R3 shl 8) or (R3 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[24]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[25]);

  R0 := (R0 shl 1) or Cardinal(R0 shr 31) xor F0;
  R1 := R1 xor F1;
  R1 := Cardinal(R1 shr 1) or (R1 shl 31);

  { 7 round }
  T0 := TwofishH(R0, ExpandedKey);
  T1 := Cardinal(R1 shl 8) or (R1 shr 24);
  T1 := TwofishH(T1, ExpandedKey);
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[22]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[23]);

  R2 := (R2 shl 1) or Cardinal(R2 shr 31) xor F0;
  R3 := R3 xor F1;
  R3 := Cardinal(R3 shr 1) or (R3 shl 31);

  { 6 round }
  T0 := TwofishH(R2, ExpandedKey);;
  T1 := Cardinal(R3 shl 8) or (R3 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[20]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[21]);

  R0 := (R0 shl 1) or Cardinal(R0 shr 31) xor F0;
  R1 := R1 xor F1;
  R1 := Cardinal(R1 shr 1) or (R1 shl 31);

  { 5 round }
  T0 := TwofishH(R0, ExpandedKey);;
  T1 := Cardinal(R1 shl 8) or (R1 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[18]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[19]);

  R2 := (R2 shl 1) or Cardinal(R2 shr 31) xor F0;
  R3 := R3 xor F1;
  R3 := Cardinal(R3 shr 1) or (R3 shl 31);

  { 4 round }
  T0 := TwofishH(R2, ExpandedKey);;
  T1 := Cardinal(R3 shl 8) or (R3 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[16]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[17]);

  R0 := (R0 shl 1) or Cardinal(R0 shr 31) xor F0;
  R1 := R1 xor F1;
  R1 := Cardinal(R1 shr 1) or (R1 shl 31);

  { 3 round }
  T0 := TwofishH(R0, ExpandedKey);;
  T1 := Cardinal(R1 shl 8) or (R1 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[14]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[15]);

  R2 := (R2 shl 1) or Cardinal(R2 shr 31) xor F0;
  R3 := R3 xor F1;
  R3 := Cardinal(R3 shr 1) or (R3 shl 31);

  { 2 round }
  T0 := TwofishH(R2, ExpandedKey);;
  T1 := Cardinal(R3 shl 8) or (R3 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[12]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[13]);

  R0 := (R0 shl 1) or Cardinal(R0 shr 31) xor F0;
  R1 := R1 xor F1;
  R1 := Cardinal(R1 shr 1) or (R1 shl 31);

  { 1 round }
  T0 := TwofishH(R0, ExpandedKey);;
  T1 := Cardinal(R1 shl 8) or (R1 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[10]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[11]);

  R2 := (R2 shl 1) or Cardinal(R2 shr 31) xor F0;
  R3 := R3 xor F1;
  R3 := Cardinal(R3 shr 1) or (R3 shl 31);

  { 0 round }
  T0 := TwofishH(R2, ExpandedKey);;
  T1 := Cardinal(R3 shl 8) or (R3 shr 24);
  T1 := TwofishH(T1, ExpandedKey);;
  F0 := Cardinal(T0 + T1 + ExpandedKey.ExpandedKey[8]);
  F1 := Cardinal(T0 + T1 shl 1 + ExpandedKey.ExpandedKey[9]);

  R0 := (R0 shl 1) or Cardinal(R0 shr 31) xor F0;
  R1 := R1 xor F1;
  R1 := Cardinal(R1 shr 1) or (R1 shl 31);

  B0 := R2 xor ExpandedKey.ExpandedKey[0];
  B1 := R3 xor ExpandedKey.ExpandedKey[1];
  B2 := R0 xor ExpandedKey.ExpandedKey[2];
  B3 := R1 xor ExpandedKey.ExpandedKey[3];
end;

function RSMDSMul(X, Y : byte) : byte;
var
  Res : Cardinal;
  Index : byte;
begin
  Res := 0;

  for Index := 7 downto 0 do
  begin
    if (Y and (1 shl Index)) <> 0 then
      Res := Res xor (Cardinal(X) shl Index);

    if (Res and (1 shl (8 + Index))) <> 0 then
      Res := Res xor ($14D shl Index);
  end;

  Result := Byte(Res);
end;

function MultiplyMDS(E, O : cardinal) : cardinal;
var
  E0, E1, E2, E3, O0, O1, O2, O3, R0, R1, R2, R3 : Byte;
begin
  E0 := E and $ff;
  E1 := (E shr 8) and $ff;
  E2 := (E shr 16) and $ff;
  E3 := (E shr 24) and $ff;
  O0 := O and $ff;
  O1 := (O shr 8) and $ff;
  O2 := (O shr 16) and $ff;
  O3 := (O shr 24) and $ff;

  R0 := RSMDSMul(E0, MDS[0, 0]) xor RSMDSMul(E1, MDS[0, 1]) xor
    RSMDSMul(E2, MDS[0, 2]) xor RSMDSMul(E3, MDS[0, 3]) xor
    RSMDSMul(O0, MDS[0, 4]) xor RSMDSMul(O1, MDS[0, 5]) xor
    RSMDSMul(O2, MDS[0, 6]) xor RSMDSMul(O3, MDS[0, 7]);
  R1 := RSMDSMul(E0, MDS[1, 0]) xor RSMDSMul(E1, MDS[1, 1]) xor
    RSMDSMul(E2, MDS[1, 2]) xor RSMDSMul(E3, MDS[1, 3]) xor
    RSMDSMul(O0, MDS[1, 4]) xor RSMDSMul(O1, MDS[1, 5]) xor
    RSMDSMul(O2, MDS[1, 6]) xor RSMDSMul(O3, MDS[1, 7]);
  R2 := RSMDSMul(E0, MDS[2, 0]) xor RSMDSMul(E1, MDS[2, 1]) xor
    RSMDSMul(E2, MDS[2, 2]) xor RSMDSMul(E3, MDS[2, 3]) xor
    RSMDSMul(O0, MDS[2, 4]) xor RSMDSMul(O1, MDS[2, 5]) xor
    RSMDSMul(O2, MDS[2, 6]) xor RSMDSMul(O3, MDS[2, 7]);
  R3 := RSMDSMul(E0, MDS[3, 0]) xor RSMDSMul(E1, MDS[3, 1]) xor
    RSMDSMul(E2, MDS[3, 2]) xor RSMDSMul(E3, MDS[3, 3]) xor
    RSMDSMul(O0, MDS[3, 4]) xor RSMDSMul(O1, MDS[3, 5]) xor
    RSMDSMul(O2, MDS[3, 6]) xor RSMDSMul(O3, MDS[3, 7]);

  Result := R0 or (R1 shl 8) or (R2 shl 16) or (R3 shl 24);
end;


procedure ExpandKey(const Key : ByteArray; var ExpandedKey : TTwofishExpandedKey);
var
  I, Cnt : integer;
  KE: array[0..3] of cardinal;
  KO : array[0..3] of cardinal;
  A, B : cardinal;
begin

  Cnt := (Length(Key) shl 3 + 63) shr 6;
  ExpandedKey.KeyLen := Length(Key) shl 3;
  for I := 0 to Cnt - 1 do
  begin
    KE[I] := Key[I shl 3] + Key[I shl 3 + 1] shl 8 + Key[I shl 3 + 2] shl 16 + Key[I shl 3 + 3] shl 24;
    KO[I] := Key[I shl 3 + 4] + Key[I shl 3 + 5] shl 8 + Key[I shl 3 + 6] shl 16 + Key[I shl 3 + 7] shl 24;

    ExpandedKey.SBoxKey[Cnt - I - 1] := MultiplyMDS(KE[I], KO[I]);
  end;
  for I := 0 to 19 do
  begin
    A := TwofishH(I * $02020202, @KE, ExpandedKey.KeyLen);
    B := TwofishH(I * $02020202 + $01010101, @KO, ExpandedKey.KeyLen);
    B := (B shl 8) or (B shr 24);
    ExpandedKey.ExpandedKey[i shl 1] := A + B;
    B := A + B shl 1;
    ExpandedKey.ExpandedKey[i shl 1 + 1] := (B shl 9) or (B shr 23);
  end;

  for I := 0 to 255 do
  begin
    A := (I and $ff) or ((I and $ff) shl 8) or ((I and $ff) shl 16) or ((I and $ff) shl 24);
    A := TwofishCalculateSBoxes(A, @ExpandedKey.SBoxKey, ExpandedKey.KeyLen);
    ExpandedKey.SBox0[I] := A and $ff;
    ExpandedKey.SBox1[I] := (A shr 8) and $ff;
    ExpandedKey.SBox2[I] := (A shr 16) and $ff;
    ExpandedKey.SBox3[I] := (A shr 24) and $ff;
  end;
end;

end.
