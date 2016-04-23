(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBSRP;

interface

uses
  SBTypes,
  SBUtils,
  SBHashFunction,
  SBMath,
  //SBRandom,
  SBStrUtils,
  SBConstants,
  SBMD
  ,
  SysUtils
  ;

type
  TSRPContext = record
    Salt: PLInt;
    A, A_Small: PLInt;
    B, B_Small: PLInt;
    V: PLInt;
    U: PLInt;
    N: PLInt;
    K: PLInt;
    G: PLInt;
    X: PLInt;
    S: PLInt;
    Initialized: boolean;
  end;

  TSSRPPrimeLen = 
  (sr1024, sr1536, sr2048, sr3072, sr4096, sr6144, sr8192);

const
  TSRPPrimesGen_1024: integer = 2;
const
  TSRPPrimes_1024: array[0..127] of byte =
 ( 
  $EE, $AF, $0A, $B9, $AD, $B3, $8D, $D6, $9C, $33, $F8, $0A, $FA, $8F, $C5, $E8,
    $60, $72, $61, $87, $75, $FF, $3C, $0B, $9E, $A2, $31, $4C, $9C, $25, $65, $76,
    $D6, $74, $DF, $74, $96, $EA, $81, $D3, $38, $3B, $48, $13, $D6, $92, $C6, $E0,
    $E0, $D5, $D8, $E2, $50, $B9, $8B, $E4, $8E, $49, $5C, $1D, $60, $89, $DA, $D1,
    $5D, $C7, $D7, $B4, $61, $54, $D6, $B6, $CE, $8E, $F4, $AD, $69, $B1, $5D, $49,
    $82, $55, $9B, $29, $7B, $CF, $18, $85, $C5, $29, $F5, $66, $66, $0E, $57, $EC,
    $68, $ED, $BC, $3C, $05, $72, $6C, $C0, $2F, $D4, $CB, $F4, $97, $6E, $AA, $9A,
    $FD, $51, $38, $FE, $83, $76, $43, $5B, $9F, $C6, $1D, $2F, $C0, $EB, $06, $E3
 ) ;

const
  TSRPPrimesGen_1536 = 2;
const
  TSRPPrimes_1536: array[0..191] of byte =
 ( 
  $9D, $EF, $3C, $AF, $B9, $39, $27, $7A, $B1, $F1, $2A, $86, $17, $A4, $7B, $BB,
    $DB, $A5, $1D, $F4, $99, $AC, $4C, $80, $BE, $EE, $A9, $61, $4B, $19, $CC, $4D,
    $5F, $4F, $5F, $55, $6E, $27, $CB, $DE, $51, $C6, $A9, $4B, $E4, $60, $7A, $29,
    $15, $58, $90, $3B, $A0, $D0, $F8, $43, $80, $B6, $55, $BB, $9A, $22, $E8, $DC,
    $DF, $02, $8A, $7C, $EC, $67, $F0, $D0, $81, $34, $B1, $C8, $B9, $79, $89, $14,
    $9B, $60, $9E, $0B, $E3, $BA, $B6, $3D, $47, $54, $83, $81, $DB, $C5, $B1, $FC,
    $76, $4E, $3F, $4B, $53, $DD, $9D, $A1, $15, $8B, $FD, $3E, $2B, $9C, $8C, $F5,
    $6E, $DF, $01, $95, $39, $34, $96, $27, $DB, $2F, $D5, $3D, $24, $B7, $C4, $86,
    $65, $77, $2E, $43, $7D, $6C, $7F, $8C, $E4, $42, $73, $4A, $F7, $CC, $B7, $AE,
    $83, $7C, $26, $4A, $E3, $A9, $BE, $B8, $7F, $8A, $2F, $E9, $B8, $B5, $29, $2E,
    $5A, $02, $1F, $FF, $5E, $91, $47, $9E, $8C, $E7, $A2, $8C, $24, $42, $C6, $F3,
    $15, $18, $0F, $93, $49, $9A, $23, $4D, $CF, $76, $E3, $FE, $D1, $35, $F9, $BB
 ) ;

const
  TSRPPrimesGen_2048 = 2;
const
  TSRPPrimes_2048: array[0..255] of byte =
 ( 
  $AC, $6B, $DB, $41, $32, $4A, $9A, $9B, $F1, $66, $DE, $5E, $13, $89, $58, $2F,
    $AF, $72, $B6, $65, $19, $87, $EE, $07, $FC, $31, $92, $94, $3D, $B5, $60, $50,
    $A3, $73, $29, $CB, $B4, $A0, $99, $ED, $81, $93, $E0, $75, $77, $67, $A1, $3D,
    $D5, $23, $12, $AB, $4B, $03, $31, $0D, $CD, $7F, $48, $A9, $DA, $04, $FD, $50,
    $E8, $08, $39, $69, $ED, $B7, $67, $B0, $CF, $60, $95, $17, $9A, $16, $3A, $B3,
    $66, $1A, $05, $FB, $D5, $FA, $AA, $E8, $29, $18, $A9, $96, $2F, $0B, $93, $B8,
    $55, $F9, $79, $93, $EC, $97, $5E, $EA, $A8, $0D, $74, $0A, $DB, $F4, $FF, $74,
    $73, $59, $D0, $41, $D5, $C3, $3E, $A7, $1D, $28, $1E, $44, $6B, $14, $77, $3B,
    $CA, $97, $B4, $3A, $23, $FB, $80, $16, $76, $BD, $20, $7A, $43, $6C, $64, $81,
    $F1, $D2, $B9, $07, $87, $17, $46, $1A, $5B, $9D, $32, $E6, $88, $F8, $77, $48,
    $54, $45, $23, $B5, $24, $B0, $D5, $7D, $5E, $A7, $7A, $27, $75, $D2, $EC, $FA,
    $03, $2C, $FB, $DB, $F5, $2F, $B3, $78, $61, $60, $27, $90, $04, $E5, $7A, $E6,
    $AF, $87, $4E, $73, $03, $CE, $53, $29, $9C, $CC, $04, $1C, $7B, $C3, $08, $D8,
    $2A, $56, $98, $F3, $A8, $D0, $C3, $82, $71, $AE, $35, $F8, $E9, $DB, $FB, $B6,
    $94, $B5, $C8, $03, $D8, $9F, $7A, $E4, $35, $DE, $23, $6D, $52, $5F, $54, $75,
    $9B, $65, $E3, $72, $FC, $D6, $8E, $F2, $0F, $A7, $11, $1F, $9E, $4A, $FF, $73
 ) ;

const
  TSRPPrimesGen_3072 = 5;
const
  TSRPPrimes_3072: array[0..383] of byte =
 ( 
  $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $C9, $0F, $DA, $A2, $21, $68, $C2, $34, $C4, $C6, $62, $8B, $80, $DC, $1C, $D1, $29, $02, $4E, $08,
    $8A, $67, $CC, $74, $02, $0B, $BE, $A6, $3B, $13, $9B, $22, $51, $4A, $08, $79, $8E, $34, $04, $DD, $EF, $95, $19, $B3, $CD, $3A, $43, $1B,
    $30, $2B, $0A, $6D, $F2, $5F, $14, $37, $4F, $E1, $35, $6D, $6D, $51, $C2, $45, $E4, $85, $B5, $76, $62, $5E, $7E, $C6, $F4, $4C, $42, $E9,
    $A6, $37, $ED, $6B, $0B, $FF, $5C, $B6, $F4, $06, $B7, $ED, $EE, $38, $6B, $FB, $5A, $89, $9F, $A5, $AE, $9F, $24, $11, $7C, $4B, $1F, $E6,
    $49, $28, $66, $51, $EC, $E4, $5B, $3D, $C2, $00, $7C, $B8, $A1, $63, $BF, $05, $98, $DA, $48, $36, $1C, $55, $D3, $9A, $69, $16, $3F, $A8,
    $FD, $24, $CF, $5F, $83, $65, $5D, $23, $DC, $A3, $AD, $96, $1C, $62, $F3, $56, $20, $85, $52, $BB, $9E, $D5, $29, $07, $70, $96, $96, $6D,
    $67, $0C, $35, $4E, $4A, $BC, $98, $04, $F1, $74, $6C, $08, $CA, $18, $21, $7C, $32, $90, $5E, $46, $2E, $36, $CE, $3B, $E3, $9E, $77, $2C,
    $18, $0E, $86, $03, $9B, $27, $83, $A2, $EC, $07, $A2, $8F, $B5, $C5, $5D, $F0, $6F, $4C, $52, $C9, $DE, $2B, $CB, $F6, $95, $58, $17, $18,
    $39, $95, $49, $7C, $EA, $95, $6A, $E5, $15, $D2, $26, $18, $98, $FA, $05, $10, $15, $72, $8E, $5A, $8A, $AA, $C4, $2D, $AD, $33, $17, $0D,
    $04, $50, $7A, $33, $A8, $55, $21, $AB, $DF, $1C, $BA, $64, $EC, $FB, $85, $04, $58, $DB, $EF, $0A, $8A, $EA, $71, $57, $5D, $06, $0C, $7D,
    $B3, $97, $0F, $85, $A6, $E1, $E4, $C7, $AB, $F5, $AE, $8C, $DB, $09, $33, $D7, $1E, $8C, $94, $E0, $4A, $25, $61, $9D, $CE, $E3, $D2, $26,
    $1A, $D2, $EE, $6B, $F1, $2F, $FA, $06, $D9, $8A, $08, $64, $D8, $76, $02, $73, $3E, $C8, $6A, $64, $52, $1F, $2B, $18, $17, $7B, $20, $0C,
    $BB, $E1, $17, $57, $7A, $61, $5D, $6C, $77, $09, $88, $C0, $BA, $D9, $46, $E2, $08, $E2, $4F, $A0, $74, $E5, $AB, $31, $43, $DB, $5B, $FC,
    $E0, $FD, $10, $8E, $4B, $82, $D1, $20, $A9, $3A, $D2, $CA, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF
 ) ;

const
  TSRPPrimesGen_4096 = 5;
const
  TSRPPrimes_4096: array[0..511] of byte =
 ( 
  $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $C9, $0F, $DA, $A2, $21, $68, $C2, $34, $C4, $C6, $62, $8B, $80, $DC, $1C, $D1, $29, $02, $4E, $08,
    $8A, $67, $CC, $74, $02, $0B, $BE, $A6, $3B, $13, $9B, $22, $51, $4A, $08, $79, $8E, $34, $04, $DD, $EF, $95, $19, $B3, $CD, $3A, $43, $1B,
    $30, $2B, $0A, $6D, $F2, $5F, $14, $37, $4F, $E1, $35, $6D, $6D, $51, $C2, $45, $E4, $85, $B5, $76, $62, $5E, $7E, $C6, $F4, $4C, $42, $E9,
    $A6, $37, $ED, $6B, $0B, $FF, $5C, $B6, $F4, $06, $B7, $ED, $EE, $38, $6B, $FB, $5A, $89, $9F, $A5, $AE, $9F, $24, $11, $7C, $4B, $1F, $E6,
    $49, $28, $66, $51, $EC, $E4, $5B, $3D, $C2, $00, $7C, $B8, $A1, $63, $BF, $05, $98, $DA, $48, $36, $1C, $55, $D3, $9A, $69, $16, $3F, $A8,
    $FD, $24, $CF, $5F, $83, $65, $5D, $23, $DC, $A3, $AD, $96, $1C, $62, $F3, $56, $20, $85, $52, $BB, $9E, $D5, $29, $07, $70, $96, $96, $6D,
    $67, $0C, $35, $4E, $4A, $BC, $98, $04, $F1, $74, $6C, $08, $CA, $18, $21, $7C, $32, $90, $5E, $46, $2E, $36, $CE, $3B, $E3, $9E, $77, $2C,
    $18, $0E, $86, $03, $9B, $27, $83, $A2, $EC, $07, $A2, $8F, $B5, $C5, $5D, $F0, $6F, $4C, $52, $C9, $DE, $2B, $CB, $F6, $95, $58, $17, $18,
    $39, $95, $49, $7C, $EA, $95, $6A, $E5, $15, $D2, $26, $18, $98, $FA, $05, $10, $15, $72, $8E, $5A, $8A, $AA, $C4, $2D, $AD, $33, $17, $0D,
    $04, $50, $7A, $33, $A8, $55, $21, $AB, $DF, $1C, $BA, $64, $EC, $FB, $85, $04, $58, $DB, $EF, $0A, $8A, $EA, $71, $57, $5D, $06, $0C, $7D,
    $B3, $97, $0F, $85, $A6, $E1, $E4, $C7, $AB, $F5, $AE, $8C, $DB, $09, $33, $D7, $1E, $8C, $94, $E0, $4A, $25, $61, $9D, $CE, $E3, $D2, $26,
    $1A, $D2, $EE, $6B, $F1, $2F, $FA, $06, $D9, $8A, $08, $64, $D8, $76, $02, $73, $3E, $C8, $6A, $64, $52, $1F, $2B, $18, $17, $7B, $20, $0C,
    $BB, $E1, $17, $57, $7A, $61, $5D, $6C, $77, $09, $88, $C0, $BA, $D9, $46, $E2, $08, $E2, $4F, $A0, $74, $E5, $AB, $31, $43, $DB, $5B, $FC,
    $E0, $FD, $10, $8E, $4B, $82, $D1, $20, $A9, $21, $08, $01, $1A, $72, $3C, $12, $A7, $87, $E6, $D7, $88, $71, $9A, $10, $BD, $BA, $5B, $26,
    $99, $C3, $27, $18, $6A, $F4, $E2, $3C, $1A, $94, $68, $34, $B6, $15, $0B, $DA, $25, $83, $E9, $CA, $2A, $D4, $4C, $E8, $DB, $BB, $C2, $DB,
    $04, $DE, $8E, $F9, $2E, $8E, $FC, $14, $1F, $BE, $CA, $A6, $28, $7C, $59, $47, $4E, $6B, $C0, $5D, $99, $B2, $96, $4F, $A0, $90, $C3, $A2,
    $23, $3B, $A1, $86, $51, $5B, $E7, $ED, $1F, $61, $29, $70, $CE, $E2, $D7, $AF, $B8, $1B, $DD, $76, $21, $70, $48, $1C, $D0, $06, $91, $27,
    $D5, $B0, $5A, $A9, $93, $B4, $EA, $98, $8D, $8F, $DD, $C1, $86, $FF, $B7, $DC, $90, $A6, $C0, $8F, $4D, $F4, $35, $C9, $34, $06, $31, $99,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF
 ) ;

const
  TSRPPrimesGen_6144 = 5;
const
  TSRPPrimes_6144: array[0..767] of byte =
 ( 
  $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $C9, $0F, $DA, $A2, $21, $68, $C2, $34, $C4, $C6, $62, $8B, $80, $DC, $1C, $D1, $29, $02, $4E, $08,
    $8A, $67, $CC, $74, $02, $0B, $BE, $A6, $3B, $13, $9B, $22, $51, $4A, $08, $79, $8E, $34, $04, $DD, $EF, $95, $19, $B3, $CD, $3A, $43, $1B,
    $30, $2B, $0A, $6D, $F2, $5F, $14, $37, $4F, $E1, $35, $6D, $6D, $51, $C2, $45, $E4, $85, $B5, $76, $62, $5E, $7E, $C6, $F4, $4C, $42, $E9,
    $A6, $37, $ED, $6B, $0B, $FF, $5C, $B6, $F4, $06, $B7, $ED, $EE, $38, $6B, $FB, $5A, $89, $9F, $A5, $AE, $9F, $24, $11, $7C, $4B, $1F, $E6,
    $49, $28, $66, $51, $EC, $E4, $5B, $3D, $C2, $00, $7C, $B8, $A1, $63, $BF, $05, $98, $DA, $48, $36, $1C, $55, $D3, $9A, $69, $16, $3F, $A8,
    $FD, $24, $CF, $5F, $83, $65, $5D, $23, $DC, $A3, $AD, $96, $1C, $62, $F3, $56, $20, $85, $52, $BB, $9E, $D5, $29, $07, $70, $96, $96, $6D,
    $67, $0C, $35, $4E, $4A, $BC, $98, $04, $F1, $74, $6C, $08, $CA, $18, $21, $7C, $32, $90, $5E, $46, $2E, $36, $CE, $3B, $E3, $9E, $77, $2C,
    $18, $0E, $86, $03, $9B, $27, $83, $A2, $EC, $07, $A2, $8F, $B5, $C5, $5D, $F0, $6F, $4C, $52, $C9, $DE, $2B, $CB, $F6, $95, $58, $17, $18,
    $39, $95, $49, $7C, $EA, $95, $6A, $E5, $15, $D2, $26, $18, $98, $FA, $05, $10, $15, $72, $8E, $5A, $8A, $AA, $C4, $2D, $AD, $33, $17, $0D,
    $04, $50, $7A, $33, $A8, $55, $21, $AB, $DF, $1C, $BA, $64, $EC, $FB, $85, $04, $58, $DB, $EF, $0A, $8A, $EA, $71, $57, $5D, $06, $0C, $7D,
    $B3, $97, $0F, $85, $A6, $E1, $E4, $C7, $AB, $F5, $AE, $8C, $DB, $09, $33, $D7, $1E, $8C, $94, $E0, $4A, $25, $61, $9D, $CE, $E3, $D2, $26,
    $1A, $D2, $EE, $6B, $F1, $2F, $FA, $06, $D9, $8A, $08, $64, $D8, $76, $02, $73, $3E, $C8, $6A, $64, $52, $1F, $2B, $18, $17, $7B, $20, $0C,
    $BB, $E1, $17, $57, $7A, $61, $5D, $6C, $77, $09, $88, $C0, $BA, $D9, $46, $E2, $08, $E2, $4F, $A0, $74, $E5, $AB, $31, $43, $DB, $5B, $FC,
    $E0, $FD, $10, $8E, $4B, $82, $D1, $20, $A9, $21, $08, $01, $1A, $72, $3C, $12, $A7, $87, $E6, $D7, $88, $71, $9A, $10, $BD, $BA, $5B, $26,
    $99, $C3, $27, $18, $6A, $F4, $E2, $3C, $1A, $94, $68, $34, $B6, $15, $0B, $DA, $25, $83, $E9, $CA, $2A, $D4, $4C, $E8, $DB, $BB, $C2, $DB,
    $04, $DE, $8E, $F9, $2E, $8E, $FC, $14, $1F, $BE, $CA, $A6, $28, $7C, $59, $47, $4E, $6B, $C0, $5D, $99, $B2, $96, $4F, $A0, $90, $C3, $A2,
    $23, $3B, $A1, $86, $51, $5B, $E7, $ED, $1F, $61, $29, $70, $CE, $E2, $D7, $AF, $B8, $1B, $DD, $76, $21, $70, $48, $1C, $D0, $06, $91, $27,
    $D5, $B0, $5A, $A9, $93, $B4, $EA, $98, $8D, $8F, $DD, $C1, $86, $FF, $B7, $DC, $90, $A6, $C0, $8F, $4D, $F4, $35, $C9, $34, $02, $84, $92,
    $36, $C3, $FA, $B4, $D2, $7C, $70, $26, $C1, $D4, $DC, $B2, $60, $26, $46, $DE, $C9, $75, $1E, $76, $3D, $BA, $37, $BD, $F8, $FF, $94, $06,
    $AD, $9E, $53, $0E, $E5, $DB, $38, $2F, $41, $30, $01, $AE, $B0, $6A, $53, $ED, $90, $27, $D8, $31, $17, $97, $27, $B0, $86, $5A, $89, $18,
    $DA, $3E, $DB, $EB, $CF, $9B, $14, $ED, $44, $CE, $6C, $BA, $CE, $D4, $BB, $1B, $DB, $7F, $14, $47, $E6, $CC, $25, $4B, $33, $20, $51, $51,
    $2B, $D7, $AF, $42, $6F, $B8, $F4, $01, $37, $8C, $D2, $BF, $59, $83, $CA, $01, $C6, $4B, $92, $EC, $F0, $32, $EA, $15, $D1, $72, $1D, $03,
    $F4, $82, $D7, $CE, $6E, $74, $FE, $F6, $D5, $5E, $70, $2F, $46, $98, $0C, $82, $B5, $A8, $40, $31, $90, $0B, $1C, $9E, $59, $E7, $C9, $7F,
    $BE, $C7, $E8, $F3, $23, $A9, $7A, $7E, $36, $CC, $88, $BE, $0F, $1D, $45, $B7, $FF, $58, $5A, $C5, $4B, $D4, $07, $B2, $2B, $41, $54, $AA,
    $CC, $8F, $6D, $7E, $BF, $48, $E1, $D8, $14, $CC, $5E, $D2, $0F, $80, $37, $E0, $A7, $97, $15, $EE, $F2, $9B, $E3, $28, $06, $A1, $D5, $8B,
    $B7, $C5, $DA, $76, $F5, $50, $AA, $3D, $8A, $1F, $BF, $F0, $EB, $19, $CC, $B1, $A3, $13, $D5, $5C, $DA, $56, $C9, $EC, $2E, $F2, $96, $32,
    $38, $7F, $E8, $D7, $6E, $3C, $04, $68, $04, $3E, $8F, $66, $3F, $48, $60, $EE, $12, $BF, $2D, $5B, $0B, $74, $74, $D6, $E6, $94, $F9, $1E,
    $6D, $CC, $40, $24, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF
 ) ;

const
  TSRPPrimesGen_8192 = 19;
const
  TSRPPrimes_8192: array[0..1023] of byte =
 ( 
  $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $C9, $0F, $DA, $A2, $21, $68, $C2, $34, $C4, $C6, $62, $8B, $80, $DC, $1C, $D1, $29, $02, $4E, $08,
    $8A, $67, $CC, $74, $02, $0B, $BE, $A6, $3B, $13, $9B, $22, $51, $4A, $08, $79, $8E, $34, $04, $DD, $EF, $95, $19, $B3, $CD, $3A, $43, $1B,
    $30, $2B, $0A, $6D, $F2, $5F, $14, $37, $4F, $E1, $35, $6D, $6D, $51, $C2, $45, $E4, $85, $B5, $76, $62, $5E, $7E, $C6, $F4, $4C, $42, $E9,
    $A6, $37, $ED, $6B, $0B, $FF, $5C, $B6, $F4, $06, $B7, $ED, $EE, $38, $6B, $FB, $5A, $89, $9F, $A5, $AE, $9F, $24, $11, $7C, $4B, $1F, $E6,
    $49, $28, $66, $51, $EC, $E4, $5B, $3D, $C2, $00, $7C, $B8, $A1, $63, $BF, $05, $98, $DA, $48, $36, $1C, $55, $D3, $9A, $69, $16, $3F, $A8,
    $FD, $24, $CF, $5F, $83, $65, $5D, $23, $DC, $A3, $AD, $96, $1C, $62, $F3, $56, $20, $85, $52, $BB, $9E, $D5, $29, $07, $70, $96, $96, $6D,
    $67, $0C, $35, $4E, $4A, $BC, $98, $04, $F1, $74, $6C, $08, $CA, $18, $21, $7C, $32, $90, $5E, $46, $2E, $36, $CE, $3B, $E3, $9E, $77, $2C,
    $18, $0E, $86, $03, $9B, $27, $83, $A2, $EC, $07, $A2, $8F, $B5, $C5, $5D, $F0, $6F, $4C, $52, $C9, $DE, $2B, $CB, $F6, $95, $58, $17, $18,
    $39, $95, $49, $7C, $EA, $95, $6A, $E5, $15, $D2, $26, $18, $98, $FA, $05, $10, $15, $72, $8E, $5A, $8A, $AA, $C4, $2D, $AD, $33, $17, $0D,
    $04, $50, $7A, $33, $A8, $55, $21, $AB, $DF, $1C, $BA, $64, $EC, $FB, $85, $04, $58, $DB, $EF, $0A, $8A, $EA, $71, $57, $5D, $06, $0C, $7D,
    $B3, $97, $0F, $85, $A6, $E1, $E4, $C7, $AB, $F5, $AE, $8C, $DB, $09, $33, $D7, $1E, $8C, $94, $E0, $4A, $25, $61, $9D, $CE, $E3, $D2, $26,
    $1A, $D2, $EE, $6B, $F1, $2F, $FA, $06, $D9, $8A, $08, $64, $D8, $76, $02, $73, $3E, $C8, $6A, $64, $52, $1F, $2B, $18, $17, $7B, $20, $0C,
    $BB, $E1, $17, $57, $7A, $61, $5D, $6C, $77, $09, $88, $C0, $BA, $D9, $46, $E2, $08, $E2, $4F, $A0, $74, $E5, $AB, $31, $43, $DB, $5B, $FC,
    $E0, $FD, $10, $8E, $4B, $82, $D1, $20, $A9, $21, $08, $01, $1A, $72, $3C, $12, $A7, $87, $E6, $D7, $88, $71, $9A, $10, $BD, $BA, $5B, $26,
    $99, $C3, $27, $18, $6A, $F4, $E2, $3C, $1A, $94, $68, $34, $B6, $15, $0B, $DA, $25, $83, $E9, $CA, $2A, $D4, $4C, $E8, $DB, $BB, $C2, $DB,
    $04, $DE, $8E, $F9, $2E, $8E, $FC, $14, $1F, $BE, $CA, $A6, $28, $7C, $59, $47, $4E, $6B, $C0, $5D, $99, $B2, $96, $4F, $A0, $90, $C3, $A2,
    $23, $3B, $A1, $86, $51, $5B, $E7, $ED, $1F, $61, $29, $70, $CE, $E2, $D7, $AF, $B8, $1B, $DD, $76, $21, $70, $48, $1C, $D0, $06, $91, $27,
    $D5, $B0, $5A, $A9, $93, $B4, $EA, $98, $8D, $8F, $DD, $C1, $86, $FF, $B7, $DC, $90, $A6, $C0, $8F, $4D, $F4, $35, $C9, $34, $02, $84, $92,
    $36, $C3, $FA, $B4, $D2, $7C, $70, $26, $C1, $D4, $DC, $B2, $60, $26, $46, $DE, $C9, $75, $1E, $76, $3D, $BA, $37, $BD, $F8, $FF, $94, $06,
    $AD, $9E, $53, $0E, $E5, $DB, $38, $2F, $41, $30, $01, $AE, $B0, $6A, $53, $ED, $90, $27, $D8, $31, $17, $97, $27, $B0, $86, $5A, $89, $18,
    $DA, $3E, $DB, $EB, $CF, $9B, $14, $ED, $44, $CE, $6C, $BA, $CE, $D4, $BB, $1B, $DB, $7F, $14, $47, $E6, $CC, $25, $4B, $33, $20, $51, $51,
    $2B, $D7, $AF, $42, $6F, $B8, $F4, $01, $37, $8C, $D2, $BF, $59, $83, $CA, $01, $C6, $4B, $92, $EC, $F0, $32, $EA, $15, $D1, $72, $1D, $03,
    $F4, $82, $D7, $CE, $6E, $74, $FE, $F6, $D5, $5E, $70, $2F, $46, $98, $0C, $82, $B5, $A8, $40, $31, $90, $0B, $1C, $9E, $59, $E7, $C9, $7F,
    $BE, $C7, $E8, $F3, $23, $A9, $7A, $7E, $36, $CC, $88, $BE, $0F, $1D, $45, $B7, $FF, $58, $5A, $C5, $4B, $D4, $07, $B2, $2B, $41, $54, $AA,
    $CC, $8F, $6D, $7E, $BF, $48, $E1, $D8, $14, $CC, $5E, $D2, $0F, $80, $37, $E0, $A7, $97, $15, $EE, $F2, $9B, $E3, $28, $06, $A1, $D5, $8B,
    $B7, $C5, $DA, $76, $F5, $50, $AA, $3D, $8A, $1F, $BF, $F0, $EB, $19, $CC, $B1, $A3, $13, $D5, $5C, $DA, $56, $C9, $EC, $2E, $F2, $96, $32,
    $38, $7F, $E8, $D7, $6E, $3C, $04, $68, $04, $3E, $8F, $66, $3F, $48, $60, $EE, $12, $BF, $2D, $5B, $0B, $74, $74, $D6, $E6, $94, $F9, $1E,
    $6D, $BE, $11, $59, $74, $A3, $92, $6F, $12, $FE, $E5, $E4, $38, $77, $7C, $B6, $A9, $32, $DF, $8C, $D8, $BE, $C4, $D0, $73, $B9, $31, $BA,
    $3B, $C8, $32, $B6, $8D, $9D, $D3, $00, $74, $1F, $A7, $BF, $8A, $FC, $47, $ED, $25, $76, $F6, $93, $6B, $A4, $24, $66, $3A, $AB, $63, $9C,
    $5A, $E4, $F5, $68, $34, $23, $B4, $74, $2B, $F1, $C9, $78, $23, $8F, $16, $CB, $E3, $9D, $65, $2D, $E3, $FD, $B8, $BE, $FC, $84, $8A, $D9,
    $22, $22, $2E, $04, $A4, $03, $7C, $07, $13, $EB, $57, $A8, $1A, $23, $F0, $C7, $34, $73, $FC, $64, $6C, $EA, $30, $6B, $4B, $CB, $C8, $86,
    $2F, $83, $85, $DD, $FA, $9D, $4B, $7F, $A2, $C0, $87, $E8, $79, $68, $33, $03, $ED, $5B, $DD, $3A, $06, $2B, $3C, $F5, $B3, $A2, $78, $A6,
    $6D, $2A, $13, $F8, $3F, $44, $F8, $2D, $DF, $31, $0E, $E0, $74, $AB, $6A, $36, $45, $97, $E8, $99, $A0, $25, $5D, $C1, $64, $F3, $1C, $C5,
    $08, $46, $85, $1D, $F9, $AB, $48, $19, $5D, $ED, $7E, $A1, $B1, $D5, $10, $BD, $7E, $E7, $4D, $73, $FA, $F3, $6B, $C3, $1E, $CF, $A2, $68,
    $35, $90, $46, $F4, $EB, $87, $9F, $92, $40, $09, $43, $8B, $48, $1C, $6C, $D7, $88, $9A, $00, $2E, $D5, $EE, $38, $2B, $C9, $19, $0D, $A6,
    $FC, $02, $6E, $47, $95, $58, $E4, $47, $56, $77, $E9, $AA, $9E, $30, $50, $E2, $76, $56, $94, $DF, $C8, $1F, $56, $E8, $80, $B9, $6E, $71,
    $60, $C9, $80, $DD, $98, $ED, $D3, $DF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF
 ) ;

procedure SrpInitContext(var SRP: TSRPContext);
procedure SrpDestroyContext(var SRP: TSRPContext);
procedure SrpServerInit(var SRP: TSRPContext);
procedure SrpGetU(N, A, B: PLInt; Proto: string; var U: PLInt);
procedure SrpGetA(UserName, UserPassword: string; var SRP: TSRPContext);
procedure SrpGetClientX(User, Password: string; Salt: PLInt; var ClX: PLInt);
procedure SrpGetClientKey(var SRP: TSRPContext);
procedure SrpGetServerKey(var SRP: TSRPContext);
procedure SrpGetNewServerData(UserName, UserPassword: string; PrimeLen: TSSRPPrimeLen; var N, G, Salt, V: ByteArray);
function LIntToBytes(I: PLInt): ByteArray;
procedure LInitBytes(I: PLInt; BA: ByteArray);

implementation


procedure SrpInitContext(var SRP: TSRPContext);
begin
  LCreate(SRP.Salt);
  LCreate(SRP.N);
  LCreate(SRP.G);
  LCreate(SRP.X);
  LCreate(SRP.A);
  LCreate(SRP.K);
  LCreate(SRP.A_small);
  LCreate(SRP.B);
  LCreate(SRP.B_small);
  LCreate(SRP.V);
  LCreate(SRP.U);
  LCreate(SRP.S);
  Srp.Initialized := true;
end;

procedure SrpDestroyContext(var SRP: TSRPContext);
begin
  LDestroy(SRP.Salt);
  LDestroy(SRP.N);
  LDestroy(SRP.G);
  LDestroy(SRP.X);
  LDestroy(SRP.A);
  LDestroy(SRP.K);
  LDestroy(SRP.A_small);
  LDestroy(SRP.B);
  LDestroy(SRP.B_small);
  LDestroy(SRP.V);
  LDestroy(SRP.U);
  LDestroy(SRP.S);
end;


procedure SrpServerInit(var SRP: TSRPContext);
var
  Tmp, Tmp1: PLInt;
  HF: TElHashFunction;
  St, St1, St_Sha: string;
  Ba : ByteArray;
  Len: integer;
begin
  try
  
  St := LToStr(SRP.N);
  while (Length(St) > 0) and (St[StringStartOffset] = '0') do
    St := StringSubstring(St, StringStartOffset + 1, Length(St));
  if Length(St) = 0 then
    St := '0';
  St_Sha := St;
  if Odd(Length(St)) then
    St_Sha := '0' + St_Sha;
  St1 := LToStr(SRP.G);
  while (Length(St1) > 0) and (St1[StringStartOffset] = '0') do
    St1 := StringSubstring(St1, StringStartOffset + 1, Length(St1));
  while (Length(St1) < Length(St_Sha)) do
    St1 := '0' + St1;
  St_Sha := St_Sha + St1;
  Len := Length(St_Sha) shr 1;
  SetLength(BA, Len);
  StringToBinary(St_Sha,  @BA[0] , Len);
  HF := TElHashFunction.Create(SB_ALGORITHM_DGST_SHA1);
  HF.Update( @BA[0] , Length(BA));
  BA := HF.Finish;
  St := BinaryToString(@BA[0], Length(BA));
  FreeAndNil(HF);
  LInit(SRP.K, St);
  LMod(SRP.K, SRP.N, SRP.K);

  LGenerate(SRP.B_small, 16);
  LCreate(Tmp);
  LCreate(Tmp1);

  LMult(SRP.V, SRP.K, Tmp);
  LMModPower(SRP.G, SRP.B_small, SRP.N, Tmp1);
  LAdd(Tmp, Tmp1, SRP.B);
  LMod(SRP.B, SRP.N, SRP.B);

  finally
    ReleaseArray(Ba);
  end;

end;

procedure SrpGetU(N, A, B: PLInt; Proto: string; var U: PLInt);
var
  St, St1, St_Sha: string;
  Ba: ByteArray;
  Len, nLen: integer;
  HF: TElHashFunction;
begin

  St := LToStr(N);
  while (Length(St) > 0) and (St[StringStartOffset] = '0') do
    St := StringSubstring(St, StringStartOffset + 1, Length(St));
  if Length(St) = 0 then
    St := '0';
  if Odd(Length(St)) then
    St := '0' + St;
  nLen := Length(St);

  St := LToStr(A);
  while (Length(St) > 0) and (St[StringStartOffset] = '0') do
    St := StringSubstring(St, StringStartOffset + 1, Length(St));
  if Length(St) = 0 then
    St := '0';
  if ((Proto = '3') or (Proto = '6')) and Odd(Length(St)) then
    St := '0' + St;
  if (Proto = '6a') or (Proto = '6A') then
    while (Length(St) < nLen) do
      St := '0' + St;
  St_Sha := St;

  St1 := LToStr(B);
  while (Length(St1) > 0) and (St1[StringStartOffset] = '0') do
    St1 := StringSubstring(St1, StringStartOffset + 1, Length(St1));
  if Length(St1) = 0 then
    St1 := '0';

  if ((Proto = '3') or (Proto = '6')) and Odd(Length(St1)) then
    St1 := '0' + St1;
  if (Proto = '6a') or (Proto = '6A') then
    while (Length(St1) < Length(St_Sha)) do
      St1 := '0' + St1;
  if Proto = '3' then
    St_Sha := '';
  St_Sha := St_Sha + St1;
  Len := Length(St_Sha) shr 1;
  SetLength(BA, Len);


  Assert(False);
  // TODO: EM !!! Check whether StringToBinary and BinaryToString are used right
  // because use of StringOfBytes and BinaryToString below is incorrect - these functions
  // perform different things !!!

  StringToBinary(St_Sha,  @BA[0] , Len);
  HF := TElHashFunction.Create(SB_ALGORITHM_DGST_SHA1);
  HF.Update( @BA[0] , Length(BA));
  St := StringOfBytes(HF.Finish);

  FreeAndNil(HF);
  if Odd(Length(St)) then
    St := '0' + St;
  if Proto = '3' then
    LInit(U, StringSubstring(St, StringStartOffset, 4))
  else
    LInit(U, St);

end;

procedure SrpGetA(UserName, UserPassword: string; var SRP: TSRPContext);
begin
  SrpGetClientX(UserName, UserPassword, SRP.Salt, SRP.X);
  LMModPower(SRP.G, SRP.X, SRP.N, SRP.V);
  LGenerate(SRP.A_small, 16);
  LMModPower(SRP.G, SRP.A_small, SRP.N, SRP.A);
end;

procedure SrpGetClientX(User, Password: string; Salt: PLInt; var ClX: PLInt);
var
  HF: TElHashFunction;
  St: string;
  BA, Ba1: ByteArray;
  Len: integer;
begin
  try

  St := User + ':' + Password;
  Ba := BytesOfString(St);
  HF := TElHashFunction.Create(SB_ALGORITHM_DGST_SHA1);
  HF.Update( @BA[0] , Length(BA));
  Len := 20;
  BA1 := HF.Finish;
  FreeAndNil(HF);
  SetLength(BA, 40);
  Len := 10;

  St := LToStr(Salt);
  while (Length(St) > 0) and (St[StringStartOffset] = '0') do
    St := StringSubstring(St, StringStartOffset + 1, Length(St));
  if Length(St) = 0 then
    St := '0';
  if Odd(Length(St)) then
    St := '0' + St;
  Len := 40;
  SetLength(Ba, Len + 20);
  StringToBinary(St, @Ba[0], Len);
  SBMove(Ba1[0], Ba[Len], 20);
  HF := TElHashFunction.Create(SB_ALGORITHM_DGST_SHA1);
  HF.Update( @BA[0] , Len + 20);
  Len := 20;
  BA := HF.Finish;
  FreeAndNil(HF);

  LInit(ClX, BinaryToString( @BA[0], 20 ));

  finally
    ReleaseArrays(Ba, Ba1);
  end;
end;

{
procedure GetU(N,A,B:PLInt; Proto:string; var U:PLInt);
var
        Sha:TSha1Context;
        St,St1,St_Sha:string;
        Dig:TMessageDigest160;
        Ba:ByteArray;
        Len,nLen:integer;
begin
        St:=LToStr(N);
        while (Length(St)>0) and (St[1]='0') do
                St:=Copy(St,2,Length(St));
        if Length(St)=0 then
                St:='0';
        if Odd(Length(St)) then
           St:='0'+St;
        nLen:=Length(St);

        St:=LToStr(A);
        while (Length(St)>0) and (St[1]='0') do
                St:=Copy(St,2,Length(St));
        if Length(St)=0 then
                St:='0';
        if ((Proto='3') or (Proto='6')) and Odd(Length(St)) then
           St:='0'+St;
        if (Proto='6a') or (Proto='6A') then
                while (Length(St)<nLen) do
                        St:='0'+St;
        St_Sha:=St;

        St1:=LToStr(B);
        while (Length(St1)>0) and (St1[1]='0') do
                St1:=Copy(St1,2,Length(St1));
        if Length(St1)=0 then
                St1:='0';

        if ((Proto='3') or (Proto='6')) and Odd(Length(St1)) then
           St1:='0'+St1;
        if (Proto='6a') or (Proto='6A') then
                while (Length(St1)<Length(St_Sha)) do
                        St1:='0'+St1;
        if Proto='3' then
                St_Sha:='';
        St_Sha:=St_Sha+St1;
        Len:=Length(St_Sha) div 2;
        SetLength(BA,Len);
//        StringToBinary(St_Sha,{$ifdef SB_VCL}{@BA[0]{$else}{BA{$endif}{,Len);
{        SbSha.InitializeSHA1(Sha);
        SbSha.HashSHA1(Sha,{$ifdef SB_VCL}{@BA[0]{$else}{BA{$endif}{,Length(BA));
{        Dig:=SbSha.FinalizeSHA1(Sha);
        SetLength(BA,20);
        {$ifdef SB_VCL}
{        SBMove(Dig, BA[0], 20);
        {$else}
{        BA:=DigestToByteArray160(Dig);
        {$endif}
{        if Proto='3' then
                LInit(U,BinaryToString(@BA[0],4))
        else
                LInit(U,BinaryToString(@BA[0],20));
end; }

procedure GenMulty(N, G: PLInt; Proto: string; var K: PLInt);
var
  St, St1, St_Sha: string;
  Ba: ByteArray;
  Len: integer;
  HF: TElHashFunction;
begin

  if Proto = '3' then
    LInit(K, '1')
  else
    if Proto = '6' then
    LInit(K, '3')
  else
    if (Proto = '6a') or (Proto = '6A') then
  begin
    St := LToStr(N);
    while (Length(St) > 0) and (St[StringStartOffset] = '0') do
      St := StringSubstring(St, StringStartOffset + 1, Length(St));
    if Length(St) = 0 then
      St := '0';
    St_Sha := St;
    if Odd(Length(St)) then
      St_Sha := '0' + St_Sha;
    St1 := LToStr(G);
    while (Length(St1) > 0) and (St1[StringStartOffset] = '0') do
      St1 := StringSubstring(St1, StringStartOffset + 1, Length(St1));
    while (Length(St1) < Length(St_Sha)) do
      St1 := '0' + St1;
    St_Sha := St_Sha + St1;
    Len := Length(St_Sha) shr 1;
    SetLength(BA, Len);
    StringToBinary(St_Sha,  @BA[0] , Len);
    HF := TElHashFunction.Create(SB_ALGORITHM_DGST_SHA1);
    HF.Update( @BA[0] , Length(BA));
    Len := 20;
    BA := HF.Finish;
    FreeAndNil(HF);

    LInit(K, BinaryToString( @BA[0], 20 ));
    LMod(K, N, K);
  end
  else
    LInit(K, '0');

end;

procedure SrpGetClientKey(var SRP: TSRPContext);
var
  Tmp, Tmp1, Tmp2: PLInt;
  St: string;
begin

  LCreate(Tmp);
  LCreate(Tmp1);
  LCreate(Tmp2);
  LMModPower(SRP.G, SRP.X, SRP.N, Tmp);

  GenMulty(SRP.N, SRP.G, '6a', Tmp2);
  LMult(Tmp, Tmp2, Tmp1);
  LMult(SRP.N, Tmp2, Tmp);
  LAdd(SRP.B, Tmp, Tmp2);
  LSub(Tmp2, Tmp1, Tmp);
  LMod(Tmp, SRP.N, Tmp1);
  LCopy(Tmp, Tmp1);

  SrpGetU(SRP.N, SRP.A, SRP.B, '6a', Tmp2);
  LMult(SRP.X, Tmp2, Tmp1);
  LAdd(Tmp1, SRP.A_small, Tmp2);
  St := LToStr(Tmp2);

  LMModPower(Tmp, Tmp2, SRP.N, SRP.S);
end;

procedure SrpGetServerKey(var SRP: TSRPContext);
var
  PLTmp, PlTmp1: PLInt;
begin
  LCreate(PLTmp);
  LCreate(PLTmp1);
  SrpGetU(SRP.N, SRP.A, SRP.B, '6a', SRP.U);
  LMModPower(SRP.V, SRP.U, SRP.N, PLTmp);
  LMult(PLTmp, SRP.A, PLTmp1);
  LMOd(PLTmp1, SRP.N, PLTmp);
  LMModPower(PLTmp, SRP.B_small, SRP.N, SRP.S);
end;

procedure SrpGetNewServerData(UserName, UserPassword: string; PrimeLen: TSSRPPrimeLen; var N, G, Salt, V: ByteArray);
var
  FSalt, FSrpG, FSrpN, FTmp: PLInt;
  Len: integer;
begin
  LCreate(FSalt);
  LGenerate(FSalt, 3);
  LCreate(FSrpN);
  LCreate(FSrpG);
  case PrimeLen of
sr1024:
      begin
        LInit(FSRPG, IntToStr(TSRPPrimesGen_1024));
        LInit(FSRPN, BinaryToString( @TSRPPrimes_1024[0], Length(TSRPPrimes_1024) ));
      end;
sr1536:
      begin
        LInit(FSRPG, IntToStr(TSRPPrimesGen_1536));
        LInit(FSRPN, BinaryToString( @TSRPPrimes_1536[0], Length(TSRPPrimes_1536) ));
      end;
sr2048:
      begin
        LInit(FSRPG, IntToStr(TSRPPrimesGen_2048));
        LInit(FSRPN, BinaryToString( @TSRPPrimes_2048[0], Length(TSRPPrimes_2048) ));
      end;
sr3072:
      begin
        LInit(FSRPG, IntToStr(TSRPPrimesGen_3072));
        LInit(FSRPN, BinaryToString( @TSRPPrimes_3072[0], Length(TSRPPrimes_3072) ));
      end;
sr4096:
      begin
        LInit(FSRPG, IntToStr(TSRPPrimesGen_4096));
        LInit(FSRPN, BinaryToString( @TSRPPrimes_4096[0], Length(TSRPPrimes_4096) ));
      end;
sr6144:
      begin
        LInit(FSRPG, IntToStr(TSRPPrimesGen_6144));
        LInit(FSRPN, BinaryToString( @TSRPPrimes_6144[0], Length(TSRPPrimes_6144) ));
      end;
sr8192:
      begin
        LInit(FSRPG, IntToStr(TSRPPrimesGen_8192));
        LInit(FSRPN, BinaryToString( @TSRPPrimes_8192[0], Length(TSRPPrimes_8192) ));
      end;
  end;
  LCreate(FTmp);
  SrpGetClientX(UserName, UserPassword, FSalt, FTmp);
  LMModPower(FSrpG, FTmp, FSrpN, FTmp);

  Len := (Length(LToStr(FSrpN)) + 1) shr 1;
  SetLength(N, Len);
  StringToBinary(LToStr(FSrpN),  @N[0] , Len);
  LTrim(FSrpG);
  Len := (Length(LToStr(FSrpG)) + 1) shr 1;
  SetLength(G, Len);
  StringToBinary(LToStr(FSrpG),  @G[0] , Len);
  Len := (Length(LToStr(FSalt)) + 1) shr 1;
  SetLength(Salt, Len);
  StringToBinary(LToStr(FSalt),  @Salt[0] , Len);
  Len := (Length(LToStr(FTmp)) + 1) shr 1;
  SetLength(V, Len);
  StringToBinary(LToStr(FTmp),  @V[0] , Len);
end;

function LIntToBytes(I: PLInt): ByteArray;
var
  Len: integer;
begin
  Len := (Length(LToStr(I)) + 1) shr 1;
  SetLength(Result, Len);
  StringToBinary(LToStr(I),  @Result[0] , Len);
end;

procedure LInitBytes(I: PLInt; BA: ByteArray);
begin
  LInit(I, BinaryToString( @Ba[0], Length(Ba) ));
end;

end.

