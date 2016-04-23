(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}      

unit SBUMAC;

interface

uses
  SBCRC,
  SBAES,
  SBTypes,
  SBUtils,
  SBConstants;

type
  UINT64 = Int64;
  UINT8  = byte;    //  1 byte
  UINT16 = WORD;    //  2 byte
  UINT32 = DWORD;   //  4 byte
  pUINT32 = ^UINT32;
  pUINT64 = ^UINT64;

const

  AES_BLOCK_LEN  = 16;    //  UMAC uses AES with 16 byte block and key lengths
  UMAC_KEY_LEN   = 16;    //  UMAC takes 16 bytes of external key

const

  L1_KEY_LEN       =  1024;     // Internal key bytes
  L1_KEY_SHIFT     =    16;     // Toeplitz key shift between streams
  L1_PAD_BOUNDARY  =    32;     // pad message to boundary multiple
  HASH_BUF_BYTES   =    64;     // NH_aux_hb buffer multiple

type

  UINT64Array = array of UINT64;

  TNHContext  = record//{$ifndef SB_NET}packed{$else}public{$endif} record
    NH_Key: ByteArray;          // NH Key
    Data: ByteArray;            // Incomming data buffer
    Next_Data_Empty: integer;   // Bookeeping variable for data buffer.
    Bytes_Hashed: integer;      // Bytes (out of L1_KEY_LEN) incorperated.
    State: UINT64Array;         // on-line state
  end;

  TUHASHContext =  packed  record
    Hash: TNHContext;            // Hash context for L1 NH hash
    Poly_Key_8: UINT64Array;     // p64 poly keys
    Poly_Accum: UINT64Array;     // poly hash result
    IP_Keys: UINT64Array;        // Inner-product keys
    IP_Trans: ByteArray;         // Inner-product translation
    Msg_Len: cardinal;           // Total length of data passed to uhash
  end;

  TPDFContext =  packed  record
    Cache: TAESBuffer;            // Previous AES output is saved
    Nonce: TAESBuffer;            // The AES input making above cache
    PRF_Key: TAESExpandedKey128;  // Expanded AES key for PDF
  end;  // pdf_ctx;

  TElUMAC = class
  protected
    fHash: TUHASHContext;    //  Hash function for message compression
    fPDF: TPDFContext;       //  PDF for hashed output
    fOutputLen: integer;
    fStreams: integer;
    procedure Initialize_UMAC(const Key: ByteArray; TagLen: integer);
    procedure UHASH_Init(const PRF_Key: TAESExpandedKey128);
    procedure Init_Members;
  {$ifdef BUILDER_USED}  
  public // we need to have it public to avoid BCB crashing
   {$endif}  
    constructor Create();  overload; 
  public
    constructor Create(const Key: ByteArray; TagLen: integer);  overload; 
    constructor Create(const Key: string; TagLen: integer);  overload; 
     destructor  Destroy; override;
    function  Clone: TElUMAC;
    //  Reset the hash function to begin a new authentication
    procedure Reset;
    procedure Update(const In_Buf: ByteArray; StartIndex, Len: cardinal);  overload; 
    procedure Update(In_Buf: Pointer; Size: integer); overload;
    //  Incorporate any pending data, pad, and generate tag
    procedure Final(const Nonce: ByteArray; out Tag: ByteArray);
    //  All-in-one version
    procedure Calculate(const In_Buf: ByteArray; StartIndex, Len: cardinal;
                        const Nonce: ByteArray; out Tag: ByteArray);  overload; 
    procedure Calculate(In_Buf: Pointer; Len: cardinal;
                        const Nonce: ByteArray; out Tag: ByteArray); overload;
  end;


implementation

uses
  SysUtils
  ;

const

  sizeof_UINT64 = sizeof(UINT64);
  sizeof_UINT32 = sizeof(UINT32);

//  Primes and masks
  p36: UINT64 = $0000000FFFFFFFFB;              // 2^36 -  5
  m36: UINT64 = $0000000FFFFFFFFF;              // The low 36 of 64 bits
{$ifdef D_7_UP}
  p64: UINT64 = UINT64($FFFFFFFFFFFFFFC5);
 {$else}
var
  p64: UINT64 = 0;
 {$endif}


procedure Copy_Array(var Dst: ByteArray; StartIndex: integer;
      const Src: array of byte; Qnt: integer); overload;
var
  i: integer;
begin
  for i := 0 to Qnt - 1 do
    Dst[StartIndex + i] := Src[i];
end;

function  Get_UINT32(const Buf: ByteArray; Idx: integer): UINT32; overload;
var
  pAddr: PUINT32;
begin
  pAddr := @Buf[0];
  inc(pAddr, Idx);
  Result := pAddr^;
end;

function  Get_UINT32(const Buf: ByteArray; Offset, Idx: integer): UINT32; overload;
var
  pAddr: PUINT32;
begin
  pAddr := @Buf[Offset];
  inc(pAddr, Idx);
  Result := pAddr^;
end;

function  Get_UINT32(const Buf: TAESBuffer; Idx: integer): UINT32; overload;
var
  pAddr: PUINT32;
begin
  pAddr := @Buf[0];
  inc(pAddr, Idx);
  Result := pAddr^;
end;

function  Get_UINT64(const Buf: TAESBuffer; Idx: integer): UINT64; overload;
var
  pAddr: PUINT64;
begin
  pAddr := @Buf[0];
  inc(pAddr, Idx);
  Result := pAddr^;
end;

function  Get_UINT64(const Buf: ByteArray; Idx: integer): UINT64; overload;
var
  pAddr: PUINT64;
begin
  pAddr := @Buf[0];
  inc(pAddr, Idx);
  Result := pAddr^;
end;

procedure Save_UINT64(var Res: ByteArray; Idx: integer; V: UINT64);
var
  pAddr: PUINT64;
begin
  pAddr := @Res[0];
  inc(pAddr, Idx);
  pAddr^ := V;
end;

procedure Save_UINT32(var Res: ByteArray; Idx: integer; V: UINT32); overload;
var
  pAddr: PUINT32;
begin
  pAddr := @Res[0];
  inc(pAddr, Idx);
  pAddr^ := V;
end;

procedure Save_UINT32(var Res: TAESBuffer; Idx: integer; V: UINT32); overload;
var
  pAddr: PUINT32;
begin
  pAddr := @Res[0];
  inc(pAddr, Idx);
  pAddr^ := V;
end;

function  CRC32(const Arr: ByteArray): cardinal; overload;
begin
  Result := CRC32(@Arr[0], Length(Arr) * sizeof(Arr[0]));
end;

function  CRC32(const Arr: UINT64Array): cardinal; overload;
begin
  Result := CRC32(@Arr[0], Length(Arr) * sizeof(Arr[0]));
end;

function  CRC32(const Arr: TAESBuffer): cardinal; overload;
begin
  Result := CRC32(@Arr[0], Length(Arr) * sizeof(Arr[0]));
end;

function  CRC32(const Arr: TAESExpandedKey128): cardinal; overload;
begin
  Result := CRC32(@Arr[0], Length(Arr) * sizeof(Arr[0]));
end;

procedure  STORE_UINT32_REVERSED(var Arr: ByteArray; StartIndex: integer; V: UINT32);
var
  X: PUINT32;
begin
  X := @Arr[StartIndex];
  X^ := (V shr 24) or ((V and $00FF0000) shr 8 )
         or ((V and $0000FF00) shl 8 ) or (V shl 24);
end;

function  BufToByteArray(Buf: Pointer; Size: cardinal): ByteArray;
var
  P: PByte;
  i: integer;
begin
  P := PByte(Buf);
  SetLength(Result, Size);

  for i := 0 to Size - 1 do
  begin
    Result[i] := P^;
    inc(P);
  end;
end;

function  Cmp64(V1, V2: UINT64): integer;
begin
  if  ((V1 >= 0) and (V2 >= 0))
      or ((V1 < 0) and (V2 < 0))  then
  begin
    if  V1 > V2 then
      Result := 1
    else if V1 = V2 then
      Result := 0
    else
      Result := -1;
  end
  else
  if  V1 < 0  then
    Result := 1
  else
    Result := -1;
end;

procedure Copy_Array(var Dst:  ByteArray ; const Src:  ByteArray );  overload; 
var
  i: integer;
begin
  for i := Low(Src) to High(Src) do
    Dst[i] := Src[i];
end;

procedure Copy_Array(var Dst:  ByteArray ; StartIndex: integer;
      const Src:  ByteArray ; Qnt: integer);  overload; 
var
  i: integer;
begin
  for i := 0 to Qnt - 1 do
    Dst[StartIndex + i] := Src[i];
end;

procedure Copy_Array(var Dst:  ByteArray ; OffsetDst: integer;
      const Src:  ByteArray ; OffsetSrc: integer; Qnt: integer);  overload; 
var
  i: integer;
begin
  for i := 0 to Qnt - 1 do
    Dst[OffsetDst + i] := Src[OffsetSrc + i];
end;

procedure Copy_Array(var Dst: UINT64Array; const Src: UINT64Array);   overload; 
var
  i: integer;
begin
  for i := Low(Src) to High(Src) do
    Dst[i] := Src[i];
end;

procedure Clear_Array(var Dst:  ByteArray ; OffsetDst: integer; nBytes: integer);  overload; 
var
  i: integer;
begin
  for i := 0 to nBytes - 1 do
    Dst[i + OffsetDst] := 0;
end;

procedure Clear_Array(var Dst:  ByteArray );  overload; 
var
  i: integer;
begin
  for i := Low(Dst) to High(Dst) do
    Dst[i] := 0;
end;

function  Calc_MOD(const A, B: UINT64): UINT64;
var
  D: UINT64;
  i, N: integer;
begin
  N := sizeof_UINT64 shl 3;
  Result := 0;
  D := A;

  for i := 1 to N do
  begin
    Result := (Result shl 1) or ((D shr 63) and 1);

    if  Result > B  then
      dec(Result, B);

    D := D shl 1;
  end;
end;

function  Mult64(V1, V2: UINT32): UINT64;
begin
  Result := UINT64(V1) * UINT64(V2);
end;

procedure KDF(var OutBuf: ByteArray; const Key: TAESExpandedKey128;
    Idx: integer; nBytes: integer);
var
  In_Buf, kBuf: TAESBuffer;
  i, k: integer;
  AES_1: integer;
begin
  //  Setup the initial value
  for i := Low(In_Buf) to High(In_Buf) do
    In_Buf[i] := 0;

  k := Low(OutBuf);
  i := 1;
  AES_1 := AES_BLOCK_LEN - 1;
  In_Buf[AES_BLOCK_LEN - 9] := Idx;
  In_Buf[AES_1] := i;

  while (nBytes >= AES_BLOCK_LEN) do
  begin
    Encrypt128(In_Buf, Key, kBuf);
    Copy_Array(OutBuf, k, kBuf, AES_BLOCK_LEN);
    inc(i);
    inc(k, AES_BLOCK_LEN);
    In_Buf[AES_1] := i;
    dec(nBytes, AES_BLOCK_LEN);
  end;

  if nBytes > 0 then
  begin
    Encrypt128(In_Buf, Key, kBuf);
    Copy_Array(OutBuf, k, kBuf, nBytes);
  end;
end;

procedure PDF_Init(var Ctx: TPDFContext; const PRF_Key: TAESExpandedKey128);
var
  Buf: ByteArray;
  K: TAESKey128;
  i: integer;
begin
  SetLength(Buf, Length(K));
  KDF(Buf, PRF_Key, 0, UMAC_KEY_LEN);

  for i := Low(Buf) to High(Buf) do
    K[i] := Buf[i];

  ExpandKeyForEncryption128(K, Ctx.PRF_Key);

  // Initialize PDF and cache

  for i := Low(Ctx.Nonce) to High(Ctx.Nonce) do
    Ctx.Nonce[i] := 0;

  Encrypt128(Ctx.Nonce, Ctx.PRF_Key, Ctx.Cache);

end;

procedure PDF_gen_XOR(var Ctx: TPDFContext; const Nonce: ByteArray;
      var Buf: ByteArray; UMAC_OutputLen: integer);
var
  LOW_BIT_MASK: byte;
  tmp_nonce_lo, wNonce: ByteArray;
  ndx, N: integer;
begin
  SetLength(tmp_nonce_lo, 4);
  SetLength(wNonce, 8);
  Clear_Array(wNonce);
  N := Min(Length(wNonce), Length(Nonce)) - 1;

  for ndx := 0 to N do
    wNonce[ndx] := Nonce[ndx];

  if (UMAC_OutputLen = 4) then
    LOW_BIT_MASK := 3
  else
  if (UMAC_OutputLen = 8) then
    LOW_BIT_MASK := 1
  else
  if (UMAC_OutputLen > 8) then
    LOW_BIT_MASK := 0
  else
    LOW_BIT_MASK := 0;

  if  LOW_BIT_MASK <> 0 then
    ndx := wNonce[7] and LOW_BIT_MASK
  else
    ndx := 0;

  Save_UINT32(tmp_nonce_lo, 0, Get_UINT32(wNonce, 1));
  tmp_nonce_lo[3] := tmp_nonce_lo[3] and not LOW_BIT_MASK; // zero last bit

  if  (Get_UINT32(tmp_nonce_lo, 0) <> Get_UINT32(Ctx.Nonce, 1))
    or (Get_UINT32(wNonce, 0) <> Get_UINT32(Ctx.Nonce, 0)) then
  begin
    Save_UINT32(Ctx.Nonce, 0, Get_UINT32(wNonce, 0));
    Save_UINT32(Ctx.Nonce, 1, Get_UINT32(tmp_nonce_lo, 0));
    Encrypt128(Ctx.Nonce, Ctx.PRF_Key, Ctx.Cache);
  end;

  if (UMAC_OutputLen = 4) then
    Save_UINT32(Buf, 0, Get_UINT32(Buf, 0) xor Get_UINT32(Ctx.Cache, ndx))
  else
  if (UMAC_OutputLen = 8) then
    Save_UINT64(Buf, 0, Get_UINT64(Buf, 0) xor Get_UINT64(Ctx.Cache, ndx))
  else
  if (UMAC_OutputLen = 12)  then
  begin
    Save_UINT64(Buf, 0, Get_UINT64(Buf, 0) xor Get_UINT64(Ctx.Cache, 0));
    Save_UINT32(Buf, 2, Get_UINT32(Buf, 2) xor Get_UINT32(Ctx.Cache, 2));
  end
  else
  if  (UMAC_OutputLen = 16) then
  begin
    Save_UINT64(Buf, 0, Get_UINT64(Buf, 0) xor Get_UINT64(Ctx.Cache, 0));
    Save_UINT64(Buf, 1, Get_UINT64(Buf, 1) xor Get_UINT64(Ctx.Cache, 1));
  end;

end;

//  Reset nh_ctx to ready for hashing of new data
procedure NH_Reset(var Ctx: TNHContext);
var
  i: integer;
begin
  Ctx.Bytes_Hashed := 0;
  Ctx.Next_Data_Empty := 0;

  for i := Low(Ctx.Data) to High(Ctx.Data) do
    Ctx.Data[i] := 0;

  for i := Low(Ctx.State) to High(Ctx.State) do
    Ctx.State[i] := 0;
end;

procedure  Endian_Convert_if_LE_4(var Buf: ByteArray; Idx: integer;
  Num_Items: integer); 
var
  i: integer;
begin
  for i := 0 to Num_Items - 1 do
    Save_UINT32(Buf, Idx + i, SwapUInt32(Get_UINT32(Buf, Idx + i)));
end;

function SwapUInt64(V: UInt64): UInt64;
begin
  Result := UInt64(SwapUInt32(V shr 32)) or (UInt64(SwapUInt32(V and $FFFFFFFF)) shl 32);
end;

procedure  Endian_Convert_if_LE_8(var Buf: UINT64Array; Idx: integer;
    Num_Items: integer);
var
  i: integer;
begin
  for i := 0 to Num_Items - 1 do
    Buf[Idx + i] := SwapUInt64(Buf[Idx + i]);
end;

//  Generate nh_key, endian convert and reset to be ready for hashing
procedure NH_Init(var Ctx: TNHContext; PRF_Key: TAESExpandedKey128);
begin
  KDF(Ctx.NH_Key, PRF_Key, 1, Length(Ctx.NH_Key));
  Endian_Convert_if_LE_4(Ctx.NH_Key, 0, Length(Ctx.NH_Key) shr 2);
  NH_Reset(Ctx);
end;

procedure NH_Aux4(const NH_Key: ByteArray; Key_Offset: UINT32;
    const Buf: ByteArray; BufOffset: UINT32; var State: UINT64Array; nBytes: UINT32);
var
  H: UINT64;
  C: integer;
  K, D: cardinal;
  Kx, Dx: cardinal;
  D0, D1, D2, D3, D4, D5, D6, D7: UINT32;
  K0, K1, K2, K3, K4, K5, K6, K7: UINT32;

  function  Get_Buf(Idx: cardinal): UINT32;
  begin
    Result := Get_UINT32(Buf, Dx, D + Idx);
  end;

  function  Get_Key(Idx: cardinal): UINT32;
  begin
    Result := Get_UINT32(NH_Key, Kx, K + Idx);
  end;

begin
  C := nBytes div 32;
  Kx := Key_Offset;
  Dx := BufOffset;
  K := 0;
  D := 0;
  H := State[0];

  while (C > 0) do
  begin
    D0 := Get_Buf(0);   D1 := Get_Buf(1);
    D2 := Get_Buf(2);   D3 := Get_Buf(3);
    D4 := Get_Buf(4);   D5 := Get_Buf(5);
    D6 := Get_Buf(6);   D7 := Get_Buf(7);
    K0 := Get_Key(0);   K1 := Get_Key(1);
    K2 := Get_Key(2);   K3 := Get_Key(3);
    K4 := Get_Key(4);   K5 := Get_Key(5);
    K6 := Get_Key(6);   K7 := Get_Key(7);

    inc(H, Mult64((K0 + D0), (K4 + D4)));
    inc(H, Mult64((K1 + D1), (K5 + D5)));
    inc(H, Mult64((K2 + D2), (K6 + D6)));
    inc(H, Mult64((K3 + D3), (K7 + D7)));

    inc(D, 8);    inc(K, 8);
    dec(C);
  end;

  State[0] := H;
end;

procedure NH_Aux8(const NH_Key: ByteArray; Key_Offset: UINT32;
    const Buf: ByteArray; BufOffset: UINT32; var State: UINT64Array; nBytes: UINT32);
var
  H1, H2: UINT64;
  C: integer;
  K, D: cardinal;
  Kx, Dx: cardinal;
  D0, D1, D2, D3, D4, D5, D6, D7: UINT32;
  K0, K1, K2, K3, K4, K5, K6, K7: UINT32;
  K8, K9, K10,K11: UINT32;

  function  Get_Buf(Idx: cardinal): UINT32;
  begin
    Result := Get_UINT32(Buf, Dx, D + Idx);
  end;

  function  Get_Key(Idx: cardinal): UINT32;
  begin
    Result := Get_UINT32(NH_Key, Kx, K + Idx);
  end;

begin
  C := nBytes div 32;
  Kx := Key_Offset;
  Dx := BufOffset;
  K := 0;
  D := 0;
  H1 := State[0];
  H2 := State[1];
  K0 := Get_Key(0);     K1 := Get_Key(1);
  K2 := Get_Key(2);     K3 := Get_Key(3);

  while (C > 0) do
  begin
    D0 := Get_Buf(0);   D1 := Get_Buf(1);
    D2 := Get_Buf(2);   D3 := Get_Buf(3);
    D4 := Get_Buf(4);   D5 := Get_Buf(5);
    D6 := Get_Buf(6);   D7 := Get_Buf(7);
    K4 := Get_Key(4);   K5 := Get_Key(5);
    K6 := Get_Key(6);   K7 := Get_Key(7);
    K8 := Get_Key(8);   K9 := Get_Key(9);
    K10:= Get_Key(10);  K11:= Get_Key(11);

    inc(H1, Mult64((K0 + D0), (K4 + D4)));
    inc(H2, Mult64((K4 + D0), (K8 + D4)));

    inc(H1, Mult64((K1 + D1), (K5 + D5)));
    inc(H2, Mult64((K5 + D1), (K9 + D5)));

    inc(H1, Mult64((K2 + D2), (K6 + D6)));
    inc(H2, Mult64((K6 + D2), (K10+ D6)));

    inc(H1, Mult64((K3 + D3), (K7 + D7)));
    inc(H2, Mult64((K7 + D3), (K11+ D7)));

    K0 := K8;     K1 := K9;
    K2 := K10;    K3 := K11;

    inc(D, 8);    inc(K, 8);
    dec(C);
  end;

  State[0] := H1;
  State[1] := H2;
end;

procedure NH_Aux12(const NH_Key: ByteArray; Key_Offset: UINT32;
    const Buf: ByteArray; BufOffset: UINT32; var State: UINT64Array; nBytes: UINT32);
var
  H1, H2, H3: UINT64;
  C: integer;
  K, D: cardinal;
  Kx, Dx: cardinal;
  D0, D1, D2, D3, D4, D5, D6, D7: UINT32;
  K0, K1, K2, K3, K4, K5, K6, K7: UINT32;
  K8, K9, K10,K11,K12,K13,K14,K15: UINT32;

  function  Get_Buf(Idx: cardinal): UINT32;
  begin
    Result := Get_UINT32(Buf, Dx, D + Idx);
  end;

  function  Get_Key(Idx: cardinal): UINT32;
  begin
    Result := Get_UINT32(NH_Key, Kx, K + Idx);
  end;

begin
  C := nBytes div 32;
  Kx := Key_Offset;
  Dx := BufOffset;
  K := 0;
  D := 0;
  H1 := State[0];
  H2 := State[1];
  H3 := State[2];
  K0 := Get_Key(0);     K1 := Get_Key(1);
  K2 := Get_Key(2);     K3 := Get_Key(3);
  K4 := Get_Key(4);     K5 := Get_Key(5);
  K6 := Get_Key(6);     K7 := Get_Key(7);

  while (C > 0) do
  begin
    D0 := Get_Buf(0);   D1 := Get_Buf(1);
    D2 := Get_Buf(2);   D3 := Get_Buf(3);
    D4 := Get_Buf(4);   D5 := Get_Buf(5);
    D6 := Get_Buf(6);   D7 := Get_Buf(7);
    K8 := Get_Key(8);   K9 := Get_Key(9);
    K10:= Get_Key(10);  K11:= Get_Key(11);
    K12:= Get_Key(12);  K13:= Get_Key(13);
    K14:= Get_Key(14);  K15:= Get_Key(15);

    inc(H1, Mult64((K0 + D0), (K4 + D4)));
    inc(H2, Mult64((K4 + D0), (K8 + D4)));
    inc(H3, Mult64((K8 + D0), (K12+ D4)));

    inc(H1, Mult64((K1 + D1), (K5 + D5)));
    inc(H2, Mult64((K5 + D1), (K9 + D5)));
    inc(H3, Mult64((K9 + D1), (K13+ D5)));

    inc(H1, Mult64((K2 + D2), (K6 + D6)));
    inc(H2, Mult64((K6 + D2), (K10+ D6)));
    inc(H3, Mult64((K10+ D2), (K14+ D6)));

    inc(H1, Mult64((K3 + D3), (K7 + D7)));
    inc(H2, Mult64((K7 + D3), (K11+ D7)));
    inc(H3, Mult64((K11+ D3), (K15+ D7)));

    K0 := K8;     K1 := K9;
    K2 := K10;    K3 := K11;
    K4 := K12;    K5 := K13;
    K6 := K14;    K7 := K15;

    inc(D, 8);    inc(K, 8);
    dec(C);
  end;

  State[0] := H1;
  State[1] := H2;
  State[2] := H3;
end;

procedure NH_Aux16(const NH_Key: ByteArray; Key_Offset: UINT32;
    const Buf: ByteArray; BufOffset: UINT32; var State: UINT64Array; nBytes: UINT32);
var
  H1, H2, H3, H4: UINT64;
  C: integer;
  K, D: cardinal;
  Kx, Dx: cardinal;
  D0, D1, D2, D3, D4, D5, D6, D7: UINT32;
  K0, K1, K2, K3, K4, K5, K6, K7: UINT32;
  K8, K9, K10,K11,K12,K13,K14,K15: UINT32;
  K16,K17,K18,K19: UINT32;

  function  Get_Buf(Idx: cardinal): UINT32;
  begin
    Result := Get_UINT32(Buf, Dx, D + Idx);
  end;

  function  Get_Key(Idx: cardinal): UINT32;
  begin
    Result := Get_UINT32(NH_Key, Kx, K + Idx);
  end;

begin
  C := nBytes div 32;
  Kx := Key_Offset;
  Dx := BufOffset;
  K := 0;
  D := 0;
  H1 := State[0];
  H2 := State[1];
  H3 := State[2];
  H4 := State[3];
  K0 := Get_Key(0);     K1 := Get_Key(1);
  K2 := Get_Key(2);     K3 := Get_Key(3);
  K4 := Get_Key(4);     K5 := Get_Key(5);
  K6 := Get_Key(6);     K7 := Get_Key(7);
  K8 := Get_Key(8);     K9 := Get_Key(9);
  K10:= Get_Key(10);    K11:= Get_Key(11);

  while (C > 0) do
  begin
    D0 := Get_Buf(0);   D1 := Get_Buf(1);
    D2 := Get_Buf(2);   D3 := Get_Buf(3);
    D4 := Get_Buf(4);   D5 := Get_Buf(5);
    D6 := Get_Buf(6);   D7 := Get_Buf(7);
    K12:= Get_Key(12);  K13:= Get_Key(13);
    K14:= Get_Key(14);  K15:= Get_Key(15);
    K16:= Get_Key(16);  K17:= Get_Key(17);
    K18:= Get_Key(18);  K19:= Get_Key(19);

    inc(H1, Mult64((K0 + D0), (K4 + D4)));
    inc(H2, Mult64((K4 + D0), (K8 + D4)));
    inc(H3, Mult64((K8 + D0), (K12+ D4)));
    inc(H4, Mult64((K12+ D0), (K16+ D4)));

    inc(H1, Mult64((K1 + D1), (K5 + D5)));
    inc(H2, Mult64((K5 + D1), (K9 + D5)));
    inc(H3, Mult64((K9 + D1), (K13+ D5)));
    inc(H4, Mult64((K13+ D1), (K17+ D5)));

    inc(H1, Mult64((K2 + D2), (K6 + D6)));
    inc(H2, Mult64((K6 + D2), (K10+ D6)));
    inc(H3, Mult64((K10+ D2), (K14+ D6)));
    inc(H4, Mult64((K14+ D2), (K18+ D6)));

    inc(H1, Mult64((K3 + D3), (K7 + D7)));
    inc(H2, Mult64((K7 + D3), (K11+ D7)));
    inc(H3, Mult64((K11+ D3), (K15+ D7)));
    inc(H4, Mult64((K15+ D3), (K19+ D7)));

    K0 := K8;     K1 := K9;
    K2 := K10;    K3 := K11;
    K4 := K12;    K5 := K13;
    K6 := K14;    K7 := K15;
    K8 := K16;    K9 := K17;
    K10:= K18;    K11:= K19;

    inc(D, 8);    inc(K, 8);
    dec(C);
  end;

  State[0] := H1;
  State[1] := H2;
  State[2] := H3;
  State[3] := H4;
end;

procedure NH_Aux(const NH_Key: ByteArray; Key_Offset: UINT32;
    const Buf: ByteArray; BufOffset: UINT32; var State: UINT64Array; nBytes: UINT32;
    UMAC_OutputLen: integer);
begin
  if  UMAC_OutputLen = 4 then
    NH_Aux4(NH_Key, Key_Offset, Buf, BufOffset, State, nBytes)
  else
  if  UMAC_OutputLen = 8 then
    NH_Aux8(NH_Key, Key_Offset, Buf, BufOffset, State, nBytes)
  else
  if  UMAC_OutputLen = 12 then
    NH_Aux12(NH_Key, Key_Offset, Buf, BufOffset, State, nBytes)
  else
  if  UMAC_OutputLen = 16 then
    NH_Aux16(NH_Key, Key_Offset, Buf, BufOffset, State, nBytes);
end;

procedure NH_Transform(var HC: TNHContext; const Buf: ByteArray;
        BufOffset: cardinal;
        nBytes: cardinal; UMAC_OutputLen: cardinal);
begin
  NH_Aux(HC.NH_Key, HC.Bytes_Hashed, Buf, BufOffset, HC.State, nBytes, UMAC_OutputLen);
end;

procedure NH_Update(var HC: TNHContext; const Buf: ByteArray; StartIndex: cardinal;
    nBytes: cardinal; UMAC_OutputLen: cardinal);
var
  i, j, ii: UINT32;
begin
  ii := 0;
  j := HC.Next_Data_Empty;

  if ((j + nBytes) >= HASH_BUF_BYTES) then
  begin
    if  j > 0 then
    begin
      i := HASH_BUF_BYTES - j;
      Copy_Array(HC.Data, j, Buf, StartIndex, i);
      NH_Transform(HC, HC.Data, 0, HASH_BUF_BYTES, UMAC_OutputLen);
      dec(nBytes, i);
      inc(HC.Bytes_Hashed, HASH_BUF_BYTES);
      inc(ii, i);
    end;

    if (nBytes >= HASH_BUF_BYTES) then
    begin
      i := nBytes AND not(HASH_BUF_BYTES - 1);
      NH_Transform(HC, Buf, StartIndex + ii, i, UMAC_OutputLen);
      dec(nBytes, i);
      inc(HC.Bytes_Hashed, i);
      inc(ii, i);
    end;

    j := 0;
  end;

  Copy_Array(HC.Data, j, Buf, StartIndex + ii, nBytes);
  HC.Next_Data_Empty := j + nBytes;
end;

procedure NH_Final(var HC: TNHContext; var Res: ByteArray; UMAC_OutputLen: integer);
var
  NH_Len, nBits, i: integer;
begin
  if (HC.Next_Data_Empty <> 0)  then
  begin
    NH_Len := ((HC.Next_Data_Empty + (L1_PAD_BOUNDARY - 1))
        and not (L1_PAD_BOUNDARY - 1));
    Clear_Array(HC.Data, HC.Next_Data_Empty, NH_Len - HC.Next_Data_Empty);
    NH_Transform(HC, HC.Data, 0, NH_Len, UMAC_OutputLen);
    inc(HC.Bytes_Hashed, HC.Next_Data_Empty);
  end
  else
  if (HC.Bytes_Hashed = 0)  then
  begin
    NH_Len := L1_PAD_BOUNDARY;
    Clear_Array(HC.Data, 0, L1_PAD_BOUNDARY);
    NH_Transform(HC, HC.Data, 0, NH_Len, UMAC_OutputLen);
  end;

  nBits := (HC.Bytes_Hashed shl 3);

  for i := Low(HC.State) to High(HC.State) do
    Save_UINT64(Res, i, HC.State[i] + nBits);

  NH_Reset(HC);
end;

procedure NH(var Ctx: TNHContext; const Buf: ByteArray; BufOffset: UINT32;
             Padded_Len: UINT32;
             Unpadded_Len: UINT32; var Res: ByteArray; UMAC_OutputLen: integer);
var
  nBits: UINT32;
  aRes: UINT64Array;
  i: integer;
begin
  // Initialize the hash state
  SetLength(aRes, UMAC_OutputLen shr 2);
  nBits := (unpadded_len shl 3);

  for i := Low(aRes) to High(aRes) do
    aRes[i] := nBits;

  NH_Aux(Ctx.NH_Key, 0, Buf, BufOffset, aRes, Padded_Len, UMAC_OutputLen);

  for i := Low(aRes) to High(aRes) do
    Save_UINT64(Res, i, aRes[i]);

end;

function  Poly64(Cur: UINT64; Key: UINT64; Data: UINT64): UINT64;
var
  key_hi, key_lo: UINT32;
  cur_hi, cur_lo: UINT32;
  x_lo, x_hi: UINT32;
  X, T, Res: UINT64;
begin
  key_hi := UINT32(key shr 32);
  key_lo := UINT32(key);
  cur_hi := UINT32(cur shr 32);
  cur_lo := UINT32(cur);

  X :=  Mult64(key_hi, cur_lo) + Mult64(cur_hi, key_lo);
  x_lo := UINT32(X);
  x_hi := UINT32(X shr 32);

  Res := (Mult64(key_hi, cur_hi) + x_hi) * 59 + Mult64(key_lo, cur_lo);

  T := UINT64(x_lo) shl 32;
  inc(Res, T);

  if Cmp64(Res, T) < 0  then
    inc(Res, 59);

  inc(Res, Data);

  if Cmp64(Res, Data) < 0 then
    inc(Res, 59);

  Result := Res;
end;

procedure Poly_Hash(var Ctx: TUHASHContext; var Data_In: ByteArray; Streams: integer);
var
  i: integer;
begin
  for i := 0 to Streams - 1 do
  begin
    if  (Get_UINT64(Data_In, i) shr 32) = UINT64($FFFFFFFF)  then
    begin
      Ctx.Poly_Accum[i] := Poly64(Ctx.Poly_Accum[i], Ctx.Poly_Key_8[i], p64 - 1);
      Ctx.Poly_Accum[i] := Poly64(Ctx.Poly_Accum[i], Ctx.Poly_Key_8[i],
          (Get_UINT64(Data_In, i) - 59));
    end
    else
    begin
      Ctx.Poly_Accum[i] := Poly64(Ctx.Poly_Accum[i], Ctx.Poly_Key_8[i], Get_UINT64(Data_In, i));
    end;
  end;
end;

function  IP_Aux(t: UINT64; const ipkp: UINT64Array;
            StartIndex: integer; data: UINT64): UINT64;
begin
  t := t + ipkp[StartIndex + 0] * UINT16(data shr 48);
  t := t + ipkp[StartIndex + 1] * UINT16(data shr 32);
  t := t + ipkp[StartIndex + 2] * UINT16(data shr 16);
  t := t + ipkp[StartIndex + 3] * UINT16(data);

  Result := t;
end;

function  IP_Reduce_P36(t: UINT64): UINT32;
var
  Ret: UINT64;
begin
//  Divisionless modular reduction */
  Ret := (t and m36) + 5 * (t shr 36);

  if (Ret >= p36) then
    Ret := Ret - p36;

  //  return least significant 32 bits
  Result := UINT32(Ret);
end;

procedure  IP_Short(var Ctx: TUHASHContext; const NH_Res: ByteArray;
      var Res: ByteArray; UMAC_OutputLen: integer);
var
  t: UINT64;
  i, N: cardinal;
begin
  N := UMAC_OutputLen shr 2 - 1;

  for i := 0 to N do
  begin
    t  := IP_Aux(0, Ctx.IP_Keys, i * 4, Get_UINT64(NH_Res, i));
    STORE_UINT32_REVERSED(Res, i * 4, IP_Reduce_P36(t) xor Get_UINT32(Ctx.IP_Trans, i));
  end;
end;

procedure IP_Long(var Ctx: TUHASHContext; var Res: ByteArray;
      Streams: integer);
var
  i: integer;
  t: UINT64;
begin
  for i := 0 to Streams - 1 do
  begin
    // fix polyhash output not in Z_p64
    if Cmp64(Ctx.Poly_Accum[i], p64) >= 0 then
      Ctx.Poly_Accum[i] := Ctx.Poly_Accum[i] - p64;
    t := IP_Aux(0, Ctx.ip_keys, (i * 4), Ctx.Poly_Accum[i]);
    STORE_UINT32_REVERSED(Res, i * 4, IP_Reduce_P36(t) xor Get_UINT32(Ctx.IP_Trans, i));
  end;
end;


 destructor  TElUMAC.Destroy;
begin
  inherited;
end;

constructor TElUMAC.Create();
begin
  inherited Create();
end;

constructor TElUMAC.Create(const Key: string; TagLen: integer);
var
  aKey: ByteArray;
  i, N: integer;
begin
  inherited Create;
  N := Length(Key);

  if  N > UMAC_KEY_LEN  then
    N := UMAC_KEY_LEN;

  SetLength(aKey, N);
  Clear_Array(aKey);
  for i := StringStartOffset to N - StringStartInvOffset do
    aKey[i   - 1  ] := ord(Key[i]);

  Initialize_UMAC(aKey, TagLen);

end;

constructor TElUMAC.Create(const Key: ByteArray; TagLen: integer);
begin
  inherited Create;
  Initialize_UMAC(Key, TagLen);
end;

procedure TElUMAC.Init_Members;
begin
  SetLength(fHash.Poly_Key_8, fStreams);
  SetLength(fHash.Poly_Accum, fStreams);
  SetLength(fHash.IP_Keys, fStreams * 4);
  SetLength(fHash.IP_Trans, fStreams * sizeof_UINT32);
  SetLength(fHash.Hash.NH_Key, L1_KEY_LEN + L1_KEY_SHIFT * (fStreams - 1));
  SetLength(fHash.Hash.Data, HASH_BUF_BYTES);
  SetLength(fHash.Hash.State, fStreams);
  fHash.Msg_Len := 0;
  fHash.Hash.Next_Data_Empty := 0;
  fHash.Hash.Bytes_Hashed := 0;
end;

procedure TElUMAC.Initialize_UMAC(const Key: ByteArray; TagLen: integer);
var
  aKey: TAESKey128;
  PRF_Key: TAESExpandedKey128;
  i, N: integer;
begin
  if  not (TagLen in [4, 8, 12, 16]) then
  begin
    raise ESecureBlackboxError.Create('Invalid UMAC tag size');      
  end;

  fOutputLen := TagLen;
  fStreams := fOutputLen shr 2;

  Init_Members();

  for i := Low(aKey) to High(aKey) do
    aKey[i] := 0;

  N := Length(Key);

  if  N > 16  then
    N := 16;

  for i := 0 to N - 1 do
    aKey[i] := Key[i];

  ExpandKeyForEncryption128(aKey, PRF_Key);
  PDF_Init(fPDF, PRF_Key);
  UHASH_Init(PRF_Key);
end;

procedure TElUMAC.UHASH_Init(const PRF_Key: TAESExpandedKey128);
var
  Buf: ByteArray;
  i, j, i4, i8: integer;
begin
  SetLength(Buf, (fStreams shl 3 + 4) * sizeof_UINT64);
  NH_Init(fHash.Hash, PRF_Key);
  KDF(Buf, PRF_Key, 2, Length(Buf));    // Fill buffer with index 1 key

  for i := 0 to fStreams - 1 do
  begin
    (* Fill keys from the buffer, skipping bytes in the buffer not
     * used by this implementation. Endian reverse the keys if on a
     * little-endian computer.
     *)
    fHash.Poly_Key_8[i] := Get_UINT64(Buf, i * 3);
    Endian_Convert_if_LE_8(fHash.Poly_Key_8, i, 1);
    // Mask the 64-bit keys to their special domain
    fHash.Poly_Key_8[i] := fHash.Poly_Key_8[i] and ((UINT64($01ffffff) shl 32) + $01ffffff);
    fHash.Poly_Accum[i] := 1;  // Our polyhash prepends a non-zero word
  end;

  // Setup L3-1 hash variables
  KDF(Buf, PRF_Key, 3, Length(Buf)); // Fill buffer with index 2 key

  for i := 0 to fStreams - 1 do
  begin
    i4 := i shl 2;
    i8 := i shl 3 + 4;

    for j := 0 to 3 do
      fHash.IP_Keys[i4 + j] := Get_UINT64(Buf, i8 + j);
  end;

  Endian_Convert_if_LE_8(fHash.IP_Keys, 0, Length(fHash.IP_Keys));

  for i := 0 to (fStreams * 4 - 1) do
    fHash.IP_Keys[i] := Calc_MOD(fHash.IP_Keys[i], p36);  // Bring into Z_p36

  // Setup L3-2 hash variables
  // Fill buffer with index 4 key
  KDF(fHash.IP_Trans, PRF_Key, 4, fStreams * sizeof_UINT32);
  Endian_Convert_if_LE_4(fHash.IP_Trans, 0, fStreams);

end;

procedure TElUMAC.Reset;
var
  i: integer;
begin
  NH_Reset(fHash.Hash);
  fHash.Msg_Len := 0;

  for i := Low(fHash.Poly_Accum) to High(fHash.Poly_Accum) do
    fHash.Poly_Accum[i] := 1;
end;

procedure TElUMAC.Update(const In_Buf: ByteArray; StartIndex, Len: cardinal);
var
  Bytes_Hashed, Bytes_Remaining: cardinal;
  NH_Result: ByteArray;
  ii: cardinal;

  procedure NHU(Offset, Len: cardinal);
  begin
    NH_Update(fHash.Hash, In_Buf, StartIndex + Offset, Len, fOutputLen);
    inc(fHash.Msg_Len, Len);
  end;

begin
  SetLength(NH_Result, fStreams * sizeof_UINT64);

  if ((fHash.Msg_Len + Len) <= L1_KEY_LEN)  then
  begin
    NHU(0, Len);
  end
  else
  begin
    ii := 0;
    Bytes_Hashed := fHash.Msg_Len mod L1_KEY_LEN;

    if  fHash.Msg_Len = L1_KEY_LEN then
      Bytes_Hashed := L1_KEY_LEN;

    if  (Bytes_Hashed + Len) >= L1_KEY_LEN  then
    begin
      // If some bytes have been passed to the hash function
      // then we want to pass at most (L1_KEY_LEN - bytes_hashed)
      // bytes to complete the current nh_block.

      if  Bytes_Hashed > 0  then
      begin
        Bytes_Remaining := (L1_KEY_LEN - Bytes_Hashed);
        NHU(0, Bytes_Remaining);
        NH_Final(fHash.Hash, NH_Result, fOutputLen);
        Poly_Hash(fHash, NH_Result, fStreams);
        dec(Len, Bytes_Remaining);
        inc(ii, Bytes_Remaining);
      end;

      //  Hash directly from input stream if enough bytes

      while (Len >= L1_KEY_LEN) do
      begin
        NH(fHash.Hash, In_Buf, StartIndex + ii, L1_KEY_LEN, L1_KEY_LEN, NH_Result, fOutputLen);
        Poly_Hash(fHash, NH_Result, fStreams);
        dec(Len, L1_KEY_LEN);
        inc(ii, L1_KEY_LEN);
        inc(fHash.Msg_Len, L1_KEY_LEN);
      end;
    end;

    // pass remaining < L1_KEY_LEN bytes of input data to NH
    if (Len > 0) then
      NHU(ii, Len);
  end;

end;

procedure TElUMAC.Update(In_Buf: Pointer; Size: integer);
begin
  Update(BufToByteArray(In_Buf, Size), 0, Size);
end;

procedure TElUMAC.Final(const Nonce: ByteArray; out Tag: ByteArray);
var
  NH_Result: ByteArray;
begin
  SetLength(Tag, fOutputLen);
  SetLength(NH_Result, fStreams * sizeof_UINT64);

  if  fHash.Msg_Len > L1_KEY_LEN  then
  begin
    if  (fHash.Msg_Len mod L1_KEY_LEN) <> 0 then
    begin
      NH_Final(fHash.Hash, NH_Result, fOutputLen);
      Poly_Hash(fHash, NH_Result, fStreams);
    end;

    IP_Long(fHash, Tag, fStreams);
  end
  else
  begin
    NH_Final(fHash.Hash, NH_Result, fOutputLen);
    IP_Short(fHash, NH_Result, Tag, fOutputLen);
  end;

  PDF_gen_XOR(fPDF, Nonce, Tag, fOutputLen);
  Reset();

end;

procedure TElUMAC.Calculate(const In_Buf: ByteArray; StartIndex, Len: cardinal;
                        const Nonce: ByteArray; out Tag: ByteArray);
var
  wBuf: ByteArray;
  NH_Result: ByteArray;
  NH_Len: UINT32;
  extra_zeroes_needed: integer;
  ii: UINT32;
begin
  Reset();
  SetLength(Tag, fOutputLen);

  SetLength(wBuf, L1_KEY_LEN);
  SetLength(NH_Result, fStreams * sizeof_UINT64);

  if  Len <= L1_KEY_LEN then
  begin
    //  If the message to be hashed is no longer than L1_HASH_LEN,
    //  we skip the polyhash.
    if  Len = 0 then
      NH_Len := L1_PAD_BOUNDARY
    else
      NH_Len := ((Len + (L1_PAD_BOUNDARY - 1)) and not(L1_PAD_BOUNDARY - 1));

    extra_zeroes_needed := NH_Len - Len;
    Copy_Array(wBuf, 0, In_Buf, StartIndex, Len);
    Clear_Array(wBuf, Len, extra_zeroes_needed);
    NH(fHash.Hash, wBuf, 0, NH_Len, Len, NH_Result, fOutputLen);
    IP_Short(fHash, NH_Result, Tag, fOutputLen);
  end
  else
  begin
    ii := 0;

    while  Len >= L1_KEY_LEN do
    begin
      NH(fHash.Hash, In_Buf, StartIndex + ii, L1_KEY_LEN, L1_KEY_LEN, NH_Result, fOutputLen);
      Poly_Hash(fHash, NH_Result, fStreams);
      dec(Len, L1_KEY_LEN);
      inc(ii, L1_KEY_LEN);
    end;

    if  Len > 0 then
    begin
      NH_Len := ((Len + (L1_PAD_BOUNDARY - 1)) and not (L1_PAD_BOUNDARY - 1));
      extra_zeroes_needed := NH_Len - Len;
      Copy_Array(wBuf, 0, In_Buf, StartIndex + ii, Len);
      Clear_Array(wBuf, Len, extra_zeroes_needed);
      NH(fHash.Hash, wBuf, 0, NH_Len, Len, NH_Result, fOutputLen);
      Poly_Hash(fHash, NH_Result, fStreams);
    end;

    IP_Long(fHash, Tag, fStreams);
  end;

  PDF_gen_XOR(fPDF, Nonce, Tag, fOutputLen);

end;

procedure TElUMAC.Calculate(In_Buf: Pointer; Len: cardinal;
               const Nonce: ByteArray; out Tag: ByteArray);
begin
  Calculate(BufToByteArray(In_Buf, Len), 0, Len, Nonce, Tag);
end;

function  TElUMAC.Clone:  TElUMAC ;
var
  Res : TElUMAC;
  i: integer;
begin
  Res := TElUMAC.Create();
  Res.Init_Members();
  Res.fOutputLen := self.fOutputLen;
  Res.fStreams := self.fStreams;

  for i := Low(fPDF.Cache) to High(fPDF.Cache) do
    Res.fPDF.Cache[i] := fPDF.Cache[i];

  for i := Low(fPDF.Nonce) to High(fPDF.Nonce) do
    Res.fPDF.Nonce[i] := fPDF.Nonce[i];


  for i := Low(fPDF.PRF_Key) to High(fPDF.PRF_Key) do
    Res.fPDF.PRF_Key[i] := fPDF.PRF_Key[i];

  Res.fHash.Msg_Len := self.fHash.Msg_Len;
  Res.fHash.Hash.Next_Data_Empty := self.fHash.Hash.Next_Data_Empty;
  Res.fHash.Hash.Bytes_Hashed := self.fHash.Hash.Bytes_Hashed;
  Copy_Array(Res.fHash.Hash.NH_Key, fHash.Hash.NH_Key);
  Copy_Array(Res.fHash.Hash.Data, fHash.Hash.Data);
  Copy_Array(Res.fHash.Hash.State, fHash.Hash.State);
  Copy_Array(Res.fHash.Poly_Key_8, fHash.Poly_Key_8);
  Copy_Array(Res.fHash.Poly_Accum, fHash.Poly_Accum);
  Copy_Array(Res.fHash.IP_Keys, fHash.IP_Keys);
  Copy_Array(Res.fHash.IP_Trans, fHash.IP_Trans);
  
  Result := Res;
end;

{$ifndef D_7_UP}
initialization
  //p64 := StrToInt64('$FFFFFFFFFFFFFFC5');              // 2^64 - 59
  try
    p64 := StrToInt64Def('$FFFFFFFFFFFFFFC5', $FFFFFFFFFFFFFFC5);              // 2^64 - 59
  except
    ;
  end;
 {$endif}

end.
