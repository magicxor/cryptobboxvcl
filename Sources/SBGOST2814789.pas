(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit  SBGOST2814789;

interface

uses
  SBTypes,
  SBUtils,
  SBConstants,
  SBStreams,
  SBGOSTCommon
  ;


//type

//  TElGostSubstBlock = array[1..8, 0..15] of byte;

//  TElGOSTKey = array[0..7] of UINT32;

type
  TElGOSTMode = (GOSTMode_ECB, GOSTMode_OFB, GOSTMode_CFB, GOSTMode_CBC);

  TElGOST = class(TElGOSTBase)
  protected
    fMode: TElGOSTMode;
    fIV: ByteArray;
    fWork_IV: ByteArray;
    fGamma: ByteArray;
    fMAC: ByteArray;
    fN3: UInt32;
    fN4: UInt32;
    procedure SetIV(const V: ByteArray);
    function  GetIV: ByteArray;
    procedure ECB_Block(const InBuf: ByteArray; In_StartIdx: integer;
                          var OutBuf: ByteArray; Out_StartIdx: integer;
                          IsEncrypt: Boolean);
    procedure CFB_Block(const InBuf: ByteArray; In_StartIdx: integer;
                          var OutBuf: ByteArray; Out_StartIdx: integer;
                          IsEncrypt: Boolean);
    procedure OFB_Block(const InBuf: ByteArray; In_StartIdx: integer;
                          var OutBuf: ByteArray; Out_StartIdx: integer;
                          IsEncrypt: Boolean);
    procedure CBC_Block(const InBuf: ByteArray; In_StartIdx: integer;
                          var OutBuf: ByteArray; Out_StartIdx: integer;
                          IsEncrypt: Boolean);
    function  Get_Block_Convertor(Mode: TElGOSTMode): TElBlockConvert_proc;
    procedure MAC_Block_proc(const InBuf: ByteArray; In_StartIdx: integer);
    procedure ConvertStream(Source: TElStream; Count: cardinal; Dest: TElStream;
                            IsEncrypt: Boolean);
    class function  GetBlockSize(): cardinal; override; 
  public
    class function  BlockSize(): integer; 
    class function  KeySize(): integer; 
    constructor Create();  overload; 
    constructor Create(const SubstBlock: TElGostSubstBlock);  overload; 
     destructor  Destroy; override;
    procedure Reset; override;
    procedure Clone(Source: TElGOSTBase); override;
    procedure Encrypt_Block(const InBuf: ByteArray; In_StartIdx: integer;
                In_Len: integer; var OutBuf: ByteArray; out Out_Len: integer;
                Out_StartIdx: integer);
    procedure Decrypt_Block(const InBuf: ByteArray; In_StartIdx: integer;
                In_Len: integer; var OutBuf: ByteArray; out Out_Len: integer;
                Out_StartIdx: integer);
    procedure Encrypt_Finalize(var OutBuf: ByteArray; out Out_Len: integer;
                          Out_StartIdx: integer);
    procedure Decrypt_Finalize(var OutBuf: ByteArray; out Out_Len: integer;
                          Out_StartIdx: integer);
    procedure EncryptBuf(const InBuf: ByteArray; In_StartIdx: integer;
                          In_Len: integer; var OutBuf: ByteArray; out Out_Len: integer;
                          Out_StartIdx: integer);  overload; 
    procedure EncryptBuf(const InBuf: ByteArray; var OutBuf: ByteArray);  overload; 
    procedure DecryptBuf(const InBuf: ByteArray; In_StartIdx: integer;
                          In_Len: integer; var OutBuf: ByteArray; out Out_Len: integer;
                          Out_StartIdx: integer);  overload; 
    procedure DecryptBuf(const InBuf: ByteArray; var OutBuf: ByteArray);  overload; 
  
    procedure EncryptStream(Source: TElStream; Count: cardinal; Dest: TElStream);
    procedure DecryptStream(Source: TElStream; Count: cardinal; Dest: TElStream);
  
    procedure MAC_Block(InBuf: Pointer; In_Len: integer);  overload; 
    procedure MAC_Block(const InBuf: ByteArray; In_StartIdx: integer; In_Len: integer);  overload; 
    procedure MAC_Finalize(Qnt_Bits: integer; out MAC: ByteArray);
    procedure MAC_Stream(Source: TElStream; Count: cardinal; Qnt_Bits: integer; out MAC: ByteArray);
    property  Key: ByteArray read GetKey write SetKey;
    property  IV: ByteArray read GetIV write SetIV;
    property  Mode: TElGOSTMode read fMode write fMode;
  end;

  { RFC 4357 key wrapping/unwrapping routines }
  { CEK - Content encryption key, i.e. key being wrapped }
  { KEK - key encryption key. Should NOT be derived from GOST R 34.10-1994 }
  { UKM - random 8 octects, or octets used in VKO GOST R 34.10-2001 key derivation }
  { WCEK - wrapped content encryption key }
  { CEK_MAC - MAC (32-bit Gost imitovstavka) }

  function KeyWrap28147(const UKM, CEK, KEK : ByteArray; var WCEK : ByteArray;
    var WCEKSize : integer; var CEK_MAC : ByteArray; var CEKMACSize : integer) : boolean; 
  function KeyUnwrap28147(const UKM, WCEK, KEK, CEK_MAC : ByteArray;
    var CEK : ByteArray; var CEKSize : integer) : boolean;  
  function KeyWrapCryptoPro(const UKM, CEK, KEK : ByteArray; var WCEK : ByteArray;
    var WCEKSize : integer; var CEK_MAC : ByteArray; var CEKMACSize : integer) : boolean; 
  function KeyUnwrapCryptoPro(const UKM, WCEK, KEK, CEK_MAC : ByteArray;
    var CEK : ByteArray; var CEKSize : integer) : boolean; 
  function gost28147IMIT(const IV, K, D : ByteArray) : ByteArray;  
  function KeyDiversifyCryptoPro(const UKM, KEK : ByteArray; var DKEK : ByteArray;
    var DKEKSize : integer) : boolean; 
implementation

const
  c_GOST_BlockSize_1 = (c_GOST_BlockSize - 1);

class function  TElGOST.BlockSize(): integer;
begin
  Result := c_GOST_BlockSize;
end;

class function  TElGOST.GetBlockSize(): cardinal;
begin
  Result := c_GOST_BlockSize;
end;

class function  TElGOST.KeySize(): integer;
begin
  Result := c_GOST_KeySize;
end;

constructor TElGOST.Create();
begin
  inherited Create();
end;

constructor TElGOST.Create(const SubstBlock: TElGostSubstBlock);
begin
  inherited Create(SubstBlock);
  fMode := GOSTMode_ECB;
//  SetLength_BA(fTail, c_GOST_BlockSize);
  SetLength_BA(fMAC, c_GOST_BlockSize);
//  Init(SubstBlock);
end;
(*
procedure TElGOST.Init(const SubstBlock: TElGostSubstBlock);
var
  i: integer;
  X: UINT32;
  HB, LB: integer;

  function  CalcPair(B1, B2: byte; Shift: integer): UINT32;
  begin
    X := ((B1 shl 4) or B2) shl Shift;
    Result := (X shl 11) or (X shr 21);
  end;

begin
  for i := 0 to 255 do
  begin
    HB := i shr 4;
    LB := i and $0F;
    K87[i] := CalcPair(SubstBlock[8, HB], SubstBlock[7, LB], 24);
    K65[i] := CalcPair(SubstBlock[6, HB], SubstBlock[5, LB], 16);
    K43[i] := CalcPair(SubstBlock[4, HB], SubstBlock[3, LB], 8);
    K21[i] := CalcPair(SubstBlock[2, HB], SubstBlock[1, LB], 0);
  end;

  Reset();
end;
*)

 destructor  TElGOST.Destroy;
begin
  inherited;
end;

procedure TElGOST.Reset;
begin
  inherited Reset();

  SetLength_BA(fGamma, c_GOST_BlockSize);
  Copy_BA(IV, fWork_IV, c_GOST_BlockSize);

  case  Mode of
    GOSTMode_ECB:
      begin
      end;
    GOSTMode_OFB:
      begin
        int_Encrypt(fIV, 0, fWork_IV, 0);
        fN3 := Buf_to_UInt(fWork_IV, 0);
        fN4 := Buf_to_UInt(fWork_IV, 4);
      end;
    GOSTMode_CFB:
      begin
      end;
    GOSTMode_CBC:
      begin
      end;
  end;
end;

procedure TElGOST.Clone(Source: TElGOSTBase);
var
  Src: TElGOST;
begin
  inherited Clone(Source);

  if  not (Source is TElGOST) then
    exit;

  Src := TElGOST(Source);
  fMode := Src.fMode;
  fIV := CloneArray(Src.fIV);
  fWork_IV := CloneArray(Src.fWork_IV);
  fGamma := CloneArray(Src.fGamma);
  fMAC := CloneArray(Src.fMAC);
  fN3 := Src.fN3;
  fN4 := Src.fN4;
end;

procedure TElGOST.SetIV(const V: ByteArray);
begin
  Copy_BA(V, fIV, 8);
end;

function  TElGOST.GetIV: ByteArray;
begin
  Result := fIV;
end;

function  TElGOST.Get_Block_Convertor(Mode: TElGOSTMode): TElBlockConvert_proc;
begin
  Result := nil;

  case  Mode of
    GOSTMode_ECB: Result := ECB_Block;
    GOSTMode_OFB: Result := OFB_Block;
    GOSTMode_CFB: Result := CFB_Block;
    GOSTMode_CBC: Result := CBC_Block;
  end;
end;

procedure TElGOST.Encrypt_Finalize(var OutBuf: ByteArray; out Out_Len: integer;
                      Out_StartIdx: integer);
begin
  Out_Len := 0;
end;

procedure TElGOST.Decrypt_Finalize(var OutBuf: ByteArray; out Out_Len: integer;
                      Out_StartIdx: integer);
begin
  Out_Len := 0;
end;

procedure TElGOST.Encrypt_Block(const InBuf: ByteArray; In_StartIdx: integer;
            In_Len: integer; var OutBuf: ByteArray; out Out_Len: integer;
            Out_StartIdx: integer);
begin
  Convert_Data(InBuf, In_StartIdx, In_Len, OutBuf, Out_Len, Out_StartIdx, True,
               Get_Block_Convertor(Mode));
end;

procedure TElGOST.Decrypt_Block(const InBuf: ByteArray; In_StartIdx: integer;
            In_Len: integer; var OutBuf: ByteArray; out Out_Len: integer;
            Out_StartIdx: integer);
begin
  Convert_Data(InBuf, In_StartIdx, In_Len, OutBuf, Out_Len, Out_StartIdx, False,
               Get_Block_Convertor(Mode));
end;

procedure TElGOST.EncryptBuf(const InBuf: ByteArray; In_StartIdx: integer;
                      In_Len: integer; var OutBuf: ByteArray; out Out_Len: integer;
                      Out_StartIdx: integer);
begin
  Reset();
  Encrypt_Block(InBuf, In_StartIdx, In_Len, OutBuf, Out_Len, Out_StartIdx);
  Encrypt_Finalize(OutBuf, Out_Len, Out_StartIdx);
end;

procedure TElGOST.EncryptBuf(const InBuf: ByteArray; var OutBuf: ByteArray);
var
  Out_Len: integer;
begin
  EncryptBuf(InBuf, 0, Length(InBuf), OutBuf, Out_Len, 0);
end;

procedure TElGOST.DecryptBuf(const InBuf: ByteArray; In_StartIdx: integer;
                      In_Len: integer; var OutBuf: ByteArray; out Out_Len: integer;
                      Out_StartIdx: integer);
begin
  Reset();
  Decrypt_Block(InBuf, In_StartIdx, In_Len, OutBuf, Out_Len, Out_StartIdx);
  Decrypt_Finalize(OutBuf, Out_Len, Out_StartIdx);
end;

procedure TElGOST.DecryptBuf(const InBuf: ByteArray; var OutBuf: ByteArray);
var
  Out_Len: integer;
begin
  DecryptBuf(InBuf, 0, Length(InBuf), OutBuf, Out_Len, 0);
end;

procedure TElGOST.ECB_Block(const InBuf: ByteArray; In_StartIdx: integer;
                      var OutBuf: ByteArray; Out_StartIdx: integer;
                      IsEncrypt: Boolean);
begin
  if  IsEncrypt then
    int_Encrypt(InBuf, In_StartIdx, OutBuf, Out_StartIdx)
  else
    int_Decrypt(InBuf, In_StartIdx, OutBuf, Out_StartIdx)
end;

procedure TElGOST.CFB_Block(const InBuf: ByteArray; In_StartIdx: integer;
                      var OutBuf: ByteArray; Out_StartIdx: integer;
                      IsEncrypt: Boolean);
var
  i: integer;
  B: Byte;
begin
  int_Encrypt(fWork_IV, 0, fGamma, 0);

  for i := 0 to c_GOST_BlockSize_1 do
  begin
    if  IsEncrypt then
    begin
      B := InBuf[In_StartIdx + i] xor fGamma[i];
      fWork_IV[i] := B;
      OutBuf[Out_StartIdx + i] := B;
    end
    else
    begin
      B := InBuf[In_StartIdx + i];
      fWork_IV[i] := B;
      OutBuf[Out_StartIdx + i] := B xor fGamma[i];
    end;
  end;
end;

const
  C1 = $01010104;
  C2 = $01010101;

procedure TElGOST.OFB_Block(const InBuf: ByteArray; In_StartIdx: integer;
                      var OutBuf: ByteArray; Out_StartIdx: integer;
                      IsEncrypt: Boolean);
var
  i: integer;
begin
  inc(fN3, C1);
  inc(fN4, C2);

  if  fN3 < C1  then  //  Wrap modulo 2^32?
    inc(fN3);         //  Make it modulo 2^32-1

  if  fN4 < C2  then  //  Wrap modulo 2^32?
    inc(fN4);         //  Make it modulo 2^32-1

  UInt_To_Buf(fN3, fWork_IV, 0);
  UInt_To_Buf(fN4, fWork_IV, 4);
  int_Encrypt(fWork_IV, 0, fGamma, 0);

  for i := 0 to c_GOST_BlockSize_1 do
    OutBuf[Out_StartIdx + i] := fGamma[i] xor InBuf[In_StartIdx + i];
end;

procedure TElGOST.CBC_Block(const InBuf: ByteArray; In_StartIdx: integer;
                      var OutBuf: ByteArray; Out_StartIdx: integer;
                      IsEncrypt: Boolean);
var
  i: integer;
begin
  if  IsEncrypt then
  begin
    for i := 0 to c_GOST_BlockSize_1 do
      fGamma[i] := fWork_IV[i] xor InBuf[In_StartIdx + i];

    int_Encrypt(fGamma, 0, fWork_IV, 0);

    for i := 0 to c_GOST_BlockSize_1 do
      OutBuf[Out_StartIdx + i] := fWork_IV[i];
  end
  else
  begin
    int_Decrypt(InBuf, In_StartIdx, fGamma, 0);

    for i := 0 to c_GOST_BlockSize_1 do
    begin
      OutBuf[Out_StartIdx + i] := fGamma[i] xor fWork_IV[i];
      fWork_IV[i] := InBuf[In_StartIdx + i];
    end;
  end;
end;

procedure TElGOST.ConvertStream(Source: TElStream; Count: cardinal; Dest: TElStream;
                            IsEncrypt: Boolean);
const
  Buf_Size : cardinal = $4000;
var
  InBuf, OutBuf: ByteArray;
  In_Len, Out_Len: integer;
  iRead: cardinal;
begin
  Reset;

  if  Count = 0 then
    Count := Source.Size;

  if  Count > Buf_Size  then
    In_Len := Buf_Size
  else
    In_Len := Count;

  SetLength_BA(InBuf, In_Len);
  SetLength_BA(OutBuf, In_Len);
  iRead := 0;

  while iRead < Count do
  begin
    Source.Read(InBuf[0], In_Len);

    if  IsEncrypt then
      Encrypt_Block(InBuf, 0, In_Len, OutBuf, Out_Len, 0)
    else
      Decrypt_Block(InBuf, 0, In_Len, OutBuf, Out_Len, 0);

    Dest.Write(OutBuf[0], Out_Len);
    inc(iRead, In_Len);

    if  (iRead + Buf_Size) > Count  then
      In_Len := Count - iRead;
  end;

  if  IsEncrypt then
    Encrypt_Finalize(OutBuf, Out_Len, 0)
  else
    Decrypt_Finalize(OutBuf, Out_Len, 0);
    
    Dest.Write(OutBuf[0], Out_Len);
end;

procedure TElGOST.EncryptStream(Source: TElStream; Count: cardinal; Dest: TElStream);
begin
  ConvertStream(Source, Count, Dest, True);
end;

procedure TElGOST.DecryptStream(Source: TElStream; Count: cardinal; Dest: TElStream);
begin
  ConvertStream(Source, Count, Dest, False);
end;

procedure TElGOST.MAC_Block_proc(const InBuf: ByteArray; In_StartIdx: integer);
var
  i: integer;
  N1, N2: UInt32;

  procedure Set_N1(Idx: integer);
  begin
    N1 := N1 xor F(N2 + fKey[Idx]);
  end;

  procedure Set_N2(Idx: integer);
  begin
    N2 := N2 xor F(N1 + fKey[Idx]);
  end;
begin
  for i := 0 to c_GOST_BlockSize_1 do
    fWork_IV[i] := fWork_IV[i] xor InBuf[In_StartIdx + i];

  N1 := Buf_to_UInt(fWork_IV, 0);
  N2 := Buf_to_UInt(fWork_IV, 4);

  Set_N2(0);    Set_N1(1);
  Set_N2(2);    Set_N1(3);
  Set_N2(4);    Set_N1(5);
  Set_N2(6);    Set_N1(7);

  Set_N2(0);    Set_N1(1);
  Set_N2(2);    Set_N1(3);
  Set_N2(4);    Set_N1(5);
  Set_N2(6);    Set_N1(7);

  UInt_To_Buf(N1, fWork_IV, 0);
  UInt_To_Buf(N2, fWork_IV, 4);
end;

procedure TElGOST.MAC_Block(InBuf: Pointer; In_Len: integer);
var
  Buf: ByteArray;
begin
  SetLength_BA(Buf, In_Len);
  SBMove(InBuf^, Buf[0], In_Len);
  MAC_Block(Buf, 0, In_Len);
end;

procedure TElGOST.MAC_Block(const InBuf: ByteArray; In_StartIdx: integer;
            In_Len: integer);
begin
  Process_Data(InBuf, In_StartIdx, In_Len,
      MAC_Block_proc
      );
end;

procedure TElGOST.MAC_Finalize(Qnt_Bits: integer; out MAC: ByteArray);
var
  i, nBytes, RemBits: integer;
begin
  if  fTailLen > 0  then
  begin
    for i := fTailLen to c_GOST_BlockSize_1 do
      fTail[i] := 0;

    MAC_Block(fTail, fTailLen, (c_GOST_BlockSize - fTailLen));
  end;

  nBytes := Qnt_Bits shr 3;

  if  nBytes >= c_GOST_BlockSize  then
  begin
    nBytes := c_GOST_BlockSize;
    RemBits := 0;
  end
  else
    RemBits := Qnt_Bits and 7;

  SetLength_BA(MAC, nBytes);

  for i := 0 to nBytes - 1 do
    MAC[i] := fWork_IV[i];

  if  RemBits > 0 then
  begin
    RemBits := 8 - RemBits;
    MAC[nBytes - 1] := (MAC[nBytes - 1] shr RemBits) shl RemBits;
  end;
end;

procedure TElGOST.MAC_Stream(Source: TElStream; Count: cardinal; Qnt_Bits: integer;
            out MAC: ByteArray);
const
  Buf_Size : cardinal = $4000;
var
  InBuf: ByteArray;
  iRead, In_Len: cardinal;
begin
  Reset;

  if  Count = 0 then
    Count := Source.Size;

  if  Count > Buf_Size  then
    In_Len := Buf_Size
  else
    In_Len := Count;

  SetLength_BA(InBuf, In_Len);
  iRead := 0;

  while iRead < Count do
  begin
    Source.Read(InBuf[0], In_Len);

    MAC_Block(InBuf, 0, In_Len);

    inc(iRead, In_Len);

    if  (iRead + Buf_Size) > Count  then
      In_Len := Count - iRead;
  end;

  MAC_Finalize(Qnt_Bits, MAC);
end;

function EncryptECB(const K, D : ByteArray) : ByteArray;
var
  GOST : TElGOST;
begin
  Result := EmptyArray;

  if (Length(D) and 7) <> 0 then
    Exit;

  GOST := TElGOST.Create;
  try
    GOST.Key := K;
    GOST.Mode := GOSTMode_ECB;
    SetLength(Result, Length(D));
    GOST.EncryptBuf(D, Result);
  finally
    FreeAndNil(GOST);
  end;
end;

function DecryptECB(const K, E : ByteArray) : ByteArray;
var
  GOST : TElGOST;
begin
  Result := EmptyArray;

  if (Length(E) and 7) <> 0 then
    Exit;

  GOST := TElGOST.Create;
  try
    GOST.Key := K;
    GOST.Mode := GOSTMode_ECB;
    SetLength(Result, Length(E));
    GOST.DecryptBuf(E, Result);
  finally
    FreeAndNil(GOST);
  end;
end;

function EncryptCFB(const IV, K, D : ByteArray) : ByteArray;
var
  GOST : TElGOST;
begin
  Result := EmptyArray;
  GOST := TElGOST.Create;
  try
    GOST.Key := K;
    GOST.IV := IV;
    GOST.Mode := GOSTMode_CFB;
    SetLength(Result, Length(D));
    GOST.EncryptBuf(D, Result);
  finally
    FreeAndNil(GOST);
  end;
end;

function DecryptCFB(const IV, K, E : ByteArray) : ByteArray;
var
  GOST : TElGOST;
begin
  Result := EmptyArray;
  GOST := TElGOST.Create;
  try
    GOST.Key := K;
    GOST.IV := IV;
    GOST.Mode := GOSTMode_CFB;
    SetLength(Result, Length(E));
    GOST.DecryptBuf(E, Result);
  finally
    FreeAndNil(GOST);
  end;
end;

function gost28147IMIT(const IV, K, D : ByteArray) : ByteArray;
var
  GOST : TElGOST;
begin
  Result := EmptyArray;
  GOST := TElGOST.Create;
  try
    GOST.Key := K;
    GOST.IV := IV;
    GOST.Reset;
    GOST.MAC_Block(D, 0, Length(D));
    SetLength(Result, 4);
    GOST.MAC_Finalize(32, Result);
  finally
    FreeAndNil(GOST);
  end;
end;

function KeyDiversifyCryptoPro(const UKM, KEK : ByteArray; var DKEK : ByteArray;
  var DKEKSize : integer) : boolean;
var
  Key, IV, E, K : ByteArray;
  S1, S2 : cardinal;
  i, j : integer;
begin
  SetLength(E, 0);
  SetLength(K, 0);
  if (Length(UKM) <> 8) or (Length(KEK) <> 32) then
  begin
    Result := false;
    DKEKSize := 0;
    Exit;
  end;

  if (DKEKSize < 32) then
  begin
    Result := false;
    DKEKSize := 32;
    Exit;
  end;

  K := CloneArray(KEK);
  SetLength(Key, 32);
  SetLength(IV, 8);

  { main iterations }
  for i := 0 to 7 do
  begin
    S1 := 0;
    S2 := 0;

    for j := 0 to 7 do
      if (UKM[i] and (1 shl j)) <> 0 then
        S1 := S1 + (K[j shl 2] or (K[(j shl 2) + 1] shl 8) or (K[(j shl 2) + 2] shl 16) or (K[(j shl 2) + 3] shl 24))
      else
        S2 := S2 + (K[j shl 2] or (K[(j shl 2) + 1] shl 8) or (K[(j shl 2) + 2] shl 16) or (K[(j shl 2) + 3] shl 24));

    IV[0] := S1 and $ff;
    IV[1] := (S1 shr 8) and $ff;
    IV[2] := (S1 shr 16) and $ff;
    IV[3] := (S1 shr 24) and $ff;
    IV[4] := S2 and $ff;
    IV[5] := (S2 shr 8) and $ff;
    IV[6] := (S2 shr 16) and $ff;
    IV[7] := (S2 shr 24) and $ff;

    E := EncryptCFB(IV, K, K);
    SBMove(E[0], K[0], 32);
  end;

  SBMove(K[0], DKEK[0], 32);
  DKEKSize := 32;
  Result := true;
end;

function KeyWrap28147(const UKM, CEK, KEK : ByteArray; var WCEK : ByteArray;
  var WCEKSize : integer; var CEK_MAC : ByteArray; var CEKMACSize : integer) : boolean;
var
  MAC, ECEK : ByteArray;
begin
  SetLength(MAC, 0);
  SetLength(ECEK, 0);
  if (Length(UKM) <> 8) or (Length(CEK) <> 32) or (Length(KEK) <> 32) then
  begin
    WCEKSize := 0;
    CEKMACSize := 0;
    Result := false;
    Exit;
  end;

  if (WCEKSize < 32) or (CEKMACSize < 4) then
  begin
    WCEKSize := 32;
    CEKMACSize := 4;
    Result := false;
    Exit;
  end;

  { computing MAC }
  MAC := gost28147IMIT(UKM, KEK, CEK);
  { encrypting CEK }
  ECEK := EncryptECB(KEK, CEK);
  { returning result }
  SBMove(MAC[0], CEK_MAC[0], 4);
  SBMove(ECEK[0], WCEK[0], 32);
  WCEKSize := 32;
  CEKMACSize := 4;
  Result := true;
end;

function KeyUnwrap28147(const UKM, WCEK, KEK, CEK_MAC : ByteArray;
  var CEK : ByteArray; var CEKSize : integer) : boolean;
var
  MAC, DCEK : ByteArray;
begin
  SetLength(MAC, 0);
  SetLength(DCEK, 0);
  if (Length(UKM) <> 8) or (Length(WCEK) <> 32) or (Length(CEK_MAC) <> 4) then
  begin
    Result := false;
    CEKSize := 0;
    Exit;
  end;

  if CEKSize < 32 then
  begin
    Result := false;
    CEKSize := 32;
    Exit;
  end;

  { decrypting CEK }
  DCEK := DecryptECB(KEK, WCEK);

  { computing and checking MAC }
  MAC := gost28147IMIT(UKM, KEK, DCEK);

  if not CompareMem(MAC, CEK_MAC) then
  begin
    Result := false;
    CEKSize := 0;
    Exit;
  end;

  { returning result }
  SBMove(DCEK[0], CEK[0], 32);
  CEKSize := 32;
  Result := true;
end;

function KeyWrapCryptoPro(const UKM, CEK, KEK : ByteArray; var WCEK : ByteArray;
  var WCEKSize : integer; var CEK_MAC : ByteArray; var CEKMACSize : integer) : boolean;
var
  DKEK, MAC, ECEK : ByteArray;
  i : integer;
begin
  SetLength(DKEK, 0);
  SetLength(MAC, 0);
  SetLength(ECEK, 0);
  if (Length(UKM) <> 8) or (Length(CEK) <> 32) or (Length(KEK) <> 32) then
  begin
    WCEKSize := 0;
    CEKMACSize := 0;
    Result := false;
    Exit;
  end;

  if (WCEKSize < 32) or (CEKMACSize < 4) then
  begin
    WCEKSize := 32;
    CEKMACSize := 4;
    Result := false;
    Exit;
  end;

  { CryptoPro KEK diversification }
  SetLength(DKEK, 32);
  i := 32;
  if not KeyDiversifyCryptoPro(UKM, KEK, DKEK, i) then
  begin
    WCEKSize := 0;
    CEKMACSize := 0;
    Result := false;
    Exit;
  end;

  { computing MAC }
  MAC := gost28147IMIT(UKM, DKEK, CEK);

  { encrypting CEK }
  ECEK := EncryptECB(DKEK, CEK);

  SBMove(MAC[0], CEK_MAC[0], 4);
  SBMove(ECEK[0], WCEK[0], 32);
  WCEKSize := 32;
  CEKMACSize := 4;
  Result := true;
end;

function KeyUnwrapCryptoPro(const UKM, WCEK, KEK, CEK_MAC : ByteArray;
  var CEK : ByteArray; var CEKSize : integer) : boolean;
var
  DKEK, MAC, DCEK : ByteArray;
  i : integer;
begin
  SetLength(DKEK, 0);
  SetLength(MAC, 0);
  SetLength(DCEK, 0);
  if (Length(UKM) <> 8) or (Length(WCEK) <> 32) or (Length(CEK_MAC) <> 4) then
  begin
    Result := false;
    CEKSize := 0;
    Exit;
  end;

  if CEKSize < 32 then
  begin
    Result := false;
    CEKSize := 32;
    Exit;
  end;

  { CryptoPro KEK diversification }
  SetLength(DKEK, 32);
  i := 32;
  if not KeyDiversifyCryptoPro(UKM, KEK, DKEK, i) then
  begin
    CEKSize := 0;
    Result := false;
    Exit;
  end;

  { decrypting CEK }
  DCEK := DecryptECB(DKEK, WCEK);

  { computing and checking MAC }
  MAC := gost28147IMIT(UKM, DKEK, DCEK);

  if not CompareMem(MAC, CEK_MAC) then
  begin
    Result := false;
    CEKSize := 0;
    Exit;
  end;

  { returning result }
  SBMove(DCEK[0], CEK[0], 32);
  CEKSize := 32;
  Result := true;
end;

end.
