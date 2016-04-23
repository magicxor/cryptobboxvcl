(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit  SBGOST341194;

interface

uses
  SBTypes,
  SBUtils,
  SBConstants,
  SBStreams,
  SBGOSTCommon
  ;


const
  c_GOST_DigestSize = 32;

type
  TElGOSTMD = class(TElGOSTBase)
  protected
    fH: ByteArray;
    fS: ByteArray;
    fM: ByteArray;
    fU: ByteArray;
    fV: ByteArray;
    fW: ByteArray;
    fTmp: ByteArray;
    fSum: ByteArray;
    fTotalLen: Int64;

    class function  GetBlockSize(): cardinal; override; 
    procedure Hash_Block(const InBuf: ByteArray; In_StartIdx: integer);
    procedure Process_Block(const InBuf: ByteArray; In_StartIdx: integer); 
  public
    class function DigestSize(): integer; 
    constructor Create();  overload; 
    constructor Create(const SubstBlock: TElGostSubstBlock);  overload; 
     destructor  Destroy; override;
    procedure Reset; override;
    procedure Clone(Source: TElGOSTBase); override;
    procedure Update(In_Buf: Pointer; Len: cardinal);  overload; 
    procedure Update(const In_Buf: ByteArray; StartIndex, Len: cardinal);  overload; 
    procedure Final(out Digest: ByteArray);
    //  All-in-one version
    procedure Calculate(const In_Buf: ByteArray; StartIndex, Len: cardinal;
                        out Digest: ByteArray);  overload; 
    procedure Calculate(Source: TElStream; Count: cardinal; out Digest: ByteArray);
                          overload; 
  end;

implementation

const
  c_GOST_DigestSize_1 = (c_GOST_DigestSize - 1);

var
  C: array[2..4] of ByteArray;

const
  C3: array[0..31] of byte =  ( 
       $00, $FF, $00, $FF, $00, $FF, $00, $FF,
       $FF, $00, $FF, $00, $FF, $00, $FF, $00,
       $00, $FF, $FF, $00, $FF, $00, $00, $FF,
       $FF, $00, $00, $00, $FF, $FF, $00, $FF
   ) ;

procedure Init_C();
var
  i: integer;
begin
  if  C[2] = nil  then
  begin
    TElGOSTMD.SetLength_BA(C[2], c_GOST_DigestSize);
    TElGOSTMD.SetLength_BA(C[3], c_GOST_DigestSize);
    TElGOSTMD.SetLength_BA(C[4], c_GOST_DigestSize);
    TElGOSTMD.FillArray(C[2], 0);
    TElGOSTMD.FillArray(C[4], 0);

    for i := 0 to c_GOST_DigestSize_1 do
      C[3][i] := C3[i];
  end;
end;

procedure Sum_Blocks(var Res: ByteArray; const toAdd: ByteArray; StartIdx: integer);
var
  i, Carry, Sm: integer;
begin
  Carry := 0;

  for i := 0 to c_GOST_DigestSize_1 do
  begin
    Sm := Res[i] + toAdd[StartIdx + i] + Carry;
    Res[i] := Sm and $FF;
    Carry := Sm shr 8;
  end;
end;

procedure XOR_Blocks(var Res: ByteArray; const V1, V2: ByteArray);
var
  i: integer;
begin
  for i := 0 to c_GOST_DigestSize_1 do
    Res[i] := V1[i] xor V2[i];
end;

function  Get_Short(const Arr: ByteArray; Start_Idx: integer): UInt16;
begin
  Result := Arr[Start_Idx] + (Arr[Start_Idx + 1] shl 8);
end;

procedure Save_Short(var Arr: ByteArray; Start_Idx: integer; V: UInt16);
begin
  Arr[Start_Idx] := V and $FF;
  Arr[Start_Idx + 1] := (V shr 8) and $FF;
end;

class function TElGOSTMD.DigestSize(): integer;
begin
  Result := c_GOST_DigestSize;
end;

class function  TElGOSTMD.GetBlockSize(): cardinal;
begin
  Result := c_GOST_DigestSize;
end;

constructor TElGOSTMD.Create();
begin
  Create(TElGOSTMD.MakeSubstBlock(SB_GOSTR3411_94_CryptoProParamSet));
end;

constructor TElGOSTMD.Create(const SubstBlock: TElGostSubstBlock);
begin
  inherited Create(SubstBlock);

  Init_C();
  SetLength_BA(fS, c_GOST_DigestSize);
  SetLength_BA(fH, c_GOST_DigestSize);
  SetLength_BA(fM, c_GOST_DigestSize);
  SetLength_BA(fU, c_GOST_DigestSize);
  SetLength_BA(fV, c_GOST_DigestSize);
  SetLength_BA(fW, c_GOST_DigestSize);
  SetLength_BA(fTmp, c_GOST_DigestSize);
  SetLength_BA(fSum, c_GOST_DigestSize);
  SetLength_BA(fTail, c_GOST_DigestSize);

end;

 destructor  TElGOSTMD.Destroy;
begin
  inherited;
end;

procedure TElGOSTMD.Reset;
begin
  inherited ;
  FillArray(fH, 0);
  FillArray(fSum, 0);
  fTotalLen := 0;
end;

procedure TElGOSTMD.Clone(Source: TElGOSTBase);
var
  Src: TElGOSTMD;
begin
  inherited Clone(Source);

  if  not (Source is TElGOSTMD) then
    exit;

  Src := TElGOSTMD(Source);
  fH := CloneArray(Src.fH);
  fS := CloneArray(Src.fS);
  fM := CloneArray(Src.fM);
  fU := CloneArray(Src.fU);
  fV := CloneArray(Src.fV);
  fW := CloneArray(Src.fW);
  fTmp := CloneArray(Src.fTmp);
  fSum := CloneArray(Src.fSum);
  fTotalLen := Src.fTotalLen;
end;

procedure TElGOSTMD.Process_Block(const InBuf: ByteArray; In_StartIdx: integer);
  procedure  Transform_A(var Res: ByteArray; const V: ByteArray);
  var
    T: array[0..7] of byte;
    i: integer;
  begin
    for i := 0 to 7 do
      T[i] := V[i] xor V[i + 8];

    ArrayCopy(V, 8, Res, 0, 24);

    for i := 0 to 7 do
      Res[i + 24] := T[i];
  end;

  procedure Transform_P(var Res: ByteArray; const V: ByteArray);
  var
    i, i4: integer;
  begin
    for i := 0 to 7 do
    begin
      i4 := i * 4;
      Res[i4] := V[i];
      Res[i4 + 1] := V[i + 8];
      Res[i4 + 2] := V[i + 16];
      Res[i4 + 3] := V[i + 24];
    end;
  end;

  procedure Transform_F(var Arr: ByteArray);
  var
    R: UInt16;
  begin
    R := Get_Short(Arr, 0) xor Get_Short(Arr, 2) xor Get_Short(Arr, 4)
         xor Get_Short(Arr, 6) xor Get_Short(Arr, 24) xor Get_Short(Arr, 30);
    ArrayCopy(Arr, 2, Arr, 0, 30);
    Save_Short(Arr, 30, R);
  end;

var
  i, Offset: integer;

begin
  ArrayCopy(InBuf, In_StartIdx, fM, 0, c_GOST_DigestSize);

  //  Key 1
  // H = h3 || h2 || h1 || h0
  // S = s3 || s2 || s1 || s0
  ArrayCopy(fH, 0, fU, 0, c_GOST_DigestSize);
  ArrayCopy(fM, 0, fV, 0, c_GOST_DigestSize);
  XOR_Blocks(fW, fU, fV);
  Transform_P(fTmp, fW);
  int_SetKey(fTmp);
  //  s0 = EK0[h0]
  int_Encrypt(fH, 0, fS, 0);

  //  Keys 2, 3, 4
  Offset := c_GOST_BlockSize;

  for i := Low(C) to High(C) do
  begin
    Transform_A(fTmp, fU);
    XOR_Blocks(fU, fTmp, C[i]);
    Transform_A(fTmp, fV);
    Transform_A(fV, fTmp);
    XOR_Blocks(fW, fU, fV);
    Transform_P(fTmp, fW);
    int_SetKey(fTmp);
    //  Si = EKi[hi]
    int_Encrypt(fH, Offset, fS, Offset);
    inc(Offset, c_GOST_BlockSize);
  end;

  for i := 1 to 12 do
    Transform_F(fS);

  XOR_Blocks(fS, fS, fM);
  Transform_F(fS);
  XOR_Blocks(fS, fS, fH);

  for i := 1 to 61 do
    Transform_F(fS);

  ArrayCopy(fS, 0, fH, 0, c_GOST_DigestSize);
end;

procedure TElGOSTMD.Hash_Block(const InBuf: ByteArray; In_StartIdx: integer);
begin
  Process_Block(InBuf, In_StartIdx);
  Sum_Blocks(fSum, InBuf, In_StartIdx);
  inc(fTotalLen, c_GOST_DigestSize);
end;

procedure TElGOSTMD.Update(In_Buf: Pointer; Len: cardinal);
var
  Buf: ByteArray;
begin
  SetLength_BA(Buf, Len);
  SBMove(In_Buf^, Buf[0], Len);
  Update(Buf, 0, Len);
end;

procedure TElGOSTMD.Update(const In_Buf: ByteArray; StartIndex, Len: cardinal);
begin
  Process_Data(In_Buf, StartIndex, Len,
      Hash_Block
      );
end;

procedure TElGOSTMD.Final(out Digest: ByteArray);
var
  i: integer;
begin
  if  fTailLen > 0  then
  begin
    for i := fTailLen to c_GOST_DigestSize_1 do
      fTail[i] := 0;

    Process_Block(fTail, 0);
    Sum_Blocks(fSum, fTail, 0);
    inc(fTotalLen, fTailLen);
  end;

  fTotalLen := fTotalLen shl 3; //  Hash length in bits
  FillArray(fTail, 0);
  i := 0;

  while fTotalLen > 0 do
  begin
    fTail[i] := fTotalLen and $FF;
    fTotalLen := fTotalLen shr 8;
    inc(i);
  end;

  Process_Block(fTail, 0);
  Process_Block(fSum, 0);
  Copy_BA(fH, Digest, c_GOST_DigestSize);
end;

procedure TElGOSTMD.Calculate(const In_Buf: ByteArray; StartIndex, Len: cardinal;
  out Digest: ByteArray);
begin
  Reset;
  Update(In_Buf, StartIndex, Len);
  Final(Digest);
end;

procedure TElGOSTMD.Calculate(Source: TElStream; Count: cardinal; out Digest: ByteArray);
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

    Update(InBuf, 0, In_Len);

    inc(iRead, In_Len);

    if  (iRead + Buf_Size) > Count  then
      In_Len := Count - iRead;
  end;

  Final(Digest);
end;

end.