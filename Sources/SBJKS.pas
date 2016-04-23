(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBJKS;

interface

uses
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBConstants,
  SBX509,
  SBSHA,
  SBRandom
  ,
  Classes,
  SysUtils
  ;


type
  Int32 = LongWord;

type
  TEntry = record
    Alias: string;
    CreationDate: TElDateTime;
    EncodedKey: ByteArray;
    Certificate_Chain: array of TElX509Certificate;
    Cert_Count: integer;
  end;

const
  E_JKS_FORMAT_ERROR = 1;
  E_JKS_READ_ERROR = 2;
  E_JKS_WRITE_ERROR = 3;
  E_JKS_VERSION_ERROR = 4;
  E_JKS_KEY_FORMAT_ERROR = 5;
  E_JKS_UNKNOWN_CERT = 6;
  E_JKS_CHECKSUM = 7;
  E_JKS_SIGNATURE = 8;
  E_JKS_NO_SPACE = 9;

type
  TElJKSPasswordEvent =  function(const Alias : string; var Password: TSBString): boolean of object;
  TElJKSAliasNeededEvent =  function(Cert : TElX509Certificate; var Alias: TSBString): boolean of object;

type
  TElJKS = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElJKS = TElJKS;
   {$endif}

  TElJKS = class
  protected
    function GetIsPrivateKey(Index: integer): boolean;
    function GetChainCount(Index: integer): integer;

  private
    FEntries: array of TEntry;
    FEntries_Count: integer;
    FSha: TSHA1Context;
    FIgnoreBadStorageSignature : boolean;

    function LoadCertFromStream(Stream: TElInputStream; var Cert: TElX509Certificate): integer;
    function LoadCertFromBuffer(const Src_Buffer: ByteArray; BufferSize: LongInt; var BufferPos: LongInt; var Cert: TElX509Certificate): integer;
    function SaveCertToStream(Stream: TElOutputStream; Cert: TElX509Certificate): integer;
    function SaveCertToBuffer(Cert: TElX509Certificate; var DstBuffer: ByteArray; BufferSize: LongInt; var BufferPos: Longint): integer;
    function LoadFromStreamViaSha(Stream: TElInputStream; var Buffer ; Count: Integer): LongInt;
    function SaveToStreamViaSha(Stream: TElOutputStream; var Buffer ; Count: Integer): LongInt;
    function LoadFromBufferViaSha(const Src_Buffer: ByteArray; BufferSize: LongInt; var BufferPos: LongInt; var Buffer ; Count: Integer): LongInt;
    function SaveToBufferViaSha(const Buffer; DstBuffer: Pointer; var BufferPos: LongInt; Count: Integer): LongInt;

    function Decryptkey(const Data, Pass: ByteArray; var Key: ByteArray): boolean;
    function Encryptkey(const Key, Pass: ByteArray; var Encrypted: ByteArray): boolean;

  public
    constructor Create;
     destructor  Destroy; override;

    function LoadFromStream(Stream: TElInputStream; const JKS_Pass: string): integer;
    function LoadFromBuffer(Src_Ptr: Pointer; BufferSize: LongInt; var BufferPos: LongInt; const JKS_Pass: string): integer;
    function GetSaveBufferSize: LongInt;
    function SaveToStream(Stream: TElOutputStream; const JKS_Pass: string): integer;
    function SaveToBuffer(var DstBuffer: ByteArray; BufferSize: LongInt; var BufferPos: LongInt; const JKS_Pass: string): integer;

    function GetPrivateKey(Index: integer; const Pass: string; var Key: ByteArray): boolean;
    function SetPrivateKey(Index: integer; const Pass: string; const Key: ByteArray): boolean;
    function AddPrivateKey(const Pass: string; const Key: ByteArray):integer;

    function GetKeyCertificate(Index, Cert_Index: integer): TElX509Certificate;
    function AddKeyCertificate(Index: integer; Cert: TElX509Certificate):integer;
    procedure DelKeyCertificate(Index, Cert_Index: integer);

    function GetTrustedCertificate(Index: integer): TElX509Certificate;
    function AddTrustedCertificate(Cert: TElX509Certificate):integer;
    procedure DelTrustedCertificate(Index: integer);

    function GetAlias(Index: integer): string;
    procedure SetAlias(Index: integer; const Alias : string);

    property Entries_Count: integer read FEntries_Count;
    property PrivateKeyCert_Count[index: integer]: integer read GetChainCount;
    property IsPrivateKey[Index: integer]: boolean read GetIsPrivateKey;
    property IgnoreBadStorageSignature : boolean read FIgnoreBadStorageSignature
      write FIgnoreBadStorageSignature;
  end;

implementation

uses SBPKCS8;


function IncDay(ADate: TElDateTime; Delta: Integer): TElDateTime;
begin
  Result := ADate + Delta;
end;

function IncTime(ATime: TDateTime; Hours, Minutes, Seconds,
  MSecs: Integer): TDateTime;
begin
  Result := ATime + (Hours div 24) + (((Hours mod 24) * 3600000 +
    Minutes * 60000 + Seconds * 1000 + MSecs) / MSecsPerDay);
  if Result < 0 then Result := Result + 1;
end;

function IncMilliSecond(ATime: TElDateTime; Delta: Integer): TElDateTime;
begin
  Result := IncTime(ATime, 0, 0, 0, Delta);
end;

function DaysBetween(ADate1, ADate2: TElDateTime): LongInt;
begin
  Result := Trunc(ADate2) - Trunc(ADate1) + 1;
  if Result < 0 then Result := 0;
end;

function MilliSecondOfTheDay(ADate: TElDateTime): LongInt;
var
  LHours, LMinutes, LSeconds, LMilliSeconds: Word;
begin
  DecodeTime(ADate, LHours, LMinutes, LSeconds, LMilliSeconds);
  Result := LMilliSeconds + (LSeconds + (LMinutes + LHours * 60) * 60) * 1000;
end;


function BEData2Int(const Buffer: ByteArray; Len: integer): Cardinal;
begin
  case Len of
    1: Result := LongWord(Buffer[0]);
    2: Result := (LongWord(Buffer[0]) shl 8) + LongWord(Buffer[1]);
    4: Result := (LongWord(Buffer[0]) shl 24) + (LongWord(Buffer[1]) shl 16) + (LongWord(Buffer[2]) shl 8) + LongWord(Buffer[3]);
  else
    Result := 0;
  end;
end;

(*
function BEData2Comp(const Buffer: ByteArray; Len: integer): Int64;
var
//  Tmp: Comp;
  i: integer;
begin
  Result := 0;
  for i := 1 to Len do
    Result := (Result shl 8) + Buffer[i - 1];
end;
*)

procedure Int2BEData(Data: Cardinal; var Buffer: ByteArray; Len: integer);
var
  i: integer;
begin
  for i := Len downto 1 do
  begin
    Buffer[i - 1] := Data and $FF;
    Data := Data shr 8;
  end;
end;


function StringToUniBe(const St: string): ByteArray;
var
  Uni: ByteArray;
  i: integer;
  b: Byte;
  Len : integer;
begin
  Len := Length(St);
  if (Len > 0) then
  begin
    SetLength(Uni, (Len + 1) shl 1); // reserving extra space for NULL character
    StringToWideChar(St, @Uni[0], Len + 1);
    SetLength(Uni, Len shl 1); // removing trailing NULL character
    for i := 1 to Length(St) do
    begin
      B := Uni[(i - 1) shl 1];
      Uni[(i - 1) shl 1] := Uni[(i - 1) shl 1 + 1];
      Uni[(i - 1) shl 1 + 1] := B;
    end;
    Result := Uni;
  end
  else
    Result := EmptyArray;

  Uni := nil; // should be that way, no release
end;

constructor TElJKS.Create;
begin
  inherited Create;
  SetLength(FEntries, 0);
  FIgnoreBadStorageSignature := true;
end;

 destructor  TElJKS.Destroy;
var
  i, j: integer;
begin
  if FEntries <> nil then
  begin
    for i := 1 to Length(FEntries) do
    begin
      for j := 1 to Length(FEntries[i - 1].Certificate_Chain) do
        FEntries[i - 1].Certificate_Chain[j - 1]. Free ;
      SetLength(FEntries[i - 1].Certificate_Chain, 0);
    end;
    SetLength(FEntries, 0);
  end;
  inherited;
end;

function TElJKS.LoadFromBufferViaSha(const Src_Buffer: ByteArray; BufferSize: LongInt; var BufferPos: LongInt; var Buffer ; Count: Integer): LongInt;
var
  B: ByteArray;
begin
  if (BufferPos + Count) > BufferSize then
  begin
    Result := 0;
    exit;
  end;

  try
    SetLength(B, Count);

    SBMove(Src_Buffer  [BufferPos],  B  [0],  Count);

    SBSha.HashSha1(FSha, @B[0], Count);
    SBMove(B[0], Buffer, Count);
    BufferPos := BufferPos + Count;
    Result := Count;
  finally
    ReleaseArray(B);
  end;
end;

function TElJKS.LoadFromStreamViaSha(Stream: TElInputStream; var Buffer; Count: LongInt): LongInt;
var
  B:  ByteArray ;
  Count1, B_Pos: integer;
begin
  try
    SetLength(B, Count);
    Count1 := Stream.Read(B  [0] , Count);
    B_Pos := 0;
    Result := LoadFromBufferViaSha((B), Count1, B_Pos, Buffer, Count);
  finally
    ReleaseArray(B);
  end;
end;

function TElJKS.SaveToBufferViaSha(const Buffer; DstBuffer: Pointer; var BufferPos: LongInt; Count: Integer): LongInt;
var
  B: ByteArray;
  PTmp: PChar;
begin
  try
    SetLength(B, Count);
    SBMove(Buffer, B[0], Count);
    SBSha.HashSha1(FSha, @B[0], Count);
    PTmp := PChar(DstBuffer) + BufferPos;
    SBMove(B[0], PTmp^, Count);
    BufferPos := BufferPos + Count;
    Result := Count;
  finally
    ReleaseArray(B);
  end;
end;

function TElJKS.SaveToStreamViaSha(Stream: TElOutputStream; var Buffer ; Count: LongInt): LongInt;
var
  B: ByteArray;
  B_Pos: integer;
begin
  try
    SetLength(B, Count);

    B_Pos := 0;
    Result := SaveToBufferViaSha(Buffer, B, B_Pos, Count);
    try
      Stream.Write((B)  [0] , Count);
    except
      Result := 0;
    end;
  finally
    ReleaseArray(B);
  end;
end;

function TElJKS.GetIsPrivateKey(Index: integer): boolean;
begin
  if (Index + 1) > FEntries_Count then
    raise ESecureBlackboxError.Create('Index out of entries count!');
  Result := (Length(FEntries[Index].EncodedKey) <> 0);
end;

function TElJKS.GetChainCount(Index: integer): integer;
begin
  if (Index + 1) > FEntries_Count then
    raise ESecureBlackboxError.Create('Index out of entries count!');
  Result := Length(FEntries[Index].Certificate_Chain);
end;

function TElJKS.LoadCertFromBuffer(const Src_Buffer: ByteArray; BufferSize: LongInt; var BufferPos: LongInt; var Cert: TElX509Certificate): integer;
var
  Count, Count1: integer;
  Alg: string;
  Buffer: ByteArray;
begin

  SetLength(Buffer, 4);
  Result := 0;
  Count := LoadFromBufferViaSha(Src_Buffer, BufferSize, BufferPos, Buffer  [0] , 2);
  if Count <> 2 then
  begin
    Result := E_JKS_READ_ERROR;
    exit;
  end;
  Alg := '';
  Count1 := BEData2Int(Buffer, 2);
  SetLength(Buffer, Count1);
  Count := LoadFromBufferViaSha(Src_Buffer, BufferSize, BufferPos, Buffer  [0] , Count1);
  if Count <> Count1 then
  begin
    Result := E_JKS_READ_ERROR;
    exit;
  end;
  Alg := StringOfBytes(Buffer);
  SetLength(Buffer, 4);
  Count := LoadFromBufferViaSha(Src_Buffer, BufferSize, BufferPos, Buffer  [0] , 4);
  if Count <> 4 then
  begin
    Result := E_JKS_READ_ERROR;
    exit;
  end;
  Count1 := BEData2Int(Buffer, 4);
  Count := Count1;
  if Alg = 'X.509' then
  begin
    SetLength(Buffer, Count1);
    Count1 := LoadFromBufferViaSha(Src_Buffer, BufferSize, BufferPos, Buffer  [0] , Count);
    if Count <> Count1 then
    begin
      Result := E_JKS_READ_ERROR;
      exit;
    end;

    Cert.LoadFromBuffer(Buffer, Count);
  end
  else
    Result := E_JKS_UNKNOWN_CERT;

end;

function TElJKS.LoadCertFromStream(Stream: TElInputStream; var Cert: TElX509Certificate): integer;
var
  Count, Count1, Buf_Size: integer;
  Alg: string;
  Buffer, Buffer1: ByteArray;
begin

  SetLength(Buffer, 4);

  Buf_Size := 2;
  //Result := 0;
  Count := LoadFromStreamViaSha(Stream, Buffer  [0] , 2);
  if Count <> 2 then
  begin
    Result := E_JKS_READ_ERROR;
    exit;
  end;
  Alg := '';
  Count1 := BEData2Int(Buffer, 2);
  SetLength(Buffer, Buf_Size + Count1);
  SetLength(Buffer1, Count1);
  Count := LoadFromStreamViaSha(Stream, Buffer1  [0] , Count1);
  if Count <> Count1 then
  begin
    Result := E_JKS_READ_ERROR;
    exit;
  end;
  SBMove(Buffer1  [0],  Buffer  [Buf_Size],  Count);
  Buf_Size := Buf_Size + Count1;

  Alg := StringOfBytes(Buffer1);
  SetLength(Buffer, Buf_Size + 4);
  SetLength(Buffer1, 4);
  Count := LoadFromStreamViaSha(Stream, Buffer1  [0] , 4);
  if Count <> 4 then
  begin
    Result := E_JKS_READ_ERROR;
    exit;
  end;
  SBMove(Buffer1  [0],  Buffer  [Buf_Size],  Count);
  Buf_Size := Buf_Size + 4;

  Count1 := BEData2Int(Buffer1, 4);
  Count := Count1;
  if Alg = 'X.509' then
  begin
    SetLength(Buffer, Buf_Size + Count);
    SetLength(Buffer1, Count);
    Count1 := LoadFromStreamViaSha(Stream, Buffer1  [0] , Count);
    SBMove(Buffer1  [0],  Buffer  [Buf_Size],  Count1);
    Buf_Size := Buf_Size + Count;
    if Count <> Count1 then
    begin
      Result := E_JKS_READ_ERROR;
      exit;
    end;
    Count := 0;
    Result := LoadCertFromBuffer(Buffer, Buf_Size, Count, Cert);
  end
  else
    Result := E_JKS_UNKNOWN_CERT;

end;

function TElJKS.SaveCertToBuffer(Cert: TElX509Certificate; var DstBuffer: ByteArray; BufferSize: LongInt; var BufferPos: Longint): integer;
var
  Count1 : Word;
  Count: integer;
  Alg: string;
  Buffer, Buffer1: ByteArray;
begin

  Result := 0;
  SetLength(Buffer, 4);

  Alg := 'X.509';
  Int2BeData(Length(Alg), Buffer, 2);
  Count := SaveToBufferViaSha(Buffer  [0] , DstBuffer, BufferPos, 2);
  if Count <> 2 then
  begin
    Result := E_JKS_WRITE_ERROR;
    exit;
  end;
  Buffer1 := BytesOfString(Alg);
  Count := SaveToBufferViaSha(Buffer1  [0] , DstBuffer, BufferPos, Length(Buffer1));
  if Count <> Length(Alg) then
  begin
    Result := E_JKS_WRITE_ERROR;
    exit;
  end;

  SetLength(Buffer, 32000);
  Count := 32000;

  Cert.SaveToBuffer( @Buffer[0],  Count);
  SetLength(Buffer1, 4);
  Int2BeData(Count, Buffer1, 4);
  Count1 := SaveToBufferViaSha(Buffer1  [0] , DstBuffer, BufferPos, 4);
  if Count1 <> 4 then
  begin
    Result := E_JKS_WRITE_ERROR;
    exit;
  end;
  Count1 := SaveToBufferViaSha(Buffer  [0] , DstBuffer, BufferPos, Count);
  if Count <> Count1 then
  begin
    Result := E_JKS_WRITE_ERROR;
    exit;
  end;

end;

function TElJKS.SaveCertToStream(Stream: TElOutputStream; Cert: TElX509Certificate): integer;
var
  Count1 : Word;
  Count: integer;
  Alg: string;
  Buffer, Buffer1: ByteArray;
begin

  Result := 0;
  SetLength(Buffer, 4);

  Alg := 'X.509';
  Int2BeData(Length(Alg), Buffer, 2);
  Count := SaveToStreamViaSha(Stream, Buffer  [0] , 2);
  if Count <> 2 then
  begin
    Result := E_JKS_WRITE_ERROR;
    exit;
  end;
  Buffer1 := BytesOfString(Alg);
  Count := SaveToStreamViaSha(Stream, Buffer1  [0] , Length(Buffer1));
  if Count <> Length(Alg) then
  begin
    Result := E_JKS_WRITE_ERROR;
    exit;
  end;

  SetLength(Buffer, 32000);
  Count := 32000;

  Cert.SaveToBuffer( @Buffer[0],  Count);
  SetLength(Buffer1, 4);
  Int2BeData(Count, Buffer1, 4);
  Count1 := SaveToStreamViaSha(Stream, Buffer1  [0] , 4);
  if Count1 <> 4 then
  begin
    Result := E_JKS_WRITE_ERROR;
    exit;
  end;

  Count1 := SaveToStreamViaSha(Stream, Buffer  [0] , Count);
  if Count <> Count1 then
  begin
    Result := E_JKS_WRITE_ERROR;
    exit;
  end;

end;

function TElJKS.GetKeyCertificate(Index, Cert_Index: integer): TElX509Certificate;
begin
  if not GetIsPrivateKey(Index) then
    raise ESecureBlackboxError.Create('Entry is not a private key!');
  if (Cert_Index + 1) > GetChainCount(Index) then
    raise ESecureBlackboxError.Create('Cert number out of index!');
  Result := FEntries[Index].Certificate_Chain[Cert_Index];
end;

function TElJKS.AddKeyCertificate(Index: integer; Cert: TElX509Certificate):integer;
begin
  if not GetIsPrivateKey(Index) then
    raise ESecureBlackboxError.Create('Entry is not a private key!');

  SetLength(FEntries[Index].Certificate_Chain, Length(FEntries[Index].Certificate_Chain) + 1);
  FEntries[Index].Certificate_Chain[Length(FEntries[Index].Certificate_Chain) - 1] := TElX509Certificate.Create(nil);
  Cert.Clone(FEntries[Index].Certificate_Chain[Length(FEntries[Index].Certificate_Chain) - 1], true);
  Result := Length(FEntries[Index].Certificate_Chain);
end;

procedure TElJKS.DelKeyCertificate(Index, Cert_Index: integer);
var
  i, Count: integer;
begin
  if not GetIsPrivateKey(Index) then
    raise ESecureBlackboxError.Create('Entry is not a private key!');
  if (Cert_Index + 1) > GetChainCount(Index) then
    raise ESecureBlackboxError.Create('Cert number out of index!');
  Count := GetChainCount(Index);
  for i := Cert_Index + 1 to Count - 1 do
    FEntries[Index].Certificate_Chain[i - 1] := FEntries[Index].Certificate_Chain[i];
  SetLength(FEntries[Index].Certificate_Chain, Count - 1);
end;

function TElJKS.GetTrustedCertificate(Index: integer): TElX509Certificate;
begin
  if GetIsPrivateKey(Index) then
    raise ESecureBlackboxError.Create('Entry is not a trusted certificate!');
  if GetChainCount(Index) = 0 then
    raise ESecureBlackboxError.Create('Cert number out of index!');

  Result := FEntries[Index].Certificate_Chain[0];
end;

function TElJKS.AddTrustedCertificate(Cert: TElX509Certificate):integer;
begin
  inc(FEntries_Count);
  SetLength(FEntries, FEntries_Count);
  SetLength(FEntries[FEntries_Count - 1].Certificate_Chain, 1);
  SetLength(FEntries[FEntries_Count - 1].EncodedKey, 0);
  FEntries[FEntries_Count - 1].Certificate_Chain[0]:=TElX509Certificate.Create(nil);
  Cert.Clone(FEntries[FEntries_Count - 1].Certificate_Chain[0], true);
  FEntries[FEntries_Count - 1].Alias := '';
  FEntries[FEntries_Count - 1].CreationDate :=  Now ;
  {$ifdef SB_WINDOWS}
  FEntries[FEntries_Count - 1].CreationDate := LocalTimeToUTCTime(FEntries[FEntries_Count - 1].CreationDate);
   {$endif}
  Result := FEntries_Count;
end;

procedure TElJKS.DelTrustedCertificate(Index: integer);
var
  i: integer;
begin
  if GetIsPrivateKey(Index) then
    raise ESecureBlackboxError.Create('Entry is not a trusted certificate!');

  FEntries[FEntries_Count - 1].Certificate_Chain[1]. Free ;
  for i := Index + 1 to FEntries_Count - 1 do
    FEntries[i - 1] := FEntries[i];
  SetLength(FEntries, FEntries_Count - 1);
  Dec(FEntries_Count);
end;

function TElJKS.GetPrivateKey(Index: integer; const Pass: string; var Key: ByteArray): boolean;
var
  bPass: ByteArray;
begin
  if not GetIsPrivateKey(Index) then
    raise ESecureBlackboxError.Create('Entry is not a private key!');

  bPass := StringToUniBe(Pass);
  Result := DecryptKey(FEntries[Index].EncodedKey, bPass, Key);
  ReleaseArray(bPass);
end;

function TElJKS.SetPrivateKey(Index: integer; const Pass: string; const Key: ByteArray): boolean;
var
  bPass: ByteArray;
begin
  if not GetIsPrivateKey(Index) then
    raise ESecureBlackboxError.Create('Entry is not a private key!');

  bPass := StringToUniBe(Pass);
  Result := EncryptKey(Key, bPass, FEntries[Index].EncodedKey);
  ReleaseArray(bPass);
end;

function TElJKS.AddPrivateKey(const Pass: string; const Key: ByteArray):integer;
var
  bPass: ByteArray;
begin
  bPass := StringToUniBe(Pass);
  inc(FEntries_Count);
  SetLength(FEntries, FEntries_Count);
  SetLength(FEntries[FEntries_Count - 1].Certificate_Chain, 0);
  SetLength(FEntries[FEntries_Count - 1].EncodedKey, Length(Key)+40);

  if Length(Key)=0 then
    SetLength(FEntries[FEntries_Count - 1].EncodedKey,0)
  else
    EncryptKey(Key, bPass, FEntries[FEntries_Count - 1].EncodedKey);
  FEntries[FEntries_Count - 1].Alias := '';
  FEntries[FEntries_Count - 1].CreationDate :=  Now ;
  {$ifdef SB_WINDOWS}
  FEntries[FEntries_Count - 1].CreationDate := LocalTimeToUTCTime(FEntries[FEntries_Count - 1].CreationDate);
   {$endif}
  Result := FEntries_Count;

  ReleaseArray(bPass);
end;

function TElJKS.GetAlias(Index: integer): string;
begin
  Result := FEntries[Index].Alias;
end;

procedure TElJKS.SetAlias(Index: integer; const Alias : string);
begin
  FEntries[Index].Alias := Alias;
end;

function TElJKS.Decryptkey(const Data, Pass: ByteArray; var Key: ByteArray): boolean;
var
  Sha: TSHA1Context;
  Dig: TMessageDigest160;
  Keystream, Check, Check1: bytearray;
  Count, i: integer;
begin

  SetLength(KeyStream, 20);
  SetLength(Check, 20);
  SetLength(Check1, 20);
  SetLength(Key, Length(Data) - 40);
  SBMove(Data[0], KeyStream[0], 20);
  SBMove(Data[Length(Data) - 20], Check[0], 20);
  Count := 0;
  while (count < Length(Key)) do
  begin
    SBSha.InitializeSHA1(Sha);
    SBSha.HashSha1(Sha,  @Pass[0] , Length(Pass));
    SBSha.HashSha1(Sha,  @KeyStream[0] , Length(KeyStream));
    Dig := SBSha.FinalizeSha1(Sha);
    SBMove(Dig, keystream[0], 20);
    i := 0;
    while (i < Length(keystream)) and (count < Length(key)) do
    begin
      Key[count] := Byte(KeyStream[i] xor Data[count + 20]);
      Inc(count);
      Inc(i);
    end;
  end;
  SBSha.InitializeSHA1(Sha);
  SBSha.HashSha1(Sha,  @Pass[0] , Length(Pass));
  SBSha.HashSha1(Sha,  @Key[0] , Length(Key));

  Dig := SBSha.FinalizeSha1(Sha);
  SBMove(Dig, Check1[0], 20);
  Result := CompareMem(Check, Check1 , 20 );

end;

function TElJKS.Encryptkey(const Key, Pass: ByteArray; var Encrypted: ByteArray): boolean;
var
  Sha: TSHA1Context;
  Dig: TMessageDigest160;
  Keystream : bytearray;
  Count, i: integer;
begin
  SetLength(Encrypted, Length(Key) + 40);
  SetLength(KeyStream, 20);

  SBRndGenerate( @KeyStream[0] , 20);
  SBMove(KeyStream[0], Encrypted[0], 20);

  Count := 0;
  while (count < Length(Key)) do
  begin
    SBSha.InitializeSHA1(Sha);
    SBSha.HashSha1(Sha,  @Pass[0] , Length(Pass));
    SBSha.HashSha1(Sha,  @KeyStream[0] , Length(KeyStream));
    Dig := SBSha.FinalizeSha1(Sha);
    SBMove(Dig, keystream[0], 20);

    i := 0;
    while (i < Length(keystream)) and (count < Length(key)) do
    begin
      Encrypted[count + 20] := Byte(KeyStream[i] xor Key[count]);
      Inc(count);
      Inc(i);
    end;
  end;
  SBSha.InitializeSHA1(Sha);
  SBSha.HashSha1(Sha,  @Pass[0] , Length(Pass));
  SBSha.HashSha1(Sha,  @Key[0] , Length(Key));
  Dig := SBSha.FinalizeSha1(Sha);
  SBMove(Dig, Encrypted[Length(Encrypted) - 20], 20);
  result := true;

  ReleaseArray(Keystream);
end;

function TElJKS.LoadFromBuffer(Src_Ptr: Pointer; BufferSize: LongInt; var BufferPos: LongInt; const JKS_Pass: string): integer;
var
  Buffer, Tmp, Tmp1: ByteArray;
  Count, Count1, i: integer;
  Entry_Count, Entry_Num, S_Count: LongWord;
  Alias_Utf: String;
  IsPrivateKey: boolean;
  PKC: TElPKCS8EncryptedPrivateKeyInfo;
  Dig: TMessageDigest160;
  //Cert: TElX509Certificate;
  Cr_Date: Int64;
  T_Days, T_MSec: LongInt;
  Src_Buffer: ByteArray;
begin


  SetLength(Src_Buffer, BufferSize - BufferPos);
  SBMove(ByteArray(Src_Ptr^), Src_Buffer[0], BufferSize - BufferPos);

  SetLength(Buffer, 1024);
  SBSha.InitializeSHA1(FSha);
  Tmp := StringToUniBe(JKS_Pass);
  SBSha.HashSha1(FSha,  @Tmp[0] , Length(Tmp));
  ReleaseArray(Tmp);
  Tmp := BytesOfString('Mighty Aphrodite');
  SBSha.HashSha1(FSha,  @Tmp[0] , Length(Tmp));
  ReleaseArray(Tmp);

  Count := LoadFromBufferViaSha(Src_Buffer, BufferSize, BufferPos, Buffer  [0] , 4);
  if Count <> 4 then
  begin
    Result := E_JKS_READ_ERROR;
    exit;
  end;
  if (Buffer[0] <> $FE) or (Buffer[1] <> $ED) or (Buffer[2] <> $FE) or (Buffer[3] <> $ED) then
  begin
    Result := E_JKS_FORMAT_ERROR;
    exit;
  end;
  Count := LoadFromBufferViaSha(Src_Buffer, BufferSize, BufferPos, Buffer  [0] , 4);
  if Count <> 4 then
  begin
    Result := E_JKS_READ_ERROR;
    exit;
  end;
  if Buffer[3] <> 2 then
  begin
    Result := E_JKS_VERSION_ERROR;
    exit;
  end;
  Count := LoadFromBufferViaSha(Src_Buffer, BufferSize, BufferPos, Buffer  [0] , 4);
  if Count <> 4 then
  begin
    Result := E_JKS_READ_ERROR;
    exit;
  end;
  Entry_Count := BEData2Int(Buffer, 4);
  for Entry_Num := 1 to Entry_Count do
  begin
    inc(FEntries_Count);
    SetLength(FEntries, FEntries_Count);
    SetLength(FEntries[FEntries_Count - 1].Certificate_Chain, 0);
    SetLength(FEntries[FEntries_Count - 1].EncodedKey, 0);
    FEntries[FEntries_Count - 1].Alias := '';
    FEntries[FEntries_Count - 1].CreationDate :=  Now ;
    {$ifdef SB_WINDOWS}
    FEntries[FEntries_Count - 1].CreationDate := LocalTimeToUTCTime(FEntries[FEntries_Count - 1].CreationDate);
     {$endif}

    Count := LoadFromBufferViaSha(Src_Buffer, BufferSize, BufferPos, Buffer  [0] , 4);
    if Count <> 4 then
    begin
      Result := E_JKS_READ_ERROR;
      exit;
    end;

    IsPrivateKey := (BEData2Int(Buffer, 4) = 1);
    Count := LoadFromBufferViaSha(Src_Buffer, BufferSize, BufferPos, Buffer  [0] , 2);
    if Count <> 2 then
    begin
      Result := E_JKS_READ_ERROR;
      exit;
    end;
    Count1 := BEData2Int(Buffer, 2);
    SetLength(Tmp, Count1);
    Alias_Utf := '';
    Count := LoadFromBufferViaSha(Src_Buffer, BufferSize, BufferPos, Tmp  [0] , Count1);
    Alias_Utf := UTF8ToStr(Tmp);
    if Count <> Count1 then
    begin
      Result := E_JKS_READ_ERROR;
      exit;
    end;
    FEntries[FEntries_Count - 1].Alias := Alias_Utf;
    Count := LoadFromBufferViaSha(Src_Buffer, BufferSize, BufferPos, Buffer  [0] , 4);
    if Count <> 4 then
    begin
      Result := E_JKS_READ_ERROR;
      exit;
    end;
    Cr_Date := BEData2Int(Buffer, 4);
    Count := LoadFromBufferViaSha(Src_Buffer, BufferSize, BufferPos, Buffer  [0] , 4);
    if Count <> 4 then
    begin
      Result := E_JKS_READ_ERROR;
      exit;
    end;
    Cr_Date := (Cr_Date shl 32) + BEData2Int(Buffer, 4);
    T_Days := Cr_Date div MSecsPerDay;
    T_Msec := Cr_Date mod MSecsPerDay;
//                Ts:=MSecsToTimeStamp(Cr_Date);

    FEntries[FEntries_Count - 1].CreationDate := IncDay( EncodeDate (1970, 1, 1), T_Days);
    FEntries[FEntries_Count - 1].CreationDate := IncMilliSecond(FEntries[FEntries_Count - 1].CreationDate, T_MSec);
    if IsPrivateKey then
    begin
      Count := LoadFromBufferViaSha(Src_Buffer, BufferSize, BufferPos, Buffer  [0] , 4);
      if Count <> 4 then
      begin
        Result := E_JKS_READ_ERROR;
        exit;
      end;
      Count1 := BEData2Int(Buffer, 4);
      SetLength(Tmp, Count1);
      Count := LoadFromBufferViaSha(Src_Buffer, BufferSize, BufferPos, Tmp  [0] , Count1);
      if Count <> Count1 then
      begin
        Result := E_JKS_READ_ERROR;
        exit;
      end;

{                        Cert:=TElX509Certificate.Create(nil);
                        Cert.LoadKeyFromBuffer(Tmp,Count1);  }

      PKC := TElPKCS8EncryptedPrivateKeyInfo.Create;
      try

        if Pkc.LoadFromBuffer(Tmp, Count1) <> 0 then
        begin
          Result := E_JKS_KEY_FORMAT_ERROR;
          exit;
        end;

        SetLength(FEntries[FEntries_Count - 1].EncodedKey, 0);
        Setlength(FEntries[FEntries_Count - 1].EncodedKey, Length(Pkc.EncryptedData));
        SBMove(Pkc.EncryptedData[0], FEntries[FEntries_Count - 1].EncodedKey[0], Length(Pkc.EncryptedData));
      finally
        FreeAndNil(Pkc);
      end;
      Count := LoadFromBufferViaSha(Src_Buffer, BufferSize, BufferPos, Buffer  [0] , 4);
      if Count <> 4 then
      begin
        Result := E_JKS_READ_ERROR;
        exit;
      end;
      S_Count := BEData2Int(Buffer, 4);
      for i := 1 to S_Count do
      begin
        Count := Length(FEntries[FEntries_Count - 1].Certificate_Chain) + 1;
        SetLength(FEntries[FEntries_Count - 1].Certificate_Chain, Count);
        FEntries[FEntries_Count - 1].Certificate_Chain[Count - 1] := TElX509Certificate.Create(nil);
        Count1 := LoadCertFromBuffer(Src_Buffer, BufferSize, BufferPos, FEntries[FEntries_Count - 1].Certificate_Chain[Count - 1]);
        if Count1 <> 0 then
        begin
          Result := Count1;
          exit;
        end;
      end;
    end
    else
    begin
      SetLength(FEntries[FEntries_Count - 1].Certificate_Chain, 1);
      FEntries[FEntries_Count - 1].Certificate_Chain[0] := TElX509Certificate.Create(nil);
      Count := LoadCertFromBuffer(Src_Buffer, BufferSize, BufferPos, FEntries[FEntries_Count - 1].Certificate_Chain[0]);
      if Count <> 0 then
      begin
        Result := Count;
        exit;
      end;
    end;
  end;
  Dig := SBSha.FinalizeSha1(FSha);
  SetLength(Tmp1, 20);
  SetLength(Tmp, 20);
  SBMove(Dig, Tmp[0], 20);

  SetLength(Buffer, 20);
  Count := LoadFromBufferViaSha(Src_Buffer, BufferSize, BufferPos, Buffer  [0] , 20);
  if Count <> 20 then
  begin
    Result := E_JKS_READ_ERROR;
    exit;
  end;
  if (not FIgnoreBadStorageSignature) and (not CompareMem(Tmp, Buffer , 20 )) then
    Result := E_JKS_SIGNATURE
  else
    Result := 0;

  ReleaseArray(Buffer);
  ReleaseArray(Tmp);
  ReleaseArray(Tmp1);
end;

function TElJKS.LoadFromStream(Stream: TElInputStream; const JKS_Pass: string): integer;
var
  Buffer, Tmp, Tmp1: ByteArray;
  Count, Count1, i: integer;
  Entry_Count, Entry_Num, S_Count: LongWord;
  Alias_Utf: string;
  IsPrivateKey: boolean;
  PKC: TElPKCS8EncryptedPrivateKeyInfo;
  Dig: TMessageDigest160;
  //Cert: TElX509Certificate;
  Cr_Date: Int64;
  T_Days, T_MSec: LongInt;
begin
  

  SetLength(Buffer, 1024);

  SBSha.InitializeSHA1(FSha);

  Tmp := StringToUniBe(JKS_Pass);
  SBSha.HashSha1(FSha,  @Tmp[0] , Length(Tmp));
  ReleaseArray(Tmp);

  Tmp := BytesOfString('Mighty Aphrodite');
  SBSha.HashSha1(FSha,  @Tmp[0] , Length(Tmp));
  ReleaseArray(Tmp);

  Count := LoadFromStreamViaSha(Stream, Buffer  [0] , 4);
  if Count <> 4 then
  begin
    Result := E_JKS_READ_ERROR;
    exit;
  end;
  if (Buffer[0] <> $FE) or (Buffer[1] <> $ED) or (Buffer[2] <> $FE) or (Buffer[3] <> $ED) then
  begin
    Result := E_JKS_FORMAT_ERROR;
    exit;
  end;
  Count := LoadFromStreamViaSha(Stream, Buffer  [0] , 4);
  if Count <> 4 then
  begin
    Result := E_JKS_READ_ERROR;
    exit;
  end;
  if Buffer[3] <> 2 then
  begin
    Result := E_JKS_VERSION_ERROR;
    exit;
  end;
  Count := LoadFromStreamViaSha(Stream, Buffer  [0] , 4);
  if Count <> 4 then
  begin
    Result := E_JKS_READ_ERROR;
    exit;
  end;
  Entry_Count := BEData2Int(Buffer, 4);
  for Entry_Num := 1 to Entry_Count do
  begin
    inc(FEntries_Count);
    SetLength(FEntries, FEntries_Count);
    SetLength(FEntries[FEntries_Count - 1].Certificate_Chain, 0);
    SetLength(FEntries[FEntries_Count - 1].EncodedKey, 0);

    FEntries[FEntries_Count - 1].Alias := '';
    FEntries[FEntries_Count - 1].CreationDate :=  Now ;
    {$ifdef SB_WINDOWS}
    FEntries[FEntries_Count - 1].CreationDate := LocalTimeToUTCTime(FEntries[FEntries_Count - 1].CreationDate);
     {$endif}

    Count := LoadFromStreamViaSha(Stream, Buffer  [0] , 4);
    if Count <> 4 then
    begin
      Result := E_JKS_READ_ERROR;
      exit;
    end;

    IsPrivateKey := (BEData2Int(Buffer, 4) = 1);
    Count := LoadFromStreamViaSha(Stream, Buffer  [0] , 2);
    if Count <> 2 then
    begin
      Result := E_JKS_READ_ERROR;
      exit;
    end;
    Count1 := BEData2Int(Buffer, 2);
    SetLength(Tmp, Count1);
    Alias_Utf := '';
    Count := LoadFromStreamViaSha(Stream, Tmp  [0] , Count1);
    Alias_Utf := UTF8ToStr(Tmp);
    if Count <> Count1 then
    begin
      Result := E_JKS_READ_ERROR;
      exit;
    end;
    FEntries[FEntries_Count - 1].Alias := Alias_Utf;

    Count := LoadFromStreamViaSha(Stream, Buffer  [0] , 4);
    if Count <> 4 then
    begin
      Result := E_JKS_READ_ERROR;
      exit;
    end;
    Cr_Date := BEData2Int(Buffer, 4);
    Count := LoadFromStreamViaSha(Stream, Buffer  [0] , 4);
    if Count <> 4 then
    begin
      Result := E_JKS_READ_ERROR;
      exit;
    end;
    Cr_Date := (Cr_Date shl 32) + BEData2Int(Buffer, 4);
    T_Days := Cr_Date div MSecsPerDay;
    T_Msec := Cr_Date mod MSecsPerDay;
//                Ts:=MSecsToTimeStamp(Cr_Date);
    FEntries[FEntries_Count - 1].CreationDate := IncDay( EncodeDate (1970, 1, 1), T_Days);
    FEntries[FEntries_Count - 1].CreationDate := IncMilliSecond(FEntries[FEntries_Count - 1].CreationDate, T_MSec);

    if IsPrivateKey then
    begin
      Count := LoadFromStreamViaSha(Stream, Buffer  [0] , 4);
      if Count <> 4 then
      begin
        Result := E_JKS_READ_ERROR;
        exit;
      end;
      Count1 := BEData2Int(Buffer, 4);
      SetLength(Tmp, Count1);
      Count := LoadFromStreamViaSha(Stream, Tmp  [0] , Count1);
      if Count <> Count1 then
      begin
        Result := E_JKS_READ_ERROR;
        exit;
      end;

      PKC := TElPKCS8EncryptedPrivateKeyInfo.Create;
      try

        if Pkc.LoadFromBuffer(Tmp, Count1) <> 0 then
        begin
          Result := E_JKS_KEY_FORMAT_ERROR;
          exit;
        end;

        SetLength(FEntries[FEntries_Count - 1].EncodedKey, 0);
        Setlength(FEntries[FEntries_Count - 1].EncodedKey, Length(Pkc.EncryptedData));
        SBMove(Pkc.EncryptedData[0], FEntries[FEntries_Count - 1].EncodedKey[0], Length(Pkc.EncryptedData));
      finally
        FreeAndNil(Pkc);
      end;

      Count := LoadFromStreamViaSha(Stream, Buffer  [0] , 4);
      if Count <> 4 then
      begin
        Result := E_JKS_READ_ERROR;
        exit;
      end;
      S_Count := BEData2Int(Buffer, 4);
      for i := 1 to S_Count do
      begin
        Count := Length(FEntries[FEntries_Count - 1].Certificate_Chain) + 1;
        SetLength(FEntries[FEntries_Count - 1].Certificate_Chain, Count);
        FEntries[FEntries_Count - 1].Certificate_Chain[Count - 1] := TElX509Certificate.Create(nil);
        Count1 := LoadCertFromStream(Stream, FEntries[FEntries_Count - 1].Certificate_Chain[Count - 1]);
        if Count1 <> 0 then
        begin
          Result := Count1;
          exit;
        end;
      end;
    end
    else
    begin
      SetLength(FEntries[FEntries_Count - 1].Certificate_Chain, 1);
      FEntries[FEntries_Count - 1].Certificate_Chain[0] := TElX509Certificate.Create(nil);
      Count := LoadCertFromStream(Stream, FEntries[FEntries_Count - 1].Certificate_Chain[0]);
      if Count <> 0 then
      begin
        Result := Count;
        exit;
      end;
    end;
  end;
  Dig := SBSha.FinalizeSha1(FSha);
  SetLength(Tmp1, 20);

  SetLength(Tmp, 20);
  SBMove(Dig, Tmp[0], 20);

  SetLength(Buffer, 20);
  Count := LoadFromStreamViaSha(Stream, Buffer  [0] , 20);
  if Count <> 20 then
  begin
    Result := E_JKS_READ_ERROR;
    exit;
  end;
  if not CompareMem(Tmp, Buffer , 20 ) then
    Result := E_JKS_SIGNATURE
  else
    Result := 0;

end;

function TElJKS.GetSaveBufferSize: LongInt;
var
  Size: LongInt;
  Count1, i: integer;
  Entry_Num: LongWord;
  PKC: TElPKCS8EncryptedPrivateKeyInfo;
  St: ByteArray;
  Tmp: ByteArray;
begin
  try

  Size := 12;
  SetLength(Tmp, 0);

  for Entry_Num := 1 to FEntries_Count do
  begin
    if Length(FEntries[Entry_Num - 1].Alias) = 0 then
      Size := Size + Length('alias' + IntToStr( Int32 (Entry_Num)))
    else
      Size := Size + Length(FEntries[Entry_Num - 1].Alias);
    Size := Size + 14;
    if Length(FEntries[Entry_Num - 1].EncodedKey) <> 0 then
    begin
      Size := Size + 8;
      PKC := TElPKCS8EncryptedPrivateKeyInfo.Create;
      try
        Pkc.EncryptionAlgorithm := {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}CreateByteArrayConst( {$endif}#43#6#1#4#1#42#2#17#1#1{$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}) {$endif};
        Pkc.EncryptionAlgorithmParams := {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}CreateByteArrayConst( {$endif}#5#0{$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}) {$endif};
        St := {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}BytesOfString {$endif}('');
        Count1:=Length(FEntries[Entry_Num - 1].EncodedKey);

        SuffixByteArray(St, Count1 - Length(St), Byte(' '));
        (*
          for i := 1 to Count1 do
          St := SBConcatArrays(St, BytesOfString(' '));
         *)

        SBMove(FEntries[Entry_Num - 1].EncodedKey[0], St[0], Length(FEntries[Entry_Num - 1].EncodedKey));
        Pkc.EncryptedData := St;
        Count1 := Length(FEntries[Entry_Num - 1].EncodedKey) shl 1;
        SetLength(Tmp, Count1);
        Pkc.SaveToBuffer( @Tmp[0] , Count1);
        Size := Size + Count1;
      finally
        FreeAndNil(Pkc);
      end;
      for i := 1 to Length(FEntries[Entry_Num - 1].Certificate_Chain) do
        Size := Size + FEntries[Entry_Num - 1].Certificate_Chain[i - 1].CertificateSize + 11;
    end
    else
      Size := Size + FEntries[Entry_Num - 1].Certificate_Chain[0].CertificateSize + 11;
  end;
  Result := Size + 20;

  finally
    ReleaseArray(Tmp)
  end;
end;

function TElJKS.SaveToBuffer(var DstBuffer: ByteArray; BufferSize: LongInt; var BufferPos: LongInt; const JKS_Pass: string): integer;
var
  Buffer, Tmp, St{, Tmp1}: ByteArray;
  Count, Count1, i: integer;
  Entry_Num, S_Count: LongWord;
  PKC: TElPKCS8EncryptedPrivateKeyInfo;
  Dig: TMessageDigest160;
  Cr_Date: Int64;
  T_Days, T_Msec: Int64;

begin

  if (BufferSize - BufferPos) < GetSaveBufferSize then
  begin
    Result := E_JKS_NO_SPACE;
    exit;
  end;


  SetLength(Buffer, 1024);

  SBSha.InitializeSHA1(FSha);
  Tmp := StringToUniBe(JKS_Pass);
  SBSha.HashSha1(FSha,  @Tmp[0] , Length(Tmp));
  ReleaseArray(Tmp);
  Tmp := BytesOfString('Mighty Aphrodite');
  SBSha.HashSha1(FSha,  @Tmp[0] , Length(Tmp));
  ReleaseArray(Tmp);

  Buffer[0] := $FE;
  Buffer[1] := $ED;
  Buffer[2] := $FE;
  Buffer[3] := $ED;
  Count := SaveToBufferViaSha(Buffer  [0] , DstBuffer, BufferPos, 4);
  if Count <> 4 then
  begin
    Result := E_JKS_WRITE_ERROR;
    exit;
  end;
  Int2BEData(2, Buffer, 4); // Version
  Count := SaveToBufferViaSha(Buffer  [0] , DstBuffer, BufferPos, 4);
  if Count <> 4 then
  begin
    Result := E_JKS_WRITE_ERROR;
    exit;
  end;
  Int2BEData(FEntries_Count, Buffer, 4);
  Count := SaveToBufferViaSha(Buffer  [0] , DstBuffer, BufferPos, 4);
  if Count <> 4 then
  begin
    Result := E_JKS_WRITE_ERROR;
    exit;
  end;
  for Entry_Num := 1 to FEntries_Count do
  begin
    if Length(FEntries[Entry_Num - 1].EncodedKey) <> 0 then
      Int2BEData(1, Buffer, 4)
    else
      Int2BEData(2, Buffer, 4);
    Count := SaveToBufferViaSha(Buffer  [0] , DstBuffer, BufferPos, 4);
    if Count <> 4 then
    begin
      Result := E_JKS_WRITE_ERROR;
      exit;
    end;
    if Length(FEntries[Entry_Num - 1].Alias) = 0 then
      FEntries[Entry_Num - 1].Alias := 'alias' + IntToStr( Int32 (Entry_Num));
    Tmp := BytesOfString(FEntries[Entry_Num - 1].Alias);
    Int2BEData(Length(Tmp), Buffer, 2);
    Count := SaveToBufferViaSha(Buffer  [0] , DstBuffer, BufferPos, 2);
    if Count <> 2 then
    begin
      Result := E_JKS_WRITE_ERROR;
      exit;
    end;
    Count := SaveToBufferViaSha(Tmp  [0] , DstBuffer, BufferPos, Length(Tmp));
    if Count <> Length(Tmp) then
    begin
      Result := E_JKS_WRITE_ERROR;
      exit;
    end;

    T_Days := DaysBetween( EncodeDate (1970, 1, 1), FEntries[Entry_Num - 1].CreationDate);
    T_Msec := MilliSecondOfTheDay(FEntries[Entry_Num - 1].CreationDate);
    Cr_Date := T_Days * MSecsPerDay + T_Msec;
    Int2BEData(Cr_Date shr 32, Buffer, 4);
    Count := SaveToBufferViaSha(Buffer  [0] , DstBuffer, BufferPos, 4);
    if Count <> 4 then
    begin
      Result := E_JKS_WRITE_ERROR;
      exit;
    end;
    Int2BEData(Cr_Date and $FFFFFFFF, Buffer, 4);
    Count := SaveToBufferViaSha(Buffer  [0] , DstBuffer, BufferPos, 4);
    if Count <> 4 then
    begin
      Result := E_JKS_WRITE_ERROR;
      exit;
    end;

    if Length(FEntries[Entry_Num - 1].EncodedKey) <> 0 then
    begin
      PKC := TElPKCS8EncryptedPrivateKeyInfo.Create;
      try
        Pkc.EncryptionAlgorithm := CreateByteArrayConst(#43#6#1#4#1#42#2#17#1#1);
        Pkc.EncryptionAlgorithmParams := CreateByteArrayConst(#5#0);

        SetLength(St, Length(FEntries[Entry_Num - 1].EncodedKey));
        FillByteArray(St, byte(' '));

        SBMove(FEntries[Entry_Num - 1].EncodedKey, 0, St, 0, Length(FEntries[Entry_Num - 1].EncodedKey));

        Count1 := Length(FEntries[Entry_Num - 1].EncodedKey) shl 1;
        SetLength(Tmp, Count1);
        Pkc.SaveToBuffer( @Tmp[0] , Count1);

        Int2BEData(Count1, Buffer, 4);
        Count := SaveToBufferViaSha(Buffer  [0] , DstBuffer, BufferPos, 4);
        if Count <> 4 then
        begin
          Result := E_JKS_WRITE_ERROR;
          exit;
        end;
        Count := SaveToBufferViaSha(Tmp  [0] , DstBuffer, BufferPos, Count1);
        if Count <> Count1 then
        begin
          Result := E_JKS_WRITE_ERROR;
          exit;
        end;
      finally
        FreeAndNil(Pkc);
      end;

      S_Count := Length(FEntries[FEntries_Count - 1].Certificate_Chain);
      Int2BEData(S_Count, Buffer, 4);
      Count := SaveToBufferViaSha(Buffer  [0] , DstBuffer, BufferPos, 4);
      if Count <> 4 then
      begin
        Result := E_JKS_WRITE_ERROR;
        exit;
      end;
      for i := 1 to S_Count do
      begin
        Count1 := SaveCertToBuffer(FEntries[Entry_Num - 1].Certificate_Chain[i - 1], DstBuffer, BufferSize - BufferPos, BufferPos);
        if Count1 <> 0 then
        begin
          Result := Count1;
          exit;
        end;
      end;
    end
    else
    begin
      Count := SaveCertToBuffer(FEntries[Entry_Num - 1].Certificate_Chain[0], DstBuffer, BufferSize - BufferPos, BufferPos);
      if Count <> 0 then
      begin
        Result := Count;
        exit;
      end;
    end;
  end;
  Dig := SBSha.FinalizeSha1(FSha);
  SetLength(Tmp, 20);
  SBMove(Dig, Tmp[0], 20);
  Count := SaveToBufferViaSha(Tmp  [0] , DstBuffer, BufferPos, 20);
  if Count <> 20 then
    Result := E_JKS_WRITE_ERROR
  else
    Result := 0;

end;

function TElJKS.SaveToStream(Stream: TElOutputStream; const JKS_Pass: string): integer;
var
  Buffer, Tmp{, Tmp1}: ByteArray;
  Count, Count1, i: integer;
  Entry_Num, S_Count: LongWord;
  St: ByteArray;
  PKC: TElPKCS8EncryptedPrivateKeyInfo;
  Dig: TMessageDigest160;
  Cr_Date: Int64;
  T_Days, T_Msec: Int64;

begin
  

  SetLength(Buffer, 1024);

  SBSha.InitializeSHA1(FSha);
  Tmp := StringToUniBe(JKS_Pass);
  SBSha.HashSha1(FSha,  @Tmp[0] , Length(Tmp));
  ReleaseArray(Tmp);
  Tmp := BytesOfString('Mighty Aphrodite');
  SBSha.HashSha1(FSha,  @Tmp[0] , Length(Tmp));
  ReleaseArray(Tmp);

  Buffer[0] := $FE;
  Buffer[1] := $ED;
  Buffer[2] := $FE;
  Buffer[3] := $ED;
  Count := SaveToStreamViaSha(Stream, Buffer  [0] , 4);
  if Count <> 4 then
  begin
    Result := E_JKS_WRITE_ERROR;
    exit;
  end;
  Int2BEData(2, Buffer, 4); // Version
  Count := SaveToStreamViaSha(Stream, Buffer  [0] , 4);
  if Count <> 4 then
  begin
    Result := E_JKS_WRITE_ERROR;
    exit;
  end;
  Int2BEData(FEntries_Count, Buffer, 4);
  Count := SaveToStreamViaSha(Stream, Buffer  [0] , 4);
  if Count <> 4 then
  begin
    Result := E_JKS_WRITE_ERROR;
    exit;
  end;
  for Entry_Num := 1 to FEntries_Count do
  begin
    if Length(FEntries[Entry_Num - 1].EncodedKey) <> 0 then
      Int2BEData(1, Buffer, 4)
    else
      Int2BEData(0, Buffer, 4);
    Count := SaveToStreamViaSha(Stream, Buffer  [0] , 4);
    if Count <> 4 then
    begin
      Result := E_JKS_WRITE_ERROR;
      exit;
    end;
    if Length(FEntries[Entry_Num - 1].Alias) = 0 then
      FEntries[Entry_Num - 1].Alias := 'alias' + IntToStr( Int32 (Entry_Num));
    Tmp := BytesOfString(FEntries[Entry_Num - 1].Alias);
    Int2BEData(Length(Tmp), Buffer, 2);
    Count := SaveToStreamViaSha(Stream, Buffer  [0] , 2);
    if Count <> 2 then
    begin
      Result := E_JKS_WRITE_ERROR;
      exit;
    end;
    Count := SaveToStreamViaSha(Stream, Tmp  [0] , Length(Tmp));
    if Count <> Length(Tmp) then
    begin
      Result := E_JKS_WRITE_ERROR;
      exit;
    end;

    T_Days := DaysBetween( EncodeDate (1970, 1, 1), FEntries[Entry_Num - 1].CreationDate);
    T_Msec := MilliSecondOfTheDay(FEntries[Entry_Num - 1].CreationDate);
    Cr_Date := T_Days * MSecsPerDay + T_Msec;
    Int2BEData(Cr_Date shr 32, Buffer, 4);
    Count := SaveToStreamViaSha(Stream, Buffer  [0] , 4);
    if Count <> 4 then
    begin
      Result := E_JKS_WRITE_ERROR;
      exit;
    end;
    Int2BEData(Cr_Date and $FFFFFFFF, Buffer, 4);
    Count := SaveToStreamViaSha(Stream, Buffer  [0] , 4);
    if Count <> 4 then
    begin
      Result := E_JKS_WRITE_ERROR;
      exit;
    end;

    if Length(FEntries[Entry_Num - 1].EncodedKey) <> 0 then
    begin
      PKC := TElPKCS8EncryptedPrivateKeyInfo.Create;
      try
        Pkc.EncryptionAlgorithm := {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}CreateByteArrayConst( {$endif}#43#6#1#4#1#42#2#17#1#1{$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}) {$endif};
        Pkc.EncryptionAlgorithmParams := {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}CreateByteArrayConst( {$endif}#5#0{$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}) {$endif};
        		
        SetLength(St, Length(FEntries[Entry_Num - 1].EncodedKey));
        FillByteArray(St, byte(' '));

        SBMove(FEntries[FEntries_Count - 1].EncodedKey[0], St[0], Length(FEntries[Entry_Num - 1].EncodedKey));
        Pkc.EncryptedData := St;
        Count1 := Length(FEntries[Entry_Num - 1].EncodedKey) shl 1;
        SetLength(Tmp, Count1);
        Pkc.SaveToBuffer( @Tmp[0] , Count1);

        Int2BEData(Count1, Buffer, 4);
        Count := SaveToStreamViaSha(Stream, Buffer  [0] , 4);
        if Count <> 4 then
        begin
          Result := E_JKS_WRITE_ERROR;
          exit;
        end;
        Count := SaveToStreamViaSha(Stream, Tmp  [0] , Count1);
        if Count <> Count1 then
        begin
          Result := E_JKS_WRITE_ERROR;
          exit;
        end;
      finally
        FreeAndNil(Pkc);
      end;

      S_Count := Length(FEntries[FEntries_Count - 1].Certificate_Chain);
      Int2BEData(S_Count, Buffer, 4);
      Count := SaveToStreamViaSha(Stream, Buffer  [0] , 4);
      if Count <> 4 then
      begin
        Result := E_JKS_WRITE_ERROR;
        exit;
      end;
      for i := 1 to S_Count do
      begin
        Count1 := SaveCertToStream(Stream, FEntries[Entry_Num - 1].Certificate_Chain[i - 1]);
        if Count1 <> 0 then
        begin
          Result := Count1;
          exit;
        end;
      end;
    end
    else
    begin
      Count := SaveCertToStream(Stream, FEntries[Entry_Num - 1].Certificate_Chain[0]);
      if Count <> 0 then
      begin
        Result := Count;
        exit;
      end;
    end;
  end;
  Dig := SBSha.FinalizeSha1(FSha);
  SetLength(Tmp, 20);
  SBMove(Dig, Tmp[0], 20);
  Count := SaveToStreamViaSha(Stream, Tmp  [0] , 20);
  if Count <> 20 then
    Result := E_JKS_WRITE_ERROR
  else
    Result := 0;

end;

end.


