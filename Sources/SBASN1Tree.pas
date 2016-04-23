(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBASN1Tree;

interface

uses
  Classes,
  SBStreams,
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBConstants,
  SBASN1;


const
  SB_ASN1_BOOLEAN               = 1;
  SB_ASN1_INTEGER               = 2;
  SB_ASN1_BITSTRING             = 3;
  SB_ASN1_OCTETSTRING           = 4;
  SB_ASN1_NULL                  = 5;
  SB_ASN1_OBJECT                = 6;
  SB_ASN1_REAL                  = 9;
  SB_ASN1_ENUMERATED            = 10;
  SB_ASN1_UTF8STRING            = 12;
  SB_ASN1_NUMERICSTR            = 18;
  SB_ASN1_PRINTABLESTRING       = 19;
  SB_ASN1_T61STRING             = 20;
  SB_ASN1_TELETEXSTRING         = 20;
  SB_ASN1_VIDEOTEXSTRING        = 21;
  SB_ASN1_IA5STRING             = 22;
  SB_ASN1_UTCTIME               = 23;
  SB_ASN1_GENERALIZEDTIME       = 24;
  SB_ASN1_GRAPHICSTRING         = 25;
  SB_ASN1_VISIBLESTRING         = 26;
  SB_ASN1_GENERALSTRING         = 27;
  SB_ASN1_UNIVERSALSTRING       = 28;
  SB_ASN1_BMPSTRING             = 30;
  SB_ASN1_SEQUENCE              = $30;
  SB_ASN1_SET                   = $31;
  SB_ASN1_A0_PRIMITIVE          = $80;
  SB_ASN1_A0                    = $A0;
  SB_ASN1_A1_PRIMITIVE          = $81;
  SB_ASN1_A1                    = $A1;
  SB_ASN1_A2_PRIMITIVE          = $82;
  SB_ASN1_A2                    = $A2;
  SB_ASN1_A3_PRIMITIVE          = $83;
  SB_ASN1_A3                    = $A3;
  SB_ASN1_A4_PRIMITIVE          = $84;
  SB_ASN1_A4                    = $A4;
  SB_ASN1_A5_PRIMITIVE          = $85;
  SB_ASN1_A5                    = $A5;
  SB_ASN1_A6_PRIMITIVE          = $86;
  SB_ASN1_A6                    = $A6;
  SB_ASN1_A7_PRIMITIVE          = $87;
  SB_ASN1_A7                    = $A7;
  SB_ASN1_A8_PRIMITIVE          = $88;
  SB_ASN1_A8                    = $A8;
  SB_ASN1_A9_PRIMITIVE          = $89;
  SB_ASN1_A9                    = $A9;

  SB_ASN1_CONSTRAINED_FLAG      = $20;

type
  TElASN1CustomTag = class{$ifdef SB_HAS_MEMORY_MANAGER}(TElIManagedObject) {$endif}
  protected
    FTagId : byte;
    FWriteHeader : boolean;

    function GetConstrained : boolean; virtual;
    function GetTagNum : byte;

  protected
    //Parent : TElASN1CustomTag;
    FUndefSize : boolean;
    FTagOffset : Int64;
    FTagSize : Int64;
    FTagHeaderSize : integer;
    FTagContentSize : Int64;
    FDepth : integer;
    function GetEncodedLen : Int64; virtual;
    function ComposeHeader(Len : Int64) : ByteArray;
    function UnknownSize : boolean; virtual;
  public
    constructor Create;
    
    {$ifdef SB_HAS_MEMORY_MANAGER}
    procedure Reset; virtual;
     {$endif}

    function LoadFromBuffer(Buffer : pointer; Size : integer) : boolean; virtual;
    function SaveToBuffer(Buffer : pointer; var Size : integer) : boolean; virtual;
    function CheckType(TagId: byte; Constrained: boolean) : boolean;
  
    function LoadFromStream(Stream: TElStream; Count : Int64  =  0): boolean; virtual;
    procedure SaveToStream(Stream: TElStream); virtual;
  
    property TagId : byte read FTagId write FTagId;
    property UndefSize : boolean read FUndefSize write FUndefSize;
    property WriteHeader : boolean read FWriteHeader write FWriteHeader;
    property IsConstrained : boolean read GetConstrained;
    property TagNum : byte read GetTagNum;
    property TagOffset : Int64 read FTagOffset;
    property TagSize : Int64 read FTagSize;
    property TagHeaderSize : integer read FTagHeaderSize;
    property TagContentSize : Int64 read FTagContentSize;
    property Depth : integer read FDepth;
  end;

  TSBASN1DataSourceType = (dstBuffer, dstStream, dstVirtual);

  TSBASN1VirtualDataNeededEvent = procedure(Sender: TObject;
    StartIndex: Int64; Buffer : pointer; MaxSize : integer; var Read: integer) of object;

  TElASN1DataSource = class
  protected
    FContentStream : TElStream;
    FContentOffset : Int64;
    FContentSize : Int64;
    FContent : ByteArray;
    FUnknownSize : boolean;
    FSourceType : TSBASN1DataSourceType;
    FOnVirtualDataNeeded : TSBASN1VirtualDataNeededEvent;
    FSkipVirtualData : boolean;
    function GetSize : Int64;
  public
     destructor  Destroy; override;

    procedure Init(const Value : ByteArray);  overload; 

    procedure Init(Stream: TElStream;
      Offset: Int64; Size: Int64);  overload; 
    procedure Init(Stream: TElStream;
      UnknownSize : boolean);  overload; 

    procedure Init(Buffer: pointer; Size: integer);  overload; 
    procedure InitVirtual(Size : Int64);
    function Read(Buffer: pointer; Size: integer; Offset: Int64): integer;
    procedure Clone(Dest : TElASN1DataSource);
    procedure CloneVirtual(Dest : TElASN1DataSource);
    function ToBuffer: ByteArray;
    property Size : Int64 read GetSize;
    property UnknownSize : boolean read FUnknownSize;
    property SkipVirtualData : boolean read FSkipVirtualData write FSkipVirtualData;
    property SourceType : TSBASN1DataSourceType read FSourceType;
    property OnVirtualDataNeeded : TSBASN1VirtualDataNeededEvent read FOnVirtualDataNeeded
      write FOnVirtualDataNeeded;
  end;

{,$hints off}
  TElASN1SimpleTag = class(TElASN1CustomTag)
  protected

    function SaveToBufferUndefSize(Buffer : Pointer; var Size : Integer) : Boolean;
    function GetConstrained : boolean; override;

    procedure SetContent(const Value : ByteArray);
    function GetContent: ByteArray;
    function UnknownSize : boolean; override;

  protected
    FDataSource : TElASN1DataSource;
    FFragmentSize : integer;
    FOnContentWriteBegin : TNotifyEvent;
    FOnContentWriteEnd : TNotifyEvent;
    function GetEncodedLen : Int64; override;
  public
    constructor Create;
     destructor  Destroy; override;
    
    class function CreateInstance: TElASN1SimpleTag; 
    {$ifdef SB_HAS_MEMORY_MANAGER}
    procedure Reset; override;
     {$endif}

    function LoadFromBuffer(Buffer : pointer; Size : integer) : boolean; override;
    function SaveToBuffer(Buffer : pointer; var Size : integer) : boolean; override;
  
    function LoadFromStream(Stream: TElStream; Count : Int64  =  0): boolean; override;
    procedure SaveToStream(Stream: TElStream); override;

    property Content : ByteArray read GetContent write SetContent;
    property DataSource : TElASN1DataSource read FDataSource;
    property FragmentSize : integer read FFragmentSize write FFragmentSize;
    property OnContentWriteBegin : TNotifyEvent read FOnContentWriteBegin
      write FOnContentWriteBegin;
    property OnContentWriteEnd : TNotifyEvent read FOnContentWriteEnd
      write FOnContentWriteEnd;
  end;

  TSBASN1StreamAccess = (saStoreStream);
  
  TElASN1ConstrainedTag = class(TElASN1CustomTag)
  protected
    FList  : TElList;
    FStack : TElList;

    FBuffer: ^byte;
    FBufferSize : integer;

    FCurrBufferIndex : Int64;
    FSingleLoad : boolean;
    FDataProcessed : boolean;
    FSizeLeft : Int64;
    FLastHeaderLen : integer;
    //FLastUndefLen : boolean;
    FInputStream : TElStream;
    FMaxStreamPos : Int64;
    FMaxSimpleTagLength : integer;
    FStreamAccess : TSBASN1StreamAccess;
    
    procedure ClearList;
    function GetCount : integer;

    function SaveToBufferUndefSize(Buffer : Pointer; var Size : Integer) : Boolean;
    function GetConstrained : boolean; override;
    function GetByteFromStream(Stream: TElStream;
      Offset: Int64): byte;
    function UnknownSize : boolean; override;
    
    procedure HandleASN1Read(Sender : TObject; Buffer : pointer; var Size : longint);
    procedure HandleASN1ReadStream(Sender : TObject; Buffer : pointer; var Size : longint);
    procedure HandleASN1Tag(Sender : TObject; TagType: asn1TagType; TagConstrained: boolean;
      Tag: pointer; TagSize: integer; Size: Int64; Data: pointer; BitRest: integer;
      var Valid : boolean);
    procedure HandleASN1TagHeader(Sender: TObject; TagID : byte; TagLen : Int64;
      HeaderLen : integer; UndefLen : boolean);
    procedure HandleASN1Skip(Sender: TObject; var Count: Int64);
    procedure HandleASN1SkipStream(Sender: TObject; var Count: Int64);
      // SB_JAVA
          
  protected
    function GetEncodedLen : Int64; override;
  public
    constructor Create;
     destructor  Destroy; override;
    
    class function CreateInstance: TElASN1ConstrainedTag; 
    {$ifdef SB_HAS_MEMORY_MANAGER}
    procedure Reset; override;
     {$endif}

    function LoadFromBuffer(Buffer : pointer; Size : integer) : boolean; override;
    function LoadFromBufferSingle(Buffer: pointer; Size: integer) : integer;
    function SaveToBuffer(Buffer : pointer; var Size : integer) : boolean; override;
    function SaveContentToBuffer(Buffer : pointer; var Size : integer) : boolean;
  
    function LoadFromStream(Stream: TElStream; Count : Int64  =  0): boolean; override;
    function LoadFromStreamSingle(Stream: TElStream; Count : Int64  =  0): boolean;
    procedure SaveToStream(Stream: TElStream); override;
  
    function AddField(Constrained : boolean) : integer;
    function RemoveField(Index : integer) : boolean;
    function GetField(Index : integer) : TElASN1CustomTag;
    procedure Clear;
    property Count : integer read GetCount;
    property MaxSimpleTagLength : integer read FMaxSimpleTagLength write FMaxSimpleTagLength;
    property StreamAccess : TSBASN1StreamAccess read FStreamAccess write FStreamAccess;
  end;
{.$hints on}


procedure asymWriteInteger(Tag : TElASN1SimpleTag; Buffer : pointer; Size : integer);

function ASN1ReadInteger(Tag: TElASN1SimpleTag): integer; 
function ASN1ReadInteger64(Tag: TElASN1SimpleTag): Int64; 
procedure ASN1WriteInteger(Tag: TElASN1SimpleTag; Value: integer); 
procedure ASN1WriteInteger64(Tag: TElASN1SimpleTag; Value: Int64); 
function ASN1ReadSimpleValue(const Data : ByteArray; var TagID : integer): ByteArray; 
function ASN1WriteTagAndLength(Tag: integer; Len : Int64): ByteArray; 
function ASN1ReadBoolean(Tag: TElASN1SimpleTag): boolean; 
procedure ASN1WriteBoolean(Tag: TElASN1SimpleTag; Value: boolean); 

function ASN1ReadString(const Data : ByteArray; TagId : integer): UnicodeString;

function FormatAttributeValue(TagID : integer; const Value : ByteArray) : ByteArray; 
function UnformatAttributeValue(const Value : ByteArray; out TagID : integer) : ByteArray; 

var
  G_MaxASN1TreeDepth : integer  =  256;
  G_MaxASN1BufferLength : integer  =  33554432; // 32 MBytes

implementation

uses
  SysUtils;

resourcestring
//  SCannotSetContent = 'Cannot set content if DataSource is set';
  SEndOfStream = 'End of stream reached';
  SMaxTreeDepthExceeded = 'Max ASN.1 tree depth exceeded';
  SUnsupportedOperationRead = 'Unsupported operation: read';
//  SDataNotLoaded = 'Data not loaded';

{$O-}


////////////////////////////////////////////////////////////////////////////////
// TElASN1CustomTag

constructor TElASN1CustomTag.Create;
begin
  inherited;
  //FUndefSize := false;
  FWriteHeader := true;
  FDepth := 0;
  //Parent := nil;
end;

{$ifdef SB_HAS_MEMORY_MANAGER}
procedure TElASN1CustomTag.Reset;
begin
  FWriteHeader := true;
  FDepth := 0;
  
  FTagId := 0;
  FUndefSize := false;
  FTagOffset := 0;
  FTagSize := 0;
  FTagHeaderSize := 0;
  FTagContentSize := 0;
end;
 {$endif}

function TElASN1CustomTag.LoadFromBuffer(Buffer : pointer; Size : integer) : boolean;
begin
  Result := false;
end;


function TElASN1CustomTag.SaveToBuffer(Buffer : Pointer; var Size : Integer) : Boolean;
begin
  Result := false;
end;



function TElASN1CustomTag.GetConstrained : boolean;
begin
  Result := false;
end;

function TElASN1CustomTag.UnknownSize : boolean;
begin
  Result := false;
end;

function TElASN1CustomTag.GetTagNum : byte;
begin
  Result := FTagID and $1F;
end;

function TElASN1CustomTag.CheckType(TagId: byte; Constrained: boolean) : boolean;
begin
  Result := (FTagID = TagID) and (Constrained = IsConstrained);
end;

function TElASN1CustomTag.LoadFromStream(Stream: TElStream; Count : Int64  =  0): boolean;
begin
  Result := false;
end;

procedure TElASN1CustomTag.SaveToStream(Stream: TElStream);
begin
  ;
end;

function TElASN1CustomTag.GetEncodedLen : Int64;
begin
  Result := 0;
end;

function TElASN1CustomTag.ComposeHeader(Len : Int64) : ByteArray;
var
  HLen, Tmp : Int64;
  HeaderBuf : ByteArray;
  I : integer;
begin

  if (Len <= 127) then
    HLen := 1
  else
  begin
    HLen := 1;
    Tmp := Len;
    while (Tmp > 0) do
    begin
      Tmp := Tmp shr 8;
      Inc(HLen);
    end;
  end;
  SetLength(HeaderBuf, HLen + 1);
  HeaderBuf[0] := TagID;
  if HLen = 1 then
    HeaderBuf[1] := Len
  else
  begin
    HeaderBuf[1] := $80 + HLen - 1;
    for I := 2 to HLen do
      HeaderBuf[I] := Len shr ((HLen - I) shl 3) and $FF
  end;
  Result := CloneArray(HeaderBuf);

end;

////////////////////////////////////////////////////////////////////////////////
// TElASN1SimpleTag

constructor TElASN1SimpleTag.Create;
begin
  inherited;

  FFragmentSize := 0;
  FDataSource := TElASN1DataSource.Create;
end;

 destructor  TElASN1SimpleTag.Destroy;
begin
  FreeAndNil(FDataSource);
  inherited;
end;

class function TElASN1SimpleTag.CreateInstance: TElASN1SimpleTag;
begin
  {$ifdef SB_HAS_MEMORY_MANAGER}
  Result := TElASN1SimpleTag(MemoryManager.AcquireObject(JLClass(TElASN1SimpleTag)));
   {$else}
  Result := TElASN1SimpleTag.Create;
   {$endif}
end;

procedure TElASN1SimpleTag.SetContent(const Value : ByteArray);
begin
  FDataSource.Init(Value);
end;

function TElASN1SimpleTag.GetContent: ByteArray;
begin
  Result := FDataSource.ToBuffer;
end;

function TElASN1SimpleTag.UnknownSize: boolean;
begin
  Result := FDataSource.UnknownSize;
end;

function TElASN1SimpleTag.LoadFromBuffer(Buffer : pointer; Size : integer) : boolean;
begin
  Result := false;
end;

function TElASN1SimpleTag.SaveToBuffer(Buffer : Pointer; var Size : Integer) : Boolean;
var
  HLen, Len, I : integer;
  Cnt : ByteArray;
  CntSize, WrittenSize : integer;
begin
  if UnknownSize then
  begin
    Cnt := GetContent;
    CntSize := Length(Cnt)
  end
  else
    CntSize := FDataSource.Size;

  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  try
   {$endif}
  if (not FWriteHeader) then
  begin
    if (Size < CntSize{Length(Cnt)}) then
    begin
      Size := CntSize{Length(Cnt)};
      Result := false;
      Exit;
    end
    else
    begin
      if Length(Cnt) = 0 then
        Cnt := GetContent;
      Size := Min(Length(Cnt), Size){Length(Cnt)};
      if (Size > 0) then
        SBMove(Cnt[0], Buffer^, Min(Length(Cnt), Size));
      Result := true;
      Exit;
    end;
  end
  else
  if FUndefSize then
  begin
    Result := SaveToBufferUndefSize(Buffer, Size);
    Exit;
  end;
  Len := CntSize{Length(Cnt)};
  if (Len <= 127) then
    HLen := 1
  else
  begin
    HLen := 1;
    while(Len > 0) do
    begin
      Len := Len shr 8;
      Inc(HLen);
    end;
  end;
  if (1 + HLen + CntSize{Length(Cnt)} > Size) then
  begin
    Size := 1 + HLen + CntSize{Length(Cnt)};
    Result := false;
    Exit;
  end
  else
  begin
    PByte(Buffer)^ := FTagId;
    if (HLen = 1) then
      PByteArray(Buffer)[1] := CntSize{Length(Cnt)}
    else
    begin
      PByteArray(Buffer)[1] := $80 + HLen - 1;
      for I := 2 to HLen do
        PByteArray(Buffer)[I] := CntSize{Length(Cnt)} shr ((HLen - I) shl 3) and $FF
    end;
    if Length(Cnt) = 0 then
      Cnt := GetContent();
    WrittenSize := Min(Length(Cnt), CntSize);
    if WrittenSize > 0 then
      SBMove(Cnt[0], PByteArray(Buffer)[HLen + 1], WrittenSize);
    Size := WrittenSize{Length(Cnt)} + HLen + 1;
    Result := true;
  end;
  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  finally
    ReleaseArray(Cnt);
  end;
   {$endif}
end;


{$ifdef SB_HAS_MEMORY_MANAGER}
procedure TElASN1SimpleTag.Reset;
begin
  inherited;
  
  FreeAndNil(FDataSource);
  
  FFragmentSize := 0;
  FDataSource := TElASN1DataSource.Create;
  FOnContentWriteBegin := nil;
  FOnContentWriteEnd := nil;
end;
 {$endif}

function TElASN1SimpleTag.SaveToBufferUndefSize(Buffer : Pointer; var Size : Integer) : Boolean;
var
  Cnt : ByteArray;
  CntSize, WrittenSize : integer;
begin
  if UnknownSize then
  begin
    Cnt := GetContent;
    CntSize := Length(Cnt)
  end
  else
    CntSize := FDataSource.Size;
  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  try
   {$endif}
  if (4 + CntSize{Length(Cnt)} > Size) then
  begin
    Size := 4 + CntSize{Length(Cnt)};
    Result := false;
  end
  else
  begin
    Cnt := GetContent();
    PByteArray(Buffer)[0] := FTagId;
    PByteArray(Buffer)[1] := $80;
    WrittenSize := Min(CntSize, Length(Cnt));
    if WrittenSize > 0 then
      SBMove(Cnt[0], PByteArray(Buffer)[2], WrittenSize);
    PByteArray(Buffer)[2 + CntSize{Length(Cnt)}] := 0;
    PByteArray(Buffer)[3 + CntSize{Length(Cnt)}] := 0;
    Result := true;
    Size := WrittenSize{Length(Cnt)} + 4;
  end;
  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  finally
    ReleaseArray(Cnt);
  end;
   {$endif}
end;

function TElASN1SimpleTag.GetEncodedLen : Int64;
var
  Len, HLen : Int64;
  DataLen : Int64;
begin
  DataLen := FDataSource.Size;
  if (not FWriteHeader) then
    Result := DataLen
  else if FUndefSize then
    Result := DataLen + 4
  else
  begin
    Len := DataLen;
    if (Len <= 127) then
      HLen := 1
    else
    begin
      HLen := 1;
      while(Len > 0) do
      begin
        Len := Len shr 8;
        Inc(HLen);
      end;
    end;
    Result := 1 + HLen + DataLen;
  end;
end;

function TElASN1SimpleTag.GetConstrained : boolean;
begin
  Result := false;
end;

function TElASN1SimpleTag.LoadFromStream(Stream: TElStream;
  Count : Int64  =  0): boolean;
begin
  Result := false;
end;

procedure TElASN1SimpleTag.SaveToStream(Stream: TElStream);
const
  CHUNK_SIZE : integer = 32768;
var
  Len, Read : Int64;
  HeaderBuf : ByteArray;
  Chunk : array of byte;
  Offset : Int64;
begin

  if UnknownSize or (FragmentSize > 0) then
  begin
    Offset := Stream.Position;
    Len := 0;

    if FFragmentSize <= 0 then
    begin
      { writing 4-byte length }
      SetLength(Chunk, CHUNK_SIZE);
      SetLength(HeaderBuf, 6);
      HeaderBuf[0] := TagId;
      HeaderBuf[1] := $84;
      Stream.Write(HeaderBuf[0], Length(HeaderBuf));
    end
    else
    begin
      SetLength(Chunk, FFragmentSize);

      if (FTagId and SB_ASN1_CONSTRAINED_FLAG) <> 0 then
      begin
        SetLength(HeaderBuf, 2);
        HeaderBuf[0] := FTagId;
        HeaderBuf[1] := $80;
        Stream.Write(HeaderBuf[0], Length(HeaderBuf));
      end;
    end;

    if Assigned(FOnContentWriteBegin) then
      FOnContentWriteBegin(Self);

    repeat
      Read := FDataSource.Read(@Chunk[0], Length(Chunk), 0);
      Len := Len + Read;

      if Read > 0 then
      begin
        if FFragmentSize > 0 then
        begin
          if (FTagId and SB_ASN1_CONSTRAINED_FLAG) <> 0 then
          begin
            FTagId := FTagId and (not SB_ASN1_CONSTRAINED_FLAG);
            HeaderBuf := ComposeHeader(Read);
            FTagId := FTagId or SB_ASN1_CONSTRAINED_FLAG;
          end
          else
            HeaderBuf := ComposeHeader(Read);
          Stream.Write(HeaderBuf[0], Length(HeaderBuf));
        end;

        Stream.Write(Chunk[0], Read);
      end;
    until Read = 0;

    if Assigned(FOnContentWriteEnd) then
      FOnContentWriteEnd(Self);

    if FFragmentSize <= 0 then
    begin
      Stream.Seek(Offset,  soFromBeginning );

      GetBytes32(Len, HeaderBuf, 2);

      Stream.Write(HeaderBuf[0], Length(HeaderBuf));

      Stream.Seek(Offset + 6 + Len,  soFromBeginning );
    end
    else
    begin
      if (FTagId and SB_ASN1_CONSTRAINED_FLAG) <> 0 then
      begin
        SetLength(HeaderBuf, 2);
        HeaderBuf[0] := 0;
        HeaderBuf[1] := 0;
        Stream.Write(HeaderBuf[0], Length(HeaderBuf));
      end;
    end;

    Exit;
  end;

  Len := FDataSource.Size;
  // writing header
  if FWriteHeader then
  begin
    if FUndefSize then
    begin
      SetLength(HeaderBuf, 2);
      HeaderBuf[0] := TagID;
      HeaderBuf[1] := $80;
    end
    else
      HeaderBuf := ComposeHeader(Len);
    Stream.Write(HeaderBuf[0], Length(HeaderBuf));
  end;

  if Assigned(FOnContentWriteBegin) then
    FOnContentWriteBegin(Self);

  // writing tag data
  if not ((FDataSource.SourceType = dstVirtual) and (FDataSource.SkipVirtualData)) then
  begin
    Offset := 0;
    SetLength(Chunk, CHUNK_SIZE);
    while Offset < Len do
    begin
      Read := FDataSource.Read(@Chunk[0], Min(CHUNK_SIZE, Len - Offset), Offset);
      Stream.Write(Chunk[0], Read);
      Inc(Offset, Read);
    end;
  end;

  if Assigned(FOnContentWriteBegin) then
    FOnContentWriteEnd(Self);

  // writing trailer for undefined sized tags
  if FWriteHeader and FUndefSize then
  begin
    SetLength(HeaderBuf, 2);
    HeaderBuf[0] := 0;
    HeaderBuf[1] := 0;
    Stream.Write(HeaderBuf[0], 2);
  end;

end;

////////////////////////////////////////////////////////////////////////////////
// TElASN1ConstrainedTag

constructor TElASN1ConstrainedTag.Create;
begin
  inherited;
  FList := TElList.Create;
  FStack := TElList.Create;
  //FMaxSimpleTagLength := 0;
  FStreamAccess := saStoreStream;
end;

 destructor  TElASN1ConstrainedTag.Destroy;
var
  P : TElASN1CustomTag;
  i : integer;
begin
  for i := 0 to FList.Count - 1 do
  begin
    P := TElASN1CustomTag(FList[i]);
    FreeAndNil(P);
  end;
  
  FreeAndNil(FList);
  FreeAndNil(FStack);
  inherited;
end;

class function TElASN1ConstrainedTag.CreateInstance: TElASN1ConstrainedTag;
begin
  {$ifdef SB_HAS_MEMORY_MANAGER}
  Result := TElASN1ConstrainedTag(MemoryManager.AcquireObject(JLClass(TElASN1ConstrainedTag)));
   {$else}
  Result := TElASN1ConstrainedTag.Create;
   {$endif}
end;

{$ifdef SB_HAS_MEMORY_MANAGER}
procedure TElASN1ConstrainedTag.Reset;
var
  P : TElASN1CustomTag;
  i : integer;
begin
  inherited;

  for i := 0 to FList.Count - 1 do
  begin
    P := TElASN1CustomTag(FList[i]);
    FreeAndNil(P);
  end;

  FList.clear();
  FStack.clear();
  ReleaseArray(FBuffer);
  FBuffer := nil;
  FInputStream := nil;
  
  FStreamAccess := TSBASN1StreamAccess.saStoreStream;
  FCurrBufferIndex := 0;
  FSingleLoad := false;
  FDataProcessed := false;
  FSizeLeft := 0;
  FLastHeaderLen := 0;
  FMaxStreamPos := 0;
  FMaxSimpleTagLength := 0;
end;
 {$endif}

procedure TElASN1ConstrainedTag.ClearList;
var
  P : TElASN1CustomTag;
begin
  while FList.Count > 0 do
  begin
    P := TElASN1CustomTag(FList[0]);
    FList. Delete (0);
    FreeAndNil(P);
  end;
end;


function TElASN1ConstrainedTag.LoadFromBuffer(Buffer : pointer; Size : integer) : boolean;
var
  ASN1Parser : TElASN1Parser;
begin
  // DoS attack prevention
  if  Size  > G_MaxASN1BufferLength then
  begin
    Result := false;
    Exit;
  end;
  FSingleLoad := false;
  FDataProcessed := false;
  ASN1Parser :=  TElASN1Parser.Create ;
  try
    FInputStream := nil;

    ASN1Parser.OnRead := HandleASN1Read;
    ASN1Parser.OnTag := HandleASN1Tag;
    ASN1Parser.OnTagHeader := HandleASN1TagHeader;
    ASN1Parser.OnSkip := HandleASN1Skip;

    ASN1Parser.RaiseOnEOC := true;
    ASN1Parser.MaxSimpleTagLength := FMaxSimpleTagLength;
    GetMem(FBuffer, Size);
    SBMove(Buffer^, FBuffer^, Size);
    FBufferSize := Size;
    ASN1Parser.MaxDataLength := FBufferSize;
    FCurrBufferIndex := 0;
    Result := true;
    try
      ASN1Parser.Parse;
    except
      Result := false;
    end;
    FreeMem(FBuffer);
  finally
    FreeAndNil(ASN1Parser);
  end;
end;

function TElASN1ConstrainedTag.LoadFromBufferSingle(Buffer: pointer; Size: integer) : integer;
var
  ASN1Parser : TElASN1Parser;
begin
  // DoS attack prevention
  if  Size  > G_MaxASN1BufferLength then
  begin
    Result := -1;
    Exit;
  end;
  FSingleLoad := true;
  FDataProcessed := false;
  FInputStream := nil;
  ASN1Parser :=  TElASN1Parser.Create ;
  try
    ASN1Parser.OnRead := HandleASN1Read;
    ASN1Parser.OnTag := HandleASN1Tag;
    ASN1Parser.OnTagHeader := HandleASN1TagHeader;
    ASN1Parser.OnSkip := HandleASN1Skip;

    ASN1Parser.RaiseOnEOC := true;
    ASN1Parser.MaxSimpleTagLength := FMaxSimpleTagLength;
    GetMem(FBuffer, Size);
    SBMove(Buffer^, FBuffer^, Size);
    FBufferSize := Size;
    ASN1Parser.MaxDataLength := FBufferSize;
    FCurrBufferIndex := 0;
    try
      ASN1Parser.Parse;
      Result := FCurrBufferIndex;
    except
      Result := -1;
    end;
    FreeMem(FBuffer);
  finally
    FreeAndNil(ASN1Parser);
  end;
end;


function TElASN1ConstrainedTag.SaveToBuffer(Buffer : Pointer; var Size : Integer) : Boolean;
var
  I, Len, HLen, Tmp : integer;
begin
  
  Tmp := 0;
  if (not FWriteHeader) then
  begin
    Len := 0;
    for I := 0 to FList.Count - 1 do
    begin
      Tmp := 0;
      TElASN1CustomTag(FList[I]).SaveToBuffer(nil, Tmp);
      Len := Len + Tmp;
    end;
    if Size < Len then
    begin
      Size := Len;
      Result := false;
      Exit;
    end
    else
    begin
      Tmp := 0;
      for I := 0 to FList.Count - 1 do
      begin
        Len := Size - Tmp;
        TElASN1CustomTag(FList[I]).SaveToBuffer(@PByteArray(Buffer)[Tmp], Len);
        Tmp := Tmp + Len;
      end;
      Size := tmp;
      Result := true;
      Exit;
    end;
  end;
  if (FUndefSize) then
  begin
    Result := SaveToBufferUndefSize(Buffer, Size);
    Exit;
  end;
  Len := 0;
  for I := 0 to FList.Count - 1 do
  begin
    Tmp := 0;
    TElASN1CustomTag(FList[I]).SaveToBuffer(nil, Tmp);
    Len := Len + Tmp;
  end;
  if (Len <= 127) then
    HLen := 1
  else
  begin
    Tmp := Len;
    HLen := 1;
    while(Tmp > 0) do
    begin
      Tmp := Tmp shr 8;
      Inc(HLen);
    end;
  end;
  if(Len + HLen + 1 > Size) then
  begin
    Size := Len + HLen + 1;
    Result := false;
  end
  else
  begin
    PByteArray(Buffer)[0] := FTagId;
    if (Len <= 127) then
      PByteArray(Buffer)[1] := Len
    else
    begin
      PByteArray(Buffer)[1] := $80 + HLen - 1;
      for I := 2 to HLen do
        PByteArray(Buffer)[I] := (Len shr ((HLen - I) shl 3)) and $FF;
    end;

    Tmp := HLen + 1;
    for i := 0 to FList.Count - 1 do
    begin
      Len := Size - Tmp;
      TElASN1CustomTag(FList[I]).SaveToBuffer(@PByteArray(Buffer)[Tmp], Len);
      Tmp := Tmp + Len;
    end;
    Size := Tmp;
    Result := true;
  end;

end;


function TElASN1ConstrainedTag.SaveToBufferUndefSize(Buffer : Pointer; var Size : Integer) : Boolean;
var
  I, Len, Tmp : integer;
begin
  

  Len := 0;
  for I := 0 to FList.Count - 1 do
  begin
    Tmp := 0;
    TElASN1CustomTag(FList[I]).SaveToBuffer(nil, Tmp);
    Len := Len + Tmp;
  end;
  if (Len + 4 > Size) then
  begin
    Size := Len + 4;
    Result := false;
  end
  else
  begin
    PByteArray(Buffer)[1] := $80;
    PByteArray(Buffer)[0] := FTagId;
    Tmp := 2;
    for i := 0 to FList.Count - 1 do
    begin
      Len := Size - Tmp;
      TElASN1CustomTag(FList[i]).SaveToBuffer(@PByteArray(Buffer)[Tmp], Len);
      Tmp := Tmp + Len;
    end;
    PByteArray(Buffer)[Tmp] := 0;
    PByteArray(Buffer)[Tmp + 1] := 0;
    Size := Tmp + 2;
    Result := true;
  end;

end;

function TElASN1ConstrainedTag.AddField(Constrained : boolean) : integer;
var
  Tag : TElASN1CustomTag;
begin
  if Constrained then
    Tag := TElASN1ConstrainedTag.CreateInstance
  else
    Tag := TElASN1SimpleTag.CreateInstance;
  Result := FList.Add(Tag);
end;

function TElASN1ConstrainedTag.RemoveField(Index : integer) : boolean;
var
  Tag : TElASN1CustomTag;
begin
  if (Index < FList.Count) and (Index >= 0) then
  begin
    Tag := TElASN1CustomTag(FList[Index]);
    FList.Delete(Index);
    FreeAndNil(Tag);
    Result := true;
  end
  else
    Result := false;
end;

function TElASN1ConstrainedTag.GetField(Index : integer) : TElASN1CustomTag;
begin
  if (Index < FList.Count) and (Index >= 0) then
    Result := TElASN1CustomTag(FList[Index])
  else
    Result := nil;
end;

function TElASN1ConstrainedTag.GetCount : integer;
begin
  Result := FList.Count;
end;

function TElASN1ConstrainedTag.UnknownSize : boolean;
var
  i : integer;
begin
  for i := 0 to Count - 1 do
    if GetField(i).UnknownSize then
    begin
      Result := true;
      Exit;
    end;
  Result := false;      
end;

function TElASN1ConstrainedTag.LoadFromStream(Stream: TElStream;
  Count : Int64  =  0): boolean;
var
  ASN1Parser : TElASN1Parser;
begin
  FSingleLoad := false;
  FDataProcessed := false;
  ASN1Parser :=  TElASN1Parser.Create ;
  try
    FInputStream := Stream;

    ASN1Parser.OnRead := HandleASN1ReadStream;
    ASN1Parser.OnTag := HandleASN1Tag;
    ASN1Parser.OnTagHeader := HandleASN1TagHeader;
    ASN1Parser.OnSkip := HandleASN1SkipStream;

    ASN1Parser.RaiseOnEOC := true;
    ASN1Parser.MaxSimpleTagLength := FMaxSimpleTagLength;
    FCurrBufferIndex := FInputStream.Position;
    if Count = 0 then
    begin
      FMaxStreamPos := FInputStream. Size ;
      ASN1Parser.MaxDataLength := FMaxStreamPos;
    end
    else
    begin
      FMaxStreamPos := FCurrBufferIndex + Count;
      ASN1Parser.MaxDataLength := Count;
    end;
    
    Result := true;
    try
      ASN1Parser.Parse;
    except
      on E : Exception do
        Result := false;
    end;
  finally
    FreeAndNil(ASN1Parser);
  end;
end;

function TElASN1ConstrainedTag.LoadFromStreamSingle(Stream: TElStream;
  Count : Int64  =  0): boolean;
var
  ASN1Parser : TElASN1Parser;
begin
  FSingleLoad := true;
  FDataProcessed := false;
  ASN1Parser :=  TElASN1Parser.Create ;
  try
    FInputStream := Stream;

    ASN1Parser.OnRead := HandleASN1ReadStream;
    ASN1Parser.OnTag := HandleASN1Tag;
    ASN1Parser.OnTagHeader := HandleASN1TagHeader;
    ASN1Parser.OnSkip := HandleASN1SkipStream;

    ASN1Parser.RaiseOnEOC := true;
    ASN1Parser.MaxSimpleTagLength := FMaxSimpleTagLength;
    FCurrBufferIndex := FInputStream.Position;
    if Count = 0 then
    begin
      FMaxStreamPos := FInputStream. Size ;
      ASN1Parser.MaxDataLength := FMaxStreamPos;
    end
    else
    begin
      FMaxStreamPos := FCurrBufferIndex + Count;
      ASN1Parser.MaxDataLength := Count;
    end;

    Result := true;
    try
      ASN1Parser.Parse;
    except
      on E : Exception do
        Result := false;
    end;
  finally
    FreeAndNil(ASN1Parser);
  end;
end;

function TElASN1ConstrainedTag.GetEncodedLen : Int64;
var
  HLen, Tmp : Int64;
  I : integer;
  DataLen : Int64;
begin
  DataLen := 0;
  for I := 0 to FList.Count - 1 do
    DataLen := DataLen + TElASN1CustomTag(FList[I]).GetEncodedLen;

  if (not FWriteHeader) then
    Result := DataLen
  else
  if (FUndefSize) then
    Result := DataLen + 4
  else
  begin
    if (DataLen <= 127) then
      HLen := 1
    else
    begin
      Tmp := DataLen;
      HLen := 1;
      while(Tmp > 0) do
      begin
        Tmp := Tmp shr 8;
        Inc(HLen);
      end;
    end;
    Result := DataLen + HLen + 1;
  end;
end;

procedure TElASN1ConstrainedTag.SaveToStream(Stream: TElStream);
var
  I : integer;
  ChildrenLen : Int64;
  HeaderBuf : ByteArray;
  UseUndefSize : boolean;
begin

  // calculating size of subitems
  UseUndefSize := FUndefSize;

  if not UnknownSize then
  begin
    ChildrenLen := 0;
    for I := 0 to FList.Count - 1 do
      ChildrenLen := ChildrenLen + TElASN1CustomTag(FList[I]).GetEncodedLen;
  end
  else
  begin
    UseUndefSize := true;
    ChildrenLen := 0;
  end;

  // writing header
  if FWriteHeader then
  begin
    if UseUndefSize then
    begin
      SetLength(HeaderBuf, 2);
      HeaderBuf[0] := TagID;
      HeaderBuf[1] := $80;
    end
    else
      HeaderBuf := ComposeHeader(ChildrenLen);
    Stream.Write(HeaderBuf[0], Length(HeaderBuf));
  end;

  // writing subitems
  for I := 0 to FList.Count - 1 do
    TElASN1CustomTag(FList[I]).SaveToStream(Stream);

  // writing trailer for undefined-length tags
  if FWriteHeader and UseUndefSize then
  begin
    SetLength(HeaderBuf, 2);
    HeaderBuf[0] := 0;
    HeaderBuf[1] := 0;
    Stream.Write(HeaderBuf[0], 2);
  end;

end;

procedure TElASN1ConstrainedTag.HandleASN1Read(Sender : TObject; Buffer : pointer;
  var Size : longint);
var NewPtr : pointer;
begin
  if (FSingleLoad) and (FDataProcessed) and (FSizeLeft <= 0) then
  begin
    Size := 0;
    Exit;
  end;
  NewPtr := pointer(PtrUInt(FBuffer) + Int64(FCurrBufferIndex));
  if Size < FBufferSize - FCurrBufferIndex then
  begin
    SBMove(NewPtr^, Buffer^, Size);
    Inc(FCurrBufferIndex, Size);
  end
  else
  begin
    Size := FBufferSize - FCurrBufferIndex;
    SBMove(NewPtr^, Buffer^, Size);
    Inc(FCurrBufferIndex, Size);
  end;

  if (FSingleLoad) and (FDataProcessed) and (FSizeLeft > 0) then
    Dec(FSizeLeft, Size);
end;

procedure TElASN1ConstrainedTag.HandleASN1ReadStream(Sender : TObject; Buffer : pointer;
  var Size : longint);
begin
  if (FSingleLoad) and (FDataProcessed) and (FSizeLeft <= 0) then
  begin
    Size := 0;
    Exit;
  end;
  FInputStream.Position := FCurrBufferIndex;
  Size := Min(FMaxStreamPos - FCurrBufferIndex, Size);
  Size := FInputStream.Read(Buffer^, Size);
  Inc(FCurrBufferIndex, Size);
  if (FSingleLoad) and (FDataProcessed) and (FSizeLeft > 0) then
    Dec(FSizeLeft, Size);
end;

procedure TElASN1ConstrainedTag.HandleASN1Skip(Sender: TObject;
  var Count: Int64);
begin
  if (FSingleLoad) and (FDataProcessed) and (FSizeLeft <= 0) then
  begin
    Count := 0;
    Exit;
  end;
  Count := Min( FBufferSize  - FCurrBufferIndex, Count);
  Inc(FCurrBufferIndex, Count);

  if (FSingleLoad) and (FDataProcessed) and (FSizeLeft > 0) then
    Dec(FSizeLeft, Count);
end;

procedure TElASN1ConstrainedTag.HandleASN1SkipStream(Sender: TObject;
  var Count: Int64);
begin
  if (FSingleLoad) and (FDataProcessed) and (FSizeLeft <= 0) then
  begin
    Count := 0;
    Exit;
  end;
  Count := Min(FMaxStreamPos - FCurrBufferIndex, Count);
  FInputStream.Position := FCurrBufferIndex + Count;
  Inc(FCurrBufferIndex, Count);

  if (FSingleLoad) and (FDataProcessed) and (FSizeLeft > 0) then
    Dec(FSizeLeft, Count);
end;

procedure TElASN1ConstrainedTag.HandleASN1Tag(Sender : TObject; TagType: asn1TagType;
  TagConstrained: boolean; Tag: pointer; TagSize: integer; Size: Int64; Data: pointer;
  BitRest: integer; var Valid : boolean);
var
  NewTag : TElASN1CustomTag;
  ParentTag : TElASN1ConstrainedTag;
  I : integer;
  NewBuf : ByteArray;
  B : byte;
  Content : ByteArray;
  NewPtr : pointer;
begin
  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  try
   {$endif}

  if TagType = asn1tEOC then
  begin
    if FStack.Count > 0 then
    begin
      FStack.Delete(FStack.Count - 1);
      if (FStack.Count = 0) and (FSingleLoad) then
      begin
        FDataProcessed := true;
        FSizeLeft := 0;
      end;
    end;
    Exit;
  end;
  if FStack.Count > 0 then
    ParentTag := TElASN1ConstrainedTag(FStack[FStack.Count - 1])
  else
    ParentTag :=  Self ;
  if (TagConstrained) then
  begin
    if FDepth >= G_MaxASN1TreeDepth then
      raise EElASN1Error.Create(SMaxTreeDepthExceeded);
    NewTag := ParentTag.GetField(ParentTag.AddField(true));
    NewTag.FDepth := FDepth + 1;
    TElASN1ConstrainedTag(NewTag).FMaxSimpleTagLength := FMaxSimpleTagLength;

    NewTag.TagId := ((integer(TagType) - integer(asn1tUniversal)) shl 6) or (integer(TagConstrained) shl 5) or PByte(Tag)^;
    //NewTag.Parent := ParentTag;
    NewTag.FTagOffset := FCurrBufferIndex - FLastHeaderLen;
    NewTag.FTagSize := Size + FLastHeaderLen;
    NewTag.FTagHeaderSize := FLastHeaderLen;
    NewTag.FTagContentSize := Size;
    if Assigned(ParentTag) and (FInputStream = nil) then
    begin
      if not ParentTag.UndefSize then
        Inc(NewTag.FTagOffset, ParentTag.FTagOffset + ParentTag.FTagHeaderSize)
      else
        Inc(NewTag.FTagOffset, TElASN1ConstrainedTag(FStack[0]).FTagOffset);
    end;
    if FInputStream <> nil then
      B := GetByteFromStream(FInputStream, FCurrBufferIndex - 1)
    else
      B := PByteArray(FBuffer)[FCurrBufferIndex - 1];
    if (Size = 0) and (B = $80) then
    begin
      NewTag.FUndefSize := true;
      FStack.Add(NewTag);
    end
    else
    begin
      if FInputStream = nil then
      begin
        NewPtr := pointer(PtrUInt(FBuffer) + Int64(FCurrBufferIndex));
        NewTag.LoadFromBuffer(NewPtr, Size);
        if (FSingleLoad) and (FStack.Count = 0) then
        begin
          FDataProcessed := true;
          FSizeLeft := Size;
        end;
      end
      else
      begin
        if Size > 0 then
          NewTag.LoadFromStream(FInputStream, Size);
        if (FSingleLoad) and (FStack.Count = 0) then
        begin
          FDataProcessed := true;
          FSizeLeft := Size;
        end;
      end;
    end;
    Valid := false;
  end
  else
  begin
    if FDepth >= G_MaxASN1TreeDepth then             
      raise EElASN1Error.Create(SMaxTreeDepthExceeded);
    NewTag := ParentTag.GetField(ParentTag.AddField(false));
    //NewTag.Parent := ParentTag;
    NewTag.FTagOffset := FCurrBufferIndex - FLastHeaderLen - Size;
    NewTag.FTagSize := Size + FLastHeaderLen;
    NewTag.FDepth := FDepth + 1;

    if (PByte(Tag)^ = asn1BitStr) and (TagType <> asn1tSpecific) then
    begin
      Dec(NewTag.FTagOffset);
      Inc(NewTag.FTagSize);
    end;

    if Assigned(ParentTag) and (FInputStream = nil) then
    begin
      if not ParentTag.UndefSize then
        Inc(NewTag.FTagOffset, ParentTag.FTagOffset + ParentTag.FTagHeaderSize)
      else
        Inc(NewTag.FTagOffset, TElASN1ConstrainedTag(FStack[0]).FTagOffset);
    end;
    NewTag.TagId := ((integer(TagType) - integer(asn1tUniversal)) shl 6) or (integer(TagConstrained) shl 5) or PByte(Tag)^;
    if (Data <> nil) or (Size = 0) then
    begin
      SetLength(Content, Size);

      if NewTag.TagId <> SB_ASN1_INTEGER then
        SBMove(Data^, Content[0], Size)
      else
      begin
        if Size = 0 then
        begin
          SetLength(Content, 1);
          Content[0]:= 0;
        end
        else
        begin
          for I := 0 to Size - 1 do
            Content[I] := PByteArray(Data)[Size - I - 1];
        end;
      end;

      if (PByte(Tag)^ = asn1BitStr) and (TagType <> asn1tSpecific) then
      begin
        SetLength(NewBuf, Length(Content) + 1);
        SBMove(Content, 0, NewBuf, 1, Length(NewBuf) - 1);
        NewBuf[0] := byte(0);
        Content := NewBuf;
      end;

      TElASN1SimpleTag(NewTag).DataSource.Init(Content);
    end
    else 
    if FInputStream <> nil then
    begin
      TElASN1SimpleTag(NewTag).FDataSource.Init(FInputStream,
        TElASN1SimpleTag(NewTag).FTagOffset + FLastHeaderLen,
        TElASN1SimpleTag(NewTag).FTagSize - FLastHeaderLen);
    end;
  end;

  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  finally
    ReleaseArray(NewBuf);
    ReleaseArray(Content);
  end;
   {$endif}
end;

procedure TElASN1ConstrainedTag.HandleASN1TagHeader(Sender: TObject; TagID : byte;
  TagLen : Int64; HeaderLen : integer; UndefLen : boolean);
begin
  FLastHeaderLen := HeaderLen;
  //FLastUndefLen := UndefLen;
end;

procedure TElASN1ConstrainedTag.Clear;
begin
  ClearList;
  FStack.Clear;
end;

function TElASN1ConstrainedTag.GetConstrained : boolean;
begin
  Result := true;
end;

function TElASN1ConstrainedTag.SaveContentToBuffer(Buffer : pointer;
  var Size : integer) : boolean;
var
  I, Needed : integer;
  Ptr :  ^byte ;
  ChunkSize : integer;
begin
  { 1. Estimating needed size }
  Needed := 0;
  Result := false;
  for I := 0 to Count - 1 do
    if GetField(I).IsConstrained then
      Exit
    else
      Inc(Needed, Length(TElASN1SimpleTag(GetField(I)).Content));
  { 2. Saving data }
  if Needed <= Size then
  begin
    Ptr :=  Buffer ;
    for I := 0 to Count - 1 do
    begin
      ChunkSize := Length(TElASN1SimpleTag(GetField(I)).Content);
      SBMove(TElASN1SimpleTag(GetField(I)).Content[0], Ptr^, ChunkSize);
      Inc(Ptr, ChunkSize);
    end;
    Result := true;
  end;
  Size := Needed;
end; 

function TElASN1ConstrainedTag.GetByteFromStream(Stream: TElStream;
  Offset: Int64): byte;
var
  OldPos : Int64;
  Len : Int64;
begin
  Result := 0;
  OldPos := Stream.Position;
  try
    Stream.Position := Offset;
    Len := Stream.Read(Result, 1);
    if Len = 0 then
      raise EElASN1Error.Create(SEndOfStream);
  finally
    Stream.Position := OldPos;
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// TElASN1DataSource class


 destructor  TElASN1DataSource.Destroy;
begin
  ReleaseArray(FContent);
  inherited;
end;

procedure TElASN1DataSource.Init(const Value : ByteArray);
begin
  FUnknownSize := false;
  FSourceType := dstBuffer;
  FContent := CloneArray(Value);
  FSkipVirtualData := false;
end;

procedure TElASN1DataSource.Init(Stream: TElStream; Offset: Int64; Size: Int64);
begin
  FUnknownSize := false;
  FSourceType := dstStream;
  FContentStream := Stream;
  FContentOffset := Offset;
  if Size = 0 then
    Size := Stream. Size  - Offset;
  FContentSize := Size;
  FSkipVirtualData := false;
end;

procedure TElASN1DataSource.Init(Stream: TElStream;
  UnknownSize : boolean);
begin
  FSourceType := dstStream;
  FContentStream := Stream;
  FUnknownSize := UnknownSize;
  FSkipVirtualData := false;

  if not UnknownSize then
  begin
    FContentOffset := Stream.Position;
    FContentSize := Stream. Size  - FContentOffset;
  end
  else
  begin
    FContentOffset := 0;
    FContentSize := 0;
  end;
end;

procedure TElASN1DataSource.Init(Buffer: pointer; Size: integer);
begin
  FUnknownSize := false;
  FSourceType := dstBuffer;
  SetLength(FContent, Size);
  SBMove(Buffer^, FContent[0], Length(FContent));
  FSkipVirtualData := false;
end;

procedure TElASN1DataSource.InitVirtual(Size : Int64);
begin
  FUnknownSize := false;
  FSourceType := dstVirtual;
  FSkipVirtualData := false;
  FContentSize := Size;
end;

function TElASN1DataSource.ToBuffer: ByteArray;
var
  Read, OldSize : integer;
  TmpBuf : ByteArray;
begin

  if FSourceType = dstBuffer then
    Result := (FContent)
  else
  if FSourceType = dstStream then
  begin
    if not FUnknownSize then
    begin
      SetLength(Result, FContentSize);
      FContentStream.Position := FContentOffset;
      Read := FContentStream.Read(Result[0], Length(Result));
      SetLength(Result, Read);
    end
    else
    begin
      SetLength(Result, 0);
      SetLength(TmpBuf, 32768);
        //OldSize := 0;
        repeat
          OldSize := Length(Result);
          Read := FContentStream.Read(TmpBuf[0], 32768);
          if Read > 0 then
          begin
            SetLength(Result, OldSize + Read);
            SBMove(TmpBuf[0], Result[0 + OldSize], Read);
          end;
        until Read = 0;

    end;
  end
  else
  if FSourceType = dstVirtual then
  begin
    if FSkipVirtualData or (not Assigned(FOnVirtualDataNeeded)) then
      Result := CloneArray(EmptyArray)
    else
    begin
      SetLength(Result, FContentSize);
      Read := 0;
      FOnVirtualDataNeeded(Self, 0,  @Result[0] , Length(Result), Read);
      SetLength(Result, FContentSize);
    end;
  end
  else
    Result := CloneArray(EmptyArray);
end;

function TElASN1DataSource.Read(Buffer: pointer; Size: integer; Offset: Int64): integer;
begin
  if FSourceType = dstBuffer then
  begin
    Result := Min(Length(FContent) - Offset, Size);
    SBMove(FContent[0 + Offset], Buffer^, Result);
  end
  else
  if FSourceType = dstStream then
  begin
    if not FUnknownSize then
    begin
      Result := Min(FContentSize - Offset, Size);
      FContentStream.Position := FContentOffset + Offset;
      Result := FContentStream.Read(Buffer^, Result);
    end
    else
    begin
      { skipping offset parameter - stream is not seekable }
      Result := Size;
      Result := FContentStream.Read(Buffer^, Result);
    end;  
  end
  else if FSourceType = dstVirtual then
  begin
    if FSkipVirtualData or (not Assigned(FOnVirtualDataNeeded)) then
      Result := 0
    else
    begin
      Result := 0;
      FOnVirtualDataNeeded(Self, Offset, Buffer, Size, Result);
    end;
  end
  else
    Result := 0;
end;

function TElASN1DataSource.GetSize : Int64;
begin
  if FSourceType = dstBuffer then
    Result := Length(FContent)
  else if FSourceType = dstStream then
    Result := FContentSize
  else if FSourceType = dstVirtual then
    Result := FContentSize
  else
    Result := 0;
end;

procedure TElASN1DataSource.Clone(Dest : TElASN1DataSource);
begin
  Dest.FSourceType := FSourceType;
  Dest.FUnknownSize := FUnknownSize;
  Dest.FSkipVirtualData := FSkipVirtualData;

  if FSourceType = dstBuffer then
    Dest.FContent := CloneArray(FContent)
  else if FSourceType = dstVirtual then
    Dest.FContentSize := FContentSize
  else
  if FSourceType = dstStream then
  begin
    Dest.FContentStream := FContentStream;
    Dest.FContentOffset := FContentOffset;
    Dest.FContentSize := FContentSize;
  end;
end;

procedure TElASN1DataSource.CloneVirtual(Dest : TElASN1DataSource);
begin
  Dest.FSourceType := dstVirtual;
  Dest.FUnknownSize := FUnknownSize;
  Dest.FSkipVirtualData := FSkipVirtualData;

  if FSourceType = dstBuffer then
    Dest.FContentSize := Length(FContent)
  else
  if FSourceType = dstStream then
    Dest.FContentSize := FContentSize;
end;

////////////////////////////////////////////////////////////////////////////////
// Miscellaneous function


procedure asymWriteInteger(Tag : TElASN1SimpleTag;
   Buffer : pointer; Size : integer );
var
  S : ByteArray;
begin
  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  try
   {$endif}
    if PByte(Buffer)^ >= 128 then
    begin
      SetLength(S, Size + 1);
      S[0] := byte(0);
      SBMove(PByte(Buffer)^, S[0 + 1], Size);
    end
    else
    begin
      SetLength(S, Size);
      SBMove(Buffer^, S[0], Length(S));
    end;
    Tag.TagId := SB_ASN1_INTEGER;
    Tag.Content := S;
  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  finally
    ReleaseArray(S);
  end;
   {$endif}
end;

function ASN1ReadInteger(Tag: TElASN1SimpleTag): integer;
var
  Cnt : ByteArray;
  I, K : integer;
begin
  Cnt := Tag.Content; // the reader function returns new array so we have to release it
  try
    I := Length(Cnt);
    K := 0;
    Result := 0;
    while (I > 0) and (K < 5) do
    begin
      Result := Result or (Cnt[I - 1] shl ({K * 8} K shl 3));
      Dec(I);
      Inc(K);
    end;
  finally
    ReleaseArray(Cnt);
  end;
end;

function ASN1ReadInteger64(Tag: TElASN1SimpleTag): Int64;
var
  Cnt : ByteArray;
  I, K : integer;
begin
  Cnt := Tag.Content;

  I := Length(Cnt);
  K := 0;
  Result := 0;
  while (I > 0) and (K < 8) do
  begin
    Result := Result or (Cnt[I - 1] shl (K shl 3));
    Dec(I);
    Inc(K);
  end;
  ReleaseArray(Cnt);
end;

function ASN1ReadSimpleValue(const Data : ByteArray; var TagID : integer): ByteArray;
var
  Tag : TElASN1ConstrainedTag;
begin
  TagID := 0;
  Result := EmptyArray;
  Tag := TElASN1ConstrainedTag.CreateInstance();
  try
    if Tag.LoadFromBuffer(@Data[0], Length(Data)) then
    begin
      if (Tag.Count = 1) and (not Tag.GetField(0).IsConstrained) then
      begin
        Result := TElASN1SimpleTag(Tag.GetField(0)).Content;
        TagID := Tag.GetField(0).TagID;
      end;
    end;
  finally
    FreeAndNil(Tag);
  end;
end;

function ASN1ReadBoolean(Tag: TElASN1SimpleTag): boolean;
var
  Cnt : ByteArray;
begin
  Cnt := Tag.Content;
  Result := (Length(Cnt) = 1) and (Cnt[0] = byte($ff));
    ReleaseArray(Cnt);
end;

function ASN1ReadString(const Data : ByteArray; TagId : integer): UnicodeString;
var
  Buf: ByteArray;
  k: Integer;
begin
  Buf := EmptyArray;
  
  case TagId of
    SB_ASN1_NUMERICSTR, SB_ASN1_PRINTABLESTRING,
    SB_ASN1_IA5STRING, SB_ASN1_VISIBLESTRING:
    begin
      Result := StringOfBytes(Data)
    end;

    SB_ASN1_UTF8STRING:
    begin
      Result := UTF8ToWideStr(Data);
      //Result := ConvertFromUTF8String(RDN.Values[i], false);
    end;

    SB_ASN1_BMPSTRING:
    begin
      Buf := Data;


      k := 0;
      if (Length(Buf) >= 2) and (Buf[0] = byte(254)) and (Buf[0 + 1] = byte(255)) then
      begin
        k := 2;
        SwapBigEndianWords(@Buf[0 + 2], Length(Buf) - k);
      end
      else
      if (Length(Buf) >= 2) and (Buf[0] = byte(255)) and (Buf[0 + 1] = byte(254)) then
        k := 2
      else
        SwapBigEndianWords(@Buf[0], Length(Buf));

      SetLength(Result, (Length(Buf) - k) shr 1);
      SBMove(PWideChar(@Buf[k])^, Result[StringStartOffset], Length(Buf) - k);

    end;

    {$ifndef SB_NO_NET_UTF32_ENCODING}
    {$ifndef SB_NO_CHARSETS}
    SB_ASN1_UNIVERSALSTRING:
    begin
      Buf := Data;

      if (Length(Buf) < 4) or
         (Buf[0] <> byte(255)) or
         (Buf[0 + 1] <> byte(254)) or
         (Buf[0 + 2] <> byte(0)) or
         (Buf[0 + 3] <> byte(0)) then
        SwapBigEndianDWords(@Buf[0], Length(Buf));
      // else UTF-32LE

      Result := ConvertFromUTF32String(Buf, False);
    end;
     {$endif}
     {$endif}
  else
    Result := StringOfBytes(Data)
  end;
end;

procedure ASN1WriteBoolean(Tag: TElASN1SimpleTag; Value: boolean);
var Tmp : ByteArray;
begin
  Tag.TagID := SB_ASN1_BOOLEAN;
  if Value then
    Tmp := GetByteArrayFromByte($ff)
  else
    Tmp := GetByteArrayFromByte($00);
  Tag.Content := Tmp;
  ReleaseArray(Tmp);
end;

procedure ASN1WriteInteger(Tag: TElASN1SimpleTag; Value: integer);
var
  Tmp,
  Val : ByteArray;
  i : integer;
  ResultBufSize : integer;
  ResultBufStart : integer;
begin
  Tag.TagId := SB_ASN1_INTEGER;

  if Value = 0 then
  begin
    SetLength(Val, 1);
    Val[0] := byte(0);
  end
  else
  begin

    ResultBufStart := 0;
    ResultBufSize := 4;

    // if the number starts from the byte with value >= 128, add 0 at the beginning
    if (Cardinal(Value) > $7FFFFFFF) then
    begin
      ResultBufSize := 5;
      ResultBufStart := 1;
    end;

    SetLength(Val, ResultBufSize);

    if ResultBufStart = 1 then
       Val[0] := byte(0);

    GetBytes32(Value, Val, ResultBufStart);

    // find position of non-zero byte
    i := ResultBufStart;
    while i < ResultBufSize do
    begin
      if Val[0 + i] <> byte(0) then
        break;
      inc(i);
    end;

    if (Val[0 + i] >= byte($80)) then
    begin
      dec(i);
    end;

    // Cut leading zeros
    if (i > ResultBufStart) then
    begin
      Tmp := Val;
      Val := CloneArray(Tmp, i, ResultBufSize - i);
      ReleaseArray(Tmp);
    end;
  end;

  Tag.Content := Val; // Setter makes a copy

  ReleaseArray(Val);
end;

procedure ASN1WriteInteger64(Tag: TElASN1SimpleTag; Value: Int64);
var
  Tmp,
  Val : ByteArray;
  i : integer;
  ResultBufSize : integer;
  ResultBufStart : integer;
begin
  Tag.TagId := SB_ASN1_INTEGER;

  if Value = 0 then
  begin
    SetLength(Val, 1);
    Val[0] := byte(0);
  end
  else
  begin

    ResultBufStart := 0;
    ResultBufSize := 8;

    // if the number starts from the byte with value >= 128, add 0 at the beginning
    if ((Value shr 56) and $ff) > $80 then
    begin
      ResultBufSize := 9;
      ResultBufStart := 1;
    end;

    SetLength(Val, ResultBufSize);

    if ResultBufStart = 1 then
       Val[0] := byte(0);

    GetBytes64(Value, Val, 0 + ResultBufStart);

    // find position of non-zero byte
    i := ResultBufStart;
    while i < ResultBufSize do
    begin
      if Val[0 + i] <> byte(0) then
        break;
      inc(i);
    end;

    if (Val[0 + i] >= byte($80)) then
    begin
      dec(i);
    end;

    // Cut leading zeros
    if (i > ResultBufStart) then
    begin
      Tmp := Val;
      Val := CloneArray(Tmp, i, ResultBufSize - i);
      ReleaseArray(Tmp);
    end;
  end;

  Tag.Content := Val;
  ReleaseArray(Val);
end;

function ASN1WriteTagAndLength(Tag: integer; Len : Int64): ByteArray;
var
  HLen : integer;
  OrigLen : Int64;
  I : integer;
begin
  OrigLen := Len;
  if (Len <= 127) then
    HLen := 1
  else
  begin
    HLen := 1;
    while (OrigLen > 0) do
    begin
      OrigLen := OrigLen shr 8;
      Inc(HLen);
    end;
  end;
  SetLength(Result, HLen + 1);

  PByte(@Result[0])^ := Tag;
  if (HLen = 1) then
    PByteArray(@Result[0])[1] := Len
  else
  begin
    PByteArray(@Result[0])[1] := $80 + HLen - 1;
    for I := 2 to HLen do
      PByteArray(@Result[0])[I] := Len shr ((HLen - I) shl 3) and $FF
  end;
end;

function FormatAttributeValue(TagID : integer; const Value : ByteArray) : ByteArray;
var
  CTag : TElASN1SimpleTag;
  Sz : integer;
begin
  CTag := TElASN1SimpleTag.CreateInstance;
  try
    CTag.TagId := TagID;
    CTag.Content := Value;
    Sz := 0;

    CTag.SaveToBuffer(nil, Sz);
    SetLength(Result, Sz);
    CTag.SaveToBuffer(@Result[0], Sz);
    SetLength(Result, Sz);
  finally
    FreeAndNil(CTag);
  end;
end;

function UnformatAttributeValue(const Value : ByteArray; out TagID : integer) : ByteArray;
var
  Tag : TElASN1ConstrainedTag;
  Sz : integer;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if Tag.LoadFromBuffer(@Value[0], Length(Value)) then
    begin
      if Tag.Count > 0 then
      begin
        Sz := 0;
        Tag.GetField(0).WriteHeader := false;
        Tag.GetField(0).SaveToBuffer(nil, Sz);
        SetLength(Result, Sz);
        Tag.GetField(0).SaveToBuffer(@Result[0], Sz);
        SetLength(Result, Sz);
        TagID := Tag.GetField(0).TagId;
      end
      else
      begin
        Result := CloneArray(Value);
        TagID := 0;
      end;
    end
    else
    begin
      Result := CloneArray(Value);
      TagID := 0;
    end;
  finally
    FreeAndNil(Tag);
  end;
end;

end.
