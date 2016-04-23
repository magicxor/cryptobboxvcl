(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBStreams;

interface

uses
  SysUtils,
  Classes,
  {$ifdef WIN32}
  Windows,
   {$endif}

    SyncObjs,
    {$ifdef SB_UNIX}
      {$ifdef FPC}
      unix,
      unixtype,
	  {$ifdef SB_LINUX}
      {$ifndef SB_ANDROID} 
      pthreads,
       {$endif}
	  linux,
       {$endif}
	   {$endif}
     {$endif}
  SBTypes,
  SBUtils;


type
  TElStream =   TStream ;
  TElMemoryStream =   TMemoryStream ;
  
  TElNativeStream = TStream;

  {$ifndef SB_NO_FILESTREAM}
  TElFileStream = class(TFileStream)
  private
    function GetPosition64: Int64;
    procedure SetPosition64(const Value: Int64);
    function GetSize64: Int64;
    procedure SetSize64(const Value: Int64);
  public
    {$ifndef VCL60}
    function Seek(Offset: Longint; Origin: Word): Longint; overload; override;
    function Seek(const Offset: Int64; Origin: Word): Int64; reintroduce; overload;
     {$endif}
    property Position64: Int64 read GetPosition64 write SetPosition64;
    property Size64: Int64 read GetSize64 write SetSize64;
  end;
   {$endif}
  

type

  TElDataStream = class
  protected
    FStart: Int64;
    FStream: TElStream;
    FFreeOnSent: Boolean;
    procedure Close;
  public
    constructor Create(LStream: TElStream; LFreeOnSent: Boolean);
     destructor  Destroy; override;
    property Start: Int64 read FStart;
    property Stream: TElStream read FStream write FStream;
    property FreeOnSent: Boolean read FFreeOnSent write FFreeOnSent;
  end;

  TElMultiStream =  class (TElStream)
  protected
    FStreams : TElList;
    FTotalSize : Int64;
    FSizeValid : boolean;
    FPosition : Int64;
    procedure CleanupStreams;
    function GetTotalSize : Int64;
    function DoRead(Buffer :  pointer ; Offset : integer; Count: Longint): Longint;
  public
    constructor Create;
     destructor  Destroy;  override; 
    function AddStream(AStream : TElStream; FreeStream : boolean) : boolean;

    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
    function Seek(Offset: Longint; Origin: Word): Longint; overload; override;
    function Seek(const Offset: Int64; Origin: {$ifdef D_6_UP}TSeekOrigin {$else}Word {$endif}): Int64; reintroduce; overload; {$ifdef D_6_UP}override; {$endif}

    
  end;

  TElReadCachingStream =  class (TElStream)
  protected
    FCache : ByteArray;
    FCacheSize : integer;
    FDataInCache : integer; // data, read to FCache
    FNextDataInCache : integer; // offset of next unread data in FCache
    FStream : TElStream;
    procedure SetCacheSize(Value : integer);
    procedure SetStream(Stream : TElStream);
  public
    constructor Create;
     destructor  Destroy;  override; 
    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
    function Seek(Offset: Longint; Origin: Word): Longint; overload; override;
    function Seek(const Offset: Int64; Origin: {$ifdef D_6_UP}TSeekOrigin {$else}Word {$endif}): Int64; reintroduce; overload; {$ifdef D_6_UP}override; {$endif}

    

    property Stream : TElStream read FStream write SetStream;
    property CacheSize : integer read FCacheSize write SetCacheSize;
  end;

  TElWriteCachingStream =  class (TElStream)
  protected
    FCache : ByteArray;
    FCacheSize : integer;
    FDataInCache : integer; // cached data size
    FStream : TElStream;
    procedure SetCacheSize(Value : integer);
    procedure SetStream(Stream : TElStream);
  public
    constructor Create;
     destructor  Destroy;  override ;

    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
    function Seek(Offset: Longint; Origin: Word): Longint; overload; override;
    function Seek(const Offset: Int64; Origin: {$ifdef D_6_UP}TSeekOrigin {$else}Word {$endif}): Int64; reintroduce; overload; {$ifdef D_6_UP}override; {$endif}

    procedure Flush; 
    
    
    property Stream : TElStream read FStream write SetStream;
    property CacheSize : integer read FCacheSize write SetCacheSize;
  end;

function CopyStream(SrcStream, DestStream: TStream; Offset : Int64; Count : Int64;
  PreservePosition : boolean = true): Int64; overload;
function CopyStream(Source, Dest: TElStream; Offset, Count: Int64; PreservePosition: Boolean;
  ProgressEvent: TSBProgressEvent): Int64;  overload; 

function StreamPosition(Stream : TElStream) : Int64; 
function StreamSize(Stream : TElStream) : Int64; 
procedure SetStreamPosition(Stream : TElStream; Position : Int64); 

procedure StreamRead(Stream: TElStream; var Buffer: ByteArray; Offset, Count: Integer);  overload; 
function StreamReadByte(Stream: TElStream): Byte;  overload ;
procedure StreamWrite(Stream: TElStream; const Buffer: ByteArray);  overload; 
procedure StreamWrite(Stream: TElStream; const Buffer: ByteArray; Offset, Count: Integer);  overload; 
procedure StreamWriteLn(Stream: TElStream; const Text: string); 

procedure StreamClear(Stream: TElMemoryStream); 

implementation

uses
  SBConstants, SBStrUtils;

resourcestring
  SStreamNotAssigned = 'Stream is not assigned';


const
  STREAM_CACHE_SIZE = $20000; // 128Kb


function CopyStream(SrcStream, DestStream: TStream; Offset : Int64; Count : Int64;
  PreservePosition : boolean = true): Int64;
const
  BUFFER_SIZE : integer = 8192;
var
  OldPos : Int64;
  Buf : ByteArray;
  ToRead, ToWrite : Int64;
begin
  Result := 0;
  OldPos := SrcStream.Position;
  try
    SetLength(Buf, BUFFER_SIZE);
    SrcStream.Position := Offset;
    while (Count > 0) and (SrcStream.Position <  SrcStream.Size ) do
    begin
      ToRead := Min(Count, BUFFER_SIZE);
      ToWrite := SrcStream.Read(Buf[0], ToRead);
      DestStream.Write(Buf[0], ToWrite);
      Dec(Count, ToWrite);
      Inc(Result, ToWrite);
    end;
  finally
    if PreservePosition then
      SrcStream.Position := OldPos;
  end;
end;

function CopyStream(Source, Dest: TElStream; Offset, Count: Int64; PreservePosition: Boolean;
  ProgressEvent: TSBProgressEvent): Int64;
const
  BUFFER_SIZE: Integer = 8192;
var
  OldPos, Total: Int64;
  Buf: ByteArray;
  ToRead, ToWrite: Int64;
  Cancelled: TSBBoolean;
begin
  Result := 0;
  if Count = 0 then
    Exit;
  OldPos := Source.Position;
  try
    SetLength(Buf, BUFFER_SIZE);
    Source.Position := Offset;
    Total := Count;
    while True do
    begin
      ToRead := Min(Count, BUFFER_SIZE);
      ToWrite := Source.Read(Buf[0], ToRead);
      if ToWrite = 0 then
        Break;
      Dest.Write(Buf[0], ToWrite);
      Dec(Count, ToWrite);
      Inc(Result, ToWrite);
      Cancelled := false;
      if Assigned(ProgressEvent) then
        ProgressEvent(nil, Total, Result, Cancelled);
      if Cancelled then
        Exit;
    end;
  finally
    if PreservePosition then
      Source.Position := OldPos;
  end;
end;

function StreamPosition(Stream : TElStream) : Int64;
begin
  {$ifndef D_6_UP}
  if Stream is TFileStream then
    Result := GetFilePosition(THandleStream(Stream).Handle)
  else
   {$endif}
    Result := Stream.Position;
end;

function StreamSize(Stream : TElStream) : Int64;
begin
  {$ifndef D_6_UP}
  if Stream is TFileStream then
    Result := GetFileSize(THandleStream(Stream).Handle)
  else
   {$endif}
    Result := Stream.Size;
end;

procedure SetStreamPosition(Stream : TElStream; Position : Int64);
begin
  {$ifndef D_6_UP}
  if Stream is TFileStream then
    SetFilePosition(THandleStream(Stream).Handle, Position)
  else
   {$endif}
    Stream.Position := Position;
end;

procedure StreamRead(Stream: TElStream; var Buffer: ByteArray; Offset, Count: Integer);
begin
  Stream.ReadBuffer(Buffer[Offset], Count);
end;

function StreamReadByte(Stream: TElStream): Byte;
begin
  Stream.ReadBuffer(Result, SizeOf(Result));
end;

procedure StreamWrite(Stream: TElStream; const Buffer: ByteArray);
begin
  Stream.WriteBuffer(Buffer[0], Length(Buffer));
end;

procedure StreamWrite(Stream: TElStream; const Buffer: ByteArray; Offset, Count: Integer);
begin
  Stream.WriteBuffer(Buffer[Offset], Count);
end;

procedure StreamClear(Stream: TElMemoryStream);
begin
  Stream.Clear();
end;

procedure StreamWriteLn(Stream: TElStream; const Text: string);
var
  TextBuf: ByteArray;
begin
  TextBuf := EmptyArray;
  if not StringIsEmpty(Text) then
  begin
    TextBuf := BytesOfString(Text);
    StreamWrite(Stream, TextBuf, 0, Length(TextBuf));
  end;

  StreamWrite(Stream, CRLFByteArray, 0, 2);
end;


{$ifndef SB_NO_FILESTREAM}

{ TElFileStream }

function TElFileStream.GetPosition64: Int64;
begin
  {$ifdef VCL60}
  Result := Position;
   {$else}
  Result := Seek(Int64(0), soFromCurrent);
   {$endif}
end;

function TElFileStream.GetSize64: Int64;
{$ifndef VCL60}
var
  Pos: Int64;
 {$endif}
begin
  {$ifdef VCL60}
  Result := Size;
   {$else}
  Pos := Seek(Int64(0), soFromCurrent);
  Result := Seek(Int64(0), soFromEnd);
  Seek(Pos, soFromBeginning);
   {$endif}
end;

{$ifndef VCL60}
function TElFileStream.Seek(Offset: Integer; Origin: Word): Longint;
var
  Result64: Int64;
begin
  Result64 := Seek(Int64(Offset), Origin);
  if (Result64 < Low(Longint)) or (Result64 > High(Longint)) then
    raise ERangeError.Create(SSeekOffsetRangeError);
  Result := LongInt(Result64);
end;

function TElFileStream.Seek(const Offset: Int64; Origin: Word): Int64;
begin
  Result := FileSeek(Handle, Offset, Origin);
end;
 {$endif}

procedure TElFileStream.SetPosition64(const Value: Int64);
begin
  {$ifdef VCL60}
  Self.Position := Value;
   {$else}
  Seek(Value, soFromBeginning);
   {$endif}
end;

procedure TElFileStream.SetSize64(const Value: Int64);
begin
  {$ifdef VCL60}
  Self.Size := Value;
   {$else}
  Seek(Value, soFromBeginning);
  Win32Check(SetEndOfFile(Handle));
   {$endif}
end;

 {$endif ifndef SB_NO_FILESTREAM}

  // non-Java

constructor TElDataStream.Create(LStream: TElStream; LFreeOnSent: Boolean);
begin
  inherited Create;
  FStream := LStream;
  FStart := LStream.Position;
  FFreeOnSent := LFreeOnSent;
end;

procedure TElDataStream.Close;
begin
  if FFreeOnSent then
    FreeAndNil(FStream);
end;

 destructor  TElDataStream.Destroy;
begin
  Close;
  inherited;
end;

constructor TElMultiStream.Create();
begin
  inherited Create;
  FStreams := TElList.Create;
  FSizeValid := true;
  FTotalSize := 0;
end;

 destructor  TElMultiStream.Destroy;
begin
  CleanupStreams;
  inherited;
end;


function TElMultiStream.AddStream(AStream : TElStream; FreeStream : boolean) : boolean;
var i  : integer;
    DS : TElDataStream;
begin
  for i := 0 to FStreams.Count - 1 do
  begin
    if TElDataStream(FStreams[i]).Stream = AStream then
    begin
      result := false;
      exit;
    end;
  end;
  DS := TElDataStream.Create(AStream, FreeStream);
  FStreams.Add(DS);
  FSizeValid := false;
  result := true;
end;

procedure TElMultiStream.CleanupStreams;
var i : integer;
begin
  for i := 0 to FStreams.Count - 1 do
  begin
    TElDataStream(FStreams[i]). Free ;;
  end;
  FStreams.Clear;
end;

function TElMultiStream.DoRead(Buffer :  pointer ; Offset : integer; Count: Longint): Longint;
var
  cStream : integer;
  CurStream : TElStream;
  iStreamRead : Int64;
  StreamLen   : Int64;
  StreamStart : Int64;
  CurToRead,
  LeftToRead  : Int64;
begin
  LeftToRead := Count;
  result := 0;
  cStream := 0;
  StreamStart := 0;

  while cStream < FStreams.Count do
  begin
    StreamLen := TElDataStream(FStreams[cStream]).Stream. Size ;

    // current stream includes FPosition
    if StreamStart + StreamLen > FPosition then
      break;

    Inc(StreamStart, StreamLen);
    inc(cStream);
  end;

  if cStream = FStreams.Count then
  begin
    result := 0;
    exit;
  end
  else
    while cStream < FStreams.Count do
    begin
      CurStream := TElDataStream(FStreams[cStream]).Stream;
      CurStream.Position := FPosition - StreamStart;
      CurToRead := Min(CurStream. Size  - CurStream.Position, LeftToRead);
      iStreamRead := CurStream.Read( PByteArray(Buffer)[Offset] ,  CurToRead);
      Inc(FPosition, iStreamRead);      
      Inc(result, iStreamRead);
      Inc(Offset, iStreamRead);
      Dec(LeftToRead, iStreamRead);
      if LeftToRead = 0 then
        break;
      Inc(cStream);
      Inc(StreamStart, CurStream. Size );
    end;
end;

function TElMultiStream.Seek(Offset: Longint; Origin: Word): Longint;
begin
  result := Seek(Int64(Offset), Origin);
end;

function TElMultiStream.Seek(const Offset: Int64; Origin: {$ifdef D_6_UP}TSeekOrigin {$else}Word {$endif}): Int64;
var Total : Int64;
begin
  Total := GetTotalSize;
  if Origin =   {$ifdef D_6_UP}soEnd {$else}soFromEnd {$endif}   then
  begin
    if Offset >= Total then
      FPosition := 0
    else
    if Offset >= 0 then
      FPosition := Total - Offset;
  end
  else
  if Origin =   {$ifdef D_6_UP}soCurrent {$else}soFromCurrent {$endif}   then
  begin
    if (Offset < 0) then
      FPosition := Max(0, Total + Offset)
    else
    if (Offset > 0) then
      FPosition := Min(Total, Total + Offset);
  end
  else
  if (Origin =   {$ifdef D_6_UP}soBeginning {$else}soFromBeginning {$endif}  ) and (Offset >= 0) then
  begin
    FPosition := Min(Total, Offset);
  end;
  result := FPosition;
end;

function TElMultiStream.Read(var Buffer; Count: Longint): Longint;
begin
  result := DoRead(Pointer(@Buffer), 0, Count);
end;

function TElMultiStream.Write(const Buffer; Count: Longint): Longint;
begin
  result := 0;
end;

function TElMultiStream.GetTotalSize : Int64;
var i : integer;
begin
  if FSizeValid then
  begin
    result := FTotalSize;
    exit;
  end;
  result := 0;
  for i := 0 to FStreams.Count - 1 do
  begin
    Inc(result, TElDataStream(FStreams[i]).Stream. Size );
  end;
  FTotalSize := result;
  FSizeValid := true;
end;



{ TElReadCachingStream }

constructor TElReadCachingStream.Create();
begin
  inherited Create;
  FStream := nil;
  SetLength(FCache, STREAM_CACHE_SIZE);
  FCacheSize := STREAM_CACHE_SIZE;
  FDataInCache := 0;
  FNextDataInCache := 0;
end;

 destructor  TElReadCachingStream.Destroy;
begin
  ReleaseArray(FCache);
  FStream := nil;
  inherited;
end;


function TElReadCachingStream.Seek(Offset: Longint; Origin: Word): Longint;
begin
  Result := Seek(Int64(Offset), {$ifdef D_6_UP}TSeekOrigin {$endif}(Origin));
end;

function TElReadCachingStream.Seek(const Offset: Int64; Origin: {$ifdef D_6_UP}TSeekOrigin {$else}Word {$endif}): Int64;
begin
  if not Assigned(FStream) then
    raise ESecureBlackboxError.Create(SStreamNotAssigned);

  if Origin =   {$ifdef D_6_UP}soCurrent {$else}soFromCurrent {$endif}   then
  begin
    if (Offset >= 0) and (FNextDataInCache + Offset < FDataInCache) then
    begin
      Inc(FNextDataInCache, Offset);
      Result := FStream.Position - (FDataInCache - FNextDataInCache);
    end
    else if (Offset < 0) and (Offset + FNextDataInCache >= 0) then
    begin
      FNextDataInCache := FNextDataInCache + Offset;
      Result := FStream.Position - (FDataInCache - FNextDataInCache);
    end
    else
    begin
      Result := FStream.Seek(Offset, Origin);
      FNextDataInCache := 0;
      FDataInCache := 0;
    end;
  end
  else
  begin
    Result := FStream.Seek(Offset, Origin);
    FDataInCache := 0;
    FNextDataInCache := 0;
  end;
end;

function TElReadCachingStream.Write(const Buffer; Count: Longint): Longint;
begin
  Result := 0;
end;



function TElReadCachingStream.Read(var Buffer; Count: Longint): Longint;
var
  Ptr :  pointer ;
begin
  if not Assigned(FStream) then
    raise ESecureBlackboxError.Create(SStreamNotAssigned);

  if (Count <= FDataInCache - FNextDataInCache) then
  begin
    SBMove(FCache[FNextDataInCache], Buffer, Count);
    Result := Count;
    Inc(FNextDataInCache, Count);
  end
  else
  begin
    Ptr :=  @Buffer ;
    if (FNextDataInCache < FDataInCache) then
    begin
      SBMove(FCache[FNextDataInCache], Buffer, FDataInCache - FNextDataInCache);
      Result := FDataInCache - FNextDataInCache;
      Dec(Count, Result);
      Inc( PtrUInt (Ptr), Result);
    end
    else
      Result := 0;

    if (Count > FCacheSize) then
    begin
      Result := Result + FStream.Read( Ptr^ , Count);
      FDataInCache := 0;
      FNextDataInCache := 0;
    end
    else
    begin
      FDataInCache := FStream.Read( FCache[0] , FCacheSize);
      if (FDataInCache < Count) then
        Count := FDataInCache;

      SBMove(FCache[0], Ptr^, Count);
      FNextDataInCache := Count;
      Inc(Result, Count);
    end;
  end;
end;

procedure TElReadCachingStream.SetCacheSize(Value : integer);
begin
  if (FDataInCache > 0) then
    { we assume that stream position is just after currently read cache, so forced to seek }
    FStream.Seek(-FDataInCache,   {$ifdef D_6_UP}soCurrent {$else}soFromCurrent {$endif}  );

  SetLength(FCache, Value);
  FCacheSize := Value;
  FDataInCache := 0;
  FNextDataInCache := 0;
end;

procedure TElReadCachingStream.SetStream(Stream : TElStream);
begin
  FStream := Stream;
  FDataInCache := 0;
  FNextDataInCache := 0;
end;

{ TElWriteCachingStream }

constructor TElWriteCachingStream.Create();
begin
  inherited Create;
  FStream := nil;
  SetLength(FCache, STREAM_CACHE_SIZE);
  FCacheSize := STREAM_CACHE_SIZE;
  FDataInCache := 0;
end;

 destructor  TElWriteCachingStream.Destroy;
begin
  if Assigned(FStream) then
    Flush;
  ReleaseArray(FCache);
  FStream := nil;
  inherited;
end;


function TElWriteCachingStream.Seek(Offset: Longint; Origin: Word): Longint;
begin
  Result := Seek(Int64(Offset), Origin);
end;

function TElWriteCachingStream.Seek(const Offset: Int64; Origin: {$ifdef D_6_UP}TSeekOrigin {$else}Word {$endif}): Int64;
begin
  if not Assigned(FStream) then
    raise ESecureBlackboxError.Create(SStreamNotAssigned);

  Flush;
  Result := FStream.Seek(Offset, Origin);
end;

function TElWriteCachingStream.Write(const Buffer; Count: Longint): Longint;
var
  Sz : integer;
  Ptr : pointer;
begin
  Result := Count;

  if Count < FCacheSize - FDataInCache then
  begin
    SBMove(Buffer, FCache[FDataInCache], Count);
    Inc(FDataInCache, Count);
  end
  else
  begin
    Sz := FCacheSize - FDataInCache;
    SBMove(Buffer, FCache[FDataInCache], Sz);
    FStream.Write(FCache[0], FCacheSize);
    Ptr := @Buffer;
    Inc(PtrUInt(Ptr), Sz);
    Dec(Count, Sz);

    if Count > FCacheSize then
    begin
      FStream.Write(Ptr^, Count);
      FDataInCache := 0;
    end
    else
    begin
      SBMove(Ptr^, FCache[0], Count);
      FDataInCache := Count;
    end;
  end;
end;

procedure TElWriteCachingStream.Flush;
begin
  if not Assigned(FStream) then
    raise ESecureBlackboxError.Create(SStreamNotAssigned);

  if FDataInCache > 0 then
  begin
    FStream.Write(FCache[0], FDataInCache);
    FDataInCache := 0;
  end;

end;


function TElWriteCachingStream.Read(var Buffer; Count: Longint): Longint;
begin
  Result := 0;
end;

procedure TElWriteCachingStream.SetCacheSize(Value : integer);
begin
  Flush;

  SetLength(FCache, Value);
  FCacheSize := Value;
  FDataInCache := 0;
end;

procedure TElWriteCachingStream.SetStream(Stream : TElStream);
begin
  FStream := Stream;
  FDataInCache := 0;
end;


end.
