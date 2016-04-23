(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SBChSUnicode.inc}


unit SBChSClasses;

interface


uses
  Classes,
  SysUtils,
  SBTypes;

type
  TPlBufferedInStream = class(TStream)
  private
    FBuffer: PByte;
    FBuffPos: Integer;
    FBuffSize: Integer;
    FBuffMaxSize: Integer;
    FStream: TStream;
    FOwnStream: Boolean;
  protected
    procedure SetSize(NewSize: Longint); override;
  public
    constructor Create(Stream: TStream; OwnStream: Boolean = True;
      BufferSize: Integer = 4096);
    destructor Destroy; override;

    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
    function Seek(Offset: Longint; Origin: Word): Longint; override;
  end;

  TPlBufferedOutStream = class(TStream)
  private
    FBuffer: PByte;
    FBuffSize: Integer;
    FBuffMaxSize: Integer;
    FStream: TStream;
    FOwnStream: Boolean;
  protected
    procedure FlushBuffer;
    procedure SetSize(NewSize: Longint); override;
  public
    constructor Create(Stream: TStream; OwnStream: Boolean = True;
      BufferSize: Integer = 4096);
    destructor Destroy; override;

    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
    function Seek(Offset: Longint; Origin: Word): Longint; override;
  end;

  TPlNewWideLineEvent = procedure (Sender: TObject; Line: PWideChar;
    LineLength: Integer) of Object;
  TPlWideLinesStream = class(TStream)
  private
    FBuffer: PByte;
    FBufPos: Integer;
    FBufSize: Integer;
    FBufWide: PWideChar;
    FLastWide: WideChar;
    FOnNewLine: TPlNewWideLineEvent;
  protected
    procedure DoNewLine;
  public
    constructor Create(OnNewLine: TPlNewWideLineEvent);
    destructor Destroy; override;

    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
    function Seek(Offset: Longint; Origin: Word): Longint; override;

    property OnNewLine: TPlNewWideLineEvent read FOnNewLine write FOnNewLine;
  end;
  {
  TPlBufferedIOStream = class(TStream)
  end;
  }


implementation


uses

{$ifdef VCL60}
  RTLConsts,
 {$endif}

{$ifdef SB_WINDOWS}
  {$ifndef FPC}
  //Consts,
   {$endif}
 {$endif}
  SBUtils
  ;

const   
  SReadError = 'Stream read error';
  SWriteError = 'Stream write error';


{ TPlBufferedInStream }

constructor TPlBufferedInStream.Create(Stream: TStream; OwnStream: Boolean;
  BufferSize: Integer);
begin
  inherited Create;
  FStream := Stream;
  FOwnStream := OwnStream;
  FBuffMaxSize := BufferSize;
  GetMem(FBuffer, FBuffMaxSize);
end;

destructor TPlBufferedInStream.Destroy;
begin
  if FOwnStream then
    FreeAndNil(FStream);
  FreeMem(FBuffer);
  inherited Destroy;
end;

function TPlBufferedInStream.Read(var Buffer; Count: Integer): Longint;
var
  Dst: PAnsiChar;
  PartSize: Integer;
begin
  Result := 0;
  Dst := PAnsiChar(@Buffer);
  while Result < Count do
    begin
      if FBuffPos >= FBuffSize then
        begin
          FBuffSize := FStream.Read(FBuffer^, FBuffMaxSize);
          FBuffPos := 0;
        end;
      if FBuffPos >= FBuffSize then
        Break
      else
        begin
          PartSize := FBuffSize - FBuffPos;
          if PartSize > Count - Result then
            PartSize := Count - Result;
          SBMove(PByteArray(FBuffer)[FBuffPos], Dst^, PartSize);
          Inc(FBuffPos, PartSize);
          Inc(Dst, PartSize);
          Inc(Result, PartSize);
        end;
    end;
end;

function TPlBufferedInStream.Seek(Offset: Integer; Origin: Word): Longint;
begin
  if Origin = soFromCurrent then
    begin
      if (-Offset > FBuffPos) or (Offset > FBuffSize - FBuffPos) then
        Dec(Offset, FBuffSize - FBuffPos)
      else
        begin
          Inc(FBuffPos, Offset);
          Result := FStream.Seek(0, soFromCurrent);
          if Result <> 0 then
            Dec(Result, FBuffSize - FBuffPos);
          Exit;
        end;
    end;
  FBuffSize := 0;
  Result := FStream.Seek(Offset, Origin);
end;

procedure TPlBufferedInStream.SetSize(NewSize: Integer);
begin
  raise EStreamError.Create(SWriteError);
end;

function TPlBufferedInStream.Write(const Buffer; Count: Integer): Longint;
begin
  raise EStreamError.Create(SWriteError);
end;

{ TPlBufferedOutStream }

constructor TPlBufferedOutStream.Create(Stream: TStream;
  OwnStream: Boolean; BufferSize: Integer);
begin
  inherited Create;
  FStream := Stream;
  FOwnStream := OwnStream;
  FBuffMaxSize := BufferSize;
  GetMem(FBuffer, FBuffMaxSize);
end;

destructor TPlBufferedOutStream.Destroy;
begin
  FlushBuffer;
  if FOwnStream then
    FreeAndNil(FStream);
  FreeMem(FBuffer);
  inherited Destroy;
end;

procedure TPlBufferedOutStream.FlushBuffer;
begin
  if FBuffSize > 0 then
    begin
      FStream.WriteBuffer(FBuffer^, FBuffSize);
      FBuffSize := 0;
    end;
end;

function TPlBufferedOutStream.Read(var Buffer; Count: Integer): Longint;
begin
  raise EStreamError.Create(SReadError);
end;

function TPlBufferedOutStream.Seek(Offset: Integer; Origin: Word): Longint;
begin
  FlushBuffer;
  Result := FStream.Seek(Offset, Origin);
end;

procedure TPlBufferedOutStream.SetSize(NewSize: Integer);
begin
  FlushBuffer;
  FStream.Size := NewSize;
end;

function TPlBufferedOutStream.Write(const Buffer; Count: Integer): Longint;
var
  Src: PAnsiChar;
  PartSize: Integer;
begin
  Src := PAnsiChar(@Buffer);
  Result := 0;
  while Result < Count do
    begin
      PartSize := FBuffMaxSize - FBuffSize;
      if PartSize > Count - Result then
        PartSize := Count - Result;
      SBMove(Src^, PByteArray(FBuffer)[FBuffSize], PartSize);
      Inc(Src, PartSize);
      Inc(Result, PartSize);
      if FBuffSize >= FBuffMaxSize then
        FlushBuffer;
    end;
end;

{ TPlWideLinesStream }

constructor TPlWideLinesStream.Create(OnNewLine: TPlNewWideLineEvent);
begin
  inherited Create;
  FOnNewLine := OnNewLine;
end;

destructor TPlWideLinesStream.Destroy;
begin
  if FBufPos > 1 then
    DoNewLine;
  FreeMem(FBuffer);
  inherited Destroy;
end;

procedure TPlWideLinesStream.DoNewLine;
begin
  if Assigned(FOnNewLine) then
    FOnNewLine(Self, Pointer(FBuffer), (FBufPos shr 1) - 1);
  FBufWide := Pointer(FBuffer);
  FBufPos := 0;
end;

function TPlWideLinesStream.Read(var Buffer; Count: Integer): Longint;
begin
  raise EStreamError.Create(SReadError);
end;

function TPlWideLinesStream.Seek(Offset: Integer; Origin: Word): Longint;
begin
  Result := 0;
end;

function TPlWideLinesStream.Write(const Buffer; Count: Integer): Longint;
var
  Wide: WideChar;
begin
  Result := 0;
  while Result < Count do
    begin
      if FBufPos = FBufSize then
        begin
          FBufWide := Pointer(PtrUInt(FBufWide) - PtrUInt(FBuffer));
          Inc(FBufSize, 1024);
          if FBuffer = nil then
            GetMem(FBuffer, FBufSize)
          else
            ReallocMem(FBuffer, FBufSize);
          FBufWide := Pointer(PtrUInt(FBuffer) + PtrUInt(FBufWide));
        end;
      PByteArray(FBuffer)[FBufPos] := PByteArray(@Buffer)[Result];
      Inc(FBufPos);
      Inc(Result);
      if (FBufPos and 1) = 0 then
        begin
          Wide := FBufWide^;
          if Wide = #13 then
            DoNewLine
          else if Wide = #10 then
            begin
              if FLastWide <> #13 then
                DoNewLine
              else
                begin
                  FBufWide := Pointer(FBuffer);
                  FBufPos := 0;
                end;
            end
          else
            Inc(FBufWide);
          FLastWide := Wide;
        end;
    end;
end;


end.
