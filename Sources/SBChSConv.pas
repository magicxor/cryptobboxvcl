(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SBChSUnicode.inc}

unit SBChSConv;

interface

uses
  {$ifdef FPC_POSIX}
  cwstring,  // needed to make TStringList.Sorted/Add/Find/IndexOf work correctly on initialization
   {$endif}
  {$ifdef WIN32}
  Windows,
   {$endif}
  Classes,
  SysUtils,
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBSharedResource,
  SBConstants,
  SBChSConvBase;

  {$DEFINE default_charset_iso_8859}
  {$ifdef SB_WINDOWS}
      {$UNDEF default_charset_iso_8859}
   {$endif}

type

  TPlConvertOption = 
  (
    coContinuePrevious, coNoDefaultChar, coInvalidCharException,
    coWriteFileHeader, coWriteLineBegin, coWriteLineEnd
  );
  
  TPlConvertOptions =  set of TPlConvertOption;


type
  
  TPlConverterLineState = 
    (lsStarted, lsFinished);

  TPlConverterLineStates = set of TPlConverterLineState;

  TPlConverter =  class( TPersistent )
  private
    fInBuffer: IPlConvBuffer;
    fOutBuffer: IPlConvBuffer;
    fLineStates: TPlConverterLineStates;

    fSrc: IPlCharset;
    fDst: IPlCharset;

    //fSrcAnsi: TElNativeStream;
    //fDstAnsi: TElNativeStream;
    //fSrcWide: TElNativeStream;
    //fDstWide: TElNativeStream;
    //fSrcByte: TElNativeStream;
    //fDstByte: TElNativeStream;
  protected
    function GetDstName: string;
    function GetSrcName: string;
    procedure SetDstName(const Value: string);
    procedure SetSrcName(const Value: string);
  public
    constructor Create;  overload; 
    constructor Create(const SrcCharset, DstCharset: string);  overload; 
    constructor Create(SrcCharset, DstCharset: IPlCharset);  overload; 
     destructor  Destroy; override;

    procedure Convert(const Source: AnsiString; out Dest: AnsiString;
      Options: TPlConvertOptions);  overload; 
    procedure Convert(Source, Dest: TElNativeStream;
      Options: TPlConvertOptions; MaxChars: Integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});  overload; 

    function IsConvert(const Source: AnsiString; out Dest: AnsiString;
      Options: TPlConvertOptions): Boolean;  overload; 
    function IsConvert(Source, Dest: TElNativeStream;
      Options: TPlConvertOptions; MaxChars: Integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}): Boolean;  overload; 

    procedure ConvertFromUnicode(const Source: UnicodeString; out Dest: AnsiString;
      Options: TPlConvertOptions);
    procedure ConvertToUnicode(const Source: AnsiString; out Dest: UnicodeString;
      Options: TPlConvertOptions);

    function IsConvertFromUnicode(const Source: UnicodeString; out Dest: AnsiString;
      Options: TPlConvertOptions): Boolean;
    function IsConvertToUnicode(const Source: AnsiString; out Dest: UnicodeString;
      Options: TPlConvertOptions): Boolean;
    {
    procedure ConvertBuffer(
      Source: ByteArray; SourceLen: Integer; var SourcePos: Integer;
      Dest: ByteArray; DestLen: Integer; var DestPos: Integer;
      Options: TPlConvertOptions);
    }
    property DstCharset: IPlCharset read fDst;
    property DstCharsetName: string read GetDstName write SetDstName;
    property SrcCharset: IPlCharset read fSrc;
    property SrcCharsetName: string read GetSrcName write SetSrcName;
  end;

  EPlConvError = class(Exception)
  public
    constructor Create(Encoding: Boolean; Charset: IPlCharset; const ErrorMessage: string);
  end;

  TPlCustomUTF = class(TPlCharset)
  private
    fByteOrderBE: Boolean;
  protected
    procedure Reset; override;
  public
    function GetCategory: string; override;
  end;

  TPlUTF32 = class(TPlCustomUTF)
  protected
    function WriteFileHeader: Cardinal; override;
    procedure WriteChar(Char: LongWord); virtual;
    function GetAliases: string; override;
  public
    function ConvertFromUCS(Char: UCS): Integer; override;
    function ConvertToUCS(Stream: TElNativeStream; out Char: UCS): Integer; override;
    function ConvertBufferToUCS(const Buf; Count : Integer; IsLastChunk : Boolean; out Char: UCS): Integer; override;

    function GetDescription: string; override;
  end;

  TPlUTF32BE = class(TPlUTF32)
  protected
    procedure Reset; override;
    procedure WriteChar(Char: LongWord); override;
    function GetAliases: string; override;
  public
    constructor Create; override; 

    function GetDescription: string; override;
  end;

  TPlUTF16 = class(TPlCustomUTF)
  protected
    function WriteFileHeader: Cardinal; override;
    procedure WriteChar(Char: Word); virtual;
    function GetAliases: string; override;
  public
    function ConvertFromUCS(Char: UCS): Integer; override;
    function ConvertToUCS(Stream: TElNativeStream; out Char: UCS): Integer; override;
    function ConvertBufferToUCS(const Buf; Count : Integer; IsLastChunk : Boolean; out Char: UCS): Integer; override;

    function GetDescription: string; override;
  end;

  TPlUTF16BE = class(TPlUTF16)
  protected
    procedure Reset; override;
    procedure WriteChar(Char: Word); override;
    function GetAliases: string; override;
  public
    constructor Create; override; 

    function GetDescription: string; override;
  end;

  TPlUTF8 = class(TPlCharset)
  protected
    function WriteFileHeader: Cardinal; override;
    function GetAliases: string; override;
  public
    function ConvertFromUCS(Char: UCS): Integer; override;
    function ConvertToUCS(Stream: TElNativeStream; out Char: UCS): Integer; override;
    function ConvertBufferToUCS(const Buf; Count : Integer; IsLastChunk : Boolean; out Char: UCS): Integer; override;

    function GetCategory: string; override;
    function GetDescription: string; override;
  end;

  TPlUTF7State = 
    (usDirect, usBase64, usShift);
  
  TPlUTF7 = class(TPlCharset)
  private
    fState: TPlUTF7State;
    fTail: Integer;
    fTailBits: Integer;
  protected
    class function GetBase64(Char: AnsiChar): Integer;
    function WriteLineEnd: Cardinal; override;
    function GetAliases: string; override;
  public
    
    function ConvertFromUCS(Char: UCS): Integer; override;
    function ConvertToUCS(Stream: TElNativeStream; out Char: UCS): Integer; override;
    function ConvertBufferToUCS(const Buf; Count : Integer; IsLastChunk : Boolean; out Char: UCS): Integer; override;

    function GetCategory: string; override;
    function GetDescription: string; override;
  end;

type
  TUserData =   Pointer ;

  TEnumCharsetsProc =  procedure(const Category, Description, Name, Aliases: string;
    UserData: TUserData; var Stop: Boolean);

type
  TPlConvBuffer = class(TInterfacedObject, IPlConvBuffer)
  private
    fData: AnsiString;
    fPosition: Integer;
    fSize: Integer;
   protected 
    procedure Clear(LeaveUnprocessedData : Boolean  =  false);
    procedure Restart;
  public
    function CheckString(Stream: TElNativeStream; const Str: AnsiString;
      Shift: Integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}): Boolean;

    function GetByte(Stream: TElNativeStream; var Exists: TSBBoolean): Byte;
    function GetWide(Stream: TElNativeStream; var Exists: TSBBoolean): Word;
    function GetLong(Stream: TElNativeStream; var Exists: TSBBoolean): LongWord;

    procedure ReturnByte;  overload; 
    procedure ReturnByte(Value: Byte);  overload; 
    procedure ReturnBytes(Count: Integer);

    procedure Flush(Stream: TElNativeStream);
    procedure Put(const Data; Count: Integer);
    procedure PutByte(Value: Byte);
    procedure PutWordLE(Value: Word);
    function RevokeByte: Byte;
  end;

  TDataPtr = Pointer;

  // TElNativeStream.Seek( const Offset: Int64 ...
  {$UNDEF SEEKINT64}
  {$ifdef VCL60}
    {$DEFINE SEEKINT64}
   {$endif}

  // TElNativeStream.SetSize
  {$UNDEF SETSIZEINT64}
  {$UNDEF SETSIZEINT64CONST}
  {$ifdef D_7_UP} // ??? todo: need ckeck in KYLIX_3 (2,1)
     {$DEFINE SETSIZEINT64}
       {$DEFINE SETSIZEINT64CONST}
   {$endif}

  TPlCustomStringStream = class(TElNativeStream)
  private
    fData: TDataPtr;
    fPosition: Integer;
    fSize: Integer;
  protected
    procedure internalSetSize(NewSize: Int64); virtual;
    procedure SetSize(NewSize: Longint); override;
    {$ifdef SETSIZEINT64}
    procedure SetSize({$ifdef SETSIZEINT64CONST}const {$endif} NewSize: Int64); override;
     {$endif}
  public

    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;

    function Seek(Offset: Longint; Origin: Word): Longint; override;
    {$ifdef SEEKINT64}
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64;  overload;  override;
     {$endif}
    procedure Clear;
  end;

  TPlAnsiStringStream = class(TPlCustomStringStream)
  protected
    procedure SetData( const   Value: PAnsiString);
    procedure internalSetSize(NewSize: Int64); override;
  public
    property Data: PAnsiString    write SetData;
  end;

  TPlWideStringStream = class(TPlCustomStringStream)
  protected
    procedure SetData( const  Value: PUnicodeString);
    procedure internalSetSize(NewSize: Int64); override;
  public
    property Data: PUnicodeString    write SetData;
  end;

  TPlByteArrayStream = class(TElNativeStream)
  private
  end;

  TPlCustomStringStreamPool = class
  protected
    FCS : TElSharedResource;
    FFreeStreams : TElList;
    FOccupiedStreams : TElList;
    function InternalAcquireStream: TPlCustomStringStream;
    procedure InternalReleaseStream(Stream: TPlCustomStringStream);
    function CreateUnderlyingStream: TPlCustomStringStream; virtual;
  public
    constructor Create;
     destructor  Destroy; override;
  end;

  TPlAnsiStringStreamPool = class(TPlCustomStringStreamPool)
  protected
    function CreateUnderlyingStream: TPlCustomStringStream; override;
  public
    function AcquireStream: TPlAnsiStringStream;
    procedure ReleaseStream(Stream : TPlAnsiStringStream);
  end;

  TPlWideStringStreamPool = class(TPlCustomStringStreamPool)
  protected
    function CreateUnderlyingStream: TPlCustomStringStream; override;
  public
    function AcquireStream: TPlWideStringStream;
    procedure ReleaseStream(Stream : TPlWideStringStream);
  end;

procedure EnumCharsets(EnumProc: TEnumCharsetsProc; UserData: TUserData); 
function CreateCharset(const Name: string): IPlCharset; 
function CreateCharsetByDescription(const ADescription: string): IPlCharset; 
function CreateSystemDefaultCharset: IPlCharset; 
function GetSystemDefaultCharsetName: string; 
function GetCharsetNameByAlias(const Alias: string): string; 

procedure Initialize; 

implementation

uses
  SyncObjs,
  SBChSConvConsts
  ;
  
var
  G_AnsiStringStreamPool : TPlAnsiStringStreamPool = nil;
  G_WideStringStreamPool : TPlWideStringStreamPool = nil;

function GetAnsiStringStreamPool() : TPlAnsiStringStreamPool;
begin
  if G_AnsiStringStreamPool = nil then
  begin
    AcquireGlobalLock;
    try
      if G_AnsiStringStreamPool = nil then
      begin
        G_AnsiStringStreamPool := TPlAnsiStringStreamPool.Create();
        RegisterGlobalObject(G_AnsiStringStreamPool);
      end;
    finally
      ReleaseGlobalLock;
    end;
  end;
  Result := G_AnsiStringStreamPool;
end;

function GetWideStringStreamPool() : TPlWideStringStreamPool;
begin
  if G_WideStringStreamPool = nil then
  begin
    AcquireGlobalLock;
    try
      if G_WideStringStreamPool = nil then
      begin
        G_WideStringStreamPool := TPlWideStringStreamPool.Create();
        RegisterGlobalObject(G_WideStringStreamPool);
      end;
    finally
      ReleaseGlobalLock;
    end;
  end;
  Result := G_WideStringStreamPool;
end;

type
  TPlCharsetInfo = class
  private
    fAliases: string;
    fCategory: string;
    fCreateProc: TCharsetCreateProc;
    fDescription: string;
    fHandle: TPlCharsetClassPtr;
    fName: string;
  public
    property Aliases: string read fAliases write fAliases;
    property Category: string read fCategory write fCategory;
    property CreateProc: TCharsetCreateProc read fCreateProc write fCreateProc;
    property Description: string read fDescription write fDescription;
    property Handle: TPlCharsetClassPtr read fHandle write fHandle;
    property Name: string read fName write fName;
  end;

{ TPlCharsetInfo }


type
  TRegisterCharsetLibrary = procedure (RegistrationProc: TCharsetLibraryRegProc);  {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif}; 

var
  Charsets:  TSBObjectList ;
  CharsetsNames: TElStringList;
  CharsetsNamesLock:  TCriticalSection ;
  CharsetLibraries: TElStringList;

procedure RegisterCharsetLibraryProc(
  Category, Description, Aliases:  PChar ;
  Handle: TPlCharsetClassPtr;
  CreateProc: TCharsetCreateProc);
var
  Info: TPlCharsetInfo;
  Names: TElStringList;
  Index, I: Integer;
begin
  Names := TElStringList.Create;
  try
    Names.CommaText := Aliases;
    if Names.Count > 0 then
    begin
      for Index := 0 to Names.Count - 1 do
        if CharsetsNames.Find(
          UpperCase(Names[Index])
           , I)
        then
        begin
          Assert(false, 'Duplicated charset name: ' + UpperCase(Names[Index]));
          Exit;
        end;

      Info := TPlCharsetInfo.Create;
      Info.Aliases := Aliases;
      Info.Category := Category;
      Info.CreateProc  :=  CreateProc;
      Info.Description := Description;
      Info.Handle := Handle;
      Info.Name := Names[0];
      Charsets.Add(Info);
      for Index := 0 to Names.Count - 1 do
        CharsetsNames.AddObject(
          UpperCase(Names[Index])
           , Info);
    end;
  finally
    FreeAndNil(Names);
  end;
end;

{$ifndef FPC}
procedure LoadCharsetLibrariesFromPath(const Path: string);
var
  Instance: HINST;
  Result: Integer;
  Proc: TRegisterCharsetLibrary;
  SearchRec: TSearchRec;

  function IncludeTrailingBackslash(const S: string): string;
  begin
    Result := S;
    {$ifndef SB_UNICODE_VCL}
    if not (Result[Length(Result)] in ['\', '/']) then
     {$else}
    if not CharInSet(Result[Length(Result)], ['\', '/']) then
     {$endif}
      Result := Result + '\';
  end;


begin
{.$WARNINGS off}
  Result := FindFirst(IncludeTrailingBackslash(Path) + '*.chl', faAnyFile, SearchRec);
{.$WARNINGS on}
  while Result = 0 do
  begin
    Instance := LoadLibrary( PChar(SearchRec.Name) ) ;
    if Instance <> 0 then
    begin
      {$ifdef SB_WINDOWS}
      Proc := GetProcAddress(Instance, 'RegisterCharsetLibrary');
       {$else}
      Proc := SysUtils.GetProcAddress(Instance, 'RegisterCharsetLibrary');
       {$endif}
      if Assigned(Proc) then
      begin
        Proc(RegisterCharsetLibraryProc);
        CharsetLibraries.AddObject(
          ExtractFileName(SearchRec.Name),
          TObject(Instance)
        );
      end;
    end;
    Result := FindNext(SearchRec);
  end;
  SysUtils.FindClose(SearchRec);
end;

procedure LoadCharsetLibraries;
{$ifdef SB_WINDOWS}
var
  SysDir: string;
 {$endif}
begin
  LoadCharsetLibrariesFromPath(ExtractFilePath(ParamStr(0)));
  {$ifdef SB_WINDOWS}
  SetLength(SysDir, MAX_PATH);
  SetLength(SysDir, GetSystemDirectory(PChar(SysDir), MAX_PATH));
  LoadCharsetLibrariesFromPath(SysDir);
   {$endif}
end;
 {$endif SB_NET}

procedure InitCharsets;
begin
  if CharsetsNamesLock = nil then
    Initialize();
  CharsetsNamesLock.Acquire();
  try
    if CharsetsNames.Count = 0 then
    begin

      RegisterCharsetLibrary( RegisterCharsetLibraryProc );
    end;
  finally
    CharsetsNamesLock.Release();
  end;

//  if CharsetsNames.Count = 0 then
//  begin
//  {$ifdef SB_NET}
//  System.Threading.Monitor.Enter(TObject(CharsetsNames));
//  try
//    if CharsetsNames.Count = 0 then
//    begin
//  {$endif}
//    RegisterCharsetLibrary({$ifndef SB_NET}RegisterCharsetLibraryProc{$else}new TCharsetLibraryRegProc(RegisterCharsetLibraryProc){$endif});
//    {$ifndef FPC}
//    {$ifdef SB_VCL}
//    LoadCharsetLibraries;
//    {$endif ifndef SB_NET}
//	{$endif}
//
//  {$ifdef SB_NET}
//    end;
//  finally
//    System.Threading.Monitor.Exit(TObject(CharsetsNames));
//  end;
//  {$endif}
//  end;
end;

{$ifndef FPC}
procedure UnloadCharsetLibraries;
var
  Index: Integer;
begin
  for Index := 0 to CharsetLibraries.Count - 1 do
    {$ifdef CLX_USED}SysUtils. {$endif}FreeLibrary( HINST(CharsetLibraries.Objects[Index]) );
end;
 {$endif}

procedure EnumCharsets(EnumProc: TEnumCharsetsProc; UserData: TUserData);
var
  Stop: Boolean;
  Index: Integer;
begin
  InitCharsets;
  Stop := False;
  for Index := 0 to Charsets.Count - 1 do
  begin
    with TPlCharsetInfo(Charsets[Index]) do
       EnumProc(Category, Description, Name, Aliases, UserData , Stop );
    if Stop then
      Break;
  end;
end;

function CreateCharset(const Name: String): IPlCharset;
var
  Index: Integer;
  UpperName : string;
begin
  Uppername := Uppercase(Name);

  InitCharsets;
  if CharsetsNames.Find(UpperName, Index) then
    with TPlCharsetInfo(CharsetsNames.Objects[Index]) do
      Result := CreateProc(Handle)
  else
    Result := TPlISO_8859_1.Create;
end;

function CreateCharsetByDescription(const ADescription: string): IPlCharset;
var
  Index: Integer;
begin
  InitCharsets;
  Result := nil;
  for Index := 0 to CharsetsNames.Count - 1 do
  begin
    with TPlCharsetInfo(CharsetsNames.Objects[Index]) do
      if CompareText(Description, ADescription) = 0 then
      begin
        Result := CreateProc(Handle);
        Break;
      end;
  end;
  if Result = nil then
    Result := TPlISO_8859_1.Create;
end;

function CreateSystemDefaultCharset: IPlCharset;
begin
  {$ifdef default_charset_iso_8859}
  CreateCharset('iso-8859-1');
   {$else}
  CreateCharset(IntToStr(GetACP));
   {$endif}
end;

function GetSystemDefaultCharsetName: string;
begin
  {$ifdef default_charset_iso_8859}
  Result := 'iso-8859-1';
   {$else}
  Result := GetCharsetNameByAlias(IntToStr(GetACP));
   {$endif}
end;

function GetCharsetNameByAlias(const Alias: string): string;
var
  Index: Integer;
  UpperAlias : string;
begin
  UpperAlias := Uppercase(Alias);

  InitCharsets;
  if CharsetsNames.Find(UpperAlias, Index) then
    Result := TPlCharsetInfo(CharsetsNames.Objects[Index]).Name
  else
    Result := 'iso-8859-1';
end;

{ TPlConvBuffer }

function TPlConvBuffer.CheckString(Stream: TElNativeStream; const Str: AnsiString;
  Shift: Integer): Boolean;
var
  I, Len, Pos: Integer;
  {$ifdef SB_NO_BOOLEAN_VAR_PARAMS}
  Res : TSBBoolean;
   {$endif}
begin
  Pos := fPosition;
  Len := Length(Str);
  Result := Len > 0;
  while Result and (fSize < Len) do
  {$ifndef SB_NO_BOOLEAN_VAR_PARAMS}
    GetByte(Stream, Result);
   {$else}
  begin
    GetByte(Stream, Res);
    Result := Res;
  end;
   {$endif}
  if Result then
  begin
    I := 0;
    while Result and (I < Len) do
    begin
      Result := Ord(fData[I + Pos + AnsiStrStartOffset]) = Ord(Str[I + AnsiStrStartOffset]) + Shift;
      (*
      {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
      Result := fData[I + Pos + AnsiStrStartOffset] = Str[I + Shift + AnsiStrStartOffset];
      {$else}
      old pascal variant: Result := PBytes(Pointer(fData))[I + Pos] = PBytes(Pointer(Str))[I] + Shift;
      {$endif}
      *)
      Inc(I);
    end;
  end;
  if Result then
    fPosition := Pos + Len
  else
    fPosition := Pos;
end;

procedure TPlConvBuffer.Clear(LeaveUnprocessedData : Boolean  =  false);
begin
  if (fSize = fPosition) or not LeaveUnprocessedData then
  begin
    fSize := 0;
    fPosition := 0;
  end
  else
  begin
    SBMove(PAnsiChar(Pointer(fData))[fPosition], PAnsiChar(Pointer(fData))^,
      fSize - fPosition);
    Dec(fSize, fPosition);
    fPosition := 0;
  end;
end;

procedure TPlConvBuffer.Flush(Stream: TElNativeStream);
begin
  if fSize = 0 then
    exit;
    
  Stream.WriteBuffer(PAnsiChar(Pointer(fData))^, fPosition);
  fPosition := 0;
  fSize := 0;
end;

function TPlConvBuffer.GetByte(Stream: TElNativeStream; var Exists: TSBBoolean): Byte;
begin
  if (fSize > 0) and (fPosition < fSize) then
  begin
    Exists := true;
    Result := Byte(PAnsiChar(fData)[fPosition]);
    Inc(fPosition);
  end
  else
  begin
    Exists := Stream.Read(Result, 1) = 1;
    if Exists then
    begin
      Inc(fSize);
      if Length(fData) < fSize then
        SetLength(fData, (fSize + 7) and not 7);
      PAnsiChar(Pointer(fData))[fPosition] := AnsiChar(Result);
      Inc(fPosition);
    end
    else
    begin
      Result := 0;
    end;
  end;
end;

function TPlConvBuffer.GetLong(Stream: TElNativeStream;
  var Exists: TSBBoolean): LongWord;
begin
  Result := GetWide(Stream, Exists);
  if Exists then
    Result := (GetWide(Stream, Exists) shl 16) or Result;
  if not Exists then
    ReturnBytes(2);
end;

function TPlConvBuffer.GetWide(Stream: TElNativeStream; var Exists: TSBBoolean): Word;
begin
  Result := GetByte(Stream, Exists);
  if Exists then
    begin
      Result := (GetByte(Stream, Exists) shl 8) or Result;
      if not Exists then
        ReturnByte;
    end;
end;

procedure TPlConvBuffer.Put(const Data; Count: Integer);
begin
  Inc(fSize, Count);
  if Length(fData) < fSize then
    SetLength(fData, (fSize + 7) and not 7);
  SBMove(Data, PAnsiChar(Pointer(fData))[fPosition], Count);
  Inc(fPosition, Count);
end;

procedure TPlConvBuffer.PutByte(Value: Byte);
begin
  Inc(fSize);
  if Length(fData) < fSize then
    SetLength(fData, (fSize + 7) and not 7);

  fData[fPosition + AnsiStrStartOffset] := AnsiChar(Value);
  Inc(fPosition);
end;
(*
{$ifndef SB_JAVA}
{$ifndef SB_VCL}
var
  Buff: array[0..0]of Byte;
begin
  Buff[0] := Value;
  Put(TBytes(Buff), 0, 1);
end;
{$else}
begin
  Put(Value, 1);
end;
{$endif}
{$else}
var
  Buff: TBytes;
begin
  SetLength(Buff, 1);
  Buff[0] := Value;
  Put(TBytes(Buff), 0, 1);
end;
{$endif}
*)

procedure TPlConvBuffer.PutWordLE(Value: Word);
begin
  Inc(fSize, 2);
  if Length(fData) < fSize then
    SetLength(fData, (fSize + 7) and not 7);

  fData[fPosition + AnsiStrStartOffset] := AnsiChar(Value and $FF);
  fData[fPosition + 1 + AnsiStrStartOffset] := AnsiChar((Value shr 8) and $FF);
  Inc(fPosition, 2);
end;

procedure TPlConvBuffer.Restart;
begin
  fPosition := 0;
end;

procedure TPlConvBuffer.ReturnByte(Value: Byte);
begin
  Dec(fPosition);
  fData[fPosition + AnsiStrStartOffset] := AnsiChar(Value);
  (*
  {$ifndef SB_VCL}
  fData[fPosition {$ifndef SB_NET}+1{$endif}] := AnsiChar(Value);
  {$else}
  PAnsiChar(fData)[fPosition] := AnsiChar(Value);
  {$endif}
  *)
end;

procedure TPlConvBuffer.ReturnByte;
begin
  Dec(fPosition);
end;

procedure TPlConvBuffer.ReturnBytes(Count: Integer);
begin
  Dec(fPosition, Count);
  if fPosition < 0 then
    fPosition := 0;
end;

function TPlConvBuffer.RevokeByte: Byte;
begin
  Dec(fSize);
  Dec(fPosition);
  Result := Byte(fData[fPosition + AnsiStrStartOffset]);
  (*
  {$ifndef SB_VCL}
  Result := Byte(fData[fPosition {$ifndef SB_NET}+1{$endif}]);
  {$else}
  Result := PBytes(fData)[fPosition];
  {$endif}
  *)
end;

{ EPlConvError }

constructor EPlConvError.Create(Encoding: Boolean; Charset: IPlCharset; const ErrorMessage: string);
begin
  if Encoding then
    inherited CreateFmt(SEncodingError, [Charset.GetDescription, ErrorMessage])
  else
    inherited CreateFmt(SDecodingError, [Charset.GetDescription, ErrorMessage]);
end;

{ TPlCustomStringStream }

function TPlCustomStringStream.Read(var Buffer; Count: Integer): Longint;
begin
  if (Count <= 0)
    then
  begin
    Result := 0;
    exit;
  end;
  Result := fSize - fPosition;
  if Result = 0 then
    Exit;
  if Result > Count then
    Result := Count;
  SBMove(PAnsiChar(fData^)[fPosition], Buffer, Result); // Debug: PChar(@Buffer)^
  Inc(fPosition, Result);
end;

function TPlCustomStringStream.Seek(Offset: Integer; Origin: Word): Longint;
begin
  case Origin of
    soFromBeginning: fPosition := Offset;
    soFromCurrent: Inc(fPosition, Offset);
    soFromEnd: fPosition := fSize + Offset;
  end;
  if fPosition > fSize then
    internalSetSize(fPosition);
  Result := fPosition;
end;

{$ifdef SEEKINT64}
function TPlCustomStringStream.Seek(const Offset: Int64; Origin: TSeekOrigin): Int64;
begin
  case Origin of
    soBeginning: fPosition := Offset;
    soCurrent: Inc(fPosition, Offset);
    soEnd: fPosition := fSize + Offset;
  end;
  if fPosition > fSize then
    internalSetSize(fPosition);
  Result := fPosition;
end;
 {$endif}



procedure TPlCustomStringStream.internalSetSize(NewSize: Int64);
begin
  { after template: }
  if NewSize < 0 then
    NewSize := 0;
  fSize := NewSize;
  if fPosition > fSize then
    fPosition := fSize;
end;

procedure TPlCustomStringStream.SetSize(NewSize: Integer);
begin
  internalSetSize(NewSize);
end;

{$ifdef SETSIZEINT64}
procedure TPlCustomStringStream.SetSize({$ifdef SETSIZEINT64CONST}const {$endif} NewSize: Int64);
begin
  internalSetSize(NewSize);
end;
 {$endif}



function TPlCustomStringStream.Write(const Buffer; Count: Integer): Longint;
begin
  if Count <= 0 then
  begin
    Result := 0;
    exit;
  end;
  Result := fPosition + Count;
  if Result > fSize then
    internalSetSize(Result);
  SBMove(Buffer, PAnsiChar(fData^)[fPosition], Count);
  fPosition := Result;
  Result := Count;
end;

procedure TPlCustomStringStream.Clear;
begin
  fData := nil;
  fSize := 0;
  fPosition := 0;
end;


{ TPlAnsiStringStream }


procedure TPlAnsiStringStream.SetData( const  Value: PAnsiString);
begin
  fData := (Value);
  fPosition := 0;
  fSize := Length(PAnsiString(fData)^);
end;

procedure TPlAnsiStringStream.internalSetSize(NewSize: Int64);
begin
  if NewSize < 0 then
    NewSize := 0;
  SetLength(PAnsiString(fData)^, NewSize);
  inherited internalSetSize(NewSize);
end;

{ TPlWideStringStream }


procedure TPlWideStringStream.SetData( const  Value: PUnicodeString);
begin
  fData := Value;
  fPosition := 0;

  if fData <> nil then
    fSize := System.Length(PUnicodeString(fData)^) shl 1
  else
    fSize := 0;
end;

procedure TPlWideStringStream.internalSetSize(NewSize: Int64);
begin
  // Size comes in bytes
  if NewSize < 0 then
    NewSize := 0;
  NewSize := ((NewSize + 1) shr 1) shl 1; // make an even number
  SetLength(PUnicodeString(fData)^, NewSize shr 1);
  inherited internalSetSize(NewSize);
end;

function SwapWord(Value: Word): Word;
begin
  Result := (Byte(Value) shl 8) or (Value shr 8);
end;

function SwapLong(Value: LongWord): LongWord;
begin
  Result := ((Value and $000000FF) shl 24) or
    ((Value and $0000FF00) shl 8) or
    ((Value and $00FF0000) shr 8) or
    ((Value and $FF000000) shr 24);
//  Result := (Word(Value) shl 16) or (Value shr 16);
end;

{ TPlConverter }

procedure TPlConverter.Convert(const Source: AnsiString; out Dest: AnsiString;
  Options: TPlConvertOptions);
var
  lSrcAnsi, lDstAnsi : TPlAnsiStringStream;
begin

  if Length(Source)=0 then
  begin
    SetLength(Dest, 0);
    exit;
  end;

  //if CompareText( SrcCharsetName, DstCharsetName ) = 0 then
  if fSrc = fDst then
  begin
    Dest := Source;
    exit;
  end;

  lSrcAnsi := GetAnsiStringStreamPool().AcquireStream();
  TPlAnsiStringStream(lSrcAnsi).Data :=   @  Source;
  // Debug: PAnsiChar(TPlAnsiStringStream(fSrcAnsi).fData^)

  lDstAnsi := GetAnsiStringStreamPool().AcquireStream();

  Dest := '';
  TPlAnsiStringStream(lDstAnsi).Data :=   @  Dest;
  // Debug: PAnsiChar(TPlAnsiStringStream(fDstAnsi).fData^)

  try
    Convert(lSrcAnsi, lDstAnsi, Options, 0);

  finally
    GetAnsiStringStreamPool().ReleaseStream(lDstAnsi);
    GetAnsiStringStreamPool().ReleaseStream(lSrcAnsi);
  end;
end;

procedure TPlConverter.Convert(Source, Dest: TElNativeStream; Options: TPlConvertOptions;
  MaxChars: Integer);
var
  Char: UCS;
  Done, CharsConverted: Integer;
  Exists: TSBBoolean;
begin
  if (Source=nil) or (Dest=nil)
    or (Source.Size=0)
    or ( (Source.Size-Source.Position)=0)
  then
    exit;

  if MaxChars = 0 then
    MaxChars := MaxInt;
  CharsConverted := 0;
  if coContinuePrevious in Options then
    fInBuffer.Restart
  else
  begin
    fSrc.Reset;
    fDst.Reset;
  end;
  if ( coWriteFileHeader in Options ) 
    {$ifndef SB_NO_FILESTREAM}
    or
    ((Dest is   TFileStream  )
    and (Dest.Position = 0)) 
     {$endif}
    then
    fDst.WriteFileHeader;
  if  coWriteLineBegin in Options  then
  begin
    fDst.WriteLineBegin;
    fLineStates := {$ifdef SB_NO_OPENARRAY_SET_ASSIGNMENT}ObjectArray {$endif}([lsStarted]);
  end;
  while True do
  begin
    if (fSrc.ConvertToUCS(Source, Char) = 0) and (Char = UCSCharIllegal) then
    begin
      Exists := false;
      Char := UCS(fInBuffer.GetByte(Source, Exists));
      if not Exists then
        Break;

      if  coInvalidCharException in Options  then
      begin
        if Char = UCSCharIllegal then
          raise EPlConvError.Create(False, fSrc, SIllegalCharacter)
        else
          raise EPlConvError.Create(True, fDst, SIllegalCharacter);
      end
      else
      if not ( coNoDefaultChar in Options ) then
      begin
        fDst.WriteDefaultChar;
        fInBuffer.Clear(true);
        fOutBuffer.Flush(Dest);
        Inc(CharsConverted);
        if CharsConverted >= MaxChars then
          Break;

        Continue;
      end;      
    end;

    if (Char = $0D) or (Char = $0A) then
    begin
      if not (lsFinished in fLineStates) then
      begin
        fDst.WriteLineEnd;
        fLineStates := {$ifdef SB_NO_OPENARRAY_SET_ASSIGNMENT}ObjectArray {$endif}([lsFinished]);
      end
    end
    else
    if not (lsStarted in fLineStates) then
    begin
      fDst.WriteLineBegin;
      fLineStates := {$ifdef SB_NO_OPENARRAY_SET_ASSIGNMENT}ObjectArray {$endif}([lsStarted]);
    end;

    if Char = UCSCharIllegal then
      Done := -1
    else
      if Char = UCSCharIgnore then
      Done := 0
    else
      Done := fDst.ConvertFromUCS(Char);
    if Done < 0 then
    begin
      if  coInvalidCharException in Options  then
      begin
        if Char = UCSCharIllegal then
          raise EPlConvError.Create(False, fSrc, SIllegalCharacter)
        else
          raise EPlConvError.Create(True, fDst, SIllegalCharacter);
      end
      else
      if not ( coNoDefaultChar in Options ) then
        fDst.WriteDefaultChar;
    end;
    fInBuffer.Clear(true);
    fOutBuffer.Flush(Dest);
    Inc(CharsConverted);
    if CharsConverted >= MaxChars then
      Break;
  end;//of: while True

  if  coWriteLineEnd in Options  then
  begin
    fDst.WriteLineEnd;
    fLineStates := {$ifdef SB_NO_OPENARRAY_SET_ASSIGNMENT}ObjectArray {$endif}([lsFinished]);
    fOutBuffer.Flush(Dest);
  end;
end;

function TPlConverter.IsConvert(const Source: AnsiString; out Dest: AnsiString;
  Options: TPlConvertOptions): Boolean;
begin
  try
    Convert(Source, Dest,
      Options + [coInvalidCharException]
        );
    Result := True;
  except
    on e: EPlConvError do
      Result := False;
  end;
end;

function TPlConverter.IsConvert(Source, Dest: TElNativeStream;
  Options: TPlConvertOptions; MaxChars: Integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}): Boolean;
begin
  try
    Convert(Source, Dest,
      Options + [coInvalidCharException]
       , MaxChars );
    Result := True;
  except
    on e: EPlConvError do
      Result := False;
  end;
end;

procedure TPlConverter.ConvertFromUnicode(const Source: UnicodeString;
  out Dest: AnsiString; Options: TPlConvertOptions);
var
  lSrcWide : TPlWideStringStream;
  lDstAnsi : TPlAnsiStringStream;
begin
  lSrcWide := GetWideStringStreamPool().AcquireStream();
  TPlWideStringStream(lSrcWide).Data :=   @  Source;

  lDstAnsi := GetAnsiStringStreamPool().AcquireStream();

  SetLength(Dest, 0);
  TPlAnsiStringStream(lDstAnsi).Data :=   @  Dest;

  try
    Convert(lSrcWide, lDstAnsi, Options, 0);

  finally
    GetAnsiStringStreamPool().ReleaseStream(lDstAnsi);
    GetWideStringStreamPool().ReleaseStream(lSrcWide);
  end;
end;

procedure TPlConverter.ConvertToUnicode(const Source: AnsiString;
  out Dest: UnicodeString; Options: TPlConvertOptions);
var
  lSrcAnsi : TPlAnsiStringStream;
  lDstWide : TPlWideStringStream;
begin
  //if fSrcAnsi = nil then
  //  fSrcAnsi := TPlAnsiStringStream.Create;
  lSrcAnsi := GetAnsiStringStreamPool().AcquireStream();
  TPlAnsiStringStream(lSrcAnsi).Data :=   @  Source;

  //if fDstWide = nil then
  //  fDstWide := TPlWideStringStream.Create;
  lDstWide := GetWideStringStreamPool().AcquireStream();
  Dest := '';
  TPlWideStringStream(lDstWide).Data :=   @  Dest;

  try
    Convert(lSrcAnsi, lDstWide, Options, 0);

  finally
    GetAnsiStringStreamPool().ReleaseStream(lSrcAnsi);
    GetWideStringStreamPool().ReleaseStream(lDstWide);
  end;
end;

function TPlConverter.IsConvertFromUnicode(const Source: UnicodeString; out Dest: AnsiString;
  Options: TPlConvertOptions): Boolean;
begin
  try
    ConvertFromUnicode(Source, Dest,
      Options + [coInvalidCharException]
        );
    Result := True;
  except
    SetLength(Dest, 0);
    Result := False;
  end;
end;

function TPlConverter.IsConvertToUnicode(const Source: AnsiString; out Dest: UnicodeString;
  Options: TPlConvertOptions): Boolean;
begin
  try
    ConvertToUnicode(Source, Dest,
      Options + [coInvalidCharException]
        );
    Result := True;
  except
    Dest := '';
    Result := False;
  end;
end;
{
procedure TPlConverter.ConvertBuffer(
  Source: ByteArray; SourceLen: Integer; var SourcePos: Integer;
  Dest: ByteArray; DestLen: Integer; var DestPos: Integer;
  Options: TPlConvertOptions);
begin
  if fSrcByte = nil then
    fSrcByte := TPlByteArrayStream.Create;
  //TPlByteArrayStream(fSrcAnsi).SetData(Source, SourceLen, SourcePos);

  if fDstByte = nil then
    fDstByte := TPlByteArrayStream.Create;
  //TPlByteArrayStream(fSrcAnsi).SetData(Dest, DestLen, DestPos);

  Convert(fSrcByte, fDstByte, Options, 0);
end;
}
constructor TPlConverter.Create;
begin
  Create(GetSystemDefaultCharsetName, GetSystemDefaultCharsetName);
end;

constructor TPlConverter.Create(const SrcCharset, DstCharset: string);
begin
  InitCharsets;
  Create(CreateCharset(SrcCharset), CreateCharset(DstCharset));
end;

constructor TPlConverter.Create(SrcCharset, DstCharset: IPlCharset);
begin
  inherited Create;
  fInBuffer := TPlConvBuffer.Create;
  fOutBuffer := TPlConvBuffer.Create;
  fSrc := SrcCharset;
  fSrc.SetBuffer(fInBuffer);
  fDst := DstCharset;
  fDst.SetBuffer(fOutBuffer);
  fLineStates := {$ifdef SB_NO_OPENARRAY_SET_ASSIGNMENT}new TElSet() {$else}[] {$endif};
end;

 destructor  TPlConverter.Destroy;
begin
  {FreeAndNil(fSrcAnsi);
  FreeAndNil(fDstAnsi);
  FreeAndNil(fSrcWide);
  FreeAndNil(fDstWide);
  FreeAndNil(fSrcByte);
  FreeAndNil(fDstByte);}
  inherited;
end;

function TPlConverter.GetDstName: string;
begin
  Result := fDst.GetName;
end;

function TPlConverter.GetSrcName: string;
begin
  Result := fSrc.GetName;
end;

procedure TPlConverter.SetDstName(const Value: string);
var
  NewCharset: IPlCharset;
begin
  NewCharset := CreateCharset(Value);
  NewCharset.SetBuffer(fOutBuffer);
  fDst := NewCharset;
end;

procedure TPlConverter.SetSrcName(const Value: string);
var
  NewCharset: IPlCharset;
begin
  NewCharset := CreateCharset(Value);
  NewCharset.SetBuffer(fInBuffer);
  fSrc := NewCharset;
end;


{ TPlCustomUTF }

function TPlCustomUTF.GetCategory: string;
begin
  Result := SUnicodeCategory;
end;

procedure TPlCustomUTF.Reset;
begin
  inherited Reset;
  fByteOrderBE := False;
end;

{ TPlUTF32 }

function TPlUTF32.ConvertFromUCS(Char: UCS): Integer;
begin
  if Char > $10FFFF then
    Result := -1
  else
  begin
    WriteChar(Char);
    Result := 4;
  end;
end;

function TPlUTF32.ConvertToUCS(Stream: TElNativeStream; out Char: UCS): Integer;
var
  Exists: TSBBoolean;
  InChar: LongWord;
begin
  Exists := false;
  InChar := Buffer.GetLong(Stream, Exists);
  if Exists then
  begin
    Result := 4;
    if InChar = UCSCharByteOrderLE32 then
    begin
      fByteOrderBE := False;
      InChar := UCSCharIgnore;
    end
    else
      if InChar = UCSCharByteOrderBE32 then
    begin
      fByteOrderBE := True;
      InChar := UCSCharIgnore;
    end
    else
      if fByteOrderBE then
      InChar := SwapLong(InChar);
    Char := InChar;
  end
  else
  begin
    Char := UCSCharIllegal;
    Result := 0;
  end;
end;

function TPlUTF32.ConvertBufferToUCS(const Buf; Count : Integer; IsLastChunk : Boolean; out Char: UCS): Integer;
var
  Buffer : array [0..3] of Byte absolute Buf;
  InChar : LongWord;
begin
  if Count > 3 then
  begin
    if not fByteOrderBE then
      InChar := LongWord(Buffer[ 0 ]) or
        (LongWord(Buffer[ 1 ]) shl 8) or
        (LongWord(Buffer[ 2 ]) shl 16) or
        (LongWord(Buffer[ 3 ]) shl 24)
    else
      InChar := (LongWord(Buffer[ 0 ]) shl 24) or
        (LongWord(Buffer[ 1 ]) shl 16) or
        (LongWord(Buffer[ 2 ]) shl 8) or
         LongWord(Buffer[ 3 ]);

    Result := 4;
    if InChar = UCSCharByteOrderLE32 then
    begin
      // fByteOrderBE is correct
      Char := UCSCharIgnore;
    end
    else
    if InChar = UCSCharByteOrderBE32 then
    begin
      fByteOrderBE := not fByteOrderBE;
      Char := UCSCharIgnore;
    end
    else
      Char := InChar;
  end
  else
  begin
    Char := UCSCharIllegal;
    Result := 0;
  end;
end;

function TPlUTF32.GetAliases: string;
begin
  Result := 'utf-32,utf-32LE,utf32'; // do not localize
end;

function TPlUTF32.GetDescription: string;
begin
  Result := SUTF32;
end;

procedure TPlUTF32.WriteChar(Char: LongWord);
begin
  Buffer.Put(Char, 4);
end;

function TPlUTF32.WriteFileHeader: Cardinal;
// const
//   HeaderValues: array[{$ifndef SB_NET}Boolean{$else}0..1{$endif}] of LongWord =
//   {$ifndef SB_NET}({$else}[{$endif}
//     UCSCharByteOrderLE32, UCSCharByteOrderBE32
//   {$ifndef SB_NET}){$else}]{$endif};
begin
  // WriteChar( HeaderValues[{$ifdef SB_NET}Ord{$endif}(fByteOrderBE)] );
  // for BE the WriteChar will write correct value UCSCharByteOrderBE32
  WriteChar(UCSCharByteOrderLE32);
  Result := 4;
end;

{ TPlUTF32BE }

constructor TPlUTF32BE.Create;
begin
  inherited Create;
  fByteOrderBE := True;
end;

    
function TPlUTF32BE.GetAliases: string;
begin
  Result := 'utf-32BE,utf32BE'; // do not localize
end;

function TPlUTF32BE.GetDescription: string;
begin
  Result := SUTF32BE;
end;

procedure TPlUTF32BE.Reset;
begin
  inherited Reset;
  fByteOrderBE := True;
end;

procedure TPlUTF32BE.WriteChar(Char: LongWord);
begin
  inherited WriteChar( SwapLong(Char) );
end;

{ TPlUTF16 }

function TPlUTF16.ConvertFromUCS(Char: UCS): Integer;
begin
  if Char > $10FFFF then
    Result := -1
  else
    if Char > $FFFF then
  begin
    Dec(Char, $10000);
    WriteChar(((Char shr 10) and $3FF) or $D800);
    WriteChar((Char and $3FF) or $DC00);
    Result := 4;
  end
  else
  begin
    WriteChar(Char);
    Result := 2;
  end;
end;

function TPlUTF16.ConvertToUCS(Stream: TElNativeStream; out Char: UCS): Integer;
var
  Exists: TSBBoolean;
  Second: UCS;
begin
  Exists := false;
  Char := Buffer.GetWide(Stream, Exists);
  if Exists then
  begin
    Result := 2;
    if Char = UCSCharByteOrderLE16 then
    begin
      fByteOrderBE := False;
      Char := UCSCharIgnore;
    end
    else
      if Char = UCSCharByteOrderBE16 then
    begin
      fByteOrderBE := True;
      Char := UCSCharIgnore;
    end
    else
    begin
      if fByteOrderBE then
        Char := SwapWord(Char);
      if (Char and $FC00) = $D800 then // Surrogate character
      begin
        Second := Buffer.GetWide(Stream, Exists);
        if Exists then
        begin
          if fByteOrderBE then
            Second := SwapWord(Second);
          if (Second and $FC00) <> $DC00 then // Broken surrogate pair
          begin
            Char := UCSCharIgnore;
            Buffer.ReturnBytes(2);
          end
          else
          begin
            Inc(Result, 2);
            Char := $10000 + ((Char and $3FF) shl 10) or
              (Second and $3FF);
          end;
        end
        else
        begin
          Buffer.ReturnBytes(2);
          Char := UCSCharIllegal;
          Result := 0;
        end;
      end;
    end;
  end
  else
  begin
    Char := UCSCharIllegal;
    Result := 0;
  end;
end;

function TPlUTF16.ConvertBufferToUCS(const Buf; Count : Integer; IsLastChunk : Boolean; out Char: UCS): Integer;
var
  Buffer : array [0..3] of Byte absolute Buf;
  Second : UCS;
begin
  if Count > 1 then
  begin
    if not fByteOrderBE then
      Char := UCS(Buffer[ 0 ]) or
        (UCS(Buffer[ 1 ]) shl 8)
    else
      Char := (UCS(Buffer[ 0 ]) shl 8) or
         UCS(Buffer[ 1 ]);

    Result := 2;
    if Char = UCSCharByteOrderLE16 then
    begin
      // fByteOrderBE is correct
      Char := UCSCharIgnore;
    end
    else
    if Char = UCSCharByteOrderBE16 then
    begin
      fByteOrderBE := not fByteOrderBE;
      Char := UCSCharIgnore;
    end
    else
    begin
      if (Char and $FC00) = $D800 then // Surrogate character
      begin
        if Count > 3 then
        begin
          if not fByteOrderBE then
            Second := UCS(Buffer[ 2 ]) or
              (UCS(Buffer[ 3 ]) shl 8)
          else
            Second := (UCS(Buffer[ 2 ]) shl 8) or
               UCS(Buffer[ 3 ]);

          if (Second and $FC00) <> $DC00 then // Broken surrogate pair
          begin
            Char := UCSCharIgnore;
            Result := 0;
          end
          else
          begin
            Inc(Result, 2);
            Char := $10000 + ((Char and $3FF) shl 10) or
              (Second and $3FF);
          end;
        end
        else
        begin
          Char := UCSCharIllegal;
          Result := 0;
        end;
      end;
    end;
  end
  else
  begin
    Char := UCSCharIllegal;
    Result := 0;
  end;
end;

function TPlUTF16.GetAliases: string;
begin
  Result := 'utf-16,,utf-16LE,unicode,iso-10646-utf-16,utf16,' +
    '1200'; // do not localize
end;

function TPlUTF16.GetDescription: string;
begin
  Result := SUTF16;
end;

procedure TPlUTF16.WriteChar(Char: Word);
begin
  Buffer.PutWordLE(Char);
end;
(*
{$ifndef SB_VCL}
var
  vBuf: array{$ifndef SB_JAVA}[0..1]{$endif} of Byte;
{$endif}
begin
  {$ifdef SB_JAVA}
  SetLength(vBuf, 2);
  {$endif}
  {$ifndef SB_VCL}
  vBuf[0] := (Word(Char)      ) and $FF;
  vBuf[1] := (Word(Char) shr 8) and $FF;
  Buffer.Put(vBuf, 0, 2);
  {$else}
  Buffer.Put(Char, 2);
  {$endif}
end;
*)

function TPlUTF16.WriteFileHeader: Cardinal;
// const
//   HeaderValues: array[{$ifndef SB_NET}Boolean{$else}0..1{$endif}] of Word =
//   {$ifndef SB_NET}({$else}[{$endif}
//     UCSCharByteOrderLE16, UCSCharByteOrderBE16
//   {$ifndef SB_NET}){$else}]{$endif};
begin
  // WriteChar( HeaderValues[{$ifdef SB_NET}Ord{$endif}(fByteOrderBE)] );
  // for BE the WriteChar will write correct value UCSCharByteOrderBE16
  WriteChar(UCSCharByteOrderLE16);
  Result := 2;
end;

{ TPlUTF16BE }

constructor TPlUTF16BE.Create;
begin
  inherited Create;
  fByteOrderBE := True;
end;


function TPlUTF16BE.GetAliases: string;
begin
  Result := 'utf-16BE,unicodeFFFE,1201'; // do not localize
end;

function TPlUTF16BE.GetDescription: string;
begin
  Result := SUTF16BE;
end;

procedure TPlUTF16BE.Reset;
begin
  fByteOrderBE := True;
end;

procedure TPlUTF16BE.WriteChar(Char: Word);
begin
  inherited WriteChar( SwapWord(Char) );
end;

{ TPlUTF8 }

const
  UT8LeadBytes: array[0..6] of Byte = 
   ( 
    $00, $00, $C0, $E0, $F0, $F8, $FC
   ) ;

  UT8LeadMasks: array[0..6] of Byte =
   ( 
    $00, $7F, $1F, $0F, $07, $03, $01
   ) ;

  UTF8Ranges: array[0..6] of LongWord =
   ( 
    $0, $0, $80, $800, $10000, $200000, $4000000
   ) ;

function TPlUTF8.ConvertFromUCS(Char: UCS): Integer;
var
  OutChar: Byte;
  Index: Cardinal;
  OutBuffer: array [0..6]  of Byte;
begin
  if LongWord(Char) > $7FFFFFFF then
    Result := -1
  else
  begin
    Result := 6;
    while LongWord(Char) < UTF8Ranges[Result] do
      Dec(Result);
    Index := Result - 1;
    while True do
    begin
      OutChar := Byte(Char);
      Char := Char shr 6;
      if Index = 0 then
        OutChar := OutChar or UT8LeadBytes[Result]
      else
        OutChar := (OutChar and $3F) or $80;
      OutBuffer[Index] := OutChar;
      if Index = 0 then
        Break;
      Dec(Index);
    end;
    Buffer.Put(OutBuffer [0] , Result);
  end;
end;

function TPlUTF8.ConvertToUCS(Stream: TElNativeStream; out Char: UCS): Integer;
var
  InChar: Byte;
  Index: Integer;
  Exists: TSBBoolean;
begin
  Exists := false;
  Index := 0;
  Result := 0;
  InChar := Buffer.GetByte(Stream, Exists);
  if Exists then
  begin
    if InChar < $C0 then
    begin
      Result := 1;
      Char := InChar;
    end
    else
    begin
      Result := 6;
      while InChar < UT8LeadBytes[Result] do
        Dec(Result);
      Index := 1;
      Char := InChar and UT8LeadMasks[Result];
      while Index < Result do
      begin
        InChar := Buffer.GetByte(Stream, Exists);
        if not Exists then
          Break;
        Char := (Char shl 6) or (InChar and $3F);
        Inc(Index);
      end;
    end;
  end;
  if not Exists then
  begin
    if Index > 0 then
      Buffer.ReturnBytes(Index);
    Char := UCSCharIllegal;
    Result := 0
  end
  else
    if (Char = UCSCharByteOrderBE16) or (Char = UCSCharByteOrderLE16) then
    Char := UCSCharIgnore;
end;

function TPlUTF8.ConvertBufferToUCS(const Buf; Count : Integer; IsLastChunk : Boolean; out Char: UCS): Integer;
var
  Buffer : array [0..0] of Byte absolute Buf;
  Offset : Integer;
  InChar : Byte;
begin
  if Count > 0 then
  begin
    InChar := Buffer[ 0 ];
    if InChar < $C0 then
    begin
      Char := InChar;
      Result := 1;
    end
    else
    begin
      Result := 6;
      while InChar < UT8LeadBytes[Result] do
        Dec(Result);

      if Result > Count then
      begin
        Char := UCSCharIllegal;
        Result := 0;
        Exit;
      end;

      Char := InChar and UT8LeadMasks[Result];
      Offset := 1;
      Count := Result - 1;
      while Count > 0 do
      begin
        InChar := Buffer[Offset];
        Char := (Char shl 6) or (InChar and $3F);
        Inc(Offset);
        Dec(Count);
      end;

      if (Result = 3) and ((Char = UCSCharByteOrderBE16) or (Char = UCSCharByteOrderLE16)) then
        Char := UCSCharIgnore;
    end;
  end
  else
  begin
    Char := UCSCharIllegal;
    Result := 0;
  end;
end;

function TPlUTF8.GetCategory: string;
begin
  Result := SUnicodeCategory;
end;

function TPlUTF8.GetAliases: string;
begin
  Result := 'utf-8,iso-10646-utf-8,utf8,unicode-1-1-utf-8,' +
    'unicode-2-0-utf-8,x-unicode-2-0-utf-8,65001'; // do not localize
end;

function TPlUTF8.GetDescription: string;
begin
  Result := SUTF8;
end;

function TPlUTF8.WriteFileHeader: Cardinal;
const
  Header: array[0..2] of Byte = 
   ( 
    $EF, $BB, $BF
   ) ;
begin
  Buffer.Put(Header [0] ,3);
  Result := 3;
end;

{ TPlUTF7 }

const
  Base64Chars: array[0..64] of Char =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
    'abcdefghijklmnopqrstuvwxyz' +
    '0123456789+/';
  (*
  Base64Set: set of AnsiChar =
  ['+', '/', '0'..'9', 'A'..'Z', 'a'..'z'];
  *)

  DirectSet: set of AnsiChar =
  [#$9, #$A, #$D, ' ', '''', '(', ')', ',', '-', '.', '/', '0'..'9', ':', '?',
    'A'..'Z', 'a'..'z'];


function TPlUTF7.ConvertFromUCS(Char: UCS): Integer;
var
  Bits: Integer;
  DirectChar {, Base64Char}: Boolean;
begin
  if LongWord(Char) > $FFFF then
    Result := -1
  else
  begin
    Result := 0;
    if Char <= Ord('z') then
    begin
      DirectChar := AnsiChar(Char) in DirectSet;
          //Base64Char := AnsiChar(Char) in Base64Set;
    end
    else
    begin
      DirectChar := False;
          //Base64Char := False;
    end;
    if (fState = usDirect) and
       not DirectChar then
    begin
      Buffer.PutByte(Byte('+'));
      Inc(Result);
      if Char = Ord('+') then
        Char := Ord('-')
      else
        fState := usBase64;
    end
    else
      if (fState = usBase64) and
         DirectChar then
    begin
      Inc(Result, WriteLineEnd);
          {
          if Base64Char then
            begin
              Buffer.PutByte(Byte('-'));
              Inc(Result);
            end;
          }
      fState := usDirect;
    end;
    if fState = usBase64 then
    begin
      Char := UCS(Char or (fTail shl 16));
      Bits := 10 + fTailBits;
      while True do
      begin
        if Bits >= 0 then
        begin
          Buffer.PutByte(Byte(Base64Chars[(Char shr Bits) and $3F]));
          Inc(Result);
          Dec(Bits, 6);
        end
        else
        begin
          Inc(Bits, 6);
          Break;
        end;
      end;
      fTail := Char;
      fTailBits := Bits;
    end
    else
    begin
      Buffer.PutByte(Char);
      Inc(Result);
    end;
  end;
end;

function TPlUTF7.ConvertToUCS(Stream: TElNativeStream; out Char: UCS): Integer;
var
  Exists: TSBBoolean;
  SpecialCharLast : Boolean;
  InChar: AnsiChar;
  Value, CharValue, Bits: Integer;
begin
  Exists := false;
  SpecialCharLast := false;
  Result := 0;
  Char := UCSCharIllegal;
  Value := fTail;
  Bits := fTailBits;
  while True do
  begin
    InChar := AnsiChar(Buffer.GetByte(Stream, Exists));
    if not Exists then
      Break;

    SpecialCharLast := false;
    Inc(Result);
    if fState = usDirect then
    begin
      if InChar = AnsiChar('+') then
        fState := usShift
      else
      begin
        Char := UCS(InChar);
        Break;
      end;
    end
    else
    begin
      if fState = usShift then
      begin
        if InChar = AnsiChar('-') then
        begin
          Char := UCS('+');
          fState := usDirect;
          Break;
        end
        else
          fState := usBase64;
      end;

      CharValue := GetBase64(InChar);
      if CharValue >= 0 then
      begin
        Value := (Value shl 6) or CharValue;
        Inc(Bits, 6);
        if Bits >= 16 then
        begin
          Dec(Bits, 16);
          Char := (Value shr Bits) and $FFFF;
          Break;
        end;
      end
      else
      begin
        if InChar <> AnsiChar('-') then
        begin
          Buffer.ReturnByte;
          Dec(Result);
        end
        else
        begin
          SpecialCharLast := true;
          Char := UCSCharIgnore;
        end;

        fState := usDirect;
        Value := 0;
        Bits := 0;
      end;
    end;
  end;
  if not Exists and not SpecialCharLast then
  begin
    if Result > 0 then
      Buffer.ReturnBytes(Result);
    Result := 0;
  end
  else
  begin
    fTail := Value;
    fTailBits := Bits;
  end;
end;

function TPlUTF7.ConvertBufferToUCS(const Buf; Count : Integer; IsLastChunk : Boolean; out Char: UCS): Integer;
var
  Buffer : array [0..0] of Byte absolute Buf;
  Offset : Integer;
  InChar : Byte;
  Value, CharValue, Bits: Integer;
begin
  Value := fTail;
  Bits := fTailBits;
  Result := 0;
  Offset := 0;
  while Result < Count do
  begin
    InChar := Buffer[Offset];
    Inc(Offset);
    Inc(Result);
    if fState = usDirect then
    begin
      if InChar = Byte('+') then
        fState := usShift
      else
      begin
        Char := UCS(InChar);
        fTail := Value;
        fTailBits := Bits;
        Exit;
      end;
    end
    else
    begin
      if fState = usShift then
      begin
        if InChar = Byte('-') then
        begin
          Char := UCS('+');
          fState := usDirect;
          fTail := Value;
          fTailBits := Bits;
          Exit;
        end
        else
          fState := usBase64;
      end;

      CharValue := GetBase64( AnsiChar (InChar));
      if CharValue >= 0 then
      begin
        Value := (Value shl 6) or CharValue;
        Inc(Bits, 6);
        if Bits >= 16 then
        begin
          Dec(Bits, 16);
          Char := (Value shr Bits) and $FFFF;
          fTail := Value;
          fTailBits := Bits;
          Exit;
        end;
      end
      else
      begin
        if InChar <> Byte('-') then
        begin
          //Dec(Offset);
          Dec(Result);
        end;

        fState := usDirect;
        Value := 0;
        Bits := 0;
        fTail := Value;
        fTailBits := Bits;
        Char := UCSCharIgnore;
        Exit;
      end;
    end;
  end;

  Char := UCSCharIllegal;
  Result := 0;
end;

function TPlUTF7.GetAliases: string;
begin
  Result := 'utf-7,unicode-1-1-utf-7,csUnicode11,csUnicode11UTF7,' +
    'UTF7,x-unicode-2-0-utf-7,65000'; // do not localize
end;

class function TPlUTF7.GetBase64(Char: AnsiChar): Integer;
begin
  case Char of
    AnsiChar('+'):
      Result := 62;
    AnsiChar('/'):
      Result := 63;
    AnsiChar('0')..AnsiChar('9'):
      Result := Integer(Char) - Ord('0') + 52;
    AnsiChar('A')..AnsiChar('Z'):
      Result := Integer(Char) - Ord('A');
    AnsiChar('a')..AnsiChar('z'):
      Result := Integer(Char) - Ord('a') + 26;
    (*
    {$ifndef SB_NET}'+'{$else}AnsiChar('+'){$endif}:
      Result := 62;
    {$ifndef SB_NET}'/'{$else}AnsiChar('/'){$endif}:
      Result := 63;
    {$ifndef SB_NET}'0'..'9'{$else}AnsiChar('0')..AnsiChar('9'){$endif}:
      Result := Integer(Char) - Ord('0') + 52;
    {$ifndef SB_NET}'A'..'Z'{$else}AnsiChar('A')..AnsiChar('Z'){$endif}:
      Result := Integer(Char) - Ord('A');
    {$ifndef SB_NET}'a'..'z'{$else}AnsiChar('a')..AnsiChar('z'){$endif}:
      Result := Integer(Char) - Ord('a') + 26;
    *)
  else
    Result := -1;
  end;
end;

function TPlUTF7.GetCategory: string;
begin
  Result := SUnicodeCategory;
end;

function TPlUTF7.GetDescription: string;
begin
  Result := SUTF7;
end;

function TPlUTF7.WriteLineEnd: Cardinal;
begin
  Result := 0;
  if fState = usBase64 then
  begin
    if fTailBits > 0 then
    begin
      Result := 1;
      Buffer.PutByte(Byte(Base64Chars[(fTail shl (6 - fTailBits)) and $3F]));
      fTailBits := 0;
    end;
    Buffer.PutByte(Byte('-'));
    Inc(Result);
  end;
  fState := usDirect;
end;

////////////////////////////////////////////////////////////////////////////////
// TPlCustomStringStreamPool class

constructor TPlCustomStringStreamPool.Create;
begin
  inherited;
  FCS := TElSharedResource.Create();
  FFreeStreams := TElList.Create();
  FOccupiedStreams := TElList.Create();
end;

 destructor  TPlCustomStringStreamPool.Destroy;
var
  I : integer;
begin
  FCS.WaitToWrite;
  try
    {$ifndef NET_CF}
    for I := 0 to FFreeStreams.Count - 1 do
      TPlCustomStringStream(FFreeStreams[I]).  Free ; ;
    for I := 0 to FOccupiedStreams.Count - 1 do
      TPlCustomStringStream(FOccupiedStreams[I]).  Free ; ;
     {$endif}
  finally
    FCS.Done;
  end;
  FreeAndNil(FFreeStreams);
  FreeAndNil(FOccupiedStreams);
  FreeAndNil(FCS);
end;

function TPlCustomStringStreamPool.InternalAcquireStream: TPlCustomStringStream;
begin
  FCS.WaitToWrite;
  try
    if FFreeStreams.Count > 0 then
    begin
      Result := TPlCustomStringStream(FFreeStreams[FFreeStreams.Count - 1]);
      FFreeStreams. Delete (FFreeStreams.Count - 1);
      FOccupiedStreams.Add(Result);
    end
    else
    begin
      Result := CreateUnderlyingStream();
      FOccupiedStreams.Add(Result);
    end;
  finally
    FCS.Done;
  end;
end;

procedure TPlCustomStringStreamPool.InternalReleaseStream(Stream : TPlCustomStringStream);
var
  Idx : integer;
begin
  FCS.WaitToWrite;
  try
    Idx := FOccupiedStreams.IndexOf(Stream);
    if Idx >= 0 then
    begin
      FOccupiedStreams. Delete (Idx);
      FFreeStreams.Add(Stream);
    end;
  finally
    FCS.Done;
  end;
end;

function TPlCustomStringStreamPool.CreateUnderlyingStream: TPlCustomStringStream;
begin
  Result := TPlCustomStringStream.Create;
end;

////////////////////////////////////////////////////////////////////////////////
// TPlAnsiStringStreamPool class

function TPlAnsiStringStreamPool.CreateUnderlyingStream: TPlCustomStringStream;
begin
  Result := TPlAnsiStringStream.Create();
end; 

function TPlAnsiStringStreamPool.AcquireStream: TPlAnsiStringStream;
begin
  Result := TPlAnsiStringStream(InternalAcquireStream());
end;

procedure TPlAnsiStringStreamPool.ReleaseStream(Stream : TPlAnsiStringStream);
begin
  InternalReleaseStream(Stream);
end;

////////////////////////////////////////////////////////////////////////////////
// TPlWideStringStreamPool class

function TPlWideStringStreamPool.CreateUnderlyingStream: TPlCustomStringStream;
begin
  Result := TPlWideStringStream.Create();
end;

function TPlWideStringStreamPool.AcquireStream: TPlWideStringStream;
begin
  Result := TPlWideStringStream(InternalAcquireStream());
end;

procedure TPlWideStringStreamPool.ReleaseStream(Stream : TPlWideStringStream);
begin
  InternalReleaseStream(Stream);
end;



procedure Initialize;
begin
  AcquireGlobalLock();
  try

    Charsets :=  TSBObjectList .Create;
    CharsetsNamesLock :=  TCriticalSection .Create;
    CharsetsNames := TElStringList.Create;
    CharsetsNames.Sorted := True;
    CharsetLibraries := TElStringList.Create;
    CharsetLibraries.Sorted := True;

    RegisterCharset(TPlUTF32);
    RegisterCharset(TPlUTF32BE);
    RegisterCharset(TPlUTF16);
    RegisterCharset(TPlUTF16BE);
    RegisterCharset(TPlUTF8);
    RegisterCharset(TPlUTF7);
    RegisterCharset(TPlASCII);
    RegisterCharset(TPlISO_8859_1);

  finally
    ReleaseGlobalLock();
  end;
end;

initialization
  Initialize;

finalization
  UnregisterCharset(TPlUTF32);
  UnregisterCharset(TPlUTF32BE);
  UnregisterCharset(TPlUTF16);
  UnregisterCharset(TPlUTF16BE);
  UnregisterCharset(TPlUTF8);
  UnregisterCharset(TPlUTF7);
  UnregisterCharset(TPlASCII);
  UnregisterCharset(TPlISO_8859_1);
  {$ifndef FPC}
  UnloadCharsetLibraries;
   {$endif}

  FreeAndNil(CharsetLibraries);
  FreeAndNil(CharsetsNames);
  FreeAndNil(CharsetsNamesLock);
  FreeAndNil(Charsets);

  
end.
