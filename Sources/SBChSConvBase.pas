(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SBChSUnicode.inc}

// Debug:
{$UNDEF _DEBUG_RESOURCE_}
{$ifdef _DEBUG_}
  {.$DEFINE _DEBUG_RESOURCE_} // WriteLn Resource binary data to "stdout".
 {$endif}

{$ifdef SB_WINRT}
{$define SB_B64_ENCODED_RESOURCES}
 {$endif}

{$ifdef WP8}
{$define SB_B64_ENCODED_RESOURCES}
 {$endif}

unit SBChSConvBase;

interface

uses
    SyncObjs,
    SysUtils,
    Classes,
  SBTypes,
  SBUtils,
  SBConstants,
  SBStrUtils;

type

  UCS = 0..$10FFFF;

const
  UCS_Count =  High(UCS)  + 1;

  UCSCharByteOrderLE32 = $0000FEFF;
  UCSCharByteOrderBE32 = $FFFE0000;
  UCSCharByteOrderLE16 = $FEFF;
  UCSCharByteOrderBE16 = $FFFE;
  UCSCharIgnore = $FFFF;
  UCSCharIllegal = $FFFD;

  SB_MAX_CHARACTER_LENGTH = 16;

type

 {$ifdef SILVERLIGHT}
 HashTable = public class(TElStringList)
 public
   constructor Create; 
 end;
  {$endif}
 

{$ifdef _USED_RESOURCES_}
  EPlConvResError =  Exception;
 {$endif}

  TElNativeStream = TStream;
  //TElStringList = TStringList;
  //TElList = TList;

  IPlConvBuffer = interface
   ['{F1D596A5-FF12-4670-A350-E9F15B107ED0}'] 
    procedure Clear(LeaveUnprocessedData : Boolean  =  false);
    procedure Restart;

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

  IPlCharset = interface
   ['{A098F214-B230-480F-8206-6D7526B7428F}'] 
    procedure SetBuffer(const Value: IPlConvBuffer);

    function GetAliases: string;
    function GetDefaultChar: UCS;

    procedure Reset;

    function WriteDefaultChar: Cardinal;
    function WriteFileHeader: Cardinal;
    function WriteLineBegin: Cardinal;
    function WriteLineEnd: Cardinal;
    function WriteString(const Str: AnsiString): Cardinal;

    function CanConvert(Char: UCS): Boolean;
    function ConvertFromUCS(Char: UCS): Integer;
    function ConvertToUCS(Stream: TElNativeStream; out Char: UCS): Integer;

    /// <returns>Number of bytes read from a buffer. If a returned value is zero and a buffer is a last chunk or Count more then SB_MAX_CHARACTER_LENGTH then invalid character occured, otherwise more data is needed.</returns>
    function ConvertBufferToUCS(const Buf; Count : Integer; IsLastChunk : Boolean; out Char: UCS): Integer;

    /// <param name="DstCount">Number of wide characters</param>
    function ConvertBufferToUTF16(const SrcBuf; SrcCount : Integer; IsLastChunk : Boolean; var DstBuf; var DstCount : Integer) : Integer;

(*
    /// <returns>Number of bytes read from a buffer. If a returned value is zero and a buffer is a last chunk or Count more then SB_MAX_CHARACTER_LENGTH then invalid character occured, otherwise more data is needed.</returns>
    {$ifdef SB_VCL}
    function ConvertBufferFromUCS(const Buf; Count : Integer; IsLastChunk : Boolean; out Char: UCS): Integer;
    {$else}
    function ConvertBufferFromUCS(const Buffer : ByteArray; Offset, Count : Integer; IsLastChunk : Boolean; out Char: UCS): Integer;
    {$endif}

    /// <param name="SrcCount">Number of wide characters</param>
    {$ifdef SB_VCL}
    function ConvertBufferFromUTF16(const SrcBuf; SrcCount : Integer; IsLastChunk : Boolean; var DstBuf; var DstCount : Integer) : Integer;
    {$else}
    function ConvertBufferFromUTF16(const SrcBuffer : CharArray; SrcOffset, SrcCount : Integer; IsLastChunk : Boolean;
      var DstBuffer : ByteArray; DstOffset : Integer; var DstCount : Integer) : Integer;
    {$endif}
*)    

    function GetCategory: string;
    function GetDescription: string;
    function GetName: string;
  end;

  TPlCharset = class(TInterfacedObject, IPlCharset)
  private
    fBuffer: IPlConvBuffer;
    fShift: Integer;
  protected
    procedure SetBuffer(const Value: IPlConvBuffer); virtual;
    function GetAliases: string; virtual;
    function GetDefaultChar: UCS; virtual;

    procedure Reset; virtual;
    procedure FinalizeCharset; virtual;

    {$ifdef _USES_RESOURCES_}
    function GetResID: String;
     {$endif}

    function WriteDefaultChar: Cardinal; virtual;
    function WriteFileHeader: Cardinal; virtual;
    function WriteLineBegin: Cardinal; virtual;
    function WriteLineEnd: Cardinal; virtual;
    function WriteString(const Str: AnsiString): Cardinal;

    property Buffer: IPlConvBuffer read fBuffer write SetBuffer;
  {$ifdef _USES_RESOURCES_}
  protected
    class function GetConversionTablesHashTable:  TStringList; 
    class function AllowSerializationData: Boolean; virtual; // .Net: no CLS compliant.
    {$ifdef _MAKE_RESOURCES_}
    procedure SerializeData( Stream: TElNativeStream
      {$ifdef _RESNET_SERIALIZABLE_}
      ; pBinaryFormatter: System.Runtime.Serialization.Formatters.Binary.BinaryFormatter
       {$endif}
    ); virtual;
    class procedure IntegerToBytes(iInteger: Integer; var B: ByteArray; iOffset: Integer);      {$endif}
    class function IntegerFromBytes(const B: ByteArray; iOffset: Integer): Integer; 
   {$endif}
  public
    constructor Create; {$ifdef BUILDER_USED}overload; {$endif}  virtual;
    {$ifndef BUILDER_USED}
    constructor CreateShift(Shift: Integer); virtual;
    constructor CreateNoInit; virtual;
    constructor CreateForFinalize; virtual;
     {$else}
    constructor Create(Shift: Integer);  {$ifdef BUILDER_USED}overload; {$endif} virtual;
    constructor Create(NoInit : Boolean);   {$ifdef BUILDER_USED}overload; {$endif} virtual; // true - CreateNoInit, false - CreateForFinalize
    // constructor CreateForFinalize; virtual;
     {$endif}

    function CanConvert(Char: UCS): Boolean; virtual;
    function ConvertFromUCS(Char: UCS): Integer; virtual;
    function ConvertToUCS(Stream: TElNativeStream; out Char: UCS): Integer; virtual;
    function ConvertBufferToUCS(const Buf; Count : Integer; IsLastChunk : Boolean; out Char: UCS): Integer; virtual;
    function ConvertBufferToUTF16(const SrcBuf; SrcCount : Integer; IsLastChunk : Boolean;
      var DstBuf; var DstCount : Integer) : Integer;

    function GetCategory: string; virtual;
    function GetDescription: string; virtual;
    function GetName: string; virtual;
  {$ifdef _USES_RESOURCES_}{$ifdef _DEBUG_RESOURCE_}
  public
     class procedure DebugB(const B: array of byte; const sTitle: String; iLimit: Integer = 0); 
   {$endif} {$endif}
  end;
    
  TPlCharsetClass =  class of TPlCharset;

  PByte = ^Byte;
  PWord = ^Word;
  PLong = ^LongWord;

  TPlPrefixes =   set of Byte ;
  PPlPrefixes =   ^ TPlPrefixes;
  TPlHiBytes =  array  [Byte]  of Byte;
  PPlHiBytes =   ^ TPlHiBytes;
  TPlChars =  array  [Byte]  of Word;
  PPlChars =   ^ TPlChars;

  TPlConversionPage = packed record
    Chars: PPlChars;
    HiBytes: PPlHiBytes;
    Prefixes: PPlPrefixes;
    CharsLoIndex: Byte;
    CharsHiIndex: Byte;
    PriorPageIndex: Byte;
    PriorPageChar: Byte;
  end;
  
  PPlConversionPage =   ^ TPlConversionPage;
  TPlConversionPages =  array  [Byte]  of TPlConversionPage;
  PPlConversionPages =   ^ TPlConversionPages;

  TPlUCSToSingleByteTable =  array  [UCS]  of Byte;
  PPlUCSToSingleByteTable =   ^ TPlUCSToSingleByteTable;
  
  TPlUCSToMultiByteItem = packed record
    Page: Byte;
    Char: Byte;
  end;
  
  TPlUCSToMultiByteTable =  array  [UCS]  of TPlUCSToMultiByteItem;
  PPlUCSToMultiByteTable =   ^ TPlUCSToMultiByteTable;

  TPlConversionTable = packed record
    MaxDirectMapped: Integer;
    PagesCount: Integer;
    Pages: PPlConversionPages;
    BackItemsCount: LongWord;
    case Integer of
    1: (ToSingleByte: PPlUCSToSingleByteTable);
    2: (ToMultiByte: PPlUCSToMultiByteTable);
  end;
  
  PPlConversionTable =   ^ TPlConversionTable;
  

  //TAnsiStringRef = {$ifdef SB_NET}public{$endif} {$ifdef SB_VCL}^AnsiString {$else}AnsiString{$endif};

  // Format of GetAdditionalFromUCS TAnsiStringRef
  // Repetable groups of chars:
  //   for one byte charsets: 2 chars - UCS, 1 charset char
  //   for multibyte charsets: 3 chars - UCS, zero ended charset chars

  TPlTableCharset = class(TPlCharset)
  private
    fTable: PPlConversionTable;
  {$ifdef _USED_RESOURCES_}
  protected
    function GetConversionTableFromResource: PPlConversionTable;
    function GetConversionTableFromCache: PPlConversionTable;
   {$endif}
  {$ifdef _USES_RESOURCES_}
  protected
    class function AllowSerializationData: Boolean; override;
    {$ifdef _MAKE_RESOURCES_}
    procedure SerializeData( Stream: TElNativeStream
      {$ifdef _RESNET_SERIALIZABLE_}
      ; pBinaryFormatter: System.Runtime.Serialization.Formatters.Binary.BinaryFormatter
       {$endif}
    ); override;
    class procedure SaveConversionTableToStream( const CT: PPlConversionTable; Stream: TElNativeStream );     {$endif}
    {$ifdef _USED_RESOURCES_}
    class function MakeConversionTableFromStream( Stream: TElNativeStream ):PPlConversionTable;
     {$endif}
   {$endif}
  protected
    class function IsEqualConversionTables(Tab1, Tab2: PPlConversionTable): Boolean;
    function GetAdditionalFromUCS: ByteArray; virtual;
    function GetConversionTable: PPlConversionTable; virtual;
    procedure GenerateBackTable;
    //procedure SetBuffer(const Value: IPlConvBuffer); override;
    procedure FinalizeCharset; override;
  public
    constructor Create; override;
    {$ifndef BUILDER_USED}
    constructor CreateForFinalize; override;
     {$else}
    constructor Create(NoInit: Boolean); override;
     {$endif}

    function CanConvert(Char: UCS): Boolean; override;
    function ConvertFromUCS(Char: UCS): Integer; override;
    function ConvertToUCS(Stream: TElNativeStream; out Char: UCS): Integer; override;
    function ConvertBufferToUCS(const Buf; Count : Integer; IsLastChunk : Boolean; out Char: UCS): Integer; override;
  end;

  TPlMixedCharset = class(TPlCharset)
  protected
    FCount: Integer;
    FCharsets: array [0..15] of TPlCharset;

    function GetCharsetClass(Index: Integer): TPlCharsetClass; virtual;
    function GetCharsetsCount: Integer; virtual;
    function GetCharsetShift(Index: Integer): Integer; virtual;

    procedure SetBuffer(const Value: IPlConvBuffer); override;
    
  {$ifdef _USES_RESOURCES_}
  protected
    class function AllowSerializationData: Boolean; override;
    {$ifdef _MAKE_RESOURCES_}
    procedure SerializeData( Stream: TElNativeStream
      {$ifdef _RESNET_SERIALIZABLE_}
      ; pBinaryFormatter: System.Runtime.Serialization.Formatters.Binary.BinaryFormatter
       {$endif}
    ); override;
     {$endif}
   {$endif}
  public
    constructor Create; override;
    {$ifndef BUILDER_USED}
    constructor CreateShift(Shift: Integer); override;
     {$else}
    constructor Create(Shift: Integer); override;
     {$endif}
    
    destructor Destroy; override;

    function CanConvert(Char: UCS): Boolean; override;
    function ConvertFromUCS(Char: UCS): Integer; override;
    function ConvertToUCS(Stream: TElNativeStream; out Char: UCS): Integer; override;
    function ConvertBufferToUCS(const Buf; Count : Integer; IsLastChunk : Boolean; out Char: UCS): Integer; override;
  end;

  TPlConvertingCharset = class(TPlCharset)
  protected
    fBase: TPlCharset;

    procedure ConvertFrom(var C1, C2: Integer); virtual;
    procedure ConvertTo(var C1, C2: Integer); virtual;
    function GetBaseCharsetClass: TPlCharsetClass; virtual;
    
    procedure SetBuffer(const Value: IPlConvBuffer); override;
  public
    constructor Create; override;
    destructor Destroy; override;

    function CanConvert(Char: UCS): Boolean; override;
    function ConvertFromUCS(Char: UCS): Integer; override;
    function ConvertToUCS(Stream: TElNativeStream; out Char: UCS): Integer; override;
    function ConvertBufferToUCS(const Buf; Count : Integer; IsLastChunk : Boolean; out Char: UCS): Integer; override;
  end;

  TPlASCII = class(TPlTableCharset)
   protected 
    function GetAliases: string; override;
    
    function GetAdditionalFromUCS: ByteArray; override;
    {$ifndef _USED_RESOURCES_}
    function GetConversionTable: PPlConversionTable; override;
     {$endif}
  public
    function GetCategory: string; override;
    function GetDescription: string; override;
  end;

  TPlISO_8859_1 = class(TPlASCII)
   protected 
    function GetAliases: string; override;
    
    {$ifndef _USED_RESOURCES_}
    function GetConversionTable: PPlConversionTable; override;
     {$endif}
  public
    function GetCategory: string; override;
    function GetDescription: string; override;
  end;

type
  TBytes = array [0..MaxInt - 1] of Byte;
  PBytes =   ^ TBytes;

procedure RegisterCharset(CharsetClass: TPlCharsetClass); 
procedure UnregisterCharset(CharsetClass: TPlCharsetClass); 

type
  TPlCharsetClassPtr =   Pointer ;
  TCharsetCreateProc =  function (Handle: TPlCharsetClassPtr): IPlCharset;
  TCharsetLibraryRegProc =  procedure(
    Category, Description, Aliases:  PChar ;
    Handle: TPlCharsetClassPtr;
    CreateProc: TCharsetCreateProc);

procedure RegisterCharsetLibrary(RegistrationProc: TCharsetLibraryRegProc);   {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};  


procedure AbstractError(const ClassName, Method: string); 

const
  cNilPrefixes = nil;
  cNilHiBytes = nil;
  cNilConvTable = nil;

{$ifdef _USES_RESOURCES_}
const
  {$ifndef MONO}
  {$ifndef NET_CF}
  {$ifndef SB_WINRT}
    {$ifndef WP8}
    cBaseResNameSpace = 'EldoS.SecureBlackbox.Unicode';
     {$else}
    cBaseResNameSpace = 'EldoS.SecureBlackbox.Unicode.NET_WinRT'; // WinRT resources are used for both WP8 and WinRT platforms
     {$endif}
   {$else SB_WINRT}
    cBaseResNameSpace = 'EldoS.SecureBlackbox.Unicode.NET_WinRT';
   {$endif SB_WINRT}
   {$else NET_CF}
  //cBaseResNameSpace = 'EldoS.SecureBlackbox.Unicode.NET_CF';
  cBaseResNameSpace = 'EldoS.SecureBlackbox.Unicode';
   {$endif NET_CF}
   {$else MONO}
  cBaseResNameSpace = 'EldoS.SecureBlackbox.Unicode.Mono';
   {$endif MONO}
 {$endif}

var
  BackGeneratorLock: TCriticalSection = nil;

{$ifdef _MAKE_RESOURCES_}
  procedure SerializeRegisteredCharsets; 

var
  // ResIDs Container (Allows to struggle with duplication of resources).
  ResourcesKeyIDTables:  TStringList ;
 {$endif}

{$ifdef _USED_RESOURCES_}
  // todo: TimeOut garbage collector for charset resource.
type
  THashItem = record
    fDataRef:  Pointer ;
    fLockCount: Integer;
    fUnLockedTime: TElDateTime;
  end;

  {$ifndef SB_NO_NET_THREADS}
  TResourceGarbageCollector = class;

  TOnResourceGarbageCollector =  procedure( Sender: TResourceGarbageCollector ) of object;

  TResourceGarbageCollector = class (TObject )
  protected
    fZeroSystemTime: TElDateTime; // Protection against unnatural change of system time.
    fOnResourceGarbageCollectors: array of TOnResourceGarbageCollector;
    fGarbageThread:  TThread ;
    fTimeOut: TDateTime;
    fTerminated: Boolean;
    procedure ThreadProc;
  public
    procedure set_TimeOut(val:  TDateTime );
    // IDisposable:
    procedure Dispose;
  public
    constructor Create;
    destructor Destroy; override;
    procedure AddOnResourceGarbageCollector(Val: TOnResourceGarbageCollector);
    procedure DelOnResourceGarbageCollector(Val: TOnResourceGarbageCollector);
    procedure Activate;
    property TimeOut:  TDateTime  read fTimeOut write set_TimeOut;
    //property OnResourceGarbageCollector: TOnResourceGarbageCollector
    //  read
    //    fOnResourceGarbageCollector
    //  write
    //    fOnResourceGarbageCollector;
  end;
   {$endif ifndef SB_NO_NET_THREADS}

 {$endif}

procedure Initialize; 

implementation

uses
  SBChSConvConsts;

{$ifdef _USED_RESOURCES_}
    {$R SecureBlackbox.Unicode.res}
 {$endif}

var
  CharsetsList:   TElList;  


procedure RegisterCharset(CharsetClass: TPlCharsetClass);
begin
  if CharsetsList = nil then
    Initialize;
  //{$ifdef SB_NET}
  if CharsetsList.IndexOf( TObject (CharsetClass)) >= 0 then
    Exit;
  //{$endif}

  CharsetsList.Add( TObject (CharsetClass));
end;

procedure UnregisterCharset(CharsetClass: TPlCharsetClass);
var
  Index: Integer;
  Charset :TPlCharset;
  //s: string;
begin
  if not Assigned(CharsetsList) then
    Exit;

  Index := CharsetsList.IndexOf( TObject (CharsetClass));
  if Index >= 0 then
  begin
    Charset := TPlCharsetClass(CharsetsList[Index]).{$ifndef BUILDER_USED}CreateForFinalize {$else}Create(False) {$endif}; // no GenerateBackTable or other advanced charset data.
    
    try
      // Debug (compiler bug):
        //s := Charset.ClassName;
        //if s = 'TPlCP1250' then
        //  s := '';
      Charset.FinalizeCharset;
    finally
      FreeAndNil(Charset);
    end;
    CharsetsList. Delete (Index);
  end;
end;

function CreateCharset(Handle: TPlCharsetClassPtr): IPlCharset;
begin
  if Handle <> nil then
    Result := TPlCharsetClass(Handle).Create
  else
    Result := nil;
end;

procedure RegisterCharsetLibrary(RegistrationProc: TCharsetLibraryRegProc);
var
  Index: Integer;
  Charset: TPlCharset;
begin
  for Index := 0 to CharsetsList.Count - 1 do
    begin
      Charset := TPlCharsetClass(CharsetsList[Index]). {$ifndef BUILDER_USED}CreateNoInit {$else}Create(true) {$endif} ; // !!!: Not generate encoded/decoded Tablses.
      try
        RegistrationProc(
           PChar (Charset.GetCategory),
           PChar (Charset.GetDescription),
           PChar (Charset.GetAliases),
          TPlCharsetClassPtr(CharsetsList[Index]),
          CreateCharset
        );
      finally
        FreeAndNil(Charset);
      end;
    end;
end;

{$ifdef _USES_RESOURCES_}
var
  ConversionTablesHashTable:  TStringList ;
 {$endif}

procedure FinalizeCharsets;
var
  Index: Integer;
  Charset: TPlCharset;
begin
  for Index := 0 to CharsetsList.Count - 1 do
  begin
    Charset := TPlCharsetClass(CharsetsList[Index]).{$ifndef BUILDER_USED}CreateForFinalize {$else}Create(false) {$endif}; // no GenerateBackTable or other advanced charset data.
    try
      Charset.FinalizeCharset;
    finally
      FreeAndNil(Charset);
    end;
    CharsetsList. Delete (Index);
  end;
  {$ifdef _USED_RESOURCES_}
    if ConversionTablesHashTable <> nil then
    begin
      FreeAndNil(ConversionTablesHashTable);
    end;
   {$endif}
end;

{ TPlCharset }

function TPlCharset.CanConvert(Char: UCS): Boolean;
begin
  Result := True;
end;

constructor TPlCharset.Create;
begin
  inherited Create;
end;


{$ifndef BUILDER_USED}
constructor TPlCharset.CreateNoInit;
 {$else}
constructor TPlCharset.Create(NoInit : boolean);
 {$endif}
begin
  inherited Create; // no initialize any fields. Need for access to information about the class only.
end;

{$ifndef BUILDER_USED}
constructor TPlCharset.CreateForFinalize;
begin
  inherited Create;
end;
 {$endif}

{$ifndef BUILDER_USED}
constructor TPlCharset.CreateShift(Shift: Integer);
 {$else}
constructor TPlCharset.Create(Shift: Integer);
 {$endif}
begin
  Create;
  fShift := Shift;
end;


procedure TPlCharset.FinalizeCharset;
begin
end;

function TPlCharset.GetDefaultChar: UCS;
begin
  Result := UCS('?');
end;

function TPlCharset.GetName: string;
var
  I: Integer;
begin
  Result := GetAliases;
  i := StringIndexOf(Result, ',');
  if i >= StringStartOffset then
    Result := StringSubstring(Result, StringStartOffset, i - StringStartOffset); 
(*
  I := Pos(',', Result);
  if I >= StringStartOffset then
    Result := StringSubstring(Result, StringStartOffset, I - StringStartOffset);
*)
end;

{$ifdef _USES_RESOURCES_}
function TPlCharset.GetResID: String;
begin
    Result :=  ClassName ;
end;
 {$endif}

procedure TPlCharset.Reset;
begin
  if Buffer <> nil then
    Buffer.Clear;
end;

procedure TPlCharset.SetBuffer(const Value: IPlConvBuffer);
begin
  fBuffer := Value;
end;

function TPlCharset.WriteDefaultChar: Cardinal;
begin
  Result := ConvertFromUCS(GetDefaultChar);
end;

function TPlCharset.WriteFileHeader: Cardinal;
begin
  Result := 0;
end;

function TPlCharset.WriteLineBegin: Cardinal;
begin
  Result := 0;
end;

function TPlCharset.WriteLineEnd: Cardinal;
begin
  Result := 0;
end;

function TPlCharset.WriteString(const Str: AnsiString): Cardinal;
var
  I: Integer;
  OutChar: array  [0..0]  of Byte;
begin
  Result := Length(Str);
  if Result > 0 then
    for I := 0 to Result - 1 do
      begin
        OutChar[0] := PByteArray(Pointer(Str))[I] + fShift;
        Buffer.Put(OutChar [0] , 1);
      end;
end;

function TPlCharset.GetAliases: string;
begin
  {empty:}
  Result := '';
end;

resourcestring
  rsAbstractNotImplemented = 'Abstract Error: not implemented method '+
  '"%s.%s"'
   ;

type
  EAbstract = Exception;

procedure AbstractError(const ClassName, Method: string);
begin
  raise EAbstract.CreateFmt(rsAbstractNotImplemented, [ClassName, Method]);
end;

function TPlCharset.ConvertFromUCS(Char: UCS): Integer;
begin
  AbstractError( ClassName , 'ConvertFromUCS');
  Result := 0;
end;

function TPlCharset.ConvertToUCS(Stream: TElNativeStream; out Char: UCS): Integer;
begin
  Char := UCSCharIllegal;
  AbstractError( ClassName , 'ConvertToUCS');
  Result := 0;
end;

function TPlCharset.ConvertBufferToUCS(const Buf; Count : Integer; IsLastChunk : Boolean; out Char: UCS): Integer;
begin
  Char := UCSCharIllegal;
  AbstractError( ClassName , 'ConvertBufferToUCS');
  Result := 0;
end;

function TPlCharset.ConvertBufferToUTF16(const SrcBuf; SrcCount : Integer; IsLastChunk : Boolean;
  var DstBuf; var DstCount : Integer) : Integer;
var
  SrcBuffer : array [0..0] of Byte absolute SrcBuf;
  DstBuffer : array [0..0] of WideChar absolute DstBuf;
  SrcOffset, DstOffset : Integer;
  Char : UCS;
  k, Written : Integer;
begin
  Result := 0;
  if SrcCount <= 0 then
  begin
    DstCount := 0;
    Exit;
  end;

  Written := 0;
  SrcOffset := 0;
  DstOffset := 0;
  while SrcCount > 0 do
  begin
    k := ConvertBufferToUCS(SrcBuffer[SrcOffset], SrcCount, IsLastChunk, Char);
    if k <= 0 then
      Break;

    Inc(Result, k);
    Inc(SrcOffset, k);
    Dec(SrcCount, k);
    if Char <> UCSCharIgnore then
    begin
      if Char > $10FFFF then
        Char := Ord('?');

      if Char > $FFFF then
      begin
        if Written + 2 > DstCount then
          Break;

        Dec(Char, $10000);
        DstBuffer[DstOffset] := WideChar(((Char shr 10) and $3FF) or $D800);
        DstBuffer[DstOffset + 1] := WideChar((Char and $3FF) or $DC00);
        Inc(DstOffset, 2);
        Inc(Written, 2);
      end
      else
      begin
        if Written + 1 > DstCount then
          Break;

        DstBuffer[DstOffset] := WideChar(Char);
        Inc(DstOffset);
        Inc(Written);
      end;
    end;
  end;

  DstCount := Written;
end;

function TPlCharset.GetCategory: string;
begin
  AbstractError( ClassName , 'GetCategory');
  Result := '';
end;

function TPlCharset.GetDescription: string;
begin
  Result := '';
end;

{$ifdef _USES_RESOURCES_}

class function TPlCharset.GetConversionTablesHashTable:  TStringList ;
begin
    if ConversionTablesHashTable = nil then
    begin
      BackGeneratorLock.Enter;
      try
        if ConversionTablesHashTable = nil then
        begin
          ConversionTablesHashTable := TElStringList.Create;
          ConversionTablesHashTable.Sorted := True;
        end;
      finally
        BackGeneratorLock.Leave;
      end;
    end;
  Result := ConversionTablesHashTable;
end;

class function TPlCharset.AllowSerializationData: Boolean;
begin
  Result := False;
end;

{$ifdef _MAKE_RESOURCES_}
procedure TPlCharset.SerializeData( Stream: TElNativeStream
  {$ifdef _RESNET_SERIALIZABLE_}
  ; pBinaryFormatter: System.Runtime.Serialization.Formatters.Binary.BinaryFormatter
   {$endif}
);
begin
  {empty}
end;

class procedure TPlCharset.IntegerToBytes(iInteger: Integer; var B: ByteArray; iOffset: Integer);
begin
  B[iOffset  ] := (iInteger and $FF);
  B[iOffset+1] := (iInteger shr 8) and $FF;
  B[iOffset+2] := (iInteger shr 16) and $FF;
  B[iOffset+3] := (iInteger shr 24) and $FF;
end;
 {$endif ifdef _MAKE_RESOURCES_}

class function TPlCharset.IntegerFromBytes(const B: ByteArray; iOffset: Integer): Integer;
begin
  Result := Integer(B[iOffset] or (B[iOffset+1] shl 8)
    or (B[iOffset+2] shl 16) or (B[iOffset+3] shl 24));
end;

{$ifdef _DEBUG_RESOURCE_}

class procedure TPlCharset.DebugB(const B:array of byte; const sTitle: String; iLimit: Integer = 0);
var
  i: Integer;
  s: String;
begin
  s := '';
  if iLimit > 0 then
  begin
    if Length(B) < iLimit then
      iLimit := Length(B)-1;
  end
  else
    iLimit := Length(B)-1;
  for i:=0 to iLimit do
  begin
    if i>0 then
      s := s+', '+B[i].ToString
    else
      s := B[i].ToString;
  end;
  WriteLn(' ', sTitle, ' as TBytes = ( ', s, ' )');
end;

 {$endif ifdef _DEBUG_RESOURCE_}

 {$endif ifdef _USES_RESOURCES_}


{ TPlTableCharset }


function TPlTableCharset.CanConvert(Char: UCS): Boolean;
begin
  Result := (Char < fTable.BackItemsCount) or 
            ((Char) <= (fTable.MaxDirectMapped));
  if Result then
    begin
    if (Char) <= (fTable.MaxDirectMapped) then
      Result := ((Char + fShift) >= 0) and ((Char + fShift) <= $FF)
    else if fTable.PagesCount < 2 then
      Result := fTable.ToSingleByte[Char] <> 0
    else
      with fTable.ToMultiByte[Char] do
        Result := (Page > 0) or (Char > 0);
    end;
end;

const
  CFUBufferSize = 32;

function TPlTableCharset.ConvertFromUCS(Char: UCS): Integer;
var
  OutChar, 
  OutBuffer : ByteArray;

  PageIndex : Integer;
  aPage : TPlConversionPage;
begin
  Result := 0;
  
  SetLength(OutChar, 1);
  SetLength(OutBuffer, CFUBufferSize);

  if (Char = 0) or
     ((Char) <= (fTable.MaxDirectMapped)) then
  begin
    Result := 1;
    OutChar[0] := Char + fShift;
    Buffer.Put(OutChar[0], 1);
  end
  else 
  if Char < fTable.BackItemsCount then
  begin
    Result := -1;
    if fTable.PagesCount < 2 then
    begin
      OutChar[0] := fTable.ToSingleByte[Char];
      if OutChar[0] <> 0 then
        begin
          Result := 1;
          Inc(OutChar[0], fShift);
          Buffer.Put(OutChar [0] , 1);
        end;
    end
    else
    begin
      with fTable.ToMultiByte[Char] do
      begin
        OutChar[0] := Char;
        PageIndex := Page;
      end;
      Result := 0;

      while (PageIndex > 0) or (OutChar[0] > 0) do
      begin
        Inc(Result);
        OutBuffer[CFUBufferSize - Result] := OutChar[0] + fShift;
        (*
        {$ifndef SB_NO_WITH_CLAUSE}
        with fTable.Pages[PageIndex] do
          begin
            OutChar[0] := PriorPageChar;
            PageIndex := PriorPageIndex;
          end;
        {$else}
        *)
        aPage := fTable.Pages[PageIndex];

        OutChar[0] := aPage.PriorPageChar;
        PageIndex := aPage.PriorPageIndex;
         (*
        {$endif}
        *)
      end;

      if Result > 0 then
        Buffer.Put(OutBuffer [CFUBufferSize - Result] , Result)
      else
        Result := -1;
    end;
  end
  else
    Result := -1;

  ReleaseArray(OutChar);
  ReleaseArray(OutBuffer);
end;

function TPlTableCharset.ConvertToUCS(Stream: TElNativeStream; out Char: UCS): Integer;
var
  Page, InChar: integer;
  Exists: TSBBoolean;
  aPage : TPlConversionPage;
begin
  Char := UCSCharIllegal;
  Page := 0;
  Result := 0;
  Exists := false;
  while True do
  begin
    InChar := Buffer.GetByte(Stream, Exists);
    if not Exists then
      Break
    else
      Inc(Result);
    if InChar >= fShift then
      InChar := InChar - fShift
    else
      Break;
    if (Page = 0) and (InChar <= fTable.MaxDirectMapped) then
    begin
      Char := InChar;
      Break;
    end;
    if fTable.PagesCount > Page then
    begin
      aPage := fTable.Pages[Page];
      if (aPage.CharsLoIndex <= InChar) and (InChar <= aPage.CharsHiIndex) then
      begin
        if (aPage.Prefixes=cNilPrefixes) or
          not (InChar in aPage.Prefixes ^ )
        then
          begin
            Dec(InChar, aPage.CharsLoIndex);
            Char := aPage.Chars[InChar];

            if aPage.HiBytes <> cNilHiBytes then
              Char := Char or (aPage.HiBytes[InChar] shl 16);

            Break;
          end
        else
            Page := aPage.Chars[InChar - aPage.CharsLoIndex];
      end//;//of: if
      else
        Break;
    end
    else
      Break;
  end;//of: while True
  if Char = UCSCharIllegal then
  begin
    Buffer.ReturnBytes(Result);
    Result := 0;
  end;
  if not Exists then
  begin
    Char := UCSCharIllegal;
    Result := 0;
  end;
end;

function TPlTableCharset.ConvertBufferToUCS(const Buf; Count : Integer; IsLastChunk : Boolean; out Char: UCS): Integer;
var
  Buffer : array [0..0] of Byte absolute Buf;
  Offset : Integer;
  Page, InChar : Integer;
  aPage : TPlConversionPage;
begin
  Char := UCSCharIllegal;
  Result := 0;
  Page := 0;
  Offset := 0;
  while Result < Count do
  begin
    InChar := Buffer[Offset];
    Inc(Result);
    Inc(Offset);
    if InChar >= fShift then
      InChar := InChar - fShift
    else
      Break;

    if (Page = 0) and (InChar <= fTable.MaxDirectMapped) then
    begin
      Char := InChar;
      Break;
    end;

    if fTable.PagesCount > Page then
    begin
      aPage := fTable.Pages[Page];
      if (aPage.CharsLoIndex <= InChar) and (InChar <= aPage.CharsHiIndex) then
      begin
        if (aPage.Prefixes = cNilPrefixes) or
          not (InChar in aPage.Prefixes ^ )
          then
        begin
          Dec(InChar, aPage.CharsLoIndex);
          Char := aPage.Chars[InChar];
          if aPage.HiBytes <> cNilHiBytes then
          Char := Char or (aPage.HiBytes[InChar] shl 16);
          Break;
        end
        else
          Page := aPage.Chars[InChar - aPage.CharsLoIndex];
      end//;//of: if
      else
        Break;
    end
    else
      Break;
  end;

  if Char = UCSCharIllegal then
    Result := 0;
end;

constructor TPlTableCharset.Create;
begin
  inherited Create;
  fTable := GetConversionTable;
  if (fTable = cNilConvTable) then
    exit;
  if (fTable.BackItemsCount = 0) and (fTable.Pages <> nil) then
    GenerateBackTable;
end;

{$ifndef BUILDER_USED}
constructor TPlTableCharset.CreateForFinalize;
begin
  inherited;
  {$ifdef _USED_RESOURCES_}
  fTable := GetConversionTableFromCache;
   {$else}
  fTable := GetConversionTable;
   {$endif}
end;
 {$else}
constructor TPlTableCharset.Create(NoInit : boolean);
begin
  inherited;
  if (not NoInit) then
  begin
    {$ifdef _USED_RESOURCES_}
    fTable := GetConversionTableFromCache;
     {$else}
    fTable := GetConversionTable;
     {$endif}
  end;
end;
 {$endif}


class function TPlTableCharset.IsEqualConversionTables(Tab1, Tab2: PPlConversionTable): Boolean;
begin
   Result :=
     Tab1 = Tab2;
end;

{$ifdef _USED_RESOURCES_}
  {$UNDEF _NoGetMemOne_}
  {.$DEFINE _NoGetMemOne_}
 {$endif}

procedure TPlTableCharset.FinalizeCharset;
{$ifdef _USED_RESOURCES_}
var
  sResID: String;
  idx: Integer;
  {$ifdef _NoGetMemOne_}
  i: Integer;
   {$endif}
 {$endif}
begin
  if (fTable = cNilConvTable) then
    exit;
      BackGeneratorLock.Enter;
  try
    {$ifdef _USED_RESOURCES_}
       sResID := GetResID;
       idx := ConversionTablesHashTable.IndexOf(sResID);
       if (idx >= 0){ and (fTable <> nil)} then
       begin
         if fTable.PagesCount = 1 then
         begin
           FreeMem(fTable.ToSingleByte);
           fTable.ToSingleByte := nil;
         end
         else
         begin
           FreeMem(fTable.ToMultiByte);
           fTable.ToMultiByte := nil;
         end;
         {$ifdef _NoGetMemOne_}
         with fTable^ do
         if (Pages <> nil) and (PagesCount>0) then
         begin
           for i := 0 to PagesCount-1 do
           begin
             with Pages[i] do
             begin
               if Chars <> nil then
               begin
                 FreeMem(Chars);
                 Chars := nil;
               end;
               if HiBytes <> nil then
               begin
                 FreeMem(HiBytes);
                 HiBytes := nil;
               end;
               if Prefixes <> nil then
               begin
                 FreeMem(Prefixes);
                 Prefixes := nil;
               end;
               CharsLoIndex := 0;
               CharsHiIndex := 0;
               PriorPageIndex := 0;
               PriorPageChar  := 0;
             end;
           end;
         end;
          {$endif ifdef _NoGetMemOne_}
         FreeMem(fTable);
         ConversionTablesHashTable.Delete(idx);
       end;
       fTable := cNilConvTable;
     {$else ifdef _USED_RESOURCES_}
        if (fTable.PagesCount>0) then
        begin
          if fTable.PagesCount = 1 then
          begin
            if fTable.ToSingleByte <> nil then
            begin
              FreeMem(fTable.ToSingleByte);
              fTable.ToSingleByte := nil;
            end;
          end
          else
          begin
            if fTable.ToMultiByte <> nil then
            begin
              FreeMem(fTable.ToMultiByte);
              fTable.ToMultiByte := nil;
            end;
          end;
        end;
     {$endif}
  finally
      BackGeneratorLock.Leave;
  end;
end;

procedure TPlTableCharset.GenerateBackTable;
var
  P, B, U, {C,} MaxChar, Pos: Integer;
  AdditionalFromUCS: ByteArray;
  //F: {$ifndef SB_VCL}Integer{$else}PAnsiChar{$endif};
  BackSingleByte: PPlUCSToSingleByteTable;
  BackMultiByte: PPlUCSToMultiByteTable;
  aPage : TPlConversionPage;
begin
  BackSingleByte := nil;
  BackMultiByte := nil;
  AdditionalFromUCS := nil; 

  if (fTable = cNilConvTable) then
    exit;
  // Check Exist BackTable:
  if not ( (fTable.BackItemsCount = 0) and (fTable.Pages <> nil) ) then
    exit;

  BackGeneratorLock.Enter;
  try
    if not ( (fTable.BackItemsCount = 0) and (fTable.Pages <> nil) ) then
      exit;

    //MaxChar := 0;
    if fTable.PagesCount < 2 then
      begin
        GetMem(BackSingleByte, SizeOf(TPlUCSToSingleByteTable));
        FillChar(BackSingleByte^, SizeOf(TPlUCSToSingleByteTable), 0);
        for B := 0 to fTable.MaxDirectMapped do
          BackSingleByte[B] := B;
        MaxChar := fTable.MaxDirectMapped;
        if fTable.PagesCount > 0 then
        begin
          aPage := fTable.Pages[0];
          for B := aPage.CharsLoIndex to aPage.CharsHiIndex do
          begin
            U := aPage.Chars[B - aPage.CharsLoIndex];
            if aPage.HiBytes <> nil then
              U := U or (aPage.HiBytes[B - aPage.CharsLoIndex] shl 16);
            if U <> UCSCharIllegal then
              begin
                if MaxChar < U then
                  MaxChar := U;
                BackSingleByte[U] := B;
              end;
          end;
        end;

        AdditionalFromUCS := GetAdditionalFromUCS;
        if Length(AdditionalFromUCS) > 0 then
        begin
          Pos := 0;
          while Pos < Length(AdditionalFromUCS) - 2 do
          begin
            U := Byte(AdditionalFromUCS[Pos]) shl 8 + Byte(AdditionalFromUCS[Pos + 1]);
            Inc(Pos, 2);
            B := Byte(AdditionalFromUCS[Pos]);
            Inc(Pos, 1);
            if (BackSingleByte[U] = 0) and (U > fTable.MaxDirectMapped) then
            begin
              if MaxChar < U then
                MaxChar := U;

              BackSingleByte[U] := B;
            end;
          end;

          Assert(Pos = Length(AdditionalFromUCS), 'Illegal AdditionalFromUCS');
       end;

        Inc(MaxChar);
        fTable.BackItemsCount := MaxChar;
        GetMem(fTable.ToSingleByte, MaxChar);
        SBMove(BackSingleByte^, fTable.ToSingleByte^, MaxChar);
      end
    else // of: if fTable.PagesCount < 2
      begin
        GetMem(BackMultiByte, SizeOf(TPlUCSToMultiByteTable));
        FillChar(BackMultiByte^, SizeOf(TPlUCSToMultiByteTable), 0);
        for B := 0 to fTable.MaxDirectMapped do
          with BackMultiByte[B] do
            begin
              Page := 0;
              Char := B;
            end;
        MaxChar := fTable.MaxDirectMapped;
        for P := 0 to fTable.PagesCount - 1 do
          begin
            for B := fTable.Pages[P].CharsLoIndex to fTable.Pages[P].CharsHiIndex do
              if (fTable.Pages[P].Prefixes = cNilPrefixes) or
                not (B in fTable.Pages[P].Prefixes ^ ) then
                begin
                  aPage := fTable.Pages[P];

                  U := aPage.Chars[B - aPage.CharsLoIndex];
                  if aPage.HiBytes <> nil then
                    U := U or (aPage.HiBytes[B - aPage.CharsLoIndex] shl 16);

                  with BackMultiByte[U] do
                  if  ({BackMultiByte[U].}Page = 0) and ({BackMultiByte[U].}Char = 0)
                    and (U > fTable.MaxDirectMapped) and (U <> UCSCharIllegal) then
                  begin
                    if MaxChar < U then
                      MaxChar := U;
                    Page := P;
                    Char := B;
                  end;
                end;
          end;

        AdditionalFromUCS := GetAdditionalFromUCS;
        if Length(AdditionalFromUCS) > 0 then
        begin
          B := 0;
          Pos := 0;
          while Pos < Length(AdditionalFromUCS) - 2 do
          begin
            U := ( Byte(AdditionalFromUCS[Pos]) shl 8 + Byte(AdditionalFromUCS[Pos + 1]) ) and $FFFFFF;
            Inc(Pos, 3);
            P := 0;
            while Pos < Length(AdditionalFromUCS) - 1 do
            begin
              B := Byte(AdditionalFromUCS[Pos]);
              Inc(Pos, 1);
              aPage := fTable.Pages[P];

              if (aPage.CharsLoIndex <= B) and (B <= aPage.CharsHiIndex) then
                if (aPage.Prefixes = cNilPrefixes) or
                  not (B in aPage.Prefixes ^ )
                then
                  Break
                else
                  P := aPage.Chars[B - aPage.CharsLoIndex]
              else
              begin
                U := UCSCharIllegal;
                Assert(False, 'Illegal AdditionalFromUCS');
              end;
            end;

            Inc(Pos, 1);
            if U <> UCSCharIllegal then
            begin
              if MaxChar < U then
                MaxChar := U;
              with BackMultiByte[U] do
              begin
                Page := P;
                Char := B;
              end;
            end;
          end;
        end;

        Inc(MaxChar);
        fTable.BackItemsCount := MaxChar;
        MaxChar := MaxChar * SizeOf(TPlUCSToMultiByteItem);
        MaxChar := MaxChar * SizeOf(TPlUCSToMultiByteItem);
        GetMem(fTable.ToMultiByte, MaxChar );
        SBMove(BackMultiByte^, fTable.ToMultiByte^, MaxChar);
      end; // of: if fTable.PagesCount < 2
  finally
    BackGeneratorLock.Leave;
    if BackSingleByte<>nil then
      FreeMem(BackSingleByte);
    if BackMultiByte <> nil then
      FreeMem(BackMultiByte);
  end;
end;

function TPlTableCharset.GetAdditionalFromUCS: ByteArray;
begin
  Result := nil;
end;

//procedure TPlTableCharset.SetBuffer(const Value: IPlConvBuffer);
//begin
//  inherited SetBuffer(Value);
//end;

function TPlTableCharset.GetConversionTable: PPlConversionTable;
begin
  {$ifdef _USED_RESOURCES_}
  if AllowSerializationData then
    Result := GetConversionTableFromResource
  else
   {$endif}
    Result := cNilConvTable;
end;

{$ifdef _USED_RESOURCES_}

class function TPlTableCharset.MakeConversionTableFromStream( Stream: TElNativeStream ):PPlConversionTable;
var
  iLen: Byte;
  iInteger, i0, i1: Integer;
  iWord: Word;
  B: ByteArray;
  vByte: Byte;
  {$ifndef _NoGetMemOne_}
  pLastPtr: Pointer;
   {$endif}
type
  TSet = array[0..255]of byte;
  PSet = ^TSet;
begin
  Stream.Position := 0;
  {$ifdef _DEBUG_RESOURCE_}
  SetLength(B, Stream.Size);
  Stream.Read(B, 0, Length(B));
  DebugB(B, ' Resource');
  Stream.Position := 0;
   {$endif}
  Stream.Read(vByte, 1);
  if vByte = 0 then
    Result := cNilConvTable
  else
  begin
    SetLength(B, SizeOf(Integer));
      Stream.Read(iInteger, SizeOf(Integer)); // Read FullSize Info
      {$ifndef _NoGetMemOne_}
      GetMem(Result, iInteger);
      pLastPtr := Result;
      inc(Integer(pLastPtr), SizeOf(TPlConversionTable) );
       {$else}
      GetMem(Result, SizeOf(TPlConversionTable));
       {$endif}
      // bug #2264 in Chrome .247
    with Result ^  do
    begin
      SetLength(B, SizeOf(Integer)*3);
        Stream.Read(B [0] , Length(B));
        iLen := 0;
        MaxDirectMapped := IntegerFromBytes(B, iLen);
        inc(iLen, SizeOf(Integer));
        PagesCount := IntegerFromBytes(B, iLen);
        // Skip Read BackItemsCount:
        {inc(iLen, SizeOf(Integer));
        BackItemsCount := IntegerFromBytes(B, iLen);{}
        BackItemsCount := 0;
        ToSingleByte := nil;
      if PagesCount < 0 then
        Pages := nil;
      // Result.Pages: PPlConversionPages:
      // TPlConversionPages = array of TPlConversionPage;
      if PagesCount > 0 then
      begin
          {$ifndef _NoGetMemOne_}
          Pages := pLastPtr;
          inc( Integer(pLastPtr), PagesCount * SizeOf(TPlConversionPage) );
           {$else}
          GetMem(Pages, PagesCount*SizeOf(TPlConversionPage));
           {$endif}
        for i0:=0 to PagesCount-1 do
        with Result.Pages[i0] do
        begin
          (*
          TPlConversionPage = packed record
            Chars: PPlChars;
            HiBytes: PPlHiBytes;
            Prefixes: PPlPrefixes;
            CharsLoIndex: Byte;
            CharsHiIndex: Byte;
            PriorPageIndex: Byte;
            PriorPageChar: Byte;
          end;
          *)
          //Chars: PPlChars;
          //TPlChars = array {$ifdef SB_VCL}[Byte]{$endif} of Word;
          Stream.Read(B [0] , SizeOf(Integer));
          iInteger := IntegerFromBytes(B, 0);
          if iInteger <= 0 then
            Chars := nil;
          if iInteger > 0 then
          begin
            Chars := nil;
              {$ifndef _NoGetMemOne_}
              Chars := pLastPtr;
              inc(Integer(pLastPtr), iInteger*SizeOf(Word));
               {$else}
              GetMem(Chars, iInteger*SizeOf(Word));
               {$endif}
            SetLength(B, iInteger * SizeOf(Word));
            Stream.Read(B [0] , Length(B));
            for iInteger := 0 to iInteger-1 do
            begin
              i1 := iInteger*2;
              iWord := Word(B[i1] or (B[i1+1] shl 8));
              Chars[iInteger] := iWord;
            end;
          end;
          //HiBytes: PPlHiBytes;
          //TPlHiBytes = array {$ifdef SB_VCL}[Byte]{$endif} of Byte;
          SetLength(B, SizeOf(Integer));
          Stream.Read(B [0] , SizeOf(Integer));
          iInteger := IntegerFromBytes(B, 0);
          if iInteger <= 0 then
            HiBytes := cNilHiBytes;
          if iInteger > 0 then
          begin
              {$ifndef _NoGetMemOne_}
              HiBytes := pLastPtr;
              inc(Integer(pLastPtr), iInteger);
               {$else}
              GetMem(HiBytes, iInteger);
               {$endif}
            Stream.Read(HiBytes [0] , iInteger);
          end;
          //Prefixes: PPlPrefixes;
          //TPlPrefixes = set of Byte;
          Stream.Read(vByte, 1);
          if vByte = 0 then
            Prefixes := cNilPrefixes
          else
          begin
            iLen := SizeOf(TPlPrefixes);
              {$ifndef _NoGetMemOne_}
              Prefixes := pLastPtr;
              inc(Integer(pLastPtr), iLen);
               {$else}
              GetMem(Prefixes, iLen);
               {$endif}
            Stream.Read(PSet(Prefixes)[0], iLen);
          end;
            //iLen :=
            Stream.Read(B [0] , SizeOf(Integer));
            CharsLoIndex := B[0];
            CharsHiIndex := B[1];
            PriorPageIndex := B[2];
            PriorPageChar := B[3];

        end;//of: with CT.Pages[i0], for

        if BackItemsCount > 0 then
        begin
          // Load BackTable:
          Stream.Read(B [0] , SizeOf(Integer));
          iInteger := IntegerFromBytes(B, 0);
          if iInteger > 0 then
          begin
              {$ifndef _NoGetMemOne_}
              ToSingleByte := pLastPtr;
              inc(Integer(pLastPtr), iInteger);
               {$else}
              GetMem(ToSingleByte, iInteger);
               {$endif}
            Stream.Read(ToSingleByte [0] , iInteger);
          end;
        end;

      end;//of: if PagesCount > 0
    end;//of: with Result
  end;
end;

function TPlTableCharset.GetConversionTableFromCache: PPlConversionTable;
var
  idx: Integer;
  sResID: String;
begin
  if ConversionTablesHashTable = nil then
  begin
    Result := cNilConvTable;
    exit;
  end;
  sResID := GetResID;
  idx := ConversionTablesHashTable.IndexOf(sResID);
  if idx >=0 then
    Result := PPlConversionTable(ConversionTablesHashTable.Objects[idx])
  else
    Result := nil;
end;

function TPlTableCharset.GetConversionTableFromResource: PPlConversionTable;
var
    idx: Integer;
    rs: TResourceStream;
    sResID: String;
  {$ifdef _STRING_RESOURCES_}
    s: String;
   {$endif}
  {$ifdef SB_B64_ENCODED_RESOURCES}
    TmpS : string;
    ResI : integer;
    TmpBuf : ByteArray;
   {$endif}

begin
  GetConversionTablesHashTable; // Create Hash Table if it not allocated.
  sResID := GetResID;


  idx := ConversionTablesHashTable.IndexOf(sResID);
  if idx >=0 then
    Result := PPlConversionTable(ConversionTablesHashTable.Objects[idx])
  else
    Result := nil;
  if Result = nil then
  begin
    BackGeneratorLock.Enter;
    try
      idx := ConversionTablesHashTable.IndexOf(sResID);
      if idx >=0 then
        Result := PPlConversionTable(ConversionTablesHashTable.Objects[idx])
      else
      begin
        rs := TResourceStream.Create(HInstance, sResID, 'SECUREBLACKBOX_UNICODE');
        try
          Result := TPlTableCharset.MakeConversionTableFromStream(rs);
        finally
          FreeAndNil(rs);
        end;
        // Result.BackItemsCount := 0;
        ConversionTablesHashTable.AddObject( sResID, TObject(Result) );
      end;
    finally
      BackGeneratorLock.Leave;
    end;
  end;


end;

 {$endif ifdef _USED_RESOURCES_}

{$ifdef _USES_RESOURCES_}

class function TPlTableCharset.AllowSerializationData: Boolean;
begin
  Result := True; // !!!
end;

{$ifdef _MAKE_RESOURCES_}

class procedure TPlTableCharset.SaveConversionTableToStream( const CT: PPlConversionTable; Stream: TElNativeStream );

var
  iLen: Byte;
  iInteger, iPages, iBackItemsCount, i0, i1: Integer;
  iFullSize, iFullSizePos: Integer;
  iWord: Word;
  B: ByteArray;
type
  TSet = array[0..255] of byte;
  PSet = ^TSet;
begin
  if CT = cNilConvTable then
    iLen := 0
  else
    iLen := 1;
  Stream.Write(iLen, SizeOf(iLen));
  if iLen > 0 then
  with CT ^  do
  begin
    iFullSize := 0;
    iFullSizePos := Stream.Position;
    SetLength(B, SizeOf(Integer));
    IntegerToBytes(iFullSize, B, 0);
    Stream.Write(B [0] , SizeOf(Integer));
    (*
    TPlConversionTable = packed record
      MaxDirectMapped: Integer;
      PagesCount: Integer;
      Pages: PPlConversionPages;
      {$ifndef SB_VCL}
      [NonSerialized] // Including Serialization exclude executing GenerateBackTable, but increases the resource size...
      {$endif}
      BackItemsCount: LongWord;
      {$ifndef SB_VCL}
      [NonSerialized] // Including Serialization exclude executing GenerateBackTable, but increases the resource size...
      ToSingleByte: PPlUCSToSingleByteTable;
      {$else}
      case Integer of
      1: (ToSingleByte: PPlUCSToSingleByteTable);
      2: (ToMultiByte: PPlUCSToMultiByteTable);
      {$endif}
    end;
    *)
    inc(iFullSize, SizeOf(TPlConversionTable));
    SetLength(B, SizeOf(Integer)*3);
      iInteger := 0;
      IntegerToBytes(MaxDirectMapped, B, iInteger);
      if Pages = nil then
        iPages := 0
      else
        iPages := PagesCount;
      inc(iInteger, SizeOf(Integer));
      IntegerToBytes(iPages, B, iInteger);
      inc(iInteger, SizeOf(Integer));
        // Save Back Table:
      //iBackItemsCount := BackItemsCount;
        // No Save Back Table:
      iBackItemsCount := 0;
      IntegerToBytes(iBackItemsCount, B, iInteger);
    Stream.Write(B [0] , Length(B));

    // CT.Pages: PPlConversionPages:
    // TPlConversionPages = array of TPlConversionPage;
    if iPages > 0 then
    begin
      for i0:=0 to iPages-1 do with CT.Pages[i0] do
      begin
        (*
        TPlConversionPage = packed record
          Chars: PPlChars;
          HiBytes: PPlHiBytes;
          Prefixes: PPlPrefixes;
          CharsLoIndex: Byte;
          CharsHiIndex: Byte;
          PriorPageIndex: Byte;
          PriorPageChar: Byte;
        end;
        *)
        //Chars: PPlChars;
        //TPlChars = array {$ifdef SB_VCL}[Byte]{$endif} of Word;
        inc(iFullSize, SizeOf(TPlConversionPage));
        if Chars = nil then
          iInteger := 0
        else
          iInteger := CharsHiIndex - CharsLoIndex + 1;
        IntegerToBytes(iInteger, B, 0);
        Stream.Write(B [0] , SizeOf(Integer));
        if iInteger > 0 then
        begin
          inc(iFullSize, iInteger * SizeOf(Word));
          SetLength(B, iInteger * SizeOf(Word));
          for iInteger := 0 to iInteger-1 do
          begin
            iWord := Chars[iInteger];
            i1 := iInteger*2;
            B[i1  ] := (Word(iWord) and $FF);
            B[i1+1] := (Word(iWord) shr 8) and $FF;
          end;
          Stream.Write(B [0] , Length(B));
        end;
        //HiBytes: PPlHiBytes;
        //TPlHiBytes = array {$ifdef SB_VCL}[Byte]{$endif} of Byte;
        if HiBytes = nil then
          iInteger := 0
        else
          iInteger := CharsHiIndex - CharsLoIndex + 1;
        SetLength(B, SizeOf(Integer));
        IntegerToBytes(iInteger, B, 0);
        Stream.Write(B [0] , SizeOf(Integer));
        if iInteger > 0 then
        begin
          inc(iFullSize, iInteger);
          Stream.Write(HiBytes [0] , iInteger);
        end;
        {.$ifndef SB_NET}
        if Prefixes = cNilPrefixes then
          iLen := 0
        else
        {.$endif}
          iLen := 1;
        Stream.Write(iLen, SizeOf(iLen));
        if iLen > 0 then
        begin
          iLen := SizeOf(TPlPrefixes);
          Stream.Write(PSet(Prefixes)[0], iLen);
          inc(iFullSize, iLen);
        end;
        SetLength(B, SizeOf(Integer));
          B[0] := CharsLoIndex;
          B[1] := CharsHiIndex;
          B[2] := PriorPageIndex;
          B[3] := PriorPageChar;
        Stream.Write(B [0] , Length(B));
      end;//of: for i0 & with CT.Pages[i0], for
      (*
      // not recommended store this tables (it is very large):
      if iBackItemsCount > 0 then
      begin
        {$ifndef SB_VCL}
          iInteger := Length(ToSingleByte);
        {$else}
        if iPages = 1 then
        begin
          iInteger := SizeOf(TPlUCSToSingleByteTable)
        end
        else
        begin
          iInteger := SizeOf(TPlUCSToMultiByteTable);
        end;
        inc(iFullSize, iInteger);
        {$endif}
        // Save BackTable
        (*
        //???: WinApi(XP SP1) can contain bug for big buffer:
        IntegerToBytes(iInteger, B, 0);
        Stream.Write(B{$ifdef SB_VCL}[0]{$else},0{$endif}, SizeOf(Integer));
        if iInteger > 0 then
        begin
          iBackItemsCount := iInteger;
          {.$hints off}
          {$ifndef SB_VCL}
          iPages := Stream.Write(ToSingleByte{$ifdef SB_VCL}[0]{$else},0{$endif}, iInteger);
          {$else}
          iPages := Stream.Write(ToSingleByte{$ifdef SB_VCL}[0]{$else},0{$endif}, iInteger);
            // WinApi can contain bug for big buffer.
          i0 := 0;
          iPages := 0;
          while iInteger > $FFF do
          begin
            i1 := Stream.Write(ToSingleByte{$ifdef SB_VCL}[i0]{$else},i0{$endif}, $FFF);
            if i1 <> $FFF then
            begin
              if i1 = 0 then
                Abort;
              //i1 := 0;
            end;
            dec(iInteger, i1);
            inc(iPages, i1);
            inc(i0, i1);
          end;
          i1 := Stream.Write(ToSingleByte{$ifdef SB_VCL}[i0]{$else},0{$endif}, iInteger);
          inc(iPages, i1);
          {$endif}
          if iPages <> iBackItemsCount then
          begin
            iInteger := iPages;
          end;
          {.$hints on}
        end;
      end;
      //*)
    end;
    i0 := Stream.Position;
    Stream.Position := iFullSizePos;
    SetLength(B, SizeOf(Integer));
    IntegerToBytes(iFullSize, B, 0);
    Stream.Write(B [0] , SizeOf(Integer));
    Stream.Position := i0;
    {$ifdef _DEBUG_RESOURCE_}
      SetLength(B, Stream.Length);
      Stream.Position := 0;
      Stream.Read(B, 0, Length(B));
      DebugB(B, ' Resource');
     {$endif}
  end;//of with CT
end;

procedure TPlTableCharset.SerializeData( Stream: TElNativeStream
  {$ifdef _RESNET_SERIALIZABLE_}
  ; pBinaryFormatter: System.Runtime.Serialization.Formatters.Binary.BinaryFormatter
   {$endif}
);
var
  sResFile: AnsiString;
  stm: TFileStream;   // - bin files.


{$ifndef _RESNET_SERIALIZABLE_}
var
  sResID: String;
  idx: Integer;
  {$ifdef _STRING_RESOURCES_}
  Buf: ByteArray;
   {$endif}
 {$endif}
begin
  {$ifdef D_12_UP}
Error See comment
(*
    _MAKE _ RESOURCES_ define is not supported under Delphi 2009 and up.
    Check the following code "Stream.Write(sResID[1], Length(sResID))"
      where sResID has a type UnicodeString
    To fix this sResID should be converted to AnsiString in all Charsets units!
*)
   {$endif}

  {$ifndef _RESNET_SERIALIZABLE_}
    sResID := GetResID;
     idx := ResourcesKeyIDTables.IndexOf(sResID);
     if (idx >= 0) then
       exit;
   {$endif}

  if  
     (fTable = cNilConvTable)
    // or (fTable.BackItemsCount = 0)
    // or (fTable.Pages = nil)
  then
    fTable := GetConversionTable;
  if (fTable.BackItemsCount = 0) and (fTable.Pages <> nil) then
     GenerateBackTable;
  {$ifdef _RESNET_SERIALIZABLE_}
  pBinaryFormatter.Serialize(Stream, TObject(fTable));
   {$else}
      ResourcesKeyIDTables.AddObject( sResID, ResourcesKeyIDTables );
      //sResID := GetResID;
      sResFile := 'SecureBlackbox.Unicode.' + sResID + '.bin';
      stm := TFileStream.Create( sResFile, fmCreate{ or fmShareDenyWrite });
      try
        SaveConversionTableToStream(fTable, stm);
        sResID := sResID + ' SECUREBLACKBOX_UNICODE "' +sResFile+'"'#13#10;
        Stream.Write(sResID[StringStartOffset], Length(sResID));
      finally
        FreeAndNil(stm);
      end;
   {$endif}
end;
 {$endif ifdef _MAKE_RESOURCES_}
 {$endif ifdef _USES_RESOURCES_}

{ TPlMixedCharset }

function TPlMixedCharset.CanConvert(Char: UCS): Boolean;
var
  I: Integer;
begin
  I := 0;
  Result := False;
  while (I < fCount) and not Result do
    begin
      Result := fCharsets[I].CanConvert(Char);
      Inc(I);
    end;
end;

function TPlMixedCharset.ConvertFromUCS(Char: UCS): Integer;
var
  I: Integer;
begin
  I := 0;
  Result := 0;
  while (I < fCount) do
    begin
      if fCharsets[I].CanConvert(Char) then
        begin
          if (Char > $7F) and (FCharsets[I] is TPlASCII) then // ASCII charset without additional characters
          begin
            Inc(i);
            Continue;
          end;

          Result := fCharsets[I].ConvertFromUCS(Char);
          Break;
        end;
      Inc(I);
    end;
end;

function TPlMixedCharset.ConvertToUCS(Stream: TElNativeStream;
  out Char: UCS): Integer;
var
  I: Integer;
begin
  I := 0;
  Result := 0;
  Char := UCSCharIllegal;
  while I < fCount do
    begin
      Result := fCharsets[I].ConvertToUCS(Stream, Char);
      if (Result > 0) and (Char <> UCSCharIllegal) then
        Break;
      Inc(I);
    end;
end;

function TPlMixedCharset.ConvertBufferToUCS(const Buf; Count : Integer; IsLastChunk : Boolean; out Char: UCS): Integer;
var
  I: Integer;
begin
  I := 0;
  Result := 0;
  Char := UCSCharIllegal;
  while I < fCount do
  begin
    Result := fCharsets[I].ConvertBufferToUCS(Buf, Count, IsLastChunk, Char);
    if (Result > 0) and (Char <> UCSCharIllegal) then
      Break;
      
    Inc(I);
  end;
end;

constructor TPlMixedCharset.Create;
var
  I: Integer;
begin
  inherited Create;
  fCount := GetCharsetsCount;
  for I := 0 to fCount - 1 do
  begin
    fCharsets[I] := GetCharsetClass(I). {$ifndef BUILDER_USED}CreateShift {$else}Create {$endif} (GetCharsetShift(I));
  end;
end;

{$ifndef BUILDER_USED}
constructor TPlMixedCharset.CreateShift(Shift: Integer);
 {$else}
constructor TPlMixedCharset.Create(Shift: Integer);
 {$endif}
var
  I: Integer;
begin
  {$ifndef BUILDER_USED}
  inherited CreateShift(Shift);
   {$else}
  inherited Create(Shift);
   {$endif}
  for I := 0 to fCount - 1 do
    Inc(fCharsets[I].fShift, Shift);
end;

destructor TPlMixedCharset.Destroy;
var
  I: Integer;
begin
  for I := 0 to fCount - 1 do
    fCharsets[I]. Free ;;
  inherited Destroy;
end;

function TPlMixedCharset.GetCharsetShift(Index: Integer): Integer;
begin
  Result := 0;
end;

procedure TPlMixedCharset.SetBuffer(const Value: IPlConvBuffer);
var
  I: Integer;
begin
  inherited SetBuffer(Value);
  for I := 0 to fCount - 1 do
    fCharsets[I].Buffer := Value;
end;

function TPlMixedCharset.GetCharsetClass(Index: Integer): TPlCharsetClass;
begin
  Result := nil;
end;

function TPlMixedCharset.GetCharsetsCount: Integer;
begin
  Result := 0;
end;

{$ifdef _USES_RESOURCES_}
class function TPlMixedCharset.AllowSerializationData: Boolean;
begin
  Result := True;
end;
{$ifdef _MAKE_RESOURCES_}
procedure TPlMixedCharset.SerializeData( Stream: TElNativeStream
  {$ifdef _RESNET_SERIALIZABLE_}
  ; pBinaryFormatter: System.Runtime.Serialization.Formatters.Binary.BinaryFormatter
   {$endif}
);
var
  i: Integer;
  vCH: TPlCharsetClass;
  Charset: TPlCharset;
begin
  for i:=0 to GetCharsetsCount-1 do
  begin
    vCH := GetCharsetClass(i);
    if (vCH<>nil) and vCH.AllowSerializationData then
    begin
       Charset :=  vCH.Create ;
       Charset.SerializeData( Stream
         {$ifdef _RESNET_SERIALIZABLE_}
         , pBinaryFormatter
          {$endif}
       );
       FreeAndNil(Charset);
    end;
  end;
end;
 {$endif}
 {$endif}

{ TPlConvertingCharset }

function TPlConvertingCharset.CanConvert(Char: UCS): Boolean;
begin
  Result := fBase.CanConvert(Char);
end;

function TPlConvertingCharset.ConvertFromUCS(Char: UCS): Integer;
var
  C1, C2: Integer;
begin
  Result := fBase.ConvertFromUCS(Char);
  if Result = 2 then
    begin
      C2 := fBuffer.RevokeByte;
      C1 := fBuffer.RevokeByte;
      ConvertFrom(C1, C2);
      if (C1 < 0) or (C2 < 0) then
        Result := -1
      else
        begin
          fBuffer.PutByte(C1);
          fBuffer.PutByte(C2);
        end;
    end;
end;

function TPlConvertingCharset.ConvertToUCS(Stream: TElNativeStream; out Char: UCS): Integer;
var
  Exists: TSBBoolean;
  C1, C2, S1, S2: Integer;
begin
  Result := 0;
  Exists := false;
  Char := UCSCharIllegal;
  C1 := Buffer.GetByte(Stream, Exists);
  if Exists then
    begin
      C2 := Buffer.GetByte(Stream, Exists);
      if Exists then
        begin
          S1 := C1;
          S2 := C2;
          ConvertTo(S1, S2);
          if (S1 < 0) or (S2 < 0) then
            Char := UCSCharIllegal
          else
            begin
              Buffer.ReturnByte(S2);
              Buffer.ReturnByte(S1);
              Result := fBase.ConvertToUCS(Stream, Char);
              if Char = UCSCharIllegal then
                begin
                  S1 := Buffer.GetByte(Stream, Exists);
                  S2 := Buffer.GetByte(Stream, Exists);
                end;
            end;
          if Char = UCSCharIllegal then
            begin
              Result := 0;
              Buffer.ReturnByte(C2);
              Buffer.ReturnByte(C1);
            end;
        end
      else
        Buffer.ReturnByte;
    end;
end;

function TPlConvertingCharset.ConvertBufferToUCS(const Buf; Count : Integer; IsLastChunk : Boolean; out Char: UCS): Integer;
var
  Buffer : array [0..1] of Byte absolute Buf;
  TmpBuf : array  [0..1]  of Byte;
  C1, C2 : Integer;
begin
  if Count > 1 then
  begin
    C1 := Buffer[ 0 ];
    C2 := Buffer[ 1 ];
    ConvertTo(C1, C2);
    if (C1 < 0) or (C2 < 0) then
    begin
      Result := 0;
      Char := UCSCharIllegal
    end
    else
    begin
      TmpBuf[0] := C1;
      TmpBuf[1] := C2;
      Result := fBase.ConvertBufferToUCS(TmpBuf[0], 2, true, Char);
      if Result <> 2 then
      begin
        Result := 0;
        Char := UCSCharIllegal
      end;
    end;
  end
  else
  begin
    Char := UCSCharIllegal;
    Result := 0;
  end;
end;

constructor TPlConvertingCharset.Create;
begin
  inherited Create;
  fBase :=  GetBaseCharsetClass.Create ;
end;


destructor TPlConvertingCharset.Destroy;
begin
  FreeAndNil(fBase);
  inherited Destroy;
end;

procedure TPlConvertingCharset.SetBuffer(const Value: IPlConvBuffer);
begin
  inherited SetBuffer(Value);
  fBase.Buffer := Value;
end;

procedure TPlConvertingCharset.ConvertFrom(var C1, C2: Integer);
begin
  AbstractError( ClassName , 'ConvertFrom');
end;

procedure TPlConvertingCharset.ConvertTo(var C1, C2: Integer);
begin
  AbstractError( ClassName , 'ConvertTo');
end;

function TPlConvertingCharset.GetBaseCharsetClass: TPlCharsetClass;
begin
  AbstractError( ClassName , 'GetBaseCharsetClass');
  Result := nil;
end;

{ TPlASCII }

{$ifndef _USED_RESOURCES_}

const
  ASCIIConversionTable: TPlConversionTable = (
    MaxDirectMapped: $7F;
    PagesCount: 0;
    Pages: nil;
    BackItemsCount: 0;
    ToSingleByte: nil;
  );

 {$endif ifndef _USED_RESOURCES_}


{$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
 {$else}
var
 {$endif}
  ASCIIAdditionalFromUCS : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = 
    #$A0#$00 + #$20 + #$A1#$00 + #$21 + #$A2#$00 + #$63 + #$A4#$00 + #$24 +
    #$A5#$00 + #$59 + #$A6#$00 + #$7C + #$A9#$00 + #$43 + #$AA#$00 + #$61 +
    #$AB#$00 + #$3C + #$AD#$00 + #$2D + #$AE#$00 + #$52 + #$B2#$00 + #$32 +
    #$B3#$00 + #$33 + #$B7#$00 + #$2E + #$B8#$00 + #$2C + #$B9#$00 + #$31 +
    #$BA#$00 + #$6F + #$BB#$00 + #$3E + #$C0#$00 + #$41 + #$C1#$00 + #$41 +
    #$C2#$00 + #$41 + #$C3#$00 + #$41 + #$C4#$00 + #$41 + #$C5#$00 + #$41 +
    #$C6#$00 + #$41 + #$C7#$00 + #$43 + #$C8#$00 + #$45 + #$C9#$00 + #$45 +
    #$CA#$00 + #$45 + #$CB#$00 + #$45 + #$CC#$00 + #$49 + #$CD#$00 + #$49 +
    #$CE#$00 + #$49 + #$CF#$00 + #$49 + #$D0#$00 + #$44 + #$D1#$00 + #$4E +
    #$D2#$00 + #$4F + #$D3#$00 + #$4F + #$D4#$00 + #$4F + #$D5#$00 + #$4F +
    #$D6#$00 + #$4F + #$D8#$00 + #$4F + #$D9#$00 + #$55 + #$DA#$00 + #$55 +
    #$DB#$00 + #$55 + #$DC#$00 + #$55 + #$DD#$00 + #$59 + #$E0#$00 + #$61 +
    #$E1#$00 + #$61 + #$E2#$00 + #$61 + #$E3#$00 + #$61 + #$E4#$00 + #$61 +
    #$E5#$00 + #$61 + #$E6#$00 + #$61 + #$E7#$00 + #$63 + #$E8#$00 + #$65 +
    #$E9#$00 + #$65 + #$EA#$00 + #$65 + #$EB#$00 + #$65 + #$EC#$00 + #$69 +
    #$ED#$00 + #$69 + #$EE#$00 + #$69 + #$EF#$00 + #$69 + #$F1#$00 + #$6E +
    #$F2#$00 + #$6F + #$F3#$00 + #$6F + #$F4#$00 + #$6F + #$F5#$00 + #$6F +
    #$F6#$00 + #$6F + #$F8#$00 + #$6F + #$F9#$00 + #$75 + #$FA#$00 + #$75 +
    #$FB#$00 + #$75 + #$FC#$00 + #$75 + #$FD#$00 + #$79 + #$FF#$00 + #$79 +
    #$00#$01 + #$41 + #$01#$01 + #$61 + #$02#$01 + #$41 + #$03#$01 + #$61 +
    #$04#$01 + #$41 + #$05#$01 + #$61 + #$06#$01 + #$43 + #$07#$01 + #$63 +
    #$08#$01 + #$43 + #$09#$01 + #$63 + #$0A#$01 + #$43 + #$0B#$01 + #$63 +
    #$0C#$01 + #$43 + #$0D#$01 + #$63 + #$0E#$01 + #$44 + #$0F#$01 + #$64 +
    #$10#$01 + #$44 + #$11#$01 + #$64 + #$12#$01 + #$45 + #$13#$01 + #$65 +
    #$14#$01 + #$45 + #$15#$01 + #$65 + #$16#$01 + #$45 + #$17#$01 + #$65 +
    #$18#$01 + #$45 + #$19#$01 + #$65 + #$1A#$01 + #$45 + #$1B#$01 + #$65 +
    #$1C#$01 + #$47 + #$1D#$01 + #$67 + #$1E#$01 + #$47 + #$1F#$01 + #$67 +
    #$20#$01 + #$47 + #$21#$01 + #$67 + #$22#$01 + #$47 + #$23#$01 + #$67 +
    #$24#$01 + #$48 + #$25#$01 + #$68 + #$26#$01 + #$48 + #$27#$01 + #$68 +
    #$28#$01 + #$49 + #$29#$01 + #$69 + #$2A#$01 + #$49 + #$2B#$01 + #$69 +
    #$2C#$01 + #$49 + #$2D#$01 + #$69 + #$2E#$01 + #$49 + #$2F#$01 + #$69 +
    #$30#$01 + #$49 + #$31#$01 + #$69 + #$34#$01 + #$4A + #$35#$01 + #$6A +
    #$36#$01 + #$4B + #$37#$01 + #$6B + #$39#$01 + #$4C + #$3A#$01 + #$6C +
    #$3B#$01 + #$4C + #$3C#$01 + #$6C + #$3D#$01 + #$4C + #$3E#$01 + #$6C +
    #$41#$01 + #$4C + #$42#$01 + #$6C + #$43#$01 + #$4E + #$44#$01 + #$6E +
    #$45#$01 + #$4E + #$46#$01 + #$6E + #$47#$01 + #$4E + #$48#$01 + #$6E +
    #$4C#$01 + #$4F + #$4D#$01 + #$6F + #$4E#$01 + #$4F + #$4F#$01 + #$6F +
    #$50#$01 + #$4F + #$51#$01 + #$6F + #$52#$01 + #$4F + #$53#$01 + #$6F +
    #$54#$01 + #$52 + #$55#$01 + #$72 + #$56#$01 + #$52 + #$57#$01 + #$72 +
    #$58#$01 + #$52 + #$59#$01 + #$72 + #$5A#$01 + #$53 + #$5B#$01 + #$73 +
    #$5C#$01 + #$53 + #$5D#$01 + #$73 + #$5E#$01 + #$53 + #$5F#$01 + #$73 +
    #$60#$01 + #$53 + #$61#$01 + #$73 + #$62#$01 + #$54 + #$63#$01 + #$74 +
    #$64#$01 + #$54 + #$65#$01 + #$74 + #$66#$01 + #$54 + #$67#$01 + #$74 +
    #$68#$01 + #$55 + #$69#$01 + #$75 + #$6A#$01 + #$55 + #$6B#$01 + #$75 +
    #$6C#$01 + #$55 + #$6D#$01 + #$75 + #$6E#$01 + #$55 + #$6F#$01 + #$75 +
    #$70#$01 + #$55 + #$71#$01 + #$75 + #$72#$01 + #$55 + #$73#$01 + #$75 +
    #$74#$01 + #$57 + #$75#$01 + #$77 + #$76#$01 + #$59 + #$77#$01 + #$79 +
    #$78#$01 + #$59 + #$79#$01 + #$5A + #$7A#$01 + #$7A + #$7B#$01 + #$5A +
    #$7C#$01 + #$7A + #$7D#$01 + #$5A + #$7E#$01 + #$7A + #$80#$01 + #$62 +
    #$89#$01 + #$44 + #$91#$01 + #$46 + #$92#$01 + #$66 + #$97#$01 + #$49 +
    #$9A#$01 + #$6C + #$9F#$01 + #$4F + #$A0#$01 + #$4F + #$A1#$01 + #$6F +
    #$AB#$01 + #$74 + #$AE#$01 + #$54 + #$AF#$01 + #$55 + #$B0#$01 + #$75 +
    #$B6#$01 + #$7A + #$CD#$01 + #$41 + #$CE#$01 + #$61 + #$CF#$01 + #$49 +
    #$D0#$01 + #$69 + #$D1#$01 + #$4F + #$D2#$01 + #$6F + #$D3#$01 + #$55 +
    #$D4#$01 + #$75 + #$D5#$01 + #$55 + #$D6#$01 + #$75 + #$D7#$01 + #$55 +
    #$D8#$01 + #$75 + #$D9#$01 + #$55 + #$DA#$01 + #$75 + #$DB#$01 + #$55 +
    #$DC#$01 + #$75 + #$DE#$01 + #$41 + #$DF#$01 + #$61 + #$E4#$01 + #$47 +
    #$E5#$01 + #$67 + #$E6#$01 + #$47 + #$E7#$01 + #$67 + #$E8#$01 + #$4B +
    #$E9#$01 + #$6B + #$EA#$01 + #$4F + #$EB#$01 + #$6F + #$EC#$01 + #$4F +
    #$ED#$01 + #$6F + #$F0#$01 + #$6A + #$61#$02 + #$67 + #$B9#$02 + #$27 +
    #$BA#$02 + #$22 + #$BC#$02 + #$27 + #$C4#$02 + #$5E + #$C6#$02 + #$5E +
    #$C8#$02 + #$27 + #$CB#$02 + #$60 + #$CD#$02 + #$5F + #$DC#$02 + #$7E +
    #$00#$03 + #$60 + #$02#$03 + #$5E + #$03#$03 + #$7E + #$0E#$03 + #$22 +
    #$31#$03 + #$5F + #$32#$03 + #$5F + #$00#$20 + #$20 + #$01#$20 + #$20 +
    #$02#$20 + #$20 + #$03#$20 + #$20 + #$04#$20 + #$20 + #$05#$20 + #$20 +
    #$06#$20 + #$20 + #$10#$20 + #$2D + #$11#$20 + #$2D + #$13#$20 + #$2D +
    #$14#$20 + #$2D + #$18#$20 + #$27 + #$19#$20 + #$27 + #$1A#$20 + #$2C +
    #$1C#$20 + #$22 + #$1D#$20 + #$22 + #$1E#$20 + #$22 + #$22#$20 + #$2E +
    #$26#$20 + #$2E + #$32#$20 + #$27 + #$35#$20 + #$60 + #$39#$20 + #$3C +
    #$3A#$20 + #$3E + #$22#$21 + #$54 + #$01#$FF + #$21 + #$02#$FF + #$22 +
    #$03#$FF + #$23 + #$04#$FF + #$24 + #$05#$FF + #$25 + #$06#$FF + #$26 +
    #$07#$FF + #$27 + #$08#$FF + #$28 + #$09#$FF + #$29 + #$0A#$FF + #$2A +
    #$0B#$FF + #$2B + #$0C#$FF + #$2C + #$0D#$FF + #$2D + #$0E#$FF + #$2E +
    #$0F#$FF + #$2F + #$10#$FF + #$30 + #$11#$FF + #$31 + #$12#$FF + #$32 +
    #$13#$FF + #$33 + #$14#$FF + #$34 + #$15#$FF + #$35 + #$16#$FF + #$36 +
    #$17#$FF + #$37 + #$18#$FF + #$38 + #$19#$FF + #$39 + #$1A#$FF + #$3A +
    #$1B#$FF + #$3B + #$1C#$FF + #$3C + #$1D#$FF + #$3D + #$1E#$FF + #$3E +
    #$20#$FF + #$40 + #$21#$FF + #$41 + #$22#$FF + #$42 + #$23#$FF + #$43 +
    #$24#$FF + #$44 + #$25#$FF + #$45 + #$26#$FF + #$46 + #$27#$FF + #$47 +
    #$28#$FF + #$48 + #$29#$FF + #$49 + #$2A#$FF + #$4A + #$2B#$FF + #$4B +
    #$2C#$FF + #$4C + #$2D#$FF + #$4D + #$2E#$FF + #$4E + #$2F#$FF + #$4F +
    #$30#$FF + #$50 + #$31#$FF + #$51 + #$32#$FF + #$52 + #$33#$FF + #$53 +
    #$34#$FF + #$54 + #$35#$FF + #$55 + #$36#$FF + #$56 + #$37#$FF + #$57 +
    #$38#$FF + #$58 + #$39#$FF + #$59 + #$3A#$FF + #$5A + #$3B#$FF + #$5B +
    #$3C#$FF + #$5C + #$3D#$FF + #$5D + #$3E#$FF + #$5E + #$3F#$FF + #$5F +
    #$40#$FF + #$60 + #$41#$FF + #$61 + #$42#$FF + #$62 + #$43#$FF + #$63 +
    #$44#$FF + #$64 + #$45#$FF + #$65 + #$46#$FF + #$66 + #$47#$FF + #$67 +
    #$48#$FF + #$68 + #$49#$FF + #$69 + #$4A#$FF + #$6A + #$4B#$FF + #$6B +
    #$4C#$FF + #$6C + #$4D#$FF + #$6D + #$4E#$FF + #$6E + #$4F#$FF + #$6F +
    #$50#$FF + #$70 + #$51#$FF + #$71 + #$52#$FF + #$72 + #$53#$FF + #$73 +
    #$54#$FF + #$74 + #$55#$FF + #$75 + #$56#$FF + #$76 + #$57#$FF + #$77 +
    #$58#$FF + #$78 + #$59#$FF + #$79 + #$5A#$FF + #$7A + #$5B#$FF + #$7B +
    #$5C#$FF + #$7C + #$5D#$FF + #$7D + #$5E#$FF + #$7E {$endif}; 

function TPlASCII.GetAliases: string;
begin
  Result := 'us-ascii,ansi_x3.4-1968,ANSI_X3.4-1986,' +
   'ISO_646.irv:1991,ASCII,ISO646-US,us,IBM367,cp367,' +
   'csASCII,iso-ir-6,20127'; // do not localize
end;

function TPlASCII.GetAdditionalFromUCS: ByteArray;
begin
  {$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
  if ConstLength(ASCIIAdditionalFromUCS) = 0 then
  begin
    ASCIIAdditionalFromUCS := BytesOfString(
      #$A0#$00 + #$20 + #$A1#$00 + #$21 + #$A2#$00 + #$63 + #$A4#$00 + #$24 +
      #$A5#$00 + #$59 + #$A6#$00 + #$7C + #$A9#$00 + #$43 + #$AA#$00 + #$61 +
      #$AB#$00 + #$3C + #$AD#$00 + #$2D + #$AE#$00 + #$52 + #$B2#$00 + #$32 +
      #$B3#$00 + #$33 + #$B7#$00 + #$2E + #$B8#$00 + #$2C + #$B9#$00 + #$31 +
      #$BA#$00 + #$6F + #$BB#$00 + #$3E + #$C0#$00 + #$41 + #$C1#$00 + #$41 +
      #$C2#$00 + #$41 + #$C3#$00 + #$41 + #$C4#$00 + #$41 + #$C5#$00 + #$41 +
      #$C6#$00 + #$41 + #$C7#$00 + #$43 + #$C8#$00 + #$45 + #$C9#$00 + #$45 +
      #$CA#$00 + #$45 + #$CB#$00 + #$45 + #$CC#$00 + #$49 + #$CD#$00 + #$49 +
      #$CE#$00 + #$49 + #$CF#$00 + #$49 + #$D0#$00 + #$44 + #$D1#$00 + #$4E +
      #$D2#$00 + #$4F + #$D3#$00 + #$4F + #$D4#$00 + #$4F + #$D5#$00 + #$4F +
      #$D6#$00 + #$4F + #$D8#$00 + #$4F + #$D9#$00 + #$55 + #$DA#$00 + #$55 +
      #$DB#$00 + #$55 + #$DC#$00 + #$55 + #$DD#$00 + #$59 + #$E0#$00 + #$61 +
      #$E1#$00 + #$61 + #$E2#$00 + #$61 + #$E3#$00 + #$61 + #$E4#$00 + #$61 +
      #$E5#$00 + #$61 + #$E6#$00 + #$61 + #$E7#$00 + #$63 + #$E8#$00 + #$65 +
      #$E9#$00 + #$65 + #$EA#$00 + #$65 + #$EB#$00 + #$65 + #$EC#$00 + #$69 +
      #$ED#$00 + #$69 + #$EE#$00 + #$69 + #$EF#$00 + #$69 + #$F1#$00 + #$6E +
      #$F2#$00 + #$6F + #$F3#$00 + #$6F + #$F4#$00 + #$6F + #$F5#$00 + #$6F +
      #$F6#$00 + #$6F + #$F8#$00 + #$6F + #$F9#$00 + #$75 + #$FA#$00 + #$75 +
      #$FB#$00 + #$75 + #$FC#$00 + #$75 + #$FD#$00 + #$79 + #$FF#$00 + #$79 +
      #$00#$01 + #$41 + #$01#$01 + #$61 + #$02#$01 + #$41 + #$03#$01 + #$61 +
      #$04#$01 + #$41 + #$05#$01 + #$61 + #$06#$01 + #$43 + #$07#$01 + #$63 +
      #$08#$01 + #$43 + #$09#$01 + #$63 + #$0A#$01 + #$43 + #$0B#$01 + #$63 +
      #$0C#$01 + #$43 + #$0D#$01 + #$63 + #$0E#$01 + #$44 + #$0F#$01 + #$64 +
      #$10#$01 + #$44 + #$11#$01 + #$64 + #$12#$01 + #$45 + #$13#$01 + #$65 +
      #$14#$01 + #$45 + #$15#$01 + #$65 + #$16#$01 + #$45 + #$17#$01 + #$65 +
      #$18#$01 + #$45 + #$19#$01 + #$65 + #$1A#$01 + #$45 + #$1B#$01 + #$65 +
      #$1C#$01 + #$47 + #$1D#$01 + #$67 + #$1E#$01 + #$47 + #$1F#$01 + #$67 +
      #$20#$01 + #$47 + #$21#$01 + #$67 + #$22#$01 + #$47 + #$23#$01 + #$67 +
      #$24#$01 + #$48 + #$25#$01 + #$68 + #$26#$01 + #$48 + #$27#$01 + #$68 +
      #$28#$01 + #$49 + #$29#$01 + #$69 + #$2A#$01 + #$49 + #$2B#$01 + #$69 +
      #$2C#$01 + #$49 + #$2D#$01 + #$69 + #$2E#$01 + #$49 + #$2F#$01 + #$69 +
      #$30#$01 + #$49 + #$31#$01 + #$69 + #$34#$01 + #$4A + #$35#$01 + #$6A +
      #$36#$01 + #$4B + #$37#$01 + #$6B + #$39#$01 + #$4C + #$3A#$01 + #$6C +
      #$3B#$01 + #$4C + #$3C#$01 + #$6C + #$3D#$01 + #$4C + #$3E#$01 + #$6C +
      #$41#$01 + #$4C + #$42#$01 + #$6C + #$43#$01 + #$4E + #$44#$01 + #$6E +
      #$45#$01 + #$4E + #$46#$01 + #$6E + #$47#$01 + #$4E + #$48#$01 + #$6E +
      #$4C#$01 + #$4F + #$4D#$01 + #$6F + #$4E#$01 + #$4F + #$4F#$01 + #$6F +
      #$50#$01 + #$4F + #$51#$01 + #$6F + #$52#$01 + #$4F + #$53#$01 + #$6F +
      #$54#$01 + #$52 + #$55#$01 + #$72 + #$56#$01 + #$52 + #$57#$01 + #$72 +
      #$58#$01 + #$52 + #$59#$01 + #$72 + #$5A#$01 + #$53 + #$5B#$01 + #$73 +
      #$5C#$01 + #$53 + #$5D#$01 + #$73 + #$5E#$01 + #$53 + #$5F#$01 + #$73 +
      #$60#$01 + #$53 + #$61#$01 + #$73 + #$62#$01 + #$54 + #$63#$01 + #$74 +
      #$64#$01 + #$54 + #$65#$01 + #$74 + #$66#$01 + #$54 + #$67#$01 + #$74 +
      #$68#$01 + #$55 + #$69#$01 + #$75 + #$6A#$01 + #$55 + #$6B#$01 + #$75 +
      #$6C#$01 + #$55 + #$6D#$01 + #$75 + #$6E#$01 + #$55 + #$6F#$01 + #$75 +
      #$70#$01 + #$55 + #$71#$01 + #$75 + #$72#$01 + #$55 + #$73#$01 + #$75 +
      #$74#$01 + #$57 + #$75#$01 + #$77 + #$76#$01 + #$59 + #$77#$01 + #$79 +
      #$78#$01 + #$59 + #$79#$01 + #$5A + #$7A#$01 + #$7A + #$7B#$01 + #$5A +
      #$7C#$01 + #$7A + #$7D#$01 + #$5A + #$7E#$01 + #$7A + #$80#$01 + #$62 +
      #$89#$01 + #$44 + #$91#$01 + #$46 + #$92#$01 + #$66 + #$97#$01 + #$49 +
      #$9A#$01 + #$6C + #$9F#$01 + #$4F + #$A0#$01 + #$4F + #$A1#$01 + #$6F +
      #$AB#$01 + #$74 + #$AE#$01 + #$54 + #$AF#$01 + #$55 + #$B0#$01 + #$75 +
      #$B6#$01 + #$7A + #$CD#$01 + #$41 + #$CE#$01 + #$61 + #$CF#$01 + #$49 +
      #$D0#$01 + #$69 + #$D1#$01 + #$4F + #$D2#$01 + #$6F + #$D3#$01 + #$55 +
      #$D4#$01 + #$75 + #$D5#$01 + #$55 + #$D6#$01 + #$75 + #$D7#$01 + #$55 +
      #$D8#$01 + #$75 + #$D9#$01 + #$55 + #$DA#$01 + #$75 + #$DB#$01 + #$55 +
      #$DC#$01 + #$75 + #$DE#$01 + #$41 + #$DF#$01 + #$61 + #$E4#$01 + #$47 +
      #$E5#$01 + #$67 + #$E6#$01 + #$47 + #$E7#$01 + #$67 + #$E8#$01 + #$4B +
      #$E9#$01 + #$6B + #$EA#$01 + #$4F + #$EB#$01 + #$6F + #$EC#$01 + #$4F +
      #$ED#$01 + #$6F + #$F0#$01 + #$6A + #$61#$02 + #$67 + #$B9#$02 + #$27 +
      #$BA#$02 + #$22 + #$BC#$02 + #$27 + #$C4#$02 + #$5E + #$C6#$02 + #$5E +
      #$C8#$02 + #$27 + #$CB#$02 + #$60 + #$CD#$02 + #$5F + #$DC#$02 + #$7E +
      #$00#$03 + #$60 + #$02#$03 + #$5E + #$03#$03 + #$7E + #$0E#$03 + #$22 +
      #$31#$03 + #$5F + #$32#$03 + #$5F + #$00#$20 + #$20 + #$01#$20 + #$20 +
      #$02#$20 + #$20 + #$03#$20 + #$20 + #$04#$20 + #$20 + #$05#$20 + #$20 +
      #$06#$20 + #$20 + #$10#$20 + #$2D + #$11#$20 + #$2D + #$13#$20 + #$2D +
      #$14#$20 + #$2D + #$18#$20 + #$27 + #$19#$20 + #$27 + #$1A#$20 + #$2C +
      #$1C#$20 + #$22 + #$1D#$20 + #$22 + #$1E#$20 + #$22 + #$22#$20 + #$2E +
      #$26#$20 + #$2E + #$32#$20 + #$27 + #$35#$20 + #$60 + #$39#$20 + #$3C +
      #$3A#$20 + #$3E + #$22#$21 + #$54 + #$01#$FF + #$21 + #$02#$FF + #$22 +
      #$03#$FF + #$23 + #$04#$FF + #$24 + #$05#$FF + #$25 + #$06#$FF + #$26 +
      #$07#$FF + #$27 + #$08#$FF + #$28 + #$09#$FF + #$29 + #$0A#$FF + #$2A +
      #$0B#$FF + #$2B + #$0C#$FF + #$2C + #$0D#$FF + #$2D + #$0E#$FF + #$2E +
      #$0F#$FF + #$2F + #$10#$FF + #$30 + #$11#$FF + #$31 + #$12#$FF + #$32 +
      #$13#$FF + #$33 + #$14#$FF + #$34 + #$15#$FF + #$35 + #$16#$FF + #$36 +
      #$17#$FF + #$37 + #$18#$FF + #$38 + #$19#$FF + #$39 + #$1A#$FF + #$3A +
      #$1B#$FF + #$3B + #$1C#$FF + #$3C + #$1D#$FF + #$3D + #$1E#$FF + #$3E +
      #$20#$FF + #$40 + #$21#$FF + #$41 + #$22#$FF + #$42 + #$23#$FF + #$43 +
      #$24#$FF + #$44 + #$25#$FF + #$45 + #$26#$FF + #$46 + #$27#$FF + #$47 +
      #$28#$FF + #$48 + #$29#$FF + #$49 + #$2A#$FF + #$4A + #$2B#$FF + #$4B +
      #$2C#$FF + #$4C + #$2D#$FF + #$4D + #$2E#$FF + #$4E + #$2F#$FF + #$4F +
      #$30#$FF + #$50 + #$31#$FF + #$51 + #$32#$FF + #$52 + #$33#$FF + #$53 +
      #$34#$FF + #$54 + #$35#$FF + #$55 + #$36#$FF + #$56 + #$37#$FF + #$57 +
      #$38#$FF + #$58 + #$39#$FF + #$59 + #$3A#$FF + #$5A + #$3B#$FF + #$5B +
      #$3C#$FF + #$5C + #$3D#$FF + #$5D + #$3E#$FF + #$5E + #$3F#$FF + #$5F +
      #$40#$FF + #$60 + #$41#$FF + #$61 + #$42#$FF + #$62 + #$43#$FF + #$63 +
      #$44#$FF + #$64 + #$45#$FF + #$65 + #$46#$FF + #$66 + #$47#$FF + #$67 +
      #$48#$FF + #$68 + #$49#$FF + #$69 + #$4A#$FF + #$6A + #$4B#$FF + #$6B +
      #$4C#$FF + #$6C + #$4D#$FF + #$6D + #$4E#$FF + #$6E + #$4F#$FF + #$6F +
      #$50#$FF + #$70 + #$51#$FF + #$71 + #$52#$FF + #$72 + #$53#$FF + #$73 +
      #$54#$FF + #$74 + #$55#$FF + #$75 + #$56#$FF + #$76 + #$57#$FF + #$77 +
      #$58#$FF + #$78 + #$59#$FF + #$79 + #$5A#$FF + #$7A + #$5B#$FF + #$7B +
      #$5C#$FF + #$7C + #$5D#$FF + #$7D + #$5E#$FF + #$7E );
  end;
   {$endif}
  
  Result := ASCIIAdditionalFromUCS;
end;

function TPlASCII.GetCategory: string;
begin
  Result := SUSCategory;
end;

{$ifndef _USED_RESOURCES_}
function TPlASCII.GetConversionTable: PPlConversionTable;
begin
  Result :=  @ ASCIIConversionTable;
end;
 {$endif}

function TPlASCII.GetDescription: string;
begin
  Result := SUS_ASCII;
end;

{ TPlISO_8859_1 }

{$ifndef _USED_RESOURCES_}
const
  ISO_8859_1ConversionTable: TPlConversionTable = (
    MaxDirectMapped: $FF;
    PagesCount: 0;
    Pages: nil;
    BackItemsCount: 0;
    ToSingleByte: nil;
  );
 {$endif}

function TPlISO_8859_1.GetAliases: string;
begin
  Result := 'iso-8859-1,CP819,IBM819,iso_8859-1,' +
    'iso_8859-1:1987,iso8859-1,iso-ir-100,latin1,l1,' +
    'csISOLatin1,x-ansi,28591'; // do not localize
end;

function TPlISO_8859_1.GetCategory: string;
begin
  Result := SWesternEuropeanCategory;
end;

{$ifndef _USED_RESOURCES_}
function TPlISO_8859_1.GetConversionTable: PPlConversionTable;
begin
  Result :=  @ ISO_8859_1ConversionTable;
end;
 {$endif}

function TPlISO_8859_1.GetDescription: string;
begin
  Result := SISO_8859_1;
end;

{$ifdef _MAKE_RESOURCES_}


procedure SerializeRegisteredCharsets;
var
  stmRC: TFileStream; // - rc file: "SecureBlackbox.Unicode.rc"
  i: Integer;
  Charset: TPlCharset;
  vCH: TPlCharsetClass;
begin
  if (CharsetsList.Count = 0) then
    exit;

  stmRC := TFileStream.Create(
        'SecureBlackbox.Unicode.rc',
        fmCreate or fmShareDenyWrite
      );

  try

  FreeAndNil(ResourcesKeyIDTables);
  ResourcesKeyIDTables := TElStringList.Create;
  ResourcesKeyIDTables.Sorted := True;

  // Serialize Registered Charsets:
  for i:=0 to CharsetsList.Count-1 do
  begin

    vCH := TPlCharsetClass(CharsetsList[i]);
    if (vCH=nil) or (not vCH.AllowSerializationData) then
      continue;

    Charset := vCH.Create;
    Charset.SerializeData( stmRC );
    FreeAndNil(Charset);

  end;//of: for

  finally
    FreeAndNil(stmRC);
  end;

end;

 {$endif}

{$ifdef _USED_RESOURCES_}

{$ifndef SB_NO_NET_THREADS}
{ TResourceGarbageCollector }

constructor TResourceGarbageCollector.Create;
begin
  inherited;
  fTimeOut :=  EncodeTime(0, 17, 0, 0) ;
  fZeroSystemTime :=  Now ;
end;

procedure TResourceGarbageCollector.Dispose;
begin
  if Assigned(fGarbageThread) then
  begin
      fTerminated := True;
      fGarbageThread.Resume;
      fGarbageThread.WaitFor;
      FreeAndNil(fGarbageThread);
      fTerminated := False;
  end;
end;

destructor TResourceGarbageCollector.Destroy;
begin
  Dispose;
  inherited;
end;

procedure TResourceGarbageCollector.AddOnResourceGarbageCollector(Val: TOnResourceGarbageCollector);
var
  i, iLen: Integer;
begin
  iLen := Length(fOnResourceGarbageCollectors);
  for i := 0 to iLen-1 do
  begin
    if @fOnResourceGarbageCollectors[i] = @Val then
      exit;
  end;
  SetLength(fOnResourceGarbageCollectors, iLen + 1);
  fOnResourceGarbageCollectors[iLen] := Val;
end;

procedure TResourceGarbageCollector.DelOnResourceGarbageCollector(Val: TOnResourceGarbageCollector);
var
  i, iLen: Integer;
begin
  iLen := Length(fOnResourceGarbageCollectors);
  for i := 0 to iLen-1 do
  begin
    if @fOnResourceGarbageCollectors[i] = @Val then
    begin
      if i < iLen-1 then
      begin
        Move(fOnResourceGarbageCollectors[i+1], fOnResourceGarbageCollectors[i], (iLen-1-i) * SizeOf(TOnResourceGarbageCollector) );
      end;
      SetLength(fOnResourceGarbageCollectors, iLen-1);
      exit;
    end;
  end;
end;


Type

  TResGarbColThread = class(TThread)
  protected
    fResourceGarbageCollector: TResourceGarbageCollector;
  public
    constructor Create(AResourceGarbageCollector: TResourceGarbageCollector);
    procedure Execute; override;
  end;

constructor TResGarbColThread.Create(AResourceGarbageCollector: TResourceGarbageCollector);
begin
  inherited Create(True);
  Priority :=  {$ifdef SB_WINDOWS}tpLowest {$else}2 {$endif} ;
  fResourceGarbageCollector := AResourceGarbageCollector;
end;

procedure TResGarbColThread.Execute;
begin
  fResourceGarbageCollector.ThreadProc;
end;


procedure TResourceGarbageCollector.set_TimeOut(val:  TDateTime );
var
  vOLDTimeOut:  TDateTime ;
begin
  vOLDTimeOut := fTimeOut;
  fTimeOut := val;
  if Assigned(fGarbageThread) then
  begin
    if (fTimeOut <= 0) then
      Dispose
    else
    if (fTimeOut < vOLDTimeOut) then
    begin
      Dispose;
      Activate;
    end;
  end;
end;

procedure TResourceGarbageCollector.Activate;
begin
  if fTimeOut <= 0 then
    exit;
  if fGarbageThread = nil then
  begin
      fGarbageThread := TResGarbColThread.Create(Self);
      fGarbageThread.Resume;
  end
  else
    {$ifndef NET_CF}
    {$ifndef SB_NO_NET_THREADRESUME}
    fGarbageThread.Resume;
     {$endif}
     {$endif}
end;

procedure TResourceGarbageCollector.ThreadProc;
var
  i: Integer;
  vEvent: TOnResourceGarbageCollector;
begin
  while True do
  begin
    if fTerminated then
      break;
    try
      for i := 0 to Length(fOnResourceGarbageCollectors)-1 do
      begin
        vEvent := fOnResourceGarbageCollectors[i];
        vEvent(Self);
        if fTerminated then
          break;
      end;
    except
    end;
  end;//of: while True
end;

 {$endif ifndef SB_NO_NET_THREADS}

 {$endif ifdef _USED_RESOURCES_}




procedure Initialize;
begin
  AcquireGlobalLock();
  try

      BackGeneratorLock := TCriticalSection.Create;
      CharsetsList :=   TElList.Create;  

      {$ifdef _MAKE_RESOURCES_}
      ResourcesKeyIDTables :=  TStringList .Create;
       {$endif}
      

  finally
    ReleaseGlobalLock;
  end;
end;

initialization
  begin
    Initialize;
  end;
finalization
  begin
    FinalizeCharsets;
    FreeAndNil(CharsetsList);
    FreeAndNil(BackGeneratorLock);
  end;

  
end.
