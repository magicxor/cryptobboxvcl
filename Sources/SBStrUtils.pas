(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}




{$ifdef SB_MACOS}
 {$endif}

unit SBStrUtils;

interface

uses
  SBConstants,
  {$ifdef SB_WINDOWS}
  Windows,
   {$endif}
  SysUtils,
  Classes,
  SBTypes,
  SBUtils
  ;


const
  UNI_REPLACEMENT_CHAR: UTF32 = $0000FFFD;
  UNI_MAX_BMP: UTF32 = $0000FFFF;
  UNI_MAX_UTF16: UTF32 = $0020FFFF;
  //UNI_MAX_UTF32: UTF32 = $7FFFFFFF;
  halfShift: integer = 10;      { used for shifting by 10 bits }
  halfBase: UTF32 = $0010000;
  halfMask: UTF32 = $3FF;
  UNI_SUR_HIGH_START: UTF32 = $0D800;
  UNI_SUR_HIGH_END: UTF32 = $0DBFF;
  UNI_SUR_LOW_START: UTF32 = $0DC00;
  UNI_SUR_LOW_END: UTF32 = $0DFFF;

  {$EXTERNALSYM CP_UTF8}
  CP_UTF8                  = 65001;         { UTF-8 translation }

  {
    Index into the table below with the first byte of a UTF-8 sequence to
    get the number of trailing bytes that are supposed to follow it.
  }

  trailingBytesForUTF8: array  [0..255]  of byte =
     ( 
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
        2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, 3,3,3,3,3,3,3,3,4,4,4,4,5,5,5,5
     ) ;

type

  TElStringConverter =  class
  protected
    FDefCharset : string;
    procedure SetDefCharset(const Value : string); virtual;
  public
    constructor Create;

    function StrToUtf8(const Source : string) : ByteArray; virtual;
    function Utf8ToStr(const Source : ByteArray) : string; virtual;
    function StrToWideStr(const Source : string) : ByteArray; virtual;
    function WideStrToStr(const Source : ByteArray) : string; virtual;

    property DefCharset : string read FDefCharset write SetDefCharset;
  end;

  {$ifdef SB_WINDOWS_OR_NET_OR_JAVA}
  // internal converter for .NET/Windows
  TElPlatformStringConverter =  class(TElStringConverter)
  protected
    procedure SetDefCharset(const Value : string); override;
    function GetWindowsCodePageIdentifier(const Name : string): integer;
  public
    constructor Create;

    function StrToUtf8(const Source : string) : ByteArray; override;
    function Utf8ToStr(const Source : ByteArray) : string; override;
    function StrToWideStr(const Source : string) : ByteArray; override;
    function WideStrToStr(const Source : ByteArray) : string; override;

    {$ifndef SB_NO_NET_ENCODING_CODES}
    function EncodeStr(const Source : string; Encoding : integer) : ByteArray;  overload; 
    function DecodeStr(const Source : ByteArray; Encoding : integer) : string;  overload; 
     {$endif}
    function EncodeStr(const Source : string; const Encoding : string) : ByteArray;  overload; 
    function DecodeStr(const Source : ByteArray; const Encoding : string) : string;  overload; 
  end;
   {$endif}

// StringClear - actually works with string builder
// StringEndsWith
function StringEndsWith(const S, SubS: string): Boolean;  overload; function StringEndsWith(const S, SubS: string; IgnoreCase: Boolean): Boolean;
   overload; // StringEquals
function StringEquals(const S1, S2: string): Boolean;  overload; 
function StringEquals(const S1, S2: string; IgnoreCase: Boolean): Boolean;
   overload; function StringEquals(const S1, S2: string; MaxLength: Integer): Boolean;
   overload; function StringEquals(const S1, S2: string; MaxLength: Integer; IgnoreCase: Boolean): Boolean;
   overload; function StringEquals(const S1: string; Index1: Integer; const S2: string; Index2: Integer;
  MaxLength: Integer): Boolean;  overload; function StringEquals(const S1: string; Index1: Integer; const S2: string; Index2: Integer;
  MaxLength: Integer; IgnoreCase: Boolean): Boolean;  overload; 
// StringIndexOf
function StringIndexOf(const S: string; const C: Char): Integer;
   overload; function StringIndexOf(const S: string; const C: Char; StartIndex: Integer): Integer;
   overload; function StringIndexOf(const S: string; const SubS: string): Integer;
   overload; function StringIndexOf(const S: string; const SubS: string; StartIndex: Integer): Integer;
   overload; 
function StringIndexOfU(const S: UnicodeString; const C: WideChar): Integer;

// StringInsert
function StringInsert(const S: UnicodeString; Index: Integer; C: WideChar): UnicodeString;
   overload; function StringInsert(const S: UnicodeString; Index: Integer; SubS: string): UnicodeString;
   overload;   
function StringInsert(const S: AnsiString; Index: Integer; C: AnsiChar): AnsiString;  overload; 
function StringInsert(const S: AnsiString; Index: Integer; SubS: AnsiString): AnsiString;  overload; 
// StringIsEmpty
function StringIsEmpty(const S: string): Boolean; 
// StringLastIndexOf
function StringLastIndexOf(const S: UnicodeString; const C: WideChar): Integer;
   overload; function StringLastIndexOf(const S: UnicodeString; const C: WideChar; StartIndex: Integer): Integer;
   overload;   
function StringLastIndexOf(const S: AnsiString; const C: AnsiChar): Integer; overload;
function StringLastIndexOf(const S: AnsiString; const C: AnsiChar; StartIndex: Integer): Integer; overload;

// StringRemove
function StringRemove(const S: UnicodeString; StartIndex: Integer): UnicodeString;
   overload; function StringRemove(const S: UnicodeString; StartIndex, Count: Integer): UnicodeString;
   overload; 
function WideStringRemove(const S: UnicodeString; StartIndex: Integer): UnicodeString;
   overload; function WideStringRemove(const S: UnicodeString; StartIndex, Count: Integer): UnicodeString;
   overload; 

function StringRemove(const S: AnsiString; StartIndex: Integer): AnsiString;
   overload; function StringRemove(const S: AnsiString; StartIndex, Count: Integer): AnsiString;
   overload; 
function AnsiStringRemove(const S: AnsiString; StartIndex: Integer): AnsiString;
   overload; function AnsiStringRemove(const S: AnsiString; StartIndex, Count: Integer): AnsiString;
   overload;  

// StringLowerCase
function StringToLower(const S: string): string; 
function StringToLowerInvariant(const S: string): string; 
// StringStartsWith
function StringStartsWith(const S, SubS: string): Boolean;  overload; function StringStartsWith(const S, SubS: string; IgnoreCase: Boolean): Boolean;
   overload; // StringSubstring
function StringSubstring(const S: string; StartIndex: Integer): string;  overload; function StringSubstring(const S: string; StartIndex, Length: Integer): string;  overload; {$ifdef SB_ANSI_VCL}
function StringSubstring(const S: UnicodeString; StartIndex: Integer): UnicodeString; overload;
function StringSubstring(const S: UnicodeString; StartIndex, Length: Integer): UnicodeString; overload;
 {$endif}

// StringTrim*
function StringTrim(const S: string): string; 
function StringTrimEnd(const S: string): string; 
function StringTrimStart(const S: string): string; 
// StringUpperCase
function StringToUpper(const S: string): string; 
function StringToUpperInvariant(const S: string): string; 
// StringSplit
function StringSplit(const S: string; Separator: Char): StringArray;  overload ;
function StringSplit(const S: string; Separator: Char; RemoveEmptyEntries: Boolean): StringArray;  overload ;

function StringSplitPV(const S : string; out Name : string; out Value : string) : boolean;  overload ;
function StringSplitPV(const S : string; out Name : string; out Value : string; Separator : char) : boolean;  overload ;

{$ifdef SB_ANSI_VCL}
function StringSplitPV(const S : UnicodeString; out Name : UnicodeString; out Value : UnicodeString) : boolean;  overload ;
function StringSplitPV(const S : UnicodeString; out Name : UnicodeString; out Value : UnicodeString; Separator : WideChar) : boolean;  overload ;
 {$endif}

{$ifndef SB_UNICODE_VCL}
function WideStringSplit(const S: WideString; Separator: WideChar): WideStringArray;  overload ;
function WideStringSplit(const S: WideString; Separator: WideChar; RemoveEmptyEntries: Boolean): WideStringArray;  overload ;
 {$endif}



{$ifndef SB_UNICODE_VCL}
function StrToDefEncoding(const AStr : string) : ByteArray;
function DefEncodingToStr(const ASrc : ByteArray) : string;
function StrToStdEncoding(const AStr : string; UseUTF8 : boolean) : ByteArray;
function StdEncodingToStr(const ASrc : ByteArray; UseUTF8 : boolean): string;
 {$else}
function StrToDefEncoding(const AStr : string) : ByteArray;
function DefEncodingToStr(ASrc : ByteArray) : string;
 {$endif}

{$ifndef VCL50}
function SameText(const S1, S2: string): Boolean;
 {$endif}


function SBExtractFilePath(const FileName : string) : string; 
function SBExtractFileName(const FileName : string) : string; 
function SBExtractFileExt(const FileName : string) : string;  overload ;
function SBExtractFileExt(const FileName : string; IncludeDot: Boolean) : string;  overload ;
function ReplaceExt(const FileName : string; const NewExtension : string) : string; 

function FilenameMatchesMask(const Name, Mask : string; CaseSensitive : boolean) : boolean; 

function DomainNameMatchesCertSN(DomainName, Match : string) : boolean;  

// this function counts, how many folder names are present in the path
function CountFoldersInPath(const Path : string) : integer; 

procedure ParseURL(URL: string; SingleNameIsPage : Boolean;
  var Protocol: string; var Username : string; var Password : string;
  var Host: string; var Port: word; var Path: string; var anchor : string; var Parameters: string);  overload ;
procedure ParseURL(URL: string; SingleNameIsPage : Boolean;
  var Protocol: string; var Username : string; var Password : string;
  var Host: string; var Port: word; var Path: string; var anchor : string; var Parameters: string;
  const DefaultProtocol: string);  overload ;
function ComposeURL(const Protocol, UserName, Password, Host: string; Port: Word;
  const Path, Anchor, Parameters: string): string; 


function SBRightPos(const Substr, Str : string) : integer; 

function SBPos(const substr, str: AnsiString): Integer; overload;

{$ifdef SB_UNICODE_VCL}
function SBPos(const substr, str: string): Integer; overload;
 {$endif}


{$ifndef HAS_DEF_PARAMS}
function SBPos(const SubP : ByteArray; const P : ByteArray) : integer;  overload; function SBPos(const SubP : string; const P : ByteArray) : integer;  overload;  {$endif}

function SBPos(const SubP :  ByteArray ; const P :  ByteArray ; StartPos : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}) : integer;  overload; function SBPos(const SubP : string; const P : ByteArray; StartPos : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}) : integer;  overload; 
function SBPos(SubP : byte; const P : ByteArray) : integer;  overload; 

function SBCopy(const str:  ByteArray ; Offset, Size : integer): ByteArray;  overload; function SBCopy(const str:  ByteArray ): ByteArray;  overload; 
function SBConcatAnsiStrings(Str1 : AnsiString; Str2 : AnsiChar) : AnsiString;  overload;  

function SBConcatAnsiStrings(Str1, Str2 : AnsiString) : AnsiString;  overload; function SBConcatAnsiStrings(const Strs : array of AnsiString): AnsiString;  overload; 
function AnsiStrPas(P: PAnsiChar) : AnsiString;



function OIDToStr(const OID: ByteArray): String; 
function StrToOID(const Str : string) : ByteArray; 


function StrToUTF8(const AStr: string) : ByteArray; 
function UTF8ToStr(const ASrc: ByteArray) : string; 
function StrToWideStr(const AStr: string) : ByteArray; 
function WideStrToStr(const ASrc: ByteArray) : string; 

(*
function LittleEndianToBigEndianUnicode(const Data : ByteArray): ByteArray; {$ifdef SB_NET}public;{$endif}
function BigEndianToLittleEndianUnicode(const Data : ByteArray): ByteArray; {$ifdef SB_NET}public;{$endif}
*)
function UnicodeChangeEndianness(const Data : ByteArray): ByteArray; 

function WideStrToUTF8(const AStr: UnicodeString) : ByteArray; overload;
function WideStrToUTF8(const ASrc; Size: integer) : ByteArray; overload;
function UTF8ToWideStr(const Buf: ByteArray): UnicodeString; overload;
function UTF8ToWideStr(const Buf; Size: Integer): UnicodeString; overload;

function ConvertUTF16toUTF8(const source: UnicodeString;
                        var target: ByteArray;
                        flags: ConversionFlags;
                        BOM: boolean): ConversionResult;

function isLegalUTF8(const source: ByteArray; sourcelen: cardinal): boolean;

function ConvertUTF8toUTF16(const source: ByteArray;
                             var target: UnicodeString;
                             flags: ConversionFlags;
                             BOM: boolean): ConversionResult;

function ConvertFromUTF8String(const Source : ByteArray; CheckBOM : boolean = true) : UnicodeString;
function ConvertToUTF8String(const Source : UnicodeString) : ByteArray;

{$ifndef SB_NO_CHARSETS}
function ConvertFromUTF32String(const Source: ByteArray; CheckBOM: Boolean = True): UnicodeString;
 {$endif}

procedure SetGlobalConverter(Converter : TElStringConverter); 
{$ifndef SB_NO_CHARSETS}
procedure SetDefaultCharset(const Charset : string); 
 {$endif}

function StrMixToInt64(const S : string) : Int64; 

{$ifndef VCL60}
function TryStrToInt(const S: string; out Value: Integer): Boolean;
function TryStrToInt64(const S: string; out Value: Int64): Boolean;
 {$endif}

function SBTrim(const S : ByteArray) : ByteArray; 

function SBUppercase(const S : ByteArray): ByteArray; 


{$ifdef SB_UNICODE_VCL}
function LowerCase(const s: ByteArray): ByteArray; overload;
function UpperCase(const s: ByteArray): ByteArray; overload;
 {$endif}

function ReplaceStr(const Source : string; Entry, ReplaceWith : string) : string;


function PAnsiCharToByteArray(const P : PAnsiChar) : ByteArray;


function PrefixString(const S : string; Count : integer; Value : char) : string;
function SuffixString(const S : string; Count : integer; Value : char) : string;

function PathFirstComponent(const Path : string) : string; 
function PathLastComponent(const Path : string) : string; 
function PathCutFirstComponent(const Path : string) : string; 
function PathCutLastComponent(const Path : string) : string; 
function PathIsDirectory(const Path : string) : boolean; 
function PathTrim(const Path : string) : string; 
function PathConcatenate(const Path1, Path2 : string) : string; 
function PathNormalizeSlashes(const Path : string) : string; 
function PathReverseSlashes(const Path : string) : string; 
function PathMatchesMask(const Path, Mask : string) : boolean;  overload; 
function PathMatchesMask(const Path, Mask : string; CaseSensitive : boolean) : boolean;  overload; 
function IsFileMask(const Path : string) : boolean; 
function ExtractPathFromMask(const Mask : string) : string;  

// ZIP specific functions that may work incorrectly for regular paths
function ZipPathFirstComponent(const Path : string) : string; 
function ZipPathLastComponent(const Path : string) : string; 
function ZipPathCutFirstComponent(const Path : string) : string; 
function ZipPathCutLastComponent(const Path : string) : string; 
function ZipPathIsDirectory(const Path : string) : boolean; 
function ZipPathTrim(const Path : string) : string; 
function ZipPathConcatenate(const Path1, Path2 : string) : string; 
function ZipPathNormalizeSlashes(const Path : string) : string; 
function ZipPathReverseSlashes(const Path : string) : string; 
function ZipPathMatchesMask(const Path, Mask : string) : boolean;  overload; 
function ZipPathMatchesMask(const Path, Mask : string; CaseSensitive : boolean) : boolean;  overload; 
function ZipIsFileMask(const Path : string) : boolean; 
function ZipExtractPathFromMask(const Mask : string) : string;  

//function ExtractFile(const Path : string) : string; {$ifdef SB_NET}public;{$endif}
//function ExtractDirectory(const Path : string) : string; {$ifdef SB_NET}public;{$endif}


// --------------------------------------------------------------------
// This came from SBMIMEUtils
//

function PosExSafe(const SubStr, S: AnsiString;
  Offset: Integer;
  Count: Integer): Integer; 
function PosLast(const SubStr, S: AnsiString): Integer; 
function WidePosEx(const SubStr, S: TWideString;
  Offset: Integer;
  Count: Integer): Integer; 
function WidePosLast(const SubStr, S: TWideString): Integer; 

function WideStringToByteString(const WS: TWideString): AnsiString; 
function AnsiStringToByteWideString(const S: AnsiString): TWideString; 
function IntToStrPadLeft(Val: Integer;
  iWidth: Integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif};
  chTemplate: TWideChar {$ifdef HAS_DEF_PARAMS} =  '0' {$endif}): TWideString; 

//procedure GetBytesOf(const Value: AnsiString; var B: TBytes);
procedure GetWideBytesOf(const Value: TWideString; var B: TBytes);
procedure GetStringOf(const Bytes: TBytes; var S: AnsiString);
procedure GetStringOfEx(const Bytes: TBytes; var S: AnsiString; LPos: Int64 = 0; RPos: Int64 = -1);
procedure GetWideStringOf(const Bytes: TBytes; var WS: TWideString);

procedure TrimEx(var S: AnsiString;
  bTrimLeft: Boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif};
  bTrimRight: Boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif});  overload; procedure TrimSemicolon(var S : TWideString);
function ExtractWideFileName(const FileName: TWideString): TWideString; 
function ExtractFileExtension(const FileName: TWideString): AnsiString; 

function ExtractWideFileExtension(const FileName: TWideString): TWideString; 

function WideTrimRight(const S : TWideString): TWideString;

procedure DecodeDateTime(const AValue: TElDateTime;
  out AYear, AMonth, ADay, AHour, AMinute, ASecond, AMilliSecond: Word); 

//function MergeLines(Strings : TStrings) : string;

//
// End of SBMIMEUtils
// --------------------------------------------------------------------


// --------------------------------------------------------------------
// This came from SBMIMEDateTime
//
function ParseRFC822TimeString(RFC822TimeString : TWideString; var ADateTime: TElDateTime): Boolean;

function LocalDateTimeToRFC822DateTimeString(ADateTime: TElDateTime): AnsiString;
function SystemDateTimeToRFC822DateTimeString(ADateTime: TElDateTime): AnsiString;

function UniversalDateTimeToRFC822DateTimeString(DT: TElDateTime): TWideString; 
function RFC822TimeStringToUniversalTime(TS: TWideString; var DT: TElDateTime): Boolean; 

//
// End of SBMIMEDateTime
// --------------------------------------------------------------------


var
  {$ifndef SB_MSSQL}
  G_StringConverter : TElStringConverter   =  nil ;
   {$else}
  G_StringConverter : TElStringConverter := TElPlatformStringConverter.Create; readonly;
   {$endif}

var
  EmptyString: string  = '' ; {$ifdef SB_MSSQL}readonly; {$endif}

  (*
  {$ifndef SB_DELPHI_MOBILE}
  EmptyAnsiString: AnsiString {$ifndef SB_NET}= ''{$else}:= EmptyArray{$endif}; {$ifdef SB_MSSQL}readonly;{$endif}
  EmptyUnicodeString : UnicodeString {$ifndef SB_NET}= ''{$else}:= String.Empty{$endif}; {$ifdef SB_MSSQL}readonly;{$endif}
  {$else}
  EmptyAnsiString : AnsiString;
  EmptyUnicodeString : String = '';
  {$endif}
  *)

implementation

{$ifndef SB_NO_CHARSETS}
uses
  SBUnicode;
 {$endif}

const
  {$ifdef SB_WINDOWS}
  SLASH = '\';
   {$else}
  SLASH = '/';
   {$endif}

// Done 7 / XE5(32) / XE5(64) / Android
function PrefixString(const S : string; Count : integer; Value : char) : string;
var
  i : integer;
begin
  // DeN 11.10.2013
  (*
  if ((S = '') and (Value = #0))  or
     ((S <> '') and (Value = #0)) then
    Exit;
  *)
  // end DeN 11.10.2013
  if (Value = #0) or (Count = 0) then 
  begin
    Result := S;
    exit;
  end;
    
  SetLength(Result, Count);
  for i := StringStartOffset to StringStartOffset + Count - StringStartInvOffset do
     Result[i] := Value;

  Result := Result + S; 
  // SBMove(S, stringStartOffset, Result, stringStartOffset + Count, Length(S) * Sizeof(Char));
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SuffixString(const S : string; Count : integer; Value : char) : string;
var 
  i : integer;
begin
  // DeN 11.10.2013
  (*
  if ((S = '') and (Value = #0))  or
     ((S <> '') and (Value = #0)) then
    Exit;
  *)
  // end DeN 11.10.2013
  if (Value = #0) or (Count = 0) then 
  begin
    Result := S;
    exit;
  end;
  	
  //Result := StringSubstring(S, StringStartOffset, MaxInt);
  SetLength(Result, {Length(S) +} Count);
  for i := StringStartOffset to Count + StringStartOffset - 1 do
     Result[i] := Value;
  //Move(Buffer[StringStartOffset], Result[StringStartOffset], Length(Buffer)); // DeN 11.10.2013 - add
  //SBMove(S, StringStartOffset, Result, StringStartOffset, Length(S) * Sizeof(Char));
  result := S + Result; 
end;

{$ifndef SB_NO_CHARSETS}
// Inner - Not tested
function GetStringConverter() : TElStringConverter;
begin
  if G_StringConverter = nil then
  begin
    AcquireGlobalLock();
    try
      if G_StringConverter = nil then
        G_StringConverter := SBUnicode.CreateUnicodeStringConverter();
    finally
      ReleaseGlobalLock();
    end;
  end;
  Result := G_StringConverter;
end;
 {$endif}

// Done 7 / XE5(32) / XE5(64) / Android
function StringEquals(const S1, S2: string): Boolean;
begin
  Result := (AnsiCompareStr(S1, S2) = 0);


end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringEquals(const S1, S2: string; IgnoreCase: Boolean): Boolean;
begin
  // DeN 16.09.2013
  if not IgnoreCase then
    Result := (AnsiCompareStr(S1, S2) = 0)
  else
  // end DeN 16.09.2013  
    Result := (CompareText(S1, S2) = 0)

{$ifdef NET_1_0}
{$define NO_STRING_COMPARISON}
 {$endif}
{$ifdef NET_CF_1_0}
{$define NO_STRING_COMPARISON}
 {$endif}


end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringEquals(const S1, S2: string; MaxLength: Integer): Boolean;
begin

  Result := (AnsiStrLComp(PChar(S1), PChar(S2), MaxLength) = 0);



end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function StringEquals(const S1, S2: string; MaxLength: Integer; IgnoreCase: Boolean): Boolean;
begin
  if IgnoreCase then
    (*
    {$ifdef SB_DELPHI_MOBILE}
    Result := (StrLIComp(PChar(S1), PChar(S2), MaxLength) = 0) // DeN 10.01.2014
    {$else}
    Result := (AnsiStrLIComp(PChar(S1), PChar(S2), MaxLength) = 0)
    {$endif}
    *)
    Result := (StrLIComp(PChar(S1), PChar(S2), MaxLength) = 0) // DeN 10.01.2014
  else
    (*
    {$ifdef SB_DELPHI_MOBILE}
    Result := (StrLComp(PChar(S1), PChar(S2), MaxLength) = 0); // DeN 10.01.2014
    {$else}
    Result := (AnsiStrLComp(PChar(S1), PChar(S2), MaxLength) = 0);
    {$endif}
    *)
    Result := (StrLComp(PChar(S1), PChar(S2), MaxLength) = 0); // DeN 10.01.2014


end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function StringEquals(const S1: string; Index1: Integer; const S2: string; Index2: Integer;
  MaxLength: Integer): Boolean;
begin
  if (MaxLength = 0) and (Length(S1) = 0) and (Length(S2) = 0) and
    (Index1 = StringStartOffset) and (Index2 = StringStartOffset) then
  begin
    Result := true;
    Exit;
  end;

  if (Index1 < StringStartOffset) or (Index2 < StringStartOffset) or (MaxLength < 0) or
    (Index1 > Length(S1)) or (Index2 > Length(S2)) then
  begin
    Result := false;
    Exit;
  end;

  if (MaxLength > Length(S1) - Index1 + 1) or (MaxLength > Length(S2) - Index2 + 1) then
    MaxLength := Max(Length(S1) - Index1 + 1, Length(S2) - Index2 + 1);

  Result := (AnsiStrLComp(PChar(S1) + (Index1 - 1), PChar(S2) + (Index2 - 1), MaxLength) = 0);


end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function StringEquals(const S1: string; Index1: Integer; const S2: string; Index2: Integer;
  MaxLength: Integer; IgnoreCase: Boolean): Boolean;
begin
  if IgnoreCase then
    Result := (AnsiStrLIComp(PChar(S1) + (Index1 - 1), PChar(S2) + (Index2 - 1), MaxLength) = 0)
  else
    Result := (AnsiStrLComp(PChar(S1) + (Index1 - 1), PChar(S2) + (Index2 - 1), MaxLength) = 0);


end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringIndexOf(const S: string; const C: Char): Integer;
begin

  Result := System.Pos(C, S);



end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringIndexOf(const S: string; const C: Char; StartIndex: Integer): Integer;
begin
  // DeN 16.09.2013
  Result := StringStartOffset - 1;
  if StartIndex < StringStartOffset then // DeN 09.01.2014
    Exit;
  // end DeN 16.09.2013

  for Result := StartIndex to Length(S) - StringStartInvOffset do // DeN 09.01.2014 - Add StringStartInvOffset
    if S[Result] = C then
      Exit;
  Result := StringStartOffset - 1;


end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringIndexOf(const S, SubS: string): Integer;
begin

  Result := System.Pos(SubS, S);



end;

// TODO: verify in Delphi Mobile for various string combinations
// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function StringIndexOf(const S: string; const SubS: string; StartIndex: Integer): Integer;
var
  SLen, SubSLen, {L, }I, J: Integer;
begin
  Result := StringStartOffset - 1; // DeN 09.01.2014
  SLen := Length(S) - StringStartInvOffset; // DeN 09.01.2014 - Add StringStartInvOffset
  SubSLen := Length(SubS);

  if (SubSLen = 0) or // DeN 03.09.2013
     (StringStartOffset > StartIndex) or
     (StartIndex > SLen) or
     (StartIndex + SubSLen - 1 > SLen) then
    Exit;

  // DeN 09.01.2014
  // L := (SLen - StartIndex + 1) - SubSLen + 1 + StringStartInvOffset;
  // DeN 07.10.2013
  // if L < StartIndex then
  //   L := StartIndex;
  // end DeN 07.10.2013
  // end DeN 09.01.2014

  for I := StartIndex to StartIndex + SubSLen do
    if S[I] = SubS[StringStartOffset] then
    begin
      Result := I;
      // DeN 09.01.2014
      // for J := 2 to SubSLen do - old
      for J := StringStartOffset + 1 to SubSLen - StringStartInvOffset do
        if S[I + J - 1] <> SubS[J] then
      // end DeN 09.01.2014
        begin
          Result := 0;
          Break;
        end;
      if Result <> 0 then
        Break;
    end;


end;

function StringIndexOfU(const S: UnicodeString; const C: WideChar): Integer;
begin

  Result := System.Pos(C, S);



end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringInsert(const S: UnicodeString; Index: Integer; C: WideChar): UnicodeString;
begin
  Result := S;
  Insert(C, Result, Index);


end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringInsert(const S: UnicodeString; Index: Integer; SubS: string): UnicodeString;
begin
  Result := S;
  Insert(SubS, Result, Index);


end;

// Done 7 / XE5(32) / XE5(64)
function StringInsert(const S: AnsiString; Index: Integer; C: AnsiChar): AnsiString;
begin
  Result := S;
  Insert(C, Result, Index);
end;

// Done 7 / XE5(32) / XE5(64)
function StringInsert(const S: AnsiString; Index: Integer; SubS: AnsiString): AnsiString;
begin
  Result := S;
  Insert(SubS, Result, Index);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringIsEmpty(const S: string): Boolean;
begin
  Result := (S = '');


end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringLastIndexOf(const S: UnicodeString; const C: WideChar): Integer;
begin
  for Result := Length(S) - StringStartInvOffset downto StringStartOffset do
    if S[Result] = C then
      Exit;
  Result := StringStartOffset - 1;


end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringLastIndexOf(const S: UnicodeString; const C: WideChar; StartIndex: Integer): Integer;
begin
  // DeN 09.01.2014
  Result := StringStartOffset - 1;
  if Length(S) = 0 then
    Exit;
  // end DeN 09.01.2014

  if StartIndex > Length(S) then
    StartIndex := Length(S);
  for Result := StartIndex downto StringStartOffset do
    if S[Result] = C then
      Exit;
  Result := StringStartOffset - 1;


end;

// Done 7 / XE5(32) / XE5(64)
function StringLastIndexOf(const S: AnsiString; const C: AnsiChar): Integer; overload;
var
  P, PS: PAnsiChar;
begin
  PS := PAnsiChar(S);
  P := AnsiStrRScan(PS, C);
  if P = nil then
    Result := AnsiStrStartOffset - 1
  else
    Result := P - PS + AnsiStrStartOffset;
end;

// Done 7 / XE5(32) / XE5(64)
function StringLastIndexOf(const S: AnsiString; const C: AnsiChar; StartIndex: Integer): Integer; overload;
begin
  if StartIndex > Length(S) then
    StartIndex := Length(S);
  for Result := StartIndex downto AnsiStrStartOffset do
    if S[Result] = C then
      Exit;
  Result := AnsiStrStartOffset - 1;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function WideStringRemove(const S: UnicodeString; StartIndex: Integer): UnicodeString;
begin
  Result := S;

  Delete(Result, StartIndex, MaxInt);



end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringRemove(const S: UnicodeString; StartIndex: Integer): UnicodeString;
begin
  result := WideStringRemove(S, StartIndex);
end;

// Done 7 / XE5
function WideStringRemove(const S: UnicodeString; StartIndex, Count: Integer): UnicodeString;
begin
  Result := S;

  Delete(Result, StartIndex, Count); // DeN 10.09.2013 replace MaxInt for Count



end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringRemove(const S: UnicodeString; StartIndex, Count: Integer): UnicodeString;
begin
  result := WideStringRemove(S, StartIndex, Count);
end;

// Done 7 / XE5(32) / XE5(64)
function StringRemove(const S: AnsiString; StartIndex: Integer): AnsiString;
begin
  Result := AnsiStringRemove(S, StartIndex);
end;

// Done 7 / XE5(32) / XE5(64)
function StringRemove(const S: AnsiString; StartIndex, Count: Integer): AnsiString;
begin
  Result := AnsiStringRemove(S, StartIndex, Count);
end;

// Done 7 / XE5(32) / XE5(64)
function AnsiStringRemove(const S: AnsiString; StartIndex: Integer): AnsiString;
begin
  Result := S;
  Delete(Result, StartIndex, MaxInt);
end;

// Done 7 / XE5(32) / XE5(64)
function AnsiStringRemove(const S: AnsiString; StartIndex, Count: Integer): AnsiString;
begin
  Result := S;
  Delete(Result, StartIndex, Count);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringToLower(const S: string): string;
begin
  Result := LowerCase(S);


end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringToLowerInvariant(const S: string): string;
begin
  Result := LowerCase(S);


end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringEndsWith(const S, SubS: string): Boolean;
begin
  Result := StringEndsWith(S, SubS, False);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringEndsWith(const S, SubS: string; IgnoreCase: Boolean): Boolean;
begin
  if (S = '') or (SubS = '') or (Length(S) < Length(SubS)) then
    Result := False
  else
  if IgnoreCase then
    Result := (StrLIComp(PChar(S) + Length(S) - Length(SubS), PChar(SubS), Length(SubS)) = 0)
  else
    Result := (StrLComp(PChar(S) + Length(S) - Length(SubS), PChar(SubS), Length(SubS)) = 0);


end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringStartsWith(const S, SubS: string): Boolean;
begin
  Result := StringStartsWith(S, SubS, False);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringStartsWith(const S, SubS: string; IgnoreCase: Boolean): Boolean;
begin
  if StringIsEmpty(S) or StringIsEmpty(SubS) then
  begin
    Result := False;
	exit;
  end;

  if Length(S) < Length(SubS) then 
    result := false
  else
  if IgnoreCase then
    Result := (StrLIComp(PChar(S), PChar(SubS), Length(SubS)) = 0)
  else
    Result := (StrLComp(PChar(S), PChar(SubS), Length(SubS)) = 0);


end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringSubstring(const S: string; StartIndex: Integer): string;
begin
    Result := System.Copy(S, StartIndex, MaxInt);


end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringSubstring(const S: string; StartIndex, Length: Integer): string;
begin
    Result := System.Copy(S, StartIndex, Length);


end;

{$ifdef SB_ANSI_VCL}
function StringSubstring(const S: UnicodeString; StartIndex: Integer): UnicodeString; overload;
begin
  Result := System.Copy(S, StartIndex, MaxInt);
end;

function StringSubstring(const S: UnicodeString; StartIndex, Length: Integer): UnicodeString; overload;
begin
  Result := System.Copy(S, StartIndex, Length);
end;
 {$endif}

// Done 7 / XE5(32) / XE5(64) / Android
function StringTrim(const S: string): string;
begin
  Result := Trim(S);


end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringTrimEnd(const S: string): string;
begin
  Result := TrimRight(S);


end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringTrimStart(const S: string): string;
begin
  Result := TrimLeft(S);


end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringToUpper(const S: string): string;
begin
  Result := AnsiUpperCase(S);


end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringToUpperInvariant(const S: string): string;
begin
  Result := UpperCase(S);


end;




{$ifndef SB_UNICODE_VCL}
// just to get rid of defines where this function will be used
// Done 7
function StrToDefEncoding(const AStr : string) : ByteArray;
begin
  SetLength(Result, Length(AStr));
  SBMove(AStr[StringStartOffset], Result[0], Length(Result));
end;

// Done 7
function DefEncodingToStr(const ASrc : ByteArray) : string;
begin
  SetLength(Result, Length(ASrc));
  SBMove(ASrc[0], Result[StringStartOffset], Length(Result));
end;

// Done 7
function StrToStdEncoding(const AStr : string; UseUTF8 : boolean) : ByteArray;
begin
  {$ifndef SB_NO_CHARSETS}
  if UseUTF8 then
    Result := StrToUTF8(AStr)
  else
   {$endif}
    Result := StrToDefEncoding(AStr);
end;

// Done 7
function StdEncodingToStr(const ASrc : ByteArray; UseUTF8 : boolean): string;
begin
  {$ifndef SB_NO_CHARSETS} 
  if UseUTF8 then
    Result := UTF8ToStr(ASrc)
  else
   {$endif}
    Result := DefEncodingToStr(ASrc);
end;
 {$else}
// Done XE5(32) / XE5(64) / Need - check in Android
function StrToDefEncoding(const AStr : string) : ByteArray;
{$ifdef SB_WINDOWS}
var Res : AnsiString;
  i : integer;
 {$endif}
begin
  {$ifdef SB_WINDOWS}
  WideCharLenToStrVar(PWideChar(@AStr[StringStartOffset]), Length(AStr), Res);
  i := Length(Res);
  SetLength(Result, i);
  if i > 0 then
    SBMove(Res[AnsiStrStartOffset], Result[0], i);
   {$else}
  Result := StrToUTF8(AStr);
   {$endif}
end;

// Done 7 / XE5(32) / XE5(64) / Android
function DefEncodingToStr(ASrc : ByteArray) : string;
{$ifdef SB_WINDOWS}
var S : RawByteString;
 {$endif}
begin
  if Length(ASrc) <= 0 then
  begin
    result := '';
    exit;
  end;
  {$ifdef SB_WINDOWS}
  SetLength(S, Length(ASrc));
  SBMove(ASrc[0], S[AnsiStrStartOffset], Length(ASrc));
  SetCodePage(S, DefaultSystemCodePage, False);
  Result := UnicodeString(S);
   {$else}
  Result := UTF8ToStr(ASrc);
   {$endif}
end;
 {$endif}

{$ifndef VCL50}
// Done 7 / XE5
function SameText(const S1, S2: string): Boolean;
begin
  result := (Length(S1) = Length(S2)) and (lowercase(S1) = lowercase(S2));
end;
 {$endif}


// Done 7 / XE5(32) / XE5(64) / Android
function ComposeURL(const Protocol, UserName, Password, Host: string; Port: Word;
  const Path, Anchor, Parameters: string): string;
begin
  Result := '';

  if Length(Protocol) > 0 then
    Result := {Result + }Protocol + '://';

  if (Length(UserName) > 0) or (Length(Password) > 0) then
    Result := Result + UserName + ':' + Password + '@';

  Result := Result + Host;
  if Port <> 0 then
    Result := Result + ':' + IntToStr(Port);

  if Length(Path) > 0 then
  begin
    if Path[StringStartOffset] <> '/' then
      Result := Result + '/';
    Result := Result + Path;
  end;

  if Length(Parameters) > 0 then
  begin
    if Parameters[StringStartOffset] <> '?' then
      Result := Result + '?';
    Result := Result + Parameters;
  end;

  if Length(Anchor) > 0 then
  begin
    if Anchor[StringStartOffset] <> '#' then
      Result := Result + '#';
    Result := Result + Anchor;
  end;
end;


// Done 7 / XE5(32) / XE5(64) / Need - check in Android
procedure ParseURL(URL: string; SingleNameIsPage: Boolean;
  var Protocol: string; var UserName: string; var Password: string;
  var Host: string; var Port: Word; var Path: string; var Anchor: string; var Parameters: string);
begin
  ParseURL(URL, SingleNameIsPage, Protocol, UserName, Password, Host, Port, Path, Anchor, Parameters, 'http');
end;

// TODO: Verify correctness of parsing in Delphi Mobile and regular Delphi
// Done 7 / XE5(32) / XE5(64) / Need - check in Android
procedure ParseURL(URL: string; SingleNameIsPage: Boolean;
  var Protocol: string; var UserName: string; var Password: string;
  var Host: string; var Port: Word; var Path: string; var Anchor: string; var Parameters: string;
  const DefaultProtocol: string);
var
  Index,
  SlashIndex,
  ColonIndex,
  SharpIndex,
  QIndex: integer;
  UserPass : string;
  ProtoFound : boolean;
  HostFound: Boolean;

begin
  Protocol := DefaultProtocol;
  UserName := EmptyString;
  Password := EmptyString;
  Host := EmptyString;
  Port := 0;
  Path := '/';
  Parameters := EmptyString;
  Anchor := EmptyString;

  if  (URL = EmptyString) then
    Exit;

  // input is correct fully-qualified address string (maybe w/out port),
  // like 'https://my.site.com/number1.html';
  // AI 20090130: if host name part is an IPv6 address, it must be enclosed
  //    into square brackets (http://user:pass@[::1]:3128/index.html).
  URL := StringTrim(URL);
  // Handle URLs like './index.html'
  // If we have '.' at the beggining of the path then remove it
  if (URL[StringStartOffset] = '.') and (URL[StringStartOffset + 1] = '/') then
    URL := StringSubstring(URL, StringStartOffset + 1);
  Index := StringIndexOf(URL, '://');
  ProtoFound := Index >= StringStartOffset;
  if ProtoFound then
    Protocol := StringSubstring(URL, StringStartOffset, Index - StringStartOffset)
  else
    Protocol := DefaultProtocol;

  if (URL[StringStartOffset] = '/') and (URL[StringStartOffset + 1] = '/') then
  begin
    URL := StringSubstring(URL, StringStartOffset + 3);
    Protocol := '';
  end;

  // check the username / password

  if Index >= StringStartOffset then
    URL := StringSubString(URL, Index + 3);

  SlashIndex := StringIndexOf(URL, '/');
  Index := StringIndexOf(URL, '@');

  if (Index >= StringStartOffset) and ((SlashIndex < StringStartOffset) or (Index < SlashIndex)) then
    UserPass := StringSubstring(URL, StringStartOffset, Index - StringStartOffset)
  else
  begin
    Index := -1;
    UserPass := '';
  end;

  inc(Index);
  // the rest of username/password parsing is done at the end of the method

  HostFound := False;

  URL := StringSubstring(URL, Index);
  if (URL <> '') and (URL[StringStartOffset] = '[') then
  begin
    Index := StringIndexOf(URL, ']');
    if Index >= StringStartOffset then
    begin
      Host := StringSubstring(URL, StringStartOffset + 1, Index - 1 - StringStartOffset);
      HostFound := True;
      if Index = Length(URL) - StringStartInvOffset then
        URL := ''
      else
        URL := StringSubstring(URL, Index + 1);
    end;
  end;
  SlashIndex := StringIndexOf(URL, '/');
  ColonIndex := StringIndexOf(URL, ':');
  QIndex := StringIndexOf(URL, '?');
  SharpIndex := StringIndexOf(URL, '#');

  // if # is before ? then there is no query in the url, just fragment
  if (QIndex >= StringStartOffset) and (SharpIndex >= StringStartOffset) and (SharpIndex < QIndex) then
    QIndex := StringStartOffset - 1;

  if QIndex >= StringStartOffset then
  begin
    if SharpIndex < StringStartOffset then  // check if there is no fragment present
    begin
      Parameters := StringSubString(URL, QIndex{ + 1});
      URL := StringSubString(URL, StringStartOffset, QIndex - StringStartOffset);
    end
    else
    begin
      Parameters := StringSubstring(URL, QIndex {+ 1}, (SharpIndex -1) - QIndex + 1);
      URL := StringRemove(URL, QIndex, SharpIndex - QIndex);
      SharpIndex := QIndex;
    end;
  end;

  // Strange thing when there's no end path, but parameters are present
  if (QIndex >= StringStartOffset) and ((SlashIndex < StringStartOffset) or (QIndex < SlashIndex)) then
  begin
    SlashIndex := StringIndexOf(URL, '/');
    ColonIndex := StringIndexOf(URL, ':');
  end;

  if SharpIndex >= StringStartOffset then
  begin
    Anchor := StringSubstring(URL, SharpIndex + 1);
    URL := StringSubstring(URL, StringStartOffset, SharpIndex - StringStartOffset);
  end;

  // Strange thing when there's no end path, but anchor is present
  if (SharpIndex >= StringStartOffset) and ((SlashIndex < StringStartOffset) or (SharpIndex < SlashIndex)) then
  begin
    SlashIndex := StringIndexOf(URL, '/');
    ColonIndex := StringIndexOf(URL, ':');
  end;

  if (SlashIndex < StringStartOffset) and (ColonIndex < StringStartOffset) and (not ProtoFound) then
  begin
    if SingleNameIsPage then
    begin
      if not HostFound then
        Host := '';
      Port := 0;
      Path := URL;
    end
    else
    begin
      if not HostFound then
        Host := URL;
      Port := 0;
      Path := '/';
    end;
  end
  else
  if (SlashIndex < StringStartOffset) and (ColonIndex >= StringStartOffset) then
  begin
    if not HostFound then
      Host := StringSubstring(URL, StringStartOffset, ColonIndex - StringStartOffset);
    Port := StrToInt(StringSubstring(URL, ColonIndex + 1, Length(URL) - ColonIndex - StringStartInvOffset));
  end
  else
  if (SlashIndex > ColonIndex) and (ColonIndex >= StringStartOffset) then
  begin
    if not HostFound then
      Host := StringSubstring(URL, StringStartOffset, ColonIndex - StringStartOffset);

    Port := StrToInt(StringSubstring(URL, ColonIndex + 1, SlashIndex - ColonIndex - StringStartOffset));
    Path := StringSubstring(URL, SlashIndex);
  end
  else
  if (SlashIndex < StringStartOffset) and (ColonIndex = SlashIndex) then
  begin
    Path := '';
    if not HostFound then
      Host := URL;
    Port := 0;
  end
  else
  begin
    if not HostFound then
      Host := StringSubstring(URL, StringStartOffset, SlashIndex - StringStartOffset);
    Path := StringSubstring(URL, SlashIndex);
  end;
  if Length(Path) = 0 then
    Path := '/';

  if Length(UserPass) > 0 then
  begin
    Index := StringIndexOf(UserPass, ':');
    if Index >= StringStartOffset then
    begin
      Username := StringSubstring(UserPass, StringStartOffset, Index - StringStartOffset);
      Password := StringSubstring(UserPass, Index + 1);
    end
    else
      Username := UserPass;

  end;
end;


// Inner - Not tested
function LastSeparatorPos(const Path : string) : integer;
var i : integer;
begin
    result := 0;

  for i := Length(Path) - StringStartInvOffset downto StringStartOffset do
  begin
    if (Path[i] = '\') or (Path[i] = '/') then
    begin
      result := i;
      exit;
    end;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SBExtractFilePath(const FileName : string) : string;
var Sep : integer;
begin
  Sep := LastSeparatorPos(Filename);

  if Sep = StringStartOffset then
  begin
    result := Filename[Sep];
  end
  else
  if Sep > StringStartOffset then
  begin
    result := StringSubstring(Filename, StringStartOffset, Sep - StringStartOffset);
  end
  else
    result := '';
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SBExtractFileName(const FileName : string) : string;
var Sep : integer;
begin
  Sep := LastSeparatorPos(Filename);

  if Sep >= StringStartOffset then
  begin
      result := System.Copy(Filename, Sep + 1, Length(Filename) - sep - StringStartInvOffset);
  end
  else
    result := FileName;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SBExtractFileExt(const FileName : string) : string;
var i : integer;
begin
  result := '';
  for i := Length(Filename) - StringStartInvOffset downto StringStartOffset do
  begin
    if (Filename[i] = '.') or (Filename[i] = ':') or (Filename[i] = '/') or (Filename[i] = '\') then
    begin
      if Filename[i] = '.' then
      begin
        result := StringSubstring(Filename, i, Length(Filename) - i + StringStartOffset);
      end;

      break;
    end;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SBExtractFileExt(const FileName: string; IncludeDot: Boolean): string;
var
  I: Integer;
  C: Char;
begin
  for I := Length(FileName) - StringStartInvOffset downto StringStartOffset do
  begin
    C := FileName[I];
    if C = '.' then
    begin
      if IncludeDot then
        Result := StringSubstring(FileName, I)
      else
        Result := StringSubstring(FileName, I + 1);
      Exit
    end
    else
    if (C = ':') or (C = '\') or (C = '/') then
      Break;
  end;
  Result := EmptyString;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ReplaceExt(const FileName : string; const NewExtension : string) : string;
var i : integer;
begin
  // DeN 10.10.2013
  // result := FileName + NewExtension; - old variant
  result := FileName;

  if (NewExtension = '') or
     (StringIndexOf(FileName, '.') = 0) or
     (StringIndexOf(FileName, '.') = Length(FileName) - StringStartInvOffset) then
    exit;
  // end DeN 10.10.2013

  for I := Length(FileName) - StringStartInvOffset downto StringStartOffset do
  begin
    if (Filename[i] = '.') or (Filename[i] = ':') or (Filename[i] = '/') or (Filename[i] = '\') then
    begin
      if Filename[i] = '.' then
      begin
        result := StringSubstring(Filename, StringStartOffset, i + StringStartInvOffset) + NewExtension;
      end;
      break;
    end;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function FilenameMatchesMask(const Name, Mask : string; CaseSensitive : boolean) : boolean;
var
  MaskPtr,
  NamePtr,
  LastStarPtr : integer;
  LastStarDec : integer;
  Dot : boolean;
begin
  Result := True;
  Dot := False;
  MaskPtr := StringStartOffset;
  NamePtr := StringStartOffset;
  LastStarPtr := StringStartOffset - 1;
  LastStarDec := 0;
  while (Result and (NamePtr < Length(Name) + StringStartOffset)) do
  begin
    if (Name[NamePtr] = '.') then
      Dot := True;
    if (MaskPtr < Length(Mask) + StringStartOffset) and (Mask[MaskPtr] = '?') then
    begin
      Inc(MaskPtr);
      Inc(NamePtr);
    end
    else
    if (MaskPtr < Length(Mask) + StringStartOffset) and (Mask[MaskPtr] = '*') then
    begin
      LastStarPtr := MaskPtr;
      LastStarDec := 0;
      Inc(MaskPtr);
      while (True) do
      begin
        if MaskPtr > Length(Mask) - StringStartInvOffset then
          break
        else
        if (Mask[MaskPtr] = '?') then
        begin
          Inc(MaskPtr);
          Inc(NamePtr);
          Inc(LastStarDec);
          if (NamePtr = Length(Name)  + StringStartOffset) then
            break;
        end
        else
        if (Mask[MaskPtr] <> '*') then
          break
        else
          Inc(MaskPtr);
      end;

      while
        (
         (NamePtr < Length(Name) + StringStartOffset)
         and
         (
          (MaskPtr > Length(Mask) - StringStartInvOffset) or
          (
          (CaseSensitive
           and
           (Mask[MaskPtr] <> Name[NamePtr])
          )
          or
          (
           (not CaseSensitive)
           and
           (Upcase(Mask[MaskPtr]) <> Upcase(Name[NamePtr]))
          )
          )
         )
        ) do
              Inc(NamePtr);
    end
    else
    begin
      Result := (MaskPtr < Length(Mask)  + StringStartOffset) and
      ((CaseSensitive and (Mask[MaskPtr] = Name[NamePtr])) or
        ((not CaseSensitive) and
        (Upcase(Mask[MaskPtr]) = Upcase(Name[NamePtr]))
        ));

      if (Result) then
      begin
        Inc(MaskPtr);
        Inc(NamePtr);
      end
      else
      begin
        Result := (LastStarPtr >= StringStartOffset);
        if Result then
        begin
          MaskPtr := LastStarPtr;
          Dec(NamePtr, LastStarDec);
        end;
      end;
    end;
  end;

  if (Result) then
  begin
    if MaskPtr < Length(Mask)  + StringStartOffset then
    begin
      while (MaskPtr < Length(Mask) + StringStartOffset) and (Mask[MaskPtr] = '*') do
        Inc(MaskPtr);

      // Workaround for masks *.*
      if ((MaskPtr = Length(Mask) - 1 -  StringStartInvOffset) and (Mask[MaskPtr] = '.') and (Mask[MaskPtr + 1] = '*')) then
        Inc(MaskPtr, 2);

      // Workaround for masks *.
      if ((MaskPtr = Length(Mask) - StringStartInvOffset) and (not Dot) and (Mask[MaskPtr] = '.')) then
        Inc(MaskPtr);
    end;
    Result := (MaskPtr > Length(Mask) - StringStartInvOffset);
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function DomainNameMatchesCertSN(DomainName, Match : string) : boolean;
var id, im : integer;
begin
  result := false;
  DomainName := StringToLower(StringTrim(DomainName));
  Match := StringToLower(StringTrim(Match));

  id :=  Length(DomainName) ;
  im :=  Length(Match) ;

  // if one of parameters is empty, or domain name contains a wildcard, we got nothing to do
  if (id = 0) or
     (im = 0) or
     (StringIndexOf(DomainName, '*') >= StringStartOffset) // DeN 08.01.2014
       then
    exit;

  if DomainName = Match then
  begin
    Result := true;
    exit;
  end;

  // if there's an asterisk in the allowed match, we need to perform wildcard matching
  if StringIndexOf(Match, '*') >= StringStartOffset then
  begin

    while true do
    begin
      if Match[im] = '*' then
      begin
        // here we need to match the asterisk to the part of the domain name
        while (id >= StringStartOffset) and (DomainName[id] <> '.') do
          dec(id);
        dec(im);
      end;
      if (id >= StringStartOffset) and (im >= StringStartOffset) then
      begin
        if DomainName[id] <> Match[im] then
          break;
        dec(id);
        dec(im);
      end;

      // if we got to the end of the Match or DomainName and there are still symbols in the other text line
      if ((im < StringStartOffset) and (id > im)) or
         ((id < StringStartOffset) and (im > id)) then
        break;

      if (im < StringStartOffset) and (id = im) then
      begin
        result := true;
        break;
      end;
    end;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function CountFoldersInPath(const Path : string) : integer;
var cp : integer;
begin
  result := 0;
  cp := StringStartOffset;
  
  while cp <= Length(Path) - StringStartInvOffset do
  begin
    if (Path[cp] = '/') and
       (cp > StringStartOffset) then // DeN 10.10.2013
      inc(result);
    inc(cp);
  end;
end;

// ansi<->unicode conversion routines

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function StrToUTF8(const AStr: string) : ByteArray;
var
  Conv : TElStringConverter;
begin
  Conv := GetStringConverter();
  if Assigned(Conv) then
    Result := Conv.StrToUtf8(AStr)
  else
    raise EElUnicodeError.Create(SUnicodeNotInitialized);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function UTF8ToStr(const ASrc: ByteArray) : string;
var
  Conv : TElStringConverter;
begin
  Conv := GetStringConverter();
  if Assigned(Conv) then
    Result := Conv.Utf8ToStr(ASrc)
  else
    raise EElUnicodeError.Create(SUnicodeNotInitialized);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function StrToWideStr(const AStr: string) : ByteArray;
var
  Conv : TElStringConverter;
begin
  Conv := GetStringConverter();
  if Assigned(Conv) then
    Result := Conv.StrToWideStr(AStr)
  else
    raise EElUnicodeError.Create(SUnicodeNotInitialized);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function WideStrToStr(const ASrc: ByteArray) : string;
var
  Conv : TElStringConverter;
begin
  Conv := GetStringConverter();
  if Assigned(Conv) then
    Result := Conv.WideStrToStr(ASrc)
  else
    raise EElUnicodeError.Create(SUnicodeNotInitialized);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function UnicodeChangeEndianness(const Data : ByteArray): ByteArray;
var
  Ptr : integer;
begin
  Ptr := 0;

  SetLength(Result, Length(Data));
  while Ptr <= Length(Data) + 0 - 1 do
  begin
    Result[Ptr] := Data[Ptr + 1];
    Result[Ptr + 1] := Data[Ptr];
    Inc(Ptr, 2);
  end;
end;

(*
function LittleEndianToBigEndianUnicode(const Data : ByteArray): ByteArray;
var
  Ptr : integer;
begin
  Ptr := 0;

  SetLength(Result, Length(Data));
  while Ptr <= Length(Data) + 0 - 1 do
  begin
    Result[Ptr] := Data[Ptr + 1];
    Result[Ptr + 1] := Data[Ptr];
    Inc(Ptr, 2);
  end;
end;

function BigEndianToLittleEndianUnicode(const Data : ByteArray): ByteArray;
var
  Ptr : integer;
begin
  Ptr := 0;

  SetLength(Result, Length(Data));
  while Ptr <= Length(Data) + 0 - 1 do
  begin
    Result[Ptr] := Data[Ptr + 1];
    Result[Ptr + 1] := Data[Ptr];
    Inc(Ptr, 2);
  end;
end;
*)

{$ifdef HAS_WCTOMB}
// Done 7 / XE5
function UTF8ToWideStr(const Buf: ByteArray): UnicodeString;
begin
  if Length(Buf) > 0 then
    Result := UTF8ToWideStr(Buf[0], Length(Buf))
  else
    Result := '';
end;

// Done 7 / XE5
function WideStrToUTF8(const AStr: UnicodeString) : ByteArray;
begin
  Result := WideStrToUTF8(AStr[StringStartOffset], Length(AStr));
end;

// Done 7, Need check in XE5
function WideStrToUTF8(const ASrc; Size: integer) : ByteArray;
var
  Sz: integer;
begin
  Sz := WideCharToMultiByte(CP_UTF8, 0, @ASrc, Size, nil, 0, nil, nil);
  SetLength(Result, Sz);
  Sz := WideCharToMultiByte(CP_UTF8, 0, @ASrc, Size, @Result[0], Length(Result),
    nil, nil);
  SetLength(Result, Sz);
end;

// Done 7 / XE5
function UTF8ToWideStr(const Buf; Size: Integer): UnicodeString;
var
  Sz: integer;
begin
  if Size <= 0 then
  begin
    Result := '';
    Exit;
  end;

  SetLength(Result, Size);
  Sz := MultiByteToWideChar(CP_UTF8, 0, @Buf, Size, @Result[StringStartOffset], Size);
  SetLength(Result, Sz);
end;
 {$else}
// Done 7 / XE5(32) / XE5(64) / Android
function UTF8ToWideStr(const Buf: ByteArray): UnicodeString;
begin
  if Length(Buf) > 0 then
    Result := UTF8ToWideStr(Buf[0], Length(Buf))
  else
    Result := '';
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function UTF8ToWideStr(const Buf; Size: Integer): UnicodeString;
var
  TS: ByteArray;
begin
  if Size <= 0 then
  begin
    Result := '';
    Exit;
  end;

  SetLength(TS, Size);
  SBMove(Buf, TS[0], Size);
  ConvertUTF8toUTF16(TS, Result, lenientConversion, false);
  ReleaseArray(TS);
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function WideStrToUTF8(const AStr: UnicodeString) : ByteArray;
var S : ByteArray;
begin
  SetLength(Result, 0);
  s := ConvertToUTF8String(AStr);
  if (Length(S) > 0) then
  begin
    SetLength(Result, Length(S));
    SBMove(S[0], Result[0], Length(S));
    ReleaseArray(S);
  end;
end;

// Done 7, Need - check in XE5
function WideStrToUTF8(const ASrc; Size: integer) : ByteArray;
var S : ByteArray;
    WS:  WideString ;
begin
  SetLength(Result, 0);
  SetLength(WS, Size shr 1);
  SBMove(ASrc, WS[StringStartOffset], Size);
  S := ConvertToUTF8String(WS);
  if (Length(S) > 0) then
  begin
    SetLength(Result, Length(S));
    SBMove(S[0], Result[0], Length(S));
    ReleaseArray(S);
  end;
end;
 {$endif}

// Done 7 / XE5(32) / XE5(64) / Android
function StrMixToInt64(const S : string) : Int64;
var i : integer;
    C : char;
begin
  result := 0;
  for i := 0 to Length(S) - 1 do
  begin
    C := S[StringStartOffset + i];
    if (ord(C) >= Byte('0')) and (ord(C) <= Byte('9')) then
      result := Result * 10 + (ord(C) - Byte('0'));
  end;
end;

// Todo
procedure SetGlobalConverter(Converter : TElStringConverter);
begin
  {$ifndef SB_MSSQL}
  if Assigned(G_StringConverter) then
    FreeAndNil(G_StringConverter);
  G_StringConverter := Converter;
   {$else}
  raise EElUnicodeError.Create('Cannot change global converter for MSSQL edition');
   {$endif}
end;

{$ifndef SB_NO_CHARSETS}
// Todo
procedure SetDefaultCharset(const Charset : string);
var
  Conv : TElStringConverter;
begin
  Conv := GetStringConverter();
  if Assigned(Conv) then
    Conv.DefCharset := Charset
  else
    raise EElUnicodeError.Create(SUnicodeNotInitialized);
end;
 {$endif}

constructor TElStringConverter.Create;
begin
  inherited;

  FDefCharset := '';
end;

procedure TElStringConverter.SetDefCharset(const Value : string);
begin
  raise EElUnicodeError.Create(SUnicodeNotInitialized);
end;

function TElStringConverter.StrToUtf8(const Source : string) : ByteArray;
begin
  SetLength(Result, 0);
  raise EElUnicodeError.Create(SUnicodeNotInitialized);
end;

function TElStringConverter.Utf8ToStr(const Source : ByteArray) : string;
begin
  Result := '';
  raise EElUnicodeError.Create(SUnicodeNotInitialized);
end;

function TElStringConverter.StrToWideStr(const Source : string) : ByteArray;
begin
  SetLength(Result, 0);
  raise EElUnicodeError.Create(SUnicodeNotInitialized);
end;

function TElStringConverter.WideStrToStr(const Source : ByteArray) : string;
begin
  Result := '';
  raise EElUnicodeError.Create(SUnicodeNotInitialized);
end;

{$ifdef SB_WINDOWS_OR_NET_OR_JAVA}

// internal converter for .NET/Windows
constructor TElPlatformStringConverter.Create;
begin
  inherited;
end;

procedure TElPlatformStringConverter.SetDefCharset(const Value : string);
begin
  FDefCharset := Value;
end;

function TElPlatformStringConverter.StrToUtf8(const Source : string) : ByteArray;
{$ifndef SB_UNICODE_VCL}
var
  i, len : integer;
  TmpBuf : ByteArray;
 {$endif}
begin
  {$ifdef SB_UNICODE_VCL}
  Result := StrToUTF8(Source);
   {$else}
  SetLength(Result, 0);
  i := MultiByteToWideChar(CP_ACP, 0, @Source[StringStartOffset], Length(Source), nil, 0);
  if i = 0 then Exit;
  SetLength(TmpBuf, i * SizeOf(WCHAR));
  Len := MultiByteToWideChar(CP_ACP, 0, @Source[StringStartOffset], Length(Source), @TmpBuf[0], i);
  if Len = 0 then Exit;

  i := WideCharToMultiByte(CP_UTF8, 0, @TmpBuf[0], Len, nil, 0, nil, nil);
  if i = 0 then Exit;

  SetLength(Result, i);
  i := WideCharToMultiByte(CP_UTF8, 0, @TmpBuf[0], Len, @Result[0], i, nil, nil);
  SetLength(Result, i);
   {$endif}
end;

function TElPlatformStringConverter.Utf8ToStr(const Source : ByteArray) : string;
{$ifndef SB_UNICODE_VCL}
var
  i, len : integer;
  TmpBuf : ByteArray;
 {$endif}
begin
  {$ifdef SB_UNICODE_VCL}
  Result := UTF8ToStr(Source);
   {$else}
  SetLength(Result, 0);
  i := MultiByteToWideChar(CP_UTF8, 0, @Source[0], Length(Source), nil, 0);
  if i = 0 then Exit;
  SetLength(TmpBuf, i * SizeOf(WCHAR));
  Len := MultiByteToWideChar(CP_UTF8, 0, @Source[0], Length(Source), @TmpBuf[0], i);
  if Len = 0 then Exit;

  i := WideCharToMultiByte(CP_ACP, 0, @TmpBuf[0], Len, nil, 0, nil, nil);
  if i = 0 then Exit;

  SetLength(Result, i);
  i := WideCharToMultiByte(CP_ACP, 0, @TmpBuf[0], Len, @Result[StringStartOffset], i, nil, nil);
  SetLength(Result, i);
   {$endif}
end;

function TElPlatformStringConverter.StrToWideStr(const Source : string) : ByteArray;
{$ifndef SB_UNICODE_VCL}
var
  i : integer;
 {$endif}
begin
  {$ifdef SB_UNICODE_VCL}
  SetLength(Result, Length(Source) * SizeOf(Char));
  if Length(Source) > 0 then
    SBMove(Source[StringStartOffset], Result[0], Length(Result));
   {$else}
  SetLength(Result, 0);
  i := MultiByteToWideChar(CP_ACP, 0, @Source[StringStartOffset], Length(Source), nil, 0);
  if i = 0 then Exit;
  SetLength(Result, i * SizeOf(WCHAR));
  i := MultiByteToWideChar(CP_ACP, 0, @Source[StringStartOffset], Length(Source), @Result[0], i);
  SetLength(Result, i * SizeOf(WCHAR));
   {$endif}
end;

function TElPlatformStringConverter.WideStrToStr(const Source : ByteArray) : string;
{$ifndef SB_UNICODE_VCL}
var
  i : integer;
 {$endif}
begin
  {$ifdef SB_UNICODE_VCL}
  if Length(Source) and 1 <> 0 then
  begin
    Result := '';
    Exit;
  end;

  SetLength(Result, Length(Source) shr 1);
  if Length(Source) > 0 then
    SBMove(Source[0], Result[StringStartOffset], Length(Result) * SizeOf(Char));
   {$else}
  SetLength(Result, 0);

  i := WideCharToMultiByte(CP_ACP, 0, @Source[0], Length(Source) shr 1, nil, 0, nil, nil);
  if i = 0 then Exit;

  SetLength(Result, i);

  i := WideCharToMultiByte(CP_ACP, 0, @Source[0], Length(Source) shr 1, @Result[StringStartOffset], i, nil, nil);
  SetLength(Result, i);
   {$endif}
end;

function TElPlatformStringConverter.EncodeStr(const Source : string; const Encoding : string) : ByteArray;
var
  CPID : integer;
begin
  if Encoding = '' then
    CPID := CP_ACP
  else
  begin
    CPID := GetWindowsCodePageIdentifier(Encoding);
    if CPID = -1 then // charset name not found
      CPID := CP_ACP;
  end;
  Result := EncodeStr(Source, CPID);
end;

{$ifndef SB_NO_NET_ENCODING_CODES}
function TElPlatformStringConverter.EncodeStr(const Source : string; Encoding : integer) : ByteArray;
var
  CPID, DefCPID : integer;
  Buf : ByteArray;
  i, len : integer;
begin
  if Length(Source) = 0 then
  begin
    Result := EmptyArray;
    Exit;
  end;
  CPID := Encoding;
  // converting string to utf16
  {$ifdef SB_UNICODE_VCL}
  SetLength(Buf, Length(Source) * SizeOf(Char));
  SBMove(Source[StringStartOffset], Buf[0], Length(Buf));
  len := Length(Source);
   {$else}

  if FDefCharset = '' then
    DefCPID := CP_ACP
  else
  begin
    DefCPID := GetWindowsCodePageIdentifier(FDefCharset);
    if DefCPID = -1 then
      DefCPID := CP_ACP;
  end;

  SetLength(Buf, 0);
  i := MultiByteToWideChar(DefCPID, 0, @Source[StringStartOffset], Length(Source), nil, 0);
  if i = 0 then Exit;
  SetLength(Buf, i * SizeOf(WCHAR));
  i := MultiByteToWideChar(DefCPID, 0, @Source[StringStartOffset], Length(Source), @Buf[0], i);
  SetLength(Buf, i * SizeOf(WCHAR));
  len := i;
   {$endif SB_UNICODE_VCL}

  // encoding utf16 string to the supplied encoding
  i := WideCharToMultiByte(CPID, 0, @Buf[0], len, nil, 0, nil, nil);
  if i = 0 then Exit;
  SetLength(Result, i);
  i := WideCharToMultiByte(CPID, 0, @Buf[0], Len, @Result[0], i, nil, nil);
  SetLength(Result, i);
end;
 {$endif}

function TElPlatformStringConverter.DecodeStr(const Source : ByteArray; const Encoding : string) : string;
var
  CPID : integer;
begin
  if Encoding = '' then
    CPID := CP_ACP
  else
  begin
    CPID := GetWindowsCodePageIdentifier(Encoding);
    if CPID = -1 then // charset name not found
      CPID := CP_ACP;
  end;
  Result := DecodeStr(Source, CPID);
end;

{$ifndef SB_NO_NET_ENCODING_CODES}
function TElPlatformStringConverter.DecodeStr(const Source : ByteArray; Encoding : integer) : string;
var
  CPID, DefCPID : integer;
  Buf : ByteArray;
  i, len : integer;
begin
  if Length(Source) = 0 then
  begin
    Result := '';
    Exit;
  end;
  CPID := Encoding;
  if FDefCharset = '' then
    DefCPID := CP_ACP
  else
  begin
    DefCPID := GetWindowsCodePageIdentifier(FDefCharset);
    if DefCPID = -1 then // charset name not found
      DefCPID := CP_ACP;
  end;
  // converting passed buffer to utf16
  SetLength(Buf, 0);
  i := MultiByteToWideChar(CPID, 0, @Source[0], Length(Source), nil, 0);
  if i = 0 then Exit;
  SetLength(Buf, i * SizeOf(WCHAR));
  i := MultiByteToWideChar(CPID, 0, @Source[0], Length(Source), @Buf[0], i);
  SetLength(Buf, i * SizeOf(WCHAR));
  len := i;
  // converting utf16 buffer to Delphi string
  {$ifdef SB_UNICODE_VCL}
  SetLength(Result, len);
  SBMove(Buf[0], Result[StringStartOffset], Length(Buf));
   {$else}
  i := WideCharToMultiByte(DefCPID, 0, @Buf[0], len, nil, 0, nil, nil);
  if i = 0 then Exit;
  SetLength(Result, i);
  i := WideCharToMultiByte(DefCPID, 0, @Buf[0], Len, @Result[StringStartOffset], i, nil, nil);
  SetLength(Result, i);
   {$endif SB_UNICODE_VCL}
end;
 {$endif}
                 
function TElPlatformStringConverter.GetWindowsCodePageIdentifier(const Name : string): integer;
var
  NormName : string;
begin
  // code page list taken from
  // http://msdn.microsoft.com/en-us/library/windows/desktop/dd317756%28v=vs.85%29.aspx
  NormName := LowerCase(Name);
  Result := StrToIntDef(NormName, -1);
  if Result <> -1 then
    Exit;
  if NormName = 'ibm037' then
    Result := 37
  else if NormName = 'ibm437' then
    Result := 437
  else if NormName = 'ibm500' then
    Result := 500
  else if NormName = 'asmo-708' then
    Result := 708
  else if NormName = 'dos-720' then
    Result := 720
  else if NormName = 'ibm737' then
    Result := 737
  else if NormName = 'ibm775' then
    Result := 775
  else if NormName = 'ibm850' then
    Result := 850
  else if NormName = 'ibm852' then
    Result := 852
  else if NormName = 'ibm855' then
    Result := 855
  else if NormName = 'ibm857' then
    Result := 857
  else if NormName = 'ibm00858' then
    Result := 858
  else if NormName = 'ibm860' then
    Result := 860
  else if NormName = 'ibm861' then
    Result := 861
  else if NormName = 'dos-862' then
    Result := 862
  else if NormName = 'ibm863' then
    Result := 863
  else if NormName = 'ibm864' then
    Result := 864
  else if NormName = 'ibm865' then
    Result := 865
  else if NormName = 'cp866' then
    Result := 866
  else if NormName = 'ibm869' then
    Result := 869
  else if NormName = 'ibm870' then
    Result := 870
  else if NormName = 'windows-874' then
    Result := 874
  else if NormName = 'cp875' then
    Result := 875
  else if NormName = 'shift_jis' then
    Result := 932
  else if NormName = 'gb2312' then
    Result := 936
  else if NormName = 'ks_c_5601-1987' then
    Result := 949
  else if NormName = 'big5' then
    Result := 950
  else if NormName = 'ibm1026' then
    Result := 1026
  else if NormName = 'ibm01047' then
    Result := 1047
  else if NormName = 'ibm01140' then
    Result := 1140
  else if NormName = 'ibm01141' then
    Result := 1141
  else if NormName = 'ibm01142' then
    Result := 1142
  else if NormName = 'ibm01143' then
    Result := 1143
  else if NormName = 'ibm01144' then
    Result := 1144
  else if NormName = 'ibm01145' then
    Result := 1145
  else if NormName = 'ibm01146' then
    Result := 1146
  else if NormName = 'ibm01147' then
    Result := 1147
  else if NormName = 'ibm01148' then
    Result := 1148
  else if NormName = 'ibm01149' then
    Result := 1149
  else if NormName = 'utf-16' then
    Result := 1200
  else if NormName = 'unicodefffe' then
    Result := 1201
  else if NormName = 'windows-1250' then
    Result := 1250
  else if NormName = 'windows-1251' then
    Result := 1251
  else if NormName = 'windows-1252' then
    Result := 1252
  else if NormName = 'windows-1253' then
    Result := 1253
  else if NormName = 'windows-1254' then
    Result := 1254
  else if NormName = 'windows-1255' then
    Result := 1255
  else if NormName = 'windows-1256' then
    Result := 1256
  else if NormName = 'windows-1257' then
    Result := 1257
  else if NormName = 'windows-1258' then
    Result := 1258
  else if NormName = 'johab' then
    Result := 1361
  else if NormName = 'macintosh' then
    Result := 10000
  else if NormName = 'x-mac-japanese' then
    Result := 10001
  else if NormName = 'x-mac-chinesetrad' then
    Result := 10002
  else if NormName = 'x-mac-korean' then
    Result := 10003
  else if NormName = 'x-mac-arabic' then
    Result := 10004
  else if NormName = 'x-mac-hebrew' then
    Result := 10005
  else if NormName = 'x-mac-greek' then
    Result := 10006
  else if NormName = 'x-mac-cyrillic' then
    Result := 10007
  else if NormName = 'x-mac-chinesesimp' then
    Result := 10008
  else if NormName = 'x-mac-romanian' then
    Result := 10010
  else if NormName = 'x-mac-ukrainian' then
    Result := 10017
  else if NormName = 'x-mac-thai' then
    Result := 10021
  else if NormName = 'x-mac-ce' then
    Result := 10029
  else if NormName = 'x-mac-icelandic' then
    Result := 10079
  else if NormName = 'x-mac-turkish' then
    Result := 10081
  else if NormName = 'x-mac-croatian' then
    Result := 10082
  else if NormName = 'utf-32' then
    Result := 12000
  else if NormName = 'utf-32be' then
    Result := 12001
  else if NormName = 'x-chinese_cns' then
    Result := 20000
  else if NormName = 'x-cp20001' then
    Result := 20001
  else if NormName = 'x_chinese-eten' then
    Result := 20002
  else if NormName = 'x-cp20003' then
    Result := 20003
  else if NormName = 'x-cp20004' then
    Result := 20004
  else if NormName = 'x-cp20005' then
    Result := 20005
  else if NormName = 'x-ia5' then
    Result := 20105
  else if NormName = 'x-ia5-german' then
    Result := 20106
  else if NormName = 'x-ia5-swedish' then
    Result := 20107
  else if NormName = 'x-ia5-norwegian' then
    Result := 20108
  else if NormName = 'us-ascii' then
    Result := 20127
  else if NormName = 'x-cp20261' then
    Result := 20261
  else if NormName = 'x-cp20269' then
    Result := 20269
  else if NormName = 'ibm273' then
    Result := 20273
  else if NormName = 'ibm277' then
    Result := 20277
  else if NormName = 'ibm278' then
    Result := 20278
  else if NormName = 'ibm280' then
    Result := 20280
  else if NormName = 'ibm284' then
    Result := 20284
  else if NormName = 'ibm285' then
    Result := 20285
  else if NormName = 'ibm290' then
    Result := 20290
  else if NormName = 'ibm297' then
    Result := 20297
  else if NormName = 'ibm420' then
    Result := 20420
  else if NormName = 'ibm423' then
    Result := 20423
  else if NormName = 'ibm424' then
    Result := 20424
  else if NormName = 'x-ebcdic-koreanextended' then
    Result := 20833
  else if NormName = 'ibm-thai' then
    Result := 20838
  else if NormName = 'koi8-r' then
    Result := 20866
  else if NormName = 'ibm871' then
    Result := 20871
  else if NormName = 'ibm880' then
    Result := 20880
  else if NormName = 'ibm905' then
    Result := 20905
  else if NormName = 'ibm00924' then
    Result := 20924
  else if NormName = 'euc-jp' then
    Result := 20932
  else if NormName = 'x-cp20936' then
    Result := 20936
  else if NormName = 'x-cp20949' then
    Result := 20949
  else if NormName = 'cp1025' then
    Result := 21025
  else if NormName = 'koi8-u' then
    Result := 21866
  else if NormName = 'iso-8859-1' then
    Result := 28591
  else if NormName = 'iso-8859-2' then
    Result := 28592
  else if NormName = 'iso-8859-3' then
    Result := 28593
  else if NormName = 'iso-8859-4' then
    Result := 28594
  else if NormName = 'iso-8859-5' then
    Result := 28595
  else if NormName = 'iso-8859-6' then
    Result := 28596
  else if NormName = 'iso-8859-7' then
    Result := 28597
  else if NormName = 'iso-8859-8' then
    Result := 28598
  else if NormName = 'iso-8859-9' then
    Result := 28599
  else if NormName = 'iso-8859-13' then
    Result := 28603
  else if NormName = 'iso-8859-15' then
    Result := 28605
  else if NormName = 'x-europa' then
    Result := 29001
  else if NormName = 'iso-8859-8-i' then
    Result := 38598
  else if NormName = 'iso-2022-jp' then
    Result := 50220
  else if NormName = 'csiso2022jp' then
    Result := 50221
  else if NormName = 'iso-2022-jp' then
    Result := 50222
  else if NormName = 'iso-2022-kr' then
    Result := 50225
  else if NormName = 'x-cp50227' then
    Result := 50227
  else if NormName = 'euc-jp' then
    Result := 51932
  else if NormName = 'euc-cn' then
    Result := 51936
  else if NormName = 'euc-kr' then
    Result := 51949
  else if NormName = 'hz-gb-2312' then
    Result := 52936
  else if NormName = 'gb18030' then
    Result := 54936
  else if NormName = 'x-iscii-de' then
    Result := 57002
  else if NormName = 'x-iscii-be' then
    Result := 57003
  else if NormName = 'x-iscii-ta' then
    Result := 57004
  else if NormName = 'x-iscii-te' then
    Result := 57005
  else if NormName = 'x-iscii-as' then
    Result := 57006
  else if NormName = 'x-iscii-or' then
    Result := 57007
  else if NormName = 'x-iscii-ka' then
    Result := 57008
  else if NormName = 'x-iscii-ma' then
    Result := 57009
  else if NormName = 'x-iscii-gu' then
    Result := 57010
  else if NormName = 'x-iscii-pa' then
    Result := 57011
  else if NormName = 'utf-7' then
    Result := 65000
  else if NormName = 'utf-8' then
    Result := 65001
  else
    Result := -1;
end;
 {$endif}

// Need check
function ConvertUTF16toUTF8(const source: UnicodeString;
                        var target: ByteArray;
                        flags: ConversionFlags;
                        BOM: boolean): ConversionResult;
const
  byteMask: UTF32 = $0BF;
  byteMark: UTF32 = $80;
var
  ch, ch2: UTF32;
  bytesToWrite: word;
  i, k, sourcelen: integer;
begin
  Result := conversionOK;
  k := 0;
  SetLength(target, Length(source));
  i := StringStartOffset;
  sourcelen := length(source) + StringStartOffset;
  while i < sourcelen do
  begin
    // bytesToWrite := 0;
    ch := UTF32(source[i]);
    inc(i);
    { If we have a surrogate pair, convert to UTF32 first }
    if ((ch >= UNI_SUR_HIGH_START) and (ch <= UNI_SUR_HIGH_END) and (i < sourcelen)) then
    begin
      ch2 := UTF32(source[i]);
      if ((ch2 >= UNI_SUR_LOW_START) and (ch2 <= UNI_SUR_LOW_END)) then
      begin
        ch := ((ch - UNI_SUR_HIGH_START) shl halfShift) + (ch2 - UNI_SUR_LOW_START) + halfBase;
        inc(i);
      end
      else
        if (flags = strictConversion) then  { it's an unpaired high surrogate }
        begin
          Result := sourceIllegal;
          break;
        end;
    end
    else
      if ((flags = strictConversion) and ((ch >= UNI_SUR_LOW_START) and (ch <= UNI_SUR_LOW_END))) then
      begin
        Result := sourceIllegal;
        break;
      end;
    { Figure out how many bytes the Result will require }
    if ch < UTF32($80) then
      bytesToWrite := 1
    else
    if ch < UTF32($800) then
      bytesToWrite := 2
    else
    if ch < UTF32($10000) then
      bytesToWrite := 3
    else
    if ch < UTF32($200000) then
      bytesToWrite := 4
    else
    if ch < UTF32($300000) then
      bytesToWrite := 5
    else
    begin
      bytesToWrite := 2;
      ch := UNI_REPLACEMENT_CHAR;
    end;

    { note: everything falls through. }

    if k + bytesToWrite > Length(target) then
      SetLength(target, Length(target) * 2 + bytesToWrite);

    if bytesToWrite = 4 then
    begin
      target[k + 3] := Byte((ch or byteMark) and byteMask);
      ch := ch shr 6
    end;
    if bytesToWrite >= 3 then
    begin
      target[k + 2] := Byte((ch or byteMark) and byteMask);
      ch := ch shr 6;
    end;
    if bytesToWrite >= 2 then
    begin
      target[k + 1] := Byte((ch or byteMark) and byteMask);
      ch := ch shr 6
    end;
    if bytesToWrite >= 1 then
    begin
      target[k] := Byte(ch or firstByteMark[bytesToWrite]);
    end;

    Inc(k, bytesToWrite);

    (*
    {$ifndef SB_DELPHI_MOBILE}
    SetLength(ts, 0);
    {$else}
    SetLength(ts, bytesToWrite);
    {$endif}
    if bytesToWrite = 4 then
    begin
      {$ifndef SB_DELPHI_MOBILE}
      ts := AnsiChar((ch or byteMark) and byteMask);
      {$else}
      SetLength(ts, 1);
      TS[0] := (ch or byteMark) and byteMask;
      {$endif}
      ch := ch shr 6
    end;
    if bytesToWrite >= 3 then
    begin
      {$ifndef SB_DELPHI_MOBILE}
      ts := AnsiChar((ch or byteMark) and byteMask) + ts;
      {$else}

      {$endif}
      ch := ch shr 6
    end;
    if bytesToWrite >= 2 then
    begin
      ts := AnsiChar((ch or byteMark) and byteMask) + ts;
      ch := ch shr 6
    end;
    if bytesToWrite >= 1 then
    begin
      ts := AnsiChar(ch or firstByteMark[bytesToWrite]) + ts;
    end;
    //target := target + ts;
    *)
  end;
  
  if k < Length(target) then
    SetLength(target, k);

  if BOM and (SBPos(UTF8BOMByteArray, target) <> 0) then
    target := SBConcatArrays(UTF8BOMByteArray, target);
end;

{
Tests of ConvertUTF8toUTF16

var
  Src: String;
  Dst: WideString;
begin
  Src := #$1#0;
  ConvertUTF8toUTF16(Src, Dst, strictConversion, False);
  assert(Dst[1] = #$1);
  Src := #$7F#0;
  ConvertUTF8toUTF16(Src, Dst, strictConversion, False);
  assert(Dst[1] = #$7F);
  Src := #$C2#$80#0;
  ConvertUTF8toUTF16(Src, Dst, strictConversion, False);
  assert(Dst[1] = #$80);
  Src := #$DF#$BF#0;
  ConvertUTF8toUTF16(Src, Dst, strictConversion, False);
  assert(Dst[1] = #$7FF);
  Src := #$E0#$A0#$80#0;
  ConvertUTF8toUTF16(Src, Dst, strictConversion, False);
  assert(Dst[1] = #$800);
  Src := #$EF#$BF#$BF#0;
  ConvertUTF8toUTF16(Src, Dst, strictConversion, False);
  assert(Dst[1] = #$FFFF);

  Src := #$F0#$90#$80#$80#0;
  ConvertUTF8toUTF16(Src, Dst, strictConversion, False);
  assert($10000 = $10000 + ((LongWord(Dst[1]) - $D800) shl 10) or (LongWord(Dst[2]) - $DC00));
  Src := #$F7#$BF#$BF#$BF#0;
  ConvertUTF8toUTF16(Src, Dst, strictConversion, False);
  assert($1FFFFF = $10000 + ((LongWord(Dst[1]) - $D800) shl 10) or (LongWord(Dst[2]) - $DC00));
end;
}

// Done 7 / XE5(32) / XE5(64) / Android
function ConvertUTF8toUTF16(const source: ByteArray;
                             var target: UnicodeString;
                             flags: ConversionFlags;
                             BOM: boolean): ConversionResult;
var
  ch: UTF32;
  extraBytesToRead: word;
  i, sourcelen: integer;
begin
  Result := conversionOK;
  i := 0;
  sourcelen := length(source);
  target := '';

  while i < sourcelen do
  begin
    ch := 0;
    extraBytesToRead := trailingBytesForUTF8[UTF8(source[i])];
    if (i + extraBytesToRead) >= sourcelen then
    begin
      Result := sourceExhausted;
      break;
    end;
    { Do this check whether lenient or strict }
    if (not isLegalUTF8(Copy(source, i, extraBytesToRead + 1), extraBytesToRead + 1)) then
    begin
      Result := sourceIllegal;
      break;
    end;

    { The cases all fall through.}
    if extraBytesToRead > 0 then
    begin
      ch := UTF32(source[i]) and not (($FF shl (7 - extraBytesToRead)) and $FF);
      inc(i);
      while extraBytesToRead > 0 do
      begin
        ch := (ch shl 6) or (UTF32(source[i]) and $3F);
        dec(extraBytesToRead);
        inc(i);
      end;
    end
    else
    begin
      ch := UTF32(source[i]);
      inc(i);
    end;
    {
    if extraBytesToRead = 3 then
    begin
      ch := ch + UTF32(source[i]);
      inc(i);
      ch := ch shl 6;
    end;
    if (extraBytesToRead >= 2) and (extraBytesToRead < 4) then
    begin
      ch := ch + UTF32(source[i]);
      inc(i);
      ch := ch shl 6;
    end;
    if (extraBytesToRead >= 1) and (extraBytesToRead < 4) then
    begin
      ch := ch + UTF32(source[i]);
      inc(i);
      ch := ch shl 6;
    end;
    if (* (extraBytesToRead >= 0) and *) (extraBytesToRead < 4) then
    begin
      ch := ch + UTF32(source[i]);
      inc(i);
    end;
    ch := ch - offsetsFromUTF8[extraBytesToRead];
    }
    if (ch <= UNI_MAX_BMP) then         { Target is a character <= 0xFFFF }
    begin
      if ((flags = strictConversion) and ((ch >= UNI_SUR_HIGH_START) and (ch <= UNI_SUR_LOW_END))) then
      begin
        Result := sourceIllegal;
        break;
      end else
        target := target + widechar(ch);  { normal case }
    end
    else
      if (ch > UNI_MAX_UTF16) then
      begin
        if (flags = strictConversion) then
        begin
          Result := sourceIllegal;
          i := i - extraBytesToRead;
        end else
          target := target + widechar(UNI_REPLACEMENT_CHAR);
      end
      else
      { target is a character in range 0xFFFF - 0x10FFFF. }
      begin
        ch := ch - halfBase;
        target := target + widechar((ch shr halfShift) + UNI_SUR_HIGH_START) +
                           widechar((ch and halfMask) + UNI_SUR_LOW_START);
      end;
  end;
  if BOM and (ord(target[StringStartOffset])<>$FEFF) then target := widechar($FEFF) + target;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function isLegalUTF8(const source: ByteArray; sourcelen: cardinal): boolean;
var
  length: cardinal;
begin
  // DeN 26.11.2013
  if source = nil then
  begin
    Result := false;
    Exit;
  end;
  // end DeN 26.11.2013
  	
  length := trailingBytesForUTF8[byte(source[0])] + 1;
    
  if length > sourcelen then
    Result := false
  else
  if length = sourcelen then
    Result := true
  else
    Result := isLegalUTF8(source, length);
end;

// Inner - Not tested
function ConvertUTF32toUTF16(const Source; Size: Integer;
  var Target: UnicodeString; Flags: ConversionFlags; BOM: boolean): ConversionResult;
var
  S: array[0..0] of Byte absolute Source;
  ch: UTF32;
  i, k: integer;
begin
  // Size in bytes
  if Size mod 4 <> 0 then
  begin
    Result := sourceExhausted;
    Exit;
  end;

  Result := conversionOK;
  Size := Size shr 2;
  Target := '';
  for i := 0 to Size - 1 do
  begin
    k := i shl 2;
    ch := S[k] + S[k + 1] shl 8 + S[k + 2] shl 16 + S[k + 3] shl 24;

    if (ch <= UNI_MAX_BMP) then         { Target is a character <= 0xFFFF }
    begin
      if ((Flags = strictConversion) and ((ch >= UNI_SUR_HIGH_START) and (ch <= UNI_SUR_LOW_END))) then
      begin
        Result := sourceIllegal;
        Exit;
      end
      else
        Target := Target + WideChar(ch);  { normal case }
    end
    else
      if (ch > UNI_MAX_UTF16) then
      begin
        if (Flags = strictConversion) then
        begin
          Result := sourceIllegal;
          Exit;
        end
        else
          Target := Target + WideChar(UNI_REPLACEMENT_CHAR);
      end
      else
      { target is a character in range 0xFFFF - 0x10FFFF. }
      begin
        ch := ch - halfBase;
        Target := Target + WideChar((ch shr halfShift) + UNI_SUR_HIGH_START) +
                           WideChar((ch and halfMask) + UNI_SUR_LOW_START);
      end;
  end;

  if BOM and (Ord(Target[StringStartOffset]) <> $FEFF) then
    Target := WideChar($FEFF) + Target;
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function ConvertToUTF8String(const Source : UnicodeString) : ByteArray;
begin
  SetLength(Result, 0);
  if ConvertUTF16ToUTF8(Source, Result, strictConversion, false) = sourceIllegal then
    result := BytesOfString(source);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ConvertFromUTF8String(const Source : ByteArray; CheckBOM : boolean = true) : UnicodeString;
begin
  if (not CheckBOM) or (CompareMem(Source, 0, UTF8BOMByteArray, 0, 3)) then
  begin
    result := '';
    if ConvertUTF8ToUTF16(Source, Result,  strictConversion, false) = sourceIllegal then
      result := StringOfBytes(Source)
    else
    begin
      if (Length(Result) > 1) and (Result[StringStartOffset] = WideChar($FEFF)) then
        Result := StringRemove(Result, StringStartOffset, 1);
    end;
  end
  else
  begin
    result := StringOfBytes(Source);
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ConvertFromUTF32String(const Source: ByteArray; CheckBOM: Boolean = True): UnicodeString;
begin
  if (not CheckBOM) or
     ((Length(Source) >= 4) and
      (Source[0] = byte($FF)) and
      (Source[0 + 1] = byte($FE)) and
      (Source[0 + 2] = byte(0)) and
      (Source[StringStartOffset + 3] = byte(0))
     ) then
  begin
    Result := '';
    if ConvertUTF32toUTF16(Source[0], Length(Source), Result,  strictConversion, false) = sourceIllegal then
      Result := StringOfBytes(Source)
    else
    begin
      if (Length(Result) > 1) and (Result[StringStartOffset] = WideChar($FEFF)) then
        Result := StringRemove(Result, StringStartOffset, 1);
    end;
  end
  else
  begin
    Result := StringOfBytes(Source);
  end;
end;



{$ifndef VCL60}
// Done 7 / XE5
function TryStrToInt(const S: string; out Value: Integer): Boolean;
var
  Err: Integer;
begin
  Val(S, Value, Err);
  Result := (Err = 0);
end;

// Done 7 / XE5
function TryStrToInt64(const S: string; out Value: Int64): Boolean;
var
  Err: Integer;
begin
  Val(S, Value, Err);
  Result := (Err = 0);
end;
 {$endif}

// Done 7 / XE5(32) / XE5(64) / Android
function SBTrim(const S : ByteArray) : ByteArray;
var fp, lp : integer;
begin
  fp := 0;
  lp := Length(S) - 1;
  while fp <= lp do
  begin
    if ((S[fp] = 9) or (S[fp] = 32) or (S[fp] = 13)or (S[fp] = 10)) then
      inc (fp)
    else
      break;
  end;

  while lp >= fp do
  begin
    if ((S[lp] = 9) or (S[lp] = 32) or (S[lp] = 13)or (S[lp] = 10)) then
      dec(lp)
    else
      break;
  end;
  result := SBCopy(S, fp, lp - fp + 1);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SBUppercase(const S : ByteArray) : ByteArray;
var i : integer;
begin
  SetLength(Result, Length(S));
  for i := 0 to Length(S) -1 do
    result[i] := Ord(Upcase(Char(S[i])));
end;


{$ifdef SB_UNICODE_VCL}
// Done XE5(32) / XE5(64) / Android
function LowerCase(const s: ByteArray): ByteArray;
var
  i: Integer;
begin
  Result := System.Copy(s, 0, Length(s));
  for i := Length(Result) - 1 downto 0 do
    if (Ord(Result[i]) >= Ord('A')) and (Ord(Result[i]) <= Ord('Z')) {Result[i] in ['A'..'Z']} then
      Result[i] := byte(Byte(Result[i]) or $20);
end;

// Done XE5(32) / XE5(64) / Android
function UpperCase(const s: ByteArray): ByteArray;
var
  i: Integer;
begin
  Result := System.Copy(s, 0, Length(s));
  for i := Length(Result) - 1 downto 0 do
    if (Ord(Result[i]) >= Ord('a')) and (Ord(Result[i]) <= Ord('z')) {Result[i] in ['a'..'z']} then
      Result[i] := byte(Byte(Result[i]) xor $20);
end;
 {$endif}

// Done 7 / XE5(32) / XE5(64) / Android
function StringSplitPV(const S : string; out Name : string; out Value : string) : boolean;
begin
  result := StringSplitPV(S, Name, Value, '=');
end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringSplitPV(const S : string; out Name : string; out Value : string; Separator : char) : boolean;
var Idx : integer;
begin
  Idx := StringIndexOf(S, Separator);

  if Idx >= StringStartOffset then
  begin
    Name := StringSubstring(S, StringStartOffset, Idx - StringStartOffset);
    Value := StringSubstring(S, Idx + 1, Length(S) - Idx - StringStartInvOffset);

    // DeN 27.09.2013
    if (Name = '') or (Value = '') then
    begin
      Name := '';
      Value := '';
      result := false;
    end
    else
    // end DeN 27.09.2013
    result := true;
  end
  else
  begin
    Name := '';
    Value := '';
    result := false;
  end;
end;

{$ifdef SB_ANSI_VCL}
// Done 7
function StringSplitPV(const S : UnicodeString; out Name : UnicodeString; out Value : UnicodeString) : boolean;
begin
  result := StringSplitPV(S, Name, Value, WideChar('='));
end;

// Done 7
function StringSplitPV(const S : UnicodeString; out Name : UnicodeString; out Value : UnicodeString; Separator : WideChar) : boolean;
var Idx : integer;
begin
  Idx := StringIndexOf(S, Char(Separator));
  if Idx >= StringStartOffset then
  begin
    Name := StringSubstring(S, StringStartOffset, Idx - StringStartOffset);
    Value := StringSubstring(S, Idx + 1);
    
    // DeN 27.09.2013
    if (Name = '') or (Value = '') then
    begin
      Name := '';
      Value := '';
      result := false;
    end
    else
    // end DeN 27.09.2013
      result := true;
  end
  else
  begin
    Name := '';
    Value := '';
    result := false;
  end;
end;
 {$endif}

{$ifndef SB_UNICODE_VCL}
// Need - check
function WideStringSplit(const S: WideString; Separator: WideChar): WideStringArray;
begin
  Result := WideStringSplit(S, Separator, False);
end;

// Done 7
function WideStringSplit(const S: WideString; Separator: WideChar; RemoveEmptyEntries: Boolean): WideStringArray;
var
  I, L, Count, Start: Integer;
begin
  L := Length(S);

  if L = 0 then
  begin
    if RemoveEmptyEntries then
      SetLength(Result, 0)
    else
    begin
      SetLength(Result, 1);
      Result[0] :=  '' ;
    end;
    Exit;
  end;

  Count := 0;
  Start := StringStartOffset;

  for I := StringStartOffset to L + StringStartOffset do
    if (I > L - StringStartInvOffset) or (S[I] = Separator) then
    begin
      if not RemoveEmptyEntries or (I > Start) then
        Inc(Count);
      Start := I + 1;
    end;

  SetLength(Result, Count);
  Count := 0;
  Start := StringStartOffset;

  for I := StringStartOffset to L + StringStartOffset do
    if (I > L - StringStartInvOffset) or (S[I] = Separator) then
    begin
      if not RemoveEmptyEntries or (I > Start) then
      begin
        if I = Start then
          Result[Count] :=  '' 
        else
          Result[Count] := StringSubstring(S, Start, I - Start);
        Inc(Count);
      end;
      Start := I + 1;
    end;

end;
 {$endif}

// Need - check
function StringSplit(const S: string; Separator: Char): StringArray;
begin
  Result := StringSplit(S, Separator, False);
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function StringSplit(const S: string; Separator: Char; RemoveEmptyEntries: Boolean): StringArray;
var
  I, L, Count, Start: Integer;
begin
  L := Length(S); // DeN 08.01.2014 - add StringStartInvOffset

  if L < 1 then
  begin
    if RemoveEmptyEntries then
      SetLength(Result, 0)
    else
    begin
      SetLength(Result, 1);
      Result[0] :=  '' ;
    end;
    Exit;
  end;
  Count := 0;
  Start := StringStartOffset;

  for I := StringStartOffset to L - StringStartInvOffset do
    if (I >= L - StringStartInvOffset) or (S[I] = Separator) then
    begin
      if not RemoveEmptyEntries or (I >= Start) then
        Inc(Count);
      Start := I + 1;
    end;

  SetLength(Result, Count);
  Count := 0;
  Start := StringStartOffset;

  for I := StringStartOffset to L - StringStartInvOffset do
    if (I >= L - StringStartInvOffset) or (S[I] = Separator) then
    begin
      if not RemoveEmptyEntries or (I >= Start) then
      begin
        if I = Start then
        begin
          if (I = L - StringStartInvOffset) and (S[I] <> Separator) then
            Result[Count] := StringSubstring(S, Start, 1)
          else
            Result[Count] :=  '' ;
        end
        else if (I <= L - StringStartInvOffset) and (S[I] = Separator) then
          Result[Count] := StringSubstring(S, Start, I - Start)
        else
          Result[Count] := StringSubstring(S, Start, I - Start + 1);
        Inc(Count);
      end;
      Start := I + 1;
    end;

end;

// Done 7
function SBPos(const substr, str: AnsiString): Integer;
begin
  result := System.Pos(substr, str);
end;

{$ifdef SB_UNICODE_VCL}
// Done 7 / XE5(32) / XE5(64) / Android
function SBPos(const substr, str: string): Integer;
begin
  result := System.Pos(substr, str);
end;
 {$endif}







// Done 7 / XE5(32) / XE5(64) / Android
function SBCopy(const str:  ByteArray ; Offset, Size : integer): ByteArray;
begin
  if (Offset < 0) or (Size <= 0) then
  begin
    result := EmptyArray;
    exit;
  end;
  if Offset + size > Length(str) then
  begin
    Size := Length(str) - offset;

    if Size <= 0 then
    begin
      result := EmptyArray;
      exit;
    end;
  end;
  SetLength(result, Size);
  SBMove(str[Offset], result[0], Size);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SBCopy(const str:  ByteArray ): ByteArray;
begin
  Result := SBCopy(str, 0, Length(str));
end;


// Done 7 / XE5(32) / XE5(64) / Android
function SBRightPos(const Substr, Str : string) : integer;
var
  i : integer;
begin
  result := StringStartOffset -1;

  // DeN 24.09.2013
  if (Length(Str) = 0) or (Length(Substr) = 0) then
    Exit;
  // end DeN 24.09.2013

  for i := Length(Str) - Length(Substr) + StringStartOffset downto StringStartOffset do
  begin
    if StrLComp(PChar(@Str[i]), PChar(Substr), Length(Substr)) = 0 then
    begin
      result := i;
      break;
    end;
  end;
end;

// TODO: possibly wrong upper bounds. Check OIDToStr carefully in VCL, .NET and Delphi Mobile
// Done 7 / XE5(32) / XE5(64) / Android
function OIDToStr(const OID: ByteArray): String;
var
  Index, Start : integer;
  ID, A, B : cardinal;
  I : integer;
begin
  // DeN 27.11.2013
  if OID = nil then
    Exit;
  // end DeN 27.11.2013
  	
  // reading the first subgroup
  Index := 0;
  while (Index <= Length(OID) - 1) and ((PByte(@OID[Index])^ and $80) = $80) do
    Inc(Index);

  if Index > Length(OID) - 1 then
    Index := Length(OID) - 1;
  ID := 0;
  for I := 0 to Index do
    ID := ID or ((Ord(OID[Index - I]) and $7f) shl (7 * I));
  if ID < 40 then
    A := 0
  else if (ID >= 40) and (ID < 80) then
    A := 1
  else
    A := 2;
  B := ID - (A * 40);

  Result := IntToStr(A) + '.' + IntToStr(B);

  Inc(Index);
  if Index > Length(OID) then
    Result := Result + '.' + '0'
  else
  begin
    Start := Index;
    while Index < Length(OID) do // DeN 27.11.2013 removed "=" and got just "<"
    begin
      // reading the subgroup
      if ((Ord(OID[Index]) and $80) <> $80) or (Index = Length(OID) - 1) then
      begin
        ID := 0;
        for I := 0 to Index - Start do  // TODO: possibly wrong upper bound. Check in VCL and .NET
          ID := ID or ((Ord(OID[Index - I]) and $7f) shl (7 * I));
        Result := Result + '.' + IntToStr(ID);
        Start := Index + 1;
      end;
      Inc(Index);
    end;
  end;
end;


// Done 7 / XE5(32) / XE5(64) / Android
function StrToOID(const Str : string) : ByteArray;

  function ReadNextArc(var S : string) : string;
  var
    Index : integer;
  begin
    Index := StringIndexOf(S, '.');

    if (Index >= StringStartOffset) then
    begin
      Result := StringSubstring(S, StringStartOffset, Index - StringStartOffset);
      S := StringSubstring(S, Index + 1);
    end
    else
    begin
      Result := S;
      SetLength(S, 0);
    end;
  end;

var
  FirstArc, SecondArc, S : string;
  N1, N2 : integer;
  B : byte;
  Right : boolean;
  Tmp1, Tmp2 : ByteArray;
begin
  S := Str;
  FirstArc := ReadNextArc(S);
  SecondArc := ReadNextArc(S);

  try
    N1 := StrToInt(FirstArc);
    N2 := StrToInt(SecondArc);
  except
    raise EElOIDError.Create(SInvalidOID);
  end;

  if (N1 < 0) or (N1 > 2) or (N2 < 0) or (N2 > 39) then
    raise EElOIDError.Create(SInvalidOID);

  SetLength(Result, 1);
  Result[0] := byte(N1 * 40 + N2);

  while Length(S) > 0 do
  begin
    FirstArc := ReadNextArc(S);
    try
      N1 := StrToInt(FirstArc);
    except
      raise EElOIDError.Create(SInvalidOID);
    end;
    Right := true;
    if N1 = 0 then
    begin
      SecondArc := #0;
    end
    else
    begin
      while N1 > 0 do
      begin
        B := N1 and $7F;
        if Right then
        begin
          SecondArc := Chr(B);
          Right := false;
        end
        else
         SecondArc := Chr(B or $80) + SecondArc;
         N1 := N1 shr 7;
      end;
    end;

    Tmp1 := Result;
    Tmp2 := BytesOfString(SecondArc);
    Result := SBConcatArrays(Tmp1, Tmp2);
    ReleaseArray(Tmp1);
    ReleaseArray(Tmp2);
  end;
end;

{$ifndef HAS_DEF_PARAMS}
function SBPos(const SubP : ByteArray; const P : ByteArray) : integer;
begin
  Result := SBPos(SubP, P, 0);
end;

function SBPos(const SubP : string; const P : ByteArray) : integer;
begin
  Result := SBPos(SubP, P, 0);
end;
 {$endif}

// Done 7 / XE5(32) / XE5(64) / Android
function SBPos(const SubP :  ByteArray ; const P :  ByteArray ; StartPos : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}) : integer;
var
  I, J : integer;
  Flag : boolean;
begin
  Result := -1;

  // DeN 06.12.2013
  if (Length(P) = 0) or (Length(SubP) = 0) or (StartPos < 0) or (Length(SubP) > Length(P)) then
    exit;
  // end DeN 06.12.2013

  for I := StartPos to Length(P) - Length(SubP) do
  begin
    Flag := true;
    for J := 0 to Length(SubP) - 1 do
    begin
      if P[I + J] <> SubP[J] then
      begin
        Flag := false;
        break;
      end;
    end;
    if Flag then
    begin
      Result := I;
      Exit;
    end;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SBPos(const SubP : string; const P : ByteArray; StartPos : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}) : integer;
var
  I, J : integer;
  Flag : boolean;
begin
  Result := -1;

  // DeN 23.09.2013
  if (P = nil) or (Length(SubP) = 0) or (StartPos < 0) then
    exit;
  // if StartPos >= Length(P) - Length(SubP) then
  //  StartPos := Length(P) - Length(SubP);
  // end DeN 23.09.2013

  for I := StartPos to Length(P) - Length(SubP) do
  begin
    Flag := true;
    for J := StringStartOffset to Length(SubP) - 1 + StringStartOffset do
    begin
      if P[I + J - StringStartOffset] <> Ord(SubP[J]) then
      begin
        Flag := false;
        break;
      end;
    end;
    if Flag then
    begin
      Result := I;
      Exit;
    end;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SBPos(SubP : byte; const P : ByteArray) : integer;	
var
  I : integer;
begin
  Result := 0 - 1;
  for I := 0 to Length(P) - 1 do
  begin
    if P[I + 0] = SubP then
    begin
      Result := I;
      Exit;
    end;
  end;
end;

// TODO: Check various variants of ReplaceStr in VCL and in Delphi Mobile
// Possible index corruption
// Done 7 / XE5(32) / XE5(64) / Android
function ReplaceStr(const Source : string; Entry, ReplaceWith : string) : string;
var i, j : integer;
    found : boolean;
    SourceLen,
    EntryLen : integer;
begin
  if Entry = '' then
  begin
    result := Source;
    exit;
  end;

  result := '';
  EntryLen := Length(Entry);
  SourceLen := Length(Source);

  i := StringStartOffset;

  while i <= SourceLen - StringStartInvOffset do
  begin
    found := true;
    j := StringStartOffset;
    while (j <= EntryLen - StringStartInvOffset) and (i + j <= SourceLen + 1) do
    begin
      if Source[i + j - StringStartOffset] <> Entry[j] then // DeN 17.01.2014
      begin
        found := false;
        break;
      end;
      inc(j);
    end;
    if (j >= EntryLen) and Found then
    begin
      result := result + ReplaceWith;
      i := i + EntryLen;
    end
    else
    begin
      result := result + Source[i];
      inc(i);
    end;
  end;
end;



// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function PAnsiCharToByteArray(const P : PAnsiChar) : ByteArray;
var i : integer;
    PB: PByte;
begin
  // DeN 23.09.2013
  if P = nil then
  begin
    result := nil;
    exit;
  end;
  // end DeN 23.09.2013
  	
  PB := PByte(P);
  i := 0;
  while (PB^) <> 0 do
  begin
    inc(i);
    inc(PB);
  end;
  if i > 0 then
  begin
    SetLength(Result, i);
    SBMove(P^, Result[0], i);
  end
  else
    result := EmptyArray;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function PathFirstComponent(const Path : string) : string;
var
  i : integer;
begin
  Result := '';
  if ( Length(Path) = 0 ) or
  // DeN 14.02.2014
  ((StringIndexOf(Path, '\') < StringStartOffset) and
   (StringIndexOf(Path, '/') < StringStartOffset)) then
  // end DeN 14.02.2014
    Exit;

  i := StringStartOffset;
  if (Path[i] = '/') or (Path[i] = '\') then
    Inc(i);

  while (i < Length(Path) - StringStartInvOffset) and (Path[i] <> '/') and (Path[i] <> '\') do
    Inc(i);

  if (i <= Length(Path) - StringStartInvOffset) then
  begin
    if (Path[i] = '\') or (Path[i] = '/') then
      Result := StringSubstring(Path, StringStartOffset, i - StringStartOffset)
    else
      Result := StringSubstring(Path, StringStartOffset, i - StringStartOffset + 1);
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function PathCutFirstComponent(const Path : string) : string;
var
  i : integer;
begin
  Result := '';
  if Length(Path) = 0 then
    Exit;

  i := StringStartOffset;
  if (Path[i] = '/') or (Path[i] = '\') then
    Inc(i);

  while (i < Length(Path) - StringStartInvOffset) and (Path[i] <> '/') and (Path[i] <> '\') do
    Inc(i);

  if (i < Length(Path) - StringStartInvOffset) then
    Result := StringSubstring(Path, i + 1, Length(Path) - i - StringStartInvOffset);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function PathCutLastComponent(const Path : string) : string;
var
  i : integer;
begin
  Result := '';

  if Length(Path) = 0 then
    Exit;

  i := Length(Path) - StringStartInvOffset;

  if (Path[i] = '/') or (Path[i] = '\') then
    Dec(i);

  while (i >= StringStartOffset) and (Path[i] <> '/') and (Path[i] <> '\') do
    Dec(i);

  if i >= StringStartOffset then
    Result := StringSubstring(Path, StringStartOffset, i - StringStartOffset);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function PathLastComponent(const Path : string) : string;
var
  i : integer;
  j : integer;
begin
  Result := '';
  if Length(Path) = 0 then
    Exit;

  i := Length(Path) - StringStartInvOffset;

  if (Path[i] = '/') or (Path[i] = '\') then
    Dec(i);

  j := i;

  while (i >= StringStartOffset) and (Path[i] <> '/') and (Path[i] <> '\') do
    Dec(i);

  inc(i);
  
  Result := StringSubstring(Path, i, j - i + 1);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function PathIsDirectory(const Path : string) : boolean;
var
  i : integer;
begin
  i := Length(Path);
  Result := (i > 0) and ((Path[i - StringStartInvOffset] = '/') {$ifdef SB_WINDOWS_OR_NET_OR_JAVA}or (Path[i - StringStartInvOffset] = '\') {$endif});
end;

// Done 7 / XE5(32) / XE5(64) / Android
function PathTrim(const Path : string) : string;
var
  i : integer;
begin
  i := Length(Path);
  if (i > 0) and ((Path[i - StringStartInvOffset] = '/') {$ifdef SB_WINDOWS_OR_NET_OR_JAVA}or (Path[i - StringStartInvOffset] = '\') {$endif}) then
    Result := StringSubstring(Path, StringStartOffset, i - {$ifndef SB_DELPHI_IOS}StringStartOffset {$else}1 {$endif})
  else
    Result := Path;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function PathConcatenate(const Path1, Path2 : string) : string;
var str1, str2, sl: string;
    i1, i2 : integer;
begin
  // DeN 17.09.2013
  str1 := PathTrim(Path1);
  str2 := PathTrim(Path2);
  sl := '';
  i1 := Length(str1);
  i2 := Length(str2);
  if (i1 > 0) and (i2 > 0) and
  {$ifdef SB_WINDOWS_OR_NET_OR_JAVA}
    (str1[i1 - StringStartInvOffset] <> '\') and (str2[StringStartOffset] <> '\') and
   {$endif} 
    (str1[i1 - StringStartInvOffset] <> '/') and (str2[StringStartOffset] <> '/')
  then
    sl := SLASH;
  // end DeN 17.09.2013

  if Length(str1) > 0 then
    Result := str1 + sl + str2
  else
    Result := str2;

  Result := PathNormalizeSlashes(Result);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function PathNormalizeSlashes(const Path : string) : string;
var
  i : integer;
begin
  Result := StringSubstring(Path, StringStartOffset, Length(Path));

  {$ifdef SB_WINDOWS}
  for i := StringStartOffset to Length(Result) - StringStartInvOffset do
   if Result[i] = '/' then
     Result[i] := '\';
   {$else}
  for i := StringStartOffset to Length(Result) - StringStartInvOffset do
   if Result[i] = '\' then
     Result[i] := '/';
   {$endif}
end;

// Done 7 / XE5(32) / XE5(64) / Android
function PathReverseSlashes(const Path : string) : string;
var
  i : integer;
begin
  Result := StringSubstring(Path, StringStartOffset, Length(Path));

  for i := StringStartOffset to Length(Result) - StringStartInvOffset do
   if Result[i] = '\' then
     Result[i] := '/'
   else if Result[i] = '/' then
     Result[i] := '\';
end;

// Need - check
function PathMatchesMask(const Path, Mask : string) : boolean;
begin
  Result := PathMatchesMask(Path, Mask, false);
end;

// Need - check
function PathMatchesMask(const Path, Mask : string; CaseSensitive : boolean) : boolean;
var
  p, m : string;
begin
  // just wrapper to normalize slashes before matching
  p := PathNormalizeSlashes(Path);
  m := PathNormalizeSlashes(Mask);
  Result := FilenameMatchesMask(p, m, CaseSensitive);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function IsFileMask(const Path : string) : boolean;
var
  i : integer;
begin
  for i := StringStartOffset to Length(Path) - StringStartInvOffset do
    if (Path[i] = '*') or (Path[i] = '?') then
    begin
      Result := true;
      Exit;
    end;

  Result := false;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ExtractPathFromMask(const Mask : string) : string;
var
  i : integer;
begin
  Result := '';

  for i := StringStartOffset to Length(Mask) - StringStartInvOffset do
    if ((Mask[i] = '/') or (Mask[i] = '\'))  then
      Result := StringSubstring(Mask, StringStartOffset, i - StringStartOffset)
    else
    if (Mask[i] = '?') or (Mask[i] = '*') then
      Exit;
end;
// -------------

// Done 7 / XE5(32) / XE5(64) / Android
function ZipPathFirstComponent(const Path : string) : string;
var
  i : integer;
begin
  { for /dir/subdir returns dir, for /dir/ - empty string !! }
  Result := '';
  if Length(Path) = 0 then
    Exit;

  i := StringStartOffset;
  if (Path[i] = '/') or (Path[i] = '\') then
    Inc(i);

  while (i < Length(Path) - StringStartInvOffset) and (Path[i] <> '/') and (Path[i] <> '\') do
    Inc(i);

  if (i < Length(Path) - StringStartInvOffset) then
  begin
    Result := StringSubstring(Path, StringStartOffset, i - StringStartOffset);

    if (Length(Result) > 1) and ((Result[StringStartOffset] = '/') or (Result[StringStartOffset] = '\')) then
      Result := StringSubstring(Result, StringStartOffset + 1, i - 1 - StringStartOffset);
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ZipPathCutFirstComponent(const Path : string) : string;
var
  i : integer;
begin
  Result := '';
  if Length(Path) = 0 then
    Exit;

  i := StringStartOffset;
  if (Path[i] = '/') or (Path[i] = '\') then
    Inc(i);

  while (i < Length(Path) - StringStartInvOffset) and (Path[i] <> '/') and (Path[i] <> '\') do
    Inc(i);

  if (i < Length(Path) - StringStartInvOffset) then
    Result := StringSubstring(Path, i + 1, Length(Path) - i - StringStartInvOffset);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ZipPathCutLastComponent(const Path : string) : string;
var
  i : integer;
begin
  Result := '';
  if Length(Path) = 0 then
    Exit;

  i := Length(Path) - StringStartInvOffset;

  if (Path[i] = '/') or (Path[i] = '\') then
    Dec(i);

  while (i >= StringStartOffset) and (Path[i] <> '/') and (Path[i] <> '\') do
    Dec(i);

  if i >= StringStartOffset then
    Result := StringSubstring(Path, StringStartOffset, i - StringStartOffset); 
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ZipPathLastComponent(const Path : string) : string;
var
  i : integer;
  j : integer;
begin
  Result := '';
  if Length(Path) = 0 then
    Exit;

  i := Length(Path) - StringStartInvOffset;

  if (Path[i] = '/') or (Path[i] = '\') then
    Dec(i);

  j := i;

  while (i >= StringStartOffset) and (Path[i] <> '/') and (Path[i] <> '\') do
    Dec(i);

  inc(i);

  Result := StringSubstring(Path, i, j - i + StringStartInvOffset); // DeN 14.01.2014
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ZipPathIsDirectory(const Path : string) : boolean;
begin
  Result := (Length(Path) > 0) and ((Path[Length(Path) - StringStartInvOffset] = '/') or ((Path[Length(Path) - StringStartInvOffset] = '\')));
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ZipPathTrim(const Path : string) : string;
var
  i : integer;
begin
  i :=  Length(Path) ;
  if (i > 0) and ((Path[i - StringStartInvOffset] = '/') or (Path[i - StringStartInvOffset] = '\')) then
    Result := StringSubstring(Path, StringStartOffset, i - {$ifndef SB_DELPHI_IOS}StringStartOffset {$else}1 {$endif})
  else
    Result := Path;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ZipPathConcatenate(const Path1, Path2 : string) : string;
var str1, str2, sl: string;
begin
  // DeN 17.09.2013
  str1 := ZipPathTrim(Path1);
  str2 := ZipPathTrim(Path2);
  sl := '';

  if (Length(str1) > 0) and (Length(str2) > 0) and 
  {$ifdef SB_WINDOWS_OR_NET_OR_JAVA}(str1[Length(str1) - StringStartInvOffset] <> '\') and (str2[StringStartOffset] <> '\') and
   {$endif} (str1[Length(str1) - StringStartInvOffset] <> '/') and (str2[StringStartOffset] <> '/')
   then 
    sl := SLASH;
  // end DeN 17.09.2013

  if Length(str1) > 0 then
    Result := str1 + sl + str2
  else
    Result := str2;

  Result := ZipPathNormalizeSlashes(Result);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ZipPathNormalizeSlashes(const Path : string) : string;
var
  i : integer;
begin
  Result := StringSubstring(Path, StringStartOffset, Length(Path));

  {$ifdef SB_WINDOWS}
  for i := StringStartOffset to Length(Result) - StringStartInvOffset do
   if Result[i] = '/' then
     Result[i] := '\';
   {$else}
  for i := StringStartOffset to Length(Result) - StringStartInvOffset do
   if Result[i] = '\' then
     Result[i] := '/';
   {$endif}
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ZipPathReverseSlashes(const Path : string) : string;
var
  i : integer;
begin
  Result := StringSubstring(Path, StringStartOffset, Length(Path));

  for i := StringStartOffset to Length(Result) - StringStartInvOffset do
   if Result[i] = '\' then
     Result[i] := '/';
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ZipPathMatchesMask(const Path, Mask : string) : boolean;
begin
  Result := ZipPathMatchesMask(Path, Mask, false);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ZipPathMatchesMask(const Path, Mask : string; CaseSensitive : boolean) : boolean;
var
  p, m : string;
begin
  // just wrapper to normalize slashes before matching
  p := ZipPathNormalizeSlashes(Path);
  m := ZipPathNormalizeSlashes(Mask);
  Result := FilenameMatchesMask(p, m, CaseSensitive);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ZipIsFileMask(const Path : string) : boolean;
var
  i : integer;
begin
  for i := StringStartOffset to Length(Path)-StringStartInvOffset do
    if (Path[i] = '*') or (Path[i] = '?') then
    begin
      Result := true;
      Exit;
    end;

  Result := false;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ZipExtractPathFromMask(const Mask : string) : string;
var
  i : integer;
begin
  Result := '';

  for i := StringStartOffset to Length(Mask) - StringStartInvOffset do
    if ((Mask[i] = '/') or (Mask[i] = '\'))  then
      Result := StringSubstring(Mask, StringStartOffset, i - StringStartOffset)
    else
    if (Mask[i] = '?') or (Mask[i] = '*') then
      Exit;
end;

(*
function ExtractFile(const Path : string) : string;
var
  i : integer;
begin
  for i := Length(Path) - StringStartInvOffset downto StringStartOffset do
    if (Path[i] = '/') or (Path[i] = '\') then
    begin
      {$ifndef SB_NET}
      Result := Copy(Path, i + 1, Length(Path) - i - StringStartInvOffset);
      {$else}
      Result := Path.Substring(i + 1, Length(Path) - i - 1);
      {$endif}
      Exit;
    end;
  Result := Path;
end;

function ExtractDirectory(const Path : string) : string;
var
  i : integer;
begin
  for i := Length(Path) - StringStartInvOffset downto StringStartOffset do
    if (Path[i] = '/') or (Path[i] = '\') then
    begin
      {$ifndef SB_NET}
      Result := Copy(Path, StringStartOffset, i - StringStartOffset);
      {$else}
      Result := Path.Substring(0, i);
      {$endif}
      Exit;
    end;
  Result := '';
end;
*)

// --------------------------------------------------------------------
// This came from SBMIMEUtils
//

// Done 7 / XE5(32) / XE5(64) / Android
procedure DecodeDateTime(const AValue: TElDateTime;
  out AYear, AMonth, ADay, AHour, AMinute, ASecond, AMilliSecond: Word);
begin
    DecodeDate(AValue, AYear, AMonth, ADay);
  DecodeTime(AValue, AHour, AMinute, ASecond, AMilliSecond);
end;

// TODO: verify indicies in all platforms
// Done 7 / XE5(32) / XE5(64) / Need - check in Android
procedure TrimEx(var S: AnsiString;
  bTrimLeft: Boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif};
  bTrimRight: Boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif});
var
  SLen, L, R: Integer;
begin
  SLen := Length(S);
  if (SLen = 0) or (not bTrimLeft and not bTrimRight)  then
    Exit;

  L := AnsiStrStartOffset;
  R := SLen - AnsiStrStartInvOffset;

  if bTrimLeft then
  begin
    while (L <= R) and ((S[L] = AnsiChar(' ')) or (S[L] = AnsiChar(#9))) do
      Inc(L);

    if L > R then
    begin
      SetLength(S, 0);
      Exit;
    end;
  end;

  if bTrimRight then
  begin
    while (R >= L) and ((S[R] = AnsiChar(' ')) or (S[R] = AnsiChar(#9))) do
      Dec(R);

    if R < L then
    begin
      SetLength(S, 0);
      Exit;
    end;
  end;

  S :=  Copy (S, L, R - L + 1);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure TrimSemicolon(var S : TWideString);
var
  I : integer;
begin
  I := Length(S) - StringStartInvOffset;
  while (I > StringStartOffset) and (S[I] = ';') do
    Dec(I);
  S := StringSubstring(S, StringStartOffset, I + StringStartInvOffset);
end;

// TODO: Verify in VCL and Delphi Mobile
// Done 7 / XE5(32) / XE5(64) / Android
function IntToStrPadLeft(Val: Integer;
  iWidth: Integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif};
  chTemplate: TWideChar {$ifdef HAS_DEF_PARAMS} =  '0' {$endif}): TWideString;
var
  i, d: Integer;
begin
  if iWidth < 0 then
    iWidth := 0;
  Result := IntToStr(Val);
  Val := Length(Result);
  if Val<iWidth then
  begin
    SetLength(Result, iWidth);
    // move first chars to last
    d := iWidth - Val;
    for i:= Val - StringStartInvOffset downto StringStartOffset do
      Result[i+d] := Result[i];
    // fill first values as '0'
    for i := StringStartOffset to d - StringStartInvOffset do
      Result[i] := chTemplate;
  end;
end;


// Done 7 / XE5(32) / XE5(64) / Android
function ExtractWideFileName(const FileName: TWideString): TWideString;
var
  I: Integer;
begin
  for i := Length(FileName) - StringStartInvOffset downto StringStartOffset do
  begin
    {$ifdef SB_WINDOWS_OR_NET_OR_JAVA}
    if (FileName[i] = '\') or (FileName[i] = '/') then
     {$else}
    if (FileName[i] = '/') then
     {$endif}
    begin
      Result := StringSubstring(FileName, i + 1 + StringStartInvOffset, Length(FileName)-i - StringStartInvOffset);
      exit;
    end;
  end;
  Result := FileName;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ExtractWideFileExtension(const FileName: TWideString): TWideString;
var
 iPos: Integer;
begin
  iPos :=  {$ifndef SB_UNICODE_VCL}PosLast {$else}WidePosLast {$endif} ('.', FileName);
  if iPos >= StringStartOffset then
    Result := StringSubstring(FileName, iPos + 1, Length(FileName) - iPos - StringStartInvOffset)
  else
    Result := '';
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ExtractFileExtension(const FileName: TWideString): AnsiString;
begin
  Result := AnsiStringOfString(ExtractWideFileExtension(FileName));
end;

// TODO : Verify in all platforms
// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function WidePosEx(const SubStr, S: TWideString;
  Offset: Integer;
  Count: Integer): Integer;
var
  I, X: Integer;
  Len, LenSubStr: Integer;
begin
  Result := -1;
  Len := Length(S);
  LenSubStr := Length(SubStr);

  if not ( (StringStartOffset > Offset) or (Offset > Len - StringStartInvOffset) or (Count = 0) or (Len = 0) or (LenSubStr = 0) ) then
  begin
    if (Count < 0) or ( Count > Len - Offset + StringStartOffset) then
      Count := Len - Offset + StringStartOffset;
    if Count < LenSubStr then
      exit;
    I := Offset;
    Len := (Offset + Count) - LenSubStr;

    while I <= Len do
    begin
      if S[I] = SubStr[StringStartOffset] then
      begin
        X := 1;//StringStartOffset;

        while (X  <  LenSubStr - StringStartInvOffset) and (S[I + X] = SubStr[X + StringStartOffset]) do // DeN 14.01.2014
          Inc(X);

        if (X = LenSubStr {- StringStartInvOffset}) then
        begin
          Result := I;
          exit;
        end;

      end;
      Inc(I);
    end;

  end;
end;


{$DEFINE POSEX}
{$ifdef SB_WINDOWS}
  {$ifdef VCL_7_USED}
    {$UNDEF POSEX}
   {$endif}
 {$endif SB_WINDOWS}

{$ifdef POSEX}

function PosEx(const SubStr, S: AnsiString; Offset: Integer): Integer;
begin
  if (Offset < AnsiStrStartOffset) or (Offset>Length(S) - AnsiStrStartInvOffset) then
    Result := AnsiStrStartOffset - 1
  else
  begin
    Result := System.Pos(SubStr, PAnsiChar(@S[Offset]));
    if Result >= AnsiStrStartOffset  then
      inc(Result, Offset);
  end;
end;

 {$endif POSEX}


// TODO: Verify in all editions
// Inner - Not tested
function _PosEx(const SubStr, S: AnsiString; Offset, Count: Integer): Integer;
var
  I,X: Integer;
  Len, LenSubStr: Integer;
begin
   I := Offset;
   LenSubStr := Length(SubStr);
   Len := (Offset + Count) - LenSubStr;

   while I <= Len do
   begin
     if S[I] = SubStr[AnsiStrStartOffset] then
     begin
       X := 1;//AnsiStrStartOffset;
       while (X  <  LenSubStr - AnsiStrStartInvOffset) and (S[I + X] = SubStr[X + AnsiStrStartOffset]) do
         Inc(X);
       if (X = LenSubStr {- AnsiStrStartInvOffset}) then // DeN 15.01.2014 - add AnsiStrStartInvOffset
       begin
         Result := I;
         exit;
       end;
     end;
     Inc(I);
   end;

   Result := -1;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function PosExSafe(const SubStr, S: AnsiString; Offset: Integer; Count: Integer): Integer;
var
  iLenS, iLenSub: Integer;
begin
  Result := -1;
  iLenS := Length(S);
  iLenSub := Length(SubStr);

  if not ( (AnsiStrStartOffset > Offset) or (Offset > iLenS - AnsiStrStartInvOffset) or (iLenS = 0) or (iLenSub = 0) or (Count = 0) ) then
  begin
    if (Count<0) or ( Count > iLenS - Offset + 1) then
      Count := iLenS - Offset + 1;

    if Count < iLenSub then
      exit;

      // Standart Pos function stop searching on #0 char...
      //if Offset+Count-1 = iLenS then
        //Result := PosEx(SubStr, S, Offset) // <- called BASM version
      //else
        Result := _PosEx(SubStr, S, Offset, Count);
    if Result < AnsiStrStartOffset then
      Result := -1;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function PosLast(const SubStr, S: AnsiString): Integer;
var
  i, LenSubStr, LenS: Integer;
  bOK: Boolean;
begin
  LenS := Length(S);
  LenSubStr := Length(SubStr);

  if (LenS = 0) or (LenSubStr = 0) or (LenSubStr > LenS) then
  begin
    Result := -1;
    exit;
  end;

  for i := LenS downto LenSubStr do
  begin
    bOK := True;
    if S[i - AnsiStrStartInvOffset] = SubStr[LenSubStr - AnsiStrStartInvOffset] then
    begin
      for Result := 1 + AnsiStrStartInvOffset to LenSubStr - AnsiStrStartOffset do
      begin
        if S[i - Result] <> SubStr[LenSubStr - Result] then
        begin
          bOK := False;
          break;
        end;
      end;
      if bOK then
      begin
        Result := i - LenSubStr + AnsiStrStartOffset;
        exit;
      end;
    end;
  end;
  Result := -1;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function WidePosLast(const SubStr, S: TWideString): Integer;
var
  LenSubStr, LenS: Integer;
  i: Integer;
  bOK: Boolean;
begin
  LenS := Length(S) - StringStartInvOffset; // DeN 14.01.2014 - add StringStartInvOffset
  LenSubStr := Length(SubStr) - StringStartInvOffset; // DeN 14.01.2014 - add StringStartInvOffset

  if (LenS = 0 - StringStartInvOffset) or // DeN 14.01.2014 - add StringStartInvOffset
     (LenSubStr = 0 - StringStartInvOffset) or // DeN 14.01.2014 - add StringStartInvOffset
     (LenSubStr > LenS) then
  begin
    Result := -1;
    exit;
  end;

  for i := LenS downto LenSubStr do
  begin
    bOK := True;
    if S[i] = SubStr[LenSubStr] then
    begin
      for Result := StringStartOffset to LenSubStr - StringStartOffset do
      begin
        if S[i - Result] <> SubStr[LenSubStr - Result] then
        begin
          bOK := False;
          break;
        end;
      end;
      if bOK then
      begin
        Result := i - LenSubStr + StringStartOffset; // DeN 06.10.2013 add '+ 1'
        exit;
      end;
    end;
  end;
  Result := -1;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function WideTrimRight(const S : TWideString): TWideString;
var
  I : integer;
begin
  I := Length(S);
  while (I > 0) and (WideChar(S[I - StringStartInvOffset]) <= ' ') do Dec(I);
  Result := S;
  SetLength(Result, I);
end;



// Done 7 / XE5(32) / XE5(64) / Android
function WideStringToByteString(const WS: TWideString): AnsiString;
var
  B: TBytes;
begin
  Result := EmptyAnsiString;
  if Length(WS) = 0 then
    exit;
  GetWideBytesOf(WS, B);
  GetStringOf(B, Result);
end;


// Inner - Not tested
procedure GetBytesOf(const Value: AnsiString; var B: TBytes);
var
  Len: Int64;
begin
  Len := Length(Value);
  SetLength(B, Len);
  if Len > 0 then
    SBMove(Value[AnsiStrStartOffset], B[0], Len);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure GetWideBytesOf(const Value: TWideString; var B: TBytes);
var
  Len: Int64;
begin
  Len := Length(Value);
  if Len > 0 then
  begin
    Len := Len * SizeOf(TWideChar);
    SetLength(B, Len);
    SBMove(Value[StringStartOffset], B[0], Len);
  end
  else
    SetLength(B, 0);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure GetStringOf(const Bytes: TBytes; var S: AnsiString);
var
  Len: Integer;
begin
  Len := Length(Bytes);
  SetLength(S, Len);
  if Len > 0 then
    SBMove(Bytes[0], S[AnsiStrStartOffset], Len);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure GetStringOfEx(const Bytes: TBytes; var S: AnsiString; LPos: Int64 = 0; RPos: Int64 = -1);
var
  Len: Integer;
begin
  if Length(Bytes) = 0 then
  begin
    S := EmptyAnsiString;
    exit;
  end;
  
  if LPos < 0 then
    LPos := 0;
  
  if (RPos < LPos) or (RPos > Length(Bytes) - 1) then
    RPos := Length(Bytes) - 1;
  
  Len := RPos - LPos + 1;
  SetLength(S, Len);
  
  if Len > 0 then
    SBMove(Bytes[LPos], S[AnsiStrStartOffset], Len); // DeN 06.10.2013 Bytes[LPos] instead of Bytes[0]
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure GetWideStringOf(const Bytes: TBytes; var WS: TWideString);
var
  Len: Integer;
begin
  Len := Length(Bytes);
  if Len > 0 then
  begin
    Len := (Len + 1) div SizeOf(TWideChar) * SizeOf(TWideChar);
    SetLength(WS, Len div SizeOf(TWideChar));
    SBMove(Bytes[0], WS[StringStartOffset], Len);
  end
  else
    WS := '';;
end;

// Need - check
function AnsiStringToByteWideString(const S: AnsiString): TWideString;
var
  B: TBytes;
begin
  Result := '';
  if Length(S) = 0 then
    exit;
  GetBytesOf(S, B);
  Result := UTF8ToWideStr(B);
end;

(*
function MergeLines(Strings : TStrings) : string;
var
  I, L, Size, Count: Integer;
  P: PByte;
  S: string;
begin
  Count := Strings.Count;
  Size := 0;
  for I := 0 to Count - 1 do
    Inc(Size, Length(Strings[I]) + 2);
  SetString(Result, nil, Size);
  P := Pointer(Result);
  for I := 0 to Count - 1 do
  begin
    S := Strings[I];
    L := Length(S);
    if L <> 0 then
    begin
      SBMove(S[StringStartOffset], P^, L);
      Inc(P, L);
    end;
    P^ := 13;
    Inc(P);
    P^ := 10;
    Inc(P);
  end;
end;
*)


//
// End of SBMIMEUtils
// --------------------------------------------------------------------

// --------------------------------------------------------------------
// This came from SBMIMEDateTime
//

const

  MonthStrUpper: array [1..12] of TWideString =
   ( 
    'JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN',
    'JUL',  'AUG', 'SEP', 'OCT', 'NOV', 'DEC'
   ) ;

  DayOfWeekStrUpper: array[0..6]of TWideString =
   ( 
    'SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'
   ) ;


  MonthStr: array [1..12] of TWideString =
   ( 
    'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
    'Jul',  'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
   ) ;

  DayOfWeekStr: array[0..6]of TWideString =
   ( 
    'Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'
   ) ;

  //Days between 1/1/0001 and 12/31/1899
  DateDelta: Integer = 693594;

//  MsecInDay: Double = 24.0 * 60.0 * 60.0 * 1000.0;
//  MsecInHour: Integer = 60 * 60 * 1000;
//  MsecInMinute: Integer = 60 * 1000;
//  SecondsInDay: Integer = 24 * 60 * 60;
//  DaysInYear: Integer = 365;

// Inner - Not tested
function ConvertWideStringMonthToInt(Month: TWideString): Integer;

begin
  Month := UpperCase(Month);
  for Result := 1 to 12 do
  begin
    if Month = MonthStrUpper[Result] then
      exit;
  end;
  Result := 0;
end;

// Inner - Not tested
function GetTimeZoneSufix: string;
var
  LD, SD: TDateTime;
  wHour, wMinute, wSecond, wMilliseconds: Word;
  tzPrefix: string;
begin
  LD := Now;
  SD := LocalDateTimeToSystemDateTime(LD) - LD;
  DecodeTime(SD, wHour, wMinute, wSecond, wMilliseconds);
  if SD < 0 then
    tzPrefix := '-'
  else
    tzPrefix := '+';
  Result := tzPrefix + IntToStrPadLeft(wHour, 2{$ifndef HAS_DEF_PARAMS}, '0' {$endif}) + IntToStrPadLeft(wMinute, 2{$ifndef HAS_DEF_PARAMS}, '0' {$endif});
end;

// Done 7 / XE5(32) / XE5(64) / Android
function UniversalDateTimeToRFC822DateTimeString(DT: TElDateTime): TWideString;
var
  wYear, wMonth, wDayOfWeek, wDay: Word;
  wHour, wMinute, wSecond, wMilliseconds: Word;
begin
  if DT = 0 then
    DT := UTCNow;
  DecodeDate(DT, wYear, wMonth, wDay);
  DecodeTime(DT, wHour, wMinute, wSecond, wMilliseconds);
  wDayOfWeek := DayOfWeek(DT) - 1;
  Result := TWideString(DayOfWeekStr[wDayOfWeek] + ', ' +
    IntToStr(wDay) + ' ' + MonthStr[wMonth]+ ' ' + IntToStrPadLeft(wYear, 4{$ifndef HAS_DEF_PARAMS}, '0' {$endif})+ ' ' +
    IntToStrPadLeft(wHour, 2{$ifndef HAS_DEF_PARAMS}, '0' {$endif}) + ':' +
    IntToStrPadLeft(wMinute, 2{$ifndef HAS_DEF_PARAMS}, '0' {$endif}) + ':' +
    IntToStrPadLeft(wSecond, 2{$ifndef HAS_DEF_PARAMS}, '0' {$endif})) + ' +0000';
end;

// Done 7 / XE5(32) / XE5(64), Need - check in Android
function RFC822TimeStringToUniversalTime(TS: TWideString; var DT: TElDateTime): Boolean;
begin
  Result := ParseRFC822TimeString(TS, DT);
  if Result then
    DT := DT - GetUTCOffsetDateTime();
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function LocalDateTimeToRFC822DateTimeString(ADateTime: TElDateTime): AnsiString;
var
  wYear, wMonth, wDayOfWeek, wDay: Word;
  wHour, wMinute, wSecond, wMilliseconds: Word;
begin
  if ADateTime = 0 then
    ADateTime := Now; // == Local DateTime

  DecodeDate(ADateTime, wYear, wMonth, wDay);
  DecodeTime(ADateTime, wHour, wMinute, wSecond, wMilliseconds);
  wDayOfWeek := ( Trunc(ADateTime) + DateDelta ) mod 7;
  Result := AnsiStringOfString(
    DayOfWeekStr[wDayOfWeek] + ',' +
    ' ' +  IntToStr(wDay)  +
    ' ' + MonthStr[wMonth]+
    ' ' + IntToStrPadLeft(wYear, 4{$ifndef HAS_DEF_PARAMS}, '0' {$endif})+
    ' ' + IntToStrPadLeft(wHour, 2{$ifndef HAS_DEF_PARAMS}, '0' {$endif})+
    ':' + IntToStrPadLeft(wMinute, 2{$ifndef HAS_DEF_PARAMS}, '0' {$endif})+
    ':' + IntToStrPadLeft(wSecond, 2{$ifndef HAS_DEF_PARAMS}, '0' {$endif})  +
    ' ' + GetTimeZoneSufix);
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function SystemDateTimeToRFC822DateTimeString(ADateTime: TElDateTime): AnsiString;
begin
  if ADateTime = 0 then
    ADateTime := Now // == Local DateTime
  else
    ADateTime := SystemDateTimeToLocalDateTime(ADateTime);
  Result := LocalDateTimeToRFC822DateTimeString(ADateTime);
end;
(*
{$ifdef SB_NET}
function StrToIntDef(const S: string; Default: Integer): Integer;
begin
  try
    if Length(S) > 0 then
      Result := Convert.ToInt32(S)
    else
      Result := Default;
  except
    Result := Default;
  end;
end;
{$endif}
*)
	
// Inner - Not tested
function ParseTimeZone(Zone: TWideString; var DateTime:  TDateTime ): Boolean;
var
  sTmp : TWideString;
  wHour: Word;
  iHour, iMinute: Integer;
begin
  DateTime := 0.0;
  Result := False;
  if Length(Zone)=0 then
    exit;

  if (Zone[StringStartOffset] = '+') or (Zone[StringStartOffset] = '-' ) then
  begin
    if (Length(Zone) <> 5) then
      exit;
    sTmp := StringSubstring(Zone, StringStartOffset + 1, 3);
    iHour := StrToIntDef(sTmp, -100);
    if (iHour = -100) then
      exit;
    if iHour < 0 then
      wHour := - iHour
    else
      wHour := iHour;
    sTmp := StringSubstring(Zone, StringStartOffset + 4, 2);
    iMinute := StrToIntDef(sTmp, -100);
    if (iMinute < 0 ) or (iMinute > 59) then
      exit;
    DateTime := EncodeTime(wHour, iMinute, 0, 0);
    if iHour > 0 then
      DateTime := - DateTime;
  end
  else
  begin
    Zone := UpperCase(Zone);
    if (Zone = 'UT')or(Zone = 'GMT') then
      iHour :=  0
    else
    if Zone = 'EST' then
      iHour := -5
    else
    if Zone = 'EDT' then
      iHour := -4
    else
    if Zone = 'CST' then
      iHour := -6
    else
    if Zone = 'CDT' then
      iHour := -5
    else
    if Zone = 'MST' then
      iHour := -7
    else
    if Zone = 'MDT' then
      iHour := -6
    else
    if Zone = 'PST' then
      iHour := -8
    else
    if Zone = 'PDT' then
      iHour := -7
    else
    if Length(Zone)=1 then
    begin
      case Zone[StringStartOffset] of
        'Z':
          iHour := 0;
        'A'..'I':
          iHour := -(Integer(Zone[StringStartOffset]) - Integer('@')); // '@' = 'A' - 1
        'K'..'M':
          iHour := -(Integer(Zone[StringStartOffset]) - Integer('A')); // 'A' = K' - 10
        'N'..'Y':
          iHour := -(Integer(Zone[StringStartOffset]) - Integer('M')); // 'M' = N' - 1
         else
           exit;
      end;
    end
    else
      exit;
    if (iHour < -12) or (iHour > 13) then
    begin
      DateTime := 0.0;
      exit;
    end;

    if iHour < 0 then
      wHour := - iHour
    else
      wHour := iHour;

    DateTime := EncodeTime(wHour, 0, 0, 0);
    if iHour > 0 then
      DateTime := - DateTime;
  end;
  Result := True;
end;


// Done 7 / XE5(32) / XE5(64), Need - check in Android
function ParseRFC822TimeString(RFC822TimeString : TWideString; var ADateTime: TElDateTime): Boolean;
type
  TElDateTimeParserState = (psDayOfWeek, psDay, psMonth, psYear, psHour, psMinute, psSecond, psZone);
var
  wYear, wMonth, wDay: Word;
  wHour, wMinute, wSecond, wMilliseconds: Word;
  parseState: TElDateTimeParserState;
  sAnsi: Char;
  space: Char;
  sTmp: String;
  i: integer;
  bError , bErrorTZ : Boolean;
  timeZone:  TDateTime ;
begin
  ADateTime := EmptyDateTime();
  Result := False;
  RFC822TimeString := StringTrim(RFC822TimeString);

  if Length(RFC822TimeString) = 0 then
    exit;
  wYear := 0;
  wMonth := 0;
  wDay := 0;
  wHour := 0;
  wMinute := 0;
  wSecond := 0;
  wMilliseconds := 0;
  parseState := psDayOfWeek;
  i := StringStartOffset;
  space := #0;
  sTmp := '';
  bError := False;
  while i <= Length(RFC822TimeString) - StringStartInvOffset do
  begin
    sAnsi := Char(RFC822TimeString[i]);
    case parseState of
      psDayOfWeek:
        begin
          {$ifndef SB_UNICODE_VCL}
          if sAnsi in ['0'..'9'] then
           {$else}
          if CharInSet(sAnsi, ['0'..'9']) then // DeN 25.12.2013
           {$endif}
          begin
            dec(i);
            parseState := psDay;
          end;
        end;
      psDay,
      psYear:
        begin
          if (sAnsi = ' '{SPACE}) or (sAnsi = Char(9) {TAB}) then
            space := sAnsi
          else
          begin
            if space <> Char(0) then
            begin
              dec(i);
              if (parseState = psDay) then
              begin
                parseState := psMonth;
                wDay := StrToIntDef(sTmp, 0);
                if (wDay < 1) or (wDay > 31) then
                begin
                  bError := True;
                  wDay := 1;
                end;
              end
              else
              begin
                parseState := psHour;
                wYear := StrToIntDef(sTmp, 0);
                if (wYear < 1901) or (wYear > 10000) then
                begin
                  bError := True;
                  wYear := 0;
                end;
              end;
              space := #0;
              sTmp := '';
            end
            else
            begin
              sTmp := sTmp + sAnsi;
            end;
          end;
        end;
      psMonth:
        begin
          {$ifndef SB_UNICODE_VCL}
          if sAnsi in ['0'..'9'] then
           {$else}
          if CharInSet(sAnsi, ['0'..'9']) then // DeN 25.12.2013
           {$endif}
          begin
            dec(i);
            parseState := psYear;
            sTmp := StringTrim(sTmp);
            wMonth := ConvertWideStringMonthToInt(sTmp);
            ReleaseString(sTmp);
            if wMonth = 0 then
            begin
              bError := True;
              wMonth := 1;
            end;
          end
          else
          begin
            sTmp := sTmp + sAnsi;
          end;
        end;
      psHour,
      psMinute,
      psSecond:
        begin
          if (sAnsi = ' '{SPACE}) or
             (sAnsi = Char(9) {TAB}) or (sAnsi = ':' {TAB}) then
            space := sAnsi
          else
          begin
            if space <> #0 then
            begin
              dec(i);
              case parseState of
                psHour:
                  begin
                    parseState := psMinute;
                    wHour := Word(StrToIntDef(sTmp, 24));
                    if {(wHour < 0) or} (wHour > 23) then
                    begin
                      bError := True;
                      wHour := 0;
                    end;
                  end;
                psMinute:
                  begin
                    if space = ':' then
                      parseState := psSecond
                    else
                      parseState := psZone;
                    wMinute := Word(StrToIntDef(sTmp, 60));
                    if {(wMinute < 0) or} (wMinute > 59) then
                    begin
                      bError := True;
                      wMinute := 0;
                    end;
                  end;
                else //psSecond:
                  begin
                    parseState := psZone;
                    wSecond := Word(StrToIntDef(sTmp, 0));
                    if {(wSecond < 0) or} (wSecond > 59) then
                    begin
                      bError := True;
                      wSecond := 2000;
                    end;
                  end;
              end; // case
              space := #0;
              SetLength(sTmp, 0);
            end // if
            else
            begin
              sTmp := sTmp  + sAnsi;
            end; // if / else
          end; // if / else
        end;
      psZone:
        begin
          if (sAnsi = ' '{SPACE}) or (sAnsi = Char(9) {TAB}) then
            // skip
          else
            sTmp := sTmp + sAnsi;
        end;
    end;
    //goto next char
    inc(i);
  end; // while

  timeZone := 0.0;
   bErrorTZ := not   ParseTimeZone(sTmp, timeZone);
  if (parseState <> psZone) then
    bError := True;

  if (not bError) or (wYear <> 0) then
  begin
    ADateTime := // debug: DateTimeToStr(DateTime)
      EncodeDate(wYear, wMonth, wDay) +
      EncodeTime(wHour, wMinute, wSecond, wMilliseconds);
    //add time zone offset               //???
    if bErrorTZ then
      timeZone := 0.0;
    ADateTime  := ADateTime + timeZone + GetUTCOffsetDateTime;
    Result := True;
  end
  else
  begin
    ADateTime := Now;
    Result := False;
  end;
  //Result := (not bError) and (not bErrorTZ);
end;

//
// End of SBMIMEDateTime
// --------------------------------------------------------------------

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function SBConcatAnsiStrings(Str1 : AnsiString; Str2 : AnsiChar) : AnsiString;
begin
  {$ifdef SB_PASCAL_STRINGS}
  result := Str1 + Str2;
   {$else}
  Result := SBConcatArrays(Str1, Str2);
   {$endif}
end;
  
// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function SBConcatAnsiStrings(Str1, Str2 : AnsiString) : AnsiString;
begin
  {$ifdef SB_PASCAL_STRINGS}
  result := Str1 + Str2;
   {$else}
  Result := SBConcatArrays(Str1, Str2);
   {$endif}
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SBConcatAnsiStrings(const Strs : array of AnsiString): AnsiString;
{$ifdef SB_PASCAL_STRINGS}
var i : integer;
 {$endif}
begin
  SetLength(Result, 0);
  {$ifdef SB_PASCAL_STRINGS}
  for i := 0 to Length(Strs) - 1 do
    result := result + Strs[i];
   {$else}
  Result := SBConcatMultipleArrays(Strs);
   {$endif}
end;

// Done 7
function AnsiStrPas(P: PAnsiChar) : AnsiString;
{$ifndef SB_ANSI_VCL}
var
  l : integer;
  PC : PAnsiChar;
 {$endif}
begin
  {$ifdef SB_ANSI_VCL}
  result := StrPas(P);
   {$else}
  PC := P;
  l := 0;
  while (PC <> nil) and // DeN 13.12.2013
        (PC^ <> AnsiChar(0)) do
  begin
    inc(PC);
    inc(l);
  end;
  SetLength(Result, l);
  SBMove(P^, Result[AnsiStrStartOffset], l);
   {$endif}
end;


end.
