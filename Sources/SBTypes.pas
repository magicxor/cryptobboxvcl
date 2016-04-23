(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBTypes;

interface

uses
  {$ifdef D_6_UP}
  Types,
   {$endif}
  SysUtils,
  Classes


  ;



const

  MaxArrSize = $7FFFFFFF;

type

  {$ifndef D_12_UP}
  UnicodeString = WideString;
  PUnicodeString = PWideString;
   {$endif}



  ByteArray = array of byte;

  LongWordArray =  array of LongWord;
  WordArray =  array of word;
  CharArray =  array of char;
  {$ifndef SB_UNICODE_VCL}
  WideCharArray =  array of WideChar;
   {$else}
  WideCharArray = CharArray;
   {$endif}

  IntegerArray = array of integer;
  Int64Array = array of Int64;
  ArrayOfByteArray = array of ByteArray;

  BooleanArray =  array of Boolean;
  StringArray =  array of string;
  {$ifndef SB_UNICODE_VCL}
  WideStringArray =  array of UnicodeString;
   {$else}
  WideStringArray = StringArray;
   {$endif}


  UTF32 =  Longword;
  UTF16 =  Word;
  UTF8  =  Byte;

  pUTF32 = ^UTF32;
  pUTF16 = ^UTF16;
  pUTF8  = ^UTF8;

  TElInputStream =    TStream  ;
  TElOutputStream =    TStream  ;

  TElDateTime = TDateTime;


  {$ifdef DELPHI_MAC}
  u_short = Word;
  TSocket = integer;
   {$endif}



  TByteArray =  array[0..MaxArrSize shr 1] of byte;
  // PByteArray = ^TByteArray;

  TWordArray =  array[0..MaxArrSize shr 2] of word;
  // PWordArray = ^TWordArray;

  TLongWordArray =  array[0..MaxArrSize shr 3] of longword;
  PLongWordArray = ^TLongWordArray;

  TInt64Array =  array[0..MaxArrSize shr 4] of int64;
  PInt64Array = ^TInt64Array;

  TAnsiCharArray = array of AnsiChar;
  TBytes = ByteArray;
  TWideString = UnicodeString;
  TWideChar = WideChar;

  {$EXTERNALSYM WCHAR}
  WCHAR =  WideChar;

  {$EXTERNALSYM DWORD}
  DWORD =  LongWord;

  {$EXTERNALSYM BOOL}
  BOOL = LongBool;

  {$EXTERNALSYM UCHAR}
  UCHAR =  Byte;

  {$EXTERNALSYM SHORT}
  SHORT =  Smallint;


  {$EXTERNALSYM UINT}
  UINT =  Cardinal;

  {$EXTERNALSYM ULONG}
  ULONG =  LongWord;

  {$EXTERNALSYM LCID}
  LCID =  DWORD;

  {$EXTERNALSYM LANGID}
  LANGID =  Word;

  TSBHostRole =  (hrNone, hrServer, hrClient, hrBoth);

  {$ifdef SB_CPU32}
  THandle = cardinal;
  HModule = THandle;
   {$endif}
  {$ifdef SB_CPU64}
  THandle = UInt64;
  HModule = THandle;
   {$endif}

  {$ifdef SB_POSIX}
type
  {$ifndef SB_WINDOWS}
  {$ifdef FPC}
  _FILETIME = record
    dwLowDateTime: DWORD;
    dwHighDateTime: DWORD;
  end;
  FILETIME = _FILETIME;
   {$endif}
   {$else}
  {$ifdef SB_FPC_GEN} // for FPC 2.4
  _FILETIME = record
    dwLowDateTime: DWORD;
    dwHighDateTime: DWORD;
  end;
  FILETIME = _FILETIME;
   {$endif}
   {$endif}
  TFileTime = _FILETIME;
  PFileTime = ^TFileTime;

  LONG = longint;
  LONGLONG = Int64;
  _LARGE_INTEGER = record
    case Integer of
    0 : (
      LowPart : DWORD;
      HighPart : LONG);
    1 : (
      QuadPart : LONGLONG);
  end;
  LARGE_INTEGER = _LARGE_INTEGER;

  _ULARGE_INTEGER = record
    case Integer of
    0 : (
      LowPart : DWORD;
      HighPart : DWORD);
    1 : (
      QuadPart : LONGLONG);
  end;
  ULARGE_INTEGER = _ULARGE_INTEGER;
   {$endif}
  

  {$ifndef VCL60}
  PByte = ^Byte;
  PBoolean = ^Boolean;
   {$endif}
  PWord = ^Word;
  PInt  = ^Integer;
  PLongWord = ^LongWord;
  PLongint = ^Longint;
  PInt64 = ^Int64;
  PCardinal = ^cardinal;
  PPointer = ^pointer;

  TSBFileTransferMode =  (ftmOverwrite, ftmSkip, ftmAppendToEnd, ftmResume, ftmOverwriteIfDiffSize{, ftmOverwriteIfNewer, ftmOverwriteIfNewerOrDiffSize});

  TSBFileCopyMode =  (fcmCopy, fcmCopyAndDeleteImmediate, fcmCopyAndDeleteOnCompletion);

  TSBParamQuoteMode =  (pqmNone, pqmWithSpace, pqmAll);

  TSBEOLMarker = 
    (emCRLF, emCR, emLF, emNone);

  // we define PtrInt and PtrUInt for easier porting to 64-bit platforms, starting from FreePascal
  {$ifdef SB_CPU32}
  {$ifndef FPC}
  PtrInt  =  LongInt;
  PtrUInt =  LongWord;
   {$endif}
   {$endif}

  {$ifndef FPC}
  QWord = {$ifdef D_7_UP}UInt64 {$else}Int64 {$endif};
   {$endif}

  {$ifdef SB_CPU64}
  {$ifndef FPC}
  PtrInt  =  Int64;
  PtrUInt =  {$ifdef FPC}QWord {$else}{$ifdef D_6_UP}UInt64 {$else}Int64 {$endif} {$endif};
   {$endif}
   {$endif}


  TPtrHandle =  THandle;
  TPtrHandle64 = Int64;

  TSBCaseConversion =  (sccNone, sccLower, sccUpper);

  TSBOperationErrorHandling =  (oehTryAllItems,
    oehStopOnFailure, oehIgnoreErrors);


  TMessageDigest128 =  packed   record
    A, B, C, D: longword;
  end;

  TMessageDigest160 =  packed   record
    A, B, C, D, E: longword;
  end;

  TMessageDigest224 =  packed   record
    A1, B1, C1, D1: longword;
    A2, B2, C2: longword;
  end;

  TMessageDigest256 =  packed   record
    A1, B1, C1, D1: longword;
    A2, B2, C2, D2: longword;
  end;

  TMessageDigest320 =  packed   record
    A1, B1, C1, D1, E1: longword;
    A2, B2, C2, D2, E2: longword;
  end;

  TMessageDigest384 =  packed   record
    A, B, C, D, E, F: int64;
  end;

  TMessageDigest512 =  packed   record
    A1, B1, C1, D1: int64;
    A2, B2, C2, D2: int64;
  end;

  TSBLongwordPair =  record
    A, B : longword;
  end;

  TSBArrayOfPairs =  array of TSBLongwordPair;
  PSBArrayOfPairs = ^TSBArrayOfPairs;

type
  TSBInteger =  integer;
  TSBLong =  int64;
  TSBString =  string;
  TSBObject =  TObject;

type
  TElStringHolder = class
  private
    FValue : string;
  public
    constructor Create(const Data : string);
    property Value : string read FValue write FValue;
  end;

  TElByteArrayHolder = class
  private
    FValue : ByteArray;
  public
    constructor Create(const Data : ByteArray);
    property Value : ByteArray read FValue write FValue;
  end;

type

  ConversionResult =  (
    conversionOK,       { conversion successful }
    sourceExhausted,    { partial character in source, but hit end }
    targetExhausted,    { insuff. room in target for conversion }
    sourceIllegal       { source sequence is illegal/malformed }
  );



type

  ConversionFlags = 
    (strictConversion, lenientConversion ); { strictConversion = 0 }

implementation




{ TElStringHolder }

constructor TElStringHolder.Create(const Data : string);
begin
  inherited Create;

  FValue := Data;
end;

{ TElByteArrayHolder }

constructor TElByteArrayHolder.Create(const Data : ByteArray);
begin
  inherited Create;

  FValue := Data;
end;


end.
 
