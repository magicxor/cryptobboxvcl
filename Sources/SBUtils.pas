(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)
{$I SecBbox.inc}
{$ifdef FPC}
{$ifdef MACOS}
{$modeswitch objectivec1}
{$define SB_NO_IPHONEALL}
 {$endif}
 {$endif}





{$define SB_SUPPRESS_NAGSCREEN}

unit
  SBUtils;

interface

uses
  SBTypes,
  SBConstants,

  {$ifdef D_6_UP}
  {$ifndef FPC}
  Types,
   {$endif}
   {$endif}
  SysUtils,
  Classes,

  {$ifdef SB_WINDOWS}
  Windows,
   {$else}
  {$ifdef SB_MACOS}
  {$ifndef FPC}
  Posix.Base,
  Posix.PThread,
   {$else}
  {$ifndef SB_iOS}
  CocoaAll,
   {$else}
  {$ifndef SB_NO_IPHONEALL}
  iPhoneAll,
   {$endif}
   {$endif SB_iOS}
   {$endif FPC}
   {$endif SB_MACOS}
  
  {$ifdef SB_ANDROID}
  {$ifndef FPC}
  Posix.Base,
  Posix.Fcntl,
  Posix.SysTime,
  Posix.SysTimes,
  Posix.SysTypes,
  Posix.Time,
   {$endif}
   {$endif SB_ANDROID}

   {$endif SB_WINDOWS}



    {$ifdef KYLIX_USED}
     {$endif}

    SyncObjs,
    {$ifdef VCL60}
    DateUtils,
     {$endif}
    {$ifdef SB_MACOS}
      {$ifndef FPC}
      // Delphi for MacOS X
      Posix.SysTime,
      Posix.Time,
      Posix.SysSysctl,
       {$else}
      ctypes,
      baseunix,
      sysctl,
      //unixutil,
      //dateutils,
       {$endif}
     {$endif}
    {$ifdef SB_UNIX}
      {$ifdef FPC}
      unix,
      unixutil,
      unixtype,
      {$ifdef SB_LINUX}
      {$ifndef SB_ANDROID}
      pthreads,
       {$endif}
      linux,
       {$endif}
       {$endif}
     {$endif}
  SBMath
  ;


const

  SBB_VERSION_NUMBER = '12.0.258.0';

  SBB_HOMEPAGE = 'https://www.eldos.com/SecureBlackbox/';
  

//  BufferSize = 1023;

type

  {$ifdef SB_NO_BOOLEAN_VAR_PARAMS}
  TSBBoolean = class;
   {$else}
  TSBBoolean =  boolean;
   {$endif}
  


  TSBComponentBase = {$ifndef SB_NO_COMPONENT}TComponent {$else}TPersistent {$endif};
  TSBControlBase = {$ifndef SB_NO_COMPONENT}TComponent {$else}TPersistent {$endif};
  TSBDisposableBase = TObject;

  {$ifdef SB_NO_NET_ARRAYLIST}
  ArrayListEnumerator = public class(IEnumerator)
  assembly or protected
    FList : ArrayList;
    FIndex : Integer;
  protected
    function GetCurrent : Object;
  public
    constructor Create(List : ArrayList);
    procedure Reset;
    function MoveNext : boolean;
    property Current : Object read GetCurrent;
  end;

  ArrayList = public class(IList, ICollection, IEnumerable)
  private
    FList : List<Object>;
    FSynchronized : Boolean;
  protected
    function GetReadOnly : Boolean;
    function GetFixedSize : Boolean;
    function GetSynchronized : Boolean;
    function GetCapacity : Int32;
    procedure SetCapacity(Value : Int32);
  public
    constructor Create;
    constructor Create(Source : ICollection);
    constructor Create(Capacity : Int32);

    function Add(Value: System.Object): Int32; virtual;
    procedure AddRange(C : ICollection); virtual;
    function Contains(value: System.Object): Boolean; virtual;
    procedure Clear; virtual;
    function Clone : System.Object; virtual;

    function GetRange(Index, Count: System.Int32) : ArrayList; virtual;

    function IndexOf(value: System.Object): System.Int32; virtual;
    function IndexOf(value: System.Object; StartIndex : Int32): System.Int32; virtual;
    function IndexOf(value: System.Object; StartIndex, Count : Int32): System.Int32; virtual;

    procedure Insert(index: System.Int32; value: System.Object); virtual;
    procedure InsertRange(Index : Int32; C : ICollection); virtual;

    function LastIndexOf(value: System.Object): System.Int32; virtual;
    function LastIndexOf(value: System.Object; StartIndex : Int32): System.Int32; virtual;
    function LastIndexOf(value: System.Object; StartIndex, Count : Int32): System.Int32; virtual;

    procedure Remove(value: System.Object); virtual;
    procedure RemoveAt(index: System.Int32); virtual;
    procedure RemoveRange(Index, Count: System.Int32); virtual;
    procedure Reverse; virtual;
    procedure Reverse(Index, Count: System.Int32); virtual;

    procedure Sort; virtual;
    procedure Sort(Comparer : IComparer); virtual;
    procedure Sort<T>(Comparer : IComparer<T>); virtual;
    procedure Sort(Index, Count : integer; Comparer : IComparer); virtual;
    procedure Sort<T>(Index, Count : integer; Comparer : IComparer<T>); virtual;

    function GetEnumerator: IEnumerator; virtual;
    procedure CopyTo(AnArray: Array); virtual;
    procedure CopyTo(AnArray: Array; index: System.Int32); virtual;
    procedure CopyTo(Index : Int32; AnArray: Array; ArrayIndex: Int32; aCount : Int32); virtual;

    property Capacity : Int32 read GetCapacity write SetCapacity;
    property Item[index : Int32] : System.Object read FList.Item[Index] write FList.Item[index]; default;
    property IsReadOnly : Boolean read GetReadOnly;
    property IsFixedSize : Boolean read GetFixedSize;
    property Count : Int32 read FList.Count;
    property SyncRoot : System.Object;
    property IsSynchronized : Boolean read GetSynchronized;
  end;
   {$endif}


  TElList =    TList;  

  TElIntegerList =    TElList;  

  {$ifdef SB_WINDOWS}
  TElStringList = TStringList;
   {$else}
  TElStringList = class(TStringList)
  public
    constructor Create;
  end;
   {$endif}


  PByteArrayItem = ^TByteArrays;
  TByteArrays = array[0..MaxListSize] of ByteArray;

  TElByteArrayList =  class
  protected
    FList: array of ByteArray;
    FCount: integer;

    procedure BMove(const Src: array of ByteArray; SrcOffset: Integer;
      var Dst: array of ByteArray; DstOffset: Integer; Size: Integer);
    function GetItem(Index: integer): ByteArray;
    procedure SetItem(Index: integer; const Value: ByteArray);
    procedure SetCapacity(NewCapacity: Integer);
    function GetCapacity : integer;
    function GetCount : integer;
  public
    constructor Create;
    destructor Destroy; override;
    function Add(const S: ByteArray): Integer;
    procedure AddRange(List: TElByteArrayList);
    procedure Assign(Source: TElByteArrayList);
    procedure Clear;
    procedure Delete(Index: Integer);
    function IndexOf(const S: ByteArray): Integer;
    procedure Insert(Index: Integer; const S: ByteArray);

    property Capacity: Integer read GetCapacity write SetCapacity;
    property Count: Integer read GetCount;

    property Item[Index: Integer]: ByteArray read GetItem write SetItem;
  end;


  TSBTextDataEvent =  procedure(Sender : TObject;
    const TextLine : ByteArray) of object;

  TSBProgressEvent =  procedure(
    Sender : TObject;
    Total, Current : Int64; var Cancel : TSBBoolean) of object;
  
  TSBProgressFunc =  procedure(
    Total, Current : Int64; Data :  pointer ;
    var Cancel : TSBBoolean) of object;

  TElMessageLoopEvent =  function: boolean of object;


  ESecureBlackboxError = class (Exception)
  protected
    FErrorCode : Integer;
    FSupplErrorCode : Integer;
  public
    // constructor without an error code should not be used
    constructor Create(const AMessage: string);  overload; 

    constructor Create(AErrorCode : Integer; const AMessage : string);  overload; 
    constructor Create(AErrorCode : Integer; ASupplErrorCode : Integer; const AMessage : string);  overload; 

    constructor Create(AErrorCode : Integer; const AMessage : string;
      AInsertErrorCodeToMessage : Boolean);  overload; 
    constructor Create(AErrorCode : Integer; const AMessageFormat : string;
      const Param1 : string);  overload; 
    constructor Create(AErrorCode : Integer; const AMessageFormat : string;
      Param1 : Integer);  overload; 
    constructor Create(AErrorCode : Integer; const AMessageFormat : string;
      const Param1 : string; Param2 : Integer);  overload; 
    constructor Create(AErrorCode : Integer; const AMessageFormat : string;
      Param1 : Integer; const Param2 : string);  overload; 
    constructor Create(AErrorCode : Integer; const AMessageFormat : string;
      Param1 : Integer; Param2 : Integer);  overload; 
    constructor Create(AErrorCode : Integer; const AMessageFormat : string;
      const Param1 : string; const Param2 : string);  overload; 
      
    constructor Create(AErrorCode : Integer; ASupplErrorCode : Integer; const AMessageFormat : string;
      const Param1 : string);  overload; 
    constructor Create(AErrorCode : Integer; ASupplErrorCode : Integer; const AMessageFormat : string;
      Param1 : Integer);  overload; 
    constructor Create(AErrorCode : Integer; ASupplErrorCode : Integer; const AMessageFormat : string;
      Param1 : Integer; Param2 : Integer);  overload; 

    // old constructors, should be removed
    constructor Create(const Message: string; Code: Integer {$ifndef FPC}; Fake: integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif} {$endif});  overload; 
    constructor Create(const Message: string; Code: Integer; InsertCodeToErrorMessage : boolean{$ifndef FPC}; Fake: integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif} {$endif});  overload; 

    property ErrorCode : Integer read FErrorCode;
    property SupplErrorCode : Integer read FSupplErrorCode;

  end;

  {$ifdef SB_WINRT}
  Win32Exception = public class (ESecureBlackboxError)
  public
    constructor Create(Win32ErrorCode : Integer);
    constructor Create(ErrorCode : Integer; Win32ErrorCode : Integer);
  end;
   {$endif}

  EElLicenseError =  class(ESecureBlackboxError);

  EElEncryptionError  =  class(ESecureBlackboxError);

  EElCertificateError =  class(ESecureBlackboxError);
  //EElCertStorageError = {$ifdef SB_NET}public{$endif} class(ESecureBlackboxError);
  EElOIDError =  class(ESecureBlackboxError);
  //EElDuplicateCertError = {$ifdef SB_NET}public{$endif} class(EElCertStorageError);
  //EElCertNotFoundError = {$ifdef SB_NET}public{$endif} class(EElCertStorageError);
  EElUnicodeError =  class(ESecureBlackboxError);

  EElOperationCancelledError =  class(ESecureBlackboxError);



// Converting functions
function DigestToStr(const Digest: TMessageDigest128;
  LowerCase: boolean = true): string; overload;
function DigestToStr(const Digest: TMessageDigest160;
  LowerCase: boolean = true): string; overload;
function DigestToStr(const Digest: TMessageDigest224;
  LowerCase: boolean = true): string; overload;
function DigestToStr(const Digest: TMessageDigest256;
  LowerCase: boolean = true): string; overload;
function DigestToStr(const Digest: TMessageDigest320;
  LowerCase: boolean = true): string; overload;
function DigestToStr(const Digest: TMessageDigest384;
  LowerCase: boolean = true): string; overload;
function DigestToStr(const Digest: TMessageDigest512;
  LowerCase: boolean = true): string; overload;
function StrToDigest(const DigestStr : string;
  var Digest : TMessageDigest128) : boolean; overload;
function StrToDigest(const DigestStr : string;
  var Digest : TMessageDigest160) : boolean; overload;

function DigestToBinary(const Digest : TMessageDigest128) : ByteArray; overload;
function DigestToBinary(const Digest : TMessageDigest160) : ByteArray; overload;
function BinaryToDigest(const Binary : ByteArray; var Digest : TMessageDigest128) : boolean; overload;
function BinaryToDigest(const Binary : ByteArray; var Digest : TMessageDigest160) : boolean; overload;

function DigestToByteArray128(const Digest : TMessageDigest128) : ByteArray; 
function DigestToByteArray160(const Digest : TMessageDigest160) : ByteArray; 
function DigestToByteArray224(const Digest : TMessageDigest224) : ByteArray; 
function DigestToByteArray256(const Digest : TMessageDigest256) : ByteArray; 
function DigestToByteArray320(const Digest : TMessageDigest320) : ByteArray; 
function DigestToByteArray384(const Digest : TMessageDigest384) : ByteArray; 
function DigestToByteArray512(const Digest : TMessageDigest512) : ByteArray; 

function ByteArrayToDigest128(const Binary : ByteArray; Position : integer; var Digest : TMessageDigest128) : boolean; 
function ByteArrayToDigest160(const Binary : ByteArray; Position : integer; var Digest : TMessageDigest160) : boolean; 
function ByteArrayToDigest224(const Binary : ByteArray; Position : integer; var Digest : TMessageDigest224) : boolean; 
function ByteArrayToDigest256(const Binary : ByteArray; Position : integer; var Digest : TMessageDigest256) : boolean; 
function ByteArrayToDigest320(const Binary : ByteArray; Position : integer; var Digest : TMessageDigest320) : boolean; 
function ByteArrayToDigest384(const Binary : ByteArray; Position : integer; var Digest : TMessageDigest384) : boolean; 
function ByteArrayToDigest512(const Binary : ByteArray; Position : integer; var Digest : TMessageDigest512) : boolean; 

{$ifndef FPC}
{$ifndef DELPHI_MAC}
function IsValidVCLObject(Obj: pointer): boolean;
 {$endif}
 {$endif}

procedure PointerToLIntP(var B: PLint; P: Pointer; Size: LongInt); overload;
procedure PointerToLInt(var B: PLint; const P : ByteArray; Size: LongInt); overload;

procedure LIntToPointerP(B: PLInt; P: Pointer; var Size: LongInt); overload;
procedure LIntToPointer(B: PLInt; P: ByteArray; var Size: LongInt); overload;
procedure LIntToPointerTrunc(B: PLInt; P: pointer; var Size: longint);
function BufferBitCount(Buffer : pointer; Size : integer) : integer;

function BeautifyBinaryString(const Str : string; Separator : Char): string; 

procedure SwapUInt16(Value: Word; var Buffer: ByteArray);  overload ;
procedure SwapUInt16(Value: Word; var Buffer: ByteArray; var Index: Integer);  overload ;
function SwapUInt16(const Buffer: ByteArray; Offset: Cardinal {$ifdef HAS_DEF_PARAMS} =  0 {$endif}): Word;  overload ;
function SwapInt32(value : integer) : integer; 
procedure SwapUInt32(Value: LongWord; var Buffer: ByteArray);  overload ;
procedure SwapUInt32(Value: LongWord; var Buffer: ByteArray; var Index: Integer);  overload ;
function SwapUInt32(const Buffer: ByteArray; Offset: Cardinal {$ifdef HAS_DEF_PARAMS} =  0 {$endif}): Cardinal;  overload ;
function SwapUInt32(value : LongWord) : LongWord;  overload ;
function SwapInt64(value : Int64) : Int64; function SwapSomeInt(Value : integer) : ByteArray; 
function RotateInteger(const Value: ByteArray) : ByteArray; 
function TrimZeros(const Value : ByteArray): ByteArray;  overload; function ZeroArray(Size : integer) : ByteArray; 
function SubArray(const Arr:  ByteArray ; Index, Size : integer) : ByteArray; 


procedure SwapBigEndianWords(P: Pointer; Size: LongInt);
procedure SwapBigEndianDWords(P: Pointer; Size: LongInt);
// Mathematical routines
function Min(const A, B: integer): integer; overload;

function Min(const A, B: cardinal): cardinal;  overload; function Min(const A, B: Int64): Int64;  overload;    // in D6, D7, 8 "TStream.Size" declared as "Int64".

function Max(const A, B: integer): integer; overload;
function Max(const A, B: cardinal): cardinal;  overload; function Max(const A, B: Int64): Int64;  overload;   // in D6, D7, 8 "TStream.Size" declared as "Int64".

function IsEmptyDateTime(DT : TElDateTime) : boolean; 
function EmptyDateTime(): TElDateTime; 

procedure SBMove(const SourcePointer; var DestinationPointer; CopyCount : Integer); overload;
procedure SBMove(Src: ByteArray; SrcOffset: Integer; Dst: ByteArray; DstOffset: Integer; Size: Integer);  overload;  

function TrimLeadingZeros(const V : ByteArray): ByteArray;  overload; 
function PrefixByteArray(Buffer : ByteArray; Count : integer; Value : Byte) : ByteArray;  overload; 
function SuffixByteArray(Buffer : ByteArray; Count : integer; Value : Byte) : ByteArray;  overload; 
procedure FillByteArray(Buffer : ByteArray; SrcOffset : integer; Count : integer; Value : byte);  overload; procedure FillByteArray(Buffer : ByteArray; Value : byte);  overload; 





function GetBytes64(const X : Int64) : ByteArray;   overload; function GetBytes32(const X : Longword) : ByteArray;   overload; function GetBytes16(const X : Word) : ByteArray;   overload; function GetBytes8(const X : Byte) : ByteArray;   overload; 
procedure GetBytes64(const X : Int64; var Buffer : ByteArray; Index : integer);   overload; procedure GetBytes32(const X : Longword; var Buffer : ByteArray; Index : integer);   overload; procedure GetBytes16(const X : Word; var Buffer : ByteArray; Index : integer);   overload; procedure GetBytes8(const X : Byte; var Buffer : ByteArray; Index : integer);   overload; 


(*
{$ifdef SB_VCL}
{$ifdef SB_UNICODE_VCL}
// Delphi 12 doesn't have a built-in FillChar
procedure FillChar(var V; Count : integer; Value : byte);
{$endif}
{$endif}
*)

function LocalDateTimeToSystemDateTime(ADateTime: TElDateTime): TElDateTime;
function SystemDateTimeToLocalDateTime(ADateTime: TElDateTime): TElDateTime;

// returns date and time increased by Days number
function DateTimeAddDays(DateTime: TElDateTime; Days: Integer): TElDateTime; 
// returns date and time increased by Hours number
function DateTimeAddHours(DateTime: TElDateTime; Hours: Integer): TElDateTime; 
// returns date and time increased by Minutes number
function DateTimeAddMinutes(DateTime: TElDateTime; Minutes: Integer): TElDateTime; 
// returns date and time increased by Months number
// !!! NOT IMPLEMENTED !!!
//function DateTimeAddMonths(DateTime: TElDateTime; Months: Integer): TElDateTime; {$ifdef SB_NET}public;{$endif}
// returns date and time increased by Seconds number
function DateTimeAddSeconds(DateTime: TElDateTime; Seconds: Integer): TElDateTime; 
// returns date and time increased by Years number
function DateTimeAddYears(DateTime: TElDateTime; Years: Integer): TElDateTime; 
// returns True if DT1 is after DT2
function DateTimeAfter(DT1, DT2: TElDateTime): Boolean; 
// returns True if DT1 if before DT2
function DateTimeBefore(DT1, DT2: TElDateTime): Boolean; 
// returns a copy of date and time
function DateTimeClone(DateTime: TElDateTime): TElDateTime; 
// returns -1 if DT1 < DT2; 1 if DT1 > DT2; 0 if they equal
function DateTimeCompare(DT1, DT2: TElDateTime): Integer; 
// returns True if the dates equal
function DateTimeEquals(DT1, DT2: TElDateTime): Boolean; 
// returns current local date and time
function DateTimeNow(): TElDateTime; 
// returns current UTC date and time
function DateTimeUtcNow(): TElDateTime; 

function CompareMem(const Mem1:  ByteArray ; const Mem2:  ByteArray ) : Boolean;  overload; function CompareMem(const Mem1:  ByteArray ; Offset1 : integer; const Mem2:  ByteArray ; Offset2 : integer) : Boolean;  overload; function CompareMem(const Mem1:  ByteArray ; Offset1 : integer; const Mem2:  ByteArray ; Offset2 : integer; Size : integer) : Boolean;  overload; 

function CompareMem(const Mem1: Pointer; const Mem2: Pointer; Size : integer): Boolean;  overload;


function CompareBuffers(const Buf1, Buf2 : ByteArray) : integer;

function CompareMD128(const M1, M2: TMessageDigest128): boolean; 
function CompareMD160(const M1, M2: TMessageDigest160): boolean; 
function CompareMD224(const M1, M2: TMessageDigest224): boolean; 
function CompareMD256(const M1, M2: TMessageDigest256): boolean; 
function CompareMD320(const M1, M2: TMessageDigest320): boolean; 
function CompareMD384(const M1, M2: TMessageDigest384): boolean; 
function CompareMD512(const M1, M2: TMessageDigest512): boolean; 

function CompareHashes(const Hash1, Hash2 : ByteArray): boolean;  overload; 
function CompareHashes(const Hash1 : ByteArray; StartIndex1 : integer; Count1 : integer;
  const Hash2 : ByteArray; StartIndex2 : integer; Count2 : integer): boolean;  overload; 

procedure FreeAndNil(var Obj); 

function GetDigestSizeBits(Algorithm : integer) : integer; 

function EncodeDSASignature(R : pointer; RSize : integer; S : pointer; SSize :
  integer; Blob: pointer; var BlobSize : integer) : boolean;
function DecodeDSASignature(Blob : pointer; Size : integer; R : pointer;
  var RSize : integer; S : pointer; var SSize : integer) : boolean;

function CompareAnsiStr(const Content, OID : AnsiString) : boolean; 


function ChangeByteOrder(const Buffer : ByteArray): ByteArray; 
function BinaryToString(const Buffer : ByteArray): string;  overload;  
function BinaryToString(const Buffer : ByteArray; Start, Count : integer): string;  overload;  

function BinaryToString(Buffer : Pointer; BufSize : integer): string; overload;

function StringToBinary(const S: string; Buffer : pointer; var Size: integer) : boolean;

function CompareGUID(const Guid1, Guid2 : TGUID) : boolean;

(*
function GetByteArrayFromByte(const AStr: Char): ByteArray;
function GetByteArrayFromByte(const Value: Byte): ByteArray;
*)

function AnsiStringOfBytes(const Src : ByteArray) : AnsiString;


function ArrayStartsWith(const SubP, P : ByteArray) : boolean;

function CompareArrays(const Buf1, Buf2 : ByteArray) : integer;


function StringOfBytes(const Src : ByteArray) : string; overload;
function StringOfBytes(const Src: ByteArray; ALow: Integer; ALen: integer): string; overload;
function BytesOfString(const Str : string) : ByteArray; overload;

function CreateByteArrayConst(const Src : {$ifndef SB_PASCAL_STRINGS}string {$else}AnsiString {$endif}): ByteArray; 

function AnsiStringOfString(const Str : string) : AnsiString; 
function StringOfAnsiString(const Str : AnsiString) : String; 

function BytesOfAnsiString(const Str : AnsiString) : ByteArray; 

function GetByteArrayFromByte(Value : Byte) : ByteArray;  overload; 
procedure GetByteArrayFromByte(Value : Byte; Dest : ByteArray; Position : integer);  overload; 

function GetByteArrayFromWordLE(Value : Word) : ByteArray;  overload; 
procedure GetByteArrayFromWordLE(Value : Word; Dest : ByteArray; Position : integer);  overload; 

function GetByteArrayFromWordBE(Value : Word) : ByteArray;  overload; 
procedure GetByteArrayFromWordBE(Value : Word; Dest : ByteArray; Position : integer);  overload; 

function GetByteArrayFromDWordLE(Value: cardinal) : ByteArray;  overload; 
procedure GetByteArrayFromDWordLE(Value : Cardinal; Dest : ByteArray; Position : integer);  overload; 

function GetByteArrayFromDWordBE(Value: cardinal) : ByteArray;  overload; 
procedure GetByteArrayFromDWordBE(Value : Cardinal; Dest : ByteArray; Position : integer);  overload; 

function GetByteArrayFromInt64LE(Value: Int64) : ByteArray;  overload; 
procedure GetByteArrayFromInt64LE(Value : Int64; Dest : ByteArray; Position : integer);  overload; 

function GetByteArrayFromInt64BE(Value: Int64) : ByteArray;  overload; 
procedure GetByteArrayFromInt64BE(Value : Int64; Dest : ByteArray; Position : integer);  overload; 

function GetWordLEFromByteArray(Source : ByteArray; Position : integer) : Word;  overload; 
function GetWordBEFromByteArray(Source : ByteArray; Position : integer) : Word;  overload; 

function GetDWordLEFromByteArray(Source : ByteArray; Position : integer) : Longword;  overload; 
function GetDWordBEFromByteArray(Source : ByteArray; Position : integer) : Longword;  overload; 

function GetInt64LEFromByteArray(Source : ByteArray; Position : integer) : Int64;  overload; 
function GetInt64BEFromByteArray(Source : ByteArray; Position : integer) : Int64;  overload; 



function EmptyAnsiString : AnsiString;

function EmptyArray: ByteArray;



function SBConcatArrays(const Buf1, Buf2 : ByteArray): ByteArray;  overload; function SBConcatArrays(const Buf1, Buf2, Buf3 : ByteArray): ByteArray;  overload; 
function SBConcatArrays(const Buf1: ByteArray; Buf2: byte): ByteArray;  overload; function SBConcatArrays(const Buf1: byte; Buf2: ByteArray): ByteArray;  overload; function SBConcatArrays(const Buf1, Buf2 : byte; Buf3: ByteArray): ByteArray;  overload; function SBConcatArrays(const Buf1 : byte; Buf2, Buf3 : ByteArray): ByteArray;  overload; 
function SBConcatMultipleArrays(const Arrays : array of ByteArray): ByteArray;  overload; 
function CloneArray(const Arr :  ByteArray ): ByteArray;  overload; 
function CloneArray(const Arr :  ByteArray ; StartIndex: integer; Count: integer): ByteArray;  overload; 
function CloneArray(const Arr : IntegerArray): IntegerArray;  overload; 
function CloneArray(const Arr : LongWordArray ): LongWordArray;   overload; 
function CloneArray(const Arr: StringArray): StringArray;  overload; 

function CloneArray(Buffer: pointer; Size: Integer): ByteArray; overload;


function ArrayEndsWith(const Buffer : ByteArray; const Substr : ByteArray): boolean; 

function UTCTimeToDate(const UTCTime: string; FourDigitYear : boolean {$ifdef HAS_DEF_PARAMS} =   false {$endif}):  TDateTime ; 
function UTCTimeToTime(const UTCTime: string; FourDigitYear : boolean {$ifdef HAS_DEF_PARAMS} =   false {$endif}):  TDateTime ; 
function UTCTimeToDateTime(const UTCTime: string; FourDigitYear : boolean {$ifdef HAS_DEF_PARAMS} =   false {$endif}):  TDateTime ; 
function GeneralizedTimeToDate(const GenTime: string):  TDateTime ; 
function GeneralizedTimeToTime(const GenTime: string):  TDateTime ; 
function GeneralizedTimeToDateTime(const GenTime: string):  TDateTime ; 
function DateTimeToUTCTime(const ADateTime :  TDateTime ; FourDigitYear : boolean {$ifdef HAS_DEF_PARAMS} =   false {$endif}) : string; 
function DateTimeToGeneralizedTime(const ADateTime :  TDateTime ) : string; 
{$ifdef SB_POSIX}
function FileTimeToUnixTime(Value : FILETIME): int64;
function UnixTimeToFileTime(Value : int64): FILETIME;
 {$endif}
function FileTimeToDateTime(Value : FILETIME): TDateTime;
function DateTimeToFileTime(Value : TDateTime): FILETIME;


function UnixTimeToDateTime(Value : Int64): TDateTime;
function DateTimeToUnixTime(Value : TDateTime): Int64;


//procedure StaticArrayToDynArray( )

function ConstLength(Arr : TByteArrayConst) : integer;


{$ifdef SB_HAS_MEMORY_MANAGER}
procedure SetLength(var Arr: JLObjectArray; aLength: integer); overload;
procedure SetLength(var Arr: ObjectArray; aLength: integer); overload;
procedure SetLength(var Arr: ByteArray; aLength: integer); overload;
procedure SetLength(var Arr: WordArray; aLength: integer); overload; 
procedure SetLength(var Arr: IntegerArray; aLength: integer); overload;
procedure SetLength(var Arr: Int64Array; aLength: integer); overload;
procedure SetLength(var Arr: CharArray; aLength: integer); overload;
procedure SetLength(var Arr: string; aLength: integer); overload;
procedure SetLength(var Arr: StringArray; aLength: integer); overload;
procedure SetLength(var Arr: AnsiString; aLength: integer); overload;
procedure SetLength(var Arr: BooleanArray; aLength: integer); overload;

procedure SetLength(var Arr: LIntArray; aLength: integer); overload;
procedure SetLength(var Arr: ByteArrayConstArray; aLength: integer); overload;
procedure SetLength(var Arr: DateArray; aLength: integer); overload;

procedure SetLength(var Arr: ArrayOfByteArray; aLength: integer); overload;

procedure SetLength(var Arr: Arr1jbyte; aLength: integer; Stub: boolean = false); overload;
procedure SetLength(var Arr: LongWordArray; aLength: integer; Stub: boolean = false); overload;
procedure SetLength(var Arr: SmallIntArray; aLength: integer; Stub: boolean = false); overload; 
 {$endif}

procedure ReleaseString(var S : AnsiString);  overload; 
procedure ReleaseString(var S : AnsiString; Zeroize : boolean);  overload; 
procedure ReleaseString(var S : UnicodeString);  overload; 
procedure ReleaseString(var S : UnicodeString; Zeroize : boolean);  overload; 

procedure ReleaseArray(var aBytes : ByteArray);  overload; 
procedure ReleaseArray(var aBytes : ByteArray; Zeroize : boolean);  overload; 
procedure ReleaseArray(var aWords: WordArray);  overload; 
procedure ReleaseArray(var aWords: WordArray; Zeroize : boolean);  overload; 
procedure ReleaseArray(var aIntegers: IntegerArray);  overload; 
procedure ReleaseArray(var aIntegers: IntegerArray; Zeroize : boolean);  overload; 
(*
procedure ReleaseArray(var aUInt32s: UInt32Array); {$ifdef SB_NET}public;{$else}overload;{$endif}
procedure ReleaseArray(var aUInt32s: UInt32Array; Zeroize : boolean); {$ifdef SB_NET}public;{$else}overload;{$endif}
*)
procedure ReleaseArray(var aLongWords: LongWordArray );  overload; 
procedure ReleaseArray(var aLongWords: LongWordArray; Zeroize : boolean);  overload; 
procedure ReleaseArray(var aInt64s: Int64Array);  overload; 
procedure ReleaseArray(var aInt64s: Int64Array; Zeroize : boolean);  overload; 
procedure ReleaseArray(var aByteArrays : ArrayOfByteArray);  overload; 
procedure ReleaseArray(var aChars: CharArray);  overload; 
procedure ReleaseArray(var aChars: CharArray; Zeroize : boolean);  overload; 
{$ifndef SB_UNICODE_VCL}
procedure ReleaseArray(var aWideChars: WideCharArray);  overload; 
procedure ReleaseArray(var aWideChars: WideCharArray; Zeroize : boolean);  overload; 
procedure ReleaseArray(var aWideStrings: WideStringArray);  overload; 
 {$endif}
procedure ReleaseArray(var aBooleans: BooleanArray);  overload; 
procedure ReleaseArray(var aBooleans: BooleanArray; Zeroize : boolean);  overload; 
procedure ReleaseArray(var aStrings: StringArray);  overload; 
procedure ReleaseArray(var aStrings: StringArray; Zeroize : boolean);  overload; 
procedure ReleaseArrays(var A1, A2 : ByteArray);  overload; 
procedure ReleaseArrays(var A1, A2 : ByteArray; Zeroize : boolean);  overload; 
procedure ReleaseArrays(var A1, A2, A3 : ByteArray);  overload; 
procedure ReleaseArrays(var A1, A2, A3 : ByteArray; Zeroize : boolean);  overload; 
procedure ReleaseArrays(var A1, A2, A3, A4 : ByteArray);  overload; 
procedure ReleaseArrays(var A1, A2, A3, A4 : ByteArray; Zeroize : boolean);  overload; 
procedure ReleaseArrays(var A1, A2, A3, A4, A5 : ByteArray);  overload; 
procedure ReleaseArrays(var A1, A2, A3, A4, A5 : ByteArray; Zeroize : boolean);  overload; 
procedure ReleaseArrays(var A1, A2, A3, A4, A5, A6 : ByteArray);  overload; 
procedure ReleaseArrays(var A1, A2, A3, A4, A5, A6 : ByteArray; Zeroize : boolean);  overload; 
procedure ReleaseArrays(var A1, A2, A3, A4, A5, A6, A7 : ByteArray);  overload; 
procedure ReleaseArrays(var A1, A2, A3, A4, A5, A6, A7 : ByteArray; Zeroize : boolean);  overload; 
procedure ReleaseArrays(var A1, A2, A3, A4, A5, A6, A7, A8 : ByteArray);  overload; 
procedure ReleaseArrays(var A1, A2, A3, A4, A5, A6, A7, A8 : ByteArray; Zeroize : boolean);  overload; 
procedure ReleaseArrays(var A1, A2, A3, A4, A5, A6, A7, A8, A9 : ByteArray);  overload; 
procedure ReleaseArrays(var A1, A2, A3, A4, A5, A6, A7, A8, A9 : ByteArray; Zeroize : boolean);  overload; 
procedure ReleaseArrays(var A1, A2, A3, A4, A5, A6, A7, A8, A9, A10 : ByteArray);  overload; 
procedure ReleaseArrays(var A1, A2, A3, A4, A5, A6, A7, A8, A9, A10 : ByteArray; Zeroize : boolean);  overload; 


function TickDiff(Previous, Current : Cardinal) : Cardinal; 

function GenerateGUID: string; 

function IsTextualOID(const S : string): boolean;

{$ifndef SB_WINDOWS}
{$ifdef SB_MACOS}
function GetTickCount: integer;
 {$endif}
{$ifdef SB_LINUX}
function GetTickCount: integer;
 {$endif}
 {$endif}


{$ifdef SB_WINDOWS}
function WaitFor(Handle : THandle): LongWord;
 {$else}
function WaitFor(Thread : TThread): LongWord; overload;
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
function WaitFor(ThreadID : TThreadID): LongWord; overload;
 {$endif}
 {$endif}

const
  COREDLL = 'coredll.dll';
  OLE32   = 'ole32.dll';
  KERNEL32 = 'kernel32.dll';
  NTDLL = 'ntdll.dll';

{$ifndef WP}
{$ifdef SB_NO_NET_COM_STRINGS}
function StringToCoTaskMemUni(const s: string): IntPtr; 
 {$endif}
 {$endif}

{$ifndef SB_NO_NET_INTEROP}
{$ifdef SB_NO_NET_UNSAFEADDROFPINNEDARRAYELEMENT}
function UnsafeAddrOfPinnedArrayElement(ArrPin: GCHandle): IntPtr; 
function UnsafeAddrOfPinnedByteArrayElement(ArrPin: GCHandle; Index: integer): IntPtr; 
 {$endif}
 {$endif}

{$ifndef SB_NO_NET_PINVOKE}
{$ifdef SB_NO_NET_COM_MEMORY_ALLOC}
{$ifdef SILVERLIGHT50}
[SecurityCritical]
 {$endif}
function LocalAlloc(Flags: DWORD; Size: Integer): IntPtr; 
{$ifdef SILVERLIGHT50}
[SecurityCritical]
 {$endif}
procedure LocalFree(Ptr: IntPtr); 
{$ifdef SILVERLIGHT50}
[SecurityCritical]
 {$endif}
function AllocCoTaskMem(Size: Integer): IntPtr; 
{$ifdef SILVERLIGHT50}
[SecurityCritical]
 {$endif}
procedure FreeCoTaskMem(Ptr: IntPtr); 
 {$endif}
 {$endif}

{$ifdef SB_NO_NET_DATETIME_OADATE}
function DateTimeToOADate(const DateTime: System.DateTime): Double; 
function DateTimeFromOADate(const d: Double): System.DateTime; 
 {$endif}

function LocalTimeToUTCTime(LocalTime: TElDateTime): TElDateTime; 
function UTCTimeToLocalTime(UtcTime : TElDateTime) : TElDateTime; 

function UTCNow() : TElDateTime;  

procedure RegisterGlobalObject(O :  TObject ); 
procedure UnregisterGlobalObject(O :  TObject ); 
procedure CleanupRegisteredGlobalObjects; 

procedure AcquireGlobalLock(); 
procedure ReleaseGlobalLock(); 

// Dumps Buffer in the form of:
//   D8 CE 4C 2A 6B B0 60 56 B0 74 A9 98 7D 4F 1D 68 B7 CA 1D DB

function HexDump(const Buffer: ByteArray; Offset: Cardinal; Len: Cardinal): string;  overload ;

// Dumps Buffer in the form of:
//   6E 74 65 78 74 20 64 65 73-74 72 6F 79 65 64 0D  ntext destroyed.
//   0A 34 3A 33 39 3A 32 38 20-50 4D 09 43 42 46 53  .4:39:28 PM.CBFS
//   20 47 65 74 46 69 6C 65 49-6E 66 6F 3A 20 5B 5C   GetFileInfo: [\
//   2E 73 73 68 5C 61 75 74 68-6F 72 69 7A 65 64 5F  .ssh\authorized_
//
// If the AddChar paramter is set to True, the buffer is also dumped as text
// (all characters with ASCII code less than 31 are replaced with period '.')

function HexDump(const Buffer: ByteArray; Offset: Cardinal; Len: Cardinal; AddChars: Boolean): string;  overload ;

// Date and time routines

function SBSameDateTime(A, B: TElDateTime): Boolean; 
function SBSameDate(A, B: TElDateTime): Boolean; 
function SBSameTime(A, B: TElDateTime): Boolean; 

function SBEncodeDateTime(Year, Month, Day, Hour, Minute, Second, Millisecond: Integer): TElDateTime; 

type

{$ifndef VCL50}
  TListNotification = (lnAdded, lnExtracted, lnDeleted);
 {$endif}

{$WARNINGS OFF}

  TSBObjectList = class(TElList)
  private
    FOwnsObjects: Boolean;
  protected
    procedure Notify(Ptr: Pointer; Action: TListNotification);
//{$ifdef FPC}override;{$endif}
{$ifdef VCL50} override;
 {$else} {$ifndef FPC}virtual; {$endif}
 {$endif}
    function GetItem(Index: Integer): TObject;
    procedure SetItem(Index: Integer; AObject: TObject);
  public
    constructor Create;  overload; 
    constructor Create(AOwnsObjects: Boolean); overload;
    function Add(AObject: TObject): Integer;
    function Remove(AObject: TObject): Integer;
    function IndexOf(AObject: TObject): Integer;
    procedure Insert(Index: Integer; AObject: TObject);
    function FindInstanceOf(AClass:  TClass  ; AExact: Boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif};
      AStartAt: Integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}): Integer;
    function Extract(Item: TObject): TObject;
    property OwnsObjects: Boolean read FOwnsObjects write FOwnsObjects;
    property Items[Index: Integer]: TObject read GetItem write SetItem; default;
  end;


{$WARNINGS ON}


{$ifdef SB_NO_BOOLEAN_VAR_PARAMS}
type
  TSBBoolean = public class
  protected
    FValue : boolean;
  public
    constructor Create;
    constructor Create(Value : boolean);
    function ToString(): string; override;
    property InnerValue : boolean read FValue write FValue;
    class operator Implicit(const Value: boolean): TSBBoolean;
    class operator Implicit(const Value: TSBBoolean): boolean;
    class operator Equal(const Left, Right: TSBBoolean): boolean;
    class operator NotEqual(const Left, Right: TSBBoolean): boolean;
    class operator Equal(const Left: TSBBoolean; const Right: boolean): boolean;
    class operator NotEqual(const Left: TSBBoolean; const Right: boolean): boolean;
    class operator BitwiseOr(const Left: TSBBoolean; const Right: boolean): boolean;
    class operator BitwiseAnd(const Left: TSBBoolean; const Right: boolean): boolean;
    class operator BitwiseOr(const Left: TSBBoolean; const Right: TSBBoolean): boolean;
    class operator BitwiseAnd(const Left: TSBBoolean; const Right: TSBBoolean): boolean;
    class operator BitwiseOr(const Left: boolean; const Right: TSBBoolean): boolean;
    class operator BitwiseAnd(const Left: boolean; const Right: TSBBoolean): boolean;
    class operator BitwiseNot(const Value: TSBBoolean): boolean;
  end;
 {$endif}


function GetUTCOffsetDateTime: TDateTime;

{ Constants }

(*
type

  TOIDEx = {$ifdef SB_NET}public{$endif} array[0..2] of Byte;
  TAlOID = {$ifdef SB_NET}{$ifndef SB_MSSQL}public{$endif}{$endif} array[0..127] of Byte;

  TExtOID = {$ifdef SB_NET}public{$endif} record
  {$ifdef SB_NET}public{$endif}
    OID: TOIDEx;
    Name: string;
  end;

const
  //error code
  SizeError = $1111;

  // tags (IDs) for data objects

  SIZE128 = $81 - 1;
  // data blocks IDs (for Synchronization)
  xBLOCKID_0 = $A0;
  xBLOCKID_1 = $A1;
  xBLOCKID_2 = $A2;
  xBLOCKID_3 = $A3;
  xBLOCK_SIZE_128 = $81;

  xMARKEREND = $00;
  xBOOL = $01;

  // data type - integer
  xINTEGER = $02;
  xINTEGER_SIZE_128 = $81;

  // data type - string of bit
  xBITSTRING = $03;
  xBITSTRING_SIZE_128 = $81;

  xOCTETSTRING = $04;
  xANYDATA = $05;
  xNULL = $05;

  xOID = $06;
  xUTF8STRING = $0C;
  xPRINTABLESTRING = $13;
  xUNKNOWNSTRING1 = $14;
  xIASTRING = $16;
  xUTCTime = $17;

  // data type - record
  xSEQUENCE = $30;
  xSEQUENCE_SIZE_UNDEFINED = $80;
  xSEQUENCE_SIZE_128 = $81;

  xSET = $31;

  // Extension OID
  xauthorityKeyIdentifier: TOIDEx =
  {$ifndef SB_NET}({$else}[{$endif}$55, $1D, $23{$ifndef SB_NET}){$else}]{$endif};
  xsubjectKeyIdentifier: TOIDEx =
  {$ifndef SB_NET}({$else}[{$endif}$55, $1D, $0E{$ifndef SB_NET}){$else}]{$endif};
  xkeyUsage: TOIDEx =
  {$ifndef SB_NET}({$else}[{$endif}$55, $1D, $0F{$ifndef SB_NET}){$else}]{$endif};
  xextendedKeyUsage: TOIDEx =
  {$ifndef SB_NET}({$else}[{$endif}$55, $1D, $25{$ifndef SB_NET}){$else}]{$endif};
  xprivateKeyUsagePeriod: TOIDEx =
  {$ifndef SB_NET}({$else}[{$endif}$55, $1D, $10{$ifndef SB_NET}){$else}]{$endif};
  xcertificatePolicies: TOIDEx =
  {$ifndef SB_NET}({$else}[{$endif}$55, $1D, $20{$ifndef SB_NET}){$else}]{$endif};
  xpolicyMappings: TOIDEx =
  {$ifndef SB_NET}({$else}[{$endif}$55, $1D, $21{$ifndef SB_NET}){$else}]{$endif};
  xsubjectAltName: TOIDEx =
  {$ifndef SB_NET}({$else}[{$endif}$55, $1D, $11{$ifndef SB_NET}){$else}]{$endif};
  xissuerAltName: TOIDEx =
  {$ifndef SB_NET}({$else}[{$endif}$55, $1D, $12{$ifndef SB_NET}){$else}]{$endif};
  xbasicConstraints: TOIDEx =
  {$ifndef SB_NET}({$else}[{$endif}$55, $1D, $13{$ifndef SB_NET}){$else}]{$endif};
  xnameConstraints: TOIDEx =
  {$ifndef SB_NET}({$else}[{$endif}$55, $1D, $1E{$ifndef SB_NET}){$else}]{$endif};
  xpolicyConstraints: TOIDEx =
  {$ifndef SB_NET}({$else}[{$endif}$55, $1D, $24{$ifndef SB_NET}){$else}]{$endif};
  xcRLDistributionPoints: TOIDEx =
  {$ifndef SB_NET}({$else}[{$endif}$55, $1D, $1F{$ifndef SB_NET}){$else}]{$endif};
  xsubjectDirectoryAttributes: TOIDEx =
  {$ifndef SB_NET}({$else}[{$endif}$55, $1D, $09{$ifndef SB_NET}){$else}]{$endif};
  xauthorityInfoAccess: TOIDEx =
  {$ifndef SB_NET}({$else}[{$endif}$55, $1D, $01{$ifndef SB_NET}){$else}]{$endif};
*)

//function OIDToContent(const OID: string) : ByteArray;
function CompareContent(const Content, OID:  ByteArray ): Boolean;  overload; 
function DateTimeToISO8601Time(Time : TElDateTime; EncodeMilliseconds : boolean): string; 
function ISO8601TimeToDateTime(const EncodedTime : string): TElDateTime; 

function DateTimeToRFC3339(Value: TElDateTime; EncodeMilliseconds: Boolean): string; 



procedure SetLicenseKey(const Key : string);
procedure CheckLicenseKey();



// workarounds for Delphi 4-Delphi 5, which have 32-bit streams
{$ifndef D_6_UP}
//function OpenFile(const Name : string; Mode : cardinal) : THandle;
function ReadFile(Handle : THandle; Buffer : pointer; Count : cardinal) : cardinal;
function WriteFile(Handle : THandle; Buffer : pointer; Count : cardinal) : cardinal;
function GetFileSize(Handle : THandle) : Int64;
procedure CloseFile(Handle : THandle);
function GetFilePosition(Handle : THandle) : Int64;
procedure SetFilePosition(Handle : THandle; Position : Int64);
 {$endif}

function AppendSlash(const Path : string): string;
function EnsureDirectoryExists(const DirName: string): Boolean;
function DirectoryExists(DirName: string): boolean;

{$ifdef SB_POSIX}
function GetCurrentThreadID: LongWord; cdecl;
 {$endif}





{$ifdef SB_HAS_MEMORY_MANAGER}
var
  ByteArrClass : JLClass;
  MemoryManager : TElMemoryManager;
 {$endif}

// DeN - move here for test
  
var
  {$ifdef SB_WINDOWS}
  GlobalLockCS : ^TRTLCriticalSection = nil;
   {$else}
  GlobalLockCS : TCriticalSection = nil;
   {$endif}
  GlobalLockCSFlag : integer  =  0;

  GlobalObjectList :  TElList =  nil;  
  
// end DeN - move here for test  

resourcestring

  SRegexUnsupported = 'Regular expressions in masks are not supported in this version of compiler / platform';

  SInvalidInputSize = 'Invalid input block size';
  SInvalidKeySize = 'Invalid key size [%d bits]';
  SInvalidUInt16BufferOffset = 'Cannot get 2 bytes at offset %d (buffer size is %d)';
  SInvalidUInt32BufferOffset = 'Cannot get 4 bytes at offset %d (buffer size is %d)';
  SInvalidOID = 'Invalid object identifier';
  sOutputBufferTooSmall = 'Output buffer too small';

  SUnicodeNotInitialized = 'Unicode module is not initialized. Please execute a SBUnicode.Unit.Initialize() call at the very start of your project.';
  SUnsupportedCharset = 'Unsupported charset';

  SOperationCancelled = 'Synchronous operation has been cancelled';

  SLicenseKeyNotSet = 'SecureBlackbox license key is not set. Please pass production or evaluation license key to SBUtils.SetLicenseKey function in initialization section of your application.' + #13#10'If this message appears in design-time, place TElSBLicenseManager component on the form and put the key to LicenseKey property.'+ #13#10'Evaluation license key can be found in <SecureBlackbox folder>\LicenseKey.txt file';
  SInvalidDateToken = 'Invalid date token (%s)';
  SInvalidTimeToken = 'Invalid time token (%s)';
  SOldLicenseKey = 'Provided license key is valid for old version of SecureBlackbox and not the current one. Please upgrade your license.';
  SUnknownLicenseKey = 'Provided license key is valid for version of SecureBlackbox, other than current one. Please check the version of SecureBlackbox and your license.';
  SLicenseKeyExpired = 'Time-limited SecureBlackbox license key has expired. Please use evaluation license key to continue evaluation.';
  SLicenseTypeNotEnabled = 'Your SecureBlackbox license key doesn''t enable the requested functionality. Please check if you have a license for the components that you are trying to use.';
  SBadOrOldLicenseKey = 'Provided license key is invalid or is valid for version of SecureBlackbox, other than current one. Please check that the license key is pasted correctly and your license covers current SecureBlackbox version.';
  SAutomaticKeyExpired = 'Your time-limited SecureBlackbox license key has expired. Please use evaluation license key to continue evaluation or request license prolongation via the HelpDesk system.';
  SSeekOffsetRangeError = 'Seek offset is out of LongInt range';

  SBase32InvalidDataSize = 'Input data size must be multiple of 8';
  SBase32InvalidData = 'Input buffer contains invalid data that is not base32 encoded';


implementation

uses
  SBRandom,
  SBMD,
  SBASN1Tree,
  SBStrUtils,
  {$ifndef SB_PGPSFX_STUB}
  SBUnicode,
   {$endif}
  SBSHA
  ;


resourcestring
  STrialCaption = 'SecureBlackbox (unlicensed) evaluation';
  STrialInformation = 'You are using trial version of SecureBlackbox.'#13#10#13#10 +
  'All major functionality includes DELAYS up to 1.5 seconds per atomic operation.'#13#10 +
  'This leads to INTENTIONAL SLOWDOWN!!! (This is not a real speed)'#13#10#13#10 +
  'Please consider purchasing a license to get rid of this nag screen.'#13#10#13#10 +
  'You can request the time-limited key, which removes time delays and the nag screen,'#13#10 +
  'using the web form on http://www.eldos.com/sbb/keyreq/';


// Not tested
constructor ESecureBlackboxError.Create(const AMessage: string);
begin
  inherited Create(AMessage);
  FErrorCode := 0;
  //Assert(false, 'No error code is set in the exception.');
end;

constructor ESecureBlackboxError.Create(AErrorCode : Integer; const AMessage : string);
begin
  inherited Create(AMessage);
  FErrorCode := AErrorCode;
  FSupplErrorCode := 0;
end;

constructor ESecureBlackboxError.Create(AErrorCode : Integer; ASupplErrorCode : Integer; const AMessage : string);
begin
  inherited Create(AMessage);
  FErrorCode := AErrorCode;
  FSupplErrorCode := ASupplErrorCode;
end;

constructor ESecureBlackboxError.Create(AErrorCode : Integer; const AMessage : string;
  AInsertErrorCodeToMessage : Boolean);
begin
  inherited Create(AMessage + ' (error code is ' + IntToStr(AErrorCode) + ')');
  FErrorCode := AErrorCode;
  FSupplErrorCode := 0;
end;

constructor ESecureBlackboxError.Create(AErrorCode : Integer; const AMessageFormat : string;
  const Param1 : string);
begin
  inherited Create(Format(AMessageFormat, [Param1]));
  FErrorCode := AErrorCode;
  FSupplErrorCode := 0;
end;

constructor ESecureBlackboxError.Create(AErrorCode : Integer; const AMessageFormat : string;
  Param1 : Integer);
begin
  inherited Create(Format(AMessageFormat, [Param1]));
  FErrorCode := AErrorCode;
  FSupplErrorCode := 0;
end;

constructor ESecureBlackboxError.Create(AErrorCode : Integer; const AMessageFormat : string;
  const Param1 : string; Param2 : Integer);
begin
  inherited Create(Format(AMessageFormat, [Param1, Param2]));
  FErrorCode := AErrorCode;
  FSupplErrorCode := 0;
end;

constructor ESecureBlackboxError.Create(AErrorCode : Integer; const AMessageFormat : string;
  Param1 : Integer; const Param2 : string);
begin
  inherited Create(Format(AMessageFormat, [Param1, Param2]));
  FErrorCode := AErrorCode;
  FSupplErrorCode := 0;
end;

constructor ESecureBlackboxError.Create(AErrorCode : Integer; const AMessageFormat : string;
  Param1 : Integer; Param2 : Integer);
begin
  inherited Create(Format(AMessageFormat, [Param1, Param2]));
  FErrorCode := AErrorCode;
  FSupplErrorCode := 0;
end;

constructor ESecureBlackboxError.Create(AErrorCode : Integer; const AMessageFormat : string;
  const Param1 : string; const Param2 : string);
begin
  inherited Create(Format(AMessageFormat, [Param1, Param2]));
  FErrorCode := AErrorCode;
  FSupplErrorCode := 0;
end;

constructor ESecureBlackboxError.Create(AErrorCode : Integer; ASupplErrorCode : Integer; const AMessageFormat : string;
  const Param1 : string);
begin
  inherited Create(Format(AMessageFormat, [Param1]));
  FErrorCode := AErrorCode;
  FSupplErrorCode := ASupplErrorCode;
end;

constructor ESecureBlackboxError.Create(AErrorCode : Integer; ASupplErrorCode : Integer; const AMessageFormat : string;
  Param1 : Integer);
begin
  inherited Create(Format(AMessageFormat, [Param1]));
  FErrorCode := AErrorCode;
  FSupplErrorCode := ASupplErrorCode;
end;

constructor ESecureBlackboxError.Create(AErrorCode : Integer; ASupplErrorCode : Integer; const AMessageFormat : string;
  Param1 : Integer; Param2 : Integer);
begin
  inherited Create(Format(AMessageFormat, [Param1, Param2]));
  FErrorCode := AErrorCode;
  FSupplErrorCode := ASupplErrorCode;
end;

// old constructors, should be removed
// Not tested
constructor ESecureBlackboxError.Create(const Message: string; Code: Integer{$ifndef FPC}; Fake: integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif} {$endif});
begin
  inherited Create(Message + ' (error code is ' + IntToStr(Code) + ')');
  FErrorCode := Code;
end;

// Not tested
constructor ESecureBlackboxError.Create(const Message: string; Code: Integer; InsertCodeToErrorMessage : boolean{$ifndef FPC}; Fake: integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif} {$endif});
var
  Msg : string;
begin
  if InsertCodeToErrorMessage then
    Msg := Message + ' (error code is ' +  IntToStr(Code)  + ')'
  else
    Msg := Message;
  inherited Create(Msg);
  FErrorCode := Code;
end;



{$ifdef SB_WINRT}
// Not tested
constructor Win32Exception.Create(Win32ErrorCode : Integer);
begin
  inherited Create(0, Win32ErrorCode, 'Win32 exception: ' + IntToStr(Win32ErrorCode));
end;

constructor Win32Exception.Create(ErrorCode : Integer; Win32ErrorCode : Integer);
begin
  inherited Create(ErrorCode, Win32ErrorCode, 'Win32 exception: ' + IntToStr(Win32ErrorCode));
end;
 {$endif}

// Need - check
function TickDiff(Previous, Current : Cardinal) : Cardinal;
begin
  if Current > Previous then
    result := Current - Previous
  else
  if Current < Previous then
    result := Current + ($7FFFFFFF - Previous) + 1 // DeN 28.11.2013 maybe here need $FFFFFFFF instead of $7FFFFFFF?
  else
    result := 0;
end;

(*
function GetByteArrayFromByte(const AStr: Char): ByteArray;
begin
  SetLength(Result, 1);
  Result[0] := byte(AStr);
end;

function GetByteArrayFromByte(const Value: Byte): ByteArray;
begin
  SetLength(Result, 1);
  Result[0] := byte(Value);
end;
*)

{$ifdef SB_UNIX} //???: need check in Kylix
const
{$ifdef SB_ANDROID}
  libpthread = 'libc';
 {$else}
{$ifdef SB_iOS}
  libpthread = 'libpthread.dylib';
 {$else}
{$ifdef DELPHI_MAC}
  libpthread = 'libpthread.dylib';
 {$else}
  libpthread = 'libpthread.so.0';
 {$endif}
 {$endif}
 {$endif}
  function GetCurrentThreadID: LongWord; cdecl;
    external libpthread name {$ifndef FPC}_PU +  {$endif}'pthread_self';
 {$endif}


(*
{$ifdef DELPHI_MAC}
function GetCurrentThreadID: LongWord; cdecl;
begin
  result := Longword(PThread.pthread_self());
end;
{$endif}
*)

{$ifdef DELPHI_MAC}
(*function GetCurrentThreadID: LongWord; cdecl;
begin
  result := Longword(Posix.PThread.pthread_self());
end;
*)
 {$else}
(*
{$ifdef SB_MACOS}
function GetCurrentThreadID: LongWord; cdecl;
begin
  result := LongWord(System.GetCurrentThreadId);
end;
{$endif}
*)
 {$endif}

{$ifndef SB_WINDOWS}
{$ifdef SB_MACOS}

{$ifndef FPC}
const
  CTL_KERN = 1;
  KERN_BOOTTIME = 21;
 {$endif}

// the below MAC GetTickCount() implementation was kindly provided by Mr Santiago Castan~o,
// KSI Seguridad Digital (http://ksitdigital.com)
function GetTickCount : integer;
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
var
  mib : array[0..1] of {$ifdef FPC}cint {$else}integer {$endif};
  len : {$ifdef FPC}cint {$else}integer {$endif};
  t : {$ifdef FPC}TTimeVal {$else}timeval {$endif};
  msec : comp;
  BootStamp : TDateTime;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  //we call sysctl kern.boottime, it returns the boot time of MAC (epoch), in UTC
  mib[0] := CTL_KERN;
  mib[1] := KERN_BOOTTIME;
  len := sizeof(t);
  {$ifdef FPC}
  if (fpsysctl(pchar(@mib), 2, @t, @len, nil, 0) = -1) then
   {$else}
  if (sysctl(pInteger(@mib), 2, @t, @len, nil, 0) = -1) then
   {$endif}
  begin
    Result := -1;
    //  raise Exception.Create('Error in sysctl KERN_BOOTTIME');
  end
  else
  begin
    BootStamp := UnixToDateTime(t.tv_sec); // boottime returns zero t.tv_usec, so ignoring it
    Result := MilliSecondsBetween(DateTimeUtcNow(), BootStamp); // kern.boottime is in UTC
  end;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;
 {$endif}
{$ifdef SB_LINUX}
function GetTickCount: integer;
var
  f: text;
  up: double;
begin
  assignfile(f, '/proc/uptime');
  reset(f);
  read(f, up);
  closefile(f);
  result := trunc(up * 1000);
end;
 {$endif}
 {$endif}

{$ifndef SB_WINDOWS}
// Not tested
constructor TElStringList.Create;
begin
  inherited;
  {$ifdef FPC}
  TextLineBreakStyle := tlbsCRLF;
   {$endif}
  {$ifdef DELPHI_MAC}
  LineBreak := #13#10;
   {$endif}
end;
 {$endif}
 

// Done 7 / XE5(32) / XE5(64) / Android
function StringOfBytes(const Src : ByteArray) : string;
{$ifdef SB_UNICODE_VCL}
var
  i: Integer;
 {$endif}
begin
  SetLength(Result, Length(Src));
  {$ifndef SB_UNICODE_VCL}
  SBMove(Src[0], Result[StringStartOffset], Length(Result));
   {$else}
  for i := 0 to Length(Result) - 1 do
    Result[StringStartOffset + i] := Chr(Src[i]);
   {$endif}
end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringOfBytes(const Src: ByteArray; ALow: Integer; ALen: integer): string;
var
  ToCopy : integer;
  {$ifdef SB_UNICODE_VCL}
  i: Integer;
   {$endif}
begin
  // DeN 16.10.2013
  if ALow < 0 then
    ALow := 0;
  // end DeN 16.10.2013
  	
  ToCopy := Min(ALen, Length(Src) - ALow);
  SetLength(Result, ToCopy);
  {$ifndef SB_UNICODE_VCL}
  SBMove(Src[ALow], Result[StringStartOffset], ToCopy);
   {$else}
  for i := 0 to ToCopy - 1 do
    Result[i + StringStartOffset] := Chr(Src[i + ALow]);
   {$endif}
end;

// Done 7 / XE5(32) / XE5(64) / Android
function BytesOfString(const Str : string) : ByteArray;
{$ifdef SB_UNICODE_VCL}
var
  i: Integer;
 {$endif}
begin
  SetLength(Result, Length(Str));
  {$ifndef SB_UNICODE_VCL}
  SBMove(Str[StringStartOffset], Result[0], Length(Result));
   {$else}
  for i := 0 to Length(Result) - 1 do
    Result[i] := Byte(Ord(Str[i + StringStartOffset]));
   {$endif}
end;

(*
function GetByteArrayFromByte(Value : Byte) : ByteArray; {$ifdef SB_NET}public;{$else}overload;{$endif}
procedure GetByteArrayFromByte(Value : Byte; Dest : ByteArray; Position : integer); {$ifdef SB_NET}public;{$else}overload;{$endif}

function GetByteArrayFromWordLE(Value : Word) : ByteArray; {$ifdef SB_NET}public;{$else}overload;{$endif}
procedure GetByteArrayFromWordLE(Value : Byte; Dest : ByteArray; Position : integer); {$ifdef SB_NET}public;{$else}overload;{$endif}

function GetByteArrayFromWordBE(Value : Word) : ByteArray; {$ifdef SB_NET}public;{$else}overload;{$endif}
procedure GetByteArrayFromWordBE(Value : Byte; Dest : ByteArray; Position : integer); {$ifdef SB_NET}public;{$else}overload;{$endif}

function GetByteArrayFromDWordBE(Value: cardinal) : ByteArray; {$ifdef SB_NET}public;{$else}overload;{$endif}
procedure GetByteArrayFromDWordBE(Value : Byte; Dest : ByteArray; Position : integer); {$ifdef SB_NET}public;{$else}overload;{$endif}

function GetByteArrayFromInt64BE(Value: Int64) : ByteArray; {$ifdef SB_NET}public;{$else}overload;{$endif}
procedure GetByteArrayFromInt64BE(Value : Byte; Dest : ByteArray; Position : integer); {$ifdef SB_NET}public;{$else}overload;{$endif}
*)
(*
function GetByteArrayFromElement(Value : byte) : ByteArray;
begin
  {$ifndef SB_NET}
  SetLength(Result, 1);
  {$else}
  Result := new Byte[1];
  {$endif}
  Result[0] := Value;
end;

function GetByteArrayFromByte(Value : Byte) : ByteArray;
begin
  {$ifndef SB_NET}
  SetLength(Result, 1);
  {$else}
  Result := new Byte[1];
  {$endif}
  Result[0] := byte(Value);
end;
*)

// Done 7 / XE5(32) / XE5(64) / Android
function GetByteArrayFromByte(Value : Byte) : ByteArray;
begin
  SetLength(Result, 1);
  Result[0] := Value;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure GetByteArrayFromByte(Value : Byte; Dest : ByteArray; Position : integer);
begin
  if Length(Dest) >= Position + sizeof(Byte) then
    Dest[Position] := Value;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function GetByteArrayFromWordLE(Value : Word) : ByteArray;
begin
  SetLength(Result, 2);

  Result[0] := Value and $ff;
  Result[1] := Value shr 8;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure GetByteArrayFromWordLE(Value : Word; Dest : ByteArray; Position : integer);
begin
  if Length(Dest) >= Position + sizeof(Word) then
  begin
    Dest[Position + 0] := Value and $ff;
    Dest[Position + 1] := Value shr 8;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function GetByteArrayFromWordBE(Value : Word) : ByteArray;
begin
  SetLength(Result, 2);
  Result[0] := Value shr 8;
  Result[1] := Value and $ff;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure GetByteArrayFromWordBE(Value : Word; Dest : ByteArray; Position : integer);
begin
  if Length(Dest) >= Position + sizeof(Word) then
  begin
    Dest[Position + 0] := Value shr 8;
    Dest[Position + 1] := Value and $ff;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function GetByteArrayFromDWordLE(Value: cardinal) : ByteArray;
begin
  SetLength(Result, 4);
  Result[3] := (Value shr 24) and $ff;
  Result[2] := (Value shr 16) and $ff;
  Result[1] := (Value shr 8) and $ff;
  Result[0] := Value and $ff;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure GetByteArrayFromDWordLE(Value : Cardinal; Dest : ByteArray; Position : integer);
begin
  if Length(Dest) >= Position + sizeof(Cardinal) then
  begin
    Dest[Position + 3] := (Value shr 24) and $ff;
    Dest[Position + 2] := (Value shr 16) and $ff;
    Dest[Position + 1] := (Value shr 8) and $ff;
    Dest[Position + 0] := Value and $ff;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function GetByteArrayFromDWordBE(Value: cardinal) : ByteArray;
begin
  SetLength(Result, 4);
  Result[0] := (Value shr 24) and $ff;
  Result[1] := (Value shr 16) and $ff;
  Result[2] := (Value shr 8) and $ff;
  Result[3] := Value and $ff;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure GetByteArrayFromDWordBE(Value : Cardinal; Dest : ByteArray; Position : integer);
begin
  if Length(Dest) >= Position + sizeof(Cardinal) then
  begin
    Dest[Position + 0] := (Value shr 24) and $ff;
    Dest[Position + 1] := (Value shr 16) and $ff;
    Dest[Position + 2] := (Value shr 8) and $ff;
    Dest[Position + 3] := Value and $ff;
  end;
end;

// Need check
function GetByteArrayFromInt64LE(Value: Int64) : ByteArray;
begin
  SetLength(Result, 8);
  Result[7] := (Value shr 56) and $ff;
  Result[6] := (Value shr 48) and $ff;
  Result[5] := (Value shr 40) and $ff;
  Result[4] := (Value shr 32) and $ff;
  Result[3] := (Value shr 24) and $ff;
  Result[2] := (Value shr 16) and $ff;
  Result[1] := (Value shr 8) and $ff;
  Result[0] := Value and $ff;
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
procedure GetByteArrayFromInt64LE(Value : Int64; Dest : ByteArray; Position : integer);
begin
  if Length(Dest) >= Position + sizeof(Int64) then
  begin
    Dest[Position + 7] := (Value shr 56) and $ff;
    Dest[Position + 6] := (Value shr 48) and $ff;
    Dest[Position + 5] := (Value shr 40) and $ff;
    Dest[Position + 4] := (Value shr 32) and $ff;
    Dest[Position + 3] := (Value shr 24) and $ff;
    Dest[Position + 2] := (Value shr 16) and $ff;
    Dest[Position + 1] := (Value shr 8) and $ff;
    Dest[Position + 0] := Value and $ff;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function GetByteArrayFromInt64BE(Value: Int64) : ByteArray;
begin
  SetLength(Result, 8);
  Result[0] := (Value shr 56) and $ff;
  Result[1] := (Value shr 48) and $ff;
  Result[2] := (Value shr 40) and $ff;
  Result[3] := (Value shr 32) and $ff;
  Result[4] := (Value shr 24) and $ff;
  Result[5] := (Value shr 16) and $ff;
  Result[6] := (Value shr 8) and $ff;
  Result[7] := Value and $ff;
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
procedure GetByteArrayFromInt64BE(Value : Int64; Dest : ByteArray; Position : integer);
begin
  if Length(Dest) >= Position + sizeof(Int64) then
  begin
    Dest[Position + 0] := (Value shr 56) and $ff;
    Dest[Position + 1] := (Value shr 48) and $ff;
    Dest[Position + 2] := (Value shr 40) and $ff;
    Dest[Position + 3] := (Value shr 32) and $ff;
    Dest[Position + 4] := (Value shr 24) and $ff;
    Dest[Position + 5] := (Value shr 16) and $ff;
    Dest[Position + 6] := (Value shr 8) and $ff;
    Dest[Position + 7] := Value and $ff;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function GetWordLEFromByteArray(Source : ByteArray; Position : integer) : Word;
begin
  // DeN 06.11.2013
  if Position < 0 then
    Position := 0;
  // end DeN 06.11.2013
  	
  if (Length(Source) >= Position + sizeof(Word)) then
    result := Source[Position + 0] + (Source[Position + 1] shl 8)
  else
    result := 0;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function GetWordBEFromByteArray(Source : ByteArray; Position : integer) : Word;
begin
  // DeN 06.11.2013
  if Position < 0 then
    Position := 0;
  // end DeN 06.11.2013
  
  if Length(Source) >= Position + sizeof(Word) then
    result := Source[Position + 1] + (Source[Position + 0] shl 8)
  else
    result := 0;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function GetDWordLEFromByteArray(Source : ByteArray; Position : integer) : Longword;
begin
  // DeN 06.11.2013
  if Position < 0 then
    Position := 0;
  // end DeN 06.11.2013

  if Length(Source) >= Position + sizeof(Longword) then
    result := Source[Position + 0] + (Source[Position + 1] shl 8) +
              (Source[Position + 2] shl 16) + (Source[Position + 3] shl 24)
  else
    result := 0;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function GetDWordBEFromByteArray(Source : ByteArray; Position : integer) : Longword;
begin
  // DeN 06.11.2013
  if Position < 0 then
    Position := 0;
  // end DeN 06.11.2013
  
  if Length(Source) >= Position + sizeof(Longword) then
    result := Source[Position + 3] + (Source[Position + 2] shl 8) +
              (Source[Position + 1] shl 16) + (Source[Position + 0] shl 24)
  else
    result := 0;
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function GetInt64LEFromByteArray(Source : ByteArray; Position : integer) : Int64;
var T1 : Cardinal;
    T2 : Cardinal;
begin
  // DeN 06.11.2013
  if Position < 0 then
    Position := 0;
  // end DeN 06.11.2013

  if Length(Source) >= Position + sizeof(Int64) then
  begin
    T1 := Source[Position + 0] + (Source[Position + 1] shl 8) + (Source[Position + 2] shl 16) + (Source[Position + 3] shl 24);
    T2 := Source[Position + 4] + (Source[Position + 5] shl 8) + (Source[Position + 6] shl 16) + (Source[Position + 7] shl 24);
    result := T1 + (Int64(T2) shl 32);
  end
  else
    result := 0;
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function GetInt64BEFromByteArray(Source : ByteArray; Position : integer) : Int64;
var T1 : Cardinal;
    T2 : Cardinal;
begin
  // DeN 06.11.2013
  if Position < 0 then
    Position := 0;
  // end DeN 06.11.2013
  
  if Length(Source) >= Position + sizeof(Int64) then
  begin
    T1 := Source[Position + 7] + (Source[Position + 6] shl 8) + (Source[Position + 5] shl 16) + (Source[Position + 4] shl 24);
    T2 := Source[Position + 3] + (Source[Position + 2] shl 8) + (Source[Position + 1] shl 16) + (Source[Position + 0] shl 24);
    result := T1 + (Int64(T2) shl 32);
  end
  else
    result := 0;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function EmptyAnsiString : AnsiString;
begin
  SetLength(Result, 0);
end;



// Done 7 / XE5(32) / XE5(64) / Android
function CloneArray(const Arr : ByteArray; StartIndex: integer; Count: integer) : ByteArray;
begin
  // DeN 18.10.2013
  if (Arr = nil) or
     (StartIndex < 0) or
     (StartIndex > Length(Arr))then
    Exit;

  if (Count > Length(Arr)) then
    Count := Length(Arr);
  // end DeN 18.10.2013
  	
  SetLength(Result, Count);
  if Count > 0 then
    SBMove(Arr[StartIndex], Result[0], Count);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function CloneArray(Buffer: pointer; Size: integer): ByteArray;
begin
  // DeN 18.10.2013
  Assert(Size >= 0);  
  if (Buffer = nil) or
     (Size < 0)
  then
    Exit;
  // end DeN 18.10.2013
  	
  SetLength(Result, Size);
  if Size > 0 then
    SBMove(Buffer^, Result[0], Length(Result));
end;

// Done 7 / XE5(32) / XE5(64) / Android
function CloneArray(const Arr : ByteArray): ByteArray;
begin
  SetLength(Result, Length(Arr));
  if Length(Result) > 0 then
    SBMove(Arr[0], Result[0], Length(Result));
end;

// Done 7 / XE5(32) / XE5(64) / Android
function CloneArray(const Arr : IntegerArray): IntegerArray;
var
  I : integer;
begin
  SetLength(Result, Length(Arr));
  if Length(Result) > 0 then
    for I := 0 to Length(Result) - 1 do
      Result[I] := Arr[I];
end;

// Done 7 / XE5(32) / XE5(64) / Android
function CloneArray(const Arr : LongWordArray): LongWordArray;
var
  I : integer;
begin
  SetLength(Result, Length(Arr));
  if Length(Result) > 0 then
    for I := 0 to Length(Result) - 1 do
      Result[I] := Arr[I];
end;


// Done 7 / XE5(32) / XE5(64) / Android
function CloneArray(const Arr: StringArray): StringArray;
var
  I: Integer;
begin
  SetLength(Result, Length(Arr));
  for I := 0 to Length(Result) - 1 do
    Result[I] := Arr[I];
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ArrayEndsWith(const Buffer : ByteArray; const Substr : ByteArray): boolean;
var
  BufferLen, SubstrLen : integer;
begin
  BufferLen := Length(Buffer);
  SubstrLen := Length(Substr);
  if (SubstrLen <= BufferLen) and
     ((Buffer <> nil) and (Substr <> nil)) then // DeN 15.10.2013
  begin
    Result := CompareMem(@Buffer[0 + BufferLen - SubstrLen], @Substr[0], SubstrLen);
  end
  else
    Result := false;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SwapInt32(value : integer) : integer;
begin
  result := (((value) shl 24) or (((value) shl 8) and $00ff0000) or (((value) shr 8) and $0000ff00) or ((value) shr 24));
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure SwapUInt16(Value: Word; var Buffer: ByteArray);
begin
  if Length(Buffer) <> SizeOf(Value) then
    SetLength(Buffer, SizeOf(Value));
  Buffer[0] := Byte(Value shr 8);
  Buffer[1] := Byte(Value);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure SwapUInt16(Value: Word; var Buffer: ByteArray; var Index: Integer);
begin
  // DeN 14.11.2013
  if Index < 0 then
    Exit;
  // end DeN 14.11.2013
      
  if Length(Buffer) < (Index + 2) then
    raise ESecureBlackboxError.Create('Insufficient buffer size');
  Buffer[Index] := Byte(Value shr 8);
  Buffer[Index + 1] := Byte(Value);
  Inc(Index, 2);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SwapUInt16(const Buffer: ByteArray; Offset: Cardinal): Word;
begin
  if Offset + 2 > Cardinal(Length(Buffer)) then
    raise ESecureBlackboxError.Create(Format(
      SInvalidUInt16BufferOffset, [Offset, Length(Buffer)]));
  Result := (Buffer[Offset] shl 8) or Buffer[Offset + 1];
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SwapUInt32(value : LongWord) : LongWord;
begin
  result := (((value) shl 24) or (((value) shl 8) and $00ff0000) or (((value) shr 8) and $0000ff00) or ((value) shr 24));
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure SwapUInt32(Value: LongWord; var Buffer: ByteArray);
begin
  if Length(Buffer) <> SizeOf(Value) then
    SetLength(Buffer, SizeOf(Value));
  Buffer[0] := Byte(Value shr 24);
  Buffer[1] := Byte(Value shr 16);
  Buffer[2] := Byte(Value shr 8);
  Buffer[3] := Byte(Value);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure SwapUInt32(Value: LongWord; var Buffer: ByteArray; var Index: Integer);
begin
  // DeN 14.11.2013
  if Index < 0 then
    Exit;
  // end DeN 14.11.2013
  
  if Length(Buffer) < (Index + 4) then
    raise ESecureBlackboxError.Create('Insufficient buffer size');
  Buffer[Index] := Byte(Value shr 24);
  Buffer[Index + 1] := Byte(Value shr 16);
  Buffer[Index + 2] := Byte(Value shr 8);
  Buffer[Index + 3] := Byte(Value);
  Inc(Index, 4);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SwapUInt32(const Buffer: ByteArray; Offset: Cardinal): Cardinal;
begin
  if Offset + 4 > Cardinal(Length(Buffer)) then
    raise ESecureBlackboxError.Create(Format(
      SInvalidUInt32BufferOffset, [Offset, Length(Buffer)]));
  Result := (Buffer[Offset] shl 24) or (Buffer[Offset + 1] shl 16) or
    (Buffer[Offset + 2] shl 8) or Buffer[Offset + 3];
end;


// Done 7 / XE5(32) / XE5(64) / Android
function SwapInt64(value : Int64) : Int64;
begin
  result := Int64(SwapUInt32(value shr 32)) or (Int64(SwapUInt32(value and $ffffffff)) shl 32);
end;


// Done 7 / XE5(32) / XE5(64) / Android
function SwapSomeInt(Value : integer) : ByteArray;
begin
  if Value > $FFFFFF then
  begin
    SetLength(Result, 4);
    Result[0] := byte((Value shr 24) and $FF);
    Result[0 + 1] := byte((Value shr 16) and $FF);
    Result[0 + 2] := byte((Value shr 8) and $FF);
    Result[0 + 3] := byte(Value and $FF);
  end
  else
  if Value > $FFFF then
  begin
    SetLength(Result, 3);
    Result[0] := byte((Value shr 16) and $FF);
    Result[0 + 1] := byte((Value shr 8) and $FF);
    Result[0 + 2] := byte(Value and $FF);
  end
  else
  if Value > $FF then
  begin
    SetLength(Result, 2);
    Result[0] := byte((Value shr 8) and $FF);
    Result[0 + 1] := byte(Value and $FF);
  end
  else
  begin
    SetLength(Result, 1);
    Result[0] := byte(Value and $FF);
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
// identical to ChangeByteOrder?
function RotateInteger(const Value: ByteArray) : ByteArray;
var
  I, Len : integer;
begin
  Len := Length(Value);
  SetLength(Result, Len);
  for I := 0 to Len - 1 do
    Result[I] := Value[Len - I - 1];
end;

// Done 7 / XE5(32) / XE5(64) / Android
// identical to TrimLeadingZeros?
function TrimZeros(const Value : ByteArray): ByteArray;
var
  StartIdx : integer;
  Len : integer;
begin
  StartIdx := 0;
  Len := Length(Value);
  while (StartIdx < Len) and (Value[StartIdx] = 0) do
    Inc(StartIdx);
  SetLength(Result, Len - StartIdx);
  SBMove(Value[StartIdx], Result[0], Length(Result));
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ZeroArray(Size : integer) : ByteArray;
begin
  SetLength(Result, Size);
  FillChar(Result[0], Size, 0);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SubArray(const Arr:  ByteArray ; Index, Size : integer) : ByteArray;
begin
  if (Index >= 0) and
     (Size >= 0)  and // DeN 27.10.2013
     (Index + Size <= Length(Arr)) then
  begin
    SetLength(Result, Size);
    SBMove(Arr[Index], Result[0], Size);
  end
  else
    SetLength(Result, 0);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function StrToDigest(const DigestStr : string;
  var Digest : TMessageDigest128) : boolean;  overload; 
var 
  i: Integer;
  j: Integer;  
  Value: string;
begin
  if Length(DigestStr) <> 32 then
    result := false
  else
  begin
    for i := 0 to 3 do
    begin
      Value := StringSubstring(DigestStr, i shl 3 + StringStartOffset, 8);
      try
        j := SwapInt32(StrToInt('$' + Value));
        case i of
          0: Digest.A := j;
          1: Digest.B := j;
          2: Digest.C := j;
          3: Digest.D := j;
        end;
      except
        result := false;
        exit;
      end;
    end;
    result := true;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function StrToDigest(const DigestStr : string;
  var Digest : TMessageDigest160) : boolean;  overload; 
var 
  i: Integer;
  j: Integer;  
  Value: string;
begin
  if Length(DigestStr) <> 40 then
    result := false
  else
  begin
    for i := 0 to 4 do
    begin
      Value := StringSubstring(DigestStr, i shl 3 + StringStartOffset, 8);
      try
        j := SwapInt32(StrToInt('$' + Value));
        case i of
          0: Digest.A := j;
          1: Digest.B := j;
          2: Digest.C := j;
          3: Digest.D := j;
          4: Digest.E := j;
        end;
      except
        result := false;
        exit;
      end;
    end;
    result := true;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function DigestToStr(const Digest: TMessageDigest128;
  LowerCase: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif}): string;
var
  Buffer: array[0..15] of byte absolute Digest;
  Alphabet: PChar;
  I: integer;
begin
  if LowerCase then
    Alphabet := LowerAlphabet
  else
    Alphabet := UpperAlphabet;
  SetLength(Result, 32);
  for I := 0 to 15 do
  begin
    Result[I shl 1 + StringStartOffset] := (Alphabet + (Buffer[I] shr 4))^;
    Result[I shl 1 + StringStartOffset + 1] := (Alphabet + (Buffer[I] and $0F))^;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function DigestToStr(const Digest: TMessageDigest160;
  LowerCase: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif}): string;
var
  Buffer: array[0..19] of byte absolute Digest;
  Alphabet: PChar;
  I: integer;
begin
  if LowerCase then
    Alphabet := LowerAlphabet
  else
    Alphabet := UpperAlphabet;
  SetLength(Result, 40);
  for I := 0 to 19 do
  begin
    Result[I shl 1 + StringStartOffset] := (Alphabet + (Buffer[I] shr 4))^;
    Result[I shl 1 + StringStartOffset + 1] := (Alphabet + (Buffer[I] and $0F))^;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function DigestToStr(const Digest: TMessageDigest224;
  LowerCase: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif}): string;
var
  Buffer: array[0..27] of byte absolute Digest;
  Alphabet: PChar;
  I: integer;
begin
  if LowerCase then
    Alphabet := LowerAlphabet
  else
    Alphabet := UpperAlphabet;
  SetLength(Result, 56);
  for I := 0 to 27 do
  begin
    Result[I shl 1 + StringStartOffset] := (Alphabet + (Buffer[I] shr 4))^;
    Result[I shl 1 + StringStartOffset + 1] := (Alphabet + (Buffer[I] and $0F))^;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function DigestToStr(const Digest: TMessageDigest256;
  LowerCase: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif}): string;
var
  Buffer: array[0..31] of byte absolute Digest;
  Alphabet: PChar;
  I: integer;
begin
  if LowerCase then
    Alphabet := LowerAlphabet
  else
    Alphabet := UpperAlphabet;
  SetLength(Result, 64);
  for I := 0 to 31 do
  begin
    Result[I shl 1 + StringStartOffset] := (Alphabet + (Buffer[I] shr 4))^;
    Result[I shl 1 + StringStartOffset + 1] := (Alphabet + (Buffer[I] and $0F))^;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function DigestToStr(const Digest: TMessageDigest320;
  LowerCase: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif}): string;
var
  Buffer: array[0..39] of byte absolute Digest;
  Alphabet: PChar;
  I: integer;
begin
  if LowerCase then
    Alphabet := LowerAlphabet
  else
    Alphabet := UpperAlphabet;
  SetLength(Result, 80);
  for I := 0 to 39 do
  begin
    Result[I shl 1 + StringStartOffset] := (Alphabet + (Buffer[I] shr 4))^;
    Result[I shl 1 + StringStartOffset + 1] := (Alphabet + (Buffer[I] and $0F))^;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function DigestToStr(const Digest: TMessageDigest384;
  LowerCase: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif}): string;
var
  Buffer: array[0..47] of byte absolute Digest;
  Alphabet: PChar;
  I: integer;
begin
  if LowerCase then
    Alphabet := LowerAlphabet
  else
    Alphabet := UpperAlphabet;
  SetLength(Result, 96);
  for I := 0 to 47 do
  begin
    Result[I shl 1 + StringStartOffset] := (Alphabet + (Buffer[I] shr 4))^;
    Result[I shl 1 + StringStartOffset + 1] := (Alphabet + (Buffer[I] and $0F))^;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function DigestToStr(const Digest: TMessageDigest512;
  LowerCase: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif}): string;
var
  Buffer: array[0..63] of byte absolute Digest;
  Alphabet: PChar;
  I: integer;
begin
  if LowerCase then
    Alphabet := LowerAlphabet
  else
    Alphabet := UpperAlphabet;
  SetLength(Result, 128);
  for I := 0 to 63 do
  begin
    Result[I shl 1 + StringStartOffset] := (Alphabet + (Buffer[I] shr 4))^;
    Result[I shl 1 + StringStartOffset + 1] := (Alphabet + (Buffer[I] and $0F))^;
  end;
end;

// Todo - Example ???
function BeautifyBinaryString(const Str : string; Separator : Char): string;
var
  i : integer;
  pl: integer;
begin
  if Length(Str) mod 2 = 0 then
  begin
    pl := Length(Str) shr 1;
    SetLength(Result, Length(Str) * 3 shr 1 - 1);
    for i := 0 to pl - 1 do
    begin
       Result[i * 3 + StringStartOffset]  := Str[i shl 1 + StringStartOffset];
       Result[i * 3 + StringStartOffset + 1]  := Str[i shl 1 + StringStartOffset + 1];
      if i < pl - 1 then
         Result[i * 3 + StringStartOffset + 2]  := Separator;
    end;

  end
  //else
  //  result := Str;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function Min(const A, B: integer): integer;  overload; 
begin
  if A < B then
    Result := A
  else
    Result := B;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function Min(const A, B: cardinal): cardinal;  overload; 
begin
  if A < B then
    Result := A
  else
    Result := B;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function Min(const A, B: Int64): Int64;  overload; 
begin
  if A < B then
    Result := A
  else
    Result := B;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function Max(const A, B: integer): integer;  overload; 
begin
  if A > B then
    Result := A
  else
    Result := B;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function Max(const A, B: cardinal): cardinal;  overload; 
begin
  if A > B then
    Result := A
  else
    Result := B;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function Max(const A, B: Int64): Int64;  overload; 
begin
  if A > B then
    Result := A
  else
    Result := B;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function BufferBitCount(Buffer : pointer; Size : integer) : integer;
var
  i : integer;
  Bt : Byte;
begin
  if (Size <= 0)    or
     // DeN 21.11.2013
     (Buffer = nil) then
     // end DeN 21.11.2013
  begin
    Result := 0;
    Exit;
  end;
  
  // DeN 21.11.2013
  if Size > Length(ByteArray(Buffer)) then
    Size := Length(ByteArray(Buffer));
  // end DeN 21.11.2013  

  i := 0;
  while (i < Size - 1) and (PByteArray(Buffer)^[i] = 0) do
    Inc(i);
  Bt :=  PByteArray(Buffer)^[i] ;
  Result := (Size - i - 1) shl 3;
  while (Bt > 0) do
  begin
    Inc(Result);
    Bt := Bt shr 1;
  end;
end;

// Need - example
procedure PointerToLInt(var B : PLInt; const P : ByteArray; Size : integer);
var
  I : integer;
  {$ifdef SB_X86ASM}
  j : LongInt;
   {$endif}
begin
  if Size shr 2 > SBMath.MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  B.Length := Size shr 2;
  for I := 1 to B.Length do
  begin

    {$ifdef SB_X86ASM}
    J := PInt(@(P[0 + Size - 4]))^;
    asm
      push eax
      mov eax, j
      bswap eax
      mov J, eax
      pop eax
    end;
    B.Digits[I] := J;
     {$else}
    // DO NOT REMOVE!!!
    B.Digits[I] := (Ord(P[0 + Size - 4]) shl 24) or (Ord(P[0 + Size - 3]) shl 16) or
      (Ord(P[0 + Size - 2]) shl 8) or P[0 + Size - 1];
     {$endif}
    Dec(Size, 4);
  end;
  if Size > 0 then
  begin
    Inc(B.Length);
    I := 0;
    B.Digits[B.Length] := 0;
    while Size > 0 do
    begin
      B.Digits[B.Length] := B.Digits[B.Length] or (Ord(P[0 + Size - 1]) shl I);
      Dec(Size);
      Inc(I, 8);
    end;
  end;
  with B^ do
    while (Digits[Length] = 0) and (Length > 1) do
      Dec(Length);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure PointerToLIntP(var B : PLInt; P : pointer; Size : integer);
var
  I : integer;
  {$ifdef SB_X86ASM}
  j : LongInt;
   {$endif}
  Buf : array of byte;
begin
  // DeN 27.11.2013
  if P = nil then
    Exit;
  // end DeN 27.11.2013
  	
  if (Size mod 4) <> 0 then
  begin
    SetLength(Buf, (((Size - 1) shr 2) + 1) shl 2);
    SBMove(P^, Buf[Length(Buf) - Size], Size);
    FillChar(Buf[0], Length(Buf) - Size, 0);
    P := @Buf[0];
    Size := Length(Buf);
  end;
  if Size shr 2 > SBMath.MAXDIGIT then
    raise EElMathException.Create(sNumberTooLarge);

  B.Length := Size shr 2;
  for I := 1 to B.Length do
  begin

    {$ifdef SB_X86ASM}
    J := PInt(@(PByteArray(P)[Size - 4]))^;
    asm
      push eax
      mov eax, j
      bswap eax
      mov J, eax
      pop eax
    end;
    B.Digits[I] := J;
     {$else}
    // DO NOT REMOVE!!!
    B.Digits[I] := (PByteArray(P)[Size - 4] shl 24) or (PByteArray(P)[Size - 3] shl 16) or
      (PByteArray(P)[Size - 2] shl 8) or PByteArray(P)[Size - 1];
     {$endif}
    Dec(Size, 4);
  end;
  if Size > 0 then
  begin
    Inc(B.Length);
    I := 0;
    B.Digits[B.Length] := 0;
    while Size > 0 do
    begin
      B.Digits[B.Length] := B.Digits[B.Length] or (PByteArray(P)[Size - 1] shl I);
      Dec(Size);
      Inc(I, 8);
    end;
  end;
  with B^ do
    while (Digits[Length] = 0) and (Length > 1) do
      Dec(Length);
end;



// Need - example
procedure LIntToPointerP(B: PLInt; P: Pointer; var Size: LongInt);
var
  I, J: Integer;
begin
  // DeN 27.11.2013
  if P = nil then
    Exit;
  // end DeN 27.11.2013
  	
  if Size < B.Length shl 2 then
    raise EElMathException.Create(sOutputBufferTooSmall);

  J := 0;
  for I := B.Length downto 1 do
  begin
    PByteArray(P)[J] := (B.digits[I] shr 24) and $FF;
    PByteArray(P)[J + 1] := (B.digits[I] shr 16) and $FF;
    PByteArray(P)[J + 2] := (B.digits[I] shr 8) and $FF;
    PByteArray(P)[J + 3] := B.digits[I] and $FF;
    J := J + 4;
  end;
  Size := J;
end;

// Need - example
procedure LIntToPointer(B: PLInt; P: ByteArray; var Size: LongInt);
var
  I, J: Integer;
begin
  // DeN 27.11.2013
  if P = nil then
    Exit;
  // end DeN 27.11.2013
  	
  if Size < B.Length shl 2 then
    raise EElMathException.Create(sOutputBufferTooSmall);

  J := 0;
  for I := B.Length downto 1 do
  begin
    P[0 + J] := byte((B.digits[I] shr 24) and $FF);
    P[0 + J + 1] := byte((B.digits[I] shr 16) and $FF);
    P[0 + J + 2] := byte((B.digits[I] shr 8) and $FF);
    P[0 + J + 3] := byte(B.digits[I] and $FF);
    J := J + 4;
  end;
  Size := J;
end;


// Need - example
procedure LIntToPointerTrunc(B: PLInt; P: pointer; var Size: longint);
var
  Buf : ByteArray;
  Len : longint;
  StartIndex : integer;
begin
  Len := B.Length shl 2;
  SetLength(Buf, Len);
  LIntToPointer(B, Buf, Len);
  StartIndex := 0;
  while (StartIndex < Len) and (Buf[StartIndex] = 0) do
    Inc(StartIndex);
  if StartIndex < Len then
  begin
    if Size < Len - StartIndex then
      raise EElMathException.Create(sOutputBufferTooSmall);

    Size := Len - StartIndex;
    SBMove(Buf[StartIndex], P^, Size);
  end
  else
    Size := 0;
end;


// Todo - example
function DecodeDSASignature(Blob : pointer; Size : integer; R : pointer;
  var RSize : integer; S : pointer; var SSize : integer) : boolean;
var
  Tag, CTag : TElASN1ConstrainedTag;
  SR, SS : ByteArray;
begin
  Result := false;
  SR := EmptyArray;
  SS := EmptyArray;
  
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if Tag.LoadFromBuffer(Blob , Size ) then
    begin
      if (not Tag.IsConstrained) or (TElASN1ConstrainedTag(Tag).Count <> 1) then
        Exit;

      CTag := TElASN1ConstrainedTag(Tag.GetField(0));
      if (CTag.TagID <> SB_ASN1_SEQUENCE) then
        Exit;

      if TElASN1ConstrainedTag(CTag).Count <> 2 then
        Exit;

      if (TElASN1ConstrainedTag(CTag).GetField(0).IsConstrained) or
        (TElASN1ConstrainedTag(CTag).GetField(1).IsConstrained) or
        (TElASN1ConstrainedTag(CTag).GetField(0).TagID <> SB_ASN1_INTEGER) or
        (TElASN1ConstrainedTag(CTag).GetField(1).TagID <> SB_ASN1_INTEGER) then
        Exit;

      SR := TElASN1SimpleTag(TElASN1ConstrainedTag(CTag).GetField(0)).Content;
      SS := TElASN1SimpleTag(TElASN1ConstrainedTag(CTag).GetField(1)).Content;
      if (Length(SR) > RSize) or (Length(SS) > SSize) then
      begin
        RSize := Length(SR);
        SSize := Length(SS);
        Exit;
      end;

      SBMove(SR[0], R^, Length(SR));
      RSize := Length(SR);
      SBMove(SS[0], S^, Length(SS));
      SSize := Length(SS);
      Result := true;
    end;
  finally
    FreeAndNil(Tag);
  end;
end;

// Todo - example
function EncodeDSASignature(R : pointer; RSize : integer; S : pointer; SSize :
  integer; Blob: pointer; var BlobSize : integer) : boolean;
var
  EstSize : integer;
  BufR, BufS : ByteArray;
  Tag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
begin
  EstSize := RSize + SSize + 16;
  if BlobSize < EstSize then
  begin
    BlobSize := EstSize;
    Result := false;
    Exit;
  end;

  if PByte(R)^ >= $80 then
  begin
    SetLength(BufR, RSize + 1);
    SBMove(R^, BufR[0 + 1], RSize);
    BufR[0] := byte(0);
  end
  else
  begin
    SetLength(BufR, RSize);
    SBMove(R^, BufR[0], RSize);
  end;
  if PByte(S)^ >= $80 then
  begin
    SetLength(BufS, SSize + 1);
    SBMove(S^, BufS[0 + 1], SSize);
    BufS[0] := byte(0);
  end
  else
  begin
    SetLength(BufS, SSize);
    SBMove(S^, BufS[0], SSize);
  end;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  Tag.TagId := SB_ASN1_SEQUENCE;
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;
  STag.Content := BufR;
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;
  STag.Content := BufS;
  try
    Result := Tag.SaveToBuffer(Blob, BlobSize);
  finally
    FreeAndNil(Tag);
  end;
end;

(*
{$ifdef SB_VCL}
{$ifdef SB_UNICODE_VCL}

// Delphi 12 doesn't have a built-in FillChar
procedure FillChar(var V; Count : integer; Value : byte);
var P : PByteArray;
    i : integer;
begin
  //TODO: rewrite in assembler
  P := PByteArray(@V);
  for i := 0 to Count - 1 do
  begin
    P[i] := Value;
  end;
end;

{$endif}
{$endif}
*)

// Done 7 / XE5(32) / Android, Need - check - XE5(64)
function IsEmptyDateTime(DT : TElDateTime) : boolean;
begin
  Result := DT = 0;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function EmptyDateTime(): TElDateTime;
begin
  Result := 0;
end;

procedure SBMove(const SourcePointer; var DestinationPointer; CopyCount : Integer);
begin
  Move(SourcePointer, DestinationPointer, CopyCount);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure SBMove(Src: ByteArray; SrcOffset: Integer; Dst: ByteArray; DstOffset: Integer; Size: Integer);
begin
  if (Length(Src) = 0) or
     (Length(Dst) = 0) or
     (Size <= 0)       or
     // DeN 25.10.2013
     (SrcOffset < 0)   or
     (DstOffset < 0)   or
     (SrcOffset >= Length(Src)) or
     (DstOffset >= Length(Dst)) then
     // end DeN 25.10.2013
    Exit;
  // DeN 25.10.2013
  if (Size > Length(Dst) - DstOffset) then
    Size := Length(Dst) - DstOffset;
  // end DeN 25.10.2013
  
  SBMove(Src[SrcOffset], Dst[DstOffset], Size);
end;


// Done 7 / XE5(32) / XE5(64) / Android
function CompareMem(const Mem1:  ByteArray ; const Mem2:  ByteArray ): Boolean;   overload; 
var
  I: Integer;
begin
  Result := False;
  if Length(Mem1) <> Length(Mem2) then
  begin
    exit;
  end;
  for I := 0 to Length(Mem1) - 1 do
  begin
    if Mem1[I] <> Mem2[I] then
    begin
      Exit;
    end;
  end;
  Result := true;
end;


// Done 7 / XE5(32) / Android, Need - check in XE5(64)
function CompareMem(const Mem1: Pointer; const Mem2: Pointer; Size : integer): Boolean;
begin
  result := SysUtils.CompareMem(Mem1, Mem2, Size);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function CompareMem(const Mem1:  ByteArray ; Offset1 : integer; const Mem2:  ByteArray ; Offset2 : integer) : Boolean;  overload; 
var
  I: Integer;
begin
  Result := False;
  
  if (Length(Mem1) - Offset1 <> Length(Mem2) - Offset2) or
     // DeN 21.11.2013
     (Offset1 < 0) or
     (Offset2 < 0) then
     // end DeN 21.11.2013
    exit;

  // DeN 21.11.2013
  if (Length(Mem1) > 0) and (Offset1 > Length(Mem1) - 1) then
    Offset1 := Length(Mem1) - 1;

  if (Length(Mem2) > 0) and (Offset2 > Length(Mem2) - 1) then
    Offset2 := Length(Mem2) - 1;
  // end DeN 21.11.2013
    
  for I := Offset1 to Length(Mem1) - 1 do
  begin
    if Mem1[I] <> Mem2[I - Offset1 + Offset2] then
      Exit;
  end;
  Result := true;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function CompareMem(const Mem1:  ByteArray ; Offset1 : integer; const Mem2:  ByteArray ; Offset2 : integer; Size : integer) : Boolean;  overload; 
var
  I: Integer;
begin
  if Size = 0 then
  begin
    Result := true;
    Exit;  
  end;

  Result := False;

  if (Length(Mem1) - Offset1 < Size) or
     (Length(Mem2) - Offset2 < Size) or
     // DeN 21.11.2013
     (Offset1 < 0) or
     (Offset2 < 0) or
     (Size < 0)   then
     // end DeN 21.11.2013     
    exit;
    
  // DeN 21.11.2013
  if (Length(Mem1) > 0) and (Offset1 > Length(Mem1) - 1) then
    Offset1 := Length(Mem1) - 1;

  if (Length(Mem2) > 0) and (Offset2 > Length(Mem2) - 1) then
    Offset2 := Length(Mem2) - 1;
  // end DeN 21.11.2013        

  for I := Offset1 to Offset1 + Size - 1 do
  begin
    if Mem1[I] <> Mem2[I - Offset1 + Offset2] then
      Exit;
  end;
  Result := true;
end;



function BinaryToString(const Buffer : ByteArray; Start, Count : integer): string;

begin
  result := '';
  if Start < Length(Buffer) then 
    result := BinaryToString(@Buffer[Start], Count);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function BinaryToString(Buffer : Pointer; BufSize : integer): string;
var i : integer;
  Alphabet: PChar;
  Buf : PByteArray;
begin
  result := '';
  Buf := PByteArray(Buffer);
  
  // DeN 27.10.2013
  if Buf = nil then
    exit;
  if BufSize > Length(ByteArray(Buf)) then
    BufSize := Length(ByteArray(Buf));
  // end DeN 27.10.2013
  

  SetLength(result, BufSize shl 1);

  Alphabet := UpperAlphabet;
  for i := 0 to BufSize - 1 do
  begin
    Result[I shl 1 + StringStartOffset] := (Alphabet + (Buf^[I] shr 4))^;
    Result[I shl 1 + StringStartOffset + 1] := (Alphabet + (Buf^[I] and $0F))^;
  end;

end;

// Done 7 / XE5(32) / XE5(64) / Android
function BinaryToString(const Buffer : ByteArray): string;
begin
  Result := BinaryToString(@Buffer[0], Length(Buffer));
end;


// Need - specify
function StringToBinary(const S: string; Buffer : pointer; var Size: integer) : boolean;

  function ConvertChar(Ch: byte) : byte;
  begin
    if (Ch >= $30) and (Ch <= $39) then
      Result := Ch - $30
    else if (Ch >= $41) and (Ch <= $46) then
      Result := Ch - 55
    else if (Ch >= $61) and (Ch <= $66) then
      Result := Ch - 87
    else
      raise EConvertError.Create('String contains non-hexadecimal characters');
  end;

var
  {$ifdef SB_UNICODE_VCL}
  Buf: ByteArray;
   {$endif}
  InPtr, OutPtr : ^byte;
  BytesLeft: integer;
begin
  Result := false;
  if Length(S) and 1 = 1 then
    Exit;

  if Size < Length(S) shr 1 then
  begin
    Size := Length(S) shr 1;
    Exit;
  end;

  {$ifndef SB_UNICODE_VCL}
  InPtr := @S[StringStartOffset];
   {$else}
  Buf := BytesOfString(S);
  InPtr := @Buf[0];
   {$endif}
  OutPtr := Buffer;
  BytesLeft := Length(S);
  while BytesLeft > 0 do
  begin
    OutPtr^ := (ConvertChar(InPtr^) shl 4) or ConvertChar(PByteArray(InPtr)[1]);
    Inc(InPtr, 2);
    Inc(OutPtr);
    Dec(BytesLeft, 2);
  end;
  Size := Length(S) shr 1;

  Result := True;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure SwapBigEndianWords(P: Pointer; Size: LongInt);
var p1 : PByteArray;
    i : integer;
    b : byte;
begin
  // DeN 21.11.2013
  if (P = nil) or (Size < 0) then
    Exit;

  if Size > Length(ByteArray(p)) then
    Size := Length(ByteArray(p));
  // end DeN 21.11.2013
  	
  p1 := PByteArray(p);
  for i := 0 to (size shr 1) - 1 do
  begin
    b := p1[i shl 1];
    p1[i shl 1] := p1[i shl 1 + 1];
    p1[i shl 1 + 1] := b;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure SwapBigEndianDWords(P: Pointer; Size: LongInt);
var
  p1 : PByteArray;
  i, k : integer;
  b : byte;
begin
  // DeN 21.11.2013
  if (P = nil) or (Size < 0) then
    Exit;

  if Size > Length(ByteArray(p)) then
    Size := Length(ByteArray(p));    
  // end DeN 21.11.2013
  	
  p1 := PByteArray(p);
  for i := 0 to (size shr 2) - 1 do
  begin
    k := i  shl 2;
    b := p1[k];
    p1[k] := p1[k + 3];
    p1[k + 3] := b;
    b := p1[k + 1];
    p1[k + 1] := p1[k + 2];
    p1[k + 2] := b;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function BinaryToDigest(const Binary : ByteArray; var Digest : TMessageDigest128) : boolean;
begin
  result := false;
  if Length(Binary) <> 16 then exit;
  SBMove(Binary[0], Digest, 16);
  result := true;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function BinaryToDigest(const Binary : ByteArray; var Digest : TMessageDigest160) : boolean;
begin
  result := false;
  if Length(Binary) <> 20 then exit;
  SBMove(Binary[0], Digest, 20);
  result := true;
end;


// Done 7 / XE5(32) / XE5(64) / Android
// identical to DigestToByteArray128?
function DigestToBinary(const Digest : TMessageDigest128) : ByteArray;
begin
  SetLength(Result, 16);
  SBMove(Digest, Result[0], 16);
end;

// Done 7 / XE5(32) / XE5(64) / Android
// identical to DigestToByteArray160?
function DigestToBinary(const Digest : TMessageDigest160) : ByteArray;
begin
  SetLength(Result, 20);
  SBMove(Digest, Result[0], 20);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function DigestToByteArray128(const Digest : TMessageDigest128) : ByteArray;
begin
  SetLength(Result, 16);
  GetByteArrayFromDWordLE(Digest.A, Result, 0);
  GetByteArrayFromDWordLE(Digest.B, Result, 4);
  GetByteArrayFromDWordLE(Digest.C, Result, 8);
  GetByteArrayFromDWordLE(Digest.D, Result, 12);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function DigestToByteArray160(const Digest : TMessageDigest160) : ByteArray;
begin
  SetLength(Result, 20);
  GetByteArrayFromDWordLE(Digest.A, Result, 0);
  GetByteArrayFromDWordLE(Digest.B, Result, 4);
  GetByteArrayFromDWordLE(Digest.C, Result, 8);
  GetByteArrayFromDWordLE(Digest.D, Result, 12);
  GetByteArrayFromDWordLE(Digest.E, Result, 16);  
end;

// Done 7 / XE5(32) / XE5(64) / Android
function DigestToByteArray224(const Digest : TMessageDigest224) : ByteArray;
begin
  SetLength(Result, 28);
  GetByteArrayFromDWordLE(Digest.A1, Result, 0);
  GetByteArrayFromDWordLE(Digest.B1, Result, 4);
  GetByteArrayFromDWordLE(Digest.C1, Result, 8);
  GetByteArrayFromDWordLE(Digest.D1, Result, 12);
  GetByteArrayFromDWordLE(Digest.A2, Result, 16);
  GetByteArrayFromDWordLE(Digest.B2, Result, 20);
  GetByteArrayFromDWordLE(Digest.C2, Result, 24);  
end;

// Done 7 / XE5(32) / XE5(64) / Android
function DigestToByteArray256(const Digest : TMessageDigest256) : ByteArray;
begin
  SetLength(Result, 32);
  GetByteArrayFromDWordLE(Digest.A1, Result, 0);
  GetByteArrayFromDWordLE(Digest.B1, Result, 4);
  GetByteArrayFromDWordLE(Digest.C1, Result, 8);
  GetByteArrayFromDWordLE(Digest.D1, Result, 12);
  GetByteArrayFromDWordLE(Digest.A2, Result, 16);
  GetByteArrayFromDWordLE(Digest.B2, Result, 20);
  GetByteArrayFromDWordLE(Digest.C2, Result, 24);
  GetByteArrayFromDWordLE(Digest.D2, Result, 28);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function DigestToByteArray320(const Digest : TMessageDigest320) : ByteArray;
begin
  SetLength(Result, 40);
  GetByteArrayFromDWordLE(Digest.A1, Result, 0);
  GetByteArrayFromDWordLE(Digest.B1, Result, 4);
  GetByteArrayFromDWordLE(Digest.C1, Result, 8);
  GetByteArrayFromDWordLE(Digest.D1, Result, 12);
  GetByteArrayFromDWordLE(Digest.E1, Result, 16);
  GetByteArrayFromDWordLE(Digest.A2, Result, 20);
  GetByteArrayFromDWordLE(Digest.B2, Result, 24);
  GetByteArrayFromDWordLE(Digest.C2, Result, 28);
  GetByteArrayFromDWordLE(Digest.D2, Result, 32);
  GetByteArrayFromDWordLE(Digest.E2, Result, 36);
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function DigestToByteArray384(const Digest : TMessageDigest384) : ByteArray;
begin
  SetLength(Result, 48);
  GetByteArrayFromInt64LE(Digest.A, Result, 0);
  GetByteArrayFromInt64LE(Digest.B, Result, 8);
  GetByteArrayFromInt64LE(Digest.C, Result, 16);
  GetByteArrayFromInt64LE(Digest.D, Result, 24);
  GetByteArrayFromInt64LE(Digest.E, Result, 32);
  GetByteArrayFromInt64LE(Digest.F, Result, 40);
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function DigestToByteArray512(const Digest : TMessageDigest512) : ByteArray;
begin
  SetLength(Result, 64);
  GetByteArrayFromInt64LE(Digest.A1, Result, 0);
  GetByteArrayFromInt64LE(Digest.B1, Result, 8);
  GetByteArrayFromInt64LE(Digest.C1, Result, 16);
  GetByteArrayFromInt64LE(Digest.D1, Result, 24);
  GetByteArrayFromInt64LE(Digest.A2, Result, 32);
  GetByteArrayFromInt64LE(Digest.B2, Result, 40);
  GetByteArrayFromInt64LE(Digest.C2, Result, 48);
  GetByteArrayFromInt64LE(Digest.D2, Result, 56);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ByteArrayToDigest128(const Binary : ByteArray; Position : integer; var Digest : TMessageDigest128) : boolean;
begin
  if Position + Length(Binary) >= 16 then
  begin
    Digest.A := GetDWordLEFromByteArray(Binary, Position + 0);
    Digest.B := GetDWordLEFromByteArray(Binary, Position + 4);
    Digest.C := GetDWordLEFromByteArray(Binary, Position + 8);
    Digest.D := GetDWordLEFromByteArray(Binary, Position + 12);
    result := true;
  end
  else
    result := false;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ByteArrayToDigest160(const Binary : ByteArray; Position : integer; var Digest : TMessageDigest160) : boolean;
begin
  if Position + Length(Binary) >= 20 then
  begin
    Digest.A := GetDWordLEFromByteArray(Binary, Position + 0);
    Digest.B := GetDWordLEFromByteArray(Binary, Position + 4);
    Digest.C := GetDWordLEFromByteArray(Binary, Position + 8);
    Digest.D := GetDWordLEFromByteArray(Binary, Position + 12);
    Digest.E := GetDWordLEFromByteArray(Binary, Position + 16);
    result := true;
  end
  else
    result := false;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ByteArrayToDigest224(const Binary : ByteArray; Position : integer; var Digest : TMessageDigest224) : boolean;
begin
  if Position + Length(Binary) >= 28 then
  begin
    Digest.A1 := GetDWordLEFromByteArray(Binary, Position + 0);
    Digest.B1 := GetDWordLEFromByteArray(Binary, Position + 4);
    Digest.C1 := GetDWordLEFromByteArray(Binary, Position + 8);
    Digest.D1 := GetDWordLEFromByteArray(Binary, Position + 12);
    Digest.A2 := GetDWordLEFromByteArray(Binary, Position + 16);
    Digest.B2 := GetDWordLEFromByteArray(Binary, Position + 20);
    Digest.C2 := GetDWordLEFromByteArray(Binary, Position + 24);
    result := true;
  end
  else
    result := false;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ByteArrayToDigest256(const Binary : ByteArray; Position : integer; var Digest : TMessageDigest256) : boolean;
begin
  if Position + Length(Binary) >= 32 then
  begin
    Digest.A1 := GetDWordLEFromByteArray(Binary, Position + 0);
    Digest.B1 := GetDWordLEFromByteArray(Binary, Position + 4);
    Digest.C1 := GetDWordLEFromByteArray(Binary, Position + 8);
    Digest.D1 := GetDWordLEFromByteArray(Binary, Position + 12);
    Digest.A2 := GetDWordLEFromByteArray(Binary, Position + 16);
    Digest.B2 := GetDWordLEFromByteArray(Binary, Position + 20);
    Digest.C2 := GetDWordLEFromByteArray(Binary, Position + 24);
    Digest.D2 := GetDWordLEFromByteArray(Binary, Position + 28);

    result := true;
  end
  else
    result := false;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ByteArrayToDigest320(const Binary : ByteArray; Position : integer; var Digest : TMessageDigest320) : boolean;
begin
  if Position + Length(Binary) >= 40 then
  begin
    Digest.A1 := GetDWordLEFromByteArray(Binary, Position + 0);
    Digest.B1 := GetDWordLEFromByteArray(Binary, Position + 4);
    Digest.C1 := GetDWordLEFromByteArray(Binary, Position + 8);
    Digest.D1 := GetDWordLEFromByteArray(Binary, Position + 12);
    Digest.E1 := GetDWordLEFromByteArray(Binary, Position + 16);
    Digest.A2 := GetDWordLEFromByteArray(Binary, Position + 20);
    Digest.B2 := GetDWordLEFromByteArray(Binary, Position + 24);
    Digest.C2 := GetDWordLEFromByteArray(Binary, Position + 28);
    Digest.D2 := GetDWordLEFromByteArray(Binary, Position + 32);
    Digest.E2 := GetDWordLEFromByteArray(Binary, Position + 36);

    result := true;
  end
  else
    result := false;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ByteArrayToDigest384(const Binary : ByteArray; Position : integer; var Digest : TMessageDigest384) : boolean;
begin
  if Position + Length(Binary) >= 48 then
  begin
    Digest.A := GetInt64LEFromByteArray(Binary, Position + 0);
    Digest.B := GetInt64LEFromByteArray(Binary, Position + 8);
    Digest.C := GetInt64LEFromByteArray(Binary, Position + 16);
    Digest.D := GetInt64LEFromByteArray(Binary, Position + 24);
    Digest.E := GetInt64LEFromByteArray(Binary, Position + 32);
    Digest.F := GetInt64LEFromByteArray(Binary, Position + 40);

    result := true;
  end
  else
    result := false;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ByteArrayToDigest512(const Binary : ByteArray; Position : integer; var Digest : TMessageDigest512) : boolean;
begin
  if Position + Length(Binary) >= 64 then
  begin
    Digest.A1 := GetInt64LEFromByteArray(Binary, Position + 0);
    Digest.B1 := GetInt64LEFromByteArray(Binary, Position + 8);
    Digest.C1 := GetInt64LEFromByteArray(Binary, Position + 16);
    Digest.D1 := GetInt64LEFromByteArray(Binary, Position + 24);
    Digest.A2 := GetInt64LEFromByteArray(Binary, Position + 32);
    Digest.B2 := GetInt64LEFromByteArray(Binary, Position + 40);
    Digest.C2 := GetInt64LEFromByteArray(Binary, Position + 48);
    Digest.D2 := GetInt64LEFromByteArray(Binary, Position + 56);
    result := true;
  end
  else
    result := false;
end;

// DeN 19.11.2013S
// Inner - Not tested
function IsStrHasOnlyDigitsAndZ (const S: String): Boolean;
var I: Integer;
begin
  Result := FALSE;

  if S = '' then
    exit;

  for I := StringStartOffset to Length(S) - StringStartInvOffset do
    {$ifndef SB_UNICODE_VCL}
    if not (S[I] in ['0'..'9']) and
     {$else}
    if not CharInSet(S[I], ['0'..'9']) and // DeN 25.12.2013
     {$endif}
    (S[I] <> 'Z') then // DeN 16.12.2013
      exit;

  Result := TRUE
end;
// end DeN 19.11.2013

// Done 7 / XE5(32) / XE5(64) / Android
function UTCTimeToDate(const UTCTime: string; FourDigitYear : boolean {$ifdef HAS_DEF_PARAMS} =   false {$endif}):  TDateTime ;
var
  Y, M, D: Word;
  Str: string;
  YearOffs : integer;
begin
  // DeN 19.11.2013
  Result := (0);
  if not IsStrHasOnlyDigitsAndZ(UTCTime) then exit;
  // end DeN 19.11.2013
  	
  if FourDigitYear then
    YearOffs := 2
  else
    YearOffs := 0;
  if Length(UTCTime) < 6 + YearOffs then
  begin
    result := 0;
    exit;
  end;
  // year
  if FourDigitYear then
  begin
    Str := StringSubstring(UTCTime, StringStartOffset, 4);
    Y := Word(StrToIntDef(Str, 0));
  end
  else
  begin
    Str := StringSubstring(UTCTime, StringStartOffset, 2);
    Y := Word(StrToIntDef(Str, 0));
    if (Y >= 50) then
      Y := (1900 + Y)
    else
      Y := (2000 + Y);
  end;
  // month
  Str := StringSubstring(UTCTime, StringStartOffset + 2 + YearOffs {+ StringStartInvOffset}, 2); // DeN 06.01.2014 - add StringStartInvOffset
  M := Word(StrToIntDef(Str, 1));
  // day
  Str := StringSubstring(UTCTime, StringStartOffset + 4 + YearOffs {+ StringStartInvOffset}, 2); // DeN 06.01.2014 - add StringStartInvOffset
  D := Word(StrToIntDef(Str, 1));

  Result := EncodeDate(Y, M, D);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function UTCTimeToTime(const UTCTime: string; FourDigitYear : boolean {$ifdef HAS_DEF_PARAMS} =   false {$endif}):  TDateTime ;
var
  H, M, S: Word;
  Str: string;
  YearOffs : integer;
begin
  // DeN 19.11.2013
  Result := (0);
  if not IsStrHasOnlyDigitsAndZ(UTCTime) then exit;
  // end DeN 19.11.2013
  	
  if FourDigitYear then
    YearOffs := 2
  else
    YearOffs := 0;

  // hour
  Str := StringSubstring(UTCTime, StringStartOffset + 6 + YearOffs {+ StringStartInvOffset}, 2); // DeN 06.01.2014 - add StringStartInvOffset
  H := Word(StrToIntDef(Str, 0));

  // minute
  Str := StringSubstring(UTCTime, StringStartOffset + 8 + YearOffs {+ StringStartInvOffset}, 2); // DeN 06.01.2014 - add StringStartInvOffset
  M := Word(StrToIntDef(Str, 0));

  // second
  Str := StringSubstring(UTCTime, 10 + YearOffs + StringStartOffset, 2);
  S := Word(StrToIntDef(Str, 0));

  Result := EncodeTime(H, M, S, 0);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function UTCTimeToDateTime(const UTCTime: string; FourDigitYear : boolean {$ifdef HAS_DEF_PARAMS} =   false {$endif}):  TDateTime ;
begin
  Result := UTCTimeToDate(UTCTime, FourDigitYear) + UTCTimeToTime(UTCTime, FourDigitYear);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function GeneralizedTimeToDate(const GenTime: string):  TDateTime ;
var
  Y, M, D: Word;
  Str: string;
begin
  // DeN 11.11.2013
  Result := (0);
  if Length(GenTime) = 0 then
    Exit;
  // end DeN 11.11.2013
  	
  // year
  // hour
  Str := StringSubstring(GenTime, StringStartOffset, 4);
  Y := Word(StrToIntDef(Str, 0));

  // month
  //SetLength(Str, 2);
  Str := StringSubstring(GenTime, StringStartOffset + 4 {+ StringStartInvOffset}, 2); // DeN 06.01.2014 - add StringStartInvOffset
  M := Word(StrToIntDef(Str, 1));

  // day
  Str := StringSubstring(GenTime, StringStartOffset + 6 {+ StringStartInvOffset}, 2); // DeN 06.01.2014 - add StringStartInvOffset
  D := Word(StrToIntDef(Str, 1));

  // DeN 11.11.2013
  if (Y > 0) and (M > 0) and (M < 13) and (D > 0) and (D < 32) then
    Result := EncodeDate(Y, M, D);
  // end DeN 11.11.2013
end;

// Done 7 / XE5(32) / XE5(64) / Android
function GeneralizedTimeToTime(const GenTime: string):  TDateTime ;
var
  H, M, S, MS: Word;
  Str: string;
begin
  // DeN 11.11.2013
  Result := (0);
  if Length(GenTime) = 0 then
    Exit;
  // end DeN 11.11.2013
  	
  // hour
  Str := StringSubstring(GenTime, StringStartOffset + 8 {+ StringStartInvOffset}, 2); // DeN 06.01.2014 - add StringStartInvOffset
  H := Word(StrToIntDef(Str, 0));

  // minute
  Str := StringSubstring(GenTime, StringStartOffset + 10 {+ StringStartInvOffset}, 2); // DeN 06.01.2014 - add StringStartInvOffset
  M := Word(StrToIntDef(Str, 0));

  // second
  Str := StringSubstring(GenTime, StringStartOffset + 12 {+ StringStartInvOffset}, 2); // DeN 06.01.2014 - add StringStartInvOffset
  S := Word(StrToIntDef(Str, 0));

  // possibly milliseconds
  if (Length(GenTime) >= 18) and (GenTime[15 - StringStartInvOffset] = '.') then
  begin
    Str := StringSubstring(GenTime, StringStartOffset + 15, 3);
    MS := Word(StrToIntDef(Str, 0));
  end
  else
    MS := 0;

  // DeN 11.11.2013
  if (H < 24) and (M < 60) and (S < 60) and (MS < 1000) then
    Result := EncodeTime(H, M, S, MS);
  // end DeN 11.11.2013
end;

// Done 7 / XE5(32) / XE5(64) / Android
function GeneralizedTimeToDateTime(const GenTime: string):  TDateTime ;
begin
  Result := GeneralizedTimeToDate(GenTime) + GeneralizedTimeToTime(GenTime);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function DateTimeToUTCTime(const ADateTime :  TDateTime ; FourDigitYear : boolean {$ifdef HAS_DEF_PARAMS} =  false {$endif}) : string;
var
  T1, T2, T3 , T4 : WORD;
  S1, S2, S3: string;
begin
  {$ifdef FPC}
  T1 := 0;
  T2 := 0;
  T3 := 0;
   {$endif}
  DecodeDate(ADateTime, T1, T2, T3);
  if not FourDigitYear then
    T1 := T1 mod 100;
  T2 := T2 mod 100;
  T3 := T3 mod 100;

  S1 := IntToStr(T1);
  S2 := IntToStr(T2);
  S3 := IntToStr(T3);
  if (Length(S1) = 1) and (not FourDigitYear) then S1 := '0' + S1;
  if Length(S2) = 1 then S2 := '0' + S2;
  if Length(S3) = 1 then S3 := '0' + S3;

  Result := S1 + S2 + S3;

  {$ifdef FPC}
  T4 := 0;
   {$endif}
  DecodeTime(ADateTime, T1, T2, T3, T4);
  S1 := IntToStr(T1);
  S2 := IntToStr(T2);
  S3 := IntToStr(T3);
  if Length(S1) = 1 then S1 := '0' + S1;
  if Length(S2) = 1 then S2 := '0' + S2;
  if Length(S3) = 1 then S3 := '0' + S3;
  Result := Result + S1 + S2 + S3 + 'Z';
end;

// Done 7 / XE5(32) / XE5(64) / Android
function DateTimeToGeneralizedTime(const ADateTime :  TDateTime ) : string;
var
  T1, T2, T3 , T4 : WORD;
  S1, S2, S3: string;
begin
  DecodeDate(ADateTime, T1, T2, T3);
  T2 := T2 mod 100;
  T3 := T3 mod 100;
  S1 := IntToStr(T1);
  S2 := IntToStr(T2);
  S3 := IntToStr(T3);
  while Length(S1) < 4 do S1 := '0' + S1;
  if Length(S2) = 1 then S2 := '0' + S2;
  if Length(S3) = 1 then S3 := '0' + S3;
  Result := S1 + S2 + S3;

  DecodeTime(ADateTime, T1, T2, T3, T4);
  S1 := IntToStr(T1);
  S2 := IntToStr(T2);
  S3 := IntToStr(T3);
  if Length(S1) = 1 then S1 := '0' + S1;
  if Length(S2) = 1 then S2 := '0' + S2;
  if Length(S3) = 1 then S3 := '0' + S3;
  Result := Result + S1 + S2 + S3 + 'Z';
end;


{$ifdef WIN32}
type
  TGetTimeZoneInformationForYearProc = function (Year: Word; Optional: Pointer;
    out Info: TTimeZoneInformation): BOOL; stdcall;
  TTzSpecificLocalTimeToSystemTimeProc = function (TimeZone: PTimeZoneInformation;
    const LocalTime: TSystemTime; out SystemTime: TSystemTime): BOOL; stdcall;
  TSystemTimeToTzSpecificLocalTimeProc = function (TimeZone: PTimeZoneInformation;
    const SystemTime: TSystemTime; out LocalTime: TSystemTime): BOOL; stdcall;

var
  GetTimeZoneInformationForYear: TGetTimeZoneInformationForYearProc = nil;
  TzSpecificLocalTimeToSystemTime: TTzSpecificLocalTimeToSystemTimeProc = nil;
  SystemTimeToTzSpecificLocalTime: TSystemTimeToTzSpecificLocalTimeProc = nil;
  TimeProcsChecked: Boolean = False;

procedure LoadTimeFunctions();
var
  Handle: HModule;
begin
  if TimeProcsChecked then
    Exit;

  TimeProcsChecked := True;
  Handle := GetModuleHandle(KERNEL32);
  if Handle <> 0 then
  begin
    GetTimeZoneInformationForYear := GetProcAddress(Handle, 'GetTimeZoneInformationForYear');
    TzSpecificLocalTimeToSystemTime := GetProcAddress(Handle, 'TzSpecificLocalTimeToSystemTime');
    SystemTimeToTzSpecificLocalTime := GetProcAddress(Handle, 'SystemTimeToTzSpecificLocalTime');
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function UTCTimeToLocalTime(UtcTime : TDateTime): TDateTime;
var
  ZoneInfo: TTimeZoneInformation;
  Year, Month, Day: Word;
  ST, LT: TSystemTime;
begin
  LoadTimeFunctions();

  FillChar(ZoneInfo, SizeOf(ZoneInfo), 0);
  DecodeDate(UtcTime, Year, Month, Day);

  if (@GetTimeZoneInformationForYear = nil) or not GetTimeZoneInformationForYear(Year, nil, ZoneInfo) then
    GetTimeZoneInformation(ZoneInfo);

  DateTimeToSystemTime(UtcTime, ST);
  if (@SystemTimeToTzSpecificLocalTime <> nil) and SystemTimeToTzSpecificLocalTime(@ZoneInfo, ST, LT) then
    Result := SystemTimeToDateTime(LT)
  else
    Result := Time;
end;
 {$else}
// Todo - Linux
function UTCTimeToLocalTime(UtcTime : TDateTime): TDateTime;
begin
  result := UtcTime;
end;
 {$endif}



{$ifdef WIN32}
// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function LocalTimeToUTCTime(LocalTime : TDateTime): TDateTime;
var
  ZoneInfo: TTimeZoneInformation;
  Year, Month, Day: Word;
  LT, ST: TSystemTime;
begin
  LoadTimeFunctions();

  DecodeDate(Time, Year, Month, Day);
  FillChar(ZoneInfo, SizeOf(ZoneInfo), 0);

  if (@GetTimeZoneInformationForYear = nil) or not GetTimeZoneInformationForYear(Year, nil, ZoneInfo) then
    GetTimeZoneInformation(ZoneInfo);

  DateTimeToSystemTime(LocalTime, LT);
  if (@TzSpecificLocalTimeToSystemTime = nil) or not TzSpecificLocalTimeToSystemTime(@ZoneInfo, LT, ST) then
    Result := LocalTime
  else
    Result := SystemTimeToDateTime(ST);
end;
 {$else}
// Todo - Linux
function LocalTimeToUTCTime(LocalTime : TDateTime): TDateTime;
(*
var T : time_t;
  ltv,
    gtv : timeval;
    gtv_r: TDateTime;
    ltv_r: TDateTime;
  ut : tm; *)
begin
(*  fpgettimeofday(@gtv, nil);
  t := ltv.tv_sec;
  gmtime_r(@t, @ut);
  gtv_r := EncodeDateTime(ut.tm_year + 1900, ut.tm_mon + 1, ut.tm_mday,
    0, 0, 0, 0);
  localtime_r(@t, @ut);
  ltv_r := EncodeDateTime(ut.tm_year + 1900, ut.tm_mon + 1, ut.tm_mday,
    0, 0, 0, 0);
  result := Time - (ltv_r - gtv_r);
*)
  result := LocalTime;
end;
 {$endif}


{$ifdef DELPHI_MAC}
type
  timezone = packed record
    tz_minuteswest, tz_dsttime : LongInt;
  end;

  ptimezone =^timezone;
  TTimeZone = timezone;
 {$endif}

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function GetUTCOffsetDateTime: TDateTime;
{$ifdef SB_WINDOWS}
var
  iBias, iBiasAbs: Integer;
  tzi: TTimeZoneInformation;
begin
  case GetTimeZoneInformation(tzi) of
    TIME_ZONE_ID_UNKNOWN  :
      iBias := tzi.Bias;
    TIME_ZONE_ID_DAYLIGHT :
      iBias := tzi.Bias + tzi.DaylightBias;
    TIME_ZONE_ID_STANDARD :
      iBias := tzi.Bias + tzi.StandardBias;
    else
      iBias := 0;
  end;
  if iBias < 0 then
    iBiasAbs := - iBias
  else
    iBiasAbs := iBias;
  Result := EncodeTime(iBiasAbs div 60, iBiasAbs mod 60, 0, 0);
  if iBias > 0 then
    Result := 0 - Result;
end;
 {$else SB_WINDOWS}
{$ifdef FPC}  // Linux and MacOS using FPC
var
  iBiasAbs: Integer;
begin
  if Tzseconds < 0 then
    iBiasAbs := - Tzseconds div 60
  else
    iBiasAbs := Tzseconds div 60;
  Result := EncodeTime(iBiasAbs div 60, iBiasAbs mod 60, 0, 0);
  if Tzseconds > 0 then
    Result := 0 - Result;
end;
 {$else FPC}
{$ifdef SB_POSIX}
var
  T: time_t;
  TV: timeval;
  UT, LT: tm;
begin
  gettimeofday(TV, nil);
  T := TV.tv_sec;
  gmtime_r(T, UT);
  localtime_r(T, LT);
  Result := EncodeTime(LT.tm_gmtoff div 3600, (LT.tm_gmtoff mod 3600) div 60, 0, 0);
  //Result := ((UT.tm_hour - LT.tm_hour) * 3600 + (UT.tm_min - LT.tm_min) * 60 +
    //(UT.tm_sec - LT.tm_sec)) div 86400; //return 0 = 30.12.1899 without time
end;
 {$endif}
 {$endif FPC}
 {$endif SB_WINDOWS}


// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function LocalDateTimeToSystemDateTime(ADateTime: TElDateTime): TElDateTime;
begin
  if ADateTime = 0 then
    ADateTime := Now; // == Local DateTime
  Result := ADateTime + GetUTCOffsetDateTime;
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function SystemDateTimeToLocalDateTime(ADateTime: TElDateTime): TElDateTime;
begin
  Result := ADateTime - GetUTCOffsetDateTime;
end;



function UTCNow() : TElDateTime;
begin
  Result := DateTimeUtcNow();
end;


// Todo - Linux
function FileTimeToUnixTime(Value : FILETIME): int64;
begin
  Result := ((Int64(ULARGE_INTEGER(Value)) - Int64(116444736000000000)) div 10000000);
end;

// Todo - Linux
function UnixTimeToFileTime(Value : int64): FILETIME;
var
  ll : int64;
begin
  ll := Value * 10000000 + 116444736000000000;
  result.dwLowDateTime := DWORD(ll);
  result.dwHighDateTime := ll shr 32;
end;

{$ifdef SB_WINDOWS}
// Done 7 / XE5(32) / XE5(64)
function FileTimeToDateTime(Value : FILETIME): TDateTime;
var
  ST : TSystemTime;
begin
  // the function expects Value to be set in UTC. No conversion to local file time is performed.
  if not FileTimeToSystemTime(Value, ST) then
    Result := 0
  else
    Result := SystemTimeToDateTime(ST);
end;

// Done 7 / XE5(32) / XE5(64)
function DateTimeToFileTime(Value : TDateTime): FILETIME;
var
  ST : TSystemTime;
begin
  // the function expects Value to be set in UTC. No conversion to local file time is performed.
  DateTimeToSystemTime(Value, ST);
  Result.dwLowDateTime := 0;
  Result.dwHighDateTime := 0;
  SystemTimeToFileTime(ST, Result);
end;
 {$else}

const FTOffset : int64 = 9435312000000;

// Inner - Not tested
function FileTimeToDateTime(Value : FileTime) : TDateTime;
var i64 : Int64Rec;
    i64val : Int64;
begin
  i64.Hi := Value.dwHighDateTime;
  i64.Lo := Value.dwLowDateTime;
  i64val := Int64(i64);
  result := ((i64val / 10000) - FTOffset) / 86400000;
end;

// Inner - Not tested
function DateTimeToFileTime(Value : TDateTime) : FileTime;
var i64 : Int64Rec;
    i64val : Int64;
begin
  i64val := Trunc(((Value * 86400000) + FTOffset) * 10000);
  i64 := Int64Rec(i64val);
  result.dwLowDateTime := i64.Lo;
  result.dwHighDateTime := i64.Hi;
end;
 {$endif}


// Done 7 / XE5(32) / XE5(64) / Android
function UnixTimeToDateTime(Value: Int64): TDateTime;
begin
  {$ifdef FPC}
  // without Double will loose accuracy on iOS/arm or 64-bit system
  Result := EncodeDate(1970, 1, 1) + (Value * Double(1.0)) / Double(86400.0);
   {$else}
  Result := EncodeDate(1970, 1, 1) + Value / 86400.0;
   {$endif}
end;

// Done 7 / XE5(32) / XE5(64) / Android
function DateTimeToUnixTime(Value : TDateTime): Int64;
begin
  Result := Round((Value - EncodeDate(1970, 1, 1)) * 86400);
end;


  {$ifdef SB_WINDOWS}
var
  GlobalObjectListCS : TRTLCriticalSection;
   {$else}
var
  GlobalObjectListCS : TCriticalSection;
   {$endif}


// Inner - Not tested
procedure InitGlobalObjectList;
begin
  if GlobalObjectList = nil then
  begin
    {$ifdef WIN32}
    InitializeCriticalSection(GlobalObjectListCS);
     {$else}
    GlobalObjectListCS := TCriticalSection.Create();
     {$endif}
    GlobalObjectList := TElList.Create;
  end;
end;

// Inner - Not tested
procedure FinalGlobalObjectList;
begin
  if GlobalObjectList <> nil then
  begin
    {$ifdef WIN32}
    DeleteCriticalSection(GlobalObjectListCS);
     {$else}
    FreeAndNil(GlobalObjectListCS);
     {$endif}
    FreeAndNil(GlobalObjectList);
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure RegisterGlobalObject(O :  TObject );
begin
  InitGlobalObjectList;
  {$ifdef WIN32}
  EnterCriticalSection(GlobalObjectListCS);
   {$else}
  GlobalObjectListCS.Acquire;
   {$endif}
  try
    if GlobalObjectList.IndexOf(O) < 0 then
      GlobalObjectList.Add(O);
  finally
    {$ifdef WIN32}
    LeaveCriticalSection(GlobalObjectListCS);
     {$else}
    GlobalObjectListCS.Release;
     {$endif}
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure UnregisterGlobalObject(O :  TObject );
var
  Index : integer;
begin
  InitGlobalObjectList;
  {$ifdef WIN32}
  EnterCriticalSection(GlobalObjectListCS);
   {$else}
  GlobalObjectListCS.Acquire;
   {$endif}
  try
    Index := GlobalObjectList.IndexOf(O);
    if Index >= 0 then
      GlobalObjectList. Delete (Index);
  finally
    {$ifdef WIN32}
    LeaveCriticalSection(GlobalObjectListCS);
     {$else}
    GlobalObjectListCS.Release;
     {$endif}
  end;
end;

// Inner - Not tested
procedure CreateGlobalLock();
var
  LocalLockCS :
    {$ifdef SB_WINDOWS}
    ^TRTLCriticalSection;
     {$else}
    TCriticalSection;
     {$endif}
  FlagValue : integer;
  //TickStart : cardinal;
begin
  LocalLockCS := nil;

  // - creating local critical section object
  if GlobalLockCS = nil then
  begin
    {$ifdef SB_WINDOWS}
    GetMem(LocalLockCS, SizeOf(TRTLCriticalSection));
    InitializeCriticalSection(LocalLockCS^);
     {$else}
    LocalLockCS := TCriticalSection.Create();
     {$endif}
  end;

  // doing interlocked increment on a global variable
  {$ifdef SB_WINDOWS}
  FlagValue := InterlockedIncrement(GlobalLockCSFlag);
   {$endif SB_WINDOWS}
  {$ifdef SB_MACOS}
  //FlagValue := IncrementAtomic(GlobalLockCSFlag) + 1;
  Inc(GlobalLockCSFlag);
  FlagValue := GlobalLockCSFlag;
   {$else}
  {$ifdef SB_UNIX}
  Inc(GlobalLockCSFlag);
  FlagValue := GlobalLockCSFlag;
   {$endif SB_UNIX}
   {$endif SB_MACOS}

  if FlagValue = 1 then // we are the first, so we have the right to create the lock
  begin
    GlobalLockCS :=  pointer (LocalLockCS);
  end
  else
  begin
    // destroying the critical section we've created
    {$ifdef SB_WINDOWS}
    DeleteCriticalSection(LocalLockCS^);
    FreeMem(LocalLockCS);
     {$else}
    FreeAndNil(LocalLockCS);
     {$endif SB_WINDOWS}

    // waiting for the concurrent thread to set the critical section variable
    while (GlobalLockCS = nil) do
      Sleep(20);//{$ifdef SB_NET}System.Threading.Thread.{$endif}{$ifdef SB_JAVA}JLThread.currentThread().{$endif}Sleep(20);
  end;
end;

// Inner - Not tested
procedure FreeGlobalLock();
begin
  if GlobalLockCS = nil then
    Exit;

  GlobalLockCSFlag := 0;

  {$ifdef SB_WINDOWS}
  DeleteCriticalSection(GlobalLockCS^);
  FreeMem(GlobalLockCS);
  GlobalLockCS := nil;
   {$else}
  FreeAndNil(GlobalLockCS);
   {$endif SB_WINDOWS}

end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
procedure AcquireGlobalLock();
begin
  if GlobalLockCS = nil then
    CreateGlobalLock();
  {$ifdef WIN32}
  EnterCriticalSection(GlobalLockCS^);
   {$else}
  GlobalLockCS.Acquire;
   {$endif}
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
procedure ReleaseGlobalLock();
begin
  if GlobalLockCS = nil then
    Exit; // lock is not acquired
  {$ifdef WIN32}
  LeaveCriticalSection(GlobalLockCS^);
   {$else}
  GlobalLockCS.Release;
   {$endif}
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure CleanupRegisteredGlobalObjects;
var
  I : integer;
  O : TObject;
begin
  InitGlobalObjectList;
  {$ifdef WIN32}
  EnterCriticalSection(GlobalObjectListCS);
   {$else}
  GlobalObjectListCS.Acquire;
   {$endif}
  try
    for I := 0 to GlobalObjectList. Count  - 1 do
    begin
      O := (GlobalObjectList [I] );
      FreeAndNil(O);
    end;
    GlobalObjectList.Clear;
  finally
    {$ifdef WIN32}
    LeaveCriticalSection(GlobalObjectListCS);
     {$else}
    GlobalObjectListCS.Release;
     {$endif}
  end;
  FinalGlobalObjectList;
  FreeGlobalLock();
end;

// Done 7 / XE5(32) / XE5(64) / Android
function CompareMD128(const M1, M2 : TMessageDigest128) : boolean;
begin
  result := (M1.A = M2.A) and
            (M1.B = M2.B) and
            (M1.C = M2.C) and
            (M1.D = M2.D);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function CompareMD160(const M1, M2 : TMessageDigest160) : boolean;
begin
  result := (M1.A = M2.A) and
            (M1.B = M2.B) and
            (M1.C = M2.C) and
            (M1.D = M2.D) and
            (M1.E = M2.E);
end;

// DeN 03.11.2013
// Done 7 / XE5(32) / XE5(64) / Android
function CompareMD224(const M1, M2 : TMessageDigest224) : boolean;
begin
  result := (M1.A1 = M2.A1) and
            (M1.B1 = M2.B1) and
            (M1.C1 = M2.C1) and
            (M1.D1 = M2.D1) and
            (M1.A2 = M2.A2) and
            (M1.B2 = M2.B2) and
            (M1.C2 = M2.C2);
end;

// DeN 03.11.2013
// Done 7 / XE5(32) / XE5(64) / Android
function CompareMD256(const M1, M2 : TMessageDigest256) : boolean;
begin
  result := (M1.A1 = M2.A1) and
            (M1.B1 = M2.B1) and
            (M1.C1 = M2.C1) and
            (M1.D1 = M2.D1) and
            (M1.A2 = M2.A2) and
            (M1.B2 = M2.B2) and
            (M1.C2 = M2.C2) and
            (M1.D2 = M2.D2);
end;

// DeN 03.11.2013
// Done 7 / XE5(32) / XE5(64) / Android
function CompareMD320(const M1, M2 : TMessageDigest320) : boolean;
begin
  result := (M1.A1 = M2.A1) and
            (M1.B1 = M2.B1) and
            (M1.C1 = M2.C1) and
            (M1.D1 = M2.D1) and
            (M1.E1 = M2.E1) and
            (M1.A2 = M2.A2) and
            (M1.B2 = M2.B2) and
            (M1.C2 = M2.C2) and
            (M1.D2 = M2.D2) and
            (M1.E2 = M2.E2);            
end;

// DeN 03.11.2013
// Done 7 / XE5(32) / XE5(64) / Android
function CompareMD384(const M1, M2 : TMessageDigest384) : boolean;
begin
  result := (M1.A = M2.A) and
            (M1.B = M2.B) and
            (M1.C = M2.C) and
            (M1.D = M2.D) and
            (M1.E = M2.E) and
            (M1.F = M2.F);
end;

// DeN 03.11.2013
// Done 7 / XE5(32) / XE5(64) / Android
function CompareMD512(const M1, M2 : TMessageDigest512) : boolean;
begin
  result := (M1.A1 = M2.A1) and
            (M1.B1 = M2.B1) and
            (M1.C1 = M2.C1) and
            (M1.D1 = M2.D1) and
            (M1.A2 = M2.A2) and
            (M1.B2 = M2.B2) and
            (M1.C2 = M2.C2) and
            (M1.D2 = M2.D2);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function CompareAnsiStr(const Content, OID : AnsiString) : boolean;
begin
  {$ifndef SB_UNICODE_VCL}
  Result := CompareStr(Content, OID) = 0;
   {$else}
  if Length(Content) <> Length(OID) then
  begin
    Result := False;
    Exit;
  end;

  if Length(Content) = 0 then
    Result := True
  else
    Result := CompareMem(@Content[AnsiStrStartOffset], @OID[AnsiStrStartOffset], Length(Content));
   {$endif}
end;

// Done 7 / XE5(32) / XE5(64) / Android
function CompareContent(const Content, OID:  ByteArray ): Boolean;
begin
  if Length(Content) <> Length(OID) then
  begin
    Result := False;
    Exit;
  end;

  if Length(Content) = 0 then
    Result := True
  else
    Result := CompareMem(@Content[0], @OID[0], Length(Content));
end;

// Inner - Not tested
function IntCompareHashes(Hash1 : pointer; Len1 : integer; Hash2 : pointer; Len2 : integer): boolean;
var
  I : integer;
  Res : byte;
begin
  Result := false;
  if (Len1 <> Len2) then
    Exit;
  Res := 0;
  for I := 0 to Len1 - 1 do
    Res := Res or (PByteArray(Hash1)[I] xor PByteArray(Hash2)[I]);
  Result := (Res = 0);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function CompareHashes(const Hash1, Hash2 : ByteArray): boolean;
begin
  Result := IntCompareHashes(@Hash1[0], Length(Hash1), @Hash2[0], Length(Hash2));
end;

// Done 7 / XE5(32) / XE5(64) / Android
function CompareHashes(const Hash1 : ByteArray; StartIndex1 : integer; Count1 : integer;
  const Hash2 : ByteArray; StartIndex2 : integer; Count2 : integer): boolean;
begin
  // DeN 21.11.2013
  if (Hash1 = nil) or (Hash2 = nil) or (StartIndex1 < 0) or (StartIndex2 < 0) or
     (Count1 <= 0) or (Count2 <= 0) then
    Result := false
  else
  // end DeN 21.11.2013  
  	Result := IntCompareHashes(@Hash1[StartIndex1], Count1, @Hash2[StartIndex2], Count2);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ChangeByteOrder(const Buffer : ByteArray): ByteArray;
var
  i, len : integer;
begin
  len := Length(Buffer);
  SetLength(Result, len);

  for i := 0 to len - 1 do
    Result[len - i - 1] := Buffer[i];
end;


// Done 7 / XE5(32) / XE5(64) / Android
function EmptyArray: ByteArray;
begin
  SetLength(Result, 0);
end;





// Done 7 / XE5(32) / XE5(64) / Android
function SBConcatArrays(const Buf1, Buf2 : ByteArray) : ByteArray;
var
  Len1, Len2 : integer;
begin
  Len1 := Length(Buf1);
  Len2 := Length(Buf2);
  SetLength(Result, Len1 + Len2);
  if Len1 > 0 then
    SBMove(Buf1[0], Result[0], Len1);
  if Len2 > 0 then
    SBMove(Buf2[0], Result[Len1], Len2);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SBConcatArrays(const Buf1, Buf2, Buf3 : ByteArray) : ByteArray;
var
  l1, l2, l3: Integer;
begin
  l1 := Length(Buf1);
  l2 := Length(Buf2);
  l3 := Length(Buf3);

  SetLength(Result, l1 + l2 + l3);

  if l1 > 0 then
    SBMove(Buf1[0], Result[0], l1);
  if l2 > 0 then
    SBMove(Buf2[0], Result[l1], l2);
  if l3 > 0 then
    SBMove(Buf3[0], Result[l1 + l2], l3);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SBConcatArrays(const Buf1: byte; Buf2: ByteArray): ByteArray;
var
  l: Integer;
begin
  l := Length(Buf2);
  SetLength(Result, 1 + l);
  Result[0] := Buf1;

  if l > 0 then
    SBMove(Buf2, 0, Result, 0 + 1, l);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SBConcatArrays(const Buf1, Buf2 : byte; Buf3: ByteArray): ByteArray;
var
  l3: Integer;
begin
  l3 := Length(Buf3);

  SetLength(Result, sizeof(Buf1) + sizeof(Buf2) + l3);

  Result[0] := Buf1;
  Result[0 + 1] := Buf2;
  if l3 > 0 then
    SBMove(Buf3, 0, Result, 0 + 2, l3);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SBConcatArrays(const Buf1: ByteArray; Buf2: byte) : ByteArray;
var
  l: Integer;
begin
  l := Length(Buf1);
  SetLength(Result, l + 1);

  if l > 0 then
    SBMove(Buf1, 0, Result, 0, l);

  Result[0 + l] := Buf2;
end;

(*
{$ifdef SB_NET}
function SBConcatArrays(const Buf1, Buf2, Buf3: ByteArray): ByteArray;
var
  l1, l2, l3: Integer;
begin
  l1 := Length(Buf1);
  l2 := Length(Buf2);
  l3 := Length(Buf3);
  Result := new Byte[l1 + l2 + l3];
  if l1 > 0 then
    System.Buffer.BlockCopy(Buf1, 0, Result, 0, l1);

  if l2 > 0 then
    System.Buffer.BlockCopy(Buf2, 0, Result, l1, l2);

  if l3 > 0 then
    System.Buffer.BlockCopy(Buf3, 0, Result, l1 + l2, l3);
end;
{$endif}
*)

// Done 7 / XE5(32) / XE5(64) / Android
function SBConcatArrays(const Buf1 : byte; Buf2, Buf3 : ByteArray): ByteArray;
var
  l1, l2, l3: Integer;
begin
  l1 := 1;
  l2 := Length(Buf2);
  l3 := Length(Buf3);

  SetLength(Result, l1 + l2 + l3);

  Result[0] := Buf1;
  if l2 > 0 then
    SBMove(Buf2, 0, Result, 0 + l1, l2);
  if l3 > 0 then
    SBMove(Buf3, 0, Result, 0 + l1 + l2, l3);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SBConcatMultipleArrays(const Arrays : array of ByteArray): ByteArray;
var i : integer;
    cp: integer;
    size : integer;
begin
  Size := 0;
  for i := 0 to Length(Arrays) - 1 do
  begin
    inc(Size, Length(Arrays[i]));
  end;
  SetLength(Result, Size);
  cp := 0;
  for i := 0 to Length(Arrays) - 1 do
  begin
    size := Length(Arrays[i]);
    SBMove(Arrays[i], 0, Result, cp, size);
    inc(cp, size);
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
// Todo - NET
procedure FreeAndNil(var Obj);
var
  O: TObject;
begin
  o := TObject(Obj);
  if o = nil then
    exit;
  TObject(Obj) := nil;
  O.Free;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function CompareGUID(const Guid1, Guid2 : TGUID) : boolean;
begin
  Result := SysUtils.CompareMem(@Guid1, @Guid2, SizeOf(Guid1));
end;

// Done 7 / XE5(32) / XE5(64) / Android
function GenerateGUID: string;
var
  Buf : array [0..15]  of byte;
  DW : cardinal;
  W1, W2, W3 : word;
  B1, B2, B3, B4, B5, B6 : byte;
begin
  SBRndGenerate(@Buf[0], 16);
  DW := (Buf[0] shl 24) or (Buf[1] shl 16) or (Buf[2] shl 8) or Buf[3];
  W1 := (Buf[4] shl 8) or Buf[5];
  W2 := (Buf[6] shl 8) or Buf[7];
  W3 := (Buf[8] shl 8) or Buf[9];
  B1 := Buf[10];
  B2 := Buf[11];
  B3 := Buf[12];
  B4 := Buf[13];
  B5 := Buf[14];
  B6 := Buf[15];
  Result := '{' + IntToHex(DW, 8) + '-' + IntToHex(W1, 4) + '-' + IntToHex(W2, 4) + '-' +
    IntToHex(W3, 4) + '-' + IntToHex(B1, 2) + IntToHex(B2, 2) + IntToHex(B3, 2) +
    IntToHex(B4, 2) + IntToHex(B5, 2) + IntToHex(B6, 2) + '}';
end;


{$ifdef SB_HAS_MEMORY_MANAGER}
// Todo - JAVA
procedure SetLength(var Arr: JLObjectArray; aLength: integer);
begin
  System.SetLength(Arr, aLength);
end;

// Todo - JAVA
procedure SetLength(var Arr: LIntArray; aLength: integer); 
begin
  System.SetLength(Arr, aLength);
end;

// Todo - JAVA
procedure SetLength(var Arr: ByteArrayConstArray; aLength: integer);
begin
  System.SetLength(Arr, aLength);
end;

// Todo - JAVA
procedure SetLength(var Arr: DateArray; aLength: integer);
begin
  System.SetLength(Arr, aLength);
end;

// Todo - JAVA
procedure SetLength(var Arr: ObjectArray; aLength: integer);
begin
  System.SetLength(Arr, aLength);
end;

{procedure SetLength(var Arr: ByteArray; aLength: integer);
begin
  System.SetLength(Arr, aLength);
end;

procedure SetLength(var Arr: Arr1jbyte; aLength: integer; Stub: boolean = false);
begin
  System.SetLength(Arr, aLength);
end;}

// Todo - JAVA
procedure SetLength(var Arr: ByteArray; aLength: integer);
var
  MO : TSBManagedObject;
  Len, ToCopy : integer;
begin
  Len := Length(Arr);
    
  if (Len <> aLength) or (Arr = nil) then
  begin
    MO := MemoryManager.AcquireArray(ByteArrClass, aLength);
    ToCopy := Min(Len, aLength);
    
    if (Arr <> nil) and (ToCopy > 0) then
    begin
      JLSystem.arraycopy(JLObject(Arr), 0, JLObject(MO), 0, ToCopy);
    end;
    
    Arr := ByteArray(MO);
  end;
end;

// Todo - JAVA
procedure SetLength(var Arr: Arr1jbyte; aLength: integer; Stub: boolean = false);
var
  MO : TSBManagedObject;
  Len, ToCopy : integer;
begin
  Len := Length(Arr);
    
  if (Len <> aLength) or (Arr = nil) then
  begin
    MO := MemoryManager.AcquireArray(ByteArrClass, aLength);
    ToCopy := Min(Len, aLength);
    
    if (Arr <> nil) and (ToCopy > 0) then
    begin
      JLSystem.arraycopy(JLObject(Arr), 0, JLObject(MO), 0, ToCopy);
    end;
        
    Arr := Arr1jbyte(MO);
  end;
end;

// Todo - JAVA
procedure SetLength(var Arr: WordArray; aLength: integer);
begin
  System.SetLength(Arr, aLength);
end;

// Todo - JAVA
procedure SetLength(var Arr: IntegerArray; aLength: integer);
begin
  System.SetLength(Arr, aLength);
end;

// Todo - JAVA
procedure SetLength(var Arr: Int64Array; aLength: integer);
begin
  System.SetLength(Arr, aLength);
end;

// Todo - JAVA
procedure SetLength(var Arr: CharArray; aLength: integer);
begin
  System.SetLength(Arr, aLength);
end;

// Todo - JAVA
procedure SetLength(var Arr: string; aLength: integer);
begin
  System.SetLength(Arr, aLength);
end;

// Todo - JAVA
procedure SetLength(var Arr: AnsiString; aLength: integer);
begin
  System.SetLength(Arr, aLength);
end;

// Todo - JAVA
procedure SetLength(var Arr: StringArray; aLength: integer);
begin
  System.SetLength(Arr, aLength);
end;

// Todo - JAVA
procedure SetLength(var Arr: BooleanArray; aLength: integer);
begin
  System.SetLength(Arr, aLength);
end;

// Todo - JAVA
procedure SetLength(var Arr: ArrayOfByteArray; aLength: integer);
begin
  System.SetLength(Arr, aLength);
end;

// Todo - JAVA
procedure SetLength(var Arr: LongWordArray; aLength: integer;  Stub: boolean = false);
begin
  System.SetLength(Arr, aLength);
end;

// Todo - JAVA
procedure SetLength(var Arr: SmallIntArray; aLength: integer; Stub: boolean = false);
begin
  System.SetLength(Arr, aLength);
end;
 {$endif}

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseString(var S : AnsiString);
begin
  S := '';
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseString(var S : AnsiString; Zeroize : boolean);
var
  I : integer;
begin
  if Zeroize then
    for I := AnsiStrStartOffset to Length(S) - AnsiStrStartInvOffset do
      S[I] := AnsiChar('A')
  else // DeN 16.10.2013
  	SetLength(S, 0);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseString(var S : UnicodeString);
begin
  SetLength(S, 0);
  S := '';
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseString(var S : UnicodeString; Zeroize : boolean);
var I : integer; // DeN 16.10.2013
begin
  // TODO
  
  // DeN 16.10.2013
  if Zeroize then
    for I := StringStartOffset to Length(S) - StringStartInvOffset do
      S[I] := Char('A') // DeN 19.12.20133 Char instead of AnsiChar
  else
  // end DeN 16.10.2013
    S  := '';
end;

(*
procedure ReleaseArray(var Buf : ByteArray; Zeroize : boolean);
begin
  if Zeroize then
    {$ifdef SB_VCL}
    FillChar(Buf[0], Length(Buf), 0);
    {$else}
    FillChar(Buf, Length(Buf), 0, 0);
    {$endif}
  {$ifdef SB_NET}
  {$ifndef NET_CF}
  if UseArrayResize then
    Array.Resize(Buf, 0);
  {$endif}
  {$endif}
  {$ifdef SB_VCL}
  SetLength(Buf, 0);
  {$endif}
  Buf := EmptyArray;
end;
*)

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArray(var aBytes : ByteArray);
begin
  if (aBytes <> nil) then
  begin
    SetLength(aBytes, 0);
    {$ifdef SB_HAS_MEMORY_MANAGER}
    MemoryManager.ReleaseArray(TSBManagedObject(aBytes));
     {$endif}
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArray(var aBytes : ByteArray; Zeroize : boolean);
begin
  if (aBytes <> nil) then
  begin
    if Zeroize then
      FillChar(aBytes[0], Length(aBytes), 0);
      SetLength(aBytes, 0);
      {$ifdef SB_HAS_MEMORY_MANAGER}
      MemoryManager.ReleaseArray(TSBManagedObject(aBytes));
       {$endif}
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArray(var aWords: WordArray);
begin
  if (aWords <> nil) then
  begin
    SetLength(aWords, 0);
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArray(var aWords: WordArray; Zeroize : boolean);
begin
  if (aWords <> nil) then
  begin
    if Zeroize then
      FillChar(aWords[0], SizeOf(Word) * Length(aWords), 0);
    SetLength(aWords, 0);
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArray(var aIntegers: IntegerArray);
begin
  if (aIntegers <> nil) then
  begin
    SetLength(aIntegers, 0);
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArray(var aIntegers: IntegerArray; Zeroize : boolean);
begin
  if (aIntegers <> nil) then
  begin
    if Zeroize then
      FillChar(aIntegers[0], SizeOf(Integer) * Length(aIntegers), 0);
    SetLength(aIntegers, 0);
  end;
end;

(*
procedure ReleaseArray(var aUInt32s: UInt32Array);
begin
  if (aUInt32s <> nil) then
  begin
    SetLength(aUInt32s, 0);
    aUInt32s := nil;
  end;
end;

procedure ReleaseArray(var aUInt32s: UInt32Array; Zeroize : boolean);
begin
  if (aUInt32s <> nil) then
  begin
    if Zeroize then
      {$ifdef SB_VCL}
      FillChar(aUInt32s[0], SizeOf(UInt32) * Length(aUInt32s), 0);
      {$else}
      FillChar(aUInt32s, Length(aUInt32s), 0, 0);
      {$endif}
    SetLength(aUInt32s, 0);
    aUInt32s := nil;
  end;
end;*)

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArray(var aLongWords: LongWordArray);
begin
  if (aLongWords <> nil) then
  begin
    SetLength(aLongWords, 0);
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArray(var aLongWords: LongWordArray; Zeroize : boolean);
begin
  if (aLongWords <> nil) then
  begin
    if Zeroize then
      FillChar(aLongWords[0], SizeOf(LongWord) * Length(aLongWords), 0);
    SetLength(aLongWords, 0);
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArray(var aInt64s: Int64Array);
begin
  if (aInt64s <> nil) then
  begin
    SetLength(aInt64s, 0);
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArray(var aInt64s: Int64Array; Zeroize : boolean);
begin
  if (aInt64s <> nil) then
  begin
    if Zeroize then
      FillChar(aInt64s[0], SizeOf(Int64) * Length(aInt64s), 0);
    SetLength(aInt64s, 0);
  end;
end;


// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArray(var aByteArrays : ArrayOfByteArray);
begin
  if (aByteArrays <> nil) then
  begin
    SetLength(aByteArrays, 0);
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArray(var aChars: CharArray);
begin
  if (aChars <> nil) then
  begin
    SetLength(aChars, 0);
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArray(var aChars: CharArray; Zeroize : boolean);
begin
  if (aChars <> nil) then
  begin
    if Zeroize then
      FillChar(aChars[0], SizeOf(char) * Length(aChars), 0);
    SetLength(aChars, 0);
  end;
end;

{$ifndef SB_UNICODE_VCL}
// Done 7
procedure ReleaseArray(var aWideChars: WideCharArray);
begin
  if (aWideChars <> nil) then
  begin
    SetLength(aWideChars, 0);
  end;
end;

// Done 7
procedure ReleaseArray(var aWideChars: WideCharArray; Zeroize : boolean);
begin
  if (aWideChars <> nil) then
  begin
    if Zeroize then
      FillChar(aWideChars[0], SizeOf(WideChar) * Length(aWideChars), 0);

    SetLength(aWideChars, 0);
  end;
end;

// Done 7
procedure ReleaseArray(var aWideStrings: WideStringArray);
begin
  if (aWideStrings <> nil) then
  begin
    SetLength(aWideStrings, 0);
  end;
end;
 {$endif}

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArray(var aBooleans: BooleanArray);
begin
  if (aBooleans <> nil) then
  begin
    SetLength(aBooleans, 0);
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArray(var aBooleans: BooleanArray; Zeroize : boolean);
begin
  if (aBooleans <> nil) then
  begin
    if Zeroize then
      FillChar(aBooleans[0], SizeOf(Boolean) * Length(aBooleans), 0);
    SetLength(aBooleans, 0);
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArray(var aStrings: StringArray);
begin
  if (aStrings <> nil) then
  begin
    SetLength(aStrings, 0);
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArray(var aStrings: StringArray; Zeroize : boolean);
var
  I : integer;
begin
  if (aStrings <> nil) then
  begin
    if Zeroize then
      for I := 0 to Length(aStrings) - 1 do
        ReleaseString(aStrings[I], Zeroize);
    SetLength(aStrings, 0);
  end;
end;




// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArrays(var A1, A2 : ByteArray);
begin
  ReleaseArray(A1);
  ReleaseArray(A2);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArrays(var A1, A2 : ByteArray; Zeroize : boolean);
begin
  ReleaseArray(A1, Zeroize);
  ReleaseArray(A2, Zeroize);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArrays(var A1, A2, A3 : ByteArray);
begin
  ReleaseArray(A1);
  ReleaseArray(A2);
  ReleaseArray(A3);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArrays(var A1, A2, A3 : ByteArray; Zeroize : boolean);
begin
  ReleaseArray(A1, Zeroize);
  ReleaseArray(A2, Zeroize);
  ReleaseArray(A3, Zeroize);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArrays(var A1, A2, A3, A4 : ByteArray);
begin
  ReleaseArray(A1);
  ReleaseArray(A2);
  ReleaseArray(A3);
  ReleaseArray(A4);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArrays(var A1, A2, A3, A4 : ByteArray; Zeroize : boolean);
begin
  ReleaseArray(A1, Zeroize);
  ReleaseArray(A2, Zeroize);
  ReleaseArray(A3, Zeroize);
  ReleaseArray(A4, Zeroize);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArrays(var A1, A2, A3, A4, A5 : ByteArray);
begin
  ReleaseArray(A1);
  ReleaseArray(A2);
  ReleaseArray(A3);
  ReleaseArray(A4);
  ReleaseArray(A5);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArrays(var A1, A2, A3, A4, A5 : ByteArray; Zeroize : boolean);
begin
  ReleaseArray(A1, Zeroize);
  ReleaseArray(A2, Zeroize);
  ReleaseArray(A3, Zeroize);
  ReleaseArray(A4, Zeroize);
  ReleaseArray(A5, Zeroize);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArrays(var A1, A2, A3, A4, A5, A6 : ByteArray);
begin
  ReleaseArray(A1);
  ReleaseArray(A2);
  ReleaseArray(A3);
  ReleaseArray(A4);
  ReleaseArray(A5);
  ReleaseArray(A6);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArrays(var A1, A2, A3, A4, A5, A6 : ByteArray; Zeroize : boolean);
begin
  ReleaseArray(A1, Zeroize);
  ReleaseArray(A2, Zeroize);
  ReleaseArray(A3, Zeroize);
  ReleaseArray(A4, Zeroize);
  ReleaseArray(A5, Zeroize);
  ReleaseArray(A6, Zeroize);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArrays(var A1, A2, A3, A4, A5, A6, A7 : ByteArray);
begin
  ReleaseArray(A1);
  ReleaseArray(A2);
  ReleaseArray(A3);
  ReleaseArray(A4);
  ReleaseArray(A5);
  ReleaseArray(A6);
  ReleaseArray(A7);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArrays(var A1, A2, A3, A4, A5, A6, A7 : ByteArray; Zeroize : boolean);
begin
  ReleaseArray(A1, Zeroize);
  ReleaseArray(A2, Zeroize);
  ReleaseArray(A3, Zeroize);
  ReleaseArray(A4, Zeroize);
  ReleaseArray(A5, Zeroize);
  ReleaseArray(A6, Zeroize);
  ReleaseArray(A7, Zeroize);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArrays(var A1, A2, A3, A4, A5, A6, A7, A8 : ByteArray);
begin
  ReleaseArray(A1);
  ReleaseArray(A2);
  ReleaseArray(A3);
  ReleaseArray(A4);
  ReleaseArray(A5);
  ReleaseArray(A6);
  ReleaseArray(A7);
  ReleaseArray(A8);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArrays(var A1, A2, A3, A4, A5, A6, A7, A8 : ByteArray; Zeroize : boolean);
begin
  ReleaseArray(A1, Zeroize);
  ReleaseArray(A2, Zeroize);
  ReleaseArray(A3, Zeroize);
  ReleaseArray(A4, Zeroize);
  ReleaseArray(A5, Zeroize);
  ReleaseArray(A6, Zeroize);
  ReleaseArray(A7, Zeroize);
  ReleaseArray(A8, Zeroize);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArrays(var A1, A2, A3, A4, A5, A6, A7, A8, A9 : ByteArray);
begin
  ReleaseArray(A1);
  ReleaseArray(A2);
  ReleaseArray(A3);
  ReleaseArray(A4);
  ReleaseArray(A5);
  ReleaseArray(A6);
  ReleaseArray(A7);
  ReleaseArray(A8);
  ReleaseArray(A9);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArrays(var A1, A2, A3, A4, A5, A6, A7, A8, A9 : ByteArray; Zeroize : boolean);
begin
  ReleaseArray(A1, Zeroize);
  ReleaseArray(A2, Zeroize);
  ReleaseArray(A3, Zeroize);
  ReleaseArray(A4, Zeroize);
  ReleaseArray(A5, Zeroize);
  ReleaseArray(A6, Zeroize);
  ReleaseArray(A7, Zeroize);
  ReleaseArray(A8, Zeroize);
  ReleaseArray(A9, Zeroize);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArrays(var A1, A2, A3, A4, A5, A6, A7, A8, A9, A10 : ByteArray);
begin
  ReleaseArray(A1);
  ReleaseArray(A2);
  ReleaseArray(A3);
  ReleaseArray(A4);
  ReleaseArray(A5);
  ReleaseArray(A6);
  ReleaseArray(A7);
  ReleaseArray(A8);
  ReleaseArray(A9);
  ReleaseArray(A10);
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure ReleaseArrays(var A1, A2, A3, A4, A5, A6, A7, A8, A9, A10 : ByteArray; Zeroize : boolean);
begin
  ReleaseArray(A1, Zeroize);
  ReleaseArray(A2, Zeroize);
  ReleaseArray(A3, Zeroize);
  ReleaseArray(A4, Zeroize);
  ReleaseArray(A5, Zeroize);
  ReleaseArray(A6, Zeroize);
  ReleaseArray(A7, Zeroize);
  ReleaseArray(A8, Zeroize);
  ReleaseArray(A9, Zeroize);
  ReleaseArray(A10, Zeroize);
end;


// Done 7 / XE5(32) / XE5(64) / Android
function GetDigestSizeBits(Algorithm : integer) : integer;
begin
  case Algorithm of
    SB_ALGORITHM_DGST_SHA1   : Result := 160;
    SB_ALGORITHM_DGST_MD5    : Result := 128;
    SB_ALGORITHM_DGST_MD2    : Result := 128;
    SB_ALGORITHM_DGST_SHA224 : Result := 224;
    SB_ALGORITHM_DGST_SHA256 : Result := 256;
    SB_ALGORITHM_DGST_SHA384 : Result := 384;
    SB_ALGORITHM_DGST_SHA512 : Result := 512;
    SB_ALGORITHM_DGST_RIPEMD160 : Result := 160;
    SB_ALGORITHM_DGST_CRC32 : Result := 32;
    SB_ALGORITHM_MAC_HMACMD5 : Result := 128;
    SB_ALGORITHM_MAC_HMACSHA1 : Result := 160;
    SB_ALGORITHM_MAC_HMACSHA224 : Result := 224;
    SB_ALGORITHM_MAC_HMACSHA256 : Result := 256;
    SB_ALGORITHM_MAC_HMACSHA384 : Result := 384;
    SB_ALGORITHM_MAC_HMACSHA512 : Result := 512;
    SB_ALGORITHM_MAC_HMACRIPEMD : Result := 160;
    SB_ALGORITHM_UMAC32         : Result := 32;
    SB_ALGORITHM_UMAC64         : Result := 64;
    SB_ALGORITHM_UMAC96         : Result := 96;
    SB_ALGORITHM_UMAC128        : Result := 128;
    SB_ALGORITHM_DGST_SSL3      : Result := 288;
    SB_ALGORITHM_MAC_GOST_28147_1989  : Result := 64;
    SB_ALGORITHM_DGST_GOST_R3411_1994  : Result := 256;
    SB_ALGORITHM_DGST_WHIRLPOOL : Result := 512;
  else
    Result := -1;
  end;
end;


// ---------------------------- TSBObjectList ----------------------------------
// Not tested
constructor TSBObjectList.Create;
begin
  inherited Create;
  FOwnsObjects := true;
end;

// Not tested
constructor TSBObjectList.Create(AOwnsObjects: Boolean);
begin
  inherited Create;
  FOwnsObjects := AOwnsObjects;
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function TSBObjectList.Add(AObject: TObject): Integer;
begin
  Result := inherited Add(AObject);
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function TSBObjectList.FindInstanceOf(AClass:  TClass  ; AExact: Boolean;
  AStartAt: Integer): Integer;
var
  I: Integer;
begin
  Result := -1;
  for I := AStartAt to Count - 1 do
    if (AExact and
      (Self[I] <> nil) and // DeN 30.11.2013
      (Self[I].ClassType = AClass)) or
      (not AExact and
      (Self[I] <> nil) and // DeN 30.11.2013      
      Self[I].InheritsFrom(AClass)) then
    begin
      Result := I;
      break;
    end;
end;

// Not tested
function TSBObjectList.GetItem(Index: Integer): TObject;
begin
  Result := inherited Items[Index];
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function TSBObjectList.IndexOf(AObject: TObject): Integer;
begin
  Result := inherited IndexOf(AObject);
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
procedure TSBObjectList.Insert(Index: Integer; AObject: TObject);
begin
  inherited Insert(Index, AObject);
end;

// Not tested
procedure TSBObjectList.Notify(Ptr: Pointer; Action: TListNotification);
{.$else}
//procedure TSBObjectList.Notify(Ptr: TObject; Action: TListNotification);
begin
  if OwnsObjects then
    if Action = lnDeleted then
      TObject(Ptr). Free ;
{$ifdef VCL50}
  inherited Notify(Ptr, Action);
 {$endif}
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function TSBObjectList.Remove(AObject: TObject): Integer;
begin
  Result := inherited Remove(AObject);
end;

// Not tested
procedure TSBObjectList.SetItem(Index: Integer; AObject: TObject);
begin
  inherited Items[Index] := AObject;
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function TSBObjectList.Extract(Item: TObject): TObject;
var
  I: Integer;
begin
  Result := nil;
  I := IndexOf(Item);
  if I >= 0 then
  begin
    Result := Item;
    List[I] := nil;
    Delete(I);
    Notify(Result, lnExtracted);
  end;
end;




////////////////////////////////////////////////////////////////////////////////
// TElSet class


{$ifdef SB_NO_BOOLEAN_VAR_PARAMS}
// Not tested
constructor TSBBoolean.Create;
begin
  inherited;
  FValue := false;
end;

// Not tested
constructor TSBBoolean.Create(Value : boolean);
begin
  inherited Create;
  FValue := Value;
end;

// Not tested
function TSBBoolean.ToString(): string;
begin
  Result := FValue.ToString();
end;

// Note: we cannot use <> and = operators to test objects for NULL here,
// as these will result in infinite recursion (<> and = operators are overloaded).
// Therefore, try/except blocks are used everywhere.

// Todo - UNICODE_VCL
class operator TSBBoolean.Implicit(const Value: boolean): TSBBoolean;
begin
  Result := new TSBBoolean(Value);
end;

// Todo - UNICODE_VCL
class operator TSBBoolean.Implicit(const Value: TSBBoolean): boolean;
begin
  try
    Result := Value.FValue
  except
    Result := false;
  end;
end;

// Todo - UNICODE_VCL
class operator TSBBoolean.Equal(const Left, Right: TSBBoolean): boolean;
var
  A, B : boolean;
begin
  try
    A := Left.FValue;
  except
    A := false;
  end;
  try
    B := Right.FValue;
  except
    B := false;
  end;
  Result := A = B;
end;

// Todo - UNICODE_VCL
class operator TSBBoolean.NotEqual(const Left, Right: TSBBoolean): boolean;
var
  A, B : boolean;
begin
  try
    A := Left.FValue;
  except
    A := false;
  end;
  try
    B := Right.FValue;
  except
    B := false;
  end;
  Result := A <> B;
end;

// Todo - UNICODE_VCL
class operator TSBBoolean.Equal(const Left: TSBBoolean; const Right: boolean): boolean;
begin
  try
    Result := Left.FValue = Right
  except
    Result := false = Right;
  end;
end;

// Todo - UNICODE_VCL
class operator TSBBoolean.NotEqual(const Left: TSBBoolean; const Right: boolean): boolean;
begin
  try
    Result := Left.FValue <> Right
  except
    Result := false <> Right;
  end;
end;

// Todo - UNICODE_VCL
class operator TSBBoolean.BitwiseOr(const Left: TSBBoolean; const Right: boolean): boolean;
begin
  try
    Result := Left.FValue or Right
  except
    Result := {false or }Right;
  end;
end;

// Todo - UNICODE_VCL
class operator TSBBoolean.BitwiseAnd(const Left: TSBBoolean; const Right: boolean): boolean;
begin
  try
    Result := Left.FValue and Right
  except
    Result := false {and Right};
  end;
end;

// Todo - UNICODE_VCL
class operator TSBBoolean.BitwiseOr(const Left: TSBBoolean; const Right: TSBBoolean): boolean;
var
  A, B : boolean;
begin
  try
    A := Left.FValue;
  except
    A := false;
  end;
  try
    B := Right.FValue;
  except
    B := false;
  end;
  Result := A or B;
end;

// Todo - UNICODE_VCL
class operator TSBBoolean.BitwiseAnd(const Left: TSBBoolean; const Right: TSBBoolean): boolean;
var
  A, B : boolean;
begin
  try
    A := Left.FValue;
  except
    A := false;
  end;
  try
    B := Right.FValue;
  except
    B := false;
  end;
  Result := A and B;
end;

// Todo - UNICODE_VCL
class operator TSBBoolean.BitwiseOr(const Left: boolean; const Right: TSBBoolean): boolean;
begin
  try
    Result := Left or Right.FValue
  except
    Result := Left {or false};
  end;
end;

// Todo - UNICODE_VCL
class operator TSBBoolean.BitwiseAnd(const Left: boolean; const Right: TSBBoolean): boolean;
begin
  try
    Result := Left and Right.FValue
  except
    Result := {Left and }false;
  end;
end;

// Todo - UNICODE_VCL
class operator TSBBoolean.BitwiseNot(const Value: TSBBoolean): boolean;
begin
  try
    Result := not Value.FValue
  except
    Result := true;
  end;
end;

 {$endif SB_NO_BOOLEAN_VAR_PARAMS}


{$ifndef SB_NO_NET_PINVOKE}
{$ifdef SB_NO_NET_COM_MEMORY_ALLOC}
[DllImport({$ifndef SILVERLIGHT}COREDLL {$else}KERNEL32 {$endif}, CharSet  =  CharSet.Auto,
  SetLastError  =  true,
  EntryPoint  =  'LocalAlloc')]
function LocalAlloc(Flags: DWORD; Size: Integer): IntPtr; external;
[DllImport({$ifndef SILVERLIGHT}COREDLL {$else}KERNEL32 {$endif}, CharSet  =  CharSet.Auto,
  SetLastError  =  true,
  EntryPoint  =  'LocalFree')]
procedure LocalFree(Ptr: IntPtr); external;

[DllImport(OLE32)]
function CoTaskMemAlloc(cb: Integer): IntPtr; external;
[DllImport(OLE32)]
procedure CoTaskMemFree(Ptr: IntPtr); external;

// Todo - NET
function AllocCoTaskMem(Size: Integer): IntPtr;
begin
  Result := CoTaskMemAlloc(Size);
  if Result = IntPtr.Zero then
    raise OutOfMemoryException.Create();
end;

// Todo - NET
procedure FreeCoTaskMem(Ptr: IntPtr);
begin
  CoTaskMemFree(Ptr);
end;
 {$endif SB_NO_NET_COM_MEMORY_ALLOC}
 {$endif SB_NO_NET_PINVOKE}

{$ifdef SB_NO_NET_DATETIME_OADATE}
// Todo - NET
function DateTimeToOADate(const DateTime: System.DateTime): Double;
var
  n, n2: Int64;
begin
  n := DateTime.Ticks;
  if n = 0 then
  begin
    Result := 0;
    Exit;
  end;

  if n < $c92a69c000 then
    n := n + $085103c0cb83c000;

  if n < $6efdddaec64000 then
    raise OverflowException.Create;

  n := (n - $85103c0cb83c000) div $2710;
  if n < 0 then
  begin
    n2 := n mod $5265c00;
    if n2 <> 0 then
     n := n - (($5265c00 + n2) shl 1);
  end;

  Result := Double(n)/86400000;
end;

// Todo - NET
function DateTimeFromOADate(const d: Double): System.DateTime;
var
  n: Int64;
begin
  if (d >= 2958466) or (d <= -657435) then
    raise ArgumentException.Create;

  if d >= 0 then
    n := Int64(d * 86400000 + 0.5)
  else
    n := Int64(d * 86400000 - 0.5);

  if n < 0 then
    n := n - (n mod $5265c00) shl 1;

  n := n + $3680b5e1fc00;
  if (n < 0) or (n >= $11efae44cb400) then
    raise ArgumentException.Create;

  Result := System.DateTime.Create(n * $2710);
end;
 {$endif}

{$ifdef NET_CF}
const
 RegValueKind_DWORD = 4;

var
  HKEY_CURRENT_USER: IntPtr  =  new IntPtr(-2147483647);
  HKEY_LOCAL_MACHINE: IntPtr  =  new IntPtr(-2147483646);

[DllImport(COREDLL, CharSet  =  CharSet.Unicode, EntryPoint  =  'RegCreateKeyEx')]
function RegCreateKeyEx(hKey: IntPtr; lpSubKey: string; Reserved: Integer; lpClass: string; dwOptions: Integer; samDesigner: Integer; lpSecurityAttributes: IntPtr; out hkResult: IntPtr; out lpdwDisposition: Integer): Integer; external;
[DllImport(COREDLL, CharSet  =  CharSet.Unicode, EntryPoint  =  'RegOpenKeyEx')]
function RegOpenKeyEx(hKey: IntPtr; lpSubKey: string; ulOptions: Integer; samDesired: Integer; out hkResult: IntPtr): Integer; external;
[DllImport(COREDLL, CharSet  =  CharSet.Unicode, EntryPoint  =  'RegQueryValueEx')]
function RegQueryValueEx(hKey: IntPtr; lpValueName: string; lpReserved: IntPtr; var lpType: Integer; var lpData: DWORD; var lpcbData: Integer): Integer; external;
[DllImport(COREDLL, CharSet  =  CharSet.Unicode, EntryPoint  =  'RegSetValueEx')]
function RegSetValueEx(hKey: IntPtr; lpValueName: string; Reserved: Integer; dwType: Integer; var lpData: DWORD; cbData: Integer): Integer; external;
[DllImport(COREDLL, CharSet  =  CharSet.Unicode, EntryPoint  =  'RegCloseKey')]
function RegCloseKey(hKey: IntPtr): Integer; external;

// Inner - Not tested
function RegCreateSubKey(hKey: IntPtr; SubKey: string): IntPtr;
var
  i, t: Integer;
begin
  if SubKey.Chars[Length(SubKey) - 1] = '\' then
    SubKey := SubKey.Substring(0, Length(SubKey) - 1);

  i := RegCreateKeyEx(hKey, SubKey, 0, nil, 0, $2001f, nil, Result, t);
  if i <> 0 then
    Result := IntPtr.Zero;
end;

// Inner - Not tested
function RegOpenSubKey(hKey: IntPtr; SubKey: string; Writable: Boolean): IntPtr;
var
  AccessRights, i: Integer;
begin
  if Writable then
    AccessRights := $2001f
  else
    AccessRights := $20019;

  if SubKey.Chars[Length(SubKey) - 1] = '\' then
    SubKey := SubKey.Substring(0, Length(SubKey) - 1);

  i := RegOpenKeyEx(hKey, SubKey, 0, AccessRights, Result);
  if i <> 0 then
    Result := IntPtr.Zero;
end;

// Inner - Not tested
procedure RegSetValue(hKey: IntPtr; const ValueName: string; var Value: DWORD);
begin
  RegSetValueEx(hKey, ValueName, 0, RegValueKind_DWORD, Value, 4);
end;

// Inner - Not tested
function RegGetValue(hKey: IntPtr; const ValueName: string): System.Object;
var
  VK, Len: Integer;
  Value: DWORD;
begin
  Len := 4;
  RegQueryValueEx(hKey, ValueName, nil, VK, Value, Len);
  if VK <> RegValueKind_DWORD then
    Result := System.Object(nil)
  else
    Result := Value;
end;
 {$endif}

{$ifndef SB_NO_NET_INTEROP}
{$ifdef SB_NO_NET_UNSAFEADDROFPINNEDARRAYELEMENT}
// Todo - NET
function UnsafeAddrOfPinnedByteArrayElement(ArrPin: GCHandle; Index: integer): IntPtr;
begin
  Result := UnsafeAddrOfPinnedArrayElement(ArrPin);
  if IntPtr.Size = 4 then
    Result := IntPtr(Result.ToInt32 + Index)
  else
    Result := IntPtr(Result.ToInt64 + Index);
end;
 {$endif}
 {$endif}

{$ifndef WP}
{$ifdef SB_NO_NET_COM_STRINGS}
[DllImport({$ifndef SILVERLIGHT}COREDLL {$else}NTDLL {$endif}, CharSet  =  CharSet.Unicode, EntryPoint  =  'memmove')]
procedure MemMove(pdst: IntPtr; psrc: string; sizetcb: IntPtr); external;
[DllImport({$ifndef SILVERLIGHT}COREDLL {$else}NTDLL {$endif}, CharSet  =  CharSet.Unicode, EntryPoint  =  'memmove')]
procedure MemMove(pdst: StringBuilder; psrc: IntPtr; sizetcb: IntPtr); external;

// Todo - NET
function StringToCoTaskMemUni(const s: string): IntPtr;
var
  i: Integer;
begin
  if Length(s) = 0 then
  begin
    Result := IntPtr.Zero;
    Exit;
  end;

  i := (Length(s) + 1) * SizeOf(Char);
  Result := {$ifndef SB_NO_NET_COM_MEMORY_ALLOC}Marshal. {$endif}AllocCoTaskMem(i);
  MemMove(Result, s, new IntPtr(i));
end;
 {$endif}
 {$endif}

{$ifndef SB_NO_NET_INTEROP}
{$ifdef SB_NO_NET_UNSAFEADDROFPINNEDARRAYELEMENT}
// Todo - NET
function UnsafeAddrOfPinnedArrayElement(ArrPin: GCHandle): IntPtr;
begin
  {$ifndef NET_CF_1_0}
  Result := ArrPin.AddrOfPinnedObject;
   {$else}
  // bug in NET CF 1.0
  // It returns a pointer to the internal array structure (consists of 32 bit
  // array size followed by array data), not to the array itself.
  if IntPtr.Size = 4 then
    Result := IntPtr(ArrPin.AddrOfPinnedObject.ToInt32 + 4)
  else
    Result := IntPtr(ArrPin.AddrOfPinnedObject.ToInt64 + 4);
   {$endif}
end;
 {$endif}
 {$endif}

// Done 7 / XE5(32) / XE5(64) / Android
function ISO8601TimeToDateTime(const EncodedTime : string): TElDateTime;
var
  DateToken, TimeToken, MSecAndTZDToken, TZD : string;
  Index, Index2 : integer;
  Year, Month, Day, Hour, Mn, Sec, MSec, DeltaSign : integer;
  DeltaHours, DeltaMins : integer;
  Delta :  TDateTime ;
begin
  // the method understands the following date/time encodings:
  // * YYYY-MM-DD
  // * YYYY-MM-DDThh:mmTZD
  // * YYYY-MM-DDThh:mm:ssTZD
  // * YYYY-MM-DDThh:mm:ss.ffffffTZD
  Index := StringIndexOf(EncodedTime, 'T');
  if Index >= StringStartOffset + StringStartInvOffset then // DeN 12.02.2014 add StringStartInvOffset
  begin
    DateToken := StringSubstring(EncodedTime, StringStartOffset, Index - StringStartOffset - StringStartInvOffset); // DeN 12.02.2014 add StringStartInvOffset
    TimeToken := StringSubstring(EncodedTime, Index + 1, Length(EncodedTime));
  end
  else
  begin
    DateToken := EncodedTime;
    TimeToken := '';
  end;

  // processing date
  if (Length(DateToken) <> 10) or (DateToken[4 + StringStartOffset] <> '-') or (DateToken[7 + StringStartOffset] <> '-') then
    raise EConvertError.CreateFmt(SInvalidDateToken, [DateToken]);

  Year := StrToIntDef(StringSubstring(DateToken, StringStartOffset, 4), 0);
  Month := StrToIntDef(StringSubstring(DateToken, StringStartOffset + 5, 2), 0);
  Day := StrToIntDef(StringSubstring(DateToken, StringStartOffset + 8, 2), 0);

  // processing time
  Hour := 0;
  Mn := 0;
  Sec := 0;
  MSec := 0;
  DeltaHours := 0;
  DeltaMins := 0;
  DeltaSign := 1;
  if Length(TimeToken) > 0 then
  begin
    if (Length(TimeToken) < 5) or (TimeToken[2 + StringStartOffset] <> ':') then
      raise EConvertError.CreateFmt(SInvalidTimeToken, [TimeToken]);

    Hour := StrToIntDef(StringSubstring(TimeToken, StringStartOffset, 2), 0);
    Mn := StrToIntDef(StringSubstring(TimeToken, StringStartOffset + 3, 2), 0);

    if Length(TimeToken) > 5 then
    begin
      if TimeToken[5 + StringStartOffset] = ':' then
      begin
        Sec := StrToIntDef(StringSubstring(TimeToken, 6 + StringStartOffset, 2), 0);
        if Length(TimeToken) > 8 then
        begin
          if TimeToken[8 + StringStartOffset] = '.' then
          begin
            // the specification says about 6 digits after decimal separator
            // however, some buggy software (e.g. Windows Azure servers)
            // generate dates with a different number of digits. Therefore
            // we are using some heuristics here.
            // What can we expect here:
            // - some digits followed by 'Z'
            // - some digits followed by '+' or '-'
            // - some digits
            MSecAndTZDToken := StringSubstring(TimeToken, 9 + StringStartOffset, Length(TimeToken));

            Index2 := StringIndexOf(MSecAndTZDToken, 'Z');
            if Index2 < StringStartOffset then
            begin
              Index2 := StringIndexOf(MSecAndTZDToken, '+');
              if Index2 < StringStartOffset then
                Index2 := StringIndexOf(MSecAndTZDToken, '-');
            end;

            if Index2 >= StringStartOffset then
            begin
              MSec := StrToIntDef(StringSubstring(MSecAndTZDToken, StringStartOffset, Index2 - StringStartOffset - StringStartInvOffset), 0); // DeN 12.02.2014 add StringStartInvOffset
              TZD := StringSubstring(MSecAndTZDToken, Index2, Length(MSecAndTZDToken));              
            end
            else
            begin
              MSec := StrToIntDef(MSecAndTZDToken, 0);
              TZD := '';
            end;
          end
          else
            TZD := StringSubstring(TimeToken, StringStartOffset + 8, Length(TimeToken) - 8);
        end
        else
          TZD := ''; 
      end
      else
        TZD := StringSubstring(TimeToken, StringStartOffset + 5, Length(TimeToken));
    end
    else
      TZD := '';
    if Length(TZD) > 0 then
    begin
      if TZD = 'Z' then
      begin
        DeltaHours := 0;
        DeltaMins := 0;
      end
      else
      begin
        // TZD may come in three forms:
        // "+01:00", "+0100", or simply "+01"
        if (Length(TZD) < 3) or ((TZD[0 + StringStartOffset] <> '+') and (TZD[0 + StringStartOffset] <> '-')) then
          raise EConvertError.CreateFmt(SInvalidTimeToken, [TimeToken]);

        if TZD[0 + StringStartOffset] = '+' then DeltaSign := 1 else DeltaSign := -1;

        DeltaHours := StrToIntDef(StringSubstring(TZD, StringStartOffset + 1, 2), 0);
        TZD := StringSubstring(TZD, StringStartOffset + 3, Length(TZD));

        if Length(TZD) > 0 then
        begin
          if TZD[0 + StringStartOffset] = ':' then
            TZD := StringSubstring(TZD, StringStartOffset + 1, Length(TZD));
          if Length(TZD) <> 2 then
            raise EConvertError.CreateFmt(SInvalidTimeToken, [TimeToken]);
          DeltaMins := StrToIntDef(TZD, 0);
        end;
      end;
    end;
  end;
  // encoding date
  Result := EncodeDate(Year, Month, Day) + EncodeTime(Hour, Mn, Sec, MSec);
  // correcting to UTC
  Delta := DeltaSign * EncodeTime(DeltaHours, DeltaMins, 0, 0);
  Result := Result - Delta;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function DateTimeToISO8601Time(Time : TElDateTime; EncodeMilliseconds : boolean): string;
var
  Year, Month, Day, Hour, Mn, Sec, MSec : word;
begin
  // always expecting the supplied time in UTC, thus encoding the result
  // in one of the following formats:
  // YYYY-MM-DDThh:mm:ssZ / YYYY-MM-DDThh:mm:ss.ffffffZ
  // 
  // CAUTION: Some buggy software (e.g. Windows Azure servers) fail to understand
  // times encoded with milliseconds. Please pass false to the EncodeMilliseconds
  // parameter to suppress milliseconds in the output.
  DecodeDate(Time, Year, Month, Day);
  DecodeTime(Time, Hour, Mn, Sec, MSec);
  Result := Format('%.4u-%.2u-%.2uT%.2u:%.2u:%.2u', [Year, Month, Day, Hour, Mn, Sec]);
  if (MSec <> 0) and EncodeMilliseconds then
    Result := Result + '.' + Format('%.6u', [MSec]);
  Result := Result + 'Z';
end;

// Done 7 / XE5(32) / XE5(64) / Android
function DateTimeToRFC3339(Value: TElDateTime; EncodeMilliseconds: Boolean): string;
var
  Year, Month, Day, Hour, Mn, Sec, MSec : word;
begin
  DecodeDate(Value, Year, Month, Day);
  DecodeTime(Value, Hour, Mn, Sec, MSec);
  Result := Format('%.4u-%.2u-%.2uT%.2u:%.2u:%.2u', [Year, Month, Day, Hour, Mn, Sec]);
  if EncodeMilliseconds then
    Result := Result + '.' + Format('%.3uZ', [MSec])
  else
    Result := Result + 'Z';
end;


{$ifdef SB_WINDOWS_DESKTOP}
// Inner - Not tested
function DrivePresent(const DrivePath: string): Boolean;
var
  i: UINT;
begin
  if (Length(DrivePath) = 0) or (not {$ifdef SB_UNICODE_VCL}CharInSet(DrivePath[StringStartOffset], ['A'..'Z', 'a'..'z']) {$else}(DrivePath[StringStartOffset] in ['A'..'Z', 'a'..'z']) {$endif}) then
  begin
    result := false;
    exit;
  end;
  i := GetDriveType(PChar(DrivePath));
  Result := (i <> DRIVE_NO_ROOT_DIR) and (i <> DRIVE_UNKNOWN);
end;
 {$endif}

// Done 7 / XE5(32) / XE5(64) / Android
function AppendSlash(const Path : string): string;
begin
  Result := Path;
  if (Result <> '') and not {$ifdef SB_UNICODE_VCL}CharInSet(AnsiLastChar(Result)^, ['\', '/']) {$else}(AnsiLastChar(Result)^ in ['\', '/']) {$endif} then
{$ifdef SB_WINDOWS}
    Result := Result + '\';
 {$else}
    Result := Result + '/';
 {$endif}
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function EnsureDirectoryExists(const DirName: string): Boolean;
begin
  result := true;
  if (DirName <> '') and (not DirectoryExists(DirName)) then
    result := CreateDir(DirName);
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function DirectoryExists(DirName: string): boolean;
var
  SRec: TSearchRec;
  LastChar : Char;
begin
  Result := false;

  {$ifdef SB_WINDOWS_DESKTOP}
  if Length(DirName) = 3 then
  begin
    result := DrivePresent(DirName);
    exit;
  end
  else
   {$endif}
  begin
    if (Length(DirName) > 3) then
    begin
      LastChar := Char(DirName[Length(DirName) - StringStartInvOffset]);
      if (LastChar = '\') or (LastChar = '/') then
        DirName := StringRemove(DirName, Length(DirName) - StringStartInvOffset, 1);
    end;
  end;

  if FindFirst(DirName, faAnyFile, SRec) = 0 then
  begin
    if (SRec.Attr and faDirectory) > 0 then Result := true;
  end;
  SysUtils.FindClose(SRec);
end;

{$ifndef D_6_UP}
(*
function OpenFile(const Name : string; Mode : cardinal) : THandle;
{$ifdef WIN32}
var
  Flags, Creation : cardinal;
  FName : PAnsiChar;
{$endif}
begin
{$ifdef WIN32}
  Flags := 0;
  if ((Mode and SB_PGP_FILE_READ) <> 0) then
    Flags := Flags or GENERIC_READ;
  if ((Mode and SB_PGP_FILE_WRITE) <> 0) then
    Flags := Flags or GENERIC_WRITE;
  if ((Mode and SB_PGP_FILE_CREATE) <> 0) then
    Creation := CREATE_ALWAYS
  else
    Creation := OPEN_EXISTING;

  GetMem(FName, Length(Name) + 1);
  try
    SBMove(Name[1], FName^, Length(Name));
    FName[Length(Name)] := #0;
    Result := CreateFile(FName, FLags, 0, nil, Creation, 0, 0);
    if Result = INVALID_HANDLE_VALUE then
      {$ifdef SB_VCL}
      raise EElPGPFileException.CreateFmt(SPGPFailedToOpenFile, [Name]);
      {$else}
      raise EElPGPFileException.Create(String.Format(SPGPFailedToOpenFile, [Name]));
      {$endif}
  finally
    FreeMem(FName);
  end;
{$else}
  raise EElPGPUserException.Create(SPGPNotImplemented);
{$endif}
end;
*)

// Todo - Delphi 5
function ReadFile(Handle : THandle; Buffer : pointer; Count : cardinal) : cardinal;
{$ifdef WIN32}
var
  ReadBytes : cardinal;
 {$endif}
begin
{$ifdef WIN32}
  if Windows.ReadFile(Handle, Buffer^, Count, ReadBytes, nil) then
    Result := ReadBytes
  else
    Result := 0;
 {$else}
  error we must not get here
  //raise EElPGPUserException.Create(SPGPNotImplemented);
 {$endif}
end;

// Todo - Delphi 5
function WriteFile(Handle : THandle; Buffer : pointer; Count : cardinal) : cardinal;
{$ifdef WIN32}
var
  WriteBytes : cardinal;
 {$endif}
begin
{$ifdef WIN32}
  if Windows.WriteFile(Handle, Buffer^, Count, WriteBytes, nil) then
    Result := WriteBytes
  else
    Result := 0;
 {$else}
  error we must not get here
  //raise EElPGPUserException.Create(SPGPNotImplemented);
 {$endif}
end;

// Todo - Delphi 5
function GetFileSize(Handle : THandle) : Int64;
{$ifdef WIN32}
var
  lo, hi : cardinal;
 {$endif}
begin
{$ifdef WIN32}
  lo := Windows.GetFileSize(Handle, @hi);
  if ((lo = $FFFFFFFF) and (GetLastError() <> NO_ERROR)) then
    Result := 0
  else
    Result := lo + hi * $100000000;
 {$else}
  error we must not get here
  //raise EElPGPUserException.Create(SPGPNotImplemented);
 {$endif}
end;

// Todo - Delphi 5
procedure CloseFile(Handle : THandle);
begin
{$ifdef WIN32}
  Windows.CloseHandle(Handle);
 {$else}
  error we must not get here
  //raise EElPGPUserException.Create(SPGPNotImplemented);
 {$endif}
end;

// Todo - Delphi 5
function GetFilePosition(Handle : THandle) : Int64;
var
  OffHigh, OffLow : cardinal;
const
  INVALID_SET_FILE_POINTER = cardinal(-1);
begin
  {$ifdef WIN32}
  OffHigh := 0;
  OffLow := SetFilePointer(Handle, 0, @OffHigh, FILE_CURRENT);
  if (OffLow = INVALID_SET_FILE_POINTER) and (GetLastError() <> NO_ERROR) then
    Result := -1
  else
    Result := (Int64(OffHigh) shl 32) or Int64(OffLow);
   {$else}
  error we must not get here
  //raise EElPGPUserException.Create(SPGPNotImplemented);
   {$endif}
end;

// Todo - Delphi 5
procedure SetFilePosition(Handle : THandle; Position : Int64);
var
  PosRec : Int64Rec;
begin
  SBMove(Position, PosRec, Sizeof(Int64));
  {$ifdef WIN32}
  SetFilePointer(Handle, PosRec.Lo, @PosRec.Hi, FILE_BEGIN);
   {$else}
  error we must not get here
  //raise EElPGPUserException.Create(SPGPNotImplemented);
   {$endif}
end;

 {$endif}

// Done 7 / XE5(32) / XE5(64) / Android
function TrimLeadingZeros(const V : ByteArray): ByteArray;
var
  Index : integer;
  Len : integer;
begin
  Len := Length(V);
  Index := 0;
  while (Index < Len) and (V[Index] = 0) do
    Inc(Index);
  SetLength(Result, Len - Index);
  SBMove(V[Index], Result[0], Length(Result));
end;

// Done 7 / XE5(32) / XE5(64) / Android
function PrefixByteArray(Buffer : ByteArray; Count : integer; Value : Byte) : ByteArray;
var i : integer;
begin
  // DeN 25.10.2013
  if Count < 0 then
    Count := 0;
  // end DeN 25.10.2013
  	
  SetLength(Result, Length(Buffer) + Count);
  
  if Count > 0 then
  begin
    for i := 0 to Count - 1 do
       Result[i] := Value;
  end;
  
  SBMove(Buffer[0], Result[Count], Length(Buffer));
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SuffixByteArray(Buffer : ByteArray; Count : integer; Value : Byte) : ByteArray;
var i : integer;
begin
  // DeN 25.10.2013
  if Count < 0 then
    Count := 0;
  // end DeN 25.10.2013
  	
  SetLength(Result, Length(Buffer) + Count);
  SBMove(Buffer[0], Result[0], Length(Buffer));
  for i := 0 to Count - 1 do
    Result[Length(Buffer) + i] := Value;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure FillByteArray(Buffer : ByteArray; SrcOffset : integer; Count : integer; Value : byte);
var i : integer;
begin
  // DeN 25.10.2013
  if (Buffer = nil) or
     (Count <= 0)   or
     (SrcOffset > Length(Buffer)) then
    Exit;

  if (Count > Length(Buffer) - SrcOffset) then
    Count := Length(Buffer) - SrcOffset;
  // end DeN 25.10.2013
  	
  for i := SrcOffset to SrcOffset + Count - 1 do
    Buffer[i] := Value;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure FillByteArray(Buffer : ByteArray; Value : byte);
begin
  FillByteArray(Buffer, 0, Length(Buffer), Value);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ArrayStartsWith(const SubP, P : ByteArray) : boolean;
var i : integer;
begin
  if (Length(SubP) > Length(P)) or
     ((SubP = nil) and (P = nil)) then // DeN 15.10.2013
    result := false
  else
  begin
    result := true;
    for i := 0 to Length(SubP) - 1 do
      if P[i] <> SubP[i] then
      begin
        result := false;
        exit;
      end;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function CompareArrays(const Buf1, Buf2 : ByteArray) : integer;
var
  I, Cnt : integer;
begin
  Cnt := Min(Length(Buf1), Length(Buf2));
  Result := 0;
  I := 0;
  while I < Cnt do
  begin
    if Buf1[I] < Buf2[I] then
    begin
      Result := -1;
      Exit;
    end
    else
    if Buf2[I] < Buf1[I] then
    begin
      Result := 1;
      Exit;
    end;
    Inc(I);
  end;
  if Length(Buf2) > Length(Buf1) then
    Result := -1
  else
  if Length(Buf1) > Length(Buf2) then
    Result := 1;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function CompareBuffers(const Buf1, Buf2 : ByteArray) : integer;
var
  I, Cnt : integer;
begin
  Cnt := Min(Length(Buf1), Length(Buf2));
  Result := 0;
  I := 0;
  while I <= Cnt - 1 do
  begin
    if Buf1[I] < Buf2[I] then
    begin
      Result := -1;
      Exit;
    end
    else
    if Buf2[I] < Buf1[I] then
    begin
      Result := 1;
      Exit;
    end;
    Inc(I);
  end;
  if Length(Buf2) > Length(Buf1) then
    Result := -1
  else
  if Length(Buf1) > Length(Buf2) then
    Result := 1;
end;


{$ifndef FPC}
{$ifndef DELPHI_MAC}
// Done 7 / XE5(32), Need - check in XE5(64) / Android
function IsValidVCLObject(Obj: pointer): boolean;
const
  {$ifdef D_12_UP}
  VMTREF_UBOUND = 20; // D2009+
   {$else}
  VMTREF_UBOUND = 17; // D5 to 2007
   {$endif}
type
  PPVmt = ^PVmt;
  PVmt = ^TVmt;
  TVmt = record
    SelfPtr : TClass;
    Other   : array[0..VMTREF_UBOUND] of pointer;
  end;
var
  Vmt: PVmt;
  ObjCand : TObject;
begin
  if Obj <> nil then
  begin
    try
      ObjCand := TObject(Obj);
      Vmt := PVmt(ObjCand.ClassType);
      if (Vmt <> nil) then
      begin
        Dec(Vmt);
        if IsBadReadPtr(Vmt, (VMTREF_UBOUND + 2) * SizeOf(pointer)) then
          Result := false
        else
          Result := ObjCand.ClassType = Vmt.SelfPtr;
      end
      else
        Result := false;
    except
      Result := false;
    end;
  end
  else
    Result := false;
end;
 {$endif}
 {$endif}


{$ifdef SB_WINDOWS}
// Todo - Windows
function WaitFor(Handle: THandle): LongWord;
var
  Msg: TMsg;
  H: THandle;
begin
  H := Handle;
  if GetCurrentThreadID = MainThreadID then
    while MsgWaitForMultipleObjects(1, H, False, INFINITE,
      QS_SENDMESSAGE) = WAIT_OBJECT_0 + 1 do PeekMessage(Msg, 0, 0, 0, PM_NOREMOVE)
  else WaitForSingleObject(H, INFINITE);
  GetExitCodeThread(H, Result);
end;
 {$endif}

{$ifdef SB_UNIX}
{$ifndef SB_MACOS}
// Todo - Linux
function WaitFor(Thread : TThread): LongWord;
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
var X: Pointer;
 {$endif}
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  X := @Result;
{$ifdef SB_ANDROID}
  Assert(false, 'Android needs special attention');
 {$else}
  pthread_join(Thread.ThreadID, X);
 {$endif}
 {$endif}
end;

{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
// Todo - ANDROID
function WaitFor(ThreadID : TThreadID): LongWord;
var X: Pointer;
begin
  X := @Result;
{$ifdef SB_ANDROID}
  Assert(false, 'Android needs special attention');
 {$else}
  pthread_join(ThreadID, X);
 {$endif}
end;
 {$endif}
 {$endif}
 {$endif}

{$ifdef SB_MACOS}
// Todo - MacOS
function WaitFor(Thread : TThread): LongWord;
begin
  Assert(false, 'MacOS needs special attention');
end;

{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
// Todo - MacOS
function WaitFor(ThreadID : TThreadID): LongWord;
begin
  Assert(false, 'MacOS needs special attention');
end;
 {$endif}
 {$endif}

// Done 7 / XE5(32) / XE5(64) / Android
// Maybe need to check if first element in [0, 2]
// and if second element in [0, 39] like StrToOID?
function IsTextualOID(const S : string): boolean;
var
  I : integer;
begin
  Result := true;

  // DeN 29.11.2013
  if Length(S) = 0 then
    Result := false;
  // end DeN 29.11.2013

  for I := StringStartOffset to Length(S) - StringStartInvOffset do
    if not (((PByte(@S[I])^ >= $30) and (PByte(@S[I])^ <= $39)) or (S[I] = '.')) then
    begin
      Result := false;
      Break;
    end;
end;

procedure SetLicenseKey(const Key : string);
begin
;
end;

procedure CheckLicenseKey;
begin
  ;
end;










// Todo - Example ???
function HexDump(const Buffer: ByteArray; Offset: Cardinal; Len: Cardinal): string;
var
  I: Integer;
begin
  if Len = 0 then
    Len := Cardinal(Length(Buffer)) - Offset;
  Result := '';
  if Len = 0 then
    Exit;
  for I := Offset to Offset + Len - 1 do
  begin
    if Result <> '' then
      Result := Result + ' ';
    Result := Result + IntToHex(Buffer[I], 2);
  end;
end;

// Todo - Example ???
function HexDump(const Buffer: ByteArray; Offset: Cardinal; Len: Cardinal; AddChars: Boolean): string;
var
  I, J, Rows, Done, Current: Cardinal;
  Row, Chars: string;
begin
  if Len = 0 then
    Len := Cardinal(Length(Buffer)) - Offset;
  Result := '';
  if Len = 0 then
    Exit;
    Rows := Len shr 4;
    if (Len mod 16) <> 0 then
      Inc(Rows);
    Done := 0;
    for I := 0 to Rows - 1 do
    begin
      Row := '';
      Chars := '';
      for J := 0 to 15 do
      begin
        Current := Offset + Done;
        if Row <> '' then
          if J = 8 then
            Row := Row + '-'
          else
            Row := Row + ' ';
        Row := Row + IntToHex(Buffer[Current], 2);
        if AddChars then
          if Buffer[Current] < 31 then
            Chars := Chars + '.'
          else
            Chars := Chars + Chr(Buffer[Current]);
        Inc(Done);
        if Done = Len then
          Break;
      end;
      if AddChars then
        Result := Result + Row + StringOfChar(' ', 50 - Length(Row)) + Chars + #13#10
      else
        Result := Result + Row + #13#10;
    end;
end;

const
  OneMillisecond = 1 / (24 * 60 * 60 * 1000);

// Done 7 / XE5(32) / XE5(64) / Android
function SBEncodeDateTime(Year, Month, Day, Hour, Minute, Second, Millisecond: Integer): TElDateTime;
begin
  Result := EncodeDate(Year, Month, Day) + EncodeTime(Hour, Minute, Second, Millisecond);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SBSameDateTime(A, B: TElDateTime): Boolean;
begin
  Result := Abs(A - B) < OneMillisecond;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SBSameDate(A, B: TElDateTime): Boolean;
begin
  Result := Trunc(A) = Trunc(B);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function SBSameTime(A, B: TElDateTime): Boolean;
begin
  Result := Abs(Frac(A) - Frac(B)) < OneMillisecond;
end;

{$ifdef SB_NO_NET_ARRAYLIST}
// Todo - NET
constructor ArrayList.Create;
begin
  FList := new List<System.Object>;
  FSynchronized := false;
end;

// Todo - NET
constructor ArrayList.Create(Source : ICollection);
var Enum : IEnumerator;
begin
  FList := new List<System.Object>;
  FSynchronized := false;

  Enum := Source.GetEnumerator;
  while Enum.MoveNext do FList.Add(Enum.Current);
end;

// Todo - NET
constructor ArrayList.Create(Capacity : Int32);
begin
  FList := new List<System.Object>(Capacity);
end;

// Todo - NET
function ArrayList.Add(Value: System.Object): Int32;
begin
  FList.Add(Value);
  result := FList.Count - 1;
end;

// Todo - NET
function ArrayList.Contains(value: System.Object): Boolean;
begin
  result := FList.Contains(value);
end;

// Todo - NET
procedure ArrayList.Clear;
begin
  FList.Clear;
end;

// Todo - NET
function ArrayList.GetReadOnly : Boolean;
begin
  result := false;
end;

// Todo - NET
function ArrayList.GetFixedSize : Boolean;
begin
  result := false;
end;

// Todo - NET
function ArrayList.GetSynchronized : Boolean;
begin
  result := FSynchronized;
end;

// Todo - NET
function ArrayList.IndexOf(value: System.Object): System.Int32; 
begin
  result := FList.IndexOf(Value);
end;

// Todo - NET
function ArrayList.IndexOf(value: System.Object; StartIndex : Int32): System.Int32; 
begin
  result := FList.IndexOf(Value, StartIndex);
end;

// Todo - NET
function ArrayList.IndexOf(value: System.Object; StartIndex, Count : Int32): System.Int32; 
begin
  result := FList.IndexOf(Value, StartIndex, Count);
end;

// Todo - NET
function ArrayList.LastIndexOf(value: System.Object): System.Int32; 
begin
  result := FList.LAstIndexOf(Value);
end;

// Todo - NET
function ArrayList.LastIndexOf(value: System.Object; StartIndex : Int32): System.Int32; 
begin
  result := FList.LastIndexOf(Value, StartIndex);
end;

// Todo - NET
function ArrayList.LastIndexOf(value: System.Object; StartIndex, Count : Int32): System.Int32; 
begin
  result := FList.LastIndexOf(Value, StartIndex, Count);
end;

// Todo - NET
procedure ArrayList.Insert(index: Int32; value: System.Object); 
begin
  FList.Insert(index, value);  
end;

procedure ArrayList.Remove(value: System.Object); 
begin
  FList.Remove(Value);
end;

// Todo - NET
procedure ArrayList.RemoveAt(index: System.Int32);
begin
  FList.RemoveAt(index);
end;

// Todo - NET
procedure ArrayList.CopyTo(AnArray: Array; index: System.Int32);
begin
  FList.CopyTo(AnArray as Array Of Object, index);
end;

// Todo - NET
procedure ArrayList.CopyTo(AnArray: Array);
begin
  FList.CopyTo(AnArray as Array Of Object);
end;

// Todo - NET
procedure ArrayList.CopyTo(Index : Int32; AnArray: Array; ArrayIndex: Int32; aCount : Int32); 
begin
  FList.CopyTo(Index, AnArray as Array Of Object, ArrayIndex, aCount);
end;

// Todo - NET
function ArrayList.Clone : System.Object; 
begin
  result := new ArrayList(Self);
end;

// Todo - NET
function ArrayList.GetCapacity : Int32;
begin
  result := FList.Capacity;
end;

// Todo - NET
procedure ArrayList.SetCapacity(Value : Int32);
begin
  FList.Capacity := Value;
end;

// Todo - NET
function ArrayList.GetEnumerator: IEnumerator;
begin
  //result := new ArrayListEnumerator(Self);
  result := FList.GetEnumerator();
end;

// Todo - NET
procedure ArrayList.AddRange(C : ICollection);
begin
  InsertRange(Count,C);
end;

// Todo - NET
procedure ArrayList.InsertRange(Index : Int32; C : ICollection);
var Enum : IEnumerator;
begin
  if Capacity - Count < C.Count then 
    Capacity := Capacity + C.Count;
  
  Enum := C.GetEnumerator;
  while Enum.MoveNext do 
  begin
    if Index >= Count then 
      FList.Add(Enum.Current)
    else
      FList.Insert(Index, Enum.Current);
    inc(Index);
  end;
end;

// Todo - NET
procedure ArrayList.RemoveRange(Index, Count: System.Int32); 
begin
  FList.RemoveRange(Index, Count);
end;

// Todo - NET
procedure ArrayList.Reverse; 
begin
  FList.Reverse;
end;

// Todo - NET
procedure ArrayList.Reverse(Index, Count: System.Int32); 
begin
  FList.Reverse(Index, Count);
end;

// Todo - NET
procedure ArrayList.Sort; 
begin
  FList.Sort();
end;

type
  {$ifndef SB_NO_NET_ICOMPARERTPL}
  TElInternalObjectComparer = class(IComparer<Object>)
   {$else}
  TElInternalObjectComparer = class(IComparer)
   {$endif}
  protected
    FOrigComparer : IComparer;
    FOrigComparerObj : IComparer<Object>;
  public
    constructor Create;
    procedure Init(OrigComparer: IComparer);
    procedure Init<T>(OrigComparer : IComparer<T>); 
    function Compare(X, Y : Object): integer;
  end;

constructor TElInternalObjectComparer.Create;
begin
  inherited Create;
  FOrigComparer := nil;
  FOrigComparerObj := nil;
end;

// Todo - NET
procedure TElInternalObjectComparer.Init(OrigComparer: IComparer);
begin
  FOrigComparer := OrigComparer;
end;

// Todo - NET
procedure TElInternalObjectComparer.Init<T>(OrigComparer : IComparer<T>);
begin
  if not (OrigComparer is IComparer<Object>) then
    raise ESecureBlackboxError.Create('Only IComparer<Object> parameter is supported');
  FOrigComparerObj := IComparer<Object>(OrigComparer);
end;

// Todo - NET
function TElInternalObjectComparer.Compare(X, Y : Object): integer;
begin
  if FOrigComparer <> nil then
    Result := FOrigComparer.Compare(X, Y)
  else
    Result := IComparer<Object>(FOrigComparerObj).Compare(X, Y);
end;

// Todo - NET
procedure ArrayList.Sort(Comparer : IComparer);
var
  ObjCmp : TElInternalObjectComparer;
begin
  if Comparer <> nil then
  begin
    // FList.Sort(IComparer<Object>(Comparer)); 
    ObjCmp := TElInternalObjectComparer.Create();
    try
      ObjCmp.Init(Comparer);
      FList.Sort({$ifndef SB_NO_NET_ICOMPARER_SORT}ObjCmp {$else}new System.Comparison<Object>(ObjCmp.Compare) {$endif});
    finally
      ObjCmp := nil;
    end; 
  end
  else
    FList.Sort();
end;

// Todo - NET
procedure ArrayList.Sort<T>(Comparer : IComparer<T>);
var
  ObjCmp : TElInternalObjectComparer;
begin
  if Comparer <> nil then
  begin
    // FList.Sort(IComparer<Object>(Comparer)); 
    ObjCmp := TElInternalObjectComparer.Create();
    try
      ObjCmp.Init(Comparer);
      FList.Sort({$ifndef SB_NO_NET_ICOMPARER}ObjCmp {$else}new System.Comparison<Object>(ObjCmp.Compare) {$endif});
    finally
      ObjCmp := nil;
    end; 
  end
  else
    FList.Sort();
end;

// Todo - NET
procedure ArrayList.Sort(Index, Count : integer; Comparer : IComparer);
var
  ObjCmp : TElInternalObjectComparer;
begin
  ObjCmp := TElInternalObjectComparer.Create();
  try
    ObjCmp.Init(Comparer);
    FList.Sort(Index, Count, ObjCmp);
  finally
    ObjCmp := nil;
  end;
end;

// Todo - NET
procedure ArrayList.Sort<T>(Index, Count : integer; Comparer : IComparer<T>);
var
  ObjCmp : TElInternalObjectComparer;
begin
  ObjCmp := TElInternalObjectComparer.Create();
  try
    ObjCmp.Init(Comparer);
    FList.Sort(Index, Count, ObjCmp);
  finally
    ObjCmp := nil;
  end;
end;

// Todo - NET
function ArrayList.GetRange(Index, Count: System.Int32) : ArrayList; 
var i : Integer;
begin
  result := new ArrayList(Count);
  if Index + Count > Self.Count then 
    Count := Self.Count - Index;
  i := 0; 
  while i < Count do 
  begin
    result.Add(Item[Index + i]);
    inc(i);
  end;
end;

// Todo - NET
function ArrayListEnumerator.GetCurrent : Object;
begin
  if FIndex < FList.Count then
    result := FList.Item[FIndex]
  else
    result := nil;
end;

// Todo - NET
constructor ArrayListEnumerator.Create(List : ArrayList);
begin
  FList := List;
  FIndex := -1;
end;

// Todo - NET
procedure ArrayListEnumerator.Reset;
begin
  FIndex := -1;
end;

// Todo - NET
function ArrayListEnumerator.MoveNext : boolean;
begin
  inc(FIndex);
  result := FIndex >= FList.Count;
end;
 {$endif}




// Done 7 / XE5(32) / XE5(64) / Android
function DateTimeAddDays(DateTime: TElDateTime; Days: Integer): TElDateTime;
begin
  Result := DateTime + Days;


end;

// Done 7 / XE5(32) / XE5(64) / Android
function DateTimeAddHours(DateTime: TElDateTime; Hours: Integer): TElDateTime;
begin
  Result := DateTime + Hours / HoursInDay;


end;

// Done 7 / XE5(32) / XE5(64) / Android
function DateTimeAddMinutes(DateTime: TElDateTime; Minutes: Integer): TElDateTime;
begin
  Result := DateTime + Minutes / MinutesInDay;


end;

//function DateTimeAddMonths(DateTime: TElDateTime; Months: Integer): TElDateTime; {$ifdef OXYGENE}public;{$endif}
//begin
//  !!! NOT IMPLEMENTED !!!
//end;

// Done 7 / XE5(32) / XE5(64) / Android
function DateTimeAddSeconds(DateTime: TElDateTime; Seconds: Integer): TElDateTime;
begin
  Result := DateTime + Seconds / SecondsInDay;


end;

// Done 7 / XE5(32) / XE5(64) / Android
function DateTimeAddYears(DateTime: TElDateTime; Years: Integer): TElDateTime;
var
  Year, Month, Day: Word;
begin
  DecodeDate(DateTime, Year, Month, Day);
  Inc(Year, Years);
  Result := EncodeDate(Year, Month, Day) + Frac(DateTime);


end;

// Done 7 / XE5(32) / XE5(64) / Android
function DateTimeAfter(DT1, DT2: TElDateTime): Boolean;
begin
  Result := (Trunc(DT1 * MSecsPerDay) > Trunc(DT2 * MSecsPerDay));


end;

// Done 7 / XE5(32) / XE5(64) / Android
function DateTimeBefore(DT1, DT2: TElDateTime): Boolean;
begin
  Result := (Trunc(DT1 * MSecsPerDay) < Trunc(DT2 * MSecsPerDay));


end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
function DateTimeClone(DateTime: TElDateTime): TElDateTime;
begin
  Result := DateTime;


end;

// Done 7 / XE5(32) / XE5(64) / Android
function DateTimeCompare(DT1, DT2: TElDateTime): Integer;
begin
  Result := Trunc(DT1 * MSecsPerDay) - Trunc(DT2 * MSecsPerDay);


end;

// Done 7 / XE5(32) / XE5(64) / Android
function DateTimeEquals(DT1, DT2: TElDateTime): Boolean;
begin
  Result := (Trunc(DT1 * MSecsPerDay) = Trunc(DT2 * MSecsPerDay));


end;

// Done 7 / XE5(32) / XE5(64) / Android
function DateTimeNow(): TElDateTime;
begin
  Result := SysUtils.Now();


end;

// VCL and FPC for Windows
 {$ifdef SB_WINDOWS}
// Done 7 / XE5(32) / XE5(64) / Android
function DateTimeUtcNow(): TElDateTime;
var
  ST: TSystemTime;
begin
  GetSystemTime(ST);
  Result := EncodeDate(ST.wYear, ST.wMonth, ST.wDay) + EncodeTime(ST.wHour, ST.wMinute, ST.wSecond, ST.wMilliseconds);
end;
 {$endif} 

// FPC for Linux and MacOS
 {$ifdef SB_POSIX}
{$ifndef DELPHI_MAC}
{$ifndef SB_ANDROID}
// Todo - Linux
function DateTimeUtcNow(): TElDateTime;
begin
  Result := Now() - (TZSeconds / 86400);
end;
 {$else}
function DateTimeUtcNow(): TElDateTime;
(*
var
  T: time_t;
  TV: timeval;
  UT: tm;
*)
begin
  Result := SysUtils.Now();
  // NOT IMPLEMENTED
(*
  gettimeofday(TV, nil);
  T := TV.tv_sec;
  gmtime_r(T, UT);
  Result := EncodeDate(UT.tm_year + 1900, UT.tm_mon + 1, UT.tm_mday) +
    EncodeTime(UT.tm_hour, UT.tm_min, UT.tm_sec, TV.tv_usec div 1000);
*)
end;
 {$endif}
 {$endif}
 {$endif} 

// VCL for MacOS
{$ifdef DELPHI_MAC}
function DateTimeUtcNow(): TElDateTime;
var
  T: time_t;
  TV: timeval;
  UT: tm;
begin
  gettimeofday(TV, nil);
  T := TV.tv_sec;
  gmtime_r(T, UT);
  Result := EncodeDate(UT.tm_year + 1900, UT.tm_mon + 1, UT.tm_mday) +
    EncodeTime(UT.tm_hour, UT.tm_min, UT.tm_sec, TV.tv_usec div 1000);
end;
 {$endif}
// .NET
// JAVA

{$ifdef SB_ANSI_VCL}
// Done 7
function AnsiStringOfBytes(const Src : ByteArray) : AnsiString;
begin
  SetLength(Result, Length(Src));
  SBMove(Src[0], Result[AnsiStrStartOffset], Length(Result));
end;
 {$else}
function AnsiStringOfBytes(const Src : ByteArray) : AnsiString;
var
  i : integer;
begin
  SetLength(Result, Length(Src));

  for i := 0 to Length(Src) - 1 do
    Result[i + AnsiStrStartOffset] := AnsiChar(Src[i]);
end;
 {$endif}

// Done 7 / XE5(32) / XE5(64) / Android
function CreateByteArrayConst(const Src : {$ifndef SB_PASCAL_STRINGS}string {$else}AnsiString {$endif}): ByteArray;
begin
  Result := {$ifndef SB_PASCAL_STRINGS}BytesOfString {$else}BytesOfAnsiString {$endif}(Src);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function AnsiStringOfString(const Str : string) : AnsiString;
{$ifndef SB_PASCAL_STRINGS}
var i : integer;
 {$endif}
begin
  {$ifdef SB_PASCAL_STRINGS}
  result := AnsiString(str);
   {$else}
  SetLength(result, Length(Str));
  for I := StringStartOffset to Length(Str) - StringStartInvOffset do
    result[I - StringStartOffset + AnsiStrStartOffset] := AnsiChar(Str[i]);
   {$endif}
end;

// Done 7 / XE5(32) / XE5(64) / Android
function StringOfAnsiString(const Str : AnsiString) : String;
{$ifndef SB_PASCAL_STRINGS}
var i : integer;
 {$endif}
begin
  {$ifdef SB_PASCAL_STRINGS}
  result := String(str);
   {$else}
  SetLength(result, Length(Str));
  for I := AnsiStrStartOffset to Length(Str) - AnsiStrStartInvOffset do
    result[I + StringStartOffset - AnsiStrStartOffset] := Char(Str[i]);
   {$endif}
end;

// Done 7 / XE5(32) / XE5(64) / Android
function BytesOfAnsiString(const Str : AnsiString) : ByteArray;
begin
  SetLength(result, Length(Str));
  SBMove(Str[AnsiStrStartOffset], Result[0], Length(Str));
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
// identical to GetByteArrayFromInt64BE(Value: Int64)?
function GetBytes64(const X : Int64) : ByteArray;
begin
  SetLength(Result, Sizeof(X));
  Result[0] := X shr 56;
  Result[1] := (X shr 48) and $ff;
  Result[2] := (X shr 40) and $ff;
  Result[3] := (X shr 32) and $ff;
  Result[4] := (X shr 24) and $ff;
  Result[5] := (X shr 16) and $ff;
  Result[6] := (X shr 8) and $ff;
  Result[7] := X and $FF;
end;

// Done 7 / XE5(32) / XE5(64) / Android
// identical to GetByteArrayFromDWordBE(Value: cardinal)?
function GetBytes32(const X : Longword) : ByteArray;
begin
  SetLength(Result, Sizeof(X));
  Result[0] := X shr 24;
  Result[1] := (X shr 16) and $ff;
  Result[2] := (X shr 8) and $ff;
  Result[3] := X and $FF;
end;

// Done 7 / XE5(32) / XE5(64) / Android
// identical to GetByteArrayFromWordBE(Value : Word)?
function GetBytes16(const X : Word) : ByteArray;
begin
  SetLength(Result, Sizeof(X));
  Result[0] := X shr 8;
  Result[1] := X and $FF;
end;

// Done 7 / XE5(32) / XE5(64) / Android
// identical to GetByteArrayFromByte(Value : Byte)?
function GetBytes8(const X : Byte) : ByteArray;
begin
  SetLength(Result, Sizeof(X));
  Result[0] := X;
end;

// Done 7 / XE5(32) / XE5(64) / Need - check in Android
// identical to GetByteArrayFromInt64BE(Value : Int64; Dest : ByteArray; Position : integer)?
procedure GetBytes64(const X : Int64; var Buffer : ByteArray; Index : integer);
begin
  if Length(Buffer) >= Index + sizeof(Int64) then // DeN 07.11.2013
  begin
    Buffer[Index + 0] := X shr 56;
    Buffer[Index + 1] := (X shr 48) and $ff;
    Buffer[Index + 2] := (X shr 40) and $ff;
    Buffer[Index + 3] := (X shr 32) and $ff;
    Buffer[Index + 4] := (X shr 24) and $ff;
    Buffer[Index + 5] := (X shr 16) and $ff;
    Buffer[Index + 6] := (X shr 8) and $ff;
    Buffer[Index + 7] := X and $FF;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
// identical to GetByteArrayFromDWordBE(Value : Cardinal; Dest : ByteArray; Position : integer)?
procedure GetBytes32(const X : Longword; var Buffer : ByteArray; Index : integer);
begin
  if Length(Buffer) >= Index + sizeof(Longword) then // DeN 07.11.2013
  begin
    Buffer[Index + 0] := X shr 24;
    Buffer[Index + 1] := (X shr 16) and $ff;
    Buffer[Index + 2] := (X shr 8) and $ff;
    Buffer[Index + 3] := X and $FF;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
// identical to GetByteArrayFromWordBE(Value : Word; Dest : ByteArray; Position : integer)?
procedure GetBytes16(const X : Word; var Buffer : ByteArray; Index : integer);
begin
  if Length(Buffer) >= Index + sizeof(Word) then // DeN 07.11.2013
  begin
    Buffer[Index + 0] := X shr 8;
    Buffer[Index + 1] := X and $FF;
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
// identical to GetByteArrayFromByte(Value : Byte; Dest : ByteArray; Position : integer)?
procedure GetBytes8(const X : Byte; var Buffer : ByteArray; Index : integer);
begin
  if Length(Buffer) >= Index + sizeof(Byte) then
    Buffer[Index] := X;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function ConstLength(Arr : TByteArrayConst) : integer;
begin
  result := Length(Arr);
end;

// Done 7 / XE5(32) / XE5(64) / Android
function TElByteArrayList.Add(const S: ByteArray): Integer;
begin
  if Length(FList) < FCount + 1 then
    SetLength(FList, FCount * 2 + 1);
  FList[FCount] := SBCopy(S);
  Inc(FCount);



  result := Count - 1;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure TElByteArrayList.AddRange(List: TElByteArrayList);
var
  i: Integer;
begin
  for i := 0 to List.Count - 1 do
    Add(List.GetItem(i));
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure TElByteArrayList.Assign(Source: TElByteArrayList);
var
  i: Integer;
begin
  Clear;
  for i := 0 to Source.Count - 1 do
    Add(Source.GetItem(i));
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure TElByteArrayList.Clear;
var
  Tmp : ByteArray;
begin
  while Count > 0 do
  begin
    Tmp := GetItem(Count - 1);
    Dec(FCount);
    ReleaseArray(Tmp);
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
procedure TElByteArrayList.Delete(Index: Integer);
var
  Tmp : ByteArray;
begin
  if (Index >= 0) and (Index <  Self.FCount ) then // DeN 30.11.2013
  begin
    Tmp := GetItem(Index);
    BMove(FList, Index + 1, FList, Index, FCount - Index - 1);
    Dec(FCount);
    ReleaseArray(Tmp);
  end;
end;

constructor TElByteArrayList.Create;
begin
  inherited;
  SetLength(FList, 8);
  FCount := 0;
end;

destructor TElByteArrayList.Destroy;
begin
  Clear;
  SetLength(FList, 0);
  inherited;
end;

procedure TElByteArrayList.BMove(const Src: array of ByteArray; SrcOffset: Integer;
  var Dst: array of ByteArray; DstOffset: Integer; Size: Integer);
var
  i : integer;
begin
  if (Length(Src) = 0) or (Length(Dst) = 0) or (Size = 0) then
    Exit;

  if (@Src[0] <> @Dst[0]) or (DstOffset < SrcOffset) or (SrcOffset + Size < DstOffset) then
  begin
    for i := 0 to Size - 1 do
      Dst[DstOffset + i] := Src[SrcOffset + i];
  end
  else
  begin
    for i := Size - 1 downto 0 do
      Dst[DstOffset + i] := Src[SrcOffset + i];
  end;
end;

// Done 7 / XE5(32) / XE5(64) / Android
function TElByteArrayList.IndexOf(const S: ByteArray): Integer;
begin
  for Result := 0 to Count - 1 do
  begin
    if CompareContent(GetItem(Result), S) then
      Exit;
  end;
  Result := -1;
end;

// Need check
procedure TElByteArrayList.Insert(Index: Integer; const S: ByteArray);
begin
  if (Index < 0) or (Index > FCount) then
    raise Exception.Create('Index is out of range');

  if Length(FList) < FCount + 1 then
    SetLength(FList, FCount * 2 + 1);

  BMove(FList, Index, FList, Index + 1, FCount - Index);
  FList[Index] := Copy(S, 0, Length(S));
  Inc(FCount);
end;

// Not tested
function TElByteArrayList.GetCount : integer;
begin
  result := FCount;
end;

// Not tested
function TElByteArrayList.GetCapacity : integer;
begin
  result := Length(FList);
end;

// Not tested
procedure TElByteArrayList.SetCapacity(NewCapacity: Integer);
begin
  if NewCapacity > Length(FList) then
    SetLength(FList, NewCapacity);
end;

// Not tested
function TElByteArrayList.GetItem(Index: integer) : ByteArray;
begin
  if (Index < 0) or (Index >= FCount) then
    raise Exception.Create('Index is out of range');
  Result := FList[Index];
end;

// Not tested
procedure TElByteArrayList.SetItem(Index: integer; const Value: ByteArray);
begin
  if (Index < 0) or (Index >= FCount) then
    raise Exception.Create('Index is out of range');
  FList[Index] := Value;
end;


initialization




  {$ifdef SB_PGPSFX_STUB}
  SBStrUtils.SetGlobalConverter(TElPlatformStringConverter.Create);
   {$else}
  SBStrUtils.SetGlobalConverter(TElUnicodeConverter.Create);
   {$endif}
  SBRndInit;
finalization
  SBRndDestroy;
  if Assigned(G_StringConverter) then
    FreeAndNil(G_StringConverter);


end.
