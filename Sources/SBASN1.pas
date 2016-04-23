(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

{$j+}
unit SBASN1;

interface

uses
    SysUtils,
    Classes,
      {$ifdef SB_UNICODE_VCL}
      SBStringList,
       {$endif}
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBConstants;
  

type
  PByte = ^byte;

const
  asn1Boolean         =  1;
  asn1Integer         =  2;
  asn1BitStr          =  3;
  asn1OctetStr        =  4;
  asn1NULL            =  5;
  asn1Object          =  6;
  asn1Real            =  9;
  asn1Enumerated      = 10;
  asn1UTF8String      = 12;

  asn1Sequence        = 16;
  asn1Set             = 17;
  asn1NumericStr      = 18;
  asn1PrintableStr    = 19;
  asn1T61String       = 20;
  asn1TeletexStr      = asn1T61String;
  asn1IA5String       = 22;
  asn1UTCTime         = 23;
  asn1GeneralizedTime = 24;
  asn1VisibleStr      = 26;
  asn1GeneralStr      = 27;

  asn1A0                = 0;
  asn1A1                = 1;
  asn1A2                = 2;
  asn1A3                = 3;
  asn1A4                = 4;
  asn1A5                = 5;
  asn1A6                = 6;
  asn1A7                = 7;
  asn1A8                = 8;


  SB_MAX_ASN1_DEPTH : integer = 1000;

type
  EElASN1Error =  class(ESecureBlackboxError);
  EElASN1ReadError =  class(ESecureBlackboxError);

  asn1TagType = (asn1tUniversal, asn1tApplication, asn1tSpecific, asn1tPrivate, asn1tEOC);

// + stream read function type, when decoder needs to read stream, it calls this function
// Stream - some pointer (or casted to pointer type) data than identifies real data stream
// Data   - pointer to buffer to store data read from stream to
// Size   - size of data wanted
  asn1tReadFunc         = function (Stream: pointer; Data: pointer; Size: integer): integer; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

// + stream write function type, when encoder needs to write stream, it calls this function
// Stream - some pointer (or casted to pointer type) data than identifies real data stream
// Data   - pointer to buffer to load data written from stream from
// Size   - size of data writing
  asn1tWriteFunc        = procedure (Stream: pointer; Data: pointer; Size: integer); {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

// + callback function type of tag processing function when incoming stream being parsed
// + it shall be called for each data field of incoming stream
// Stream         - some data to give callback function the possibility to differ data treating
//                  depending on stream when incoming stream being parsed
// TagType        - type of read tag
// TagConstrained - if incoming field is constrained i.e. incapsulates some other fields
//                  if it's yes callback won't get any real data
// Tag            - buffer containing tag value
// SizeTag        - size of tag
// Size           - size of incoming data
// Data           - buffer containing data value
// BitRest        - number of significant bits in last data byte (from left to right)
//                  meaningful only for BIT STRING fields, if 0, whole last byte is significant
  asn1tCallBackFunc     = function (Stream: pointer; TagType: asn1TagType; TagConstrained: boolean;
                        Tag: pointer; TagSize: integer; Size: integer; Data: pointer;
                        BitRest: integer): boolean of object; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

var
// if it needs to revert bytes in tag itself when writing to stream
  asn1RevertTagBytes: boolean  =  true;
// if  it needs to revert bytes in integers when reading from stream
  asn1RevertReadInts: boolean  =  true;
// actual stream read function
///  asn1ReadFunc:       asn1tReadFunc;
// actual stream write function
  asn1WriteFunc:      asn1tWriteFunc;

// --- general functions
//  -  generic function to add tag to stream (see later)
//  -  all parameters have same meaning as in callback function type definition
  function asn1AddTag(Stream: pointer; TagType: asn1TagType; TagConstrained: boolean; Tag: pointer;
    TagSize: integer; Size: integer; Data: pointer = nil; Revert: boolean = false;
    BitRest: integer = 0): boolean; overload;
//  -  incoming stream parsing function
  procedure asn1ParseStream(Stream: pointer; CallBack: asn1tCallBackFunc);

// --- helper for use w/ simple (1 byte long) tags
  function asn1AddTag(Stream: pointer; TagType: asn1TagType; TagConstrained: boolean; Tag: byte;
    Size: integer; Data: pointer = nil; Revert: boolean = false; BitRest: integer = 0): boolean;
    overload;

// --- helpers to use w/ most used data types
//  -  when writing to stream an integer value standard claims to use minimum of bytes need to
//  -  represent particular value so storing of integer means special treating
  function asn1AddInt(Stream: pointer; Value: integer; Revert: boolean = true): boolean;

  function asn1AddBool(Stream: pointer; Value: boolean): boolean;

//function asn1AddStr(Stream: pointer; const Value: AnsiString): boolean;

  function asn1AddBuf(Stream: pointer; Value: pointer; Size: integer): boolean;

  function asn1AddSeq(Stream: pointer): boolean;

  function asn1AddSet(Stream: pointer): boolean;


// --- helpers to write constrained fields
//  -  !!! there no builtin constrains nest checking
//  -  !!! use AddConstrained/CloseConstrained calls carefully
  function asn1AddConstrained(Stream: pointer; TagType: asn1TagType; Tag: pointer; TagSize: integer;
    Size: integer = 0): boolean; overload;
  function asn1AddConstrained(Stream: pointer; TagType: asn1TagType; Tag: byte;
    Size: integer = 0): boolean; overload;
//  - !!! use CloseConstrained ONLY if you previously used AddConstrained w/ Size == 0
//  - !!! (i.e. implicit size encoding)
//  -  if you use asn1AddConstrained function w/ Size == 0, it means that implicit length encoding
//  -  is used
  procedure asn1CloseConstrained(Stream: pointer);

// --- you can specify type equivalency (like Type1 ::= [TagType1 Tag1] IMPLICIT Type2)
  procedure asn1AddTypeEqu(TagType1: asn1TagType; Tag1: pointer; TagSize1: integer;
    TagType2: asn1TagType; Tag2: pointer; TagSize2: integer); overload;
  // -- defaults: TagType2 = asn1tUniversal, TagSize2 = 1
  procedure asn1AddTypeEqu(TagType1: asn1TagType; Tag1: pointer; TagSize1: integer;
    Tag2: byte); overload;

type
  TSBASN1ReadEvent = procedure(Sender : TObject; Buffer : pointer; var Size : longint) of object;
  TSBASN1TagEvent = procedure(Sender : TObject; TagType: asn1TagType; TagConstrained: boolean;
    Tag: pointer; TagSize: integer; Size: Int64; Data: pointer; BitRest: integer;
    var Valid : boolean) of object;
  TSBASN1TagHeaderEvent = procedure(Sender: TObject; TagID : byte; TagLen : Int64;
    HeaderLen : integer; UndefLen : boolean) of object;
  TSBASN1SkipEvent = procedure(Sender: TObject; var Count : Int64) of object;

  TElASN1Parser = class(TObject)
  private
    FOnRead : TSBASN1ReadEvent;
    FOnTag : TSBASN1TagEvent;
    FOnTagHeader : TSBASN1TagHeaderEvent;
    FOnSkip : TSBASN1SkipEvent;
    FReadSize : Int64;
    FRaiseOnEOC : boolean;
    FMaxDataLength : Int64;
    FMaxSimpleTagLength : integer;
    FCurrDepth : integer;
  protected
    procedure asn1Read(Data: pointer; Size: integer);
    procedure ReadRevertBytes(Data: pointer; Size: integer);
    procedure ReadRepackedBits(Tag: pointer; var TagSize: integer;
      MaxTagSize: integer; Revert: boolean = true);
    procedure DoRead(Buffer : pointer; var Size : longint);
    procedure DoTag(TagType: asn1TagType; TagConstrained: boolean; Tag: pointer;
      TagSize: integer; Size: Int64; Data: pointer; BitRest: integer; var Valid : boolean);
    procedure asn1Skip(var Count: Int64);
    function DecodeField(InvokeCallBack: {$ifndef SB_WP7_OR_WP8}TSBBoolean {$else}boolean {$endif} {$ifdef HAS_DEF_PARAMS} =  true {$endif}): Int64;  overload; 

  public
    constructor Create;
    procedure Parse;
    property RaiseOnEOC : boolean read FRaiseOnEOC write FRaiseOnEOC  default false ;
    property MaxDataLength : Int64 read FMaxDataLength write FMaxDataLength;
    property MaxSimpleTagLength : integer read FMaxSimpleTagLength write FMaxSimpleTagLength;
    property OnRead : TSBASN1ReadEvent read FOnRead write FOnRead;
    property OnTag : TSBASN1TagEvent read FOnTag write FOnTag;
    property OnTagHeader : TSBASN1TagHeaderEvent read FOnTagHeader write FOnTagHeader;
    property OnSkip : TSBASN1SkipEvent read FOnSkip write FOnSkip;
  end;

function WriteListSequence(const Strings: TElByteArrayList): ByteArray; 
function WriteArraySequence(const Values: array of ByteArray): ByteArray; 

function WritePrimitiveListSeq(Tag : Byte; Strings : TElByteArrayList): ByteArray; 
function WritePrimitiveArraySeq(Tag : Byte; Strings : array of ByteArray): ByteArray; 

function WriteSet(const Strings: TElByteArrayList) : ByteArray;  overload; function WriteSet(const Strings : array of ByteArray): ByteArray;  overload; 
function WriteA0(const Strings : TElByteArrayList): ByteArray;  overload; function WriteA0(const Strings : array of ByteArray): ByteArray; overload; 
function WriteExplicit(const Data: ByteArray):  ByteArray; 
function WriteInteger(const Data: ByteArray; TagID : byte  =  $02):  ByteArray; overload; function WriteInteger(Number : integer; TagID : byte  =  $02) :  ByteArray; overload; function WriteOID(const Data: ByteArray):  ByteArray; 
function WritePrintableString(const Data: string): ByteArray;  overload; function WriteUTF8String(const Data: string): ByteArray;  overload; function WriteIA5String(const Data: string) : ByteArray;  overload; 
function WritePrintableString(const Data: ByteArray) : ByteArray;  overload; function WriteUTF8String(const Data: ByteArray) : ByteArray;  overload; function WriteIA5String(const Data: ByteArray): ByteArray;  overload; 
function WriteUTCTime(const Data: string) : ByteArray; 
function WriteGeneralizedTime(T : TElDateTime) : ByteArray; 
function WriteSize(Size: LongWord):  ByteArray; 
function WriteBitString(const Data: ByteArray):  ByteArray; 
function WriteOctetString(const Data : string) : ByteArray;  overload; function WriteOctetString(const Data: ByteArray): ByteArray;  overload; 
function WriteVisibleString(const Data : string) : ByteArray; 
function WriteBoolean(Data : boolean) :  ByteArray; 
function WriteNULL: ByteArray; 

function WritePrimitive(Tag: Byte; const Data: ByteArray): ByteArray;  overload; 
function WriteStringPrimitive(Tag: Byte; const Data: string) : ByteArray;  overload; function WriteStringPrimitive(Tag: Byte; const Data: ByteArray): ByteArray;  overload; 

implementation

resourcestring
  SMaxDepthExceeded = 'Maximal ASN.1 tag depth exceeded';


// --- TYPE LIST ---

type
  TTypeEqu = class
  public
    TagType1: asn1TagType;
    TagType2: asn1TagType;
    Tag1: pointer; // this type is
    Tag2: pointer; // equivalent to this
    TagSize1: integer;
    TagSize2: integer;
    constructor Create(aTagType1: asn1TagType; aTag1: pointer; aTagSize1: integer;
      aTagType2: asn1TagType; aTag2: pointer; aTagSize2: integer);
    destructor Destroy; override;
  end;

constructor TTypeEqu.Create(aTagType1: asn1TagType; aTag1: pointer; aTagSize1: integer;
  aTagType2: asn1TagType; aTag2: pointer; aTagSize2: integer);
begin
  TagType1 := aTagType1;
  TagType2 := aTagType2;
  TagSize1 := aTagSize1;
  TagSize2 := aTagSize2;
  GetMem(Tag1, TagSize1);
  SBMove(aTag1^, Tag1^, TagSize1);
  GetMem(Tag2, TagSize2);
  SBMove(aTag2^, Tag2^, TagSize2);
end;

destructor TTypeEqu.Destroy;
begin
  if Assigned(Tag1) then
    FreeMem(Tag1);
  if Assigned(Tag2) then
    FreeMem(Tag2);
  inherited;
end;

var
  EquList : TElList;

(*{$ifdef SB_JAVA}
procedure InitEquList;
begin
  EquList := ArrayList.Create;
end;
{$endif}*)

constructor TElASN1Parser.Create;
begin
  (*
  FReadSize := 0;
  FRaiseOnEOC := false;
  FMaxSimpleTagLength := 0;
  *)
end;

procedure TElASN1Parser.Parse;
begin
  FCurrDepth := 0;
  while DecodeField(true) >= 0 do;
end;


procedure TElASN1Parser.DoRead(Buffer : pointer; var Size : longint);
begin
  if Assigned(FOnRead) then
    FOnRead(Self, Buffer, Size);
end;

procedure TElASN1Parser.DoTag(TagType: asn1TagType; TagConstrained: boolean; Tag: pointer;
  TagSize: integer; Size: Int64; Data: pointer; BitRest: integer; var Valid : boolean);
begin
  if Assigned(FOnTag) then
    FOnTag(Self, TagType, TagConstrained, Tag, TagSize, Size, Data,
      BitRest, Valid);
end;

procedure asn1AddTypeEqu(TagType1: asn1TagType; Tag1: pointer; TagSize1: integer;
  TagType2: asn1TagType; Tag2: pointer; TagSize2: integer); 
var
  Equ: TTypeEqu;
begin
  Equ := TTypeEqu.Create(TagType1, Tag1, TagSize1, TagType2, Tag2, TagSize2);
  (*{$ifdef SB_JAVA}
  if EquList = nil then
    InitEquList();
  {$endif}*)
  EquList.Add(Equ);
end;

procedure asn1AddTypeEqu(TagType1: asn1TagType; Tag1: pointer; TagSize1: integer;
  Tag2: byte); 
begin
  asn1AddTypeEqu(TagType1, Tag1, TagSize1, asn1tUniversal, @Tag2, sizeof(Tag2));
end;

function CompareTypes(TagType1: asn1TagType; Tag1: pointer; TagSize1: integer;
  TagType2: asn1TagType; Tag2: pointer; TagSize2: integer): boolean;
var
  t1, t2: PByte;
  i: integer;
begin
  result := false;
  if (TagType1 <> TagType2) or (TagSize1 <> TagSize2) then
    exit;
  t1 := PByte(Tag1);
  t2 := PByte(Tag2);
  for i := 1 to TagSize1 do
  begin
    if t1^ <> t2^ then
      exit;
    inc(t1);
    inc(t2);
  end;
  result := true;
end;

function IsUniType(TagType: asn1TagType; Tag: pointer; TagSize: integer; Uni: byte): boolean;
var
  i: integer;
  e: TTypeEqu;
  tType: asn1TagType;
  t: pointer;
  tSize: integer;
begin
  i := 1;
  tType := TagType;
  t := Tag;
  tSize := TagSize;

  (*{$ifdef SB_JAVA}
  if EquList = nil then
    InitEquList();
  {$endif}*)

  while i <= EquList.Count do
  begin
    e := TTypeEqu(EquList[i - 1]);
    if CompareTypes(tType, t, tSize, e.TagType1, e.Tag1, e.TagSize1) then
    begin
      tType := e.TagType2;
      t := e.Tag2;
      tSize := e.TagSize2;
      i := 0;
    end;
    inc(i);
  end;
  result := (tType = asn1tUniversal) and (tSize = 1) and (PByte(t)^ = Uni);
end;

// --- ENCODER ---

//type
//  PByte = ^byte;

function noOfBits(Bits: Integer): Integer;
begin
  result := 0;
  while Bits > 0 do
  begin
    Bits := Bits shr 1;
    inc(result);
  end;
end;

procedure WriteRevertBytes(Stream: pointer; Data: pointer; Size: integer);
var
  pData: PByte;
begin
  pData := PByte(PtrUInt(Data) + Cardinal(Size) - 1);
  while Size > 0 do
  begin
    asn1WriteFunc(Stream, pData, 1);
    dec(pData);
    dec(Size);
  end;
end;

procedure WriteRepackedBits(Stream: pointer; Data: pointer; Size: integer; Revert: boolean = false;
  PackedBytes: boolean = false);
var
  lData, lBits, lBytes, lRest, lFirst: integer;
  pData: PByte;
begin
  if Revert then
    pData := PByte(PtrUInt(Data) + Cardinal(Size) - 1)
  else
    pData := PByte(Data);
  if PackedBytes then
    while (Size > 1) and (pData^ = 0) do
    begin
      dec(Size);
      if Revert then
        dec(pData)
      else
        inc(pData);
    end;
  lRest := noOfBits(pData^);
  lBits := lRest + (Size - 1) shl 3;
  lBytes := (lBits + 6) div 7;
  if lRest = 0 then
    inc(lRest, 7);
  lData := $80;
  lFirst := lBits mod 7;
  if lFirst > 0 then
  begin
    if lFirst > lRest then
    begin
      lData := lData or ((pData^ and not ($ff shl lRest)) shl (lFirst - lRest));
      if Revert then
        dec(pData)
      else
        inc(pData);
      lRest := 8 - lFirst + lRest;
      lData := lData or (pData^ shr lRest);
    end
    else
    begin
      lData := lData or ((pData^ shr (lRest - lFirst)) and not ($ff shl lFirst));
      lRest := lRest - lFirst;
    end;

    asn1WriteFunc(Stream, @lData, 1);
    dec(lBytes);
  end;
  if lRest = 0 then
    inc(lRest, 7);
  while lBytes > 0 do
  begin
    if lBytes > 1 then
      lData := $80
    else
      lData := 0;
    if lRest <= 7 then
    begin
      lData := lData or ((pData^ and not ($ff shl lRest)) shl (7 - lRest));
      if Revert then
        dec(pData)
      else
        inc(pData);
      lData := lData or (pData^ shr (lRest + 1));
      lRest := lRest + 1;
    end
    else
    begin
      lData := lData or ((pData^ and $fe) shr 1);
      lRest := lRest - 7;
    end;
    asn1WriteFunc(Stream, @lData, 1);
    dec(lBytes);
  end;
end;

function asn1AddTag(Stream: pointer; TagType: asn1TagType; TagConstrained: boolean; Tag: pointer;
  TagSize: integer; Size: integer; Data: pointer = nil; Revert: boolean = false;
  BitRest: integer = 0): boolean;
var
  lTag, lLen, Prev: Byte;
  pData: PByte;
  pSize: integer;
begin
  result := false;
  if TagSize < 1 then
    exit;
  lTag := ((integer(TagType) - integer(asn1tUniversal)) shl 6) or (integer(TagConstrained) shl 5);

// --- tag encoding
  // -- checking if real tag is less than 30 - maximum that may be encoded in one byte
  if (TagSize = 1) and (PByte(Tag)^ < 30) then
  begin
    lTag := lTag or PByte(Tag)^;
    asn1WriteFunc(Stream, @lTag, 1);
  end
  else
  begin
    // -- no, must build multibyte tag
    if PByte(Tag)^ = 0 then exit;
    lTag := lTag or $1f;
    asn1WriteFunc(Stream, @lTag, 1);
    WriteRepackedBits(Stream, Tag, TagSize, asn1RevertTagBytes, true);
  end;

// --- data/size correction
  pSize := Size;
  if (Size > 0) and (not TagConstrained) then
  begin
    if Revert then
      pData := PByte(PtrUInt(Data) + Cardinal(Size) - 1)
    else
      pData := PByte(Data);
    if IsUniType(TagType, Tag, TagSize, asn1BitStr) then
      inc(pSize);
    if IsUniType(TagType, Tag, TagSize, asn1Integer) then
    begin
      while pSize > 1 do
      begin
        if Revert then
          Prev := PByte(PtrUInt(pData) - 1)^
        else
          Prev := PByte(PtrUInt(pData) + 1)^;
        if ((pData^ = 0) and ((Prev and $80) = 0)) or
          ((pData^ = $ff) and ((Prev and $80) = $80)) then
        begin
          dec(pSize);
          if Revert then
            dec(pData)
          else
            inc(pData);
        end
        else
          break;
      end;
    end;
{    case lTag and $df of
      asn1BitStr:
        inc(pSize);
      asn1Integer:
        while pSize > 1 do
        begin
          if Revert then
            Prev := PByte(PtrInt(pData) - 1)^
          else
            Prev := PByte(PtrInt(pData) + 1)^;
          if ((pData^ = 0) and ((Prev and $80) = 0)) or
            ((pData^ = $ff) and ((Prev and $80) = $80)) then
          begin
            dec(pSize);
            if Revert then
              dec(pData)
            else
              inc(pData);
          end
          else
            break;
        end;
    end;}
  end;

// --- length encoding
  if pSize <= 0 then
  begin
    if TagConstrained then
      lLen := $80
    else
      lLen := 0;
    asn1WriteFunc(Stream, @lLen, 1);
  end
  else
  if pSize <= $7f then
  begin
    lLen := pSize;
    asn1WriteFunc(Stream, @lLen, 1);
  end
  else
  begin
    lLen := $80 + (noOfBits(pSize) + 7) shr 3;
    // -- can't use reserved value lLen == $ff
    if lLen = $ff then
      raise EElASN1Error.Create('Data size too large');
    asn1WriteFunc(Stream, @lLen, 1);
    WriteRevertBytes(Stream, @pSize, lLen and $7f);
  end;

// --- data storing
  if (Size > 0) and (not TagConstrained) then
  begin
    if IsUniType(TagType, Tag, TagSize, asn1BitStr) then
    begin
      asn1WriteFunc(Stream, @BitRest, 1);
      pSize := Size;
    end;
{    case lTag and $df of
      asn1BitStr:
        begin
          asn1WriteFunc(Stream, @BitRest, 1);
          pSize := Size;
        end;
    end;}
    if Revert then
      WriteRevertBytes(Stream, Data, pSize)
    else
      asn1WriteFunc(Stream, Data, pSize {$ifndef HAS_DEF_PARAMS}, 0 {$endif});
  end;

  result := true;
end;

function asn1AddTag(Stream: pointer; TagType: asn1TagType; TagConstrained: boolean; Tag: byte;
  Size: integer; Data: pointer = nil; Revert: boolean = false; BitRest: integer = 0): boolean;
begin
  result := asn1AddTag(Stream, TagType, TagConstrained, @Tag, sizeof(Tag), Size, Data, Revert, BitRest);
end;

function asn1AddBool(Stream: pointer; Value: boolean): boolean;
begin
  result := asn1AddTag(Stream, asn1tUniversal, false, asn1Boolean, sizeof(Value), @Value);
end;

function asn1AddInt(Stream: pointer; Value: integer; Revert: boolean = true): boolean;
begin
  result := asn1AddTag(Stream, asn1tUniversal, false, asn1Integer, sizeof(Value), @Value, Revert);
end;

(*
{$ifndef SB_VCL}
function asn1AddStr(Stream: ByteArray; const Value: AnsiString): boolean;
{$else}
function asn1AddStr(Stream: pointer; const Value: AnsiString): boolean;
{$endif}
begin
  {$ifndef SB_VCL}
  result := asn1AddTag(Stream, asn1tUniversal, false, asn1VisibleStr, Length(Value),
    BytesOfAnsiString(Value), false, 0);
  {$else}
  result := asn1AddTag(Stream, asn1tUniversal, false, asn1VisibleStr, Length(Value), @Value[AnsiStrStartOffset]);
  {$endif}
end;
*)
function asn1AddBuf(Stream: pointer; Value: pointer; Size: integer): boolean;
begin
  result := asn1AddTag(Stream, asn1tUniversal, false, asn1OctetStr, Size, Value, false, 0);
end;

// ---

function asn1AddConstrained(Stream: pointer; TagType: asn1TagType; Tag: pointer; TagSize: integer; Size: integer): boolean;
begin
  result := asn1AddTag(Stream, TagType, true, Tag, TagSize, Size);
end;

function asn1AddConstrained(Stream: pointer; TagType: asn1TagType; Tag: byte; Size: integer): boolean;
begin
  result := asn1AddConstrained(Stream, TagType, @Tag, sizeof(Tag), Size);
end;

procedure asn1CloseConstrained(Stream: pointer);
const
  FinalSignature: word = 0;
begin
  asn1WriteFunc(Stream, @FinalSignature, sizeof(FinalSignature));
end;

function asn1AddSeq(Stream: pointer): boolean;
begin
  result := asn1AddConstrained(Stream, asn1tUniversal, asn1Sequence {$ifndef HAS_DEF_PARAMS}, 0 {$endif});
end;

function asn1AddSet(Stream: pointer): boolean;
begin
  result := asn1AddConstrained(Stream, asn1tUniversal, asn1Set {$ifndef HAS_DEF_PARAMS}, 0 {$endif});
end;

// --- DECODER ---

// AI 2010.04.28: the following classes are not used, commented out
(*type
  EElASN1StreamEnd = {$ifdef SB_NET}assembly{$endif} class(ESecureBlackboxError);
  EElASN1Exit = {$ifdef SB_NET}assembly{$endif} class(ESecureBlackboxError);*)

const
  asn1MaxTagSize = 100;

procedure TElASN1Parser.asn1Read(Data: pointer; Size: integer);
var
  r: integer;
begin
  r := Size;
  DoRead(Data, r);
//  r := asn1ReadFunc(Data, Size);
  if r <> Size then
    raise EElASN1ReadError.Create(
      'Invalid ASN1 sequence');
  inc(FReadSize, r);
end;

procedure TElASN1Parser.asn1Skip(var Count: Int64);
var
  R : Int64;
begin
  R := Count;
  if Assigned(FOnSkip) then
    FOnSkip(Self, Count);
  if R <> Count then
    raise EElASN1ReadError.Create(
      'Invalid ASN1 sequence');
  inc(FReadSize, R);
end;

procedure TElASN1Parser.ReadRevertBytes(Data: pointer; Size: integer);
var
  pData: PByte;
begin

  pData := PByte(PtrUInt(Data) + Cardinal(Size) - 1);
  while Size > 0 do
  begin
    asn1Read(pData, 1);
    dec(Size);
    dec(pData);
  end;

end;

procedure TElASN1Parser.ReadRepackedBits(Tag: pointer; var TagSize: integer;
  MaxTagSize: integer; Revert: boolean = true);
var
  lTag: PByte;
  lfTag: PByte;
  pTag: PByte;
  zTag: PByte;
  BitsLeft: byte;
  b: byte;
  x: integer;
  InTags: integer;
begin
  zTag := nil;
  inTags := 1;
  GetMem(lTag, MaxTagSize);
  lfTag := lTag;
  BitsLeft := 8;
  repeat
    asn1Read(@b, sizeof(b));
    if BitsLeft < 7 then
    begin
      lfTag^ := lfTag^ or ((b and $7f) shr (7 - BitsLeft));
      inc(InTags);
      inc(lfTag);
      if InTags > MaxTagSize then
        raise EElASN1Error.Create('Tag size too large');
      BitsLeft := BitsLeft + 1;
    end
    else
      BitsLeft := BitsLeft - 7;
    lfTag^ := ((b and $7f) shl BitsLeft);
  until (b and $80) = 0;
  if not Revert then
  begin
    GetMem(pTag, MaxTagSize);
    zTag := pTag;
  end
  else
    pTag := PByte(Tag);
  TagSize := 1;
  for x := 1 to InTags do
  begin
    if TagSize > MaxTagSize then
      raise EElASN1Error.Create(
        'Tag size too large');
    pTag^ := lfTag^ shr BitsLeft;
    if x < InTags then
    begin
      dec(lfTag);
      pTag^ := pTag^ or (lfTag^ shl (8 - BitsLeft));
    end;
    inc(TagSize);
    inc(pTag);
  end;
  while pTag^ = 0 do
  begin
    dec(pTag);
    dec(TagSize);
  end;
  if not Revert then
    SBMove(zTag^, Tag^, TagSize);
  FreeMem(lTag, MaxTagSize);
end;

function TElASN1Parser.DecodeField(InvokeCallBack: {$ifndef SB_WP7_OR_WP8}TSBBoolean {$else}boolean {$endif} {$ifdef HAS_DEF_PARAMS} =  true {$endif}): Int64;

// -1 - end of stream
// 0 - end of constrained
// more - field size
var
  llTag: byte;
  llLen: byte;
  lRevert: boolean;
  lSubSize: Int64;
  lSubResult: Int64;

  lTagBufLarge : array[0..asn1MaxTagSize - 1] of byte;

  lTagConstrained: boolean;
  lTagType: asn1TagType;
  lTagBufSmall : Byte;
  lTag: pointer;
  lTagSize: integer;
  lSize: Int64;
  lData: pointer;
  lBitRest: byte;
  lInvokeCallBack: TSBBoolean;
  Len : integer;
  lTagID : byte;
  lUndefSize: boolean;
  lHeaderSize: integer;
begin
  result := -1;
  if FCurrDepth > SB_MAX_ASN1_DEPTH then
    raise EElASN1Error.Create('Maximal ASN.1 tag depth exceeded'{SMaxDepthExceeded});

// --- start field initialization
  lRevert := false;
  lInvokeCallBack := InvokeCallBack;
  lTagSize := 0;
{.$hints off}
  lSize := 0;
{.$hints on}
  lData := nil;
  lBitRest := 0;

// --- stream read start
  FReadSize := 1;

  try

  // -- decoding tag
    Len := SizeOf( llTag );
    DoRead(@llTag, Len);
    if Len <> sizeof( llTag ) then
  // -- probably we've reached end of the stream
      exit;
    if llTag = 0 then
    begin
      asn1Read(@llLen, sizeof(llLen));
      if llLen <> 0 then
        raise EElASN1Error.Create('Invalid ASN1 Sequence');
  //    if lInvokeCallBack then
  //      lInvokeCallBack := CallBack(Stream, asn1TagType(0), false, nil, 0, 0, nil, 0);

      // II 220703 OnTagEnd
      if FRaiseOnEOC then
        DoTag(asn1tEOC, false, @llTag, 1, 0, nil, 0, lInvokeCallBack);

      result := 2; // 0  !!
      exit;
    end;
    lTagID := llTag;
    lTagConstrained := (llTag and $20) <> 0;
    lTagType := asn1TagType((llTag shr 6) + integer(asn1tUniversal));
    llTag := llTag and $1f;
    lHeaderSize := 1;
    if llTag < $1f then
    begin
  //    GetMem(lTag, 1);
      lTagSize := 1;
      lTag := @lTagBufSmall;
      PByte(lTag)^ := llTag;
    end
    else
    begin
  //    GetMem(lTag, asn1MaxTagSize);
      lTag :=  @ lTagBufLarge;
      ReadRepackedBits(lTag, lTagSize, asn1MaxTagSize, asn1RevertTagBytes);
    end;

  // -- decoding size
    lUndefSize := false;
    asn1Read(@llLen, sizeof(llLen));
    if llLen > $80 then
    begin
      llLen := llLen and $7f;
      if llLen > sizeof( lSize ) then
        raise EElASN1Error.Create('Block size too large');
      ReadRevertBytes(@lSize, llLen);     
      Inc(lHeaderSize, 1 + llLen);
    end
    else
    if llLen = $80 then
    begin
      if not lTagConstrained then
        raise EElASN1Error.Create('Invalid ASN1 sequence');
      lSize := 0;
      lUndefSize := true;
      Inc(lHeaderSize);
    end
    else
    begin
      lSize := llLen;
      Inc(lHeaderSize);
    end;
    if IsUniType(lTagType, lTag, lTagSize, asn1BitStr) then
      if not lTagConstrained then
      begin
        dec(lSize);
        asn1Read(@lBitRest, sizeof(lBitRest));
      end;

    // check that lSize not malformed
    if lSize > FMaxDataLength then
      raise EElASN1ReadError.Create('Invalid size');

    if Assigned(FOnTagHeader) then
      FOnTagHeader(Self, lTagID, lSize, lHeaderSize, lUndefSize);
    
  // -- reading data itself
    if IsUniType(lTagType, lTag, lTagSize, asn1Integer) then
      if asn1RevertReadInts then
        lRevert := true;

    if (lSize > 0) and (not lTagConstrained) then
    begin
      // skipping non-integer tags larger than MaxSimpleTagLength
      if (FMaxSimpleTagLength = 0) or (lSize <= FMaxSimpleTagLength) or
        (PByte(lTag)^ = asn1Integer) then
      begin
        GetMem(lData, lSize);
        if lRevert then
          ReadRevertBytes(lData, lSize)
        else
          asn1Read(lData, lSize);
      end
      else
      begin
        lData := nil;
        asn1Skip(lSize);
      end;
    end;

    if lInvokeCallBack then
    begin
  //    lInvokeCallBack := CallBack(Stream, lTagType, lTagConstrained, lTag, lTagSize, lSize, lData, lBitRest);
      DoTag(lTagType, lTagConstrained, lTag, lTagSize, lSize, lData, lBitRest, lInvokeCallBack);
    end;

  // -- fetching subfields
    result := FReadSize;

    lSubSize := 0;
    lSubResult := -1;
    if lTagConstrained and (lSize > 0) then // ltagConstrained
    begin
      if lInvokeCallback then
      begin
        repeat
          if lSize > 0 then
            if lSubSize = lSize then
              break
            else
              if lSubSize > lSize then
                raise EElASN1Error.Create('Invalid stream data');

          Inc(FCurrDepth);
          try
            lSubResult := DecodeField(lInvokeCallBack);
          finally
            Dec(FCurrDepth);
          end;
          if (lSubResult < 0) and (lSubSize <> lSize) then
            raise EElASN1Error.Create('Unexpected stream end');
          if lSubResult > 0 then
            inc(lSubSize, lSubResult);
        until (lSubResult = 0) and (lSize <= 0);

        if lInvokeCallBack {and (lSize > 0)} then
          DoTag(asn1TagType(0), false, nil, 0, 0, nil, 0, lInvokeCallBack);

      end
      else
      begin
        // lInvokeCallBack is false => the tag has been already processed by
        // the LoadFromBuffer() call done from inside the above DoTag() handler.
        // We only need to skip the amount of bytes read.
        asn1Skip(lSize);
        lSubSize := lSize;
      end;
    end;
    result := result + lSubSize;

  finally
    if lData <> nil then
      FreeMem(lData);

  end;
end;

procedure asn1ParseStream(Stream: pointer; CallBack: asn1tCallBackFunc);
begin
//  while DecodeField(Stream, CallBack) >= 0 do;
end;

procedure FinalizeAll;
var
  i: integer;
begin
  for i := 1 to EquList.Count do
    TTypeEqu(EquList[i - 1]). Free ;;
  FreeAndNil(EquList);
end;

// ASN1 write routines

function WritePrimitiveListSeq(Tag : Byte; Strings : TElByteArrayList): ByteArray;
var
  I: integer;
  TotalSize: Word;
  CurPos  : integer;
  CurLine : ByteArray;
begin
  // calculate total size of data
  TotalSize := 0;

  for I := 0 to Strings.Count - 1 do
    TotalSize := TotalSize + Length(Strings.Item[I]);

  try

    // get a string with total size
    CurLine := WriteSize(TotalSize);

    // adjust output buffer length
    SetLength(Result, 1 + Length(CurLine) + TotalSize);

    // write the tag to the first element of the output array
    Result[0] := byte(Tag);

    // write the total length to the output array
    SBMove(CurLine, 0, Result, 1, Length(CurLine));
    CurPos := 1 + Length(CurLine);
  finally
    ReleaseArray(CurLine);
  end;

  // now write each data buffer to the output array
  for I := 0 to Strings.Count - 1 do
  begin
    CurLine := Strings.Item[I];
    SBMove(CurLine, 0, Result, CurPos, Length(CurLine));
    Inc(CurPos, Length(CurLine));
  end;
end;

function WritePrimitiveArraySeq(Tag : Byte; Strings : array of ByteArray): ByteArray;
var
  I: integer;
  TotalSize: Word;
  CurPos  : integer;
  CurLine : ByteArray;
begin
  // calculate total size of data
  TotalSize := 0;

  for I := 0 to Length(Strings) - 1 do
    TotalSize := TotalSize + Length(Strings[I]);

  try

    // get a string with total size
    CurLine := WriteSize(TotalSize);

    // adjust output buffer length
    SetLength(Result, 1 + Length(CurLine) + TotalSize);

    // write the tag to the first element of the output array
    Result[0] := byte(Tag);

    // write the total length to the output array
    SBMove(CurLine, 0, Result, 1, Length(CurLine));

    CurPos := 1 + Length(CurLine);
  finally
    ReleaseArray(CurLine);
  end;

  // now write each data buffer to the output array
  for I := 0 to Length(Strings) - 1 do
  begin
    CurLine := Strings[i];
    SBMove(CurLine, 0, Result, CurPos, Length(CurLine));
    Inc(CurPos, Length(CurLine));
  end;
end;

(*
function WritePrimitiveSeq(Tag : Byte; Strings : TElByteArrayList): ByteArray;
var
  I: integer;
  TotalSize: Word;
  CurPos  : integer;
  {$ifndef SB_VCL}
  CurLine : ByteArray;
  {$else}
  CurLine : ByteArray;
  {$endif}
begin

  // calculate total size of data
  TotalSize := 0;

  {$ifndef SB_VCL}
  for I := 0 to Length(Strings) - 1 do
  {$else}
  for I := 0 to Strings.Count - 1 do
  {$endif}
    TotalSize := TotalSize + Length({$ifndef SB_VCL}Strings{$else}Strings.Strings{$endif}[I]);

  {$ifndef SB_VCL}
  try
  {$endif}

    // get a string with total size
    CurLine := WriteSize(TotalSize);

    // adjust output buffer length
    {$ifndef SB_NET}
    SetLength(Result, 1 + Length(CurLine) + TotalSize);
    {$else}
    Result := new Byte[1 + Length(CurLine) + TotalSize];
    {$endif}

    // write the tag to the first element of the output array
    Result[0] := byte(Tag);

    // write the total length to the output array
    {$ifndef SB_VCL}
    SBMove(CurLine, 0, Result, 1, Length(CurLine));
    {$else}
    SBMove(CurLine[0], Result[0 + 1], Length(CurLine));
    {$endif}
    CurPos := 1 + Length(CurLine);

  {$ifndef SB_VCL}
  finally
    ReleaseArray(CurLine);
  end;
  {$endif}

  // now write each data buffer to the output array
  {$ifndef SB_VCL}
  for I := 0 to Length(Strings) - 1 do
  begin
    CurLine := Strings[i];
    SBMove(CurLine, 0, Result, CurPos, Length(CurLine));
    Inc(CurPos, Length(CurLine));
  end;
  {$else}
  for I := 0 to Strings.Count - 1 do
  begin
    CurLine := Strings.Strings[i];
    SBMove(CurLine[0], Result[CurPos + 0], Length(CurLine));
    Inc(CurPos, Length(CurLine));
  end;
  {$endif}
end;
*)
(*
{$ifdef SB_UNICODE_VCL}
function WritePrimitiveSeq(Tag : Byte; const Strings : array of ByteArray): ByteArray;
var
  I: integer;
  TotalSize: Word;
  CurPos  : integer;
  CurLine : ByteArray;
begin

  // calculate total size of data
  TotalSize := 0;
  for I := 0 to Length(Strings) - 1 do
    TotalSize := TotalSize + Length(Strings[I]);

  // get a string with total size
  CurLine := WriteSize(TotalSize);

  // adjust output buffer length
  SetLength(Result, 1 + Length(CurLine) + TotalSize);

  // write the tag to the first element of the output array
  Result[0] := byte(Tag);

  // write the total length to the output array
  SBMove(CurLine[0], Result[0 + 1], Length(CurLine));
  CurPos := 1 + Length(CurLine);

  // now write each data buffer to the output array
  for I := 0 to Length(Strings) - 1 do
  begin
    CurLine := Strings[i];
    SBMove(CurLine[0], Result[CurPos + 0], Length(CurLine));
    Inc(CurPos, Length(CurLine));
  end;
end;
{$endif}
*)

function WriteA0(const Strings : TElByteArrayList): ByteArray;
begin
  result := WritePrimitiveListSeq($A0, Strings);
end;

function WriteA0(const Strings : array of ByteArray): ByteArray;
begin
  Result := WritePrimitiveArraySeq($A0, Strings);
end;

function WriteListSequence(const Strings: TElByteArrayList): ByteArray;
begin
  result := WritePrimitiveListSeq($30, Strings);
end;

function WriteArraySequence(const Values: array of ByteArray): ByteArray;
begin
  result := WritePrimitiveArraySeq($30, Values);
end;

function WriteSet(const Strings: TElByteArrayList):  ByteArray;
begin
  result := WritePrimitiveListSeq($31, Strings);
end;

function WriteSet(const Strings : array of ByteArray): ByteArray;
begin
  result := WritePrimitiveArraySeq($31, Strings);
end;

function WriteStringPrimitive(Tag: Byte; const Data: string) : ByteArray;
var
  TmpBuf: ByteArray;
begin
  TmpBuf := BytesOfString(Data);
  Result := WritePrimitive(Tag, TmpBuf);
  ReleaseArray(TmpBuf);
end;

function WriteStringPrimitive(Tag: Byte; const Data: ByteArray): ByteArray;
begin
  Result := WritePrimitive(Tag, Data);
end;

function WritePrimitive(Tag: Byte; const Data: ByteArray):  ByteArray;
var
  LenBuf : ByteArray;
begin
  LenBuf := WriteSize(Length(Data));
  SetLength(Result, 1 + Length(LenBuf) + Length(Data));

  Result[0] := byte(Tag);

  SBMove(LenBuf, 0, Result, 1, Length(LenBuf));
  SBMove(Data, 0, Result, 1 + Length(LenBuf), Length(Data));

  ReleaseArray(LenBuf);
end;

function WriteExplicit(const Data: ByteArray) : ByteArray;
begin
  result := WritePrimitive($A0, Data);
end;

function WriteInteger(const Data: ByteArray; TagID : byte  =  $02): ByteArray;
var
  Tmp : ByteArray;
  Index : integer;
  DL : integer;
const
  NEGFLAG = $80;
begin

  // removing leading zeros
  Index := 0;
  DL := Length(Data);
  while (Index < DL) and (Data[Index] = 0) do
    Inc(Index);

  if Index >= DL then
  begin
    // the value to write is 0
    SetLength(Tmp, 1);
    Tmp[0] := 0;
  end
  else
  begin
    // appending leading 0 for values starting with 0x80+ values
    if Data[Index] >= byte(NEGFLAG) then
    begin
      SetLength(Tmp, DL - Index + 1);

      Tmp[0] := 0;

      SBMove(Data, Index, Tmp, 1, DL - Index);
    end
    else
    begin
      SetLength(Tmp, DL - Index);
      SBMove(Data, Index, Tmp, 0, DL - Index);
    end;
  end;
  result := WritePrimitive(TagID, Tmp);

  ReleaseArray(Tmp);
end;

function WriteInteger(Number : integer; TagID : byte  =  $02) : ByteArray;
var TmpBuf : ByteArray; // NO NEED for ReleaseArray
    Tmp : ByteArray;
    i : integer;
begin
  if Number = 0 then
    TmpBuf := WriteInteger(GetBytes8(0), TagID)
  else
  begin
    SetLength(TmpBuf, 4);
    FillChar(TmpBuf [0] , Length(TmpBuf), 0);
    i := Length(TmpBuf) - 1;
    while Number <> 0 do
    begin
      TmpBuf[i] := byte(Number and $ff);
      Number := Number shr 8;
      Dec(i);
    end;
    Tmp := CloneArray(TmpBuf, i + 1, Length(TmpBuf) - i - 1);
    TmpBuf := WriteInteger(Tmp, TagID);
    ReleaseArray(Tmp);
  end;
  Result := TmpBuf;
end;

function WriteOID(const Data: ByteArray): ByteArray;
begin
  result := WritePrimitive($06, Data);
end;

function WritePrintableString(const Data: string): ByteArray;
begin
  result := WriteStringPrimitive($13, Data);
end;

function WriteUTF8String(const Data: string): ByteArray;
{$ifndef SB_ANSI_VCL}
var
  TmpBuf : ByteArray;
 {$endif}
begin
  {$ifndef SB_ANSI_VCL}
  TmpBuf := StrToUTF8(Data);
  result := WriteStringPrimitive(12, TmpBuf);
  ReleaseArray(TmpBuf);
   {$else}
  WriteStringPrimitive(12, Data);
   {$endif}
end;

function WritePrintableString(const Data: ByteArray): ByteArray;
begin
  result := WritePrimitive($13, Data);
end;

function WriteUTF8String(const Data: ByteArray): ByteArray;
begin
  result := WritePrimitive(12, Data);
end;

function WriteIA5String(const Data: string) : ByteArray;
begin
  result := WriteStringPrimitive(22, Data);
end;

function WriteIA5String(const Data: ByteArray) : ByteArray;
begin
  result := WriteStringPrimitive(22, Data);
end;

function WriteUTCTime(const Data: string): ByteArray;
begin
  result := WriteStringPrimitive($17, Data);
end;

function WriteGeneralizedTime(T : TElDateTime) : ByteArray;
var
  TmpBuf : ByteArray;

  Year, Day, Month, Hour, Min, Sec, MSec : word;
  YearStr, DayStr, MonStr, HourStr, MinStr, SecStr : string;
  TmpResult : ByteArray;

  function IntToStr2(Value : word) : String;
  begin
    Result := IntToStr((Value div 10) mod 10) + IntToStr(Value mod 10);
  end;

begin
  DecodeDate(T, Year, Month, Day);
  DecodeTime(T, Hour, Min, Sec, MSec);
  try
    YearStr := IntToStr(Year);
  except
    YearStr := '2000';
  end;
  while Length(YearStr) < 4 do
    YearStr := '0' + YearStr;
  DayStr := IntToStr2(Day);
  MonStr := IntToStr2(Month);
  HourStr := IntToStr2(Hour);
  MinStr := IntToStr2(Min);
  SecStr := IntToStr2(Sec);
  // Get the result
  TmpResult := BytesOfString(YearStr + MonStr + DayStr + HourStr + MinStr + SecStr + 'Z');

  // get the size "string"
  TmpBuf := WriteSize(Length(TmpResult));

  // adjust resulting buffer size
  SetLength(Result, 1 + Length(TmpBuf) + Length(TmpResult));

  // set resulting buffer contents;
  Result[0] := byte($18);
  SBMove(TmpBuf[0], Result[0 + 1], Length(TmpBuf));
  SBMove(TmpResult[0], Result[0 + 1 + Length(TmpBuf)], Length(TmpResult));
end;

function WriteSize(Size: LongWord): ByteArray;
begin
  if Size < 128 then
  begin
    SetLength(Result, 1);
    Result[0] := byte(Size);
  end
  else
  if (Size >= 128) and (Size < 256) then
  begin
    SetLength(Result, 2);
    Result[0] := byte($81);
    Result[1] := byte(Size);
  end
  else
  begin
    SetLength(Result, 3);
    Result[0] := byte($82);
    Result[1] := byte(Size shr 8);
    Result[2] := byte(Size and $FF);
  end;
end;

function WriteBitString(const Data: ByteArray): ByteArray;
var SizeBuf : ByteArray;
begin
  SizeBuf := WriteSize(Length(Data) + 1);

  SetLength(Result, 1 + Length(SizeBuf) + 1 + Length(Data));

  Result[0] := byte($03);
  SBMove(SizeBuf[0], Result[0+ 1], Length(SizeBuf));
  SBMove(Data[0], Result[0 + 1 + Length(SizeBuf) + 1], Length(Data));
  Result[0 + 1 + Length(SizeBuf)] := byte($0);

  //Result := #$03 + WriteSize(Length(Data) + 1) + #$0 + Data;

  ReleaseArray(SizeBuf);
end;

function WriteNULL: ByteArray;
begin
  //Result := #$05#$00;
  SetLength(Result, 2);
  Result[0] := byte(5);
  Result[1] := byte(0);
  //SBMove(AnsiString(#$05#$00), 0, Result, 0, 2);
end;

function WriteOctetString(const Data : ByteArray) : ByteArray;
var SizeBuf : ByteArray;
begin
//Result := #$04 + WriteSize(Length(Data)) + {$ifdef SB_UNICODE_VCL}ByteArrayOfString{$endif}(Data);

  SizeBuf := WriteSize(Length(Data));

  SetLength(Result, 1 + Length(SizeBuf) + Length(Data));

  Result[0] := byte($04);

  SBMove(SizeBuf, 0, Result, 1, Length(SizeBuf));

  SBMove(Data, 0, Result, 1 + Length(SizeBuf), Length(Data));

  ReleaseArray(SizeBuf);
end;

function WriteOctetString(const Data : string) : ByteArray;
var SizeBuf : ByteArray;
    TmpStr  : ByteArray;
begin
  TmpStr := EmptyArray;

//Result := #$04 + WriteSize(Length(Data)) + {$ifdef SB_UNICODE_VCL}ByteArrayOfString{$endif}(Data);

  SizeBuf := WriteSize(Length(Data));

  SetLength(Result, 1 + Length(SizeBuf) + Length(Data));

  Result[0] := byte($04);

  SBMove(SizeBuf, 0, Result, 1, Length(SizeBuf));
  
  TmpStr := BytesOfString(Data);
  SBMove(TmpStr, 0, Result, 1 + Length(SizeBuf), Length(Data));
  
  ReleaseArray(SizeBuf);
  ReleaseArray(TmpStr);
end;

function WriteBoolean(Data : boolean) : ByteArray;
begin
  SetLength(Result, 3);
  Result[0] := byte($01);
  Result[0 + 1] := byte($01);
  if Data then
    Result[0 + 2] := byte($FF)
  else
    Result[0 + 2] := byte($00);
end;

function WriteVisibleString(const Data : string) : ByteArray;
var SizeBuf : ByteArray;
    TmpStr  : ByteArray;
begin
  // AI 2011.01.25: removed trailing space; it seems that space is not needed (see example in 8.21 of X.690)
  try

    SizeBuf := WriteSize(Length(Data));

    SetLength(Result, 1 + Length(SizeBuf) + Length(Data));

    Result[0] := byte(26);

    SBMove(SizeBuf, 0, Result, 1, Length(SizeBuf));
    TmpStr := BytesOfString(Data);
    SBMove(TmpStr, 0, Result, 1 + Length(SizeBuf), Length(Data));
  //Result := #26 + WriteSize(Length(Data)) + {$ifdef SB_UNICODE_VCL}ByteArrayOfString{$endif}(Data);

  finally
    ReleaseArray(SizeBuf);
    ReleaseArray(TmpStr);
  end;
end;


initialization
  EquList := TElList.Create;
  
finalization
  FinalizeAll;

  
end.
