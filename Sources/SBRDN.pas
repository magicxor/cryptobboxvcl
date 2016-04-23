
(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBRDN;

interface

uses
  Classes,
  SysUtils,
  SBStringList,
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBConstants,
  SBASN1Tree;


type
  TElRelativeDistinguishedName = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElRelativeDistinguishedName = TElRelativeDistinguishedName;
   {$endif}

  TElRelativeDistinguishedName =  class(TPersistent) 
  private
    FTypes: TElByteArrayList;
    FValues: TElByteArrayList;
    FTags: TElIntegerList;
    FGroups: TElIntegerList;
  
    function GetCount: integer;
    procedure SetCount(Value: integer);
    function GetValues(Index: integer): ByteArray;
    procedure SetValues(Index: integer; const Value: ByteArray);
    function GetOIDs(Index: integer): ByteArray;
    procedure SetOIDs(Index: integer; const Value: ByteArray);
    function GetTags(Index: integer): byte;
    procedure SetTags(Index: integer; Value: byte);
    function GetGroup(Index: integer): integer;
    procedure SetGroup(Index: integer; Value: integer);
  protected
    procedure AssignTo(Dest: TPersistent); override;
  public
    constructor Create;
     destructor  Destroy; override;
    procedure Assign(Source: TPersistent); override;
    function LoadFromTag(Tag: TElASN1ConstrainedTag; IgnoreTopSequence: boolean{$ifdef HAS_DEF_PARAMS}  =  false {$endif}): boolean;
    function LoadFromDNString(const S : string; LiberalMode : boolean): boolean;
    function SaveToTag(Tag: TElASN1ConstrainedTag): boolean;
    function SaveToDNString: string;
    function Add(const OID: ByteArray; const Value: ByteArray; Tag: byte{$ifdef HAS_DEF_PARAMS}  =  0 {$endif}): integer;
    procedure Remove(Index: integer);
    procedure GetValuesByOID(const OID: ByteArray; Values: TElByteArrayList);
    function GetFirstValueByOID(const OID: ByteArray): ByteArray;
    function IndexOf(const OID: ByteArray): integer;
    procedure Clear;
    (*
    function Equals(RDN : TElRelativeDistinguishedName; IgnoreTags : boolean;
      IgnoreOrder : boolean): boolean; {$ifdef D_12_UP}reintroduce; overload;{$endif}
    {$ifdef D_12_UP}
    function Equals(Obj: TObject): Boolean; overload; override;
    {$endif}
    *)
    function Contains(RDN : TElRelativeDistinguishedName; IgnoreTags : boolean): boolean;
    property Values[Index: integer]: ByteArray 
         read GetValues write SetValues ;
    property OIDs[Index: integer]: ByteArray 
         read GetOIDs write SetOIDs ;
    property Tags[Index: integer]: byte 
         read GetTags write SetTags ;
    property Groups[Index: integer]: integer read GetGroup write SetGroup;
    property Count: integer read GetCount write SetCount;
  end;

  TElRDNConverter = class(TSBDisposableBase)
  protected
    FPrefixes : TElStringList;
    FOIDs : TElByteArrayList;
    FSeparator : string;
    FInsertSeparatorPrefix : boolean;
  procedure AddPair(const Prefix : string; const OID : ByteArray);
    procedure SetupKnownOIDs;
  public
    constructor Create();
     destructor  Destroy; override;
    function SaveToDNString(RDN : TElRelativeDistinguishedName): string;
    procedure LoadFromDNString(RDN : TElRelativeDistinguishedName; const S : string;
      LiberalMode : boolean);
    property Separator : string read FSeparator write FSeparator;
    property InsertSeparatorPrefix : boolean read FInsertSeparatorPrefix
      write FInsertSeparatorPrefix;
  end;

function FormatRDN(RDN: TElRelativeDistinguishedName): string; 

function GetRDNStringValue(const RDN: TElRelativeDistinguishedName; Index: Integer): UnicodeString; 

function CompareRDN(Name1, Name2 : TElRelativeDistinguishedName) : boolean; 
function CompareRDNAsStrings(Name1, Name2 : TElRelativeDistinguishedName) : Boolean; 
function NonstrictCompareRDN(InnerRDN, OuterRDN: TElRelativeDistinguishedName): boolean; 
function NonstrictCompareRDNAsStrings(InnerRDN, OuterRDN: TElRelativeDistinguishedName): Boolean; 

var
  IgnoreTagsWhenComparingRDNs: boolean = false;

implementation

resourcestring
  SAssignError = 'Can not assign %s to %s';

function GetRDNStringValue(const RDN: TElRelativeDistinguishedName; Index: Integer): UnicodeString;
begin
  result := ASN1ReadString(RDN.Values[Index], RDN.Tags[Index]);
end;

(*
var
  Buf: ByteArray;
  {$ifdef SB_VCL}
  k: Integer;
  {$endif}
begin
  case RDN.Tags[Index] of
    SB_ASN1_NUMERICSTR, SB_ASN1_PRINTABLESTRING,
    SB_ASN1_IA5STRING, SB_ASN1_VISIBLESTRING:
    begin
      Result := StringOfBytes(RDN.Values[Index])
    end;

    SB_ASN1_UTF8STRING:
    begin
      {$ifdef SB_VCL}
      Result := UTF8ToWideStr(RDN.Values[Index]);
      //Result := ConvertFromUTF8String(RDN.Values[i], false);
      {$else}
      Buf := RDN.Values[Index];
      Result := {$ifndef SB_JAVA}System.Text.Encoding.UTF8.GetString{$else}GetStringUTF8{$endif}(Buf, 0, Length(Buf));
      {$endif}
    end;

    SB_ASN1_BMPSTRING:
    begin
      Buf := RDN.Values[Index];

      {$ifdef SB_VCL}

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
      SBMove(PWideChar(@Buf[0 + k])^, Result[StringStartOffset], Length(Buf) - k);

      {$else}
      if (Length(Buf) >= 2) and (Buf[0] = 254) and (Buf[1] = 255) then
        Result := {$ifndef SB_JAVA}System.Text.Encoding.BigEndianUnicode.GetString{$else}GetStringUTF16BE{$endif}(Buf, 2, Length(Buf) - 2)
      else
      if (Length(Buf) >= 2) and (Buf[0] = 255) and (Buf[1] = 254) then
        Result := {$ifndef SB_JAVA}System.Text.Encoding.Unicode.GetString{$else}GetStringUTF16LE{$endif}(Buf, 2, Length(Buf) - 2)
      else
        Result := {$ifndef SB_JAVA}System.Text.Encoding.BigEndianUnicode.GetString{$else}GetStringUTF16BE{$endif}(Buf, 0, Length(Buf));
      {$endif}
    end;

    {$ifndef SB_NO_NET_UTF32_ENCODING}
    SB_ASN1_UNIVERSALSTRING:
    begin
      Buf := RDN.Values[Index];

      {$ifdef SB_VCL}
      if (Length(Buf) < 4) or
         (Buf[0] <> byte(255)) or
         (Buf[0 + 1] <> byte(254)) or
         (Buf[0 + 2] <> byte(0)) or
         (Buf[0 + 3] <> byte(0)) then
        SwapBigEndianDWords(@Buf[0], Length(Buf));
      // else UTF-32LE

      Result := ConvertFromUTF32String(Buf, False);
      {$else}
      if (Length(Buf) < 4) or (Buf[0] <> 255) or (Buf[1] <> 254) or (Buf[2] <> 0) or (Buf[3] <> 0) then
        SwapBigEndianDWords(Buf);

      {$ifndef SB_JAVA}
      {$ifdef NET_1_0}
      Result := System.Text.Encoding.GetEncoding('utf-32').GetString(Buf, 0, Length(Buf));
      {$else}
      {$ifndef NET_CF}
      Result := System.Text.Encoding.UTF32.GetString(Buf, 0, Length(Buf));
      {$else}
      Result := System.Text.Encoding.GetEncoding('utf-32').GetString(Buf, 0, Length(Buf));
      {$endif}
      {$endif}
      {$else}
      Result := GetStringUTF32LE(Buf, 0, Length(Buf));
      {$endif}
      if (Length(Result) > 0) and (Result[StringStartOffset] = WideChar($FEFF)) then
        {$ifdef SB_NET}
        Result := Result.Remove(0, 1);
        {$else}
        Delete(Result, StringStartOffset, 1);
        {$endif}

      {$endif SB_VCL}
    end;
    {$endif}
  else
    Result := StringOfBytes(RDN.Values[Index])
  end;
end;
*)

function CompareRDN(Name1, Name2 : TElRelativeDistinguishedName) : boolean;
var
  I, J : integer;
  OID, Value : ByteArray;
  Found : boolean;
  TagID : byte;
begin
  Result := false;
  if Name1.Count <> Name2.Count then
    Exit;
  for I := 0 to Name1.Count - 1 do
  begin
    OID := Name1.OIDs[I];
    Value := Name1.Values[I];
    TagID := Name1.Tags[I];
    Found := false;
    for J := 0 to Name2.Count - 1 do
    begin
      if (CompareContent(Name2.OIDs[J], OID)) and (CompareContent(Name2.Values[J], Value)) and
        ((Name2.Tags[J] = TagID) or (IgnoreTagsWhenComparingRDNs)) then
      begin
        Found := true;
        Break;
      end;
    end;
    if not Found then
      Exit;
  end;
  Result := true;
end;

function CompareRDNAsStrings(Name1, Name2 : TElRelativeDistinguishedName) : Boolean;
var
  I, J : Integer;
  OID : ByteArray;
  Value: UnicodeString;
  Found : Boolean;
begin
  Result := false;
  if Name1.Count <> Name2.Count then
    Exit;
  for I := 0 to Name1.Count - 1 do
  begin
    OID := Name1.OIDs[I];
    Value := GetRDNStringValue(Name1, I);
    Found := false;
    for J := 0 to Name2.Count - 1 do
    begin
      if CompareContent(Name2.OIDs[J], OID) and
         (GetRDNStringValue(Name2, J) = Value) then
      begin
        Found := true;
        Break;
      end;
    end;
    if not Found then
      Exit;
  end;
  Result := true;
end;

function NonstrictCompareRDN(InnerRDN, OuterRDN: TElRelativeDistinguishedName):
  boolean;
var
  I, J: integer;
  Found: boolean;
  OID, Value: ByteArray;
  TagID: byte;
begin
  Result := false;
  for I := 0 to InnerRDN.Count - 1 do
  begin
    OID := InnerRDN.OIDs[I];
    Value := InnerRDN.Values[I];
    TagID := InnerRDN.Tags[I];
    Found := false;
    for J := 0 to OuterRDN.Count - 1 do
    begin
      if (CompareContent(OuterRDN.OIDs[J], OID)) and
        (CompareContent(OuterRDN.Values[J], Value)) and
        ((OuterRDN.Tags[J] = TagID) or (IgnoreTagsWhenComparingRDNs)) then
      begin
        Found := true;
        Break;
      end;
    end;
    if not Found then
      Exit;
  end;
  Result := true;
end;

function NonstrictCompareRDNAsStrings(InnerRDN, OuterRDN: TElRelativeDistinguishedName): Boolean;
var
  I, J: Integer;
  OID: ByteArray;
  Value: UnicodeString;
  Found : Boolean;
begin
  Result := False;
  for I := 0 to InnerRDN.Count - 1 do
  begin
    OID := InnerRDN.OIDs[I];
    Value := GetRDNStringValue(InnerRDN, I);
    Found := False;
    for J := 0 to OuterRDN.Count - 1 do
    begin
      if CompareContent(OuterRDN.OIDs[J], OID) and
         (GetRDNStringValue(OuterRDN, J) = Value) then
      begin
        Found := true;
        Break;
      end;
    end;

    if not Found then
      Exit;
  end;
  Result := True;
end;

function TElRelativeDistinguishedName. GetValues (Index: integer): ByteArray;
begin
  Result := FValues.Item[Index];
end;

procedure TElRelativeDistinguishedName. SetValues (Index: integer; const Value: ByteArray);
begin
  FValues.Item[Index] := Value;
end;

constructor TElRelativeDistinguishedName.Create;
begin
  inherited;
  FTypes := TElByteArrayList.Create;
  FValues := TElByteArrayList.Create;
  FGroups := TElIntegerList.Create;
  FTags := TElIntegerList.Create;
end;

 destructor  TElRelativeDistinguishedName.Destroy;
begin
  FreeAndNil(FTypes);
  FreeAndNil(FValues);
  FreeAndNil(FGroups);
  FreeAndNil(FTags);
  inherited;
end;

procedure TElRelativeDistinguishedName.Remove(Index: integer);
begin
  if (Index >= 0) and (Index < FTypes.Count) then
  begin
    FTypes.Delete(Index);
    FValues.Delete(Index);
    FGroups.Delete(Index);
    FTags.Delete(Index);
  end;
end;

function TElRelativeDistinguishedName. GetOIDs (Index: integer): ByteArray;
begin
  Result := FTypes.Item[Index];
end;

procedure TElRelativeDistinguishedName. SetOIDs (Index: integer; const Value: ByteArray);
begin
  FTypes.Item[Index] := Value;
end;

function TElRelativeDistinguishedName.GetCount: integer;
begin
  Result := FTypes.Count;
end;

procedure TElRelativeDistinguishedName.SetCount(Value: integer);
var
  GroupNum: integer;
begin
  while FTypes.Count < Value do
  begin
    if FTypes.Count = 0 then
      GroupNum := 0
    else
      GroupNum := Groups[FTypes.Count - 1] + 1;
    FTypes.Add(EmptyArray);
    FValues.Add(EmptyArray);
    FTags.Add( pointer (SB_ASN1_OCTETSTRING));
    FGroups.Add( pointer (GroupNum));
  end;
  while FTypes.Count > Value do
  begin
    FTypes.Delete(FTypes.Count - 1);
    FValues.Delete(FValues.Count - 1);
    FTags.Delete(FTags.Count - 1);
    FGroups.Delete(FGroups.Count - 1);
  end;
end;

procedure TElRelativeDistinguishedName.GetValuesByOID(const OID: ByteArray; Values: TElByteArrayList);
var
  I: integer;
begin
  if Values = nil then exit;
  Values.Clear;
  for I := 0 to FTypes.Count - 1 do
  begin
    if CompareContent(FTypes.Item[I], OID) then
      Values.Add(FValues.Item[I]);
  end;
end;

function TElRelativeDistinguishedName.GetFirstValueByOID(const OID: ByteArray): ByteArray;
var
  Lst : TElByteArrayList;
begin
  Lst := TElByteArrayList.Create();
  try
    GetValuesByOID(OID, Lst);
    if Lst.Count > 0 then
      Result := Lst.Item[0]
    else
      Result := EmptyArray;
  finally
    FreeAndNil(Lst);
  end;
end;

function TElRelativeDistinguishedName.LoadFromTag(Tag: TElASN1ConstrainedTag;
  IgnoreTopSequence: boolean{$ifdef HAS_DEF_PARAMS}  =  false {$endif}): boolean;
var
  TagSet, TagSeq, TagDfn: TElASN1ConstrainedTag;
  I, J, Size: integer;
  OID, Value: ByteArray;
  TagID: byte;
begin
  Result := false;
  if (not IgnoreTopSequence) and (Tag.TagId <> SB_ASN1_SEQUENCE) then
    Exit;
  SetCount(0);
  TagDfn := TElASN1ConstrainedTag.CreateInstance;
  try
    for I := 0 to Tag.Count - 1 do
    begin
      if (not Tag.GetField(I).IsConstrained) or (Tag.GetField(I).TagId <> SB_ASN1_SET) then
        Exit;
      TagSet := TElASN1ConstrainedTag(Tag.GetField(I));
      for J := 0 to TagSet.Count - 1 do
      begin
        if (not TagSet.GetField(J).IsConstrained) or (TagSet.GetField(J).TagId <> SB_ASN1_SEQUENCE) then
          Exit;

        TagSeq := TElASN1ConstrainedTag(TagSet.GetField(J));
        if (TagSeq.Count <> 2) then
          Exit;

        if (TagSeq.GetField(0).IsConstrained) or (TagSeq.GetField(0).TagId <> SB_ASN1_OBJECT) then
          Exit;

        OID := TElASN1SimpleTag(TagSeq.GetField(0)).Content;
        Size := 0;
        SetLength(Value, Size);
        TagSeq.GetField(1).SaveToBuffer( nil , Size);
        SetLength(Value, Size);
        TagSeq.GetField(1).SaveToBuffer( @Value[0] , Size);
        SetLength(Value, Size);
        TagID := TagSeq.GetField(1).TagId;
        TagDfn.Clear;
        if (TagDfn.LoadFromBuffer(@Value[0], Size)) and (TagDfn.Count > 0) then
        begin
          TagID := PByte(@Value[0])^;
          Size := 0;
          SetLength(Value, Size);
          TagDfn.GetField(0).SaveToBuffer( nil , Size);
          SetLength(Value, Size);
          TagDfn.GetField(0).WriteHeader := false;
          TagDfn.GetField(0).SaveToBuffer( @Value[0] , Size);
          SetLength(Value, Size);
        end;
        FValues.Add(Value);
        FTypes.Add(OID);
        FGroups.Add( pointer (I));
        FTags.Add( pointer (TagID));
      end;
    end;
  finally
    FreeAndNil(TagDfn);
  end;
  Result := true;
end;

function TElRelativeDistinguishedName.LoadFromDNString(const S : string; LiberalMode : boolean): boolean;
var
  Conv : TElRDNConverter;
begin
  Result := true;
  try
    Conv := TElRDNConverter.Create();
    try
      Conv.FSeparator := '/';
      Conv.LoadFromDNString(Self, S, LiberalMode);
    finally
      FreeAndNil(Conv);
    end;
  except
    Result := false;
  end;
end;

function TElRelativeDistinguishedName.SaveToTag(Tag: TElASN1ConstrainedTag): boolean;
var
  TagSet, TagSeq: TElASN1ConstrainedTag;
  TagSimp: TElASN1SimpleTag;
  I: integer;
  PrevGroupNum: integer;
begin
  Tag.TagId := SB_ASN1_SEQUENCE;
  TagSet := nil;
  PrevGroupNum := -1;
  for I := 0 to FTypes.Count - 1 do
  begin
    if (Groups[I] <> PrevGroupNum) or (TagSet = nil) then
    begin
      TagSet := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
      TagSet.TagId := SB_ASN1_SET;
      PrevGroupNum := Groups[I];
    end;
    TagSeq := TElASN1ConstrainedTag(TagSet.GetField(TagSet.AddField(true)));
    TagSeq.TagId := SB_ASN1_SEQUENCE;
    TagSimp := TElASN1SimpleTag(TagSeq.GetField(TagSeq.AddField(false)));
    TagSimp.TagId := SB_ASN1_OBJECT;
    TagSimp.Content := FTypes.Item[I];
    TagSimp := TElASN1SimpleTag(TagSeq.GetField(TagSeq.AddField(false)));
    TagSimp.TagId := byte( FTags[I] );
    TagSimp.Content := FValues.Item[I];
  end;
  Result := true;
end;

function TElRelativeDistinguishedName.SaveToDNString: string;
var
  Conv : TElRDNConverter;
begin
  Conv := TElRDNConverter.Create();
  try
    Result := Conv.SaveToDNString(Self);
  finally
    FreeAndNil(Conv);
  end;
end;

function TElRelativeDistinguishedName.IndexOf(const OID: ByteArray): integer;
begin
  Result := FTypes.IndexOf(OID);
end;

procedure TElRelativeDistinguishedName.Clear;
begin
  FTypes.Clear;
  FValues.Clear;
  FGroups.Clear;
  FTags.Clear;
end;

function TElRelativeDistinguishedName. GetTags (Index: integer): byte;
begin
  Result := byte(FTags.Items[Index]);
end;

procedure TElRelativeDistinguishedName. SetTags (Index: integer; Value: byte);
begin
  FTags.Items[Index] :=  pointer( Value ) ;
end;

function TElRelativeDistinguishedName.GetGroup(Index: integer): integer;
begin
  Result := integer(FGroups[Index]);
end;

procedure TElRelativeDistinguishedName.SetGroup(Index: integer; Value: integer);
begin
  FGroups[Index] :=   pointer  (Value);
end;

procedure TElRelativeDistinguishedName.Assign(Source: TPersistent);
var
  SrcName: string;
  I: integer;
begin
  if Source is TElRelativeDistinguishedName then
  begin
    FTypes.Clear;
    FValues.Clear;
    FGroups.Clear;
    FTags.Clear;
    FTypes.Assign(TElRelativeDistinguishedName(Source).FTypes);
    FValues.Assign(TElRelativeDistinguishedName(Source).FValues);
    for I := 0 to TElRelativeDistinguishedName(Source).FTags.Count - 1 do
      FTags.Add(TElRelativeDistinguishedName(Source).FTags. Items [I]);
    for I := 0 to TElRelativeDistinguishedName(Source).FGroups.Count - 1 do
      FGroups.Add(TElRelativeDistinguishedName(Source).FGroups. Items [I]);
  end
  else
  begin
    if Assigned(Source) then
      SrcName := Source.ClassName
    else
      SrcName := 'nil';
    raise EConvertError.CreateFmt(SAssignError, [SrcName, ClassName]);
  end;
end;


procedure TElRelativeDistinguishedName.AssignTo(Dest: TPersistent);
begin
  if Dest <> nil then
    Dest.Assign(Self)
  else
    raise EConvertError.CreateFmt(SAssignError, [ClassName, 'nil']);
end;

function TElRelativeDistinguishedName.Add(const OID: ByteArray; const Value: ByteArray; Tag: byte{$ifdef HAS_DEF_PARAMS}  =  0 {$endif}): integer;
var
  OldCount: integer;
  GroupNum: integer;
begin
  OldCount := Count;
  Count := Count + 1;
  OIDs[OldCount] := CloneArray(OID);
  Values[OldCount] := CloneArray(Value);
  // getting last group value
  if OldCount = 0 then
    GroupNum := 0
  else
    GroupNum := Groups[OldCount - 1] + 1;
  Groups[OldCount] := GroupNum;
  if Tag <> 0 then
    Tags[OldCount] := Tag
  else
    Tags[OldCount] := SB_ASN1_OCTETSTRING;
  Result := OldCount;
end;

(*
function TElRelativeDistinguishedName.Equals(RDN : TElRelativeDistinguishedName;
  IgnoreTags : boolean; IgnoreOrder : boolean): boolean;
begin
  // TODO
  Result := false;
end;

{$ifdef D_12_UP}
function TElRelativeDistinguishedName.Equals(Obj: TObject): Boolean;
begin
  Result := inherited;
end;
{$endif}
*)

function TElRelativeDistinguishedName.Contains(RDN : TElRelativeDistinguishedName;
  IgnoreTags : boolean): boolean;
var
  I, J, Tag : integer;
  Oid, Val : ByteArray;
  Found : boolean;
begin
  Result := true;
  for I := 0 to RDN.Count - 1 do
  begin
    Oid := RDN.OIDs[I];
    Val := RDN.Values[I];
    Tag := RDN.Tags[I];
    Found := false;
    for J := 0 to Count - 1 do
    begin
      if (CompareContent(OIDs[J], Oid)) and (CompareContent(Values[J], Val)) and
        ((IgnoreTags) or (Tags[J] = Tag)) then
      begin
        Found := true;
        Break;
      end;
    end;
    if not Found then
    begin
      Result := false;
      Break;
    end;
  end;
end;


function FormatRDN(RDN: TElRelativeDistinguishedName): string;
var
  J: integer;
  S: string;
begin
  Result := '';
  for J := 0 to RDN.Count - 1 do
  begin
    if CompareContent(RDN.OIDs[J], SB_CERT_OID_COMMON_NAME) then
      S := 'CN='
    else
      if CompareContent(RDN.OIDs[J], SB_CERT_OID_COUNTRY) then
      S := 'C='
    else
      if CompareContent(RDN.OIDs[J], SB_CERT_OID_ORGANIZATION) then
      S := 'O='
    else
      if CompareContent(RDN.OIDs[J], SB_CERT_OID_ORGANIZATION_UNIT) then
      S := 'OU='
    else
      if CompareContent(RDN.OIDs[J], SB_CERT_OID_EMAIL) then
      S := 'E='
    else
      if CompareContent(RDN.OIDs[J], SB_CERT_OID_LOCALITY) then
      S := 'L='
    else
      if CompareContent(RDN.OIDs[J], SB_CERT_OID_STATE_OR_PROVINCE) then
      S := 'SP='
    else
      S := OIDToStr(RDN.OIDs[J]) + '=';

    Result := Result + S + StringOfBytes(RDN.Values[J]) + ' / ';
  end;

  if RDN.Count > 0 then
    Result := StringSubstring(Result, StringStartOffset, Length(Result) - 3);
end;


////////////////////////////////////////////////////////////////////////////////
// TElRDNConverter class

constructor TElRDNConverter.Create();
begin
  inherited;
  FPrefixes := TElStringList.Create();
  FOIDs := TElByteArrayList.Create();
  FSeparator := '/';
  FInsertSeparatorPrefix := true;
  SetupKnownOIDs;
end;

 destructor  TElRDNConverter.Destroy;
begin
  FreeAndNil(FPrefixes);
  FreeAndNil(FOIDs);
  inherited;
end;

procedure TElRDNConverter.AddPair(const Prefix : string; const OID : ByteArray);
begin
  FPrefixes.Add(Prefix);
  FOIDs.Add(OID);
end;

procedure TElRDNConverter.SetupKnownOIDs;
  procedure AddPair(const Prefix : string; const OID : ByteArray);
  begin
    FPrefixes.Add(Prefix);
    FOIDs.Add(OID);
  end;
begin
  AddPair('C', SB_CERT_OID_COUNTRY);
  AddPair('ST', SB_CERT_OID_STATE_OR_PROVINCE);
  AddPair('L', SB_CERT_OID_LOCALITY);
  AddPair('O', SB_CERT_OID_ORGANIZATION);
  AddPair('OU', SB_CERT_OID_ORGANIZATION_UNIT);
  AddPair('CN', SB_CERT_OID_COMMON_NAME);
  AddPair('N', SB_CERT_OID_NAME);
  AddPair('G', SB_CERT_OID_GIVEN_NAME);
  AddPair('S', SB_CERT_OID_SURNAME);
  AddPair('I', SB_CERT_OID_INITIALS);
  AddPair('T', SB_CERT_OID_TITLE);
  AddPair('E', SB_CERT_OID_EMAIL);
  AddPair('Email', SB_CERT_OID_EMAIL);
  AddPair('emailAddress', SB_CERT_OID_EMAIL);
  AddPair('SN', SB_CERT_OID_SERIAL_NUMBER);
  AddPair('serialNumber', SB_CERT_OID_SERIAL_NUMBER);
end;

function TElRDNConverter.SaveToDNString(RDN : TElRelativeDistinguishedName): string;
var
  I : integer;
  Idx : integer;
  Prefix, Token, S : string;
  Value : ByteArray;
begin
  if FInsertSeparatorPrefix then
    Result := FSeparator
  else
    Result := '';
  for I := 0 to RDN.Count - 1 do
  begin
    Idx := FOIDs.IndexOf(RDN.OIDs[I]);
    if Idx >= 0 then
      Prefix := FPrefixes[Idx]
    else
      Prefix := OIDToStr(RDN.OIDs[I]);
    //Token := Prefix + '=' + {$ifdef SB_VCL}{$ifdef SB_UNICODE_VCL}StringOfBytes{$endif}{$else}StringOfBytes{$endif}(RDN.Values[I]);
    //Token := Prefix + '=' + {$ifdef SB_VCL}Utf8ToStr{$else}StringOfBytes{$endif}(RDN.Values[I]);
    
    Value := RDN.Values[I];

    case RDN.Tags[I] of
      SB_ASN1_PRINTABLESTRING, SB_ASN1_IA5STRING:
        S := StringOfBytes(Value);
      SB_ASN1_UNIVERSALSTRING, SB_ASN1_BMPSTRING:
        S := WideStrToStr(Value);
      SB_ASN1_UTF8STRING:
        S := Utf8ToStr(Value);
      else
        S := StringOfBytes(Value);
    end;

    Token := Prefix + '=' + S;
    ReleaseString(S);
    
    if I <> RDN.Count - 1 then
      Token := Token + FSeparator;
    Result := Result + Token;
  end;
end;

procedure TElRDNConverter.LoadFromDNString(RDN : TElRelativeDistinguishedName; const S : string;
  LiberalMode : boolean);
var
  Chunk, Token, Oid, Val : string;
  EncOid : ByteArray;
  Idx, OtherIdx : integer;
begin
  RDN.Clear;
  Chunk := S;
  repeat
    Idx := StringIndexOf(Chunk, FSeparator);
    if Idx >= StringStartOffset then
    begin
      Token := StringSubstring(Chunk, StringStartOffset, Idx - StringStartOffset);
      Chunk := StringSubstring(Chunk, Idx + 1);
    end
    else
    begin
      Token := Chunk;
      Chunk := '';
    end;
    Token := StringTrim(Token);
    if Length(Token) > 0 then
    begin
      OtherIdx := StringIndexOf(Token, '=');
      if OtherIdx >= StringStartOffset then
      begin
        Oid := StringSubstring(Token, StringStartOffset, OtherIdx - StringStartOffset);
        Val := StringSubstring(Token, OtherIdx + 1);

        OtherIdx := FPrefixes.IndexOf(Oid);
        if OtherIdx >= 0 then
          RDN.Add(FOIDs.Item[OtherIdx], BytesOfString(Val))
        else
        begin
          try
            EncOid := StrToOID(Oid);
            RDN.Add(EncOid, BytesOfString(Val));
          except
            if not LiberalMode then
              raise;
          end;
        end;
      end;
    end;
  until Idx < StringStartOffset;
end;


end.
