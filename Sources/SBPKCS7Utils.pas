(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBPKCS7Utils;

interface

uses
  Classes,
  SysUtils,
  {$ifdef SB_UNICODE_VCL}
  SBStringList,
   {$endif}
  SBTypes,
  SBRDN,
  SBUtils,
  SBConstants,
  SBASN1Tree;


const
  SB_PKCS7_ERROR_INVALID_ASN_DATA                          = Integer($1E01);
  SB_PKCS7_ERROR_NO_DATA                                   = Integer($1E02);
  SB_PKCS7_ERROR_INVALID_CONTENT_INFO                      = Integer($1E03);
  SB_PKCS7_ERROR_UNKNOWN_DATA_TYPE                         = Integer($1E04);
  SB_PKCS7_ERROR_INVALID_DATA                              = Integer($1E05);
  SB_PKCS7_ERROR_INVALID_ENVELOPED_DATA                    = Integer($1E06);
  SB_PKCS7_ERROR_INVALID_ENVELOPED_DATA_VERSION            = Integer($1E07);
  SB_PKCS7_ERROR_INVALID_ENVELOPED_DATA_CONTENT            = Integer($1E08);
  SB_PKCS7_ERROR_INVALID_RECIPIENT_INFOS                   = Integer($1E09);
  SB_PKCS7_ERROR_INVALID_RECIPIENT_INFO                    = Integer($1E0A);
  SB_PKCS7_ERROR_INVALID_RECIPIENT_INFO_VERSION            = Integer($1E0B);
  SB_PKCS7_ERROR_INVALID_RECIPIENT_INFO_KEY                = Integer($1E0C);
  SB_PKCS7_ERROR_INVALID_ISSUER                            = Integer($1E0D);
  SB_PKCS7_ERROR_INVALID_ALGORITHM                         = Integer($1E0E);
  SB_PKCS7_ERROR_INVALID_SIGNED_DATA                       = Integer($1E0F);
  SB_PKCS7_ERROR_INVALID_SIGNED_DATA_VERSION               = Integer($1E10);
  SB_PKCS7_ERROR_INVALID_SIGNER_INFOS                      = Integer($1E11);
  SB_PKCS7_ERROR_INVALID_SIGNER_INFO_VERSION               = Integer($1E12);
  SB_PKCS7_ERROR_INVALID_SIGNER_INFO                       = Integer($1E13);
  SB_PKCS7_ERROR_INTERNAL_ERROR                            = Integer($1E14);
  SB_PKCS7_ERROR_INVALID_ATTRIBUTES                        = Integer($1E15);
  SB_PKCS7_ERROR_INVALID_DIGESTED_DATA                     = Integer($1E16);
  SB_PKCS7_ERROR_INVALID_DIGESTED_DATA_VERSION             = Integer($1E17);
  SB_PKCS7_ERROR_INVALID_ENCRYPTED_DATA                    = Integer($1E18);
  SB_PKCS7_ERROR_INVALID_ENCRYPTED_DATA_VERSION            = Integer($1E19);
  SB_PKCS7_ERROR_INVALID_SIGNED_AND_ENVELOPED_DATA         = Integer($1E1A);
  SB_PKCS7_ERROR_INVALID_SIGNED_AND_ENVELOPED_DATA_VERSION = Integer($1E1B);
  SB_PKCS7_ERROR_INVALID_AUTHENTICATED_DATA                = Integer($1E1C);
  SB_PKCS7_ERROR_INVALID_AUTHENTICATED_DATA_VERSION        = Integer($1E1D);
  SB_PKCS7_ERROR_INVALID_COMPRESSED_DATA                   = Integer($1E1E);
  SB_PKCS7_ERROR_INVALID_COMPRESSED_DATA_CONTENT           = Integer($1E1F);
  SB_PKCS7_ERROR_INVALID_TIMESTAMPED_DATA                  = Integer($1E20);
  SB_PKCS7_ERROR_INVALID_TIMESTAMPED_DATA_VERSION          = Integer($1E21);
  SB_PKCS7_ERROR_INVALID_TIMESTAMPED_DATA_CONTENT          = Integer($1E22);

type
  TElPKCS7Attributes = class
  private
    FAttributes : TElByteArrayList;
    FRawAttributeSequences : TElByteArrayList;
    FValues : TElList;
  protected 
    procedure QuickSort(L, R: integer);

    procedure SetCount(Value : integer);
    function GetCount : integer;
    function GetAttribute(Index : integer) : ByteArray;
    procedure SetAttribute(Index : integer; const Value : ByteArray);
    function  GetValues (Index : integer) : TElByteArrayList;
    function GetRawAttributeSequence(Index : integer): ByteArray;
    procedure SetRawAttributeSequence(Index : integer; const Value : ByteArray);
  public
    constructor Create;
     destructor  Destroy; override;
    function Remove(Index : integer) : boolean;
    procedure Copy(Dest : TElPKCS7Attributes);
    function SaveToBuffer(Buffer : pointer; var Size : integer) : boolean;
    function FindAttribute(const Name : ByteArray) : integer;
    procedure SortLexicographically;
    procedure RecalculateRawAttributeSequences;

    procedure Clear;
    
    property Attributes[Index : integer] : ByteArray read GetAttribute write
      SetAttribute;
    property Values[Index : integer] : TElByteArrayList read  GetValues ;
    property RawAttributeSequences[Index: integer] : ByteArray read GetRawAttributeSequence
      write SetRawAttributeSequence;
      
    property Count : integer read GetCount write SetCount;
  end;

  TSBPKCS7IssuerType = (itIssuerAndSerialNumber, itSubjectKeyIdentifier);
  TElPKCS7Issuer = class
  protected
    FIssuer : TElRelativeDistinguishedName;
    FSerialNumber : ByteArray;
    FSubjectKeyIdentifier : ByteArray;
    FIssuerType : TSBPKCS7IssuerType;
    procedure SetSerialNumber(const V : ByteArray);
    procedure SetSubjectKeyIdentifier(const V : ByteArray);
  public
    constructor Create;
     destructor  Destroy; override;
    procedure Assign(Source: TElPKCS7Issuer);
    property Issuer : TElRelativeDistinguishedName read FIssuer;
    property SerialNumber : ByteArray read FSerialNumber write SetSerialNumber;
    property SubjectKeyIdentifier : ByteArray read FSubjectKeyIdentifier
      write SetSubjectKeyIdentifier;
    property IssuerType : TSBPKCS7IssuerType read FIssuerType write FIssuerType;
  end;

procedure SaveAttributes(Tag : TElASN1ConstrainedTag; Attributes : TElPKCS7Attributes;
  TagID : byte  =  SB_ASN1_SET); 

function ProcessAlgorithmIdentifier(Tag : TElASN1CustomTag; var Algorithm :
  ByteArray; var Params : ByteArray; ImplicitTagging : boolean = false) : integer;
procedure SaveAlgorithmIdentifier(Tag : TElASN1ConstrainedTag; const Algorithm :
  ByteArray; const Params : ByteArray; ImplicitTag : byte = 0;
  WriteNullIfParamsAreEmpty : boolean = true);

implementation

////////////////////////////////////////////////////////////////////////////////
// TElPKCS7Attributes

constructor TElPKCS7Attributes.Create;
begin
  inherited;
  FAttributes := TElByteArrayList.Create;
  FRawAttributeSequences := TElByteArrayList.Create;
  FValues := TElList.Create;
end;

 destructor  TElPKCS7Attributes.Destroy;
var
  Lst : TElByteArrayList;
begin
  FreeAndNil(FAttributes);
  FreeAndNil(FRawAttributeSequences);
  while FValues.Count > 0 do
  begin
    Lst := TElByteArrayList(FValues. Items [0]);
    FValues. Delete (0);
    FreeAndNil(Lst);
  end;
  FreeAndNil(FValues);
  inherited;
end;

procedure TElPKCS7Attributes.Clear;
var
  Lst : TElByteArrayList;
begin
  FAttributes.Clear;
  FRawAttributeSequences.Clear;
  while FValues.Count > 0 do
  begin
    Lst := TElByteArrayList(FValues. Items [0]);
    FValues. Delete (0);
    FreeAndNil(Lst);
  end;
end;

function TElPKCS7Attributes.GetAttribute(Index : integer) : ByteArray;
begin
  if Index < FAttributes.Count then
    Result := CloneArray(FAttributes.Item[Index])
  else
    SetLength(Result, 0);
end;

procedure TElPKCS7Attributes.SetAttribute(Index : integer; const Value : ByteArray);
begin
  if Index < FAttributes.Count then
    FAttributes.Item[Index] := CloneArray(Value);
end;

function TElPKCS7Attributes.GetRawAttributeSequence(Index : integer): ByteArray;
begin
  if Index < FRawAttributeSequences.Count then
    Result := CloneArray(FRawAttributeSequences.Item[Index])
  else
    SetLength(Result, 0);
end;

procedure TElPKCS7Attributes.SetRawAttributeSequence(Index : integer; const Value : ByteArray);
begin
  if Index < FRawAttributeSequences.Count then
    FRawAttributeSequences.Item[Index] := CloneArray(Value);
end;

function TElPKCS7Attributes.FindAttribute(const Name : ByteArray) : integer;
var i : integer;
begin
  result := -1;
  for i := 0 to FAttributes.Count - 1 do
  begin
    if CompareContent(FAttributes.Item[i], Name) then
    begin
      result := i;
      exit;
    end;
  end;
end;

function TElPKCS7Attributes. GetValues (Index : integer) : TElByteArrayList;
begin
  if Index < FValues.Count then
  begin
    Result := TElByteArrayList(FValues[Index]);
  end
  else
    Result := nil;
end;

function TElPKCS7Attributes.GetCount : integer;
begin
  Result := FAttributes.Count;
end;

procedure TElPKCS7Attributes.SetCount(Value : integer);
var
  Lst : TElByteArrayList;
begin
  if Value < FAttributes.Count then
  begin
    while FAttributes.Count > Value do
      FAttributes.Delete(FAttributes.Count - 1);
    while FRawAttributeSequences.Count > Value do
      FRawAttributeSequences.Delete(FRawAttributeSequences.Count - 1);
    while FValues.Count > Value do
    begin
      Lst := TElByteArrayList(FValues[FValues.Count - 1]);
      FValues.Delete(FValues.Count - 1);
      FreeAndNil(Lst);
    end;
  end
  else
  if Value > FAttributes.Count then
  begin
    while FAttributes.Count < Value do
      FAttributes.Add(EmptyArray);
    while FRawAttributeSequences.Count < Value do
      FRawAttributeSequences.Add(EmptyArray);

    while FValues.Count < Value do
      FValues.Add(TElByteArrayList.Create);
  end;
end;

function TElPKCS7Attributes.Remove(Index : integer) : boolean;
var
  Lst : TElByteArrayList;
begin
  if Index < FAttributes.Count then
  begin
    FAttributes.Delete(Index);
    FRawAttributeSequences.Delete(Index);
    Lst := TElByteArrayList(FValues.Items[Index]);
    FValues.Delete(Index);
    FreeAndNil(Lst);
    Result := true;
  end
  else
    Result := false;
end;

procedure TElPKCS7Attributes.Copy(Dest : TElPKCS7Attributes);
var
  I, J, OldCount : integer;
begin
  if not Assigned(Dest) then
    Exit;
  OldCount := Dest.Count;
  Dest.Count := OldCount + FAttributes.Count;
  for I := 0 to FAttributes.Count - 1 do
  begin
    Dest.FAttributes.Item[OldCount + I] := CloneArray(FAttributes.Item[I]);
    Dest.FRawAttributeSequences.Item[OldCount + I] := CloneArray(FRawAttributeSequences.Item[I]);
    for J := 0 to Values[I].Count - 1 do
    begin
      Dest.Values[OldCount + I].Add(CloneArray(TElByteArrayList(Values[I]).Item[J]));
    end;
  end;
end;


function TElPKCS7Attributes.SaveToBuffer(Buffer : pointer; var Size : integer) :
  boolean;
var
  CTag : TElASN1ConstrainedTag;
begin
  CTag := TElASN1ConstrainedTag.CreateInstance;
  try
    SaveAttributes(CTag, Self);
    Result := CTag.SaveToBuffer(Buffer, Size);
  finally
    FreeAndNil(CTag);
  end;
end;

procedure TElPKCS7Attributes.QuickSort(L, R: integer);
var
  I, J, t : integer;
  sp, st : ByteArray;
  ot :  TObject ;
  function CompareLex(const A, B : ByteArray): integer;
  var
    LenA, LenB, Len : integer;
    BufA, BufB : ByteArray;
    K : integer;
  begin
    LenA := Length(A);
    LenB := Length(B);
    Len := Max(LenA, LenB);
    SetLength(BufA, Len);
    SetLength(BufB, Len);
    SBMove(A, 0, BufA, 0, LenA);
    SBMove(B, 0, BufB, 0, LenB);

    FillChar(BufA[LenA + 0], Len - LenA, 0);
    FillChar(BufB[LenB + 0], Len - LenB, 0);
    Result := 0;
    for K := 0 to Len - 1 do
    begin
      Result := PByteArray(@BufA[0])[K] - PByteArray(@BufB[0])[K];
      if Result <> 0 then
        Break;
    end;
    ReleaseArray(BufA);
    ReleaseArray(BufB);
  end;

begin
  SetLength(St, 0);
  repeat
    I := L;
    J := R;
    t := (L + R) shr 1;
    sp := RawAttributeSequences[t];
    repeat
      while (CompareLex(RawAttributeSequences[I], sp) < 0) do
        Inc(I);
      while (CompareLex(RawAttributeSequences[J], sp) > 0) do
        Dec(J);
      if (I <= J) then
      begin
        if (I <> J) then
        begin
          // swapping the elements (attribute, values and rawattributesequences)
          st := RawAttributeSequences[I];
          RawAttributeSequences[I] := RawAttributeSequences[J];
          RawAttributeSequences[J] := CloneArray(st);

          st := Attributes[I];
          Attributes[I] := Attributes[J];
          Attributes[J] := CloneArray(st);

          ot := FValues[I];
          FValues[I] := FValues[J];
          FValues[J] := ot;
        end;
        Inc(I);
        Dec(J);
      end;
    until I > J;
    if (L < J) then
      QuickSort(L, J);
    L := I;
  until I >= R;
end;

procedure TElPKCS7Attributes.SortLexicographically;
var
  I, J : integer;
  CTag, SubCTag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  Buf : ByteArray;
  Size : integer;
begin
  if Count = 0 then
    Exit;

  // (a) recalculating empty raw attribute sequences
  for I := 0 to Count - 1 do
  begin
    if Length(RawAttributeSequences[I]) = 0 then
    begin
      CTag := TElASN1ConstrainedTag.CreateInstance();
      try
        CTag.TagId := SB_ASN1_SEQUENCE;
        STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
        STag.TagId := SB_ASN1_OBJECT;
        STag.Content := FAttributes.Item[I];
        SubCTag := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
        SubCTag.TagId := SB_ASN1_SET;
        for J := 0 to Values[I].Count - 1 do
        begin
          STag := TElASN1SimpleTag(SubCTag.GetField(SubCTag.AddField(false)));
          STag.WriteHeader := false;
          STag.Content := Values[I].Item[J];
        end;
        Size := 0;
        CTag.SaveToBuffer( nil , Size);
        SetLength(Buf, Size);
        CTag.SaveToBuffer( @Buf[0] , Size);
        SetLength(Buf, Size);
        RawAttributeSequences[I] := CloneArray(Buf);
      finally
        FreeAndNil(CTag);
      end;
    end;
  end;
  // (b) sorting attributes on the basis of RawAttributeSequences
  QuickSort(0, Count - 1);

  ReleaseArray(Buf);
end;

procedure TElPKCS7Attributes.RecalculateRawAttributeSequences;
var
  I, J : integer;
  CTag, SubCTag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  Buf : ByteArray;
  Size : integer;
begin
  for I := 0 to Count - 1 do
  begin
    if Length(RawAttributeSequences[I]) = 0 then
    begin
      CTag := TElASN1ConstrainedTag.CreateInstance();
      try
        CTag.TagId := SB_ASN1_SEQUENCE;
        STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
        STag.TagId := SB_ASN1_OBJECT;
        STag.Content := FAttributes.Item[I];
        SubCTag := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
        SubCTag.TagId := SB_ASN1_SET;
        for J := 0 to Values[I].Count - 1 do
        begin
          STag := TElASN1SimpleTag(SubCTag.GetField(SubCTag.AddField(false)));
          STag.WriteHeader := false;
          STag.Content := Values[I].Item[J];
        end;
        Size := 0;
        CTag.SaveToBuffer( nil , Size);
        SetLength(Buf, Size);
        CTag.SaveToBuffer( @Buf[0] , Size);
        SetLength(Buf, Size);
        RawAttributeSequences[I] := CloneArray(Buf);
      finally
        FreeAndNil(CTag);
      end;
    end;
  end;
end;


procedure SaveAttributes(Tag : TElASN1ConstrainedTag; Attributes :
  TElPKCS7Attributes; TagID : byte  =  SB_ASN1_SET);
var
  CTag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  I, J : integer;
begin
  Tag.TagId := TagID;
  for I := 0 to Attributes.Count - 1 do
  begin
    CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    CTag.TagId := SB_ASN1_SEQUENCE;
    STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
    STag.TagId := SB_ASN1_OBJECT;
    STag.Content := Attributes.FAttributes.Item[I];
    CTag := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
    CTag.TagId := SB_ASN1_SET;
    for J := 0 to Attributes.Values[I].Count - 1 do
    begin
      STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
      STag.WriteHeader := false;
      STag.Content := Attributes.Values[I].Item[J];
    end;
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// TElPKCS7Issuer

constructor TElPKCS7Issuer.Create;
begin
  inherited;
  FIssuer := TElRelativeDistinguishedName.Create;
  FIssuerType := itIssuerAndSerialNumber;
end;

 destructor  TElPKCS7Issuer.Destroy;
begin
  FreeAndNil(FIssuer);
  ReleaseArrays(FSerialNumber, FSubjectKeyIdentifier);
  inherited;
end;

procedure TElPKCS7Issuer.Assign(Source: TElPKCS7Issuer);
begin
  FSerialNumber := CloneArray(Source.FSerialNumber);
  FIssuer.Assign(TElRelativeDistinguishedName(Source.FIssuer));
  FIssuerType := Source.IssuerType;
  FSubjectKeyIdentifier := CloneArray(Source.SubjectKeyIdentifier);
end;

procedure TElPKCS7Issuer.SetSerialNumber(const V : ByteArray);
begin
  FSerialNumber := CloneArray(V);
end;

procedure TElPKCS7Issuer.SetSubjectKeyIdentifier(const V : ByteArray);
begin
  FSubjectKeyIdentifier := CloneArray(V);
end;

////////////////////////////////////////////////////////////////////////////////
// Methods

procedure SaveAlgorithmIdentifier(Tag : TElASN1ConstrainedTag; const Algorithm :
  ByteArray; const Params : ByteArray; ImplicitTag: byte = 0;
  WriteNullIfParamsAreEmpty : boolean = true);
var
  STag : TElASN1SimpleTag;
begin
  if ImplicitTag = 0 then
    Tag.TagId := SB_ASN1_SEQUENCE
  else
    Tag.TagId := ImplicitTag;
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_OBJECT;
  STag.Content := CloneArray(Algorithm);
  if (Length(Params) > 0) or (WriteNullIfParamsAreEmpty) then
  begin
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));

    STag.Content := CloneArray(Params);
    if (Params = nil) or (Length(Params) = 0) then
      STag.TagId := SB_ASN1_NULL
    else
      STag.WriteHeader := false;
  end;
end;

function ProcessAlgorithmIdentifier(Tag : TElASN1CustomTag; var Algorithm :
  ByteArray; var Params : ByteArray; ImplicitTagging : boolean = false) : integer;
var
  Sz : integer;
begin
  if (not Tag.IsConstrained) or
    ((not ImplicitTagging) and (Tag.TagId <> SB_ASN1_SEQUENCE)) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ALGORITHM;
    Exit;
  end;
  if (TElASN1ConstrainedTag(Tag).Count > 2) or (TElASN1ConstrainedTag(Tag).Count < 1) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ALGORITHM;
    Exit;
  end;
  if (TElASN1ConstrainedTag(Tag).GetField(0).IsConstrained) or
    (TElASN1ConstrainedTag(Tag).GetField(0).TagId <> SB_ASN1_OBJECT) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ALGORITHM;
    Exit;
  end;
  Algorithm := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(0)).Content;
  if TElASN1ConstrainedTag(Tag).Count = 2 then
  begin
    if TElASN1ConstrainedTag(Tag).GetField(1).IsConstrained then
    begin
      Sz := 0;
      SetLength(Params, Sz);
      TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(1)).SaveToBuffer(nil, Sz);
      SetLength(Params, Sz);
      TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(1)).SaveToBuffer(
        @Params[0], Sz);
      SetLength(Params, Sz);
    end
    else
    begin
      Sz := 0;
      SetLength(Params, Sz);
      TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(1)).SaveToBuffer(nil, Sz);
      SetLength(Params, Sz);
      TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(1)).SaveToBuffer(@Params[0], Sz);
      SetLength(Params, Sz);
    end;
  end
  else
    Params := EmptyArray;
  Result := 0;
end;


end.

