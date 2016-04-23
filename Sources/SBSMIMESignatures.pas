(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBSMIMESignatures;

interface

uses
  SBMessages,
  Classes,
  SBTypes,
  SBUtils,
  SBConstants;


const
  SB_MESSAGE_ERROR_INVALID_MESSAGE_DIGEST   = Integer($2050);
  SB_MESSAGE_WARNING_OMITTED_MESSAGE_DIGEST = Integer($2051);

type
  TElSMIMEMessageSigner = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElSMIMEMessageSigner = TElSMIMEMessageSigner;
   {$endif}

  TElSMIMEMessageSigner = class(TElMessageSigner)
  public
    function Sign(InBuffer: Pointer; InSize: Integer; OutBuffer: Pointer;
      var OutSize: Integer; Detached: Boolean = False): Integer;  override;
  end;

  TElSMIMEMessageVerifier = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElSMIMEMessageVerifier = TElSMIMEMessageVerifier;
   {$endif}

  TElSMIMEMessageVerifier = class(TElMessageVerifier)
  private
    function ProcessTime(const Time: ByteArray):  TDateTime ;
  public
    function Verify(InBuffer: Pointer; InSize: Integer; OutBuffer: Pointer;
      var OutSize: Integer): Integer; override;
    function VerifyDetached(Buffer: Pointer; Size: Integer; Signature: Pointer;
      SignatureSize: Integer): Integer;  override;
  end;

implementation

uses
  SysUtils,
  //SBMD,
  SBASN1Tree,
  SBHashFunction;

{$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
 {$else}
var
 {$endif}

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS OFF}
 {$endif}

//OID_SHA1               :TByteArrayConst = #$2b#$0E#$03#$02#$1A;
//OID_RSAENCRYPTION      :TByteArrayConst = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$01;
//OID_PKCS7_DATA         :TByteArrayConst = #$2a#$86#$48#$86#$f7#$0d#$01#$07#$01;
  OID_DES_EDE3_CBC       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = #$2A#$86#$48#$86#$F7#$0D#$03#$07 {$endif}; 
  OID_RC2_CBC            : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = #$2A#$86#$48#$86#$F7#$0D#$03#$02 {$endif};
  OID_CONTENT_TYPE       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = #$2a#$86#$48#$86#$f7#$0d#$01#$09#$03 {$endif}; 
  OID_SIGNING_TIME       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = #$2a#$86#$48#$86#$f7#$0d#$01#$09#$05 {$endif}; 
  OID_MESSAGE_DIGEST     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = #$2a#$86#$48#$86#$f7#$0d#$01#$09#$04 {$endif}; 
  OID_SMIME_CAPABILITIES : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = #$2a#$86#$48#$86#$f7#$0d#$01#$09#$0f {$endif}; 
  OID_DES_CBC            : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = #$2b#$0e#$03#$02#$07 {$endif}; 
//OID_SHA1_RSAENCRYPTION :TByteArrayConst = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$05;

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS ON}
 {$endif}

{ TElSMIMEMessageSigner }

(*
{$ifndef SB_VCL}
function TElSMIMEMessageSigner.Sign(const InBuffer: ByteArray; var OutBuffer: ByteArray;
  var OutSize: Integer; Detached: Boolean = false): Integer;
{$else}
function TElSMIMEMessageSigner.Sign(InBuffer: Pointer; InSize: Integer; OutBuffer: Pointer;
  var OutSize: Integer; Detached: Boolean = false): Integer;
{$endif}
//*)
function TElSMIMEMessageSigner.Sign(InBuffer: Pointer; InSize: Integer; OutBuffer: Pointer;
  var OutSize: Integer; Detached: Boolean = false): Integer;
var
  Signer: TElMessageSigner;
  HashRes, Digest, SigTime: ByteArray;
  Tag, CTag: TElASN1ConstrainedTag;
  STag: TElASN1SimpleTag;
  Sz: Integer;
  HFunc : TElHashFunction;
  Tmp1, Tmp2 : ByteArray;
  Capabs : ByteArray;
begin
  Signer := TElMessageSigner.Create(nil);
  try

    Signer.HashAlgorithm := HashAlgorithm;
    Signer.CertStorage := CertStorage;
    Signer.SigningTime := Self.SigningTime;
    Signer.SigningOptions := Self.SigningOptions;

    HFunc := TElHashFunction.Create(HashAlgorithm);
    try
      HFunc.Update(InBuffer,  InSize );
      HashRes := HFunc.Finish;
    finally
      FreeAndNil(HFunc);
    end;

    if Length(HashRes) > 0 then
    begin
      SetLength(Digest, Length(HashRes) + 2);

      Digest[0] := byte($04);
      Digest[0 + 1] := byte(Length(HashRes));

      SBMove(HashRes[0], Digest[0 + 2], Length(HashRes));
    end
    else
    begin
      Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
      Exit;
    end;

    Signer.AuthenticatedAttributes.Count := 4;
    with Signer.AuthenticatedAttributes do
    begin
      Attributes[0] := OID_CONTENT_TYPE;
      Tmp1 := GetByteArrayFromByte(SB_ASN1_OBJECT);
      Tmp2 := GetByteArrayFromByte(ConstLength(SB_OID_PKCS7_DATA));
      Values[0].Add(SBConcatArrays(Tmp1, Tmp2, SB_OID_PKCS7_DATA));
      ReleaseArray(Tmp1);
      ReleaseArray(Tmp2);
      Attributes[1] := OID_SIGNING_TIME;
      if (SigningTime >=
         EncodeDate(2050, 1, 1) )
        or
        (SigningTime <
         EncodeDate(1950, 1, 1) )
      then
      begin
        SigTime := BytesOfString(DateTimeToGeneralizedTime(SigningTime));
        SigTime := FormatAttributeValue(SB_ASN1_GENERALIZEDTIME, SigTime);
        //SigTime := TByteArrayConst(Chr(SB_ASN1_GENERALIZEDTIME)) + Chr(Length(SigTime)) + SigTime;
      end
      else
      begin
        SigTime := BytesOfString(DateTimeToUTCTime(SigningTime));
        SigTime := FormatAttributeValue(SB_ASN1_UTCTIME, SigTime);
        //SigTime := TByteArrayConst(Chr(SB_ASN1_UTCTIME)) + Chr(Length(SigTime)) + SigTime;
      end;
      Values[1].Add(SigTime);
      Attributes[2] := OID_MESSAGE_DIGEST;
      Values[2].Add(Digest);
      Attributes[3] := OID_SMIME_CAPABILITIES;

      Tag := TElASN1ConstrainedTag.CreateInstance;
      try
        Tag.TagId := SB_ASN1_SEQUENCE;
        { 3DES }
        CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
        CTag.TagId := SB_ASN1_SEQUENCE;
        STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
        STag.TagId := SB_ASN1_OBJECT;
        STag.Content := OID_DES_EDE3_CBC;
        { RC2128 }
        CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
        CTag.TagId := SB_ASN1_SEQUENCE;
        STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
        STag.TagId := SB_ASN1_OBJECT;
        STag.Content := OID_RC2_CBC;
        STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
        STag.TagId := SB_ASN1_Integer;
        STag.Content := BytesOfString(#$0#$80);
        { AES128 }
        CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
        CTag.TagId := SB_ASN1_SEQUENCE;
        STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
        STag.TagId := SB_ASN1_OBJECT;
        STag.Content := SB_OID_AES128_CBC;
        { AES192 }
        CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
        CTag.TagId := SB_ASN1_SEQUENCE;
        STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
        STag.TagId := SB_ASN1_OBJECT;
        STag.Content := SB_OID_AES192_CBC;
        { AES256 }
        CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
        CTag.TagId := SB_ASN1_SEQUENCE;
        STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
        STag.TagId := SB_ASN1_OBJECT;
        STag.Content := SB_OID_AES256_CBC;
        { RC264 }
        CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
        CTag.TagId := SB_ASN1_SEQUENCE;
        STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
        STag.TagId := SB_ASN1_OBJECT;
        STag.Content := OID_RC2_CBC;
        STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
        STag.TagId := SB_ASN1_Integer;
        STag.Content := GetByteArrayFromByte($40);
        { DES }
        CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
        CTag.TagId := SB_ASN1_SEQUENCE;
        STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
        STag.TagId := SB_ASN1_OBJECT;
        STag.Content := OID_DES_CBC;
        { SHA1WithRSA }
        CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
        CTag.TagId := SB_ASN1_SEQUENCE;
        STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
        STag.TagId := SB_ASN1_OBJECT;
        STag.Content := SB_OID_SHA1_RSA;
        Sz := 0;
        Tag.SaveToBuffer(nil, Sz);
        SetLength(Capabs, Sz);
        Tag.SaveToBuffer(@Capabs[0], Sz);
        SetLength(Capabs, Sz);
        Values[3].Add(Capabs);
      finally
        FreeAndNil(Tag);
      end;
    end;

    Result := Signer.Sign(InBuffer, InSize,  OutBuffer, OutSize, Detached);
  finally
    FreeAndNil(Signer);
    ReleaseArray(HashRes);
    ReleaseArray(Digest);
    ReleaseArray(SigTime);
  end;
end;

{ TElSMIMEMessageVerifier }

(*
{$ifndef SB_VCL}
function TElSMIMEMessageVerifier.Verify(const InBuffer: ByteArray; var OutBuffer: ByteArray;
  var OutSize: Integer): Integer;
{$else}
function TElSMIMEMessageVerifier.Verify(InBuffer: Pointer; InSize: Integer; OutBuffer: Pointer;
  var OutSize: Integer): Integer;
{$endif}
//*)
function TElSMIMEMessageVerifier.Verify(InBuffer: Pointer; InSize: Integer; OutBuffer: Pointer;
  var OutSize: Integer): Integer;
var
  Hash: TElHashFunction;
  IncludedDigest, ActualDigest: ByteArray;
  I: Integer;
  Tag, InternalTag: TElASN1ConstrainedTag;
  Field: TElASN1CustomTag;
  Written, ChunkSize: Integer;
  P: PByte;
begin
  Result := inherited Verify(InBuffer, InSize, OutBuffer, OutSize);

  if Result <> 0 then
    Exit;

  if (OutSize <> 0) and
    ( PByte(OutBuffer)^  = SB_ASN1_SEQUENCE) then
  begin
    // the code below seems to be a workaround for some buggy S/MIME implementation

    Tag := TElASN1ConstrainedTag.CreateInstance;
    try
      if Tag.LoadFromBuffer(OutBuffer, OutSize) then
      begin
        if (Tag.Count <> 0) and Tag.GetField(0).IsConstrained then
        begin
          InternalTag := TElASN1ConstrainedTag(Tag.GetField(0));

          P := OutBuffer;
          Written := 0;

          for I := 0 to InternalTag.Count - 1 do
          begin
            ChunkSize := OutSize - Written;

            Field := InternalTag.GetField(I);
            Field.WriteHeader := False;

            if Field.SaveToBuffer(P, ChunkSize) then
            begin
              Inc(P, ChunkSize);
              Inc(Written, ChunkSize);
            end;
          end;

          OutSize := Written;
        end;
      end;
    finally
      FreeAndNil(Tag);
    end;
  end;

  IncludedDigest := EmptyArray();

  if Attributes.Count > 0 then
  begin
    for I := 0 to Attributes.Count - 1 do
    begin
      if CompareContent(Attributes.Attributes[I], OID_MESSAGE_DIGEST) then
        IncludedDigest := CloneArray(Attributes.Values[I].Item[0])
      else
      if CompareContent(Attributes.Attributes[I], OID_SIGNING_TIME) then
        if Attributes.Values[I].Count > 0 then
        begin
          FSigningTime := ProcessTime(Attributes.Values[I].Item[0]);
        end;
    end;
  end;

  if (Attributes.Count = 0) or (Length(IncludedDigest) = 0) then
  begin
    Result := SB_MESSAGE_WARNING_OMITTED_MESSAGE_DIGEST;
    ReleaseArray(IncludedDigest);
    Exit;
  end;

  try
    Hash := TElHashFunction.Create(HashAlgorithm);
  except
    Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
    ReleaseArray(IncludedDigest);
    Exit;
  end;
  try
    Hash.Update(OutBuffer, OutSize);
    ActualDigest := Hash.Finish();
  finally
    FreeAndNil(Hash);
  end;

  Result := SB_MESSAGE_ERROR_INVALID_MESSAGE_DIGEST;

  if (Length(IncludedDigest) = Length(ActualDigest) + 2) and
     (IncludedDigest[0] = Byte($04)) and (IncludedDigest[1] = Byte(Length(ActualDigest))) then
  begin
    if CompareMem(@IncludedDigest[2], @ActualDigest[0], Length(ActualDigest))
    then
      Result := 0;
  end;

  ReleaseArray(IncludedDigest);
  ReleaseArray(ActualDigest);
end;

(*
{$ifndef SB_VCL}
function TElSMIMEMessageVerifier.VerifyDetached(const Buffer: ByteArray;
  const Signature: ByteArray): Integer;
{$else}
function TElSMIMEMessageVerifier.VerifyDetached(Buffer: Pointer; Size: Integer; Signature: Pointer;
  SignatureSize: Integer): Integer;
{$endif}
//*)
function TElSMIMEMessageVerifier.VerifyDetached(Buffer: Pointer; Size: Integer; Signature: Pointer;
  SignatureSize: Integer): Integer;
var
  OutBuf: ByteArray;
  OutSize: Integer;
  I: Integer;
  Digest, HashRes: ByteArray;
  HFunc : TElHashFunction;
begin

  OutSize := SignatureSize;
  SetLength(OutBuf, OutSize);
  Result := inherited VerifyDetached(Buffer, Size, Signature, SignatureSize);
  //Result := inherited Verify(Signature, SignatureSize, @OutBuf[0], OutSize);
  if Result <> 0 then
    Exit;

  for I := 0 to Attributes.Count - 1 do
  begin
    if CompareContent(Attributes.Attributes[I], OID_MESSAGE_DIGEST) then
      Digest := Attributes.Values[I].Item[0]
    else
    if CompareContent(Attributes.Attributes[I], OID_SIGNING_TIME) then
      if Attributes.Values[I].Count > 0 then
      begin
        FSigningTime := ProcessTime(Attributes.Values[I].Item[0]);
      end;
  end;

  if (Attributes.Count > 0) then
  begin
    HFunc := TElHashFunction.Create(HashAlgorithm);
    try
      HFunc.Update(Buffer, Size);
      HashRes := HFunc.Finish;
    finally
      FreeAndNil(HFunc);
    end;

    if Length(HashRes) > 0 then
    begin
      Result := SB_MESSAGE_ERROR_INVALID_MESSAGE_DIGEST;

      if (Length(Digest) = Length(HashRes) + 2) and
        (Digest[0] = byte($04)) and (Digest[0 + 1] = byte(Length(HashRes)))
      then
      begin
        if CompareMem(@Digest[0 + 2], @HashRes[0], Length(HashRes))
        then
          Result := 0;
      end;
    end
    else
      Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
  end;

end;

function TElSMIMEMessageVerifier.ProcessTime(const Time: ByteArray):  TDateTime ;
var
  Tag: Byte;
  Content: ByteArray;
begin
  if Length(Time)=0 then
  begin
    Result :=  0 ;
    exit;
  end;
  Tag := PByte(@Time[0])^; // ->:   Tag := Byte(Time[1]); ???
  Content := Copy(Time, 0 + 2, Length(Time));
  if Tag = SB_ASN1_UTCTIME then
    Result := UTCTimeToDateTime(StringOfBytes(Content))
  else if Tag = SB_ASN1_GENERALIZEDTIME then
    Result := GeneralizedTimeToDateTime(StringOfBytes(Content))
  else
    Result :=  0 ;
  ReleaseArray(Content);
end;

{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
initialization

  OID_DES_EDE3_CBC       := CreateByteArrayConst(#$2A#$86#$48#$86#$F7#$0D#$03#$07);
  OID_RC2_CBC            := CreateByteArrayConst(#$2A#$86#$48#$86#$F7#$0D#$03#$02);
  OID_CONTENT_TYPE       := CreateByteArrayConst(#$2a#$86#$48#$86#$f7#$0d#$01#$09#$03);
  OID_SIGNING_TIME       := CreateByteArrayConst(#$2a#$86#$48#$86#$f7#$0d#$01#$09#$05);
  OID_MESSAGE_DIGEST     := CreateByteArrayConst(#$2a#$86#$48#$86#$f7#$0d#$01#$09#$04);
  OID_SMIME_CAPABILITIES := CreateByteArrayConst(#$2a#$86#$48#$86#$f7#$0d#$01#$09#$0f);
  OID_DES_CBC            := CreateByteArrayConst(#$2b#$0e#$03#$02#$07);

 {$endif}

end.
