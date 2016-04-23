(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBTSPClient;

interface

uses


  Classes,
  SysUtils,
  

  SBTypes,
  SBUtils,
  SBEncoding,
  SBConstants,
  SBPEM,
  SBASN1,
  SBASN1Tree,
  SBX509,
  SBX509Ext,
  SBPKCS7,
  SBPKCS7Utils,
  SBPKICommon,
  SBTSPCommon,
  SBCustomCertStorage;



type
  TElClientTSPInfo = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElClientTSPInfo = TElClientTSPInfo;
   {$endif}

  TSBTSPOption = (tsoIncludeReqPolicy, tsoIgnoreBadSignature, tsoIgnoreBadNonce);
  TSBTSPOptions = set of TSBTSPOption;
  TSBTSPRequestFormat = (tsfRFC3161, tsfCMS);

  TElClientTSPInfo = class(TElTSPInfo)
  protected
    FOwner : TObject;
    FVerifier: TObject;//TElMessageVerifier;
    FMessageImprint : ByteArray;
    FResponseNonce: ByteArray;
    FCMS : ByteArray;
    FIgnoreBadSignature : boolean;
    FLastValidationResult : integer;
    FHashAlgorithm : integer;
    FHashedData : ByteArray;
    procedure ProcessMessageImprint(Tag : TElASN1ConstrainedTag);
    function GetCertificates: TElCustomCertStorage;
  public
    constructor Create; override;
     destructor  Destroy; override;

    function ParseCMS(const CMSData: ByteArray): integer;  overload; 
    function ParseCMS(const CMSData: ByteArray; NoOuterInfo : boolean): integer;  overload; 
    procedure Reset; override;

    function GetSignerCertificate : TElX509Certificate;

    property Nonce: ByteArray read FNonce write SetNonce; 
    property Certificates: TElCustomCertStorage read GetCertificates;
    property MessageImprint : ByteArray read FMessageImprint;
    property ResponseNonce: ByteArray read FResponseNonce;
    property CMS : ByteArray read FCMS;
    property IgnoreBadSignature : boolean read FIgnoreBadSignature write FIgnoreBadSignature;
    property LastValidationResult : integer read FLastValidationResult;
    property HashAlgorithm : integer read FHashAlgorithm;
    property HashedData : ByteArray read FHashedData;
  end;

  TElCustomTSPClient = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCustomTSPClient = TElCustomTSPClient;
   {$endif}

  TSBTSPBeforeSignEvent = procedure (Sender: TObject;
    Signer : TObject) of object;

  TSBTSPErrorEvent =  procedure(Sender: TObject; ResultCode : integer) of object;

    
  TElCustomTSPClient = class(TElTSPClass)
  protected
    FTSPInfo: TElClientTSPInfo;
    FHashAlgorithm: Integer;
    FIncludeCertificates: Boolean;
    FReqPolicy : ByteArray;
    FOptions : TSBTSPOptions;
    FRequestFormat : TSBTSPRequestFormat;
    FCertStorage : TElCustomCertStorage;
    FOnBeforeSign : TSBTSPBeforeSignEvent;
    FOnCertificateValidate : TSBCertificateValidationEvent;
    FOnTSPError : TSBTSPErrorEvent;
    procedure DoTSPError(ResultCode : integer);
    procedure DoCertificateValidate(
      Certificate : TElX509Certificate;
      AdditionalCertificates : TElCustomCertStorage;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason;
      var DoContinue : TSBBoolean); virtual;
    function CreateRequest(const HashedData : ByteArray; var Request: ByteArray): integer;
    function CreateRequestRFC3161(const HashedData : ByteArray; var Request: ByteArray): integer;
    function CreateRequestCMS(const HashedData : ByteArray; var Request: ByteArray): integer;
    function MessageImprint(const HashedData : ByteArray): ByteArray;
    function ProcessReply(const Reply: ByteArray; out ServerResult:  TSBPKIStatus ;
      out FailureInfo: integer; out ReplyCMS : ByteArray): integer;
    function MatchTSPRequirements(const HashedData : ByteArray): Integer;
    procedure Notification(AComponent : TComponent; AOperation : TOperation); override;
    procedure SetCertStorage(Value : TElCustomCertStorage);
    procedure SetReqPolicy(const V : ByteArray);
  public
    constructor Create(Owner: TSBComponentBase);   override;  
     destructor  Destroy; override;

    function Timestamp(const HashedData: ByteArray;
      {$ifndef BUILDER_USED}out {$else}var {$endif} ServerResult:  TSBPKIStatus ;
      {$ifndef BUILDER_USED}out {$else}var {$endif} FailureInfo: integer;
      {$ifndef BUILDER_USED}out {$else}var {$endif} ReplyCMS : ByteArray) : Integer; virtual; abstract;
    
    property TSPInfo: TElClientTSPInfo read FTSPInfo;

    property ReqPolicy : ByteArray read FReqPolicy write SetReqPolicy;

  published
    property HashAlgorithm: Integer read FHashAlgorithm write FHashAlgorithm;
    // IncludeCertificates specifies, if the reply from the server must include
    // certificate(s), used for signing. This corresponds to TElMessageSigner.IncludeCertificates
    property IncludeCertificates: Boolean read FIncludeCertificates write
      FIncludeCertificates;
    property Options : TSBTSPOptions read FOptions write FOptions;
    property RequestFormat : TSBTSPRequestFormat read FRequestFormat write FRequestFormat;
    property CertStorage : TElCustomCertStorage read FCertStorage write SetCertStorage;
    property OnCertificateValidate : TSBCertificateValidationEvent read FOnCertificateValidate write FOnCertificateValidate;
    property OnBeforeSign : TSBTSPBeforeSignEvent read FOnBeforeSign write FOnBeforeSign;
    property OnTSPError : TSBTSPErrorEvent read FOnTSPError write FOnTSPError;
  end;

  TSBTimestampNeededEvent =  procedure(Sender : TObject;
    RequestStream, ReplyStream:  TStream ; var Succeeded : TSBBoolean) of object;
    
  TElFileTSPClient = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElFileTSPClient = TElFileTSPClient;
   {$endif}

  TElFileTSPClient = class(TElCustomTSPClient)
  protected
    FOnTimestampNeeded : TSBTimestampNeededEvent;
    FHashOnlyNeeded : boolean;
  public
    function Timestamp(const HashedData: ByteArray;
      {$ifndef BUILDER_USED}out {$else}var {$endif} ServerResult:  TSBPKIStatus ;
      {$ifndef BUILDER_USED}out {$else}var {$endif} FailureInfo: integer;
      {$ifndef BUILDER_USED}out {$else}var {$endif} ReplyCMS : ByteArray) : Integer; override;
  published
    property HashOnlyNeeded : boolean read FHashOnlyNeeded write FHashOnlyNeeded;
    property OnTimestampNeeded : TSBTimestampNeededEvent read FOnTimestampNeeded write FOnTimestampNeeded;
  end;

procedure Register;

implementation

uses
  {$ifdef SB_UNICODE_VCL}
  SBStringList,
   {$endif}
  SBMessages;

procedure Register;
begin
  RegisterComponents('PKIBlackbox', [TElFileTSPClient]);
end;

constructor TElCustomTSPClient.Create(Owner: TSBComponentBase);
begin
  inherited Create(Owner);
  FTSPInfo := TElClientTSPInfo.Create;
  FTSPInfo.FOwner := Self;
  IncludeCertificates := true;
  FHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
  FReqPolicy := EmptyArray;
  FOptions := [];
  FRequestFormat := tsfRFC3161;
end;


 destructor  TElCustomTSPClient.Destroy;
begin
  FreeAndNil(FTSPInfo);
  inherited;
end;

//  s := TByteArrayConst(#$2B#$06#$01#$05#$05#$07#$30#$03#$08); //id-kp-timeStamping

function TElCustomTSPClient.CreateRequestRFC3161(const HashedData : ByteArray; var
  Request: ByteArray): integer;
var
  s: ByteArray;
  l: TElByteArrayList;
begin
  l := TElByteArrayList.Create;
  try
      // TimeStampReq ::= SEQUENCE  {
      //   version                      INTEGER  { v1(1) },
    l.Add(WriteInteger(1));
      //   messageImprint               MessageImprint,
    l.Add(MessageImprint(HashedData));
      //   reqPolicy             TSAPolicyId              OPTIONAL,
      //      TSAPolicyId ::= OBJECT IDENTIFIER
      // not needed???
    if (Length(FReqPolicy) > 0) or
       (tsoIncludeReqPolicy in Options)  then
      l.Add(WriteOID(FReqPolicy));
      //   nonce                 INTEGER                  OPTIONAL,
    if Length(FTSPInfo.Nonce) <> 0 then
    begin
      if Length(FTSPInfo.FNonce) > 8 then
        SetLength(FTSPInfo.FNonce, 8);
      l.Add(WritePrimitive($02, FTSPInfo.FNonce));
    end;

      //   certReq               BOOLEAN                  DEFAULT FALSE,
    l.Add(WriteBoolean(FIncludeCertificates));
      // }
    s := WriteListSequence(l);
  finally
    FreeAndNil(l);
  end;

  Request := s;
  Result := 0;
end;

function TElCustomTSPClient.CreateRequestCMS(const HashedData : ByteArray; var
  Request: ByteArray): integer;
var
  InnerRequest: ByteArray;
  Signer : TElMessageSigner;
  Sz : TSBInteger;
begin
  CreateRequestRFC3161(HashedData, InnerRequest);
  Signer := TElMessageSigner.Create( nil );
  try
    Signer.HashAlgorithm := SB_ALGORITHM_DGST_SHA1;
    Signer.CertStorage := FCertStorage;
    Signer.IncludeCertificates := true;
    Signer.UseUndefSize := false;
    if Assigned(FOnBeforeSign) then
      FOnBeforeSign(Self, Signer);
    Sz := 0;
    Signer.Sign(@InnerRequest[0], Length(InnerRequest), nil, Sz);
    SetLength(Request, Sz);
    Result := Signer.Sign(@InnerRequest[0], Length(InnerRequest), @Request[0], Sz);
    SetLength(Request, Sz);
  finally
    FreeAndNil(Signer);
    ReleaseArray(InnerRequest);
  end;
end;

function TElCustomTSPClient.CreateRequest(const HashedData : ByteArray; var
    Request: ByteArray): integer;
begin
  if FRequestFormat = tsfRFC3161 then
    Result := CreateRequestRFC3161(HashedData, Request)
  else
    Result := CreateRequestCMS(HashedData, Request);
end;

function TElCustomTSPClient.MatchTSPRequirements(const HashedData : ByteArray): Integer;
begin
  Result := 0;

  if (not (tsoIgnoreBadNonce in Options)) and (not CompareContent(TrimZeros(FTSPInfo.Nonce), TrimZeros(FTSPInfo.ResponseNonce))) then
    result := SB_TSP_ERROR_WRONG_NONCE
  else
  if not ValidateImprint(FHashAlgorithm, HashedData, FTSPInfo.FMessageImprint) then
    result := SB_TSP_ERROR_WRONG_IMPRINT
  else
  if (not IncludeCertificates) and (TSPInfo.Certificates.Count > 0) then
    result := SB_TSP_ERROR_UNEXPECTED_CERTIFICATES;
end;

function TElCustomTSPClient.MessageImprint(const HashedData : ByteArray): ByteArray;
var
  l: TElByteArrayList;
begin
  l := TElByteArrayList.Create;
  try
    l.Add(WriteOID(GetOIDByHashAlgorithm(FHashAlgorithm)));
    result := WriteListSequence(l);
  finally
    FreeAndNil(l);
  end;
  l := TElByteArrayList.Create;
  try
    l.Add(result);
    l.Add(WriteOctetString(HashedData));
    result := WriteListSequence(l);
  finally
    FreeAndNil(l);
  end;
end;

procedure TElCustomTSPClient.DoTSPError(ResultCode : integer);
begin
  if assigned(FOnTSPError) then
    FOnTSPError(Self, ResultCode);
end;

//  id_ct_TSTInfo = #$2b#$06#$2a#$86#$48#$86#$f7#$0d#$01#$09#$10#$01#$04;

procedure TElCustomTSPClient.DoCertificateValidate(
      Certificate : TElX509Certificate;
      AdditionalCertificates : TElCustomCertStorage;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason;
      var DoContinue : TSBBoolean);
begin
  DoContinue := true;
  if assigned(FOnCertificateValidate) then
  begin
    FOnCertificateValidate(Self, Certificate, AdditionalCertificates, Validity, Reason, DoContinue);
  end;
end;

function TElCustomTSPClient.ProcessReply(const Reply: ByteArray; out ServerResult:  TSBPKIStatus ; out FailureInfo: integer; out ReplyCMS : ByteArray): integer;
var
  ASN, Sequence, Field: TElASN1ConstrainedTag;
  Param: TElASN1SimpleTag;
  sz: integer;
  TmpBuf : ByteArray;
  TmpBufSize : integer;
  Validity : TSBCertificateValidity;
  Reason: TSBCertificateValidityReason;
  DoContinue : TSBBoolean;
  RespLen : integer;
begin

  TmpBufSize := Length(Reply);

  if IsBase64UnicodeSequence( @Reply[0], Length(Reply) ) then
  begin
    SetLength(TmpBuf, Length(Reply));
    Base64UnicodeDecode( @Reply[0], Length(Reply) , TmpBuf, TmpBufSize);
    SetLength(TmpBuf, TmpBufSize);
  end
  else
  if IsBase64Sequence( @Reply[0], Length(Reply) ) then
  begin
    SetLength(TmpBuf, Length(Reply));
    Base64Decode( @Reply[0], Length(Reply) , TmpBuf, TmpBufSize);
    SetLength(TmpBuf, TmpBufSize);
  end
  else
  begin
    TmpBuf := Reply;
  end;

  // This method doesn't parse CMS. It just parses the reply and puts CMS to
  // Reply CMS. Parsing is done separately by ParseCMS
  Result := SB_TSP_ERROR_WRONG_DATA;
  ReplyCMS := EmptyArray;
  ServerResult := psGranted;
  FailureInfo := 0;

  try
    ASN := TElASN1ConstrainedTag.CreateInstance;
    try
      try
        // II20120110: LoadFromBuffer replaced with LoadFromBufferSingle to
        // make the component tolerant to timestamp replies having rubbish
        // after the end of data
        //if not ASN.LoadFromBuffer({$ifndef SB_VCL}TmpBuf{$else}@TmpBuf[0], Length(TmpBuf){$endif}) then
        //  exit;
        RespLen := ASN.LoadFromBufferSingle( @TmpBuf[0], Length(TmpBuf) );
        if RespLen = -1 then
          exit;
      except
        exit;
      end;
      if ASN.Count = 0 then
        exit;
      //   TimeStampResp ::= SEQUENCE  {
      //      status                  PKIStatusInfo,
      //      timeStampToken          TimeStampToken     OPTIONAL  }
      Field := TElASN1ConstrainedTag(ASN.GetField(0));
      if (Field = nil) or not Field.IsConstrained then
        exit;
      if Field.Count < 1 then
        exit;
      //   PKIStatusInfo ::= SEQUENCE {
      Sequence := TElASN1ConstrainedTag(Field.GetField(0));
      if (Sequence = nil) or not Sequence.IsConstrained then
        exit;
      //      status        PKIStatus,
      Param := TElASN1SimpleTag(Sequence.GetField(0));
      if (Param = nil) or Param.IsConstrained or (Param.TagId <> SB_ASN1_INTEGER) then
        exit;
      ServerResult :=  TSBPKIStatus( ASN1ReadInteger(Param) ) ;
      Param := TElASN1SimpleTag(Sequence.GetField(1));
      //      statusString  PKIFreeText     OPTIONAL,
      if (Param <> nil) and Param.IsConstrained then
        Param := TElASN1SimpleTag(Sequence.GetField(2));
      //      failInfo      PKIFailureInfo  OPTIONAL
      if (Param <> nil) and not Param.IsConstrained and (Param.TagId = SB_ASN1_BITSTRING) then
        FailureInfo := ASN1ReadInteger(Param);
      //   }
      //   TimeStampToken ::= ContentInfo
      Sequence := TElASN1ConstrainedTag(Field.GetField(1));
      if (Sequence <> nil) and Sequence.IsConstrained then
      begin
        sz := 0;
        Sequence.SaveToBuffer(nil, sz);
        SetLength(ReplyCMS, sz);
        Sequence.SaveToBuffer(@ReplyCMS[0], sz);
        SetLength(ReplyCMS, sz);

        // Parse the reply CMS
        FTSPInfo.IgnoreBadSignature :=  (tsoIgnoreBadSignature in Options) ;
        result := FTSPInfo.ParseCMS(ReplyCMS);

        // if the reply was parsed, validate it's certificate (if available)
        if (Result = 0) and IncludeCertificates and (not FTSPInfo.IgnoreBadSignature) then
        begin
          Validity := cvOk;
          Reason :=  [] ;
          DoContinue := true;

          DoCertificateValidate(FTSPInfo.GetSignerCertificate, FTSPInfo.Certificates, Validity, Reason, DoContinue);
          if Validity <> cvOk then
          begin
            if not DoContinue then
              Result := SB_MESSAGE_ERROR_INVALID_SIGNATURE;
          end;
        end;

        exit;
      end;
    finally
      FreeAndNil(ASN);
    end;
  except
    ServerResult := psRejection;
    FailureInfo := tfiSystemFailure;
  end;

  if (ServerResult = psGranted) or (ServerResult = psGrantedWithMods) then
    Result := 0
  else
    Result := SB_TSP_ERROR_REQUEST_REJECTED;

end;

procedure TElCustomTSPClient.SetCertStorage(Value : TElCustomCertStorage);
begin
{$ifdef VCL50}
  if (FCertStorage <> nil) and (not (csDestroying in
    FCertStorage.ComponentState)) then
    FCertStorage.RemoveFreeNotification(Self);
 {$endif}
  FCertStorage := Value;
  if FCertStorage <> nil then
    FCertStorage.FreeNotification(Self)
end;

procedure TElCustomTSPClient.SetReqPolicy(const V : ByteArray);
begin
  FReqPolicy := CloneArray(V);
end;

procedure TElCustomTSPClient.Notification(AComponent : TComponent; AOperation : TOperation);
begin
  inherited;
  if (AComponent = FCertStorage) and (AOperation = opRemove) then
    CertStorage := nil;
end;


////////////////////////////////////////////////////////////////////////////////
// TElFileTSPClient class

function TElFileTSPClient.Timestamp(const HashedData: ByteArray;
  {$ifndef BUILDER_USED}out {$else}var {$endif} ServerResult:  TSBPKIStatus ;
  {$ifndef BUILDER_USED}out {$else}var {$endif} FailureInfo: integer;
  {$ifndef BUILDER_USED}out {$else}var {$endif} ReplyCMS : ByteArray) : Integer;
var RequestStream,
    ReplyStream :   TMemoryStream  ;
    Request : ByteArray;
    Success : TSBBoolean;
begin

  if not Assigned(FOnTimestampNeeded) then
  begin
    result := SB_TSP_ERROR_NO_PARAMETERS;
    DoTSPError(result);
    exit;
  end;
  if FHashAlgorithm = 0 then
  begin
    result := SB_TSP_ERROR_NO_PARAMETERS;
    DoTSPError(result);
    exit;
  end;

  RequestStream :=   TMemoryStream  .Create;
  ReplyStream :=   TMemoryStream  .Create;
  try
    if not HashOnlyNeeded then
    begin
      Result := CreateRequest(HashedData, Request);
      if Result <> 0 then
      begin
        DoTSPError(result);
        Exit;
      end;
      RequestStream.Write(Request[0], Length(Request));
    end
    else
    begin
      RequestStream.Write(HashedData[0], Length(HashedData));
    end;
    RequestStream.Position := 0;

    Success := true;
    FOnTimestampNeeded(Self, RequestStream, ReplyStream, Success);
    if not Success then
    begin
      result := SB_TSP_ERROR_NO_REPLY;
      DoTSPError(result);
      exit;
    end;
    SetLength(Request, ReplyStream. Size );
    if Length(Request) = 0 then
    begin
      result := SB_TSP_ERROR_WRONG_DATA;
      DoTSPError(result);
      exit;
    end;

    ReplyStream.Position := 0;

    ReplyStream.Read(Request[0], Length(Request));
    result := ProcessReply(Request, ServerResult, FailureInfo,
      ReplyCMS);

    if Result = 0 then
      result := MatchTSPRequirements(HashedData)
    else
      DoTSPError(result);
  finally
    FreeAndNil(RequestStream);
    FreeAndNil(ReplyStream);
  end;
end;

constructor TElClientTSPInfo.Create;
begin
  inherited;
  FVerifier := TElMessageVerifier.Create(nil);
  FIgnoreBadSignature := true;
  FLastValidationResult := 0;
end;

 destructor  TElClientTSPInfo.Destroy;
begin
  FreeAndNil(FVerifier);
  inherited;
end;

function TElClientTSPInfo.GetSignerCertificate : TElX509Certificate;
var Verifier : TElMessageVerifier;
    CertID : TElPKCS7Issuer;
    Lookup : TElCertificateLookup;
    idx    : integer;
begin
  result := nil;

  Verifier := TElMessageVerifier(FVerifier);
  if (Verifier.Certificates.Count = 0) or (Verifier.CertIDCount = 0) then
    exit
  else
  begin
    CertID := Verifier.CertIDs[0];

    Lookup := TElCertificateLookup.Create (nil) ;
    try
      Lookup.Criteria :=  [] ;
      Lookup.Options :=  [] ;

      if CertID.IssuerType = itSubjectKeyIdentifier then
      begin
        Lookup.SubjectKeyIdentifier := CertID.SubjectKeyIdentifier;
        Lookup.Criteria :=  [lcSubjectKeyIdentifier] ;
      end
      else
      begin
        Lookup.IssuerRDN.Assign(CertID.Issuer);
        Lookup.SerialNumber := CertID.SerialNumber;
        Lookup.Criteria :=  [lcIssuer, lcSerialNumber] ;
        Lookup.Options :=  [loExactMatch, loMatchAll] ;
      end;
      idx := Verifier.Certificates.FindFirst(Lookup);
      if idx <> -1 then
      begin
        result := Verifier.Certificates.Certificates[idx];
      end;
    finally
      FreeAndNil(Lookup);
    end;
  end;
end;

function TElClientTSPInfo.GetCertificates: TElCustomCertStorage;
begin
  Result := TElMessageVerifier(FVerifier).Certificates;
end;

procedure TElClientTSPInfo.ProcessMessageImprint(Tag : TElASN1ConstrainedTag);
var
  Seq : TElASN1ConstrainedTag;
  Param : TElASN1SimpleTag;
begin
  FHashAlgorithm := SB_ALGORITHM_UNKNOWN;
  FHashedData := EmptyArray;
  if Tag.Count < 2 then
    Exit;
  if not Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true) then
    Exit;
  // Read AlgorithmIdentifier
  Seq := TElASN1ConstrainedTag(Tag.GetField(0));
  if (Seq.Count <> 1) and (Seq.Count <> 2) then
    Exit;
  if not Seq.GetField(0).CheckType(SB_ASN1_OBJECT, false) then
    Exit;
  Param := TElASN1SimpleTag(Seq.GetField(0));
  FHashAlgorithm := GetAlgorithmByOID(Param.Content);
  // read HashedData
  if not Tag.GetField(1).CheckType(SB_ASN1_OCTETSTRING, false) then
    Exit;
  Param := TElASN1SimpleTag(Tag.GetField(1));
  FHashedData := CloneArray(Param.Content);
end;

function TElClientTSPInfo.ParseCMS(const CMSData: ByteArray): integer;
begin
  Result := ParseCMS(CMSData, false);
end;

function TElClientTSPInfo.ParseCMS(const CMSData: ByteArray; NoOuterInfo : boolean): integer;
var
  buf: ByteArray;
  sz : TSBInteger;
  fld, fld2: integer;
  ASN, Sequence, {Seq, }Field: TElASN1ConstrainedTag;
  Param: TElASN1SimpleTag;
begin
(*
  this method does the following:
  1) Parse CMS Data using Verifier.Verify and check the result. Return this result, if it is not successful.
  2) Extract TSP-specific data and put it into the corresponding properties
*)

  try

  FCMS := (CMSData);
  FLastValidationResult := 0;

  if not NoOuterInfo then
  begin
    sz := 0;
    Setlength(buf, 0);
    Result :=
    TElMessageVerifier(FVerifier).Verify(@CMSData[0], Length(CMSData), nil, sz);

    if Result = SB_MESSAGE_ERROR_BUFFER_TOO_SMALL then
    begin
      SetLength(buf, sz);
      Result :=
      TElMessageVerifier(FVerifier).Verify(@CMSData[0], Length(CMSData), @buf[0], sz);
      FLastValidationResult := Result;

      if not FIgnoreBadSignature then
      begin
        if (Result <> 0) and not (((FOwner = nil) or (not TElCustomTSPClient(FOwner).IncludeCertificates)) and (Result = SB_MESSAGE_ERROR_NO_CERTIFICATE)) then
          exit;
      end;

      SetLength(buf, sz);
    end
    else
    begin
      FLastValidationResult := Result;
      exit;
    end;
  end
  else
    buf := CloneArray(CMSData);

  Result := -1;
  FLastValidationResult := SB_TSP_ERROR_UNRECOGNIZED_FORMAT; 
  try
    ASN := TElASN1ConstrainedTag.CreateInstance;
    try
      try
        if not ASN.LoadFromBuffer( @buf[0], Length(buf) ) then
          exit;
      except
        exit;
      end;

      if ASN.Count = 0 then
        exit;

      // TSTInfo ::= SEQUENCE  {
      if not ASN.GetField(0).CheckType(SB_ASN1_SEQUENCE, true) then
        Exit;
      Field := TElASN1ConstrainedTag(ASN.GetField(0));
      if Field.Count < 5 then
        exit;
      //   version                      INTEGER  { v1(1) },
      if not Field.GetField(0).CheckType(SB_ASN1_INTEGER, false) then
        Exit;
      Param := TElASN1SimpleTag(Field.GetField(0));
      if ASN1ReadInteger(Param) <> 1 {default v1(1)} then
        exit;
      //   policy                       TSAPolicyId,
      if not Field.GetField(1).CheckType(SB_ASN1_OBJECT, false) then
        Exit;

      //   messageImprint               MessageImprint,
      if not Field.GetField(2).CheckType(SB_ASN1_SEQUENCE, true) then
        Exit;
      Sequence := TElASN1ConstrainedTag(Field.GetField(2));
      sz := 0;
      SetLength(FMessageImprint, sz);
      Sequence.SaveToBuffer(@FMessageImprint[0], sz);
      SetLength(FMessageImprint, sz);
      Sequence.SaveToBuffer(@FMessageImprint[0], sz);
      SetLength(FMessageImprint, sz);
      // retrieving data contained in the message imprint
      ProcessMessageImprint(Sequence);
      //   serialNumber                 INTEGER,
      if not Field.GetField(3).CheckType(SB_ASN1_INTEGER, false) then
        Exit;
      Param := TElASN1SimpleTag(Field.GetField(3));
      FSerialNumber := Param.Content;
      //   genTime                      GeneralizedTime,
      if not Field.GetField(4).CheckType(SB_ASN1_GENERALIZEDTIME, false) then
        Exit;
      Param := TElASN1SimpleTag(Field.GetField(4));
      FTime := GeneralizedTimeToDateTime(StringOfBytes(Param.Content));

      fld := 5;

      FResponseNonce := EmptyArray;

      FAccuracySet := false;
      FAccuracySec := 0;
      FAccuracyMilli := 0;
      FAccuracyMicro := 0;
      //   accuracy                     Accuracy                 OPTIONAL,
      if (fld < Field.Count) and (Field.GetField(fld).CheckType(SB_ASN1_SEQUENCE, true)) then
      begin
        Sequence := TElASN1ConstrainedTag(Field.GetField(fld));
        FAccuracySet := true;
        //   Accuracy ::= SEQUENCE {
        fld2 := 0;
        if (fld2 < Sequence.Count) and (Sequence.GetField(fld2).CheckType(SB_ASN1_INTEGER, false)) then
        begin
          //     seconds        INTEGER              OPTIONAL,
          Param := TElASN1SimpleTag(Sequence.GetField(fld2));
          FAccuracySec := ASN1ReadInteger(Param);
          inc(fld2);
        end;
        //     millis     [0] INTEGER  (1..999)    OPTIONAL,
        if (fld2 < Sequence.Count) and (Sequence.GetField(fld2).CheckType($80, false)) then
        begin
          Param := TElASN1SimpleTag(Sequence.GetField(fld2));
          FAccuracyMilli := ASN1ReadInteger(Param);
          inc(fld2);
        end;
        //     micros     [1] INTEGER  (1..999)    OPTIONAL  }
        if (fld2 < Sequence.Count) and (Sequence.GetField(fld2).CheckType($81, false)) then
        begin
          Param := TElASN1SimpleTag(Sequence.GetField(fld2));
          FAccuracyMicro := ASN1ReadInteger(Param);
        end;
        inc(fld);
      end;
      //   ordering                     BOOLEAN             DEFAULT FALSE,
      if (fld < Field.Count) and (Field.GetField(fld).CheckType(SB_ASN1_BOOLEAN, false)) then
      begin
        inc(fld);
      end;
      //   nonce                        INTEGER                  OPTIONAL,
      if (fld < Field.Count) and (Field.GetField(fld).CheckType(SB_ASN1_INTEGER, false)) then
      begin
        Param := TElASN1SimpleTag(Field.GetField(fld));
        FResponseNonce := Param.Content;
        inc(fld);
      end;
      //   tsa                          [0] GeneralName          OPTIONAL,
      if (fld < Field.Count) and (Field.GetField(fld).CheckType(SB_ASN1_A0, true)) then
      begin
        Sequence := TElASN1ConstrainedTag(Field.GetField(fld));
        if Assigned(FTSAName) then
          FreeAndNil(FTSAName);
        FTSAName := TElGeneralName.Create;
        FTSAName.LoadFromTag(Sequence.GetField(0));
        FTSANameSet := true;
      end;

      // reading extensions if present
      if (fld < Field.Count) and (Field.GetField(fld).CheckType(SB_ASN1_A1, true)) then
      begin
        // reading extensions
      end;

    finally
      FreeAndNil(ASN);
    end;
  except
    exit;
  end;
  result := 0;
  FLastValidationResult := 0;

  finally
    ReleaseArray(buf);
  end;
end;

procedure TElClientTSPInfo.Reset;
begin
  inherited;
  FMessageImprint := EmptyArray;
  FResponseNonce := EmptyArray;
  FCMS := EmptyArray;
  FIgnoreBadSignature := false;
  FLastValidationResult := 0;
end;

end.
