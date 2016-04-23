(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBOCSPClient;

interface

uses
  Classes,
  SysUtils,
  {$ifdef SB_UNICODE_VCL}
  SBStringList,
   {$endif}
  SBConstants,
  SBTypes,
  SBUtils,
  SBEncoding,
  SBPEM,
  SBASN1,
  SBASN1Tree,
  SBX509,
  SBX509Ext,
  SBSHA,
  SBRDN,
  SBOCSPCommon,
  SBPublicKeyCrypto,
  SBPKCS7Utils,
  SBPKICommon,
  SBCMSUtils,
  SBHashFunction,
  SBCustomCertStorage;



type

  TElOCSPClient = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElOCSPClient = TElOCSPClient;
   {$endif}

  TElOCSPResponderID = class
  protected
    FName : TElRelativeDistinguishedName;
    FSHA1KeyHash : ByteArray;
    procedure SetSHA1KeyHash(const V : ByteArray);
  public
    constructor Create;
     destructor  Destroy; override;
    procedure Clear;
    property Name : TElRelativeDistinguishedName read FName;
    property SHA1KeyHash : ByteArray read FSHA1KeyHash write SetSHA1KeyHash;
  end;

  TElOCSPSingleResponse = class
  private
    FHashAlgorithm : integer;
    FIssuerNameHash : ByteArray;
    FIssuerKeyHash : ByteArray;
    FSerialNumber : ByteArray;
    FCertStatus : TElOCSPCertificateStatus;
    FThisUpdate : TElDateTime;
    FNextUpdate : TElDateTime;
    FRevocationTime : TElDateTime;
    FRevocationReasons : TSBCRLReasonFlags;
  public
     destructor  Destroy; override;
    procedure LoadFromTag(Tag : TElASN1ConstrainedTag);
    function CertMatches(Cert : TElX509Certificate; Issuer : TElX509Certificate  =  nil): boolean;
    function SignerMatches(Signer : TElPKCS7Issuer; Issuer : TElX509Certificate  =  nil): boolean; 
    property HashAlgorithm : integer read FHashAlgorithm;
    property IssuerNameHash : ByteArray read FIssuerNameHash;
    property IssuerKeyHash : ByteArray read FIssuerKeyHash;
    property SerialNumber : ByteArray read FSerialNumber;
    property CertStatus : TElOCSPCertificateStatus read FCertStatus;
    property ThisUpdate : TElDateTime read FThisUpdate;
    property NextUpdate : TElDateTime read FNextUpdate;
    property RevocationTime : TElDateTime read FRevocationTime;
    property RevocationReasons : TSBCRLReasonFlags read FRevocationReasons;
  end;

  TElOCSPResponse = class (TPersistent) 
  private
    FSignatureAlgorithm : integer;
    FCertificates : TElMemoryCertStorage;
    FResponderID : TElOCSPResponderID;
    FProducedAt : TElDateTime;
    FResponses : TElList;
    FData : ByteArray;
    FDataBasic : ByteArray;
    FTBS : ByteArray;
    FSig : ByteArray;
    FSigAlg : integer;
    FSigAlgOID : ByteArray;
    FOnCertificateNeeded : TSBCMSCertificateNeededEvent;

    function GetResponseCount : integer;
    function GetResponse(Index: integer) : TElOCSPSingleResponse;
  public
    constructor Create;
     destructor  Destroy; override;
    procedure Clear;
    procedure Assign(Source : TPersistent); override;
    procedure Load(Buffer: pointer; Size: integer);
    function Save(Buffer: pointer; var Size: integer): boolean;
    function SaveBasic(Buffer: pointer; var Size: integer): boolean;
    function EqualsTo(OtherResponse : TElOCSPResponse): boolean;
    function FindResponse(Cert : TElX509Certificate;
      Issuer : TElX509Certificate  =  nil): integer;  overload; 
    function FindResponse(Signer : TElPKCS7Issuer;
      Issuer : TElX509Certificate  =  nil): integer;  overload; 
    function GetSignerCertificate : TElX509Certificate;
    function IsSignerCertificate(Certificate :  TElX509Certificate) : boolean;
    function Validate() : TSBCMSSignatureValidity;  overload; 
    function Validate(CACertificate : TElX509Certificate) : TSBCMSSignatureValidity;  overload; 
    property SignatureAlgorithm : integer read FSignatureAlgorithm;
    property Certificates : TElMemoryCertStorage read FCertificates;
    property ResponderID : TElOCSPResponderID read FResponderID;
    property ProducedAt : TElDateTime read FProducedAt;
    property Responses[Index: integer] : TElOCSPSingleResponse read GetResponse;
    property ResponseCount : integer read GetResponseCount;
    property OnCertificateNeeded : TSBCMSCertificateNeededEvent read FOnCertificateNeeded
      write FOnCertificateNeeded;
  end;

  TSBOCSPClientOption = (ocoIncludeVersion, ocoIncludeSupportedResponseTypes);
  TSBOCSPClientOptions = set of TSBOCSPClientOption;

  TElOCSPClient = class(TElOCSPClass)
  protected
    FCertStorage: TElCustomCertStorage;
    FIssuerCertStorage: TElCustomCertStorage;
    FReplyCertificates: TElCustomCertStorage;
    FReplyProducedAt: TElDateTime;

    FThisUpdate : array of TElDateTime;
    FNextUpdate : array of TElDateTime;
    FRevocationTime : array of TElDateTime;
    FRevocationReason : array of TSBCRLReasonFlag;
    FCertStatus : array of TElOCSPCertificateStatus;
    FNonce: ByteArray;
    FReplyNonce: ByteArray;
    FServerName : TElRelativeDistinguishedName;
    FServerCertKeyHash : ByteArray;
    FURL: string;

    FNesting: integer;
    FParseState: integer;
    FParseState2: integer;
    FParseCert: integer;
    FRespStatus: TElOCSPServerError;
    //FASN1Parser : TElASN1Parser;
    FIncludeSignature : boolean;
    FResponse : TElOCSPResponse;
    FOptions : TSBOCSPClientOptions;
    FSignatureAlgorithm : integer;
  protected
    procedure Notification(AComponent : TComponent; AOperation : TOperation); override;

    function ParseResponseData(const Data: ByteArray; Certificates: TElCustomCertStorage;
      var SignCert: TElX509Certificate): Boolean;
    function ValidateResponseSignature(const ReplyBuf, SignatureAlg, SignatureParam,SignatureBody:
      ByteArray; SignCertificate: TElX509Certificate): Boolean;

    function WriteRequestList (var List: ByteArray) : integer;
    function WriteRequestorName: ByteArray;
    function WriteExtensions : ByteArray;

    function CalculateSignature(const r : ByteArray; SigAlg : integer; Cert : TElX509Certificate) : ByteArray;
    function DoSignRequest(const TBS : ByteArray): ByteArray;
    
    procedure SetCertStorage(Value : TElCustomCertStorage);
    procedure SetIssuerCertStorage(Value : TElCustomCertStorage);
    procedure SetReplyNonce(const V: ByteArray);
    procedure SetServerCertKeyHash(const V : ByteArray);
    function GetCertStatus(Index: Integer): TElOCSPCertificateStatus;
    function GetThisUpdate(Index: Integer): TElDateTime;
    function GetNextUpdate(Index: Integer): TElDateTime;

    function GetRevocationTime(Index: Integer): TElDateTime;
    function GetRevocationReason(Index: Integer): TSBCRLReasonFlag;
  public
    constructor Create(Owner: TSBComponentBase);   override; 
     destructor  Destroy; override;

    function CreateRequest( var Request : ByteArray ) : integer;
    
    function ProcessReply(const Reply : ByteArray; var ServerResult : TElOCSPServerError) : integer;
    function PerformRequest(var ServerResult : TElOCSPServerError; var Reply : ByteArray) : Integer; virtual;
    
    function SupportsLocation(const URI: string): Boolean; virtual;  abstract; 

    property ReplyProducedAt: TElDateTime read FReplyProducedAt;

    property ReplyNonce: ByteArray read FReplyNonce;
    property ReplyCertificates : TElCustomCertStorage read FReplyCertificates;

    property ServerName : TElRelativeDistinguishedName read FServerName;
    property ServerCertKeyHash : ByteArray read FServerCertKeyHash write SetServerCertKeyHash;

    property CertStatus[Index: Integer]: TElOCSPCertificateStatus read GetCertStatus;
    property RevocationTime[Index: Integer]: TDateTime  read GetRevocationTime;
    property RevocationReason[Index: Integer]: TSBCRLReasonFlag read GetRevocationReason;

    property ThisUpdate[Index: Integer]:  TDateTime  read GetThisUpdate;
    property NextUpdate[Index: Integer]:  TDateTime  read GetNextUpdate;
    property Response : TElOCSPResponse read FResponse;

    property Nonce: ByteArray read FNonce write FNonce;

  published
    property CertStorage: TElCustomCertStorage read FCertStorage write SetCertStorage;
    property IssuerCertStorage: TElCustomCertStorage read FIssuerCertStorage write SetIssuerCertStorage;
    property IncludeSignature : boolean read FIncludeSignature write FIncludeSignature;
    property SignatureAlgorithm : integer read FSignatureAlgorithm write FSignatureAlgorithm;
    property Options : TSBOCSPClientOptions read FOptions write FOptions;
    property URL: string read FURL write FURL;
  end;

  TSBOCSPValidationNeededEvent =  procedure(Sender : TObject; const URL : string;
    RequestStream, ReplyStream:  TStream ; var Succeeded : TSBBoolean) of object;
    
  TElFileOCSPClient = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElFileOCSPClient = TElFileOCSPClient;
   {$endif}

  TElFileOCSPClient = class(TElOCSPClient)
  private
    FOnOCSPValidationNeeded : TSBOCSPValidationNeededEvent;
  public
    function SupportsLocation(const URI: string): Boolean; override;
    function PerformRequest(var ServerResult : TElOCSPServerError; var Reply : ByteArray) : Integer; override;
  published
    property OnOCSPValidationNeeded : TSBOCSPValidationNeededEvent read FOnOCSPValidationNeeded write FOnOCSPValidationNeeded;
  end;

  TElCustomOCSPClientFactory = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCustomOCSPClientFactory = TElCustomOCSPClientFactory;
   {$endif}

  TElCustomOCSPClientFactory =  class
  public
    function SupportsLocation(const URI: string): Boolean; virtual; abstract;
    function GetClientInstance(Validator : TObject) : TElOCSPClient; virtual; abstract;
  end;

  TElOCSPClientManager = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElOCSPClientManager = TElOCSPClientManager;
   {$endif}

  TElOCSPClientManager =  class
  private
    FFactoryList : TElList;
  public
    constructor Create;
     destructor  Destroy; override;
    function FindOCSPClientByLocation(const Location : string; Validator : TObject) : TElOCSPClient;
    procedure RegisterOCSPClientFactory(Factory : TElCustomOCSPClientFactory);
    procedure UnregisterOCSPClientFactory(Factory : TElCustomOCSPClientFactory);
  end;

function OCSPClientManagerAddRef : TElOCSPClientManager; 
procedure OCSPClientManagerRelease; 

procedure Register;

implementation

uses
  SBMessages;

procedure Register;
begin
  RegisterComponents('PKIBlackbox', [TElFileOCSPClient]);
end;

resourcestring
  SInvalidOCSPResponse = 'Invalid OCSP response';
  SInvalidSingleResponse = 'Invalid single OCSP response';
  SUnsupportedSignatureAlgorithm = 'Unsupported signature algorithm';

var OCSPClientManager : TElOCSPClientManager  =  nil;
var OCSPClientManagerUseCount : integer  =  0;

constructor TElOCSPClient.Create (Owner: TSBComponentBase) ;
begin
  inherited Create(Owner);
  FServerName := TElRelativeDistinguishedName.Create;
  FReplyCertificates := TElMemoryCertStorage.Create(nil);
  FIncludeSignature := false;
  FIncludeCertificates := true;
  FResponse := TElOCSPResponse.Create();
  FOptions :=  [] ;
  FSignatureAlgorithm := SB_ALGORITHM_UNKNOWN;
end;


 destructor  TElOCSPClient.Destroy;
begin
  FreeAndNil(FReplyCertificates);
  FreeAndNil(FServerName);
  FreeAndNil(FResponse);
  ReleaseArrays(FNonce, FReplyNonce, FServerCertKeyHash);
  inherited;
end;

function SHA1Digest(const d: ByteArray): ByteArray;
var
  dg: TMessageDigest160;
//  ctx: TSHA1Context;
begin
//  InitializeSHA1(ctx);
  dg := HashSHA1(d);
  result := DigestToBinary(dg);
//  FinalizeSHA1(ctx);
end;

function issuerNameHash(cert: TElX509Certificate; Hash_OID : ByteArray): ByteArray;
var
  Tag : TElASN1ConstrainedTag;
  Buffer : ByteArray;
  Size : integer;
  HashFunc : TElHashFunction;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  cert.IssuerRDN.SaveToTag(Tag);

  Size := 0;
  Tag.SaveToBuffer(nil, Size);
  SetLength(Buffer, Size);
  Tag.SaveToBuffer(@Buffer[0], Size);
  SetLength(Buffer, Size);

  HashFunc := TElHashFunction.Create(Hash_OID);
  try
    HashFunc.Update( @Buffer[0] , Size);
    result := HashFunc.Finish();
  finally
    FreeAndNil(HashFunc);
  end;

  ReleaseArray(Buffer);
  FreeAndNil(Tag);
end;

function publicKeyHash(cert: TElX509Certificate): ByteArray;
var
  i: integer;
  ikey: ByteArray;
begin
  i := 0;
  cert.GetPublicKeyBlob(nil, i);
  SetLength(ikey, i);
  cert.GetPublicKeyBlob(@ikey[0], i);
  SetLength(ikey, i);
  result := SHA1Digest(ikey);
  ReleaseArray(ikey);
end;

(*
function WriteExtension(id: ByteArray; critical: boolean; value: ByteArray): ByteArray;
var
  {$ifdef SB_VCL}
  l: TStringList;
  {$else}
  l: array of ByteArray;
  {$endif}
begin
  {$ifdef SB_VCL}
  l := TElStringList.Create;
  try
  l.Add(WriteOID(id));
  l.Add(WriteBoolean(critical));
  l.Add(WriteOctetString(value));
  {$else}
  SetLength(l, 3);
  l[0] := WriteOID(id);
  l[1] := WriteBoolean(critical);
  l[2] := WritePrintableString(value);
  {$endif}
  result := WriteSequence(l);
  {$ifdef SB_VCL}
  finally
    l.Free;
  end;
  {$endif}
end;
*)

function WriteNonce(const value: ByteArray): ByteArray;
var
  s: ByteArray;
  l: array of ByteArray;

begin

  SetLength(l, 2);
  l[0] := WriteOID(SB_OCSP_OID_NONCE);
  l[1] := WriteOctetString(value);

  s := WriteArraySequence(l);
  SetLength(l, 1);
  l[0] := s;
  result := WriteArraySequence(l);
end;

function WriteExtension(const oid, value: ByteArray; valueType : integer): ByteArray;
var
  l: array of ByteArray;
begin
  SetLength(l, 2);
  l[0] := WriteOID(oid);
  if valueType <> 0 then
    l[1] := WritePrimitive(valueType, value)
  else
    l[1] := value;

  result := WriteArraySequence(l);
end;

function WriteHashAlgorithm(Hash_Oid:ByteArray): ByteArray;
var
  l: array of ByteArray;
begin
  SetLength(l, 2);
  l[0] := WriteOID(Hash_Oid);
  l[1] := WriteNULL;
  result := WriteArraySequence(l);
end;


function TElOCSPClient.CreateRequest( var Request : ByteArray ): integer;
var
  l: array of ByteArray;
  b: ByteArray;
  res : integer;
  cnt : integer;
  Exts : ByteArray;
begin
  if (CertStorage = nil) or
     (CertStorage.Count = 0) or
     (IssuerCertStorage = nil) or
     (IssuerCertStorage.Count = 0) or
     (IncludeSignature and ((SigningCertStorage = nil) or (SigningCertStorage.Count = 0))) then
  begin
    SetLength(Request, 0);
    result := SB_OCSP_ERROR_NO_CERTIFICATES;
  end
  else
  begin
    cnt := 2;
    if Length(FNonce) > 0 then
      inc(cnt);
    SetLength(l, cnt);
    //  tbsRequest
    //    version
    if (ocoIncludeVersion in FOptions) then
      l[0] := WriteExplicit(WriteInteger(0));
    //    requestorName
    if not FRequestorName.IsEmpty then
      l[0] := WriteRequestorName;
    res := WriteRequestList(b);
    if res = 0 then
      l[1] := b
    else
    begin
      result := res;
      exit;
    end;
    Exts := WriteExtensions();
    if Length(Exts) > 0 then
      l[2] := WritePrimitive($A2, Exts);

    b := WriteArraySequence(l);

    cnt := 1;
    if IncludeSignature and (SigningCertStorage <> nil) then
      inc(cnt);
    SetLength(l, cnt);
    l[0] := b;

    if IncludeSignature and (SigningCertStorage <> nil) then
    begin
      b := DoSignRequest(b);
      if Length(b) > 0 then
        l[1] := b;
    end;

    Request := WriteArraySequence(l);
    result := 0;
  end;
end;

function TElOCSPClient.ProcessReply(const Reply : ByteArray; var ServerResult : TElOCSPServerError): integer;
var
  Count : integer;
  ASN   : TElASN1ConstrainedTag;

  Sequence,
  SeqLev1,
  SeqLev2,
  Field : TElASN1ConstrainedTag;
  Param: TElASN1SimpleTag;
  Custom: TElASN1CustomTag;
  i : integer;
  FReplyBuf: ByteArray;
  FSignatureAlg : ByteArray;
  FSignatureBody: ByteArray;
  FSignatureParam : ByteArray;

  FSignCerts    : TElMemoryCertStorage;

  Cert : TElX509Certificate;
  CertBuf : ByteArray;
  BufLen : integer;

  TmpBuf : ByteArray;
  TmpBufSize : integer;
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

  result := SB_OCSP_ERROR_WRONG_DATA;

  if (Length(TmpBuf) = 0) then
    exit;

  if (CertStorage = nil) or (CertStorage.Count = 0) then
  begin
    result := SB_OCSP_ERROR_NO_CERTIFICATES;
    Count := 0;
  end
  else
  begin
    Count := CertStorage.Count;
  end;
  
  FReplyCertificates.Clear;

  SetLength(FThisUpdate, Count);
  SetLength(FNextUpdate, Count);
  SetLength(FRevocationTime, Count);
  SetLength(FRevocationReason, Count);
  SetLength(FCertStatus, Count);

  FRespStatus := oseInternalError;

  ASN := TElASN1ConstrainedTag.CreateInstance;
  try
    try
      // II20120110: LoadFromBuffer replaced with LoadFromBufferSingle to process
      // responses with trash after their end tolerantly
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

    Sequence := TElASN1ConstrainedTag(ASN.GetField(0));
    if (Sequence = nil) or (Sequence.Count < 1) then
      exit;

    // access response status
    Param := TElASN1SimpleTag(Sequence.GetField(0));
    if (Param = nil) or (Length(Param.Content) = 0) then
      exit;
    FRespStatus := TElOCSPServerError(Param.Content[0]);

    Sequence := TElASN1ConstrainedTag(Sequence.GetField(1));
    if (Sequence = nil) or (Sequence.Count < 1) then
    begin
      if FRespStatus <> oseSuccessful then
      begin
        result := 0;
        ServerResult := FRespStatus;
      end;
      exit;
    end;
    Sequence := TElASN1ConstrainedTag(Sequence.GetField(0));
    if (Sequence = nil) or (Sequence.Count < 1) then
      exit;

    // access response type
    Param := TElASN1SimpleTag(Sequence.GetField(0));
    if (Param = nil) or (Length(Param.Content) = 0) then
      exit;
    if not CompareMem(Param.Content, SB_OCSP_OID_BASIC_RESPONSE) then
      exit;

    // access response
    Param := TElASN1SimpleTag(Sequence.GetField(1));
    if (Param = nil) or (Length(Param.Content) = 0) then
      exit;

    SetLength(FReplyBuf, Length(Param.Content));

    SBMove(Param.Content, 0, FReplyBuf, 0, Length(Param.Content));
  finally
    FreeAndNil(ASN);
  end;

  FSignCerts := TElMemoryCertStorage.Create(nil);
  try
    // now load and parse the actual response
    ASN := TElASN1ConstrainedTag.CreateInstance;
    try
      try
        if not ASN.LoadFromBuffer( @FReplyBuf[0], Length(FReplyBuf) ) then
          exit;
      except
        exit;
      end;

      // loading ocsp response, not a basic ocsp response
      //FResponse.Load(@FReplyBuf[0], Length(FReplyBuf));
      FResponse.Load(@TmpBuf[0], Length(TmpBuf));

      if ASN.Count = 0 then
        exit;

      result := SB_OCSP_ERROR_INVALID_RESPONSE;

      Sequence := TElASN1ConstrainedTag(ASN.GetField(0));
      if (Sequence = nil) or (Sequence.Count < 1) then
        exit;

      // access responseData
      if not (Sequence.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
        exit;
      Field := TElASN1ConstrainedTag(Sequence.GetField(0));
      if (Field = nil) then
        exit;

      BufLen := 0;
      SetLength(FReplyBuf, BufLen);
      Field.SaveToBuffer(@FReplyBuf[0], BufLen);
      SetLength(FReplyBuf, BufLen);
      Field.SaveToBuffer(@FReplyBuf[0], BufLen);
      SetLength(FReplyBuf, BufLen);

      // access signature info
      if not (Sequence.GetField(1).CheckType(SB_ASN1_SEQUENCE, true)) then
        exit;
      SeqLev1 := TElASN1ConstrainedTag(Sequence.GetField(1));
      if (SeqLev1 = nil) or (SeqLev1.Count < 1) then
      begin
        exit;
      end;

      if SeqLev1.GetField(0).IsConstrained then
        exit;
      Param := TElASN1SimpleTag(SeqLev1.GetField(0));
      if (Param = nil) or (Length(Param.Content) = 0) then
      begin
        exit;
      end;
      SetLength(FSignatureAlg, Length(Param.Content));
      SBMove(Param.Content, 0, FSignatureAlg, 0, Length(Param.Content));
      
      SetLength(FSignatureParam, 0);

      if SeqLev1.Count > 1 then
      begin
        if (SeqLev1.GetField(1).IsConstrained) then
        begin
          SeqLev2 := TElASN1ConstrainedTag(SeqLev1.GetField(1));
          if (SeqLev2 <> nil) and (SeqLev2.Count <> 0) then
          begin
            BufLen := 0;
            SeqLev2.SaveToBuffer( nil , BufLen);
            SetLength(FSignatureParam, BufLen);
            SeqLev2.SaveToBuffer( @FSignatureParam[0] , BufLen);
          end;
        end
        else
        begin
          Param := TElASN1SimpleTag(SeqLev1.GetField(1));
          if (Param <> nil) and (Length(Param.Content) <> 0) then
          begin
            SetLength(FSignatureParam, Length(Param.Content));
            SBMove(Param.Content, 0, FSignatureParam, 0, Length(Param.Content));
          end;
        end;
      end;

      // access signature
      if not Sequence.GetField(2).CheckType(SB_ASN1_BITSTRING, false) then
        exit;
      Param := TElASN1SimpleTag(Sequence.GetField(2));
      if (Param = nil) or (Length(Param.Content) = 0) then
      begin
        exit;
      end;

      SetLength(FSignatureBody, Length(Param.Content) - 1);

      SBMove(Param.Content, 0 + 1, FSignatureBody, 0, Length(Param.Content) - 1);

      // access certificates
      if Sequence.Count > 3 then
      begin
        if not Sequence.GetField(3).IsConstrained then
          Exit;
        SeqLev1 := TElASN1ConstrainedTag(Sequence.GetField(3));
        if (SeqLev1 = nil) or (SeqLev1.Count < 1) then
          exit;

        // +++++ moved outside the loop
        if not TElASN1ConstrainedTag(SeqLev1.GetField(0)).CheckType(SB_ASN1_SEQUENCE, true) then
          exit;
        SeqLev2 := TElASN1ConstrainedTag(SeqLev1.GetField(0));
        if (SeqLev2 = nil) or (SeqLev2.Count < 1) then
          exit;

        Cert := TElX509Certificate.Create(nil);
        try
          for i := 0 to SeqLev2.Count -1 do
          begin
            Custom := SeqLev2.GetField(i);
            BufLen := 0;
            SetLength(CertBuf, BufLen);
            Custom.SaveToBuffer(@CertBuf[0], BufLen);
            SetLength(CertBuf, BufLen);
            Custom.SaveToBuffer(@CertBuf[0], BufLen);
            Cert.LoadFromBuffer(CertBuf, BufLen);
            FSignCerts.Add(Cert);
          end;
        finally
          FreeAndNil(Cert);
        end;
      end;
    finally
      FreeAndNil(ASN);
    end;

    Cert := nil;
    if not ParseResponseData(FReplyBuf, FSignCerts, Cert) then
      exit;

    FSignCerts.ExportTo(FReplyCertificates);
    ServerResult := FRespStatus;

    if not ValidateResponseSignature(FReplyBuf, FSignatureAlg, FSignatureParam, FSignatureBody, Cert) then
      result := SB_OCSP_ERROR_WRONG_SIGNATURE
    else
      result := 0;

  finally
    FreeAndNil(FSignCerts);
  end;
end;

function TElOCSPClient.DoSignRequest(const TBS : ByteArray): ByteArray;
var
  SigMain, Sig, AlgID, Certs : TElASN1ConstrainedTag;
  SigValue, CertValue : TElASN1SimpleTag;
  I : integer;
  Cert : TElX509Certificate;
  SigData : ByteArray;
  CertData : ByteArray;
  Size : integer;
  SizeInt : integer;
  SigAlg : integer;
  Params : ByteArray;
  l: array of ByteArray;

  function AdjustSignatureAlgorithm() : integer;
  begin
    if FSignatureAlgorithm <> SB_ALGORITHM_UNKNOWN then
      Result := FSignatureAlgorithm
    else if Cert.KeyMaterial is TElRSAKeyMaterial then
    begin
      if TElRSAKeyMaterial(Cert.KeyMaterial).KeyFormat = rsaPSS then
        Result := SB_CERT_ALGORITHM_ID_RSAPSS
      else
        Result := SB_CERT_ALGORITHM_SHA1_RSA_ENCRYPTION;
    end
    else if Cert.KeyMaterial is TElDSAKeyMaterial then
      Result := SB_CERT_ALGORITHM_ID_DSA_SHA1
    else if Cert.KeyMaterial is TElElGamalKeyMaterial then
      Result := SB_CERT_ALGORITHM_ID_ELGAMAL
    {$ifdef SB_HAS_ECC}
    else if Cert.KeyMaterial is TElECKeyMaterial then
      Result := SB_CERT_ALGORITHM_SHA1_ECDSA
     {$endif}
    else
      Result := SB_ALGORITHM_UNKNOWN;
  end;
begin
  Cert := nil;
  for I := 0 to SigningCertStorage.Count - 1 do
  begin
    if SigningCertStorage.Certificates[I].PrivateKeyExists then
    begin
      Cert := SigningCertStorage.Certificates[I];
      Break;
    end;
  end;
  if Cert = nil then
  begin
    Result := EmptyArray;
    Exit;
  end;
  SigMain := TElASN1ConstrainedTag.CreateInstance;
  try
    SigMain.TagId := SB_ASN1_A0;
    Sig := TElASN1ConstrainedTag(SigMain.GetField(SigMain.AddField(true)));
    Sig.TagId := SB_ASN1_SEQUENCE;
    AlgID := TElASN1ConstrainedTag(Sig.GetField(Sig.AddField(true)));
    SigAlg := AdjustSignatureAlgorithm();

    if Cert.KeyMaterial is TElDSAKeyMaterial then
    begin
      SetLength(l,3);
      l[0] := WriteInteger(TElDSAKeyMaterial(Cert.KeyMaterial).P);
      l[1] := WriteInteger(TElDSAKeyMaterial(Cert.KeyMaterial).Q);
      l[2] := WriteInteger(TElDSAKeyMaterial(Cert.KeyMaterial).G);
      Params := WriteArraySequence(l);
      ReleaseArrays(l[0], l[1], l[2]);
    end
    else if SigAlg = SB_CERT_ALGORITHM_ID_RSAPSS then
      Params := TElRSAKeyMaterial.WritePSSParams(TElRSAKeyMaterial(Cert.KeyMaterial).HashAlgorithm,
        TElRSAKeyMaterial(Cert.KeyMaterial).SaltSize,
        TElRSAKeyMaterial(Cert.KeyMaterial).MGFAlgorithm,
        TElRSAKeyMaterial(Cert.KeyMaterial).TrailerField)
    else
      Params := EmptyArray;
    SaveAlgorithmIdentifier(AlgID, GetOIDByAlgorithm(SigAlg), Params);
    SigData := CalculateSignature(TBS, SigAlg, Cert);

    SigData := SBConcatArrays(byte(0), SigData);

    SigValue := TElASN1SimpleTag(Sig.GetField(Sig.AddField(false)));
    SigValue.TagId := SB_ASN1_BITSTRING;
    SigValue.Content := SigData;
    if IncludeCertificates then
    begin
      Certs := TElASN1ConstrainedTag(Sig.GetField(Sig.AddField(true)));
      Certs.TagId := SB_ASN1_A0;
      Certs := TElASN1ConstrainedTag(Certs.GetField(Certs.AddField(true)));
      Certs.TagId := SB_ASN1_SEQUENCE;
      for I := 0 to SigningCertStorage.Count - 1 do
      begin
        Cert := SigningCertStorage.Certificates[I];
        CertValue := TElASN1SimpleTag(Certs.GetField(Certs.AddField(false)));
        CertValue.WriteHeader := false;
        Size := 0;
        Cert.SaveToBuffer( nil , Size);
        SetLength(CertData, Size);
        Cert.SaveToBuffer(@CertData[0], Size);
        SetLength(CertData, Size);
        CertValue.Content := CloneArray(CertData);
      end;
    end;
    SizeInt := 0;
    SigMain.SaveToBuffer( nil , SizeInt);
    SetLength(Result, SizeInt);
    SigMain.SaveToBuffer(@Result[0], SizeInt);
    SetLength(Result, SizeInt);
  finally
    FreeAndNil(SigMain);
  end;
end;

function TElOCSPClient.CalculateSignature(const r : ByteArray; SigAlg : integer;
  Cert : TElX509Certificate) : ByteArray;
var
  Crypto : TElPublicKeyCrypto;
  Factory : TElPublicKeyCryptoFactory;
  size : integer;
begin
  SetLength(Result,0);
  Factory := TElPublicKeyCryptoFactory.Create();
  try
    Crypto := Factory.CreateInstance(SigAlg);
  finally
    FreeAndNil(Factory);
  end;
  if Crypto = nil then
    exit;
  try
    Crypto.InputIsHash := false;
    Size := 0;
    if Crypto is TElRSAPublicKeyCrypto then
    begin
      TElRSAPublicKeyCrypto(Crypto).KeyMaterial := TElRSAKeymaterial(Cert.KeyMaterial);
      TElRSAPublicKeyCrypto(Crypto).UseAlgorithmPrefix := true;
    end
    else if Crypto is TElDSAPublicKeyCrypto then
      TElDSAPublicKeyCrypto(Crypto).KeyMaterial := TElDSAKeymaterial(Cert.KeyMaterial)
    else if Crypto is TElDHPublicKeyCrypto then
      TElDHPublicKeyCrypto(Crypto).KeyMaterial := TElDHKeymaterial(Cert.KeyMaterial)
    {$ifdef SB_HAS_ECC}
    else if Crypto is TElECDSAPublicKeyCrypto then
      TElECDSAPublicKeyCrypto(Crypto).KeyMaterial := TElECKeymaterial(Cert.KeyMaterial)        
     {$endif}
    {$ifndef SB_NO_SRP}
    else if Crypto is TElSRPPublicKeyCrypto then
      TElSRPPublicKeyCrypto(Crypto).KeyMaterial := TElSRPKeymaterial(Cert.KeyMaterial)
     {$endif}
    else if Crypto is TElElGamalPublicKeyCrypto then
      TElElGamalPublicKeyCrypto(Crypto).KeyMaterial := TElElGamalKeymaterial(Cert.KeyMaterial)
    else
      Crypto.KeyMaterial := TElPublicKeyMaterial(Cert.KeyMaterial);

    Crypto.SignDetached(@R[0], Length(r), @Result[0], size);
    SetLength(result, Size);
    Crypto.SignDetached(@R[0], Length(r), @Result[0], size);
    SetLength(Result, Size);
  finally
    FreeAndNil(Crypto);
  end;
end;

procedure TElOCSPClient.SetCertStorage(Value : TElCustomCertStorage);
begin
  FCertStorage := Value;
  if FCertStorage <> nil then
    FCertStorage.FreeNotification(Self);
end;

procedure TElOCSPClient.SetIssuerCertStorage(Value : TElCustomCertStorage);
begin
  FIssuerCertStorage := Value;
  if FIssuerCertStorage <> nil then
    FIssuerCertStorage.FreeNotification(Self);
end;

procedure TElOCSPClient.SetReplyNonce(const V: ByteArray);
begin
  FReplyNonce := CloneArray(V);
end;

procedure TElOCSPClient.SetServerCertKeyHash(const V : ByteArray);
begin
  FServerCertKeyHash := CloneArray(V);
end;

function TElOCSPClient.GetCertStatus(Index: Integer): TElOCSPCertificateStatus;
begin
  if (index < 0) or (index >= Length(FCertStatus)) then
    result := csUnknown
  else
    result := FCertStatus[index];
end;

function TElOCSPClient.GetThisUpdate(Index: Integer):  TDateTime ;
begin
  if (index < 0) or (index >= Length(FThisUpdate)) then
    result :=  0 
  else
    result := FThisUpdate[index];
end;

function TElOCSPClient.GetNextUpdate(Index: Integer):  TDateTime ;
begin
  if (index < 0) or (index >= Length(FNextUpdate)) then
    result :=  0 
  else
    result := FNextUpdate[index];
end;

procedure TElOCSPClient.Notification(AComponent : TComponent; AOperation :
  TOperation);
begin
  inherited;
  if (AComponent = FCertStorage) and (AOperation = opRemove) then
    CertStorage := nil;
  if (AComponent = FIssuerCertStorage) and (AOperation = opRemove) then
    IssuerCertStorage := nil;
end;

function TElOCSPClient.GetRevocationTime(Index: Integer):  TDateTime ;
begin
  if (index < 0) or (index >= Length(FRevocationTime)) then
    result :=  0 
  else
    result := FRevocationTime[index];
end;

function TElOCSPClient.GetRevocationReason(Index: Integer): TSBCRLReasonFlag;
begin
  if GetCertStatus(Index) = csRevoked then
    result := FRevocationReason[index]
  else
    result := rfUnspecified;
end;

function TElOCSPClient.ParseResponseData(const Data: ByteArray; Certificates:
    TElCustomCertStorage; var SignCert: TElX509Certificate): Boolean;
var
  ASN   : TElASN1ConstrainedTag;

  Sequence,
  SeqLev1,
  SeqLev2,
  SeqResp,
  Field,
  Response: TElASN1ConstrainedTag;
  Param: TElASN1SimpleTag;
  Custom: TElASN1CustomTag;
  i, ir, ic : integer;
  Lookup : TElCertificateLookup;
  CurrTagIndex, CurrInnerTagIndex : integer;
  ExtOID, ExtContent : ByteArray;
  Hash_OID:ByteArray;
begin
  Result := false;

  ASN := TElASN1ConstrainedTag.CreateInstance;
  try
    try
      if not ASN.LoadFromBuffer( @Data[0], Length(Data) ) then
        exit;
    except
      exit;
    end;

    if ASN.Count = 0 then
      exit;

    // access sequence tag
    Sequence := TElASN1ConstrainedTag(ASN.GetField(0));
    if Sequence.Count < 1 then
      exit;

    CurrTagIndex := 0;
    if Sequence.GetField(CurrTagIndex).CheckType(SB_ASN1_A0, true) then
    begin
      // version
      SeqLev1 := TElASN1ConstrainedTag(Sequence.GetField(CurrTagIndex));
      if not ((SeqLev1.Count = 1) and (SeqLev1.GetField(0).CheckType(SB_ASN1_INTEGER, false)) and
        (asn1ReadInteger(TElASN1SimpleTag(SeqLev1.GetField(0))) = 0)) then
        Exit;
      Inc(CurrTagIndex);
    end;

    // responder id
    if (Sequence.Count <= CurrTagIndex) then
      Exit;
    SeqLev1 := TElASN1ConstrainedTag(Sequence.GetField(CurrTagIndex));
    if SeqLev1.Count < 1 then
      exit;
    Custom := SeqLev1.GetField(0);
    if Custom.IsConstrained then
    begin
      FServerCertKeyHash := EmptyArray;

      // we've got name
      Field := TElASN1ConstrainedTag(Custom);
      if (Field = nil) or (not Field.IsConstrained) then
        exit;
      FServerName.LoadFromTag(Field);
      Lookup := TElCertificateLookup.Create(nil);
      try
        //Lookup.Options := {$ifdef SB_VCL}[loMatchAll]{$else}loMatchAll{$endif};
        Lookup.SubjectRDN.Assign(FServerName);
        Lookup.Criteria :=  [lcSubject] ;
        Lookup.Options :=  [loExactMatch, loMatchAll] ;

        i := Certificates.FindFirst(Lookup);
        if i <> -1 then
          SignCert := Certificates.Certificates[i]
        else
        begin
          i := IssuerCertStorage.FindFirst(Lookup);
          if i <> -1 then
            SignCert := IssuerCertStorage.Certificates[i];
        end;

      finally
        FreeAndNil(Lookup);
      end;
    end
    else
    begin
      Param := TElASN1SimpleTag(Custom);
      FServerCertKeyHash := CloneArray(Param.Content);
      Lookup := TElCertificateLookup.Create(nil);
      try
        Lookup.PublicKeyHash := FServerCertKeyHash;
        Lookup.PublicKeyHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
        Lookup.Criteria :=  [lcPublicKeyHash] ;
        Lookup.Options :=  [loExactMatch, loMatchAll] ;

        i := Certificates.FindFirst(Lookup);
        if i <> -1 then
          SignCert := Certificates.Certificates[i]
        else
        begin
          i := IssuerCertStorage.FindFirst(Lookup);
          if i <> -1 then
            SignCert := IssuerCertStorage.Certificates[i];
        end;
      finally
        FreeAndNil(Lookup);
      end;
    end;
    Inc(CurrTagIndex);

    // produced at
    if (Sequence.Count <= CurrTagIndex) or (not Sequence.GetField(CurrTagIndex).CheckType(SB_ASN1_GENERALIZEDTIME, false)) then
      Exit;
    Param := TElASN1SimpleTag(Sequence.GetField(CurrTagIndex));
    FReplyProducedAt := GeneralizedTimeToDateTime(StringOfBytes(Param.Content));
    Inc(CurrTagIndex);

    // responses
    if (Sequence.Count <= CurrTagIndex) or (not Sequence.GetField(CurrTagIndex).CheckType(SB_ASN1_SEQUENCE, true)) then
      Exit;
    SeqResp := TElASN1ConstrainedTag(Sequence.GetField(CurrTagIndex));
    (*
    if ((FCertStorage = nil) and (SeqResp.Count > 0)) or
       (SeqResp.Count > FCertStorage.Count) then
      Exit;
    *)

    for i := 0 to FCertStorage.Count - 1 do
    begin
      FCertStatus[i] := csUnknown;
    end;

    for ir := 0 to SeqResp.Count -1 do
    begin

      Response := TElASN1ConstrainedTag(SeqResp.GetField(ir));
      if (Response = nil) or (not Response.IsConstrained) then
      exit;

      if Response.Count < 3 then
        exit;

      // check CertID
      SeqLev1 := TElASN1ConstrainedTag(Response.GetField(0));
      if (SeqLev1 = nil) or (not SeqLev1.IsConstrained) or (SeqLev1.Count < 4) then
        exit;

      SeqLev2 := TElASN1ConstrainedTag(SeqLev1.GetField(0));
      if (SeqLev2 = nil) or (not SeqLev2.IsConstrained) or (SeqLev2.Count < 1) then
        exit;

      // check algorithm identifier
      Param := TElASN1SimpleTag(SeqLev2.GetField(0));
      Hash_OID := Param.Content;

      // now find the certificate, for which the data is provided

      ic := -1;
      for i := 0 to FCertStorage.Count - 1 do
      begin
        // check serial number
        Param := TElASN1SimpleTag(SeqLev1.GetField(3));
        (*
        {$ifndef SB_VCL}
        if CompareMem(ByteArray(Param.Content),
          FCertStorage.Certificates[i].SerialNumber ) then
        {$else}
        if Param.Content = FCertStorage.Certificates[i].SerialNumber then
        {$endif}
        *)
        if SerialNumberCorresponds(FCertStorage.Certificates[i], Param.Content) then
        begin
          // check name hash
          Param := TElASN1SimpleTag(SeqLev1.GetField(1));
          if CompareMem(ByteArray(Param.Content), issuerNameHash(FCertStorage.Certificates[i], Hash_OID)) then
          begin
            ic := i;
            break;
          end;
        end;
      end;

      if ic = -1 then
        continue;

      FThisUpdate[ic] := 0;
      FNextUpdate[ic] := 0;
      FRevocationTime[ic] := 0;
      FRevocationReason[ic] := TSBCRLReasonFlag(0);
      FCertStatus[ic] := TElOCSPCertificateStatus(0);

      // obtain certificate status
      Custom := Response.GetField(1);

      case Custom.TagId of
        $80:
          FCertStatus[ic] := csGood;
        $81, $A1:
          begin
            FCertStatus[ic] := csRevoked;
            if Custom.IsConstrained then
            begin
              Field := TElASN1ConstrainedTag(Custom);

              // obtain revocation time
              Param := TElASN1SimpleTag(Field.GetField(0));
              if (Param <> nil) and (Param.TagId = SB_ASN1_GENERALIZEDTIME) then
                FRevocationTime[ic] := GeneralizedTimeToDateTime(StringOfBytes(Param.Content));

              if Field.Count >= 2 then
              begin
                // obtain revocation reason
                if (Field.GetField(1).CheckType(SB_ASN1_A0, true)) and (TElASN1ConstrainedTag(Field.GetField(1)).Count = 1) and
                  (TElASN1ConstrainedTag(Field.GetField(1)).GetField(0).CheckType(SB_ASN1_ENUMERATED, false)) then
                begin
                  Param := TElASN1SimpleTag(TElASN1ConstrainedTag(Field.GetField(1)).GetField(0));
                  if (Param <> nil) and (Length(Param.Content) > 0) then
                    FRevocationReason[ic] := EnumToReasonFlag(asn1ReadInteger(Param));
                end;
              end;
            end;
          end;
        $82,
        $A2:
          FCertStatus[ic] := csUnknown;
      end;

      // obtain thisUpdate
      Param := TElASN1SimpleTag(Response.GetField(2));
      if (Param = nil) or (Param.TagId <> SB_ASN1_GENERALIZEDTIME) then
        exit;
      FThisUpdate[ic] := GeneralizedTimeToDateTime(StringOfBytes(Param.Content));

      if Response.Count > 3 then
      begin
        // obtain nextUpdate
        Custom := Response.GetField(3);
        if (Custom.CheckType(SB_ASN1_A0, true)) and (TElASN1ConstrainedTag(Custom).Count = 1) then
        begin
          Custom := TElASN1ConstrainedTag(Custom).GetField(0);
          if (Custom.CheckType(SB_ASN1_GENERALIZEDTIME, false)) then
          begin
            Param := TElASN1SimpleTag(Custom);
            FNextUpdate[ic] := GeneralizedTimeToDateTime(StringOfBytes(Param.Content));
          end;
        end;
      end;
    end;
    Inc(CurrTagIndex);

    // extensions
    if (Sequence.Count > CurrTagIndex) and Sequence.GetField(CurrTagIndex).CheckType(SB_ASN1_A1, true) then
    begin
      SeqLev1 := TElASN1ConstrainedTag(Sequence.GetField(CurrTagIndex));
      if (SeqLev1.Count <> 1) or (not SeqLev1.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
        Exit;
      SeqLev1 := TElASN1ConstrainedTag(SeqLev1.GetField(0));
      for I := 0 to SeqLev1.Count - 1 do
      begin
        if SeqLev1.GetField(I).CheckType(SB_ASN1_SEQUENCE, true) then
        begin
          SeqLev2 := TElASN1ConstrainedTag(SeqLev1.GetField(I));
          CurrInnerTagIndex := 0;
          // OID
          if (SeqLev2.Count > CurrInnerTagIndex) and (SeqLev2.GetField(CurrInnerTagIndex).CheckType(SB_ASN1_OBJECT, false)) then
          begin
            ExtOID := TElASN1SimpleTag(SeqLev2.GetField(CurrInnerTagIndex)).Content;
            Inc(CurrInnerTagIndex);
          end;
          // Critical
          if (SeqLev2.Count > CurrInnerTagIndex) and (SeqLev2.GetField(CurrInnerTagIndex).CheckType(SB_ASN1_BOOLEAN, false)) then
            Inc(CurrInnerTagIndex);
          // Value
          if (SeqLev2.Count > CurrInnerTagIndex) and (SeqLev2.GetField(CurrInnerTagIndex).CheckType(SB_ASN1_OCTETSTRING, false)) then
            ExtContent := TElASN1SimpleTag(SeqLev2.GetField(CurrInnerTagIndex)).Content;
          if CompareContent(ExtOID, SB_OCSP_OID_NONCE) then
            FReplyNonce := CloneArray(ExtContent);
        end;
      end;
    end;
  finally
    FreeAndNil(ASN);
  end;
  result := true;
end;

function TElOCSPClient.PerformRequest(var ServerResult : TElOCSPServerError; var Reply : ByteArray) : Integer;
begin
  SetLength(Reply, 0);
  result := 0;
end;

function TElOCSPClient.ValidateResponseSignature(const ReplyBuf, SignatureAlg, SignatureParam,
  SignatureBody: ByteArray; SignCertificate: TElX509Certificate): Boolean;
var
  Crypto : TElPublicKeyCrypto;
  Factory : TElPublicKeyCryptoFactory;
  Tag : TElASN1ConstrainedTag;
  HAlg, SaltSize, MGF, MGFHAlg, TrField, Size : TSBInteger;
  P, Q, G, Y: ByteArray;
  SigAlg : integer;
begin
  result := false;
  

  if SignCertificate = nil then
    if Assigned(FOnCertificateNeeded) then
      FOnCertificateNeeded(Self, SignCertificate);

  if SignCertificate = nil then
    exit;

  Factory := TElPublicKeyCryptoFactory.Create();
  try
    Crypto := Factory.CreateInstance(SignatureAlg);
  finally
    FreeAndNil(Factory);
  end;
  if Crypto = nil then
    exit;
  try
    Crypto.InputIsHash := false;
    Crypto.HashAlgorithm := GetHashAlgorithmByOID(SignatureAlg);
    SigAlg := GetAlgorithmByOID(SignatureAlg);
    if Crypto.HashAlgorithm = SB_ALGORITHM_UNKNOWN then
      Crypto.HashAlgorithm := GetHashAlgorithmBySigAlgorithm(SigAlg);
    SigAlg := GetAlgorithmByOID(SignatureAlg);
    if Crypto is TElRSAPublicKeyCrypto then
    begin
      TElRSAPublicKeyCrypto(Crypto).KeyMaterial := TElRSAKeyMaterial(SignCertificate.KeyMaterial);
      TElRSAPublicKeyCrypto(Crypto).UseAlgorithmPrefix := true;
      if SigAlg = SB_CERT_ALGORITHM_ID_RSAPSS then
      begin
        if not TElRSAKeyMaterial.ReadPSSParams( @SignatureParam[0] ,
          Length(SignatureParam), HAlg, SaltSize, MGF, MGFHAlg, TrField) then
          exit;
        TElRSAKeyMaterial(TElRSAPublicKeyCrypto(Crypto).KeyMaterial).SaltSize := SaltSize;
        TElRSAKeyMaterial(TElRSAPublicKeyCrypto(Crypto).KeyMaterial).HashAlgorithm := HAlg;
        TElRSAKeyMaterial(TElRSAPublicKeyCrypto(Crypto).KeyMaterial).TrailerField := TrField;
        TElRSAKeyMaterial(TElRSAPublicKeyCrypto(Crypto).KeyMaterial).MGFAlgorithm := MGFHAlg;
      end;
    end
    else if Crypto is TElDSAPublicKeyCrypto then
    begin
      TElDSAPublicKeyCrypto(Crypto).KeyMaterial := TElDSAKeyMaterial(SignCertificate.KeyMaterial);
      Tag := TElASN1ConstrainedTag.CreateInstance;
      try
        if (not Tag.LoadFromBuffer( @SignatureParam[0], Length(SignatureParam) )) or
          (not Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) or
          (TElASN1ConstrainedTag(Tag.GetField(0)).Count <> 3) or
          (not TElASN1ConstrainedTag(Tag.GetField(0)).GetField(0).CheckType(SB_ASN1_INTEGER, false)) or
          (not TElASN1ConstrainedTag(Tag.GetField(0)).GetField(1).CheckType(SB_ASN1_INTEGER, false)) or
          (not TElASN1ConstrainedTag(Tag.GetField(0)).GetField(2).CheckType(SB_ASN1_INTEGER, false)) then
          exit;
        P := ReadAsnInteger(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(0)).Content);
        Q := ReadAsnInteger(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(1)).Content);
        G := ReadAsnInteger(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(2)).Content);
        Size := 0;
        SignCertificate.KeyMaterial.SavePublic( @Y[0] , Size);
        SetLength(Y,Size);
        SignCertificate.KeyMaterial.SavePublic( @Y[0] , Size);
        Tag.Clear;
        if (not Tag.LoadFromBuffer( @Y[0], Length(Y) )) or
          (not Tag.GetField(0).CheckType(SB_ASN1_INTEGER, false)) then
          exit;
        Y := ReadAsnInteger(TElASN1SimpleTag(Tag.GetField(0)).Content);
        try
          TElDSAKeyMaterial(TElDSAPublicKeyCrypto(Crypto).KeyMaterial).ImportPublicKey(@P[0],
            Length(P), @Q[0], Length(Q), @G[0], Length(G), @Y[0], Length(Y));
        except
          exit;
        end;
      finally
        ReleaseArray(P);
        ReleaseArray(Q);
        ReleaseArray(G);
        ReleaseArray(Y);
        FreeAndNil(Tag);
      end;
    end
    else if Crypto is TElDHPublicKeyCrypto then
      TElDHPublicKeyCrypto(Crypto).KeyMaterial := TElDHKeyMaterial(SignCertificate.KeyMaterial)
    {$ifdef SB_HAS_ECC}
    else if Crypto is TElECDSAPublicKeyCrypto then
      TElECDSAPublicKeyCrypto(Crypto).KeyMaterial := TElECKeyMaterial(SignCertificate.KeyMaterial)
     {$endif}
    {$ifndef SB_NO_SRP}
    else if Crypto is TElSRPPublicKeyCrypto then
      TElSRPPublicKeyCrypto(Crypto).KeyMaterial := TElSRPKeyMaterial(SignCertificate.KeyMaterial)
     {$endif}
    else if Crypto is TElElGamalPublicKeyCrypto then
      TElElGamalPublicKeyCrypto(Crypto).KeyMaterial := TElElGamalKeyMaterial(SignCertificate.KeyMaterial)
    else
      Crypto.KeyMaterial := TElPublicKeyMaterial(SignCertificate.KeyMaterial);

    Result :=(Crypto.VerifyDetached(@ReplyBuf[0], Length(ReplyBuf), @SignatureBody[0], Length(SignatureBody)) = pkvrSuccess);
  finally
    FreeAndNil(Crypto);
  end;
end;

function TElOCSPClient.WriteRequestList (var List: ByteArray) : integer;
var
  requestList: array of ByteArray;
  request: array of ByteArray;
  idx,
  i: integer;
  b: ByteArray;
  IssuerCert  : TElX509Certificate;
  Lookup      : TElCertificateLookup;
  //Alg : integer;
  Hash_Oid: ByteArray;
begin
   result := 0;

  SetLength(Request, 0);
  SetLength(requestList, FCertStorage.Count);

  Lookup := TElCertificateLookup.Create(nil);
  try

    Lookup.Criteria :=  [lcSubject] ;
    Lookup.Options :=  [loExactMatch, loMatchAll] ;

    for i := 0 to FCertStorage.Count -1 do
    begin
      //Alg := FCertStorage.Certificates[i].SignatureAlgorithm;
      //Hash_Oid := GetOIDByAlgorithm(GetHashAlgorithmBySigAlgorithm(Alg));
      Hash_Oid := SB_OID_SHA1;
      SetLength(request, 4);
      request[0] := WriteHashAlgorithm(Hash_Oid);
      request[1] := WriteOctetString(issuerNameHash(FCertStorage.Certificates[i],Hash_Oid));
  
      Lookup.SubjectRDN.Assign(FCertStorage.Certificates[i].IssuerRDN);

      idx := FIssuerCertStorage.FindFirst(Lookup);
      if Idx = -1 then
      begin
        result := SB_OCSP_ERROR_NO_ISSUER_CERTIFICATES;
        exit;
      end;

      IssuerCert := FIssuerCertStorage.Certificates[idx];

      request[2] := WriteOctetString(publicKeyHash(IssuerCert));
      if Length(FCertStorage.Certificates[i].SerialNumber) > 0 then
        request[3] := FCertStorage.Certificates[i].WriteSerialNumber;
  
      b := WriteArraySequence(request);

      SetLength(request, 1);
      request[0] := b;
      requestList[i] := WriteArraySequence(request);
    end;
  finally
    FreeAndNil(Lookup);
  end;
  List := WriteArraySequence(requestList);
end;

function TElOCSPClient.WriteRequestorName: ByteArray;
var Tag : TElASN1SimpleTag;
    Size: integer;
begin
  Tag := TElASN1SimpleTag.CreateInstance;
  try
    FRequestorName.SaveToTag(Tag);
    Size := 0;
    SetLength(Result, Size);
    Tag.SaveToBuffer(nil, Size);
    SetLength(Result, Size);
    Tag.SaveToBuffer(@Result[0], Size);
    if Length(Result) <> Size then
      SetLength(Result, Size);
  finally
    FreeAndNil(Tag);
  end;
  result := WritePrimitive($A1, Result);
end;

function TElOCSPClient.WriteExtensions : ByteArray;
var
  Lst : array of ByteArray;
  Cnt : integer;
  Ext, V : ByteArray;
begin
  SetLength(Lst, 0);
  try
    // nonce
    if Length(FNonce) > 0 then
    begin
      Ext := WriteExtension(SB_OCSP_OID_NONCE, FNonce, SB_ASN1_OCTETSTRING);
      SetLength(Lst, 1);
      Lst[0] := Ext;
    end;
    // supported response types
    if ocoIncludeSupportedResponseTypes in FOptions then
    begin
      // a single basic-response at the moment
      V := WritePrimitive(SB_ASN1_SEQUENCE, WriteOID(SB_OCSP_OID_BASIC_RESPONSE));
      Ext := WriteExtension(SB_OCSP_OID_OCSP_RESPONSE, V, 0);
      Cnt := Length(Lst);
      SetLength(Lst, Cnt + 1);
      Lst[Cnt] := Ext;
    end;
    if Length(Lst) > 0 then
      Result := WriteArraySequence(Lst)
    else
      Result := EmptyArray;
  finally
    Lst := nil;
  end;
end;

function TElFileOCSPClient.SupportsLocation(const URI: string): Boolean;
begin
  result := false;
end;

function TElFileOCSPClient.PerformRequest(var ServerResult : TElOCSPServerError; var Reply : ByteArray) : Integer;
var
  RequestStream,
  ReplyStream :   TMemoryStream  ;
  Request :  ByteArray ;
  Success : TSBBoolean;
begin
  if not Assigned(FOnOCSPValidationNeeded) then
  begin
    result := SB_OCSP_ERROR_NO_PARAMETERS;
    exit;
  end;

  RequestStream :=   TMemoryStream  .Create;
  ReplyStream :=   TMemoryStream  .Create;
  try
    CreateRequest(Request);

    RequestStream.Write(Request[0], Length(Request));
    RequestStream.Position := 0;

    Success := true;
    FOnOCSPValidationNeeded(Self, URL, RequestStream, ReplyStream, Success);
    if not Success then
    begin
      result := SB_OCSP_ERROR_NO_REPLY;
      exit;
    end;

    SetLength(Reply, ReplyStream. Size );
    if Length(Reply) = 0 then
    begin
      result := SB_OCSP_ERROR_WRONG_DATA;
      exit;
    end;

    ReplyStream.Position := 0;

    ReplyStream.Read(Reply[0], Length(Reply));

    result := ProcessReply(Reply, ServerResult);

  finally
    FreeAndNil(RequestStream);
    FreeAndNil(ReplyStream);
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// TElOCSPResponderID class

constructor TElOCSPResponderID.Create;
begin
  inherited;
  FName := TElRelativeDistinguishedName.Create;
end;

 destructor  TElOCSPResponderID.Destroy;
begin
  FreeAndNil(FName);
  inherited;
end;

procedure TElOCSPResponderID.SetSHA1KeyHash(const V : ByteArray);
begin
  FSHA1KeyHash := CloneArray(V);
end;

procedure TElOCSPResponderID.Clear;
begin
  FSHA1KeyHash := EmptyArray;
  FName.Clear;
end;

procedure GetOCSPCertID(Cert, Issuer : TElX509Certificate; DigestAlg : integer;
  var IssuerNameHash : ByteArray; var IssuerKeyHash : ByteArray);  overload; 
var
  HashFunc : TElHashFunction;
  Tag : TElASN1ConstrainedTag;
  Size : integer;
  NameData, KeyData : ByteArray;
begin
  // obtaining issuer name
  Tag := TElASN1ConstrainedTag.CreateInstance();
  try
    Cert.IssuerRDN.SaveToTag(Tag);
    Size := 0;
    Tag.SaveToBuffer( nil , Size);
    SetLength(NameData, Size);
    Tag.SaveToBuffer( @NameData[0] , Size);
    SetLength(NameData, Size);
  finally
    FreeAndNil(Tag);
  end;
  // obtaining issuer key data
  if Issuer <> nil then
  begin
    Size := 0;
    Issuer.GetPublicKeyBlob( nil , Size);
    SetLength(KeyData, Size);
    Issuer.GetPublicKeyBlob( @KeyData[0] , Size);
    SetLength(KeyData, Size);
  end
  else
    SetLength(KeyData, 0);

  HashFunc := TElHashFunction.Create(DigestAlg);
  try
    HashFunc.Update( @NameData[0] , Length(NameData));
    IssuerNameHash := HashFunc.Finish();
    HashFunc.Reset;
    if Length(KeyData) > 0 then
    begin
      HashFunc.Update( @KeyData[0] , Length(KeyData));
      IssuerKeyHash := HashFunc.Finish();
    end
    else
      IssuerKeyHash := EmptyArray;
  finally
    FreeAndNil(HashFunc);
  end;
end;

procedure GetOCSPCertID(Signer : TElPKCS7Issuer; Issuer : TElX509Certificate; DigestAlg : integer;
  var IssuerNameHash : ByteArray; var IssuerKeyHash : ByteArray);  overload; 
var
  HashFunc : TElHashFunction;
  Tag : TElASN1ConstrainedTag;
  Size : integer;
  NameData, KeyData : ByteArray;
begin
  // obtaining issuer name
  Tag := TElASN1ConstrainedTag.CreateInstance();
  try
    Signer.Issuer.SaveToTag(Tag);
    Size := 0;
    Tag.SaveToBuffer( nil , Size);
    SetLength(NameData, Size);
    Tag.SaveToBuffer( @NameData[0] , Size);
    SetLength(NameData, Size);
  finally
    FreeAndNil(Tag);
  end;
  // obtaining issuer key data
  if Issuer <> nil then
  begin
    Size := 0;
    Issuer.GetPublicKeyBlob( nil , Size);
    SetLength(KeyData, Size);
    Issuer.GetPublicKeyBlob( @KeyData[0] , Size);
    SetLength(KeyData, Size);
  end
  else
    SetLength(KeyData, 0);

  HashFunc := TElHashFunction.Create(DigestAlg);
  try
    HashFunc.Update( @NameData[0] , Length(NameData));
    IssuerNameHash := HashFunc.Finish();
    HashFunc.Reset;
    if Length(KeyData) > 0 then
    begin
      HashFunc.Update( @KeyData[0] , Length(KeyData));
      IssuerKeyHash := HashFunc.Finish();
    end
    else
      IssuerKeyHash := EmptyArray;
  finally
    FreeAndNil(HashFunc);
  end;
end;


////////////////////////////////////////////////////////////////////////////////
// TElOCSPResponse class

constructor TElOCSPResponse.Create;
begin
  inherited;
  FCertificates := TElMemoryCertStorage.Create(nil);
  FResponderID := TElOCSPResponderID.Create();
  FResponses := TElList.Create;
end;

 destructor  TElOCSPResponse.Destroy;
begin
  Clear;
  FreeAndNil(FCertificates);
  FreeAndNil(FResponderID);
  FreeAndNil(FResponses);
  inherited;
end;

procedure TElOCSPResponse.Clear;
var
  I : integer;
begin
  for I := 0 to FResponses.Count - 1 do
    TElOCSPSingleResponse(FResponses[I]). Free ;
  FResponses.Clear;
  FCertificates.Clear;
  FSignatureAlgorithm := SB_ALGORITHM_UNKNOWN;
  FResponderID.Clear;
  FProducedAt := (0);
  FTBS := EmptyArray;
  FSig := EmptyArray;
  FSigAlg := SB_ALGORITHM_UNKNOWN;
end;

function TElOCSPResponse.IsSignerCertificate(Certificate :  TElX509Certificate) : boolean;
var
  Size : integer;
  Buf : ByteArray;
  M160 : TMessageDigest160;
  Hash : ByteArray;
begin
  result := false;
  if Length(FResponderID.FSHA1KeyHash) = 20 then
  begin
    Size := 0;
    Certificate.GetPublicKeyBlob( nil , Size);
    SetLength(Buf, Size);
    Certificate.GetPublicKeyBlob( @Buf[0] , Size);
    SetLength(Buf, Size);
    M160 := HashSHA1( @Buf[0] , Size);
    Hash := FResponderID.FSHA1KeyHash;
    if CompareMem(@M160, @Hash[0], Length(Hash)) then
    begin
      result := true;
    end;
  end
  else
  if CompareRDN(FResponderID.Name, Certificate.SubjectRDN) then
  begin
    result := true;
  end;
end;

function TElOCSPResponse.GetSignerCertificate : TElX509Certificate;
var
  Cert : TElX509Certificate;
  I : integer;
  Lookup : TElCertificateLookup;
begin
  result := nil;
  for I := 0 to FCertificates.Count - 1 do
  begin
    Cert := FCertificates.Certificates[i];
    if IsSignerCertificate(Cert) then
    begin
      result := Cert;
      break;
    end;
  end;
  if (Result = nil) and Assigned(FOnCertificateNeeded) then
  begin
    Lookup := TElCertificateLookup.Create(nil);
    try
      Lookup.Criteria :=  [] ;
      Lookup.Options :=  [loMatchAll] ;
      if Length(FResponderID.FSHA1KeyHash) > 0 then
      begin
        Lookup.Criteria := Lookup.Criteria + [lcPublicKeyHash];
        Lookup.PublicKeyHash := FResponderID.FSHA1KeyHash;
        Lookup.PublicKeyHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
      end;
      if (FResponderID.Name.Count > 0) then
      begin
        Lookup.Criteria := Lookup.Criteria + [lcSubject];
        Lookup.SubjectRDN.Assign(FResponderID.Name);
      end;
      FOnCertificateNeeded(Self, Lookup, Result);
    finally
      FreeAndNil(Lookup);
    end;
  end;
end;

function TElOCSPResponse.Validate() : TSBCMSSignatureValidity;
begin
  Result := Validate(nil);
end;

function TElOCSPResponse.Validate(CACertificate : TElX509Certificate) : TSBCMSSignatureValidity;
var
  Cert : TElX509Certificate;
  Fac : TElPublicKeyCryptoFactory;
  Crypto : TElPublicKeyCrypto;
  VR : TSBPublicKeyVerificationResult;
begin
  Result := csvGeneralFailure;
  Cert := nil;
  if (CACertificate <> nil) and IsSignerCertificate(CACertificate) then
    Cert := CACertificate;

  if Cert = nil then
    Cert := GetSignerCertificate;

  if Cert <> nil then
  begin
    Fac := TElPublicKeyCryptoFactory.Create();
    try
      Crypto := Fac.CreateInstance(FSigAlgOID);
      if Crypto <> nil then
        try
          Crypto.KeyMaterial := Cert.KeyMaterial;
          Crypto.InputIsHash := false;
          Crypto.HashAlgorithm := GetHashAlgorithmBySigAlgorithm(FSigAlg);
          if Crypto is TElRSAPublicKeyCrypto then
            TElRSAPublicKeyCrypto(Crypto).UseAlgorithmPrefix := true;
          VR := Crypto.VerifyDetached(@FTBS[0], Length(FTBS), @FSig[0], Length(FSig));
          case VR of
            pkvrSuccess : Result := csvValid;
            pkvrInvalidSignature : Result := csvInvalid;
            pkvrKeyNotFound : Result := csvSignerNotFound;
            pkvrFailure : Result := csvGeneralFailure;
          end;
        finally
          FreeAndNil(Crypto);
        end;
    finally                
      FreeAndNil(Fac);
    end;
  end
  else
    Result := csvSignerNotFound
end;

procedure TElOCSPResponse.Load(Buffer: pointer; Size: integer);
var
  Tag, Seq, SubSeq, SubSubSeq : TElASN1ConstrainedTag;
  Param : TElASN1SimpleTag;
  Sz : integer;
  CurrIndex : integer;
  I : integer;
  Resp : TElOCSPSingleResponse;
  //RespStatus : TElOCSPServerError;
  Alg, AlgParams : ByteArray;
  Buf, ReplyBuf : ByteArray;
  Cert : TElX509Certificate;
  OcspLen : integer;
begin
  Clear;
  SetLength(FData, Size);
  SBMove(Buffer^, FData[0], Length(FData));
  Tag := TElASN1ConstrainedTag.CreateInstance();
  try
    // II20120110: LoadFromBuffer replaced with LoadFromBufferSingle to be
    // tolerant to trash after the end-of-data
    //if not Tag.LoadFromBuffer(Buffer, {$ifndef SB_VCL}StartIndex, {$endif}Size) then
    //  raise EElOCSPError.Create(SInvalidOCSPResponse);
    OcspLen := Tag.LoadFromBufferSingle(Buffer, Size);
    if OcspLen = -1 then
      raise EElOCSPError.Create(SInvalidOCSPResponse);
    SetLength(FData, OcspLen);
    if (Tag.Count <> 1) or (not Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      raise EElOCSPError.Create(SInvalidOCSPResponse);
    Seq := TElASN1ConstrainedTag(Tag.GetField(0));
    // reading Basic OCSP response
    if Seq.Count = 2 then
    begin
      // access response status
      Param := TElASN1SimpleTag(Seq.GetField(0));
      if (Param = nil) or (Length(Param.Content) = 0) then
        raise EElOCSPError.Create(SInvalidOCSPResponse);
      //RespStatus := TElOCSPServerError(Param.Content[0]);

      Seq := TElASN1ConstrainedTag(Seq.GetField(1));
      if (Seq = nil) or (Seq.Count < 1) then
        raise EElOCSPError.Create(SInvalidOCSPResponse);

      Seq := TElASN1ConstrainedTag(Seq.GetField(0));
      if (Seq = nil) or (Seq.Count < 1) then
        raise EElOCSPError.Create(SInvalidOCSPResponse);

      Param := TElASN1SimpleTag(Seq.GetField(0));
      if (Param = nil) or (Length(Param.Content) = 0) then
        raise EElOCSPError.Create(SInvalidOCSPResponse);
      if not CompareMem(Param.Content, SB_OCSP_OID_BASIC_RESPONSE) then
        raise EElOCSPError.Create(SInvalidOCSPResponse);

      // access response
      Param := TElASN1SimpleTag(Seq.GetField(1));
      if (Param = nil) or (Length(Param.Content) = 0) then
        raise EElOCSPError.Create(SInvalidOCSPResponse);

      SetLength(ReplyBuf, Length(Param.Content));

      SBMove(Param.Content[0], ReplyBuf[0], Length(Param.Content));

      FreeAndNil(Tag);
      Tag := TElASN1ConstrainedTag.CreateInstance();
      if not Tag.LoadFromBuffer(ReplyBuf, Length(ReplyBuf)) then
        raise EElOCSPError.Create(SInvalidOCSPResponse);
      if (Tag.Count <> 1) or (not Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
        raise EElOCSPError.Create(SInvalidOCSPResponse);
      FDataBasic := CloneArray(ReplyBuf);
      Seq := TElASN1ConstrainedTag(Tag.GetField(0));
    end
    else
      FDataBasic := CloneArray(FData);

    if (Seq.Count < 3) or (Seq.Count > 4) then
      raise EElOCSPError.Create(SInvalidOCSPResponse);
    if (not Seq.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) or
      (not Seq.GetField(1).CheckType(SB_ASN1_SEQUENCE, true)) or
      (not Seq.GetField(2).CheckType(SB_ASN1_BITSTRING, false)) then
      raise EElOCSPError.Create(SInvalidOCSPResponse);
    // processing TBS response data
    SubSeq := TElASN1ConstrainedTag(Seq.GetField(0));
    Sz := 0;
    SubSeq.SaveToBuffer( nil , Sz);
    SetLength(FTBS, Sz);
    SubSeq.SaveToBuffer( @FTBS[0] , Sz);
    SetLength(FTBS, Sz);
    CurrIndex := 0;
    if CurrIndex >= SubSeq.Count then
      raise EElOCSPError.Create(SInvalidOCSPResponse);
    if SubSeq.GetField(CurrIndex).CheckType(SB_ASN1_A0, true) then
      Inc(CurrIndex); // just skipping version
    if CurrIndex >= SubSeq.Count then
      raise EElOCSPError.Create(SInvalidOCSPResponse);
    FResponderID.FName.Clear;
    FResponderID.FSHA1KeyHash := EmptyArray;
    if SubSeq.GetField(CurrIndex).CheckType(SB_ASN1_A1, true) then
    begin
      SubSubSeq := TElASN1ConstrainedTag(SubSeq.GetField(CurrIndex));
      if (SubSubSeq.Count = 1) and (SubSubSeq.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
        FResponderID.FName.LoadFromTag(TElASN1ConstrainedTag(SubSubSeq.GetField(0)))
      else
        raise EElOCSPError.Create(SInvalidOCSPResponse);
      Inc(CurrIndex);
    end
    else if SubSeq.GetField(CurrIndex).CheckType(SB_ASN1_A2, true) then
    begin
      SubSubSeq := TElASN1ConstrainedTag(SubSeq.GetField(CurrIndex));
      if (SubSubSeq.Count = 1) and (SubSubSeq.GetField(0).CheckType(SB_ASN1_OCTETSTRING, false)) then
        FResponderID.FSHA1KeyHash := TElASN1SimpleTag(SubSubSeq.GetField(0)).Content
      else
        raise EElOCSPError.Create(SInvalidOCSPResponse);
      Inc(CurrIndex);
    end
    else
      raise EElOCSPError.Create(SInvalidOCSPResponse);
    if CurrIndex >= SubSeq.Count then
      raise EElOCSPError.Create(SInvalidOCSPResponse);
    if SubSeq.GetField(CurrIndex).CheckType(SB_ASN1_GENERALIZEDTIME, false) then
      FProducedAt := GeneralizedTimeToDateTime(StringOfBytes(TElASN1SimpleTag(SubSeq.GetField(CurrIndex)).Content))
    else
      raise EElOCSPError.Create(SInvalidOCSPResponse);
    Inc(CurrIndex);
    if CurrIndex >= SubSeq.Count then
      raise EElOCSPError.Create(SInvalidOCSPResponse);
    if SubSeq.GetField(CurrIndex).CheckType(SB_ASN1_SEQUENCE, true) then
    begin
      SubSubSeq := TElASN1ConstrainedTag(SubSeq.GetField(CurrIndex));
      for I := 0 to SubSubSeq.Count - 1 do
      begin
        if SubSubSeq.GetField(I).CheckType(SB_ASN1_SEQUENCE, true) then
        begin
          Resp := TElOCSPSingleResponse.Create();
          try
            Resp.LoadFromTag(TElASN1ConstrainedTag(SubSubSeq.GetField(I)));
            FResponses.Add(Resp);
          except
            FreeAndNil(Resp);
            raise;
          end;
        end;
      end;
    end
    else
      raise EElOCSPError.Create(SInvalidOCSPResponse);
    Inc(CurrIndex);
    if CurrIndex < SubSeq.Count then
    begin
      if SubSeq.GetField(CurrIndex).CheckType(SB_ASN1_A1, true) then
      begin
        // extensions -- not supported at the moment
      end;
    end;

    // processing algorithm identifier
    SubSeq := TElASN1ConstrainedTag(Seq.GetField(1));
    if ProcessAlgorithmIdentifier(SubSeq, Alg, AlgParams) <> 0 then
      raise EElOCSPError.Create(SUnsupportedSignatureAlgorithm);
    FSignatureAlgorithm := GetAlgorithmByOID(Alg);
    FSigAlg := FSignatureAlgorithm;
    FSigAlgOID := Alg;

    // processing signature
    FSig := TElASN1SimpleTag(Seq.GetField(2)).Content;

    // processing certificates
    if (Seq.Count > 3) and (Seq.GetField(3).CheckType(SB_ASN1_A0, true)) then
    begin
      SubSeq := TElASN1ConstrainedTag(Seq.GetField(3));
      if (SubSeq.Count = 1) and (SubSeq.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      begin
        SubSeq := TElASN1ConstrainedTag(SubSeq.GetField(0));
        for I := 0 to SubSeq.Count - 1 do
        begin
          Sz := 0;
          SubSeq.GetField(I).SaveToBuffer( nil , Sz);
          SetLength(Buf, Sz);
          SubSeq.GetField(I).SaveToBuffer( @Buf[0] , Sz);
          try
            Cert := TElX509Certificate.Create(nil);
            try
              Cert.LoadFromBuffer( @Buf[0] , Sz);
              FCertificates.Add(Cert);
            finally
              FreeAndNil(Cert);
            end;
          except
            // ignoring the exception to allow processing of further certificates
          end;
        end;
      end;
    end;
  finally
    FreeAndNil(Tag);
  end;
end;


function TElOCSPResponse.Save(Buffer: pointer; var Size: integer): boolean;
begin
  if Size < Length(FData) then
  begin
    Size := Length(FData);
    Result := false;
  end
  else
  begin
    Size := Length(FData);
    SBMove(FData[0], Buffer^, Size);
    Result := true;                
  end;
end;

function TElOCSPResponse.SaveBasic(Buffer: pointer; var Size: integer): boolean;
begin
  if Size < Length(FDataBasic) then
  begin
    Size := Length(FDataBasic);
    Result := false;
  end
  else
  begin
    Size := Length(FDataBasic);
    SBMove(FDataBasic[0], Buffer^, Size);
    Result := true;                
  end;
end;

procedure TElOCSPResponse.Assign(Source :  TPersistent );
var
  Data : ByteArray;
begin
  if not (Source is TElOCSPResponse) then
    raise ESecureBlackboxError.Create('Invalid object type');
  Data := CloneArray(TElOCSPResponse(Source).FData);
  Load(@Data[0], Length(Data));
  ReleaseArray(Data);
end;

function TElOCSPResponse.GetResponse(Index: integer) : TElOCSPSingleResponse;
begin
  Result := TElOCSPSingleResponse(FResponses[Index]);
end;

function TElOCSPResponse.GetResponseCount : integer;
begin
  Result := FResponses.Count;
end;

function TElOCSPResponse.EqualsTo(OtherResponse : TElOCSPResponse): boolean;
begin
  Result := (Length(FData) = Length(OtherResponse.FData)) and
    CompareMem(@FData[0], @OtherResponse.FData[0], Length(FData));
end;

function TElOCSPResponse.FindResponse(Cert : TElX509Certificate;
  Issuer : TElX509Certificate  =  nil): integer;
var
  I : integer;
begin
  Result := -1;
  try
    for I := 0 to ResponseCount - 1 do
    begin
      if Responses[I].CertMatches(Cert, Issuer) then
      begin
        Result := I;
        Break;
      end;
    end;
  except
    ;
  end;
end;

function TElOCSPResponse.FindResponse(Signer : TElPKCS7Issuer;
  Issuer : TElX509Certificate  =  nil): integer;
var
  I : integer;
begin
  Result := -1;
  try
    for I := 0 to ResponseCount - 1 do
    begin
      if Responses[I].SignerMatches(Signer, Issuer) then
      begin
        Result := I;
        Break;
      end;
    end;
  except
    ;
  end;
end;


////////////////////////////////////////////////////////////////////////////////
// TElOCSPSingleResponse class

 destructor  TElOCSPSingleResponse.Destroy;
begin
  inherited;
end;

procedure TElOCSPSingleResponse.LoadFromTag(Tag : TElASN1ConstrainedTag);
var
  Alg, AlgParams : ByteArray;
  Seq : TElASN1ConstrainedTag;
  Reasons : TSBCRLReasonFlags;
  B : integer;
  CurrIndex : integer;
begin
  if Tag.TagID <> SB_ASN1_SEQUENCE then
    raise EElOCSPError.Create(SInvalidSingleResponse);
  if (Tag.Count < 3) or (not Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) or
    (not Tag.GetField(2).CheckType(SB_ASN1_GENERALIZEDTIME, false)) then
    raise EElOCSPError.Create(SInvalidSingleResponse);
  Seq := TElASN1ConstrainedTag(Tag.GetField(0));
  // processing CertID
  if Seq.Count <> 4 then
    raise EElOCSPError.Create(SInvalidSingleResponse);
  if (not Seq.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) or
    (not Seq.GetField(1).CheckType(SB_ASN1_OCTETSTRING, false)) or
    (not Seq.GetField(2).CheckType(SB_ASN1_OCTETSTRING, false)) or
    (not Seq.GetField(3).CheckType(SB_ASN1_INTEGER, false)) then
    raise EElOCSPError.Create(SInvalidSingleResponse);
  if ProcessAlgorithmIdentifier(Seq.GetField(0), Alg, AlgParams) <> 0 then
    raise EElOCSPError.Create(SInvalidSingleResponse);
  FHashAlgorithm := GetHashAlgorithmByOID(Alg);
  FIssuerNameHash := TElASN1SimpleTag(Seq.GetField(1)).Content;
  FIssuerKeyHash := TElASN1SimpleTag(Seq.GetField(2)).Content;
  FSerialNumber := TElASN1SimpleTag(Seq.GetField(3)).Content;
  // certStatus
  FCertStatus := csUnknown;
  if Tag.GetField(1).CheckType($80, false) then
    FCertStatus := csGood
  else if Tag.GetField(1).CheckType(SB_ASN1_A1, true) then
  begin
    FCertStatus := csRevoked;
    Seq := TElASN1ConstrainedTag(Tag.GetField(1));
    if Seq.Count < 1 then
      raise EElOCSPError.Create(SInvalidSingleResponse);
    if Seq.GetField(0).CheckType(SB_ASN1_GENERALIZEDTIME, false) then
      FRevocationTime := GeneralizedTimeToDateTime(StringOfBytes(TElASN1SimpleTag(Seq.GetField(0)).Content));
    FRevocationReasons :=  [] ;
    if (Seq.Count > 1) and (Seq.GetField(1).CheckType(SB_ASN1_A0, true)) then
    begin
      Seq := TElASN1ConstrainedTag(Seq.GetField(1));
      if (Seq.Count = 1) and (not Seq.GetField(0).IsConstrained) then
      begin
        B := ASN1ReadInteger(TElASN1SimpleTag(Seq.GetField(0)));
        Reasons :=  [] ;
        if (B and $400) = $400 then
          Reasons := Reasons  + [rfAACompromise] ;
        if (B and $200) = $200 then
          Reasons := Reasons  + [rfPrivilegeWithdrawn] ;
        if (B and $100) = $100 then
          Reasons := Reasons  + [rfRemoveFromCRL] ;
        if (B and $80) = $80 then
          Reasons := Reasons  + [rfObsolete1] ;
        if (B and $40) = $40 then
          Reasons := Reasons  + [rfKeyCompromise] ;
        if (B and $20) = $20 then
          Reasons := Reasons  + [rfCACompromise] ;
        if (B and $10) = $10 then
          Reasons := Reasons  + [rfAffiliationChanged] ;
        if (B and $08) = $08 then
          Reasons := Reasons  + [rfSuperseded] ;
        if (B and $04) = $04 then
          Reasons := Reasons  + [rfCessationOfOperation] ;
        if (B and $02) = $02 then
          Reasons := Reasons  + [rfCertificateHold] ;
        FRevocationReasons := Reasons;
      end;
    end;
  end;
  // thisUpdate
  if not (Tag.GetField(2).CheckType(SB_ASN1_GENERALIZEDTIME, false)) then
    raise EElOCSPError.Create(SInvalidSingleResponse);
  FThisUpdate := GeneralizedTimeToDateTime(StringOfBytes(TElASN1SimpleTag(Tag.GetField(2)).Content));
  CurrIndex := 3;
  // nextUpdate
  FNextUpdate := (0);
  if (CurrIndex < Tag.Count) and (Tag.GetField(CurrIndex).CheckType(SB_ASN1_A0, true)) then
  begin
    Seq := TElASN1ConstrainedTag(Tag.GetField(CurrIndex));
    if (Seq.Count = 1) and (Seq.GetField(0).CheckType(SB_ASN1_GENERALIZEDTIME, false)) then
      FNextUpdate := GeneralizedTimeToDateTime(StringOfBytes(TElASN1SimpleTag(Seq.GetField(0)).Content));
    //Inc(CurrIndex);
  end;
  // extensions -- not supported at the moment
end;

function TElOCSPSingleResponse.CertMatches(Cert : TElX509Certificate;
  Issuer : TElX509Certificate  =  nil): boolean;
var
  IssuerNameHash, IssuerKeyHash : ByteArray;
begin
  // performing partial comparison if no issuer certificate is provided
  Result := false;
  try
    GetOCSPCertID(Cert, Issuer, FHashAlgorithm, IssuerNameHash, IssuerKeyHash);
    if CompareContent(IssuerNameHash, FIssuerNameHash) and
      SerialNumberCorresponds(Cert, FSerialNumber) then
    begin
      if Issuer <> nil then
        Result := CompareContent(IssuerKeyHash, FIssuerKeyHash)
      else
        Result := true;
    end;
  except
    ;
  end;
end;

function TElOCSPSingleResponse.SignerMatches(Signer : TElPKCS7Issuer; Issuer : TElX509Certificate  =  nil): boolean;
var
  IssuerNameHash, IssuerKeyHash : ByteArray;
begin
  // performing partial comparison if no issuer certificate is provided
  Result := false;
  try
    GetOCSPCertID(Signer, Issuer, FHashAlgorithm, IssuerNameHash, IssuerKeyHash);
    if CompareContent(IssuerNameHash, FIssuerNameHash) and
      CompareContent(Signer.SerialNumber, FSerialNumber) then
    begin
      if Issuer <> nil then
        Result := CompareContent(IssuerKeyHash, FIssuerKeyHash)
      else
        Result := true;
    end;
  except
    ;
  end;
end;

constructor TElOCSPClientManager.Create;
begin
  inherited;
  FFactoryList := TElList.Create;
end;

 destructor  TElOCSPClientManager.Destroy;
var
  i : integer;
begin
  for i := 0 to FFactoryList.Count - 1 do
    TElCustomOCSPClientFactory(FFactoryList[i]). Free ;
  FreeAndNil(FFactoryList);
  inherited;
end;

function TElOCSPClientManager.FindOCSPClientByLocation(const Location : string; Validator : TObject) : TElOCSPClient;
var i : integer;
    Factory : TElCustomOCSPClientFactory;
begin
  result := nil;
  for i := 0 to FFactoryList.Count - 1 do
  begin
    Factory := TElCustomOCSPClientFactory(FFactoryList[i]);
    if Factory.SupportsLocation(Location) then
    begin
      result := Factory.GetClientInstance(Validator);
      break;
    end;
  end;
end;

procedure TElOCSPClientManager.RegisterOCSPClientFactory(Factory : TElCustomOCSPClientFactory);
begin
  FFactoryList.Add(Factory);
end;

procedure TElOCSPClientManager.UnregisterOCSPClientFactory(Factory : TElCustomOCSPClientFactory);
begin
  FFactoryList.Remove(Factory);
end;

procedure InitializeOCSPClientManager;
begin
  AcquireGlobalLock;
  try
    if OCSPClientManager = nil then
      OCSPClientManager := TElOCSPClientManager.Create;
  finally
    ReleaseGlobalLock;
  end;
end;

function OCSPClientManagerAddRef : TElOCSPClientManager;
begin
  if OCSPClientManager = nil then
    InitializeOCSPClientManager;
  OCSPClientManagerUseCount := OCSPClientManagerUseCount + 1;
  result := OCSPClientManager;
end;

procedure OCSPClientManagerRelease;
begin
  OCSPClientManagerUseCount := OCSPClientManagerUseCount - 1;
  if OCSPClientManagerUseCount = 0 then
    FreeAndNil(OCSPClientManager);
end;

// we grab one account of OCSPClientManager in order to save one instance from the beginning to the end of application operations
initialization

  OCSPClientManagerAddRef;

finalization

  OCSPClientManagerRelease;

end.

