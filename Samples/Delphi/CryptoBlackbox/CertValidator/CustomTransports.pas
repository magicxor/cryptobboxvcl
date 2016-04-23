unit CustomTransports;

interface

uses
  Classes,
  SysUtils,
  SBTypes, 
  SBUtils,
  SBCRL,
  SBCRLStorage,
  SBX509,
  SBX509Ext,
  SBHTTPSClient,
  SBOCSPCommon,
  SBOCSPClient;

type

  TElSampleHTTPCRLRetriever = class(TElCustomCRLRetriever)
  protected
    FHTTPClient: TElHTTPSClient;
  public
    constructor Create(AOwner : TComponent); override;

    destructor Destroy; override;

    function Supports(NameType : TSBGeneralName; const Location : string) : boolean; override;
    function GetCRL(Certificate, CACertificate : TElX509Certificate; NameType : TSBGeneralName; const Location : string) : TElCertificateRevocationList; override;
  published
    property HTTPClient: TElHTTPSClient read FHTTPClient;
  end;

  TElSampleHTTPCRLRetrieverFactory = class(TElCustomCRLRetrieverFactory)
  public
    function Supports(NameType : TSBGeneralName; const Location : string) : boolean; override;
    function GetRetrieverInstance(Validator : TObject) : TElCustomCRLRetriever; override;
  end;

  TElSampleHTTPOCSPClient = class(TElOCSPClient)
  protected
    FHTTPClient : TElHTTPSClient;
  public
    function SupportsLocation(const URI: string): Boolean; override;
    function PerformRequest(var ServerResult : TElOCSPServerError; var Reply : ByteArray) : Integer; override;

    constructor Create(AOwner : TComponent); override;
    destructor Destroy; override;
  end;

  TElSampleHTTPOCSPClientFactory = class(TElCustomOCSPClientFactory)
  public
    function SupportsLocation(const URI: string): Boolean; override;
    function GetClientInstance(Validator : TObject) : TElOCSPClient; override;
  end;

procedure RegisterHTTPOCSPClientFactory;
procedure RegisterHTTPCRLRetrieverFactory;

procedure UnregisterHTTPOCSPClientFactory;
procedure UnregisterHTTPCRLRetrieverFactory;

implementation

constructor TElSampleHTTPCRLRetriever.Create;
begin
  inherited;
  FHTTPClient := TElHTTPSClient.Create(nil);
  FHTTPClient.SocketTimeout := 5000;
end;

destructor TElSampleHTTPCRLRetriever.Destroy;
begin
  FHTTPClient.Free;
  inherited;
end;

function TElSampleHTTPCRLRetriever.GetCRL(Certificate, CACertificate : TElX509Certificate;
  NameType : TSBGeneralName; const Location : string) : TElCertificateRevocationList;
var ReplyStream : TMemoryStream;
    ReplyCode : integer;
begin
  result := nil;

  if (NameType = gnUniformResourceIdentifier) and (Location <> '') and (FHTTPClient <> nil) then
  begin
    try
      ReplyStream := TMemoryStream.Create;
      try
        FHTTPClient.OutputStream := ReplyStream;
        ReplyCode := FHTTPClient.Get(Location);
        if ReplyCode < 400 then
        begin
          ReplyStream.Position := 0;
          result := TElCertificateRevocationList.Create(nil);
          try
            Result.LoadFromStream(ReplyStream);
          except
            FreeAndNil(Result);
          end;
        end;
      finally
        FreeAndNil(ReplyStream);
      end;
    except
      on Ex: EElLicenseError do
        raise;
      // we suppress all other errors because the only thing that matters is whether the CRL has been retrieved or not
    end;
  end;
end;

function TElSampleHTTPCRLRetriever.Supports(NameType : TSBGeneralName; const Location : string) : boolean;
begin
  result := NameType = gnUniformResourceIdentifier;
end;

function TElSampleHTTPCRLRetrieverFactory.Supports(NameType : TSBGeneralName; const Location : string) : boolean;
begin
  result := NameType = gnUniformResourceIdentifier;
end;

function TElSampleHTTPCRLRetrieverFactory.GetRetrieverInstance(Validator : TObject) : TElCustomCRLRetriever;
begin
  result := TElSampleHTTPCRLRetriever.Create(nil);
end;

const
  sOCSPReply = 'APPLICATION/OCSP-REPLY';
  sOCSPResponse = 'APPLICATION/OCSP-RESPONSE';

function TElSampleHTTPOCSPClient.PerformRequest(var ServerResult: TElOCSPServerError; var Reply : ByteArray) : Integer;
var Request : ByteArray;
    ReplyStream : TMemoryStream;
    CT : string;
    ReplyCode : integer;
begin
  if (Length(URL) = 0) or (FHTTPClient = nil) then
  begin
    result := SB_OCSP_ERROR_NO_PARAMETERS;
    exit;
  end;

  result := CreateRequest(Request);
  if Result <> 0 then
    exit;

  ReplyStream := TMemoryStream.Create;
  try
    FHTTPClient.RequestParameters.ContentType := 'application/ocsp-request';
    FHTTPClient.OutputStream := ReplyStream;

    try
      ReplyCode := FHTTPClient.Post(FURL, Request);
    except
      on E: EElHTTPSConnectionShutdownError do
      begin
        result := SB_OCSP_ERROR_NO_REPLY;
        exit;
      end;
    end;

    if ReplyCode <> 200 then
    begin
      result := SB_OCSP_ERROR_NO_REPLY;
      exit;
    end;

    CT := FHTTPClient.GetHeaderByName(FHTTPClient.ResponseHeaders, 'Content-Type');
    if (Uppercase(CT) <> socspReply) and
       (Uppercase(CT) <> socspResponse) then
    begin
      result := SB_OCSP_ERROR_WRONG_DATA;
      exit;
    end;

    SetLength(Reply, ReplyStream.Size);
    if Length(Reply) = 0 then
    begin
      result := SB_OCSP_ERROR_WRONG_DATA;
      exit;
    end;

    ReplyStream.Position := 0;
    ReplyStream.Read(Reply[0], Length(Reply));

    result := ProcessReply(Reply, ServerResult);
  finally
    FreeAndNil(ReplyStream);
  end;
end;

function TElSampleHTTPOCSPClient.SupportsLocation(const URI: string): Boolean;
begin
  result := Pos('http://', Lowercase(Trim(URI))) = 1;
end;

constructor TElSampleHTTPOCSPClient.Create;
begin
  inherited;
  FHTTPClient := TElHTTPSClient.Create(nil);
  FHTTPClient.SocketTimeout := 5000;
end;

destructor TElSampleHTTPOCSPClient.Destroy;
begin
  FHTTPClient.Free;
  inherited;
end;


function TElSampleHTTPOCSPClientFactory.SupportsLocation(const URI: string): Boolean;
begin
  result := Pos('http://', Lowercase(Trim(URI))) = 1;
end;

function TElSampleHTTPOCSPClientFactory.GetClientInstance(Validator : TObject) : TElOCSPClient;
begin
  result := TElSampleHTTPOCSPClient.Create(nil);
end;

var AOCSPFactory : TElSampleHTTPOCSPClientFactory;

procedure RegisterHTTPOCSPClientFactory;
begin
  AOCSPFactory := TElSampleHTTPOCSPClientFactory.Create;
  OCSPClientManagerAddRef.RegisterOCSPClientFactory(AOCSPFactory);
  OCSPClientManagerRelease;
end;

procedure UnregisterHTTPOCSPClientFactory;
begin
  OCSPClientManagerAddRef.UnregisterOCSPClientFactory(AOCSPFactory);
  OCSPClientManagerRelease;
end;
            
var ACRLFactory : TElSampleHTTPCRLRetrieverFactory;

procedure RegisterHTTPCRLRetrieverFactory;
begin
  ACRLFactory := TElSampleHTTPCRLRetrieverFactory.Create;
  CRLManagerAddRef.RegisterCRLRetrieverFactory(ACRLFactory);
  CRLManagerRelease;
end;

procedure UnregisterHTTPCRLRetrieverFactory;
begin
  CRLManagerAddRef.UnregisterCRLRetrieverFactory(ACRLFactory);
  CRLManagerRelease;
end;


end.
