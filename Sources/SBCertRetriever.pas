(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBCertRetriever;

interface

uses


  Classes,
  SysUtils,
  

  SBTypes,
  SBUtils,
  SBEncoding,
  SBConstants,

  SBX509,
  SBX509Ext;


const

  ERROR_FACILITY_CERT_RETRIEVER = $1B000;
  ERROR_CERT_RETRIEVER_ERROR_FLAG = $00800;

(*
  SB_CERT_RETRIEVER_ERROR_NO_CERTIFICATES        = Integer(ERROR_FACILITY_CERT_RETRIEVER + ERROR_CERT_RETRIEVER_ERROR_FLAG + 1);
  SB_CERT_RETRIEVER_ERROR_NO_ISSUER_CERTIFICATES = Integer(ERROR_FACILITY_CERT_RETRIEVER + ERROR_CERT_RETRIEVER_ERROR_FLAG + 2);
  SB_CERT_RETRIEVER_ERROR_WRONG_DATA             = Integer(ERROR_FACILITY_CERT_RETRIEVER + ERROR_CERT_RETRIEVER_ERROR_FLAG + 3);
  SB_CERT_RETRIEVER_ERROR_NO_EVENT_HANDLER       = Integer(ERROR_FACILITY_CERT_RETRIEVER + ERROR_CERT_RETRIEVER_ERROR_FLAG + 4);
*)
  SB_CERT_RETRIEVER_ERROR_NO_PARAMETERS          = Integer(ERROR_FACILITY_CERT_RETRIEVER + ERROR_CERT_RETRIEVER_ERROR_FLAG + 5);
  SB_CERT_RETRIEVER_ERROR_NO_REPLY               = Integer(ERROR_FACILITY_CERT_RETRIEVER + ERROR_CERT_RETRIEVER_ERROR_FLAG + 6);
(*
  SB_CERT_RETRIEVER_ERROR_WRONG_SIGNATURE        = Integer(ERROR_FACILITY_CERT_RETRIEVER + ERROR_CERT_RETRIEVER_ERROR_FLAG + 7);
  SB_CERT_RETRIEVER_ERROR_UNSUPPORTED_ALGORITHM  = Integer(ERROR_FACILITY_CERT_RETRIEVER + ERROR_CERT_RETRIEVER_ERROR_FLAG + 8);
  SB_CERT_RETRIEVER_ERROR_INVALID_RESPONSE       = Integer(ERROR_FACILITY_CERT_RETRIEVER + ERROR_CERT_RETRIEVER_ERROR_FLAG + 9);
*)
type

  TElCustomCertificateRetriever = class(TSBControlBase)
  public
    constructor Create(Owner: TSBComponentBase);  override; 
     destructor  Destroy; override;

    function SupportsLocation(NameType : TSBGeneralName; const URI : string) : boolean; virtual; abstract;
    function RetrieveCertificate(Certificate: TElX509Certificate; NameType : TSBGeneralName; const URL : string) : TElX509Certificate; virtual; abstract;
  end;

  TSBCertificateRetrievalEvent =  procedure(Sender : TObject;
    Certificate: TElX509Certificate; NameType : TSBGeneralName; const Location : string; var CACertificate : TElX509Certificate) of object;

  TElFileCertificateRetriever = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElFileCertificateRetriever = TElFileCertificateRetriever;
   {$endif}

  TElFileCertificateRetriever = class(TElCustomCertificateRetriever)
  protected
    FOnCertificateNeeded: TSBCertificateRetrievalEvent;
  public
    function RetrieveCertificate(Certificate: TElX509Certificate; NameType : TSBGeneralName; const URL : string) : TElX509Certificate; override;
    function SupportsLocation(NameType : TSBGeneralName; const URI : string) : boolean; override;

  published
    property OnCertificateNeeded : TSBCertificateRetrievalEvent read FOnCertificateNeeded write FOnCertificateNeeded;
  end;

  TElCustomCertificateRetrieverFactory = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCustomCertificateRetrieverFactory = TElCustomCertificateRetrieverFactory;
   {$endif}

  TElCustomCertificateRetrieverFactory =  class
  public
    function SupportsLocation(NameType : TSBGeneralName; const URI: string): Boolean; virtual; abstract;
    function GetClientInstance(Validator : TObject) : TElCustomCertificateRetriever; virtual; abstract;
  end;

  TElCertificateRetrieverManager = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCertRetrieverManager = TElCertificateRetrieverManager;
   {$endif}

  TElCertificateRetrieverManager =  class
  private
    FFactoryList : TElList;
  public
    constructor Create;
     destructor  Destroy; override;
    function FindCertificateRetrieverByLocation(NameType : TSBGeneralName; const Location : string; Validator : TObject) : TElCustomCertificateRetriever;
    procedure RegisterCertificateRetrieverFactory(Factory : TElCustomCertificateRetrieverFactory);
    procedure UnregisterCertificateRetrieverFactory(Factory : TElCustomCertificateRetrieverFactory);
  end;

function CertificateRetrieverManagerAddRef : TElCertificateRetrieverManager; 
procedure CertificateRetrieverManagerRelease; 

procedure Register;

implementation

procedure Register;
begin
  RegisterComponents('PKIBlackbox', [TElFileCertificateRetriever]);
end;

var CertificateRetrieverManager : TElCertificateRetrieverManager  =  nil;
var CertificateRetrieverManagerUseCount : integer  =  0;

constructor TElCustomCertificateRetriever.Create(Owner: TSBComponentBase);
begin
  inherited Create(Owner);
end;


 destructor  TElCustomCertificateRetriever.Destroy;
begin
  inherited;
end;

function TElFileCertificateRetriever.SupportsLocation(NameType : TSBGeneralName; const URI : string) : boolean;
begin
  result := true;
end;

function TElFileCertificateRetriever.RetrieveCertificate(Certificate: TElX509Certificate; NameType : TSBGeneralName; const URL : string) : TElX509Certificate;
begin
  if not Assigned(FOnCertificateNeeded) then
  begin
    result := nil; //SB_CERT_RETRIEVER_ERROR_NO_PARAMETERS;
    exit;
  end;
   FOnCertificateNeeded(Self, Certificate, NameType, URL  , result );
end;

constructor TElCertificateRetrieverManager.Create;
begin
  inherited;
  FFactoryList := TElList.Create;
end;

 destructor  TElCertificateRetrieverManager.Destroy;
var
  i : integer;
begin
  for i := 0 to FFactoryList.Count - 1 do
    TElCustomCertificateRetrieverFactory(FFactoryList[i]). Free ;
  FreeAndNil(FFactoryList);
  inherited;
end;

function TElCertificateRetrieverManager.FindCertificateRetrieverByLocation(NameType : TSBGeneralName; const Location : string; Validator : TObject) : TElCustomCertificateRetriever;
var i : integer;
    Factory : TElCustomCertificateRetrieverFactory;
begin
  result := nil;
  for i := 0 to FFactoryList.Count - 1 do
  begin
    Factory := TElCustomCertificateRetrieverFactory(FFactoryList[i]);
    if Factory.SupportsLocation(NameType, Location) then
    begin
      result := Factory.GetClientInstance(Validator);
      break;
    end;
  end;
end;

procedure TElCertificateRetrieverManager.RegisterCertificateRetrieverFactory(Factory : TElCustomCertificateRetrieverFactory);
begin
  FFactoryList.Add(Factory);
end;

procedure TElCertificateRetrieverManager.UnregisterCertificateRetrieverFactory(Factory : TElCustomCertificateRetrieverFactory);
begin
  FFactoryList.Remove(Factory);
end;

function CertificateRetrieverManagerAddRef : TElCertificateRetrieverManager;
begin
  if CertificateRetrieverManager = nil then
    CertificateRetrieverManager := TElCertificateRetrieverManager.Create;
  CertificateRetrieverManagerUseCount := CertificateRetrieverManagerUseCount + 1;
  result := CertificateRetrieverManager;
end;

procedure CertificateRetrieverManagerRelease;
begin
  CertificateRetrieverManagerUseCount := CertificateRetrieverManagerUseCount - 1;
  if CertificateRetrieverManagerUseCount = 0 then
    FreeAndNil(CertificateRetrieverManager);
end;

// we grab one account of CertificateRetrieverManager in order to save one instance from the beginning to the end of application operations
initialization

  CertificateRetrieverManagerAddRef;

finalization

  CertificateRetrieverManagerRelease;

end.
