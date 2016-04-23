unit MainFrm;

{$i CertValidator.inc}

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms,
  Dialogs, SBCertValidator, StdCtrls, Buttons, SBTypes, SBUtils, SBX509, SBX509Ext,
  SBCRL, SBPKICommon, SBOCSPCommon, SBOCSPClient, 
  SBCRLStorage,
  {$ifndef CRYPTOBLACKBOX}
  SBLDAPCRL,
  CustomTransports,
  {$endif}
  ExtCtrls,
  SBCustomCertStorage,
  SBWinCertStorage;

type
  TForm1 = class(TForm)
    Validator: TElX509CertificateValidator;
    OpenDialog1: TOpenDialog;
    mmLog: TMemo;
    Panel1: TPanel;
    Label1: TLabel;
    bbValidate: TButton;
    cbCheckCRL: TCheckBox;
    cbCheckOCSP: TCheckBox;
    cbCheckValidityPeriodForTrusted: TCheckBox;
    cbForceCompleteChainValidationForTrusted: TCheckBox;
    cbIgnoreCAKeyUsage: TCheckBox;
    cbIgnoreSystemTrusted: TCheckBox;
    cbTrustSelfSigned: TCheckBox;
    cbMandatoryCRLCheck: TCheckBox;
    cbMandatoryOCSPCheck: TCheckBox;
    cbMandatoryRevocationCheck: TCheckBox;
    cbOfflineMode: TCheckBox;
    cbSystemStorages: TCheckBox;
    cbValidateInvalidCerts: TCheckBox;
    WinCertStorage: TElWinCertStorage;
    cbCert: TComboBox;
    ElX509Certificate: TElX509Certificate;
    bbChoose: TButton;
    procedure bbValidateClick(Sender: TObject);
    procedure ValidatorAfterCertificateValidation(Sender: TObject; Certificate,
      CACertificate: TElX509Certificate; var Validity: TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason; var DoContinue: Boolean);
    procedure ValidatorAfterCRLUse(Sender: TObject; Certificate,
      CACertificate: TElX509Certificate; CRL: TElCertificateRevocationList);
    procedure ValidatorAfterOCSPResponseUse(Sender: TObject; Certificate,
      CACertificate: TElX509Certificate; Response: TElOCSPResponse);
    procedure ValidatorBeforeCertificateValidation(Sender: TObject;
      Certificate: TElX509Certificate);
    procedure ValidatorBeforeCRLRetrieverUse(Sender: TObject; Certificate,
      CACertificate: TElX509Certificate; NameType: TSBGeneralName;
      const Location: string; var Retriever: TElCustomCRLRetriever);
    procedure ValidatorBeforeOCSPClientUse(Sender: TObject; Certificate,
      CACertificate: TElX509Certificate; const OCSPLocation: string;
      var OCSPClient: TElOCSPClient);
    procedure ValidatorCACertificateNeeded(Sender: TObject;
      Certificate: TElX509Certificate; var CACertificate: TElX509Certificate);
    procedure ValidatorCRLRetrieved(Sender: TObject; Certificate,
      CACertificate: TElX509Certificate; NameType: TSBGeneralName;
      const Location: string; CRL: TElCertificateRevocationList);
    procedure FormCreate(Sender: TObject);
    procedure ValidatorCRLNeeded(Sender: TObject; Certificate,
      CACertificate: TElX509Certificate; var CRLs: TElCustomCRLStorage);
    procedure bbChooseClick(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

function ReasonToString(Reason : TSBCertificateValidityReason): String;
begin
  Result := '';
  if vrBadData in Reason then
    Result := Result + 'bad data,';
  if vrRevoked in Reason then
    Result := Result + 'revoked,';
  if vrNotYetValid in Reason then
    Result := Result + 'yet not valid,';
  if vrExpired in Reason then
    Result := Result + 'expired,';
  if vrInvalidSignature in Reason then
    Result := Result + 'invalid sign.,';
  if vrUnknownCA in Reason then
    Result := Result + 'unknown CA,';
  if vrCAUnauthorized in Reason then
    Result := Result + 'CA unauthorized,';
  if vrCRLNotVerified in Reason then
    Result := Result + 'CRL not verified,';
  if vrOCSPNotVerified in Reason then
    Result := Result + 'OCSP not verified,';
  if vrIdentityMismatch in Reason then
    Result := Result + 'identity mismatch,';
  if vrNoKeyUsage in Reason then
    Result := Result + 'no key usage,';
  if vrBlocked in Reason then
    Result := Result + 'blocked,';

  Delete(Result, Length(Result), 1);
end;

function ValidityToString(Validity : TSBCertificateValidity) : string;
begin
  case Validity of
    cvOk: Result := 'valid';
    cvSelfSigned: Result := 'self signed';
    cvInvalid: Result := 'invalid';
    cvStorageError: Result := 'storage error';
    cvChainUnvalidated: Result := 'chain unvalidated';
  end;
end;

procedure TForm1.bbValidateClick(Sender: TObject);
var
  Validity : TSBCertificateValidity;
  Reason : TSBCertificateValidityReason;
  S, SReason : string;
  Err : integer;
begin
  if Length(cbCert.Text) = 0 then
  begin
    ShowMessage('Choose certificate to validate!');
    Exit;
  end;

  if FileExists(cbCert.Text) then
  begin
    Err := ElX509Certificate.LoadFromFileAuto(OpenDialog1.Filename, '');
    if Err <> 0 then
    begin
      ShowMessage('Error loading certificate [' + IntToStr(Err) + ']');
      Exit;
    end;
  end
  else
    ElX509Certificate.Assign(WinCertStorage[cbCert.ItemIndex]);

  try
    Validator.CheckCRL := cbCheckCRL.Checked;
    Validator.CheckOCSP := cbCheckOCSP.Checked;
    Validator.CheckValidityPeriodForTrusted := cbCheckValidityPeriodForTrusted.Checked;
    Validator.ForceCompleteChainValidationForTrusted := cbForceCompleteChainValidationForTrusted.Checked;
    Validator.IgnoreCAKeyUsage := cbIgnoreCAKeyUsage.Checked;
    Validator.IgnoreSystemTrust := cbIgnoreSystemTrusted.Checked;
    Validator.ImplicitlyTrustSelfSignedCertificates := cbTrustSelfSigned.Checked;
    Validator.MandatoryCRLCheck := cbMandatoryCRLCheck.Checked;
    Validator.MandatoryOCSPCheck := cbMandatoryOCSPCheck.Checked;
    Validator.MandatoryRevocationCheck := cbMandatoryRevocationCheck.Checked;
    Validator.OfflineMode := cbOfflineMode.Checked;
    Validator.UseSystemStorages := cbSystemStorages.Checked;
    Validator.ValidateInvalidCertificates := cbValidateInvalidCerts.Checked;

    Validity := cvInvalid;
    Reason := [];
    Validator.Validate(ElX509Certificate, Validity, Reason);

    S := #13#10 + DateTimeToStr(Now) + ' RESULT:'#13#10;
    S := S + 'CN=' + ElX509Certificate.SubjectName.CommonName;
    S := S + ', validity=' + ValidityToString(Validity);
    SReason := ReasonToString(Reason);
    if Length(SReason) > 0 then
      S := S + ', reason=' + SReason;
    S := S + #13#10#13#10;
    mmLog.Lines.Add(S);
  except
    on Ex: Exception do
      mmLog.Lines.Add('ERROR:'#13#10 + Ex.Message + #13#10);
  end;
end;

procedure TForm1.FormCreate(Sender: TObject);
var
  i : integer;
begin
  WinCertStorage.BeginRead;
  try
    for i := 0 to WinCertStorage.Count - 1 do
      cbCert.Items.Add(WinCertStorage[i].SubjectName.CommonName);
  finally
    WinCertStorage.EndRead;
  end;
  {$ifndef CRYPTOBLACKBOX}
  RegisterHTTPCRLRetrieverFactory;
  RegisterHTTPOCSPClientFactory;
  {$endif}
end;

procedure TForm1.ValidatorAfterCertificateValidation(Sender: TObject;
  Certificate, CACertificate: TElX509Certificate;
  var Validity: TSBCertificateValidity;
  var Reason: TSBCertificateValidityReason; var DoContinue: Boolean);
var
  S, SReason : string;
begin
  S := DateTimeToStr(Now) + ' AfterCertificateValidation:'#13#10;
  S := S + 'CN=' + Certificate.SubjectName.CommonName;
  if Length(Certificate.StorageName) > 0 then
     S := S + ', storage=' + Certificate.StorageName;

  if Assigned(CACertificate) then
    S := S + ', root CN=' + CACertificate.SubjectName.CommonName
  else
    S := S + ', root CN=self-signed';

  S := S + ', validity=' + ValidityToString(Validity);
  SReason := ReasonToString(Reason);
  if Length(SReason) > 0 then
    S := S + ', reason=' + SReason;

  mmLog.Lines.Add(S);
end;

procedure TForm1.ValidatorAfterCRLUse(Sender: TObject; Certificate,
  CACertificate: TElX509Certificate; CRL: TElCertificateRevocationList);
var
  S : string;
begin
  S := DateTimeToStr(Now) + ' AfterCRLUse:'#13#10;
  S := S + 'CN=' + Certificate.SubjectName.CommonName;
  if Length(Certificate.StorageName) > 0 then
     S := S + ', storage=' + Certificate.StorageName;

  if Assigned(CACertificate) then
    S := S + ', root CN=' + CACertificate.SubjectName.CommonName
  else
    S := S + ', root CN=self-signed';

  S := S + ', validity=' + IntToStr(CRL.Validate(CACertificate));
  mmLog.Lines.Add(S);
end;

procedure TForm1.ValidatorAfterOCSPResponseUse(Sender: TObject; Certificate,
  CACertificate: TElX509Certificate; Response: TElOCSPResponse);
var
  S : string;
begin
  S := DateTimeToStr(Now) + ' AfterOCSPResponseUse:'#13#10;
  S := S + 'CN=' + Certificate.SubjectName.CommonName;
  if Length(Certificate.StorageName) > 0 then
     S := S + ', storage=' + Certificate.StorageName;

  if Assigned(CACertificate) then
    S := S + ', root CN=' + CACertificate.SubjectName.CommonName
  else
    S := S + ', root CN=self-signed';

  case Response.Validate of
    csvValid : S := S + ', validity=valid';
    csvInvalid : S := S + ', validity=invalid';
    csvSignerNotFound : S := S + ', validity=signer not found';
    csvGeneralFailure : S := S + ', validity=general failure';
  end;

  mmLog.Lines.Add(S);
end;

procedure TForm1.ValidatorBeforeCertificateValidation(Sender: TObject;
  Certificate: TElX509Certificate);
var
  S : string;
begin
  S := DateTimeToStr(Now) + ' BeforeCertificateValidation:'#13#10;
  S := S + 'CN=' + Certificate.SubjectName.CommonName;
  if Length(Certificate.StorageName) > 0 then
     S := S + ', storage=' + Certificate.StorageName;
  mmLog.Lines.Add(S);
end;

procedure TForm1.ValidatorBeforeCRLRetrieverUse(Sender: TObject; Certificate,
  CACertificate: TElX509Certificate; NameType: TSBGeneralName;
  const Location: string; var Retriever: TElCustomCRLRetriever);
var
  S : string;
begin
  S := DateTimeToStr(Now) + ' BeforeCRLRetrieverUse:'#13#10;
  S := S + 'CN=' + Certificate.SubjectName.CommonName;
  if Length(Certificate.StorageName) > 0 then
     S := S + ', storage=' + Certificate.StorageName;
  S := S + ', location=' + Location;
  mmLog.Lines.Add(S);
end;

procedure TForm1.ValidatorBeforeOCSPClientUse(Sender: TObject; Certificate,
  CACertificate: TElX509Certificate; const OCSPLocation: string;
  var OCSPClient: TElOCSPClient);
var
  S : string;
begin
  S := DateTimeToStr(Now) + ' BeforeOCSPClientUse:'#13#10;
  S := S + 'CN=' + Certificate.SubjectName.CommonName;
  if Length(Certificate.StorageName) > 0 then
     S := S + ', storage=' + Certificate.StorageName;
  S := S + ', location=' + OCSPLocation;
  mmLog.Lines.Add(S);
end;

procedure TForm1.ValidatorCACertificateNeeded(Sender: TObject;
  Certificate: TElX509Certificate; var CACertificate: TElX509Certificate);
var
  S : string;
begin
  S := DateTimeToStr(Now) + ' CACertificateNeeded:'#13#10;
  S := S + 'CN=' + Certificate.SubjectName.CommonName;
  S := S + ', CA certificate missing';
  mmLog.Lines.Add(S);
end;

procedure TForm1.ValidatorCRLNeeded(Sender: TObject; Certificate,
  CACertificate: TElX509Certificate; var CRLs: TElCustomCRLStorage);
var
  S : string;
begin
  S := DateTimeToStr(Now) + ' CRLNeeded:'#13#10;
  S := S + 'CN=' + Certificate.SubjectName.CommonName;
  S := S + ', CRL missing';
  mmLog.Lines.Add(S);
end;

procedure TForm1.ValidatorCRLRetrieved(Sender: TObject; Certificate,
  CACertificate: TElX509Certificate; NameType: TSBGeneralName;
  const Location: string; CRL: TElCertificateRevocationList);
var
  S : string;
begin
  S := DateTimeToStr(Now) + ' CRLRetrieved:'#13#10;
  S := S + 'CN=' + Certificate.SubjectName.CommonName;
  if Length(Certificate.StorageName) > 0 then
     S := S + ', storage=' + Certificate.StorageName;
  S := S + ', location=' + Location;
  S := S + ', retrieved successfully';
  mmLog.Lines.Add(S);
end;

procedure TForm1.bbChooseClick(Sender: TObject);
begin
  if OpenDialog1.Execute then
    cbCert.Text := OpenDialog1.Filename;
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  {$ifndef CRYPTOBLACKBOX}
  UnregisterHTTPCRLRetrieverFactory;
  UnregisterHTTPOCSPClientFactory;
  {$endif}
end;

initialization

{$ifndef CRYPTOBLACKBOX}
#error Please pick the evaluation license key from <SecureBlackbox>\LicenseKey.txt file and place it here. If the evaluation key expires, you can request an extension using the form on https://www.eldos.com/sbb/keyreq/
SetLicenseKey('<put the key here>');
{$endif}

end.
