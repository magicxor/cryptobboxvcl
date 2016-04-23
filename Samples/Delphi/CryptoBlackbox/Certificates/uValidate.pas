{
   This form used to validate certificates
}
unit uValidate;

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  SBConstants, SBX509, SBX509Ext, SBPKCS12, SBCustomCertStorage,
  SBRDN, SBTypes, SBWinCertStorage, StdCtrls, ExtCtrls, ComCtrls, ImgList;

type
  TfrmValidate = class(TForm)
    tvPath: TTreeView;
    pnlBottom: TPanel;
    pnlValidity: TPanel;
    lblCertificateState: TLabel;
    memNotes: TMemo;
    ilTree: TImageList;
    btnOk: TButton;
  private
    { Private declarations }
    FTrustedStorages : array of TElCustomCertStorage;
    FTrustedStorageNames : array of string;
    FStorages : array of TElCustomCertStorage;
    FStorageNames : array of string;
    FCert : TElx509Certificate;

    procedure DoValidateCertificate;  
  public
    { Public declarations }
    class procedure ValidateCertificate(TrustedStorages,Storages : TStringList;
      Cert : TElX509Certificate);
  end;

function GetStringByOID(const S : ByteArray) : string;
function GetOIDValue(NTS: TElRelativeDistinguishedName; const S: ByteArray; const Delimeter: AnsiString = ' / '): AnsiString;

implementation

uses frmMain, ExtensionEncoder, SBUtils;

var
  frmValidate: TfrmValidate;
{$R *.DFM}

function GetStringByOID(const S : ByteArray) : string;
begin
  if CompareContent(S, SB_CERT_OID_COMMON_NAME) then
    Result := 'CommonName'
  else
  if CompareContent(S, SB_CERT_OID_COUNTRY) then
    Result := 'Country'
  else
  if CompareContent(S, SB_CERT_OID_LOCALITY) then
    Result := 'Locality'
  else
  if CompareContent(S, SB_CERT_OID_STATE_OR_PROVINCE) then
    Result := 'StateOrProvince'
  else
  if CompareContent(S, SB_CERT_OID_ORGANIZATION) then
    Result := 'Organization'
  else
  if CompareContent(S, SB_CERT_OID_ORGANIZATION_UNIT) then
    Result := 'OrganizationUnit'
  else
  if CompareContent(S, SB_CERT_OID_EMAIL) then
    Result := 'Email'
  else
    Result := 'UnknownField';
end;

function GetOIDValue(NTS: TElRelativeDistinguishedName; const S: ByteArray; const Delimeter: AnsiString = ' / '): AnsiString;
var
  i: Integer;
  t: AnsiString;
begin
  Result := '';
  for i := 0 to NTS.Count - 1 do
    if CompareContent(S, NTS.OIDs[i]) then
    begin
      t := AnsiString(StringOfBytes(NTS.Values[i]));
      if t = '' then
        Continue;

      if Result = '' then
      begin
        Result := t;
        if Delimeter = '' then
          Exit;
      end
      else
        Result := Result + Delimeter + t;
    end;
end;

function GetCertDisplayName(Cert : TelX509Certificate) : string;
begin
  try
    Result := GetOIDValue(Cert.SubjectRDN, SB_CERT_OID_COMMON_NAME);
    if Result = '' then
      Result := GetOIDValue(Cert.SubjectRDN, SB_CERT_OID_ORGANIZATION);
  except Result:=''; end;
end;

{ TfrmValidate }

procedure TfrmValidate.DoValidateCertificate;

{
  Returns : 0 - Trust unknown
            1 - Not trusted
            2 - Not valid
            3 - Valid

}
function ValidateCert(Cert : TELx509Certificate) : boolean;
begin
  Result := True;

  if Cert.ValidTo < Date then Result := False;
end;

function TestCert(PrevCert : TElX509Certificate; var PrevNode : TTreeNode) : integer;
var i : integer;
    CACert : TElX509Certificate;
    CAIdx : integer;
begin
  if not ValidateCert(PrevCert) then
  begin
    PrevNode := tvPath.Items.AddChild(PrevNode,GetCertDisplayName(PrevCert));
    PrevNode.ImageIndex := 1;
    PrevNode.SelectedIndex := 1;
    PrevNode.Data := PrevCert;
    memNotes.Text := PrevNode.Text + ' - not valid (expired)';
    Result := 2;
    exit;
  end;
  if PrevCert.SelfSigned then
  begin
    PrevNode := tvPath.Items.AddChild(PrevNode,GetCertDisplayName(PrevCert));
    PrevNode.Data := PrevCert;

    if PrevCert.Validate then
    begin
      memNotes.Text := PrevNode.Text + ' - self signed';
      PrevNode.ImageIndex := 0;
      PrevNode.SelectedIndex := 0;
      Result := 3;
    end
    else
    begin
      memNotes.Text := PrevNode.Text + ' - invalid self-signature';
      PrevNode.ImageIndex := 1;
      PrevNode.SelectedIndex := 1;
      Result := 5;
    end;  
    Exit;
  end;
  // not self signed
  // Looking in trusted storages
  for i:=0 to High(FTrustedStorages) do
  begin
    try
      CAIdx:=FTrustedStorages[i].GetIssuerCertificate(PrevCert);
    except
      CAIdx := -1; //skipping buggy KAV certificates
    end;
    if CAIdx > -1 then
    begin
      CACert := FTrustedStorages[i].Certificates[CAIdx];
      PrevNode := tvPath.Items.AddChild(PrevNode,GetCertDisplayName(CACert));
      PrevNode.Data := CACert;

      if not PrevCert.ValidateWithCA(CACert) then
      begin
        PrevNode.ImageIndex := 1;
        PrevNode.SelectedIndex := 1;
        memNotes.Text := PrevNode.Text + ' - invalid signature ';
        PrevNode := tvPath.Items.AddChild(PrevNode,GetCertDisplayName(PrevCert));
        memNotes.Lines.Add(GetCertDisplayName(PrevCert));
        Result := 5;
        Exit;
      end;
      
      if ValidateCert(CACert) then
      begin
        PrevNode.ImageIndex := 0;
        PrevNode.SelectedIndex := 0;
        memNotes.Text := PrevNode.Text + ' - belongs to trusted storage ' +
          FTrustedStorageNames[i];
        PrevNode := tvPath.Items.AddChild(PrevNode,GetCertDisplayName(PrevCert));
        PrevNode.ImageIndex := 0;
        PrevNode.SelectedIndex := 0;
        memNotes.Lines.Add(GetCertDisplayName(PrevCert));
        Result := 3;
      end else
      begin
        PrevNode.ImageIndex := 1;
        PrevNode.SelectedIndex := 1;
        memNotes.Text := PrevNode.Text + ' - belongs to trusted storage but not valid (expired)' +
          FTrustedStorageNames[i];
        PrevNode := tvPath.Items.AddChild(PrevNode,GetCertDisplayName(PrevCert));
        PrevNode.ImageIndex := 1;
        PrevNode.SelectedIndex := 1;
        memNotes.Lines.Add(GetCertDisplayName(PrevCert));
        Result := 2;
      end;

      Exit;
    end;
  end;
  // Looking in untrusted storages
  for i:=0 to High(FStorages) do
  begin
    CAIdx:=FStorages[i].GetIssuerCertificate(PrevCert);
    if CAIdx > -1 then
    begin
      CACert := FStorages[i].Certificates[CAIdx];
      Result := TestCert(CACert, PrevNode);
      
      if not PrevCert.ValidateWithCA(CACert) then
      begin
        PrevNode := tvPath.Items.AddChild(PrevNode,GetCertDisplayName(PrevCert));
        PrevNode.ImageIndex := 1;
        PrevNode.SelectedIndex := 1;
        memNotes.Text := PrevNode.Text + ' - invalid signature ';
        Result := 5;
        Exit;
      end
      else
      begin
        PrevNode := tvPath.Items.AddChild(PrevNode,GetCertDisplayName(PrevCert));
        PrevNode.ImageIndex := 0;
        PrevNode.SelectedIndex := 0;
        PrevNode.Data := CACert;
        memNotes.Text := PrevNode.Text + ' - belongs to untrusted storage';
        exit;
      end;  
    end;
  end;
  // No path:(
  PrevNode := tvPath.Items.AddChild(PrevNode,GetCertDisplayName(PrevCert));
  PrevNode.ImageIndex := 1;
  PrevNode.SelectedIndex := 1;
  PrevNode.Data := PrevCert;
  memNotes.Text := PrevNode.Text + ' - trust unknown';
  Result := 0;
end;
var TN : TTreeNode;
begin
  TN := nil;
  case TestCert(FCert, TN) of
  0 : lblCertificateState.Caption := 'Trust unknown';
  1 : lblCertificateState.Caption := 'Not trusted';
  2 : lblCertificateState.Caption := 'Not valid';
  3 : lblCertificateState.Caption := 'Valid';
  4 : lblCertificateState.Caption := 'Invalid signature';
  end;
  if TN <> nil then TN.Selected := True;
  ShowModal;
end;

class procedure TfrmValidate.ValidateCertificate(TrustedStorages,
  Storages: TStringList; Cert: TElX509Certificate);
var i : integer;
begin
   frmValidate := TfrmValidate.Create(Application);
   with frmValidate do
   begin
     FCert := Cert;
     SetLength(FTrustedStorages, TrustedStorages.Count);
     SetLength(FTrustedStorageNames, TrustedStorages.Count);
     for i:=0 to TrustedStorages.Count - 1 do
     begin
       FTrustedStorages[i] := TElCustomCertStorage(TrustedStorages.Objects[i]);
       FTrustedStorageNames[i] := TrustedStorages[i];
     end;
     SetLength(FStorages, Storages.Count);
     SetLength(FStorageNames, Storages.Count);
     for i:=0 to Storages.Count - 1 do
     begin
       FStorages[i] := TElCustomCertStorage(Storages.Objects[i]);
       FStorageNames[i] := Storages[i];
     end;
     DoValidateCertificate;
     Free;
   end;
end;

end.

