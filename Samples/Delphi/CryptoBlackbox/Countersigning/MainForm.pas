unit MainForm;

{$i Countersigning.inc}

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  ComCtrls, StdCtrls, ExtCtrls, SBMessages, SBX509, SBCustomCertStorage,
  SBTypes, 
  SBUtils;

type
  TfrmMain = class(TForm)
    PageControl: TPageControl;
    pBottom: TPanel;
    btnClose: TButton;
    tabSign: TTabSheet;
    tabVerify: TTabSheet;
    gbCSProps: TGroupBox;
    lblSigFile: TLabel;
    editSigFile: TEdit;
    btnBrowseSigFile: TButton;
    lblCertFile: TLabel;
    editCertFile: TEdit;
    btnBrowseCertFile: TButton;
    lblCertPass: TLabel;
    editCertPass: TEdit;
    lblOutputFile: TLabel;
    editOutputFile: TEdit;
    btnBrowseOutputFile: TButton;
    btnCountersign: TButton;
    OpenDialog: TOpenDialog;
    OpenDialogCert: TOpenDialog;
    SaveDialog: TSaveDialog;
    gbCVProps: TGroupBox;
    Label1: TLabel;
    editCountersignedFile: TEdit;
    btnBrowseCountersignature: TButton;
    Label2: TLabel;
    lvSigProps: TListView;
    btnVerify: TButton;
    procedure btnBrowseSigFileClick(Sender: TObject);
    procedure btnBrowseCertFileClick(Sender: TObject);
    procedure btnBrowseOutputFileClick(Sender: TObject);
    procedure btnCountersignClick(Sender: TObject);
    procedure btnBrowseCountersignatureClick(Sender: TObject);
    procedure btnVerifyClick(Sender: TObject);
    procedure btnCloseClick(Sender: TObject);
  private
    procedure Countersign;
    procedure VerifyCountersignatures;
  public
    { Public declarations }
  end;

var
  frmMain: TfrmMain;

implementation

{$R *.DFM}

procedure TfrmMain.btnBrowseSigFileClick(Sender: TObject);
begin
  if OpenDialog.Execute then
    editSigFile.Text := OpenDialog.Filename;
end;

procedure TfrmMain.btnBrowseCertFileClick(Sender: TObject);
begin
  if OpenDialogCert.Execute then
    editCertFile.Text := OpenDialogCert.Filename;
end;

procedure TfrmMain.btnBrowseOutputFileClick(Sender: TObject);
begin
  if SaveDialog.Execute then
    editOutputFile.Text := SaveDialog.Filename;
end;

procedure TfrmMain.btnCountersignClick(Sender: TObject);
begin
  Countersign;
end;

procedure TfrmMain.btnBrowseCountersignatureClick(Sender: TObject);
begin
  if OpenDialog.Execute then
    editCountersignedFile.Text := OpenDialog.Filename;
end;

procedure TfrmMain.btnVerifyClick(Sender: TObject);
begin
  VerifyCountersignatures;
end;

procedure TfrmMain.Countersign;
var
  Signer : TElMessageSigner;
  CertStorage : TElMemoryCertStorage;
  F : TFileStream;
  InBuf, OutBuf : ByteArray;
  OutSize : integer;
  R : integer;
begin
  Signer := TElMessageSigner.Create(nil);
  CertStorage := TElMemoryCertStorage.Create(nil);
  try
    F := TFileStream.Create(editCertFile.Text, fmOpenRead);
    try
      R := CertStorage.LoadFromStreamPFX(F, editCertPass.Text);
    finally
      FreeAndNil(F);
    end;
    if R <> 0 then
    begin
      MessageDlg('Failed to load certificate, error ' + IntToHex(R, 4), mtError, [mbOk], 0);
      Exit;
    end;
    F := TFileStream.Create(editSigFile.Text, fmOpenRead);
    try
      SetLength(InBuf, F.Size);
      F.Read(InBuf[0], Length(InBuf));
    finally
      FreeAndNil(F);
    end;
    Signer.CertStorage := CertStorage;
    OutSize := 0;
    Signer.Countersign(@InBuf[0], Length(InBuf), nil, OutSize);
    SetLength(OutBuf, OutSize);
    R := Signer.Countersign(@InBuf[0], Length(InBuf), @OutBuf[0], OutSize);
    if R = 0 then
    begin
      F := TFileStream.Create(editOutputFile.Text, fmCreate);
      try
        F.Write(OutBuf[0], OutSize);
      finally
        FreeAndNil(F);
      end;
      MessageDlg('Countersigning succeeded', mtInformation, [mbOk], 0);
    end
    else
      MessageDlg('Failed to countersign the signature, error ' + IntToHex(R, 4),
        mtError, [mbOk], 0);
  finally
    FreeAndNil(Signer);
    FreeAndNil(CertStorage);
  end;
end;

procedure TfrmMain.VerifyCountersignatures;
var
  Verifier : TElMessageVerifier;
  F : TFileStream;
  InBuf, OutBuf : ByteArray;
  OutSize : integer;
  R, I, J : integer;
  CertID : string;
  procedure AddPropertyValue(const Prop, Value: string);
  var
    Item : TListItem;
  begin
    Item := lvSigProps.Items.Add;
    Item.Caption := Prop;
    Item.SubItems.Add(Value);
  end;
begin
  lvSigProps.Items.Clear;
  Verifier := TElMessageVerifier.Create(nil);
  try
    F := TFileStream.Create(editCountersignedFile.Text, fmOpenRead);
    try
      SetLength(InBuf, F.Size);
      F.Read(InBuf[0], Length(InBuf));
    finally
      FreeAndNil(F);
    end;
    Verifier.VerifyCountersignatures := true;
    OutSize := 0;
    Verifier.Verify(@InBuf[0], Length(InBuf), nil, OutSize);
    SetLength(OutBuf, OutSize);
    R := Verifier.Verify(@InBuf[0], Length(InBuf), @OutBuf[0], OutSize);
    AddPropertyValue('Verification result', '0x' + IntToHex(R, 4));
    AddPropertyValue('Countersignatures count', IntToStr(Verifier.CountersignatureCertIDCount));
    for I := 0 to Verifier.CountersignatureCertIDCount - 1 do
    begin
      CertID := '';
      for J := 0 to Verifier.CountersignatureCertIDs[I].Issuer.Count - 1 do
        CertID := CertID + StringOfBytes(Verifier.CountersignatureCertIDs[I].Issuer.Values[J]) + ', ';
      CertID := CertID + 'Validity: 0x' + IntToHex(Verifier.CountersignatureVerificationResults[I], 4);
      AddPropertyValue('Countersignature #' + IntToStr(I), CertID);
    end;
    MessageDlg('Verification finished', mtInformation, [mbOk], 0);
  finally
    FreeAndNil(Verifier);
  end;
end;

procedure TfrmMain.btnCloseClick(Sender: TObject);
begin
  Close;
end;


initialization

{$ifndef CRYPTOBLACKBOX}
#error Please pick the evaluation license key from <SecureBlackbox>\LicenseKey.txt file and place it here. If the evaluation key expires, you can request an extension using the form on https://www.eldos.com/sbb/keyreq/
SetLicenseKey('<put the key here>');
{$endif}

end.
