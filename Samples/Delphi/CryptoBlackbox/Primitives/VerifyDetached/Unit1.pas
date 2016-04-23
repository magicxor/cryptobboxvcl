unit Unit1;

{$i VerifyDetached.inc}

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms,
  Dialogs, ExtCtrls, StdCtrls, SBPublicKeyCrypto, SBTypes, SBUtils, SBX509;

type
  TfrmMainForm = class(TForm)
    btnVerify: TButton;
    btnCancel: TButton;
    dlgOpenDialog: TOpenDialog;
    dlgOpenKey: TOpenDialog;
    gbSettings: TGroupBox;
    lblInputFile: TLabel;
    lblAlgorithm: TLabel;
    lblPassword: TLabel;
    lblKeyFilename: TLabel;
    lblSigFile: TLabel;
    lblInputEncoding: TLabel;
    editInputFile: TEdit;
    btnBrowseInputFile: TButton;
    comboAlg: TComboBox;
    btnBrowseKey: TButton;
    editKeyFile: TEdit;
    editPassphrase: TEdit;
    btnBrowseOutputFile: TButton;
    editSignatureFile: TEdit;
    comboInputEncoding: TComboBox;
    lblKeyContainerType: TLabel;
    comboKeyContainerType: TComboBox;
    procedure btnCancelClick(Sender: TObject);
    procedure btnBrowseInputFileClick(Sender: TObject);
    procedure btnBrowseOutputFileClick(Sender: TObject);
    procedure btnVerifyClick(Sender: TObject);
    procedure btnBrowseKeyClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    procedure DoVerifyDetached;
  public
    { Public declarations }
  end;

var
  frmMainForm: TfrmMainForm;

implementation

{$R *.dfm}

procedure TfrmMainForm.DoVerifyDetached;
var
  Crypto : TElPublicKeyCrypto;
  StreamInput, StreamSignature, StreamKey: TFileStream;
  KeyLoaded : Boolean;
  KeyMaterial : TElPublicKeyMaterial;
  Cert : TElX509Certificate;
  CertType : TSBCertFileFormat;
  VR : TSBPublicKeyVerificationResult;
  R : integer;
  ErrorMsg : string;
begin
  if comboAlg.ItemIndex = 0 then
  begin
    Crypto := TElRSAPublicKeyCrypto.Create();
    KeyMaterial := TElRSAKeyMaterial.Create;
  end
  else
  begin
    Crypto := TElDSAPublicKeyCrypto.Create();
    KeyMaterial := TElDSAKeyMaterial.Create;
  end;
  try
    try
      if comboInputEncoding.ItemIndex = 0 then
        Crypto.InputEncoding := pkeBinary
      else
        Crypto.InputEncoding := pkeBase64;

      // load certificate/key
      KeyLoaded := false;
      if comboKeyContainerType.ItemIndex = 1 then
      begin
        Cert := TElX509Certificate.Create(nil);
        StreamKey := TFileStream.Create(editKeyFile.Text, fmOpenRead or fmShareDenyWrite);
        try
          CertType := cert.DetectCertFileFormat(StreamKey);
          case CertType of
            cfDER :
              try
                Cert.LoadFromStream(StreamKey);
                KeyLoaded := true;
              except
                on E : Exception do
                  ErrorMsg := E.Message;
              end;
            cfPEM :
            begin
              R := Cert.LoadFromStreamPEM(StreamKey, editPassphrase.Text);
              if R <> 0 then
                ErrorMsg := 'PEM read error: ' + IntToStr(R)
              else
                KeyLoaded := true;
            end;
            cfPFX :
            begin
              R := Cert.LoadFromStreamPFX(StreamKey, editPassphrase.Text);
              if R <> 0 then
                ErrorMsg := 'PFX read error: ' + IntToStr(R)
              else
                KeyLoaded := true;
            end;
            cfSPC :
            begin
              R := Cert.LoadFromStreamSPC(StreamKey);
              if R <> 0 then
                ErrorMsg := 'SPC read error: ' + IntToStr(R)
              else
                KeyLoaded := true;
            end;
          end;
          if not KeyLoaded then
            raise Exception.Create(ErrorMsg);
          KeyMaterial.Assign(Cert.KeyMaterial);
        finally
          FreeAndNil(StreamKey);
          FreeAndNil(Cert);
        end;

      end
      else
      begin
        StreamKey := TFileStream.Create(editKeyFile.Text, fmOpenRead or fmShareDenyWrite);
        try
          if KeyMaterial is TElRSAKeyMaterial then
            TElRSAKeyMaterial(KeyMaterial).Passphrase := editPassphrase.Text
          else if KeyMaterial is TElDSAKeyMaterial then
            TElDSAKeyMaterial(KeyMaterial).Passphrase := editPassphrase.Text;
          try
            KeyMaterial.LoadPublic(StreamKey);
            KeyLoaded := true;
          except
            on E : Exception do
              ErrorMsg := E.Message;
          end;
          if not KeyLoaded then
            try
              StreamKey.Position := 0;
              KeyMaterial.LoadSecret(StreamKey);
              KeyLoaded := true;
            except
              on E : Exception do
                ErrorMsg := ErrorMsg + ','#13#10 + E.Message;
            end;
        finally
          FreeAndNil(StreamKey);
        end;
        if not KeyLoaded then
          raise Exception.Create('There were errors reading key material:'#13#10 + ErrorMsg);
      end;

      // setting properties of crypto class
      Crypto.KeyMaterial := KeyMaterial;

      // validating the signature
      StreamInput := TFileStream.Create(editInputFile.Text, fmOpenRead);
      try
        StreamSignature := TFileStream.Create(editSignatureFile.Text, fmOpenRead);
        try
          VR := Crypto.VerifyDetached(StreamInput, StreamSignature);
        finally
          FreeAndNil(StreamSignature);
        end;
      finally
        FreeAndNil(StreamInput);
      end;
      case VR of
        pkvrSuccess :
          MessageDlg('Verification succeeded', mtInformation, [mbOk], 0);
        pkvrFailure :
          MessageDlg('Verification failed', mtError, [mbOk], 0);
        pkvrInvalidSignature :
          MessageDlg('Invalid signature', mtError, [mbOk], 0);
        pkvrKeyNotFound :
          MessageDlg('Validation key not found', mtError, [mbOk], 0);
      end;
    finally
      FreeAndNil(KeyMaterial);
      FreeAndNil(Crypto);
    end;
  except
    on E : Exception do
      MessageDlg(E.Message, mtError, [mbOk], 0);
  end;

  Close;
end;

procedure TfrmMainForm.btnCancelClick(Sender: TObject);
begin
  Close;
end;

procedure TfrmMainForm.btnBrowseInputFileClick(Sender: TObject);
begin
  if dlgOpenDialog.Execute then
    editInputFile.Text := dlgOpenDialog.FileName;
end;

procedure TfrmMainForm.btnBrowseOutputFileClick(Sender: TObject);
begin
  if dlgOpenDialog.Execute then
    editSignatureFile.Text := dlgOpenDialog.FileName;
end;

procedure TfrmMainForm.btnBrowseKeyClick(Sender: TObject);
begin
  if dlgOpenKey.Execute then
    editKeyFile.Text := dlgOpenKey.FileName;
end;

procedure TfrmMainForm.btnVerifyClick(Sender: TObject);
begin
  if not FileExists(editInputFile.Text) then
    MessageDlg('Source file not found', mtError, [mbOk], 0)
  else if not FileExists(editSignatureFile.Text) then
    MessageDlg('Signature file not found', mtError, [mbOk], 0)
  else if not FileExists(editKeyFile.Text) then
    MessageDlg('Key or certificate file not found', mtError, [mbOk], 0)
  else
    DoVerifyDetached;
end;

procedure TfrmMainForm.FormCreate(Sender: TObject);
begin
  comboAlg.ItemIndex := 0;
  comboInputEncoding.ItemIndex := 0;
  comboKeyContainerType.ItemIndex := 0;
end;

initialization

{$ifndef CRYPTOBLACKBOX}
#error Please pick the evaluation license key from <SecureBlackbox>\LicenseKey.txt file and place it here. If the evaluation key expires, you can request an extension using the form on https://www.eldos.com/sbb/keyreq/
SetLicenseKey('<put the key here>');
{$endif}

end.
