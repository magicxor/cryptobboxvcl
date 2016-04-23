unit Unit1;

{$i Encrypt.inc}

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms,
  Dialogs, ExtCtrls, StdCtrls, SBPublicKeyCrypto, SBTypes, SBUtils, SBX509;

type
  TfrmMainForm = class(TForm)
    btnEncrypt: TButton;
    btnCancel: TButton;
    dlgOpenDialog: TOpenDialog;
    dlgSaveDialog: TSaveDialog;
    dlgOpenKey: TOpenDialog;
    gbSettings: TGroupBox;
    lblInputFile: TLabel;
    lblAlgorithm: TLabel;
    lblPassword: TLabel;
    lblKeyFilename: TLabel;
    lblOutputFile: TLabel;
    lblInputEncoding: TLabel;
    lblOutputEncoding: TLabel;
    editInputFile: TEdit;
    btnBrowseInputFile: TButton;
    comboAlg: TComboBox;
    btnBrowseKey: TButton;
    editKeyFile: TEdit;
    editPassphrase: TEdit;
    btnBrowseOutputFile: TButton;
    editOutputFile: TEdit;
    comboInputEncoding: TComboBox;
    comboOutputEncoding: TComboBox;
    lblKeyContainerType: TLabel;
    comboKeyContainerType: TComboBox;
    procedure btnCancelClick(Sender: TObject);
    procedure btnBrowseInputFileClick(Sender: TObject);
    procedure btnBrowseOutputFileClick(Sender: TObject);
    procedure btnEncryptClick(Sender: TObject);
    procedure btnBrowseKeyClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    { Private declarations }
    procedure DoEncrypt;
  public
    { Public declarations }
  end;

var
  frmMainForm: TfrmMainForm;

implementation

{$R *.dfm}

procedure TfrmMainForm.DoEncrypt;
var
  Crypto : TElRSAPublicKeyCrypto;
  StreamInput, StreamOutput, StreamKey: TFileStream;
  KeyLoaded : Boolean;
  KeyMaterial : TElRSAKeyMaterial;
  Cert : TElX509Certificate;
  CertType : TSBCertFileFormat;
  ErrorMsg : string;
  R : integer;
begin
  Crypto := TElRSAPublicKeyCrypto.Create();
  KeyMaterial := TElRSAKeyMaterial.Create;

  try
    try
      // load certificate/key
      KeyLoaded := false;
      if comboKeyContainerType.ItemIndex = 1 then
      begin
        Cert := TElX509Certificate.Create(nil);
        StreamKey := TFileStream.Create(editKeyFile.Text, fmOpenRead or fmShareDenyWrite);
        try
          CertType := Cert.DetectCertFileFormat(StreamKey);
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
          FreeAndNil(streamKey);
          FreeAndNil(Cert);
        end;
      end
      else
      begin
        StreamKey := TFileStream.Create(editKeyFile.Text, fmOpenRead or fmShareDenyWrite);
        try
          KeyMaterial.Passphrase := editPassphrase.Text;
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

      Crypto.KeyMaterial := KeyMaterial;
      if comboInputEncoding.ItemIndex = 0 then
        Crypto.InputEncoding := pkeBinary
      else
        Crypto.InputEncoding := pkeBase64;
      if comboOutputEncoding.ItemIndex = 0 then
        Crypto.OutputEncoding := pkeBinary
      else
        Crypto.OutputEncoding := pkeBase64;

      StreamInput := TFileStream.Create(editInputFile.Text, fmOpenRead);
      try
        StreamOutput := TFileStream.Create(editOutputFile.Text, fmCreate);
        try
          Crypto.Encrypt(StreamInput, StreamOutput);
        finally
          FreeAndNil(StreamOutput);
        end;
      finally
        FreeAndNil(StreamInput);
      end;

    finally
      FreeAndNil(KeyMaterial);
      FreeAndNil(Crypto);
    end;

    MessageDlg('The file was encrypted successfully', mtInformation, [mbOk], 0);

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
  if dlgSaveDialog.Execute then
    editOutputFile.Text := dlgSaveDialog.FileName;
end;

procedure TfrmMainForm.btnBrowseKeyClick(Sender: TObject);
begin
  if dlgOpenKey.Execute then
    editKeyFile.Text := dlgOpenKey.FileName;
end;

procedure TfrmMainForm.btnEncryptClick(Sender: TObject);
begin
  if not FileExists(editInputFile.Text) then
    MessageDlg('Source file not found', mtError, [mbOk], 0)
  else if editOutputFile.Text = '' then
    MessageDlg('Please provide a valid name for the output file', mtError, [mbOk], 0)
  else if not FileExists(editKeyFile.Text) then
    MessageDlg('Key container file not found', mtError, [mbOk], 0)
  else
    DoEncrypt;
end;

procedure TfrmMainForm.FormCreate(Sender: TObject);
begin
  comboKeyContainerType.ItemIndex := 0;
  comboAlg.ItemIndex := 0;
  comboInputEncoding.ItemIndex := 0;
  comboOutputEncoding.ItemIndex := 0;
end;

initialization

{$ifndef CRYPTOBLACKBOX}
#error Please pick the evaluation license key from <SecureBlackbox>\LicenseKey.txt file and place it here. If the evaluation key expires, you can request an extension using the form on https://www.eldos.com/sbb/keyreq/
SetLicenseKey('<put the key here>');
{$endif}

end.
