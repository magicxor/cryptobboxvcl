program Decrypt_BDS2005;

uses
  Forms,
  Unit1 in 'Unit1.pas' {frmMainForm};



begin
  Application.Initialize;
  Application.Title := 'ElPublicKeyCrypto decryption demo';
  Application.CreateForm(TfrmMainForm, frmMainForm);
  Application.Run;
end.
