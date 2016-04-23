program Encrypt;

uses
  Forms,
  Unit1 in 'Unit1.pas' {frmMainForm};



begin
  Application.Initialize;
  Application.Title := 'ElPublicKeyCrypto encryption demo';
  Application.CreateForm(TfrmMainForm, frmMainForm);
  Application.Run;
end.
