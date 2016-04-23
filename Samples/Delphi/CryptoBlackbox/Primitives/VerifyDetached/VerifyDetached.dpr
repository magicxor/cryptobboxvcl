program VerifyDetached;

uses
  Forms,
  Unit1 in 'Unit1.pas' {frmMainForm};



begin
  Application.Initialize;
  Application.CreateForm(TfrmMainForm, frmMainForm);
  Application.Run;
end.
