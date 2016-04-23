program CSDemo;

uses
  Forms,
  MainForm in 'MainForm.pas' {frmMain};



begin
  Application.Initialize;
  Application.CreateForm(TfrmMain, frmMain);
  Application.Run;
end.
