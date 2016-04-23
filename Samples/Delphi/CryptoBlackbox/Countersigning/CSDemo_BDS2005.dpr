program CSDemo_BDS2005;

uses
  Forms,
  MainForm in 'MainForm.pas' {frmMain};



begin
  Application.Initialize;
  Application.CreateForm(TfrmMain, frmMain);
  Application.Run;
end.
