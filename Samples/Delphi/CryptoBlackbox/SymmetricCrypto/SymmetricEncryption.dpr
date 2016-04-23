program SymmetricEncryption;

uses
  Forms,
  MainFrm in 'MainFrm.pas' {Form1};

{$R *.RES}

begin
  Application.Initialize;
  Application.CreateForm(TfmMain, fmMain);
  Application.Run;
end.
