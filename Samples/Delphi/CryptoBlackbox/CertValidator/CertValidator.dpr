program CertValidator;

{$i CertValidator.inc}

uses
  Forms,
  MainFrm in 'MainFrm.pas' {Form1}
  {$ifndef CRYPTOBLACKBOX}
  , CustomTransports in 'CustomTransports.pas'
  {$endif}
  ;

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
