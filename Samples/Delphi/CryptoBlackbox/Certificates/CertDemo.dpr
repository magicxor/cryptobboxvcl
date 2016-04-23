program CertDemo;

{%ToDo 'CertDemo.todo'}

uses
  Forms,
  frmMain in 'frmMain.pas' {MainForm},
  SelectStorage in 'SelectStorage.pas' {StorageSelectForm},
  CountryList in 'CountryList.pas',
  AboutForm in 'AboutForm.pas' {frmAbout},
  ExtensionEncoder in 'ExtensionEncoder.pas',
  uValidate in 'uValidate.pas' {frmValidate};

begin
  Application.Initialize;
  Application.CreateForm(TMainForm, MainForm);
  Application.CreateForm(TfrmAbout, frmAbout);
  Application.Run;
end.
