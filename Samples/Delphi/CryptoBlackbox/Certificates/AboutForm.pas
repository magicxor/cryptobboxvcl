unit AboutForm;

interface

uses
  Windows,Messages,SysUtils,Classes,Graphics,Controls,Forms,Dialogs,StdCtrls;

type
  TfrmAbout = class(TForm)
    lTitle: TLabel;
    lProduct: TLabel;
    lCopyright: TLabel;
    btnOK: TButton;
  private
    { Private declarations }
  public
    { Public declarations }
    class procedure ShowAboutBox;
  end;

var
  frmAbout: TfrmAbout;

implementation

{$R *.DFM}

{ TfrmAbout }

class procedure TfrmAbout.ShowAboutBox;
begin
  with TfrmAbout.Create(nil) do ShowModal;
end;

end.
