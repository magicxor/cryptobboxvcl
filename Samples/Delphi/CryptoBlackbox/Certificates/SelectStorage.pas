unit SelectStorage;

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  StdCtrls, SBCustomCertStorage, SBWinCertStorage, ComCtrls;

type
  TStorageSelectForm = class(TForm)
    lblSelectStorage: TLabel;
    btnOk: TButton;
    treeStorage: TTreeView;
    btnCancel: TButton;
    procedure btnOkClick(Sender: TObject);
    procedure FormActivate(Sender: TObject);
    procedure btnCancelClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  StorageSelectForm: TStorageSelectForm;

implementation

uses frmMain;

{$R *.DFM}

procedure TStorageSelectForm.btnOkClick(Sender: TObject);
begin
  if (treeStorage.Selected <> nil) and (treeStorage.Selected.Data <> nil) then
  begin
    ModalResult := mrOk;
  end
  else
    ShowMessage('Storage is not selected');
end;

procedure TStorageSelectForm.FormActivate(Sender: TObject);
var I, J : integer;
begin
  with treeStorage do
  begin
    Items.Clear;
    Items.Add(nil, 'Storages');
    Items.AddChild(Items[0], 'Windows Storages');
    Items.AddChild(Items[0], 'File Storages');
    Items.AddChild(Items[0], 'Memory Storages');
    for I := 0 to 2 do
      for J := 0 to MainForm.treeCert.Items[0].Item[I].Count - 1 do
        Items.AddChildObject(Items[0].Item[I],
          MainForm.treeCert.Items[0].Item[I].Item[J].Text,
          MainForm.treeCert.Items[0].Item[I].Item[J].Data);
    end;
end;

procedure TStorageSelectForm.btnCancelClick(Sender: TObject);
begin
  if MessageDlg('Are you sure you want to cancel operation?',
    mtConfirmation, [mbYes, mbNo], 0) = mrYes then
  begin
    ModalResult := mrCancel;
  end;
end;

end.
