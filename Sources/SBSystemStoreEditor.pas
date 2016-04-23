
(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBSystemStoreEditor;

interface

uses
{$ifdef SB_WINDOWS}
  Windows,
 {$else}
  {$ifndef FPC}Libc, {$endif}
 {$endif}
  Messages, SysUtils,  Classes, Graphics, Controls, Forms,
  StdCtrls,
  TypInfo,
  {$ifdef VCL60}
  DesignEditors,
  DesignConst,
  DesignIntf,
   {$else}
  DsgnIntf,
   {$endif}
  SBTypes,
  SBUtils,
  SBWinCrypt;

type
  TElSystemStorePropertyEditor = class(TPropertyEditor)
  public
    procedure Edit; override;
    function GetAttributes : TPropertyAttributes; override;
    function GetValue : string; override;
  end;

type
  TSystemStoreEditorForm = class(TForm)
    LRButton: TButton;
    RLButton: TButton;
    OKButton: TButton;
    CancelButton: TButton;
    LeftList: TListBox;
    RightList: TListBox;
    MainGroupBox: TGroupBox;
    Label1: TLabel;
    Label2: TLabel;
    procedure FormShow(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure LRButtonClick(Sender: TObject);
    procedure RLButtonClick(Sender: TObject);
    procedure OKButtonClick(Sender: TObject);
    procedure CancelButtonClick(Sender: TObject);
  private
    { Private declarations }
    FValue : TStringList;
    Stores : TStringList;
    LeftPanel, RightPanel : TStringList;
    procedure Refresh;
    procedure SetAbsent;
  public
    { Public declarations }
    procedure Initialize;
    procedure SetPresent(List : TStringList);
    property Value : TStringList read FValue;
  end;

procedure Register;

implementation

uses
  SBWinCertStorage;

procedure TElSystemStorePropertyEditor.Edit;
var
  I : integer;
  Obj : TPersistent;
  frm : TSystemStoreEditorForm;
begin
  frm := TSystemStoreEditorForm.Create(Application);
  with frm do
  try
//    Obj := TPersistent.Create;
    Obj := GetComponent(0);
    SetPresent(TElWinCertStorage(Obj).SystemStores);
    frm.Initialize;
    if ShowModal = mrOk then
      begin
        TElWinCertStorage(Obj).SystemStores.Clear;
        for I := 0 to Value.Count - 1 do
          TElWinCertStorage(Obj).SystemStores.Add(Value.Strings[I]);
      end;
  finally
    Free;
  end;
end;

function TElSystemStorePropertyEditor.GetAttributes: TPropertyAttributes;
begin
  GetAttributes := [paDialog];
end;

function TElSystemStorePropertyEditor.GetValue : string;
begin
  Result := '(TStrings)';
end;

{$R *.dfm}

procedure TSystemStoreEditorForm.FormShow(Sender: TObject);
begin
  Refresh;
end;

procedure TSystemStoreEditorForm.FormCreate(Sender: TObject);
begin
  LeftPanel := TElStringList.Create;
  RightPanel := TElStringList.Create;
  Stores := TElStringList.Create;
  FValue := TElStringList.Create;
  Initialize;
end;

procedure TSystemStoreEditorForm.FormDestroy(Sender: TObject);
begin
  LeftPanel.Free;
  RightPanel.Free;
  Stores.Free;
  FValue.Free;
end;

procedure TSystemStoreEditorForm.LRButtonClick(Sender: TObject);
begin
  if (LeftList.ItemIndex > LeftList.Items.Count - 1) or (LeftList.ItemIndex < 0) then
    exit;
  RightPanel.Add(LeftPanel.Strings[LeftList.ItemIndex]);
  LeftPanel.Delete(LeftList.ItemIndex);
  Refresh;
end;

procedure TSystemStoreEditorForm.RLButtonClick(Sender: TObject);
begin
  if (RightList.ItemIndex > RightList.Items.Count - 1) or (RightList.ItemIndex < 0) then
    exit;
  LeftPanel.Add(RightPanel.Strings[RightList.ItemIndex]);
  RightPanel.Delete(RightList.ItemIndex);
  Refresh;
end;

procedure TSystemStoreEditorForm.OKButtonClick(Sender: TObject);
var
  I : integer;
begin
  Value.Clear;
  for I := 0 to RightPanel.Count - 1 do
    Value.Add(RightPanel.Strings[I]);
  ModalResult := mrOk;
end;

procedure TSystemStoreEditorForm.CancelButtonClick(Sender: TObject);
begin
  ModalResult := mrCancel;
end;

procedure TSystemStoreEditorForm.Refresh;
var
  I : integer;
begin
  LeftList.Clear;
  RightList.Clear;
  for I := 0 to LeftPanel.Count - 1 do
    LeftList.Items.Add(LeftPanel.Strings[I]);
  for I := 0 to RightPanel.Count - 1 do
    RightList.Items.Add(RightPanel.Strings[I]);
end;

function CBF(pvSystemStore: Pointer; dwFlags: DWORD; pStoreInfo: PCERT_SYSTEM_STORE_INFO;
  pvReserved: Pointer; pvArg: Pointer): BOOL; stdcall;
begin
  TStringList(pvArg).Add(WideCharToString(pvSystemStore));
  Result := true;
end;

procedure TSystemStoreEditorForm.Initialize;
var
  ModuleHandle : HMODULE;
  Flag : boolean;
  P : pointer;
begin
  Stores.Clear;
  Flag := true;
  ModuleHandle := GetModuleHandle(PChar('crypt32.dll'));
  if ModuleHandle = 0 then
    begin
      ModuleHandle := LoadLibrary(PChar('crypt32.dll'));
      if ModuleHandle = 0 then
        begin
          Flag := false;
        end
      else
        begin
          P := GetProcAddress(ModuleHandle, PChar('CertEnumSystemStore'));
          if not Assigned(P) then
            Flag := false;
        end;
    end;
  if not Flag then
    begin
      Stores.Add('ROOT');
      Stores.Add('CA');
      Stores.Add('MY');
      Stores.Add('SPC');
    end
  else
    begin
      if not CertEnumSystemStore(CERT_SYSTEM_STORE_CURRENT_USER, nil, Stores, CBF) then
        raise Exception.Create('Cannot load store names');
    end;
  SetAbsent;
end;

procedure TSystemStoreEditorForm.SetPresent(List : TStringList);
var
  I : integer;
begin
  RightPanel.Clear;
  for I := 0 to List.Count - 1 do
    RightPanel.Add(List.Strings[I]);
end;

procedure TSystemStoreEditorForm.SetAbsent;
var
  I : integer;
begin
  LeftPanel.Clear;
  for I := 0 to Stores.Count - 1 do
    begin
      if RightPanel.IndexOf(Stores.Strings[I]) = -1 then
        LeftPanel.Add(Stores.Strings[I]);
    end;
end;

procedure Register;
begin
  RegisterPropertyEditor(TypeInfo(TStrings), TElWinCertStorage, 'SystemStores', TElSystemStorePropertyEditor);
end;

end.
