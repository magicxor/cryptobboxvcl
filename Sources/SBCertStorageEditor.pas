
(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBCertStorageEditor;

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  StdCtrls, ExtCtrls, ComCtrls, SBCustomCertStorage, SBX509, SBConstants,
  SBPKCS12, SBUtils, SBStrUtils, SBTypes,
  {$ifdef VCL60}
  DesignEditors,
  DesignConst,
  DesignIntf,
   {$else}
  DsgnIntf,
   {$endif}
  ImgList;

type
  TCertStorageEditorForm = class(TForm)
    CmdPanel: TPanel;
    BtnPanel: TPanel;
    Button1: TButton;
    Button2: TButton;
    MainPanel: TPanel;
    Panel1: TPanel;
    Label1: TLabel;
    CertList: TListBox;
    Splitter1: TSplitter;
    Panel2: TPanel;
    Label2: TLabel;
    PropList: TListView;
    ExportBtn: TButton;
    ImportBtn: TButton;
    DeleteBtn: TButton;
    OpenDlg: TOpenDialog;
    SaveDlg: TSaveDialog;
    ImageList1: TImageList;
    procedure FormShow(Sender: TObject);
    procedure CertListClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure DeleteBtnClick(Sender: TObject);
    procedure ImportBtnClick(Sender: TObject);
    procedure ExportBtnClick(Sender: TObject);
  private
    { Private declarations }
  protected
    procedure FillCertList;
    procedure UpdateCertProps;
    procedure UpdateButtons;
  public
    Storage : TElCustomCertStorage;
  end;

  TElCertStorageEditor = class(TDefaultEditor)
  public
    procedure ExecuteVerb(Index: integer); override;
    function GetVerb(Index: integer): string; override;
    function GetVerbCount: integer; override;
  end;

var
  CertStorageEditorForm: TCertStorageEditorForm;

procedure Register;

implementation

{$R *.DFM}

const OpenFilterFull = 'Storage from PKCS#12 (*.pfx,*.p12)|*.pfx;*.p12|Certificate from PKCS#12 (*.pfx,*.p12)|*.pfx;*.p12|Certificate from PEM format(*.pem)|*.pem|Certificate from X.509 format (*.cer,*.crt)|*.cer;*.crt';
      OpenFilterStorage = 'Storage from PKCS#12 (*.pfx,*.p12)|*.pfx;*.p12';
      SaveFilterFull = 'Storage to PKCS#12 (*.pfx,*.p12)|*.pfx;*.p12|Certificate to PKCS#12 (*.pfx,*.p12)|*.pfx;*.p12|Certificate to PEM format(*.pem)|*.pem|Certificate to X.509 format (*.cer,*.crt)|*.cer;*.crt';
      SaveFilterStorage = 'Storage to PKCS#12 (*.pfx,*.p12)|*.pfx;*.p12';

function ReplaceExt(const FileName, NewExt: string): string;
var
  i, j, l : integer;
begin
  j := length(FileName);
  i := length(ExtractFileExt(FileName));
  if (j = 0) then
  begin
    result := '';
    exit;
  end;
  l := length(NewExt);
  SetLength(Result, j - i + l);
  SBMove(FileName[1], Result[1], j - i);
  if l > 0 then
    SBMove(NewExt[1], Result[j - i + 1], l);
end;

procedure TCertStorageEditorForm.FormShow(Sender: TObject);
begin
  FillCertList;
  CertListClick(nil);
end;

procedure TCertStorageEditorForm.CertListClick(Sender: TObject);
begin
  UpdateCertProps;
  UpdateButtons;
end;

procedure TCertStorageEditorForm.FillCertList;
var i : integer;
    S : string;
begin
  CertList.Clear;
  for i := 0 to Storage.Count - 1 do
  begin
    S := Storage.Certificates[i].SubjectName.CommonName;
    if Length(S) = 0 then
      S := Storage.Certificates[i].SubjectName.Organization;
    CertList.Items.Add(S);
  end;
end;

procedure TCertStorageEditorForm.UpdateCertProps;
var Item : TListItem;
    X509 : TElX509Certificate;
begin
  PropList.Items.Clear;
  if (CertList.ItemIndex <> -1) and (CertList.ItemIndex < CertList.Items.Count) then
  begin
    X509 := Storage.Certificates[CertList.ItemIndex];

    // Subject
    Item := PropList.Items.Add;
    Item.Caption := 'Subject.Name';
    Item.SubItems.Add(X509.SubjectName.CommonName);

    Item := PropList.Items.Add;
    Item.Caption := 'Subject.Organization';
    Item.SubItems.Add(X509.SubjectName.Organization);

    Item := PropList.Items.Add;
    Item.Caption := 'Subject.OrganizationUnit';
    Item.SubItems.Add(X509.SubjectName.OrganizationUnit);

    Item := PropList.Items.Add;
    Item.Caption := 'Subject.Country';
    Item.SubItems.Add(X509.SubjectName.Country);

    // Issuer
    Item := PropList.Items.Add;
    Item.Caption := 'Issuer.Name';
    Item.SubItems.Add(X509.IssuerName.CommonName);

    Item := PropList.Items.Add;
    Item.Caption := 'Issuer.Organization';
    Item.SubItems.Add(X509.IssuerName.Organization);

    Item := PropList.Items.Add;
    Item.Caption := 'Issuer.OrganizationUnit';
    Item.SubItems.Add(X509.IssuerName.OrganizationUnit);

    Item := PropList.Items.Add;
    Item.Caption := 'Issuer.Country';
    Item.SubItems.Add(X509.IssuerName.Country);

    Item := PropList.Items.Add;
    Item.Caption := 'Valid From';
    Item.SubItems.Add(DateTimeToStr(X509.ValidFrom));

    Item := PropList.Items.Add;
    Item.Caption := 'Valid To';
    Item.SubItems.Add(DateTimeToStr(X509.ValidTo));

//    X509.Free;
  end;
end;

procedure TCertStorageEditorForm.UpdateButtons;
begin
  DeleteBtn.Enabled := CertList.ItemIndex <> -1;
end;

procedure TCertStorageEditorForm.FormCreate(Sender: TObject);
begin
  Storage := TElMemoryCertStorage.Create(nil);
end;

procedure TCertStorageEditorForm.FormDestroy(Sender: TObject);
begin
  Storage.Free;
  Storage := nil;
end;

procedure TCertStorageEditorForm.DeleteBtnClick(Sender: TObject);
begin
  Storage.Remove(CertList.ItemIndex);
  CertList.Items.Delete(CertList.ItemIndex);
  CertListClick(nil);
end;

procedure TCertStorageEditorForm.ImportBtnClick(Sender: TObject);

  procedure LoadStorage(const FileName : string);
  var Stream : TStream;
      Buf : Pointer;
      BufSize : integer;
      S : string;
      err : integer;
  begin
    S := '';
    if InputQuery('File password', 'Enter PFX file password', S) then
    try
      Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
      try
        BufSize := Stream.Size;
        GetMem(Buf, BufSize);
        try
          Stream.ReadBuffer(PChar(Buf)^, BufSize);
          err := Storage.LoadFromBufferPFX(Buf, BufSize, S);
        finally
          FreeMem(Buf);
        end;

        if err <> 0 then
          raise Exception.Create('Error #' + IntToStr(err) + #13#10'(see SecureBlackbox documentation for error details)');
      finally
        Stream.Free;
      end;
      FillCertList;
    except
      on E : Exception do
        MessageDlg('Failed to load the certificate storage from file:' + #13#10 + E.Message, mtError, [mbOk], 0);
    end;
  end;

  procedure LoadFile(const FileName : string; FileType : integer);
  var Stream,
      DERStream : TStream;
      Buf : Pointer;
      BufSize : integer;
      S : string;
      DerFileName : string;
      err : integer;
      X509 : TElX509Certificate;

  begin
    S := '';

    if (FileType in [2, 3]) and (not InputQuery('File password', 'Enter private key password', S)) then
      exit;

    try
      Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
      try
        BufSize := Stream.Size;
        GetMem(Buf, BufSize);
        try
          Stream.ReadBuffer(PChar(Buf)^, BufSize);
          X509 := TElX509Certificate.Create(nil);
          try
            case FileType of
              2: err := X509.LoadFromBufferPFX(Buf, BufSize, S);
              3: err := X509.LoadFromBufferPEM(Buf, BufSize, S);
              4: begin
                   X509.LoadFromBuffer(Buf, BufSize);
                   err := 0;
                 end;
              else
                err := 0;
            end;
            if err <> 0 then
              raise Exception.Create('Error #' + IntToStr(err) + #13#10'(see SecureBlackbox documentation for error details)');
            if FileType = 4 then
            begin
              DerFileName := ReplaceExt(FileName, '.DER');
              if FileExists(DerFileName) then
              begin
                if MessageDlg(Format('File with corresponding private key (%s) has been found.'#13#10'Do you want to import private key too?', [DerFileName]), mtConfirmation, [mbYes, mbNo], 0) = mrYes then
                begin
                  DERStream := TFileStream.Create(DERFileName, fmOpenRead or fmShareDenyWrite);
                  try
                    FreeMem(Buf);
                    Buf := nil;
                    BufSize := DERStream.Size;
                    GetMem(Buf, BufSize);
                    DERStream.ReadBuffer(PChar(Buf)^, BufSize);
                    X509.LoadKeyFromBuffer(Buf, BufSize);
                  finally
                    DERStream.Free;
                  end;
                end;
              end;
            end;
            Storage.Add(X509{$ifndef HAS_DEF_PARAMS}, true {$endif});
            FillCertList;
          finally
            X509.Free;
          end;
        finally
          FreeMem(Buf);
        end;
      finally
        Stream.Free;
      end;
    except
      on E : Exception do
        MessageDlg('Failed to load certificate from file:' + #13#10 + E.Message, mtError, [mbOk], 0);
    end;
  end;

begin
  OpenDlg.Filter := OpenFilterFull;
  if OpenDlg.Execute then
  begin
    if OpenDlg.FilterIndex = 1 then
      LoadStorage(OpenDlg.FileName)
    else
      LoadFile(OpenDlg.FileName, OpenDlg.FilterIndex);
  end;
end;

procedure TCertStorageEditorForm.ExportBtnClick(Sender: TObject);
var SaveDER : boolean;
    Pwd : string;

  procedure SaveFile(const FileName : string; const Password : string; FileType : integer);
  var Stream,
      DERStream : TStream;
      Buf : Pointer;
      BufSize : integer;
      DerFileName : string;
      err : integer;
      X509 : TElX509Certificate;

  begin
    try
      if FileType <> 1 then
        X509 := Storage.Certificates[CertList.ItemIndex]
      else
        X509 := nil;

      Stream := TFileStream.Create(FileName, fmCreate or fmShareDenyWrite);
      try
        BufSize := 0;
        case FileType of
          1: begin
               err := Storage.SaveToBufferPFX(nil, BufSize, Password, SB_ALGORITHM_PBE_SHA1_RC4_128, SB_ALGORITHM_PBE_SHA1_RC4_128);
               if (err = SB_PKCS12_ERROR_BUFFER_TOO_SMALL) and (BufSize > 0) then
               begin
                 GetMem(Buf, BufSize);
                 err := Storage.SaveToBufferPFX(Buf, BufSize, Password, SB_ALGORITHM_PBE_SHA1_RC4_128, SB_ALGORITHM_PBE_SHA1_RC4_128);
                 if err <> 0 then
                   raise Exception.Create('Error #' + IntToStr(err) + #13#10'(see SecureBlackbox documentation for error details)');
                 Stream.WriteBuffer(PChar(Buf)^, BufSize);
                 FreeMem(Buf);
               end
               else
               if err <> 0 then
                 raise Exception.Create('Error #' + IntToStr(err) + #13#10'(see SecureBlackbox documentation for error details)');
             end;
          2: begin
               X509.SaveToStreamPFX(Stream, Password, SB_ALGORITHM_PBE_SHA1_RC4_128, SB_ALGORITHM_PBE_SHA1_RC4_128);
             end;
          3: begin
               X509.SaveToStreamPEM(Stream, Password);
               X509.SaveKeyToStreamPEM(Stream, Password);
             end;
          4: begin
               X509.SaveToStream(Stream);
             end;
        end;
      finally
        Stream.Free;
      end;

      if FileType = 4 then
      begin
        if SaveDer then
        begin
          DerFileName := ReplaceExt(FileName, '.DER');
          DERStream := TFileStream.Create(DERFileName, fmCreate or fmShareDenyWrite);
          try
            X509.SaveKeyToStream(DerStream);
          finally
            DERStream.Free;
          end;
        end;
      end;
    except
      on E : Exception do
        MessageDlg('Failed to save certificate to file:' + #13#10 + E.Message, mtError, [mbOk], 0);
    end;
  end;

begin
  if CertList.ItemIndex <> -1 then
    SaveDlg.Filter := SaveFilterFull
  else
    SaveDlg.Filter := SaveFilterStorage;
  if SaveDlg.Execute then
  begin
    if SaveDlg.FilterIndex = 4 then
    begin
      SaveDER := MessageDlg('Do you want to save corresponding private keys', mtConfirmation, [mbYes, mbNo], 0) = mrYes;
    end;
    if (SaveDlg.FilterIndex <> 4) or SaveDER then
    begin
      Pwd := '';
      if (not InputQuery('File password', 'Enter private key password', Pwd)) then
        exit;
    end;
    SaveFile(SaveDlg.FileName, Pwd, SaveDlg.FilterIndex);
  end;
end;

procedure TElCertStorageEditor.ExecuteVerb(Index: integer);
var AStorage : TElCustomCertStorage;
    Form : TCustomForm;
begin
  if Index = 0 then
  begin
    with TCertStorageEditorForm.Create(nil) do
    try
      AStorage := Component as TElCustomCertStorage;
      AStorage.ExportTo(Storage);
      if ShowModal = mrOk then
      begin
        AStorage.Clear;
        Storage.ExportTo(AStorage);
        if Component.Owner is TCustomForm then
        begin
          Form := TCustomForm(Component.Owner);
          if (Form <> nil) and (Form.Designer <> nil) then Form.Designer.Modified;
        end;
      end;
    finally
      Free;
    end;
  end;
end;

function TElCertStorageEditor.GetVerb(Index: integer): string;
begin
  Result := 'Storage Manager...';
end;

function TElCertStorageEditor.GetVerbCount: integer;
begin
  Result := 1;
end;

procedure Register;
begin
  RegisterComponentEditor(TElMemoryCertStorage, TElCertStorageEditor);
end;

end.
