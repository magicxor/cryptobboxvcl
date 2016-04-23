unit MainFrm;

{$i SymmetricEncryptionWithJS.inc}

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  StdCtrls, SBTypes, SBUtils, SBSymmetricCrypto, SBConstants, SBHashFunction,
  SBEncoding, SBPKCS5, SBRandom;

type
  TfmMain = class(TForm)
    edInputStr: TEdit;
    Label1: TLabel;
    edEncryptedStr: TEdit;
    bbEncrypt: TButton;
    bbDecrypt: TButton;
    edDecryptedStr: TEdit;
    edPassword: TEdit;
    Label4: TLabel;
    Label5: TLabel;
    Label2: TLabel;
    bbGenerateKey: TButton;
    Label7: TLabel;
    Label8: TLabel;
    Label9: TLabel;
    Label6: TLabel;
    edSalt: TEdit;
    edKey: TEdit;
    edIV: TEdit;
    Label3: TLabel;
    procedure bbEncryptClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure bbDecryptClick(Sender: TObject);
    procedure bbGenerateKeyClick(Sender: TObject);
  private
    { Private declarations }
    FFactory : TElSymmetricCryptoFactory;
    function CreateKeyMaterial: TElSymmetricKeyMaterial;
  public
    { Public declarations }
  end;

var
  fmMain: TfmMain;

implementation

{$R *.DFM}


function TfmMain.CreateKeyMaterial: TElSymmetricKeyMaterial;
var
  IV, Key : ByteArray;
  Size : integer;
begin
  if (Length(edKey.Text) <> 256 div 4) or (Length(edIV.Text) <> 128 div 4) then
    raise Exception.Create('Empty or invalid Key/IV value!');

  SetLength(IV, 16);
  Size := 16;
  SBUtils.StringToBinary(edIV.Text, @IV[0], Size);
  SetLength(IV, Size);

  SetLength(Key, 32);
  Size := 32;
  SBUtils.StringToBinary(edKey.Text, @Key[0], Size);
  SetLength(Key, Size);


  Result := TElSymmetricKeyMaterial.Create;
  Result.Key := Key;
  Result.IV := IV;
end;

procedure TfmMain.bbEncryptClick(Sender: TObject);
var
  Crypto : TElSymmetricCrypto;
  KeyMaterial : TElSymmetricKeyMaterial;
  InBuf, OutBuf : ByteArray;
  OutSize : integer;
begin
  Crypto := FFactory.CreateInstance(SB_ALGORITHM_CNT_AES256, cmCBC);
  try
    try
      KeyMaterial := CreateKeyMaterial;
      Crypto.KeyMaterial := KeyMaterial;

      InBuf := SBUtils.BytesOfString(edInputStr.Text);

      OutSize := 0;
      Crypto.Encrypt(@InBuf[0], Length(InBuf), nil, OutSize);
      SetLength(OutBuf, OutSize);
      Crypto.Encrypt(@InBuf[0], Length(InBuf), @OutBuf[0], OutSize);
      SetLength(OutBuf, OutSize);

      // convert binary output to Base64 to make it readable
      edEncryptedStr.Text := SBEncoding.Base64EncodeArray(OutBuf, false);
    except
      on Ex : Exception do
        ShowMessage('Encryption error: ' + Ex.Message);
    end;
  finally
    FreeAndNil(Crypto);
    FreeAndNil(KeyMaterial);
  end;
end;

procedure TfmMain.FormCreate(Sender: TObject);
begin
  FFactory := TElSymmetricCryptoFactory.Create;
end;

procedure TfmMain.FormDestroy(Sender: TObject);
begin
  FreeAndNil(FFactory);
end;

procedure TfmMain.bbDecryptClick(Sender: TObject);
var
  Crypto : TElSymmetricCrypto;
  InBuf, OutBuf : ByteArray;
  BufSt : AnsiString;
  OutSize : integer;
begin
  Crypto := FFactory.CreateInstance(SB_ALGORITHM_CNT_AES256, cmCBC);
  try
    try
      InBuf := SBEncoding.Base64DecodeArray(edEncryptedStr.Text);
      BufSt := StringOfBytes(InBuf);

      Crypto.KeyMaterial := CreateKeyMaterial;

      OutSize := 0;
      Crypto.Decrypt(@InBuf[0], Length(InBuf), nil, OutSize);
      SetLength(OutBuf, OutSize);
      Crypto.Decrypt(@InBuf[0], Length(InBuf), @OutBuf[0], OutSize);
      SetLength(OutBuf, OutSize);

      edDecryptedStr.Text := SBUtils.StringOfBytes(OutBuf);
    except
      on Ex : Exception do
        ShowMessage('Decryption error: ' + Ex.Message);
    end;
  finally
    FreeAndNil(Crypto);
  end;
end;

procedure TfmMain.bbGenerateKeyClick(Sender: TObject);
var
  salt : AnsiString;
  key : ByteArray;
  Size : integer;
  PBE : TElPKCS5PBE;  
  //keyMaterial : TElSymmetricKeyMaterial;
begin
  { generating new salt if field is empty, otherwise using pasted value }
  if Length(edSalt.Text) = 0 then
  begin
    SetLength(salt, 8);
    SBRndGenerate(@salt[1], 8);
    edSalt.Text := SBUtils.BinaryToString(@salt[1], 8);
  end
  else
  begin
    Size := (Length(edSalt.Text) div 2) + 1;
    SetLength(salt, Size);
    SBUtils.StringToBinary(edSalt.Text, @salt[1], Size);
    SetLength(salt, Size);
  end;

  PBE := TElPKCS5PBE.Create(SB_ALGORITHM_CNT_AES128 {doesn't matter as we do not intend to do any encryption}, SB_ALGORITHM_DGST_SHA256, true);
  try
    PBE.Salt := BytesOfString(salt);
    PBE.IterationCount := 1;
    key := PBE.DeriveKey(edPassword.Text, 256 + 128);
  finally
    FreeAndNil(PBE);
  end;

  (*  
  // this will work in the next SBB update
  keyMaterial := TElSymmetricKeyMaterial.Create;

  try
    { deriving 256-bit key and 128-bit IV, using PBKDF2 function and 1 iteration }
    keyMaterial.DeriveKey(256 + 128, edPassword.Text, BytesOfString(salt), 1);
    key := keyMaterial.Key;
  finally
    FreeAndNil(keyMaterial);
  end;*)

  edKey.Text := SBUtils.BinaryToString(@key[0], 256 div 8);
  edIV.Text := SBUtils.BinaryToString(@key[256 div 8], 128 div 8);
end;

initialization

{$ifndef CRYPTOBLACKBOX}
#error Please pick the evaluation license key from <SecureBlackbox>\LicenseKey.txt file and place it here. If the evaluation key expires, you can request an extension using the form on https://www.eldos.com/sbb/keyreq/
SetLicenseKey('<put the key here>');
{$endif}

end.
