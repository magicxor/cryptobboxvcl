unit MainFrm;

{$i SymmetricEncryption.inc}

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  StdCtrls, SBTypes, SBUtils, SBSymmetricCrypto, SBConstants, SBHashFunction, SBEncoding;

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
    procedure bbEncryptClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure bbDecryptClick(Sender: TObject);
  private
    { Private declarations }
    FFactory : TElSymmetricCryptoFactory;
  public
    { Public declarations }
  end;

var
  fmMain: TfmMain;

implementation

{$R *.DFM}

// This function converts a password into an encryption key using SHA-256 hash
// function. Initialization vector is filled with zeros.
// NEVER do this in real life since this makes security void.
// Instead you should convert a password to encryption key using some
// password derivation function (see PKCS#5 for details).
function PasswordToKeyMaterial(const Pass: string): TElSymmetricKeyMaterial;
var
  Hash : TElHashFunction;
  PassBytes : ByteArray;
  Digest : ByteArray;
  IV : ByteArray;
begin
  SetLength(IV, 16);
  FillChar(IV[0], 16, 0);

  Hash := TElHashFunction.Create(SB_ALGORITHM_DGST_SHA256);
  try
    PassBytes := SBUtils.BytesOfString(Pass);
    Hash.Update(@PassBytes[0], Length(PassBytes));
    Digest := Hash.Finish;
  finally
    FreeAndNil(Hash);
  end;

  Result := TElSymmetricKeyMaterial.Create;
  Result.Key := Digest; // set 256-bit key
  Result.IV := IV; // set 128-bit initialization vector
end;

procedure TfmMain.bbEncryptClick(Sender: TObject);
var
  Crypto : TElSymmetricCrypto;
  KeyMaterial : TElSymmetricKeyMaterial;
  InBuf, OutBuf : ByteArray;
  OutSize : integer;
begin
  Crypto := FFactory.CreateInstance(SB_ALGORITHM_CNT_AES256, cmDefault);
  try
    try
      Crypto.KeyMaterial := PasswordToKeyMaterial(edPassword.Text);

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
  KeyMaterial : TElSymmetricKeyMaterial;
  InBuf, OutBuf : ByteArray;
  OutSize : integer;
begin
  Crypto := FFactory.CreateInstance(SB_ALGORITHM_CNT_AES256, cmDefault);
  try
    try
      Crypto.KeyMaterial := PasswordToKeyMaterial(edPassword.Text);

      InBuf := SBEncoding.Base64DecodeArray(edEncryptedStr.Text);

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

initialization

{$ifndef CRYPTOBLACKBOX}
#error Please pick the evaluation license key from <SecureBlackbox>\LicenseKey.txt file and place it here. If the evaluation key expires, you can request an extension using the form on https://www.eldos.com/sbb/keyreq/
SetLicenseKey('<put the key here>');
{$endif}

end.
