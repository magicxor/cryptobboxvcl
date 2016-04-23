object fmMain: TfmMain
  Left = 686
  Top = 363
  BorderStyle = bsDialog
  Caption = 'Symmetric Encryption with JavaScript Sample'
  ClientHeight = 403
  ClientWidth = 357
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  PixelsPerInch = 96
  TextHeight = 13
  object Label1: TLabel
    Left = 16
    Top = 120
    Width = 80
    Height = 13
    Caption = 'String to encrypt:'
  end
  object Label4: TLabel
    Left = 16
    Top = 168
    Width = 49
    Height = 13
    Caption = 'Password:'
  end
  object Label5: TLabel
    Left = 16
    Top = 328
    Width = 80
    Height = 13
    Caption = 'Decrypted string:'
  end
  object Label2: TLabel
    Left = 16
    Top = 280
    Width = 335
    Height = 13
    Caption = 
      'Encrypted, base64-encoded output (can be with salt, like in Open' +
      'SSL):'
  end
  object Label7: TLabel
    Left = 16
    Top = 232
    Width = 21
    Height = 13
    Caption = 'Key:'
  end
  object Label8: TLabel
    Left = 16
    Top = 256
    Width = 13
    Height = 13
    Caption = 'IV:'
  end
  object Label9: TLabel
    Left = 16
    Top = 192
    Width = 21
    Height = 13
    Caption = 'Salt:'
  end
  object Label6: TLabel
    Left = 16
    Top = 8
    Width = 324
    Height = 78
    Caption = 
      'Javascript-compatible encryption (crypto-js) demo. You can use p' +
      'assword to generate key and iv, or paste  hex-encoded key and iv' +
      '. Salt is used to randomize password and should be passed with p' +
      'assword to JavaScript. This sample uses PBKDF2 key-derivation fu' +
      'nction, and AES-256 CBC encryption with  PKCS#5 (PKCS#7) padding' +
      '.'
    WordWrap = True
  end
  object Label3: TLabel
    Left = 72
    Top = 208
    Width = 220
    Height = 13
    Caption = '* clear Salt value to generate new salt and key'
  end
  object edInputStr: TEdit
    Left = 16
    Top = 136
    Width = 329
    Height = 21
    TabOrder = 0
    Text = 'Input String!!!'
  end
  object edEncryptedStr: TEdit
    Left = 16
    Top = 296
    Width = 329
    Height = 21
    TabOrder = 1
  end
  object bbEncrypt: TButton
    Left = 96
    Top = 374
    Width = 75
    Height = 25
    Caption = 'Encrypt'
    TabOrder = 2
    OnClick = bbEncryptClick
  end
  object bbDecrypt: TButton
    Left = 176
    Top = 374
    Width = 75
    Height = 25
    Caption = 'Decrypt'
    TabOrder = 3
    OnClick = bbDecryptClick
  end
  object edDecryptedStr: TEdit
    Left = 16
    Top = 344
    Width = 329
    Height = 21
    ReadOnly = True
    TabOrder = 4
  end
  object edPassword: TEdit
    Left = 72
    Top = 160
    Width = 169
    Height = 21
    TabOrder = 5
  end
  object bbGenerateKey: TButton
    Left = 248
    Top = 160
    Width = 97
    Height = 22
    Caption = 'Generate key'
    TabOrder = 6
    OnClick = bbGenerateKeyClick
  end
  object edSalt: TEdit
    Left = 72
    Top = 184
    Width = 273
    Height = 21
    TabOrder = 7
  end
  object edKey: TEdit
    Left = 72
    Top = 224
    Width = 273
    Height = 21
    TabOrder = 8
  end
  object edIV: TEdit
    Left = 72
    Top = 248
    Width = 273
    Height = 21
    TabOrder = 9
  end
end
