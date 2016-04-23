object fmMain: TfmMain
  Left = 283
  Top = 153
  BorderStyle = bsDialog
  Caption = 'Symmetric Encryption Sample'
  ClientHeight = 243
  ClientWidth = 352
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
    Top = 16
    Width = 55
    Height = 13
    Caption = 'Input string:'
  end
  object Label4: TLabel
    Left = 16
    Top = 64
    Width = 49
    Height = 13
    Caption = 'Password:'
  end
  object Label5: TLabel
    Left = 16
    Top = 160
    Width = 80
    Height = 13
    Caption = 'Decrypted string:'
  end
  object Label2: TLabel
    Left = 16
    Top = 112
    Width = 84
    Height = 13
    Caption = 'Encrypted output:'
  end
  object edInputStr: TEdit
    Left = 16
    Top = 32
    Width = 321
    Height = 21
    TabOrder = 0
    Text = 'Input String'
  end
  object edEncryptedStr: TEdit
    Left = 16
    Top = 128
    Width = 321
    Height = 21
    TabOrder = 1
  end
  object bbEncrypt: TButton
    Left = 96
    Top = 206
    Width = 75
    Height = 25
    Caption = 'Encrypt'
    TabOrder = 2
    OnClick = bbEncryptClick
  end
  object bbDecrypt: TButton
    Left = 176
    Top = 206
    Width = 75
    Height = 25
    Caption = 'Decrypt'
    TabOrder = 3
    OnClick = bbDecryptClick
  end
  object edDecryptedStr: TEdit
    Left = 16
    Top = 176
    Width = 321
    Height = 21
    ReadOnly = True
    TabOrder = 4
  end
  object edPassword: TEdit
    Left = 16
    Top = 80
    Width = 321
    Height = 21
    TabOrder = 5
  end
end
