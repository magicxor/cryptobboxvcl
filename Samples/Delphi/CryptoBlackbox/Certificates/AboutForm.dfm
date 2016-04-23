object frmAbout: TfrmAbout
  Left = 192
  Top = 107
  BorderStyle = bsDialog
  Caption = 'About'
  ClientHeight = 147
  ClientWidth = 234
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poScreenCenter
  PixelsPerInch = 96
  TextHeight = 13
  object lTitle: TLabel
    Left = 0
    Top = 24
    Width = 233
    Height = 13
    Alignment = taCenter
    AutoSize = False
    Caption = 'X.509 certificates demo application'
  end
  object lProduct: TLabel
    Left = 0
    Top = 48
    Width = 233
    Height = 13
    Alignment = taCenter
    AutoSize = False
    Caption = 'EldoS SecureBlackbox library'
  end
  object lCopyright: TLabel
    Left = 0
    Top = 72
    Width = 233
    Height = 13
    Alignment = taCenter
    AutoSize = False
    Caption = 'Copyright (C) 2006-2011 EldoS Corporation'
  end
  object btnOK: TButton
    Left = 80
    Top = 104
    Width = 75
    Height = 25
    Cancel = True
    Caption = 'OK'
    Default = True
    ModalResult = 1
    TabOrder = 0
  end
end
