object frmMainForm: TfrmMainForm
  Left = 220
  Top = 183
  BorderStyle = bsDialog
  Caption = 'ElPublicKeyCrypto detached signature verification demo'
  ClientHeight = 452
  ClientWidth = 629
  Color = clBtnFace
  Font.Charset = RUSSIAN_CHARSET
  Font.Color = clWindowText
  Font.Height = -14
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poScreenCenter
  OnCreate = FormCreate
  PixelsPerInch = 120
  TextHeight = 17
  object btnVerify: TButton
    Left = 220
    Top = 408
    Width = 98
    Height = 33
    Caption = 'Verify'
    Default = True
    TabOrder = 1
    OnClick = btnVerifyClick
  end
  object btnCancel: TButton
    Left = 324
    Top = 408
    Width = 98
    Height = 33
    Cancel = True
    Caption = 'Cancel'
    TabOrder = 2
    OnClick = btnCancelClick
  end
  object gbSettings: TGroupBox
    Left = 10
    Top = 10
    Width = 609
    Height = 389
    Caption = 'Settings'
    TabOrder = 0
    object lblInputFile: TLabel
      Left = 21
      Top = 31
      Width = 91
      Height = 17
      Caption = 'Input filename:'
    end
    object lblAlgorithm: TLabel
      Left = 21
      Top = 178
      Width = 133
      Height = 17
      Caption = 'Encryption algorithm:'
    end
    object lblPassword: TLabel
      Left = 21
      Top = 314
      Width = 63
      Height = 17
      Caption = 'Password:'
    end
    object lblKeyFilename: TLabel
      Left = 21
      Top = 251
      Width = 146
      Height = 17
      Caption = 'Public key container file:'
    end
    object lblSigFile: TLabel
      Left = 21
      Top = 105
      Width = 116
      Height = 17
      Caption = 'Signature filename:'
    end
    object lblInputEncoding: TLabel
      Left = 199
      Top = 178
      Width = 98
      Height = 17
      Caption = 'Input encoding:'
    end
    object lblKeyContainerType: TLabel
      Left = 272
      Top = 314
      Width = 121
      Height = 17
      Caption = 'Key container type:'
    end
    object editInputFile: TEdit
      Left = 21
      Top = 58
      Width = 472
      Height = 21
      TabOrder = 0
    end
    object btnBrowseInputFile: TButton
      Left = 502
      Top = 52
      Width = 93
      Height = 33
      Caption = 'Browse ...'
      TabOrder = 1
      OnClick = btnBrowseInputFileClick
    end
    object comboAlg: TComboBox
      Left = 21
      Top = 199
      Width = 158
      Height = 25
      Style = csDropDownList
      ItemHeight = 17
      TabOrder = 4
      Items.Strings = (
        'RSA'
        'DSA')
    end
    object btnBrowseKey: TButton
      Left = 502
      Top = 268
      Width = 93
      Height = 33
      Caption = 'Browse ...'
      TabOrder = 7
      OnClick = btnBrowseKeyClick
    end
    object editKeyFile: TEdit
      Left = 21
      Top = 272
      Width = 472
      Height = 21
      TabOrder = 6
    end
    object editPassphrase: TEdit
      Left = 21
      Top = 335
      Width = 231
      Height = 21
      PasswordChar = '*'
      TabOrder = 8
    end
    object btnBrowseOutputFile: TButton
      Left = 502
      Top = 122
      Width = 93
      Height = 32
      Caption = 'Browse ...'
      TabOrder = 3
      OnClick = btnBrowseOutputFileClick
    end
    object editSignatureFile: TEdit
      Left = 21
      Top = 126
      Width = 472
      Height = 21
      TabOrder = 2
    end
    object comboInputEncoding: TComboBox
      Left = 199
      Top = 199
      Width = 137
      Height = 25
      Style = csDropDownList
      ItemHeight = 17
      TabOrder = 5
      Items.Strings = (
        'Binary'
        'Base64')
    end
    object comboKeyContainerType: TComboBox
      Left = 272
      Top = 335
      Width = 221
      Height = 25
      Style = csDropDownList
      ItemHeight = 17
      TabOrder = 9
      Items.Strings = (
        'Generic public key'
        'X.509 certificate')
    end
  end
  object dlgOpenDialog: TOpenDialog
    Title = 'Please, select file'
    Left = 40
    Top = 376
  end
  object dlgOpenKey: TOpenDialog
    Filter = 'All key and certificate files (*.*)|*.*'
    FilterIndex = 0
    Title = 'Please, select key/certificate file'
    Left = 136
    Top = 384
  end
end
