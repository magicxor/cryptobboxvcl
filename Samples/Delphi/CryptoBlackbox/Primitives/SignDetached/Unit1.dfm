object frmMainForm: TfrmMainForm
  Left = 219
  Top = 154
  BorderStyle = bsDialog
  Caption = 'ElPublicKeyCrypto detached signing demo'
  ClientHeight = 347
  ClientWidth = 481
  Color = clBtnFace
  Font.Charset = RUSSIAN_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poScreenCenter
  OnCreate = FormCreate
  PixelsPerInch = 96
  TextHeight = 13
  object btnSign: TButton
    Left = 168
    Top = 312
    Width = 75
    Height = 25
    Caption = 'Sign'
    Default = True
    TabOrder = 1
    OnClick = btnSignClick
  end
  object btnCancel: TButton
    Left = 248
    Top = 312
    Width = 75
    Height = 25
    Cancel = True
    Caption = 'Cancel'
    TabOrder = 2
    OnClick = btnCancelClick
  end
  object gbSettings: TGroupBox
    Left = 8
    Top = 8
    Width = 465
    Height = 297
    Caption = 'Settings'
    TabOrder = 0
    object lblInputFIle: TLabel
      Left = 16
      Top = 24
      Width = 73
      Height = 13
      Caption = 'Input filename:'
    end
    object lblAlgorithm: TLabel
      Left = 16
      Top = 136
      Width = 102
      Height = 13
      Caption = 'Encryption algorithm:'
    end
    object lblPassword: TLabel
      Left = 16
      Top = 240
      Width = 50
      Height = 13
      Caption = 'Password:'
    end
    object lblKeyFilename: TLabel
      Left = 16
      Top = 192
      Width = 123
      Height = 13
      Caption = 'Private key container file:'
    end
    object lblOutputFile: TLabel
      Left = 16
      Top = 80
      Width = 81
      Height = 13
      Caption = 'Output filename:'
    end
    object lblInputEncoding: TLabel
      Left = 152
      Top = 136
      Width = 76
      Height = 13
      Caption = 'Input encoding:'
    end
    object lblOutputEncoding: TLabel
      Left = 272
      Top = 136
      Width = 84
      Height = 13
      Caption = 'Output encoding:'
    end
    object lblKeyContainerType: TLabel
      Left = 208
      Top = 240
      Width = 95
      Height = 13
      Caption = 'Key container type:'
    end
    object editInputFile: TEdit
      Left = 16
      Top = 44
      Width = 361
      Height = 21
      TabOrder = 0
    end
    object btnBrowseInputFile: TButton
      Left = 384
      Top = 40
      Width = 71
      Height = 25
      Caption = 'Browse ...'
      TabOrder = 1
      OnClick = btnBrowseInputFileClick
    end
    object comboAlg: TComboBox
      Left = 16
      Top = 152
      Width = 121
      Height = 21
      Style = csDropDownList
      ItemHeight = 13
      TabOrder = 4
      Items.Strings = (
        'RSA'
        'DSA')
    end
    object btnBrowseKey: TButton
      Left = 384
      Top = 205
      Width = 71
      Height = 25
      Caption = 'Browse ...'
      TabOrder = 8
      OnClick = btnBrowseKeyClick
    end
    object editKeyFile: TEdit
      Left = 16
      Top = 208
      Width = 361
      Height = 21
      TabOrder = 7
    end
    object editPassphrase: TEdit
      Left = 16
      Top = 256
      Width = 177
      Height = 21
      PasswordChar = '*'
      TabOrder = 9
    end
    object btnBrowseOutputFile: TButton
      Left = 384
      Top = 93
      Width = 71
      Height = 25
      Caption = 'Browse ...'
      TabOrder = 3
      OnClick = btnBrowseOutputFileClick
    end
    object editSignatureFile: TEdit
      Left = 16
      Top = 96
      Width = 361
      Height = 21
      TabOrder = 2
    end
    object comboInputEncoding: TComboBox
      Left = 152
      Top = 152
      Width = 105
      Height = 21
      Style = csDropDownList
      ItemHeight = 13
      TabOrder = 5
      Items.Strings = (
        'Binary'
        'Base64')
    end
    object comboOutputEncoding: TComboBox
      Left = 272
      Top = 152
      Width = 105
      Height = 21
      Style = csDropDownList
      ItemHeight = 13
      TabOrder = 6
      Items.Strings = (
        'Binary'
        'Base64')
    end
    object comboKeyContainerType: TComboBox
      Left = 208
      Top = 256
      Width = 169
      Height = 21
      Style = csDropDownList
      ItemHeight = 13
      TabOrder = 10
      Items.Strings = (
        'Generic private key'
        'X.509 certificate')
    end
  end
  object dlgOpenDialog: TOpenDialog
    Title = 'Please, select file'
    Left = 16
    Top = 312
  end
  object dlgSaveDialog: TSaveDialog
    Title = 'Please, select file'
    Left = 48
    Top = 312
  end
  object dlgOpenKey: TOpenDialog
    Filter = 'All key and certificate files (*.*)|*.*'
    FilterIndex = 0
    Title = 'Please, select key/certificate file'
    Left = 80
    Top = 312
  end
end
