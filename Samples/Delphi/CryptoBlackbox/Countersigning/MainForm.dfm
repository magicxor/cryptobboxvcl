object frmMain: TfrmMain
  Left = 235
  Top = 172
  BorderStyle = bsDialog
  Caption = 'EldoS Countersigning demo'
  ClientHeight = 339
  ClientWidth = 440
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  PixelsPerInch = 96
  TextHeight = 13
  object PageControl: TPageControl
    Left = 0
    Top = 0
    Width = 440
    Height = 298
    ActivePage = tabSign
    Align = alClient
    TabOrder = 0
    object tabSign: TTabSheet
      Caption = 'Countersign existing signature'
      object gbCSProps: TGroupBox
        Left = 8
        Top = 0
        Width = 417
        Height = 257
        Caption = 'Countersigning properties'
        TabOrder = 0
        object lblSigFile: TLabel
          Left = 16
          Top = 24
          Width = 67
          Height = 13
          Caption = 'Signature file:'
        end
        object lblCertFile: TLabel
          Left = 16
          Top = 72
          Width = 71
          Height = 13
          Caption = 'Certificate file:'
        end
        object lblCertPass: TLabel
          Left = 16
          Top = 120
          Width = 103
          Height = 13
          Caption = 'Certificate password:'
        end
        object lblOutputFile: TLabel
          Left = 16
          Top = 168
          Width = 55
          Height = 13
          Caption = 'Output file:'
        end
        object editSigFile: TEdit
          Left = 16
          Top = 40
          Width = 305
          Height = 21
          TabOrder = 0
        end
        object btnBrowseSigFile: TButton
          Left = 328
          Top = 40
          Width = 75
          Height = 25
          Caption = 'Browse...'
          TabOrder = 1
          OnClick = btnBrowseSigFileClick
        end
        object editCertFile: TEdit
          Left = 16
          Top = 88
          Width = 305
          Height = 21
          TabOrder = 2
        end
        object btnBrowseCertFile: TButton
          Left = 328
          Top = 88
          Width = 75
          Height = 25
          Caption = 'Browse...'
          TabOrder = 3
          OnClick = btnBrowseCertFileClick
        end
        object editCertPass: TEdit
          Left = 16
          Top = 136
          Width = 137
          Height = 21
          PasswordChar = '*'
          TabOrder = 4
        end
        object editOutputFile: TEdit
          Left = 16
          Top = 184
          Width = 305
          Height = 21
          TabOrder = 5
        end
        object btnBrowseOutputFile: TButton
          Left = 328
          Top = 184
          Width = 75
          Height = 25
          Caption = 'Browse...'
          TabOrder = 6
          OnClick = btnBrowseOutputFileClick
        end
        object btnCountersign: TButton
          Left = 168
          Top = 216
          Width = 75
          Height = 25
          Caption = 'Countersign'
          TabOrder = 7
          OnClick = btnCountersignClick
        end
      end
    end
    object tabVerify: TTabSheet
      Caption = 'Verify countersignatures'
      ImageIndex = 1
      object gbCVProps: TGroupBox
        Left = 8
        Top = 0
        Width = 417
        Height = 257
        Caption = 'Countersignature verification properties'
        TabOrder = 0
        object Label1: TLabel
          Left = 16
          Top = 24
          Width = 91
          Height = 13
          Caption = 'Countersigned file:'
        end
        object Label2: TLabel
          Left = 16
          Top = 72
          Width = 102
          Height = 13
          Caption = 'Signature properties:'
        end
        object editCountersignedFile: TEdit
          Left = 16
          Top = 40
          Width = 305
          Height = 21
          TabOrder = 0
        end
        object btnBrowseCountersignature: TButton
          Left = 328
          Top = 40
          Width = 75
          Height = 25
          BiDiMode = bdLeftToRight
          Caption = 'Browse...'
          ParentBiDiMode = False
          TabOrder = 1
          OnClick = btnBrowseCountersignatureClick
        end
        object lvSigProps: TListView
          Left = 16
          Top = 88
          Width = 385
          Height = 121
          Columns = <
            item
              Caption = 'Property'
              Width = 100
            end
            item
              Caption = 'Value'
              Width = 250
            end>
          ReadOnly = True
          RowSelect = True
          TabOrder = 2
          ViewStyle = vsReport
        end
        object btnVerify: TButton
          Left = 168
          Top = 216
          Width = 75
          Height = 25
          Caption = 'Verify'
          TabOrder = 3
          OnClick = btnVerifyClick
        end
      end
    end
  end
  object pBottom: TPanel
    Left = 0
    Top = 298
    Width = 440
    Height = 41
    Align = alBottom
    BevelOuter = bvNone
    TabOrder = 1
    object btnClose: TButton
      Left = 360
      Top = 8
      Width = 75
      Height = 25
      Caption = 'Close'
      TabOrder = 0
      OnClick = btnCloseClick
    end
  end
  object OpenDialog: TOpenDialog
    InitialDir = '.'
    Left = 356
    Top = 56
  end
  object OpenDialogCert: TOpenDialog
    Filter = 'PFX certificate (*.pfx)|*.pfx|All files (*.*)|*.*'
    InitialDir = '.'
    Left = 364
    Top = 96
  end
  object SaveDialog: TSaveDialog
    InitialDir = '.'
    Left = 364
    Top = 208
  end
end
