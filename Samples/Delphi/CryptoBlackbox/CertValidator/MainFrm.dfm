object Form1: TForm1
  Left = 195
  Top = 174
  Width = 615
  Height = 438
  Caption = 'X509CertificateValidator demo'
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  PixelsPerInch = 96
  TextHeight = 13
  object mmLog: TMemo
    Left = 0
    Top = 193
    Width = 607
    Height = 218
    Align = alClient
    ReadOnly = True
    ScrollBars = ssBoth
    TabOrder = 0
  end
  object Panel1: TPanel
    Left = 0
    Top = 0
    Width = 607
    Height = 193
    Align = alTop
    BevelOuter = bvNone
    TabOrder = 1
    object Label1: TLabel
      Left = 16
      Top = 13
      Width = 217
      Height = 13
      Caption = 'Certificate to check (from MY storage or file):'
    end
    object bbValidate: TButton
      Left = 480
      Top = 30
      Width = 75
      Height = 25
      Caption = 'Validate'
      TabOrder = 0
      OnClick = bbValidateClick
    end
    object cbCheckCRL: TCheckBox
      Left = 16
      Top = 67
      Width = 97
      Height = 17
      Caption = 'Check CRL'
      Checked = True
      State = cbChecked
      TabOrder = 1
    end
    object cbCheckOCSP: TCheckBox
      Left = 16
      Top = 90
      Width = 97
      Height = 17
      Caption = 'Check OCSP'
      Checked = True
      State = cbChecked
      TabOrder = 2
    end
    object cbCheckValidityPeriodForTrusted: TCheckBox
      Left = 16
      Top = 113
      Width = 177
      Height = 17
      Caption = 'Check validity period for trusted'
      Checked = True
      State = cbChecked
      TabOrder = 3
    end
    object cbForceCompleteChainValidationForTrusted: TCheckBox
      Left = 16
      Top = 136
      Width = 195
      Height = 17
      Caption = 'Complete chain validation for trusted'
      Checked = True
      State = cbChecked
      TabOrder = 4
    end
    object cbIgnoreCAKeyUsage: TCheckBox
      Left = 16
      Top = 159
      Width = 128
      Height = 17
      Caption = 'Ignore CA key usage'
      Checked = True
      State = cbChecked
      TabOrder = 5
    end
    object cbIgnoreSystemTrusted: TCheckBox
      Left = 225
      Top = 67
      Width = 128
      Height = 17
      Caption = 'Ignore system trust'
      TabOrder = 6
    end
    object cbTrustSelfSigned: TCheckBox
      Left = 225
      Top = 90
      Width = 160
      Height = 17
      Caption = 'Trust self-signed certificates'
      TabOrder = 7
    end
    object cbMandatoryCRLCheck: TCheckBox
      Left = 225
      Top = 113
      Width = 160
      Height = 17
      Caption = 'Mandatory CRL check'
      TabOrder = 8
    end
    object cbMandatoryOCSPCheck: TCheckBox
      Left = 225
      Top = 136
      Width = 168
      Height = 17
      Caption = 'Mandatory OCSP check'
      TabOrder = 9
    end
    object cbMandatoryRevocationCheck: TCheckBox
      Left = 225
      Top = 159
      Width = 168
      Height = 17
      Caption = 'Mandatory revocation check'
      Checked = True
      State = cbChecked
      TabOrder = 10
    end
    object cbOfflineMode: TCheckBox
      Left = 433
      Top = 67
      Width = 173
      Height = 17
      Caption = 'Offline mode'
      TabOrder = 11
    end
    object cbSystemStorages: TCheckBox
      Left = 433
      Top = 90
      Width = 173
      Height = 17
      Caption = 'Use system storages'
      Checked = True
      State = cbChecked
      TabOrder = 12
    end
    object cbValidateInvalidCerts: TCheckBox
      Left = 433
      Top = 113
      Width = 173
      Height = 17
      Caption = 'Validate invalid certificates'
      TabOrder = 13
    end
    object cbCert: TComboBox
      Left = 16
      Top = 32
      Width = 377
      Height = 21
      ItemHeight = 13
      TabOrder = 14
    end
    object bbChoose: TButton
      Left = 400
      Top = 30
      Width = 75
      Height = 25
      Caption = 'Choose'
      TabOrder = 15
      OnClick = bbChooseClick
    end
  end
  object Validator: TElX509CertificateValidator
    IgnoreSystemTrust = False
    UseSystemStorages = True
    CheckValidityPeriodForTrusted = True
    IgnoreCAKeyUsage = True
    MandatoryCRLCheck = False
    ValidateInvalidCertificates = False
    OfflineMode = False
    RevocationMomentGracePeriod = 60
    ImplicitlyTrustSelfSignedCertificates = False
    OnCRLNeeded = ValidatorCRLNeeded
    OnCRLRetrieved = ValidatorCRLRetrieved
    OnBeforeCRLRetrieverUse = ValidatorBeforeCRLRetrieverUse
    OnBeforeOCSPClientUse = ValidatorBeforeOCSPClientUse
    OnBeforeCertificateValidation = ValidatorBeforeCertificateValidation
    OnAfterCertificateValidation = ValidatorAfterCertificateValidation
    OnCACertificateNeeded = ValidatorCACertificateNeeded
    OnAfterCRLUse = ValidatorAfterCRLUse
    OnAfterOCSPResponseUse = ValidatorAfterOCSPResponseUse
    Left = 24
    Top = 200
  end
  object OpenDialog1: TOpenDialog
    Left = 208
    Top = 200
  end
  object WinCertStorage: TElWinCertStorage
    Options = [csoStrictChainBuilding]
    SystemStores.Strings = (
      'MY')
    ReadOnly = False
    Left = 88
    Top = 200
  end
  object ElX509Certificate: TElX509Certificate
    Left = 152
    Top = 200
  end
end
