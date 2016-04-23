(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBX509Ext;

interface

uses
  Classes,
  SysUtils,
  {$ifdef SB_UNICODE_VCL}
  SBStringList,
   {$endif}
  SBRDN,
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBConstants,
  SBASN1,
  SBPKCS7Utils,
  SBASN1Tree;



type
  TSBCertificateExtension = (ceAuthorityKeyIdentifier, ceSubjectKeyIdentifier,
    ceKeyUsage, cePrivateKeyUsagePeriod, ceCertificatePolicies,
      cePolicyMappings,
    ceSubjectAlternativeName, ceIssuerAlternativeName, ceBasicConstraints,
    ceNameConstraints, cePolicyConstraints, ceExtendedKeyUsage,
    ceCRLDistributionPoints, ceAuthorityInformationAccess,

    ceNetscapeCertType, ceNetscapeBaseURL, ceNetscapeRevokeURL,
    ceNetscapeCARevokeURL, ceNetscapeRenewalURL, ceNetscapeCAPolicyURL,
    ceNetscapeServerName, ceNetscapeComment, ceCommonName,

    ceSubjectDirectoryAttributes);

  TSBCertificateExtensions = set of TSBCertificateExtension;

  TSBKeyUsageType = (kuDigitalSignature, kuNonRepudiation, kuKeyEncipherment,
    kuDataEncipherment, kuKeyAgreement, kuKeyCertSign, kuCRLSign,
    kuEncipherOnly, kuDecipherOnly);
  TSBKeyUsage = set of TSBKeyUsageType;

  TSBCRLReasonFlag = (rfUnspecified, rfKeyCompromise, rfCACompromise,
    rfAffiliationChanged, rfSuperseded, rfCessationOfOperation,
      rfCertificateHold, rfObsolete1, rfRemoveFromCRL, rfPrivilegeWithdrawn, rfAACompromise);
  TSBCRLReasonFlags = set of TSBCRLReasonFlag;

const TSBCRLAllReasonFlags : TSBCRLReasonFlags = [rfUnspecified, rfKeyCompromise, rfCACompromise,
    rfAffiliationChanged, rfSuperseded, rfCessationOfOperation,
      rfCertificateHold, rfObsolete1, rfRemoveFromCRL, rfPrivilegeWithdrawn, rfAACompromise];

type

  EElCertificateError =  class(ESecureBlackboxError);

  { X.509 Certificate Extensions classes }

  TSBGeneralName =  (gnRFC822Name, gnDNSName, gnDirectoryName, gnEdiPartyName,
    gnUniformResourceIdentifier, gnIPAddress, gnRegisteredID, gnOtherName, gnUnknown, gnPermanentIdentifier);

  TElEDIPartyName = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElEDIPartyName = TElEDIPartyName;
   {$endif}

  TElEDIPartyName =  class{$ifndef SB_NO_NET_MARSHALBYREF}( TPersistent ) {$endif}
   private 
    FNameAssigner : string;
    FPartyName : string;
  public

    property NameAssigner : string read FNameAssigner write FNameAssigner;
    property PartyName : string read FPartyName write FPartyName;
  end;

  TElOtherName = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElOtherName = TElOtherName;
   {$endif}

  TElOtherName =  class{$ifndef SB_NO_NET_MARSHALBYREF}( TPersistent ) {$endif}
   private 
    FOID : ByteArray;
    FValue : ByteArray;
    procedure SetOID(const V: ByteArray);
    procedure SetValue(const V: ByteArray);
  public

    property OID : ByteArray read FOID write SetOID;
    property Value : ByteArray read FValue write SetValue;
  end;

  TElPermanentIdentifier = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElPermanentIdentifier = TElPermanentIdentifier;
   {$endif}

  TElPermanentIdentifier =   class{$ifndef SB_NO_NET_MARSHALBYREF}( TPersistent ) {$endif}
  protected
    FPermanentIdentifier: ByteArray;
    FAssigner : ByteArray;
    procedure SetPermanentIdentifier(const V : ByteArray);
    procedure SetAssigner(const V : ByteArray);
  public
  
    property PermanentIdentifier : ByteArray read FPermanentIdentifier write SetPermanentIdentifier;
    property Assigner : ByteArray read FAssigner write SetAssigner;
  end;

  TElGeneralName = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElGeneralName = TElGeneralName;
   {$endif}

  TElGeneralName =
     class( TPersistent )
  protected
    FRFC822Name: string;
    FDNSName: string;
    FDirectoryName: TElRelativeDistinguishedName;
    FEdiPartyName: TElEDIPartyName;
    FUniformResourceIdentifier: string;
    FIpAddress: string;
    FIpAddressBytes: ByteArray;
    FRegisteredID: ByteArray;
    FOtherName : TElOtherName;
    FPermanentIdentifier: TElPermanentIdentifier;
    FNameType : TSBGeneralName;
    procedure TryKnownOtherNames;
    procedure SaveKnownOtherNames;
    procedure ParsePermanentIdentifier(Buffer: pointer; Size: integer);
    procedure SavePermanentIdentifier(var OID : ByteArray; var Content: ByteArray);
    function Equals(Other : TElGeneralName) : boolean; {$ifdef D_12_UP}reintroduce; {$endif}
    function GetIsEmpty : boolean;
    procedure SetRegisteredID(const V : ByteArray);
  public
    constructor Create;
     destructor  Destroy; override;

    procedure Assign(Source:  TPersistent );
      override; 
    procedure AssignTo(Dest:  TPersistent );
      override; 
    function LoadFromTag(Tag: TElASN1CustomTag): boolean;
    function SaveToTag(Tag: TElASN1SimpleTag): boolean;
    property RFC822Name: string read FRFC822Name write FRFC822Name;
    property DNSName: string read FDNSName write FDNSName;
    property DirectoryName: TElRelativeDistinguishedName read FDirectoryName;
    property EdiPartyName: TElEDIPartyName read FEdiPartyName;
    property UniformResourceIdentifier: string read FUniformResourceIdentifier write FUniformResourceIdentifier;
    property IpAddress: string read FIpAddress write FIpAddress;
    property IpAddressBytes: ByteArray read FIpAddressBytes write FIpAddressBytes;
    property RegisteredID: ByteArray read FRegisteredID write SetRegisteredID;
    property OtherName : TElOtherName read FOtherName;
    property PermanentIdentifier : TElPermanentIdentifier read FPermanentIdentifier;
    property NameType : TSBGeneralName read FNameType write FNameType;
    property IsEmpty : boolean read GetIsEmpty;
  end;

  TElGeneralNames = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElGeneralNames = TElGeneralNames;
   {$endif}

  TElGeneralNames =
     class( TPersistent )
  private
    FNames : TElList;
  protected
    function GetCount : integer;
    function  GetNames (Index: integer): TElGeneralName;
    function Contains(Other : TElGeneralNames) : boolean;
  public
    constructor Create;
     destructor  Destroy; override;

    procedure Assign(Source:  TPersistent );
      override; 
    procedure AssignTo(Dest:  TPersistent );
      override; 

    function Equals(Other : TElGeneralNames) : boolean; {$ifdef D_12_UP}reintroduce; {$endif}
    function HasCommon(Other : TElGeneralNames) : boolean;

    function Add : integer;
    procedure Remove(Index: integer);
    procedure Clear;
    function ContainsEmailAddress(const Addr: string): boolean;
    function FindNameByType(NameType : TSBGeneralName; StartIndex: integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}) : integer;
    function LoadFromTag(Tag: TElASN1ConstrainedTag; AllowRDN : boolean {$ifdef HAS_DEF_PARAMS} =  false {$endif}): boolean;
    function SaveToTag(Tag: TElASN1ConstrainedTag): boolean;
    property Names[Index: integer] : TElGeneralName read  GetNames ;
    property Count: integer read GetCount;
  end;

  TElCustomExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCustomExtension = TElCustomExtension;
   {$endif}

  TElCustomExtension =
     class( TPersistent )
  protected
    FCritical: boolean;
    FOID: ByteArray;
    FValue: ByteArray;
    procedure Clear; virtual;
    procedure RaiseInvalidExtensionError;

    function GetOID: ByteArray; virtual;
    procedure SetOID(const Value: ByteArray); virtual;
    procedure SetValue(const Value: ByteArray); virtual;
    function GetValue: ByteArray; virtual;
  public
    constructor Create;
     destructor  Destroy; override;
    procedure SaveToTag(Tag: TElASN1ConstrainedTag); virtual;
    property Critical: boolean read FCritical write FCritical  default false ;
    property OID: ByteArray read GetOID write SetOID;
    property Value: ByteArray read GetValue write SetValue;
  end;

  TElAuthorityKeyIdentifierExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElAuthorityKeyIdentifierExtension = TElAuthorityKeyIdentifierExtension;
   {$endif}

  TElAuthorityKeyIdentifierExtension =  class(TElCustomExtension)
  protected
    FKeyIdentifier: ByteArray;
    FAuthorityCertIssuer: TElGeneralNames;
    FAuthorityCertSerial: ByteArray;

    procedure Clear; override;
    function GetOID: ByteArray; override;
    procedure SetOID(const Value: ByteArray); override;
    procedure SetValue(const Value: ByteArray); override;
    function GetValue: ByteArray; override;
    procedure SetKeyIdentifier(const V: ByteArray);
    procedure SetAuthorityCertSerial(const V: ByteArray);
  public
    constructor Create;
     destructor  Destroy; override;
    property KeyIdentifier: ByteArray read FKeyIdentifier write SetKeyIdentifier;
    property AuthorityCertIssuer: TElGeneralNames read FAuthorityCertIssuer;
    property AuthorityCertSerial: ByteArray read FAuthorityCertSerial write
      SetAuthorityCertSerial;
  end;

  TElSubjectKeyIdentifierExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElSubjectKeyIdentifierExtension = TElSubjectKeyIdentifierExtension;
   {$endif}

  TElSubjectKeyIdentifierExtension =  class(TElCustomExtension)
  protected
    FKeyIdentifier: ByteArray;
    procedure Clear; override;

    function GetOID: ByteArray; override;
    procedure SetOID(const Value: ByteArray); override;
    procedure SetValue(const Value: ByteArray); override;
    procedure SetKeyIdentifier(const V : ByteArray);
  public
    property KeyIdentifier: ByteArray read FKeyIdentifier write SetKeyIdentifier;
  end;

  TElKeyUsageExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElKeyUsageExtension = TElKeyUsageExtension;
   {$endif}

  TElKeyUsageExtension =  class(TElCustomExtension)
  protected
    FDigitalSignature: boolean;
    FNonRepudiation: boolean;
    FKeyEncipherment: boolean;
    FDataEncipherment: boolean;
    FKeyAgreement: boolean;
    FKeyCertSign: boolean;
    FCRLSign: boolean;
    FEncipherOnly: boolean;
    FDecipherOnly: boolean;

    procedure Clear; override;
    
    function GetOID: ByteArray; override;
    procedure SetOID(const Value: ByteArray); override;
    procedure SetValue(const Value: ByteArray); override;
  public
    property DigitalSignature: boolean read FDigitalSignature write
      FDigitalSignature;
    property NonRepudiation: boolean read FNonRepudiation write FNonRepudiation;
    property KeyEncipherment: boolean read FKeyEncipherment write
      FKeyEncipherment;
    property DataEncipherment: boolean read FDataEncipherment write
      FDataEncipherment;
    property KeyAgreement: boolean read FKeyAgreement write FKeyAgreement;
    property KeyCertSign: boolean read FKeyCertSign write FKeyCertSign;
    property CRLSign: boolean read FCRLSign write FCRLSign;
    property EncipherOnly: boolean read FEncipherOnly write FEncipherOnly;
    property DecipherOnly: boolean read FDecipherOnly write FDecipherOnly;
  end;

  TElPrivateKeyUsagePeriodExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElPrivateKeyUsagePeriodExtension = TElPrivateKeyUsagePeriodExtension;
   {$endif}

  TElPrivateKeyUsagePeriodExtension =  class(TElCustomExtension)
  protected
    FNotBefore: TElDateTime;
    FNotAfter: TElDateTime;
    procedure Clear; override;

    function GetOID: ByteArray; override;
    procedure SetOID(const Value: ByteArray); override;
    procedure SetValue(const Value: ByteArray); override;
  public
    property NotBefore: TElDateTime read FNotBefore write FNotBefore;
    property NotAfter: TElDateTime read FNotAfter write FNotAfter;
  end;

  {JPM - added NetscapeExtensions}
  TElNetscapeCertTypeFlag = (nsSSLClient, nsSSLServer, nsSMIME, nsObjectSign,
    nsSSLCA,  nsSMIMECA, nsObjectSignCA);
  TElNetscapeCertType = set of TElNetscapeCertTypeFlag;

  TElNetscapeCertTypeExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElNetscapeCertTypeExtension = TElNetscapeCertTypeExtension;
   {$endif}

  TElNetscapeCertTypeExtension =  class(TElCustomExtension)
  protected
    FCertType : TElNetscapeCertType;
    procedure Clear; override;

    procedure SetValue(const Value: ByteArray); override;
  public
    property CertType : TElNetscapeCertType read FCertType write FCertType;
  end;

  TElNetscapeString = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElNetscapeString = TElNetscapeString;
   {$endif}

  TElNetscapeString =  class(TElCustomExtension)
  protected
    FContent : string;
    procedure Clear; override;

    procedure SetValue(const Value: ByteArray); override;
    function GetOID : ByteArray; override;
  public
    property Content : string read FContent write FContent;
  end;

  TElNetscapeBaseURL =  class(TElNetscapeString);
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElNetscapeBaseURL = TElNetscapeBaseURL;
   {$endif}
  TElNetscapeRevokeURL =  class(TElNetscapeString);
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElNetscapeRevokeURL = TElNetscapeRevokeURL;
   {$endif}
  TElNetscapeCARevokeURL =  class(TElNetscapeString);
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElNetscapeCARevokeURL = TElNetscapeCARevokeURL;
   {$endif}
  TElNetscapeRenewalURL =  class(TElNetscapeString);
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElNetscapeRenewalURL = TElNetscapeRenewalURL;
   {$endif}
  TElNetscapeCAPolicy =  class(TElNetscapeString);
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElNetscapeCAPolicy = TElNetscapeCAPolicy;
   {$endif}
  TElNetscapeServerName =  class(TElNetscapeString);
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElNetscapeServerName = TElNetscapeServerName;
   {$endif}
  TElNetscapeComment =  class(TElNetscapeString);
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElNetscapeComment = TElNetscapeComment;
   {$endif}

  TElCommonName =  class(TElNetscapeString);  //not a netscape extension but the coding is similar to the others
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCommonName = TElCommonName;
   {$endif}
  // end

  TElUserNotice = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElUserNotice = TElUserNotice;
   {$endif}

  TElUserNotice =  class( TPersistent )
  protected
    FOrganization: string;
    FNoticeNumbers: array of integer;
    FExplicitText: string;
    function GetNoticeNumbersCount: integer;
    procedure SetNoticeNumbersCount(Value: integer);
    function GetNoticeNumbers(Index: integer): integer;
    procedure SetNoticeNumbers(Index: integer; Value: integer);
  public
     destructor  Destroy;  override; 

    property Organization: string read FOrganization write FOrganization;
    property NoticeNumbers[Index: integer]: integer 
         read GetNoticeNumbers write SetNoticeNumbers ;
    property NoticeNumbersCount: integer read GetNoticeNumbersCount write
    SetNoticeNumbersCount;
    property ExplicitText: string read FExplicitText write FExplicitText;
  end;

  TElSinglePolicyQualifier = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElSinglePolicyQualifier = TElSinglePolicyQualifier;
   {$endif}

  TElSinglePolicyQualifier =  class( TPersistent )
  protected
    FCPSURI: string;
    FUserNotice: TElUserNotice;
  public
    constructor Create;
     destructor  Destroy; override;

    property CPSURI: string read FCPSURI write FCPSURI;
    property UserNotice: TElUserNotice read FUserNotice;
  end;

  TElSinglePolicyInformation = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElSinglePolicyInformation = TElSinglePolicyInformation;
   {$endif}

  TElSinglePolicyInformation =
     class( TPersistent )
  protected
    FPolicyIdentifier: ByteArray;
    FPolicyQualifiers: TElList;

    procedure SetPolicyIdentifier(const V : ByteArray);
    function GetQualifierCount: integer;
    procedure SetQualifierCount(Value: integer);

    function GetPolicyQualifier(Index: integer): TElSinglePolicyQualifier;
  public
    constructor Create;
     destructor  Destroy; override;

    property PolicyIdentifier: ByteArray read FPolicyIdentifier write
      SetPolicyIdentifier;
    property QualifierCount: integer read GetQualifierCount write SetQualifierCount;
    property Qualifiers[Index: integer]: TElSinglePolicyQualifier read GetPolicyQualifier;
  end;

  TElCertificatePoliciesExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCertificatePoliciesExtension = TElCertificatePoliciesExtension;
   {$endif}

  TElCertificatePoliciesExtension =  class(TElCustomExtension)
  protected
    FList: TElList;
    procedure ClearList;
    procedure Clear; override;

    function GetOID: ByteArray; override;
    procedure SetOID(const Value: ByteArray); override;
    procedure SetValue(const Value: ByteArray); override;
    function GetCount: integer;
    procedure SetCount(Value: integer);
    function GetPolicyInformation(Index: integer): TElSinglePolicyInformation;
  public
    constructor Create;
     destructor  Destroy; override;
    procedure Remove(Index: integer);
    property PolicyInformation[Index: integer]: TElSinglePolicyInformation
    read GetPolicyInformation;
    property Count: integer read GetCount write SetCount;
  end;

  TElPolicyMapping = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElPolicyMapping = TElPolicyMapping;
   {$endif}

  TElPolicyMapping =  class( TPersistent )
  protected
    FIssuerDomainPolicy: ByteArray;
    FSubjectDomainPolicy: ByteArray;
    procedure SetIssuerDomainPolicy(const V: ByteArray);
    procedure SetSubjectDomainPolicy(const V: ByteArray);
  public
     destructor  Destroy;  override; 
    property IssuerDomainPolicy: ByteArray read FIssuerDomainPolicy write
      SetIssuerDomainPolicy;
    property SubjectDomainPolicy: ByteArray read FSubjectDomainPolicy write
      SetSubjectDomainPolicy;
  end;

  TElPolicyMappingsExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElPolicyMappingsExtension = TElPolicyMappingsExtension;
   {$endif}

  TElPolicyMappingsExtension =  class(TElCustomExtension)
  protected
    FList: TElList;
    procedure ClearList;
    procedure Clear; override;
    
    function GetCount: integer;
    procedure SetCount(Value: integer);

    function GetOID: ByteArray; override;
    procedure SetOID(const Value: ByteArray); override;
    procedure SetValue(const Value: ByteArray); override;
    function  GetPolicies (Index: integer): TElPolicyMapping;
  public
    constructor Create;
     destructor  Destroy; override;
    procedure Remove(Index: integer);
    property Count: integer read GetCount write SetCount;
    property Policies[Index: integer]: TElPolicyMapping read  GetPolicies ;
  end;

  TElAlternativeNameExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElAlternativeNameExtension = TElAlternativeNameExtension;
   {$endif}

  TElAlternativeNameExtension =  class(TElCustomExtension)
  protected
    FContent: TElGeneralNames;
    FIssuerAltName : boolean;
    procedure Clear; override;

    function GetOID: ByteArray; override;
    procedure SetOID(const Value: ByteArray); override;
    procedure SetValue(const Value: ByteArray); override;
    function GetValue: ByteArray; override;
  public
    constructor Create(IssuerAltName : boolean); 
     destructor  Destroy; override;
    property Content: TElGeneralNames read FContent;
  end;

  TElBasicConstraintsExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElBasicConstraintsExtension = TElBasicConstraintsExtension;
   {$endif}

  TElBasicConstraintsExtension =  class(TElCustomExtension)
  protected
    FCA: boolean;
    FPathLenConstraint: integer;
    procedure Clear; override;
    function GetOID: ByteArray; override;
    procedure SetOID(const Value: ByteArray); override;
    procedure SetValue(const Value: ByteArray); override;
  public
    property CA: boolean read FCA write FCA;
    property PathLenConstraint: integer read FPathLenConstraint write
      FPathLenConstraint;
  end;

  TElNameConstraint = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElNameConstraint = TElNameConstraint;
   {$endif}

  TElNameConstraint =
     class( TPersistent )
  protected
    FBase: TElGeneralName;
    FMinimum: Integer;
    FMaximum: Integer;
  public
    constructor Create;
     destructor  Destroy; override;
    property Base: TElGeneralName read FBase;
    property Minimum: Integer read FMinimum write FMinimum;
    property Maximum: Integer read FMaximum write FMaximum;
  end;

  TElNameConstraintsExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElNameConstraintsExtension = TElNameConstraintsExtension;
   {$endif}

  TElNameConstraintsExtension =  class(TElCustomExtension)
  protected
    FPermittedList: TElList;
    FExcludedList: TElList;
    procedure Clear; override;
    procedure ClearList;
    
    function GetPermittedCount: integer;
    function GetExcludedCount: integer;
    procedure SetPermittedCount(Value: integer);
    procedure SetExcludedCount(Value: integer);

    function GetOID: ByteArray; override;
    procedure SetOID(const Value: ByteArray); override;
    procedure SetValue(const Value: ByteArray); override;
    function NameSubtreeCorresponds(Subtree: TElGeneralName; Name : TElGeneralName): boolean;
    function URICorresponds(const URITpl, URI: string): boolean;
    function EMailAddressCorresponds(const EMailTpl, EMail : string): boolean;
    function DNSNameCorresponds(const DNSNameTpl, DNSName : string): boolean;
    function DirectoryNameCorresponds(DirNameTpl, DirName : TElRelativeDistinguishedName): boolean;
    function IPAddressCorresponds(const IPAddressTpl, IPAddress: ByteArray): boolean;

    function GetPermittedSubtrees(Index: integer): TElNameConstraint;
    function GetExcludedSubtrees(Index: integer): TElNameConstraint;
  public
    constructor Create;
     destructor  Destroy; override;
    function AreNamesAcceptable(Subj : TElRelativeDistinguishedName;
      SubjAltName : TElGeneralNames): boolean;
    procedure RemovePermitted(Index: integer);
    procedure RemoveExcluded(Index: integer);
    property PermittedSubtrees[Index: integer]: TElNameConstraint read
     GetPermittedSubtrees ;
    property ExcludedSubtrees[Index: integer]: TElNameConstraint read
     GetExcludedSubtrees ;
    property PermittedCount: integer read GetPermittedCount write
      SetPermittedCount;
    property ExcludedCount: integer read GetExcludedCount write
      SetExcludedCount;
  end;

  TElPolicyConstraintsExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElPolicyConstraintsExtension = TElPolicyConstraintsExtension;
   {$endif}

  TElPolicyConstraintsExtension =  class(TElCustomExtension)
  protected
    FRequireExplicitPolicy: integer;
    FInhibitPolicyMapping: integer;

    procedure Clear; override;
    function GetOID: ByteArray; override;
    procedure SetOID(const Value: ByteArray); override;
    procedure SetValue(const Value: ByteArray); override;
  public
    property RequireExplicitPolicy: integer read FRequireExplicitPolicy
    write FRequireExplicitPolicy;
    property InhibitPolicyMapping: integer read FInhibitPolicyMapping
    write FInhibitPolicyMapping;
  end;

  TElExtendedKeyUsageExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElExtendedKeyUsageExtension = TElExtendedKeyUsageExtension;
   {$endif}

  TElExtendedKeyUsageExtension =  class(TElCustomExtension)
  protected
    FServerAuthentication: boolean;
    FClientAuthentication: boolean;
    FCodeSigning: boolean;
    FEmailProtection: boolean;
    FTimeStamping: boolean;
    FOCSPSigning : boolean; 
    FCustomUsages : TElByteArrayList;
    procedure Clear; override;
    
    function GetOID: ByteArray; override;
    procedure SetOID(const Value: ByteArray); override;
    procedure SetValue(const Value: ByteArray); override;
    function GetTotalUsageCount : integer;
    function GetCustomUsageCount: integer;
    function GetCustomUsage(Index: integer) : ByteArray;
    procedure SetCustomUsage(Index: integer; const Value: ByteArray);
  public
    constructor Create;
     destructor  Destroy; override;
    function AddCustomUsage(const UsageOID : ByteArray): integer;
    procedure RemoveCustomUsage(Index: integer);
    procedure ClearCustomUsages;

    property TotalUsageCount : integer read GetTotalUsageCount;

    property ServerAuthentication: boolean read FServerAuthentication
    write FServerAuthentication;
    property ClientAuthentication: boolean read FClientAuthentication
    write FClientAuthentication;
    property CodeSigning: boolean read FCodeSigning write FCodeSigning;
    property EmailProtection: boolean read FEmailProtection
    write FEmailProtection;
    property TimeStamping: boolean read FTimeStamping write FTimeStamping;
    property OCSPSigning : boolean read FOCSPSigning write FOCSPSigning;

    property CustomUsages[Index: integer] : ByteArray read GetCustomUsage
      write SetCustomUsage;
    property CustomUsageCount: integer read GetCustomUsageCount;
  end;

  TElDistributionPointParameter = (dppName, dppCRLIssuer, dppReasonFlags);
  TElDistributionPointParameters = set of TElDistributionPointParameter;

  TElDistributionPoint = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElDistributionPoint = TElDistributionPoint;
   {$endif}

  TElDistributionPoint =
     class( TPersistent )
  protected
    FName: TElGeneralNames;
    FCRLIssuer: TElGeneralNames;
    FReasonFlags: TSBCRLReasonFlags;
    FIncluded : TElDistributionPointParameters;
  public
    constructor Create;
     destructor  Destroy; override;
    property Name: TElGeneralNames read FName;
    property ReasonFlags: TSBCRLReasonFlags read FReasonFlags write
      FReasonFlags;
    property CRLIssuer: TElGeneralNames read FCRLIssuer;

    property Included : TElDistributionPointParameters read FIncluded write FIncluded;
  end;

  TElCRLDistributionPointsExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCRLDistributionPointsExtension = TElCRLDistributionPointsExtension;
   {$endif}

  TElCRLDistributionPointsExtension =  class(TElCustomExtension)
  protected
    FPoints: TElList;
    procedure ClearList;
    procedure Clear; override;
    
    function GetCount: integer;
    procedure SetCount(Value: integer);
    function GetOID: ByteArray; override;
    procedure SetOID(const Value: ByteArray); override;
    procedure SetValue(const Value: ByteArray); override;
    //procedure Parse(const Value: ByteArray);
    function  GetDistributionPoints (Index: integer): TElDistributionPoint;
  public
    constructor Create;
     destructor  Destroy; override;
    procedure Remove(Index: integer);
    property DistributionPoints[Index: integer]: TElDistributionPoint read
       GetDistributionPoints ;
    property Count: integer read GetCount write SetCount;
  end;

  TElAccessDescription = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElAccessDescription = TElAccessDescription;
   {$endif}

  TElAccessDescription =
     class( TPersistent )
  protected
    FAccessMethod: ByteArray;
    FGeneralName: TElGeneralName;
    procedure SetAccessMethod(const V : ByteArray);
  public
    constructor Create;
     destructor  Destroy; override;
    property AccessMethod: ByteArray read FAccessMethod write SetAccessMethod;
    property AccessLocation: TElGeneralName read FGeneralName;
  end;

  TElAuthorityInformationAccessExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElAuthorityInformationAccessExtension = TElAuthorityInformationAccessExtension;
   {$endif}

  TElAuthorityInformationAccessExtension =  class(TElCustomExtension)
  protected
    FList: TElList;
    procedure ClearList;
    procedure Clear; override;
      
    function GetCount: integer;
    procedure SetCount(Value: integer);
    function GetOID: ByteArray; override;
    procedure SetOID(const Value: ByteArray); override;
    procedure SetValue(const Value: ByteArray); override;
    function  GetAccessDescriptions (Index: integer): TElAccessDescription;
  public
    constructor Create;
     destructor  Destroy; override;
    procedure Remove(Index: integer);
    
    property AccessDescriptions[Index: integer]: TElAccessDescription
    read  GetAccessDescriptions ;

    property Count: integer read GetCount write SetCount;
  end;

  TElSubjectDirectoryAttributesExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElSubjectDirectoryAttributesExtension = TElSubjectDirectoryAttributesExtension;
   {$endif}

  TElSubjectDirectoryAttributesExtension =  class(TElCustomExtension)
  private
    FAttributes : TElPKCS7Attributes;
  protected
    procedure Clear; override;

    function GetOID: ByteArray; override;
    procedure SetOID(const Value: ByteArray); override;
    procedure SetValue(const Value: ByteArray); override;
  public
    constructor Create;
     destructor  Destroy; override;
    property Attributes : TElPKCS7Attributes read FAttributes;
  end;

  TElCertificateExtensions = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCertificateExtensions = TElCertificateExtensions;
   {$endif}

  TElCertificateExtensions =  class
  protected
    FAuthorityKeyIdentifier: TElAuthorityKeyIdentifierExtension;
    FSubjectKeyIdentifier: TElSubjectKeyIdentifierExtension;
    FKeyUsage: TElKeyUsageExtension;
    FPrivateKeyUsagePeriod: TElPrivateKeyUsagePeriodExtension;
    FCertificatePolicies: TElCertificatePoliciesExtension;
    FPolicyMappings: TElPolicyMappingsExtension;
    FSubjectAlternativeName: TElAlternativeNameExtension;
    FIssuerAlternativeName: TElAlternativeNameExtension;
    FBasicConstraints: TElBasicConstraintsExtension;
    FNameConstraints: TElNameConstraintsExtension;
    FPolicyConstraints: TElPolicyConstraintsExtension;
    FExtendedKeyUsage: TElExtendedKeyUsageExtension;
    FCRLDistributionPoints: TElCRLDistributionPointsExtension;
    FAuthorityInformationAccess: TElAuthorityInformationAccessExtension;
    //JPM Additons
    FNetscapeCertType : TElNetscapeCertTypeExtension;
    FNetscapeComment : TElNetscapeComment;
    FNetscapeCAPolicy: TElNetscapeCAPolicy;
    FNetscapeCARevokeURL: TElNetscapeCARevokeURL;
    FNetscapeRevokeURL: TElNetscapeRevokeURL;
    FNetscapeServerName: TElNetscapeServerName;
    FNetscapeBaseURL: TElNetscapeBaseURL;
    FNetscapeRenewalURL: TElNetscapeRenewalURL;
    FCommonName: TElCommonName;
    //end
    FSubjectDirectoryAttributes : TElSubjectDirectoryAttributesExtension;
    FIncluded: TSBCertificateExtensions;
    FOtherList: TElList;
    procedure ClearOtherList;
  
    function GetOtherCount: integer;
    procedure SetOtherCount(Value: integer);
    function GetOtherExtensions(Index: integer): TElCustomExtension;
  public
    constructor Create;
     destructor  Destroy; override;
    function RemoveOther(Index: integer) : boolean;
    procedure ClearExtensions;
    property AuthorityKeyIdentifier: TElAuthorityKeyIdentifierExtension
    read FAuthorityKeyIdentifier;
    property SubjectKeyIdentifier: TElSubjectKeyIdentifierExtension
    read FSubjectKeyIdentifier;
    property KeyUsage: TElKeyUsageExtension
    read FKeyUsage write FKeyUsage;
    property PrivateKeyUsagePeriod: TElPrivateKeyUsagePeriodExtension
    read FPrivateKeyUsagePeriod write FPrivateKeyUsagePeriod;
    property CertificatePolicies: TElCertificatePoliciesExtension
    read FCertificatePolicies;
    property PolicyMappings: TElPolicyMappingsExtension
    read FPolicyMappings write FPolicyMappings;
    property SubjectAlternativeName: TElAlternativeNameExtension
    read FSubjectAlternativeName write FSubjectAlternativeName;
    property IssuerAlternativeName: TElAlternativeNameExtension
    read FIssuerAlternativeName write FIssuerAlternativeName;
    property BasicConstraints: TElBasicConstraintsExtension
    read FBasicConstraints write FBasicConstraints;
    property NameConstraints: TElNameConstraintsExtension
    read FNameConstraints;
    property PolicyConstraints: TElPolicyConstraintsExtension
    read FPolicyConstraints write FPolicyConstraints;
    property ExtendedKeyUsage: TElExtendedKeyUsageExtension
    read FExtendedKeyUsage;
    property CRLDistributionPoints: TElCRLDistributionPointsExtension
    read FCRLDistributionPoints;
    property AuthorityInformationAccess: TElAuthorityInformationAccessExtension
    read FAuthorityInformationAccess;
    //jpm additon
    property NetscapeCertType : TElNetscapeCertTypeExtension read FNetscapeCertType write FNetscapeCertType;
    property NetscapeComment : TElNetscapeComment read FNetscapeComment write FNetscapeComment;
    property NetscapeBaseURL : TElNetscapeBaseURL read FNetscapeBaseURL write FNetscapeBaseURL;
    property NetscapeRevokeURL : TElNetscapeRevokeURL read FNetscapeRevokeURL write FNetscapeRevokeURL;
    property NetscapeCARevokeURL : TElNetscapeCARevokeURL read FNetscapeCARevokeURL write FNetscapeCARevokeURL;
    property NetscapeRenewalURL : TElNetscapeRenewalURL read FNetscapeRenewalURL write FNetscapeRenewalURL;
    property NetscapeCAPolicy : TElNetscapeCAPolicy read FNetscapeCAPolicy write FNetscapeCAPolicy;
    property NetscapeServerName : TElNetscapeServerName read FNetscapeServerName write FNetscapeServerName;
    property CommonName : TElCommonName read FCommonName write FCommonName;
    //end
    property SubjectDirectoryAttributes : TElSubjectDirectoryAttributesExtension
    read FSubjectDirectoryAttributes;
    property OtherExtensions[Index: integer]: TElCustomExtension read
         GetOtherExtensions ;
    property OtherCount: integer read GetOtherCount write SetOtherCount;
    property Included: TSBCertificateExtensions read FIncluded write FIncluded;
  end;

  TElExtensionWriter = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElExtensionWriter = TElExtensionWriter;
   {$endif}

  TElExtensionWriter = class
  private
    FCertificateExtensions : TElCertificateExtensions;
    FUseA3Prefix : boolean;
  public
    constructor Create(Exts : TElCertificateExtensions;
      CertExtensions: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif}); 
    function WriteExtensions: ByteArray;
    function WriteExtension(const OID: ByteArray; Critical: boolean; const Value: ByteArray): ByteArray;
    function WriteExtensionBasicConstraints: ByteArray;
    function WriteExtensionKeyUsage: ByteArray;
    function WriteExtensionPrivateKeyUsagePeriod: ByteArray;
    function WriteExtensionSubjectAltName: ByteArray;
    function WriteExtensionIssuerAltName: ByteArray;
    function WriteExtensionExtendedKeyUsage: ByteArray;
    function WriteExtensionPolicyMappings: ByteArray;
    function WriteExtensionNameConstraints: ByteArray;
    function WriteExtensionPolicyConstraints: ByteArray;
    function WriteExtensionCertificatePolicies: ByteArray;
    function WriteExtensionAuthorityKeyIdentifier: ByteArray;
    function WriteExtensionCRLDistributionPoints: ByteArray;
    function WriteExtensionAuthorityInformationAccess: ByteArray;
    function WriteExtensionNetscapeCertType: ByteArray;
    function WriteExtensionNetscapeString(const AOID: ByteArray; const ANetStr: string): ByteArray;  overload;  
    function WriteExtensionNetscapeString(const AOID: ByteArray; const ANetStr: ByteArray): ByteArray;  overload;  
    function WriteExtensionSubjectKeyIdentifier: ByteArray;
    function WritePolicyInformation(P: TElSinglePolicyInformation): ByteArray;
    function WriteDistributionPoint(P: TElDistributionPoint): ByteArray;
    function WriteExtensionSubjectDirectoryAttributes : ByteArray;
    property Extensions : TElCertificateExtensions read FCertificateExtensions;
    property UseA3Prefix : boolean read FUseA3Prefix write FUseA3Prefix;
  end;

  TElExtensionReader = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElExtensionReader = TElExtensionReader;
   {$endif}

  TElExtensionReader = class
  private
    FCertificateExtensions : TElCertificateExtensions;
    FStrictMode : boolean;
  public
    constructor Create(Exts : TElCertificateExtensions; StrictMode : boolean); 
    procedure ParseExtension(const OID: ByteArray; Critical: boolean;
      const Content: ByteArray);
    property Extensions : TElCertificateExtensions read FCertificateExtensions;
  end;

{$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
 {$else}
var
 {$endif}

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS OFF}
 {$endif}

  PEM_CERTIFICATE_BEGIN_LINE     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  '-----BEGIN CERTIFICATE-----' {$endif}; 
  PEM_CERTIFICATE_END_LINE       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  '-----END CERTIFICATE-----' {$endif};  //#$0A{$endif}; {$ifdef SB_NET}readonly;{$endif}
  PEM_CERTIFICATEX509_BEGIN_LINE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  '-----BEGIN X509 CERTIFICATE-----' {$endif}; 
  PEM_CERTIFICATEX509_END_LINE   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  '-----END X509 CERTIFICATE-----' {$endif};  //#$0A{$endif}; {$ifdef SB_NET}readonly;{$endif}

  PEM_RSA_PRIVATE_KEY_BEGIN_LINE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  '-----BEGIN RSA PRIVATE KEY-----' {$endif}; 
  PEM_RSA_PRIVATE_KEY_END_LINE   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  '-----END RSA PRIVATE KEY-----' {$endif};  //#$0A{$endif}; {$ifdef SB_NET}readonly;{$endif}
  PEM_DSA_PRIVATE_KEY_BEGIN_LINE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  '-----BEGIN DSA PRIVATE KEY-----' {$endif}; 
  PEM_DSA_PRIVATE_KEY_END_LINE   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  '-----END DSA PRIVATE KEY-----' {$endif};  //#$0A{$endif}; {$ifdef SB_NET}readonly;{$endif}
  PEM_DH_PRIVATE_KEY_BEGIN_LINE  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  '-----BEGIN DH PRIVATE KEY-----' {$endif}; 
  PEM_DH_PRIVATE_KEY_END_LINE    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  '-----END DH PRIVATE KEY-----' {$endif};  //#$0A{$endif}; {$ifdef SB_NET}readonly;{$endif}
  PEM_EC_PRIVATE_KEY_BEGIN_LINE  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  '-----BEGIN EC PRIVATE KEY-----' {$endif}; 
  PEM_EC_PRIVATE_KEY_END_LINE    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  '-----END EC PRIVATE KEY-----' {$endif}; 
  PEM_PRIVATE_KEY_BEGIN_LINE     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  '-----BEGIN PRIVATE KEY-----' {$endif}; 
  PEM_PRIVATE_KEY_END_LINE       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  '-----END PRIVATE KEY-----' {$endif}; 

  SB_CERT_OID_NETSCAPE_CERT_TYPE      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$60#$86#$48#$01#$86#$F8#$42#$01#$01 {$endif}; 
  SB_CERT_OID_NETSCAPE_BASE_URL       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$60#$86#$48#$01#$86#$F8#$42#$01#$02 {$endif}; 
  SB_CERT_OID_NETSCAPE_REVOKE_URL     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$60#$86#$48#$01#$86#$F8#$42#$01#$03 {$endif}; 
  SB_CERT_OID_NETSCAPE_CA_REVOKE_URL  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$60#$86#$48#$01#$86#$F8#$42#$01#$04 {$endif}; 
  SB_CERT_OID_NETSCAPE_RENEWAL_URL    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$60#$86#$48#$01#$86#$F8#$42#$01#$07 {$endif}; 
  SB_CERT_OID_NETSCAPE_CA_POLICY      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$60#$86#$48#$01#$86#$F8#$42#$01#$08 {$endif}; 
  SB_CERT_OID_NETSCAPE_SERVER_NAME    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$60#$86#$48#$01#$86#$F8#$42#$01#$0C {$endif}; 
  SB_CERT_OID_NETSCAPE_COMMENT        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$60#$86#$48#$01#$86#$F8#$42#$01#$0D {$endif}; 

  SB_CERT_OID_SUBJECT_DIRECTORY_ATTRIBUTES  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$1D#$09 {$endif}; 
  SB_CERT_OID_SUBJECT_KEY_IDENTIFIER        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$1D#$0E {$endif}; 
  SB_CERT_OID_KEY_USAGE                     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$1D#$0F {$endif}; 
  SB_CERT_OID_PRIVATE_KEY_USAGE_PERIOD      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$1D#$10 {$endif}; 
  SB_CERT_OID_SUBJECT_ALTERNATIVE_NAME      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$1D#$11 {$endif}; 
  SB_CERT_OID_ISSUER_ALTERNATIVE_NAME       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$1D#$12 {$endif}; 
  SB_CERT_OID_BASIC_CONSTRAINTS             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$1D#$13 {$endif}; 
  SB_CERT_OID_NAME_CONSTRAINTS              : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$1D#$1E {$endif}; 
  SB_CERT_OID_CRL_DISTRIBUTION_POINTS       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$1D#$1F {$endif}; 
  SB_CERT_OID_CERTIFICATE_POLICIES          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$1D#$20 {$endif}; 
  SB_CERT_OID_POLICY_MAPPINGS               : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$1D#$21 {$endif}; 
  SB_CERT_OID_AUTHORITY_KEY_IDENTIFIER      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$1D#$23 {$endif}; 
  SB_CERT_OID_POLICY_CONSTRAINTS            : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$1D#$24 {$endif}; 
  SB_CERT_OID_EXTENDED_KEY_USAGE            : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$1D#$25 {$endif}; 

  SB_CERT_OID_AUTHORITY_INFORMATION_ACCESS  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$01#$01 {$endif}; 

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS ON}
 {$endif}

function OctetsToIPAddress(const Octets : ByteArray) : string; 
function IPAddressToOctets(const IPAddrStr : string) : ByteArray; 

{$ifndef SB_FPC_GEN}
implementation
 {$endif}

{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
{$ifdef SB_UNICODE_VCL}
  {$WARNINGS OFF}
 {$endif}
const
  PEM_CERTIFICATE_BEGIN_LINE_STR     = '-----BEGIN CERTIFICATE-----';
  PEM_CERTIFICATE_END_LINE_STR       = '-----END CERTIFICATE-----'; //#$0A;
  PEM_CERTIFICATEX509_BEGIN_LINE_STR = '-----BEGIN X509 CERTIFICATE-----';
  PEM_CERTIFICATEX509_END_LINE_STR   = '-----END X509 CERTIFICATE-----'; //#$0A;

  PEM_RSA_PRIVATE_KEY_BEGIN_LINE_STR = '-----BEGIN RSA PRIVATE KEY-----';
  PEM_RSA_PRIVATE_KEY_END_LINE_STR   = '-----END RSA PRIVATE KEY-----'; //#$0A;
  PEM_DSA_PRIVATE_KEY_BEGIN_LINE_STR = '-----BEGIN DSA PRIVATE KEY-----';
  PEM_DSA_PRIVATE_KEY_END_LINE_STR   = '-----END DSA PRIVATE KEY-----'; //#$0A;
  PEM_DH_PRIVATE_KEY_BEGIN_LINE_STR  = '-----BEGIN DH PRIVATE KEY-----';
  PEM_DH_PRIVATE_KEY_END_LINE_STR    = '-----END DH PRIVATE KEY-----'; //#$0A;
  PEM_EC_PRIVATE_KEY_BEGIN_LINE_STR  = '-----BEGIN EC PRIVATE KEY-----';
  PEM_EC_PRIVATE_KEY_END_LINE_STR    = '-----END EC PRIVATE KEY-----';
  PEM_PRIVATE_KEY_BEGIN_LINE_STR     = '-----BEGIN PRIVATE KEY-----';
  PEM_PRIVATE_KEY_END_LINE_STR       = '-----END PRIVATE KEY-----';

  SB_CERT_OID_NETSCAPE_CERT_TYPE_STR      = #$60#$86#$48#$01#$86#$F8#$42#$01#$01;
  SB_CERT_OID_NETSCAPE_BASE_URL_STR       = #$60#$86#$48#$01#$86#$F8#$42#$01#$02;
  SB_CERT_OID_NETSCAPE_REVOKE_URL_STR     = #$60#$86#$48#$01#$86#$F8#$42#$01#$03;
  SB_CERT_OID_NETSCAPE_CA_REVOKE_URL_STR  = #$60#$86#$48#$01#$86#$F8#$42#$01#$04;
  SB_CERT_OID_NETSCAPE_RENEWAL_URL_STR    = #$60#$86#$48#$01#$86#$F8#$42#$01#$07;
  SB_CERT_OID_NETSCAPE_CA_POLICY_STR      = #$60#$86#$48#$01#$86#$F8#$42#$01#$08;
  SB_CERT_OID_NETSCAPE_SERVER_NAME_STR    = #$60#$86#$48#$01#$86#$F8#$42#$01#$0C;
  SB_CERT_OID_NETSCAPE_COMMENT_STR        = #$60#$86#$48#$01#$86#$F8#$42#$01#$0D;

  SB_CERT_OID_SUBJECT_DIRECTORY_ATTRIBUTES_STR  = #$55#$1D#$09;
  SB_CERT_OID_SUBJECT_KEY_IDENTIFIER_STR        = #$55#$1D#$0E;
  SB_CERT_OID_KEY_USAGE_STR                     = #$55#$1D#$0F;
  SB_CERT_OID_PRIVATE_KEY_USAGE_PERIOD_STR      = #$55#$1D#$10;
  SB_CERT_OID_SUBJECT_ALTERNATIVE_NAME_STR      = #$55#$1D#$11;
  SB_CERT_OID_ISSUER_ALTERNATIVE_NAME_STR       = #$55#$1D#$12;
  SB_CERT_OID_BASIC_CONSTRAINTS_STR             = #$55#$1D#$13;
  SB_CERT_OID_NAME_CONSTRAINTS_STR              = #$55#$1D#$1E;
  SB_CERT_OID_CRL_DISTRIBUTION_POINTS_STR       = #$55#$1D#$1F;
  SB_CERT_OID_CERTIFICATE_POLICIES_STR          = #$55#$1D#$20;
  SB_CERT_OID_POLICY_MAPPINGS_STR               = #$55#$1D#$21;
  SB_CERT_OID_AUTHORITY_KEY_IDENTIFIER_STR      = #$55#$1D#$23;
  SB_CERT_OID_POLICY_CONSTRAINTS_STR            = #$55#$1D#$24;
  SB_CERT_OID_EXTENDED_KEY_USAGE_STR            = #$55#$1D#$25;

  SB_CERT_OID_AUTHORITY_INFORMATION_ACCESS_STR  = #$2B#$06#$01#$05#$05#$07#$01#$01;

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS ON}
 {$endif}
 {$endif}

{$ifdef SB_FPC_GEN}
implementation
 {$endif}

resourcestring
  SInvalidCertificateExtension = 'Unrecognized critical certificate extension';
  SInvalidTypeCast = 'Invalid type cast';
  SNonCriticalExtensionMarkedAsCritical = 'Non-critical extension is marked as critical';

////////////////////////////////////////////////////////////////////////////////
// TElCertificateExtensions

constructor TElCertificateExtensions.Create;
begin
  inherited;
  FAuthorityKeyIdentifier := TElAuthorityKeyIdentifierExtension.Create;
  FSubjectKeyIdentifier := TElSubjectKeyIdentifierExtension.Create;
  FKeyUsage := TElKeyUsageExtension.Create;
  FPrivateKeyUsagePeriod := TElPrivateKeyUsagePeriodExtension.Create;
  FSubjectAlternativeName := TElAlternativeNameExtension.Create(false);
  FIssuerAlternativeName := TElAlternativeNameExtension.Create(true);
  FBasicConstraints := TElBasicConstraintsExtension.Create;
  FExtendedKeyUsage := TElExtendedKeyUsageExtension.Create;
  FPolicyMappings := TElPolicyMappingsExtension.Create;
  FNameConstraints := TElNameConstraintsExtension.Create;
  FPolicyConstraints := TElPolicyConstraintsExtension.Create;
  FCertificatePolicies := TElCertificatePoliciesExtension.Create;
  FCRLDistributionPoints := TElCRLDistributionPointsExtension.Create;
  FAuthorityInformationAccess := TElAuthorityInformationAccessExtension.Create;
  //JPM addition
  FNetscapeCertType := TElNetscapeCertTypeExtension.Create;
  FNetscapeCAPolicy:= TElNetscapeCAPolicy.Create;
  FNetscapeCARevokeURL:= TElNetscapeCARevokeURL.Create;
  FNetscapeRevokeURL:= TElNetscapeRevokeURL.Create;
  FNetscapeServerName:= TElNetscapeServerName.Create;
  FNetscapeBaseURL:= TElNetscapeBaseURL.Create;
  FNetscapeRenewalURL:= TElNetscapeRenewalURL.Create;
  FNetscapeComment := TElNetscapeComment.Create;
  FCommonName := TElCommonName.Create;
  //end
  FSubjectDirectoryAttributes := TElSubjectDirectoryAttributesExtension.Create;
  FOtherList := TElList.Create;
end;

 destructor  TElCertificateExtensions.Destroy;
begin
  FreeAndNil(FAuthorityKeyIdentifier);
  FreeAndNil(FKeyUsage);
  FreeAndNil(FPrivateKeyUsagePeriod);
  FreeAndNil(FSubjectAlternativeName);
  FreeAndNil(FIssuerAlternativeName);
  FreeAndNil(FBasicConstraints);
  FreeAndNil(FExtendedKeyUsage);
  FreeAndNil(FPolicyMappings);
  FreeAndNil(FNameConstraints);
  FreeAndNil(FPolicyConstraints);
  FreeAndNil(FSubjectKeyIdentifier);
  FreeAndNil(FCertificatePolicies);
  FreeAndNil(FCRLDistributionPoints);
  FreeAndNil(FAuthorityInformationAccess);
  //JPM addition
  FreeAndNil(FNetscapeCertType);
  FreeAndNil(FNetscapeCAPolicy);
  FreeAndNil(FNetscapeCARevokeURL);
  FreeAndNil(FNetscapeRevokeURL);
  FreeAndNil(FNetscapeServerName);
  FreeAndNil(FNetscapeBaseURL);
  FreeAndNil(FNetscapeRenewalURL);
  FreeAndNil(FNetscapeComment);
  FreeAndNil(FCommonName);
  //
  FreeAndNil(FSubjectDirectoryAttributes);
  ClearOtherList;
  FreeAndNil(FOtherList);
  inherited;
end;

procedure TElCertificateExtensions.ClearExtensions;
begin
  FAuthorityKeyIdentifier.Clear;
  FSubjectKeyIdentifier.Clear;
  FKeyUsage.Clear;
  FPrivateKeyUsagePeriod.Clear;
  FCertificatePolicies.Clear;
  FPolicyMappings.Clear;
  FSubjectAlternativeName.Clear;
  FIssuerAlternativeName.Clear;
  FBasicConstraints.Clear;
  FNameConstraints.Clear;
  FPolicyConstraints.Clear;
  FExtendedKeyUsage.Clear;
  FCRLDistributionPoints.Clear;
  FAuthorityInformationAccess.Clear;
  FNetscapeCertType.Clear;
  FNetscapeComment.Clear;
  FNetscapeCAPolicy.Clear;
  FNetscapeCARevokeURL.Clear;
  FNetscapeRevokeURL.Clear;
  FNetscapeServerName.Clear;
  FNetscapeBaseURL.Clear;
  FNetscapeRenewalURL.Clear;
  FCommonName.Clear;
  FSubjectDirectoryAttributes.Clear;
  ClearOtherList;
  FIncluded :=  [] 
end;

procedure TElCertificateExtensions.ClearOtherList;
var
  P: TElCustomExtension;
begin
  while FOtherList.Count > 0 do
  begin
    P := TElCustomExtension(FOtherList[0]);
    FOtherList.Delete(0);
    FreeAndNil(P);
  end;
end;

function TElCertificateExtensions. GetOtherExtensions (Index: integer):
  TElCustomExtension;
begin
  Result := TElCustomExtension(FOtherList[Index]);
end;

function TElCertificateExtensions.GetOtherCount: integer;
begin
  Result := FOtherList.Count;
end;

procedure TElCertificateExtensions.SetOtherCount(Value: integer);
var
  P: TElCustomExtension;
begin
  if Value < FOtherList.Count then
  begin
    while FOtherList.Count > Value do
    begin
      P := TElCustomExtension(FOtherList[FOtherList.Count - 1]);
      FOtherList.Delete(FOtherList.Count - 1);
      FreeAndNil(P);
    end;
  end
  else
    if Value > FOtherList.Count then
    while FOtherList.Count < Value do
      FOtherList.Add(TElCustomExtension.Create);
end;

function TElCertificateExtensions.RemoveOther(Index: integer) : boolean;
begin
  if Index < FOtherList.Count then
  begin
    TElCustomExtension(FOtherList[Index]). Free ;
    FOtherList.Delete(Index);
    Result := true;
  end
  else
    Result := false;
end;

constructor TElCustomExtension.Create;
begin
  inherited;
  SetLength(FOID, 0);
  SetLength(FValue, 0);
end;

 destructor  TElCustomExtension.Destroy; 
begin
  ReleaseArrays(FOID, FValue);
  inherited;
end;

procedure TElCustomExtension.Clear;
begin
  SetLength(FOID, 0);
  SetLength(FValue, 0);
end;

function TElCustomExtension.GetOID: ByteArray;
begin
  Result := FOID;
end;

procedure TElCustomExtension.SetOID(const Value: ByteArray);
begin
  FOID := CloneArray(Value);
end;

procedure TElCustomExtension.SetValue(const Value: ByteArray);
begin
  Clear;
  FValue := CloneArray(Value);
end;

function TElCustomExtension.GetValue: ByteArray;
begin
  Result := FValue;
end;

procedure TElCustomExtension.SaveToTag(Tag: TElASN1ConstrainedTag);
var
  STag: TElASN1SimpleTag;
begin
  Tag.TagId := SB_ASN1_SEQUENCE;
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_OBJECT;
  STag.Content := OID;
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_BOOLEAN;
  if Critical then
    STag.Content := GetByteArrayFromByte($FF)
  else
    STag.Content := GetByteArrayFromByte($0);
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_OCTETSTRING;
  STag.Content := CloneArray(Value);
end;

procedure TElCustomExtension.RaiseInvalidExtensionError;
begin
  if Critical then
    raise EElCertificateError.Create(SInvalidCertificateExtension);;
end;

function TElPolicyMappingsExtension. GetPolicies (Index: integer):
  TElPolicyMapping;
begin
  Result := TElPolicyMapping(FList[Index]);
end;

function TElPolicyMappingsExtension.GetCount: integer;
begin
  Result := FList.Count;
end;

constructor TElPolicyMappingsExtension.Create;
begin
  inherited;
  FList := TElList.Create;
end;

 destructor  TElPolicyMappingsExtension.Destroy;
begin
  ClearList;
  FreeAndNil(FList);
  inherited;
end;

procedure TElPolicyMappingsExtension.Clear;
begin
  ClearList;
end;

function TElPolicyMappingsExtension.GetOID: ByteArray;
begin
  Result := SB_CERT_OID_POLICY_MAPPINGS;
end;

procedure TElPolicyMappingsExtension.SetOID(const Value: ByteArray);
begin
end;

procedure TElPolicyMappingsExtension.SetValue(const Value: ByteArray);
var
  Tag, SeqTag : TElASN1ConstrainedTag;
  I : integer;
  OldCount : integer;
begin
  inherited;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if Tag.LoadFromBuffer(@Value[0], Length(Value)) then
    begin
      if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      begin
        for I := 0 to TElASN1ConstrainedTag(Tag.GetField(0)).Count - 1 do
        begin
          if TElASN1ConstrainedTag(Tag.GetField(0)).GetField(I).CheckType(SB_ASN1_SEQUENCE, true) then
          begin
            SeqTag := TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(I));
            if (SeqTag.Count = 2) and (SeqTag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) and
              (SeqTag.GetField(1).CheckType(SB_ASN1_OBJECT, false)) then
            begin
              OldCount := Count;
              Count := OldCount + 1;
              Policies[OldCount].IssuerDomainPolicy := TElASN1SimpleTag(SeqTag.GetField(0)).Content;
              Policies[OldCount].SubjectDomainPolicy := TElASN1SimpleTag(SeqTag.GetField(1)).Content;
            end
            else
              RaiseInvalidExtensionError;
          end
          else
            RaiseInvalidExtensionError;
        end;
      end
      else
        RaiseInvalidExtensionError;
    end
    else
      RaiseInvalidExtensionError;
  finally
    FreeAndNil(Tag);
  end;
end;

procedure TElPolicyMappingsExtension.SetCount(Value: integer);
var
  P: TElPolicyMapping;
begin
  if Value < FList.Count then
  begin
    while FList.Count > Value do
    begin
      P := TElPolicyMapping(FList[FList.Count - 1]);
      FList.Delete(FList.Count - 1);
      FreeAndNil(P);
    end;
  end
  else
    while FList.Count < Value do
      FList.Add(TElPolicyMapping.Create);
end;

procedure TElPolicyMappingsExtension.Remove(Index: integer);
var
  P: TElPolicyMapping;
begin
  P := TElPolicyMapping(FList[Index]);
  FreeAndNil(P);
  FList.Delete(Index);
end;

procedure TElPolicyMappingsExtension.ClearList;
var
  P : TElPolicyMapping;
begin
  while FList.Count > 0 do
  begin
    P := TElPolicyMapping(FList[FList.Count - 1]);
    FreeAndNil(P);
    FList.Count := FList.Count - 1;
  end;
end;

constructor TElAlternativeNameExtension.Create(IssuerAltName : boolean);
begin
  inherited Create;
  FContent := TElGeneralNames.Create;
  FIssuerAltName := IssuerAltName;
end;

 destructor  TElAlternativeNameExtension.Destroy;
begin
  FreeAndNil(FContent);
  inherited;
end;

procedure TElAlternativeNameExtension.Clear;
begin
  FreeAndNil(FContent);
  FContent := TElGeneralNames.Create;
end;

function TElAlternativeNameExtension.GetOID: ByteArray;
begin
  if Length(FOID) > 0 then
    Result := CloneArray(FOID)
  else
  begin
    if FIssuerAltName then
      Result := SB_CERT_OID_ISSUER_ALTERNATIVE_NAME
    else
      Result := SB_CERT_OID_SUBJECT_ALTERNATIVE_NAME;
  end;
end;

procedure TElAlternativeNameExtension.SetOID(const Value: ByteArray);
begin
  if CompareContent(Value, SB_CERT_OID_SUBJECT_ALTERNATIVE_NAME) or CompareContent(Value, SB_CERT_OID_ISSUER_ALTERNATIVE_NAME) then
    FOID := CloneArray(Value);
end;

procedure TElAlternativeNameExtension.SetValue(const Value: ByteArray);
var
  Tag : TElASN1ConstrainedTag;
begin
  inherited;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if Tag.LoadFromBuffer(@Value[0], Length(Value)) then
    begin
      if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
        FContent.LoadFromTag(TElASN1ConstrainedTag(Tag.GetField(0)), false)
        //ParseGeneralNames(TElASN1ConstrainedTag(Tag.GetField(0)), FContent, false)
      else
        RaiseInvalidExtensionError;
    end
    else
      RaiseInvalidExtensionError;
  finally
    FreeAndNil(Tag);
  end;
end;

function TElAlternativeNameExtension.GetValue: ByteArray;
var
  Tag : TElASN1ConstrainedTag;
  Size : integer;
begin
  if Length(FValue) > 0 then
    Result := CloneArray(FValue)
  else
  begin
    Tag := TElASN1ConstrainedTag.CreateInstance();
    try
      FContent.SaveToTag(Tag);
      Size := 0;
      Tag.SaveToBuffer( nil , Size);
      SetLength(Result, Size);
      Tag.SaveToBuffer( @Result[0] , Size);
      SetLength(Result, Size);
    finally
      FreeAndNil(Tag);
    end;
  end;
end;

constructor TElNameConstraintsExtension.Create;
begin
  inherited;
  FPermittedList := TElList.Create;
  FExcludedList := TElList.Create;
end;

procedure TElNameConstraintsExtension.Clear;
begin
  ClearList;
end;

function TElNameConstraintsExtension.GetOID: ByteArray;
begin
  Result := SB_CERT_OID_NAME_CONSTRAINTS;
end;

procedure TElNameConstraintsExtension.SetOID(const Value: ByteArray);
begin
end;

procedure TElNameConstraintsExtension.SetValue(const Value: ByteArray);
  procedure ReadGeneralSubtrees(Tag: TElASN1ConstrainedTag; List : TElList);
  var
    I : integer;
    SubtreeTag : TElASN1ConstrainedTag;
    CurrIndex: integer;
    Index: integer;
  begin
    for I := 0 to Tag.Count - 1 do
    begin
      if Tag.GetField(I).CheckType(SB_ASN1_SEQUENCE, true) then
      begin
        Index := List.Add(TElNameConstraint.Create);
        SubtreeTag := TElASN1ConstrainedTag(Tag.GetField(I));
        CurrIndex := 0;
        if CurrIndex >= SubtreeTag.Count then
          Continue;
        //ParseGeneralName(SubtreeTag.GetField(CurrIndex), TElNameConstraint(List[Index]).FBase);
        TElNameConstraint(List[Index]).FBase.LoadFromTag(SubtreeTag.GetField(CurrIndex));

        Inc(CurrIndex);
        if (CurrIndex < SubtreeTag.Count) and (SubtreeTag.GetField(CurrIndex).CheckType($80, false)) then
        begin
          TElNameConstraint(List[Index]).FMinimum := ASN1ReadInteger(TElASN1SimpleTag(SubtreeTag.GetField(CurrIndex)));
          Inc(CurrIndex);
        end
        else
          TElNameConstraint(List[Index]).FMinimum := 0;
        if (CurrIndex < SubtreeTag.Count) and (SubtreeTag.GetField(CurrIndex).CheckType($81, false)) then
        begin
          TElNameConstraint(List[Index]).FMaximum := ASN1ReadInteger(TElASN1SimpleTag(SubtreeTag.GetField(CurrIndex)));
        end;
      end
      else
        RaiseInvalidExtensionError;
    end;
  end;
var
  Tag, SeqTag : TElASN1ConstrainedTag;
  CurrTagIndex: integer;
begin
  inherited;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if Tag.LoadFromBuffer(@Value[0], Length(Value)) then
    begin
      if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      begin
        SeqTag := TElASN1ConstrainedTag(Tag.GetField(0));
        CurrTagIndex := 0;
        if (CurrTagIndex < SeqTag.Count) and (SeqTag.GetField(CurrTagIndex).CheckType(SB_ASN1_A0, true)) then
        begin
          // reading permittedSubtrees
          ReadGeneralSubtrees(TElASN1ConstrainedTag(SeqTag.GetField(CurrTagIndex)),
            FPermittedList);
          Inc(CurrTagIndex);
        end;
        if (CurrTagIndex < SeqTag.Count) and (SeqTag.GetField(CurrTagIndex).CheckType(SB_ASN1_A1, true)) then
        begin
          // reading excluded subtrees
          ReadGeneralSubtrees(TElASN1ConstrainedTag(SeqTag.GetField(CurrTagIndex)),
            FExcludedList);
        end;
      end
      else
        RaiseInvalidExtensionError;
    end
    else
      RaiseInvalidExtensionError;
  finally
    FreeAndNil(Tag);
  end;
end;

// This is the main method that should be called by the consumers
// (e.g. TElX509CertificateValidator)
function TElNameConstraintsExtension.AreNamesAcceptable(Subj : TElRelativeDistinguishedName;
  SubjAltName : TElGeneralNames): boolean;
var
  I, K : integer;
begin
  Result := true;
  if SubjAltName <> nil then
  begin
    // Checking excluded subtrees first
    for I := 0 to ExcludedCount - 1 do
    begin
      for K := 0 to SubjAltName.Count - 1 do
      begin
        if NameSubtreeCorresponds(ExcludedSubtrees[I].FBase, SubjAltName.Names[K]) then
        begin
          Result := false;
          Break;
        end;
      end;
      if Result and (ExcludedSubtrees[I].FBase.NameType = gnDirectoryName) then
        Result := not DirectoryNameCorresponds(ExcludedSubtrees[I].FBase.DirectoryName, Subj);
      if not Result then
        Break;
    end;
    if not Result then
      Exit;
    // Checking permitted subtrees
    if PermittedCount > 0 then
    begin
      Result := false;
      for I := 0 to PermittedCount - 1 do
      begin
        for K := 0 to SubjAltName.Count - 1 do
        begin
          if NameSubtreeCorresponds(PermittedSubtrees[I].FBase, SubjAltName.Names[K]) then
          begin
            Result := true;
            Break;
          end;
        end;
        if (not Result) and (PermittedSubtrees[I].FBase.NameType = gnDirectoryName) then
          Result := DirectoryNameCorresponds(PermittedSubtrees[I].FBase.DirectoryName, Subj);
        if Result then
          Break;
      end;
    end;
  end
  else
  begin
    // according to the X.509 RFC, if no alternative name is present in the certificate
    // we should check subject distinguished name for the 'email' attribute
    // Checking excluded subtrees first
    for I := 0 to ExcludedCount - 1 do
    begin
      for K := 0 to Subj.Count - 1 do
      begin
        if (ExcludedSubtrees[I].FBase.NameType = gnRFC822Name) and
          (CompareContent(Subj.OIDs[K], SB_CERT_OID_EMAIL)) and
          EMailAddressCorresponds(ExcludedSubtrees[I].FBase.FRFC822Name, GetRDNStringValue(Subj, K)) then
        begin
          Result := false;
          Break;
        end;
      end;
      if Result and (ExcludedSubtrees[I].FBase.NameType = gnDirectoryName) then
        Result := not DirectoryNameCorresponds(ExcludedSubtrees[I].FBase.DirectoryName, Subj);
      if not Result then
        Break;
    end;
    if not Result then
      Exit;
    // Checking permitted subtrees
    if PermittedCount > 0 then
    begin
      Result := false;
      for I := 0 to PermittedCount - 1 do
      begin
        for K := 0 to Subj.Count - 1 do
        begin
          if (PermittedSubtrees[I].FBase.NameType = gnRFC822Name) and
            (CompareContent(Subj.OIDs[K], SB_CERT_OID_EMAIL)) and
            EMailAddressCorresponds(PermittedSubtrees[I].FBase.FRFC822Name, GetRDNStringValue(Subj, K)) then
          begin
            Result := true;
            Break;
          end;
        end;
        if (not Result) and (PermittedSubtrees[I].FBase.NameType = gnDirectoryName) then
          Result := DirectoryNameCorresponds(PermittedSubtrees[I].FBase.DirectoryName, Subj);
        if Result then
          Break;
      end;
    end;
  end;
end;

function TElNameConstraintsExtension.NameSubtreeCorresponds(Subtree: TElGeneralName;
  Name : TElGeneralName): boolean;
begin
  Result := false;
  if Subtree.NameType = Name.NameType then
  begin
    if Subtree.NameType = gnUniformResourceIdentifier then
    begin
      Result := URICorresponds(Subtree.FUniformResourceIdentifier, Name.UniformResourceIdentifier);
    end
    else if Subtree.NameType = gnRFC822Name then
    begin
      Result := EMailAddressCorresponds(Subtree.RFC822Name, Name.FRFC822Name);
    end
    else if Subtree.NameType = gnDNSName then
    begin
      Result := DNSNameCorresponds(Subtree.FDNSName, Name.DNSName);
    end
    else if Subtree.NameType = gnDirectoryName then
    begin
      Result := DirectoryNameCorresponds(Subtree.FDirectoryName, Name.FDirectoryName);
    end
    else if Subtree.NameType = gnIPAddress then
    begin
      Result := IPAddressCorresponds(Subtree.IpAddressBytes, Name.IpAddressBytes);
    end;
  end;
end;

function TElNameConstraintsExtension.URICorresponds(const URITpl, URI: string): boolean;
var
  Proto, User, Pass, Host, Path, Anchor, Pars : string;
  Port : word;
begin
  Port := 0;
  try
    ParseURL(URI, false, Proto, User, Pass, Host, Port, Path, Anchor, Pars);
  except
    Host := '';
  end;
  if StringStartsWith(URITpl, '.') then
    Result := StringEndsWith(Host, URITpl, true)
  else
    Result := StringEquals(URITpl, Host, true);
end;

function TElNameConstraintsExtension.EMailAddressCorresponds(const EMailTpl, EMail : string): boolean;
var
  Idx : integer;
  Domain : string;
begin
  if StringIndexOf(EMailTpl, '@') >= AnsiStrStartOffset then
    Result := StringEquals(EMailTpl, EMail, true)
  else
  begin
    Idx := StringIndexOf(EMail, '@');
    if Idx >= AnsiStrStartOffset then
    begin
      Domain := StringSubstring(EMail, Idx + 1);
      if StringStartsWith(EMailTpl, '.') then
        Result := StringEndsWith(Domain, EMailTpl, true)
      else
        Result := StringEquals(EMailTpl, Domain, true);
    end
    else
      Result := false;
  end;
end;

function TElNameConstraintsExtension.DNSNameCorresponds(const DNSNameTpl, DNSName : string): boolean;
var
  PrefixedTpl : string;
begin
  PrefixedTpl := '.' + DNSNameTpl;
  Result := StringEquals(DNSNameTpl, DNSName) or StringEndsWith(DNSName, PrefixedTpl, true);
end;

function TElNameConstraintsExtension.DirectoryNameCorresponds(DirNameTpl, DirName : TElRelativeDistinguishedName): boolean;
//var
//  I : integer;
begin
  Result := NonstrictCompareRDN(DirNameTpl, DirName);
  (*for I := 0 to DirNameTpl.Count - 1 do
    for J := 0 to DirName.Count - 1 do
    begin
      if DirNameTpl
    end;*)
end;

function TElNameConstraintsExtension.IPAddressCorresponds(const IPAddressTpl,
  IPAddress: ByteArray): boolean;
var
  TplSubnet, TplMask : ByteArray;
  I : integer;
begin
  TplMask := EmptyArray;
  TplSubnet := EmptyArray;
  if (Length(IPAddressTpl) = 8) and (Length(IPAddress) = 4) then
  begin
    TplSubnet := CloneArray( @IPAddressTpl[0] , 4);
    TplMask := CloneArray( @IPAddressTpl[4] , 4);
  end
  else if (Length(IPAddressTpl) = 32) and (Length(IPAddress) = 16) then
  begin
    TplSubnet := CloneArray( @IPAddressTpl[0] , 16);
    TplMask := CloneArray( @IPAddressTpl[16] , 16);
  end
  else
  begin
    Result := false;
    Exit;
  end;
  Result := true;
  for I := 0 to Length(TplSubnet) - 1 do
  begin
    if (TplSubnet[I] and TplMask[I]) <> (IPAddress[I] and TplMask[I]) then
    begin
      Result := false;
      Break;
    end;
  end;        
end;

////////////////////////////////////////////////////////////////////////////////
// TElGeneralName class

constructor TElGeneralName.Create;
begin
  inherited;
  FDirectoryName := TElRelativeDistinguishedName.Create;
  FEdiPartyName := TElEDIPartyName.Create;
  FOtherName := TElOtherName.Create;
  FPermanentIdentifier := TElPermanentIdentifier.Create;
  SetLength(FIpAddressBytes, 0);
end;

 destructor  TElGeneralName.Destroy;
begin
  FreeAndNil(FDirectoryName);
  FreeAndNil(FEdiPartyName);
  FreeAndNil(FOtherName);
  FreeAndNil(FPermanentIdentifier);
  inherited;
end;

function TElGeneralName.Equals(Other : TElGeneralName) : boolean;
begin
  result := false;
  if (GetIsEmpty = Other.GetIsEmpty) and (Self.NameType = Other.NameType) then
  begin
    case NameType of
      gnRFC822Name:
        result := Self.RFC822Name = Other.RFC822Name;
      gnDNSName:
        result := Self.DNSName = Other.DNSName;
      gnDirectoryName:
        result := CompareRDN(Self.DirectoryName, Other.DirectoryName);
      gnEdiPartyName:
        result := (Self.EdiPartyName.NameAssigner = Other.EdiPartyName.NameAssigner) and
                  (Self.EdiPartyName.NameAssigner = Other.EdiPartyName.NameAssigner);
      gnUniformResourceIdentifier:
        result := Self.UniformResourceIdentifier = Other.UniformResourceIdentifier;
      gnIPAddress:
        result := Self.IpAddress = Other.IpAddress;
      gnRegisteredID:
        result := CompareContent(Self.RegisteredID, Other.RegisteredID);
      gnOtherName:
        result := CompareContent(Self.OtherName.OID, Other.OtherName.OID) and
                  CompareContent(Self.OtherName.Value, Other.OtherName.Value);
      gnPermanentIdentifier:
        result := (Self.PermanentIdentifier.Assigner = Other.PermanentIdentifier.Assigner) and (Self.PermanentIdentifier.PermanentIdentifier = Other.PermanentIdentifier.PermanentIdentifier);
    end;
  end;
end;

function TElGeneralName.LoadFromTag(Tag: TElASN1CustomTag): boolean;
var
  CurrIndex : integer;
  B : boolean;
  Size : integer;
  Val : ByteArray;
begin
  Result := true;
  FNameType := gnUnknown;
  if Tag.CheckType(SB_ASN1_A0, true) then
  begin
    // other name
    if (TElASN1ConstrainedTag(Tag).Count = 2) and
      (TElASN1ConstrainedTag(Tag).GetField(0).CheckType(SB_ASN1_OBJECT, false)) and
      (TElASN1ConstrainedTag(Tag).GetField(1).CheckType(SB_ASN1_A0, true)) then
    begin
      FOtherName.OID := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(0)).Content;
      B := TElASN1ConstrainedTag(Tag).GetField(1).WriteHeader;
      TElASN1ConstrainedTag(Tag).GetField(1).WriteHeader := false;
      Size := 0;
      TElASN1ConstrainedTag(Tag).GetField(1).SaveToBuffer( nil , Size);
      SetLength(Val, Size);
      TElASN1ConstrainedTag(Tag).GetField(1).SaveToBuffer( @Val[0] , Size);
      SetLength(Val, Size);
      TElASN1ConstrainedTag(Tag).GetField(1).WriteHeader := B;
      FOtherName.Value := Val;
      FNameType := gnOtherName;
      ReleaseArray(Val);
      TryKnownOtherNames;
    end
    else
      Result := false;
  end
  else if Tag.CheckType(SB_ASN1_A1_PRIMITIVE, false) then
  begin
    // rfc822 name
    FRFC822Name := StringOfBytes(TElASN1SimpleTag(Tag).Content);
    FNameType := gnRFC822Name;
  end
  else if Tag.CheckType(SB_ASN1_A2_PRIMITIVE, false) then
  begin
    // dns name
    FDnsName := StringOfBytes(TElASN1SimpleTag(Tag).Content);
    FNameType := gnDnsName;
  end
  else if Tag.CheckType(SB_ASN1_A3, true) then
  begin
    // ORAddress, unsupported
  end
  else if Tag.CheckType(SB_ASN1_A4, true) then
  begin
    // directory name
    if (TElASN1ConstrainedTag(Tag).Count = 1) and (TElASN1ConstrainedTag(Tag).GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      FDirectoryName.LoadFromTag(TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(0)), true);
    FNameType := gnDirectoryName;
  end
  else if Tag.CheckType(SB_ASN1_A5, true) then
  begin
    // edi party name
    CurrIndex := 0;
    if (CurrIndex < TElASN1ConstrainedTag(Tag).Count) and (TElASN1ConstrainedTag(Tag).GetField(CurrIndex).CheckType(SB_ASN1_A0_PRIMITIVE, false)) then
    begin
      FEdiPartyName.NameAssigner := StringOfBytes(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(CurrIndex)).Content);
      Inc(CurrIndex);
    end
    else
      FEdiPartyName.NameAssigner := '';
    if (CurrIndex < TElASN1ConstrainedTag(Tag).Count) and (TElASN1ConstrainedTag(Tag).GetField(CurrIndex).CheckType(SB_ASN1_A1_PRIMITIVE, false)) then
      FEdiPartyName.PartyName := StringOfBytes(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(CurrIndex)).Content);
    FNameType := gnEdiPartyName;
  end
  else if Tag.CheckType(SB_ASN1_A6_PRIMITIVE, false) then
  begin
    // uri
    FUniformResourceIdentifier := StringOfBytes(TElASN1SimpleTag(Tag).Content);
    FNameType := gnUniformResourceIdentifier;
  end
  else if Tag.CheckType(SB_ASN1_A7_PRIMITIVE, false) then
  begin
    // ip address
    FIpAddress := OctetsToIPAddress(TElASN1SimpleTag(Tag).Content);
    FIpAddressBytes := CloneArray(TElASN1SimpleTag(Tag).Content);
    FNameType := gnIPAddress;
  end
  else if Tag.CheckType(SB_ASN1_A8_PRIMITIVE, false) then
  begin
    // registered id
    FRegisteredID := TElASN1SimpleTag(Tag).Content;
    FNameType := gnRegisteredID;
  end
  else
    Result := false;
end;

function TElGeneralName.SaveToTag(Tag: TElASN1SimpleTag): boolean;
var
  STag: TElASN1SimpleTag;
  CTag: TElASN1ConstrainedTag;
  Size : integer;
  Buf : ByteArray;
begin
  Result := true;
  SaveKnownOtherNames;
  if FNameType = gnRFC822Name then
  begin
    Tag.Content := {$ifndef SB_ANSI_VCL}StrToUTF8 {$else}CreateByteArrayConst {$endif}(FRFC822Name);
    Tag.TagId := SB_ASN1_A1_PRIMITIVE;
  end
  else
  if FNameType = gnDNSName then
  begin
    Tag.Content := {$ifndef SB_ANSI_VCL}StrToUTF8 {$else}CreateByteArrayConst {$endif}(FDnsName);
    Tag.TagId := SB_ASN1_A2_PRIMITIVE;
  end
  else
  if FNameType = gnDirectoryName then
  begin
    CTag := TElASN1ConstrainedTag.CreateInstance;
    try
      FDirectoryName.SaveToTag(CTag);
      Size := 0;
      CTag.WriteHeader := true;
      CTag.SaveToBuffer( nil , Size);
      SetLength(Buf, Size);
      CTag.SaveToBuffer( @Buf[0] , Size);
      SetLength(Buf, Size);
      Tag.TagId := SB_ASN1_A4;
      Tag.Content := CloneArray(Buf);
    finally
      FreeAndNil(CTag);
    end;
  end
  else
  if FNameType = gnEdiPartyName then
  begin
    CTag := TElASN1ConstrainedTag.CreateInstance;
    try
      if Length(FEdiPartyName.NameAssigner) > 0 then
      begin
        STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
        STag.TagId := SB_ASN1_A0_PRIMITIVE;  
        STag.Content := {$ifndef SB_ANSI_VCL}StrToUTF8 {$else}CreateByteArrayConst {$endif}(FEdiPartyName.NameAssigner);
      end;
      STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
      STag.TagId := SB_ASN1_A1_PRIMITIVE;
      STag.Content := {$ifndef SB_ANSI_VCL}StrToUTF8 {$else}CreateByteArrayConst {$endif}(FEdiPartyName.PartyName);
      CTag.WriteHeader := false;//true;
      Size := 0;
      CTag.SaveToBuffer( nil , Size);
      SetLength(Buf, Size);
      CTag.SaveToBuffer( @Buf[0] , Size);
      SetLength(Buf, Size);
      Tag.TagId := SB_ASN1_A5;
      Tag.Content := CloneArray(Buf);
    finally
      FreeAndNil(CTag);
    end;
  end
  else
  if FNameType = gnUniformResourceIdentifier then
  begin
    Tag.Content := {$ifndef SB_ANSI_VCL}StrToUTF8 {$else}CreateByteArrayConst {$endif}(FUniformResourceIdentifier);
    Tag.TagId := SB_ASN1_A6_PRIMITIVE;
  end
  else
  if FNameType = gnIPAddress then
  begin
    if (Length(FIpAddressBytes) > 0) then
      Tag.Content := CloneArray(FIpAddressBytes)
    else
      Tag.Content := IpAddressToOctets(FIpAddress);
    Tag.TagId := SB_ASN1_A7_PRIMITIVE;
  end
  else
  if FNameType = gnRegisteredID then
  begin
    Tag.Content := FRegisteredID;
    Tag.TagId := SB_ASN1_A8_PRIMITIVE;
  end
  else
  if FNameType = gnOtherName then
  begin
    CTag := TElASN1ConstrainedTag.CreateInstance;
    try
      STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
      STag.TagId := SB_ASN1_OBJECT;
      STag.Content := FOtherName.FOID;
      STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
      STag.TagId := SB_ASN1_A0;
      STag.Content := FOtherName.FValue;
      CTag.WriteHeader := false;
      Size := 0;
      CTag.SaveToBuffer( nil , Size);
      SetLength(Buf, Size);
      CTag.SaveToBuffer( @Buf[0] , Size);
      SetLength(Buf, Size);
      Tag.TagId := SB_ASN1_A0;
      Tag.Content := CloneArray(Buf);
    finally
      FreeAndNil(CTag);
    end;
  end
  else
    Result := false;
  ReleaseArray(Buf);
end;

function TElGeneralName.GetIsEmpty : boolean;
begin
  Result := not ((Length(FRFC822Name) > 0) or (Length(FDNSName) > 0) or
    (FDirectoryName.Count > 0) or (Length(FEdiPartyName.FNameAssigner) > 0) or
    (Length(FEdiPartyName.FPartyName) > 0) or
    (Length(FUniformResourceIdentifier) > 0) or (Length(FIpAddress) > 0) or (Length(FIpAddressBytes) > 0) or
    (Length(FRegisteredID) > 0));
end;

procedure TElGeneralName.SetRegisteredID(const V : ByteArray);
begin
  FRegisteredID := CloneArray(V);
end;

procedure TElGeneralName.Assign(Source:  TPersistent );
begin
  if not (Source is TElGeneralName) then
    raise EElCertificateError.Create(SInvalidTypeCast);
  FRFC822Name := TElGeneralName(Source).FRFC822Name;
  FDNSName := TElGeneralName(Source).FDNSName;
  FDirectoryName.Assign(TElGeneralName(Source).FDirectoryName);
  FEdiPartyName.FNameAssigner := TElGeneralName(Source).FEdiPartyName.FNameAssigner;
  FEdiPartyName.FPartyName := TElGeneralName(Source).FEdiPartyName.FPartyName;
  FUniformResourceIdentifier := TElGeneralName(Source).FUniformResourceIdentifier;
  FIpAddress := TElGeneralName(Source).FIpAddress;
  FIpAddressBytes := CloneArray(TElGeneralName(Source).FIpAddressBytes);
  FRegisteredID := CloneArray(TElGeneralName(Source).FRegisteredID);
  FOtherName.FOID := CloneArray(TElGeneralName(Source).FOtherName.FOID);
  FOtherName.FValue := CloneArray(TElGeneralName(Source).FOtherName.FValue);
  FPermanentIdentifier.FPermanentIdentifier := CloneArray(TElGeneralName(Source).FPermanentIdentifier.FPermanentIdentifier);
  FPermanentIdentifier.FAssigner := CloneArray(TElGeneralName(Source).FPermanentIdentifier.FAssigner);
  FNameType := TElGeneralName(Source).FNameType;
end;

procedure TElGeneralName.AssignTo(Dest:  TPersistent );
begin
  if not (Dest is TElGeneralName) then
    raise EElCertificateError.Create(SInvalidTypeCast);
  Dest.Assign(Self);
end;

procedure TElGeneralName.TryKnownOtherNames;
begin
  if CompareContent(FOtherName.FOID, SB_CERT_OID_PERMANENT_IDENTIFIER) then
  begin
    ParsePermanentIdentifier(@FOtherName.FValue[0], Length(FOtherName.FValue));
    FNameType := gnPermanentIdentifier;
  end;
end;

procedure TElGeneralName.SaveKnownOtherNames;
var
  ONOID, ONContent: ByteArray;
begin
  if NameType = gnPermanentIdentifier then
  begin
    SavePermanentIdentifier(ONOID, ONContent);
    FOtherName.OID := ONOID;
    FOtherName.Value := ONContent;
    NameType := gnOtherName;
  end;
end;

procedure TElGeneralName.ParsePermanentIdentifier(Buffer: pointer; Size: integer);
var
  Tag, Root : TElASN1ConstrainedTag;
  CurrIndex: integer;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if Tag.LoadFromBuffer(Buffer,  Size ) then
    begin
      if (Tag.Count <> 1) or (not Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
        Exit;
      Root := TElASN1ConstrainedTag(Tag.GetField(0));
      CurrIndex := 0;
      if CurrIndex >= Root.Count then
        Exit;
      if Root.GetField(CurrIndex).CheckType(SB_ASN1_UTF8STRING, false) then
      begin
        FPermanentIdentifier.FPermanentIdentifier := TElASN1SimpleTag(Root.GetField(CurrIndex)).Content;
        Inc(CurrIndex);
      end;
      if (CurrIndex < Root.Count) and Root.GetField(CurrIndex).CheckType(SB_ASN1_OBJECT, false) then
        FPermanentIdentifier.FAssigner := TElASN1SimpleTag(Root.GetField(CurrIndex)).Content;
    end;
  finally
    FreeAndNil(Tag);
  end;
end;

procedure TElGeneralName.SavePermanentIdentifier(var OID : ByteArray; var Content: ByteArray);
var
  Tag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  Size : integer;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    Tag.TagId := SB_ASN1_SEQUENCE;
    if Length(FPermanentIdentifier.FPermanentIdentifier) > 0 then
    begin
      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      STag.TagId := SB_ASN1_UTF8STRING;
      STag.Content := FPermanentIdentifier.FPermanentIdentifier;
    end;
    if Length(FPermanentIdentifier.FAssigner) > 0 then
    begin
      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      STag.TagId := SB_ASN1_OBJECT;
      STag.Content := FPermanentIdentifier.FAssigner;
    end;
    OID := SB_CERT_OID_PERMANENT_IDENTIFIER;
    Size := 0;
    Tag.SaveToBuffer( nil , Size);
    SetLength(Content, Size);
    Tag.SaveToBuffer( @Content[0] , Size);
    SetLength(Content, Size);
  finally
    FreeAndNil(Tag);
  end;
end;

 destructor  TElNameConstraintsExtension.Destroy;
begin
  ClearList;
  FreeAndNil(FPermittedList);
  FreeAndNil(FExcludedList);
  inherited;
end;

function TElNameConstraintsExtension. GetPermittedSubtrees (Index: integer):
  TElNameConstraint;
begin
  Result := TElNameConstraint(FPermittedList[Index]);
end;

function TElNameConstraintsExtension. GetExcludedSubtrees (Index: integer):
  TElNameConstraint;
begin
  Result := TElNameConstraint(FExcludedList[Index]);
end;

function TElNameConstraintsExtension.GetPermittedCount: integer;
begin
  Result := FPermittedList.Count;
end;

function TElNameConstraintsExtension.GetExcludedCount: integer;
begin
  Result := FExcludedList.Count;
end;

procedure TElNameConstraintsExtension.SetPermittedCount(Value: integer);
var
  P: TElNameConstraint;
begin
  if Value < FPermittedList.Count then
  begin
    while FPermittedList.Count > Value do
    begin
      P := TElNameConstraint(FPermittedList[FPermittedList.Count - 1]);
      FPermittedList.Delete(FPermittedList.Count - 1);
      FreeAndNil(P);
    end;
  end
  else
    while FPermittedList.Count < Value do
      FPermittedList.Add(TElNameConstraint.Create);
end;

procedure TElNameConstraintsExtension.SetExcludedCount(Value: integer);
var
  P: TElNameConstraint;
begin
  if Value < FExcludedList.Count then
  begin
    while FExcludedList.Count > Value do
    begin
      P := TElNameConstraint(FExcludedList[FExcludedList.Count - 1]);
      FExcludedList.Delete(FExcludedList.Count - 1);
      FreeAndNil(P);
    end;
  end
  else
    while FExcludedList.Count < Value do
      FExcludedList.Add(TElNameConstraint.Create);
end;

procedure TElNameConstraintsExtension.ClearList;
begin
  while FPermittedList.Count > 0 do
  begin
    TElNameConstraint(FPermittedList[FPermittedList.Count - 1]). Free ;
    FPermittedList.Count := FPermittedList.Count - 1;
  end;
  while FExcludedList.Count > 0 do
  begin
    TElNameConstraint(FExcludedList[FExcludedList.Count - 1]). Free ;
    FExcludedList.Count := FExcludedList.Count - 1;
  end;
end;

procedure TElNameConstraintsExtension.RemovePermitted(Index: integer);
begin
  TElNameConstraint(FPermittedList[Index]). Free ;
  FPermittedList.Delete(Index);
end;

procedure TElNameConstraintsExtension.RemoveExcluded(Index: integer);
begin
  TElNameConstraint(FExcludedList[Index]). Free ;
  FExcludedList.Delete(Index);
end;

 destructor  TElUserNotice.Destroy;
begin
  inherited;
end;



function TElUserNotice. GetNoticeNumbers (Index: integer): integer;
begin
  if Index >= Length(FNoticeNumbers) then
    raise EElCertificateError.Create('List index out of bounds')
  else
    Result := FNoticeNumbers[Index];
end;

procedure TElUserNotice. SetNoticeNumbers (Index: integer; Value: integer);
begin
  if Index >= Length(FNoticeNumbers) then
    raise EElCertificateError.Create('List index out of bounds')
  else
    FNoticeNumbers[Index] := Value;
end;

function TElUserNotice.GetNoticeNumbersCount: integer;
begin
  Result := Length(FNoticeNumbers);
end;

procedure TElUserNotice.SetNoticeNumbersCount(Value: integer);
begin
  SetLength(FNoticeNumbers, Value);
end;

constructor TElSinglePolicyQualifier.Create;
begin
  inherited;
  FUserNotice := TElUserNotice.Create;
end;

 destructor  TElSinglePolicyQualifier.Destroy;
begin
  FreeAndNil(FUserNotice);
  ReleaseString(FCPSURI);
  inherited;
end;

constructor TElSinglePolicyInformation.Create;
begin
  inherited;
  FPolicyQualifiers := TElList.Create;
end;

 destructor  TElSinglePolicyInformation.Destroy;
var
  i: integer;
begin
  for i := 0 to FPolicyQualifiers.Count - 1 do
    TElSinglePolicyQualifier(FPolicyQualifiers[i]). Free ;

  FreeAndNil(FPolicyQualifiers);
  inherited;
end;

function TElSinglePolicyInformation.GetPolicyQualifier(Index: integer): TElSinglePolicyQualifier;
begin
  Result := TElSinglePolicyQualifier(FPolicyQualifiers[Index]);
end;

function TElSinglePolicyInformation.GetQualifierCount: integer;
begin
  Result := FPolicyQualifiers.Count;
end;

procedure TElSinglePolicyInformation.SetQualifierCount(Value: integer);
begin
  if Value < FPolicyQualifiers.Count then
  begin
    while FPolicyQualifiers.Count > Value do
    begin
      TElSinglePolicyQualifier(FPolicyQualifiers[FPolicyQualifiers.Count - 1]). Free ;
      FPolicyQualifiers.Count := FPolicyQualifiers.Count - 1;
    end;
  end
  else
    while FPolicyQualifiers.Count < Value do
      FPolicyQualifiers.Add(TElSinglePolicyQualifier.Create);
end;

procedure TElSinglePolicyInformation.SetPolicyIdentifier(const V : ByteArray);
begin
  FPolicyIdentifier := CloneArray(V);
end;

function TElCertificatePoliciesExtension.GetPolicyInformation(Index: integer):
TElSinglePolicyInformation;
begin
  Result := TElSinglePolicyInformation(FList[Index]);
end;

function TElCertificatePoliciesExtension.GetCount: integer;
begin
  Result := FList.Count;
end;

procedure TElCertificatePoliciesExtension.Clear;
begin
  ClearList;
end;

function TElCertificatePoliciesExtension.GetOID: ByteArray;
begin
  Result := SB_CERT_OID_CERTIFICATE_POLICIES;
end;

procedure TElCertificatePoliciesExtension.SetOID(const Value: ByteArray);
begin
end;

procedure TElCertificatePoliciesExtension.SetValue(const Value: ByteArray);
  procedure ReadUserNotice(Tag: TElASN1ConstrainedTag; Notice: TElUserNotice);
  var
    CurrIndex: integer;
    SeqTag : TElASN1ConstrainedTag;
    I : integer;
    OldCount : integer;
  begin
    CurrIndex := 0;
    if (CurrIndex < Tag.Count) and (Tag.GetField(CurrIndex).CheckType(SB_ASN1_SEQUENCE, true)) then
    begin
      SeqTag := TElASN1ConstrainedTag(Tag.GetField(CurrIndex));
      Inc(CurrIndex);
      if (SeqTag.Count = 2) and (SeqTag.GetField(0).TagId in [SB_ASN1_VISIBLESTRING,
        SB_ASN1_UTF8STRING, SB_ASN1_IA5STRING]) and (not SeqTag.GetField(0).IsConstrained) and
        (SeqTag.GetField(1).CheckType(SB_ASN1_SEQUENCE, true)) then
      begin
        Notice.FOrganization := ASN1ReadString(TElASN1SimpleTag(SeqTag.GetField(0)).Content, SeqTag.GetField(0).TagId);
        // Replaced with the call to ASN1ReadString by EM, 13/12/2013
        //Notice.FOrganization := UTF8ToStr(TElASN1SimpleTag(SeqTag.GetField(0)).Content);
        for I := 0 to TElASN1ConstrainedTag(SeqTag.GetField(1)).Count - 1 do
        begin
          if TElASN1ConstrainedTag(SeqTag.GetField(1)).GetField(I).CheckType(SB_ASN1_INTEGER, false) then
          begin
            OldCount := Length(Notice.FNoticeNumbers);
            SetLength(Notice.FNoticeNumbers, OldCount + 1);
            Notice.FNoticeNumbers[OldCount] := ASN1ReadInteger(TElASN1SimpleTag(TElASN1ConstrainedTag(SeqTag.GetField(1)).GetField(I)));
          end;
        end;
      end;
    end;
    if (CurrIndex < Tag.Count) and (not Tag.GetField(CurrIndex).IsConstrained) then
    begin
      Notice.FExplicitText := ASN1ReadString(TElASN1SimpleTag(Tag.GetField(CurrIndex)).Content, Tag.GetField(CurrIndex).TagId);

      // Replaced with the call to ASN1ReadString by EM, 13/12/2013
      (*
      if Tag.GetField(CurrIndex).TagId = SB_ASN1_UTF8STRING then
        Notice.FExplicitText := UTF8ToStr(TElASN1SimpleTag(Tag.GetField(CurrIndex)).Content)
      else if Tag.GetField(CurrIndex).TagId = SB_ASN1_VISIBLESTRING then
        Notice.FExplicitText := StringOfBytes(TElASN1SimpleTag(Tag.GetField(CurrIndex)).Content)
      else if Tag.GetField(CurrIndex).TagId = SB_ASN1_BMPSTRING then
        Notice.FExplicitText := WideStrToStr(UnicodeChangeEndianness(TElASN1SimpleTag(Tag.GetField(CurrIndex)).Content));
      *)
    end;
  end;
var
  Tag, SeqTag, PITag, PQTag : TElASN1ConstrainedTag;
  I, J : integer;
  CurrTagIndex : integer;
  Obj : ByteArray;
  Index : integer;
  Qualifier: TElSinglePolicyQualifier;
begin
  inherited;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if Tag.LoadFromBuffer(@Value[0], Length(Value)) then
    begin
      if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      begin
        SeqTag := TElASN1ConstrainedTag(Tag.GetField(0));
        for I := 0 to SeqTag.Count - 1 do
        begin
          if SeqTag.GetField(I).CheckType(SB_ASN1_SEQUENCE, true) then
          begin
            PITag := TElASN1ConstrainedTag(SeqTag.GetField(I));
            CurrTagIndex := 0;
            Obj := nil;
            if (CurrTagIndex < PITag.Count) and (PITag.GetField(CurrTagIndex).CheckType(SB_ASN1_OBJECT, false)) then
            begin
              Obj := TElASN1SimpleTag(PITag.GetField(CurrTagIndex)).Content;
              Inc(CurrTagIndex);
            end
            else
              Continue;

            Index := FList.Add(TElSinglePolicyInformation.Create);
            TElSinglePolicyInformation(FList[Index]).PolicyIdentifier := Obj;

            if (CurrTagIndex < PITag.Count) and (PITag.GetField(CurrTagIndex).CheckType(SB_ASN1_SEQUENCE, true)) then
            begin
              for J := 0 to TElASN1ConstrainedTag(PITag.GetField(CurrTagIndex)).Count - 1 do
              begin
                if TElASN1ConstrainedTag(PITag.GetField(CurrTagIndex)).GetField(J).CheckType(SB_ASN1_SEQUENCE, true) then
                begin
                  PQTag := TElASN1ConstrainedTag(TElASN1ConstrainedTag(PITag.GetField(CurrTagIndex)).GetField(J));
                  CurrTagIndex := 0;
                  if (CurrTagIndex < PQTag.Count) and (PQTag.GetField(CurrTagIndex).CheckType(SB_ASN1_OBJECT, false)) then
                  begin
                    Obj := TElASN1SimpleTag(PQTag.GetField(CurrTagIndex)).Content;
                    Inc(CurrTagIndex);
                  end
                  else
                    Continue;
                  if (CurrTagIndex < PQTag.Count) then
                  begin
                    if CompareContent(Obj, SB_OID_QT_CPS) and (PQTag.GetField(CurrTagIndex).CheckType(SB_ASN1_IA5STRING, false)) then
                    begin
                      Qualifier := TElSinglePolicyQualifier.Create;
                      Qualifier.FCPSURI := StringOfBytes(TElASN1SimpleTag(PQTag.GetField(CurrTagIndex)).Content);
                      TElSinglePolicyInformation(FList[Index]).FPolicyQualifiers.Add(Qualifier);
                    end
                    else if CompareContent(Obj, SB_OID_QT_UNOTICE) and (PQTag.GetField(CurrTagIndex).CheckType(SB_ASN1_SEQUENCE, true)) then
                    begin
                      Qualifier := TElSinglePolicyQualifier.Create;
                      ReadUserNotice(TElASN1ConstrainedTag(PQTag.GetField(CurrTagIndex)), Qualifier.FUserNotice);
                      TElSinglePolicyInformation(FList[Index]).FPolicyQualifiers.Add(Qualifier);
                    end;
                  end;
                end;
              end;
            end;
          end
          else
            RaiseInvalidExtensionError;
        end;
      end
      else
        RaiseInvalidExtensionError;
    end
    else
      RaiseInvalidExtensionError;
  finally
    FreeAndNil(Tag);
  end;
end;

procedure TElCertificatePoliciesExtension.SetCount(Value: integer);
begin
  if Value < FList.Count then
  begin
    while FList.Count > Value do
    begin
      TElSinglePolicyInformation(FList[FList.Count - 1]). Free ;
      FList.Count := FList.Count - 1;
    end;
  end
  else
    while FList.Count < Value do
      FList.Add(TElSinglePolicyInformation.Create);
end;

constructor TElCertificatePoliciesExtension.Create;
begin
  inherited;
  FList := TElList.Create;
end;

 destructor  TElCertificatePoliciesExtension.Destroy;
begin
  ClearList;
  FreeAndNil(FList);
  inherited;
end;

procedure TElCertificatePoliciesExtension.ClearList;
begin
  while FList.Count > 0 do
  begin
    TElSinglePolicyInformation(FList[FList.Count - 1]). Free ;
    FList.Count := FList.Count - 1;
  end;
end;

procedure TElCertificatePoliciesExtension.Remove(Index: integer);
begin
  TElSinglePolicyInformation(FList[Index]). Free ;
  FList.Delete(Index);
end;

constructor TElNameConstraint.Create;
begin
  inherited;
  FBase := TElGeneralName.Create;
end;

 destructor  TElNameConstraint.Destroy;
begin
  FreeAndNil(FBase);
  inherited;
end;

constructor TElAuthorityKeyIdentifierExtension.Create;
begin
  inherited;
  FAuthorityCertIssuer := TElGeneralNames.Create;
end;

 destructor  TElAuthorityKeyIdentifierExtension.Destroy;
begin
  FreeAndNil(FAuthorityCertIssuer);
  inherited;
end;

procedure TElAuthorityKeyIdentifierExtension.Clear;
begin
  SetLength(FKeyIdentifier, 0);  
  SetLength(FAuthorityCertSerial, 0);
  FreeAndNil(FAuthorityCertIssuer);
  FAuthorityCertIssuer := TElGeneralNames.Create;
end;

function TElAuthorityKeyIdentifierExtension.GetOID: ByteArray;
begin
  Result := SB_CERT_OID_AUTHORITY_KEY_IDENTIFIER;
end;

procedure TElAuthorityKeyIdentifierExtension.SetOID(const Value: ByteArray);
begin
end;

procedure TElAuthorityKeyIdentifierExtension.SetValue(const Value: ByteArray);
var
  Tag, SeqTag : TElASN1ConstrainedTag;
  CurrTagIndex : integer;
begin
  inherited;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if Tag.LoadFromBuffer(@Value[0], Length(Value)) then
    begin
      if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      begin
        SeqTag := TElASN1ConstrainedTag(Tag.GetField(0));
        CurrTagIndex := 0;
        if (CurrTagIndex < SeqTag.Count) and (SeqTag.GetField(CurrTagIndex).CheckType($80, false)) then
        begin
          FKeyIdentifier := TElASN1SimpleTag(SeqTag.GetField(CurrTagIndex)).Content;
          Inc(CurrTagIndex);
        end
        else if (CurrTagIndex < SeqTag.Count) and (SeqTag.GetField(CurrTagIndex).CheckType($A0, true)) then
        begin
          if (TElASN1ConstrainedTag(SeqTag.GetField(CurrTagIndex)).Count > 0) and
            TElASN1ConstrainedTag(SeqTag.GetField(CurrTagIndex)).GetField(0).CheckType(SB_ASN1_OCTETSTRING, false) then
            FKeyIdentifier := TElASN1SimpleTag(TElASN1ConstrainedTag(SeqTag.GetField(CurrTagIndex)).GetField(0)).Content;
          Inc(CurrTagIndex);
        end;
        if (CurrTagIndex < SeqTag.Count) and (SeqTag.GetField(CurrTagIndex).CheckType($A1, true)) then
        begin
          //ParseGeneralNames(TElASN1ConstrainedTag(SeqTag.GetField(CurrTagIndex)),
          //  FAuthorityCertIssuer, true, true);
          FAuthorityCertIssuer.LoadFromTag(TElASN1ConstrainedTag(SeqTag.GetField(CurrTagIndex)), true);
          Inc(CurrTagIndex);
        end;
        if (CurrTagIndex < SeqTag.Count) and (SeqTag.GetField(CurrTagIndex).CheckType($82, false)) then
        begin
          FAuthorityCertSerial := CloneArray(TElASN1SimpleTag(SeqTag.GetField(CurrTagIndex)).Content);
        end;
      end
      else
        RaiseInvalidExtensionError;
    end
    else
      RaiseInvalidExtensionError;
  finally
    FreeAndNil(Tag);
  end;
end;

function TElAuthorityKeyIdentifierExtension.GetValue: ByteArray;
var
  Lst: TElByteArrayList;
  Tmp: ByteArray;
  Size: integer;
  Tag: TElASN1ConstrainedTag;
begin
  if Length(FValue) > 0 then
    Result := CloneArray(FValue)
  else
  begin
    Lst := TElByteArrayList.Create;
    try
      Tmp := WriteOctetString(KeyIdentifier);
      Tmp[0] := byte($80);
      Lst.Add(Tmp);

      if AuthorityCertIssuer.Count > 0 then
      begin
        Tag := TElASN1ConstrainedTag.CreateInstance;
        try
          AuthorityCertIssuer.SaveToTag(Tag);
          Size := 0;
          Tag.SaveToBuffer( nil , Size);
          SetLength(Tmp, Size);
          Tag.SaveToBuffer( @Tmp[0] , Size);
          SetLength(Tmp, Size);
        finally
          FreeAndNil(Tag);
        end;

        Tmp[0] := byte($A1);
        Lst.Add(Tmp);
      end;

      Tmp := AuthorityCertSerial;
      if Length(Tmp) <> 0 then
        Lst.Add(WritePrimitive($82, Tmp));
      { Must Not be critical }
      Result := WriteListSequence(Lst);
    finally
      FreeAndNil(Lst);
    end;
  end;
end;

procedure TElAuthorityKeyIdentifierExtension.SetKeyIdentifier(const V: ByteArray);
begin
  FKeyIdentifier := CloneArray(V);
end;

procedure TElAuthorityKeyIdentifierExtension.SetAuthorityCertSerial(const V: ByteArray);
begin
  FAuthorityCertSerial := CloneArray(V);
end;

constructor TElDistributionPoint.Create;
begin
  inherited;
  FName := TElGeneralNames.Create;
  FCRLIssuer := TElGeneralNames.Create;
  FReasonFlags := [rfUnspecified, rfKeyCompromise, rfCACompromise,
    rfAffiliationChanged, rfSuperseded, rfCessationOfOperation,
      rfCertificateHold, rfRemoveFromCRL, rfPrivilegeWithdrawn, rfAACompromise];
  FIncluded := [dppName, dppCRLIssuer, dppReasonFlags];
end;

 destructor  TElDistributionPoint.Destroy;
begin
  FreeAndNil(FName);
  FreeAndNil(FCRLIssuer);
  inherited;
end;

function TElCRLDistributionPointsExtension. GetDistributionPoints (Index:
  integer): TElDistributionPoint;
begin
  Result := TElDistributionPoint(FPoints[Index]);
end;

function TElCRLDistributionPointsExtension.GetCount: integer;
begin
  Result := FPoints.Count;
end;

procedure TElCRLDistributionPointsExtension.SetCount(Value: integer);
var
  P: TElDistributionPoint;
begin
  if Value < FPoints.Count then
  begin
    while FPoints.Count > Value do
    begin
      P := TElDistributionPoint(FPoints[FPoints.Count - 1]);
      FPoints.Delete(FPoints.Count - 1);
      FreeAndNil(P);
    end;
  end
  else
    while FPoints.Count < Value do
      FPoints.Add(TElDistributionPoint.Create);
end;

procedure TElCRLDistributionPointsExtension.ClearList;
begin
  while FPoints.Count > 0 do
  begin
    TElDistributionPoint(FPoints[FPoints.Count - 1]). Free ;
    FPoints.Count := FPoints.Count - 1;
  end;
end;

procedure TElCRLDistributionPointsExtension.Remove(Index: integer);
begin
  TElDistributionPoint(FPoints[Index]). Free ;
  FPoints.Delete(Index);
end;

constructor TElCRLDistributionPointsExtension.Create;
begin
  inherited;
  FPoints := TElList.Create;
end;

 destructor  TElCRLDistributionPointsExtension.Destroy;
begin
  ClearList;
  FreeAndNil(FPoints);
  inherited;
end;

procedure TElCRLDistributionPointsExtension.Clear;
begin
  ClearList;
end;

function TElCRLDistributionPointsExtension.GetOID: ByteArray;
begin
  Result := SB_CERT_OID_CRL_DISTRIBUTION_POINTS;
end;

procedure TElCRLDistributionPointsExtension.SetOID(const Value: ByteArray);
begin
end;

procedure TElCRLDistributionPointsExtension.SetValue(const Value: ByteArray);
var
  Tag, DP : TElASN1ConstrainedTag;
  I : integer;
  CurrTagIndex : integer;
  Point : TElDistributionPoint;
  Reasons : TSBCRLReasonFlags;
  S : ByteArray;
  B : Word;
begin
  inherited;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if Tag.LoadFromBuffer(@Value[0], Length(Value)) then
    begin
      if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      begin
        for I := 0 to TElASN1ConstrainedTag(Tag.GetField(0)).Count - 1 do
        begin
          Point := TElDistributionPoint.Create;
          if TElASN1ConstrainedTag(Tag.GetField(0)).GetField(I).CheckType(SB_ASN1_SEQUENCE, true) then
          begin
            DP := TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(I));
            CurrTagIndex := 0;
            if (CurrTagIndex < DP.Count) and (DP.GetField(CurrTagIndex).CheckType(SB_ASN1_A0, true)) then
            begin
              if (TElASN1ConstrainedTag(DP.GetField(CurrTagIndex)).Count = 1) and
                (TElASN1ConstrainedTag(DP.GetField(CurrTagIndex)).GetField(0).CheckType(SB_ASN1_A0, true)) then
              begin
                //ParseGeneralNames(TElASN1ConstrainedTag(TElASN1ConstrainedTag(DP.GetField(CurrTagIndex)).GetField(0)),
                //  Point.FName, true);
                Point.FName.LoadFromTag(TElASN1ConstrainedTag(TElASN1ConstrainedTag(DP.GetField(CurrTagIndex)).GetField(0)), false);
              end
              else if (TElASN1ConstrainedTag(DP.GetField(CurrTagIndex)).Count = 1) and
                (TElASN1ConstrainedTag(DP.GetField(CurrTagIndex)).GetField(0).CheckType(SB_ASN1_A1, true)) then
              begin
                Point.FName.Add;
                Point.FName.Names[0].FNameType := gnDirectoryName;
                Point.FName.Names[0].DirectoryName.LoadFromTag(TElASN1ConstrainedTag(TElASN1ConstrainedTag(DP.GetField(CurrTagIndex)).GetField(0)){$ifndef HAS_DEF_PARAMS}, false {$endif});
              end;
              Inc(CurrTagIndex);
            end;
            if (CurrTagIndex < DP.Count) and (DP.GetField(CurrTagIndex).CheckType($81, false)) then
            begin
              S := TElASN1SimpleTag(DP.GetField(CurrTagIndex)).Content;
              if Length(S) > 2 then
                B := PByte(@S[0 + 1])^ or (PByte(@S[0 + 2])^ shl 8)
              else if Length(S) = 2 then
                B := PByte(@S[0 + 1])^
              else
                B := 0;
              Reasons :=  [] ;
              if (B and $8000) = $8000 then
                Reasons := Reasons  + [rfAACompromise] ;
              if (B and $80) = $80 then
                Reasons := Reasons  + [rfPrivilegeWithdrawn] ;
              (*if (B and $100) = $100 then
                Reasons := Reasons {$ifdef SB_VCL}+ [rfRemoveFromCRL]{$else}or rfRemoveFromCRL{$endif};
              if (B and $80) = $80 then
                Reasons := Reasons {$ifdef SB_VCL}+ [rfObsolete1]{$else}or rfObsolete1{$endif};*)
              if (B and $40) = $40 then
                Reasons := Reasons  + [rfKeyCompromise] ;
              if (B and $20) = $20 then
                Reasons := Reasons  + [rfCACompromise] ;
              if (B and $10) = $10 then
                Reasons := Reasons  + [rfAffiliationChanged] ;
              if (B and $08) = $08 then
                Reasons := Reasons  + [rfSuperseded] ;
              if (B and $04) = $04 then
                Reasons := Reasons  + [rfCessationOfOperation] ;
              if (B and $02) = $02 then
                Reasons := Reasons  + [rfCertificateHold] ;
              Point.FReasonFlags := Reasons;

              Inc(CurrTagIndex);
            end;
            if (CurrTagIndex < DP.Count) and (DP.GetField(CurrTagIndex).CheckType(SB_ASN1_A2, true)) then
            begin
              //ParseGeneralNames(TElASN1ConstrainedTag(DP.GetField(CurrTagIndex)),
              //  Point.FCRLIssuer, true);
              Point.FCRLIssuer.LoadFromTag(TElASN1ConstrainedTag(DP.GetField(CurrTagIndex)){$ifndef HAS_DEF_PARAMS}, false {$endif});
            end;
            FPoints.Add(Point);
          end;
        end;
      end
      else
        RaiseInvalidExtensionError;
    end
    else
      RaiseInvalidExtensionError;
  finally
    FreeAndNil(Tag);
  end;
end;

constructor TElAccessDescription.Create;
begin
  inherited;
  FGeneralName := TElGeneralName.Create;
end;

 destructor  TElAccessDescription.Destroy;
begin
  FreeAndNil(FGeneralName);
  inherited;
end;

procedure TElAccessDescription.SetAccessMethod(const V : ByteArray);
begin
  FAccessMethod := CloneArray(V);
end;

function TElAuthorityInformationAccessExtension. GetAccessDescriptions (Index:
  integer): TElAccessDescription;
begin
  Result := TElAccessDescription(FList[Index]);
end;

function TElAuthorityInformationAccessExtension.GetCount: integer;
begin
  Result := FList.Count;
end;

procedure TElAuthorityInformationAccessExtension.SetCount(Value: integer);
var
  P: TElAccessDescription;
begin
  if Value < FList.Count then
  begin
    while FList.Count > Value do
    begin
      P := TElAccessDescription(FList[FList.Count - 1]);
      FList.Delete(FList.Count - 1);
      FreeAndNil(P);
    end;
  end
  else
    while FList.Count < Value do
      FList.Add(TElAccessDescription.Create);
end;

procedure TElAuthorityInformationAccessExtension.ClearList;
var
  P: TElAccessDescription;
begin
  while FList.Count > 0 do
  begin
    P := TElAccessDescription(FList[0]);
    FList.Delete(0);
    FreeAndNil(P);
  end;
end;

procedure TElAuthorityInformationAccessExtension.Remove(Index: integer);
var
  P: TElAccessDescription;
begin
  P := TElAccessDescription(FList[Index]);
  FList.Delete(Index);
  FreeAndNil(P);
end;

constructor TElAuthorityInformationAccessExtension.Create;
begin
  inherited;
  FList := TElList.Create;
end;

 destructor  TElAuthorityInformationAccessExtension.Destroy;
begin
  ClearList;
  FreeAndNil(FList);
  inherited;
end;

procedure TElAuthorityInformationAccessExtension.Clear;
begin
  ClearList;
end;

function TElAuthorityInformationAccessExtension.GetOID: ByteArray;
begin
  Result := SB_CERT_OID_AUTHORITY_INFORMATION_ACCESS;
end;

procedure TElAuthorityInformationAccessExtension.SetOID(const Value:
  ByteArray);
begin
end;

procedure TElAuthorityInformationAccessExtension.SetValue(const Value:
  ByteArray);
var
  Tag : TElASN1ConstrainedTag;
  I : integer;
  AD : TElAccessDescription;
begin
  inherited;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if Tag.LoadFromBuffer(@Value[0], Length(Value)) then
    begin
      if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      begin
        for I := 0 to TElASN1ConstrainedTag(Tag.GetField(0)).Count - 1 do
        begin
          if (TElASN1ConstrainedTag(Tag.GetField(0)).GetField(I).CheckType(SB_ASN1_SEQUENCE, true)) then
          begin
            if (TElASN1ConstrainedTag((TElASN1ConstrainedTag(Tag.GetField(0)).GetField(I))).Count = 2) and
              (TElASN1ConstrainedTag((TElASN1ConstrainedTag(Tag.GetField(0)).GetField(I))).GetField(0).CheckType(SB_ASN1_OBJECT, false)) then
            begin
              AD := TElAccessDescription.Create;
              AD.FAccessMethod := TElASN1SimpleTag(TElASN1ConstrainedTag((TElASN1ConstrainedTag(Tag.GetField(0)).GetField(I))).GetField(0)).Content;
              //ParseGeneralName(TElASN1ConstrainedTag((TElASN1ConstrainedTag(Tag.GetField(0)).GetField(I))).GetField(1),
              //  AD.FGeneralName);
              AD.FGeneralName.LoadFromTag(TElASN1ConstrainedTag((TElASN1ConstrainedTag(Tag.GetField(0)).GetField(I))).GetField(1));
              FList.Add(AD);
            end;
          end
          else
            RaiseInvalidExtensionError;
        end;
      end
      else
        RaiseInvalidExtensionError;
    end
    else
      RaiseInvalidExtensionError;
  finally
    FreeAndNil(Tag);
  end;
end;

procedure TElSubjectKeyIdentifierExtension.Clear;
begin
  SetLength(FKeyIdentifier, 0);
end;

function TElSubjectKeyIdentifierExtension.GetOID: ByteArray;
begin
  Result := SB_CERT_OID_SUBJECT_KEY_IDENTIFIER;
end;

procedure TElSubjectKeyIdentifierExtension.SetOID(const Value: ByteArray);
begin
end;

procedure TElSubjectKeyIdentifierExtension.SetValue(const Value: ByteArray);
var
  Tag : TElASN1ConstrainedTag;
begin
  inherited;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if Tag.LoadFromBuffer(@Value[0], Length(Value)) then
    begin
      if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_OCTETSTRING, false)) then
        FKeyIdentifier := TElASN1SimpleTag(Tag.GetField(0)).Content
      else
        RaiseInvalidExtensionError;
    end
    else
      RaiseInvalidExtensionError;
  finally
    FreeAndNil(Tag);
  end;
end;

procedure TElSubjectKeyIdentifierExtension.SetKeyIdentifier(const V : ByteArray);
begin
  FKeyIdentifier := CloneArray(V);
end;

procedure TElKeyUsageExtension.Clear;
begin
  FDigitalSignature := false;
  FNonRepudiation := false;
  FKeyEncipherment := false;
  FDataEncipherment := false;
  FKeyAgreement := false;
  FKeyCertSign := false;
  FCRLSign := false;
  FEncipherOnly := false;
  FDecipherOnly := false;
end;

function TElKeyUsageExtension.GetOID: ByteArray;
begin
  Result := SB_CERT_OID_KEY_USAGE;
end;

procedure TElKeyUsageExtension.SetOID(const Value: ByteArray);
begin
end;

procedure TElKeyUsageExtension.SetValue(const Value: ByteArray);
var
  Tag : TElASN1ConstrainedTag;
  Size : integer;
  Tmp : ByteArray;
begin
  inherited;
  SetLength(Tmp, 0);
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if Tag.LoadFromBuffer(@Value[0], Length(Value)) then
    begin
      if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_BITSTRING, false)) then
      begin
        Tmp := TElASN1SimpleTag(Tag.GetField(0)).Content;
        Size := Length(Tmp);
        if Size >= 2 then
        begin
          FDigitalSignature := (Tmp[1] and $80) = $80;
          FNonRepudiation := (Tmp[1] and $40) = $40;
          FKeyEncipherment := (Tmp[1] and $20) = $20;
          FDataEncipherment := (Tmp[1] and $10) = $10;
          FKeyAgreement := (Tmp[1] and $08) = $08;
          FKeyCertSign := (Tmp[1] and $04) = $04;
          FCRLSign := (Tmp[1] and $02) = $02;
          FEncipherOnly := (Tmp[1] and $01) = $01;
        end;
        if Size >= 3 then
        begin
          FDecipherOnly := (Tmp[2] and $80) = $80;
        end;
      end
      else
        RaiseInvalidExtensionError;
    end
    else
      RaiseInvalidExtensionError;
  finally
    FreeAndNil(Tag);
  end;
end;

procedure TElPrivateKeyUsagePeriodExtension.Clear;
begin
  FNotBefore := 0;
  FNotAfter := 0;
end;

function TElPrivateKeyUsagePeriodExtension.GetOID: ByteArray;
begin
  Result := SB_CERT_OID_PRIVATE_KEY_USAGE_PERIOD;
end;

procedure TElPrivateKeyUsagePeriodExtension.SetOID(const Value: ByteArray);
begin
end;

procedure TElPrivateKeyUsagePeriodExtension.SetValue(const Value: ByteArray);
var
  Tag, SeqTag : TElASN1ConstrainedTag;
  CurrIndex : integer;
begin
  inherited;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if Tag.LoadFromBuffer(@Value[0], Length(Value)) then
    begin
      if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      begin
        SeqTag := TElASN1ConstrainedTag(Tag.GetField(0));
        CurrIndex := 0;
        if (CurrIndex < SeqTag.Count) and (SeqTag.GetField(CurrIndex).CheckType($80, false)) then
        begin
          FNotBefore := GeneralizedTimeToDateTime(StringOfBytes(TElASN1SimpleTag(SeqTag.GetField(CurrIndex)).Content));
          Inc(CurrIndex);
        end;
        if (CurrIndex < SeqTag.Count) and (SeqTag.GetField(CurrIndex).CheckType($81, false)) then
          FNotAfter := GeneralizedTimeToDateTime(StringOfBytes(TElASN1SimpleTag(SeqTag.GetField(CurrIndex)).Content));
      end
      else
        RaiseInvalidExtensionError;
    end
    else
      RaiseInvalidExtensionError;
  finally
    FreeAndNil(Tag);
  end;
end;

procedure TElBasicConstraintsExtension.Clear;
begin
  FCA := false;
  FPathLenConstraint := 0;
end;

function TElBasicConstraintsExtension.GetOID: ByteArray;
begin
  Result := SB_CERT_OID_BASIC_CONSTRAINTS;
end;

procedure TElBasicConstraintsExtension.SetOID(const Value: ByteArray);
begin
end;

procedure TElBasicConstraintsExtension.SetValue(const Value: ByteArray);
var
  Tag : TElASN1ConstrainedTag;
  CurrTagIndex : integer;
  Cnt : ByteArray;
  I, K : integer;
begin
  inherited;
  FCA := false;
  FPathLenConstraint := 0;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if Tag.LoadFromBuffer(@Value[0], Length(Value)) then
    begin
      if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      begin
        CurrTagIndex := 0;
        if (TElASN1ConstrainedTag(Tag.GetField(0)).Count > CurrTagIndex) and
          (TElASN1ConstrainedTag(Tag.GetField(0)).GetField(CurrTagIndex).CheckType(SB_ASN1_BOOLEAN, false)) then
        begin
          Cnt := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(CurrTagIndex)).Content;
          FCA := (Length(Cnt) > 0) and (Cnt[0] = byte($FF));
          Inc(CurrTagIndex);
        end
        else
          FCA := false;
        if (TElASN1ConstrainedTag(Tag.GetField(0)).Count > CurrTagIndex) and
          (TElASN1ConstrainedTag(Tag.GetField(0)).GetField(CurrTagIndex).CheckType(SB_ASN1_INTEGER, false)) then
        begin
          Cnt := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(CurrTagIndex)).Content;
          FPathLenConstraint := 0;
          I := Length(Cnt);
          K := 0;
          while (I > 0) and (K < 4) do
          begin
            FPathLenConstraint := FPathLenConstraint or (PByte(@Cnt[I - 1 + 0])^ shl (K shl 3));
            Dec(I);
            Inc(K);
          end;
        end
        else
          FPathLenConstraint := -1;
      end
      else
        RaiseInvalidExtensionError;
    end
    else
      RaiseInvalidExtensionError;
  finally
    FreeAndNil(Tag);
  end;
end;

procedure TElPolicyConstraintsExtension.Clear;
begin
  FRequireExplicitPolicy := 0;
  FInhibitPolicyMapping := 0;
end;

function TElPolicyConstraintsExtension.GetOID: ByteArray;
begin
  Result := SB_CERT_OID_POLICY_CONSTRAINTS;
end;

procedure TElPolicyConstraintsExtension.SetOID(const Value: ByteArray);
begin
end;

procedure TElPolicyConstraintsExtension.SetValue(const Value: ByteArray);
var
  Tag, SeqTag : TElASN1ConstrainedTag;
  CurrIndex : integer;
begin
  inherited;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if Tag.LoadFromBuffer(@Value[0], Length(Value)) then
    begin
      if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      begin
        SeqTag := TElASN1ConstrainedTag(Tag.GetField(0));
        CurrIndex := 0;
        if (CurrIndex < SeqTag.Count) and (SeqTag.GetField(CurrIndex).CheckType($80, false)) then
        begin
          FRequireExplicitPolicy := ASN1ReadInteger(TElASN1SimpleTag(SeqTag.GetField(CurrIndex)));
          Inc(CurrIndex);
        end;
        if (CurrIndex < SeqTag.Count) and (SeqTag.GetField(CurrIndex).CheckType($81, false)) then
          FInhibitPolicyMapping := ASN1ReadInteger(TElASN1SimpleTag(SeqTag.GetField(CurrIndex)));
      end
      else
        RaiseInvalidExtensionError;
    end
    else
      RaiseInvalidExtensionError;
  finally
    FreeAndNil(Tag);
  end;  
end;

constructor TElExtendedKeyUsageExtension.Create;
begin
  inherited;
  FCustomUsages := TElByteArrayList.Create;
end;

 destructor  TElExtendedKeyUsageExtension.Destroy;
begin
  FreeAndNil(FCustomUsages);
  inherited;
end;

procedure TElExtendedKeyUsageExtension.Clear;
begin
  FServerAuthentication := false;
  FClientAuthentication := false;
  FCodeSigning := false;
  FEmailProtection := false;
  FTimeStamping := false;
  FOCSPSigning := false;
  ClearCustomUsages;
end;

function TElExtendedKeyUsageExtension.GetOID: ByteArray;
begin
  Result := SB_CERT_OID_EXTENDED_KEY_USAGE;
end;

procedure TElExtendedKeyUsageExtension.SetOID(const Value: ByteArray);
begin
end;

procedure TElExtendedKeyUsageExtension.SetValue(const Value: ByteArray);
var
  Tag : TElASN1ConstrainedTag;
  I : integer;
  OID : ByteArray;
begin
  inherited;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if (Tag.LoadFromBuffer(@Value[0], Length(Value))) then
    begin
      if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      begin
        for I := 0 to TElASN1ConstrainedTag(Tag.GetField(0)).Count - 1 do
        begin
          if TElASN1ConstrainedTag(Tag.GetField(0)).GetField(I).CheckType(SB_ASN1_OBJECT, false) then
          begin
            OID := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(I)).Content;
            if CompareContent(OID, SB_OID_SERVER_AUTH) then
              FServerAuthentication := true
            else if CompareContent(OID, SB_OID_CLIENT_AUTH) then
              FClientAuthentication := true
            else if CompareContent(OID, SB_OID_CODE_SIGNING) then
              FCodeSigning := true
            else if CompareContent(OID, SB_OID_EMAIL_PROT) then
              FEmailProtection := true
            else if CompareContent(OID, SB_OID_TIME_STAMPING) then
              FTimestamping := true
            else if CompareContent(OID, SB_OID_OCSP_SIGNING) then
              FOCSPSigning := true
            else
              FCustomUsages.Add(OID);
          end
          else
            RaiseInvalidExtensionError;
        end;
      end
      else
        RaiseInvalidExtensionError;
    end
    else
      RaiseInvalidExtensionError;
  finally
    FreeAndNil(Tag);
  end;
end;

function TElExtendedKeyUsageExtension.AddCustomUsage(const UsageOID : ByteArray): integer;
begin
  Result := FCustomUsages.Add(UsageOID);
end;

procedure TElExtendedKeyUsageExtension.RemoveCustomUsage(Index: integer);
begin
  if (Index >= 0) and (Index < FCustomUsages.Count) then
    FCustomUsages.Delete(Index)
  else
    raise EElCertificateError.Create('List index out of bounds');
end;

procedure TElExtendedKeyUsageExtension.ClearCustomUsages;
begin
  FCustomUsages.Clear;
end;

function TElExtendedKeyUsageExtension.GetCustomUsage(Index: integer) : ByteArray;
begin
  if (Index >= 0) and (Index < FCustomUsages.Count) then
    Result := CloneArray(FCustomUsages.Item[Index])
  else
    raise EElCertificateError.Create('List index out of bounds');
end;

procedure TElExtendedKeyUsageExtension.SetCustomUsage(Index: integer; const Value: ByteArray);
begin
  if (Index >= 0) and (Index < FCustomUsages.Count) then
    FCustomUsages.Item[Index] := CloneArray(Value)
  else
    raise EElCertificateError.Create('List index out of bounds');
end;

function TElExtendedKeyUsageExtension.GetTotalUsageCount : integer;
const KUValues : array[boolean] of integer =  ( 0, 1 ) ;
begin
  result := GetCustomUsageCount +
    KUValues[ServerAuthentication] +
    KUValues[ClientAuthentication] +
    KUValues[CodeSigning] +
    KUValues[EmailProtection] +
    KUValues[TimeStamping] +
    KUValues[OCSPSigning];
end;

function TElExtendedKeyUsageExtension.GetCustomUsageCount: integer;
begin
  Result := FCustomUsages.Count;
end;

////////////////////////////////////////////////////////////////////////////////
// TElGeneralNames class

constructor TElGeneralNames.Create;
begin
  inherited;
  FNames :=  TElList.Create ;
end;

 destructor  TElGeneralNames.Destroy;
begin
  Clear;
  FreeAndNil(FNames);
  inherited;
end;

function TElGeneralNames.GetCount : integer;
begin
  Result := FNames.Count;
end;

function TElGeneralNames. GetNames (Index: integer): TElGeneralName;
begin
  Result := TElGeneralName(FNames[Index]);
end;

function TElGeneralNames.Add : integer;
begin
  Result := FNames.Add(TElGeneralName.Create);
end;

procedure TElGeneralNames.Remove(Index: integer);
begin
  if (Index < 0) or (Index >= FNames.Count) then
    raise EElCertificateError.Create('List index out of bounds');
  TElGeneralName(FNames[Index]). Free ;
   FNames.Delete(Index) ;
end;

function TElGeneralNames.Contains(Other : TElGeneralNames) : boolean;
var i, j : integer;
    OthersName : TElGeneralName;
    ir : boolean;
begin
  result := true;
  for i := 0 to Other.Count - 1 do
  begin
    OthersName := Other.Names[i];
    ir := false;
    for j := 0 to Self.Count - 1 do
    begin
      if OthersName.Equals(Self.Names[j]) then
      begin
        result := true;
        exit;
      end;
    end;
    if not ir then
    begin
      result := false;
      exit;
    end;
  end;
end;

function TElGeneralNames.HasCommon(Other : TElGeneralNames) : boolean;
var i, j : integer;
    Name : TElGeneralName;
begin
  result := false;
  for i := 0 to Count - 1 do
  begin
    Name := Names[i];
    for j := 0 to Other.Count - 1 do
    begin
      if Name.Equals(Other.Names[j]) then
      begin
        result := true;
        exit;
      end;
    end;
  end;
end;

function TElGeneralNames.Equals(Other : TElGeneralNames) : boolean;
begin
  result := (Self.Count = Other.Count) and Self.Contains(Other) and Other.Contains(Self);
end;

procedure TElGeneralNames.Clear;
var
  I : integer;
begin
  for I := 0 to FNames.Count - 1 do
    TElGeneralName(FNames[I]). Free ;
  FNames.Clear;
end;

function TElGeneralNames.LoadFromTag(Tag: TElASN1ConstrainedTag; 
    AllowRDN: boolean {$ifdef HAS_DEF_PARAMS} =  false {$endif}): boolean;
var
  I, Index : integer;
begin
  Clear;
  Result := true;
  for I := 0 to Tag.Count - 1 do
  begin
    Index := Add;
    if not Names[Index].LoadFromTag(Tag.GetField(I)) then
    begin
      if (AllowRDN) and (Tag.GetField(I).CheckType(SB_ASN1_SEQUENCE, true)) then
      begin
        Names[Index].DirectoryName.LoadFromTag(TElASN1ConstrainedTag(Tag.GetField(I)), false);
        Names[Index].NameType := gnDirectoryName;
      end
      else
      begin
        Remove(Index);
        Result := false;
      end;
    end;
  end;
end;

function TElGeneralNames.SaveToTag(Tag: TElASN1ConstrainedTag): boolean;
var
  I : integer;
  STag : TElASN1SimpleTag;
  Index: integer;
begin
  for I := 0 to Count - 1 do
  begin
    Index := Tag.AddField(false);
    STag := TElASN1SimpleTag(Tag.GetField(Index));
    if not Names[I].SaveToTag(STag) then
      Tag.RemoveField(Index);
  end;
  Tag.TagId := SB_ASN1_SEQUENCE;
  Result := true;
end;

function TElGeneralNames.FindNameByType(NameType : TSBGeneralName;
  StartIndex: integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}) : integer;
var
  I : integer;
begin
  I := StartIndex;
  while (I < Count) and (Names[I].NameType <> NameType) do
    Inc(I);
  if I < Count then
    Result := I
  else
    Result := -1;
end;

function TElGeneralNames.ContainsEmailAddress(const Addr: string): boolean;
var
  CurrIndex : integer;
begin
  CurrIndex := -1;
  Result := false;
  repeat
    CurrIndex := FindNameByType(gnRFC822Name, CurrIndex + 1);
    if (CurrIndex >= 0) and 
      (CompareStr(lowercase(Names[CurrIndex].RFC822Name), lowercase(Addr)) = 0)
        then
    begin
      Result := true;
      Break;
    end;
  until CurrIndex < 0;
end;

procedure TElGeneralNames.Assign(Source:  TPersistent );
var
  I : integer;
begin
  if not (Source is TElGeneralNames) then
    raise EElCertificateError.Create(SInvalidTypeCast);
  Clear;
  for I := 0 to TElGeneralNames(Source).Count - 1 do
  begin
    Add;
    Names[I].Assign(TElGeneralNames(Source).Names[I]);
  end;
end;

procedure TElGeneralNames.AssignTo(Dest:  TPersistent );
begin
  if not (Dest is TElGeneralNames) then
    raise EElCertificateError.Create(SInvalidTypeCast);
  Dest.Assign(Self);
end;

////////////////////////////////////////////////////////////////////////////////
// TElNetscapeCertTypeExtension class

procedure TElNetscapeCertTypeExtension.SetValue(const Value: ByteArray);
var
  LVal : Byte;
  Tag : TElASN1ConstrainedTag;
const
  ASN_BIT_0 = $80;
  ASN_BIT_1 = $40;
  ASN_BIT_2 = $20;
  ASN_BIT_3 = $10;
  ASN_BIT_4 = $08;
  ASN_BIT_5 = $04;
  ASN_BIT_6 = $02;
  ASN_BIT_7 = $01;
begin
  inherited;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if Tag.LoadFromBuffer(@Value[0], Length(Value)) then
    begin
      if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_BITSTRING, false)) then
      begin
        if Length(TElASN1SimpleTag(Tag.GetField(0)).Content) > 1 then
          LVal := PByte(@TElASN1SimpleTag(Tag.GetField(0)).Content[1 + 0])^
        else
          LVal := 0;

        if LVal and ASN_BIT_0 = ASN_BIT_0 then
        begin
          CertType := CertType + [nsSSLClient];
        end;
        if LVal and ASN_BIT_1 = ASN_BIT_1 then
        begin
          CertType := CertType + [nsSSLServer];
        end;
        if LVal and ASN_BIT_2 = ASN_BIT_2 then
        begin
          CertType := CertType + [nsSMIME];
        end;
        if LVal and ASN_BIT_3 = ASN_BIT_3 then
        begin
          CertType := CertType + [nsObjectSign];
        end;
        if LVal and ASN_BIT_5 = ASN_BIT_5 then
        begin
          CertType := CertType + [nsSSLCA];
        end;
        if LVal and ASN_BIT_6 = ASN_BIT_6 then
        begin
          CertType := CertType + [nsSMIMECA];
        end;
        if LVal and ASN_BIT_7 = ASN_BIT_7 then
        begin
          CertType := CertType + [nsObjectSignCA];
        end;
      end
      else
        RaiseInvalidExtensionError;
    end
    else
      RaiseInvalidExtensionError;
  finally
    FreeAndNil(Tag);
  end;              
end;

procedure TElNetscapeCertTypeExtension.Clear;
begin
  inherited;
  FCertType :=  [] ;
end;

////////////////////////////////////////////////////////////////////////////////
// TElNetscapeString class

procedure TElNetscapeString.SetValue(const Value: ByteArray);
var
  Tag : TElASN1ConstrainedTag;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if Tag.LoadFromBuffer(@Value[0], Length(Value)) then
    begin
      if (Tag.Count = 1) and (not Tag.GetField(0).IsConstrained) and
        (Tag.GetField(0).TagId in [SB_ASN1_IA5STRING, SB_ASN1_VISIBLESTRING,
          SB_ASN1_PRINTABLESTRING]) then
      begin
        FContent := ASN1ReadString(TElASN1SimpleTag(Tag.GetField(0)).Content, Tag.GetField(0).TagId);
        // Replaced with the call to ASN1ReadString by EM, 13/12/2013
        // FContent := {$ifndef SB_VCL}StringOfBytes{$else}{$ifdef SB_UNICODE_VCL}StringOfBytes{$endif}{$endif}(TElASN1SimpleTag(Tag.GetField(0)).Content);
      end;
    end
    else
      RaiseInvalidExtensionError;
  finally
    FreeAndNil(Tag);
  end;
end;

procedure TElNetscapeString.Clear;
begin
  inherited;
  SetLength(FContent, 0);
end;

function TElNetscapeString.GetOID : ByteArray;
begin
  if Self is TElNetscapeBaseURL then
    Result := SB_CERT_OID_NETSCAPE_BASE_URL
  else if Self is TElNetscapeRevokeURL then
    Result := SB_CERT_OID_NETSCAPE_REVOKE_URL
  else if Self is TElNetscapeCARevokeURL then
    Result := SB_CERT_OID_NETSCAPE_CA_REVOKE_URL
  else if Self is TElNetscapeRenewalURL then
    Result := SB_CERT_OID_NETSCAPE_RENEWAL_URL
  else if Self is TElNetscapeCAPolicy then
    Result := SB_CERT_OID_NETSCAPE_CA_POLICY
  else if Self is TElNetscapeServerName then
    Result := SB_CERT_OID_NETSCAPE_SERVER_NAME
  else if Self is TElNetscapeComment then
    Result := SB_CERT_OID_NETSCAPE_COMMENT
  else if Self is TElCommonName then
    Result := SB_CERT_OID_COMMON_NAME
  else
    Result := EmptyArray;
end;

////////////////////////////////////////////////////////////////////////////////
// Miscellaneous routines

function OctetsToIPAddress(const Octets : ByteArray) : string;
var
  I: Integer;
begin
  Result := EmptyString;
  if Length(Octets) = 4 then
  begin
    // IPv4 address
    for I := 0 to 4 - 1 do
    begin
      if I > 0 then
        Result := Result + '.';
      Result := Result + IntToStr(PByte(@Octets[I])^);
    end;
  end
  else
  if Length(Octets) = 16 then
  begin
    // IPv6 address
    for I := 0 to 16 - 1 do
    begin
      if (I > 0) and (((I - 0) and $1) = 0) then
        Result := Result + ':';
      Result := Result + StringToLower(IntToHex(PByte(@Octets[I])^, 2));
    end;
  end;
end;

function TryStrToIPv4Elem(const S: string; out Element: byte): Boolean;
var
  I: Integer;
begin
  Result := TryStrToInt(S, I) and (I >= 0) and (I <= 255);
  if Result then
    Element := byte(I);
end;

function TryStrToIPv6Elem(const S: string; out Elem: Integer): Boolean;
var
  I: Integer;
begin
  Result := TryStrToInt('$' + S, I);

  if Result and (I >= 0) and (I <= 65535) then
    Elem := I
  else
    Result := False;
end;

function IPAddressToOctets(const IPAddrStr : string) : ByteArray;
var
  I, J, N, E, RI, RJ: Integer;
  Parts: StringArray;
  EmptyFound: Boolean;
  Buffer: ByteArray;
begin
  Result := EmptyArray;

  I := StringIndexOf(IPAddrStr, ':');
  if I < StringStartOffset then
  begin
    // seems to be a IPv4 address
    Parts := StringSplit(IPAddrStr, '.', True);
    if Length(Parts) <> 4 then
      Exit;
    SetLength(Buffer, 4);
    if TryStrToIPv4Elem(Parts[0], Buffer[0]) and
      TryStrToIPv4Elem(Parts[1], Buffer[0 + 1]) and
      TryStrToIPv4Elem(Parts[2], Buffer[0 + 2]) and
      TryStrToIPv4Elem(Parts[3], Buffer[0 + 3]) then
      Result := Buffer
    else
      ReleaseArray(Buffer);
  end
  else
  begin
    // seems to be a IPv6 address
    Parts := StringSplit(IPAddrStr, ':', False);
    N := Length(Parts);
    if (N < 3) or (N > 8) then
      Exit;

    SetLength(Buffer, 16);
    FillChar(Buffer[0], Length(Buffer), 0);

    I := 0;                     // for input array
    J := 0; // for output array
    EmptyFound := False;

    while I < N do
    begin
      EmptyFound := StringIsEmpty(Parts[I]);
      if EmptyFound then
        Break;
      if not TryStrToIPv6Elem(Parts[I], E) then
      begin
        ReleaseArray(Buffer);
        Exit;
      end;
      Inc(I);
      Buffer[J] := byte(E shr 8);
      Inc(J);
      Buffer[J] := byte(E and $FF);
      Inc(J);
    end;

    if not EmptyFound then
    begin
      Result := Buffer;
      Exit;
    end;

    RI := N - 1;                          // for input array
    RJ := 16 - 1;  // for output array
    while RI > I do
    begin
      if StringIsEmpty(Parts[RI]) then
        if (RI = 1) or (RI = N - 1) then  // :: at the beginning or at the end (e.g. ::1 or fc00::)
          Break;
      if not TryStrToIPv6Elem(Parts[RI], E) then
      begin
        ReleaseArray(Buffer);
        Exit;
      end;
      Dec(RI);
      Buffer[RJ] := byte(E and $FF);
      Dec(RJ);
      Buffer[RJ] := byte(E shr 8);
      Dec(RJ);
    end;

    Result := Buffer;
  end;
end;



procedure TElOtherName.SetOID(const V: ByteArray);
begin
  FOID := CloneArray(V);
end;

procedure TElOtherName.SetValue(const V: ByteArray);
begin
  FValue := CloneArray(V);
end;


procedure TElPermanentIdentifier.SetPermanentIdentifier(const V : ByteArray);
begin
  FPermanentIdentifier := CloneArray(V);
end;

procedure TElPermanentIdentifier.SetAssigner(const V : ByteArray);
begin
  FAssigner := CloneArray(V);
end;



 destructor  TElPolicyMapping.Destroy;
begin
  ReleaseArrays(FIssuerDomainPolicy, FSubjectDomainPolicy);
  inherited;
end;

procedure TElPolicyMapping.SetIssuerDomainPolicy(const V: ByteArray);
begin
  FIssuerDomainPolicy := CloneArray(V);
end;

procedure TElPolicyMapping.SetSubjectDomainPolicy(const V: ByteArray);
begin
  FSubjectDomainPolicy := CloneArray(V);
end;


////////////////////////////////////////////////////////////////////////////////
// TElSubjectDirectoryAttributesExtension class

constructor TElSubjectDirectoryAttributesExtension.Create;
begin
  inherited;
  FAttributes := TElPKCS7Attributes.Create;
end;

 destructor  TElSubjectDirectoryAttributesExtension.Destroy;
begin
  FreeAndNil(FAttributes);
  inherited;
end;

procedure TElSubjectDirectoryAttributesExtension.Clear;
begin
  inherited;
  FAttributes.Count := 0;
end;

function TElSubjectDirectoryAttributesExtension.GetOID: ByteArray;
begin
  Result := SB_CERT_OID_SUBJECT_DIRECTORY_ATTRIBUTES;
end;

procedure TElSubjectDirectoryAttributesExtension.SetOID(const Value: ByteArray);
begin
  ;
end;

procedure TElSubjectDirectoryAttributesExtension.SetValue(const Value: ByteArray);
var
  Tag, CTag, AttrTag, ValTag : TElASN1ConstrainedTag;
  I, J : integer;
  Size : integer;
  Buf : ByteArray;
begin
  inherited;
  FAttributes.Count := 0;
  Tag := TElASN1ConstrainedTag.CreateInstance();
  try
    if Tag.LoadFromBuffer(@Value[0], Length(Value)) then
    begin
      if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      begin
        CTag := TElASN1ConstrainedTag(Tag.GetField(0));
        for I := 0 to CTag.Count - 1 do
        begin
          if CTag.GetField(I).CheckType(SB_ASN1_SEQUENCE, true) then
          begin
            AttrTag := TElASN1ConstrainedTag(CTag.GetField(I));
            if (AttrTag.Count = 2) and (AttrTag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) and
              (AttrTag.GetField(1).CheckType(SB_ASN1_SET, true)) then
            begin
              FAttributes.Count := FAttributes.Count + 1;
              FAttributes.Attributes[FAttributes.Count - 1] := TElASN1SimpleTag(AttrTag.GetField(0)).Content;
              ValTag := TElASN1ConstrainedTag(AttrTag.GetField(1));
              for J := 0 to ValTag.Count - 1 do
              begin
                Size := 0;
                ValTag.GetField(J).SaveToBuffer( nil , Size);
                SetLength(Buf, Size);
                ValTag.GetField(J).SaveToBuffer( @Buf[0] , Size);
                SetLength(Buf, Size);
                FAttributes.Values[I].Add(Buf);
              end;
            end;
          end;
        end;
      end;
    end;
  finally
    FreeAndNil(Tag);
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// TElExtensionWriter class

constructor TElExtensionWriter.Create(Exts : TElCertificateExtensions;
  CertExtensions: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif});
begin
  inherited Create;
  FCertificateExtensions := Exts;
  FUseA3Prefix := CertExtensions;
end;

function TElExtensionWriter.WriteExtensions: ByteArray;
var
  Lst: TElByteArrayList;
  I: integer;
begin
  Lst := TElByteArrayList.Create;
  try
    if ceAuthorityKeyIdentifier in FCertificateExtensions.Included then
      Lst.Add(WriteExtensionAuthorityKeyIdentifier);
    if ceSubjectKeyIdentifier in FCertificateExtensions.Included then
      Lst.Add(WriteExtensionSubjectKeyIdentifier);
    if ceBasicConstraints in FCertificateExtensions.Included then
      Lst.Add(WriteExtensionBasicConstraints);
    if ceKeyUsage in FCertificateExtensions.Included then
      Lst.Add(WriteExtensionKeyUsage);
    if cePrivateKeyUsagePeriod in FCertificateExtensions.Included then
      Lst.Add(WriteExtensionPrivateKeyUsagePeriod);
    if ceCertificatePolicies in FCertificateExtensions.Included then
      Lst.Add(WriteExtensionCertificatePolicies);
    if cePolicyMappings in FCertificateExtensions.Included then
      Lst.Add(WriteExtensionPolicyMappings);
    if ceSubjectAlternativeName in FCertificateExtensions.Included then
      Lst.Add(WriteExtensionSubjectAltName);
    if ceIssuerAlternativeName in FCertificateExtensions.Included then
      Lst.Add(WriteExtensionIssuerAltName);
    if ceNameConstraints in FCertificateExtensions.Included then
      Lst.Add(WriteExtensionNameConstraints);
    if cePolicyConstraints in FCertificateExtensions.Included then
      Lst.Add(WriteExtensionPolicyConstraints);
    if ceExtendedKeyUsage in FCertificateExtensions.Included then
      Lst.Add(WriteExtensionExtendedKeyUsage);
    if ceCRLDistributionPoints in FCertificateExtensions.Included then
      Lst.Add(WriteExtensionCRLDistributionPoints);
    if ceAuthorityInformationAccess in FCertificateExtensions.Included then
      Lst.Add(WriteExtensionAuthorityInformationAccess);
     //JPM additions
    if ceNetscapeCertType in FCertificateExtensions.Included then
    begin
      Lst.Add(WriteExtensionNetscapeCertType);
    end;
    if ceNetscapeBaseURL in FCertificateExtensions.Included then
    begin
      Lst.Add(WriteExtensionNetscapeString(SB_CERT_OID_NETSCAPE_BASE_URL,
          Extensions.NetscapeBaseURL.Content));
    end;
    if ceNetscapeRevokeURL in FCertificateExtensions.Included then
    begin
      Lst.Add(WriteExtensionNetscapeString(SB_CERT_OID_NETSCAPE_REVOKE_URL,
          Extensions.NetscapeRevokeURL.Content));
    end;
    if ceNetscapeCARevokeURL in FCertificateExtensions.Included then
    begin
      Lst.Add(WriteExtensionNetscapeString(SB_CERT_OID_NETSCAPE_CA_REVOKE_URL,
          (Extensions.NetscapeCARevokeURL.Content)));
    end;
    if ceNetscapeRenewalURL in FCertificateExtensions.Included then
    begin
      Lst.Add(WriteExtensionNetscapeString(SB_CERT_OID_NETSCAPE_RENEWAL_URL,
          (Extensions.NetscapeRenewalURL.Content)));
    end;
    if ceNetscapeCAPolicyURL in FCertificateExtensions.Included then
    begin
      Lst.Add(WriteExtensionNetscapeString(SB_CERT_OID_NETSCAPE_CA_POLICY,
          (Extensions.NetscapeCAPolicy.Content)));
    end;
    if ceNetscapeServerName in FCertificateExtensions.Included then
    begin
      Lst.Add(WriteExtensionNetscapeString(SB_CERT_OID_NETSCAPE_SERVER_NAME,
          (Extensions.NetscapeServerName.Content)));
    end;
    if ceNetscapeComment in FCertificateExtensions.Included then
    begin
      Lst.Add(WriteExtensionNetscapeString(SB_CERT_OID_NETSCAPE_COMMENT,
          (Extensions.NetscapeComment.Content)));
    end;
    if ceCommonName in FCertificateExtensions.Included then
    begin
      Lst.Add(WriteExtension(SB_CERT_OID_COMMON_NAME,
          False, WritePrintableString({$ifndef SB_PASCAL_STRINGS}StrToUTF8 {$else}{$ifdef SB_UNICODE_VCL}StrToUTF8 {$endif} {$endif}(Extensions.CommonName.Content))));
    end;
    //
    if ceSubjectDirectoryAttributes in FCertificateExtensions.Included then
    begin
      if (FCertificateExtensions.SubjectDirectoryAttributes.Attributes.Count > 0) then
        Lst.Add(WriteExtensionSubjectDirectoryAttributes);
    end;

    for I := 0 to FCertificateExtensions.OtherCount - 1 do
    begin
      Lst.Add(WriteExtension(FCertificateExtensions.OtherExtensions[I].OID,
        FCertificateExtensions.OtherExtensions[I].Critical,
        FCertificateExtensions.OtherExtensions[I].Value));
    end;
    Result := WriteListSequence(Lst);
    if FUseA3Prefix then
      Result := SBConcatArrays(byte($A3), WriteSize(Length(Result)), Result);
  
  finally
    FreeAndNil(Lst);
  end;
end;

function TElExtensionWriter.WriteExtension(const OID: ByteArray; Critical: boolean; const Value: ByteArray): ByteArray;
var
  Lst: array of ByteArray;
begin
  SetLength(Lst, 3);
  Lst[0] := WriteOID(OID);
  Lst[1] := WriteBoolean(Critical);
  Lst[2] := WriteOctetString(Value);
  Result := WriteArraySequence(Lst);
end;

function TElExtensionWriter.WriteExtensionBasicConstraints: ByteArray;
var
  Lst: array of ByteArray;

  I: integer;
begin
  SetLength(Lst, 1);
  Lst[0] := WriteBoolean(FCertificateExtensions.BasicConstraints.CA);
  if FCertificateExtensions.BasicConstraints.PathLenConstraint >= 0 then
  begin
    I := FCertificateExtensions.BasicConstraints.PathLenConstraint;
    SetLength(Lst, 2);
    Lst[1] := WriteInteger(SwapSomeInt(I));
  end;
  { Must be critical in CA certificates }
  Result := WriteExtension(SB_CERT_OID_BASIC_CONSTRAINTS,
    FCertificateExtensions.BasicConstraints.Critical, WriteArraySequence(Lst));
end;

function TElExtensionWriter.WriteExtensionKeyUsage: ByteArray;
var
  B1, B2: byte;
  Str: ByteArray;
begin
  B1 := 0;
  B2 := 0;
  if FCertificateExtensions.KeyUsage.DigitalSignature then
    B1 := B1 or $80;
  if FCertificateExtensions.KeyUsage.NonRepudiation then
    B1 := B1 or $40;
  if FCertificateExtensions.KeyUsage.KeyEncipherment then
    B1 := B1 or $20;
  if FCertificateExtensions.KeyUsage.DataEncipherment then
    B1 := B1 or $10;
  if FCertificateExtensions.KeyUsage.KeyAgreement then
    B1 := B1 or $08;
  if FCertificateExtensions.KeyUsage.KeyCertSign then
    B1 := B1 or $04;
  if FCertificateExtensions.KeyUsage.CRLSign then
    B1 := B1 or $02;
  if FCertificateExtensions.KeyUsage.EncipherOnly then
    B1 := B1 or $01;
  if FCertificateExtensions.KeyUsage.DecipherOnly then
    B2 := B2 or $80;
  SetLength(Str, 2);

  Str[0] := byte(B1);
  Str[0+ 1] := byte(B2);

  { Should be Critical }
  Result := WriteExtension(SB_CERT_OID_KEY_USAGE,
    FCertificateExtensions.KeyUsage.Critical, WriteBitString(Str));
end;

function TElExtensionWriter.WriteExtensionPrivateKeyUsagePeriod: ByteArray;
var
  Lst : array of ByteArray;
  Tmp: ByteArray; // NO NEED to ReleaseArray
begin
  SetLength(Lst, 2);

  Tmp := WriteGeneralizedTime(FCertificateExtensions.PrivateKeyUsagePeriod.NotBefore);
  Tmp[0] := byte($80);
  Lst[0] := Tmp;
  Tmp := WriteGeneralizedTime(FCertificateExtensions.PrivateKeyUsagePeriod.NotAfter);
  Tmp[0] := byte($81);
  Lst[1] := Tmp;

  { Must be not critical }
  Result := WriteExtension(SB_CERT_OID_PRIVATE_KEY_USAGE_PERIOD, FCertificateExtensions.PrivateKeyUsagePeriod.Critical,
    WriteArraySequence(Lst));

  ReleaseArrays(Lst[0], Lst[1]);
end;

function TElExtensionWriter.WriteExtensionSubjectAltName: ByteArray;
var
  Tag: TElASN1ConstrainedTag;
  Size: integer;
  Tmp: ByteArray;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    FCertificateExtensions.SubjectAlternativeName.Content.SaveToTag(Tag);
    Size := 0;
    Tag.SaveToBuffer( nil , Size);
    SetLength(Tmp, Size);
    Tag.SaveToBuffer( @Tmp[0] , Size);
    SetLength(Tmp, Size);
  finally
    FreeAndNil(Tag);
  end;

  { Critical unknown }
  Result := WriteExtension(SB_CERT_OID_SUBJECT_ALTERNATIVE_NAME,
    FCertificateExtensions.SubjectAlternativeName.Critical, Tmp);
  ReleaseArray(Tmp);
end;

function TElExtensionWriter.WriteExtensionIssuerAltName: ByteArray;
var
  Tmp: ByteArray;
  Size: integer;
  Tag: TElASN1ConstrainedTag;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    FCertificateExtensions.IssuerAlternativeName.Content.SaveToTag(Tag);
    Size := 0;
    Tag.SaveToBuffer( nil , Size);
    SetLength(Tmp, Size);
    Tag.SaveToBuffer( @Tmp[0] , Size);
    SetLength(Tmp, Size);
  finally
    FreeAndNil(Tag);
  end;

  { Critical unknown }
  Result := WriteExtension(SB_CERT_OID_ISSUER_ALTERNATIVE_NAME,
    FCertificateExtensions.IssuerAlternativeName.Critical,
    Tmp);
  ReleaseArray(Tmp);
end;

function TElExtensionWriter.WriteExtensionPolicyMappings: ByteArray;
var
  Lst: array of ByteArray;
  TmpLst: array of ByteArray;
  I: integer;
begin
  SetLength(Lst, FCertificateExtensions.PolicyMappings.Count);
  SetLength(TmpLst, 2);
  for I := 0 to FCertificateExtensions.PolicyMappings.Count - 1 do
  begin
    TmpLst[0] := WriteOID(FCertificateExtensions.PolicyMappings.Policies[I].IssuerDomainPolicy);
    TmpLst[1] := WriteOID(FCertificateExtensions.PolicyMappings.Policies[I].SubjectDomainPolicy);
    Lst[I] := WriteArraySequence(TmpLst);
  end;
  { Must be not critical }
  Result := WriteExtension(SB_CERT_OID_POLICY_MAPPINGS,
    FCertificateExtensions.PolicyMappings.Critical, WriteArraySequence(Lst));
  ReleaseArrays(TmpLst[0], TmpLst[1]);
end;

function TElExtensionWriter.WriteExtensionNameConstraints: ByteArray;
var
  Lst: array of ByteArray;
  TmpLst, OutmostLst: array of ByteArray;
  Tmp: ByteArray;
  I: integer;
  Size: integer;
  P: TElGeneralName;
  Tag: TElASN1SimpleTag;
begin
  SetLength(TmpLst, 3);
  SetLength(Lst, FCertificateExtensions.NameConstraints.PermittedCount);
  SetLength(OutmostLst, 2);
  for I := 0 to FCertificateExtensions.NameConstraints.PermittedCount - 1 do
  begin
    P := FCertificateExtensions.NameConstraints.PermittedSubtrees[I].Base;
    //TmpLst[0] := WriteGeneralName(P);
    Tag := TElASN1SimpleTag.CreateInstance;
    try
      P.SaveToTag(Tag);
      Size := 0;
      Tag.SaveToBuffer( nil , Size);
      SetLength(Tmp, Size);
      Tag.SaveToBuffer( @Tmp[0] , Size);
      SetLength(Tmp, Size);
      TmpLst[0] := Tmp;
    finally
      FreeAndNil(Tag);
    end;

    Tmp := WriteInteger(FCertificateExtensions.NameConstraints.PermittedSubtrees[I].Minimum);
    //TmpLst[1] := WritePrimitive($A0, Tmp);
    Tmp[0] := byte($80);
    TmpLst[1] := Tmp;

    Tmp := WriteInteger(FCertificateExtensions.NameConstraints.PermittedSubtrees[I].Maximum);
    //TmpLst[2] := WritePrimitive($A1, Tmp);
    Tmp[0] := byte($81);
    TmpLst[2] := Tmp;
    Lst[I] := WriteArraySequence(TmpLst);
  end;
  Tmp := WriteArraySequence(Lst);
  Tmp[0] := byte($A0);
  OutmostLst[0] := Tmp;
  SetLength(Lst, FCertificateExtensions.NameConstraints.ExcludedCount);
  for I := 0 to FCertificateExtensions.NameConstraints.ExcludedCount - 1 do
  begin
    P := FCertificateExtensions.NameConstraints.ExcludedSubtrees[I].Base;
    //TmpLst[0] := WriteGeneralName(P);
    Tag := TElASN1SimpleTag.CreateInstance;
    try
      P.SaveToTag(Tag);
      Size := 0;
      Tag.SaveToBuffer( nil , Size);
      SetLength(Tmp, Size);
      Tag.SaveToBuffer( @Tmp[0] , Size);
      SetLength(Tmp, Size);
      TmpLst[0] := Tmp;
    finally
      FreeAndNil(Tag);
    end;

    Tmp := WriteInteger(FCertificateExtensions.NameConstraints.ExcludedSubtrees[I].Minimum);
    // TmpLst[1] := WritePrimitive($A0, Tmp);
    Tmp[0] := byte($80);
    TmpLst[1] := Tmp;

    Tmp := WriteInteger(FCertificateExtensions.NameConstraints.ExcludedSubtrees[I].Maximum);
    // TmpLst[2] := WritePrimitive($A1, Tmp);
    Tmp[0] := byte($81);
    TmpLst[2] := Tmp;

    Lst[I] := WriteArraySequence(TmpLst);
  end;
  Tmp := WriteArraySequence(Lst);
  Tmp[0] := byte($A1);
  OutmostLst[1] := Tmp;

  Result := WriteExtension(SB_CERT_OID_NAME_CONSTRAINTS,
    FCertificateExtensions.NameConstraints.Critical, WriteArraySequence(OutmostLst));
  ReleaseArrays(TmpLst[0], TmpLst[1], TmpLst[2]);
  ReleaseArrays(OutmostLst[0], OutmostLst[1]);
end;

function TElExtensionWriter.WriteExtensionPolicyConstraints: ByteArray;
var
  Lst: array of ByteArray;
  Tmp: ByteArray;
begin
  SetLength(Lst, 2);
  Lst[0] := WriteInteger(FCertificateExtensions.PolicyConstraints.RequireExplicitPolicy);
  Lst[1] := WriteInteger(FCertificateExtensions.PolicyConstraints.InhibitPolicyMapping);

  Tmp := Lst[0];
  Tmp[0] := byte($80);
  Lst[0] := Tmp;

  Tmp := Lst[1];
  Tmp[0] := byte($81);
  Lst[1] := Tmp;

  Result := WriteExtension(SB_CERT_OID_POLICY_CONSTRAINTS,
    FCertificateExtensions.PolicyConstraints.Critical, WriteArraySequence(Lst));
  ReleaseArrays(Lst[0], Lst[1]);
end;

function TElExtensionWriter.WriteExtensionExtendedKeyUsage: ByteArray;
var
  Lst: TElByteArrayList;
  I: integer;
begin
  Lst := TElByteArrayList.Create;
  try
  if FCertificateExtensions.ExtendedKeyUsage.ServerAuthentication then
    Lst.Add(WriteOID(CreateByteArrayConst(#$2B#$06#$01#$05#$05#$07#$03#$01)));
  if FCertificateExtensions.ExtendedKeyUsage.ClientAuthentication then
    Lst.Add(WriteOID(CreateByteArrayConst(#$2B#$06#$01#$05#$05#$07#$03#$02)));
  if FCertificateExtensions.ExtendedKeyUsage.CodeSigning then
    Lst.Add(WriteOID(CreateByteArrayConst(#$2B#$06#$01#$05#$05#$07#$03#$03)));
  if FCertificateExtensions.ExtendedKeyUsage.EmailProtection then
    Lst.Add(WriteOID(CreateByteArrayConst(#$2B#$06#$01#$05#$05#$07#$03#$04)));
  if FCertificateExtensions.ExtendedKeyUsage.TimeStamping then
    Lst.Add(WriteOID(CreateByteArrayConst(#$2B#$06#$01#$05#$05#$07#$03#$08)));
  if FCertificateExtensions.ExtendedKeyUsage.OCSPSigning then
    Lst.Add(WriteOID(CreateByteArrayConst(#$2B#$06#$01#$05#$05#$07#$03#$09)));
  for I := 0 to FCertificateExtensions.ExtendedKeyUsage.CustomUsageCount - 1 do
    Lst.Add(WriteOID(FCertificateExtensions.ExtendedKeyUsage.CustomUsages[I]));
  Result := WriteExtension(SB_CERT_OID_EXTENDED_KEY_USAGE,
    FCertificateExtensions.ExtendedKeyUsage.Critical, WriteListSequence(Lst));

  finally
    FreeAndNil(Lst);
  end;
end;

function TElExtensionWriter.WriteExtensionCertificatePolicies: ByteArray;
var
  Lst: array of ByteArray;
  TmpBuf: ByteArray;
  I: integer;
begin
  SetLength(Lst, FCertificateExtensions.CertificatePolicies.Count);
  for I := 0 to FCertificateExtensions.CertificatePolicies.Count - 1 do
  begin
    TmpBuf := WritePolicyInformation(TElSinglePolicyInformation(FCertificateExtensions.CertificatePolicies.PolicyInformation[I]));
    Lst[i] := TmpBuf;
  end;
  Result := WriteExtension(SB_CERT_OID_CERTIFICATE_POLICIES,
    FCertificateExtensions.CertificatePolicies.Critical, WriteArraySequence(Lst));
end;

function TElExtensionWriter.WriteExtensionAuthorityKeyIdentifier: ByteArray;
var
  Lst: TElByteArrayList;
  Tmp: ByteArray;
  Size: integer;
  Tag: TElASN1ConstrainedTag;
begin
  Lst := TElByteArrayList.Create;
  try
  Tmp := WriteOctetString(FCertificateExtensions.AuthorityKeyIdentifier.KeyIdentifier);
  Tmp[0] := byte($80);

  Lst.Add(Tmp);

  if FCertificateExtensions.AuthorityKeyIdentifier.AuthorityCertIssuer.Count > 0 then
  begin
    Tag := TElASN1ConstrainedTag.CreateInstance;
    try
      FCertificateExtensions.AuthorityKeyIdentifier.AuthorityCertIssuer.SaveToTag(Tag);
      Size := 0;
      Tag.SaveToBuffer( nil , Size);
      SetLength(Tmp, Size);
      Tag.SaveToBuffer( @Tmp[0] , Size);
      SetLength(Tmp, Size);
    finally
      FreeAndNil(Tag);
    end;
    Tmp[0] := byte($A1);
    Lst.Add(Tmp);
  end;

  Tmp := FCertificateExtensions.AuthorityKeyIdentifier.AuthorityCertSerial;
  if Length(Tmp) <> 0 then
    Lst.Add(WritePrimitive($82, Tmp));

  { Must Not be critical }
  Result := WriteExtension(SB_CERT_OID_AUTHORITY_KEY_IDENTIFIER,
    FCertificateExtensions.AuthorityKeyIdentifier.Critical, WriteListSequence(Lst));

  finally
    FreeAndNil(Lst);
  end;
end;

function TElExtensionWriter.WriteExtensionSubjectKeyIdentifier: ByteArray;
var
  Tmp: ByteArray;
begin
  { Must not be critical }
  Tmp := WriteOctetString(FCertificateExtensions.SubjectKeyIdentifier.KeyIdentifier);

  Result := WriteExtension(SB_CERT_OID_SUBJECT_KEY_IDENTIFIER,
    FCertificateExtensions.SubjectKeyIdentifier.Critical, Tmp);
end;

function TElExtensionWriter.WriteExtensionCRLDistributionPoints: ByteArray;
var
  Lst: array of ByteArray;
  TmpBuf: ByteArray;
  I: integer;
begin
  SetLength(Lst, FCertificateExtensions.CRLDistributionPoints.Count);
  for I := 0 to FCertificateExtensions.CRLDistributionPoints.Count - 1 do
  begin
    TmpBuf := WriteDistributionPoint(TElDistributionPoint(FCertificateExtensions.CRLDistributionPoints.DistributionPoints[I]));
    Lst[I] := TmpBuf;
  end;
  Result := WriteExtension(SB_CERT_OID_CRL_DISTRIBUTION_POINTS,
    FCertificateExtensions.CRLDistributionPoints.Critical, WriteArraySequence(Lst));
end;

function TElExtensionWriter.WriteExtensionAuthorityInformationAccess: ByteArray;
var
  Lst: array of ByteArray;
  TmpLst: array of ByteArray;
  I: integer;
  P: TElAccessDescription;
  Tag: TElASN1SimpleTag;
  Size: integer;
  Tmp: ByteArray;
begin
  SetLength(Lst, FCertificateExtensions.AuthorityInformationAccess.Count);
  SetLength(TmpLst, 2);
  for I := 0 to FCertificateExtensions.AuthorityInformationAccess.Count - 1 do
  begin
    P := TElAccessDescription(FCertificateExtensions.AuthorityInformationAccess.AccessDescriptions[I]);
    TmpLst[0] := WriteOID(P.AccessMethod);

    //TmpLst[1] := WriteGeneralName(P.AccessLocation);
    Tag := TElASN1SimpleTag.CreateInstance;
    try
      P.AccessLocation.SaveToTag(Tag);
      Size := 0;
      Tag.SaveToBuffer( nil , Size);
      SetLength(Tmp, Size);
      Tag.SaveToBuffer( @Tmp[0] , Size);
      SetLength(Tmp, Size);
    finally
      FreeAndNil(Tag);
    end;
    TmpLst[1] := Tmp;

    Lst[I] := WriteArraySequence(TmpLst);
    ReleaseArrays(TmpLst[0], TmpLst[1]);
  end;
  Result := WriteExtension(SB_CERT_OID_AUTHORITY_INFORMATION_ACCESS,
    FCertificateExtensions.AuthorityInformationAccess.Critical,
    WriteArraySequence(Lst));
end;

function TElExtensionWriter.WriteExtensionNetscapeCertType: ByteArray;
var
  s: ByteArray;
  LVal: Byte;
const
  ASN_BIT_0 = $80;
  ASN_BIT_1 = $40;
  ASN_BIT_2 = $20;
  ASN_BIT_3 = $10;
  ASN_BIT_4 = $08;
  ASN_BIT_5 = $04;
  ASN_BIT_6 = $02;
  ASN_BIT_7 = $01;
begin
  LVal := 0;
  if nsSSLClient in Extensions.NetscapeCertType.CertType then
  begin
    LVal := LVal or ASN_BIT_0;
  end;
  if nsSSLServer in Extensions.NetscapeCertType.CertType then
  begin
    LVal := LVal or ASN_BIT_1;
  end;
  if nsSMIME in Extensions.NetscapeCertType.CertType then
  begin
    LVal := LVal or ASN_BIT_2;
  end;
  if nsObjectSign in Extensions.NetscapeCertType.CertType then
  begin
    LVal := LVal or ASN_BIT_3;
  end;
  if nsSSLCA in Extensions.NetscapeCertType.CertType then
  begin
    LVal := LVal or ASN_BIT_5;
  end;
  if nsSMIMECA in Extensions.NetscapeCertType.CertType then
  begin
    LVal := LVal or ASN_BIT_6;
  end;
  if nsObjectSignCA in Extensions.NetscapeCertType.CertType then
  begin
    LVal := LVal or ASN_BIT_7;
  end;
  SetLength(s, 1);
  S[0] := byte(LVal);
  Result := WriteExtension(SB_CERT_OID_NETSCAPE_CERT_TYPE,
        False, WriteBitString(s));
end;

function TElExtensionWriter.WriteExtensionNetscapeString(const AOID: ByteArray; const ANetStr: string): ByteArray;
var Tmp : ByteArray;
begin
  Tmp := {$ifndef SB_ANSI_VCL}StrToUTF8 {$else}CreateByteArrayConst {$endif}(ANetStr);
  Result := WriteExtension(AOID, False, WritePrimitive(asn1IA5String, Tmp));
  ReleaseArray(Tmp);
end;

function TElExtensionWriter.WriteExtensionNetscapeString(const AOID: ByteArray;
  const ANetStr: ByteArray): ByteArray;
begin
  Result := WriteExtension(AOID, False, WritePrimitive(asn1IA5String, ANetStr));
end;

function TElExtensionWriter.WritePolicyInformation(P: TElSinglePolicyInformation): ByteArray;
var
  Lst, TmpLst, InfoLst, UserNoticeLst, NoticeRefLst, NoticeNumLst: TElByteArrayList;
  Q: TElSinglePolicyQualifier;
  I, J: integer;
begin
  Lst := TElByteArrayList.Create;
  TmpLst := TElByteArrayList.Create;
  InfoLst := TElByteArrayList.Create;
  try
    Lst.Add(WriteOID(P.PolicyIdentifier));

    for I := 0 to P.QualifierCount - 1 do
    begin
      Q := P.Qualifiers[I];

      // adding policy qualifiers
      {1}
      if Length(Q.CPSURI) > 0 then
      begin
        InfoLst.Clear;
        InfoLst.Add(WriteOID(CreateByteArrayConst(#$2B#$06#$01#$05#$05#$07#$02#$01)));
        InfoLst.Add(WriteStringPrimitive($16, Q.CPSURI));
        TmpLst.Add(WriteListSequence(InfoLst));
      end
      {2}
      else if (Length(Q.FUserNotice.FOrganization) > 0) or
        (Length(Q.FUserNotice.FExplicitText) > 0) or
        (Length(Q.FUserNotice.FNoticeNumbers) > 0) then
      begin
        InfoLst.Clear;
        { checkup usernotice to be turned on }
        // if UserNotice is On then
        UserNoticeLst := TElByteArrayList.Create;
        NoticeRefLst := TElByteArrayList.Create;
        NoticeNumLst := TElByteArrayList.Create;
        { Info-ID }
        InfoLst.Add(WriteOID(CreateByteArrayConst(#$2B#$06#$01#$05#$05#$07#$02#$02)));
          { Organization }
        NoticeRefLst.Add(WriteStringPrimitive($16, Q.UserNotice.Organization));
        for J := 0 to Q.UserNotice.NoticeNumbersCount - 1 do
          NoticeNumLst.Add(WriteInteger(Q.UserNotice.NoticeNumbers[J]));
          { Notice numbers }
        NoticeRefLst.Add(WriteListSequence(NoticeNumLst));
        { Notice Ref }
        UserNoticeLst.Add(WriteListSequence(NoticeRefLst));
        { Explicit Text }
        UserNoticeLst.Add(WriteVisibleString(Q.UserNotice.ExplicitText));
        { Info-Qualifier }
        InfoLst.Add(WriteListSequence(UserNoticeLst));
        FreeAndNil(UserNoticeLst);
        FreeAndNil(NoticeRefLst);
        FreeAndNil(NoticeNumLst);
        TmpLst.Add(WriteListSequence(InfoLst));
      end;
    end;

    Lst.Add(WriteListSequence(TmpLst));
    Result := WriteListSequence(Lst);
  finally
    FreeAndNil(Lst);
    FreeAndNil(TmpLst);
    FreeAndNil(InfoLst);
  end;
end;

function TElExtensionWriter.WriteDistributionPoint(P: TElDistributionPoint): ByteArray;
var
  Lst: array of ByteArray;
  Tmp: ByteArray;
  B1: Word;
  Tag: TElASN1ConstrainedTag;
  Size: integer;
begin
  SetLength(Lst, 0);

  if (P.Name.Count > 0) and (dppName in P.Included) then
  begin
    Tag := TElASN1ConstrainedTag.CreateInstance;
    try
      P.Name.SaveToTag(Tag);
      Size := 0;
      Tag.SaveToBuffer( nil , Size);
      SetLength(Tmp, Size);
      Tag.SaveToBuffer( @Tmp[0] , Size);
      SetLength(Tmp, Size);
      Tmp[0] := byte($A0);
    finally
      FreeAndNil(Tag);
    end;
    SetLength(Lst, 1);
    Lst[0] := WritePrimitive($A0, Tmp);
  end;

  if (dppReasonFlags in P.Included) then
  begin
    B1 := 0;
    if rfAACompromise in P.ReasonFlags then
      B1 := B1 or $8000;
    if rfPrivilegeWithdrawn in P.ReasonFlags then
      B1 := B1 or $80;
    (*{$ifdef SB_VCL}
    if rfRemoveFromCRL in P.ReasonFlags then
    {$else}
    if rfRemoveFromCRL and P.ReasonFlags = rfRemoveFromCRL then
    {$endif}
      B1 := B1 or $100;
    {$ifdef SB_VCL}
    if rfObsolete1 in P.ReasonFlags then
    {$else}
    if rfObsolete1 and P.ReasonFlags = rfObsolete1 then
    {$endif}
      B1 := B1 or $80;*)
    if rfUnspecified in P.ReasonFlags then
      B1 := B1 or $1;
    if rfKeyCompromise in P.ReasonFlags then
      B1 := B1 or $40;
    if rfCACompromise in P.ReasonFlags then
      B1 := B1 or $20;
    if rfAffiliationChanged in P.ReasonFlags then
      B1 := B1 or $10;
    if rfSuperseded in P.ReasonFlags then
      B1 := B1 or $08;
    if rfCessationOfOperation in P.ReasonFlags then
      B1 := B1 or $04;
    if rfCertificateHold in P.ReasonFlags then
      B1 := B1 or $02;

    if (B1 > $FF) then
    begin
      // two bytes are needed
      Tmp := WriteBitString(GetByteArrayFromWordLE(B1));
    end
    else
    begin
      // one byte is needed
      Tmp := WriteBitString(GetByteArrayFromByte(byte(B1)));
    end;
    Tmp[0] := byte($81);
    SetLength(Lst, Length(Lst) + 1);
    Lst[Length(Lst) - 1] := Tmp;
  end;

  if (P.CRLIssuer.Count > 0) and (dppCRLIssuer in P.Included) then
  begin
    //Tmp := WriteGeneralNamesSeq(P.CRLIssuer);
    Tag := TElASN1ConstrainedTag.CreateInstance;
    try
      P.CRLIssuer.SaveToTag(Tag);
      Size := 0;
      Tag.SaveToBuffer( nil , Size);
      SetLength(Tmp, Size);
      Tag.SaveToBuffer( @Tmp[0] , Size);
      SetLength(Tmp, Size);
      Tmp[0] := byte($A2);
    finally
      FreeAndNil(Tag);
    end;
    SetLength(Lst, Length(Lst) + 1);
    Lst[Length(Lst) - 1] := Tmp;
  end;

  Result := WriteArraySequence(Lst);
end;

function TElExtensionWriter.WriteExtensionSubjectDirectoryAttributes : ByteArray;
var
  Tag : TElASN1ConstrainedTag;
  Size: integer;
  Buf : ByteArray;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    SaveAttributes(Tag, Extensions.SubjectDirectoryAttributes.Attributes, SB_ASN1_SEQUENCE);
    Size := 0;
    Tag.SaveToBuffer( nil , Size);
    SetLength(Buf, Size);
    Tag.SaveToBuffer( @Buf[0] , Size);
    SetLength(Buf, Size);
  finally
    FreeAndNil(Tag);
  end;
  Result := WriteExtension(SB_CERT_OID_SUBJECT_DIRECTORY_ATTRIBUTES, False, Buf);
end;

////////////////////////////////////////////////////////////////////////////////
// TElExtensionReader class

constructor TElExtensionReader.Create(Exts : TElCertificateExtensions;
  StrictMode : boolean);
begin
  inherited Create;
  FCertificateExtensions := Exts;
  FStrictMode := StrictMode;
end;

procedure TElExtensionReader.ParseExtension(const OID: ByteArray; Critical: boolean;
  const Content: ByteArray);
var
  Exten: TElCustomExtension;
begin 
  if CompareContent(OID, SB_CERT_OID_BASIC_CONSTRAINTS) or
    CompareContent(OID, CreateByteArrayConst(#$55#$1D#$0A)) then
  begin
    Exten := FCertificateExtensions.BasicConstraints;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [ceBasicConstraints] ;
  end
  else
    if CompareContent(OID, SB_CERT_OID_AUTHORITY_KEY_IDENTIFIER) or
    CompareContent(OID, CreateByteArrayConst(#$55#$1D#$01)) then
  begin
    Exten := FCertificateExtensions.AuthorityKeyIdentifier;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [ceAuthorityKeyIdentifier] ;
    if (FStrictMode) and Critical then
      raise EElCertificateError.Create(SNonCriticalExtensionMarkedAsCritical);
  end
  else
    if CompareContent(OID, SB_CERT_OID_SUBJECT_KEY_IDENTIFIER) then
  begin
    Exten := FCertificateExtensions.SubjectKeyIdentifier;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [ceSubjectKeyIdentifier] ;
    if (FStrictMode) and Critical then
      raise EElCertificateError.Create(SNonCriticalExtensionMarkedAsCritical);
  end
  else
    if CompareContent(OID, SB_CERT_OID_KEY_USAGE) then
  begin
    Exten := FCertificateExtensions.KeyUsage;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [ceKeyUsage] ;
  end
  else
    if CompareContent(OID, SB_CERT_OID_PRIVATE_KEY_USAGE_PERIOD) then
  begin
    Exten := FCertificateExtensions.PrivateKeyUsagePeriod;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [cePrivateKeyUsagePeriod] ;
  end
  else
    if CompareContent(OID, SB_CERT_OID_CERTIFICATE_POLICIES) then
  begin
    Exten := FCertificateExtensions.CertificatePolicies;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [ceCertificatePolicies] ;
  end
  else
    if CompareContent(OID, SB_CERT_OID_POLICY_MAPPINGS) then
  begin
    Exten := FCertificateExtensions.PolicyMappings;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [cePolicyMappings] ;
    if (FStrictMode) and Critical then
      raise EElCertificateError.Create(SNonCriticalExtensionMarkedAsCritical);
  end
  else
    if CompareContent(OID, SB_CERT_OID_POLICY_CONSTRAINTS) then
  begin
    Exten := FCertificateExtensions.PolicyConstraints;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [cePolicyConstraints] ;
  end
  else
    if CompareContent(OID, SB_CERT_OID_EXTENDED_KEY_USAGE) then
  begin
    Exten := FCertificateExtensions.ExtendedKeyUsage;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [ceExtendedKeyUsage] ;
  end
  else
    if CompareContent(OID, SB_CERT_OID_AUTHORITY_INFORMATION_ACCESS) then
  begin
    Exten := FCertificateExtensions.AuthorityInformationAccess;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [ceAuthorityInformationAccess] ;
    if (FStrictMode) and Critical then
      raise EElCertificateError.Create(SNonCriticalExtensionMarkedAsCritical);
  end
  else
    if CompareContent(OID, SB_CERT_OID_NAME_CONSTRAINTS) then
  begin
    Exten := FCertificateExtensions.NameConstraints;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [ceNameConstraints] ;
  end
  else
    if CompareContent(OID, SB_CERT_OID_CRL_DISTRIBUTION_POINTS) then
  begin
    Exten := FCertificateExtensions.CRLDistributionPoints;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [ceCRLDistributionPoints] ;
  end
  else
    if CompareContent(OID, SB_CERT_OID_ISSUER_ALTERNATIVE_NAME) then
  begin
    Exten := FCertificateExtensions.IssuerAlternativeName;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [ceIssuerAlternativeName] ;
  end
  else
    if CompareContent(OID, SB_CERT_OID_SUBJECT_ALTERNATIVE_NAME) then
  begin
    Exten := FCertificateExtensions.SubjectAlternativeName;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [ceSubjectAlternativeName] ;
  end
  else
  //JPM
    if CompareContent(OID, SB_CERT_OID_NETSCAPE_CERT_TYPE) then
  begin
    Exten := FCertificateExtensions.NetscapeCertType;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [ceNetscapeCertType] ;
  end
  else
    if CompareContent(OID, SB_CERT_OID_NETSCAPE_BASE_URL) then
  begin
    Exten := FCertificateExtensions.NetscapeBaseURL;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [ceNetscapeBaseURL] ;
  end
  else
    if CompareContent(OID, SB_CERT_OID_NETSCAPE_REVOKE_URL) then
  begin
    Exten := FCertificateExtensions.NetscapeRevokeURL;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [ceNetscapeRevokeURL] ;
  end
  else
    if CompareContent(OID, SB_CERT_OID_NETSCAPE_CA_REVOKE_URL) then
  begin
    Exten := FCertificateExtensions.NetscapeCARevokeURL;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [ceNetscapeCARevokeURL] ;
  end
  else
    if CompareContent(OID, SB_CERT_OID_NETSCAPE_RENEWAL_URL) then
  begin
    Exten := FCertificateExtensions.NetscapeRenewalURL;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [ceNetscapeRenewalURL] ;
  end
  else
    if CompareContent(OID, SB_CERT_OID_NETSCAPE_CA_POLICY) then
  begin
    Exten := FCertificateExtensions.NetscapeCAPolicy;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [ceNetscapeCAPolicyURL] ;
  end
  else
    if CompareContent(OID, SB_CERT_OID_NETSCAPE_SERVER_NAME) then
  begin
    Exten := FCertificateExtensions.NetscapeServerName;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [ceNetscapeServerName] ;
  end
  else
    if CompareContent(OID, SB_CERT_OID_NETSCAPE_COMMENT) then
  begin
    Exten := FCertificateExtensions.NetscapeComment;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [ceNetscapeComment] ;
  end
  else
    if CompareContent(OID, SB_CERT_OID_COMMON_NAME) then
  begin
    Exten := FCertificateExtensions.CommonName;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [ceCommonName] ;
  end
  //end
  else
    if CompareContent(OID, SB_CERT_OID_SUBJECT_DIRECTORY_ATTRIBUTES) then
  begin
    Exten := FCertificateExtensions.SubjectDirectoryAttributes;
    FCertificateExtensions.Included := FCertificateExtensions.Included  + [ceSubjectDirectoryAttributes] ;
  end
  else
  begin
    Exten := TElCustomExtension.Create;
    FCertificateExtensions.FOtherList.Add(Exten);
  end;
  if Assigned(Exten) then
  begin
    Exten.Critical := Critical;
    try
      Exten.Value := Content;
    except
      if Critical and FStrictMode then
        raise;
    end;
    Exten.OID := OID;
  end;
end;

initialization
  begin
  {$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}

  SB_CERT_OID_NETSCAPE_CERT_TYPE      := CreateByteArrayConst( SB_CERT_OID_NETSCAPE_CERT_TYPE_STR );
  SB_CERT_OID_NETSCAPE_BASE_URL       := CreateByteArrayConst( SB_CERT_OID_NETSCAPE_BASE_URL_STR );
  SB_CERT_OID_NETSCAPE_REVOKE_URL     := CreateByteArrayConst( SB_CERT_OID_NETSCAPE_REVOKE_URL_STR );
  SB_CERT_OID_NETSCAPE_CA_REVOKE_URL  := CreateByteArrayConst( SB_CERT_OID_NETSCAPE_CA_REVOKE_URL_STR );
  SB_CERT_OID_NETSCAPE_RENEWAL_URL    := CreateByteArrayConst( SB_CERT_OID_NETSCAPE_RENEWAL_URL_STR );
  SB_CERT_OID_NETSCAPE_CA_POLICY      := CreateByteArrayConst( SB_CERT_OID_NETSCAPE_CA_POLICY_STR );
  SB_CERT_OID_NETSCAPE_SERVER_NAME    := CreateByteArrayConst( SB_CERT_OID_NETSCAPE_SERVER_NAME_STR );
  SB_CERT_OID_NETSCAPE_COMMENT        := CreateByteArrayConst( SB_CERT_OID_NETSCAPE_COMMENT_STR );

  SB_CERT_OID_SUBJECT_DIRECTORY_ATTRIBUTES  := CreateByteArrayConst( SB_CERT_OID_SUBJECT_DIRECTORY_ATTRIBUTES_STR );
  SB_CERT_OID_SUBJECT_KEY_IDENTIFIER        := CreateByteArrayConst( SB_CERT_OID_SUBJECT_KEY_IDENTIFIER_STR );
  SB_CERT_OID_KEY_USAGE                     := CreateByteArrayConst( SB_CERT_OID_KEY_USAGE_STR );
  SB_CERT_OID_PRIVATE_KEY_USAGE_PERIOD      := CreateByteArrayConst( SB_CERT_OID_PRIVATE_KEY_USAGE_PERIOD_STR );
  SB_CERT_OID_SUBJECT_ALTERNATIVE_NAME      := CreateByteArrayConst( SB_CERT_OID_SUBJECT_ALTERNATIVE_NAME_STR );
  SB_CERT_OID_ISSUER_ALTERNATIVE_NAME       := CreateByteArrayConst( SB_CERT_OID_ISSUER_ALTERNATIVE_NAME_STR );
  SB_CERT_OID_BASIC_CONSTRAINTS             := CreateByteArrayConst( SB_CERT_OID_BASIC_CONSTRAINTS_STR );
  SB_CERT_OID_NAME_CONSTRAINTS              := CreateByteArrayConst( SB_CERT_OID_NAME_CONSTRAINTS_STR );
  SB_CERT_OID_CRL_DISTRIBUTION_POINTS       := CreateByteArrayConst( SB_CERT_OID_CRL_DISTRIBUTION_POINTS_STR );
  SB_CERT_OID_CERTIFICATE_POLICIES          := CreateByteArrayConst( SB_CERT_OID_CERTIFICATE_POLICIES_STR );
  SB_CERT_OID_POLICY_MAPPINGS               := CreateByteArrayConst( SB_CERT_OID_POLICY_MAPPINGS_STR );
  SB_CERT_OID_AUTHORITY_KEY_IDENTIFIER      := CreateByteArrayConst( SB_CERT_OID_AUTHORITY_KEY_IDENTIFIER_STR );
  SB_CERT_OID_POLICY_CONSTRAINTS            := CreateByteArrayConst( SB_CERT_OID_POLICY_CONSTRAINTS_STR );
  SB_CERT_OID_EXTENDED_KEY_USAGE            := CreateByteArrayConst( SB_CERT_OID_EXTENDED_KEY_USAGE_STR );

  SB_CERT_OID_AUTHORITY_INFORMATION_ACCESS  := CreateByteArrayConst( SB_CERT_OID_AUTHORITY_INFORMATION_ACCESS_STR );

  PEM_CERTIFICATE_BEGIN_LINE      := CreateByteArrayConst( PEM_CERTIFICATE_BEGIN_LINE_STR );
  PEM_CERTIFICATE_END_LINE        := CreateByteArrayConst( PEM_CERTIFICATE_END_LINE_STR );
  PEM_CERTIFICATEX509_BEGIN_LINE  := CreateByteArrayConst( PEM_CERTIFICATEX509_BEGIN_LINE_STR);
  PEM_CERTIFICATEX509_END_LINE    := CreateByteArrayConst( PEM_CERTIFICATEX509_END_LINE_STR);
  PEM_RSA_PRIVATE_KEY_BEGIN_LINE  := CreateByteArrayConst( PEM_RSA_PRIVATE_KEY_BEGIN_LINE_STR );
  PEM_RSA_PRIVATE_KEY_END_LINE    := CreateByteArrayConst( PEM_RSA_PRIVATE_KEY_END_LINE_STR );
  PEM_DSA_PRIVATE_KEY_BEGIN_LINE  := CreateByteArrayConst( PEM_DSA_PRIVATE_KEY_BEGIN_LINE_STR );
  PEM_DSA_PRIVATE_KEY_END_LINE    := CreateByteArrayConst( PEM_DSA_PRIVATE_KEY_END_LINE_STR );
  PEM_DH_PRIVATE_KEY_BEGIN_LINE   := CreateByteArrayConst( PEM_DH_PRIVATE_KEY_BEGIN_LINE_STR );
  PEM_DH_PRIVATE_KEY_END_LINE     := CreateByteArrayConst( PEM_DH_PRIVATE_KEY_END_LINE_STR );
  PEM_EC_PRIVATE_KEY_BEGIN_LINE   := CreateByteArrayConst( PEM_EC_PRIVATE_KEY_BEGIN_LINE_STR );
  PEM_EC_PRIVATE_KEY_END_LINE     := CreateByteArrayConst( PEM_EC_PRIVATE_KEY_END_LINE_STR );
  PEM_PRIVATE_KEY_BEGIN_LINE      := CreateByteArrayConst( PEM_PRIVATE_KEY_BEGIN_LINE_STR );
  PEM_PRIVATE_KEY_END_LINE        := CreateByteArrayConst( PEM_PRIVATE_KEY_END_LINE_STR );
   {$endif}
end;

end.
