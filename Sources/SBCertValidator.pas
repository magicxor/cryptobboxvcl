(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$i SecBbox.inc}

unit SBCertValidator;

interface

uses
  SysUtils,
  Classes,
  {$ifdef WIN32}
  Windows,
   {$endif}
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBRDN,
  SBConstants,
  SBX509,
  SBX509Ext,
  SBOCSPCommon,
  SBOCSPClient,
  SBRandom,
  SBPKICommon,
  SBCRL,
  SBCRLStorage,
  SBCertRetriever,
  {$ifdef SB_HAS_WINCRYPT}
  SBWinCertStorage,
  //SBWinCRLStorage,
   {$endif}
  SBCustomCertStorage;

const

  SB_VALIDATOR_CRL_ERROR_BASE  = 1000;
  SB_VALIDATOR_OCSP_ERROR_BASE = 2000;

  SB_VALIDATOR_CRL_ERROR_VALIDATION_FAILED = SB_VALIDATOR_CRL_ERROR_BASE + 1;
  SB_VALIDATOR_CRL_ERROR_NO_RETRIEVER      = SB_VALIDATOR_CRL_ERROR_BASE + 2;
  SB_VALIDATOR_CRL_ERROR_RETRIEVER_FAILED  = SB_VALIDATOR_CRL_ERROR_BASE + 3;
  SB_VALIDATOR_CRL_ERROR_NO_CRLS_RETRIEVED = SB_VALIDATOR_CRL_ERROR_BASE + 4;
  SB_VALIDATOR_CRL_ERROR_CERT_REVOKED      = SB_VALIDATOR_CRL_ERROR_BASE + 5;

  SB_VALIDATOR_OCSP_ERROR_VALIDATION_FAILED = SB_VALIDATOR_OCSP_ERROR_BASE + 1;
  SB_VALIDATOR_OCSP_ERROR_NO_CLIENT         = SB_VALIDATOR_OCSP_ERROR_BASE + 2;
  SB_VALIDATOR_OCSP_ERROR_CLIENT_FAILED     = SB_VALIDATOR_OCSP_ERROR_BASE + 3;
  SB_VALIDATOR_OCSP_ERROR_INVALID_RESPONSE  = SB_VALIDATOR_OCSP_ERROR_BASE + 4;
  SB_VALIDATOR_OCSP_ERROR_CERT_REVOKED      = SB_VALIDATOR_OCSP_ERROR_BASE + 5;

type

  EElValidationFailedInternalError =  class(ESecureBlackboxError);

  TSBCRLNeededEvent =  procedure(Sender : TObject;
    Certificate, CACertificate : TElX509Certificate; var CRLs : TElCustomCRLStorage) of object;

  TSBCACertificateRetrievedEvent =   procedure(Sender : TObject;
    Certificate : TElX509Certificate; NameType : TSBGeneralName; const Location : string; CACertificate : TElX509Certificate) of object;

  TSBCRLRetrievedEvent =   procedure(Sender : TObject;
    Certificate, CACertificate : TElX509Certificate; NameType : TSBGeneralName; const Location : string; CRL : TElCertificaterevocationList) of object;

  TSBAfterCRLUseEvent =   procedure(Sender : TObject;
    Certificate, CACertificate : TElX509Certificate; CRL : TElCertificaterevocationList) of object;

  TSBAfterOCSPResponseUseEvent =   procedure(Sender : TObject;
    Certificate, CACertificate : TElX509Certificate; Response : TElOCSPResponse) of object;
    
  TSBOCSPResponseSignerValidEvent =  procedure(Sender : TObject;
    Certificate, CACertificate : TElX509Certificate; Response : TElOCSPResponse;
    SignerCertificate : TElX509Certificate; var SignerValid : boolean) of object;

  TSBBeforeCertificateRetrieverUseEvent =   procedure(Sender : TObject;
    Certificate : TElX509Certificate;
    NameType : TSBGeneralName;
    const Location : string;
    var Retriever : TElCustomCertificateRetriever
  ) of object;

  TSBBeforeCRLRetrieverUseEvent =   procedure(Sender : TObject;
    Certificate : TElX509Certificate;
    CACertificate : TElX509Certificate;
    NameType : TSBGeneralName;
    const Location : string;
    var Retriever : TElCustomCRLRetriever
  ) of object;

  TSBBeforeOCSPClientUseEvent =  procedure(Sender : TObject;
    Certificate : TElX509Certificate;
    CACertificate : TElX509Certificate;
    const OCSPLocation : string;
    var OCSPClient : TElOCSPClient
  ) of object;

  TSBCertificateValidatorCRLErrorEvent =  procedure(Sender : TObject;
    Certificate : TElX509Certificate; const Location : string; Retriever : TElCustomCRLRetriever; ErrorCode : integer) of object;

  TSBCertificateValidatorOCSPErrorEvent =  procedure(Sender : TObject;
    Certificate : TElX509Certificate; const Location : string; Client : TElOCSPClient; ErrorCode : integer) of object;

  TSBCACertificateNeededEvent =  procedure(Sender : TObject;
    Certificate : TElX509Certificate;
    var CACertificate : TElX509Certificate
  ) of object;

  TSBBeforeCertificateValidationEvent =  procedure(Sender : TObject;
    Certificate : TElX509Certificate) of object;

  TSBAfterCertificateValidationEvent =  procedure(Sender : TObject;
    Certificate : TElX509Certificate;
    CACertificate : TElX509Certificate;
    var Validity : TSBCertificateValidity;
    var Reason: TSBCertificateValidityReason;
    var DoContinue : TSBBoolean
    ) of object;


  TSBX509RevocationCheckPreference = (rcpPreferCRL, rcpPreferOCSP, rcpCheckBoth);

  TElX509CertificateValidator = class(TSBControlBase)
  protected
    FCRLRetrievers : TElList;
    FOCSPClients : TElList;
    FCertificateRetrievers : TElList;
    FCheckedCertificates : TElMemoryCertStorage;
    FChainCertificates : TElMemoryCertStorage;
    FCachedCACertificates : TElMemoryCertStorage;

    FTrustedCertificates : TElList;
    FBlockedCertificates : TElList;
    FKnownCertificates : TElList;
    //FTrustedCRLs : TElList;
    FKnownCRLs : TElList;
    //FTrustedOCSPResponses : TElList;
    FKnownOCSPResponses : TElList;
    FUsedCertificates : TElMemoryCertStorage; // certificates used during validation process
    FUsedCRLs : TElMemoryCRLStorage;  // CRLs used during validation process
    FUsedOCSPResponses : TElList; // CRLs used during validation process

    {$ifdef SB_HAS_WINCRYPT}
    FWinStorageTrust   : TElWinCertStorage;
    FWinStorageCA      : TElWinCertStorage;
    FWinStorageBlocked : TElWinCertStorage;
    FUseSystemStorages : boolean;
    FIgnoreSystemTrust : Boolean;
     {$endif}
    FCRLManager : TElCRLManager;
    FOCSPClientManager : TElOCSPClientManager;
    FCertRetrieverManager : TElCertificateRetrieverManager;

    FCheckOCSP: Boolean;
    FCheckCRL: Boolean;
    FOnCACertificateRetrieved : TSBCACertificateRetrievedEvent;
    FOnCRLRetrieved : TSBCRLRetrievedEvent;
    FOnCRLNeeded : TSBCRLNeededEvent;
    FOnBeforeCertificateRetrieverUse : TSBBeforeCertificateRetrieverUseEvent;
    FOnBeforeCRLRetrieverUse : TSBBeforeCRLRetrieverUseEvent;
    FOnBeforeOCSPClientUse : TSBBeforeOCSPClientUseEvent;
    FOnBeforeCertificateValidation : TSBBeforeCertificateValidationEvent;
    FOnAfterCertificateValidation : TSBAfterCertificateValidationEvent;
    FOnCACertificateNeeded: TSBCACertificateNeededEvent;
    FOnAfterCRLUse : TSBAfterCRLUseEvent;
    FOnAfterOCSPResponseUse : TSBAfterOCSPResponseUseEvent;
    FOnOCSPResponseSignerValid : TSBOCSPResponseSignerValidEvent;

    FOnCRLError : TSBCertificateValidatorCRLErrorEvent;
    FOnOCSPError: TSBCertificateValidatorOCSPErrorEvent;

    FValidateInvalidCertificates: Boolean;
    FCheckValidityPeriodForTrusted: Boolean;
    FIgnoreCAKeyUsage: Boolean;
    FIgnoreRevocationKeyUsage: boolean;
    FIgnoreSSLKeyUsage: boolean;
    FIgnoreBadOCSPChains : boolean;
	FIgnoreCABasicConstraints : boolean;
	FIgnoreCANameConstraints : boolean;
    FMandatoryCRLCheck: Boolean;
    FMandatoryOCSPCheck: Boolean;
    FMandatoryRevocationCheck: Boolean;
    FForceCompleteChainValidationForTrusted: Boolean;
    FForceRevocationCheckForRoot: Boolean;
    FOfflineMode : boolean;
    FRevocationMomentGracePeriod : integer;
    FImplicitlyTrustSelfSignedCertificates : boolean;
    FPromoteLongOCSPResponses : boolean;
    FValidationStack : TElList;
    FRevocationCheckPreference : TSBX509RevocationCheckPreference;
    FLookupCRLByNameIfDPNotPresent : boolean;

    procedure DeleteStorages;
    procedure DeleteCRLRetrievers;
    procedure DeleteOCSPClients;
    procedure DeleteCertificateRetrievers;

    procedure AddUsedCertificate(Cert: TElX509Certificate);
    procedure AddUsedCRL(Crl : TElCertificateRevocationList);
    procedure AddUsedOCSPResponse(OcspResp : TElOCSPResponse);
    procedure ClearUsedValidationInfo;

    function GetCertificateRetriever(NameType : TSBGeneralName; const Location : string) : TElCustomCertificateRetriever;
    function GetOCSPClient(const Location : string) : TElOCSPClient;
    function GetCRLRetriever(NameType : TSBGeneralName; const Location : string) : TElCustomCRLRetriever;

    procedure Notification(AComponent : TComponent; AOperation : TOperation); override;

    function FindMatchingCRL(Certificate : TElX509Certificate;
      DistributionPoint : TElDistributionPoint;
      Storage : TElCustomCRLStorage;
      ValidityMoment: TElDateTime) : TElCertificateRevocationList;

    function CheckIfTrusted(Certificate: TElX509Certificate): Boolean;
    procedure CheckValidityPeriod(Certificate: TElX509Certificate;
      ValidityMoment: TElDateTime;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason);

    function FindSignerCertificate(AdditionalCertificates : TElCustomCertStorage;
      Signer: TElRelativeDistinguishedName; SignerKeyIdentifier : ByteArray;
      var Trusted : TSBBoolean): TElX509Certificate;
    function FindCA(AdditionalCertificates : TElCustomCertStorage;
      Certificate: TElX509Certificate;
      var Trusted : TSBBoolean): TElX509Certificate;

    function FindCertificateInStorage(Certificate: TElX509Certificate; Storage:
      TElCustomCertStorage): Integer;

    function CertificateIsBlocked(Certificate : TElX509Certificate) : boolean;

    procedure CheckOCSPResponse(Response : TElOCSPResponse;
      AdditionalCertificates : TElCustomCertStorage;
      Certificate: TElX509Certificate;
      CACertificate: TElX509Certificate;
      ValidityMoment: TElDateTime;
      var Found : TSBBoolean;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason);

    procedure PerformOCSPCheck(
      AdditionalCertificates : TElCustomCertStorage;
      Certificate: TElX509Certificate;
      CACertificate: TElX509Certificate;
      ValidityMoment: TElDateTime;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason;
      var OcspExistsForCert : TSBBoolean);
    procedure PerformCRLCheck(
      AdditionalCertificates : TElCustomCertStorage;
      Certificate: TElX509Certificate;
      CACertificate: TElX509Certificate;
      ValidityMoment: TElDateTime;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason;
      var CrlExistsForCert : TSBBoolean);

    procedure RemoveCertificateFromChecked(Certificate: TElX509Certificate);

    procedure TriggerBeforeCertificateRetrieverUse(
      Certificate : TElX509Certificate;
      NameType : TSBGeneralName;
      const Location : string;
      var Retriever: TElCustomCertificateRetriever); virtual;
    procedure TriggerBeforeCRLRetrieverUse(
      Certificate : TElX509Certificate;
      CACertificate : TElX509Certificate;
      NameType : TSBGeneralName;
      const Location : string;
      var Retriever: TElCustomCRLRetriever); virtual;
    procedure TriggerBeforeOCSPClientUse(
      Certificate : TElX509Certificate;
      CACertificate : TElX509Certificate;
      const OCSPLocation : string;
      var Client: TElOCSPClient); virtual;
    procedure TriggerBeforeValidation(Certificate : TElX509Certificate); virtual;
    procedure TriggerAfterValidation(
      Certificate : TElX509Certificate;
      CACertificate : TElX509Certificate;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason;
      var DoContinue : TSBBoolean); virtual;
    procedure TriggerCACertificateNeeded(Certificate: TElX509Certificate; var
      CACertificate: TElX509Certificate); virtual;
    procedure TriggerCRLNeeded(Certificate, CACertificate : TElX509Certificate;
      var CRLs : TElCustomCRLStorage); virtual;
    procedure TriggerCACertificateRetrieved(Certificate : TElX509Certificate;
      NameType : TSBGeneralName; const Location : string; CACertificate : TElX509Certificate); virtual;
    procedure TriggerCRLRetrieved(Certificate, CACertificate : TElX509Certificate;
      NameType : TSBGeneralName; const Location : string; CRL : TElCertificaterevocationList); virtual;
    procedure TriggerAfterCRLUse(Certificate, CACertificate : TElX509Certificate;
      CRL : TElCertificaterevocationList); virtual;
    procedure TriggerAfterOCSPResponseUse(Certificate, CACertificate : TElX509Certificate;
      Response : TElOCSPResponse); virtual;
    procedure TriggerCRLError(Certificate : TElX509Certificate; const Location : string;
      Retriever : TElCustomCRLRetriever; ErrorCode : integer); virtual;
    procedure TriggerOCSPError(Certificate : TElX509Certificate; const Location : string;
      Client : TElOCSPClient; ErrorCode : integer); virtual;
    procedure TriggerOCSPResponseSignerValid(Certificate, CACertificate : TElX509Certificate;
      Response : TElOCSPResponse; SignerCertificate : TElX509Certificate; var SignerValid : boolean); virtual;
    
    function FindMatchingOCSP(Certificate : TElX509Certificate; CACertificate :
        TElX509Certificate; OCSPResponses : TElList; ValidityMoment: TElDateTime):
        TElOCSPResponse;
    procedure SetupImplicitDP(Certificate : TElX509Certificate; DP : TElDistributionPoint);
    function RetrieveCRLs(
      Certificate : TElX509Certificate;
      CACertificate : TElX509Certificate;
      Storage : TElCustomCRLStorage;
      ValidityMoment: TElDateTime;
      var Reason: TSBCertificateValidityReason) : string;
    function ValidateOCSP(
      AdditionalCertificates : TElCustomCertStorage;
      Certificate: TElX509Certificate;
      CACertificate: TElX509Certificate;
      Response : TElOCSPResponse;
      ValidityMoment: TElDateTime;
      var Reason : TSBCertificateValidityReason) : boolean;
    function ValidateCRL(AdditionalCertificates : TElCustomCertStorage; CRL : TElCertificateRevocationList;
      ValidityMoment: TElDateTime;
      var Reason : TSBCertificateValidityReason) : boolean;

    procedure InternalValidate(Certificate: TElX509Certificate;
      AdditionalCertificates : TElCustomCertStorage;
      CompleteChainValidation : boolean;
      ResetCertificateCache : boolean;
      ValidityMoment: TElDateTime;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason);  overload; 

    function CertificatePresentInStack(Cert: TElX509Certificate): boolean;

  public
    constructor Create(AOwner : TComponent); override;
     destructor  Destroy; override;

    {$ifdef SB_HAS_WINCRYPT}
    procedure InitializeWinStorages;
     {$endif}

    procedure Validate(Certificate: TElX509Certificate;
      AdditionalCertificates : TElCustomCertStorage;
      CompleteChainValidation : boolean;
      ResetCertificateCache : boolean;
      ValidityMoment: TElDateTime;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason
    );  overload; 

    procedure Validate(Certificate: TElX509Certificate;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason
    );  overload; 

    procedure ValidateForSMIME(Certificate: TElX509Certificate;
      EMailAddress : string;
      AdditionalCertificates : TElCustomCertStorage;
      CompleteChainValidation : boolean;
      ResetCertificateCache : boolean;
      ValidityMoment: TElDateTime;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason
    );

    procedure ValidateForSSL(Certificate: TElX509Certificate;
      DomainName : string;
      IPAddress : string;
      HostRole : TSBHostRole;
      AdditionalCertificates : TElCustomCertStorage;
      CompleteChainValidation : boolean;
      ResetCertificateCache : boolean;
      ValidityMoment: TElDateTime;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason
    );  overload; 

    procedure ValidateForSSL(Certificate: TElX509Certificate;
      DomainName : string;
      IPAddress : string;
      HostRole : TSBHostRole;
      AdditionalCertificates : TElCustomCertStorage;
      CompleteChainValidation : boolean;
      ResetCertificateCache : boolean;
      ValidityMoment: TElDateTime;
      InternalValidation : boolean;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason
    );  overload; 

    procedure ValidateForTimestamping(Certificate: TElX509Certificate;
      AdditionalCertificates : TElCustomCertStorage;
      CompleteChainValidation : boolean;
      ResetCertificateCache : boolean;
      ValidityMoment: TElDateTime;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason
    );

    procedure AddTrustedCertificates(Storage : TElCustomCertStorage);
    procedure ClearTrustedCertificates;

    procedure AddBlockedCertificates(Storage : TElCustomCertStorage);
    procedure ClearBlockedCertificates;

    procedure AddKnownCertificates(Storage : TElCustomCertStorage);
    procedure ClearKnownCertificates;

    procedure AddKnownCRLs(Storage : TElCustomCRLStorage);
    procedure ClearKnownCRLs;

    procedure AddKnownOCSPResponses(Response : TElOCSPResponse);
    procedure ClearKnownOCSPResponses;

    property UsedCertificates : TElMemoryCertStorage read FUsedCertificates;
	
    property UsedCRLs : TElMemoryCRLStorage read FUsedCRLs;
    property UsedOCSPResponses : TElList read FUsedOCSPResponses;
    {$ifdef SB_HAS_WINCRYPT}
    property WinStorageTrust   : TElWinCertStorage read FWinStorageTrust;
    property WinStorageCA      : TElWinCertStorage read FWinStorageCA;
    property WinStorageBlocked : TElWinCertStorage read FWinStorageBlocked;
     {$endif}                 
  published
    {$ifdef SB_HAS_WINCRYPT}
    property IgnoreSystemTrust: Boolean read FIgnoreSystemTrust write FIgnoreSystemTrust;
    property UseSystemStorages : boolean read FUseSystemStorages write FUseSystemStorages;
     {$endif}
    property CheckCRL: Boolean read FCheckCRL write FCheckCRL  default true ;
    property CheckOCSP: Boolean read FCheckOCSP write FCheckOCSP  default true ;

    property CheckValidityPeriodForTrusted: Boolean read FCheckValidityPeriodForTrusted write FCheckValidityPeriodForTrusted;
    property IgnoreCAKeyUsage: Boolean read FIgnoreCAKeyUsage write FIgnoreCAKeyUsage;
    property IgnoreRevocationKeyUsage: boolean read FIgnoreRevocationKeyUsage write FIgnoreRevocationKeyUsage;
    property IgnoreSSLKeyUsage: boolean read FIgnoreSSLKeyUsage write FIgnoreSSLKeyUsage;
    property IgnoreBadOCSPChains : boolean read FIgnoreBadOCSPChains write FIgnoreBadOCSPChains;
    property IgnoreCABasicConstraints : boolean read FIgnoreCABasicConstraints write FIgnoreCABasicConstraints;
    property IgnoreCANameConstraints : boolean read FIgnoreCANameConstraints write FIgnoreCANameConstraints;
    property MandatoryCRLCheck: Boolean read FMandatoryCRLCheck write FMandatoryCRLCheck  default true ;
    property MandatoryOCSPCheck: Boolean read FMandatoryOCSPCheck write FMandatoryOCSPCheck  default true ;
    property MandatoryRevocationCheck: Boolean read FMandatoryRevocationCheck write FMandatoryRevocationCheck  default true ;
    property ValidateInvalidCertificates: Boolean read FValidateInvalidCertificates write FValidateInvalidCertificates;
    property ForceCompleteChainValidationForTrusted: Boolean read FForceCompleteChainValidationForTrusted
      write FForceCompleteChainValidationForTrusted  default true ;
    property ForceRevocationCheckForRoot: Boolean read FForceRevocationCheckForRoot
      write FForceRevocationCheckForRoot  default true ;
    property OfflineMode : boolean read FOfflineMode write FOfflineMode;
    property RevocationMomentGracePeriod : integer read FRevocationMomentGracePeriod
      write FRevocationMomentGracePeriod;
    property ImplicitlyTrustSelfSignedCertificates : boolean read FImplicitlyTrustSelfSignedCertificates
      write FImplicitlyTrustSelfSignedCertificates;
    property PromoteLongOCSPResponses : boolean read FPromoteLongOCSPResponses
      write FPromoteLongOCSPResponses;
    property RevocationCheckPreference : TSBX509RevocationCheckPreference read FRevocationCheckPreference
      write FRevocationCheckPreference;
    property LookupCRLByNameIfDPNotPresent : boolean read FLookupCRLByNameIfDPNotPresent
      write FLookupCRLByNameIfDPNotPresent; 

    property OnCRLNeeded : TSBCRLNeededEvent read FOnCRLNeeded write FOnCRLNeeded;
    property OnCRLRetrieved : TSBCRLRetrievedEvent read FOnCRLRetrieved write FOnCRLRetrieved;
    property OnBeforeCRLRetrieverUse : TSBBeforeCRLRetrieverUseEvent read FOnBeforeCRLRetrieverUse write FOnBeforeCRLRetrieverUse;
    property OnBeforeCertificateRetrieverUse : TSBBeforeCertificateRetrieverUseEvent read FOnBeforeCertificateRetrieverUse write FOnBeforeCertificateRetrieverUse;
    property OnCACertificateRetrieved : TSBCACertificateRetrievedEvent read FOnCACertificateRetrieved write FOnCACertificateRetrieved;
    property OnBeforeOCSPClientUse : TSBBeforeOCSPClientUseEvent read FOnBeforeOCSPClientUse write FOnBeforeOCSPClientUse;
    property OnBeforeCertificateValidation : TSBBeforeCertificateValidationEvent
      read FOnBeforeCertificateValidation write FOnBeforeCertificateValidation;
    property OnAfterCertificateValidation : TSBAfterCertificateValidationEvent read FOnAfterCertificateValidation write FOnAfterCertificateValidation;
    property OnCACertificateNeeded: TSBCACertificateNeededEvent read FOnCACertificateNeeded write FOnCACertificateNeeded;

    property OnAfterCRLUse : TSBAfterCRLUseEvent read FOnAfterCRLUse write FOnAfterCRLUse;
    property OnAfterOCSPResponseUse : TSBAfterOCSPResponseUseEvent read FOnAfterOCSPResponseUse write FOnAfterOCSPResponseUse;
    
    property OnOCSPResponseSignerValid : TSBOCSPResponseSignerValidEvent read FOnOCSPResponseSignerValid write FOnOCSPResponseSignerValid;

    property OnCRLError : TSBCertificateValidatorCRLErrorEvent read FOnCRLError write FOnCRLError;
    property OnOCSPError: TSBCertificateValidatorOCSPErrorEvent read FOnOCSPError write FOnOCSPError;
  end;

procedure Register;

implementation

procedure Register;
begin
  RegisterComponents('PKIBlackbox', [TElX509CertificateValidator]);
end;

constructor TElX509CertificateValidator.Create;
begin
  inherited;
  FTrustedCertificates := TElList.Create;
  FBlockedCertificates := TElList.Create;

  FKnownCertificates := TElList.Create;
  FKnownCRLs := TElList.Create;
  FKnownOCSPResponses := TElList.Create;

  FCheckedCertificates := TElMemoryCertStorage.Create (nil) ;
  FChainCertificates := TElMemoryCertStorage.Create (nil) ;
  FCachedCACertificates := TElMemoryCertStorage.Create (nil) ;

  FUsedCertificates := TElMemoryCertStorage.Create( nil );
  FUsedCRLs := TElMemoryCRLStorage.Create( nil );
  FUsedOCSPResponses := TElList.Create();

  FCRLRetrievers := TElList.Create;
  FOCSPClients := TElList.Create;
  FCertificateRetrievers := TElList.Create;

  FCheckCRL := true;
  FCheckOCSP := true;
  FMandatoryCRLCheck := true;
  FMandatoryOCSPCheck := true;
  FMandatoryRevocationCheck := true;
  FCheckValidityPeriodForTrusted := true;
  FIgnoreCAKeyUsage := false;
  FIgnoreCABasicConstraints := false;
  FIgnoreCANameConstraints := false;
  FIgnoreRevocationKeyUsage := false;
  FIgnoreSSLKeyUsage := false;
  FIgnoreBadOCSPChains := false;
  FValidateInvalidCertificates := false;
  FForceCompleteChainValidationForTrusted := true;
  FForceRevocationCheckForRoot := true;
  FOfflineMode := false;
  FRevocationCheckPreference := rcpCheckBoth;
  FLookupCRLByNameIfDPNotPresent := true;
  {$ifdef SB_HAS_WINCRYPT}
  UseSystemStorages :=  true ;
   {$endif}



  FCRLManager := CRLManagerAddRef;
  FOCSPClientManager := OCSPClientManagerAddRef;
  FCertRetrieverManager := CertificateRetrieverManagerAddRef;

  FValidationStack := TElList.Create;
  FRevocationMomentGracePeriod := 60; // 60 seconds
  FImplicitlyTrustSelfSignedCertificates := false; // this mode (though can be considered as dumb and buggy) is applied when validator is used to only *collect* revocation info (but not *validate*)
  // If the below property is set to true, the component publishes
  // full ('long') OCSP server responses in the created TElOCSPResponse instances.
  // Only BasicOCSPResponse blobs are promoted otherwise. The 'long' mode
  // is particularly used in PAdES components.
  FPromoteLongOCSPResponses := false;
end;

 destructor  TElX509CertificateValidator.Destroy;
begin
  {$ifdef SB_HAS_WINCRYPT}
  FreeAndNil(FWinStorageTrust);
  FreeAndNil(FWinStorageCA);
  FreeAndNil(FWinStorageBlocked);
   {$endif}

  FreeAndNil(FValidationStack);

  DeleteStorages;
  DeleteCRLRetrievers;
  DeleteOCSPClients;
  DeleteCertificateRetrievers;

  ClearUsedValidationInfo();
  FreeAndNil(FUsedCertificates);
  FreeAndNil(FUsedCRLs);
  FreeAndNil(FUsedOCSPResponses);

  CRLManagerRelease;
  OCSPClientManagerRelease;
  CertificateRetrieverManagerRelease;

  inherited;
end;

procedure TElX509CertificateValidator.Notification(AComponent : TComponent; AOperation :
  TOperation);
begin
  inherited;

  if (AComponent is TElCustomCertStorage) and (AOperation = opRemove) then
  begin
    FTrustedCertificates.Remove(AComponent);
    FBlockedCertificates.Remove(AComponent);
    FKnownCertificates.Remove(AComponent);
  end;

  if (AComponent is TElCustomCRLStorage) and (AOperation = opRemove) then
  begin
    FKnownCRLs.Remove(AComponent);
  end;
end;

function TElX509CertificateValidator.CheckIfTrusted(Certificate:
    TElX509Certificate): Boolean;
var SearchResult : integer;
    i : integer;
begin
  result := false;

  for i := 0 to Self.FTrustedCertificates.Count - 1 do
  begin
    SearchResult := FindCertificateInStorage(Certificate, TElCustomCertStorage(FTrustedCertificates[i]));
    if SearchResult > -1 then
    begin
      result := true;
      exit;
    end;
  end;

  SearchResult := FindCertificateInStorage(Certificate, FCheckedCertificates);
  if SearchResult > -1 then
  begin
    result := true;
    exit;
  end;

  {$ifdef SB_HAS_WINCRYPT}
  if FUseSystemStorages and (not FIgnoreSystemTrust) {$ifdef SILVERLIGHT}and SBUtils.ElevatedPermissionsAvailable {$endif} then
  begin
    SearchResult := FindCertificateInStorage(Certificate, FWinStorageTrust);
    if SearchResult > -1 then
    begin
      result := true;
      exit;
    end;
  end;
   {$endif}
end;

{$ifdef SB_HAS_WINCRYPT}
procedure TElX509CertificateValidator.InitializeWinStorages;
begin
  {$ifdef SILVERLIGHT}
  if not SBUtils.ElevatedPermissionsAvailable then
    Exit;
   {$endif}
  if FWinStorageTrust = nil then
  begin
    FWinStorageTrust := TElWinCertStorage.Create (nil) ;
    FWinStorageTrust.ReadOnly := true;
    FWinStorageTrust.SystemStores.BeginUpdate;
    FWinStorageTrust.SystemStores.Add('Root');
    FWinStorageTrust.SystemStores.Add('Trust');
    FWinStorageTrust.SystemStores.Add('TrustedPublisher');
    FWinStorageTrust.SystemStores.Add('AuthRoot');
    FWinStorageTrust.SystemStores.Add('TrustedPeople');
    FWinStorageTrust.SystemStores.EndUpdate;
    FWinStorageTrust.PreloadCertificates;
  end;
  if FWinStorageCA = nil then
  begin
    FWinStorageCA := TElWinCertStorage.Create (nil) ;
    FWinStorageCA.ReadOnly := true;
    FWinStorageCA.SystemStores.BeginUpdate;
    FWinStorageCA.SystemStores.Add('CA');
    FWinStorageCA.SystemStores.Add('UserDS');
    FWinStorageCA.SystemStores.Add('ADDRESSBOOK');
    FWinStorageCA.SystemStores.EndUpdate;
    FWinStorageCA.PreloadCertificates;
  end;
  if FWinStorageBlocked = nil then
  begin
    FWinStorageBlocked := TElWinCertStorage.Create (nil) ;
    FWinStorageBlocked.ReadOnly := true; 
    FWinStorageBlocked.SystemStores.BeginUpdate;
    FWinStorageBlocked.SystemStores.Add('Disallowed');
    FWinStorageBlocked.SystemStores.EndUpdate;
    FWinStorageBlocked.PreloadCertificates;
  end;
end;
 {$endif}

procedure TElX509CertificateValidator.DeleteCRLRetrievers;
var i : integer;
begin
  for i := 0 to FCRLRetrievers.Count -1 do
    TElCustomCRLRetriever(FCRLRetrievers[i]). Free ;
  FreeAndNil(FCRLRetrievers);
end;

procedure TElX509CertificateValidator.DeleteOCSPClients;
var i : integer;
begin
  for i := 0 to FOCSPClients.Count -1 do
    TElOCSPClient(FOCSPClients[i]). Free ;
  FreeAndNil(FOCSPClients);
end;

procedure TElX509CertificateValidator.DeleteCertificateRetrievers;
var i : integer;
begin
  for i := 0 to FCertificateRetrievers.Count -1 do
    TElCustomCertificateRetriever(FCertificateRetrievers[i]). Free ;
  FreeAndNil(FCertificateRetrievers);
end;

procedure TElX509CertificateValidator.DeleteStorages;
begin
  FreeAndNil(FCheckedCertificates);
  FreeAndNil(FChainCertificates);
  FreeAndNil(FCachedCACertificates);

  ClearTrustedCertificates;
  FreeAndNil(FTrustedCertificates);

  ClearKnownCertificates;
  FreeAndNil(FKnownCertificates);

  ClearBlockedCertificates;
  FreeAndNil(FBlockedCertificates);

  ClearKnownCRLs;
  FreeAndNil(FKnownCRLs);

  ClearKnownOCSPResponses;
  FreeAndNil(FKnownOCSPResponses);
end;

procedure TElX509CertificateValidator.AddUsedCertificate(Cert: TElX509Certificate);
begin
  if FUsedCertificates.IndexOf(Cert) < 0 then
    FUsedCertificates.Add(Cert, false);
end;

procedure TElX509CertificateValidator.AddUsedCRL(Crl : TElCertificateRevocationList);
begin
  if FUsedCRLs.IndexOf(Crl) < 0 then
    FUsedCRLs.Add(Crl);
end;

procedure TElX509CertificateValidator.AddUsedOCSPResponse(OcspResp : TElOCSPResponse);
var
  Resp : TElOCSPResponse;
  I : integer;
  Found : boolean;
begin
  Found := false;
  for I := 0 to FUsedOCSPResponses.Count - 1 do
  begin
    if TElOCSPResponse(FUsedOCSPResponses[I]).EqualsTo(OcspResp) then
    begin
      Found := true;
      Break;
    end;
  end;
  if not Found then
  begin
    Resp := TElOCSPResponse.Create();
    Resp.Assign(OcspResp);
    FUsedOCSPResponses.Add(Resp);
  end;
end;

procedure TElX509CertificateValidator.ClearUsedValidationInfo;
var
  I : integer;
begin
  FUsedCertificates.Clear;
  FUsedCRLs.Clear;
  for I := 0 to FUsedOCSPResponses.Count - 1 do
    TElOCSPResponse(FUsedOCSPResponses[I]). Free ;
  FUsedOCSPResponses.Clear;
end;

procedure TElX509CertificateValidator.CheckValidityPeriod(
  Certificate: TElX509Certificate;
  ValidityMoment: TElDateTime;
  var Validity : TSBCertificateValidity;
  var Reason : TSBCertificateValidityReason);
var
  vm : double;
begin
  vm := ValidityMoment;
  if ValidityMoment = 0.0 then
  {$ifdef SB_WINDOWS}
    vm := LocalTimeToUTCTime(now);
   {$else}
    vm := now;
   {$endif}

  {$ifndef SB_NO_NET_DATETIME_OADATE}
  if (Certificate.ValidFrom > vm) then
   {$else}
  if (DateTimeToOADate(Certificate.ValidFrom) > vm) then
   {$endif}
  begin
    Reason := Reason  + [vrNotYetValid] ;
    Validity :=  cvInvalid ;
  end;
  {$ifndef SB_NO_NET_DATETIME_OADATE}
  if (Certificate.ValidTo < vm) then
   {$else}
  if (DateTimeToOADate(Certificate.ValidTo) < vm) then
   {$endif}
  begin
    Reason := Reason  + [vrExpired] ;
    Validity :=  cvInvalid ;
  end;
end;

function TElX509CertificateValidator.CertificateIsBlocked(Certificate : TElX509Certificate) : boolean;
var i : integer;
begin
  result := false;

  for i := 0 to FBlockedCertificates.Count -1 do
  begin
    if FindCertificateInStorage(Certificate, TElCustomCertStorage(FBlockedCertificates[i])) <> -1 then
    begin
      result := true;
      exit;
    end;
  end;

  {$ifdef SB_HAS_WINCRYPT}
  if (FWinStorageBlocked <> nil) and (FindCertificateInStorage(Certificate, FWinStorageBlocked) <> -1) then
  begin
    result := true;
    exit;
  end;
   {$endif}
end;

function TElX509CertificateValidator.FindCA(AdditionalCertificates : TElCustomCertStorage;
  Certificate: TElX509Certificate; var Trusted : TSBBoolean):
    TElX509Certificate;
var
    SearchResult : integer;
    i : integer;
    AIACount : integer;
    AccessDescription : TElAccessDescription;
    GeneralName : TElGeneralName;
    CurrentLocation : string;
    CurrentCertificateRetriever : TElCustomCertificateRetriever;
    RDNConverter : TElRDNConverter;
begin
  Trusted := false;
  result := nil;

  if AdditionalCertificates <> nil then
  begin
    SearchResult := AdditionalCertificates.GetIssuerCertificate(Certificate);
    if SearchResult <> -1 then
    begin
      result := AdditionalCertificates.Certificates[SearchResult];
      exit;
    end;
  end;

  SearchResult := FCheckedCertificates.GetIssuerCertificate(Certificate);
  if SearchResult <> -1 then
  begin
    result := FCheckedCertificates.Certificates[SearchResult];
    Trusted := true;
    exit;
  end;

  SearchResult := FChainCertificates.GetIssuerCertificate(Certificate);
  if SearchResult <> -1 then
  begin
    result := FChainCertificates.Certificates[SearchResult];
    Trusted := true;
    exit;
  end;

  for i := 0 to Self.FTrustedCertificates.Count - 1 do
  begin
    SearchResult := TElCustomCertStorage(FTrustedCertificates[i]).GetIssuerCertificate(Certificate);
    if SearchResult <> -1 then
    begin
      result := TElCustomCertStorage(FTrustedCertificates[i]).Certificates[SearchResult];
      Trusted := true;
      exit;
    end;
  end;

  for i := 0 to Self.FKnownCertificates.Count - 1 do
  begin
    SearchResult := TElCustomCertStorage(FKnownCertificates[i]).GetIssuerCertificate(Certificate);
    if SearchResult <> -1 then
    begin
      result := TElCustomCertStorage(FKnownCertificates[i]).Certificates[SearchResult];
      exit;
    end;
  end;

  SearchResult := FCachedCACertificates.GetIssuerCertificate(Certificate);
  if SearchResult <> -1 then
  begin
    result := FCachedCACertificates.Certificates[SearchResult];
    exit;
  end;

  {$ifdef SB_HAS_WINCRYPT}
  if FUseSystemStorages {$ifdef SILVERLIGHT}and SBUtils.ElevatedPermissionsAvailable {$endif} then
  begin
    SearchResult := FWinStorageTrust.GetIssuerCertificate(Certificate);
    if SearchResult <> -1 then
    begin
      result := FWinStorageTrust.Certificates[SearchResult];
      Trusted := not FIgnoreSystemTrust;
      exit;
    end;
    SearchResult := FWinStorageCA.GetIssuerCertificate(Certificate);
    if SearchResult <> -1 then
    begin
      result := FWinStorageCA.Certificates[SearchResult];
      exit;
    end;
  end;
   {$endif}

  // if we are here, try to download the certificate

  if ceAuthorityInformationAccess in Certificate.Extensions.Included then
  begin
    AIACount := Certificate.Extensions.AuthorityInformationAccess.Count;
    if AIACount > 0 then
    begin
      for i := 0 to AIACount - 1 do
      begin
        AccessDescription := Certificate.Extensions.AuthorityInformationAccess.AccessDescriptions[i];

        if CompareContent(AccessDescription.AccessMethod, SB_OID_ACCESS_METHOD_CAISSUER) then
        begin
          // Here we attempt to retrieve the CRL from one of the locations, listed in the AccessLocation list
          GeneralName := AccessDescription.AccessLocation;
          if GeneralName <> nil then
          begin
            // Get location
            case GeneralName.NameType of
              (*
              Possible values:
              gnRFC822Name, gnDNSName, gnDirectoryName, gnEdiPartyName,
              gnUniformResourceIdentifier, gnIPAddress, gnRegisteredID,
              gnOtherName, gnUnknown, gnPermanentIdentifier
              *)
              gnUniformResourceIdentifier:
                CurrentLocation := GeneralName.UniformResourceIdentifier;
              gnDirectoryName:
              begin
                RDNConverter := TElRDNConverter.Create;
                RDNConverter.Separator := ',';
                RDNConverter.InsertSeparatorPrefix := false;
                try
                  CurrentLocation := RDNConverter.SaveToDNString(GeneralName.DirectoryName);
                finally
                  FreeAndNil(RDNConverter);
                end;
              end
              else
                CurrentLocation := '';
            end; // case

            // Now download the certificate from the server
            if CurrentLocation <> '' then
            begin
              CurrentCertificateRetriever := GetCertificateRetriever(GeneralName.NameType, CurrentLocation);
              TriggerBeforeCertificateRetrieverUse(Certificate, GeneralName.NameType, CurrentLocation, CurrentCertificateRetriever);
              if CurrentCertificateRetriever <> nil then
              begin
                try
                  result := CurrentCertificateRetriever.RetrieveCertificate(Certificate, GeneralName.NameType, CurrentLocation);
                  FCachedCACertificates.Add(result, false);
                except
                  // do nothing as retrieval is not mandatory
                end;
              end;

              if result <> nil then
              begin
                TriggerCACertificateRetrieved(Certificate, GeneralName.NameType, CurrentLocation, Result);
                exit;
              end;
            end; // if CurrentLocation <>
          end; // if GeneralName <> ...
        end;
      end;
    end;
  end;
end;

function TElX509CertificateValidator.FindSignerCertificate(AdditionalCertificates : TElCustomCertStorage;
  Signer: TElRelativeDistinguishedName; SignerKeyIdentifier : ByteArray;
  var Trusted : TSBBoolean): TElX509Certificate;
var
  SearchResult : integer;
  i : integer;
  Lookup : TElCertificateLookup;
begin
  result := nil;
  Trusted := false;
  Lookup := TElCertificateLookup.Create(nil);
  try
    Lookup.SubjectRDN.Assign(Signer);
    Lookup.Criteria :=  [lcSubject] ;
    Lookup.Options :=  [loExactMatch] ;
    if Length(SignerKeyIdentifier) > 0 then
    begin
      Lookup.SubjectKeyIdentifier := SignerKeyIdentifier;
      Lookup.Criteria := Lookup.Criteria   + [lcSubjectKeyIdentifier] ;
      Lookup.Options := Lookup.Options   + [loMatchAll] ;
    end;

    if AdditionalCertificates <> nil then
    begin
      SearchResult := AdditionalCertificates.FindFirst(Lookup);
      if SearchResult <> -1 then
      begin
        result := AdditionalCertificates.Certificates[SearchResult];
        exit;
      end;
    end;

    SearchResult := FCheckedCertificates.FindFirst(Lookup);
    if SearchResult <> -1 then
    begin
      result := FCheckedCertificates.Certificates[SearchResult];
      Trusted := true;
      exit;
    end;

    SearchResult := FChainCertificates.FindFirst(Lookup);
    if SearchResult <> -1 then
    begin
      result := FChainCertificates.Certificates[SearchResult];
      Trusted := true;
      exit;
    end;

    for i := 0 to Self.FTrustedCertificates.Count - 1 do
    begin
      SearchResult := TElCustomCertStorage(FTrustedCertificates[i]).FindFirst(Lookup);
      if SearchResult <> -1 then
      begin
        result := TElCustomCertStorage(FTrustedCertificates[i]).Certificates[SearchResult];
        Trusted := true;
        exit;
      end;
    end;

    {$ifdef SB_HAS_WINCRYPT}
    if FUseSystemStorages {$ifdef SILVERLIGHT}and SBUtils.ElevatedPermissionsAvailable {$endif} then
    begin
      SearchResult := FWinStorageTrust.FindFirst(Lookup);
      if SearchResult <> -1 then
      begin
        result := FWinStorageTrust.Certificates[SearchResult];
        Trusted := not FIgnoreSystemTrust;
        exit;
      end;

      SearchResult := FWinStorageCA.FindFirst(Lookup);
      if SearchResult <> -1 then
      begin
        result := FWinStorageCA.Certificates[SearchResult];
        exit;
      end;
    end;
     {$endif}

    for i := 0 to Self.FKnownCertificates.Count - 1 do
    begin
      SearchResult := TElCustomCertStorage(FKnownCertificates[i]).FindFirst(Lookup);
      if SearchResult <> -1 then
      begin
        result := TElCustomCertStorage(FKnownCertificates[i]).Certificates[SearchResult];
        exit;
      end;
    end;
  finally
    FreeAndNil(Lookup);
  end;
end;

function TElX509CertificateValidator.FindCertificateInStorage(Certificate:
  TElX509Certificate; Storage: TElCustomCertStorage): Integer;
var
  i : integer;
begin
  result := -1;
  for i := 0 to Storage.Count -1 do
  begin
    if Certificate.Equals(Storage.Certificates[i]) then
    begin
      result := i;
      exit;
    end;
  end;
end;

function TElX509CertificateValidator.ValidateCRL(AdditionalCertificates : TElCustomCertStorage;
  CRL : TElCertificateRevocationList;
  ValidityMoment: TElDateTime;
  var Reason : TSBCertificateValidityReason) : boolean;
var
  Signer : TElX509Certificate;
  Trusted: TSBBoolean;
  Validity : TSBCertificateValidity;
begin
  result := false;

  if FValidationStack.IndexOf(CRL) > -1 then
  begin
    Validity := cvStorageError;
    exit;
  end;

  FValidationStack.Add(CRL);
  try

    if crlAuthorityKeyIdentifier in CRL.Extensions.Included then
      Signer := FindSignerCertificate(AdditionalCertificates, CRL.Issuer, CRL.Extensions.AuthorityKeyIdentifier.KeyIdentifier, Trusted)
    else
      Signer := FindSignerCertificate(AdditionalCertificates, CRL.Issuer, EmptyArray, Trusted);

    if Assigned(Signer) then
    begin
      if CRL.Validate(Signer) <> 0 then
        exit;

      if not Trusted then
      begin
        // Checking if we already have the Signer certificate in the validation stack
        // (this may occur if CRL server issues revocation status for itself. There
        // were no such servers encountered live, but OCSP server exposing similar
        // behaviour was noticed with Spanish ACCV CA.
        // We can simply skip the InternalValidate() call for such certificates,
        // as this call has already been made deeper the stack, and therefore
        // there is a guarantee that this certificate will be validated.
        if not CertificatePresentInStack(Signer) then
          // II20120515: ValidityMoment replaced with CRL.ThisUpdate, as we
          // need to establish the validity of the CRL signer at the moment
          // when the CRL was actually signed, not at the initial validation moment.
          // CRL can be signed a while after the validated signature was created,
          // and thus a while after the ValidationMoment passed to the Validate() method.
          InternalValidate(Signer, AdditionalCertificates, false, false, {ValidityMoment}CRL.ThisUpdate, Validity, Reason);
        result := (Validity =  cvOk );
        if result then
        begin
          if  ceKeyUsage in Signer.Extensions.Included  then
          begin
            if (not Signer.Extensions.KeyUsage.CRLSign) and (not FIgnoreRevocationKeyUsage) then
            begin
              Validity :=  cvInvalid ;
              Reason := Reason  + [vrNoKeyUsage] ;
              result := false;
            end;
          end;
        end;
      end
      else
        result := true;
    end;
  finally
    FValidationStack.Remove(CRL);
  end;
end;

procedure TElX509CertificateValidator.PerformCRLCheck(
      AdditionalCertificates : TElCustomCertStorage;
      Certificate: TElX509Certificate;
      CACertificate: TElX509Certificate;
      ValidityMoment: TElDateTime;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason;
      var CrlExistsForCert : TSBBoolean);
var i, idx : integer;
    TempStorage : TElCustomCRLStorage;
    ACRL : TElCertificateRevocationList;
    RevocationItem : TElRevocationItem;
    revoked : boolean;
    CRLFrom : string;
begin
  if FLookupCRLByNameIfDPNotPresent then
    CrlExistsForCert := true
  else
    CrlExistsForCert := ((Certificate.Extensions <> nil) and (Certificate.Extensions.CRLDistributionPoints <> nil) and
      (ceCRLDistributionPoints in Certificate.Extensions.Included));

  TempStorage := TElMemoryCRLStorage.Create (nil) ;
  try
    try
      CRLFrom := RetrieveCRLs(Certificate, CACertificate, TempStorage, ValidityMoment, Reason);
    except
      on E : EElValidationFailedInternalError do
      begin
        Validity :=  cvInvalid ;
        Reason := Reason  + [vrCRLNotVerified] ;
        exit;
      end;
    end;

    for i := 0 to TempStorage.Count - 1 do
    begin
      ACRL := TempStorage.CRLs[i];
      AddUsedCRL(ACRL);
      if ValidateCRL(AdditionalCertificates, ACRL, ValidityMoment, Reason) then
      begin
        try
          idx := ACRL.IndexOf(Certificate);
          if (idx > -1) then
          begin
            RevocationItem := ACRL.Items[idx];

            revoked := true;
            if ( crlReasonCode in RevocationItem.Extensions.Included ) then
            begin
              revoked := (not RevocationItem.Extensions.ReasonCode.RemoveFromCRL) and
                 (RevocationItem.Extensions.ReasonCode.Reason <> rfRemoveFromCRL);
            end;

            if revoked and ((IsEmptyDateTime(ValidityMoment)) or 
            (RevocationItem.RevocationDate <= ValidityMoment)) 
            then
            begin
              TriggerCRLError(Certificate, CRLFrom, nil, SB_VALIDATOR_CRL_ERROR_CERT_REVOKED);
              Validity :=  cvInvalid ;
              Reason := Reason  + [vrRevoked] ;
              break;
            end;
          end;
        finally
          TriggerAfterCRLUse(Certificate, CACertificate, ACRL);
        end;
      end
      else
      begin
        TriggerCRLError(Certificate, CRLFrom, nil, SB_VALIDATOR_CRL_ERROR_VALIDATION_FAILED);
        Reason := Reason  + [vrCRLNotVerified] ;
        if MandatoryCRLCheck then
        begin
          Validity :=  cvInvalid ;
          break;
        end;
      end;
    end; // for
  finally
    FreeAndNil(TempStorage);
  end;
end;

function TElX509CertificateValidator.CertificatePresentInStack(Cert: TElX509Certificate): boolean;
var
  I : integer;
begin
  Result := false;
  for I := 0 to FValidationStack.Count - 1 do
    if (TObject(FValidationStack[I]) is TElX509Certificate) then
    begin
      if TElX509Certificate(FValidationStack[I]).Equals(Cert) then
      begin
        Result := true;
        Break;
      end;
    end;
end;

function TElX509CertificateValidator.ValidateOCSP(AdditionalCertificates : TElCustomCertStorage;
  Certificate: TElX509Certificate;
  CACertificate: TElX509Certificate;
  Response : TElOCSPResponse;
  ValidityMoment: TElDateTime;
  var Reason : TSBCertificateValidityReason) : boolean;
var Signer : TElX509Certificate;
    Validity : TSBCertificateValidity;
    DedicatedOCSPCert : boolean;
    NameMatch,
    KeyMatch,
    KeyIDMatch : boolean;
    SignersCA : TElX509Certificate;
    Trusted : TSBBoolean;
    SignersKeyBlob,
    CAKeyBlob : ByteArray;
begin
  result := false;

  if FValidationStack.IndexOf(Response) > -1 then
  begin
    Validity := cvStorageError;
    exit;
  end;

  FValidationStack.Add(Response);
  try
    if Response.IsSignerCertificate(CACertificate) then
    begin
      Signer := CACertificate;
      DedicatedOCSPCert := false;
    end
    else
    begin
      Signer := Response.GetSignerCertificate;
      if signer <> nil then
      begin
        NameMatch := CompareRDN(Signer.IssuerRDN, CACertificate.SubjectRDN) or CompareRDN(Signer.IssuerRDN, CACertificate.IssuerRDN);
        KeyIDMatch := false;
        KeyMatch := false;
        if not NameMatch then
        begin
          KeyMatch := false;

          SignersCA := Self.FindCA(AdditionalCertificates, Signer, Trusted);
          if (SignersCA = nil) and (Response.Certificates.Count > 1) then
            SignersCA := Self.FindCA(Response.Certificates, Signer, Trusted);
            
          if (SignersCA <> nil) and (CACertificate <> nil) then
          begin
            SignersCA.GetPublicKeyBlob(SignersKeyBlob);
            CACertificate.GetPublicKeyBlob(CAKeyBlob);
            KeyMatch := CompareMem(SignersKeyBlob, CAKeyBlob);
            ReleaseArray(SignersKeyBlob);
            ReleaseArray(CAKeyBlob);
          end;

          if not KeyMatch then
          begin
            KeyIDMatch :=
              ( ceAuthorityKeyIdentifier in Signer.Extensions.Included ) and
              ( ceSubjectKeyIdentifier in CACertificate.Extensions.Included ) and
              (CompareContent(Signer.Extensions.AuthorityKeyIdentifier.Value, CACertificate.Extensions.SubjectKeyIdentifier.Value));
          end;
        end;

        if not (KeyIDMatch or KeyMatch or NameMatch) then
        begin
          NameMatch := false;
          TriggerOCSPResponseSignerValid(Certificate, CACertificate, Response, Signer, NameMatch);
          if not NameMatch then
            Signer := nil;
        end;
      end;
      DedicatedOCSPCert := true;
    end;

    if Signer <> nil then
    begin
      if Response.Validate(Signer) <> csvValid then
        exit;

      if not CheckIfTrusted(Signer) then
      begin
        // Checking if we already have the Signer certificate in the validation stack
        // (this may occur if OCSP server issues revocation status for itself,
        // like some CAs (e.g. Spanish ACCV CA) do).
        // We can simply skip the InternalValidate() call for such certificates,
        // as this call has already been made deeper the stack, and therefore
        // there is a guarantee that this certificate will be validated.
        if not CertificatePresentInStack(Signer) then
          // II20120515: ValidityMoment replaced with Response.ProducedAt, as we
          // need to establish the validity of the OCSP signer at the moment
          // when the OCSP response was actually signed, not at the initial validation moment.
          // OCSP response can be signed a while after the validated signature was created,
          // and thus a while after the ValidationMoment passed to the Validate() method.
          InternalValidate(Signer, AdditionalCertificates, false, false, {ValidityMoment}Response.ProducedAt, Validity, Reason);
        result := (Validity =  cvOk );
        if result then
        begin
          if DedicatedOCSPCert then
          begin
            if  ceKeyUsage in Signer.Extensions.Included  then
            begin
              if (not Signer.Extensions.KeyUsage.DigitalSignature) and (not Signer.Extensions.KeyUsage.NonRepudiation) and (not FIgnoreRevocationKeyUsage) then
              begin
                Validity :=  cvInvalid ;
                Reason := Reason  + [vrNoKeyUsage] ;
                result := false;
              end;
            end;

            if  ceExtendedKeyUsage in Signer.Extensions.Included  then
            begin
              if (not Signer.Extensions.ExtendedKeyUsage.OCSPSigning) and (not FIgnoreRevocationKeyUsage) then
              begin
                Validity :=  cvInvalid ;
                Reason := Reason  + [vrNoKeyUsage] ;
                result := false;
              end;
            end;
          end;
        end;
      end
      else
        result := true;
    end;
  finally
    FValidationStack.Remove(Response);
  end;
end;

procedure TElX509CertificateValidator.CheckOCSPResponse(Response : TElOCSPResponse;
  AdditionalCertificates : TElCustomCertStorage;
  Certificate: TElX509Certificate;
  CACertificate: TElX509Certificate;
  ValidityMoment: TElDateTime;
  var Found : TSBBoolean;
  var Validity : TSBCertificateValidity;
  var Reason: TSBCertificateValidityReason);

var SingleResponse : TElOCSPSingleResponse;
    index : integer;
begin
  // check certificate status
  index := Response.FindResponse(Certificate, CACertificate);
  Found := (index <> -1);
  if Found then
  begin
    AddUsedOCSPResponse(Response);
    if not ValidateOCSP(AdditionalCertificates, Certificate, CACertificate, Response, ValidityMoment, Reason) then
    begin
      TriggerOCSPError(Certificate, '', nil, SB_VALIDATOR_OCSP_ERROR_VALIDATION_FAILED);
      Validity :=  cvInvalid ;
      Reason := Reason  + [vrOCSPNotVerified] ;
    end;

    SingleResponse := Response.Responses[index];
    if (SingleResponse.CertStatus <> csGood) then
    begin
      if (SingleResponse.CertStatus <> csRevoked) or ((IsEmptyDateTime(ValidityMoment)) or 
      (SingleResponse.RevocationTime <= ValidityMoment)) 
      then
      begin
        TriggerOCSPError(Certificate, '', nil, SB_VALIDATOR_OCSP_ERROR_CERT_REVOKED);
        Validity :=  cvInvalid ;
        Reason := Reason  + [vrRevoked] ;
      end;
    end;
  end;
end;


function TElX509CertificateValidator.FindMatchingOCSP(Certificate :
    TElX509Certificate; CACertificate : TElX509Certificate; OCSPResponses :
    TElList; ValidityMoment: TElDateTime): TElOCSPResponse;
var i, idx : integer;
    Response : TElOCSPResponse;
    SignerCert: TElX509Certificate;
    SingleResp : TElOCSPSingleResponse;
    ThisUpdate, NextUpdate : TElDateTime;
begin
  // TODO:
  result := nil;
  for i := 0 to OCSPResponses.Count - 1 do
  begin
    Response := TElOCSPResponse(OCSPResponses[i]);
    SignerCert := Response.GetSignerCertificate;
    if not Assigned(SignerCert) then
      Continue;
      
    idx := Response.FindResponse(Certificate, CACertificate);
    if idx <> -1 then
      SingleResp := Response.Responses[idx]
    else
      SingleResp := nil;
    if SingleResp <> nil then
    begin
      NextUpdate := SingleResp.NextUpdate;
      ThisUpdate := SingleResp.ThisUpdate;
      if (CACertificate.Equals(SignerCert) or
          ((CompareRDN(SignerCert.IssuerRDN, CACertificate.SubjectRDN) or (FIgnoreBadOCSPChains)) and
           (ceExtendedKeyUsage in SignerCert.Extensions.Included) and
           SignerCert.Extensions.ExtendedKeyUsage.OCSPSigning and
           (SignerCert.Extensions.ExtendedKeyUsage.TotalUsageCount = 1)
          )
         )
         and
         (
           // There are three possible relationships between validation moment and OCSP response times:
           // a) response is issued after the validation moment + delta (OK for us)
           (ThisUpdate >  ValidityMoment - FRevocationMomentGracePeriod / SecsPerDay ) or
           
           // b) response is issued before the validation moment and next update is set
           ((NextUpdate <>  0 ) and (ValidityMoment >= ThisUpdate) and (ValidityMoment <= NextUpdate)) or

           // c) response is issued before the validation moment and next update is not set
           ((NextUpdate =  0 ) and (ValidityMoment >= ThisUpdate) and (ValidityMoment <  ThisUpdate + FRevocationMomentGracePeriod / SecsPerDay ))
         ) then
      begin
        result := Response;
        exit;
      end;
    end;
  end;
end;


procedure TElX509CertificateValidator.PerformOCSPCheck(
      AdditionalCertificates : TElCustomCertStorage;
      Certificate: TElX509Certificate;
      CACertificate: TElX509Certificate;
      ValidityMoment: TElDateTime;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason;
      var OcspExistsForCert : TSBBoolean);

var CurrentOCSPClient : TElOCSPClient;
    RequestResult, i : integer;
    AccessDescription : TElAccessDescription;
    OCSPLocation : string;
    OCSPGot      : boolean;
    ServerResult : TElOCSPServerError;
    Reply        : ByteArray;
    Stg,
    CAStg        : TElMemoryCertStorage;
    Found        : TSBBoolean;
    Response     : TElOCSPResponse;
begin
  OcspExistsForCert := false;

  Reply := EmptyArray;

  Response := FindMatchingOCSP(Certificate, CACertificate, FKnownOCSPResponses, ValidityMoment);

  if Response <> nil then
  begin
    CheckOCSPResponse(Response, AdditionalCertificates, Certificate, CACertificate, ValidityMoment, Found, Validity, Reason);
    TriggerAfterOCSPResponseUse(Certificate, CACertificate, Response);
    OcspExistsForCert := true;
  end
  else
  begin
    if (Certificate.Extensions <> nil) and (Certificate.Extensions.AuthorityInformationAccess <> nil) and
      (ceAuthorityInformationAccess in Certificate.Extensions.Included)
      and (Certificate.Extensions.AuthorityInformationAccess.Count > 0)
    then
    begin
      OCSPGot := true;

      for i := 0 to Certificate.Extensions.AuthorityInformationAccess.Count -1 do
      begin
        AccessDescription := Certificate.Extensions.AuthorityInformationAccess.AccessDescriptions[i];

        if CompareContent(AccessDescription.AccessMethod, SB_OID_ACCESS_METHOD_OCSP) then
        begin
          OcspExistsForCert := true;

          OCSPGot := false;

          OCSPLocation := AccessDescription.AccessLocation.UniformResourceIdentifier;

          CurrentOCSPClient := GetOCSPClient(OCSPLocation);
          TriggerBeforeOCSPClientUse(Certificate, CACertificate, OCSPLocation, CurrentOCSPClient);
          if (CurrentOCSPClient <> nil) then
          begin
            CurrentOCSPClient.URL := OCSPLocation;

            Stg := TElMemoryCertStorage.Create (nil) ;
            try
              CAStg := TElMemoryCertStorage.Create (nil) ;
              try
                // prepare the client for request
                Stg.Add(Certificate, false);
                CAStg.Add(CACertificate, false);
                CurrentOCSPClient.CertStorage := Stg;
                CurrentOCSPClient.IssuerCertStorage := CAStg;

                //CurrentOCSPClient.Nonce := SBUtils.GenerateGUID;

                // perform request
                try
                  RequestResult := CurrentOCSPClient.PerformRequest(ServerResult, Reply);
                except
                  // set result to error to skip next IF code block
                  TriggerOCSPError(Certificate, OCSPLocation, CurrentOCSPClient, SB_VALIDATOR_OCSP_ERROR_CLIENT_FAILED);
                  RequestResult := SB_OCSP_ERROR_NO_REPLY;
                end;

                if (RequestResult = 0) and (ServerResult = oseSuccessful) then
                begin
                  Response := TElOCSPResponse.Create();
                  try
                    if not FPromoteLongOCSPResponses then
                      Response.Assign(CurrentOCSPClient.Response)
                    else
                      Response.Load(@Reply[0], Length(Reply));

                    CheckOCSPResponse(Response, AdditionalCertificates, Certificate, CACertificate, ValidityMoment, Found, Validity, Reason);
                    if not Found then
                    begin
                      TriggerOCSPError(Certificate, OCSPLocation, CurrentOCSPClient, SB_VALIDATOR_OCSP_ERROR_INVALID_RESPONSE);
                      Validity :=  cvInvalid ;
                      Reason := Reason  + [vrOCSPNotVerified] ;
                    end;
                    TriggerAfterOCSPResponseUse(Certificate, CACertificate, Response);
                    if Validity = cvInvalid then
                      exit;
                    OCSPGot := true;
                  finally
                    FreeAndNil(Response);
                  end;
                end
                else
                  TriggerOCSPError(Certificate, OCSPLocation, CurrentOCSPClient, SB_VALIDATOR_OCSP_ERROR_CLIENT_FAILED);
              finally
                FreeAndNil(CAStg);
              end;
            finally
              FreeAndNil(Stg);
            end;
          end
          else
            TriggerOCSPError(Certificate, OCSPLocation, CurrentOCSPClient, SB_VALIDATOR_OCSP_ERROR_NO_CLIENT);
        end;
      end;

      if (not OCSPGot) then
      begin
        TriggerOCSPError(Certificate, OCSPLocation, CurrentOCSPClient, SB_VALIDATOR_OCSP_ERROR_INVALID_RESPONSE);
        Reason := Reason  + [vrOCSPNotVerified] ;
        if MandatoryOCSPCheck then
          Validity := cvInvalid;
      end;
    end;
  end;
end;

function TElX509CertificateValidator.FindMatchingCRL(Certificate : TElX509Certificate;
  DistributionPoint : TElDistributionPoint;
  Storage : TElCustomCRLStorage;
  ValidityMoment: TElDateTime) : TElCertificateRevocationList;
var i, k : integer;
    ExtnsOK : boolean;
    TempStorage : TElList;
    ACRL : TElCertificateRevocationList;
begin
  TempStorage := TElList.Create;
  try
    Result := nil;
    Storage.FindMatchingCRLs(Certificate, DistributionPoint, TempStorage);
    for i := 0 to TempStorage.Count - 1 do
    begin
      ACRL := TElCertificateRevocationList(TempStorage[i]);
	  // ensuring that the CRL does not contain any unknown critical extensions (as any unknown extension may potentially reduce the scope of the CRL)
	  ExtnsOK := true;
	  for k := 0 to ACRL.Extensions.OtherCount - 1 do
	    if ACRL.Extensions.OtherExtensions[k].Critical then
		begin
		  ExtnsOK := false;
		  Break;
		end;
	  if not ExtnsOK then
	    Continue;
      if (Result = nil) then
        Result := ACRL
      else
      if (ACRL.ThisUpdate <= ValidityMoment) and (ACRL.NextUpdate >= ValidityMoment) then
      begin
        Result := ACRL;
        exit;
      end
      else
      begin
        if Result.NextUpdate < ACRL.NextUpdate then
          Result := ACRL;
      end;
    end;
  finally
    FreeAndNil(TempStorage);
  end;
end;

procedure TElX509CertificateValidator.SetupImplicitDP(Certificate : TElX509Certificate; DP : TElDistributionPoint);
var
  I : integer;
begin
  DP.Included :=  [dppName] ;
  DP.Name.Clear;
  DP.Name.Add();
  DP.Name.Names[0].NameType := gnDirectoryName;
  DP.Name.Names[0].DirectoryName.Assign(Certificate.IssuerRDN);
  if ceIssuerAlternativeName in Certificate.Extensions.Included then
  begin
    for I := 0 to Certificate.Extensions.IssuerAlternativeName.Content.Count - 1 do
    begin
      DP.Name.Add();
      DP.Name.Names[I + 1].Assign(Certificate.Extensions.IssuerAlternativeName.Content.Names[I]);
    end;
  end;
end;

function TElX509CertificateValidator.RetrieveCRLs(
    Certificate   : TElX509Certificate;
    CACertificate : TElX509Certificate;
    Storage       : TElCustomCRLStorage;
    ValidityMoment: TElDateTime;
    var Reason: TSBCertificateValidityReason) : string;
var CurrentCRLRetriever : TElCustomCRLRetriever;
    DistributionPoint, ImplicitDP : TElDistributionPoint;
    GeneralName : TElGeneralName;
    DPC : integer; // Distribution Point counter
    NC  : integer; // Name counter
    i   : integer;
    PointGot : boolean;
    CurrentLocation : string;
    CRLSource : TElGeneralNames;
    ACRL  : TElCertificateRevocationList;
    PointCount  : integer;
    TempStorage : TElCustomCRLStorage;
    RDNConverter : TElRDNConverter;
    ImplicitDPModifier : integer;
    //IssuerName  : TElRelativeDistinguishedName;
    //NameIdx : integer;
begin
  result := '';

  TempStorage := TElMemoryCRLStorage.Create (nil) ;
  ImplicitDP := TElDistributionPoint.Create();
  try
    CurrentCRLRetriever := nil;

    // We are using one extra 'artificial' implicit distribution point here
    // to comply to RFC5280 p6.3.3:
    //
    // "If the revocation status has not been determined, repeat the process
    // above with any available CRLs not specified in a distribution point
    // but issued by the certificate issuer. For the processing of such a
    // CRL, assume a DP with both the reasons and the cRLIssuer fields
    // omitted and a distribution point name of the certificate issuer.
    // That is, the sequence of names in fullName is generated from the
    // certificate issuer field as well as the certificate issuerAltName
    // extension."
    if
      (ceCRLDistributionPoints in Certificate.Extensions.Included)
        then
      PointCount := Certificate.Extensions.CRLDistributionPoints.Count
    else
      PointCount := 0;

    if FLookupCRLByNameIfDPNotPresent then
    begin
      SetupImplicitDP(Certificate, ImplicitDP);
      ImplicitDPModifier := 1;
    end
    else
      ImplicitDPModifier := 0;

    // iterate through all CRL locations saved in the certificate
    for DPC := 0 to PointCount - 1 + ImplicitDPModifier do // Note that we might need to iterate over PointCount PLUS ONE points to cater for the 'artifical' point (see above)
    begin
      if DPC < PointCount then
        DistributionPoint := Certificate.Extensions.CRLDistributionPoints.DistributionPoints[DPC]
      else
        DistributionPoint := ImplicitDP;

      if DistributionPoint <> nil then
      begin
        // choose where to take the CRLs from, as described in RFC 3280, section 4.2.1.14
        if (DistributionPoint.Name <> nil) and (DistributionPoint.Name.Count > 0) then
        begin
          CRLSource := DistributionPoint.Name;
        end
        else if (DistributionPoint.CRLIssuer <> nil) and (DistributionPoint.CRLIssuer.Count > 0) then
        begin
          CRLSource := DistributionPoint.CRLIssuer;
        end
        else
          CRLSource := nil;

        if CRLSource <> nil then
        begin
          PointGot := false;
          NC := 0;

          // Here we attempt to retrieve the CRL from one of the locations, listed in the DistributionPoint list
          while NC < CRLSource.Count do
          begin
            GeneralName := CRLSource.Names[NC];
            if GeneralName <> nil then
            begin
              // check presense of the CRL in the global cache first, as it is fresher
              FCRLManager.PurgeExpiredCRLs();
              ACRL := FindMatchingCRL(Certificate, DistributionPoint, FCRLManager.CRLCache, ValidityMoment);

              // If CRLCache is not enabled, we need to check previously loaded CRLs
              if not Assigned(ACRL) and not FCRLManager.CRLCache.Enabled then
                ACRL := FindMatchingCRL(Certificate, DistributionPoint, Storage, ValidityMoment);

              // if not found, look in known CRLs list
              if ACRL = nil then
              begin
                for i := 0 to FKnownCRLs.Count - 1 do
                begin
                  ACRL := FindMatchingCRL(Certificate, DistributionPoint, TElCustomCRLStorage(FKnownCRLs[i]), ValidityMoment);
                  if ACRL <> nil then
                    break;
                end;
              end;

              if (ACRL = nil) or
              (ACRL.NextUpdate < ValidityMoment)
              then
              begin
                // Get location
                case GeneralName.NameType of
                  (*
                  Possible values:
                  gnRFC822Name, gnDNSName, gnDirectoryName, gnEdiPartyName,
                  gnUniformResourceIdentifier, gnIPAddress, gnRegisteredID,
                  gnOtherName, gnUnknown, gnPermanentIdentifier
                  *)
                  gnUniformResourceIdentifier:
                    CurrentLocation := GeneralName.UniformResourceIdentifier;
                  gnDirectoryName:
                  begin
                    RDNConverter := TElRDNConverter.Create;
                    RDNConverter.Separator := ',';
                    RDNConverter.InsertSeparatorPrefix := false;
                    try
                      CurrentLocation := RDNConverter.SaveToDNString(GeneralName.DirectoryName);
                    finally
                      FreeAndNil(RDNConverter);
                    end;
                  end
                  else
                    CurrentLocation := '';
                end; // case

                // Now download the CRL from the server
                if CurrentLocation <> '' then
                begin
                  result := CurrentLocation;
                  CurrentCRLRetriever := GetCRLRetriever(GeneralName.NameType, CurrentLocation);
                  TriggerBeforeCRLRetrieverUse(Certificate, CACertificate, GeneralName.NameType, CurrentLocation, CurrentCRLRetriever);
                  if CurrentCRLRetriever <> nil then
                  begin
                    try
                      ACRL := CurrentCRLRetriever.GetCRL(Certificate, CACertificate, GeneralName.NameType, CurrentLocation);
                    except
                      ACRL := nil;
                      TriggerCRLError(Certificate, CurrentLocation, CurrentCRLRetriever, SB_VALIDATOR_CRL_ERROR_RETRIEVER_FAILED);
                      Reason := Reason  + [vrCRLNotVerified] ;
                    end;
                  end
                  else
                  begin
                    ACRL := nil;
                    TriggerCRLError(Certificate, CurrentLocation, nil, SB_VALIDATOR_CRL_ERROR_NO_RETRIEVER);
                    Reason := Reason  + [vrCRLNotVerified] ;
                  end;

                  if ACRL <> nil then
                  begin
                    TriggerCRLRetrieved(Certificate, CACertificate, GeneralName.NameType, CurrentLocation, ACRL);
                    FCRLManager.CRLCache.Add(ACRL); // add the downloaded CRL to the cache
                    Storage.Add(ACRL);
                    //FreeAndNil(ACRL);
                    PointGot := true;
                    break;
                  end
                  else
                    result := ''; // if
                end; // if CurrentLocation <>
              end
              else
              begin
                Storage.Add(ACRL);
                PointGot := true;
                break;
              end; // if ACRL = nil
              inc(NC);
            end; // if GeneralName <> ...
          end; // while NC < ...
          if (not PointGot) and MandatoryCRLCheck and
             (DPC < PointCount) then // ignore retrieval failure for 'artificial' implicit distribution point
          begin
            result := '';
            TriggerCRLError(Certificate, '', nil, SB_VALIDATOR_CRL_ERROR_NO_CRLS_RETRIEVED);
            raise EElValidationFailedInternalError.Create('CRL Retrieval failed from ' + CurrentLocation);
          end;
        end; // if CRLSource <> ...
      end; // if DistributionPoint <> ...
    end; // for

    // if we failed to obtain any CRLs, ask the caller about them
    if Storage.Count = 0 then
    begin
      TriggerCRLNeeded(Certificate, CACertificate, TempStorage);
      for i := 0 to TempStorage.Count -1 do
        Storage.Add(TempStorage.CRLs[i]);
    end;
  finally
    FreeAndNil(TempStorage);
    FreeAndNil(ImplicitDP);
  end;
end;

procedure TElX509CertificateValidator.TriggerBeforeValidation(Certificate : TElX509Certificate);
begin
  if Assigned(FOnBeforeCertificateValidation) then
    FOnBeforeCertificateValidation(Self, Certificate);
end;

procedure TElX509CertificateValidator.TriggerAfterValidation(
      Certificate : TElX509Certificate;
      CACertificate : TElX509Certificate;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason;
      var DoContinue : TSBBoolean);
begin
  if assigned(FOnAfterCertificateValidation) then
    FOnAfterCertificateValidation(Self, Certificate, CACertificate, Validity, Reason, DoContinue);
end;

procedure TElX509CertificateValidator.TriggerBeforeOCSPClientUse(
      Certificate : TElX509Certificate;
      CACertificate : TElX509Certificate;
      const OCSPLocation : string;
      var Client: TElOCSPClient);
begin
  if assigned(FOnBeforeOCSPClientUse) then
    FOnBeforeOCSPClientUse(Self, Certificate, CACertificate, OCSPLocation, Client);
end;

procedure TElX509CertificateValidator.TriggerBeforeCertificateRetrieverUse(
    Certificate : TElX509Certificate;
    NameType : TSBGeneralName;
    const Location : string;
    var Retriever: TElCustomCertificateRetriever);
begin
  if assigned(FOnBeforeCertificateRetrieverUse) then
    FOnBeforeCertificateRetrieverUse(Self, Certificate, NameType, Location, Retriever);
end;


procedure TElX509CertificateValidator.TriggerBeforeCRLRetrieverUse(
    Certificate : TElX509Certificate;
    CACertificate : TElX509Certificate;
    NameType : TSBGeneralName;
    const Location : string;
    var Retriever: TElCustomCRLRetriever);
begin
  if assigned(FOnBeforeCRLRetrieverUse) then
    FOnBeforeCRLRetrieverUse(Self, Certificate, CACertificate, NameType, Location, Retriever);
end;

procedure TElX509CertificateValidator.TriggerCRLNeeded(Certificate, CACertificate : TElX509Certificate; var CRLs : TElCustomCRLStorage);
begin
  if Assigned(FOnCRLNeeded) then
    FOnCRLNeeded(Self, Certificate, CACertificate, CRLs);
end;

procedure TElX509CertificateValidator.TriggerCRLRetrieved(Certificate, CACertificate : TElX509Certificate;
    NameType : TSBGeneralName; const Location : string; CRL : TElCertificaterevocationList);
begin
  if Assigned(FOnCRLRetrieved) then
    FOnCRLRetrieved(Self, Certificate, CACertificate, NameType, Location, CRL);
end;

procedure TElX509CertificateValidator.TriggerCACertificateRetrieved(Certificate : TElX509Certificate;
    NameType : TSBGeneralName; const Location : string; CACertificate : TElX509Certificate);
begin
  if Assigned(FOnCACertificateRetrieved) then
    FOnCACertificateRetrieved(Self, Certificate, NameType, Location, CACertificate);
end;

procedure TElX509CertificateValidator.TriggerCACertificateNeeded(Certificate:
    TElX509Certificate; var CACertificate: TElX509Certificate);
begin
  CACertificate := nil;
  if Assigned(FOnCACertificateNeeded) then
    FOnCACertificateNeeded(Self, Certificate, CACertificate);
end;

procedure TElX509CertificateValidator.TriggerAfterCRLUse(Certificate, CACertificate : TElX509Certificate; CRL : TElCertificaterevocationList);
begin
  if assigned(FOnAfterCRLUse) then
    FOnAfterCRLUse(Self, Certificate, CACertificate, CRL);
end;

procedure TElX509CertificateValidator.TriggerAfterOCSPResponseUse(Certificate, CACertificate : TElX509Certificate; Response : TElOCSPResponse);
begin
  if assigned(FOnAfterOCSPResponseUse) then
    FOnAfterOCSPResponseUse(Self, Certificate, CACertificate, Response);
end;

procedure TElX509CertificateValidator.TriggerCRLError(Certificate : TElX509Certificate; const Location : string;
  Retriever : TElCustomCRLRetriever; ErrorCode : integer);
begin
  if assigned(FOnCRLError) then
    FOnCRLError(Self, Certificate, Location, Retriever, ErrorCode);
end;

procedure TElX509CertificateValidator.TriggerOCSPError(Certificate : TElX509Certificate; const Location : string;
  Client : TElOCSPClient; ErrorCode : integer);
begin
  if assigned(FOnOCSPError) then
    FOnOCSPError(Self, Certificate, Location, Client, ErrorCode);
end;

procedure TElX509CertificateValidator.TriggerOCSPResponseSignerValid(Certificate, CACertificate : TElX509Certificate;
      Response : TElOCSPResponse; SignerCertificate : TElX509Certificate; var SignerValid : boolean);
begin
  if assigned (FOnOCSPResponseSignerValid) then
    FOnOCSPResponseSignerValid(Self, Certificate, CACertificate, Response, SignerCertificate, SignerValid); 
end;

procedure TElX509CertificateValidator.Validate(Certificate: TElX509Certificate;
    var Validity : TSBCertificateValidity;
    var Reason: TSBCertificateValidityReason
     );
begin
  Validate(Certificate, nil, false, false, UtcNow, Validity, Reason);
end;

procedure TElX509CertificateValidator.Validate(Certificate: TElX509Certificate;
      AdditionalCertificates : TElCustomCertStorage;
      CompleteChainValidation : boolean;
      ResetCertificateCache : boolean;
      ValidityMoment: TElDateTime;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason
       );
begin
  {$ifdef SB_HAS_WINCRYPT}
  // we initialize the storages only before actual use
  if UseSystemStorages {$ifdef SILVERLIGHT}and SBUtils.ElevatedPermissionsAvailable {$endif} then
    InitializeWinStorages;
   {$endif}

  Validity := cvOk;
  Reason :=  [] ;
  FChainCertificates.Clear;
  ClearUsedValidationInfo;
  InternalValidate(Certificate, AdditionalCertificates, CompleteChainValidation, ResetCertificateCache, ValidityMoment,
    Validity, Reason);
end;


procedure TElX509CertificateValidator.InternalValidate(Certificate: TElX509Certificate;
      AdditionalCertificates : TElCustomCertStorage;
      CompleteChainValidation : boolean;
      ResetCertificateCache : boolean;
      ValidityMoment: TElDateTime;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason);
var CurrentCertificate : TElX509Certificate;
    CACertificate      : TElX509Certificate;
    Trusted            : TSBBoolean;
    SkipCheck          : boolean;
    DoContinue         : TSBBoolean;
    CAValidity         : TSBCertificateValidity;
    CAReason           : TSBCertificateValidityReason;
    CrlExists,
    OcspExists         : TSBBoolean;
	ExtnsOK            : boolean;
	CurrPathLen        : integer;
	AltName            : TElGeneralNames;
begin

  if ResetCertificateCache then
    FCheckedCertificates.Clear;

  CurrPathLen := 0;

(*

Sequence of operations:

- Check certificate time validity
- Check if the certificate is found in trusted certificates
- Find the issuer
- Check certificate signature
- Check certificate revocation via CRL
  - Check CRL in the cache
  - Check CRLRetriever
  - Check in the CRL
- Check certificate revocation via OCSP
- fire the post-validation event

*)

  if Certificate = nil then
  begin
    Validity := cvStorageError;
    exit;
  end;

  if FValidationStack.IndexOf(Certificate) > -1 then
  begin
    Validity := cvStorageError;
    exit;
  end;

  FValidationStack.Add(Certificate);
  try
    CurrentCertificate := Certificate;

    if Certificate.Chain <> nil then
      FChainCertificates.ImportFrom(Certificate.Chain, false);

    while CurrentCertificate <> nil do
    begin
      TriggerBeforeValidation(CurrentCertificate);

      AddUsedCertificate(CurrentCertificate);

      CAValidity :=  cvOk ;
      CAReason :=   [] ;

      SkipCheck := false;

      // Check if the certificate is blocked (i.e. explicitly declared as not trusted / valid
      if CertificateIsBlocked(CurrentCertificate) then
      begin
        CAValidity :=  cvInvalid ;
        CAReason := CAReason  + [vrBlocked] ;
        if not FValidateInvalidCertificates then
          SkipCheck := true;
      end;

      // Check if the certificate is trusted
      if not SkipCheck then
        Trusted := CheckIfTrusted(CurrentCertificate);

      if (not SkipCheck) and ((not Trusted) or CheckValidityPeriodForTrusted) then
      begin
        // Check certificate time validity
        CheckValidityPeriod(CurrentCertificate, ValidityMoment, CAValidity, CAReason);

        if (Trusted) and (CAValidity =  cvOk )
          and (not FForceCompleteChainValidationForTrusted) then
          SkipCheck := true; // the certificate is trusted and there's nothing more to check
      end
      else if (not FForceCompleteChainValidationForTrusted) then
        SkipCheck := true; // the certificate is trusted and there's nothing more to check

      if (CAValidity =  cvInvalid ) and (not FValidateInvalidCertificates) then
        SkipCheck := true;

      // Find the issuer
      if CurrentCertificate.SelfSigned or ((Trusted) and (not FForceCompleteChainValidationForTrusted)) then
        CACertificate := nil
      else
      begin
        CACertificate := FindCA(AdditionalCertificates, CurrentCertificate, Trusted);

        if (CACertificate = nil) then
        begin
          TriggerCACertificateNeeded(CurrentCertificate, CACertificate);
          if (CACertificate <> nil) then
            FCachedCACertificates.Add(CACertificate, false);
        end;
      end;

      if not SkipCheck then
      begin
        // Check certificate integrity
        if (CurrentCertificate.SelfSigned) then
        begin
          CACertificate := CurrentCertificate; // this setting is needed for further CRL/OCSP check

          if not CurrentCertificate.Validate then
          begin
            CAReason := CAReason  + [vrInvalidSignature] ;
            CAValidity :=  cvInvalid ;
          end
          else
          begin
            if Trusted then
              CAValidity :=  cvOk 
            else
              CAValidity :=  cvSelfSigned ;
          end;

          // special handling in ImplicitlyTrustSelfSignedCertificates mode
          if FImplicitlyTrustSelfSignedCertificates and (CAValidity = cvSelfSigned) then
            CAValidity := cvOk; 
        end
        else
        begin
          if (CACertificate = nil) then
          begin
            CAValidity :=  cvInvalid ;
            CAReason := CAReason  + [vrUnknownCA] ;
          end
          else
          begin
            CAReason := CAReason  - [vrUnknownCA] ;

            // Checking CA certificate for conformance:
            ExtnsOK := true;

            // - basic constraints
            if (not IgnoreCABasicConstraints) and (CACertificate.Version >= 3) then
            begin
              if not (( (ceBasicConstraints in CACertificate.Extensions.Included) ) and (CACertificate.Extensions.BasicConstraints.Critical) and (CACertificate.Extensions.BasicConstraints.CA)) then
                ExtnsOK := false
              else if (CACertificate.Extensions.BasicConstraints.PathLenConstraint <> -1) and (CurrPathLen > CACertificate.Extensions.BasicConstraints.PathLenConstraint) then
                ExtnsOK := false;
            end;

            // - name constraints
            if (not FIgnoreCANameConstraints) and (CACertificate.Version >= 3) and
              ( (ceNameConstraints in CACertificate.Extensions.Included) ) then
            begin
              if  (ceSubjectAlternativeName in CurrentCertificate.Extensions.Included)  then
                AltName := CurrentCertificate.Extensions.SubjectAlternativeName.Content
              else
                AltName := nil;
              if not CACertificate.Extensions.NameConstraints.AreNamesAcceptable(CurrentCertificate.SubjectRDN, AltName) then
                ExtnsOK := false;
            end;

            // - key usage
            if (not IgnoreCAKeyUsage) and
              ((CACertificate.Version >= 3) and
               ( (ceKeyUsage in CACertificate.Extensions.Included) 
              and (not CACertificate.Extensions.KeyUsage.KeyCertSign))) then
              ExtnsOK := false;

            if not (ExtnsOK) then
            begin
              CAValidity :=  cvInvalid ;
              CAReason := CAReason  + [vrCAUnauthorized] ;
            end
            else
            if not CurrentCertificate.ValidateWithCA(CACertificate) then
            begin
              CAReason := CAReason  + [vrInvalidSignature] ;
              CAValidity :=  cvInvalid ;
            end;
          end;
        end;

        if (not CurrentCertificate.SelfSigned) or FForceRevocationCheckForRoot then
        begin
          CrlExists := false;
          OcspExists := false;

          if FRevocationCheckPreference = rcpCheckBoth then
          begin
            // Checking status from both CRL and OCSP responders.

            // Check the CRLs
            if CheckCRL and ((CAValidity <>  cvInvalid ) or FValidateInvalidCertificates) then
              PerformCRLCheck(AdditionalCertificates, CurrentCertificate, CACertificate, ValidityMoment, CAValidity, CAReason, CrlExists);

            // Check OCSP
            if CheckOCSP and ((CAValidity <>  cvInvalid ) or FValidateInvalidCertificates) then
              PerformOCSPCheck(AdditionalCertificates, CurrentCertificate, CACertificate, ValidityMoment, CAValidity, CAReason, OcspExists);
          end
          else if FRevocationCheckPreference = rcpPreferOCSP then
          begin
            // Trying to get status via OCSP first; only trying CRL if we fail to get the status from an OCSP responder.

            // Check OCSP
            if CheckOCSP and ((CAValidity <>  cvInvalid ) or FValidateInvalidCertificates) then
              PerformOCSPCheck(AdditionalCertificates, CurrentCertificate, CACertificate, ValidityMoment, CAValidity, CAReason, OcspExists);

            if (not OcspExists) or ( vrOCSPNotVerified in CAReason ) then
            begin
              // Check the CRLs
              if CheckCRL and ((CAValidity <>  cvInvalid ) or FValidateInvalidCertificates) then
                PerformCRLCheck(AdditionalCertificates, CurrentCertificate, CACertificate, ValidityMoment, CAValidity, CAReason, CrlExists);
            end;
          end
          else if FRevocationCheckPreference = rcpPreferCRL then
          begin
            // Trying to get status from CRL first; only trying OCSP if we fail to get the status from the CRL server.

            // Check the CRLs
            if CheckCRL and ((CAValidity <>  cvInvalid ) or FValidateInvalidCertificates) then
              PerformCRLCheck(AdditionalCertificates, CurrentCertificate, CACertificate, ValidityMoment, CAValidity, CAReason, CrlExists);

            if (not CrlExists) or ( vrCRLNotVerified in CAReason ) then
            begin
              // Check OCSP
              if CheckOCSP and ((CAValidity <>  cvInvalid ) or FValidateInvalidCertificates) then
                PerformOCSPCheck(AdditionalCertificates, CurrentCertificate, CACertificate, ValidityMoment, CAValidity, CAReason, OcspExists);
            end;
          end;

          // Checking if at least one revocation check (CRL-based / OCSP-based) succeeded
          if (not FMandatoryCRLCheck) and (not FMandatoryOCSPCheck) and (FMandatoryRevocationCheck) then
          begin
            // MandatoryRevocationCheck requires at least one source of
            // revocation information to be obtained and checked

            if
              // revocation info is published through CRL but it has not been found
              (CrlExists and (not OcspExists) and ( vrCRLNotVerified in CAReason )) or
              // revocation info is published through OCSP but it has not been found
              (OcspExists and (not CrlExists) and ( vrOCSPNotVerified in CAReason )) or
              // revocation info is published through both CRL and OCSP but neither has been found
              ((OcspExists) and (CrlExists) and ( vrCRLNotVerified in CAReason ) and ( vrOCSPNotVerified in CAReason )) then

              CAValidity := cvInvalid;

          end;
        end;
      end; // if not SkipCheck ...

      DoContinue := (CAValidity =  cvOk ) or CompleteChainValidation;
      TriggerAfterValidation(CurrentCertificate, CACertificate, CAValidity, CAReason, DoContinue);

      if (Trusted) and (not FForceCompleteChainValidationForTrusted) then
      begin
        Validity := CAValidity;
        Reason := CAReason;
        break;
      end;

      if CurrentCertificate = Certificate then
      begin
        Validity := CAValidity;
        Reason := CAReason;
      end
      else
      begin
        if CAValidity <>  cvOk  then
          Validity := cvChainUnvalidated;

        if CAReason <>  []  then
          Reason := Reason + CAReason;
      end;

      if not DoContinue then
        break;

      if (CAValidity =  cvInvalid ) and (not CompleteChainValidation) then
        break;
      if Validity =  cvOk  then
        FCheckedCertificates.Add(CurrentCertificate)
      else
        RemoveCertificateFromChecked(CurrentCertificate); // just in case it was there
      if (CurrentCertificate.SelfSigned) then
        CACertificate := nil; // forcing loop termination

      CurrentCertificate := CACertificate;
	  Inc(CurrPathLen);
    end; // while

    (*
    if CAValidity <> {$ifndef SB_NET}cvOk{$else}TSBCertificateValidity.cvOk{$endif} then
      Validity := CAValidity;
    if CAReason <> {$ifndef SB_NET}[]{$else}0{$endif} then
      Reason := CAReason;
    *)
  finally
    FValidationStack.Remove(Certificate);
  end;
end;

procedure TElX509CertificateValidator.ValidateForTimestamping(Certificate: TElX509Certificate;
      AdditionalCertificates : TElCustomCertStorage;
      CompleteChainValidation : boolean;
      ResetCertificateCache : boolean;
      ValidityMoment: TElDateTime;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason
       );
var KUFine : boolean;
    DoContinue : TSBBoolean;
begin
  KUFine := ( ceKeyUsage in Certificate.Extensions.Included ) and
            ((Certificate.Extensions.KeyUsage.DigitalSignature) or (Certificate.Extensions.KeyUsage.NonRepudiation)) and
            (
             ( ceExtendedKeyUsage in Certificate.Extensions.Included ) and
             (Certificate.Extensions.ExtendedKeyUsage.TotalUsageCount = 1) and Certificate.Extensions.ExtendedKeyUsage.Timestamping
            );
  if not KUFine then
  begin
    Validity :=  cvInvalid ;
    Reason := Reason  + [vrNoKeyUsage] ;
    DoContinue := false;
    TriggerAfterValidation(Certificate, nil, Validity, Reason, DoContinue);
    if not DoContinue then
      exit;
  end;

  Validate(Certificate, AdditionalCertificates, CompleteChainValidation, ResetCertificateCache, ValidityMoment, 
     Validity, Reason );
end;

procedure TElX509CertificateValidator.ValidateForSMIME(Certificate: TElX509Certificate;
      EMailAddress : string;
      AdditionalCertificates : TElCustomCertStorage;
      CompleteChainValidation : boolean;
      ResetCertificateCache : boolean;
      ValidityMoment: TElDateTime;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason
       );
var Name : string;
    i : integer;
    AltName : TElAlternativeNameExtension;
    Found : boolean;
    DoContinue : TSBBoolean;
    SkipCheck : boolean;
begin
  {$ifdef SB_HAS_WINCRYPT}
  // we initialize the storages only before actual use
  if UseSystemStorages {$ifdef SILVERLIGHT}and SBUtils.ElevatedPermissionsAvailable {$endif} then
    InitializeWinStorages;
   {$endif}

  EMailAddress := StringToLower(StringTrim(EMailAddress));

  if not CheckIfTrusted(Certificate) then 
  begin
    Found := true;
    if EMailAddress <> '' then
    begin
      if  ceSubjectAlternativeName in Certificate.Extensions.Included  then
      begin
  
        AltName := Certificate.Extensions.SubjectAlternativeName;
        if AltName.Content.Count > 0 then
        begin
          i := 0;
          repeat
            i := AltName.Content.FindNameByType(gnRFC822Name, i);
            if i <> -1 then
            begin
              Found := false;
  
              Name := AltName.Content.Names[i].RFC822Name;
              Name := StringToLower(StringTrim(Name));
              if Name = EMailAddress then
              begin
                Found := true;
                break;
              end
              else
                inc(i);
            end;
          until i = -1;
        end;
      end;
    end;
  
    // check key usage of the certificate
    if Found then
    begin
      SkipCheck := false;
      if  ceKeyUsage in Certificate.Extensions.Included  then
      begin
        if (not Certificate.Extensions.KeyUsage.DigitalSignature) and (not Certificate.Extensions.KeyUsage.NonRepudiation) then
        begin
          Validity :=  cvInvalid ;
          Reason := Reason  + [vrNoKeyUsage] ;
          DoContinue := false;
          TriggerAfterValidation(Certificate, nil, Validity, Reason, DoContinue);
          if not DoContinue then
            exit
          else
            SkipCheck := true;
        end;
      end;

      if (not SkipCheck) and ( ceExtendedKeyUsage in Certificate.Extensions.Included ) then
      begin
        if not Certificate.Extensions.ExtendedKeyUsage.EmailProtection then
        begin
          Validity :=  cvInvalid ;
          Reason := Reason  + [vrNoKeyUsage] ;
          DoContinue := false;
          TriggerAfterValidation(Certificate, nil, Validity, Reason, DoContinue);
          if not DoContinue then
            exit;
        end;
      end;
    end;

    if not Found then
    begin
      Validity :=  cvInvalid ;
      Reason := Reason  + [vrIdentityMismatch] ;
      DoContinue := false;
      TriggerAfterValidation(Certificate, nil, Validity, Reason, DoContinue);
      if not DoContinue then
        exit;
    end;
  end;

  Validate(Certificate, AdditionalCertificates, CompleteChainValidation, ResetCertificateCache, ValidityMoment, 
     Validity, Reason )
end;

procedure TElX509CertificateValidator.ValidateForSSL(Certificate: TElX509Certificate;
      DomainName : string; IPAddress : string; HostRole : TSBHostRole;
      AdditionalCertificates : TElCustomCertStorage;
      CompleteChainValidation : boolean;
      ResetCertificateCache : boolean;
      ValidityMoment: TElDateTime;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason
       );
begin
  ValidateForSSL(Certificate, DomainName, IPAddress, HostRole, AdditionalCertificates, CompleteChainValidation, ResetCertificateCache, ValidityMoment, false, 
     Validity, Reason );
end;

procedure TElX509CertificateValidator.ValidateForSSL(Certificate: TElX509Certificate;
      DomainName : string; IPAddress : string; HostRole : TSBHostRole;
      AdditionalCertificates : TElCustomCertStorage;
      CompleteChainValidation : boolean;
      ResetCertificateCache : boolean;
      ValidityMoment: TElDateTime;
      InternalValidation : boolean;
      var Validity : TSBCertificateValidity;
      var Reason: TSBCertificateValidityReason
       );

var Name : string;
    i : integer;
    AltName : TElAlternativeNameExtension;
    Found : boolean;
    DoContinue : TSBBoolean;
    SkipCheck : boolean;
    IPAddressBuf, AltNameBuf: ByteArray;
begin
  {$ifdef SB_HAS_WINCRYPT}
  // we initialize the storages only before actual use
  if UseSystemStorages {$ifdef SILVERLIGHT}and SBUtils.ElevatedPermissionsAvailable {$endif} then
    InitializeWinStorages;
   {$endif}

  DomainName := StringToLower(StringTrim(DomainName));
  IPAddress := StringToLower(StringTrim(IPAddress));

  if not CheckIfTrusted(Certificate) then
  begin
    Found := false;
    if  ceSubjectAlternativeName in Certificate.Extensions.Included  then
    begin
      AltName := Certificate.Extensions.SubjectAlternativeName;
      if AltName.Content.Count > 0 then
      begin

        // check the domain names
        if DomainName <> '' then
        begin
          i := 0;
          repeat
            i := AltName.Content.FindNameByType(gnDNSName, i);
            if i <> -1 then
            begin
              Name := AltName.Content.Names[i].DNSName;
              if DomainNameMatchesCertSN(DomainName, StringToLower(StringTrim(Name))) then
              begin
                Found := true;
                break;
              end
              else
                inc(i);
            end;
          until i = -1;
        end;

        if not Found and not StringIsEmpty(IPAddress) then
        begin
          IPAddressBuf := IPAddressToOctets(IPAddress);
          if Length(IPAddressBuf) <> 0 then
          begin
            I := 0;
            while True do
            begin
              I := AltName.Content.FindNameByType(gnIPAddress, I);
              if I = -1 then
                Break;

              AltNameBuf := IPAddressToOctets(AltName.Content.Names[I].IpAddress);
              if Length(AltNameBuf) <> 0 then
              begin
                Found := CompareContent(IPAddressBuf, AltNameBuf);
                ReleaseArray(AltNameBuf);

                if Found then
                  Break;
              end;

              Inc(I);
            end;
            ReleaseArray(IPAddressBuf);
          end;
        end;
      end;
    end;
  
    if not Found then
    begin
      Name := Certificate.SubjectName.CommonName;

      Found := not StringIsEmpty(DomainName) and
        DomainNameMatchesCertSN(DomainName, StringToLower(StringTrim(Name)));

      if not Found and not StringIsEmpty(IPAddress) then
      begin
        IPAddressBuf := IPAddressToOctets(IPAddress);
        if Length(IPAddressBuf) <> 0 then
        begin
          AltNameBuf := IPAddressToOctets(Name);
          if Length(AltNameBuf) <> 0 then
          begin
            Found := CompareContent(IPAddressBuf, AltNameBuf);
            ReleaseArray(AltNameBuf);
          end;
          ReleaseArray(IPAddressBuf);
        end;
      end;
    end;
  
    // check key usage of the certificate
    if Found then
    begin
      SkipCheck := false;
      if (not FIgnoreSSLKeyUsage) and ( ceKeyUsage in Certificate.Extensions.Included ) then
      begin
        if (not Certificate.Extensions.KeyUsage.DigitalSignature) or
           (((HostRole = hrServer) or (HostRole = hrBoth)) and (not (Certificate.Extensions.KeyUsage.KeyEncipherment or Certificate.Extensions.KeyUsage.KeyAgreement))) then
        begin
          Validity :=  cvInvalid ;
          Reason := Reason  + [vrNoKeyUsage] ;
          DoContinue := false;
          TriggerAfterValidation(Certificate, nil, Validity, Reason, DoContinue);
          if not DoContinue then
            exit
          else
            SkipCheck := true;
        end;
      end;
  
      if (not SkipCheck) and (not FIgnoreSSLKeyUsage) and (( ceExtendedKeyUsage in Certificate.Extensions.Included )) then
      begin
        if (((HostRole = hrServer) or (HostRole = hrBoth)) and (not Certificate.Extensions.ExtendedKeyUsage.ServerAuthentication)) or
           (((HostRole = hrClient) or (HostRole = hrBoth)) and (not Certificate.Extensions.ExtendedKeyUsage.ClientAuthentication)) then
        begin
          Validity :=  cvInvalid ;
          Reason := Reason  + [vrNoKeyUsage] ;
          DoContinue := false;
          TriggerAfterValidation(Certificate, nil, Validity, Reason, DoContinue);
          if not DoContinue then
            exit;
        end;
      end;
    end;

    if not Found then
    begin
      Validity :=  cvInvalid ;
      Reason := Reason  + [vrIdentityMismatch] ;
      DoContinue := false;
      TriggerAfterValidation(Certificate, nil, Validity, Reason, DoContinue);
      if not DoContinue then
        exit;
    end;
  end;

  Validity := cvOk;
  Reason :=  [] ;

  if not InternalValidation then
  begin
    FChainCertificates.Clear;
    ClearUsedValidationInfo;
  end;

  InternalValidate(Certificate, AdditionalCertificates, CompleteChainValidation, ResetCertificateCache, ValidityMoment,
    Validity, Reason);
end;

procedure TElX509CertificateValidator.AddTrustedCertificates(Storage : TElCustomCertStorage);
begin
  if (Storage <> nil) and (FTrustedCertificates.IndexOf(Storage) = -1) then
  begin
    FTrustedCertificates.Add(Storage);
    Storage.FreeNotification(Self);
  end;
end;

procedure TElX509CertificateValidator.ClearTrustedCertificates;
begin
  FTrustedCertificates.Clear;
end;

procedure TElX509CertificateValidator.AddKnownCertificates(Storage : TElCustomCertStorage);
begin
  if (Storage <> nil) and (FKnownCertificates.IndexOf(Storage) = -1) then
  begin
    FKnownCertificates.Add(Storage);
    Storage.FreeNotification(Self);
  end;
end;

procedure TElX509CertificateValidator.ClearKnownCertificates;
begin
  FKnownCertificates.Clear;
end;

procedure TElX509CertificateValidator.AddKnownCRLs(Storage : TElCustomCRLStorage);
begin
  if (Storage <> nil) and (FKnownCRLs.IndexOf(Storage) = -1) then
  begin
    FKnownCRLs.Add(Storage);
    Storage.FreeNotification(Self);
  end;
end;

procedure TElX509CertificateValidator.ClearKnownCRLs;
begin
  FKnownCRLs.Clear;
end;

procedure TElX509CertificateValidator.AddKnownOCSPResponses(Response : TElOCSPResponse);
var NewResponse : TElOCSPResponse;
begin
  NewResponse := TElOCSPResponse.Create;
  NewResponse.Assign(Response);
  FKnownOCSPResponses.Add(NewResponse);
end;

procedure TElX509CertificateValidator.AddBlockedCertificates(Storage :
    TElCustomCertStorage);
begin
  if (Storage <> nil) and (FBlockedCertificates.IndexOf(Storage) = -1) then
  begin
    FBlockedCertificates.Add(Storage);
    Storage.FreeNotification(Self);
  end;
end;

procedure TElX509CertificateValidator.ClearKnownOCSPResponses;
var i : integer;
begin
  for i := 0 to FKnownOCSPResponses.Count - 1 do
    TElOCSPResponse(FKnownOCSPResponses[i]). Free ;
  FKnownOCSPResponses.Clear;
end;

procedure TElX509CertificateValidator.ClearBlockedCertificates;
begin
  FBlockedCertificates.Clear;
end;

function TElX509CertificateValidator.GetCertificateRetriever(NameType : TSBGeneralName; const Location : string) : TElCustomCertificateRetriever;
var i : integer;
begin
  result := nil;

  if FOfflineMode then
    Exit;

  for i := 0 to FCertificateRetrievers.Count - 1 do
  begin
    if TElCustomCertificateRetriever(FCertificateRetrievers[i]).SupportsLocation(NameType, Location) then
    begin
      result := TElCustomCertificateRetriever(FCertificateRetrievers[i]);
      break;
    end;
  end;

  if result = nil then
  begin
    Result := FCertRetrieverManager.FindCertificateRetrieverByLocation(NameType, Location, Self);
    if Result <> nil then
      FCertificateRetrievers.Add(Result);
  end;
end;


function TElX509CertificateValidator.GetOCSPClient(const Location : string) : TElOCSPClient;
var i : integer;
begin
  result := nil;

  if FOfflineMode then
    Exit;

  for i := 0 to FOCSPClients.Count - 1 do
  begin
    if TElOCSPClient(FOCSPClients[i]).SupportsLocation(Location) then
    begin
      result := TElOCSPClient(FOCSPClients[i]);
      break;
    end;
  end;

  if result = nil then
  begin
    Result := FOCSPClientManager.FindOCSPClientByLocation(Location, Self);
    if Result <> nil then
      FOCSPClients.Add(Result);
  end;
end;

function TElX509CertificateValidator.GetCRLRetriever(NameType : TSBGeneralName; const Location : string) : TElCustomCRLRetriever;
var i : integer;
begin
  result := nil;

  if FOfflineMode then
    Exit;

  for i := 0 to FCRLRetrievers.Count - 1 do
  begin
    if TElCustomCRLRetriever(FCRLRetrievers[i]).Supports(NameType, Location) then
    begin
      result := TElCustomCRLRetriever(FCRLRetrievers[i]);
      break;
    end;
  end;

  if result = nil then
  begin
    Result := FCRLManager.FindCRLRetriever(NameType, Location, Self);
    if Result <> nil then
      FCRLRetrievers.Add(Result);
  end;
end;

procedure TElX509CertificateValidator.RemoveCertificateFromChecked(Certificate:
    TElX509Certificate);
var i : integer;
begin
  i := FindCertificateInStorage(Certificate, FCheckedCertificates);
  if i <> -1 then
    FCheckedCertificates.Remove(i);
end;

end.

