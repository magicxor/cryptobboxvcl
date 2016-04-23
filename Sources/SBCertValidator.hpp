// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbcertvalidator.pas' rev: 21.00

#ifndef SbcertvalidatorHPP
#define SbcertvalidatorHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Windows.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbrdn.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbx509.hpp>	// Pascal unit
#include <Sbx509ext.hpp>	// Pascal unit
#include <Sbocspcommon.hpp>	// Pascal unit
#include <Sbocspclient.hpp>	// Pascal unit
#include <Sbrandom.hpp>	// Pascal unit
#include <Sbpkicommon.hpp>	// Pascal unit
#include <Sbcrl.hpp>	// Pascal unit
#include <Sbcrlstorage.hpp>	// Pascal unit
#include <Sbcertretriever.hpp>	// Pascal unit
#include <Sbwincertstorage.hpp>	// Pascal unit
#include <Sbcustomcertstorage.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbcertvalidator
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS EElValidationFailedInternalError;
class PASCALIMPLEMENTATION EElValidationFailedInternalError : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElValidationFailedInternalError(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElValidationFailedInternalError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElValidationFailedInternalError(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElValidationFailedInternalError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElValidationFailedInternalError(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElValidationFailedInternalError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElValidationFailedInternalError(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElValidationFailedInternalError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElValidationFailedInternalError(void) { }
	
};


typedef void __fastcall (__closure *TSBCRLNeededEvent)(System::TObject* Sender, Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* CACertificate, Sbcrlstorage::TElCustomCRLStorage* &CRLs);

typedef void __fastcall (__closure *TSBCACertificateRetrievedEvent)(System::TObject* Sender, Sbx509::TElX509Certificate* Certificate, Sbx509ext::TSBGeneralName NameType, const System::UnicodeString Location, Sbx509::TElX509Certificate* CACertificate);

typedef void __fastcall (__closure *TSBCRLRetrievedEvent)(System::TObject* Sender, Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* CACertificate, Sbx509ext::TSBGeneralName NameType, const System::UnicodeString Location, Sbcrl::TElCertificateRevocationList* CRL);

typedef void __fastcall (__closure *TSBAfterCRLUseEvent)(System::TObject* Sender, Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* CACertificate, Sbcrl::TElCertificateRevocationList* CRL);

typedef void __fastcall (__closure *TSBAfterOCSPResponseUseEvent)(System::TObject* Sender, Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* CACertificate, Sbocspclient::TElOCSPResponse* Response);

typedef void __fastcall (__closure *TSBOCSPResponseSignerValidEvent)(System::TObject* Sender, Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* CACertificate, Sbocspclient::TElOCSPResponse* Response, Sbx509::TElX509Certificate* SignerCertificate, bool &SignerValid);

typedef void __fastcall (__closure *TSBBeforeCertificateRetrieverUseEvent)(System::TObject* Sender, Sbx509::TElX509Certificate* Certificate, Sbx509ext::TSBGeneralName NameType, const System::UnicodeString Location, Sbcertretriever::TElCustomCertificateRetriever* &Retriever);

typedef void __fastcall (__closure *TSBBeforeCRLRetrieverUseEvent)(System::TObject* Sender, Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* CACertificate, Sbx509ext::TSBGeneralName NameType, const System::UnicodeString Location, Sbcrlstorage::TElCustomCRLRetriever* &Retriever);

typedef void __fastcall (__closure *TSBBeforeOCSPClientUseEvent)(System::TObject* Sender, Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* CACertificate, const System::UnicodeString OCSPLocation, Sbocspclient::TElOCSPClient* &OCSPClient);

typedef void __fastcall (__closure *TSBCertificateValidatorCRLErrorEvent)(System::TObject* Sender, Sbx509::TElX509Certificate* Certificate, const System::UnicodeString Location, Sbcrlstorage::TElCustomCRLRetriever* Retriever, int ErrorCode);

typedef void __fastcall (__closure *TSBCertificateValidatorOCSPErrorEvent)(System::TObject* Sender, Sbx509::TElX509Certificate* Certificate, const System::UnicodeString Location, Sbocspclient::TElOCSPClient* Client, int ErrorCode);

typedef void __fastcall (__closure *TSBCACertificateNeededEvent)(System::TObject* Sender, Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* &CACertificate);

typedef void __fastcall (__closure *TSBBeforeCertificateValidationEvent)(System::TObject* Sender, Sbx509::TElX509Certificate* Certificate);

typedef void __fastcall (__closure *TSBAfterCertificateValidationEvent)(System::TObject* Sender, Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* CACertificate, Sbx509::TSBCertificateValidity &Validity, Sbx509::TSBCertificateValidityReason &Reason, bool &DoContinue);

#pragma option push -b-
enum TSBX509RevocationCheckPreference { rcpPreferCRL, rcpPreferOCSP, rcpCheckBoth };
#pragma option pop

class DELPHICLASS TElX509CertificateValidator;
class PASCALIMPLEMENTATION TElX509CertificateValidator : public Classes::TComponent
{
	typedef Classes::TComponent inherited;
	
protected:
	Classes::TList* FCRLRetrievers;
	Classes::TList* FOCSPClients;
	Classes::TList* FCertificateRetrievers;
	Sbcustomcertstorage::TElMemoryCertStorage* FCheckedCertificates;
	Sbcustomcertstorage::TElMemoryCertStorage* FChainCertificates;
	Sbcustomcertstorage::TElMemoryCertStorage* FCachedCACertificates;
	Classes::TList* FTrustedCertificates;
	Classes::TList* FBlockedCertificates;
	Classes::TList* FKnownCertificates;
	Classes::TList* FKnownCRLs;
	Classes::TList* FKnownOCSPResponses;
	Sbcustomcertstorage::TElMemoryCertStorage* FUsedCertificates;
	Sbcrlstorage::TElMemoryCRLStorage* FUsedCRLs;
	Classes::TList* FUsedOCSPResponses;
	Sbwincertstorage::TElWinCertStorage* FWinStorageTrust;
	Sbwincertstorage::TElWinCertStorage* FWinStorageCA;
	Sbwincertstorage::TElWinCertStorage* FWinStorageBlocked;
	bool FUseSystemStorages;
	bool FIgnoreSystemTrust;
	Sbcrlstorage::TElCRLManager* FCRLManager;
	Sbocspclient::TElOCSPClientManager* FOCSPClientManager;
	Sbcertretriever::TElCertificateRetrieverManager* FCertRetrieverManager;
	bool FCheckOCSP;
	bool FCheckCRL;
	TSBCACertificateRetrievedEvent FOnCACertificateRetrieved;
	TSBCRLRetrievedEvent FOnCRLRetrieved;
	TSBCRLNeededEvent FOnCRLNeeded;
	TSBBeforeCertificateRetrieverUseEvent FOnBeforeCertificateRetrieverUse;
	TSBBeforeCRLRetrieverUseEvent FOnBeforeCRLRetrieverUse;
	TSBBeforeOCSPClientUseEvent FOnBeforeOCSPClientUse;
	TSBBeforeCertificateValidationEvent FOnBeforeCertificateValidation;
	TSBAfterCertificateValidationEvent FOnAfterCertificateValidation;
	TSBCACertificateNeededEvent FOnCACertificateNeeded;
	TSBAfterCRLUseEvent FOnAfterCRLUse;
	TSBAfterOCSPResponseUseEvent FOnAfterOCSPResponseUse;
	TSBOCSPResponseSignerValidEvent FOnOCSPResponseSignerValid;
	TSBCertificateValidatorCRLErrorEvent FOnCRLError;
	TSBCertificateValidatorOCSPErrorEvent FOnOCSPError;
	bool FValidateInvalidCertificates;
	bool FCheckValidityPeriodForTrusted;
	bool FIgnoreCAKeyUsage;
	bool FIgnoreRevocationKeyUsage;
	bool FIgnoreSSLKeyUsage;
	bool FIgnoreBadOCSPChains;
	bool FIgnoreCABasicConstraints;
	bool FIgnoreCANameConstraints;
	bool FMandatoryCRLCheck;
	bool FMandatoryOCSPCheck;
	bool FMandatoryRevocationCheck;
	bool FForceCompleteChainValidationForTrusted;
	bool FForceRevocationCheckForRoot;
	bool FOfflineMode;
	int FRevocationMomentGracePeriod;
	bool FImplicitlyTrustSelfSignedCertificates;
	bool FPromoteLongOCSPResponses;
	Classes::TList* FValidationStack;
	TSBX509RevocationCheckPreference FRevocationCheckPreference;
	bool FLookupCRLByNameIfDPNotPresent;
	void __fastcall DeleteStorages(void);
	void __fastcall DeleteCRLRetrievers(void);
	void __fastcall DeleteOCSPClients(void);
	void __fastcall DeleteCertificateRetrievers(void);
	void __fastcall AddUsedCertificate(Sbx509::TElX509Certificate* Cert);
	void __fastcall AddUsedCRL(Sbcrl::TElCertificateRevocationList* Crl);
	void __fastcall AddUsedOCSPResponse(Sbocspclient::TElOCSPResponse* OcspResp);
	void __fastcall ClearUsedValidationInfo(void);
	Sbcertretriever::TElCustomCertificateRetriever* __fastcall GetCertificateRetriever(Sbx509ext::TSBGeneralName NameType, const System::UnicodeString Location);
	Sbocspclient::TElOCSPClient* __fastcall GetOCSPClient(const System::UnicodeString Location);
	Sbcrlstorage::TElCustomCRLRetriever* __fastcall GetCRLRetriever(Sbx509ext::TSBGeneralName NameType, const System::UnicodeString Location);
	virtual void __fastcall Notification(Classes::TComponent* AComponent, Classes::TOperation AOperation);
	Sbcrl::TElCertificateRevocationList* __fastcall FindMatchingCRL(Sbx509::TElX509Certificate* Certificate, Sbx509ext::TElDistributionPoint* DistributionPoint, Sbcrlstorage::TElCustomCRLStorage* Storage, System::TDateTime ValidityMoment);
	bool __fastcall CheckIfTrusted(Sbx509::TElX509Certificate* Certificate);
	void __fastcall CheckValidityPeriod(Sbx509::TElX509Certificate* Certificate, System::TDateTime ValidityMoment, Sbx509::TSBCertificateValidity &Validity, Sbx509::TSBCertificateValidityReason &Reason);
	Sbx509::TElX509Certificate* __fastcall FindSignerCertificate(Sbcustomcertstorage::TElCustomCertStorage* AdditionalCertificates, Sbrdn::TElRelativeDistinguishedName* Signer, Sbtypes::ByteArray SignerKeyIdentifier, bool &Trusted);
	Sbx509::TElX509Certificate* __fastcall FindCA(Sbcustomcertstorage::TElCustomCertStorage* AdditionalCertificates, Sbx509::TElX509Certificate* Certificate, bool &Trusted);
	int __fastcall FindCertificateInStorage(Sbx509::TElX509Certificate* Certificate, Sbcustomcertstorage::TElCustomCertStorage* Storage);
	bool __fastcall CertificateIsBlocked(Sbx509::TElX509Certificate* Certificate);
	void __fastcall CheckOCSPResponse(Sbocspclient::TElOCSPResponse* Response, Sbcustomcertstorage::TElCustomCertStorage* AdditionalCertificates, Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* CACertificate, System::TDateTime ValidityMoment, bool &Found, Sbx509::TSBCertificateValidity &Validity, Sbx509::TSBCertificateValidityReason &Reason);
	void __fastcall PerformOCSPCheck(Sbcustomcertstorage::TElCustomCertStorage* AdditionalCertificates, Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* CACertificate, System::TDateTime ValidityMoment, Sbx509::TSBCertificateValidity &Validity, Sbx509::TSBCertificateValidityReason &Reason, bool &OcspExistsForCert);
	void __fastcall PerformCRLCheck(Sbcustomcertstorage::TElCustomCertStorage* AdditionalCertificates, Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* CACertificate, System::TDateTime ValidityMoment, Sbx509::TSBCertificateValidity &Validity, Sbx509::TSBCertificateValidityReason &Reason, bool &CrlExistsForCert);
	void __fastcall RemoveCertificateFromChecked(Sbx509::TElX509Certificate* Certificate);
	virtual void __fastcall TriggerBeforeCertificateRetrieverUse(Sbx509::TElX509Certificate* Certificate, Sbx509ext::TSBGeneralName NameType, const System::UnicodeString Location, Sbcertretriever::TElCustomCertificateRetriever* &Retriever);
	virtual void __fastcall TriggerBeforeCRLRetrieverUse(Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* CACertificate, Sbx509ext::TSBGeneralName NameType, const System::UnicodeString Location, Sbcrlstorage::TElCustomCRLRetriever* &Retriever);
	virtual void __fastcall TriggerBeforeOCSPClientUse(Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* CACertificate, const System::UnicodeString OCSPLocation, Sbocspclient::TElOCSPClient* &Client);
	virtual void __fastcall TriggerBeforeValidation(Sbx509::TElX509Certificate* Certificate);
	virtual void __fastcall TriggerAfterValidation(Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* CACertificate, Sbx509::TSBCertificateValidity &Validity, Sbx509::TSBCertificateValidityReason &Reason, bool &DoContinue);
	virtual void __fastcall TriggerCACertificateNeeded(Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* &CACertificate);
	virtual void __fastcall TriggerCRLNeeded(Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* CACertificate, Sbcrlstorage::TElCustomCRLStorage* &CRLs);
	virtual void __fastcall TriggerCACertificateRetrieved(Sbx509::TElX509Certificate* Certificate, Sbx509ext::TSBGeneralName NameType, const System::UnicodeString Location, Sbx509::TElX509Certificate* CACertificate);
	virtual void __fastcall TriggerCRLRetrieved(Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* CACertificate, Sbx509ext::TSBGeneralName NameType, const System::UnicodeString Location, Sbcrl::TElCertificateRevocationList* CRL);
	virtual void __fastcall TriggerAfterCRLUse(Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* CACertificate, Sbcrl::TElCertificateRevocationList* CRL);
	virtual void __fastcall TriggerAfterOCSPResponseUse(Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* CACertificate, Sbocspclient::TElOCSPResponse* Response);
	virtual void __fastcall TriggerCRLError(Sbx509::TElX509Certificate* Certificate, const System::UnicodeString Location, Sbcrlstorage::TElCustomCRLRetriever* Retriever, int ErrorCode);
	virtual void __fastcall TriggerOCSPError(Sbx509::TElX509Certificate* Certificate, const System::UnicodeString Location, Sbocspclient::TElOCSPClient* Client, int ErrorCode);
	virtual void __fastcall TriggerOCSPResponseSignerValid(Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* CACertificate, Sbocspclient::TElOCSPResponse* Response, Sbx509::TElX509Certificate* SignerCertificate, bool &SignerValid);
	Sbocspclient::TElOCSPResponse* __fastcall FindMatchingOCSP(Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* CACertificate, Classes::TList* OCSPResponses, System::TDateTime ValidityMoment);
	void __fastcall SetupImplicitDP(Sbx509::TElX509Certificate* Certificate, Sbx509ext::TElDistributionPoint* DP);
	System::UnicodeString __fastcall RetrieveCRLs(Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* CACertificate, Sbcrlstorage::TElCustomCRLStorage* Storage, System::TDateTime ValidityMoment, Sbx509::TSBCertificateValidityReason &Reason);
	bool __fastcall ValidateOCSP(Sbcustomcertstorage::TElCustomCertStorage* AdditionalCertificates, Sbx509::TElX509Certificate* Certificate, Sbx509::TElX509Certificate* CACertificate, Sbocspclient::TElOCSPResponse* Response, System::TDateTime ValidityMoment, Sbx509::TSBCertificateValidityReason &Reason);
	bool __fastcall ValidateCRL(Sbcustomcertstorage::TElCustomCertStorage* AdditionalCertificates, Sbcrl::TElCertificateRevocationList* CRL, System::TDateTime ValidityMoment, Sbx509::TSBCertificateValidityReason &Reason);
	void __fastcall InternalValidate(Sbx509::TElX509Certificate* Certificate, Sbcustomcertstorage::TElCustomCertStorage* AdditionalCertificates, bool CompleteChainValidation, bool ResetCertificateCache, System::TDateTime ValidityMoment, Sbx509::TSBCertificateValidity &Validity, Sbx509::TSBCertificateValidityReason &Reason)/* overload */;
	bool __fastcall CertificatePresentInStack(Sbx509::TElX509Certificate* Cert);
	
public:
	__fastcall virtual TElX509CertificateValidator(Classes::TComponent* AOwner);
	__fastcall virtual ~TElX509CertificateValidator(void);
	void __fastcall InitializeWinStorages(void);
	void __fastcall Validate(Sbx509::TElX509Certificate* Certificate, Sbcustomcertstorage::TElCustomCertStorage* AdditionalCertificates, bool CompleteChainValidation, bool ResetCertificateCache, System::TDateTime ValidityMoment, Sbx509::TSBCertificateValidity &Validity, Sbx509::TSBCertificateValidityReason &Reason)/* overload */;
	void __fastcall Validate(Sbx509::TElX509Certificate* Certificate, Sbx509::TSBCertificateValidity &Validity, Sbx509::TSBCertificateValidityReason &Reason)/* overload */;
	void __fastcall ValidateForSMIME(Sbx509::TElX509Certificate* Certificate, System::UnicodeString EMailAddress, Sbcustomcertstorage::TElCustomCertStorage* AdditionalCertificates, bool CompleteChainValidation, bool ResetCertificateCache, System::TDateTime ValidityMoment, Sbx509::TSBCertificateValidity &Validity, Sbx509::TSBCertificateValidityReason &Reason);
	void __fastcall ValidateForSSL(Sbx509::TElX509Certificate* Certificate, System::UnicodeString DomainName, System::UnicodeString IPAddress, Sbtypes::TSBHostRole HostRole, Sbcustomcertstorage::TElCustomCertStorage* AdditionalCertificates, bool CompleteChainValidation, bool ResetCertificateCache, System::TDateTime ValidityMoment, Sbx509::TSBCertificateValidity &Validity, Sbx509::TSBCertificateValidityReason &Reason)/* overload */;
	void __fastcall ValidateForSSL(Sbx509::TElX509Certificate* Certificate, System::UnicodeString DomainName, System::UnicodeString IPAddress, Sbtypes::TSBHostRole HostRole, Sbcustomcertstorage::TElCustomCertStorage* AdditionalCertificates, bool CompleteChainValidation, bool ResetCertificateCache, System::TDateTime ValidityMoment, bool InternalValidation, Sbx509::TSBCertificateValidity &Validity, Sbx509::TSBCertificateValidityReason &Reason)/* overload */;
	void __fastcall ValidateForTimestamping(Sbx509::TElX509Certificate* Certificate, Sbcustomcertstorage::TElCustomCertStorage* AdditionalCertificates, bool CompleteChainValidation, bool ResetCertificateCache, System::TDateTime ValidityMoment, Sbx509::TSBCertificateValidity &Validity, Sbx509::TSBCertificateValidityReason &Reason);
	void __fastcall AddTrustedCertificates(Sbcustomcertstorage::TElCustomCertStorage* Storage);
	void __fastcall ClearTrustedCertificates(void);
	void __fastcall AddBlockedCertificates(Sbcustomcertstorage::TElCustomCertStorage* Storage);
	void __fastcall ClearBlockedCertificates(void);
	void __fastcall AddKnownCertificates(Sbcustomcertstorage::TElCustomCertStorage* Storage);
	void __fastcall ClearKnownCertificates(void);
	void __fastcall AddKnownCRLs(Sbcrlstorage::TElCustomCRLStorage* Storage);
	void __fastcall ClearKnownCRLs(void);
	void __fastcall AddKnownOCSPResponses(Sbocspclient::TElOCSPResponse* Response);
	void __fastcall ClearKnownOCSPResponses(void);
	__property Sbcustomcertstorage::TElMemoryCertStorage* UsedCertificates = {read=FUsedCertificates};
	__property Sbcrlstorage::TElMemoryCRLStorage* UsedCRLs = {read=FUsedCRLs};
	__property Classes::TList* UsedOCSPResponses = {read=FUsedOCSPResponses};
	__property Sbwincertstorage::TElWinCertStorage* WinStorageTrust = {read=FWinStorageTrust};
	__property Sbwincertstorage::TElWinCertStorage* WinStorageCA = {read=FWinStorageCA};
	__property Sbwincertstorage::TElWinCertStorage* WinStorageBlocked = {read=FWinStorageBlocked};
	
__published:
	__property bool IgnoreSystemTrust = {read=FIgnoreSystemTrust, write=FIgnoreSystemTrust, nodefault};
	__property bool UseSystemStorages = {read=FUseSystemStorages, write=FUseSystemStorages, nodefault};
	__property bool CheckCRL = {read=FCheckCRL, write=FCheckCRL, default=1};
	__property bool CheckOCSP = {read=FCheckOCSP, write=FCheckOCSP, default=1};
	__property bool CheckValidityPeriodForTrusted = {read=FCheckValidityPeriodForTrusted, write=FCheckValidityPeriodForTrusted, nodefault};
	__property bool IgnoreCAKeyUsage = {read=FIgnoreCAKeyUsage, write=FIgnoreCAKeyUsage, nodefault};
	__property bool IgnoreRevocationKeyUsage = {read=FIgnoreRevocationKeyUsage, write=FIgnoreRevocationKeyUsage, nodefault};
	__property bool IgnoreSSLKeyUsage = {read=FIgnoreSSLKeyUsage, write=FIgnoreSSLKeyUsage, nodefault};
	__property bool IgnoreBadOCSPChains = {read=FIgnoreBadOCSPChains, write=FIgnoreBadOCSPChains, nodefault};
	__property bool IgnoreCABasicConstraints = {read=FIgnoreCABasicConstraints, write=FIgnoreCABasicConstraints, nodefault};
	__property bool IgnoreCANameConstraints = {read=FIgnoreCANameConstraints, write=FIgnoreCANameConstraints, nodefault};
	__property bool MandatoryCRLCheck = {read=FMandatoryCRLCheck, write=FMandatoryCRLCheck, default=1};
	__property bool MandatoryOCSPCheck = {read=FMandatoryOCSPCheck, write=FMandatoryOCSPCheck, default=1};
	__property bool MandatoryRevocationCheck = {read=FMandatoryRevocationCheck, write=FMandatoryRevocationCheck, default=1};
	__property bool ValidateInvalidCertificates = {read=FValidateInvalidCertificates, write=FValidateInvalidCertificates, nodefault};
	__property bool ForceCompleteChainValidationForTrusted = {read=FForceCompleteChainValidationForTrusted, write=FForceCompleteChainValidationForTrusted, default=1};
	__property bool ForceRevocationCheckForRoot = {read=FForceRevocationCheckForRoot, write=FForceRevocationCheckForRoot, default=1};
	__property bool OfflineMode = {read=FOfflineMode, write=FOfflineMode, nodefault};
	__property int RevocationMomentGracePeriod = {read=FRevocationMomentGracePeriod, write=FRevocationMomentGracePeriod, nodefault};
	__property bool ImplicitlyTrustSelfSignedCertificates = {read=FImplicitlyTrustSelfSignedCertificates, write=FImplicitlyTrustSelfSignedCertificates, nodefault};
	__property bool PromoteLongOCSPResponses = {read=FPromoteLongOCSPResponses, write=FPromoteLongOCSPResponses, nodefault};
	__property TSBX509RevocationCheckPreference RevocationCheckPreference = {read=FRevocationCheckPreference, write=FRevocationCheckPreference, nodefault};
	__property bool LookupCRLByNameIfDPNotPresent = {read=FLookupCRLByNameIfDPNotPresent, write=FLookupCRLByNameIfDPNotPresent, nodefault};
	__property TSBCRLNeededEvent OnCRLNeeded = {read=FOnCRLNeeded, write=FOnCRLNeeded};
	__property TSBCRLRetrievedEvent OnCRLRetrieved = {read=FOnCRLRetrieved, write=FOnCRLRetrieved};
	__property TSBBeforeCRLRetrieverUseEvent OnBeforeCRLRetrieverUse = {read=FOnBeforeCRLRetrieverUse, write=FOnBeforeCRLRetrieverUse};
	__property TSBBeforeCertificateRetrieverUseEvent OnBeforeCertificateRetrieverUse = {read=FOnBeforeCertificateRetrieverUse, write=FOnBeforeCertificateRetrieverUse};
	__property TSBCACertificateRetrievedEvent OnCACertificateRetrieved = {read=FOnCACertificateRetrieved, write=FOnCACertificateRetrieved};
	__property TSBBeforeOCSPClientUseEvent OnBeforeOCSPClientUse = {read=FOnBeforeOCSPClientUse, write=FOnBeforeOCSPClientUse};
	__property TSBBeforeCertificateValidationEvent OnBeforeCertificateValidation = {read=FOnBeforeCertificateValidation, write=FOnBeforeCertificateValidation};
	__property TSBAfterCertificateValidationEvent OnAfterCertificateValidation = {read=FOnAfterCertificateValidation, write=FOnAfterCertificateValidation};
	__property TSBCACertificateNeededEvent OnCACertificateNeeded = {read=FOnCACertificateNeeded, write=FOnCACertificateNeeded};
	__property TSBAfterCRLUseEvent OnAfterCRLUse = {read=FOnAfterCRLUse, write=FOnAfterCRLUse};
	__property TSBAfterOCSPResponseUseEvent OnAfterOCSPResponseUse = {read=FOnAfterOCSPResponseUse, write=FOnAfterOCSPResponseUse};
	__property TSBOCSPResponseSignerValidEvent OnOCSPResponseSignerValid = {read=FOnOCSPResponseSignerValid, write=FOnOCSPResponseSignerValid};
	__property TSBCertificateValidatorCRLErrorEvent OnCRLError = {read=FOnCRLError, write=FOnCRLError};
	__property TSBCertificateValidatorOCSPErrorEvent OnOCSPError = {read=FOnOCSPError, write=FOnOCSPError};
};


//-- var, const, procedure ---------------------------------------------------
static const Word SB_VALIDATOR_CRL_ERROR_BASE = 0x3e8;
static const Word SB_VALIDATOR_OCSP_ERROR_BASE = 0x7d0;
static const Word SB_VALIDATOR_CRL_ERROR_VALIDATION_FAILED = 0x3e9;
static const Word SB_VALIDATOR_CRL_ERROR_NO_RETRIEVER = 0x3ea;
static const Word SB_VALIDATOR_CRL_ERROR_RETRIEVER_FAILED = 0x3eb;
static const Word SB_VALIDATOR_CRL_ERROR_NO_CRLS_RETRIEVED = 0x3ec;
static const Word SB_VALIDATOR_CRL_ERROR_CERT_REVOKED = 0x3ed;
static const Word SB_VALIDATOR_OCSP_ERROR_VALIDATION_FAILED = 0x7d1;
static const Word SB_VALIDATOR_OCSP_ERROR_NO_CLIENT = 0x7d2;
static const Word SB_VALIDATOR_OCSP_ERROR_CLIENT_FAILED = 0x7d3;
static const Word SB_VALIDATOR_OCSP_ERROR_INVALID_RESPONSE = 0x7d4;
static const Word SB_VALIDATOR_OCSP_ERROR_CERT_REVOKED = 0x7d5;
extern PACKAGE void __fastcall Register(void);

}	/* namespace Sbcertvalidator */
using namespace Sbcertvalidator;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbcertvalidatorHPP
