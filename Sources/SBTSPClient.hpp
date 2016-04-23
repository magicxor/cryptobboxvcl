// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbtspclient.pas' rev: 21.00

#ifndef SbtspclientHPP
#define SbtspclientHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbencoding.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbpem.hpp>	// Pascal unit
#include <Sbasn1.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit
#include <Sbx509.hpp>	// Pascal unit
#include <Sbx509ext.hpp>	// Pascal unit
#include <Sbpkcs7.hpp>	// Pascal unit
#include <Sbpkcs7utils.hpp>	// Pascal unit
#include <Sbpkicommon.hpp>	// Pascal unit
#include <Sbtspcommon.hpp>	// Pascal unit
#include <Sbcustomcertstorage.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbtspclient
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElClientTSPInfo;
class PASCALIMPLEMENTATION TElClientTSPInfo : public Sbtspcommon::TElTSPInfo
{
	typedef Sbtspcommon::TElTSPInfo inherited;
	
protected:
	System::TObject* FOwner;
	System::TObject* FVerifier;
	Sbtypes::ByteArray FMessageImprint;
	Sbtypes::ByteArray FResponseNonce;
	Sbtypes::ByteArray FCMS;
	bool FIgnoreBadSignature;
	int FLastValidationResult;
	int FHashAlgorithm;
	Sbtypes::ByteArray FHashedData;
	void __fastcall ProcessMessageImprint(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	Sbcustomcertstorage::TElCustomCertStorage* __fastcall GetCertificates(void);
	
public:
	__fastcall virtual TElClientTSPInfo(void);
	__fastcall virtual ~TElClientTSPInfo(void);
	int __fastcall ParseCMS(const Sbtypes::ByteArray CMSData)/* overload */;
	int __fastcall ParseCMS(const Sbtypes::ByteArray CMSData, bool NoOuterInfo)/* overload */;
	virtual void __fastcall Reset(void);
	Sbx509::TElX509Certificate* __fastcall GetSignerCertificate(void);
	__property Sbtypes::ByteArray Nonce = {read=FNonce, write=SetNonce};
	__property Sbcustomcertstorage::TElCustomCertStorage* Certificates = {read=GetCertificates};
	__property Sbtypes::ByteArray MessageImprint = {read=FMessageImprint};
	__property Sbtypes::ByteArray ResponseNonce = {read=FResponseNonce};
	__property Sbtypes::ByteArray CMS = {read=FCMS};
	__property bool IgnoreBadSignature = {read=FIgnoreBadSignature, write=FIgnoreBadSignature, nodefault};
	__property int LastValidationResult = {read=FLastValidationResult, nodefault};
	__property int HashAlgorithm = {read=FHashAlgorithm, nodefault};
	__property Sbtypes::ByteArray HashedData = {read=FHashedData};
};

typedef TElClientTSPInfo ElClientTSPInfo
#pragma option push -b-
enum TSBTSPOption { tsoIncludeReqPolicy, tsoIgnoreBadSignature, tsoIgnoreBadNonce };
#pragma option pop

typedef Set<TSBTSPOption, tsoIncludeReqPolicy, tsoIgnoreBadNonce>  TSBTSPOptions;

#pragma option push -b-
enum TSBTSPRequestFormat { tsfRFC3161, tsfCMS };
#pragma option pop

class DELPHICLASS TElCustomTSPClient;
typedef void __fastcall (__closure *TSBTSPBeforeSignEvent)(System::TObject* Sender, System::TObject* Signer);

typedef void __fastcall (__closure *TSBTSPErrorEvent)(System::TObject* Sender, int ResultCode);

class PASCALIMPLEMENTATION TElCustomTSPClient : public Sbtspcommon::TElTSPClass
{
	typedef Sbtspcommon::TElTSPClass inherited;
	
protected:
	TElClientTSPInfo* FTSPInfo;
	int FHashAlgorithm;
	bool FIncludeCertificates;
	Sbtypes::ByteArray FReqPolicy;
	TSBTSPOptions FOptions;
	TSBTSPRequestFormat FRequestFormat;
	Sbcustomcertstorage::TElCustomCertStorage* FCertStorage;
	TSBTSPBeforeSignEvent FOnBeforeSign;
	Sbcustomcertstorage::TSBCertificateValidationEvent FOnCertificateValidate;
	TSBTSPErrorEvent FOnTSPError;
	void __fastcall DoTSPError(int ResultCode);
	virtual void __fastcall DoCertificateValidate(Sbx509::TElX509Certificate* Certificate, Sbcustomcertstorage::TElCustomCertStorage* AdditionalCertificates, Sbx509::TSBCertificateValidity &Validity, Sbx509::TSBCertificateValidityReason &Reason, bool &DoContinue);
	int __fastcall CreateRequest(const Sbtypes::ByteArray HashedData, Sbtypes::ByteArray &Request);
	int __fastcall CreateRequestRFC3161(const Sbtypes::ByteArray HashedData, Sbtypes::ByteArray &Request);
	int __fastcall CreateRequestCMS(const Sbtypes::ByteArray HashedData, Sbtypes::ByteArray &Request);
	Sbtypes::ByteArray __fastcall MessageImprint(const Sbtypes::ByteArray HashedData);
	int __fastcall ProcessReply(const Sbtypes::ByteArray Reply, /* out */ Sbpkicommon::TSBPKIStatus &ServerResult, /* out */ int &FailureInfo, /* out */ Sbtypes::ByteArray &ReplyCMS);
	int __fastcall MatchTSPRequirements(const Sbtypes::ByteArray HashedData);
	virtual void __fastcall Notification(Classes::TComponent* AComponent, Classes::TOperation AOperation);
	void __fastcall SetCertStorage(Sbcustomcertstorage::TElCustomCertStorage* Value);
	void __fastcall SetReqPolicy(const Sbtypes::ByteArray V);
	
public:
	__fastcall virtual TElCustomTSPClient(Classes::TComponent* Owner);
	__fastcall virtual ~TElCustomTSPClient(void);
	virtual int __fastcall Timestamp(const Sbtypes::ByteArray HashedData, /* out */ Sbpkicommon::TSBPKIStatus &ServerResult, /* out */ int &FailureInfo, /* out */ Sbtypes::ByteArray &ReplyCMS) = 0 ;
	__property TElClientTSPInfo* TSPInfo = {read=FTSPInfo};
	__property Sbtypes::ByteArray ReqPolicy = {read=FReqPolicy, write=SetReqPolicy};
	
__published:
	__property int HashAlgorithm = {read=FHashAlgorithm, write=FHashAlgorithm, nodefault};
	__property bool IncludeCertificates = {read=FIncludeCertificates, write=FIncludeCertificates, nodefault};
	__property TSBTSPOptions Options = {read=FOptions, write=FOptions, nodefault};
	__property TSBTSPRequestFormat RequestFormat = {read=FRequestFormat, write=FRequestFormat, nodefault};
	__property Sbcustomcertstorage::TElCustomCertStorage* CertStorage = {read=FCertStorage, write=SetCertStorage};
	__property Sbcustomcertstorage::TSBCertificateValidationEvent OnCertificateValidate = {read=FOnCertificateValidate, write=FOnCertificateValidate};
	__property TSBTSPBeforeSignEvent OnBeforeSign = {read=FOnBeforeSign, write=FOnBeforeSign};
	__property TSBTSPErrorEvent OnTSPError = {read=FOnTSPError, write=FOnTSPError};
};

typedef TElCustomTSPClient ElCustomTSPClient
typedef void __fastcall (__closure *TSBTimestampNeededEvent)(System::TObject* Sender, Classes::TStream* RequestStream, Classes::TStream* ReplyStream, bool &Succeeded);

class DELPHICLASS TElFileTSPClient;
class PASCALIMPLEMENTATION TElFileTSPClient : public TElCustomTSPClient
{
	typedef TElCustomTSPClient inherited;
	
protected:
	TSBTimestampNeededEvent FOnTimestampNeeded;
	bool FHashOnlyNeeded;
	
public:
	virtual int __fastcall Timestamp(const Sbtypes::ByteArray HashedData, /* out */ Sbpkicommon::TSBPKIStatus &ServerResult, /* out */ int &FailureInfo, /* out */ Sbtypes::ByteArray &ReplyCMS);
	
__published:
	__property bool HashOnlyNeeded = {read=FHashOnlyNeeded, write=FHashOnlyNeeded, nodefault};
	__property TSBTimestampNeededEvent OnTimestampNeeded = {read=FOnTimestampNeeded, write=FOnTimestampNeeded};
public:
	/* TElCustomTSPClient.Create */ inline __fastcall virtual TElFileTSPClient(Classes::TComponent* Owner) : TElCustomTSPClient(Owner) { }
	/* TElCustomTSPClient.Destroy */ inline __fastcall virtual ~TElFileTSPClient(void) { }
	
};

typedef TElFileTSPClient ElFileTSPClient
//-- var, const, procedure ---------------------------------------------------
extern PACKAGE void __fastcall Register(void);

}	/* namespace Sbtspclient */
using namespace Sbtspclient;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbtspclientHPP
