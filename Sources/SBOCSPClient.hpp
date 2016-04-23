// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbocspclient.pas' rev: 21.00

#ifndef SbocspclientHPP
#define SbocspclientHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbstringlist.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbencoding.hpp>	// Pascal unit
#include <Sbpem.hpp>	// Pascal unit
#include <Sbasn1.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit
#include <Sbx509.hpp>	// Pascal unit
#include <Sbx509ext.hpp>	// Pascal unit
#include <Sbsha.hpp>	// Pascal unit
#include <Sbrdn.hpp>	// Pascal unit
#include <Sbocspcommon.hpp>	// Pascal unit
#include <Sbpublickeycrypto.hpp>	// Pascal unit
#include <Sbpkcs7utils.hpp>	// Pascal unit
#include <Sbpkicommon.hpp>	// Pascal unit
#include <Sbcmsutils.hpp>	// Pascal unit
#include <Sbhashfunction.hpp>	// Pascal unit
#include <Sbcustomcertstorage.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbocspclient
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElOCSPClient;
class DELPHICLASS TElOCSPResponse;
#pragma option push -b-
enum TSBOCSPClientOption { ocoIncludeVersion, ocoIncludeSupportedResponseTypes };
#pragma option pop

typedef Set<TSBOCSPClientOption, ocoIncludeVersion, ocoIncludeSupportedResponseTypes>  TSBOCSPClientOptions;

class PASCALIMPLEMENTATION TElOCSPClient : public Sbocspcommon::TElOCSPClass
{
	typedef Sbocspcommon::TElOCSPClass inherited;
	
private:
	typedef DynamicArray<System::TDateTime> _TElOCSPClient__1;
	
	typedef DynamicArray<System::TDateTime> _TElOCSPClient__2;
	
	typedef DynamicArray<System::TDateTime> _TElOCSPClient__3;
	
	typedef DynamicArray<Sbx509ext::TSBCRLReasonFlag> _TElOCSPClient__4;
	
	typedef DynamicArray<Sbocspcommon::TElOCSPCertificateStatus> _TElOCSPClient__5;
	
	
protected:
	Sbcustomcertstorage::TElCustomCertStorage* FCertStorage;
	Sbcustomcertstorage::TElCustomCertStorage* FIssuerCertStorage;
	Sbcustomcertstorage::TElCustomCertStorage* FReplyCertificates;
	System::TDateTime FReplyProducedAt;
	_TElOCSPClient__1 FThisUpdate;
	_TElOCSPClient__2 FNextUpdate;
	_TElOCSPClient__3 FRevocationTime;
	_TElOCSPClient__4 FRevocationReason;
	_TElOCSPClient__5 FCertStatus;
	Sbtypes::ByteArray FNonce;
	Sbtypes::ByteArray FReplyNonce;
	Sbrdn::TElRelativeDistinguishedName* FServerName;
	Sbtypes::ByteArray FServerCertKeyHash;
	System::UnicodeString FURL;
	int FNesting;
	int FParseState;
	int FParseState2;
	int FParseCert;
	Sbocspcommon::TElOCSPServerError FRespStatus;
	bool FIncludeSignature;
	TElOCSPResponse* FResponse;
	TSBOCSPClientOptions FOptions;
	int FSignatureAlgorithm;
	virtual void __fastcall Notification(Classes::TComponent* AComponent, Classes::TOperation AOperation);
	bool __fastcall ParseResponseData(const Sbtypes::ByteArray Data, Sbcustomcertstorage::TElCustomCertStorage* Certificates, Sbx509::TElX509Certificate* &SignCert);
	bool __fastcall ValidateResponseSignature(const Sbtypes::ByteArray ReplyBuf, const Sbtypes::ByteArray SignatureAlg, const Sbtypes::ByteArray SignatureParam, const Sbtypes::ByteArray SignatureBody, Sbx509::TElX509Certificate* SignCertificate);
	int __fastcall WriteRequestList(Sbtypes::ByteArray &List);
	Sbtypes::ByteArray __fastcall WriteRequestorName(void);
	Sbtypes::ByteArray __fastcall WriteExtensions(void);
	Sbtypes::ByteArray __fastcall CalculateSignature(const Sbtypes::ByteArray r, int SigAlg, Sbx509::TElX509Certificate* Cert);
	Sbtypes::ByteArray __fastcall DoSignRequest(const Sbtypes::ByteArray TBS);
	void __fastcall SetCertStorage(Sbcustomcertstorage::TElCustomCertStorage* Value);
	void __fastcall SetIssuerCertStorage(Sbcustomcertstorage::TElCustomCertStorage* Value);
	void __fastcall SetReplyNonce(const Sbtypes::ByteArray V);
	void __fastcall SetServerCertKeyHash(const Sbtypes::ByteArray V);
	Sbocspcommon::TElOCSPCertificateStatus __fastcall GetCertStatus(int Index);
	System::TDateTime __fastcall GetThisUpdate(int Index);
	System::TDateTime __fastcall GetNextUpdate(int Index);
	System::TDateTime __fastcall GetRevocationTime(int Index);
	Sbx509ext::TSBCRLReasonFlag __fastcall GetRevocationReason(int Index);
	
public:
	__fastcall virtual TElOCSPClient(Classes::TComponent* Owner);
	__fastcall virtual ~TElOCSPClient(void);
	int __fastcall CreateRequest(Sbtypes::ByteArray &Request);
	int __fastcall ProcessReply(const Sbtypes::ByteArray Reply, Sbocspcommon::TElOCSPServerError &ServerResult);
	virtual int __fastcall PerformRequest(Sbocspcommon::TElOCSPServerError &ServerResult, Sbtypes::ByteArray &Reply);
	virtual bool __fastcall SupportsLocation(const System::UnicodeString URI) = 0 ;
	__property System::TDateTime ReplyProducedAt = {read=FReplyProducedAt};
	__property Sbtypes::ByteArray ReplyNonce = {read=FReplyNonce};
	__property Sbcustomcertstorage::TElCustomCertStorage* ReplyCertificates = {read=FReplyCertificates};
	__property Sbrdn::TElRelativeDistinguishedName* ServerName = {read=FServerName};
	__property Sbtypes::ByteArray ServerCertKeyHash = {read=FServerCertKeyHash, write=SetServerCertKeyHash};
	__property Sbocspcommon::TElOCSPCertificateStatus CertStatus[int Index] = {read=GetCertStatus};
	__property System::TDateTime RevocationTime[int Index] = {read=GetRevocationTime};
	__property Sbx509ext::TSBCRLReasonFlag RevocationReason[int Index] = {read=GetRevocationReason};
	__property System::TDateTime ThisUpdate[int Index] = {read=GetThisUpdate};
	__property System::TDateTime NextUpdate[int Index] = {read=GetNextUpdate};
	__property TElOCSPResponse* Response = {read=FResponse};
	__property Sbtypes::ByteArray Nonce = {read=FNonce, write=FNonce};
	
__published:
	__property Sbcustomcertstorage::TElCustomCertStorage* CertStorage = {read=FCertStorage, write=SetCertStorage};
	__property Sbcustomcertstorage::TElCustomCertStorage* IssuerCertStorage = {read=FIssuerCertStorage, write=SetIssuerCertStorage};
	__property bool IncludeSignature = {read=FIncludeSignature, write=FIncludeSignature, nodefault};
	__property int SignatureAlgorithm = {read=FSignatureAlgorithm, write=FSignatureAlgorithm, nodefault};
	__property TSBOCSPClientOptions Options = {read=FOptions, write=FOptions, nodefault};
	__property System::UnicodeString URL = {read=FURL, write=FURL};
};

typedef TElOCSPClient ElOCSPClient
class DELPHICLASS TElOCSPResponderID;
class PASCALIMPLEMENTATION TElOCSPResponderID : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	Sbrdn::TElRelativeDistinguishedName* FName;
	Sbtypes::ByteArray FSHA1KeyHash;
	void __fastcall SetSHA1KeyHash(const Sbtypes::ByteArray V);
	
public:
	__fastcall TElOCSPResponderID(void);
	__fastcall virtual ~TElOCSPResponderID(void);
	void __fastcall Clear(void);
	__property Sbrdn::TElRelativeDistinguishedName* Name = {read=FName};
	__property Sbtypes::ByteArray SHA1KeyHash = {read=FSHA1KeyHash, write=SetSHA1KeyHash};
};


class DELPHICLASS TElOCSPSingleResponse;
class PASCALIMPLEMENTATION TElOCSPSingleResponse : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	int FHashAlgorithm;
	Sbtypes::ByteArray FIssuerNameHash;
	Sbtypes::ByteArray FIssuerKeyHash;
	Sbtypes::ByteArray FSerialNumber;
	Sbocspcommon::TElOCSPCertificateStatus FCertStatus;
	System::TDateTime FThisUpdate;
	System::TDateTime FNextUpdate;
	System::TDateTime FRevocationTime;
	Sbx509ext::TSBCRLReasonFlags FRevocationReasons;
	
public:
	__fastcall virtual ~TElOCSPSingleResponse(void);
	void __fastcall LoadFromTag(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	bool __fastcall CertMatches(Sbx509::TElX509Certificate* Cert, Sbx509::TElX509Certificate* Issuer = (Sbx509::TElX509Certificate*)(0x0));
	bool __fastcall SignerMatches(Sbpkcs7utils::TElPKCS7Issuer* Signer, Sbx509::TElX509Certificate* Issuer = (Sbx509::TElX509Certificate*)(0x0));
	__property int HashAlgorithm = {read=FHashAlgorithm, nodefault};
	__property Sbtypes::ByteArray IssuerNameHash = {read=FIssuerNameHash};
	__property Sbtypes::ByteArray IssuerKeyHash = {read=FIssuerKeyHash};
	__property Sbtypes::ByteArray SerialNumber = {read=FSerialNumber};
	__property Sbocspcommon::TElOCSPCertificateStatus CertStatus = {read=FCertStatus, nodefault};
	__property System::TDateTime ThisUpdate = {read=FThisUpdate};
	__property System::TDateTime NextUpdate = {read=FNextUpdate};
	__property System::TDateTime RevocationTime = {read=FRevocationTime};
	__property Sbx509ext::TSBCRLReasonFlags RevocationReasons = {read=FRevocationReasons, nodefault};
public:
	/* TObject.Create */ inline __fastcall TElOCSPSingleResponse(void) : System::TObject() { }
	
};


class PASCALIMPLEMENTATION TElOCSPResponse : public Classes::TPersistent
{
	typedef Classes::TPersistent inherited;
	
private:
	int FSignatureAlgorithm;
	Sbcustomcertstorage::TElMemoryCertStorage* FCertificates;
	TElOCSPResponderID* FResponderID;
	System::TDateTime FProducedAt;
	Classes::TList* FResponses;
	Sbtypes::ByteArray FData;
	Sbtypes::ByteArray FDataBasic;
	Sbtypes::ByteArray FTBS;
	Sbtypes::ByteArray FSig;
	int FSigAlg;
	Sbtypes::ByteArray FSigAlgOID;
	Sbcmsutils::TSBCMSCertificateNeededEvent FOnCertificateNeeded;
	int __fastcall GetResponseCount(void);
	TElOCSPSingleResponse* __fastcall GetResponse(int Index);
	
public:
	__fastcall TElOCSPResponse(void);
	__fastcall virtual ~TElOCSPResponse(void);
	void __fastcall Clear(void);
	virtual void __fastcall Assign(Classes::TPersistent* Source);
	void __fastcall Load(void * Buffer, int Size);
	bool __fastcall Save(void * Buffer, int &Size);
	bool __fastcall SaveBasic(void * Buffer, int &Size);
	bool __fastcall EqualsTo(TElOCSPResponse* OtherResponse);
	int __fastcall FindResponse(Sbx509::TElX509Certificate* Cert, Sbx509::TElX509Certificate* Issuer = (Sbx509::TElX509Certificate*)(0x0))/* overload */;
	int __fastcall FindResponse(Sbpkcs7utils::TElPKCS7Issuer* Signer, Sbx509::TElX509Certificate* Issuer = (Sbx509::TElX509Certificate*)(0x0))/* overload */;
	Sbx509::TElX509Certificate* __fastcall GetSignerCertificate(void);
	bool __fastcall IsSignerCertificate(Sbx509::TElX509Certificate* Certificate);
	Sbpkicommon::TSBCMSSignatureValidity __fastcall Validate(void)/* overload */;
	Sbpkicommon::TSBCMSSignatureValidity __fastcall Validate(Sbx509::TElX509Certificate* CACertificate)/* overload */;
	__property int SignatureAlgorithm = {read=FSignatureAlgorithm, nodefault};
	__property Sbcustomcertstorage::TElMemoryCertStorage* Certificates = {read=FCertificates};
	__property TElOCSPResponderID* ResponderID = {read=FResponderID};
	__property System::TDateTime ProducedAt = {read=FProducedAt};
	__property TElOCSPSingleResponse* Responses[int Index] = {read=GetResponse};
	__property int ResponseCount = {read=GetResponseCount, nodefault};
	__property Sbcmsutils::TSBCMSCertificateNeededEvent OnCertificateNeeded = {read=FOnCertificateNeeded, write=FOnCertificateNeeded};
};


typedef void __fastcall (__closure *TSBOCSPValidationNeededEvent)(System::TObject* Sender, const System::UnicodeString URL, Classes::TStream* RequestStream, Classes::TStream* ReplyStream, bool &Succeeded);

class DELPHICLASS TElFileOCSPClient;
class PASCALIMPLEMENTATION TElFileOCSPClient : public TElOCSPClient
{
	typedef TElOCSPClient inherited;
	
private:
	TSBOCSPValidationNeededEvent FOnOCSPValidationNeeded;
	
public:
	virtual bool __fastcall SupportsLocation(const System::UnicodeString URI);
	virtual int __fastcall PerformRequest(Sbocspcommon::TElOCSPServerError &ServerResult, Sbtypes::ByteArray &Reply);
	
__published:
	__property TSBOCSPValidationNeededEvent OnOCSPValidationNeeded = {read=FOnOCSPValidationNeeded, write=FOnOCSPValidationNeeded};
public:
	/* TElOCSPClient.Create */ inline __fastcall virtual TElFileOCSPClient(Classes::TComponent* Owner) : TElOCSPClient(Owner) { }
	/* TElOCSPClient.Destroy */ inline __fastcall virtual ~TElFileOCSPClient(void) { }
	
};

typedef TElFileOCSPClient ElFileOCSPClient
class DELPHICLASS TElCustomOCSPClientFactory;
class PASCALIMPLEMENTATION TElCustomOCSPClientFactory : public System::TObject
{
	typedef System::TObject inherited;
	
public:
	virtual bool __fastcall SupportsLocation(const System::UnicodeString URI) = 0 ;
	virtual TElOCSPClient* __fastcall GetClientInstance(System::TObject* Validator) = 0 ;
public:
	/* TObject.Create */ inline __fastcall TElCustomOCSPClientFactory(void) : System::TObject() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TElCustomOCSPClientFactory(void) { }
	
};

typedef TElCustomOCSPClientFactory ElCustomOCSPClientFactory
class DELPHICLASS TElOCSPClientManager;
class PASCALIMPLEMENTATION TElOCSPClientManager : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	Classes::TList* FFactoryList;
	
public:
	__fastcall TElOCSPClientManager(void);
	__fastcall virtual ~TElOCSPClientManager(void);
	TElOCSPClient* __fastcall FindOCSPClientByLocation(const System::UnicodeString Location, System::TObject* Validator);
	void __fastcall RegisterOCSPClientFactory(TElCustomOCSPClientFactory* Factory);
	void __fastcall UnregisterOCSPClientFactory(TElCustomOCSPClientFactory* Factory);
};

typedef TElOCSPClientManager ElOCSPClientManager
//-- var, const, procedure ---------------------------------------------------
extern PACKAGE void __fastcall Register(void);
extern PACKAGE TElOCSPClientManager* __fastcall OCSPClientManagerAddRef(void);
extern PACKAGE void __fastcall OCSPClientManagerRelease(void);

}	/* namespace Sbocspclient */
using namespace Sbocspclient;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbocspclientHPP
