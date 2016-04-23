// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbx509ext.pas' rev: 21.00

#ifndef Sbx509extHPP
#define Sbx509extHPP

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
#include <Sbrdn.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbasn1.hpp>	// Pascal unit
#include <Sbpkcs7utils.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbx509ext
{
//-- type declarations -------------------------------------------------------
#pragma option push -b-
enum TSBCertificateExtension { ceAuthorityKeyIdentifier, ceSubjectKeyIdentifier, ceKeyUsage, cePrivateKeyUsagePeriod, ceCertificatePolicies, cePolicyMappings, ceSubjectAlternativeName, ceIssuerAlternativeName, ceBasicConstraints, ceNameConstraints, cePolicyConstraints, ceExtendedKeyUsage, ceCRLDistributionPoints, ceAuthorityInformationAccess, ceNetscapeCertType, ceNetscapeBaseURL, ceNetscapeRevokeURL, ceNetscapeCARevokeURL, ceNetscapeRenewalURL, ceNetscapeCAPolicyURL, ceNetscapeServerName, ceNetscapeComment, ceCommonName, ceSubjectDirectoryAttributes };
#pragma option pop

typedef Set<TSBCertificateExtension, ceAuthorityKeyIdentifier, ceSubjectDirectoryAttributes>  TSBCertificateExtensions;

#pragma option push -b-
enum TSBKeyUsageType { kuDigitalSignature, kuNonRepudiation, kuKeyEncipherment, kuDataEncipherment, kuKeyAgreement, kuKeyCertSign, kuCRLSign, kuEncipherOnly, kuDecipherOnly };
#pragma option pop

typedef Set<TSBKeyUsageType, kuDigitalSignature, kuDecipherOnly>  TSBKeyUsage;

#pragma option push -b-
enum TSBCRLReasonFlag { rfUnspecified, rfKeyCompromise, rfCACompromise, rfAffiliationChanged, rfSuperseded, rfCessationOfOperation, rfCertificateHold, rfObsolete1, rfRemoveFromCRL, rfPrivilegeWithdrawn, rfAACompromise };
#pragma option pop

typedef Set<TSBCRLReasonFlag, rfUnspecified, rfAACompromise>  TSBCRLReasonFlags;

class DELPHICLASS EElCertificateError;
class PASCALIMPLEMENTATION EElCertificateError : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElCertificateError(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElCertificateError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElCertificateError(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElCertificateError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElCertificateError(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElCertificateError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElCertificateError(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElCertificateError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElCertificateError(void) { }
	
};


#pragma option push -b-
enum TSBGeneralName { gnRFC822Name, gnDNSName, gnDirectoryName, gnEdiPartyName, gnUniformResourceIdentifier, gnIPAddress, gnRegisteredID, gnOtherName, gnUnknown, gnPermanentIdentifier };
#pragma option pop

class DELPHICLASS TElEDIPartyName;
class PASCALIMPLEMENTATION TElEDIPartyName : public Classes::TPersistent
{
	typedef Classes::TPersistent inherited;
	
private:
	System::UnicodeString FNameAssigner;
	System::UnicodeString FPartyName;
	
public:
	__property System::UnicodeString NameAssigner = {read=FNameAssigner, write=FNameAssigner};
	__property System::UnicodeString PartyName = {read=FPartyName, write=FPartyName};
public:
	/* TPersistent.Destroy */ inline __fastcall virtual ~TElEDIPartyName(void) { }
	
public:
	/* TObject.Create */ inline __fastcall TElEDIPartyName(void) : Classes::TPersistent() { }
	
};

typedef TElEDIPartyName ElEDIPartyName
class DELPHICLASS TElOtherName;
class PASCALIMPLEMENTATION TElOtherName : public Classes::TPersistent
{
	typedef Classes::TPersistent inherited;
	
private:
	Sbtypes::ByteArray FOID;
	Sbtypes::ByteArray FValue;
	void __fastcall SetOID(const Sbtypes::ByteArray V);
	void __fastcall SetValue(const Sbtypes::ByteArray V);
	
public:
	__property Sbtypes::ByteArray OID = {read=FOID, write=SetOID};
	__property Sbtypes::ByteArray Value = {read=FValue, write=SetValue};
public:
	/* TPersistent.Destroy */ inline __fastcall virtual ~TElOtherName(void) { }
	
public:
	/* TObject.Create */ inline __fastcall TElOtherName(void) : Classes::TPersistent() { }
	
};

typedef TElOtherName ElOtherName
class DELPHICLASS TElPermanentIdentifier;
class PASCALIMPLEMENTATION TElPermanentIdentifier : public Classes::TPersistent
{
	typedef Classes::TPersistent inherited;
	
protected:
	Sbtypes::ByteArray FPermanentIdentifier;
	Sbtypes::ByteArray FAssigner;
	void __fastcall SetPermanentIdentifier(const Sbtypes::ByteArray V);
	void __fastcall SetAssigner(const Sbtypes::ByteArray V);
	
public:
	__property Sbtypes::ByteArray PermanentIdentifier = {read=FPermanentIdentifier, write=SetPermanentIdentifier};
	__property Sbtypes::ByteArray Assigner = {read=FAssigner, write=SetAssigner};
public:
	/* TPersistent.Destroy */ inline __fastcall virtual ~TElPermanentIdentifier(void) { }
	
public:
	/* TObject.Create */ inline __fastcall TElPermanentIdentifier(void) : Classes::TPersistent() { }
	
};

typedef TElPermanentIdentifier ElPermanentIdentifier
class DELPHICLASS TElGeneralName;
class PASCALIMPLEMENTATION TElGeneralName : public Classes::TPersistent
{
	typedef Classes::TPersistent inherited;
	
protected:
	System::UnicodeString FRFC822Name;
	System::UnicodeString FDNSName;
	Sbrdn::TElRelativeDistinguishedName* FDirectoryName;
	TElEDIPartyName* FEdiPartyName;
	System::UnicodeString FUniformResourceIdentifier;
	System::UnicodeString FIpAddress;
	Sbtypes::ByteArray FIpAddressBytes;
	Sbtypes::ByteArray FRegisteredID;
	TElOtherName* FOtherName;
	TElPermanentIdentifier* FPermanentIdentifier;
	TSBGeneralName FNameType;
	void __fastcall TryKnownOtherNames(void);
	void __fastcall SaveKnownOtherNames(void);
	void __fastcall ParsePermanentIdentifier(void * Buffer, int Size);
	void __fastcall SavePermanentIdentifier(Sbtypes::ByteArray &OID, Sbtypes::ByteArray &Content);
	HIDESBASE bool __fastcall Equals(TElGeneralName* Other);
	bool __fastcall GetIsEmpty(void);
	void __fastcall SetRegisteredID(const Sbtypes::ByteArray V);
	
public:
	__fastcall TElGeneralName(void);
	__fastcall virtual ~TElGeneralName(void);
	virtual void __fastcall Assign(Classes::TPersistent* Source);
	virtual void __fastcall AssignTo(Classes::TPersistent* Dest);
	bool __fastcall LoadFromTag(Sbasn1tree::TElASN1CustomTag* Tag);
	bool __fastcall SaveToTag(Sbasn1tree::TElASN1SimpleTag* Tag);
	__property System::UnicodeString RFC822Name = {read=FRFC822Name, write=FRFC822Name};
	__property System::UnicodeString DNSName = {read=FDNSName, write=FDNSName};
	__property Sbrdn::TElRelativeDistinguishedName* DirectoryName = {read=FDirectoryName};
	__property TElEDIPartyName* EdiPartyName = {read=FEdiPartyName};
	__property System::UnicodeString UniformResourceIdentifier = {read=FUniformResourceIdentifier, write=FUniformResourceIdentifier};
	__property System::UnicodeString IpAddress = {read=FIpAddress, write=FIpAddress};
	__property Sbtypes::ByteArray IpAddressBytes = {read=FIpAddressBytes, write=FIpAddressBytes};
	__property Sbtypes::ByteArray RegisteredID = {read=FRegisteredID, write=SetRegisteredID};
	__property TElOtherName* OtherName = {read=FOtherName};
	__property TElPermanentIdentifier* PermanentIdentifier = {read=FPermanentIdentifier};
	__property TSBGeneralName NameType = {read=FNameType, write=FNameType, nodefault};
	__property bool IsEmpty = {read=GetIsEmpty, nodefault};
};

typedef TElGeneralName ElGeneralName
class DELPHICLASS TElGeneralNames;
class PASCALIMPLEMENTATION TElGeneralNames : public Classes::TPersistent
{
	typedef Classes::TPersistent inherited;
	
private:
	Classes::TList* FNames;
	
protected:
	int __fastcall GetCount(void);
	TElGeneralName* __fastcall GetNames(int Index);
	bool __fastcall Contains(TElGeneralNames* Other);
	
public:
	__fastcall TElGeneralNames(void);
	__fastcall virtual ~TElGeneralNames(void);
	virtual void __fastcall Assign(Classes::TPersistent* Source);
	virtual void __fastcall AssignTo(Classes::TPersistent* Dest);
	HIDESBASE bool __fastcall Equals(TElGeneralNames* Other);
	bool __fastcall HasCommon(TElGeneralNames* Other);
	int __fastcall Add(void);
	void __fastcall Remove(int Index);
	void __fastcall Clear(void);
	bool __fastcall ContainsEmailAddress(const System::UnicodeString Addr);
	int __fastcall FindNameByType(TSBGeneralName NameType, int StartIndex = 0x0);
	bool __fastcall LoadFromTag(Sbasn1tree::TElASN1ConstrainedTag* Tag, bool AllowRDN = false);
	bool __fastcall SaveToTag(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	__property TElGeneralName* Names[int Index] = {read=GetNames};
	__property int Count = {read=GetCount, nodefault};
};

typedef TElGeneralNames ElGeneralNames
class DELPHICLASS TElCustomExtension;
class PASCALIMPLEMENTATION TElCustomExtension : public Classes::TPersistent
{
	typedef Classes::TPersistent inherited;
	
protected:
	bool FCritical;
	Sbtypes::ByteArray FOID;
	Sbtypes::ByteArray FValue;
	virtual void __fastcall Clear(void);
	void __fastcall RaiseInvalidExtensionError(void);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	virtual Sbtypes::ByteArray __fastcall GetValue(void);
	
public:
	__fastcall TElCustomExtension(void);
	__fastcall virtual ~TElCustomExtension(void);
	virtual void __fastcall SaveToTag(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	__property bool Critical = {read=FCritical, write=FCritical, default=0};
	__property Sbtypes::ByteArray OID = {read=GetOID, write=SetOID};
	__property Sbtypes::ByteArray Value = {read=GetValue, write=SetValue};
};

typedef TElCustomExtension ElCustomExtension
class DELPHICLASS TElAuthorityKeyIdentifierExtension;
class PASCALIMPLEMENTATION TElAuthorityKeyIdentifierExtension : public TElCustomExtension
{
	typedef TElCustomExtension inherited;
	
protected:
	Sbtypes::ByteArray FKeyIdentifier;
	TElGeneralNames* FAuthorityCertIssuer;
	Sbtypes::ByteArray FAuthorityCertSerial;
	virtual void __fastcall Clear(void);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	virtual Sbtypes::ByteArray __fastcall GetValue(void);
	void __fastcall SetKeyIdentifier(const Sbtypes::ByteArray V);
	void __fastcall SetAuthorityCertSerial(const Sbtypes::ByteArray V);
	
public:
	__fastcall TElAuthorityKeyIdentifierExtension(void);
	__fastcall virtual ~TElAuthorityKeyIdentifierExtension(void);
	__property Sbtypes::ByteArray KeyIdentifier = {read=FKeyIdentifier, write=SetKeyIdentifier};
	__property TElGeneralNames* AuthorityCertIssuer = {read=FAuthorityCertIssuer};
	__property Sbtypes::ByteArray AuthorityCertSerial = {read=FAuthorityCertSerial, write=SetAuthorityCertSerial};
};

typedef TElAuthorityKeyIdentifierExtension ElAuthorityKeyIdentifierExtension
class DELPHICLASS TElSubjectKeyIdentifierExtension;
class PASCALIMPLEMENTATION TElSubjectKeyIdentifierExtension : public TElCustomExtension
{
	typedef TElCustomExtension inherited;
	
protected:
	Sbtypes::ByteArray FKeyIdentifier;
	virtual void __fastcall Clear(void);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	void __fastcall SetKeyIdentifier(const Sbtypes::ByteArray V);
	
public:
	__property Sbtypes::ByteArray KeyIdentifier = {read=FKeyIdentifier, write=SetKeyIdentifier};
public:
	/* TElCustomExtension.Create */ inline __fastcall TElSubjectKeyIdentifierExtension(void) : TElCustomExtension() { }
	/* TElCustomExtension.Destroy */ inline __fastcall virtual ~TElSubjectKeyIdentifierExtension(void) { }
	
};

typedef TElSubjectKeyIdentifierExtension ElSubjectKeyIdentifierExtension
class DELPHICLASS TElKeyUsageExtension;
class PASCALIMPLEMENTATION TElKeyUsageExtension : public TElCustomExtension
{
	typedef TElCustomExtension inherited;
	
protected:
	bool FDigitalSignature;
	bool FNonRepudiation;
	bool FKeyEncipherment;
	bool FDataEncipherment;
	bool FKeyAgreement;
	bool FKeyCertSign;
	bool FCRLSign;
	bool FEncipherOnly;
	bool FDecipherOnly;
	virtual void __fastcall Clear(void);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	
public:
	__property bool DigitalSignature = {read=FDigitalSignature, write=FDigitalSignature, nodefault};
	__property bool NonRepudiation = {read=FNonRepudiation, write=FNonRepudiation, nodefault};
	__property bool KeyEncipherment = {read=FKeyEncipherment, write=FKeyEncipherment, nodefault};
	__property bool DataEncipherment = {read=FDataEncipherment, write=FDataEncipherment, nodefault};
	__property bool KeyAgreement = {read=FKeyAgreement, write=FKeyAgreement, nodefault};
	__property bool KeyCertSign = {read=FKeyCertSign, write=FKeyCertSign, nodefault};
	__property bool CRLSign = {read=FCRLSign, write=FCRLSign, nodefault};
	__property bool EncipherOnly = {read=FEncipherOnly, write=FEncipherOnly, nodefault};
	__property bool DecipherOnly = {read=FDecipherOnly, write=FDecipherOnly, nodefault};
public:
	/* TElCustomExtension.Create */ inline __fastcall TElKeyUsageExtension(void) : TElCustomExtension() { }
	/* TElCustomExtension.Destroy */ inline __fastcall virtual ~TElKeyUsageExtension(void) { }
	
};

typedef TElKeyUsageExtension ElKeyUsageExtension
class DELPHICLASS TElPrivateKeyUsagePeriodExtension;
class PASCALIMPLEMENTATION TElPrivateKeyUsagePeriodExtension : public TElCustomExtension
{
	typedef TElCustomExtension inherited;
	
protected:
	System::TDateTime FNotBefore;
	System::TDateTime FNotAfter;
	virtual void __fastcall Clear(void);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	
public:
	__property System::TDateTime NotBefore = {read=FNotBefore, write=FNotBefore};
	__property System::TDateTime NotAfter = {read=FNotAfter, write=FNotAfter};
public:
	/* TElCustomExtension.Create */ inline __fastcall TElPrivateKeyUsagePeriodExtension(void) : TElCustomExtension() { }
	/* TElCustomExtension.Destroy */ inline __fastcall virtual ~TElPrivateKeyUsagePeriodExtension(void) { }
	
};

typedef TElPrivateKeyUsagePeriodExtension ElPrivateKeyUsagePeriodExtension
#pragma option push -b-
enum TElNetscapeCertTypeFlag { nsSSLClient, nsSSLServer, nsSMIME, nsObjectSign, nsSSLCA, nsSMIMECA, nsObjectSignCA };
#pragma option pop

typedef Set<TElNetscapeCertTypeFlag, nsSSLClient, nsObjectSignCA>  TElNetscapeCertType;

class DELPHICLASS TElNetscapeCertTypeExtension;
class PASCALIMPLEMENTATION TElNetscapeCertTypeExtension : public TElCustomExtension
{
	typedef TElCustomExtension inherited;
	
protected:
	TElNetscapeCertType FCertType;
	virtual void __fastcall Clear(void);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	
public:
	__property TElNetscapeCertType CertType = {read=FCertType, write=FCertType, nodefault};
public:
	/* TElCustomExtension.Create */ inline __fastcall TElNetscapeCertTypeExtension(void) : TElCustomExtension() { }
	/* TElCustomExtension.Destroy */ inline __fastcall virtual ~TElNetscapeCertTypeExtension(void) { }
	
};

typedef TElNetscapeCertTypeExtension ElNetscapeCertTypeExtension
class DELPHICLASS TElNetscapeString;
class PASCALIMPLEMENTATION TElNetscapeString : public TElCustomExtension
{
	typedef TElCustomExtension inherited;
	
protected:
	System::UnicodeString FContent;
	virtual void __fastcall Clear(void);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	
public:
	__property System::UnicodeString Content = {read=FContent, write=FContent};
public:
	/* TElCustomExtension.Create */ inline __fastcall TElNetscapeString(void) : TElCustomExtension() { }
	/* TElCustomExtension.Destroy */ inline __fastcall virtual ~TElNetscapeString(void) { }
	
};

typedef TElNetscapeString ElNetscapeString
class DELPHICLASS TElNetscapeBaseURL;
class PASCALIMPLEMENTATION TElNetscapeBaseURL : public TElNetscapeString
{
	typedef TElNetscapeString inherited;
	
public:
	/* TElCustomExtension.Create */ inline __fastcall TElNetscapeBaseURL(void) : TElNetscapeString() { }
	/* TElCustomExtension.Destroy */ inline __fastcall virtual ~TElNetscapeBaseURL(void) { }
	
};


typedef TElNetscapeBaseURL ElNetscapeBaseURL;

class DELPHICLASS TElNetscapeRevokeURL;
class PASCALIMPLEMENTATION TElNetscapeRevokeURL : public TElNetscapeString
{
	typedef TElNetscapeString inherited;
	
public:
	/* TElCustomExtension.Create */ inline __fastcall TElNetscapeRevokeURL(void) : TElNetscapeString() { }
	/* TElCustomExtension.Destroy */ inline __fastcall virtual ~TElNetscapeRevokeURL(void) { }
	
};


typedef TElNetscapeRevokeURL ElNetscapeRevokeURL;

class DELPHICLASS TElNetscapeCARevokeURL;
class PASCALIMPLEMENTATION TElNetscapeCARevokeURL : public TElNetscapeString
{
	typedef TElNetscapeString inherited;
	
public:
	/* TElCustomExtension.Create */ inline __fastcall TElNetscapeCARevokeURL(void) : TElNetscapeString() { }
	/* TElCustomExtension.Destroy */ inline __fastcall virtual ~TElNetscapeCARevokeURL(void) { }
	
};


typedef TElNetscapeCARevokeURL ElNetscapeCARevokeURL;

class DELPHICLASS TElNetscapeRenewalURL;
class PASCALIMPLEMENTATION TElNetscapeRenewalURL : public TElNetscapeString
{
	typedef TElNetscapeString inherited;
	
public:
	/* TElCustomExtension.Create */ inline __fastcall TElNetscapeRenewalURL(void) : TElNetscapeString() { }
	/* TElCustomExtension.Destroy */ inline __fastcall virtual ~TElNetscapeRenewalURL(void) { }
	
};


typedef TElNetscapeRenewalURL ElNetscapeRenewalURL;

class DELPHICLASS TElNetscapeCAPolicy;
class PASCALIMPLEMENTATION TElNetscapeCAPolicy : public TElNetscapeString
{
	typedef TElNetscapeString inherited;
	
public:
	/* TElCustomExtension.Create */ inline __fastcall TElNetscapeCAPolicy(void) : TElNetscapeString() { }
	/* TElCustomExtension.Destroy */ inline __fastcall virtual ~TElNetscapeCAPolicy(void) { }
	
};


typedef TElNetscapeCAPolicy ElNetscapeCAPolicy;

class DELPHICLASS TElNetscapeServerName;
class PASCALIMPLEMENTATION TElNetscapeServerName : public TElNetscapeString
{
	typedef TElNetscapeString inherited;
	
public:
	/* TElCustomExtension.Create */ inline __fastcall TElNetscapeServerName(void) : TElNetscapeString() { }
	/* TElCustomExtension.Destroy */ inline __fastcall virtual ~TElNetscapeServerName(void) { }
	
};


typedef TElNetscapeServerName ElNetscapeServerName;

class DELPHICLASS TElNetscapeComment;
class PASCALIMPLEMENTATION TElNetscapeComment : public TElNetscapeString
{
	typedef TElNetscapeString inherited;
	
public:
	/* TElCustomExtension.Create */ inline __fastcall TElNetscapeComment(void) : TElNetscapeString() { }
	/* TElCustomExtension.Destroy */ inline __fastcall virtual ~TElNetscapeComment(void) { }
	
};


typedef TElNetscapeComment ElNetscapeComment;

class DELPHICLASS TElCommonName;
class PASCALIMPLEMENTATION TElCommonName : public TElNetscapeString
{
	typedef TElNetscapeString inherited;
	
public:
	/* TElCustomExtension.Create */ inline __fastcall TElCommonName(void) : TElNetscapeString() { }
	/* TElCustomExtension.Destroy */ inline __fastcall virtual ~TElCommonName(void) { }
	
};


typedef TElCommonName ElCommonName;

class DELPHICLASS TElUserNotice;
class PASCALIMPLEMENTATION TElUserNotice : public Classes::TPersistent
{
	typedef Classes::TPersistent inherited;
	
private:
	typedef DynamicArray<int> _TElUserNotice__1;
	
	
protected:
	System::UnicodeString FOrganization;
	_TElUserNotice__1 FNoticeNumbers;
	System::UnicodeString FExplicitText;
	int __fastcall GetNoticeNumbersCount(void);
	void __fastcall SetNoticeNumbersCount(int Value);
	int __fastcall GetNoticeNumbers(int Index);
	void __fastcall SetNoticeNumbers(int Index, int Value);
	
public:
	__fastcall virtual ~TElUserNotice(void);
	__property System::UnicodeString Organization = {read=FOrganization, write=FOrganization};
	__property int NoticeNumbers[int Index] = {read=GetNoticeNumbers, write=SetNoticeNumbers};
	__property int NoticeNumbersCount = {read=GetNoticeNumbersCount, write=SetNoticeNumbersCount, nodefault};
	__property System::UnicodeString ExplicitText = {read=FExplicitText, write=FExplicitText};
public:
	/* TObject.Create */ inline __fastcall TElUserNotice(void) : Classes::TPersistent() { }
	
};

typedef TElUserNotice ElUserNotice
class DELPHICLASS TElSinglePolicyQualifier;
class PASCALIMPLEMENTATION TElSinglePolicyQualifier : public Classes::TPersistent
{
	typedef Classes::TPersistent inherited;
	
protected:
	System::UnicodeString FCPSURI;
	TElUserNotice* FUserNotice;
	
public:
	__fastcall TElSinglePolicyQualifier(void);
	__fastcall virtual ~TElSinglePolicyQualifier(void);
	__property System::UnicodeString CPSURI = {read=FCPSURI, write=FCPSURI};
	__property TElUserNotice* UserNotice = {read=FUserNotice};
};

typedef TElSinglePolicyQualifier ElSinglePolicyQualifier
class DELPHICLASS TElSinglePolicyInformation;
class PASCALIMPLEMENTATION TElSinglePolicyInformation : public Classes::TPersistent
{
	typedef Classes::TPersistent inherited;
	
protected:
	Sbtypes::ByteArray FPolicyIdentifier;
	Classes::TList* FPolicyQualifiers;
	void __fastcall SetPolicyIdentifier(const Sbtypes::ByteArray V);
	int __fastcall GetQualifierCount(void);
	void __fastcall SetQualifierCount(int Value);
	TElSinglePolicyQualifier* __fastcall GetPolicyQualifier(int Index);
	
public:
	__fastcall TElSinglePolicyInformation(void);
	__fastcall virtual ~TElSinglePolicyInformation(void);
	__property Sbtypes::ByteArray PolicyIdentifier = {read=FPolicyIdentifier, write=SetPolicyIdentifier};
	__property int QualifierCount = {read=GetQualifierCount, write=SetQualifierCount, nodefault};
	__property TElSinglePolicyQualifier* Qualifiers[int Index] = {read=GetPolicyQualifier};
};

typedef TElSinglePolicyInformation ElSinglePolicyInformation
class DELPHICLASS TElCertificatePoliciesExtension;
class PASCALIMPLEMENTATION TElCertificatePoliciesExtension : public TElCustomExtension
{
	typedef TElCustomExtension inherited;
	
protected:
	Classes::TList* FList;
	void __fastcall ClearList(void);
	virtual void __fastcall Clear(void);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	int __fastcall GetCount(void);
	void __fastcall SetCount(int Value);
	TElSinglePolicyInformation* __fastcall GetPolicyInformation(int Index);
	
public:
	__fastcall TElCertificatePoliciesExtension(void);
	__fastcall virtual ~TElCertificatePoliciesExtension(void);
	void __fastcall Remove(int Index);
	__property TElSinglePolicyInformation* PolicyInformation[int Index] = {read=GetPolicyInformation};
	__property int Count = {read=GetCount, write=SetCount, nodefault};
};

typedef TElCertificatePoliciesExtension ElCertificatePoliciesExtension
class DELPHICLASS TElPolicyMapping;
class PASCALIMPLEMENTATION TElPolicyMapping : public Classes::TPersistent
{
	typedef Classes::TPersistent inherited;
	
protected:
	Sbtypes::ByteArray FIssuerDomainPolicy;
	Sbtypes::ByteArray FSubjectDomainPolicy;
	void __fastcall SetIssuerDomainPolicy(const Sbtypes::ByteArray V);
	void __fastcall SetSubjectDomainPolicy(const Sbtypes::ByteArray V);
	
public:
	__fastcall virtual ~TElPolicyMapping(void);
	__property Sbtypes::ByteArray IssuerDomainPolicy = {read=FIssuerDomainPolicy, write=SetIssuerDomainPolicy};
	__property Sbtypes::ByteArray SubjectDomainPolicy = {read=FSubjectDomainPolicy, write=SetSubjectDomainPolicy};
public:
	/* TObject.Create */ inline __fastcall TElPolicyMapping(void) : Classes::TPersistent() { }
	
};

typedef TElPolicyMapping ElPolicyMapping
class DELPHICLASS TElPolicyMappingsExtension;
class PASCALIMPLEMENTATION TElPolicyMappingsExtension : public TElCustomExtension
{
	typedef TElCustomExtension inherited;
	
protected:
	Classes::TList* FList;
	void __fastcall ClearList(void);
	virtual void __fastcall Clear(void);
	int __fastcall GetCount(void);
	void __fastcall SetCount(int Value);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	TElPolicyMapping* __fastcall GetPolicies(int Index);
	
public:
	__fastcall TElPolicyMappingsExtension(void);
	__fastcall virtual ~TElPolicyMappingsExtension(void);
	void __fastcall Remove(int Index);
	__property int Count = {read=GetCount, write=SetCount, nodefault};
	__property TElPolicyMapping* Policies[int Index] = {read=GetPolicies};
};

typedef TElPolicyMappingsExtension ElPolicyMappingsExtension
class DELPHICLASS TElAlternativeNameExtension;
class PASCALIMPLEMENTATION TElAlternativeNameExtension : public TElCustomExtension
{
	typedef TElCustomExtension inherited;
	
protected:
	TElGeneralNames* FContent;
	bool FIssuerAltName;
	virtual void __fastcall Clear(void);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	virtual Sbtypes::ByteArray __fastcall GetValue(void);
	
public:
	__fastcall TElAlternativeNameExtension(bool IssuerAltName);
	__fastcall virtual ~TElAlternativeNameExtension(void);
	__property TElGeneralNames* Content = {read=FContent};
};

typedef TElAlternativeNameExtension ElAlternativeNameExtension
class DELPHICLASS TElBasicConstraintsExtension;
class PASCALIMPLEMENTATION TElBasicConstraintsExtension : public TElCustomExtension
{
	typedef TElCustomExtension inherited;
	
protected:
	bool FCA;
	int FPathLenConstraint;
	virtual void __fastcall Clear(void);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	
public:
	__property bool CA = {read=FCA, write=FCA, nodefault};
	__property int PathLenConstraint = {read=FPathLenConstraint, write=FPathLenConstraint, nodefault};
public:
	/* TElCustomExtension.Create */ inline __fastcall TElBasicConstraintsExtension(void) : TElCustomExtension() { }
	/* TElCustomExtension.Destroy */ inline __fastcall virtual ~TElBasicConstraintsExtension(void) { }
	
};

typedef TElBasicConstraintsExtension ElBasicConstraintsExtension
class DELPHICLASS TElNameConstraint;
class PASCALIMPLEMENTATION TElNameConstraint : public Classes::TPersistent
{
	typedef Classes::TPersistent inherited;
	
protected:
	TElGeneralName* FBase;
	int FMinimum;
	int FMaximum;
	
public:
	__fastcall TElNameConstraint(void);
	__fastcall virtual ~TElNameConstraint(void);
	__property TElGeneralName* Base = {read=FBase};
	__property int Minimum = {read=FMinimum, write=FMinimum, nodefault};
	__property int Maximum = {read=FMaximum, write=FMaximum, nodefault};
};

typedef TElNameConstraint ElNameConstraint
class DELPHICLASS TElNameConstraintsExtension;
class PASCALIMPLEMENTATION TElNameConstraintsExtension : public TElCustomExtension
{
	typedef TElCustomExtension inherited;
	
protected:
	Classes::TList* FPermittedList;
	Classes::TList* FExcludedList;
	virtual void __fastcall Clear(void);
	void __fastcall ClearList(void);
	int __fastcall GetPermittedCount(void);
	int __fastcall GetExcludedCount(void);
	void __fastcall SetPermittedCount(int Value);
	void __fastcall SetExcludedCount(int Value);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	bool __fastcall NameSubtreeCorresponds(TElGeneralName* Subtree, TElGeneralName* Name);
	bool __fastcall URICorresponds(const System::UnicodeString URITpl, const System::UnicodeString URI);
	bool __fastcall EMailAddressCorresponds(const System::UnicodeString EMailTpl, const System::UnicodeString EMail);
	bool __fastcall DNSNameCorresponds(const System::UnicodeString DNSNameTpl, const System::UnicodeString DNSName);
	bool __fastcall DirectoryNameCorresponds(Sbrdn::TElRelativeDistinguishedName* DirNameTpl, Sbrdn::TElRelativeDistinguishedName* DirName);
	bool __fastcall IPAddressCorresponds(const Sbtypes::ByteArray IPAddressTpl, const Sbtypes::ByteArray IPAddress);
	TElNameConstraint* __fastcall GetPermittedSubtrees(int Index);
	TElNameConstraint* __fastcall GetExcludedSubtrees(int Index);
	
public:
	__fastcall TElNameConstraintsExtension(void);
	__fastcall virtual ~TElNameConstraintsExtension(void);
	bool __fastcall AreNamesAcceptable(Sbrdn::TElRelativeDistinguishedName* Subj, TElGeneralNames* SubjAltName);
	void __fastcall RemovePermitted(int Index);
	void __fastcall RemoveExcluded(int Index);
	__property TElNameConstraint* PermittedSubtrees[int Index] = {read=GetPermittedSubtrees};
	__property TElNameConstraint* ExcludedSubtrees[int Index] = {read=GetExcludedSubtrees};
	__property int PermittedCount = {read=GetPermittedCount, write=SetPermittedCount, nodefault};
	__property int ExcludedCount = {read=GetExcludedCount, write=SetExcludedCount, nodefault};
};

typedef TElNameConstraintsExtension ElNameConstraintsExtension
class DELPHICLASS TElPolicyConstraintsExtension;
class PASCALIMPLEMENTATION TElPolicyConstraintsExtension : public TElCustomExtension
{
	typedef TElCustomExtension inherited;
	
protected:
	int FRequireExplicitPolicy;
	int FInhibitPolicyMapping;
	virtual void __fastcall Clear(void);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	
public:
	__property int RequireExplicitPolicy = {read=FRequireExplicitPolicy, write=FRequireExplicitPolicy, nodefault};
	__property int InhibitPolicyMapping = {read=FInhibitPolicyMapping, write=FInhibitPolicyMapping, nodefault};
public:
	/* TElCustomExtension.Create */ inline __fastcall TElPolicyConstraintsExtension(void) : TElCustomExtension() { }
	/* TElCustomExtension.Destroy */ inline __fastcall virtual ~TElPolicyConstraintsExtension(void) { }
	
};

typedef TElPolicyConstraintsExtension ElPolicyConstraintsExtension
class DELPHICLASS TElExtendedKeyUsageExtension;
class PASCALIMPLEMENTATION TElExtendedKeyUsageExtension : public TElCustomExtension
{
	typedef TElCustomExtension inherited;
	
protected:
	bool FServerAuthentication;
	bool FClientAuthentication;
	bool FCodeSigning;
	bool FEmailProtection;
	bool FTimeStamping;
	bool FOCSPSigning;
	Sbutils::TElByteArrayList* FCustomUsages;
	virtual void __fastcall Clear(void);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	int __fastcall GetTotalUsageCount(void);
	int __fastcall GetCustomUsageCount(void);
	Sbtypes::ByteArray __fastcall GetCustomUsage(int Index);
	void __fastcall SetCustomUsage(int Index, const Sbtypes::ByteArray Value);
	
public:
	__fastcall TElExtendedKeyUsageExtension(void);
	__fastcall virtual ~TElExtendedKeyUsageExtension(void);
	int __fastcall AddCustomUsage(const Sbtypes::ByteArray UsageOID);
	void __fastcall RemoveCustomUsage(int Index);
	void __fastcall ClearCustomUsages(void);
	__property int TotalUsageCount = {read=GetTotalUsageCount, nodefault};
	__property bool ServerAuthentication = {read=FServerAuthentication, write=FServerAuthentication, nodefault};
	__property bool ClientAuthentication = {read=FClientAuthentication, write=FClientAuthentication, nodefault};
	__property bool CodeSigning = {read=FCodeSigning, write=FCodeSigning, nodefault};
	__property bool EmailProtection = {read=FEmailProtection, write=FEmailProtection, nodefault};
	__property bool TimeStamping = {read=FTimeStamping, write=FTimeStamping, nodefault};
	__property bool OCSPSigning = {read=FOCSPSigning, write=FOCSPSigning, nodefault};
	__property Sbtypes::ByteArray CustomUsages[int Index] = {read=GetCustomUsage, write=SetCustomUsage};
	__property int CustomUsageCount = {read=GetCustomUsageCount, nodefault};
};

typedef TElExtendedKeyUsageExtension ElExtendedKeyUsageExtension
#pragma option push -b-
enum TElDistributionPointParameter { dppName, dppCRLIssuer, dppReasonFlags };
#pragma option pop

typedef Set<TElDistributionPointParameter, dppName, dppReasonFlags>  TElDistributionPointParameters;

class DELPHICLASS TElDistributionPoint;
class PASCALIMPLEMENTATION TElDistributionPoint : public Classes::TPersistent
{
	typedef Classes::TPersistent inherited;
	
protected:
	TElGeneralNames* FName;
	TElGeneralNames* FCRLIssuer;
	TSBCRLReasonFlags FReasonFlags;
	TElDistributionPointParameters FIncluded;
	
public:
	__fastcall TElDistributionPoint(void);
	__fastcall virtual ~TElDistributionPoint(void);
	__property TElGeneralNames* Name = {read=FName};
	__property TSBCRLReasonFlags ReasonFlags = {read=FReasonFlags, write=FReasonFlags, nodefault};
	__property TElGeneralNames* CRLIssuer = {read=FCRLIssuer};
	__property TElDistributionPointParameters Included = {read=FIncluded, write=FIncluded, nodefault};
};

typedef TElDistributionPoint ElDistributionPoint
class DELPHICLASS TElCRLDistributionPointsExtension;
class PASCALIMPLEMENTATION TElCRLDistributionPointsExtension : public TElCustomExtension
{
	typedef TElCustomExtension inherited;
	
protected:
	Classes::TList* FPoints;
	void __fastcall ClearList(void);
	virtual void __fastcall Clear(void);
	int __fastcall GetCount(void);
	void __fastcall SetCount(int Value);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	TElDistributionPoint* __fastcall GetDistributionPoints(int Index);
	
public:
	__fastcall TElCRLDistributionPointsExtension(void);
	__fastcall virtual ~TElCRLDistributionPointsExtension(void);
	void __fastcall Remove(int Index);
	__property TElDistributionPoint* DistributionPoints[int Index] = {read=GetDistributionPoints};
	__property int Count = {read=GetCount, write=SetCount, nodefault};
};

typedef TElCRLDistributionPointsExtension ElCRLDistributionPointsExtension
class DELPHICLASS TElAccessDescription;
class PASCALIMPLEMENTATION TElAccessDescription : public Classes::TPersistent
{
	typedef Classes::TPersistent inherited;
	
protected:
	Sbtypes::ByteArray FAccessMethod;
	TElGeneralName* FGeneralName;
	void __fastcall SetAccessMethod(const Sbtypes::ByteArray V);
	
public:
	__fastcall TElAccessDescription(void);
	__fastcall virtual ~TElAccessDescription(void);
	__property Sbtypes::ByteArray AccessMethod = {read=FAccessMethod, write=SetAccessMethod};
	__property TElGeneralName* AccessLocation = {read=FGeneralName};
};

typedef TElAccessDescription ElAccessDescription
class DELPHICLASS TElAuthorityInformationAccessExtension;
class PASCALIMPLEMENTATION TElAuthorityInformationAccessExtension : public TElCustomExtension
{
	typedef TElCustomExtension inherited;
	
protected:
	Classes::TList* FList;
	void __fastcall ClearList(void);
	virtual void __fastcall Clear(void);
	int __fastcall GetCount(void);
	void __fastcall SetCount(int Value);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	TElAccessDescription* __fastcall GetAccessDescriptions(int Index);
	
public:
	__fastcall TElAuthorityInformationAccessExtension(void);
	__fastcall virtual ~TElAuthorityInformationAccessExtension(void);
	void __fastcall Remove(int Index);
	__property TElAccessDescription* AccessDescriptions[int Index] = {read=GetAccessDescriptions};
	__property int Count = {read=GetCount, write=SetCount, nodefault};
};

typedef TElAuthorityInformationAccessExtension ElAuthorityInformationAccessExtension
class DELPHICLASS TElSubjectDirectoryAttributesExtension;
class PASCALIMPLEMENTATION TElSubjectDirectoryAttributesExtension : public TElCustomExtension
{
	typedef TElCustomExtension inherited;
	
private:
	Sbpkcs7utils::TElPKCS7Attributes* FAttributes;
	
protected:
	virtual void __fastcall Clear(void);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	
public:
	__fastcall TElSubjectDirectoryAttributesExtension(void);
	__fastcall virtual ~TElSubjectDirectoryAttributesExtension(void);
	__property Sbpkcs7utils::TElPKCS7Attributes* Attributes = {read=FAttributes};
};

typedef TElSubjectDirectoryAttributesExtension ElSubjectDirectoryAttributesExtension
class DELPHICLASS TElCertificateExtensions;
class PASCALIMPLEMENTATION TElCertificateExtensions : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	TElAuthorityKeyIdentifierExtension* FAuthorityKeyIdentifier;
	TElSubjectKeyIdentifierExtension* FSubjectKeyIdentifier;
	TElKeyUsageExtension* FKeyUsage;
	TElPrivateKeyUsagePeriodExtension* FPrivateKeyUsagePeriod;
	TElCertificatePoliciesExtension* FCertificatePolicies;
	TElPolicyMappingsExtension* FPolicyMappings;
	TElAlternativeNameExtension* FSubjectAlternativeName;
	TElAlternativeNameExtension* FIssuerAlternativeName;
	TElBasicConstraintsExtension* FBasicConstraints;
	TElNameConstraintsExtension* FNameConstraints;
	TElPolicyConstraintsExtension* FPolicyConstraints;
	TElExtendedKeyUsageExtension* FExtendedKeyUsage;
	TElCRLDistributionPointsExtension* FCRLDistributionPoints;
	TElAuthorityInformationAccessExtension* FAuthorityInformationAccess;
	TElNetscapeCertTypeExtension* FNetscapeCertType;
	TElNetscapeComment* FNetscapeComment;
	TElNetscapeCAPolicy* FNetscapeCAPolicy;
	TElNetscapeCARevokeURL* FNetscapeCARevokeURL;
	TElNetscapeRevokeURL* FNetscapeRevokeURL;
	TElNetscapeServerName* FNetscapeServerName;
	TElNetscapeBaseURL* FNetscapeBaseURL;
	TElNetscapeRenewalURL* FNetscapeRenewalURL;
	TElCommonName* FCommonName;
	TElSubjectDirectoryAttributesExtension* FSubjectDirectoryAttributes;
	TSBCertificateExtensions FIncluded;
	Classes::TList* FOtherList;
	void __fastcall ClearOtherList(void);
	int __fastcall GetOtherCount(void);
	void __fastcall SetOtherCount(int Value);
	TElCustomExtension* __fastcall GetOtherExtensions(int Index);
	
public:
	__fastcall TElCertificateExtensions(void);
	__fastcall virtual ~TElCertificateExtensions(void);
	bool __fastcall RemoveOther(int Index);
	void __fastcall ClearExtensions(void);
	__property TElAuthorityKeyIdentifierExtension* AuthorityKeyIdentifier = {read=FAuthorityKeyIdentifier};
	__property TElSubjectKeyIdentifierExtension* SubjectKeyIdentifier = {read=FSubjectKeyIdentifier};
	__property TElKeyUsageExtension* KeyUsage = {read=FKeyUsage, write=FKeyUsage};
	__property TElPrivateKeyUsagePeriodExtension* PrivateKeyUsagePeriod = {read=FPrivateKeyUsagePeriod, write=FPrivateKeyUsagePeriod};
	__property TElCertificatePoliciesExtension* CertificatePolicies = {read=FCertificatePolicies};
	__property TElPolicyMappingsExtension* PolicyMappings = {read=FPolicyMappings, write=FPolicyMappings};
	__property TElAlternativeNameExtension* SubjectAlternativeName = {read=FSubjectAlternativeName, write=FSubjectAlternativeName};
	__property TElAlternativeNameExtension* IssuerAlternativeName = {read=FIssuerAlternativeName, write=FIssuerAlternativeName};
	__property TElBasicConstraintsExtension* BasicConstraints = {read=FBasicConstraints, write=FBasicConstraints};
	__property TElNameConstraintsExtension* NameConstraints = {read=FNameConstraints};
	__property TElPolicyConstraintsExtension* PolicyConstraints = {read=FPolicyConstraints, write=FPolicyConstraints};
	__property TElExtendedKeyUsageExtension* ExtendedKeyUsage = {read=FExtendedKeyUsage};
	__property TElCRLDistributionPointsExtension* CRLDistributionPoints = {read=FCRLDistributionPoints};
	__property TElAuthorityInformationAccessExtension* AuthorityInformationAccess = {read=FAuthorityInformationAccess};
	__property TElNetscapeCertTypeExtension* NetscapeCertType = {read=FNetscapeCertType, write=FNetscapeCertType};
	__property TElNetscapeComment* NetscapeComment = {read=FNetscapeComment, write=FNetscapeComment};
	__property TElNetscapeBaseURL* NetscapeBaseURL = {read=FNetscapeBaseURL, write=FNetscapeBaseURL};
	__property TElNetscapeRevokeURL* NetscapeRevokeURL = {read=FNetscapeRevokeURL, write=FNetscapeRevokeURL};
	__property TElNetscapeCARevokeURL* NetscapeCARevokeURL = {read=FNetscapeCARevokeURL, write=FNetscapeCARevokeURL};
	__property TElNetscapeRenewalURL* NetscapeRenewalURL = {read=FNetscapeRenewalURL, write=FNetscapeRenewalURL};
	__property TElNetscapeCAPolicy* NetscapeCAPolicy = {read=FNetscapeCAPolicy, write=FNetscapeCAPolicy};
	__property TElNetscapeServerName* NetscapeServerName = {read=FNetscapeServerName, write=FNetscapeServerName};
	__property TElCommonName* CommonName = {read=FCommonName, write=FCommonName};
	__property TElSubjectDirectoryAttributesExtension* SubjectDirectoryAttributes = {read=FSubjectDirectoryAttributes};
	__property TElCustomExtension* OtherExtensions[int Index] = {read=GetOtherExtensions};
	__property int OtherCount = {read=GetOtherCount, write=SetOtherCount, nodefault};
	__property TSBCertificateExtensions Included = {read=FIncluded, write=FIncluded, nodefault};
};

typedef TElCertificateExtensions ElCertificateExtensions
class DELPHICLASS TElExtensionWriter;
class PASCALIMPLEMENTATION TElExtensionWriter : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	TElCertificateExtensions* FCertificateExtensions;
	bool FUseA3Prefix;
	
public:
	__fastcall TElExtensionWriter(TElCertificateExtensions* Exts, bool CertExtensions);
	Sbtypes::ByteArray __fastcall WriteExtensions(void);
	Sbtypes::ByteArray __fastcall WriteExtension(const Sbtypes::ByteArray OID, bool Critical, const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall WriteExtensionBasicConstraints(void);
	Sbtypes::ByteArray __fastcall WriteExtensionKeyUsage(void);
	Sbtypes::ByteArray __fastcall WriteExtensionPrivateKeyUsagePeriod(void);
	Sbtypes::ByteArray __fastcall WriteExtensionSubjectAltName(void);
	Sbtypes::ByteArray __fastcall WriteExtensionIssuerAltName(void);
	Sbtypes::ByteArray __fastcall WriteExtensionExtendedKeyUsage(void);
	Sbtypes::ByteArray __fastcall WriteExtensionPolicyMappings(void);
	Sbtypes::ByteArray __fastcall WriteExtensionNameConstraints(void);
	Sbtypes::ByteArray __fastcall WriteExtensionPolicyConstraints(void);
	Sbtypes::ByteArray __fastcall WriteExtensionCertificatePolicies(void);
	Sbtypes::ByteArray __fastcall WriteExtensionAuthorityKeyIdentifier(void);
	Sbtypes::ByteArray __fastcall WriteExtensionCRLDistributionPoints(void);
	Sbtypes::ByteArray __fastcall WriteExtensionAuthorityInformationAccess(void);
	Sbtypes::ByteArray __fastcall WriteExtensionNetscapeCertType(void);
	Sbtypes::ByteArray __fastcall WriteExtensionNetscapeString(const Sbtypes::ByteArray AOID, const System::UnicodeString ANetStr)/* overload */;
	Sbtypes::ByteArray __fastcall WriteExtensionNetscapeString(const Sbtypes::ByteArray AOID, const Sbtypes::ByteArray ANetStr)/* overload */;
	Sbtypes::ByteArray __fastcall WriteExtensionSubjectKeyIdentifier(void);
	Sbtypes::ByteArray __fastcall WritePolicyInformation(TElSinglePolicyInformation* P);
	Sbtypes::ByteArray __fastcall WriteDistributionPoint(TElDistributionPoint* P);
	Sbtypes::ByteArray __fastcall WriteExtensionSubjectDirectoryAttributes(void);
	__property TElCertificateExtensions* Extensions = {read=FCertificateExtensions};
	__property bool UseA3Prefix = {read=FUseA3Prefix, write=FUseA3Prefix, nodefault};
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TElExtensionWriter(void) { }
	
};

typedef TElExtensionWriter ElExtensionWriter
class DELPHICLASS TElExtensionReader;
class PASCALIMPLEMENTATION TElExtensionReader : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	TElCertificateExtensions* FCertificateExtensions;
	bool FStrictMode;
	
public:
	__fastcall TElExtensionReader(TElCertificateExtensions* Exts, bool StrictMode);
	void __fastcall ParseExtension(const Sbtypes::ByteArray OID, bool Critical, const Sbtypes::ByteArray Content);
	__property TElCertificateExtensions* Extensions = {read=FCertificateExtensions};
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TElExtensionReader(void) { }
	
};

typedef TElExtensionReader ElExtensionReader
//-- var, const, procedure ---------------------------------------------------
extern PACKAGE TSBCRLReasonFlags TSBCRLAllReasonFlags;
extern PACKAGE Sbtypes::ByteArray PEM_CERTIFICATE_BEGIN_LINE;
extern PACKAGE Sbtypes::ByteArray PEM_CERTIFICATE_END_LINE;
extern PACKAGE Sbtypes::ByteArray PEM_CERTIFICATEX509_BEGIN_LINE;
extern PACKAGE Sbtypes::ByteArray PEM_CERTIFICATEX509_END_LINE;
extern PACKAGE Sbtypes::ByteArray PEM_RSA_PRIVATE_KEY_BEGIN_LINE;
extern PACKAGE Sbtypes::ByteArray PEM_RSA_PRIVATE_KEY_END_LINE;
extern PACKAGE Sbtypes::ByteArray PEM_DSA_PRIVATE_KEY_BEGIN_LINE;
extern PACKAGE Sbtypes::ByteArray PEM_DSA_PRIVATE_KEY_END_LINE;
extern PACKAGE Sbtypes::ByteArray PEM_DH_PRIVATE_KEY_BEGIN_LINE;
extern PACKAGE Sbtypes::ByteArray PEM_DH_PRIVATE_KEY_END_LINE;
extern PACKAGE Sbtypes::ByteArray PEM_EC_PRIVATE_KEY_BEGIN_LINE;
extern PACKAGE Sbtypes::ByteArray PEM_EC_PRIVATE_KEY_END_LINE;
extern PACKAGE Sbtypes::ByteArray PEM_PRIVATE_KEY_BEGIN_LINE;
extern PACKAGE Sbtypes::ByteArray PEM_PRIVATE_KEY_END_LINE;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_NETSCAPE_CERT_TYPE;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_NETSCAPE_BASE_URL;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_NETSCAPE_REVOKE_URL;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_NETSCAPE_CA_REVOKE_URL;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_NETSCAPE_RENEWAL_URL;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_NETSCAPE_CA_POLICY;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_NETSCAPE_SERVER_NAME;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_NETSCAPE_COMMENT;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_SUBJECT_DIRECTORY_ATTRIBUTES;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_SUBJECT_KEY_IDENTIFIER;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_KEY_USAGE;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_PRIVATE_KEY_USAGE_PERIOD;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_SUBJECT_ALTERNATIVE_NAME;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_ISSUER_ALTERNATIVE_NAME;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_BASIC_CONSTRAINTS;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_NAME_CONSTRAINTS;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_CRL_DISTRIBUTION_POINTS;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_CERTIFICATE_POLICIES;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_POLICY_MAPPINGS;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_AUTHORITY_KEY_IDENTIFIER;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_POLICY_CONSTRAINTS;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_EXTENDED_KEY_USAGE;
extern PACKAGE Sbtypes::ByteArray SB_CERT_OID_AUTHORITY_INFORMATION_ACCESS;
extern PACKAGE System::UnicodeString __fastcall OctetsToIPAddress(const Sbtypes::ByteArray Octets);
extern PACKAGE Sbtypes::ByteArray __fastcall IPAddressToOctets(const System::UnicodeString IPAddrStr);

}	/* namespace Sbx509ext */
using namespace Sbx509ext;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// Sbx509extHPP
