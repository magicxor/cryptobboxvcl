// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbcrl.pas' rev: 21.00

#ifndef SbcrlHPP
#define SbcrlHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sbstringlist.hpp>	// Pascal unit
#include <Sbasn1.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbencoding.hpp>	// Pascal unit
#include <Sbx509.hpp>	// Pascal unit
#include <Sbpem.hpp>	// Pascal unit
#include <Sbx509ext.hpp>	// Pascal unit
#include <Sbrdn.hpp>	// Pascal unit
#include <Sbsharedresource.hpp>	// Pascal unit
#include <Sbcustomcrypto.hpp>	// Pascal unit
#include <Sbpublickeycrypto.hpp>	// Pascal unit
#include <Sbalgorithmidentifier.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbcrl
{
//-- type declarations -------------------------------------------------------
typedef Sbx509ext::TElCustomExtension TElCRLExtension;

typedef Sbx509ext::TElCustomExtension ElCRLExtension;

class DELPHICLASS TElAuthorityKeyIdentifierCRLExtension;
class PASCALIMPLEMENTATION TElAuthorityKeyIdentifierCRLExtension : public Sbx509ext::TElCustomExtension
{
	typedef Sbx509ext::TElCustomExtension inherited;
	
private:
	Sbtypes::ByteArray FKeyIdentifier;
	Sbx509ext::TElGeneralNames* FAuthorityCertIssuer;
	Sbtypes::ByteArray FAuthorityCertSerial;
	bool FSaveIssuer;
	
protected:
	virtual void __fastcall Clear(void);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	virtual Sbtypes::ByteArray __fastcall GetValue(void);
	void __fastcall SetKeyIdentifier(const Sbtypes::ByteArray V);
	void __fastcall SetAuthorityCertSerial(const Sbtypes::ByteArray V);
	
public:
	__fastcall TElAuthorityKeyIdentifierCRLExtension(void);
	__fastcall virtual ~TElAuthorityKeyIdentifierCRLExtension(void);
	__property Sbtypes::ByteArray KeyIdentifier = {read=FKeyIdentifier, write=SetKeyIdentifier};
	__property Sbx509ext::TElGeneralNames* AuthorityCertIssuer = {read=FAuthorityCertIssuer};
	__property Sbtypes::ByteArray AuthorityCertSerial = {read=FAuthorityCertSerial, write=SetAuthorityCertSerial};
	__property bool IssuerSet = {read=FSaveIssuer, write=FSaveIssuer, nodefault};
};

typedef TElAuthorityKeyIdentifierCRLExtension ElAuthorityKeyIdentifierCRLExtension
class DELPHICLASS TElCRLNumberCRLExtension;
class PASCALIMPLEMENTATION TElCRLNumberCRLExtension : public Sbx509ext::TElCustomExtension
{
	typedef Sbx509ext::TElCustomExtension inherited;
	
private:
	Sbtypes::ByteArray FBinaryNumber;
	
protected:
	virtual void __fastcall Clear(void);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	virtual Sbtypes::ByteArray __fastcall GetValue(void);
	int __fastcall GetNumber(void);
	void __fastcall SetNumber(int Value);
	void __fastcall SetBinaryNumber(const Sbtypes::ByteArray V);
	
public:
	__property int Number = {read=GetNumber, write=SetNumber, nodefault};
	__property Sbtypes::ByteArray BinaryNumber = {read=FBinaryNumber, write=SetBinaryNumber};
public:
	/* TElCustomExtension.Create */ inline __fastcall TElCRLNumberCRLExtension(void) : Sbx509ext::TElCustomExtension() { }
	/* TElCustomExtension.Destroy */ inline __fastcall virtual ~TElCRLNumberCRLExtension(void) { }
	
};

typedef TElCRLNumberCRLExtension ElCRLNumberCRLExtension
class DELPHICLASS TElDeltaCRLIndicatorCRLExtension;
class PASCALIMPLEMENTATION TElDeltaCRLIndicatorCRLExtension : public Sbx509ext::TElCustomExtension
{
	typedef Sbx509ext::TElCustomExtension inherited;
	
private:
	Sbtypes::ByteArray FBinaryNumber;
	
protected:
	virtual void __fastcall Clear(void);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	virtual Sbtypes::ByteArray __fastcall GetValue(void);
	int __fastcall GetNumber(void);
	void __fastcall SetNumber(int Value);
	void __fastcall SetBinaryNumber(const Sbtypes::ByteArray Value);
	
public:
	__property int Number = {read=GetNumber, write=SetNumber, nodefault};
	__property Sbtypes::ByteArray BinaryNumber = {read=FBinaryNumber, write=SetBinaryNumber};
public:
	/* TElCustomExtension.Create */ inline __fastcall TElDeltaCRLIndicatorCRLExtension(void) : Sbx509ext::TElCustomExtension() { }
	/* TElCustomExtension.Destroy */ inline __fastcall virtual ~TElDeltaCRLIndicatorCRLExtension(void) { }
	
};

typedef TElDeltaCRLIndicatorCRLExtension ElDeltaCRLIndicatorCRLExtension
class DELPHICLASS TElReasonCodeCRLExtension;
class PASCALIMPLEMENTATION TElReasonCodeCRLExtension : public Sbx509ext::TElCustomExtension
{
	typedef Sbx509ext::TElCustomExtension inherited;
	
private:
	Sbx509ext::TSBCRLReasonFlag FReason;
	bool FRemoveFromCRL;
	
protected:
	virtual void __fastcall Clear(void);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	virtual Sbtypes::ByteArray __fastcall GetValue(void);
	
public:
	__property Sbx509ext::TSBCRLReasonFlag Reason = {read=FReason, write=FReason, nodefault};
	__property bool RemoveFromCRL = {read=FRemoveFromCRL, write=FRemoveFromCRL, nodefault};
public:
	/* TElCustomExtension.Create */ inline __fastcall TElReasonCodeCRLExtension(void) : Sbx509ext::TElCustomExtension() { }
	/* TElCustomExtension.Destroy */ inline __fastcall virtual ~TElReasonCodeCRLExtension(void) { }
	
};

typedef TElReasonCodeCRLExtension ElReasonCodeCRLExtension
#pragma option push -b-
enum TElInstructionCode { icNone, icCallIssuer, icReject };
#pragma option pop

class DELPHICLASS TElHoldInstructionCodeCRLExtension;
class PASCALIMPLEMENTATION TElHoldInstructionCodeCRLExtension : public Sbx509ext::TElCustomExtension
{
	typedef Sbx509ext::TElCustomExtension inherited;
	
private:
	TElInstructionCode FCode;
	
protected:
	virtual void __fastcall Clear(void);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	virtual Sbtypes::ByteArray __fastcall GetValue(void);
	
public:
	__property TElInstructionCode Code = {read=FCode, write=FCode, nodefault};
public:
	/* TElCustomExtension.Create */ inline __fastcall TElHoldInstructionCodeCRLExtension(void) : Sbx509ext::TElCustomExtension() { }
	/* TElCustomExtension.Destroy */ inline __fastcall virtual ~TElHoldInstructionCodeCRLExtension(void) { }
	
};

typedef TElHoldInstructionCodeCRLExtension ElHoldInstructionCodeCRLExtension
class DELPHICLASS TElInvalidityDateCRLExtension;
class PASCALIMPLEMENTATION TElInvalidityDateCRLExtension : public Sbx509ext::TElCustomExtension
{
	typedef Sbx509ext::TElCustomExtension inherited;
	
private:
	System::TDateTime FDate;
	
protected:
	virtual void __fastcall Clear(void);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	virtual Sbtypes::ByteArray __fastcall GetValue(void);
	
public:
	__property System::TDateTime InvalidityDate = {read=FDate, write=FDate};
public:
	/* TElCustomExtension.Create */ inline __fastcall TElInvalidityDateCRLExtension(void) : Sbx509ext::TElCustomExtension() { }
	/* TElCustomExtension.Destroy */ inline __fastcall virtual ~TElInvalidityDateCRLExtension(void) { }
	
};

typedef TElInvalidityDateCRLExtension ElInvalidityDateCRLExtension
class DELPHICLASS TElCertificateIssuerCRLExtension;
class PASCALIMPLEMENTATION TElCertificateIssuerCRLExtension : public Sbx509ext::TElCustomExtension
{
	typedef Sbx509ext::TElCustomExtension inherited;
	
private:
	Sbx509ext::TElGeneralNames* FIssuer;
	
protected:
	virtual void __fastcall Clear(void);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	virtual Sbtypes::ByteArray __fastcall GetValue(void);
	
public:
	__fastcall TElCertificateIssuerCRLExtension(void);
	__fastcall virtual ~TElCertificateIssuerCRLExtension(void);
	__property Sbx509ext::TElGeneralNames* Issuer = {read=FIssuer};
};

typedef TElCertificateIssuerCRLExtension ElCertificateIssuerCRLExtension
class DELPHICLASS TElIssuingDistributionPointCRLExtension;
class PASCALIMPLEMENTATION TElIssuingDistributionPointCRLExtension : public Sbx509ext::TElCustomExtension
{
	typedef Sbx509ext::TElCustomExtension inherited;
	
protected:
	Sbx509ext::TElGeneralNames* FDistributionPoint;
	Sbx509ext::TSBCRLReasonFlags FReasonFlags;
	bool FOnlyContainsUserCerts;
	bool FOnlyContainsCACerts;
	bool FOnlyContainsAttributeCerts;
	bool FIndirectCRL;
	bool FReasonFlagsIncluded;
	virtual void __fastcall Clear(void);
	virtual Sbtypes::ByteArray __fastcall GetOID(void);
	virtual void __fastcall SetOID(const Sbtypes::ByteArray Value);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	virtual Sbtypes::ByteArray __fastcall GetValue(void);
	
public:
	__fastcall TElIssuingDistributionPointCRLExtension(void);
	__fastcall virtual ~TElIssuingDistributionPointCRLExtension(void);
	__property Sbx509ext::TElGeneralNames* DistributionPoint = {read=FDistributionPoint};
	__property Sbx509ext::TSBCRLReasonFlags OnlySomeReasons = {read=FReasonFlags, write=FReasonFlags, nodefault};
	__property bool OnlyContainsUserCerts = {read=FOnlyContainsUserCerts, write=FOnlyContainsUserCerts, nodefault};
	__property bool OnlyContainsCACerts = {read=FOnlyContainsCACerts, write=FOnlyContainsCACerts, nodefault};
	__property bool OnlyContainsAttributeCerts = {read=FOnlyContainsAttributeCerts, write=FOnlyContainsAttributeCerts, nodefault};
	__property bool IndirectCRL = {read=FIndirectCRL, write=FIndirectCRL, nodefault};
	__property bool ReasonFlagsIncluded = {read=FReasonFlagsIncluded, write=FReasonFlagsIncluded, nodefault};
};


#pragma option push -b-
enum TSBCRLExtension { crlAuthorityKeyIdentifier, crlIssuerAlternativeName, crlCRLNumber, crlDeltaCRLIndicator, crlIssuingDistributionPoint };
#pragma option pop

typedef Set<TSBCRLExtension, crlAuthorityKeyIdentifier, crlIssuingDistributionPoint>  TSBCRLExtensions;

class DELPHICLASS TElCRLExtensions;
class PASCALIMPLEMENTATION TElCRLExtensions : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	TElAuthorityKeyIdentifierCRLExtension* FAuthorityKeyIdentifier;
	Sbx509ext::TElAlternativeNameExtension* FIssuerAlternativeName;
	TElCRLNumberCRLExtension* FCRLNumber;
	TElDeltaCRLIndicatorCRLExtension* FDeltaCRLIndicator;
	TElIssuingDistributionPointCRLExtension* FDistributionPoint;
	Classes::TList* FOtherExtensions;
	TSBCRLExtensions FIncluded;
	void __fastcall ClearList(void);
	int __fastcall LoadFromTag(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	void __fastcall SaveToTag(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	int __fastcall AddExtension(const Sbtypes::ByteArray OID, bool Critical, const Sbtypes::ByteArray Value);
	int __fastcall GetOtherCount(void);
	void __fastcall SetOtherCount(int Value);
	Sbx509ext::TElCustomExtension* __fastcall GetOther(int Index);
	
public:
	__fastcall TElCRLExtensions(void);
	__fastcall virtual ~TElCRLExtensions(void);
	__property TElAuthorityKeyIdentifierCRLExtension* AuthorityKeyIdentifier = {read=FAuthorityKeyIdentifier};
	__property Sbx509ext::TElAlternativeNameExtension* IssuerAlternativeName = {read=FIssuerAlternativeName};
	__property TElCRLNumberCRLExtension* CRLNumber = {read=FCRLNumber};
	__property TElDeltaCRLIndicatorCRLExtension* DeltaCRLIndicator = {read=FDeltaCRLIndicator};
	__property TElIssuingDistributionPointCRLExtension* IssuingDistributionPoint = {read=FDistributionPoint};
	__property Sbx509ext::TElCustomExtension* OtherExtensions[int Index] = {read=GetOther};
	__property int OtherCount = {read=GetOtherCount, write=SetOtherCount, nodefault};
	__property TSBCRLExtensions Included = {read=FIncluded, write=FIncluded, nodefault};
};

typedef TElCRLExtensions ElCRLExtensions
#pragma option push -b-
enum TSBCRLEntryExtension { crlReasonCode, crlHoldInstructionCode, crlInvalidityDate, crlCertificateIssuer };
#pragma option pop

typedef Set<TSBCRLEntryExtension, crlReasonCode, crlCertificateIssuer>  TSBCRLEntryExtensions;

class DELPHICLASS TElCRLEntryExtensions;
class PASCALIMPLEMENTATION TElCRLEntryExtensions : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	TElReasonCodeCRLExtension* FReasonCode;
	TElHoldInstructionCodeCRLExtension* FHoldInstructionCode;
	TElInvalidityDateCRLExtension* FInvalidityDate;
	TElCertificateIssuerCRLExtension* FCertificateIssuer;
	Classes::TList* FOtherExtensions;
	TSBCRLEntryExtensions FIncluded;
	void __fastcall ClearList(void);
	int __fastcall LoadFromTag(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	void __fastcall SaveToTag(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	int __fastcall AddExtension(const Sbtypes::ByteArray OID, bool Critical, const Sbtypes::ByteArray Value);
	int __fastcall GetOtherCount(void);
	void __fastcall SetOtherCount(int Value);
	Sbx509ext::TElCustomExtension* __fastcall GetOther(int Index);
	
public:
	__fastcall TElCRLEntryExtensions(void);
	__fastcall virtual ~TElCRLEntryExtensions(void);
	__property TElReasonCodeCRLExtension* ReasonCode = {read=FReasonCode};
	__property TElHoldInstructionCodeCRLExtension* HoldInstructionCode = {read=FHoldInstructionCode};
	__property TElInvalidityDateCRLExtension* InvalidityDate = {read=FInvalidityDate};
	__property TElCertificateIssuerCRLExtension* CertificateIssuer = {read=FCertificateIssuer};
	__property Sbx509ext::TElCustomExtension* OtherExtensions[int Index] = {read=GetOther};
	__property int OtherCount = {read=GetOtherCount, write=SetOtherCount, nodefault};
	__property TSBCRLEntryExtensions Included = {read=FIncluded, write=FIncluded, nodefault};
};

typedef TElCRLEntryExtensions ElCRLEntryExtensions
class DELPHICLASS TElRevocationItem;
class PASCALIMPLEMENTATION TElRevocationItem : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	Sbtypes::ByteArray FSerialNumber;
	System::TDateTime FRevocationDate;
	TElCRLEntryExtensions* FExtensions;
	void __fastcall SetSerialNumber(const Sbtypes::ByteArray V);
	
public:
	__fastcall TElRevocationItem(void);
	__fastcall virtual ~TElRevocationItem(void);
	__property Sbtypes::ByteArray SerialNumber = {read=FSerialNumber, write=SetSerialNumber};
	__property System::TDateTime RevocationDate = {read=FRevocationDate, write=FRevocationDate};
	__property TElCRLEntryExtensions* Extensions = {read=FExtensions};
};

typedef TElRevocationItem ElRevocationItem
class DELPHICLASS TElCertificateRevocationList;
class PASCALIMPLEMENTATION TElCertificateRevocationList : public Classes::TComponent
{
	typedef Classes::TComponent inherited;
	
protected:
	Sbrdn::TElRelativeDistinguishedName* FIssuer;
	System::TDateTime FThisUpdate;
	System::TDateTime FNextUpdate;
	int FVersion;
	System::UnicodeString FLocation;
	Classes::TList* FItems;
	Sbtypes::ByteArray FSignature;
	Sbalgorithmidentifier::TElAlgorithmIdentifier* FSignatureAlgorithm;
	TElCRLExtensions* FExtensions;
	Sbtypes::ByteArray FTBS;
	Sbtypes::ByteArray FCRLBinary;
	int __fastcall ParseCertList(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	int __fastcall ParseRevokedCertificates(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	void __fastcall SaveCertList(Sbasn1tree::TElASN1ConstrainedTag* Tag, Sbx509::TElX509Certificate* Certificate);
	void __fastcall SaveRevokedCertificates(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	void __fastcall ClearList(void);
	int __fastcall GetCount(void);
	int __fastcall GetSignatureAlgorithm(void);
	int __fastcall GetCRLSize(void);
	TElRevocationItem* __fastcall GetItems(int Index);
	
public:
	__fastcall virtual TElCertificateRevocationList(Classes::TComponent* Owner);
	__fastcall virtual ~TElCertificateRevocationList(void);
	int __fastcall Add(Sbx509::TElX509Certificate* Certificate)/* overload */;
	int __fastcall Add(const Sbtypes::ByteArray SerialNumber)/* overload */;
	virtual void __fastcall Assign(Classes::TPersistent* Source);
	HIDESBASE bool __fastcall Remove(Sbx509::TElX509Certificate* Certificate)/* overload */;
	HIDESBASE bool __fastcall Remove(int Index)/* overload */;
	bool __fastcall IsPresent(Sbx509::TElX509Certificate* Certificate);
	int __fastcall IndexOf(Sbx509::TElX509Certificate* Certificate);
	void __fastcall Clear(void);
	int __fastcall LoadFromBuffer(void * Buffer, int Size);
	int __fastcall SaveToBuffer(void * Buffer, int &Size)/* overload */;
	int __fastcall LoadFromBufferPEM(void * Buffer, int Size, const System::UnicodeString Passphrase = L"");
	int __fastcall SaveToBufferPEM(void * Buffer, int &Size, const System::UnicodeString Passphrase = L"")/* overload */;
	int __fastcall LoadFromStream(Classes::TStream* Stream, int Count = 0x0);
	int __fastcall LoadFromStreamPEM(Classes::TStream* Stream, const System::UnicodeString Passphrase = L"", int Count = 0x0);
	bool __fastcall SameCRL(TElCertificateRevocationList* CRL, bool CheckUpdateTime);
	int __fastcall Validate(Sbx509::TElX509Certificate* Certificate);
	__property System::UnicodeString Location = {read=FLocation, write=FLocation};
	__property Sbrdn::TElRelativeDistinguishedName* Issuer = {read=FIssuer};
	__property System::TDateTime ThisUpdate = {read=FThisUpdate, write=FThisUpdate};
	__property System::TDateTime NextUpdate = {read=FNextUpdate, write=FNextUpdate};
	__property int SignatureAlgorithm = {read=GetSignatureAlgorithm, nodefault};
	__property Sbalgorithmidentifier::TElAlgorithmIdentifier* SignatureAlgorithmIdentifier = {read=FSignatureAlgorithm};
	__property Sbtypes::ByteArray Signature = {read=FSignature};
	__property Sbtypes::ByteArray TBS = {read=FTBS};
	__property TElRevocationItem* Items[int Index] = {read=GetItems};
	__property int Count = {read=GetCount, nodefault};
	__property TElCRLExtensions* Extensions = {read=FExtensions};
	__property int CRLSize = {read=GetCRLSize, nodefault};
};

typedef TElCertificateRevocationList ElCertificateRevocationList
class DELPHICLASS EElCRLError;
class PASCALIMPLEMENTATION EElCRLError : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElCRLError(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElCRLError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElCRLError(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElCRLError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElCRLError(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElCRLError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElCRLError(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElCRLError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElCRLError(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
static const int SB_CRL_ERROR_INVALID_FORMAT = 8705;
static const int SB_CRL_ERROR_BAD_SIGNATURE_ALGORITHM = 8706;
static const int SB_CRL_ERROR_INVALID_ISSUER = 8707;
static const int SB_CRL_ERROR_INVALID_SIGNATURE = 8708;
static const int SB_CRL_ERROR_UNSUPPORTED_VERSION = 8709;
static const int SB_CRL_ERROR_UNSUPPORTED_ALGORITHM = 8710;
static const int SB_CRL_ERROR_INVALID_CERTIFICATE = 8711;
static const int SB_CRL_ERROR_ALREADY_EXISTS = 8712;
static const int SB_CRL_ERROR_NOT_FOUND = 8713;
static const int SB_CRL_ERROR_PRIVATE_KEY_NOT_FOUND = 8714;
static const int SB_CRL_ERROR_UNSUPPORTED_CERTIFICATE = 8715;
static const int SB_CRL_ERROR_INTERNAL_ERROR = 8716;
static const int SB_CRL_ERROR_BUFFER_TOO_SMALL = 8717;
static const int SB_CRL_ERROR_NOTHING_TO_VERIFY = 8718;
static const int SB_CRL_ERROR_NO_SIGNED_CRL_FOUND = 8719;
extern PACKAGE void __fastcall Register(void);

}	/* namespace Sbcrl */
using namespace Sbcrl;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbcrlHPP
