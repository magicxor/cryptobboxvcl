// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbocspcommon.pas' rev: 21.00

#ifndef SbocspcommonHPP
#define SbocspcommonHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbx509.hpp>	// Pascal unit
#include <Sbx509ext.hpp>	// Pascal unit
#include <Sbcustomcertstorage.hpp>	// Pascal unit
#include <Sbasn1.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbocspcommon
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS EElOCSPParseError;
class PASCALIMPLEMENTATION EElOCSPParseError : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElOCSPParseError(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElOCSPParseError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElOCSPParseError(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElOCSPParseError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElOCSPParseError(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElOCSPParseError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElOCSPParseError(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElOCSPParseError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElOCSPParseError(void) { }
	
};


#pragma option push -b-
enum TElOCSPServerError { oseSuccessful, oseMalformedRequest, oseInternalError, oseTryLater, oseUnused1, oseSigRequired, oseUnauthorized };
#pragma option pop

#pragma option push -b-
enum TElOCSPCertificateStatus { csGood, csRevoked, csUnknown };
#pragma option pop

#pragma option push -b-
enum TElResponderIDType { ritName, ritKeyHash };
#pragma option pop

typedef DynamicArray<TElOCSPCertificateStatus> TElOCSPReplyArray;

typedef void __fastcall (__closure *TSBCertificateOCSPCheckEvent)(System::TObject* Sender, const Sbtypes::ByteArray HashAlgOID, const Sbtypes::ByteArray IssuerNameHash, const Sbtypes::ByteArray IssuerKeyHash, const Sbtypes::ByteArray CertificateSerial, TElOCSPCertificateStatus &CertStatus, Sbx509ext::TSBCRLReasonFlag &Reason, System::TDateTime &RevocationTime, System::TDateTime &ThisUpdate, System::TDateTime &NextUpdate);

typedef void __fastcall (__closure *TSBOCSPSignatureValidateEvent)(System::TObject* Sender, bool &Valid);

typedef void __fastcall (__closure *TSBOCSPCertificateNeededEvent)(System::TObject* Sender, Sbx509::TElX509Certificate* &Certificate);

class DELPHICLASS TElOCSPClass;
class PASCALIMPLEMENTATION TElOCSPClass : public Classes::TComponent
{
	typedef Classes::TComponent inherited;
	
protected:
	bool FIncludeCertificates;
	Sbx509ext::TElGeneralName* FRequestorName;
	Sbcustomcertstorage::TElCustomCertStorage* FSigningCertStorage;
	TSBOCSPCertificateNeededEvent FOnCertificateNeeded;
	virtual void __fastcall Notification(Classes::TComponent* AComponent, Classes::TOperation AOperation);
	void __fastcall SetSigningCertStorage(const Sbcustomcertstorage::TElCustomCertStorage* Value);
	
public:
	__fastcall virtual TElOCSPClass(Classes::TComponent* Owner);
	__fastcall virtual ~TElOCSPClass(void);
	__property Sbx509ext::TElGeneralName* RequestorName = {read=FRequestorName};
	
__published:
	__property bool IncludeCertificates = {read=FIncludeCertificates, write=FIncludeCertificates, nodefault};
	__property Sbcustomcertstorage::TElCustomCertStorage* SigningCertStorage = {read=FSigningCertStorage, write=SetSigningCertStorage};
	__property TSBOCSPCertificateNeededEvent OnCertificateNeeded = {read=FOnCertificateNeeded, write=FOnCertificateNeeded};
};

typedef TElOCSPClass ElOCSPClass
class DELPHICLASS EElOCSPError;
class PASCALIMPLEMENTATION EElOCSPError : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElOCSPError(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElOCSPError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElOCSPError(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElOCSPError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElOCSPError(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElOCSPError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElOCSPError(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElOCSPError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElOCSPError(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
static const int ERROR_FACILITY_OCSP = 0x13000;
static const Word ERROR_OCSP_PROTOCOL_ERROR_FLAG = 0x800;
static const int SB_OCSP_ERROR_NO_CERTIFICATES = 79873;
static const int SB_OCSP_ERROR_NO_ISSUER_CERTIFICATES = 79874;
static const int SB_OCSP_ERROR_WRONG_DATA = 79875;
static const int SB_OCSP_ERROR_NO_EVENT_HANDLER = 79876;
static const int SB_OCSP_ERROR_NO_PARAMETERS = 79877;
static const int SB_OCSP_ERROR_NO_REPLY = 79878;
static const int SB_OCSP_ERROR_WRONG_SIGNATURE = 79879;
static const int SB_OCSP_ERROR_UNSUPPORTED_ALGORITHM = 79880;
static const int SB_OCSP_ERROR_INVALID_RESPONSE = 79881;
extern PACKAGE Sbtypes::ByteArray SB_OCSP_OID_BASIC_RESPONSE;
extern PACKAGE Sbtypes::ByteArray SB_OCSP_OID_NONCE;
extern PACKAGE Sbtypes::ByteArray SB_OCSP_OID_OCSP_RESPONSE;
extern PACKAGE Sbtypes::ByteArray SB_OID_OCSP_RESPONSE;
extern PACKAGE int __fastcall ReasonFlagToEnum(Sbx509ext::TSBCRLReasonFlag Value);
extern PACKAGE Sbx509ext::TSBCRLReasonFlag __fastcall EnumToReasonFlag(int Value);
extern PACKAGE Sbtypes::ByteArray __fastcall ReadAsnInteger(const Sbtypes::ByteArray IntBuf);

}	/* namespace Sbocspcommon */
using namespace Sbocspcommon;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbocspcommonHPP
