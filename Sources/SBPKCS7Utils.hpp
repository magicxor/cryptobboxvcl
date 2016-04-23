// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbpkcs7utils.pas' rev: 21.00

#ifndef Sbpkcs7utilsHPP
#define Sbpkcs7utilsHPP

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
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbrdn.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbpkcs7utils
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElPKCS7Attributes;
class PASCALIMPLEMENTATION TElPKCS7Attributes : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	Sbutils::TElByteArrayList* FAttributes;
	Sbutils::TElByteArrayList* FRawAttributeSequences;
	Classes::TList* FValues;
	
protected:
	void __fastcall QuickSort(int L, int R);
	void __fastcall SetCount(int Value);
	int __fastcall GetCount(void);
	Sbtypes::ByteArray __fastcall GetAttribute(int Index);
	void __fastcall SetAttribute(int Index, const Sbtypes::ByteArray Value);
	Sbutils::TElByteArrayList* __fastcall GetValues(int Index);
	Sbtypes::ByteArray __fastcall GetRawAttributeSequence(int Index);
	void __fastcall SetRawAttributeSequence(int Index, const Sbtypes::ByteArray Value);
	
public:
	__fastcall TElPKCS7Attributes(void);
	__fastcall virtual ~TElPKCS7Attributes(void);
	bool __fastcall Remove(int Index);
	void __fastcall Copy(TElPKCS7Attributes* Dest);
	bool __fastcall SaveToBuffer(void * Buffer, int &Size);
	int __fastcall FindAttribute(const Sbtypes::ByteArray Name);
	void __fastcall SortLexicographically(void);
	void __fastcall RecalculateRawAttributeSequences(void);
	void __fastcall Clear(void);
	__property Sbtypes::ByteArray Attributes[int Index] = {read=GetAttribute, write=SetAttribute};
	__property Sbutils::TElByteArrayList* Values[int Index] = {read=GetValues};
	__property Sbtypes::ByteArray RawAttributeSequences[int Index] = {read=GetRawAttributeSequence, write=SetRawAttributeSequence};
	__property int Count = {read=GetCount, write=SetCount, nodefault};
};


#pragma option push -b-
enum TSBPKCS7IssuerType { itIssuerAndSerialNumber, itSubjectKeyIdentifier };
#pragma option pop

class DELPHICLASS TElPKCS7Issuer;
class PASCALIMPLEMENTATION TElPKCS7Issuer : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	Sbrdn::TElRelativeDistinguishedName* FIssuer;
	Sbtypes::ByteArray FSerialNumber;
	Sbtypes::ByteArray FSubjectKeyIdentifier;
	TSBPKCS7IssuerType FIssuerType;
	void __fastcall SetSerialNumber(const Sbtypes::ByteArray V);
	void __fastcall SetSubjectKeyIdentifier(const Sbtypes::ByteArray V);
	
public:
	__fastcall TElPKCS7Issuer(void);
	__fastcall virtual ~TElPKCS7Issuer(void);
	void __fastcall Assign(TElPKCS7Issuer* Source);
	__property Sbrdn::TElRelativeDistinguishedName* Issuer = {read=FIssuer};
	__property Sbtypes::ByteArray SerialNumber = {read=FSerialNumber, write=SetSerialNumber};
	__property Sbtypes::ByteArray SubjectKeyIdentifier = {read=FSubjectKeyIdentifier, write=SetSubjectKeyIdentifier};
	__property TSBPKCS7IssuerType IssuerType = {read=FIssuerType, write=FIssuerType, nodefault};
};


//-- var, const, procedure ---------------------------------------------------
static const int SB_PKCS7_ERROR_INVALID_ASN_DATA = 7681;
static const int SB_PKCS7_ERROR_NO_DATA = 7682;
static const int SB_PKCS7_ERROR_INVALID_CONTENT_INFO = 7683;
static const int SB_PKCS7_ERROR_UNKNOWN_DATA_TYPE = 7684;
static const int SB_PKCS7_ERROR_INVALID_DATA = 7685;
static const int SB_PKCS7_ERROR_INVALID_ENVELOPED_DATA = 7686;
static const int SB_PKCS7_ERROR_INVALID_ENVELOPED_DATA_VERSION = 7687;
static const int SB_PKCS7_ERROR_INVALID_ENVELOPED_DATA_CONTENT = 7688;
static const int SB_PKCS7_ERROR_INVALID_RECIPIENT_INFOS = 7689;
static const int SB_PKCS7_ERROR_INVALID_RECIPIENT_INFO = 7690;
static const int SB_PKCS7_ERROR_INVALID_RECIPIENT_INFO_VERSION = 7691;
static const int SB_PKCS7_ERROR_INVALID_RECIPIENT_INFO_KEY = 7692;
static const int SB_PKCS7_ERROR_INVALID_ISSUER = 7693;
static const int SB_PKCS7_ERROR_INVALID_ALGORITHM = 7694;
static const int SB_PKCS7_ERROR_INVALID_SIGNED_DATA = 7695;
static const int SB_PKCS7_ERROR_INVALID_SIGNED_DATA_VERSION = 7696;
static const int SB_PKCS7_ERROR_INVALID_SIGNER_INFOS = 7697;
static const int SB_PKCS7_ERROR_INVALID_SIGNER_INFO_VERSION = 7698;
static const int SB_PKCS7_ERROR_INVALID_SIGNER_INFO = 7699;
static const int SB_PKCS7_ERROR_INTERNAL_ERROR = 7700;
static const int SB_PKCS7_ERROR_INVALID_ATTRIBUTES = 7701;
static const int SB_PKCS7_ERROR_INVALID_DIGESTED_DATA = 7702;
static const int SB_PKCS7_ERROR_INVALID_DIGESTED_DATA_VERSION = 7703;
static const int SB_PKCS7_ERROR_INVALID_ENCRYPTED_DATA = 7704;
static const int SB_PKCS7_ERROR_INVALID_ENCRYPTED_DATA_VERSION = 7705;
static const int SB_PKCS7_ERROR_INVALID_SIGNED_AND_ENVELOPED_DATA = 7706;
static const int SB_PKCS7_ERROR_INVALID_SIGNED_AND_ENVELOPED_DATA_VERSION = 7707;
static const int SB_PKCS7_ERROR_INVALID_AUTHENTICATED_DATA = 7708;
static const int SB_PKCS7_ERROR_INVALID_AUTHENTICATED_DATA_VERSION = 7709;
static const int SB_PKCS7_ERROR_INVALID_COMPRESSED_DATA = 7710;
static const int SB_PKCS7_ERROR_INVALID_COMPRESSED_DATA_CONTENT = 7711;
static const int SB_PKCS7_ERROR_INVALID_TIMESTAMPED_DATA = 7712;
static const int SB_PKCS7_ERROR_INVALID_TIMESTAMPED_DATA_VERSION = 7713;
static const int SB_PKCS7_ERROR_INVALID_TIMESTAMPED_DATA_CONTENT = 7714;
extern PACKAGE void __fastcall SaveAttributes(Sbasn1tree::TElASN1ConstrainedTag* Tag, TElPKCS7Attributes* Attributes, System::Byte TagID = (System::Byte)(0x31));
extern PACKAGE void __fastcall SaveAlgorithmIdentifier(Sbasn1tree::TElASN1ConstrainedTag* Tag, const Sbtypes::ByteArray Algorithm, const Sbtypes::ByteArray Params, System::Byte ImplicitTag = (System::Byte)(0x0), bool WriteNullIfParamsAreEmpty = true);
extern PACKAGE int __fastcall ProcessAlgorithmIdentifier(Sbasn1tree::TElASN1CustomTag* Tag, Sbtypes::ByteArray &Algorithm, Sbtypes::ByteArray &Params, bool ImplicitTagging = false);

}	/* namespace Sbpkcs7utils */
using namespace Sbpkcs7utils;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// Sbpkcs7utilsHPP
