// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbpkcs8.pas' rev: 21.00

#ifndef Sbpkcs8HPP
#define Sbpkcs8HPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbpkcs7.hpp>	// Pascal unit
#include <Sbpkcs7utils.hpp>	// Pascal unit
#include <Sbpkcs5.hpp>	// Pascal unit
#include <Sbasn1.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sbpem.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbpkcs8
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElPKCS8PrivateKeyInfo;
class PASCALIMPLEMENTATION TElPKCS8PrivateKeyInfo : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	Sbtypes::ByteArray FPrivateKeyAlgorithm;
	Sbtypes::ByteArray FPrivateKeyAlgorithmParams;
	Sbtypes::ByteArray FPrivateKey;
	void __fastcall SetPrivateKeyAlgorithm(const Sbtypes::ByteArray V);
	void __fastcall SetPrivateKeyAlgorithmParams(const Sbtypes::ByteArray V);
	void __fastcall SetPrivateKey(const Sbtypes::ByteArray V);
	void __fastcall Clear(void);
	
public:
	__fastcall TElPKCS8PrivateKeyInfo(void);
	__fastcall virtual ~TElPKCS8PrivateKeyInfo(void);
	int __fastcall LoadFromBuffer(void * Buffer, int Size);
	bool __fastcall SaveToBuffer(void * Buffer, int &Size);
	int __fastcall LoadFromStream(Classes::TStream* Stream, int Count = 0x0);
	bool __fastcall SaveToStream(Classes::TStream* Stream);
	__property Sbtypes::ByteArray PrivateKeyAlgorithm = {read=FPrivateKeyAlgorithm, write=SetPrivateKeyAlgorithm};
	__property Sbtypes::ByteArray PrivateKeyAlgorithmParams = {read=FPrivateKeyAlgorithmParams, write=SetPrivateKeyAlgorithmParams};
	__property Sbtypes::ByteArray PrivateKey = {read=FPrivateKey, write=SetPrivateKey};
};


class DELPHICLASS TElPKCS8EncryptedPrivateKeyInfo;
class PASCALIMPLEMENTATION TElPKCS8EncryptedPrivateKeyInfo : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	Sbtypes::ByteArray FEncryptionAlgorithm;
	Sbtypes::ByteArray FEncryptionAlgorithmParams;
	Sbtypes::ByteArray FEncryptedData;
	void __fastcall SetEncryptionAlgorithm(const Sbtypes::ByteArray V);
	void __fastcall SetEncryptionAlgorithmParams(const Sbtypes::ByteArray V);
	void __fastcall SetEncryptedData(const Sbtypes::ByteArray V);
	
public:
	__fastcall virtual ~TElPKCS8EncryptedPrivateKeyInfo(void);
	int __fastcall LoadFromBuffer(void * Buffer, int Size);
	bool __fastcall SaveToBuffer(void * Buffer, int &Size);
	int __fastcall LoadFromStream(Classes::TStream* Stream, int Count = 0x0);
	bool __fastcall SaveToStream(Classes::TStream* Stream);
	int __fastcall LoadFromTag(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	bool __fastcall SaveToTag(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	__property Sbtypes::ByteArray EncryptionAlgorithm = {read=FEncryptionAlgorithm, write=SetEncryptionAlgorithm};
	__property Sbtypes::ByteArray EncryptionAlgorithmParams = {read=FEncryptionAlgorithmParams, write=SetEncryptionAlgorithmParams};
	__property Sbtypes::ByteArray EncryptedData = {read=FEncryptedData, write=SetEncryptedData};
public:
	/* TObject.Create */ inline __fastcall TElPKCS8EncryptedPrivateKeyInfo(void) : System::TObject() { }
	
};


class DELPHICLASS TElPKCS8PrivateKey;
class PASCALIMPLEMENTATION TElPKCS8PrivateKey : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	TElPKCS8PrivateKeyInfo* FKeyInfo;
	TElPKCS8EncryptedPrivateKeyInfo* FEncryptedKeyInfo;
	int FAlgorithm;
	bool FUseNewFeatures;
	int __fastcall ProcessEncryptedInfo(const System::UnicodeString Password);
	void __fastcall SetSymmetricAlgorithm(int Value);
	int __fastcall GetSymmetricAlgorithm(void);
	void __fastcall SetUseNewFeatures(bool Value);
	bool __fastcall GetUseNewFeatures(void);
	Sbtypes::ByteArray __fastcall GetKeyMaterial(void);
	void __fastcall SetKeyMaterial(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetKeyAlgorithm(void);
	void __fastcall SetKeyAlgorithm(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetKeyAlgorithmParams(void);
	void __fastcall SetKeyAlgorithmParams(const Sbtypes::ByteArray Value);
	
public:
	__fastcall TElPKCS8PrivateKey(void);
	__fastcall virtual ~TElPKCS8PrivateKey(void);
	int __fastcall LoadFromBuffer(void * Buffer, int Size, const System::UnicodeString Passphrase = L"");
	int __fastcall SaveToBuffer(void * Buffer, int &Size, const System::UnicodeString Passphrase = L"", bool UsePEMEnvelope = true);
	int __fastcall LoadFromStream(Classes::TStream* Stream, const System::UnicodeString Passphrase = L"", int Count = 0x0);
	int __fastcall SaveToStream(Classes::TStream* Stream, const System::UnicodeString Passphrase = L"", bool UsePEMEnvelope = true);
	__property int SymmetricAlgorithm = {read=GetSymmetricAlgorithm, write=SetSymmetricAlgorithm, nodefault};
	__property bool UseNewFeatures = {read=GetUseNewFeatures, write=SetUseNewFeatures, default=0};
	__property Sbtypes::ByteArray KeyMaterial = {read=GetKeyMaterial, write=SetKeyMaterial};
	__property Sbtypes::ByteArray KeyAlgorithm = {read=GetKeyAlgorithm, write=SetKeyAlgorithm};
	__property Sbtypes::ByteArray KeyAlgorithmParams = {read=GetKeyAlgorithmParams, write=SetKeyAlgorithmParams};
};


class DELPHICLASS EElPKCS8Error;
class PASCALIMPLEMENTATION EElPKCS8Error : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElPKCS8Error(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElPKCS8Error(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElPKCS8Error(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElPKCS8Error(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElPKCS8Error(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElPKCS8Error(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElPKCS8Error(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElPKCS8Error(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElPKCS8Error(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
static const int SB_PKCS8_ERROR_OK = 0;
static const int SB_PKCS8_ERROR_INVALID_ASN_DATA = 8961;
static const int SB_PKCS8_ERROR_INVALID_FORMAT = 8962;
static const int SB_PKCS8_ERROR_UNSUPPORTED_ALGORITHM = 8963;
static const int SB_PKCS8_ERROR_INVALID_PASSWORD = 8964;
static const int SB_PKCS8_ERROR_INVALID_VERSION = 8965;
static const int SB_PKCS8_ERROR_INVALID_PARAMETER = 8966;
static const int SB_PKCS8_ERROR_UNKNOWN = 8967;
static const int SB_PKCS8_ERROR_BUFFER_TOO_SMALL = 8968;
static const int SB_PKCS8_ERROR_NO_PRIVATE_KEY = 8969;
extern PACKAGE void __fastcall RaisePKCS8Error(int ErrorCode);

}	/* namespace Sbpkcs8 */
using namespace Sbpkcs8;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// Sbpkcs8HPP
