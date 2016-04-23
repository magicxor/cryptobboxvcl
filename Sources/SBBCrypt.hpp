// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbbcrypt.pas' rev: 21.00

#ifndef SbbcryptHPP
#define SbbcryptHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbencoding.hpp>	// Pascal unit
#include <Sbblowfish.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbrandom.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbbcrypt
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElBCrypt;
class PASCALIMPLEMENTATION TElBCrypt : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	__classmethod Sbtypes::ByteArray __fastcall EncryptRaw(int Rounds, const Sbtypes::ByteArray Password, const Sbtypes::ByteArray Salt);
	__classmethod System::UnicodeString __fastcall Base64Encode(const Sbtypes::ByteArray Value);
	__classmethod Sbtypes::ByteArray __fastcall Base64Decode(const System::UnicodeString Value);
	
public:
	__classmethod Sbtypes::ByteArray __fastcall GenerateSalt();
	__classmethod System::UnicodeString __fastcall EncryptPassword(const System::UnicodeString Password)/* overload */;
	__classmethod System::UnicodeString __fastcall EncryptPassword(const System::UnicodeString Password, Sbtypes::ByteArray Salt)/* overload */;
	__classmethod System::UnicodeString __fastcall EncryptPassword(const System::UnicodeString Password, Sbtypes::ByteArray Salt, int Rounds)/* overload */;
	__classmethod bool __fastcall CheckPassword(const System::UnicodeString Password, const System::UnicodeString EncryptedPassword);
public:
	/* TObject.Create */ inline __fastcall TElBCrypt(void) : System::TObject() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TElBCrypt(void) { }
	
};


class DELPHICLASS EElBCryptException;
class PASCALIMPLEMENTATION EElBCryptException : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElBCryptException(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElBCryptException(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElBCryptException(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElBCryptException(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElBCryptException(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElBCryptException(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElBCryptException(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElBCryptException(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElBCryptException(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE System::ResourceString _SInvalidRoundsNumber;
#define Sbbcrypt_SInvalidRoundsNumber System::LoadResourceString(&Sbbcrypt::_SInvalidRoundsNumber)
extern PACKAGE System::ResourceString _SInvalidSaltSize;
#define Sbbcrypt_SInvalidSaltSize System::LoadResourceString(&Sbbcrypt::_SInvalidSaltSize)
extern PACKAGE System::ResourceString _SInvalidPasswordLength;
#define Sbbcrypt_SInvalidPasswordLength System::LoadResourceString(&Sbbcrypt::_SInvalidPasswordLength)
extern PACKAGE System::ResourceString _SInvalidBase64Encoding;
#define Sbbcrypt_SInvalidBase64Encoding System::LoadResourceString(&Sbbcrypt::_SInvalidBase64Encoding)
extern PACKAGE System::ResourceString _SInvalidEncryptedPassword;
#define Sbbcrypt_SInvalidEncryptedPassword System::LoadResourceString(&Sbbcrypt::_SInvalidEncryptedPassword)

}	/* namespace Sbbcrypt */
using namespace Sbbcrypt;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbbcryptHPP
