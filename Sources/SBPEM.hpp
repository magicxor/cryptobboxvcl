// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbpem.pas' rev: 21.00

#ifndef SbpemHPP
#define SbpemHPP

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
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbencoding.hpp>	// Pascal unit
#include <Sbsymmetriccrypto.hpp>	// Pascal unit
#include <Sbhashfunction.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbpem
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElPEMProcessor;
class PASCALIMPLEMENTATION TElPEMProcessor : public Classes::TComponent
{
	typedef Classes::TComponent inherited;
	
protected:
	System::UnicodeString FHeader;
	System::UnicodeString FPassphrase;
	int FEncryptionAlgorithm;
	Sbsymmetriccrypto::TSBSymmetricCryptoMode FEncryptionMode;
	
public:
	__fastcall virtual TElPEMProcessor(Classes::TComponent* AOwner);
	bool __fastcall PEMEncode(const Sbtypes::ByteArray InBuffer, Sbtypes::ByteArray &OutBuffer, bool Encrypt)/* overload */;
	int __fastcall PEMDecode(const Sbtypes::ByteArray InBuffer, Sbtypes::ByteArray &OutBuffer)/* overload */;
	bool __fastcall PEMEncode(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, bool Encrypt)/* overload */;
	int __fastcall PEMDecode(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	
__published:
	__property System::UnicodeString Header = {read=FHeader, write=FHeader};
	__property System::UnicodeString Passphrase = {read=FPassphrase, write=FPassphrase};
	__property int EncryptionAlgorithm = {read=FEncryptionAlgorithm, write=FEncryptionAlgorithm, nodefault};
	__property Sbsymmetriccrypto::TSBSymmetricCryptoMode EncryptionMode = {read=FEncryptionMode, write=FEncryptionMode, nodefault};
public:
	/* TComponent.Destroy */ inline __fastcall virtual ~TElPEMProcessor(void) { }
	
};


class DELPHICLASS EElPEMError;
class PASCALIMPLEMENTATION EElPEMError : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElPEMError(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElPEMError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElPEMError(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElPEMError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElPEMError(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElPEMError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElPEMError(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElPEMError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElPEMError(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
static const int PEM_DECODE_RESULT_OK = 0;
static const int PEM_DECODE_RESULT_INVALID_FORMAT = 7425;
static const int PEM_DECODE_RESULT_INVALID_PASSPHRASE = 7426;
static const int PEM_DECODE_RESULT_NOT_ENOUGH_SPACE = 7427;
static const int PEM_DECODE_RESULT_UNKNOWN_CIPHER = 7428;
extern PACKAGE Sbtypes::ByteArray PEM_BEGIN_CERTIFICATE_LINE;
extern PACKAGE Sbtypes::ByteArray PEM_END_CERTIFICATE_LINE;
extern PACKAGE void __fastcall RaisePEMError(int ErrorCode);
extern PACKAGE bool __fastcall EncodeEx(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, const System::UnicodeString Header, int EncryptionAlgorithm, const System::UnicodeString PassPhrase)/* overload */;
extern PACKAGE bool __fastcall EncodeEx(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, const System::UnicodeString Header, int EncryptionAlgorithm, Sbsymmetriccrypto::TSBSymmetricCryptoMode EncryptionMode, const System::UnicodeString PassPhrase)/* overload */;
extern PACKAGE bool __fastcall Encode(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, const System::UnicodeString Header, bool Encrypt, const System::UnicodeString PassPhrase);
extern PACKAGE int __fastcall Decode(void * InBuffer, int InSize, void * OutBuffer, const System::UnicodeString PassPhrase, int &OutSize, System::UnicodeString &Header);
extern PACKAGE bool __fastcall IsBase64UnicodeSequence(void * Buffer, int Size);
extern PACKAGE bool __fastcall IsBase64Sequence(void * Buffer, int Size);
extern PACKAGE bool __fastcall IsPEMSequence(void * Buffer, int Size);

}	/* namespace Sbpem */
using namespace Sbpem;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbpemHPP
