// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbpunycode.pas' rev: 21.00

#ifndef SbpunycodeHPP
#define SbpunycodeHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbpunycode
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS EElPunycodeError;
class PASCALIMPLEMENTATION EElPunycodeError : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElPunycodeError(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElPunycodeError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElPunycodeError(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElPunycodeError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElPunycodeError(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElPunycodeError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElPunycodeError(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElPunycodeError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElPunycodeError(void) { }
	
};


typedef System::WideChar CodePoint;

typedef DynamicArray<System::WideChar> CodePointArray;

//-- var, const, procedure ---------------------------------------------------
static const ShortInt BASE = 0x24;
static const ShortInt TMIN = 0x1;
static const ShortInt TMAX = 0x1a;
static const ShortInt SKEW = 0x26;
static const Word DAMP = 0x2bc;
static const ShortInt INITIAL_BIAS = 0x48;
static const Byte INITIAL_N = 0x80;
static const ShortInt DELIMITER = 0x2d;
static const int MAXUINTGR = 2147483647;
static const Word MAXPUNYLEN = 0x100;
static const ShortInt SB_PUNYCODE_BAD_INPUT = 0x1;
static const ShortInt SB_PUNYCODE_BIG_OUTPUT = 0x2;
static const ShortInt SB_PUNYCODE_OVERFLOW = 0x3;
extern PACKAGE System::ResourceString _SBadInput;
#define Sbpunycode_SBadInput System::LoadResourceString(&Sbpunycode::_SBadInput)
extern PACKAGE System::ResourceString _SBigOutput;
#define Sbpunycode_SBigOutput System::LoadResourceString(&Sbpunycode::_SBigOutput)
extern PACKAGE System::ResourceString _SOverflow;
#define Sbpunycode_SOverflow System::LoadResourceString(&Sbpunycode::_SOverflow)
extern PACKAGE System::UnicodeString __fastcall PunycodeEncode(const System::UnicodeString Input);
extern PACKAGE System::UnicodeString __fastcall PunycodeDecode(const System::UnicodeString Input);
extern PACKAGE System::UnicodeString __fastcall ToASCII(const System::UnicodeString Domain);
extern PACKAGE System::UnicodeString __fastcall ToUnicode(const System::UnicodeString Domain);

}	/* namespace Sbpunycode */
using namespace Sbpunycode;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbpunycodeHPP
