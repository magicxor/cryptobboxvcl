// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbrandom.pas' rev: 21.00

#ifndef SbrandomHPP
#define SbrandomHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbmath.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Windows.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstreams.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbrandom
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElRandom;
class PASCALIMPLEMENTATION TElRandom : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	StaticArray<System::Byte, 256> S;
	int CI;
	int CJ;
	
public:
	__fastcall TElRandom(void)/* overload */;
	__fastcall TElRandom(unsigned TimeSeed)/* overload */;
	__fastcall virtual ~TElRandom(void);
	void __fastcall Randomize(const Sbtypes::ByteArray Seed)/* overload */;
	void __fastcall Randomize(Classes::TStream* Stream, int Count = 0x0)/* overload */;
	Sbtypes::ByteArray __fastcall Generate(int Count)/* overload */;
	void __fastcall Randomize(void * Buffer, int Count)/* overload */;
	void __fastcall Generate(void * Buffer, int Count)/* overload */;
	void __fastcall Seed(void * Buffer, int Count);
	void __fastcall Generate(Classes::TStream* Stream, int Count)/* overload */;
};

typedef TElRandom ElRandom
//-- var, const, procedure ---------------------------------------------------
extern PACKAGE int __fastcall SBRndTimeSeed(void);
extern PACKAGE void __fastcall SBRndInit(void);
extern PACKAGE void __fastcall SBRndCreate(void);
extern PACKAGE void __fastcall SBRndDestroy(void);
extern PACKAGE void __fastcall SBRndSeed(const System::UnicodeString Salt = L"")/* overload */;
extern PACKAGE void __fastcall SBRndSeed(void * Buffer, int Size)/* overload */;
extern PACKAGE void __fastcall SBRndSeedTime(void);
extern PACKAGE void __fastcall SBRndGenerate(void * Buffer, int Size)/* overload */;
extern PACKAGE unsigned __fastcall SBRndGenerate(unsigned UpperBound = (unsigned)(0x0))/* overload */;
extern PACKAGE void __fastcall SBRndGenerateLInt(Sbmath::PLInt A, int Bytes);
extern PACKAGE void __fastcall SBRndRandomize(const Sbtypes::ByteArray Seed);

}	/* namespace Sbrandom */
using namespace Sbrandom;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbrandomHPP
