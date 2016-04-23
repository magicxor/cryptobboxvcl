// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbseed.pas' rev: 21.00

#ifndef SbseedHPP
#define SbseedHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbseed
{
//-- type declarations -------------------------------------------------------
typedef unsigned UInt32;

typedef __int64 UInt64;

typedef StaticArray<System::Byte, 16> TSEEDKey;

//-- var, const, procedure ---------------------------------------------------
static const ShortInt SEED_ENCODE = 0x0;
static const ShortInt SEED_DECODE = 0x1;
extern PACKAGE void __fastcall SeedCoding(unsigned &B0, unsigned &B1, unsigned &B2, unsigned &B3, System::Byte const *Key, System::Byte Direction);

}	/* namespace Sbseed */
using namespace Sbseed;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbseedHPP
