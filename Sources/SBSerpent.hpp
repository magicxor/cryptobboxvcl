// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbserpent.pas' rev: 21.00

#ifndef SbserpentHPP
#define SbserpentHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbserpent
{
//-- type declarations -------------------------------------------------------
typedef DynamicArray<System::Byte> TSerpentKey;

typedef StaticArray<System::Byte, 16> TSerpentBuffer;

typedef StaticArray<StaticArray<unsigned, 4>, 33> TSerpentExpandedKey;

typedef TSerpentExpandedKey *PSerpentExpandedKey;

typedef StaticArray<unsigned, 132> TSerpentExpandedKeyEx;

//-- var, const, procedure ---------------------------------------------------
extern PACKAGE void __fastcall ExpandKey(const TSerpentKey Key, StaticArray<unsigned, 4> *ExpandedKey);
extern PACKAGE void __fastcall EncryptBlock(unsigned &B0, unsigned &B1, unsigned &B2, unsigned &B3, StaticArray<unsigned, 4> const *ExpandedKey);
extern PACKAGE void __fastcall DecryptBlock(unsigned &B0, unsigned &B1, unsigned &B2, unsigned &B3, StaticArray<unsigned, 4> const *ExpandedKey);

}	/* namespace Sbserpent */
using namespace Sbserpent;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbserpentHPP
