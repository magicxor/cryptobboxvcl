// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbidea.pas' rev: 21.00

#ifndef SbideaHPP
#define SbideaHPP

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

namespace Sbidea
{
//-- type declarations -------------------------------------------------------
typedef StaticArray<System::Byte, 16> TIDEAKey;

typedef TIDEAKey *PIDEAKey;

typedef StaticArray<System::Word, 52> TIDEAExpandedKey;

typedef TIDEAExpandedKey *PIDEAExpandedKey;

//-- var, const, procedure ---------------------------------------------------
static const ShortInt TIDEAExpandedKeySize = 0x68;
extern PACKAGE bool IdeaEnabled;
extern PACKAGE void __fastcall ExpandKeyForEncryption(System::Byte const *Key, /* out */ System::Word *ExpandedKey);
extern PACKAGE void __fastcall ExpandKeyForDecryption(System::Word const *CipherKey, /* out */ System::Word *DecipherKey);
extern PACKAGE void __fastcall Encrypt(unsigned &B0, unsigned &B1, System::Word const *Key);

}	/* namespace Sbidea */
using namespace Sbidea;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbideaHPP
