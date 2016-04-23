// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbcast128.pas' rev: 21.00

#ifndef Sbcast128HPP
#define Sbcast128HPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbcast128
{
//-- type declarations -------------------------------------------------------
typedef StaticArray<System::Byte, 16> TCAST128Key;

typedef TCAST128Key *PCAST128Key;

typedef StaticArray<unsigned, 32> TCAST128ExpandedKey;

typedef StaticArray<System::Byte, 8> TCAST128Buffer;

typedef TCAST128Buffer *PCAST128Buffer;

typedef unsigned *PLongWord;

//-- var, const, procedure ---------------------------------------------------
extern PACKAGE void __fastcall ExpandKey(System::Byte const *Key, /* out */ unsigned *ExpandedKey);
extern PACKAGE void __fastcall Encrypt16(unsigned &B0, unsigned &B1, unsigned *ExpandedKey);
extern PACKAGE void __fastcall Decrypt16(unsigned &B0, unsigned &B1, unsigned *ExpandedKey);

}	/* namespace Sbcast128 */
using namespace Sbcast128;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// Sbcast128HPP
