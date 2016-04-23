// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbdes.pas' rev: 21.00

#ifndef SbdesHPP
#define SbdesHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbdes
{
//-- type declarations -------------------------------------------------------
typedef StaticArray<unsigned, 32> TDESExpandedKey;

//-- var, const, procedure ---------------------------------------------------
static const ShortInt TDESBufferSize = 0x8;
static const ShortInt TDESKeySize = 0x8;
static const Word TDESExpandedKeySize = 0x300;
static const ShortInt T3DESBufferSize = 0x8;
static const ShortInt T3DESKeySize = 0x18;
static const Word T3DESExpandedKeySize = 0x900;
extern PACKAGE void __fastcall ExpandKeyForEncryption(const Sbtypes::ByteArray Key, unsigned *ExpandedKey);
extern PACKAGE void __fastcall ExpandKeyForDecryption(const Sbtypes::ByteArray Key, unsigned *ExpandedKey);
extern PACKAGE void __fastcall Encrypt(unsigned &B0, unsigned &B1, unsigned const *ExpandedKey);
extern PACKAGE void __fastcall EncryptEDE(unsigned &B0, unsigned &B1, unsigned const *Key1, unsigned const *Key2, unsigned const *Key3);

}	/* namespace Sbdes */
using namespace Sbdes;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbdesHPP
