// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbrc2.pas' rev: 21.00

#ifndef Sbrc2HPP
#define Sbrc2HPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbrc2
{
//-- type declarations -------------------------------------------------------
typedef DynamicArray<System::Byte> TRC2Key;

typedef StaticArray<System::Word, 64> TRC2ExpandedKey;

//-- var, const, procedure ---------------------------------------------------
static const ShortInt TRC2BufferSize = 0x8;
static const ShortInt TRC2ExpandedKeyLength = 0x40;
extern PACKAGE void __fastcall ExpandKey(const TRC2Key Key, /* out */ System::Word *ExpandedKey);
extern PACKAGE void __fastcall Encrypt(unsigned &B0, unsigned &B1, System::Word const *ExpandedKey);
extern PACKAGE void __fastcall Decrypt(unsigned &B0, unsigned &B1, System::Word const *ExpandedKey);
extern PACKAGE bool __fastcall ParseASN1Params(const Sbtypes::ByteArray Params, Sbtypes::ByteArray &IV, int &KeyBits);
extern PACKAGE void __fastcall WriteASN1Params(const Sbtypes::ByteArray IV, int KeyBits, Sbtypes::ByteArray &Params);

}	/* namespace Sbrc2 */
using namespace Sbrc2;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// Sbrc2HPP
