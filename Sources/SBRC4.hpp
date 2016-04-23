// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbrc4.pas' rev: 21.00

#ifndef Sbrc4HPP
#define Sbrc4HPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbrc4
{
//-- type declarations -------------------------------------------------------
typedef DynamicArray<System::Byte> TRC4Key;

typedef StaticArray<System::Byte, 256> TRC4ExpandedKey;

struct TRC4Context
{
	
public:
	System::Byte L;
	System::Byte K;
	StaticArray<System::Byte, 256> TK;
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE void __fastcall Initialize(TRC4Context &Context, const TRC4Key Key);
extern PACKAGE bool __fastcall Encrypt(TRC4Context &Context, void * Buf, void * OutBuf, unsigned Size)/* overload */;
extern PACKAGE bool __fastcall Decrypt(TRC4Context &Context, void * Buf, void * OutBuf, unsigned Size)/* overload */;
extern PACKAGE bool __fastcall NFinalize(TRC4Context &Context);
extern PACKAGE void __fastcall Encrypt(void * InBuffer, const int Size, System::Byte const *ExpandedKey, void * OutBuffer)/* overload */;
extern PACKAGE void __fastcall Decrypt(void * InBuffer, const int Size, System::Byte const *ExpandedKey, void * OutBuffer)/* overload */;

}	/* namespace Sbrc4 */
using namespace Sbrc4;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// Sbrc4HPP
