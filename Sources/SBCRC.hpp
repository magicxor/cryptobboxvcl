// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbcrc.pas' rev: 21.00

#ifndef SbcrcHPP
#define SbcrcHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbcrc
{
//-- type declarations -------------------------------------------------------
//-- var, const, procedure ---------------------------------------------------
extern PACKAGE StaticArray<unsigned, 256> CRC32Table;
extern PACKAGE unsigned __fastcall CRC32(void * Buffer, int Size, unsigned Start)/* overload */;
extern PACKAGE unsigned __fastcall CRC32(void * Buffer, int Size)/* overload */;

}	/* namespace Sbcrc */
using namespace Sbcrc;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbcrcHPP
