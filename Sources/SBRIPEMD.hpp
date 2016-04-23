// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbripemd.pas' rev: 21.00

#ifndef SbripemdHPP
#define SbripemdHPP

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

namespace Sbripemd
{
//-- type declarations -------------------------------------------------------
typedef StaticArray<unsigned, 16> TRMD160Buffer;

#pragma pack(push,1)
struct TRMD160Context
{
	
public:
	TRMD160Buffer Buffer;
	unsigned BufSize;
	unsigned h1;
	unsigned h2;
	unsigned h3;
	unsigned h4;
	unsigned h5;
	unsigned MessageSizeLo;
	unsigned MessageSizeHi;
};
#pragma pack(pop)


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE void __fastcall InitializeRMD160(TRMD160Context &Context);
extern PACKAGE void __fastcall HashRMD160(TRMD160Context &Context, void * Chunk, int Size)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest160 __fastcall HashRMD160(void * Buffer, int Size)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest160 __fastcall HashRMD160(const System::UnicodeString Buffer)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest160 __fastcall HashRMD160(const Sbtypes::ByteArray Buffer)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest160 __fastcall FinalizeRMD160(TRMD160Context &Context);

}	/* namespace Sbripemd */
using namespace Sbripemd;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbripemdHPP
