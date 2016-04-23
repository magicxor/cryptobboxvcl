// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbmd.pas' rev: 21.00

#ifndef SbmdHPP
#define SbmdHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbmd
{
//-- type declarations -------------------------------------------------------
#pragma pack(push,1)
struct TMD5Context
{
	
public:
	__int64 Size;
	StaticArray<System::Byte, 64> Buffer;
	unsigned BufSize;
	unsigned A;
	unsigned B;
	unsigned C;
	unsigned D;
};
#pragma pack(pop)


#pragma pack(push,1)
struct TMD2Context
{
	
public:
	__int64 Size;
	StaticArray<System::Byte, 16> Checksum;
	StaticArray<System::Byte, 16> Buffer;
	int BufSize;
	StaticArray<System::Byte, 16> State;
};
#pragma pack(pop)


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE void __fastcall InternalMD5(Sbtypes::PLongWordArray Chunk, unsigned &A, unsigned &B, unsigned &C, unsigned &D);
extern PACKAGE Sbtypes::TMessageDigest128 __fastcall HashMD5(const Sbtypes::ByteArray Buffer)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest128 __fastcall HashMD5(void * Buffer, unsigned Size)/* overload */;
extern PACKAGE void __fastcall InitializeMD5(TMD5Context &Context);
extern PACKAGE void __fastcall HashMD5(TMD5Context &Context, void * Chunk, unsigned Size)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest128 __fastcall FinalizeMD5(TMD5Context &Context);
extern PACKAGE Sbtypes::TMessageDigest128 __fastcall HashMD2(void * Buffer, unsigned Size)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest128 __fastcall HashMD2(const Sbtypes::ByteArray S)/* overload */;
extern PACKAGE void __fastcall InitializeMD2(TMD2Context &Context);
extern PACKAGE Sbtypes::TMessageDigest128 __fastcall FinalizeMD2(TMD2Context &Context);
extern PACKAGE void __fastcall HashMD2(TMD2Context &Context, void * Buffer, int Size)/* overload */;

}	/* namespace Sbmd */
using namespace Sbmd;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbmdHPP
