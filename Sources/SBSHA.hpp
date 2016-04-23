// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbsha.pas' rev: 21.00

#ifndef SbshaHPP
#define SbshaHPP

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

namespace Sbsha
{
//-- type declarations -------------------------------------------------------
#pragma pack(push,1)
struct TSHA1Context
{
	
public:
	__int64 Size;
	StaticArray<System::Byte, 64> Buffer;
	StaticArray<unsigned, 80> LChunk;
	unsigned BufSize;
	unsigned A;
	unsigned B;
	unsigned C;
	unsigned D;
	unsigned E;
};
#pragma pack(pop)


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE void __fastcall InternalSHA1(Sbtypes::PLongWordArray Chunk, unsigned &A, unsigned &B, unsigned &C, unsigned &D, unsigned &E);
extern PACKAGE Sbtypes::TMessageDigest160 __fastcall HashSHA1(const Sbtypes::ByteArray S)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest160 __fastcall HashSHA1(void * Buffer, unsigned Size)/* overload */;
extern PACKAGE void __fastcall InitializeSHA1(/* out */ TSHA1Context &Context);
extern PACKAGE void __fastcall HashSHA1(TSHA1Context &Context, void * Chunk, unsigned Size)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest160 __fastcall FinalizeSHA1(TSHA1Context &Context);

}	/* namespace Sbsha */
using namespace Sbsha;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbshaHPP
