// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbsha2.pas' rev: 21.00

#ifndef Sbsha2HPP
#define Sbsha2HPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbmath.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbsha2
{
//-- type declarations -------------------------------------------------------
#pragma pack(push,1)
struct TSHA256Context
{
	
public:
	__int64 Size;
	StaticArray<System::Byte, 64> Buffer;
	unsigned BufSize;
	unsigned A;
	unsigned B;
	unsigned C;
	unsigned D;
	unsigned E;
	unsigned F;
	unsigned G;
	unsigned H;
};
#pragma pack(pop)


#pragma pack(push,1)
struct TSHA512Context
{
	
public:
	__int64 Size;
	StaticArray<System::Byte, 128> Buffer;
	unsigned BufSize;
	__int64 A;
	__int64 B;
	__int64 C;
	__int64 D;
	__int64 E;
	__int64 F;
	__int64 G;
	__int64 H;
};
#pragma pack(pop)


typedef TSHA512Context TSHA384Context;

//-- var, const, procedure ---------------------------------------------------
extern PACKAGE void __fastcall InitializeSHA224(TSHA256Context &Context);
extern PACKAGE Sbtypes::TMessageDigest224 __fastcall HashSHA224(const Sbtypes::ByteArray S)/* overload */;
extern PACKAGE void __fastcall HashSHA224(TSHA256Context &Context, void * Chunk, unsigned Size)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest224 __fastcall HashSHA224(void * Buffer, unsigned Size)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest224 __fastcall FinalizeSHA224(TSHA256Context &Context);
extern PACKAGE void __fastcall InitializeSHA256(TSHA256Context &Context);
extern PACKAGE Sbtypes::TMessageDigest256 __fastcall HashSHA256(const Sbtypes::ByteArray S)/* overload */;
extern PACKAGE void __fastcall HashSHA256(TSHA256Context &Context, void * Chunk, unsigned Size)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest256 __fastcall HashSHA256(void * Buffer, unsigned Size)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest256 __fastcall FinalizeSHA256(TSHA256Context &Context);
extern PACKAGE void __fastcall InitializeSHA512(TSHA512Context &Context);
extern PACKAGE Sbtypes::TMessageDigest512 __fastcall HashSHA512(const Sbtypes::ByteArray S)/* overload */;
extern PACKAGE void __fastcall HashSHA512(TSHA512Context &Context, void * Chunk, unsigned Size)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest512 __fastcall HashSHA512(void * Buffer, unsigned Size)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest512 __fastcall FinalizeSHA512(TSHA512Context &Context);
extern PACKAGE void __fastcall InitializeSHA384(TSHA512Context &Context);
extern PACKAGE Sbtypes::TMessageDigest384 __fastcall HashSHA384(const Sbtypes::ByteArray S)/* overload */;
extern PACKAGE void __fastcall HashSHA384(TSHA512Context &Context, void * Chunk, unsigned Size)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest384 __fastcall HashSHA384(void * Buffer, unsigned Size)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest384 __fastcall FinalizeSHA384(TSHA512Context &Context);

}	/* namespace Sbsha2 */
using namespace Sbsha2;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// Sbsha2HPP
