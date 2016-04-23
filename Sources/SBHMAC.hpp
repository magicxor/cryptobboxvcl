// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbhmac.pas' rev: 21.00

#ifndef SbhmacHPP
#define SbhmacHPP

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
#include <Sbsha2.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbhmac
{
//-- type declarations -------------------------------------------------------
#pragma pack(push,1)
struct TMACMD5Context
{
	
public:
	StaticArray<System::Byte, 64> NKey;
	StaticArray<System::Byte, 64> iKey;
	StaticArray<System::Byte, 80> oKey;
	unsigned Size;
	StaticArray<System::Byte, 64> Buffer;
	unsigned BufSize;
	unsigned A;
	unsigned B;
	unsigned C;
	unsigned D;
};
#pragma pack(pop)


#pragma pack(push,1)
struct TMACSHA1Context
{
	
public:
	StaticArray<System::Byte, 64> NKey;
	StaticArray<System::Byte, 64> iKey;
	StaticArray<System::Byte, 84> oKey;
	unsigned Size;
	StaticArray<System::Byte, 64> Buffer;
	unsigned BufSize;
	unsigned A;
	unsigned B;
	unsigned C;
	unsigned D;
	unsigned E;
};
#pragma pack(pop)


#pragma pack(push,1)
struct TMACSHA256Context
{
	
public:
	StaticArray<System::Byte, 64> oKey;
	Sbsha2::TSHA256Context Ctx;
};
#pragma pack(pop)


#pragma pack(push,1)
struct TMACSHA512Context
{
	
public:
	StaticArray<System::Byte, 128> oKey;
	Sbsha2::TSHA512Context Ctx;
};
#pragma pack(pop)


typedef TMACSHA256Context TMACSHA224Context;

typedef TMACSHA512Context TMACSHA384Context;

//-- var, const, procedure ---------------------------------------------------
extern PACKAGE Sbtypes::TMessageDigest128 __fastcall HashMACMD5(const Sbtypes::ByteArray S, const Sbtypes::ByteArray Key)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest128 __fastcall HashMACMD5(void * Buffer, unsigned Size, const Sbtypes::ByteArray Key)/* overload */;
extern PACKAGE void __fastcall InitializeMACMD5(TMACMD5Context &Context, const Sbtypes::ByteArray Key);
extern PACKAGE void __fastcall HashMACMD5(TMACMD5Context &Context, void * Chunk, unsigned Size)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest128 __fastcall FinalizeMACMD5(TMACMD5Context &Context);
extern PACKAGE Sbtypes::TMessageDigest128 __fastcall HashMACMD5(Classes::TStream* Stream, const Sbtypes::ByteArray Key, unsigned Count = (unsigned)(0x0))/* overload */;
extern PACKAGE Sbtypes::TMessageDigest160 __fastcall HashMACSHA1(const Sbtypes::ByteArray S, const Sbtypes::ByteArray Key)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest160 __fastcall HashMACSHA1(void * Buffer, unsigned Size, const Sbtypes::ByteArray Key)/* overload */;
extern PACKAGE void __fastcall InitializeMACSHA1(TMACSHA1Context &Context, const Sbtypes::ByteArray Key);
extern PACKAGE void __fastcall HashMACSHA1(TMACSHA1Context &Context, void * Chunk, unsigned Size)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest160 __fastcall FinalizeMACSHA1(TMACSHA1Context &Context);
extern PACKAGE Sbtypes::TMessageDigest160 __fastcall HashMACSHA1(Classes::TStream* Stream, const Sbtypes::ByteArray Key, unsigned Count = (unsigned)(0x0))/* overload */;
extern PACKAGE void __fastcall InitializeMACSHA256(TMACSHA256Context &Context, const Sbtypes::ByteArray Key);
extern PACKAGE Sbtypes::TMessageDigest256 __fastcall FinalizeMACSHA256(TMACSHA256Context &Context);
extern PACKAGE void __fastcall HashMACSHA256(TMACSHA256Context &Context, void * Chunk, int Size)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest256 __fastcall HashMACSHA256(const Sbtypes::ByteArray S, const Sbtypes::ByteArray Key)/* overload */;
extern PACKAGE void __fastcall InitializeMACSHA512(TMACSHA512Context &Context, const Sbtypes::ByteArray Key);
extern PACKAGE Sbtypes::TMessageDigest512 __fastcall FinalizeMACSHA512(TMACSHA512Context &Context);
extern PACKAGE void __fastcall HashMACSHA512(TMACSHA512Context &Context, void * Chunk, int Size)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest512 __fastcall HashMACSHA512(const Sbtypes::ByteArray S, const Sbtypes::ByteArray Key)/* overload */;
extern PACKAGE void __fastcall InitializeMACSHA224(TMACSHA256Context &Context, const Sbtypes::ByteArray Key);
extern PACKAGE Sbtypes::TMessageDigest224 __fastcall FinalizeMACSHA224(TMACSHA256Context &Context);
extern PACKAGE void __fastcall HashMACSHA224(TMACSHA256Context &Context, void * Chunk, int Size)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest224 __fastcall HashMACSHA224(const Sbtypes::ByteArray S, const Sbtypes::ByteArray Key)/* overload */;
extern PACKAGE void __fastcall InitializeMACSHA384(TMACSHA512Context &Context, const Sbtypes::ByteArray Key);
extern PACKAGE Sbtypes::TMessageDigest384 __fastcall FinalizeMACSHA384(TMACSHA512Context &Context);
extern PACKAGE void __fastcall HashMACSHA384(TMACSHA512Context &Context, void * Chunk, int Size)/* overload */;
extern PACKAGE Sbtypes::TMessageDigest384 __fastcall HashMACSHA384(const Sbtypes::ByteArray S, const Sbtypes::ByteArray Key)/* overload */;

}	/* namespace Sbhmac */
using namespace Sbhmac;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbhmacHPP
