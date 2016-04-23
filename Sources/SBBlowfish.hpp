// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbblowfish.pas' rev: 21.00

#ifndef SbblowfishHPP
#define SbblowfishHPP

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

//-- user supplied -----------------------------------------------------------

namespace Sbblowfish
{
//-- type declarations -------------------------------------------------------
struct TSBBlowfishContext
{
	
public:
	unsigned P0;
	unsigned P1;
	unsigned P2;
	unsigned P3;
	unsigned P4;
	unsigned P5;
	unsigned P6;
	unsigned P7;
	unsigned P8;
	unsigned P9;
	unsigned P10;
	unsigned P11;
	unsigned P12;
	unsigned P13;
	unsigned P14;
	unsigned P15;
	unsigned P16;
	unsigned P17;
	StaticArray<unsigned, 256> S0;
	StaticArray<unsigned, 256> S1;
	StaticArray<unsigned, 256> S2;
	StaticArray<unsigned, 256> S3;
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE void __fastcall EncryptBlock(TSBBlowfishContext &Context, unsigned &L, unsigned &R);
extern PACKAGE void __fastcall DecryptBlock(TSBBlowfishContext &Context, unsigned &L, unsigned &R);
extern PACKAGE void __fastcall Initialize(TSBBlowfishContext &Context, const Sbtypes::ByteArray Key);
extern PACKAGE void __fastcall EksInitialize(TSBBlowfishContext &Context, int Rounds, const Sbtypes::ByteArray Salt, const Sbtypes::ByteArray Key);

}	/* namespace Sbblowfish */
using namespace Sbblowfish;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbblowfishHPP
