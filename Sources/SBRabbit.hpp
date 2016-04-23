// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbrabbit.pas' rev: 21.00

#ifndef SbrabbitHPP
#define SbrabbitHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbrabbit
{
//-- type declarations -------------------------------------------------------
typedef unsigned UInt32;

typedef __int64 UInt64;

typedef StaticArray<unsigned, 8> UInt32Array8;

#pragma pack(push,1)
struct Rabbit_Instance
{
	
public:
	UInt32Array8 X;
	UInt32Array8 C;
	UInt32Array8 K;
	System::Byte Carry;
};
#pragma pack(pop)


#pragma pack(push,1)
struct Rabbit_Context
{
	
public:
	Rabbit_Instance Rabbit;
	Rabbit_Instance Rabbit_Master;
};
#pragma pack(pop)


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE void __fastcall Rabbit_Cipher(Rabbit_Context &Context, const Sbtypes::ByteArray Src, Sbtypes::ByteArray &Dst);
extern PACKAGE void __fastcall Rabbit_IVInit(Rabbit_Context &Context, const Sbtypes::ByteArray IV_Key);
extern PACKAGE void __fastcall Rabbit_Init(Rabbit_Context &Context, const Sbtypes::ByteArray Key);

}	/* namespace Sbrabbit */
using namespace Sbrabbit;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbrabbitHPP
