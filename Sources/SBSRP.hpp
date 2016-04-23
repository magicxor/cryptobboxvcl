// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbsrp.pas' rev: 21.00

#ifndef SbsrpHPP
#define SbsrpHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbhashfunction.hpp>	// Pascal unit
#include <Sbmath.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbmd.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbsrp
{
//-- type declarations -------------------------------------------------------
struct TSRPContext
{
	
public:
	Sbmath::TLInt *Salt;
	Sbmath::TLInt *A;
	Sbmath::TLInt *A_Small;
	Sbmath::TLInt *B;
	Sbmath::TLInt *B_Small;
	Sbmath::TLInt *V;
	Sbmath::TLInt *U;
	Sbmath::TLInt *N;
	Sbmath::TLInt *K;
	Sbmath::TLInt *G;
	Sbmath::TLInt *X;
	Sbmath::TLInt *S;
	bool Initialized;
};


#pragma option push -b-
enum TSSRPPrimeLen { sr1024, sr1536, sr2048, sr3072, sr4096, sr6144, sr8192 };
#pragma option pop

//-- var, const, procedure ---------------------------------------------------
extern PACKAGE int TSRPPrimesGen_1024;
extern PACKAGE StaticArray<System::Byte, 128> TSRPPrimes_1024;
static const ShortInt TSRPPrimesGen_1536 = 0x2;
extern PACKAGE StaticArray<System::Byte, 192> TSRPPrimes_1536;
static const ShortInt TSRPPrimesGen_2048 = 0x2;
extern PACKAGE StaticArray<System::Byte, 256> TSRPPrimes_2048;
static const ShortInt TSRPPrimesGen_3072 = 0x5;
extern PACKAGE StaticArray<System::Byte, 384> TSRPPrimes_3072;
static const ShortInt TSRPPrimesGen_4096 = 0x5;
extern PACKAGE StaticArray<System::Byte, 512> TSRPPrimes_4096;
static const ShortInt TSRPPrimesGen_6144 = 0x5;
extern PACKAGE StaticArray<System::Byte, 768> TSRPPrimes_6144;
static const ShortInt TSRPPrimesGen_8192 = 0x13;
extern PACKAGE StaticArray<System::Byte, 1024> TSRPPrimes_8192;
extern PACKAGE void __fastcall SrpInitContext(TSRPContext &SRP);
extern PACKAGE void __fastcall SrpDestroyContext(TSRPContext &SRP);
extern PACKAGE void __fastcall SrpServerInit(TSRPContext &SRP);
extern PACKAGE void __fastcall SrpGetU(Sbmath::PLInt N, Sbmath::PLInt A, Sbmath::PLInt B, System::UnicodeString Proto, Sbmath::PLInt &U);
extern PACKAGE void __fastcall SrpGetA(System::UnicodeString UserName, System::UnicodeString UserPassword, TSRPContext &SRP);
extern PACKAGE void __fastcall SrpGetClientX(System::UnicodeString User, System::UnicodeString Password, Sbmath::PLInt Salt, Sbmath::PLInt &ClX);
extern PACKAGE void __fastcall SrpGetClientKey(TSRPContext &SRP);
extern PACKAGE void __fastcall SrpGetServerKey(TSRPContext &SRP);
extern PACKAGE void __fastcall SrpGetNewServerData(System::UnicodeString UserName, System::UnicodeString UserPassword, TSSRPPrimeLen PrimeLen, Sbtypes::ByteArray &N, Sbtypes::ByteArray &G, Sbtypes::ByteArray &Salt, Sbtypes::ByteArray &V);
extern PACKAGE Sbtypes::ByteArray __fastcall LIntToBytes(Sbmath::PLInt I);
extern PACKAGE void __fastcall LInitBytes(Sbmath::PLInt I, Sbtypes::ByteArray BA);

}	/* namespace Sbsrp */
using namespace Sbsrp;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbsrpHPP
