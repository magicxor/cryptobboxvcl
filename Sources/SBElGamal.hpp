// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbelgamal.pas' rev: 21.00

#ifndef SbelgamalHPP
#define SbelgamalHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbmath.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbelgamal
{
//-- type declarations -------------------------------------------------------
//-- var, const, procedure ---------------------------------------------------
extern PACKAGE bool __fastcall ExternalGenerationSupported(void);
extern PACKAGE bool __fastcall Generate(int Bits, Sbmath::PLInt P, Sbmath::PLInt G, Sbmath::PLInt X, Sbmath::PLInt Y, Sbmath::TSBMathProgressFunc ProgressFunc = 0x0, void * Data = (void *)(0x0))/* overload */;
extern PACKAGE bool __fastcall ExternalGenerate(int Bits, Sbmath::PLInt P, Sbmath::PLInt G, Sbmath::PLInt X, Sbmath::PLInt Y, Sbmath::TSBMathProgressFunc ProgressFunc = 0x0, void * Data = (void *)(0x0))/* overload */;
extern PACKAGE bool __fastcall Encrypt(Sbmath::PLInt Src, Sbmath::PLInt P, Sbmath::PLInt G, Sbmath::PLInt Y, Sbmath::PLInt A, Sbmath::PLInt B);
extern PACKAGE bool __fastcall Decrypt(Sbmath::PLInt P, Sbmath::PLInt G, Sbmath::PLInt X, Sbmath::PLInt A, Sbmath::PLInt B, Sbmath::PLInt Dest);
extern PACKAGE bool __fastcall Sign(Sbmath::PLInt Src, Sbmath::PLInt P, Sbmath::PLInt G, Sbmath::PLInt X, Sbmath::PLInt A, Sbmath::PLInt B);
extern PACKAGE bool __fastcall Verify(Sbmath::PLInt Src, Sbmath::PLInt P, Sbmath::PLInt G, Sbmath::PLInt Y, Sbmath::PLInt A, Sbmath::PLInt B);
extern PACKAGE bool __fastcall EncodeResult(void * R, int RSize, void * S, int SSize, void * Blob, int &BlobSize);
extern PACKAGE bool __fastcall DecodeResult(void * Blob, int Size, void * R, int &RSize, void * S, int &SSize);
extern PACKAGE bool __fastcall EncodePublicKey(void * P, int PSize, void * G, int GSize, void * Y, int YSize, void * OutBuffer, int &OutSize);
extern PACKAGE bool __fastcall EncodePrivateKey(void * P, int PSize, void * G, int GSize, void * X, int XSize, void * OutBuffer, int &OutSize);

}	/* namespace Sbelgamal */
using namespace Sbelgamal;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbelgamalHPP
