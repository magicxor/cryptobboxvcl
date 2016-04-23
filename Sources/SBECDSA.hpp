// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbecdsa.pas' rev: 21.00

#ifndef SbecdsaHPP
#define SbecdsaHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbmath.hpp>	// Pascal unit
#include <Sbecmath.hpp>	// Pascal unit
#include <Sbeccommon.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbecdsa
{
//-- type declarations -------------------------------------------------------
//-- var, const, procedure ---------------------------------------------------
extern PACKAGE bool __fastcall ExternalGenerationSupported(void);
extern PACKAGE bool __fastcall GenerateEx(void * A, int ASize, void * B, int BSize, void * X, int XSize, void * Y, int YSize, void * N, int NSize, void * P, int PSize, int FldType, int Fld, void * D, int &DSize, void * Qx, int &QxSize, void * Qy, int &QySize);
extern PACKAGE bool __fastcall ExternalGenerateEx(void * A, int ASize, void * B, int BSize, void * X, int XSize, void * Y, int YSize, void * N, int NSize, void * P, int PSize, int CurveID, const Sbtypes::ByteArray CurveOID, int FldType, int Fld, void * D, int &DSize, void * Qx, int &QxSize, void * Qy, int &QySize);
extern PACKAGE bool __fastcall SignEx(void * hash, int hashSize, void * d, int dSize, void * A, int ASize, void * B, int BSize, void * X, int XSize, void * Y, int YSize, void * N, int NSize, void * P, int PSize, int FldType, int Fld, int Flag, void * R, int &RSize, void * S, int &SSize);
extern PACKAGE bool __fastcall VerifyEx(void * hash, int hashSize, void * Qx, int QxSize, void * Qy, int QySize, void * R, int RSize, void * S, int SSize, void * A, int ASize, void * B, int BSize, void * X, int XSize, void * Y, int YSize, void * N, int NSize, void * P, int PSize, int FldType, int Fld, int Flags);

}	/* namespace Sbecdsa */
using namespace Sbecdsa;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbecdsaHPP
