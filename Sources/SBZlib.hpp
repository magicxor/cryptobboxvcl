// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbzlib.pas' rev: 21.00

#ifndef SbzlibHPP
#define SbzlibHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbzcompressunit.hpp>	// Pascal unit
#include <Sbzcommonunit.hpp>	// Pascal unit
#include <Sbzuncompressunit.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbzlib
{
//-- type declarations -------------------------------------------------------
struct TZlibContext
{
	
public:
	Sbzcommonunit::TZStreamRec strm;
};


typedef bool __fastcall (__closure *TSBZLibOutputFunc)(void * Buffer, int Size, void * Param);

//-- var, const, procedure ---------------------------------------------------
extern PACKAGE void __fastcall InitializeCompression(TZlibContext &Context, int CompressionLevel);
extern PACKAGE void __fastcall InitializeCompressionEx(TZlibContext &Context, int Level = 0x9)/* overload */;
extern PACKAGE void __fastcall InitializeCompressionEx(TZlibContext &Context, int Level, int WindowBits)/* overload */;
extern PACKAGE void __fastcall InitializeDecompressionEx(TZlibContext &Context, bool UseZLib = false);
extern PACKAGE void __fastcall InitializeDecompressionEx64(TZlibContext &Context, bool UseZLib = false);
extern PACKAGE void __fastcall Compress(TZlibContext &Context, void * InBuffer, unsigned InSize, void * OutBuffer, unsigned &OutSize);
extern PACKAGE void __fastcall CompressEx(TZlibContext &Context, void * InBuffer, unsigned InSize, void * OutBuffer, unsigned &OutSize);
extern PACKAGE void __fastcall InitializeDecompression(TZlibContext &Context);
extern PACKAGE void __fastcall InitializeDecompression64(TZlibContext &Context);
extern PACKAGE void __fastcall Decompress(TZlibContext &Context, void * InBuffer, unsigned InSize, void * OutBuffer, unsigned &OutSize);
extern PACKAGE void __fastcall DecompressEx(TZlibContext &Context, void * InBuffer, unsigned InSize, TSBZLibOutputFunc OutputFunc, void * Param);
extern PACKAGE void __fastcall FinalizeCompressionEx(TZlibContext &Context, void * OutBuffer, unsigned &OutSize);
extern PACKAGE void __fastcall FinalizeDecompressionEx(TZlibContext &Context);

}	/* namespace Sbzlib */
using namespace Sbzlib;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbzlibHPP
