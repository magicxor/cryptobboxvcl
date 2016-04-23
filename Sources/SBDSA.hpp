// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbdsa.pas' rev: 21.00

#ifndef SbdsaHPP
#define SbdsaHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbmath.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbhashfunction.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbdsa
{
//-- type declarations -------------------------------------------------------
//-- var, const, procedure ---------------------------------------------------
extern PACKAGE bool __fastcall ValidateSignature(void * Hash, int HashSize, void * P, int PSize, void * Q, int QSize, void * G, int GSize, void * Y, int YSize, void * R, int RSize, void * S, int SSize);
extern PACKAGE bool __fastcall ExternalGenerationSupported(void);
extern PACKAGE bool __fastcall Generate(int Bits, void * P, int &PSize, void * Q, int &QSize, void * G, int &GSize, void * Y, int &YSize, void * X, int &XSize)/* overload */;
extern PACKAGE bool __fastcall ExternalGenerate(int Bits, void * P, int &PSize, void * Q, int &QSize, void * G, int &GSize, void * Y, int &YSize, void * X, int &XSize)/* overload */;
extern PACKAGE bool __fastcall GenerateEx(int PBits, int QBits, void * P, int &PSize, void * Q, int &QSize, void * G, int &GSize, void * Y, int &YSize, void * X, int &XSize, Sbmath::TSBMathProgressFunc ProgressFunc = 0x0, void * Data = (void *)(0x0))/* overload */;
extern PACKAGE bool __fastcall ExternalGenerateEx(int PBits, int QBits, void * P, int &PSize, void * Q, int &QSize, void * G, int &GSize, void * Y, int &YSize, void * X, int &XSize, Sbmath::TSBMathProgressFunc ProgressFunc = 0x0, void * Data = (void *)(0x0))/* overload */;
extern PACKAGE bool __fastcall Generate(int Bits, void * P, int &PSize, void * Q, int &QSize, void * G, int &GSize, void * Y, int &YSize, void * X, int &XSize, void * PrivateKeyBlob, int &PrivateKeyBlobSize, Sbmath::TSBMathProgressFunc ProgressFunc = 0x0, void * Data = (void *)(0x0))/* overload */;
extern PACKAGE bool __fastcall ExternalGenerate(int Bits, void * P, int &PSize, void * Q, int &QSize, void * G, int &GSize, void * Y, int &YSize, void * X, int &XSize, void * PrivateKeyBlob, int &PrivateKeyBlobSize, Sbmath::TSBMathProgressFunc ProgressFunc = 0x0, void * Data = (void *)(0x0))/* overload */;
extern PACKAGE bool __fastcall SignEx(void * Hash, int HashSize, void * P, int PSize, void * Q, int QSize, void * G, int GSize, void * X, int XSize, void * R, int &RSize, void * S, int &SSize);
extern PACKAGE bool __fastcall Sign(void * Hash, int HashSize, void * P, int PSize, void * Q, int QSize, void * G, int GSize, void * X, int XSize, void * R, int &RSize, void * S, int &SSize);
extern PACKAGE bool __fastcall DecodePrivateKey(void * Buffer, int Size, void * P, int &PSize, void * Q, int &QSize, void * G, int &GSize, void * Y, int &YSize, void * X, int &XSize);
extern PACKAGE bool __fastcall EncodePrivateKey(void * P, int PSize, void * Q, int QSize, void * G, int GSize, void * Y, int YSize, void * X, int XSize, void * OutBuffer, int &OutSize);
extern PACKAGE bool __fastcall DecodeSignature(void * Blob, int Size, void * R, int &RSize, void * S, int &SSize);
extern PACKAGE bool __fastcall EncodeSignature(void * R, int RSize, void * S, int SSize, void * Blob, int &BlobSize);
extern PACKAGE bool __fastcall IsValidKey(void * P, int PSize, void * Q, int QSize, void * G, int GSize, void * Y, int YSize, void * X, int XSize, bool Secret, bool StrictMode = false);

}	/* namespace Sbdsa */
using namespace Sbdsa;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbdsaHPP
