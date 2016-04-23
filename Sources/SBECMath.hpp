// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbecmath.pas' rev: 21.00

#ifndef SbecmathHPP
#define SbecmathHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbmath.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbecmath
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS EElECError;
class PASCALIMPLEMENTATION EElECError : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElECError(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElECError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElECError(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElECError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElECError(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElECError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElECError(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElECError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElECError(void) { }
	
};


class DELPHICLASS EElECMathError;
class PASCALIMPLEMENTATION EElECMathError : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElECMathError(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElECMathError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElECMathError(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElECMathError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElECMathError(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElECMathError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElECMathError(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElECMathError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElECMathError(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE void __fastcall GetFieldByP(Sbmath::PLInt &P, int &Field, int &FldType);
extern PACKAGE void __fastcall GetBinaryFieldK(Sbmath::PLInt P, int &M, int &K1, int &K2, int &K3);
extern PACKAGE void __fastcall SetBinaryFieldK(Sbmath::PLInt &P, int M, int K1, int K2, int K3);
extern PACKAGE void __fastcall FpZero(Sbmath::PLInt &A, Sbmath::PLInt P);
extern PACKAGE void __fastcall FpOne(Sbmath::PLInt &A, Sbmath::PLInt P);
extern PACKAGE void __fastcall FpInt(Sbmath::PLInt &A, Sbmath::PLInt P, unsigned C);
extern PACKAGE int __fastcall FpCmp(Sbmath::PLInt A, Sbmath::PLInt B, Sbmath::PLInt P);
extern PACKAGE void __fastcall FpAdd(Sbmath::PLInt A, Sbmath::PLInt B, Sbmath::PLInt P, Sbmath::PLInt &C);
extern PACKAGE void __fastcall FpSub(Sbmath::PLInt A, Sbmath::PLInt B, Sbmath::PLInt P, Sbmath::PLInt &C);
extern PACKAGE bool __fastcall FpIsOne(Sbmath::PLInt A, Sbmath::PLInt P);
extern PACKAGE bool __fastcall FpIsZero(Sbmath::PLInt A, Sbmath::PLInt P);
extern PACKAGE void __fastcall FpReduce(Sbmath::PLInt &A, Sbmath::PLInt P, Sbmath::PLInt T1, Sbmath::PLInt T2, int Field);
extern PACKAGE void __fastcall FpMul(Sbmath::PLInt A, Sbmath::PLInt B, Sbmath::PLInt P, Sbmath::PLInt T1, Sbmath::PLInt T2, Sbmath::PLInt &C, int Field);
extern PACKAGE void __fastcall FpSqr(Sbmath::PLInt A, Sbmath::PLInt P, Sbmath::PLInt T1, Sbmath::PLInt T2, Sbmath::PLInt &C, int Field);
extern PACKAGE void __fastcall FpDiv2(Sbmath::PLInt A, Sbmath::PLInt P, Sbmath::PLInt &C);
extern PACKAGE void __fastcall FpInv(Sbmath::PLInt A, Sbmath::PLInt P, Sbmath::PLInt &C, int Field);
extern PACKAGE void __fastcall FpDiv(Sbmath::PLInt A, Sbmath::PLInt B, Sbmath::PLInt P, Sbmath::PLInt &C, int Field);
extern PACKAGE void __fastcall F2mPZero(Sbmath::PLInt &A, Sbmath::PLInt P);
extern PACKAGE void __fastcall F2mPOne(Sbmath::PLInt &A, Sbmath::PLInt P);
extern PACKAGE bool __fastcall F2mPIsZero(Sbmath::PLInt A, Sbmath::PLInt P);
extern PACKAGE bool __fastcall F2mPIsOne(Sbmath::PLInt A, Sbmath::PLInt P);
extern PACKAGE int __fastcall F2mPCmp(Sbmath::PLInt A, Sbmath::PLInt B, Sbmath::PLInt P);
extern PACKAGE void __fastcall F2mPAdd(Sbmath::PLInt A, Sbmath::PLInt B, Sbmath::PLInt P, Sbmath::PLInt &C);
extern PACKAGE void __fastcall F2mPReduce(Sbmath::PLInt &A, Sbmath::PLInt P, int Field);
extern PACKAGE void __fastcall F2mPMul(Sbmath::PLInt A, Sbmath::PLInt B, Sbmath::PLInt P, Sbmath::PLInt &T1, Sbmath::PLInt &C, int Field);
extern PACKAGE void __fastcall F2mPSqr(Sbmath::PLInt A, Sbmath::PLInt P, Sbmath::PLInt &C, int Field);
extern PACKAGE void __fastcall F2mPDivX(Sbmath::PLInt A, Sbmath::PLInt P, Sbmath::PLInt &C);
extern PACKAGE void __fastcall F2mPDiv(Sbmath::PLInt A, Sbmath::PLInt B, Sbmath::PLInt P, Sbmath::PLInt &C);
extern PACKAGE void __fastcall F2mPInv(Sbmath::PLInt A, Sbmath::PLInt P, Sbmath::PLInt &C);
extern PACKAGE void __fastcall ECPFpJDouble(Sbmath::PLInt X1, Sbmath::PLInt Y1, Sbmath::PLInt Z1, Sbmath::PLInt P, Sbmath::PLInt &X3, Sbmath::PLInt &Y3, Sbmath::PLInt &Z3, int Field)/* overload */;
extern PACKAGE void __fastcall ECPFpJDouble(Sbmath::PLInt X1, Sbmath::PLInt Y1, Sbmath::PLInt Z1, Sbmath::PLInt P, Sbmath::PLInt A, Sbmath::PLInt &X3, Sbmath::PLInt &Y3, Sbmath::PLInt &Z3, int Field)/* overload */;
extern PACKAGE void __fastcall ECPFpJAAdd(Sbmath::PLInt X1, Sbmath::PLInt Y1, Sbmath::PLInt Z1, Sbmath::PLInt x2, Sbmath::PLInt y2, Sbmath::PLInt P, Sbmath::PLInt &X3, Sbmath::PLInt &Y3, Sbmath::PLInt &Z3, int Field);
extern PACKAGE void __fastcall ECPFpDouble(Sbmath::PLInt x1, Sbmath::PLInt y1, Sbmath::PLInt P, Sbmath::PLInt A, Sbmath::PLInt &x3, Sbmath::PLInt &y3, int Field);
extern PACKAGE void __fastcall ECPFpAdd(Sbmath::PLInt x1, Sbmath::PLInt y1, Sbmath::PLInt x2, Sbmath::PLInt y2, Sbmath::PLInt P, Sbmath::PLInt A, Sbmath::PLInt &x3, Sbmath::PLInt &y3, int Field);
extern PACKAGE void __fastcall ECPFpJ2A(Sbmath::PLInt X, Sbmath::PLInt Y, Sbmath::PLInt Z, Sbmath::PLInt P, Sbmath::PLInt &xr, Sbmath::PLInt &yr, int Field);
extern PACKAGE void __fastcall ECPFpExpJA(Sbmath::PLInt x1, Sbmath::PLInt y1, Sbmath::PLInt P, Sbmath::PLInt A, Sbmath::PLInt n, Sbmath::PLInt &xr, Sbmath::PLInt &yr, int Field);
extern PACKAGE void __fastcall ECPFpExp(Sbmath::PLInt x1, Sbmath::PLInt y1, Sbmath::PLInt P, Sbmath::PLInt A, Sbmath::PLInt n, Sbmath::PLInt &xr, Sbmath::PLInt &yr, int Field);
extern PACKAGE bool __fastcall ECPFpPointOnCurve(Sbmath::PLInt X, Sbmath::PLInt Y, Sbmath::PLInt A, Sbmath::PLInt B, Sbmath::PLInt P, int Field);
extern PACKAGE void __fastcall ECPF2mPLDDouble(Sbmath::PLInt X1, Sbmath::PLInt Y1, Sbmath::PLInt Z1, Sbmath::PLInt a, Sbmath::PLInt b, Sbmath::PLInt P, Sbmath::PLInt &X3, Sbmath::PLInt &Y3, Sbmath::PLInt &Z3, int Field);
extern PACKAGE void __fastcall ECPF2mPLDAAdd(Sbmath::PLInt X1, Sbmath::PLInt Y1, Sbmath::PLInt Z1, Sbmath::PLInt x2, Sbmath::PLInt y2, Sbmath::PLInt a, Sbmath::PLInt b, Sbmath::PLInt P, Sbmath::PLInt &X3, Sbmath::PLInt &Y3, Sbmath::PLInt &Z3, int Field);
extern PACKAGE void __fastcall ECPF2mPDouble(Sbmath::PLInt x1, Sbmath::PLInt y1, Sbmath::PLInt a, Sbmath::PLInt b, Sbmath::PLInt P, Sbmath::PLInt &x3, Sbmath::PLInt &y3, int Field);
extern PACKAGE void __fastcall ECPF2mPAdd(Sbmath::PLInt x1, Sbmath::PLInt y1, Sbmath::PLInt x2, Sbmath::PLInt y2, Sbmath::PLInt a, Sbmath::PLInt b, Sbmath::PLInt P, Sbmath::PLInt &x3, Sbmath::PLInt &y3, int Field);
extern PACKAGE void __fastcall ECPF2mPLD2A(Sbmath::PLInt X, Sbmath::PLInt Y, Sbmath::PLInt Z, Sbmath::PLInt P, Sbmath::PLInt &xr, Sbmath::PLInt &yr, int Field);
extern PACKAGE void __fastcall ECPF2mPExpLDA(Sbmath::PLInt x1, Sbmath::PLInt y1, Sbmath::PLInt a, Sbmath::PLInt b, Sbmath::PLInt P, Sbmath::PLInt n, Sbmath::PLInt &xr, Sbmath::PLInt &yr, int Field);
extern PACKAGE void __fastcall ECPF2mPExp(Sbmath::PLInt x1, Sbmath::PLInt y1, Sbmath::PLInt a, Sbmath::PLInt b, Sbmath::PLInt P, Sbmath::PLInt n, Sbmath::PLInt &xr, Sbmath::PLInt &yr, int Field);
extern PACKAGE bool __fastcall ECPF2mPPointOnCurve(Sbmath::PLInt X, Sbmath::PLInt Y, Sbmath::PLInt A, Sbmath::PLInt B, Sbmath::PLInt P, int Field);
extern PACKAGE int __fastcall ECPF2mPGetYpBit(Sbmath::PLInt X, Sbmath::PLInt Y, Sbmath::PLInt P, int Field);
extern PACKAGE bool __fastcall ECPFpDecompress(int yp, Sbmath::PLInt X, Sbmath::PLInt A, Sbmath::PLInt B, Sbmath::PLInt P, Sbmath::PLInt &Y, int Field);
extern PACKAGE bool __fastcall ECPF2mPDecompress(int yp, Sbmath::PLInt X, Sbmath::PLInt A, Sbmath::PLInt B, Sbmath::PLInt P, Sbmath::PLInt &Y, int Field);

}	/* namespace Sbecmath */
using namespace Sbecmath;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbecmathHPP
