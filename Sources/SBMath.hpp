// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbmath.pas' rev: 21.00

#ifndef SbmathHPP
#define SbmathHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbmath
{
//-- type declarations -------------------------------------------------------
struct TRC4Random
{
	
public:
	StaticArray<System::Byte, 256> S;
	int I;
	int J;
};


struct TRC4RandomContext
{
	
public:
	StaticArray<System::Byte, 256> S;
	int I;
	int J;
	bool RandomInit;
};


typedef __int64 TSBInt64;

typedef bool __fastcall (__closure *TSBMathProgressFunc)(void * Data);

class DELPHICLASS EElMathException;
class PASCALIMPLEMENTATION EElMathException : public Sysutils::Exception
{
	typedef Sysutils::Exception inherited;
	
public:
	/* Exception.Create */ inline __fastcall EElMathException(const System::UnicodeString Msg) : Sysutils::Exception(Msg) { }
	/* Exception.CreateFmt */ inline __fastcall EElMathException(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sysutils::Exception(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElMathException(int Ident)/* overload */ : Sysutils::Exception(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElMathException(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sysutils::Exception(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElMathException(const System::UnicodeString Msg, int AHelpContext) : Sysutils::Exception(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElMathException(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sysutils::Exception(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElMathException(int Ident, int AHelpContext)/* overload */ : Sysutils::Exception(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElMathException(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sysutils::Exception(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElMathException(void) { }
	
};


struct TLInt;
typedef TLInt *PLInt;

struct TLInt
{
	
public:
	int Length;
	StaticArray<unsigned, 768> Digits;
	bool Sign;
};


//-- var, const, procedure ---------------------------------------------------
static const Word MAXDIGIT = 0x300;
static const ShortInt RandKeyLength = 0x2;
extern PACKAGE System::ResourceString _sNumberTooLarge;
#define Sbmath_sNumberTooLarge System::LoadResourceString(&Sbmath::_sNumberTooLarge)
extern PACKAGE System::ResourceString _sDivisionByZero;
#define Sbmath_sDivisionByZero System::LoadResourceString(&Sbmath::_sDivisionByZero)
extern PACKAGE void __fastcall LShl(PLInt &Num);
extern PACKAGE void __fastcall LShlEx(PLInt &Num, int Bits);
extern PACKAGE void __fastcall LShlNum(PLInt Src, PLInt Dest, int Bits);
extern PACKAGE void __fastcall LShr(PLInt &Num);
extern PACKAGE void __fastcall LShrEx(PLInt &Num, int Bits);
extern PACKAGE void __fastcall LDec(PLInt &A);
extern PACKAGE void __fastcall LInc(PLInt &A);
extern PACKAGE void __fastcall LAdd(PLInt A, unsigned B, PLInt C)/* overload */;
extern PACKAGE void __fastcall LAdd(PLInt A, PLInt B, PLInt C)/* overload */;
extern PACKAGE void __fastcall LSub(PLInt A, unsigned B, PLInt &PTm)/* overload */;
extern PACKAGE void __fastcall LSub(PLInt A, PLInt B, PLInt &PTm)/* overload */;
extern PACKAGE bool __fastcall LGreater(PLInt A, PLInt B);
extern PACKAGE bool __fastcall LEqual(PLInt A, PLInt B);
extern PACKAGE bool __fastcall LEven(PLInt A);
extern PACKAGE bool __fastcall LNull(PLInt A);
extern PACKAGE void __fastcall LZero(PLInt &A);
extern PACKAGE void __fastcall LCopy(PLInt &P, PLInt A);
extern PACKAGE void __fastcall LShiftLeft(PLInt &A, unsigned N);
extern PACKAGE void __fastcall LTrim(PLInt &A);
extern PACKAGE void __fastcall LMult(PLInt A, PLInt B, PLInt &Res);
extern PACKAGE unsigned __fastcall LBitCount(PLInt A);
extern PACKAGE void __fastcall LDiv(PLInt A, PLInt B, PLInt &C, PLInt &D);
extern PACKAGE void __fastcall LInit(PLInt &P, System::UnicodeString Num)/* overload */;
extern PACKAGE void __fastcall LInit(PLInt &P, unsigned Num)/* overload */;
extern PACKAGE void __fastcall LInit(PLInt &P, __int64 Num)/* overload */;
extern PACKAGE void __fastcall LCreate(/* out */ PLInt &A);
extern PACKAGE void __fastcall LGenerate(PLInt &R, int Len);
extern PACKAGE void __fastcall LDestroy(PLInt &P);
extern PACKAGE System::WideChar __fastcall DecToHexDigit(int A);
extern PACKAGE int __fastcall HexToDecDigit(System::WideChar A);
extern PACKAGE System::UnicodeString __fastcall DecToHex(unsigned A);
extern PACKAGE System::UnicodeString __fastcall LToStr(PLInt A);
extern PACKAGE System::UnicodeString __fastcall LToBase64(PLInt A);
extern PACKAGE void __fastcall LModPower(PLInt A, PLInt E, PLInt N, PLInt &Res);
extern PACKAGE void __fastcall LGCD(PLInt B, PLInt A, PLInt &C, PLInt &D);
extern PACKAGE void __fastcall LMontgomery(PLInt A, PLInt B, PLInt N, PLInt &Res);
extern PACKAGE void __fastcall LSwap(PLInt &A, PLInt &B);
extern PACKAGE void __fastcall LMod(PLInt X, PLInt N, PLInt &Res);
extern PACKAGE void __fastcall LBAddPowB(PLInt Src, PLInt Dest, unsigned Bases);
extern PACKAGE void __fastcall LBM(PLInt SrcMod, PLInt Dest, unsigned Bits);
extern PACKAGE void __fastcall LBDivPowB(PLInt Src, PLInt Dest, unsigned Bases);
extern PACKAGE void __fastcall LBModPowB(PLInt Src, PLInt Dest, unsigned Bases);
extern PACKAGE void __fastcall LBMul(PLInt SrcA, PLInt SrcB, PLInt Dest, unsigned FromBases, unsigned ToBases);
extern PACKAGE void __fastcall LBMod(PLInt Src, PLInt SrcMod, PLInt SrcM, PLInt &Dest, unsigned Bits);
extern PACKAGE void __fastcall LBPowMod(PLInt SrcA, PLInt SrcB, PLInt SrcMod, PLInt &Dest, PLInt ModInv);
extern PACKAGE void __fastcall LShrNum(PLInt X, PLInt &Res, unsigned Bits);
extern PACKAGE void __fastcall LMMul(PLInt A, PLInt B, PLInt N, PLInt &Res);
extern PACKAGE void __fastcall LMultSh(PLInt A, unsigned B, PLInt Res);
extern PACKAGE void __fastcall LDivSh(PLInt A, unsigned B, PLInt Q, PLInt R);
extern PACKAGE void __fastcall LMModPower(PLInt X, PLInt E, PLInt N, PLInt &Res, TSBMathProgressFunc ProgressFunc = 0x0, void * Data = (void *)(0x0), bool RaiseExceptionOnCancel = false);
extern PACKAGE bool __fastcall LIsPrime(PLInt P, TSBMathProgressFunc ProgressFunc = 0x0, void * Data = (void *)(0x0), bool RaiseExceptionOnCancel = false);
extern PACKAGE bool __fastcall LRabinMillerPrimeTest(PLInt P, TSBMathProgressFunc ProgressFunc = 0x0, void * Data = (void *)(0x0), bool RaiseExceptionOnCancel = false);
extern PACKAGE void __fastcall LModSh(PLInt A, unsigned B, unsigned &Res);
extern PACKAGE void __fastcall LGenPrime(PLInt P, int Len, bool RSAPrime = false, TSBMathProgressFunc ProgressFunc = 0x0, void * Data = (void *)(0x0), bool RaiseExceptionOnCancel = false);
extern PACKAGE void __fastcall LGenPrimeEx(PLInt P, int Bits, bool RSAPrime = false, TSBMathProgressFunc ProgressFunc = 0x0, void * Data = (void *)(0x0), bool RaiseExceptionOnCancel = false);
extern PACKAGE void __fastcall LRC4Randomize(TRC4RandomContext &Ctx, PLInt Key);
extern PACKAGE void __fastcall LRC4Init(TRC4RandomContext &Ctx);
extern PACKAGE System::Byte __fastcall LRC4RandomByte(TRC4RandomContext &Ctx);
extern PACKAGE void __fastcall LRandom(TRC4RandomContext &Ctx, PLInt A, int Bytes);
extern PACKAGE bool __fastcall LBitSet(PLInt A, int n);
extern PACKAGE void __fastcall LSetBit(PLInt &A, int n, bool Value);
extern PACKAGE void __fastcall LBitTruncate(PLInt &A, int Bits);
extern PACKAGE void __fastcall LModEx(PLInt X, PLInt N, PLInt &Res);
extern PACKAGE bool __fastcall MathOperationCanceled(TSBMathProgressFunc ProgressFunc, void * Data);

}	/* namespace Sbmath */
using namespace Sbmath;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbmathHPP
