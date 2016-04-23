// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbeccommon.pas' rev: 21.00

#ifndef SbeccommonHPP
#define SbeccommonHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbmath.hpp>	// Pascal unit
#include <Sbecmath.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbeccommon
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElECDomainParameters;
class PASCALIMPLEMENTATION TElECDomainParameters : public System::TObject
{
	typedef System::TObject inherited;
	
public:
	Sbtypes::ByteArray FA;
	Sbtypes::ByteArray FB;
	Sbtypes::ByteArray FP;
	Sbtypes::ByteArray FN;
	int FH;
	Sbtypes::ByteArray FX;
	Sbtypes::ByteArray FY;
	Sbtypes::ByteArray FSeed;
	int FCurve;
	Sbtypes::ByteArray FCurveOID;
	int FFieldType;
	int FField;
	int FK1;
	int FK2;
	int FK3;
	int FM;
	void __fastcall SetupCurveParameters(int Curve);
	void __fastcall SetP(const Sbtypes::ByteArray Value);
	void __fastcall UpdateP(void);
	void __fastcall SetM(int Value);
	void __fastcall SetK1(int Value);
	void __fastcall SetK2(int Value);
	void __fastcall SetK3(int Value);
	void __fastcall SetField(int Value);
	void __fastcall SetCurve(int Value);
	void __fastcall SetCurveOID(const Sbtypes::ByteArray Value);
	void __fastcall SetSeed(const Sbtypes::ByteArray Value);
	void __fastcall SetA(const Sbtypes::ByteArray V);
	void __fastcall SetB(const Sbtypes::ByteArray V);
	void __fastcall SetN(const Sbtypes::ByteArray V);
	void __fastcall SetX(const Sbtypes::ByteArray V);
	void __fastcall SetY(const Sbtypes::ByteArray V);
	int __fastcall GetFieldBits(void);
	int __fastcall GetSubgroupBits(void);
	__fastcall TElECDomainParameters(void);
	__fastcall virtual ~TElECDomainParameters(void);
	void __fastcall Reset(void);
	bool __fastcall Check(void);
	__property int Curve = {read=FCurve, write=SetCurve, nodefault};
	__property Sbtypes::ByteArray CurveOID = {read=FCurveOID, write=SetCurveOID};
	__property Sbtypes::ByteArray P = {read=FP, write=SetP};
	__property Sbtypes::ByteArray A = {read=FA, write=SetA};
	__property Sbtypes::ByteArray B = {read=FB, write=SetB};
	__property Sbtypes::ByteArray N = {read=FN, write=SetN};
	__property int H = {read=FH, write=FH, nodefault};
	__property Sbtypes::ByteArray X = {read=FX, write=SetX};
	__property Sbtypes::ByteArray Y = {read=FY, write=SetY};
	__property Sbtypes::ByteArray Seed = {read=FSeed, write=SetSeed};
	__property int FieldType = {read=FFieldType, write=FFieldType, nodefault};
	__property int Field = {read=FField, write=SetField, nodefault};
	__property int FieldBits = {read=GetFieldBits, nodefault};
	__property int SubgroupBits = {read=GetSubgroupBits, nodefault};
	__property int M = {read=FM, write=SetM, nodefault};
	__property int K1 = {read=FK1, write=SetK1, nodefault};
	__property int K2 = {read=FK2, write=SetK2, nodefault};
	__property int K3 = {read=FK3, write=SetK3, nodefault};
};


class DELPHICLASS EElECPointCompressionError;
class PASCALIMPLEMENTATION EElECPointCompressionError : public Sbecmath::EElECError
{
	typedef Sbecmath::EElECError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElECPointCompressionError(const System::UnicodeString AMessage)/* overload */ : Sbecmath::EElECError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElECPointCompressionError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbecmath::EElECError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElECPointCompressionError(int Ident)/* overload */ : Sbecmath::EElECError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElECPointCompressionError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbecmath::EElECError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElECPointCompressionError(const System::UnicodeString Msg, int AHelpContext) : Sbecmath::EElECError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElECPointCompressionError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbecmath::EElECError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElECPointCompressionError(int Ident, int AHelpContext)/* overload */ : Sbecmath::EElECError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElECPointCompressionError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbecmath::EElECError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElECPointCompressionError(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE int __fastcall GetCurveByOID(const Sbtypes::ByteArray OID);
extern PACKAGE Sbtypes::ByteArray __fastcall GetOIDByCurve(int Curve);
extern PACKAGE bool __fastcall IsPointCompressed(void * Buffer, int Size);
extern PACKAGE bool __fastcall PointToBuffer(void * X, int XSize, void * Y, int YSize, TElECDomainParameters* DomainParams, void * Buffer, int &Size, bool Compress, bool Hybrid);
extern PACKAGE bool __fastcall BufferToPoint(void * Buffer, int Size, TElECDomainParameters* DomainParams, void * X, int &XSize, void * Y, int &YSize);
extern PACKAGE bool __fastcall ValidateKey(TElECDomainParameters* DomainParams, void * D, int DSize, void * Qx, int QxSize, void * Qy, int QySize);
extern PACKAGE Sbtypes::ByteArray __fastcall HexStrToFieldElement(const System::UnicodeString Src, bool LittleEndian, int PSize);
extern PACKAGE void __fastcall BufferToFieldElement(const Sbtypes::ByteArray Buf, Sbmath::PLInt &A, Sbmath::PLInt P)/* overload */;
extern PACKAGE void __fastcall BufferToFieldElement(void * Buf, int Size, Sbmath::PLInt &A, Sbmath::PLInt P)/* overload */;

}	/* namespace Sbeccommon */
using namespace Sbeccommon;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbeccommonHPP
