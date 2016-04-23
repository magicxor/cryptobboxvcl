// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbgost341094.pas' rev: 21.00

#ifndef Sbgost341094HPP
#define Sbgost341094HPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbmath.hpp>	// Pascal unit
#include <Sbgostcommon.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbgost341094
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElGOSTSignerBase;
class PASCALIMPLEMENTATION TElGOSTSignerBase : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	Sbmath::TLInt *fSecretKey;
	Sbmath::TLInt *fPublicKey;
	void __fastcall SetSecretKey(const Sbmath::PLInt V);
	void __fastcall SetPublicKey(const Sbmath::PLInt V);
	
public:
	__fastcall TElGOSTSignerBase(void);
	__fastcall virtual ~TElGOSTSignerBase(void);
	void __fastcall AssignSecretKey(const System::UnicodeString HexStr);
	void __fastcall AssignPublicKey(const System::UnicodeString HexStr);
	virtual Sbtypes::ByteArray __fastcall Sign(const Sbtypes::ByteArray Digest) = 0 /* overload */;
	virtual bool __fastcall Verify(const Sbtypes::ByteArray Digest, const Sbtypes::ByteArray Sign) = 0 /* overload */;
	virtual void __fastcall Generate_Keys(void) = 0 /* overload */;
	__property Sbmath::PLInt SecretKey = {read=fSecretKey, write=SetSecretKey};
	__property Sbmath::PLInt PublicKey = {read=fPublicKey, write=SetPublicKey};
};


class DELPHICLASS TElGOSTSigner;
class PASCALIMPLEMENTATION TElGOSTSigner : public TElGOSTSignerBase
{
	typedef TElGOSTSignerBase inherited;
	
protected:
	Sbmath::TLInt *fP;
	Sbmath::TLInt *fQ;
	Sbmath::TLInt *fA;
	void __fastcall SetP(const Sbmath::PLInt V);
	void __fastcall SetQ(const Sbmath::PLInt V);
	void __fastcall SetA(const Sbmath::PLInt V);
	
public:
	__fastcall TElGOSTSigner(void);
	__fastcall virtual ~TElGOSTSigner(void);
	void __fastcall AssignP(const System::UnicodeString HexStr);
	void __fastcall AssignQ(const System::UnicodeString HexStr);
	void __fastcall AssignA(const System::UnicodeString HexStr);
	__classmethod bool __fastcall Check_Params(int Bits, const Sbmath::PLInt P, const Sbmath::PLInt Q, const Sbmath::PLInt A, __int64 x0, __int64 c);
	bool __fastcall Generate_PQA(int Bits, int TypeProc, __int64 &x0, __int64 &c)/* overload */;
	__classmethod bool __fastcall Generate_PQA(int Bits, int TypeProc, __int64 &x0, __int64 &c, Sbmath::PLInt &P, Sbmath::PLInt &Q, Sbmath::PLInt &A)/* overload */;
	bool __fastcall Generate_All(int Bits, int TypeProc, __int64 &x0, __int64 &c);
	virtual void __fastcall Generate_Keys(void)/* overload */;
	__classmethod void __fastcall Generate_Keys(const Sbmath::PLInt P, const Sbmath::PLInt Q, const Sbmath::PLInt A, Sbmath::PLInt &SecretKey, Sbmath::PLInt &PublicKey)/* overload */;
	virtual Sbtypes::ByteArray __fastcall Sign(const Sbtypes::ByteArray Digest)/* overload */;
	__classmethod Sbtypes::ByteArray __fastcall Sign(const Sbtypes::ByteArray Digest, const System::UnicodeString P, const System::UnicodeString Q, const System::UnicodeString A, const System::UnicodeString Key)/* overload */;
	__classmethod Sbtypes::ByteArray __fastcall Sign(const Sbtypes::ByteArray Digest, const Sbmath::PLInt P, const Sbmath::PLInt Q, const Sbmath::PLInt A, const Sbmath::PLInt Key)/* overload */;
	virtual bool __fastcall Verify(const Sbtypes::ByteArray Digest, const Sbtypes::ByteArray Sign)/* overload */;
	__classmethod bool __fastcall Verify(const Sbtypes::ByteArray Digest, const Sbtypes::ByteArray Sign, const Sbmath::PLInt P, const Sbmath::PLInt Q, const Sbmath::PLInt A, const Sbmath::PLInt Key)/* overload */;
	__property Sbmath::PLInt P = {read=fP, write=SetP};
	__property Sbmath::PLInt Q = {read=fQ, write=SetQ};
	__property Sbmath::PLInt A = {read=fA, write=SetA};
};


//-- var, const, procedure ---------------------------------------------------

}	/* namespace Sbgost341094 */
using namespace Sbgost341094;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// Sbgost341094HPP
