// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbpkiasync.pas' rev: 21.00

#ifndef SbpkiasyncHPP
#define SbpkiasyncHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Windows.hpp>	// Pascal unit
#include <Syncobjs.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbelgamal.hpp>	// Pascal unit
#include <Sbdsa.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbmath.hpp>	// Pascal unit
#include <Sbrsa.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbpkiasync
{
//-- type declarations -------------------------------------------------------
#pragma option push -b-
enum TSBPublicKeyComputationTokenType { ttElgamalEncrypt, ttElgamalSign, ttDSASign, ttPrimeGeneration, ttDSAGeneration, ttRSAGeneration, ttElgamalGeneration };
#pragma option pop

class DELPHICLASS TElPublicKeyComputationToken;
class DELPHICLASS TElPublicKeyAsyncCalculator;
class PASCALIMPLEMENTATION TElPublicKeyComputationToken : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	Classes::TThread* FThread;
	bool FThreadFinished;
	TElPublicKeyAsyncCalculator* FOwner;
	TSBPublicKeyComputationTokenType FTokenType;
	StaticArray<Sbmath::PLInt, 8> FLIntArray;
	Sbmath::TLInt *FElgA;
	Sbmath::TLInt *FElgP;
	Sbmath::TLInt *FElgQ;
	Sbmath::TLInt *FElgR;
	Sbmath::TLInt *FElgT1;
	Sbmath::TLInt *FElgT2;
	Sbmath::TLInt *FElgT3;
	Sbmath::TLInt *FElgKInv;
	Sbmath::TLInt *FPrime;
	Sbmath::TLInt *FRSAM;
	Sbmath::TLInt *FRSAPrivExp;
	Sbmath::TLInt *FRSAPubExp;
	Sbmath::TLInt *FRSAPrime1;
	Sbmath::TLInt *FRSAPrime2;
	Sbmath::TLInt *FRSAExp1;
	Sbmath::TLInt *FRSAExp2;
	Sbmath::TLInt *FRSACoeff;
	Sbmath::TLInt *FDSAP;
	Sbmath::TLInt *FDSAQ;
	Sbmath::TLInt *FDSAG;
	Sbmath::TLInt *FDSAY;
	Sbmath::TLInt *FDSAX;
	Sbmath::TLInt *FDSAT1;
	Sbmath::TLInt *FDSAR;
	Sbmath::TLInt *FDSAK;
	Sbtypes::ByteArray FKeyBlob;
	void *FData;
	void __fastcall OnThreadTerminate(System::TObject* Sender);
	bool __fastcall GetFinished(void);
	
protected:
	void __fastcall BeginElgamalEncryption(Sbmath::PLInt P, Sbmath::PLInt G, Sbmath::PLInt Y);
	void __fastcall BeginElgamalSigning(Sbmath::PLInt P, Sbmath::PLInt G);
	void __fastcall BeginPrimeGeneration(int Bits);
	void __fastcall BeginDSASigning(Sbmath::PLInt P, Sbmath::PLInt Q, Sbmath::PLInt G);
	void __fastcall BeginRSAGeneration(int Bits);
	void __fastcall BeginDSAGeneration(int Bits);
	void __fastcall BeginElgamalGeneration(int Bits);
	void __fastcall Start(void);
	void __fastcall Resume(void);
	void __fastcall Stop(void);
	void __fastcall Wait(void);
	
public:
	__fastcall TElPublicKeyComputationToken(TSBPublicKeyComputationTokenType TokenType, TElPublicKeyAsyncCalculator* Owner);
	__fastcall virtual ~TElPublicKeyComputationToken(void);
	void __fastcall Cancel(void);
	__property TSBPublicKeyComputationTokenType TokenType = {read=FTokenType, nodefault};
	__property bool Finished = {read=GetFinished, nodefault};
	__property void * Data = {read=FData, write=FData};
};


class PASCALIMPLEMENTATION TElPublicKeyAsyncCalculator : public Classes::TComponent
{
	typedef Classes::TComponent inherited;
	
private:
	Classes::TList* FThreads;
	Syncobjs::TCriticalSection* FCS;
	Classes::TThreadPriority FPriority;
	void __fastcall KillThreads(void);
	void __fastcall AddTokenToList(TElPublicKeyComputationToken* Token);
	void __fastcall RemoveTokenFromList(TElPublicKeyComputationToken* Token);
	void __fastcall Release(TElPublicKeyComputationToken* Token);
	
public:
	__fastcall virtual TElPublicKeyAsyncCalculator(Classes::TComponent* AOwner);
	__fastcall virtual ~TElPublicKeyAsyncCalculator(void);
	TElPublicKeyComputationToken* __fastcall BeginElgamalEncryption(Sbmath::PLInt P, Sbmath::PLInt G, Sbmath::PLInt Y);
	void __fastcall EndElgamalEncryption(TElPublicKeyComputationToken* Token, Sbmath::PLInt Src, Sbmath::PLInt A, Sbmath::PLInt B);
	TElPublicKeyComputationToken* __fastcall BeginElgamalSigning(Sbmath::PLInt P, Sbmath::PLInt G);
	void __fastcall EndElgamalSigning(TElPublicKeyComputationToken* Token, Sbmath::PLInt X, Sbmath::PLInt Src, Sbmath::PLInt A, Sbmath::PLInt B);
	TElPublicKeyComputationToken* __fastcall BeginPrimeGeneration(int Bits);
	void __fastcall EndPrimeGeneration(TElPublicKeyComputationToken* Token, Sbmath::PLInt Prime);
	TElPublicKeyComputationToken* __fastcall BeginDSASigning(Sbmath::PLInt P, Sbmath::PLInt Q, Sbmath::PLInt G);
	void __fastcall EndDSASigning(TElPublicKeyComputationToken* Token, Sbmath::PLInt X, void * Hash, int HashSize, Sbmath::PLInt R, Sbmath::PLInt S);
	TElPublicKeyComputationToken* __fastcall BeginRSAGeneration(int Bits);
	void __fastcall EndRSAGeneration(TElPublicKeyComputationToken* Token, Sbmath::PLInt M, Sbmath::PLInt PrivE, Sbmath::PLInt PubE, Sbmath::PLInt Prime1, Sbmath::PLInt Prime2, Sbmath::PLInt Exp1, Sbmath::PLInt Exp2, Sbmath::PLInt Coeff)/* overload */;
	bool __fastcall EndRSAGeneration(TElPublicKeyComputationToken* Token, void * Blob, int &BlobSize)/* overload */;
	TElPublicKeyComputationToken* __fastcall BeginDSAGeneration(int Bits);
	void __fastcall EndDSAGeneration(TElPublicKeyComputationToken* Token, Sbmath::PLInt P, Sbmath::PLInt Q, Sbmath::PLInt G, Sbmath::PLInt X, Sbmath::PLInt Y)/* overload */;
	bool __fastcall EndDSAGeneration(TElPublicKeyComputationToken* Token, void * Blob, int &BlobSize)/* overload */;
	TElPublicKeyComputationToken* __fastcall BeginElgamalGeneration(int Bits);
	void __fastcall EndElgamalGeneration(TElPublicKeyComputationToken* Token, Sbmath::PLInt P, Sbmath::PLInt G, Sbmath::PLInt X, Sbmath::PLInt Y);
	__property Classes::TThreadPriority Priority = {read=FPriority, write=FPriority, nodefault};
};


class DELPHICLASS EElPublicKeyAsyncCalculatorError;
class PASCALIMPLEMENTATION EElPublicKeyAsyncCalculatorError : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElPublicKeyAsyncCalculatorError(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElPublicKeyAsyncCalculatorError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElPublicKeyAsyncCalculatorError(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElPublicKeyAsyncCalculatorError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElPublicKeyAsyncCalculatorError(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElPublicKeyAsyncCalculatorError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElPublicKeyAsyncCalculatorError(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElPublicKeyAsyncCalculatorError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElPublicKeyAsyncCalculatorError(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE TElPublicKeyAsyncCalculator* __fastcall GetGlobalAsyncCalculator(void);

}	/* namespace Sbpkiasync */
using namespace Sbpkiasync;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbpkiasyncHPP
