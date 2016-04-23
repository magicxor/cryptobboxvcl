// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbhashfunction.pas' rev: 21.00

#ifndef SbhashfunctionHPP
#define SbhashfunctionHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sbcryptoprov.hpp>	// Pascal unit
#include <Sbcustomcrypto.hpp>	// Pascal unit
#include <Sbmd.hpp>	// Pascal unit
#include <Sbrdn.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbhashfunction
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElHMACKeyMaterial;
class PASCALIMPLEMENTATION TElHMACKeyMaterial : public Sbcustomcrypto::TElKeyMaterial
{
	typedef Sbcustomcrypto::TElKeyMaterial inherited;
	
private:
	Sbcryptoprov::TElCustomCryptoKey* FKey;
	Sbcryptoprov::TElCustomCryptoProvider* FCryptoProvider;
	Sbcryptoprov::TElCustomCryptoProviderManager* FCryptoProviderManager;
	Sbtypes::ByteArray __fastcall GetKey(void);
	void __fastcall SetKey(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetNonce(void);
	void __fastcall SetNonce(const Sbtypes::ByteArray Value);
	Sbcryptoprov::TElCustomCryptoProvider* __fastcall GetCryptoProvider(void);
	
public:
	__fastcall TElHMACKeyMaterial(Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall TElHMACKeyMaterial(Sbcryptoprov::TElCustomCryptoKey* Key, Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall TElHMACKeyMaterial(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall TElHMACKeyMaterial(Sbcryptoprov::TElCustomCryptoKey* Key, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual ~TElHMACKeyMaterial(void);
	__property Sbtypes::ByteArray Key = {read=GetKey, write=SetKey};
	__property Sbtypes::ByteArray Nonce = {read=GetNonce, write=SetNonce};
	__property Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider = {read=GetCryptoProvider};
};

typedef TElHMACKeyMaterial ElHMACKeyMaterial
class DELPHICLASS TElHashFunction;
class PASCALIMPLEMENTATION TElHashFunction : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	Sbcryptoprov::TElCustomCryptoProvider* FCryptoProvider;
	Sbcryptoprov::TElCustomCryptoProviderManager* FCryptoProviderManager;
	Sbcryptoprov::TElCustomCryptoContext* FContext;
	TElHMACKeyMaterial* FKey;
	void __fastcall UpdateDigest(void * Buffer, int Size)/* overload */;
	void __fastcall UpdateDigest(const Sbtypes::ByteArray Buffer, int StartIndex, int Count)/* overload */;
	int __fastcall GetAlgorithm(void);
	void __fastcall SetKey(TElHMACKeyMaterial* Value);
	TElHMACKeyMaterial* __fastcall GetKey(void);
	void __fastcall SetCryptoProvider(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider);
	Sbcryptoprov::TElCustomCryptoProvider* __fastcall GetCryptoProvider(void);
	
public:
	__fastcall TElHashFunction(int Algorithm, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall TElHashFunction(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall TElHashFunction(int Algorithm, Sbrdn::TElRelativeDistinguishedName* Parameters, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall TElHashFunction(const Sbtypes::ByteArray OID, Sbrdn::TElRelativeDistinguishedName* Parameters, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall TElHashFunction(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall TElHashFunction(int Algorithm, TElHMACKeyMaterial* Key)/* overload */;
	__fastcall TElHashFunction(const Sbtypes::ByteArray OID, TElHMACKeyMaterial* Key)/* overload */;
	__fastcall TElHashFunction(int Algorithm, TElHMACKeyMaterial* Key, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall TElHashFunction(const Sbtypes::ByteArray OID, TElHMACKeyMaterial* Key, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall TElHashFunction(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall TElHashFunction(int Algorithm, Sbrdn::TElRelativeDistinguishedName* Parameters, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall TElHashFunction(const Sbtypes::ByteArray OID, Sbrdn::TElRelativeDistinguishedName* Parameters, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall TElHashFunction(int Algorithm, TElHMACKeyMaterial* Key, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall TElHashFunction(const Sbtypes::ByteArray OID, TElHMACKeyMaterial* Key, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual ~TElHashFunction(void);
	void __fastcall Reset(void);
	void __fastcall Update(void * Buffer, int Size)/* overload */;
	void __fastcall Update(const Sbtypes::ByteArray Buffer, int StartIndex, int Count)/* overload */;
	void __fastcall Update(const Sbtypes::ByteArray Buffer)/* overload */;
	void __fastcall UpdateStream(Classes::TStream* Stream, __int64 Count = 0x000000000)/* overload */;
	Sbtypes::ByteArray __fastcall Finish(void);
	TElHashFunction* __fastcall Clone(void);
	__classmethod bool __fastcall IsAlgorithmSupported(int Algorithm, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider = (Sbcryptoprov::TElCustomCryptoProvider*)(0x0))/* overload */;
	__classmethod bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider = (Sbcryptoprov::TElCustomCryptoProvider*)(0x0))/* overload */;
	__classmethod int __fastcall GetDigestSizeBits(int Algorithm, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider = (Sbcryptoprov::TElCustomCryptoProvider*)(0x0))/* overload */;
	__classmethod int __fastcall GetDigestSizeBits(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider = (Sbcryptoprov::TElCustomCryptoProvider*)(0x0))/* overload */;
	__classmethod bool __fastcall IsAlgorithmSupported(int Algorithm, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__classmethod bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__classmethod int __fastcall GetDigestSizeBits(int Algorithm, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__classmethod int __fastcall GetDigestSizeBits(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__classmethod Sbtypes::ByteArray __fastcall Hash(int Algorithm, void * Buffer, int Size)/* overload */;
	__classmethod Sbtypes::ByteArray __fastcall Hash(int Algorithm, TElHMACKeyMaterial* Key, void * Buffer, int Size)/* overload */;
	__property int Algorithm = {read=GetAlgorithm, nodefault};
	__property Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider = {read=GetCryptoProvider, write=SetCryptoProvider};
	__property TElHMACKeyMaterial* Key = {read=GetKey, write=SetKey};
};

typedef TElHashFunction ElHashFunction
class DELPHICLASS EElHashFunctionError;
class PASCALIMPLEMENTATION EElHashFunctionError : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElHashFunctionError(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElHashFunctionError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElHashFunctionError(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElHashFunctionError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElHashFunctionError(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElHashFunctionError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElHashFunctionError(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElHashFunctionError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElHashFunctionError(void) { }
	
};


class DELPHICLASS EElHashFunctionUnsupportedError;
class PASCALIMPLEMENTATION EElHashFunctionUnsupportedError : public EElHashFunctionError
{
	typedef EElHashFunctionError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElHashFunctionUnsupportedError(const System::UnicodeString AMessage)/* overload */ : EElHashFunctionError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElHashFunctionUnsupportedError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : EElHashFunctionError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElHashFunctionUnsupportedError(int Ident)/* overload */ : EElHashFunctionError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElHashFunctionUnsupportedError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : EElHashFunctionError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElHashFunctionUnsupportedError(const System::UnicodeString Msg, int AHelpContext) : EElHashFunctionError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElHashFunctionUnsupportedError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : EElHashFunctionError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElHashFunctionUnsupportedError(int Ident, int AHelpContext)/* overload */ : EElHashFunctionError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElHashFunctionUnsupportedError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : EElHashFunctionError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElHashFunctionUnsupportedError(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE bool G_CheckPointerIsNotAnObject;

}	/* namespace Sbhashfunction */
using namespace Sbhashfunction;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbhashfunctionHPP
