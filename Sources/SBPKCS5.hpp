// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbpkcs5.pas' rev: 21.00

#ifndef Sbpkcs5HPP
#define Sbpkcs5HPP

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
#include <Sbasn1.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sbhashfunction.hpp>	// Pascal unit
#include <Sbsymmetriccrypto.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbpkcs5
{
//-- type declarations -------------------------------------------------------
#pragma option push -b-
enum TSBPKCS5Version { sbP5v1, sbP5v2 };
#pragma option pop

class DELPHICLASS TElPKCS5PBE;
class PASCALIMPLEMENTATION TElPKCS5PBE : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	int FAlgorithm;
	int FKeyLength;
	int FIterationCount;
	Sbtypes::ByteArray FSalt;
	int FKeyDerivationFunction;
	int FPseudoRandomFunction;
	int FPseudoRandomFunctionSize;
	int FHashFunction;
	int FIndex;
	Sbtypes::ByteArray FIV;
	Sbtypes::ByteArray FEncryptionAlgorithm;
	Sbtypes::ByteArray FEncryptionAlgorithmParams;
	Sbtypes::ByteArray FSymmetricAlgorithm;
	TSBPKCS5Version FVersion;
	void __fastcall DeriveKeyKDF1(const Sbtypes::ByteArray Password, int Size, Sbtypes::ByteArray &Key);
	void __fastcall DeriveKeyKDF2(const Sbtypes::ByteArray Password, int Size, Sbtypes::ByteArray &Key);
	int __fastcall FindAlgIndexByOID(const Sbtypes::ByteArray OID);
	void __fastcall ProcessPBES1Params(const Sbtypes::ByteArray Params);
	void __fastcall ProcessPBES2Params(const Sbtypes::ByteArray Params);
	void __fastcall DecryptPBES1(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, const System::UnicodeString Password);
	void __fastcall DecryptPBES2(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, const System::UnicodeString Password);
	void __fastcall EncryptPBES1(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, const System::UnicodeString Password);
	void __fastcall EncryptPBES2(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, const System::UnicodeString Password);
	void __fastcall ProcessKDFParams(const Sbtypes::ByteArray OID, const Sbtypes::ByteArray Params);
	void __fastcall ProcessPBKDF2Params(const Sbtypes::ByteArray Params);
	void __fastcall ProcessESParams(const Sbtypes::ByteArray OID, const Sbtypes::ByteArray Params);
	Sbtypes::ByteArray __fastcall WriteESParams(void);
	Sbtypes::ByteArray __fastcall WriteES1Params(void);
	Sbtypes::ByteArray __fastcall WriteES2Params(void);
	Sbtypes::ByteArray __fastcall PRF(const System::UnicodeString Password, const Sbtypes::ByteArray Salt);
	Sbtypes::ByteArray __fastcall PRFHMAC(const System::UnicodeString Password, const Sbtypes::ByteArray Salt, int Algorithm);
	void __fastcall SetSalt(const Sbtypes::ByteArray V);
	void __fastcall SetPseudoRandomFunction(const int Value);
	
public:
	__fastcall TElPKCS5PBE(const Sbtypes::ByteArray OID, const Sbtypes::ByteArray Params)/* overload */;
	__fastcall TElPKCS5PBE(int StreamAlg, int HashAlg, bool UseNewVersion)/* overload */;
	__fastcall virtual ~TElPKCS5PBE(void);
	void __fastcall Decrypt(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, const System::UnicodeString Password);
	void __fastcall Encrypt(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, const System::UnicodeString Password);
	Sbtypes::ByteArray __fastcall DeriveKey(const System::UnicodeString Password, int Bits);
	bool __fastcall IsPRFSupported(int Alg);
	__classmethod bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	__classmethod bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	__classmethod int __fastcall GetAlgorithmByOID(const Sbtypes::ByteArray OID);
	__property int Algorithm = {read=FAlgorithm, nodefault};
	__property TSBPKCS5Version Version = {read=FVersion, nodefault};
	__property Sbtypes::ByteArray EncryptionAlgorithmOID = {read=FEncryptionAlgorithm};
	__property Sbtypes::ByteArray EncryptionAlgorithmParams = {read=FEncryptionAlgorithmParams};
	__property Sbtypes::ByteArray Salt = {read=FSalt, write=SetSalt};
	__property int IterationCount = {read=FIterationCount, write=FIterationCount, nodefault};
	__property int PseudoRandomFunction = {read=FPseudoRandomFunction, write=SetPseudoRandomFunction, nodefault};
};


class DELPHICLASS EElPKCS5Error;
class PASCALIMPLEMENTATION EElPKCS5Error : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElPKCS5Error(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElPKCS5Error(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElPKCS5Error(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElPKCS5Error(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElPKCS5Error(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElPKCS5Error(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElPKCS5Error(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElPKCS5Error(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElPKCS5Error(void) { }
	
};


class DELPHICLASS EElPKCS5UnsupportedError;
class PASCALIMPLEMENTATION EElPKCS5UnsupportedError : public EElPKCS5Error
{
	typedef EElPKCS5Error inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElPKCS5UnsupportedError(const System::UnicodeString AMessage)/* overload */ : EElPKCS5Error(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElPKCS5UnsupportedError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : EElPKCS5Error(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElPKCS5UnsupportedError(int Ident)/* overload */ : EElPKCS5Error(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElPKCS5UnsupportedError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : EElPKCS5Error(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElPKCS5UnsupportedError(const System::UnicodeString Msg, int AHelpContext) : EElPKCS5Error(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElPKCS5UnsupportedError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : EElPKCS5Error(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElPKCS5UnsupportedError(int Ident, int AHelpContext)/* overload */ : EElPKCS5Error(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElPKCS5UnsupportedError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : EElPKCS5Error(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElPKCS5UnsupportedError(void) { }
	
};


class DELPHICLASS EElPKCS5InternalError;
class PASCALIMPLEMENTATION EElPKCS5InternalError : public EElPKCS5Error
{
	typedef EElPKCS5Error inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElPKCS5InternalError(const System::UnicodeString AMessage)/* overload */ : EElPKCS5Error(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElPKCS5InternalError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : EElPKCS5Error(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElPKCS5InternalError(int Ident)/* overload */ : EElPKCS5Error(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElPKCS5InternalError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : EElPKCS5Error(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElPKCS5InternalError(const System::UnicodeString Msg, int AHelpContext) : EElPKCS5Error(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElPKCS5InternalError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : EElPKCS5Error(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElPKCS5InternalError(int Ident, int AHelpContext)/* overload */ : EElPKCS5Error(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElPKCS5InternalError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : EElPKCS5Error(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElPKCS5InternalError(void) { }
	
};


class DELPHICLASS EElPKCS5InvalidParameterError;
class PASCALIMPLEMENTATION EElPKCS5InvalidParameterError : public EElPKCS5Error
{
	typedef EElPKCS5Error inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElPKCS5InvalidParameterError(const System::UnicodeString AMessage)/* overload */ : EElPKCS5Error(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElPKCS5InvalidParameterError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : EElPKCS5Error(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElPKCS5InvalidParameterError(int Ident)/* overload */ : EElPKCS5Error(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElPKCS5InvalidParameterError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : EElPKCS5Error(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElPKCS5InvalidParameterError(const System::UnicodeString Msg, int AHelpContext) : EElPKCS5Error(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElPKCS5InvalidParameterError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : EElPKCS5Error(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElPKCS5InvalidParameterError(int Ident, int AHelpContext)/* overload */ : EElPKCS5Error(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElPKCS5InvalidParameterError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : EElPKCS5Error(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElPKCS5InvalidParameterError(void) { }
	
};


class DELPHICLASS EElPKCS5InvalidPasswordError;
class PASCALIMPLEMENTATION EElPKCS5InvalidPasswordError : public EElPKCS5Error
{
	typedef EElPKCS5Error inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElPKCS5InvalidPasswordError(const System::UnicodeString AMessage)/* overload */ : EElPKCS5Error(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElPKCS5InvalidPasswordError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : EElPKCS5Error(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElPKCS5InvalidPasswordError(int Ident)/* overload */ : EElPKCS5Error(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElPKCS5InvalidPasswordError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : EElPKCS5Error(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElPKCS5InvalidPasswordError(const System::UnicodeString Msg, int AHelpContext) : EElPKCS5Error(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElPKCS5InvalidPasswordError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : EElPKCS5Error(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElPKCS5InvalidPasswordError(int Ident, int AHelpContext)/* overload */ : EElPKCS5Error(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElPKCS5InvalidPasswordError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : EElPKCS5Error(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElPKCS5InvalidPasswordError(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------

}	/* namespace Sbpkcs5 */
using namespace Sbpkcs5;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// Sbpkcs5HPP
