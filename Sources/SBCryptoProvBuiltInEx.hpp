// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbcryptoprovbuiltinex.pas' rev: 21.00

#ifndef SbcryptoprovbuiltinexHPP
#define SbcryptoprovbuiltinexHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbcryptoprov.hpp>	// Pascal unit
#include <Sbcryptoprovbuiltin.hpp>	// Pascal unit
#include <Sbcryptoprovbuiltinsym.hpp>	// Pascal unit
#include <Sbcryptoprovrs.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sbidea.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbcryptoprovbuiltinex
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElBuiltInExtendedCryptoProvider;
class PASCALIMPLEMENTATION TElBuiltInExtendedCryptoProvider : public Sbcryptoprovbuiltin::TElBuiltInCryptoProvider
{
	typedef Sbcryptoprovbuiltin::TElBuiltInCryptoProvider inherited;
	
protected:
	virtual System::TObject* __fastcall CreateSymmetricCryptoFactory(void);
	
public:
	virtual Sbcryptoprov::TElCustomCryptoProvider* __fastcall GetDefaultInstance(void);
	__classmethod virtual void __fastcall SetAsDefault();
public:
	/* TElCustomCryptoProvider.Create */ inline __fastcall virtual TElBuiltInExtendedCryptoProvider(Classes::TComponent* AOwner)/* overload */ : Sbcryptoprovbuiltin::TElBuiltInCryptoProvider(AOwner) { }
	/* TElCustomCryptoProvider.Destroy */ inline __fastcall virtual ~TElBuiltInExtendedCryptoProvider(void) { }
	
};


class DELPHICLASS TElBuiltInExtendedSymmetricCryptoFactory;
class PASCALIMPLEMENTATION TElBuiltInExtendedSymmetricCryptoFactory : public Sbcryptoprovbuiltinsym::TElBuiltInSymmetricCryptoFactory
{
	typedef Sbcryptoprovbuiltinsym::TElBuiltInSymmetricCryptoFactory inherited;
	
protected:
	virtual void __fastcall RegisterDefaultClasses(void);
public:
	/* TElBuiltInSymmetricCryptoFactory.Create */ inline __fastcall TElBuiltInExtendedSymmetricCryptoFactory(void) : Sbcryptoprovbuiltinsym::TElBuiltInSymmetricCryptoFactory() { }
	/* TElBuiltInSymmetricCryptoFactory.Destroy */ inline __fastcall virtual ~TElBuiltInExtendedSymmetricCryptoFactory(void) { }
	
};


class DELPHICLASS TElBuiltInIDEASymmetricCrypto;
class PASCALIMPLEMENTATION TElBuiltInIDEASymmetricCrypto : public Sbcryptoprovbuiltinsym::TElBuiltInSymmetricCrypto
{
	typedef Sbcryptoprovbuiltinsym::TElBuiltInSymmetricCrypto inherited;
	
protected:
	Sbidea::TIDEAExpandedKey FKey;
	virtual void __fastcall SetKeyMaterial(Sbcryptoprov::TElCustomCryptoKey* Material);
	virtual void __fastcall EncryptBlock8(unsigned &B0, unsigned &B1);
	virtual void __fastcall DecryptBlock8(unsigned &B0, unsigned &B1);
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int AlgID)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray AlgOID)/* overload */;
	__classmethod virtual void __fastcall GetDefaultKeyAndBlockLengths(int AlgID, int &KeyLen, int &BlockLen)/* overload */;
	__classmethod virtual void __fastcall GetDefaultKeyAndBlockLengths(const Sbtypes::ByteArray OID, int &KeyLen, int &BlockLen)/* overload */;
	
public:
	__fastcall virtual TElBuiltInIDEASymmetricCrypto(int AlgID, Sbcryptoprovbuiltinsym::TSBBuiltInSymmetricCryptoMode Mode)/* overload */;
	__fastcall virtual TElBuiltInIDEASymmetricCrypto(const Sbtypes::ByteArray AlgOID, Sbcryptoprovbuiltinsym::TSBBuiltInSymmetricCryptoMode Mode)/* overload */;
	__fastcall virtual TElBuiltInIDEASymmetricCrypto(Sbcryptoprovbuiltinsym::TSBBuiltInSymmetricCryptoMode Mode)/* overload */;
	virtual void __fastcall InitializeEncryption(void);
	virtual void __fastcall InitializeDecryption(void);
public:
	/* TElBuiltInSymmetricCrypto.Destroy */ inline __fastcall virtual ~TElBuiltInIDEASymmetricCrypto(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE Sbcryptoprov::TElCustomCryptoProvider* __fastcall BuiltInCryptoProviderEx(void);

}	/* namespace Sbcryptoprovbuiltinex */
using namespace Sbcryptoprovbuiltinex;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbcryptoprovbuiltinexHPP
