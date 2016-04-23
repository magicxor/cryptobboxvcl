// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbcryptoprovbuiltinhash.pas' rev: 21.00

#ifndef SbcryptoprovbuiltinhashHPP
#define SbcryptoprovbuiltinhashHPP

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
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sbcrc.hpp>	// Pascal unit
#include <Sbmd.hpp>	// Pascal unit
#include <Sbsha.hpp>	// Pascal unit
#include <Sbsha2.hpp>	// Pascal unit
#include <Sbripemd.hpp>	// Pascal unit
#include <Sbwhirlpool.hpp>	// Pascal unit
#include <Sbgostcommon.hpp>	// Pascal unit
#include <Sbgost341194.hpp>	// Pascal unit
#include <Sbgost2814789.hpp>	// Pascal unit
#include <Sbumac.hpp>	// Pascal unit
#include <Sbcryptoprov.hpp>	// Pascal unit
#include <Sbcryptoprovrs.hpp>	// Pascal unit
#include <Sbcryptoprovbuiltin.hpp>	// Pascal unit
#include <Sbrdn.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbcryptoprovbuiltinhash
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElBuiltInHashFunction;
class PASCALIMPLEMENTATION TElBuiltInHashFunction : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	int FAlgorithm;
	Sbmd::TMD2Context FCtxMD2;
	Sbmd::TMD5Context FCtxMD5;
	Sbsha::TSHA1Context FCtxSHA1;
	Sbsha2::TSHA256Context FCtxSHA256;
	Sbsha2::TSHA512Context FCtxSHA512;
	Sbripemd::TRMD160Context FCtxRMD160;
	Sbwhirlpool::TWhirlpoolContext FCtxWhirlpool;
	unsigned FCRC32;
	Sbtypes::ByteArray FDigest;
	Sbcryptoprov::TElCustomCryptoKey* FKeyMaterial;
	bool FUseHMAC;
	int FHMACBlockSize;
	Sbumac::TElUMAC* FCtxUMAC;
	Sbgostcommon::TElGOSTBase* FCtxGOST;
	void __fastcall InitializeDigest(Sbrdn::TElRelativeDistinguishedName* Parameters = (Sbrdn::TElRelativeDistinguishedName*)(0x0));
	void __fastcall UpdateDigest(void * Buffer, int Size);
	void __fastcall FinalizeDigest(void);
	
public:
	__fastcall TElBuiltInHashFunction(int Algorithm, Sbrdn::TElRelativeDistinguishedName* Parameters, Sbcryptoprov::TElCustomCryptoKey* Key)/* overload */;
	__fastcall TElBuiltInHashFunction(const Sbtypes::ByteArray OID, Sbrdn::TElRelativeDistinguishedName* Parameters, Sbcryptoprov::TElCustomCryptoKey* Key)/* overload */;
	void __fastcall SetHashFunctionProp(const Sbtypes::ByteArray PropID, const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetHashFunctionProp(const Sbtypes::ByteArray PropID, const Sbtypes::ByteArray Default);
	__fastcall virtual ~TElBuiltInHashFunction(void);
	void __fastcall Reset(void);
	void __fastcall Update(void * Buffer, int Size)/* overload */;
	void __fastcall Update(Classes::TStream* Stream, __int64 Count = 0x000000000)/* overload */;
	Sbtypes::ByteArray __fastcall Finish(void);
	TElBuiltInHashFunction* __fastcall Clone(void);
	__property int Algorithm = {read=FAlgorithm, nodefault};
	__property Sbcryptoprov::TElCustomCryptoKey* KeyMaterial = {read=FKeyMaterial, write=FKeyMaterial};
	__classmethod bool __fastcall IsAlgorithmSupported(int Algorithm)/* overload */;
	__classmethod bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	__classmethod int __fastcall GetDigestSizeBits(int Algorithm)/* overload */;
	__classmethod int __fastcall GetDigestSizeBits(const Sbtypes::ByteArray OID)/* overload */;
};


class DELPHICLASS EElHashFunctionError;
class PASCALIMPLEMENTATION EElHashFunctionError : public Sbcryptoprov::EElCryptoProviderError
{
	typedef Sbcryptoprov::EElCryptoProviderError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElHashFunctionError(const System::UnicodeString AMessage)/* overload */ : Sbcryptoprov::EElCryptoProviderError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElHashFunctionError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbcryptoprov::EElCryptoProviderError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElHashFunctionError(int Ident)/* overload */ : Sbcryptoprov::EElCryptoProviderError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElHashFunctionError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbcryptoprov::EElCryptoProviderError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElHashFunctionError(const System::UnicodeString Msg, int AHelpContext) : Sbcryptoprov::EElCryptoProviderError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElHashFunctionError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbcryptoprov::EElCryptoProviderError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElHashFunctionError(int Ident, int AHelpContext)/* overload */ : Sbcryptoprov::EElCryptoProviderError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElHashFunctionError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbcryptoprov::EElCryptoProviderError(ResStringRec, Args, Args_Size, AHelpContext) { }
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


class DELPHICLASS TElBuiltInMACKey;
class PASCALIMPLEMENTATION TElBuiltInMACKey : public Sbcryptoprovbuiltin::TElBuiltInCryptoKey
{
	typedef Sbcryptoprovbuiltin::TElBuiltInCryptoKey inherited;
	
protected:
	Sbtypes::ByteArray FValue;
	Sbtypes::ByteArray FNonce;
	virtual bool __fastcall GetIsPublic(void);
	virtual bool __fastcall GetIsSecret(void);
	virtual bool __fastcall GetIsExportable(void);
	virtual bool __fastcall GetIsPersistent(void);
	virtual bool __fastcall GetIsValid(void);
	virtual int __fastcall GetBits(void);
	virtual int __fastcall GetAlgorithm(void);
	virtual Sbcryptoprov::TElCustomCryptoKeyStorage* __fastcall GetKeyStorage(void);
	virtual int __fastcall GetMode(void);
	virtual void __fastcall SetMode(int Value);
	virtual Sbtypes::ByteArray __fastcall GetIV(void);
	virtual void __fastcall SetIV(const Sbtypes::ByteArray Value);
	virtual Sbtypes::ByteArray __fastcall GetValue(void);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	
public:
	__fastcall virtual ~TElBuiltInMACKey(void);
	virtual void __fastcall Reset(void);
	virtual void __fastcall Generate(int Bits, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0));
	virtual void __fastcall ImportPublic(void * Buffer, int Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0));
	virtual void __fastcall ImportSecret(void * Buffer, int Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0));
	virtual void __fastcall ExportPublic(void * Buffer, int &Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0));
	virtual void __fastcall ExportSecret(void * Buffer, int &Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0));
	virtual Sbcryptoprov::TElCustomCryptoKey* __fastcall Clone(Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0));
	virtual Sbcryptoprov::TElCustomCryptoKey* __fastcall ClonePublic(Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0));
	virtual void __fastcall ClearPublic(void);
	virtual void __fastcall ClearSecret(void);
	virtual Sbtypes::ByteArray __fastcall GetKeyProp(const Sbtypes::ByteArray PropID, const Sbtypes::ByteArray Default = (Sbtypes::ByteArray)(0x0));
	virtual void __fastcall SetKeyProp(const Sbtypes::ByteArray PropID, const Sbtypes::ByteArray Value);
	virtual void __fastcall ChangeAlgorithm(int Algorithm);
	virtual bool __fastcall Equals(Sbcryptoprov::TElCustomCryptoKey* Source, bool PublicOnly, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0))/* overload */;
public:
	/* TElCustomCryptoKey.Create */ inline __fastcall virtual TElBuiltInMACKey(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider) : Sbcryptoprovbuiltin::TElBuiltInCryptoKey(CryptoProvider) { }
	
	
/* Hoisted overloads: */
	
public:
	inline bool __fastcall  Equals(System::TObject* Obj){ return Sbcryptoprov::TElCustomCryptoKey::Equals(Obj); }
	
};


//-- var, const, procedure ---------------------------------------------------

}	/* namespace Sbcryptoprovbuiltinhash */
using namespace Sbcryptoprovbuiltinhash;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbcryptoprovbuiltinhashHPP
