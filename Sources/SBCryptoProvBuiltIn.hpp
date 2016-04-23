// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbcryptoprovbuiltin.pas' rev: 21.00

#ifndef SbcryptoprovbuiltinHPP
#define SbcryptoprovbuiltinHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Windows.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbcryptoprov.hpp>	// Pascal unit
#include <Sbcryptoprovrs.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbrandom.hpp>	// Pascal unit
#include <Sbsharedresource.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbrdn.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbcryptoprovbuiltin
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElBuiltInCryptoProviderOptions;
class PASCALIMPLEMENTATION TElBuiltInCryptoProviderOptions : public Sbcryptoprov::TElCustomCryptoProviderOptions
{
	typedef Sbcryptoprov::TElCustomCryptoProviderOptions inherited;
	
protected:
	bool FUsePlatformKeyGeneration;
	bool FRollbackToBuiltInKeyGeneration;
	bool FUseTimingAttackProtection;
	virtual void __fastcall Init(void);
	
public:
	virtual void __fastcall Assign(Sbcryptoprov::TElCustomCryptoProviderOptions* Options);
	__property bool UsePlatformKeyGeneration = {read=FUsePlatformKeyGeneration, write=FUsePlatformKeyGeneration, nodefault};
	__property bool RollbackToBuiltInKeyGeneration = {read=FRollbackToBuiltInKeyGeneration, write=FRollbackToBuiltInKeyGeneration, nodefault};
	__property bool UseTimingAttackProtection = {read=FUseTimingAttackProtection, write=FUseTimingAttackProtection, nodefault};
public:
	/* TElCustomCryptoProviderOptions.Create */ inline __fastcall TElBuiltInCryptoProviderOptions(void) : Sbcryptoprov::TElCustomCryptoProviderOptions() { }
	
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TElBuiltInCryptoProviderOptions(void) { }
	
};


class DELPHICLASS TElBuiltInCryptoKey;
class PASCALIMPLEMENTATION TElBuiltInCryptoKey : public Sbcryptoprov::TElCustomCryptoKey
{
	typedef Sbcryptoprov::TElCustomCryptoKey inherited;
	
protected:
	int FMode;
	Sbtypes::ByteArray FIV;
	Sbtypes::ByteArray FValue;
	virtual int __fastcall GetMode(void);
	virtual void __fastcall SetMode(int Value);
	virtual Sbtypes::ByteArray __fastcall GetIV(void);
	virtual void __fastcall SetIV(const Sbtypes::ByteArray Value);
	virtual Sbtypes::ByteArray __fastcall GetValue(void);
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value);
	
public:
	__fastcall virtual ~TElBuiltInCryptoKey(void);
	virtual void __fastcall Reset(void);
	virtual void __fastcall ChangeAlgorithm(int Algorithm);
	virtual void __fastcall PrepareForEncryption(bool MultiUse = false);
	virtual void __fastcall PrepareForSigning(bool MultiUse = false);
	virtual void __fastcall CancelPreparation(void);
	virtual bool __fastcall AsyncOperationFinished(void);
	virtual bool __fastcall Equals(Sbcryptoprov::TElCustomCryptoKey* Source, bool PublicOnly, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0))/* overload */;
	virtual void __fastcall Persistentiate(void);
public:
	/* TElCustomCryptoKey.Create */ inline __fastcall virtual TElBuiltInCryptoKey(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider) : Sbcryptoprov::TElCustomCryptoKey(CryptoProvider) { }
	
	
/* Hoisted overloads: */
	
public:
	inline bool __fastcall  Equals(System::TObject* Obj){ return Sbcryptoprov::TElCustomCryptoKey::Equals(Obj); }
	
};


class DELPHICLASS TElBuiltInCryptoProvider;
class PASCALIMPLEMENTATION TElBuiltInCryptoProvider : public Sbcryptoprov::TElBlackboxCryptoProvider
{
	typedef Sbcryptoprov::TElBlackboxCryptoProvider inherited;
	
private:
	Classes::TList* FKeys;
	Classes::TList* FContexts;
	Sbrandom::TElRandom* FRandom;
	Sbsharedresource::TElSharedResource* FRandomAccess;
	Sbsharedresource::TElSharedResource* FLock;
	void __fastcall ClearKeys(void);
	void __fastcall ClearContexts(void);
	Sbcryptoprov::TElCustomCryptoKey* __fastcall InternalCreateKey(int Algorithm, int Mode, const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0));
	void __fastcall InternalEncryptInit(Sbcryptoprov::TElCustomCryptoContext* Context);
	void __fastcall InternalDecryptInit(Sbcryptoprov::TElCustomCryptoContext* Context);
	void __fastcall InternalSignInit(Sbcryptoprov::TElCustomCryptoContext* Context, bool Detached);
	void __fastcall InternalVerifyInit(Sbcryptoprov::TElCustomCryptoContext* Context, void * SigBuffer, int SigSize);
	void __fastcall RandomSeedTime(void);
	
protected:
	virtual System::TObject* __fastcall CreateSymmetricCryptoFactory(void);
	virtual Sbcryptoprov::TElCustomCryptoProviderOptions* __fastcall CreateOptions(void);
	
public:
	virtual void __fastcall Init(void);
	virtual void __fastcall Deinit(void);
	__classmethod virtual void __fastcall SetAsDefault();
	virtual bool __fastcall IsAlgorithmSupported(int Algorithm, int Mode)/* overload */;
	virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, int Mode)/* overload */;
	virtual bool __fastcall IsOperationSupported(int Operation, int Algorithm, int Mode, Sbcryptoprov::TElCustomCryptoKey* Key, Sbrdn::TElRelativeDistinguishedName* Params)/* overload */;
	virtual bool __fastcall IsOperationSupported(int Operation, const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, int Mode, Sbcryptoprov::TElCustomCryptoKey* Key, Sbrdn::TElRelativeDistinguishedName* Params)/* overload */;
	virtual Sbtypes::ByteArray __fastcall GetAlgorithmProperty(int Algorithm, int Mode, const Sbtypes::ByteArray PropID)/* overload */;
	virtual Sbtypes::ByteArray __fastcall GetAlgorithmProperty(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, int Mode, const Sbtypes::ByteArray PropID)/* overload */;
	virtual int __fastcall GetAlgorithmClass(int Algorithm)/* overload */;
	virtual int __fastcall GetAlgorithmClass(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams)/* overload */;
	virtual Sbcryptoprov::TElCustomCryptoProvider* __fastcall GetDefaultInstance(void);
	virtual Sbcryptoprov::TElCustomCryptoKey* __fastcall CreateKey(int Algorithm, int Mode, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0))/* overload */;
	virtual Sbcryptoprov::TElCustomCryptoKey* __fastcall CreateKey(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0))/* overload */;
	virtual Sbcryptoprov::TElCustomCryptoKey* __fastcall CloneKey(Sbcryptoprov::TElCustomCryptoKey* Key);
	virtual void __fastcall ReleaseKey(Sbcryptoprov::TElCustomCryptoKey* &Key);
	virtual void __fastcall DeleteKey(Sbcryptoprov::TElCustomCryptoKey* &Key);
	virtual Sbcryptoprov::TElCustomCryptoKey* __fastcall DecryptKey(void * EncKey, int EncKeySize, const Sbtypes::ByteArray EncKeyAlgOID, const Sbtypes::ByteArray EncKeyAlgParams, Sbcryptoprov::TElCustomCryptoKey* Key, const Sbtypes::ByteArray KeyAlgOID, const Sbtypes::ByteArray KeyAlgParams, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0));
	virtual Sbcryptoprov::TElCustomCryptoContext* __fastcall EncryptInit(int Algorithm, int Mode, Sbcryptoprov::TElCustomCryptoKey* Key, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
	virtual Sbcryptoprov::TElCustomCryptoContext* __fastcall EncryptInit(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, int Mode, Sbcryptoprov::TElCustomCryptoKey* Key, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
	virtual Sbcryptoprov::TElCustomCryptoContext* __fastcall DecryptInit(int Algorithm, int Mode, Sbcryptoprov::TElCustomCryptoKey* Key, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
	virtual Sbcryptoprov::TElCustomCryptoContext* __fastcall DecryptInit(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, int Mode, Sbcryptoprov::TElCustomCryptoKey* Key, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
	virtual Sbcryptoprov::TElCustomCryptoContext* __fastcall SignInit(int Algorithm, Sbcryptoprov::TElCustomCryptoKey* Key, bool Detached, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
	virtual Sbcryptoprov::TElCustomCryptoContext* __fastcall SignInit(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, Sbcryptoprov::TElCustomCryptoKey* Key, bool Detached, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
	virtual Sbcryptoprov::TElCustomCryptoContext* __fastcall VerifyInit(int Algorithm, Sbcryptoprov::TElCustomCryptoKey* Key, void * SigBuffer, int SigSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
	virtual Sbcryptoprov::TElCustomCryptoContext* __fastcall VerifyInit(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, Sbcryptoprov::TElCustomCryptoKey* Key, void * SigBuffer, int SigSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
	virtual void __fastcall EncryptUpdate(Sbcryptoprov::TElCustomCryptoContext* Context, void * InBuffer, int InSize, void * OutBuffer, int &OutSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0));
	virtual void __fastcall DecryptUpdate(Sbcryptoprov::TElCustomCryptoContext* Context, void * InBuffer, int InSize, void * OutBuffer, int &OutSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0));
	virtual void __fastcall SignUpdate(Sbcryptoprov::TElCustomCryptoContext* Context, void * InBuffer, int InSize, void * OutBuffer, int &OutSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0));
	virtual void __fastcall VerifyUpdate(Sbcryptoprov::TElCustomCryptoContext* Context, void * InBuffer, int InSize, void * OutBuffer, int &OutSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0));
	virtual void __fastcall EncryptFinal(Sbcryptoprov::TElCustomCryptoContext* Context, void * Buffer, int &Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0));
	virtual void __fastcall DecryptFinal(Sbcryptoprov::TElCustomCryptoContext* Context, void * Buffer, int &Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0));
	virtual void __fastcall SignFinal(Sbcryptoprov::TElCustomCryptoContext* Context, void * Buffer, int &Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0));
	virtual int __fastcall VerifyFinal(Sbcryptoprov::TElCustomCryptoContext* Context, void * Buffer, int &Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0));
	virtual Sbcryptoprov::TElCustomCryptoContext* __fastcall HashInit(int Algorithm, Sbcryptoprov::TElCustomCryptoKey* Key, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
	virtual Sbcryptoprov::TElCustomCryptoContext* __fastcall HashInit(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, Sbcryptoprov::TElCustomCryptoKey* Key, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
	virtual void __fastcall HashUpdate(Sbcryptoprov::TElCustomCryptoContext* Context, void * Buffer, int Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0));
	virtual Sbtypes::ByteArray __fastcall HashFinal(Sbcryptoprov::TElCustomCryptoContext* Context, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0));
	virtual void __fastcall ReleaseCryptoContext(Sbcryptoprov::TElCustomCryptoContext* &Context);
	virtual Sbcryptoprov::TElCustomCryptoKeyStorage* __fastcall CreateKeyStorage(bool Persistent, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0));
	virtual void __fastcall ReleaseKeyStorage(Sbcryptoprov::TElCustomCryptoKeyStorage* &KeyStorage);
	virtual void __fastcall DeleteKeyStorage(Sbcryptoprov::TElCustomCryptoKeyStorage* &KeyStorage);
	virtual void __fastcall RandomInit(void * BaseData, int BaseDataSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0));
	virtual void __fastcall RandomSeed(void * Data, int DataSize);
	virtual void __fastcall RandomGenerate(void * Buffer, int Size)/* overload */;
	virtual int __fastcall RandomGenerate(int MaxValue)/* overload */;
public:
	/* TElCustomCryptoProvider.Create */ inline __fastcall virtual TElBuiltInCryptoProvider(Classes::TComponent* AOwner)/* overload */ : Sbcryptoprov::TElBlackboxCryptoProvider(AOwner) { }
	/* TElCustomCryptoProvider.Destroy */ inline __fastcall virtual ~TElBuiltInCryptoProvider(void) { }
	
};


class DELPHICLASS EElBuiltInCryptoProviderError;
class PASCALIMPLEMENTATION EElBuiltInCryptoProviderError : public Sbcryptoprov::EElCryptoProviderError
{
	typedef Sbcryptoprov::EElCryptoProviderError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElBuiltInCryptoProviderError(const System::UnicodeString AMessage)/* overload */ : Sbcryptoprov::EElCryptoProviderError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElBuiltInCryptoProviderError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbcryptoprov::EElCryptoProviderError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElBuiltInCryptoProviderError(int Ident)/* overload */ : Sbcryptoprov::EElCryptoProviderError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElBuiltInCryptoProviderError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbcryptoprov::EElCryptoProviderError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElBuiltInCryptoProviderError(const System::UnicodeString Msg, int AHelpContext) : Sbcryptoprov::EElCryptoProviderError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElBuiltInCryptoProviderError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbcryptoprov::EElCryptoProviderError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElBuiltInCryptoProviderError(int Ident, int AHelpContext)/* overload */ : Sbcryptoprov::EElCryptoProviderError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElBuiltInCryptoProviderError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbcryptoprov::EElCryptoProviderError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElBuiltInCryptoProviderError(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE Sbcryptoprov::TElCustomCryptoProvider* __fastcall BuiltInCryptoProvider(void);

}	/* namespace Sbcryptoprovbuiltin */
using namespace Sbcryptoprovbuiltin;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbcryptoprovbuiltinHPP
