// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbcryptoprov.pas' rev: 21.00

#ifndef SbcryptoprovHPP
#define SbcryptoprovHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbrdn.hpp>	// Pascal unit
#include <Sbasn1.hpp>	// Pascal unit
#include <Sbmath.hpp>	// Pascal unit
#include <Sbsharedresource.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbcryptoprov
{
//-- type declarations -------------------------------------------------------
typedef void * TElCPKeyHandle;

typedef Sbrdn::TElRelativeDistinguishedName TElCPParameters;

class DELPHICLASS TElCustomCryptoKey;
class DELPHICLASS TElCustomCryptoProvider;
class DELPHICLASS TElCustomCryptoKeyStorage;
class PASCALIMPLEMENTATION TElCustomCryptoKey : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	Sbtypes::ByteArray FOwnerUniqueID;
	TElCustomCryptoProvider* FCryptoProvider;
	void __fastcall InternalImportPublic(void * Buffer, int Size, int &Algorithm, Sbtypes::ByteArray &Key, Sbtypes::ByteArray &IV);
	void __fastcall InternalExportPublic(int Algorithm, const Sbtypes::ByteArray Key, const Sbtypes::ByteArray IV, void * Buffer, int &Size);
	virtual bool __fastcall GetIsPublic(void) = 0 ;
	virtual bool __fastcall GetIsSecret(void) = 0 ;
	virtual bool __fastcall GetIsExportable(void) = 0 ;
	virtual bool __fastcall GetIsPersistent(void) = 0 ;
	virtual bool __fastcall GetIsValid(void) = 0 ;
	virtual int __fastcall GetBits(void) = 0 ;
	virtual int __fastcall GetAlgorithm(void) = 0 ;
	virtual TElCustomCryptoKeyStorage* __fastcall GetKeyStorage(void) = 0 ;
	virtual int __fastcall GetMode(void) = 0 ;
	virtual void __fastcall SetMode(int Value) = 0 ;
	virtual Sbtypes::ByteArray __fastcall GetIV(void) = 0 ;
	virtual void __fastcall SetIV(const Sbtypes::ByteArray Value) = 0 ;
	virtual Sbtypes::ByteArray __fastcall GetValue(void) = 0 ;
	virtual void __fastcall SetValue(const Sbtypes::ByteArray Value) = 0 ;
	
public:
	__fastcall virtual TElCustomCryptoKey(TElCustomCryptoProvider* CryptoProvider);
	virtual void __fastcall Reset(void) = 0 ;
	virtual void __fastcall Generate(int Bits, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0)) = 0 ;
	virtual void __fastcall ImportPublic(void * Buffer, int Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0)) = 0 ;
	virtual void __fastcall ImportSecret(void * Buffer, int Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0)) = 0 ;
	virtual void __fastcall ExportPublic(void * Buffer, int &Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0)) = 0 ;
	virtual void __fastcall ExportSecret(void * Buffer, int &Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0)) = 0 ;
	virtual TElCustomCryptoKey* __fastcall Clone(Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0)) = 0 ;
	virtual TElCustomCryptoKey* __fastcall ClonePublic(Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0)) = 0 ;
	virtual void __fastcall ClearPublic(void) = 0 ;
	virtual void __fastcall ClearSecret(void) = 0 ;
	virtual Sbtypes::ByteArray __fastcall GetKeyProp(const Sbtypes::ByteArray PropID, const Sbtypes::ByteArray Default = (Sbtypes::ByteArray)(0x0)) = 0 ;
	virtual void __fastcall SetKeyProp(const Sbtypes::ByteArray PropID, const Sbtypes::ByteArray Value) = 0 ;
	virtual void __fastcall ChangeAlgorithm(int Algorithm) = 0 ;
	virtual void __fastcall PrepareForEncryption(bool MultiUse = false) = 0 ;
	virtual void __fastcall PrepareForSigning(bool MultiUse = false) = 0 ;
	virtual void __fastcall CancelPreparation(void) = 0 ;
	virtual bool __fastcall AsyncOperationFinished(void) = 0 ;
	HIDESBASE virtual bool __fastcall Equals(TElCustomCryptoKey* Key, bool PublicOnly, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0))/* overload */;
	virtual bool __fastcall Equals(System::TObject* Obj)/* overload */;
	virtual void __fastcall Persistentiate(void) = 0 ;
	__property bool IsPublic = {read=GetIsPublic, nodefault};
	__property bool IsSecret = {read=GetIsSecret, nodefault};
	__property bool IsExportable = {read=GetIsExportable, nodefault};
	__property bool IsPersistent = {read=GetIsPersistent, nodefault};
	__property bool IsValid = {read=GetIsValid, nodefault};
	__property int Bits = {read=GetBits, nodefault};
	__property int Algorithm = {read=GetAlgorithm, nodefault};
	__property Sbtypes::ByteArray Value = {read=GetValue, write=SetValue};
	__property Sbtypes::ByteArray IV = {read=GetIV, write=SetIV};
	__property int Mode = {read=GetMode, write=SetMode, nodefault};
	__property TElCustomCryptoProvider* CryptoProvider = {read=FCryptoProvider};
	__property TElCustomCryptoKeyStorage* KeyStorage = {read=GetKeyStorage};
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TElCustomCryptoKey(void) { }
	
};


class PASCALIMPLEMENTATION TElCustomCryptoKeyStorage : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	TElCustomCryptoProvider* FCryptoProvider;
	virtual bool __fastcall GetIsPersistent(void) = 0 ;
	virtual TElCustomCryptoKey* __fastcall GetKey(int Index) = 0 ;
	virtual int __fastcall GetCount(void) = 0 ;
	
public:
	virtual int __fastcall AddKey(TElCustomCryptoKey* Key, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0)) = 0 ;
	virtual void __fastcall RemoveKey(int Index, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0)) = 0 /* overload */;
	virtual void __fastcall RemoveKey(TElCustomCryptoKey* Key, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0)) = 0 /* overload */;
	virtual void __fastcall Clear(void) = 0 ;
	virtual TElCustomCryptoKeyStorage* __fastcall Clone(Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0)) = 0 ;
	virtual void __fastcall Lock(void) = 0 ;
	virtual void __fastcall Unlock(void) = 0 ;
	virtual Sbtypes::ByteArray __fastcall GetStorageProp(const Sbtypes::ByteArray PropID, const Sbtypes::ByteArray Default = (Sbtypes::ByteArray)(0x0)) = 0 ;
	virtual void __fastcall SetStorageProp(const Sbtypes::ByteArray PropID, const Sbtypes::ByteArray Value) = 0 ;
	__property TElCustomCryptoKey* Keys[int Index] = {read=GetKey};
	__property int Count = {read=GetCount, nodefault};
	__property bool IsPersistent = {read=GetIsPersistent, nodefault};
	__property TElCustomCryptoProvider* CryptoProvider = {read=FCryptoProvider};
public:
	/* TObject.Create */ inline __fastcall TElCustomCryptoKeyStorage(void) : System::TObject() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TElCustomCryptoKeyStorage(void) { }
	
};


class DELPHICLASS TElCustomCryptoContext;
class PASCALIMPLEMENTATION TElCustomCryptoContext : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	TElCustomCryptoProvider* FProvider;
	virtual int __fastcall GetAlgorithm(void) = 0 ;
	virtual int __fastcall GetAlgorithmClass(void) = 0 ;
	virtual int __fastcall GetKeySize(void) = 0 ;
	virtual void __fastcall SetKeySize(int Value) = 0 ;
	virtual int __fastcall GetBlockSize(void) = 0 ;
	virtual void __fastcall SetBlockSize(int Value) = 0 ;
	virtual int __fastcall GetDigestSize(void) = 0 ;
	virtual void __fastcall SetDigestSize(int Value) = 0 ;
	virtual int __fastcall GetMode(void) = 0 ;
	virtual void __fastcall SetMode(int Value) = 0 ;
	virtual int __fastcall GetPadding(void) = 0 ;
	virtual void __fastcall SetPadding(int Value) = 0 ;
	
public:
	virtual Sbtypes::ByteArray __fastcall GetContextProp(const Sbtypes::ByteArray PropID, const Sbtypes::ByteArray Default = (Sbtypes::ByteArray)(0x0)) = 0 ;
	virtual void __fastcall SetContextProp(const Sbtypes::ByteArray PropID, const Sbtypes::ByteArray Value) = 0 ;
	virtual TElCustomCryptoContext* __fastcall Clone(Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0)) = 0 ;
	virtual __int64 __fastcall EstimateOutputSize(__int64 InSize) = 0 ;
	__property int Algorithm = {read=GetAlgorithm, nodefault};
	__property TElCustomCryptoProvider* CryptoProvider = {read=FProvider};
	__property int KeySize = {read=GetKeySize, write=SetKeySize, nodefault};
	__property int BlockSize = {read=GetBlockSize, write=SetBlockSize, nodefault};
	__property int DigestSize = {read=GetDigestSize, write=SetDigestSize, nodefault};
	__property int Mode = {read=GetMode, write=SetMode, nodefault};
	__property int Padding = {read=GetPadding, write=SetPadding, nodefault};
	__property int AlgorithmClass = {read=GetAlgorithmClass, nodefault};
public:
	/* TObject.Create */ inline __fastcall TElCustomCryptoContext(void) : System::TObject() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TElCustomCryptoContext(void) { }
	
};


class DELPHICLASS TElCustomCryptoProviderOptions;
class PASCALIMPLEMENTATION TElCustomCryptoProviderOptions : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	int FMaxPublicKeySize;
	bool FStoreKeys;
	virtual void __fastcall Init(void);
	
public:
	__fastcall TElCustomCryptoProviderOptions(void);
	virtual void __fastcall Assign(TElCustomCryptoProviderOptions* Options);
	__property int MaxPublicKeySize = {read=FMaxPublicKeySize, write=FMaxPublicKeySize, nodefault};
	__property bool StoreKeys = {read=FStoreKeys, write=FStoreKeys, nodefault};
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TElCustomCryptoProviderOptions(void) { }
	
};


typedef void __fastcall (__closure *TSBCryptoProviderObjectEvent)(System::TObject* Sender, System::TObject* Obj);

typedef TMetaClass* TElCustomCryptoProviderClass;

class DELPHICLASS TElCustomCryptoProviderManager;
class PASCALIMPLEMENTATION TElCustomCryptoProvider : public Classes::TComponent
{
	typedef Classes::TComponent inherited;
	
protected:
	TElCustomCryptoProviderManager* FCryptoProviderManager;
	Sbtypes::ByteArray FUniqueID;
	Sbmath::TSBMathProgressFunc FOnProgress;
	TSBCryptoProviderObjectEvent FOnCreateObject;
	TSBCryptoProviderObjectEvent FOnDestroyObject;
	TElCustomCryptoProviderOptions* FOptions;
	bool FEnabled;
	void __fastcall DoCreateObject(System::TObject* Obj);
	void __fastcall DoDestroyObject(System::TObject* Obj);
	__classmethod void __fastcall DoSetAsDefault(TElCustomCryptoProviderClass Value);
	virtual TElCustomCryptoProviderOptions* __fastcall CreateOptions(void);
	
public:
	__fastcall virtual TElCustomCryptoProvider(Classes::TComponent* AOwner)/* overload */;
	__fastcall virtual TElCustomCryptoProvider(TElCustomCryptoProviderOptions* Options, Classes::TComponent* AOwner)/* overload */;
	__fastcall virtual ~TElCustomCryptoProvider(void);
	virtual void __fastcall Init(void);
	virtual void __fastcall Deinit(void);
	__classmethod virtual void __fastcall SetAsDefault();
	virtual TElCustomCryptoProvider* __fastcall GetDefaultInstance(void);
	virtual TElCustomCryptoProvider* __fastcall Clone(void);
	virtual bool __fastcall IsAlgorithmSupported(int Algorithm, int Mode)/* overload */;
	virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, int Mode)/* overload */;
	virtual bool __fastcall IsOperationSupported(int Operation, int Algorithm, int Mode, TElCustomCryptoKey* Key, Sbrdn::TElRelativeDistinguishedName* Params)/* overload */;
	virtual bool __fastcall IsOperationSupported(int Operation, const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, int Mode, TElCustomCryptoKey* Key, Sbrdn::TElRelativeDistinguishedName* Params)/* overload */;
	virtual Sbtypes::ByteArray __fastcall GetAlgorithmProperty(int Algorithm, int Mode, const Sbtypes::ByteArray PropID)/* overload */;
	virtual Sbtypes::ByteArray __fastcall GetAlgorithmProperty(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, int Mode, const Sbtypes::ByteArray PropID)/* overload */;
	virtual int __fastcall GetAlgorithmClass(int Algorithm) = 0 /* overload */;
	virtual int __fastcall GetAlgorithmClass(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams) = 0 /* overload */;
	virtual Sbtypes::ByteArray __fastcall GetProviderProp(const Sbtypes::ByteArray PropID, const Sbtypes::ByteArray Default = (Sbtypes::ByteArray)(0x0));
	virtual void __fastcall SetProviderProp(const Sbtypes::ByteArray PropID, const Sbtypes::ByteArray Value);
	virtual TElCustomCryptoKey* __fastcall CreateKey(int Algorithm, int Mode, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0)) = 0 /* overload */;
	virtual TElCustomCryptoKey* __fastcall CreateKey(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0)) = 0 /* overload */;
	virtual TElCustomCryptoKey* __fastcall CloneKey(TElCustomCryptoKey* Key) = 0 ;
	virtual void __fastcall ReleaseKey(TElCustomCryptoKey* &Key) = 0 ;
	virtual void __fastcall DeleteKey(TElCustomCryptoKey* &Key) = 0 ;
	virtual TElCustomCryptoKey* __fastcall DecryptKey(void * EncKey, int EncKeySize, const Sbtypes::ByteArray EncKeyAlgOID, const Sbtypes::ByteArray EncKeyAlgParams, TElCustomCryptoKey* Key, const Sbtypes::ByteArray KeyAlgOID, const Sbtypes::ByteArray KeyAlgParams, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0)) = 0 ;
	virtual TElCustomCryptoKeyStorage* __fastcall CreateKeyStorage(bool Persistent, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0)) = 0 ;
	virtual void __fastcall ReleaseKeyStorage(TElCustomCryptoKeyStorage* &KeyStorage) = 0 ;
	virtual void __fastcall DeleteKeyStorage(TElCustomCryptoKeyStorage* &KeyStorage) = 0 ;
	virtual TElCustomCryptoContext* __fastcall EncryptInit(int Algorithm, int Mode, TElCustomCryptoKey* Key, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0)) = 0 /* overload */;
	virtual TElCustomCryptoContext* __fastcall EncryptInit(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, int Mode, TElCustomCryptoKey* Key, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0)) = 0 /* overload */;
	virtual TElCustomCryptoContext* __fastcall DecryptInit(int Algorithm, int Mode, TElCustomCryptoKey* Key, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0)) = 0 /* overload */;
	virtual TElCustomCryptoContext* __fastcall DecryptInit(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, int Mode, TElCustomCryptoKey* Key, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0)) = 0 /* overload */;
	virtual TElCustomCryptoContext* __fastcall SignInit(int Algorithm, TElCustomCryptoKey* Key, bool Detached, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0)) = 0 /* overload */;
	virtual TElCustomCryptoContext* __fastcall SignInit(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, TElCustomCryptoKey* Key, bool Detached, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0)) = 0 /* overload */;
	virtual TElCustomCryptoContext* __fastcall VerifyInit(int Algorithm, TElCustomCryptoKey* Key, void * SigBuffer, int SigSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0)) = 0 /* overload */;
	virtual TElCustomCryptoContext* __fastcall VerifyInit(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, TElCustomCryptoKey* Key, void * SigBuffer, int SigSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0)) = 0 /* overload */;
	virtual void __fastcall EncryptUpdate(TElCustomCryptoContext* Context, void * InBuffer, int InSize, void * OutBuffer, int &OutSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0)) = 0 ;
	virtual void __fastcall DecryptUpdate(TElCustomCryptoContext* Context, void * InBuffer, int InSize, void * OutBuffer, int &OutSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0)) = 0 ;
	virtual void __fastcall SignUpdate(TElCustomCryptoContext* Context, void * InBuffer, int InSize, void * OutBuffer, int &OutSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0)) = 0 ;
	virtual void __fastcall VerifyUpdate(TElCustomCryptoContext* Context, void * InBuffer, int InSize, void * OutBuffer, int &OutSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0)) = 0 ;
	virtual void __fastcall EncryptFinal(TElCustomCryptoContext* Context, void * Buffer, int &Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0)) = 0 ;
	virtual void __fastcall DecryptFinal(TElCustomCryptoContext* Context, void * Buffer, int &Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0)) = 0 ;
	virtual void __fastcall SignFinal(TElCustomCryptoContext* Context, void * Buffer, int &Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0)) = 0 ;
	virtual int __fastcall VerifyFinal(TElCustomCryptoContext* Context, void * Buffer, int &Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0)) = 0 ;
	virtual void __fastcall Encrypt(int Algorithm, int Mode, TElCustomCryptoKey* Key, void * InBuffer, int InSize, void * OutBuffer, int &OutSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
	virtual void __fastcall Encrypt(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, int Mode, TElCustomCryptoKey* Key, void * InBuffer, int InSize, void * OutBuffer, int &OutSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
	virtual void __fastcall Decrypt(int Algorithm, int Mode, TElCustomCryptoKey* Key, void * InBuffer, int InSize, void * OutBuffer, int &OutSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
	virtual void __fastcall Decrypt(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, int Mode, TElCustomCryptoKey* Key, void * InBuffer, int InSize, void * OutBuffer, int &OutSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
	virtual void __fastcall Sign(int Algorithm, TElCustomCryptoKey* Key, bool Detached, void * InBuffer, int InSize, void * OutBuffer, int &OutSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
	virtual void __fastcall Sign(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, TElCustomCryptoKey* Key, bool Detached, void * InBuffer, int InSize, void * OutBuffer, int &OutSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
	virtual int __fastcall Verify(int Algorithm, TElCustomCryptoKey* Key, void * InBuffer, int InSize, void * OutBuffer, int &OutSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
	virtual int __fastcall Verify(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, TElCustomCryptoKey* Key, void * InBuffer, int InSize, void * OutBuffer, int &OutSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
	virtual int __fastcall VerifyDetached(int Algorithm, TElCustomCryptoKey* Key, void * InBuffer, int InSize, void * SigBuffer, int SigSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
	virtual int __fastcall VerifyDetached(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, TElCustomCryptoKey* Key, void * InBuffer, int InSize, void * SigBuffer, int SigSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
	virtual TElCustomCryptoContext* __fastcall HashInit(int Algorithm, TElCustomCryptoKey* Key, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0)) = 0 /* overload */;
	virtual TElCustomCryptoContext* __fastcall HashInit(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, TElCustomCryptoKey* Key, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0)) = 0 /* overload */;
	virtual Sbtypes::ByteArray __fastcall HashFinal(TElCustomCryptoContext* Context, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0)) = 0 ;
	virtual void __fastcall HashUpdate(TElCustomCryptoContext* Context, void * Buffer, int Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0)) = 0 ;
	virtual Sbtypes::ByteArray __fastcall Hash(int Algorithm, TElCustomCryptoKey* Key, void * Buffer, int Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
	virtual Sbtypes::ByteArray __fastcall Hash(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, TElCustomCryptoKey* Key, void * Buffer, int Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
	virtual void __fastcall ReleaseCryptoContext(TElCustomCryptoContext* &Context) = 0 ;
	virtual void __fastcall RandomInit(void * BaseData, int BaseDataSize, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0)) = 0 ;
	virtual void __fastcall RandomSeed(void * Data, int DataSize) = 0 ;
	virtual void __fastcall RandomGenerate(void * Buffer, int Size) = 0 /* overload */;
	virtual int __fastcall RandomGenerate(int MaxValue) = 0 /* overload */;
	virtual bool __fastcall OwnsObject(System::TObject* Obj);
	__property TElCustomCryptoProviderOptions* Options = {read=FOptions};
	__property bool Enabled = {read=FEnabled, write=FEnabled, nodefault};
	__property TElCustomCryptoProviderManager* CryptoProviderManager = {read=FCryptoProviderManager, write=FCryptoProviderManager};
	__property TSBCryptoProviderObjectEvent OnCreateObject = {read=FOnCreateObject, write=FOnCreateObject};
	__property TSBCryptoProviderObjectEvent OnDestroyObject = {read=FOnDestroyObject, write=FOnDestroyObject};
};


class DELPHICLASS TElBlackboxCryptoProvider;
class PASCALIMPLEMENTATION TElBlackboxCryptoProvider : public TElCustomCryptoProvider
{
	typedef TElCustomCryptoProvider inherited;
	
public:
	/* TElCustomCryptoProvider.Create */ inline __fastcall virtual TElBlackboxCryptoProvider(Classes::TComponent* AOwner)/* overload */ : TElCustomCryptoProvider(AOwner) { }
	/* TElCustomCryptoProvider.Destroy */ inline __fastcall virtual ~TElBlackboxCryptoProvider(void) { }
	
};


class DELPHICLASS TElExternalCryptoProvider;
class PASCALIMPLEMENTATION TElExternalCryptoProvider : public TElBlackboxCryptoProvider
{
	typedef TElBlackboxCryptoProvider inherited;
	
public:
	/* TElCustomCryptoProvider.Create */ inline __fastcall virtual TElExternalCryptoProvider(Classes::TComponent* AOwner)/* overload */ : TElBlackboxCryptoProvider(AOwner) { }
	/* TElCustomCryptoProvider.Destroy */ inline __fastcall virtual ~TElExternalCryptoProvider(void) { }
	
};


class PASCALIMPLEMENTATION TElCustomCryptoProviderManager : public Classes::TComponent
{
	typedef Classes::TComponent inherited;
	
protected:
	Classes::TList* FProviders;
	Sbsharedresource::TElSharedResource* FLock;
	TElCustomCryptoProvider* FDefaultProvider;
	TElCustomCryptoProvider* __fastcall GetDefaultCryptoProvider(void);
	TElCustomCryptoProvider* __fastcall GetCryptoProvider(int Index);
	int __fastcall GetCount(void);
	virtual void __fastcall Notification(Classes::TComponent* AComponent, Classes::TOperation AOperation);
	
public:
	__fastcall virtual TElCustomCryptoProviderManager(Classes::TComponent* AOwner);
	__fastcall virtual ~TElCustomCryptoProviderManager(void);
	virtual void __fastcall Init(void);
	virtual void __fastcall Deinit(void);
	int __fastcall RegisterCryptoProvider(TElCustomCryptoProvider* Prov);
	void __fastcall UnregisterCryptoProvider(TElCustomCryptoProvider* Prov)/* overload */;
	void __fastcall UnregisterCryptoProvider(int Index)/* overload */;
	void __fastcall SetDefaultCryptoProvider(TElCustomCryptoProvider* Prov)/* overload */;
	void __fastcall SetDefaultCryptoProvider(int Index)/* overload */;
	void __fastcall SetDefaultCryptoProviderType(TElCustomCryptoProviderClass Value);
	TElCustomCryptoProvider* __fastcall GetSuitableProvider(int Operation, int Algorithm, int Mode, TElCustomCryptoKey* Key, Sbrdn::TElRelativeDistinguishedName* Params)/* overload */;
	TElCustomCryptoProvider* __fastcall GetSuitableProvider(int Operation, const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, int Mode, TElCustomCryptoKey* Key, Sbrdn::TElRelativeDistinguishedName* Params)/* overload */;
	TElCustomCryptoProvider* __fastcall GetSuitableProvider(int Algorithm, int Mode)/* overload */;
	TElCustomCryptoProvider* __fastcall GetSuitableProvider(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, int Mode)/* overload */;
	bool __fastcall IsOperationSupported(int Operation, int Algorithm, int Mode, TElCustomCryptoKey* Key, Sbrdn::TElRelativeDistinguishedName* Params)/* overload */;
	bool __fastcall IsOperationSupported(int Operation, const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, int Mode, TElCustomCryptoKey* Key, Sbrdn::TElRelativeDistinguishedName* Params)/* overload */;
	bool __fastcall IsAlgorithmSupported(int Algorithm, int Mode)/* overload */;
	bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, int Mode)/* overload */;
	virtual bool __fastcall IsProviderAllowed(TElCustomCryptoProvider* Prov);
	Sbtypes::ByteArray __fastcall GetAlgorithmProperty(int Algorithm, int Mode, const Sbtypes::ByteArray PropID)/* overload */;
	Sbtypes::ByteArray __fastcall GetAlgorithmProperty(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, int Mode, const Sbtypes::ByteArray PropID)/* overload */;
	int __fastcall GetAlgorithmClass(int Algorithm)/* overload */;
	int __fastcall GetAlgorithmClass(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams)/* overload */;
	__property TElCustomCryptoProvider* CryptoProviders[int Index] = {read=GetCryptoProvider};
	__property int Count = {read=GetCount, nodefault};
	__property TElCustomCryptoProvider* DefaultCryptoProvider = {read=GetDefaultCryptoProvider};
};


class DELPHICLASS EElCryptoProviderError;
class PASCALIMPLEMENTATION EElCryptoProviderError : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElCryptoProviderError(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElCryptoProviderError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElCryptoProviderError(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElCryptoProviderError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElCryptoProviderError(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElCryptoProviderError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElCryptoProviderError(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElCryptoProviderError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElCryptoProviderError(void) { }
	
};


class DELPHICLASS EElCryptoKeyError;
class PASCALIMPLEMENTATION EElCryptoKeyError : public EElCryptoProviderError
{
	typedef EElCryptoProviderError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElCryptoKeyError(const System::UnicodeString AMessage)/* overload */ : EElCryptoProviderError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElCryptoKeyError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : EElCryptoProviderError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElCryptoKeyError(int Ident)/* overload */ : EElCryptoProviderError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElCryptoKeyError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : EElCryptoProviderError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElCryptoKeyError(const System::UnicodeString Msg, int AHelpContext) : EElCryptoProviderError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElCryptoKeyError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : EElCryptoProviderError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElCryptoKeyError(int Ident, int AHelpContext)/* overload */ : EElCryptoProviderError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElCryptoKeyError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : EElCryptoProviderError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElCryptoKeyError(void) { }
	
};


class DELPHICLASS EElCryptoProviderManagerError;
class PASCALIMPLEMENTATION EElCryptoProviderManagerError : public EElCryptoProviderError
{
	typedef EElCryptoProviderError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElCryptoProviderManagerError(const System::UnicodeString AMessage)/* overload */ : EElCryptoProviderError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElCryptoProviderManagerError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : EElCryptoProviderError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElCryptoProviderManagerError(int Ident)/* overload */ : EElCryptoProviderError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElCryptoProviderManagerError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : EElCryptoProviderError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElCryptoProviderManagerError(const System::UnicodeString Msg, int AHelpContext) : EElCryptoProviderError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElCryptoProviderManagerError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : EElCryptoProviderError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElCryptoProviderManagerError(int Ident, int AHelpContext)/* overload */ : EElCryptoProviderError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElCryptoProviderManagerError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : EElCryptoProviderError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElCryptoProviderManagerError(void) { }
	
};


class DELPHICLASS EElCryptoProviderInvalidSignatureError;
class PASCALIMPLEMENTATION EElCryptoProviderInvalidSignatureError : public EElCryptoProviderError
{
	typedef EElCryptoProviderError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElCryptoProviderInvalidSignatureError(const System::UnicodeString AMessage)/* overload */ : EElCryptoProviderError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElCryptoProviderInvalidSignatureError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : EElCryptoProviderError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElCryptoProviderInvalidSignatureError(int Ident)/* overload */ : EElCryptoProviderError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElCryptoProviderInvalidSignatureError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : EElCryptoProviderError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElCryptoProviderInvalidSignatureError(const System::UnicodeString Msg, int AHelpContext) : EElCryptoProviderError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElCryptoProviderInvalidSignatureError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : EElCryptoProviderError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElCryptoProviderInvalidSignatureError(int Ident, int AHelpContext)/* overload */ : EElCryptoProviderError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElCryptoProviderInvalidSignatureError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : EElCryptoProviderError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElCryptoProviderInvalidSignatureError(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
static const ShortInt SB_ALGCLASS_NONE = 0x0;
static const ShortInt SB_ALGCLASS_BLOCK = 0x1;
static const ShortInt SB_ALGCLASS_STREAM = 0x2;
static const ShortInt SB_ALGCLASS_PUBLICKEY = 0x3;
static const ShortInt SB_ALGCLASS_HASH = 0x4;
static const ShortInt SB_SYMENC_MODE_DEFAULT = 0x0;
static const ShortInt SB_SYMENC_MODE_BLOCK = 0x1;
static const ShortInt SB_SYMENC_MODE_CBC = 0x2;
static const ShortInt SB_SYMENC_MODE_CFB8 = 0x3;
static const ShortInt SB_SYMENC_MODE_CTR = 0x4;
static const ShortInt SB_SYMENC_MODE_ECB = 0x5;
static const ShortInt SB_SYMENC_MODE_CCM = 0x6;
static const ShortInt SB_SYMENC_MODE_GCM = 0x7;
static const ShortInt SB_SYMENC_PADDING_NONE = 0x0;
static const ShortInt SB_SYMENC_PADDING_PKCS5 = 0x1;
static const ShortInt SB_VR_SUCCESS = 0x0;
static const ShortInt SB_VR_INVALID_SIGNATURE = 0x1;
static const ShortInt SB_VR_KEY_NOT_FOUND = 0x2;
static const ShortInt SB_VR_FAILURE = 0x3;
static const ShortInt SB_OPTYPE_NONE = 0x0;
static const ShortInt SB_OPTYPE_ENCRYPT = 0x1;
static const ShortInt SB_OPTYPE_DECRYPT = 0x2;
static const ShortInt SB_OPTYPE_SIGN = 0x3;
static const ShortInt SB_OPTYPE_SIGN_DETACHED = 0x4;
static const ShortInt SB_OPTYPE_VERIFY = 0x5;
static const ShortInt SB_OPTYPE_VERIFY_DETACHED = 0x6;
static const ShortInt SB_OPTYPE_HASH = 0x7;
static const ShortInt SB_OPTYPE_KEY_GENERATE = 0x8;
static const ShortInt SB_OPTYPE_KEY_DECRYPT = 0x9;
static const ShortInt SB_OPTYPE_RANDOM = 0xa;
static const ShortInt SB_OPTYPE_KEY_CREATE = 0xb;
static const ShortInt SB_OPTYPE_KEYSTORAGE_CREATE = 0xc;
static const int ERROR_FACILITY_CRYPTOPROV = 0x15000;
static const Word ERROR_CRYPTOPROV_ERROR_FLAG = 0x800;
static const int ERROR_CP_NOT_INITIALIZED = 88065;
static const int ERROR_CP_FEATURE_NOT_SUPPORTED = 88066;
static const int ERROR_CP_INVALID_KEY_SIZE = 88069;
static const int ERROR_CP_INVALID_IV_SIZE = 88070;
static const int ERROR_CP_BUFFER_TOO_SMALL = 88071;
static const ShortInt SB_CRYPTOPROV_GENERAL_ERROR = 0x1;
extern PACKAGE Sbtypes::ByteArray SB_PROVPROP_DLL_PATH;
extern PACKAGE Sbtypes::ByteArray SB_PROVPROP_SESSION_HANDLE;
extern PACKAGE Sbtypes::ByteArray SB_PROVPROP_WINDOW_HANDLE;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_KEYFORMAT;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_HASH_ALGORITHM;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_MGF_ALGORITHM;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_TRAILER_FIELD;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_SALT_SIZE;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_STRLABEL;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_RSA_M;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_RSA_E;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_RSA_D;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_DSA_STRICT_VALIDATION;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_RSA_RAWKEY;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_DSA_P;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_DSA_Q;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_DSA_G;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_DSA_X;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_DSA_Y;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_DSA_QBITS;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_ELGAMAL_P;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_ELGAMAL_G;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_ELGAMAL_X;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_ELGAMAL_Y;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_DH_P;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_DH_G;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_DH_X;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_DH_Y;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_DH_PEER_Y;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_WIN32_CERTCONTEXT;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_WIN32_CONTAINERNAME;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_WIN32_PROVIDERNAME;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_WIN32_KEYPROVINFO;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_WIN32_KEYEXCHANGEPIN;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_WIN32_SIGNATUREPIN;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EFFECTIVE_KEY_LENGTH;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_PKCS11_KEY_HANDLE;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_PKCS11_SESSION_HANDLE;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_PKCS11_PUBKEY_HANDLE;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_PKCS11_PERSISTENT;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_PKCS11_LABEL;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_PKCS11_SUBJECT;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_PKCS11_ID;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_PKCS11_SENSITIVE;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_PKCS11_PRIVATE;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_PKCS11_CREATE_PUBLIC;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_PKCS11_ADD_PRIVATE_FLAG;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_PKCS11_FORCE_OBJECT_CREATION;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_CURVE;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_CURVE_INT;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_FIELD_TYPE;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_FIELD_TYPE_INT;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_FIELD_BITS;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_SUBGROUP_BITS;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_FIELD;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_FIELD_INT;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_P;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_M;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_K1;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_K2;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_K3;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_A;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_B;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_N;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_H;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_SEED;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_X;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_Y;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_BP;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_D;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_QX;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_QY;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_Q;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_COMPRESS_POINTS;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_EC_HYBRID_POINTS;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_GOST_R3410_1994_T;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_GOST_R3410_1994_P;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_GOST_R3410_1994_Q;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_GOST_R3410_1994_A;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_GOST_R3410_1994_X0;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_GOST_R3410_1994_C;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_GOST_R3410_1994_D;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_GOST_R3410_1994_X;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_GOST_R3410_1994_Y;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_GOST_R3410_PARAMSET;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_GOST_R3410_DIGEST_PARAMSET;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_GOST_R3410_ENCRYPTION_PARAMSET;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_ENVELOPE_VALUE;
extern PACKAGE Sbtypes::ByteArray SB_KEYPROP_SBB_KEYID_BLOB;
extern PACKAGE Sbtypes::ByteArray SB_ALGPROP_DIGEST_SIZE;
extern PACKAGE Sbtypes::ByteArray SB_ALGPROP_BLOCK_SIZE;
extern PACKAGE Sbtypes::ByteArray SB_ALGPROP_DEFAULT_KEY_SIZE;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_SKIP_KEYSTREAM_BYTES;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_USE_ALGORITHM_PREFIX;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_HASH_ALGORITHM;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_INPUT_IS_HASH;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_HASH_FUNC_OID;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_ALGORITHM_SCHEME;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_SALT_SIZE;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_STR_LABEL;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_TRAILER_FIELD;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_MGF_ALGORITHM;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_PADDING_TYPE;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_GOSTR3411_1994_PARAMSET;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_GOSTR3411_1994_PARAMETERS;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_GOST28147_1989_PARAMSET;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_GOST28147_1989_PARAMETERS;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_GOST28147_1989_USE_KEY_MESHING;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_GOST3410_UKM;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_GOST3410_EPHEMERAL_KEY;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_GOST3410_CEK_MAC;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_AEAD_NONCE;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_AEAD_TAG_SIZE;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_AEAD_ASSOCIATED_DATA;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_CCM_ASSOCIATED_DATA_SIZE;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_CCM_PAYLOAD_SIZE;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_CTR_LITTLE_ENDIAN;
extern PACKAGE Sbtypes::ByteArray SB_CTXPROP_EC_PLAIN_ECDSA;

}	/* namespace Sbcryptoprov */
using namespace Sbcryptoprov;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbcryptoprovHPP
