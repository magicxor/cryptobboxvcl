// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbcryptoprovwin32.pas' rev: 21.00

#ifndef Sbcryptoprovwin32HPP
#define Sbcryptoprovwin32HPP

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
#include <Sbcryptoprovutils.hpp>	// Pascal unit
#include <Sbcryptoprovrs.hpp>	// Pascal unit
#include <Sbsharedresource.hpp>	// Pascal unit
#include <Sbmskeyblob.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit
#include <Sbrsa.hpp>	// Pascal unit
#include <Sbdsa.hpp>	// Pascal unit
#include <Sbwincrypt.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbrandom.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbrdn.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbcryptoprovwin32
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElWin32CryptoProviderOptions;
class PASCALIMPLEMENTATION TElWin32CryptoProviderOptions : public Sbcryptoprov::TElCustomCryptoProviderOptions
{
	typedef Sbcryptoprov::TElCustomCryptoProviderOptions inherited;
	
protected:
	bool FUseForPublicKeyOperations;
	bool FUseForSymmetricKeyOperations;
	bool FUseForHashingOperations;
	bool FUseForNonPrivateOperations;
	bool FThreadSafe;
	bool FUseBaseCSP;
	bool FUseStrongCSP;
	bool FUseEnhancedCSP;
	bool FUseAESCSP;
	bool FUseDSSCSP;
	bool FUseBaseDSSDHCSP;
	bool FUseEnhancedDSSDHCSP;
	bool FUseRSASchannelCSP;
	bool FUseRSASignatureCSP;
	bool FUseECDSASigCSP;
	bool FUseECNRASigCSP;
	bool FUseECDSAFullCSP;
	bool FUseECNRAFullCSP;
	bool FUseDHSchannelCSP;
	bool FUseCPGOST;
	bool FFIPSMode;
	bool FCacheKeyContexts;
	bool FStorePublicKeysInMemoryContainers;
	bool FForceEnhancedCSPForLongKeys;
	bool FAutoSelectEnhancedCSP;
	bool FTryAlternativeKeySpecOnFailure;
	bool FGenerateExportablePrivateKeys;
	bool FUseLocalMachineAccount;
	virtual void __fastcall Init(void);
	
public:
	virtual void __fastcall Assign(Sbcryptoprov::TElCustomCryptoProviderOptions* Options);
	__property bool UseForPublicKeyOperations = {read=FUseForPublicKeyOperations, write=FUseForPublicKeyOperations, nodefault};
	__property bool UseForSymmetricKeyOperations = {read=FUseForSymmetricKeyOperations, write=FUseForSymmetricKeyOperations, nodefault};
	__property bool UseForHashingOperations = {read=FUseForHashingOperations, write=FUseForHashingOperations, nodefault};
	__property bool UseForNonPrivateOperations = {read=FUseForNonPrivateOperations, write=FUseForNonPrivateOperations, nodefault};
	__property bool ThreadSafe = {read=FThreadSafe, write=FThreadSafe, nodefault};
	__property bool UseBaseCSP = {read=FUseBaseCSP, write=FUseBaseCSP, nodefault};
	__property bool UseStrongCSP = {read=FUseStrongCSP, write=FUseStrongCSP, nodefault};
	__property bool UseEnhancedCSP = {read=FUseEnhancedCSP, write=FUseEnhancedCSP, nodefault};
	__property bool UseAESCSP = {read=FUseAESCSP, write=FUseAESCSP, nodefault};
	__property bool UseDSSCSP = {read=FUseDSSCSP, write=FUseDSSCSP, nodefault};
	__property bool UseBaseDSSDHCSP = {read=FUseBaseDSSDHCSP, write=FUseBaseDSSDHCSP, nodefault};
	__property bool UseEnhancedDSSDHCSP = {read=FUseEnhancedDSSDHCSP, write=FUseEnhancedDSSDHCSP, nodefault};
	__property bool UseRSASchannelCSP = {read=FUseRSASchannelCSP, write=FUseRSASchannelCSP, nodefault};
	__property bool UseRSASignatureCSP = {read=FUseRSASignatureCSP, write=FUseRSASignatureCSP, nodefault};
	__property bool UseECDSASigCSP = {read=FUseECDSASigCSP, write=FUseECDSASigCSP, nodefault};
	__property bool UseECNRASigCSP = {read=FUseECNRASigCSP, write=FUseECNRASigCSP, nodefault};
	__property bool UseECDSAFullCSP = {read=FUseECDSAFullCSP, write=FUseECDSAFullCSP, nodefault};
	__property bool UseECNRAFullCSP = {read=FUseECNRAFullCSP, write=FUseECNRAFullCSP, nodefault};
	__property bool UseDHSchannelCSP = {read=FUseDHSchannelCSP, write=FUseDHSchannelCSP, nodefault};
	__property bool UseCPGOST = {read=FUseCPGOST, write=FUseCPGOST, nodefault};
	__property bool FIPSMode = {read=FFIPSMode, write=FFIPSMode, nodefault};
	__property bool CacheKeyContexts = {read=FCacheKeyContexts, write=FCacheKeyContexts, nodefault};
	__property bool StorePublicKeysInMemoryContainers = {read=FStorePublicKeysInMemoryContainers, write=FStorePublicKeysInMemoryContainers, nodefault};
	__property bool ForceEnhancedCSPForLongKeys = {read=FForceEnhancedCSPForLongKeys, write=FForceEnhancedCSPForLongKeys, nodefault};
	__property bool AutoSelectEnhancedCSP = {read=FAutoSelectEnhancedCSP, write=FAutoSelectEnhancedCSP, nodefault};
	__property bool TryAlternativeKeySpecOnFailure = {read=FTryAlternativeKeySpecOnFailure, write=FTryAlternativeKeySpecOnFailure, nodefault};
	__property bool GenerateExportablePrivateKeys = {read=FGenerateExportablePrivateKeys, write=FGenerateExportablePrivateKeys, nodefault};
	__property bool UseLocalMachineAccount = {read=FUseLocalMachineAccount, write=FUseLocalMachineAccount, nodefault};
public:
	/* TElCustomCryptoProviderOptions.Create */ inline __fastcall TElWin32CryptoProviderOptions(void) : Sbcryptoprov::TElCustomCryptoProviderOptions() { }
	
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TElWin32CryptoProviderOptions(void) { }
	
};


class DELPHICLASS TElWin32CryptoProvider;
class PASCALIMPLEMENTATION TElWin32CryptoProvider : public Sbcryptoprov::TElExternalCryptoProvider
{
	typedef Sbcryptoprov::TElExternalCryptoProvider inherited;
	
protected:
	Classes::TList* FKeys;
	Classes::TList* FContexts;
	Sbsharedresource::TElSharedResource* FLock;
	bool FTryEnhancedCryptoProvider;
	bool FNativeSizeCalculation;
	HWND FWindowHandle;
	Classes::TList* FProviderInfos;
	System::UnicodeString FLastSigningError;
	unsigned FLastSigningErrorCode;
	bool __fastcall AddProviderInfo(unsigned Handle, const System::UnicodeString Name, bool FIPSCompliant);
	void __fastcall RefreshProviderInfos(void);
	void __fastcall ClearProviderInfos(void);
	void __fastcall ClearKeys(void);
	void __fastcall ClearContexts(void);
	Sbcryptoprov::TElCustomCryptoKey* __fastcall InternalCreateKey(const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0));
	bool __fastcall TrySignHash(Sbcryptoprov::TElCustomCryptoContext* Context, unsigned Hash, unsigned KeySpec, void * OutBuf, int &OutBufSize);
	bool __fastcall DecryptPKI(Sbcryptoprov::TElCustomCryptoContext* Context, void * Buffer, int Size, void * OutBuffer, int &OutSize);
	bool __fastcall DecryptPKIOAEP(Sbcryptoprov::TElCustomCryptoContext* Context, void * Buffer, int Size, void * OutBuffer, int &OutSize);
	bool __fastcall SignPKI(Sbcryptoprov::TElCustomCryptoContext* Context, void * Buffer, int Size, void * OutBuffer, int &OutSize);
	bool __fastcall SignPKIPSS(Sbcryptoprov::TElCustomCryptoContext* Context, void * Buffer, int Size, void * OutBuffer, int &OutSize);
	int __fastcall VerifyPKI(Sbcryptoprov::TElCustomCryptoContext* Context, void * HashBuffer, int HashSize, void * SigBuffer, int SigSize);
	Sbtypes::ByteArray __fastcall TryDecodeASN1EncodedHash(void * HashBuffer, int HashSize, int &DefHashAlgorithm);
	Sbcryptoprov::TElCustomCryptoProviderManager* __fastcall ReturnCryptoProviderManager(void);
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
	virtual Sbtypes::ByteArray __fastcall GetProviderProp(const Sbtypes::ByteArray PropID, const Sbtypes::ByteArray Default = (Sbtypes::ByteArray)(0x0));
	virtual void __fastcall SetProviderProp(const Sbtypes::ByteArray PropID, const Sbtypes::ByteArray Value);
	__property bool TryEnhancedCryptoProvider = {read=FTryEnhancedCryptoProvider, write=FTryEnhancedCryptoProvider, nodefault};
	__property bool NativeSizeCalculation = {read=FNativeSizeCalculation, write=FNativeSizeCalculation, nodefault};
public:
	/* TElCustomCryptoProvider.Create */ inline __fastcall virtual TElWin32CryptoProvider(Classes::TComponent* AOwner)/* overload */ : Sbcryptoprov::TElExternalCryptoProvider(AOwner) { }
	/* TElCustomCryptoProvider.Destroy */ inline __fastcall virtual ~TElWin32CryptoProvider(void) { }
	
};


class DELPHICLASS EElWin32CryptoProviderError;
class PASCALIMPLEMENTATION EElWin32CryptoProviderError : public Sbcryptoprov::EElCryptoProviderError
{
	typedef Sbcryptoprov::EElCryptoProviderError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElWin32CryptoProviderError(const System::UnicodeString AMessage)/* overload */ : Sbcryptoprov::EElCryptoProviderError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElWin32CryptoProviderError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbcryptoprov::EElCryptoProviderError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElWin32CryptoProviderError(int Ident)/* overload */ : Sbcryptoprov::EElCryptoProviderError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElWin32CryptoProviderError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbcryptoprov::EElCryptoProviderError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElWin32CryptoProviderError(const System::UnicodeString Msg, int AHelpContext) : Sbcryptoprov::EElCryptoProviderError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElWin32CryptoProviderError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbcryptoprov::EElCryptoProviderError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElWin32CryptoProviderError(int Ident, int AHelpContext)/* overload */ : Sbcryptoprov::EElCryptoProviderError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElWin32CryptoProviderError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbcryptoprov::EElCryptoProviderError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElWin32CryptoProviderError(void) { }
	
};


class DELPHICLASS TElCNGCryptoProviderHandleInfo;
class PASCALIMPLEMENTATION TElCNGCryptoProviderHandleInfo : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	unsigned *FHandle;
	int FRefCount;
	
public:
	__fastcall TElCNGCryptoProviderHandleInfo(Sbwincrypt::ULONG_PTR Handle);
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TElCNGCryptoProviderHandleInfo(void) { }
	
};


class DELPHICLASS TElCNGCryptoProviderHandleManager;
class PASCALIMPLEMENTATION TElCNGCryptoProviderHandleManager : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	Classes::TList* FList;
	Sbsharedresource::TElSharedResource* FCS;
	
public:
	__fastcall TElCNGCryptoProviderHandleManager(void);
	__fastcall virtual ~TElCNGCryptoProviderHandleManager(void);
	unsigned __fastcall OpenCNGStorageProvider(unsigned &phProvider, System::WideChar * pszProviderName, unsigned dwFlags)/* overload */;
	unsigned __fastcall OpenCNGStorageProvider(Sbwincrypt::ULONG_PTR &phProvider, System::WideChar * pszProviderName, unsigned dwFlags)/* overload */;
	void __fastcall FreeCNGStorageProvider(unsigned hProvider);
	void __fastcall CNGStorageProviderAddRef(unsigned hProvider);
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE Sbcryptoprov::TElCustomCryptoProvider* __fastcall Win32CryptoProvider(void)/* overload */;
extern PACKAGE Sbcryptoprov::TElCustomCryptoProvider* __fastcall Win32CryptoProvider(TElWin32CryptoProviderOptions* OptionsTemplate)/* overload */;

}	/* namespace Sbcryptoprovwin32 */
using namespace Sbcryptoprovwin32;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// Sbcryptoprovwin32HPP
