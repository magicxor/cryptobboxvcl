// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbsymmetriccrypto.pas' rev: 21.00

#ifndef SbsymmetriccryptoHPP
#define SbsymmetriccryptoHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbcustomcrypto.hpp>	// Pascal unit
#include <Windows.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbwincrypt.hpp>	// Pascal unit
#include <Sbsha2.hpp>	// Pascal unit
#include <Sbcryptoprov.hpp>	// Pascal unit
#include <Sbcryptoprovmanager.hpp>	// Pascal unit
#include <Sbcryptoprovutils.hpp>	// Pascal unit
#include <Sbcryptoprovrs.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbrandom.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbsymmetriccrypto
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElSymmetricKeyMaterial;
class PASCALIMPLEMENTATION TElSymmetricKeyMaterial : public Sbcustomcrypto::TElKeyMaterial
{
	typedef Sbcustomcrypto::TElKeyMaterial inherited;
	
private:
	unsigned FWin32Handle;
	unsigned FWin32Prov;
	Sbcryptoprov::TElCustomCryptoProvider* FProvider;
	Sbcryptoprov::TElCustomCryptoProviderManager* FProviderManager;
	void __fastcall SetKey(const Sbtypes::ByteArray Value);
	void __fastcall SetIV(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetKey(void);
	Sbtypes::ByteArray __fastcall GetIV(void);
	
protected:
	void __fastcall Reset(void);
	virtual int __fastcall GetBits(void);
	virtual int __fastcall GetAlgorithm(void);
	virtual bool __fastcall GetValid(void);
	void __fastcall SetAlgorithm(int Value);
	
public:
	__fastcall virtual TElSymmetricKeyMaterial(Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual TElSymmetricKeyMaterial(Sbcryptoprov::TElCustomCryptoKey* Key, Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual TElSymmetricKeyMaterial(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual TElSymmetricKeyMaterial(Sbcryptoprov::TElCustomCryptoKey* Key, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual ~TElSymmetricKeyMaterial(void);
	virtual void __fastcall Generate(int Bits);
	virtual void __fastcall GenerateIV(int Bits);
	void __fastcall DeriveKey(int Bits, const System::UnicodeString Password)/* overload */;
	void __fastcall DeriveKey(int Bits, const System::UnicodeString Password, const System::UnicodeString Salt)/* overload */;
	void __fastcall DeriveKey(int Bits, const System::UnicodeString Password, const Sbtypes::ByteArray Salt)/* overload */;
	void __fastcall DeriveKey(int Bits, const System::UnicodeString Password, const Sbtypes::ByteArray Salt, int Iterations)/* overload */;
	HIDESBASE virtual void __fastcall Load(void * Buffer, int &Size)/* overload */;
	HIDESBASE virtual void __fastcall Save(void * Buffer, int &Size)/* overload */;
	virtual void __fastcall Load(Classes::TStream* Stream, int Count = 0x0)/* overload */;
	virtual void __fastcall Save(Classes::TStream* Stream)/* overload */;
	bool __fastcall ImportEncryptedSymmetricKeyWin32(const Sbtypes::ByteArray EncryptedKey, int SymAlgorithm, int PKAlgorithm, const Sbtypes::ByteArray SymAlgParams, unsigned hProv, unsigned hUserKey);
	virtual void __fastcall Persistentiate(void);
	__property Sbtypes::ByteArray Key = {read=GetKey, write=SetKey};
	__property Sbtypes::ByteArray IV = {read=GetIV, write=SetIV};
	__property int Algorithm = {read=GetAlgorithm, write=SetAlgorithm, nodefault};
};

typedef TElSymmetricKeyMaterial ElSymmetricKeyMaterial
#pragma option push -b-
enum TSBSymmetricCryptoMode { cmDefault, cmECB, cmCBC, cmCTR, cmCFB8, cmGCM, cmCCM };
#pragma option pop

#pragma option push -b-
enum TSBSymmetricCipherPadding { cpNone, cpPKCS5 };
#pragma option pop

class DELPHICLASS TElSymmetricCrypto;
class PASCALIMPLEMENTATION TElSymmetricCrypto : public Sbcustomcrypto::TElCustomCrypto
{
	typedef Sbcustomcrypto::TElCustomCrypto inherited;
	
private:
	TElSymmetricKeyMaterial* FKeyMaterial;
	Sbutils::TSBProgressEvent FOnProgress;
	Sbcryptoprov::TElCustomCryptoProvider* FCryptoProvider;
	Sbcryptoprov::TElCustomCryptoProviderManager* FCryptoProviderManager;
	int FAlgID;
	Sbtypes::ByteArray FAlgOID;
	TSBSymmetricCryptoMode FMode;
	Sbcryptoprov::TElCustomCryptoContext* FContext;
	TSBSymmetricCipherPadding FPadding;
	bool FCTRLittleEndian;
	Sbtypes::ByteArray FNonce;
	int FTagSize;
	int FAssociatedDataSize;
	int FPayloadSize;
	TSBSymmetricCryptoMode __fastcall GetMode(void);
	int __fastcall GetBlockSize(void);
	int __fastcall GetKeySize(void);
	TSBSymmetricCipherPadding __fastcall GetPadding(void);
	void __fastcall SetPadding(TSBSymmetricCipherPadding Value);
	bool __fastcall GetCTRLittleEndian(void);
	void __fastcall SetCTRLittleEndian(bool Value);
	Sbtypes::ByteArray __fastcall GetNonce(void);
	void __fastcall SetNonce(const Sbtypes::ByteArray Value);
	int __fastcall GetTagSize(void);
	void __fastcall SetTagSize(int Value);
	int __fastcall GetAssociatedDataSize(void);
	void __fastcall SetAssociatedDataSize(int Value);
	int __fastcall GetPayloadSize(void);
	void __fastcall SetPayloadSize(int Value);
	bool __fastcall GetAssociatedData(void);
	void __fastcall SetAssociatedData(bool Value);
	
protected:
	bool __fastcall DoProgress(__int64 Total, __int64 Current);
	virtual void __fastcall SetKeyMaterial(TElSymmetricKeyMaterial* Material);
	virtual bool __fastcall GetNetIsStreamCipher(void);
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int AlgID, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider = (Sbcryptoprov::TElCustomCryptoProvider*)(0x0))/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray AlgOID, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider = (Sbcryptoprov::TElCustomCryptoProvider*)(0x0))/* overload */;
	__classmethod virtual void __fastcall GetDefaultKeyAndBlockLengths(int AlgID, int &KeyLen, int &BlockLen, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider = (Sbcryptoprov::TElCustomCryptoProvider*)(0x0))/* overload */;
	__classmethod virtual void __fastcall GetDefaultKeyAndBlockLengths(const Sbtypes::ByteArray OID, int &KeyLen, int &BlockLen, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider = (Sbcryptoprov::TElCustomCryptoProvider*)(0x0))/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int AlgID, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray AlgOID, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__classmethod virtual void __fastcall GetDefaultKeyAndBlockLengths(int AlgID, int &KeyLen, int &BlockLen, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__classmethod virtual void __fastcall GetDefaultKeyAndBlockLengths(const Sbtypes::ByteArray OID, int &KeyLen, int &BlockLen, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	int __fastcall EstimatedOutputSize(int InputSize, bool Encrypt);
	virtual void __fastcall Init(void);
	virtual Sbcryptoprov::TElCustomCryptoProvider* __fastcall GetSuitableCryptoProvider(void);
	
public:
	__fastcall virtual TElSymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElSymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElSymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElSymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElSymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElSymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual ~TElSymmetricCrypto(void);
	virtual void __fastcall InitializeEncryption(void);
	virtual void __fastcall InitializeDecryption(void);
	void __fastcall Encrypt(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	void __fastcall Encrypt(Classes::TStream* InStream, Classes::TStream* OutStream)/* overload */;
	void __fastcall EncryptUpdate(void * InBuffer, int InSize, void * OutBuffer, int &OutSize);
	virtual void __fastcall FinalizeEncryption(void * OutBuffer, int &OutSize);
	virtual void __fastcall EncryptAEAD(void * AssociatedData, int ADataSize, void * InBuffer, int InSize, void * OutBuffer, int &OutSize);
	void __fastcall Decrypt(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	virtual void __fastcall DecryptAEAD(void * AssociatedData, int ADataSize, void * InBuffer, int InSize, void * OutBuffer, int &OutSize);
	void __fastcall Decrypt(Classes::TStream* InStream, Classes::TStream* OutStream, int InCount = 0x0)/* overload */;
	void __fastcall DecryptUpdate(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	void __fastcall DecryptUpdateWin32(void * InBuffer, int InSize, void * OutBuffer, int &OutSize);
	virtual void __fastcall FinalizeDecryption(void * OutBuffer, int &OutSize);
	__classmethod Sbtypes::ByteArray __fastcall Decrypt(int AlgID, const Sbtypes::ByteArray Key, const Sbtypes::ByteArray IV, TSBSymmetricCryptoMode Mode, void * Buffer, int Size)/* overload */;
	__classmethod Sbtypes::ByteArray __fastcall Encrypt(int AlgID, const Sbtypes::ByteArray Key, const Sbtypes::ByteArray IV, TSBSymmetricCryptoMode Mode, void * Buffer, int Size)/* overload */;
	__property int AlgID = {read=FAlgID, nodefault};
	__property TElSymmetricKeyMaterial* KeyMaterial = {read=FKeyMaterial, write=SetKeyMaterial};
	__property TSBSymmetricCryptoMode Mode = {read=GetMode, nodefault};
	__property int BlockSize = {read=GetBlockSize, nodefault};
	__property int KeySize = {read=GetKeySize, nodefault};
	__property TSBSymmetricCipherPadding Padding = {read=GetPadding, write=SetPadding, nodefault};
	__property bool CTRLittleEndian = {read=GetCTRLittleEndian, write=SetCTRLittleEndian, nodefault};
	__property Sbtypes::ByteArray Nonce = {read=GetNonce, write=SetNonce};
	__property int TagSize = {read=GetTagSize, write=SetTagSize, nodefault};
	__property int AssociatedDataSize = {read=GetAssociatedDataSize, write=SetAssociatedDataSize, nodefault};
	__property int PayloadSize = {read=GetPayloadSize, write=SetPayloadSize, nodefault};
	__property bool AssociatedData = {read=GetAssociatedData, write=SetAssociatedData, nodefault};
	__property bool IsStreamCipher = {read=GetNetIsStreamCipher, nodefault};
	__property Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider = {read=FCryptoProvider, write=FCryptoProvider};
	__property Sbcryptoprov::TElCustomCryptoProviderManager* CryptoProviderManager = {read=FCryptoProviderManager, write=FCryptoProviderManager};
	__property Sbutils::TSBProgressEvent OnProgress = {read=FOnProgress, write=FOnProgress};
};

typedef TElSymmetricCrypto ElSymmetricCrypto
typedef TMetaClass* TElSymmetricCryptoClass;

typedef TElSymmetricCryptoClass ElSymmetricCryptoClass;

class DELPHICLASS TElSymmetricCryptoFactory;
class PASCALIMPLEMENTATION TElSymmetricCryptoFactory : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	Sbcryptoprov::TElCustomCryptoProvider* FCryptoProvider;
	Sbcryptoprov::TElCustomCryptoProviderManager* FCryptoProviderManager;
	
public:
	__fastcall TElSymmetricCryptoFactory(void);
	__fastcall virtual ~TElSymmetricCryptoFactory(void);
	TElSymmetricCrypto* __fastcall CreateInstance(const Sbtypes::ByteArray OID, TSBSymmetricCryptoMode Mode = (TSBSymmetricCryptoMode)(0x0))/* overload */;
	TElSymmetricCrypto* __fastcall CreateInstance(int Alg, TSBSymmetricCryptoMode Mode = (TSBSymmetricCryptoMode)(0x0))/* overload */;
	bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	bool __fastcall GetDefaultKeyAndBlockLengths(int Alg, int &KeyLen, int &BlockLen)/* overload */;
	bool __fastcall GetDefaultKeyAndBlockLengths(const Sbtypes::ByteArray OID, int &KeyLen, int &BlockLen)/* overload */;
	__property Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider = {read=FCryptoProvider, write=FCryptoProvider};
	__property Sbcryptoprov::TElCustomCryptoProviderManager* CryptoProviderManager = {read=FCryptoProviderManager, write=FCryptoProviderManager};
};

typedef TElSymmetricCryptoFactory ElSymmetricCryptoFactory
class DELPHICLASS TElAESSymmetricCrypto;
class PASCALIMPLEMENTATION TElAESSymmetricCrypto : public TElSymmetricCrypto
{
	typedef TElSymmetricCrypto inherited;
	
public:
	__fastcall virtual TElAESSymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElAESSymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElAESSymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElAESSymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElAESSymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElAESSymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
public:
	/* TElSymmetricCrypto.Destroy */ inline __fastcall virtual ~TElAESSymmetricCrypto(void) { }
	
};

typedef TElAESSymmetricCrypto ElAESSymmetricCrypto
class DELPHICLASS TElBlowfishSymmetricCrypto;
class PASCALIMPLEMENTATION TElBlowfishSymmetricCrypto : public TElSymmetricCrypto
{
	typedef TElSymmetricCrypto inherited;
	
public:
	__fastcall virtual TElBlowfishSymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElBlowfishSymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElBlowfishSymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElBlowfishSymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElBlowfishSymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElBlowfishSymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
public:
	/* TElSymmetricCrypto.Destroy */ inline __fastcall virtual ~TElBlowfishSymmetricCrypto(void) { }
	
};

typedef TElBlowfishSymmetricCrypto ElBlowfishSymmetricCrypto
class DELPHICLASS TElTwofishSymmetricCrypto;
class PASCALIMPLEMENTATION TElTwofishSymmetricCrypto : public TElSymmetricCrypto
{
	typedef TElSymmetricCrypto inherited;
	
public:
	__fastcall virtual TElTwofishSymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElTwofishSymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElTwofishSymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElTwofishSymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElTwofishSymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElTwofishSymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
public:
	/* TElSymmetricCrypto.Destroy */ inline __fastcall virtual ~TElTwofishSymmetricCrypto(void) { }
	
};

typedef TElTwofishSymmetricCrypto ElTwofishSymmetricCrypto
class DELPHICLASS TElIDEASymmetricCrypto;
class PASCALIMPLEMENTATION TElIDEASymmetricCrypto : public TElSymmetricCrypto
{
	typedef TElSymmetricCrypto inherited;
	
public:
	__fastcall virtual TElIDEASymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElIDEASymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElIDEASymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElIDEASymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElIDEASymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElIDEASymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
public:
	/* TElSymmetricCrypto.Destroy */ inline __fastcall virtual ~TElIDEASymmetricCrypto(void) { }
	
};

typedef TElIDEASymmetricCrypto ElIDEASymmetricCrypto
class DELPHICLASS TElCAST128SymmetricCrypto;
class PASCALIMPLEMENTATION TElCAST128SymmetricCrypto : public TElSymmetricCrypto
{
	typedef TElSymmetricCrypto inherited;
	
public:
	__fastcall virtual TElCAST128SymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElCAST128SymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElCAST128SymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElCAST128SymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElCAST128SymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElCAST128SymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
public:
	/* TElSymmetricCrypto.Destroy */ inline __fastcall virtual ~TElCAST128SymmetricCrypto(void) { }
	
};

typedef TElCAST128SymmetricCrypto ElCAST128SymmetricCrypto
class DELPHICLASS TElRC2SymmetricCrypto;
class PASCALIMPLEMENTATION TElRC2SymmetricCrypto : public TElSymmetricCrypto
{
	typedef TElSymmetricCrypto inherited;
	
public:
	__fastcall virtual TElRC2SymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElRC2SymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElRC2SymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElRC2SymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElRC2SymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElRC2SymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
public:
	/* TElSymmetricCrypto.Destroy */ inline __fastcall virtual ~TElRC2SymmetricCrypto(void) { }
	
};

typedef TElRC2SymmetricCrypto ElRC2SymmetricCrypto
class DELPHICLASS TElRC4SymmetricCrypto;
class PASCALIMPLEMENTATION TElRC4SymmetricCrypto : public TElSymmetricCrypto
{
	typedef TElSymmetricCrypto inherited;
	
private:
	int FSkipKeystreamBytes;
	int __fastcall GetSkipKeystreamBytes(void);
	void __fastcall SetSkipKeystreamBytes(int Value);
	
protected:
	virtual void __fastcall Init(void);
	
public:
	__fastcall virtual TElRC4SymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElRC4SymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElRC4SymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElRC4SymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElRC4SymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElRC4SymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	virtual void __fastcall InitializeEncryption(void);
	virtual void __fastcall InitializeDecryption(void);
	__property int SkipKeystreamBytes = {read=GetSkipKeystreamBytes, write=SetSkipKeystreamBytes, nodefault};
public:
	/* TElSymmetricCrypto.Destroy */ inline __fastcall virtual ~TElRC4SymmetricCrypto(void) { }
	
};

typedef TElRC4SymmetricCrypto ElRC4SymmetricCrypto
class DELPHICLASS TElDESSymmetricCrypto;
class PASCALIMPLEMENTATION TElDESSymmetricCrypto : public TElSymmetricCrypto
{
	typedef TElSymmetricCrypto inherited;
	
public:
	__fastcall virtual TElDESSymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElDESSymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElDESSymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElDESSymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElDESSymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElDESSymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
public:
	/* TElSymmetricCrypto.Destroy */ inline __fastcall virtual ~TElDESSymmetricCrypto(void) { }
	
};

typedef TElDESSymmetricCrypto ElDESSymmetricCrypto
class DELPHICLASS TEl3DESSymmetricCrypto;
class PASCALIMPLEMENTATION TEl3DESSymmetricCrypto : public TElSymmetricCrypto
{
	typedef TElSymmetricCrypto inherited;
	
public:
	__fastcall virtual TEl3DESSymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TEl3DESSymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TEl3DESSymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TEl3DESSymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TEl3DESSymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TEl3DESSymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
public:
	/* TElSymmetricCrypto.Destroy */ inline __fastcall virtual ~TEl3DESSymmetricCrypto(void) { }
	
};

typedef TEl3DESSymmetricCrypto El3DESSymmetricCrypto
class DELPHICLASS TElCamelliaSymmetricCrypto;
class PASCALIMPLEMENTATION TElCamelliaSymmetricCrypto : public TElSymmetricCrypto
{
	typedef TElSymmetricCrypto inherited;
	
public:
	__fastcall virtual TElCamelliaSymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElCamelliaSymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElCamelliaSymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElCamelliaSymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElCamelliaSymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElCamelliaSymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
public:
	/* TElSymmetricCrypto.Destroy */ inline __fastcall virtual ~TElCamelliaSymmetricCrypto(void) { }
	
};

typedef TElCamelliaSymmetricCrypto ElCamelliaSymmetricCrypto
class DELPHICLASS TElSerpentSymmetricCrypto;
class PASCALIMPLEMENTATION TElSerpentSymmetricCrypto : public TElSymmetricCrypto
{
	typedef TElSymmetricCrypto inherited;
	
public:
	__fastcall virtual TElSerpentSymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElSerpentSymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElSerpentSymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElSerpentSymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElSerpentSymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElSerpentSymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
public:
	/* TElSymmetricCrypto.Destroy */ inline __fastcall virtual ~TElSerpentSymmetricCrypto(void) { }
	
};

typedef TElSerpentSymmetricCrypto ElSerpentSymmetricCrypto
class DELPHICLASS TElSEEDSymmetricCrypto;
class PASCALIMPLEMENTATION TElSEEDSymmetricCrypto : public TElSymmetricCrypto
{
	typedef TElSymmetricCrypto inherited;
	
public:
	__fastcall virtual TElSEEDSymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElSEEDSymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElSEEDSymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElSEEDSymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElSEEDSymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElSEEDSymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
public:
	/* TElSymmetricCrypto.Destroy */ inline __fastcall virtual ~TElSEEDSymmetricCrypto(void) { }
	
};

typedef TElSEEDSymmetricCrypto ElSEEDSymmetricCrypto
class DELPHICLASS TElRabbitSymmetricCrypto;
class PASCALIMPLEMENTATION TElRabbitSymmetricCrypto : public TElSymmetricCrypto
{
	typedef TElSymmetricCrypto inherited;
	
public:
	__fastcall virtual TElRabbitSymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElRabbitSymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElRabbitSymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElRabbitSymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElRabbitSymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElRabbitSymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
public:
	/* TElSymmetricCrypto.Destroy */ inline __fastcall virtual ~TElRabbitSymmetricCrypto(void) { }
	
};

typedef TElRabbitSymmetricCrypto ElRabbitSymmetricCrypto
class DELPHICLASS TElGOST28147SymmetricCrypto;
class PASCALIMPLEMENTATION TElGOST28147SymmetricCrypto : public TElSymmetricCrypto
{
	typedef TElSymmetricCrypto inherited;
	
private:
	Sbtypes::ByteArray FParamSet;
	Sbtypes::ByteArray FSBoxes;
	bool FUseKeyMeshing;
	Sbtypes::ByteArray __fastcall GetParamSet(void);
	void __fastcall SetParamSet(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetSBoxes(void);
	void __fastcall SetSBoxes(const Sbtypes::ByteArray Value);
	bool __fastcall GetUseKeyMeshing(void);
	void __fastcall SetUseKeyMeshing(bool Value);
	
protected:
	virtual void __fastcall Init(void);
	
public:
	__fastcall virtual TElGOST28147SymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElGOST28147SymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElGOST28147SymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElGOST28147SymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElGOST28147SymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElGOST28147SymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	virtual void __fastcall InitializeEncryption(void);
	virtual void __fastcall InitializeDecryption(void);
	__property Sbtypes::ByteArray ParamSet = {read=GetParamSet, write=SetParamSet};
	__property Sbtypes::ByteArray SBoxes = {read=GetSBoxes, write=SetSBoxes};
	__property bool UseKeyMeshing = {read=GetUseKeyMeshing, write=SetUseKeyMeshing, nodefault};
public:
	/* TElSymmetricCrypto.Destroy */ inline __fastcall virtual ~TElGOST28147SymmetricCrypto(void) { }
	
};

typedef TElGOST28147SymmetricCrypto ElGOST28147SymmetricCrypto
class DELPHICLASS TElIdentitySymmetricCrypto;
class PASCALIMPLEMENTATION TElIdentitySymmetricCrypto : public TElSymmetricCrypto
{
	typedef TElSymmetricCrypto inherited;
	
public:
	__fastcall virtual TElIdentitySymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElIdentitySymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElIdentitySymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElIdentitySymmetricCrypto(int AlgID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElIdentitySymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElIdentitySymmetricCrypto(TSBSymmetricCryptoMode Mode, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
public:
	/* TElSymmetricCrypto.Destroy */ inline __fastcall virtual ~TElIdentitySymmetricCrypto(void) { }
	
};

typedef TElIdentitySymmetricCrypto ElIdentitySymmetricCrypto
class DELPHICLASS EElSymmetricCryptoError;
class PASCALIMPLEMENTATION EElSymmetricCryptoError : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElSymmetricCryptoError(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElSymmetricCryptoError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElSymmetricCryptoError(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElSymmetricCryptoError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElSymmetricCryptoError(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElSymmetricCryptoError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElSymmetricCryptoError(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElSymmetricCryptoError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElSymmetricCryptoError(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------

}	/* namespace Sbsymmetriccrypto */
using namespace Sbsymmetriccrypto;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbsymmetriccryptoHPP
