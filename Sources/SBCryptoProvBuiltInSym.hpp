// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbcryptoprovbuiltinsym.pas' rev: 21.00

#ifndef SbcryptoprovbuiltinsymHPP
#define SbcryptoprovbuiltinsymHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbcryptoprov.hpp>	// Pascal unit
#include <Sbcryptoprovbuiltin.hpp>	// Pascal unit
#include <Sbcryptoprovutils.hpp>	// Pascal unit
#include <Sbcryptoprovrs.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbaes.hpp>	// Pascal unit
#include <Sbblowfish.hpp>	// Pascal unit
#include <Sbtwofish.hpp>	// Pascal unit
#include <Sbasn1.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit
#include <Sbcast128.hpp>	// Pascal unit
#include <Sbrc2.hpp>	// Pascal unit
#include <Sbrc4.hpp>	// Pascal unit
#include <Sbseed.hpp>	// Pascal unit
#include <Sbrabbit.hpp>	// Pascal unit
#include <Sbdes.hpp>	// Pascal unit
#include <Sbcamellia.hpp>	// Pascal unit
#include <Sbgostcommon.hpp>	// Pascal unit
#include <Sbgost2814789.hpp>	// Pascal unit
#include <Sbserpent.hpp>	// Pascal unit
#include <Sbsha2.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbrdn.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbcryptoprovbuiltinsym
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElBuiltInSymmetricCryptoKey;
class PASCALIMPLEMENTATION TElBuiltInSymmetricCryptoKey : public Sbcryptoprovbuiltin::TElBuiltInCryptoKey
{
	typedef Sbcryptoprovbuiltin::TElBuiltInCryptoKey inherited;
	
private:
	int FAlgorithm;
	
protected:
	virtual int __fastcall GetBits(void);
	virtual int __fastcall GetAlgorithm(void);
	virtual bool __fastcall GetIsPublic(void);
	virtual bool __fastcall GetIsSecret(void);
	virtual bool __fastcall GetIsExportable(void);
	virtual bool __fastcall GetIsPersistent(void);
	virtual bool __fastcall GetIsValid(void);
	virtual Sbcryptoprov::TElCustomCryptoKeyStorage* __fastcall GetKeyStorage(void);
	
public:
	__fastcall virtual TElBuiltInSymmetricCryptoKey(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall TElBuiltInSymmetricCryptoKey(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider, const Sbtypes::ByteArray AlgOID, const Sbtypes::ByteArray AlgParams)/* overload */;
	virtual void __fastcall Generate(int Bits, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0));
	virtual void __fastcall GenerateIV(int Bits);
	virtual void __fastcall ImportPublic(void * Buffer, int Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0));
	virtual void __fastcall ImportSecret(void * Buffer, int Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0));
	virtual void __fastcall ExportPublic(void * Buffer, int &Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0));
	virtual void __fastcall ExportSecret(void * Buffer, int &Size, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0));
	virtual void __fastcall ChangeAlgorithm(int Algorithm);
	virtual void __fastcall Reset(void);
	virtual Sbcryptoprov::TElCustomCryptoKey* __fastcall Clone(Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0));
	virtual Sbcryptoprov::TElCustomCryptoKey* __fastcall ClonePublic(Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0));
	virtual void __fastcall ClearPublic(void);
	virtual void __fastcall ClearSecret(void);
	virtual Sbtypes::ByteArray __fastcall GetKeyProp(const Sbtypes::ByteArray PropID, const Sbtypes::ByteArray Default = (Sbtypes::ByteArray)(0x0));
	virtual void __fastcall SetKeyProp(const Sbtypes::ByteArray PropID, const Sbtypes::ByteArray Value);
	virtual bool __fastcall Equals(Sbcryptoprov::TElCustomCryptoKey* Source, bool PublicOnly, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0))/* overload */;
public:
	/* TElBuiltInCryptoKey.Destroy */ inline __fastcall virtual ~TElBuiltInSymmetricCryptoKey(void) { }
	
	
/* Hoisted overloads: */
	
public:
	inline bool __fastcall  Equals(System::TObject* Obj){ return Sbcryptoprov::TElCustomCryptoKey::Equals(Obj); }
	
};


#pragma option push -b-
enum TSBBuiltInSymmetricCryptoMode { cmDefault, cmECB, cmCBC, cmCTR, cmCFB8, cmCCM, cmGCM };
#pragma option pop

#pragma option push -b-
enum TSBBuiltInSymmetricCipherPadding { cpNone, cpPKCS5 };
#pragma option pop

#pragma option push -b-
enum TSBBuiltInSymmetricCryptoOperation { coNone, coEncryption, coDecryption };
#pragma option pop

typedef void __fastcall (__closure *TSBSymmetricCryptoProcessingFunction)(void * Buffer, void * OutBuffer, int Size);

struct TSBGCMContext
{
	
public:
	unsigned IV0;
	unsigned IV1;
	unsigned IV2;
	unsigned IV3;
	__int64 H0;
	__int64 H1;
	__int64 Y0;
	__int64 Y1;
	__int64 Ctr0;
	__int64 Ctr1;
	__int64 ASize;
	__int64 PSize;
	StaticArray<__int64, 32> HTable;
};


class DELPHICLASS TElBuiltInSymmetricCrypto;
class PASCALIMPLEMENTATION TElBuiltInSymmetricCrypto : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	Sbcryptoprov::TElCustomCryptoKey* FKeyMaterial;
	TSBBuiltInSymmetricCryptoMode FMode;
	bool FAssociatedData;
	Sbtypes::ByteArray FNonce;
	TSBGCMContext FGCMCtx;
	Sbtypes::ByteArray FGCMH;
	Sbtypes::ByteArray FAEADY;
	Sbtypes::ByteArray FAEADCtr0;
	__int64 FAEADASize;
	__int64 FAEADPSize;
	__int64 FAssociatedDataSize;
	__int64 FPayloadSize;
	int FTagSize;
	TSBBuiltInSymmetricCryptoOperation FOperation;
	bool FCTRLittleEndian;
	TSBSymmetricCryptoProcessingFunction FInternalEncryptFunction;
	TSBSymmetricCryptoProcessingFunction FInternalDecryptFunction;
	int FKeySize;
	int FBlockSize;
	TSBBuiltInSymmetricCipherPadding FPadding;
	Sbtypes::ByteArray FVector;
	int FBytesLeft;
	Sbtypes::ByteArray FTail;
	Sbtypes::ByteArray FPadBytes;
	Sbtypes::ByteArray FOID;
	Sbutils::TSBProgressEvent FOnProgress;
	bool __fastcall DoProgress(__int64 Total, __int64 Current);
	virtual void __fastcall SetKeyMaterial(Sbcryptoprov::TElCustomCryptoKey* Material);
	void __fastcall SetAssociatedData(bool Value);
	Sbtypes::ByteArray __fastcall AddPadding(void * Block, int Size);
	int __fastcall EstimatedOutputSize(int InputSize, bool Encrypt);
	void __fastcall SetNonce(const Sbtypes::ByteArray V);
	void __fastcall BlockToUInts8(const Sbtypes::ByteArray Buf, unsigned &B0, unsigned &B1);
	void __fastcall BlockToUints16(const Sbtypes::ByteArray Buf, unsigned &B0, unsigned &B1, unsigned &B2, unsigned &B3);
	void __fastcall UIntsToBlock8(const unsigned B0, const unsigned B1, Sbtypes::ByteArray Buf);
	void __fastcall UIntsToBlock16(const unsigned B0, const unsigned B1, const unsigned B2, const unsigned B3, Sbtypes::ByteArray Buf);
	void __fastcall IncrementCounter8(unsigned &C0, unsigned &C1);
	void __fastcall IncrementCounter16(unsigned &C0, unsigned &C1, unsigned &C2, unsigned &C3);
	virtual void __fastcall EncryptBlock8(unsigned &B0, unsigned &B1);
	virtual void __fastcall EncryptBlock16(unsigned &B0, unsigned &B1, unsigned &B2, unsigned &B3);
	void __fastcall EncryptBlock(__int64 &B)/* overload */;
	void __fastcall EncryptBlock(__int64 &B0, __int64 &B1)/* overload */;
	virtual void __fastcall DecryptBlock8(unsigned &B0, unsigned &B1);
	virtual void __fastcall DecryptBlock16(unsigned &B0, unsigned &B1, unsigned &B2, unsigned &B3);
	void __fastcall EncryptBlockArr(const Sbtypes::ByteArray Src, Sbtypes::ByteArray &Dest);
	void __fastcall DecryptBlockArr(const Sbtypes::ByteArray Src, Sbtypes::ByteArray &Dest);
	void __fastcall GHASHInit(void);
	void __fastcall GHASHUpdate(const Sbtypes::ByteArray Buf);
	void __fastcall InternalEncryptInit(void);
	virtual void __fastcall InternalEncryptECB8(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall InternalEncryptECB16(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall InternalEncryptCBC8(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall InternalEncryptCBC16(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall InternalEncryptCTR8(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall InternalEncryptCTR16(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall InternalEncryptCFB88(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall InternalEncryptCFB816(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall InternalEncryptGCM(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall InternalEncryptCCM(void * Buffer, void * OutBuffer, int Size);
	void __fastcall InternalDecryptInit(void);
	virtual void __fastcall InternalDecryptECB8(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall InternalDecryptECB16(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall InternalDecryptCBC8(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall InternalDecryptCBC16(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall InternalDecryptCFB88(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall InternalDecryptCFB816(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall InternalDecryptGCM(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall InternalDecryptCCM(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall EncryptStreamBlock(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall DecryptStreamBlock(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall ExpandKeyForEncryption(void);
	virtual void __fastcall ExpandKeyForDecryption(void);
	virtual void __fastcall InitializeGCM(void);
	virtual void __fastcall InitializeCCM(void);
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int AlgID)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray AlgOID)/* overload */;
	__classmethod virtual bool __fastcall StreamCipher();
	virtual bool __fastcall GetIsStreamCipher(void);
	__classmethod virtual void __fastcall GetDefaultKeyAndBlockLengths(int AlgID, int &KeyLen, int &BlockLen)/* overload */;
	__classmethod virtual void __fastcall GetDefaultKeyAndBlockLengths(const Sbtypes::ByteArray OID, int &KeyLen, int &BlockLen)/* overload */;
	
public:
	__fastcall virtual TElBuiltInSymmetricCrypto(int AlgID, TSBBuiltInSymmetricCryptoMode Mode)/* overload */;
	__fastcall virtual TElBuiltInSymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBBuiltInSymmetricCryptoMode Mode)/* overload */;
	__fastcall virtual TElBuiltInSymmetricCrypto(TSBBuiltInSymmetricCryptoMode Mode)/* overload */;
	__fastcall virtual ~TElBuiltInSymmetricCrypto(void);
	virtual void __fastcall InitializeEncryption(void);
	virtual void __fastcall InitializeDecryption(void);
	void __fastcall Encrypt(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	void __fastcall Encrypt(Classes::TStream* InStream, Classes::TStream* OutStream)/* overload */;
	void __fastcall EncryptUpdate(void * InBuffer, int InSize, void * OutBuffer, int &OutSize);
	virtual void __fastcall FinalizeEncryption(void * OutBuffer, int &OutSize);
	void __fastcall Decrypt(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	void __fastcall Decrypt(Classes::TStream* InStream, Classes::TStream* OutStream, int InCount = 0x0)/* overload */;
	void __fastcall DecryptUpdate(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	virtual void __fastcall FinalizeDecryption(void * OutBuffer, int &OutSize);
	__property Sbcryptoprov::TElCustomCryptoKey* KeyMaterial = {read=FKeyMaterial, write=SetKeyMaterial};
	__property bool AssociatedData = {read=FAssociatedData, write=SetAssociatedData, nodefault};
	__property __int64 AssociatedDataSize = {read=FAssociatedDataSize, write=FAssociatedDataSize};
	__property __int64 PayloadSize = {read=FPayloadSize, write=FPayloadSize};
	__property Sbtypes::ByteArray Nonce = {read=FNonce, write=SetNonce};
	__property int TagSize = {read=FTagSize, write=FTagSize, nodefault};
	__property TSBBuiltInSymmetricCryptoMode Mode = {read=FMode, nodefault};
	__property int BlockSize = {read=FBlockSize, nodefault};
	__property int KeySize = {read=FKeySize, nodefault};
	__property TSBBuiltInSymmetricCipherPadding Padding = {read=FPadding, write=FPadding, nodefault};
	__property bool CTRLittleEndian = {read=FCTRLittleEndian, write=FCTRLittleEndian, nodefault};
	__property bool IsStreamCipher = {read=GetIsStreamCipher, nodefault};
	__property Sbutils::TSBProgressEvent OnProgress = {read=FOnProgress, write=FOnProgress};
};


typedef TMetaClass* TElBuiltInSymmetricCryptoClass;

class DELPHICLASS TElBuiltInSymmetricCryptoFactory;
class PASCALIMPLEMENTATION TElBuiltInSymmetricCryptoFactory : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	Classes::TList* FRegisteredClasses;
	virtual void __fastcall RegisterDefaultClasses(void);
	TElBuiltInSymmetricCryptoClass __fastcall GetRegisteredClass(int Index);
	int __fastcall GetRegisteredClassCount(void);
	
public:
	__fastcall TElBuiltInSymmetricCryptoFactory(void);
	__fastcall virtual ~TElBuiltInSymmetricCryptoFactory(void);
	void __fastcall RegisterClass(TElBuiltInSymmetricCryptoClass Cls);
	TElBuiltInSymmetricCrypto* __fastcall CreateInstance(const Sbtypes::ByteArray OID, TSBBuiltInSymmetricCryptoMode Mode = (TSBBuiltInSymmetricCryptoMode)(0x0))/* overload */;
	TElBuiltInSymmetricCrypto* __fastcall CreateInstance(int Alg, TSBBuiltInSymmetricCryptoMode Mode = (TSBBuiltInSymmetricCryptoMode)(0x0))/* overload */;
	bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	bool __fastcall GetDefaultKeyAndBlockLengths(int Alg, int &KeyLen, int &BlockLen)/* overload */;
	bool __fastcall GetDefaultKeyAndBlockLengths(const Sbtypes::ByteArray OID, int &KeyLen, int &BlockLen)/* overload */;
	__property TElBuiltInSymmetricCryptoClass RegisteredClasses[int Index] = {read=GetRegisteredClass};
	__property int RegisteredClassCount = {read=GetRegisteredClassCount, nodefault};
};


class DELPHICLASS TElBuiltInIdentitySymmetricCrypto;
class PASCALIMPLEMENTATION TElBuiltInIdentitySymmetricCrypto : public TElBuiltInSymmetricCrypto
{
	typedef TElBuiltInSymmetricCrypto inherited;
	
protected:
	virtual void __fastcall SetKeyMaterial(Sbcryptoprov::TElCustomCryptoKey* Material);
	virtual void __fastcall EncryptStreamBlock(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall DecryptStreamBlock(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall ExpandKeyForEncryption(void);
	virtual void __fastcall ExpandKeyForDecryption(void);
	__classmethod virtual bool __fastcall StreamCipher();
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int AlgID)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray AlgOID)/* overload */;
	__classmethod virtual void __fastcall GetDefaultKeyAndBlockLengths(int AlgID, int &KeyLen, int &BlockLen)/* overload */;
	__classmethod virtual void __fastcall GetDefaultKeyAndBlockLengths(const Sbtypes::ByteArray OID, int &KeyLen, int &BlockLen)/* overload */;
	
public:
	__fastcall virtual TElBuiltInIdentitySymmetricCrypto(int AlgID, TSBBuiltInSymmetricCryptoMode Mode)/* overload */;
	__fastcall virtual TElBuiltInIdentitySymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBBuiltInSymmetricCryptoMode Mode)/* overload */;
	__fastcall virtual TElBuiltInIdentitySymmetricCrypto(TSBBuiltInSymmetricCryptoMode Mode)/* overload */;
public:
	/* TElBuiltInSymmetricCrypto.Destroy */ inline __fastcall virtual ~TElBuiltInIdentitySymmetricCrypto(void) { }
	
};


class DELPHICLASS TElBuiltInRC4SymmetricCrypto;
class PASCALIMPLEMENTATION TElBuiltInRC4SymmetricCrypto : public TElBuiltInSymmetricCrypto
{
	typedef TElBuiltInSymmetricCrypto inherited;
	
protected:
	int FSkipKeyStreamBytes;
	Sbrc4::TRC4Context FContext;
	virtual void __fastcall SetKeyMaterial(Sbcryptoprov::TElCustomCryptoKey* Material);
	virtual void __fastcall EncryptStreamBlock(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall DecryptStreamBlock(void * Buffer, void * OutBuffer, int Size);
	virtual void __fastcall ExpandKeyForEncryption(void);
	virtual void __fastcall ExpandKeyForDecryption(void);
	__classmethod virtual bool __fastcall StreamCipher();
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int AlgID)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray AlgOID)/* overload */;
	__classmethod virtual void __fastcall GetDefaultKeyAndBlockLengths(int AlgID, int &KeyLen, int &BlockLen)/* overload */;
	__classmethod virtual void __fastcall GetDefaultKeyAndBlockLengths(const Sbtypes::ByteArray OID, int &KeyLen, int &BlockLen)/* overload */;
	
public:
	__fastcall virtual TElBuiltInRC4SymmetricCrypto(int AlgID, TSBBuiltInSymmetricCryptoMode Mode)/* overload */;
	__fastcall virtual TElBuiltInRC4SymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBBuiltInSymmetricCryptoMode Mode)/* overload */;
	__fastcall virtual TElBuiltInRC4SymmetricCrypto(TSBBuiltInSymmetricCryptoMode Mode)/* overload */;
	virtual void __fastcall InitializeEncryption(void);
	virtual void __fastcall InitializeDecryption(void);
	__property int SkipKeystreamBytes = {read=FSkipKeyStreamBytes, write=FSkipKeyStreamBytes, nodefault};
public:
	/* TElBuiltInSymmetricCrypto.Destroy */ inline __fastcall virtual ~TElBuiltInRC4SymmetricCrypto(void) { }
	
};


class DELPHICLASS TElBuiltInGOST28147SymmetricCrypto;
class PASCALIMPLEMENTATION TElBuiltInGOST28147SymmetricCrypto : public TElBuiltInSymmetricCrypto
{
	typedef TElBuiltInSymmetricCrypto inherited;
	
protected:
	Sbgost2814789::TElGOST* fGOST;
	int FProcessedBlocks;
	bool FUseKeyMeshing;
	virtual void __fastcall SetKeyMaterial(Sbcryptoprov::TElCustomCryptoKey* Material);
	void __fastcall DoKeyMeshing(unsigned &IV0, unsigned &IV1);
	virtual void __fastcall EncryptBlock8(unsigned &B0, unsigned &B1);
	virtual void __fastcall DecryptBlock8(unsigned &B0, unsigned &B1);
	virtual void __fastcall ExpandKeyForEncryption(void);
	virtual void __fastcall ExpandKeyForDecryption(void);
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int AlgID)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray AlgOID)/* overload */;
	__classmethod virtual void __fastcall GetDefaultKeyAndBlockLengths(int AlgID, int &KeyLen, int &BlockLen)/* overload */;
	__classmethod virtual void __fastcall GetDefaultKeyAndBlockLengths(const Sbtypes::ByteArray OID, int &KeyLen, int &BlockLen)/* overload */;
	void __fastcall InitializeCipher(void);
	void __fastcall SetParamSet(const Sbtypes::ByteArray Value);
	void __fastcall SetSBoxes(const Sbtypes::ByteArray Value);
	
public:
	__fastcall virtual ~TElBuiltInGOST28147SymmetricCrypto(void);
	__fastcall virtual TElBuiltInGOST28147SymmetricCrypto(int AlgID, TSBBuiltInSymmetricCryptoMode Mode)/* overload */;
	__fastcall virtual TElBuiltInGOST28147SymmetricCrypto(const Sbtypes::ByteArray AlgOID, TSBBuiltInSymmetricCryptoMode Mode)/* overload */;
	__fastcall virtual TElBuiltInGOST28147SymmetricCrypto(TSBBuiltInSymmetricCryptoMode Mode)/* overload */;
	__property Sbtypes::ByteArray ParamSet = {write=SetParamSet};
	__property Sbtypes::ByteArray SBoxes = {write=SetSBoxes};
	__property bool UseKeyMeshing = {read=FUseKeyMeshing, write=FUseKeyMeshing, nodefault};
};


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
static const Word SYMMETRIC_BLOCK_SIZE = 0x4000;
static const TSBBuiltInSymmetricCryptoMode SYMMETRIC_DEFAULT_MODE = (TSBBuiltInSymmetricCryptoMode)(2);

}	/* namespace Sbcryptoprovbuiltinsym */
using namespace Sbcryptoprovbuiltinsym;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbcryptoprovbuiltinsymHPP
