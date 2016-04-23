// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbpublickeycrypto.pas' rev: 21.00

#ifndef SbpublickeycryptoHPP
#define SbpublickeycryptoHPP

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
#include <Sbstringlist.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbencoding.hpp>	// Pascal unit
#include <Sbmath.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbrsa.hpp>	// Pascal unit
#include <Sbdsa.hpp>	// Pascal unit
#include <Sbelgamal.hpp>	// Pascal unit
#include <Sbpem.hpp>	// Pascal unit
#include <Sbsrp.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit
#include <Sbwincrypt.hpp>	// Pascal unit
#include <Sbcustomcrypto.hpp>	// Pascal unit
#include <Sbcryptoprov.hpp>	// Pascal unit
#include <Sbcryptoprovmanager.hpp>	// Pascal unit
#include <Sbcryptoprovutils.hpp>	// Pascal unit
#include <Sbasn1.hpp>	// Pascal unit
#include <Sbalgorithmidentifier.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbpublickeycrypto
{
//-- type declarations -------------------------------------------------------
typedef unsigned SB_CK_ULONG;

typedef void __fastcall (__closure *TSBAsyncOperationFinishedEvent)(System::TObject* Sender, bool Success);

#pragma option push -b-
enum TSBKeyStoreFormat { ksfRaw, ksfPKCS8 };
#pragma option pop

class DELPHICLASS TElPublicKeyMaterial;
class PASCALIMPLEMENTATION TElPublicKeyMaterial : public Sbcustomcrypto::TElKeyMaterial
{
	typedef Sbcustomcrypto::TElKeyMaterial inherited;
	
protected:
	bool FBusy;
	Sbcryptoprov::TElCustomCryptoProvider* FProvider;
	Sbcryptoprov::TElCustomCryptoProviderManager* FProviderManager;
	TSBKeyStoreFormat FStoreFormat;
	bool FAsyncOperationFinished;
	bool FAsyncOperationSucceeded;
	System::UnicodeString FAsyncOperationError;
	TSBAsyncOperationFinishedEvent FOnAsyncOperationFinished;
	Classes::TThread* FWorkingThread;
	bool __fastcall IsPEM(void * Buffer, int Size);
	virtual void __fastcall InternalGenerate(int Bits);
	void __fastcall OnThreadTerminate(System::TObject* Sender);
	Sbwincrypt::PCCERT_CONTEXT __fastcall GetCertHandle(void);
	void __fastcall SetCertHandle(Sbwincrypt::PCCERT_CONTEXT Value);
	System::UnicodeString __fastcall GetKeyExchangePIN(void);
	void __fastcall SetKeyExchangePIN(const System::UnicodeString Value);
	System::UnicodeString __fastcall GetSignaturePIN(void);
	void __fastcall SetSignaturePIN(const System::UnicodeString Value);
	unsigned __fastcall GetKeyHandle(void);
	void __fastcall SetKeyHandle(unsigned Value);
	unsigned __fastcall GetSessionHandle(void);
	void __fastcall SetSessionHandle(unsigned Value);
	virtual bool __fastcall GetValid(void);
	bool __fastcall GetIsPublicKey(void);
	bool __fastcall GetIsSecretKey(void);
	virtual bool __fastcall GetExportable(void);
	void __fastcall SetOnAsyncOperationFinished(TSBAsyncOperationFinishedEvent Value);
	virtual bool __fastcall GetAsyncOperationFinished(void);
	
public:
	__fastcall virtual TElPublicKeyMaterial(Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual TElPublicKeyMaterial(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual ~TElPublicKeyMaterial(void);
	__classmethod int __fastcall GetMaxPublicKeySize(Sbcryptoprov::TElCustomCryptoProvider* Prov);
	virtual void __fastcall AssignCryptoKey(Sbcryptoprov::TElCustomCryptoKey* Key);
	virtual void __fastcall Generate(int Bits);
	virtual void __fastcall LoadPublic(void * Buffer, int Size)/* overload */;
	virtual void __fastcall LoadSecret(void * Buffer, int Size)/* overload */;
	virtual void __fastcall SavePublic(void * Buffer, int &Size)/* overload */;
	virtual void __fastcall SaveSecret(void * Buffer, int &Size)/* overload */;
	virtual void __fastcall LoadParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	virtual void __fastcall SaveParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	void __fastcall LoadPublic(Classes::TStream* Stream, int Count = 0x0)/* overload */;
	void __fastcall LoadSecret(Classes::TStream* Stream, int Count = 0x0)/* overload */;
	virtual void __fastcall SavePublic(Classes::TStream* Stream)/* overload */;
	virtual void __fastcall SaveSecret(Classes::TStream* Stream)/* overload */;
	virtual void __fastcall Save(Classes::TStream* Stream);
	virtual void __fastcall Load(Classes::TStream* Stream, int Count = 0x0);
	virtual void __fastcall LoadFromXML(const System::UnicodeString Str);
	virtual System::UnicodeString __fastcall SaveToXML(bool IncludePrivateKey = false);
	virtual Sbcustomcrypto::TElKeyMaterial* __fastcall Clone(void);
	virtual bool __fastcall Equals(Sbcustomcrypto::TElKeyMaterial* Source, bool PublicOnly)/* overload */;
	virtual void __fastcall ClearSecret(void);
	virtual void __fastcall ClearPublic(void);
	void __fastcall Clear(void);
	void __fastcall BeginGenerate(int Bits);
	void __fastcall EndGenerate(void);
	void __fastcall CancelAsyncOperation(void);
	virtual void __fastcall PrepareForEncryption(bool MultiUse = false);
	virtual void __fastcall PrepareForSigning(bool MultiUse = false);
	__property bool PublicKey = {read=GetIsPublicKey, nodefault};
	__property bool SecretKey = {read=GetIsSecretKey, nodefault};
	__property Sbwincrypt::PCCERT_CONTEXT CertHandle = {read=GetCertHandle, write=SetCertHandle};
	__property System::UnicodeString KeyExchangePIN = {read=GetKeyExchangePIN, write=SetKeyExchangePIN};
	__property System::UnicodeString SignaturePIN = {read=GetSignaturePIN, write=SetSignaturePIN};
	__property unsigned KeyHandle = {read=GetKeyHandle, write=SetKeyHandle, nodefault};
	__property unsigned SessionHandle = {read=GetSessionHandle, write=SetSessionHandle, nodefault};
	__property bool Busy = {read=FBusy, nodefault};
	__property TSBKeyStoreFormat StoreFormat = {read=FStoreFormat, write=FStoreFormat, nodefault};
	__property bool AsyncOperationFinished = {read=GetAsyncOperationFinished, nodefault};
	__property TSBAsyncOperationFinishedEvent OnAsyncOperationFinished = {read=FOnAsyncOperationFinished, write=SetOnAsyncOperationFinished};
	
/* Hoisted overloads: */
	
public:
	inline bool __fastcall  Equals(System::TObject* Obj){ return Sbcustomcrypto::TElKeyMaterial::Equals(Obj); }
	
};

typedef TElPublicKeyMaterial ElPublicKeyMaterial
#pragma option push -b-
enum TSBPublicKeyOperation { pkoEncrypt, pkoDecrypt, pkoSign, pkoSignDetached, pkoVerify, pkoVerifyDetached, pkoDecryptKey };
#pragma option pop

#pragma option push -b-
enum TSBPublicKeyVerificationResult { pkvrSuccess, pkvrInvalidSignature, pkvrKeyNotFound, pkvrFailure };
#pragma option pop

#pragma option push -b-
enum TSBPublicKeyCryptoEncoding { pkeBinary, pkeBase64 };
#pragma option pop

class DELPHICLASS TElPublicKeyCrypto;
class PASCALIMPLEMENTATION TElPublicKeyCrypto : public Sbcustomcrypto::TElCustomCrypto
{
	typedef Sbcustomcrypto::TElCustomCrypto inherited;
	
protected:
	TElPublicKeyMaterial* FKeyMaterial;
	Sbtypes::ByteArray FOutput;
	Classes::TStream* FOutputStream;
	bool FOutputIsStream;
	bool FInputIsHash;
	TSBPublicKeyCryptoEncoding FInputEncoding;
	TSBPublicKeyCryptoEncoding FOutputEncoding;
	Sbencoding::TSBBase64Context FInB64Ctx;
	Sbencoding::TSBBase64Context FOutB64Ctx;
	Sbtypes::ByteArray FInputSpool;
	bool FBusy;
	bool FAsyncOperationFinished;
	TSBAsyncOperationFinishedEvent FOnAsyncOperationFinished;
	Sbcryptoprov::TElCustomCryptoProvider* FCryptoProvider;
	Sbcryptoprov::TElCustomCryptoProviderManager* FCryptoProviderManager;
	Sbcryptoprov::TElCustomCryptoContext* FContext;
	bool FAsyncOperationSucceeded;
	System::UnicodeString FAsyncOperationError;
	TSBPublicKeyOperation FAsyncOperation;
	TSBPublicKeyVerificationResult FVerificationResult;
	Classes::TThread* FWorkingThread;
	int FHashAlg;
	virtual void __fastcall AdjustContextProps(Sbrdn::TElRelativeDistinguishedName* Params);
	virtual void __fastcall SaveContextProps(void);
	void __fastcall DecodeInput(void * InData, int InSize);
	void __fastcall OnThreadTerminate(System::TObject* Sender);
	void __fastcall InternalEncrypt(void)/* overload */;
	void __fastcall InternalDecrypt(void)/* overload */;
	void __fastcall InternalSign(void)/* overload */;
	void __fastcall InternalSignDetached(void)/* overload */;
	TSBPublicKeyVerificationResult __fastcall InternalVerify(void)/* overload */;
	TSBPublicKeyVerificationResult __fastcall InternalVerifyDetached(void)/* overload */;
	void __fastcall InternalEncrypt(Classes::TStream* InStream, Classes::TStream* OutStream, int Count = 0x0)/* overload */;
	void __fastcall InternalDecrypt(Classes::TStream* InStream, Classes::TStream* OutStream, int Count = 0x0)/* overload */;
	void __fastcall InternalSign(Classes::TStream* InStream, Classes::TStream* OutStream, int Count = 0x0)/* overload */;
	void __fastcall InternalSignDetached(Classes::TStream* InStream, Classes::TStream* OutStream, int Count = 0x0)/* overload */;
	TSBPublicKeyVerificationResult __fastcall InternalVerify(Classes::TStream* InStream, Classes::TStream* OutStream, int Count = 0x0)/* overload */;
	TSBPublicKeyVerificationResult __fastcall InternalVerifyDetached(Classes::TStream* InStream, Classes::TStream* SigStream, int InCount = 0x0, int SigCount = 0x0)/* overload */;
	virtual void __fastcall SignInit(bool Detached);
	virtual void __fastcall SignUpdate(void * Buffer, int Size);
	virtual void __fastcall SignFinal(void);
	virtual void __fastcall EncryptInit(void);
	virtual void __fastcall EncryptUpdate(void * Buffer, int Size);
	virtual void __fastcall EncryptFinal(void);
	virtual void __fastcall DecryptInit(void);
	virtual void __fastcall DecryptUpdate(void * Buffer, int Size);
	virtual void __fastcall DecryptFinal(void);
	virtual void __fastcall VerifyInit(bool Detached, void * Signature, int SigSize);
	virtual void __fastcall VerifyUpdate(void * Buffer, int Size);
	virtual TSBPublicKeyVerificationResult __fastcall VerifyFinal(void);
	virtual int __fastcall EstimateOutputSize(void * InBuffer, int InSize, TSBPublicKeyOperation Operation);
	virtual void __fastcall WriteToOutput(void * Buffer, int Size);
	void __fastcall Reset(void);
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	__classmethod virtual System::UnicodeString __fastcall GetName();
	__classmethod virtual System::UnicodeString __fastcall GetDescription();
	virtual Sbcryptoprov::TElCustomCryptoProvider* __fastcall GetSuitableCryptoProvider(TSBPublicKeyOperation Operation, int Algorithm, Sbrdn::TElRelativeDistinguishedName* Pars);
	virtual bool __fastcall GetSupportsEncryption(void);
	virtual bool __fastcall GetSupportsSigning(void);
	virtual void __fastcall SetKeyMaterial(TElPublicKeyMaterial* Material);
	void __fastcall SetInputIsHash(bool Value);
	void __fastcall SetInputEncoding(TSBPublicKeyCryptoEncoding Value);
	void __fastcall SetOutputEncoding(TSBPublicKeyCryptoEncoding Value);
	void __fastcall SetOnAsyncOperationFinished(TSBAsyncOperationFinishedEvent Value);
	int __fastcall GetHashAlgorithm(void);
	void __fastcall SetHashAlgorithm(int Value);
	
public:
	__fastcall virtual TElPublicKeyCrypto(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElPublicKeyCrypto(int Alg, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElPublicKeyCrypto(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElPublicKeyCrypto(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElPublicKeyCrypto(int Alg, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElPublicKeyCrypto(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual ~TElPublicKeyCrypto(void);
	virtual void __fastcall LoadParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	virtual void __fastcall SaveParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	void __fastcall Encrypt(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	void __fastcall Decrypt(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	void __fastcall Sign(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	void __fastcall SignDetached(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	TSBPublicKeyVerificationResult __fastcall Verify(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	TSBPublicKeyVerificationResult __fastcall VerifyDetached(void * InBuffer, int InSize, void * SigBuffer, int SigSize)/* overload */;
	void __fastcall Encrypt(Classes::TStream* InStream, Classes::TStream* OutStream, int Count = 0x0)/* overload */;
	void __fastcall Decrypt(Classes::TStream* InStream, Classes::TStream* OutStream, int Count = 0x0)/* overload */;
	void __fastcall Sign(Classes::TStream* InStream, Classes::TStream* OutStream, int Count = 0x0)/* overload */;
	void __fastcall SignDetached(Classes::TStream* InStream, Classes::TStream* OutStream, int Count = 0x0)/* overload */;
	TSBPublicKeyVerificationResult __fastcall Verify(Classes::TStream* InStream, Classes::TStream* OutStream, int Count = 0x0)/* overload */;
	TSBPublicKeyVerificationResult __fastcall VerifyDetached(Classes::TStream* InStream, Classes::TStream* SigStream, int InCount = 0x0, int SigCount = 0x0)/* overload */;
	virtual Sbcustomcrypto::TElKeyMaterial* __fastcall DecryptKey(void * EncKey, int EncKeySize, const Sbtypes::ByteArray EncKeyAlgOID, const Sbtypes::ByteArray EncKeyAlgParams);
	void __fastcall BeginEncrypt(void * InBuffer, int InSize)/* overload */;
	bool __fastcall EndEncrypt(void * OutBuffer, int &OutSize)/* overload */;
	void __fastcall BeginDecrypt(void * InBuffer, int InSize)/* overload */;
	bool __fastcall EndDecrypt(void * OutBuffer, int &OutSize)/* overload */;
	void __fastcall BeginSign(void * InBuffer, int InSize)/* overload */;
	bool __fastcall EndSign(void * OutBuffer, int &OutSize)/* overload */;
	void __fastcall BeginSignDetached(void * InBuffer, int InSize)/* overload */;
	bool __fastcall EndSignDetached(void * OutBuffer, int &OutSize)/* overload */;
	void __fastcall BeginVerify(void * InBuffer, int InSize)/* overload */;
	bool __fastcall EndVerify(void * OutBuffer, int &OutSize, TSBPublicKeyVerificationResult &VerificationResult)/* overload */;
	void __fastcall BeginVerifyDetached(void * InBuffer, int InSize, void * SigBuffer, int SigSize)/* overload */;
	void __fastcall BeginEncrypt(Classes::TStream* InStream, Classes::TStream* OutStream, int Count = 0x0)/* overload */;
	void __fastcall EndEncrypt(void)/* overload */;
	void __fastcall BeginDecrypt(Classes::TStream* InStream, Classes::TStream* OutStream, int Count = 0x0)/* overload */;
	void __fastcall EndDecrypt(void)/* overload */;
	void __fastcall BeginSign(Classes::TStream* InStream, Classes::TStream* OutStream, int Count = 0x0)/* overload */;
	void __fastcall EndSign(void)/* overload */;
	void __fastcall BeginSignDetached(Classes::TStream* InStream, Classes::TStream* OutStream, int Count = 0x0)/* overload */;
	void __fastcall EndSignDetached(void)/* overload */;
	void __fastcall BeginVerify(Classes::TStream* InStream, Classes::TStream* OutStream, int Count = 0x0)/* overload */;
	TSBPublicKeyVerificationResult __fastcall EndVerify(void)/* overload */;
	void __fastcall BeginVerifyDetached(Classes::TStream* InStream, Classes::TStream* SigStream, int InCount = 0x0, int SigCount = 0x0)/* overload */;
	TSBPublicKeyVerificationResult __fastcall EndVerifyDetached(void)/* overload */;
	void __fastcall CancelAsyncOperation(void);
	__property TElPublicKeyMaterial* KeyMaterial = {read=FKeyMaterial, write=SetKeyMaterial};
	__property bool SupportsEncryption = {read=GetSupportsEncryption, nodefault};
	__property bool SupportsSigning = {read=GetSupportsSigning, nodefault};
	__property bool InputIsHash = {read=FInputIsHash, write=SetInputIsHash, nodefault};
	__property TSBPublicKeyCryptoEncoding InputEncoding = {read=FInputEncoding, write=SetInputEncoding, nodefault};
	__property TSBPublicKeyCryptoEncoding OutputEncoding = {read=FOutputEncoding, write=SetOutputEncoding, nodefault};
	__property bool Busy = {read=FBusy, nodefault};
	__property int HashAlgorithm = {read=GetHashAlgorithm, write=SetHashAlgorithm, nodefault};
	__property bool AsyncOperationFinished = {read=FAsyncOperationFinished, nodefault};
	__property TSBAsyncOperationFinishedEvent OnAsyncOperationFinished = {read=FOnAsyncOperationFinished, write=SetOnAsyncOperationFinished};
};

typedef TElPublicKeyCrypto ElPublicKeyCrypto
typedef TMetaClass* TElPublicKeyCryptoClass;

typedef TElPublicKeyCryptoClass ElPublicKeyCryptoClass;

#pragma option push -b-
enum TSBRSAKeyFormat { rsaPKCS1, rsaOAEP, rsaPSS, rsaX509 };
#pragma option pop

class DELPHICLASS TElRSAKeyMaterial;
class PASCALIMPLEMENTATION TElRSAKeyMaterial : public TElPublicKeyMaterial
{
	typedef TElPublicKeyMaterial inherited;
	
protected:
	TSBRSAKeyFormat FKeyFormat;
	System::UnicodeString FPassphrase;
	bool FPEMEncode;
	void __fastcall Reset(void);
	virtual void __fastcall InternalGenerate(int Bits);
	Sbtypes::ByteArray __fastcall GetM(void);
	Sbtypes::ByteArray __fastcall GetE(void);
	Sbtypes::ByteArray __fastcall GetD(void);
	virtual bool __fastcall GetValid(void);
	virtual int __fastcall GetBits(void);
	void __fastcall SetPassphrase(const System::UnicodeString Value);
	void __fastcall SetPEMEncode(bool Value);
	void __fastcall SetStrLabel(const System::UnicodeString Value);
	void __fastcall SetSaltSize(int Value);
	void __fastcall SetMGFAlgorithm(int Value);
	void __fastcall SetTrailerField(int Value);
	void __fastcall SetHashAlgorithm(int Value);
	void __fastcall SetRawPublicKey(bool Value);
	System::UnicodeString __fastcall GetStrLabel(void);
	int __fastcall GetSaltSize(void);
	int __fastcall GetMGFAlgorithm(void);
	int __fastcall GetTrailerField(void);
	int __fastcall GetHashAlgorithm(void);
	bool __fastcall GetRawPublicKey(void);
	
public:
	__fastcall virtual TElRSAKeyMaterial(Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual TElRSAKeyMaterial(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual ~TElRSAKeyMaterial(void);
	virtual void __fastcall Assign(Sbcustomcrypto::TElKeyMaterial* Source);
	virtual void __fastcall LoadParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	virtual void __fastcall SaveParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	virtual void __fastcall LoadPublic(void * Buffer, int Size)/* overload */;
	virtual void __fastcall LoadSecret(void * Buffer, int Size)/* overload */;
	HIDESBASE void __fastcall LoadPublic(void * Modulus, int ModulusSize, void * Exponent, int ExponentSize)/* overload */;
	virtual void __fastcall SavePublic(void * Buffer, int &Size)/* overload */;
	virtual void __fastcall SaveSecret(void * Buffer, int &Size)/* overload */;
	virtual void __fastcall LoadFromXML(const System::UnicodeString Str);
	virtual System::UnicodeString __fastcall SaveToXML(bool IncludePrivateKey = false);
	bool __fastcall EncodePublicKey(void * PublicModulus, int PublicModulusSize, void * PublicExponent, int PublicExponentSize, const Sbtypes::ByteArray AlgID, void * OutBuffer, int &OutSize, bool InnerValuesOnly = false)/* overload */;
	bool __fastcall EncodePrivateKey(void * PublicModulus, int PublicModulusSize, void * PublicExponent, int PublicExponentSize, void * PrivateExponent, int PrivateExponentSize, void * OutBuffer, int &OutSize)/* overload */;
	bool __fastcall EncodePrivateKey(void * N, int NSize, void * E, int ESize, void * D, int DSize, void * P, int PSize, void * Q, int QSize, void * DP, int DPSize, void * DQ, int DQSize, void * QInv, int QInvSize, void * OutBuffer, int &OutSize)/* overload */;
	bool __fastcall EncodePrivateKey(void * N, int NSize, void * E, int ESize, void * D, int DSize, void * P, int PSize, void * Q, int QSize, void * OutBuffer, int &OutSize)/* overload */;
	bool __fastcall DecodePrivateKey(void * Blob, int BlobSize, void * N, int &NSize, void * E, int &ESize, void * D, int &DSize, void * P, int &PSize, void * Q, int &QSize, void * DP, int &DPSize, void * DQ, int &DQSize, void * QInv, int &QInvSize);
	__classmethod Sbtypes::ByteArray __fastcall WritePSSParams(int HashAlgorithm, int SaltSize, int MGFAlgorithm, int TrailerField);
	__classmethod bool __fastcall ReadPSSParams(void * InBuffer, int InBufferSize, int &HashAlgorithm, int &SaltSize, int &MGF, int &MGFHashAlgorithm, int &TrailerField);
	__classmethod Sbtypes::ByteArray __fastcall WriteOAEPParams(int HashAlgorithm, int MGFHashAlgorithm, const System::UnicodeString StrLabel);
	__classmethod bool __fastcall ReadOAEPParams(void * InBuffer, int InBufferSize, int &HashAlgorithm, int &MGFHashAlgorithm, System::UnicodeString &StrLabel);
	virtual Sbcustomcrypto::TElKeyMaterial* __fastcall Clone(void);
	virtual bool __fastcall Equals(Sbcustomcrypto::TElKeyMaterial* Source, bool PublicOnly)/* overload */;
	virtual void __fastcall ClearSecret(void);
	virtual void __fastcall ClearPublic(void);
	__property TSBRSAKeyFormat KeyFormat = {read=FKeyFormat, write=FKeyFormat, nodefault};
	__property System::UnicodeString Passphrase = {read=FPassphrase, write=SetPassphrase};
	__property bool PEMEncode = {read=FPEMEncode, write=SetPEMEncode, nodefault};
	__property System::UnicodeString StrLabel = {read=GetStrLabel, write=SetStrLabel};
	__property int SaltSize = {read=GetSaltSize, write=SetSaltSize, nodefault};
	__property int MGFAlgorithm = {read=GetMGFAlgorithm, write=SetMGFAlgorithm, nodefault};
	__property int TrailerField = {read=GetTrailerField, write=SetTrailerField, nodefault};
	__property int HashAlgorithm = {read=GetHashAlgorithm, write=SetHashAlgorithm, nodefault};
	__property bool RawPublicKey = {read=GetRawPublicKey, write=SetRawPublicKey, nodefault};
	__property Sbtypes::ByteArray PublicModulus = {read=GetM};
	__property Sbtypes::ByteArray PublicExponent = {read=GetE};
	__property Sbtypes::ByteArray PrivateExponent = {read=GetD};
	
/* Hoisted overloads: */
	
public:
	inline void __fastcall  LoadPublic(Classes::TStream* Stream, int Count = 0x0){ TElPublicKeyMaterial::LoadPublic(Stream, Count); }
	inline void __fastcall  LoadSecret(Classes::TStream* Stream, int Count = 0x0){ TElPublicKeyMaterial::LoadSecret(Stream, Count); }
	inline void __fastcall  SavePublic(Classes::TStream* Stream){ TElPublicKeyMaterial::SavePublic(Stream); }
	inline void __fastcall  SaveSecret(Classes::TStream* Stream){ TElPublicKeyMaterial::SaveSecret(Stream); }
	inline bool __fastcall  Equals(System::TObject* Obj){ return Sbcustomcrypto::TElKeyMaterial::Equals(Obj); }
	
};

typedef TElRSAKeyMaterial ElRSAKeyMaterial
#pragma option push -b-
enum TSBRSAPublicKeyCryptoType { rsapktPKCS1, rsapktOAEP, rsapktPSS, rsapktSSL3 };
#pragma option pop

class DELPHICLASS TElRSAPublicKeyCrypto;
class PASCALIMPLEMENTATION TElRSAPublicKeyCrypto : public TElPublicKeyCrypto
{
	typedef TElPublicKeyCrypto inherited;
	
protected:
	Sbtypes::ByteArray FOID;
	bool FSupportsEncryption;
	bool FSupportsSigning;
	TSBRSAPublicKeyCryptoType FCryptoType;
	bool FUseAlgorithmPrefix;
	Sbtypes::ByteArray FSpool;
	Sbtypes::ByteArray FHashFuncOID;
	int FSaltSize;
	int FTrailerField;
	int FMGFAlgorithm;
	System::UnicodeString FStrLabel;
	virtual void __fastcall AdjustContextProps(Sbrdn::TElRelativeDistinguishedName* Params);
	virtual void __fastcall SignInit(bool Detached);
	virtual void __fastcall SignUpdate(void * Buffer, int Size);
	virtual void __fastcall SignFinal(void);
	virtual void __fastcall EncryptInit(void);
	virtual void __fastcall EncryptUpdate(void * Buffer, int Size);
	virtual void __fastcall EncryptFinal(void);
	virtual void __fastcall DecryptInit(void);
	virtual void __fastcall DecryptUpdate(void * Buffer, int Size);
	virtual void __fastcall DecryptFinal(void);
	virtual void __fastcall VerifyInit(bool Detached, void * Signature, int SigSize);
	virtual void __fastcall VerifyUpdate(void * Buffer, int Size);
	virtual TSBPublicKeyVerificationResult __fastcall VerifyFinal(void);
	virtual int __fastcall EstimateOutputSize(void * InBuffer, int InSize, TSBPublicKeyOperation Operation);
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	__classmethod virtual System::UnicodeString __fastcall GetName();
	__classmethod virtual System::UnicodeString __fastcall GetDescription();
	HIDESBASE void __fastcall Reset(void);
	virtual bool __fastcall GetSupportsEncryption(void);
	virtual bool __fastcall GetSupportsSigning(void);
	virtual void __fastcall SetKeyMaterial(TElPublicKeyMaterial* Material);
	void __fastcall SetCryptoType(TSBRSAPublicKeyCryptoType Value);
	void __fastcall SetUseAlgorithmPrefix(bool Value);
	void __fastcall SetHashFuncOID(const Sbtypes::ByteArray Value);
	int __fastcall GetSaltSize(void);
	void __fastcall SetSaltSize(int Value);
	System::UnicodeString __fastcall GetStrLabel(void);
	void __fastcall SetStrLabel(const System::UnicodeString Value);
	int __fastcall GetTrailerField(void);
	void __fastcall SetTrailerField(int Value);
	int __fastcall GetMGFAlgorithm(void);
	void __fastcall SetMGFAlgorithm(int Value);
	
public:
	__fastcall virtual TElRSAPublicKeyCrypto(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElRSAPublicKeyCrypto(int Alg, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElRSAPublicKeyCrypto(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElRSAPublicKeyCrypto(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElRSAPublicKeyCrypto(int Alg, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElRSAPublicKeyCrypto(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual ~TElRSAPublicKeyCrypto(void);
	virtual void __fastcall LoadParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	virtual void __fastcall SaveParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	virtual Sbcustomcrypto::TElKeyMaterial* __fastcall DecryptKey(void * EncKey, int EncKeySize, const Sbtypes::ByteArray EncKeyAlgOID, const Sbtypes::ByteArray EncKeyAlgParams);
	__property TSBRSAPublicKeyCryptoType CryptoType = {read=FCryptoType, write=SetCryptoType, nodefault};
	__property bool UseAlgorithmPrefix = {read=FUseAlgorithmPrefix, write=SetUseAlgorithmPrefix, nodefault};
	__property Sbtypes::ByteArray HashFuncOID = {read=FHashFuncOID, write=SetHashFuncOID};
	__property int SaltSize = {read=GetSaltSize, write=SetSaltSize, nodefault};
	__property System::UnicodeString StrLabel = {read=GetStrLabel, write=SetStrLabel};
	__property int TrailerField = {read=GetTrailerField, write=SetTrailerField, nodefault};
	__property int MGFAlgorithm = {read=GetMGFAlgorithm, write=SetMGFAlgorithm, nodefault};
};

typedef TElRSAPublicKeyCrypto ElRSAPublicKeyCrypto
#pragma option push -b-
enum TSBDSAKeyFormat { dsaFIPS, dsaX509 };
#pragma option pop

class DELPHICLASS TElDSAKeyMaterial;
class PASCALIMPLEMENTATION TElDSAKeyMaterial : public TElPublicKeyMaterial
{
	typedef TElPublicKeyMaterial inherited;
	
protected:
	TSBDSAKeyFormat FKeyFormat;
	System::UnicodeString FPassphrase;
	bool FPEMEncode;
	void __fastcall Reset(void);
	virtual void __fastcall InternalGenerate(int Bits)/* overload */;
	HIDESBASE virtual void __fastcall InternalGenerate(int PBits, int QBits)/* overload */;
	virtual bool __fastcall GetValid(void);
	virtual int __fastcall GetBits(void);
	int __fastcall GetQBits(void);
	int __fastcall GetHashAlgorithm(void);
	void __fastcall SetHashAlgorithm(int Value);
	void __fastcall SetPassphrase(const System::UnicodeString Value);
	void __fastcall SetPEMEncode(bool Value);
	void __fastcall SetStrictKeyValidation(bool Value);
	bool __fastcall GetStrictKeyValidation(void);
	Sbtypes::ByteArray __fastcall GetP(void);
	Sbtypes::ByteArray __fastcall GetQ(void);
	Sbtypes::ByteArray __fastcall GetG(void);
	Sbtypes::ByteArray __fastcall GetX(void);
	Sbtypes::ByteArray __fastcall GetY(void);
	void __fastcall SetP(const Sbtypes::ByteArray Value);
	void __fastcall SetQ(const Sbtypes::ByteArray Value);
	void __fastcall SetG(const Sbtypes::ByteArray Value);
	void __fastcall SetY(const Sbtypes::ByteArray Value);
	void __fastcall SetX(const Sbtypes::ByteArray Value);
	
public:
	__fastcall virtual TElDSAKeyMaterial(Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual TElDSAKeyMaterial(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual ~TElDSAKeyMaterial(void);
	virtual void __fastcall Assign(Sbcustomcrypto::TElKeyMaterial* Source);
	virtual void __fastcall LoadParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	virtual void __fastcall SaveParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	virtual void __fastcall Generate(int Bits)/* overload */;
	HIDESBASE virtual void __fastcall Generate(int PBits, int QBits)/* overload */;
	HIDESBASE virtual void __fastcall BeginGenerate(int PBits, int QBits)/* overload */;
	virtual void __fastcall LoadSecret(void * Buffer, int Size)/* overload */;
	virtual void __fastcall SaveSecret(void * Buffer, int &Size)/* overload */;
	virtual void __fastcall LoadPublic(void * Buffer, int Size)/* overload */;
	virtual void __fastcall SavePublic(void * Buffer, int &Size)/* overload */;
	void __fastcall ImportPublicKey(void * P, int PSize, void * Q, int QSize, void * G, int GSize, void * Y, int YSize);
	void __fastcall ExportPublicKey(void * P, int &PSize, void * Q, int &QSize, void * G, int &GSize, void * Y, int &YSize);
	virtual void __fastcall LoadFromXML(const System::UnicodeString Str);
	virtual System::UnicodeString __fastcall SaveToXML(bool IncludePrivateKey = false);
	bool __fastcall EncodePrivateKey(void * P, int PSize, void * Q, int QSize, void * G, int GSize, void * Y, int YSize, void * X, int XSize, void * OutBuffer, int &OutSize)/* overload */;
	bool __fastcall DecodePrivateKey(void * Blob, int BlobSize, void * P, int &PSize, void * Q, int &QSize, void * G, int &GSize, void * Y, int &YSize, void * X, int &XSize);
	virtual Sbcustomcrypto::TElKeyMaterial* __fastcall Clone(void);
	virtual bool __fastcall Equals(Sbcustomcrypto::TElKeyMaterial* Source, bool PublicOnly)/* overload */;
	virtual void __fastcall ClearSecret(void);
	virtual void __fastcall ClearPublic(void);
	__property TSBDSAKeyFormat KeyFormat = {read=FKeyFormat, nodefault};
	__property int QBits = {read=GetQBits, nodefault};
	__property int HashAlgorithm = {read=GetHashAlgorithm, write=SetHashAlgorithm, nodefault};
	__property System::UnicodeString Passphrase = {read=FPassphrase, write=SetPassphrase};
	__property bool PEMEncode = {read=FPEMEncode, write=SetPEMEncode, nodefault};
	__property bool StrictKeyValidation = {read=GetStrictKeyValidation, write=SetStrictKeyValidation, nodefault};
	__property Sbtypes::ByteArray P = {read=GetP, write=SetP};
	__property Sbtypes::ByteArray Q = {read=GetQ, write=SetQ};
	__property Sbtypes::ByteArray G = {read=GetG, write=SetG};
	__property Sbtypes::ByteArray Y = {read=GetY, write=SetY};
	__property Sbtypes::ByteArray X = {read=GetX, write=SetX};
	
/* Hoisted overloads: */
	
public:
	inline void __fastcall  LoadSecret(Classes::TStream* Stream, int Count = 0x0){ TElPublicKeyMaterial::LoadSecret(Stream, Count); }
	inline void __fastcall  SaveSecret(Classes::TStream* Stream){ TElPublicKeyMaterial::SaveSecret(Stream); }
	inline void __fastcall  LoadPublic(Classes::TStream* Stream, int Count = 0x0){ TElPublicKeyMaterial::LoadPublic(Stream, Count); }
	inline void __fastcall  SavePublic(Classes::TStream* Stream){ TElPublicKeyMaterial::SavePublic(Stream); }
	inline bool __fastcall  Equals(System::TObject* Obj){ return Sbcustomcrypto::TElKeyMaterial::Equals(Obj); }
	
};

typedef TElDSAKeyMaterial ElDSAKeyMaterial
class DELPHICLASS TElDSAPublicKeyCrypto;
class PASCALIMPLEMENTATION TElDSAPublicKeyCrypto : public TElPublicKeyCrypto
{
	typedef TElPublicKeyCrypto inherited;
	
protected:
	Sbtypes::ByteArray FOID;
	Sbtypes::ByteArray FSpool;
	virtual void __fastcall SignInit(bool Detached);
	virtual void __fastcall SignUpdate(void * Buffer, int Size);
	virtual void __fastcall SignFinal(void);
	virtual void __fastcall VerifyInit(bool Detached, void * Signature, int SigSize);
	virtual void __fastcall VerifyUpdate(void * Buffer, int Size);
	virtual TSBPublicKeyVerificationResult __fastcall VerifyFinal(void);
	virtual int __fastcall EstimateOutputSize(void * InBuffer, int InSize, TSBPublicKeyOperation Operation);
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	__classmethod virtual System::UnicodeString __fastcall GetName();
	__classmethod virtual System::UnicodeString __fastcall GetDescription();
	HIDESBASE void __fastcall Reset(void);
	virtual void __fastcall AdjustContextProps(Sbrdn::TElRelativeDistinguishedName* Params);
	virtual bool __fastcall GetSupportsEncryption(void);
	virtual bool __fastcall GetSupportsSigning(void);
	virtual void __fastcall SetKeyMaterial(TElPublicKeyMaterial* Material);
	
public:
	__fastcall virtual TElDSAPublicKeyCrypto(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElDSAPublicKeyCrypto(int Alg, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElDSAPublicKeyCrypto(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElDSAPublicKeyCrypto(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElDSAPublicKeyCrypto(int Alg, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElDSAPublicKeyCrypto(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual ~TElDSAPublicKeyCrypto(void);
	virtual void __fastcall LoadParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	virtual void __fastcall SaveParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	void __fastcall EncodeSignature(void * R, int RSize, void * S, int SSize, void * Sig, int &SigSize);
	void __fastcall DecodeSignature(void * Sig, int SigSize, void * R, int &RSize, void * S, int &SSize);
};

typedef TElDSAPublicKeyCrypto ElDSAPublicKeyCrypto
class DELPHICLASS TElECKeyMaterial;
class PASCALIMPLEMENTATION TElECKeyMaterial : public TElPublicKeyMaterial
{
	typedef TElPublicKeyMaterial inherited;
	
protected:
	bool FSpecifiedCurve;
	bool FImplicitCurve;
	virtual void __fastcall InternalGenerate(int Bits)/* overload */;
	virtual bool __fastcall GetValid(void);
	virtual int __fastcall GetBits(void);
	int __fastcall GetFieldBits(void);
	int __fastcall GetHashAlgorithm(void);
	int __fastcall GetRecommendedHashAlgorithm(void);
	void __fastcall SetHashAlgorithm(int Value);
	Sbtypes::ByteArray __fastcall GetA(void);
	void __fastcall SetA(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetB(void);
	void __fastcall SetB(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetP(void);
	void __fastcall SetP(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetN(void);
	void __fastcall SetN(const Sbtypes::ByteArray Value);
	int __fastcall GetH(void);
	void __fastcall SetH(int Value);
	Sbtypes::ByteArray __fastcall GetX(void);
	void __fastcall SetX(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetY(void);
	void __fastcall SetY(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetQX(void);
	void __fastcall SetQX(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetQY(void);
	void __fastcall SetQY(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetQ(void);
	void __fastcall SetQ(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetD(void);
	void __fastcall SetD(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetBase(void);
	void __fastcall SetBase(const Sbtypes::ByteArray Value);
	int __fastcall GetCurve(void);
	void __fastcall SetCurve(int Value);
	Sbtypes::ByteArray __fastcall GetCurveOID(void);
	void __fastcall SetCurveOID(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetSeed(void);
	void __fastcall SetSeed(const Sbtypes::ByteArray Value);
	int __fastcall GetFieldType(void);
	void __fastcall SetFieldType(int Value);
	int __fastcall GetM(void);
	void __fastcall SetM(int Value);
	int __fastcall GetK1(void);
	void __fastcall SetK1(int Value);
	int __fastcall GetK2(void);
	void __fastcall SetK2(int Value);
	int __fastcall GetK3(void);
	void __fastcall SetK3(int Value);
	bool __fastcall GetCompressPoints(void);
	void __fastcall SetCompressPoints(bool Value);
	bool __fastcall GetHybridPoints(void);
	void __fastcall SetHybridPoints(bool Value);
	
public:
	__fastcall virtual TElECKeyMaterial(Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual TElECKeyMaterial(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual ~TElECKeyMaterial(void);
	virtual void __fastcall Assign(Sbcustomcrypto::TElKeyMaterial* Source);
	HIDESBASE virtual void __fastcall Generate(void)/* overload */;
	virtual void __fastcall LoadParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	virtual void __fastcall SaveParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	virtual void __fastcall LoadSecret(void * Buffer, int Size)/* overload */;
	virtual void __fastcall SaveSecret(void * Buffer, int &Size)/* overload */;
	virtual void __fastcall LoadPublic(void * Buffer, int Size)/* overload */;
	virtual void __fastcall SavePublic(void * Buffer, int &Size)/* overload */;
	void __fastcall ImportPublicKey(void * QX, int QXSize, void * QY, int QYSize);
	void __fastcall ExportPublicKey(void * QX, int &QXSize, void * QY, int &QYSize);
	virtual Sbcustomcrypto::TElKeyMaterial* __fastcall Clone(void);
	virtual bool __fastcall Equals(Sbcustomcrypto::TElKeyMaterial* Source, bool PublicOnly)/* overload */;
	virtual void __fastcall ClearSecret(void);
	virtual void __fastcall ClearPublic(void);
	__property bool CompressPoints = {read=GetCompressPoints, write=SetCompressPoints, nodefault};
	__property bool HybridPoints = {read=GetHybridPoints, write=SetHybridPoints, nodefault};
	__property int FieldType = {read=GetFieldType, write=SetFieldType, nodefault};
	__property int FieldBits = {read=GetFieldBits, nodefault};
	__property int M = {read=GetM, write=SetM, nodefault};
	__property int K1 = {read=GetK1, write=SetK1, nodefault};
	__property int K2 = {read=GetK2, write=SetK2, nodefault};
	__property int K3 = {read=GetK3, write=SetK3, nodefault};
	__property int HashAlgorithm = {read=GetHashAlgorithm, write=SetHashAlgorithm, nodefault};
	__property int RecommendedHashAlgorithm = {read=GetRecommendedHashAlgorithm, nodefault};
	__property Sbtypes::ByteArray D = {read=GetD, write=SetD};
	__property Sbtypes::ByteArray N = {read=GetN, write=SetN};
	__property int H = {read=GetH, write=SetH, nodefault};
	__property Sbtypes::ByteArray A = {read=GetA, write=SetA};
	__property Sbtypes::ByteArray B = {read=GetB, write=SetB};
	__property Sbtypes::ByteArray X = {read=GetX, write=SetX};
	__property Sbtypes::ByteArray Y = {read=GetY, write=SetY};
	__property Sbtypes::ByteArray Q = {read=GetQ, write=SetQ};
	__property Sbtypes::ByteArray QX = {read=GetQX, write=SetQX};
	__property Sbtypes::ByteArray QY = {read=GetQY, write=SetQY};
	__property Sbtypes::ByteArray Base = {read=GetBase, write=SetBase};
	__property Sbtypes::ByteArray P = {read=GetP, write=SetP};
	__property int Curve = {read=GetCurve, write=SetCurve, nodefault};
	__property Sbtypes::ByteArray CurveOID = {read=GetCurveOID, write=SetCurveOID};
	__property bool SpecifiedCurve = {read=FSpecifiedCurve, write=FSpecifiedCurve, nodefault};
	__property bool ImplicitCurve = {read=FImplicitCurve, write=FImplicitCurve, nodefault};
	__property Sbtypes::ByteArray Seed = {read=GetSeed, write=SetSeed};
	
/* Hoisted overloads: */
	
public:
	inline void __fastcall  LoadSecret(Classes::TStream* Stream, int Count = 0x0){ TElPublicKeyMaterial::LoadSecret(Stream, Count); }
	inline void __fastcall  SaveSecret(Classes::TStream* Stream){ TElPublicKeyMaterial::SaveSecret(Stream); }
	inline void __fastcall  LoadPublic(Classes::TStream* Stream, int Count = 0x0){ TElPublicKeyMaterial::LoadPublic(Stream, Count); }
	inline void __fastcall  SavePublic(Classes::TStream* Stream){ TElPublicKeyMaterial::SavePublic(Stream); }
	inline bool __fastcall  Equals(System::TObject* Obj){ return Sbcustomcrypto::TElKeyMaterial::Equals(Obj); }
	
};


class DELPHICLASS TElECDSAPublicKeyCrypto;
class PASCALIMPLEMENTATION TElECDSAPublicKeyCrypto : public TElPublicKeyCrypto
{
	typedef TElPublicKeyCrypto inherited;
	
protected:
	Sbtypes::ByteArray FOID;
	Sbtypes::ByteArray FSpool;
	virtual void __fastcall SignInit(bool Detached);
	virtual void __fastcall SignUpdate(void * Buffer, int Size);
	virtual void __fastcall SignFinal(void);
	virtual void __fastcall VerifyInit(bool Detached, void * Signature, int SigSize);
	virtual void __fastcall VerifyUpdate(void * Buffer, int Size);
	virtual TSBPublicKeyVerificationResult __fastcall VerifyFinal(void);
	virtual int __fastcall EstimateOutputSize(void * InBuffer, int InSize, TSBPublicKeyOperation Operation);
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	__classmethod virtual System::UnicodeString __fastcall GetName();
	__classmethod virtual System::UnicodeString __fastcall GetDescription();
	HIDESBASE void __fastcall Reset(void);
	virtual void __fastcall AdjustContextProps(Sbrdn::TElRelativeDistinguishedName* Params);
	virtual bool __fastcall GetSupportsEncryption(void);
	virtual bool __fastcall GetSupportsSigning(void);
	virtual void __fastcall SetKeyMaterial(TElPublicKeyMaterial* Material);
	
public:
	__fastcall virtual TElECDSAPublicKeyCrypto(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElECDSAPublicKeyCrypto(int Alg, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElECDSAPublicKeyCrypto(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElECDSAPublicKeyCrypto(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElECDSAPublicKeyCrypto(int Alg, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElECDSAPublicKeyCrypto(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual ~TElECDSAPublicKeyCrypto(void);
	virtual void __fastcall LoadParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	virtual void __fastcall SaveParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	void __fastcall EncodeSignature(void * R, int RSize, void * S, int SSize, void * Sig, int &SigSize);
	void __fastcall DecodeSignature(void * Sig, int SigSize, void * R, int &RSize, void * S, int &SSize);
};


class DELPHICLASS TElECDHPublicKeyCrypto;
class PASCALIMPLEMENTATION TElECDHPublicKeyCrypto : public TElPublicKeyCrypto
{
	typedef TElPublicKeyCrypto inherited;
	
protected:
	Sbtypes::ByteArray FSpool;
	virtual void __fastcall EncryptInit(void);
	virtual void __fastcall EncryptUpdate(void * Buffer, int Size);
	virtual void __fastcall EncryptFinal(void);
	virtual void __fastcall DecryptInit(void);
	virtual void __fastcall DecryptUpdate(void * Buffer, int Size);
	virtual void __fastcall DecryptFinal(void);
	virtual int __fastcall EstimateOutputSize(void * InBuffer, int InSize, TSBPublicKeyOperation Operation);
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	__classmethod virtual System::UnicodeString __fastcall GetName();
	__classmethod virtual System::UnicodeString __fastcall GetDescription();
	virtual bool __fastcall GetSupportsEncryption(void);
	virtual bool __fastcall GetSupportsSigning(void);
	virtual void __fastcall SetKeyMaterial(TElPublicKeyMaterial* Material);
	
public:
	__fastcall virtual TElECDHPublicKeyCrypto(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElECDHPublicKeyCrypto(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElECDHPublicKeyCrypto(int Alg, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElECDHPublicKeyCrypto(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElECDHPublicKeyCrypto(int Alg, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElECDHPublicKeyCrypto(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual ~TElECDHPublicKeyCrypto(void);
	virtual void __fastcall LoadParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	virtual void __fastcall SaveParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
};


#pragma option push -b-
enum TSBDHKeyFormat { dhRaw, dhX509 };
#pragma option pop

class DELPHICLASS TElDHKeyMaterial;
class PASCALIMPLEMENTATION TElDHKeyMaterial : public TElPublicKeyMaterial
{
	typedef TElPublicKeyMaterial inherited;
	
protected:
	TSBDHKeyFormat FKeyFormat;
	void __fastcall Reset(void);
	virtual void __fastcall InternalGenerate(int Bits);
	virtual bool __fastcall GetValid(void);
	virtual int __fastcall GetBits(void);
	Sbtypes::ByteArray __fastcall GetP(void);
	Sbtypes::ByteArray __fastcall GetG(void);
	Sbtypes::ByteArray __fastcall GetX(void);
	Sbtypes::ByteArray __fastcall GetY(void);
	Sbtypes::ByteArray __fastcall GetPeerY(void);
	void __fastcall SetP(const Sbtypes::ByteArray Value);
	void __fastcall SetG(const Sbtypes::ByteArray Value);
	void __fastcall SetX(const Sbtypes::ByteArray Value);
	void __fastcall SetY(const Sbtypes::ByteArray Value);
	void __fastcall SetPeerY(const Sbtypes::ByteArray Value);
	
public:
	__fastcall virtual TElDHKeyMaterial(Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual TElDHKeyMaterial(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual ~TElDHKeyMaterial(void);
	virtual void __fastcall LoadParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	virtual void __fastcall SaveParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	HIDESBASE void __fastcall LoadPublic(void * P, int PSize, void * G, int GSize, void * Y, int YSize)/* overload */;
	virtual void __fastcall SavePublic(void * Buffer, int &Size)/* overload */;
	virtual void __fastcall SaveSecret(void * Buffer, int &Size)/* overload */;
	virtual void __fastcall LoadSecret(void * Buffer, int Size)/* overload */;
	void __fastcall LoadPeerY(void * Y, int YSize);
	virtual void __fastcall LoadFromXML(const System::UnicodeString Str);
	virtual System::UnicodeString __fastcall SaveToXML(bool IncludePrivateKey = false);
	virtual void __fastcall Assign(Sbcustomcrypto::TElKeyMaterial* Source);
	virtual Sbcustomcrypto::TElKeyMaterial* __fastcall Clone(void);
	virtual bool __fastcall Equals(Sbcustomcrypto::TElKeyMaterial* Source, bool PublicOnly)/* overload */;
	virtual void __fastcall ClearSecret(void);
	virtual void __fastcall ClearPublic(void);
	__property TSBDHKeyFormat KeyFormat = {read=FKeyFormat, nodefault};
	__property Sbtypes::ByteArray P = {read=GetP, write=SetP};
	__property Sbtypes::ByteArray G = {read=GetG, write=SetG};
	__property Sbtypes::ByteArray X = {read=GetX, write=SetX};
	__property Sbtypes::ByteArray Y = {read=GetY, write=SetY};
	__property Sbtypes::ByteArray PeerY = {read=GetPeerY, write=SetPeerY};
	
/* Hoisted overloads: */
	
public:
	inline void __fastcall  LoadPublic(void * Buffer, int Size){ TElPublicKeyMaterial::LoadPublic(Buffer, Size); }
	inline void __fastcall  LoadPublic(Classes::TStream* Stream, int Count = 0x0){ TElPublicKeyMaterial::LoadPublic(Stream, Count); }
	inline void __fastcall  SavePublic(Classes::TStream* Stream){ TElPublicKeyMaterial::SavePublic(Stream); }
	inline void __fastcall  SaveSecret(Classes::TStream* Stream){ TElPublicKeyMaterial::SaveSecret(Stream); }
	inline void __fastcall  LoadSecret(Classes::TStream* Stream, int Count = 0x0){ TElPublicKeyMaterial::LoadSecret(Stream, Count); }
	inline bool __fastcall  Equals(System::TObject* Obj){ return Sbcustomcrypto::TElKeyMaterial::Equals(Obj); }
	
};

typedef TElDHKeyMaterial ElDHKeyMaterial
#pragma option push -b-
enum TSBDHPublicKeyCryptoType { dhpktPKCS1, dhpktRaw };
#pragma option pop

class DELPHICLASS TElDHPublicKeyCrypto;
class PASCALIMPLEMENTATION TElDHPublicKeyCrypto : public TElPublicKeyCrypto
{
	typedef TElPublicKeyCrypto inherited;
	
protected:
	Sbtypes::ByteArray FSpool;
	TSBDHPublicKeyCryptoType FCryptoType;
	virtual void __fastcall EncryptInit(void);
	virtual void __fastcall EncryptUpdate(void * Buffer, int Size);
	virtual void __fastcall EncryptFinal(void);
	virtual void __fastcall DecryptInit(void);
	virtual void __fastcall DecryptUpdate(void * Buffer, int Size);
	virtual void __fastcall DecryptFinal(void);
	virtual int __fastcall EstimateOutputSize(void * InBuffer, int InSize, TSBPublicKeyOperation Operation);
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	__classmethod virtual System::UnicodeString __fastcall GetName();
	__classmethod virtual System::UnicodeString __fastcall GetDescription();
	void __fastcall SetCryptoType(TSBDHPublicKeyCryptoType Value);
	virtual bool __fastcall GetSupportsEncryption(void);
	virtual bool __fastcall GetSupportsSigning(void);
	virtual void __fastcall SetKeyMaterial(TElPublicKeyMaterial* Material);
	
public:
	__fastcall virtual TElDHPublicKeyCrypto(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElDHPublicKeyCrypto(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElDHPublicKeyCrypto(int Alg, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElDHPublicKeyCrypto(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElDHPublicKeyCrypto(int Alg, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElDHPublicKeyCrypto(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual ~TElDHPublicKeyCrypto(void);
	virtual void __fastcall LoadParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	virtual void __fastcall SaveParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	__property TSBDHPublicKeyCryptoType CryptoType = {read=FCryptoType, write=SetCryptoType, nodefault};
};

typedef TElDHPublicKeyCrypto ElDHPublicKeyCrypto
class DELPHICLASS TElElGamalKeyMaterial;
class PASCALIMPLEMENTATION TElElGamalKeyMaterial : public TElPublicKeyMaterial
{
	typedef TElPublicKeyMaterial inherited;
	
protected:
	void __fastcall Reset(void);
	virtual void __fastcall InternalGenerate(int Bits);
	virtual bool __fastcall GetValid(void);
	virtual int __fastcall GetBits(void);
	Sbtypes::ByteArray __fastcall GetP(void);
	Sbtypes::ByteArray __fastcall GetG(void);
	Sbtypes::ByteArray __fastcall GetY(void);
	Sbtypes::ByteArray __fastcall GetX(void);
	
public:
	__fastcall virtual TElElGamalKeyMaterial(Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual TElElGamalKeyMaterial(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual ~TElElGamalKeyMaterial(void);
	virtual void __fastcall Assign(Sbcustomcrypto::TElKeyMaterial* Source);
	virtual Sbcustomcrypto::TElKeyMaterial* __fastcall Clone(void);
	HIDESBASE void __fastcall LoadPublic(void * P, int PSize, void * G, int GSize, void * Y, int YSize);
	HIDESBASE void __fastcall LoadSecret(void * P, int PSize, void * G, int GSize, void * Y, int YSize, void * X, int XSize);
	virtual void __fastcall SavePublic(void * Buffer, int &Size)/* overload */;
	virtual void __fastcall SaveSecret(void * Buffer, int &Size)/* overload */;
	virtual void __fastcall LoadFromXML(const System::UnicodeString Str);
	virtual System::UnicodeString __fastcall SaveToXML(bool IncludePrivateKey = false);
	virtual bool __fastcall Equals(Sbcustomcrypto::TElKeyMaterial* Source, bool PublicOnly)/* overload */;
	virtual void __fastcall ClearSecret(void);
	virtual void __fastcall ClearPublic(void);
	__property Sbtypes::ByteArray P = {read=GetP};
	__property Sbtypes::ByteArray G = {read=GetG};
	__property Sbtypes::ByteArray Y = {read=GetY};
	__property Sbtypes::ByteArray X = {read=GetX};
	
/* Hoisted overloads: */
	
public:
	inline void __fastcall  SavePublic(Classes::TStream* Stream){ TElPublicKeyMaterial::SavePublic(Stream); }
	inline void __fastcall  SaveSecret(Classes::TStream* Stream){ TElPublicKeyMaterial::SaveSecret(Stream); }
	inline bool __fastcall  Equals(System::TObject* Obj){ return Sbcustomcrypto::TElKeyMaterial::Equals(Obj); }
	
};

typedef TElElGamalKeyMaterial ElElGamalKeyMaterial
class DELPHICLASS TElElGamalPublicKeyCrypto;
class PASCALIMPLEMENTATION TElElGamalPublicKeyCrypto : public TElPublicKeyCrypto
{
	typedef TElPublicKeyCrypto inherited;
	
protected:
	Sbtypes::ByteArray FSpool;
	virtual void __fastcall AdjustContextProps(Sbrdn::TElRelativeDistinguishedName* Params);
	virtual void __fastcall SignInit(bool Detached);
	virtual void __fastcall SignUpdate(void * Buffer, int Size);
	virtual void __fastcall SignFinal(void);
	virtual void __fastcall EncryptInit(void);
	virtual void __fastcall EncryptUpdate(void * Buffer, int Size);
	virtual void __fastcall EncryptFinal(void);
	virtual void __fastcall DecryptInit(void);
	virtual void __fastcall DecryptUpdate(void * Buffer, int Size);
	virtual void __fastcall DecryptFinal(void);
	virtual void __fastcall VerifyInit(bool Detached, void * Signature, int SigSize);
	virtual void __fastcall VerifyUpdate(void * Buffer, int Size);
	virtual TSBPublicKeyVerificationResult __fastcall VerifyFinal(void);
	virtual int __fastcall EstimateOutputSize(void * InBuffer, int InSize, TSBPublicKeyOperation Operation);
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	__classmethod virtual System::UnicodeString __fastcall GetName();
	__classmethod virtual System::UnicodeString __fastcall GetDescription();
	HIDESBASE void __fastcall Reset(void);
	virtual bool __fastcall GetSupportsEncryption(void);
	virtual bool __fastcall GetSupportsSigning(void);
	virtual void __fastcall SetKeyMaterial(TElPublicKeyMaterial* Material);
	
public:
	__fastcall virtual TElElGamalPublicKeyCrypto(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElElGamalPublicKeyCrypto(int Alg, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElElGamalPublicKeyCrypto(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElElGamalPublicKeyCrypto(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElElGamalPublicKeyCrypto(int Alg, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElElGamalPublicKeyCrypto(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual ~TElElGamalPublicKeyCrypto(void);
	void __fastcall EncodeResult(void * A, int ASize, void * B, int BSize, void * Blob, int &BlobSize);
	void __fastcall DecodeResult(void * Blob, int BlobSize, void * A, int &ASize, void * B, int &BSize);
};

typedef TElElGamalPublicKeyCrypto ElElGamalPublicKeyCrypto
class DELPHICLASS TElSRPKeyMaterial;
class PASCALIMPLEMENTATION TElSRPKeyMaterial : public TElPublicKeyMaterial
{
	typedef TElPublicKeyMaterial inherited;
	
protected:
	Sbsrp::TSRPContext FSRPContext;
	Sbtypes::ByteArray __fastcall GetSalt(void);
	Sbtypes::ByteArray __fastcall GetN(void);
	Sbtypes::ByteArray __fastcall GetG(void);
	Sbtypes::ByteArray __fastcall GetX(void);
	Sbtypes::ByteArray __fastcall GetA(void);
	Sbtypes::ByteArray __fastcall GetK(void);
	Sbtypes::ByteArray __fastcall GetA_small(void);
	Sbtypes::ByteArray __fastcall GetB(void);
	Sbtypes::ByteArray __fastcall GetB_small(void);
	Sbtypes::ByteArray __fastcall GetV(void);
	Sbtypes::ByteArray __fastcall GetU(void);
	Sbtypes::ByteArray __fastcall GetS(void);
	
public:
	__fastcall virtual TElSRPKeyMaterial(Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual TElSRPKeyMaterial(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual ~TElSRPKeyMaterial(void);
	virtual void __fastcall Assign(Sbcustomcrypto::TElKeyMaterial* Source);
	HIDESBASE bool __fastcall LoadPublic(Sbtypes::ByteArray N, Sbtypes::ByteArray G, Sbtypes::ByteArray Salt, Sbtypes::ByteArray V)/* overload */;
	HIDESBASE bool __fastcall LoadPublic(void * Buffer, int Len)/* overload */;
	virtual Sbcustomcrypto::TElKeyMaterial* __fastcall Clone(void);
	__property Sbtypes::ByteArray Salt = {read=GetSalt};
	__property Sbtypes::ByteArray N = {read=GetN};
	__property Sbtypes::ByteArray G = {read=GetG};
	__property Sbtypes::ByteArray X = {read=GetX};
	__property Sbtypes::ByteArray A = {read=GetA};
	__property Sbtypes::ByteArray K = {read=GetK};
	__property Sbtypes::ByteArray A_small = {read=GetA_small};
	__property Sbtypes::ByteArray B = {read=GetB};
	__property Sbtypes::ByteArray B_small = {read=GetB_small};
	__property Sbtypes::ByteArray V = {read=GetV};
	__property Sbtypes::ByteArray U = {read=GetU};
	__property Sbtypes::ByteArray S = {read=GetS};
	
/* Hoisted overloads: */
	
public:
	inline void __fastcall  LoadPublic(Classes::TStream* Stream, int Count = 0x0){ TElPublicKeyMaterial::LoadPublic(Stream, Count); }
	
};


class DELPHICLASS TElSRPPublicKeyCrypto;
class PASCALIMPLEMENTATION TElSRPPublicKeyCrypto : public TElPublicKeyCrypto
{
	typedef TElPublicKeyCrypto inherited;
	
protected:
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	__classmethod virtual System::UnicodeString __fastcall GetName();
	__classmethod virtual System::UnicodeString __fastcall GetDescription();
	virtual bool __fastcall GetSupportsEncryption(void);
	virtual bool __fastcall GetSupportsSigning(void);
	virtual void __fastcall SetKeyMaterial(TElPublicKeyMaterial* Material);
	
public:
	__fastcall virtual TElSRPPublicKeyCrypto(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElSRPPublicKeyCrypto(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElSRPPublicKeyCrypto(int Alg, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElSRPPublicKeyCrypto(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElSRPPublicKeyCrypto(int Alg, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElSRPPublicKeyCrypto(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	void __fastcall GetServerKey(const Sbtypes::ByteArray Buffer, int Index, int Len, Sbtypes::ByteArray &Master);
	void __fastcall GetClientKeyParam(const System::UnicodeString UserName, const System::UnicodeString UserPassword, Sbtypes::ByteArray &A);
public:
	/* TElPublicKeyCrypto.Destroy */ inline __fastcall virtual ~TElSRPPublicKeyCrypto(void) { }
	
};


class DELPHICLASS TElGOST94KeyMaterial;
class PASCALIMPLEMENTATION TElGOST94KeyMaterial : public TElPublicKeyMaterial
{
	typedef TElPublicKeyMaterial inherited;
	
protected:
	void __fastcall Reset(void);
	virtual void __fastcall InternalGenerate(int Bits);
	virtual bool __fastcall GetValid(void);
	virtual int __fastcall GetBits(void);
	Sbtypes::ByteArray __fastcall GetP(void);
	Sbtypes::ByteArray __fastcall GetQ(void);
	Sbtypes::ByteArray __fastcall GetA(void);
	Sbtypes::ByteArray __fastcall GetX(void);
	void __fastcall SetX(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetY(void);
	void __fastcall SetY(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetProp(Sbtypes::ByteArray PropID);
	Sbtypes::ByteArray __fastcall GetParamSet(void);
	void __fastcall SetParamSet(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetDigestParamSet(void);
	void __fastcall SetDigestParamSet(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetEncryptionParamSet(void);
	void __fastcall SetEncryptionParamSet(const Sbtypes::ByteArray Value);
	
public:
	__fastcall virtual TElGOST94KeyMaterial(Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual TElGOST94KeyMaterial(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual ~TElGOST94KeyMaterial(void);
	virtual void __fastcall Assign(Sbcustomcrypto::TElKeyMaterial* Source);
	virtual Sbcustomcrypto::TElKeyMaterial* __fastcall Clone(void);
	virtual void __fastcall LoadSecret(void * Buffer, int Size)/* overload */;
	virtual void __fastcall SaveSecret(void * Buffer, int &Size)/* overload */;
	virtual void __fastcall LoadPublic(void * Buffer, int Size)/* overload */;
	virtual void __fastcall SavePublic(void * Buffer, int &Size)/* overload */;
	HIDESBASE void __fastcall LoadPublic(void * P, int PSize, void * Q, int QSize, void * A, int ASize, void * Y, int YSize)/* overload */;
	HIDESBASE void __fastcall LoadSecret(void * P, int PSize, void * Q, int QSize, void * A, int ASize, void * Y, int YSize, void * X, int XSize)/* overload */;
	HIDESBASE void __fastcall LoadPublic(const Sbtypes::ByteArray P, int PIndex, int PSize, const Sbtypes::ByteArray Q, int QIndex, int QSize, const Sbtypes::ByteArray A, int AIndex, int ASize, const Sbtypes::ByteArray Y, int YIndex, int YSize)/* overload */;
	HIDESBASE void __fastcall LoadSecret(const Sbtypes::ByteArray P, int PIndex, int PSize, const Sbtypes::ByteArray Q, int QIndex, int QSize, const Sbtypes::ByteArray A, int AIndex, int ASize, const Sbtypes::ByteArray Y, int YIndex, int YSize, const Sbtypes::ByteArray X, int XIndex, int XSize)/* overload */;
	virtual void __fastcall LoadFromXML(const System::UnicodeString Str);
	virtual System::UnicodeString __fastcall SaveToXML(bool IncludePrivateKey = false);
	virtual bool __fastcall Equals(Sbcustomcrypto::TElKeyMaterial* Source, bool PublicOnly)/* overload */;
	virtual void __fastcall ClearSecret(void);
	virtual void __fastcall ClearPublic(void);
	virtual void __fastcall LoadParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	virtual void __fastcall SaveParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	__property Sbtypes::ByteArray P = {read=GetP};
	__property Sbtypes::ByteArray Q = {read=GetQ};
	__property Sbtypes::ByteArray A = {read=GetA};
	__property Sbtypes::ByteArray Y = {read=GetY, write=SetY};
	__property Sbtypes::ByteArray X = {read=GetX, write=SetX};
	__property Sbtypes::ByteArray ParamSet = {read=GetParamSet, write=SetParamSet};
	__property Sbtypes::ByteArray DigestParamSet = {read=GetDigestParamSet, write=SetDigestParamSet};
	__property Sbtypes::ByteArray EncryptionParamSet = {read=GetEncryptionParamSet, write=SetEncryptionParamSet};
	
/* Hoisted overloads: */
	
public:
	inline void __fastcall  LoadSecret(Classes::TStream* Stream, int Count = 0x0){ TElPublicKeyMaterial::LoadSecret(Stream, Count); }
	inline void __fastcall  SaveSecret(Classes::TStream* Stream){ TElPublicKeyMaterial::SaveSecret(Stream); }
	inline void __fastcall  LoadPublic(Classes::TStream* Stream, int Count = 0x0){ TElPublicKeyMaterial::LoadPublic(Stream, Count); }
	inline void __fastcall  SavePublic(Classes::TStream* Stream){ TElPublicKeyMaterial::SavePublic(Stream); }
	inline bool __fastcall  Equals(System::TObject* Obj){ return Sbcustomcrypto::TElKeyMaterial::Equals(Obj); }
	
};

typedef TElGOST94KeyMaterial ElGOST94KeyMaterial
class DELPHICLASS TElGOST94PublicKeyCrypto;
class PASCALIMPLEMENTATION TElGOST94PublicKeyCrypto : public TElPublicKeyCrypto
{
	typedef TElPublicKeyCrypto inherited;
	
protected:
	Sbtypes::ByteArray FSpool;
	virtual void __fastcall AdjustContextProps(Sbrdn::TElRelativeDistinguishedName* Params);
	virtual void __fastcall SignInit(bool Detached);
	virtual void __fastcall SignUpdate(void * Buffer, int Size);
	virtual void __fastcall SignFinal(void);
	virtual void __fastcall VerifyInit(bool Detached, void * Signature, int SigSize);
	virtual void __fastcall VerifyUpdate(void * Buffer, int Size);
	virtual TSBPublicKeyVerificationResult __fastcall VerifyFinal(void);
	virtual int __fastcall EstimateOutputSize(void * InBuffer, int InSize, TSBPublicKeyOperation Operation);
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	__classmethod virtual System::UnicodeString __fastcall GetName();
	__classmethod virtual System::UnicodeString __fastcall GetDescription();
	HIDESBASE void __fastcall Reset(void);
	virtual bool __fastcall GetSupportsEncryption(void);
	virtual bool __fastcall GetSupportsSigning(void);
	virtual void __fastcall SetKeyMaterial(TElPublicKeyMaterial* Material);
	
public:
	__fastcall virtual TElGOST94PublicKeyCrypto(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElGOST94PublicKeyCrypto(int Alg, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElGOST94PublicKeyCrypto(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElGOST94PublicKeyCrypto(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElGOST94PublicKeyCrypto(int Alg, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElGOST94PublicKeyCrypto(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual ~TElGOST94PublicKeyCrypto(void);
};

typedef TElGOST94PublicKeyCrypto ElGOST94PublicKeyCrypto
class DELPHICLASS TElGOST2001KeyMaterial;
class PASCALIMPLEMENTATION TElGOST2001KeyMaterial : public TElPublicKeyMaterial
{
	typedef TElPublicKeyMaterial inherited;
	
protected:
	void __fastcall Reset(void);
	virtual void __fastcall InternalGenerate(int Bits)/* overload */;
	virtual int __fastcall GetBits(void);
	virtual bool __fastcall GetValid(void);
	Sbtypes::ByteArray __fastcall GetQ(void);
	void __fastcall SetQ(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetD(void);
	void __fastcall SetD(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetParamSet(void);
	void __fastcall SetParamSet(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetDigestParamSet(void);
	void __fastcall SetDigestParamSet(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetEncryptionParamSet(void);
	void __fastcall SetEncryptionParamSet(const Sbtypes::ByteArray Value);
	
public:
	__fastcall virtual TElGOST2001KeyMaterial(Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual TElGOST2001KeyMaterial(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* Prov)/* overload */;
	__fastcall virtual ~TElGOST2001KeyMaterial(void);
	virtual void __fastcall Assign(Sbcustomcrypto::TElKeyMaterial* Source);
	HIDESBASE virtual void __fastcall Generate(void)/* overload */;
	virtual void __fastcall LoadParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	virtual void __fastcall SaveParameters(Sbalgorithmidentifier::TElAlgorithmIdentifier* AlgorithmIdentifier);
	virtual void __fastcall LoadSecret(void * Buffer, int Size)/* overload */;
	virtual void __fastcall SaveSecret(void * Buffer, int &Size)/* overload */;
	virtual void __fastcall LoadPublic(void * Buffer, int Size)/* overload */;
	virtual void __fastcall SavePublic(void * Buffer, int &Size)/* overload */;
	virtual Sbcustomcrypto::TElKeyMaterial* __fastcall Clone(void);
	virtual bool __fastcall Equals(Sbcustomcrypto::TElKeyMaterial* Source, bool PublicOnly)/* overload */;
	virtual void __fastcall ClearSecret(void);
	virtual void __fastcall ClearPublic(void);
	__property Sbtypes::ByteArray Q = {read=GetQ, write=SetQ};
	__property Sbtypes::ByteArray D = {read=GetD, write=SetD};
	__property Sbtypes::ByteArray ParamSet = {read=GetParamSet, write=SetParamSet};
	__property Sbtypes::ByteArray DigestParamSet = {read=GetDigestParamSet, write=SetDigestParamSet};
	__property Sbtypes::ByteArray EncryptionParamSet = {read=GetEncryptionParamSet, write=SetEncryptionParamSet};
	
/* Hoisted overloads: */
	
public:
	inline void __fastcall  LoadSecret(Classes::TStream* Stream, int Count = 0x0){ TElPublicKeyMaterial::LoadSecret(Stream, Count); }
	inline void __fastcall  SaveSecret(Classes::TStream* Stream){ TElPublicKeyMaterial::SaveSecret(Stream); }
	inline void __fastcall  LoadPublic(Classes::TStream* Stream, int Count = 0x0){ TElPublicKeyMaterial::LoadPublic(Stream, Count); }
	inline void __fastcall  SavePublic(Classes::TStream* Stream){ TElPublicKeyMaterial::SavePublic(Stream); }
	inline bool __fastcall  Equals(System::TObject* Obj){ return Sbcustomcrypto::TElKeyMaterial::Equals(Obj); }
	
};

typedef TElGOST2001KeyMaterial ElGOST2001KeyMaterial
class DELPHICLASS TElGOST2001PublicKeyCrypto;
class PASCALIMPLEMENTATION TElGOST2001PublicKeyCrypto : public TElPublicKeyCrypto
{
	typedef TElPublicKeyCrypto inherited;
	
protected:
	Sbtypes::ByteArray FSpool;
	Sbtypes::ByteArray FUKM;
	Sbtypes::ByteArray FEphemeralKey;
	Sbtypes::ByteArray FCEKMAC;
	virtual void __fastcall AdjustContextProps(Sbrdn::TElRelativeDistinguishedName* Params);
	virtual void __fastcall SaveContextProps(void);
	virtual void __fastcall SignInit(bool Detached);
	virtual void __fastcall SignUpdate(void * Buffer, int Size);
	virtual void __fastcall SignFinal(void);
	virtual void __fastcall VerifyInit(bool Detached, void * Signature, int SigSize);
	virtual void __fastcall VerifyUpdate(void * Buffer, int Size);
	virtual TSBPublicKeyVerificationResult __fastcall VerifyFinal(void);
	virtual void __fastcall EncryptInit(void);
	virtual void __fastcall EncryptUpdate(void * Buffer, int Size);
	virtual void __fastcall EncryptFinal(void);
	virtual void __fastcall DecryptInit(void);
	virtual void __fastcall DecryptUpdate(void * Buffer, int Size);
	virtual void __fastcall DecryptFinal(void);
	virtual int __fastcall EstimateOutputSize(void * InBuffer, int InSize, TSBPublicKeyOperation Operation);
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	__classmethod virtual System::UnicodeString __fastcall GetName();
	__classmethod virtual System::UnicodeString __fastcall GetDescription();
	HIDESBASE void __fastcall Reset(void);
	virtual bool __fastcall GetSupportsEncryption(void);
	virtual bool __fastcall GetSupportsSigning(void);
	virtual void __fastcall SetKeyMaterial(TElPublicKeyMaterial* Material);
	void __fastcall SetUKM(const Sbtypes::ByteArray V);
	void __fastcall SetEphemeralKey(const Sbtypes::ByteArray V);
	void __fastcall SetCEKMAC(const Sbtypes::ByteArray V);
	
public:
	__fastcall virtual TElGOST2001PublicKeyCrypto(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElGOST2001PublicKeyCrypto(int Alg, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElGOST2001PublicKeyCrypto(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElGOST2001PublicKeyCrypto(const Sbtypes::ByteArray OID, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElGOST2001PublicKeyCrypto(int Alg, Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual TElGOST2001PublicKeyCrypto(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual ~TElGOST2001PublicKeyCrypto(void);
	__property Sbtypes::ByteArray UKM = {read=FUKM, write=SetUKM};
	__property Sbtypes::ByteArray CEKMAC = {read=FCEKMAC, write=SetCEKMAC};
	__property Sbtypes::ByteArray EphemeralKey = {read=FEphemeralKey, write=SetEphemeralKey};
};

typedef TElGOST2001PublicKeyCrypto ElGOST2001PublicKeyCrypto
class DELPHICLASS TElPublicKeyCryptoFactory;
class PASCALIMPLEMENTATION TElPublicKeyCryptoFactory : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	Classes::TList* FRegisteredClasses;
	Sbcryptoprov::TElCustomCryptoProvider* FCryptoProvider;
	Sbcryptoprov::TElCustomCryptoProviderManager* FCryptoProviderManager;
	void __fastcall RegisterDefaultClasses(void);
	TElPublicKeyCryptoClass __fastcall GetRegisteredClass(int Index);
	int __fastcall GetRegisteredClassCount(void);
	
public:
	__fastcall TElPublicKeyCryptoFactory(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall TElPublicKeyCryptoFactory(Sbcryptoprov::TElCustomCryptoProviderManager* Manager, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	__fastcall virtual ~TElPublicKeyCryptoFactory(void);
	TElPublicKeyMaterial* __fastcall CreateKeyInstance(void * Buffer, int Size, const System::UnicodeString Password = L"")/* overload */;
	TElPublicKeyMaterial* __fastcall CreateKeyInstance(Classes::TStream* Stream, const System::UnicodeString Password = L"", int Count = 0x0)/* overload */;
	TElPublicKeyMaterial* __fastcall CreateKeyInstance(int Alg)/* overload */;
	void __fastcall RegisterClass(TElPublicKeyCryptoClass Cls);
	TElPublicKeyCrypto* __fastcall CreateInstance(const Sbtypes::ByteArray OID)/* overload */;
	TElPublicKeyCrypto* __fastcall CreateInstance(int Alg)/* overload */;
	bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	__property TElPublicKeyCryptoClass RegisteredClasses[int Index] = {read=GetRegisteredClass};
	__property int RegisteredClassCount = {read=GetRegisteredClassCount, nodefault};
};

typedef TElPublicKeyCryptoFactory ElPublicKeyCryptoFactory
class DELPHICLASS EElPublicKeyCryptoError;
class PASCALIMPLEMENTATION EElPublicKeyCryptoError : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElPublicKeyCryptoError(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElPublicKeyCryptoError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElPublicKeyCryptoError(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElPublicKeyCryptoError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElPublicKeyCryptoError(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElPublicKeyCryptoError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElPublicKeyCryptoError(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElPublicKeyCryptoError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElPublicKeyCryptoError(void) { }
	
};


class DELPHICLASS EElPublicKeyCryptoAsyncError;
class PASCALIMPLEMENTATION EElPublicKeyCryptoAsyncError : public EElPublicKeyCryptoError
{
	typedef EElPublicKeyCryptoError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElPublicKeyCryptoAsyncError(const System::UnicodeString AMessage)/* overload */ : EElPublicKeyCryptoError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElPublicKeyCryptoAsyncError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : EElPublicKeyCryptoError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElPublicKeyCryptoAsyncError(int Ident)/* overload */ : EElPublicKeyCryptoError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElPublicKeyCryptoAsyncError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : EElPublicKeyCryptoError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElPublicKeyCryptoAsyncError(const System::UnicodeString Msg, int AHelpContext) : EElPublicKeyCryptoError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElPublicKeyCryptoAsyncError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : EElPublicKeyCryptoError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElPublicKeyCryptoAsyncError(int Ident, int AHelpContext)/* overload */ : EElPublicKeyCryptoError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElPublicKeyCryptoAsyncError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : EElPublicKeyCryptoError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElPublicKeyCryptoAsyncError(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------

}	/* namespace Sbpublickeycrypto */
using namespace Sbpublickeycrypto;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbpublickeycryptoHPP
