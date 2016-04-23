// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbcryptoprovbuiltinpki.pas' rev: 21.00

#ifndef SbcryptoprovbuiltinpkiHPP
#define SbcryptoprovbuiltinpkiHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbstreams.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbcryptoprov.hpp>	// Pascal unit
#include <Sbcryptoprovutils.hpp>	// Pascal unit
#include <Sbcryptoprovbuiltin.hpp>	// Pascal unit
#include <Sbcryptoprovbuiltinhash.hpp>	// Pascal unit
#include <Sbcryptoprovrs.hpp>	// Pascal unit
#include <Sbrsa.hpp>	// Pascal unit
#include <Sbdsa.hpp>	// Pascal unit
#include <Sbecdsa.hpp>	// Pascal unit
#include <Sbeccommon.hpp>	// Pascal unit
#include <Sbecmath.hpp>	// Pascal unit
#include <Sbgostcommon.hpp>	// Pascal unit
#include <Sbgost2814789.hpp>	// Pascal unit
#include <Sbgost341094.hpp>	// Pascal unit
#include <Sbgost341001.hpp>	// Pascal unit
#include <Sbelgamal.hpp>	// Pascal unit
#include <Sbmath.hpp>	// Pascal unit
#include <Sbpkiasync.hpp>	// Pascal unit
#include <Sbasn1.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit
#include <Sbrdn.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbcryptoprovbuiltinpki
{
//-- type declarations -------------------------------------------------------
#pragma option push -b-
enum TSBBuiltInRSACryptoKeyFormat { rsaPKCS1, rsaOAEP, rsaPSS };
#pragma option pop

class DELPHICLASS TElBuiltInRSACryptoKey;
class PASCALIMPLEMENTATION TElBuiltInRSACryptoKey : public Sbcryptoprovbuiltin::TElBuiltInCryptoKey
{
	typedef Sbcryptoprovbuiltin::TElBuiltInCryptoKey inherited;
	
private:
	Sbtypes::ByteArray FKeyBlob;
	Sbtypes::ByteArray FPublicKeyBlob;
	Sbtypes::ByteArray FM;
	Sbtypes::ByteArray FE;
	Sbtypes::ByteArray FD;
	System::UnicodeString FPassphrase;
	bool FPEMEncode;
	Sbtypes::ByteArray FStrLabel;
	int FSaltSize;
	int FHashAlgorithm;
	int FMGFAlgorithm;
	int FTrailerField;
	bool FSecretKey;
	bool FPublicKey;
	TSBBuiltInRSACryptoKeyFormat FKeyFormat;
	bool FRawPublicKey;
	void __fastcall RecalculatePublicKeyBlob(bool RawPublicKey);
	void __fastcall TrimParams(void);
	
protected:
	Sbrsa::TElRSAAntiTimingParams* FAntiTimingParams;
	virtual bool __fastcall GetIsPublic(void);
	virtual bool __fastcall GetIsSecret(void);
	virtual bool __fastcall GetIsExportable(void);
	virtual bool __fastcall GetIsPersistent(void);
	virtual bool __fastcall GetIsValid(void);
	virtual int __fastcall GetBits(void);
	virtual int __fastcall GetAlgorithm(void);
	virtual Sbcryptoprov::TElCustomCryptoKeyStorage* __fastcall GetKeyStorage(void);
	void __fastcall InitAntiTimingParams(void);
	
public:
	__fastcall virtual TElBuiltInRSACryptoKey(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider);
	__fastcall virtual ~TElBuiltInRSACryptoKey(void);
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
	virtual bool __fastcall Equals(Sbcryptoprov::TElCustomCryptoKey* Source, bool PublicOnly, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0))/* overload */;
	
/* Hoisted overloads: */
	
public:
	inline bool __fastcall  Equals(System::TObject* Obj){ return Sbcryptoprov::TElCustomCryptoKey::Equals(Obj); }
	
};


class DELPHICLASS TElBuiltInDSACryptoKey;
class PASCALIMPLEMENTATION TElBuiltInDSACryptoKey : public Sbcryptoprovbuiltin::TElBuiltInCryptoKey
{
	typedef Sbcryptoprovbuiltin::TElBuiltInCryptoKey inherited;
	
private:
	bool FPublicKey;
	bool FSecretKey;
	Sbtypes::ByteArray FKeyBlob;
	Sbtypes::ByteArray FP;
	Sbtypes::ByteArray FQ;
	Sbtypes::ByteArray FG;
	Sbtypes::ByteArray FY;
	Sbtypes::ByteArray FX;
	bool FStrictKeyValidation;
	int FHashAlgorithm;
	Sbpkiasync::TElPublicKeyComputationToken* FToken;
	bool FReleaseToken;
	void __fastcall TrimParams(void);
	HIDESBASE void __fastcall Generate(int PBits, int QBits)/* overload */;
	
protected:
	virtual bool __fastcall GetIsPublic(void);
	virtual bool __fastcall GetIsSecret(void);
	virtual bool __fastcall GetIsExportable(void);
	virtual bool __fastcall GetIsPersistent(void);
	virtual bool __fastcall GetIsValid(void);
	virtual int __fastcall GetBits(void);
	virtual int __fastcall GetAlgorithm(void);
	virtual Sbcryptoprov::TElCustomCryptoKeyStorage* __fastcall GetKeyStorage(void);
	
public:
	__fastcall virtual TElBuiltInDSACryptoKey(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider);
	__fastcall virtual ~TElBuiltInDSACryptoKey(void);
	virtual void __fastcall Reset(void);
	virtual void __fastcall Generate(int Bits, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0))/* overload */;
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
	virtual void __fastcall PrepareForSigning(bool MultiUse = false);
	virtual void __fastcall CancelPreparation(void);
	virtual bool __fastcall AsyncOperationFinished(void);
	virtual bool __fastcall Equals(Sbcryptoprov::TElCustomCryptoKey* Source, bool PublicOnly, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0))/* overload */;
	
/* Hoisted overloads: */
	
public:
	inline bool __fastcall  Equals(System::TObject* Obj){ return Sbcryptoprov::TElCustomCryptoKey::Equals(Obj); }
	
};


class DELPHICLASS TElBuiltInElgamalCryptoKey;
class PASCALIMPLEMENTATION TElBuiltInElgamalCryptoKey : public Sbcryptoprovbuiltin::TElBuiltInCryptoKey
{
	typedef Sbcryptoprovbuiltin::TElBuiltInCryptoKey inherited;
	
private:
	Sbtypes::ByteArray FP;
	Sbtypes::ByteArray FG;
	Sbtypes::ByteArray FY;
	Sbtypes::ByteArray FX;
	bool FPublicKey;
	bool FSecretKey;
	Sbpkiasync::TElPublicKeyComputationToken* FToken;
	bool FReleaseToken;
	void __fastcall TrimParams(void);
	
protected:
	virtual bool __fastcall GetIsPublic(void);
	virtual bool __fastcall GetIsSecret(void);
	virtual bool __fastcall GetIsExportable(void);
	virtual bool __fastcall GetIsPersistent(void);
	virtual bool __fastcall GetIsValid(void);
	virtual int __fastcall GetBits(void);
	virtual int __fastcall GetAlgorithm(void);
	virtual Sbcryptoprov::TElCustomCryptoKeyStorage* __fastcall GetKeyStorage(void);
	
public:
	__fastcall virtual TElBuiltInElgamalCryptoKey(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider);
	__fastcall virtual ~TElBuiltInElgamalCryptoKey(void);
	virtual void __fastcall Generate(int Bits, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0));
	virtual void __fastcall Reset(void);
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
	virtual void __fastcall PrepareForEncryption(bool MultiUse = false);
	virtual void __fastcall PrepareForSigning(bool MultiUse = false);
	virtual void __fastcall CancelPreparation(void);
	virtual bool __fastcall AsyncOperationFinished(void);
	virtual bool __fastcall Equals(Sbcryptoprov::TElCustomCryptoKey* Source, bool PublicOnly, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0))/* overload */;
	
/* Hoisted overloads: */
	
public:
	inline bool __fastcall  Equals(System::TObject* Obj){ return Sbcryptoprov::TElCustomCryptoKey::Equals(Obj); }
	
};


class DELPHICLASS TElBuiltInDHCryptoKey;
class PASCALIMPLEMENTATION TElBuiltInDHCryptoKey : public Sbcryptoprovbuiltin::TElBuiltInCryptoKey
{
	typedef Sbcryptoprovbuiltin::TElBuiltInCryptoKey inherited;
	
private:
	Sbtypes::ByteArray FP;
	Sbtypes::ByteArray FG;
	Sbtypes::ByteArray FX;
	Sbtypes::ByteArray FY;
	Sbtypes::ByteArray FPeerY;
	bool FSecretKey;
	bool FPublicKey;
	
protected:
	virtual bool __fastcall GetIsPublic(void);
	virtual bool __fastcall GetIsSecret(void);
	virtual bool __fastcall GetIsExportable(void);
	virtual bool __fastcall GetIsPersistent(void);
	virtual bool __fastcall GetIsValid(void);
	virtual int __fastcall GetBits(void);
	virtual int __fastcall GetAlgorithm(void);
	virtual Sbcryptoprov::TElCustomCryptoKeyStorage* __fastcall GetKeyStorage(void);
	void __fastcall ExternalGenerate(int Bits, Sbtypes::ByteArray &P, Sbtypes::ByteArray &G, Sbtypes::ByteArray &X, Sbtypes::ByteArray &Y);
	bool __fastcall ExternalGenerationSupported(void);
	
public:
	__fastcall virtual TElBuiltInDHCryptoKey(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider);
	__fastcall virtual ~TElBuiltInDHCryptoKey(void);
	virtual void __fastcall Generate(int Bits, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0));
	virtual void __fastcall Reset(void);
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
	virtual bool __fastcall Equals(Sbcryptoprov::TElCustomCryptoKey* Source, bool PublicOnly, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0))/* overload */;
	
/* Hoisted overloads: */
	
public:
	inline bool __fastcall  Equals(System::TObject* Obj){ return Sbcryptoprov::TElCustomCryptoKey::Equals(Obj); }
	
};


class DELPHICLASS TElBuiltInECCryptoKey;
class PASCALIMPLEMENTATION TElBuiltInECCryptoKey : public Sbcryptoprovbuiltin::TElBuiltInCryptoKey
{
	typedef Sbcryptoprovbuiltin::TElBuiltInCryptoKey inherited;
	
private:
	bool FPublicKey;
	bool FSecretKey;
	Sbtypes::ByteArray FQX;
	Sbtypes::ByteArray FQY;
	Sbtypes::ByteArray FQ;
	Sbtypes::ByteArray FD;
	Sbeccommon::TElECDomainParameters* FDomainParameters;
	bool FCompressPoints;
	bool FHybridPoints;
	bool FStrictKeyValidation;
	int FHashAlgorithm;
	bool __fastcall CheckDomainParameters(void);
	
protected:
	virtual bool __fastcall GetIsPublic(void);
	virtual bool __fastcall GetIsSecret(void);
	virtual bool __fastcall GetIsExportable(void);
	virtual bool __fastcall GetIsPersistent(void);
	virtual bool __fastcall GetIsValid(void);
	virtual int __fastcall GetAlgorithm(void);
	virtual Sbcryptoprov::TElCustomCryptoKeyStorage* __fastcall GetKeyStorage(void);
	virtual int __fastcall GetBits(void);
	
public:
	__fastcall virtual TElBuiltInECCryptoKey(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider);
	__fastcall virtual ~TElBuiltInECCryptoKey(void);
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
	virtual bool __fastcall AsyncOperationFinished(void);
	virtual bool __fastcall Equals(Sbcryptoprov::TElCustomCryptoKey* Source, bool PublicOnly, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0))/* overload */;
	
/* Hoisted overloads: */
	
public:
	inline bool __fastcall  Equals(System::TObject* Obj){ return Sbcryptoprov::TElCustomCryptoKey::Equals(Obj); }
	
};


class DELPHICLASS TElBuiltInGOST341094CryptoKey;
class PASCALIMPLEMENTATION TElBuiltInGOST341094CryptoKey : public Sbcryptoprovbuiltin::TElBuiltInCryptoKey
{
	typedef Sbcryptoprovbuiltin::TElBuiltInCryptoKey inherited;
	
private:
	Sbtypes::ByteArray FP;
	Sbtypes::ByteArray FQ;
	Sbtypes::ByteArray FA;
	Sbtypes::ByteArray FY;
	Sbtypes::ByteArray FX;
	Sbtypes::ByteArray FC;
	Sbtypes::ByteArray FD;
	unsigned Fx0;
	Sbtypes::ByteArray FParamSet;
	Sbtypes::ByteArray FDigestParamSet;
	Sbtypes::ByteArray FEncryptionParamSet;
	bool FPublicKey;
	bool FSecretKey;
	void __fastcall TrimParams(void);
	
protected:
	virtual bool __fastcall GetIsPublic(void);
	virtual bool __fastcall GetIsSecret(void);
	virtual bool __fastcall GetIsExportable(void);
	virtual bool __fastcall GetIsPersistent(void);
	virtual bool __fastcall GetIsValid(void);
	virtual int __fastcall GetBits(void);
	virtual int __fastcall GetAlgorithm(void);
	virtual Sbcryptoprov::TElCustomCryptoKeyStorage* __fastcall GetKeyStorage(void);
	void __fastcall LoadParamset(const Sbtypes::ByteArray Paramset);
	
public:
	__fastcall virtual TElBuiltInGOST341094CryptoKey(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider);
	__fastcall virtual ~TElBuiltInGOST341094CryptoKey(void);
	virtual void __fastcall Generate(int Bits, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0), Sbutils::TSBProgressFunc ProgressFunc = 0x0, void * ProgressData = (void *)(0x0));
	virtual void __fastcall Reset(void);
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
	virtual bool __fastcall Equals(Sbcryptoprov::TElCustomCryptoKey* Source, bool PublicOnly, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0))/* overload */;
	
/* Hoisted overloads: */
	
public:
	inline bool __fastcall  Equals(System::TObject* Obj){ return Sbcryptoprov::TElCustomCryptoKey::Equals(Obj); }
	
};


class DELPHICLASS TElBuiltInGOST34102001CryptoKey;
class PASCALIMPLEMENTATION TElBuiltInGOST34102001CryptoKey : public Sbcryptoprovbuiltin::TElBuiltInCryptoKey
{
	typedef Sbcryptoprovbuiltin::TElBuiltInCryptoKey inherited;
	
private:
	bool FPublicKey;
	bool FSecretKey;
	Sbtypes::ByteArray FQX;
	Sbtypes::ByteArray FQY;
	Sbtypes::ByteArray FQ;
	Sbtypes::ByteArray FD;
	Sbeccommon::TElECDomainParameters* FDomainParameters;
	Sbtypes::ByteArray FParamSet;
	Sbtypes::ByteArray FDigestParamSet;
	Sbtypes::ByteArray FEncryptionParamSet;
	void __fastcall LoadParamset(const Sbtypes::ByteArray Paramset);
	
protected:
	virtual bool __fastcall GetIsPublic(void);
	virtual bool __fastcall GetIsSecret(void);
	virtual bool __fastcall GetIsExportable(void);
	virtual bool __fastcall GetIsPersistent(void);
	virtual bool __fastcall GetIsValid(void);
	virtual int __fastcall GetAlgorithm(void);
	virtual Sbcryptoprov::TElCustomCryptoKeyStorage* __fastcall GetKeyStorage(void);
	virtual int __fastcall GetBits(void);
	
public:
	__fastcall virtual TElBuiltInGOST34102001CryptoKey(Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider);
	__fastcall virtual ~TElBuiltInGOST34102001CryptoKey(void);
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
	virtual bool __fastcall Equals(Sbcryptoprov::TElCustomCryptoKey* Source, bool PublicOnly, Sbrdn::TElRelativeDistinguishedName* Params = (Sbrdn::TElRelativeDistinguishedName*)(0x0))/* overload */;
	virtual Sbtypes::ByteArray __fastcall GetKeyProp(const Sbtypes::ByteArray PropID, const Sbtypes::ByteArray Default = (Sbtypes::ByteArray)(0x0));
	virtual void __fastcall SetKeyProp(const Sbtypes::ByteArray PropID, const Sbtypes::ByteArray Value);
	
/* Hoisted overloads: */
	
public:
	inline bool __fastcall  Equals(System::TObject* Obj){ return Sbcryptoprov::TElCustomCryptoKey::Equals(Obj); }
	
};


#pragma option push -b-
enum TSBBuiltInPublicKeyOperation { pkoEncrypt, pkoDecrypt, pkoSign, pkoSignDetached, pkoVerify, pkoVerifyDetached };
#pragma option pop

class DELPHICLASS TElBuiltInPublicKeyCrypto;
class PASCALIMPLEMENTATION TElBuiltInPublicKeyCrypto : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	Sbcryptoprov::TElCustomCryptoKey* FKeyMaterial;
	Sbtypes::ByteArray FOutput;
	Classes::TStream* FOutputStream;
	bool FOutputIsStream;
	bool FFinished;
	bool FInputIsHash;
	Sbcryptoprov::TElCustomCryptoProvider* FCryptoProvider;
	virtual bool __fastcall GetSupportsEncryption(void);
	virtual bool __fastcall GetSupportsSigning(void);
	virtual void __fastcall SetKeyMaterial(Sbcryptoprov::TElCustomCryptoKey* Material);
	virtual void __fastcall WriteToOutput(void * Buffer, int Size);
	virtual void __fastcall Reset(void);
	virtual void __fastcall PrepareForOperation(void);
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	__classmethod virtual System::UnicodeString __fastcall GetName();
	__classmethod virtual System::UnicodeString __fastcall GetDescription();
	
public:
	__fastcall virtual TElBuiltInPublicKeyCrypto(const Sbtypes::ByteArray OID)/* overload */;
	__fastcall virtual TElBuiltInPublicKeyCrypto(int Alg)/* overload */;
	__fastcall virtual TElBuiltInPublicKeyCrypto(void)/* overload */;
	__fastcall virtual ~TElBuiltInPublicKeyCrypto(void);
	virtual void __fastcall SignInit(bool Detached);
	virtual void __fastcall SignUpdate(void * Buffer, int Size);
	virtual void __fastcall SignFinal(void * Buffer, int &Size);
	virtual void __fastcall EncryptInit(void);
	virtual void __fastcall EncryptUpdate(void * Buffer, int Size);
	virtual void __fastcall EncryptFinal(void);
	virtual void __fastcall DecryptInit(void);
	virtual void __fastcall DecryptUpdate(void * Buffer, int Size);
	virtual void __fastcall DecryptFinal(void);
	virtual void __fastcall VerifyInit(bool Detached, void * Signature, int SigSize);
	virtual void __fastcall VerifyUpdate(void * Buffer, int Size);
	virtual int __fastcall VerifyFinal(void);
	void __fastcall Encrypt(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	void __fastcall Decrypt(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	void __fastcall Sign(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	void __fastcall SignDetached(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	int __fastcall Verify(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	int __fastcall VerifyDetached(void * InBuffer, int InSize, void * SigBuffer, int SigSize)/* overload */;
	void __fastcall Encrypt(Classes::TStream* InStream, Classes::TStream* OutStream, int Count = 0x0)/* overload */;
	void __fastcall Decrypt(Classes::TStream* InStream, Classes::TStream* OutStream, int Count = 0x0)/* overload */;
	void __fastcall Sign(Classes::TStream* InStream, Classes::TStream* OutStream, int Count = 0x0)/* overload */;
	void __fastcall SignDetached(Classes::TStream* InStream, Classes::TStream* OutStream, int Count = 0x0)/* overload */;
	int __fastcall Verify(Classes::TStream* InStream, Classes::TStream* OutStream, int Count = 0x0)/* overload */;
	int __fastcall VerifyDetached(Classes::TStream* InStream, Classes::TStream* SigStream, int InCount = 0x0, int SigCount = 0x0)/* overload */;
	virtual __int64 __fastcall EstimateOutputSize(void * InBuffer, __int64 InSize, TSBBuiltInPublicKeyOperation Operation)/* overload */;
	virtual __int64 __fastcall EstimateOutputSize(__int64 InSize, TSBBuiltInPublicKeyOperation Operation)/* overload */;
	__property Sbcryptoprov::TElCustomCryptoKey* KeyMaterial = {read=FKeyMaterial, write=SetKeyMaterial};
	__property bool SupportsEncryption = {read=GetSupportsEncryption, nodefault};
	__property bool SupportsSigning = {read=GetSupportsSigning, nodefault};
	__property bool InputIsHash = {read=FInputIsHash, write=FInputIsHash, nodefault};
};


typedef TMetaClass* TElBuiltInPublicKeyCryptoClass;

#pragma option push -b-
enum TSBBuiltInRSAPublicKeyCryptoType { rsapktPKCS1, rsapktOAEP, rsapktPSS, rsapktSSL3 };
#pragma option pop

class DELPHICLASS TElBuiltInRSAPublicKeyCrypto;
class PASCALIMPLEMENTATION TElBuiltInRSAPublicKeyCrypto : public TElBuiltInPublicKeyCrypto
{
	typedef TElBuiltInPublicKeyCrypto inherited;
	
private:
	Sbtypes::ByteArray FOID;
	bool FSupportsEncryption;
	bool FSupportsSigning;
	TSBBuiltInRSAPublicKeyCryptoType FCryptoType;
	bool FUseAlgorithmPrefix;
	Sbtypes::ByteArray FSpool;
	Sbcryptoprovbuiltinhash::TElBuiltInHashFunction* FHashFunction;
	Sbtypes::ByteArray FSignature;
	Sbtypes::ByteArray FHashFuncOID;
	int FHashAlgorithm;
	int FMGFAlgorithm;
	int FSaltSize;
	int FTrailerField;
	int __fastcall GetUsedHashFunction(void);
	Sbtypes::ByteArray __fastcall GetUsedHashFunctionOID(void);
	void __fastcall SetHashFuncOID(const Sbtypes::ByteArray V);
	Sbtypes::ByteArray __fastcall AddAlgorithmPrefix(const Sbtypes::ByteArray Hash);
	Sbtypes::ByteArray __fastcall RemoveAlgorithmPrefix(const Sbtypes::ByteArray Value, Sbtypes::ByteArray &HashAlg, Sbtypes::ByteArray &HashPar);
	Sbrsa::TElRSAAntiTimingParams* __fastcall GetAntiTimingParams(Sbcryptoprov::TElCustomCryptoKey* KM);
	
protected:
	virtual bool __fastcall GetSupportsEncryption(void);
	virtual bool __fastcall GetSupportsSigning(void);
	virtual void __fastcall SetKeyMaterial(Sbcryptoprov::TElCustomCryptoKey* Material);
	void __fastcall SetCryptoType(TSBBuiltInRSAPublicKeyCryptoType Value);
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	__classmethod virtual System::UnicodeString __fastcall GetName();
	__classmethod virtual System::UnicodeString __fastcall GetDescription();
	virtual void __fastcall WriteToOutput(void * Buffer, int Size);
	virtual void __fastcall Reset(void);
	bool __fastcall AlgorithmPrefixNeeded(void);
	
public:
	__fastcall virtual TElBuiltInRSAPublicKeyCrypto(const Sbtypes::ByteArray OID)/* overload */;
	__fastcall virtual TElBuiltInRSAPublicKeyCrypto(int Alg)/* overload */;
	__fastcall virtual TElBuiltInRSAPublicKeyCrypto(void)/* overload */;
	__fastcall virtual ~TElBuiltInRSAPublicKeyCrypto(void);
	virtual void __fastcall SignInit(bool Detached);
	virtual void __fastcall SignUpdate(void * Buffer, int Size);
	virtual void __fastcall SignFinal(void * Buffer, int &Size);
	virtual void __fastcall EncryptInit(void);
	virtual void __fastcall EncryptUpdate(void * Buffer, int Size);
	virtual void __fastcall EncryptFinal(void);
	virtual void __fastcall DecryptInit(void);
	virtual void __fastcall DecryptUpdate(void * Buffer, int Size);
	virtual void __fastcall DecryptFinal(void);
	virtual void __fastcall VerifyInit(bool Detached, void * Signature, int SigSize);
	virtual void __fastcall VerifyUpdate(void * Buffer, int Size);
	virtual int __fastcall VerifyFinal(void);
	virtual __int64 __fastcall EstimateOutputSize(void * InBuffer, __int64 InSize, TSBBuiltInPublicKeyOperation Operation)/* overload */;
	__property TSBBuiltInRSAPublicKeyCryptoType CryptoType = {read=FCryptoType, write=SetCryptoType, nodefault};
	__property bool UseAlgorithmPrefix = {read=FUseAlgorithmPrefix, write=FUseAlgorithmPrefix, nodefault};
	__property Sbtypes::ByteArray HashFuncOID = {read=FHashFuncOID, write=SetHashFuncOID};
	__property int HashAlgorithm = {read=FHashAlgorithm, write=FHashAlgorithm, nodefault};
	__property int SaltSize = {read=FSaltSize, write=FSaltSize, nodefault};
	__property int MGFAlgorithm = {read=FMGFAlgorithm, write=FMGFAlgorithm, nodefault};
	__property int TrailerField = {read=FTrailerField, write=FTrailerField, nodefault};
	
/* Hoisted overloads: */
	
public:
	inline __int64 __fastcall  EstimateOutputSize(__int64 InSize, TSBBuiltInPublicKeyOperation Operation){ return TElBuiltInPublicKeyCrypto::EstimateOutputSize(InSize, Operation); }
	
};


class DELPHICLASS TElBuiltInDSAPublicKeyCrypto;
class PASCALIMPLEMENTATION TElBuiltInDSAPublicKeyCrypto : public TElBuiltInPublicKeyCrypto
{
	typedef TElBuiltInPublicKeyCrypto inherited;
	
protected:
	Sbtypes::ByteArray FOID;
	Sbtypes::ByteArray FSpool;
	Sbcryptoprovbuiltinhash::TElBuiltInHashFunction* FHashFunction;
	Sbtypes::ByteArray FSignature;
	int __fastcall GetUsedHashFunction(void);
	virtual bool __fastcall GetSupportsEncryption(void);
	virtual bool __fastcall GetSupportsSigning(void);
	virtual void __fastcall SetKeyMaterial(Sbcryptoprov::TElCustomCryptoKey* Material);
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	__classmethod virtual System::UnicodeString __fastcall GetName();
	__classmethod virtual System::UnicodeString __fastcall GetDescription();
	virtual void __fastcall WriteToOutput(void * Buffer, int Size);
	virtual void __fastcall Reset(void);
	
public:
	__fastcall virtual TElBuiltInDSAPublicKeyCrypto(const Sbtypes::ByteArray OID)/* overload */;
	__fastcall virtual TElBuiltInDSAPublicKeyCrypto(int Alg)/* overload */;
	__fastcall virtual TElBuiltInDSAPublicKeyCrypto(void)/* overload */;
	__fastcall virtual ~TElBuiltInDSAPublicKeyCrypto(void);
	void __fastcall EncodeSignature(void * R, int RSize, void * S, int SSize, void * Sig, int &SigSize);
	void __fastcall DecodeSignature(void * Sig, int SigSize, void * R, int &RSize, void * S, int &SSize);
	virtual void __fastcall SignInit(bool Detached);
	virtual void __fastcall SignUpdate(void * Buffer, int Size);
	virtual void __fastcall SignFinal(void * Buffer, int &Size);
	virtual void __fastcall VerifyInit(bool Detached, void * Signature, int SigSize);
	virtual void __fastcall VerifyUpdate(void * Buffer, int Size);
	virtual int __fastcall VerifyFinal(void);
	virtual __int64 __fastcall EstimateOutputSize(void * InBuffer, __int64 InSize, TSBBuiltInPublicKeyOperation Operation)/* overload */;
	
/* Hoisted overloads: */
	
public:
	inline __int64 __fastcall  EstimateOutputSize(__int64 InSize, TSBBuiltInPublicKeyOperation Operation){ return TElBuiltInPublicKeyCrypto::EstimateOutputSize(InSize, Operation); }
	
};


class DELPHICLASS TElBuiltInElgamalPublicKeyCrypto;
class PASCALIMPLEMENTATION TElBuiltInElgamalPublicKeyCrypto : public TElBuiltInPublicKeyCrypto
{
	typedef TElBuiltInPublicKeyCrypto inherited;
	
private:
	Sbtypes::ByteArray FSpool;
	Sbcryptoprovbuiltinhash::TElBuiltInHashFunction* FHashFunction;
	Sbtypes::ByteArray FSignature;
	int FHashAlgorithm;
	
protected:
	virtual bool __fastcall GetSupportsEncryption(void);
	virtual bool __fastcall GetSupportsSigning(void);
	virtual void __fastcall SetKeyMaterial(Sbcryptoprov::TElCustomCryptoKey* Material);
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	__classmethod virtual System::UnicodeString __fastcall GetName();
	__classmethod virtual System::UnicodeString __fastcall GetDescription();
	virtual void __fastcall WriteToOutput(void * Buffer, int Size);
	virtual void __fastcall Reset(void);
	
public:
	__fastcall virtual TElBuiltInElgamalPublicKeyCrypto(const Sbtypes::ByteArray OID)/* overload */;
	__fastcall virtual TElBuiltInElgamalPublicKeyCrypto(int Alg)/* overload */;
	__fastcall virtual TElBuiltInElgamalPublicKeyCrypto(void)/* overload */;
	__fastcall virtual ~TElBuiltInElgamalPublicKeyCrypto(void);
	virtual void __fastcall SignInit(bool Detached);
	virtual void __fastcall SignUpdate(void * Buffer, int Size);
	virtual void __fastcall SignFinal(void * Buffer, int &Size);
	virtual void __fastcall EncryptInit(void);
	virtual void __fastcall EncryptUpdate(void * Buffer, int Size);
	virtual void __fastcall EncryptFinal(void);
	virtual void __fastcall DecryptInit(void);
	virtual void __fastcall DecryptUpdate(void * Buffer, int Size);
	virtual void __fastcall DecryptFinal(void);
	virtual void __fastcall VerifyInit(bool Detached, void * Signature, int SigSize);
	virtual void __fastcall VerifyUpdate(void * Buffer, int Size);
	virtual int __fastcall VerifyFinal(void);
	virtual __int64 __fastcall EstimateOutputSize(void * InBuffer, __int64 InSize, TSBBuiltInPublicKeyOperation Operation)/* overload */;
	__property int HashAlgorithm = {read=FHashAlgorithm, write=FHashAlgorithm, nodefault};
	
/* Hoisted overloads: */
	
public:
	inline __int64 __fastcall  EstimateOutputSize(__int64 InSize, TSBBuiltInPublicKeyOperation Operation){ return TElBuiltInPublicKeyCrypto::EstimateOutputSize(InSize, Operation); }
	
};


class DELPHICLASS TElBuiltInDHPublicKeyCrypto;
class PASCALIMPLEMENTATION TElBuiltInDHPublicKeyCrypto : public TElBuiltInPublicKeyCrypto
{
	typedef TElBuiltInPublicKeyCrypto inherited;
	
private:
	Sbtypes::ByteArray FSpool;
	
protected:
	virtual bool __fastcall GetSupportsEncryption(void);
	virtual bool __fastcall GetSupportsSigning(void);
	virtual void __fastcall SetKeyMaterial(Sbcryptoprov::TElCustomCryptoKey* Material);
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	__classmethod virtual System::UnicodeString __fastcall GetName();
	__classmethod virtual System::UnicodeString __fastcall GetDescription();
	virtual void __fastcall WriteToOutput(void * Buffer, int Size);
	virtual void __fastcall Reset(void);
	
public:
	__fastcall virtual TElBuiltInDHPublicKeyCrypto(const Sbtypes::ByteArray OID)/* overload */;
	__fastcall virtual TElBuiltInDHPublicKeyCrypto(int Alg)/* overload */;
	__fastcall virtual TElBuiltInDHPublicKeyCrypto(void)/* overload */;
	__fastcall virtual ~TElBuiltInDHPublicKeyCrypto(void);
	virtual void __fastcall EncryptInit(void);
	virtual void __fastcall EncryptUpdate(void * Buffer, int Size);
	virtual void __fastcall EncryptFinal(void);
	virtual void __fastcall DecryptInit(void);
	virtual void __fastcall DecryptUpdate(void * Buffer, int Size);
	virtual void __fastcall DecryptFinal(void);
	virtual __int64 __fastcall EstimateOutputSize(void * InBuffer, __int64 InSize, TSBBuiltInPublicKeyOperation Operation)/* overload */;
	
/* Hoisted overloads: */
	
public:
	inline __int64 __fastcall  EstimateOutputSize(__int64 InSize, TSBBuiltInPublicKeyOperation Operation){ return TElBuiltInPublicKeyCrypto::EstimateOutputSize(InSize, Operation); }
	
};


class DELPHICLASS TElBuiltInECDSAPublicKeyCrypto;
class PASCALIMPLEMENTATION TElBuiltInECDSAPublicKeyCrypto : public TElBuiltInPublicKeyCrypto
{
	typedef TElBuiltInPublicKeyCrypto inherited;
	
protected:
	Sbtypes::ByteArray FOID;
	int FHashAlgorithm;
	Sbtypes::ByteArray FSpool;
	Sbcryptoprovbuiltinhash::TElBuiltInHashFunction* FHashFunction;
	Sbtypes::ByteArray FSignature;
	bool FPlainECDSA;
	int __fastcall GetUsedHashFunction(void);
	virtual bool __fastcall GetSupportsEncryption(void);
	virtual bool __fastcall GetSupportsSigning(void);
	virtual void __fastcall SetKeyMaterial(Sbcryptoprov::TElCustomCryptoKey* Material);
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	__classmethod virtual System::UnicodeString __fastcall GetName();
	__classmethod virtual System::UnicodeString __fastcall GetDescription();
	virtual void __fastcall WriteToOutput(void * Buffer, int Size);
	virtual void __fastcall Reset(void);
	
public:
	__fastcall virtual TElBuiltInECDSAPublicKeyCrypto(const Sbtypes::ByteArray OID)/* overload */;
	__fastcall virtual TElBuiltInECDSAPublicKeyCrypto(int Alg)/* overload */;
	__fastcall virtual TElBuiltInECDSAPublicKeyCrypto(void)/* overload */;
	__fastcall virtual ~TElBuiltInECDSAPublicKeyCrypto(void);
	void __fastcall EncodeSignature(void * R, int RSize, void * S, int SSize, void * Sig, int &SigSize);
	void __fastcall DecodeSignature(void * Sig, int SigSize, void * R, int &RSize, void * S, int &SSize);
	virtual void __fastcall SignInit(bool Detached);
	virtual void __fastcall SignUpdate(void * Buffer, int Size);
	virtual void __fastcall SignFinal(void * Buffer, int &Size);
	virtual void __fastcall VerifyInit(bool Detached, void * Signature, int SigSize);
	virtual void __fastcall VerifyUpdate(void * Buffer, int Size);
	virtual int __fastcall VerifyFinal(void);
	virtual __int64 __fastcall EstimateOutputSize(void * InBuffer, __int64 InSize, TSBBuiltInPublicKeyOperation Operation)/* overload */;
	__property int HashAlgorithm = {read=FHashAlgorithm, write=FHashAlgorithm, nodefault};
	__property bool PlainECDSA = {read=FPlainECDSA, write=FPlainECDSA, nodefault};
	
/* Hoisted overloads: */
	
public:
	inline __int64 __fastcall  EstimateOutputSize(__int64 InSize, TSBBuiltInPublicKeyOperation Operation){ return TElBuiltInPublicKeyCrypto::EstimateOutputSize(InSize, Operation); }
	
};


class DELPHICLASS TElBuiltInECDHPublicKeyCrypto;
class PASCALIMPLEMENTATION TElBuiltInECDHPublicKeyCrypto : public TElBuiltInPublicKeyCrypto
{
	typedef TElBuiltInPublicKeyCrypto inherited;
	
protected:
	Sbtypes::ByteArray FSpool;
	virtual bool __fastcall GetSupportsEncryption(void);
	virtual bool __fastcall GetSupportsSigning(void);
	virtual void __fastcall SetKeyMaterial(Sbcryptoprov::TElCustomCryptoKey* Material);
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	__classmethod virtual System::UnicodeString __fastcall GetName();
	__classmethod virtual System::UnicodeString __fastcall GetDescription();
	virtual void __fastcall WriteToOutput(void * Buffer, int Size);
	virtual void __fastcall Reset(void);
	
public:
	__fastcall virtual TElBuiltInECDHPublicKeyCrypto(const Sbtypes::ByteArray OID)/* overload */;
	__fastcall virtual TElBuiltInECDHPublicKeyCrypto(int Alg)/* overload */;
	__fastcall virtual TElBuiltInECDHPublicKeyCrypto(void)/* overload */;
	__fastcall virtual ~TElBuiltInECDHPublicKeyCrypto(void);
	virtual void __fastcall EncryptInit(void);
	virtual void __fastcall EncryptUpdate(void * Buffer, int Size);
	virtual void __fastcall EncryptFinal(void);
	virtual void __fastcall DecryptInit(void);
	virtual void __fastcall DecryptUpdate(void * Buffer, int Size);
	virtual void __fastcall DecryptFinal(void);
	virtual __int64 __fastcall EstimateOutputSize(void * InBuffer, __int64 InSize, TSBBuiltInPublicKeyOperation Operation)/* overload */;
	
/* Hoisted overloads: */
	
public:
	inline __int64 __fastcall  EstimateOutputSize(__int64 InSize, TSBBuiltInPublicKeyOperation Operation){ return TElBuiltInPublicKeyCrypto::EstimateOutputSize(InSize, Operation); }
	
};


class DELPHICLASS TElBuiltInGOST94PublicKeyCrypto;
class PASCALIMPLEMENTATION TElBuiltInGOST94PublicKeyCrypto : public TElBuiltInPublicKeyCrypto
{
	typedef TElBuiltInPublicKeyCrypto inherited;
	
private:
	Sbtypes::ByteArray FSpool;
	Sbcryptoprovbuiltinhash::TElBuiltInHashFunction* FHashFunction;
	Sbtypes::ByteArray FSignature;
	int FHashAlgorithm;
	
protected:
	void __fastcall Param_to_PLInt(const Sbtypes::ByteArray PropID, Sbmath::PLInt &Res);
	virtual bool __fastcall GetSupportsEncryption(void);
	virtual bool __fastcall GetSupportsSigning(void);
	virtual void __fastcall SetKeyMaterial(Sbcryptoprov::TElCustomCryptoKey* Material);
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	__classmethod virtual System::UnicodeString __fastcall GetName();
	__classmethod virtual System::UnicodeString __fastcall GetDescription();
	virtual void __fastcall WriteToOutput(void * Buffer, int Size);
	virtual void __fastcall Reset(void);
	
public:
	__fastcall virtual TElBuiltInGOST94PublicKeyCrypto(const Sbtypes::ByteArray OID)/* overload */;
	__fastcall virtual TElBuiltInGOST94PublicKeyCrypto(int Alg)/* overload */;
	__fastcall virtual TElBuiltInGOST94PublicKeyCrypto(void)/* overload */;
	__fastcall virtual ~TElBuiltInGOST94PublicKeyCrypto(void);
	virtual void __fastcall SignInit(bool Detached);
	virtual void __fastcall SignUpdate(void * Buffer, int Size);
	virtual void __fastcall SignFinal(void * Buffer, int &Size);
	virtual void __fastcall VerifyInit(bool Detached, void * Signature, int SigSize);
	virtual void __fastcall VerifyUpdate(void * Buffer, int Size);
	virtual int __fastcall VerifyFinal(void);
	virtual __int64 __fastcall EstimateOutputSize(void * InBuffer, __int64 InSize, TSBBuiltInPublicKeyOperation Operation)/* overload */;
	__property int HashAlgorithm = {read=FHashAlgorithm, write=FHashAlgorithm, nodefault};
	
/* Hoisted overloads: */
	
public:
	inline __int64 __fastcall  EstimateOutputSize(__int64 InSize, TSBBuiltInPublicKeyOperation Operation){ return TElBuiltInPublicKeyCrypto::EstimateOutputSize(InSize, Operation); }
	
};


class DELPHICLASS TElBuiltInGOST2001PublicKeyCrypto;
class PASCALIMPLEMENTATION TElBuiltInGOST2001PublicKeyCrypto : public TElBuiltInPublicKeyCrypto
{
	typedef TElBuiltInPublicKeyCrypto inherited;
	
private:
	Sbtypes::ByteArray FSpool;
	Sbcryptoprovbuiltinhash::TElBuiltInHashFunction* FHashFunction;
	Sbtypes::ByteArray FSignature;
	int FHashAlgorithm;
	Sbtypes::ByteArray FUKM;
	Sbtypes::ByteArray FEphemeralKey;
	Sbtypes::ByteArray FCEKMAC;
	
protected:
	virtual bool __fastcall GetSupportsEncryption(void);
	virtual bool __fastcall GetSupportsSigning(void);
	virtual void __fastcall SetKeyMaterial(Sbcryptoprov::TElCustomCryptoKey* Material);
	__classmethod virtual bool __fastcall IsAlgorithmSupported(int Alg)/* overload */;
	__classmethod virtual bool __fastcall IsAlgorithmSupported(const Sbtypes::ByteArray OID)/* overload */;
	__classmethod virtual System::UnicodeString __fastcall GetName();
	__classmethod virtual System::UnicodeString __fastcall GetDescription();
	virtual void __fastcall WriteToOutput(void * Buffer, int Size);
	virtual void __fastcall Reset(void);
	Sbtypes::ByteArray __fastcall DeriveKEK(void);
	void __fastcall SetUKM(const Sbtypes::ByteArray V);
	void __fastcall SetCEKMAC(const Sbtypes::ByteArray V);
	void __fastcall SetEphemeralKey(const Sbtypes::ByteArray V);
	
public:
	__fastcall virtual TElBuiltInGOST2001PublicKeyCrypto(const Sbtypes::ByteArray OID)/* overload */;
	__fastcall virtual TElBuiltInGOST2001PublicKeyCrypto(int Alg)/* overload */;
	__fastcall virtual TElBuiltInGOST2001PublicKeyCrypto(void)/* overload */;
	__fastcall virtual ~TElBuiltInGOST2001PublicKeyCrypto(void);
	virtual void __fastcall EncryptInit(void);
	virtual void __fastcall EncryptUpdate(void * Buffer, int Size);
	virtual void __fastcall EncryptFinal(void);
	virtual void __fastcall DecryptInit(void);
	virtual void __fastcall DecryptUpdate(void * Buffer, int Size);
	virtual void __fastcall DecryptFinal(void);
	virtual void __fastcall SignInit(bool Detached);
	virtual void __fastcall SignUpdate(void * Buffer, int Size);
	virtual void __fastcall SignFinal(void * Buffer, int &Size);
	virtual void __fastcall VerifyInit(bool Detached, void * Signature, int SigSize);
	virtual void __fastcall VerifyUpdate(void * Buffer, int Size);
	virtual int __fastcall VerifyFinal(void);
	virtual __int64 __fastcall EstimateOutputSize(void * InBuffer, __int64 InSize, TSBBuiltInPublicKeyOperation Operation)/* overload */;
	__property int HashAlgorithm = {read=FHashAlgorithm, write=FHashAlgorithm, nodefault};
	__property Sbtypes::ByteArray UKM = {read=FUKM, write=SetUKM};
	__property Sbtypes::ByteArray CEKMAC = {read=FCEKMAC, write=SetCEKMAC};
	__property Sbtypes::ByteArray EphemeralKey = {read=FEphemeralKey, write=SetEphemeralKey};
	
/* Hoisted overloads: */
	
public:
	inline __int64 __fastcall  EstimateOutputSize(__int64 InSize, TSBBuiltInPublicKeyOperation Operation){ return TElBuiltInPublicKeyCrypto::EstimateOutputSize(InSize, Operation); }
	
};


//-- var, const, procedure ---------------------------------------------------

}	/* namespace Sbcryptoprovbuiltinpki */
using namespace Sbcryptoprovbuiltinpki;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbcryptoprovbuiltinpkiHPP
