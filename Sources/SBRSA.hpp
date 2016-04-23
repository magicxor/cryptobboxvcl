// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbrsa.pas' rev: 21.00

#ifndef SbrsaHPP
#define SbrsaHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbsharedresource.hpp>	// Pascal unit
#include <Sbmath.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbrsa
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElRSAAntiTimingParams;
class PASCALIMPLEMENTATION TElRSAAntiTimingParams : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	Sbmath::TLInt *FVI;
	Sbmath::TLInt *FVF;
	Sbtypes::ByteArray FRSAE;
	Sbtypes::ByteArray FRSAM;
	bool FInitialized;
	bool FPrepared;
	Sbsharedresource::TElSharedResource* FSharedResource;
	void __fastcall PrepareBlindingPair(void);
	void __fastcall UpdateBlindingPair(void);
	
public:
	__fastcall TElRSAAntiTimingParams(void);
	__fastcall virtual ~TElRSAAntiTimingParams(void);
	void __fastcall Init(const Sbtypes::ByteArray RSAM, const Sbtypes::ByteArray RSAE);
	void __fastcall Reset(void);
	void __fastcall GetNextBlindingPair(Sbmath::PLInt VI, Sbmath::PLInt VF);
	__property bool Initialized = {read=FInitialized, nodefault};
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE bool __fastcall ValidateSignature(void * Hash, int HashSize, void * PublicModulus, int PublicModulusSize, void * PublicExponent, int PublicExponentSize, void * Signature, int SignatureSize);
extern PACKAGE Sbtypes::ByteArray __fastcall ExtractSignedData(void * PublicModulus, int PublicModulusSize, void * PublicExponent, int PublicExponentSize, void * Signature, int SignatureSize);
extern PACKAGE bool __fastcall Generate(int Bits, void * PublicModulus, int &PublicModulusSize, void * PublicExponent, int &PublicExponentSize, void * PrivateExponent, int &PrivateExponentSize)/* overload */;
extern PACKAGE bool __fastcall ExternalGenerationSupported(void);
extern PACKAGE bool __fastcall ExternalGenerate(int Bits, void * PublicModulus, int &PublicModulusSize, void * PublicExponent, int &PublicExponentSize, void * PrivateExponent, int &PrivateExponentSize)/* overload */;
extern PACKAGE bool __fastcall Generate(int Bits, Sbmath::PLInt PublicModulus, Sbmath::PLInt PublicExponent, Sbmath::PLInt PrivateExponent, Sbmath::PLInt P, Sbmath::PLInt Q, Sbmath::PLInt U)/* overload */;
extern PACKAGE bool __fastcall ExternalGenerate(int Bits, Sbmath::PLInt PublicModulus, Sbmath::PLInt PublicExponent, Sbmath::PLInt PrivateExponent, Sbmath::PLInt P, Sbmath::PLInt Q, Sbmath::PLInt U)/* overload */;
extern PACKAGE bool __fastcall Generate(int Bits, void * PublicModulus, int &PublicModulusSize, void * PublicExponent, int &PublicExponentSize, void * PrivateExponent, int &PrivateExponentSize, void * PrivateKeyBlob, int &PrivateKeyBlobSize, Sbmath::TSBMathProgressFunc ProgressFunc = 0x0, void * Data = (void *)(0x0))/* overload */;
extern PACKAGE bool __fastcall ExternalGenerate(int Bits, void * PublicModulus, int &PublicModulusSize, void * PublicExponent, int &PublicExponentSize, void * PrivateExponent, int &PrivateExponentSize, void * PrivateKeyBlob, int &PrivateKeyBlobSize, Sbmath::TSBMathProgressFunc ProgressFunc = 0x0, void * Data = (void *)(0x0))/* overload */;
extern PACKAGE bool __fastcall Sign(void * Hash, int HashSize, void * PublicModulus, int PublicModulusSize, void * PrivateExponent, int PrivateExponentSize, void * Signature, int &SignatureSize, TElRSAAntiTimingParams* AntiTimingParams)/* overload */;
extern PACKAGE bool __fastcall Encrypt(void * InBuffer, int InSize, void * PublicModulus, int PublicModulusSize, void * PublicExponent, int PublicExponentSize, void * OutBuffer, int &OutSize)/* overload */;
extern PACKAGE bool __fastcall Encrypt(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, Sbmath::PLInt PublicModulus, Sbmath::PLInt PublicExponent)/* overload */;
extern PACKAGE bool __fastcall Decrypt(void * InBuffer, int InSize, void * PublicModulus, int PublicModulusSize, void * PrivateExponent, int PrivateExponentSize, void * OutBuffer, int &OutSize, TElRSAAntiTimingParams* AntiTimingParams)/* overload */;
extern PACKAGE bool __fastcall DecodePrivateKey(void * Buffer, int Size, void * PublicModulus, int &PublicModulusSize, void * PublicExponent, int &PublicExponentSize, void * PrivateExponent, int &PrivateExponentSize)/* overload */;
extern PACKAGE bool __fastcall DecodePrivateKey(void * Buffer, int Size, void * PublicModulus, int &PublicModulusSize, void * PublicExponent, int &PublicExponentSize, void * PrivateExponent, int &PrivateExponentSize, void * P, int &PSize, void * Q, int &QSize, void * E1, int &E1Size, void * E2, int &E2Size, void * U, int &USize)/* overload */;
extern PACKAGE bool __fastcall EncodePrivateKey(void * PublicModulus, int PublicModulusSize, void * PublicExponent, int PublicExponentSize, void * PrivateExponent, int PrivateExponentSize, void * Prime1, int Prime1Size, void * Prime2, int Prime2Size, void * Exponent1, int Exponent1Size, void * Exponent2, int Exponent2Size, void * Coef, int CoefSize, void * OutBuffer, int &OutSize)/* overload */;
extern PACKAGE bool __fastcall EncodePrivateKey(void * PublicModulus, int PublicModulusSize, void * PublicExponent, int PublicExponentSize, void * PrivateExponent, int PrivateExponentSize, void * OutBuffer, int &OutSize)/* overload */;
extern PACKAGE bool __fastcall Decrypt(void * InBuffer, int InSize, void * PrivateKeyBlob, int PrivateKeyBlobSize, void * OutBuffer, int &OutSize, TElRSAAntiTimingParams* AntiTimingParams)/* overload */;
extern PACKAGE bool __fastcall Sign(void * Hash, int HashSize, void * PrivateKeyBlob, int PrivateKeyBlobSize, void * Signature, int &SignatureSize, TElRSAAntiTimingParams* AntiTimingParams)/* overload */;
extern PACKAGE bool __fastcall IsValidKey(void * Blob, int BlobSize);
extern PACKAGE bool __fastcall PerformExponentiation(void * Modulus, int ModulusSize, void * Exponent, int ExponentSize, void * InBuffer, int InSize, void * OutBuffer, int &OutSize, TElRSAAntiTimingParams* AntiTimingParams)/* overload */;
extern PACKAGE bool __fastcall PerformExponentiation(void * Blob, int BlobSize, void * InBuffer, int InSize, void * OutBuffer, int &OutSize, TElRSAAntiTimingParams* AntiTimingParams)/* overload */;
extern PACKAGE bool __fastcall EncryptOAEP(void * InBuffer, int InSize, void * PublicModulus, int PublicModulusSize, void * PublicExponent, int PublicExponentSize, void * Salt, int SaltSize, int HashAlg, void * OutBuffer, int &OutSize);
extern PACKAGE bool __fastcall DecryptOAEP(void * InBuffer, int InSize, void * PublicModulus, int PublicModulusSize, void * PrivateExponent, int PrivateExponentSize, void * Salt, int SaltSize, int HashAlg, void * OutBuffer, int &OutSize, TElRSAAntiTimingParams* AntiTimingParams)/* overload */;
extern PACKAGE bool __fastcall DecryptOAEP(void * InBuffer, int InSize, void * Blob, int BlobSize, void * Salt, int SaltSize, int HashAlg, void * OutBuffer, int &OutSize, TElRSAAntiTimingParams* AntiTimingParams)/* overload */;
extern PACKAGE bool __fastcall SignPSS(void * HashValue, int HashValueSize, int HashAlgorithm, int SaltSize, void * PublicModulus, int PublicModulusSize, void * PublicExponent, int PublicExponentSize, void * PrivateExponent, int PrivateExponentSize, void * Signature, int &SignatureSize, TElRSAAntiTimingParams* AntiTimingParams)/* overload */;
extern PACKAGE bool __fastcall SignPSS(void * HashValue, int HashValueSize, int HashAlgorithm, int SaltSize, void * KeyBlob, int KeyBlobSize, void * Signature, int &SignatureSize, TElRSAAntiTimingParams* AntiTimingParams)/* overload */;
extern PACKAGE bool __fastcall VerifyPSS(void * HashValue, int HashValueSize, int HashAlgorithm, int SaltSize, void * PublicModulus, int PublicModulusSize, void * PublicExponent, int PublicExponentSize, void * Signature, int SignatureSize);
extern PACKAGE bool __fastcall DecodePublicKey(void * Buffer, int Size, void * PublicModulus, int &PublicModulusSize, void * PublicExponent, int &PublicExponentSize, Sbtypes::ByteArray &AlgID, bool InnerValuesOnly = false);
extern PACKAGE bool __fastcall EncodePublicKey(void * PublicModulus, int PublicModulusSize, void * PublicExponent, int PublicExponentSize, const Sbtypes::ByteArray AlgID, void * OutBuffer, int &OutSize, bool InnerValuesOnly = false);

}	/* namespace Sbrsa */
using namespace Sbrsa;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbrsaHPP
