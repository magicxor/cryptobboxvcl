// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbpkcs12.pas' rev: 21.00

#ifndef Sbpkcs12HPP
#define Sbpkcs12HPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Windows.hpp>	// Pascal unit
#include <Sbstringlist.hpp>	// Pascal unit
#include <Sbpkcs7.hpp>	// Pascal unit
#include <Sbcrl.hpp>	// Pascal unit
#include <Sbpkcs7utils.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit
#include <Sbasn1.hpp>	// Pascal unit
#include <Sbx509.hpp>	// Pascal unit
#include <Sbrandom.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbmd.hpp>	// Pascal unit
#include <Sbsha.hpp>	// Pascal unit
#include <Sbmath.hpp>	// Pascal unit
#include <Sbcryptoprov.hpp>	// Pascal unit
#include <Sbhashfunction.hpp>	// Pascal unit
#include <Sbrsa.hpp>	// Pascal unit
#include <Sbdsa.hpp>	// Pascal unit
#include <Sbcrlstorage.hpp>	// Pascal unit
#include <Sbcustomcertstorage.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbpkcs12
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElPKCS12Message;
class PASCALIMPLEMENTATION TElPKCS12Message : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	Sbutils::TElByteArrayList* FPrivateKeys;
	Sbutils::TElByteArrayList* FPrivateKeyParams;
	Sbutils::TElByteArrayList* FPrivateKeyAlgorithms;
	Sbtypes::ByteArray FDigestAlgorithm;
	Sbtypes::ByteArray FDigestAlgorithmParams;
	Sbtypes::ByteArray FDigest;
	Sbtypes::ByteArray FSalt;
	System::UnicodeString FPassword;
	int FIterations;
	Sbcustomcertstorage::TElMemoryCertStorage* FCertificates;
	Sbcrlstorage::TElMemoryCRLStorage* FCRLs;
	int FKeyEncryptionAlgorithm;
	int FCertEncryptionAlgorithm;
	int FCRLEncryptionAlgorithm;
	Sbrandom::TElRandom* FRandom;
	unsigned FLastKeyId;
	bool FUseEmptyPasswordWorkaround;
	Sbcryptoprov::TElCustomCryptoProviderManager* FCryptoProviderManager;
	
protected:
	int __fastcall ProcessAuthenticatedSafe(void * Buffer, int Size);
	int __fastcall ProcessMACData(Sbasn1tree::TElASN1ConstrainedTag* Tag, void * Buffer, int Size);
	int __fastcall ProcessSafeBags(void * P, int Size);
	int __fastcall ProcessPrivateKeyInfo(void * Buffer, int Size, Sbtypes::ByteArray &Algorithm, Sbtypes::ByteArray &PrivateKey, Sbtypes::ByteArray &PrivateKeyParams);
	int __fastcall ProcessSafeContents(Sbpkcs7::TElPKCS7Message* Mes);
	int __fastcall ProcessSafeBag(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	int __fastcall ProcessShroudedKeyBag(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	int __fastcall ProcessCertBag(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	int __fastcall ProcessKeyBag(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	int __fastcall ProcessCRLBag(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	int __fastcall ProcessEncryptedSafeBags(Sbpkcs7::TElPKCS7Message* Tag);
	bool __fastcall DecryptRC2(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, const Sbtypes::ByteArray Key, const Sbtypes::ByteArray IV);
	bool __fastcall Decrypt3DES(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, const Sbtypes::ByteArray Key, const Sbtypes::ByteArray IV);
	bool __fastcall DecryptRC4(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, const Sbtypes::ByteArray Key);
	bool __fastcall EncryptContent(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, int Algorithm, const Sbtypes::ByteArray Key, const Sbtypes::ByteArray IV);
	bool __fastcall CheckPadding(void * Buffer, int Size);
	bool __fastcall GetKeyAndIVLengths(int AlgId, int &KeyLen, int &IVLen);
	bool __fastcall KeyCorresponds(Sbx509::TElX509Certificate* Certificate, void * KeyBuffer, int KeySize);
	Sbtypes::ByteArray __fastcall DeriveKeyFromPassword(const System::UnicodeString Password, const Sbtypes::ByteArray Salt, System::Byte Id, int HashAlgorithm, int Iters, int Size, bool UseEmptyPassBugWorkaround = false);
	Sbtypes::TMessageDigest160 __fastcall CalculateHashSHA1(void * Buffer, int Size, int Iterations);
	Sbtypes::TMessageDigest128 __fastcall CalculateHashMD5(void * Buffer, int Size, int Iterations);
	int __fastcall SaveAuthenticatedSafe(Sbasn1tree::TElASN1ConstrainedTag* Tag, Sbasn1tree::TElASN1ConstrainedTag* MAC);
	int __fastcall SaveShroudedKeyBag(void * OutBuffer, int &OutSize, Sbx509::TElX509Certificate* Cert);
	int __fastcall SaveCertBag(void * CertBuffer, int CertSize, void * OutBuffer, int &OutSize);
	int __fastcall SaveCRLBag(void * CRLBuffer, int CRLSize, void * OutBuffer, int &OutSize);
	int __fastcall SaveMACData(void * Buffer, int Size, Sbasn1tree::TElASN1ConstrainedTag* Tag);
	bool __fastcall ComposeDSAPrivateKey(void * X, int XSize, Sbx509::TElX509Certificate* Certificate, void * OutBuffer, int &OutSize);
	bool __fastcall DecomposeDSAPrivateKey(void * KeyBlob, int KeyBlobSize, void * PrivateKey, int &PrivateKeySize, void * Params, int &ParamsSize);
	System::UnicodeString __fastcall GetPassword(void);
	void __fastcall SetPassword(const System::UnicodeString Value);
	
public:
	__fastcall TElPKCS12Message(void);
	__fastcall virtual ~TElPKCS12Message(void);
	int __fastcall LoadFromBuffer(void * Buffer, int Size);
	int __fastcall SaveToBuffer(void * Buffer, int &Size);
	__property int Iterations = {read=FIterations, write=FIterations, nodefault};
	__property System::UnicodeString Password = {read=GetPassword, write=SetPassword};
	__property Sbcustomcertstorage::TElMemoryCertStorage* Certificates = {read=FCertificates};
	__property Sbcrlstorage::TElMemoryCRLStorage* CRLs = {read=FCRLs};
	__property int KeyEncryptionAlgorithm = {read=FKeyEncryptionAlgorithm, write=FKeyEncryptionAlgorithm, nodefault};
	__property int CertEncryptionAlgorithm = {read=FCertEncryptionAlgorithm, write=FCertEncryptionAlgorithm, nodefault};
	__property int CRLEncryptionAlgorithm = {read=FCRLEncryptionAlgorithm, write=FCRLEncryptionAlgorithm, nodefault};
	__property bool UseEmptyPasswordWorkaround = {read=FUseEmptyPasswordWorkaround, write=FUseEmptyPasswordWorkaround, nodefault};
	__property Sbcryptoprov::TElCustomCryptoProviderManager* CryptoProviderManager = {read=FCryptoProviderManager, write=FCryptoProviderManager};
};

typedef TElPKCS12Message ElPKCS12Message
class DELPHICLASS EElPKCS12Error;
class PASCALIMPLEMENTATION EElPKCS12Error : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElPKCS12Error(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElPKCS12Error(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElPKCS12Error(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElPKCS12Error(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElPKCS12Error(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElPKCS12Error(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElPKCS12Error(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElPKCS12Error(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElPKCS12Error(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
static const int SB_PKCS12_ERROR_INVALID_ASN_DATA = 7937;
static const int SB_PKCS12_ERROR_NO_DATA = 7938;
static const int SB_PKCS12_ERROR_INVALID_DATA = 7939;
static const int SB_PKCS12_ERROR_INVALID_VERSION = 7940;
static const int SB_PKCS12_ERROR_INVALID_CONTENT = 7941;
static const int SB_PKCS12_ERROR_INVALID_AUTHENTICATED_SAFE_DATA = 7942;
static const int SB_PKCS12_ERROR_INVALID_MAC_DATA = 7943;
static const int SB_PKCS12_ERROR_INVALID_SAFE_CONTENTS = 7944;
static const int SB_PKCS12_ERROR_INVALID_SAFE_BAG = 7945;
static const int SB_PKCS12_ERROR_INVALID_SHROUDED_KEY_BAG = 7946;
static const int SB_PKCS12_ERROR_UNKNOWN_PBE_ALGORITHM = 7947;
static const int SB_PKCS12_ERROR_INTERNAL_ERROR = 7948;
static const int SB_PKCS12_ERROR_INVALID_PBE_ALGORITHM_PARAMS = 7949;
static const int SB_PKCS12_ERROR_INVALID_CERT_BAG = 7950;
static const int SB_PKCS12_ERROR_UNSUPPORTED_CERTIFICATE_TYPE = 7951;
static const int SB_PKCS12_ERROR_INVALID_PRIVATE_KEY = 7952;
static const int SB_PKCS12_ERROR_INVALID_MAC = 7953;
static const int SB_PKCS12_ERROR_NO_CERTIFICATES = 7954;
static const int SB_PKCS12_ERROR_INVALID_PASSWORD = 7955;
static const int SB_PKCS12_ERROR_BUFFER_TOO_SMALL = 7956;
static const int SB_PKCS12_ERROR_INVALID_CRL_BAG = 7957;
static const int SB_PKCS12_ERROR_UNSUPPORTED_CRL_TYPE = 7958;
extern PACKAGE void __fastcall RaisePKCS12Error(int ErrorCode);
extern PACKAGE int __fastcall BufToInt(void * Buffer, int Size);
extern PACKAGE Sbtypes::ByteArray __fastcall IntToBuf(int Number);

}	/* namespace Sbpkcs12 */
using namespace Sbpkcs12;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// Sbpkcs12HPP
