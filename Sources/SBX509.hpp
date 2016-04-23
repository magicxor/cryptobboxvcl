// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbx509.pas' rev: 21.00

#ifndef Sbx509HPP
#define Sbx509HPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Windows.hpp>	// Pascal unit
#include <Activex.hpp>	// Pascal unit
#include <Sbwincrypt.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbstringlist.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbstreams.hpp>	// Pascal unit
#include <Sbencoding.hpp>	// Pascal unit
#include <Sbmd.hpp>	// Pascal unit
#include <Sbsha.hpp>	// Pascal unit
#include <Sbmath.hpp>	// Pascal unit
#include <Sbrdn.hpp>	// Pascal unit
#include <Sbasn1.hpp>	// Pascal unit
#include <Sbpem.hpp>	// Pascal unit
#include <Sbhashfunction.hpp>	// Pascal unit
#include <Sbpkiasync.hpp>	// Pascal unit
#include <Sbx509ext.hpp>	// Pascal unit
#include <Sbcustomcrypto.hpp>	// Pascal unit
#include <Sbsymmetriccrypto.hpp>	// Pascal unit
#include <Sbpublickeycrypto.hpp>	// Pascal unit
#include <Sbalgorithmidentifier.hpp>	// Pascal unit
#include <Sbcryptoprov.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbx509
{
//-- type declarations -------------------------------------------------------
#pragma option push -b-
enum TSBCertificateValidity { cvOk, cvSelfSigned, cvInvalid, cvStorageError, cvChainUnvalidated };
#pragma option pop

#pragma option push -b-
enum Sbx509__1 { vrBadData, vrRevoked, vrNotYetValid, vrExpired, vrInvalidSignature, vrUnknownCA, vrCAUnauthorized, vrCRLNotVerified, vrOCSPNotVerified, vrIdentityMismatch, vrNoKeyUsage, vrBlocked };
#pragma option pop

typedef Set<Sbx509__1, vrBadData, vrBlocked>  TSBCertificateValidityReason;

#pragma option push -b-
enum TSBCertFileFormat { cfUnknown, cfDER, cfPEM, cfPFX, cfSPC };
#pragma option pop

#pragma option push -b-
enum TSBX509KeyFileFormat { kffUnknown, kffDER, kffPEM, kffPFX, kffPVK, kffNET, kffPKCS8 };
#pragma option pop

struct TValidity
{
	
public:
	System::TDateTime NotBefore;
	System::TDateTime NotAfter;
};


struct TName
{
	
public:
	System::UnicodeString Country;
	System::UnicodeString StateOrProvince;
	System::UnicodeString Locality;
	System::UnicodeString Organization;
	System::UnicodeString OrganizationUnit;
	System::UnicodeString CommonName;
	System::UnicodeString EMailAddress;
};


class DELPHICLASS TElSubjectPublicKeyInfo;
class PASCALIMPLEMENTATION TElSubjectPublicKeyInfo : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	Sbalgorithmidentifier::TElAlgorithmIdentifier* FAlgorithm;
	Sbtypes::ByteArray FRawData;
	Sbtypes::ByteArray FFullData;
	Sbalgorithmidentifier::TElAlgorithmIdentifier* __fastcall GetPublicKeyAlgorithmIdentifier(void);
	int __fastcall GetPublicKeyAlgorithm(void);
	Sbtypes::ByteArray __fastcall GetRawData(void);
	
public:
	__fastcall TElSubjectPublicKeyInfo(void);
	__fastcall virtual ~TElSubjectPublicKeyInfo(void);
	void __fastcall Clear(void);
	__property Sbalgorithmidentifier::TElAlgorithmIdentifier* PublicKeyAlgorithmIdentifier = {read=GetPublicKeyAlgorithmIdentifier};
	__property int PublicKeyAlgorithm = {read=GetPublicKeyAlgorithm, nodefault};
	__property Sbtypes::ByteArray RawData = {read=GetRawData};
};

typedef TElSubjectPublicKeyInfo ElSubjectPublicKeyInfo
class DELPHICLASS TElTBSCertificate;
class PASCALIMPLEMENTATION TElTBSCertificate : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	System::Byte FVersion;
	Sbtypes::ByteArray FSerialNumber;
	Sbalgorithmidentifier::TElAlgorithmIdentifier* FSignatureIdentifier;
	TValidity FValidity;
	Classes::TStringList* FIssuer;
	Classes::TStringList* FSubject;
	TElSubjectPublicKeyInfo* FSubjectPublicKeyInfo;
	Sbtypes::ByteArray FIssuerUniqueID;
	Sbtypes::ByteArray FSubjectUniqueID;
	void __fastcall SetSerialNumber(const Sbtypes::ByteArray V);
	void __fastcall SetIssuerUniqueID(const Sbtypes::ByteArray V);
	void __fastcall SetSubjectUniqueID(const Sbtypes::ByteArray V);
	
public:
	__fastcall TElTBSCertificate(void);
	__fastcall virtual ~TElTBSCertificate(void);
	void __fastcall Clear(void);
	__property System::Byte Version = {read=FVersion, write=FVersion, nodefault};
	__property Sbtypes::ByteArray SerialNumber = {read=FSerialNumber, write=SetSerialNumber};
	__property Sbalgorithmidentifier::TElAlgorithmIdentifier* SignatureIdentifier = {read=FSignatureIdentifier};
	__property Classes::TStringList* Issuer = {read=FIssuer};
	__property Classes::TStringList* Subject = {read=FSubject};
	__property TElSubjectPublicKeyInfo* SubjectPublicKeyInfo = {read=FSubjectPublicKeyInfo};
	__property Sbtypes::ByteArray IssuerUniqueID = {read=FIssuerUniqueID, write=SetIssuerUniqueID};
	__property Sbtypes::ByteArray SubjectUniqueID = {read=FSubjectUniqueID, write=SetSubjectUniqueID};
	__property TValidity Validity = {read=FValidity, write=FValidity};
};

typedef TElTBSCertificate ElTBSCertificate
class DELPHICLASS TElX509CertificateChain;
class DELPHICLASS TElX509Certificate;
class PASCALIMPLEMENTATION TElX509CertificateChain : public Classes::TComponent
{
	typedef Classes::TComponent inherited;
	
protected:
	Classes::TList* FCertificates;
	int __fastcall GetCount(void);
	void __fastcall DoAdd(TElX509Certificate* Certificate);
	bool __fastcall GetComplete(void);
	TElX509Certificate* __fastcall GetCertificate(int Index);
	
public:
	__fastcall virtual TElX509CertificateChain(Classes::TComponent* Owner);
	__fastcall virtual ~TElX509CertificateChain(void);
	bool __fastcall Add(TElX509Certificate* Certificate);
	TSBCertificateValidity __fastcall Validate(TSBCertificateValidityReason &Reason, System::TDateTime ValidityMoment = 0.000000E+00)/* overload */;
	TSBCertificateValidity __fastcall Validate(TSBCertificateValidityReason &Reason, bool CheckCACertDates, System::TDateTime ValidityMoment = 0.000000E+00)/* overload */;
	__property TElX509Certificate* Certificates[int Index] = {read=GetCertificate};
	__property bool Complete = {read=GetComplete, nodefault};
	__property int Count = {read=GetCount, nodefault};
};

typedef TElX509CertificateChain ElX509CertificateChain
typedef TElX509Certificate ElX509Certificate;

class DELPHICLASS TElBaseCertStorage;
class PASCALIMPLEMENTATION TElBaseCertStorage : public Classes::TComponent
{
	typedef Classes::TComponent inherited;
	
protected:
	void __fastcall AddToChain(TElX509CertificateChain* Chain, TElX509Certificate* Certificate);
public:
	/* TComponent.Create */ inline __fastcall virtual TElBaseCertStorage(Classes::TComponent* AOwner) : Classes::TComponent(AOwner) { }
	/* TComponent.Destroy */ inline __fastcall virtual ~TElBaseCertStorage(void) { }
	
};

typedef TElBaseCertStorage ElBaseCertStorage
#pragma option push -b-
enum TSBCertSecurityLevel { cslLow, cslMedium, cslHigh };
#pragma option pop

class PASCALIMPLEMENTATION TElX509Certificate : public Classes::TComponent
{
	typedef Classes::TComponent inherited;
	
protected:
	TElTBSCertificate* FtbsCertificate;
	Sbalgorithmidentifier::TElAlgorithmIdentifier* FSignatureAlgorithm;
	Sbcryptoprov::TElCustomCryptoProvider* FCryptoProvider;
	Sbpublickeycrypto::TElPublicKeyMaterial* FSigningKey;
	Sbtypes::ByteArray FSignatureValue;
	TName FIssuerName;
	TName FSubjectName;
	bool FNegativeSerial;
	System::Byte FErrorCode;
	Sysutils::TByteArray *FPData;
	int FAllSize;
	int FCertificateSize;
	int FCertificateOffset;
	TName FNewSubject;
	TName FNewIssuer;
	bool FCAAvailable;
	Sbtypes::ByteArray FCAKeyIdentifier;
	TElX509Certificate* FCACert;
	Sbtypes::ByteArray FOurKeyIdentifier;
	Sbx509ext::TElCertificateExtensions* FCertificateExtensions;
	Sbrdn::TElRelativeDistinguishedName* FIssuerRDN;
	Sbrdn::TElRelativeDistinguishedName* FSubjectRDN;
	bool FStrictMode;
	bool FReportErrorOnPartialLoad;
	bool FUseUTF8;
	Sbpublickeycrypto::TElPublicKeyMaterial* FKeyMaterial;
	Sbtypes::ByteArray FPublicKeyBlob;
	bool FIgnoreVersion;
	void __fastcall ReadCertificate(void);
	void __fastcall ReadCertificateFromASN(void);
	void __fastcall AddFieldByOID(TName &Name, const Sbtypes::ByteArray OID, System::Byte Tag, const Sbtypes::ByteArray Content);
	Sysutils::PByteArray __fastcall GetCertificateBinary(void);
	bool __fastcall GetCertificateSelfSigned(void);
	int __fastcall GetSignatureAlgorithm(void);
	System::TDateTime __fastcall GetValidFrom(void);
	System::TDateTime __fastcall GetValidTo(void);
	void __fastcall SetValidFrom(const System::TDateTime Value);
	void __fastcall SetValidTo(const System::TDateTime Value);
	int __fastcall GetPublicKeyAlgorithm(void);
	Sbalgorithmidentifier::TElAlgorithmIdentifier* __fastcall GetPublicKeyAlgorithmIdentifier(void);
	TElBaseCertStorage* FCertStorage;
	int FBelongsTo;
	System::UnicodeString FStorageName;
	TElX509CertificateChain* FChain;
	Sbcryptoprov::TElCustomCryptoProviderManager* FCryptoProviderManager;
	virtual void __fastcall ClearData(void);
	virtual void __fastcall AssignTo(Classes::TPersistent* Dest);
	void __fastcall RaiseInvalidCertificateException(void);
	void __fastcall SetupKeyMaterial(void);
	Sbwincrypt::PCCERT_CONTEXT __fastcall GetCertHandle(void);
	void __fastcall SetCertHandle(Sbwincrypt::PCCERT_CONTEXT Value);
	System::UnicodeString __fastcall GetFriendlyName(void);
	void __fastcall SetFriendlyName(const System::UnicodeString Value);
	bool __fastcall GetCanEncrypt(void);
	bool __fastcall GetCanSign(void);
	System::Byte __fastcall GetVersion(void);
	void __fastcall SetVersion(System::Byte Value);
	Sbtypes::ByteArray __fastcall GetSerialNumber(void);
	void __fastcall SetSerialNumber(const Sbtypes::ByteArray Value);
	Classes::TStringList* __fastcall GetIssuer(void);
	Classes::TStringList* __fastcall GetSubject(void);
	Sbtypes::ByteArray __fastcall GetIssuerUniqueID(void);
	Sbtypes::ByteArray __fastcall GetSubjectUniqueID(void);
	bool __fastcall GetPrivateKeyExtractable(void);
	bool __fastcall GetPrivateKeyExists(void);
	
public:
	__fastcall virtual TElX509Certificate(Classes::TComponent* Owner);
	__fastcall virtual ~TElX509Certificate(void);
	__classmethod TSBCertFileFormat __fastcall DetectCertFileFormat(const System::UnicodeString FileName)/* overload */;
	__classmethod TSBCertFileFormat __fastcall DetectCertFileFormat(Classes::TStream* Stream)/* overload */;
	__classmethod TSBX509KeyFileFormat __fastcall DetectKeyFileFormat(Classes::TStream* Stream, const System::UnicodeString Password)/* overload */;
	__classmethod TSBCertFileFormat __fastcall DetectCertFileFormat(void * Buffer, int Size)/* overload */;
	__classmethod TSBX509KeyFileFormat __fastcall DetectKeyFileFormat(const System::UnicodeString FileName, const System::UnicodeString Password)/* overload */;
	__classmethod TSBX509KeyFileFormat __fastcall DetectKeyFileFormat(void * Buffer, int Size, const System::UnicodeString Password)/* overload */;
	HIDESBASE bool __fastcall Equals(TElX509Certificate* Other);
	void __fastcall Clone(TElX509Certificate* Dest, bool CopyPrivateKey = true)/* overload */;
	void __fastcall Clone(TElX509Certificate* Dest, Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider)/* overload */;
	void __fastcall ChangeSecurityLevel(TSBCertSecurityLevel Level, const System::UnicodeString Password);
	void __fastcall LoadFromBuffer(void * Buffer, int Size);
	int __fastcall LoadFromBufferPEM(void * Buffer, int Size, const System::UnicodeString PassPhrase);
	void __fastcall LoadKeyFromBuffer(void * Buffer, int Size);
	int __fastcall LoadKeyFromBufferPEM(void * Buffer, int Size, const System::UnicodeString PassPhrase);
	int __fastcall LoadFromBufferPFX(void * Buffer, int Size, const System::UnicodeString Password);
	int __fastcall LoadFromBufferSPC(void * Buffer, int Size);
	int __fastcall LoadKeyFromBufferMS(void * Buffer, int Size);
	int __fastcall LoadKeyFromBufferPKCS8(void * Buffer, int Size, const System::UnicodeString Password);
	int __fastcall LoadFromBufferAuto(void * Buffer, int Size, const System::UnicodeString Password);
	int __fastcall LoadKeyFromBufferAuto(void * Buffer, int Size, const System::UnicodeString Password);
	int __fastcall LoadKeyFromBufferNET(void * Buffer, int Size, const System::UnicodeString Password);
	int __fastcall LoadKeyFromBufferPVK(void * Buffer, int Size, const System::UnicodeString Password);
	void __fastcall LoadKeyFromBufferPKCS15(void * Buffer, int Size, const System::UnicodeString Password);
	void __fastcall LoadKeyFromStreamPKCS15(Classes::TStream* Stream, const System::UnicodeString Password, int Count = 0x0);
	void __fastcall LoadFromStream(Classes::TStream* Stream, int Count = 0x0)/* overload */;
	void __fastcall LoadFromStream(_di_IStream Stream, int Count = 0x0)/* overload */;
	void __fastcall LoadKeyFromStream(Classes::TStream* Stream, int Count = 0x0);
	int __fastcall LoadKeyFromStreamPEM(Classes::TStream* Stream, const System::UnicodeString PassPhrase, int Count = 0x0);
	int __fastcall LoadFromStreamPEM(Classes::TStream* Stream, const System::UnicodeString PassPhrase, int Count = 0x0);
	int __fastcall LoadFromStreamPFX(Classes::TStream* Stream, const System::UnicodeString Password, int Count = 0x0);
	int __fastcall LoadFromStreamSPC(Classes::TStream* Stream, int Count = 0x0);
	int __fastcall LoadKeyFromStreamMS(Classes::TStream* Stream, int Count = 0x0);
	int __fastcall LoadKeyFromStreamPKCS8(Classes::TStream* Stream, const System::UnicodeString Password, int Count = 0x0);
	int __fastcall LoadKeyFromStreamPVK(Classes::TStream* Stream, const System::UnicodeString Password, int Count = 0x0);
	int __fastcall LoadFromStreamAuto(Classes::TStream* Stream, const System::UnicodeString Password, int Count);
	int __fastcall LoadKeyFromStreamAuto(Classes::TStream* Stream, const System::UnicodeString Password, int Count);
	int __fastcall LoadKeyFromStreamNET(Classes::TStream* Stream, const System::UnicodeString Password, int Count = 0x0);
	int __fastcall LoadFromFileAuto(const System::UnicodeString Filename, const System::UnicodeString Password);
	int __fastcall LoadKeyFromFileAuto(const System::UnicodeString Filename, const System::UnicodeString Password);
	bool __fastcall SaveToBuffer(void * Buffer, int &Size);
	bool __fastcall SaveKeyToBuffer(void * Buffer, int &Size);
	bool __fastcall SaveToBufferPEM(void * Buffer, int &Size, const System::UnicodeString PassPhrase);
	bool __fastcall SaveKeyToBufferPEM(void * Buffer, int &Size, const System::UnicodeString PassPhrase)/* overload */;
	bool __fastcall SaveKeyToBufferPEM(void * Buffer, int &Size, int EncryptionAlgorithm, Sbsymmetriccrypto::TSBSymmetricCryptoMode EncryptionMode, const System::UnicodeString PassPhrase)/* overload */;
	int __fastcall SaveToBufferPFX(void * Buffer, int &Size, const System::UnicodeString Password, int KeyEncryptionAlgorithm, int CertEncryptionAlgorithm)/* overload */;
	int __fastcall SaveToBufferPFX(void * Buffer, int &Size, const System::UnicodeString Password)/* overload */;
	int __fastcall SaveToBufferSPC(void * Buffer, int &Size);
	int __fastcall SaveKeyToBufferMS(void * Buffer, int &Size);
	int __fastcall SaveKeyToBufferNET(void * Buffer, int &Size);
	int __fastcall SaveKeyToBufferPVK(void * Buffer, int &Size, const System::UnicodeString Password, bool UseStrongEncryption = true);
	int __fastcall SaveKeyToBufferPKCS8(void * Buffer, int &Size, const System::UnicodeString Password);
	void __fastcall SaveToStream(Classes::TStream* Stream);
	void __fastcall SaveKeyToStream(Classes::TStream* Stream);
	void __fastcall SaveToStreamPEM(Classes::TStream* Stream, const System::UnicodeString PassPhrase);
	void __fastcall SaveKeyToStreamPEM(Classes::TStream* Stream, const System::UnicodeString PassPhrase)/* overload */;
	void __fastcall SaveKeyToStreamPEM(Classes::TStream* Stream, int EncryptionAlgorithm, Sbsymmetriccrypto::TSBSymmetricCryptoMode EncryptionMode, const System::UnicodeString PassPhrase)/* overload */;
	int __fastcall SaveToStreamPFX(Classes::TStream* Stream, const System::UnicodeString Password, int KeyEncryptionAlgorithm, int CertEncryptionAlgorithm)/* overload */;
	int __fastcall SaveToStreamPFX(Classes::TStream* Stream, const System::UnicodeString Password)/* overload */;
	int __fastcall SaveToStreamSPC(Classes::TStream* Stream);
	bool __fastcall SaveKeyValueToBuffer(void * Buffer, int &Size);
	int __fastcall SaveKeyToStreamMS(Classes::TStream* Stream);
	int __fastcall SaveKeyToStreamNET(Classes::TStream* Stream, const System::UnicodeString Password);
	int __fastcall SaveKeyToStreamPVK(Classes::TStream* Stream, const System::UnicodeString Password, bool UseStrongEncryption = true);
	int __fastcall SaveKeyToStreamPKCS8(Classes::TStream* Stream, const System::UnicodeString Password);
	int __fastcall SaveToFile(const System::UnicodeString Filename, const System::UnicodeString Password, TSBCertFileFormat Format);
	int __fastcall SaveKeyToFile(const System::UnicodeString Filename, const System::UnicodeString Password, TSBX509KeyFileFormat Format);
	bool __fastcall Validate(void);
	bool __fastcall ValidateWithCA(TElX509Certificate* CACertificate);
	bool __fastcall GetRSAParams(void * RSAModulus, int &RSAModulusSize, void * RSAPublicKey, int &RSAPublicKeySize);
	bool __fastcall GetDSSParams(void * DSSP, int &DSSPSize, void * DSSQ, int &DSSQSize, void * DSSG, int &DSSGSize, void * DSSY, int &DSSYSize);
	bool __fastcall GetDHParams(void * DHP, int &DHPSize, void * DHG, int &DHGSize, void * DHY, int &DHYSize);
	bool __fastcall GetPublicKeyBlob(void * Buffer, int &Size)/* overload */;
	void __fastcall GetPublicKeyBlob(/* out */ Sbtypes::ByteArray &Buffer)/* overload */;
	Sbtypes::ByteArray __fastcall GetFullPublicKeyInfo(void);
	Sbtypes::TMessageDigest128 __fastcall GetHashMD5(void);
	Sbtypes::TMessageDigest160 __fastcall GetHashSHA1(void);
	Sbtypes::TMessageDigest160 __fastcall GetKeyHashSHA1(void);
	Sbtypes::ByteArray __fastcall GetZIPCertIdentifier(void);
	int __fastcall GetPublicKeySize(void);
	bool __fastcall IsKeyValid(void);
	Sbtypes::ByteArray __fastcall WriteSerialNumber(void);
	Sbtypes::ByteArray __fastcall WriteExtensionSubjectKeyIdentifier(void);
	virtual Sbtypes::ByteArray __fastcall WriteSubject(void);
	virtual Sbtypes::ByteArray __fastcall WriteIssuer(void);
	void __fastcall SetKeyMaterial(Sbpublickeycrypto::TElPublicKeyMaterial* Value);
	bool __fastcall View(HWND Owner);
	__property Sysutils::PByteArray CertificateBinary = {read=GetCertificateBinary};
	__property int CertificateSize = {read=FAllSize, nodefault};
	__property int SignatureAlgorithm = {read=GetSignatureAlgorithm, nodefault};
	__property Sbalgorithmidentifier::TElAlgorithmIdentifier* SignatureAlgorithmIdentifier = {read=FSignatureAlgorithm};
	__property Sbtypes::ByteArray Signature = {read=FSignatureValue};
	__property System::Byte Version = {read=GetVersion, write=SetVersion, nodefault};
	__property Sbtypes::ByteArray SerialNumber = {read=GetSerialNumber, write=SetSerialNumber};
	__property System::TDateTime ValidFrom = {read=GetValidFrom, write=SetValidFrom};
	__property System::TDateTime ValidTo = {read=GetValidTo, write=SetValidTo};
	__property int BelongsTo = {read=FBelongsTo, write=FBelongsTo, nodefault};
	__property Sbwincrypt::PCCERT_CONTEXT CertHandle = {read=GetCertHandle, write=SetCertHandle};
	__property System::UnicodeString FriendlyName = {read=GetFriendlyName, write=SetFriendlyName};
	__property Sbtypes::ByteArray IssuerUniqueID = {read=GetIssuerUniqueID};
	__property Sbtypes::ByteArray SubjectUniqueID = {read=GetSubjectUniqueID};
	__property int PublicKeyAlgorithm = {read=GetPublicKeyAlgorithm, nodefault};
	__property Sbalgorithmidentifier::TElAlgorithmIdentifier* PublicKeyAlgorithmIdentifier = {read=GetPublicKeyAlgorithmIdentifier};
	__property bool PrivateKeyExists = {read=GetPrivateKeyExists, nodefault};
	__property bool PrivateKeyExtractable = {read=GetPrivateKeyExtractable, nodefault};
	__property bool CAAvailable = {read=FCAAvailable, write=FCAAvailable, nodefault};
	__property bool SelfSigned = {read=GetCertificateSelfSigned, nodefault};
	__property TName IssuerName = {read=FIssuerName};
	__property TName SubjectName = {read=FSubjectName};
	__property Sbrdn::TElRelativeDistinguishedName* IssuerRDN = {read=FIssuerRDN};
	__property Sbrdn::TElRelativeDistinguishedName* SubjectRDN = {read=FSubjectRDN};
	__property Sbx509ext::TElCertificateExtensions* Extensions = {read=FCertificateExtensions};
	__property TElBaseCertStorage* CertStorage = {read=FCertStorage, write=FCertStorage};
	__property System::UnicodeString StorageName = {read=FStorageName, write=FStorageName};
	__property bool CanEncrypt = {read=GetCanEncrypt, nodefault};
	__property bool CanSign = {read=GetCanSign, nodefault};
	__property bool StrictMode = {read=FStrictMode, write=FStrictMode, default=0};
	__property bool UseUTF8 = {read=FUseUTF8, write=FUseUTF8, default=0};
	__property TElX509CertificateChain* Chain = {read=FChain, write=FChain};
	__property Sbpublickeycrypto::TElPublicKeyMaterial* KeyMaterial = {read=FKeyMaterial};
	__property bool NegativeSerial = {read=FNegativeSerial, nodefault};
	__property bool ReportErrorOnPartialLoad = {read=FReportErrorOnPartialLoad, write=FReportErrorOnPartialLoad, nodefault};
	__property Sbcryptoprov::TElCustomCryptoProvider* CryptoProvider = {read=FCryptoProvider, write=FCryptoProvider};
	__property Sbcryptoprov::TElCustomCryptoProviderManager* CryptoProviderManager = {read=FCryptoProviderManager, write=FCryptoProviderManager};
	__property bool IgnoreVersion = {read=FIgnoreVersion, write=FIgnoreVersion, default=0};
};


typedef TMetaClass* TElX509CertificateClass;

typedef TElX509CertificateClass ElX509CertificateClass;

class DELPHICLASS EElX509Error;
class PASCALIMPLEMENTATION EElX509Error : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElX509Error(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElX509Error(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElX509Error(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElX509Error(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElX509Error(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElX509Error(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElX509Error(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElX509Error(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElX509Error(void) { }
	
};


#pragma pack(push,1)
struct TPVKHeader
{
	
public:
	unsigned magic;
	unsigned reserved;
	unsigned keytype;
	unsigned encrypted;
	unsigned saltlen;
	unsigned keylen;
};
#pragma pack(pop)


//-- var, const, procedure ---------------------------------------------------
static const int SB_X509_ERROR_INVALID_PVK_FILE = 20481;
static const int SB_X509_ERROR_INVALID_PASSWORD = 20482;
static const int SB_X509_ERROR_NO_PRIVATE_KEY = 20483;
static const int SB_X509_ERROR_UNSUPPORTED_ALGORITHM = 20484;
static const int SB_X509_ERROR_INVALID_PRIVATE_KEY = 20485;
static const int SB_X509_ERROR_INTERNAL_ERROR = 20486;
static const int SB_X509_ERROR_BUFFER_TOO_SMALL = 20487;
static const int SB_X509_ERROR_NO_CERTIFICATE = 20488;
static const int SB_X509_ERROR_UNRECOGNIZED_FORMAT = 20489;
static const ShortInt BT_WINDOWS = 0x1;
static const ShortInt BT_PKCS11 = 0x2;
static const ShortInt BT_WAB = 0x4;
static const ShortInt BT_OUTLOOK = 0x8;
static const ShortInt BT_FILE = 0x10;
extern PACKAGE bool NegativeSerialWorkaround;
extern PACKAGE void __fastcall RaiseX509Error(int ErrorCode);
extern PACKAGE void __fastcall Register(void);
extern PACKAGE Sbtypes::ByteArray __fastcall PVKHeaderToByteArray(const TPVKHeader &Header);
extern PACKAGE Sbtypes::ByteArray __fastcall PVK_DeriveKey(const Sbtypes::ByteArray Password, const Sbtypes::ByteArray Salt, bool AWeakMethod);
extern PACKAGE bool __fastcall SerialNumberCorresponds(TElX509Certificate* Cert, const Sbtypes::ByteArray Serial);
extern PACKAGE Sbtypes::ByteArray __fastcall GetOriginalSerialNumber(TElX509Certificate* Cert);

}	/* namespace Sbx509 */
using namespace Sbx509;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// Sbx509HPP
