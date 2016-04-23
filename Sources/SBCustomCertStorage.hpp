// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbcustomcertstorage.pas' rev: 21.00

#ifndef SbcustomcertstorageHPP
#define SbcustomcertstorageHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbstringlist.hpp>	// Pascal unit
#include <Sbasn1.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit
#include <Sbcryptoprov.hpp>	// Pascal unit
#include <Sbrdn.hpp>	// Pascal unit
#include <Sbsymmetriccrypto.hpp>	// Pascal unit
#include <Sbx509.hpp>	// Pascal unit
#include <Sbx509ext.hpp>	// Pascal unit
#include <Sbcrl.hpp>	// Pascal unit
#include <Sbpem.hpp>	// Pascal unit
#include <Sbjks.hpp>	// Pascal unit
#include <Sbstreams.hpp>	// Pascal unit
#include <Sbsharedresource.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbencoding.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbcustomcertstorage
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElCustomCertStorage;
#pragma option push -b-
enum TSBCertStorageOption { csoStrictChainBuilding };
#pragma option pop

typedef Set<TSBCertStorageOption, csoStrictChainBuilding, csoStrictChainBuilding>  TSBCertStorageOptions;

class DELPHICLASS TElCertificateLookup;
class PASCALIMPLEMENTATION TElCustomCertStorage : public Sbx509::TElBaseCertStorage
{
	typedef Sbx509::TElBaseCertStorage inherited;
	
private:
	typedef DynamicArray<int> _TElCustomCertStorage__1;
	
	
public:
	Sbx509::TElX509Certificate* operator[](int Index) { return Certificates[Index]; }
	
private:
	TSBCertStorageOptions FOptions;
	void __fastcall ReadCertificatesProp(Classes::TStream* Reader);
	void __fastcall WriteCertificatesProp(Classes::TStream* Writer);
	bool __fastcall IsCertificatesPropStored(void);
	void __fastcall ReadFakeCertificatesProp(Classes::TReader* Reader);
	
protected:
	bool FRebuildChains;
	_TElCustomCertStorage__1 FChains;
	Sbcrl::TElCertificateRevocationList* FCRL;
	Sbsharedresource::TElSharedResource* FSharedResource;
	Sbcryptoprov::TElCustomCryptoProviderManager* FCryptoProviderManager;
	bool __fastcall Equal(const Sbx509::TName &N1, const Sbx509::TName &N2);
	virtual void __fastcall AssignTo(Classes::TPersistent* Dest);
	virtual void __fastcall DefineProperties(Classes::TFiler* Filer);
	bool __fastcall AliasNeededInt(Sbx509::TElX509Certificate* Cert, System::UnicodeString &Alias);
	bool __fastcall IsIssuerCertificate(Sbx509::TElX509Certificate* Subject, Sbx509::TElX509Certificate* Issuer);
	void __fastcall BuildAllChains(void);
	virtual void __fastcall Notification(Classes::TComponent* AComponent, Classes::TOperation Operation);
	virtual int __fastcall GetCount(void);
	int __fastcall GetChainCount(void);
	void __fastcall SetCRL(Sbcrl::TElCertificateRevocationList* Value);
	void __fastcall SetCryptoProviderManager(Sbcryptoprov::TElCustomCryptoProviderManager* Value);
	virtual Sbx509::TElX509Certificate* __fastcall GetCertificates(int Index);
	int __fastcall GetChain(int Index);
	
public:
	__fastcall virtual TElCustomCertStorage(Classes::TComponent* Owner);
	__fastcall virtual ~TElCustomCertStorage(void);
	virtual Sbx509::TSBCertificateValidity __fastcall Validate(Sbx509::TElX509Certificate* Certificate, Sbx509::TSBCertificateValidityReason &Reason, System::TDateTime ValidityMoment = 0.000000E+00)/* overload */;
	virtual Sbx509::TSBCertificateValidity __fastcall Validate(Sbx509::TElX509Certificate* Certificate, Sbx509::TSBCertificateValidityReason &Reason, bool CheckCACertDates, System::TDateTime ValidityMoment = 0.000000E+00)/* overload */;
	virtual void __fastcall Add(Sbx509::TElX509Certificate* Certificate, bool CopyPrivateKey = true) = 0 ;
	HIDESBASE virtual void __fastcall Remove(int Index) = 0 ;
	virtual void __fastcall ExportTo(TElCustomCertStorage* Storage);
	int __fastcall LoadFromBufferPKCS7(void * Buffer, int Size);
	bool __fastcall SaveToBufferPKCS7(void * Buffer, int &Size);
	int __fastcall LoadFromStreamPKCS7(Classes::TStream* Stream, int Count = 0x0);
	bool __fastcall SaveToStreamPKCS7(Classes::TStream* Stream);
	int __fastcall LoadFromBufferPEM(void * Buffer, int Size, const System::UnicodeString Password);
	bool __fastcall SaveToBufferPEM(void * Buffer, int &Size, const System::UnicodeString Password)/* overload */;
	bool __fastcall SaveToBufferPEM(void * Buffer, int &Size, const System::UnicodeString Password, int EncryptionAlgorithm, Sbsymmetriccrypto::TSBSymmetricCryptoMode EncryptionMode)/* overload */;
	int __fastcall LoadFromStreamPEM(Classes::TStream* Stream, const System::UnicodeString Password, int Count = 0x0);
	bool __fastcall SaveToStreamPEM(Classes::TStream* Stream, const System::UnicodeString Password)/* overload */;
	bool __fastcall SaveToStreamPEM(Classes::TStream* Stream, const System::UnicodeString Password, int EncryptionAlgorithm, Sbsymmetriccrypto::TSBSymmetricCryptoMode EncryptionMode)/* overload */;
	bool __fastcall LoadFromBufferJKS(void * Buffer, const System::UnicodeString Pass, int Size, Sbjks::TElJKSPasswordEvent OnPasswordNeeded = 0x0);
	bool __fastcall SaveToBufferJKS(void * Buffer, const System::UnicodeString Pass, int &Size);
	bool __fastcall SaveToBufferJKSEx(void * Buffer, const System::UnicodeString Pass, int &Size, Sbjks::TElJKSAliasNeededEvent OnAliasNeeded);
	bool __fastcall LoadFromStreamJKS(Classes::TStream* Stream, const System::UnicodeString Pass, int Count = 0x0, Sbjks::TElJKSPasswordEvent OnPasswordNeeded = 0x0);
	bool __fastcall SaveToStreamJKS(Classes::TStream* Stream, const System::UnicodeString Pass);
	bool __fastcall SaveToStreamJKSEx(Classes::TStream* Stream, const System::UnicodeString Pass, Sbjks::TElJKSAliasNeededEvent OnAliasNeeded);
	int __fastcall LoadFromBufferPFX(void * Buffer, int Size, const System::UnicodeString Password);
	int __fastcall SaveToBufferPFX(void * Buffer, int &Size, const System::UnicodeString Password, int KeyEncryptionAlgorithm, int CertEncryptionAlgorithm)/* overload */;
	int __fastcall SaveToBufferPFX(void * Buffer, int &Size, const System::UnicodeString Password)/* overload */;
	int __fastcall LoadFromStreamPFX(Classes::TStream* Stream, const System::UnicodeString Password, int Count = 0x0);
	int __fastcall SaveToStreamPFX(Classes::TStream* Stream, const System::UnicodeString Password, int KeyEncryptionAlgorithm, int CertEncryptionAlgorithm)/* overload */;
	int __fastcall SaveToStreamPFX(Classes::TStream* Stream, const System::UnicodeString Password)/* overload */;
	bool __fastcall LoadFromBufferPkiPath(void * Buffer, int Size);
	bool __fastcall SaveToBufferPkiPath(void * Buffer, int &Size)/* overload */;
	bool __fastcall LoadFromStreamPkiPath(Classes::TStream* Stream, int Count = 0x0);
	bool __fastcall SaveToStreamPkiPath(Classes::TStream* Stream)/* overload */;
	Sbx509::TElX509CertificateChain* __fastcall BuildChain(Sbx509::TElX509Certificate* Certificate)/* overload */;
	Sbx509::TElX509CertificateChain* __fastcall BuildChain(int ChainIndex)/* overload */;
	virtual int __fastcall IndexOf(Sbx509::TElX509Certificate* Certificate);
	bool __fastcall IsPresent(Sbx509::TElX509Certificate* Certificate);
	virtual void __fastcall Clear(void);
	int __fastcall FindByHash(const Sbtypes::TMessageDigest160 &Digest)/* overload */;
	int __fastcall FindByHash(const Sbtypes::TMessageDigest128 &Digest)/* overload */;
	virtual int __fastcall GetIssuerCertificate(Sbx509::TElX509Certificate* Certificate);
	__classmethod virtual bool __fastcall IsReadOnly();
	int __fastcall FindFirst(TElCertificateLookup* Lookup);
	int __fastcall FindNext(TElCertificateLookup* Lookup);
	virtual void __fastcall ImportFrom(Sbx509::TElX509CertificateChain* Chain)/* overload */;
	virtual void __fastcall ImportFrom(Sbx509::TElX509CertificateChain* Chain, bool ImportEndEntity)/* overload */;
	void __fastcall BeginRead(void);
	bool __fastcall Contains(Sbx509::TElX509Certificate* Certificate);
	void __fastcall EndRead(void);
	__property int Count = {read=GetCount, nodefault};
	__property int ChainCount = {read=GetChainCount, nodefault};
	__property Sbx509::TElX509Certificate* Certificates[int Index] = {read=GetCertificates/*, default*/};
	__property int Chains[int Index] = {read=GetChain};
	
__published:
	__property Sbcrl::TElCertificateRevocationList* CRL = {read=FCRL, write=SetCRL};
	__property Sbcryptoprov::TElCustomCryptoProviderManager* CryptoProviderManager = {read=FCryptoProviderManager, write=SetCryptoProviderManager};
	__property TSBCertStorageOptions Options = {read=FOptions, write=FOptions, nodefault};
};

typedef TElCustomCertStorage ElCustomCertStorage
#pragma option push -b-
enum TSBLookupCriterion { lcIssuer, lcSubject, lcValidity, lcPublicKeyAlgorithm, lcSignatureAlgorithm, lcPublicKeySize, lcAuthorityKeyIdentifier, lcSubjectKeyIdentifier, lcKeyUsage, lcEmail, lcSerialNumber, lcPublicKeyHash, lcCertificateHash };
#pragma option pop

typedef Set<TSBLookupCriterion, lcIssuer, lcCertificateHash>  TSBLookupCriteria;

#pragma option push -b-
enum TSBLookupOption { loExactMatch, loMatchAll, loCompareRDNAsStrings };
#pragma option pop

typedef Set<TSBLookupOption, loExactMatch, loCompareRDNAsStrings>  TSBLookupOptions;

#pragma option push -b-
enum TSBDateLookupOption { dloBefore, dloAfter, dloBetween };
#pragma option pop

typedef Set<TSBDateLookupOption, dloBefore, dloBetween>  TSBDateLookupOptions;

#pragma option push -b-
enum TSBKeySizeLookupOption { ksloSmaller, ksloGreater, ksloBetween };
#pragma option pop

#pragma option push -b-
enum TSBKeyUsageLookupOption { kuloMatchAll };
#pragma option pop

typedef Set<TSBKeyUsageLookupOption, kuloMatchAll, kuloMatchAll>  TSBKeyUsageLookupOptions;

typedef TElCertificateLookup ElCertificateLookup;

class PASCALIMPLEMENTATION TElCertificateLookup : public Classes::TComponent
{
	typedef Classes::TComponent inherited;
	
private:
	TSBLookupCriteria FCriteria;
	TSBLookupOptions FOptions;
	Sbrdn::TElRelativeDistinguishedName* FIssuerRDN;
	Sbrdn::TElRelativeDistinguishedName* FSubjectRDN;
	System::TDateTime FValidFrom;
	System::TDateTime FValidTo;
	int FPublicKeyAlgorithm;
	int FSignatureAlgorithm;
	int FPublicKeySizeMin;
	int FPublicKeySizeMax;
	Sbtypes::ByteArray FAuthorityKeyIdentifier;
	Sbtypes::ByteArray FSubjectKeyIdentifier;
	Sbx509ext::TSBKeyUsage FKeyUsage;
	Classes::TStringList* FEmailAddresses;
	Sbtypes::ByteArray FSerialNumber;
	Sbtypes::ByteArray FPublicKeyHash;
	int FPublicKeyHashAlgorithm;
	Sbtypes::ByteArray FCertificateHash;
	int FCertificateHashAlgorithm;
	TSBDateLookupOptions FDateLookupOptions;
	TSBKeySizeLookupOption FKeySizeLookupOption;
	TSBKeyUsageLookupOptions FKeyUsageLookupOptions;
	
protected:
	int FLastIndex;
	virtual int __fastcall FindNext(TElCustomCertStorage* Storage);
	void __fastcall SetCriteria(TSBLookupCriteria Value);
	void __fastcall SetAuthorityKeyIdentifier(const Sbtypes::ByteArray V);
	void __fastcall SetSubjectKeyIdentifier(const Sbtypes::ByteArray V);
	void __fastcall SetSerialNumber(const Sbtypes::ByteArray V);
	void __fastcall SetPublicKeyHash(const Sbtypes::ByteArray V);
	void __fastcall SetCertificateHash(const Sbtypes::ByteArray V);
	
public:
	__fastcall virtual TElCertificateLookup(Classes::TComponent* AOwner);
	__fastcall virtual ~TElCertificateLookup(void);
	__property Sbtypes::ByteArray AuthorityKeyIdentifier = {read=FAuthorityKeyIdentifier, write=SetAuthorityKeyIdentifier};
	__property Sbtypes::ByteArray SubjectKeyIdentifier = {read=FSubjectKeyIdentifier, write=SetSubjectKeyIdentifier};
	__property Sbtypes::ByteArray SerialNumber = {read=FSerialNumber, write=SetSerialNumber};
	__property Sbtypes::ByteArray PublicKeyHash = {read=FPublicKeyHash, write=SetPublicKeyHash};
	__property Sbtypes::ByteArray CertificateHash = {read=FCertificateHash, write=SetCertificateHash};
	
__published:
	__property TSBLookupCriteria Criteria = {read=FCriteria, write=SetCriteria, nodefault};
	__property TSBLookupOptions Options = {read=FOptions, write=FOptions, nodefault};
	__property Sbrdn::TElRelativeDistinguishedName* IssuerRDN = {read=FIssuerRDN};
	__property Sbrdn::TElRelativeDistinguishedName* SubjectRDN = {read=FSubjectRDN};
	__property System::TDateTime ValidFrom = {read=FValidFrom, write=FValidFrom};
	__property System::TDateTime ValidTo = {read=FValidTo, write=FValidTo};
	__property int PublicKeyAlgorithm = {read=FPublicKeyAlgorithm, write=FPublicKeyAlgorithm, nodefault};
	__property int SignatureAlgorithm = {read=FSignatureAlgorithm, write=FSignatureAlgorithm, nodefault};
	__property int PublicKeySizeMin = {read=FPublicKeySizeMin, write=FPublicKeySizeMin, nodefault};
	__property int PublicKeySizeMax = {read=FPublicKeySizeMax, write=FPublicKeySizeMax, nodefault};
	__property Sbx509ext::TSBKeyUsage KeyUsage = {read=FKeyUsage, write=FKeyUsage, nodefault};
	__property Classes::TStringList* EmailAddresses = {read=FEmailAddresses};
	__property int PublicKeyHashAlgorithm = {read=FPublicKeyHashAlgorithm, write=FPublicKeyHashAlgorithm, nodefault};
	__property int CertificateHashAlgorithm = {read=FCertificateHashAlgorithm, write=FCertificateHashAlgorithm, nodefault};
	__property TSBDateLookupOptions DateLookupOptions = {read=FDateLookupOptions, write=FDateLookupOptions, nodefault};
	__property TSBKeySizeLookupOption KeySizeLookupOption = {read=FKeySizeLookupOption, write=FKeySizeLookupOption, nodefault};
	__property TSBKeyUsageLookupOptions KeyUsageLookupOptions = {read=FKeyUsageLookupOptions, write=FKeyUsageLookupOptions, nodefault};
};


typedef void __fastcall (__closure *TSBCertificateValidationEvent)(System::TObject* Sender, Sbx509::TElX509Certificate* Certificate, TElCustomCertStorage* AdditionalCertificates, Sbx509::TSBCertificateValidity &Validity, Sbx509::TSBCertificateValidityReason &Reason, bool &DoContinue);

class DELPHICLASS TElMemoryCertStorage;
class PASCALIMPLEMENTATION TElMemoryCertStorage : public TElCustomCertStorage
{
	typedef TElCustomCertStorage inherited;
	
private:
	Sbutils::TSBObjectList* FCertificateList;
	
protected:
	virtual int __fastcall GetCount(void);
	virtual Sbx509::TElX509Certificate* __fastcall GetCertificates(int Index);
	
public:
	__fastcall virtual TElMemoryCertStorage(Classes::TComponent* Owner);
	__fastcall virtual ~TElMemoryCertStorage(void);
	virtual void __fastcall Add(Sbx509::TElX509Certificate* X509Certificate, bool CopyPrivateKey = true);
	virtual void __fastcall Remove(int Index);
	__property Sbutils::TSBObjectList* CertificateList = {read=FCertificateList};
};

typedef TElMemoryCertStorage ElMemoryCertStorage
#pragma option push -b-
enum TSBFileCertStorageAccessType { csatImmediate, csatOnDemand };
#pragma option pop

#pragma option push -b-
enum TSBFileCertStorageSaveOption { fcsoSaveOnDestroy, fcsoSaveOnFilenameChange, fcsoSaveOnChange };
#pragma option pop

typedef Set<TSBFileCertStorageSaveOption, fcsoSaveOnDestroy, fcsoSaveOnChange>  TSBFileCertStorageSaveOptions;

class DELPHICLASS TElFileCertStorage;
class PASCALIMPLEMENTATION TElFileCertStorage : public TElCustomCertStorage
{
	typedef TElCustomCertStorage inherited;
	
private:
	System::UnicodeString FFileName;
	Sbutils::TSBObjectList* FCertificateList;
	bool FLoaded;
	TSBFileCertStorageAccessType FAccessType;
	TSBFileCertStorageSaveOptions FSaveOptions;
	
protected:
	void __fastcall LoadFromFile(void);
	void __fastcall InternalClear(void);
	void __fastcall CreateEmptyStorage(void);
	virtual int __fastcall GetCount(void);
	void __fastcall SetFileName(const System::UnicodeString FileName);
	void __fastcall SetAccessType(TSBFileCertStorageAccessType Value);
	virtual Sbx509::TElX509Certificate* __fastcall GetCertificates(int Index);
	
public:
	__fastcall virtual TElFileCertStorage(Classes::TComponent* Owner);
	__fastcall virtual ~TElFileCertStorage(void);
	virtual Sbx509::TSBCertificateValidity __fastcall Validate(Sbx509::TElX509Certificate* Certificate, Sbx509::TSBCertificateValidityReason &Reason, bool CheckCACertDates, System::TDateTime ValidityMoment = 0.000000E+00)/* overload */;
	virtual void __fastcall Add(Sbx509::TElX509Certificate* X509Certificate, bool CopyPrivateKey = true);
	virtual void __fastcall Remove(int Index);
	virtual void __fastcall Clear(void);
	void __fastcall SaveToFile(const System::UnicodeString FileName);
	void __fastcall Reload(void);
	void __fastcall Save(void);
	
__published:
	__property System::UnicodeString FileName = {read=FFileName, write=SetFileName};
	__property TSBFileCertStorageAccessType AccessType = {read=FAccessType, write=SetAccessType, default=1};
	__property TSBFileCertStorageSaveOptions SaveOptions = {read=FSaveOptions, write=FSaveOptions, default=0};
	
/* Hoisted overloads: */
	
public:
	inline Sbx509::TSBCertificateValidity __fastcall  Validate(Sbx509::TElX509Certificate* Certificate, Sbx509::TSBCertificateValidityReason &Reason, System::TDateTime ValidityMoment = 0.000000E+00){ return TElCustomCertStorage::Validate(Certificate, Reason, ValidityMoment); }
	
};

typedef TElFileCertStorage ElFileCertStorage
class DELPHICLASS EElCertStorageError;
class PASCALIMPLEMENTATION EElCertStorageError : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElCertStorageError(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElCertStorageError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElCertStorageError(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElCertStorageError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElCertStorageError(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElCertStorageError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElCertStorageError(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElCertStorageError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElCertStorageError(void) { }
	
};


class DELPHICLASS EElDuplicateCertError;
class PASCALIMPLEMENTATION EElDuplicateCertError : public EElCertStorageError
{
	typedef EElCertStorageError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElDuplicateCertError(const System::UnicodeString AMessage)/* overload */ : EElCertStorageError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElDuplicateCertError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : EElCertStorageError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElDuplicateCertError(int Ident)/* overload */ : EElCertStorageError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElDuplicateCertError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : EElCertStorageError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElDuplicateCertError(const System::UnicodeString Msg, int AHelpContext) : EElCertStorageError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElDuplicateCertError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : EElCertStorageError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElDuplicateCertError(int Ident, int AHelpContext)/* overload */ : EElCertStorageError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElDuplicateCertError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : EElCertStorageError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElDuplicateCertError(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE void __fastcall Register(void);

}	/* namespace Sbcustomcertstorage */
using namespace Sbcustomcertstorage;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbcustomcertstorageHPP
