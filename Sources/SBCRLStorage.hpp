// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbcrlstorage.pas' rev: 21.00

#ifndef SbcrlstorageHPP
#define SbcrlstorageHPP

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
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbx509.hpp>	// Pascal unit
#include <Sbpem.hpp>	// Pascal unit
#include <Sbx509ext.hpp>	// Pascal unit
#include <Sbrdn.hpp>	// Pascal unit
#include <Sbsharedresource.hpp>	// Pascal unit
#include <Sbcustomcrypto.hpp>	// Pascal unit
#include <Sbpublickeycrypto.hpp>	// Pascal unit
#include <Sbalgorithmidentifier.hpp>	// Pascal unit
#include <Sbcrl.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbcrlstorage
{
//-- type declarations -------------------------------------------------------
#pragma option push -b-
enum TSBCRLLookupCriterion { clcIssuer, clcDistributionPoint, clcNumber, clcReason, clcAuthorityKeyIdentifier, clcBaseCRLNumber };
#pragma option pop

typedef Set<TSBCRLLookupCriterion, clcIssuer, clcBaseCRLNumber>  TSBCRLLookupCriteria;

#pragma option push -b-
enum TSBCRLLookupOption { cloExactMatch, cloMatchAll };
#pragma option pop

typedef Set<TSBCRLLookupOption, cloExactMatch, cloMatchAll>  TSBCRLLookupOptions;

class DELPHICLASS TElCustomCRLStorage;
class DELPHICLASS TElCRLLookup;
class PASCALIMPLEMENTATION TElCustomCRLStorage : public Classes::TComponent
{
	typedef Classes::TComponent inherited;
	
protected:
	bool FEnabled;
	virtual int __fastcall GetCount(void) = 0 ;
	virtual Sbcrl::TElCertificateRevocationList* __fastcall GetCRL(int Index) = 0 ;
	
public:
	__fastcall virtual TElCustomCRLStorage(Classes::TComponent* AOwner);
	virtual void __fastcall BeginRead(void);
	virtual void __fastcall EndRead(void);
	virtual void __fastcall BeginWrite(void);
	virtual void __fastcall EndWrite(void);
	virtual int __fastcall Add(Sbcrl::TElCertificateRevocationList* CRL) = 0 ;
	void __fastcall FindMatchingCRLs(Sbx509::TElX509Certificate* Certificate, Sbx509ext::TElDistributionPoint* DistributionPoint, Classes::TList* List);
	HIDESBASE virtual void __fastcall Remove(int Index) = 0 ;
	virtual void __fastcall Clear(void) = 0 ;
	int __fastcall FindFirst(TElCRLLookup* Lookup);
	int __fastcall FindNext(TElCRLLookup* Lookup);
	void __fastcall ExportTo(TElCustomCRLStorage* Storage);
	virtual int __fastcall IndexOf(Sbcrl::TElCertificateRevocationList* Crl) = 0 ;
	__property Sbcrl::TElCertificateRevocationList* CRLs[int Index] = {read=GetCRL};
	__property int Count = {read=GetCount, nodefault};
public:
	/* TComponent.Destroy */ inline __fastcall virtual ~TElCustomCRLStorage(void) { }
	
};

typedef TElCustomCRLStorage ElCustomCRLStorage
typedef TElCRLLookup ElCRLLookup;

class PASCALIMPLEMENTATION TElCRLLookup : public Classes::TComponent
{
	typedef Classes::TComponent inherited;
	
protected:
	TSBCRLLookupCriteria FCriteria;
	TSBCRLLookupOptions FOptions;
	Sbrdn::TElRelativeDistinguishedName* FIssuerRDN;
	Sbx509ext::TElGeneralName* FDistributionPoint;
	Sbtypes::ByteArray FNumber;
	Sbx509ext::TSBCRLReasonFlags FReasons;
	Sbtypes::ByteArray FAuthorityKeyIdentifier;
	Sbtypes::ByteArray FBaseCRLNumber;
	int FLastIndex;
	virtual int __fastcall FindNext(TElCustomCRLStorage* Storage);
	void __fastcall SetCriteria(const TSBCRLLookupCriteria Value);
	void __fastcall SetNumber(const Sbtypes::ByteArray V);
	void __fastcall SetAuthorityKeyIdentifier(const Sbtypes::ByteArray V);
	void __fastcall SetBaseCRLNumber(const Sbtypes::ByteArray V);
	
public:
	__fastcall virtual TElCRLLookup(Classes::TComponent* AOwner);
	__fastcall virtual ~TElCRLLookup(void);
	__property Sbrdn::TElRelativeDistinguishedName* IssuerRDN = {read=FIssuerRDN};
	__property Sbx509ext::TElGeneralName* DistributionPoint = {read=FDistributionPoint};
	__property Sbtypes::ByteArray Number = {read=FNumber, write=SetNumber};
	__property Sbx509ext::TSBCRLReasonFlags Reasons = {read=FReasons, write=FReasons, nodefault};
	__property Sbtypes::ByteArray AuthorityKeyIdentifier = {read=FAuthorityKeyIdentifier, write=SetAuthorityKeyIdentifier};
	__property Sbtypes::ByteArray BaseCRLNumber = {read=FBaseCRLNumber, write=SetBaseCRLNumber};
	
__published:
	__property TSBCRLLookupCriteria Criteria = {read=FCriteria, write=SetCriteria, nodefault};
	__property TSBCRLLookupOptions Options = {read=FOptions, write=FOptions, nodefault};
};


class DELPHICLASS TElMemoryCRLStorage;
class PASCALIMPLEMENTATION TElMemoryCRLStorage : public TElCustomCRLStorage
{
	typedef TElCustomCRLStorage inherited;
	
protected:
	Sbsharedresource::TElSharedResource* FSharedResource;
	Classes::TList* FList;
	virtual int __fastcall GetCount(void);
	virtual Sbcrl::TElCertificateRevocationList* __fastcall GetCRL(int Index);
	
public:
	__fastcall virtual TElMemoryCRLStorage(Classes::TComponent* AOwner);
	__fastcall virtual ~TElMemoryCRLStorage(void);
	virtual void __fastcall BeginRead(void);
	virtual void __fastcall EndRead(void);
	virtual void __fastcall BeginWrite(void);
	virtual void __fastcall EndWrite(void);
	virtual int __fastcall Add(Sbcrl::TElCertificateRevocationList* CRL);
	virtual void __fastcall Remove(int Index);
	virtual void __fastcall Clear(void);
	virtual int __fastcall IndexOf(Sbcrl::TElCertificateRevocationList* Crl);
};

typedef TElMemoryCRLStorage ElMemoryCRLStorage
class DELPHICLASS TElCRLCacheStorage;
class PASCALIMPLEMENTATION TElCRLCacheStorage : public TElMemoryCRLStorage
{
	typedef TElMemoryCRLStorage inherited;
	
public:
	virtual int __fastcall Add(Sbcrl::TElCertificateRevocationList* CRL);
	__property bool Enabled = {read=FEnabled, write=FEnabled, nodefault};
public:
	/* TElMemoryCRLStorage.Create */ inline __fastcall virtual TElCRLCacheStorage(Classes::TComponent* AOwner) : TElMemoryCRLStorage(AOwner) { }
	/* TElMemoryCRLStorage.Destroy */ inline __fastcall virtual ~TElCRLCacheStorage(void) { }
	
};


class DELPHICLASS TElCustomCRLRetriever;
class PASCALIMPLEMENTATION TElCustomCRLRetriever : public Classes::TComponent
{
	typedef Classes::TComponent inherited;
	
public:
	virtual bool __fastcall Supports(Sbx509ext::TSBGeneralName NameType, const System::UnicodeString Location) = 0 ;
	virtual Sbcrl::TElCertificateRevocationList* __fastcall GetCRL(Sbx509::TElX509Certificate* ACertificate, Sbx509::TElX509Certificate* CACertificate, Sbx509ext::TSBGeneralName NameType, const System::UnicodeString Location) = 0 ;
public:
	/* TComponent.Create */ inline __fastcall virtual TElCustomCRLRetriever(Classes::TComponent* AOwner) : Classes::TComponent(AOwner) { }
	/* TComponent.Destroy */ inline __fastcall virtual ~TElCustomCRLRetriever(void) { }
	
};

typedef TElCustomCRLRetriever ElCustomCRLRetriever
class DELPHICLASS TElCustomCRLRetrieverFactory;
class PASCALIMPLEMENTATION TElCustomCRLRetrieverFactory : public System::TObject
{
	typedef System::TObject inherited;
	
public:
	virtual bool __fastcall Supports(Sbx509ext::TSBGeneralName NameType, const System::UnicodeString Location) = 0 ;
	virtual TElCustomCRLRetriever* __fastcall GetRetrieverInstance(System::TObject* Validator) = 0 ;
public:
	/* TObject.Create */ inline __fastcall TElCustomCRLRetrieverFactory(void) : System::TObject() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TElCustomCRLRetrieverFactory(void) { }
	
};


class DELPHICLASS TElCRLManager;
class PASCALIMPLEMENTATION TElCRLManager : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	Classes::TList* FFactoryList;
	TElCRLCacheStorage* FCache;
	bool FUseCache;
	void __fastcall SetUseCache(bool Value);
	
public:
	__fastcall TElCRLManager(void);
	__fastcall virtual ~TElCRLManager(void);
	void __fastcall PurgeExpiredCRLs(void);
	void __fastcall RegisterCRLRetrieverFactory(TElCustomCRLRetrieverFactory* Factory);
	void __fastcall UnregisterCRLRetrieverFactory(TElCustomCRLRetrieverFactory* Factory);
	TElCustomCRLRetriever* __fastcall FindCRLRetriever(Sbx509ext::TSBGeneralName NameType, const System::UnicodeString Location, System::TObject* Validator);
	__property TElCRLCacheStorage* CRLCache = {read=FCache};
	__property bool UseCache = {read=FUseCache, write=SetUseCache, nodefault};
};

typedef TElCRLManager ElCRLManager
//-- var, const, procedure ---------------------------------------------------
extern PACKAGE TElCRLManager* __fastcall CRLManagerAddRef(void);
extern PACKAGE void __fastcall CRLManagerRelease(void);

}	/* namespace Sbcrlstorage */
using namespace Sbcrlstorage;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbcrlstorageHPP
