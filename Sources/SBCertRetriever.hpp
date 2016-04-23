// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbcertretriever.pas' rev: 21.00

#ifndef SbcertretrieverHPP
#define SbcertretrieverHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbencoding.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbx509.hpp>	// Pascal unit
#include <Sbx509ext.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbcertretriever
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElCustomCertificateRetriever;
class PASCALIMPLEMENTATION TElCustomCertificateRetriever : public Classes::TComponent
{
	typedef Classes::TComponent inherited;
	
public:
	__fastcall virtual TElCustomCertificateRetriever(Classes::TComponent* Owner);
	__fastcall virtual ~TElCustomCertificateRetriever(void);
	virtual bool __fastcall SupportsLocation(Sbx509ext::TSBGeneralName NameType, const System::UnicodeString URI) = 0 ;
	virtual Sbx509::TElX509Certificate* __fastcall RetrieveCertificate(Sbx509::TElX509Certificate* Certificate, Sbx509ext::TSBGeneralName NameType, const System::UnicodeString URL) = 0 ;
};


typedef void __fastcall (__closure *TSBCertificateRetrievalEvent)(System::TObject* Sender, Sbx509::TElX509Certificate* Certificate, Sbx509ext::TSBGeneralName NameType, const System::UnicodeString Location, Sbx509::TElX509Certificate* &CACertificate);

class DELPHICLASS TElFileCertificateRetriever;
class PASCALIMPLEMENTATION TElFileCertificateRetriever : public TElCustomCertificateRetriever
{
	typedef TElCustomCertificateRetriever inherited;
	
protected:
	TSBCertificateRetrievalEvent FOnCertificateNeeded;
	
public:
	virtual Sbx509::TElX509Certificate* __fastcall RetrieveCertificate(Sbx509::TElX509Certificate* Certificate, Sbx509ext::TSBGeneralName NameType, const System::UnicodeString URL);
	virtual bool __fastcall SupportsLocation(Sbx509ext::TSBGeneralName NameType, const System::UnicodeString URI);
	
__published:
	__property TSBCertificateRetrievalEvent OnCertificateNeeded = {read=FOnCertificateNeeded, write=FOnCertificateNeeded};
public:
	/* TElCustomCertificateRetriever.Create */ inline __fastcall virtual TElFileCertificateRetriever(Classes::TComponent* Owner) : TElCustomCertificateRetriever(Owner) { }
	/* TElCustomCertificateRetriever.Destroy */ inline __fastcall virtual ~TElFileCertificateRetriever(void) { }
	
};

typedef TElFileCertificateRetriever ElFileCertificateRetriever
class DELPHICLASS TElCustomCertificateRetrieverFactory;
class PASCALIMPLEMENTATION TElCustomCertificateRetrieverFactory : public System::TObject
{
	typedef System::TObject inherited;
	
public:
	virtual bool __fastcall SupportsLocation(Sbx509ext::TSBGeneralName NameType, const System::UnicodeString URI) = 0 ;
	virtual TElCustomCertificateRetriever* __fastcall GetClientInstance(System::TObject* Validator) = 0 ;
public:
	/* TObject.Create */ inline __fastcall TElCustomCertificateRetrieverFactory(void) : System::TObject() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TElCustomCertificateRetrieverFactory(void) { }
	
};

typedef TElCustomCertificateRetrieverFactory ElCustomCertificateRetrieverFactory
class DELPHICLASS TElCertificateRetrieverManager;
class PASCALIMPLEMENTATION TElCertificateRetrieverManager : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	Classes::TList* FFactoryList;
	
public:
	__fastcall TElCertificateRetrieverManager(void);
	__fastcall virtual ~TElCertificateRetrieverManager(void);
	TElCustomCertificateRetriever* __fastcall FindCertificateRetrieverByLocation(Sbx509ext::TSBGeneralName NameType, const System::UnicodeString Location, System::TObject* Validator);
	void __fastcall RegisterCertificateRetrieverFactory(TElCustomCertificateRetrieverFactory* Factory);
	void __fastcall UnregisterCertificateRetrieverFactory(TElCustomCertificateRetrieverFactory* Factory);
};

typedef TElCertificateRetrieverManager ElCertRetrieverManager
//-- var, const, procedure ---------------------------------------------------
static const int ERROR_FACILITY_CERT_RETRIEVER = 0x1b000;
static const Word ERROR_CERT_RETRIEVER_ERROR_FLAG = 0x800;
static const int SB_CERT_RETRIEVER_ERROR_NO_PARAMETERS = 112645;
static const int SB_CERT_RETRIEVER_ERROR_NO_REPLY = 112646;
extern PACKAGE void __fastcall Register(void);
extern PACKAGE TElCertificateRetrieverManager* __fastcall CertificateRetrieverManagerAddRef(void);
extern PACKAGE void __fastcall CertificateRetrieverManagerRelease(void);

}	/* namespace Sbcertretriever */
using namespace Sbcertretriever;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbcertretrieverHPP
