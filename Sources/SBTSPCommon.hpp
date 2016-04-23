// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbtspcommon.pas' rev: 21.00

#ifndef SbtspcommonHPP
#define SbtspcommonHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbasn1.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit
#include <Sbx509ext.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbtspcommon
{
//-- type declarations -------------------------------------------------------
typedef short TSBTSPFailureInfo;

class DELPHICLASS TElTSPInfo;
class PASCALIMPLEMENTATION TElTSPInfo : public Classes::TPersistent
{
	typedef Classes::TPersistent inherited;
	
protected:
	Sbtypes::ByteArray FNonce;
	Sbtypes::ByteArray FSerialNumber;
	System::TDateTime FTime;
	bool FAccuracySet;
	int FAccuracySec;
	int FAccuracyMilli;
	int FAccuracyMicro;
	Sbx509ext::TElGeneralName* FTSAName;
	bool FTSANameSet;
	virtual void __fastcall SetNonce(const Sbtypes::ByteArray Nonce);
	void __fastcall SetSerialNumber(const Sbtypes::ByteArray SN);
	
public:
	__fastcall virtual TElTSPInfo(void);
	__fastcall virtual ~TElTSPInfo(void);
	virtual void __fastcall Assign(Classes::TPersistent* Source);
	virtual void __fastcall Reset(void);
	__property Sbtypes::ByteArray SerialNumber = {read=FSerialNumber, write=SetSerialNumber};
	__property Sbtypes::ByteArray Nonce = {read=FNonce, write=SetNonce};
	__property System::TDateTime Time = {read=FTime, write=FTime};
	__property int AccuracySec = {read=FAccuracySec, write=FAccuracySec, nodefault};
	__property int AccuracyMilli = {read=FAccuracyMilli, write=FAccuracyMilli, nodefault};
	__property int AccuracyMicro = {read=FAccuracyMicro, write=FAccuracyMicro, nodefault};
	__property bool AccuracySet = {read=FAccuracySet, write=FAccuracySet, nodefault};
	__property Sbx509ext::TElGeneralName* TSAName = {read=FTSAName};
	__property bool TSANameSet = {read=FTSANameSet, write=FTSANameSet, nodefault};
};

typedef TElTSPInfo ElTSPInfo
class DELPHICLASS TElTSPClass;
class PASCALIMPLEMENTATION TElTSPClass : public Classes::TComponent
{
	typedef Classes::TComponent inherited;
	
public:
	__fastcall virtual TElTSPClass(Classes::TComponent* Owner);
	__fastcall virtual ~TElTSPClass(void);
	bool __fastcall ValidateImprint(int Algorithm, const Sbtypes::ByteArray HashedData, const Sbtypes::ByteArray Imprint);
};

typedef TElTSPClass ElTSPClass
//-- var, const, procedure ---------------------------------------------------
static const int ERROR_FACILITY_TSP = 0x14000;
static const Word ERROR_TSP_PROTOCOL_ERROR_FLAG = 0x800;
static const int SB_TSP_ERROR_ABORTED = 83969;
static const int SB_TSP_ERROR_NO_REPLY = 83970;
static const int SB_TSP_ERROR_NO_PARAMETERS = 83971;
static const int SB_TSP_ERROR_NO_CERTIFICATES = 83972;
static const int SB_TSP_ERROR_WRONG_DATA = 83973;
static const int SB_TSP_ERROR_WRONG_IMPRINT = 83974;
static const int SB_TSP_ERROR_WRONG_NONCE = 83975;
static const int SB_TSP_ERROR_UNEXPECTED_CERTIFICATES = 83976;
static const int SB_TSP_ERROR_UNRECOGNIZED_FORMAT = 81921;
static const int SB_TSP_ERROR_DATA_TOO_LONG = 81922;
static const int SB_TSP_ERROR_UNSUPPORTED_REPLY = 81923;
static const int SB_TSP_ERROR_GENERAL_ERROR = 81924;
static const int SB_TSP_ERROR_REQUEST_REJECTED = 81925;
static const short tfiBadAlg = 0;
static const short tfiBadRequest = 2;
static const short tfiBadDataFormat = 5;
static const short tfiTimeNotAvailable = 14;
static const short tfiUnacceptedPolicy = 15;
static const short tfiUnacceptedExtension = 16;
static const short tfiAddInfoNotAvailable = 17;
static const short tfiSystemFailure = 25;
extern PACKAGE Sbtypes::ByteArray SB_TSP_OID_AUTHENTICODE_TIMESTAMP;
extern PACKAGE Sbtypes::ByteArray SB_TSP_OID_PKCS7_DATA;

}	/* namespace Sbtspcommon */
using namespace Sbtspcommon;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbtspcommonHPP
