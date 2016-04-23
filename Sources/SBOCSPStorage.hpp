// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbocspstorage.pas' rev: 21.00

#ifndef SbocspstorageHPP
#define SbocspstorageHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbocspcommon.hpp>	// Pascal unit
#include <Sbocspclient.hpp>	// Pascal unit
#include <Sbpkicommon.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbocspstorage
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElOCSPResponseStorage;
class PASCALIMPLEMENTATION TElOCSPResponseStorage : public Classes::TPersistent
{
	typedef Classes::TPersistent inherited;
	
private:
	Classes::TList* FList;
	Sbocspclient::TElOCSPResponse* __fastcall GetResponse(int Index);
	int __fastcall GetCount(void);
	
public:
	__fastcall TElOCSPResponseStorage(void);
	__fastcall virtual ~TElOCSPResponseStorage(void);
	int __fastcall Add(Sbocspclient::TElOCSPResponse* Resp)/* overload */;
	int __fastcall Add(void)/* overload */;
	void __fastcall Remove(int Index);
	int __fastcall IndexOf(Sbocspclient::TElOCSPResponse* Resp);
	void __fastcall Clear(void);
	__property Sbocspclient::TElOCSPResponse* Responses[int Index] = {read=GetResponse};
	__property int Count = {read=GetCount, nodefault};
};


//-- var, const, procedure ---------------------------------------------------

}	/* namespace Sbocspstorage */
using namespace Sbocspstorage;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbocspstorageHPP
