// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbsharedresource.pas' rev: 21.00

#ifndef SbsharedresourceHPP
#define SbsharedresourceHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Windows.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbrandom.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbsharedresource
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElSharedResource;
class PASCALIMPLEMENTATION TElSharedResource : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	unsigned FActiveThreadID;
	int FActive;
	int FWaitingReaders;
	int FWaitingWriters;
	unsigned FSemReaders;
	unsigned FSemWriters;
	_RTL_CRITICAL_SECTION FCS;
	int FWriteDepth;
	bool FEnabled;
	
public:
	__fastcall TElSharedResource(void);
	__fastcall virtual ~TElSharedResource(void);
	void __fastcall WaitToRead(void);
	void __fastcall WaitToWrite(void);
	void __fastcall Done(void);
	__property bool Enabled = {read=FEnabled, write=FEnabled, default=1};
};


//-- var, const, procedure ---------------------------------------------------

}	/* namespace Sbsharedresource */
using namespace Sbsharedresource;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbsharedresourceHPP
