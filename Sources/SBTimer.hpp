// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbtimer.pas' rev: 21.00

#ifndef SbtimerHPP
#define SbtimerHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Windows.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbsharedresource.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbtimer
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TTimerThread;
class PASCALIMPLEMENTATION TTimerThread : public Classes::TThread
{
	typedef Classes::TThread inherited;
	
private:
	unsigned FEvent;
	Classes::TNotifyEvent FOnTimer;
	Classes::TNotifyEvent FOnFinish;
	int FInterval;
	bool FTerminate;
	bool FEnabled;
	
protected:
	void __fastcall DoTimer(void);
	void __fastcall SetInterval(int Interval);
	void __fastcall SetEnabled(bool Value);
	bool __fastcall GetEnabled(void);
	
public:
	__fastcall TTimerThread(void);
	__fastcall virtual ~TTimerThread(void);
	virtual void __fastcall Execute(void);
	__property Classes::TNotifyEvent OnTimer = {read=FOnTimer, write=FOnTimer};
	__property Classes::TNotifyEvent OnFinish = {read=FOnFinish, write=FOnFinish};
	__property int Interval = {read=FInterval, write=SetInterval, nodefault};
	__property bool TerminateNow = {read=FTerminate, write=FTerminate, nodefault};
	__property bool Enabled = {read=GetEnabled, write=SetEnabled, nodefault};
};


class DELPHICLASS TElTimer;
class PASCALIMPLEMENTATION TElTimer : public Classes::TComponent
{
	typedef Classes::TComponent inherited;
	
protected:
	Classes::TNotifyEvent FOnTimer;
	int FInterval;
	TTimerThread* FTimerThread;
	bool FRecreateThreads;
	Sbsharedresource::TElSharedResource* FTimerThreadCS;
	void __fastcall SetInterval(int Value);
	bool __fastcall GetEnabled(void);
	void __fastcall SetEnabled(bool Value);
	void __fastcall HandleTimerEvent(System::TObject* Sender);
	void __fastcall CreateTimerIfNeeded(void);
	void __fastcall KillTimer(void);
	
public:
	__fastcall virtual TElTimer(Classes::TComponent* AOwner);
	__fastcall virtual ~TElTimer(void);
	__property int Interval = {read=FInterval, write=SetInterval, nodefault};
	__property bool Enabled = {read=GetEnabled, write=SetEnabled, nodefault};
	__property bool RecreateThreads = {read=FRecreateThreads, write=FRecreateThreads, nodefault};
	
__published:
	__property Classes::TNotifyEvent OnTimer = {read=FOnTimer, write=FOnTimer};
};


//-- var, const, procedure ---------------------------------------------------

}	/* namespace Sbtimer */
using namespace Sbtimer;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbtimerHPP
