// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbsockettspclient.pas' rev: 21.00

#ifndef SbsockettspclientHPP
#define SbsockettspclientHPP

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
#include <Sbpem.hpp>	// Pascal unit
#include <Sbasn1.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit
#include <Sbx509.hpp>	// Pascal unit
#include <Sbx509ext.hpp>	// Pascal unit
#include <Sbpkcs7.hpp>	// Pascal unit
#include <Sbpkicommon.hpp>	// Pascal unit
#include <Sbtspcommon.hpp>	// Pascal unit
#include <Sbtspclient.hpp>	// Pascal unit
#include <Sbsocket.hpp>	// Pascal unit
#include <Sbcustomcertstorage.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbsockettspclient
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElSocketTSPClient;
class PASCALIMPLEMENTATION TElSocketTSPClient : public Sbtspclient::TElCustomTSPClient
{
	typedef Sbtspclient::TElCustomTSPClient inherited;
	
protected:
	System::UnicodeString FAddress;
	int FPort;
	int FSocketTimeout;
	Sbsocket::TElSocket* FSocket;
	System::UnicodeString FErrorMessage;
	void __fastcall PrepareSocket(void);
	
public:
	__fastcall virtual TElSocketTSPClient(Classes::TComponent* Owner);
	__fastcall virtual ~TElSocketTSPClient(void);
	virtual int __fastcall Timestamp(const Sbtypes::ByteArray HashedData, /* out */ Sbpkicommon::TSBPKIStatus &ServerResult, /* out */ int &FailureInfo, /* out */ Sbtypes::ByteArray &ReplyCMS);
	__property Sbsocket::TElSocket* Socket = {read=FSocket};
	__property System::UnicodeString ErrorMessage = {read=FErrorMessage};
	
__published:
	__property System::UnicodeString Address = {read=FAddress, write=FAddress};
	__property int Port = {read=FPort, write=FPort, nodefault};
	__property int SocketTimeout = {read=FSocketTimeout, write=FSocketTimeout, nodefault};
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE void __fastcall Register(void);

}	/* namespace Sbsockettspclient */
using namespace Sbsockettspclient;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbsockettspclientHPP
