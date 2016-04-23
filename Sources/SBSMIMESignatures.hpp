// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbsmimesignatures.pas' rev: 21.00

#ifndef SbsmimesignaturesHPP
#define SbsmimesignaturesHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbmessages.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbsmimesignatures
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElSMIMEMessageSigner;
class PASCALIMPLEMENTATION TElSMIMEMessageSigner : public Sbmessages::TElMessageSigner
{
	typedef Sbmessages::TElMessageSigner inherited;
	
public:
	virtual int __fastcall Sign(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, bool Detached = false)/* overload */;
public:
	/* TElMessageSigner.Create */ inline __fastcall virtual TElSMIMEMessageSigner(Classes::TComponent* AOwner) : Sbmessages::TElMessageSigner(AOwner) { }
	/* TElMessageSigner.Destroy */ inline __fastcall virtual ~TElSMIMEMessageSigner(void) { }
	
	
/* Hoisted overloads: */
	
public:
	inline int __fastcall  Sign(Classes::TStream* InStream, Classes::TStream* OutStream, bool Detached = false, __int64 InCount = 0x000000000){ return Sbmessages::TElMessageSigner::Sign(InStream, OutStream, Detached, InCount); }
	
};

typedef TElSMIMEMessageSigner ElSMIMEMessageSigner
class DELPHICLASS TElSMIMEMessageVerifier;
class PASCALIMPLEMENTATION TElSMIMEMessageVerifier : public Sbmessages::TElMessageVerifier
{
	typedef Sbmessages::TElMessageVerifier inherited;
	
private:
	System::TDateTime __fastcall ProcessTime(const Sbtypes::ByteArray Time);
	
public:
	virtual int __fastcall Verify(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
	virtual int __fastcall VerifyDetached(void * Buffer, int Size, void * Signature, int SignatureSize)/* overload */;
public:
	/* TElMessageVerifier.Create */ inline __fastcall virtual TElSMIMEMessageVerifier(Classes::TComponent* AOwner) : Sbmessages::TElMessageVerifier(AOwner) { }
	/* TElMessageVerifier.Destroy */ inline __fastcall virtual ~TElSMIMEMessageVerifier(void) { }
	
	
/* Hoisted overloads: */
	
public:
	inline int __fastcall  Verify(Classes::TStream* InStream, Classes::TStream* OutStream, __int64 InCount = 0x000000000){ return Sbmessages::TElMessageVerifier::Verify(InStream, OutStream, InCount); }
	inline int __fastcall  VerifyDetached(Classes::TStream* InStream, Classes::TStream* SigStream, __int64 InCount = 0x000000000, __int64 SigCount = 0x000000000){ return Sbmessages::TElMessageVerifier::VerifyDetached(InStream, SigStream, InCount, SigCount); }
	
};

typedef TElSMIMEMessageVerifier ElSMIMEMessageVerifier
//-- var, const, procedure ---------------------------------------------------
static const int SB_MESSAGE_ERROR_INVALID_MESSAGE_DIGEST = 8272;
static const int SB_MESSAGE_WARNING_OMITTED_MESSAGE_DIGEST = 8273;

}	/* namespace Sbsmimesignatures */
using namespace Sbsmimesignatures;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbsmimesignaturesHPP
