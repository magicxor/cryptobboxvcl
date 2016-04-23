// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbhttpauth.pas' rev: 21.00

#ifndef SbhttpauthHPP
#define SbhttpauthHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbencoding.hpp>	// Pascal unit
#include <Sbhashfunction.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbhttpsconstants.hpp>	// Pascal unit
#include <Sbrandom.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Windows.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbhttpauth
{
//-- type declarations -------------------------------------------------------
typedef void * *PPointer;

typedef int *PInteger;

typedef unsigned *PLongWord;

struct AUTH_SEQ
{
	
public:
	bool UUEncodeData;
	System::UnicodeString RequestURI;
	int RequestMethod;
	System::UnicodeString sNonce;
	System::UnicodeString cNonce;
	int cNonceCount;
	System::UnicodeString cRequest;
};


typedef AUTH_SEQ *PAUTH_SEQ;

//-- var, const, procedure ---------------------------------------------------
extern PACKAGE System::UnicodeString cAuth;
extern PACKAGE System::UnicodeString cAuth2;
extern PACKAGE System::UnicodeString cPAuth;
extern PACKAGE System::UnicodeString cPAuth2;
extern PACKAGE System::UnicodeString cBasic;
extern PACKAGE System::UnicodeString cNTLM;
extern PACKAGE System::UnicodeString cDigest;
extern PACKAGE bool secInit;
extern PACKAGE char *TOKEN_SOURCE_NAME;
extern PACKAGE void __fastcall ValidateSecPacks(Classes::TStringList* ls);
extern PACKAGE void __fastcall AuthInit(PAUTH_SEQ pAS);
extern PACKAGE void __fastcall AuthTerm(PAUTH_SEQ pAS);
extern PACKAGE bool __fastcall AuthConverse(PAUTH_SEQ pAS, const Sbtypes::ByteArray BuffIn, /* out */ Sbtypes::ByteArray &BuffOut, bool &NeedMoreData, System::UnicodeString Package, System::UnicodeString User, const System::UnicodeString Password);
extern PACKAGE bool __fastcall AddAuthorizationHeader(System::UnicodeString &Str, const System::UnicodeString Scheme, const System::UnicodeString AuthData, const System::UnicodeString UserName, const System::UnicodeString Password, bool &NeedMoreData, bool ForProxy, PAUTH_SEQ aSeq);
extern PACKAGE void __fastcall InitAuthLib(void);

}	/* namespace Sbhttpauth */
using namespace Sbhttpauth;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbhttpauthHPP
