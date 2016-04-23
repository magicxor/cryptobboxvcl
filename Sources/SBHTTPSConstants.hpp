// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbhttpsconstants.pas' rev: 21.00

#ifndef SbhttpsconstantsHPP
#define SbhttpsconstantsHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbhttpsconstants
{
//-- type declarations -------------------------------------------------------
#pragma option push -b-
enum TSBHTTPVersion { hvHTTP10, hvHTTP11 };
#pragma option pop

#pragma option push -b-
enum TSBHTTPChunkState { chSize, chLineFeed, chData, chHeader };
#pragma option pop

typedef StaticArray<System::UnicodeString, 2> Sbhttpsconstants__1;

typedef StaticArray<System::UnicodeString, 8> Sbhttpsconstants__2;

typedef StaticArray<System::UnicodeString, 7> Sbhttpsconstants__3;

typedef StaticArray<System::UnicodeString, 7> Sbhttpsconstants__4;

typedef StaticArray<System::UnicodeString, 12> Sbhttpsconstants__5;

//-- var, const, procedure ---------------------------------------------------
static const ShortInt SB_HTTP_REQUEST_CUSTOM = 0x0;
static const ShortInt SB_HTTP_REQUEST_FIRST = 0x1;
static const ShortInt SB_HTTP_REQUEST_GET = 0x1;
static const ShortInt SB_HTTP_REQUEST_POST = 0x2;
static const ShortInt SB_HTTP_REQUEST_HEAD = 0x3;
static const ShortInt SB_HTTP_REQUEST_OPTIONS = 0x4;
static const ShortInt SB_HTTP_REQUEST_DELETE = 0x5;
static const ShortInt SB_HTTP_REQUEST_TRACE = 0x6;
static const ShortInt SB_HTTP_REQUEST_PUT = 0x7;
static const ShortInt SB_HTTP_REQUEST_CONNECT = 0x8;
static const ShortInt SB_HTTP_REQUEST_LAST = 0x8;
extern PACKAGE Sbhttpsconstants__1 HTTPVersionStrings;
extern PACKAGE Sbhttpsconstants__2 HTTPCommandStrings;
extern PACKAGE Sbhttpsconstants__3 WkDays;
extern PACKAGE Sbhttpsconstants__4 WeekDays;
extern PACKAGE Sbhttpsconstants__5 Months;
extern PACKAGE Sbtypes::ByteArray HTTP10ByteArray;
extern PACKAGE Sbtypes::ByteArray HTTP11ByteArray;
extern PACKAGE System::ResourceString _SInvalidDateTime;
#define Sbhttpsconstants_SInvalidDateTime System::LoadResourceString(&Sbhttpsconstants::_SInvalidDateTime)

}	/* namespace Sbhttpsconstants */
using namespace Sbhttpsconstants;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbhttpsconstantsHPP
