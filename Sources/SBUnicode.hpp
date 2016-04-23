// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbunicode.pas' rev: 21.00

#ifndef SbunicodeHPP
#define SbunicodeHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Windows.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbunicode
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElUnicodeConverter;
class PASCALIMPLEMENTATION TElUnicodeConverter : public Sbstrutils::TElStringConverter
{
	typedef Sbstrutils::TElStringConverter inherited;
	
protected:
	virtual void __fastcall SetDefCharset(const System::UnicodeString Value);
	
public:
	__fastcall TElUnicodeConverter(void);
	__fastcall virtual ~TElUnicodeConverter(void);
	virtual Sbtypes::ByteArray __fastcall StrToUtf8(const System::UnicodeString Source);
	virtual System::UnicodeString __fastcall Utf8ToStr(const Sbtypes::ByteArray Source);
	virtual Sbtypes::ByteArray __fastcall StrToWideStr(const System::UnicodeString Source);
	virtual System::UnicodeString __fastcall WideStrToStr(const Sbtypes::ByteArray Source);
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE Sbstrutils::TElStringConverter* __fastcall CreateUnicodeStringConverter(void);

}	/* namespace Sbunicode */
using namespace Sbunicode;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbunicodeHPP
