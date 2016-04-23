// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbstringlist.pas' rev: 21.00

#ifndef SbstringlistHPP
#define SbstringlistHPP

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
#include <Sbconstants.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbstringlist
{
//-- type declarations -------------------------------------------------------
typedef Classes::TStringList ElStringList;

typedef StaticArray<Sbtypes::ByteArray, 134217728> TByteArrays;

typedef TByteArrays *PByteArrayItem;

class DELPHICLASS TElStringTokenizer;
class PASCALIMPLEMENTATION TElStringTokenizer : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	int FPosition;
	bool FInQuote;
	bool FReturnEmptyTokens;
	System::UnicodeString FDelimiters;
	System::WideChar FEscapeChar;
	System::WideChar FOpeningQuote;
	System::WideChar FClosingQuote;
	System::UnicodeString FSourceString;
	bool FTrimQuotes;
	bool FTrimSpaces;
	bool __fastcall DoGetNext(bool CareForDelimiters, System::UnicodeString &Value);
	void __fastcall SetClosingQuote(const System::WideChar Value);
	void __fastcall SetReturnEmptyTokens(const bool Value);
	void __fastcall SetDelimiters(const System::UnicodeString Value);
	void __fastcall SetEscapeChar(const System::WideChar Value);
	void __fastcall SetOpeningQuote(const System::WideChar Value);
	void __fastcall SetSourceString(const System::UnicodeString Value);
	void __fastcall SetTrimQuotes(const bool Value);
	void __fastcall SetTrimSpaces(const bool Value);
	
public:
	__fastcall TElStringTokenizer(void);
	Classes::TStringList* __fastcall GetAll(void)/* overload */;
	void __fastcall GetAll(Classes::TStringList* ResultList)/* overload */;
	bool __fastcall GetNext(System::UnicodeString &Value);
	bool __fastcall GetRest(System::UnicodeString &Value);
	void __fastcall Reset(void);
	__property System::WideChar ClosingQuote = {read=FClosingQuote, write=SetClosingQuote, nodefault};
	__property bool ReturnEmptyTokens = {read=FReturnEmptyTokens, write=SetReturnEmptyTokens, nodefault};
	__property System::UnicodeString Delimiters = {read=FDelimiters, write=SetDelimiters};
	__property System::WideChar EscapeChar = {read=FEscapeChar, write=SetEscapeChar, nodefault};
	__property System::WideChar OpeningQuote = {read=FOpeningQuote, write=SetOpeningQuote, nodefault};
	__property System::UnicodeString SourceString = {read=FSourceString, write=SetSourceString};
	__property bool TrimQuotes = {read=FTrimQuotes, write=SetTrimQuotes, nodefault};
	__property bool TrimSpaces = {read=FTrimSpaces, write=SetTrimSpaces, nodefault};
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TElStringTokenizer(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------

}	/* namespace Sbstringlist */
using namespace Sbstringlist;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbstringlistHPP
