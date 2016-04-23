// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbrdn.pas' rev: 21.00

#ifndef SbrdnHPP
#define SbrdnHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbstringlist.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbasn1tree.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbrdn
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElRelativeDistinguishedName;
class PASCALIMPLEMENTATION TElRelativeDistinguishedName : public Classes::TPersistent
{
	typedef Classes::TPersistent inherited;
	
private:
	Sbutils::TElByteArrayList* FTypes;
	Sbutils::TElByteArrayList* FValues;
	Classes::TList* FTags;
	Classes::TList* FGroups;
	int __fastcall GetCount(void);
	void __fastcall SetCount(int Value);
	Sbtypes::ByteArray __fastcall GetValues(int Index);
	void __fastcall SetValues(int Index, const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetOIDs(int Index);
	void __fastcall SetOIDs(int Index, const Sbtypes::ByteArray Value);
	System::Byte __fastcall GetTags(int Index);
	void __fastcall SetTags(int Index, System::Byte Value);
	int __fastcall GetGroup(int Index);
	void __fastcall SetGroup(int Index, int Value);
	
protected:
	virtual void __fastcall AssignTo(Classes::TPersistent* Dest);
	
public:
	__fastcall TElRelativeDistinguishedName(void);
	__fastcall virtual ~TElRelativeDistinguishedName(void);
	virtual void __fastcall Assign(Classes::TPersistent* Source);
	bool __fastcall LoadFromTag(Sbasn1tree::TElASN1ConstrainedTag* Tag, bool IgnoreTopSequence = false);
	bool __fastcall LoadFromDNString(const System::UnicodeString S, bool LiberalMode);
	bool __fastcall SaveToTag(Sbasn1tree::TElASN1ConstrainedTag* Tag);
	System::UnicodeString __fastcall SaveToDNString(void);
	int __fastcall Add(const Sbtypes::ByteArray OID, const Sbtypes::ByteArray Value, System::Byte Tag = (System::Byte)(0x0));
	void __fastcall Remove(int Index);
	void __fastcall GetValuesByOID(const Sbtypes::ByteArray OID, Sbutils::TElByteArrayList* Values);
	Sbtypes::ByteArray __fastcall GetFirstValueByOID(const Sbtypes::ByteArray OID);
	int __fastcall IndexOf(const Sbtypes::ByteArray OID);
	void __fastcall Clear(void);
	bool __fastcall Contains(TElRelativeDistinguishedName* RDN, bool IgnoreTags);
	__property Sbtypes::ByteArray Values[int Index] = {read=GetValues, write=SetValues};
	__property Sbtypes::ByteArray OIDs[int Index] = {read=GetOIDs, write=SetOIDs};
	__property System::Byte Tags[int Index] = {read=GetTags, write=SetTags};
	__property int Groups[int Index] = {read=GetGroup, write=SetGroup};
	__property int Count = {read=GetCount, write=SetCount, nodefault};
};

typedef TElRelativeDistinguishedName ElRelativeDistinguishedName
class DELPHICLASS TElRDNConverter;
class PASCALIMPLEMENTATION TElRDNConverter : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	Classes::TStringList* FPrefixes;
	Sbutils::TElByteArrayList* FOIDs;
	System::UnicodeString FSeparator;
	bool FInsertSeparatorPrefix;
	void __fastcall AddPair(const System::UnicodeString Prefix, const Sbtypes::ByteArray OID);
	void __fastcall SetupKnownOIDs(void);
	
public:
	__fastcall TElRDNConverter(void);
	__fastcall virtual ~TElRDNConverter(void);
	System::UnicodeString __fastcall SaveToDNString(TElRelativeDistinguishedName* RDN);
	void __fastcall LoadFromDNString(TElRelativeDistinguishedName* RDN, const System::UnicodeString S, bool LiberalMode);
	__property System::UnicodeString Separator = {read=FSeparator, write=FSeparator};
	__property bool InsertSeparatorPrefix = {read=FInsertSeparatorPrefix, write=FInsertSeparatorPrefix, nodefault};
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE bool IgnoreTagsWhenComparingRDNs;
extern PACKAGE System::UnicodeString __fastcall GetRDNStringValue(const TElRelativeDistinguishedName* RDN, int Index);
extern PACKAGE bool __fastcall CompareRDN(TElRelativeDistinguishedName* Name1, TElRelativeDistinguishedName* Name2);
extern PACKAGE bool __fastcall CompareRDNAsStrings(TElRelativeDistinguishedName* Name1, TElRelativeDistinguishedName* Name2);
extern PACKAGE bool __fastcall NonstrictCompareRDN(TElRelativeDistinguishedName* InnerRDN, TElRelativeDistinguishedName* OuterRDN);
extern PACKAGE bool __fastcall NonstrictCompareRDNAsStrings(TElRelativeDistinguishedName* InnerRDN, TElRelativeDistinguishedName* OuterRDN);
extern PACKAGE System::UnicodeString __fastcall FormatRDN(TElRelativeDistinguishedName* RDN);

}	/* namespace Sbrdn */
using namespace Sbrdn;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbrdnHPP
