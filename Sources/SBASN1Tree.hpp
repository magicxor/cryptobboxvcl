// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbasn1tree.pas' rev: 21.00

#ifndef Sbasn1treeHPP
#define Sbasn1treeHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sbstreams.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbasn1.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbasn1tree
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElASN1CustomTag;
class PASCALIMPLEMENTATION TElASN1CustomTag : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	System::Byte FTagId;
	bool FWriteHeader;
	virtual bool __fastcall GetConstrained(void);
	System::Byte __fastcall GetTagNum(void);
	bool FUndefSize;
	__int64 FTagOffset;
	__int64 FTagSize;
	int FTagHeaderSize;
	__int64 FTagContentSize;
	int FDepth;
	virtual __int64 __fastcall GetEncodedLen(void);
	Sbtypes::ByteArray __fastcall ComposeHeader(__int64 Len);
	virtual bool __fastcall UnknownSize(void);
	
public:
	__fastcall TElASN1CustomTag(void);
	virtual bool __fastcall LoadFromBuffer(void * Buffer, int Size);
	virtual bool __fastcall SaveToBuffer(void * Buffer, int &Size);
	bool __fastcall CheckType(System::Byte TagId, bool Constrained);
	virtual bool __fastcall LoadFromStream(Classes::TStream* Stream, __int64 Count = 0x000000000);
	virtual void __fastcall SaveToStream(Classes::TStream* Stream);
	__property System::Byte TagId = {read=FTagId, write=FTagId, nodefault};
	__property bool UndefSize = {read=FUndefSize, write=FUndefSize, nodefault};
	__property bool WriteHeader = {read=FWriteHeader, write=FWriteHeader, nodefault};
	__property bool IsConstrained = {read=GetConstrained, nodefault};
	__property System::Byte TagNum = {read=GetTagNum, nodefault};
	__property __int64 TagOffset = {read=FTagOffset};
	__property __int64 TagSize = {read=FTagSize};
	__property int TagHeaderSize = {read=FTagHeaderSize, nodefault};
	__property __int64 TagContentSize = {read=FTagContentSize};
	__property int Depth = {read=FDepth, nodefault};
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TElASN1CustomTag(void) { }
	
};


#pragma option push -b-
enum TSBASN1DataSourceType { dstBuffer, dstStream, dstVirtual };
#pragma option pop

typedef void __fastcall (__closure *TSBASN1VirtualDataNeededEvent)(System::TObject* Sender, __int64 StartIndex, void * Buffer, int MaxSize, int &Read);

class DELPHICLASS TElASN1DataSource;
class PASCALIMPLEMENTATION TElASN1DataSource : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	Classes::TStream* FContentStream;
	__int64 FContentOffset;
	__int64 FContentSize;
	Sbtypes::ByteArray FContent;
	bool FUnknownSize;
	TSBASN1DataSourceType FSourceType;
	TSBASN1VirtualDataNeededEvent FOnVirtualDataNeeded;
	bool FSkipVirtualData;
	__int64 __fastcall GetSize(void);
	
public:
	__fastcall virtual ~TElASN1DataSource(void);
	void __fastcall Init(const Sbtypes::ByteArray Value)/* overload */;
	void __fastcall Init(Classes::TStream* Stream, __int64 Offset, __int64 Size)/* overload */;
	void __fastcall Init(Classes::TStream* Stream, bool UnknownSize)/* overload */;
	void __fastcall Init(void * Buffer, int Size)/* overload */;
	void __fastcall InitVirtual(__int64 Size);
	int __fastcall Read(void * Buffer, int Size, __int64 Offset);
	void __fastcall Clone(TElASN1DataSource* Dest);
	void __fastcall CloneVirtual(TElASN1DataSource* Dest);
	Sbtypes::ByteArray __fastcall ToBuffer(void);
	__property __int64 Size = {read=GetSize};
	__property bool UnknownSize = {read=FUnknownSize, nodefault};
	__property bool SkipVirtualData = {read=FSkipVirtualData, write=FSkipVirtualData, nodefault};
	__property TSBASN1DataSourceType SourceType = {read=FSourceType, nodefault};
	__property TSBASN1VirtualDataNeededEvent OnVirtualDataNeeded = {read=FOnVirtualDataNeeded, write=FOnVirtualDataNeeded};
public:
	/* TObject.Create */ inline __fastcall TElASN1DataSource(void) : System::TObject() { }
	
};


class DELPHICLASS TElASN1SimpleTag;
class PASCALIMPLEMENTATION TElASN1SimpleTag : public TElASN1CustomTag
{
	typedef TElASN1CustomTag inherited;
	
protected:
	bool __fastcall SaveToBufferUndefSize(void * Buffer, int &Size);
	virtual bool __fastcall GetConstrained(void);
	void __fastcall SetContent(const Sbtypes::ByteArray Value);
	Sbtypes::ByteArray __fastcall GetContent(void);
	virtual bool __fastcall UnknownSize(void);
	TElASN1DataSource* FDataSource;
	int FFragmentSize;
	Classes::TNotifyEvent FOnContentWriteBegin;
	Classes::TNotifyEvent FOnContentWriteEnd;
	virtual __int64 __fastcall GetEncodedLen(void);
	
public:
	__fastcall TElASN1SimpleTag(void);
	__fastcall virtual ~TElASN1SimpleTag(void);
	__classmethod TElASN1SimpleTag* __fastcall CreateInstance();
	virtual bool __fastcall LoadFromBuffer(void * Buffer, int Size);
	virtual bool __fastcall SaveToBuffer(void * Buffer, int &Size);
	virtual bool __fastcall LoadFromStream(Classes::TStream* Stream, __int64 Count = 0x000000000);
	virtual void __fastcall SaveToStream(Classes::TStream* Stream);
	__property Sbtypes::ByteArray Content = {read=GetContent, write=SetContent};
	__property TElASN1DataSource* DataSource = {read=FDataSource};
	__property int FragmentSize = {read=FFragmentSize, write=FFragmentSize, nodefault};
	__property Classes::TNotifyEvent OnContentWriteBegin = {read=FOnContentWriteBegin, write=FOnContentWriteBegin};
	__property Classes::TNotifyEvent OnContentWriteEnd = {read=FOnContentWriteEnd, write=FOnContentWriteEnd};
};


#pragma option push -b-
enum TSBASN1StreamAccess { saStoreStream };
#pragma option pop

class DELPHICLASS TElASN1ConstrainedTag;
class PASCALIMPLEMENTATION TElASN1ConstrainedTag : public TElASN1CustomTag
{
	typedef TElASN1CustomTag inherited;
	
protected:
	Classes::TList* FList;
	Classes::TList* FStack;
	System::Byte *FBuffer;
	int FBufferSize;
	__int64 FCurrBufferIndex;
	bool FSingleLoad;
	bool FDataProcessed;
	__int64 FSizeLeft;
	int FLastHeaderLen;
	Classes::TStream* FInputStream;
	__int64 FMaxStreamPos;
	int FMaxSimpleTagLength;
	TSBASN1StreamAccess FStreamAccess;
	void __fastcall ClearList(void);
	int __fastcall GetCount(void);
	bool __fastcall SaveToBufferUndefSize(void * Buffer, int &Size);
	virtual bool __fastcall GetConstrained(void);
	System::Byte __fastcall GetByteFromStream(Classes::TStream* Stream, __int64 Offset);
	virtual bool __fastcall UnknownSize(void);
	void __fastcall HandleASN1Read(System::TObject* Sender, void * Buffer, int &Size);
	void __fastcall HandleASN1ReadStream(System::TObject* Sender, void * Buffer, int &Size);
	void __fastcall HandleASN1Tag(System::TObject* Sender, Sbasn1::asn1TagType TagType, bool TagConstrained, void * Tag, int TagSize, __int64 Size, void * Data, int BitRest, bool &Valid);
	void __fastcall HandleASN1TagHeader(System::TObject* Sender, System::Byte TagID, __int64 TagLen, int HeaderLen, bool UndefLen);
	void __fastcall HandleASN1Skip(System::TObject* Sender, __int64 &Count);
	void __fastcall HandleASN1SkipStream(System::TObject* Sender, __int64 &Count);
	virtual __int64 __fastcall GetEncodedLen(void);
	
public:
	__fastcall TElASN1ConstrainedTag(void);
	__fastcall virtual ~TElASN1ConstrainedTag(void);
	__classmethod TElASN1ConstrainedTag* __fastcall CreateInstance();
	virtual bool __fastcall LoadFromBuffer(void * Buffer, int Size);
	int __fastcall LoadFromBufferSingle(void * Buffer, int Size);
	virtual bool __fastcall SaveToBuffer(void * Buffer, int &Size);
	bool __fastcall SaveContentToBuffer(void * Buffer, int &Size);
	virtual bool __fastcall LoadFromStream(Classes::TStream* Stream, __int64 Count = 0x000000000);
	bool __fastcall LoadFromStreamSingle(Classes::TStream* Stream, __int64 Count = 0x000000000);
	virtual void __fastcall SaveToStream(Classes::TStream* Stream);
	int __fastcall AddField(bool Constrained);
	bool __fastcall RemoveField(int Index);
	TElASN1CustomTag* __fastcall GetField(int Index);
	void __fastcall Clear(void);
	__property int Count = {read=GetCount, nodefault};
	__property int MaxSimpleTagLength = {read=FMaxSimpleTagLength, write=FMaxSimpleTagLength, nodefault};
	__property TSBASN1StreamAccess StreamAccess = {read=FStreamAccess, write=FStreamAccess, nodefault};
};


//-- var, const, procedure ---------------------------------------------------
static const ShortInt SB_ASN1_BOOLEAN = 0x1;
static const ShortInt SB_ASN1_INTEGER = 0x2;
static const ShortInt SB_ASN1_BITSTRING = 0x3;
static const ShortInt SB_ASN1_OCTETSTRING = 0x4;
static const ShortInt SB_ASN1_NULL = 0x5;
static const ShortInt SB_ASN1_OBJECT = 0x6;
static const ShortInt SB_ASN1_REAL = 0x9;
static const ShortInt SB_ASN1_ENUMERATED = 0xa;
static const ShortInt SB_ASN1_UTF8STRING = 0xc;
static const ShortInt SB_ASN1_NUMERICSTR = 0x12;
static const ShortInt SB_ASN1_PRINTABLESTRING = 0x13;
static const ShortInt SB_ASN1_T61STRING = 0x14;
static const ShortInt SB_ASN1_TELETEXSTRING = 0x14;
static const ShortInt SB_ASN1_VIDEOTEXSTRING = 0x15;
static const ShortInt SB_ASN1_IA5STRING = 0x16;
static const ShortInt SB_ASN1_UTCTIME = 0x17;
static const ShortInt SB_ASN1_GENERALIZEDTIME = 0x18;
static const ShortInt SB_ASN1_GRAPHICSTRING = 0x19;
static const ShortInt SB_ASN1_VISIBLESTRING = 0x1a;
static const ShortInt SB_ASN1_GENERALSTRING = 0x1b;
static const ShortInt SB_ASN1_UNIVERSALSTRING = 0x1c;
static const ShortInt SB_ASN1_BMPSTRING = 0x1e;
static const ShortInt SB_ASN1_SEQUENCE = 0x30;
static const ShortInt SB_ASN1_SET = 0x31;
static const Byte SB_ASN1_A0_PRIMITIVE = 0x80;
static const Byte SB_ASN1_A0 = 0xa0;
static const Byte SB_ASN1_A1_PRIMITIVE = 0x81;
static const Byte SB_ASN1_A1 = 0xa1;
static const Byte SB_ASN1_A2_PRIMITIVE = 0x82;
static const Byte SB_ASN1_A2 = 0xa2;
static const Byte SB_ASN1_A3_PRIMITIVE = 0x83;
static const Byte SB_ASN1_A3 = 0xa3;
static const Byte SB_ASN1_A4_PRIMITIVE = 0x84;
static const Byte SB_ASN1_A4 = 0xa4;
static const Byte SB_ASN1_A5_PRIMITIVE = 0x85;
static const Byte SB_ASN1_A5 = 0xa5;
static const Byte SB_ASN1_A6_PRIMITIVE = 0x86;
static const Byte SB_ASN1_A6 = 0xa6;
static const Byte SB_ASN1_A7_PRIMITIVE = 0x87;
static const Byte SB_ASN1_A7 = 0xa7;
static const Byte SB_ASN1_A8_PRIMITIVE = 0x88;
static const Byte SB_ASN1_A8 = 0xa8;
static const Byte SB_ASN1_A9_PRIMITIVE = 0x89;
static const Byte SB_ASN1_A9 = 0xa9;
static const ShortInt SB_ASN1_CONSTRAINED_FLAG = 0x20;
extern PACKAGE int G_MaxASN1TreeDepth;
extern PACKAGE int G_MaxASN1BufferLength;
extern PACKAGE void __fastcall asymWriteInteger(TElASN1SimpleTag* Tag, void * Buffer, int Size);
extern PACKAGE int __fastcall ASN1ReadInteger(TElASN1SimpleTag* Tag);
extern PACKAGE __int64 __fastcall ASN1ReadInteger64(TElASN1SimpleTag* Tag);
extern PACKAGE Sbtypes::ByteArray __fastcall ASN1ReadSimpleValue(const Sbtypes::ByteArray Data, int &TagID);
extern PACKAGE bool __fastcall ASN1ReadBoolean(TElASN1SimpleTag* Tag);
extern PACKAGE System::UnicodeString __fastcall ASN1ReadString(const Sbtypes::ByteArray Data, int TagId);
extern PACKAGE void __fastcall ASN1WriteBoolean(TElASN1SimpleTag* Tag, bool Value);
extern PACKAGE void __fastcall ASN1WriteInteger(TElASN1SimpleTag* Tag, int Value);
extern PACKAGE void __fastcall ASN1WriteInteger64(TElASN1SimpleTag* Tag, __int64 Value);
extern PACKAGE Sbtypes::ByteArray __fastcall ASN1WriteTagAndLength(int Tag, __int64 Len);
extern PACKAGE Sbtypes::ByteArray __fastcall FormatAttributeValue(int TagID, const Sbtypes::ByteArray Value);
extern PACKAGE Sbtypes::ByteArray __fastcall UnformatAttributeValue(const Sbtypes::ByteArray Value, /* out */ int &TagID);

}	/* namespace Sbasn1tree */
using namespace Sbasn1tree;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// Sbasn1treeHPP
