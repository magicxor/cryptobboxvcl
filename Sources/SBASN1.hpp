// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbasn1.pas' rev: 21.00

#ifndef Sbasn1HPP
#define Sbasn1HPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sbstringlist.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbasn1
{
//-- type declarations -------------------------------------------------------
typedef System::Byte *PByte;

class DELPHICLASS EElASN1Error;
class PASCALIMPLEMENTATION EElASN1Error : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElASN1Error(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElASN1Error(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElASN1Error(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElASN1Error(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElASN1Error(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElASN1Error(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElASN1Error(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElASN1Error(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElASN1Error(void) { }
	
};


class DELPHICLASS EElASN1ReadError;
class PASCALIMPLEMENTATION EElASN1ReadError : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElASN1ReadError(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElASN1ReadError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElASN1ReadError(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElASN1ReadError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElASN1ReadError(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElASN1ReadError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElASN1ReadError(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElASN1ReadError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElASN1ReadError(void) { }
	
};


#pragma option push -b-
enum asn1TagType { asn1tUniversal, asn1tApplication, asn1tSpecific, asn1tPrivate, asn1tEOC };
#pragma option pop

typedef int __stdcall (*asn1tReadFunc)(void * Stream, void * Data, int Size);

typedef void __stdcall (*asn1tWriteFunc)(void * Stream, void * Data, int Size);

typedef bool __stdcall (__closure *asn1tCallBackFunc)(void * Stream, asn1TagType TagType, bool TagConstrained, void * Tag, int TagSize, int Size, void * Data, int BitRest);

typedef void __fastcall (__closure *TSBASN1ReadEvent)(System::TObject* Sender, void * Buffer, int &Size);

typedef void __fastcall (__closure *TSBASN1TagEvent)(System::TObject* Sender, asn1TagType TagType, bool TagConstrained, void * Tag, int TagSize, __int64 Size, void * Data, int BitRest, bool &Valid);

typedef void __fastcall (__closure *TSBASN1TagHeaderEvent)(System::TObject* Sender, System::Byte TagID, __int64 TagLen, int HeaderLen, bool UndefLen);

typedef void __fastcall (__closure *TSBASN1SkipEvent)(System::TObject* Sender, __int64 &Count);

class DELPHICLASS TElASN1Parser;
class PASCALIMPLEMENTATION TElASN1Parser : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	TSBASN1ReadEvent FOnRead;
	TSBASN1TagEvent FOnTag;
	TSBASN1TagHeaderEvent FOnTagHeader;
	TSBASN1SkipEvent FOnSkip;
	__int64 FReadSize;
	bool FRaiseOnEOC;
	__int64 FMaxDataLength;
	int FMaxSimpleTagLength;
	int FCurrDepth;
	
protected:
	void __fastcall asn1Read(void * Data, int Size);
	void __fastcall ReadRevertBytes(void * Data, int Size);
	void __fastcall ReadRepackedBits(void * Tag, int &TagSize, int MaxTagSize, bool Revert = true);
	void __fastcall DoRead(void * Buffer, int &Size);
	void __fastcall DoTag(asn1TagType TagType, bool TagConstrained, void * Tag, int TagSize, __int64 Size, void * Data, int BitRest, bool &Valid);
	void __fastcall asn1Skip(__int64 &Count);
	__int64 __fastcall DecodeField(bool InvokeCallBack = true)/* overload */;
	
public:
	__fastcall TElASN1Parser(void);
	void __fastcall Parse(void);
	__property bool RaiseOnEOC = {read=FRaiseOnEOC, write=FRaiseOnEOC, default=0};
	__property __int64 MaxDataLength = {read=FMaxDataLength, write=FMaxDataLength};
	__property int MaxSimpleTagLength = {read=FMaxSimpleTagLength, write=FMaxSimpleTagLength, nodefault};
	__property TSBASN1ReadEvent OnRead = {read=FOnRead, write=FOnRead};
	__property TSBASN1TagEvent OnTag = {read=FOnTag, write=FOnTag};
	__property TSBASN1TagHeaderEvent OnTagHeader = {read=FOnTagHeader, write=FOnTagHeader};
	__property TSBASN1SkipEvent OnSkip = {read=FOnSkip, write=FOnSkip};
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TElASN1Parser(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
static const ShortInt asn1Boolean = 0x1;
static const ShortInt asn1Integer = 0x2;
static const ShortInt asn1BitStr = 0x3;
static const ShortInt asn1OctetStr = 0x4;
static const ShortInt asn1NULL = 0x5;
static const ShortInt asn1Object = 0x6;
static const ShortInt asn1Real = 0x9;
static const ShortInt asn1Enumerated = 0xa;
static const ShortInt asn1UTF8String = 0xc;
static const ShortInt asn1Sequence = 0x10;
static const ShortInt asn1Set = 0x11;
static const ShortInt asn1NumericStr = 0x12;
static const ShortInt asn1PrintableStr = 0x13;
static const ShortInt asn1T61String = 0x14;
static const ShortInt asn1TeletexStr = 0x14;
static const ShortInt asn1IA5String = 0x16;
static const ShortInt asn1UTCTime = 0x17;
static const ShortInt asn1GeneralizedTime = 0x18;
static const ShortInt asn1VisibleStr = 0x1a;
static const ShortInt asn1GeneralStr = 0x1b;
static const ShortInt asn1A0 = 0x0;
static const ShortInt asn1A1 = 0x1;
static const ShortInt asn1A2 = 0x2;
static const ShortInt asn1A3 = 0x3;
static const ShortInt asn1A4 = 0x4;
static const ShortInt asn1A5 = 0x5;
static const ShortInt asn1A6 = 0x6;
static const ShortInt asn1A7 = 0x7;
static const ShortInt asn1A8 = 0x8;
extern PACKAGE int SB_MAX_ASN1_DEPTH;
extern PACKAGE bool asn1RevertTagBytes;
extern PACKAGE bool asn1RevertReadInts;
extern PACKAGE asn1tWriteFunc asn1WriteFunc;
extern PACKAGE void __fastcall asn1AddTypeEqu(asn1TagType TagType1, void * Tag1, int TagSize1, asn1TagType TagType2, void * Tag2, int TagSize2)/* overload */;
extern PACKAGE void __fastcall asn1AddTypeEqu(asn1TagType TagType1, void * Tag1, int TagSize1, System::Byte Tag2)/* overload */;
extern PACKAGE bool __fastcall asn1AddTag(void * Stream, asn1TagType TagType, bool TagConstrained, void * Tag, int TagSize, int Size, void * Data = (void *)(0x0), bool Revert = false, int BitRest = 0x0)/* overload */;
extern PACKAGE bool __fastcall asn1AddTag(void * Stream, asn1TagType TagType, bool TagConstrained, System::Byte Tag, int Size, void * Data = (void *)(0x0), bool Revert = false, int BitRest = 0x0)/* overload */;
extern PACKAGE bool __fastcall asn1AddBool(void * Stream, bool Value);
extern PACKAGE bool __fastcall asn1AddInt(void * Stream, int Value, bool Revert = true);
extern PACKAGE bool __fastcall asn1AddBuf(void * Stream, void * Value, int Size);
extern PACKAGE bool __fastcall asn1AddConstrained(void * Stream, asn1TagType TagType, void * Tag, int TagSize, int Size = 0x0)/* overload */;
extern PACKAGE bool __fastcall asn1AddConstrained(void * Stream, asn1TagType TagType, System::Byte Tag, int Size = 0x0)/* overload */;
extern PACKAGE void __fastcall asn1CloseConstrained(void * Stream);
extern PACKAGE bool __fastcall asn1AddSeq(void * Stream);
extern PACKAGE bool __fastcall asn1AddSet(void * Stream);
extern PACKAGE void __fastcall asn1ParseStream(void * Stream, asn1tCallBackFunc CallBack);
extern PACKAGE Sbtypes::ByteArray __fastcall WritePrimitiveListSeq(System::Byte Tag, Sbutils::TElByteArrayList* Strings);
extern PACKAGE Sbtypes::ByteArray __fastcall WritePrimitiveArraySeq(System::Byte Tag, Sbtypes::ByteArray *Strings, const int Strings_Size);
extern PACKAGE Sbtypes::ByteArray __fastcall WriteA0(const Sbutils::TElByteArrayList* Strings)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall WriteA0(Sbtypes::ByteArray const *Strings, const int Strings_Size)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall WriteListSequence(const Sbutils::TElByteArrayList* Strings);
extern PACKAGE Sbtypes::ByteArray __fastcall WriteArraySequence(Sbtypes::ByteArray const *Values, const int Values_Size);
extern PACKAGE Sbtypes::ByteArray __fastcall WriteSet(const Sbutils::TElByteArrayList* Strings)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall WriteSet(Sbtypes::ByteArray const *Strings, const int Strings_Size)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall WriteStringPrimitive(System::Byte Tag, const System::UnicodeString Data)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall WriteStringPrimitive(System::Byte Tag, const Sbtypes::ByteArray Data)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall WritePrimitive(System::Byte Tag, const Sbtypes::ByteArray Data)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall WriteExplicit(const Sbtypes::ByteArray Data);
extern PACKAGE Sbtypes::ByteArray __fastcall WriteInteger(const Sbtypes::ByteArray Data, System::Byte TagID = (System::Byte)(0x2))/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall WriteInteger(int Number, System::Byte TagID = (System::Byte)(0x2))/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall WriteOID(const Sbtypes::ByteArray Data);
extern PACKAGE Sbtypes::ByteArray __fastcall WritePrintableString(const System::UnicodeString Data)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall WriteUTF8String(const System::UnicodeString Data)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall WritePrintableString(const Sbtypes::ByteArray Data)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall WriteUTF8String(const Sbtypes::ByteArray Data)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall WriteIA5String(const System::UnicodeString Data)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall WriteIA5String(const Sbtypes::ByteArray Data)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall WriteUTCTime(const System::UnicodeString Data);
extern PACKAGE Sbtypes::ByteArray __fastcall WriteGeneralizedTime(System::TDateTime T);
extern PACKAGE Sbtypes::ByteArray __fastcall WriteSize(unsigned Size);
extern PACKAGE Sbtypes::ByteArray __fastcall WriteBitString(const Sbtypes::ByteArray Data);
extern PACKAGE Sbtypes::ByteArray __fastcall WriteNULL(void);
extern PACKAGE Sbtypes::ByteArray __fastcall WriteOctetString(const Sbtypes::ByteArray Data)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall WriteOctetString(const System::UnicodeString Data)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall WriteBoolean(bool Data);
extern PACKAGE Sbtypes::ByteArray __fastcall WriteVisibleString(const System::UnicodeString Data);

}	/* namespace Sbasn1 */
using namespace Sbasn1;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// Sbasn1HPP
