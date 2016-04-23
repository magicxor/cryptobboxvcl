// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbtypes.pas' rev: 21.00

#ifndef SbtypesHPP
#define SbtypesHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Types.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbtypes
{
//-- type declarations -------------------------------------------------------
typedef DynamicArray<System::Byte> ByteArray;

typedef DynamicArray<unsigned> LongWordArray;

typedef DynamicArray<System::Word> WordArray;

typedef DynamicArray<System::WideChar> CharArray;

typedef CharArray WideCharArray;

typedef DynamicArray<int> IntegerArray;

typedef DynamicArray<__int64> Int64Array;

typedef DynamicArray<DynamicArray<System::Byte> > ArrayOfByteArray;

typedef DynamicArray<bool> BooleanArray;

typedef DynamicArray<System::UnicodeString> StringArray;

typedef StringArray WideStringArray;

typedef unsigned UTF32;

typedef System::Word UTF16;

typedef System::Byte UTF8;

typedef unsigned *pUTF32;

typedef System::Word *pUTF16;

typedef System::Byte *pUTF8;

typedef Classes::TStream TElInputStream;

typedef Classes::TStream TElOutputStream;

typedef System::TDateTime TElDateTime;

typedef StaticArray<System::Byte, 1073741824> TByteArray;

typedef StaticArray<System::Word, 536870912> TWordArray;

typedef StaticArray<unsigned, 268435456> TLongWordArray;

typedef TLongWordArray *PLongWordArray;

typedef StaticArray<__int64, 134217728> TInt64Array;

typedef TInt64Array *PInt64Array;

typedef DynamicArray<char> TAnsiCharArray;

typedef ByteArray TBytes;

typedef System::UnicodeString TWideString;

typedef System::WideChar TWideChar;

#pragma option push -b-
enum TSBHostRole { hrNone, hrServer, hrClient, hrBoth };
#pragma option pop

typedef unsigned THandle;

typedef unsigned HModule;

typedef System::Word *PWord;

typedef int *PInt;

typedef unsigned *PLongWord;

typedef int *PLongint;

typedef __int64 *PInt64;

typedef unsigned *PCardinal;

typedef void * *PPointer;

#pragma option push -b-
enum TSBFileTransferMode { ftmOverwrite, ftmSkip, ftmAppendToEnd, ftmResume, ftmOverwriteIfDiffSize };
#pragma option pop

#pragma option push -b-
enum TSBFileCopyMode { fcmCopy, fcmCopyAndDeleteImmediate, fcmCopyAndDeleteOnCompletion };
#pragma option pop

#pragma option push -b-
enum TSBParamQuoteMode { pqmNone, pqmWithSpace, pqmAll };
#pragma option pop

#pragma option push -b-
enum TSBEOLMarker { emCRLF, emCR, emLF, emNone };
#pragma option pop

typedef int PtrInt;

typedef unsigned PtrUInt;

typedef unsigned __int64 QWord;

typedef unsigned TPtrHandle;

typedef __int64 TPtrHandle64;

#pragma option push -b-
enum TSBCaseConversion { sccNone, sccLower, sccUpper };
#pragma option pop

#pragma option push -b-
enum TSBOperationErrorHandling { oehTryAllItems, oehStopOnFailure, oehIgnoreErrors };
#pragma option pop

#pragma pack(push,1)
struct TMessageDigest128
{
	
public:
	unsigned A;
	unsigned B;
	unsigned C;
	unsigned D;
};
#pragma pack(pop)


#pragma pack(push,1)
struct TMessageDigest160
{
	
public:
	unsigned A;
	unsigned B;
	unsigned C;
	unsigned D;
	unsigned E;
};
#pragma pack(pop)


#pragma pack(push,1)
struct TMessageDigest224
{
	
public:
	unsigned A1;
	unsigned B1;
	unsigned C1;
	unsigned D1;
	unsigned A2;
	unsigned B2;
	unsigned C2;
};
#pragma pack(pop)


#pragma pack(push,1)
struct TMessageDigest256
{
	
public:
	unsigned A1;
	unsigned B1;
	unsigned C1;
	unsigned D1;
	unsigned A2;
	unsigned B2;
	unsigned C2;
	unsigned D2;
};
#pragma pack(pop)


#pragma pack(push,1)
struct TMessageDigest320
{
	
public:
	unsigned A1;
	unsigned B1;
	unsigned C1;
	unsigned D1;
	unsigned E1;
	unsigned A2;
	unsigned B2;
	unsigned C2;
	unsigned D2;
	unsigned E2;
};
#pragma pack(pop)


#pragma pack(push,1)
struct TMessageDigest384
{
	
public:
	__int64 A;
	__int64 B;
	__int64 C;
	__int64 D;
	__int64 E;
	__int64 F;
};
#pragma pack(pop)


#pragma pack(push,1)
struct TMessageDigest512
{
	
public:
	__int64 A1;
	__int64 B1;
	__int64 C1;
	__int64 D1;
	__int64 A2;
	__int64 B2;
	__int64 C2;
	__int64 D2;
};
#pragma pack(pop)


struct TSBLongwordPair
{
	
public:
	unsigned A;
	unsigned B;
};


typedef DynamicArray<TSBLongwordPair> TSBArrayOfPairs;

typedef TSBArrayOfPairs *PSBArrayOfPairs;

typedef int TSBInteger;

typedef __int64 TSBLong;

typedef System::UnicodeString TSBString;

typedef System::TObject TSBObject;

class DELPHICLASS TElStringHolder;
class PASCALIMPLEMENTATION TElStringHolder : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	System::UnicodeString FValue;
	
public:
	__fastcall TElStringHolder(const System::UnicodeString Data);
	__property System::UnicodeString Value = {read=FValue, write=FValue};
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TElStringHolder(void) { }
	
};


class DELPHICLASS TElByteArrayHolder;
class PASCALIMPLEMENTATION TElByteArrayHolder : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	ByteArray FValue;
	
public:
	__fastcall TElByteArrayHolder(const ByteArray Data);
	__property ByteArray Value = {read=FValue, write=FValue};
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TElByteArrayHolder(void) { }
	
};


#pragma option push -b-
enum ConversionResult { conversionOK, sourceExhausted, targetExhausted, sourceIllegal };
#pragma option pop

#pragma option push -b-
enum ConversionFlags { strictConversion, lenientConversion };
#pragma option pop

//-- var, const, procedure ---------------------------------------------------
static const int MaxArrSize = 0x7fffffff;

}	/* namespace Sbtypes */
using namespace Sbtypes;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbtypesHPP
