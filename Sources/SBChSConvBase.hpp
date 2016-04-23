// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbchsconvbase.pas' rev: 21.00

#ifndef SbchsconvbaseHPP
#define SbchsconvbaseHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Syncobjs.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbchsconvbase
{
//-- type declarations -------------------------------------------------------
typedef int UCS;

typedef Classes::TStream TElNativeStream;

__interface IPlConvBuffer;
typedef System::DelphiInterface<IPlConvBuffer> _di_IPlConvBuffer;
__interface  INTERFACE_UUID("{F1D596A5-FF12-4670-A350-E9F15B107ED0}") IPlConvBuffer  : public System::IInterface 
{
	
public:
	virtual void __fastcall Clear(bool LeaveUnprocessedData = false) = 0 ;
	virtual void __fastcall Restart(void) = 0 ;
	virtual bool __fastcall CheckString(Classes::TStream* Stream, const System::AnsiString Str, int Shift = 0x0) = 0 ;
	virtual System::Byte __fastcall GetByte(Classes::TStream* Stream, bool &Exists) = 0 ;
	virtual System::Word __fastcall GetWide(Classes::TStream* Stream, bool &Exists) = 0 ;
	virtual unsigned __fastcall GetLong(Classes::TStream* Stream, bool &Exists) = 0 ;
	virtual void __fastcall ReturnByte(void) = 0 /* overload */;
	virtual void __fastcall ReturnByte(System::Byte Value) = 0 /* overload */;
	virtual void __fastcall ReturnBytes(int Count) = 0 ;
	virtual void __fastcall Flush(Classes::TStream* Stream) = 0 ;
	virtual void __fastcall Put(const void *Data, int Count) = 0 ;
	virtual void __fastcall PutByte(System::Byte Value) = 0 ;
	virtual void __fastcall PutWordLE(System::Word Value) = 0 ;
	virtual System::Byte __fastcall RevokeByte(void) = 0 ;
};

__interface IPlCharset;
typedef System::DelphiInterface<IPlCharset> _di_IPlCharset;
__interface  INTERFACE_UUID("{A098F214-B230-480F-8206-6D7526B7428F}") IPlCharset  : public System::IInterface 
{
	
public:
	virtual void __fastcall SetBuffer(const _di_IPlConvBuffer Value) = 0 ;
	virtual System::UnicodeString __fastcall GetAliases(void) = 0 ;
	virtual UCS __fastcall GetDefaultChar(void) = 0 ;
	virtual void __fastcall Reset(void) = 0 ;
	virtual unsigned __fastcall WriteDefaultChar(void) = 0 ;
	virtual unsigned __fastcall WriteFileHeader(void) = 0 ;
	virtual unsigned __fastcall WriteLineBegin(void) = 0 ;
	virtual unsigned __fastcall WriteLineEnd(void) = 0 ;
	virtual unsigned __fastcall WriteString(const System::AnsiString Str) = 0 ;
	virtual bool __fastcall CanConvert(UCS Char) = 0 ;
	virtual int __fastcall ConvertFromUCS(UCS Char) = 0 ;
	virtual int __fastcall ConvertToUCS(Classes::TStream* Stream, /* out */ UCS &Char) = 0 ;
	virtual int __fastcall ConvertBufferToUCS(const void *Buf, int Count, bool IsLastChunk, /* out */ UCS &Char) = 0 ;
	virtual int __fastcall ConvertBufferToUTF16(const void *SrcBuf, int SrcCount, bool IsLastChunk, void *DstBuf, int &DstCount) = 0 ;
	virtual System::UnicodeString __fastcall GetCategory(void) = 0 ;
	virtual System::UnicodeString __fastcall GetDescription(void) = 0 ;
	virtual System::UnicodeString __fastcall GetName(void) = 0 ;
};

class DELPHICLASS TPlCharset;
class PASCALIMPLEMENTATION TPlCharset : public System::TInterfacedObject
{
	typedef System::TInterfacedObject inherited;
	
private:
	_di_IPlConvBuffer fBuffer;
	int fShift;
	
protected:
	virtual void __fastcall SetBuffer(const _di_IPlConvBuffer Value);
	virtual System::UnicodeString __fastcall GetAliases(void);
	virtual UCS __fastcall GetDefaultChar(void);
	virtual void __fastcall Reset(void);
	virtual void __fastcall FinalizeCharset(void);
	virtual unsigned __fastcall WriteDefaultChar(void);
	virtual unsigned __fastcall WriteFileHeader(void);
	virtual unsigned __fastcall WriteLineBegin(void);
	virtual unsigned __fastcall WriteLineEnd(void);
	unsigned __fastcall WriteString(const System::AnsiString Str);
	__property _di_IPlConvBuffer Buffer = {read=fBuffer, write=SetBuffer};
	
public:
	__fastcall virtual TPlCharset(void);
	__fastcall virtual TPlCharset(int Shift);
	__fastcall virtual TPlCharset(void);
	__fastcall virtual TPlCharset(void);
	virtual bool __fastcall CanConvert(UCS Char);
	virtual int __fastcall ConvertFromUCS(UCS Char);
	virtual int __fastcall ConvertToUCS(Classes::TStream* Stream, /* out */ UCS &Char);
	virtual int __fastcall ConvertBufferToUCS(const void *Buf, int Count, bool IsLastChunk, /* out */ UCS &Char);
	int __fastcall ConvertBufferToUTF16(const void *SrcBuf, int SrcCount, bool IsLastChunk, void *DstBuf, int &DstCount);
	virtual System::UnicodeString __fastcall GetCategory(void);
	virtual System::UnicodeString __fastcall GetDescription(void);
	virtual System::UnicodeString __fastcall GetName(void);
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TPlCharset(void) { }
	
private:
	void *__IPlCharset;	/* IPlCharset */
	
public:
	#if defined(MANAGED_INTERFACE_OPERATORS)
	operator _di_IPlCharset()
	{
		_di_IPlCharset intf;
		GetInterface(intf);
		return intf;
	}
	#else
	operator IPlCharset*(void) { return (IPlCharset*)&__IPlCharset; }
	#endif
	
};


typedef TMetaClass* TPlCharsetClass;

typedef System::Byte *PByte;

typedef System::Word *PWord;

typedef unsigned *PLong;

typedef Set<System::Byte, 0, 255>  TPlPrefixes;

typedef TPlPrefixes *PPlPrefixes;

typedef StaticArray<System::Byte, 256> TPlHiBytes;

typedef TPlHiBytes *PPlHiBytes;

typedef StaticArray<System::Word, 256> TPlChars;

typedef TPlChars *PPlChars;

#pragma pack(push,1)
struct TPlConversionPage
{
	
public:
	TPlChars *Chars;
	TPlHiBytes *HiBytes;
	TPlPrefixes *Prefixes;
	System::Byte CharsLoIndex;
	System::Byte CharsHiIndex;
	System::Byte PriorPageIndex;
	System::Byte PriorPageChar;
};
#pragma pack(pop)


typedef TPlConversionPage *PPlConversionPage;

typedef StaticArray<TPlConversionPage, 256> TPlConversionPages;

typedef TPlConversionPages *PPlConversionPages;

typedef StaticArray<System::Byte, 1114112> TPlUCSToSingleByteTable;

typedef TPlUCSToSingleByteTable *PPlUCSToSingleByteTable;

#pragma pack(push,1)
struct TPlUCSToMultiByteItem
{
	
public:
	System::Byte Page;
	System::Byte Char;
};
#pragma pack(pop)


typedef StaticArray<TPlUCSToMultiByteItem, 1114112> TPlUCSToMultiByteTable;

typedef TPlUCSToMultiByteTable *PPlUCSToMultiByteTable;

#pragma pack(push,1)
struct TPlConversionTable
{
	
public:
	int MaxDirectMapped;
	int PagesCount;
	TPlConversionPages *Pages;
	unsigned BackItemsCount;
	union
	{
		struct 
		{
			TPlUCSToMultiByteTable *ToMultiByte;
			
		};
		struct 
		{
			TPlUCSToSingleByteTable *ToSingleByte;
			
		};
		
	};
};
#pragma pack(pop)


typedef TPlConversionTable *PPlConversionTable;

class DELPHICLASS TPlTableCharset;
class PASCALIMPLEMENTATION TPlTableCharset : public TPlCharset
{
	typedef TPlCharset inherited;
	
private:
	TPlConversionTable *fTable;
	
protected:
	__classmethod bool __fastcall IsEqualConversionTables(PPlConversionTable Tab1, PPlConversionTable Tab2);
	virtual Sbtypes::ByteArray __fastcall GetAdditionalFromUCS(void);
	virtual PPlConversionTable __fastcall GetConversionTable(void);
	void __fastcall GenerateBackTable(void);
	virtual void __fastcall FinalizeCharset(void);
	
public:
	__fastcall virtual TPlTableCharset(void);
	__fastcall virtual TPlTableCharset(void);
	virtual bool __fastcall CanConvert(UCS Char);
	virtual int __fastcall ConvertFromUCS(UCS Char);
	virtual int __fastcall ConvertToUCS(Classes::TStream* Stream, /* out */ UCS &Char);
	virtual int __fastcall ConvertBufferToUCS(const void *Buf, int Count, bool IsLastChunk, /* out */ UCS &Char);
public:
	/* TPlCharset.CreateShift */ inline __fastcall virtual TPlTableCharset(int Shift) : TPlCharset(Shift) { }
	/* TPlCharset.CreateNoInit */ inline __fastcall virtual TPlTableCharset(void) : TPlCharset() { }
	
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TPlTableCharset(void) { }
	
};


class DELPHICLASS TPlMixedCharset;
class PASCALIMPLEMENTATION TPlMixedCharset : public TPlCharset
{
	typedef TPlCharset inherited;
	
protected:
	int FCount;
	StaticArray<TPlCharset*, 16> FCharsets;
	virtual TPlCharsetClass __fastcall GetCharsetClass(int Index);
	virtual int __fastcall GetCharsetsCount(void);
	virtual int __fastcall GetCharsetShift(int Index);
	virtual void __fastcall SetBuffer(const _di_IPlConvBuffer Value);
	
public:
	__fastcall virtual TPlMixedCharset(void);
	__fastcall virtual TPlMixedCharset(int Shift);
	__fastcall virtual ~TPlMixedCharset(void);
	virtual bool __fastcall CanConvert(UCS Char);
	virtual int __fastcall ConvertFromUCS(UCS Char);
	virtual int __fastcall ConvertToUCS(Classes::TStream* Stream, /* out */ UCS &Char);
	virtual int __fastcall ConvertBufferToUCS(const void *Buf, int Count, bool IsLastChunk, /* out */ UCS &Char);
public:
	/* TPlCharset.CreateNoInit */ inline __fastcall virtual TPlMixedCharset(void) : TPlCharset() { }
	/* TPlCharset.CreateForFinalize */ inline __fastcall virtual TPlMixedCharset(void) : TPlCharset() { }
	
};


class DELPHICLASS TPlConvertingCharset;
class PASCALIMPLEMENTATION TPlConvertingCharset : public TPlCharset
{
	typedef TPlCharset inherited;
	
protected:
	TPlCharset* fBase;
	virtual void __fastcall ConvertFrom(int &C1, int &C2);
	virtual void __fastcall ConvertTo(int &C1, int &C2);
	virtual TPlCharsetClass __fastcall GetBaseCharsetClass(void);
	virtual void __fastcall SetBuffer(const _di_IPlConvBuffer Value);
	
public:
	__fastcall virtual TPlConvertingCharset(void);
	__fastcall virtual ~TPlConvertingCharset(void);
	virtual bool __fastcall CanConvert(UCS Char);
	virtual int __fastcall ConvertFromUCS(UCS Char);
	virtual int __fastcall ConvertToUCS(Classes::TStream* Stream, /* out */ UCS &Char);
	virtual int __fastcall ConvertBufferToUCS(const void *Buf, int Count, bool IsLastChunk, /* out */ UCS &Char);
public:
	/* TPlCharset.CreateShift */ inline __fastcall virtual TPlConvertingCharset(int Shift) : TPlCharset(Shift) { }
	/* TPlCharset.CreateNoInit */ inline __fastcall virtual TPlConvertingCharset(void) : TPlCharset() { }
	/* TPlCharset.CreateForFinalize */ inline __fastcall virtual TPlConvertingCharset(void) : TPlCharset() { }
	
};


class DELPHICLASS TPlASCII;
class PASCALIMPLEMENTATION TPlASCII : public TPlTableCharset
{
	typedef TPlTableCharset inherited;
	
protected:
	virtual System::UnicodeString __fastcall GetAliases(void);
	virtual Sbtypes::ByteArray __fastcall GetAdditionalFromUCS(void);
	virtual PPlConversionTable __fastcall GetConversionTable(void);
	
public:
	virtual System::UnicodeString __fastcall GetCategory(void);
	virtual System::UnicodeString __fastcall GetDescription(void);
public:
	/* TPlTableCharset.Create */ inline __fastcall virtual TPlASCII(void) : TPlTableCharset() { }
	/* TPlTableCharset.CreateForFinalize */ inline __fastcall virtual TPlASCII(void) : TPlTableCharset() { }
	
public:
	/* TPlCharset.CreateShift */ inline __fastcall virtual TPlASCII(int Shift) : TPlTableCharset(Shift) { }
	/* TPlCharset.CreateNoInit */ inline __fastcall virtual TPlASCII(void) : TPlTableCharset() { }
	
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TPlASCII(void) { }
	
};


class DELPHICLASS TPlISO_8859_1;
class PASCALIMPLEMENTATION TPlISO_8859_1 : public TPlASCII
{
	typedef TPlASCII inherited;
	
protected:
	virtual System::UnicodeString __fastcall GetAliases(void);
	virtual PPlConversionTable __fastcall GetConversionTable(void);
	
public:
	virtual System::UnicodeString __fastcall GetCategory(void);
	virtual System::UnicodeString __fastcall GetDescription(void);
public:
	/* TPlTableCharset.Create */ inline __fastcall virtual TPlISO_8859_1(void) : TPlASCII() { }
	/* TPlTableCharset.CreateForFinalize */ inline __fastcall virtual TPlISO_8859_1(void) : TPlASCII() { }
	
public:
	/* TPlCharset.CreateShift */ inline __fastcall virtual TPlISO_8859_1(int Shift) : TPlASCII(Shift) { }
	/* TPlCharset.CreateNoInit */ inline __fastcall virtual TPlISO_8859_1(void) : TPlASCII() { }
	
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TPlISO_8859_1(void) { }
	
};


typedef StaticArray<System::Byte, 2147483647> TBytes;

typedef TBytes *PBytes;

typedef void * TPlCharsetClassPtr;

typedef _di_IPlCharset __fastcall (*TCharsetCreateProc)(void * Handle);

typedef void __fastcall (*TCharsetLibraryRegProc)(System::WideChar * Category, System::WideChar * Description, System::WideChar * Aliases, void * Handle, TCharsetCreateProc CreateProc);

//-- var, const, procedure ---------------------------------------------------
static const int UCS_Count = 0x110000;
static const Word UCSCharByteOrderLE32 = 0xfeff;
static const unsigned UCSCharByteOrderBE32 = 0xfffe0000;
static const Word UCSCharByteOrderLE16 = 0xfeff;
static const Word UCSCharByteOrderBE16 = 0xfffe;
static const Word UCSCharIgnore = 0xffff;
static const Word UCSCharIllegal = 0xfffd;
static const ShortInt SB_MAX_CHARACTER_LENGTH = 0x10;
#define cNilPrefixes (void *)(0)
#define cNilHiBytes (void *)(0)
#define cNilConvTable (void *)(0)
extern PACKAGE Syncobjs::TCriticalSection* BackGeneratorLock;
extern PACKAGE void __fastcall RegisterCharset(TPlCharsetClass CharsetClass);
extern PACKAGE void __fastcall UnregisterCharset(TPlCharsetClass CharsetClass);
extern PACKAGE void __stdcall RegisterCharsetLibrary(TCharsetLibraryRegProc RegistrationProc);
extern PACKAGE void __fastcall AbstractError(const System::UnicodeString ClassName, const System::UnicodeString Method);
extern PACKAGE void __fastcall Initialize(void);

}	/* namespace Sbchsconvbase */
using namespace Sbchsconvbase;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbchsconvbaseHPP
