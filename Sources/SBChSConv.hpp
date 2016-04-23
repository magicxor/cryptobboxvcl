// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbchsconv.pas' rev: 21.00

#ifndef SbchsconvHPP
#define SbchsconvHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Windows.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbsharedresource.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbchsconvbase.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbchsconv
{
//-- type declarations -------------------------------------------------------
#pragma option push -b-
enum TPlConvertOption { coContinuePrevious, coNoDefaultChar, coInvalidCharException, coWriteFileHeader, coWriteLineBegin, coWriteLineEnd };
#pragma option pop

typedef Set<TPlConvertOption, coContinuePrevious, coWriteLineEnd>  TPlConvertOptions;

#pragma option push -b-
enum TPlConverterLineState { lsStarted, lsFinished };
#pragma option pop

typedef Set<TPlConverterLineState, lsStarted, lsFinished>  TPlConverterLineStates;

class DELPHICLASS TPlConverter;
class PASCALIMPLEMENTATION TPlConverter : public Classes::TPersistent
{
	typedef Classes::TPersistent inherited;
	
private:
	Sbchsconvbase::_di_IPlConvBuffer fInBuffer;
	Sbchsconvbase::_di_IPlConvBuffer fOutBuffer;
	TPlConverterLineStates fLineStates;
	Sbchsconvbase::_di_IPlCharset fSrc;
	Sbchsconvbase::_di_IPlCharset fDst;
	
protected:
	System::UnicodeString __fastcall GetDstName(void);
	System::UnicodeString __fastcall GetSrcName(void);
	void __fastcall SetDstName(const System::UnicodeString Value);
	void __fastcall SetSrcName(const System::UnicodeString Value);
	
public:
	__fastcall TPlConverter(void)/* overload */;
	__fastcall TPlConverter(const System::UnicodeString SrcCharset, const System::UnicodeString DstCharset)/* overload */;
	__fastcall TPlConverter(Sbchsconvbase::_di_IPlCharset SrcCharset, Sbchsconvbase::_di_IPlCharset DstCharset)/* overload */;
	__fastcall virtual ~TPlConverter(void);
	void __fastcall Convert(const System::AnsiString Source, /* out */ System::AnsiString &Dest, TPlConvertOptions Options)/* overload */;
	void __fastcall Convert(Classes::TStream* Source, Classes::TStream* Dest, TPlConvertOptions Options, int MaxChars = 0x0)/* overload */;
	bool __fastcall IsConvert(const System::AnsiString Source, /* out */ System::AnsiString &Dest, TPlConvertOptions Options)/* overload */;
	bool __fastcall IsConvert(Classes::TStream* Source, Classes::TStream* Dest, TPlConvertOptions Options, int MaxChars = 0x0)/* overload */;
	void __fastcall ConvertFromUnicode(const System::UnicodeString Source, /* out */ System::AnsiString &Dest, TPlConvertOptions Options);
	void __fastcall ConvertToUnicode(const System::AnsiString Source, /* out */ System::UnicodeString &Dest, TPlConvertOptions Options);
	bool __fastcall IsConvertFromUnicode(const System::UnicodeString Source, /* out */ System::AnsiString &Dest, TPlConvertOptions Options);
	bool __fastcall IsConvertToUnicode(const System::AnsiString Source, /* out */ System::UnicodeString &Dest, TPlConvertOptions Options);
	__property Sbchsconvbase::_di_IPlCharset DstCharset = {read=fDst};
	__property System::UnicodeString DstCharsetName = {read=GetDstName, write=SetDstName};
	__property Sbchsconvbase::_di_IPlCharset SrcCharset = {read=fSrc};
	__property System::UnicodeString SrcCharsetName = {read=GetSrcName, write=SetSrcName};
};


class DELPHICLASS EPlConvError;
class PASCALIMPLEMENTATION EPlConvError : public Sysutils::Exception
{
	typedef Sysutils::Exception inherited;
	
public:
	__fastcall EPlConvError(bool Encoding, Sbchsconvbase::_di_IPlCharset Charset, const System::UnicodeString ErrorMessage);
public:
	/* Exception.CreateFmt */ inline __fastcall EPlConvError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sysutils::Exception(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EPlConvError(int Ident)/* overload */ : Sysutils::Exception(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EPlConvError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sysutils::Exception(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EPlConvError(const System::UnicodeString Msg, int AHelpContext) : Sysutils::Exception(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EPlConvError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sysutils::Exception(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EPlConvError(int Ident, int AHelpContext)/* overload */ : Sysutils::Exception(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EPlConvError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sysutils::Exception(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EPlConvError(void) { }
	
};


class DELPHICLASS TPlCustomUTF;
class PASCALIMPLEMENTATION TPlCustomUTF : public Sbchsconvbase::TPlCharset
{
	typedef Sbchsconvbase::TPlCharset inherited;
	
private:
	bool fByteOrderBE;
	
protected:
	virtual void __fastcall Reset(void);
	
public:
	virtual System::UnicodeString __fastcall GetCategory(void);
public:
	/* TPlCharset.Create */ inline __fastcall virtual TPlCustomUTF(void) : Sbchsconvbase::TPlCharset() { }
	/* TPlCharset.CreateShift */ inline __fastcall virtual TPlCustomUTF(int Shift) : Sbchsconvbase::TPlCharset(Shift) { }
	/* TPlCharset.CreateNoInit */ inline __fastcall virtual TPlCustomUTF(void) : Sbchsconvbase::TPlCharset() { }
	/* TPlCharset.CreateForFinalize */ inline __fastcall virtual TPlCustomUTF(void) : Sbchsconvbase::TPlCharset() { }
	
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TPlCustomUTF(void) { }
	
};


class DELPHICLASS TPlUTF32;
class PASCALIMPLEMENTATION TPlUTF32 : public TPlCustomUTF
{
	typedef TPlCustomUTF inherited;
	
protected:
	virtual unsigned __fastcall WriteFileHeader(void);
	virtual void __fastcall WriteChar(unsigned Char);
	virtual System::UnicodeString __fastcall GetAliases(void);
	
public:
	virtual int __fastcall ConvertFromUCS(Sbchsconvbase::UCS Char);
	virtual int __fastcall ConvertToUCS(Classes::TStream* Stream, /* out */ Sbchsconvbase::UCS &Char);
	virtual int __fastcall ConvertBufferToUCS(const void *Buf, int Count, bool IsLastChunk, /* out */ Sbchsconvbase::UCS &Char);
	virtual System::UnicodeString __fastcall GetDescription(void);
public:
	/* TPlCharset.Create */ inline __fastcall virtual TPlUTF32(void) : TPlCustomUTF() { }
	/* TPlCharset.CreateShift */ inline __fastcall virtual TPlUTF32(int Shift) : TPlCustomUTF(Shift) { }
	/* TPlCharset.CreateNoInit */ inline __fastcall virtual TPlUTF32(void) : TPlCustomUTF() { }
	/* TPlCharset.CreateForFinalize */ inline __fastcall virtual TPlUTF32(void) : TPlCustomUTF() { }
	
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TPlUTF32(void) { }
	
};


class DELPHICLASS TPlUTF32BE;
class PASCALIMPLEMENTATION TPlUTF32BE : public TPlUTF32
{
	typedef TPlUTF32 inherited;
	
protected:
	virtual void __fastcall Reset(void);
	virtual void __fastcall WriteChar(unsigned Char);
	virtual System::UnicodeString __fastcall GetAliases(void);
	
public:
	__fastcall virtual TPlUTF32BE(void);
	virtual System::UnicodeString __fastcall GetDescription(void);
public:
	/* TPlCharset.CreateShift */ inline __fastcall virtual TPlUTF32BE(int Shift) : TPlUTF32(Shift) { }
	/* TPlCharset.CreateNoInit */ inline __fastcall virtual TPlUTF32BE(void) : TPlUTF32() { }
	/* TPlCharset.CreateForFinalize */ inline __fastcall virtual TPlUTF32BE(void) : TPlUTF32() { }
	
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TPlUTF32BE(void) { }
	
};


class DELPHICLASS TPlUTF16;
class PASCALIMPLEMENTATION TPlUTF16 : public TPlCustomUTF
{
	typedef TPlCustomUTF inherited;
	
protected:
	virtual unsigned __fastcall WriteFileHeader(void);
	virtual void __fastcall WriteChar(System::Word Char);
	virtual System::UnicodeString __fastcall GetAliases(void);
	
public:
	virtual int __fastcall ConvertFromUCS(Sbchsconvbase::UCS Char);
	virtual int __fastcall ConvertToUCS(Classes::TStream* Stream, /* out */ Sbchsconvbase::UCS &Char);
	virtual int __fastcall ConvertBufferToUCS(const void *Buf, int Count, bool IsLastChunk, /* out */ Sbchsconvbase::UCS &Char);
	virtual System::UnicodeString __fastcall GetDescription(void);
public:
	/* TPlCharset.Create */ inline __fastcall virtual TPlUTF16(void) : TPlCustomUTF() { }
	/* TPlCharset.CreateShift */ inline __fastcall virtual TPlUTF16(int Shift) : TPlCustomUTF(Shift) { }
	/* TPlCharset.CreateNoInit */ inline __fastcall virtual TPlUTF16(void) : TPlCustomUTF() { }
	/* TPlCharset.CreateForFinalize */ inline __fastcall virtual TPlUTF16(void) : TPlCustomUTF() { }
	
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TPlUTF16(void) { }
	
};


class DELPHICLASS TPlUTF16BE;
class PASCALIMPLEMENTATION TPlUTF16BE : public TPlUTF16
{
	typedef TPlUTF16 inherited;
	
protected:
	virtual void __fastcall Reset(void);
	virtual void __fastcall WriteChar(System::Word Char);
	virtual System::UnicodeString __fastcall GetAliases(void);
	
public:
	__fastcall virtual TPlUTF16BE(void);
	virtual System::UnicodeString __fastcall GetDescription(void);
public:
	/* TPlCharset.CreateShift */ inline __fastcall virtual TPlUTF16BE(int Shift) : TPlUTF16(Shift) { }
	/* TPlCharset.CreateNoInit */ inline __fastcall virtual TPlUTF16BE(void) : TPlUTF16() { }
	/* TPlCharset.CreateForFinalize */ inline __fastcall virtual TPlUTF16BE(void) : TPlUTF16() { }
	
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TPlUTF16BE(void) { }
	
};


class DELPHICLASS TPlUTF8;
class PASCALIMPLEMENTATION TPlUTF8 : public Sbchsconvbase::TPlCharset
{
	typedef Sbchsconvbase::TPlCharset inherited;
	
protected:
	virtual unsigned __fastcall WriteFileHeader(void);
	virtual System::UnicodeString __fastcall GetAliases(void);
	
public:
	virtual int __fastcall ConvertFromUCS(Sbchsconvbase::UCS Char);
	virtual int __fastcall ConvertToUCS(Classes::TStream* Stream, /* out */ Sbchsconvbase::UCS &Char);
	virtual int __fastcall ConvertBufferToUCS(const void *Buf, int Count, bool IsLastChunk, /* out */ Sbchsconvbase::UCS &Char);
	virtual System::UnicodeString __fastcall GetCategory(void);
	virtual System::UnicodeString __fastcall GetDescription(void);
public:
	/* TPlCharset.Create */ inline __fastcall virtual TPlUTF8(void) : Sbchsconvbase::TPlCharset() { }
	/* TPlCharset.CreateShift */ inline __fastcall virtual TPlUTF8(int Shift) : Sbchsconvbase::TPlCharset(Shift) { }
	/* TPlCharset.CreateNoInit */ inline __fastcall virtual TPlUTF8(void) : Sbchsconvbase::TPlCharset() { }
	/* TPlCharset.CreateForFinalize */ inline __fastcall virtual TPlUTF8(void) : Sbchsconvbase::TPlCharset() { }
	
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TPlUTF8(void) { }
	
};


#pragma option push -b-
enum TPlUTF7State { usDirect, usBase64, usShift };
#pragma option pop

class DELPHICLASS TPlUTF7;
class PASCALIMPLEMENTATION TPlUTF7 : public Sbchsconvbase::TPlCharset
{
	typedef Sbchsconvbase::TPlCharset inherited;
	
private:
	TPlUTF7State fState;
	int fTail;
	int fTailBits;
	
protected:
	__classmethod int __fastcall GetBase64(char Char);
	virtual unsigned __fastcall WriteLineEnd(void);
	virtual System::UnicodeString __fastcall GetAliases(void);
	
public:
	virtual int __fastcall ConvertFromUCS(Sbchsconvbase::UCS Char);
	virtual int __fastcall ConvertToUCS(Classes::TStream* Stream, /* out */ Sbchsconvbase::UCS &Char);
	virtual int __fastcall ConvertBufferToUCS(const void *Buf, int Count, bool IsLastChunk, /* out */ Sbchsconvbase::UCS &Char);
	virtual System::UnicodeString __fastcall GetCategory(void);
	virtual System::UnicodeString __fastcall GetDescription(void);
public:
	/* TPlCharset.Create */ inline __fastcall virtual TPlUTF7(void) : Sbchsconvbase::TPlCharset() { }
	/* TPlCharset.CreateShift */ inline __fastcall virtual TPlUTF7(int Shift) : Sbchsconvbase::TPlCharset(Shift) { }
	/* TPlCharset.CreateNoInit */ inline __fastcall virtual TPlUTF7(void) : Sbchsconvbase::TPlCharset() { }
	/* TPlCharset.CreateForFinalize */ inline __fastcall virtual TPlUTF7(void) : Sbchsconvbase::TPlCharset() { }
	
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TPlUTF7(void) { }
	
};


typedef void * TUserData;

typedef void __fastcall (*TEnumCharsetsProc)(const System::UnicodeString Category, const System::UnicodeString Description, const System::UnicodeString Name, const System::UnicodeString Aliases, void * UserData, bool &Stop);

class DELPHICLASS TPlConvBuffer;
class PASCALIMPLEMENTATION TPlConvBuffer : public System::TInterfacedObject
{
	typedef System::TInterfacedObject inherited;
	
private:
	System::AnsiString fData;
	int fPosition;
	int fSize;
	
protected:
	void __fastcall Clear(bool LeaveUnprocessedData = false);
	void __fastcall Restart(void);
	
public:
	bool __fastcall CheckString(Classes::TStream* Stream, const System::AnsiString Str, int Shift = 0x0);
	System::Byte __fastcall GetByte(Classes::TStream* Stream, bool &Exists);
	System::Word __fastcall GetWide(Classes::TStream* Stream, bool &Exists);
	unsigned __fastcall GetLong(Classes::TStream* Stream, bool &Exists);
	void __fastcall ReturnByte(void)/* overload */;
	void __fastcall ReturnByte(System::Byte Value)/* overload */;
	void __fastcall ReturnBytes(int Count);
	void __fastcall Flush(Classes::TStream* Stream);
	void __fastcall Put(const void *Data, int Count);
	void __fastcall PutByte(System::Byte Value);
	void __fastcall PutWordLE(System::Word Value);
	System::Byte __fastcall RevokeByte(void);
public:
	/* TObject.Create */ inline __fastcall TPlConvBuffer(void) : System::TInterfacedObject() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TPlConvBuffer(void) { }
	
private:
	void *__IPlConvBuffer;	/* Sbchsconvbase::IPlConvBuffer */
	
public:
	#if defined(MANAGED_INTERFACE_OPERATORS)
	operator Sbchsconvbase::_di_IPlConvBuffer()
	{
		Sbchsconvbase::_di_IPlConvBuffer intf;
		GetInterface(intf);
		return intf;
	}
	#else
	operator IPlConvBuffer*(void) { return (IPlConvBuffer*)&__IPlConvBuffer; }
	#endif
	
};


typedef void * TDataPtr;

class DELPHICLASS TPlCustomStringStream;
class PASCALIMPLEMENTATION TPlCustomStringStream : public Classes::TStream
{
	typedef Classes::TStream inherited;
	
private:
	void *fData;
	int fPosition;
	int fSize;
	
protected:
	virtual void __fastcall internalSetSize(__int64 NewSize);
	virtual void __fastcall SetSize(int NewSize)/* overload */;
	virtual void __fastcall SetSize(const __int64 NewSize)/* overload */;
	
public:
	virtual int __fastcall Read(void *Buffer, int Count);
	virtual int __fastcall Write(const void *Buffer, int Count);
	virtual int __fastcall Seek(int Offset, System::Word Origin)/* overload */;
	virtual __int64 __fastcall Seek(const __int64 Offset, Classes::TSeekOrigin Origin)/* overload */;
	void __fastcall Clear(void);
public:
	/* TObject.Create */ inline __fastcall TPlCustomStringStream(void) : Classes::TStream() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TPlCustomStringStream(void) { }
	
};


class DELPHICLASS TPlAnsiStringStream;
class PASCALIMPLEMENTATION TPlAnsiStringStream : public TPlCustomStringStream
{
	typedef TPlCustomStringStream inherited;
	
protected:
	void __fastcall SetData(const System::PAnsiString Value);
	virtual void __fastcall internalSetSize(__int64 NewSize);
	
public:
	__property System::PAnsiString Data = {write=SetData};
public:
	/* TObject.Create */ inline __fastcall TPlAnsiStringStream(void) : TPlCustomStringStream() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TPlAnsiStringStream(void) { }
	
};


class DELPHICLASS TPlWideStringStream;
class PASCALIMPLEMENTATION TPlWideStringStream : public TPlCustomStringStream
{
	typedef TPlCustomStringStream inherited;
	
protected:
	void __fastcall SetData(const System::PUnicodeString Value);
	virtual void __fastcall internalSetSize(__int64 NewSize);
	
public:
	__property System::PUnicodeString Data = {write=SetData};
public:
	/* TObject.Create */ inline __fastcall TPlWideStringStream(void) : TPlCustomStringStream() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TPlWideStringStream(void) { }
	
};


class DELPHICLASS TPlByteArrayStream;
class PASCALIMPLEMENTATION TPlByteArrayStream : public Classes::TStream
{
	typedef Classes::TStream inherited;
	
public:
	/* TObject.Create */ inline __fastcall TPlByteArrayStream(void) : Classes::TStream() { }
	/* TObject.Destroy */ inline __fastcall virtual ~TPlByteArrayStream(void) { }
	
};


class DELPHICLASS TPlCustomStringStreamPool;
class PASCALIMPLEMENTATION TPlCustomStringStreamPool : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	Sbsharedresource::TElSharedResource* FCS;
	Classes::TList* FFreeStreams;
	Classes::TList* FOccupiedStreams;
	TPlCustomStringStream* __fastcall InternalAcquireStream(void);
	void __fastcall InternalReleaseStream(TPlCustomStringStream* Stream);
	virtual TPlCustomStringStream* __fastcall CreateUnderlyingStream(void);
	
public:
	__fastcall TPlCustomStringStreamPool(void);
	__fastcall virtual ~TPlCustomStringStreamPool(void);
};


class DELPHICLASS TPlAnsiStringStreamPool;
class PASCALIMPLEMENTATION TPlAnsiStringStreamPool : public TPlCustomStringStreamPool
{
	typedef TPlCustomStringStreamPool inherited;
	
protected:
	virtual TPlCustomStringStream* __fastcall CreateUnderlyingStream(void);
	
public:
	TPlAnsiStringStream* __fastcall AcquireStream(void);
	void __fastcall ReleaseStream(TPlAnsiStringStream* Stream);
public:
	/* TPlCustomStringStreamPool.Create */ inline __fastcall TPlAnsiStringStreamPool(void) : TPlCustomStringStreamPool() { }
	/* TPlCustomStringStreamPool.Destroy */ inline __fastcall virtual ~TPlAnsiStringStreamPool(void) { }
	
};


class DELPHICLASS TPlWideStringStreamPool;
class PASCALIMPLEMENTATION TPlWideStringStreamPool : public TPlCustomStringStreamPool
{
	typedef TPlCustomStringStreamPool inherited;
	
protected:
	virtual TPlCustomStringStream* __fastcall CreateUnderlyingStream(void);
	
public:
	TPlWideStringStream* __fastcall AcquireStream(void);
	void __fastcall ReleaseStream(TPlWideStringStream* Stream);
public:
	/* TPlCustomStringStreamPool.Create */ inline __fastcall TPlWideStringStreamPool(void) : TPlCustomStringStreamPool() { }
	/* TPlCustomStringStreamPool.Destroy */ inline __fastcall virtual ~TPlWideStringStreamPool(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE void __fastcall EnumCharsets(TEnumCharsetsProc EnumProc, void * UserData);
extern PACKAGE Sbchsconvbase::_di_IPlCharset __fastcall CreateCharset(const System::UnicodeString Name);
extern PACKAGE Sbchsconvbase::_di_IPlCharset __fastcall CreateCharsetByDescription(const System::UnicodeString ADescription);
extern PACKAGE Sbchsconvbase::_di_IPlCharset __fastcall CreateSystemDefaultCharset(void);
extern PACKAGE System::UnicodeString __fastcall GetSystemDefaultCharsetName(void);
extern PACKAGE System::UnicodeString __fastcall GetCharsetNameByAlias(const System::UnicodeString Alias);
extern PACKAGE void __fastcall Initialize(void);

}	/* namespace Sbchsconv */
using namespace Sbchsconv;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbchsconvHPP
