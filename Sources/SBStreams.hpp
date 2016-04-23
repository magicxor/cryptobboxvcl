// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbstreams.pas' rev: 21.00

#ifndef SbstreamsHPP
#define SbstreamsHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Windows.hpp>	// Pascal unit
#include <Syncobjs.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbstreams
{
//-- type declarations -------------------------------------------------------
typedef Classes::TStream TElStream;

typedef Classes::TMemoryStream TElMemoryStream;

typedef Classes::TStream TElNativeStream;

class DELPHICLASS TElFileStream;
class PASCALIMPLEMENTATION TElFileStream : public Classes::TFileStream
{
	typedef Classes::TFileStream inherited;
	
private:
	__int64 __fastcall GetPosition64(void);
	void __fastcall SetPosition64(const __int64 Value);
	__int64 __fastcall GetSize64(void);
	HIDESBASE void __fastcall SetSize64(const __int64 Value);
	
public:
	__property __int64 Position64 = {read=GetPosition64, write=SetPosition64};
	__property __int64 Size64 = {read=GetSize64, write=SetSize64};
public:
	/* TFileStream.Create */ inline __fastcall TElFileStream(const System::UnicodeString AFileName, System::Word Mode)/* overload */ : Classes::TFileStream(AFileName, Mode) { }
	/* TFileStream.Destroy */ inline __fastcall virtual ~TElFileStream(void) { }
	
};


class DELPHICLASS TElDataStream;
class PASCALIMPLEMENTATION TElDataStream : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	__int64 FStart;
	Classes::TStream* FStream;
	bool FFreeOnSent;
	void __fastcall Close(void);
	
public:
	__fastcall TElDataStream(Classes::TStream* LStream, bool LFreeOnSent);
	__fastcall virtual ~TElDataStream(void);
	__property __int64 Start = {read=FStart};
	__property Classes::TStream* Stream = {read=FStream, write=FStream};
	__property bool FreeOnSent = {read=FFreeOnSent, write=FFreeOnSent, nodefault};
};


class DELPHICLASS TElMultiStream;
class PASCALIMPLEMENTATION TElMultiStream : public Classes::TStream
{
	typedef Classes::TStream inherited;
	
protected:
	Classes::TList* FStreams;
	__int64 FTotalSize;
	bool FSizeValid;
	__int64 FPosition;
	void __fastcall CleanupStreams(void);
	__int64 __fastcall GetTotalSize(void);
	int __fastcall DoRead(void * Buffer, int Offset, int Count);
	
public:
	__fastcall TElMultiStream(void);
	__fastcall virtual ~TElMultiStream(void);
	bool __fastcall AddStream(Classes::TStream* AStream, bool FreeStream);
	virtual int __fastcall Read(void *Buffer, int Count);
	virtual int __fastcall Write(const void *Buffer, int Count);
	virtual int __fastcall Seek(int Offset, System::Word Origin)/* overload */;
	virtual __int64 __fastcall Seek(const __int64 Offset, Classes::TSeekOrigin Origin)/* overload */;
};


class DELPHICLASS TElReadCachingStream;
class PASCALIMPLEMENTATION TElReadCachingStream : public Classes::TStream
{
	typedef Classes::TStream inherited;
	
protected:
	Sbtypes::ByteArray FCache;
	int FCacheSize;
	int FDataInCache;
	int FNextDataInCache;
	Classes::TStream* FStream;
	void __fastcall SetCacheSize(int Value);
	void __fastcall SetStream(Classes::TStream* Stream);
	
public:
	__fastcall TElReadCachingStream(void);
	__fastcall virtual ~TElReadCachingStream(void);
	virtual int __fastcall Read(void *Buffer, int Count);
	virtual int __fastcall Write(const void *Buffer, int Count);
	virtual int __fastcall Seek(int Offset, System::Word Origin)/* overload */;
	virtual __int64 __fastcall Seek(const __int64 Offset, Classes::TSeekOrigin Origin)/* overload */;
	__property Classes::TStream* Stream = {read=FStream, write=SetStream};
	__property int CacheSize = {read=FCacheSize, write=SetCacheSize, nodefault};
};


class DELPHICLASS TElWriteCachingStream;
class PASCALIMPLEMENTATION TElWriteCachingStream : public Classes::TStream
{
	typedef Classes::TStream inherited;
	
protected:
	Sbtypes::ByteArray FCache;
	int FCacheSize;
	int FDataInCache;
	Classes::TStream* FStream;
	void __fastcall SetCacheSize(int Value);
	void __fastcall SetStream(Classes::TStream* Stream);
	
public:
	__fastcall TElWriteCachingStream(void);
	__fastcall virtual ~TElWriteCachingStream(void);
	virtual int __fastcall Read(void *Buffer, int Count);
	virtual int __fastcall Write(const void *Buffer, int Count);
	virtual int __fastcall Seek(int Offset, System::Word Origin)/* overload */;
	virtual __int64 __fastcall Seek(const __int64 Offset, Classes::TSeekOrigin Origin)/* overload */;
	void __fastcall Flush(void);
	__property Classes::TStream* Stream = {read=FStream, write=SetStream};
	__property int CacheSize = {read=FCacheSize, write=SetCacheSize, nodefault};
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE __int64 __fastcall CopyStream(Classes::TStream* SrcStream, Classes::TStream* DestStream, __int64 Offset, __int64 Count, bool PreservePosition = true)/* overload */;
extern PACKAGE __int64 __fastcall CopyStream(Classes::TStream* Source, Classes::TStream* Dest, __int64 Offset, __int64 Count, bool PreservePosition, Sbutils::TSBProgressEvent ProgressEvent)/* overload */;
extern PACKAGE __int64 __fastcall StreamPosition(Classes::TStream* Stream);
extern PACKAGE __int64 __fastcall StreamSize(Classes::TStream* Stream);
extern PACKAGE void __fastcall SetStreamPosition(Classes::TStream* Stream, __int64 Position);
extern PACKAGE void __fastcall StreamRead(Classes::TStream* Stream, Sbtypes::ByteArray &Buffer, int Offset, int Count)/* overload */;
extern PACKAGE System::Byte __fastcall StreamReadByte(Classes::TStream* Stream)/* overload */;
extern PACKAGE void __fastcall StreamWrite(Classes::TStream* Stream, const Sbtypes::ByteArray Buffer)/* overload */;
extern PACKAGE void __fastcall StreamWrite(Classes::TStream* Stream, const Sbtypes::ByteArray Buffer, int Offset, int Count)/* overload */;
extern PACKAGE void __fastcall StreamClear(Classes::TMemoryStream* Stream);
extern PACKAGE void __fastcall StreamWriteLn(Classes::TStream* Stream, const System::UnicodeString Text);

}	/* namespace Sbstreams */
using namespace Sbstreams;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbstreamsHPP
