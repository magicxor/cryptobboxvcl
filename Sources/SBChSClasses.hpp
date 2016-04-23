// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbchsclasses.pas' rev: 21.00

#ifndef SbchsclassesHPP
#define SbchsclassesHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbchsclasses
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TPlBufferedInStream;
class PASCALIMPLEMENTATION TPlBufferedInStream : public Classes::TStream
{
	typedef Classes::TStream inherited;
	
private:
	System::Byte *FBuffer;
	int FBuffPos;
	int FBuffSize;
	int FBuffMaxSize;
	Classes::TStream* FStream;
	bool FOwnStream;
	
protected:
	virtual void __fastcall SetSize(int NewSize)/* overload */;
	
public:
	__fastcall TPlBufferedInStream(Classes::TStream* Stream, bool OwnStream, int BufferSize);
	__fastcall virtual ~TPlBufferedInStream(void);
	virtual int __fastcall Read(void *Buffer, int Count);
	virtual int __fastcall Write(const void *Buffer, int Count);
	virtual int __fastcall Seek(int Offset, System::Word Origin)/* overload */;
	
/* Hoisted overloads: */
	
protected:
	inline void __fastcall  SetSize(const __int64 NewSize){ Classes::TStream::SetSize(NewSize); }
	
public:
	inline __int64 __fastcall  Seek(const __int64 Offset, Classes::TSeekOrigin Origin){ return Classes::TStream::Seek(Offset, Origin); }
	
};


class DELPHICLASS TPlBufferedOutStream;
class PASCALIMPLEMENTATION TPlBufferedOutStream : public Classes::TStream
{
	typedef Classes::TStream inherited;
	
private:
	System::Byte *FBuffer;
	int FBuffSize;
	int FBuffMaxSize;
	Classes::TStream* FStream;
	bool FOwnStream;
	
protected:
	void __fastcall FlushBuffer(void);
	virtual void __fastcall SetSize(int NewSize)/* overload */;
	
public:
	__fastcall TPlBufferedOutStream(Classes::TStream* Stream, bool OwnStream, int BufferSize);
	__fastcall virtual ~TPlBufferedOutStream(void);
	virtual int __fastcall Read(void *Buffer, int Count);
	virtual int __fastcall Write(const void *Buffer, int Count);
	virtual int __fastcall Seek(int Offset, System::Word Origin)/* overload */;
	
/* Hoisted overloads: */
	
protected:
	inline void __fastcall  SetSize(const __int64 NewSize){ Classes::TStream::SetSize(NewSize); }
	
public:
	inline __int64 __fastcall  Seek(const __int64 Offset, Classes::TSeekOrigin Origin){ return Classes::TStream::Seek(Offset, Origin); }
	
};


typedef void __fastcall (__closure *TPlNewWideLineEvent)(System::TObject* Sender, System::WideChar * Line, int LineLength);

class DELPHICLASS TPlWideLinesStream;
class PASCALIMPLEMENTATION TPlWideLinesStream : public Classes::TStream
{
	typedef Classes::TStream inherited;
	
private:
	System::Byte *FBuffer;
	int FBufPos;
	int FBufSize;
	System::WideChar *FBufWide;
	System::WideChar FLastWide;
	TPlNewWideLineEvent FOnNewLine;
	
protected:
	void __fastcall DoNewLine(void);
	
public:
	__fastcall TPlWideLinesStream(TPlNewWideLineEvent OnNewLine);
	__fastcall virtual ~TPlWideLinesStream(void);
	virtual int __fastcall Read(void *Buffer, int Count);
	virtual int __fastcall Write(const void *Buffer, int Count);
	virtual int __fastcall Seek(int Offset, System::Word Origin)/* overload */;
	__property TPlNewWideLineEvent OnNewLine = {read=FOnNewLine, write=FOnNewLine};
	
/* Hoisted overloads: */
	
public:
	inline __int64 __fastcall  Seek(const __int64 Offset, Classes::TSeekOrigin Origin){ return Classes::TStream::Seek(Offset, Origin); }
	
};


//-- var, const, procedure ---------------------------------------------------

}	/* namespace Sbchsclasses */
using namespace Sbchsclasses;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbchsclassesHPP
