// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbencoding.pas' rev: 21.00

#ifndef SbencodingHPP
#define SbencodingHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbencoding
{
//-- type declarations -------------------------------------------------------
struct TSBBase64Context
{
	
public:
	StaticArray<System::Byte, 4> Tail;
	int TailBytes;
	int LineWritten;
	int LineSize;
	bool TrailingEol;
	bool PutFirstEol;
	bool LiberalMode;
	StaticArray<System::Byte, 4> fEOL;
	int EOLSize;
	StaticArray<System::Byte, 4> OutBuf;
	int EQUCount;
};


struct TSBBase32Context
{
	
private:
	typedef DynamicArray<System::Byte> _TSBBase32Context__1;
	
	
public:
	_TSBBase32Context__1 Tail;
	int TailSize;
	bool UseExtAlphabet;
};


class DELPHICLASS EElBase32Error;
class PASCALIMPLEMENTATION EElBase32Error : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElBase32Error(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElBase32Error(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElBase32Error(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElBase32Error(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElBase32Error(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElBase32Error(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElBase32Error(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElBase32Error(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElBase32Error(void) { }
	
};


class DELPHICLASS EElURLDecodeError;
class PASCALIMPLEMENTATION EElURLDecodeError : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElURLDecodeError(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElURLDecodeError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElURLDecodeError(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElURLDecodeError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElURLDecodeError(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElURLDecodeError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElURLDecodeError(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElURLDecodeError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElURLDecodeError(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
static const ShortInt BASE64_DECODE_OK = 0x0;
static const ShortInt BASE64_DECODE_INVALID_CHARACTER = 0x1;
static const ShortInt BASE64_DECODE_WRONG_DATA_SIZE = 0x2;
static const ShortInt BASE64_DECODE_NOT_ENOUGH_SPACE = 0x3;
extern PACKAGE StaticArray<System::Byte, 64> Base64Symbols;
extern PACKAGE StaticArray<System::Byte, 256> Base64Values;
extern PACKAGE StaticArray<System::Byte, 32> Base32Symbols;
extern PACKAGE StaticArray<System::Byte, 256> Base32Values;
extern PACKAGE StaticArray<System::Byte, 32> Base32ExtSymbols;
extern PACKAGE StaticArray<System::Byte, 256> Base32ExtValues;
static const System::Byte base64PadByte = 0x3d;
static const Word SB_BASE32_ERROR_BASE = 0x120;
static const Word SB_BASE32_INVALID_DATA_SIZE = 0x121;
static const Word SB_BASE32_INVALID_DATA = 0x122;
extern PACKAGE int __fastcall B32EstimateEncodedSize(const TSBBase32Context &Context, int InSize);
extern PACKAGE void __fastcall B32InitializeEncoding(TSBBase32Context &Context, bool UseExtendedAlphabet);
extern PACKAGE bool __fastcall B32Encode(TSBBase32Context &Context, void * Buffer, int Size, void * OutBuffer, int &OutSize)/* overload */;
extern PACKAGE bool __fastcall B32Encode(TSBBase32Context &Context, Sbtypes::ByteArray Buffer, int Index, int Size, Sbtypes::ByteArray &OutBuffer, int OutIndex, int &OutSize)/* overload */;
extern PACKAGE bool __fastcall B32FinalizeEncoding(TSBBase32Context &Context, void * OutBuffer, int &OutSize)/* overload */;
extern PACKAGE bool __fastcall B32FinalizeEncoding(TSBBase32Context &Context, Sbtypes::ByteArray &OutBuffer, int OutIndex, int &OutSize)/* overload */;
extern PACKAGE bool __fastcall Base32Encode(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, bool UseExtendedAlphabet)/* overload */;
extern PACKAGE bool __fastcall Base32Encode(Sbtypes::ByteArray InBuffer, int InIndex, int InSize, Sbtypes::ByteArray &OutBuffer, int OutIndex, int &OutSize, bool UseExtendedAlphabet)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall Base32EncodeBuffer(const Sbtypes::ByteArray Data, bool UseExtendedAlphabet);
extern PACKAGE System::UnicodeString __fastcall Base32EncodeString(const System::UnicodeString Data, bool UseExtendedAlphabet);
extern PACKAGE int __fastcall B32EstimateDecodedSize(const TSBBase32Context &Context, int InSize);
extern PACKAGE void __fastcall B32InitializeDecoding(TSBBase32Context &Context, bool UseExtendedAlphabet);
extern PACKAGE bool __fastcall B32Decode(TSBBase32Context &Context, void * Buffer, int Size, void * OutBuffer, int &OutSize)/* overload */;
extern PACKAGE bool __fastcall B32Decode(TSBBase32Context &Context, Sbtypes::ByteArray Buffer, int Index, int Size, Sbtypes::ByteArray &OutBuffer, int OutIndex, int &OutSize)/* overload */;
extern PACKAGE bool __fastcall B32FinalizeDecoding(TSBBase32Context &Context);
extern PACKAGE bool __fastcall Base32Decode(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, bool UseExtendedAlphabet)/* overload */;
extern PACKAGE bool __fastcall Base32Decode(Sbtypes::ByteArray InBuffer, int InIndex, int InSize, Sbtypes::ByteArray &OutBuffer, int OutIndex, int &OutSize, bool UseExtendedAlphabet)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall Base32DecodeBuffer(const Sbtypes::ByteArray Data, bool UseExtendedAlphabet);
extern PACKAGE System::UnicodeString __fastcall Base32DecodeString(const System::UnicodeString Data, bool UseExtendedAlphabet);
extern PACKAGE Sbtypes::ByteArray __fastcall Base32Extract(const Sbtypes::ByteArray Data, int Start, int Size, bool UseExtendedAlphabet)/* overload */;
extern PACKAGE System::UnicodeString __fastcall Base32Extract(const System::UnicodeString Data, int Start, int Size, bool UseExtendedAlphabet)/* overload */;
extern PACKAGE int __fastcall B64EstimateEncodedSize(const TSBBase64Context &Ctx, int InSize);
extern PACKAGE bool __fastcall B64InitializeDecoding(TSBBase64Context &Ctx)/* overload */;
extern PACKAGE bool __fastcall B64InitializeDecoding(TSBBase64Context &Ctx, bool LiberalMode)/* overload */;
extern PACKAGE bool __fastcall B64InitializeEncoding(TSBBase64Context &Ctx, int LineSize, Sbtypes::TSBEOLMarker fEOL, bool TrailingEOL = false);
extern PACKAGE bool __fastcall B64Encode(TSBBase64Context &Ctx, void * Buffer, int Size, void * OutBuffer, int &OutSize);
extern PACKAGE bool __fastcall B64Decode(TSBBase64Context &Ctx, void * Buffer, int Size, void * OutBuffer, int &OutSize);
extern PACKAGE bool __fastcall B64FinalizeEncoding(TSBBase64Context &Ctx, void * OutBuffer, int &OutSize);
extern PACKAGE bool __fastcall B64FinalizeDecoding(TSBBase64Context &Ctx, void * OutBuffer, int &OutSize);
extern PACKAGE System::UnicodeString __fastcall Base64EncodeString(const System::UnicodeString InText, bool WrapLines = true)/* overload */;
extern PACKAGE System::UnicodeString __fastcall Base64EncodeArray(const Sbtypes::ByteArray InBuf, bool WrapLines = true)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall Base64DecodeArray(const System::UnicodeString InBuf)/* overload */;
extern PACKAGE System::UnicodeString __fastcall Base64DecodeString(const System::UnicodeString InText)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall Base64EncodeString(const Sbtypes::ByteArray InBuf, bool WrapLines = true)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall Base64DecodeString(const Sbtypes::ByteArray InBuf)/* overload */;
extern PACKAGE bool __fastcall Base64Encode(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, bool WrapLines = true);
extern PACKAGE int __fastcall Base64UnicodeDecode(void * InBuffer, int InSize, void * OutBuffer, int &OutSize);
extern PACKAGE int __fastcall Base64Decode(void * InBuffer, int InSize, void * OutBuffer, int &OutSize)/* overload */;
extern PACKAGE int __fastcall Base64Decode(void * InBuffer, int InSize, void * OutBuffer, int &OutSize, bool LiberalMode)/* overload */;
extern PACKAGE System::UnicodeString __fastcall URLEncode(const System::UnicodeString Data);
extern PACKAGE System::UnicodeString __fastcall URLDecode(const System::UnicodeString Data);
extern PACKAGE Sbtypes::ByteArray __fastcall Base16DecodeString(const System::UnicodeString Data);

}	/* namespace Sbencoding */
using namespace Sbencoding;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbencodingHPP
