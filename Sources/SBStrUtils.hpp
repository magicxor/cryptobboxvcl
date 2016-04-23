// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbstrutils.pas' rev: 21.00

#ifndef SbstrutilsHPP
#define SbstrutilsHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Windows.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbstrutils
{
//-- type declarations -------------------------------------------------------
class DELPHICLASS TElStringConverter;
class PASCALIMPLEMENTATION TElStringConverter : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	System::UnicodeString FDefCharset;
	virtual void __fastcall SetDefCharset(const System::UnicodeString Value);
	
public:
	__fastcall TElStringConverter(void);
	virtual Sbtypes::ByteArray __fastcall StrToUtf8(const System::UnicodeString Source);
	virtual System::UnicodeString __fastcall Utf8ToStr(const Sbtypes::ByteArray Source);
	virtual Sbtypes::ByteArray __fastcall StrToWideStr(const System::UnicodeString Source);
	virtual System::UnicodeString __fastcall WideStrToStr(const Sbtypes::ByteArray Source);
	__property System::UnicodeString DefCharset = {read=FDefCharset, write=SetDefCharset};
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TElStringConverter(void) { }
	
};


class DELPHICLASS TElPlatformStringConverter;
class PASCALIMPLEMENTATION TElPlatformStringConverter : public TElStringConverter
{
	typedef TElStringConverter inherited;
	
protected:
	virtual void __fastcall SetDefCharset(const System::UnicodeString Value);
	int __fastcall GetWindowsCodePageIdentifier(const System::UnicodeString Name);
	
public:
	__fastcall TElPlatformStringConverter(void);
	virtual Sbtypes::ByteArray __fastcall StrToUtf8(const System::UnicodeString Source);
	virtual System::UnicodeString __fastcall Utf8ToStr(const Sbtypes::ByteArray Source);
	virtual Sbtypes::ByteArray __fastcall StrToWideStr(const System::UnicodeString Source);
	virtual System::UnicodeString __fastcall WideStrToStr(const Sbtypes::ByteArray Source);
	Sbtypes::ByteArray __fastcall EncodeStr(const System::UnicodeString Source, int Encoding)/* overload */;
	System::UnicodeString __fastcall DecodeStr(const Sbtypes::ByteArray Source, int Encoding)/* overload */;
	Sbtypes::ByteArray __fastcall EncodeStr(const System::UnicodeString Source, const System::UnicodeString Encoding)/* overload */;
	System::UnicodeString __fastcall DecodeStr(const Sbtypes::ByteArray Source, const System::UnicodeString Encoding)/* overload */;
public:
	/* TObject.Destroy */ inline __fastcall virtual ~TElPlatformStringConverter(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
extern PACKAGE unsigned UNI_REPLACEMENT_CHAR;
extern PACKAGE unsigned UNI_MAX_BMP;
extern PACKAGE unsigned UNI_MAX_UTF16;
extern PACKAGE int halfShift;
extern PACKAGE unsigned halfBase;
extern PACKAGE unsigned halfMask;
extern PACKAGE unsigned UNI_SUR_HIGH_START;
extern PACKAGE unsigned UNI_SUR_HIGH_END;
extern PACKAGE unsigned UNI_SUR_LOW_START;
extern PACKAGE unsigned UNI_SUR_LOW_END;
extern PACKAGE StaticArray<System::Byte, 256> trailingBytesForUTF8;
extern PACKAGE TElStringConverter* G_StringConverter;
extern PACKAGE System::UnicodeString EmptyString;
extern PACKAGE System::UnicodeString __fastcall PrefixString(const System::UnicodeString S, int Count, System::WideChar Value);
extern PACKAGE System::UnicodeString __fastcall SuffixString(const System::UnicodeString S, int Count, System::WideChar Value);
extern PACKAGE bool __fastcall StringEquals(const System::UnicodeString S1, const System::UnicodeString S2)/* overload */;
extern PACKAGE bool __fastcall StringEquals(const System::UnicodeString S1, const System::UnicodeString S2, bool IgnoreCase)/* overload */;
extern PACKAGE bool __fastcall StringEquals(const System::UnicodeString S1, const System::UnicodeString S2, int MaxLength)/* overload */;
extern PACKAGE bool __fastcall StringEquals(const System::UnicodeString S1, const System::UnicodeString S2, int MaxLength, bool IgnoreCase)/* overload */;
extern PACKAGE bool __fastcall StringEquals(const System::UnicodeString S1, int Index1, const System::UnicodeString S2, int Index2, int MaxLength)/* overload */;
extern PACKAGE bool __fastcall StringEquals(const System::UnicodeString S1, int Index1, const System::UnicodeString S2, int Index2, int MaxLength, bool IgnoreCase)/* overload */;
extern PACKAGE int __fastcall StringIndexOf(const System::UnicodeString S, const System::WideChar C)/* overload */;
extern PACKAGE int __fastcall StringIndexOf(const System::UnicodeString S, const System::WideChar C, int StartIndex)/* overload */;
extern PACKAGE int __fastcall StringIndexOf(const System::UnicodeString S, const System::UnicodeString SubS)/* overload */;
extern PACKAGE int __fastcall StringIndexOf(const System::UnicodeString S, const System::UnicodeString SubS, int StartIndex)/* overload */;
extern PACKAGE int __fastcall StringIndexOfU(const System::UnicodeString S, const System::WideChar C);
extern PACKAGE System::UnicodeString __fastcall StringInsert(const System::UnicodeString S, int Index, System::WideChar C)/* overload */;
extern PACKAGE System::UnicodeString __fastcall StringInsert(const System::UnicodeString S, int Index, System::UnicodeString SubS)/* overload */;
extern PACKAGE System::AnsiString __fastcall StringInsert(const System::AnsiString S, int Index, char C)/* overload */;
extern PACKAGE System::AnsiString __fastcall StringInsert(const System::AnsiString S, int Index, System::AnsiString SubS)/* overload */;
extern PACKAGE bool __fastcall StringIsEmpty(const System::UnicodeString S);
extern PACKAGE int __fastcall StringLastIndexOf(const System::UnicodeString S, const System::WideChar C)/* overload */;
extern PACKAGE int __fastcall StringLastIndexOf(const System::UnicodeString S, const System::WideChar C, int StartIndex)/* overload */;
extern PACKAGE int __fastcall StringLastIndexOf(const System::AnsiString S, const char C)/* overload */;
extern PACKAGE int __fastcall StringLastIndexOf(const System::AnsiString S, const char C, int StartIndex)/* overload */;
extern PACKAGE System::UnicodeString __fastcall WideStringRemove(const System::UnicodeString S, int StartIndex)/* overload */;
extern PACKAGE System::UnicodeString __fastcall StringRemove(const System::UnicodeString S, int StartIndex)/* overload */;
extern PACKAGE System::UnicodeString __fastcall WideStringRemove(const System::UnicodeString S, int StartIndex, int Count)/* overload */;
extern PACKAGE System::UnicodeString __fastcall StringRemove(const System::UnicodeString S, int StartIndex, int Count)/* overload */;
extern PACKAGE System::AnsiString __fastcall StringRemove(const System::AnsiString S, int StartIndex)/* overload */;
extern PACKAGE System::AnsiString __fastcall StringRemove(const System::AnsiString S, int StartIndex, int Count)/* overload */;
extern PACKAGE System::AnsiString __fastcall AnsiStringRemove(const System::AnsiString S, int StartIndex)/* overload */;
extern PACKAGE System::AnsiString __fastcall AnsiStringRemove(const System::AnsiString S, int StartIndex, int Count)/* overload */;
extern PACKAGE System::UnicodeString __fastcall StringToLower(const System::UnicodeString S);
extern PACKAGE System::UnicodeString __fastcall StringToLowerInvariant(const System::UnicodeString S);
extern PACKAGE bool __fastcall StringEndsWith(const System::UnicodeString S, const System::UnicodeString SubS)/* overload */;
extern PACKAGE bool __fastcall StringEndsWith(const System::UnicodeString S, const System::UnicodeString SubS, bool IgnoreCase)/* overload */;
extern PACKAGE bool __fastcall StringStartsWith(const System::UnicodeString S, const System::UnicodeString SubS)/* overload */;
extern PACKAGE bool __fastcall StringStartsWith(const System::UnicodeString S, const System::UnicodeString SubS, bool IgnoreCase)/* overload */;
extern PACKAGE System::UnicodeString __fastcall StringSubstring(const System::UnicodeString S, int StartIndex)/* overload */;
extern PACKAGE System::UnicodeString __fastcall StringSubstring(const System::UnicodeString S, int StartIndex, int Length)/* overload */;
extern PACKAGE System::UnicodeString __fastcall StringTrim(const System::UnicodeString S);
extern PACKAGE System::UnicodeString __fastcall StringTrimEnd(const System::UnicodeString S);
extern PACKAGE System::UnicodeString __fastcall StringTrimStart(const System::UnicodeString S);
extern PACKAGE System::UnicodeString __fastcall StringToUpper(const System::UnicodeString S);
extern PACKAGE System::UnicodeString __fastcall StringToUpperInvariant(const System::UnicodeString S);
extern PACKAGE Sbtypes::ByteArray __fastcall StrToDefEncoding(const System::UnicodeString AStr);
extern PACKAGE System::UnicodeString __fastcall DefEncodingToStr(Sbtypes::ByteArray ASrc);
extern PACKAGE System::UnicodeString __fastcall ComposeURL(const System::UnicodeString Protocol, const System::UnicodeString UserName, const System::UnicodeString Password, const System::UnicodeString Host, System::Word Port, const System::UnicodeString Path, const System::UnicodeString Anchor, const System::UnicodeString Parameters);
extern PACKAGE void __fastcall ParseURL(System::UnicodeString URL, bool SingleNameIsPage, System::UnicodeString &Protocol, System::UnicodeString &Username, System::UnicodeString &Password, System::UnicodeString &Host, System::Word &Port, System::UnicodeString &Path, System::UnicodeString &anchor, System::UnicodeString &Parameters)/* overload */;
extern PACKAGE void __fastcall ParseURL(System::UnicodeString URL, bool SingleNameIsPage, System::UnicodeString &Protocol, System::UnicodeString &Username, System::UnicodeString &Password, System::UnicodeString &Host, System::Word &Port, System::UnicodeString &Path, System::UnicodeString &anchor, System::UnicodeString &Parameters, const System::UnicodeString DefaultProtocol)/* overload */;
extern PACKAGE System::UnicodeString __fastcall SBExtractFilePath(const System::UnicodeString FileName);
extern PACKAGE System::UnicodeString __fastcall SBExtractFileName(const System::UnicodeString FileName);
extern PACKAGE System::UnicodeString __fastcall SBExtractFileExt(const System::UnicodeString FileName)/* overload */;
extern PACKAGE System::UnicodeString __fastcall SBExtractFileExt(const System::UnicodeString FileName, bool IncludeDot)/* overload */;
extern PACKAGE System::UnicodeString __fastcall ReplaceExt(const System::UnicodeString FileName, const System::UnicodeString NewExtension);
extern PACKAGE bool __fastcall FilenameMatchesMask(const System::UnicodeString Name, const System::UnicodeString Mask, bool CaseSensitive);
extern PACKAGE bool __fastcall DomainNameMatchesCertSN(System::UnicodeString DomainName, System::UnicodeString Match);
extern PACKAGE int __fastcall CountFoldersInPath(const System::UnicodeString Path);
extern PACKAGE Sbtypes::ByteArray __fastcall StrToUTF8(const System::UnicodeString AStr);
extern PACKAGE System::UnicodeString __fastcall UTF8ToStr(const Sbtypes::ByteArray ASrc);
extern PACKAGE Sbtypes::ByteArray __fastcall StrToWideStr(const System::UnicodeString AStr);
extern PACKAGE System::UnicodeString __fastcall WideStrToStr(const Sbtypes::ByteArray ASrc);
extern PACKAGE Sbtypes::ByteArray __fastcall UnicodeChangeEndianness(const Sbtypes::ByteArray Data);
extern PACKAGE System::UnicodeString __fastcall UTF8ToWideStr(const Sbtypes::ByteArray Buf)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall WideStrToUTF8(const System::UnicodeString AStr)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall WideStrToUTF8(const void *ASrc, int Size)/* overload */;
extern PACKAGE System::UnicodeString __fastcall UTF8ToWideStr(const void *Buf, int Size)/* overload */;
extern PACKAGE __int64 __fastcall StrMixToInt64(const System::UnicodeString S);
extern PACKAGE void __fastcall SetGlobalConverter(TElStringConverter* Converter);
extern PACKAGE void __fastcall SetDefaultCharset(const System::UnicodeString Charset);
extern PACKAGE Sbtypes::ConversionResult __fastcall ConvertUTF16toUTF8(const System::UnicodeString source, Sbtypes::ByteArray &target, Sbtypes::ConversionFlags flags, bool BOM);
extern PACKAGE Sbtypes::ConversionResult __fastcall ConvertUTF8toUTF16(const Sbtypes::ByteArray source, System::UnicodeString &target, Sbtypes::ConversionFlags flags, bool BOM);
extern PACKAGE bool __fastcall isLegalUTF8(const Sbtypes::ByteArray source, unsigned sourcelen);
extern PACKAGE Sbtypes::ByteArray __fastcall ConvertToUTF8String(const System::UnicodeString Source);
extern PACKAGE System::UnicodeString __fastcall ConvertFromUTF8String(const Sbtypes::ByteArray Source, bool CheckBOM = true);
extern PACKAGE System::UnicodeString __fastcall ConvertFromUTF32String(const Sbtypes::ByteArray Source, bool CheckBOM = true);
extern PACKAGE Sbtypes::ByteArray __fastcall SBTrim(const Sbtypes::ByteArray S);
extern PACKAGE Sbtypes::ByteArray __fastcall SBUppercase(const Sbtypes::ByteArray S);
extern PACKAGE Sbtypes::ByteArray __fastcall LowerCase(const Sbtypes::ByteArray s)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall UpperCase(const Sbtypes::ByteArray s)/* overload */;
extern PACKAGE bool __fastcall StringSplitPV(const System::UnicodeString S, /* out */ System::UnicodeString &Name, /* out */ System::UnicodeString &Value)/* overload */;
extern PACKAGE bool __fastcall StringSplitPV(const System::UnicodeString S, /* out */ System::UnicodeString &Name, /* out */ System::UnicodeString &Value, System::WideChar Separator)/* overload */;
extern PACKAGE Sbtypes::StringArray __fastcall StringSplit(const System::UnicodeString S, System::WideChar Separator)/* overload */;
extern PACKAGE Sbtypes::StringArray __fastcall StringSplit(const System::UnicodeString S, System::WideChar Separator, bool RemoveEmptyEntries)/* overload */;
extern PACKAGE int __fastcall SBPos(const System::AnsiString substr, const System::AnsiString str)/* overload */;
extern PACKAGE int __fastcall SBPos(const System::UnicodeString substr, const System::UnicodeString str)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall SBCopy(const Sbtypes::ByteArray str, int Offset, int Size)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall SBCopy(const Sbtypes::ByteArray str)/* overload */;
extern PACKAGE int __fastcall SBRightPos(const System::UnicodeString Substr, const System::UnicodeString Str);
extern PACKAGE System::UnicodeString __fastcall OIDToStr(const Sbtypes::ByteArray OID);
extern PACKAGE Sbtypes::ByteArray __fastcall StrToOID(const System::UnicodeString Str);
extern PACKAGE int __fastcall SBPos(const Sbtypes::ByteArray SubP, const Sbtypes::ByteArray P, int StartPos = 0x0)/* overload */;
extern PACKAGE int __fastcall SBPos(const System::UnicodeString SubP, const Sbtypes::ByteArray P, int StartPos = 0x0)/* overload */;
extern PACKAGE int __fastcall SBPos(System::Byte SubP, const Sbtypes::ByteArray P)/* overload */;
extern PACKAGE System::UnicodeString __fastcall ReplaceStr(const System::UnicodeString Source, System::UnicodeString Entry, System::UnicodeString ReplaceWith);
extern PACKAGE Sbtypes::ByteArray __fastcall PAnsiCharToByteArray(const char * P);
extern PACKAGE System::UnicodeString __fastcall PathFirstComponent(const System::UnicodeString Path);
extern PACKAGE System::UnicodeString __fastcall PathCutFirstComponent(const System::UnicodeString Path);
extern PACKAGE System::UnicodeString __fastcall PathCutLastComponent(const System::UnicodeString Path);
extern PACKAGE System::UnicodeString __fastcall PathLastComponent(const System::UnicodeString Path);
extern PACKAGE bool __fastcall PathIsDirectory(const System::UnicodeString Path);
extern PACKAGE System::UnicodeString __fastcall PathTrim(const System::UnicodeString Path);
extern PACKAGE System::UnicodeString __fastcall PathConcatenate(const System::UnicodeString Path1, const System::UnicodeString Path2);
extern PACKAGE System::UnicodeString __fastcall PathNormalizeSlashes(const System::UnicodeString Path);
extern PACKAGE System::UnicodeString __fastcall PathReverseSlashes(const System::UnicodeString Path);
extern PACKAGE bool __fastcall PathMatchesMask(const System::UnicodeString Path, const System::UnicodeString Mask)/* overload */;
extern PACKAGE bool __fastcall PathMatchesMask(const System::UnicodeString Path, const System::UnicodeString Mask, bool CaseSensitive)/* overload */;
extern PACKAGE bool __fastcall IsFileMask(const System::UnicodeString Path);
extern PACKAGE System::UnicodeString __fastcall ExtractPathFromMask(const System::UnicodeString Mask);
extern PACKAGE System::UnicodeString __fastcall ZipPathFirstComponent(const System::UnicodeString Path);
extern PACKAGE System::UnicodeString __fastcall ZipPathCutFirstComponent(const System::UnicodeString Path);
extern PACKAGE System::UnicodeString __fastcall ZipPathCutLastComponent(const System::UnicodeString Path);
extern PACKAGE System::UnicodeString __fastcall ZipPathLastComponent(const System::UnicodeString Path);
extern PACKAGE bool __fastcall ZipPathIsDirectory(const System::UnicodeString Path);
extern PACKAGE System::UnicodeString __fastcall ZipPathTrim(const System::UnicodeString Path);
extern PACKAGE System::UnicodeString __fastcall ZipPathConcatenate(const System::UnicodeString Path1, const System::UnicodeString Path2);
extern PACKAGE System::UnicodeString __fastcall ZipPathNormalizeSlashes(const System::UnicodeString Path);
extern PACKAGE System::UnicodeString __fastcall ZipPathReverseSlashes(const System::UnicodeString Path);
extern PACKAGE bool __fastcall ZipPathMatchesMask(const System::UnicodeString Path, const System::UnicodeString Mask)/* overload */;
extern PACKAGE bool __fastcall ZipPathMatchesMask(const System::UnicodeString Path, const System::UnicodeString Mask, bool CaseSensitive)/* overload */;
extern PACKAGE bool __fastcall ZipIsFileMask(const System::UnicodeString Path);
extern PACKAGE System::UnicodeString __fastcall ZipExtractPathFromMask(const System::UnicodeString Mask);
extern PACKAGE void __fastcall DecodeDateTime(const System::TDateTime AValue, /* out */ System::Word &AYear, /* out */ System::Word &AMonth, /* out */ System::Word &ADay, /* out */ System::Word &AHour, /* out */ System::Word &AMinute, /* out */ System::Word &ASecond, /* out */ System::Word &AMilliSecond);
extern PACKAGE void __fastcall TrimEx(System::AnsiString &S, bool bTrimLeft = true, bool bTrimRight = true)/* overload */;
extern PACKAGE void __fastcall TrimSemicolon(System::UnicodeString &S);
extern PACKAGE System::UnicodeString __fastcall IntToStrPadLeft(int Val, int iWidth = 0x0, System::WideChar chTemplate = (System::WideChar)(0x30));
extern PACKAGE System::UnicodeString __fastcall ExtractWideFileName(const System::UnicodeString FileName);
extern PACKAGE System::UnicodeString __fastcall ExtractWideFileExtension(const System::UnicodeString FileName);
extern PACKAGE System::AnsiString __fastcall ExtractFileExtension(const System::UnicodeString FileName);
extern PACKAGE int __fastcall WidePosEx(const System::UnicodeString SubStr, const System::UnicodeString S, int Offset, int Count);
extern PACKAGE int __fastcall PosExSafe(const System::AnsiString SubStr, const System::AnsiString S, int Offset, int Count);
extern PACKAGE int __fastcall PosLast(const System::AnsiString SubStr, const System::AnsiString S);
extern PACKAGE int __fastcall WidePosLast(const System::UnicodeString SubStr, const System::UnicodeString S);
extern PACKAGE System::UnicodeString __fastcall WideTrimRight(const System::UnicodeString S);
extern PACKAGE System::AnsiString __fastcall WideStringToByteString(const System::UnicodeString WS);
extern PACKAGE void __fastcall GetWideBytesOf(const System::UnicodeString Value, Sbtypes::ByteArray &B);
extern PACKAGE void __fastcall GetStringOf(const Sbtypes::ByteArray Bytes, System::AnsiString &S);
extern PACKAGE void __fastcall GetStringOfEx(const Sbtypes::ByteArray Bytes, System::AnsiString &S, __int64 LPos = 0x000000000, __int64 RPos = 0xffffffffffffffff);
extern PACKAGE void __fastcall GetWideStringOf(const Sbtypes::ByteArray Bytes, System::UnicodeString &WS);
extern PACKAGE System::UnicodeString __fastcall AnsiStringToByteWideString(const System::AnsiString S);
extern PACKAGE System::UnicodeString __fastcall UniversalDateTimeToRFC822DateTimeString(System::TDateTime DT);
extern PACKAGE bool __fastcall RFC822TimeStringToUniversalTime(System::UnicodeString TS, System::TDateTime &DT);
extern PACKAGE System::AnsiString __fastcall LocalDateTimeToRFC822DateTimeString(System::TDateTime ADateTime);
extern PACKAGE System::AnsiString __fastcall SystemDateTimeToRFC822DateTimeString(System::TDateTime ADateTime);
extern PACKAGE bool __fastcall ParseRFC822TimeString(System::UnicodeString RFC822TimeString, System::TDateTime &ADateTime);
extern PACKAGE System::AnsiString __fastcall SBConcatAnsiStrings(System::AnsiString Str1, char Str2)/* overload */;
extern PACKAGE System::AnsiString __fastcall SBConcatAnsiStrings(System::AnsiString Str1, System::AnsiString Str2)/* overload */;
extern PACKAGE System::AnsiString __fastcall SBConcatAnsiStrings(System::AnsiString const *Strs, const int Strs_Size)/* overload */;
extern PACKAGE System::AnsiString __fastcall AnsiStrPas(char * P);

}	/* namespace Sbstrutils */
using namespace Sbstrutils;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbstrutilsHPP
