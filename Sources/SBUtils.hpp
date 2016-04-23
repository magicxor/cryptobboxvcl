// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbutils.pas' rev: 21.00

#ifndef SbutilsHPP
#define SbutilsHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Types.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Windows.hpp>	// Pascal unit
#include <Syncobjs.hpp>	// Pascal unit
#include <Dateutils.hpp>	// Pascal unit
#include <Sbmath.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbutils
{
//-- type declarations -------------------------------------------------------
typedef bool TSBBoolean;

typedef Classes::TComponent TSBComponentBase;

typedef Classes::TComponent TSBControlBase;

typedef System::TObject TSBDisposableBase;

typedef Classes::TList TElList;

typedef Classes::TList TElIntegerList;

typedef Classes::TStringList TElStringList;

typedef StaticArray<Sbtypes::ByteArray, 134217728> TByteArrays;

typedef TByteArrays *PByteArrayItem;

class DELPHICLASS TElByteArrayList;
class PASCALIMPLEMENTATION TElByteArrayList : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	typedef DynamicArray<DynamicArray<System::Byte> > _TElByteArrayList__1;
	
	
protected:
	_TElByteArrayList__1 FList;
	int FCount;
	void __fastcall BMove(Sbtypes::ByteArray const *Src, const int Src_Size, int SrcOffset, Sbtypes::ByteArray *Dst, const int Dst_Size, int DstOffset, int Size);
	Sbtypes::ByteArray __fastcall GetItem(int Index);
	void __fastcall SetItem(int Index, const Sbtypes::ByteArray Value);
	void __fastcall SetCapacity(int NewCapacity);
	int __fastcall GetCapacity(void);
	int __fastcall GetCount(void);
	
public:
	__fastcall TElByteArrayList(void);
	__fastcall virtual ~TElByteArrayList(void);
	int __fastcall Add(const Sbtypes::ByteArray S);
	void __fastcall AddRange(TElByteArrayList* List);
	void __fastcall Assign(TElByteArrayList* Source);
	void __fastcall Clear(void);
	void __fastcall Delete(int Index);
	int __fastcall IndexOf(const Sbtypes::ByteArray S);
	void __fastcall Insert(int Index, const Sbtypes::ByteArray S);
	__property int Capacity = {read=GetCapacity, write=SetCapacity, nodefault};
	__property int Count = {read=GetCount, nodefault};
	__property Sbtypes::ByteArray Item[int Index] = {read=GetItem, write=SetItem};
};


typedef void __fastcall (__closure *TSBTextDataEvent)(System::TObject* Sender, const Sbtypes::ByteArray TextLine);

typedef void __fastcall (__closure *TSBProgressEvent)(System::TObject* Sender, __int64 Total, __int64 Current, bool &Cancel);

typedef void __fastcall (__closure *TSBProgressFunc)(__int64 Total, __int64 Current, void * Data, bool &Cancel);

typedef bool __fastcall (__closure *TElMessageLoopEvent)(void);

class DELPHICLASS ESecureBlackboxError;
class PASCALIMPLEMENTATION ESecureBlackboxError : public Sysutils::Exception
{
	typedef Sysutils::Exception inherited;
	
protected:
	int FErrorCode;
	int FSupplErrorCode;
	
public:
	__fastcall ESecureBlackboxError(const System::UnicodeString AMessage)/* overload */;
	__fastcall ESecureBlackboxError(int AErrorCode, const System::UnicodeString AMessage)/* overload */;
	__fastcall ESecureBlackboxError(int AErrorCode, int ASupplErrorCode, const System::UnicodeString AMessage)/* overload */;
	__fastcall ESecureBlackboxError(int AErrorCode, const System::UnicodeString AMessage, bool AInsertErrorCodeToMessage)/* overload */;
	__fastcall ESecureBlackboxError(int AErrorCode, const System::UnicodeString AMessageFormat, const System::UnicodeString Param1)/* overload */;
	__fastcall ESecureBlackboxError(int AErrorCode, const System::UnicodeString AMessageFormat, int Param1)/* overload */;
	__fastcall ESecureBlackboxError(int AErrorCode, const System::UnicodeString AMessageFormat, const System::UnicodeString Param1, int Param2)/* overload */;
	__fastcall ESecureBlackboxError(int AErrorCode, const System::UnicodeString AMessageFormat, int Param1, const System::UnicodeString Param2)/* overload */;
	__fastcall ESecureBlackboxError(int AErrorCode, const System::UnicodeString AMessageFormat, int Param1, int Param2)/* overload */;
	__fastcall ESecureBlackboxError(int AErrorCode, const System::UnicodeString AMessageFormat, const System::UnicodeString Param1, const System::UnicodeString Param2)/* overload */;
	__fastcall ESecureBlackboxError(int AErrorCode, int ASupplErrorCode, const System::UnicodeString AMessageFormat, const System::UnicodeString Param1)/* overload */;
	__fastcall ESecureBlackboxError(int AErrorCode, int ASupplErrorCode, const System::UnicodeString AMessageFormat, int Param1)/* overload */;
	__fastcall ESecureBlackboxError(int AErrorCode, int ASupplErrorCode, const System::UnicodeString AMessageFormat, int Param1, int Param2)/* overload */;
	__fastcall ESecureBlackboxError(const System::UnicodeString Message, int Code, int Fake)/* overload */;
	__fastcall ESecureBlackboxError(const System::UnicodeString Message, int Code, bool InsertCodeToErrorMessage, int Fake)/* overload */;
	__property int ErrorCode = {read=FErrorCode, nodefault};
	__property int SupplErrorCode = {read=FSupplErrorCode, nodefault};
public:
	/* Exception.CreateFmt */ inline __fastcall ESecureBlackboxError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sysutils::Exception(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall ESecureBlackboxError(int Ident)/* overload */ : Sysutils::Exception(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall ESecureBlackboxError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sysutils::Exception(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall ESecureBlackboxError(const System::UnicodeString Msg, int AHelpContext) : Sysutils::Exception(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall ESecureBlackboxError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sysutils::Exception(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall ESecureBlackboxError(int Ident, int AHelpContext)/* overload */ : Sysutils::Exception(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall ESecureBlackboxError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sysutils::Exception(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~ESecureBlackboxError(void) { }
	
};


class DELPHICLASS EElLicenseError;
class PASCALIMPLEMENTATION EElLicenseError : public ESecureBlackboxError
{
	typedef ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElLicenseError(const System::UnicodeString AMessage)/* overload */ : ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElLicenseError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElLicenseError(int Ident)/* overload */ : ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElLicenseError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElLicenseError(const System::UnicodeString Msg, int AHelpContext) : ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElLicenseError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElLicenseError(int Ident, int AHelpContext)/* overload */ : ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElLicenseError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElLicenseError(void) { }
	
};


class DELPHICLASS EElEncryptionError;
class PASCALIMPLEMENTATION EElEncryptionError : public ESecureBlackboxError
{
	typedef ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElEncryptionError(const System::UnicodeString AMessage)/* overload */ : ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElEncryptionError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElEncryptionError(int Ident)/* overload */ : ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElEncryptionError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElEncryptionError(const System::UnicodeString Msg, int AHelpContext) : ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElEncryptionError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElEncryptionError(int Ident, int AHelpContext)/* overload */ : ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElEncryptionError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElEncryptionError(void) { }
	
};


class DELPHICLASS EElCertificateError;
class PASCALIMPLEMENTATION EElCertificateError : public ESecureBlackboxError
{
	typedef ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElCertificateError(const System::UnicodeString AMessage)/* overload */ : ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElCertificateError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElCertificateError(int Ident)/* overload */ : ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElCertificateError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElCertificateError(const System::UnicodeString Msg, int AHelpContext) : ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElCertificateError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElCertificateError(int Ident, int AHelpContext)/* overload */ : ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElCertificateError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElCertificateError(void) { }
	
};


class DELPHICLASS EElOIDError;
class PASCALIMPLEMENTATION EElOIDError : public ESecureBlackboxError
{
	typedef ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElOIDError(const System::UnicodeString AMessage)/* overload */ : ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElOIDError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElOIDError(int Ident)/* overload */ : ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElOIDError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElOIDError(const System::UnicodeString Msg, int AHelpContext) : ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElOIDError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElOIDError(int Ident, int AHelpContext)/* overload */ : ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElOIDError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElOIDError(void) { }
	
};


class DELPHICLASS EElUnicodeError;
class PASCALIMPLEMENTATION EElUnicodeError : public ESecureBlackboxError
{
	typedef ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElUnicodeError(const System::UnicodeString AMessage)/* overload */ : ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElUnicodeError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElUnicodeError(int Ident)/* overload */ : ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElUnicodeError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElUnicodeError(const System::UnicodeString Msg, int AHelpContext) : ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElUnicodeError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElUnicodeError(int Ident, int AHelpContext)/* overload */ : ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElUnicodeError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElUnicodeError(void) { }
	
};


class DELPHICLASS EElOperationCancelledError;
class PASCALIMPLEMENTATION EElOperationCancelledError : public ESecureBlackboxError
{
	typedef ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElOperationCancelledError(const System::UnicodeString AMessage)/* overload */ : ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElOperationCancelledError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElOperationCancelledError(int Ident)/* overload */ : ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElOperationCancelledError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElOperationCancelledError(const System::UnicodeString Msg, int AHelpContext) : ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElOperationCancelledError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElOperationCancelledError(int Ident, int AHelpContext)/* overload */ : ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElOperationCancelledError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElOperationCancelledError(void) { }
	
};


class DELPHICLASS TSBObjectList;
class PASCALIMPLEMENTATION TSBObjectList : public Classes::TList
{
	typedef Classes::TList inherited;
	
public:
	System::TObject* operator[](int Index) { return Items[Index]; }
	
private:
	bool FOwnsObjects;
	
protected:
	virtual void __fastcall Notify(void * Ptr, Classes::TListNotification Action);
	System::TObject* __fastcall GetItem(int Index);
	void __fastcall SetItem(int Index, System::TObject* AObject);
	
public:
	__fastcall TSBObjectList(void)/* overload */;
	__fastcall TSBObjectList(bool AOwnsObjects)/* overload */;
	HIDESBASE int __fastcall Add(System::TObject* AObject);
	HIDESBASE int __fastcall Remove(System::TObject* AObject);
	HIDESBASE int __fastcall IndexOf(System::TObject* AObject);
	HIDESBASE void __fastcall Insert(int Index, System::TObject* AObject);
	int __fastcall FindInstanceOf(System::TClass AClass, bool AExact = true, int AStartAt = 0x0);
	HIDESBASE System::TObject* __fastcall Extract(System::TObject* Item);
	__property bool OwnsObjects = {read=FOwnsObjects, write=FOwnsObjects, nodefault};
	__property System::TObject* Items[int Index] = {read=GetItem, write=SetItem/*, default*/};
public:
	/* TList.Destroy */ inline __fastcall virtual ~TSBObjectList(void) { }
	
};


//-- var, const, procedure ---------------------------------------------------
#define SBB_VERSION_NUMBER L"12.0.258.0"
#define SBB_HOMEPAGE L"https://www.eldos.com/SecureBlackbox/"
#define COREDLL L"coredll.dll"
#define OLE32 L"ole32.dll"
#define KERNEL32 L"kernel32.dll"
#define NTDLL L"ntdll.dll"
extern PACKAGE _RTL_CRITICAL_SECTION *GlobalLockCS;
extern PACKAGE int GlobalLockCSFlag;
extern PACKAGE Classes::TList* GlobalObjectList;
extern PACKAGE System::ResourceString _SRegexUnsupported;
#define Sbutils_SRegexUnsupported System::LoadResourceString(&Sbutils::_SRegexUnsupported)
extern PACKAGE System::ResourceString _SInvalidInputSize;
#define Sbutils_SInvalidInputSize System::LoadResourceString(&Sbutils::_SInvalidInputSize)
extern PACKAGE System::ResourceString _SInvalidKeySize;
#define Sbutils_SInvalidKeySize System::LoadResourceString(&Sbutils::_SInvalidKeySize)
extern PACKAGE System::ResourceString _SInvalidUInt16BufferOffset;
#define Sbutils_SInvalidUInt16BufferOffset System::LoadResourceString(&Sbutils::_SInvalidUInt16BufferOffset)
extern PACKAGE System::ResourceString _SInvalidUInt32BufferOffset;
#define Sbutils_SInvalidUInt32BufferOffset System::LoadResourceString(&Sbutils::_SInvalidUInt32BufferOffset)
extern PACKAGE System::ResourceString _SInvalidOID;
#define Sbutils_SInvalidOID System::LoadResourceString(&Sbutils::_SInvalidOID)
extern PACKAGE System::ResourceString _sOutputBufferTooSmall;
#define Sbutils_sOutputBufferTooSmall System::LoadResourceString(&Sbutils::_sOutputBufferTooSmall)
extern PACKAGE System::ResourceString _SUnicodeNotInitialized;
#define Sbutils_SUnicodeNotInitialized System::LoadResourceString(&Sbutils::_SUnicodeNotInitialized)
extern PACKAGE System::ResourceString _SUnsupportedCharset;
#define Sbutils_SUnsupportedCharset System::LoadResourceString(&Sbutils::_SUnsupportedCharset)
extern PACKAGE System::ResourceString _SOperationCancelled;
#define Sbutils_SOperationCancelled System::LoadResourceString(&Sbutils::_SOperationCancelled)
extern PACKAGE System::ResourceString _SLicenseKeyNotSet;
#define Sbutils_SLicenseKeyNotSet System::LoadResourceString(&Sbutils::_SLicenseKeyNotSet)
extern PACKAGE System::ResourceString _SInvalidDateToken;
#define Sbutils_SInvalidDateToken System::LoadResourceString(&Sbutils::_SInvalidDateToken)
extern PACKAGE System::ResourceString _SInvalidTimeToken;
#define Sbutils_SInvalidTimeToken System::LoadResourceString(&Sbutils::_SInvalidTimeToken)
extern PACKAGE System::ResourceString _SOldLicenseKey;
#define Sbutils_SOldLicenseKey System::LoadResourceString(&Sbutils::_SOldLicenseKey)
extern PACKAGE System::ResourceString _SUnknownLicenseKey;
#define Sbutils_SUnknownLicenseKey System::LoadResourceString(&Sbutils::_SUnknownLicenseKey)
extern PACKAGE System::ResourceString _SLicenseKeyExpired;
#define Sbutils_SLicenseKeyExpired System::LoadResourceString(&Sbutils::_SLicenseKeyExpired)
extern PACKAGE System::ResourceString _SLicenseTypeNotEnabled;
#define Sbutils_SLicenseTypeNotEnabled System::LoadResourceString(&Sbutils::_SLicenseTypeNotEnabled)
extern PACKAGE System::ResourceString _SBadOrOldLicenseKey;
#define Sbutils_SBadOrOldLicenseKey System::LoadResourceString(&Sbutils::_SBadOrOldLicenseKey)
extern PACKAGE System::ResourceString _SAutomaticKeyExpired;
#define Sbutils_SAutomaticKeyExpired System::LoadResourceString(&Sbutils::_SAutomaticKeyExpired)
extern PACKAGE System::ResourceString _SSeekOffsetRangeError;
#define Sbutils_SSeekOffsetRangeError System::LoadResourceString(&Sbutils::_SSeekOffsetRangeError)
extern PACKAGE System::ResourceString _SBase32InvalidDataSize;
#define Sbutils_SBase32InvalidDataSize System::LoadResourceString(&Sbutils::_SBase32InvalidDataSize)
extern PACKAGE System::ResourceString _SBase32InvalidData;
#define Sbutils_SBase32InvalidData System::LoadResourceString(&Sbutils::_SBase32InvalidData)
extern PACKAGE unsigned __fastcall TickDiff(unsigned Previous, unsigned Current);
extern PACKAGE System::UnicodeString __fastcall StringOfBytes(const Sbtypes::ByteArray Src)/* overload */;
extern PACKAGE System::UnicodeString __fastcall StringOfBytes(const Sbtypes::ByteArray Src, int ALow, int ALen)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall BytesOfString(const System::UnicodeString Str)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall GetByteArrayFromByte(System::Byte Value)/* overload */;
extern PACKAGE void __fastcall GetByteArrayFromByte(System::Byte Value, Sbtypes::ByteArray Dest, int Position)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall GetByteArrayFromWordLE(System::Word Value)/* overload */;
extern PACKAGE void __fastcall GetByteArrayFromWordLE(System::Word Value, Sbtypes::ByteArray Dest, int Position)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall GetByteArrayFromWordBE(System::Word Value)/* overload */;
extern PACKAGE void __fastcall GetByteArrayFromWordBE(System::Word Value, Sbtypes::ByteArray Dest, int Position)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall GetByteArrayFromDWordLE(unsigned Value)/* overload */;
extern PACKAGE void __fastcall GetByteArrayFromDWordLE(unsigned Value, Sbtypes::ByteArray Dest, int Position)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall GetByteArrayFromDWordBE(unsigned Value)/* overload */;
extern PACKAGE void __fastcall GetByteArrayFromDWordBE(unsigned Value, Sbtypes::ByteArray Dest, int Position)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall GetByteArrayFromInt64LE(__int64 Value)/* overload */;
extern PACKAGE void __fastcall GetByteArrayFromInt64LE(__int64 Value, Sbtypes::ByteArray Dest, int Position)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall GetByteArrayFromInt64BE(__int64 Value)/* overload */;
extern PACKAGE void __fastcall GetByteArrayFromInt64BE(__int64 Value, Sbtypes::ByteArray Dest, int Position)/* overload */;
extern PACKAGE System::Word __fastcall GetWordLEFromByteArray(Sbtypes::ByteArray Source, int Position)/* overload */;
extern PACKAGE System::Word __fastcall GetWordBEFromByteArray(Sbtypes::ByteArray Source, int Position)/* overload */;
extern PACKAGE unsigned __fastcall GetDWordLEFromByteArray(Sbtypes::ByteArray Source, int Position)/* overload */;
extern PACKAGE unsigned __fastcall GetDWordBEFromByteArray(Sbtypes::ByteArray Source, int Position)/* overload */;
extern PACKAGE __int64 __fastcall GetInt64LEFromByteArray(Sbtypes::ByteArray Source, int Position)/* overload */;
extern PACKAGE __int64 __fastcall GetInt64BEFromByteArray(Sbtypes::ByteArray Source, int Position)/* overload */;
extern PACKAGE System::AnsiString __fastcall EmptyAnsiString(void);
extern PACKAGE Sbtypes::ByteArray __fastcall CloneArray(const Sbtypes::ByteArray Arr, int StartIndex, int Count)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall CloneArray(void * Buffer, int Size)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall CloneArray(const Sbtypes::ByteArray Arr)/* overload */;
extern PACKAGE Sbtypes::IntegerArray __fastcall CloneArray(const Sbtypes::IntegerArray Arr)/* overload */;
extern PACKAGE Sbtypes::LongWordArray __fastcall CloneArray(const Sbtypes::LongWordArray Arr)/* overload */;
extern PACKAGE Sbtypes::StringArray __fastcall CloneArray(const Sbtypes::StringArray Arr)/* overload */;
extern PACKAGE bool __fastcall ArrayEndsWith(const Sbtypes::ByteArray Buffer, const Sbtypes::ByteArray Substr);
extern PACKAGE int __fastcall SwapInt32(int value);
extern PACKAGE void __fastcall SwapUInt16(System::Word Value, Sbtypes::ByteArray &Buffer)/* overload */;
extern PACKAGE void __fastcall SwapUInt16(System::Word Value, Sbtypes::ByteArray &Buffer, int &Index)/* overload */;
extern PACKAGE System::Word __fastcall SwapUInt16(const Sbtypes::ByteArray Buffer, unsigned Offset = (unsigned)(0x0))/* overload */;
extern PACKAGE unsigned __fastcall SwapUInt32(unsigned value)/* overload */;
extern PACKAGE void __fastcall SwapUInt32(unsigned Value, Sbtypes::ByteArray &Buffer)/* overload */;
extern PACKAGE void __fastcall SwapUInt32(unsigned Value, Sbtypes::ByteArray &Buffer, int &Index)/* overload */;
extern PACKAGE unsigned __fastcall SwapUInt32(const Sbtypes::ByteArray Buffer, unsigned Offset = (unsigned)(0x0))/* overload */;
extern PACKAGE __int64 __fastcall SwapInt64(__int64 value);
extern PACKAGE Sbtypes::ByteArray __fastcall SwapSomeInt(int Value);
extern PACKAGE Sbtypes::ByteArray __fastcall RotateInteger(const Sbtypes::ByteArray Value);
extern PACKAGE Sbtypes::ByteArray __fastcall TrimZeros(const Sbtypes::ByteArray Value)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall ZeroArray(int Size);
extern PACKAGE Sbtypes::ByteArray __fastcall SubArray(const Sbtypes::ByteArray Arr, int Index, int Size);
extern PACKAGE bool __fastcall StrToDigest(const System::UnicodeString DigestStr, Sbtypes::TMessageDigest128 &Digest)/* overload */;
extern PACKAGE bool __fastcall StrToDigest(const System::UnicodeString DigestStr, Sbtypes::TMessageDigest160 &Digest)/* overload */;
extern PACKAGE System::UnicodeString __fastcall DigestToStr(const Sbtypes::TMessageDigest128 &Digest, bool LowerCase = true)/* overload */;
extern PACKAGE System::UnicodeString __fastcall DigestToStr(const Sbtypes::TMessageDigest160 &Digest, bool LowerCase = true)/* overload */;
extern PACKAGE System::UnicodeString __fastcall DigestToStr(const Sbtypes::TMessageDigest224 &Digest, bool LowerCase = true)/* overload */;
extern PACKAGE System::UnicodeString __fastcall DigestToStr(const Sbtypes::TMessageDigest256 &Digest, bool LowerCase = true)/* overload */;
extern PACKAGE System::UnicodeString __fastcall DigestToStr(const Sbtypes::TMessageDigest320 &Digest, bool LowerCase = true)/* overload */;
extern PACKAGE System::UnicodeString __fastcall DigestToStr(const Sbtypes::TMessageDigest384 &Digest, bool LowerCase = true)/* overload */;
extern PACKAGE System::UnicodeString __fastcall DigestToStr(const Sbtypes::TMessageDigest512 &Digest, bool LowerCase = true)/* overload */;
extern PACKAGE System::UnicodeString __fastcall BeautifyBinaryString(const System::UnicodeString Str, System::WideChar Separator);
extern PACKAGE int __fastcall Min(const int A, const int B)/* overload */;
extern PACKAGE unsigned __fastcall Min(const unsigned A, const unsigned B)/* overload */;
extern PACKAGE __int64 __fastcall Min(const __int64 A, const __int64 B)/* overload */;
extern PACKAGE int __fastcall Max(const int A, const int B)/* overload */;
extern PACKAGE unsigned __fastcall Max(const unsigned A, const unsigned B)/* overload */;
extern PACKAGE __int64 __fastcall Max(const __int64 A, const __int64 B)/* overload */;
extern PACKAGE int __fastcall BufferBitCount(void * Buffer, int Size);
extern PACKAGE void __fastcall PointerToLInt(Sbmath::PLInt &B, const Sbtypes::ByteArray P, int Size)/* overload */;
extern PACKAGE void __fastcall PointerToLIntP(Sbmath::PLInt &B, void * P, int Size)/* overload */;
extern PACKAGE void __fastcall LIntToPointerP(Sbmath::PLInt B, void * P, int &Size)/* overload */;
extern PACKAGE void __fastcall LIntToPointer(Sbmath::PLInt B, Sbtypes::ByteArray P, int &Size)/* overload */;
extern PACKAGE void __fastcall LIntToPointerTrunc(Sbmath::PLInt B, void * P, int &Size);
extern PACKAGE bool __fastcall DecodeDSASignature(void * Blob, int Size, void * R, int &RSize, void * S, int &SSize);
extern PACKAGE bool __fastcall EncodeDSASignature(void * R, int RSize, void * S, int SSize, void * Blob, int &BlobSize);
extern PACKAGE bool __fastcall IsEmptyDateTime(System::TDateTime DT);
extern PACKAGE System::TDateTime __fastcall EmptyDateTime(void);
extern PACKAGE void __fastcall SBMove(const void *SourcePointer, void *DestinationPointer, int CopyCount)/* overload */;
extern PACKAGE void __fastcall SBMove(Sbtypes::ByteArray Src, int SrcOffset, Sbtypes::ByteArray Dst, int DstOffset, int Size)/* overload */;
extern PACKAGE bool __fastcall CompareMem(const Sbtypes::ByteArray Mem1, const Sbtypes::ByteArray Mem2)/* overload */;
extern PACKAGE bool __fastcall CompareMem(const void * Mem1, const void * Mem2, int Size)/* overload */;
extern PACKAGE bool __fastcall CompareMem(const Sbtypes::ByteArray Mem1, int Offset1, const Sbtypes::ByteArray Mem2, int Offset2)/* overload */;
extern PACKAGE bool __fastcall CompareMem(const Sbtypes::ByteArray Mem1, int Offset1, const Sbtypes::ByteArray Mem2, int Offset2, int Size)/* overload */;
extern PACKAGE System::UnicodeString __fastcall BinaryToString(const Sbtypes::ByteArray Buffer, int Start, int Count)/* overload */;
extern PACKAGE System::UnicodeString __fastcall BinaryToString(void * Buffer, int BufSize)/* overload */;
extern PACKAGE System::UnicodeString __fastcall BinaryToString(const Sbtypes::ByteArray Buffer)/* overload */;
extern PACKAGE bool __fastcall StringToBinary(const System::UnicodeString S, void * Buffer, int &Size);
extern PACKAGE void __fastcall SwapBigEndianWords(void * P, int Size);
extern PACKAGE void __fastcall SwapBigEndianDWords(void * P, int Size);
extern PACKAGE bool __fastcall BinaryToDigest(const Sbtypes::ByteArray Binary, Sbtypes::TMessageDigest128 &Digest)/* overload */;
extern PACKAGE bool __fastcall BinaryToDigest(const Sbtypes::ByteArray Binary, Sbtypes::TMessageDigest160 &Digest)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall DigestToBinary(const Sbtypes::TMessageDigest128 &Digest)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall DigestToBinary(const Sbtypes::TMessageDigest160 &Digest)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall DigestToByteArray128(const Sbtypes::TMessageDigest128 &Digest);
extern PACKAGE Sbtypes::ByteArray __fastcall DigestToByteArray160(const Sbtypes::TMessageDigest160 &Digest);
extern PACKAGE Sbtypes::ByteArray __fastcall DigestToByteArray224(const Sbtypes::TMessageDigest224 &Digest);
extern PACKAGE Sbtypes::ByteArray __fastcall DigestToByteArray256(const Sbtypes::TMessageDigest256 &Digest);
extern PACKAGE Sbtypes::ByteArray __fastcall DigestToByteArray320(const Sbtypes::TMessageDigest320 &Digest);
extern PACKAGE Sbtypes::ByteArray __fastcall DigestToByteArray384(const Sbtypes::TMessageDigest384 &Digest);
extern PACKAGE Sbtypes::ByteArray __fastcall DigestToByteArray512(const Sbtypes::TMessageDigest512 &Digest);
extern PACKAGE bool __fastcall ByteArrayToDigest128(const Sbtypes::ByteArray Binary, int Position, Sbtypes::TMessageDigest128 &Digest);
extern PACKAGE bool __fastcall ByteArrayToDigest160(const Sbtypes::ByteArray Binary, int Position, Sbtypes::TMessageDigest160 &Digest);
extern PACKAGE bool __fastcall ByteArrayToDigest224(const Sbtypes::ByteArray Binary, int Position, Sbtypes::TMessageDigest224 &Digest);
extern PACKAGE bool __fastcall ByteArrayToDigest256(const Sbtypes::ByteArray Binary, int Position, Sbtypes::TMessageDigest256 &Digest);
extern PACKAGE bool __fastcall ByteArrayToDigest320(const Sbtypes::ByteArray Binary, int Position, Sbtypes::TMessageDigest320 &Digest);
extern PACKAGE bool __fastcall ByteArrayToDigest384(const Sbtypes::ByteArray Binary, int Position, Sbtypes::TMessageDigest384 &Digest);
extern PACKAGE bool __fastcall ByteArrayToDigest512(const Sbtypes::ByteArray Binary, int Position, Sbtypes::TMessageDigest512 &Digest);
extern PACKAGE System::TDateTime __fastcall UTCTimeToDate(const System::UnicodeString UTCTime, bool FourDigitYear = false);
extern PACKAGE System::TDateTime __fastcall UTCTimeToTime(const System::UnicodeString UTCTime, bool FourDigitYear = false);
extern PACKAGE System::TDateTime __fastcall UTCTimeToDateTime(const System::UnicodeString UTCTime, bool FourDigitYear = false);
extern PACKAGE System::TDateTime __fastcall GeneralizedTimeToDate(const System::UnicodeString GenTime);
extern PACKAGE System::TDateTime __fastcall GeneralizedTimeToTime(const System::UnicodeString GenTime);
extern PACKAGE System::TDateTime __fastcall GeneralizedTimeToDateTime(const System::UnicodeString GenTime);
extern PACKAGE System::UnicodeString __fastcall DateTimeToUTCTime(const System::TDateTime ADateTime, bool FourDigitYear = false);
extern PACKAGE System::UnicodeString __fastcall DateTimeToGeneralizedTime(const System::TDateTime ADateTime);
extern PACKAGE System::TDateTime __fastcall UTCTimeToLocalTime(System::TDateTime UtcTime);
extern PACKAGE System::TDateTime __fastcall LocalTimeToUTCTime(System::TDateTime LocalTime);
extern PACKAGE System::TDateTime __fastcall GetUTCOffsetDateTime(void);
extern PACKAGE System::TDateTime __fastcall LocalDateTimeToSystemDateTime(System::TDateTime ADateTime);
extern PACKAGE System::TDateTime __fastcall SystemDateTimeToLocalDateTime(System::TDateTime ADateTime);
extern PACKAGE System::TDateTime __fastcall UTCNow(void);
extern PACKAGE System::TDateTime __fastcall FileTimeToDateTime(const _FILETIME &Value);
extern PACKAGE _FILETIME __fastcall DateTimeToFileTime(System::TDateTime Value);
extern PACKAGE System::TDateTime __fastcall UnixTimeToDateTime(__int64 Value);
extern PACKAGE __int64 __fastcall DateTimeToUnixTime(System::TDateTime Value);
extern PACKAGE void __fastcall RegisterGlobalObject(System::TObject* O);
extern PACKAGE void __fastcall UnregisterGlobalObject(System::TObject* O);
extern PACKAGE void __fastcall AcquireGlobalLock(void);
extern PACKAGE void __fastcall ReleaseGlobalLock(void);
extern PACKAGE void __fastcall CleanupRegisteredGlobalObjects(void);
extern PACKAGE bool __fastcall CompareMD128(const Sbtypes::TMessageDigest128 &M1, const Sbtypes::TMessageDigest128 &M2);
extern PACKAGE bool __fastcall CompareMD160(const Sbtypes::TMessageDigest160 &M1, const Sbtypes::TMessageDigest160 &M2);
extern PACKAGE bool __fastcall CompareMD224(const Sbtypes::TMessageDigest224 &M1, const Sbtypes::TMessageDigest224 &M2);
extern PACKAGE bool __fastcall CompareMD256(const Sbtypes::TMessageDigest256 &M1, const Sbtypes::TMessageDigest256 &M2);
extern PACKAGE bool __fastcall CompareMD320(const Sbtypes::TMessageDigest320 &M1, const Sbtypes::TMessageDigest320 &M2);
extern PACKAGE bool __fastcall CompareMD384(const Sbtypes::TMessageDigest384 &M1, const Sbtypes::TMessageDigest384 &M2);
extern PACKAGE bool __fastcall CompareMD512(const Sbtypes::TMessageDigest512 &M1, const Sbtypes::TMessageDigest512 &M2);
extern PACKAGE bool __fastcall CompareAnsiStr(const System::AnsiString Content, const System::AnsiString OID);
extern PACKAGE bool __fastcall CompareContent(const Sbtypes::ByteArray Content, const Sbtypes::ByteArray OID)/* overload */;
extern PACKAGE bool __fastcall CompareHashes(const Sbtypes::ByteArray Hash1, const Sbtypes::ByteArray Hash2)/* overload */;
extern PACKAGE bool __fastcall CompareHashes(const Sbtypes::ByteArray Hash1, int StartIndex1, int Count1, const Sbtypes::ByteArray Hash2, int StartIndex2, int Count2)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall ChangeByteOrder(const Sbtypes::ByteArray Buffer);
extern PACKAGE Sbtypes::ByteArray __fastcall EmptyArray(void);
extern PACKAGE Sbtypes::ByteArray __fastcall SBConcatArrays(const Sbtypes::ByteArray Buf1, const Sbtypes::ByteArray Buf2)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall SBConcatArrays(const Sbtypes::ByteArray Buf1, const Sbtypes::ByteArray Buf2, const Sbtypes::ByteArray Buf3)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall SBConcatArrays(const System::Byte Buf1, Sbtypes::ByteArray Buf2)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall SBConcatArrays(const System::Byte Buf1, const System::Byte Buf2, Sbtypes::ByteArray Buf3)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall SBConcatArrays(const Sbtypes::ByteArray Buf1, System::Byte Buf2)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall SBConcatArrays(const System::Byte Buf1, Sbtypes::ByteArray Buf2, Sbtypes::ByteArray Buf3)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall SBConcatMultipleArrays(Sbtypes::ByteArray const *Arrays, const int Arrays_Size)/* overload */;
extern PACKAGE void __fastcall FreeAndNil(void *Obj);
extern PACKAGE bool __fastcall CompareGUID(const GUID &Guid1, const GUID &Guid2);
extern PACKAGE System::UnicodeString __fastcall GenerateGUID(void);
extern PACKAGE void __fastcall ReleaseString(System::AnsiString &S)/* overload */;
extern PACKAGE void __fastcall ReleaseString(System::AnsiString &S, bool Zeroize)/* overload */;
extern PACKAGE void __fastcall ReleaseString(System::UnicodeString &S)/* overload */;
extern PACKAGE void __fastcall ReleaseString(System::UnicodeString &S, bool Zeroize)/* overload */;
extern PACKAGE void __fastcall ReleaseArray(Sbtypes::ByteArray &aBytes)/* overload */;
extern PACKAGE void __fastcall ReleaseArray(Sbtypes::ByteArray &aBytes, bool Zeroize)/* overload */;
extern PACKAGE void __fastcall ReleaseArray(Sbtypes::WordArray &aWords)/* overload */;
extern PACKAGE void __fastcall ReleaseArray(Sbtypes::WordArray &aWords, bool Zeroize)/* overload */;
extern PACKAGE void __fastcall ReleaseArray(Sbtypes::IntegerArray &aIntegers)/* overload */;
extern PACKAGE void __fastcall ReleaseArray(Sbtypes::IntegerArray &aIntegers, bool Zeroize)/* overload */;
extern PACKAGE void __fastcall ReleaseArray(Sbtypes::LongWordArray &aLongWords)/* overload */;
extern PACKAGE void __fastcall ReleaseArray(Sbtypes::LongWordArray &aLongWords, bool Zeroize)/* overload */;
extern PACKAGE void __fastcall ReleaseArray(Sbtypes::Int64Array &aInt64s)/* overload */;
extern PACKAGE void __fastcall ReleaseArray(Sbtypes::Int64Array &aInt64s, bool Zeroize)/* overload */;
extern PACKAGE void __fastcall ReleaseArray(Sbtypes::ArrayOfByteArray &aByteArrays)/* overload */;
extern PACKAGE void __fastcall ReleaseArray(Sbtypes::CharArray &aChars)/* overload */;
extern PACKAGE void __fastcall ReleaseArray(Sbtypes::CharArray &aChars, bool Zeroize)/* overload */;
extern PACKAGE void __fastcall ReleaseArray(Sbtypes::BooleanArray &aBooleans)/* overload */;
extern PACKAGE void __fastcall ReleaseArray(Sbtypes::BooleanArray &aBooleans, bool Zeroize)/* overload */;
extern PACKAGE void __fastcall ReleaseArray(Sbtypes::StringArray &aStrings)/* overload */;
extern PACKAGE void __fastcall ReleaseArray(Sbtypes::StringArray &aStrings, bool Zeroize)/* overload */;
extern PACKAGE void __fastcall ReleaseArrays(Sbtypes::ByteArray &A1, Sbtypes::ByteArray &A2)/* overload */;
extern PACKAGE void __fastcall ReleaseArrays(Sbtypes::ByteArray &A1, Sbtypes::ByteArray &A2, bool Zeroize)/* overload */;
extern PACKAGE void __fastcall ReleaseArrays(Sbtypes::ByteArray &A1, Sbtypes::ByteArray &A2, Sbtypes::ByteArray &A3)/* overload */;
extern PACKAGE void __fastcall ReleaseArrays(Sbtypes::ByteArray &A1, Sbtypes::ByteArray &A2, Sbtypes::ByteArray &A3, bool Zeroize)/* overload */;
extern PACKAGE void __fastcall ReleaseArrays(Sbtypes::ByteArray &A1, Sbtypes::ByteArray &A2, Sbtypes::ByteArray &A3, Sbtypes::ByteArray &A4)/* overload */;
extern PACKAGE void __fastcall ReleaseArrays(Sbtypes::ByteArray &A1, Sbtypes::ByteArray &A2, Sbtypes::ByteArray &A3, Sbtypes::ByteArray &A4, bool Zeroize)/* overload */;
extern PACKAGE void __fastcall ReleaseArrays(Sbtypes::ByteArray &A1, Sbtypes::ByteArray &A2, Sbtypes::ByteArray &A3, Sbtypes::ByteArray &A4, Sbtypes::ByteArray &A5)/* overload */;
extern PACKAGE void __fastcall ReleaseArrays(Sbtypes::ByteArray &A1, Sbtypes::ByteArray &A2, Sbtypes::ByteArray &A3, Sbtypes::ByteArray &A4, Sbtypes::ByteArray &A5, bool Zeroize)/* overload */;
extern PACKAGE void __fastcall ReleaseArrays(Sbtypes::ByteArray &A1, Sbtypes::ByteArray &A2, Sbtypes::ByteArray &A3, Sbtypes::ByteArray &A4, Sbtypes::ByteArray &A5, Sbtypes::ByteArray &A6)/* overload */;
extern PACKAGE void __fastcall ReleaseArrays(Sbtypes::ByteArray &A1, Sbtypes::ByteArray &A2, Sbtypes::ByteArray &A3, Sbtypes::ByteArray &A4, Sbtypes::ByteArray &A5, Sbtypes::ByteArray &A6, bool Zeroize)/* overload */;
extern PACKAGE void __fastcall ReleaseArrays(Sbtypes::ByteArray &A1, Sbtypes::ByteArray &A2, Sbtypes::ByteArray &A3, Sbtypes::ByteArray &A4, Sbtypes::ByteArray &A5, Sbtypes::ByteArray &A6, Sbtypes::ByteArray &A7)/* overload */;
extern PACKAGE void __fastcall ReleaseArrays(Sbtypes::ByteArray &A1, Sbtypes::ByteArray &A2, Sbtypes::ByteArray &A3, Sbtypes::ByteArray &A4, Sbtypes::ByteArray &A5, Sbtypes::ByteArray &A6, Sbtypes::ByteArray &A7, bool Zeroize)/* overload */;
extern PACKAGE void __fastcall ReleaseArrays(Sbtypes::ByteArray &A1, Sbtypes::ByteArray &A2, Sbtypes::ByteArray &A3, Sbtypes::ByteArray &A4, Sbtypes::ByteArray &A5, Sbtypes::ByteArray &A6, Sbtypes::ByteArray &A7, Sbtypes::ByteArray &A8)/* overload */;
extern PACKAGE void __fastcall ReleaseArrays(Sbtypes::ByteArray &A1, Sbtypes::ByteArray &A2, Sbtypes::ByteArray &A3, Sbtypes::ByteArray &A4, Sbtypes::ByteArray &A5, Sbtypes::ByteArray &A6, Sbtypes::ByteArray &A7, Sbtypes::ByteArray &A8, bool Zeroize)/* overload */;
extern PACKAGE void __fastcall ReleaseArrays(Sbtypes::ByteArray &A1, Sbtypes::ByteArray &A2, Sbtypes::ByteArray &A3, Sbtypes::ByteArray &A4, Sbtypes::ByteArray &A5, Sbtypes::ByteArray &A6, Sbtypes::ByteArray &A7, Sbtypes::ByteArray &A8, Sbtypes::ByteArray &A9)/* overload */;
extern PACKAGE void __fastcall ReleaseArrays(Sbtypes::ByteArray &A1, Sbtypes::ByteArray &A2, Sbtypes::ByteArray &A3, Sbtypes::ByteArray &A4, Sbtypes::ByteArray &A5, Sbtypes::ByteArray &A6, Sbtypes::ByteArray &A7, Sbtypes::ByteArray &A8, Sbtypes::ByteArray &A9, bool Zeroize)/* overload */;
extern PACKAGE void __fastcall ReleaseArrays(Sbtypes::ByteArray &A1, Sbtypes::ByteArray &A2, Sbtypes::ByteArray &A3, Sbtypes::ByteArray &A4, Sbtypes::ByteArray &A5, Sbtypes::ByteArray &A6, Sbtypes::ByteArray &A7, Sbtypes::ByteArray &A8, Sbtypes::ByteArray &A9, Sbtypes::ByteArray &A10)/* overload */;
extern PACKAGE void __fastcall ReleaseArrays(Sbtypes::ByteArray &A1, Sbtypes::ByteArray &A2, Sbtypes::ByteArray &A3, Sbtypes::ByteArray &A4, Sbtypes::ByteArray &A5, Sbtypes::ByteArray &A6, Sbtypes::ByteArray &A7, Sbtypes::ByteArray &A8, Sbtypes::ByteArray &A9, Sbtypes::ByteArray &A10, bool Zeroize)/* overload */;
extern PACKAGE int __fastcall GetDigestSizeBits(int Algorithm);
extern PACKAGE System::TDateTime __fastcall ISO8601TimeToDateTime(const System::UnicodeString EncodedTime);
extern PACKAGE System::UnicodeString __fastcall DateTimeToISO8601Time(System::TDateTime Time, bool EncodeMilliseconds);
extern PACKAGE System::UnicodeString __fastcall DateTimeToRFC3339(System::TDateTime Value, bool EncodeMilliseconds);
extern PACKAGE System::UnicodeString __fastcall AppendSlash(const System::UnicodeString Path);
extern PACKAGE bool __fastcall EnsureDirectoryExists(const System::UnicodeString DirName);
extern PACKAGE bool __fastcall DirectoryExists(System::UnicodeString DirName);
extern PACKAGE Sbtypes::ByteArray __fastcall TrimLeadingZeros(const Sbtypes::ByteArray V)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall PrefixByteArray(Sbtypes::ByteArray Buffer, int Count, System::Byte Value)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall SuffixByteArray(Sbtypes::ByteArray Buffer, int Count, System::Byte Value)/* overload */;
extern PACKAGE void __fastcall FillByteArray(Sbtypes::ByteArray Buffer, int SrcOffset, int Count, System::Byte Value)/* overload */;
extern PACKAGE void __fastcall FillByteArray(Sbtypes::ByteArray Buffer, System::Byte Value)/* overload */;
extern PACKAGE bool __fastcall ArrayStartsWith(const Sbtypes::ByteArray SubP, const Sbtypes::ByteArray P);
extern PACKAGE int __fastcall CompareArrays(const Sbtypes::ByteArray Buf1, const Sbtypes::ByteArray Buf2);
extern PACKAGE int __fastcall CompareBuffers(const Sbtypes::ByteArray Buf1, const Sbtypes::ByteArray Buf2);
extern PACKAGE bool __fastcall IsValidVCLObject(void * Obj);
extern PACKAGE unsigned __fastcall WaitFor(unsigned Handle);
extern PACKAGE bool __fastcall IsTextualOID(const System::UnicodeString S);
extern PACKAGE void __fastcall SetLicenseKey(const System::UnicodeString Key);
extern PACKAGE void __fastcall CheckLicenseKey(void);
extern PACKAGE System::UnicodeString __fastcall HexDump(const Sbtypes::ByteArray Buffer, unsigned Offset, unsigned Len)/* overload */;
extern PACKAGE System::UnicodeString __fastcall HexDump(const Sbtypes::ByteArray Buffer, unsigned Offset, unsigned Len, bool AddChars)/* overload */;
extern PACKAGE System::TDateTime __fastcall SBEncodeDateTime(int Year, int Month, int Day, int Hour, int Minute, int Second, int Millisecond);
extern PACKAGE bool __fastcall SBSameDateTime(System::TDateTime A, System::TDateTime B);
extern PACKAGE bool __fastcall SBSameDate(System::TDateTime A, System::TDateTime B);
extern PACKAGE bool __fastcall SBSameTime(System::TDateTime A, System::TDateTime B);
extern PACKAGE System::TDateTime __fastcall DateTimeAddDays(System::TDateTime DateTime, int Days);
extern PACKAGE System::TDateTime __fastcall DateTimeAddHours(System::TDateTime DateTime, int Hours);
extern PACKAGE System::TDateTime __fastcall DateTimeAddMinutes(System::TDateTime DateTime, int Minutes);
extern PACKAGE System::TDateTime __fastcall DateTimeAddSeconds(System::TDateTime DateTime, int Seconds);
extern PACKAGE System::TDateTime __fastcall DateTimeAddYears(System::TDateTime DateTime, int Years);
extern PACKAGE bool __fastcall DateTimeAfter(System::TDateTime DT1, System::TDateTime DT2);
extern PACKAGE bool __fastcall DateTimeBefore(System::TDateTime DT1, System::TDateTime DT2);
extern PACKAGE System::TDateTime __fastcall DateTimeClone(System::TDateTime DateTime);
extern PACKAGE int __fastcall DateTimeCompare(System::TDateTime DT1, System::TDateTime DT2);
extern PACKAGE bool __fastcall DateTimeEquals(System::TDateTime DT1, System::TDateTime DT2);
extern PACKAGE System::TDateTime __fastcall DateTimeNow(void);
extern PACKAGE System::TDateTime __fastcall DateTimeUtcNow(void);
extern PACKAGE System::AnsiString __fastcall AnsiStringOfBytes(const Sbtypes::ByteArray Src);
extern PACKAGE Sbtypes::ByteArray __fastcall CreateByteArrayConst(const System::AnsiString Src);
extern PACKAGE System::AnsiString __fastcall AnsiStringOfString(const System::UnicodeString Str);
extern PACKAGE System::UnicodeString __fastcall StringOfAnsiString(const System::AnsiString Str);
extern PACKAGE Sbtypes::ByteArray __fastcall BytesOfAnsiString(const System::AnsiString Str);
extern PACKAGE Sbtypes::ByteArray __fastcall GetBytes64(const __int64 X)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall GetBytes32(const unsigned X)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall GetBytes16(const System::Word X)/* overload */;
extern PACKAGE Sbtypes::ByteArray __fastcall GetBytes8(const System::Byte X)/* overload */;
extern PACKAGE void __fastcall GetBytes64(const __int64 X, Sbtypes::ByteArray &Buffer, int Index)/* overload */;
extern PACKAGE void __fastcall GetBytes32(const unsigned X, Sbtypes::ByteArray &Buffer, int Index)/* overload */;
extern PACKAGE void __fastcall GetBytes16(const System::Word X, Sbtypes::ByteArray &Buffer, int Index)/* overload */;
extern PACKAGE void __fastcall GetBytes8(const System::Byte X, Sbtypes::ByteArray &Buffer, int Index)/* overload */;
extern PACKAGE int __fastcall ConstLength(Sbtypes::ByteArray Arr);

}	/* namespace Sbutils */
using namespace Sbutils;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbutilsHPP
