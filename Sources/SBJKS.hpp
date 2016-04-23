// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbjks.pas' rev: 21.00

#ifndef SbjksHPP
#define SbjksHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbx509.hpp>	// Pascal unit
#include <Sbsha.hpp>	// Pascal unit
#include <Sbrandom.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbjks
{
//-- type declarations -------------------------------------------------------
typedef unsigned Int32;

struct TEntry
{
	
private:
	typedef DynamicArray<Sbx509::TElX509Certificate*> _TEntry__1;
	
	
public:
	System::UnicodeString Alias;
	System::TDateTime CreationDate;
	Sbtypes::ByteArray EncodedKey;
	_TEntry__1 Certificate_Chain;
	int Cert_Count;
};


typedef bool __fastcall (__closure *TElJKSPasswordEvent)(const System::UnicodeString Alias, System::UnicodeString &Password);

typedef bool __fastcall (__closure *TElJKSAliasNeededEvent)(Sbx509::TElX509Certificate* Cert, System::UnicodeString &Alias);

class DELPHICLASS TElJKS;
class PASCALIMPLEMENTATION TElJKS : public System::TObject
{
	typedef System::TObject inherited;
	
private:
	typedef DynamicArray<TEntry> _TElJKS__1;
	
	
protected:
	bool __fastcall GetIsPrivateKey(int Index);
	int __fastcall GetChainCount(int Index);
	
private:
	_TElJKS__1 FEntries;
	int FEntries_Count;
	Sbsha::TSHA1Context FSha;
	bool FIgnoreBadStorageSignature;
	int __fastcall LoadCertFromStream(Classes::TStream* Stream, Sbx509::TElX509Certificate* &Cert);
	int __fastcall LoadCertFromBuffer(const Sbtypes::ByteArray Src_Buffer, int BufferSize, int &BufferPos, Sbx509::TElX509Certificate* &Cert);
	int __fastcall SaveCertToStream(Classes::TStream* Stream, Sbx509::TElX509Certificate* Cert);
	int __fastcall SaveCertToBuffer(Sbx509::TElX509Certificate* Cert, Sbtypes::ByteArray &DstBuffer, int BufferSize, int &BufferPos);
	int __fastcall LoadFromStreamViaSha(Classes::TStream* Stream, void *Buffer, int Count);
	int __fastcall SaveToStreamViaSha(Classes::TStream* Stream, void *Buffer, int Count);
	int __fastcall LoadFromBufferViaSha(const Sbtypes::ByteArray Src_Buffer, int BufferSize, int &BufferPos, void *Buffer, int Count);
	int __fastcall SaveToBufferViaSha(const void *Buffer, void * DstBuffer, int &BufferPos, int Count);
	bool __fastcall Decryptkey(const Sbtypes::ByteArray Data, const Sbtypes::ByteArray Pass, Sbtypes::ByteArray &Key);
	bool __fastcall Encryptkey(const Sbtypes::ByteArray Key, const Sbtypes::ByteArray Pass, Sbtypes::ByteArray &Encrypted);
	
public:
	__fastcall TElJKS(void);
	__fastcall virtual ~TElJKS(void);
	int __fastcall LoadFromStream(Classes::TStream* Stream, const System::UnicodeString JKS_Pass);
	int __fastcall LoadFromBuffer(void * Src_Ptr, int BufferSize, int &BufferPos, const System::UnicodeString JKS_Pass);
	int __fastcall GetSaveBufferSize(void);
	int __fastcall SaveToStream(Classes::TStream* Stream, const System::UnicodeString JKS_Pass);
	int __fastcall SaveToBuffer(Sbtypes::ByteArray &DstBuffer, int BufferSize, int &BufferPos, const System::UnicodeString JKS_Pass);
	bool __fastcall GetPrivateKey(int Index, const System::UnicodeString Pass, Sbtypes::ByteArray &Key);
	bool __fastcall SetPrivateKey(int Index, const System::UnicodeString Pass, const Sbtypes::ByteArray Key);
	int __fastcall AddPrivateKey(const System::UnicodeString Pass, const Sbtypes::ByteArray Key);
	Sbx509::TElX509Certificate* __fastcall GetKeyCertificate(int Index, int Cert_Index);
	int __fastcall AddKeyCertificate(int Index, Sbx509::TElX509Certificate* Cert);
	void __fastcall DelKeyCertificate(int Index, int Cert_Index);
	Sbx509::TElX509Certificate* __fastcall GetTrustedCertificate(int Index);
	int __fastcall AddTrustedCertificate(Sbx509::TElX509Certificate* Cert);
	void __fastcall DelTrustedCertificate(int Index);
	System::UnicodeString __fastcall GetAlias(int Index);
	void __fastcall SetAlias(int Index, const System::UnicodeString Alias);
	__property int Entries_Count = {read=FEntries_Count, nodefault};
	__property int PrivateKeyCert_Count[int index] = {read=GetChainCount};
	__property bool IsPrivateKey[int Index] = {read=GetIsPrivateKey};
	__property bool IgnoreBadStorageSignature = {read=FIgnoreBadStorageSignature, write=FIgnoreBadStorageSignature, nodefault};
};

typedef TElJKS ElJKS
//-- var, const, procedure ---------------------------------------------------
static const ShortInt E_JKS_FORMAT_ERROR = 0x1;
static const ShortInt E_JKS_READ_ERROR = 0x2;
static const ShortInt E_JKS_WRITE_ERROR = 0x3;
static const ShortInt E_JKS_VERSION_ERROR = 0x4;
static const ShortInt E_JKS_KEY_FORMAT_ERROR = 0x5;
static const ShortInt E_JKS_UNKNOWN_CERT = 0x6;
static const ShortInt E_JKS_CHECKSUM = 0x7;
static const ShortInt E_JKS_SIGNATURE = 0x8;
static const ShortInt E_JKS_NO_SPACE = 0x9;

}	/* namespace Sbjks */
using namespace Sbjks;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbjksHPP
