// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbumac.pas' rev: 21.00

#ifndef SbumacHPP
#define SbumacHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbcrc.hpp>	// Pascal unit
#include <Sbaes.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbumac
{
//-- type declarations -------------------------------------------------------
typedef __int64 UINT64;

typedef System::Byte UINT8;

typedef System::Word UINT16;

typedef unsigned UINT32;

typedef unsigned *pUINT32;

typedef __int64 *pUINT64;

typedef DynamicArray<__int64> UINT64Array;

struct TNHContext
{
	
public:
	Sbtypes::ByteArray NH_Key;
	Sbtypes::ByteArray Data;
	int Next_Data_Empty;
	int Bytes_Hashed;
	UINT64Array State;
};


#pragma pack(push,1)
struct TUHASHContext
{
	
public:
	TNHContext Hash;
	UINT64Array Poly_Key_8;
	UINT64Array Poly_Accum;
	UINT64Array IP_Keys;
	Sbtypes::ByteArray IP_Trans;
	unsigned Msg_Len;
};
#pragma pack(pop)


#pragma pack(push,1)
struct TPDFContext
{
	
public:
	Sbaes::TAESBuffer Cache;
	Sbaes::TAESBuffer Nonce;
	Sbaes::TAESExpandedKey128 PRF_Key;
};
#pragma pack(pop)


class DELPHICLASS TElUMAC;
class PASCALIMPLEMENTATION TElUMAC : public System::TObject
{
	typedef System::TObject inherited;
	
protected:
	TUHASHContext fHash;
	TPDFContext fPDF;
	int fOutputLen;
	int fStreams;
	void __fastcall Initialize_UMAC(const Sbtypes::ByteArray Key, int TagLen);
	void __fastcall UHASH_Init(unsigned const *PRF_Key);
	void __fastcall Init_Members(void);
	__fastcall TElUMAC(void)/* overload */;
	
public:
	__fastcall TElUMAC(const Sbtypes::ByteArray Key, int TagLen)/* overload */;
	__fastcall TElUMAC(const System::UnicodeString Key, int TagLen)/* overload */;
	__fastcall virtual ~TElUMAC(void);
	TElUMAC* __fastcall Clone(void);
	void __fastcall Reset(void);
	void __fastcall Update(const Sbtypes::ByteArray In_Buf, unsigned StartIndex, unsigned Len)/* overload */;
	void __fastcall Update(void * In_Buf, int Size)/* overload */;
	void __fastcall Final(const Sbtypes::ByteArray Nonce, /* out */ Sbtypes::ByteArray &Tag);
	void __fastcall Calculate(const Sbtypes::ByteArray In_Buf, unsigned StartIndex, unsigned Len, const Sbtypes::ByteArray Nonce, /* out */ Sbtypes::ByteArray &Tag)/* overload */;
	void __fastcall Calculate(void * In_Buf, unsigned Len, const Sbtypes::ByteArray Nonce, /* out */ Sbtypes::ByteArray &Tag)/* overload */;
};


//-- var, const, procedure ---------------------------------------------------
static const ShortInt AES_BLOCK_LEN = 0x10;
static const ShortInt UMAC_KEY_LEN = 0x10;
static const Word L1_KEY_LEN = 0x400;
static const ShortInt L1_KEY_SHIFT = 0x10;
static const ShortInt L1_PAD_BOUNDARY = 0x20;
static const ShortInt HASH_BUF_BYTES = 0x40;

}	/* namespace Sbumac */
using namespace Sbumac;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbumacHPP
