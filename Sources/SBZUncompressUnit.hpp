// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbzuncompressunit.pas' rev: 21.00

#ifndef SbzuncompressunitHPP
#define SbzuncompressunitHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Windows.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbzcommonunit.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbzuncompressunit
{
//-- type declarations -------------------------------------------------------
#pragma pack(push,1)
struct code
{
	
public:
	System::Byte op;
	System::Byte bits;
	unsigned val;
};
#pragma pack(pop)


typedef StaticArray<unsigned, 321> TArrShr;

typedef TArrShr *PArrShr;

typedef StaticArray<unsigned, 289> TArrShr288;

typedef TArrShr *PArrShr288;

typedef code *PCode;

typedef StaticArray<code, 2049> TArrCds;

typedef TArrCds *PArrCds;

typedef StaticArray<code, 32> TArrCds31;

typedef TArrCds31 *PArrCds31;

typedef StaticArray<code, 512> TArrCds511;

typedef TArrCds511 *PArrCds511;

#pragma option push -b-
enum inflate_mode { HEAD, DICTID, DICT, TYPEB, TYPEDO, STORED, COPY, TABLE, LENLENS, CODELENS, LEN, LENEXT, DIST, DISTEXT, MATCH, LIT, CHECK, DONE, BAD, MEM, SYNC };
#pragma option pop

struct inflate_state_s;
typedef inflate_state_s *inflate_state;

struct inflate_state_s
{
	
public:
	inflate_mode mode;
	int last;
	int wrap;
	int havedict;
	int flags;
	unsigned dmax;
	unsigned check;
	unsigned total;
	unsigned wbits;
	unsigned wsize;
	unsigned whave;
	unsigned Write;
	unsigned hold;
	unsigned bits;
	unsigned Length;
	unsigned offset;
	unsigned extra;
	char *window;
	TArrCds511 *lencode;
	TArrCds31 *distcode;
	unsigned lenbits;
	unsigned distbits;
	unsigned ncode;
	unsigned nlen;
	unsigned ndist;
	unsigned have;
	code *next;
	TArrShr lens;
	TArrShr288 work;
	TArrCds codes;
};


//-- var, const, procedure ---------------------------------------------------
static const Word MANY = 0x5a0;
static const ShortInt DEF_WBITS = 0x10;
static const ShortInt BMAX = 0xf;
extern PACKAGE int __fastcall inflateEnd(Sbzcommonunit::TZStreamRec &z);
extern PACKAGE int __fastcall inflateReset(Sbzcommonunit::TZStreamRec &z);
extern PACKAGE int __fastcall inflateInit2_(Sbzcommonunit::TZStreamRec &z, int w, const Sbtypes::ByteArray version, int stream_size);
extern PACKAGE int __fastcall inflateInit_(Sbzcommonunit::TZStreamRec &z, const Sbtypes::ByteArray version, int stream_size);
extern PACKAGE int __fastcall uncompress(Sbzcommonunit::ArrayPtr &dest, unsigned &destLen, Sbzcommonunit::ArrayPtr source, unsigned sourceLen);
extern PACKAGE int __fastcall inflate(Sbzcommonunit::TZStreamRec &z, int f);

}	/* namespace Sbzuncompressunit */
using namespace Sbzuncompressunit;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbzuncompressunitHPP
