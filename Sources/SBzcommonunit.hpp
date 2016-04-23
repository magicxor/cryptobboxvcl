// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbzcommonunit.pas' rev: 21.00

#ifndef SbzcommonunitHPP
#define SbzcommonunitHPP

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

//-- user supplied -----------------------------------------------------------

namespace Sbzcommonunit
{
//-- type declarations -------------------------------------------------------
#pragma pack(push,1)
struct ct_data_s
{
	
	union
	{
		struct 
		{
			int Code;
			int Len;
			
		};
		struct 
		{
			int Freq;
			int Dad;
			
		};
		
	};
};
#pragma pack(pop)


typedef ct_data_s ct_data;

typedef StaticArray<System::Byte, 4096> Arrayfff;

typedef Arrayfff *ArrayPtr;

typedef StaticArray<System::Word, 65536> ArrayWord;

typedef ArrayWord *ArrayWordPtr;

typedef StaticArray<int, 65536> ArrayInt;

typedef ArrayInt *ArrayIntPtr;

typedef StaticArray<unsigned, 65536> ArrayuInt;

typedef ArrayuInt *ArrayuIntPtr;

typedef StaticArray<ct_data_s, 65536> ArrayCt;

typedef ArrayCt *ArrayCtPtr;

typedef ArrayPtr Bytef;

typedef ArrayPtr *PBytef;

typedef unsigned ulg;

typedef System::Word ush;

typedef System::Word Pos;

typedef ArrayWordPtr Posf;

typedef unsigned IPos;

typedef ArrayIntPtr Intf;

typedef System::Byte uch;

typedef ArrayPtr uchf;

typedef ArrayWordPtr ushf;

typedef ArrayuIntPtr uIntf;

typedef ArrayPtr *Bytefp;

typedef ArrayuIntPtr uLongf;

typedef unsigned *PuInt;

typedef void __fastcall (*voidpf)(void);

typedef void * __fastcall (*TAlloc)(void * AppData, int Items, int Size);

typedef void __fastcall (*TFree)(void * AppData, void * Block);

struct TZStreamRec;
typedef TZStreamRec *PZStreamRec;

struct TZStreamRec
{
	
public:
	char *next_in;
	int avail_in;
	int total_in;
	char *next_out;
	int avail_out;
	int total_out;
	System::WideChar *msg;
	void *internal;
	TAlloc zalloc;
	TFree zfree;
	void *AppData;
	int data_type;
	unsigned adler;
	int reserved;
	bool deflate64;
};


struct static_tree_desc_s
{
	
public:
	ArrayCt *static_tree;
	ArrayInt *extra_bits;
	int extra_base;
	int elems;
	int max_length;
};


typedef static_tree_desc_s static_tree_desc;

struct tree_desc_s
{
	
public:
	ArrayCt *dyn_tree;
	int max_code;
	static_tree_desc_s stat_desc;
};


typedef tree_desc_s tree_desc;

struct ptr_table_s
{
	
public:
	void *org_ptr;
	void *new_ptr;
};


typedef ptr_table_s ptr_table;

//-- var, const, procedure ---------------------------------------------------
extern PACKAGE Sbtypes::ByteArray ZLIB_VERSION;
static const Word ENOUGH = 0x800;
static const Word MAXD = 0x250;
static const ShortInt LENGTH_CODES = 0x1d;
static const Word LITERALS = 0x100;
static const Word L_CODES = 0x11e;
static const Word HEAP_SIZE = 0x23d;
static const ShortInt D_CODES = 0x1e;
static const ShortInt BL_CODES = 0x13;
static const ShortInt MAX_BITS = 0xf;
static const Word ZLIB_VERNUM = 0x1220;
static const ShortInt Z_NO_FLUSH = 0x0;
static const ShortInt Z_PARTIAL_FLUSH = 0x1;
static const ShortInt Z_SYNC_FLUSH = 0x2;
static const ShortInt Z_FULL_FLUSH = 0x3;
static const ShortInt Z_FINISH = 0x4;
static const ShortInt Z_BLOCK = 0x5;
static const ShortInt Z_OK = 0x0;
static const ShortInt Z_STREAM_END = 0x1;
static const ShortInt Z_NEED_DICT = 0x2;
static const ShortInt Z_STREAM_ERROR = -2;
static const ShortInt Z_DATA_ERROR = -3;
static const ShortInt Z_MEM_ERROR = -4;
static const ShortInt Z_BUF_ERROR = -5;
static const ShortInt Z_VERSION_ERROR = -6;
#define Z_NULL (void *)(0)
static const ShortInt MAX_PTR = 0xa;
static const ShortInt MAX_WBITS = 0x10;
static const ShortInt Z_RLE = 0x3;
static const ShortInt Z_FIXED = 0x4;
static const ShortInt Z_DEFLATED = 0x8;
static const ShortInt PRESET_DICT = 0x20;
extern PACKAGE StaticArray<ptr_table_s, 11> table;
extern PACKAGE Sbtypes::ByteArray __fastcall zlibVersion(void);
extern PACKAGE void __cdecl ZlibMemCpy(void * dest, void * source, int count);
extern PACKAGE unsigned __fastcall adler32(unsigned adler, void * buf, unsigned len);
extern PACKAGE void * __fastcall zlibAllocMem(void * AppData, int Items, int Size);
extern PACKAGE void __fastcall zlibFreeMem(void * AppData, void * Block);
extern PACKAGE int __fastcall CCheck(int code);

}	/* namespace Sbzcommonunit */
using namespace Sbzcommonunit;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbzcommonunitHPP
