// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbzcompressunit.pas' rev: 21.00

#ifndef SbzcompressunitHPP
#define SbzcompressunitHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Sbzcommonunit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbzcompressunit
{
//-- type declarations -------------------------------------------------------
typedef System::Byte *BytePtr;

typedef char * charf;

typedef System::Byte block_state;

struct internal_state_s;
typedef internal_state_s *internal_state;

struct internal_state_s
{
	
public:
	Sbzcommonunit::TZStreamRec *strm;
	int status;
	Sbzcommonunit::Arrayfff *pending_buf;
	Sbzcommonunit::Arrayfff *pending_out;
	unsigned pending_buf_size;
	int pending;
	int wrap;
	System::Byte data_type;
	System::Byte method;
	int last_flush;
	unsigned w_size;
	unsigned w_bits;
	unsigned w_mask;
	Sbzcommonunit::Arrayfff *window;
	unsigned window_size;
	Sbzcommonunit::ArrayWord *prev;
	Sbzcommonunit::ArrayWord *head;
	unsigned ins_h;
	unsigned hash_size;
	unsigned hash_bits;
	unsigned hash_mask;
	unsigned hash_shift;
	int block_start;
	unsigned match_length;
	unsigned prev_match;
	int match_available;
	unsigned strstart;
	unsigned match_start;
	unsigned lookahead;
	unsigned prev_length;
	unsigned max_chain_length;
	unsigned max_lazy_match;
	int level;
	int strategy;
	unsigned good_match;
	int nice_match;
	StaticArray<Sbzcommonunit::ct_data_s, 574> dyn_ltree;
	StaticArray<Sbzcommonunit::ct_data_s, 62> dyn_dtree;
	StaticArray<Sbzcommonunit::ct_data_s, 40> bl_tree;
	Sbzcommonunit::tree_desc_s l_desc;
	Sbzcommonunit::tree_desc_s d_desc;
	Sbzcommonunit::tree_desc_s bl_desc;
	StaticArray<System::Word, 17> bl_count;
	StaticArray<int, 574> heap;
	int heap_len;
	int heap_max;
	StaticArray<System::Byte, 574> depth;
	Sbzcommonunit::Arrayfff *l_buf;
	unsigned lit_bufsize;
	unsigned last_lit;
	Sbzcommonunit::ArrayWord *d_buf;
	unsigned opt_len;
	unsigned static_len;
	unsigned matches;
	int last_eob_len;
	System::Word bi_buf;
	int bi_valid;
};


typedef internal_state *internal_state_p;

typedef internal_state deflate_state;

typedef System::Byte __fastcall (*compress_func)(internal_state_s &s, int &flush);

struct config_s
{
	
public:
	System::Word good_length;
	System::Word max_lazy;
	System::Word nice_length;
	System::Word max_chain;
	compress_func func;
};


typedef config_s config;

typedef StaticArray<System::UnicodeString, 11> Sbzcompressunit__1;

//-- var, const, procedure ---------------------------------------------------
static const ShortInt Z_BINARY = 0x0;
static const ShortInt Z_TEXT = 0x1;
static const ShortInt Z_ASCII = 0x1;
static const ShortInt Z_UNKNOWN = 0x2;
static const ShortInt MAX_MEM_LEVEL = 0x9;
static const ShortInt DEF_MEM_LEVEL = 0x8;
static const ShortInt Z_NO_COMPRESSION = 0x0;
static const ShortInt Z_BEST_SPEED = 0x1;
static const ShortInt Z_BEST_COMPRESSION = 0x9;
static const ShortInt Z_DEFAULT_COMPRESSION = -1;
static const ShortInt Z_FILTERED = 0x1;
static const ShortInt Z_DEFAULT_STRATEGY = 0x0;
static const ShortInt Z_HUFFMAN_ONLY = 0x2;
static const ShortInt need_more = 0x0;
static const ShortInt block_done = 0x1;
static const ShortInt finish_started = 0x2;
static const ShortInt finish_done = 0x3;
static const ShortInt Buf_size = 0x10;
static const ShortInt MIN_MATCH = 0x3;
static const Word MAX_MATCH = 0x102;
extern PACKAGE unsigned MIN_LOOKAHEAD;
static const Word DIST_CODE_LEN = 0x200;
static const Word END_BLOCK = 0x100;
static const ShortInt MAX_BL_BITS = 0x7;
static const Word TOO_FAR = 0x1000;
extern PACKAGE System::Word tmpi;
extern PACKAGE Sbzcompressunit__1 z_errmsg;
extern PACKAGE int FORCE_STORED;
extern PACKAGE int FORCE_STATIC;
extern PACKAGE int FASTEST;
extern PACKAGE int GEN_TREES_H;
extern PACKAGE int STDC;
extern PACKAGE int ASMV;
extern PACKAGE int __fastcall deflate(Sbzcommonunit::TZStreamRec &strm, int flush);
extern PACKAGE int __fastcall deflateEnd(Sbzcommonunit::TZStreamRec &strm);
extern PACKAGE int __fastcall deflateReset(Sbzcommonunit::TZStreamRec &strm);
extern PACKAGE int __fastcall deflateInit2_(Sbzcommonunit::TZStreamRec &strm, int level, int method, int windowBits, int memLevel, int strategy, Sbtypes::ByteArray version, int recsize);
extern PACKAGE int __fastcall deflateInit_(Sbzcommonunit::TZStreamRec &strm, int level, Sbtypes::ByteArray version, int recsize);
extern PACKAGE void __fastcall CompressBuf(const void * InBuf, int InBytes, /* out */ void * &OutBuf, /* out */ int &OutBytes);
extern PACKAGE int __fastcall deflateSetDictionary(Sbzcommonunit::TZStreamRec &strm, char * dictionary, unsigned dictLength);

}	/* namespace Sbzcompressunit */
using namespace Sbzcompressunit;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbzcompressunitHPP
