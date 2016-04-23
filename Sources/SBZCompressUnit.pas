(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

(* 

  Oiriginal source code:

  Copyright (C) 1995-2005 Jean-loup Gailly and Mark Adler

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Jean-loup Gailly        Mark Adler
  jloup@gzip.org          madler@alumni.caltech.edu


  The data format used by the zlib library is described by RFCs (Request for
  Comments) 1950 to 1952 in the files http://www.ietf.org/rfc/rfc1950.txt
  (zlib format), rfc1951.txt (deflate format) and rfc1952.txt (gzip format).
*)

{$I SecBbox.inc}

unit SBZCompressUnit;

interface

{$ifndef DONT_USE_ZLIB}

uses
{$ifdef SB_WIN32}
  windows,
 {$endif}
  SysUtils,
  SBZCommonUnit,
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  SBDumper,
   {$endif}
  SBTypes,
  SBUtils,
  SBConstants
  ;


const

  Z_BINARY = 0;
  Z_TEXT = 1;
  Z_ASCII = 1;
  Z_UNKNOWN = 2;

  MAX_MEM_LEVEL = 9;
  DEF_MEM_LEVEL = 8;

  Z_NO_COMPRESSION = 0;
  Z_BEST_SPEED = 1;
  Z_BEST_COMPRESSION = 9;
  Z_DEFAULT_COMPRESSION = (-1);

  Z_FILTERED = 1;
  Z_DEFAULT_STRATEGY = 0;
  Z_HUFFMAN_ONLY = 2;

 //This constants is for block_state type
  need_more = 0; // block not completed, need more input or more output
  block_done = 1; // block flush performed
  finish_started = 2; // finish started, need only more output at next deflate
  finish_done = 3; // finish done, accept no more input or output

  Buf_size = (8 shl 1 * SizeOf(AnsiChar));
// {* Number of bits used within bi_buf. (bi_buf might be implemented on
// * more than 16 bits on some systems.)}

  MIN_MATCH = 3;
  MAX_MATCH = 258;

  MIN_LOOKAHEAD : unsigned = MAX_MATCH + MIN_MATCH + 1;

  DIST_CODE_LEN = 512; // see definition of array dist_code below

  END_BLOCK = 256;
// end of block literal code

  MAX_BL_BITS = 7; // Bit length codes must not exceed MAX_BL_BITS bits
  TOO_FAR = 4096;
    // Matches of length 3 are discarded if their distance exceeds TOO_FAR

type
  BytePtr = ^Byte;
  charf = PAnsiChar; //array of char;
  block_state =  byte;
    //Can have only 4 values (0,1,2,3), const is defined highe (up)

{ ct_data_s = record
  Freq :ush;
  Code :ush;
  Dad  :ush;
  Len  :ush;
 end;
 ct_data = ct_data_s; }
{ z_streamp = ^z_stream;}


  internal_state = ^internal_state_s;
  internal_state_s = record
    strm: PZStreamRec; // pointer back to this zlib stream
    status: integer; // as the name implies
    pending_buf: ArrayPtr; // output still pending
    pending_out: Bytef; // next pending byte to output to the stream
    pending_buf_size: ulg; // size of pending_buf
    pending: integer; // nb of bytes in the pending buffer
//    noheader: integer; // suppress zlib header and adler32
    wrap: Integer;   // bit 0 true for zlib, bit 1 true for gzip

    data_type: byte; // UNKNOWN, BINARY or ASCII
    method: byte; // STORED (for zip only) or DEFLATED
    last_flush: integer; // value of flush param for previous deflate call

                // used by deflate.c:

    w_size: uInt; // LZ77 window size (32K by default)
    w_bits: uInt; // log2(w_size)  (8..16)
    w_mask: uInt; // w_size - 1

    window: Bytef;
    {* Sliding window. Input bytes are read into the second half of the window,
     * and move to the first half later to keep a dictionary of at least wSize
     * bytes. With this organization, matches are limited to a distance of
     * wSize-MAX_MATCH bytes, but this ensures that IO is always
     * performed with a length multiple of the block size. Also, it limits
     * the window size to 64K, which is quite useful on MSDOS.
     * To do: use the user input buffer as sliding window.
     *}

    window_size: ulg;
    {* Actual size of window: 2*wSize, except when the user input buffer
     * is directly used as sliding window.
     *}

    prev: Posf;
    {* Link to older string with same hash index. To limit the size of this
     * array to 64K, this link is maintained only for the last 32K strings.
     * An index in this array is thus a window index modulo 32K.
     *}

    head: Posf; // Heads of the hash chains or NIL.

    ins_h: uInt; // hash index of string to be inserted
    hash_size: uInt; // number of elements in hash table
    hash_bits: uInt; // log2(hash_size)
    hash_mask: uInt; // hash_size-1

    hash_shift: uInt;
    {* Number of bits by which ins_h must be shifted at each input
     * step. It must be such that after MIN_MATCH steps, the oldest
     * byte no longer takes part in the hash key, that is:
     *   hash_shift * MIN_MATCH >= hash_bits
     *}

    block_start: long;
     {* Window position at the beginning of the current output block. Gets
     * negative when the window is moved backwards.
     *}

    match_length: uInt; // length of best match
    prev_match: IPos; // previous match
    match_available: integer; // set if previous match exists
    strstart: uInt; // start of string to insert
    match_start: uInt; // start of matching string
    lookahead: uInt; // number of valid bytes ahead in window

    prev_length: uInt;
    {* Length of the best match at previous step. Matches not greater than this
     * are discarded. This is used in the lazy match evaluation.
     *}

    max_chain_length: uInt;
    {* To speed up deflation, hash chains are never searched beyond this
     * length.  A higher limit improves compression ratio but degrades the
     * speed.
     *}

    max_lazy_match: uInt;
    {* Attempt to find a better match only when the current match is strictly
     * smaller than this value. This mechanism is used only for compression
     * levels >= 4.
     *}

    level: integer; // compression level (1..9)
    strategy: integer; // favor or force Huffman coding

    good_match: uInt;
    {* Use a faster search when the previous match is longer than this *}

    nice_match: integer; // Stop searching when current match exceeds this

                // used by trees.c:
    // Didn't use ct_data typedef below to supress compiler warning
    dyn_ltree: array[0..HEAP_SIZE] of ct_data_s; // literal and length tree
    dyn_dtree: array[0..2 * D_CODES + 1] of ct_data_s; // distance tree
    bl_tree: array[0..2 * BL_CODES + 1] of ct_data_s;
      // Huffman tree for bit lengths

    l_desc: tree_desc_s; // desc. for literal tree
    d_desc: tree_desc_s; // desc. for distance tree
    bl_desc: tree_desc_s; // desc. for bit length tree

    bl_count: array[0..MAX_BITS + 1] of ush;
      // number of codes at each bit length for an optimal tree

    heap: array[0..2 * L_CODES + 1] of integer;
      // heap used to build the Huffman trees
    heap_len: integer; // number of elements in the heap
    heap_max: integer; // element of largest frequency
    {* The sons of heap[n] are heap[2*n] and heap[2*n+1]. heap[0] is not used.
     * The same heap array is used to build all trees.
     *}

    depth: array[0..2 * L_CODES + 1] of uch;
    {* Depth of each subtree used as tie breaker for trees of equal frequency
     *}

    l_buf: ArrayPtr; // buffer for literals or lengths

    lit_bufsize: Cardinal;
    {* Size of match buffer for literals/lengths.  There are 4 reasons for
     * limiting lit_bufsize to 64K:
     *   - frequencies can be kept in 16 bit counters
     *   - if compression is not successful for the first block, all input
     *     data is still in the window so we can still emit a stored block even
     *     when input comes from standard input.  (This can also be done for
     *     all blocks if lit_bufsize is not greater than 32K.)
     *   - if compression is not successful for a file smaller than 64K, we can
     *     even emit a stored file instead of a stored block (saving 5 bytes).
     *     This is applicable only for zip (not gzip or zlib).
     *   - creating new Huffman trees less frequently may not provide fast
     *     adaptation to changes in the input data statistics. (Take for
     *     example a binary file with poorly compressible code followed by
     *     a highly compressible string table.) Smaller buffer sizes give
     *     fast adaptation but have of course the overhead of transmitting
     *     trees more frequently.
     *   - I can't count above 4
     *}

    last_lit: Cardinal; //uInt;   // running index in l_buf

    d_buf: ArrayWordPtr; //ushf;
    {* Buffer for distances. To simplify the code, d_buf and l_buf have
     * the same number of elements. To use different lengths, an extra flag
     * array would be necessary.
     *}

    opt_len: ulg; // bit length of current block with optimal trees
    static_len: ulg; // bit length of current block with static trees
    matches: uInt; // number of string matches in current block
    last_eob_len: integer; // bit length of EOB code for last block

    bi_buf: ush;
    {* Output buffer. bits are inserted starting at the bottom (least
     * significant bits).
     *}
    bi_valid: integer;
    {* Number of valid bits in bi_buf.  All bits above the last valid bit
     * are always zero.
     *}
  //  FAR deflate_state; }
  end; //end of internal_state record
  internal_state_p = ^deflate_state;
  deflate_state = internal_state;

  compress_func =  function(var s: internal_state_s; 
    var flush: integer): block_state;
    
  config_s =  record
    good_length: ush; // reduce lazy search above this match length
    max_lazy: ush; // do not perform lazy search above this match length
    nice_length: ush; // quit search above this match length
    max_chain: ush;
    func: compress_func;
  end;
  
  config =  config_s;

var
  tmpi: Word;

  z_errmsg: array[0..10] of string;

 //Ii?aaaeaiea #ifdef-ia
  FORCE_STORED: integer;
  FORCE_STATIC: integer;
  FASTEST: integer;
  GEN_TREES_H: integer;
  STDC: integer;
  ASMV: integer;

//Export functions translated(ported) from MS VC++
function deflateInit_(var strm: TZStreamRec; level: Integer; version: ByteArray;
  recsize: Integer): Integer;
function deflateInit2_(var strm: TZStreamRec; level: Integer; method,
  windowBits, memLevel, strategy: Integer; version: ByteArray; recsize: Integer):
  Integer;
function deflateEnd(var strm: TZStreamRec): Integer; 

{    deflate compresses as much data as possible, and stops when the input
  buffer becomes empty or the output buffer becomes full. It may introduce some
  output latency (reading input without producing any output) except when
  forced to flush.

    The detailed semantics are as follows. deflate performs one or both of the
  following actions:

  - Compress more input starting at next_in and update next_in and avail_in
    accordingly. If not all input can be processed (because there is not
    enough room in the output buffer), next_in and avail_in are updated and
    processing will resume at this point for the next call of deflate().

  - Provide more output starting at next_out and update next_out and avail_out
    accordingly. This action is forced if the parameter flush is non zero.
    Forcing flush frequently degrades the compression ratio, so this parameter
    should be set only when necessary (in interactive applications).
    Some output may be provided even if flush is not set.

  Before the call of deflate(), the application should ensure that at least
  one of the actions is possible, by providing more input and/or consuming
  more output, and updating avail_in or avail_out accordingly; avail_out
  should never be zero before the call. The application can consume the
  compressed output when it wants, for example when the output buffer is full
  (avail_out == 0), or after each call of deflate(). If deflate returns Z_OK
  and with zero avail_out, it must be called again after making room in the
  output buffer because there might be more output pending.

    If the parameter flush is set to Z_SYNC_FLUSH, all pending output is
  flushed to the output buffer and the output is aligned on a byte boundary, so
  that the decompressor can get all input data available so far. (In particular
  avail_in is zero after the call if enough output space has been provided
  before the call.)  Flushing may degrade compression for some compression
  algorithms and so it should be used only when necessary.

    If flush is set to Z_FULL_FLUSH, all output is flushed as with
  Z_SYNC_FLUSH, and the compression state is reset so that decompression can
  restart from this point if previous compressed data has been damaged or if
  random access is desired. Using Z_FULL_FLUSH too often can seriously degrade
  the compression.

    If deflate returns with avail_out == 0, this function must be called again
  with the same value of the flush parameter and more output space (updated
  avail_out), until the flush is complete (deflate returns with non-zero
  avail_out).

    If the parameter flush is set to Z_FINISH, pending input is processed,
  pending output is flushed and deflate returns with Z_STREAM_END if there
  was enough output space; if deflate returns with Z_OK, this function must be
  called again with Z_FINISH and more output space (updated avail_out) but no
  more input data, until it returns with Z_STREAM_END or an error. After
  deflate has returned Z_STREAM_END, the only possible operations on the
  stream are deflateReset or deflateEnd.

    Z_FINISH can be used immediately after deflateInit if all the compression
  is to be done in a single step. In this case, avail_out must be at least
  0.1% larger than avail_in plus 12 bytes.  If deflate does not return
  Z_STREAM_END, then it must be called again as described above.

    deflate() sets strm->adler to the adler32 checksum of all input read
  so far (that is, total_in bytes).

    deflate() may update data_type if it can make a good guess about
  the input data type (Z_ASCII or Z_BINARY). In doubt, the data is considered
  binary. This field is only for information purposes and does not affect
  the compression algorithm in any manner.

    deflate() returns Z_OK if some progress has been made (more input
  processed or more output produced), Z_STREAM_END if all input has been
  consumed and all output has been produced (only when flush is set to
  Z_FINISH), Z_STREAM_ERROR if the stream state was inconsistent (for example
  if next_in or next_out was NULL), Z_BUF_ERROR if no progress is possible
  (for example avail_in or avail_out was zero).}
function deflate(var strm: TZStreamRec; flush: Integer): Integer; 
function deflateReset(var strm: TZStreamRec): Integer; 
function deflateSetDictionary(var strm: TZStreamRec; dictionary: PAnsiChar;
  dictLength: uInt): integer;
procedure CompressBuf(const InBuf: Pointer; InBytes: Integer; out OutBuf:
  Pointer; out OutBytes: Integer);

implementation

var

  extra_dbits: array[0..D_CODES - 1] of integer;
    // extra bits for each distance code
 {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13}
  extra_lbits: array[0..LENGTH_CODES - 1] of integer;
  extra_blbits: array[0..BL_CODES - 1] of integer;

  configuration_table: array[0..9] of config;

 {* Distance codes. The first 256 values correspond to the distances
 * 3 .. 258, the last 256 values correspond to the top 8 bits of
 * the 15 bit distances.}
  _dist_code: array[0..DIST_CODE_LEN - 1] of byte;

 // length code for each normalized match length (0 == MIN_MATCH)
  _length_code: array[0..MAX_MATCH - MIN_MATCH] of uch;

 // First normalized length for each code (0 = MIN_MATCH)
  base_length: array[0..LENGTH_CODES - 1] of integer;

 // First normalized distance for each code (0 = distance of 1)
  base_dist: array[0..D_CODES - 1] of integer;

  bl_order: array[0..BL_CODES] of uch;
{* The lengths of the bit length codes are sent in order of decreasing
 * probability, to avoid transmitting the lengths for unused bit length codes.}


  static_ltree: array[0..L_CODES + 2 - 1] of ct_data;
{* The static literal tree. Since the bit lengths are imposed, there is no
 * need for the L_CODES extra codes used during heap construction. However
 * The codes 286 and 287 are needed to build a canonical tree (see _tr_init
 * below).}
  static_dtree: array[0..D_CODES - 1] of ct_data;
{* The static distance tree. (Actually a trivial tree since all codes use
 * 5 bits.)}

  static_l_desc: static_tree_desc;
  static_d_desc: static_tree_desc;
  static_bl_desc: static_tree_desc;

const

  STORED_BLOCK = 0;
  STATIC_TREES = 1;
  DYN_TREES = 2;

  INIT_STATE = 42;
  BUSY_STATE = 113;
  FINISH_STATE = 666;
  EXTRA_STATE = 69;
  NAME_STATE = 73;
  COMMENT_STATE = 91;
  HCRC_STATE = 103;

  SMALLEST = 1;

  REP_3_6 = 16; // repeat previous bit length 3-6 times (2 bits of repeat count)
  REPZ_3_10 = 17; // repeat a zero length 3-10 times  (3 bits of repeat count)
  REPZ_11_138 = 18; //repeat a zero length 11-138 times  (7 bits of repeat count)

 {* Distance codes. The first 256 values correspond to the distances
 * 3 .. 258, the last 256 values correspond to the top 8 bits of
 * the 15 bit distances.}
  _dist_code_const: array[0..DIST_CODE_LEN - 1] of byte {uch} =
     ( 
    0, 1, 2, 3, 4, 4, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8,
    8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
      11,
    11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
      12,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 13, 13, 13,
      13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
      13,
    13, 13, 13, 13, 13, 13, 13, 13, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
      14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
      14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
      14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 15, 15, 15, 15, 15, 15, 15,
      15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
      15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
      15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 0, 0, 16,
      17,
    18, 18, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21, 22, 22, 22, 22, 22, 22, 22,
      22,
    23, 23, 23, 23, 23, 23, 23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
      24,
    24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
      25,
    26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26,
    26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 27, 27, 27, 27, 27, 27, 27,
      27,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
      27,
    27, 27, 27, 27, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
      28,
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
      28,
    28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
      28,
    28, 28, 28, 28, 28, 28, 28, 28, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
      29,
    29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
      29,
    29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29,
      29,
    29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29, 29
     ) ;

  _length_code_const: array[0..MAX_MATCH - MIN_MATCH] of byte = 
     ( 
    0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 12, 12,
    13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15, 16, 16, 16, 16, 16, 16, 16,
      16,
    17, 17, 17, 17, 17, 17, 17, 17, 18, 18, 18, 18, 18, 18, 18, 18, 19, 19, 19,
      19,
    19, 19, 19, 19, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20,
      20,
    21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 22, 22, 22,
      22,
    22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 23, 23, 23, 23, 23, 23, 23,
      23,
    23, 23, 23, 23, 23, 23, 23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
      24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
      24,
    25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
      25,
    25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 26, 26, 26, 26, 26, 26, 26,
      26,
    26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
      26,
    26, 26, 26, 26, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
      27,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 28
     ) ;


  base_length_const: array[0..LENGTH_CODES - 1] of integer =
     ( 
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56,
    64, 80, 96, 112, 128, 160, 192, 224, 0
     ) ;

  base_dist_const: array[0..D_CODES - 1] of integer = 
     ( 
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24,
    32, 48, 64, 96, 128, 192, 256, 384, 512, 768,
    1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576
     ) ;

  bl_order_const: array[0..BL_CODES - 1] of byte =
     ( 
    16, 17, 18, 0, 8, 7, 9, 6,
    10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
     ) ;

  extra_dbits_const: array[0..D_CODES - 1] of integer = 
     ( 
    0, 0, 0, 0, 1, 1, 2, 2,
    3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
     ) ;
    // extra bits for each distance code
  extra_lbits_const: array[0..LENGTH_CODES - 1] of integer = 
     ( 
    0, 0, 0, 0, 0, 0,
    0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
     ) ;

  extra_blbits_const: array[0..BL_CODES - 1] of integer = 
     ( 
    0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7
     ) ; // extra bits for each bit length code */

{* The static literal tree. Since the bit lengths are imposed, there is no
 * need for the L_CODES extra codes used during heap construction. However
 * The codes 286 and 287 are needed to build a canonical tree (see _tr_init
 * below).}
  static_ltree_const: array[0..L_CODES + 2 - 1] of ct_data = 
   (
    (Freq: 12; Dad: 8), (Freq: 140; Dad: 8), (Freq: 76; Dad: 8),
    (Freq: 204; Dad: 8), (Freq: 44; Dad: 8), (Freq: 172; Dad: 8),
    (Freq: 108; Dad: 8), (Freq: 236; Dad: 8), (Freq: 28; Dad: 8),
    (Freq: 156; Dad: 8), (Freq: 92; Dad: 8), (Freq: 220; Dad: 8),
    (Freq: 60; Dad: 8), (Freq: 188; Dad: 8), (Freq: 124; Dad: 8),
    (Freq: 252; Dad: 8), (Freq: 2; Dad: 8), (Freq: 130; Dad: 8),
    (Freq: 66; Dad: 8), (Freq: 194; Dad: 8), (Freq: 34; Dad: 8),
    (Freq: 162; Dad: 8), (Freq: 98; Dad: 8), (Freq: 226; Dad: 8),
    (Freq: 18; Dad: 8), (Freq: 146; Dad: 8), (Freq: 82; Dad: 8),
    (Freq: 210; Dad: 8), (Freq: 50; Dad: 8), (Freq: 178; Dad: 8),
    (Freq: 114; Dad: 8), (Freq: 242; Dad: 8), (Freq: 10; Dad: 8),
    (Freq: 138; Dad: 8), (Freq: 74; Dad: 8), (Freq: 202; Dad: 8),
    (Freq: 42; Dad: 8), (Freq: 170; Dad: 8), (Freq: 106; Dad: 8),
    (Freq: 234; Dad: 8), (Freq: 26; Dad: 8), (Freq: 154; Dad: 8),
    (Freq: 90; Dad: 8), (Freq: 218; Dad: 8), (Freq: 58; Dad: 8),
    (Freq: 186; Dad: 8), (Freq: 122; Dad: 8), (Freq: 250; Dad: 8),
    (Freq: 6; Dad: 8), (Freq: 134; Dad: 8), (Freq: 70; Dad: 8),
    (Freq: 198; Dad: 8), (Freq: 38; Dad: 8), (Freq: 166; Dad: 8),
    (Freq: 102; Dad: 8), (Freq: 230; Dad: 8), (Freq: 22; Dad: 8),
    (Freq: 150; Dad: 8), (Freq: 86; Dad: 8), (Freq: 214; Dad: 8),
    (Freq: 54; Dad: 8), (Freq: 182; Dad: 8), (Freq: 118; Dad: 8),
    (Freq: 246; Dad: 8), (Freq: 14; Dad: 8), (Freq: 142; Dad: 8),
    (Freq: 78; Dad: 8), (Freq: 206; Dad: 8), (Freq: 46; Dad: 8),
    (Freq: 174; Dad: 8), (Freq: 110; Dad: 8), (Freq: 238; Dad: 8),
    (Freq: 30; Dad: 8), (Freq: 158; Dad: 8), (Freq: 94; Dad: 8),
    (Freq: 222; Dad: 8), (Freq: 62; Dad: 8), (Freq: 190; Dad: 8),
    (Freq: 126; Dad: 8), (Freq: 254; Dad: 8), (Freq: 1; Dad: 8),
    (Freq: 129; Dad: 8), (Freq: 65; Dad: 8), (Freq: 193; Dad: 8),
    (Freq: 33; Dad: 8), (Freq: 161; Dad: 8), (Freq: 97; Dad: 8),
    (Freq: 225; Dad: 8), (Freq: 17; Dad: 8), (Freq: 145; Dad: 8),
    (Freq: 81; Dad: 8), (Freq: 209; Dad: 8), (Freq: 49; Dad: 8),
    (Freq: 177; Dad: 8), (Freq: 113; Dad: 8), (Freq: 241; Dad: 8),
    (Freq: 9; Dad: 8), (Freq: 137; Dad: 8), (Freq: 73; Dad: 8),
    (Freq: 201; Dad: 8), (Freq: 41; Dad: 8), (Freq: 169; Dad: 8),
    (Freq: 105; Dad: 8), (Freq: 233; Dad: 8), (Freq: 25; Dad: 8),
    (Freq: 153; Dad: 8), (Freq: 89; Dad: 8), (Freq: 217; Dad: 8),
    (Freq: 57; Dad: 8), (Freq: 185; Dad: 8), (Freq: 121; Dad: 8),
    (Freq: 249; Dad: 8), (Freq: 5; Dad: 8), (Freq: 133; Dad: 8),
    (Freq: 69; Dad: 8), (Freq: 197; Dad: 8), (Freq: 37; Dad: 8),
    (Freq: 165; Dad: 8), (Freq: 101; Dad: 8), (Freq: 229; Dad: 8),
    (Freq: 21; Dad: 8), (Freq: 149; Dad: 8), (Freq: 85; Dad: 8),
    (Freq: 213; Dad: 8), (Freq: 53; Dad: 8), (Freq: 181; Dad: 8),
    (Freq: 117; Dad: 8), (Freq: 245; Dad: 8), (Freq: 13; Dad: 8),
    (Freq: 141; Dad: 8), (Freq: 77; Dad: 8), (Freq: 205; Dad: 8),
    (Freq: 45; Dad: 8), (Freq: 173; Dad: 8), (Freq: 109; Dad: 8),
    (Freq: 237; Dad: 8), (Freq: 29; Dad: 8), (Freq: 157; Dad: 8),
    (Freq: 93; Dad: 8), (Freq: 221; Dad: 8), (Freq: 61; Dad: 8),
    (Freq: 189; Dad: 8), (Freq: 125; Dad: 8), (Freq: 253; Dad: 8),
    (Freq: 19; Dad: 9), (Freq: 275; Dad: 9), (Freq: 147; Dad: 9),
    (Freq: 403; Dad: 9), (Freq: 83; Dad: 9), (Freq: 339; Dad: 9),
    (Freq: 211; Dad: 9), (Freq: 467; Dad: 9), (Freq: 51; Dad: 9),
    (Freq: 307; Dad: 9), (Freq: 179; Dad: 9), (Freq: 435; Dad: 9),
    (Freq: 115; Dad: 9), (Freq: 371; Dad: 9), (Freq: 243; Dad: 9),
    (Freq: 499; Dad: 9), (Freq: 11; Dad: 9), (Freq: 267; Dad: 9),
    (Freq: 139; Dad: 9), (Freq: 395; Dad: 9), (Freq: 75; Dad: 9),
    (Freq: 331; Dad: 9), (Freq: 203; Dad: 9), (Freq: 459; Dad: 9),
    (Freq: 43; Dad: 9), (Freq: 299; Dad: 9), (Freq: 171; Dad: 9),
    (Freq: 427; Dad: 9), (Freq: 107; Dad: 9), (Freq: 363; Dad: 9),
    (Freq: 235; Dad: 9), (Freq: 491; Dad: 9), (Freq: 27; Dad: 9),
    (Freq: 283; Dad: 9), (Freq: 155; Dad: 9), (Freq: 411; Dad: 9),
    (Freq: 91; Dad: 9), (Freq: 347; Dad: 9), (Freq: 219; Dad: 9),
    (Freq: 475; Dad: 9), (Freq: 59; Dad: 9), (Freq: 315; Dad: 9), // (Freq: 15; Dad :9)
    (Freq: 187; Dad: 9), (Freq: 443; Dad: 9), (Freq: 123; Dad: 9),
    (Freq: 379; Dad: 9), (Freq: 251; Dad: 9), (Freq: 507; Dad: 9),
    (Freq: 7; Dad: 9), (Freq: 263; Dad: 9), (Freq: 135; Dad: 9),
    (Freq: 391; Dad: 9), (Freq: 71; Dad: 9), (Freq: 327; Dad: 9),
    (Freq: 199; Dad: 9), (Freq: 455; Dad: 9), (Freq: 39; Dad: 9),
    (Freq: 295; Dad: 9), (Freq: 167; Dad: 9), (Freq: 423; Dad: 9),
    (Freq: 103; Dad: 9), (Freq: 359; Dad: 9), (Freq: 231; Dad: 9),
    (Freq: 487; Dad: 9), (Freq: 23; Dad: 9), (Freq: 279; Dad: 9),
    (Freq: 151; Dad: 9), (Freq: 407; Dad: 9), (Freq: 87; Dad: 9),
    (Freq: 343; Dad: 9), (Freq: 215; Dad: 9), (Freq: 471; Dad: 9),
    (Freq: 55; Dad: 9), (Freq: 311; Dad: 9), (Freq: 183; Dad: 9),
    (Freq: 439; Dad: 9), (Freq: 119; Dad: 9), (Freq: 375; Dad: 9),
    (Freq: 247; Dad: 9), (Freq: 503; Dad: 9), (Freq: 15; Dad: 9),
    (Freq: 271; Dad: 9), (Freq: 143; Dad: 9), (Freq: 399; Dad: 9),
    (Freq: 79; Dad: 9), (Freq: 335; Dad: 9), (Freq: 207; Dad: 9),
    (Freq: 463; Dad: 9), (Freq: 47; Dad: 9), (Freq: 303; Dad: 9),
    (Freq: 175; Dad: 9), (Freq: 431; Dad: 9), (Freq: 111; Dad: 9),
    (Freq: 367; Dad: 9), (Freq: 239; Dad: 9), (Freq: 495; Dad: 9),
    (Freq: 31; Dad: 9), (Freq: 287; Dad: 9), (Freq: 159; Dad: 9),
    (Freq: 415; Dad: 9), (Freq: 95; Dad: 9), (Freq: 351; Dad: 9),
    (Freq: 223; Dad: 9), (Freq: 479; Dad: 9), (Freq: 63; Dad: 9),
    (Freq: 319; Dad: 9), (Freq: 191; Dad: 9), (Freq: 447; Dad: 9),
    (Freq: 127; Dad: 9), (Freq: 383; Dad: 9), (Freq: 255; Dad: 9),
    (Freq: 511; Dad: 9), (Freq: 0; Dad: 7), (Freq: 64; Dad: 7),
    (Freq: 32; Dad: 7), (Freq: 96; Dad: 7), (Freq: 16; Dad: 7),
    (Freq: 80; Dad: 7), (Freq: 48; Dad: 7), (Freq: 112; Dad: 7),
    (Freq: 8; Dad: 7), (Freq: 72; Dad: 7), (Freq: 40; Dad: 7),
    (Freq: 104; Dad: 7), (Freq: 24; Dad: 7), (Freq: 88; Dad: 7),
    (Freq: 56; Dad: 7), (Freq: 120; Dad: 7), (Freq: 4; Dad: 7),
    (Freq: 68; Dad: 7), (Freq: 36; Dad: 7), (Freq: 100; Dad: 7),
    (Freq: 20; Dad: 7), (Freq: 84; Dad: 7), (Freq: 52; Dad: 7),
    (Freq: 116; Dad: 7), (Freq: 3; Dad: 8), (Freq: 131; Dad: 8),
    (Freq: 67; Dad: 8), (Freq: 195; Dad: 8), (Freq: 35; Dad: 8),
    (Freq: 163; Dad: 8), (Freq: 99; Dad: 8), (Freq: 227; Dad: 8)
   );

{* The static distance tree. (Actually a trivial tree since all codes use
 * 5 bits.)}
  static_dtree_const: array[0..D_CODES - 1] of ct_data = 
   (
    (Freq: 0; Dad: 5), (Freq: 16; Dad: 5), (Freq: 8; Dad: 5),
    (Freq: 24; Dad: 5), (Freq: 4; Dad: 5), (Freq: 20; Dad: 5),
    (Freq: 12; Dad: 5), (Freq: 28; Dad: 5), (Freq: 2; Dad: 5),
    (Freq: 18; Dad: 5), (Freq: 10; Dad: 5), (Freq: 26; Dad: 5),
    (Freq: 6; Dad: 5), (Freq: 22; Dad: 5), (Freq: 14; Dad: 5),
    (Freq: 30; Dad: 5), (Freq: 1; Dad: 5), (Freq: 17; Dad: 5),
    (Freq: 9; Dad: 5), (Freq: 25; Dad: 5), (Freq: 5; Dad: 5),
    (Freq: 21; Dad: 5), (Freq: 13; Dad: 5), (Freq: 29; Dad: 5),
    (Freq: 3; Dad: 5), (Freq: 19; Dad: 5), (Freq: 11; Dad: 5),
    (Freq: 27; Dad: 5), (Freq: 7; Dad: 5), (Freq: 23; Dad: 5)
   );

{$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
procedure DumpTrees(s: internal_state_s);
var
  I : integer;
  Str: string;
begin
  Str := '';
  for I := 0 to 573 do
  begin
    Str := Str + ' (' +
      IntToStr(s.dyn_ltree[I].Freq) + ',' +
      IntToStr(s.dyn_ltree[I].Dad) + ',' +
      IntToStr(s.dyn_ltree[I].Code) + ',' +
      IntToStr(s.dyn_ltree[I].Len) + ')';
  end;
  Dumper.WriteString('LTree: ' + Str);
  Str := '';
  for I := 0 to 61 do
  begin
    Str := Str + ' (' +
      IntToStr(s.dyn_dtree[I].Freq) + ',' +
      IntToStr(s.dyn_dtree[I].Dad) + ',' +
      IntToStr(s.dyn_dtree[I].Code) + ',' +
      IntToStr(s.dyn_dtree[I].Len) + ')';
  end;
  Dumper.WriteString('DTree: ' + Str);
  Str := '';
  for I := 0 to 39 do
  begin
    Str := Str + ' (' +
      IntToStr(s.bl_tree[I].Freq) + ',' +
      IntToStr(s.bl_tree[I].Dad) + ',' +
      IntToStr(s.bl_tree[I].Code) + ',' +
      IntToStr(s.bl_tree[I].Len) + ')';
  end;
  Dumper.WriteString('BLTree: ' + Str);
end;

procedure DumpState(s: internal_state_s);
var
  Str : string;
begin
  Str := 'S=' + IntToStr(s.status) + ',P=' + IntToStr(s.pending) + ',W=' +
    IntToStr(s.Wrap) + ',DT=' + IntToStr(s.Data_Type) + ',M=' + IntToStr(s.method) +
    'LF=' + IntToStr(s.last_flush) + 'WS=' + IntToStr(s.w_size) + ',WB=' +
    IntToStr(s.w_bits) + ',WM=' + IntToStr(s.w_mask) + ',WinS=' +
    IntToStr(s.window_size) + ',IH=' + IntToStr(s.ins_h) + ',BS=' + IntToStr(s.block_start) +
    ',ML=' + IntToStr(s.match_length) + ',PM=' + IntToStr(s.prev_match) +
    ',MA=' + IntToStr(s.match_available) + ',SS=' + IntToStr(s.strstart) +
    ',MS=' + IntToStr(s.match_start) + ',LA=' + IntToStr(s.lookahead) +
    ',PL=' + IntToStr(s.prev_length) + ',MCL=' + IntToStr(s.max_chain_length) +
    ',MLM=' + IntToStr(s.max_lazy_match) + ',L=' + IntToStr(s.level) +
    ',S=' + IntToStr(s.strategy) + ',GM=' + IntToStr(s.good_match) +
    ',NM=' + IntToStr(s.nice_match) + ',HL=' + IntToStr(s.heap_len) +
    ',HM=' + IntToStr(s.heap_max) + ',LL=' + IntToStr(s.last_lit) +
    ',OL=' + IntToStr(s.opt_len) + ',SL=' + IntToStr(s.static_len) +
    ',M=' + IntToStr(s.matches) + ',BB=' + IntToStr(s.bi_buf) +
    ',BV=' + IntToStr(s.bi_valid);
  Dumper.WriteString('state: ' + Str);
  DumpTrees(s);
end;
 {$endif}

function ERR_MSG(err: integer): string;
begin
  result := z_errmsg[Z_NEED_DICT - err];
end;

function ERR_RETURN(var strm: TZStreamRec; err: integer): byte;
begin
  strm.msg := PChar(ERR_MSG(err));
  result := err;
end;

(*procedure put_byte(var s: internal_state_s; c: byte);
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('put_byte(' + {$ifndef SB_NET}IntToHex(c, 2){$else}c.ToString('X2'){$endif} + ')');
  {$endif}
  {$ifndef SB_VCL}
  s.pending_buf[s.pending] := c;
  {$else}
  s.pending_buf^[s.pending] := c;
  {$endif}
  inc(s.pending);
end; *)

procedure putShortMSB(var s: internal_state_s; b: uInt);
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('putShortMSB(' +  IntToHex(b, 4)  + ')');
   {$endif}
  s.pending_buf^[s.pending] := b shr 8;
  inc(s.pending);
  s.pending_buf^[s.pending] := b and $ff;
  inc(s.pending);
end;

{* =========================================================================
 * Flush as much pending output as possible. All deflate() output goes
 * through this function so some applications may wish to modify it
 * to avoid allocating a large strm->next_out buffer and copying into it.
 * (See also read_buf()).}

procedure flush_pending(var strm: TZStreamRec);
var
  len: unsigned;
//  byteftmp: Bytef;
//  i: word;
begin
  len := internal_state(strm.internal).pending; // as internal_state;
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('flush_pending(' + IntToStr(len) + ')');
   {$endif}

  if (len > unsigned(strm.avail_out)) then len := strm.avail_out;
  if (len = 0) then exit;
  // added by II
  SBMove(internal_state_s(strm.internal^).pending_out^, strm.next_out[0], len);
  // II's adding end

  strm.next_out := @strm.next_out[len];
  internal_state(strm.internal).pending_out := @(internal_state(strm.internal).pending_out[len]);
  strm.total_out := strm.total_out + integer(len);
  strm.avail_out := strm.avail_out - integer(len);
  internal_state(strm.internal).pending := internal_state(strm.internal).pending
    - integer(len);
  if (internal_state(strm.internal).pending = 0) then
  begin
    internal_state(strm.internal).pending_out := internal_state(strm.internal).pending_buf;
  end;
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  DumpState(internal_state(strm.internal) ^ );
   {$endif}
end;

// replaced by inline code
{function MAX_DIST(const s: internal_state_s): uInt;
begin
  result := s.w_size - MIN_LOOKAHEAD;
end;}

{* ===========================================================================
 * Read a new buffer from the current input stream, update the adler32
 * and total number of bytes read.  All deflate() input goes through
 * this function so some applications may wish to modify it to avoid
 * allocating a large strm->next_in buffer and copying from it.
 * (See also flush_pending()).
 *}

function read_buf(var strm: TZStreamRec; var buf: Bytef; size, start: unsigned):
  integer;
var
  len: unsigned;
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('read_buf()');
   {$endif}

  len := strm.avail_in;

  if (len > size) then len := size;
  if (len = 0) then
  begin
    result := 0;
    exit;
  end;

  strm.avail_in := strm.avail_in - integer(len);

  if (internal_state(strm.internal).wrap = 1) then
  begin
    strm.adler := adler32(strm.adler, strm.next_in, len);
  end;

  ZlibMemCpy(buf, strm.next_in, len);
  strm.next_in := @strm.next_in[len];
  strm.total_in := strm.total_in + integer(len);

  result := integer(len);
end;

{* ===========================================================================
 * Update a hash value with the given input byte
 * IN  assertion: all calls to to UPDATE_HASH are made with consecutive
 *    input characters, so that a running hash key can be computed from the
 *    previous key instead of complete recalculation each time.}

procedure UPDATE_HASH(var s: internal_state_s; var h: uInt; c: byte);
begin
  h := ((h shl s.hash_shift) xor c) and s.hash_mask;
end;

{* ===========================================================================
 * Fill the window when the lookahead becomes insufficient.
 * Updates strstart and lookahead.
 *
 * IN assertion: lookahead < MIN_LOOKAHEAD
 * OUT assertions: strstart <= window_size-MIN_LOOKAHEAD
 *    At least one byte has been read, or avail_in == 0; reads are
 *    performed for at least two bytes (required for the zip translate_eol
 *    option -- not supported here).}

procedure fill_window(var s: internal_state_s);
var
  n, m: unsigned;
  p: Posf;
  more: unsigned; // Amount of free space at the end of the window.
  wsize1: uInt;
  ArrP : ArrayPtr;
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('fill_window()');
  Dumper.BeginSubsection;
  DumpState(s);
   {$endif}

  wsize1 := unsigned(s.w_size);

  repeat
    more := unsigned(s.window_size - ulg(s.lookahead) - ulg(s.strstart));
        // Deal with !@#$% 64K limit: */
//  if (sizeof(int) <= 2) ... a iii aieuoa ... eiiiaioe?oai
{    if ((more = 0) and (s.strstart = 0) and (s.lookahead = 0)) then
    begin
      more := wsize1;
    end
    else
      if (more = unsigned(-1)) then
    begin
      dec(more);

    end
    else}

    if (s.strstart >= (wsize1 + s.w_size - MIN_LOOKAHEAD)) then
    begin

      ZlibMemCpy(s.window, Pointer(PtrUInt(s.window) + wsize1), unsigned(wsize1));
      {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
      Dumper.WriteString('[0]');
      Dumper.WriteBinary(s.window, unsigned(wsize1));
       {$endif}
      s.match_start := s.match_start - wsize1;
      s.strstart := s.strstart - wsize1; // we now have strstart >= MAX_DIST
      s.block_start := s.block_start - long(wsize1);

                 {* Slide the hash table (could be avoided with 32 bit values
                    at the expense of memory usage). We slide even when level == 0
                    to keep the hash table consistent if we switch back to level > 0
                    later. (Using level 0 permanently is not an optimal usage of
                    zlib, so we don't care about this pathological case.)}
      n := s.hash_size;
      p := @s.head[n];
      repeat
        p := Pointer(PtrUInt(@p[0]) - Cardinal(sizeof(Word)));
        m := p[0];
        if (m >= wsize1) then
          p[0] := m - wsize1
        else
          p[0] := 0;
        dec(n);
      until (not (n <> 0));
      n := wsize1;
      { II begin }
      p := @s.prev[n];
      repeat
        p := pointer(PtrUInt(@p[0]) - cardinal(sizeof(word)));
        m := p[0];
        if m >= wsize1 then
          p[0] := m - wsize1
        else
          p[0] := 0;
        dec(n);
      until (n = 0);

      { II end }
      more := more + wsize1;
    end;
    if (s.strm.avail_in = 0) then begin {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}Dumper.EndSubsection; {$endif} exit; end;

        {* If there was no sliding:
         *    strstart <= WSIZE+MAX_DIST-1 && lookahead <= MIN_LOOKAHEAD - 1 &&
         *    more == window_size - lookahead - strstart
         * => more >= window_size - (MIN_LOOKAHEAD-1 + WSIZE + MAX_DIST-1)
         * => more >= window_size - 2*WSIZE + 2
         * In the BIG_MEM or MMAP case (not yet supported),
         *   window_size == input_size + MIN_LOOKAHEAD  &&
         *   strstart + s->lookahead <= input_size => more >= MIN_LOOKAHEAD.
         * Otherwise, window_size == 2*WSIZE so more >= 2.
         * If there was sliding, more >= WSIZE. So in all cases, more >= 2.}
    Assert((more >= 2), 'more < 2');

    // II ++
    ArrP := pointer(PtrUInt(s.window) + s.strstart + s.lookahead);
    n := read_buf(s.strm^, ArrP, unsigned(more), unsigned(s.strstart +
      s.lookahead));
    {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
    Dumper.WriteString('[1]');
    Dumper.WriteBinary(pointer(PtrUInt(s.window) + s.strstart + s.lookahead), n);
     {$endif}
//    n := read_buf(s.strm^, s.window, unsigned(more), unsigned(s.strstart +
//      s.lookahead));

    s.lookahead := s.lookahead + n;

        // Initialize the hash value now that we have some input:
    if (s.lookahead >= MIN_MATCH) then
    begin
      s.ins_h := s.window[s.strstart];
      UPDATE_HASH(s, s.ins_h, s.window[s.strstart + 1]);
    end;
  until not ((s.lookahead < MIN_LOOKAHEAD) and (s.strm.avail_in <> 0));


  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  DumpState(s);
  Dumper.EndSubsection;
   {$endif}
end;

{* ===========================================================================
 * Set the data type to ASCII or BINARY, using a crude approximation:
 * binary if more than 20% of the bytes are <= 6 or >= 128, ascii otherwise.
 * IN assertion: the fields freq of dyn_ltree are set and the total of all
 * frequencies does not exceed 64K (to fit in an int on 16 bit machines).}

procedure set_data_type(var s: internal_state_s);
var
  n: integer;
  //ascii_freq: unsigned;
  //bin_freq: unsigned;
begin
{  n := 0;
  ascii_freq := 0;
  bin_freq := 0;
  while (n < 7) do
  begin
    bin_freq := bin_freq + unsigned(s.dyn_ltree[n].Freq);
    inc(n);
  end;
  while (n < 128) do
  begin
    ascii_freq := ascii_freq + unsigned(s.dyn_ltree[n].Freq);
    inc(n);
  end;
  while (n < LITERALS) do
  begin
    bin_freq := bin_freq + unsigned(s.dyn_ltree[n].Freq);
    inc(n);
  end;
  if (bin_freq > (ascii_freq shr 2)) then
    s.strm.data_type := Byte(Z_BINARY)
  else
    s.strm.data_type := Byte(Z_ASCII);
} // zlib 1.2.3 update
  for n := 0 to 8 do
    if s.dyn_ltree[n].{$ifndef NET_CF_1_0}Freq {$else}Code {$endif} <> 0 then
      Break;
  if (n = 9) then
    for n := 14 to 31 do
      if s.dyn_ltree[n].{$ifndef NET_CF_1_0}Freq {$else}Code {$endif} <> 0 then
        Break;
  if n = 32 then
    s.strm.data_type := Z_TEXT
  else
    s.strm.data_type := Z_BINARY;
end;

{$ifdef CLX_USED}
type BOOL = WordBool;
 {$endif}

{* ===========================================================================
 * Compares to subtrees, using the tree depth as tie breaker when
 * the subtrees have equal frequency. This minimizes the worst case length.}

function smaller(tree: ArrayCtPtr; n, m: integer; depth: ArrayPtr): BOOL;
begin
  result := ((tree[n].Freq < tree[m].Freq) or ((tree[n].Freq = tree[m].Freq) and
    (depth^[n] <= depth^[m])));
end;

{* ===========================================================================
 * Restore the heap property by moving down the tree starting at node k,
 * exchanging a node with the smallest of its two sons if necessary, stopping
 * when the heap property is re-established (each father smaller than its
 * two sons).}

procedure pqdownheap(var s: internal_state_s; tree: ArrayCtPtr
  { the tree to restore}; k: integer {node to move down});
var
  v: integer;
  j: integer;
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('pqdownheap(' + IntToStr(k) + ')');
   {$endif}
  v := s.heap[k];
  j := k shl 1; // left son of k
  while (j <= s.heap_len) do
  begin
      // Set j to the smallest of the two sons:
    if ((j < s.heap_len) and smaller(tree, s.heap[j + 1], s.heap[j], @s.depth))
      then
    begin
      inc(j);
    end;
      // Exit if v is smaller than both sons
    if (smaller(tree, v, s.heap[j], @s.depth)) then break;

      // Exchange v with the smallest son
    s.heap[k] := s.heap[j];
    k := j;

      // And continue down the tree, setting j to the left son of k
    j := j shl 1;
  end;
  s.heap[k] := v;
end;

{* ===========================================================================
 * Remove the smallest element from the heap and recreate the heap with
 * one less element. Updates heap and heap_len.}

procedure pqremove(var s: internal_state_s; tree: ArrayCtPtr; var top: integer);
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('pqremove()');
   {$endif}
  top := s.heap[SMALLEST];
  s.heap[SMALLEST] := s.heap[s.heap_len];
  dec(s.heap_len);
  pqdownheap(s, tree, SMALLEST);
end;

function MAX(a, b: integer): integer;
begin
  if a >= b then
    result := a
  else
    result := b;
end;

{* ===========================================================================
 * Compute the optimal bit lengths for a tree and update the total bit length
 * for the current block.
 * IN assertion: the fields freq and dad are set, heap[heap_max] and
 *    above are the tree nodes sorted by increasing frequency.
 * OUT assertions: the field len is set to the optimal bit length, the
 *     array bl_count contains the frequencies for each bit length.
 *     The length opt_len is updated; static_len is also updated if stree is
 *     not null.}

procedure gen_bitlen(var s: internal_state_s; var desc: tree_desc
  {the tree descriptor});
var
  tree: ArrayCtPtr;
  max_code: integer;
  stree: ArrayCtPtr;
  extra: intf;
  base: integer;
  max_length: integer;
  h: integer; // heap index
  n, m: integer; // iterate over the tree elements
  bits: integer; // bit length
  xbits: integer; // extra bits
  f: ush; // frequency
  overflow: integer; // number of elements with bit length too large
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('gen_bitlen()');
  DumpState(s);
   {$endif}
  tree := desc.dyn_tree;
  max_code := desc.max_code;
  stree := desc.stat_desc.static_tree;
  extra := desc.stat_desc.extra_bits;
  base := desc.stat_desc.extra_base;
  max_length := desc.stat_desc.max_length;
  overflow := 0;

  for bits := 0 to MAX_BITS do
    s.bl_count[bits] := 0;
   
    {* In a first pass, compute the optimal bit lengths (which may
     * overflow in the case of the bit length tree).}

  tree^[s.heap[s.heap_max]].Len := 0; // root of the heap
  
  h := s.heap_max + 1;
  while  h <= HEAP_SIZE - 1 do
  begin
    n := s.heap[h];
    bits := tree^[tree^[n].Dad].Len + 1;
    
    if (bits > max_length) then
    begin
      bits := max_length;
      inc(overflow)
    end;
    tree^[n].Len := ush(bits);
        // We overwrite tree[n].Dad which is no longer needed

    if (n > max_code) then
    begin
      inc(h);
      continue;
    end; // not a leaf node

    Inc(s.bl_count[bits]);
    xbits := 0;
    if (n >= base) then xbits := extra[n - base];
    f := tree^[n].Freq;
    s.opt_len := s.opt_len + ulg(f * (bits + xbits));
    {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
    WriteStringToFile('[1] opt_len=' + IntToStr(s.opt_len), 'D:\Temp\z\output_p');
     {$endif}

    if (stree <> nil) then
      s.static_len := s.static_len + ulg(f * (stree^[n].Len + xbits));
    inc(h);
  end;
  if overflow = 0 then 
    Exit;

    //  ********* Trace((stderr,'\nbit length overflow\n'));
    // This happens for example on obj2 and pic of the Calgary corpus

    // Find the first bit length which could increase: */
  repeat
    begin
      bits := max_length - 1;
      while (s.bl_count[bits] = 0) do
        dec(bits);
      dec(s.bl_count[bits]); // move one leaf down the tree
      s.bl_count[bits + 1] := s.bl_count[bits + 1] + 2;
        // move one overflow item as its brother
      dec(s.bl_count[max_length]);
        {* The brother of the overflow item also moves one step up,
         * but this does not affect bl_count[max_length]}
      overflow := overflow - 2;
    end;
  until not (overflow > 0); //------- Yoo eaeueo n N io?ii iioii eni?aaeou !!!
  
    {* Now recompute all bit lengths, scanning in increasing frequency.
     * h is still equal to HEAP_SIZE. (It is simpler to reconstruct all
     * lengths instead of fixing only the wrong ones. This idea is taken
     * from 'ar' written by Haruhiko Okumura.)}
  for bits := max_length downto 0 do
  begin
    n := s.bl_count[bits];
    while (n <> 0) do
    begin
      dec(h); // II 251103
//      m := s.heap[- -h];
      m := s.heap[h];
      if (m > max_code) then continue;
      if (tree^[m].Len <> bits) then
      begin
        // Trace((stderr,"code %d bits %d->%d\n", m, tree[m].Len, bits));
        s.opt_len := s.opt_len + (ulg(bits) - ulg(tree^[m].Len)) * ulg(tree^[m].Freq);
        tree^[m].Len := ush(bits);
      end;
      dec(n);
    end;
  end;
end;

{* ===========================================================================
 * Reverse the first len bits of a code, using straightforward code (a faster
 * method would use a table)
 * IN assertion: 1 <= len <= 15}

function bi_reverse(code: ush; len: integer): unsigned;
{    unsigned code; /* the value to invert */
    int len;       /* its bit length */  }
var
  res: unsigned;
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('bi_reverse(' +  IntToHex(code, 4)  + 
        ', ' +  IntToHex(len, 8)  + ')');
   {$endif}
  res := 0;
  repeat
    begin
      res := res or (code and 1);
      code := code shr 1;
      res := res shl 1;
      dec(len);
    end;
  until not (len > 0); //----- Eni?aaeou yoo eaeueo ec N ia ii?iaeuiia oneiaea
  result := res shr 1;
end;

{* ===========================================================================
 * Generate the codes for a given tree and bit counts (which need not be
 * optimal).
 * IN assertion: the array bl_count contains the bit length statistics for
 * the given tree and the field len is set for all tree elements.
 * OUT assertion: the field code is set for all tree elements of non
 *     zero code length.}

procedure gen_codes(tree: ArrayCtPtr; max_code: integer; bl_count: ushf);
{    tree;            /* the tree to decorate
    max_code;         /* largest code with non zero frequency
    bl_count;         /* number of codes at each bit length}
var
  next_code: array[0..MAX_BITS] of ush; // next code value for each bit length
  code: ush; // running code value
  bits: integer; // bit index
  n: integer; // code index
  len: integer;
begin
//    ush next_code[MAX_BITS+1];
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('gen_codes(,' + IntToStr(max_code) + ',)');
   {$endif}
  code := 0;

    {* The distribution counts are first used to generate the code values
     * without bit reversal.}
  for bits := 1 to MAX_BITS do
  begin
    next_code[bits] := (code + bl_count[bits - 1]) shl 1;
    code := (code + bl_count[bits - 1]) shl 1;
  end;
    {* Check that the bit counts in bl_count are consistent. The last code
     * must be all ones.}
  Assert(code + bl_count[MAX_BITS] - 1 = (1 shl MAX_BITS) - 1,
    'inconsistent bit counts');
//  *******************  Tracev((stderr,"\ngen_codes: max_code %d ", max_code));

  for n := 0 to max_code do
  begin
    len := tree^[n].Len;
    if len = 0 then continue;
    // Now reverse the bits
    tree^[n].Code := bi_reverse(next_code[len], len);
    inc(next_code[len]);
//        Tracecv(tree != static_ltree, (stderr,"\nn %3d %c l %2d c %4x (%x) ",
//             n, (isgraph(n) ? n : ' '), len, tree[n].Code, next_code[len]-1));
  end;
end;

procedure build_tree(var s: internal_state_s; var desc: tree_desc
  {the tree descriptor});
var
  tree: ArrayCtPtr;
  stree: ArrayCtPtr;
  elems: integer;
  n, m: integer; // iterate over heap elements
  max_code: integer; // largest code with non zero frequency
  node: integer; // new node being created
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('build_tree()');
  Dumper.BeginSubsection;
  DumpState(s);
   {$endif}
  tree := desc.dyn_tree;
  stree := desc.stat_desc.static_tree;
  elems := desc.stat_desc.elems;
  max_code := -1;

 {* Construct the initial heap, with least frequent element in
  * heap[SMALLEST]. The sons of heap[n] are heap[2*n] and heap[2*n+1].
  * heap[0] is not used.}
  s.heap_len := 0;
  s.heap_max := HEAP_SIZE;

  for n := 0 to elems - 1 do
  begin
    if (tree^[n].Freq <> 0) then
    begin
      inc(s.heap_len);
      s.heap[s.heap_len] := n;
      max_code := n;
      s.depth[n] := 0;
    end
    else
    begin
      tree^[n].Len := 0;
    end;
  end;
  
    {* The pkzip format requires that at least one distance code exists,
     * and that at least one bit should be sent even if there is only one
     * possible code. So to avoid special checks later on we force at least
     * two codes of non zero frequency.}

  while (s.heap_len < 2) do
  begin
    inc(s.heap_len);
    if ((max_code - 1) < 2) then
    begin
      inc(max_code);
      node := max_code;
      s.heap[s.heap_len] := max_code;
    end
    else
    begin
      node := 0;
      s.heap[s.heap_len] := 0;
    end;
    tree^[node].Freq := 1;
    s.depth[node] := 0;
    dec(s.opt_len);
    {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
    WriteStringToFile('[2] opt_len=' + IntToStr(s.opt_len), 'D:\Temp\z\output_p');
     {$endif}
    if (@stree <> nil) then s.static_len := s.static_len - ulg(stree^[node].Len);
        // node is 0 or 1 so it does not have extra bits */
  end;
  desc.max_code := max_code;

    {* The elements heap[heap_len/2+1 .. heap_len] are leaves of the tree,
     * establish sub-heaps of increasing lengths:}
  for n := s.heap_len shr 1 downto 1 do
    pqdownheap(s, tree, n);

    {* Construct the Huffman tree by repeatedly combining the least two
     * frequent nodes.}
  node := elems; // next internal node of the tree
  repeat
    begin
      pqremove(s, tree, n); // n = node of least frequency
      m := s.heap[SMALLEST]; // m = node of next least frequency

      dec(s.heap_max);
      s.heap[s.heap_max] := n; // keep the nodes sorted by frequency
      dec(s.heap_max);
      s.heap[s.heap_max] := m;

      // Create a new node father of n and m
      tree^[node].Freq := tree^[n].Freq + tree^[m].Freq;
      // replaced by II 21 Feb 2005
//      s.depth[node] := uch(MAX(s.depth[n], s.depth[m] + 1));
      s.depth[node] := uch(MAX(s.depth[n], s.depth[m]) + 1);
      tree^[n].Dad := ush(node);
      tree^[m].Dad := ush(node);
      // and insert the new node in the heap
      s.heap[SMALLEST] := node;
      inc(node);
      pqdownheap(s, tree, SMALLEST);
    end
  until not (s.heap_len >= 2); //Iiiaiyou ia ii?iaeuiia oneiaea (yoi eaeuea n N)

  dec(s.heap_max);
  s.heap[s.heap_max] := s.heap[SMALLEST];

    {* At this point, the fields freq and dad are set. We can now
     * generate the bit lengths.}
     
  gen_bitlen(s, desc);

  // The field len is now set, we can generate the bit codes
  gen_codes(tree, max_code, @s.bl_count[0]);

  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  DumpState(s);
  Dumper.EndSubsection;
   {$endif}
end;

{* ===========================================================================
 * Scan a literal or distance tree to determine the frequencies of the codes
 * in the bit length tree.}

procedure scan_tree(var s: internal_state_s; tree: ArrayCtPtr; var max_code:
  integer);
{    deflate_state *s;
    ct_data *tree;   /* the tree to be scanned */
    int max_code;    /* and its largest code of non zero frequency */}
var
  n: integer; // iterates over all tree elements
  prevlen: integer; // last emitted length
  curlen: integer; // length of current code
  nextlen: integer; // length of next code
  count: integer; // repeat count of the current code
  max_count: integer; // max repeat count
  min_count: integer; // min repeat count
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('scan_tree()');
   {$endif}

  prevlen := -1; // last emitted length
  nextlen := tree^[0].Len; // length of next code
  count := 0; // repeat count of the current code
  max_count := 7; // max repeat count
  min_count := 4; // min repeat count

  if (nextlen = 0) then
  begin
    max_count := 138;
    min_count := 3;
  end;
  tree^[max_code + 1].Len := ush($FFFF); // guard

  for n := 0 to max_code do
  begin
    curlen := nextlen;
    nextlen := tree^[n + 1].Len;
    inc(count);
    if ((count < max_count) and (curlen = nextlen)) then
      continue
    else
      if (count < min_count) then
      {$ifndef NET_CF_1_0}
        s.bl_tree[curlen].Freq := s.bl_tree[curlen].Freq + count
       {$else}
        s.bl_tree[curlen].Code := s.bl_tree[curlen].Code + count
       {$endif}
    else
      if (curlen <> 0) then
    begin
      if (curlen <> prevlen) then
        inc(s.bl_tree[curlen].{$ifndef NET_CF_1_0}Freq {$else}Code {$endif});
      inc(s.bl_tree[REP_3_6].{$ifndef NET_CF_1_0}Freq {$else}Code {$endif});
    end
    else
      if (count <= 10) then
      inc(s.bl_tree[REPZ_3_10].{$ifndef NET_CF_1_0}Freq {$else}Code {$endif})
    else
      inc(s.bl_tree[REPZ_11_138].{$ifndef NET_CF_1_0}Freq {$else}Code {$endif});
    count := 0;
    prevlen := curlen;
    if (nextlen = 0) then
    begin
      max_count := 138;
      min_count := 3;
    end
    else
      if (curlen = nextlen) then
    begin
      max_count := 6;
      min_count := 3;
    end
    else
    begin
      max_count := 7;
      min_count := 4
    end;
  end;
end;

function build_bl_tree(var s: internal_state_s): integer;
var
  max_blindex: integer; // index of last bit length code of non zero freq
begin
    // Determine the bit length frequencies for literal and distance trees
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('build_bl_tree()');
  Dumper.BeginSubsection;
  DumpState(s);
   {$endif}

  scan_tree(s, @s.dyn_ltree, s.l_desc.max_code);
  scan_tree(s, @s.dyn_dtree, s.d_desc.max_code);

    // Build the bit length tree:
  build_tree(s, s.bl_desc);
    {* opt_len now includes the length of the tree representations, except
     * the lengths of the bit lengths codes and the 5+5+4 bits for the counts.}

    {* Determine the number of bit length codes to send. The pkzip format
     * requires that at least 4 bit length codes be sent. (appnote.txt says
     * 3 but the actual value used is 4.)}
  for max_blindex := BL_CODES - 1 downto 3 do
    if (s.bl_tree[bl_order[max_blindex]]. Len  <> 0) then break;

    //* Update opt_len to include the bit length tree and counts
  s.opt_len := s.opt_len + 3 * (ulg(max_blindex) + 1) + 5 + 5 + 4;
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  WriteStringToFile('[3] opt_len=' + IntToStr(s.opt_len), 'D:\Temp\z\output_p');
   {$endif}
//    Tracev((stderr, "\ndyn trees: dyn %ld, stat %ld", s->opt_len, s->static_len));

  result := max_blindex;

  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  DumpState(s);
  Dumper.EndSubsection;
   {$endif}
end;

{* ===========================================================================
 * Output a short LSB first on the stream.
 * IN assertion: there is enough room in pendingBuf.}

procedure put_short(var s: internal_state_s; w: word);
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('put_short(' +  IntToHex(w, 4)  + ')');
   {$endif}
  s.pending_buf^[s.pending] := w and $ff;
  inc(s.pending);
  s.pending_buf^[s.pending] := w shr 8;
  inc(s.pending);
end;

procedure send_bits(var s: internal_state_s; value, length: integer);
var
  len: integer;
  val: integer;
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('send_bits(' + IntToStr(value) + ', ' + IntToStr(length) + ')');
   {$endif}
  len := length;
  if (s.bi_valid > (int(Buf_size) - len)) then
  begin
    val := value;
    s.bi_buf := s.bi_buf or (val shl s.bi_valid);
//  Assert(s.bi_buf <= $FFFF);
    //put_short(s, s.bi_buf);
    s.pending_buf^[s.pending] := s.bi_buf and $ff;
    inc(s.pending);
    s.pending_buf^[s.pending] := s.bi_buf shr 8;
    inc(s.pending);
    s.bi_buf := ush(val) shr (Buf_size - s.bi_valid);
    s.bi_valid := s.bi_valid + len - Buf_size;
    Assert((s.bi_valid >= 0) and (s.bi_valid < 1048576));
  end
  else
  begin
    s.bi_buf := s.bi_buf or ((value) shl s.bi_valid);
    s.bi_valid := s.bi_valid + len;
    Assert((s.bi_valid >= 0) and (s.bi_valid < 128000));
  end;
end;

{* ===========================================================================
 * Flush the bit buffer and align the output on a byte boundary}

procedure bi_windup(var s: internal_state_s);
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('bi_windup()');
   {$endif}
  if (s.bi_valid > 8) then
    put_short(s, s.bi_buf)
  else
    if (s.bi_valid > 0) then
    begin
      s.pending_buf^[s.pending] := Byte(s.bi_buf);
      inc(s.pending);
      //put_byte(s, Byte(s.bi_buf));
    end;  
  s.bi_buf := 0;
  s.bi_valid := 0;
end;

{* ===========================================================================
 * Copy a stored block, storing first the length and its
 * one's complement if requested.}

procedure copy_block(var s: internal_state_s; var buf: charf; var len: unsigned;
  header: integer);
 {   deflate_state *s;
    charf    *buf;    /* the input data */
    unsigned len;     /* its length */
    int      header;  /* true if block header must be written */}
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('copy_block(' + IntToStr(len) + ', ' + IntToStr(header) + ')');
   {$endif}
  bi_windup(s); // align on byte boundary
  s.last_eob_len := 8; // enough lookahead for inflate

  if (header <> 0) then
  begin
    put_short(s, ush(len));
    put_short(s, ush(not len));
  end;
  while (len <> 0) do
  begin
    dec(len);
    //put_byte(s, byte(buf[0]));
    s.pending_buf^[s.pending] := Byte(buf[0]);
    inc(s.pending);
    buf := @buf[1];
  end;
end;

{* ===========================================================================
 * Send a stored block}

procedure _tr_stored_block(var s: internal_state_s; buf: charf; stored_len: ulg;
  eof: integer);
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('_tr_stored_block()');
   {$endif}
  send_bits(s, (STORED_BLOCK shl 1) + eof, 3); // send block type
  copy_block(s, buf,  unsigned (stored_len), 1); // with header
end;

procedure send_code(var s: internal_state_s; c: integer; tree: ArrayCtPtr);
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('send_code()');
   {$endif}
  send_bits(s, tree^[c].Code, tree^[c].Len);
end;

function d_code(dist: unsigned): uch;
begin
  if ((dist) < 256) then
    result := _dist_code[dist]
  else
    result := _dist_code[256 + (dist shr 7)];
end;
{* Mapping from a distance to a distance code. dist is the distance - 1 and
 * must not have side effects. _dist_code[256] and _dist_code[257] are never
 * used.}

{* ===========================================================================
 * Send the block data compressed using the given Huffman trees}
procedure compress_block(var s: internal_state_s; ltree: ArrayCtPtr; dtree:
  ArrayCtPtr);
var
  dist: unsigned; // distance of matched string
  lc: integer; // match length or unmatched char (if dist == 0)
  lx: unsigned;
  code: unsigned; // the code to send
  extra: integer; // number of extra bits to send
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('compress_block()');
  Dumper.BeginSubsection;
  DumpState(s);
   {$endif}

  lx := 0; // running index in l_buf

  if (s.last_lit <> 0) then
    repeat
      begin
        dist := s.d_buf[lx];
        lc := s.l_buf[lx];
        inc(lx);

        {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
        Dumper.WriteString('dist=' + IntToStr(dist) + ', lc=' + IntToStr(lc));
         {$endif}

        if (dist = 0) then
        begin
          send_code(s, lc, ltree); // send a literal byte
//            Tracecv(isgraph(lc), (stderr," '%c' ", lc));
        end
        else
        begin
       // Here, lc is the match length - MIN_MATCH
          code := _length_code[lc];
          send_code(s, code + LITERALS + 1, ltree); // send the length code
          extra := extra_lbits[code];
          if (extra <> 0) then
          begin
            lc := lc - base_length[code];
            send_bits(s, lc, extra); // send the extra length bits
          end;
          dec(dist); // dist is now the match distance - 1
          code := d_code(dist);
//       Assert (code < D_CODES, 'bad d_code');

          send_code(s, code, dtree); // send the distance code
          extra := extra_dbits[code];
          if (extra <> 0) then
          begin
            dist := dist - unsigned(base_dist[code]);
            send_bits(s, dist, extra); // send the extra distance bits
          end;
        end; // literal or match pair ?

      // Check that the overlay between pending_buf and d_buf+l_buf is ok: */
        Assert(s.pending < Integer(s.lit_bufsize) + 2 * Integer(lx), 'pendingBuf overflow');
      end;
    until not (lx < s.last_lit); //Yoi eaeuea n N, a aaeuiaeoai a? iaai eni?aaeou

  send_code(s, END_BLOCK, ltree);
  s.last_eob_len := ltree^[END_BLOCK].Len;

  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  DumpState(s);
  Dumper.EndSubsection;
   {$endif}
end;

{* ===========================================================================
 * Send a literal or distance tree in compressed form, using the codes in
 * bl_tree.}

procedure send_tree(var s: internal_state_s; tree: ArrayCtPtr; max_code:
  integer);
var
  n: integer; // iterates over all tree elements
  prevlen: integer; // last emitted length
  curlen: integer; // length of current code
  nextlen: integer; // length of next code
  count: integer; // repeat count of the current code
  max_count: integer; // max repeat count
  min_count: integer; // min repeat count
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('send_tree(' + IntToStr(max_code) + ')');
  Dumper.BeginSubsection;
  DumpState(s);
   {$endif}

  prevlen := -1; // last emitted length
  nextlen := tree^[0].Len; // length of next code
  count := 0; // repeat count of the current code
  max_count := 7; // max repeat count
  min_count := 4; // min repeat count

 {/* tree[max_code+1].Len = -1; */  /* guard already set */}
  if nextlen = 0 then
  begin
    max_count := 138;
    min_count := 3;
  end;

  for n := 0 to max_code do
  begin
    curlen := nextlen;
    nextlen := tree^[n + 1].Len;
    inc(count);
    if ((count < max_count) and (curlen = nextlen)) then
      continue
    else if count < min_count then
    begin
      repeat
        send_code(s, curlen, @s.bl_tree);
        dec(count);
      until not (count <> 0);
    end
    else if curlen <> 0 then
    begin
      if curlen <> prevlen then
      begin
        send_code(s, curlen, @s.bl_tree);
        dec(count);
      end;
      Assert(((count >= 3) and (count <= 6)), ' 3_6?');
      send_code(s, REP_3_6, @s.bl_tree);
      send_bits(s, count - 3, 2);
    end
    else if (count <= 10) then
    begin
      send_code(s, REPZ_3_10, @s.bl_tree);
      send_bits(s, count - 3, 3);
    end
    else
    begin
      send_code(s, REPZ_11_138, @s.bl_tree);
      send_bits(s, count - 11, 7);
    end;
    count := 0;
    prevlen := curlen;
    if nextlen = 0 then
    begin
      max_count := 138;
      min_count := 3;
    end
    else if curlen = nextlen then
    begin
      max_count := 6;
      min_count := 3;
    end
    else
    begin
      max_count := 7;
      min_count := 4;
    end;
  end;

  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  DumpState(s);
  Dumper.EndSubsection;
   {$endif}
end;

{* ===========================================================================
 * Send the header for a block using dynamic Huffman trees: the counts, the
 * lengths of the bit length codes, the literal tree and the distance tree.
 * IN assertion: lcodes >= 257, dcodes >= 1, blcodes >= 4.}

procedure send_all_trees(var s: internal_state_s; lcodes, dcodes, blcodes:
  integer);
 {   deflate_state *s;
    int lcodes, dcodes, blcodes; /* number of codes for each tree }
var
  rank: integer; // index in bl_order
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('send_all_trees()');
  Dumper.BeginSubsection;
   {$endif}

  Assert(((lcodes >= 257) and (dcodes >= 1) and (blcodes >= 4)),
    'not enough codes');
  Assert(((lcodes <= L_CODES) and (dcodes <= D_CODES) and (blcodes <= BL_CODES)),
    'too many codes');
 //Tracev((stderr, "\nbl counts: "));
  send_bits(s, lcodes - 257, 5); // not +255 as stated in appnote.txt
  send_bits(s, dcodes - 1, 5);
  send_bits(s, blcodes - 4, 4); // not -3 as stated in appnote.txt
  for rank := 0 to blcodes - 1 do
  begin
  // Tracev((stderr, "\nbl code %2d ", bl_order[rank]));
    send_bits(s, s.bl_tree[bl_order[rank]]. Len , 3);
  end;
//    Tracev((stderr, "\nbl tree: sent %ld", s->bits_sent));

  send_tree(s, @s.dyn_ltree, lcodes - 1); // literal tree
//    Tracev((stderr, "\nlit tree: sent %ld", s->bits_sent));

  send_tree(s, @s.dyn_dtree, dcodes - 1); // distance tree
//    Tracev((stderr, "\ndist tree: sent %ld", s->bits_sent));
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.EndSubsection;
   {$endif}
end;

{* ===========================================================================
 * Initialize a new block.
 *}

procedure init_block(var s: internal_state_s);
var
  n: integer; // iterates over tree elements
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('init_block()');
   {$endif}

    // Initialize the trees.
  for n := 0 to L_CODES - 1 do
    s.dyn_ltree[n].{$ifndef NET_CF_1_0}Freq {$else}Code {$endif} := 0;
  for n := 0 to D_CODES - 1 do
    s.dyn_dtree[n].{$ifndef NET_CF_1_0}Freq {$else}Code {$endif} := 0;
  for n := 0 to BL_CODES - 1 do
    s.bl_tree[n].{$ifndef NET_CF_1_0}Freq {$else}Code {$endif} := 0;

  s.dyn_ltree[END_BLOCK].{$ifndef NET_CF_1_0}Freq {$else}Code {$endif} := 1;
  s.opt_len := 0;
  s.static_len := 0;
  s.last_lit := 0;
  s.matches := 0;
end;

procedure _tr_flush_block(var s: internal_state_s; var buf: charf; stored_len:
  ulg; eof: integer);
var
  opt_lenb, static_lenb: ulg; // opt_len and static_len in bytes
  max_blindex: integer; // index of last bit length code of non zero freq
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('_tr_flush_block()');
  Dumper.BeginSubsection;
  DumpState(s);
   {$endif}

  max_blindex := 0; // index of last bit length code of non zero freq

    // Build the Huffman trees unless a stored block is forced
  if (s.level > 0) then
  begin
      // Check if the file is ascii or binary
    //if (s.strm.data_type = Z_UNKNOWN) then set_data_type(s);
    // zlib 1.2.3 update
    
    if (stored_len > 0) and (s.strm.data_type = Z_UNKNOWN) then
      set_data_type(s);

      // Construct the literal and distance trees
    build_tree(s,  tree_desc (s.l_desc));
//      Tracev(stderr, '\nlit data: dyn'+inttostr(s.opt_len)+', stat'+inttostr(s.static_len));

    build_tree(s,  tree_desc (s.d_desc));
//      Tracev(stderr, '\ndist data: dyn'+inttostr(s.opt_len)+', stat %ld'+inttostr(s.static_len));
 {* At this point, opt_len and static_len are the total bit lengths of
  * the compressed block data, excluding the tree representations.}

 {* Build the bit length tree for the above two trees, and get the index
  * in bl_order of the last bit length code to send.}
    max_blindex := build_bl_tree(s);

 // Determine the best encoding. Compute first the block length in bytes
    opt_lenb := (s.opt_len + 3 + 7) shr 3;
    static_lenb := (s.static_len + 3 + 7) shr 3;

//  Tracev((stderr, "\nopt %lu(%lu) stat %lu(%lu) stored %lu lit %u ",
//    opt_lenb, s->opt_len, static_lenb, s->static_len, stored_len,
//    s->last_lit));

    if (static_lenb <= opt_lenb) then opt_lenb := static_lenb;
  end
  else
  begin
//        Assert(buf^[0]<>char(0), 'lost buf');
    opt_lenb := stored_len + 5;
    static_lenb := stored_len + 5; // force a stored block
  end;

  if ((stored_len + 4 <= opt_lenb) and (buf <> nil)) then
  begin
         // 4: two words for the lengths
        {* The test buf != NULL is only necessary if LIT_BUFSIZE > WSIZE.
         * Otherwise we can't have processed more than WSIZE input bytes since
         * the last block flush, because compression would have been
         * successful. If LIT_BUFSIZE <= WSIZE, it is never too late to
         * transform a block into a stored block.}

    _tr_stored_block(s, buf, stored_len, eof);
  end
  else
    if (static_lenb = opt_lenb) then
  begin
    send_bits(s, (STATIC_TREES shl 1) + eof, 3);
    compress_block(s, @static_ltree[0], @static_dtree[0]); //?
  end
  else
  begin
    send_bits(s, (DYN_TREES shl 1) + eof, 3);
    send_all_trees(s, s.l_desc.max_code + 1, s.d_desc.max_code + 1, max_blindex
      + 1);
    compress_block(s, @s.dyn_ltree, @s.dyn_dtree);
  end;
//    Assert ((s.compressed_len=s.bits_sent), 'bad compressed size');
    {* The above check is made mod 2^32, for files larger than 512 MB
     * and uLong implemented on 32 bits.}
     
  init_block(s);

  if eof <> 0 then
  begin
    bi_windup(s);
  end;
 //   Tracev((stderr,"\ncomprlen %lu(%lu) ", s->compressed_len>>3, s->compressed_len-7*eof));
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  DumpState(s);
  Dumper.EndSubsection;
   {$endif}
end;

procedure FLUSH_BLOCK_ONLY(var s: internal_state_s; eof: byte);
var
  f: charf;
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('FLUSH_BLOCK_ONLY()');
  Dumper.BeginSubsection;
  DumpState(s);
   {$endif}
  if (s.block_start >= 0) then
  begin
    f := @s.window[unsigned(s.block_start)];
//    f := @s.window[0]; // II // II again
  end
  else
    f := nil;
    
  _tr_flush_block(s, f, ulg(long(s.strstart) - s.block_start), eof);
  s.block_start := s.strstart;
  flush_pending(s.strm^);
// Tracev(stderr,'[FLUSH]');
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  DumpState(s);
  Dumper.EndSubsection;
   {$endif}
end;

// Same but force premature exit if necessary.

function FLUSH_BLOCK(var s: internal_state_s; eof: byte; var MustReturn:  boolean ): byte;
begin
  result := 0;
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('FLUSH_BLOCK()');
   {$endif}
 
  FLUSH_BLOCK_ONLY(s, eof);
  if s.strm.avail_out = 0 then
  begin
    if (eof <> 0) then
      result := finish_started
    else
      result := need_more;
    MustReturn := true;
  end
  else
    MustReturn := false;
end;

{* ===========================================================================
 * Copy without compression as much as possible from the input stream, return
 * the current block state.
 * This function does not insert new strings in the dictionary since
 * uncompressible data is probably not useful. This function is used
 * only for the level=0 compression option.
 * NOTE: this function should be optimized to avoid extra copying from
 * window to pending_buf.}

function deflate_stored(var s: internal_state_s; var flush: integer):
  block_state;
var
  max_block_size: ulg;
  max_start: ulg;
  fori: byte;
  ret : TSBBoolean;
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('deflate_stored()');
  DumpState(s);
   {$endif}
  
  
    {* Stored blocks are limited to 0xffff bytes, pending_buf is limited
     * to pending_buf_size, and each stored block has a 5 byte header:}
  max_block_size := $FFFF;

  if (max_block_size > s.pending_buf_size - 5) then
  begin
    max_block_size := s.pending_buf_size - 5;
  end;

    // Copy as much as possible from input to output:

  fori := 0;
  while (fori = 0) do
  begin
        // Fill the window as much as possible:
    if (s.lookahead <= 1) then
    begin

      Assert((s.strstart < s.w_size + s.w_size - MIN_LOOKAHEAD) or
        (s.block_start >= long(s.w_size)), 'slide too late');

      fill_window(s);
      if ((s.lookahead = 0) and (flush = Z_NO_FLUSH)) then
      begin
        result := need_more;
        exit;
      end;

      if (s.lookahead = 0) then break; // flush the current block
    end;
    Assert(s.block_start >= 0, 'block gone');

    s.strstart := s.strstart + s.lookahead;
    s.lookahead := 0;

 // Emit a stored block if pending_buf will be full:
    max_start := ulg(s.block_start) + ulg(max_block_size);
    if ((s.strstart = 0) or (ulg(s.strstart) >= max_start)) then
    begin
     // strstart == 0 is possible when wraparound on 16-bit machine
      s.lookahead := uInt(s.strstart - max_start);
      s.strstart := uInt(max_start);
      result := FLUSH_BLOCK(s, 0, ret);
      if ret then
        exit;
    end;
 {* Flush if we may have to slide, otherwise block_start may become
         * negative and the data will be gone:}
    if ((s.strstart - uInt(s.block_start)) >= s.w_size - MIN_LOOKAHEAD) then
    begin
      result := FLUSH_BLOCK(s, 0, ret);
      if ret then
        exit;
    end;
  end;

  result := FLUSH_BLOCK(s, byte(flush = Z_FINISH), ret);
  if ret then
    Exit;

  if (flush = Z_FINISH) then
    result := finish_done
  else
    result := block_done;
end;

{* ===========================================================================
 * Flush the bit buffer, keeping at most 7 bits in it.}

procedure bi_flush(var s: internal_state_s);
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('bi_flush()');
   {$endif}
  if (s.bi_valid = 16) then
  begin
    put_short(s, s.bi_buf);
    s.bi_buf := 0;
    s.bi_valid := 0;
  end
  else
    if (s.bi_valid >= 8) then
  begin
    s.pending_buf^[s.pending] := s.bi_buf;
    inc(s.pending);
    //put_byte(s, s.bi_buf);
    s.bi_buf := s.bi_buf shr 8;
    s.bi_valid := s.bi_valid - 8;
    Assert((s.bi_valid >= 0) and (s.bi_valid < 128000));
  end;
end;

procedure _tr_align(var s: internal_state_s);
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('_tr_align()');
   {$endif}
  send_bits(s, STATIC_TREES shl 1, 3);
  send_code(s, END_BLOCK, @static_ltree);

  bi_flush(s);
    {* Of the 10 bits for the empty block, we have already sent
     * (10 - bi_valid) bits. The lookahead for the last real code (before
     * the EOB of the previous block) was thus at least one plus the length
     * of the EOB plus what we have just sent of the empty static block.}
  if (1 + s.last_eob_len + 10 - s.bi_valid < 9) then
  begin
    send_bits(s, STATIC_TREES shl 1, 3);
    send_code(s, END_BLOCK, @static_ltree); //@static_ltree
    bi_flush(s);
  end;
  s.last_eob_len := 7;
end;

{* ===========================================================================
 * Initialize the hash table (avoiding 64K overflow for 16 bit systems).
 * prev[] will be initialized on the fly.
 *}

procedure CLEAR_HASH(var s: internal_state_s);
// var i : integer;
begin
  s.head[s.hash_size - 1] := 0;
  FillChar(s.head^, unsigned((s.hash_size - 1) * sizeof(Word)), 0);
end;

function deflate(var strm: TZStreamRec; flush: integer): integer;
var
  old_flush: integer;
  s: internal_state;
  header: uInt;
  level_flags: uInt;
  bstate: block_state;
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('deflate()');
   {$endif}
  bstate := 0;
  if ((@strm = nil) or (strm.internal = nil) or (flush > Z_FINISH) or (flush < 0)) then
  begin
    result := Z_STREAM_ERROR;
    exit;
  end;
 
  s := strm.internal;

  if ((strm.next_out = nil) or ((strm.next_in = nil) and (strm.avail_in <> 0))
    or ((s.status = FINISH_STATE) and (flush <> Z_FINISH))) then
  begin
    result := ERR_RETURN(strm, Z_STREAM_ERROR);
    exit;
  end;
  if (strm.avail_out = 0) then
  begin
    result := ERR_RETURN(strm, Z_BUF_ERROR);
    exit;
  end;
  s.strm := @strm; // just in case
  old_flush := s.last_flush;
  s.last_flush := flush;

 // Write the zlib header
  if (s.status = INIT_STATE) then
  begin
    header := (Z_DEFLATED + ((s.w_bits - 8) shl 4)) shl 8;

    if (s.strategy >= Z_HUFFMAN_ONLY) or (s.level < 2) then
     level_flags := 0
    else if (s.level < 6) then
           level_flags := 1
         else if (s.level = 6) then
                level_flags := 2
              else
                level_flags := 3;

    header := (header or (level_flags shl 6));
    if (s.strstart <> 0) then header := header or PRESET_DICT;
    header := header + (31 - (header mod 31));

    s.status := BUSY_STATE;
    putShortMSB(s^, header);

   // Save the adler32 of the preset dictionary:
    if (s.strstart <> 0) then
    begin
      putShortMSB(s^, uInt(strm.adler shr 16));
      putShortMSB(s^, uInt(strm.adler and $FFFF));
    end;
    strm.adler := adler32(0, Z_NULL, 0);
  end;

   // Flush as much pending output as possible
  if (s.pending <> 0) then
  begin
    flush_pending(strm);
    if (strm.avail_out = 0) then
    begin
       {* Since avail_out is 0, deflate will be called again with
        * more output space, but possibly with both pending and
        * avail_in equal to zero. There won't be anything to do,
        * but this is not an error situation so make sure we
        * return OK instead of BUF_ERROR at next call of deflate:}
      s.last_flush := -1;
      result := Z_OK;
      exit;
    end;
      {* Make sure there is something to do and avoid duplicate consecutive
      * flushes. For repeated and useless calls with Z_FINISH, we keep
      * returning Z_STREAM_END instead of Z_BUFF_ERROR.}
  end
  else
    if ((strm.avail_in = 0) and (flush <= old_flush) and (flush <> Z_FINISH))
      then
  begin
    result := ERR_RETURN(strm, Z_BUF_ERROR);
    exit;
  end;

    // User must not provide more input after the first FINISH:
  if ((s.status = FINISH_STATE) and (strm.avail_in <> 0)) then
  begin
    result := ERR_RETURN(strm, Z_BUF_ERROR);
    exit;
  end;

    // Start a new block or continue the current one.
  if ((strm.avail_in <> 0) or (s.lookahead <> 0) or ((flush <> Z_NO_FLUSH) and
    (s.status <> FINISH_STATE))) then
  begin
    bstate := configuration_table[s.level].func(s^, flush);

    if ((bstate = finish_started) or (bstate = finish_done)) then
    begin
      s.status := FINISH_STATE;
    end;
    if ((bstate = need_more) or (bstate = finish_started)) then
    begin
      if (strm.avail_out = 0) then
      begin
        s.last_flush := -1; // avoid BUF_ERROR next call, see above
      end;
      result := Z_OK;
      exit;
         {* If flush != Z_NO_FLUSH && avail_out == 0, the next call
          * of deflate should use the same flush parameter to make sure
          * that the flush is complete. So we don't have to output an
          * empty block here, this will be done at next call. This also
          * ensures that for a very small output buffer, we emit at most
          * one empty block.}
    end;
  end;

  if (bstate = block_done) then
  begin
    if (flush = Z_PARTIAL_FLUSH) then
    begin
      _tr_align(s^);
//      s.block_start := 0; // II
//      s.strstart := 0; // II // Not needed

      s.pending_buf_size := 0;
      s.match_start := 0;
      s.lookahead := 0;
    end
    else // FULL_FLUSH or SYNC_FLUSH
    begin
      _tr_stored_block(s^, nil, 0, 0);
            {* For a full flush, this empty block will be recognized
             * as a special marker by inflate_sync().
             */}
      if (flush = Z_FULL_FLUSH) then
      begin
        CLEAR_HASH(s^); // forget history
      end;
    end;
    flush_pending(strm);
    if (strm.avail_out = 0) then
    begin
      s.last_flush := -1; // avoid BUF_ERROR at next call, see above
      result := Z_OK;
      exit;
    end;
  end;
//    end;
//    Assert(strm.avail_out > 0, 'bug2');

  if (flush <> Z_FINISH) then
  begin
    result := Z_OK;
    exit;
  end;
  if (s.wrap <= 0) then
  begin
    result := Z_STREAM_END;
    exit;
  end;

    // Write the zlib trailer (adler32)
  putShortMSB(s^, uInt(strm.adler shr 16));
  putShortMSB(s^, uInt(strm.adler and $FFFF));
  flush_pending(strm);
    {* If avail_out is zero, the application will call deflate again
     * to flush the rest. }

//  s.noheader := -1; // write the trailer only once!
  s.wrap := 0 ;

  if s.pending <> 0 then
    result := Z_OK
  else
    result := Z_STREAM_END;
end;

function ZALLOC(var strm: TZStreamRec; items, size: Cardinal): Pointer;
begin
  Result := AllocMem(Items * Size);
end;

(*
procedure ZFREE(var strm: TZStreamRec; var addr: Bytef);
begin
  strm.zfree(strm.AppData, addr);
end;

procedure TRY_FREE(var s: TZStreamRec; var p: Bytef);
begin
  if (p <> nil) then ZFREE(s, p);
end;
*)

// ========================================================================= */

function deflateEnd(var strm: TZStreamRec): integer;
var
  status: integer;
begin
  if ((@strm = nil) or (strm.internal = nil)) then
  begin
    result := Z_STREAM_ERROR;
    exit;
  end;

  status := internal_state(strm.internal).status;
  if ((status <> INIT_STATE) and (status <> BUSY_STATE) and (status <>
    FINISH_STATE) and (status <> EXTRA_STATE) and (status <> NAME_STATE) and
    (status <> COMMENT_STATE) and (status <> HCRC_STATE)) then
  begin
    result := Z_STREAM_ERROR;
    exit;
  end;

    // Deallocate in reverse order of allocations:

  FreeMem(internal_state_s(strm.internal^).pending_buf);
  FreeMem(internal_state_s(strm.internal^).head);
  FreeMem(internal_state_s(strm.internal^).prev);
  FreeMem(internal_state_s(strm.internal^).window);
  FreeMem(strm.internal);

  strm.internal := nil;

  if status = BUSY_STATE then
    result := Z_DATA_ERROR
  else
    result := Z_OK;
end;

{* ===========================================================================
 * Initialize the various 'constant' tables.}

procedure tr_static_init;
begin
end;

{* ===========================================================================
 * Initialize the tree data structures for a new zlib stream.}

procedure _tr_init(var s: internal_state_s);
begin
  tr_static_init; //Yoa i?ioaao?a oi?iaeuii ionoay aioo?e e ia auiieiyaony

  s.l_desc.dyn_tree := @s.dyn_ltree;
  s.l_desc.stat_desc := static_l_desc;

  s.d_desc.dyn_tree := @s.dyn_dtree;
  s.d_desc.stat_desc := static_d_desc;

  s.bl_desc.dyn_tree := @s.bl_tree;
  s.bl_desc.stat_desc := static_bl_desc;

  s.bi_buf := 0;
  s.bi_valid := 0;
  s.last_eob_len := 8; // enough lookahead for inflate

 // Initialize the first block of the first file:
  init_block(s);
end;

{* ===========================================================================
 * Initialize the "longest match" routines for a new zlib stream}

procedure lm_init(var s: internal_state_s);
begin
  s.window_size := ulg(s.w_size shl 1);

  CLEAR_HASH(s);

 // Set the default configuration parameters:
  s.max_lazy_match := configuration_table[s.level].max_lazy;
  s.good_match := configuration_table[s.level].good_length;
  s.nice_match := configuration_table[s.level].nice_length;
  s.max_chain_length := configuration_table[s.level].max_chain;

  s.strstart := 0;
  s.block_start := 0;
  s.lookahead := 0;
  s.match_length := MIN_MATCH - 1;
  s.prev_length := MIN_MATCH - 1;
  s.match_available := 0;
  s.ins_h := 0;
end;

// =========================================================================

function deflateReset(var strm: TZStreamRec): integer;
var
  s: deflate_state;
begin
  if ((@strm = nil) or (strm.internal = nil) or (@strm.zalloc = nil) or
    (@strm.zfree = nil)) then
  begin
    result := Z_STREAM_ERROR;
    exit;
  end;

  strm.total_in := 0;
  strm.total_out := 0;
  strm.msg :=  nil ; // use zfree if we ever allocate msg dynamically
  strm.data_type := Z_UNKNOWN;

  s := deflate_state(strm.internal);
  s.pending := 0;
  s.pending_out := s.pending_buf;

  if s.wrap < 0 then
  begin
    s.wrap := 0; // was made negative by deflate(..., Z_FINISH);
  end;
  if s.wrap <> 0 then
    s.status := INIT_STATE
  else
    s.status := BUSY_STATE;
    
  strm.adler := adler32(0, Z_NULL, 0);
  s.last_flush := Z_NO_FLUSH;

  _tr_init(s^);
  lm_init(s^);

  result := Z_OK;
end;

// ========================================================================= */

function deflateInit2_(var strm: TZStreamRec; level: Integer; method,
  windowBits, memLevel, strategy: Integer; version: ByteArray; recsize: Integer):
  Integer;
var
  s: internal_state;
  wrap: integer;
  my_version: ByteArray;
  overlay: Pointer; //ushf;
begin
//  noheader := 0;
  wrap := 1;
  my_version := zLibVersion;

    {* We overlay pending_buf and d_buf+l_buf. This works since the average
     * output size for (length,distance) codes is <= 24 bits.}

  if ((version = nil) or (version[0] <> my_version[0]) or
      (recsize <> sizeof(TZStreamRec))) then
  begin
    result := Z_VERSION_ERROR;
    exit;
  end;

  if @strm = nil then
  begin
    result := Z_STREAM_ERROR;
    exit;
  end;

  strm.msg :=  nil ;
  if (@strm.zalloc = nil) then
  begin
    strm.zalloc := zlibAllocMem;
    strm.AppData := nil;
  end;

  if @strm.zfree = nil then strm.zfree := zlibFreeMem;

  if (level = Z_DEFAULT_COMPRESSION) then level := 6;

  if windowBits < 0 then // suppress zlib wrapper
  begin
    wrap := 0;
    windowBits := -windowBits;
  end;
  if ((memLevel < 1) or (memLevel > MAX_MEM_LEVEL) or 
      (method <> Z_DEFLATED) or
      (windowBits < 8) or (windowBits > 15) or (level < 0) or (level > 9) or
      (strategy < 0) or (strategy > Z_FIXED)) then
  begin
    result := Z_STREAM_ERROR;
    exit;
  end;
  if (windowBits = 8) then windowBits := 9;  // until 256-byte window bug fixed

  s := ZALLOC(strm, 1, sizeof(internal_state_s));
  if s = nil then
  begin
    result := Z_MEM_ERROR;
    exit;
  end;

  strm.internal := s;
  s^.strm := @strm;

  s^.wrap := wrap;
  s^.w_bits := windowBits;
  s^.w_size := 1 shl s^.w_bits;
  s^.w_mask := s.w_size - 1;

  s^.hash_bits := memLevel + 7;
  s^.hash_size := 1 shl s^.hash_bits;
  s^.hash_mask := s^.hash_size - 1;
  s^.hash_shift := ((s^.hash_bits + MIN_MATCH - 1) div MIN_MATCH);

  GetMem(s^.window, s^.w_size shl 1 * sizeof(Byte));
  GetMem(s^.prev, s^.w_size * sizeof(Pos));
  GetMem(s^.head, s^.hash_size * sizeof(Pos));
 //   FillChar(s^.prev^, s^.w_size*sizeof(Pos), 0);

  s^.lit_bufsize := 1 shl (memLevel + 6); // 16K elements by default

  GetMem(overlay, (s^.lit_bufsize * sizeof(ush)) shl 1 + 2);
    //Ooo ii?ii iii?iaiaaou oi?inoeou auaaeaiea iaiyoe
  s^.pending_buf := overlay;
  s^.pending_buf_size := ulg(s^.lit_bufsize * (sizeof(ush) + 2));

  if ((s^.window = nil) or (s^.prev = nil) or (s^.head = nil) or (s^.pending_buf
    = nil)) then
  begin
    s^.status := FINISH_STATE;
    strm.msg := Pchar(ERR_MSG(Z_MEM_ERROR));
    deflateEnd(strm);
    result := Z_MEM_ERROR;
    exit;
  end;
  s^.d_buf := Pointer(PtrUInt(overlay) + (s^.lit_bufsize div sizeof(ush)) shl 1);
  s^.l_buf := Pointer(PtrUInt(s^.pending_buf) + (1 + sizeof(ush)) *
    s^.lit_bufsize);

  s^.level := level;
  s^.strategy := strategy;
  s^.method := Byte(method);

  result := deflateReset(strm);
end;

// ========================================================================= */

function deflateInit_(var strm: TZStreamRec; level: integer; version: ByteArray;
  recsize: Integer): Integer;
const
  DEFLATE_W_BITS = 15;
begin
  result := deflateInit2_(strm, level, Z_DEFLATED, DEFLATE_W_BITS, DEF_MEM_LEVEL,
    Z_DEFAULT_STRATEGY, version , recsize );
    // To do: ignore strm->next_in if we use it as window */
end;

{* ===========================================================================
     Compresses the source buffer into the destination buffer. The level
   parameter has the same meaning as in deflateInit.  sourceLen is the byte
   length of the source buffer. Upon entry, destLen is the total size of the
   destination buffer, which must be at least 0.1% larger than sourceLen plus
   12 bytes. Upon exit, destLen is the actual size of the compressed buffer.

     compress2 returns Z_OK if success, Z_MEM_ERROR if there was not enough
   memory, Z_BUF_ERROR if there was not enough room in the output buffer,
   Z_STREAM_ERROR if the level parameter is invalid.}

procedure CompressBuf(const InBuf: Pointer; InBytes: Integer;
  out OutBuf: Pointer; out OutBytes: Integer);
var
  strm: TZStreamRec;
  P: Pointer;
begin
  FillChar(strm, sizeof(strm), 0);
  strm.zalloc :=  zlibAllocMem ;
  strm.zfree :=  zlibFreeMem ;
  OutBytes := ((InBytes + (InBytes div 10) + 12) + 255) and not 255;
  GetMem(OutBuf, OutBytes);
  try
    strm.next_in := InBuf;
    strm.avail_in := InBytes;
    strm.next_out := OutBuf;
    strm.avail_out := OutBytes;
    CCheck(deflateInit_(strm, {Z_BEST_COMPRESSION} -1, zlibVersion
       , SizeOf(strm) ));
    try
      while CCheck(deflate(strm, Z_FINISH)) <> Z_STREAM_END do
      begin
        P := OutBuf;
        Inc(OutBytes, 256);
        ReallocMem(OutBuf, OutBytes);
        strm.next_out := PAnsiChar(PtrInt(OutBuf) + (PtrInt(strm.next_out) - PtrInt(P)));
        strm.avail_out := 256;
      end;
    finally
      CCheck(deflateEnd(strm));
    end;
    ReallocMem(OutBuf, strm.total_out);
    OutBytes := strm.total_out;
  except
    FreeMem(OutBuf);
    raise
  end;
end;
{* ===========================================================================
 * Insert string str in the dictionary and set match_head to the previous head
 * of the hash chain (the most recent string with same hash key). Return
 * the previous length of the hash chain.
 * If this file is compiled with -DFASTEST, the compression level is forced
 * to 1, and no hash chains are maintained.
 * IN  assertion: all calls to to INSERT_STRING are made with consecutive
 *    input characters and the first MIN_MATCH bytes of str are valid
 *    (except for the last MIN_MATCH-1 bytes of the input file).}

procedure INSERT_STRING(var s: internal_state_s; var str: uInt; var match_head:
  IPos);
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('INSERT_STRING()');
   {$endif}
  begin
    s.ins_h := ((s.ins_h shl s.hash_shift) xor s.window[str + (MIN_MATCH - 1)])
      and s.hash_mask;
    match_head := s.head[s.ins_h];
    s.prev[str and s.w_mask] := match_head;
    s.head[s.ins_h] :=  Pos (str);
  end;
end;

//  70-80% of working time is spent inside this function, so it's divided into 2 parts
//    for better readability

function longest_match(var s: internal_state_s; var cur_match: IPos) : uInt;
var
  chain_length: unsigned;
  scan: Bytef;
  strend: ArrayPtr;
  wnd: Bytef;
  match: Bytef; // matched string
  len: cardinal;
  best_len, best_len1: cardinal;
  nice_match: cardinal;
  limit: IPos;
  prev: Posf;
  wmask: uInt;
  scan_endw: Word;
  Flchk: Boolean;
  cur_match_: IPos;
  i: byte;
begin
  chain_length := s.max_chain_length; // max hash chain length
  scan := @s.window[s.strstart]; // current string
  best_len := s.prev_length; // best match length so far
  best_len1 := best_len - 1; // best_len - 1
  nice_match := s.nice_match; // stop if match long enough
  limit := IPos(s.w_size - MIN_LOOKAHEAD);
  if s.strstart > limit then
    limit := s.strstart - limit
  else
    limit := 0;

  prev := s.prev;
  wmask := s.w_mask;
  cur_match_ := cur_match;

  strend := @s.window[s.strstart + MAX_MATCH];
  scan_endw := PWord(@scan[best_len1])^;
  wnd := @s.window[0];

  if (s.prev_length >= s.good_match) then
    chain_length := chain_length shr 2;

  if (uInt(nice_match) > s.lookahead) then
    nice_match := s.lookahead;

  repeat
    match := @wnd[cur_match_];

    if (PWord(@match[best_len1])^ <> scan_endw) or
      (PWord(match)^ <> PWord(scan)^)
    then
    begin
      cur_match_ := prev[cur_match_ and wmask];

      if cur_match_ <= limit then
        break;

      dec(chain_length);
    end
    else 
    begin
      scan := @scan[2];
      match := @match[2];

      repeat
        Flchk := False;
        for i := 1 to 8 do
        begin
          scan := @scan[1];
          match := @match[1];
          if scan[0] <> match[0] then
          begin
            Flchk := true;
            break;
          end;
        end;
        if Flchk then
          break;
        if (PtrUInt(@scan[0])>=PtrUInt(@strend[0])) then
          break;
      until not ((PtrUInt(@scan[0]) < PtrUInt(@strend[0])) and (not Flchk));

      len := MAX_MATCH - (PtrUInt(@strend[0]) - PtrUInt(@scan[0]));
      scan := Pointer(PtrUInt(@strend[0]) - MAX_MATCH);

      if (len > best_len) then
      begin
        s.match_start := cur_match_;
        best_len := len;
        best_len1 := best_len - 1;
        if (len >= nice_match) then
          break;
        scan_endw := PWord(@scan[best_len1])^;
      end;

      cur_match_ := prev[cur_match_ and wmask];
      if (cur_match_ <= limit) then
        break;
      dec(chain_length);
    end;
  until (chain_length = 0);

  cur_match := cur_match_;
  if (uInt(best_len) <= s.lookahead) then
    result := uInt(best_len)
  else
    result := s.lookahead;
end;

procedure _tr_tally_dist(var s: internal_state_s; distance, length: uInt; var
  flush: integer);
var
  len: uch;
  dist: ush;
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('_tr_tally_dist()');
   {$endif}
  len := length;
  dist := distance;
  s.d_buf^[s.last_lit] := dist;
  s.l_buf^[s.last_lit] := len;
  inc(s.last_lit);
  dec(dist);
  inc(s.dyn_ltree[(_length_code[len]) + LITERALS + 1].{$ifndef NET_CF_1_0}Freq {$else}Code {$endif});
  inc(s.dyn_dtree[d_code(dist)].{$ifndef NET_CF_1_0}Freq {$else}Code {$endif});
  
  if s.last_lit = s.lit_bufsize - 1 then
    flush := 1
  else
    flush := 0;
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  DumpState(s);
   {$endif}
end;

procedure _tr_tally_lit(var s: internal_state_s; c: byte; var flush: integer);
var
  cc: byte;
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('_tr_tally_lit(' + IntToStr(c) + ')');
   {$endif}
  cc := c;
  s.d_buf[s.last_lit] := 0;
  s.l_buf[s.last_lit] := cc;
  inc(s.last_lit);
  inc(s.dyn_ltree[cc].{$ifndef NET_CF_1_0}Freq {$else}Code {$endif});
  
  if s.last_lit = s.lit_bufsize - 1 then
    flush := 1
  else
    flush := 0;
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  DumpState(s);
   {$endif}
end;

{* ===========================================================================
 * Compress as much as possible from the input stream, return the current
 * block state.
 * This function does not perform lazy evaluation of matches and inserts
 * new strings in the dictionary only for unmatched strings or for short
 * matches. It is used only for the fast compression options.}

function deflate_fast(var s: internal_state_s; var flush: integer): block_state;
var
  hash_head: IPos;
  bflush: integer; // set if current block must be flushed
  fori: byte;
  ret : TSBBoolean;
begin
  hash_head := 0; // head of the hash chain

  fori := 0;
  while (fori = 0) do
  begin
   {* Make sure that we always have enough lookahead, except
    * at the end of the input file. We need MAX_MATCH bytes
    * for the next match, plus MIN_MATCH bytes to insert the
    * string following the next match.}

    if (s.lookahead < MIN_LOOKAHEAD) then
    begin
      fill_window(s);
      if ((s.lookahead < MIN_LOOKAHEAD) and (flush = Z_NO_FLUSH)) then
      begin
        result := need_more;
        exit;
      end;
      if (s.lookahead = 0) then break; // flush the current block
    end;

   {* Insert the string window[strstart .. strstart+2] in the
    * dictionary, and set hash_head to the head of the hash chain:}

    if (s.lookahead >= MIN_MATCH) then
    begin
      INSERT_STRING(s, s.strstart, hash_head);
    end;

   {* Find the longest match, discarding those <= prev_length.
    * At this point we have always match_length < MIN_MATCH}

    if ((hash_head <> 0) and (s.strstart - hash_head <= s.w_size - MIN_LOOKAHEAD)) then
    begin
     {* To simplify the code, we prevent matches with the string
      * of window index 0 (in particular we have to avoid a match
      * of the string with itself at the start of the input file).}

      if ((s.strategy <> Z_HUFFMAN_ONLY) and (s.strategy <> Z_RLE)) then
        s.match_length := longest_match(s, hash_head)
      else
      begin
        if (s.strategy = Z_RLE ) AND ((s.strstart - hash_head) = 1) then
        begin
//          s.match_length := longest_match_fast(s, hash_head)  ;
          s.match_length := longest_match(s, hash_head)  ;
        end;
      end;
      // longest_match() sets match_start
    end;

    if (s.match_length >= MIN_MATCH) then
    begin
//     check_match(s, s.strstart, s.match_start, s.match_length);

      _tr_tally_dist(s, s.strstart - s.match_start, s.match_length - MIN_MATCH,
        bflush);
      s.lookahead := s.lookahead - s.match_length;

     {* Insert new strings in the hash table only if the match length
      * is not too large. This saves time but degrades compression.}

      if ((s.match_length <= s.max_lazy_match) and (s.lookahead >= MIN_MATCH))
        then
      begin
        dec(s.match_length); // string at strstart already in hash table
        repeat
          begin
            inc(s.strstart);
            INSERT_STRING(s, s.strstart, hash_head);
       {* strstart never exceeds WSIZE-MAX_MATCH, so there are
        * always MIN_MATCH bytes ahead.}
            dec(s.match_length);
          end;
        until (s.match_length = 0);
        inc(s.strstart);
      end
      else
      begin
        s.strstart := s.strstart + s.match_length;
        s.match_length := 0;
        s.ins_h := s.window[s.strstart];
        UPDATE_HASH(s, s.ins_h, s.window[s.strstart + 1]);
{#if MIN_MATCH != 3
                Call UPDATE_HASH() MIN_MATCH-3 more times
#endif    }
  {* If lookahead < MIN_MATCH, ins_h is garbage, but it does not
   * matter since it will be recomputed at next deflate call.}
      end
    end
    else
    begin
    // No match, output a literal byte

     //Tracevv((stderr,"%c", s->window[s->strstart]));
      _tr_tally_lit(s, s.window[s.strstart], bflush);
      dec(s.lookahead);
      inc(s.strstart);
    end;
    if (bflush <> 0) then
    begin
      result := FLUSH_BLOCK(s, 0, ret);
      if ret then
        Exit;
    end;
  end;

  result := FLUSH_BLOCK(s, byte(flush = Z_FINISH), ret);
  if ret then
    Exit;

  if flush = Z_FINISH then
    result := finish_done
  else
    result := block_done;
end;

{* ===========================================================================
 * Same as above, but achieves better compression. We use a lazy
 * evaluation for matches: a match is finally adopted only if there is
 * no better match at the next window position.}

function deflate_slow(var s: internal_state_s; var flush: integer): block_state;
var
  hash_head: IPos;
  bflush: integer; // set if current block must be flushed
  fori: byte;
  max_insert: uInt;
  ret : TSBBoolean;
begin
  
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('deflate_slow()');
  DumpState(s);
   {$endif}
  hash_head := 0; // head of hash chain

 // Process the input block.
  fori := 0;
  while (fori = 0) do
  begin
  {* Make sure that we always have enough lookahead, except
   * at the end of the input file. We need MAX_MATCH bytes
   * for the next match, plus MIN_MATCH bytes to insert the
   * string following the next match.}

    if (s.lookahead < MIN_LOOKAHEAD) then
    begin
      fill_window(s);
      if ((s.lookahead < MIN_LOOKAHEAD) and (flush = Z_NO_FLUSH)) then
      begin
        result := need_more;
        exit;
      end;
      if (s.lookahead = 0) then break; // flush the current block
    end;

   {* Insert the string window[strstart .. strstart+2] in the
    * dictionary, and set hash_head to the head of the hash chain:}

    if (s.lookahead >= MIN_MATCH) then
    begin
      //INSERT_STRING(s, s.strstart, hash_head);
      s.ins_h := ((s.ins_h shl s.hash_shift) xor s.window[s.strstart + (MIN_MATCH - 1)])
        and s.hash_mask;
      hash_head := s.head[s.ins_h];
      s.prev[s.strstart and s.w_mask] := hash_head;
      s.head[s.ins_h] :=  Pos (s.strstart);
    end;

   // Find the longest match, discarding those <= prev_length.

    s.prev_length := s.match_length;
    s.prev_match := s.match_start;
    s.match_length := MIN_MATCH - 1;

    if ((hash_head <> 0) and (s.prev_length < s.max_lazy_match) and (s.strstart
      - hash_head <= s.w_size - MIN_LOOKAHEAD)) then
    begin
     {* To simplify the code, we prevent matches with the string
      * of window index 0 (in particular we have to avoid a match
      * of the string with itself at the start of the input file).}
      if ((s.strategy <> Z_HUFFMAN_ONLY) and (s.strategy <> Z_RLE)) then 
      begin
        s.match_length := longest_match(s, hash_head);
      end
      else if ((s.strategy = Z_RLE) AND ((s.strstart - hash_head) = 1)) then
                s.match_length := longest_match(s, hash_head);
//                s.match_length := longest_match_fast(s, hash_head);

     // longest_match() sets match_start

      if ((s.match_length <= 5) and ((s.strategy = Z_FILTERED) or
        ((s.match_length = MIN_MATCH) and (s.strstart - s.match_start >
          TOO_FAR)))) then
      begin
      {* If prev_match is also MIN_MATCH, match_start is garbage
       * but we will ignore the current match anyway.}

        s.match_length := MIN_MATCH - 1;
      end;
    end;
    {* If there was a match at the previous step and the current
     * match is not better, output the previous match:}

    if ((s.prev_length >= MIN_MATCH) and (s.match_length <= s.prev_length)) then
    begin
      max_insert := s.strstart + s.lookahead - MIN_MATCH;
      // Do not insert strings in hash table beyond this.

      //check_match(s, s.strstart-1, s.prev_match, s.prev_length);

      _tr_tally_dist(s, s.strstart - 1 - s.prev_match, s.prev_length -
        MIN_MATCH, bflush);

      {* Insert in hash table all strings up to the end of the match.
       * strstart-1 and strstart are already inserted. If there is not
       * enough lookahead, the last two strings are not inserted in
       * the hash table.}

      s.lookahead := s.lookahead - (s.prev_length - 1);
      s.prev_length := s.prev_length - 2;
      repeat
        begin
          inc(s.strstart);
          if (s.strstart <= max_insert) then
          begin
            //INSERT_STRING(s, s.strstart, hash_head);
            s.ins_h := ((s.ins_h shl s.hash_shift) xor s.window[s.strstart + (MIN_MATCH - 1)])
              and s.hash_mask;
            hash_head := s.head[s.ins_h];
            s.prev[s.strstart and s.w_mask] := hash_head;
            s.head[s.ins_h] :=  Pos (s.strstart);
          end;
          dec(s.prev_length);
        end;
      until s.prev_length = 0;
      s.match_available := 0;
      s.match_length := MIN_MATCH - 1;
      inc(s.strstart);

      if (bflush <> 0) then
      begin
        Result := FLUSH_BLOCK(s, 0, ret);
        if ret then
          Exit;
      end;

    end
    else
      if (s.match_available <> 0) then
    begin
      {* If there was no match at the previous position, output a
       * single literal. If there was a match but the current match
       * is longer, truncate the previous match to a single literal.}

//            Tracevv((stderr,"%c", s->window[s->strstart-1]));
      //_tr_tally_lit(s, s.window[s.strstart - 1], bflush);
      s.d_buf[s.last_lit] := 0;
      s.l_buf[s.last_lit] := s.window[s.strstart - 1];
      inc(s.last_lit);
      inc(s.dyn_ltree[s.window[s.strstart - 1]].{$ifndef NET_CF_1_0}Freq {$else}Code {$endif});

      if s.last_lit = s.lit_bufsize - 1 then
        FLUSH_BLOCK_ONLY(s, 0);

      inc(s.strstart);
      dec(s.lookahead);
      if (s.strm.avail_out = 0) then
      begin
        result := need_more;
        exit;
      end;
    end
    else
    begin
       {* There is no previous match to compare with, wait for
        * the next step to decide.}

      s.match_available := 1;
      inc(s.strstart);
      dec(s.lookahead);
    end;
  end;
  Assert(flush <> Z_NO_FLUSH, 'no flush?');
  if (s.match_available <> 0) then
  begin
      //Tracevv((stderr,"%c", s->window[s->strstart-1]));
    _tr_tally_lit(s, s.window[s.strstart - 1], bflush);
    s.match_available := 0;
  end;
  Result := FLUSH_BLOCK(s, byte(flush = Z_FINISH), ret);
  if ret then
    Exit;
  if flush = Z_FINISH then
    result := finish_done
  else
    result := block_done;
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  DumpState(s);
   {$endif}
end;

// =========================================================================

function deflateSetDictionary(var strm: TZStreamRec; dictionary: PAnsiChar;
  dictLength: uInt): integer;
var
  s: ^internal_state_s;
  length: uInt;
  n: uInt;
  hash_head: IPos;
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('deflateSetDictionary()');
   {$endif}

  length := dictLength;
  hash_head := 0;

  if ((@strm = nil) or (strm.internal = nil) or (dictionary = nil) or
    (internal_state(strm.internal).wrap = 2) or
    ((internal_state(strm.internal).wrap = 1) and (internal_state(strm.internal).status <> INIT_STATE))) then
  begin
    result := Z_STREAM_ERROR;
    exit;
  end;

  s := strm.internal;
  strm.adler := adler32(strm.adler, dictionary, dictLength);

  if (length < MIN_MATCH) then
  begin
    result := Z_OK;
    exit;
  end;

  if (length > s^.w_size - MIN_LOOKAHEAD) then
  begin
    length := s^.w_size - MIN_LOOKAHEAD;
{#ifndef USE_DICT_HEAD
 dictionary += dictLength - length; /* use the tail of the dictionary */
#endif}
  end;
  ZlibMemCpy(s.window, dictionary, length);
  s.strstart := length;
  s.block_start := long(length);

  { Insert all strings in the hash table (except for the last two bytes).
    s.lookahead stays nil, so s.ins_h will be recomputed at the next
    call of fill_window.}

  s.ins_h := s.window[0];
  UPDATE_HASH(s ^ , s.ins_h, s.window[1]);
  n := 0;
  while n <= length - MIN_MATCH do
  begin
    INSERT_STRING(s ^ , n, hash_head);
    inc(n);
  end;
  if (hash_head <> 0) then hash_head := 0; // to make compiler happy
  result := Z_OK;
end;

begin
  z_errmsg[0] := 'need dictionary'; // Z_NEED_DICT       2
  z_errmsg[1] := 'stream end'; // Z_STREAM_END      1
  z_errmsg[2] := ''; // Z_OK              0
  z_errmsg[3] := 'file error'; // Z_ERRNO         (-1)
  z_errmsg[4] := 'stream error'; // Z_STREAM_ERROR  (-2)
  z_errmsg[5] := 'data error'; // Z_DATA_ERROR    (-3)
  z_errmsg[6] := 'insufficient memory'; // Z_MEM_ERROR     (-4)
  z_errmsg[7] := 'buffer error'; // Z_BUF_ERROR     (-5)
  z_errmsg[8] := 'incompatible version'; // Z_VERSION_ERROR (-6)
  z_errmsg[9] := '';

 // store only
  configuration_table[0].good_length := 0;
    // reduce lazy search above this match length
  configuration_table[0].max_lazy := 0;
    // do not perform lazy search above this match length
  configuration_table[0].nice_length := 0; // quit search above this match length
  configuration_table[0].max_chain := 0;
  configuration_table[0].func :=  deflate_stored ;

 // maximum speed, no lazy matches
  configuration_table[1].good_length := 4;
    // reduce lazy search above this match length
  configuration_table[1].max_lazy := 4;
    // do not perform lazy search above this match length
  configuration_table[1].nice_length := 8; // quit search above this match length
  configuration_table[1].max_chain := 4;
  configuration_table[1].func :=  deflate_fast ;

  configuration_table[2].good_length := 4;
    // reduce lazy search above this match length
  configuration_table[2].max_lazy := 5;
    // do not perform lazy search above this match length
  configuration_table[2].nice_length := 16;
    // quit search above this match length
  configuration_table[2].max_chain := 8;
  configuration_table[2].func :=  deflate_fast ;

  configuration_table[3].good_length := 4;
    // reduce lazy search above this match length
  configuration_table[3].max_lazy := 6;
    // do not perform lazy search above this match length
  configuration_table[3].nice_length := 32;
    // quit search above this match length
  configuration_table[3].max_chain := 32;
  configuration_table[3].func :=  deflate_fast ;

 // lazy matches
  configuration_table[4].good_length := 4;
    // reduce lazy search above this match length
  configuration_table[4].max_lazy := 4;
    // do not perform lazy search above this match length
  configuration_table[4].nice_length := 16;
    // quit search above this match length
  configuration_table[4].max_chain := 16;
  configuration_table[4].func :=  deflate_slow ;

  configuration_table[5].good_length := 8;
    // reduce lazy search above this match length
  configuration_table[5].max_lazy := 16;
    // do not perform lazy search above this match length
  configuration_table[5].nice_length := 32;
    // quit search above this match length
  configuration_table[5].max_chain := 32;
  configuration_table[5].func :=  deflate_slow ;

  configuration_table[6].good_length := 8;
    // reduce lazy search above this match length
  configuration_table[6].max_lazy := 16;
    // do not perform lazy search above this match length
  configuration_table[6].nice_length := 128;
    // quit search above this match length
  configuration_table[6].max_chain := 128;
  configuration_table[6].func :=  deflate_slow ;

  configuration_table[7].good_length := 8;
    // reduce lazy search above this match length
  configuration_table[7].max_lazy := 32;
    // do not perform lazy search above this match length
  configuration_table[7].nice_length := 128;
    // quit search above this match length
  configuration_table[7].max_chain := 256;
  configuration_table[7].func :=  deflate_slow ;

  configuration_table[8].good_length := 32;
    // reduce lazy search above this match length
  configuration_table[8].max_lazy := 128;
    // do not perform lazy search above this match length
  configuration_table[8].nice_length := 258;
    // quit search above this match length
  configuration_table[8].max_chain := 1024;
  configuration_table[8].func :=  deflate_slow ;

 // maximum compression
  configuration_table[9].good_length := 32;
    // reduce lazy search above this match length
  configuration_table[9].max_lazy := 258;
    // do not perform lazy search above this match length
  configuration_table[9].nice_length := 258;
    // quit search above this match length
  configuration_table[9].max_chain := 4096;
  configuration_table[9].func :=  deflate_slow ;
 {* Note: the deflate() code requires max_lazy >= MIN_MATCH and max_chain >= 4
 * For deflate_fast() (levels <= 3) good is ignored and lazy has a different
 * meaning.}


  for tmpi := 0 to BL_CODES - 1 do
    bl_order[tmpi] := bl_order_const[tmpi];
{* The lengths of the bit length codes are sent in order of decreasing
 * probability, to avoid transmitting the lengths for unused bit length codes.}
  for tmpi := 0 to D_CODES - 1 do
    extra_dbits[tmpi] := extra_dbits_const[tmpi];
  for tmpi := 0 to LENGTH_CODES - 1 do
    extra_lbits[tmpi] := extra_lbits_const[tmpi];
  for tmpi := 0 to BL_CODES - 1 do
    extra_blbits[tmpi] := extra_blbits_const[tmpi];
  for tmpi := 0 to DIST_CODE_LEN - 1 do
    _dist_code[tmpi] := _dist_code_const[tmpi];
  for tmpi := 0 to L_CODES + 2 - 1 do
  begin
    static_ltree[tmpi] := static_ltree_const[tmpi];
  end;
  for tmpi := 0 to D_CODES - 1 do
  begin
    static_dtree[tmpi] := static_dtree_const[tmpi];
  end;
  for tmpi := 0 to MAX_MATCH - MIN_MATCH do
    _length_code[tmpi] := _length_code_const[tmpi];
  for tmpi := 0 to LENGTH_CODES - 1 do
    base_length[tmpi] := base_length_const[tmpi];
  for tmpi := 0 to D_CODES - 1 do
    base_dist[tmpi] := base_dist_const[tmpi];
    
  static_l_desc.static_tree := @static_ltree;
  static_l_desc.extra_bits := @extra_lbits;
  static_l_desc.extra_base := LITERALS + 1;
  static_l_desc.elems := L_CODES;
  static_l_desc.max_length := MAX_BITS;
  
  static_d_desc.static_tree := @static_dtree;
  static_d_desc.extra_bits := @extra_dbits;
  static_d_desc.extra_base := 0;
  static_d_desc.elems := D_CODES;
  static_d_desc.max_length := MAX_BITS;

  static_bl_desc.static_tree := Nil;
  static_bl_desc.extra_bits := @extra_blbits;
  static_bl_desc.extra_base := 0;
  static_bl_desc.elems := BL_CODES;
  static_bl_desc.max_length := MAX_BL_BITS;
  

 {$else}
implementation

 {$endif}

end.
