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

unit SBZUncompressUnit;

interface

{$ifndef DONT_USE_ZLIB}

{$WARNINGS OFF}

{.$define SECURE_BLACKBOX_DEBUG}

uses
{$ifdef SB_WINDOWS}
      windows,
 {$endif}
  // we DON'T use SysUtils in Delphi.NET
      SysUtils,
{$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
      SBDumper,
 {$endif}
  SBTypes,
  SBUtils,
      SBZCommonUnit;


const

 {  Maximum size of dynamic tree.  The maximum found in a long but non-
    exhaustive search was 1004 huft structures (850 for length/literals
    and 154 for distances, the latter actually the result of an
    exhaustive search).  The actual maximum is not known, but the
    value below is more than safe. }
 MANY=1440;
 DEF_WBITS=MAX_WBITS;
// If BMAX needs to be larger than 16, then h and x[] should be uLong.
 BMAX=15; { maximum bit length of any code }

type  
//  code_s = packed record
  code =  packed   record
    op: byte;   //      /* operation, extra bits, table bits */
    bits: byte; //      /* bits in this part of the code */
    val: cardinal;  //      /* offset in table or code value */
    
  end;

  TArrShr = array[0..320] of cardinal;
  PArrShr = ^TArrShr;
  TArrShr288 = array[0..288] of cardinal;
  PArrShr288 = ^TArrShr;

  PCode = ^code;
  TArrCds = array[0..ENOUGH] of code;
  PArrCds = ^TArrCds;
  TArrCds31 = array[0..31] of code;
  PArrCds31 = ^TArrCds31;
  TArrCds511 = array[0..511] of code;
  PArrCds511 = ^TArrCds511;

//  PPArrCds = ^PArrCds;

 inflate_mode =  (
    HEAD,       // i: waiting for magic header */
    DICTID,     // i: waiting for dictionary check value */
    DICT,       // waiting for inflateSetDictionary() call */
    TYPEB,       // (aianoi TYPE) i: waiting for type bits, including last-flag bit */
    TYPEDO,     // i: same, but skip check to exit inflate on new block */
    STORED,     // i: waiting for stored size (length and complement) */
    COPY,       // i/o: waiting for input or output to copy stored block */
    TABLE,      // i: waiting for dynamic block table lengths */
    LENLENS,    // i: waiting for code length code lengths */
    CODELENS,   // i: waiting for length/lit and distance code lengths */
    LEN,        // i: waiting for length/lit code */
    LENEXT,     // i: waiting for length extra bits */
    DIST,       // i: waiting for distance code */
    DISTEXT,    // i: waiting for distance extra bits */
    MATCH,      // o: waiting for output space to copy string */
    LIT,        // o: waiting for output space to write literal */
    CHECK,      // i: waiting for 32-bit check value */
    DONE,       // finished check, done -- remain here until reset */
    BAD,        // got a data error -- remain here until reset */
    MEM,        // got an inflate() memory error -- remain here until reset */
    SYNC        // looking for synchronization bytes to restart inflate() */
      );     // got an error--stay here

// inflate private state
 inflate_state = ^inflate_state_s;
 inflate_state_s = record
   mode :inflate_mode;   // current inflate mode
   last : integer;      //* true if processing last block */
   wrap : integer;      //* bit 0 true for zlib, bit 1 true for gzip */
   havedict : integer;  //* true if dictionary provided */
   flags : integer;     //* gzip header method and flags (0 if zlib) */
   dmax : cardinal;     //* zlib header max distance 
   check : ulg;        //* protected copy of check value */
   total : ulg;        //* protected copy of output count */
    //* sliding window */
   wbits : uInt;       // log base 2 of requested window size */
   wsize : uInt;       //* window size or zero if not using window */
   whave : uInt;       //* valid bytes in the window */
   Write : uInt;       //* window write index */
   //* bit accumulator */
   hold : uLg;         //* input bit accumulator */
   bits : uInt;        //* number of bits in "in" */
   //* for string and stored block copying */
   Length : uInt;     //* literal or length of data to copy */
   offset : uInt;     //* distance back to copy string from */
   //* for table and code decoding */
   extra : uInt;     //* extra bits needed */
   window : PAnsiChar;  //* allocated sliding window, if needed */
 //        /* fixed and dynamic code tables */
 //  lencode : ^code;  //  /* starting table for length/literal codes */
   lencode : PArrCds511;  //  /* starting table for length/literal codes */
   distcode : PArrCds31; //  /* starting table for distance codes */

   lenbits : uInt;  //* index bits for lencode */
   distbits : uInt; //         /* index bits for distcode */
         //* dynamic table building */
   ncode : uInt; //            /* number of code length code lengths */
   nlen : uInt; //              /* number of length code lengths */
   ndist : uInt; //            /* number of distance code lengths */
   have : uInt;  //            /* number of code lengths in lens[] */
 //  Newt : ^code;             /* next available space in codes[] */
   next : PCode; // next available space in codes[]
   lens : TArrShr;
   work : TArrShr288;
   codes: TArrCds;  //       /* space for code tables */
 end;

//function inflateEnd(var z :TZStreamRec):integer;
function inflateReset(var z :TZStreamRec):integer; 
function inflateInit_(var z :TZStreamRec;
  const version: ByteArray ; stream_size: integer ): integer; 
function inflateInit2_(var z :TZStreamRec;w :integer;
  const version: ByteArray ; stream_size: integer ): integer; 
function inflateEnd(var z :TZStreamRec):Integer; 
{   inflate decompresses as much data as possible, and stops when the input
  buffer becomes empty or the output buffer becomes full. It may some
  introduce some output latency (reading input without producing any output)
  except when forced to flush.

  The detailed semantics are as follows. inflate performs one or both of the
  following actions:

  - Decompress more input starting at next_in and update next_in and avail_in
    accordingly. If not all input can be processed (because there is not
    enough room in the output buffer), next_in is updated and processing
    will resume at this point for the next call of inflate().

  - Provide more output starting at next_out and update next_out and avail_out
    accordingly.  inflate() provides as much output as possible, until there
    is no more input data or no more space in the output buffer (see below
    about the flush parameter).

  Before the call of inflate(), the application should ensure that at least
  one of the actions is possible, by providing more input and/or consuming
  more output, and updating the next_* and avail_* values accordingly.
  The application can consume the uncompressed output when it wants, for
  example when the output buffer is full (avail_out == 0), or after each
  call of inflate(). If inflate returns Z_OK and with zero avail_out, it
  must be called again after making room in the output buffer because there
  might be more output pending.

    If the parameter flush is set to Z_SYNC_FLUSH, inflate flushes as much
  output as possible to the output buffer. The flushing behavior of inflate is
  not specified for values of the flush parameter other than Z_SYNC_FLUSH
  and Z_FINISH, but the current implementation actually flushes as much output
  as possible anyway.

    inflate() should normally be called until it returns Z_STREAM_END or an
  error. However if all decompression is to be performed in a single step
  (a single call of inflate), the parameter flush should be set to
  Z_FINISH. In this case all pending input is processed and all pending
  output is flushed; avail_out must be large enough to hold all the
  uncompressed data. (The size of the uncompressed data may have been saved
  by the compressor for this purpose.) The next operation on this stream must
  be inflateEnd to deallocate the decompression state. The use of Z_FINISH
  is never required, but can be used to inform inflate that a faster routine
  may be used for the single inflate() call.

     If a preset dictionary is needed at this point (see inflateSetDictionary
  below), inflate sets strm-adler to the adler32 checksum of the
  dictionary chosen by the compressor and returns Z_NEED_DICT; otherwise
  it sets strm->adler to the adler32 checksum of all output produced
  so far (that is, total_out bytes) and returns Z_OK, Z_STREAM_END or
  an error code as described below. At the end of the stream, inflate()
  checks that its computed adler32 checksum is equal to that saved by the
  compressor and returns Z_STREAM_END only if the checksum is correct.

    inflate() returns Z_OK if some progress has been made (more input processed
  or more output produced), Z_STREAM_END if the end of the compressed data has
  been reached and all uncompressed output has been produced, Z_NEED_DICT if a
  preset dictionary is needed at this point, Z_DATA_ERROR if the input data was
  corrupted (input stream not conforming to the zlib format or incorrect
  adler32 checksum), Z_STREAM_ERROR if the stream structure was inconsistent
  (for example if next_in or next_out was NULL), Z_MEM_ERROR if there was not
  enough memory, Z_BUF_ERROR if no progress is possible or if there was not
  enough room in the output buffer when Z_FINISH is used. In the Z_DATA_ERROR
  case, the application may then call inflateSync to look for a good
  compression block.}
function inflate(var z :TZStreamRec;f :integer):integer; 
function uncompress(var dest :ArrayPtr;var destLen :Cardinal; source :Bytef;sourceLen :uLong):integer; 
//function inflateSetDictionary(var strm: TZStreamRec; dictionary: PChar; dictLength :uInt):integer;
//procedure DecompressBuf(const InBuf: Pointer; InBytes: Integer;
// OutEstimate: Integer; out OutBuf: Pointer; out OutBytes: Integer);


implementation

type
 codetype = (
    CODES,
    LENS,
    DISTS
 );

 const 
   lbase : array[0..30] of cardinal = 
    ( 
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0, 0
    ) ; //* Length codes 257..285 base */
{$ifdef SB_DEFLATE64}
  lbase64 : array[0..30] of cardinal = 
    ( 
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 3, 0, 0
    ) ; //* Length codes 257..285 base */   
 {$endif}   

  lext : array[0..30]  of cardinal = 
    ( 
    16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18, 18,
    19, 19, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21, 16, 201, 196 // , 199, 198.
    ) ; //* Length codes 257..285 extra */
{$ifdef SB_DEFLATE64}   
  lext64 : array[0..30]  of cardinal =
    ( 
    16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18, 18,
    19, 19, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21, 31, 201, 196 // , 199, 198.
    ) ; //* Length codes 257..285 extra */   
 {$endif}   
   
  dbase : array[0..31]  of cardinal = 
    ( 
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577, 0, 0
    ) ; //* Distance codes 0..29 base */
{$ifdef SB_DEFLATE64}   
  dbase64 : array[0..31]  of cardinal =
    ( 
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577, 32769, 49153
    ) ; //* Deflate64 Distance codes 0..31 base */
 {$endif}   
   
   

  dext : array[0..31] of cardinal  = 
    ( 
    16, 16, 16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 21, 21, 22, 22,
    23, 23, 24, 24, 25, 25, 26, 26, 27, 27,
    28, 28, 29, 29, 64, 64
    ) ; //* Distance codes 0..29 extra */
{$ifdef SB_DEFLATE64}   
  dext64 : array[0..31] of cardinal  =
    ( 
    16, 16, 16, 16, 17, 17, 18, 18, 19, 19, 20, 20, 21, 21, 22, 22,
    23, 23, 24, 24, 25, 25, 26, 26, 27, 27,
    28, 28, 29, 29, 30, 30
    ) ; //* Deflate64 Distance codes 0..31 extra */
 {$endif}

  distfix: array[0..31] of code =
    (
      (op : (16); bits : (5); val : 1), (op : (23); bits : (5); val : 257), (op : (19); bits : (5); val : 17), (op : (27); bits : (5); val : 4097), (op : (17); bits : (5); val : 5), (op : (25); bits : (5); val : 1025),
      (op : (21); bits : (5); val : 65), (op : (29); bits : (5); val : 16385), (op : (16); bits : (5); val : 3), (op : (24); bits : (5); val : 513), (op : (20); bits : (5); val : 33), (op : (28); bits : (5); val : 8193),
      (op : (18); bits : (5); val : 9), (op : (26); bits : (5); val : 2049), (op : (22); bits : (5); val : 129), (op : (64); bits : (5); val : 0), (op : (16); bits : (5); val : 2), (op : (23); bits : (5); val : 385),
      (op : (19); bits : (5); val : 25), (op : (27); bits : (5); val : 6145), (op : (17); bits : (5); val : 7), (op : (25); bits : (5); val : 1537), (op : (21); bits : (5); val : 97), (op : (29); bits : (5); val : 24577),
      (op : (16); bits : (5); val : 4), (op : (24); bits : (5); val : 769), (op : (20); bits : (5); val : 49), (op : (28); bits : (5); val : 12289), (op : (18); bits : (5); val : 13), (op : (26); bits : (5); val : 3073),
      (op : (22); bits : (5); val : 193), (op : (64); bits : (5); val : 0)
    )
     ;
  
{$ifdef SB_DEFLATE64}  
  distfix64: array[0..31] of code =
    (
      (op : (16); bits : (5); val : 1), (op : (23); bits : (5); val : 257), (op : (19); bits : (5); val : 17), (op : (27); bits : (5); val : 4097), (op : (17); bits : (5); val : 5), (op : (25); bits : (5); val : 1025),
      (op : (21); bits : (5); val : 65), (op : (29); bits : (5); val : 16385), (op : (16); bits : (5); val : 3), (op : (24); bits : (5); val : 513), (op : (20); bits : (5); val : 33), (op : (28); bits : (5); val : 8193),
      (op : (18); bits : (5); val : 9), (op : (26); bits : (5); val : 2049), (op : (22); bits : (5); val : 129), (op : (30); bits : (5); val : 32769), (op : (16); bits : (5); val : 2), (op : (23); bits : (5); val : 385),
      (op : (19); bits : (5); val : 25), (op : (27); bits : (5); val : 6145), (op : (17); bits : (5); val : 7), (op : (25); bits : (5); val : 1537), (op : (21); bits : (5); val : 97), (op : (29); bits : (5); val : 24577),
      (op : (16); bits : (5); val : 4), (op : (24); bits : (5); val : 769), (op : (20); bits : (5); val : 49), (op : (28); bits : (5); val : 12289), (op : (18); bits : (5); val : 13), (op : (26); bits : (5); val : 3073),
      (op : (22); bits : (5); val : 193), (op : (30); bits : (5); val : 49153)
    )
     ;
 {$endif}

  lenfix : array[0..511] of code =
    (
      (op : (96) ; bits : (7); val : 0),(op : (0);bits : (8); val : 80),(op : (0);bits : (8); val : 16),(op : (20);bits : (8); val : 115),(op : (18);bits : (7); val : 31),(op : (0);bits : (8); val : 112),(op : (0);bits : (8); val : 48),
      (op : (0);bits : (9); val : 192),(op : (16);bits : (7); val : 10),(op : (0);bits : (8); val : 96),(op : (0);bits : (8); val : 32),(op : (0);bits : (9); val : 160),(op : (0);bits : (8); val : 0),(op : (0);bits : (8); val : 128),
      (op : (0);bits : (8); val : 64),(op : (0);bits : (9); val : 224),(op : (16);bits : (7); val : 6),(op : (0);bits : (8); val : 88),(op : (0);bits : (8); val : 24),(op : (0);bits : (9); val : 144),(op : (19);bits : (7); val : 59),
      (op : (0);bits : (8); val : 120),(op : (0);bits : (8); val : 56),(op : (0);bits : (9); val : 208),(op : (17);bits : (7); val : 17),(op : (0);bits : (8); val : 104),(op : (0);bits : (8); val : 40),(op : (0);bits : (9); val : 176),
      (op : (0);bits : (8); val : 8),(op : (0);bits : (8); val : 136),(op : (0);bits : (8); val : 72),(op : (0);bits : (9); val : 240),(op : (16);bits : (7); val : 4),(op : (0);bits : (8); val : 84),(op : (0);bits : (8); val : 20),
      (op : (21);bits : (8); val : 227),(op : (19);bits : (7); val : 43),(op : (0);bits : (8); val : 116),(op : (0);bits : (8); val : 52),(op : (0);bits : (9); val : 200),(op : (17);bits : (7); val : 13),(op : (0);bits : (8); val : 100),
      (op : (0);bits : (8); val : 36),(op : (0);bits : (9); val : 168),(op : (0);bits : (8); val : 4),(op : (0);bits : (8); val : 132),(op : (0);bits : (8); val : 68),(op : (0);bits : (9); val : 232),(op : (16);bits : (7); val : 8),
      (op : (0);bits : (8); val : 92),(op : (0);bits : (8); val : 28),(op : (0);bits : (9); val : 152),(op : (20);bits : (7); val : 83),(op : (0);bits : (8); val : 124),(op : (0);bits : (8); val : 60),(op : (0);bits : (9); val : 216),
      (op : (18);bits : (7); val : 23),(op : (0);bits : (8); val : 108),(op : (0);bits : (8); val : 44),(op : (0);bits : (9); val : 184),(op : (0);bits : (8); val : 12),(op : (0);bits : (8); val : 140),(op : (0);bits : (8); val : 76),
      (op : (0);bits : (9); val : 248),(op : (16);bits : (7); val : 3),(op : (0);bits : (8); val : 82),(op : (0);bits : (8); val : 18),(op : (21);bits : (8); val : 163),(op : (19);bits : (7); val : 35),(op : (0);bits : (8); val : 114),
      (op : (0);bits : (8); val : 50),(op : (0);bits : (9); val : 196),(op : (17);bits : (7); val : 11),(op : (0);bits : (8); val : 98),(op : (0);bits : (8); val : 34),(op : (0);bits : (9); val : 164),(op : (0);bits : (8); val : 2),
      (op : (0);bits : (8); val : 130),(op : (0);bits : (8); val : 66),(op : (0);bits : (9); val : 228),(op : (16);bits : (7); val : 7),(op : (0);bits : (8); val : 90),(op : (0);bits : (8); val : 26),(op : (0);bits : (9); val : 148),
      (op : (20);bits : (7); val : 67),(op : (0);bits : (8); val : 122),(op : (0);bits : (8); val : 58),(op : (0);bits : (9); val : 212),(op : (18);bits : (7); val : 19),(op : (0);bits : (8); val : 106),(op : (0);bits : (8); val : 42),
      (op : (0);bits : (9); val : 180),(op : (0);bits : (8); val : 10),(op : (0);bits : (8); val : 138),(op : (0);bits : (8); val : 74),(op : (0);bits : (9); val : 244),(op : (16);bits : (7); val : 5),(op : (0);bits : (8); val : 86),
      (op : (0);bits : (8); val : 22),(op : (64);bits : (8); val : 0),(op : (19);bits : (7); val : 51),(op : (0);bits : (8); val : 118),(op : (0);bits : (8); val : 54),(op : (0);bits : (9); val : 204),(op : (17);bits : (7); val : 15),
      (op : (0);bits : (8); val : 102),(op : (0);bits : (8); val : 38),(op : (0);bits : (9); val : 172),(op : (0);bits : (8); val : 6),(op : (0);bits : (8); val : 134),(op : (0);bits : (8); val : 70),(op : (0);bits : (9); val : 236),
      (op : (16);bits : (7); val : 9),(op : (0);bits : (8); val : 94),(op : (0);bits : (8); val : 30),(op : (0);bits : (9); val : 156),(op : (20);bits : (7); val : 99),(op : (0);bits : (8); val : 126),(op : (0);bits : (8); val : 62),
      (op : (0);bits : (9); val : 220),(op : (18);bits : (7); val : 27),(op : (0);bits : (8); val : 110),(op : (0);bits : (8); val : 46),(op : (0);bits : (9); val : 188),(op : (0);bits : (8); val : 14),(op : (0);bits : (8); val : 142),
      (op : (0);bits : (8); val : 78),(op : (0);bits : (9); val : 252),(op : (96);bits : (7); val : 0),(op : (0);bits : (8); val : 81),(op : (0);bits : (8); val : 17),(op : (21);bits : (8); val : 131),(op : (18);bits : (7); val : 31),
      (op : (0);bits : (8); val : 113),(op : (0);bits : (8); val : 49),(op : (0);bits : (9); val : 194),(op : (16);bits : (7); val : 10),(op : (0);bits : (8); val : 97),(op : (0);bits : (8); val : 33),(op : (0);bits : (9); val : 162),
      (op : (0);bits : (8); val : 1),(op : (0);bits : (8); val : 129),(op : (0);bits : (8); val : 65),(op : (0);bits : (9); val : 226),(op : (16);bits : (7); val : 6),(op : (0);bits : (8); val : 89),(op : (0);bits : (8); val : 25),
      (op : (0);bits : (9); val : 146),(op : (19);bits : (7); val : 59),(op : (0);bits : (8); val : 121),(op : (0);bits : (8); val : 57),(op : (0);bits : (9); val : 210),(op : (17);bits : (7); val : 17),(op : (0);bits : (8); val : 105),
      (op : (0);bits : (8); val : 41),(op : (0);bits : (9); val : 178),(op : (0);bits : (8); val : 9),(op : (0);bits : (8); val : 137),(op : (0);bits : (8); val : 73),(op : (0);bits : (9); val : 242),(op : (16);bits : (7); val : 4),
      (op : (0);bits : (8); val : 85),(op : (0);bits : (8); val : 21),(op : (16);bits : (8); val : 258),(op : (19);bits : (7); val : 43),(op : (0);bits : (8); val : 117),(op : (0);bits : (8); val : 53),(op : (0);bits : (9); val : 202),
      (op : (17);bits : (7); val : 13),(op : (0);bits : (8); val : 101),(op : (0);bits : (8); val : 37),(op : (0);bits : (9); val : 170),(op : (0);bits : (8); val : 5),(op : (0);bits : (8); val : 133),(op : (0);bits : (8); val : 69),
      (op : (0);bits : (9); val : 234),(op : (16);bits : (7); val : 8),(op : (0);bits : (8); val : 93),(op : (0);bits : (8); val : 29),(op : (0);bits : (9); val : 154),(op : (20);bits : (7); val : 83),(op : (0);bits : (8); val : 125),
      (op : (0);bits : (8); val : 61),(op : (0);bits : (9); val : 218),(op : (18);bits : (7); val : 23),(op : (0);bits : (8); val : 109),(op : (0);bits : (8); val : 45),(op : (0);bits : (9); val : 186),(op : (0);bits : (8); val : 13),
      (op : (0);bits : (8); val : 141),(op : (0);bits : (8); val : 77),(op : (0);bits : (9); val : 250),(op : (16);bits : (7); val : 3),(op : (0);bits : (8); val : 83),(op : (0);bits : (8); val : 19),(op : (21);bits : (8); val : 195),
      (op : (19);bits : (7); val : 35),(op : (0);bits : (8); val : 115),(op : (0);bits : (8); val : 51),(op : (0);bits : (9); val : 198),(op : (17);bits : (7); val : 11),(op : (0);bits : (8); val : 99),(op : (0);bits : (8); val : 35),
      (op : (0);bits : (9); val : 166),(op : (0);bits : (8); val : 3),(op : (0);bits : (8); val : 131),(op : (0);bits : (8); val : 67),(op : (0);bits : (9); val : 230),(op : (16);bits : (7); val : 7),(op : (0);bits : (8); val : 91),
      (op : (0);bits : (8); val : 27),(op : (0);bits : (9); val : 150),(op : (20);bits : (7); val : 67),(op : (0);bits : (8); val : 123),(op : (0);bits : (8); val : 59),(op : (0);bits : (9); val : 214),(op : (18);bits : (7); val : 19),
      (op : (0);bits : (8); val : 107),(op : (0);bits : (8); val : 43),(op : (0);bits : (9); val : 182),(op : (0);bits : (8); val : 11),(op : (0);bits : (8); val : 139),(op : (0);bits : (8); val : 75),(op : (0);bits : (9); val : 246),
      (op : (16);bits : (7); val : 5),(op : (0);bits : (8); val : 87),(op : (0);bits : (8); val : 23),(op : (64);bits : (8); val : 0),(op : (19);bits : (7); val : 51),(op : (0);bits : (8); val : 119),(op : (0);bits : (8); val : 55),
      (op : (0);bits : (9); val : 206),(op : (17);bits : (7); val : 15),(op : (0);bits : (8); val : 103),(op : (0);bits : (8); val : 39),(op : (0);bits : (9); val : 174),(op : (0);bits : (8); val : 7),(op : (0);bits : (8); val : 135),
      (op : (0);bits : (8); val : 71),(op : (0);bits : (9); val : 238),(op : (16);bits : (7); val : 9),(op : (0);bits : (8); val : 95),(op : (0);bits : (8); val : 31),(op : (0);bits : (9); val : 158),(op : (20);bits : (7); val : 99),
      (op : (0);bits : (8); val : 127),(op : (0);bits : (8); val : 63),(op : (0);bits : (9); val : 222),(op : (18);bits : (7); val : 27),(op : (0);bits : (8); val : 111),(op : (0);bits : (8); val : 47),(op : (0);bits : (9); val : 190),
      (op : (0);bits : (8); val : 15),(op : (0);bits : (8); val : 143),(op : (0);bits : (8); val : 79),(op : (0);bits : (9); val : 254),(op : (96);bits : (7); val : 0),(op : (0);bits : (8); val : 80),(op : (0);bits : (8); val : 16),
      (op : (20);bits : (8); val : 115),(op : (18);bits : (7); val : 31),(op : (0);bits : (8); val : 112),(op : (0);bits : (8); val : 48),(op : (0);bits : (9); val : 193),(op : (16);bits : (7); val : 10),(op : (0);bits : (8); val : 96),
      (op : (0);bits : (8); val : 32),(op : (0);bits : (9); val : 161),(op : (0);bits : (8); val : 0),(op : (0);bits : (8); val : 128),(op : (0);bits : (8); val : 64),(op : (0);bits : (9); val : 225),(op : (16);bits : (7); val : 6),
      (op : (0);bits : (8); val : 88),(op : (0);bits : (8); val : 24),(op : (0);bits : (9); val : 145),(op : (19);bits : (7); val : 59),(op : (0);bits : (8); val : 120),(op : (0);bits : (8); val : 56),(op : (0);bits : (9); val : 209),
      (op : (17);bits : (7); val : 17),(op : (0);bits : (8); val : 104),(op : (0);bits : (8); val : 40),(op : (0);bits : (9); val : 177),(op : (0);bits : (8); val : 8),(op : (0);bits : (8); val : 136),(op : (0);bits : (8); val : 72),
      (op : (0);bits : (9); val : 241),(op : (16);bits : (7); val : 4),(op : (0);bits : (8); val : 84),(op : (0);bits : (8); val : 20),(op : (21);bits : (8); val : 227),(op : (19);bits : (7); val : 43),(op : (0);bits : (8); val : 116),
      (op : (0);bits : (8); val : 52),(op : (0);bits : (9); val : 201),(op : (17);bits : (7); val : 13),(op : (0);bits : (8); val : 100),(op : (0);bits : (8); val : 36),(op : (0);bits : (9); val : 169),(op : (0);bits : (8); val : 4),
      (op : (0);bits : (8); val : 132),(op : (0);bits : (8); val : 68),(op : (0);bits : (9); val : 233),(op : (16);bits : (7); val : 8),(op : (0);bits : (8); val : 92),(op : (0);bits : (8); val : 28),(op : (0);bits : (9); val : 153),
      (op : (20);bits : (7); val : 83),(op : (0);bits : (8); val : 124),(op : (0);bits : (8); val : 60),(op : (0);bits : (9); val : 217),(op : (18);bits : (7); val : 23),(op : (0);bits : (8); val : 108),(op : (0);bits : (8); val : 44),
      (op : (0);bits : (9); val : 185),(op : (0);bits : (8); val : 12),(op : (0);bits : (8); val : 140),(op : (0);bits : (8); val : 76),(op : (0);bits : (9); val : 249),(op : (16);bits : (7); val : 3),(op : (0);bits : (8); val : 82),
      (op : (0);bits : (8); val : 18),(op : (21);bits : (8); val : 163),(op : (19);bits : (7); val : 35),(op : (0);bits : (8); val : 114),(op : (0);bits : (8); val : 50),(op : (0);bits : (9); val : 197),(op : (17);bits : (7); val : 11),
      (op : (0);bits : (8); val : 98),(op : (0);bits : (8); val : 34),(op : (0);bits : (9); val : 165),(op : (0);bits : (8); val : 2),(op : (0);bits : (8); val : 130),(op : (0);bits : (8); val : 66),(op : (0);bits : (9); val : 229),
      (op : (16);bits : (7); val : 7),(op : (0);bits : (8); val : 90),(op : (0);bits : (8); val : 26),(op : (0);bits : (9); val : 149),(op : (20);bits : (7); val : 67),(op : (0);bits : (8); val : 122),(op : (0);bits : (8); val : 58),
      (op : (0);bits : (9); val : 213),(op : (18);bits : (7); val : 19),(op : (0);bits : (8); val : 106),(op : (0);bits : (8); val : 42),(op : (0);bits : (9); val : 181),(op : (0);bits : (8); val : 10),(op : (0);bits : (8); val : 138),
      (op : (0);bits : (8); val : 74),(op : (0);bits : (9); val : 245),(op : (16);bits : (7); val : 5),(op : (0);bits : (8); val : 86),(op : (0);bits : (8); val : 22),(op : (64);bits : (8); val : 0),(op : (19);bits : (7); val : 51),
      (op : (0);bits : (8); val : 118),(op : (0);bits : (8); val : 54),(op : (0);bits : (9); val : 205),(op : (17);bits : (7); val : 15),(op : (0);bits : (8); val : 102),(op : (0);bits : (8); val : 38),(op : (0);bits : (9); val : 173),
      (op : (0);bits : (8); val : 6),(op : (0);bits : (8); val : 134),(op : (0);bits : (8); val : 70),(op : (0);bits : (9); val : 237),(op : (16);bits : (7); val : 9),(op : (0);bits : (8); val : 94),(op : (0);bits : (8); val : 30),
      (op : (0);bits : (9); val : 157),(op : (20);bits : (7); val : 99),(op : (0);bits : (8); val : 126),(op : (0);bits : (8); val : 62),(op : (0);bits : (9); val : 221),(op : (18);bits : (7); val : 27),(op : (0);bits : (8); val : 110),
      (op : (0);bits : (8); val : 46),(op : (0);bits : (9); val : 189),(op : (0);bits : (8); val : 14),(op : (0);bits : (8); val : 142),(op : (0);bits : (8); val : 78),(op : (0);bits : (9); val : 253),(op : (96);bits : (7); val : 0),
      (op : (0);bits : (8); val : 81),(op : (0);bits : (8); val : 17),(op : (21);bits : (8); val : 131),(op : (18);bits : (7); val : 31),(op : (0);bits : (8); val : 113),(op : (0);bits : (8); val : 49),(op : (0);bits : (9); val : 195),

      (op : (16); bits : (7); val : 10),(op : (0); bits : (8); val : 97),(op : (0); bits : (8); val : 33),(op : (0); bits : (9); val : 163),(op : (0); bits : (8); val : 1),(op : (0); bits : (8); val : 129),(op : (0); bits : (8); val : 65),
      (op : (0); bits : (9); val : 227),(op : (16); bits : (7); val : 6),(op : (0); bits : (8); val : 89),(op : (0); bits : (8); val : 25),(op : (0); bits : (9); val : 147),(op : (19); bits : (7); val : 59),(op : (0); bits : (8); val : 121),
      (op : (0); bits : (8); val : 57),(op : (0); bits : (9); val : 211),(op : (17); bits : (7); val : 17),(op : (0); bits : (8); val : 105),(op : (0); bits : (8); val : 41),(op : (0); bits : (9); val : 179),(op : (0); bits : (8); val : 9),
      (op : (0); bits : (8); val : 137),(op : (0); bits : (8); val : 73),(op : (0); bits : (9); val : 243),(op : (16); bits : (7); val : 4),(op : (0); bits : (8); val : 85),(op : (0); bits : (8); val : 21),(op : (16); bits : (8); val : 258),
      (op : (19); bits : (7); val : 43),(op : (0); bits : (8); val : 117),(op : (0); bits : (8); val : 53),(op : (0); bits : (9); val : 203),(op : (17); bits : (7); val : 13),(op : (0); bits : (8); val : 101),(op : (0); bits : (8); val : 37),
      (op : (0); bits : (9); val : 171),(op : (0); bits : (8); val : 5),(op : (0); bits : (8); val : 133),(op : (0); bits : (8); val : 69),(op : (0); bits : (9); val : 235),(op : (16); bits : (7); val : 8),(op : (0); bits : (8); val : 93),
      (op : (0); bits : (8); val : 29),(op : (0); bits : (9); val : 155),(op : (20); bits : (7); val : 83),(op : (0); bits : (8); val : 125),(op : (0); bits : (8); val : 61),(op : (0); bits : (9); val : 219),(op : (18); bits : (7); val : 23),
      (op : (0); bits : (8); val : 109),(op : (0); bits : (8); val : 45),(op : (0); bits : (9); val : 187),(op : (0); bits : (8); val : 13),(op : (0); bits : (8); val : 141),(op : (0); bits : (8); val : 77),(op : (0); bits : (9); val : 251),
      (op : (16); bits : (7); val : 3),(op : (0); bits : (8); val : 83),(op : (0); bits : (8); val : 19),(op : (21); bits : (8); val : 195),(op : (19); bits : (7); val : 35),(op : (0); bits : (8); val : 115),(op : (0); bits : (8); val : 51),
      (op : (0); bits : (9); val : 199),(op : (17); bits : (7); val : 11),(op : (0); bits : (8); val : 99),(op : (0); bits : (8); val : 35),(op : (0); bits : (9); val : 167),(op : (0); bits : (8); val : 3),(op : (0); bits : (8); val : 131),
      (op : (0); bits : (8); val : 67),(op : (0); bits : (9); val : 231),(op : (16); bits : (7); val : 7),(op : (0); bits : (8); val : 91),(op : (0); bits : (8); val : 27),(op : (0); bits : (9); val : 151),(op : (20); bits : (7); val : 67),
      (op : (0); bits : (8); val : 123),(op : (0); bits : (8); val : 59),(op : (0); bits : (9); val : 215),(op : (18); bits : (7); val : 19),(op : (0); bits : (8); val : 107),(op : (0); bits : (8); val : 43),(op : (0); bits : (9); val : 183),
      (op : (0); bits : (8); val : 11),(op : (0); bits : (8); val : 139),(op : (0); bits : (8); val : 75),(op : (0); bits : (9); val : 247),(op : (16); bits : (7); val : 5),(op : (0); bits : (8); val : 87),(op : (0); bits : (8); val : 23),

      (op : (64); bits : (8); val : 0),(op : (19); bits : (7); val : 51),(op : (0); bits : (8); val : 119),(op : (0); bits : (8); val : 55),(op : (0); bits : (9); val : 207),(op : (17); bits : (7); val : 15),(op : (0); bits : (8); val : 103),
      (op : (0); bits : (8); val : 39),(op : (0); bits : (9); val : 175),(op : (0); bits : (8); val : 7),(op : (0); bits : (8); val : 135),(op : (0); bits : (8); val : 71),(op : (0); bits : (9); val : 239),(op : (16); bits : (7); val : 9),
      (op : (0); bits : (8); val : 95),(op : (0); bits : (8); val : 31),(op : (0); bits : (9); val : 159),(op : (20); bits : (7); val : 99),(op : (0); bits : (8); val : 127),(op : (0); bits : (8); val : 63),(op : (0); bits : (9); val : 223),
      (op : (18); bits : (7); val : 27),(op : (0); bits : (8); val : 111),(op : (0); bits : (8); val : 47),(op : (0); bits : (9); val : 191),(op : (0); bits : (8); val : 15),(op : (0); bits : (8); val : 143),(op : (0); bits : (8); val : 79),
      (op : (0); bits : (9); val : 255)
    );
  
{$ifdef SB_DEFLATE64}  
  lenfix64 : array[0..511] of code =
    (
      (op : (96) ; bits : (7); val : 0),(op : (0);bits : (8); val : 80),(op : (0);bits : (8); val : 16),(op : (20);bits : (8); val : 115),(op : (18);bits : (7); val : 31),(op : (0);bits : (8); val : 112),(op : (0);bits : (8); val : 48),
      (op : (0);bits : (9); val : 192),(op : (16);bits : (7); val : 10),(op : (0);bits : (8); val : 96),(op : (0);bits : (8); val : 32),(op : (0);bits : (9); val : 160),(op : (0);bits : (8); val : 0),(op : (0);bits : (8); val : 128),
      (op : (0);bits : (8); val : 64),(op : (0);bits : (9); val : 224),(op : (16);bits : (7); val : 6),(op : (0);bits : (8); val : 88),(op : (0);bits : (8); val : 24),(op : (0);bits : (9); val : 144),(op : (19);bits : (7); val : 59),
      (op : (0);bits : (8); val : 120),(op : (0);bits : (8); val : 56),(op : (0);bits : (9); val : 208),(op : (17);bits : (7); val : 17),(op : (0);bits : (8); val : 104),(op : (0);bits : (8); val : 40),(op : (0);bits : (9); val : 176),
      (op : (0);bits : (8); val : 8),(op : (0);bits : (8); val : 136),(op : (0);bits : (8); val : 72),(op : (0);bits : (9); val : 240),(op : (16);bits : (7); val : 4),(op : (0);bits : (8); val : 84),(op : (0);bits : (8); val : 20),
      (op : (21);bits : (8); val : 227),(op : (19);bits : (7); val : 43),(op : (0);bits : (8); val : 116),(op : (0);bits : (8); val : 52),(op : (0);bits : (9); val : 200),(op : (17);bits : (7); val : 13),(op : (0);bits : (8); val : 100),
      (op : (0);bits : (8); val : 36),(op : (0);bits : (9); val : 168),(op : (0);bits : (8); val : 4),(op : (0);bits : (8); val : 132),(op : (0);bits : (8); val : 68),(op : (0);bits : (9); val : 232),(op : (16);bits : (7); val : 8),
      (op : (0);bits : (8); val : 92),(op : (0);bits : (8); val : 28),(op : (0);bits : (9); val : 152),(op : (20);bits : (7); val : 83),(op : (0);bits : (8); val : 124),(op : (0);bits : (8); val : 60),(op : (0);bits : (9); val : 216),
      (op : (18);bits : (7); val : 23),(op : (0);bits : (8); val : 108),(op : (0);bits : (8); val : 44),(op : (0);bits : (9); val : 184),(op : (0);bits : (8); val : 12),(op : (0);bits : (8); val : 140),(op : (0);bits : (8); val : 76),
      (op : (0);bits : (9); val : 248),(op : (16);bits : (7); val : 3),(op : (0);bits : (8); val : 82),(op : (0);bits : (8); val : 18),(op : (21);bits : (8); val : 163),(op : (19);bits : (7); val : 35),(op : (0);bits : (8); val : 114),
      (op : (0);bits : (8); val : 50),(op : (0);bits : (9); val : 196),(op : (17);bits : (7); val : 11),(op : (0);bits : (8); val : 98),(op : (0);bits : (8); val : 34),(op : (0);bits : (9); val : 164),(op : (0);bits : (8); val : 2),
      (op : (0);bits : (8); val : 130),(op : (0);bits : (8); val : 66),(op : (0);bits : (9); val : 228),(op : (16);bits : (7); val : 7),(op : (0);bits : (8); val : 90),(op : (0);bits : (8); val : 26),(op : (0);bits : (9); val : 148),
      (op : (20);bits : (7); val : 67),(op : (0);bits : (8); val : 122),(op : (0);bits : (8); val : 58),(op : (0);bits : (9); val : 212),(op : (18);bits : (7); val : 19),(op : (0);bits : (8); val : 106),(op : (0);bits : (8); val : 42),
      (op : (0);bits : (9); val : 180),(op : (0);bits : (8); val : 10),(op : (0);bits : (8); val : 138),(op : (0);bits : (8); val : 74),(op : (0);bits : (9); val : 244),(op : (16);bits : (7); val : 5),(op : (0);bits : (8); val : 86),
      (op : (0);bits : (8); val : 22),(op : (64);bits : (8); val : 0),(op : (19);bits : (7); val : 51),(op : (0);bits : (8); val : 118),(op : (0);bits : (8); val : 54),(op : (0);bits : (9); val : 204),(op : (17);bits : (7); val : 15),
      (op : (0);bits : (8); val : 102),(op : (0);bits : (8); val : 38),(op : (0);bits : (9); val : 172),(op : (0);bits : (8); val : 6),(op : (0);bits : (8); val : 134),(op : (0);bits : (8); val : 70),(op : (0);bits : (9); val : 236),
      (op : (16);bits : (7); val : 9),(op : (0);bits : (8); val : 94),(op : (0);bits : (8); val : 30),(op : (0);bits : (9); val : 156),(op : (20);bits : (7); val : 99),(op : (0);bits : (8); val : 126),(op : (0);bits : (8); val : 62),
      (op : (0);bits : (9); val : 220),(op : (18);bits : (7); val : 27),(op : (0);bits : (8); val : 110),(op : (0);bits : (8); val : 46),(op : (0);bits : (9); val : 188),(op : (0);bits : (8); val : 14),(op : (0);bits : (8); val : 142),
      (op : (0);bits : (8); val : 78),(op : (0);bits : (9); val : 252),(op : (96);bits : (7); val : 0),(op : (0);bits : (8); val : 81),(op : (0);bits : (8); val : 17),(op : (21);bits : (8); val : 131),(op : (18);bits : (7); val : 31),
      (op : (0);bits : (8); val : 113),(op : (0);bits : (8); val : 49),(op : (0);bits : (9); val : 194),(op : (16);bits : (7); val : 10),(op : (0);bits : (8); val : 97),(op : (0);bits : (8); val : 33),(op : (0);bits : (9); val : 162),
      (op : (0);bits : (8); val : 1),(op : (0);bits : (8); val : 129),(op : (0);bits : (8); val : 65),(op : (0);bits : (9); val : 226),(op : (16);bits : (7); val : 6),(op : (0);bits : (8); val : 89),(op : (0);bits : (8); val : 25),
      (op : (0);bits : (9); val : 146),(op : (19);bits : (7); val : 59),(op : (0);bits : (8); val : 121),(op : (0);bits : (8); val : 57),(op : (0);bits : (9); val : 210),(op : (17);bits : (7); val : 17),(op : (0);bits : (8); val : 105),
      (op : (0);bits : (8); val : 41),(op : (0);bits : (9); val : 178),(op : (0);bits : (8); val : 9),(op : (0);bits : (8); val : 137),(op : (0);bits : (8); val : 73),(op : (0);bits : (9); val : 242),(op : (16);bits : (7); val : 4),
      (op : (0);bits : (8); val : 85),(op : (0);bits : (8); val : 21),(op : (31);bits : (8); val : 3),(op : (19);bits : (7); val : 43),(op : (0);bits : (8); val : 117),(op : (0);bits : (8); val : 53),(op : (0);bits : (9); val : 202),
      (op : (17);bits : (7); val : 13),(op : (0);bits : (8); val : 101),(op : (0);bits : (8); val : 37),(op : (0);bits : (9); val : 170),(op : (0);bits : (8); val : 5),(op : (0);bits : (8); val : 133),(op : (0);bits : (8); val : 69),
      (op : (0);bits : (9); val : 234),(op : (16);bits : (7); val : 8),(op : (0);bits : (8); val : 93),(op : (0);bits : (8); val : 29),(op : (0);bits : (9); val : 154),(op : (20);bits : (7); val : 83),(op : (0);bits : (8); val : 125),
      (op : (0);bits : (8); val : 61),(op : (0);bits : (9); val : 218),(op : (18);bits : (7); val : 23),(op : (0);bits : (8); val : 109),(op : (0);bits : (8); val : 45),(op : (0);bits : (9); val : 186),(op : (0);bits : (8); val : 13),
      (op : (0);bits : (8); val : 141),(op : (0);bits : (8); val : 77),(op : (0);bits : (9); val : 250),(op : (16);bits : (7); val : 3),(op : (0);bits : (8); val : 83),(op : (0);bits : (8); val : 19),(op : (21);bits : (8); val : 195),
      (op : (19);bits : (7); val : 35),(op : (0);bits : (8); val : 115),(op : (0);bits : (8); val : 51),(op : (0);bits : (9); val : 198),(op : (17);bits : (7); val : 11),(op : (0);bits : (8); val : 99),(op : (0);bits : (8); val : 35),
      (op : (0);bits : (9); val : 166),(op : (0);bits : (8); val : 3),(op : (0);bits : (8); val : 131),(op : (0);bits : (8); val : 67),(op : (0);bits : (9); val : 230),(op : (16);bits : (7); val : 7),(op : (0);bits : (8); val : 91),
      (op : (0);bits : (8); val : 27),(op : (0);bits : (9); val : 150),(op : (20);bits : (7); val : 67),(op : (0);bits : (8); val : 123),(op : (0);bits : (8); val : 59),(op : (0);bits : (9); val : 214),(op : (18);bits : (7); val : 19),
      (op : (0);bits : (8); val : 107),(op : (0);bits : (8); val : 43),(op : (0);bits : (9); val : 182),(op : (0);bits : (8); val : 11),(op : (0);bits : (8); val : 139),(op : (0);bits : (8); val : 75),(op : (0);bits : (9); val : 246),
      (op : (16);bits : (7); val : 5),(op : (0);bits : (8); val : 87),(op : (0);bits : (8); val : 23),(op : (64);bits : (8); val : 0),(op : (19);bits : (7); val : 51),(op : (0);bits : (8); val : 119),(op : (0);bits : (8); val : 55),
      (op : (0);bits : (9); val : 206),(op : (17);bits : (7); val : 15),(op : (0);bits : (8); val : 103),(op : (0);bits : (8); val : 39),(op : (0);bits : (9); val : 174),(op : (0);bits : (8); val : 7),(op : (0);bits : (8); val : 135),
      (op : (0);bits : (8); val : 71),(op : (0);bits : (9); val : 238),(op : (16);bits : (7); val : 9),(op : (0);bits : (8); val : 95),(op : (0);bits : (8); val : 31),(op : (0);bits : (9); val : 158),(op : (20);bits : (7); val : 99),
      (op : (0);bits : (8); val : 127),(op : (0);bits : (8); val : 63),(op : (0);bits : (9); val : 222),(op : (18);bits : (7); val : 27),(op : (0);bits : (8); val : 111),(op : (0);bits : (8); val : 47),(op : (0);bits : (9); val : 190),
      (op : (0);bits : (8); val : 15),(op : (0);bits : (8); val : 143),(op : (0);bits : (8); val : 79),(op : (0);bits : (9); val : 254),(op : (96);bits : (7); val : 0),(op : (0);bits : (8); val : 80),(op : (0);bits : (8); val : 16),
      (op : (20);bits : (8); val : 115),(op : (18);bits : (7); val : 31),(op : (0);bits : (8); val : 112),(op : (0);bits : (8); val : 48),(op : (0);bits : (9); val : 193),(op : (16);bits : (7); val : 10),(op : (0);bits : (8); val : 96),
      (op : (0);bits : (8); val : 32),(op : (0);bits : (9); val : 161),(op : (0);bits : (8); val : 0),(op : (0);bits : (8); val : 128),(op : (0);bits : (8); val : 64),(op : (0);bits : (9); val : 225),(op : (16);bits : (7); val : 6),
      (op : (0);bits : (8); val : 88),(op : (0);bits : (8); val : 24),(op : (0);bits : (9); val : 145),(op : (19);bits : (7); val : 59),(op : (0);bits : (8); val : 120),(op : (0);bits : (8); val : 56),(op : (0);bits : (9); val : 209),
      (op : (17);bits : (7); val : 17),(op : (0);bits : (8); val : 104),(op : (0);bits : (8); val : 40),(op : (0);bits : (9); val : 177),(op : (0);bits : (8); val : 8),(op : (0);bits : (8); val : 136),(op : (0);bits : (8); val : 72),
      (op : (0);bits : (9); val : 241),(op : (16);bits : (7); val : 4),(op : (0);bits : (8); val : 84),(op : (0);bits : (8); val : 20),(op : (21);bits : (8); val : 227),(op : (19);bits : (7); val : 43),(op : (0);bits : (8); val : 116),
      (op : (0);bits : (8); val : 52),(op : (0);bits : (9); val : 201),(op : (17);bits : (7); val : 13),(op : (0);bits : (8); val : 100),(op : (0);bits : (8); val : 36),(op : (0);bits : (9); val : 169),(op : (0);bits : (8); val : 4),
      (op : (0);bits : (8); val : 132),(op : (0);bits : (8); val : 68),(op : (0);bits : (9); val : 233),(op : (16);bits : (7); val : 8),(op : (0);bits : (8); val : 92),(op : (0);bits : (8); val : 28),(op : (0);bits : (9); val : 153),
      (op : (20);bits : (7); val : 83),(op : (0);bits : (8); val : 124),(op : (0);bits : (8); val : 60),(op : (0);bits : (9); val : 217),(op : (18);bits : (7); val : 23),(op : (0);bits : (8); val : 108),(op : (0);bits : (8); val : 44),
      (op : (0);bits : (9); val : 185),(op : (0);bits : (8); val : 12),(op : (0);bits : (8); val : 140),(op : (0);bits : (8); val : 76),(op : (0);bits : (9); val : 249),(op : (16);bits : (7); val : 3),(op : (0);bits : (8); val : 82),
      (op : (0);bits : (8); val : 18),(op : (21);bits : (8); val : 163),(op : (19);bits : (7); val : 35),(op : (0);bits : (8); val : 114),(op : (0);bits : (8); val : 50),(op : (0);bits : (9); val : 197),(op : (17);bits : (7); val : 11),
      (op : (0);bits : (8); val : 98),(op : (0);bits : (8); val : 34),(op : (0);bits : (9); val : 165),(op : (0);bits : (8); val : 2),(op : (0);bits : (8); val : 130),(op : (0);bits : (8); val : 66),(op : (0);bits : (9); val : 229),
      (op : (16);bits : (7); val : 7),(op : (0);bits : (8); val : 90),(op : (0);bits : (8); val : 26),(op : (0);bits : (9); val : 149),(op : (20);bits : (7); val : 67),(op : (0);bits : (8); val : 122),(op : (0);bits : (8); val : 58),
      (op : (0);bits : (9); val : 213),(op : (18);bits : (7); val : 19),(op : (0);bits : (8); val : 106),(op : (0);bits : (8); val : 42),(op : (0);bits : (9); val : 181),(op : (0);bits : (8); val : 10),(op : (0);bits : (8); val : 138),
      (op : (0);bits : (8); val : 74),(op : (0);bits : (9); val : 245),(op : (16);bits : (7); val : 5),(op : (0);bits : (8); val : 86),(op : (0);bits : (8); val : 22),(op : (64);bits : (8); val : 0),(op : (19);bits : (7); val : 51),
      (op : (0);bits : (8); val : 118),(op : (0);bits : (8); val : 54),(op : (0);bits : (9); val : 205),(op : (17);bits : (7); val : 15),(op : (0);bits : (8); val : 102),(op : (0);bits : (8); val : 38),(op : (0);bits : (9); val : 173),
      (op : (0);bits : (8); val : 6),(op : (0);bits : (8); val : 134),(op : (0);bits : (8); val : 70),(op : (0);bits : (9); val : 237),(op : (16);bits : (7); val : 9),(op : (0);bits : (8); val : 94),(op : (0);bits : (8); val : 30),
      (op : (0);bits : (9); val : 157),(op : (20);bits : (7); val : 99),(op : (0);bits : (8); val : 126),(op : (0);bits : (8); val : 62),(op : (0);bits : (9); val : 221),(op : (18);bits : (7); val : 27),(op : (0);bits : (8); val : 110),
      (op : (0);bits : (8); val : 46),(op : (0);bits : (9); val : 189),(op : (0);bits : (8); val : 14),(op : (0);bits : (8); val : 142),(op : (0);bits : (8); val : 78),(op : (0);bits : (9); val : 253),(op : (96);bits : (7); val : 0),
      (op : (0);bits : (8); val : 81),(op : (0);bits : (8); val : 17),(op : (21);bits : (8); val : 131),(op : (18);bits : (7); val : 31),(op : (0);bits : (8); val : 113),(op : (0);bits : (8); val : 49),(op : (0);bits : (9); val : 195),

      (op : (16); bits : (7); val : 10),(op : (0); bits : (8); val : 97),(op : (0); bits : (8); val : 33),(op : (0); bits : (9); val : 163),(op : (0); bits : (8); val : 1),(op : (0); bits : (8); val : 129),(op : (0); bits : (8); val : 65),
      (op : (0); bits : (9); val : 227),(op : (16); bits : (7); val : 6),(op : (0); bits : (8); val : 89),(op : (0); bits : (8); val : 25),(op : (0); bits : (9); val : 147),(op : (19); bits : (7); val : 59),(op : (0); bits : (8); val : 121),
      (op : (0); bits : (8); val : 57),(op : (0); bits : (9); val : 211),(op : (17); bits : (7); val : 17),(op : (0); bits : (8); val : 105),(op : (0); bits : (8); val : 41),(op : (0); bits : (9); val : 179),(op : (0); bits : (8); val : 9),
      (op : (0); bits : (8); val : 137),(op : (0); bits : (8); val : 73),(op : (0); bits : (9); val : 243),(op : (16); bits : (7); val : 4),(op : (0); bits : (8); val : 85),(op : (0); bits : (8); val : 21),(op : (31); bits : (8); val : 3),
      (op : (19); bits : (7); val : 43),(op : (0); bits : (8); val : 117),(op : (0); bits : (8); val : 53),(op : (0); bits : (9); val : 203),(op : (17); bits : (7); val : 13),(op : (0); bits : (8); val : 101),(op : (0); bits : (8); val : 37),
      (op : (0); bits : (9); val : 171),(op : (0); bits : (8); val : 5),(op : (0); bits : (8); val : 133),(op : (0); bits : (8); val : 69),(op : (0); bits : (9); val : 235),(op : (16); bits : (7); val : 8),(op : (0); bits : (8); val : 93),
      (op : (0); bits : (8); val : 29),(op : (0); bits : (9); val : 155),(op : (20); bits : (7); val : 83),(op : (0); bits : (8); val : 125),(op : (0); bits : (8); val : 61),(op : (0); bits : (9); val : 219),(op : (18); bits : (7); val : 23),
      (op : (0); bits : (8); val : 109),(op : (0); bits : (8); val : 45),(op : (0); bits : (9); val : 187),(op : (0); bits : (8); val : 13),(op : (0); bits : (8); val : 141),(op : (0); bits : (8); val : 77),(op : (0); bits : (9); val : 251),
      (op : (16); bits : (7); val : 3),(op : (0); bits : (8); val : 83),(op : (0); bits : (8); val : 19),(op : (21); bits : (8); val : 195),(op : (19); bits : (7); val : 35),(op : (0); bits : (8); val : 115),(op : (0); bits : (8); val : 51),
      (op : (0); bits : (9); val : 199),(op : (17); bits : (7); val : 11),(op : (0); bits : (8); val : 99),(op : (0); bits : (8); val : 35),(op : (0); bits : (9); val : 167),(op : (0); bits : (8); val : 3),(op : (0); bits : (8); val : 131),
      (op : (0); bits : (8); val : 67),(op : (0); bits : (9); val : 231),(op : (16); bits : (7); val : 7),(op : (0); bits : (8); val : 91),(op : (0); bits : (8); val : 27),(op : (0); bits : (9); val : 151),(op : (20); bits : (7); val : 67),
      (op : (0); bits : (8); val : 123),(op : (0); bits : (8); val : 59),(op : (0); bits : (9); val : 215),(op : (18); bits : (7); val : 19),(op : (0); bits : (8); val : 107),(op : (0); bits : (8); val : 43),(op : (0); bits : (9); val : 183),
      (op : (0); bits : (8); val : 11),(op : (0); bits : (8); val : 139),(op : (0); bits : (8); val : 75),(op : (0); bits : (9); val : 247),(op : (16); bits : (7); val : 5),(op : (0); bits : (8); val : 87),(op : (0); bits : (8); val : 23),

      (op : (64); bits : (8); val : 0),(op : (19); bits : (7); val : 51),(op : (0); bits : (8); val : 119),(op : (0); bits : (8); val : 55),(op : (0); bits : (9); val : 207),(op : (17); bits : (7); val : 15),(op : (0); bits : (8); val : 103),
      (op : (0); bits : (8); val : 39),(op : (0); bits : (9); val : 175),(op : (0); bits : (8); val : 7),(op : (0); bits : (8); val : 135),(op : (0); bits : (8); val : 71),(op : (0); bits : (9); val : 239),(op : (16); bits : (7); val : 9),
      (op : (0); bits : (8); val : 95),(op : (0); bits : (8); val : 31),(op : (0); bits : (9); val : 159),(op : (20); bits : (7); val : 99),(op : (0); bits : (8); val : 127),(op : (0); bits : (8); val : 63),(op : (0); bits : (9); val : 223),
      (op : (18); bits : (7); val : 27),(op : (0); bits : (8); val : 111),(op : (0); bits : (8); val : 47),(op : (0); bits : (9); val : 191),(op : (0); bits : (8); val : 15),(op : (0); bits : (8); val : 143),(op : (0); bits : (8); val : 79),
      (op : (0); bits : (9); val : 255)
    );
 {$endif}


{$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
procedure DumpDistcodes(codes: PArrCds31; Index, Count: integer);
var
  I : integer;
  S : string;
begin
  S := 'Distance table: ';
  for I := 0 to Count - 1 do
  begin
    S := S + '(' + IntToStr(codes[i + Index].op) + ',' + IntToStr(codes[i + Index].bits) + ',' +
      IntToStr(codes[i + Index].val) + ') ';
  end;
  Dumper.WriteString(S);
end;

procedure DumpLenCodes(codes: PArrCds511; Index: integer);
var
  I : integer;
  S : string;
begin
  S := 'Len table: ';
  for I := 0 to 511 do
  begin
    S := S + '(' + IntToStr(codes[i + Index].op) + ',' + IntToStr(codes[i + Index].bits) + ',' +
      IntToStr(codes[i + Index].val) + ') ';
  end;
  Dumper.WriteString(S);
end;
 {$endif}

function inflateEnd(var z :TZStreamRec):integer;
//z_streamp z;
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('inflateEnd');
   {$endif}
   if ((@z=nil) or (z.internal=nil) or (@z.zfree=nil)) then
   begin
    result:=Z_STREAM_ERROR;
    exit;
   end;
  if (inflate_state(z.internal).window <> nil) then
    zlibFreeMem(z.AppData,inflate_state(z.internal).window);
  zlibFreeMem(z.AppData, z.internal);//ZFREE(z, Bytef(z.state));
  z.internal:=nil;
//  Tracev((stderr, "inflate: end\n"));
  result:=Z_OK;
end;

function inflateReset(var z :TZStreamRec):integer;
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('inflateReset');
   {$endif}
  if ((@z=nil) or (z.internal=nil)) then
  begin
    result:=Z_STREAM_ERROR;
    exit;
  end;
  z.total_in:=0;
  z.total_out:=0;
  z.msg:= nil ;
  z.adler := 1;
  inflate_state(z.internal).mode := HEAD;
  inflate_state(z.internal).last := 0;
  inflate_state(z.internal).havedict := 0;
  {$ifdef SB_DEFLATE64}
  if (z.deflate64) then
    inflate_state(z.internal).dmax := 65536
  else
    inflate_state(z.internal).dmax := 32768;
   {$else}
  inflate_state(z.internal).dmax := 32768;
   {$endif}
  inflate_state(z.internal).wsize := 0;
  inflate_state(z.internal).whave := 0;
  inflate_state(z.internal).Write := 0;
  inflate_state(z.internal).hold := 0;
  inflate_state(z.internal).bits := 0;

  inflate_state(z.internal).lencode := @inflate_state(z.internal).codes;
  inflate_state(z.internal).distcode := @inflate_state(z.internal).codes;
  inflate_state(z.internal).next := @inflate_state(z.internal).codes;
  result:=Z_OK;
end;

function inflateInit2_(var z :TZStreamRec;w :integer;
  const version: ByteArray ; stream_size: integer ): integer;
var
  s         :inflate_state;
begin
  if (Length(Version) = 0) or
     (version[0] <> ZLIB_VERSION[0]) 
     or
     (stream_size<>sizeof(TZStreamRec)) 
       then
  begin
    result:=Z_VERSION_ERROR;
    exit;
  end;

  // initialize state
  if (@z=nil) then begin result:=Z_STREAM_ERROR; exit; end;
  z.msg :=   Z_NULL  ;
  if  (@z.zalloc=nil)  then
   begin
    z.zalloc:= zlibAllocMem ;
    z.AppData:=nil;
   end;
  if  (@z.zfree=nil)  then 
    z.zfree:= zlibFreeMem ;

  s:=zlibAllocMem(z.AppData, 1, sizeof(inflate_state_s));

  z.internal:=s;
  if z.internal=nil then
   begin
    result:=Z_MEM_ERROR;
    exit;
   end;

  // handle undocumented nowrap option (no zlib header or check)
//  internal_state(z.internal).nowrap:=0;
  if (w < 0) then
   begin
    w:=-w;
    inflate_state(z.internal).wrap := 0;
   end
  else
  begin
    inflate_state(z.internal).wrap := (w shr 4) + 1;
  end;
  // set window size
  if ((w < 8) or (w > MAX_WBITS)) then
  begin
     zlibFreeMem(z.AppData, z.internal);
     z.internal :=  Z_NULL ;
     result:=Z_STREAM_ERROR;
     exit;
   end;
  inflate_state(z.internal).wbits:=uInt(w);
  inflate_state(z.internal).window := nil;
//  Tracev((stderr, "inflate: allocated\n"));

  // reset state
  inflateReset(z);
  result:=Z_OK;
end;

function inflateInit_(var z :TZStreamRec;
  const version: ByteArray ; stream_size: integer ): integer;
begin
  Result := inflateInit2_(z, DEF_WBITS, version
     , stream_size );
end;

function inflateInit(var strm :TZStreamRec):integer;
begin
 result:=inflateInit_(strm, ZLibVersion
     , SizeOf(TZStreamRec) );
end;

{* ===========================================================================
     Decompresses the source buffer into the destination buffer.  sourceLen is
   the byte length of the source buffer. Upon entry, destLen is the total
   size of the destination buffer, which must be large enough to hold the
   entire uncompressed data. (The size of the uncompressed data must have
   been saved previously by the compressor and transmitted to the decompressor
   by some mechanism outside the scope of this compression library.)
   Upon exit, destLen is the actual size of the compressed buffer.
     This function can be used to decompress a whole file at once if the
   input file is mmap'ed.

     uncompress returns Z_OK if success, Z_MEM_ERROR if there was not
   enough memory, Z_BUF_ERROR if there was not enough room in the output
   buffer, or Z_DATA_ERROR if the input data was corrupted.}

function uncompress(var dest :ArrayPtr;var destLen :Cardinal; source :Bytef;sourceLen :uLong):integer;
var
 stream       :TZStreamRec;
 err          :integer;
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('uncompress');
   {$endif}
  
  
    stream.next_in:=Pointer(source);
    stream.avail_in:=uInt(sourceLen);
    // Check for source > 64K on 16-bit machine:
    if (uLong(stream.avail_in)<>sourceLen) then begin result:=Z_BUF_ERROR; exit; end;

    stream.next_out:=Pointer(dest);
    stream.avail_out:=uInt(destLen);
    if (uLong(stream.avail_out)<>destLen) then begin result:=Z_BUF_ERROR; exit; end;

    stream.zalloc:=TAlloc(0);
    stream.zfree:=TFree(0);

    err:=inflateInit(stream);
    if err<>Z_OK then begin result:=err; exit; end;

    err:=inflate(stream, Z_FINISH);
    if err<>Z_STREAM_END then
     begin
      inflateEnd(stream);
      if (err = Z_NEED_DICT) or ((err = Z_BUF_ERROR) and (stream.avail_in = 0)) then
        result:=Z_BUF_ERROR
      else result:=err;
      exit;
     end;
    destLen:=stream.total_out;

    err:=inflateEnd(stream);
    result:=err;
end;

{$ifdef CLX_USED}
type BOOL = WordBool;
 {$endif}



//* Return the low n bits of the bit accumulator (n < 16) */
function BITSS(n : uint; var hold : Cardinal): cardinal;
var i : Cardinal;
begin
//    ((unsigned)hold & ( (1U << n) - 1) )
  i:= (Longword(1) shl n);
  Dec(i);
  Result := (i and Longword(hold));
end;

procedure PULLBYTE( var bits: uint;var have : uInt;var res : Boolean;var Next: PAnsiChar; var hold : cardinal);
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  //Dumper.WriteString('PULLBYTE(' + IntToStr(bits) + ',' + IntToStr(have) + ',' + IntToStr(hold) + ')');
   {$endif}
   if (have = 0) then
   begin
     res := False;
     Exit;
   end;
   Dec(have);
//    hold += (unsigned long)( *next++) << bits; \
   hold := hold + (Cardinal(Next^) shl bits);
   Next := @Next[1];
   bits := bits + 8;
end;

procedure NEEDBITS(n : uInt; var bits: uint;var have : uInt;var res : Boolean;var Next: PAnsiChar; var hold : cardinal);
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  //Dumper.WriteString('NEEDBITS(' + IntToStr(n) + ',' + IntToStr(have) + ',' + IntToStr(hold) + ')');
   {$endif}
  while (bits < n) do
  begin
    PULLBYTE(bits, have, res, Next, hold);
    if not res then Exit;
  end;
end;

function updatewindow(const strm :TZStreamRec; out1 : cardinal) : Integer;
{/*
   Update the window with the last wsize (normally 32K) bytes written before
   returning.  If window does not exist yet, create it.  This is only called
   when a window is already in use, or when output has been written during this
   inflate call, but the end of the deflate stream has not been reached yet.
   It is also called to create a window for dictionary data when a dictionary
   is loaded.

   Providing output buffers larger than 32K to inflate() should provide a speed
   advantage, since only the last 32K of output is copied to the sliding window
   upon return from inflate(), and since all distances after the first 32K of
   output will fall in the output data, making match copies simpler and faster.
   The advantage may be dependent on the size of the processor's data caches.
 */}
var
  copy1, dist : uInt;
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('updateWindow(' + IntToStr(out1) + ')');
   {$endif}
//    /* if it hasn't been done already, allocate space for the window */
  if (inflate_state(strm.internal).window = Z_NULL) then
  begin
    inflate_state(strm.internal).window := zlibAllocMem(strm.AppData, uInt(1) shl inflate_state(strm.internal).wbits, sizeof(Byte));
    if (inflate_state(strm.internal).window = Z_NULL) then
    begin
      Result := 1;
      Exit;
    end;
  end;

//    /* if window not in use yet, initialize */
  if (inflate_state(strm.internal).wsize = 0) then
  begin
    inflate_state(strm.internal).wsize := uInt(1) shl inflate_state(strm.internal).wbits;
    inflate_state(strm.internal).write := 0;
    inflate_state(strm.internal).whave := 0;
  end;

//    / * copy inflate_state(strm.internal).wsize or less output bytes into the circular window */
  copy1 := Integer(out1) - strm.avail_out;
  if (copy1 >= inflate_state(strm.internal).wsize) then
  begin
    ZlibMemCpy(inflate_state(strm.internal).window, strm.next_out - inflate_state(strm.internal).wsize, inflate_state(strm.internal).wsize);
    inflate_state(strm.internal).write := 0;
    inflate_state(strm.internal).whave := inflate_state(strm.internal).wsize;
  end
  else
  begin
    dist := inflate_state(strm.internal).wsize - inflate_state(strm.internal).write;
    if (dist > copy1) then
      dist := copy1;
    ZlibMemCpy(inflate_state(strm.internal).window + inflate_state(strm.internal).write, strm.next_out - copy1, dist);
    copy1 := copy1 - dist;
    if (Copy1 <> 0) then
    begin
      ZlibMemCpy(inflate_state(strm.internal).window, strm.next_out - copy1, copy1);
      inflate_state(strm.internal).write := copy1;
      inflate_state(strm.internal).whave := inflate_state(strm.internal).wsize;
    end
    else
    begin
      inflate_state(strm.internal).write := inflate_state(strm.internal).write + dist;
      if (inflate_state(strm.internal).Write = inflate_state(strm.internal).wsize) then
        inflate_state(strm.internal).write := 0;
      if (inflate_state(strm.internal).whave < inflate_state(strm.internal).wsize) then
        inflate_state(strm.internal).whave := inflate_state(strm.internal).whave + dist;
    end;
  end;
  Result := 0;
end;


function Update(const z :TZStreamRec;var check : Cardinal; buf : PAnsiChar; var len : cardinal) : cardinal;
begin
//  (state->flags ? crc32(check, buf, len) : adler32(check, buf, len))
{  if inflate_state(z.internal).flags <> 0 then
    Result := crc32(check, buf, len)
  else}
  // o.e. yoi zlib oi flag=0 e i?iaa?eo ii?ii ia aaeaou
  Result := adler32(check, buf, len);
end;

function REVERSE(var q: cardinal) : cardinal;
begin
//    ((((q) >> 24) & 0xff) + (((q) >> 8) & 0xff00) + \
//     (((q) & 0xff00) << 8) + (((q) & 0xff) << 24))
  result := ((((q) shr 24) and $ff) + (((q) shr 8) and $ff00) + (((q) and $ff00) shl 8) + (((q) and $ff) shl 24));
end;

procedure INITBITS(var bits: uint; var hold: cardinal);
begin
  hold := 0;
  bits := 0;
end;

procedure DROPBITS(n : uint; var bits: uint; var hold: cardinal);
begin
  hold := hold shr n;
  bits := bits - n;
//  hold >>= (n); \
//  bits -= (unsigned)(n); \
end;

procedure RESTORE(var strm :TZStreamRec; var bits: uint; var Left : uint;var have : uInt;var Next: PAnsiChar;var put: PAnsiChar; var hold : cardinal );
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('RESTORE(' + IntToStr(bits) + ',' + IntToStr(Left) + ',' + IntToStr(have) + ',' + IntToStr(hold) + ')');
   {$endif}
  strm.next_out := put;
  strm.next_in := Next;
  strm.avail_out := left;
  strm.avail_in := have;
  inflate_state(strm.internal).hold := hold;
  inflate_state(strm.internal).bits := bits;
end;


procedure fixedtables(var state : inflate_state{$ifdef SB_DEFLATE64}; deflate64 : boolean {$endif});
//struct inflate_state FAR *state;
begin 
  {$ifdef SB_DEFLATE64}  
  if deflate64 then
  begin
    state.distcode := @distfix64;
    state.lencode := @lenfix64;    
  end
  else
   {$endif}
  begin
    state.distcode := @distfix;
    state.lencode := @lenfix;    
  end;
  
  state.distbits := 5;
  state.lenbits := 9;
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  //DumpDistcodes(state.distcode, {$ifdef SB_VCL}0{$else}state.distcodeoffset{$endif}, 1 shl state.distbits);
   {$endif}
end;

function inflate_table(types : codetype; llens : PArrShr ; c : uInt; var Next : PCode; var  bits : uInt;var work: TArrShr288{$ifdef SB_DEFLATE64}; deflate64: boolean {$endif}) : integer;
var
   used, root : uInt;
   len : uInt; //               /* a code's length in bits */
   sym : uInt; //              /* index of code symbols */
   min, max : uInt; //         /* minimum and maximum code lengths */
//   root : uInt; //             /* number of index bits for root table */
   curr : uInt; //             /* number of index bits for current table */
   drop : uInt; //             /* code bits to drop for sub-table */
   Left : Integer; //                  /* number of prefix codes available */
//   used : uInt; //             /* code entries in table used */
   huff : uInt; //             /* Huffman code */
   incr : uInt; //             /* for incrementing code, index */
   fill: uInt; //              /* index for replicating entries */
   low: uInt; //               /* low bits for current root entry */
   mask: uInt; //              /* mask for low root bits */
   thiss : code; //                  /* table entry for duplication */
   NNext : PArrCds  ; //            /* next available space in table */
//    const unsigned short FAR *base;     /* base value table to use */
//    const unsigned short FAR *extra;    /* extra bits table to use */
   base : PArrShr; //    /* base value table to use */
   extra: PArrShr;    //* extra bits table to use */
   endd : integer; //                   /* use base and extra for symbol > end */
   Count : array[0..MAX_BITS] of short; //   /* number of codes of each length */
   offs : array[0..MAX_BITS] of short;  //   /* offsets in table for each length */
   table : PArrCds;
   //ptr : Pointer;
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('inflate_table');
   {$endif}
{    /*
       Process a set of code lengths to create a canonical Huffman code.  The
       code lengths are lens[0..codes-1].  Each length corresponds to the
       symbols 0..codes-1.  The Huffman code is generated by first sorting the
       symbols by length from short to long, and retaining the symbol order
       for codes with equal lengths.  Then the code starts with all zero bits
       for the first code of the shortest length, and the codes are integer
       increments for the same length, and zeros are appended as the length
       increases.  For the deflate format, these bits are stored backwards
       from their more natural integer increment ordering, and so when the
       decoding tables are built in the large loop below, the integer codes
       are incremented backwards.

       This routine assumes, but does not check, that all of the entries in
       lens[] are in the range 0..MAXBITS.  The caller must assure this.
       1..MAXBITS is interpreted as that code length.  zero means that that
       symbol does not occur in this code.

       The codes are sorted by computing a count of codes for each length,
       creating from that a table of starting indices for each length in the
       sorted table, and then entering the symbols in order in the sorted
       table.  The sorted table is work[], with that space being provided by
       the caller.

       The length counts are used for other purposes as well, i.e. finding
       the minimum and maximum length codes, determining if there are any
       codes at all, checking for a valid set of lengths, and looking ahead
       at length counts to determine sub-table sizes when building the
       decoding tables.
     */
 }
    //* accumulate lengths for codes (assumes lens[] all in 0..MAXBITS) */
  table := PArrCds(Next);
  for len := 0 to MAX_BITS do
    count[len] := 0;
  for sym := 0 to c-1 do
    Count[llens[sym]] := Count[llens[sym]] + 1;

  //* bound code lengths, force root to be within code lengths */
  root := bits;
  for max := MAX_BITS downto 1 do
      if count[max] <> 0 then break;

  if (root > max) then root := max;
  if (max = 0) then
  begin
    thiss.op := uch(64);    { Invalid code marker }
    thiss.bits := uch(1);
    thiss.val := ush(0);
    table[0] := thiss;      { Make a table to force an error }
    table := @table[0];
    table[0] := thiss;
    table := @table[0];
    bits := 1;
    result := 0;            { No symbols, but wait for decoding to report error }
    Exit;
  end;
  for min := 1 to MAX_BITS do
      if (count[min] <> 0) then break;
  if (root < min) then root := min;

//  /* check for an over-subscribed or incomplete set of lengths */
  Left := 1;
  for len := 1 to MAX_BITS do
  begin
      Left := Left shl 1;
      left := Left - count[len];
      if (left < 0) then
      begin
       Result :=  -1; //        /* over-subscribed */
       Exit;
      end;
  end;
  if (left > 0 ) and ( (types = CODES) or 
     (max <> 1)) then //((Integer(c) - count[0]) <> 1)) then -- zlib 1.2.3 update
  begin
    Result := -1;   //                   /* incomplete set */
    Exit;
  end;

 // /* generate offsets into symbol table for each length for sorting */
  offs[1] := 0;

  for len := 1 to MAX_BITS-1 do
      offs[len + 1] := offs[len] + count[len];

  //* sort symbols by length, by symbol order within each length */
  for sym := 0 to c-1 do
    if (llens[sym] <> 0) then
    begin
//    if (lens[sym] != 0) work[ offs[lens[sym]]++ ] = (unsigned short)sym;
      work[offs[llens[sym]]] := sym;
      offs[llens[sym]] := offs[llens[sym]] + 1;
    end;

  {/*
     Create and fill in decoding tables.  In this loop, the table being
     filled is at next and has curr index bits.  The code being used is huff
     with length len.  That code is converted to an index by dropping drop
     bits off of the bottom.  For codes where len is less than drop + curr,
     those top drop + curr - len bits are incremented through all values to
     fill the table with replicated entries.

     root is the number of index bits for the root table.  When len exceeds
     root, sub-tables are created pointed to by the root entry with an index
     of the low root bits of huff.  This is saved in low to check for when a
     new sub-table should be started.  drop is zero when the root table is
     being filled, and drop is root when sub-tables are being filled.

     When a new sub-table is needed, it is necessary to look ahead in the
     code lengths to determine what size sub-table is needed.  The length
     counts are used for this, and so count[] is decremented as codes are
     entered in the tables.

     used keeps track of how many table entries have been allocated from the
     provided *table space.  It is checked when a LENS table is being made
     against the space in *table, ENOUGH, minus the maximum space needed by
     the worst case distance code, MAXD.  This should never happen, but the
     sufficiency of ENOUGH has not been proven exhaustively, hence the check.
     This assumes that when type == LENS, bits == 9.

     sym increments through all symbols, and the loop terminates when
     all codes of length max, i.e. all codes, have been processed.  This
     routine permits incomplete codes, so another loop after this one fills
     in the rest of the decoding tables with invalid code markers.
   */
  }
//  /* set up for code type */
  case types of
    CODES:
    begin
      base := @work;
      extra := @work;    //* dummy value--not used */
      endd := 19;
    end;
    LENS:
    begin
      {$ifdef SB_DEFLATE64}
      if deflate64 then
      begin
        base := @lbase64;
        extra := @lext64;
      end
      else
       {$endif}
      begin
        base := @lbase;
        extra := @lext;
      end;

      Dec(PCardinal(base), 257); // base := base - 257; (257*2)
      Dec(PCardinal(extra), 257) ; // extra := extra - 257;

      endd := 256;
    end;
    else    //         /* DISTS */
      begin
        {$ifdef SB_DEFLATE64}
        if deflate64 then
        begin
          base := @dbase64;
          extra := @dext64;
        end
        else
         {$endif}
        begin
          base := @dbase;
          extra := @dext;
        end;

        endd := -1;
    end;
  end;

  (* initialize state for loop *)
  huff := 0;                   (* starting code *)
  sym := 0;                    (* starting code symbol *)
  len := min;                  (* starting code length *)
//  nnext := @Table;              (* current table to fill in *)
  nnext := Table;              (* current table to fill in *)
  curr := root;                (* current table index bits *)
  drop := 0;                   (* current bits to drop from code for index *)
  low := $ffffffff;       (* trigger new sub-table when len > root *)
  used := 1 shl root;          (* use root table entries *)
  mask := used - 1;            (* mask for comparing low *)

  (* check available table space *)
  if (types = LENS) and 
     (used >= (ENOUGH - MAXD)) then
  begin
    Result := 1;
    Exit;
  end;
  (* process all codes and make table entries *)
  while true do
  begin
      (* create table entry *)
      thiss.bits := len - drop;
      if (Integer(work[sym]) < endd) then begin
        thiss.op := uInt(0);
        thiss.val := work[sym];
      end
      else if (Integer(work[sym]) > endd) then
      begin
        thiss.op := uInt(extra^[work[sym]]);
        thiss.val := base^[work[sym]];
      end
      else begin
          thiss.op := uInt(32 + 64);         (* end of block *)
          thiss.val := 0;
      end;

      (* replicate for those indices with low len bits equal to huff *)
      incr := 1 shl (len - drop);
      fill := 1 shl curr;
      min := fill;
      repeat
          fill := fill - incr;

//          nnext[(huff shr drop) + fill] := thiss;
          nnext[(huff shr drop) + fill] := thiss;
      until (fill = 0) ;

      (* backwards increment the len-bit code huff *)
      incr := 1 shl (len - 1);

      while ((huff and incr) <> 0) do
        incr := incr shr 1;

      if (incr <> 0) then
      begin
          huff  := huff and (incr - 1);
          huff  := huff + incr;
      end
      else
          huff := 0;

      (* go to next symbol, update count, len *)
      sym := sym + 1;
      Count[len] := Count[len] -1;
      if (Count[len] = 0) then
      begin
          if (len = max) then break;
          len := llens[work[sym]];
      end;

      (* create new sub-table if needed *)
      if ((len > root) and (uInt(huff and mask) <> Low)) then
      begin
          (* if first time, transition to sub-tables *)
          if (drop = 0) then
              drop := root;

          (* increment past last table *)
(*            {$ifndef SB_VCL}
            nnext := nnext + unsigned(1) shl curr;
            {$else}
            nnext := @nnext[unsigned(1) shl curr];
            {$endif}*)
          // zlib 1.2.3 update  
          nnext := @nnext[min];
          (* determine length of next table *)
          curr := len - drop;
          left := Integer(1 shl curr);
          while (curr + drop < max) do
          begin
              Left := Left - count[curr + drop];
              if (left <= 0) then break;
              curr := curr +1;
              Left := Left shl 1;
          end;

          (* check for enough space *)
          used := used + (unsigned(1) shl curr);
          if (types = LENS) and 
             (used >= ENOUGH - MAXD) then
          begin
            Result := 1;
            Exit;
          end;
          (* point entry in root table to sub-table *)
          low := huff and mask;
          code(Table[low]).op := uInt(curr);
          code(Table[low]).bits := root;
//        (*table)[low].val = (unsigned short)(next - *table);
          code(Table[low]).val :=  round((PtrUInt(nnext) - PtrUInt(Table)) / SizeOf(code)) ;

      end;
  end;

  (*
     Fill in rest of table for incomplete codes.  This loop is similar to the
     loop above in incrementing huff for table indices.  It is assumed that
     len is equal to curr + drop, so there is no loop needed to increment
     through high index bits.  When the current sub-table is filled, the loop
     drops back to the root table to fill in any remaining entries there.
   *)
  thiss.op := 64;                (* invalid code marker *)
  thiss.bits := (len - drop);
  thiss.val := 0;
  while (huff <> 0) do
  begin
    (* when done with sub-table, drop back to root table *)
    if (drop <> 0) and ((huff and mask) <> low) then
    begin
        drop := 0;
        len := root;
        nnext := @table;
        thiss.bits := len;
    end;

    (* put invalid code marker in table *)
    nnext[huff shr drop] := thiss;

    (* backwards increment the len-bit code huff *)
    incr := (uInt(1) shl (len - 1));
    while ((huff and incr) <> 0) do
        incr := incr shr 1;
    if (incr <> 0) then
    begin
        huff := huff and (incr - 1);
        huff := huff + incr;
    end
    else
        huff := 0;
  end;

  (* set return parameters *)
//  *table + := used;
  next := @Table[used];
  bits := root;

  Result := 0;
end;

procedure BYTEBITS( var bits: uint; var hold: cardinal);
begin
   hold := hold shr (bits and 7);
   bits := bits - (bits and 7);
//        hold >>= bits & 7; \
//        bits -= bits & 7; \
end;


{ (*
   Decode literal, length, and distance codes and write out the resulting
   literal and match bytes until either not enough input or output is
   available, an end-of-block is encountered, or a data error is encountered.
   When large enough input and output buffers are supplied to inflate(), for
   example, a 16K input buffer and a 64K output buffer, more than 95% of the
   inflate execution time is spent in this routine.

   Entry assumptions:

        state->mode == LEN
        strm->avail_in >= 6
        strm->avail_out >= 258
        start >= strm->avail_out
        state->bits < 8

   On return, state->mode is one of:

        LEN -- ran out of enough output space or enough available input
        TYPE -- reached end of block code, inflate() to interpret next block
        BAD -- error in block data

   Notes:

    - The maximum input bits used by a length/distance pair is 15 bits for the
      length code, 5 bits for the length extra, 15 bits for the distance code,
      and 13 bits for the distance extra.  This totals 48 bits, or six bytes.
      Therefore if strm->avail_in >= 6, then there is enough input to avoid
      checking for available input while decoding.

    - The maximum bytes that a single length/distance pair can output is 258
      bytes, which is the maximum length that can be coded.  inflate_fast()
      requires strm->avail_out >= 258 for each loop to avoid checking for
      output space.
 *) }


{.$warnings off}
procedure inflate_fast(var strm :TZStreamRec;start :Integer);
{  OFF = 1;
   PUP(a) = *++(a)}
  function PUP(var a:PAnsiChar) : PAnsiChar;
  begin
    a := @a[1];
    result := a;
  end;
  procedure Out2from(var out1,from : PAnsiChar);
  begin
    out1 := @out1[1];
    From := @From[1];
    out1[0] := From[0];
  end;
var
  OFF : Integer;
  in1 : PAnsiChar; //     (* local strm->next_in *)
  last : PAnsiChar; //   (* while in < last, enough input available *)
  out1 : PAnsiChar; //    (* local strm->next_out *)
  beg  : PAnsiChar; //    (* inflate()'s initial strm->next_out *)
  end1 : PAnsiChar; //    (* while out < end, enough space available *)
  wsize : uInt; //    (* window size or zero if not using window *)
  whave : uInt; //    (* valid bytes in the window *)
  Write : uInt; //    (* window write index *)
  window : PAnsiChar; //  (* allocated sliding window, if wsize != 0 *)
  hold : uLong;  //   (* local strm->hold *)
  bits : uInt; //     (* local strm->bits *)
  lcode : PArrCds511; // (* local strm->lencode *)
  dcode : PArrCds31; // (* local strm->distcode *)
  lmask : uInt;  //   (* mask for first level of length codes *)
  dmask : uInt; //    (* mask for first level of distance codes *)
  this : code; //     (* retrieved table entry *)
  op : uInt;  //      (* code bits, operation, extra bits, or *)
 //                  (*  window position, window bytes to copy *)
  len : uInt; //      (* match length, unused bytes *)
  dist : uInt; //     (* match distance *)
  pFrom : PAnsiChar; //   (* where to copy match from *)
  dodist, dolen, breakmode : Boolean;
begin
  (* copy state to local variables *)
  OFF := 1;
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('inflate_fast()');
   {$endif}

  in1 := strm.next_in - OFF;
  out1 := strm.next_out - OFF;
  {$ifdef SB_DEFLATE64}
  if strm.deflate64 then
  begin
    last := in1 + (strm.avail_in - 7); 
    end1 := out1 + (strm.avail_out - 65538);  
  end  
  else  
   {$endif}
  begin
    last := in1 + (strm.avail_in - 5); 
    end1 := out1 + (strm.avail_out - 257);  
  end;
  beg := out1 - (start - strm.avail_out);
  wsize := inflate_state(strm.internal).wsize;
  whave := inflate_state(strm.internal).whave;
  write := inflate_state(strm.internal).write;
  window := inflate_state(strm.internal).window;
  hold := inflate_state(strm.internal).hold;
  bits := inflate_state(strm.internal).bits;
  lcode := inflate_state(strm.internal).lencode;
  dcode := inflate_state(strm.internal).distcode;
  lmask := (uInt(1) shl inflate_state(strm.internal).lenbits) - 1;
  dmask := (uInt(1) shl inflate_state(strm.internal).distbits) - 1;
  //dodist := True;
  //dolen := True;
  breakmode := false;

    (* decode literals and length/distances until end-of-block or not enough
       input data or output space *)
  while (in1 < last) and (out1 < end1) do
  begin
    if (bits < 15) then
    begin
      hold := hold + (ord(PUP(in1)[0]) shl bits);
      bits := bits + 8;
      hold := hold + (ord(PUP(in1)[0]) shl bits);
      bits := bits + 8;
    end;
    this := lcode^[hold and lmask];

    {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
    Dumper.WriteString(Format('CODE: (%d, %d, %d), output left: %d', [cardinal(this.op), cardinal(this.bits), this.val, cardinal(end1-out1)]));
     {$endif}

//      dolen:
      repeat
        dolen := False;
        op := this.bits;
        hold := hold shr op;
        bits := bits - op;
        op := this.op;
        if (op = 0) then
        begin                   //       (* literal *)
//            Tracevv((stderr, this.val > := 0x20 and this.val < 0x7f ?
//                    'inflate:         literal ''%c'''#10'' :
//                    'inflate:         literal 0x%02x'#10'', this.val));
            out1 := @out1[1];
            out1[0] := AnsiChar(this.val);
        end
        else
          if ((op and 16) <> 0) then
          begin
            len := this.val; //  (* length base *)
            op := op and 15;  // (* number of extra bits *)
      {$ifdef SB_DEFLATE64}
            if op = 15 then
              op := 16; // extra 16 bits for deflate64
       {$endif}

            if (op <> 0) then
            begin
              {Deflate64: added while: 2 bytes could be needed }
              while (bits < op) do
              begin
                hold := hold + (ord(PUP(in1)[0]) shl bits);
                bits := bits + 8;
              end;
              len := len + uInt(hold and ((uInt(1) shl op) - 1));
              hold := hold shr op;
              bits := bits - op;
            end;

            {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
            Dumper.WriteString(Format('MATCH LEN: %d', [len]));
             {$endif}

            // Tracevv((stderr, 'inflate:         length %u'#10'', len));
            if (bits < 15) then
            begin
                hold := hold + (ord(PUP(in1)[0]) shl bits);
                bits := bits + 8;
                hold := hold + (ord(PUP(in1)[0]) shl bits);
                bits := bits + 8;
            end;
            this := dcode^[hold and dmask];
            {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
            Dumper.WriteString(Format('DISTCODE: (%d, %d, %d), output written: %d', [cardinal(this.op), cardinal(this.bits), this.val, cardinal(out1-beg)]));
             {$endif}

//          dodist:
            repeat
              dodist := False;
              op := this.bits;
              hold := hold shr op;
              bits := bits - op;
              op := this.op;
              if ((op and 16) <> 0) then
              begin
                  dist := this.val; // (* distance base *)
                  op := op and 15;   // (* number of extra bits *)
                  if (bits < op) then
                  begin
                      hold := hold + (ord(PUP(in1)[0]) shl bits);
                      bits := bits + 8;
                      if (bits < op) then
                      begin
                          hold := hold + (ord(PUP(in1)[0]) shl bits);
                          bits := bits + 8;
                      end;
                  end;
                  dist := dist + uInt(hold and ((uInt(1) shl op) - 1));

                  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
                  Dumper.WriteString(Format('DIST: %d', [dist]));
                   {$endif}

                  hold := hold shr op;
                  bits := bits - op;
  //                Tracevv((stderr, 'inflate:         distance %u'#10'', dist));
                  op := uInt(out1 - beg); //     (* max distance in output *)
                  if (dist > op) then
                  begin    //            (* see if copy from window *)
                      op := dist - op;           //  (* distance back in window *)
                      if (op > whave) then
                      begin
                          strm.msg := 'invalid distance too far back';
                          inflate_state(strm.internal).mode := BAD;
                          breakmode := True;
                          break;
                      end;
                      // DONE: Check this;
                      pFrom := window - OFF;
                      if (write = 0) then
                      begin           (* very common case *)
                          pFrom := pFrom + wsize - op;
                          if (op < len) then
                          begin         (* some from window *)
                              len := len - op;
                              repeat
//                                PUP(out1) := PUP(pFrom);
                                Out2from(out1, pFrom);
                                dec(op);
                              until (op = 0);
                              pFrom := out1 - dist;  (* rest from output *)
                          end;
                      end
                      else
                        if (write < op) then
                        begin      (* wrap around window *)
                          pFrom := pFrom + wsize + write - op;
                          op := op - write;
                          if (op < len) then
                          begin         (* some from end of window *)
                              len := len - op;
                              repeat
//                                PUP(out1) := PUP(pFrom);
                                Out2from(out1, pFrom);
                                dec(op);
                              until (op = 0);
                              pFrom := window - OFF;
                              if (write < len) then (* some from start of window *)
                              begin
                                  op := write;
                                  len := len - op;
                                  repeat
//                                    PUP(out1) := PUP(pFrom);
                                    Out2from(out1, pFrom);
                                    dec(op);
                                  until (op = 0);
                                  pFrom := out1 - dist;      (* rest from output *)
                              end;
                          end;
                      end
                      else begin                      (* contiguous in window *)
                          pFrom := pFrom + write - op;
                          if (op < len) then
                          begin         (* some from window *)
                              len := len - op;
                              repeat
//                                PUP(out1) := PUP(pFrom);
                                Out2from(out1, pFrom);
                                dec(op);
                              until (op = 0);
                              // DONE: Erorr
                              pFrom := out1 - dist;  (* rest from output *)
                          end;
                      end;
                      while (len > 2) do begin
//                          PUP(out1) := PUP(pFrom);
//                          PUP(out1) := PUP(pFrom);
//                          PUP(out1) := PUP(pFrom);
                          Out2from(out1, pFrom);
                          Out2from(out1, pFrom);
                          Out2from(out1, pFrom);
                          len := len - 3;
                      end;
                      if (len <> 0) then
                      begin
//                          PUP(out1) := PUP(pFrom);
                            Out2from(out1, pFrom);
                          if (len > 1) then
                          begin
//                              PUP(out1) := PUP(pFrom);
                            Out2from(out1, pFrom);
                          end;
                      end;
                  end
                  else begin
                      pFrom := out1 - dist;          (* copy direct from output *)
                      repeat                        (* minimum length is three *)
//                          PUP(out1) := PUP(pFrom);
//                          PUP(out1) := PUP(pFrom);
//                          PUP(out1) := PUP(pFrom);
                          Out2from(out1, pFrom);
                          Out2from(out1, pFrom);
                          Out2from(out1, pFrom);
                          len := len - 3;
                      until (len <= 2);
                      if (len <> 0) then
                      begin
//                          PUP(out1) := PUP(pFrom);
                          Out2from(out1, pFrom);
                          if (len > 1) then
                          begin
//                              PUP(out1) := PUP(pFrom);
                            Out2from(out1, pFrom);
                          end;
                      end;
                  end;
              end
              else
                if ((op and 64) = 0) then
                begin          (* 2nd level distance code *)
                    this := dcode^[this.val + (hold and ((uInt(1) shl op) - 1))];
                    dodist := True;
                end
                else begin
                    strm.msg := 'invalid distance code';
                    inflate_state(strm.internal).mode := BAD;
                    breakmode := True;
                    break;
                end;
            until (dodist <> True);
            if breakmode then break;
        end
        else
          if ((op and 64) = 0) then
          begin              (* 2nd level length code *)
              this := lcode^[this.val + (hold and ((uInt(1) shl op) - 1))];
              dolen := true;
          end
          else
            if ((op and 32) <> 0) then
            begin                     (* end-of-block *)
            //    Tracevv((stderr, 'inflate:         end of block'#10''));
                inflate_state(strm.internal).mode := TYPEB;
                breakmode := True;
                break;
            end
            else begin
                strm.msg := 'invalid literal/length code';
                inflate_state(strm.internal).mode := BAD;
                breakmode := True;
                break;
            end;
      until (dolen <> True);
      if breakmode then break;
  end;

    (* return unused bytes (on entry, bits < 8, so in won't go too far back) *)
    len := bits shr 3;
    in1 := in1 - len;
    bits := bits - (len shl 3);
    hold := hold and ((uInt(1) shl bits) - 1);

    (* update state and return *)
    strm.next_in := in1 + OFF;
    strm.next_out := out1 + OFF;
  
  {$ifdef SB_DEFLATE64}
  if strm.deflate64 then
  begin
      if (in1 < last) then
        strm.avail_in := 7 + Integer(last - in1)
      else
        strm.avail_in := 7 - Integer(in1 - last);
      if (out1 < end1) then
        strm.avail_out := 65538 + Integer(end1 - out1)
      else
        strm.avail_out := 65538 - Integer(out1 - end1);  
  end
  else
   {$endif}
  begin
      if (in1 < last) then
        strm.avail_in := 5 + Integer(last - in1)
      else
        strm.avail_in := 5 - Integer(in1 - last);
      if (out1 < end1) then
        strm.avail_out := 257 + Integer(end1 - out1)
      else
        strm.avail_out := 257 - Integer(out1 - end1);
  end;  
    inflate_state(strm.internal).hold := hold;
    inflate_state(strm.internal).bits := bits;
 {(*
   inflate_fast() speedups that turned out slower (on a PowerPC G3 750CXe):
   - Using bit fields for code structure
   - Different op definition to avoid & for extra bits (do & for table bits)
   - Three separate decoding do-loops for direct, window, and write == 0
   - Special case for distance > 1 copies to do overlapped load and store copy
   - Explicit branch predictions (based on measured branch probabilities)
   - Deferring match copy and interspersed it with decoding subsequent codes
   - Swapping literal/length else
   - Swapping window/direct else
   - Larger unrolled copy loops (three is about right)
   - Moving len -= 3 statement into middle of loop
 *)}

end;

function inflate(var z :TZStreamRec;f :integer):integer;
var
 Next, put, pFrom : PAnsiChar;
 ret      :integer;
 bits,have, Left,in1,out1,copy1,lenn :uInt;
 hold : Cardinal;
 this, last : code;
 res : TSBBoolean;

{
    unsigned char FAR *next;    /* next input */
    unsigned char FAR *put;     /* next output */
    unsigned have, left;        /* available input and output */
    unsigned long hold;         /* bit buffer */
    unsigned bits;              /* bits in bit buffer */
    unsigned in, out;           /* save starting available input and output */
    unsigned copy;              /* number of stored or match bytes to copy */
    unsigned char FAR *from;    /* where to copy match bytes from */
    code this;                  /* current decoding table entry */
    code last;                  /* parent table entry */
    unsigned len;               /* length to copy for repeats, bits to drop */
    int ret;                    /* return code */
}
const
 order : array[0..18] of Integer = 
    ( 
    16 , 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
    ) ;
begin
  {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
  Dumper.WriteString('inflate');
   {$endif}
  if ((@z=nil) or (z.internal=nil) or (z.next_out=nil) or ((z.next_in=nil) and (z.avail_in <>0))) then
   begin
    result:=Z_STREAM_ERROR;
    exit;
   end;

  if inflate_state(z.internal).mode = TYPEB then
    inflate_state(z.internal).mode := TYPEDO; //skip check

  res := True;
  put := z.next_out;
  next := z.next_in;
  left := z.avail_out;
  have := z.avail_in;
  hold := inflate_state(z.internal).hold;
  bits := inflate_state(z.internal).bits;
  in1 := have;
  out1 := Left;
  ret := Z_OK;

  while res do
  begin
//   HEAD:
   if (inflate_state(z.internal).mode = HEAD) then
   begin
     if (inflate_state(z.internal).wrap = 0) then
     begin
       inflate_state(z.internal).mode := TYPEDO;
       continue;
     end;
     NEEDBITS(16, bits, have, res, Next, hold);
     if not res then break;
//       if (((BITSS(8,hold) shl 8) + (hold shr 8)) % 31) then
     if ((((BITSS(8,hold) shl 8) + (hold shr 8)) mod 31) <> 0) then
     begin
       z.Msg := 'incorrect header check';
       inflate_state(z.internal).mode := BAD;
       continue;
     end;
     if (BITSS(4,hold) <> Z_DEFLATED) then
     begin
       z.msg := 'unknown compression method';
       inflate_state(z.internal).mode := BAD;
       continue;
     end;
     DROPBITS(4,bits,hold);
     lenn := BITSS(4, hold) + 8; // zlib 1.2.3 update
     if (lenn > inflate_state(z.internal).wbits) then
     begin
       z.msg := 'invalid window size';
       inflate_state(z.internal).mode := BAD;
       continue;
     end;
     inflate_state(z.internal).dmax := 1 shl lenn;
//            Tracev((stderr, "inflate:   zlib header ok\n"));
     z.adler := adler32(0, Z_NULL, 0);
     inflate_state(z.internal).check := adler32(0, Z_NULL, 0);
//     if (inflate_state(z.internal).mode = inflate_mode(hold and $200)) then
     if ((hold and $200) <> 0) then
       inflate_state(z.internal).mode := DICTID
     else
       inflate_state(z.internal).mode := TYPEB;
//       state.mode = hold & 0x200 ? DICTID : TYPE1;
     INITBITS(bits,hold);
     continue;
   end;
//   DICTID:
   if (inflate_state(z.internal).mode = DICTID) then
   begin
     NEEDBITS(32,bits,have,res,Next,hold);
     if not res then break;
     z.adler := REVERSE(hold);
     inflate_state(z.internal).check := REVERSE(hold);
     INITBITS(bits,hold);
     inflate_state(z.internal).mode := DICT;
   end;
//   DICT:
   if (inflate_state(z.internal).mode = DICT) then
   begin
     if (inflate_state(z.internal).havedict = 0) then
     begin
       z.next_out := put;
       z.next_in := next;
       z.avail_out := left;
       z.avail_in := have;
       inflate_state(z.internal).hold := hold;
       inflate_state(z.internal).bits := bits;
       result := Z_NEED_DICT;
       Exit;
     end;
     z.adler := adler32(0, Z_NULL, 0);
     inflate_state(z.internal).check := adler32(0, Z_NULL, 0);
     inflate_state(z.internal).mode := TYPEB;
    end;
//    TYPEB:
    if (inflate_state(z.internal).mode = TYPEB) then
    begin
      if (f = Z_BLOCK) then
      begin
       res := false;
       break;
      end;
      inflate_state(z.internal).mode := TYPEDO;
    end;
//    TYPEDO:
    if (inflate_state(z.internal).mode = TYPEDO) then
    begin
      if (inflate_state(z.internal).last <> 0) then
      begin
        BYTEBITS(bits,hold);
        inflate_state(z.internal).mode := CHECK;
        continue;
      end;
      NEEDBITS(3,bits,have,res,Next,hold);
     if not res then break;
     inflate_state(z.internal).last := BITSS(1,hold);
     DROPBITS(1,bits,hold);
     case BITSS(2,hold) of
       0: //                             /* stored block */
         begin
           {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
           Dumper.WriteString('***** BEGIN STORED BLOCK *****');
            {$endif}         
//             Tracev((stderr, "inflate:     stored block%s\n",state->last ? " (last)" : ""));
           inflate_state(z.internal).mode := STORED;
         end;
       1: //                            /* fixed block */
         begin
           {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
           Dumper.WriteString('***** BEGIN FIXED TABLES BLOCK *****');
            {$endif}
           fixedtables(inflate_state(z.internal){$ifdef SB_DEFLATE64}, z.deflate64 {$endif});
//            Tracev((stderr, "inflate:     fixed codes block%s\n",state->last ? " (last)" : ""));
           inflate_state(z.internal).mode := LEN;  //              /* decode codes */
           {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
           DumpLenCodes(inflate_state(z.internal).lencode, 0);
           DumpDistCodes(inflate_state(z.internal).distcode, 0, 1 shl inflate_state(z.internal).distbits);
            {$endif}
         end;
       2: //                            /* dynamic block */
         begin
           {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
           Dumper.WriteString('***** BEGIN DYNAMIC BLOCK *****');
            {$endif}
//            Tracev((stderr, "inflate:     dynamic codes block%s\n", state->last ? " (last)" : ""));
           inflate_state(z.internal).mode := TABLE;
         end;
       3:
         begin;
           z.msg := 'invalid block type';
           inflate_state(z.internal).mode := BAD;
         end;
     end;
     DROPBITS(2,bits,hold);
     continue;
    end;
//    STORED:
    if (inflate_state(z.internal).mode = STORED) then
    begin
      BYTEBITS(bits, hold);   //                      /* go to byte boundary */
      NEEDBITS(32,bits,have,res,Next,hold);
      if not res then break;
//            if ((hold & 0xffff) != ((hold >> 16) ^ 0xffff)) {
      if ((hold and $ffff) <> ((hold shr 16) xor $ffff)) then
      begin
          z.msg := 'invalid stored block lengths';
          inflate_state(z.internal).mode := BAD;
          continue;
      end;
      inflate_state(z.internal).Length := (Longword(hold) and $ffff);
//            Tracev((stderr, "inflate:       stored length %u\n",state->length));
      INITBITS(bits,hold);
      inflate_state(z.internal).mode := COPY;
    end;
//    COPY:
    if (inflate_state(z.internal).mode = COPY) then
    begin
      copy1 := inflate_state(z.internal).Length;
      if (copy1 <> 0) then
      begin
          if (copy1 > have) then copy1 := have;
          if (copy1 > left) then copy1 := left;
          if (copy1 = 0) then break;
          ZlibMemCpy(put, next, copy1);
          have := have - copy1;
          next := Next + copy1;
          left := Left - copy1;
          put := put + copy1;
          inflate_state(z.internal).length := inflate_state(z.internal).Length - copy1;
          continue;
      end;
//        Tracev((stderr, "inflate:       stored end\n"));
      inflate_state(z.internal).mode := TYPEB;
      continue;
    end;
//    TABLE:
    if (inflate_state(z.internal).mode = TABLE) then
    begin
      NEEDBITS(14,bits,have,res,Next,hold);
      if not res then break;
      inflate_state(z.internal).nlen := BITSS(5,hold) + 257;
      DROPBITS(5,bits,hold);
      inflate_state(z.internal).ndist := BITSS(5,hold) + 1;
      DROPBITS(5,bits,hold);
      inflate_state(z.internal).ncode := BITSS(4,hold) + 4;
      DROPBITS(4,bits,hold);
//        Tracev((stderr, "inflate:       table sizes ok\n"));
      {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
      Dumper.WriteString(Format('New Trees : %d lencodes, %d dist codes, %d code len codes', [inflate_state(z.internal).nlen, inflate_state(z.internal).ndist, inflate_state(z.internal).ncode]));
       {$endif}

      inflate_state(z.internal).have := 0;
      inflate_state(z.internal).mode := LENLENS;
    end;
//    LENLENS:
    if (inflate_state(z.internal).mode = LENLENS) then
    begin
      while (inflate_state(z.internal).have < inflate_state(z.internal).ncode) do
      begin
        NEEDBITS(3,bits,have,res,Next,hold);
        if not res then break;
        inflate_state(z.internal).lens[order[inflate_state(z.internal).have]] := Byte(BITSS(3,hold));
        inflate_state(z.internal).have := inflate_state(z.internal).have +1 ;
        DROPBITS(3,bits,hold);
      end;
      // added by II Aug 21 2004
      if not res then
        break;
      while (inflate_state(z.internal).have < 19) do
      begin
        inflate_state(z.internal).lens[order[inflate_state(z.internal).have]] := 0;
        inflate_state(z.internal).have := inflate_state(z.internal).have + 1;
      end;
      inflate_state(z.internal).next := @inflate_state(z.internal).codes;
      inflate_state(z.internal).lencode := @inflate_state(z.internal).codes;
      inflate_state(z.internal).lenbits := 7;
      ret := inflate_table(CODES, @inflate_state(z.internal).lens, 19, inflate_state(z.internal).Next, inflate_state(z.internal).lenbits, inflate_state(z.internal).work{$ifdef SB_DEFLATE64},z.deflate64 {$endif});

      if (ret <> 0) then
      begin
        z.msg := 'invalid code lengths set';
        inflate_state(z.internal).mode := BAD;
        continue;
      end;
//        Tracev((stderr, "inflate:       code lengths ok\n"));
      inflate_state(z.internal).have := 0;
      inflate_state(z.internal).mode := CODELENS;
    end;
//    CODELENS:
    if (inflate_state(z.internal).mode = CODELENS) then
    begin
      while (inflate_state(z.internal).have < inflate_state(z.internal).nlen + inflate_state(z.internal).ndist) do
      begin
        while True do
        begin
            this := inflate_state(z.internal).lencode^[BITSS(inflate_state(z.internal).lenbits, hold)];
            if (this.bits <= bits) then break;
            PULLBYTE(bits,have,res,Next,hold);
            if not res then break;
        end;
        if not res then break;
        if (this.val < 16) then
        begin
          NEEDBITS(this.bits,bits,have,res,Next,hold);
          if not res then break;
          DROPBITS(this.bits,bits,hold);
          inflate_state(z.internal).lens[inflate_state(z.internal).have] := this.val;
          inc(inflate_state(z.internal).have);
        end
        else
        begin
          if (this.val = 16) then
          begin
            NEEDBITS(this.bits + 2,bits,have,res,Next,hold);
            if not res then break;
            DROPBITS(this.bits,bits,hold);
            if (inflate_state(z.internal).have = 0) then
            begin
              z.msg := 'invalid bit length repeat';
              inflate_state(z.internal).mode := BAD;
              continue;
            end;
            lenn := inflate_state(z.internal).lens[inflate_state(z.internal).have - 1];
            copy1 := 3 + BITSS(2,hold);
            DROPBITS(2,bits,hold);
          end
          else
            if (this.val = 17) then
            begin
              NEEDBITS(this.bits + 3,bits,have,res,Next,hold);
              if not res then break;
              DROPBITS(this.bits,bits,hold);
              lenn := 0;
              copy1 := 3 + BITSS(3, hold);
              DROPBITS(3,bits,hold);
            end
            else
            begin
              NEEDBITS(this.bits + 7,bits,have,res,Next,hold);
              if not res then break;
              DROPBITS(this.bits,bits,hold);
              lenn := 0;
              copy1 := 11 + BITSS(7,hold);
              DROPBITS(7,bits,hold);
            end;
          if (inflate_state(z.internal).have + copy1 > inflate_state(z.internal).nlen + inflate_state(z.internal).ndist) then
          begin
              z.msg := 'invalid bit length repeat';
              inflate_state(z.internal).mode := BAD;
              continue;
          end;
          while (copy1 > 0) do
          begin
            inflate_state(z.internal).lens[inflate_state(z.internal).have] := lenn;
            inflate_state(z.internal).have := inflate_state(z.internal).have +1;
            copy1 := copy1 - 1;
          end;
        end;
      end; //endwhile
      // added by II Jul 19 2004
      if not res then
        break;

      //   * handle error breaks in while */
      if inflate_state(z.internal).mode = BAD then
        Break;

      //   * build code tables */
      inflate_state(z.internal).Next := @inflate_state(z.internal).codes;
      inflate_state(z.internal).lencode := PArrCds511(inflate_state(z.internal).Next);
      inflate_state(z.internal).lenbits := 9;
      ret := inflate_table(LENS, @inflate_state(z.internal).lens, inflate_state(z.internal).nlen, inflate_state(z.internal).Next,inflate_state(z.internal).lenbits, inflate_state(z.internal).work{$ifdef SB_DEFLATE64},z.deflate64 {$endif});

      {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
      DumpLenCodes(inflate_state(z.internal).lencode, 0);
       {$endif}
      
      if (ret<>0) then
      begin
          z.msg := 'invalid literal/lengths set';
          inflate_state(z.internal).mode := BAD;
          continue;
      end;
      inflate_state(z.internal).distcode := PArrCds31(inflate_state(z.internal).Next);
      inflate_state(z.internal).distbits := 6;
      ret := inflate_table(DISTS, @inflate_state(z.internal).lens[inflate_state(z.internal).nlen],inflate_state(z.internal).ndist, inflate_state(z.internal).next, inflate_state(z.internal).distbits, inflate_state(z.internal).work{$ifdef SB_DEFLATE64},z.deflate64 {$endif});
      {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
      DumpDistcodes( inflate_state(z.internal).distcode, 0 , 1 shl inflate_state(z.internal).distbits);
       {$endif}

      if (ret<>0) then
      begin
          z.msg := 'invalid distances set';
          inflate_state(z.internal).mode := BAD;
          continue;
      end;
//            Tracev((stderr, "inflate: codes ok\n"));
      inflate_state(z.internal).mode := LEN;
    end;
//    LEN:
    if (inflate_state(z.internal).mode = LEN) then
    begin
    {$ifdef SB_DEFLATE64}
    if ((z.deflate64) and (have >= 8) and (left >= 65539)) or
      ((not z.deflate64) and (have >= 6) and (left >= 258)) then
       {$else}    
      if (have >= 6) AND (left >= 258) then    
     {$endif}
      begin
          RESTORE(z,bits,Left,have,Next,put,hold);
          inflate_fast(z, out1);
          put := z.next_out;
          next := z.next_in;
          left := z.avail_out;
          have := z.avail_in;
          hold := inflate_state(z.internal).hold;
          bits := inflate_state(z.internal).bits;
          continue;
      end;

      {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
      Dumper.WriteString('Inflate: LEN');
       {$endif}

      while true do
      begin
        this := inflate_state(z.internal).lencode^[BITSS(inflate_state(z.internal).lenbits,hold)];
        if ((this.bits) <= bits) then break;
        PULLBYTE(bits,have,res,Next,hold);
        if not res then break;
      end;
      
      if not res then break;
      
      if (this.op <> 0) and ((this.op and $f0) = 0) then
      begin
        last := this;

        while true do
        begin
          this := inflate_state(z.internal).lencode^[last.val + (BITSS(last.bits + last.op,hold) shr last.bits)];
          if ((last.bits + this.bits) <= bits) then break;
          PULLBYTE(bits,have,res,Next,hold);
          if not res then break;
        end;
        if not res then break;
        DROPBITS(last.bits,bits,hold);
      end;
      DROPBITS(this.bits,bits,hold);
      inflate_state(z.internal).length := this.val;

      if (integer(this.op) = 0) then
      begin
//          Tracevv((stderr, this.val >= 0x20 && this.val < 0x7f ?
//                  "inflate:         literal '%c'\n" :
//                  "inflate:         literal 0x%02x\n", this.val));
        inflate_state(z.internal).mode := LIT;
        continue;
      end;
      if ((this.op and 32) <> 0) then
      begin
//          Tracevv((stderr, "inflate:         end of block\n"));
        inflate_state(z.internal).mode := TYPEB;
        continue;
      end;
      if ((this.op and 64) <> 0) then
      begin
        z.msg := 'invalid literal/length code';
        inflate_state(z.internal).mode := BAD;
        continue;
      end;
      inflate_state(z.internal).extra := Cardinal((this.op) and 15);
    {$ifdef SB_DEFLATE64}
      if (inflate_state(z.internal).extra = 15) then { for Deflate64 support}
        inflate_state(z.internal).extra := 16;
     {$endif}
      {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
      Dumper.WriteString(Format('extra: %d', [inflate_state(z.internal).extra]));
       {$endif}

      inflate_state(z.internal).mode := LENEXT;
    end;
//    LENEXT:
    if (inflate_state(z.internal).mode = LENEXT) then
    begin
      if (inflate_state(z.internal).extra > 0) then
      begin
        NEEDBITS(inflate_state(z.internal).extra,bits,have,res,Next,hold);
        if not res then break;
        inflate_state(z.internal).Length := inflate_state(z.internal).Length + BITSS(inflate_state(z.internal).extra, hold);
        {$ifdef SECURE_BLACKBOX_DEBUG_ZLIB}
        Dumper.WriteString(Format('length extended: %d', [inflate_state(z.internal).length]));
         {$endif}

        DROPBITS(inflate_state(z.internal).extra,bits,hold);
      end;
//          Tracevv((stderr, "inflate:         length %u\n", state->length));
      inflate_state(z.internal).mode := DIST;
    end;
//    DIST:
    if (inflate_state(z.internal).mode = DIST) then
    begin
      while True do
      begin
        this := inflate_state(z.internal).distcode^[BITSS(inflate_state(z.internal).distbits,hold)];
        if ((this.bits) <= bits) then break;
        PULLBYTE(bits,have,res,Next,hold);
        if not res then break;
      end;
      if not res then break;
      if ((this.op and $f0) = 0) then
      begin
        last := this;
        while True do
        begin
          this := inflate_state(z.internal).distcode^[last.val + (BITSS(last.bits + last.op,hold) shr last.bits)];
          if (cardinal(last.bits + this.bits) <= bits) then break;
          PULLBYTE(bits,have,res,Next,hold);
          if not res then break;
        end;
        if not res then break;
        DROPBITS(last.bits,bits,hold);
      end;
      DROPBITS(this.bits,bits,hold);
      if (this.op and 64) > 0 then
      begin
        z.msg := 'invalid distance code';
        inflate_state(z.internal).mode := BAD;
        continue;
      end;
      inflate_state(z.internal).offset := this.val;
      inflate_state(z.internal).extra := cardinal(this.op and 15);
      inflate_state(z.internal).mode := DISTEXT;
    end;
//    DISTEXT:
    if (inflate_state(z.internal).mode = DISTEXT) then
    begin
      if (inflate_state(z.internal).extra > 0) then
      begin
        NEEDBITS(inflate_state(z.internal).extra,bits,have,res,Next,hold);
        if not res then break;
        inflate_state(z.internal).offset := inflate_state(z.internal).offset + BITSS(inflate_state(z.internal).extra, hold);
        DROPBITS(inflate_state(z.internal).extra,bits, hold);
      end;
      if (inflate_state(z.internal).offset > inflate_state(z.internal).whave + out1 - left) then
      begin
          z.msg := 'invalid distance too far back';
          inflate_state(z.internal).mode := BAD;
          continue;
      end;
//          Tracevv((stderr, "inflate:         distance %u\n", state->offset));
      inflate_state(z.internal).mode := MATCH;
    end;
//    MATCH:
    if (inflate_state(z.internal).mode = MATCH) then
    begin
      if (left = 0) then break;
      copy1 := out1 - left;
      if (inflate_state(z.internal).offset > copy1) then
      begin         // *  copy from window */
          copy1 := inflate_state(z.internal).offset - copy1;
          if (copy1 > inflate_state(z.internal).write) then
          begin
            copy1 := copy1 - inflate_state(z.internal).write;
            pFrom := inflate_state(z.internal).window + (inflate_state(z.internal).wsize - copy1);
          end
          else
            pFrom := inflate_state(z.internal).window + (inflate_state(z.internal).write - copy1);
          if (copy1 > inflate_state(z.internal).length) then
            copy1 := inflate_state(z.internal).length;
      end
      else
      begin         //                     /* copy from output */
        pFrom := put - inflate_state(z.internal).offset;
        copy1 := inflate_state(z.internal).length;
      end;
      if (copy1 > left) then
        copy1 := left;
      left := Left - copy1;
      inflate_state(z.internal).length := inflate_state(z.internal).Length - copy1;
//      do begin
//          *put++ = *from++;
//      end; while (--copy1);
      repeat
        put[0] := pFrom[0];
        put := @put[1];
        pFrom := @pFrom[1];
        dec(copy1);
      until (copy1 <= 0);
      if (inflate_state(z.internal).Length = 0) then inflate_state(z.internal).mode := LEN;
      continue;
    end;
//        case LIT:
    if (inflate_state(z.internal).mode = LIT) then
    begin
      if (left = 0) then break;
//      *put++ = (unsigned char)(state->length);
      put[0] := AnsiChar(inflate_state(z.internal).Length);
      put := @put[1];
      Dec(Left);
      inflate_state(z.internal).mode := LEN;
      continue;
    end;
//        case CHECK:
    if (inflate_state(z.internal).mode = CHECK) then
    begin
      if (inflate_state(z.internal).wrap > 0) then
      begin
        NEEDBITS(32,bits,have,res,Next,hold);
        if not res then break;
        out1 := out1 - left;
        z.total_out := z.total_out + integer(out1);
        inflate_state(z.internal).total := inflate_state(z.internal).total + out1;
        if (out1 > 0) then
        begin
          z.adler := UPDATE(z, inflate_state(z.internal).check, put - out1, out1);
          inflate_state(z.internal).check := UPDATE(z,inflate_state(z.internal).check, put - out1, out1);
        end;
        out1 := left;
        if ((REVERSE(hold)) <> inflate_state(z.internal).check) then
        begin
          z.msg := 'incorrect data check';
          inflate_state(z.internal).mode := BAD;
          continue;
        end;
        INITBITS(bits,hold);
//        Tracev((stderr, "inflate:   check matches trailer\n"));
      end;
      inflate_state(z.internal).mode := DONE;
    end;
//        case DONE:
    if (inflate_state(z.internal).mode = DONE) then
    begin
      ret := Z_STREAM_END;
      break;
    end;
//        case BAD:
    if (inflate_state(z.internal).mode = BAD) then
    begin
      ret := Z_DATA_ERROR;
      break;
    end;
//        case MEM:
    if (inflate_state(z.internal).mode = MEM) then
    begin
      Result := Z_MEM_ERROR;
      Exit;
    end;
//        case SYNC:
//        default:
    Result := Z_STREAM_ERROR;
    Exit;
  end; // whilend

   { /*
       Return from inflate(), updating the total counts and the check value.
       If there was no progress during the inflate() call, return a buffer
       error.  Call updatewindow() to create and/or update the window state.
       Note: a memory error from inflate() is non-recoverable.
     */}
//  inf_leave:
    RESTORE(z,bits,Left,have,Next,put,hold);
//    if (state->wsize || (state->mode < CHECK && out != strm->avail_out))
    if ((inflate_state(z.internal).wsize > 0) or 
        ((inflate_state(z.internal).mode < CHECK) And 
         (integer(out1) <> z.avail_out))) then
      if (updatewindow(z, out1) <> 0) then
      begin
        inflate_state(z.internal).mode := MEM;
        Result := Z_MEM_ERROR;
        Exit;
      end;
    in1 := integer(in1) - z.avail_in;
    out1 := integer(out1) - z.avail_out;
    z.total_in := z.total_in + integer(in1);
    z.total_out := z.total_out + integer(out1);
    inflate_state(z.internal).total := inflate_state(z.internal).total + out1;
    if (inflate_state(z.internal).wrap >0) and (out1 > 0) then
    begin
      z.adler := Update(z,inflate_state(z.internal).check, z.next_out - out1, out1);
      inflate_state(z.internal).check := Update(z,inflate_state(z.internal).check, z.next_out - out1, out1);
    end;
//    strm->data_type = state->bits + (state->last ? 64 : 0) +
//                      (state->mode == TYPEB ? 128 : 0);
    z.data_type := inflate_state(z.internal).bits;
    if (inflate_state(z.internal).last <> 0) then
      z.data_type := z.data_type + 64;
    if (inflate_state(z.internal).mode = TYPEB) then
      z.data_type := z.data_type + 128;

//    if (((in1 == 0 && out1 == 0) || flush == Z_FINISH) && ret == Z_OK)
//        ret = Z_BUF_ERROR;
    if ((((in1 = 0) and (out1 = 0)) or (f = Z_FINISH)) and (ret = Z_OK)) then
      ret := Z_BUF_ERROR;
    Result := ret;
end;
{.$warnings on}

{ DecompressBuf decompresses data, buffer to buffer, in one call.
   In: InBuf = ptr to compressed data
       InBytes = number of bytes in InBuf
       OutEstimate = zero, or est. size of the decompressed data
  Out: OutBuf = ptr to newly allocated buffer containing decompressed data
       OutBytes = number of bytes in OutBuf   }
{procedure DecompressBuf(const InBuf: Pointer; InBytes: Integer;
  OutEstimate: Integer; out OutBuf: Pointer; out OutBytes: Integer);
var
  strm: TZStreamRec;
  P: Pointer;
  BufInc: Integer;
begin
  FillChar(strm, sizeof(strm), 0);
  strm.zalloc := zlibAllocMem;
  strm.zfree := zlibFreeMem;
  BufInc := (InBytes + 255) and not 255;
  if OutEstimate = 0 then
    OutBytes := BufInc
  else
    OutBytes := OutEstimate;
  GetMem(OutBuf, OutBytes);
  try
    strm.next_in := InBuf;
    strm.avail_in := InBytes;
    strm.next_out := OutBuf;
    strm.avail_out := OutBytes;
    CCheck(inflateInit_(strm, zlib_version, sizeof(strm)));
    try
      while CCheck(inflate(strm, Z_FINISH)) <> Z_STREAM_END do
      begin
        P := OutBuf;
        Inc(OutBytes, BufInc);
        ReallocMem(OutBuf, OutBytes);
        strm.next_out := PChar(Integer(OutBuf) + (Integer(strm.next_out) - Integer(P)));
        strm.avail_out := BufInc;
      end;
    finally
      CCheck(inflateEnd(strm));
    end;
    ReallocMem(OutBuf, strm.total_out);
    OutBytes := strm.total_out;
  except
    FreeMem(OutBuf);
    raise
  end;
end;
}

{$WARNINGS ON}

 {$else}
implementation
 {$endif}

end.
