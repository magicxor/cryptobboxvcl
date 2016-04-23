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

unit SBZlib;

interface

{$ifndef DONT_USE_ZLIB}

uses
  {$ifndef SB_NO_COMPRESSION}SBZCompressUnit, {$endif}
  SBZCommonUnit,
  SBZUncompressUnit
  , 
  SBStrUtils,
  SBTypes,
  SBUtils
  ;
  
type

  TZlibContext =  record
    strm : TZStreamRec;
  end;
  
  TSBZLibOutputFunc = function(Buffer: pointer; Size: integer; Param: pointer): boolean of object;

{$ifndef SB_NO_COMPRESSION}
procedure InitializeCompression(var Context : TZlibContext; CompressionLevel : integer); 
 {$endif SB_NO_COMPRESSION}
procedure InitializeDecompression(var Context : TZlibContext); 
{$ifdef SB_DEFLATE64}
procedure InitializeDecompression64(var Context : TZlibContext); 
 {$endif}
{$ifndef SB_NO_COMPRESSION}
procedure InitializeCompressionEx(var Context : TZlibContext; Level: integer {$ifdef HAS_DEF_PARAMS} =  Z_BEST_COMPRESSION {$endif}
 );  overload; 
procedure InitializeCompressionEx(var Context : TZlibContext; Level: integer; WindowBits : integer);  overload; 
 {$endif SB_NO_COMPRESSION}

procedure InitializeDecompressionEx(var Context : TZlibContext; UseZLib : boolean {$ifdef HAS_DEF_PARAMS} =  false {$endif}); 
{$ifdef SB_DEFLATE64}
procedure InitializeDecompressionEx64(var Context : TZlibContext; UseZLib : boolean {$ifdef HAS_DEF_PARAMS} =  false {$endif}); 
 {$endif}

{$ifndef SB_NO_COMPRESSION}
procedure FinalizeCompressionEx(var Context : TZlibContext; OutBuffer: pointer;
  var OutSize: cardinal);
 {$endif SB_NO_COMPRESSION}
procedure FinalizeDecompressionEx(var Context : TZlibContext); 

{$ifndef SB_NO_COMPRESSION}
procedure Compress(var Context : TZlibContext; InBuffer : pointer; InSize : cardinal;
  OutBuffer : pointer; var OutSize : cardinal);
 {$endif SB_NO_COMPRESSION}
procedure Decompress(var Context : TZlibContext; InBuffer : pointer; InSize : cardinal;
  OutBuffer : pointer; var OutSize : cardinal);
{$ifndef SB_NO_COMPRESSION}
procedure CompressEx(var Context : TZlibContext; InBuffer : pointer; InSize : cardinal;
  OutBuffer : pointer; var OutSize : cardinal);
 {$endif SB_NO_COMPRESSION}
procedure DecompressEx(var Context : TZlibContext; InBuffer : pointer; InSize : cardinal;
  OutputFunc : TSBZlibOutputFunc; Param : pointer);
{$ifdef SB_DEFLATE64}
//procedure Decompress64(var Context : TZlibContext; InBuffer : pointer; InSize : cardinal;
//  OutBuffer : pointer; var OutSize : cardinal);
//procedure DecompressEx64(var Context : TZlibContext; InBuffer : pointer; InSize : cardinal;
//  OutputFunc : TSBZlibOutputFunc; Param : pointer);
 {$endif}  

implementation

  // we DON'T use SysUtils in Delphi.NET
uses
  SysUtils;

resourcestring
  {$ifndef SB_NO_COMPRESSION}
  SCompressionFailed = 'Compression failed, deflate returned '+ '[%d]' ;
   {$endif SB_NO_COMPRESSION}
  SDecompressionFailed = 'Decompression failed, inflate returned '+ '[%d]' ;
  SOutputBufferTooSmall = 'Output buffer too small';

{$ifndef SB_NO_COMPRESSION}
procedure InitializeCompression(var Context : TZlibContext; CompressionLevel : integer);
begin
  if (CompressionLevel < 1) or (CompressionLevel > 9) then
    CompressionLevel := 6;
  deflateInit_(Context.strm, CompressionLevel, ZLibVersion
     , SizeOf(Context.strm) );
end;

procedure InitializeCompressionEx(var Context: TZlibContext;
    Level: integer {$ifdef HAS_DEF_PARAMS} =  Z_BEST_COMPRESSION {$endif});
begin
  deflateInit2_(Context.strm, {Z_BEST_COMPRESSION}Level, Z_DEFLATED, {-MAX_WBITS}-12,
    DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY, ZLibVersion
     , SizeOf(Context.strm) );
end;

procedure InitializeCompressionEx(var Context : TZlibContext; Level: integer; WindowBits : integer);
begin
  deflateInit2_(Context.strm, Level, Z_DEFLATED, -WindowBits,
    DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY, ZLibVersion
     , SizeOf(Context.strm) );
end;

 {$endif SB_NO_COMPRESSION}

procedure InitializeDecompressionEx(var Context: TZlibContext;
    UseZLib: boolean {$ifdef HAS_DEF_PARAMS} =  false {$endif});
begin
  Context.strm.deflate64 := false;
  if UseZLib then
    inflateInit2_(Context.strm, MAX_WBITS, ZLibVersion
         , SizeOf(Context.strm) )
  else
    inflateInit2_(Context.strm, -MAX_WBITS{-13}, ZLibVersion
         , SizeOf(Context.strm) )
end;

{$ifdef SB_DEFLATE64}
procedure InitializeDecompressionEx64(var Context: TZlibContext;
    UseZLib: boolean {$ifdef HAS_DEF_PARAMS} =  false {$endif});
begin
  InitializeDecompressionEx(Context, UseZLib);
  Context.strm.deflate64 := true;
  inflateReset(Context.strm);
end;
 {$endif}

{$ifndef SB_NO_COMPRESSION}
procedure Compress(var Context : TZlibContext; InBuffer : pointer; InSize : cardinal;
  OutBuffer : pointer; var OutSize : cardinal);
var
  FBuffer : array[Word] of AnsiChar;
  Sz : integer;
  Index : integer;
begin

  Context.strm.next_in := InBuffer;
  Context.strm.avail_in := InSize;
  Index := 0;
  repeat
    Context.strm.next_out :=  @FBuffer[0] ;
    Context.strm.avail_out := SizeOf(FBuffer);
    Sz := Deflate(Context.strm, Z_PARTIAL_FLUSH);
    if Sz = Z_OK then
      SBMove(FBuffer[0], PByteArray(OutBuffer)[Index], SizeOf(FBuffer) - Context.strm.avail_out)
    else
      raise Exception.CreateFmt(SCompressionFailed, [Sz]);
    Inc(Index, SizeOf(FBuffer) - Context.strm.avail_out);
  until Context.strm.avail_out <> 0;
  OutSize := Index;
end;

procedure CompressEx(var Context : TZlibContext; InBuffer : pointer; InSize : cardinal;
  OutBuffer : pointer; var OutSize : cardinal);
var
  FBuffer : array[Word] of AnsiChar;
  Sz : integer;
  Index : integer;
begin
  Context.strm.next_in := InBuffer;
  Context.strm.avail_in := InSize;
  Index := 0;
  repeat
    Context.strm.next_out :=  @FBuffer[0] ;
    Context.strm.avail_out := SizeOf(FBuffer);
    Sz := Deflate(Context.strm, Z_PARTIAL_FLUSH{Z_FULL_FLUSH});
    if Sz = Z_OK then
      SBMove(FBuffer[0], PByteArray(OutBuffer)[Index], SizeOf(FBuffer) - Context.strm.avail_out)
    else
      raise Exception.CreateFmt(SCompressionFailed, [Sz]);
    Inc(Index, SizeOf(FBuffer) - Context.strm.avail_out);
  until Context.strm.avail_out <> 0;
  OutSize := Index;
end;
 {$endif SB_NO_COMPRESSION}

procedure InitializeDecompression(var Context : TZlibContext);
begin
  Context.strm.deflate64 := false;

  inflateInit_(Context.strm, ZLibVersion
     , SizeOf(Context.strm) );
end;

{$ifdef SB_DEFLATE64}
procedure InitializeDecompression64(var Context : TZlibContext);
begin
  InitializeDecompression(Context);
  Context.strm.deflate64 := true;
  InflateReset(Context.strm);
end;
 {$endif}

procedure Decompress(var Context : TZlibContext; InBuffer : pointer; InSize : cardinal;
  OutBuffer : pointer; var OutSize : cardinal);
var
  FBuffer : array[Word] of AnsiChar;
  Sz : integer;
  CurrIndex : integer;
  ToMove : integer;
begin
  
  Context.strm.next_in := InBuffer;
  Context.strm.avail_in := InSize;
  CurrIndex := 0;

  while true do
  begin
    if Context.strm.avail_in = 0 then
      Break;

    Context.strm.next_out :=  @FBuffer[0] ;
    Context.strm.avail_out := SizeOf(FBuffer);

    Sz := inflate(Context.strm, Z_PARTIAL_FLUSH);
    if (Sz = Z_OK) or (Sz = Z_STREAM_END) then
    begin
      ToMove :=  SizeOf(FBuffer)  - Context.Strm.avail_out;

      if CurrIndex + ToMove > integer(OutSize) then
        raise Exception.Create(SOutputBufferTooSmall);

      SBMove(FBuffer[0], PByteArray(OutBuffer)[CurrIndex], ToMove);
      Inc(CurrIndex, ToMove);

      if Sz = Z_STREAM_END then
        Break;
    end
    else
      if Sz = Z_BUF_ERROR then
        abort
      else
        raise Exception.CreateFmt(SDecompressionFailed, [Sz]);

  end;
  OutSize := CurrIndex;
//  inflateEnd(Context.Strm);
end;

procedure DecompressEx(var Context : TZlibContext; InBuffer : pointer; InSize : cardinal;
  OutputFunc: TSBZlibOutputFunc; Param: pointer);
var
  FBuffer : array[0..69999] of AnsiChar;
  Sz : integer;
begin
  
  Context.strm.next_in := InBuffer;
  Context.strm.avail_in := InSize;

  while true do
  begin
    if Context.strm.avail_in = 0 then
      Break;

    Context.strm.next_out :=  @FBuffer[0] ;
    Context.strm.avail_out := SizeOf(FBuffer);


    Sz := inflate(Context.strm, Z_FULL_FLUSH);
    if (Sz = Z_OK) or (Sz = Z_STREAM_END) then
    begin
      OutputFunc(@FBuffer[0], SizeOf(FBuffer) - Context.Strm.avail_out, Param);
      if Sz = Z_STREAM_END then
        Break;
    end
    else if Sz = Z_BUF_ERROR then
      abort
    else
      raise Exception.CreateFmt(SDecompressionFailed, [Sz]);
  end;
end;

{$ifndef SB_NO_COMPRESSION}
procedure FinalizeCompressionEx(var Context : TZlibContext; OutBuffer: pointer;
  var OutSize: cardinal);
var
  FBuffer : array[0..4095] of AnsiChar;
  Sz : integer;
  Index : integer;
begin
  Context.strm.next_in := nil;
  Context.strm.avail_in := 0;
  Index := 0;
  repeat
    Context.strm.next_out :=  @FBuffer[0] ;
    Context.strm.avail_out := SizeOf(FBuffer);
    
    Sz := Deflate(Context.strm, Z_FINISH);
    if Sz = Z_STREAM_END then
      SBMove(FBuffer[0], PByteArray(OutBuffer)[Index], SizeOf(FBuffer) - Context.strm.avail_out)
    else
      raise Exception.CreateFmt(SCompressionFailed, [Sz]);
    Inc(Index, SizeOf(FBuffer) - Context.strm.avail_out);
  until Context.strm.avail_out <> 0;
  OutSize := Index;
  DeflateEnd(Context.strm);
end;
 {$endif SB_NO_COMPRESSION}

procedure FinalizeDecompressionEx(var Context : TZlibContext);
begin
  InflateEnd(Context.strm);
end;

 {$else}

implementation

 {$endif}

end.

