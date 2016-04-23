(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBEncoding;

interface

uses
  SysUtils,
  SBTypes,
  SBUtils,
  SBConstants;


const

  BASE64_DECODE_OK                      = 0;
  BASE64_DECODE_INVALID_CHARACTER       = 1;
  BASE64_DECODE_WRONG_DATA_SIZE         = 2;
  BASE64_DECODE_NOT_ENOUGH_SPACE        = 3;

  Base64Symbols : array [0..63] of byte =
     ( 
     $41, $42, $43, $44, $45, $46, $47, $48, $49, $4A, $4B, $4C, $4D, $4E, $4F, $50,
     $51, $52, $53, $54, $55, $56, $57, $58, $59, $5A, $61, $62, $63, $64, $65, $66,
     $67, $68, $69, $6A, $6B, $6C, $6D, $6E, $6F, $70, $71, $72, $73, $74, $75, $76,
     $77, $78, $79, $7A, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $2B, $2F
     ) ;
  Base64Values : array [0..255] of byte =
     ( 
     $FE, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FE, $FE, $FF, $FF, $FE, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FE, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $3E, $FF, $FF, $FF, $3F,
     $34, $35, $36, $37, $38, $39, $3A, $3B, $3C, $3D, $FF, $FF, $FF, $FD, $FF, $FF,
     $FF,  $0,  $1,  $2,  $3,  $4,  $5,  $6,  $7,  $8,  $9,  $A,  $B,  $C,  $D,  $E,
      $F, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $FF, $FF, $FF, $FF, $FF,
     $FF, $1A, $1B, $1C, $1D, $1E, $1F, $20, $21, $22, $23, $24, $25, $26, $27, $28,
     $29, $2A, $2B, $2C, $2D, $2E, $2F, $30, $31, $32, $33, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF
     ) ;

  Base32Symbols: array [0..31] of Byte =
     ( 
     $41, $42, $43, $44, $45, $46, $47, $48, $49, $4A, $4B, $4C, $4D, $4E, $4F, $50,
     $51, $52, $53, $54, $55, $56, $57, $58, $59, $5A, $32, $33, $34, $35, $36, $37
     ) ;
  Base32Values : array [0..255] of Byte =
     ( 
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FE, $FE, $FF, $FF, $FE, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $1A, $1B, $1C, $1D, $1E, $1F, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $00, $01, $02, $03, $04, $05, $06, $07, $08, $09, $0A, $0B, $0C, $0D, $0E,
     $0F, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF
     ) ;

  Base32ExtSymbols: array [0..31] of Byte =
     ( 
     $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $41, $42, $43, $44, $45, $46,
     $47, $48, $49, $4A, $4B, $4C, $4D, $4E, $4F, $50, $51, $52, $53, $54, $55, $56
     ) ;
  Base32ExtValues : array [0..255] of Byte =
     ( 
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FE, $FE, $FF, $FF, $FE, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $00, $01, $02, $03, $04, $05, $06, $07, $08, $09, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $0A, $0B, $0C, $0D, $0E, $0F, $10, $11, $12, $13, $14, $15, $16, $17, $18,
     $19, $1A, $1B, $1C, $1D, $1E, $1F, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
     $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF
     ) ;

  base64PadByte = Byte($3D);

type
  TSBBase64Context = record
    Tail :  array [0..3] of byte ;
    TailBytes : integer;
    LineWritten : integer;
    LineSize : integer;
    TrailingEol : boolean;
    PutFirstEol : boolean;
    LiberalMode : boolean;

    fEOL : array [0..3] of byte;
    EOLSize : integer;

    OutBuf :  array [0..3] of byte ;
    EQUCount : integer;
  end;

  TSBBase32Context =  record
    Tail: array of Byte;
    TailSize: Integer;  // must be between 0 and 4
    UseExtAlphabet: Boolean;
  end;
  EElBase32Error =  class(ESecureBlackboxError);

  EElURLDecodeError =  class(ESecureBlackboxError);


function B64EstimateEncodedSize(Ctx : TSBBase64Context; InSize : integer) : integer; 
function B64InitializeEncoding(var Ctx : TSBBase64Context; LineSize : integer;
   fEOL  : TSBEOLMarker; TrailingEOL : boolean  =  false) : boolean;  
function B64InitializeDecoding(var Ctx : TSBBase64Context) : boolean;    overload; 
function B64InitializeDecoding(var Ctx : TSBBase64Context; LiberalMode : boolean) : boolean;    overload; 
function B64Encode(var Ctx : TSBBase64Context; Buffer : pointer; Size : integer;
  OutBuffer : pointer; var OutSize : integer) : boolean;
function B64Decode(var Ctx : TSBBase64Context; Buffer : pointer; Size : integer;
  OutBuffer: pointer; var OutSize : integer) : boolean;
function B64FinalizeEncoding(var Ctx : TSBBase64Context;
  OutBuffer : pointer; var OutSize : integer) : boolean;
function B64FinalizeDecoding(var Ctx : TSBBase64Context;
  OutBuffer : pointer; var OutSize : integer) : boolean;
function Base64UnicodeDecode(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
  var OutSize : integer) : integer;
function Base64Decode(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
  var OutSize : integer) : integer; overload;
function Base64Decode(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
  var OutSize : integer; LiberalMode : boolean) : integer; overload;
function Base64Encode(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
  var OutSize : integer; WrapLines : boolean = true) : boolean;
function Base64EncodeString(const InText: string; WrapLines : boolean{$ifdef HAS_DEF_PARAMS} =  true {$endif}) : string;  overload; function Base64DecodeString(const InText: string) : string;  overload; 
function Base64EncodeArray(const InBuf: ByteArray; WrapLines : boolean{$ifdef HAS_DEF_PARAMS} =  true {$endif}) : string;  overload; function Base64DecodeArray(const InBuf: string) : ByteArray;  overload; 
{$ifdef SB_UNICODE_VCL}
function Base64EncodeString(const InBuf: ByteArray; WrapLines : boolean{$ifdef HAS_DEF_PARAMS}= true {$endif}) : ByteArray; overload;
function Base64DecodeString(const InBuf: ByteArray) : ByteArray; overload;
 {$endif}

// Base32 processing routines according to RFC 4648

const
  SB_BASE32_ERROR_BASE = $0120;
  SB_BASE32_INVALID_DATA_SIZE = SB_BASE32_ERROR_BASE + 1;
  SB_BASE32_INVALID_DATA = SB_BASE32_ERROR_BASE + 2;

function B32EstimateEncodedSize(const Context: TSBBase32Context; InSize: Integer): Integer; 

procedure B32InitializeEncoding(var Context: TSBBase32Context; UseExtendedAlphabet: Boolean); 
function B32Encode(var Context: TSBBase32Context; Buffer: Pointer; Size: Integer;
  OutBuffer: Pointer; var OutSize: Integer): Boolean; overload;
function B32FinalizeEncoding(var Context: TSBBase32Context; OutBuffer: Pointer;
  var OutSize: Integer): Boolean; overload;
function Base32Encode(InBuffer: Pointer; InSize: Integer; OutBuffer: Pointer;
  var OutSize: Integer; UseExtendedAlphabet: Boolean): Boolean; overload;
function B32Encode(var Context: TSBBase32Context; Buffer: ByteArray; Index, Size: Integer;
  var OutBuffer: ByteArray; OutIndex: Integer; var OutSize: Integer): Boolean;  overload ;
function B32FinalizeEncoding(var Context: TSBBase32Context; var OutBuffer: ByteArray;
  OutIndex: Integer; var OutSize: Integer): Boolean;  overload ;
function Base32Encode(InBuffer: ByteArray; InIndex, InSize: Integer; var OutBuffer: ByteArray;
  OutIndex: Integer; var OutSize: Integer; UseExtendedAlphabet: Boolean): Boolean;  overload ;
function Base32EncodeBuffer(const Data: ByteArray; UseExtendedAlphabet: Boolean): ByteArray; 
function Base32EncodeString(const Data: string; UseExtendedAlphabet: Boolean): string; 

// Returns the size of buffer that is enough to store the decoded data.
// Actual size of the decoded data can be up to 4 bytes lesser than the estimated one.
// The function returns -1 if InSize is not multiple of 8.
function B32EstimateDecodedSize(const Context: TSBBase32Context; InSize: Integer): Integer; 

procedure B32InitializeDecoding(var Context: TSBBase32Context; UseExtendedAlphabet: Boolean); 
// Decodes a chunk of input data and writes the decoded data (if any) into the output buffer.
// The function returns True if the operation succeeded and the OutSize parameter specifies
// the actual size of the decoded data writtent into the output buffer.
// If size of the output buffer is less than needed to write the decoded data, the function
// returns False and the value of OutSize parameter specified the required output buffer size.
// If the input buffer contains an invalid data, the function returns False and the value
// of OutSize parameter is set to -1.
function B32Decode(var Context: TSBBase32Context; Buffer: Pointer; Size: Integer;
  OutBuffer: Pointer; var OutSize: Integer): Boolean; overload;
// Decodes the input data and writes the decoded data into the output buffer. If the process
// succeeded, the function returns True and OutSize parameter is set to size of the actual
// decoded data written into the output buffer. If the input buffer contains an invalid data,
// the function returns False and the OutSize parameter is set to -1. If the output buffer is
// too small to hold all decoded data, the function returns False and the OutSize parameter
// is set to required output buffer size.
function Base32Decode(InBuffer: Pointer; InSize: Integer; OutBuffer: Pointer;
  var OutSize: Integer; UseExtendedAlphabet: Boolean): Boolean; overload;
// Decodes a chunk of input data and writes the decoded data (if any) into the output buffer.
// The function returns True if the operation succeeded and the OutSize parameter specifies
// the actual size of the decoded data writtent into the output buffer.Base64UnicodeDecode
// If size of the output buffer is less than needed to write the decoded data, the function
// returns False and the value of OutSize parameter specified the required output buffer size.
// If the input buffer contains an invalid data, the function returns False and the value
// of OutSize parameter is set to -1.
function B32Decode(var Context: TSBBase32Context; Buffer: ByteArray; Index, Size: Integer;
  var OutBuffer: ByteArray; OutIndex: Integer; var OutSize: Integer): Boolean;  overload ;
// Checks if all the decoding process went fine and returns True if so.
function B32FinalizeDecoding(var Context: TSBBase32Context): Boolean; 
function Base32Decode(InBuffer: ByteArray; InIndex, InSize: Integer; var OutBuffer: ByteArray;
  OutIndex: Integer; var OutSize: Integer; UseExtendedAlphabet: Boolean): Boolean;  overload ;
function Base32DecodeBuffer(const Data: ByteArray; UseExtendedAlphabet: Boolean): ByteArray; 
function Base32DecodeString(const Data: string; UseExtendedAlphabet: Boolean): string; 

function Base32Extract(const Data: ByteArray; Start, Size: Integer; UseExtendedAlphabet: Boolean): ByteArray;  overload ;
function Base32Extract(const Data: string; Start, Size: Integer; UseExtendedAlphabet: Boolean): string;  overload ;

function URLEncode(const Data: string): string; 
function URLDecode(const Data: string): string; 

function Base16DecodeString(const Data: string): ByteArray; 

implementation

uses
  SBStrUtils;

{ Base32 Processing Routines }


function B32EstimateEncodedSize(const Context: TSBBase32Context; InSize: Integer): Integer;
begin
  // Context parameter is not used yet and specified for possible use
  // in the future like in base64 routine.
  Result := ((InSize + 4) div 5) shl 3;
end;

procedure B32InitializeEncoding(var Context: TSBBase32Context; UseExtendedAlphabet: Boolean);
begin
  Context.TailSize := 0;
  SetLength(Context.Tail, 5);
  SetLength(Context.Tail, 5);
  FillChar(Context.Tail[0], 5, 0);
  Context.UseExtAlphabet := UseExtendedAlphabet;
end;

procedure B32EncodeBlock(InBlock, OutBlock: Pointer; UseExtendedAlphabet: Boolean);
var
  Alphabet: PByteArray;
begin
  if UseExtendedAlphabet then
    Alphabet := @Base32ExtSymbols
  else
    Alphabet := @Base32Symbols;

  PByteArray(OutBlock)[0] := Alphabet[PByteArray(InBlock)[0] shr 3];
  PByteArray(OutBlock)[1] := Alphabet[((PByteArray(InBlock)[0] and $07) shl 2) or
    (PByteArray(InBlock)[1] shr 6)];
  PByteArray(OutBlock)[2] := Alphabet[(PByteArray(InBlock)[1] and $3E) shr 1];
  PByteArray(OutBlock)[3] := Alphabet[((PByteArray(InBlock)[1] and $01) shl 4) or
    (PByteArray(InBlock)[2] shr 4)];
  PByteArray(OutBlock)[4] := Alphabet[((PByteArray(InBlock)[2] and $0F) shl 1) or
    (PByteArray(InBlock)[3] shr 7)];
  PByteArray(OutBlock)[5] := Alphabet[(PByteArray(InBlock)[3] and $7C) shr 2];
  PByteArray(OutBlock)[6] := Alphabet[((PByteArray(InBlock)[3] and $03) shl 3) or
    (PByteArray(InBlock)[4] shr 5)];
  PByteArray(OutBlock)[7] := Alphabet[PByteArray(InBlock)[4] and $1F];
end;

function B32Encode(var Context: TSBBase32Context; Buffer: Pointer; Size: Integer;
  OutBuffer: Pointer; var OutSize: Integer): Boolean;
var
  Temp: Integer;
  InPointer, OutPointer: PByte;
begin
  // check if there is any data to encode
  Result := (Size >= 0);
  if Size <= 0 then
  begin
    OutSize := 0;
    Exit;
  end;
  // check if there is enough data for at least one encoding iteration
  if (Size + Context.TailSize) < 5 then
  begin
    OutSize := 0;
    SBMove(Buffer^, Context.Tail[Context.TailSize], Size);
    Inc(Context.TailSize, Size);
    Exit;
  end;
  // check if there is enough space in the output buffer
  Temp := ((Size + Context.TailSize) div 5) shl 3;  // shl 3 = * 8
  Result := (Temp <= OutSize);
  if not Result then
  begin
    OutSize := Temp;
    Exit;
  end;
  // initialize local variables
  InPointer := Buffer;
  OutPointer := OutBuffer;
  OutSize := 0;
  // check if some data left since the previous call
  if Context.TailSize > 0 then
  begin
    Temp := 5 - Context.TailSize;
    SBMove(InPointer^, Context.Tail[Context.TailSize], Temp);
    Inc(InPointer, Temp);
    Dec(Size, Temp);
    B32EncodeBlock(InPointer, OutPointer, Context.UseExtAlphabet);
    Inc(OutPointer, 8);
    Inc(OutSize, 8);
    FillChar(Context.Tail[0], SizeOf(Context.Tail), 0);
    Context.TailSize := 0;
  end;
  // encode the data chunk by chunk
  while Size >= 5 do
  begin
    B32EncodeBlock(InPointer, OutPointer, Context.UseExtAlphabet);
    Inc(InPointer, 5);
    Dec(Size, 5);
    Inc(OutPointer, 8);
    Inc(OutSize, 8);
  end;
  // check if any data left unencoded
  if Size > 0 then
  begin
    // store the remaining data into the context
    SBMove(InPointer^, Context.Tail[0], Size);
    Context.TailSize := Size;
  end;
end;

function B32Encode(var Context: TSBBase32Context; Buffer: ByteArray; Index, Size: Integer;
  var OutBuffer: ByteArray; OutIndex: Integer; var OutSize: Integer): Boolean;
begin
  Result := B32Encode(Context, @Buffer[Index], Size, @OutBuffer[OutIndex], OutSize);
end;

function B32FinalizeEncoding(var Context: TSBBase32Context; OutBuffer: Pointer;
  var OutSize: Integer): Boolean;
begin
  if Context.TailSize = 0 then
  begin
    OutSize := 0;
    Result := True;
  end
  else
  begin
    Result := (OutSize <= 8);
    OutSize := 8;
    if not Result then
      Exit;
    B32EncodeBlock(@Context.Tail[0], OutBuffer, Context.UseExtAlphabet);
    PByteArray(OutBuffer)[7] := $3D;
    if Context.TailSize < 4 then
    begin
      PByteArray(OutBuffer)[6] := $3D;
      PByteArray(OutBuffer)[5] := $3D;
    end;
    if Context.TailSize < 3 then
      PByteArray(OutBuffer)[4] := $3D;
    if Context.TailSize < 2 then
    begin
      PByteArray(OutBuffer)[3] := $3D;
      PByteArray(OutBuffer)[2] := $3D;
    end;
  end;
end;

function B32FinalizeEncoding(var Context: TSBBase32Context; var OutBuffer: ByteArray;
  OutIndex: Integer; var OutSize: Integer): Boolean;
begin
  Result := B32FinalizeEncoding(Context, @OutBuffer[OutIndex], OutSize);
end;

function Base32Encode(InBuffer: Pointer; InSize: Integer; OutBuffer: Pointer;
  var OutSize: Integer; UseExtendedAlphabet: Boolean): Boolean;
var
  Context: TSBBase32Context;
  Size: Integer;
begin
  B32InitializeEncoding(Context, UseExtendedAlphabet);
  Size := B32EstimateEncodedSize(Context, InSize);
  Result := (OutSize >= Size);
  OutSize := Size;
  if not Result then
    Exit;
  Result := B32Encode(Context, InBuffer, InSize, OutBuffer, Size);
  if not Result then
    Exit;
  OutBuffer := @(PByteArray(OutBuffer)[Size]);
  Size := OutSize - Size;
  Result := B32FinalizeEncoding(Context, OutBuffer, Size);
end;

function Base32Encode(InBuffer: ByteArray; InIndex, InSize: Integer; var OutBuffer: ByteArray;
  OutIndex: Integer; var OutSize: Integer; UseExtendedAlphabet: Boolean): Boolean;
begin
  Result := Base32Encode(@InBuffer[InIndex], InSize, @OutBuffer[OutIndex], OutSize, UseExtendedAlphabet);
end;

function Base32EncodeBuffer(const Data: ByteArray; UseExtendedAlphabet: Boolean): ByteArray;
var
  Size, Dummy: Integer;
  Context: TSBBase32Context;
begin
  if Length(Data) = 0 then
  begin
    SetLength(Result, 0);
    Exit;
  end;
  B32InitializeEncoding(Context, UseExtendedAlphabet);
  Size := B32EstimateEncodedSize(Context, Length(Data));
  SetLength(Result, Size);
  if not B32Encode(Context, Data, 0, Length(Data), Result, 0, Size) then
  begin
    SetLength(Result, 0);
    Exit;
  end;
  Dummy := Size;
  Size := Length(Result) - Size;
  if not B32FinalizeEncoding(Context, Result, Dummy, Size)  then
    SetLength(Result, 0);
end;

function Base32EncodeString(const Data: string; UseExtendedAlphabet: Boolean): string;
begin
  if Length(Data) = 0 then
    Result :=  '' 
  else
    Result := StringOfBytes(Base32EncodeBuffer(BytesOfString(Data), UseExtendedAlphabet));
end;

function B32EstimateDecodedSize(const Context: TSBBase32Context; InSize: Integer): Integer;
begin
  if (InSize mod 8) = 0 then
    Result := (InSize shr 3) * 5
  else
    Result := -1;
end;

// Decodes the block (8 bytes) of data and returns the actual data size (1-5 bytes)
// written to the output buffer. The function returns 0 if the input data is not correct.
function B32DecodeBlock(InBlock, OutBlock: Pointer; UseExtendedAlphabet: Boolean): Integer;
var
  Alphabet: PByteArray;
  B1, B2, B3: Byte;
begin
  if UseExtendedAlphabet then
    Alphabet := @Base32ExtValues
  else
    Alphabet := @Base32Values;

  B1 := Alphabet[PByteArray(InBlock)[0]];
  B2 := Alphabet[PByteArray(InBlock)[1]];
  Result := 0;
  if (B1 = $FF) or (B2 = $FF)  then
    Exit;
  PByteArray(OutBlock)[0] := (B1 shl 3) or (B2 shr 2);
  B1 := PByteArray(InBlock)[2];
  if B1 = $3D then
  begin
    Result := 1;
    Exit;
  end;
  B1 := Alphabet[B1];
  B3 := Alphabet[PByteArray(InBlock)[3]];
  if (B1 = $FF) or (B3 = $FF) then
    Exit;
  PByteArray(OutBlock)[1] := (B2 shl 6) or (B1 shl 1) or (B3 shr 4);
  B1 := PByteArray(InBlock)[4];
  if B1 = $3D then
  begin
    Result := 2;
    Exit;
  end;
  B1 := Alphabet[B1];
  if B1 = $FF then
    Exit;
  PByteArray(OutBlock)[2] := (B3 shl 4) or (B1 shr 1);
  B2 := PByteArray(InBlock)[5];
  if B2 = $3D then
  begin
    Result := 3;
    Exit;
  end;
  B2 := Alphabet[B2];
  B3 := Alphabet[PByteArray(InBlock)[6]];
  if (B2 = $FF) or (B3 = $FF) then
    Exit;
  PByteArray(OutBlock)[3] := (B1 shl 7) or (B2 shl 2) or (B3 shr 3);
  B1 := PByteArray(InBlock)[7];
  if B1 = $3D then
  begin
    Result := 4;
    Exit;
  end;
  B1 := Alphabet[B1];
  if B1 = $FF then
    Exit;
  PByteArray(OutBlock)[4] := (B3 shl 5) or B1;
  Result := 5;
end;

procedure B32InitializeDecoding(var Context: TSBBase32Context; UseExtendedAlphabet: Boolean);
begin
  Context.TailSize := 0;
  SetLength(Context.Tail, 8);
  FillChar(Context.Tail[0], 8, 0);
  Context.UseExtAlphabet := UseExtendedAlphabet;
end;

function B32Decode(var Context: TSBBase32Context; Buffer: Pointer; Size: Integer;
  OutBuffer: Pointer; var OutSize: Integer): Boolean;
var
  Temp: Integer;
  InPointer, OutPointer: PByte;
begin
  Result := False;
  // check if there is any data to encode
  if Size <= 0 then
  begin
    Result := (Size = 0);
    OutSize := 0;
    Exit;
  end;
  // check if there is enough data for at least one decoding iteration
  if (Size + Context.TailSize) < 8 then
  begin
    OutSize := 0;
    SBMove(Buffer^, Context.Tail[Context.TailSize], Size);
    Inc(Context.TailSize, Size);
    Exit;
  end;
  // check if there is enough space in the output buffer
  Temp := ((Size + Context.TailSize) shr 3) * 5;  // shr 3 = div 8
  if Temp > OutSize then
  begin
    OutSize := Temp;
    Exit;
  end;
  // initialize local variables
  InPointer := Buffer;
  OutPointer := OutBuffer;
  OutSize := 0;
  // check if some data left since the previous call
  if Context.TailSize > 0 then
  begin
    Temp := 8 - Context.TailSize;
    SBMove(InPointer^, Context.Tail[Context.TailSize], Temp);
    Inc(InPointer, Temp);
    Dec(Size, Temp);
    Temp := B32DecodeBlock(InPointer, OutPointer, Context.UseExtAlphabet);
    if Temp = 0 then
    begin
      OutSize := -1;
      Exit;
    end;
    Inc(OutPointer, Temp);
    Inc(OutSize, Temp);
    FillChar(Context.Tail[0], SizeOf(Context.Tail), 0);
    Context.TailSize := 0;
    if Temp < 5 then      // this is the last chunk if less than 5 bytes written to the output buffer
    begin
      Result := True;
      Exit;
    end;
  end;
  // decode the data chunk by chunk
  while Size >= 8 do
  begin
    Temp := B32DecodeBlock(InPointer, OutPointer, Context.UseExtAlphabet);
    if Temp = 0 then
    begin
      OutSize := -1;
      Exit;
    end;
    Inc(InPointer, 8);
    Dec(Size, 8);
    Inc(OutPointer, Temp);
    Inc(OutSize, Temp);
    if Temp < 5 then      // this is the last chunk if less than 5 bytes written to the output buffer
    begin
      Result := True;
      Exit;
    end;
  end;
  // check if any data left undecoded
  if Size > 0 then
  begin
    // store the remaining data into the context
    SBMove(InPointer^, Context.Tail[0], Size);
    Context.TailSize := Size;
  end;
  Result := True;
end;

function B32Decode(var Context: TSBBase32Context; Buffer: ByteArray; Index, Size: Integer;
  var OutBuffer: ByteArray; OutIndex: Integer; var OutSize: Integer): Boolean;
begin
  Result := B32Decode(Context, @Buffer[Index], Size, @OutBuffer[OutIndex], OutSize);
end;

function B32FinalizeDecoding(var Context: TSBBase32Context): Boolean;
begin
  Result := (Context.TailSize = 0);
end;

function Base32Decode(InBuffer: Pointer; InSize: Integer; OutBuffer: Pointer;
  var OutSize: Integer; UseExtendedAlphabet: Boolean): Boolean;
var
  Context: TSBBase32Context;
  Size: Integer;
begin
  B32InitializeDecoding(Context, UseExtendedAlphabet);
  Size := B32EstimateDecodedSize(Context, InSize);
  Result := (OutSize >= Size);
  OutSize := Size;
  if not Result then
    Exit;
  Result := B32Decode(Context, InBuffer, InSize, OutBuffer, OutSize);
  if not Result then
    Exit;
  Result := B32FinalizeDecoding(Context);
end;

function Base32Decode(InBuffer: ByteArray; InIndex, InSize: Integer; var OutBuffer: ByteArray;
  OutIndex: Integer; var OutSize: Integer; UseExtendedAlphabet: Boolean): Boolean;
begin
  Result := Base32Decode(@InBuffer[InIndex], InSize, @OutBuffer[OutIndex], OutSize, UseExtendedAlphabet);
end;

function Base32DecodeBuffer(const Data: ByteArray; UseExtendedAlphabet: Boolean): ByteArray;
var
  Size: Integer;
  Context: TSBBase32Context;
begin
  if Length(Data) = 0 then
  begin
    SetLength(Result, 0);
    Exit;
  end;
  B32InitializeDecoding(Context, UseExtendedAlphabet);
  Size := B32EstimateDecodedSize(Context, Length(Data));
  if Size < 0 then
    raise EElBase32Error.Create(SBase32InvalidDataSize, SB_BASE32_INVALID_DATA_SIZE);
  SetLength(Result, Size);
  if not B32Decode(Context, Data, 0, Length(Data), Result, 0, Size) then
  begin
    SetLength(Result, 0);
    if Size < 0 then
      raise EElBase32Error.Create(SBase32InvalidData, SB_BASE32_INVALID_DATA)
    else
      Exit;
  end;
  if B32FinalizeDecoding(Context) then
  begin
    if Size < Length(Result) then
      SetLength(Result, Size);
  end
  else
    SetLength(Result, 0);
end;

function Base32DecodeString(const Data: string; UseExtendedAlphabet: Boolean): string;
begin
  if Length(Data) = 0 then
    Result :=  '' 
  else
    Result := StringOfBytes(Base32DecodeBuffer(BytesOfString(Data), UseExtendedAlphabet));
end;

function Base32Extract(const Data: ByteArray; Start, Size: Integer; UseExtendedAlphabet: Boolean): ByteArray;
var
  I, Count: Integer;
  Alphabet:  PByteArray ;
begin
  Count := Length(Data);
  if (Count = 0) or (Start >= Count) then
  begin
    SetLength(Result, 0);
    Exit;
  end;
  if Size = 0 then
    Size := Count - Start
  else
    Size := Min(Count, Start + Size);
  Count := 0;
  if UseExtendedAlphabet then
  begin
    Alphabet :=  @ Base32ExtValues;
  end
  else
  begin
    Alphabet :=  @ Base32Values;
  end;

  for I := Start to Size - 1 do
    if (Data[I] = $3D) or (Alphabet[Data[I]] <> $FF) then
      Inc(Count)
    else
      Break;
  Count := Count and Integer($7FF8);  // ensure that Count is multiple of 8
  SetLength(Result, Count);
  if Count > 0 then
    SBMove(Data[Start], Result[0], Count);

end;

function Base32Extract(const Data: string; Start, Size: Integer; UseExtendedAlphabet: Boolean): string;
begin
  Result := StringOfBytes(Base32Extract(BytesOfString(Data), Start - StringStartOffset, Size, UseExtendedAlphabet));
end;

{ Base64 processing routines }

function B64EstimateEncodedSize(Ctx : TSBBase64Context; InSize : integer) : integer;
begin
  Result := ((InSize + 2) div 3) shl 2;

  if (Ctx.EOLSize > 0) and (Ctx.LineSize > 0) then
  begin
    Result := Result + ((Result + Ctx.LineSize - 1) div Ctx.LineSize) * Ctx.EOLSize;

    if not Ctx.TrailingEol then
      Result := Result - Ctx.EOLSize;
  end;    
end;

function B64InitializeDecoding(var Ctx : TSBBase64Context) : boolean;
begin

  Ctx.TailBytes := 0;
  Ctx.EQUCount := 0;
  Ctx.LiberalMode := false;

  Result := true;
end;

function B64InitializeDecoding(var Ctx : TSBBase64Context; LiberalMode : boolean) : boolean;
begin

  Ctx.TailBytes := 0;
  Ctx.EQUCount := 0;
  Ctx.LiberalMode := LiberalMode;

  Result := true;
end;

function B64InitializeEncoding(var Ctx : TSBBase64Context; LineSize : integer;
   fEOL  : TSBEOLMarker; TrailingEOL : boolean  =  false) : boolean;
begin

  Result := false;
  Ctx.TailBytes := 0;
  Ctx.LineSize := LineSize;
  Ctx.LineWritten := 0;
  Ctx.EQUCount := 0;
  Ctx.TrailingEol := TrailingEol;
  Ctx.PutFirstEol := false;

  if LineSize < 4 then Exit;

  case  fEOL  of
  emCRLF :
    begin
      SBMove(CRLFByteArray[0], Ctx.fEOL[0], ConstLength(CRLFByteArray));
      Ctx.EOLSize := ConstLength(CRLFByteArray);
    end;
  emCR :
    begin
      SBMove(CRByteArray[0], Ctx.fEOL[0], ConstLength(CRByteArray));
      Ctx.EOLSize := ConstLength(CRByteArray);
    end;
  emLF :
    begin
      SBMove(LFByteArray[0], Ctx.fEOL[0], ConstLength(LFByteArray));
      Ctx.EOLSize := ConstLength(LFByteArray);
    end;
    else
      Ctx.EOLSize := 0;
  end;

  Result := true;
end;

function B64Encode(var Ctx : TSBBase64Context; Buffer : pointer; Size : integer;
  OutBuffer : pointer; var OutSize : integer) : boolean;
var
  EstSize, I, Chunks : integer;
  PreserveLastEol : boolean;
begin
  PreserveLastEol := false;

  EstSize := ((Size + Ctx.TailBytes) div 3) shl 2;
  if (Ctx.LineSize > 0) and (Ctx.EOLSize > 0) then
  begin
    if (EstSize > 0) and ((Ctx.LineWritten + EstSize) mod Ctx.LineSize = 0) and
      ((Ctx.TailBytes + Size) mod 3 = 0) then
      PreserveLastEol := true;
    EstSize := EstSize + ((EstSize + Ctx.LineWritten) div Ctx.LineSize) * Ctx.EOLSize;
    if PreserveLastEol then
      EstSize := EstSize - Ctx.EOLSize;
  end;
  if Ctx.PutFirstEol then
    EstSize := EstSize + Ctx.EOLSize;

  if OutSize < EstSize then
  begin
    OutSize := EstSize;
    Result := false;
    Exit;
  end;

  OutSize := EstSize;

  if Ctx.PutFirstEol then
  begin
    SBMove(Ctx.fEOL[0], OutBuffer^, Ctx.EOLSize);
    Inc(PtrUInt(OutBuffer), Ctx.EOLSize);
    Ctx.PutFirstEol := false;
  end;  

  if Size + Ctx.TailBytes < 3 then
  begin
    for I := 0 to Size - 1 do
      Ctx.Tail[Ctx.TailBytes + I] := PByteArray(Buffer)^[I];
    Inc(Ctx.TailBytes, Size);
    Result := true;
    Exit;
  end;

  if Ctx.TailBytes > 0 then
  begin
    for I := 0 to 2 - Ctx.TailBytes do
      Ctx.Tail[Ctx.TailBytes + I] := PByteArray(Buffer)^[I];

    Inc(PtrUInt(Buffer), 3 - Ctx.TailBytes);
    Dec(Size, 3 - Ctx.TailBytes);

    Ctx.TailBytes := 0;

    Ctx.OutBuf[0] := Base64Symbols[Ctx.Tail[0] shr 2];
    Ctx.OutBuf[1] := Base64Symbols[((Ctx.Tail[0] and 3) shl 4) or (Ctx.Tail[1] shr 4)];
    Ctx.OutBuf[2] := Base64Symbols[((Ctx.Tail[1] and $f) shl 2) or (Ctx.Tail[2] shr 6)];
    Ctx.OutBuf[3] := Base64Symbols[Ctx.Tail[2] and $3f];

    if (Ctx.LineSize = 0) or (Ctx.LineWritten + 4 < Ctx.LineSize) then
    begin
      SBMove(Ctx.OutBuf[0], OutBuffer^, 4);
      Inc(PtrUInt(OutBuffer), 4);
      Inc(Ctx.LineWritten, 4);
    end
    else
    begin
      I := Ctx.LineSize - Ctx.LineWritten;
      SBMove(Ctx.OutBuf[0], OutBuffer^, I);
      Inc(PtrUInt(OutBuffer), I);
      if (Size > 0) or (I < 4) or (not PreserveLastEol) then
      begin
        SBMove(Ctx.fEOL[0], OutBuffer^, Ctx.EOLSize);
        Inc(PtrUInt(OutBuffer), Ctx.EOLSize);
      end;  
      SBMove(Ctx.OutBuf[I], OutBuffer^, 4 - I);
      Inc(PtrUInt(OutBuffer), 4 - I);
      Ctx.LineWritten := 4 - I;
    end;
  end;

  while Size >= 3 do
  begin
    if Ctx.LineSize > 0 then
    begin
      Chunks := (Ctx.LineSize - Ctx.LineWritten) shr 2;
      if Chunks > Size div 3 then
        Chunks := Size div 3;
    end
    else
      Chunks := Size div 3;


    for I := 0 to Chunks - 1 do
    begin
      PByte(OutBuffer)^ := Base64Symbols[PByteArray(Buffer)^[0] shr 2];
      Inc(PtrUInt(OutBuffer));
      PByte(OutBuffer)^ := Base64Symbols[((PByteArray(Buffer)^[0] and 3) shl 4)
        or (PByteArray(Buffer)^[1] shr 4)];
      Inc(PtrUInt(OutBuffer));
      PByte(OutBuffer)^ := Base64Symbols[((PByteArray(Buffer)^[1] and $f) shl 2)
        or (PByteArray(Buffer)^[2] shr 6)];
      Inc(PtrUInt(OutBuffer));
      PByte(OutBuffer)^ := Base64Symbols[PByteArray(Buffer)^[2] and $3f];
      Inc(PtrUInt(OutBuffer));
      Inc(PtrUInt(Buffer), 3);
    end;

    Dec(Size, 3 * Chunks);

    if Ctx.LineSize > 0 then
    begin
      Inc(Ctx.LineWritten, Chunks shl 2);

      if (Size >= 3) and (Ctx.LineSize - Ctx.LineWritten > 0) then
      begin
        Ctx.OutBuf[0] := Base64Symbols[PByteArray(Buffer)^[0] shr 2];
        Ctx.OutBuf[1] := Base64Symbols[((PByteArray(Buffer)^[0] and 3) shl 4)
          or (PByteArray(Buffer)^[1] shr 4)];
        Ctx.OutBuf[2] := Base64Symbols[((PByteArray(Buffer)^[1] and $f) shl 2)
          or (PByteArray(Buffer)^[2] shr 6)];
        Ctx.OutBuf[3] := Base64Symbols[PByteArray(Buffer)^[2] and $3f];
        Inc(PtrUInt(Buffer), 3);

        Dec(Size, 3);

        I := Ctx.LineSize - Ctx.LineWritten;

        SBMove(Ctx.OutBuf[0], OutBuffer^, I);
        Inc(PtrUInt(OutBuffer), I);
        if (Ctx.EOLSize > 0) and ((I < 4) or (Size > 0) or (not PreserveLastEol)) then
        begin
          SBMove(Ctx.fEOL[0], OutBuffer^, Ctx.EOLSize);
          Inc(PtrUInt(OutBuffer), Ctx.EOLSize);
        end;  

        SBMove(Ctx.OutBuf[I], OutBuffer^, 4 - I);
        Inc(PtrUInt(OutBuffer), 4 - I);

        Ctx.LineWritten := 4 - I;
      end
      else
      if Ctx.LineWritten = Ctx.LineSize then
      begin
        Ctx.LineWritten := 0;
        if (Ctx.EOLSize > 0) and ((Size > 0) or (not PreserveLastEol)) then
        begin
          SBMove(Ctx.fEOL[0], OutBuffer^, Ctx.EOLSize);
          Inc(PtrUInt(OutBuffer), Ctx.EOLSize);
        end;
      end;
    end;
  end;

  if Size > 0 then
  begin
    SBMove(Buffer^, Ctx.Tail[0], Size);
    Ctx.TailBytes := Size;
  end
  else
    if PreserveLastEol then
      Ctx.PutFirstEol := true;

  Result := true;
end;

function B64Decode(var Ctx : TSBBase64Context; Buffer : pointer; Size : integer;
  OutBuffer : pointer; var OutSize : integer) : boolean;
var
  I, EstSize, EQUCount : integer;
  BufPtr : pointer;
  C : byte;
begin
  if Size = 0 then
  begin
    Result := true;
    OutSize := 0;
    Exit;
  end;

  EQUCount := Ctx.EQUCount;
  EstSize := Ctx.TailBytes;
  BufPtr := Buffer;

  for I := 0 to Size - 1 do
  begin
    C := Base64Values[PByte(BufPtr)^];
    if C < 64 then
      Inc(EstSize)
    else
    if C = $ff then
    begin
      if not Ctx.LiberalMode then
      begin
        Result := false;
        OutSize := 0;
        Exit;
      end;
    end
    else
    if C = $fd then
    begin
      if EQUCount > 1 then
      begin
        Result := false;
        OutSize := 0;
        Exit;
      end;

      Inc(EQUCount);
    end;

    Inc(PtrUInt(BufPtr));
  end;

  EstSize := (EstSize shr 2) * 3;
  if OutSize < EstSize then
  begin
    OutSize := EstSize;
    Result := false;
    Exit;
  end;

  Ctx.EQUCount := EQUCount;
  OutSize := EstSize;

  while Size > 0 do
  begin
    C := Base64Values[PByte(Buffer)^];
    if C < 64 then
    begin
      Ctx.Tail[Ctx.TailBytes] := C;
      Inc(Ctx.TailBytes);

      if Ctx.TailBytes = 4 then
      begin
        PByte(OutBuffer)^ := (Ctx.Tail[0] shl 2) or (Ctx.Tail[1] shr 4);
        Inc(PtrUInt(OutBuffer));
        PByte(OutBuffer)^ := ((Ctx.Tail[1] and $f) shl 4) or (Ctx.Tail[2] shr 2);
        Inc(PtrUInt(OutBuffer));
        PByte(OutBuffer)^ := ((Ctx.Tail[2] and $3) shl 6) or Ctx.Tail[3];
        Inc(PtrUInt(OutBuffer));
        Ctx.TailBytes := 0;
      end;
    end;
    Inc(PtrUInt(Buffer));
    Dec(Size);
  end;
  Result := true;
end;

function B64FinalizeEncoding(var Ctx : TSBBase64Context;
  OutBuffer : pointer; var OutSize : integer) : boolean;
var
  EstSize : integer;
begin
  if Ctx.TailBytes > 0
  then
    EstSize := 4
  else
    EstSize := 0;

  if Ctx.TrailingEol then
    EstSize := EstSize + Ctx.EOLSize;

  if OutSize < EstSize then
  begin
    OutSize := EstSize;
    Result := false;
    Exit;
  end;

  OutSize := EstSize;

  if Ctx.TailBytes = 0 then
  begin
    { writing trailing EOL }
    if (Ctx.EOLSize > 0) and Ctx.TrailingEol then
    begin
      OutSize := Ctx.EOLSize;
      Result := true;
      SBMove(Ctx.fEOL[0], OutBuffer^, Ctx.EOLSize);
    end
    else
      Result := true;

    Exit;
  end;

  if Ctx.TailBytes = 1 then
  begin
    PByteArray(OutBuffer)^[0] := Base64Symbols[Ctx.Tail[0] shr 2];
    PByteArray(OutBuffer)^[1] := Base64Symbols[((Ctx.Tail[0] and 3) shl 4)];
    PByteArray(OutBuffer)^[2] := $3D; // '='
    PByteArray(OutBuffer)^[3] := $3D; // '='
  end
  else if Ctx.TailBytes = 2 then
  begin
    PByteArray(OutBuffer)^[0] := Base64Symbols[Ctx.Tail[0] shr 2];
    PByteArray(OutBuffer)^[1] := Base64Symbols[((Ctx.Tail[0] and 3) shl 4) or (Ctx.Tail[1] shr 4)];
    PByteArray(OutBuffer)^[2] := Base64Symbols[((Ctx.Tail[1] and $f) shl 2)];
    PByteArray(OutBuffer)^[3] := $3D; // '='
  end;

  if (Ctx.EOLSize > 0) and (Ctx.TrailingEol) then
    SBMove(Ctx.fEOL[0], PByteArray(OutBuffer)^[4], Ctx.EOLSize);

  Result := true;
end;

function B64FinalizeDecoding(var Ctx : TSBBase64Context;
  OutBuffer : pointer; var OutSize : integer) : boolean;
begin
  if (Ctx.EQUCount = 0) then
  begin
    OutSize := 0;
    Result := Ctx.TailBytes = 0;
    Exit;
  end
  else
  if (Ctx.EQUCount = 1) then
  begin
    if Ctx.TailBytes <> 3 then
    begin
      Result := false;
      OutSize := 0;
      Exit;
    end;

    if OutSize < 2 then
    begin
      OutSize := 2;
      Result := false;
      Exit;
    end;

    PByte(OutBuffer)^ := (Ctx.Tail[0] shl 2) or (Ctx.Tail[1] shr 4);
    Inc(PtrUInt(OutBuffer));
    PByte(OutBuffer)^ := ((Ctx.Tail[1] and $f) shl 4) or (Ctx.Tail[2] shr 2);
    OutSize := 2;
    Result := true;
  end
  else if (Ctx.EQUCount = 2) then
  begin
    if Ctx.TailBytes <> 2 then
    begin
      Result := false;
      OutSize := 0;
      Exit;
    end;

    if OutSize < 1 then
    begin
      OutSize := 1;
      Result := false;
      Exit;
    end;

    PByte(OutBuffer)^ := (Ctx.Tail[0] shl 2) or (Ctx.Tail[1] shr 4);

    OutSize := 1;
    Result := true;
  end
  else
  begin
    Result := false;
    OutSize := 0;
  end;
end;


function Base64EncodeString(const InText: string; WrapLines : boolean{$ifdef HAS_DEF_PARAMS} =  true {$endif}) : string;
var
  Size : integer;
  {$ifndef SB_ANSI_VCL}
  InBuf, OutBuf : ByteArray;
   {$endif}
begin
  {$ifdef SB_UNICODE_VCL}
  InBuf := BytesOfString(InText);
  if Length(InBuf) = 0 then
   {$else}
  if Length(InText) = 0 then
   {$endif}
  begin
    Result := '';
    Exit;
  end;

  Size := 0;

  {$ifndef SB_UNICODE_VCL}
  Base64Encode(@InText[StringStartOffset], Length(InText), nil, Size, WrapLines);
  SetLength(Result, Size);
  Base64Encode(@InText[StringStartOffset], Length(InText), @Result[StringStartOffset], Size, WrapLines);
  SetLength(Result, Size);
   {$else}
  Base64Encode(@InBuf[0], Length(InBuf), nil, Size, WrapLines);
  SetLength(OutBuf, Size);
  Base64Encode(@InBuf[0], Length(InBuf), @OutBuf[0], Size, WrapLines);
  SetLength(OutBuf, Size);
  Result := StringOfBytes(OutBuf);
   {$endif}

    {$ifndef SB_ANSI_VCL}
    ReleaseArray(InBuf);
    ReleaseArray(OutBuf);
     {$endif}
end;

function Base64EncodeArray(const InBuf: ByteArray;
  WrapLines : boolean{$ifdef HAS_DEF_PARAMS} =  true {$endif}) : string;
var
  Size : integer;
  OutBuf : ByteArray;
begin
  Result := EmptyString;
  if Length(InBuf) = 0 then
    Exit;


    Size := 0;
    SetLength(OutBuf, 0);
    Base64Encode(@InBuf[0], Length(InBuf), nil, Size, WrapLines);
    SetLength(OutBuf, Size);
    Base64Encode(@InBuf[0], Length(InBuf), @OutBuf[0], Size, WrapLines);
    SetLength(OutBuf, Size);
    Result := StringOfBytes(OutBuf);

end;

function Base64DecodeArray(const InBuf: string): ByteArray;
var
  Size: Integer;
  InBytes: ByteArray;
begin
  InBytes := EmptyArray;

  if Length(InBuf) = 0 then
    Result := EmptyArray
  else
      InBytes := BytesOfString(InBuf);
      Size := Length(InBytes);
      SetLength(Result, Size);
      Base64Decode(@InBytes[0], Size, @Result[0], Size);
      SetLength(Result, Size);
end;

function Base64DecodeString(const InText: string) : string;
{$ifndef SB_UNICODE_VCL}
var
  Size : integer;
 {$endif}
begin
  if Length(InText) = 0 then
  begin
    Result := '';
    Exit;
  end;


  {$ifndef SB_UNICODE_VCL}
  Size := 0;
  Base64Decode(@InText[StringStartOffset], Length(InText), nil, Size);
  SetLength(Result, Size);
  Base64Decode(@InText[StringStartOffset], Length(InText), @Result[StringStartOffset], Size);
  SetLength(Result, Size);
   {$else SB_UNICODE_VCL}
  Result := StringOfBytes(Base64DecodeString(BytesOfString(InText)));
   {$endif SB_UNICODE_VCL}

end;

{$ifdef SB_UNICODE_VCL}
function Base64EncodeString(const InBuf: ByteArray; WrapLines : boolean{$ifdef HAS_DEF_PARAMS}= true {$endif}) : ByteArray;
var
  Size : integer;
begin
  if Length(InBuf) = 0 then
  begin
    SetLength(Result, 0);
    Exit;
  end;

  Size := 0;
  Base64Encode(@InBuf[0], Length(InBuf), nil, Size, WrapLines);
  SetLength(Result, Size);
  Base64Encode(@InBuf[0], Length(InBuf), @Result[0], Size, WrapLines);
  SetLength(Result, Size);
end;

function Base64DecodeString(const InBuf: ByteArray) : ByteArray;
var
  Size : integer;
begin
  if Length(InBuf) = 0 then
  begin
    SetLength(Result, 0);
    Exit;
  end;

  Size := 0;
  Base64Decode(@InBuf[0], Length(InBuf), nil, Size);
  SetLength(Result, Size);
  Base64Decode(@InBuf[0], Length(InBuf), @Result[0], Size);
  SetLength(Result, Size);
end;
 {$endif}

function Base64Encode(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
  var OutSize : integer; WrapLines : boolean = true) : boolean;
var
  Ctx : TSBBase64Context;
  TmpSize : integer;
begin
  if WrapLines then
    B64InitializeEncoding(Ctx, 64, emCRLF, false)
  else
    B64InitializeEncoding(Ctx, 0, emNone, false);

  TmpSize := B64EstimateEncodedSize(Ctx, InSize);

  if (OutSize < TmpSize) then
  begin
    OutSize := TmpSize;
    Result := false;
    Exit;
  end;

  TmpSize := OutSize;
  B64Encode(Ctx, InBuffer, InSize, OutBuffer, TmpSize);
  OutSize := OutSize - TmpSize;
  B64FinalizeEncoding(Ctx, Pointer({$ifdef SB_CPU64}QWord {$else}Cardinal {$endif}(OutBuffer) + cardinal(TmpSize)), OutSize);
  OutSize := OutSize + TmpSize;

  Result := true;
end;


function Base64UnicodeDecode(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
  var OutSize : integer) : integer;
var ChS : integer;
    Buf : pointer;
    i   : integer;
    extraSyms : integer;
begin
  if (InSize and 1) = 1 then
  begin
    result := BASE64_DECODE_WRONG_DATA_SIZE;
    exit;
  end;

  extraSyms := 0;

  ChS := (InSize shr 1);
  for i := 0 to Chs - 1 do
  begin
    if (PWordArray(InBuffer)[i] = 13) or (PWordArray(InBuffer)[i] = 10) then
      inc(extraSyms);
  end;

  if OutSize < (ChS - extraSyms) * 3 shr 2 then
  begin
    Result := BASE64_DECODE_NOT_ENOUGH_SPACE;
    OutSize := (Chs - extraSyms) * 3 shr 2 + 1;
    Exit;
  end;

  GetMem(Buf, Chs);
  try
    for i := 0 to Chs - 1 do
    begin
      PByteArray(Buf)[i] := Byte(PWordArray(InBuffer)[i]);
    end;
    result := Base64Decode(Buf, Chs, OutBuffer, OutSize);
  finally
    FreeMem(Buf);
  end;
end;

function Base64Decode(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
  var OutSize : integer) : integer;
begin
  Result := Base64Decode(InBuffer, InSize, OutBuffer, OutSize, false);
end;

function Base64Decode(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
  var OutSize : integer; LiberalMode : boolean) : integer;
var
  I, TmpSize : integer;
  ExtraSyms : integer;
  Ctx : TSBBase64Context;
begin
  ExtraSyms := 0;
  for i := 0 to InSize - 1 do
    if (PByteArray(InBuffer)[i] = $0d) or (PByteArray(InBuffer)[i] = $0a) or (PByteArray(InBuffer)[i] = 0) then // some buggy software products insert 0x00 characters to BASE64 they produce
      Inc(ExtraSyms);

  if not LiberalMode then
  begin
    if ((InSize - ExtraSyms) and $3) <> 0 then
    begin
      Result := BASE64_DECODE_WRONG_DATA_SIZE;
      OutSize := 0;
      Exit;
    end;
  end;

  TmpSize := ((InSize - ExtraSyms) shr 2) * 3;
  if OutSize < TmpSize then
  begin
    Result := BASE64_DECODE_NOT_ENOUGH_SPACE;
    OutSize := TmpSize;
    Exit;
  end;

  B64InitializeDecoding(Ctx, LiberalMode);
  TmpSize := OutSize;
  if not B64Decode(Ctx, InBuffer, InSize, OutBuffer, TmpSize) then
  begin
    Result := BASE64_DECODE_INVALID_CHARACTER;
    OutSize := 0;
    Exit;
  end;
  OutSize := OutSize - TmpSize;
  if not B64FinalizeDecoding(Ctx, @PByteArray(OutBuffer)[TmpSize], OutSize) then
  begin
    Result := BASE64_DECODE_INVALID_CHARACTER;
    OutSize := 0;
    Exit;
  end;
  OutSize := OutSize + TmpSize;
  Result := BASE64_DECODE_OK;
end;

////////////////////////////////////////////////////////////////////////////////
// URLEncode functions

function URLEncode(const Data: string): string;
var
  UTF8Src : ByteArray;
  I : integer;
  B : byte;
begin
  Result := '';
  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  try
   {$endif}

  {$ifdef SB_ANSI_VCL}
  UTF8Src := BytesOfAnsiString(Data);
   {$else}
  UTF8Src := StrToUTF8(Data);
   {$endif}
  for I := 0 to Length(UTF8Src) - 1 do
  begin
    B := PByteArray(@UTF8Src[0])[I];
    if ((B >= $41) and (B <= $5A)) or ((B >= $61) and (B <= $7A)) or ((B >= $30) and (B <= $39)) or
      (B = $2D) or (B = $2E) or (B = $5F) or (B = $7E) then
      Result := Result + {$ifdef SB_UNICODE_VCL}Char {$endif} (PAnsiChar(@B)^) 
    else
      Result := Result + '%' + IntToHex(B, 2);
  end;

  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  finally
    ReleaseArray(UTF8Src);
  end;
   {$endif}
end;

function URLDecode(const Data: string): string;
var
  I : integer;
  State : byte;
  B, BV, B1 : byte;
  DataArr, UTF8Str : ByteArray;
  Tmp : ByteArray;
const
  STATE_READ_DATA = 0;
  STATE_READ_PERCENT_ENCODED_BYTE_1 = 1;
  STATE_READ_PERCENT_ENCODED_BYTE_2 = 2;
const
  HexCharsHigh : array[0..15] of byte =  ( 
    $30, $31, $32, $33,
    $34, $35, $36, $37,
    $38, $39, 65, 66,
    67, 68, 69, 70
   ) ;
begin
  B1 := 0;
  State := STATE_READ_DATA;
  UTF8Str := EmptyArray;
  DataArr := BytesOfString(Data);
  for I := 0 to Length(DataArr) - 1 do
  begin
    B := PByteArray(@DataArr[0 + I])[0];
    if State = STATE_READ_DATA then
    begin
      if B = $25 then
        State := STATE_READ_PERCENT_ENCODED_BYTE_1
      else
      begin
        Tmp := UTF8Str;
        UTF8Str := SBConcatArrays(Tmp, byte(Data[StringStartOffset + I]));
        ReleaseArray(Tmp);
      end;
    end
    else
    if (State = STATE_READ_PERCENT_ENCODED_BYTE_1) or (State = STATE_READ_PERCENT_ENCODED_BYTE_2) then
    begin
      if (B >= 65) and (B <= 70) then
        BV := B - 55
      else if (B >= 97) and (B <= 102) then
        BV := B - 87
      else if (B >= $30) and (B <= $39) then
        BV := B - $30
      else
        raise EElURLDecodeError.Create('Unexpected character: 0x' + IntToHex(B, 2));
      if State = STATE_READ_PERCENT_ENCODED_BYTE_1 then
      begin
        B1 := BV;
        State := STATE_READ_PERCENT_ENCODED_BYTE_2;
      end
      else
      begin
        B := (B1 shl 4) or BV;

        Tmp := UTF8Str;
        UTF8Str := SBConcatArrays(Tmp, b);
        ReleaseArray(Tmp);

        State := STATE_READ_DATA;
      end;
    end;
  end;
  {$ifndef SB_ANSI_VCL}
  Result := UTF8ToStr(UTF8Str);
   {$else}
  Result := AnsiStringOfBytes(UTF8Str);
   {$endif}

  ReleaseArray(UTF8Str);
  ReleaseArray(DataArr);
end;

function GetHexNum(C: char): integer;
const
  LowerAlphabet : string = '0123456789abcdef';
  UpperAlphabet : string = '0123456789ABCDEF';
var
  I : integer;
begin
  Result := 0;
  for I := StringStartOffset to 15 + StringStartOffset do
    if (C = LowerAlphabet[I]) or (C = UpperAlphabet[I]) then
    begin
      Result := I - StringStartOffset;
      Break;
    end;
end;

function Base16DecodeString(const Data: string): ByteArray;
var
//  Hex : string;
  Idx, OutIdx : integer;
begin
  SetLength(Result, Length(Data) shr 1);
  OutIdx := 0;
  Idx := StringStartOffset;
  while Idx < Length(Data)- StringStartInvOffset do
  begin
    Result[OutIdx] := byte(GetHexNum(Data[Idx]) shl 4) or GetHexNum(Data[Idx + 1]);
    Inc(Idx, 2);
    Inc(OutIdx);
  end;
end;

end.
