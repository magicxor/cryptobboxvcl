(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBGSSAPIBase;

interface

{$ifdef SB_GSSAPI}

uses
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBConstants;

const
  // Flag bits for context-level services.
  GSS_C_DELEG_FLAG      = 1;
  GSS_C_MUTUAL_FLAG     = 2;
  GSS_C_REPLAY_FLAG     = 4;
  GSS_C_SEQUENCE_FLAG   = 8;
  GSS_C_CONF_FLAG       = 16;
  GSS_C_INTEG_FLAG      = 32;
  GSS_C_ANON_FLAG       = 64;
  GSS_C_PROT_READY_FLAG = 128;
  GSS_C_TRANS_FLAG      = 256;

  // Credential usage options
  GSS_C_BOTH      = 0;
  GSS_C_INITIATE  = 1;
  GSS_C_ACCEPT    = 2;

  // Status code types for gss_display_status
  GSS_C_GSS_CODE  = 1;
  GSS_C_MECH_CODE = 2;

  // Define the default Quality of Protection for per-message services.
  GSS_C_QOP_DEFAULT = 0;

  // Expiration time of 2^32-1 seconds means infinite lifetime for a credential or security context
  GSS_C_INDEFINITE = LongWord(-1); // 0xFFFFFFFF

  // The constant definitions for channel-bindings address families
  GSS_C_AF_UNSPEC     = 0;
  GSS_C_AF_LOCAL      = 1;
  GSS_C_AF_INET       = 2;
  GSS_C_AF_IMPLINK    = 3;
  GSS_C_AF_PUP        = 4;
  GSS_C_AF_CHAOS      = 5;
  GSS_C_AF_NS         = 6;
  GSS_C_AF_NBS        = 7;
  GSS_C_AF_ECMA       = 8;
  GSS_C_AF_DATAKIT    = 9;
  GSS_C_AF_CCITT      = 10;
  GSS_C_AF_SNA        = 11;
  GSS_C_AF_DECnet     = 12;
  GSS_C_AF_DLI        = 13;
  GSS_C_AF_LAT        = 14;
  GSS_C_AF_HYLINK     = 15;
  GSS_C_AF_APPLETALK  = 16;
  GSS_C_AF_BSC        = 17;
  GSS_C_AF_DSS        = 18;
  GSS_C_AF_OSI        = 19;
  GSS_C_AF_X25        = 21;
  GSS_C_AF_NULLADDR   = 255;

  // Major status codes

  //    MSB                                                        LSB
  //    |------------------------------------------------------------|
  //    | Calling Error | Routine Error  |    Supplementary Info     |
  //    |------------------------------------------------------------|
  // Bit 31           24 23            16 15                        0

  GSS_C_CALLING_ERROR_OFFSET = 24;
  GSS_C_ROUTINE_ERROR_OFFSET = 16;
  GSS_C_SUPPLEMENTARY_OFFSET = 0;
  GSS_C_CALLING_ERROR_MASK   = LongWord($FF);
  GSS_C_ROUTINE_ERROR_MASK   = LongWord($FF);
  GSS_C_SUPPLEMENTARY_MASK   = LongWord($FFFF);

  GSS_S_COMPLETE = LongWord(0);           // normal completion

  // Routine Errors
  GSS_S_BAD_MECH = LongWord(1 shl GSS_C_ROUTINE_ERROR_OFFSET);              // unsupported mechanism requested
  GSS_S_BAD_NAME = LongWord(2 shl GSS_C_ROUTINE_ERROR_OFFSET);              // invalid name provided
  GSS_S_BAD_NAMETYPE = LongWord(3 shl GSS_C_ROUTINE_ERROR_OFFSET);          // name of unsupported type provided
  GSS_S_BAD_BINDINGS = LongWord(4 shl GSS_C_ROUTINE_ERROR_OFFSET);          // channel binding mismatch
  GSS_S_BAD_STATUS = LongWord(5 shl GSS_C_ROUTINE_ERROR_OFFSET);            // invalid input status selector
  GSS_S_BAD_SIG = LongWord(6 shl GSS_C_ROUTINE_ERROR_OFFSET);               // token had invalid integrity check
  GSS_S_NO_CRED = LongWord(7 shl GSS_C_ROUTINE_ERROR_OFFSET);               // no valid credentials provided
  GSS_S_NO_CONTEXT = LongWord(8 shl GSS_C_ROUTINE_ERROR_OFFSET);            // no valid security context specified
  GSS_S_DEFECTIVE_TOKEN = LongWord(9 shl GSS_C_ROUTINE_ERROR_OFFSET);       // defective token detected
  GSS_S_DEFECTIVE_CREDENTIAL = LongWord(10 shl GSS_C_ROUTINE_ERROR_OFFSET); // defective credential detected
  GSS_S_CREDENTIALS_EXPIRED = LongWord(11 shl GSS_C_ROUTINE_ERROR_OFFSET);  // expired credentials detected
  GSS_S_CONTEXT_EXPIRED = LongWord(12 shl GSS_C_ROUTINE_ERROR_OFFSET);      // specified security context expired
  GSS_S_FAILURE = LongWord(13 shl GSS_C_ROUTINE_ERROR_OFFSET);              // failure, unspecified at GSS-API level
  GSS_S_BAD_QOP = LongWord(14 shl GSS_C_ROUTINE_ERROR_OFFSET);              // unsupported QOP value
  GSS_S_UNAUTHORIZED = LongWord(15 shl GSS_C_ROUTINE_ERROR_OFFSET);         // operation unauthorized
  GSS_S_UNAVAILABLE = LongWord(16 shl GSS_C_ROUTINE_ERROR_OFFSET);          // operation unavailable
  GSS_S_DUPLICATE_ELEMENT = LongWord(17 shl GSS_C_ROUTINE_ERROR_OFFSET);    // duplicate credential element requested
  GSS_S_NAME_NOT_MN = LongWord(18 shl GSS_C_ROUTINE_ERROR_OFFSET);          // name contains multi-mechanism elements
  GSS_S_BAD_MIC = GSS_S_BAD_SIG;                                            // preferred alias for GSS_S_BAD_SIG
  GSS_S_CRED_UNAVAIL = GSS_S_FAILURE;

  // Supplementary Status Bits
  GSS_S_CONTINUE_NEEDED = LongWord(1 shl GSS_C_SUPPLEMENTARY_OFFSET);       // continuation call to routine required
  GSS_S_DUPLICATE_TOKEN = LongWord(1 shl (GSS_C_SUPPLEMENTARY_OFFSET + 1)); // duplicate per-message token detected
  GSS_S_OLD_TOKEN       = LongWord(1 shl (GSS_C_SUPPLEMENTARY_OFFSET + 2)); // timed-out per-message token detected
  GSS_S_UNSEQ_TOKEN     = LongWord(1 shl (GSS_C_SUPPLEMENTARY_OFFSET + 3)); // reordered (early) per-message token detected
  GSS_S_GAP_TOKEN       = LongWord(1 shl (GSS_C_SUPPLEMENTARY_OFFSET + 4)); // skipped predecessor token(s) detected

  // Calling Errors
  GSS_S_CALL_INACCESSIBLE_READ  = LongWord(1 shl GSS_C_CALLING_ERROR_OFFSET); // A required input parameter could not be read.
  GSS_S_CALL_INACCESSIBLE_WRITE = LongWord(2 shl GSS_C_CALLING_ERROR_OFFSET); // A required output parameter could not be written.
  GSS_S_CALL_BAD_STRUCTURE      = LongWord(3 shl GSS_C_CALLING_ERROR_OFFSET); // A parameter was malformed

function GSS_CALLING_ERROR(x: LongWord): LongWord; 
function GSS_ROUTINE_ERROR(x: LongWord): LongWord; 
function GSS_SUPPLEMENTARY_INFO(x: LongWord): LongWord; 
function GSS_ERROR(x: LongWord): LongWord; 

function DecodeMechOID(OID: ByteArray): ByteArray; 
function EncodeMechOID(OID: ByteArray): ByteArray; 

 {$endif SB_GSSAPI}

implementation

{$ifdef SB_GSSAPI}

function GSS_CALLING_ERROR(x: LongWord): LongWord;
begin
  Result := x and (GSS_C_CALLING_ERROR_MASK shl GSS_C_CALLING_ERROR_OFFSET);
end;

function GSS_ROUTINE_ERROR(x: LongWord): LongWord;
begin
  Result := x and (GSS_C_ROUTINE_ERROR_MASK shl GSS_C_ROUTINE_ERROR_OFFSET);
end;

function GSS_SUPPLEMENTARY_INFO(x: LongWord): LongWord;
begin
  Result := x and (GSS_C_SUPPLEMENTARY_MASK shl GSS_C_SUPPLEMENTARY_OFFSET);
end;

function GSS_ERROR(x: LongWord): LongWord;
begin
  Result := x and ((GSS_C_CALLING_ERROR_MASK shl GSS_C_CALLING_ERROR_OFFSET) or (GSS_C_ROUTINE_ERROR_MASK shl GSS_C_ROUTINE_ERROR_OFFSET));
end;

function DecodeMechOID(OID: ByteArray): ByteArray;
begin
  if (Length(OID) < 2) or (OID[0] <> byte(6)) or
     ( Ord (OID[0 + 1]) > Length(OID) + 2) then
    Result := EmptyArray
  else
    Result := Copy(OID, 0 + 2,  Ord (OID[0 + 1]));
end;

function EncodeMechOID(OID: ByteArray): ByteArray;
begin
  Result := SBConcatArrays(byte(6), byte(Length(OID)), OID);
  (*
  {$ifndef SB_NET}
  Result := AnsiChar(#6) + AnsiChar(Length(OID)) + OID;
  {$else}
  SetLength(Result, Length(OID) + 2);
  Result[0] := 6;
  Result[1] := Length(OID);
  SBMove(OID, 0, Result, 2, Length(OID));
  {$endif}
  *)
end;

 {$endif SB_GSSAPI}

end.
