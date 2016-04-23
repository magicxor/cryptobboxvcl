(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBHTTPSConstants;

interface

uses
  SBTypes,
  SBConstants,
  SBUtils;

  
type

  // TODO: in 9.0 move to SBHTTPSCommon
  TSBHTTPVersion =   (hvHTTP10, hvHTTP11);

  TSBHTTPChunkState = 
    (chSize, chLineFeed, chData, chHeader);

const
  SB_HTTP_REQUEST_CUSTOM = 0;

  SB_HTTP_REQUEST_FIRST = 1;
  SB_HTTP_REQUEST_GET = 1;
  SB_HTTP_REQUEST_POST = 2;
  SB_HTTP_REQUEST_HEAD = 3;
  SB_HTTP_REQUEST_OPTIONS = 4;
  SB_HTTP_REQUEST_DELETE = 5;
  SB_HTTP_REQUEST_TRACE = 6;
  SB_HTTP_REQUEST_PUT = 7;
  SB_HTTP_REQUEST_CONNECT = 8;
  SB_HTTP_REQUEST_LAST = 8;

const
  HTTPVersionStrings : array[ TSBHTTPVersion ] of string =
   ( 
  'HTTP/1.0', 'HTTP/1.1'
   ) ;

  HTTPCommandStrings: array[SB_HTTP_REQUEST_FIRST .. SB_HTTP_REQUEST_LAST] of string =
   ( 
  'GET', 'POST', 'HEAD', 'OPTIONS', 'DELETE', 'TRACE', 'PUT', 'CONNECT'
   ) ;

  WkDays:  array[1..7] of string =
   ( 
    'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'
   ) ;

  WeekDays:  array[1..7] of string =
   ( 
    'Monday', 'Tuesday', 'Wednesday', 'Thursday',
    'Friday', 'Saturday', 'Sunday'
   ) ;

  Months:  array[1..12] of string =
   ( 
    'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul',
    'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
   ) ;

{$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
 {$else}
var
 {$endif}

  HTTP10ByteArray : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = 'HTTP/1.0' {$endif}; 
  HTTP11ByteArray : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = 'HTTP/1.1' {$endif}; 

resourcestring

  SInvalidDateTime = 'Invalid date/time parameter';


implementation

initialization

  {$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
  HTTP10ByteArray := BytesOfString('HTTP/1.0');
  HTTP11ByteArray := BytesOfString('HTTP/1.1');
  (*
  HTTPCommandStrings[SB_HTTP_REQUEST_GET] := BytesOfString('GET');
  HTTPCommandStrings[SB_HTTP_REQUEST_POST] := BytesOfString('POST');
  HTTPCommandStrings[SB_HTTP_REQUEST_HEAD] := BytesOfString('HEAD');
  HTTPCommandStrings[SB_HTTP_REQUEST_OPTIONS] := BytesOfString('OPTIONS');
  HTTPCommandStrings[SB_HTTP_REQUEST_DELETE] := BytesOfString('DELETE');
  HTTPCommandStrings[SB_HTTP_REQUEST_TRACE] := BytesOfString('TRACE');
  HTTPCommandStrings[SB_HTTP_REQUEST_PUT] := BytesOfString('PUT');
  HTTPCommandStrings[SB_HTTP_REQUEST_CONNECT] := BytesOfString('CONNECT');
  *)
   {$endif}

end.
