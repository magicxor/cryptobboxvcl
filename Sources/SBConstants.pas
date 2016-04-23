(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBConstants;

interface

uses
  SBTypes;


const
  EncArr : array[0..63] of char
    = ( 
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
    'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1',
    '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
   ) ;

  CRLFStr = #13#10;
  CRStr = #13;
  LFStr = #10;
  LFLFStr = #10#10;
  CRLFCRLFStr = #13#10#13#10;
  CRLFCRLFZeroStr = #13#10#13#10#0;
  CRLFTABStr = #13#10#9;
  CRLFSPACEStr = #13#10#32;
  TwoDashesStr = '--';
  SpaceStr = ' ';
  EqualCharStr = '=';

  TabByte = 9;
  CRByte = 13;
  LFByte = 10;
  SpaceByte = $20;
  DoubleQuoteByte = $22;
  ColonByte = $3a;
  BackslashByte = $5c;
  
  HexChars : array[0..15] of Char =  ( 
                '0', '1', '2', '3',
                '4', '5', '6', '7',
                '8', '9', 'A', 'B',
                'C', 'D', 'E', 'F'
       ) ;

  BooleanStrings : array[false..true] of string =  ( 
                'false', 'true'
       ) ;

  SecondsInDay = 86400; {Number of seconds in a day}
  SecondsInHour = 3600; {Number of seconds in an hour}
  SecondsInMinute = 60; {Number of seconds in a minute}
  HoursInDay = 24; {Number of hours in a day}
  MinutesInHour = 60; {Number of minutes in an hour}
  MinutesInDay = 1440; {Number of minutes in a day}

  AnsiStrStartOffset = 1;
  AnsiStrStartInvOffset = 0;
  StringStartOffset = 1;
  StringStartInvOffset = 0;


    {$ifdef LINUX}
    cSBPathSeparator = '/';
     {$else}
    cSBPathSeparator = '\';
     {$endif}

const
  SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION     = Integer($0000);
  SB_CERT_ALGORITHM_MD2_RSA_ENCRYPTION    = Integer($0001);
  SB_CERT_ALGORITHM_MD5_RSA_ENCRYPTION    = Integer($0002);
  SB_CERT_ALGORITHM_SHA1_RSA_ENCRYPTION   = Integer($0003);
  SB_CERT_ALGORITHM_ID_DSA                = Integer($0004);
  SB_CERT_ALGORITHM_ID_DSA_SHA1           = Integer($0005);
  SB_CERT_ALGORITHM_DH_PUBLIC             = Integer($0006);
  SB_CERT_ALGORITHM_SHA224_RSA_ENCRYPTION = Integer($0007);
  SB_CERT_ALGORITHM_SHA256_RSA_ENCRYPTION = Integer($0008);
  SB_CERT_ALGORITHM_SHA384_RSA_ENCRYPTION = Integer($0009);
  SB_CERT_ALGORITHM_SHA512_RSA_ENCRYPTION = Integer($000A);
  SB_CERT_ALGORITHM_ID_RSAPSS             = Integer($000B);
  SB_CERT_ALGORITHM_ID_RSAOAEP            = Integer($000C);
  SB_CERT_ALGORITHM_RSASIGNATURE_RIPEMD160= Integer($000D);
  SB_CERT_ALGORITHM_ID_ELGAMAL            = Integer($000E);
  SB_CERT_ALGORITHM_SHA1_ECDSA            = Integer($000F);
  SB_CERT_ALGORITHM_RECOMMENDED_ECDSA     = Integer($0010);
  SB_CERT_ALGORITHM_SHA224_ECDSA          = Integer($0011);
  SB_CERT_ALGORITHM_SHA256_ECDSA          = Integer($0012);
  SB_CERT_ALGORITHM_SHA384_ECDSA          = Integer($0013);
  SB_CERT_ALGORITHM_SHA512_ECDSA          = Integer($0014);
  SB_CERT_ALGORITHM_EC                    = Integer($0015);
  SB_CERT_ALGORITHM_SPECIFIED_ECDSA       = Integer($0016);
  SB_CERT_ALGORITHM_GOST_R3410_1994       = Integer($0017);
  SB_CERT_ALGORITHM_GOST_R3410_2001       = Integer($0018);
  SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_1994 = Integer($0019);
  SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_2001 = Integer($001A);
  SB_CERT_ALGORITHM_SHA1_ECDSA_PLAIN      = Integer($001B);
  SB_CERT_ALGORITHM_SHA224_ECDSA_PLAIN    = Integer($001C);
  SB_CERT_ALGORITHM_SHA256_ECDSA_PLAIN    = Integer($001D);
  SB_CERT_ALGORITHM_SHA384_ECDSA_PLAIN    = Integer($001E);
  SB_CERT_ALGORITHM_SHA512_ECDSA_PLAIN    = Integer($001F);
  SB_CERT_ALGORITHM_RIPEMD160_ECDSA_PLAIN = Integer($0020);
  SB_CERT_ALGORITHM_WHIRLPOOL_RSA_ENCRYPTION = Integer($0021);

  SB_CERT_MGF1                            = Integer($0201);
  SB_CERT_MGF1_SHA1                       = Integer($0202);
  SB_CERT_MGF1_SHA224                     = Integer($0203);
  SB_CERT_MGF1_SHA256                     = Integer($0204);
  SB_CERT_MGF1_SHA384                     = Integer($0205);
  SB_CERT_MGF1_SHA512                     = Integer($0206);
  SB_CERT_MGF1_RIPEMD160                  = Integer($0207);
  SB_CERT_MGF1_WHIRLPOOL                  = Integer($0208);

  SB_CERT_ALGORITHM_UNKNOWN               = Integer($0000FFFF);

type
  TByteArrayConst = ByteArray;


  { Algorithms and OIDs }

{$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
 {$else}
var
 {$endif}

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS OFF}
 {$endif}

  //PKCS#1
  // Encryption Algorithm OIDs
  SB_OID_RC4                : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$03#$04 {$endif}; 
  SB_OID_RSAENCRYPTION      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$01 {$endif}; 
  SB_OID_EA_RSA             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$08#$01#$01 {$endif}; 
  SB_OID_RSAPSS             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$0A {$endif}; 
  SB_OID_RSAOAEP            : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$07 {$endif}; 
  SB_OID_DSA                : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$CE#$38#$04#$01 {$endif}; 
  SB_OID_DSA_SHA1           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$CE#$38#$04#$03 {$endif}; 
  SB_OID_DSA_SHA224         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$60#$86#$48#$01#$65#$03#$04#$03#$01 {$endif}; 
  SB_OID_DSA_SHA256         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$60#$86#$48#$01#$65#$03#$04#$03#$02 {$endif}; 
  SB_OID_DSA_ALT            : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$0E#$03#$02#$0C {$endif}; 
  SB_OID_DSA_SHA1_ALT       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$0E#$03#$02#$0D {$endif}; 
  SB_OID_DH                 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$CE#$3E#$02#$01 {$endif}; 
  SB_OID_DES_EDE3_CBC       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$03#$07 {$endif}; 
  SB_OID_PKCS7_DATA         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$07#$01 {$endif}; 
  SB_OID_RC2_CBC            : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$03#$02 {$endif}; 
  SB_OID_DES_CBC            : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$0e#$03#$02#$07 {$endif}; 
  SB_OID_SHA1_RSAENCRYPTION : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$05 {$endif}; 
  SB_OID_SHA1_RSAENCRYPTION2 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$0E#$03#$02#$1D {$endif}; 
  SB_OID_SHA224_RSAENCRYPTION : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$0E {$endif}; 
  SB_OID_SHA256_RSAENCRYPTION : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$0B {$endif}; 
  SB_OID_SHA384_RSAENCRYPTION : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$0C {$endif}; 
  SB_OID_SHA512_RSAENCRYPTION : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$0D {$endif}; 
  SB_OID_RSASIGNATURE_RIPEMD160 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$24#$03#$03#$01#$02 {$endif}; 
  SB_OID_TSTINFO          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$09#$10#$01#$04 {$endif}; 
  SB_OID_AES128_CBC         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$60#$86#$48#$01#$65#$03#$04#$01#$02 {$endif}; 
  SB_OID_AES192_CBC         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$60#$86#$48#$01#$65#$03#$04#$01#$16 {$endif}; 
  SB_OID_AES256_CBC         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$60#$86#$48#$01#$65#$03#$04#$01#$2A {$endif}; 
  SB_OID_SERPENT128_CBC     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$DA#$47#$0D#$02#$02 {$endif}; 
  SB_OID_SERPENT192_CBC     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$DA#$47#$0D#$02#$16 {$endif}; 
  SB_OID_SERPENT256_CBC     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$DA#$47#$0D#$02#$2A {$endif}; 
  SB_OID_CAST5_CBC          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F6#$7D#$07#$42#$0A {$endif}; 
  SB_OID_BLOWFISH_CBC       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$97#$55#$01#$01#$02 {$endif}; 
  SB_OID_CAMELLIA128_CBC    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$83#$08#$8C#$9A#$4B#$3D#$01#$01#$01#$02 {$endif}; 
  SB_OID_CAMELLIA192_CBC    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$83#$08#$8C#$9A#$4B#$3D#$01#$01#$01#$03 {$endif}; 
  SB_OID_CAMELLIA256_CBC    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$83#$08#$8C#$9A#$4B#$3D#$01#$01#$01#$04 {$endif}; 
  SB_OID_SEED               : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$83#$1A#$8C#$9A#$44#$01#$04#$05#$00 {$endif}; 
  SB_OID_RABBIT             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$00 {$endif}; 
  SB_OID_IDENTITY           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'identity@eldos.com' {$endif};  // special fake OID value
  SB_OID_IDENTITY_ELDOS     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$90#$22#$02#$03#$01 {$endif}; 
  SB_OID_TWOFISH128_ELDOS   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$90#$22#$02#$03#$05 {$endif}; 
  SB_OID_TWOFISH256_ELDOS   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$90#$22#$02#$03#$06 {$endif}; 
  SB_OID_TWOFISH192_ELDOS   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$90#$22#$02#$03#$07 {$endif}; 
  // ISO 9796
  SB_OID_RSASIGNATURE_RIPEMD160_ISO9796 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$24#$03#$04#$03#$02#$02 {$endif}; 
  SB_OID_WHIRLPOOL_RSAENCRYPTION_ELDOS : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$90#$22#$02#$02#$01 {$endif}; 

  //mask generation function
  SB_OID_MGF1               : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$08 {$endif}; 

  SB_OID_MGF1_SHA1               : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'mgf1-sha1@eldos.com' {$endif}; 
  SB_OID_MGF1_SHA224             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'mgf1-sha224@eldos.com' {$endif}; 
  SB_OID_MGF1_SHA256             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'mgf1-sha256@eldos.com' {$endif}; 
  SB_OID_MGF1_SHA384             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'mgf1-sha384@eldos.com' {$endif}; 
  SB_OID_MGF1_SHA512             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'mgf1-sha512@eldos.com' {$endif}; 
  SB_OID_MGF1_RIPEMD160          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'mgf1-ripemd160@eldos.com' {$endif}; 
  SB_OID_MGF1_WHIRLPOOL          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'mgf1-whirlpool@eldos.com' {$endif}; 

  //label source function for RSA-OAEP
  SB_OID_OAEP_SRC_SPECIFIED : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$09 {$endif}; 
  //PKCS#5 password-based encryption
  SB_OID_PBE_MD2_DES        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$05#$01 {$endif}; 
  SB_OID_PBE_MD2_RC2        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$05#$04 {$endif}; 
  SB_OID_PBE_MD5_DES        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$05#$03 {$endif}; 
  SB_OID_PBE_MD5_RC2        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$05#$03 {$endif}; 
  SB_OID_PBE_SHA1_DES       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$05#$0A {$endif}; 
  SB_OID_PBE_SHA1_RC2       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$05#$0B {$endif}; 
  SB_OID_PBES2              : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$05#$0D {$endif}; 
  SB_OID_PBKDF2             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$05#$0C {$endif}; 
  SB_OID_PBMAC1             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$05#$0E {$endif}; 

  //PKCS#12
  SB_OID_PBE_SHA1_RC4_128   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$0c#$01#$01 {$endif}; 
  SB_OID_PBE_SHA1_RC4_40    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$0c#$01#$02 {$endif}; 
  SB_OID_PBE_SHA1_3DES      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$0c#$01#$03 {$endif}; 
  SB_OID_PBE_SHA1_RC2_128   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$0c#$01#$05 {$endif}; 
  SB_OID_PBE_SHA1_RC2_40    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$0c#$01#$06 {$endif}; 
  SB_OID_MD2_RSAENCRYPTION  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$02 {$endif}; 
  SB_OID_MD4_RSAENCRYPTION  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$03 {$endif}; 
  SB_OID_MD5_RSAENCRYPTION  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$04 {$endif}; 
  SB_OID_SHA1_RSA           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$0E#$03#$02#$1D {$endif}; 
  SB_OID_SHA1_DSA           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$CE#$38#$04#$03 {$endif}; 

  // PKCS#15
  SB_OID_PKCS15             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$0F#$03#$01 {$endif}; 
  SB_OID_PWRI_KEK           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$03#$09 {$endif}; 
  SB_OID_DATA               : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$07#$01 {$endif}; 

  // Digest Algorithm OIDs
  SB_OID_MD2                : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$02#$02 {$endif}; 
  SB_OID_MD4                : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$02#$04 {$endif}; 
  SB_OID_MD5                : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$02#$05 {$endif}; 
  SB_OID_SHA1               : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$0E#$03#$02#$1A {$endif}; 
  SB_OID_SHA224             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$60#$86#$48#$01#$65#$03#$04#$02#$04 {$endif}; 
  SB_OID_SHA256             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$60#$86#$48#$01#$65#$03#$04#$02#$01 {$endif}; 
  SB_OID_SHA384             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$60#$86#$48#$01#$65#$03#$04#$02#$02 {$endif}; 
  SB_OID_SHA512             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$60#$86#$48#$01#$65#$03#$04#$02#$03 {$endif}; 
  SB_OID_RIPEMD160          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$24#$03#$02#$01 {$endif}; 
  SB_OID_SSL3               : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ssl-hash@eldos.com' {$endif}; 
  SB_OID_WHIRLPOOL          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$28#$CF#$06#$03#$00#$37 {$endif}; 

  // MAC Algorithm OIDs
  SB_OID_HMACSHA1           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$08#$01#$02 {$endif}; 
  SB_OID_HMACSHA1_PKCS      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$02#$07 {$endif}; 
  SB_OID_HMACSHA224         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$08#$01#$08 {$endif}; 
  SB_OID_HMACSHA256         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$08#$01#$09 {$endif}; 
  SB_OID_HMACSHA384         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$08#$01#$0A {$endif}; 
  SB_OID_HMACSHA512         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$08#$01#$0B {$endif}; 
  SB_OID_RSA_HMACSHA1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$F7#$0D#$02#$07 {$endif};  // a copy of SB_OID_HMACSHA1_PKCS

  // UMAC
  SB_OID_UMAC32             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'umac32@eldos.com' {$endif}; 
  SB_OID_UMAC64             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'umac64@eldos.com' {$endif}; 
  SB_OID_UMAC96             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'umac96@eldos.com' {$endif}; 
  SB_OID_UMAC128            : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'umac128@eldos.com' {$endif}; 

  // Attribute OIDs
  SB_OID_CONTENT_TYPE       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$03 {$endif}; 
  SB_OID_MESSAGE_DIGEST     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$04 {$endif}; 
  SB_OID_SIGNING_TIME       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$05 {$endif}; 
  SB_OID_COUNTER_SIGNATURE  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$06 {$endif}; 
  SB_OID_SMIME_CAPABILITIES : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$0F {$endif}; 
  SB_OID_TIMESTAMP_TOKEN    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$0E {$endif}; 
  SB_OID_SIGNING_CERTIFICATE: TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$0C {$endif}; 
  SB_OID_SIGNING_CERTIFICATEV2: TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$2F {$endif}; 
  SB_OID_CONTENT_HINTS      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$04 {$endif}; 
  SB_OID_CONTENT_IDENTIFIER : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$07 {$endif}; 
  SB_OID_CONTENT_REFERENCE  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$0A {$endif}; 
  SB_OID_SIGNATURE_POLICY   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$0F {$endif}; 
  SB_OID_COMMITMENT_TYPE    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$10 {$endif}; 
  SB_OID_SIGNER_LOCATION    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$11 {$endif}; 
  SB_OID_SIGNER_ATTRIBUTES  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$12 {$endif}; 
  SB_OID_CONTENT_TIMESTAMP  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$14 {$endif}; 
  SB_OID_CERTIFICATE_REFS   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$15 {$endif}; 
  SB_OID_REVOCATION_REFS    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$16 {$endif}; 
  SB_OID_CERTIFICATE_VALUES : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$17 {$endif}; 
  SB_OID_REVOCATION_VALUES  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$18 {$endif}; 
  SB_OID_ESCTIMESTAMP       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$19 {$endif}; 
  SB_OID_CERTCRLTIMESTAMP   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$1A {$endif}; 
  SB_OID_ARCHIVETIMESTAMP   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$1B {$endif}; 
  SB_OID_ARCHIVETIMESTAMP2  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$30 {$endif}; 
  SB_OID_ARCHIVETIMESTAMP3  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$04#$00#$8D#$45#$02#$04 {$endif}; 
  SB_OID_ATSHASHINDEX       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$04#$00#$8D#$45#$02#$05 {$endif}; 

  // Authenticode OIDs
  SB_OID_SPC_INDIRECT_DATA  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$04 {$endif}; 
  SB_OID_SPC_SP_AGENCY_INFO : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$0A {$endif}; 
  SB_OID_SPC_STATEMENT_TYPE_OBJID : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$0A {$endif}; 
  SB_OID_SPC_STATEMENT_TYPE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$0B {$endif}; 
  SB_OID_SPC_SP_OPUS_INFO   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$0C {$endif}; 
  SB_OID_SPC_PE_IMAGE_DATA  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$0F {$endif}; 
  SB_OID_SPC_MINIMAL_CRITERIA: TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$1A {$endif}; 
  SB_OID_SPC_FINANCIAL_CRITERIA: TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$1B {$endif}; 
  SB_OID_SPC_LINK           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$1C {$endif}; 
  SB_OID_SPC_HASH_INFO      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$1D {$endif}; 
  SB_OID_SPC_SIPINFO        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$1E {$endif}; 
  SB_OID_SPC_CERT_EXTENSIONS: TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$0E {$endif}; 
  SB_OID_SPC_RAW_FILE_DATA  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$12 {$endif}; 
  SB_OID_SPC_STRUCTURED_STORAGE_DATA: TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$13 {$endif}; 
  SB_OID_SPC_JAVA_CLASS_DATA: TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$14 {$endif}; 
  SB_OID_SPC_INDIVIDUAL_SP_KEY_PURPOSE: TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$15 {$endif}; 
  SB_OID_SPC_COMMERCIAL_SP_KEY_PURPOSE: TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$16 {$endif}; 
  SB_OID_SPC_CAB_DATA       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$19 {$endif}; 
  // certificate extension OIDs
  SB_OID_QT_CPS             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$02#$01 {$endif}; 
  SB_OID_QT_UNOTICE         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$02#$02 {$endif}; 
  SB_OID_SERVER_AUTH        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$03#$01 {$endif}; 
  SB_OID_CLIENT_AUTH        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$03#$02 {$endif}; 
  SB_OID_CODE_SIGNING       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$03#$03 {$endif}; 
  SB_OID_EMAIL_PROT         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$03#$04 {$endif}; 
  SB_OID_TIME_STAMPING      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$03#$08 {$endif}; 
  SB_OID_OCSP_SIGNING       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$03#$09 {$endif}; 

  SB_OID_ACCESS_METHOD_OCSP : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$30#$01 {$endif}; 
  SB_OID_ACCESS_METHOD_CAISSUER : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$30#$02 {$endif}; 

  SB_OID_UNSTRUCTURED_NAME  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$02 {$endif}; 

  SB_OID_CERT_EXTENSIONS    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$09#$0e {$endif}; 
  SB_OID_CERT_EXTENSIONS_MS : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$06#$01#$04#$01#$82#$37#$02#$01#$0e {$endif}; 

  // GOST algorithms
  SB_OID_GOST_28147_1989           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$15 {$endif}; 
  SB_OID_GOST_28147_1989_MAC       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$16 {$endif}; 
  SB_OID_GOST_R3410_2001           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$13 {$endif}; 
  SB_OID_GOST_R3410_1994           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$14 {$endif}; 
  SB_OID_GOST_R3410_1994_DH        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$63 {$endif}; 
  SB_OID_GOST_R3411_1994_WITH_GOST_R3410_2001 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$03 {$endif}; 
  SB_OID_GOST_R3411_1994_WITH_GOST_R3410_1994 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$04 {$endif}; 
  SB_OID_GOST_R3411_1994           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$09 {$endif}; 
  SB_OID_GOST_R3411_1994_HMAC      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$0A {$endif}; 

  // GOST algorithm parameters
  // CryptoPro RFC 4357 GOST 28147-89 parameters
  SB_OID_GOST_28147_1989_PARAM_CP_TEST  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$1F#$00 {$endif}; 
  SB_OID_GOST_28147_1989_PARAM_CP_A     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$1F#$01 {$endif}; 
  SB_OID_GOST_28147_1989_PARAM_CP_B     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$1F#$02 {$endif}; 
  SB_OID_GOST_28147_1989_PARAM_CP_C     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$1F#$03 {$endif}; 
  SB_OID_GOST_28147_1989_PARAM_CP_D     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$1F#$04 {$endif}; 
  SB_OID_GOST_28147_1989_PARAM_CP_OSCAR_11 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$1F#$05 {$endif}; 
  SB_OID_GOST_28147_1989_PARAM_CP_OSCAR_10 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$1F#$06 {$endif}; 
  SB_OID_GOST_28147_1989_PARAM_CP_RIC_1 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$1F#$07 {$endif}; 
  // CryptoPro RFC 4357 GOST R 34.11-94 parameters
  SB_OID_GOST_R3411_1994_PARAM_CP_TEST  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$1E#$00 {$endif}; 
  SB_OID_GOST_R3411_1994_PARAM_CP       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$1E#$01 {$endif}; 
  // CryptoPro RFC 4357 GOST R 34.10-94 parameters
  SB_OID_GOST_R3410_1994_PARAM_CP_TEST  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$20#$00 {$endif}; 
  SB_OID_GOST_R3410_1994_PARAM_CP_A     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$20#$02 {$endif}; 
  SB_OID_GOST_R3410_1994_PARAM_CP_B     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$20#$03 {$endif}; 
  SB_OID_GOST_R3410_1994_PARAM_CP_C     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$20#$04 {$endif}; 
  SB_OID_GOST_R3410_1994_PARAM_CP_D     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$20#$05 {$endif}; 
  SB_OID_GOST_R3410_1994_PARAM_CP_XCHA  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$20#$01 {$endif}; 
  SB_OID_GOST_R3410_1994_PARAM_CP_XCHB  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$20#$02 {$endif}; 
  SB_OID_GOST_R3410_1994_PARAM_CP_XCHC  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$20#$03 {$endif}; 
  // CryptoPro RFC 4357 GOST R 34.10-2001 parameters are represented by curves below

  // EC-related OIDs

  // EC field OIDs
  SB_OID_FLD_CUSTOM         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'fld-custom@eldos.com' {$endif}; 
  SB_OID_FLD_TYPE_FP        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$CE#$3D#$01#$01 {$endif}; 
  SB_OID_FLD_TYPE_F2M       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$CE#$3D#$01#$02 {$endif}; 
  SB_OID_FLD_BASIS_N        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$CE#$3D#$01#$02#$03#$01 {$endif}; 
  SB_OID_FLD_BASIS_T        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$CE#$3D#$01#$02#$03#$02 {$endif}; 
  SB_OID_FLD_BASIS_P        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$CE#$3D#$01#$02#$03#$03 {$endif}; 

  // EC key types
  SB_OID_EC_KEY             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$CE#$3D#$02#$01 {$endif}; 
  SB_OID_ECDH               : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$81#$04#$01#$0C {$endif}; 
  SB_OID_ECMQV              : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$81#$04#$01#$0D {$endif}; 

  // ECDSA X9.62 signature algorithms
  SB_OID_ECDSA_SHA1         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$04#$01 {$endif}; 
  SB_OID_ECDSA_RECOMMENDED  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$04#$02 {$endif}; 
  SB_OID_ECDSA_SHA224       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$04#$03#$01 {$endif}; 
  SB_OID_ECDSA_SHA256       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$04#$03#$02 {$endif}; 
  SB_OID_ECDSA_SHA384       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$04#$03#$03 {$endif}; 
  SB_OID_ECDSA_SHA512       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$04#$03#$04 {$endif}; 
  SB_OID_ECDSA_SPECIFIED    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$04#$03 {$endif}; 

  // ECDSA signature algorithm, German BSI Technical Guideline TR-03111
  SB_OID_ECDSA_PLAIN_SHA1     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$01 {$endif}; 
  SB_OID_ECDSA_PLAIN_SHA224   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$02 {$endif}; 
  SB_OID_ECDSA_PLAIN_SHA256   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$03 {$endif}; 
  SB_OID_ECDSA_PLAIN_SHA384   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$04 {$endif}; 
  SB_OID_ECDSA_PLAIN_SHA512   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$05 {$endif}; 
  SB_OID_ECDSA_PLAIN_RIPEMD160: TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$06 {$endif}; 
  
  // Known elliptic curve OIDs
  // fake OID to represent custom EC
  SB_OID_EC_CUSTOM          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-custom@eldos.com' {$endif}; 

  // X9.62 curves
  { recommended curves over the binary fields }
  SB_OID_EC_C2PNB163V1      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$00#$01 {$endif}; 
  SB_OID_EC_C2PNB163V2      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$00#$02 {$endif}; 
  SB_OID_EC_C2PNB163V3      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$00#$03 {$endif}; 
  SB_OID_EC_C2PNB176W1      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$00#$04 {$endif}; 
  SB_OID_EC_C2TNB191V1      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$00#$05 {$endif}; 
  SB_OID_EC_C2TNB191V2      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$00#$06 {$endif}; 
  SB_OID_EC_C2TNB191V3      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$00#$07 {$endif}; 
  SB_OID_EC_C2ONB191V4      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$00#$08 {$endif}; 
  SB_OID_EC_C2ONB191V5      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$00#$09 {$endif}; 
  SB_OID_EC_C2PNB208W1      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$00#$0A {$endif}; 
  SB_OID_EC_C2TNB239V1      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$00#$0B {$endif}; 
  SB_OID_EC_C2TNB239V2      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$00#$0C {$endif}; 
  SB_OID_EC_C2TNB239V3      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$00#$0D {$endif}; 
  SB_OID_EC_C2ONB239V4      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$00#$0E {$endif}; 
  SB_OID_EC_C2ONB239V5      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$00#$0F {$endif}; 
  SB_OID_EC_C2PNB272W1      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$00#$10 {$endif}; 
  SB_OID_EC_C2PNB304W1      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$00#$11 {$endif}; 
  SB_OID_EC_C2TNB359V1      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$00#$12 {$endif}; 
  SB_OID_EC_C2PNB368W1      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$00#$13 {$endif}; 
  SB_OID_EC_C2TNB431R1      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$00#$14 {$endif}; 
  { recommended curves over the prime field }
  SB_OID_EC_PRIME192V1      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$01#$01 {$endif}; 
  SB_OID_EC_PRIME192V2      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$01#$02 {$endif}; 
  SB_OID_EC_PRIME192V3      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$01#$03 {$endif}; 
  SB_OID_EC_PRIME239V1      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$01#$04 {$endif}; 
  SB_OID_EC_PRIME239V2      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$01#$05 {$endif}; 
  SB_OID_EC_PRIME239V3      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$01#$06 {$endif}; 
  SB_OID_EC_PRIME256V1      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$01#$07 {$endif}; 
  // SEC2 curves
  { SEC2 recommended curves over a prime field }
  SB_OID_EC_SECP112R1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$06 {$endif}; 
  SB_OID_EC_SECP112R2       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$07 {$endif}; 
  SB_OID_EC_SECP128R1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$1C {$endif}; 
  SB_OID_EC_SECP128R2       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$1D {$endif}; 
  SB_OID_EC_SECP160K1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$09 {$endif}; 
  SB_OID_EC_SECP160R1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$08 {$endif}; 
  SB_OID_EC_SECP160R2       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$1E {$endif}; 
  SB_OID_EC_SECP192K1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$1F {$endif}; 
                              // SECP192R1 is the same as PRIME192V1
  SB_OID_EC_SECP192R1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$01#$01 {$endif}; 
  SB_OID_EC_SECP224K1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$20 {$endif}; 
  SB_OID_EC_SECP224R1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$21 {$endif}; 
  SB_OID_EC_SECP256K1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$0A {$endif}; 
                              // SECP256R1 is the same as PRIME256V1
  SB_OID_EC_SECP256R1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$03#$01#$07 {$endif}; 
  SB_OID_EC_SECP384R1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$22 {$endif}; 
  SB_OID_EC_SECP521R1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$23 {$endif}; 
  { SEC2 recommended curves over extended binary field }
  SB_OID_EC_SECT113R1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$04 {$endif}; 
  SB_OID_EC_SECT113R2       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$05 {$endif}; 
  SB_OID_EC_SECT131R1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$16 {$endif}; 
  SB_OID_EC_SECT131R2       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$17 {$endif}; 
  SB_OID_EC_SECT163K1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$01 {$endif}; 
  SB_OID_EC_SECT163R1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$02 {$endif}; 
  SB_OID_EC_SECT163R2       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$0f {$endif}; 
  SB_OID_EC_SECT193R1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$18 {$endif}; 
  SB_OID_EC_SECT193R2       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$19 {$endif}; 
  SB_OID_EC_SECT233K1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$1A {$endif}; 
  SB_OID_EC_SECT233R1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$1B {$endif}; 
  SB_OID_EC_SECT239K1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$03 {$endif}; 
  SB_OID_EC_SECT283K1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$10 {$endif}; 
  SB_OID_EC_SECT283R1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$11 {$endif}; 
  SB_OID_EC_SECT409K1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$24 {$endif}; 
  SB_OID_EC_SECT409R1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$25 {$endif}; 
  SB_OID_EC_SECT571K1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$26 {$endif}; 
  SB_OID_EC_SECT571R1       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$81#$04#$00#$27 {$endif}; 

  { GOST 34.11-2001 RFC 4357 (CryptoPro) curves }
  SB_OID_EC_GOST_CP_TEST    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$23#$00 {$endif}; 
  SB_OID_EC_GOST_CP_A       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$23#$01 {$endif}; 
  SB_OID_EC_GOST_CP_B       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$23#$02 {$endif}; 
  SB_OID_EC_GOST_CP_C       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$23#$03 {$endif}; 
  SB_OID_EC_GOST_CP_XCHA    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$24#$00 {$endif}; 
  SB_OID_EC_GOST_CP_XCHB    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$24#$01 {$endif}; 

  { EldoS Corporation dedicated OIDs }
  SB_OID_ELDOSCORP_BASE     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$90#$22 {$endif};  // 1.3.6.1.4.1.34850
  { all direct sub-OIDs (first-level sub-OIDs) must be defined here to prevent conflicts }
  SB_OID_ELDOS_PKI          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$90#$22#$01 {$endif}; 
  SB_OID_ELDOS_ALGS         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$90#$22#$02 {$endif}; 
  SB_OID_ELDOS_DATASTORAGE  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$90#$22#$07 {$endif}; 

  SB_OID_ELDOS_ALGS_NULL    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$90#$22#$02#$01 {$endif}; 
  SB_OID_ELDOS_ALGS_PKEY    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$90#$22#$02#$02 {$endif}; 
  SB_OID_ELDOS_ALGS_SKEY    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$90#$22#$02#$03 {$endif}; 
  SB_OID_ELDOS_ALGS_DGST    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$90#$22#$02#$04 {$endif}; 
  SB_OID_ELDOS_ALGS_HMAC    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$90#$22#$02#$05 {$endif}; 
  SB_OID_ELDOS_ALGS_COMPR   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$90#$22#$02#$06 {$endif}; 


  SB_CERT_OID_COMMON_NAME          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$03  {$endif}; 
  SB_CERT_OID_SURNAME              : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$04  {$endif}; 
  SB_CERT_OID_COUNTRY              : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$06  {$endif}; 
  SB_CERT_OID_LOCALITY             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$07  {$endif}; 
  SB_CERT_OID_STATE_OR_PROVINCE    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$08  {$endif}; 
  SB_CERT_OID_ORGANIZATION         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$0A  {$endif}; 
  SB_CERT_OID_ORGANIZATION_UNIT    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$0B  {$endif}; 
  SB_CERT_OID_TITLE                : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$0C  {$endif}; 
  SB_CERT_OID_NAME                 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$29  {$endif}; 
  SB_CERT_OID_GIVEN_NAME           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$2A  {$endif}; 
  SB_CERT_OID_INITIALS             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$2B  {$endif}; 
  SB_CERT_OID_GENERATION_QUALIFIER : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$2C  {$endif}; 
  SB_CERT_OID_DN_QUALIFIER         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$2E  {$endif}; 
  SB_CERT_OID_EMAIL                : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$09#$01  {$endif}; 

  SB_CERT_OID_STREET_ADDRESS       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = #$55#$04#$09  {$endif}; 
  SB_CERT_OID_POSTAL_ADDRESS       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = #$55#$04#$10  {$endif}; 
  SB_CERT_OID_POSTAL_CODE          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = #$55#$04#$11  {$endif}; 
  SB_CERT_OID_POST_OFFICE_BOX      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = #$55#$04#$12  {$endif}; 
  SB_CERT_OID_PHYSICAL_DELIVERY_OFFICE_NAME : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$13  {$endif}; 
  SB_CERT_OID_TELEPHONE_NUMBER     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$14  {$endif}; 
  SB_CERT_OID_TELEX_NUMBER         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$15  {$endif}; 
  SB_CERT_OID_TELEX_TERMINAL_ID    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$16  {$endif}; 
  SB_CERT_OID_FACIMILE_PHONE_NUMBER: TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$17  {$endif}; 

  SB_CERT_OID_X12_ADDRESS          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$18  {$endif}; 
  SB_CERT_OID_INTERNATIONAL_ISDN_NUMBER : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$19  {$endif}; 
  SB_CERT_OID_REGISTERED_ADDRESS   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$1A  {$endif}; 
  SB_CERT_OID_DESTINATION_INDICATOR: TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$1B  {$endif}; 
  SB_CERT_OID_PREFERRED_DELIVERY_METHOD : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$1C  {$endif}; 
  SB_CERT_OID_PRESENTATION_ADDRESS : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$1D  {$endif}; 
  SB_CERT_OID_SUPPORTED_APPLICATION_CONTEXT : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$1E  {$endif}; 
  SB_CERT_OID_MEMBER            : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$1F  {$endif}; 
  SB_CERT_OID_OWNER             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$20  {$endif}; 
  SB_CERT_OID_ROLE_OCCUPENT        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$21  {$endif}; 
  SB_CERT_OID_SEE_ALSO             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$22  {$endif}; 
  SB_CERT_OID_USER_PASSWORD        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$23  {$endif}; 
  SB_CERT_OID_USER_CERTIFICATE     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$24  {$endif}; 
  SB_CERT_OID_CA_CERTIFICATE       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$25  {$endif}; 
  SB_CERT_OID_AUTHORITY_REVOCATION_LIST : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$26  {$endif}; 
  SB_CERT_OID_CERTIFICATE_REVOCATION_LIST: TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$27  {$endif}; 
  SB_CERT_OID_CERTIFICATE_PAIR     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$28  {$endif}; 
  SB_CERT_OID_UNIQUE_IDENTIFIER    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$2D  {$endif}; 
  SB_CERT_OID_ENHANCED_SEARCH_GUIDE: TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$2F  {$endif}; 

  SB_CERT_OID_OBJECT_CLASS         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$00  {$endif}; 
  SB_CERT_OID_ALIASED_ENTRY_NAME   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$01  {$endif}; 
  SB_CERT_OID_KNOWLEDGE_INFORMATION: TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$02  {$endif}; 
  SB_CERT_OID_SERIAL_NUMBER        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$05  {$endif}; 
  SB_CERT_OID_DESCRIPTION          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$0D  {$endif}; 
  SB_CERT_OID_SEARCH_GUIDE         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$0E  {$endif}; 
  SB_CERT_OID_BUSINESS_CATEGORY    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$0F  {$endif}; 
  SB_CERT_OID_PROTOCOL_INFORMATION : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$30  {$endif}; 
  SB_CERT_OID_DISTINGUISHED_NAME   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$31  {$endif}; 
  SB_CERT_OID_UNIQUE_MEMBER        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$32  {$endif}; 
  SB_CERT_OID_HOUSE_IDENTIFIER     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$33  {$endif}; 
  SB_CERT_OID_SUPPORTED_ALGORITHMS : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$34  {$endif}; 
  SB_CERT_OID_DELTA_REVOCATION_LIST: TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$35  {$endif}; 
  SB_CERT_OID_ATTRIBUTE_CERTIFICATE: TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$3A  {$endif}; 
  SB_CERT_OID_PSEUDONYM            : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$55#$04#$41  {$endif}; 

  SB_CERT_OID_PERMANENT_IDENTIFIER : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$06#$01#$05#$05#$07#$00#$12#$08#$03  {$endif}; 

  SB_CERT_OID_USER_ID              : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$9#$92#$26#$89#$93#$F2#$2C#$64#$1#$1  {$endif}; 
  SB_CERT_OID_DOMAIN_COMPONENT     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$9#$92#$26#$89#$93#$F2#$2C#$64#$1#$19  {$endif}; 

  SB_CERT_OID_CA_OCSP              : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$06#$01#$05#$05#$07#$30#$01  {$endif}; 
  SB_CERT_OID_CA_ISSUER            : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2b#$06#$01#$05#$05#$07#$30#$02  {$endif}; 


  SB_CERT_OID_RSAENCRYPTION        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$01  {$endif}; 
  SB_CERT_OID_RSAOAEP              : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$07  {$endif}; 
  SB_CERT_OID_RSAPSS               : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$0A  {$endif}; 
  SB_CERT_OID_DSA                  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$CE#$38#$04#$01  {$endif}; 
  SB_CERT_OID_DH                   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$CE#$3E#$02#$01  {$endif}; 
  SB_CERT_OID_DSA_SHA1             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$CE#$38#$04#$03  {$endif}; 
  SB_CERT_OID_DSA_SHA224           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$CE#$38#$04#$03  {$endif}; 
  SB_CERT_OID_DSA_SHA256           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$CE#$38#$04#$03  {$endif}; 
  SB_CERT_OID_MD2_RSAENCRYPTION    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$02  {$endif}; 
  SB_CERT_OID_MD5_RSAENCRYPTION    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$04  {$endif}; 
  SB_CERT_OID_SHA1_RSAENCRYPTION   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$05  {$endif}; 
  SB_CERT_OID_SHA224_RSAENCRYPTION : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$0E  {$endif}; 
  SB_CERT_OID_SHA256_RSAENCRYPTION : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$0B  {$endif}; 
  SB_CERT_OID_SHA384_RSAENCRYPTION : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$0C  {$endif}; 
  SB_CERT_OID_SHA512_RSAENCRYPTION : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$01#$0D  {$endif}; 

  SB_CERT_OID_ECDSA_SHA1           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$CE#$3D#$04#$01  {$endif}; 
  SB_CERT_OID_ECDSA_RECOMMENDED    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$CE#$3D#$04#$02  {$endif}; 
  SB_CERT_OID_ECDSA_SHA224         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$CE#$3D#$04#$03#$01  {$endif}; 
  SB_CERT_OID_ECDSA_SHA256         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$CE#$3D#$04#$03#$02  {$endif}; 
  SB_CERT_OID_ECDSA_SHA384         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$CE#$3D#$04#$03#$03  {$endif}; 
  SB_CERT_OID_ECDSA_SHA512         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$CE#$3D#$04#$03#$04  {$endif}; 
  SB_CERT_OID_ECDSA_SPECIFIED      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$CE#$3D#$04#$03  {$endif}; 

  { Signature algorithms, defined in German BSI Technical Guideline TR-03111 }
  SB_CERT_OID_ECDSA_PLAIN_SHA1     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$01  {$endif}; 
  SB_CERT_OID_ECDSA_PLAIN_SHA224   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$02  {$endif}; 
  SB_CERT_OID_ECDSA_PLAIN_SHA256   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$03  {$endif}; 
  SB_CERT_OID_ECDSA_PLAIN_SHA384   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$04  {$endif}; 
  SB_CERT_OID_ECDSA_PLAIN_SHA512   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$05  {$endif}; 
  SB_CERT_OID_ECDSA_PLAIN_RIPEMD160: TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$06  {$endif}; 

  SB_CERT_OID_GOST_R3410_1994      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$14  {$endif}; 
  SB_CERT_OID_GOST_R3410_2001      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$13  {$endif}; 
  SB_CERT_OID_GOST_R3411_WITH_GOST3410_1994 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$04  {$endif}; 
  SB_CERT_OID_GOST_R3411_WITH_GOST3410_2001 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$85#$03#$02#$02#$03  {$endif}; 

  SB_CERT_OID_SHA1_RSA             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$0E#$03#$02#$1D  {$endif}; 
  SB_CERT_OID_SHA1_DSA             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$CE#$38#$04#$03  {$endif}; 
  SB_CERT_OID_SHA1                 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$0E#$03#$02#$1A  {$endif}; 
  SB_CERT_OID_MD2                  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$02#$02  {$endif}; 
  SB_CERT_OID_MD5                  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$02#$05  {$endif}; 

  { RFC 5272 }

  SB_CMC_OID_PKI_DATA               : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$0C#$02  {$endif}; 
  SB_CMC_OID_PKI_RESPONSE           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$0C#$03  {$endif}; 

  SB_CMC_OID_STATUS_INFO            : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$01  {$endif}; 
  SB_CMC_OID_IDENTIFICATION         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$02  {$endif}; 
  SB_CMC_OID_IDENTITY_PROOF         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$03  {$endif}; 
  SB_CMC_OID_DATA_RETURN            : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$04  {$endif}; 
  SB_CMC_OID_TRANSACTION_ID         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$05  {$endif}; 
  SB_CMC_OID_SENDER_NONCE           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$06  {$endif}; 
  SB_CMC_OID_RECIPIENT_NONCE        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$07  {$endif}; 
  SB_CMC_OID_ADD_EXTENSIONS         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$08  {$endif}; 
  SB_CMC_OID_ENCRYPTED_POP          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$09  {$endif}; 
  SB_CMC_OID_DECRYPTED_POP          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$0A  {$endif}; 
  SB_CMC_OID_LRA_POP_WITNESS        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$0B  {$endif}; 
  SB_CMC_OID_GET_CERT               : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$0F  {$endif}; 
  SB_CMC_OID_GET_CRL                : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$10  {$endif}; 
  SB_CMC_OID_REVOKE_REQUEST         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$11  {$endif}; 
  SB_CMC_OID_REG_INFO               : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$12  {$endif}; 
  SB_CMC_OID_RESPONSE_INFO          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$13  {$endif}; 
  SB_CMC_OID_QUERY_PENDING          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$15  {$endif}; 
  SB_CMC_OID_POP_LINK_RANDOM        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$16  {$endif}; 
  SB_CMC_OID_POP_LINK_WITNESS       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$17  {$endif}; 
  SB_CMC_OID_POP_LINK_WITNESS_V2    : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$21  {$endif}; 
  SB_CMC_OID_CONFIRM_CERT_ACCEPTANCE  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$18  {$endif}; 
  SB_CMC_OID_STATUS_INFO_V2         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$19  {$endif}; 
  SB_CMC_OID_TRUSTED_ANCHORS        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$1A  {$endif}; 
  SB_CMC_OID_AUTH_DATA              : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$1B  {$endif}; 
  SB_CMC_OID_BATCH_REQUESTS         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$1C  {$endif}; 
  SB_CMC_OID_BATCH_RESPONSES        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$1D  {$endif}; 
  SB_CMC_OID_PUBLISH_CERT           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$1E  {$endif}; 
  SB_CMC_OID_MOD_CERT_TEMPLATE      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$1F  {$endif}; 
  SB_CMC_OID_CONTROL_PROCESSED      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$20  {$endif}; 
  SB_CMC_OID_IDENTITY_PROOF_V2      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$05#$05#$07#$07#$22  {$endif}; 

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS ON}
 {$endif}

const
  // Symmetric algorithms
  SB_ALGORITHM_CNT_BASE                 = $7000;
  SB_ALGORITHM_CNT_RC4                  = SmallInt(SB_ALGORITHM_CNT_BASE + $01);
  SB_ALGORITHM_CNT_DES                  = SmallInt(SB_ALGORITHM_CNT_BASE + $02);
  SB_ALGORITHM_CNT_3DES                 = SmallInt(SB_ALGORITHM_CNT_BASE + $03);
  SB_ALGORITHM_CNT_RC2                  = SmallInt(SB_ALGORITHM_CNT_BASE + $04);
  SB_ALGORITHM_CNT_AES128               = SmallInt(SB_ALGORITHM_CNT_BASE + $05);
  SB_ALGORITHM_CNT_AES192               = SmallInt(SB_ALGORITHM_CNT_BASE + $06);
  SB_ALGORITHM_CNT_AES256               = SmallInt(SB_ALGORITHM_CNT_BASE + $07);
  SB_ALGORITHM_CNT_IDENTITY             = SmallInt(SB_ALGORITHM_CNT_BASE + $0A);
  SB_ALGORITHM_CNT_BLOWFISH             = SmallInt(SB_ALGORITHM_CNT_BASE + $10);
  SB_ALGORITHM_CNT_TWOFISH              = SmallInt(SB_ALGORITHM_CNT_BASE + $11);
  SB_ALGORITHM_CNT_CAMELLIA             = SmallInt(SB_ALGORITHM_CNT_BASE + $12);
  SB_ALGORITHM_CNT_CAST128              = SmallInt(SB_ALGORITHM_CNT_BASE + $13);
  SB_ALGORITHM_CNT_IDEA                 = SmallInt(SB_ALGORITHM_CNT_BASE + $14);
  SB_ALGORITHM_CNT_SERPENT              = SmallInt(SB_ALGORITHM_CNT_BASE + $15);
  SB_ALGORITHM_CNT_TWOFISH128           = SmallInt(SB_ALGORITHM_CNT_BASE + $16);
  SB_ALGORITHM_CNT_TWOFISH192           = SmallInt(SB_ALGORITHM_CNT_BASE + $17);
  SB_ALGORITHM_CNT_TWOFISH256           = SmallInt(SB_ALGORITHM_CNT_BASE + $18);
  SB_ALGORITHM_CNT_CAMELLIA128          = SmallInt(SB_ALGORITHM_CNT_BASE + $19);
  SB_ALGORITHM_CNT_CAMELLIA192          = SmallInt(SB_ALGORITHM_CNT_BASE + $1A);
  SB_ALGORITHM_CNT_CAMELLIA256          = SmallInt(SB_ALGORITHM_CNT_BASE + $1B);
  SB_ALGORITHM_CNT_SERPENT128           = SmallInt(SB_ALGORITHM_CNT_BASE + $1C);
  SB_ALGORITHM_CNT_SERPENT192           = SmallInt(SB_ALGORITHM_CNT_BASE + $1D);
  SB_ALGORITHM_CNT_SERPENT256           = SmallInt(SB_ALGORITHM_CNT_BASE + $1E);
  SB_ALGORITHM_CNT_SEED                 = SmallInt(SB_ALGORITHM_CNT_BASE + $20);
  SB_ALGORITHM_CNT_RABBIT               = SmallInt(SB_ALGORITHM_CNT_BASE + $21);
  SB_ALGORITHM_CNT_SYMMETRIC            = SmallInt(SB_ALGORITHM_CNT_BASE + $22); // special value for overall symmetric ciphers
  SB_ALGORITHM_CNT_GOST_28147_1989      = SmallInt(SB_ALGORITHM_CNT_BASE + $23);

  // Public key algorithms
  SB_ALGORITHM_PK_BASE                  = $7400;
  SB_ALGORITHM_PK_RSA                   = SmallInt(SB_ALGORITHM_PK_BASE + $01);
  SB_ALGORITHM_PK_DSA                   = SmallInt(SB_ALGORITHM_PK_BASE + $02);
  SB_ALGORITHM_PK_ELGAMAL               = SmallInt(SB_ALGORITHM_PK_BASE + $03);
  SB_ALGORITHM_PK_GOST_R3410_1994        = SmallInt(SB_ALGORITHM_PK_BASE + $04);
  SB_ALGORITHM_PK_EC                    = SmallInt(SB_ALGORITHM_PK_BASE + $05);
  SB_ALGORITHM_PK_ECDSA                 = SmallInt(SB_ALGORITHM_PK_BASE + $06);
  SB_ALGORITHM_PK_DH                    = SmallInt(SB_ALGORITHM_PK_BASE + $07);
  SB_ALGORITHM_PK_SRP                   = SmallInt(SB_ALGORITHM_PK_BASE + $08);
  SB_ALGORITHM_PK_ECDH                  = SmallInt(SB_ALGORITHM_PK_BASE + $09);
  SB_ALGORITHM_PK_GOST_R3410_2001        = SmallInt(SB_ALGORITHM_PK_BASE + $0A);

  // Hash algorithms
  SB_ALGORITHM_DGST_BASE                = $7100;
  SB_ALGORITHM_DGST_SHA1                = SmallInt(SB_ALGORITHM_DGST_BASE + $01);
  SB_ALGORITHM_DGST_MD5                 = SmallInt(SB_ALGORITHM_DGST_BASE + $02);
  SB_ALGORITHM_DGST_MD2                 = SmallInt(SB_ALGORITHM_DGST_BASE + $03);
  SB_ALGORITHM_DGST_SHA256              = SmallInt(SB_ALGORITHM_DGST_BASE + $04);
  SB_ALGORITHM_DGST_SHA384              = SmallInt(SB_ALGORITHM_DGST_BASE + $05);
  SB_ALGORITHM_DGST_SHA512              = SmallInt(SB_ALGORITHM_DGST_BASE + $06);
  SB_ALGORITHM_DGST_SHA224              = SmallInt(SB_ALGORITHM_DGST_BASE + $07);
  SB_ALGORITHM_DGST_MD4                 = SmallInt(SB_ALGORITHM_DGST_BASE + $08);
  SB_ALGORITHM_DGST_RIPEMD160           = SmallInt(SB_ALGORITHM_DGST_BASE + $09);
  SB_ALGORITHM_DGST_CRC32               = SmallInt(SB_ALGORITHM_DGST_BASE + $0A); // RFC 1510,ISO 3309
  SB_ALGORITHM_DGST_SSL3                = SmallInt(SB_ALGORITHM_DGST_BASE + $0B);
  SB_ALGORITHM_DGST_GOST_R3411_1994     = SmallInt(SB_ALGORITHM_DGST_BASE + $0C);
  SB_ALGORITHM_DGST_WHIRLPOOL           = SmallInt(SB_ALGORITHM_DGST_BASE + $0D);

  // PKCS#12 PBE algorithms 
  SB_ALGORITHM_PBE_BASE                 = $7200;
  SB_ALGORITHM_PBE_SHA1_RC4_128         = SmallInt($7201);
  SB_ALGORITHM_PBE_SHA1_RC4_40          = SmallInt($7202);
  SB_ALGORITHM_PBE_SHA1_3DES            = SmallInt($7203);
  SB_ALGORITHM_PBE_SHA1_RC2_128         = SmallInt($7204);
  SB_ALGORITHM_PBE_SHA1_RC2_40          = SmallInt($7205);
  { PKCS#5 PBES1 algorithms }
  SB_ALGORITHM_P5_PBE_MD2_DES           = SmallInt($7221);
  SB_ALGORITHM_P5_PBE_MD2_RC2           = SmallInt($7222);
  SB_ALGORITHM_P5_PBE_MD5_DES           = SmallInt($7223);
  SB_ALGORITHM_P5_PBE_MD5_RC2           = SmallInt($7224);
  SB_ALGORITHM_P5_PBE_SHA1_DES          = SmallInt($7225);
  SB_ALGORITHM_P5_PBE_SHA1_RC2          = SmallInt($7226);
  { PKCS#5 auxiliary algorithms }
  SB_ALGORITHM_P5_PBES1                 = SmallInt($7241);
  SB_ALGORITHM_P5_PBES2                 = SmallInt($7242);
  SB_ALGORITHM_P5_PBKDF1                = SmallInt($7251);
  SB_ALGORITHM_P5_PBKDF2                = SmallInt($7252);
  SB_ALGORITHM_P5_PBMAC1                = SmallInt($7261);

  // MAC algorithms
  SB_ALGORITHM_MAC_BASE                 = $7300;
  SB_ALGORITHM_MAC_HMACSHA1             = SmallInt(SB_ALGORITHM_MAC_BASE + $01);
  SB_ALGORITHM_MAC_HMACSHA224           = SmallInt(SB_ALGORITHM_MAC_BASE + $02);
  SB_ALGORITHM_MAC_HMACSHA256           = SmallInt(SB_ALGORITHM_MAC_BASE + $03);
  SB_ALGORITHM_MAC_HMACSHA384           = SmallInt(SB_ALGORITHM_MAC_BASE + $04);
  SB_ALGORITHM_MAC_HMACSHA512           = SmallInt(SB_ALGORITHM_MAC_BASE + $05);
  SB_ALGORITHM_MAC_HMACMD5              = SmallInt(SB_ALGORITHM_MAC_BASE + $06);
  SB_ALGORITHM_MAC_HMACRIPEMD           = SmallInt(SB_ALGORITHM_MAC_BASE + $07);
  SB_ALGORITHM_HMAC                     = SmallInt(SB_ALGORITHM_MAC_BASE + $08); //special value for overall MAC algorithms

  SB_ALGORITHM_UMAC32                   = SmallInt(SB_ALGORITHM_MAC_BASE + $10);
  SB_ALGORITHM_UMAC64                   = SmallInt(SB_ALGORITHM_MAC_BASE + $11);
  SB_ALGORITHM_UMAC96                   = SmallInt(SB_ALGORITHM_MAC_BASE + $12);
  SB_ALGORITHM_UMAC128                  = SmallInt(SB_ALGORITHM_MAC_BASE + $13);

  SB_ALGORITHM_MAC_GOST_28147_1989      = SmallInt(SB_ALGORITHM_MAC_BASE + $14);
  SB_ALGORITHM_HMAC_GOST_R3411_1994     = SmallInt(SB_ALGORITHM_MAC_BASE + $15);

  SB_ALGORITHM_UNKNOWN                  = SmallInt($7FFF);

  {$EXTERNALSYM ALG_CLASS_DATA_ENCRYPT}
  ALG_CLASS_DATA_ENCRYPT                = SmallInt((3 shl 13));
  {$EXTERNALSYM ALG_TYPE_BLOCK}
  ALG_TYPE_BLOCK                        = SmallInt((3 shl 9));
  {$EXTERNALSYM ALG_TYPE_STREAM}
  ALG_TYPE_STREAM                       = SmallInt((4 shl 9));
  {$EXTERNALSYM ALG_SID_DES}
  ALG_SID_DES                           = SmallInt(1);
  {$EXTERNALSYM ALG_SID_3DES}
  ALG_SID_3DES                          = SmallInt(3);
  {$EXTERNALSYM ALG_SID_RC2}
  ALG_SID_RC2                           = SmallInt(2);
  {$EXTERNALSYM ALG_SID_RC4}
  ALG_SID_RC4                           = SmallInt(1);

  {$EXTERNALSYM CALG_DES}
  CALG_DES                              = SmallInt(ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_DES);
  {$EXTERNALSYM CALG_3DES}
  CALG_3DES                             = SmallInt(ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_3DES);
  {$EXTERNALSYM CALG_RC2}
  CALG_RC2                              = SmallInt(ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or ALG_SID_RC2);
  {$EXTERNALSYM CALG_RC4}
  CALG_RC4                              = SmallInt(ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_STREAM or ALG_SID_RC4);

  { EC-related constants }

const
  { fields }

  SB_EC_FLD_TYPE_BASE  = $6000;

  SB_EC_FLD_TYPE_UNKNOWN = SmallInt(SB_EC_FLD_TYPE_BASE);     // unknown field
  SB_EC_FLD_TYPE_FP    = SmallInt(SB_EC_FLD_TYPE_BASE + $01); // prime field Fp
  SB_EC_FLD_TYPE_F2MP  = SmallInt(SB_EC_FLD_TYPE_BASE + $02); // binary extended field F2m in polynomial basis
  SB_EC_FLD_TYPE_F2MN  = SmallInt(SB_EC_FLD_TYPE_BASE + $03); // binary extended field F2m in normal basis, not implemented yet

  SB_EC_FLD_BASE  = $6100;

  SB_EC_FLD_FIRST      = SmallInt(SB_EC_FLD_BASE);

  SB_EC_FLD_CUSTOM     = SmallInt(SB_EC_FLD_BASE);
  SB_EC_FLD_NIST_P192S  = SmallInt(SB_EC_FLD_BASE + $01);
  SB_EC_FLD_NIST_P224S  = SmallInt(SB_EC_FLD_BASE + $02);
  SB_EC_FLD_NIST_P256S  = SmallInt(SB_EC_FLD_BASE + $03);
  SB_EC_FLD_NIST_P384  = SmallInt(SB_EC_FLD_BASE + $04);
  SB_EC_FLD_NIST_P521  = SmallInt(SB_EC_FLD_BASE + $05);

  SB_EC_FLD_NIST_B163  = SmallInt(SB_EC_FLD_BASE + $06);
  SB_EC_FLD_NIST_B233  = SmallInt(SB_EC_FLD_BASE + $07);
  SB_EC_FLD_NIST_B283  = SmallInt(SB_EC_FLD_BASE + $08);
  SB_EC_FLD_NIST_B409  = SmallInt(SB_EC_FLD_BASE + $09);
  SB_EC_FLD_NIST_B571  = SmallInt(SB_EC_FLD_BASE + $0A);

  SB_EC_FLD_LAST       = SmallInt(SB_EC_FLD_BASE + $0A);

  { ECDSA hash wrapping flags }
  SB_ECDSA_WRAP_SHIFT  = 0;
  SB_ECDSA_WRAP_MOD_N  = 1;

  { Elliptic curves }

  SB_EC_BASE  = $6200;

  SB_EC_FIRST     = SmallInt(SB_EC_BASE);

  SB_EC_CUSTOM    = SmallInt(SB_EC_BASE);
  { SEC2 recommended curves over a prime field }
  SB_EC_SECP112R1 = SmallInt(SB_EC_BASE + $01);
  SB_EC_SECP112R2 = SmallInt(SB_EC_BASE + $02);
  SB_EC_SECP128R1 = SmallInt(SB_EC_BASE + $03);
  SB_EC_SECP128R2 = SmallInt(SB_EC_BASE + $04);
  SB_EC_SECP160K1 = SmallInt(SB_EC_BASE + $05);
  SB_EC_SECP160R1 = SmallInt(SB_EC_BASE + $06);
  SB_EC_SECP160R2 = SmallInt(SB_EC_BASE + $07);
  SB_EC_SECP192K1 = SmallInt(SB_EC_BASE + $08);
  SB_EC_SECP192R1 = SmallInt(SB_EC_BASE + $09);
  SB_EC_SECP224K1 = SmallInt(SB_EC_BASE + $0A);
  SB_EC_SECP224R1 = SmallInt(SB_EC_BASE + $0B);
  SB_EC_SECP256K1 = SmallInt(SB_EC_BASE + $0C);
  SB_EC_SECP256R1 = SmallInt(SB_EC_BASE + $0D);
  SB_EC_SECP384R1 = SmallInt(SB_EC_BASE + $0E);
  SB_EC_SECP521R1 = SmallInt(SB_EC_BASE + $0F);
  { SEC2 recommended curves over extended binary field }
  SB_EC_SECT113R1 = SmallInt(SB_EC_BASE + $10);
  SB_EC_SECT113R2 = SmallInt(SB_EC_BASE + $11);
  SB_EC_SECT131R1 = SmallInt(SB_EC_BASE + $12);
  SB_EC_SECT131R2 = SmallInt(SB_EC_BASE + $13);
  SB_EC_SECT163K1 = SmallInt(SB_EC_BASE + $14);
  SB_EC_SECT163R1 = SmallInt(SB_EC_BASE + $15);
  SB_EC_SECT163R2 = SmallInt(SB_EC_BASE + $16);
  SB_EC_SECT193R1 = SmallInt(SB_EC_BASE + $17);
  SB_EC_SECT193R2 = SmallInt(SB_EC_BASE + $18);
  SB_EC_SECT233K1 = SmallInt(SB_EC_BASE + $19);
  SB_EC_SECT233R1 = SmallInt(SB_EC_BASE + $1A);
  SB_EC_SECT239K1 = SmallInt(SB_EC_BASE + $1B);
  SB_EC_SECT283K1 = SmallInt(SB_EC_BASE + $1C);
  SB_EC_SECT283R1 = SmallInt(SB_EC_BASE + $1D);
  SB_EC_SECT409K1 = SmallInt(SB_EC_BASE + $1E);
  SB_EC_SECT409R1 = SmallInt(SB_EC_BASE + $1F);
  SB_EC_SECT571K1 = SmallInt(SB_EC_BASE + $20);
  SB_EC_SECT571R1 = SmallInt(SB_EC_BASE + $21);
  { X9.62 recommended curves }
  { prime field }
  SB_EC_PRIME192V1 = SB_EC_SECP192R1;
  SB_EC_PRIME192V2 = SmallInt(SB_EC_BASE + $22);
  SB_EC_PRIME192V3 = SmallInt(SB_EC_BASE + $23);
  SB_EC_PRIME239V1 = SmallInt(SB_EC_BASE + $24);
  SB_EC_PRIME239V2 = SmallInt(SB_EC_BASE + $25);
  SB_EC_PRIME239V3 = SmallInt(SB_EC_BASE + $26);
  SB_EC_PRIME256V1 = SB_EC_SECP256R1;
  { binary extended field }
  SB_EC_C2PNB163V1 = SmallInt(SB_EC_BASE + $27);
  SB_EC_C2PNB163V2 = SmallInt(SB_EC_BASE + $28);
  SB_EC_C2PNB163V3 = SmallInt(SB_EC_BASE + $29);
  SB_EC_C2PNB176W1 = SmallInt(SB_EC_BASE + $2A);
  SB_EC_C2TNB191V1 = SmallInt(SB_EC_BASE + $2B);
  SB_EC_C2TNB191V2 = SmallInt(SB_EC_BASE + $2C);
  SB_EC_C2TNB191V3 = SmallInt(SB_EC_BASE + $2D);
  SB_EC_C2ONB191V4 = SmallInt(SB_EC_BASE + $2E);
  SB_EC_C2ONB191V5 = SmallInt(SB_EC_BASE + $2F);
  SB_EC_C2PNB208W1 = SmallInt(SB_EC_BASE + $30);
  SB_EC_C2TNB239V1 = SmallInt(SB_EC_BASE + $31);
  SB_EC_C2TNB239V2 = SmallInt(SB_EC_BASE + $32);
  SB_EC_C2TNB239V3 = SmallInt(SB_EC_BASE + $33);
  SB_EC_C2ONB239V4 = SmallInt(SB_EC_BASE + $34);
  SB_EC_C2ONB239V5 = SmallInt(SB_EC_BASE + $35);
  SB_EC_C2PNB272W1 = SmallInt(SB_EC_BASE + $36);
  SB_EC_C2PNB304W1 = SmallInt(SB_EC_BASE + $37);
  SB_EC_C2TNB359V1 = SmallInt(SB_EC_BASE + $38);
  SB_EC_C2PNB368W1 = SmallInt(SB_EC_BASE + $39);
  SB_EC_C2TNB431R1 = SmallInt(SB_EC_BASE + $3A);

  { NIST recommended curves name aliases. All are mapped to SEC2 curves }
  SB_EC_NIST_P192 = SB_EC_SECP192R1;
  SB_EC_NIST_P224 = SB_EC_SECP224R1;
  SB_EC_NIST_P256 = SB_EC_SECP256R1;
  SB_EC_NIST_P384 = SB_EC_SECP384R1;
  SB_EC_NIST_P521 = SB_EC_SECP521R1;
  { NIST recommended curves over a extended binary field }
  SB_EC_NIST_B163 = SB_EC_SECT163R2;
  SB_EC_NIST_B233 = SB_EC_SECT233R1;
  SB_EC_NIST_B283 = SB_EC_SECT283R1;
  SB_EC_NIST_B409 = SB_EC_SECT409R1;
  SB_EC_NIST_B571 = SB_EC_SECT571R1;
  { NIST recommended Koblitz curves }
  SB_EC_NIST_K163 = SB_EC_SECT163K1;
  SB_EC_NIST_K233 = SB_EC_SECT233K1;
  SB_EC_NIST_K283 = SB_EC_SECT283K1;
  SB_EC_NIST_K409 = SB_EC_SECT409K1;
  SB_EC_NIST_K571 = SB_EC_SECT571K1;

  { GOST 34.11-2001 RFC 4357 CryptoPro curves }

  SB_EC_GOST_CP_TEST = SmallInt(SB_EC_BASE + $3B);
  SB_EC_GOST_CP_A    = SmallInt(SB_EC_BASE + $3C);
  SB_EC_GOST_CP_B    = SmallInt(SB_EC_BASE + $3D);
  SB_EC_GOST_CP_C    = SmallInt(SB_EC_BASE + $3E);
  SB_EC_GOST_CP_XCHA = SmallInt(SB_EC_BASE + $3F);
  SB_EC_GOST_CP_XCHB = SmallInt(SB_EC_BASE + $40);

  SB_EC_LAST      = SmallInt(SB_EC_BASE + $40);

  { GOST paramset constants }
  SB_GOST_PARAM_BASE    = $6300;
  SB_GOST_PARAM_NONE    = SmallInt(SB_GOST_PARAM_BASE);
  SB_GOST_PARAM_CUSTOM  = SmallInt(SB_GOST_PARAM_BASE + $01);

  SB_GOST_28147_1989_PARAM_CP_TEST = SmallInt(SB_GOST_PARAM_BASE + $02);
  SB_GOST_28147_1989_PARAM_CP_A    = SmallInt(SB_GOST_PARAM_BASE + $03);
  SB_GOST_28147_1989_PARAM_CP_B    = SmallInt(SB_GOST_PARAM_BASE + $04);
  SB_GOST_28147_1989_PARAM_CP_C    = SmallInt(SB_GOST_PARAM_BASE + $05);
  SB_GOST_28147_1989_PARAM_CP_D    = SmallInt(SB_GOST_PARAM_BASE + $06);
  SB_GOST_28147_1989_PARAM_CP_OSCAR_11 = SmallInt(SB_GOST_PARAM_BASE + $07);
  SB_GOST_28147_1989_PARAM_CP_OSCAR_10 = SmallInt(SB_GOST_PARAM_BASE + $08);
  SB_GOST_28147_1989_PARAM_CP_RIC_1 = SmallInt(SB_GOST_PARAM_BASE + $09);
  // CryptoPro RFC 4357 GOST R 34.11-94 parameters
  SB_GOST_R3411_1994_PARAM_CP_TEST = SmallInt(SB_GOST_PARAM_BASE + $0A);
  SB_GOST_R3411_1994_PARAM_CP      = SmallInt(SB_GOST_PARAM_BASE + $0B);
  // CryptoPro RFC 4357 GOST R 34.10-94 parameters
  SB_GOST_R3410_1994_PARAM_CP_TEST = SmallInt(SB_GOST_PARAM_BASE + $0C);
  SB_GOST_R3410_1994_PARAM_CP_A    = SmallInt(SB_GOST_PARAM_BASE + $0D);
  SB_GOST_R3410_1994_PARAM_CP_B    = SmallInt(SB_GOST_PARAM_BASE + $0E);
  SB_GOST_R3410_1994_PARAM_CP_C    = SmallInt(SB_GOST_PARAM_BASE + $0F);
  SB_GOST_R3410_1994_PARAM_CP_D    = SmallInt(SB_GOST_PARAM_BASE + $10);
  SB_GOST_R3410_1994_PARAM_CP_XCHA = SmallInt(SB_GOST_PARAM_BASE + $11);
  SB_GOST_R3410_1994_PARAM_CP_XCHB = SmallInt(SB_GOST_PARAM_BASE + $12);
  SB_GOST_R3410_1994_PARAM_CP_XCHC = SmallInt(SB_GOST_PARAM_BASE + $13);

const
  LowerAlphabet = '0123456789abcdef';
  UpperAlphabet = '0123456789ABCDEF';



{$ifdef SB_UNICODE_VCL}
  {$WARNINGS ON}
 {$endif}

{$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
 {$else}
var
 {$endif}

  SpaceByteArray : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$20 {$endif}; 
  CommaByteArray : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  ',' {$endif}; 
  SlashByteArray : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  '/' {$endif}; 
  ColonByteArray : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  ':' {$endif}; 
  EqualCharByteArray : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  '=' {$endif}; 
  DashByteArray : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  '-' {$endif}; 

  LFByteArray : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$0A {$endif}; 
  CRByteArray : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$0D {$endif}; 

  LFLFByteArray : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$0A#$0A {$endif}; 
  CRLFByteArray : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$0D#$0A {$endif}; 
  CRLFCRLFByteArray : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$0D#$0A#$0D#$0A {$endif}; 
  CRCRLFByteArray : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$0D#$0D#$0A {$endif}; 
  CRLFTABByteArray : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$0D#$0A#$09 {$endif}; 
  CRLFSPACEByteArray : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$0D#$0A#$20 {$endif}; 
  CRCRLFCRCRLFByteArray : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$0D#$0D#$0A#$0D#$0D#$0A {$endif}; 

  TwoDashesByteArray : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = '--' {$endif}; 
  FiveDashesByteArray : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = '-----' {$endif}; 
  BeginLineByteArray : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = '-----BEGIN ' {$endif}; 
  LFEndLineByteArray : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = #$0A'-----END ' {$endif}; 

  UTF8BOMByteArray : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = #$ef#$bb#$bf {$endif}; 

const

{
  Magic values subtracted from a buffer value during UTF8 conversion.
  This table contains as many values as there might be trailing bytes
  in a UTF-8 sequence.
}
  offsetsFromUTF8: array [0..5] of UTF32 =
   ( 
  $00000000, $00003080, $000E2080,
  $03C82080, $0FA082080, $82082080
   ) ;

  firstByteMark: array [0..6] of UTF8 =
   ( 
  $00, $00, $0c0, $0e0, $0f0, $0f8, $0fc
   ) ;

{$ifdef SB_NO_NET_LEGACY_STRINGCOMPARE}
const
  //BoolStringCompareOption : array[boolean] of StringComparison = [StringComparison.OrdinalIgnoreCase, StringComparison.Ordinal];
  BoolStringCompareOption : array[boolean] of StringComparison = [StringComparison.Ordinal, StringComparison.OrdinalIgnoreCase];
 {$endif}

  //const SB_OID_RC4 = _SB_OID_RC4;

function GetPBEAlgorithmByOID(const OID: ByteArray): Integer; 
function GetOIDByPBEAlgorithm(Algorithm: Integer): ByteArray; 
function GetPKAlgorithmByOID(const OID: ByteArray): Integer; 
function GetOIDByPKAlgorithm(Algorithm : Integer): ByteArray; 
function GetSigAlgorithmByOID(const OID: ByteArray): integer; 
function GetOIDBySigAlgorithm(Algorithm: integer): ByteArray; 
function GetHashAlgorithmByOID(const OID : ByteArray) : integer; 
function GetOIDByHashAlgorithm(Algorithm : integer) : ByteArray; 
function GetAlgorithmByOID(const OID : ByteArray; UseCryptoProvConstants : boolean  =  false) : integer; 
function GetOIDByAlgorithm(Algorithm : integer) : ByteArray; 
function GetAlgorithmNameByAlgorithm(Algorithm: Integer): string; 
function GetAlgorithmNameByOID(const OID: ByteArray): string; 
function GetHashAlgorithmBySigAlgorithm(Algorithm: integer): integer; 
function GetHMACAlgorithmByHashAlgorithm(Algorithm: integer): integer; 
function GetHashAlgorithmByHMACAlgorithm(Algorithm: integer): integer; 
function GetSigAlgorithmByHashAlgorithm(BasePKAlg : integer; HashAlg : integer): integer; 
function GetKeyAlgorithmBySigAlgorithm(SigAlg : integer) : integer; 
function GetSigAlgorithmByKeyAlgorithm(KeyAlg : integer) : integer; 
function IsSymmetricKeyAlgorithm(Algorithm : integer): boolean; 
function IsHashAlgorithm(Algorithm : integer): boolean; 
function IsMACAlgorithm(Algorithm : integer): boolean; 
function IsPublicKeyAlgorithm(Algorithm : integer): boolean; 
function NormalizeAlgorithmConstant(Value: integer): integer; 
function MGF1AlgorithmByHash(Value: integer): integer; 
function HashAlgorithmByMGF1(Value: integer): integer; 

{$ifndef SB_FPC_GEN}
implementation

uses
  SysUtils,
  Classes,
  SBUtils,
  SBStrUtils;
 {$endif}

{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
{$ifdef SB_UNICODE_VCL}
  {$WARNINGS OFF}
 {$endif}
const
  //PKCS#1
  // Encryption Algorithm OIDs
  SB_OID_RC4_STR            = #$2a#$86#$48#$86#$f7#$0d#$03#$04;
  SB_OID_RSAENCRYPTION_STR  = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$01;
  SB_OID_EA_RSA_STR         = #$55#$08#$01#$01;
  SB_OID_RSAPSS_STR         = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$0A;
  SB_OID_RSAOAEP_STR        = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$07;
  SB_OID_DSA_STR            = #$2A#$86#$48#$CE#$38#$04#$01;
  SB_OID_DSA_SHA1_STR       = #$2A#$86#$48#$CE#$38#$04#$03;
  SB_OID_DSA_SHA224_STR     = #$60#$86#$48#$01#$65#$03#$04#$03#$01;
  SB_OID_DSA_SHA256_STR     = #$60#$86#$48#$01#$65#$03#$04#$03#$02;
  SB_OID_DSA_ALT_STR        = #$2B#$0E#$03#$02#$0C;
  SB_OID_DSA_SHA1_ALT_STR   = #$2B#$0E#$03#$02#$0D;
  SB_OID_DH_STR             = #$2A#$86#$48#$CE#$3E#$02#$01;
  SB_OID_DES_EDE3_CBC_STR   = #$2A#$86#$48#$86#$F7#$0D#$03#$07;
  SB_OID_PKCS7_DATA_STR     = #$2a#$86#$48#$86#$f7#$0d#$01#$07#$01;
  SB_OID_RC2_CBC_STR        = #$2A#$86#$48#$86#$F7#$0D#$03#$02;
  SB_OID_DES_CBC_STR        = #$2b#$0e#$03#$02#$07;
  SB_OID_SHA1_RSAENCRYPTION_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$05;
  SB_OID_SHA1_RSAENCRYPTION2_STR = #$2B#$0E#$03#$02#$1D;
  SB_OID_SHA224_RSAENCRYPTION_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$0E;
  SB_OID_SHA256_RSAENCRYPTION_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$0B;
  SB_OID_SHA384_RSAENCRYPTION_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$0C;
  SB_OID_SHA512_RSAENCRYPTION_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$0D;
  SB_OID_RSASIGNATURE_RIPEMD160_STR = #$2B#$24#$03#$03#$01#$02;
  SB_OID_TSTINFO_STR      = #$2a#$86#$48#$86#$f7#$0d#$01#$09#$10#$01#$04;
  SB_OID_AES128_CBC_STR     = #$60#$86#$48#$01#$65#$03#$04#$01#$02;
  SB_OID_AES192_CBC_STR     = #$60#$86#$48#$01#$65#$03#$04#$01#$16;
  SB_OID_AES256_CBC_STR     = #$60#$86#$48#$01#$65#$03#$04#$01#$2A;
  SB_OID_SERPENT128_CBC_STR = #$2B#$06#$01#$04#$01#$DA#$47#$0D#$02#$02;
  SB_OID_SERPENT192_CBC_STR = #$2B#$06#$01#$04#$01#$DA#$47#$0D#$02#$16;
  SB_OID_SERPENT256_CBC_STR = #$2B#$06#$01#$04#$01#$DA#$47#$0D#$02#$2A;
  SB_OID_CAST5_CBC_STR      = #$2A#$86#$48#$86#$F6#$7D#$07#$42#$0A;
  SB_OID_BLOWFISH_CBC_STR   = #$2B#$06#$01#$04#$01#$97#$55#$01#$01#$02;
  SB_OID_CAMELLIA128_CBC_STR = #$2A#$83#$08#$8C#$9A#$4B#$3D#$01#$01#$01#$02;
  SB_OID_CAMELLIA192_CBC_STR = #$2A#$83#$08#$8C#$9A#$4B#$3D#$01#$01#$01#$03;
  SB_OID_CAMELLIA256_CBC_STR = #$2A#$83#$08#$8C#$9A#$4B#$3D#$01#$01#$01#$04;
  SB_OID_SEED_STR           = #$2A#$83#$1A#$8C#$9A#$44#$01#$04#$05#$00;
  SB_OID_RABBIT_STR         = #$00;
  SB_OID_IDENTITY_STR       = 'identity@eldos.com'; // special fake OID value
  SB_OID_IDENTITY_ELDOS_STR = #$2B#$06#$01#$04#$01#$82#$90#$22#$02#$03#$01;
  SB_OID_TWOFISH128_ELDOS_STR = #$2B#$06#$01#$04#$01#$82#$90#$22#$02#$03#$05;
  SB_OID_TWOFISH256_ELDOS_STR = #$2B#$06#$01#$04#$01#$82#$90#$22#$02#$03#$06;
  SB_OID_TWOFISH192_ELDOS_STR = #$2B#$06#$01#$04#$01#$82#$90#$22#$02#$03#$07;
  // ISO 9796
  SB_OID_RSASIGNATURE_RIPEMD160_ISO9796_STR = #$2B#$24#$03#$04#$03#$02#$02;
  SB_OID_WHIRLPOOL_RSAENCRYPTION_ELDOS_STR = #$2B#$06#$01#$04#$01#$82#$90#$22#$02#$02#$01;

  //mask generation function
  SB_OID_MGF1_STR           = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$08;

  SB_OID_MGF1_SHA1_STR = 'mgf1-sha1@eldos.com';
  SB_OID_MGF1_SHA224_STR = 'mgf1-sha224@eldos.com';
  SB_OID_MGF1_SHA256_STR = 'mgf1-sha256@eldos.com';
  SB_OID_MGF1_SHA384_STR = 'mgf1-sha384@eldos.com';
  SB_OID_MGF1_SHA512_STR = 'mgf1-sha512@eldos.com';
  SB_OID_MGF1_RIPEMD160_STR = 'mgf1-ripemd160@eldos.com';
  SB_OID_MGF1_WHIRLPOOL_STR = 'mgf1-whirlpool@eldos.com';

  //label source function for RSA-OAEP
  SB_OID_OAEP_SRC_SPECIFIED_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$09;
  //PKCS#5 password-based encryption
  SB_OID_PBE_MD2_DES_STR    = #$2a#$86#$48#$86#$f7#$0d#$01#$05#$01;
  SB_OID_PBE_MD2_RC2_STR    = #$2a#$86#$48#$86#$f7#$0d#$01#$05#$04;
  SB_OID_PBE_MD5_DES_STR    = #$2a#$86#$48#$86#$f7#$0d#$01#$05#$03;
  SB_OID_PBE_MD5_RC2_STR    = #$2a#$86#$48#$86#$f7#$0d#$01#$05#$03;
  SB_OID_PBE_SHA1_DES_STR   = #$2a#$86#$48#$86#$f7#$0d#$01#$05#$0A;
  SB_OID_PBE_SHA1_RC2_STR   = #$2a#$86#$48#$86#$f7#$0d#$01#$05#$0B;
  SB_OID_PBES2_STR          = #$2a#$86#$48#$86#$f7#$0d#$01#$05#$0D;
  SB_OID_PBKDF2_STR         = #$2a#$86#$48#$86#$f7#$0d#$01#$05#$0C;
  SB_OID_PBMAC1_STR         = #$2a#$86#$48#$86#$f7#$0d#$01#$05#$0E;

  //PKCS#12
  SB_OID_PBE_SHA1_RC4_128_STR = #$2a#$86#$48#$86#$f7#$0d#$01#$0c#$01#$01;
  SB_OID_PBE_SHA1_RC4_40_STR = #$2a#$86#$48#$86#$f7#$0d#$01#$0c#$01#$02;
  SB_OID_PBE_SHA1_3DES_STR  = #$2a#$86#$48#$86#$f7#$0d#$01#$0c#$01#$03;
  SB_OID_PBE_SHA1_RC2_128_STR = #$2a#$86#$48#$86#$f7#$0d#$01#$0c#$01#$05;
  SB_OID_PBE_SHA1_RC2_40_STR = #$2a#$86#$48#$86#$f7#$0d#$01#$0c#$01#$06;
  SB_OID_MD2_RSAENCRYPTION_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$02;
  SB_OID_MD4_RSAENCRYPTION_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$03;
  SB_OID_MD5_RSAENCRYPTION_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$04;
  SB_OID_SHA1_RSA_STR       = #$2B#$0E#$03#$02#$1D;
  SB_OID_SHA1_DSA_STR       = #$2A#$86#$48#$CE#$38#$04#$03;

  // PKCS#15
  SB_OID_PKCS15_STR         = #$2A#$86#$48#$86#$F7#$0D#$01#$0F#$03#$01;
  SB_OID_PWRI_KEK_STR       = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$03#$09;
  SB_OID_DATA_STR           = #$2A#$86#$48#$86#$F7#$0D#$01#$07#$01;

  // Digest Algorithm OIDs
  SB_OID_MD2_STR            = #$2a#$86#$48#$86#$f7#$0d#$02#$02;
  SB_OID_MD4_STR            = #$2a#$86#$48#$86#$f7#$0d#$02#$04;
  SB_OID_MD5_STR            = #$2a#$86#$48#$86#$f7#$0d#$02#$05;
  SB_OID_SHA1_STR           = #$2b#$0E#$03#$02#$1A;
  SB_OID_SHA224_STR         = #$60#$86#$48#$01#$65#$03#$04#$02#$04;
  SB_OID_SHA256_STR         = #$60#$86#$48#$01#$65#$03#$04#$02#$01;
  SB_OID_SHA384_STR         = #$60#$86#$48#$01#$65#$03#$04#$02#$02;
  SB_OID_SHA512_STR         = #$60#$86#$48#$01#$65#$03#$04#$02#$03;
  SB_OID_RIPEMD160_STR      = #$2B#$24#$03#$02#$01;
  SB_OID_SSL3_STR           = 'ssl-hash@eldos.com';
  SB_OID_WHIRLPOOL_STR      = #$28#$CF#$06#$03#$00#$37;

  // MAC Algorithm OIDs
  SB_OID_HMACSHA1_STR       = #$2B#$06#$01#$05#$05#$08#$01#$02;
  SB_OID_HMACSHA1_PKCS_STR  = #$2a#$86#$48#$86#$f7#$0d#$02#$07;
  SB_OID_HMACSHA224_STR     = #$2B#$06#$01#$05#$05#$08#$01#$08;
  SB_OID_HMACSHA256_STR     = #$2B#$06#$01#$05#$05#$08#$01#$09;
  SB_OID_HMACSHA384_STR     = #$2B#$06#$01#$05#$05#$08#$01#$0A;
  SB_OID_HMACSHA512_STR     = #$2B#$06#$01#$05#$05#$08#$01#$0B;
  SB_OID_RSA_HMACSHA1_STR   = #$2a#$86#$48#$86#$F7#$0D#$02#$07; // a copy of SB_OID_HMACSHA1_PKCS

  // UMAC
  SB_OID_UMAC32_STR         = 'umac32@eldos.com';
  SB_OID_UMAC64_STR         = 'umac64@eldos.com';
  SB_OID_UMAC96_STR         = 'umac96@eldos.com';
  SB_OID_UMAC128_STR        = 'umac128@eldos.com';

  // Attribute OIDs
  SB_OID_CONTENT_TYPE_STR   = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$03;
  SB_OID_MESSAGE_DIGEST_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$04;
  SB_OID_SIGNING_TIME_STR   = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$05;
  SB_OID_COUNTER_SIGNATURE_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$06;
  SB_OID_SMIME_CAPABILITIES_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$0F;
  SB_OID_TIMESTAMP_TOKEN_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$0E;
  SB_OID_SIGNING_CERTIFICATE_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$0C;
  SB_OID_SIGNING_CERTIFICATEV2_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$2F;
  SB_OID_CONTENT_HINTS_STR  = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$04;
  SB_OID_CONTENT_IDENTIFIER_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$07;
  SB_OID_CONTENT_REFERENCE_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$0A;
  SB_OID_SIGNATURE_POLICY_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$0F;
  SB_OID_COMMITMENT_TYPE_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$10;
  SB_OID_SIGNER_LOCATION_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$11;
  SB_OID_SIGNER_ATTRIBUTES_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$12;
  SB_OID_CONTENT_TIMESTAMP_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$14;
  SB_OID_CERTIFICATE_REFS_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$15;
  SB_OID_REVOCATION_REFS_STR  = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$16;
  SB_OID_CERTIFICATE_VALUES_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$17;
  SB_OID_REVOCATION_VALUES_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$18;
  SB_OID_ESCTIMESTAMP_STR   = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$19;
  SB_OID_CERTCRLTIMESTAMP_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$1A;
  SB_OID_ARCHIVETIMESTAMP_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$1B;
  SB_OID_ARCHIVETIMESTAMP2_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$02#$30;
  SB_OID_ARCHIVETIMESTAMP3_STR = #$04#$00#$8D#$45#$02#$04;
  SB_OID_ATSHASHINDEX_STR   = #$04#$00#$8D#$45#$02#$05;

  // Authenticode OIDs
  SB_OID_SPC_INDIRECT_DATA_STR  = #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$04;
  SB_OID_SPC_SP_AGENCY_INFO_STR = #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$0A;
  SB_OID_SPC_STATEMENT_TYPE_OBJID_STR = #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$0A;
  SB_OID_SPC_STATEMENT_TYPE_STR = #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$0B;
  SB_OID_SPC_SP_OPUS_INFO_STR   = #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$0C;
  SB_OID_SPC_PE_IMAGE_DATA_STR  = #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$0F;
  SB_OID_SPC_MINIMAL_CRITERIA_STR = #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$1A;
  SB_OID_SPC_FINANCIAL_CRITERIA_STR = #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$1B;
  SB_OID_SPC_LINK_STR           = #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$1C;
  SB_OID_SPC_HASH_INFO_STR      = #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$1D;
  SB_OID_SPC_SIPINFO_STR        = #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$1E;
  SB_OID_SPC_CERT_EXTENSIONS_STR = #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$0E;
  SB_OID_SPC_RAW_FILE_DATA_STR  = #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$12;
  SB_OID_SPC_STRUCTURED_STORAGE_DATA_STR = #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$13;
  SB_OID_SPC_JAVA_CLASS_DATA_STR = #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$14;
  SB_OID_SPC_INDIVIDUAL_SP_KEY_PURPOSE_STR = #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$15;
  SB_OID_SPC_COMMERCIAL_SP_KEY_PURPOSE_STR = #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$16;
  SB_OID_SPC_CAB_DATA_STR       = #$2B#$06#$01#$04#$01#$82#$37#$02#$01#$19;
  // certificate extension OIDs
  SB_OID_QT_CPS_STR             = #$2B#$06#$01#$05#$05#$07#$02#$01;
  SB_OID_QT_UNOTICE_STR         = #$2B#$06#$01#$05#$05#$07#$02#$02;
  SB_OID_SERVER_AUTH_STR        = #$2B#$06#$01#$05#$05#$07#$03#$01;
  SB_OID_CLIENT_AUTH_STR        = #$2B#$06#$01#$05#$05#$07#$03#$02;
  SB_OID_CODE_SIGNING_STR       = #$2B#$06#$01#$05#$05#$07#$03#$03;
  SB_OID_EMAIL_PROT_STR         = #$2B#$06#$01#$05#$05#$07#$03#$04;
  SB_OID_TIME_STAMPING_STR      = #$2B#$06#$01#$05#$05#$07#$03#$08;
  SB_OID_OCSP_SIGNING_STR       = #$2B#$06#$01#$05#$05#$07#$03#$09;

  SB_OID_ACCESS_METHOD_OCSP_STR = #$2B#$06#$01#$05#$05#$07#$30#$01;
  SB_OID_ACCESS_METHOD_CAISSUER_STR = #$2B#$06#$01#$05#$05#$07#$30#$02;

  SB_OID_UNSTRUCTURED_NAME_STR  = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$02;

  SB_OID_CERT_EXTENSIONS_STR    = #$2a#$86#$48#$86#$f7#$0d#$01#$09#$0e;
  SB_OID_CERT_EXTENSIONS_MS_STR = #$2b#$06#$01#$04#$01#$82#$37#$02#$01#$0e;

  // GOST algorithms
  SB_OID_GOST_28147_1989_STR           = #$2A#$85#$03#$02#$02#$15;
  SB_OID_GOST_28147_1989_MAC_STR       = #$2A#$85#$03#$02#$02#$16;
  SB_OID_GOST_R3410_2001_STR           = #$2A#$85#$03#$02#$02#$13;
  SB_OID_GOST_R3410_1994_STR           = #$2A#$85#$03#$02#$02#$14;
  SB_OID_GOST_R3410_1994_DH_STR        = #$2A#$85#$03#$02#$02#$63;
  SB_OID_GOST_R3411_1994_WITH_GOST_R3410_2001_STR = #$2A#$85#$03#$02#$02#$03;
  SB_OID_GOST_R3411_1994_WITH_GOST_R3410_1994_STR = #$2A#$85#$03#$02#$02#$04;
  SB_OID_GOST_R3411_1994_STR           = #$2A#$85#$03#$02#$02#$09;
  SB_OID_GOST_R3411_1994_HMAC_STR      = #$2A#$85#$03#$02#$02#$0A;

  // GOST algorithm parameters
  // CryptoPro RFC 4357 GOST 28147-89 parameters
  SB_OID_GOST_28147_1989_PARAM_CP_TEST_STR  = #$2A#$85#$03#$02#$02#$1F#$00;
  SB_OID_GOST_28147_1989_PARAM_CP_A_STR     = #$2A#$85#$03#$02#$02#$1F#$01;
  SB_OID_GOST_28147_1989_PARAM_CP_B_STR     = #$2A#$85#$03#$02#$02#$1F#$02;
  SB_OID_GOST_28147_1989_PARAM_CP_C_STR     = #$2A#$85#$03#$02#$02#$1F#$03;
  SB_OID_GOST_28147_1989_PARAM_CP_D_STR     = #$2A#$85#$03#$02#$02#$1F#$04;
  SB_OID_GOST_28147_1989_PARAM_CP_OSCAR_11_STR = #$2A#$85#$03#$02#$02#$1F#$05;
  SB_OID_GOST_28147_1989_PARAM_CP_OSCAR_10_STR = #$2A#$85#$03#$02#$02#$1F#$06;
  SB_OID_GOST_28147_1989_PARAM_CP_RIC_1_STR = #$2A#$85#$03#$02#$02#$1F#$07;
  // CryptoPro RFC 4357 GOST R 34.11-94 parameters
  SB_OID_GOST_R3411_1994_PARAM_CP_TEST_STR  = #$2A#$85#$03#$02#$02#$1E#$00;
  SB_OID_GOST_R3411_1994_PARAM_CP_STR       = #$2A#$85#$03#$02#$02#$1E#$01;
  // CryptoPro RFC 4357 GOST R 34.10-94 parameters
  SB_OID_GOST_R3410_1994_PARAM_CP_TEST_STR  = #$2A#$85#$03#$02#$02#$20#$00;
  SB_OID_GOST_R3410_1994_PARAM_CP_A_STR     = #$2A#$85#$03#$02#$02#$20#$02;
  SB_OID_GOST_R3410_1994_PARAM_CP_B_STR     = #$2A#$85#$03#$02#$02#$20#$03;
  SB_OID_GOST_R3410_1994_PARAM_CP_C_STR     = #$2A#$85#$03#$02#$02#$20#$04;
  SB_OID_GOST_R3410_1994_PARAM_CP_D_STR     = #$2A#$85#$03#$02#$02#$20#$05;
  SB_OID_GOST_R3410_1994_PARAM_CP_XCHA_STR  = #$2A#$85#$03#$02#$02#$20#$01;
  SB_OID_GOST_R3410_1994_PARAM_CP_XCHB_STR  = #$2A#$85#$03#$02#$02#$20#$02;
  SB_OID_GOST_R3410_1994_PARAM_CP_XCHC_STR  = #$2A#$85#$03#$02#$02#$20#$03;
  // CryptoPro RFC 4357 GOST R 34.10-2001 parameters are represented by curves below

  // EC-related OIDs

  // EC field OIDs
  SB_OID_FLD_CUSTOM_STR         = 'fld-custom@eldos.com';
  SB_OID_FLD_TYPE_FP_STR        = #$2A#$86#$48#$CE#$3D#$01#$01;
  SB_OID_FLD_TYPE_F2M_STR       = #$2A#$86#$48#$CE#$3D#$01#$02;
  SB_OID_FLD_BASIS_N_STR        = #$2A#$86#$48#$CE#$3D#$01#$02#$03#$01;
  SB_OID_FLD_BASIS_T_STR        = #$2A#$86#$48#$CE#$3D#$01#$02#$03#$02;
  SB_OID_FLD_BASIS_P_STR        = #$2A#$86#$48#$CE#$3D#$01#$02#$03#$03;

  // EC key types
  SB_OID_EC_KEY_STR             = #$2A#$86#$48#$CE#$3D#$02#$01;
  SB_OID_ECDH_STR               = #$2B#$81#$04#$01#$0C;
  SB_OID_ECMQV_STR              = #$2B#$81#$04#$01#$0D;

  // ECDSA X9.62 signature algorithms
  SB_OID_ECDSA_SHA1_STR         = #$2a#$86#$48#$CE#$3D#$04#$01;
  SB_OID_ECDSA_RECOMMENDED_STR  = #$2a#$86#$48#$CE#$3D#$04#$02;
  SB_OID_ECDSA_SHA224_STR       = #$2a#$86#$48#$CE#$3D#$04#$03#$01;
  SB_OID_ECDSA_SHA256_STR       = #$2a#$86#$48#$CE#$3D#$04#$03#$02;
  SB_OID_ECDSA_SHA384_STR       = #$2a#$86#$48#$CE#$3D#$04#$03#$03;
  SB_OID_ECDSA_SHA512_STR       = #$2a#$86#$48#$CE#$3D#$04#$03#$04;
  SB_OID_ECDSA_SPECIFIED_STR    = #$2a#$86#$48#$CE#$3D#$04#$03;

  // ECDSA signature algorithm, German BSI Technical Guideline TR-03111
  SB_OID_ECDSA_PLAIN_SHA1_STR     = #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$01;
  SB_OID_ECDSA_PLAIN_SHA224_STR   = #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$02;
  SB_OID_ECDSA_PLAIN_SHA256_STR   = #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$03;
  SB_OID_ECDSA_PLAIN_SHA384_STR   = #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$04;
  SB_OID_ECDSA_PLAIN_SHA512_STR   = #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$05;
  SB_OID_ECDSA_PLAIN_RIPEMD160_STR = #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$06;

  // Known elliptic curve OIDs
  // fake OID to represent custom EC
  SB_OID_EC_CUSTOM_STR          = 'ec-custom@eldos.com';

  // X9.62 curves
  { recommended curves over the binary fields }
  SB_OID_EC_C2PNB163V1_STR      = #$2a#$86#$48#$CE#$3D#$03#$00#$01;
  SB_OID_EC_C2PNB163V2_STR      = #$2a#$86#$48#$CE#$3D#$03#$00#$02;
  SB_OID_EC_C2PNB163V3_STR      = #$2a#$86#$48#$CE#$3D#$03#$00#$03;
  SB_OID_EC_C2PNB176W1_STR      = #$2a#$86#$48#$CE#$3D#$03#$00#$04;
  SB_OID_EC_C2TNB191V1_STR      = #$2a#$86#$48#$CE#$3D#$03#$00#$05;
  SB_OID_EC_C2TNB191V2_STR      = #$2a#$86#$48#$CE#$3D#$03#$00#$06;
  SB_OID_EC_C2TNB191V3_STR      = #$2a#$86#$48#$CE#$3D#$03#$00#$07;
  SB_OID_EC_C2ONB191V4_STR      = #$2a#$86#$48#$CE#$3D#$03#$00#$08;
  SB_OID_EC_C2ONB191V5_STR      = #$2a#$86#$48#$CE#$3D#$03#$00#$09;
  SB_OID_EC_C2PNB208W1_STR      = #$2a#$86#$48#$CE#$3D#$03#$00#$0A;
  SB_OID_EC_C2TNB239V1_STR      = #$2a#$86#$48#$CE#$3D#$03#$00#$0B;
  SB_OID_EC_C2TNB239V2_STR      = #$2a#$86#$48#$CE#$3D#$03#$00#$0C;
  SB_OID_EC_C2TNB239V3_STR      = #$2a#$86#$48#$CE#$3D#$03#$00#$0D;
  SB_OID_EC_C2ONB239V4_STR      = #$2a#$86#$48#$CE#$3D#$03#$00#$0E;
  SB_OID_EC_C2ONB239V5_STR      = #$2a#$86#$48#$CE#$3D#$03#$00#$0F;
  SB_OID_EC_C2PNB272W1_STR      = #$2a#$86#$48#$CE#$3D#$03#$00#$10;
  SB_OID_EC_C2PNB304W1_STR      = #$2a#$86#$48#$CE#$3D#$03#$00#$11;
  SB_OID_EC_C2TNB359V1_STR      = #$2a#$86#$48#$CE#$3D#$03#$00#$12;
  SB_OID_EC_C2PNB368W1_STR      = #$2a#$86#$48#$CE#$3D#$03#$00#$13;
  SB_OID_EC_C2TNB431R1_STR      = #$2a#$86#$48#$CE#$3D#$03#$00#$14;
  { recommended curves over the prime field }
  SB_OID_EC_PRIME192V1_STR      = #$2a#$86#$48#$CE#$3D#$03#$01#$01;
  SB_OID_EC_PRIME192V2_STR      = #$2a#$86#$48#$CE#$3D#$03#$01#$02;
  SB_OID_EC_PRIME192V3_STR      = #$2a#$86#$48#$CE#$3D#$03#$01#$03;
  SB_OID_EC_PRIME239V1_STR      = #$2a#$86#$48#$CE#$3D#$03#$01#$04;
  SB_OID_EC_PRIME239V2_STR      = #$2a#$86#$48#$CE#$3D#$03#$01#$05;
  SB_OID_EC_PRIME239V3_STR      = #$2a#$86#$48#$CE#$3D#$03#$01#$06;
  SB_OID_EC_PRIME256V1_STR      = #$2a#$86#$48#$CE#$3D#$03#$01#$07;
  // SEC2 curves
  { SEC2 recommended curves over a prime field }
  SB_OID_EC_SECP112R1_STR       = #$2b#$81#$04#$00#$06;
  SB_OID_EC_SECP112R2_STR       = #$2b#$81#$04#$00#$07;
  SB_OID_EC_SECP128R1_STR       = #$2b#$81#$04#$00#$1C;
  SB_OID_EC_SECP128R2_STR       = #$2b#$81#$04#$00#$1D;
  SB_OID_EC_SECP160K1_STR       = #$2b#$81#$04#$00#$09;
  SB_OID_EC_SECP160R1_STR       = #$2b#$81#$04#$00#$08;
  SB_OID_EC_SECP160R2_STR       = #$2b#$81#$04#$00#$1E;
  SB_OID_EC_SECP192K1_STR       = #$2b#$81#$04#$00#$1F;
                              // SECP192R1 is the same as PRIME192V1
  SB_OID_EC_SECP192R1_STR       = #$2a#$86#$48#$CE#$3D#$03#$01#$01;
  SB_OID_EC_SECP224K1_STR       = #$2b#$81#$04#$00#$20;
  SB_OID_EC_SECP224R1_STR       = #$2b#$81#$04#$00#$21;
  SB_OID_EC_SECP256K1_STR       = #$2b#$81#$04#$00#$0A;
                              // SECP256R1 is the same as PRIME256V1
  SB_OID_EC_SECP256R1_STR       = #$2a#$86#$48#$CE#$3D#$03#$01#$07;
  SB_OID_EC_SECP384R1_STR       = #$2b#$81#$04#$00#$22;
  SB_OID_EC_SECP521R1_STR       = #$2b#$81#$04#$00#$23;
  { SEC2 recommended curves over extended binary field }
  SB_OID_EC_SECT113R1_STR       = #$2b#$81#$04#$00#$04;
  SB_OID_EC_SECT113R2_STR       = #$2b#$81#$04#$00#$05;
  SB_OID_EC_SECT131R1_STR       = #$2b#$81#$04#$00#$16;
  SB_OID_EC_SECT131R2_STR       = #$2b#$81#$04#$00#$17;
  SB_OID_EC_SECT163K1_STR       = #$2b#$81#$04#$00#$01;
  SB_OID_EC_SECT163R1_STR       = #$2b#$81#$04#$00#$02;
  SB_OID_EC_SECT163R2_STR       = #$2b#$81#$04#$00#$0f;
  SB_OID_EC_SECT193R1_STR       = #$2b#$81#$04#$00#$18;
  SB_OID_EC_SECT193R2_STR       = #$2b#$81#$04#$00#$19;
  SB_OID_EC_SECT233K1_STR       = #$2b#$81#$04#$00#$1A;
  SB_OID_EC_SECT233R1_STR       = #$2b#$81#$04#$00#$1B;
  SB_OID_EC_SECT239K1_STR       = #$2b#$81#$04#$00#$03;
  SB_OID_EC_SECT283K1_STR       = #$2b#$81#$04#$00#$10;
  SB_OID_EC_SECT283R1_STR       = #$2b#$81#$04#$00#$11;
  SB_OID_EC_SECT409K1_STR       = #$2b#$81#$04#$00#$24;
  SB_OID_EC_SECT409R1_STR       = #$2b#$81#$04#$00#$25;
  SB_OID_EC_SECT571K1_STR       = #$2b#$81#$04#$00#$26;
  SB_OID_EC_SECT571R1_STR       = #$2b#$81#$04#$00#$27;

  { GOST 34.11-2001 RFC 4357 (CryptoPro) curves }
  SB_OID_EC_GOST_CP_TEST_STR    = #$2A#$85#$03#$02#$02#$23#$00;
  SB_OID_EC_GOST_CP_A_STR       = #$2A#$85#$03#$02#$02#$23#$01;
  SB_OID_EC_GOST_CP_B_STR       = #$2A#$85#$03#$02#$02#$23#$02;
  SB_OID_EC_GOST_CP_C_STR       = #$2A#$85#$03#$02#$02#$23#$03;
  SB_OID_EC_GOST_CP_XCHA_STR    = #$2A#$85#$03#$02#$02#$24#$00;
  SB_OID_EC_GOST_CP_XCHB_STR    = #$2A#$85#$03#$02#$02#$24#$01;

  { EldoS Corporation dedicated OIDs }
  SB_OID_ELDOSCORP_BASE_STR     = #$2B#$06#$01#$04#$01#$82#$90#$22; // 1.3.6.1.4.1.34850
  { all direct sub-OIDs (first-level sub-OIDs) must be defined here to prevent conflicts }
  SB_OID_ELDOS_PKI_STR          = #$2B#$06#$01#$04#$01#$82#$90#$22#$01;
  SB_OID_ELDOS_ALGS_STR         = #$2B#$06#$01#$04#$01#$82#$90#$22#$02;
  SB_OID_ELDOS_DATASTORAGE_STR  = #$2B#$06#$01#$04#$01#$82#$90#$22#$07;

  SB_OID_ELDOS_ALGS_NULL_STR    = #$2B#$06#$01#$04#$01#$82#$90#$22#$02#$01;
  SB_OID_ELDOS_ALGS_PKEY_STR    = #$2B#$06#$01#$04#$01#$82#$90#$22#$02#$02;
  SB_OID_ELDOS_ALGS_SKEY_STR    = #$2B#$06#$01#$04#$01#$82#$90#$22#$02#$03;
  SB_OID_ELDOS_ALGS_DGST_STR    = #$2B#$06#$01#$04#$01#$82#$90#$22#$02#$04;
  SB_OID_ELDOS_ALGS_HMAC_STR    = #$2B#$06#$01#$04#$01#$82#$90#$22#$02#$05;
  SB_OID_ELDOS_ALGS_COMPR_STR   = #$2B#$06#$01#$04#$01#$82#$90#$22#$02#$06;


  SB_CERT_OID_COMMON_NAME_STR          = #$55#$04#$03;
  SB_CERT_OID_SURNAME_STR              = #$55#$04#$04;
  SB_CERT_OID_COUNTRY_STR              = #$55#$04#$06;
  SB_CERT_OID_LOCALITY_STR             = #$55#$04#$07;
  SB_CERT_OID_STATE_OR_PROVINCE_STR    = #$55#$04#$08;
  SB_CERT_OID_ORGANIZATION_STR         = #$55#$04#$0A;
  SB_CERT_OID_ORGANIZATION_UNIT_STR    = #$55#$04#$0B;
  SB_CERT_OID_TITLE_STR                = #$55#$04#$0C;
  SB_CERT_OID_NAME_STR                 = #$55#$04#$29;
  SB_CERT_OID_GIVEN_NAME_STR           = #$55#$04#$2A;
  SB_CERT_OID_INITIALS_STR             = #$55#$04#$2B;
  SB_CERT_OID_GENERATION_QUALIFIER_STR = #$55#$04#$2C;
  SB_CERT_OID_DN_QUALIFIER_STR         = #$55#$04#$2E;
  SB_CERT_OID_EMAIL_STR                = #$2a#$86#$48#$86#$f7#$0d#$01#$09#$01;

  SB_CERT_OID_STREET_ADDRESS_STR       = #$55#$04#$09;
  SB_CERT_OID_POSTAL_ADDRESS_STR       = #$55#$04#$10;
  SB_CERT_OID_POSTAL_CODE_STR          = #$55#$04#$11;
  SB_CERT_OID_POST_OFFICE_BOX_STR      = #$55#$04#$12;
  SB_CERT_OID_PHYSICAL_DELIVERY_OFFICE_NAME_STR = #$55#$04#$13;
  SB_CERT_OID_TELEPHONE_NUMBER_STR     = #$55#$04#$14;
  SB_CERT_OID_TELEX_NUMBER_STR         = #$55#$04#$15;
  SB_CERT_OID_TELEX_TERMINAL_ID_STR    = #$55#$04#$16;
  SB_CERT_OID_FACIMILE_PHONE_NUMBER_STR = #$55#$04#$17;

  SB_CERT_OID_X12_ADDRESS_STR          = #$55#$04#$18;
  SB_CERT_OID_INTERNATIONAL_ISDN_NUMBER_STR = #$55#$04#$19;
  SB_CERT_OID_REGISTERED_ADDRESS_STR   = #$55#$04#$1A;
  SB_CERT_OID_DESTINATION_INDICATOR_STR = #$55#$04#$1B;
  SB_CERT_OID_PREFERRED_DELIVERY_METHOD_STR = #$55#$04#$1C;
  SB_CERT_OID_PRESENTATION_ADDRESS_STR = #$55#$04#$1D;
  SB_CERT_OID_SUPPORTED_APPLICATION_CONTEXT_STR = #$55#$04#$1E;
  SB_CERT_OID_MEMBER_STR            = #$55#$04#$1F;
  SB_CERT_OID_OWNER_STR             = #$55#$04#$20;
  SB_CERT_OID_ROLE_OCCUPENT_STR        = #$55#$04#$21;
  SB_CERT_OID_SEE_ALSO_STR             = #$55#$04#$22;
  SB_CERT_OID_USER_PASSWORD_STR        = #$55#$04#$23;
  SB_CERT_OID_USER_CERTIFICATE_STR     = #$55#$04#$24;
  SB_CERT_OID_CA_CERTIFICATE_STR       = #$55#$04#$25;
  SB_CERT_OID_AUTHORITY_REVOCATION_LIST_STR = #$55#$04#$26;
  SB_CERT_OID_CERTIFICATE_REVOCATION_LIST_STR = #$55#$04#$27;
  SB_CERT_OID_CERTIFICATE_PAIR_STR     = #$55#$04#$28;
  SB_CERT_OID_UNIQUE_IDENTIFIER_STR    = #$55#$04#$2D;
  SB_CERT_OID_ENHANCED_SEARCH_GUIDE_STR = #$55#$04#$2F;

  SB_CERT_OID_OBJECT_CLASS_STR         = #$55#$04#$00;
  SB_CERT_OID_ALIASED_ENTRY_NAME_STR   = #$55#$04#$01;
  SB_CERT_OID_KNOWLEDGE_INFORMATION_STR = #$55#$04#$02;
  SB_CERT_OID_SERIAL_NUMBER_STR        = #$55#$04#$05;
  SB_CERT_OID_DESCRIPTION_STR          = #$55#$04#$0D;
  SB_CERT_OID_SEARCH_GUIDE_STR         = #$55#$04#$0E;
  SB_CERT_OID_BUSINESS_CATEGORY_STR    = #$55#$04#$0F;
  SB_CERT_OID_PROTOCOL_INFORMATION_STR = #$55#$04#$30;
  SB_CERT_OID_DISTINGUISHED_NAME_STR   = #$55#$04#$31;
  SB_CERT_OID_UNIQUE_MEMBER_STR        = #$55#$04#$32;
  SB_CERT_OID_HOUSE_IDENTIFIER_STR     = #$55#$04#$33;
  SB_CERT_OID_SUPPORTED_ALGORITHMS_STR = #$55#$04#$34;
  SB_CERT_OID_DELTA_REVOCATION_LIST_STR = #$55#$04#$35;
  SB_CERT_OID_ATTRIBUTE_CERTIFICATE_STR = #$55#$04#$3A;
  SB_CERT_OID_PSEUDONYM_STR            = #$55#$04#$41;

  SB_CERT_OID_PERMANENT_IDENTIFIER_STR = #$2b#$06#$01#$05#$05#$07#$00#$12#$08#$03;

  SB_CERT_OID_USER_ID_STR              = #$9#$92#$26#$89#$93#$F2#$2C#$64#$1#$1;
  SB_CERT_OID_DOMAIN_COMPONENT_STR     = #$9#$92#$26#$89#$93#$F2#$2C#$64#$1#$19;

  SB_CERT_OID_CA_OCSP_STR              = #$2b#$06#$01#$05#$05#$07#$30#$01;
  SB_CERT_OID_CA_ISSUER_STR            = #$2b#$06#$01#$05#$05#$07#$30#$02;


  SB_CERT_OID_RSAENCRYPTION_STR        = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$01;
  SB_CERT_OID_RSAOAEP_STR              = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$07;
  SB_CERT_OID_RSAPSS_STR               = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$0A;
  SB_CERT_OID_DSA_STR                  = #$2A#$86#$48#$CE#$38#$04#$01;
  SB_CERT_OID_DH_STR                   = #$2A#$86#$48#$CE#$3E#$02#$01;
  SB_CERT_OID_DSA_SHA1_STR             = #$2A#$86#$48#$CE#$38#$04#$03;
  SB_CERT_OID_DSA_SHA224_STR           = #$2A#$86#$48#$CE#$38#$04#$03;
  SB_CERT_OID_DSA_SHA256_STR           = #$2A#$86#$48#$CE#$38#$04#$03;
  SB_CERT_OID_MD2_RSAENCRYPTION_STR    = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$02;
  SB_CERT_OID_MD5_RSAENCRYPTION_STR    = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$04;
  SB_CERT_OID_SHA1_RSAENCRYPTION_STR   = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$05;
  SB_CERT_OID_SHA224_RSAENCRYPTION_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$0E;
  SB_CERT_OID_SHA256_RSAENCRYPTION_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$0B;
  SB_CERT_OID_SHA384_RSAENCRYPTION_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$0C;
  SB_CERT_OID_SHA512_RSAENCRYPTION_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$01#$0D;

  SB_CERT_OID_ECDSA_SHA1_STR           = #$2A#$86#$48#$CE#$3D#$04#$01;
  SB_CERT_OID_ECDSA_RECOMMENDED_STR    = #$2A#$86#$48#$CE#$3D#$04#$02;
  SB_CERT_OID_ECDSA_SHA224_STR         = #$2A#$86#$48#$CE#$3D#$04#$03#$01;
  SB_CERT_OID_ECDSA_SHA256_STR         = #$2A#$86#$48#$CE#$3D#$04#$03#$02;
  SB_CERT_OID_ECDSA_SHA384_STR         = #$2A#$86#$48#$CE#$3D#$04#$03#$03;
  SB_CERT_OID_ECDSA_SHA512_STR         = #$2A#$86#$48#$CE#$3D#$04#$03#$04;
  SB_CERT_OID_ECDSA_SPECIFIED_STR      = #$2a#$86#$48#$CE#$3D#$04#$03;

  { Signature algorithms, defined in German BSI Technical Guideline TR-03111 }
  SB_CERT_OID_ECDSA_PLAIN_SHA1_STR     = #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$01;
  SB_CERT_OID_ECDSA_PLAIN_SHA224_STR   = #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$02;
  SB_CERT_OID_ECDSA_PLAIN_SHA256_STR   = #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$03;
  SB_CERT_OID_ECDSA_PLAIN_SHA384_STR   = #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$04;
  SB_CERT_OID_ECDSA_PLAIN_SHA512_STR   = #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$05;
  SB_CERT_OID_ECDSA_PLAIN_RIPEMD160_STR = #$04#$00#$7F#$00#$07#$01#$01#$04#$01#$06;

  SB_CERT_OID_GOST_R3410_1994_STR      = #$2A#$85#$03#$02#$02#$14;
  SB_CERT_OID_GOST_R3410_2001_STR      = #$2A#$85#$03#$02#$02#$13;
  SB_CERT_OID_GOST_R3411_WITH_GOST3410_1994_STR = #$2A#$85#$03#$02#$02#$04;
  SB_CERT_OID_GOST_R3411_WITH_GOST3410_2001_STR = #$2A#$85#$03#$02#$02#$03;

  SB_CERT_OID_SHA1_RSA_STR             = #$2B#$0E#$03#$02#$1D;
  SB_CERT_OID_SHA1_DSA_STR             = #$2A#$86#$48#$CE#$38#$04#$03;
  SB_CERT_OID_SHA1_STR                 = #$2B#$0E#$03#$02#$1A;
  SB_CERT_OID_MD2_STR                  = #$2A#$86#$48#$86#$F7#$0D#$02#$02;
  SB_CERT_OID_MD5_STR                  = #$2A#$86#$48#$86#$F7#$0D#$02#$05;

  { RFC 5272 }

  SB_CMC_OID_PKI_DATA_STR               = #$2B#$06#$01#$05#$05#$07#$0C#$02;
  SB_CMC_OID_PKI_RESPONSE_STR           = #$2B#$06#$01#$05#$05#$07#$0C#$03;

  SB_CMC_OID_STATUS_INFO_STR            = #$2B#$06#$01#$05#$05#$07#$07#$01;
  SB_CMC_OID_IDENTIFICATION_STR         = #$2B#$06#$01#$05#$05#$07#$07#$02;
  SB_CMC_OID_IDENTITY_PROOF_STR         = #$2B#$06#$01#$05#$05#$07#$07#$03;
  SB_CMC_OID_DATA_RETURN_STR            = #$2B#$06#$01#$05#$05#$07#$07#$04;
  SB_CMC_OID_TRANSACTION_ID_STR         = #$2B#$06#$01#$05#$05#$07#$07#$05;
  SB_CMC_OID_SENDER_NONCE_STR           = #$2B#$06#$01#$05#$05#$07#$07#$06;
  SB_CMC_OID_RECIPIENT_NONCE_STR        = #$2B#$06#$01#$05#$05#$07#$07#$07;
  SB_CMC_OID_ADD_EXTENSIONS_STR         = #$2B#$06#$01#$05#$05#$07#$07#$08;
  SB_CMC_OID_ENCRYPTED_POP_STR          = #$2B#$06#$01#$05#$05#$07#$07#$09;
  SB_CMC_OID_DECRYPTED_POP_STR          = #$2B#$06#$01#$05#$05#$07#$07#$0A;
  SB_CMC_OID_LRA_POP_WITNESS_STR        = #$2B#$06#$01#$05#$05#$07#$07#$0B;
  SB_CMC_OID_GET_CERT_STR               = #$2B#$06#$01#$05#$05#$07#$07#$0F;
  SB_CMC_OID_GET_CRL_STR                = #$2B#$06#$01#$05#$05#$07#$07#$10;
  SB_CMC_OID_REVOKE_REQUEST_STR         = #$2B#$06#$01#$05#$05#$07#$07#$11;
  SB_CMC_OID_REG_INFO_STR               = #$2B#$06#$01#$05#$05#$07#$07#$12;
  SB_CMC_OID_RESPONSE_INFO_STR          = #$2B#$06#$01#$05#$05#$07#$07#$13;
  SB_CMC_OID_QUERY_PENDING_STR          = #$2B#$06#$01#$05#$05#$07#$07#$15;
  SB_CMC_OID_POP_LINK_RANDOM_STR        = #$2B#$06#$01#$05#$05#$07#$07#$16;
  SB_CMC_OID_POP_LINK_WITNESS_STR       = #$2B#$06#$01#$05#$05#$07#$07#$17;
  SB_CMC_OID_POP_LINK_WITNESS_V2_STR    = #$2B#$06#$01#$05#$05#$07#$07#$21;
  SB_CMC_OID_CONFIRM_CERT_ACCEPTANCE_STR  = #$2B#$06#$01#$05#$05#$07#$07#$18;
  SB_CMC_OID_STATUS_INFO_V2_STR         = #$2B#$06#$01#$05#$05#$07#$07#$19;
  SB_CMC_OID_TRUSTED_ANCHORS_STR        = #$2B#$06#$01#$05#$05#$07#$07#$1A;
  SB_CMC_OID_AUTH_DATA_STR              = #$2B#$06#$01#$05#$05#$07#$07#$1B;
  SB_CMC_OID_BATCH_REQUESTS_STR         = #$2B#$06#$01#$05#$05#$07#$07#$1C;
  SB_CMC_OID_BATCH_RESPONSES_STR        = #$2B#$06#$01#$05#$05#$07#$07#$1D;
  SB_CMC_OID_PUBLISH_CERT_STR           = #$2B#$06#$01#$05#$05#$07#$07#$1E;
  SB_CMC_OID_MOD_CERT_TEMPLATE_STR      = #$2B#$06#$01#$05#$05#$07#$07#$1F;
  SB_CMC_OID_CONTROL_PROCESSED_STR      = #$2B#$06#$01#$05#$05#$07#$07#$20;
  SB_CMC_OID_IDENTITY_PROOF_V2_STR      = #$2B#$06#$01#$05#$05#$07#$07#$22;

  SpaceByteArray_STR = #$20;
  CommaByteArray_STR = ',';
  SlashByteArray_STR = '/';
  ColonByteArray_STR = ':';
  EqualCharByteArray_STR = '=';
  DashByteArray_STR = '-';

  LFByteArray_STR = #$0A;
  CRByteArray_STR = #$0D;

  LFLFByteArray_STR = #$0A#$0A;
  CRLFByteArray_STR = #$0D#$0A;
  CRLFCRLFByteArray_STR = #$0D#$0A#$0D#$0A;
  CRCRLFByteArray_STR = #$0D#$0D#$0A;
  CRLFTABByteArray_STR = #$0D#$0A#$09;
  CRLFSPACEByteArray_STR = #$0D#$0A#$20;
  CRCRLFCRCRLFByteArray_STR = #$0D#$0D#$0A#$0D#$0D#$0A;

  TwoDashesByteArray_STR = '--';
  FiveDashesByteArray_STR = '-----';
  BeginLineByteArray_STR = '-----BEGIN ';
  LFEndLineByteArray_STR = #$0A'-----END ';

  UTF8BOMByteArray_STR = #$ef#$bb#$bf;
{$ifdef SB_UNICODE_VCL}
  {$WARNINGS ON}
 {$endif}
 {$endif}

{$ifdef SB_FPC_GEN}
implementation

uses
  SysUtils,
  Classes,
  SBUtils,
  SBStrUtils;
 {$endif}


function GetPBEAlgorithmByOID(const OID: ByteArray): Integer;
begin
  if CompareContent(OID, SB_OID_PBE_SHA1_3DES) then
    Result := SB_ALGORITHM_PBE_SHA1_3DES
  else
  if CompareContent(OID, SB_OID_PBE_SHA1_RC4_128) then
    Result := SB_ALGORITHM_PBE_SHA1_RC4_128
  else if CompareContent(OID, SB_OID_PBE_SHA1_RC4_40) then
    Result := SB_ALGORITHM_PBE_SHA1_RC4_40
  else if CompareContent(OID, SB_OID_PBE_SHA1_RC2_128) then
    Result := SB_ALGORITHM_PBE_SHA1_RC2_128
  else if CompareContent(OID, SB_OID_PBE_SHA1_RC2_40) then
    Result := SB_ALGORITHM_PBE_SHA1_RC2_40
  { PKCS#5 PBES1 }
  else if CompareContent(OID, SB_OID_PBE_MD2_DES) then
    Result := SB_ALGORITHM_P5_PBE_MD2_DES
  else if CompareContent(OID, SB_OID_PBE_MD2_RC2) then
    Result := SB_ALGORITHM_P5_PBE_MD2_RC2
  else if CompareContent(OID, SB_OID_PBE_MD5_DES) then
    Result := SB_ALGORITHM_P5_PBE_MD5_DES
  else if CompareContent(OID, SB_OID_PBE_MD5_RC2) then
    Result := SB_ALGORITHM_P5_PBE_MD5_RC2
  else if CompareContent(OID, SB_OID_PBE_SHA1_DES) then
    Result := SB_ALGORITHM_P5_PBE_SHA1_DES
  else if CompareContent(OID, SB_OID_PBE_SHA1_RC2) then
    Result := SB_ALGORITHM_P5_PBE_SHA1_RC2
  { PKCS#5 PBES2 }
  else if CompareContent(OID, SB_OID_PBES2) then
    Result := SB_ALGORITHM_P5_PBES2
  { PKCS#5 : key derivation function PBKDF2 }
  else if CompareContent(OID, SB_OID_PBKDF2) then
    Result := SB_ALGORITHM_P5_PBKDF2
  else
    Result := SB_ALGORITHM_UNKNOWN;
end;

function GetOIDByPBEAlgorithm(Algorithm: Integer): ByteArray;
begin
  case Algorithm of
    SB_ALGORITHM_PBE_SHA1_3DES    : Result := SB_OID_PBE_SHA1_3DES;
    SB_ALGORITHM_PBE_SHA1_RC4_128 : Result := SB_OID_PBE_SHA1_RC4_128;
    SB_ALGORITHM_PBE_SHA1_RC4_40  : Result := SB_OID_PBE_SHA1_RC4_40;
    SB_ALGORITHM_PBE_SHA1_RC2_128 : Result := SB_OID_PBE_SHA1_RC2_128;
    SB_ALGORITHM_PBE_SHA1_RC2_40  : Result := SB_OID_PBE_SHA1_RC2_40;
    SB_ALGORITHM_P5_PBE_MD2_DES      : Result := SB_OID_PBE_MD2_DES;
    SB_ALGORITHM_P5_PBE_MD2_RC2      : Result := SB_OID_PBE_MD2_RC2;
    SB_ALGORITHM_P5_PBE_MD5_DES      : Result := SB_OID_PBE_MD5_DES;
    SB_ALGORITHM_P5_PBE_MD5_RC2      : Result := SB_OID_PBE_MD5_RC2;
    SB_ALGORITHM_P5_PBE_SHA1_DES     : Result := SB_OID_PBE_SHA1_DES;
    SB_ALGORITHM_P5_PBE_SHA1_RC2     : Result := SB_OID_PBE_SHA1_RC2;
    SB_ALGORITHM_P5_PBES2            : Result := SB_OID_PBES2;
    SB_ALGORITHM_P5_PBKDF2           : Result := SB_OID_PBKDF2;
  else
    Result := EmptyArray;
  end;
end;

function GetPKAlgorithmByOID(const OID: ByteArray): Integer;
begin
  // compatible with X.509 unit constants
  if (CompareContent(OID, SB_OID_RSAENCRYPTION)) or
    (CompareContent(OID, SB_OID_EA_RSA)) then
    Result := SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION {0}
  else if (CompareContent(OID, SB_OID_RSASIGNATURE_RIPEMD160_ISO9796)) then
    Result := SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION
  else if (CompareContent(OID, SB_OID_DSA)) or
    (CompareContent(OID, SB_OID_DSA_ALT)) then
    Result := SB_CERT_ALGORITHM_ID_DSA {4}
  else if CompareContent(OID, SB_OID_DH) then
    Result := SB_CERT_ALGORITHM_DH_PUBLIC {6}
  else if CompareContent(OID, SB_OID_RSAPSS) then
    Result := SB_CERT_ALGORITHM_ID_RSAPSS
  else if CompareContent(OID, SB_OID_RSAOAEP) then
    Result := SB_CERT_ALGORITHM_ID_RSAOAEP
  else if CompareContent(OID, SB_OID_EC_KEY) then
    Result := SB_CERT_ALGORITHM_EC
  else if CompareContent(OID, SB_OID_GOST_R3410_1994) then
    Result := SB_CERT_ALGORITHM_GOST_R3410_1994
  else if CompareContent(OID, SB_OID_GOST_R3410_2001) then
    Result := SB_CERT_ALGORITHM_GOST_R3410_2001
  else
    Result := SB_ALGORITHM_UNKNOWN;
end;

function GetOIDByPKAlgorithm(Algorithm : Integer): ByteArray;
begin
  case Algorithm of
    SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION,
    SB_ALGORITHM_PK_RSA :
      Result := SB_OID_RSAENCRYPTION;
    SB_CERT_ALGORITHM_ID_DSA,
    SB_ALGORITHM_PK_DSA :
      Result := SB_OID_DSA;
    SB_CERT_ALGORITHM_DH_PUBLIC,
    SB_ALGORITHM_PK_DH :
      Result := SB_OID_DH;
    SB_CERT_ALGORITHM_ID_RSAPSS :
      Result := SB_OID_RSAPSS;
    SB_CERT_ALGORITHM_ID_RSAOAEP :
      Result := SB_OID_RSAOAEP;
    SB_CERT_ALGORITHM_EC,
    SB_ALGORITHM_PK_EC,
    SB_ALGORITHM_PK_ECDH :
      Result := SB_OID_EC_KEY;
    SB_CERT_ALGORITHM_GOST_R3410_1994:
      Result := SB_OID_GOST_R3410_1994;
    SB_CERT_ALGORITHM_GOST_R3410_2001:
      Result := SB_OID_GOST_R3410_2001;
  else
    Result := EmptyArray;
  end;
end;

function GetSigAlgorithmByOID(const OID: ByteArray): integer;
begin
  if CompareContent(OID, SB_OID_RSAENCRYPTION) then
    Result := SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION
  else if CompareContent(OID, SB_OID_MD2_RSAENCRYPTION) then
    Result := SB_CERT_ALGORITHM_MD2_RSA_ENCRYPTION
  else if CompareContent(OID, SB_OID_MD5_RSAENCRYPTION) then
    Result := SB_CERT_ALGORITHM_MD5_RSA_ENCRYPTION
  else if CompareContent(OID, SB_OID_SHA1_RSAENCRYPTION) then
    Result := SB_CERT_ALGORITHM_SHA1_RSA_ENCRYPTION
  else if CompareContent(OID, SB_OID_SHA1_RSAENCRYPTION2) then
    Result := SB_CERT_ALGORITHM_SHA1_RSA_ENCRYPTION
  else if CompareContent(OID, SB_OID_RSAPSS) then
    Result := SB_CERT_ALGORITHM_ID_RSAPSS
  else if CompareContent(OID, SB_OID_SHA1_DSA) or
    (CompareContent(OID, SB_OID_DSA_SHA1_ALT)) then
    Result := SB_CERT_ALGORITHM_ID_DSA_SHA1
  else if CompareContent(OID, SB_OID_DSA) then
    Result := SB_CERT_ALGORITHM_ID_DSA
  else if CompareContent(OID, SB_OID_SHA224_RSAENCRYPTION) then
    Result := SB_CERT_ALGORITHM_SHA224_RSA_ENCRYPTION
  else if CompareContent(OID, SB_OID_SHA256_RSAENCRYPTION) then
    Result := SB_CERT_ALGORITHM_SHA256_RSA_ENCRYPTION
  else if CompareContent(OID, SB_OID_SHA384_RSAENCRYPTION) then
    Result := SB_CERT_ALGORITHM_SHA384_RSA_ENCRYPTION
  else if CompareContent(OID, SB_OID_SHA512_RSAENCRYPTION) then
    Result := SB_CERT_ALGORITHM_SHA512_RSA_ENCRYPTION
  else if CompareContent(OID, SB_OID_RSASIGNATURE_RIPEMD160) then
    Result := SB_CERT_ALGORITHM_RSASIGNATURE_RIPEMD160
  else if CompareContent(OID, SB_OID_ECDSA_SHA1) then
    Result := SB_CERT_ALGORITHM_SHA1_ECDSA
  else if CompareContent(OID, SB_OID_ECDSA_RECOMMENDED) then
    Result := SB_CERT_ALGORITHM_RECOMMENDED_ECDSA
  else if CompareContent(OID, SB_OID_ECDSA_SHA224) then
    Result := SB_CERT_ALGORITHM_SHA224_ECDSA
  else if CompareContent(OID, SB_OID_ECDSA_SHA256) then
    Result := SB_CERT_ALGORITHM_SHA256_ECDSA
  else if CompareContent(OID, SB_OID_ECDSA_SHA384) then
    Result := SB_CERT_ALGORITHM_SHA384_ECDSA
  else if CompareContent(OID, SB_OID_ECDSA_SHA512) then
    Result := SB_CERT_ALGORITHM_SHA512_ECDSA
  else if CompareContent(OID, SB_OID_ECDSA_SPECIFIED) then
    Result := SB_CERT_ALGORITHM_SPECIFIED_ECDSA
  else if CompareContent(OID, SB_OID_ECDSA_PLAIN_SHA1) then
    Result := SB_CERT_ALGORITHM_SHA1_ECDSA_PLAIN
  else if CompareContent(OID, SB_OID_ECDSA_PLAIN_SHA224) then
    Result := SB_CERT_ALGORITHM_SHA224_ECDSA_PLAIN
  else if CompareContent(OID, SB_OID_ECDSA_PLAIN_SHA256) then
    Result := SB_CERT_ALGORITHM_SHA256_ECDSA_PLAIN
  else if CompareContent(OID, SB_OID_ECDSA_PLAIN_SHA384) then
    Result := SB_CERT_ALGORITHM_SHA384_ECDSA_PLAIN
  else if CompareContent(OID, SB_OID_ECDSA_PLAIN_SHA512) then
    Result := SB_CERT_ALGORITHM_SHA512_ECDSA_PLAIN
  else if CompareContent(OID, SB_OID_ECDSA_PLAIN_RIPEMD160) then
    Result := SB_CERT_ALGORITHM_RIPEMD160_ECDSA_PLAIN
  else if CompareContent(OID, SB_OID_GOST_R3411_1994_WITH_GOST_R3410_1994) then
    Result := SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_1994
  else if CompareContent(OID, SB_OID_GOST_R3410_1994) then
    Result := SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_1994
  else if CompareContent(OID, SB_OID_GOST_R3411_1994_WITH_GOST_R3410_2001) then
    Result := SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_2001
  else if CompareContent(OID, SB_OID_GOST_R3410_2001) then
    Result := SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_2001
  else if CompareContent(OID, SB_OID_WHIRLPOOL_RSAENCRYPTION_ELDOS) then
    Result := SB_CERT_ALGORITHM_WHIRLPOOL_RSA_ENCRYPTION
  else
    Result := SB_ALGORITHM_UNKNOWN;
end;

function GetOIDBySigAlgorithm(Algorithm: integer): ByteArray;
begin
  case Algorithm of
    SB_CERT_ALGORITHM_MD2_RSA_ENCRYPTION  : Result := SB_OID_MD2_RSAENCRYPTION;
    SB_CERT_ALGORITHM_MD5_RSA_ENCRYPTION  : Result := SB_OID_MD5_RSAENCRYPTION;
    SB_CERT_ALGORITHM_SHA1_RSA_ENCRYPTION : Result := SB_OID_SHA1_RSAENCRYPTION;
    SB_CERT_ALGORITHM_ID_RSAPSS : Result := SB_OID_RSAPSS;
    SB_CERT_ALGORITHM_ID_RSAOAEP : Result := SB_OID_RSAOAEP;
    SB_CERT_ALGORITHM_ID_DSA_SHA1 : Result := SB_OID_SHA1_DSA;
    SB_CERT_ALGORITHM_SHA224_RSA_ENCRYPTION : Result := SB_OID_SHA224_RSAENCRYPTION;
    SB_CERT_ALGORITHM_SHA256_RSA_ENCRYPTION : Result := SB_OID_SHA256_RSAENCRYPTION;
    SB_CERT_ALGORITHM_SHA384_RSA_ENCRYPTION : Result := SB_OID_SHA384_RSAENCRYPTION;
    SB_CERT_ALGORITHM_SHA512_RSA_ENCRYPTION : Result := SB_OID_SHA512_RSAENCRYPTION;
    SB_CERT_ALGORITHM_RSASIGNATURE_RIPEMD160: Result := SB_OID_RSASIGNATURE_RIPEMD160;
    SB_CERT_ALGORITHM_SHA1_ECDSA : Result := SB_OID_ECDSA_SHA1;
    SB_CERT_ALGORITHM_RECOMMENDED_ECDSA,
      SB_ALGORITHM_PK_ECDSA : Result := SB_OID_ECDSA_RECOMMENDED;
    SB_CERT_ALGORITHM_SHA224_ECDSA : Result := SB_OID_ECDSA_SHA224;
    SB_CERT_ALGORITHM_SHA256_ECDSA : Result := SB_OID_ECDSA_SHA256;
    SB_CERT_ALGORITHM_SHA384_ECDSA : Result := SB_OID_ECDSA_SHA384;
    SB_CERT_ALGORITHM_SHA512_ECDSA : Result := SB_OID_ECDSA_SHA512;
    SB_CERT_ALGORITHM_SPECIFIED_ECDSA : Result := SB_OID_ECDSA_SPECIFIED;
    SB_CERT_ALGORITHM_SHA1_ECDSA_PLAIN : Result := SB_OID_ECDSA_PLAIN_SHA1;
    SB_CERT_ALGORITHM_SHA224_ECDSA_PLAIN : Result := SB_OID_ECDSA_PLAIN_SHA224;
    SB_CERT_ALGORITHM_SHA256_ECDSA_PLAIN : Result := SB_OID_ECDSA_PLAIN_SHA256;
    SB_CERT_ALGORITHM_SHA384_ECDSA_PLAIN : Result := SB_OID_ECDSA_PLAIN_SHA384;
    SB_CERT_ALGORITHM_SHA512_ECDSA_PLAIN : Result := SB_OID_ECDSA_PLAIN_SHA512;
    SB_CERT_ALGORITHM_RIPEMD160_ECDSA_PLAIN : Result := SB_OID_ECDSA_PLAIN_RIPEMD160;
    SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_1994 : Result := SB_OID_GOST_R3411_1994_WITH_GOST_R3410_1994;
    SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_2001 : Result := SB_OID_GOST_R3411_1994_WITH_GOST_R3410_2001;
    SB_CERT_ALGORITHM_WHIRLPOOL_RSA_ENCRYPTION : Result := SB_OID_WHIRLPOOL_RSAENCRYPTION_ELDOS;
  else
    Result := EmptyArray;
  end;
end;

function GetHashAlgorithmBySigAlgorithm(Algorithm: integer): integer;
begin
  case Algorithm of
    SB_CERT_ALGORITHM_MD2_RSA_ENCRYPTION  : Result := SB_ALGORITHM_DGST_MD2;
    SB_CERT_ALGORITHM_MD5_RSA_ENCRYPTION  : Result := SB_ALGORITHM_DGST_MD5;
    SB_CERT_ALGORITHM_SHA1_RSA_ENCRYPTION : Result := SB_ALGORITHM_DGST_SHA1;
    SB_CERT_ALGORITHM_ID_DSA_SHA1 : Result := SB_ALGORITHM_DGST_SHA1;
    SB_CERT_ALGORITHM_SHA224_RSA_ENCRYPTION : Result := SB_ALGORITHM_DGST_SHA224;
    SB_CERT_ALGORITHM_SHA256_RSA_ENCRYPTION : Result := SB_ALGORITHM_DGST_SHA256;
    SB_CERT_ALGORITHM_SHA384_RSA_ENCRYPTION : Result := SB_ALGORITHM_DGST_SHA384;
    SB_CERT_ALGORITHM_SHA512_RSA_ENCRYPTION : Result := SB_ALGORITHM_DGST_SHA512;
    SB_CERT_ALGORITHM_RSASIGNATURE_RIPEMD160: Result := SB_ALGORITHM_DGST_RIPEMD160;
    SB_CERT_ALGORITHM_SHA1_ECDSA : Result := SB_ALGORITHM_DGST_SHA1;
    SB_CERT_ALGORITHM_SHA224_ECDSA : Result := SB_ALGORITHM_DGST_SHA224;
    SB_CERT_ALGORITHM_SHA256_ECDSA : Result := SB_ALGORITHM_DGST_SHA256;
    SB_CERT_ALGORITHM_SHA384_ECDSA : Result := SB_ALGORITHM_DGST_SHA384;
    SB_CERT_ALGORITHM_SHA512_ECDSA : Result := SB_ALGORITHM_DGST_SHA512;
    SB_CERT_ALGORITHM_SHA1_ECDSA_PLAIN : Result := SB_ALGORITHM_DGST_SHA1;
    SB_CERT_ALGORITHM_SHA224_ECDSA_PLAIN : Result := SB_ALGORITHM_DGST_SHA224;
    SB_CERT_ALGORITHM_SHA256_ECDSA_PLAIN : Result := SB_ALGORITHM_DGST_SHA256;
    SB_CERT_ALGORITHM_SHA384_ECDSA_PLAIN : Result := SB_ALGORITHM_DGST_SHA384;
    SB_CERT_ALGORITHM_SHA512_ECDSA_PLAIN : Result := SB_ALGORITHM_DGST_SHA512;
    SB_CERT_ALGORITHM_RIPEMD160_ECDSA_PLAIN : Result := SB_ALGORITHM_DGST_RIPEMD160;
    SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_1994: Result := SB_ALGORITHM_DGST_GOST_R3411_1994;
    SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_2001: Result := SB_ALGORITHM_DGST_GOST_R3411_1994;
    SB_CERT_ALGORITHM_WHIRLPOOL_RSA_ENCRYPTION : Result := SB_ALGORITHM_DGST_WHIRLPOOL;
  else
    Result := SB_ALGORITHM_UNKNOWN;
  end;
end;

function GetHMACAlgorithmByHashAlgorithm(Algorithm: integer): integer;
begin
  case Algorithm of
    SB_ALGORITHM_DGST_SHA1 : Result := SB_ALGORITHM_MAC_HMACSHA1;
    SB_ALGORITHM_DGST_SHA224 : Result := SB_ALGORITHM_MAC_HMACSHA224;
    SB_ALGORITHM_DGST_SHA256 : Result := SB_ALGORITHM_MAC_HMACSHA256;
    SB_ALGORITHM_DGST_SHA384 : Result := SB_ALGORITHM_MAC_HMACSHA384;
    SB_ALGORITHM_DGST_SHA512 : Result := SB_ALGORITHM_MAC_HMACSHA512;
    SB_ALGORITHM_DGST_MD5 : Result := SB_ALGORITHM_MAC_HMACMD5;
    SB_ALGORITHM_DGST_RIPEMD160 : Result := SB_ALGORITHM_MAC_HMACRIPEMD;
  else
    Result := SB_ALGORITHM_UNKNOWN;
  end;
end;

function GetHashAlgorithmByHMACAlgorithm(Algorithm: integer): integer;
begin
  case Algorithm of
    SB_ALGORITHM_MAC_HMACSHA1 : Result := SB_ALGORITHM_DGST_SHA1;
    SB_ALGORITHM_MAC_HMACSHA224 : Result := SB_ALGORITHM_DGST_SHA224;
    SB_ALGORITHM_MAC_HMACSHA256 : Result := SB_ALGORITHM_DGST_SHA256;
    SB_ALGORITHM_MAC_HMACSHA384 : Result := SB_ALGORITHM_DGST_SHA384;
    SB_ALGORITHM_MAC_HMACSHA512 : Result := SB_ALGORITHM_DGST_SHA512;
    SB_ALGORITHM_MAC_HMACMD5 : Result := SB_ALGORITHM_DGST_MD5;
    SB_ALGORITHM_MAC_HMACRIPEMD : Result := SB_ALGORITHM_DGST_RIPEMD160;
  else
    Result := SB_ALGORITHM_UNKNOWN;
  end;
end;

function GetSigAlgorithmByHashAlgorithm(BasePKAlg : integer; HashAlg : integer): integer;
begin
  Result := SB_ALGORITHM_UNKNOWN;
  if BasePKAlg = SB_CERT_ALGORITHM_EC then
  begin
    case HashAlg of
      SB_ALGORITHM_DGST_SHA1 :
        Result := SB_CERT_ALGORITHM_SHA1_ECDSA;
      SB_ALGORITHM_DGST_SHA224 :
        Result := SB_CERT_ALGORITHM_SHA224_ECDSA;
      SB_ALGORITHM_DGST_SHA256 :
        Result := SB_CERT_ALGORITHM_SHA256_ECDSA;
      SB_ALGORITHM_DGST_SHA384 :
        Result := SB_CERT_ALGORITHM_SHA384_ECDSA;
      SB_ALGORITHM_DGST_SHA512 :
        Result := SB_CERT_ALGORITHM_SHA512_ECDSA;
    end;
  end;
end;

function GetKeyAlgorithmBySigAlgorithm(SigAlg : integer) : integer;
begin
  case SigAlg of
    SB_CERT_ALGORITHM_MD2_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_MD5_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA1_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA224_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA256_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA384_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA512_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_RSASIGNATURE_RIPEMD160,
    SB_CERT_ALGORITHM_WHIRLPOOL_RSA_ENCRYPTION:
      Result := SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION;

    SB_CERT_ALGORITHM_ID_DSA_SHA1 :
      Result := SB_CERT_ALGORITHM_ID_DSA;

    SB_CERT_ALGORITHM_ID_RSAPSS :
      Result := SB_CERT_ALGORITHM_ID_RSAPSS;

    SB_CERT_ALGORITHM_SHA1_ECDSA,
    SB_CERT_ALGORITHM_RECOMMENDED_ECDSA,
    SB_CERT_ALGORITHM_SHA224_ECDSA,
    SB_CERT_ALGORITHM_SHA256_ECDSA,
    SB_CERT_ALGORITHM_SHA384_ECDSA,
    SB_CERT_ALGORITHM_SHA512_ECDSA,
    SB_CERT_ALGORITHM_SPECIFIED_ECDSA :
      Result := SB_CERT_ALGORITHM_EC;

    SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_1994 :
      Result := SB_CERT_ALGORITHM_GOST_R3410_1994;

    SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_2001 :
      Result := SB_CERT_ALGORITHM_GOST_R3410_2001
  else
    Result := SB_ALGORITHM_UNKNOWN;
  end;
end;

function GetSigAlgorithmByKeyAlgorithm(KeyAlg : integer) : integer;
begin
  case KeyAlg of
    SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION :
      Result := SB_CERT_ALGORITHM_SHA1_RSA_ENCRYPTION;
    SB_CERT_ALGORITHM_ID_DSA :
      Result := SB_CERT_ALGORITHM_ID_DSA_SHA1;
    SB_CERT_ALGORITHM_ID_RSAPSS :
      Result := SB_CERT_ALGORITHM_ID_RSAPSS;
    SB_CERT_ALGORITHM_EC :
      Result := SB_CERT_ALGORITHM_SHA1_ECDSA;
    SB_CERT_ALGORITHM_GOST_R3410_1994 :
      Result := SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_1994;
    SB_CERT_ALGORITHM_GOST_R3410_2001 :
      Result := SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_2001
  else
    Result := SB_ALGORITHM_UNKNOWN;
  end;
end;

function NormalizeAlgorithmConstant(Value: integer): integer;
begin
  if (Value = SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION) or
    (Value = SB_CERT_ALGORITHM_MD5_RSA_ENCRYPTION) or
    (Value = SB_CERT_ALGORITHM_SHA1_RSA_ENCRYPTION) or
    (Value = SB_CERT_ALGORITHM_SHA224_RSA_ENCRYPTION) or
    (Value = SB_CERT_ALGORITHM_SHA256_RSA_ENCRYPTION) or
    (Value = SB_CERT_ALGORITHM_SHA384_RSA_ENCRYPTION) or
    (Value = SB_CERT_ALGORITHM_SHA512_RSA_ENCRYPTION) or
    (Value = SB_CERT_ALGORITHM_ID_RSAPSS) or
    (Value = SB_CERT_ALGORITHM_ID_RSAOAEP) or
    (Value = SB_CERT_ALGORITHM_RSASIGNATURE_RIPEMD160) or
    (Value = SB_CERT_ALGORITHM_WHIRLPOOL_RSA_ENCRYPTION) then
    Result := SB_ALGORITHM_PK_RSA
  else if (Value = SB_CERT_ALGORITHM_ID_DSA) or
    (Value = SB_CERT_ALGORITHM_ID_DSA_SHA1) then
    Result := SB_ALGORITHM_PK_DSA
  else if (Value = SB_CERT_ALGORITHM_EC) or
    (Value = SB_CERT_ALGORITHM_SHA1_ECDSA) or
    (Value = SB_CERT_ALGORITHM_RECOMMENDED_ECDSA) or
    (Value = SB_CERT_ALGORITHM_SHA224_ECDSA) or
    (Value = SB_CERT_ALGORITHM_SHA256_ECDSA) or
    (Value = SB_CERT_ALGORITHM_SHA384_ECDSA) or
    (Value = SB_CERT_ALGORITHM_SHA512_ECDSA) or
    (Value = SB_CERT_ALGORITHM_SPECIFIED_ECDSA) then
    Result := SB_ALGORITHM_PK_EC
  else if (Value = SB_CERT_ALGORITHM_UNKNOWN) then
    Result := SB_ALGORITHM_UNKNOWN
  else
    Result := Value;
end;

function GetAlgorithmByOID(const OID : ByteArray; UseCryptoProvConstants : boolean  =  false) : integer;
begin
  if CompareContent(OID, SB_OID_RSAENCRYPTION) then
    Result := SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION
  else if CompareContent(OID, SB_OID_MD5_RSAENCRYPTION) then
    Result := SB_CERT_ALGORITHM_MD5_RSA_ENCRYPTION
  else if CompareContent(OID, SB_OID_SHA1_RSAENCRYPTION) then
    Result := SB_CERT_ALGORITHM_SHA1_RSA_ENCRYPTION
  else if CompareContent(OID, SB_OID_SHA1_RSAENCRYPTION2) then
    Result := SB_CERT_ALGORITHM_SHA1_RSA_ENCRYPTION
  else if CompareContent(OID, SB_OID_SHA224_RSAENCRYPTION) then
    Result := SB_CERT_ALGORITHM_SHA224_RSA_ENCRYPTION
  else if CompareContent(OID, SB_OID_SHA256_RSAENCRYPTION) then
    Result := SB_CERT_ALGORITHM_SHA256_RSA_ENCRYPTION
  else if CompareContent(OID, SB_OID_SHA384_RSAENCRYPTION) then
    Result := SB_CERT_ALGORITHM_SHA384_RSA_ENCRYPTION
  else if CompareContent(OID, SB_OID_SHA512_RSAENCRYPTION) then
    Result := SB_CERT_ALGORITHM_SHA512_RSA_ENCRYPTION
  else if CompareContent(OID, SB_OID_RSASIGNATURE_RIPEMD160) then
    Result := SB_CERT_ALGORITHM_RSASIGNATURE_RIPEMD160
  else if CompareContent(OID, SB_OID_RSASIGNATURE_RIPEMD160_ISO9796) then
    Result := SB_CERT_ALGORITHM_RSASIGNATURE_RIPEMD160
  else if CompareContent(OID, SB_OID_DSA) then
    Result := SB_CERT_ALGORITHM_ID_DSA
  else if CompareContent(OID, SB_OID_DSA_SHA1) then
    Result := SB_CERT_ALGORITHM_ID_DSA_SHA1
  else if CompareContent(OID, SB_OID_ECDSA_SHA1) then
    Result := SB_CERT_ALGORITHM_SHA1_ECDSA
  else if CompareContent(OID, SB_OID_ECDSA_RECOMMENDED) then
    Result := SB_CERT_ALGORITHM_RECOMMENDED_ECDSA
  else if CompareContent(OID, SB_OID_ECDSA_SHA224) then
    Result := SB_CERT_ALGORITHM_SHA224_ECDSA
  else if CompareContent(OID, SB_OID_ECDSA_SHA256) then
    Result := SB_CERT_ALGORITHM_SHA256_ECDSA
  else if CompareContent(OID, SB_OID_ECDSA_SHA384) then
    Result := SB_CERT_ALGORITHM_SHA384_ECDSA
  else if CompareContent(OID, SB_OID_ECDSA_SHA512) then
    Result := SB_CERT_ALGORITHM_SHA512_ECDSA
  else if CompareContent(OID, SB_OID_ECDSA_PLAIN_SHA1) then
    Result := SB_CERT_ALGORITHM_SHA1_ECDSA_PLAIN
  else if CompareContent(OID, SB_OID_ECDSA_PLAIN_SHA224) then
    Result := SB_CERT_ALGORITHM_SHA224_ECDSA_PLAIN
  else if CompareContent(OID, SB_OID_ECDSA_PLAIN_SHA256) then
    Result := SB_CERT_ALGORITHM_SHA256_ECDSA_PLAIN
  else if CompareContent(OID, SB_OID_ECDSA_PLAIN_SHA384) then
    Result := SB_CERT_ALGORITHM_SHA384_ECDSA_PLAIN
  else if CompareContent(OID, SB_OID_ECDSA_PLAIN_SHA512) then
    Result := SB_CERT_ALGORITHM_SHA512_ECDSA_PLAIN
  else if CompareContent(OID, SB_OID_ECDSA_PLAIN_RIPEMD160) then
    Result := SB_CERT_ALGORITHM_RIPEMD160_ECDSA_PLAIN
  else if CompareContent(OID, SB_OID_RSAPSS) then
    Result := SB_CERT_ALGORITHM_ID_RSAPSS
  else if CompareContent(OID, SB_OID_DH) then
    Result := SB_CERT_ALGORITHM_DH_PUBLIC
  else if CompareContent(OID, SB_OID_MGF1) then
    Result := SB_CERT_MGF1
  else if CompareContent(OID, SB_OID_MGF1_SHA1) then
    Result := SB_CERT_MGF1_SHA1
  else if CompareContent(OID, SB_OID_MGF1_SHA224) then
    Result := SB_CERT_MGF1_SHA224
  else if CompareContent(OID, SB_OID_MGF1_SHA256) then
    Result := SB_CERT_MGF1_SHA256
  else if CompareContent(OID, SB_OID_MGF1_SHA384) then
    Result := SB_CERT_MGF1_SHA384
  else if CompareContent(OID, SB_OID_MGF1_SHA512) then
    Result := SB_CERT_MGF1_SHA512
  else if CompareContent(OID, SB_OID_MGF1_RIPEMD160) then
    Result := SB_CERT_MGF1_RIPEMD160
  else if CompareContent(OID, SB_OID_MGF1_WHIRLPOOL) then
    Result := SB_CERT_MGF1_WHIRLPOOL
  else if CompareContent(OID, SB_OID_RC4) then
    Result := SB_ALGORITHM_CNT_RC4
  else if CompareContent(OID, SB_OID_DES_EDE3_CBC) then 
    Result := SB_ALGORITHM_CNT_3DES
  else if CompareContent(OID, SB_OID_RC2_CBC) then
    Result := SB_ALGORITHM_CNT_RC2
  else if CompareContent(OID, SB_OID_DES_CBC) then
    Result := SB_ALGORITHM_CNT_DES
  else if CompareContent(OID, SB_OID_AES128_CBC) then
    Result := SB_ALGORITHM_CNT_AES128
  else if CompareContent(OID, SB_OID_AES192_CBC) then
    Result := SB_ALGORITHM_CNT_AES192
  else if CompareContent(OID, SB_OID_AES256_CBC) then
    Result := SB_ALGORITHM_CNT_AES256
  else if CompareContent(OID, SB_OID_SERPENT128_CBC) then
    Result := SB_ALGORITHM_CNT_SERPENT128
  else if CompareContent(OID, SB_OID_SERPENT192_CBC) then
    Result := SB_ALGORITHM_CNT_SERPENT192
  else if CompareContent(OID, SB_OID_SERPENT256_CBC) then
    Result := SB_ALGORITHM_CNT_SERPENT256
  else if CompareContent(OID, SB_OID_CAMELLIA128_CBC) then
    Result := SB_ALGORITHM_CNT_CAMELLIA128
  else if CompareContent(OID, SB_OID_CAMELLIA192_CBC) then
    Result := SB_ALGORITHM_CNT_CAMELLIA192
  else if CompareContent(OID, SB_OID_CAMELLIA256_CBC) then
    Result := SB_ALGORITHM_CNT_CAMELLIA256
  else if CompareContent(OID, SB_OID_CAST5_CBC) then
    Result := SB_ALGORITHM_CNT_CAST128
  else if CompareContent(OID, SB_OID_BLOWFISH_CBC) then
    Result := SB_ALGORITHM_CNT_BLOWFISH
  else if CompareContent(OID, SB_OID_RABBIT) then
    Result := SB_ALGORITHM_CNT_RABBIT
  else if CompareContent(OID, SB_OID_SEED) then
    Result := SB_ALGORITHM_CNT_SEED
  else if CompareContent(OID, SB_OID_IDENTITY_ELDOS) then
    Result := SB_ALGORITHM_CNT_IDENTITY
  else if CompareContent(OID, SB_OID_TWOFISH128_ELDOS) then
    Result := SB_ALGORITHM_CNT_TWOFISH128
  else if CompareContent(OID, SB_OID_TWOFISH256_ELDOS) then
    Result := SB_ALGORITHM_CNT_TWOFISH256
  else if CompareContent(OID, SB_OID_TWOFISH192_ELDOS) then
    Result := SB_ALGORITHM_CNT_TWOFISH192
  else if CompareContent(OID, SB_OID_SHA1) then
    Result := SB_ALGORITHM_DGST_SHA1
  else if CompareContent(OID, SB_OID_MD2) then
    Result := SB_ALGORITHM_DGST_MD2
  else if CompareContent(OID, SB_OID_MD4) then
    Result := SB_ALGORITHM_DGST_MD4
  else if CompareContent(OID, SB_OID_MD5) then
    Result := SB_ALGORITHM_DGST_MD5
  else if CompareContent(OID, SB_OID_SHA224) then
    Result := SB_ALGORITHM_DGST_SHA224
  else if CompareContent(OID, SB_OID_SHA256) then
    Result := SB_ALGORITHM_DGST_SHA256
  else if CompareContent(OID, SB_OID_SHA384) then
    Result := SB_ALGORITHM_DGST_SHA384
  else if CompareContent(OID, SB_OID_SHA512) then
    Result := SB_ALGORITHM_DGST_SHA512
  else if CompareContent(OID, SB_OID_RIPEMD160) then
    Result := SB_ALGORITHM_DGST_RIPEMD160
  else if CompareContent(OID, SB_OID_HMACSHA1) then
    Result := SB_ALGORITHM_MAC_HMACSHA1
  else if CompareContent(OID, SB_OID_HMACSHA1_PKCS) then
    Result := SB_ALGORITHM_MAC_HMACSHA1
  else if CompareContent(OID, SB_OID_HMACSHA224) then
    Result := SB_ALGORITHM_MAC_HMACSHA224
  else if CompareContent(OID, SB_OID_HMACSHA256) then
    Result := SB_ALGORITHM_MAC_HMACSHA256
  else if CompareContent(OID, SB_OID_HMACSHA384) then
    Result := SB_ALGORITHM_MAC_HMACSHA384
  else if CompareContent(OID, SB_OID_HMACSHA512) then
    Result := SB_ALGORITHM_MAC_HMACSHA512
  else if CompareContent(OID, SB_OID_SSL3) then
    Result := SB_ALGORITHM_DGST_SSL3
  else if CompareContent(OID, SB_OID_UMAC32) then
    Result := SB_ALGORITHM_UMAC32
  else if CompareContent(OID, SB_OID_UMAC64) then
    Result := SB_ALGORITHM_UMAC64
  else if CompareContent(OID, SB_OID_UMAC96) then
    Result := SB_ALGORITHM_UMAC96
  else if CompareContent(OID, SB_OID_UMAC128) then
    Result := SB_ALGORITHM_UMAC128
  else if CompareContent(OID, SB_OID_GOST_28147_1989) then
    Result := SB_ALGORITHM_CNT_GOST_28147_1989
  else if CompareContent(OID, SB_OID_GOST_28147_1989_MAC) then
    Result := SB_ALGORITHM_MAC_GOST_28147_1989
  else if CompareContent(OID, SB_OID_GOST_R3411_1994) then
    Result := SB_ALGORITHM_DGST_GOST_R3411_1994
  else if CompareContent(OID, SB_OID_GOST_R3410_1994) then
    Result := SB_CERT_ALGORITHM_GOST_R3410_1994
  else if CompareContent(OID, SB_OID_GOST_R3410_2001) then
    Result := SB_CERT_ALGORITHM_GOST_R3410_2001
  else if CompareContent(OID, SB_OID_GOST_R3411_1994_WITH_GOST_R3410_1994) then
    Result := SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_1994
  else if CompareContent(OID, SB_OID_GOST_R3411_1994_WITH_GOST_R3410_2001) then
    Result := SB_CERT_ALGORITHM_GOST_R3410_2001
  else if CompareContent(OID, SB_OID_WHIRLPOOL) then
    Result := SB_ALGORITHM_DGST_WHIRLPOOL
  else if CompareContent(OID, SB_OID_WHIRLPOOL_RSAENCRYPTION_ELDOS) then
    Result := SB_CERT_ALGORITHM_WHIRLPOOL_RSA_ENCRYPTION
  else
    Result := SB_ALGORITHM_UNKNOWN;

  if UseCryptoProvConstants then
    Result := NormalizeAlgorithmConstant(Result);
end;

function GetAlgorithmNameByAlgorithm(Algorithm: Integer): string;
begin
  case Algorithm of
    // Certificate algorithms (base = 0x0000)
    SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION         : Result := 'RSA';
    SB_CERT_ALGORITHM_MD2_RSA_ENCRYPTION        : Result := 'MD2 with RSA encryption';
    SB_CERT_ALGORITHM_MD5_RSA_ENCRYPTION        : Result := 'MD5 with RSA encryption';
    SB_CERT_ALGORITHM_SHA1_RSA_ENCRYPTION       : Result := 'SHA-1 with RSA encryption';
    SB_CERT_ALGORITHM_ID_DSA                    : Result := 'DSA';
    SB_CERT_ALGORITHM_ID_DSA_SHA1               : Result := 'SHA-1 with DSA';
    SB_CERT_ALGORITHM_DH_PUBLIC                 : Result := 'DH';
    SB_CERT_ALGORITHM_SHA224_RSA_ENCRYPTION     : Result := 'SHA-224 with RSA encryption';
    SB_CERT_ALGORITHM_SHA256_RSA_ENCRYPTION     : Result := 'SHA-256 with RSA encryption';
    SB_CERT_ALGORITHM_SHA384_RSA_ENCRYPTION     : Result := 'SHA-384 with RSA encryption';
    SB_CERT_ALGORITHM_SHA512_RSA_ENCRYPTION     : Result := 'SHA-512 with RSA encryption';
    SB_CERT_ALGORITHM_ID_RSAPSS                 : Result := 'RSA-PSS';
    SB_CERT_ALGORITHM_ID_RSAOAEP                : Result := 'RSA-OAEP';
    SB_CERT_ALGORITHM_RSASIGNATURE_RIPEMD160    : Result := 'RIPEMD-160 with RSA signature';
    SB_CERT_ALGORITHM_ID_ELGAMAL                : Result := 'ElGamal';
    SB_CERT_ALGORITHM_SHA1_ECDSA                : Result := 'SHA-1 with ECDSA';
    SB_CERT_ALGORITHM_RECOMMENDED_ECDSA         : Result := 'Recommended ECDSA';
    SB_CERT_ALGORITHM_SHA224_ECDSA              : Result := 'SHA-224 with ECDSA';
    SB_CERT_ALGORITHM_SHA256_ECDSA              : Result := 'SHA-256 with ECDSA';
    SB_CERT_ALGORITHM_SHA384_ECDSA              : Result := 'SHA-384 with ECDSA';
    SB_CERT_ALGORITHM_SHA512_ECDSA              : Result := 'SHA-512 with ECDSA';
    SB_CERT_ALGORITHM_EC                        : Result := 'EC';
    SB_CERT_ALGORITHM_SPECIFIED_ECDSA           : Result := 'Specified ECDSA';
    SB_CERT_ALGORITHM_GOST_R3410_1994           : Result := 'GOST R 34.10-94';
    SB_CERT_ALGORITHM_GOST_R3410_2001           : Result := 'GOST R 34.10-01';
    SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_1994: Result := 'GOST R 34.11 with R 34.10-94';
    SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_2001: Result := 'GOST R 34.11 with R 34.10-01';
    SB_CERT_ALGORITHM_WHIRLPOOL_RSA_ENCRYPTION  : Result := 'Whirlpool with RSA encryption';
    // Certificate algorithms (base = 0x0200)
    SB_CERT_MGF1                                : Result := 'MGF-1';
    SB_CERT_MGF1_SHA1                           : Result := 'SHA-1 with MGF-1';
    // Symmetric algorithms (base = 0x7000)
    SB_ALGORITHM_CNT_RC4             : Result := 'RC4';
    SB_ALGORITHM_CNT_DES             : Result := 'DES';
    SB_ALGORITHM_CNT_3DES            : Result := 'Triple DES';
    SB_ALGORITHM_CNT_RC2             : Result := 'RC2';
    SB_ALGORITHM_CNT_AES128          : Result := 'AES 128';
    SB_ALGORITHM_CNT_AES192          : Result := 'AES 192';
    SB_ALGORITHM_CNT_AES256          : Result := 'AES 256';
    SB_ALGORITHM_CNT_IDENTITY        : Result := 'Identity';
    SB_ALGORITHM_CNT_BLOWFISH        : Result := 'Blowfish';
    SB_ALGORITHM_CNT_TWOFISH         : Result := 'Twofish';
    SB_ALGORITHM_CNT_CAMELLIA        : Result := 'Camellia';
    SB_ALGORITHM_CNT_CAST128         : Result := 'CAST-128';
    SB_ALGORITHM_CNT_IDEA            : Result := 'IDEA';
    SB_ALGORITHM_CNT_SERPENT         : Result := 'Serpent';
    SB_ALGORITHM_CNT_TWOFISH128      : Result := 'Twofish 128';
    SB_ALGORITHM_CNT_TWOFISH192      : Result := 'Twofish 192';
    SB_ALGORITHM_CNT_TWOFISH256      : Result := 'Twofish 256';
    SB_ALGORITHM_CNT_CAMELLIA128     : Result := 'Camellia 128';
    SB_ALGORITHM_CNT_CAMELLIA192     : Result := 'Camellia 192';
    SB_ALGORITHM_CNT_CAMELLIA256     : Result := 'Camellia 256';
    SB_ALGORITHM_CNT_SERPENT128      : Result := 'Serpent 128';
    SB_ALGORITHM_CNT_SERPENT192      : Result := 'Serpent 192';
    SB_ALGORITHM_CNT_SERPENT256      : Result := 'Serpent 256';
    SB_ALGORITHM_CNT_SEED            : Result := 'SEED';
    SB_ALGORITHM_CNT_RABBIT          : Result := 'Rabbit';
    SB_ALGORITHM_CNT_SYMMETRIC       : Result := 'Symmetric';
    SB_ALGORITHM_CNT_GOST_28147_1989 : Result := 'GOST 28149-89';
    // Hash algorithms (base = 0x7100)
    SB_ALGORITHM_DGST_SHA1           : Result := 'SHA-1';
    SB_ALGORITHM_DGST_MD5            : Result := 'MD5';
    SB_ALGORITHM_DGST_MD2            : Result := 'MD2';
    SB_ALGORITHM_DGST_SHA256         : Result := 'SHA-256';
    SB_ALGORITHM_DGST_SHA384         : Result := 'SHA-384';
    SB_ALGORITHM_DGST_SHA512         : Result := 'SHA-512';
    SB_ALGORITHM_DGST_SHA224         : Result := 'SHA-224';
    SB_ALGORITHM_DGST_MD4            : Result := 'MD4';
    SB_ALGORITHM_DGST_RIPEMD160      : Result := 'RIPEMD-160';
    SB_ALGORITHM_DGST_CRC32          : Result := 'CRC-32';
    SB_ALGORITHM_DGST_SSL3           : Result := 'SSL 3';
    SB_ALGORITHM_DGST_GOST_R3411_1994: Result := 'GOST R 34.11-94';
    SB_ALGORITHM_DGST_WHIRLPOOL      : Result := 'Whirlpool';
    // MAC algorithms (base = 0x7300)
    SB_ALGORITHM_MAC_HMACSHA1        : Result := 'HMAC SHA-1';
    SB_ALGORITHM_MAC_HMACSHA224      : Result := 'HMAC SHA-224';
    SB_ALGORITHM_MAC_HMACSHA256      : Result := 'HMAC SHA-256';
    SB_ALGORITHM_MAC_HMACSHA384      : Result := 'HMAC SHA-384';
    SB_ALGORITHM_MAC_HMACSHA512      : Result := 'HMAC SHA-512';
    SB_ALGORITHM_MAC_HMACMD5         : Result := 'HMAC MD5';
    SB_ALGORITHM_MAC_HMACRIPEMD      : Result := 'HMAC RIPEMD';
    SB_ALGORITHM_HMAC                : Result := 'HMAC';
    SB_ALGORITHM_UMAC32              : Result := 'UMAC-32';
    SB_ALGORITHM_UMAC64              : Result := 'UMAC-64';
    SB_ALGORITHM_UMAC96              : Result := 'UMAC-96';
    SB_ALGORITHM_UMAC128             : Result := 'UMAC-128';
    SB_ALGORITHM_MAC_GOST_28147_1989 : Result := 'GOST 28147-89';
    SB_ALGORITHM_HMAC_GOST_R3411_1994: Result := 'GOST R 34.11-94';
    // Public key algorithms (base = 0x7400)
    SB_ALGORITHM_PK_RSA              : Result := 'RSA';
    SB_ALGORITHM_PK_DSA              : Result := 'DSA';
    SB_ALGORITHM_PK_ELGAMAL          : Result := 'ElGamal';
    SB_ALGORITHM_PK_GOST_R3410_1994  : Result := 'GOST R 34.10-94';
    SB_ALGORITHM_PK_EC               : Result := 'EC';
    SB_ALGORITHM_PK_ECDSA            : Result := 'ECDSA';
    SB_ALGORITHM_PK_DH               : Result := 'DH';
    SB_ALGORITHM_PK_SRP              : Result := 'SRP';
    SB_ALGORITHM_PK_ECDH             : Result := 'ECDH';
    SB_ALGORITHM_PK_GOST_R3410_2001  : Result := 'GOST R 34.10-01';
  else
    Result := Format('Unknown (0x%.4X)', [Algorithm]);
  end;
end;

function GetAlgorithmNameByOID(const OID: ByteArray): string;
begin
  Result := GetAlgorithmNameByAlgorithm(GetAlgorithmByOID(OID));
end;

function GetOIDByAlgorithm(Algorithm : integer) : ByteArray;
begin
  result := EmptyArray;
  case Algorithm of
    // public key algorithms
    SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION,
    SB_ALGORITHM_PK_RSA :
      Result := SB_OID_RSAENCRYPTION;
    SB_CERT_ALGORITHM_RSASIGNATURE_RIPEMD160 :
      Result := SB_OID_RSASIGNATURE_RIPEMD160;
    SB_CERT_ALGORITHM_ID_DSA,
    SB_ALGORITHM_PK_DSA :
      Result := SB_OID_DSA;
    SB_ALGORITHM_PK_ECDSA :
      Result := SB_OID_ECDSA_RECOMMENDED;
    SB_CERT_ALGORITHM_DH_PUBLIC,
    SB_ALGORITHM_PK_DH :
      Result := SB_OID_DH;
    // MGF algorithms
    SB_CERT_MGF1 :
      Result := SB_OID_MGF1;
    SB_CERT_MGF1_SHA1 :
      Result := SB_OID_MGF1_SHA1;
    SB_CERT_MGF1_SHA224 :
      Result := SB_OID_MGF1_SHA224;
    SB_CERT_MGF1_SHA256 :
      Result := SB_OID_MGF1_SHA256;
    SB_CERT_MGF1_SHA384 :
      Result := SB_OID_MGF1_SHA384;
    SB_CERT_MGF1_SHA512 :
      Result := SB_OID_MGF1_SHA512;
    SB_CERT_MGF1_RIPEMD160 :
      Result := SB_OID_MGF1_RIPEMD160;
    SB_CERT_MGF1_WHIRLPOOL :
      Result := SB_OID_MGF1_WHIRLPOOL;
    // stream cipher algorithms
    SB_ALGORITHM_CNT_RC4 :
      Result := SB_OID_RC4;
    SB_ALGORITHM_CNT_RC2 :
      Result := SB_OID_RC2_CBC;
    SB_ALGORITHM_CNT_3DES :
      Result := SB_OID_DES_EDE3_CBC;
    SB_ALGORITHM_CNT_DES :
      Result := SB_OID_DES_CBC;
    SB_ALGORITHM_CNT_AES128 :
      Result := SB_OID_AES128_CBC;
    SB_ALGORITHM_CNT_AES192 :
      Result := SB_OID_AES192_CBC;
    SB_ALGORITHM_CNT_AES256 :
      Result := SB_OID_AES256_CBC;
    SB_ALGORITHM_CNT_BLOWFISH :
      Result := SB_OID_BLOWFISH_CBC;
    SB_ALGORITHM_CNT_CAMELLIA128 :
      Result := SB_OID_CAMELLIA128_CBC;
    SB_ALGORITHM_CNT_CAMELLIA192 :
      Result := SB_OID_CAMELLIA192_CBC;
    SB_ALGORITHM_CNT_CAMELLIA256 :
      Result := SB_OID_CAMELLIA256_CBC;
    SB_ALGORITHM_CNT_CAST128 :
      Result := SB_OID_CAST5_CBC;
    SB_ALGORITHM_CNT_SERPENT128 :
      Result := SB_OID_SERPENT128_CBC;
    SB_ALGORITHM_CNT_SERPENT192 :
      Result := SB_OID_SERPENT192_CBC;
    SB_ALGORITHM_CNT_SERPENT256 :
      Result := SB_OID_SERPENT256_CBC;
    SB_ALGORITHM_CNT_IDENTITY :
      Result := SB_OID_IDENTITY_ELDOS;
    SB_ALGORITHM_CNT_TWOFISH128,
    SB_ALGORITHM_CNT_TWOFISH :
      Result := SB_OID_TWOFISH128_ELDOS;
    SB_ALGORITHM_CNT_TWOFISH256 :
      Result := SB_OID_TWOFISH256_ELDOS;
    SB_ALGORITHM_CNT_TWOFISH192 :
      Result := SB_OID_TWOFISH192_ELDOS;
    // digest algorithms
    SB_ALGORITHM_DGST_SHA1 :
      Result := SB_OID_SHA1;
    SB_ALGORITHM_DGST_MD2 :
      Result := SB_OID_MD2;
    SB_ALGORITHM_DGST_MD4 :
      Result := SB_OID_MD4;
    SB_ALGORITHM_DGST_MD5 :
      Result := SB_OID_MD5;
    SB_ALGORITHM_DGST_SHA224 :
      Result := SB_OID_SHA224;
    SB_ALGORITHM_DGST_SHA256 :
      Result := SB_OID_SHA256;
    SB_ALGORITHM_DGST_SHA384 :
      Result := SB_OID_SHA384;
    SB_ALGORITHM_DGST_SHA512 :
      Result := SB_OID_SHA512;
    SB_ALGORITHM_DGST_RIPEMD160 :
      Result := SB_OID_RIPEMD160;
    SB_ALGORITHM_DGST_SSL3 :
      Result := SB_OID_SSL3;
    SB_ALGORITHM_DGST_WHIRLPOOL:
      Result := SB_OID_WHIRLPOOL;
    // hmac algorithms
    SB_ALGORITHM_MAC_HMACSHA1 :
      Result := SB_OID_HMACSHA1;
    SB_ALGORITHM_MAC_HMACSHA224 :
      Result := SB_OID_HMACSHA224;
    SB_ALGORITHM_MAC_HMACSHA256 :
      Result := SB_OID_HMACSHA256;
    SB_ALGORITHM_MAC_HMACSHA384 :
      Result := SB_OID_HMACSHA384;
    SB_ALGORITHM_MAC_HMACSHA512 :
      Result := SB_OID_HMACSHA512;
    SB_ALGORITHM_UMAC32 :
      Result := SB_OID_UMAC32;
    SB_ALGORITHM_UMAC64 :
      Result := SB_OID_UMAC64;
    SB_ALGORITHM_UMAC96 :
      Result := SB_OID_UMAC96;
    SB_ALGORITHM_UMAC128 :
      Result := SB_OID_UMAC128;
    // gost algorithms
    SB_ALGORITHM_CNT_GOST_28147_1989:
      Result := SB_OID_GOST_28147_1989;
    SB_ALGORITHM_MAC_GOST_28147_1989:
      Result := SB_OID_GOST_28147_1989_MAC;
    SB_ALGORITHM_DGST_GOST_R3411_1994:
      Result := SB_OID_GOST_R3411_1994;
    SB_ALGORITHM_PK_GOST_R3410_1994:
      Result := SB_OID_GOST_R3410_1994;
    SB_ALGORITHM_PK_GOST_R3410_2001:
      Result := SB_OID_GOST_R3410_2001;
  else
    Result := GetOIDBySigAlgorithm(Algorithm);
  end;
end;

function GetHashAlgorithmByOID(const OID : ByteArray) : integer;
begin
  if CompareContent(OID, SB_OID_SHA1) then
    Result := SB_ALGORITHM_DGST_SHA1
  else if CompareContent(OID, SB_OID_MD2) then
    Result := SB_ALGORITHM_DGST_MD2
  else if CompareContent(OID, SB_OID_MD4) then
    Result := SB_ALGORITHM_DGST_MD4
  else if CompareContent(OID, SB_OID_MD5) then
    Result := SB_ALGORITHM_DGST_MD5
  else if CompareContent(OID, SB_OID_SHA224) then
    Result := SB_ALGORITHM_DGST_SHA224
  else if CompareContent(OID, SB_OID_SHA256) then
    Result := SB_ALGORITHM_DGST_SHA256
  else if CompareContent(OID, SB_OID_SHA384) then
    Result := SB_ALGORITHM_DGST_SHA384
  else if CompareContent(OID, SB_OID_SHA512) then
    Result := SB_ALGORITHM_DGST_SHA512
  else if CompareContent(OID, SB_OID_RIPEMD160) then
    Result := SB_ALGORITHM_DGST_RIPEMD160
  else if CompareContent(OID, SB_OID_GOST_R3411_1994) then
    Result := SB_ALGORITHM_DGST_GOST_R3411_1994
  else if CompareContent(OID, SB_OID_WHIRLPOOL) then
    Result := SB_ALGORITHM_DGST_WHIRLPOOL
  else
    Result := SB_ALGORITHM_UNKNOWN;
end;

function GetOIDByHashAlgorithm(Algorithm : integer) : ByteArray;
begin
  case Algorithm of
    SB_ALGORITHM_DGST_SHA1 :
      Result := SB_OID_SHA1;
    SB_ALGORITHM_DGST_MD2 :
      Result := SB_OID_MD2;
    SB_ALGORITHM_DGST_MD4 :
      Result := SB_OID_MD4;
    SB_ALGORITHM_DGST_MD5 :
      Result := SB_OID_MD5;
    SB_ALGORITHM_DGST_SHA224 :
      Result := SB_OID_SHA224;
    SB_ALGORITHM_DGST_SHA256 :
      Result := SB_OID_SHA256;
    SB_ALGORITHM_DGST_SHA384 :
      Result := SB_OID_SHA384;
    SB_ALGORITHM_DGST_SHA512 :
      Result := SB_OID_SHA512;
    SB_ALGORITHM_DGST_RIPEMD160 :
      Result := SB_OID_RIPEMD160;
    SB_ALGORITHM_DGST_GOST_R3411_1994:
      Result := SB_OID_GOST_R3411_1994;
    SB_ALGORITHM_DGST_WHIRLPOOL:
      Result := SB_OID_WHIRLPOOL;
  else
    Result := EmptyArray;
  end;
end;

function IsSymmetricKeyAlgorithm(Algorithm : integer): boolean;
begin
  //Result := (Algorithm >= SB_ALGORITHM_CNT_FIRST) and (Algorithm <= SB_ALGORITHM_CNT_LAST);
  Result := ((Algorithm and $7FFFFF00) = SB_ALGORITHM_CNT_BASE);
end;

function IsPublicKeyAlgorithm(Algorithm : integer): boolean;
begin
  //Result := (Algorithm >= SB_ALGORITHM_PK_FIRST) and (Algorithm <= SB_ALGORITHM_PK_LAST);
  Result := ((Algorithm and $7FFFFF00) = SB_ALGORITHM_PK_BASE);
end;

function IsHashAlgorithm(Algorithm : integer): boolean;
begin
  //Result := (Algorithm >= SB_ALGORITHM_DGST_FIRST) and (Algorithm <= SB_ALGORITHM_DGST_LAST);
  Result := ((Algorithm and $7FFFFF00) = SB_ALGORITHM_DGST_BASE);
end;

function IsMACAlgorithm(Algorithm : integer): boolean;
begin
  Result := ((Algorithm and $7FFFFF00) = SB_ALGORITHM_MAC_BASE);
end;

function MGF1AlgorithmByHash(Value: integer): integer;
begin
  case Value of
    SB_ALGORITHM_DGST_SHA1 :
      Result := SB_CERT_MGF1_SHA1;
    SB_ALGORITHM_DGST_SHA224 :
      Result := SB_CERT_MGF1_SHA224;
    SB_ALGORITHM_DGST_SHA256 :
      Result := SB_CERT_MGF1_SHA256;
    SB_ALGORITHM_DGST_SHA384 :
      Result := SB_CERT_MGF1_SHA384;
    SB_ALGORITHM_DGST_SHA512 :
      Result := SB_CERT_MGF1_SHA512;
    SB_ALGORITHM_DGST_RIPEMD160 :
      Result := SB_CERT_MGF1_RIPEMD160;
    SB_ALGORITHM_DGST_WHIRLPOOL:
      Result := SB_CERT_MGF1_WHIRLPOOL;
  else
    Result := SB_CERT_MGF1;
  end;
end;

function HashAlgorithmByMGF1(Value: integer): integer;
begin
  case Value of
    SB_CERT_MGF1_SHA1 :
      Result := SB_ALGORITHM_DGST_SHA1;
    SB_CERT_MGF1_SHA224 :
      Result := SB_ALGORITHM_DGST_SHA224;
    SB_CERT_MGF1_SHA256 :
      Result := SB_ALGORITHM_DGST_SHA256;
    SB_CERT_MGF1_SHA384 :
      Result := SB_ALGORITHM_DGST_SHA384;
    SB_CERT_MGF1_SHA512 :
      Result := SB_ALGORITHM_DGST_SHA512;
    SB_CERT_MGF1_RIPEMD160 :
      Result := SB_ALGORITHM_DGST_RIPEMD160;
    SB_CERT_MGF1_WHIRLPOOL :
      Result := SB_ALGORITHM_DGST_WHIRLPOOL;
  else
    Result := SB_ALGORITHM_DGST_SHA1;
  end;
end;

initialization
  begin
  {$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}

    SpaceByteArray := CreateByteArrayConst( SpaceByteArray_STR );
    CommaByteArray := CreateByteArrayConst( CommaByteArray_STR );
    SlashByteArray := CreateByteArrayConst( SlashByteArray_STR );
    ColonByteArray := CreateByteArrayConst( ColonByteArray_STR );
    EqualCharByteArray := CreateByteArrayConst( EqualCharByteArray_STR);
    DashByteArray := CreateByteArrayConst( DashByteArray_STR );

    LFByteArray := CreateByteArrayConst( LFByteArray_STR );
    CRByteArray := CreateByteArrayConst( CRByteArray_STR );

    LFLFByteArray := CreateByteArrayConst( LFLFByteArray_STR );
    CRLFByteArray := CreateByteArrayConst( CRLFByteArray_STR );
    CRLFCRLFByteArray := CreateByteArrayConst( CRLFCRLFByteArray_STR );
    CRCRLFByteArray := CreateByteArrayConst( CRCRLFByteArray_STR );
    CRLFTABByteArray := CreateByteArrayConst( CRLFTABByteArray_STR );
    CRLFSPACEByteArray := CreateByteArrayConst( CRLFSPACEByteArray_STR );
    CRCRLFCRCRLFByteArray := CreateByteArrayConst( CRCRLFCRCRLFByteArray_STR );

    TwoDashesByteArray := CreateByteArrayConst( TwoDashesByteArray_STR );
    FiveDashesByteArray := CreateByteArrayConst( FiveDashesByteArray_STR );
    BeginLineByteArray := CreateByteArrayConst( BeginLineByteArray_STR );
    LFEndLineByteArray := CreateByteArrayConst( LFEndLineByteArray_STR );

    UTF8BOMByteArray := CreateByteArrayConst( UTF8BOMByteArray_STR );

    SB_OID_RC4                := CreateByteArrayConst( SB_OID_RC4_STR );
    SB_OID_RSAENCRYPTION      := CreateByteArrayConst( SB_OID_RSAENCRYPTION_STR );
    SB_OID_EA_RSA             := CreateByteArrayConst( SB_OID_EA_RSA_STR );
    SB_OID_RSAPSS             := CreateByteArrayConst( SB_OID_RSAPSS_STR );
    SB_OID_RSAOAEP            := CreateByteArrayConst( SB_OID_RSAOAEP_STR );
    SB_OID_DSA                := CreateByteArrayConst( SB_OID_DSA_STR );
    SB_OID_DSA_SHA1           := CreateByteArrayConst( SB_OID_DSA_SHA1_STR );
    SB_OID_DSA_SHA224         := CreateByteArrayConst( SB_OID_DSA_SHA224_STR );
    SB_OID_DSA_SHA256         := CreateByteArrayConst( SB_OID_DSA_SHA256_STR );
    SB_OID_DSA_ALT            := CreateByteArrayConst( SB_OID_DSA_ALT_STR );
    SB_OID_DSA_SHA1_ALT       := CreateByteArrayConst( SB_OID_DSA_SHA1_ALT_STR );
    SB_OID_DH                 := CreateByteArrayConst( SB_OID_DH_STR );
    SB_OID_DES_EDE3_CBC       := CreateByteArrayConst( SB_OID_DES_EDE3_CBC_STR );
    SB_OID_PKCS7_DATA         := CreateByteArrayConst( SB_OID_PKCS7_DATA_STR );
    SB_OID_RC2_CBC            := CreateByteArrayConst( SB_OID_RC2_CBC_STR );
    SB_OID_DES_CBC            := CreateByteArrayConst( SB_OID_DES_CBC_STR );
    SB_OID_SHA1_RSAENCRYPTION := CreateByteArrayConst( SB_OID_SHA1_RSAENCRYPTION_STR );
    SB_OID_SHA1_RSAENCRYPTION2 := CreateByteArrayConst( SB_OID_SHA1_RSAENCRYPTION2_STR );
    SB_OID_SHA224_RSAENCRYPTION := CreateByteArrayConst( SB_OID_SHA224_RSAENCRYPTION_STR );
    SB_OID_SHA256_RSAENCRYPTION := CreateByteArrayConst( SB_OID_SHA256_RSAENCRYPTION_STR );
    SB_OID_SHA384_RSAENCRYPTION := CreateByteArrayConst( SB_OID_SHA384_RSAENCRYPTION_STR );
    SB_OID_SHA512_RSAENCRYPTION := CreateByteArrayConst( SB_OID_SHA512_RSAENCRYPTION_STR );
    SB_OID_RSASIGNATURE_RIPEMD160 := CreateByteArrayConst( SB_OID_RSASIGNATURE_RIPEMD160_STR );
    SB_OID_TSTINFO          := CreateByteArrayConst( SB_OID_TSTINFO_STR );
    SB_OID_AES128_CBC         := CreateByteArrayConst( SB_OID_AES128_CBC_STR );
    SB_OID_AES192_CBC         := CreateByteArrayConst( SB_OID_AES192_CBC_STR );
    SB_OID_AES256_CBC         := CreateByteArrayConst( SB_OID_AES256_CBC_STR );
    SB_OID_SERPENT128_CBC     := CreateByteArrayConst( SB_OID_SERPENT128_CBC_STR );
    SB_OID_SERPENT192_CBC     := CreateByteArrayConst( SB_OID_SERPENT192_CBC_STR );
    SB_OID_SERPENT256_CBC     := CreateByteArrayConst( SB_OID_SERPENT256_CBC_STR );
    SB_OID_CAST5_CBC          := CreateByteArrayConst( SB_OID_CAST5_CBC_STR );
    SB_OID_BLOWFISH_CBC       := CreateByteArrayConst( SB_OID_BLOWFISH_CBC_STR );
    SB_OID_CAMELLIA128_CBC    := CreateByteArrayConst( SB_OID_CAMELLIA128_CBC_STR );
    SB_OID_CAMELLIA192_CBC    := CreateByteArrayConst( SB_OID_CAMELLIA192_CBC_STR );
    SB_OID_CAMELLIA256_CBC    := CreateByteArrayConst( SB_OID_CAMELLIA256_CBC_STR );
    SB_OID_SEED               := CreateByteArrayConst( SB_OID_SEED_STR );
    SB_OID_RABBIT             := CreateByteArrayConst( SB_OID_RABBIT_STR );
    SB_OID_IDENTITY           := CreateByteArrayConst( SB_OID_IDENTITY_STR ); // special fake OID value
    SB_OID_IDENTITY_ELDOS     := CreateByteArrayConst( SB_OID_IDENTITY_ELDOS_STR);
    // ISO 9796
    SB_OID_RSASIGNATURE_RIPEMD160_ISO9796:= CreateByteArrayConst( SB_OID_RSASIGNATURE_RIPEMD160_ISO9796_STR );
    SB_OID_WHIRLPOOL_RSAENCRYPTION_ELDOS := CreateByteArrayConst( SB_OID_WHIRLPOOL_RSAENCRYPTION_ELDOS_STR );

    //mask generation function
    SB_OID_MGF1               := CreateByteArrayConst( SB_OID_MGF1_STR );

    SB_OID_MGF1_SHA1 := CreateByteArrayConst( SB_OID_MGF1_SHA1_STR );
    SB_OID_MGF1_SHA224 := CreateByteArrayConst( SB_OID_MGF1_SHA224_STR );
    SB_OID_MGF1_SHA256 := CreateByteArrayConst( SB_OID_MGF1_SHA256_STR );
    SB_OID_MGF1_SHA384 := CreateByteArrayConst( SB_OID_MGF1_SHA384_STR );
    SB_OID_MGF1_SHA512 := CreateByteArrayConst( SB_OID_MGF1_SHA512_STR );
    SB_OID_MGF1_RIPEMD160 := CreateByteArrayConst( SB_OID_MGF1_RIPEMD160_STR );
    SB_OID_MGF1_WHIRLPOOL := CreateByteArrayConst( SB_OID_MGF1_WHIRLPOOL_STR );

    //label source function for RSA-OAEP
    SB_OID_OAEP_SRC_SPECIFIED := CreateByteArrayConst( SB_OID_OAEP_SRC_SPECIFIED_STR );
    //PKCS#5 password-based encryption
    SB_OID_PBE_MD2_DES        := CreateByteArrayConst( SB_OID_PBE_MD2_DES_STR );
    SB_OID_PBE_MD2_RC2        := CreateByteArrayConst( SB_OID_PBE_MD2_RC2_STR );
    SB_OID_PBE_MD5_DES        := CreateByteArrayConst( SB_OID_PBE_MD5_DES_STR );
    SB_OID_PBE_MD5_RC2        := CreateByteArrayConst( SB_OID_PBE_MD5_RC2_STR );
    SB_OID_PBE_SHA1_DES       := CreateByteArrayConst( SB_OID_PBE_SHA1_DES_STR );
    SB_OID_PBE_SHA1_RC2       := CreateByteArrayConst( SB_OID_PBE_SHA1_RC2_STR );
    SB_OID_PBES2              := CreateByteArrayConst( SB_OID_PBES2_STR );
    SB_OID_PBKDF2             := CreateByteArrayConst( SB_OID_PBKDF2_STR );
    SB_OID_PBMAC1             := CreateByteArrayConst( SB_OID_PBMAC1_STR );

    //PKCS#12
    SB_OID_PBE_SHA1_RC4_128   := CreateByteArrayConst( SB_OID_PBE_SHA1_RC4_128_STR );
    SB_OID_PBE_SHA1_RC4_40    := CreateByteArrayConst( SB_OID_PBE_SHA1_RC4_40_STR );
    SB_OID_PBE_SHA1_3DES      := CreateByteArrayConst( SB_OID_PBE_SHA1_3DES_STR );
    SB_OID_PBE_SHA1_RC2_128   := CreateByteArrayConst( SB_OID_PBE_SHA1_RC2_128_STR );
    SB_OID_PBE_SHA1_RC2_40    := CreateByteArrayConst( SB_OID_PBE_SHA1_RC2_40_STR );
    SB_OID_MD2_RSAENCRYPTION  := CreateByteArrayConst( SB_OID_MD2_RSAENCRYPTION_STR );
    SB_OID_MD5_RSAENCRYPTION  := CreateByteArrayConst( SB_OID_MD5_RSAENCRYPTION_STR );
    SB_OID_SHA1_RSA           := CreateByteArrayConst( SB_OID_SHA1_RSA_STR );
    SB_OID_SHA1_DSA           := CreateByteArrayConst( SB_OID_SHA1_DSA_STR );

    // PKCS#15
    SB_OID_PKCS15             := CreateByteArrayConst( SB_OID_PKCS15_STR );
    SB_OID_PWRI_KEK           := CreateByteArrayConst( SB_OID_PWRI_KEK_STR );
    SB_OID_DATA               := CreateByteArrayConst( SB_OID_DATA_STR );

    // Digest Algorithm OIDs
    SB_OID_MD2                := CreateByteArrayConst( SB_OID_MD2_STR );
    SB_OID_MD4                := CreateByteArrayConst( SB_OID_MD4_STR );
    SB_OID_MD5                := CreateByteArrayConst( SB_OID_MD5_STR );
    SB_OID_SHA1               := CreateByteArrayConst( SB_OID_SHA1_STR );
    SB_OID_SHA224             := CreateByteArrayConst( SB_OID_SHA224_STR );
    SB_OID_SHA256             := CreateByteArrayConst( SB_OID_SHA256_STR );
    SB_OID_SHA384             := CreateByteArrayConst( SB_OID_SHA384_STR );
    SB_OID_SHA512             := CreateByteArrayConst( SB_OID_SHA512_STR );
    SB_OID_RIPEMD160          := CreateByteArrayConst( SB_OID_RIPEMD160_STR );
    SB_OID_SSL3               := CreateByteArrayConst( SB_OID_SSL3_STR );
    SB_OID_WHIRLPOOL          := CreateByteArrayConst( SB_OID_WHIRLPOOL_STR );

    // MAC Algorithm OIDs
    SB_OID_HMACSHA1           := CreateByteArrayConst( SB_OID_HMACSHA1_STR );
    SB_OID_HMACSHA1_PKCS      := CreateByteArrayConst( SB_OID_HMACSHA1_PKCS_STR );
    SB_OID_HMACSHA224         := CreateByteArrayConst( SB_OID_HMACSHA224_STR );
    SB_OID_HMACSHA256         := CreateByteArrayConst( SB_OID_HMACSHA256_STR );
    SB_OID_HMACSHA384         := CreateByteArrayConst( SB_OID_HMACSHA384_STR );
    SB_OID_HMACSHA512         := CreateByteArrayConst( SB_OID_HMACSHA512_STR );
    SB_OID_RSA_HMACSHA1       := CreateByteArrayConst( SB_OID_RSA_HMACSHA1_STR ); // a copy of SB_OID_HMACSHA1_PKCS

    // UMAC
    SB_OID_UMAC32             := CreateByteArrayConst( SB_OID_UMAC32_STR );
    SB_OID_UMAC64             := CreateByteArrayConst( SB_OID_UMAC64_STR );
    SB_OID_UMAC96             := CreateByteArrayConst( SB_OID_UMAC96_STR );
    SB_OID_UMAC128            := CreateByteArrayConst( SB_OID_UMAC128_STR );

    // Attribute OIDs
    SB_OID_CONTENT_TYPE       := CreateByteArrayConst( SB_OID_CONTENT_TYPE_STR );
    SB_OID_MESSAGE_DIGEST     := CreateByteArrayConst( SB_OID_MESSAGE_DIGEST_STR );
    SB_OID_SIGNING_TIME       := CreateByteArrayConst( SB_OID_SIGNING_TIME_STR );
    SB_OID_COUNTER_SIGNATURE  := CreateByteArrayConst( SB_OID_COUNTER_SIGNATURE_STR );
    SB_OID_SMIME_CAPABILITIES := CreateByteArrayConst( SB_OID_SMIME_CAPABILITIES_STR );
    SB_OID_TIMESTAMP_TOKEN    := CreateByteArrayConst( SB_OID_TIMESTAMP_TOKEN_STR );
    SB_OID_SIGNING_CERTIFICATE:= CreateByteArrayConst( SB_OID_SIGNING_CERTIFICATE_STR );
    SB_OID_SIGNING_CERTIFICATEV2:= CreateByteArrayConst( SB_OID_SIGNING_CERTIFICATEV2_STR );
    SB_OID_CONTENT_HINTS      := CreateByteArrayConst( SB_OID_CONTENT_HINTS_STR );
    SB_OID_CONTENT_IDENTIFIER := CreateByteArrayConst( SB_OID_CONTENT_IDENTIFIER_STR );
    SB_OID_CONTENT_REFERENCE  := CreateByteArrayConst( SB_OID_CONTENT_REFERENCE_STR );
    SB_OID_SIGNATURE_POLICY   := CreateByteArrayConst( SB_OID_SIGNATURE_POLICY_STR );
    SB_OID_COMMITMENT_TYPE    := CreateByteArrayConst( SB_OID_COMMITMENT_TYPE_STR );
    SB_OID_SIGNER_LOCATION    := CreateByteArrayConst( SB_OID_SIGNER_LOCATION_STR );
    SB_OID_SIGNER_ATTRIBUTES  := CreateByteArrayConst( SB_OID_SIGNER_ATTRIBUTES_STR );
    SB_OID_CONTENT_TIMESTAMP  := CreateByteArrayConst( SB_OID_CONTENT_TIMESTAMP_STR );
    SB_OID_CERTIFICATE_REFS   := CreateByteArrayConst( SB_OID_CERTIFICATE_REFS_STR );
    SB_OID_REVOCATION_REFS    := CreateByteArrayConst( SB_OID_REVOCATION_REFS_STR );
    SB_OID_CERTIFICATE_VALUES := CreateByteArrayConst( SB_OID_CERTIFICATE_VALUES_STR );
    SB_OID_REVOCATION_VALUES  := CreateByteArrayConst( SB_OID_REVOCATION_VALUES_STR );
    SB_OID_ESCTIMESTAMP       := CreateByteArrayConst( SB_OID_ESCTIMESTAMP_STR );
    SB_OID_CERTCRLTIMESTAMP   := CreateByteArrayConst( SB_OID_CERTCRLTIMESTAMP_STR );
    SB_OID_ARCHIVETIMESTAMP   := CreateByteArrayConst( SB_OID_ARCHIVETIMESTAMP_STR );
    SB_OID_ARCHIVETIMESTAMP2  := CreateByteArrayConst( SB_OID_ARCHIVETIMESTAMP2_STR );
    SB_OID_ARCHIVETIMESTAMP3  := CreateByteArrayConst( SB_OID_ARCHIVETIMESTAMP3_STR );
    SB_OID_ATSHASHINDEX       := CreateByteArrayConst( SB_OID_ATSHASHINDEX_STR );

    // Authenticode OIDs
    SB_OID_SPC_INDIRECT_DATA  := CreateByteArrayConst( SB_OID_SPC_INDIRECT_DATA_STR );
    SB_OID_SPC_SP_AGENCY_INFO := CreateByteArrayConst( SB_OID_SPC_SP_AGENCY_INFO_STR );
    SB_OID_SPC_STATEMENT_TYPE_OBJID := CreateByteArrayConst( SB_OID_SPC_STATEMENT_TYPE_OBJID_STR );
    SB_OID_SPC_STATEMENT_TYPE := CreateByteArrayConst( SB_OID_SPC_STATEMENT_TYPE_STR );
    SB_OID_SPC_SP_OPUS_INFO   := CreateByteArrayConst( SB_OID_SPC_SP_OPUS_INFO_STR );
    SB_OID_SPC_PE_IMAGE_DATA  := CreateByteArrayConst( SB_OID_SPC_PE_IMAGE_DATA_STR );
    SB_OID_SPC_MINIMAL_CRITERIA:= CreateByteArrayConst( SB_OID_SPC_MINIMAL_CRITERIA_STR );
    SB_OID_SPC_FINANCIAL_CRITERIA:= CreateByteArrayConst( SB_OID_SPC_FINANCIAL_CRITERIA_STR );
    SB_OID_SPC_LINK           := CreateByteArrayConst( SB_OID_SPC_LINK_STR );
    SB_OID_SPC_HASH_INFO      := CreateByteArrayConst( SB_OID_SPC_HASH_INFO_STR );
    SB_OID_SPC_SIPINFO        := CreateByteArrayConst( SB_OID_SPC_SIPINFO_STR );
    SB_OID_SPC_CERT_EXTENSIONS:= CreateByteArrayConst( SB_OID_SPC_CERT_EXTENSIONS_STR );
    SB_OID_SPC_RAW_FILE_DATA  := CreateByteArrayConst( SB_OID_SPC_RAW_FILE_DATA_STR );
    SB_OID_SPC_STRUCTURED_STORAGE_DATA:= CreateByteArrayConst( SB_OID_SPC_STRUCTURED_STORAGE_DATA_STR );
    SB_OID_SPC_JAVA_CLASS_DATA:= CreateByteArrayConst( SB_OID_SPC_JAVA_CLASS_DATA_STR );
    SB_OID_SPC_INDIVIDUAL_SP_KEY_PURPOSE:= CreateByteArrayConst( SB_OID_SPC_INDIVIDUAL_SP_KEY_PURPOSE_STR );
    SB_OID_SPC_COMMERCIAL_SP_KEY_PURPOSE:= CreateByteArrayConst( SB_OID_SPC_COMMERCIAL_SP_KEY_PURPOSE_STR );
    SB_OID_SPC_CAB_DATA       := CreateByteArrayConst( SB_OID_SPC_CAB_DATA_STR );
    // certificate extension OIDs
    SB_OID_QT_CPS             := CreateByteArrayConst( SB_OID_QT_CPS_STR );
    SB_OID_QT_UNOTICE         := CreateByteArrayConst( SB_OID_QT_UNOTICE_STR );
    SB_OID_SERVER_AUTH        := CreateByteArrayConst( SB_OID_SERVER_AUTH_STR );
    SB_OID_CLIENT_AUTH        := CreateByteArrayConst( SB_OID_CLIENT_AUTH_STR );
    SB_OID_CODE_SIGNING       := CreateByteArrayConst( SB_OID_CODE_SIGNING_STR );
    SB_OID_EMAIL_PROT         := CreateByteArrayConst( SB_OID_EMAIL_PROT_STR );
    SB_OID_TIME_STAMPING      := CreateByteArrayConst( SB_OID_TIME_STAMPING_STR );
    SB_OID_OCSP_SIGNING       := CreateByteArrayConst( SB_OID_OCSP_SIGNING_STR );

    SB_OID_ACCESS_METHOD_OCSP := CreateByteArrayConst( SB_OID_ACCESS_METHOD_OCSP_STR );


    SB_OID_UNSTRUCTURED_NAME  := CreateByteArrayConst( SB_OID_UNSTRUCTURED_NAME_STR );

    SB_OID_CERT_EXTENSIONS    := CreateByteArrayConst( SB_OID_CERT_EXTENSIONS_STR );
    SB_OID_CERT_EXTENSIONS_MS := CreateByteArrayConst( SB_OID_CERT_EXTENSIONS_MS_STR );

    // GOST algorithms
    SB_OID_GOST_28147_1989           := CreateByteArrayConst( SB_OID_GOST_28147_1989_STR );
    SB_OID_GOST_28147_1989_MAC       := CreateByteArrayConst( SB_OID_GOST_28147_1989_MAC_STR );
    SB_OID_GOST_R3410_2001           := CreateByteArrayConst( SB_OID_GOST_R3410_2001_STR );
    SB_OID_GOST_R3410_1994           := CreateByteArrayConst( SB_OID_GOST_R3410_1994_STR );
    SB_OID_GOST_R3410_1994_DH        := CreateByteArrayConst( SB_OID_GOST_R3410_1994_DH_STR );
    SB_OID_GOST_R3411_1994_WITH_GOST_R3410_2001 := CreateByteArrayConst( SB_OID_GOST_R3411_1994_WITH_GOST_R3410_2001_STR );
    SB_OID_GOST_R3411_1994_WITH_GOST_R3410_1994 := CreateByteArrayConst( SB_OID_GOST_R3411_1994_WITH_GOST_R3410_1994_STR );
    SB_OID_GOST_R3411_1994           := CreateByteArrayConst( SB_OID_GOST_R3411_1994_STR );
    SB_OID_GOST_R3411_1994_HMAC      := CreateByteArrayConst( SB_OID_GOST_R3411_1994_HMAC_STR );

    // GOST algorithm parameters
    // CryptoPro RFC 4357 GOST 28147-89 parameters
    SB_OID_GOST_28147_1989_PARAM_CP_TEST  := CreateByteArrayConst( SB_OID_GOST_28147_1989_PARAM_CP_TEST_STR );
    SB_OID_GOST_28147_1989_PARAM_CP_A     := CreateByteArrayConst( SB_OID_GOST_28147_1989_PARAM_CP_A_STR );
    SB_OID_GOST_28147_1989_PARAM_CP_B     := CreateByteArrayConst( SB_OID_GOST_28147_1989_PARAM_CP_B_STR );
    SB_OID_GOST_28147_1989_PARAM_CP_C     := CreateByteArrayConst( SB_OID_GOST_28147_1989_PARAM_CP_C_STR );
    SB_OID_GOST_28147_1989_PARAM_CP_D     := CreateByteArrayConst( SB_OID_GOST_28147_1989_PARAM_CP_D_STR );
    SB_OID_GOST_28147_1989_PARAM_CP_OSCAR_11 := CreateByteArrayConst( SB_OID_GOST_28147_1989_PARAM_CP_OSCAR_11_STR );
    SB_OID_GOST_28147_1989_PARAM_CP_OSCAR_10 := CreateByteArrayConst( SB_OID_GOST_28147_1989_PARAM_CP_OSCAR_10_STR );
    SB_OID_GOST_28147_1989_PARAM_CP_RIC_1 := CreateByteArrayConst( SB_OID_GOST_28147_1989_PARAM_CP_RIC_1_STR );
    // CryptoPro RFC 4357 GOST R 34.11-94 parameters
    SB_OID_GOST_R3411_1994_PARAM_CP_TEST  := CreateByteArrayConst( SB_OID_GOST_R3411_1994_PARAM_CP_TEST_STR );
    SB_OID_GOST_R3411_1994_PARAM_CP       := CreateByteArrayConst( SB_OID_GOST_R3411_1994_PARAM_CP_STR );
    // CryptoPro RFC 4357 GOST R 34.10-94 parameters
    SB_OID_GOST_R3410_1994_PARAM_CP_TEST  := CreateByteArrayConst( SB_OID_GOST_R3410_1994_PARAM_CP_TEST_STR );
    SB_OID_GOST_R3410_1994_PARAM_CP_A     := CreateByteArrayConst( SB_OID_GOST_R3410_1994_PARAM_CP_A_STR );
    SB_OID_GOST_R3410_1994_PARAM_CP_B     := CreateByteArrayConst( SB_OID_GOST_R3410_1994_PARAM_CP_B_STR );
    SB_OID_GOST_R3410_1994_PARAM_CP_C     := CreateByteArrayConst( SB_OID_GOST_R3410_1994_PARAM_CP_C_STR );
    SB_OID_GOST_R3410_1994_PARAM_CP_D     := CreateByteArrayConst( SB_OID_GOST_R3410_1994_PARAM_CP_D_STR );
    SB_OID_GOST_R3410_1994_PARAM_CP_XCHA  := CreateByteArrayConst( SB_OID_GOST_R3410_1994_PARAM_CP_XCHA_STR );
    SB_OID_GOST_R3410_1994_PARAM_CP_XCHB  := CreateByteArrayConst( SB_OID_GOST_R3410_1994_PARAM_CP_XCHB_STR );
    SB_OID_GOST_R3410_1994_PARAM_CP_XCHC  := CreateByteArrayConst( SB_OID_GOST_R3410_1994_PARAM_CP_XCHC_STR );
    // CryptoPro RFC 4357 GOST R 34.10-2001 parameters are represented by curves below

    // EC-related OIDs

    // EC field OIDs
    SB_OID_FLD_CUSTOM         := CreateByteArrayConst( SB_OID_FLD_CUSTOM_STR );
    SB_OID_FLD_TYPE_FP        := CreateByteArrayConst( SB_OID_FLD_TYPE_FP_STR );
    SB_OID_FLD_TYPE_F2M       := CreateByteArrayConst( SB_OID_FLD_TYPE_F2M_STR );
    SB_OID_FLD_BASIS_N        := CreateByteArrayConst( SB_OID_FLD_BASIS_N_STR );
    SB_OID_FLD_BASIS_T        := CreateByteArrayConst( SB_OID_FLD_BASIS_T_STR );
    SB_OID_FLD_BASIS_P        := CreateByteArrayConst( SB_OID_FLD_BASIS_P_STR );

    // EC key types
    SB_OID_EC_KEY             := CreateByteArrayConst( SB_OID_EC_KEY_STR );
    SB_OID_ECDH               := CreateByteArrayConst( SB_OID_ECDH_STR );
    SB_OID_ECMQV              := CreateByteArrayConst( SB_OID_ECMQV_STR );

    // ECDSA X9.62 signature algorithms
    SB_OID_ECDSA_SHA1         := CreateByteArrayConst( SB_OID_ECDSA_SHA1_STR );
    SB_OID_ECDSA_RECOMMENDED  := CreateByteArrayConst( SB_OID_ECDSA_RECOMMENDED_STR );
    SB_OID_ECDSA_SHA224       := CreateByteArrayConst( SB_OID_ECDSA_SHA224_STR );
    SB_OID_ECDSA_SHA256       := CreateByteArrayConst( SB_OID_ECDSA_SHA256_STR );
    SB_OID_ECDSA_SHA384       := CreateByteArrayConst( SB_OID_ECDSA_SHA384_STR );
    SB_OID_ECDSA_SHA512       := CreateByteArrayConst( SB_OID_ECDSA_SHA512_STR );
    SB_OID_ECDSA_SPECIFIED    := CreateByteArrayConst( SB_OID_ECDSA_SPECIFIED_STR );

    // ECDSA signature algorithm, German BSI Technical Guideline TR-03111
    SB_OID_ECDSA_PLAIN_SHA1     := CreateByteArrayConst( SB_OID_ECDSA_PLAIN_SHA1_STR );
    SB_OID_ECDSA_PLAIN_SHA224   := CreateByteArrayConst( SB_OID_ECDSA_PLAIN_SHA224_STR );
    SB_OID_ECDSA_PLAIN_SHA256   := CreateByteArrayConst( SB_OID_ECDSA_PLAIN_SHA256_STR );
    SB_OID_ECDSA_PLAIN_SHA384   := CreateByteArrayConst( SB_OID_ECDSA_PLAIN_SHA384_STR );
    SB_OID_ECDSA_PLAIN_SHA512   := CreateByteArrayConst( SB_OID_ECDSA_PLAIN_SHA512_STR );
    SB_OID_ECDSA_PLAIN_RIPEMD160:= CreateByteArrayConst( SB_OID_ECDSA_PLAIN_RIPEMD160_STR );

    // Known elliptic curve OIDs
    // fake OID to represent custom EC
    SB_OID_EC_CUSTOM          := CreateByteArrayConst( SB_OID_EC_CUSTOM_STR );

    // X9.62 curves
    { recommended curves over the binary fields }
    SB_OID_EC_C2PNB163V1      := CreateByteArrayConst( SB_OID_EC_C2PNB163V1_STR );
    SB_OID_EC_C2PNB163V2      := CreateByteArrayConst( SB_OID_EC_C2PNB163V2_STR );
    SB_OID_EC_C2PNB163V3      := CreateByteArrayConst( SB_OID_EC_C2PNB163V3_STR );
    SB_OID_EC_C2PNB176W1      := CreateByteArrayConst( SB_OID_EC_C2PNB176W1_STR );
    SB_OID_EC_C2TNB191V1      := CreateByteArrayConst( SB_OID_EC_C2TNB191V1_STR );
    SB_OID_EC_C2TNB191V2      := CreateByteArrayConst( SB_OID_EC_C2TNB191V2_STR );
    SB_OID_EC_C2TNB191V3      := CreateByteArrayConst( SB_OID_EC_C2TNB191V3_STR );
    SB_OID_EC_C2ONB191V4      := CreateByteArrayConst( SB_OID_EC_C2ONB191V4_STR );
    SB_OID_EC_C2ONB191V5      := CreateByteArrayConst( SB_OID_EC_C2ONB191V5_STR );
    SB_OID_EC_C2PNB208W1      := CreateByteArrayConst( SB_OID_EC_C2PNB208W1_STR );
    SB_OID_EC_C2TNB239V1      := CreateByteArrayConst( SB_OID_EC_C2TNB239V1_STR );
    SB_OID_EC_C2TNB239V2      := CreateByteArrayConst( SB_OID_EC_C2TNB239V2_STR );
    SB_OID_EC_C2TNB239V3      := CreateByteArrayConst( SB_OID_EC_C2TNB239V3_STR );
    SB_OID_EC_C2ONB239V4      := CreateByteArrayConst( SB_OID_EC_C2ONB239V4_STR );
    SB_OID_EC_C2ONB239V5      := CreateByteArrayConst( SB_OID_EC_C2ONB239V5_STR );
    SB_OID_EC_C2PNB272W1      := CreateByteArrayConst( SB_OID_EC_C2PNB272W1_STR );
    SB_OID_EC_C2PNB304W1      := CreateByteArrayConst( SB_OID_EC_C2PNB304W1_STR );
    SB_OID_EC_C2TNB359V1      := CreateByteArrayConst( SB_OID_EC_C2TNB359V1_STR );
    SB_OID_EC_C2PNB368W1      := CreateByteArrayConst( SB_OID_EC_C2PNB368W1_STR );
    SB_OID_EC_C2TNB431R1      := CreateByteArrayConst( SB_OID_EC_C2TNB431R1_STR );
    { recommended curves over the prime field }
    SB_OID_EC_PRIME192V1      := CreateByteArrayConst( SB_OID_EC_PRIME192V1_STR );
    SB_OID_EC_PRIME192V2      := CreateByteArrayConst( SB_OID_EC_PRIME192V2_STR );
    SB_OID_EC_PRIME192V3      := CreateByteArrayConst( SB_OID_EC_PRIME192V3_STR );
    SB_OID_EC_PRIME239V1      := CreateByteArrayConst( SB_OID_EC_PRIME239V1_STR );
    SB_OID_EC_PRIME239V2      := CreateByteArrayConst( SB_OID_EC_PRIME239V2_STR );
    SB_OID_EC_PRIME239V3      := CreateByteArrayConst( SB_OID_EC_PRIME239V3_STR );
    SB_OID_EC_PRIME256V1      := CreateByteArrayConst( SB_OID_EC_PRIME256V1_STR );
    // SEC2 curves
    { SEC2 recommended curves over a prime field }
    SB_OID_EC_SECP112R1       := CreateByteArrayConst( SB_OID_EC_SECP112R1_STR );
    SB_OID_EC_SECP112R2       := CreateByteArrayConst( SB_OID_EC_SECP112R2_STR );
    SB_OID_EC_SECP128R1       := CreateByteArrayConst( SB_OID_EC_SECP128R1_STR );
    SB_OID_EC_SECP128R2       := CreateByteArrayConst( SB_OID_EC_SECP128R2_STR );
    SB_OID_EC_SECP160K1       := CreateByteArrayConst( SB_OID_EC_SECP160K1_STR );
    SB_OID_EC_SECP160R1       := CreateByteArrayConst( SB_OID_EC_SECP160R1_STR );
    SB_OID_EC_SECP160R2       := CreateByteArrayConst( SB_OID_EC_SECP160R2_STR );
    SB_OID_EC_SECP192K1       := CreateByteArrayConst( SB_OID_EC_SECP192K1_STR );
                                // SECP192R1 is the same as PRIME192V1
    SB_OID_EC_SECP192R1       := CreateByteArrayConst( SB_OID_EC_SECP192R1_STR );
    SB_OID_EC_SECP224K1       := CreateByteArrayConst( SB_OID_EC_SECP224K1_STR );
    SB_OID_EC_SECP224R1       := CreateByteArrayConst( SB_OID_EC_SECP224R1_STR );
    SB_OID_EC_SECP256K1       := CreateByteArrayConst( SB_OID_EC_SECP256K1_STR );
                                // SECP256R1 is the same as PRIME256V1
    SB_OID_EC_SECP256R1       := CreateByteArrayConst( SB_OID_EC_SECP256R1_STR );
    SB_OID_EC_SECP384R1       := CreateByteArrayConst( SB_OID_EC_SECP384R1_STR );
    SB_OID_EC_SECP521R1       := CreateByteArrayConst( SB_OID_EC_SECP521R1_STR );
    { SEC2 recommended curves over extended binary field }
    SB_OID_EC_SECT113R1       := CreateByteArrayConst( SB_OID_EC_SECT113R1_STR );
    SB_OID_EC_SECT113R2       := CreateByteArrayConst( SB_OID_EC_SECT113R2_STR );
    SB_OID_EC_SECT131R1       := CreateByteArrayConst( SB_OID_EC_SECT131R1_STR );
    SB_OID_EC_SECT131R2       := CreateByteArrayConst( SB_OID_EC_SECT131R2_STR );
    SB_OID_EC_SECT163K1       := CreateByteArrayConst( SB_OID_EC_SECT163K1_STR );
    SB_OID_EC_SECT163R1       := CreateByteArrayConst( SB_OID_EC_SECT163R1_STR );
    SB_OID_EC_SECT163R2       := CreateByteArrayConst( SB_OID_EC_SECT163R2_STR );
    SB_OID_EC_SECT193R1       := CreateByteArrayConst( SB_OID_EC_SECT193R1_STR );
    SB_OID_EC_SECT193R2       := CreateByteArrayConst( SB_OID_EC_SECT193R2_STR );
    SB_OID_EC_SECT233K1       := CreateByteArrayConst( SB_OID_EC_SECT233K1_STR );
    SB_OID_EC_SECT233R1       := CreateByteArrayConst( SB_OID_EC_SECT233R1_STR );
    SB_OID_EC_SECT239K1       := CreateByteArrayConst( SB_OID_EC_SECT239K1_STR );
    SB_OID_EC_SECT283K1       := CreateByteArrayConst( SB_OID_EC_SECT283K1_STR );
    SB_OID_EC_SECT283R1       := CreateByteArrayConst( SB_OID_EC_SECT283R1_STR );
    SB_OID_EC_SECT409K1       := CreateByteArrayConst( SB_OID_EC_SECT409K1_STR );
    SB_OID_EC_SECT409R1       := CreateByteArrayConst( SB_OID_EC_SECT409R1_STR );
    SB_OID_EC_SECT571K1       := CreateByteArrayConst( SB_OID_EC_SECT571K1_STR );
    SB_OID_EC_SECT571R1       := CreateByteArrayConst( SB_OID_EC_SECT571R1_STR );

    { GOST 34.11-2001 RFC 4357 (CryptoPro) curves }
    SB_OID_EC_GOST_CP_TEST    := CreateByteArrayConst( SB_OID_EC_GOST_CP_TEST_STR );
    SB_OID_EC_GOST_CP_A       := CreateByteArrayConst( SB_OID_EC_GOST_CP_A_STR );
    SB_OID_EC_GOST_CP_B       := CreateByteArrayConst( SB_OID_EC_GOST_CP_B_STR );
    SB_OID_EC_GOST_CP_C       := CreateByteArrayConst( SB_OID_EC_GOST_CP_C_STR );
    SB_OID_EC_GOST_CP_XCHA    := CreateByteArrayConst( SB_OID_EC_GOST_CP_XCHA_STR );
    SB_OID_EC_GOST_CP_XCHB    := CreateByteArrayConst( SB_OID_EC_GOST_CP_XCHB_STR );

    { EldoS Corporation dedicated OIDs }
    SB_OID_ELDOSCORP_BASE     := CreateByteArrayConst( SB_OID_ELDOSCORP_BASE_STR ); // 1.3.6.1.4.1.34850
    { all direct sub-OIDs (first-level sub-OIDs) must be defined here to prevent conflicts }
    SB_OID_ELDOS_PKI          := CreateByteArrayConst( SB_OID_ELDOS_PKI_STR );
    SB_OID_ELDOS_ALGS         := CreateByteArrayConst( SB_OID_ELDOS_ALGS_STR );
    SB_OID_ELDOS_DATASTORAGE  := CreateByteArrayConst( SB_OID_ELDOS_DATASTORAGE_STR );

    SB_OID_ELDOS_ALGS_NULL    := CreateByteArrayConst( SB_OID_ELDOS_ALGS_NULL_STR );
    SB_OID_ELDOS_ALGS_PKEY    := CreateByteArrayConst( SB_OID_ELDOS_ALGS_PKEY_STR );
    SB_OID_ELDOS_ALGS_SKEY    := CreateByteArrayConst( SB_OID_ELDOS_ALGS_SKEY_STR );
    SB_OID_ELDOS_ALGS_DGST    := CreateByteArrayConst( SB_OID_ELDOS_ALGS_DGST_STR );
    SB_OID_ELDOS_ALGS_HMAC    := CreateByteArrayConst( SB_OID_ELDOS_ALGS_HMAC_STR );
    SB_OID_ELDOS_ALGS_COMPR   := CreateByteArrayConst( SB_OID_ELDOS_ALGS_COMPR_STR );

    SB_CERT_OID_COMMON_NAME          := CreateByteArrayConst( SB_CERT_OID_COMMON_NAME_STR );
    SB_CERT_OID_SURNAME              := CreateByteArrayConst( SB_CERT_OID_SURNAME_STR );
    SB_CERT_OID_COUNTRY              := CreateByteArrayConst( SB_CERT_OID_COUNTRY_STR );
    SB_CERT_OID_LOCALITY             := CreateByteArrayConst( SB_CERT_OID_LOCALITY_STR );
    SB_CERT_OID_STATE_OR_PROVINCE    := CreateByteArrayConst( SB_CERT_OID_STATE_OR_PROVINCE_STR );
    SB_CERT_OID_ORGANIZATION         := CreateByteArrayConst( SB_CERT_OID_ORGANIZATION_STR );
    SB_CERT_OID_ORGANIZATION_UNIT    := CreateByteArrayConst( SB_CERT_OID_ORGANIZATION_UNIT_STR );
    SB_CERT_OID_TITLE                := CreateByteArrayConst( SB_CERT_OID_TITLE_STR );
    SB_CERT_OID_NAME                 := CreateByteArrayConst( SB_CERT_OID_NAME_STR );
    SB_CERT_OID_GIVEN_NAME           := CreateByteArrayConst( SB_CERT_OID_GIVEN_NAME_STR );
    SB_CERT_OID_INITIALS             := CreateByteArrayConst( SB_CERT_OID_INITIALS_STR );
    SB_CERT_OID_GENERATION_QUALIFIER := CreateByteArrayConst( SB_CERT_OID_GENERATION_QUALIFIER_STR );
    SB_CERT_OID_DN_QUALIFIER         := CreateByteArrayConst( SB_CERT_OID_DN_QUALIFIER_STR );
    SB_CERT_OID_EMAIL                := CreateByteArrayConst( SB_CERT_OID_EMAIL_STR );

    SB_CERT_OID_STREET_ADDRESS       := CreateByteArrayConst( SB_CERT_OID_STREET_ADDRESS_STR );
    SB_CERT_OID_POSTAL_ADDRESS       := CreateByteArrayConst( SB_CERT_OID_POSTAL_ADDRESS_STR );
    SB_CERT_OID_POSTAL_CODE          := CreateByteArrayConst( SB_CERT_OID_POSTAL_CODE_STR );
    SB_CERT_OID_POST_OFFICE_BOX      := CreateByteArrayConst( SB_CERT_OID_POST_OFFICE_BOX_STR );
    SB_CERT_OID_PHYSICAL_DELIVERY_OFFICE_NAME := CreateByteArrayConst( SB_CERT_OID_PHYSICAL_DELIVERY_OFFICE_NAME_STR );
    SB_CERT_OID_TELEPHONE_NUMBER     := CreateByteArrayConst( SB_CERT_OID_TELEPHONE_NUMBER_STR );
    SB_CERT_OID_TELEX_NUMBER         := CreateByteArrayConst( SB_CERT_OID_TELEX_NUMBER_STR );
    SB_CERT_OID_TELEX_TERMINAL_ID    := CreateByteArrayConst( SB_CERT_OID_TELEX_TERMINAL_ID_STR );
    SB_CERT_OID_FACIMILE_PHONE_NUMBER:= CreateByteArrayConst( SB_CERT_OID_FACIMILE_PHONE_NUMBER_STR );

    SB_CERT_OID_X12_ADDRESS          := CreateByteArrayConst( SB_CERT_OID_X12_ADDRESS_STR );
    SB_CERT_OID_INTERNATIONAL_ISDN_NUMBER := CreateByteArrayConst( SB_CERT_OID_INTERNATIONAL_ISDN_NUMBER_STR );
    SB_CERT_OID_REGISTERED_ADDRESS   := CreateByteArrayConst( SB_CERT_OID_REGISTERED_ADDRESS_STR );
    SB_CERT_OID_DESTINATION_INDICATOR:= CreateByteArrayConst( SB_CERT_OID_DESTINATION_INDICATOR_STR );
    SB_CERT_OID_PREFERRED_DELIVERY_METHOD := CreateByteArrayConst( SB_CERT_OID_PREFERRED_DELIVERY_METHOD_STR );
    SB_CERT_OID_PRESENTATION_ADDRESS := CreateByteArrayConst( SB_CERT_OID_PRESENTATION_ADDRESS_STR );
    SB_CERT_OID_SUPPORTED_APPLICATION_CONTEXT := CreateByteArrayConst( SB_CERT_OID_SUPPORTED_APPLICATION_CONTEXT_STR );
    SB_CERT_OID_MEMBER            := CreateByteArrayConst( SB_CERT_OID_MEMBER_STR );
    SB_CERT_OID_OWNER             := CreateByteArrayConst( SB_CERT_OID_OWNER_STR );
    SB_CERT_OID_ROLE_OCCUPENT        := CreateByteArrayConst( SB_CERT_OID_ROLE_OCCUPENT_STR );
    SB_CERT_OID_SEE_ALSO             := CreateByteArrayConst( SB_CERT_OID_SEE_ALSO_STR );
    SB_CERT_OID_USER_PASSWORD        := CreateByteArrayConst( SB_CERT_OID_USER_PASSWORD_STR );
    SB_CERT_OID_USER_CERTIFICATE     := CreateByteArrayConst( SB_CERT_OID_USER_CERTIFICATE_STR );
    SB_CERT_OID_CA_CERTIFICATE       := CreateByteArrayConst( SB_CERT_OID_CA_CERTIFICATE_STR );
    SB_CERT_OID_AUTHORITY_REVOCATION_LIST := CreateByteArrayConst( SB_CERT_OID_AUTHORITY_REVOCATION_LIST_STR );
    SB_CERT_OID_CERTIFICATE_REVOCATION_LIST:= CreateByteArrayConst( SB_CERT_OID_CERTIFICATE_REVOCATION_LIST_STR );
    SB_CERT_OID_CERTIFICATE_PAIR     := CreateByteArrayConst( SB_CERT_OID_CERTIFICATE_PAIR_STR );
    SB_CERT_OID_UNIQUE_IDENTIFIER    := CreateByteArrayConst( SB_CERT_OID_UNIQUE_IDENTIFIER_STR );
    SB_CERT_OID_ENHANCED_SEARCH_GUIDE:= CreateByteArrayConst( SB_CERT_OID_ENHANCED_SEARCH_GUIDE_STR );

    SB_CERT_OID_OBJECT_CLASS         := CreateByteArrayConst( SB_CERT_OID_OBJECT_CLASS_STR );
    SB_CERT_OID_ALIASED_ENTRY_NAME   := CreateByteArrayConst( SB_CERT_OID_ALIASED_ENTRY_NAME_STR );
    SB_CERT_OID_KNOWLEDGE_INFORMATION:= CreateByteArrayConst( SB_CERT_OID_KNOWLEDGE_INFORMATION_STR );
    SB_CERT_OID_SERIAL_NUMBER        := CreateByteArrayConst( SB_CERT_OID_SERIAL_NUMBER_STR );
    SB_CERT_OID_DESCRIPTION          := CreateByteArrayConst( SB_CERT_OID_DESCRIPTION_STR );
    SB_CERT_OID_SEARCH_GUIDE         := CreateByteArrayConst( SB_CERT_OID_SEARCH_GUIDE_STR );
    SB_CERT_OID_BUSINESS_CATEGORY    := CreateByteArrayConst( SB_CERT_OID_BUSINESS_CATEGORY_STR );
    SB_CERT_OID_PROTOCOL_INFORMATION := CreateByteArrayConst( SB_CERT_OID_PROTOCOL_INFORMATION_STR );
    SB_CERT_OID_DISTINGUISHED_NAME   := CreateByteArrayConst( SB_CERT_OID_DISTINGUISHED_NAME_STR );
    SB_CERT_OID_UNIQUE_MEMBER        := CreateByteArrayConst( SB_CERT_OID_UNIQUE_MEMBER_STR );
    SB_CERT_OID_HOUSE_IDENTIFIER     := CreateByteArrayConst( SB_CERT_OID_HOUSE_IDENTIFIER_STR );
    SB_CERT_OID_SUPPORTED_ALGORITHMS := CreateByteArrayConst( SB_CERT_OID_SUPPORTED_ALGORITHMS_STR );
    SB_CERT_OID_DELTA_REVOCATION_LIST:= CreateByteArrayConst( SB_CERT_OID_DELTA_REVOCATION_LIST_STR );
    SB_CERT_OID_ATTRIBUTE_CERTIFICATE:= CreateByteArrayConst( SB_CERT_OID_ATTRIBUTE_CERTIFICATE_STR );
    SB_CERT_OID_PSEUDONYM            := CreateByteArrayConst( SB_CERT_OID_PSEUDONYM_STR );

    SB_CERT_OID_PERMANENT_IDENTIFIER := CreateByteArrayConst( SB_CERT_OID_PERMANENT_IDENTIFIER_STR );

    SB_CERT_OID_USER_ID              := CreateByteArrayConst( SB_CERT_OID_USER_ID_STR );
    SB_CERT_OID_DOMAIN_COMPONENT     := CreateByteArrayConst( SB_CERT_OID_DOMAIN_COMPONENT_STR );

    SB_CERT_OID_CA_OCSP              := CreateByteArrayConst( SB_CERT_OID_CA_OCSP_STR );
    SB_CERT_OID_CA_ISSUER            := CreateByteArrayConst( SB_CERT_OID_CA_ISSUER_STR );

    SB_CERT_OID_RSAENCRYPTION        := CreateByteArrayConst( SB_CERT_OID_RSAENCRYPTION_STR );
    SB_CERT_OID_RSAOAEP              := CreateByteArrayConst( SB_CERT_OID_RSAOAEP_STR );
    SB_CERT_OID_RSAPSS               := CreateByteArrayConst( SB_CERT_OID_RSAPSS_STR );
    SB_CERT_OID_DSA                  := CreateByteArrayConst( SB_CERT_OID_DSA_STR );
    SB_CERT_OID_DH                   := CreateByteArrayConst( SB_CERT_OID_DH_STR );
    SB_CERT_OID_DSA_SHA1             := CreateByteArrayConst( SB_CERT_OID_DSA_SHA1_STR );
    SB_CERT_OID_DSA_SHA224           := CreateByteArrayConst( SB_CERT_OID_DSA_SHA224_STR );
    SB_CERT_OID_DSA_SHA256           := CreateByteArrayConst( SB_CERT_OID_DSA_SHA256_STR );
    SB_CERT_OID_MD2_RSAENCRYPTION    := CreateByteArrayConst( SB_CERT_OID_MD2_RSAENCRYPTION_STR );
    SB_CERT_OID_MD5_RSAENCRYPTION    := CreateByteArrayConst( SB_CERT_OID_MD5_RSAENCRYPTION_STR );
    SB_CERT_OID_SHA1_RSAENCRYPTION   := CreateByteArrayConst( SB_CERT_OID_SHA1_RSAENCRYPTION_STR );
    SB_CERT_OID_SHA224_RSAENCRYPTION := CreateByteArrayConst( SB_CERT_OID_SHA224_RSAENCRYPTION_STR );
    SB_CERT_OID_SHA256_RSAENCRYPTION := CreateByteArrayConst( SB_CERT_OID_SHA256_RSAENCRYPTION_STR );
    SB_CERT_OID_SHA384_RSAENCRYPTION := CreateByteArrayConst( SB_CERT_OID_SHA384_RSAENCRYPTION_STR );
    SB_CERT_OID_SHA512_RSAENCRYPTION := CreateByteArrayConst( SB_CERT_OID_SHA512_RSAENCRYPTION_STR );

    SB_CERT_OID_ECDSA_SHA1           := CreateByteArrayConst( SB_CERT_OID_ECDSA_SHA1_STR );
    SB_CERT_OID_ECDSA_RECOMMENDED    := CreateByteArrayConst( SB_CERT_OID_ECDSA_RECOMMENDED_STR );
    SB_CERT_OID_ECDSA_SHA224         := CreateByteArrayConst( SB_CERT_OID_ECDSA_SHA224_STR );
    SB_CERT_OID_ECDSA_SHA256         := CreateByteArrayConst( SB_CERT_OID_ECDSA_SHA256_STR );
    SB_CERT_OID_ECDSA_SHA384         := CreateByteArrayConst( SB_CERT_OID_ECDSA_SHA384_STR );
    SB_CERT_OID_ECDSA_SHA512         := CreateByteArrayConst( SB_CERT_OID_ECDSA_SHA512_STR );
    SB_CERT_OID_ECDSA_SPECIFIED      := CreateByteArrayConst( SB_CERT_OID_ECDSA_SPECIFIED_STR );

    { Signature algorithms, defined in German BSI Technical Guideline TR-03111 }
    SB_CERT_OID_ECDSA_PLAIN_SHA1     := CreateByteArrayConst( SB_CERT_OID_ECDSA_PLAIN_SHA1_STR );
    SB_CERT_OID_ECDSA_PLAIN_SHA224   := CreateByteArrayConst( SB_CERT_OID_ECDSA_PLAIN_SHA224_STR );
    SB_CERT_OID_ECDSA_PLAIN_SHA256   := CreateByteArrayConst( SB_CERT_OID_ECDSA_PLAIN_SHA256_STR );
    SB_CERT_OID_ECDSA_PLAIN_SHA384   := CreateByteArrayConst( SB_CERT_OID_ECDSA_PLAIN_SHA384_STR );
    SB_CERT_OID_ECDSA_PLAIN_SHA512   := CreateByteArrayConst( SB_CERT_OID_ECDSA_PLAIN_SHA512_STR );
    SB_CERT_OID_ECDSA_PLAIN_RIPEMD160:= CreateByteArrayConst( SB_CERT_OID_ECDSA_PLAIN_RIPEMD160_STR );

    SB_CERT_OID_GOST_R3410_1994      := CreateByteArrayConst( SB_CERT_OID_GOST_R3410_1994_STR );
    SB_CERT_OID_GOST_R3410_2001      := CreateByteArrayConst( SB_CERT_OID_GOST_R3410_2001_STR );
    SB_CERT_OID_GOST_R3411_WITH_GOST3410_1994 := CreateByteArrayConst( SB_CERT_OID_GOST_R3411_WITH_GOST3410_1994_STR );
    SB_CERT_OID_GOST_R3411_WITH_GOST3410_2001 := CreateByteArrayConst( SB_CERT_OID_GOST_R3411_WITH_GOST3410_2001_STR );

    SB_CERT_OID_SHA1_RSA             := CreateByteArrayConst( SB_CERT_OID_SHA1_RSA_STR );
    SB_CERT_OID_SHA1_DSA             := CreateByteArrayConst( SB_CERT_OID_SHA1_DSA_STR );
    SB_CERT_OID_SHA1                 := CreateByteArrayConst( SB_CERT_OID_SHA1_STR );
    SB_CERT_OID_MD2                  := CreateByteArrayConst( SB_CERT_OID_MD2_STR );
    SB_CERT_OID_MD5                  := CreateByteArrayConst( SB_CERT_OID_MD5_STR );

    { RFC 5272 }

    SB_CMC_OID_PKI_DATA               := CreateByteArrayConst(SB_CMC_OID_PKI_DATA_STR );
    SB_CMC_OID_PKI_RESPONSE           := CreateByteArrayConst(SB_CMC_OID_PKI_RESPONSE_STR );

    SB_CMC_OID_STATUS_INFO            := CreateByteArrayConst(SB_CMC_OID_STATUS_INFO_STR );
    SB_CMC_OID_IDENTIFICATION         := CreateByteArrayConst(SB_CMC_OID_IDENTIFICATION_STR );
    SB_CMC_OID_IDENTITY_PROOF         := CreateByteArrayConst(SB_CMC_OID_IDENTITY_PROOF_STR );
    SB_CMC_OID_DATA_RETURN            := CreateByteArrayConst(SB_CMC_OID_DATA_RETURN_STR );
    SB_CMC_OID_TRANSACTION_ID         := CreateByteArrayConst(SB_CMC_OID_TRANSACTION_ID_STR );
    SB_CMC_OID_SENDER_NONCE           := CreateByteArrayConst(SB_CMC_OID_SENDER_NONCE_STR );
    SB_CMC_OID_RECIPIENT_NONCE        := CreateByteArrayConst(SB_CMC_OID_RECIPIENT_NONCE_STR );
    SB_CMC_OID_ADD_EXTENSIONS         := CreateByteArrayConst(SB_CMC_OID_ADD_EXTENSIONS_STR );
    SB_CMC_OID_ENCRYPTED_POP          := CreateByteArrayConst(SB_CMC_OID_ENCRYPTED_POP_STR );
    SB_CMC_OID_DECRYPTED_POP          := CreateByteArrayConst(SB_CMC_OID_DECRYPTED_POP_STR );
    SB_CMC_OID_LRA_POP_WITNESS        := CreateByteArrayConst(SB_CMC_OID_LRA_POP_WITNESS_STR );
    SB_CMC_OID_GET_CERT               := CreateByteArrayConst(SB_CMC_OID_GET_CERT_STR );
    SB_CMC_OID_GET_CRL                := CreateByteArrayConst(SB_CMC_OID_GET_CRL_STR );
    SB_CMC_OID_REVOKE_REQUEST         := CreateByteArrayConst(SB_CMC_OID_REVOKE_REQUEST_STR );
    SB_CMC_OID_REG_INFO               := CreateByteArrayConst(SB_CMC_OID_REG_INFO_STR );
    SB_CMC_OID_RESPONSE_INFO          := CreateByteArrayConst(SB_CMC_OID_RESPONSE_INFO_STR );
    SB_CMC_OID_QUERY_PENDING          := CreateByteArrayConst(SB_CMC_OID_QUERY_PENDING_STR );
    SB_CMC_OID_POP_LINK_RANDOM        := CreateByteArrayConst(SB_CMC_OID_POP_LINK_RANDOM_STR );
    SB_CMC_OID_POP_LINK_WITNESS       := CreateByteArrayConst(SB_CMC_OID_POP_LINK_WITNESS_STR );
    SB_CMC_OID_POP_LINK_WITNESS_V2    := CreateByteArrayConst(SB_CMC_OID_POP_LINK_WITNESS_V2_STR );
    SB_CMC_OID_CONFIRM_CERT_ACCEPTANCE:= CreateByteArrayConst(SB_CMC_OID_CONFIRM_CERT_ACCEPTANCE_STR );
    SB_CMC_OID_STATUS_INFO_V2         := CreateByteArrayConst(SB_CMC_OID_STATUS_INFO_V2_STR );
    SB_CMC_OID_TRUSTED_ANCHORS        := CreateByteArrayConst(SB_CMC_OID_TRUSTED_ANCHORS_STR );
    SB_CMC_OID_AUTH_DATA              := CreateByteArrayConst(SB_CMC_OID_AUTH_DATA_STR );
    SB_CMC_OID_BATCH_REQUESTS         := CreateByteArrayConst(SB_CMC_OID_BATCH_REQUESTS_STR );
    SB_CMC_OID_BATCH_RESPONSES        := CreateByteArrayConst(SB_CMC_OID_BATCH_RESPONSES_STR );
    SB_CMC_OID_PUBLISH_CERT           := CreateByteArrayConst(SB_CMC_OID_PUBLISH_CERT_STR );
    SB_CMC_OID_MOD_CERT_TEMPLATE      := CreateByteArrayConst(SB_CMC_OID_MOD_CERT_TEMPLATE_STR );
    SB_CMC_OID_CONTROL_PROCESSED      := CreateByteArrayConst(SB_CMC_OID_CONTROL_PROCESSED_STR );
    SB_CMC_OID_IDENTITY_PROOF_V2      := CreateByteArrayConst(SB_CMC_OID_IDENTITY_PROOF_V2_STR );
   {$endif SB_NO_BYTEARRAY_CONST_ARRAYS}
  end;
end.


