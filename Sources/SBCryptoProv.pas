(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBCryptoProv;

interface

uses
  Classes,
  SysUtils,
  SBRDN,
  SBASN1,
  SBMath,
  SBSharedResource,
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBConstants;


const
  // algorithm classes
  SB_ALGCLASS_NONE      = 0;
  SB_ALGCLASS_BLOCK     = 1;
  SB_ALGCLASS_STREAM    = 2;
  SB_ALGCLASS_PUBLICKEY = 3;
  SB_ALGCLASS_HASH      = 4;

  // encryption modes for symmetric crypto
  SB_SYMENC_MODE_DEFAULT        = 0;
  SB_SYMENC_MODE_BLOCK          = 1;
  SB_SYMENC_MODE_CBC            = 2;
  SB_SYMENC_MODE_CFB8           = 3;
  SB_SYMENC_MODE_CTR            = 4;
  SB_SYMENC_MODE_ECB            = 5;
  SB_SYMENC_MODE_CCM            = 6;
  SB_SYMENC_MODE_GCM            = 7;

  // symmetric crypto padding types
  SB_SYMENC_PADDING_NONE        = 0;
  SB_SYMENC_PADDING_PKCS5       = 1;

  // verification results
  SB_VR_SUCCESS                 = 0;
  SB_VR_INVALID_SIGNATURE       = 1;
  SB_VR_KEY_NOT_FOUND           = 2;
  SB_VR_FAILURE                 = 3;

  // operation types
  SB_OPTYPE_NONE                = 0;
  SB_OPTYPE_ENCRYPT             = 1;
  SB_OPTYPE_DECRYPT             = 2;
  SB_OPTYPE_SIGN                = 3;
  SB_OPTYPE_SIGN_DETACHED       = 4;
  SB_OPTYPE_VERIFY              = 5;
  SB_OPTYPE_VERIFY_DETACHED     = 6;
  SB_OPTYPE_HASH                = 7;
  SB_OPTYPE_KEY_GENERATE        = 8;
  SB_OPTYPE_KEY_DECRYPT         = 9;
  SB_OPTYPE_RANDOM              = 10;
  SB_OPTYPE_KEY_CREATE          = 11;
  SB_OPTYPE_KEYSTORAGE_CREATE   = 12;

  ERROR_FACILITY_CRYPTOPROV = $15000;
  ERROR_CRYPTOPROV_ERROR_FLAG = $00800;

  ERROR_CP_NOT_INITIALIZED  = Integer(ERROR_FACILITY_CRYPTOPROV + ERROR_CRYPTOPROV_ERROR_FLAG + 1);
  ERROR_CP_FEATURE_NOT_SUPPORTED = Integer(ERROR_FACILITY_CRYPTOPROV + ERROR_CRYPTOPROV_ERROR_FLAG + 2);
  ERROR_CP_INVALID_KEY_SIZE = Integer(ERROR_FACILITY_CRYPTOPROV + ERROR_CRYPTOPROV_ERROR_FLAG + 5);
  ERROR_CP_INVALID_IV_SIZE  = Integer(ERROR_FACILITY_CRYPTOPROV + ERROR_CRYPTOPROV_ERROR_FLAG + 6);
  ERROR_CP_BUFFER_TOO_SMALL = Integer(ERROR_FACILITY_CRYPTOPROV + ERROR_CRYPTOPROV_ERROR_FLAG + 7);

  SB_CRYPTOPROV_GENERAL_ERROR = 1;


// parameter constants
{$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
 {$else}
var
 {$endif}
  //////////////////////////////////////////////
  // Provider and common properties

  {$ifndef SB_NO_PKCS11}
  {$ifndef SB_STATIC_PKCS11}
  // PKCS11 DLL path
  // Possible values:
  // (PKCS11 crypto provider) path to the DLL providing PKCS#11 interface
  SB_PROVPROP_DLL_PATH : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'dll-path@eldos.com'  {$endif}; 
   {$else}
  SB_PROVPROP_FUNC_MNG : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'functions-manager@eldos.com'  {$endif}; 
   {$endif}
  
  // PKCS11 session handle
  // Possible values:
  // (PKCS11 crypto provider) session handle (UINT32)
  SB_PROVPROP_SESSION_HANDLE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'session-handle@eldos.com'  {$endif}; 

   {$endif}

  {$ifdef SB_HAS_CRYPTUI}
  // Win32 CSP parent window handle
  SB_PROVPROP_WINDOW_HANDLE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'window-handle@eldos.com'  {$endif}; 
   {$endif}

  //////////////////////////////////////////////
  // Key properties
  

  // Key format
  // Possible values:
  // (RSA keys) 'pkcs#1', 'oaep', 'pss'
  SB_KEYPROP_KEYFORMAT : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'key-format@eldos.com'  {$endif}; 

  // Hash algorithm
  // Possible values:
  // (RSA-PSS, RSA-OAEP, DSA keys) the OID of the hash algorithm (ASN.1-encoded notation, e.g. 2a 86 48 86 ...)
  SB_KEYPROP_HASH_ALGORITHM : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'hash-algorithm@eldos.com'  {$endif}; 

  // Mask generation function algorithm
  // Possible values:
  // (RSA-PSS) the OID of the mask generation function algorithm (ASN.1-encoded notation, e.g. 2a 86 48 86 ...)
  SB_KEYPROP_MGF_ALGORITHM : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'mgf-algorithm@eldos.com'  {$endif}; 

  // Trailer field
  // Possible values:
  // (RSA-PSS keys) the big-endian encoding of the integer value (4 bytes)
  SB_KEYPROP_TRAILER_FIELD : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'trailer-field@eldos.com'  {$endif}; 

  // Salt size
  // Possible values:
  // (RSA-PSS keys) the big-endian encoding of the integer value (4 bytes)
  SB_KEYPROP_SALT_SIZE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'salt-size@eldos.com'  {$endif}; 

  // String label
  // Possible values:
  // (RSA-OAEP keys) StrLabel value
  SB_KEYPROP_STRLABEL : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'strlabel@eldos.com'  {$endif}; 

  // RSA modulus
  // Possible values:
  // (RSA keys) big-endian public modulus value
  SB_KEYPROP_RSA_M : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'rsa-m@eldos.com'  {$endif}; 

  // RSA public exponent
  // Possible values:
  // (RSA keys) big-endian public exponent value
  SB_KEYPROP_RSA_E : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'rsa-e@eldos.com'  {$endif}; 

  // RSA private exponent
  // Possible values:
  // (RSA keys) big-endian private exponent value
  SB_KEYPROP_RSA_D : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'rsa-d@eldos.com'  {$endif}; 

  // DSA strict validation flag
  // Possible values:
  // (DSA keys) one-byte boolean value (0x01/0x00)
  SB_KEYPROP_DSA_STRICT_VALIDATION : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'dsa-strict@eldos.com'  {$endif}; 

  // RSA raw key material flag
  // Possible values:
  // (RSA keys) one-byte boolean value (0x01/0x00)
  SB_KEYPROP_RSA_RAWKEY : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'rsa-raw-key@eldos.com'  {$endif}; 

  // DSA prime
  // Possible values:
  // (DSA keys) big-endian prime value
  SB_KEYPROP_DSA_P : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'dsa-p@eldos.com'  {$endif}; 

  // DSA q value
  // Possible values:
  // (DSA keys) big-endian q value
  SB_KEYPROP_DSA_Q : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'dsa-q@eldos.com'  {$endif}; 

  // DSA generator
  // Possible values:
  // (DSA keys) big-endian generator value
  SB_KEYPROP_DSA_G : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'dsa-g@eldos.com'  {$endif}; 

  // DSA secret value
  // Possible values:
  // (DSA keys) big-endian secret value
  SB_KEYPROP_DSA_X : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'dsa-x@eldos.com'  {$endif}; 

  // DSA public value
  // Possible values:
  // (DSA keys) big-endian public value
  SB_KEYPROP_DSA_Y : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'dsa-y@eldos.com'  {$endif}; 

  // DSA q size (in bits)
  // Possible values:
  // (DSA keys) big-endian encoding of integer value (4 bytes)
  SB_KEYPROP_DSA_QBITS : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'dsa-qbits@eldos.com'  {$endif}; 

  // Elgamal prime
  // Possible values:
  // (Elgamal keys) big-endian prime value
  SB_KEYPROP_ELGAMAL_P : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'elg-p@eldos.com'  {$endif}; 

  // Elgamal generator
  // Possible values:
  // (Elgamal keys) big-endian generator value
  SB_KEYPROP_ELGAMAL_G : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'elg-g@eldos.com'  {$endif}; 

  // Elgamal secret value
  // Possible values:
  // (Elgamal keys) big-endian secret value
  SB_KEYPROP_ELGAMAL_X : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'elg-x@eldos.com'  {$endif}; 

  // Elgamal public value
  // Possible values:
  // (Elgamal keys) big-endian public value
  SB_KEYPROP_ELGAMAL_Y : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'elg-y@eldos.com'  {$endif}; 

  // DH prime
  // Possible values:
  // (DH keys) big-endian prime value
  SB_KEYPROP_DH_P : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'dh-p@eldos.com'  {$endif}; 

  // DH generator
  // Possible values:
  // (DH keys) big-endian generator value
  SB_KEYPROP_DH_G : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'dh-g@eldos.com'  {$endif}; 

  // DH secret value
  // Possible values:
  // (DH keys) big-endian secret value
  SB_KEYPROP_DH_X : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'dh-x@eldos.com'  {$endif}; 

  // DH public value
  // Possible values:
  // (DH keys) big-endian public value
  SB_KEYPROP_DH_Y : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'dh-y@eldos.com'  {$endif}; 

  // DH public value of peer
  // Possible values:
  // (DH keys) big-endian peer's public value
  SB_KEYPROP_DH_PEER_Y : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'dh-peer-y@eldos.com'  {$endif}; 

  // Win32 CryptoAPI certificate context
  // Possible values:
  // (Win32 keys) big-endian 64 bit certificate handle value (PCCERT_CONTEXT/IntPtr)
  SB_KEYPROP_WIN32_CERTCONTEXT : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'win32-certcontext@eldos.com'  {$endif}; 

  // Win32 CryptoAPI container name
  // Possible values:
  // (Win32 keys) [usually UUID-like] string 
  SB_KEYPROP_WIN32_CONTAINERNAME : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'win32-containername@eldos.com'  {$endif}; 

  // Win32 CryptoAPI provider name
  // Possible values:
  // (Win32 keys) string (e.g. 'Microsoft Enhanced Cryptographic Provider v1.0')
  SB_KEYPROP_WIN32_PROVIDERNAME : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'win32-provname@eldos.com'  {$endif}; 

  // Existing Win32 provider info (used to identify keys not bound to certificates) 
  // Possible values:
  // (Win32 keys) [usually UUID-like] string 
  SB_KEYPROP_WIN32_KEYPROVINFO : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'win32-keyprovinfo@eldos.com'  {$endif}; 

  // Win32 provider key exchange PIN
  // Possible values:
  // (Win32 keys) A string of ASCII characters (as required by MSDN for PP_KEYEXCHANGE_PIN provider parameter)
  SB_KEYPROP_WIN32_KEYEXCHANGEPIN : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'win32-keyexchangepin@eldos.com'  {$endif}; 

  // Win32 provider signature PIN
  // Possible values:
  // (Win32 keys) A string of ASCII characters (as required by MSDN for PP_SIGNATURE_PIN provider parameter)
  SB_KEYPROP_WIN32_SIGNATUREPIN : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'win32-signaturepin@eldos.com'  {$endif}; 

  // Effective key length
  // Possible values:
  // (RC2 keys) effective length of the key in bits
  SB_KEYPROP_EFFECTIVE_KEY_LENGTH : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'effective-key-length@eldos.com'  {$endif}; 

  // PKCS11 private key handle
  // Possible values:
  // (PKCS11 keys) big-endian encoding of integer value (4 bytes)
  SB_KEYPROP_PKCS11_KEY_HANDLE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'p11-key-handle@eldos.com'  {$endif}; 

  // PKCS11 session handle
  // Possible values:
  // (PKCS11 keys) big-endian encoding of integer value (4 bytes)
  SB_KEYPROP_PKCS11_SESSION_HANDLE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'p11-session-handle@eldos.com'  {$endif}; 

  // PKCS11 public key handle
  // Possible values:
  // (PKCS11 keys) big-endian encoding of integer value (4 bytes)
  SB_KEYPROP_PKCS11_PUBKEY_HANDLE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'p11-pubkey-handle@eldos.com'  {$endif}; 

  // PKCS11 persistence modifier
  // Possible values:
  // (PKCS11 keys) boolean value indicating whether the key is persistent (stored on the token)
  SB_KEYPROP_PKCS11_PERSISTENT : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'p11-persistent@eldos.com'  {$endif}; 

  // PKCS11 key label
  // Possible value:
  // (PKCS11 keys) textual label of the key
  SB_KEYPROP_PKCS11_LABEL : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'p11-label@eldos.com'  {$endif}; 
  
  // PKCS11 subject
  // Possible value:
  // (PKCS11 keys) textual subject of the key
  SB_KEYPROP_PKCS11_SUBJECT : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'p11-subject@eldos.com'  {$endif}; 

  // PKCS11 id
  // Possible value:
  // (PKCS11 keys) id of the key
  SB_KEYPROP_PKCS11_ID : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'p11-id@eldos.com'  {$endif}; 

  // PKCS11 sensitivity modifier
  // Possible value:
  // (PKCS11 keys) boolean value indicating whether the key is sensitive (non-exportable)
  SB_KEYPROP_PKCS11_SENSITIVE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'p11-sensitive@eldos.com'  {$endif}; 

  // PKCS11 privacy modifier
  // Possible value:
  // (PKCS11 keys) boolean value indicating whether the key is private
  SB_KEYPROP_PKCS11_PRIVATE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'p11-private@eldos.com'  {$endif}; 

  // PKCS11 "create public" flag
  // Possible value:
  // (PKCS11 keys) boolean value indicating whether the corresponding public key object should be created from the imported secret key
  SB_KEYPROP_PKCS11_CREATE_PUBLIC : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'p11-create-public@eldos.com'  {$endif}; 

  // PKCS11 "add private flag"
  // Possible value:
  // (PKCS11 keys) boolean value indicating whether a "private" attribute should be included in a call to CreateObject when adding private key to the token
  SB_KEYPROP_PKCS11_ADD_PRIVATE_FLAG : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'p11-add-private-flag@eldos.com'  {$endif}; 

  // PKCS11 "force object creation"
  // Possible value:
  // (PKCS11 keys) boolean value indicating that the object must be created on a token (be it persistent or not)
  SB_KEYPROP_PKCS11_FORCE_OBJECT_CREATION : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'p11-force-object-creation@eldos.com'  {$endif}; 

  /////////////////////////////////
  // Elliptic Curve key properties
  //

  // Elliptic curve
  // Possible values:
  // Curve OID
  SB_KEYPROP_EC_CURVE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-curve@eldos.com'  {$endif}; 

  // Elliptic curve
  // Possible values:
  // Curve integer constant
  SB_KEYPROP_EC_CURVE_INT : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-curve-int@eldos.com'  {$endif}; 

  // Underlying field type
  // Possible values:
  // Field type OID
  SB_KEYPROP_EC_FIELD_TYPE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-field-type@eldos.com'  {$endif}; 

  // Underlying field type
  // Possible values:
  // Field type integer constant
  SB_KEYPROP_EC_FIELD_TYPE_INT : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-field-type-int@eldos.com'  {$endif}; 

  // Underlying field bit size
  // Possible values:
  // Field size integer constant
  SB_KEYPROP_EC_FIELD_BITS : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-field-bits@eldos.com'  {$endif}; 

  // Elliptic curve subgroup order bit size
  // Possible values:
  // Subgroup order bit size integer constant
  SB_KEYPROP_EC_SUBGROUP_BITS : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-subgroup-bits@eldos.com'  {$endif}; 

  // Predefined underlying field
  // Possible values:
  // Field OID
  SB_KEYPROP_EC_FIELD : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-field@eldos.com'  {$endif}; 

  // Predefined underlying field
  // Possible values:
  // Field integer constant
  SB_KEYPROP_EC_FIELD_INT : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-field-int@eldos.com'  {$endif}; 

  // Elliptic curve underlying field order (for Fp) or irreducible polynom.
  // Possible values:
  // (EC keys) big-endian P parameter value
  SB_KEYPROP_EC_P : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-p@eldos.com'  {$endif}; 

  // Elliptic curve underlying field F2m irreducible polynom order.
  // Possible values:
  // (EC keys) integer - irreducible polynom order
  SB_KEYPROP_EC_M : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-m@eldos.com'  {$endif}; 

  // Elliptic curve underlying field F2m irreducible polynom K1 (for trinoms & pentanoms).
  // Possible values:
  // (EC keys) integer - K1 value
  SB_KEYPROP_EC_K1 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-k1@eldos.com'  {$endif}; 

  // Elliptic curve underlying field F2m irreducible polynom K2 (for pentanoms).
  // Possible values:
  // (EC keys) integer - K2 value
  SB_KEYPROP_EC_K2 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-k2@eldos.com'  {$endif}; 

  // Elliptic curve underlying field F2m irreducible polynom K3 (for pentanoms).
  // Possible values:
  // (EC keys) integer - K3 value
  SB_KEYPROP_EC_K3 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-k3@eldos.com'  {$endif}; 

  // Elliptic curve A domain parameter
  // Possible values:
  // (EC keys) big-endian A parameter value
  SB_KEYPROP_EC_A : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-a@eldos.com'  {$endif}; 

  // Elliptic curve B domain parameter
  // Possible values:
  // (EC keys) big-endian B parameter value
  SB_KEYPROP_EC_B : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-b@eldos.com'  {$endif}; 

  // Elliptic curve order
  // Possible values:
  // (EC keys) big-endian elliptic curve order
  SB_KEYPROP_EC_N : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-n@eldos.com'  {$endif}; 

  // Elliptic curve order cofactor
  // Possible values:
  // (EC keys) integer cofactor
  SB_KEYPROP_EC_H : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-h@eldos.com'  {$endif}; 

  // Seed of random generated curve
  // Possible values:
  // (EC keys) array seed
  SB_KEYPROP_EC_SEED : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-seed@eldos.com'  {$endif}; 

  // Elliptic curve base point X coordinate
  // Possible values:
  // (EC keys) big-endian elliptic curve base point X coordinate
  SB_KEYPROP_EC_X : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-x@eldos.com'  {$endif}; 

  // Elliptic curve base point Y coordinate
  // Possible values:
  // (EC keys) big-endian elliptic curve base point Y coordinate
  SB_KEYPROP_EC_Y : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-y@eldos.com'  {$endif}; 

  // Elliptic curve base point coordinates, converted to octet string according to X9.62 pt. 4.3.6.
  // Possible values:
  // (EC keys) big-endian octet string, representing base point
  SB_KEYPROP_EC_BP : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-bp@eldos.com'  {$endif}; 

  // Elliptic curve secret key value (D)
  // Possible values:
  // (EC keys) big-endian secret key value D
  SB_KEYPROP_EC_D : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-d@eldos.com'  {$endif}; 

  // Elliptic curve public key value X coordinate
  // Possible values:
  // (EC keys) big-endian elliptic curve public key value X coordinate
  SB_KEYPROP_EC_QX : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-qx@eldos.com'  {$endif}; 

  // Elliptic curve public key value Y coordinate
  // Possible values:
  // (EC keys) big-endian elliptic curve public key value Y coordinate
  SB_KEYPROP_EC_QY : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-qy@eldos.com'  {$endif}; 

  // Elliptic curve public key coordinates, converted to octet string according to X9.62 pt. 4.3.6.
  // Possible values:
  // (EC keys) big-endian octet string, representing public key value
  SB_KEYPROP_EC_Q : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-q@eldos.com'  {$endif}; 

  // Point compression usage
  SB_KEYPROP_EC_COMPRESS_POINTS : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-compress@eldos.com'  {$endif}; 

  // Hybrid form of compressed points usage
  SB_KEYPROP_EC_HYBRID_POINTS : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ec-hybrid@eldos.com'  {$endif}; 

  /////////////////////////////////
  //  GOST 34.10 key properties
  //
  //  t - bit length of p (512 or 1024 bits);
  SB_KEYPROP_GOST_R3410_1994_T       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'gost-R3410-1994_t@eldos.com'  {$endif}; 
  //  p - modulus, prime number, 2^(t-1)<p<2^t;
  SB_KEYPROP_GOST_R3410_1994_P       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'gost-R3410-1994_p@eldos.com'  {$endif}; 
  //  q - order of cyclic group, prime number, 2^254<q<2^256, q is a factor of p-1;
  SB_KEYPROP_GOST_R3410_1994_Q       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'gost-R3410-1994_q@eldos.com'  {$endif}; 
  //  a - generator, integer, 1<a<p-1, at that aq (mod p) = 1;
  SB_KEYPROP_GOST_R3410_1994_A       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'gost-R3410-1994_a@eldos.com'  {$endif}; 
  //  x0 - seed;
  SB_KEYPROP_GOST_R3410_1994_X0      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'gost-R3410-1994_x0@eldos.com'  {$endif}; 
  //  c  - used for p and q generation;
  SB_KEYPROP_GOST_R3410_1994_C       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'gost-R3410-1994_c@eldos.com'  {$endif}; 
  //  d  - used for a generation.
  SB_KEYPROP_GOST_R3410_1994_D       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'gost-R3410-1994_d@eldos.com'  {$endif}; 
  //  x  - big-endian secret value
  SB_KEYPROP_GOST_R3410_1994_X       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'gost-R3410-1994_x@eldos.com'  {$endif}; 
  //  y  - big-endian public value
  SB_KEYPROP_GOST_R3410_1994_Y       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'gost-R3410-1994_y@eldos.com'  {$endif}; 
  //  parameter set
  SB_KEYPROP_GOST_R3410_PARAMSET: TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'gost-R3410_paramset@eldos.com'  {$endif}; 
  //  digest parameter set
  SB_KEYPROP_GOST_R3410_DIGEST_PARAMSET: TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'gost-R3410_digest_paramset@eldos.com'  {$endif}; 
  //  encryption parameter set
  SB_KEYPROP_GOST_R3410_ENCRYPTION_PARAMSET: TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'gost-R3410_encryption_paramset@eldos.com'  {$endif}; 

  // Key envelope (data associated with a key)
  // Possible value:
  // X.509 certificate in DER format, OpenPGP keyring etc.
  SB_KEYPROP_ENVELOPE_VALUE          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'envelope-value@eldos.com'  {$endif}; 

  // SecureBlackbox Key ID blob
  // Possible value:
  // Serialized key id in TElCPKeyID format
  SB_KEYPROP_SBB_KEYID_BLOB          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'sbb-keyid@eldos.com'  {$endif}; 

  //////////////////////////////////////////////
  // Algorithm properties

  // Digest size in bits
  // Possible values:
  // (Hash algorithms) big-endian digest size
  SB_ALGPROP_DIGEST_SIZE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'digest-size@eldos.com'  {$endif}; 

  // Symmetric cipher block size, bytes
  // Possible values:
  // (Symmetric algorithms) big-endian block size
  SB_ALGPROP_BLOCK_SIZE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'block-size@eldos.com'  {$endif}; 

  // Symmetric cipher default key size, bytes
  // Possible values:
  // (Symmetric algorithms) big-endian key size
  SB_ALGPROP_DEFAULT_KEY_SIZE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'default-key-size@eldos.com'  {$endif}; 

  //////////////////////////////////////////////
  // Crypto context properties

  // RC4 security hole workaround (used in SSH)
  // Possible values:
  // (RC4) big-endian offset value (SSH uses 1536)
  SB_CTXPROP_SKIP_KEYSTREAM_BYTES : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'skip-keystream-bytes@eldos.com'  {$endif}; 

  // Enabling/disabling hash algorithm prefix for RSA keys
  // Possible values:
  // (RSA) boolean value 
  SB_CTXPROP_USE_ALGORITHM_PREFIX : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'use-algorithm-prefix@eldos.com'  {$endif}; 

  // Hash algorithm for public key algorithm
  // Possible values:
  // (RSA) Hash algorithm oid (ASN.1-formatted object identifier)
  SB_CTXPROP_HASH_ALGORITHM : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'hash-algorithm@eldos.com'  {$endif}; 

  // Specifies if input data is already a calculated hash value
  // Possible values:
  // (PKI) boolean value
  SB_CTXPROP_INPUT_IS_HASH : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'input-is-hash@eldos.com'  {$endif}; 

  // Specifies the object identifier for a hash function (to be prepended to the hash to be encrypted)
  // Possible values:
  // (RSA) ASN.1-formatted object identifier
  SB_CTXPROP_HASH_FUNC_OID : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'hash-func-oid@eldos.com'  {$endif}; 

  // Specifies algorithm scheme (~algorithm modifier) to be used for encryption/signing
  // Possible values:
  // (RSA schemes) 'pkcs#1', 'oaep', 'pss'
  SB_CTXPROP_ALGORITHM_SCHEME : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'alg-scheme@eldos.com'  {$endif}; 

  // Specifies salt size for particular crypto operations
  // Possible values:
  // (RSA-PSS scheme): see PKCS#1 2.0 specification
  SB_CTXPROP_SALT_SIZE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'salt-size@eldos.com'  {$endif}; 

  // Specifies label for particular crypto operations
  // Possible values:
  // (RSA-OAEP scheme): see PKCS#1 2.0 specification
  SB_CTXPROP_STR_LABEL : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'str-label@eldos.com'  {$endif}; 

  // Specifies trailer field for RSA-PSS scheme.
  // Possible values:
  //  see PKCS#1 2.0 specification
  SB_CTXPROP_TRAILER_FIELD : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'trailer-field@eldos.com'  {$endif}; 

  // Specifies mask generation function for RSA-PSS scheme.
  // Possible values:
  //  see PKCS#1 2.0 specification
  SB_CTXPROP_MGF_ALGORITHM : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'mgf-algorithm@eldos.com'  {$endif}; 

  // Specifies padding type for block encryption algorithms.
  // Possible values:
  // 'pkcs#5', ''
  SB_CTXPROP_PADDING_TYPE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'padding-type@eldos.com'  {$endif}; 

  // Specifies GOST R34.11-1994 hash function parameters set OID
  // Possible value:
  // SB_OID_GOST_R3411_1994_PARAM_CP, SB_OID_GOST_R3411_1994_PARAM_TEST (the last one only for testing purposes!)
  SB_CTXPROP_GOSTR3411_1994_PARAMSET : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'gost-R3411-1994-paramset@eldos.com'  {$endif}; 

  // Specifies GOST R34.11-1994 hash function parameters
  // Possible value:
  // 128-byte array, representing underlying S-Boxes filling
  SB_CTXPROP_GOSTR3411_1994_PARAMETERS : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'gost-R3411-1994-parameters@eldos.com'  {$endif}; 

  // Specifies GOST 28147-1989 parameters set OID
  // Possible values:
  // SB_OID_GOST_28147_1989_PARAM_CP_*
  SB_CTXPROP_GOST28147_1989_PARAMSET : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'gost-28147-1989-paramset@eldos.com'  {$endif}; 

  // Specifies GOST 28147-1989 S-boxes
  // Possible value:
  // 128-byte array, representing S-Boxes filling
  SB_CTXPROP_GOST28147_1989_PARAMETERS : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'gost-28147-1989-parameters@eldos.com'  {$endif}; 

  // Specifies GOST 28147-1989 CryptoPro Key Meshing algorithm usage (RFC 4357).
  // Possible value:
  // boolean, enable or disable CryptoProp key meshing. Applicable only for CFB mode now (used in CMS)
  SB_CTXPROP_GOST28147_1989_USE_KEY_MESHING : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'gost-28147-use-key-meshing@eldos.com'  {$endif}; 

  // Specifies GOST R 34.10-2001 UKM for key wrapping and derivation 
  // Possible value:
  // 8-byte array, UKM
  SB_CTXPROP_GOST3410_UKM : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'gost-3410-ukm@eldos.com'  {$endif}; 

  // Specifies GOST R 34.10-2001 ephemeral key for CEK derivation 
  // Possible value:
  // 32-byte array, GOST R 34.10-2001 public key (EC point)
  SB_CTXPROP_GOST3410_EPHEMERAL_KEY : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'gost-3410-ephemeral-key@eldos.com'  {$endif}; 

  // Specifies GOST R 34.10-2001 CEK MAC for CryptoPro key unwrap procedure 
  // Possible value:
  // 4-byte array, CEK MAC
  SB_CTXPROP_GOST3410_CEK_MAC : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'gost-3410-cek-mac@eldos.com'  {$endif}; 

  // AEAD encryption Nonce
  // Possible value:
  // 7-13 byte buffer
  SB_CTXPROP_AEAD_NONCE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'aead-nonce@eldos.com'  {$endif}; 

  // AEAD encryption authentication tag size
  // Possible value:
  // int 4-16
  SB_CTXPROP_AEAD_TAG_SIZE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'aead-tag-size@eldos.com'  {$endif}; 

  // AEAD associated data flag
  // Possible value:
  // true: input to encrypt/decrypt function is associated data (authenticated , but not encrypted)
  // false : input to encrypt/decrypt function is payload (authenticated and encrypted)
  SB_CTXPROP_AEAD_ASSOCIATED_DATA : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'aead-associated-data@eldos.com'  {$endif}; 

  // AEAD/CCM encryption associated data size
  // Possible value:
  // 32-bit integer
  SB_CTXPROP_CCM_ASSOCIATED_DATA_SIZE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ccm-a-size@eldos.com'  {$endif}; 

  // AEAD/CCM encryption payload size
  // Possible value:
  // 32-bit integer
  SB_CTXPROP_CCM_PAYLOAD_SIZE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ccm-payload-size@eldos.com'  {$endif}; 

  // CTR mode IV little-endian incrementing order (used in WinZip AES crypto)
  // Possible values:
  // false - normal, big-endian mode
  // true - WinZip little-endian mode
  SB_CTXPROP_CTR_LITTLE_ENDIAN : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ctr-little-endian@eldos.com'  {$endif}; 

  // Plain ECDSA signature encoding (for German signatures)
  SB_CTXPROP_EC_PLAIN_ECDSA : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  'ecdsa-plain@eldos.com'  {$endif}; 

type

  TElCPKeyHandle = pointer;
  TElCPParameters = TElRelativeDistinguishedName;

  TElCustomCryptoProvider = class;
  TElCustomCryptoProviderManager = class;
  TElCustomCryptoKeyStorage = class;

  // TODO: implement correct work of progress funcs

  TElCustomCryptoKey = class(TSBDisposableBase)
  protected
    FOwnerUniqueID : ByteArray;
  protected
    FCryptoProvider : TElCustomCryptoProvider;
    procedure InternalImportPublic(Buffer : pointer; Size : integer;
      var Algorithm : integer; var Key : ByteArray; var IV : ByteArray);
    procedure InternalExportPublic(Algorithm : integer; const Key, IV : ByteArray;
      Buffer : pointer; var Size : integer);
    function GetIsPublic: boolean; virtual; abstract;
    function GetIsSecret: boolean; virtual; abstract;
    function GetIsExportable: boolean; virtual; abstract;
    function GetIsPersistent: boolean; virtual; abstract;
    function GetIsValid: boolean; virtual; abstract;
    function GetBits : integer; virtual; abstract;
    function GetAlgorithm : integer; virtual; abstract;
    function GetKeyStorage : TElCustomCryptoKeyStorage; virtual; abstract;
    function GetMode : integer; virtual; abstract;
    procedure SetMode(Value : integer); virtual; abstract;
    function GetIV : ByteArray; virtual; abstract;
    procedure SetIV(const Value : ByteArray); virtual; abstract;
    function GetValue : ByteArray; virtual; abstract;
    procedure SetValue(const Value : ByteArray); virtual; abstract;
  public
    constructor Create(CryptoProvider : TElCustomCryptoProvider); virtual; 
    procedure Reset; virtual; abstract;
    // Possible parameters:
    // (DSA keys) SB_KEYPROP_DSA_QBITS: bits in dsa q value
    {$ifndef SB_PGPSFX_STUB}
    procedure Generate(Bits : integer;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil); virtual; abstract;
     {$endif SB_PGPSFX_STUB}
    procedure ImportPublic(Buffer: pointer; Size: integer; Params : TElCPParameters = nil); virtual; abstract;
    procedure ImportSecret(Buffer: pointer; Size: integer; Params : TElCPParameters = nil); virtual; abstract;
    procedure ExportPublic(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil); virtual; abstract;
    procedure ExportSecret(Buffer: pointer; var Size: integer; Params : TElCPParameters = nil); virtual; abstract;
    function Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoKey; virtual; abstract;
    function ClonePublic(Params : TElCPParameters  =  nil) : TElCustomCryptoKey; virtual; abstract;
    procedure ClearPublic; virtual; abstract;
    procedure ClearSecret; virtual; abstract;
    {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS}
    function GetKeyProp(const PropID : ByteArray; const Default : ByteArray  =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif} ): ByteArray; virtual; abstract;
     {$else}
    function GetKeyProp(const PropID : ByteArray): ByteArray;  overload; 
    function GetKeyProp(const PropID : ByteArray; const Default : ByteArray): ByteArray;  overload;  virtual; abstract;
     {$endif}
    procedure SetKeyProp(const PropID : ByteArray; const Value : ByteArray); virtual; abstract;
    procedure ChangeAlgorithm(Algorithm : integer); virtual; abstract;
    {$ifndef SB_PGPSFX_STUB}
    procedure PrepareForEncryption(MultiUse: boolean  =  false); virtual; abstract;
    procedure PrepareForSigning(MultiUse: boolean  =  false); virtual; abstract;
    procedure CancelPreparation; virtual; abstract;
    function AsyncOperationFinished : boolean; virtual; abstract;
     {$endif SB_PGPSFX_STUB}
    function Equals(Key: TElCustomCryptoKey; PublicOnly : boolean;
      Params : TElCPParameters  =  nil): boolean; {$ifdef D_12_UP}reintroduce; overload; {$endif} virtual;
    {$ifdef D_12_UP}
    function Equals(Obj: TObject): Boolean; overload; override;
     {$endif}
    procedure Persistentiate; virtual; abstract;
    property IsPublic : boolean read GetIsPublic;
    property IsSecret : boolean read GetIsSecret;
    property IsExportable : boolean read GetIsExportable;
    property IsPersistent : boolean read GetIsPersistent;
    property IsValid : boolean read GetIsValid;
    property Bits : integer read GetBits;
    property Algorithm : integer read GetAlgorithm;
    property Value : ByteArray read GetValue write SetValue;
    property IV : ByteArray read GetIV write SetIV;
    property Mode : integer read GetMode write SetMode;
    property CryptoProvider : TElCustomCryptoProvider read FCryptoProvider;
    property KeyStorage : TElCustomCryptoKeyStorage read GetKeyStorage;
  end;

  TElCustomCryptoKeyStorage = class(TSBDisposableBase)
  protected
    FCryptoProvider : TElCustomCryptoProvider;
    function GetIsPersistent: boolean; virtual; abstract;
    function GetKey(Index: integer): TElCustomCryptoKey; virtual; abstract;
    function GetCount : integer; virtual; abstract;
  public
    function AddKey(Key : TElCustomCryptoKey; Params : TElCPParameters  =  nil): integer; virtual; abstract;
    procedure RemoveKey(Index: integer; Params : TElCPParameters  =  nil);  overload;  virtual; abstract;
    procedure RemoveKey(Key : TElCustomCryptoKey; Params : TElCPParameters  =  nil);  overload;  virtual; abstract;
    procedure Clear; virtual; abstract;
    function Clone(Params : TElCPParameters  =  nil): TElCustomCryptoKeyStorage; virtual; abstract;
    procedure Lock; virtual; abstract;
    procedure Unlock; virtual; abstract;
    {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS}
    function GetStorageProp(const PropID : ByteArray; const Default : ByteArray  =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif} ): ByteArray; virtual; abstract;
     {$else}
    function GetStorageProp(const PropID : ByteArray): ByteArray;  overload; 
    function GetStorageProp(const PropID : ByteArray; const Default : ByteArray): ByteArray;  overload;  virtual; abstract;
     {$endif}
    procedure SetStorageProp(const PropID : ByteArray; const Value : ByteArray); virtual; abstract;
    property Keys[Index: integer]: TElCustomCryptoKey read GetKey;
    property Count : integer read GetCount;
    property IsPersistent : boolean read GetIsPersistent;
    property CryptoProvider : TElCustomCryptoProvider read FCryptoProvider;
  end;

  TElCustomCryptoContext = class(TSBDisposableBase)
  protected
    // TODO: set the FProvider in the constructor
    FProvider : TElCustomCryptoProvider;
    function GetAlgorithm : integer; virtual; abstract;
    function GetAlgorithmClass : integer; virtual; abstract;
    function GetKeySize : integer; virtual; abstract;
    procedure SetKeySize(Value: integer); virtual; abstract;
    function GetBlockSize : integer; virtual; abstract;
    procedure SetBlockSize(Value: integer); virtual; abstract;
    function GetDigestSize : integer; virtual; abstract;
    procedure SetDigestSize(Value : integer); virtual; abstract;
    function GetMode : integer; virtual; abstract;
    procedure SetMode(Value : integer); virtual; abstract;
    function GetPadding : integer; virtual; abstract;
    procedure SetPadding(Value : integer); virtual; abstract;
  public
    {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS}
    function GetContextProp(const PropID : ByteArray; const Default : ByteArray  =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif} ): ByteArray; virtual; abstract;
     {$else}
    function GetContextProp(const PropID : ByteArray): ByteArray;  overload; 
    function GetContextProp(const PropID : ByteArray; const Default : ByteArray): ByteArray;  overload;  virtual; abstract;
     {$endif}
    procedure SetContextProp(const PropID : ByteArray; const Value : ByteArray); virtual; abstract;
    function Clone(Params : TElCPParameters  =  nil) : TElCustomCryptoContext; virtual; abstract;
    function EstimateOutputSize(InSize: Int64): Int64; virtual; abstract;
    property Algorithm : integer read GetAlgorithm;
    property CryptoProvider : TElCustomCryptoProvider read FProvider;
    property KeySize : integer read GetKeySize write SetKeySize;
    property BlockSize : integer read GetBlockSize write SetBlockSize;
    property DigestSize : integer read GetDigestSize write SetDigestSize;
    property Mode : integer read GetMode write SetMode;
    property Padding : integer read GetPadding write SetPadding;
    property AlgorithmClass : integer read GetAlgorithmClass;
  end;

  TElCustomCryptoProviderOptions = class
  protected
    FMaxPublicKeySize : integer;
    FStoreKeys : boolean;
    procedure Init; virtual;
  public
    constructor Create;
    procedure Assign(Options: TElCustomCryptoProviderOptions); virtual;
    property MaxPublicKeySize : integer read FMaxPublicKeySize write FMaxPublicKeySize;
    property StoreKeys : boolean read FStoreKeys write FStoreKeys;
  end;

  TSBCryptoProviderObjectEvent = procedure(Sender: TObject; Obj : TObject) of object;

  TElCustomCryptoProviderClass = class of TElCustomCryptoProvider;

  TElCustomCryptoProvider = class(TSBControlBase)
  protected
    FCryptoProviderManager : TElCustomCryptoProviderManager;
    FUniqueID : ByteArray;
  protected
    FOnProgress : TSBMathProgressFunc;
    FOnCreateObject : TSBCryptoProviderObjectEvent;
    FOnDestroyObject : TSBCryptoProviderObjectEvent;
    FOptions : TElCustomCryptoProviderOptions;
    FEnabled : boolean;
    procedure DoCreateObject(Obj : TObject);
    procedure DoDestroyObject(Obj : TObject);
    class procedure DoSetAsDefault(Value : TElCustomCryptoProviderClass);
    function CreateOptions : TElCustomCryptoProviderOptions; virtual;
  public
    constructor Create({$ifndef SB_NO_COMPONENT}AOwner: TComponent {$endif});  overload;  {$ifndef SB_NO_COMPONENT}override; {$else}virtual; {$endif}
    constructor Create(Options : TElCustomCryptoProviderOptions{$ifndef SB_NO_COMPONENT}; AOwner: TComponent {$endif});  reintroduce;  overload;  virtual;

     destructor  Destroy; override;

    procedure Init(); virtual;
    procedure Deinit(); virtual;
    class procedure SetAsDefault; virtual; 

    function GetDefaultInstance : TElCustomCryptoProvider; virtual;
	
    function Clone : TElCustomCryptoProvider; virtual;

    function IsAlgorithmSupported(Algorithm : integer; Mode : integer) : boolean;  overload;  virtual;
    function IsAlgorithmSupported(const AlgOID, AlgParams : ByteArray;
      Mode : integer): boolean;  overload;  virtual;
    function IsOperationSupported(Operation : integer; Algorithm : integer;
      Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters): boolean;  overload;  virtual;
    function IsOperationSupported(Operation : integer; const AlgOID, AlgParams : ByteArray;
      Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters): boolean;  overload;  virtual;

    function GetAlgorithmProperty(Algorithm : integer; Mode : integer;
      const PropID : ByteArray): ByteArray;  overload;  virtual;
    function GetAlgorithmProperty(const AlgOID, AlgParams : ByteArray;
      Mode : integer; const PropID : ByteArray): ByteArray;  overload;  virtual;
    function GetAlgorithmClass(Algorithm : integer): integer;  overload;  virtual; abstract;
    function GetAlgorithmClass(const AlgOID, AlgParams : ByteArray): integer;  overload;  virtual; abstract;
    {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS}
    function GetProviderProp(const PropID : ByteArray; const Default : ByteArray  =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif} ): ByteArray;{$ifndef SB_STATIC_PKCS11} virtual; {$else} overload;  virtual;
    function GetProviderProp(const PropID : ByteArray; Default : TObject  =  nil): TObject; overload;  virtual; {$endif}
     {$else}
    function GetProviderProp(const PropID : ByteArray): ByteArray;  overload; 
    function GetProviderProp(const PropID : ByteArray; const Default : ByteArray ): ByteArray;  overload;  virtual;
    {$ifdef SB_STATIC_PKCS11}
    function GetProviderProp(const PropID : ByteArray; Default : TObject  =  nil): TObject; overload;  virtual;
     {$endif}
     {$endif}
    procedure SetProviderProp(const PropID : ByteArray; const Value : ByteArray);{$ifndef SB_STATIC_PKCS11} virtual; {$else} overload;  virtual;
    procedure SetProviderProp(const PropID : ByteArray; Value : TObject); overload;  virtual; {$endif}

    // key management routines
    function CreateKey(Algorithm : integer; Mode : integer; Params : TElCPParameters  =  nil): TElCustomCryptoKey;  overload;  virtual; abstract;
    function CreateKey(const AlgOID : ByteArray; const AlgParams : ByteArray;
      Params : TElCPParameters  =  nil): TElCustomCryptoKey;  overload;  virtual; abstract;
    function CloneKey(Key : TElCustomCryptoKey) : TElCustomCryptoKey; virtual; abstract;
    procedure ReleaseKey(var Key : TElCustomCryptoKey); virtual; abstract;
    procedure DeleteKey(var Key : TElCustomCryptoKey); virtual; abstract;
    function DecryptKey(EncKey : pointer; EncKeySize : integer; const EncKeyAlgOID,
      EncKeyAlgParams : ByteArray; Key : TElCustomCryptoKey; const KeyAlgOID,
      KeyAlgParams : ByteArray; Params : TElCPParameters = nil;
      ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil): TElCustomCryptoKey; virtual; abstract;

    // storage management routines
    function CreateKeyStorage(Persistent: boolean; Params : TElCPParameters  =  nil): TElCustomCryptoKeyStorage; virtual; abstract;
    procedure ReleaseKeyStorage(var KeyStorage : TElCustomCryptoKeyStorage); virtual; abstract;
    procedure DeleteKeyStorage(var KeyStorage : TElCustomCryptoKeyStorage); virtual; abstract;

    // encryption and signing functions
    {$ifndef SB_PGPSFX_STUB}
    function EncryptInit(Algorithm : integer; Mode : integer; Key : TElCustomCryptoKey;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil) : TElCustomCryptoContext;  overload;  virtual; abstract;
    function EncryptInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
      Mode : integer; Key : TElCustomCryptoKey;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil): TElCustomCryptoContext;  overload;  virtual; abstract;
     {$endif SB_PGPSFX_STUB}
    function DecryptInit(Algorithm : integer; Mode : integer; Key : TElCustomCryptoKey;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil) : TElCustomCryptoContext;  overload;  virtual; abstract;
    function DecryptInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
      Mode : integer; Key : TElCustomCryptoKey;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil): TElCustomCryptoContext;  overload;  virtual; abstract;
    {$ifndef SB_PGPSFX_STUB}
    function SignInit(Algorithm : integer; Key : TElCustomCryptoKey;
      Detached : boolean; Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil) : TElCustomCryptoContext;  overload;  virtual; abstract;
    function SignInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
      Key : TElCustomCryptoKey; Detached : boolean;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil): TElCustomCryptoContext;  overload;  virtual; abstract;
     {$endif SB_PGPSFX_STUB}
    function VerifyInit(Algorithm : integer; Key : TElCustomCryptoKey;
      SigBuffer : pointer; SigSize : integer; Params : TElCPParameters = nil;
      ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil) : TElCustomCryptoContext; overload; virtual; abstract;
    function VerifyInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
      Key : TElCustomCryptoKey; SigBuffer : pointer; SigSize : integer;
      Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil) : TElCustomCryptoContext; overload; virtual; abstract;
    {$ifndef SB_PGPSFX_STUB}
    procedure EncryptUpdate(Context : TElCustomCryptoContext; InBuffer : pointer;
      InSize : integer; OutBuffer : pointer; var OutSize : integer;
      Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil); virtual; abstract;
     {$endif SB_PGPSFX_STUB}
    procedure DecryptUpdate(Context : TElCustomCryptoContext; InBuffer : pointer;
      InSize : integer; OutBuffer : pointer; var OutSize : integer;
      Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil); virtual; abstract;
    {$ifndef SB_PGPSFX_STUB}
    procedure SignUpdate(Context : TElCustomCryptoContext; InBuffer : pointer;
      InSize : integer; OutBuffer: pointer; var OutSize : integer; Params : TElCPParameters = nil;
      ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil); virtual; abstract;
     {$endif SB_PGPSFX_STUB}
    procedure VerifyUpdate(Context : TElCustomCryptoContext; InBuffer : pointer;
      InSize : integer; OutBuffer : pointer; var OutSize : integer;
      Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil); virtual; abstract;
    {$ifndef SB_PGPSFX_STUB}
    procedure EncryptFinal(Context : TElCustomCryptoContext; Buffer : pointer;
      var Size : integer; Params : TElCPParameters = nil;
      ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil); virtual; abstract;
     {$endif SB_PGPSFX_STUB}
    procedure DecryptFinal(Context : TElCustomCryptoContext; Buffer : pointer;
      var Size : integer; Params : TElCPParameters = nil;
      ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil); virtual; abstract;
    {$ifndef SB_PGPSFX_STUB}
    procedure SignFinal(Context : TElCustomCryptoContext; Buffer : pointer;
      var Size : integer; Params : TElCPParameters = nil;
      ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil); virtual; abstract;
     {$endif SB_PGPSFX_STUB}
    function VerifyFinal(Context : TElCustomCryptoContext; Buffer: pointer;
      var Size : integer; Params : TElCPParameters = nil;
      ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil): integer; virtual; abstract;
    {$ifndef SB_PGPSFX_STUB}
    procedure Encrypt(Algorithm: integer; Mode: integer; Key: TElCustomCryptoKey;
      InBuffer: pointer; InSize: integer; OutBuffer: pointer; var OutSize: integer;
      Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil); overload; virtual;
    procedure Encrypt(const AlgOID, AlgParams : ByteArray; Mode: integer; Key: TElCustomCryptoKey;
      InBuffer: pointer; InSize: integer; OutBuffer: pointer; var OutSize: integer;
      Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil); overload; virtual;
     {$endif SB_PGPSFX_STUB}
    procedure Decrypt(Algorithm: integer; Mode: integer; Key: TElCustomCryptoKey;
      InBuffer: pointer; InSize: integer; OutBuffer: pointer; var OutSize: integer;
      Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil); overload; virtual;
    procedure Decrypt(const AlgOID, AlgParams : ByteArray; Mode: integer; Key: TElCustomCryptoKey;
      InBuffer: pointer; InSize: integer; OutBuffer: pointer; var OutSize: integer;
      Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil); overload; virtual;
    {$ifndef SB_PGPSFX_STUB}
    procedure Sign(Algorithm: integer; Key : TElCustomCryptoKey; Detached : boolean;
      InBuffer: pointer; InSize: integer; OutBuffer: pointer; var OutSize: integer;
      Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil); overload; virtual;
    procedure Sign(const AlgOID, AlgParams : ByteArray; Key : TElCustomCryptoKey; Detached : boolean;
      InBuffer: pointer; InSize: integer; OutBuffer: pointer; var OutSize: integer;
      Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil); overload; virtual;
     {$endif SB_PGPSFX_STUB}
    function Verify(Algorithm: integer; Key : TElCustomCryptoKey; InBuffer: pointer;
      InSize: integer; OutBuffer: pointer; var OutSize : integer; Params : TElCPParameters = nil;
      ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil): integer; overload; virtual;
    function Verify(const AlgOID, AlgParams: ByteArray; Key : TElCustomCryptoKey; InBuffer: pointer;
      InSize: integer; OutBuffer: pointer; var OutSize : integer; Params : TElCPParameters = nil;
      ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil): integer; overload; virtual;
    function VerifyDetached(Algorithm: integer; Key : TElCustomCryptoKey; InBuffer: pointer;
      InSize: integer; SigBuffer: pointer; SigSize : integer; Params : TElCPParameters = nil;
      ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil): integer; overload; virtual;
    function VerifyDetached(const AlgOID, AlgParams: ByteArray; Key : TElCustomCryptoKey;
      InBuffer: pointer; InSize: integer; SigBuffer: pointer; SigSize : integer;
      Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil): integer; overload; virtual;

    // hash functions
    function HashInit(Algorithm : integer; Key : TElCustomCryptoKey;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil): TElCustomCryptoContext;  overload;  virtual; abstract;
    function HashInit(const AlgOID : ByteArray; const AlgParams : ByteArray;
      Key : TElCustomCryptoKey;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil): TElCustomCryptoContext;  overload;  virtual; abstract;
    function HashFinal(Context : TElCustomCryptoContext;
      Params : TElCPParameters  =  nil;
      ProgressFunc : TSBProgressFunc  =  nil;
      ProgressData :  pointer   =  nil): ByteArray; virtual; abstract;

    procedure HashUpdate(Context : TElCustomCryptoContext; Buffer : pointer;
      Size : integer; Params : TElCPParameters = nil;
      ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil); virtual; abstract;
    function Hash(Algorithm: integer; Key : TElCustomCryptoKey; Buffer: pointer;
      Size: integer; Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil): ByteArray; overload; virtual;
    function Hash(const AlgOID, AlgParams: ByteArray; Key : TElCustomCryptoKey; Buffer: pointer;
      Size: integer; Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
      ProgressData : pointer = nil): ByteArray; overload; virtual;

    // crypto context functions
    procedure ReleaseCryptoContext(var Context : TElCustomCryptoContext); virtual; abstract;

    // randomizer functions
    procedure RandomInit(BaseData: pointer; BaseDataSize: integer; Params : TElCPParameters = nil); virtual; abstract;
    procedure RandomSeed(Data: pointer; DataSize: integer); virtual; abstract;
    procedure RandomGenerate(Buffer: pointer; Size: integer); overload; virtual; abstract;
    function RandomGenerate(MaxValue: integer): integer;  overload;  virtual; abstract;

    function OwnsObject(Obj : TObject): boolean; virtual;

    property Options : TElCustomCryptoProviderOptions read FOptions;
    property Enabled : boolean read FEnabled write FEnabled;
    property CryptoProviderManager : TElCustomCryptoProviderManager read FCryptoProviderManager write FCryptoProviderManager;
                          
    property OnCreateObject : TSBCryptoProviderObjectEvent read FOnCreateObject write FOnCreateObject;
    property OnDestroyObject : TSBCryptoProviderObjectEvent read FOnDestroyObject write FOnDestroyObject;
  end;

  TElBlackboxCryptoProvider = class(TElCustomCryptoProvider)
  public
  end;

  TElExternalCryptoProvider = class(TElBlackboxCryptoProvider)
    // this class maps external code as a standard blackbox cryptoprovider
  end;

  TElCustomCryptoProviderManager = class(TSBComponentBase)
  protected
    FProviders : TElList;
    FLock : TElSharedResource;
    FDefaultProvider : TElCustomCryptoProvider;
    function GetDefaultCryptoProvider : TElCustomCryptoProvider;
    function GetCryptoProvider(Index: integer): TElCustomCryptoProvider;
    function GetCount : integer;
  protected
    {$ifndef SB_NO_COMPONENT}
    procedure Notification(AComponent : TComponent; AOperation : TOperation); override;
     {$endif}
  public
    {$ifndef SB_NO_COMPONENT}
    constructor Create(AOwner : TComponent); override;
     {$else}
    constructor Create;
     {$endif}
     destructor  Destroy; override;
    procedure Init(); virtual;
    procedure Deinit(); virtual;
    // provider registration/unregistration methods
    function RegisterCryptoProvider(Prov : TElCustomCryptoProvider): integer;
    procedure UnregisterCryptoProvider(Prov : TElCustomCryptoProvider);  overload; 
    procedure UnregisterCryptoProvider(Index : integer);  overload; 
    procedure SetDefaultCryptoProvider(Prov : TElCustomCryptoProvider);  overload; 
    procedure SetDefaultCryptoProvider(Index : integer);  overload; 
    procedure SetDefaultCryptoProviderType(Value : TElCustomCryptoProviderClass);
    // provider access functions
    function GetSuitableProvider(Operation : integer; Algorithm : integer;
      Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters): TElCustomCryptoProvider;  overload; 
    function {$ifndef BUILDER_USED}GetSuitableProvider {$else}GetSuitableProvider2 {$endif}(Operation : integer; const AlgOID, AlgParams : ByteArray;
      Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters): TElCustomCryptoProvider;  overload; 
    function {$ifndef BUILDER_USED}GetSuitableProvider {$else}GetSuitableProvider3 {$endif}(Algorithm : integer; Mode : integer) : TElCustomCryptoProvider;  overload; 
    function {$ifndef BUILDER_USED}GetSuitableProvider {$else}GetSuitableProvider4 {$endif}(const AlgOID, AlgParams : ByteArray; Mode : integer) : TElCustomCryptoProvider;  overload; 
    function IsOperationSupported(Operation : integer; Algorithm : integer;
      Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters): boolean;  overload; 
    function IsOperationSupported(Operation : integer; const AlgOID, AlgParams : ByteArray;
      Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters): boolean;  overload; 
    function IsAlgorithmSupported(Algorithm : integer; Mode : integer): boolean;  overload; 
    function IsAlgorithmSupported(const AlgOID, AlgParams : ByteArray; Mode : integer): boolean;  overload; 
    function IsProviderAllowed(Prov : TElCustomCryptoProvider): boolean; virtual;
    // algorithm information methods
    function GetAlgorithmProperty(Algorithm : integer; Mode : integer;
      const PropID : ByteArray): ByteArray;  overload; 
    function GetAlgorithmProperty(const AlgOID, AlgParams : ByteArray;
      Mode : integer; const PropID : ByteArray): ByteArray;  overload; 
    function GetAlgorithmClass(Algorithm : integer): integer;  overload; 
    function GetAlgorithmClass(const AlgOID, AlgParams : ByteArray): integer;  overload; 
    // generic access for all installed providers
    property CryptoProviders[Index : integer] : TElCustomCryptoProvider read GetCryptoProvider;
    property Count : integer read GetCount;
    // default provider
    property DefaultCryptoProvider : TElCustomCryptoProvider read GetDefaultCryptoProvider;
  end;

  EElCryptoProviderError =  class(ESecureBlackboxError);
  EElCryptoKeyError =  class(EElCryptoProviderError);
  EElCryptoProviderManagerError = class(EElCryptoProviderError);
  EElCryptoProviderInvalidSignatureError =  class(EElCryptoProviderError);

implementation

uses
  SBSHA2,
  SBRandom,
  //SBCryptoProvBuiltIn,
  SBCryptoProvDefault,
  SBCryptoProvRS
{$ifdef SB_HAS_WINCRYPT}
//, SBCryptoProvWin32
 {$endif}
{$ifndef SB_NO_PKCS11}
//, SBCryptoProvPKCS11
 {$endif};

// TODO: check that all descedants DO NOT contain non-overridden abstract methods

////////////////////////////////////////////////////////////////////////////////
// TElCustomCryptoProvider class

constructor TElCustomCryptoProvider.Create({$ifndef SB_NO_COMPONENT}AOwner: TComponent {$endif});
begin
  inherited;
  FOptions := CreateOptions();
  FEnabled := true;
  SetLength(FUniqueID, 16);
  SBRndGenerate(@FUniqueID[0], Length(FUniqueID));
  Init;
end;

constructor TElCustomCryptoProvider.Create(Options : TElCustomCryptoProviderOptions
  {$ifndef SB_NO_COMPONENT}; AOwner: TComponent {$endif});
begin
  inherited Create({$ifndef SB_NO_COMPONENT}AOwner {$endif});
  FOptions := CreateOptions();
  FOptions.Assign(Options);
  FEnabled := true;
  SetLength(FUniqueID, 16);
  SBRndGenerate(@FUniqueID[0], Length(FUniqueID));
  Init;
end;

 destructor  TElCustomCryptoProvider.Destroy;
begin
  DeInit;
  FreeAndNil(FOptions);
  inherited;
end;

procedure TElCustomCryptoProvider.Deinit;
begin
  // default implementation does nothing
end;

procedure TElCustomCryptoProvider.Init;
begin
  // default implementation does nothing
end;

function TElCustomCryptoProvider.IsAlgorithmSupported(Algorithm,
  Mode: integer): boolean;
begin
  result := false;
end;

function TElCustomCryptoProvider.IsAlgorithmSupported(const AlgOID, AlgParams : ByteArray;
  Mode : integer): boolean;
begin
  Result := false;
end;

function TElCustomCryptoProvider.IsOperationSupported(Operation : integer; Algorithm : integer;
  Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters): boolean;
begin
  Result := false;
end;

function TElCustomCryptoProvider.IsOperationSupported(Operation : integer; const AlgOID, AlgParams : ByteArray;
  Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters): boolean; 
begin
  Result := false;
end;

function TElCustomCryptoProvider.GetAlgorithmProperty(Algorithm : integer; Mode : integer;
  const PropID : ByteArray): ByteArray;
begin
  raise EElCryptoProviderError.CreateFmt(SUnsupportedAlgorithmInt, [Algorithm]);
end;

function TElCustomCryptoProvider.GetAlgorithmProperty(const AlgOID, AlgParams : ByteArray;
  Mode : integer; const PropID : ByteArray): ByteArray;
begin
  raise EElCryptoProviderError.CreateFmt(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]);
end;

{$ifdef SB_NO_DEFAULT_BYTEARRAY_PARAMS}
function TElCustomCryptoProvider.GetProviderProp(const PropID : ByteArray): ByteArray;
begin
  Result := GetProviderProp(PropID, EmptyArray);
end;
 {$endif}

function TElCustomCryptoProvider.GetProviderProp(const PropID : ByteArray; const Default : ByteArray {$ifndef SB_NO_DEFAULT_BYTEARRAY_PARAMS} =   {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}nil {$else}'' {$endif}  {$endif}): ByteArray;
begin
  raise EElCryptoProviderError.CreateFmt(SUnsupportedPropertyStr, [BinaryToString(PropID)]);
end;

procedure TElCustomCryptoProvider.SetProviderProp(const PropID : ByteArray; const Value : ByteArray);
begin
  raise EElCryptoProviderError.CreateFmt(SUnsupportedPropertyStr, [BinaryToString(PropID)]);
end;

{$ifdef SB_STATIC_PKCS11}
function TElCustomCryptoProvider.GetProviderProp(const PropID : ByteArray; Default : TObject  =  nil): TObject;
begin
  raise EElCryptoProviderError.CreateFmt(SUnsupportedPropertyStr, [BinaryToString(PropID)]);
end;

procedure TElCustomCryptoProvider.SetProviderProp(const PropID : ByteArray; Value : TObject);
begin
  raise EElCryptoProviderError.CreateFmt(SUnsupportedPropertyStr, [BinaryToString(PropID)]);
end;
 {$endif}

////////////////////////////////////////////////////////////////////////////////
// TElCustomCryptoKey class

constructor TElCustomCryptoKey.Create(CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create;
  FCryptoProvider := CryptoProvider;
  FOwnerUniqueID := CloneArray(CryptoProvider.FUniqueID);
end;

function TElCustomCryptoKey.Equals(Key: TElCustomCryptoKey; PublicOnly : boolean;
  Params : TElCPParameters  =  nil): boolean;
begin
  raise EElCryptoProviderError.Create(SUnsupportedOperation);
end;

{$ifdef D_12_UP}
function TElCustomCryptoKey.Equals(Obj: TObject): Boolean;
begin
  Result := inherited;
end;
 {$endif}

{$ifdef SB_NO_DEFAULT_BYTEARRAY_PARAMS}
function TElCustomCryptoKey.GetKeyProp(const PropID : ByteArray): ByteArray;
begin
  Result := GetKeyProp(PropID, EmptyArray);
end;
 {$endif}

////////////////////////////////////////////////////////////////////////////////
// TElCustomCryptoStorage

{$ifdef SB_NO_DEFAULT_BYTEARRAY_PARAMS}
function TElCustomCryptoKeyStorage.GetStorageProp(const PropID : ByteArray): ByteArray;
begin
  Result := GetStorageProp(PropID, EmptyArray);
end;
 {$endif}

////////////////////////////////////////////////////////////////////////////////
// TElCustomCryptoStorage

{$ifdef SB_NO_DEFAULT_BYTEARRAY_PARAMS}
function TElCustomCryptoContext.GetContextProp(const PropID : ByteArray): ByteArray;
begin
  Result := GetContextProp(PropID, EmptyArray);
end;
 {$endif}

////////////////////////////////////////////////////////////////////////////////
// TElCustomCryptoProvider class

{$ifndef SB_PGPSFX_STUB}
procedure TElCustomCryptoProvider.Encrypt(Algorithm: integer; Mode: integer; Key: TElCustomCryptoKey;
  InBuffer: pointer; InSize: integer; OutBuffer: pointer; var OutSize: integer;
  Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
  ProgressData : pointer = nil);
var
  Context : TElCustomCryptoContext;
  Ptr :  ^byte ;
  ChunkSize : integer;
begin
  Context := EncryptInit(Algorithm, Mode, Key, Params);
  try
    if OutBuffer = nil then
      OutSize := Context.EstimateOutputSize(InSize)
    else
    begin
      Ptr :=  OutBuffer ;
      ChunkSize := OutSize;
      EncryptUpdate(Context, InBuffer, InSize, Ptr, ChunkSize, Params);
      Inc(Ptr, ChunkSize);
      Dec(OutSize, ChunkSize);
      EncryptFinal(Context, Ptr, OutSize, Params);
      OutSize := OutSize + ChunkSize;
    end;
  finally
    ReleaseCryptoContext(Context);
  end;
end;

procedure TElCustomCryptoProvider.Encrypt(const AlgOID, AlgParams : ByteArray; Mode: integer; Key: TElCustomCryptoKey;
  InBuffer: pointer; InSize: integer; OutBuffer: pointer; var OutSize: integer;
  Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
  ProgressData : pointer = nil);
var
  Context : TElCustomCryptoContext;
  Ptr :  ^byte ;
  ChunkSize : integer;
begin
  Context := EncryptInit(AlgOID, AlgParams, Mode, Key, Params);
  try
    if OutBuffer = nil then
      OutSize := Context.EstimateOutputSize(InSize)
    else
    begin
      Ptr :=  OutBuffer ;
      ChunkSize := OutSize;
      EncryptUpdate(Context, InBuffer, InSize, Ptr, ChunkSize, Params);
      Inc(Ptr, ChunkSize);
      Dec(OutSize, ChunkSize);
      EncryptFinal(Context, Ptr, OutSize, Params);
      OutSize := OutSize + ChunkSize;
    end;
  finally
    ReleaseCryptoContext(Context);
  end;
end;
 {$endif SB_PGPSFX_STUB}

procedure TElCustomCryptoProvider.Decrypt(Algorithm: integer; Mode: integer; Key: TElCustomCryptoKey;
  InBuffer: pointer; InSize: integer; OutBuffer: pointer; var OutSize: integer;
  Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
  ProgressData : pointer = nil);
var
  Context : TElCustomCryptoContext;
  Ptr :  ^byte ;
  ChunkSize : integer;
begin
  Context := DecryptInit(Algorithm, Mode, Key, Params);
  try
    if OutBuffer = nil then
      OutSize := Context.EstimateOutputSize(InSize)
    else
    begin
      Ptr :=  OutBuffer ;
      ChunkSize := OutSize;
      DecryptUpdate(Context, InBuffer, InSize, Ptr, ChunkSize, Params);
      Inc(Ptr, ChunkSize);
      Dec(OutSize, ChunkSize);
      DecryptFinal(Context, Ptr, OutSize, Params);
      OutSize := OutSize + ChunkSize;
    end;
  finally
    ReleaseCryptoContext(Context);
  end;
end;

procedure TElCustomCryptoProvider.Decrypt(const AlgOID, AlgParams : ByteArray; Mode: integer; Key: TElCustomCryptoKey;
  InBuffer: pointer; InSize: integer; OutBuffer: pointer; var OutSize: integer;
  Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
  ProgressData : pointer = nil);
var
  Context : TElCustomCryptoContext;
  Ptr :  ^byte ;
  ChunkSize : integer;
begin
  Context := DecryptInit(AlgOID, AlgParams, Mode, Key, Params);
  try
    if OutBuffer = nil then
      OutSize := Context.EstimateOutputSize(InSize)
    else
    begin
      Ptr :=  OutBuffer ;
      ChunkSize := OutSize;
      DecryptUpdate(Context, InBuffer, InSize, Ptr, ChunkSize, Params);
      Inc(Ptr, ChunkSize);
      Dec(OutSize, ChunkSize);
      DecryptFinal(Context, Ptr, OutSize, Params);
      OutSize := OutSize + ChunkSize;
    end;
  finally
    ReleaseCryptoContext(Context);
  end;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElCustomCryptoProvider.Sign(Algorithm: integer; Key : TElCustomCryptoKey; Detached : boolean;
  InBuffer: pointer; InSize: integer; OutBuffer: pointer; var OutSize: integer;
  Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
  ProgressData : pointer = nil);
var
  Context : TElCustomCryptoContext;
  Ptr :  ^byte ;
  ChunkSize : integer;
begin
  Context := SignInit(Algorithm, Key, Detached, Params);
  try
    if OutBuffer = nil then
      OutSize := Context.EstimateOutputSize(InSize)
    else
    begin
      Ptr :=  OutBuffer ;
      ChunkSize := OutSize;
      SignUpdate(Context, InBuffer, InSize, Ptr, ChunkSize, Params);
      Inc(Ptr, ChunkSize);
      Dec(OutSize, ChunkSize);
      SignFinal(Context, Ptr, OutSize, Params);
      OutSize := OutSize + ChunkSize;
    end;
  finally
    ReleaseCryptoContext(Context);
  end;
end;

procedure TElCustomCryptoProvider.Sign(const AlgOID, AlgParams : ByteArray; Key : TElCustomCryptoKey; Detached : boolean;
  InBuffer: pointer; InSize: integer; OutBuffer: pointer; var OutSize: integer;
  Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
  ProgressData : pointer = nil);
var
  Context : TElCustomCryptoContext;
  Ptr :  ^byte ;
  ChunkSize : integer;
begin
  Context := SignInit(AlgOID, AlgParams, Key, Detached, Params);
  try
    if OutBuffer = nil then
      OutSize := Context.EstimateOutputSize(InSize)
    else
    begin
      Ptr :=  OutBuffer ;
      ChunkSize := OutSize;
      SignUpdate(Context, InBuffer, InSize, Ptr, ChunkSize, Params);
      Inc(Ptr, ChunkSize);
      Dec(OutSize, ChunkSize);
      SignFinal(Context, Ptr, OutSize, Params);
      OutSize := OutSize + ChunkSize;
    end;
  finally
    ReleaseCryptoContext(Context);
  end;
end;
 {$endif SB_PGPSFX_STUB}

function TElCustomCryptoProvider.Verify(Algorithm: integer; Key : TElCustomCryptoKey; InBuffer: pointer;
  InSize: integer; OutBuffer: pointer; var OutSize : integer; Params : TElCPParameters = nil;
  ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil): integer;
var
  Context : TElCustomCryptoContext;
  Ptr :  ^byte ;
  ChunkSize : integer;
begin
  Context := VerifyInit(Algorithm, Key, nil, 0, Params);
  try
    if OutBuffer = nil then
    begin
      OutSize := Context.EstimateOutputSize(InSize);
      Result := SB_VR_FAILURE;
    end
    else
    begin
      Ptr :=  OutBuffer ;
      ChunkSize := OutSize;
      VerifyUpdate(Context, InBuffer, InSize, Ptr, ChunkSize, Params);
      Inc(Ptr, ChunkSize);
      Dec(OutSize, ChunkSize);
      Result := VerifyFinal(Context, Ptr, OutSize, Params);
      OutSize := OutSize + ChunkSize;
    end;
  finally
    ReleaseCryptoContext(Context);
  end;
end;

function TElCustomCryptoProvider.Verify(const AlgOID, AlgParams: ByteArray;
  Key : TElCustomCryptoKey; InBuffer: pointer; InSize: integer; OutBuffer: pointer;
  var OutSize : integer; Params : TElCPParameters = nil;
  ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil): integer;
var
  Context : TElCustomCryptoContext;
  Ptr :  ^byte ;
  ChunkSize : integer;
begin
  Context := VerifyInit(AlgOID, AlgParams, Key, nil, 0, Params);
  try
    if OutBuffer = nil then
    begin
      OutSize := Context.EstimateOutputSize(InSize);
      Result := SB_VR_FAILURE;
    end
    else
    begin
      Ptr :=  OutBuffer ;
      ChunkSize := OutSize;
      VerifyUpdate(Context, InBuffer, InSize, Ptr, ChunkSize, Params);
      Inc(Ptr, ChunkSize);
      Dec(OutSize, ChunkSize);
      Result := VerifyFinal(Context, Ptr, OutSize, Params);
      OutSize := OutSize + ChunkSize;
    end;
  finally
    ReleaseCryptoContext(Context);
  end;
end;

function TElCustomCryptoProvider.VerifyDetached(Algorithm: integer; Key : TElCustomCryptoKey; InBuffer: pointer;
  InSize: integer; SigBuffer: pointer; SigSize : integer; Params : TElCPParameters = nil;
  ProgressFunc : TSBProgressFunc = nil; ProgressData : pointer = nil): integer;
var
  Context : TElCustomCryptoContext;
  OutSize : integer;
  TmpBuf : ByteArray;
begin
  Context := VerifyInit(Algorithm, Key, SigBuffer, SigSize, Params);
  try
    OutSize := 0;
    VerifyUpdate(Context, InBuffer, InSize, nil, OutSize, Params);
    SetLength(TmpBuf, OutSize);
    VerifyUpdate(Context, InBuffer, InSize, @TmpBuf[0], OutSize, Params);
    OutSize := 0;
    VerifyFinal(Context,  nil , OutSize, Params);
    SetLength(TmpBuf, OutSize);
    Result := VerifyFinal(Context,  @TmpBuf[0] , OutSize, Params);
  finally
    ReleaseCryptoContext(Context);
  end;
end;

function TElCustomCryptoProvider.VerifyDetached(const AlgOID, AlgParams: ByteArray; Key : TElCustomCryptoKey;
  InBuffer: pointer; InSize: integer; SigBuffer: pointer; SigSize : integer;
  Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
  ProgressData : pointer = nil): integer;
var
  Context : TElCustomCryptoContext;
  OutSize : integer;
begin
  Context := VerifyInit(AlgOID, AlgParams, Key, SigBuffer, SigSize, Params);
  try
    OutSize := 0;
    VerifyUpdate(Context, InBuffer, InSize, nil, OutSize, Params);
    OutSize := 0;
    Result := VerifyFinal(Context,  nil , OutSize, Params);
  finally
    ReleaseCryptoContext(Context);
  end;
end;

function TElCustomCryptoProvider.Hash(Algorithm: integer; Key : TElCustomCryptoKey; Buffer: pointer;
  Size: integer; Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
  ProgressData : pointer = nil): ByteArray;
var
  Context : TElCustomCryptoContext;
begin
  Context := HashInit(Algorithm, Key, Params);
  try
    HashUpdate(Context, Buffer, Size, Params);
    Result := CloneArray(HashFinal(Context, Params));
  finally
    ReleaseCryptoContext(Context);
  end;
end;

function TElCustomCryptoProvider.Hash(const AlgOID, AlgParams: ByteArray; Key : TElCustomCryptoKey; Buffer: pointer;
  Size: integer; Params : TElCPParameters = nil; ProgressFunc : TSBProgressFunc = nil;
  ProgressData : pointer = nil): ByteArray;
var
  Context : TElCustomCryptoContext;
begin
  Context := HashInit(AlgOID, AlgParams, Key, Params);
  try
    HashUpdate(Context, Buffer, Size, Params);
    Result := CloneArray(HashFinal(Context, Params));
  finally
    ReleaseCryptoContext(Context);
  end;
end;

procedure TElCustomCryptoProvider.DoCreateObject(Obj : TObject);
begin
  if Assigned(FOnCreateObject) then
    FOnCreateObject(Self, Obj);
end;

procedure TElCustomCryptoProvider.DoDestroyObject(Obj : TObject);
begin
  if Assigned(FOnDestroyObject) then
    FOnDestroyObject(Self, Obj);
end;

function TElCustomCryptoProvider.CreateOptions : TElCustomCryptoProviderOptions;
begin
  Result := TElCustomCryptoProviderOptions.Create();
end;

class procedure TElCustomCryptoProvider.SetAsDefault;
begin
  DoSetAsDefault(TElCustomCryptoProvider);
end;

class procedure TElCustomCryptoProvider.DoSetAsDefault(Value : TElCustomCryptoProviderClass);
begin
  SetDefaultCryptoProviderType(Value);
end;

function TElCustomCryptoProvider.GetDefaultInstance : TElCustomCryptoProvider;
begin
  raise EElCryptoProviderError.Create(SInstantiationFailed);
end;

function TElCustomCryptoProvider.Clone : TElCustomCryptoProvider;
begin
  raise EElCryptoProviderError.Create(SInstantiationFailed);
end;

function TElCustomCryptoProvider.OwnsObject(Obj : TObject): boolean;
begin
  Result := (Obj is TElCustomCryptoKey) and (CompareArrays(TElCustomCryptoKey(Obj).FOwnerUniqueID, FUniqueID) = 0);
end;

////////////////////////////////////////////////////////////////////////////////
// TElCustomCryptoKey class

procedure TElCustomCryptoKey.InternalImportPublic(Buffer : pointer; Size : integer;
  var Algorithm : integer; var Key : ByteArray; var IV : ByteArray);
var
  MinSize, MaxSize, NeedIVSize : integer;
  Alg : word;
  KeySize, IVSize : integer;
  Hash, OrigHash : TMessageDigest256;
  LKey, LIV : ByteArray;
begin
  if Size < 38 then
    raise EElCryptoProviderError.Create(SInvalidKeyMaterial);

  Alg := PByteArray(Buffer)^[0] shl 8 + PByteArray(Buffer)^[1];
  KeySize := PByteArray(Buffer)^[2] shl 8 + PByteArray(Buffer)^[3];

  if (Size < 38 + KeySize) then
    raise EElCryptoProviderError.Create(SInvalidKeyMaterial);

  MinSize := 1;
  MaxSize := 56;
  NeedIVSize := 0;
  case Alg of
    SB_ALGORITHM_CNT_RC4 :
      begin
        MinSize := 1;
        MaxSize := 32;
        NeedIVSize := 0;
      end;
    SB_ALGORITHM_CNT_DES :
      begin
        MinSize := 8;
        MaxSize := 8;
        NeedIVSize := 8;
      end;
    SB_ALGORITHM_CNT_3DES :
      begin
        MinSize := 24;
        MaxSize := 24;
        NeedIVSize := 8;
      end;
    SB_ALGORITHM_CNT_RC2 :
      begin
        MinSize := 1;
        MaxSize := 16;
        NeedIVSize := 8;
      end;
    SB_ALGORITHM_CNT_AES128 :
      begin
        MinSize := 16;
        MaxSize := 16;
        NeedIVSize := 16;
      end;
    SB_ALGORITHM_CNT_AES192 :
      begin
        MinSize := 24;
        MaxSize := 24;
        NeedIVSize := 16;
      end;
    SB_ALGORITHM_CNT_AES256 :
      begin
        MinSize := 32;
        MaxSize := 32;
        NeedIVSize := 16;
      end;
    SB_ALGORITHM_CNT_BLOWFISH :
      begin
        MinSize := 4;
        MaxSize := 56;
        NeedIVSize := 8;
      end;
    SB_ALGORITHM_CNT_TWOFISH :
      begin
        MinSize := 16;
        MaxSize := 32;
        NeedIVSize := 16;
      end;
    SB_ALGORITHM_CNT_CAMELLIA :
      begin
        MinSize := 16;
        MaxSize := 32;
        NeedIVSize := 16;
      end;
    SB_ALGORITHM_CNT_CAST128 :
      begin
        MinSize := 16;
        MaxSize := 16;
        NeedIVSize := 8;
      end;
    SB_ALGORITHM_CNT_IDEA :
      begin
        MinSize := 16;
        MaxSize := 16;
        NeedIVSize := 8;
      end;
    SB_ALGORITHM_CNT_SERPENT :
      begin
        MinSize := 16;
        MaxSize := 32;
        NeedIVSize := 16;
      end;
  end;

  if (KeySize < MinSize) or (KeySize > MaxSize) then
    raise EElCryptoProviderError.Create(SInvalidKeyMaterial);

  IVSize := PByteArray(Buffer)^[4 + KeySize] shl 8 + PByteArray(Buffer)^[5 + KeySize];

  if ((IVSize <> NeedIVSize) and (IVSize <> 0)) or (Size < 38 + KeySize + IVSize) then
    raise EElCryptoProviderError.Create(SInvalidKeyMaterial);

  SBMove(PByteArray(Buffer)^[6 + KeySize + IVSize], Hash, 32);
  OrigHash := SBSHA2.HashSHA256(Buffer, 6 + KeySize + IVSize);

  if not CompareMem(@Hash, @OrigHash, 32) then
    raise EElCryptoProviderError.Create(SInvalidKeyMaterial);

  Algorithm := Alg;

  SetLength(LKey, KeySize);
  SetLength(LIV, IVSize);

  SBMove(PByteArray(Buffer)^[4], LKey[0], KeySize);
  SBMove(PByteArray(Buffer)^[6 + KeySize], LIV[0], IVSize);
  Key := LKey;
  IV := LIV;
end;

procedure TElCustomCryptoKey.InternalExportPublic(Algorithm : integer; const Key, IV : ByteArray;
  Buffer : pointer; var Size : integer);
var
  KeySize, IVSize : integer;
  Hash : TMessageDigest256;
begin
  if Size <  38 + Length(Key) + Length(IV) then
  begin
    if Size = 0 then
    begin
      Size := 38 + Length(Key) + Length(IV);
      Exit
    end
    else
      raise EElCryptoProviderError.Create(SBufferTooSmall);
  end
  else
    Size := 38 + Length(Key) + Length(IV);

  KeySize := Length(Key);
  IVSize := Length(IV);

  PByteArray(Buffer)^[0] := (Algorithm shr 8) and $ff;
  PByteArray(Buffer)^[1] := Algorithm and $ff;
  PByteArray(Buffer)^[2] := (KeySize shr 8) and $ff;
  PByteArray(Buffer)^[3] := KeySize and $ff;

  SBMove(Key[0], PByteArray(Buffer)^[4], KeySize);
  PByteArray(Buffer)^[4 + KeySize] := (IVSize shr 8) and $ff;
  PByteArray(Buffer)^[5 + KeySize] := IVSize and $ff;
  SBMove(IV[0], PByteArray(Buffer)^[6 + KeySize], IVSize);

  Hash := SBSHA2.HashSHA256(Buffer, Size - 32);
  SBMove(Hash, PByteArray(Buffer)^[6 + KeySize + IVSize], 32);
end;

////////////////////////////////////////////////////////////////////////////////
// TElCustomCryptoProviderOptions class

constructor TElCustomCryptoProviderOptions.Create;
begin
  inherited;
  Init();
end;

procedure TElCustomCryptoProviderOptions.Init;
begin
  FMaxPublicKeySize := 8192;
  FStoreKeys := false;
end;

procedure TElCustomCryptoProviderOptions.Assign(Options: TElCustomCryptoProviderOptions);
begin
  FMaxPublicKeySize := Options.FMaxPublicKeySize;
  FStoreKeys := Options.FStoreKeys;
end;

////////////////////////////////////////////////////////////////////////////////
// TElCryptoProviderManager class

constructor TElCustomCryptoProviderManager.Create({$ifndef SB_NO_COMPONENT}AOwner : TComponent {$endif});
begin
  inherited;
  FProviders := TElList.Create();
  FLock := TElSharedResource.Create();
  FDefaultProvider := nil;
  Init();
end;

 destructor  TElCustomCryptoProviderManager.Destroy;
begin
  Deinit();
  FreeAndNil(FLock);
  FreeAndNil(FProviders);
  inherited;
end;

procedure TElCustomCryptoProviderManager.Init();
begin
  ;
end;

procedure TElCustomCryptoProviderManager.Deinit();
begin
  ;
end;

{$ifndef SB_NO_COMPONENT}
procedure TElCustomCryptoProviderManager.Notification(AComponent : TComponent; AOperation : TOperation);
begin
  inherited;
end;
 {$endif}

function TElCustomCryptoProviderManager.RegisterCryptoProvider(Prov : TElCustomCryptoProvider): integer;
begin
  FLock.WaitToWrite;
  try
    Prov.CryptoProviderManager := Self;
    Result := FProviders.Add(Prov);
    if FDefaultProvider = nil then
      FDefaultProvider := Prov;
  finally
    FLock.Done;
  end;
end;

procedure TElCustomCryptoProviderManager.UnregisterCryptoProvider(Prov : TElCustomCryptoProvider);
var
  Index : integer;
begin
  FLock.WaitToWrite;
  try
    if Prov = DefaultCryptoProvider then
      raise EElCryptoProviderManagerError.Create(SCannotUnregisterDefaultProvider);
    Index := FProviders.IndexOf(Prov);
    if Index >= 0 then
    begin
      Prov.FCryptoProviderManager := nil;
      FProviders. Delete (Index);
    end;
  finally
    FLock.Done;
  end;
end;

procedure TElCustomCryptoProviderManager.UnregisterCryptoProvider(Index : integer);
begin
  FLock.WaitToWrite;
  try
    TElCustomCryptoProvider(FProviders[Index]).FCryptoProviderManager := nil;
    FProviders. Delete (Index);
  finally
    FLock.Done;
  end;
end;

procedure TElCustomCryptoProviderManager.SetDefaultCryptoProvider(Prov : TElCustomCryptoProvider);
var
  Index : integer;
begin
  FLock.WaitToWrite;
  try
    Index := FProviders.IndexOf(Prov);
    if Index < 0 then
      RegisterCryptoProvider(Prov);
    FDefaultProvider := Prov;
  finally
    FLock.Done;
  end;
end;

procedure TElCustomCryptoProviderManager.SetDefaultCryptoProvider(Index : integer);
begin
  FLock.WaitToWrite;
  try
    FDefaultProvider := TElCustomCryptoProvider(FProviders[Index]);
  finally
    FLock.Done;
  end;
end;

procedure TElCustomCryptoProviderManager.SetDefaultCryptoProviderType(Value : TElCustomCryptoProviderClass);
var
  I : integer;
  Done : boolean;
  Prov, Inst : TElCustomCryptoProvider;
begin
  if FDefaultProvider is Value then
    Exit;
  FLock.WaitToWrite;
  try
    Done := false;
    for I := 0 to FProviders.Count - 1 do
    begin
      if TElCustomCryptoProvider(FProviders[I]) is Value then
      begin
        FDefaultProvider := TElCustomCryptoProvider(FProviders[I]);
        Done := true;
        Break;
      end;
    end;
    if not Done then
    begin
      Prov :=  Value.Create ({$ifndef SB_NO_COMPONENT}nil {$endif});
      try
        Inst := Prov.GetDefaultInstance();
      finally
        FreeAndNil(Prov);
      end;
      I := RegisterCryptoProvider(Inst);
      FDefaultProvider := TElCustomCryptoProvider(FProviders[I]);
    end;
  finally
    FLock.Done;
  end;
end;

function TElCustomCryptoProviderManager.GetSuitableProvider(Operation : integer; Algorithm : integer;
  Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters): TElCustomCryptoProvider;
var
  I : integer;
begin
  Result := nil;
  FLock.WaitToRead;
  try
    if FDefaultProvider.IsOperationSupported(Operation, Algorithm, Mode, Key, Params) then
      Result := FDefaultProvider
    else
    begin    
      for I := 0 to FProviders.Count - 1 do
      begin
        if (TElCustomCryptoProvider(FProviders[I]).Enabled) and (TElCustomCryptoProvider(FProviders[I]).IsOperationSupported(Operation,
          Algorithm, Mode, Key, Params)) then
        begin
          Result := TElCustomCryptoProvider(FProviders[I]);
          Break;
        end;
      end;
    end;
  finally
    FLock.Done;
  end;
  if Result = nil then
    raise EElCryptoProviderManagerError.CreateFmt(SNoSuitableProviderInt, [Operation, Algorithm, Mode]);
end;

function TElCustomCryptoProviderManager.{$ifndef BUILDER_USED}GetSuitableProvider {$else}GetSuitableProvider2 {$endif}(Operation : integer; const AlgOID, AlgParams : ByteArray;
  Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters): TElCustomCryptoProvider;
var
  I : integer;
begin
  Result := nil;
  FLock.WaitToRead;
  try
    if FDefaultProvider.IsOperationSupported(Operation, AlgOID, AlgParams, Mode, Key, Params) then
      Result := FDefaultProvider
    else
    begin
      for I := 0 to FProviders.Count - 1 do
      begin
        if (TElCustomCryptoProvider(FProviders[I]).Enabled) and TElCustomCryptoProvider(FProviders[I]).IsOperationSupported(Operation,
          AlgOID, AlgParams, Mode, Key, Params) then
        begin
          Result := TElCustomCryptoProvider(FProviders[I]);
          Break;
        end;
      end;
    end;
  finally
    FLock.Done;
  end;
  if Result = nil then
    raise EElCryptoProviderManagerError.CreateFmt(SNoSuitableProviderStr, [Operation, OIDToStr(AlgOID), BinaryToString(AlgParams), Mode]);
end;

function TElCustomCryptoProviderManager.{$ifndef BUILDER_USED}GetSuitableProvider {$else}GetSuitableProvider3 {$endif}(Algorithm : integer; Mode : integer) : TElCustomCryptoProvider;
var
  I : integer;
begin
  Result := nil;
  FLock.WaitToRead;
  try
    if FDefaultProvider.IsAlgorithmSupported(Algorithm, Mode) then
      Result := FDefaultProvider
    else
    begin
      for I := 0 to FProviders.Count - 1 do
      begin
        if (TElCustomCryptoProvider(FProviders[I]).Enabled) and (TElCustomCryptoProvider(FProviders[I]).IsAlgorithmSupported(Algorithm, Mode)) then
        begin
          Result := TElCustomCryptoProvider(FProviders[I]);
          Break;
        end;
      end;
    end;
  finally
    FLock.Done;
  end;
  if Result = nil then
    raise EElCryptoProviderManagerError.CreateFmt(SNoSuitableProviderInt, [SB_OPTYPE_NONE, Algorithm, Mode]);
end;

function TElCustomCryptoProviderManager.{$ifndef BUILDER_USED}GetSuitableProvider {$else}GetSuitableProvider4 {$endif}(const AlgOID, AlgParams : ByteArray; Mode : integer) : TElCustomCryptoProvider;
var
  I : integer;
begin
  Result := nil;
  FLock.WaitToRead;
  try
    if FDefaultProvider.IsAlgorithmSupported(AlgOID, AlgParams, Mode) then
      Result := FDefaultProvider
    else
    begin
      for I := 0 to FProviders.Count - 1 do
      begin
        if (TElCustomCryptoProvider(FProviders[I]).Enabled) and TElCustomCryptoProvider(FProviders[I]).IsAlgorithmSupported(AlgOID, AlgParams, Mode) then
        begin
          Result := TElCustomCryptoProvider(FProviders[I]);
          Break;
        end;
      end;
    end;
  finally
    FLock.Done;
  end;
  if Result = nil then
    raise EElCryptoProviderManagerError.CreateFmt(SNoSuitableProviderStr, [SB_OPTYPE_NONE, OIDToStr(AlgOID), BinaryToString(AlgParams), Mode]);
end;

function TElCustomCryptoProviderManager.IsOperationSupported(Operation : integer; Algorithm : integer;
  Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters): boolean;
var
  I : integer;
begin
  Result := false;
  FLock.WaitToRead;
  try
    for I := 0 to FProviders.Count - 1 do
    begin
      if (TElCustomCryptoProvider(FProviders[I]).Enabled) and TElCustomCryptoProvider(FProviders[I]).IsOperationSupported(Operation,
        Algorithm, Mode, Key, Params) then
      begin
        Result := true;
        Break;
      end;
    end;
  finally
    FLock.Done;
  end;
end;

function TElCustomCryptoProviderManager.IsOperationSupported(Operation : integer; const AlgOID, AlgParams : ByteArray;
  Mode : integer; Key : TElCustomCryptoKey; Params : TElCPParameters): boolean;
var
  I : integer;
begin
  Result := false;
  FLock.WaitToRead;
  try
    for I := 0 to FProviders.Count - 1 do
    begin
      if (TElCustomCryptoProvider(FProviders[I]).Enabled) and TElCustomCryptoProvider(FProviders[I]).IsOperationSupported(Operation,
        AlgOID, AlgParams, Mode, Key, Params) then
      begin
        Result := true;
        Break;
      end;
    end;
  finally
    FLock.Done;
  end;
end;

function TElCustomCryptoProviderManager.IsAlgorithmSupported(Algorithm : integer; Mode : integer): boolean;
var
  I : integer;
begin
  Result := false;
  FLock.WaitToRead;
  try
    for I := 0 to FProviders.Count - 1 do
    begin
      if (TElCustomCryptoProvider(FProviders[I]).Enabled) and TElCustomCryptoProvider(FProviders[I]).IsAlgorithmSupported(Algorithm, Mode) then
      begin
        Result := true;
        Break;
      end;
    end;
  finally
    FLock.Done;
  end;
end;

function TElCustomCryptoProviderManager.IsAlgorithmSupported(const AlgOID, AlgParams : ByteArray; Mode : integer): boolean;
var
  I : integer;
begin
  Result := false;
  FLock.WaitToRead;
  try
    for I := 0 to FProviders.Count - 1 do
    begin
      if (TElCustomCryptoProvider(FProviders[I]).Enabled) and TElCustomCryptoProvider(FProviders[I]).IsAlgorithmSupported(AlgOID, AlgParams, Mode) then
      begin
        Result := true;
        Break;
      end;
    end;
  finally
    FLock.Done;
  end;
end;

function TElCustomCryptoProviderManager.IsProviderAllowed(Prov : TElCustomCryptoProvider): boolean;
begin
  Result := true;
end;

function TElCustomCryptoProviderManager.GetAlgorithmProperty(Algorithm : integer; Mode : integer;
  const PropID : ByteArray): ByteArray;
var
  I : integer;
begin
  Result := EmptyArray;
  FLock.WaitToRead;
  try
    for I := 0 to FProviders.Count - 1 do
    begin
      if (TElCustomCryptoProvider(FProviders[I]).Enabled) and TElCustomCryptoProvider(FProviders[I]).IsAlgorithmSupported(Algorithm, Mode) then
      begin
        Result := TElCustomCryptoProvider(FProviders[I]).GetAlgorithmProperty(Algorithm, Mode, PropID);
        Break;
      end;
    end;
  finally
    FLock.Done;
  end;
end;

function TElCustomCryptoProviderManager.GetAlgorithmProperty(const AlgOID, AlgParams : ByteArray;
  Mode : integer; const PropID : ByteArray): ByteArray;
var
  I : integer;
begin
  Result := EmptyArray;
  FLock.WaitToRead;
  try
    for I := 0 to FProviders.Count - 1 do
    begin
      if (TElCustomCryptoProvider(FProviders[I]).Enabled) and TElCustomCryptoProvider(FProviders[I]).IsAlgorithmSupported(AlgOID, AlgParams, Mode) then
      begin
        Result := TElCustomCryptoProvider(FProviders[I]).GetAlgorithmProperty(AlgOID, AlgParams, Mode, PropID);
        Break;
      end;
    end;
  finally
    FLock.Done;
  end;
end;

function TElCustomCryptoProviderManager.GetAlgorithmClass(Algorithm : integer): integer;
var
  I : integer;
begin
  Result := SB_ALGCLASS_NONE;
  FLock.WaitToRead;
  try
    for I := 0 to FProviders.Count - 1 do
    begin
      if (TElCustomCryptoProvider(FProviders[I]).Enabled) and TElCustomCryptoProvider(FProviders[I]).IsAlgorithmSupported(Algorithm, 0) then
      begin
        Result := TElCustomCryptoProvider(FProviders[I]).GetAlgorithmClass(Algorithm);
        Break;
      end;
    end;
  finally
    FLock.Done;
  end;
end;

function TElCustomCryptoProviderManager.GetAlgorithmClass(const AlgOID, AlgParams : ByteArray): integer;
var
  I : integer;
begin
  Result := SB_ALGCLASS_NONE;
  FLock.WaitToRead;
  try
    for I := 0 to FProviders.Count - 1 do
    begin
      if (TElCustomCryptoProvider(FProviders[I]).Enabled) and TElCustomCryptoProvider(FProviders[I]).IsAlgorithmSupported(AlgOID, AlgParams, 0) then
      begin
        Result := TElCustomCryptoProvider(FProviders[I]).GetAlgorithmClass(AlgOID, AlgParams);
        Break;
      end;
    end;
  finally
    FLock.Done;
  end;
end;

function TElCustomCryptoProviderManager.GetDefaultCryptoProvider : TElCustomCryptoProvider;
begin
  FLock.WaitToRead;
  try
    Result := FDefaultProvider;
  finally
    FLock.Done;
  end;
end;

function TElCustomCryptoProviderManager.GetCryptoProvider(Index: integer): TElCustomCryptoProvider;
begin
  FLock.WaitToRead;
  try
    Result := TElCustomCryptoProvider(FProviders[Index]);
  finally
    FLock.Done;
  end;
end;

function TElCustomCryptoProviderManager.GetCount : integer;
begin
  FLock.WaitToRead;
  try
    Result := FProviders.Count;
  finally
    FLock.Done;
  end;
end;

{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
initialization

  {$ifndef SB_NO_PKCS11}
  {$ifndef SB_STATIC_PKCS11}
  SB_PROVPROP_DLL_PATH := BytesOfString('dll-path@eldos.com');
   {$else}
  SB_PROVPROP_FUNC_MNG := BytesOfString('functions-manager@eldos.com');
   {$endif}


  // PKCS11 session handle
  // Possible values:
  // (PKCS11 crypto provider) session handle (UINT32)
  SB_PROVPROP_SESSION_HANDLE := BytesOfString('session-handle@eldos.com');
   {$endif}

  {$ifdef SB_HAS_CRYPTUI}
  // Win32 CSP parent window handle
  SB_PROVPROP_WINDOW_HANDLE := BytesOfString('window-handle@eldos.com');
   {$endif}

  //////////////////////////////////////////////
  // Key properties

  
  // Key format
  // Possible values:
  // (RSA keys) 'pkcs#1', 'oaep', 'pss'
  SB_KEYPROP_KEYFORMAT := BytesOfString('key-format@eldos.com');

  // Hash algorithm
  // Possible values:
  // (RSA-PSS, RSA-OAEP, DSA keys) the OID of the hash algorithm (ASN.1-encoded notation, e.g. 2a 86 48 86 ...)
  SB_KEYPROP_HASH_ALGORITHM := BytesOfString('hash-algorithm@eldos.com');

  // Mask generation function algorithm
  // Possible values:
  // (RSA-PSS) the OID of the mask generation function algorithm (ASN.1-encoded notation, e.g. 2a 86 48 86 ...)
  SB_KEYPROP_MGF_ALGORITHM := BytesOfString('mgf-algorithm@eldos.com');

  // Trailer field
  // Possible values:
  // (RSA-PSS keys) the big-endian encoding of the integer value (4 bytes)
  SB_KEYPROP_TRAILER_FIELD := BytesOfString('trailer-field@eldos.com');

  // Salt size
  // Possible values:
  // (RSA-PSS keys) the big-endian encoding of the integer value (4 bytes)
  SB_KEYPROP_SALT_SIZE := BytesOfString('salt-size@eldos.com');

  // String label
  // Possible values:
  // (RSA-OAEP keys) StrLabel value
  SB_KEYPROP_STRLABEL := BytesOfString('strlabel@eldos.com');

  // RSA modulus
  // Possible values:
  // (RSA keys) big-endian public modulus value
  SB_KEYPROP_RSA_M := BytesOfString('rsa-m@eldos.com');

  // RSA public exponent
  // Possible values:
  // (RSA keys) big-endian public exponent value
  SB_KEYPROP_RSA_E := BytesOfString('rsa-e@eldos.com');

  // RSA private exponent
  // Possible values:
  // (RSA keys) big-endian private exponent value
  SB_KEYPROP_RSA_D := BytesOfString('rsa-d@eldos.com');

  // DSA strict validation flag
  // Possible values:
  // (DSA keys) one-byte boolean value (0x01/0x00)
  SB_KEYPROP_DSA_STRICT_VALIDATION := BytesOfString('dsa-strict@eldos.com');

  // RSA raw key material flag
  // Possible values:
  // (RSA keys) one-byte boolean value (0x01/0x00)
  SB_KEYPROP_RSA_RAWKEY := BytesOfString('rsa-raw-key@eldos.com');

  // DSA prime
  // Possible values:
  // (DSA keys) big-endian prime value
  SB_KEYPROP_DSA_P := BytesOfString('dsa-p@eldos.com');

  // DSA q value
  // Possible values:
  // (DSA keys) big-endian q value
  SB_KEYPROP_DSA_Q := BytesOfString('dsa-q@eldos.com');

  // DSA generator
  // Possible values:
  // (DSA keys) big-endian generator value
  SB_KEYPROP_DSA_G := BytesOfString('dsa-g@eldos.com');

  // DSA secret value
  // Possible values:
  // (DSA keys) big-endian secret value
  SB_KEYPROP_DSA_X := BytesOfString('dsa-x@eldos.com');

  // DSA public value
  // Possible values:
  // (DSA keys) big-endian public value
  SB_KEYPROP_DSA_Y := BytesOfString('dsa-y@eldos.com');

  // DSA q size (in bits)
  // Possible values:
  // (DSA keys) big-endian encoding of integer value (4 bytes)
  SB_KEYPROP_DSA_QBITS := BytesOfString('dsa-qbits@eldos.com');

  // Elgamal prime
  // Possible values:
  // (Elgamal keys) big-endian prime value
  SB_KEYPROP_ELGAMAL_P := BytesOfString('elg-p@eldos.com');

  // Elgamal generator
  // Possible values:
  // (Elgamal keys) big-endian generator value
  SB_KEYPROP_ELGAMAL_G := BytesOfString('elg-g@eldos.com');

  // Elgamal secret value
  // Possible values:
  // (Elgamal keys) big-endian secret value
  SB_KEYPROP_ELGAMAL_X := BytesOfString('elg-x@eldos.com');

  // Elgamal public value
  // Possible values:
  // (Elgamal keys) big-endian public value
  SB_KEYPROP_ELGAMAL_Y := BytesOfString('elg-y@eldos.com');

  // DH prime
  // Possible values:
  // (DH keys) big-endian prime value
  SB_KEYPROP_DH_P := BytesOfString('dh-p@eldos.com');

  // DH generator
  // Possible values:
  // (DH keys) big-endian generator value
  SB_KEYPROP_DH_G := BytesOfString('dh-g@eldos.com');

  // DH secret value
  // Possible values:
  // (DH keys) big-endian secret value
  SB_KEYPROP_DH_X := BytesOfString('dh-x@eldos.com');

  // DH public value
  // Possible values:
  // (DH keys) big-endian public value
  SB_KEYPROP_DH_Y := BytesOfString('dh-y@eldos.com');

  // DH public value of peer
  // Possible values:
  // (DH keys) big-endian peer's public value
  SB_KEYPROP_DH_PEER_Y := BytesOfString('dh-peer-y@eldos.com');

  // Win32 CryptoAPI certificate context
  // Possible values:
  // (Win32 keys) big-endian 64 bit certificate handle value (PCCERT_CONTEXT/IntPtr)
  SB_KEYPROP_WIN32_CERTCONTEXT := BytesOfString('win32-certcontext@eldos.com');

  // Win32 CryptoAPI container name
  // Possible values:
  // (Win32 keys) [usually UUID-like] string 
  SB_KEYPROP_WIN32_CONTAINERNAME := BytesOfString('win32-containername@eldos.com');

  // Existing Win32 provider info (used to identify keys not bound to certificates) 
  // Possible values:
  // (Win32 keys) [usually UUID-like] string 
  SB_KEYPROP_WIN32_KEYPROVINFO := BytesOfString('win32-keyprovinfo@eldos.com');

  // Win32 provider key exchange PIN
  // Possible values:
  // (Win32 keys) A string of ASCII characters (as required by MSDN for PP_KEYEXCHANGE_PIN provider parameter)
  SB_KEYPROP_WIN32_KEYEXCHANGEPIN := BytesOfString('win32-keyexchangepin@eldos.com');

  // Win32 provider signature PIN
  // Possible values:
  // (Win32 keys) A string of ASCII characters (as required by MSDN for PP_SIGNATURE_PIN provider parameter)
  SB_KEYPROP_WIN32_SIGNATUREPIN := BytesOfString('win32-signaturepin@eldos.com');

  // Effective key length
  // Possible values:
  // (RC2 keys) effective length of the key in bits
  SB_KEYPROP_EFFECTIVE_KEY_LENGTH := BytesOfString('effective-key-length@eldos.com');

  // PKCS11 private key handle
  // Possible values:
  // (PKCS11 keys) big-endian encoding of integer value (4 bytes)
  SB_KEYPROP_PKCS11_KEY_HANDLE := BytesOfString('p11-key-handle@eldos.com');

  // PKCS11 session handle
  // Possible values:
  // (PKCS11 keys) big-endian encoding of integer value (4 bytes)
  SB_KEYPROP_PKCS11_SESSION_HANDLE := BytesOfString('p11-session-handle@eldos.com');

  // PKCS11 public key handle
  // Possible values:
  // (PKCS11 keys) big-endian encoding of integer value (4 bytes)
  SB_KEYPROP_PKCS11_PUBKEY_HANDLE := BytesOfString('p11-pubkey-handle@eldos.com');

  // PKCS11 persistence modifier
  // Possible values:
  // (PKCS11 keys) boolean value indicating whether the key is persistent (stored on the token)
  SB_KEYPROP_PKCS11_PERSISTENT := BytesOfString('p11-persistent@eldos.com');

  // PKCS11 key label
  // Possible value:
  // (PKCS11 keys) textual label of the key
  SB_KEYPROP_PKCS11_LABEL := BytesOfString('p11-label@eldos.com');
  
  // PKCS11 subject
  // Possible value:
  // (PKCS11 keys) textual subject of the key
  SB_KEYPROP_PKCS11_SUBJECT := BytesOfString('p11-subject@eldos.com');

  // PKCS11 id
  // Possible value:
  // (PKCS11 keys) id of the key
  SB_KEYPROP_PKCS11_ID := BytesOfString('p11-id@eldos.com');

  // PKCS11 sensitivity modifier
  // Possible value:
  // (PKCS11 keys) boolean value indicating whether the key is sensitive (non-exportable)
  SB_KEYPROP_PKCS11_SENSITIVE := BytesOfString('p11-sensitive@eldos.com');

  // PKCS11 privacy modifier
  // Possible value:
  // (PKCS11 keys) boolean value indicating whether the key is private
  SB_KEYPROP_PKCS11_PRIVATE := BytesOfString('p11-private@eldos.com');

  // PKCS11 "create public" flag
  // Possible value:
  // (PKCS11 keys) boolean value indicating whether the corresponding public key object should be created from the imported secret key
  SB_KEYPROP_PKCS11_CREATE_PUBLIC := BytesOfString('p11-create-public@eldos.com');

  // PKCS11 "add private flag"
  // Possible value:
  // (PKCS11 keys) boolean value indicating whether a "private" attribute should be included in a call to CreateObject when adding private key to the token
  SB_KEYPROP_PKCS11_ADD_PRIVATE_FLAG := BytesOfString('p11-add-private-flag@eldos.com');

  // PKCS11 "force object creation"
  // Possible value:
  // (PKCS11 keys) boolean value indicating that the object must be created on a token (be it persistent or not)
  SB_KEYPROP_PKCS11_FORCE_OBJECT_CREATION := BytesOfString('p11-force-object-creation@eldos.com');

  /////////////////////////////////
  // Elliptic Curve key properties
  //

  // Elliptic curve
  // Possible values:
  // Curve OID
  SB_KEYPROP_EC_CURVE := BytesOfString('ec-curve@eldos.com');

  // Elliptic curve
  // Possible values:
  // Curve integer constant
  SB_KEYPROP_EC_CURVE_INT := BytesOfString('ec-curve-int@eldos.com');

  // Underlying field type
  // Possible values:
  // Field type OID
  SB_KEYPROP_EC_FIELD_TYPE := BytesOfString('ec-field-type@eldos.com');

  // Underlying field type
  // Possible values:
  // Field type integer constant
  SB_KEYPROP_EC_FIELD_TYPE_INT := BytesOfString('ec-field-type-int@eldos.com');

  // Underlying field bit size
  // Possible values:
  // Field size integer constant
  SB_KEYPROP_EC_FIELD_BITS := BytesOfString('ec-field-bits@eldos.com');

  // Elliptic curve subgroup order bit size
  // Possible values:
  // Subgroup order bit size integer constant
  SB_KEYPROP_EC_SUBGROUP_BITS := BytesOfString('ec-subgroup-bits@eldos.com');

  // Predefined underlying field
  // Possible values:
  // Field OID
  SB_KEYPROP_EC_FIELD := BytesOfString('ec-field@eldos.com');

  // Predefined underlying field
  // Possible values:
  // Field integer constant
  SB_KEYPROP_EC_FIELD_INT := BytesOfString('ec-field-int@eldos.com');

  // Elliptic curve underlying field order (for Fp) or irreducible polynom.
  // Possible values:
  // (EC keys) big-endian P parameter value
  SB_KEYPROP_EC_P := BytesOfString('ec-p@eldos.com');

  // Elliptic curve underlying field F2m irreducible polynom order.
  // Possible values:
  // (EC keys) integer - irreducible polynom order
  SB_KEYPROP_EC_M := BytesOfString('ec-m@eldos.com');

  // Elliptic curve underlying field F2m irreducible polynom K1 (for trinoms & pentanoms).
  // Possible values:
  // (EC keys) integer - K1 value
  SB_KEYPROP_EC_K1 := BytesOfString('ec-k1@eldos.com');

  // Elliptic curve underlying field F2m irreducible polynom K2 (for pentanoms).
  // Possible values:
  // (EC keys) integer - K2 value
  SB_KEYPROP_EC_K2 := BytesOfString('ec-k2@eldos.com');

  // Elliptic curve underlying field F2m irreducible polynom K3 (for pentanoms).
  // Possible values:
  // (EC keys) integer - K3 value
  SB_KEYPROP_EC_K3 := BytesOfString('ec-k3@eldos.com');

  // Elliptic curve A domain parameter
  // Possible values:
  // (EC keys) big-endian A parameter value
  SB_KEYPROP_EC_A := BytesOfString('ec-a@eldos.com');

  // Elliptic curve B domain parameter
  // Possible values:
  // (EC keys) big-endian B parameter value
  SB_KEYPROP_EC_B := BytesOfString('ec-b@eldos.com');

  // Elliptic curve order
  // Possible values:
  // (EC keys) big-endian elliptic curve order
  SB_KEYPROP_EC_N := BytesOfString('ec-n@eldos.com');

  // Elliptic curve order cofactor
  // Possible values:
  // (EC keys) integer cofactor
  SB_KEYPROP_EC_H := BytesOfString('ec-h@eldos.com');

  // Seed of random generated curve
  // Possible values:
  // (EC keys) array seed
  SB_KEYPROP_EC_SEED := BytesOfString('ec-seed@eldos.com');

  // Elliptic curve base point X coordinate
  // Possible values:
  // (EC keys) big-endian elliptic curve base point X coordinate
  SB_KEYPROP_EC_X := BytesOfString('ec-x@eldos.com');

  // Elliptic curve base point Y coordinate
  // Possible values:
  // (EC keys) big-endian elliptic curve base point Y coordinate
  SB_KEYPROP_EC_Y := BytesOfString('ec-y@eldos.com');

  // Elliptic curve base point coordinates, converted to octet string according to X9.62 pt. 4.3.6.
  // Possible values:
  // (EC keys) big-endian octet string, representing base point
  SB_KEYPROP_EC_BP := BytesOfString('ec-bp@eldos.com');

  // Elliptic curve secret key value (D)
  // Possible values:
  // (EC keys) big-endian secret key value D
  SB_KEYPROP_EC_D := BytesOfString('ec-d@eldos.com');

  // Elliptic curve public key value X coordinate
  // Possible values:
  // (EC keys) big-endian elliptic curve public key value X coordinate
  SB_KEYPROP_EC_QX := BytesOfString('ec-qx@eldos.com');

  // Elliptic curve public key value Y coordinate
  // Possible values:
  // (EC keys) big-endian elliptic curve public key value Y coordinate
  SB_KEYPROP_EC_QY := BytesOfString('ec-qy@eldos.com');

  // Elliptic curve public key coordinates, converted to octet string according to X9.62 pt. 4.3.6.
  // Possible values:
  // (EC keys) big-endian octet string, representing public key value
  SB_KEYPROP_EC_Q := BytesOfString('ec-q@eldos.com');

  // Point compression usage
  SB_KEYPROP_EC_COMPRESS_POINTS := BytesOfString('ec-compress@eldos.com');

  // Hybrid form of compressed points usage
  SB_KEYPROP_EC_HYBRID_POINTS := BytesOfString('ec-hybrid@eldos.com');

  /////////////////////////////////
  //  GOST 34.10 key properties
  //
  //  t - bit length of p (512 or 1024 bits);
  SB_KEYPROP_GOST_R3410_1994_T       := BytesOfString('gost-R3410-1994_t@eldos.com');
  //  p - modulus, prime number, 2^(t-1)<p<2^t;
  SB_KEYPROP_GOST_R3410_1994_P       := BytesOfString('gost-R3410-1994_p@eldos.com');
  //  q - order of cyclic group, prime number, 2^254<q<2^256, q is a factor of p-1;
  SB_KEYPROP_GOST_R3410_1994_Q       := BytesOfString('gost-R3410-1994_q@eldos.com');
  //  a - generator, integer, 1<a<p-1, at that aq (mod p) = 1;
  SB_KEYPROP_GOST_R3410_1994_A       := BytesOfString('gost-R3410-1994_a@eldos.com');
  //  x0 - seed;
  SB_KEYPROP_GOST_R3410_1994_X0      := BytesOfString('gost-R3410-1994_x0@eldos.com');
  //  c  - used for p and q generation;
  SB_KEYPROP_GOST_R3410_1994_C       := BytesOfString('gost-R3410-1994_c@eldos.com');
  //  d  - used for a generation.
  SB_KEYPROP_GOST_R3410_1994_D       := BytesOfString('gost-R3410-1994_d@eldos.com');
  //  x  - big-endian secret value
  SB_KEYPROP_GOST_R3410_1994_X       := BytesOfString('gost-R3410-1994_x@eldos.com');
  //  y  - big-endian public value
  SB_KEYPROP_GOST_R3410_1994_Y       := BytesOfString('gost-R3410-1994_y@eldos.com');
  //  parameter set
  SB_KEYPROP_GOST_R3410_PARAMSET:= BytesOfString('gost-R3410_paramset@eldos.com');
  //  digest parameter set
  SB_KEYPROP_GOST_R3410_DIGEST_PARAMSET:= BytesOfString('gost-R3410_digest_paramset@eldos.com');
  //  encryption parameter set
  SB_KEYPROP_GOST_R3410_ENCRYPTION_PARAMSET:= BytesOfString('gost-R3410_encryption_paramset@eldos.com');

  // Key envelope (data associated with a key)
  // Possible value:
  // X.509 certificate in DER format, OpenPGP keyring etc.
  SB_KEYPROP_ENVELOPE_VALUE          := BytesOfString('envelope-value@eldos.com');

  // SecureBlackbox Key ID blob
  // Possible value:
  // Serialized key id in TElCPKeyID format
  SB_KEYPROP_SBB_KEYID_BLOB          := BytesOfString('sbb-keyid@eldos.com');

  //////////////////////////////////////////////
  // Algorithm properties

  // Digest size in bits
  // Possible values:
  // (Hash algorithms) big-endian digest size
  SB_ALGPROP_DIGEST_SIZE := BytesOfString('digest-size@eldos.com');

  // Symmetric cipher block size, bytes
  // Possible values:
  // (Symmetric algorithms) big-endian block size
  SB_ALGPROP_BLOCK_SIZE := BytesOfString('block-size@eldos.com');

  // Symmetric cipher default key size, bytes
  // Possible values:
  // (Symmetric algorithms) big-endian key size
  SB_ALGPROP_DEFAULT_KEY_SIZE := BytesOfString('default-key-size@eldos.com');

  //////////////////////////////////////////////
  // Crypto context properties

  // RC4 security hole workaround (used in SSH)
  // Possible values:
  // (RC4) big-endian offset value (SSH uses 1536)
  SB_CTXPROP_SKIP_KEYSTREAM_BYTES := BytesOfString('skip-keystream-bytes@eldos.com');

  // Enabling/disabling hash algorithm prefix for RSA keys
  // Possible values:
  // (RSA) boolean value 
  SB_CTXPROP_USE_ALGORITHM_PREFIX := BytesOfString('use-algorithm-prefix@eldos.com');

  // Hash algorithm for public key algorithm
  // Possible values:
  // (RSA) Hash algorithm oid (ASN.1-formatted object identifier)
  SB_CTXPROP_HASH_ALGORITHM := BytesOfString('hash-algorithm@eldos.com');

  // Specifies if input data is already a calculated hash value
  // Possible values:
  // (PKI) boolean value
  SB_CTXPROP_INPUT_IS_HASH := BytesOfString('input-is-hash@eldos.com');

  // Specifies the object identifier for a hash function (to be prepended to the hash to be encrypted)
  // Possible values:
  // (RSA) ASN.1-formatted object identifier
  SB_CTXPROP_HASH_FUNC_OID := BytesOfString('hash-func-oid@eldos.com');

  // Specifies algorithm scheme (~algorithm modifier) to be used for encryption/signing
  // Possible values:
  // (RSA schemes) 'pkcs#1', 'oaep', 'pss'
  SB_CTXPROP_ALGORITHM_SCHEME := BytesOfString('alg-scheme@eldos.com');

  // Specifies salt size for particular crypto operations
  // Possible values:
  // (RSA-PSS scheme): see PKCS#1 2.0 specification
  SB_CTXPROP_SALT_SIZE := BytesOfString('salt-size@eldos.com');

  // Specifies label for particular crypto operations
  // Possible values:
  // (RSA-OAEP scheme): see PKCS#1 2.0 specification
  SB_CTXPROP_STR_LABEL := BytesOfString('str-label@eldos.com');

  // Specifies trailer field for RSA-PSS scheme.
  // Possible values:
  //  see PKCS#1 2.0 specification
  SB_CTXPROP_TRAILER_FIELD := BytesOfString('trailer-field@eldos.com');

  // Specifies mask generation function for RSA-PSS scheme.
  // Possible values:
  //  see PKCS#1 2.0 specification
  SB_CTXPROP_MGF_ALGORITHM := BytesOfString('mgf-algorithm@eldos.com');

  // Specifies padding type for block encryption algorithms.
  // Possible values:
  // 'pkcs#5', ''
  SB_CTXPROP_PADDING_TYPE := BytesOfString('padding-type@eldos.com');

  // Specifies GOST R34.11-1994 hash function parameters set OID
  // Possible value:
  // SB_OID_GOST_R3411_1994_PARAM_CP, SB_OID_GOST_R3411_1994_PARAM_TEST (the last one only for testing purposes!)
  SB_CTXPROP_GOSTR3411_1994_PARAMSET := BytesOfString('gost-R3411-1994-paramset@eldos.com');

  // Specifies GOST R34.11-1994 hash function parameters
  // Possible value:
  // 128-byte array, representing underlying S-Boxes filling
  SB_CTXPROP_GOSTR3411_1994_PARAMETERS := BytesOfString('gost-R3411-1994-parameters@eldos.com');

  // Specifies GOST 28147-1989 parameters set OID
  // Possible values:
  // SB_OID_GOST_28147_1989_PARAM_CP_*
  SB_CTXPROP_GOST28147_1989_PARAMSET := BytesOfString('gost-28147-1989-paramset@eldos.com');

  // Specifies GOST 28147-1989 S-boxes
  // Possible value:
  // 128-byte array, representing S-Boxes filling
  SB_CTXPROP_GOST28147_1989_PARAMETERS := BytesOfString('gost-28147-1989-parameters@eldos.com');

  // AEAD encryption Nonce
  // Possible value:
  // 7-13 byte buffer
  SB_CTXPROP_AEAD_NONCE := BytesOfString('aead-nonce@eldos.com');

  // AEAD encryption authentication tag size
  // Possible value:
  // int 4-16
  SB_CTXPROP_AEAD_TAG_SIZE := BytesOfString('aead-tag-size@eldos.com');

  // AEAD associated data flag
  // Possible value:
  // true: input to encrypt/decrypt function is associated data (authenticated , but not encrypted)
  // false : input to encrypt/decrypt function is payload (authenticated and encrypted)
  SB_CTXPROP_AEAD_ASSOCIATED_DATA := BytesOfString('aead-associated-data@eldos.com');

  // AEAD/CCM encryption associated data size
  // Possible value:
  // 32-bit integer
  SB_CTXPROP_CCM_ASSOCIATED_DATA_SIZE := BytesOfString('ccm-a-size@eldos.com');

  // AEAD/CCM encryption payload size
  // Possible value:
  // 32-bit integer
  SB_CTXPROP_CCM_PAYLOAD_SIZE := BytesOfString('ccm-payload-size@eldos.com');

  // CTR mode IV little-endian incrementing order (used in WinZip AES crypto)
  // Possible values:
  // false - normal, big-endian mode
  // true - WinZip little-endian mode
  SB_CTXPROP_CTR_LITTLE_ENDIAN := BytesOfString('ctr-little-endian@eldos.com');

  // Plain ECDSA signature encoding (for German signatures)
  SB_CTXPROP_EC_PLAIN_ECDSA := BytesOfString('ecdsa-plain@eldos.com');
  
 {$endif}

end.
