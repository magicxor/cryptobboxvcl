(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBSSPI;

interface

uses
  SysUtils,
  {$ifdef SB_WINDOWS}
  Windows,
   {$endif}
  SBTypes,
  SBUtils;



{$ifndef SB_NO_SSPI}

{$ifdef SB_WINDOWS_OR_NET}

const

//
//  Security Package Capabilities
//

  {$EXTERNALSYM SECPKG_FLAG_INTEGRITY}
  SECPKG_FLAG_INTEGRITY               = $00000001; // Supports integrity on messages
  {$EXTERNALSYM SECPKG_FLAG_PRIVACY}
  SECPKG_FLAG_PRIVACY                 = $00000002; // Supports privacy (confidentiality)
  {$EXTERNALSYM SECPKG_FLAG_TOKEN_ONLY}
  SECPKG_FLAG_TOKEN_ONLY              = $00000004; // Only security token needed
  {$EXTERNALSYM SECPKG_FLAG_DATAGRAM}
  SECPKG_FLAG_DATAGRAM                = $00000008; // Datagram RPC support
  {$EXTERNALSYM SECPKG_FLAG_CONNECTION}
  SECPKG_FLAG_CONNECTION              = $00000010; // Connection oriented RPC support
  {$EXTERNALSYM SECPKG_FLAG_MULTI_REQUIRED}
  SECPKG_FLAG_MULTI_REQUIRED          = $00000020; // Full 3-leg required for re-auth.
  {$EXTERNALSYM SECPKG_FLAG_CLIENT_ONLY}
  SECPKG_FLAG_CLIENT_ONLY             = $00000040; // Server side functionality not available
  {$EXTERNALSYM SECPKG_FLAG_EXTENDED_ERROR}
  SECPKG_FLAG_EXTENDED_ERROR          = $00000080; // Supports extended error msgs
  {$EXTERNALSYM SECPKG_FLAG_IMPERSONATION}
  SECPKG_FLAG_IMPERSONATION           = $00000100; // Supports impersonation
  {$EXTERNALSYM SECPKG_FLAG_ACCEPT_WIN32_NAME}
  SECPKG_FLAG_ACCEPT_WIN32_NAME       = $00000200; // Accepts Win32 names
  {$EXTERNALSYM SECPKG_FLAG_STREAM}
  SECPKG_FLAG_STREAM                  = $00000400; // Supports stream semantics
  {$EXTERNALSYM SECPKG_FLAG_NEGOTIABLE}
  SECPKG_FLAG_NEGOTIABLE              = $00000800; // Can be used by the negotiate package
  {$EXTERNALSYM SECPKG_FLAG_GSS_COMPATIBLE}
  SECPKG_FLAG_GSS_COMPATIBLE          = $00001000; // GSS Compatibility Available
  {$EXTERNALSYM SECPKG_FLAG_LOGON}
  SECPKG_FLAG_LOGON                   = $00002000; // Supports common LsaLogonUser
  {$EXTERNALSYM SECPKG_FLAG_ASCII_BUFFERS}
  SECPKG_FLAG_ASCII_BUFFERS           = $00004000; // Token Buffers are in ASCII
  {$EXTERNALSYM SECPKG_FLAG_FRAGMENT}
  SECPKG_FLAG_FRAGMENT                = $00008000; // Package can fragment to fit
  {$EXTERNALSYM SECPKG_FLAG_MUTUAL_AUTH}
  SECPKG_FLAG_MUTUAL_AUTH             = $00010000; // Package can perform mutual authentication
  {$EXTERNALSYM SECPKG_FLAG_DELEGATION}
  SECPKG_FLAG_DELEGATION              = $00020000; // Package can delegate
  {$EXTERNALSYM SECPKG_FLAG_READONLY_WITH_CHECKSUM}
  SECPKG_FLAG_READONLY_WITH_CHECKSUM  = $00040000; // Package can delegate


  {$EXTERNALSYM SECPKG_ID_NONE}
  SECPKG_ID_NONE                      = $FFFF;

//
// SecBuffer
//

  {$EXTERNALSYM SECBUFFER_VERSION}
  SECBUFFER_VERSION            = 0;

  {$EXTERNALSYM SECBUFFER_EMPTY}
  SECBUFFER_EMPTY              = 0;  // Undefined, replaced by provider
  {$EXTERNALSYM SECBUFFER_DATA}
  SECBUFFER_DATA               = 1;  // Packet data
  {$EXTERNALSYM SECBUFFER_TOKEN}
  SECBUFFER_TOKEN              = 2;  // Security token
  {$EXTERNALSYM SECBUFFER_PKG_PARAMS}
  SECBUFFER_PKG_PARAMS         = 3;  // Package specific parameters
  {$EXTERNALSYM SECBUFFER_MISSING}
  SECBUFFER_MISSING            = 4;  // Missing Data indicator
  {$EXTERNALSYM SECBUFFER_EXTRA}
  SECBUFFER_EXTRA              = 5;  // Extra data
  {$EXTERNALSYM SECBUFFER_STREAM_TRAILER}
  SECBUFFER_STREAM_TRAILER     = 6;  // Security Trailer
  {$EXTERNALSYM SECBUFFER_STREAM_HEADER}
  SECBUFFER_STREAM_HEADER      = 7;  // Security Header
  {$EXTERNALSYM SECBUFFER_NEGOTIATION_INFO}
  SECBUFFER_NEGOTIATION_INFO   = 8;  // Hints from the negotiation pkg
  {$EXTERNALSYM SECBUFFER_PADDING}
  SECBUFFER_PADDING            = 9;  // non-data padding
  {$EXTERNALSYM SECBUFFER_STREAM}
  SECBUFFER_STREAM             = 10; // whole encrypted message
  {$EXTERNALSYM SECBUFFER_MECHLIST}
  SECBUFFER_MECHLIST           = 11;
  {$EXTERNALSYM SECBUFFER_MECHLIST_SIGNATURE}
  SECBUFFER_MECHLIST_SIGNATURE = 12;
  {$EXTERNALSYM SECBUFFER_TARGET}
  SECBUFFER_TARGET             = 13;
  {$EXTERNALSYM SECBUFFER_CHANNEL_BINDINGS}
  SECBUFFER_CHANNEL_BINDINGS   = 14;

  {$EXTERNALSYM SECBUFFER_ATTRMASK}
  SECBUFFER_ATTRMASK                = $F0000000;
  {$EXTERNALSYM SECBUFFER_READONLY}
  SECBUFFER_READONLY                = $80000000; // Buffer is read-only, no checksum
  {$EXTERNALSYM SECBUFFER_READONLY_WITH_CHECKSUM}
  SECBUFFER_READONLY_WITH_CHECKSUM  = $10000000; // Buffer is read-only, and checksummed
  {$EXTERNALSYM SECBUFFER_RESERVED}
  SECBUFFER_RESERVED                = $60000000; // Flags reserved to security system

//
//  Data Representation Constant:
//

  {$EXTERNALSYM SECURITY_NATIVE_DREP}
  SECURITY_NATIVE_DREP  = $00000010;
  {$EXTERNALSYM SECURITY_NETWORK_DREP}
  SECURITY_NETWORK_DREP = $00000000;

//
//  Credential Use Flags
//

  {$EXTERNALSYM SECPKG_CRED_INBOUND}
  SECPKG_CRED_INBOUND   = $00000001;
  {$EXTERNALSYM SECPKG_CRED_OUTBOUND}
  SECPKG_CRED_OUTBOUND  = $00000002;
  {$EXTERNALSYM SECPKG_CRED_BOTH}
  SECPKG_CRED_BOTH      = $00000003;
  {$EXTERNALSYM SECPKG_CRED_DEFAULT}
  SECPKG_CRED_DEFAULT   = $00000004;
  {$EXTERNALSYM SECPKG_CRED_RESERVED}
  SECPKG_CRED_RESERVED  = $F0000000;

//
//  InitializeSecurityContext Requirement and return flags:
//

  {$EXTERNALSYM ISC_REQ_DELEGATE}
  ISC_REQ_DELEGATE                = $00000001;
  {$EXTERNALSYM ISC_REQ_MUTUAL_AUTH}
  ISC_REQ_MUTUAL_AUTH             = $00000002;
  {$EXTERNALSYM ISC_REQ_REPLAY_DETECT}
  ISC_REQ_REPLAY_DETECT           = $00000004;
  {$EXTERNALSYM ISC_REQ_SEQUENCE_DETECT}
  ISC_REQ_SEQUENCE_DETECT         = $00000008;
  {$EXTERNALSYM ISC_REQ_CONFIDENTIALITY}
  ISC_REQ_CONFIDENTIALITY         = $00000010;
  {$EXTERNALSYM ISC_REQ_USE_SESSION_KEY}
  ISC_REQ_USE_SESSION_KEY         = $00000020;
  {$EXTERNALSYM ISC_REQ_PROMPT_FOR_CREDS}
  ISC_REQ_PROMPT_FOR_CREDS        = $00000040;
  {$EXTERNALSYM ISC_REQ_USE_SUPPLIED_CREDS}
  ISC_REQ_USE_SUPPLIED_CREDS      = $00000080;
  {$EXTERNALSYM ISC_REQ_ALLOCATE_MEMORY}
  ISC_REQ_ALLOCATE_MEMORY         = $00000100;
  {$EXTERNALSYM ISC_REQ_USE_DCE_STYLE}
  ISC_REQ_USE_DCE_STYLE           = $00000200;
  {$EXTERNALSYM ISC_REQ_DATAGRAM}
  ISC_REQ_DATAGRAM                = $00000400;
  {$EXTERNALSYM ISC_REQ_CONNECTION}
  ISC_REQ_CONNECTION              = $00000800;
  {$EXTERNALSYM ISC_REQ_CALL_LEVEL}
  ISC_REQ_CALL_LEVEL              = $00001000;
  {$EXTERNALSYM ISC_REQ_FRAGMENT_SUPPLIED}
  ISC_REQ_FRAGMENT_SUPPLIED       = $00002000;
  {$EXTERNALSYM ISC_REQ_EXTENDED_ERROR}
  ISC_REQ_EXTENDED_ERROR          = $00004000;
  {$EXTERNALSYM ISC_REQ_STREAM}
  ISC_REQ_STREAM                  = $00008000;
  {$EXTERNALSYM ISC_REQ_INTEGRITY}
  ISC_REQ_INTEGRITY               = $00010000;
  {$EXTERNALSYM ISC_REQ_IDENTIFY}
  ISC_REQ_IDENTIFY                = $00020000;
  {$EXTERNALSYM ISC_REQ_NULL_SESSION}
  ISC_REQ_NULL_SESSION            = $00040000;
  {$EXTERNALSYM ISC_REQ_MANUAL_CRED_VALIDATION}
  ISC_REQ_MANUAL_CRED_VALIDATION  = $00080000;
  {$EXTERNALSYM ISC_REQ_RESERVED1}
  ISC_REQ_RESERVED1               = $00100000;
  {$EXTERNALSYM ISC_REQ_FRAGMENT_TO_FIT}
  ISC_REQ_FRAGMENT_TO_FIT         = $00200000;

  {$EXTERNALSYM ISC_RET_DELEGATE}
  ISC_RET_DELEGATE                = $00000001;
  {$EXTERNALSYM ISC_RET_MUTUAL_AUTH}
  ISC_RET_MUTUAL_AUTH             = $00000002;
  {$EXTERNALSYM ISC_RET_REPLAY_DETECT}
  ISC_RET_REPLAY_DETECT           = $00000004;
  {$EXTERNALSYM ISC_RET_SEQUENCE_DETECT}
  ISC_RET_SEQUENCE_DETECT         = $00000008;
  {$EXTERNALSYM ISC_RET_CONFIDENTIALITY}
  ISC_RET_CONFIDENTIALITY         = $00000010;
  {$EXTERNALSYM ISC_RET_USE_SESSION_KEY}
  ISC_RET_USE_SESSION_KEY         = $00000020;
  {$EXTERNALSYM ISC_RET_USED_COLLECTED_CREDS}
  ISC_RET_USED_COLLECTED_CREDS    = $00000040;
  {$EXTERNALSYM ISC_RET_USED_SUPPLIED_CREDS}
  ISC_RET_USED_SUPPLIED_CREDS     = $00000080;
  {$EXTERNALSYM ISC_RET_ALLOCATED_MEMORY}
  ISC_RET_ALLOCATED_MEMORY        = $00000100;
  {$EXTERNALSYM ISC_RET_USED_DCE_STYLE}
  ISC_RET_USED_DCE_STYLE          = $00000200;
  {$EXTERNALSYM ISC_RET_DATAGRAM}
  ISC_RET_DATAGRAM                = $00000400;
  {$EXTERNALSYM ISC_RET_CONNECTION}
  ISC_RET_CONNECTION              = $00000800;
  {$EXTERNALSYM ISC_RET_INTERMEDIATE_RETURN}
  ISC_RET_INTERMEDIATE_RETURN     = $00001000;
  {$EXTERNALSYM ISC_RET_CALL_LEVEL}
  ISC_RET_CALL_LEVEL              = $00002000;
  {$EXTERNALSYM ISC_RET_EXTENDED_ERROR}
  ISC_RET_EXTENDED_ERROR          = $00004000;
  {$EXTERNALSYM ISC_RET_STREAM}
  ISC_RET_STREAM                  = $00008000;
  {$EXTERNALSYM ISC_RET_INTEGRITY}
  ISC_RET_INTEGRITY               = $00010000;
  {$EXTERNALSYM ISC_RET_IDENTIFY}
  ISC_RET_IDENTIFY                = $00020000;
  {$EXTERNALSYM ISC_RET_NULL_SESSION}
  ISC_RET_NULL_SESSION            = $00040000;
  {$EXTERNALSYM ISC_RET_MANUAL_CRED_VALIDATION}
  ISC_RET_MANUAL_CRED_VALIDATION  = $00080000;
  {$EXTERNALSYM ISC_RET_RESERVED1}
  ISC_RET_RESERVED1               = $00100000;
  {$EXTERNALSYM ISC_RET_FRAGMENT_ONLY}
  ISC_RET_FRAGMENT_ONLY           = $00200000;

  {$EXTERNALSYM ASC_REQ_DELEGATE}
  ASC_REQ_DELEGATE                = $00000001;
  {$EXTERNALSYM ASC_REQ_MUTUAL_AUTH}
  ASC_REQ_MUTUAL_AUTH             = $00000002;
  {$EXTERNALSYM ASC_REQ_REPLAY_DETECT}
  ASC_REQ_REPLAY_DETECT           = $00000004;
  {$EXTERNALSYM ASC_REQ_SEQUENCE_DETECT}
  ASC_REQ_SEQUENCE_DETECT         = $00000008;
  {$EXTERNALSYM ASC_REQ_CONFIDENTIALITY}
  ASC_REQ_CONFIDENTIALITY         = $00000010;
  {$EXTERNALSYM ASC_REQ_USE_SESSION_KEY}
  ASC_REQ_USE_SESSION_KEY         = $00000020;
  {$EXTERNALSYM ASC_REQ_ALLOCATE_MEMORY}
  ASC_REQ_ALLOCATE_MEMORY         = $00000100;
  {$EXTERNALSYM ASC_REQ_USE_DCE_STYLE}
  ASC_REQ_USE_DCE_STYLE           = $00000200;
  {$EXTERNALSYM ASC_REQ_DATAGRAM}
  ASC_REQ_DATAGRAM                = $00000400;
  {$EXTERNALSYM ASC_REQ_CONNECTION}
  ASC_REQ_CONNECTION              = $00000800;
  {$EXTERNALSYM ASC_REQ_CALL_LEVEL}
  ASC_REQ_CALL_LEVEL              = $00001000;
  {$EXTERNALSYM ASC_REQ_EXTENDED_ERROR}
  ASC_REQ_EXTENDED_ERROR          = $00008000;
  {$EXTERNALSYM ASC_REQ_STREAM}
  ASC_REQ_STREAM                  = $00010000;
  {$EXTERNALSYM ASC_REQ_INTEGRITY}
  ASC_REQ_INTEGRITY               = $00020000;
  {$EXTERNALSYM ASC_REQ_LICENSING}
  ASC_REQ_LICENSING               = $00040000;
  {$EXTERNALSYM ASC_REQ_IDENTIFY}
  ASC_REQ_IDENTIFY                = $00080000;
  {$EXTERNALSYM ASC_REQ_ALLOW_NULL_SESSION}
  ASC_REQ_ALLOW_NULL_SESSION      = $00100000;
  {$EXTERNALSYM ASC_REQ_ALLOW_NON_USER_LOGONS}
  ASC_REQ_ALLOW_NON_USER_LOGONS   = $00200000;
  {$EXTERNALSYM ASC_REQ_ALLOW_CONTEXT_REPLAY}
  ASC_REQ_ALLOW_CONTEXT_REPLAY    = $00400000;
  {$EXTERNALSYM ASC_REQ_FRAGMENT_TO_FIT}
  ASC_REQ_FRAGMENT_TO_FIT         = $00800000;
  {$EXTERNALSYM ASC_REQ_FRAGMENT_SUPPLIED}
  ASC_REQ_FRAGMENT_SUPPLIED       = $00002000;
  {$EXTERNALSYM ASC_REQ_NO_TOKEN}
  ASC_REQ_NO_TOKEN                = $01000000;

  {$EXTERNALSYM ASC_RET_DELEGATE}
  ASC_RET_DELEGATE                = $00000001;
  {$EXTERNALSYM ASC_RET_MUTUAL_AUTH}
  ASC_RET_MUTUAL_AUTH             = $00000002;
  {$EXTERNALSYM ASC_RET_REPLAY_DETECT}
  ASC_RET_REPLAY_DETECT           = $00000004;
  {$EXTERNALSYM ASC_RET_SEQUENCE_DETECT}
  ASC_RET_SEQUENCE_DETECT         = $00000008;
  {$EXTERNALSYM ASC_RET_CONFIDENTIALITY}
  ASC_RET_CONFIDENTIALITY         = $00000010;
  {$EXTERNALSYM ASC_RET_USE_SESSION_KEY}
  ASC_RET_USE_SESSION_KEY         = $00000020;
  {$EXTERNALSYM ASC_RET_ALLOCATED_MEMORY}
  ASC_RET_ALLOCATED_MEMORY        = $00000100;
  {$EXTERNALSYM ASC_RET_USED_DCE_STYLE}
  ASC_RET_USED_DCE_STYLE          = $00000200;
  {$EXTERNALSYM ASC_RET_DATAGRAM}
  ASC_RET_DATAGRAM                = $00000400;
  {$EXTERNALSYM ASC_RET_CONNECTION}
  ASC_RET_CONNECTION              = $00000800;
  {$EXTERNALSYM ASC_RET_CALL_LEVEL}
  ASC_RET_CALL_LEVEL              = $00002000; // skipped 1000 to be like ISC_
  {$EXTERNALSYM ASC_RET_THIRD_LEG_FAILED}
  ASC_RET_THIRD_LEG_FAILED        = $00004000;
  {$EXTERNALSYM ASC_RET_EXTENDED_ERROR}
  ASC_RET_EXTENDED_ERROR          = $00008000;
  {$EXTERNALSYM ASC_RET_STREAM}
  ASC_RET_STREAM                  = $00010000;
  {$EXTERNALSYM ASC_RET_INTEGRITY}
  ASC_RET_INTEGRITY               = $00020000;
  {$EXTERNALSYM ASC_RET_LICENSING}
  ASC_RET_LICENSING               = $00040000;
  {$EXTERNALSYM ASC_RET_IDENTIFY}
  ASC_RET_IDENTIFY                = $00080000;
  {$EXTERNALSYM ASC_RET_NULL_SESSION}
  ASC_RET_NULL_SESSION            = $00100000;
  {$EXTERNALSYM ASC_RET_ALLOW_NON_USER_LOGONS}
  ASC_RET_ALLOW_NON_USER_LOGONS   = $00200000;
  {$EXTERNALSYM ASC_RET_ALLOW_CONTEXT_REPLAY}
  ASC_RET_ALLOW_CONTEXT_REPLAY    = $00400000;
  {$EXTERNALSYM ASC_RET_FRAGMENT_ONLY}
  ASC_RET_FRAGMENT_ONLY           = $00800000;
  {$EXTERNALSYM ASC_RET_NO_TOKEN}
  ASC_RET_NO_TOKEN                = $01000000;

//
//  Security Credentials Attributes:
//

  {$EXTERNALSYM SECPKG_CRED_ATTR_NAMES}
  SECPKG_CRED_ATTR_NAMES        = 1;
  {$EXTERNALSYM SECPKG_CRED_ATTR_SSI_PROVIDER}
  SECPKG_CRED_ATTR_SSI_PROVIDER = 2;

//
//  Security Context Attributes:
//

  {$EXTERNALSYM SECPKG_ATTR_SIZES}
  SECPKG_ATTR_SIZES               = 0;
  {$EXTERNALSYM SECPKG_ATTR_NAMES}
  SECPKG_ATTR_NAMES               = 1;
  {$EXTERNALSYM SECPKG_ATTR_LIFESPAN}
  SECPKG_ATTR_LIFESPAN            = 2;
  {$EXTERNALSYM SECPKG_ATTR_DCE_INFO}
  SECPKG_ATTR_DCE_INFO            = 3;
  {$EXTERNALSYM SECPKG_ATTR_STREAM_SIZES}
  SECPKG_ATTR_STREAM_SIZES        = 4;
  {$EXTERNALSYM SECPKG_ATTR_KEY_INFO}
  SECPKG_ATTR_KEY_INFO            = 5;
  {$EXTERNALSYM SECPKG_ATTR_AUTHORITY}
  SECPKG_ATTR_AUTHORITY           = 6;
  {$EXTERNALSYM SECPKG_ATTR_PROTO_INFO}
  SECPKG_ATTR_PROTO_INFO          = 7;
  {$EXTERNALSYM SECPKG_ATTR_PASSWORD_EXPIRY}
  SECPKG_ATTR_PASSWORD_EXPIRY     = 8;
  {$EXTERNALSYM SECPKG_ATTR_SESSION_KEY}
  SECPKG_ATTR_SESSION_KEY         = 9;
  {$EXTERNALSYM SECPKG_ATTR_PACKAGE_INFO}
  SECPKG_ATTR_PACKAGE_INFO        = 10;
  {$EXTERNALSYM SECPKG_ATTR_USER_FLAGS}
  SECPKG_ATTR_USER_FLAGS          = 11;
  {$EXTERNALSYM SECPKG_ATTR_NEGOTIATION_INFO}
  SECPKG_ATTR_NEGOTIATION_INFO    = 12;
  {$EXTERNALSYM SECPKG_ATTR_NATIVE_NAMES}
  SECPKG_ATTR_NATIVE_NAMES        = 13;
  {$EXTERNALSYM SECPKG_ATTR_FLAGS}
  SECPKG_ATTR_FLAGS               = 14;
  {$EXTERNALSYM SECPKG_ATTR_USE_VALIDATED}
  SECPKG_ATTR_USE_VALIDATED       = 15;
  {$EXTERNALSYM SECPKG_ATTR_CREDENTIAL_NAME}
  SECPKG_ATTR_CREDENTIAL_NAME     = 16;
  {$EXTERNALSYM SECPKG_ATTR_TARGET_INFORMATION}
  SECPKG_ATTR_TARGET_INFORMATION  = 17;
  {$EXTERNALSYM SECPKG_ATTR_ACCESS_TOKEN}
  SECPKG_ATTR_ACCESS_TOKEN        = 18;
  {$EXTERNALSYM SECPKG_ATTR_TARGET}
  SECPKG_ATTR_TARGET              = 19;
  {$EXTERNALSYM SECPKG_ATTR_AUTHENTICATION_ID}
  SECPKG_ATTR_AUTHENTICATION_ID   = 20;
  {$EXTERNALSYM SECPKG_ATTR_LOGOFF_TIME}
  SECPKG_ATTR_LOGOFF_TIME         = 21;


  {$EXTERNALSYM SECPKG_NEGOTIATION_COMPLETE}
  SECPKG_NEGOTIATION_COMPLETE       = 0;
  {$EXTERNALSYM SECPKG_NEGOTIATION_OPTIMISTIC}
  SECPKG_NEGOTIATION_OPTIMISTIC     = 1;
  {$EXTERNALSYM SECPKG_NEGOTIATION_IN_PROGRESS}
  SECPKG_NEGOTIATION_IN_PROGRESS    = 2;
  {$EXTERNALSYM SECPKG_NEGOTIATION_DIRECT}
  SECPKG_NEGOTIATION_DIRECT         = 3;
  {$EXTERNALSYM SECPKG_NEGOTIATION_TRY_MULTICRED}
  SECPKG_NEGOTIATION_TRY_MULTICRED  = 4;

//
// Flags for ExportSecurityContext
//

  {$EXTERNALSYM SECPKG_CONTEXT_EXPORT_RESET_NEW}
  SECPKG_CONTEXT_EXPORT_RESET_NEW   = $00000001; // New context is reset to initial state
  {$EXTERNALSYM SECPKG_CONTEXT_EXPORT_DELETE_OLD}
  SECPKG_CONTEXT_EXPORT_DELETE_OLD  = $00000002; // Old context is deleted during export
  {$EXTERNALSYM SECPKG_CONTEXT_EXPORT_TO_KERNEL}
  SECPKG_CONTEXT_EXPORT_TO_KERNEL   = $00000004; // Context is to be transferred to the kernel


  {$EXTERNALSYM SECQOP_WRAP_NO_ENCRYPT}
  SECQOP_WRAP_NO_ENCRYPT = $80000001;
  {$EXTERNALSYM SECQOP_WRAP_OOB_DATA}
  SECQOP_WRAP_OOB_DATA   = $40000000;

  SECURITY_ENTRYPOINT_ANSIW  = 'InitSecurityInterfaceW'; {Do not Localize}
  SECURITY_ENTRYPOINT_ANSIA  = 'InitSecurityInterfaceA'; {Do not Localize}
  SECURITY_ENTRYPOINTW       = 'InitSecurityInterfaceW'; {Do not Localize}
  SECURITY_ENTRYPOINTA       = 'InitSecurityInterfaceA'; {Do not Localize}
  SECURITY_ENTRYPOINT16      = 'INITSECURITYINTERFACEA'; {Do not Localize}

  // Function table has all routines through DecryptMessage
  {$EXTERNALSYM SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION}
  SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION   = 1;

  // Function table has all routines through SetContextAttributes
  {$EXTERNALSYM SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION_2}
  SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION_2 = 2;

  // Function table has all routines through SetCredentialsAttributes
  {$EXTERNALSYM SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION_3}
  SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION_3 = 3;


  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_ANSI}
  SEC_WINNT_AUTH_IDENTITY_ANSI    = 1;
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_UNICODE}
  SEC_WINNT_AUTH_IDENTITY_UNICODE = 2;

  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_VERSION}
  SEC_WINNT_AUTH_IDENTITY_VERSION = $200;

  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_MARSHALLED}
  SEC_WINNT_AUTH_IDENTITY_MARSHALLED = 4; // all data is in one buffer
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_ONLY}
  SEC_WINNT_AUTH_IDENTITY_ONLY       = 8; // these credentials are for identity only - no PAC needed

  {$EXTERNALSYM SEC_E_OK}
  SEC_E_OK                            = 0;
  {$EXTERNALSYM SEC_E_INSUFFICIENT_MEMORY}
  SEC_E_INSUFFICIENT_MEMORY           = HRESULT($80090300);
  {$EXTERNALSYM SEC_E_INVALID_HANDLE}
  SEC_E_INVALID_HANDLE                = HRESULT($80090301);
  {$EXTERNALSYM SEC_E_UNSUPPORTED_FUNCTION}
  SEC_E_UNSUPPORTED_FUNCTION          = HRESULT($80090302);
  {$EXTERNALSYM SEC_E_TARGET_UNKNOWN}
  SEC_E_TARGET_UNKNOWN                = HRESULT($80090303);
  {$EXTERNALSYM SEC_E_INTERNAL_ERROR}
  SEC_E_INTERNAL_ERROR                = HRESULT($80090304);
  {$EXTERNALSYM SEC_E_SECPKG_NOT_FOUND}
  SEC_E_SECPKG_NOT_FOUND              = HRESULT($80090305);
  {$EXTERNALSYM SEC_E_NOT_OWNER}
  SEC_E_NOT_OWNER                     = HRESULT($80090306);
  {$EXTERNALSYM SEC_E_CANNOT_INSTALL}
  SEC_E_CANNOT_INSTALL                = HRESULT($80090307);
  {$EXTERNALSYM SEC_E_INVALID_TOKEN}
  SEC_E_INVALID_TOKEN                 = HRESULT($80090308);
  {$EXTERNALSYM SEC_E_CANNOT_PACK}
  SEC_E_CANNOT_PACK                   = HRESULT($80090309);
  {$EXTERNALSYM SEC_E_QOP_NOT_SUPPORTED}
  SEC_E_QOP_NOT_SUPPORTED             = HRESULT($8009030A);
  {$EXTERNALSYM SEC_E_NO_IMPERSONATION}
  SEC_E_NO_IMPERSONATION              = HRESULT($8009030B);
  {$EXTERNALSYM SEC_E_LOGON_DENIED}
  SEC_E_LOGON_DENIED                  = HRESULT($8009030C);
  {$EXTERNALSYM SEC_E_UNKNOWN_CREDENTIALS}
  SEC_E_UNKNOWN_CREDENTIALS           = HRESULT($8009030D);
  {$EXTERNALSYM SEC_E_NO_CREDENTIALS}
  SEC_E_NO_CREDENTIALS                = HRESULT($8009030E);
  {$EXTERNALSYM SEC_E_MESSAGE_ALTERED}
  SEC_E_MESSAGE_ALTERED               = HRESULT($8009030F);
  {$EXTERNALSYM SEC_E_OUT_OF_SEQUENCE}
  SEC_E_OUT_OF_SEQUENCE               = HRESULT($80090310);
  {$EXTERNALSYM SEC_E_NO_AUTHENTICATING_AUTHORITY}
  SEC_E_NO_AUTHENTICATING_AUTHORITY   = HRESULT($80090311);
  {$EXTERNALSYM SEC_I_CONTINUE_NEEDED}
  SEC_I_CONTINUE_NEEDED               = HRESULT($00090312);
  {$EXTERNALSYM SEC_I_COMPLETE_NEEDED}
  SEC_I_COMPLETE_NEEDED               = HRESULT($00090313);
  {$EXTERNALSYM SEC_I_COMPLETE_AND_CONTINUE}
  SEC_I_COMPLETE_AND_CONTINUE         = HRESULT($00090314);
  {$EXTERNALSYM SEC_I_LOCAL_LOGON}
  SEC_I_LOCAL_LOGON                   = HRESULT($00090315);
  {$EXTERNALSYM SEC_E_BAD_PKGID}
  SEC_E_BAD_PKGID                     = HRESULT($80090316);
  {$EXTERNALSYM SEC_E_CONTEXT_EXPIRED}
  SEC_E_CONTEXT_EXPIRED               = HRESULT($80090317);
  {$EXTERNALSYM SEC_E_INCOMPLETE_MESSAGE}
  SEC_E_INCOMPLETE_MESSAGE            = HRESULT($80090318);
  {$EXTERNALSYM SEC_E_INCOMPLETE_CREDENTIALS}
  SEC_E_INCOMPLETE_CREDENTIALS        = HRESULT($80090320);
  {$EXTERNALSYM SEC_E_BUFFER_TOO_SMALL}
  SEC_E_BUFFER_TOO_SMALL              = HRESULT($80090321);
  {$EXTERNALSYM SEC_I_INCOMPLETE_CREDENTIALS}
  SEC_I_INCOMPLETE_CREDENTIALS        = HRESULT($00090320);
  {$EXTERNALSYM SEC_I_RENEGOTIATE}
  SEC_I_RENEGOTIATE                   = HRESULT($00090321);
  {$EXTERNALSYM SEC_E_WRONG_PRINCIPAL}
  SEC_E_WRONG_PRINCIPAL               = HRESULT($80090322);
  {$EXTERNALSYM SEC_I_NO_LSA_CONTEXT}
  SEC_I_NO_LSA_CONTEXT                = HRESULT($00090323);
  {$EXTERNALSYM SEC_E_TIME_SKEW}
  SEC_E_TIME_SKEW                     = HRESULT($80090324);
  {$EXTERNALSYM SEC_E_UNTRUSTED_ROOT}
  SEC_E_UNTRUSTED_ROOT                = HRESULT($80090325);
  {$EXTERNALSYM SEC_E_ILLEGAL_MESSAGE}
  SEC_E_ILLEGAL_MESSAGE               = HRESULT($80090326);
  {$EXTERNALSYM SEC_E_CERT_UNKNOWN}
  SEC_E_CERT_UNKNOWN                  = HRESULT($80090327);
  {$EXTERNALSYM SEC_E_CERT_EXPIRED}
  SEC_E_CERT_EXPIRED                  = HRESULT($80090328);
  {$EXTERNALSYM SEC_E_ENCRYPT_FAILURE}
  SEC_E_ENCRYPT_FAILURE               = HRESULT($80090329);
  {$EXTERNALSYM SEC_E_DECRYPT_FAILURE}
  SEC_E_DECRYPT_FAILURE               = HRESULT($80090330);
  {$EXTERNALSYM SEC_E_ALGORITHM_MISMATCH}
  SEC_E_ALGORITHM_MISMATCH            = HRESULT($80090331);
  {$EXTERNALSYM SEC_E_SECURITY_QOS_FAILED}
  SEC_E_SECURITY_QOS_FAILED           = HRESULT($80090332);
  {$EXTERNALSYM SEC_E_UNFINISHED_CONTEXT_DELETED}
  SEC_E_UNFINISHED_CONTEXT_DELETED    = HRESULT($80090333);
  {$EXTERNALSYM SEC_E_NO_TGT_REPLY}
  SEC_E_NO_TGT_REPLY                  = HRESULT($80090334);
  {$EXTERNALSYM SEC_E_NO_IP_ADDRESSES}
  SEC_E_NO_IP_ADDRESSES               = HRESULT($80090335);
  {$EXTERNALSYM SEC_E_WRONG_CREDENTIAL_HANDLE}
  SEC_E_WRONG_CREDENTIAL_HANDLE       = HRESULT($80090336);
  {$EXTERNALSYM SEC_E_CRYPTO_SYSTEM_INVALID}
  SEC_E_CRYPTO_SYSTEM_INVALID         = HRESULT($80090337);
  {$EXTERNALSYM SEC_E_MAX_REFERRALS_EXCEEDED}
  SEC_E_MAX_REFERRALS_EXCEEDED        = HRESULT($80090338);
  {$EXTERNALSYM SEC_E_MUST_BE_KDC}
  SEC_E_MUST_BE_KDC                   = HRESULT($80090339);
  {$EXTERNALSYM SEC_E_STRONG_CRYPTO_NOT_SUPPORTED}
  SEC_E_STRONG_CRYPTO_NOT_SUPPORTED   = HRESULT($8009033A);
  {$EXTERNALSYM SEC_E_TOO_MANY_PRINCIPALS}
  SEC_E_TOO_MANY_PRINCIPALS           = HRESULT($8009033B);
  {$EXTERNALSYM SEC_E_NO_PA_DATA}
  SEC_E_NO_PA_DATA                    = HRESULT($8009033C);
  {$EXTERNALSYM SEC_E_PKINIT_NAME_MISMATCH}
  SEC_E_PKINIT_NAME_MISMATCH          = HRESULT($8009033D);
  {$EXTERNALSYM SEC_E_SMARTCARD_LOGON_REQUIRED}
  SEC_E_SMARTCARD_LOGON_REQUIRED      = HRESULT($8009033E);
  {$EXTERNALSYM SEC_E_SHUTDOWN_IN_PROGRESS}
  SEC_E_SHUTDOWN_IN_PROGRESS          = HRESULT($8009033F);
  {$EXTERNALSYM SEC_E_KDC_INVALID_REQUEST}
  SEC_E_KDC_INVALID_REQUEST           = HRESULT($80090340);
  {$EXTERNALSYM SEC_E_KDC_UNABLE_TO_REFER}
  SEC_E_KDC_UNABLE_TO_REFER           = HRESULT($80090341);
  {$EXTERNALSYM SEC_E_KDC_UNKNOWN_ETYPE}
  SEC_E_KDC_UNKNOWN_ETYPE             = HRESULT($80090342);
  {$EXTERNALSYM SEC_E_UNSUPPORTED_PREAUTH}
  SEC_E_UNSUPPORTED_PREAUTH           = HRESULT($80090343);
  {$EXTERNALSYM SEC_E_DELEGATION_REQUIRED}
  SEC_E_DELEGATION_REQUIRED           = HRESULT($80090345);
  {$EXTERNALSYM SEC_E_BAD_BINDINGS}
  SEC_E_BAD_BINDINGS                  = HRESULT($80090346);
  {$EXTERNALSYM SEC_E_MULTIPLE_ACCOUNTS}
  SEC_E_MULTIPLE_ACCOUNTS             = HRESULT($80090347);
  {$EXTERNALSYM SEC_E_NO_KERB_KEY}
  SEC_E_NO_KERB_KEY                   = HRESULT($80090348);
  {$EXTERNALSYM SEC_E_CERT_WRONG_USAGE}
  SEC_E_CERT_WRONG_USAGE              = HRESULT($80090349);
  {$EXTERNALSYM SEC_E_DOWNGRADE_DETECTED}
  SEC_E_DOWNGRADE_DETECTED            = HRESULT($80090350);
  {$EXTERNALSYM SEC_E_SMARTCARD_CERT_REVOKED}
  SEC_E_SMARTCARD_CERT_REVOKED        = HRESULT($80090351);
  {$EXTERNALSYM SEC_E_ISSUING_CA_UNTRUSTED}
  SEC_E_ISSUING_CA_UNTRUSTED          = HRESULT($80090352);
  {$EXTERNALSYM SEC_E_REVOCATION_OFFLINE_C}
  SEC_E_REVOCATION_OFFLINE_C          = HRESULT($80090353);
  {$EXTERNALSYM SEC_E_PKINIT_CLIENT_FAILURE}
  SEC_E_PKINIT_CLIENT_FAILURE         = HRESULT($80090354);
  {$EXTERNALSYM SEC_E_SMARTCARD_CERT_EXPIRED}
  SEC_E_SMARTCARD_CERT_EXPIRED        = HRESULT($80090355);
  {$EXTERNALSYM SEC_E_NO_S4U_PROT_SUPPORT}
  SEC_E_NO_S4U_PROT_SUPPORT           = HRESULT($80090356);
  {$EXTERNALSYM SEC_E_CROSSREALM_DELEGATION_FAILURE}
  SEC_E_CROSSREALM_DELEGATION_FAILURE = HRESULT($80090357);
  {$EXTERNALSYM SEC_E_REVOCATION_OFFLINE_KDC}
  SEC_E_REVOCATION_OFFLINE_KDC        = HRESULT($80090358);
  {$EXTERNALSYM SEC_E_ISSUING_CA_UNTRUSTED_KDC}
  SEC_E_ISSUING_CA_UNTRUSTED_KDC      = HRESULT($80090359);
  {$EXTERNALSYM SEC_E_KDC_CERT_EXPIRED}
  SEC_E_KDC_CERT_EXPIRED              = HRESULT($8009035A);
  {$EXTERNALSYM SEC_E_KDC_CERT_REVOKED}
  SEC_E_KDC_CERT_REVOKED              = HRESULT($8009035B);


type
  {$EXTERNALSYM USHORT}
  USHORT =  Word;
  PUSHORT = ^USHORT;

  {$EXTERNALSYM PVOID}
  PVOID =  Pointer;

  {$EXTERNALSYM PPVOID}
  PPVOID = ^PVOID;

  SECURITY_INTEGER = LARGE_INTEGER;

  TimeStamp = SECURITY_INTEGER;
  PTimeStamp = ^TimeStamp;

  PSEC_WCHAR = PWideChar;
  SEC_WCHAR = WideChar;

  PSEC_CHAR = PAnsiChar;
  SEC_CHAR = AnsiChar;

  PSECURITY_STATUS = ^SECURITY_STATUS;
  SECURITY_STATUS = LongInt;

  SECURITY_PSTR = ^SEC_WCHAR;

  {$EXTERNALSYM PSecHandle}
  PSecHandle = ^SecHandle;

  {$EXTERNALSYM SecHandle}
  SecHandle = record
    dwLower: Pointer;
    dwUpper: Pointer;
  end;

  {$EXTERNALSYM CredHandle}
  CredHandle = SecHandle;
  {$EXTERNALSYM PCredHandle}
  PCredHandle = PSecHandle;

  {$EXTERNALSYM CtxtHandle}
  CtxtHandle = SecHandle;
  {$EXTERNALSYM PCtxtHandle}
  PCtxtHandle = PSecHandle;

//
// SecPkgInfo structure
//
//  Provides general information about a security provider
//

  PPSecPkgInfoW = ^PSecPkgInfoW;

  PSecPkgInfoW = ^SecPkgInfoW;

  SecPkgInfoW = record
    fCapabilities: ULONG;     // Capability bitmask
    wVersion: USHORT;         // Version of driver
    wRPCID: USHORT;           // ID for RPC Runtime
    cbMaxToken: ULONG;        // Size of authentication token (max)
    Name: PSEC_WCHAR;         // Text name
    Comment: SEC_WCHAR;       // Comment
  end;

  PPSecPkgInfoA = ^PSecPkgInfoA;

  PSecPkgInfoA = ^SecPkgInfoA;

  SecPkgInfoA = record
    fCapabilities: ULONG;     // Capability bitmask
    wVersion: USHORT;         // Version of driver
    wRPCID: USHORT;           // ID for RPC Runtime
    cbMaxToken: ULONG;        // Size of authentication token (max)
    Name: PSEC_CHAR;          // Text name
    Comment: PSEC_CHAR;       // Comment
  end;

//
// SecBuffer
//
//  Generic memory descriptors for buffers passed in to the security
//  API
//

  PSecBuffer = ^SecBuffer;

  SecBuffer = record
    cbBuffer: ULONG;          // Size of the buffer, in bytes
    BufferType: ULONG;        // Type of the buffer (below)
    pvBuffer: PVOID;          // Pointer to the buffer
  end;

  PSecBufferDesc = ^SecBufferDesc;

  SecBufferDesc = record
    ulVersion: ULONG;         // Version number
    cBuffers: ULONG;          // Number of buffers
    pBuffers: PSecBuffer;     // Pointer to array of buffers
  end;

  PSEC_NEGOTIATION_INFO = ^SEC_NEGOTIATION_INFO;

  SEC_NEGOTIATION_INFO = record
    Size: ULONG;                      // Size of this structure
    NameLength: ULONG;                // Length of name hint
    Name: PSEC_WCHAR;                 // Name hint
    Reserved: PVOID;                  // Reserved
  end;

  PSEC_CHANNEL_BINDINGS = ^SEC_CHANNEL_BINDINGS;

  SEC_CHANNEL_BINDINGS = record
    dwInitiatorAddrType: ULONG;
    cbInitiatorLength: ULONG;
    dwInitiatorOffset: ULONG;
    dwAcceptorAddrType: ULONG;
    cbAcceptorLength: ULONG;
    dwAcceptorOffset: ULONG;
    cbApplicationDataLength: ULONG;
    dwApplicationDataOffset: ULONG;
  end;

  PSecPkgCredentials_NamesW = ^SecPkgCredentials_NamesW;

  SecPkgCredentials_NamesW = record
    sUserName: PSEC_WCHAR;
  end;

  PSecPkgCredentials_NamesA = ^SecPkgCredentials_NamesA;
  
  SecPkgCredentials_NamesA = record
    sUserName: PSEC_CHAR;
  end;

  PSecPkgCredentials_SSIProviderW = ^SecPkgCredentials_SSIProviderW;

  SecPkgCredentials_SSIProviderW = record
    sProviderName: PSEC_WCHAR;
    ProviderInfoLength: ULONG;
    ProviderInfo: PAnsiChar;
  end;

  PSecPkgCredentials_SSIProviderA = ^SecPkgCredentials_SSIProviderA;

  SecPkgCredentials_SSIProviderA = record
    sProviderName: PSEC_CHAR;
    ProviderInfoLength: ULONG;
    ProviderInfo: PAnsiChar;
  end;

  PSecPkgContext_Sizes = ^SecPkgContext_Sizes;

  SecPkgContext_Sizes = record
    cbMaxToken: ULONG;
    cbMaxSignature: ULONG;
    cbBlockSize: ULONG;
    cbSecurityTrailer: ULONG;
  end;

  PSecPkgContext_StreamSizes = ^SecPkgContext_StreamSizes;

  SecPkgContext_StreamSizes = record
    cbHeader: ULONG;
    cbTrailer: ULONG;
    cbMaximumMessage: ULONG;
    cBuffers: ULONG;
    cbBlockSize: ULONG;
  end;

  PSecPkgContext_NamesW = ^SecPkgContext_NamesW;

  SecPkgContext_NamesW = record
    sUserName: PSEC_WCHAR;
  end;

  PSecPkgContext_NamesA = ^SecPkgContext_NamesA;

  SecPkgContext_NamesA = record
    sUserName: PSEC_CHAR;
  end;

  PSecPkgContext_Lifespan = ^SecPkgContext_Lifespan;

  SecPkgContext_Lifespan = record
    tsStart: TimeStamp;
    tsExpiry: TimeStamp;
  end;

  PSecPkgContext_DceInfo = ^SecPkgContext_DceInfo;

  SecPkgContext_DceInfo = record
    AuthzSvc: ULONG;
    pPac: PVOID;
  end;

  PSecPkgContext_KeyInfoA = ^SecPkgContext_KeyInfoA;

  SecPkgContext_KeyInfoA = record
    sSignatureAlgorithmName: PSEC_CHAR;
    sEncryptAlgorithmName: PSEC_CHAR;
    KeySize: ULONG;
    SignatureAlgorithm: ULONG;
    EncryptAlgorithm: ULONG;
  end;

  PSecPkgContext_KeyInfoW = ^SecPkgContext_KeyInfoW;

  SecPkgContext_KeyInfoW = record
    sSignatureAlgorithmName: PSEC_WCHAR;
    sEncryptAlgorithmName: PSEC_WCHAR;
    KeySize: ULONG;
    SignatureAlgorithm: ULONG;
    EncryptAlgorithm: ULONG;
  end;

  PSecPkgContext_AuthorityA = ^SecPkgContext_AuthorityA;

  SecPkgContext_AuthorityA = record
    sAuthorityName: PSEC_CHAR;
  end;

  PSecPkgContext_AuthorityW = ^SecPkgContext_AuthorityW;

  SecPkgContext_AuthorityW = record
    sAuthorityName: PSEC_WCHAR;
  end;

  PSecPkgContext_ProtoInfoA = ^SecPkgContext_ProtoInfoA;

  SecPkgContext_ProtoInfoA = record
    sProtocolName: PSEC_CHAR;
    majorVersion: ULONG;
    minorVersion: ULONG;
  end;

  PSecPkgContext_ProtoInfoW = ^SecPkgContext_ProtoInfoW;
  
  SecPkgContext_ProtoInfoW = record
    sProtocolName: PSEC_WCHAR;
    majorVersion: ULONG;
    minorVersion: ULONG;
  end;

  PSecPkgContext_PasswordExpiry = ^SecPkgContext_PasswordExpiry;

  SecPkgContext_PasswordExpiry = record
    tsPasswordExpires: TimeStamp;
  end;

  PSecPkgContext_SessionKey = ^SecPkgContext_SessionKey;

  SecPkgContext_SessionKey = record
    SessionKeyLength: ULONG;
    SessionKey: PUCHAR;
  end;

  PSecPkgContext_PackageInfoW = ^SecPkgContext_PackageInfoW;

  SecPkgContext_PackageInfoW = record
    PackageInfo: PSecPkgInfoW;
  end;

  PSecPkgContext_PackageInfoA = ^SecPkgContext_PackageInfoA;

  SecPkgContext_PackageInfoA = record
    PackageInfo: PSecPkgInfoA;
  end;

  PSecPkgContext_UserFlags = ^SecPkgContext_UserFlags;

  SecPkgContext_UserFlags = record
    UserFlags: ULONG;
  end;

  PSecPkgContext_Flags = ^SecPkgContext_Flags;

  SecPkgContext_Flags = record
    Flags: ULONG;
  end;

  PSecPkgContext_NegotiationInfoA = ^SecPkgContext_NegotiationInfoA;

  SecPkgContext_NegotiationInfoA = record
    PackageInfo: PSecPkgInfoA;
    NegotiationState: ULONG;
  end;

  PSecPkgContext_NegotiationInfoW = ^SecPkgContext_NegotiationInfoW;
  
  SecPkgContext_NegotiationInfoW = record
    PackageInfo: PSecPkgInfoW;
    NegotiationState: ULONG;
  end;

  PSecPkgContext_NativeNamesW = ^SecPkgContext_NativeNamesW;

  SecPkgContext_NativeNamesW = record
    sClientName: PSEC_WCHAR;
    sServerName: PSEC_WCHAR;
  end;

  PSecPkgContext_NativeNamesA = ^SecPkgContext_NativeNamesA;

  SecPkgContext_NativeNamesA = record
    sClientName: PSEC_CHAR;
    sServerName: PSEC_CHAR;
  end;

  PSecPkgContext_CredentialNameW = ^SecPkgContext_CredentialNameW;

  SecPkgContext_CredentialNameW = record
    CredentialType: ULONG;
    sCredentialName: PSEC_WCHAR;
  end;

  PSecPkgContext_CredentialNameA = ^SecPkgContext_CredentialNameA;

  SecPkgContext_CredentialNameA = record
    CredentialType: ULONG;
    sCredentialName: PSEC_CHAR;
  end;

  PSecPkgContext_AccessToken = ^SecPkgContext_AccessToken;

  SecPkgContext_AccessToken = record
    AccessToken: PVOID;
  end;

  PSecPkgContext_TargetInformation = ^SecPkgContext_TargetInformation;

  SecPkgContext_TargetInformation = record
    MarshalledTargetInfoLength: ULONG;
    MarshalledTargetInfo: PBYTE;
  end;

  PSecPkgContext_AuthzID = ^SecPkgContext_AuthzID;

  SecPkgContext_AuthzID = record
    AuthzIDLength: ULONG;
    AuthzID: PAnsiChar;
  end;

  PSecPkgContext_Target = ^SecPkgContext_Target;

  SecPkgContext_Target = record
    TargetLength: ULONG;
    Target: PAnsiChar;
  end;

  SEC_GET_KEY_FN = function(
    Arg: PVOID;                // Argument passed in
    Principal: PVOID;          // Principal ID
    KeyVer: ULONG;             // Key Version
    Key: PPVOID;               // Returned ptr to key
    Status: PSECURITY_STATUS   // returned status
  ): PVOID; stdcall;

  ACQUIRE_CREDENTIALS_HANDLE_FN_W = function( // AcquireCredentialsHandleW
    pszPrincipal: PSEC_WCHAR;   // Name of principal
    pszPackage: PSEC_WCHAR;     // Name of package
    fCredentialUse: ULONG;      // Flags indicating use
    pvLogonId: PVOID;           // Pointer to logon ID
    pAuthData: PVOID;           // Package specific data
    pGetKeyFn: SEC_GET_KEY_FN;  // Pointer to GetKey() func
    pvGetKeyArgument: PVOID;    // Value to pass to GetKey()
    phCredential: PCredHandle;  // (out) Cred Handle
    ptsExpiry: PTimeStamp       // (out) Lifetime (optional)
  ): SECURITY_STATUS; stdcall;

  ACQUIRE_CREDENTIALS_HANDLE_FN_A = function( // AcquireCredentialsHandleW
    pszPrincipal: PSEC_CHAR;    // Name of principal
    pszPackage: PSEC_CHAR;      // Name of package
    fCredentialUse: ULONG;      // Flags indicating use
    pvLogonId: PVOID;           // Pointer to logon ID
    pAuthData: PVOID;           // Package specific data
    pGetKeyFn: SEC_GET_KEY_FN;  // Pointer to GetKey() func
    pvGetKeyArgument: PVOID;    // Value to pass to GetKey()
    phCredential: PCredHandle;  // (out) Cred Handle
    ptsExpiry: PTimeStamp       // (out) Lifetime (optional)
  ): SECURITY_STATUS; stdcall;

  FREE_CREDENTIALS_HANDLE_FN = function( // FreeCredentialsHandle
    phCredential: PCredHandle   // Handle to free
  ): SECURITY_STATUS; stdcall;

  ADD_CREDENTIALS_FN_W = function( // AddCredentialsW
    hCredentials: PCredHandle;
    pszPrincipal: PSEC_WCHAR;   // Name of principal
    pszPackage: PSEC_WCHAR;     // Name of package
    fCredentialUse: ULONG;      // Flags indicating use
    pAuthData: PVOID;           // Package specific data
    pGetKeyFn: SEC_GET_KEY_FN;  // Pointer to GetKey() func
    pvGetKeyArgument: PVOID;    // Value to pass to GetKey()
    ptsExpiry: PTimeStamp       // (out) Lifetime (optional)
  ): SECURITY_STATUS; stdcall;

  ADD_CREDENTIALS_FN_A = function( // AddCredentialsA
    hCredentials: PCredHandle;
    pszPrincipal: PSEC_CHAR;    // Name of principal
    pszPackage: PSEC_CHAR;      // Name of package
    fCredentialUse: ULONG;      // Flags indicating use
    pAuthData: PVOID;           // Package specific data
    pGetKeyFn: SEC_GET_KEY_FN;  // Pointer to GetKey() func
    pvGetKeyArgument: PVOID;    // Value to pass to GetKey()
    ptsExpiry: PTimeStamp       // (out) Lifetime (optional)
  ): SECURITY_STATUS; stdcall;

////////////////////////////////////////////////////////////////////////
///
/// Context Management Functions
///
////////////////////////////////////////////////////////////////////////

  INITIALIZE_SECURITY_CONTEXT_FN_W = function( // InitializeSecurityContextW
    phCredential: PCredHandle;  // Cred to base context
    phContext: PCtxtHandle;     // Existing context (OPT)
    pszTargetName: PSEC_WCHAR;  // Name of target
    fContextReq: ULONG;         // Context Requirements
    Reserved1: ULONG;           // Reserved, MBZ
    TargetDataRep: ULONG;       // Data rep of target
    pInput: PSecBufferDesc;     // Input Buffers
    Reserved2: ULONG;           // Reserved, MBZ
    phNewContext: PCtxtHandle;  // (out) New Context handle
    pOutput: PSecBufferDesc;    // (inout) Output Buffers
    pfContextAttr: PULONG;      // (out) Context attrs
    ptsExpiry: PTimeStamp       // (out) Life span (OPT)
  ): SECURITY_STATUS; stdcall;

  INITIALIZE_SECURITY_CONTEXT_FN_A = function( // InitializeSecurityContextA
    phCredential: PCredHandle;  // Cred to base context
    phContext: PCtxtHandle;     // Existing context (OPT)
    pszTargetName: PSEC_CHAR;   // Name of target
    fContextReq: ULONG;         // Context Requirements
    Reserved1: ULONG;           // Reserved, MBZ
    TargetDataRep: ULONG;       // Data rep of target
    pInput: PSecBufferDesc;     // Input Buffers
    Reserved2: ULONG;           // Reserved, MBZ
    phNewContext: PCtxtHandle;  // (out) New Context handle
    pOutput: PSecBufferDesc;    // (inout) Output Buffers
    pfContextAttr: PULONG;      // (out) Context attrs
    ptsExpiry: PTimeStamp       // (out) Life span (OPT)
  ): SECURITY_STATUS; stdcall;

  ACCEPT_SECURITY_CONTEXT_FN = function( // AcceptSecurityContext
    phCredential: PCredHandle;  // Cred to base context
    phContext: PCtxtHandle;     // Existing context (OPT)
    pInput: PSecBufferDesc;     // Input buffer
    fContextReq: ULONG;         // Context Requirements
    TargetDataRep: ULONG;       // Target Data Rep
    phNewContext: PCtxtHandle;  // (out) New context handle
    pOutput: PSecBufferDesc;    // (inout) Output buffers
    pfContextAttr: PULONG;      // (out) Context attributes
    ptsExpiry: PTimeStamp       // (out) Life span (OPT)
  ): SECURITY_STATUS; stdcall;

  COMPLETE_AUTH_TOKEN_FN = function( // CompleteAuthToken
    phContext: PCtxtHandle;     // Context to complete
    pToken: PSecBufferDesc      // Token to complete
  ): SECURITY_STATUS; stdcall;

  IMPERSONATE_SECURITY_CONTEXT_FN = function( // ImpersonateSecurityContext
    phContext: PCtxtHandle      // Context to impersonate
  ): SECURITY_STATUS; stdcall;

  REVERT_SECURITY_CONTEXT_FN = function( // RevertSecurityContext
    phContext: PCtxtHandle      // Context from which to re
  ): SECURITY_STATUS; stdcall;

  QUERY_SECURITY_CONTEXT_TOKEN_FN = function( // QuerySecurityContextToken
    phContext: PCtxtHandle;
    Token: PPVOID
  ): SECURITY_STATUS; stdcall;

  DELETE_SECURITY_CONTEXT_FN = function( // DeleteSecurityContext
    phContext: PCtxtHandle      // Context to delete
  ): SECURITY_STATUS; stdcall;

  APPLY_CONTROL_TOKEN_FN = function( // ApplyControlToken
    phContext: PCtxtHandle;     // Context to modify
    pInput: PSecBufferDesc      // Input token to apply
  ): SECURITY_STATUS; stdcall;

  QUERY_CONTEXT_ATTRIBUTES_FN_W = function( // QueryContextAttributesW
    phContext: PCtxtHandle;     // Context to query
    ulAttribute: ULONG;         // Attribute to query
    pBuffer: PVOID              // Buffer for attributes
  ): SECURITY_STATUS; stdcall;

  QUERY_CONTEXT_ATTRIBUTES_FN_A = function( // QueryContextAttributesA
    phContext: PCtxtHandle;     // Context to query
    ulAttribute: ULONG;         // Attribute to query
    pBuffer: PVOID              // Buffer for attributes
  ): SECURITY_STATUS; stdcall;

  QUERY_CREDENTIALS_ATTRIBUTES_FN_W = function( // QueryCredentialsAttributesW
    phCredential: PCredHandle;  // Credential to query
    ulAttribute: ULONG;         // Attribute to query
    pBuffer: PVOID              // Buffer for attributes
  ): SECURITY_STATUS; stdcall;

  QUERY_CREDENTIALS_ATTRIBUTES_FN_A = function( // QueryCredentialsAttributesA
    phCredential: PCredHandle;  // Credential to query
    ulAttribute: ULONG;         // Attribute to query
    pBuffer: PVOID              // Buffer for attributes
  ): SECURITY_STATUS; stdcall;

  SET_CONTEXT_ATTRIBUTES_FN_W = function ( // SetContextAttributesW
    phContext: PCtxtHandle;     // Context to Set
    ulAttribute: ULONG;         // Attribute to Set
    pBuffer: PVOID;             // Buffer for attributes
    cbBuffer: ULONG             // Size (in bytes) of Buffer
  ): SECURITY_STATUS; stdcall;

  SET_CONTEXT_ATTRIBUTES_FN_A = function ( // SetContextAttributesA
    phContext: PCtxtHandle;     // Context to Set
    ulAttribute: ULONG;         // Attribute to Set
    pBuffer: PVOID;             // Buffer for attributes
    cbBuffer: ULONG             // Size (in bytes) of Buffer
  ): SECURITY_STATUS; stdcall;

  SET_CREDENTIALS_ATTRIBUTES_FN_W = function ( // SetCredentialsAttributesW
    phCredential: PCredHandle;  // Credential to Set
    ulAttribute: ULONG;         // Attribute to Set
    pBuffer: PVOID;             // Buffer for attributes
    cbBuffer: ULONG             // Size (in bytes) of Buffer
  ): SECURITY_STATUS; stdcall;

  SET_CREDENTIALS_ATTRIBUTES_FN_A = function ( // SetCredentialsAttributesA
    phCredential: PCredHandle;  // Credential to Set
    ulAttribute: ULONG;         // Attribute to Set
    pBuffer: PVOID;             // Buffer for attributes
    cbBuffer: ULONG             // Size (in bytes) of Buffer
  ): SECURITY_STATUS; stdcall;

  FREE_CONTEXT_BUFFER_FN = function( // FreeContextBuffer
    pvContextBuffer: PVOID      // buffer to free
  ): SECURITY_STATUS; stdcall;

///////////////////////////////////////////////////////////////////
////
////    Message Support API
////
//////////////////////////////////////////////////////////////////

  MAKE_SIGNATURE_FN = function( // MakeSignature
    phContext: PCtxtHandle;     // Context to use
    fQOP: ULONG;                // Quality of Protection
    pMessage: PSecBufferDesc;   // Message to sign
    MessageSeqNo: ULONG         // Message Sequence Num.
  ): SECURITY_STATUS; stdcall;

  VERIFY_SIGNATURE_FN = function( // VerifySignature
    phContext: PCtxtHandle;     // Context to use
    pMessage: PSecBufferDesc;   // Message to verify
    MessageSeqNo: ULONG;        // Sequence Num.
    pfQOP: PULONG               // QOP used
  ): SECURITY_STATUS; stdcall;

  ENCRYPT_MESSAGE_FN = function( // EncryptMessage
    phContext: PCtxtHandle;
    fQOP: ULONG;
    pMessage: PSecBufferDesc;
    MessageSeqNo: ULONG
  ): SECURITY_STATUS; stdcall;

  DECRYPT_MESSAGE_FN = function( // DecryptMessage
    phContext: PCtxtHandle;
    pMessage: PSecBufferDesc;
    MessageSeqNo: ULONG;
    pfQOP: PULONG 
  ): SECURITY_STATUS; stdcall;

///////////////////////////////////////////////////////////////////////////
////
////    Misc.
////
///////////////////////////////////////////////////////////////////////////

  ENUMERATE_SECURITY_PACKAGES_FN_W = function( // EnumerateSecurityPackagesW
    pcPackages: PULONG;           // Receives num. packages
    ppPackageInfo: PPSecPkgInfoW  // Receives array of info
  ): SECURITY_STATUS; stdcall;

  ENUMERATE_SECURITY_PACKAGES_FN_A = function( // EnumerateSecurityPackagesA
    pcPackages: PULONG;           // Receives num. packages
    ppPackageInfo: PPSecPkgInfoA  // Receives array of info
  ): SECURITY_STATUS; stdcall;

  QUERY_SECURITY_PACKAGE_INFO_FN_W = function( // QuerySecurityPackageInfoW
    pszPackageName: PSEC_WCHAR;   // Name of package
    ppPackageInfo: PPSecPkgInfoW  // Receives package info
  ): SECURITY_STATUS; stdcall;

  QUERY_SECURITY_PACKAGE_INFO_FN_A = function( // QuerySecurityPackageInfoA
    pszPackageName: PSEC_CHAR;    // Name of package
    ppPackageInfo: PPSecPkgInfoA  // Receives package info
  ): SECURITY_STATUS; stdcall;

  SecDelegationType = (
    SecFull,
    SecService,
    SecTree,
    SecDirectory,
    SecObject
  );

  PSecDelegationType = ^SecDelegationType;

  DELEGATE_SECURITY_CONTEXT_FN = function( // DelegateSecurityContext
    phContext: PCtxtHandle;             // IN Active context to delegate
    pszTarget: PSEC_CHAR;               // IN Target path
    DelegationType: SecDelegationType;  // IN Type of delegation
    pExpiry: PTimeStamp;                // IN OPTIONAL time limit
    pPackageParameters: PSecBuffer;     // IN OPTIONAL package specific
    pOutput: PSecBufferDesc             // OUT Token for applycontroltoken.
  ): SECURITY_STATUS; stdcall;

///////////////////////////////////////////////////////////////////////////
////
////    Proxies
////
///////////////////////////////////////////////////////////////////////////

//
// Proxies are only available on NT platforms
//

///////////////////////////////////////////////////////////////////////////
////
////    Context export/import
////
///////////////////////////////////////////////////////////////////////////

  EXPORT_SECURITY_CONTEXT_FN = function( // ExportSecurityContext
    phContext: PCtxtHandle;     // (in) context to export
    fFlags: ULONG;              // (in) option flags
    pPackedContext: PSecBuffer; // (out) marshalled context
    pToken: PPVOID              // (out, optional) token handle for impersonation
  ): SECURITY_STATUS; stdcall;

  IMPORT_SECURITY_CONTEXT_FN_W = function( // ImportSecurityContextW
    pszPackage: PSEC_WCHAR;
    pPackedContext: PSecBuffer; // (in) marshalled context
    Token: PVOID;               // (in, optional) handle to token for context
    phContext: PCtxtHandle      // (out) new context handle
  ): SECURITY_STATUS; stdcall;

  IMPORT_SECURITY_CONTEXT_FN_A = function( // ImportSecurityContextA
    pszPackage: PSEC_CHAR;
    pPackedContext: PSecBuffer; // (in) marshalled context
    Token: PVOID;               // (in, optional) handle to token for context
    phContext: PCtxtHandle      // (out) new context handle
  ): SECURITY_STATUS; stdcall;

///////////////////////////////////////////////////////////////////////////////
////
////  Fast access for RPC:
////
///////////////////////////////////////////////////////////////////////////////

  PSecurityFunctionTableW = ^SecurityFunctionTableW;

  SecurityFunctionTableW = packed record
    dwVersion: ULONG;
    EnumerateSecurityPackagesW: ENUMERATE_SECURITY_PACKAGES_FN_W;
    QueryCredentialsAttributesW: QUERY_CREDENTIALS_ATTRIBUTES_FN_W;
    AcquireCredentialsHandleW: ACQUIRE_CREDENTIALS_HANDLE_FN_W;
    FreeCredentialsHandle: FREE_CREDENTIALS_HANDLE_FN;
    Reserved2: PVOID;
    InitializeSecurityContextW: INITIALIZE_SECURITY_CONTEXT_FN_W;
    AcceptSecurityContext: ACCEPT_SECURITY_CONTEXT_FN;
    CompleteAuthToken: COMPLETE_AUTH_TOKEN_FN;
    DeleteSecurityContext: DELETE_SECURITY_CONTEXT_FN;
    ApplyControlToken: APPLY_CONTROL_TOKEN_FN;
    QueryContextAttributesW: QUERY_CONTEXT_ATTRIBUTES_FN_W;
    ImpersonateSecurityContext: IMPERSONATE_SECURITY_CONTEXT_FN;
    RevertSecurityContext: REVERT_SECURITY_CONTEXT_FN;
    MakeSignature: MAKE_SIGNATURE_FN;
    VerifySignature: VERIFY_SIGNATURE_FN;
    FreeContextBuffer: FREE_CONTEXT_BUFFER_FN;
    QuerySecurityPackageInfoW: QUERY_SECURITY_PACKAGE_INFO_FN_W;
    Reserved3: PVOID;
    Reserved4: PVOID;
    ExportSecurityContext: EXPORT_SECURITY_CONTEXT_FN;
    ImportSecurityContextW: IMPORT_SECURITY_CONTEXT_FN_W;
    AddCredentialsW : ADD_CREDENTIALS_FN_W;
    Reserved8: PVOID;
    QuerySecurityContextToken: QUERY_SECURITY_CONTEXT_TOKEN_FN;
    EncryptMessage: ENCRYPT_MESSAGE_FN;
    DecryptMessage: DECRYPT_MESSAGE_FN;
    SetContextAttributesW: SET_CONTEXT_ATTRIBUTES_FN_W;
    SetCredentialsAttributesW: SET_CREDENTIALS_ATTRIBUTES_FN_W
  end;

  PSecurityFunctionTableA = ^SecurityFunctionTableA;

  SecurityFunctionTableA = packed record
    dwVersion: ULONG;
    EnumerateSecurityPackagesA: ENUMERATE_SECURITY_PACKAGES_FN_A;
    QueryCredentialsAttributesA: QUERY_CREDENTIALS_ATTRIBUTES_FN_A;
    AcquireCredentialsHandleA: ACQUIRE_CREDENTIALS_HANDLE_FN_A;
    FreeCredentialsHandle: FREE_CREDENTIALS_HANDLE_FN;
    Reserved2: PVOID;
    InitializeSecurityContextA: INITIALIZE_SECURITY_CONTEXT_FN_A;
    AcceptSecurityContext: ACCEPT_SECURITY_CONTEXT_FN;
    CompleteAuthToken: COMPLETE_AUTH_TOKEN_FN;
    DeleteSecurityContext: DELETE_SECURITY_CONTEXT_FN;
    ApplyControlToken: APPLY_CONTROL_TOKEN_FN;
    QueryContextAttributesA: QUERY_CONTEXT_ATTRIBUTES_FN_A;
    ImpersonateSecurityContext: IMPERSONATE_SECURITY_CONTEXT_FN;
    RevertSecurityContext: REVERT_SECURITY_CONTEXT_FN;
    MakeSignature: MAKE_SIGNATURE_FN;
    VerifySignature: VERIFY_SIGNATURE_FN;
    FreeContextBuffer: FREE_CONTEXT_BUFFER_FN;
    QuerySecurityPackageInfoA: QUERY_SECURITY_PACKAGE_INFO_FN_A;
    Reserved3: PVOID;
    Reserved4: PVOID;
    ExportSecurityContext: EXPORT_SECURITY_CONTEXT_FN;
    ImportSecurityContextA: IMPORT_SECURITY_CONTEXT_FN_A;
    AddCredentialsA : ADD_CREDENTIALS_FN_A;
    Reserved8: PVOID;
    QuerySecurityContextToken: QUERY_SECURITY_CONTEXT_TOKEN_FN;
    EncryptMessage: ENCRYPT_MESSAGE_FN;
    DecryptMessage: DECRYPT_MESSAGE_FN;
    SetContextAttributesA: SET_CONTEXT_ATTRIBUTES_FN_A;
    SetCredentialsAttributesA: SET_CREDENTIALS_ATTRIBUTES_FN_A 
  end;

  INIT_SECURITY_INTERFACE_A = function(): PSecurityFunctionTableA; stdcall; // InitSecurityInterfaceA

  INIT_SECURITY_INTERFACE_W = function(): PSecurityFunctionTableW; stdcall; // InitSecurityInterfaceW

// This is the legacy credentials structure.
// The EX version below is preferred.

  PSEC_WINNT_AUTH_IDENTITY_W = ^SEC_WINNT_AUTH_IDENTITY_W;
  
  SEC_WINNT_AUTH_IDENTITY_W = record
    User: PWideChar;
    UserLength: ULONG;
    Domain: PWideChar;
    DomainLength: ULONG;
    Password: PWideChar;
    PasswordLength: ULONG;
    Flags: ULONG;
  end;

  PSEC_WINNT_AUTH_IDENTITY_A = ^SEC_WINNT_AUTH_IDENTITY_A;

  SEC_WINNT_AUTH_IDENTITY_A = record
    User: PAnsiChar;
    UserLength: ULONG;
    Domain: PAnsiChar;
    DomainLength: ULONG;
    Password: PAnsiChar;
    PasswordLength: ULONG;
    Flags: ULONG;
  end;

// This is the combined authentication identity structure that may be
// used with the negotiate package, NTLM, Kerberos, or SCHANNEL

  PSEC_WINNT_AUTH_IDENTITY_EXW = ^SEC_WINNT_AUTH_IDENTITY_EXW;

  SEC_WINNT_AUTH_IDENTITY_EXW = record
    Version: ULONG;
    Length: ULONG;
    User: PUSHORT;
    UserLength: ULONG;
    Domain: PUSHORT;
    DomainLength: ULONG;
    Password: PUSHORT;
    PasswordLength: ULONG;
    Flags: ULONG;
    PackageList: PUSHORT;
    PackageListLength: ULONG;
  end;

  PSEC_WINNT_AUTH_IDENTITY_EXA = ^SEC_WINNT_AUTH_IDENTITY_EXA;

  SEC_WINNT_AUTH_IDENTITY_EXA = record
    Version: ULONG;
    Length: ULONG;
    User: PUCHAR;
    UserLength: ULONG;
    Domain: PUCHAR;
    DomainLength: ULONG;
    Password: PUCHAR;
    PasswordLength: ULONG;
    Flags: ULONG;
    PackageList: PUCHAR;
    PackageListLength: ULONG;
  end;


function SEC_SUCCESS(Status: SECURITY_STATUS): Boolean; 


procedure SecInvalidateHandleInt(var x: SecHandle);
function SecIsValidHandleInt(const x : SecHandle): Boolean;

procedure Initialize;
procedure FreeAuthLibrary;

var
  SecFuncsA : PSecurityFunctionTableA = nil;
  SecFuncsW : PSecurityFunctionTableW = nil;


 {$endif SB_WINDOWS_OR_NET}

 {$endif SB_NO_SSPI}
implementation

{$ifndef SB_NO_SSPI}

{$ifdef SB_WINDOWS_OR_NET}

function SEC_SUCCESS(Status: SECURITY_STATUS): Boolean;
begin
  Result := Status >= 0;
end;

const
  SECURITY_DLL = 'security.dll';
  SECUR32_DLL = 'secur32.dll';
  SYSTEM_DLL = 'system.dll';

var
  hSecLib : HMODULE  =  0;

procedure SecInvalidateHandleInt(var x: SecHandle);
begin
  x.dwLower := Pointer(-1);
  x.dwUpper := Pointer(-1);
end;

function SecIsValidHandleInt(const x : SecHandle): Boolean;
begin
  Result := (x.dwLower <> Pointer(-1)) and (x.dwUpper <> Pointer(-1));
end;

procedure Initialize;
var
  SecDLL: string;
  InitSecInterfaceA: INIT_SECURITY_INTERFACE_A;
  InitSecInterfaceW: INIT_SECURITY_INTERFACE_W;
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  if hSecLib <> 0 then
    Exit;

  {$ifdef SB_WINCE}
  SecDLL := SECUR32_DLL;
   {$else}
  if Win32Platform = VER_PLATFORM_WIN32_NT then
    SecDLL := SECURITY_DLL
  else
  if Win32Platform = VER_PLATFORM_WIN32_WINDOWS then
    SecDLL := SYSTEM_DLL
  else
    Exit;
   {$endif}

  hSecLib := LoadLibrary({$ifdef SB_WINCE}PWideChar(WideString(SecDLL)) {$else}PChar(SecDLL) {$endif});
  if hSecLib = 0 then
    Exit;

  InitSecInterfaceA := INIT_SECURITY_INTERFACE_A(GetProcAddress(hSecLib, SECURITY_ENTRYPOINTA));
  if Assigned(InitSecInterfaceA) then
    SecFuncsA := InitSecInterfaceA();

  InitSecInterfaceW := INIT_SECURITY_INTERFACE_W(GetProcAddress(hSecLib, SECURITY_ENTRYPOINTW));
  if Assigned(InitSecInterfaceW) then
    SecFuncsW := InitSecInterfaceW();

  if not Assigned(SecFuncsA) and
     not Assigned(SecFuncsW) then
  begin
    SecFuncsA := nil;
    SecFuncsW := nil;
    FreeLibrary(hSecLib);
    hSecLib := 0;
  end;
 {$endif}
end;

procedure FreeAuthLibrary;
begin
  SecFuncsA := nil;
  SecFuncsW := nil;
  if hSecLib <> 0 then
  begin
    FreeLibrary(hSecLib);
    hSecLib := 0;
  end;
end;


 {$endif SB_WINDOWS_OR_NET}

 {$endif}

end.
