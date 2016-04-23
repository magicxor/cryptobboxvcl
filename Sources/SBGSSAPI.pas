(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBGSSAPI;

interface

{$ifdef SB_GSSAPI}

uses
  SysUtils,
  {$ifdef SB_WINDOWS}
  Windows,
   {$else}
  {$ifdef FPC}
  {$ifdef SB_POSIX}
  {$ifndef SB_MACOS}
  linux,
   {$endif}	
  dynlibs,
  ctypes,
  unix,
  errors,
  sysconst,
  baseunix,
  unixtype,
  sockets,
  initc,
   {$endif}
   {$endif}

   {$endif}
  
  {$ifdef SB_UNICODE_VCL}
  SBStringList,
   {$endif}
  SBGSSAPIBase,
  SBMD,
  SBTypes,
  SBStrUtils,
  SBUtils,
  SBConstants;


type
  OM_uint32 = LongWord;
  gss_uint32 = LongWord;
  gss_int32 = LongInt;

  gss_qop_t = LongWord;
  gss_cred_usage_t = LongInt;

  gss_ctx_id_t = Pointer;
  gss_cred_id_t = Pointer;
  gss_name_t = Pointer;

  p_gss_OID = ^gss_OID;

  gss_OID = ^gss_OID_desc;

  gss_OID_desc = record
    length: LongWord;
    elements: Pointer;
  end;

  gss_OID_set = ^gss_OID_set_desc;

  gss_OID_set_desc = record
    count: LongWord;
    elements: gss_OID;
  end;

  gss_buffer_t = ^gss_buffer_desc;

  gss_buffer_desc = record
    length: LongWord;
    value: Pointer;
  end;

  gss_channel_bindings_t = ^gss_channel_bindings_desc_t;

  gss_channel_bindings_desc_t = record
    initiator_addrtype: OM_uint32;
    initiator_address: gss_buffer_desc;
    acceptor_addrtype: OM_uint32;
    acceptor_address: gss_buffer_desc;
    application_data: gss_buffer_desc;
  end;

  // Function prototypes for the GSS-API routines

  // Assume a global identity; Obtain a GSS-API credential handle for pre-existing credentials.
  gss_acquire_cred = function(
    var minor_status: OM_uint32;
    const desired_name: gss_name_t;
    time_req: OM_uint32;
    const desired_mechs: gss_OID_set;
    cred_usage: gss_cred_usage_t;
    var output_cred_handle: gss_cred_id_t;
    var actual_mechs: gss_OID_set;
    var time_rec: OM_uint32
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Discard a credential handle.
  gss_release_cred = function(
    var minor_status: OM_uint32;
    var cred_handle: gss_cred_id_t
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Initiate a security context with a peer application
  gss_init_sec_context = function(
    var minor_status: OM_uint32;
    const initiator_cred_handle: gss_cred_id_t;
    var context_handle: gss_ctx_id_t;
    const target_name: gss_name_t;
    const mech_type: gss_OID;
    req_flags: OM_uint32;
    time_req: OM_uint32;
    input_chan_bindings: gss_channel_bindings_t;
    const input_token: gss_buffer_t;
    actual_mech_type: p_gss_OID;
    output_token: gss_buffer_t;
    var ret_flags: OM_uint32;
    var time_rec: OM_uint32
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Accept a security context initiated by a peer application
  gss_accept_sec_context = function(
    var minor_status: OM_uint32;
    var context_handle: gss_ctx_id_t;
    const acceptor_cred_handle: gss_cred_id_t;
    const input_token_buffer: gss_buffer_t;
    const input_chan_bindings: gss_channel_bindings_t;
    var src_name: gss_name_t;
    var mech_type: gss_OID;
    output_token: gss_buffer_t;
    var ret_flags: OM_uint32;
    var time_rec: OM_uint32;
    var delegated_cred_handle: gss_cred_id_t
  ): OM_uint32 ; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Process a token on a security context from a peer application
  gss_process_context_token = function(
    var minor_status: OM_uint32;
    const context_handle: gss_ctx_id_t;
    const token_buffer: gss_buffer_t
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Discard a security context
  gss_delete_sec_context = function(
    var minor_status: OM_uint32;
    var context_handle: gss_ctx_id_t;
    output_token: gss_buffer_t
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Determine for how long a context will remain valid
  gss_context_time = function(
    var minor_status: OM_uint32;
    const context_handle: gss_ctx_id_t;
    var time_rec: OM_uint32
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Calculate a cryptographic message integrity code (MIC) for a message; integrity service
  gss_get_mic = function(
    var minor_status: OM_uint32;
    const context_handle: gss_ctx_id_t;
    qop_req: gss_qop_t;
    const message_buffer: gss_buffer_t;
    message_token: gss_buffer_t
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Check a MIC against a message; verify integrity of a received message
  gss_verify_mic = function(
    var minor_status: OM_uint32;
    const context_handle: gss_ctx_id_t;
    const message_buffer: gss_buffer_t;
    const token_buffer: gss_buffer_t;
    var qop_state: gss_qop_t
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Attach a MIC to a message, and optionally encrypt the message content; confidentiality service
  gss_wrap = function(
    var minor_status: OM_uint32;
    const context_handle: gss_ctx_id_t;
    conf_req_flag: Integer;
    qop_req: gss_qop_t;
    const input_message_buffer: gss_buffer_t;
    var conf_state: Integer;
    output_message_buffer: gss_buffer_t
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Verify a message with attached MIC, and decrypt message content if necessary.
  gss_unwrap = function(
    var minor_status: OM_uint32;
    const context_handle: gss_ctx_id_t;
    const input_message_buffer: gss_buffer_t;
    output_message_buffer: gss_buffer_t;
    var conf_state: Integer;
    var qop_state: gss_qop_t
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Convert a GSS-API status code to text
  gss_display_status = function(
    var minor_status: OM_uint32;
    status_value: OM_uint32;
    status_type: Integer;
    const mech_type: gss_OID;
    var message_context: OM_uint32;
    status_string: gss_buffer_t
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Determine available underlying authentication mechanisms
  gss_indicate_mechs = function(
    var minor_status: OM_uint32;
    var mech_set: gss_OID_set
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Compare two internal-form names
  gss_compare_name = function(
    var minor_status: OM_uint32;
    const name1: gss_name_t;
    const name2: gss_name_t;
    var name_equal: Integer
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Convert internal-form name to text
  gss_display_name = function(
    var minor_status: OM_uint32;
    const input_name: gss_name_t;
    output_name_buffer: gss_buffer_t;
    var output_name_type: gss_OID
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Convert a contiguous string name to internal-form
  gss_import_name = function(
    var minor_status: OM_uint32;
    const input_name_buffer: gss_buffer_t;
    const input_name_type: gss_OID;
    var output_name: gss_name_t
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Convert an MN to export form
  gss_export_name = function(
    var minor_status: OM_uint32;
    const input_name: gss_name_t;
    exported_name: gss_buffer_t
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Discard an internal-form name
  gss_release_name = function(
    var minor_status: OM_uint32;
    var input_name: gss_name_t
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Discard a buffer
  gss_release_buffer = function(
    var minor_status: OM_uint32;
    buffer: gss_buffer_t
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Discard a set of object identifiers
  gss_release_oid_set = function(
    var minor_status: OM_uint32;
    var oid_set: gss_OID_set
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Obtain information about a credential
  gss_inquire_cred = function(
    var minor_status: OM_uint32;
    const cred_handle: gss_cred_id_t;
    var name: gss_name_t;
    var lifetime: OM_uint32;
    var cred_usage: gss_cred_usage_t;
    var mechanisms: gss_OID_set
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Obtain information about a security context
  gss_inquire_context = function(
    var minor_status: OM_uint32;
    const context_handle: gss_ctx_id_t;
    var src_name: gss_name_t;
    var targ_name: gss_name_t;
    var lifetime_rec: OM_uint32;
    var mech_type: gss_OID;
    var ctx_flags: OM_uint32;
    var locally_initiated: Integer;
    var open: Integer
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Determine token-size limit for gss_wrap on a context
  gss_wrap_size_limit = function(
    var minor_status: OM_uint32;
    const context_handle: gss_ctx_id_t;
    conf_req_flag: Integer;
    qop_req: gss_qop_t;
    req_output_size: OM_uint32;
    var max_input_size: OM_uint32
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Construct credentials incrementally
  gss_add_cred = function(
    var minor_status: OM_uint32;
    const input_cred_handle: gss_cred_id_t;
    const desired_name: gss_name_t;
    const desired_mech: gss_OID;
    cred_usage: gss_cred_usage_t;
    initiator_time_req: OM_uint32;
    acceptor_time_req: OM_uint32;
    var output_cred_handle: gss_cred_id_t;
    var actual_mechs: gss_OID_set;
    var initiator_time_rec: OM_uint32;
    var acceptor_time_rec: OM_uint32
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Store a credential in the current credential store
  // http://www.ietf.org/internet-drafts/draft-ietf-kitten-gssapi-store-cred-03.txt
  gss_store_cred = function(
    var minor_status: OM_uint32;
    const input_cred: gss_cred_id_t;
    cred_usage: gss_cred_usage_t;
    const desired_mech: gss_OID;
    overwrite_cred: OM_uint32;
    default_cred: OM_uint32;
    var elements_stored: gss_OID_set;
    var cred_usage_stored: gss_cred_usage_t
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Obtain per-mechanism information about a credential.
  gss_inquire_cred_by_mech = function(
    var minor_status: OM_uint32;
    const cred_handle: gss_cred_id_t;
    const mech_type: gss_OID;
    var name: gss_name_t;
    var initiator_lifetime: OM_uint32;
    var acceptor_lifetime: OM_uint32;
    var cred_usage: gss_cred_usage_t
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Transfer a security context to another process
  gss_export_sec_context = function(
    var minor_status: OM_uint32;
    var context_handle: gss_ctx_id_t;
    interprocess_token: gss_buffer_t
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Import a transferred context
  gss_import_sec_context = function(
    var minor_status: OM_uint32;
    const interprocess_token: gss_buffer_t;
    var context_handle: gss_ctx_id_t
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Create a set containing no object identifiers
  gss_create_empty_oid_set = function(
    var minor_status: OM_uint32;
    var oid_set: gss_OID_set
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Add an object identifier to a set
  gss_add_oid_set_member = function(
    var minor_status: OM_uint32;
    const member_oid: gss_OID;
    var oid_set: gss_OID_set
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Determines whether an object identifier is a member of a set.
  gss_test_oid_set_member = function(
    var minor_status: OM_uint32;
    const member: gss_OID;
    const oid_set: gss_OID_set;
    var present: Integer
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // List the name-types supported by the specified mechanism
  gss_inquire_names_for_mech = function(
    var minor_status: OM_uint32;
    const mechanism: gss_OID;
    var name_types: gss_OID_set
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // List mechanisms that support the specified name-type
  gss_inquire_mechs_for_name = function(
    var minor_status: OM_uint32;
    const input_name: gss_name_t;
    var mech_types: gss_OID_set
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Convert an internal name to an MN
  gss_canonicalize_name = function(
    var minor_status: OM_uint32;
    const input_name: gss_name_t;
    const mech_type: gss_OID;
    var output_name: gss_name_t
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Create a copy of an internal name
  gss_duplicate_name = function(
    var minor_status: OM_uint32;
    const src_name: gss_name_t;
    var dest_name: gss_name_t
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Release an object identifier
  gss_release_oid = function(
    var minor_status: OM_uint32;
    var oid: gss_OID
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Convert a string to an OID
  gss_str_to_oid = function(
    var minor_status: OM_uint32;
    const oid_str: gss_buffer_t;
    var oid: gss_OID
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Convert an OID to a string
  gss_oid_to_str = function(
    var minor_status: OM_uint32;
    const oid: gss_OID;
    oid_str: gss_buffer_t
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // The following routines are obsolete variants of gss_get_mic,
  // gss_verify_mic, gss_wrap and gss_unwrap. They should be
  // provided by GSSAPI V2 implementations for backwards
  // compatibility with V1 applications. Distinct entrypoints
  // (as opposed to #defines) should be provided, both to allow
  // GSSAPI V1 applications to link against GSSAPI V2 implementations,
  // and to retain the slight parameter type differences between the
  // obsolete versions of these routines and their current forms.

  // Sign a message; integrity service
  gss_sign = function(
    var minor_status: OM_uint32;
    context_handle: gss_ctx_id_t;
    qop_req: Integer;
    message_buffer: gss_buffer_t;
    message_token: gss_buffer_t
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Check signature on a message
  gss_verify = function(
    var minor_status: OM_uint32;
    context_handle: gss_ctx_id_t;
    message_buffer: gss_buffer_t;
    token_buffer: gss_buffer_t;
    var qop_state: Integer
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Sign (optionally encrypt) a message; confidentiality service
  gss_seal = function(
    var minor_status: OM_uint32;
    context_handle: gss_ctx_id_t;
    conf_req_flag: Integer;
    qop_req: Integer;
    input_message_buffer: gss_buffer_t;
    var conf_state: Integer;
    output_message_buffer: gss_buffer_t
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  // Verify (optionally decrypt) message
  gss_unseal = function(
    var minor_status: OM_uint32;
    context_handle: gss_ctx_id_t;
    input_message_buffer: gss_buffer_t;
    output_message_buffer: gss_buffer_t;
    var conf_state: Integer;
    var qop_state: Integer
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

  gss_krb5_ccache_name = function(
    var minor_status: OM_uint32;
    const name : gss_name_t;     // const char *
    const out_name : gss_name_t // const char **
  ): OM_uint32; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

const
  // Various Null values
  GSS_C_NO_NAME = gss_name_t(0);
  GSS_C_NO_BUFFER = gss_buffer_t(0);
  GSS_C_NO_OID = gss_OID(0);
  GSS_C_NO_OID_SET = gss_OID_set(0);
  GSS_C_NO_CONTEXT = gss_ctx_id_t(0);
  GSS_C_NO_CREDENTIAL = gss_cred_id_t(0);
  GSS_C_NO_CHANNEL_BINDINGS = gss_channel_bindings_t(0);
  //GSS_C_EMPTY_BUFFER: gss_buffer_desc = (0, NULL);
  GSS_C_NULL_OID = GSS_C_NO_OID;
  GSS_C_NULL_OID_SET = GSS_C_NO_OID_SET;


type
  //TSBGSSBuffer = ByteArray;
  //TSBGSSOID = ByteArray;
  //TSBGSSOIDSet = array of TSBGSSOID;
  TSBGSSQOP = LongWord;
  TSBGSSCredUsage = LongInt;

  TElGSSCustomContext = class
  public
    MechOID : ByteArray;
    RequestFlags : LongWord;
    ResponseFlags : LongWord;
  end;

  TElGSSCustomName = class
  public
    MechOID : ByteArray;
  end;

  EElGSSError = class (ESecureBlackboxError);

  TSBGSSErrorEvent = procedure (Sender : TObject; const Operation : string;
    MajorStatus, MinorStatus : LongWord; const MajorErrorMsg, MinorErrorMsg : string) of object;

  // The custom class for Generic Security Service Application Program Interface (GSS-API)
  TElGSSBaseMechanism = class
  protected
    FMajorStatus: LongWord;
    FMinorStatus: LongWord;
    FMechOIDs : TElByteArrayList;
    FMechHashes : TElByteArrayList;
    FData : pointer;
    FOnError : TSBGSSErrorEvent;
  protected
    function GetCount : Integer; virtual;
    function GetMechs(Index : Integer) : ByteArray; virtual;
    procedure RecalculateMechHashes();

    procedure DoError(const Operation : string; MajorStatus, MinorStatus : LongWord;
      const MechOID : ByteArray);  overload;  virtual;
    procedure DoError(const Operation : string; MajorStatus, MinorStatus : LongWord;
      const MajorErrorMsg, MinorErrorMsg : string);  overload; 
  public
    constructor Create; virtual;
    destructor Destroy; override;

    function Initialize : Boolean; virtual; abstract;
    //procedure FinalizeMech; virtual;

    function GetLastMajorStatus: LongWord;
    function GetLastMinorStatus: LongWord;

    function AcquireCred(const MechOID: ByteArray; var Ctx: TElGSSCustomContext): LongWord; virtual; abstract;
    function AcceptSecContext(Ctx: TElGSSCustomContext; SourceName : TElGSSCustomName;
      const InputToken : ByteArray; var OutputToken: ByteArray): LongWord; virtual; abstract;
    function InitSecContext(Ctx: TElGSSCustomContext; TargetName : TElGSSCustomName; DelegateCred: Boolean;
      const InputToken : ByteArray; var OutputToken: ByteArray): LongWord; virtual; abstract;
    function ReleaseContext(var Ctx: TElGSSCustomContext): LongWord; virtual; abstract;

    function ImportName(const MechOID: ByteArray; const InputName: string;
      var OutputName: TElGSSCustomName): LongWord; virtual; abstract;
    function ReleaseName(var Name: TElGSSCustomName): LongWord; virtual; abstract;

    function GetMIC(Ctx: TElGSSCustomContext; const MessageBuffer: ByteArray;
      var MessageToken: ByteArray): LongWord; virtual; abstract;
    function VerifyMIC(Ctx: TElGSSCustomContext; const MessageBuffer: ByteArray;
      const MessageToken: ByteArray): LongWord; virtual; abstract;

    function IsMechSupported(const OID: ByteArray): Boolean; virtual;
    function IsIntegrityAvailable(Ctx: TElGSSCustomContext): Boolean; virtual;
    function IsMutualAvailable(Ctx: TElGSSCustomContext): Boolean; virtual;

    function GetMechOIDByHash(const Hash: ByteArray): ByteArray;

    property Count : Integer read GetCount;
    property Mechs[Index : Integer] : ByteArray read GetMechs;

    property OnError : TSBGSSErrorEvent read FOnError write FOnError;
  end;


  TElGSSAPIContext = class (TElGSSCustomContext)
  public
    Context: gss_ctx_id_t;
  end;

  TElGSSAPIName = class (TElGSSCustomName)
  public
    ServiceName : Pointer;
  end;

  TElGSSAPIMechanism = class (TElGSSBaseMechanism)
  private
    FAcceptSecContext: gss_accept_sec_context;
    FAcquireCred: gss_acquire_cred;
    FDeleteSecContext: gss_delete_sec_context;
    FDisplayStatus : gss_display_status;
    FGetMic: gss_get_mic;
    FIndicateMechs: gss_indicate_mechs;
    FInitSecContext: gss_init_sec_context;
    FImportName: gss_import_name;
    FKRB5CCacheName : gss_krb5_ccache_name;
    FReleaseArray: gss_release_buffer;
    FReleaseCred: gss_release_cred;
    FReleaseName: gss_release_name;
    FReleaseOIDSet: gss_release_oid_set;
    FVerifyMic: gss_verify_mic;
    FKRB5CredentialCacheName : string;
    FRequestFlags : LongWord;

    FLibraryHandle : HMODULE;
    FLibraryName : string;

    (*
    {$ifndef NET_CF}{$ifdef NET_2_0_UP}
    [DllImport('kernel32.dll', CharSet {$ifndef SB_NET}={$else}:={$endif} CharSet.{$ifndef SB_NO_NET_PINVOKEAUTOCHARSET}Auto{$else}Unicode{$endif}, SetLastError {$ifndef SB_NET}={$else}:={$endif} True)]
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
    {$endif}
    class function LoadLibrary(dllname: string): IntPtr; external;

    [DllImport('kernel32.dll', CharSet {$ifndef SB_NET}={$else}:={$endif} CharSet.{$ifndef SB_NO_NET_PINVOKEAUTOCHARSET}Auto{$else}Unicode{$endif}, SetLastError {$ifndef SB_NET}={$else}:={$endif} True)]
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
    {$endif}
    class function FreeLibrary(hModule: IntPtr): Boolean; external;

    [DllImport('kernel32.dll', CharSet {$ifndef SB_NET}={$else}:={$endif} CharSet.Ansi,
      ExactSpelling {$ifndef SB_NET}={$else}:={$endif} True, SetLastError {$ifndef SB_NET}={$else}:={$endif} True)]
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
    {$endif}
    class function GetProcAddress(hModule: IntPtr; procname: string): IntPtr; external;
    {$endif}{$endif}
    *)

    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure IndicateMechs;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure SetLibraryName(const Value: string);

    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function KRB5CCacheName(const Name : string) : LongWord;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure SetKRB5CredentialCacheName(const Value : string);

    function SetStatus(Major: OM_uint32; Minor: OM_uint32): LongWord;

    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function ValidateFunctions: Boolean;
  protected
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure DoError(const Operation : string; MajorStatus, MinorStatus : LongWord;
      const MechOID : ByteArray); override;
  public
    constructor Create; override;
    destructor Destroy; override;

    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function Initialize : Boolean; override;

    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function AcquireCred(const MechOID: ByteArray; var Ctx: TElGSSCustomContext): LongWord; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function AcceptSecContext(Ctx: TElGSSCustomContext; SourceName : TElGSSCustomName;
      const InputToken : ByteArray; var OutputToken: ByteArray): LongWord; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function InitSecContext(Ctx: TElGSSCustomContext; TargetName : TElGSSCustomName; DelegateCred: Boolean;
      const InputToken : ByteArray; var OutputToken: ByteArray): LongWord; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function ReleaseContext(var Ctx: TElGSSCustomContext): LongWord; override;

    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function ImportName(const MechOID: ByteArray; const InputName: string;
      var OutputName: TElGSSCustomName): LongWord; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function ReleaseName(var Name: TElGSSCustomName): LongWord; override;

    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetMIC(Ctx: TElGSSCustomContext; const MessageBuffer: ByteArray;
      var MessageToken: ByteArray): LongWord; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function VerifyMIC(Ctx: TElGSSCustomContext; const MessageBuffer: ByteArray;
      const MessageToken: ByteArray): LongWord; override;

    property LibraryName: string read FLibraryName write SetLibraryName;

    property KRB5CredentialCacheName : string read FKRB5CredentialCacheName write SetKRB5CredentialCacheName;
    property RequestFlags : LongWord read FRequestFlags write FRequestFlags;

    property accept_sec_context: gss_accept_sec_context read FAcceptSecContext write FAcceptSecContext;
    property acquire_cred: gss_acquire_cred read FAcquireCred write FAcquireCred;
    property delete_sec_context: gss_delete_sec_context read FDeleteSecContext write FDeleteSecContext;
    property display_status : gss_display_status read FDisplayStatus write FDisplayStatus;
    property get_mic: gss_get_mic read FGetMic write FGetMic;
    property indicate_mechs: gss_indicate_mechs read FIndicateMechs write FIndicateMechs;
    property init_sec_context: gss_init_sec_context read FInitSecContext write FInitSecContext;
    property import_name: gss_import_name read FImportName write FImportName;
    property krb5_ccache_name : gss_krb5_ccache_name read FKRB5CCacheName write FKRB5CCacheName;
    property release_buffer: gss_release_buffer read FReleaseArray write FReleaseArray;
    property release_cred: gss_release_cred read FReleaseCred write FReleaseCred;
    property release_name: gss_release_name read FReleaseName write FReleaseName;
    property release_oid_set: gss_release_oid_set read FReleaseOIDSet write FReleaseOIDSet;
    property verify_mic: gss_verify_mic read FVerifyMic write FVerifyMic;
  end;

  TElGSSMechanismCollection = class (TElGSSBaseMechanism)
  protected
    FRegisteredMechClasses: TElList;

    function GetCount : Integer; override;
    function GetMechs(Index : Integer) : ByteArray; override;
    procedure HandleError(Sender :  TObject ;
      const Operation : string; MajorStatus, MinorStatus : LongWord;
      const MajorErrorMsg, MinorErrorMsg : string);
    function SetStatus(Major: LongWord; Minor: LongWord): LongWord;
  public
    constructor Create; override;
    destructor Destroy; override;

    function Initialize : Boolean; override;

    function GetMechByOID(const OID: ByteArray): TElGSSBaseMechanism;
    procedure RegisterMechanism(Mech: TElGSSBaseMechanism);
    procedure UnregisterMechanism(Mech: TElGSSBaseMechanism);

    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function AcquireCred(const MechOID: ByteArray; var Ctx: TElGSSCustomContext): LongWord; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function AcceptSecContext(Ctx: TElGSSCustomContext; SourceName : TElGSSCustomName;
      const InputToken : ByteArray; var OutputToken: ByteArray): LongWord; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function InitSecContext(Ctx: TElGSSCustomContext; TargetName : TElGSSCustomName; DelegateCred: Boolean;
      const InputToken : ByteArray; var OutputToken: ByteArray): LongWord; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function ReleaseContext(var Ctx: TElGSSCustomContext): LongWord; override;

    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function ImportName(const MechOID: ByteArray; const InputName: string;
      var OutputName: TElGSSCustomName): LongWord; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function ReleaseName(var Name: TElGSSCustomName): LongWord; override;

    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetMIC(Ctx: TElGSSCustomContext; const MessageBuffer: ByteArray;
      var MessageToken: ByteArray): LongWord; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function VerifyMIC(Ctx: TElGSSCustomContext; const MessageBuffer: ByteArray;
      const MessageToken: ByteArray): LongWord; override;

    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function IsMechSupported(const OID: ByteArray): Boolean; override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function IsIntegrityAvailable(Ctx: TElGSSCustomContext): Boolean; override;
  end;

{$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
 {$else}
var
 {$endif}

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS OFF}
 {$endif}

  GSS_C_NT_HOSTBASED_SERVICE_OID : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = #$2B#$06#$01#$05#$06#$02 {$endif}; 
  GSS_KRB5_NT_PRINCIPAL_NAME_OID : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = #$2A#$86#$48#$86#$F7#$12#$01#$02#$02#$01 {$endif}; 

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS ON}
 {$endif}


{$ifndef NET_CF}{$ifdef NET_2_0_UP}
[DllImport('kernel32.dll', CharSet  =  CharSet.{$ifndef SB_NO_NET_PINVOKEAUTOCHARSET}Auto {$else}Unicode {$endif}, SetLastError  =  True)]
{$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
[SecuritySafeCritical]
 {$endif}
function LoadLibrary(dllname: string): IntPtr; external;

[DllImport('kernel32.dll', CharSet  =  CharSet.{$ifndef SB_NO_NET_PINVOKEAUTOCHARSET}Auto {$else}Unicode {$endif}, SetLastError  =  True)]
{$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
[SecuritySafeCritical]
 {$endif}
function FreeLibrary(hModule: IntPtr): Boolean; external;

[DllImport('kernel32.dll', CharSet  =  CharSet.Ansi,
  ExactSpelling  =  True, SetLastError  =  True)]
{$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
[SecuritySafeCritical]
 {$endif}
function GetProcAddress(hModule: IntPtr; procname: string): IntPtr; external;
 {$endif} {$endif}


 {$endif SB_GSSAPI}

{$ifndef SB_FPC_GEN}
implementation
 {$endif}

{$ifdef SB_GSSAPI}
{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
{$ifdef SB_UNICODE_VCL}
  {$WARNINGS OFF}
 {$endif}
const
  GSS_C_NT_HOSTBASED_SERVICE_OID_STR = #$2B#$06#$01#$05#$06#$02;
  GSS_KRB5_NT_PRINCIPAL_NAME_OID_STR = #$2A#$86#$48#$86#$F7#$12#$01#$02#$02#$01;
{$ifdef SB_UNICODE_VCL}
  {$WARNINGS ON}
 {$endif}
 {$endif}
 {$endif}

{$ifdef SB_FPC_GEN}
implementation
 {$endif}

{$ifdef SB_GSSAPI}

{ TElGSSBase }

constructor TElGSSBaseMechanism.Create;
begin
  inherited;
  FMechOIDs := TElByteArrayList.Create;
  FMechHashes := TElByteArrayList.Create;
end;

destructor TElGSSBaseMechanism.Destroy;
begin
  FreeAndNil(FMechOIDs);
  FreeAndNil(FMechHashes);
  inherited;
end;

procedure TElGSSBaseMechanism.DoError(const Operation : string;
  MajorStatus, MinorStatus : LongWord; const MechOID : ByteArray);
begin
  if Assigned(FOnError) then
    FOnError(Self, Operation, MajorStatus, MinorStatus, '', '');
end;

procedure TElGSSBaseMechanism.DoError(const Operation : string;
  MajorStatus, MinorStatus : LongWord;
  const MajorErrorMsg, MinorErrorMsg : string);
begin
  if Assigned(FOnError) then
    FOnError(Self, Operation, MajorStatus, MinorStatus, MajorErrorMsg, MinorErrorMsg);
end;

function TElGSSBaseMechanism.GetLastMajorStatus: LongWord;
begin
  Result := FMajorStatus;
end;

function TElGSSBaseMechanism.GetLastMinorStatus: LongWord;
begin
  Result := FMinorStatus;
end;

function TElGSSBaseMechanism.GetCount : Integer;
begin
  Result := FMechOIDs.Count;
end;

function TElGSSBaseMechanism.GetMechOIDByHash(const Hash: ByteArray): ByteArray;
var
  i: Integer;
begin
  SetLength(Result, 0);
  if FMechHashes.Count <> FMechOIDs.Count then
    RecalculateMechHashes;

  for i := 0 to FMechHashes.Count - 1 do
    if CompareContent(Hash, FMechHashes.Item[i]) then
    begin
      Result := CloneArray(FMechOIDs.Item[i]);
      Break;
    end;
end;

function TElGSSBaseMechanism.GetMechs(Index : Integer) : ByteArray;
begin
  Result := CloneArray(FMechOIDs.Item[Index]);
end;

function TElGSSBaseMechanism.IsIntegrityAvailable(Ctx: TElGSSCustomContext): Boolean;
begin
  Result := Assigned(Ctx) and ((Ctx.ResponseFlags and GSS_C_INTEG_FLAG) > 0);
end;

function TElGSSBaseMechanism.IsMutualAvailable(Ctx: TElGSSCustomContext): Boolean;
begin
  Result := Assigned(Ctx) and ((Ctx.ResponseFlags and GSS_C_MUTUAL_FLAG) > 0);
end;

function TElGSSBaseMechanism.IsMechSupported(const OID: ByteArray): Boolean;
var
  i: Integer;
begin
  Result := False;
  for i := 0 to FMechOIDs.Count - 1 do
    if CompareContent(OID, FMechOIDs.Item[i]) then
    begin
      Result := True;
      Exit;
    end;

  if FMechHashes.Count <> FMechOIDs.Count then
    RecalculateMechHashes;

  for i := 0 to FMechHashes.Count - 1 do
    if CompareContent(OID, FMechHashes.Item[i]) then
    begin
      Result := True;
      Exit;
    end;
end;

procedure TElGSSBaseMechanism.RecalculateMechHashes;
var
  M128 : TMessageDigest128;
  Hash : ByteArray;
  i: Integer;
begin
  FMechHashes.Clear;
  SetLength(Hash, 16);
  for i := 0 to FMechOIDs.Count - 1 do
  begin
    M128 := HashMD5(EncodeMechOID(FMechOIDs.Item[i]));
    SBMove(M128, Hash[0], 16);
    FMechHashes.Add(CloneArray(Hash));
  end;
end;

{ TElGSSMechanismCollection }

function TElGSSMechanismCollection.AcceptSecContext(
  Ctx: TElGSSCustomContext; SourceName: TElGSSCustomName;
  const InputToken: ByteArray; var OutputToken: ByteArray): LongWord;
var
  Mech : TElGSSBaseMechanism;
begin
  if not Assigned(Ctx) or not Assigned(SourceName) or
     not CompareContent(Ctx.MechOID, SourceName.MechOID) then
  begin
    Result := SetStatus(GSS_S_NO_CONTEXT, 0);
    Exit;
  end;

  Mech := GetMechByOID(Ctx.MechOID);
  if not Assigned(Mech) then
  begin
    Result := SetStatus(GSS_S_BAD_MECH, 0);
    Exit;
  end;

  Result := Mech.AcceptSecContext(Ctx, SourceName, InputToken, OutputToken);
  SetStatus(Mech.FMajorStatus, Mech.FMinorStatus);
end;

function TElGSSMechanismCollection.AcquireCred(const MechOID: ByteArray;
  var Ctx: TElGSSCustomContext): LongWord;
var
  Mech : TElGSSBaseMechanism;
begin
  Mech := GetMechByOID(MechOID);
  if not Assigned(Mech) then
  begin
    Result := SetStatus(GSS_S_BAD_MECH, 0);
    Exit;
  end;

  Result := Mech.AcquireCred(MechOID, Ctx);
  SetStatus(Mech.FMajorStatus, Mech.FMinorStatus);
end;

constructor TElGSSMechanismCollection.Create;
begin
  inherited;
  FRegisteredMechClasses := TElList.Create;
end;

destructor TElGSSMechanismCollection.Destroy;
var
  i: Integer;
begin
  for i := 0 to FRegisteredMechClasses.Count - 1 do
    TElGSSBaseMechanism(FRegisteredMechClasses[i]). Free ;

  FreeAndNil(FRegisteredMechClasses);
  inherited;
end;

function TElGSSMechanismCollection.GetCount: Integer;
var
  i: Integer;
begin
  Result := 0;
  for i := 0 to FRegisteredMechClasses.Count - 1 do
    Result := Result + TElGSSBaseMechanism(FRegisteredMechClasses[i]).Count;
end;

function TElGSSMechanismCollection.GetMechByOID(const OID: ByteArray): TElGSSBaseMechanism;
var
  i: Integer;
begin
  Result := nil;
  for i := 0 to FRegisteredMechClasses.Count - 1 do
    if TElGSSBaseMechanism(FRegisteredMechClasses[i]).IsMechSupported(OID) then
    begin
      Result := TElGSSBaseMechanism(FRegisteredMechClasses[i]);
      Break;
    end;
end;

function TElGSSMechanismCollection.GetMechs(Index: Integer): ByteArray;
var
  i: Integer;
begin
  Result := EmptyArray;
  for i := 0 to FRegisteredMechClasses.Count - 1 do
  begin
    if Index >= TElGSSBaseMechanism(FRegisteredMechClasses[i]).Count then
      Index := Index - TElGSSBaseMechanism(FRegisteredMechClasses[i]).Count
    else
    begin
      Result := TElGSSBaseMechanism(FRegisteredMechClasses[i]).Mechs[Index];
      Exit;
    end;
  end;
end;

function TElGSSMechanismCollection.GetMIC(Ctx: TElGSSCustomContext;
  const MessageBuffer: ByteArray; var MessageToken: ByteArray): LongWord;
var
  Mech : TElGSSBaseMechanism;
begin
  if not Assigned(Ctx) then
  begin
    Result := SetStatus(GSS_S_NO_CONTEXT, 0);
    Exit;
  end;

  Mech := GetMechByOID(Ctx.MechOID);
  if not Assigned(Mech) then
  begin
    Result := SetStatus(GSS_S_BAD_MECH, 0);
    Exit;
  end;

  Result := Mech.GetMIC(Ctx, MessageBuffer, MessageToken);
  SetStatus(Mech.FMajorStatus, Mech.FMinorStatus);
end;

procedure TElGSSMechanismCollection.HandleError(Sender :  TObject ;
   const Operation : string; MajorStatus, MinorStatus : LongWord; const MajorErrorMsg, MinorErrorMsg : string);
begin
  if Assigned(FOnError) then
    FOnError(Sender, Operation, MajorStatus, MinorStatus, MajorErrorMsg, MinorErrorMsg);
end;

function TElGSSMechanismCollection.ImportName(const MechOID: ByteArray;
  const InputName: string; var OutputName: TElGSSCustomName): LongWord;
var
  Mech : TElGSSBaseMechanism;
begin
  Mech := GetMechByOID(MechOID);
  if not Assigned(Mech) then
  begin
    Result := SetStatus(GSS_S_BAD_MECH, 0);
    Exit;
  end;

  Result := Mech.ImportName(MechOID, InputName, OutputName);
  SetStatus(Mech.FMajorStatus, Mech.FMinorStatus);
end;

function TElGSSMechanismCollection.Initialize: Boolean;
var
  i: Integer;
begin
  Result := False;
  for i := 0 to FRegisteredMechClasses.Count - 1 do
    Result := Result or TElGSSBaseMechanism(FRegisteredMechClasses[i]).Initialize;
end;

function TElGSSMechanismCollection.InitSecContext(Ctx: TElGSSCustomContext;
  TargetName: TElGSSCustomName; DelegateCred: Boolean;
  const InputToken: ByteArray; var OutputToken: ByteArray): LongWord;
var
  Mech : TElGSSBaseMechanism;
begin
  if not Assigned(Ctx) or not Assigned(TargetName) or
     not CompareContent(Ctx.MechOID, TargetName.MechOID) then
  begin
    Result := SetStatus(GSS_S_NO_CONTEXT, 0);
    Exit;
  end;

  Mech := GetMechByOID(Ctx.MechOID);
  if not Assigned(Mech) then
  begin
    Result := SetStatus(GSS_S_BAD_MECH, 0);
    Exit;
  end;

  Result := Mech.InitSecContext(Ctx, TargetName, DelegateCred, InputToken, OutputToken);
  SetStatus(Mech.FMajorStatus, Mech.FMinorStatus);
end;

function TElGSSMechanismCollection.IsIntegrityAvailable(
  Ctx: TElGSSCustomContext): Boolean;
var
  Mech : TElGSSBaseMechanism;
begin
  Result := False;
  if not Assigned(Ctx) then
    Exit;

  Mech := GetMechByOID(Ctx.MechOID);
  if not Assigned(Mech) then
    Exit;

  Result := Mech.IsIntegrityAvailable(Ctx);
end;

function TElGSSMechanismCollection.IsMechSupported(const OID: ByteArray): Boolean;
var
  i: Integer;
begin
  Result := False;
  for i := 0 to FRegisteredMechClasses.Count - 1 do
    if TElGSSBaseMechanism(FRegisteredMechClasses[i]).IsMechSupported(OID) then
    begin
      Result := True;
      Exit;
    end;
end;

procedure TElGSSMechanismCollection.RegisterMechanism(Mech: TElGSSBaseMechanism);
begin
  if not Assigned(Mech) then
    Exit;

  FRegisteredMechClasses.Add(Mech);
  Mech.OnError := HandleError;
end;

function TElGSSMechanismCollection.ReleaseContext(
  var Ctx: TElGSSCustomContext): LongWord;
var
  Mech : TElGSSBaseMechanism;
begin
  if not Assigned(Ctx) then
  begin
    Result := SetStatus(GSS_S_NO_CONTEXT, 0);
    Exit;
  end;

  Mech := GetMechByOID(Ctx.MechOID);
  if not Assigned(Mech) then
  begin
    Result := SetStatus(GSS_S_BAD_MECH, 0);
    Exit;
  end;

  Result := Mech.ReleaseContext(Ctx);
  SetStatus(Mech.FMajorStatus, Mech.FMinorStatus);
end;

function TElGSSMechanismCollection.ReleaseName(
  var Name: TElGSSCustomName): LongWord;
var
  Mech : TElGSSBaseMechanism;
begin
  if not Assigned(Name) then
  begin
    Result := SetStatus(GSS_S_NO_CONTEXT, 0);
    Exit;
  end;

  Mech := GetMechByOID(Name.MechOID);
  if not Assigned(Mech) then
  begin
    Result := SetStatus(GSS_S_BAD_MECH, 0);
    Exit;
  end;

  Result := Mech.ReleaseName(Name);
  SetStatus(Mech.FMajorStatus, Mech.FMinorStatus);
end;

function TElGSSMechanismCollection.SetStatus(Major: LongWord; Minor: LongWord): LongWord;
begin
  FMajorStatus := Major;
  FMinorStatus := Minor;
  Result := FMajorStatus;
end;

procedure TElGSSMechanismCollection.UnregisterMechanism(Mech: TElGSSBaseMechanism);
begin
  if not Assigned(Mech) then
    Exit;

  Mech.OnError := nil;
  FRegisteredMechClasses.Remove(Mech);
end;

function TElGSSMechanismCollection.VerifyMIC(Ctx: TElGSSCustomContext;
  const MessageBuffer, MessageToken: ByteArray): LongWord;
var
  Mech : TElGSSBaseMechanism;
begin
  if not Assigned(Ctx) then
  begin
    Result := SetStatus(GSS_S_NO_CONTEXT, 0);
    Exit;
  end;

  Mech := GetMechByOID(Ctx.MechOID);
  if not Assigned(Mech) then
  begin
    Result := SetStatus(GSS_S_BAD_MECH, 0);
    Exit;
  end;

  Result := Mech.VerifyMIC(Ctx, MessageBuffer, MessageToken);
  SetStatus(Mech.FMajorStatus, Mech.FMinorStatus);
end;

{ TElGSSAPIMechanism }

function TElGSSAPIMechanism.AcceptSecContext(Ctx: TElGSSCustomContext;
  SourceName: TElGSSCustomName; const InputToken: ByteArray;
  var OutputToken: ByteArray): LongWord;
begin
  Result := SetStatus(GSS_S_FAILURE, 0);
  if FMajorStatus = GSS_S_FAILURE then
    DoError('gss_accept_sec_context', FMajorStatus, FMinorStatus, Ctx.MechOID);
end;

function TElGSSAPIMechanism.AcquireCred(const MechOID: ByteArray;
  var Ctx: TElGSSCustomContext): LongWord;
var
  OID: ByteArray;
begin
  OID := GetMechOIDByHash(MechOID);
  if Length(OID) = 0 then
    OID := MechOID;

  Ctx := TElGSSAPIContext.Create;
  Ctx.MechOID  := CloneArray(OID);
  Ctx.RequestFlags := FRequestFlags;
  Ctx.ResponseFlags := 0;
  TElGSSAPIContext(Ctx).Context := GSS_C_NO_CONTEXT;
  Result := SetStatus(GSS_S_COMPLETE, 0);
end;

constructor TElGSSAPIMechanism.Create;
begin
  inherited;
  FLibraryHandle := 0;
  FRequestFlags := GSS_C_MUTUAL_FLAG or GSS_C_INTEG_FLAG;
end;

destructor TElGSSAPIMechanism.Destroy;
begin
  if FLibraryHandle <> 0 then
  begin
    {$ifndef FPC_UNIX}FreeLibrary {$else}UnloadLibrary {$endif}(FLibraryHandle);
    FLibraryHandle := 0;
  end;

  inherited;
end;




procedure TElGSSAPIMechanism.DoError(const Operation : string;
  MajorStatus, MinorStatus : LongWord; const MechOID : ByteArray);
var
  Buf: gss_buffer_desc;
  OID: gss_OID_desc;
  pOID : gss_OID;
  Str : ByteArray;
  MajorErrorMsg, MinorErrorMsg : string;
  maj_status, min_status : LongWord;
  ctx : LongWord;
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  if not Assigned(FOnError) then
    Exit;

  MajorErrorMsg := '';
  MinorErrorMsg := '';
  if Assigned(FDisplayStatus) then
  begin
    ctx := 0;
    if Length(MechOID) > 0 then
    begin
      OID.elements := PAnsiChar(MechOID);
      OID.length := Length(MechOID);
      pOID := @OID;
    end
    else
      pOID := GSS_C_NO_OID;

    repeat
      Buf.length := 0;
      Buf.value := nil;
      maj_status := FDisplayStatus(min_status, MajorStatus, GSS_C_GSS_CODE, pOID, ctx, @Buf);
      if maj_status <> GSS_S_COMPLETE then
        Break;

      SetLength(Str, Buf.length);
      SBMove(Buf.value^, Str[0], Buf.length);
      if (Length(MajorErrorMsg) > 0) and (Length(Str) > 0) then
        MajorErrorMsg := MajorErrorMsg + CRLFStr;

      MajorErrorMsg := MajorErrorMsg +  StringOfBytes (Str);
      maj_status := FReleaseArray(min_status, @Buf);
      if maj_status <> GSS_S_COMPLETE then
        Break;
    until ctx = 0;

    ctx := 0;
    repeat
      Buf.length := 0;
      Buf.value := nil;
      maj_status := FDisplayStatus(min_status, MinorStatus, GSS_C_MECH_CODE, pOID, ctx, @Buf);
      if maj_status <> GSS_S_COMPLETE then
        Break;

      SetLength(Str, Buf.length);
      SBMove(Buf.value^, Str[0], Buf.length);
      if (Length(MinorErrorMsg) > 0) and (Length(Str) > 0) then
        MinorErrorMsg := MinorErrorMsg + CRLFStr;

      MinorErrorMsg := MinorErrorMsg +  StringOfBytes (Str);

      maj_status := FReleaseArray(min_status,  @ Buf);
      if maj_status <> GSS_S_COMPLETE then
        Break;
    until ctx = 0;

  end;

  DoError(Operation, MajorStatus, MinorStatus, MajorErrorMsg, MinorErrorMsg);
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

function TElGSSAPIMechanism.GetMIC(Ctx: TElGSSCustomContext;
  const MessageBuffer: ByteArray; var MessageToken: ByteArray): LongWord;
var
  APICtx : TElGSSAPIContext;
  msg_buf, msg_tok : gss_buffer_desc;
  min_status, maj_status : OM_uint32;
begin
  if not (Ctx is TElGSSAPIContext) then
  begin
    SetLength(MessageToken, 0);
    Result := SetStatus(GSS_S_NO_CONTEXT, 0);
    DoError('GetMic', FMajorStatus, FMinorStatus, EmptyArray);
    Exit;
  end;

  if not ValidateFunctions() then
  begin
    SetLength(MessageToken, 0);
    Result := FMajorStatus;
    Exit;
  end;

  APICtx := TElGSSAPIContext(Ctx);
  msg_buf.value := @MessageBuffer[0];
  msg_buf.length := Length(MessageBuffer);
  msg_tok.value := nil;
  msg_tok.length := 0;

  FMajorStatus := FGetMic(FMinorStatus, APICtx.Context, 0, @msg_buf, @msg_tok);
  if FMajorStatus = GSS_S_FAILURE then
    DoError('gss_get_mic', FMajorStatus, FMinorStatus, APICtx.MechOID);

  SetLength(MessageToken, msg_tok.length);
  if msg_tok.length > 0 then
  begin
    SBMove(msg_tok.value^, MessageToken[0], Length(MessageToken));
    maj_status := FReleaseArray(min_status, @msg_tok);
    if maj_status = GSS_S_FAILURE then
      DoError('gss_release_buffer', maj_status, min_status, APICtx.MechOID);

    if (FMajorStatus = GSS_S_COMPLETE) and (maj_status = GSS_S_FAILURE) then
    begin
      Result := SetStatus(maj_status, min_status);
      Exit;
    end;
  end;

  Result := FMajorStatus;
end;

function TElGSSAPIMechanism.ImportName(const MechOID: ByteArray;
  const InputName: string; var OutputName: TElGSSCustomName): LongWord;
var
  Buf: gss_buffer_desc;
  OID: gss_OID_desc;
  OutName: gss_name_t;
  TmpName: AnsiString;
  TmpOID: ByteArray;
begin
  if not ValidateFunctions() then
  begin
    Result := FMajorStatus;
    Exit;
  end;

  TmpName := {$ifdef SB_UNICODE_VCL}AnsiString {$endif}(InputName);
  if StringIndexOf({$ifdef SB_UNICODE_VCL}string {$endif}(TmpName), '@') < StringStartOffset then
    TmpName := 'host@' +
      TmpName;

  Buf.value := PAnsiChar(TmpName);
  Buf.length := Length(TmpName);

  if  Copy ((TmpName), StringStartOffset, 6) = 'krbtgt' then
  begin
    OID.elements := PAnsiChar(GSS_KRB5_NT_PRINCIPAL_NAME_OID);
    OID.length := Length(GSS_KRB5_NT_PRINCIPAL_NAME_OID);
  end
  else
  begin
    OID.elements := PAnsiChar(GSS_C_NT_HOSTBASED_SERVICE_OID);
    OID.length := Length(GSS_C_NT_HOSTBASED_SERVICE_OID);
  end;

  FMajorStatus := FImportName(FMinorStatus, @Buf, @OID, OutName);
  TmpName := '';

  TmpOID := GetMechOIDByHash(MechOID);
  if Length(TmpOID) = 0 then
    TmpOID := MechOID;

  Result := FMajorStatus;
  if FMajorStatus <> GSS_S_COMPLETE then
  begin
    DoError('gss_import_name', FMajorStatus, FMinorStatus, TmpOID);
    Exit;
  end;

  OutputName := TElGSSAPIName.Create;
  OutputName.MechOID := CloneArray(TmpOID);
  TElGSSAPIName(OutputName).ServiceName := OutName;
end;

procedure TElGSSAPIMechanism.IndicateMechs;
type
  AOIDs = array[0..0] of gss_OID_desc;
  PAOIDs = ^AOIDs;
var
  mech_set: gss_OID_set;
  OIDs : PAOIDs;
  OID : ByteArray;
  min_status, maj_status : OM_uint32;
  i: Integer;
begin
  mech_set := nil;
  FMajorStatus := FIndicateMechs(FMinorStatus, mech_set);
  if FMajorStatus = GSS_S_COMPLETE then
  begin
    OIDs := PAOIDs(mech_set.elements);
    for i := 0 to mech_set.count - 1 do
    begin
      SetLength(OID, OIDs[i].length);
      SBMove(OIDs[i].elements^, OID[0], Length(OID));
      FMechOIDs.Add(OID);
    end;
  end
  else
    DoError('gss_indicate_mechs', FMajorStatus, FMinorStatus, EmptyArray);

  maj_status := FReleaseOIDSet(min_status, mech_set);
  if maj_status = GSS_S_FAILURE then
    DoError('gss_release_oid_set', maj_status, min_status, EmptyArray);

  if (FMajorStatus = GSS_S_COMPLETE) and (maj_status = GSS_S_FAILURE) then
    SetStatus(maj_status, min_status);
end;

function TElGSSAPIMechanism.Initialize: Boolean;
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  if (Length(FLibraryName) > 0) and (FLibraryHandle = 0) then
  begin
    FLibraryHandle := LoadLibrary({$ifdef SB_WINCE}PWideChar(WideString(FLibraryName)) {$else}PChar(FLibraryName) {$endif});

    if FLibraryHandle <> 0 then
    begin
      if not Assigned(FAcceptSecContext) then
        FAcceptSecContext := gss_accept_sec_context({$ifdef DELPHI_MAC}GetProcAddress {$else}{$ifdef SB_WINDOWS}GetProcAddress {$else}GetProcedureAddress {$endif} {$endif}(FLibraryHandle, 'gss_accept_sec_context'));
      if not Assigned(FAcquireCred) then
        FAcquireCred := gss_acquire_cred({$ifdef DELPHI_MAC}GetProcAddress {$else}{$ifdef SB_WINDOWS}GetProcAddress {$else}GetProcedureAddress {$endif} {$endif}(FLibraryHandle, 'gss_acquire_cred'));
      if not Assigned(FDeleteSecContext) then
        FDeleteSecContext := gss_delete_sec_context({$ifdef DELPHI_MAC}GetProcAddress {$else}{$ifdef SB_WINDOWS}GetProcAddress {$else}GetProcedureAddress {$endif} {$endif}(FLibraryHandle, 'gss_delete_sec_context'));
      if not Assigned(FDisplayStatus) then
        FDisplayStatus := gss_display_status({$ifdef DELPHI_MAC}GetProcAddress {$else}{$ifdef SB_WINDOWS}GetProcAddress {$else}GetProcedureAddress {$endif} {$endif}(FLibraryHandle, 'gss_display_status'));
      if not Assigned(FGetMic) then
        FGetMic := gss_get_mic({$ifdef DELPHI_MAC}GetProcAddress {$else}{$ifdef SB_WINDOWS}GetProcAddress {$else}GetProcedureAddress {$endif} {$endif}(FLibraryHandle, 'gss_get_mic'));
      if not Assigned(FIndicateMechs) then
        FIndicateMechs := gss_indicate_mechs({$ifdef DELPHI_MAC}GetProcAddress {$else}{$ifdef SB_WINDOWS}GetProcAddress {$else}GetProcedureAddress {$endif} {$endif}(FLibraryHandle, 'gss_indicate_mechs'));
      if not Assigned(FInitSecContext) then
        FInitSecContext := gss_init_sec_context({$ifdef DELPHI_MAC}GetProcAddress {$else}{$ifdef SB_WINDOWS}GetProcAddress {$else}GetProcedureAddress {$endif} {$endif}(FLibraryHandle, 'gss_init_sec_context'));
      if not Assigned(FImportName) then
        FImportName := gss_import_name({$ifdef DELPHI_MAC}GetProcAddress {$else}{$ifdef SB_WINDOWS}GetProcAddress {$else}GetProcedureAddress {$endif} {$endif}(FLibraryHandle, 'gss_import_name'));
      if not Assigned(FKRB5CCacheName) then
        FKRB5CCacheName := gss_krb5_ccache_name({$ifdef DELPHI_MAC}GetProcAddress {$else}{$ifdef SB_WINDOWS}GetProcAddress {$else}GetProcedureAddress {$endif} {$endif}(FLibraryHandle, 'gss_krb5_ccache_name'));
      if not Assigned(FReleaseArray) then
        FReleaseArray := gss_release_buffer({$ifdef DELPHI_MAC}GetProcAddress {$else}{$ifdef SB_WINDOWS}GetProcAddress {$else}GetProcedureAddress {$endif} {$endif}(FLibraryHandle, 'gss_release_buffer'));
      if not Assigned(FReleaseCred) then
        FReleaseCred := gss_release_cred({$ifdef DELPHI_MAC}GetProcAddress {$else}{$ifdef SB_WINDOWS}GetProcAddress {$else}GetProcedureAddress {$endif} {$endif}(FLibraryHandle, 'gss_release_cred'));
      if not Assigned(FReleaseName) then
        FReleaseName := gss_release_name({$ifdef DELPHI_MAC}GetProcAddress {$else}{$ifdef SB_WINDOWS}GetProcAddress {$else}GetProcedureAddress {$endif} {$endif}(FLibraryHandle, 'gss_release_name'));
      if not Assigned(FReleaseOIDSet) then
        FReleaseOIDSet := gss_release_oid_set({$ifdef DELPHI_MAC}GetProcAddress {$else}{$ifdef SB_WINDOWS}GetProcAddress {$else}GetProcedureAddress {$endif} {$endif}(FLibraryHandle, 'gss_release_oid_set'));
      if not Assigned(FVerifyMic) then
        FVerifyMic := gss_verify_mic({$ifdef DELPHI_MAC}GetProcAddress {$else}{$ifdef SB_WINDOWS}GetProcAddress {$else}GetProcedureAddress {$endif} {$endif}(FLibraryHandle, 'gss_verify_mic'));
    end
    else
    begin
      SetStatus(GSS_S_FAILURE, {$ifndef FPC}GetLastError() {$else}{$ifdef SB_WINDOWS}GetLastError() {$else}errno {$endif} {$endif});
      Result := False;
      Exit;
    end;
  end
  else  
  begin
    Result := ValidateFunctions;
    Exit;
  end;

  Result := ValidateFunctions;
  if Result then
  begin
    IndicateMechs;

    if Length(FKRB5CredentialCacheName) > 0 then
    begin
      KRB5CCacheName(FKRB5CredentialCacheName)
    end;
  end;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

function TElGSSAPIMechanism.InitSecContext(Ctx: TElGSSCustomContext;
  TargetName: TElGSSCustomName; DelegateCred: Boolean;
  const InputToken: ByteArray; var OutputToken: ByteArray): LongWord;
var
  APICtx : TElGSSAPIContext;
  TargetAPIName : TElGSSAPIName;
  OID: gss_OID_desc;
  input_tok, output_tok: gss_buffer_desc;
  req_flags, ret_flags : OM_uint32;
  min_status, maj_status, time_rec : OM_uint32;
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  if not (Ctx is TElGSSAPIContext) or not (TargetName is TElGSSAPIName) then
  begin
    SetLength(OutputToken, 0);
    Result := SetStatus(GSS_S_NO_CONTEXT, 0);
    DoError('InitSecContext', FMajorStatus, FMinorStatus, EmptyArray);
    Exit;
  end;

  if not ValidateFunctions() then
  begin
    SetLength(OutputToken, 0);
    Result := FMajorStatus;
    Exit;
  end;

  APICtx := TElGSSAPIContext(Ctx);
  TargetAPIName := TElGSSAPIName(TargetName);

  req_flags := Ctx.RequestFlags;
  if DelegateCred then
    req_flags := req_flags or GSS_C_DELEG_FLAG;

  OID.elements := PAnsiChar(APICtx.MechOID);
  OID.length := Length(APICtx.MechOID);
  output_tok.value := nil;
  output_tok.length := 0;

  if Length(InputToken) > 0 then
  begin
    input_tok.value := @InputToken[0];
    input_tok.length := Length(InputToken);
  end
  else
  begin
    input_tok.value := nil;
    input_tok.length := 0;
  end;

  FMajorStatus := FInitSecContext(FMinorStatus, GSS_C_NO_CREDENTIAL, APICtx.Context,
    TargetAPIName.ServiceName, @OID, req_flags, 0, GSS_C_NO_CHANNEL_BINDINGS,
    @input_tok, nil, @output_tok, ret_flags, time_rec);

  if FMajorStatus = GSS_S_FAILURE then
    DoError('gss_init_sec_context', FMajorStatus, FMinorStatus, APICtx.MechOID);

  Ctx.ResponseFlags := ret_flags;
  SetLength(OutputToken, output_tok.length);
  if output_tok.length <> 0 then
  begin
    SBMove(output_tok.value^, OutputToken[0], Length(OutputToken));
    maj_status := FReleaseArray(min_status, @output_tok);
    if maj_status = GSS_S_FAILURE then
      DoError('gss_release_buffer', maj_status, min_status, APICtx.MechOID);

    if ((FMajorStatus = GSS_S_COMPLETE) or (FMajorStatus = GSS_S_CONTINUE_NEEDED)) and
       (maj_status = GSS_S_FAILURE) then
    begin
      Result := SetStatus(maj_status, min_status);
      Exit;
    end;
  end;


  Result := FMajorStatus;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

function TElGSSAPIMechanism.KRB5CCacheName(const Name : string) : LongWord;
var
  Tmp : ByteArray;
begin
  if Assigned(FKRB5CCacheName) then
  begin
    if Length(Name) > 0 then
    begin
      Tmp := BytesOfString(Name);
      FMajorStatus := FKRB5CCacheName(FMinorStatus, @Tmp[0], nil)
    end
    else
      FMajorStatus := FKRB5CCacheName(FMinorStatus, nil, nil);

    if FMajorStatus <> GSS_S_COMPLETE then
      DoError('gss_krb_ccache_name', FMajorStatus, FMinorStatus, EmptyArray);

    Result := FMajorStatus;
  end
  else
  begin
    Result := GSS_S_FAILURE;
  end;
end;

function TElGSSAPIMechanism.ReleaseContext(var Ctx: TElGSSCustomContext): LongWord;
var
  APICtx : TElGSSAPIContext;
begin
  if not (Ctx is TElGSSAPIContext) then
  begin
    Result := SetStatus(GSS_S_NO_CONTEXT, 0);
    DoError('ReleaseContext', FMajorStatus, FMinorStatus, EmptyArray);
    Exit;
  end;

  if not ValidateFunctions() then
  begin
    Result := FMajorStatus;
    Exit;
  end;

  APICtx := TElGSSAPIContext(Ctx);
  if APICtx.Context <> GSS_C_NO_CONTEXT then
  begin
    FMajorStatus := FDeleteSecContext(FMinorStatus, APICtx.Context, GSS_C_NO_BUFFER);

    if FMajorStatus = GSS_S_FAILURE then
      DoError('gss_delete_sec_context', FMajorStatus, FMinorStatus, APICtx.MechOID);
  end;

  FreeAndNil(Ctx);
  Result := FMajorStatus;
end;

function TElGSSAPIMechanism.ReleaseName(var Name: TElGSSCustomName): LongWord;
begin
  if not ValidateFunctions() then
  begin
    Result := FMajorStatus;
    Exit;
  end;

  if not (Name is TElGSSAPIName) then
  begin
    Result := SetStatus(GSS_S_FAILURE, 0);
    DoError('ReleaseName', FMajorStatus, FMinorStatus, EmptyArray);
    Exit;
  end;

  FMajorStatus := FReleaseName(FMinorStatus, TElGSSAPIName(Name).ServiceName);
  if FMajorStatus = GSS_S_FAILURE then
    DoError('gss_release_name', FMajorStatus, FMinorStatus, Name.MechOID);

  FreeAndNil(Name);
  Result := FMajorStatus;
end;

procedure TElGSSAPIMechanism.SetKRB5CredentialCacheName(const Value : string);
begin
  if FKRB5CredentialCacheName = Value then
    Exit;

  FKRB5CredentialCacheName := Value;
  KRB5CCacheName(FKRB5CredentialCacheName);
end;

procedure TElGSSAPIMechanism.SetLibraryName(const Value: string);
begin
  FLibraryName := Value;

  if FLibraryHandle <> 0 then
  begin
    FAcceptSecContext := nil;
    FAcquireCred := nil;
    FDeleteSecContext := nil;
    FDeleteSecContext := nil;
    FGetMic := nil;
    FIndicateMechs := nil;
    FInitSecContext := nil;
    FImportName := nil;
    FKRB5CCacheName := nil;
    FReleaseArray := nil;
    FReleaseCred := nil;
    FReleaseName := nil;
    FReleaseOIDSet := nil;
    FVerifyMic := nil;

    {$ifndef FPC_UNIX}FreeLibrary {$else}UnloadLibrary {$endif}(FLibraryHandle);
    FLibraryHandle := 0;
  end;
end;

function TElGSSAPIMechanism.SetStatus(Major, Minor: OM_uint32): LongWord;
begin
  FMajorStatus := Major;
  FMinorStatus := Minor;
  Result := FMajorStatus;
end;

function TElGSSAPIMechanism.ValidateFunctions: Boolean;
begin
  Result := True;
  if not Assigned(FAcceptSecContext) or {not Assigned(FAcquireCred) or}
     not Assigned(FDeleteSecContext) or not Assigned(FGetMic) or
     not Assigned(FIndicateMechs) or not Assigned(FInitSecContext) or
     not Assigned(FImportName) or not Assigned(FReleaseArray) or
     {not Assigned(FReleaseCred) or} not Assigned(FReleaseName) or
     not Assigned(FReleaseOIDSet) or not Assigned(FVerifyMic) then
  begin
    SetStatus(GSS_S_FAILURE, 0);
    DoError('ValidateFunctions', FMajorStatus, FMinorStatus, EmptyArray);
    Result := False;
  end;
end;

function TElGSSAPIMechanism.VerifyMIC(Ctx: TElGSSCustomContext;
  const MessageBuffer, MessageToken: ByteArray): LongWord;
var
  APICtx : TElGSSAPIContext;
  msg_buf, msg_tok : gss_buffer_desc;
  qop_state: gss_qop_t;
begin
  if not (Ctx is TElGSSAPIContext) then
  begin
    Result := SetStatus(GSS_S_NO_CONTEXT, 0);
    DoError('VerifyMIC', FMajorStatus, FMinorStatus, EmptyArray);
    Exit;
  end;

  if not ValidateFunctions() then
  begin
    Result := FMajorStatus;
    Exit;
  end;

  APICtx := TElGSSAPIContext(Ctx);
  msg_buf.value := @MessageBuffer[0];
  msg_buf.length := Length(MessageBuffer);
  msg_tok.value := @MessageToken[0];
  msg_tok.length := Length(MessageToken);

  FMajorStatus := FVerifyMic(FMinorStatus, APICtx.Context, @msg_buf, @msg_tok, qop_state);
  if FMajorStatus = GSS_S_FAILURE then
    DoError('gss_verify_mic', FMajorStatus, FMinorStatus, APICtx.MechOID);

  Result := FMajorStatus;
end;



initialization

  {$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
  GSS_C_NT_HOSTBASED_SERVICE_OID := CreateByteArrayConst( GSS_C_NT_HOSTBASED_SERVICE_OID_STR );
  GSS_KRB5_NT_PRINCIPAL_NAME_OID := CreateByteArrayConst( GSS_KRB5_NT_PRINCIPAL_NAME_OID_STR );
   {$endif}

 {$endif SB_GSSAPI}


end.
