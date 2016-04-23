(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBSocket;

interface

uses
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBConstants,
  {$ifdef SB_HAS_HTTPAUTH}
  SBHTTPAuth,
   {$endif}
  SBStringList,
  SBHTTPSConstants,
  SBEncoding,
  {$ifdef SB_DNSSEC}
  SBDNSSECTypes,
   {$endif}
  SysUtils,
  Classes,
{$ifdef WIN32}
  Windows,
  Winsock,
  {$ifdef FPC}
  sockets,
   {$endif}
 {$else}
  {$ifdef SB_MACOS}
  {$ifdef DELPHI_MAC}
  {$ifndef SB_IOS}
  MacAPI.CocoaTypes,
   {$endif SB_IOS}
  Posix.NetinetTCP,
   {$endif DELPHI_MAC}
  {$ifndef FPC}
  Posix.ArpaInet,
  Posix.Base,
  Posix.Errno,
  Posix.NetDB,
  Posix.NetinetIn,
  Posix.NetinetIp6,
  Posix.StrOpts,
  Posix.SysSelect,
  Posix.SysSocket,
  Posix.SysTime,
  Posix.Unistd,
   {$endif FPC}
   {$endif SB_MACOS}

  {$ifdef SB_ANDROID}
  {$ifndef FPC}
  Posix.ArpaInet,
  Posix.Base,
  Posix.Errno,
  Posix.NetDB,
  Posix.NetinetIn,
  Posix.NetinetIp6,
  Posix.NetinetTCP,
  Posix.StrOpts,
  Posix.SysSelect,
  Posix.SysSocket,
  Posix.SysTime,
  Posix.Unistd,
   {$endif FPC}
   {$endif SB_ANDROID}

  {$ifdef FPC}
  unix,
  ctypes,
  {$ifndef SB_MACOS}
  linux,
   {$endif}
  errors,
  sysconst,
  baseunix,
  unixtype,
  sockets,
  initc,
   {$endif}
 {$endif}
  SBPunycode
  ;

{$ifdef SB_SILVERLIGHT_SOCKETS}
  {$define SB_NET_REDUCED_SOCKETS}
 {$endif}
{$ifdef SB_WINRT_SOCKETS}
  {$define SB_NET_REDUCED_SOCKETS}
 {$endif}




{$ifdef BUILDER_USED}

{$HPPEMIT '#ifdef SD_RECEIVE'}
{$HPPEMIT '#undef SD_RECEIVE'}
{$HPPEMIT '#endif'}

{$HPPEMIT '#ifdef SD_SEND'}
{$HPPEMIT '#undef SD_SEND'}
{$HPPEMIT '#endif'}

{$HPPEMIT '#ifdef SD_BOTH'}
{$HPPEMIT '#undef SD_BOTH'}
{$HPPEMIT '#endif'}

{$HPPEMIT '#define SD_RECEIVE 0'}
{$HPPEMIT '#define SD_SEND 1'}
{$HPPEMIT '#define SD_BOTH 2'}

 {$endif}

const

  ERROR_FACILITY_SOCKET = $17000;

  ERROR_SOCKET_PROTOCOL_ERROR_FLAG = $00800;

  SB_SOCKET_ERROR_WINSOCK_INIT_FAILED = Integer(ERROR_FACILITY_SOCKET + ERROR_SOCKET_PROTOCOL_ERROR_FLAG + 1);
  SB_SOCKET_ERROR_WRONG_SOCKET_STATE = Integer(ERROR_FACILITY_SOCKET + ERROR_SOCKET_PROTOCOL_ERROR_FLAG + 2);
  SB_SOCKET_ERROR_NOT_A_SOCKET = Integer(ERROR_FACILITY_SOCKET + ERROR_SOCKET_PROTOCOL_ERROR_FLAG + 3);
  SB_SOCKET_ERROR_INVALID_ADDRESS = Integer(ERROR_FACILITY_SOCKET + ERROR_SOCKET_PROTOCOL_ERROR_FLAG + 4);
  SB_SOCKET_ERROR_ACCEPT_FAILED = Integer(ERROR_FACILITY_SOCKET + ERROR_SOCKET_PROTOCOL_ERROR_FLAG + 5);
  SB_SOCKET_ERROR_ADDRESS_FAMILY_MISMATCH = Integer(ERROR_FACILITY_SOCKET + ERROR_SOCKET_PROTOCOL_ERROR_FLAG + 6);
  SB_SOCKET_ERROR_INVALID_SOCKET_TYPE = Integer(ERROR_FACILITY_SOCKET + ERROR_SOCKET_PROTOCOL_ERROR_FLAG + 7);
  SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED = Integer(ERROR_FACILITY_SOCKET + ERROR_SOCKET_PROTOCOL_ERROR_FLAG + 8);
  SB_SOCKET_ERROR_SOCKS_AUTH_FAILED = Integer(ERROR_FACILITY_SOCKET + ERROR_SOCKET_PROTOCOL_ERROR_FLAG + 9);
  SB_SOCKET_ERROR_SOCKS_FAILED_TO_RESOLVE_DESTINATION_ADDRESS = Integer(ERROR_FACILITY_SOCKET + ERROR_SOCKET_PROTOCOL_ERROR_FLAG + 10);
  SB_SOCKET_ERROR_DNS_SECURITY_FAILURE = Integer(ERROR_FACILITY_SOCKET + ERROR_SOCKET_PROTOCOL_ERROR_FLAG + 11);
  SB_SOCKET_ERROR_DNS_TIMEOUT = Integer(ERROR_FACILITY_SOCKET + ERROR_SOCKET_PROTOCOL_ERROR_FLAG + 12);
  SB_SOCKET_ERROR_WEBTUNNEL_NEGOTIATION_FAILED = Integer(ERROR_FACILITY_SOCKET + ERROR_SOCKET_PROTOCOL_ERROR_FLAG + 13);
  SB_SOCKET_ERROR_TIMEOUT = Integer(ERROR_FACILITY_SOCKET + ERROR_SOCKET_PROTOCOL_ERROR_FLAG + 14);

type
  TElShutdownDirection =  (sdReceive, sdSend, sdSendAndReceive);
  TElSocketState = (issNotASocket, issInitializing, issInitialized, issBound,
    issConnected, issListening, issConnecting);
  TElSocketType = (istStream, istDatagram);
  TElSocksVersion = (elSocks4, elSocks5);
  TElSocksAuthentication = (saNoAuthentication, saUsercode);
  TElWebTunnelAuthentication = (wtaNoAuthentication, wtaBasic, wtaDigest, wtaNTLM);
  TElBandwidthPolicy = (bpFlexible, bpStrict);
  EElSocketError = class(ESecureBlackboxError);


  {$ifdef SB_POSIX}
  {$ifdef FPC}
  TSocket = longint;
  TSockAddrIn = TInetSockAddr;
  PSockAddrIn = PInetSockAddr;

  u_short = cushort;
  u_long = culong;
  uint32_t = dword;
  __socklen_t = dword;

  SOCKLEN_T = __socklen_t;
  PSOCKLEN_T = ^SOCKLEN_T;

  Phostent = ^hostent;
  hostent = record
    h_name: PChar;
    h_aliases: PPChar;
    h_addrtype: Integer;
    h_length: socklen_t;
    case Byte of
      0: (h_addr_list: PPChar);
      1: (h_addr: PPChar);
  end;
  PPhostent = ^Phostent;

  Pin_addr_t = ^in_addr_t;
  in_addr_t = uint32_t;
  Pin_addr = ^in_addr;
{
  in_addr = record
    s_addr : in_addr_t;
  end;
}
   {$else}
  TSockAddrIn = sockaddr_in;
  PSockAddrIn = Psockaddr_in;

  TInAddr = in_addr;
  PInAddr = ^in_addr;

  TFDSet = fd_set;
  PFDSet = pfd_set;
  TTimeVal = timeval;

  {$EXTERNALSYM u_long}
  u_long = Longint;

   {$endif}
   {$endif}

const
  {$EXTERNALSYM _SSALIGNSIZE}
  _SSALIGNSIZE = SizeOf(Int64);
  {$EXTERNALSYM _SSMAXSIZE}
  _SSMAXSIZE = 128;
  {$EXTERNALSYM _SSPAD1SIZE}
  _SSPAD1SIZE = _SSALIGNSIZE - SizeOf(u_short);
  {$EXTERNALSYM _SSPAD2SIZE}
  _SSPAD2SIZE = _SSMAXSIZE - (SizeOf(u_short) + _SSPAD1SIZE + _SSALIGNSIZE);

  {$ifdef SB_POSIX}
  {$ifndef FPC}
  INVALID_SOCKET = -1;
  SOCKET_ERROR = -1;
   {$endif}
   {$endif}

  {$ifdef SB_HAS_MSGNOSIGNAL}
const
  MSG_NOSIGNAL = $4000;
   {$endif}

  {$ifdef SB_MACOS}
const
  SO_NOSIGPIPE = $1022;
   {$endif}

type
  PSockAddrStorage = ^TSockAddrStorage;
  {.$EXTERNALSYM sockaddr_storage}
  sockaddr_storage = packed record
    ss_family: Word;
    __ss_pad1: array [0.._SSPAD1SIZE - 1] of Byte;
    __ss_align: int64;
    __ss_pad2: array [0.._SSPAD2SIZE - 1] of Byte;
  end;
  TSockAddrStorage = sockaddr_storage;

function AddressToString(const Addr: TSockAddrStorage; out S: string): Boolean;
function StringToAddress(const S: string; out Addr: TSockAddrStorage): Boolean;

{$ifdef SB_IPv6}
const
  {$EXTERNALSYM AF_INET6}
  AF_INET6 = 23;

function IsIPv6Address(const S: string): Boolean;
 {$endif}


type
  TSBSocksAuthMethodChooseEvent = procedure(Sender: TObject;
    AuthMethods : array of TElSocksAuthentication;
    var AuthMethod : TElSocksAuthentication; var Cancel : boolean) of object;
  TSBSocksAuthPasswordEvent = procedure(Sender: TObject;
    const Username : string; const Password : string; var Accept : boolean) of object;
  TSBSocksConnectEvent = procedure(Sender: TObject;
    const DestHost : string; DestPort : integer; var Allow : boolean) of object;


  TElSocket = class;

  {$ifndef SB_NO_SERVER_SOCKETS}
  TElCustomSocketBinding = class (TPersistent) 
  protected
    FPort : integer;
    FLocalIntfAddress  : string;
  public
    procedure Assign(Source : TElCustomSocketBinding);  reintroduce;  virtual;
  published
    property LocalIntfAddress: string read FLocalIntfAddress write FLocalIntfAddress;
    property Port: integer read FPort write FPort;
  end;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCustomSocketBinding = TElCustomSocketBinding;
   {$endif}
   {$endif}

  {$ifndef SB_NO_SERVER_SOCKETS}
  TElClientSocketBinding = class(TElCustomSocketBinding)
  protected
    FPortRangeFrom : integer;
    FPortRangeTo   : integer;
  public
    procedure Assign(Source : TElCustomSocketBinding); override;
  published
    property PortRangeFrom: integer read FPortRangeFrom write FPortRangeFrom;
    property PortRangeTo: integer read FPortRangeTo write FPortRangeTo;
  end;

  TElSocketBinding =  TElClientSocketBinding;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElClientSocketBinding =  TElClientSocketBinding;
  ElSocketBinding =  TElClientSocketBinding;
   {$endif}
   {$endif}


  TElSocketSecondaryEvent =  procedure(Sender : TObject;
    Socket : TElSocket; State : integer; var AbortConnect : boolean) of object;

  {$ifdef SB_DNSSEC}
  TSBDNSResolveEvent =  procedure (Sender: TObject;
    const HostName: string; Response: TElDNSResourceRecordSet; ResolveResult: Integer;
    SecurityStatus: TSBDNSSecurityStatus) of object;

  TElDNSSettings = class(TPersistent)
  private
    FAllowStatuses: TSBDNSSecurityStatuses;
    FEnabled: Boolean;
    FPort: Word;
    FServers: TElStringList;
    FQueryTimeout: Word;
    FTotalTimeout: Word;
    {$ifdef SB_IPv6}
    FUseIPv6: Boolean;
     {$endif}
    FUseSecurity: Boolean;
    FOnKeyNeeded: TSBDNSKeyNeededEvent;
    FOnKeyValidate: TSBDNSKeyValidateEvent;
    FOnResolve: TSBDNSResolveEvent;
    procedure HandleKeyNeeded(Sender: TObject; const Owner: string; KeyTag: Word; Algorithm: Byte;
      var Key: TElDNSPublicKeyRecord; var ReleaseKey: TSBBoolean);
    procedure HandleKeyValidate(Sender: TObject; Key: TElDNSPublicKeyRecord;
      var Valid: TSBBoolean);

    procedure SetServers(const Value: TElStringList);
  protected
    procedure DoKeyNeeded(const Owner: string; KeyTag: Word; Algorithm: Byte;
      var Key: TElDNSPublicKeyRecord; var ReleaseKey: TSBBoolean); virtual;
    procedure DoKeyValidate(Key: TElDNSPublicKeyRecord; var Valid: TSBBoolean); virtual;
    procedure DoResolve(const HostName: string; Response: TElDNSResourceRecordSet;
      ResolveResult: Integer; SecurityStatus: TSBDNSSecurityStatus); virtual;
  protected
    property OnKeyNeeded: TSBDNSKeyNeededEvent read FOnKeyNeeded write FOnKeyNeeded;
    property OnKeyValidate: TSBDNSKeyValidateEvent read FOnKeyValidate write FOnKeyValidate;
    property OnResolve: TSBDNSResolveEvent read FOnResolve write FOnResolve;

  public
    constructor Create;
     destructor  Destroy; override;
    procedure Assign(Source:  TPersistent); override ;

    {$ifdef SB_IPv6}
    function ResolveHostName(const HostName: string; UseIPv6: Boolean; out Addr: TSockAddrStorage): Boolean;
     {$else}
    function ResolveHostName(const HostName: string): LongWord;
     {$endif}
  published
    property AllowStatuses: TSBDNSSecurityStatuses read FAllowStatuses write FAllowStatuses
       default [dnsInsecure, dnsIndeterminate, dnsSecure] ;

    property Enabled: Boolean read FEnabled write FEnabled  default False ;

    property Port: Word read FPort write FPort  default 53 ;

    property Servers: TElStringList read FServers write SetServers;

    property QueryTimeout: Word read FQueryTimeout write FQueryTimeout  default 3000 ;

    property TotalTimeout: Word read FTotalTimeout write FTotalTimeout  default 15000 ;

    {$ifdef SB_IPv6}
    property UseIPv6: Boolean read FUseIPv6 write FUseIPv6  default False ;
     {$endif}

    property UseSecurity: Boolean read FUseSecurity write FUseSecurity  default True ;
  end;
   {$endif}

  //TSBSocketLogEvent = {$ifdef SB_NET}public{$endif} procedure(Sender: TObject; const S : string) of object;

  TElSocket = class(TSBControlBase)
  protected
    FSocket: TSocket;
    {$ifdef SB_IPv6}
    FUseIPv6: Boolean;
    FUsingIPv6: Boolean;
     {$endif}
    FUseNagle : boolean;

    FSktType: TElSocketType;
    FState: TElSocketState;

    {$ifdef SB_DNSSEC}
    FDNS: TElDNSSettings;
    FOnDNSKeyNeeded: TSBDNSKeyNeededEvent;
    FOnDNSKeyValidate: TSBDNSKeyValidateEvent;
    FOnDNSResolve: TSBDNSResolveEvent;
     {$endif}

    FRemoteAddress: string;
    FRemotePort: integer;

    {$ifndef SB_NO_SERVER_SOCKETS}
    FBoundAddress: string;
    FBoundPort: integer;

    (*
    FListenAddress: string;
    FListenPort : integer;
    FListenPortRangeFrom : integer;
    FListenPortRangeTo : integer;
    *)
     {$endif}

    // Bandwidth control
    FIncomingSpeedLimit: Integer;
    FOutgoingSpeedLimit: Integer;
    FBandwidthPolicy: TElBandwidthPolicy;

    // Bandwidth limitation begin

    FblLastSentTime,
    FblLastRecvTime : Integer; // the time when the last send/recv operation occured

    FblLastSentSize,
    FblLastRecvSize : Integer; // the time when the last send/recv operation occured

    // Bandwidth limitation end


    {$ifdef SILVERLIGHT}
    FClientAccessPolicyProtocol : TElSocketClientAccessPolicyProtocol;
     {$endif}

    {$ifndef SB_NO_SERVER_SOCKETS}
    FLocalBinding :  TElClientSocketBinding ;
    FListenBinding:  TElClientSocketBinding ;
     {$endif}

    FBuffer: ByteArray;
    FBufStart: integer;
    FBufLen: integer;
    CloseRequest: Boolean;

    FSocksAuthentication: TElSocksAuthentication;
    FSocksPassword: string;
    FSocksPort: Integer;
    {$ifndef SB_SILVERLIGHT_SOCKETS}
    FSocksResolveAddress: Boolean;
     {$endif}
    FSocksServer: string;
    FSocksUserCode: string;
    FSocksVersion: TElSocksVersion;
    FUseSocks: Boolean;
    {$ifdef SB_IPv6}
    FSocksUseIPv6: Boolean;
     {$endif}
    //  Web tunneling support
    FUseWebTunneling: boolean;
    FWebTunnelAddress: string;
    FWebTunnelAuthentication: TElWebTunnelAuthentication;
    FWebTunnelPassword: string;
    FWebTunnelPort: Integer;
    FWebTunnelUserId: string;
    FWebTunnelRequestHeaders, FWebTunnelResponseHeaders: TElStringList;
    FWebTunnelResponseBody: string;
    FWebTunnelResponseBodyLen: integer;

    FProxyResult : integer;

    FShuttingDown : boolean;

    {$ifdef SB_WINRT_SOCKETS}
    FInputSpool : ByteArray;
    FInputSpoolLock : System.Object;
    FOutboundDataSocket : boolean;
    FActivateReadLoop : boolean;
    FExtraDelayBeforeClose : integer;
    FExtraDelayAfterSend : integer;
    FSendDoneFlag,
    FRecvDoneFlag   : ManualResetEvent;
    FLoadOp : IAsyncOperationWithProgress<IBuffer, uint>;
    FReadBuffer : IBuffer;
    FSessionStartTick : cardinal;
    FLastSendTick : cardinal;
    FTotalDataSent : int64;
    FTotalSendTime : int64;
    FLastWinRTSocketError : Exception;
    //FOnLog : TSBSocketLogEvent;
     {$endif}

    function GetRequestHeaders : string;

    {$ifndef SB_NET_REDUCED_SOCKETS}
    procedure FinishAsyncConnect;
     {$endif}
    procedure DoAfterConnect; virtual;

    function HTTPConnect(Timeout: integer; var NextHeader : string): Integer;

    procedure DoSetUseNagle(Value: Boolean);

    procedure SetNonBlocking;

    procedure ReturnData(Data: Pointer; DataLen: Integer);
    function SocksConnect(Timeout: integer): Integer;

    function Init({$ifdef SB_IPv6}UseIPv6: Boolean {$endif}): Integer;
    function SocksSendReceive(Timeout: Cardinal; sendBuf: pointer; sendBufSize:
      integer; var wasSent: integer; readBuf: pointer; readBufSize: integer; var
      wasRead: integer; NeedDoubleCRLF : boolean = false): boolean;


    {$ifdef SB_SILVERLIGHT_SOCKETS}
    class procedure SocketArgs_Completed(Sender : Object; e : {$ifndef SB_NO_NET_SOCKETS}SocketAsyncEventArgs {$else}TElCustomSocketHandlerAsyncEventArgs {$endif} );

    procedure SLProcessConnect(e : {$ifndef SB_NO_NET_SOCKETS}SocketAsyncEventArgs {$else}TElCustomSocketHandlerAsyncEventArgs {$endif} );
    procedure SLProcessReceive(e : {$ifndef SB_NO_NET_SOCKETS}SocketAsyncEventArgs {$else}TElCustomSocketHandlerAsyncEventArgs {$endif} );
    procedure SLProcessSend(e : {$ifndef SB_NO_NET_SOCKETS}SocketAsyncEventArgs {$else}TElCustomSocketHandlerAsyncEventArgs {$endif} );

    function SLSend(Data : ByteArray; Start : Integer; ToSend : Integer; Timeout : integer) : Integer;
    function SLReceive(Data : ByteArray; {Start : Integer; }ToReceive : Integer; Timeout : integer) : Integer;

    // If there's a pending receive operation, attempts to wait for at most specified WaitTime
    function SLPendingReceiveCleared(var WaitTime : integer) : boolean;
     {$endif}

    {$ifdef SB_WINRT_SOCKETS}
    procedure RaiseLastWinRTSocketError;
    procedure RTStartReceiveLoop;
    procedure RTStopReceiveLoop;
    function RTSend(Data : ByteArray; Start : Integer; ToSend : Integer; Timeout : integer) : Integer;
    function RTReceive(Data : ByteArray; Start : Integer; ToReceive : Integer; Timeout : integer) : Integer;
    function RTPoll(Timeout : integer; SendDirection : boolean): boolean;
    procedure RTWaitForOutboundDataDeliveryFacepalm(Socket : StreamSocket);
    procedure HandleConnectAsyncCompleted(AsyncInfo : IAsyncAction; Status: AsyncStatus);
    procedure HandleRecvCompleted(AsyncInfo : IAsyncOperationWithProgress<IBuffer, uint>; Status: AsyncStatus);
    procedure HandleSendCompleted(AsyncInfo : IAsyncOperationWithProgress<uint, uint>; Status: AsyncStatus);
    procedure HandleFlushCompleted(AsyncInfo : IAsyncOperation<boolean>; Status: AsyncStatus);
    procedure WriteToInputSpool(Buf : ByteArray; StartIndex : integer; Len : integer);
    function ReadFromInputSpool(var Buf : ByteArray; StartIndex : integer; Len : integer): integer;
     {$endif}

    procedure PollRemainingDataForShutdown(Timeout : integer);

    {$ifdef SB_DNSSEC}
    procedure HandleDNSKeyNeeded(Sender: TObject; const Owner: string; KeyTag: Word; Algorithm: Byte;
      var Key: TElDNSPublicKeyRecord; var ReleaseKey: TSBBoolean);
    procedure HandleDNSKeyValidate(Sender: TObject; Key: TElDNSPublicKeyRecord;
      var Valid: TSBBoolean);
    procedure HandleDNSResolve(Sender: TObject; const HostName: string;
      Response: TElDNSResourceRecordSet; ResolveResult: Integer; SecurityStatus: TSBDNSSecurityStatus);
     {$endif}

    {$ifndef SB_NO_SERVER_SOCKETS}
    procedure SetLocalBinding(value :  TElClientSocketBinding );
    procedure SetListenBinding(value :  TElClientSocketBinding );
    function GetLocalHostName: string;
     {$endif}
    procedure IntSetUseNagle(Value: Boolean);

    function InternalReceive( Data: pointer ;
             DataLen: integer {$ifdef SB_ASYNC_SOCKETS}; Timeout : integer {$endif}): Integer;

    procedure SetAddress(const Value: string);
    function GetAddress: string;
    procedure SetWebTunnelRequestHeaders(Value : TElStringList);
    procedure SetWebTunnelAddress(const Value: string);
    function GetWebTunnelAddress : string;
    procedure SetPort(Value: Integer);
    procedure SetUseSocks(const Value: Boolean);
    procedure SetUseWebTunneling(const Value: boolean);
    procedure SetSocketType(const Value: TElSocketType);

    {$ifndef SB_NO_SERVER_SOCKETS}
    function GetListenPort : Integer;
    procedure SetListenPort(Value : Integer);
    function GetListenPortRangeFrom: Integer;
    procedure SetListenPortRangeFrom(Value: Integer);
    function GetListenPortRangeTo: Integer;
    procedure SetListenPortRangeTo(Value: Integer);
    function GetListenAddress: string;
    procedure SetListenAddress(Value: string);
     {$endif}

    function GetRemoteAddress : string;
    {$ifdef SB_DNSSEC}
    procedure SetDNS(ASettings: TElDNSSettings);
     {$endif}

  public
    constructor Create(Owner: TComponent); overload; override;
    constructor Create;  reintroduce; overload;  
     destructor  Destroy; override;
    {$ifdef SB_IPv6}
    class function LoadIPv6Proc(ProcName: string; out Proc: Pointer;
      var WinsockUsed: Integer; var Wship6Used: Integer): Boolean;
    class procedure InitializeIPv6;
    class procedure FinalizeIPv6;
     {$endif}
    {$ifndef SB_WINRT_SOCKETS}
    procedure ShutdownSocket();  overload; 
    procedure ShutdownSocket(Direction : TElShutdownDirection);  overload; 
     {$endif}
    procedure Close(Forced: boolean);  overload; 
    procedure Close(Forced: boolean; Timeout : integer);  overload; 

    {$ifndef SB_NET_REDUCED_SOCKETS}
    function StartAsyncConnect: Integer;
     {$endif}

    function AsyncConnect(Timeout: integer): Integer;
    class procedure FinalizeWinSock;
    class procedure InitializeWinSock;

    function LastNetError: Integer;

    {$ifndef SB_SILVERLIGHT_SOCKETS}
    function IPFromHost(const Host : string{$ifdef SB_IPv6}; UseIPv6 : boolean {$endif}) : string;
     {$endif}

    function Receive(Data: pointer; DataLen: integer; var Received: integer): Integer;
    function Send(Data: pointer; DataLen: integer; var Sent: integer): Integer;

    // UDP-specific
    function ReceiveFrom(Data: pointer; DataLen: integer; var Received:
      integer; var RemoteAddress: string; var RemotePort: word): Integer;
    function SendTo(Data: pointer; DataLen: integer; var Sent: integer;
      const RemoteAddress: string; RemotePort: Word): Integer;
    (*function AddToMulticastSrv(const GroupAddress, BindAddress: string): Integer;
    function AddToMulticastCli(const BindAddress: string; TTL: byte; DoLoop: boolean): Integer;*)

    function Connect(Timeout: integer): Integer;

    function CanReceive(WaitTime: integer  =  0): Boolean;
    function CanSend(WaitTime: integer  =  0): Boolean;

    {$ifndef SB_NO_SERVER_SOCKETS}
    function CanAccept(WaitTime: integer  =  0): Boolean;
    function Bind(): Integer;  overload; 
    function Bind(Outgoing: Boolean): Integer;  overload; 
    function Bind(Outgoing: Boolean; ReuseAddress : boolean): Integer;  overload; 
    function Listen: Integer;
    function Accept(Timeout: integer): Integer;  overload; 
    procedure Accept(Timeout: integer;  var Socket : TElSocket );  overload; 
     {$endif}
    {$ifndef SB_NET_REDUCED_SOCKETS}
    function AsyncConnectEx(Timeout: integer; SecondarySocket : TElSocket; SecSend,
      SecRecv : boolean; SecEvent : TElSocketSecondaryEvent): Integer;
     {$endif}

    {$ifndef SB_NO_SERVER_SOCKETS}{.$ifdef SB_NET_DESKTOP}
    procedure SocksAccept(Timeout: integer;
      OnAuthMethodChoose : TSBSocksAuthMethodChooseEvent;
      OnAuthPassword : TSBSocksAuthPasswordEvent;
      OnConnect : TSBSocksConnectEvent;
      CloseConnectionOnError : boolean;
      ResolveAddress : boolean);
     {$endif}

    {$ifndef SB_NO_SERVER_SOCKETS}
    property LocalHostName: string read GetLocalHostName;
     {$endif}
    {$ifndef SB_SILVERLIGHT_SOCKETS}
    property RemoteAddress: string read GetRemoteAddress;
     {$endif}

    property ProxyResult : Integer read FProxyResult;
    property SocketType: TElSocketType read FSktType write SetSocketType;
    property State: TElSocketState read FState;
    {$ifdef SB_IPv6}
    property UsingIPv6: Boolean read FUsingIPv6;
     {$endif}
    {$ifndef SB_NO_SERVER_SOCKETS}
    property BoundPort: Integer read FBoundPort;
    property BoundAddress: string read FBoundAddress;
     {$endif}
    property NativeSocket: TSocket read FSocket;
  published
    property Address: string read GetAddress write SetAddress;
    property Port: Integer read FRemotePort write SetPort;

    {$ifndef SB_NO_SERVER_SOCKETS}
    property ListenPort : Integer read GetListenPort write SetListenPort;
    property ListenPortRangeFrom: Integer read GetListenPortRangeFrom write SetListenPortRangeFrom;
    property ListenPortRangeTo: Integer read GetListenPortRangeTo write SetListenPortRangeTo;
    property ListenAddress: string read GetListenAddress write SetListenAddress;

    property ListenBinding:  TElClientSocketBinding  read FListenBinding write SetListenBinding;
    property OutgoingLocalBinding :  TElClientSocketBinding  read FLocalBinding write SetLocalBinding;
     {$endif}
    {$ifdef SILVERLIGHT}
    property ClientAccessPolicyProtocol : TElSocketClientAccessPolicyProtocol
      read FClientAccessPolicyProtocol write FClientAccessPolicyProtocol;
     {$endif}

    //property BandwidthPolicy: TElBandwidthPolicy read FBandwidthPolicy write
    //    FBandwidthPolicy;
    property IncomingSpeedLimit: Integer read FIncomingSpeedLimit write
        FIncomingSpeedLimit;
    property OutgoingSpeedLimit: Integer read FOutgoingSpeedLimit write
        FOutgoingSpeedLimit;

    property SocksAuthentication: TElSocksAuthentication read FSocksAuthentication
      write FSocksAuthentication;
    property SocksPassword: string read FSocksPassword write FSocksPassword;
    property SocksPort: Integer read FSocksPort write FSocksPort  default 1080 ;
    {$ifndef SB_SILVERLIGHT_SOCKETS}
    property SocksResolveAddress: Boolean read FSocksResolveAddress write
    FSocksResolveAddress  default false ;
     {$endif}
    property SocksServer: string read FSocksServer write FSocksServer;
    {$ifdef SB_IPv6} // this is used only if Address contains a host name and SocksResolveAddress is False
    property SocksUseIPv6: Boolean read FSocksUseIPv6 write FSocksUseIPv6;
     {$endif}
    property SocksUserCode: string read FSocksUserCode write FSocksUserCode;
    property SocksVersion: TElSocksVersion read FSocksVersion write FSocksVersion
        default elSocks5 ;
    property UseSocks: Boolean read FUseSocks write SetUseSocks  default false ;

    {$ifdef SB_IPv6}
    property UseIPv6: Boolean read FUseIPv6 write FUseIPv6  default False ;
     {$endif}

    property UseNagle: Boolean read FUseNagle write FUseNagle  default False ;

    //  Web tunneling support
    property UseWebTunneling: boolean read FUseWebTunneling write
    SetUseWebTunneling  default false ;
    property WebTunnelAddress: string read GetWebTunnelAddress write
    SetWebTunnelAddress;
    property WebTunnelAuthentication: TElWebTunnelAuthentication read
    FWebTunnelAuthentication write FWebTunnelAuthentication
      default wtaNoAuthentication ;
    property WebTunnelPassword: string read FWebTunnelPassword write
    FWebTunnelPassword;
    property WebTunnelPort: Integer read FWebTunnelPort write FWebTunnelPort;
    property WebTunnelUserId: string read FWebTunnelUserId write FWebTunnelUserId;
    property WebTunnelRequestHeaders: TElStringList read FWebTunnelRequestHeaders write SetWebTunnelRequestHeaders;
    property WebTunnelResponseHeaders: TElStringList read FWebTunnelResponseHeaders;
    property WebTunnelResponseBody: string read FWebTunnelResponseBody;
    {$ifdef SB_WINRT}
    property OutboundDataSocket : boolean read FOutboundDataSocket write FOutboundDataSocket;
    property ExtraDelayBeforeClose : integer read FExtraDelayBeforeClose write FExtraDelayBeforeClose;
    property ExtraDelayAfterSend : integer read FExtraDelayAfterSend write FExtraDelayAfterSend;
     {$endif}

    {$ifdef SB_WINRT_SOCKETS}
    property ActivateReadLoop : boolean read FActivateReadLoop write FActivateReadLoop;
     {$endif}

    {$ifdef SB_DNSSEC}
    property DNS: TElDNSSettings read FDNS write SetDNS;
    property OnDNSKeyNeeded: TSBDNSKeyNeededEvent read FOnDNSKeyNeeded write FOnDNSKeyNeeded;
    property OnDNSKeyValidate: TSBDNSKeyValidateEvent read FOnDNSKeyValidate write FOnDNSKeyValidate;
    property OnDNSResolve: TSBDNSResolveEvent read FOnDNSResolve write FOnDNSResolve;
     {$endif}

    {$ifdef SB_WINRT}
    //event OnLog : TSBSocketLogEvent delegate FOnLog;
     {$endif}
  end;

  {$ifdef SB_WINRT_SOCKETS}
  SocketException = public class(ESecureBlackboxError);
   {$endif}


{$ifdef FPC}
{$ifdef WIN32}
const
  INVALID_SOCKET = TSocket(-1);
 {$endif}
 {$endif}


const
  SB_SOCKET_ERROR_CODE_TIMEDOUT = {$ifdef SB_WINDOWS_OR_NET}WSAETIMEDOUT {$else} {$ifdef FPC}ESysETIMEDOUT {$else}ETIMEDOUT {$endif}  {$endif};
  SB_SOCKET_ERROR_CODE_WOULDBLOCK = {$ifdef SB_WINDOWS_OR_NET}WSAEWOULDBLOCK {$else} {$ifdef FPC}EsockEWOULDBLOCK {$else}EWOULDBLOCK {$endif}  {$endif};
  SB_SOCKET_ERROR_CODE_CONNRESET = {$ifdef SB_WINDOWS_OR_NET}WSAECONNRESET {$else} {$ifdef FPC}ESysECONNRESET {$else}ECONNRESET {$endif}  {$endif};
  SB_SOCKET_ERROR_CODE_ADDRINUSE = {$ifdef SB_WINDOWS_OR_NET}WSAEADDRINUSE {$else} {$ifdef FPC}EsockEINVAL {$else}EINVAL {$endif}  {$endif};
  SB_SOCKET_ERROR_CODE_ISCONN = {$ifdef SB_WINDOWS_OR_NET}WSAEISCONN {$else} {$ifdef FPC}ESysEISCONN {$else}EISCONN {$endif}  {$endif};
  SB_SOCKET_ERROR_CODE_INPROGRESS = {$ifdef SB_WINDOWS_OR_NET}WSAEINPROGRESS {$else} {$ifdef FPC}ESysEINPROGRESS {$else}EINPROGRESS {$endif}  {$endif};
  SB_SOCKET_ERROR_CODE_SHUTDOWN = {$ifdef SB_WINDOWS_OR_NET}WSAESHUTDOWN {$else} {$ifdef FPC}ESysESHUTDOWN {$else}ESHUTDOWN {$endif}  {$endif};

{$ifdef SB_IPv6}{$ifdef NET_CF}
procedure SupportsIPv6Initialize; 
 {$endif} {$endif}

{$ifdef SB_WINRT_SOCKETS}
function IsValidIPv4Address(const S : string): boolean;
function IsValidIPv6Address(const S : string): boolean;
function GetIPAddressBytes(const S : string) : ByteArray;
 {$endif}

procedure Register;

implementation

{$ifdef SB_DNSSEC}
uses
  SBDNSSECConsts,
  SBDNSSECUtils,
  SBDNSSEC;
 {$endif}

{$ifdef SB_POSIX}
{$ifdef FPC}
const
  INVALID_SOCKET = -1;
  SOCKET_ERROR = -1;
 {$endif}
 {$endif}

  {$ifndef DELPHI_MAC}
    {$define SB_SetSockOptByRef}
   {$endif}

{$ifdef SB_POSIX}
{$ifdef FPC}
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  function inet_ntoa(__in:in_addr):Pchar;cdecl;external clib name 'inet_ntoa';
  function inet_addr(__cp:Pchar):in_addr_t;cdecl;external clib name 'inet_addr';
  function gethostbyaddr(__addr:pointer; __len:__socklen_t; __type:longint):Phostent;cdecl;external clib name 'gethostbyaddr';
  function gethostbyname(__name:Pchar):Phostent;cdecl;external clib name 'gethostbyname';
  function getpeername(__fd:longint; __addr:Psockaddr; __len:Psocklen_t):longint;cdecl;external clib name 'getpeername';
  function getsockname(__fd:longint; __addr:Psockaddr; __len:Psocklen_t):longint;cdecl;external clib name 'getsockname';
 {$endif}
 {$else}
  function gethostbyaddr(__addr:pointer; __len: socklen_t; __type:longint):Phostent; cdecl; external libc name _PU + 'gethostbyaddr';
  function gethostbyname(__name : PAnsiChar):Phostent; cdecl; external libc name _PU + 'gethostbyname';
 {$endif}
 {$endif}

const
  DEF_BUFFER_SIZE = 16384;//16384;//65535;//16384;

const
  {$ifdef BUILDER_USED}
  {$externalsym SD_RECEIVE}
   {$endif}
  SD_RECEIVE = 00;
  {$ifdef BUILDER_USED}
  {$externalsym SD_SEND}
   {$endif}
  SD_SEND = 01;
  {$ifdef BUILDER_USED}
  {$externalsym SD_BOTH}
   {$endif}
  SD_BOTH = 02;

{$ifdef SB_WINDOWS}
  {$ifdef BUILDER_USED}
  {$externalsym IP_MULTICAST_IF}
   {$endif}
  IP_MULTICAST_IF = 9;
  {$ifdef BUILDER_USED}
  {$externalsym IP_MULTICAST_TTL}
   {$endif}
  IP_MULTICAST_TTL = 10;
  {$ifdef BUILDER_USED}
  {$externalsym IP_MULTICAST_LOOP}
   {$endif}
  IP_MULTICAST_LOOP = 11;
  {$ifdef BUILDER_USED}
  {$externalsym IP_ADD_MEMBERSHIP}
   {$endif}
  IP_ADD_MEMBERSHIP = 12;
  {$ifdef BUILDER_USED}
  {$externalsym IP_DROP_MEMBERSHIP}
   {$endif}
  IP_DROP_MEMBERSHIP = 13;
 {$endif}

{$ifndef SB_MACOS}
type
  size_t = {$ifdef WIN64}QWord {$else}LongWord {$endif};

  PAddrInfoA = ^TAddrInfoA;
  {$EXTERNALSYM addrinfo}
  addrinfo = packed record
    ai_flags: integer;
    ai_family: integer;
    ai_socktype: integer;
    ai_protocol: integer;
    addrlen: size_t;
    CanonName: PAnsiChar;
    Addr: PSockAddr;
    Next: PAddrInfoA;
  end;
  TAddrInfoA = addrinfo;

  PAddrInfoW = ^TAddrInfoW;
  {$EXTERNALSYM addrinfoW}
  addrinfoW = packed record
    ai_flags: integer;
    ai_family: integer;
    ai_socktype: integer;
    ai_protocol: integer;
    addrlen: size_t;
    CanonName: PWideChar;
    Addr: PSockAddr;
    Next: PAddrInfoW;
  end;
  TAddrInfoW = addrinfoW;

  {$ifdef UNICODE}
  TAddrInfo = TAddrInfoW;
  PAddrInfo = PAddrInfoW;
   {$else}
  TAddrInfo = TAddrInfoA;
  PAddrInfo = PAddrInfoA;
   {$endif}

 {$endif}

{$ifdef SB_IPv6}
const
  {$EXTERNALSYM AI_PASSIVE}
  AI_PASSIVE = $00000001;
  {$EXTERNALSYM AI_CANONNAME}
  AI_CANONNAME = $00000002;
  {$EXTERNALSYM AI_NUMERICHOST}
  AI_NUMERICHOST = $00000004;
  {$EXTERNALSYM AI_NUMERICSERV}
  AI_NUMERICSERV = $00000008;
  {$EXTERNALSYM AI_ALL}
  AI_ALL = $00000100;
  {$EXTERNALSYM AI_ADDRCONFIG}
  AI_ADDRCONFIG = $00000400;
  {$EXTERNALSYM AI_V4MAPPED}
  AI_V4MAPPED = $00000800;
  {$EXTERNALSYM AI_NON_AUTHORITATIVE}
  AI_NON_AUTHORITATIVE = $00004000;
  {$EXTERNALSYM AI_SECURE}
  AI_SECURE = $00008000;
  {$EXTERNALSYM AI_RETURN_PREFERRED_NAMES}
  AI_RETURN_PREFERRED_NAMES = $00010000;

  {$EXTERNALSYM NI_MAXHOST}
  NI_MAXHOST = 1025;
  {$EXTERNALSYM NI_MAXSERV}
  NI_MAXSERV = 32;

  {$EXTERNALSYM NI_NOFQDN}
  NI_NOFQDN = $01;
  {$EXTERNALSYM NI_NUMERICHOST}
  NI_NUMERICHOST = $02;
  {$EXTERNALSYM NI_NAMEREQD}
  NI_NAMEREQD = $04;
  {$EXTERNALSYM NI_NUMERICSERV}
  NI_NUMERICSERV = $08;
  {$EXTERNALSYM NI_DGRAM}
  NI_DGRAM = $10;

type
  PIn6Addr = ^TIn6Addr;
  {$EXTERNALSYM in6_addr}
  in6_addr = packed record
    case Integer of
      0: (Bytes: array [0..15] of Byte);
      1: (Words: array [0..7] of Word);
  end;
  TIn6Addr = in6_addr;

  PSockAddrIn6 = ^TSockAddrIn6;
  {$EXTERNALSYM sockaddr_in6}
  sockaddr_in6 = packed record
    sin6_family: Word;
    sin6_port: Word;
    sin6_flowinfo: LongWord;
    sin6_addr: in6_addr;
    sin6_scope_id: LongWord;
  end;
  TSockAddrIn6 = sockaddr_in6;

  TFreeAddrInfoA = procedure (AddrInfo: PAddrInfoA); {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};
  TFreeAddrInfoW = procedure (AddrInfo: PAddrInfoW); {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};
  TGetAddrInfoA = function (NodeName: PAnsiChar; ServName: PAnsiChar; Hints: PAddrInfoA;
    out Res: PAddrInfoA): Integer; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};
  TGetAddrInfoW = function (NodeName: PWideChar; ServName: PWideChar; Hints: PAddrInfoW;
    out Res: PAddrInfoW): Integer; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};
  TGetNameInfoA = function (Addr: PSockAddr; AddLen: Integer; Host: PAnsiChar; HostLen: LongWord;
    Service: PAnsiChar; ServiceLen: LongWord; Flags: Integer): Integer; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};
  TGetNameInfoW = function (Addr: PSockAddr; AddLen: Integer; Host: PWideChar; HostLen: LongWord;
    Service: PWideChar; ServiceLen: LongWord; Flags: Integer): Integer; {$ifdef SB_USE_CDECL}cdecl {$else}stdcall {$endif};

const
  IN6ADDR_ANY: TIn6Addr = (Words: (0, 0, 0, 0, 0, 0, 0, 0););
 {$endif SB_IPv6}

{$ifdef SB_POSIX}
const
  FIONBIO = $5421;
 {$endif}

resourcestring
  sDefaultUserAgent = 'User-agent: SecureBlackbox';
  sWinsockInitFailed = 'Winsock initialization failed';
  sNotASocket = 'Not a socket';
  sInvalidAddress = 'Invalid address';
  sAcceptFailed = 'Accept failed';
  sAddressFamilyMismatch = 'Socket handle is IPv6 and could not be used with IPv4 address';
  sSocksNegotiationFailed = 'Socks negotiation failed';
  sSocketNotConnected = 'Socket not connected';
  sTimeout = 'Timeout';
  sOperationFailed = 'Operation failed';
  sInternalError = 'Internal error';
  sWrongSocketState = 'Wrong socket state %d in %s';
  sInvalidSocketType = 'Invalid socket type %d in %s';

{$ifdef SB_WINDOWS}
const
  SocketTypes: array[TElSocketType] of integer = (SOCK_STREAM, SOCK_DGRAM);
  {$ifdef SB_IPv6}
  SocketProtocols: array [TElSocketType] of Integer = (IPPROTO_TCP, IPPROTO_UDP);
   {$endif}
 {$endif SB_WINDOWS}

{$ifdef SB_POSIX}
const
  SocketTypes: array[TElSocketType] of integer = (SOCK_STREAM, SOCK_DGRAM);
 {$endif SB_POSIX}



{$ifdef SB_WINDOWS}
var
  WinsockInitialized: boolean;
  {$ifdef SB_IPv6}
  WinsockIPv6Enabled: Boolean;
  WinsockHandle: THandle;
  Wship6Handle: THandle;
  // Pointers to IPv6 functions
  FreeAddrInfoAProc: TFreeAddrInfoA;
  FreeAddrInfoWProc: TFreeAddrInfoW;
  GetAddrInfoAProc: TGetAddrInfoA;
  GetAddrInfoWProc: TGetAddrInfoW;
  GetNameInfoAProc: TGetNameInfoA;
  GetNameInfoWProc: TGetNameInfoW;
   {$endif}
 {$endif SB_WINDOWS}

{$ifdef SB_IPv6}
{$ifdef NET_CF}
var
  SupportsIPv6: nullable Boolean;

procedure SupportsIPv6Initialize;
var
  TestSocket: Socket;
begin
  if not Assigned(SupportsIPv6) then
  begin
    SupportsIPv6 := False;
    try
      TestSocket := Socket.Create(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
      TestSocket := Socket.Create(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
      SupportsIPv6 := True;
    except
      // ignore errors
    end;
  end;
end;
 {$endif}
 {$endif}


procedure Register;
begin
  RegisterComponents('SecureBlackbox', [TElSocket]);
end;

{
******************************* IPv6 Functions *********************************
}

{$ifdef SB_IPv6}
procedure FreeAddrInfo(AddrInfo: PAddrInfo);
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  {$ifdef SB_UNICODE_WINAPI}
  if @FreeAddrInfoWProc <> nil then
    FreeAddrInfoWProc(AddrInfo)
   {$else}
  if @FreeAddrInfoAProc <> nil then
    FreeAddrInfoAProc(AddrInfo)
   {$endif}
  else
    WSASetLastError(WSAVERNOTSUPPORTED);
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

procedure FreeAddrInfoA(AddrInfo: PAddrInfoA);
begin
  if @FreeAddrInfoAProc <> nil then
    FreeAddrInfoAProc(AddrInfo)
  else
    WSASetLastError(WSAVERNOTSUPPORTED);
end;

procedure FreeAddrInfoW(AddrInfo: PAddrInfoW);
begin
  if @FreeAddrInfoWProc <> nil then
    FreeAddrInfoWProc(AddrInfo)
  else
    WSASetLastError(WSAVERNOTSUPPORTED);
end;

function GetAddrInfo(NodeName: PChar; ServName: PChar; Hints: PAddrInfo; out Res: PAddrInfo): Integer;
{$ifdef SB_WINCE}
var 
  NodeNameW : WideString;
  ServNameW : WideString;
  NodeNameP : PWideChar;
  ServNameP : PWideChar;
 {$endif}
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  {$ifdef SB_WINCE}
  if @GetAddrInfoWProc <> nil then
  begin
    NodeNameW := WideString(StrPas(NodeName));
    ServNameW := WideString(StrPas(ServName));
    if NodeNameW <> '' then 
      NodeNameP := PWideChar(NodeNameW)
    else
      NodeNameP := nil;
    if ServNameW <> '' then 
      ServNameP := PWideChar(ServNameW)
    else
      ServNameP := nil;
    Result := GetAddrInfoWProc(NodeNameP, ServNameP, Hints, Res);
  end
   {$else}
  {$ifdef SB_UNICODE_WINAPI}
  if @GetAddrInfoWProc <> nil then
    Result := GetAddrInfoWProc(NodeName, ServName, Hints, Res)
   {$else}
  if @GetAddrInfoAProc <> nil then
    Result := GetAddrInfoAProc(NodeName, ServName, Hints, Res)
   {$endif}
   {$endif}
  else
  begin
    Result := WSAVERNOTSUPPORTED;
    WSASetLastError(Result);
  end;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

function GetAddrInfoA(NodeName: PAnsiChar; ServName: PAnsiChar; Hints: PAddrInfoA; out Res: PAddrInfoA): Integer;
begin
  if @GetAddrInfoAProc <> nil then
    Result := GetAddrInfoAProc(NodeName, ServName, Hints, Res)
  else
  begin
    Result := WSAVERNOTSUPPORTED;
    WSASetLastError(Result);
  end;
end;

function GetAddrInfoW(NodeName: PWideChar; ServName: PWideChar; Hints: PAddrInfoW; out Res: PAddrInfoW): Integer;
begin
  if @GetAddrInfoWProc <> nil then
    Result := GetAddrInfoWProc(NodeName, ServName, Hints, Res)
  else
  begin
    Result := WSAVERNOTSUPPORTED;
    WSASetLastError(Result);
  end;
end;

function GetNameInfo(Addr: PSockAddr; AddrLen: Integer; Host: PChar; HostLen: LongWord;
  Service: PChar; ServiceLen: LongWord; Flags: Integer): Integer;
begin
  {$ifdef SB_UNICODE_VCL}
  if @GetNameInfoWProc <> nil then
    Result := GetNameInfoWProc(Addr, AddrLen, Host, HostLen, Service, ServiceLen, Flags)
   {$else}
  if @GetNameInfoAProc <> nil then
    Result := GetNameInfoAProc(Addr, AddrLen, Host, HostLen, Service, ServiceLen, Flags)
   {$endif}
  else
  begin
    Result := WSAVERNOTSUPPORTED;
    WSASetLastError(Result);
  end;
end;

function GetNameInfoA(Addr: PSockAddr; AddrLen: Integer; Host: PAnsiChar; HostLen: LongWord;
  Service: PAnsiChar; ServiceLen: LongWord; Flags: Integer): Integer;
begin
  if @GetNameInfoAProc <> nil then
    Result := GetNameInfoAProc(Addr, AddrLen, Host, HostLen, Service, ServiceLen, Flags)
  else
  begin
    Result := WSAVERNOTSUPPORTED;
    WSASetLastError(Result);
  end;
end;

function GetNameInfoW(Addr: PSockAddr; AddrLen: Integer; Host: PWideChar; HostLen: LongWord;
    Service: PWideChar; ServiceLen: LongWord; Flags: Integer): Integer;
begin
  if @GetNameInfoWProc <> nil then
    Result := GetNameInfoWProc(Addr, AddrLen, Host, HostLen, Service, ServiceLen, Flags)
  else
  begin
    Result := WSAVERNOTSUPPORTED;
    WSASetLastError(Result);
  end;
end;

function BackResolveAddress(Addr: TSockAddrStorage; out HostName: string): Boolean;
var
  Temp: array [0..NI_MAXHOST] of Char;
  HostEnt: PHostEnt;
begin
  HostName := '';
  if WinsockIPv6Enabled then
  begin
    Result := (GetNameInfo(PSockAddr(@Addr), SizeOf(Addr), @Temp[0], NI_MAXHOST, nil, 0, NI_NAMEREQD) = 0);
    if Result then
      HostName := StrPas(PChar(@Temp[0]));
  end
  else
  if Addr.ss_family = AF_INET6 then
    Result := False
  else
  begin
    HostEnt := gethostbyaddr(@PSockAddrIn(@Addr).sin_addr, SizeOf(PSockAddrIn(@Addr).sin_addr), AF_INET);
    if HostEnt = nil then
      Result := False
    else
    begin
      HostName := String(StrPas(HostEnt.h_name));
      Result := True;
    end;
  end;
end;

function IsIPv6Address(const S: string): Boolean;
var
  Hints: TAddrInfo;
  Res: PAddrInfo;
begin
  Result := False;
  if WinsockIPv6Enabled then
  begin
    FillChar(Hints, SizeOf(Hints), 0);
    Hints.ai_flags := AI_NUMERICHOST;
    Hints.ai_family := AF_INET6;
    Res := nil;
    Result := (GetAddrInfo(PChar(S), nil, @Hints, Res) = 0) and (Res <> nil);
    FreeAddrInfo(Res);
  end;
end;
 {$endif}

// The function converts an IP address specified by Addr parameter to string representation and
// returns True if succeeded; otherwise it returns False.
// Note: if IPv6 protocol is not enabled on a computer and Addr contains an IPv6 address, the
//       function returns False.
function AddressToString(const Addr: TSockAddrStorage; out S: string): Boolean;
{$ifdef SB_IPv6}
var
  Temp: array [0..NI_MAXHOST] of Char;
 {$endif}
var
  TmpAS : AnsiString;

begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  {$ifdef SB_IPv6}
  if WinsockIPv6Enabled then
  begin
    Result := (GetNameInfo(PSockAddr(@Addr), SizeOf(Addr), @Temp[0], NI_MAXHOST, nil, 0, NI_NUMERICHOST) = 0);
    if Result then
      S := StrPas(PChar(@Temp[0]))
    else
      S := '';
    UniqueString(S);
  end
  else
  if Addr.ss_family = AF_INET6 then
    Result := False
  else
   {$endif}
  begin
    TmpAS := AnsiStrPas(PAnsiChar(inet_ntoa(PSockAddrIn(@Addr).sin_addr)));
    S := StringOfAnsiString(TmpAS);
    Result := True;
  end;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

//
function StringToAddress(const S: string; out Addr: TSockAddrStorage): Boolean;
var
  {$ifdef SB_IPv6}
  Hints: TAddrInfo;
  Res: PAddrInfo;
   {$endif}
  Address: Integer;
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  FillChar(Addr, SizeOf(Addr), 0);
  {$ifdef SB_IPv6}
  if WinsockIPv6Enabled then
  begin
    FillChar(Hints, SizeOf(Hints), 0);
    Hints.ai_flags := AI_NUMERICHOST;
    Res := nil;
    Result := (GetAddrInfo(PChar(S), nil, @Hints, Res) = 0) and (Res <> nil);
    if Result then
      SBMove(Res.Addr^, Addr, Min(Res.addrlen, SizeOf(Addr)));
    FreeAddrInfo(Res);
  end
  else
   {$endif}
  begin
    {$ifndef SB_UNICODE_VCL}
    Address := inet_addr(PAnsiChar(S));
     {$else}
    Address := inet_addr(PAnsiChar(AnsiString(S)));
     {$endif}
    if Address = Integer(INADDR_NONE) then
      Result := False
    else
    begin
      Addr.ss_family := AF_INET;
      PSockAddrIn(@Addr).sin_addr.S_addr := Address;
      Result := True;
    end;
  end;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

function ResolveHostName(const HostName: string; {$ifdef SB_IPv6}UseIPv6: Boolean; {$endif}
   out Addr: TSockAddrStorage): Boolean;
var
  {$ifdef SB_IPv6}
  Hints: TAddrInfo;
  Res: PAddrInfo;
   {$endif}
  HostEnt: PHostEnt;
  {$ifndef VCL60}
  AnsiName: PAnsiChar;
   {$endif}
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  Result := StringToAddress(HostName, Addr);
  if not Result {$ifdef SB_IPv6}or ((Addr.ss_family = AF_INET6) and not UseIPv6) {$endif} then
  begin
    FillChar(Addr, SizeOf(Addr), 0);
    Result := False;
    {$ifdef SB_IPv6}
    if WinsockIPv6Enabled and UseIPv6 then
    begin
      FillChar(Hints, SizeOf(Hints), 0);
      Hints.ai_family := AF_INET6;
      Res := nil;
      Result := (GetAddrInfo(PChar(HostName), nil, @Hints, Res) = 0);
      if Result then
        SBMove(Res.Addr^, Addr, Min(Res.addrlen, SizeOf(Addr)));
      FreeAddrInfo(Res);
    end;
    // if IPv6 is not enabled or IPv6 should not be used or failed to get an IPv6 address,
    // try to get an IPv4 address
     {$endif}
    if not Result then
    begin
      {$ifdef VCL60}
      HostEnt := gethostbyname(PAnsiChar(AnsiString(HostName)));
       {$else}
      // This is a workaround for string reference counter bug in VCL 5 and earlier
      GetMem(AnsiName, Length(HostName) + 1);
      try
        StrPCopy(AnsiName, HostName);
        HostEnt := gethostbyname(AnsiName);
      finally
        FreeMem(AnsiName);
      end;
       {$endif}
      if HostEnt <> nil then
      begin
        Addr.ss_family := AF_INET;
        {$ifndef SB_POSIX}
        SBMove(HostEnt.h_addr^[0], PSockAddrIn(@Addr).sin_addr.S_addr, SizeOf(PSockAddrIn(@Addr).sin_addr.S_addr));
         {$else}
        SBMove(HostEnt.h_addr_list^[0], PSockAddrIn(@Addr).sin_addr.S_addr, SizeOf(PSockAddrIn(@Addr).sin_addr.S_addr));
         {$endif}
        Result := True;
      end;
    end;
  end;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;


 // Java


{
******************************* TElDNSSettings *********************************
}

{$ifdef SB_DNSSEC}
procedure TElDNSSettings.Assign(Source:  TPersistent );
begin
  if Source is TElDNSSettings then
  begin
    FAllowStatuses := TElDNSSettings(Source).FAllowStatuses;
    FEnabled := TElDNSSettings(Source).FEnabled;
    FPort := TElDNSSettings(Source).FPort;
    FServers.Assign(TElDNSSettings(Source).FServers);
    FQueryTimeout := TElDNSSettings(Source).FQueryTimeout;
    FTotalTimeout := TElDNSSettings(Source).FTotalTimeout;
    {$ifdef SB_IPv6}
    FUseIPv6 := TElDNSSettings(Source).FUseIPv6;
     {$endif}
    FUseSecurity := TElDNSSettings(Source).FUseSecurity;
  end
  else
    inherited;
end;

constructor TElDNSSettings.Create;
begin
  inherited;
  FAllowStatuses :=  [dnsInsecure, dnsIndeterminate, dnsSecure] ;
  FEnabled := False;
  FPort := 53;
  FServers := TElStringList.Create;
  FQueryTimeout := 3000;
  FTotalTimeout := 15000;
  {$ifdef SB_IPv6}
  FUseIPv6 := False;
   {$endif}
  FUseSecurity := True;
end;

function CreateResolver(Settings: TElDNSSettings): TElDNSResolver;
begin
  Result := TElDNSResolver.Create( nil );
  Result.Port := Settings.Port;
  Result.Servers.Assign(Settings.Servers);
  Result.QueryTimeout := Settings.QueryTimeout;
  Result.TotalTimeout := Settings.TotalTimeout;
  {$ifdef SB_IPv6}
  Result.UseIPv6 := Settings.UseIPv6;
   {$endif}
  Result.UseSecurity := Settings.UseSecurity;
  Result.OnKeyNeeded  :=  Settings.HandleKeyNeeded;
  Result.OnKeyValidate  :=  Settings.HandleKeyValidate;
end;

 destructor  TElDNSSettings.Destroy;
begin
  FreeAndNil(FServers);
  inherited;
end;

procedure TElDNSSettings.DoKeyNeeded(const Owner: string; KeyTag: Word; Algorithm: Byte;
  var Key: TElDNSPublicKeyRecord; var ReleaseKey: TSBBoolean);
begin
  if Assigned(FOnKeyNeeded) then
    FOnKeyNeeded(Self, Owner, KeyTag, Algorithm, Key, ReleaseKey);
end;

procedure TElDNSSettings.DoKeyValidate(Key: TElDNSPublicKeyRecord; var Valid: TSBBoolean);
begin
  if Assigned(FOnKeyValidate) then
    FOnKeyValidate(Self, Key, Valid);
end;

procedure TElDNSSettings.DoResolve(const HostName: string; Response: TElDNSResourceRecordSet;
  ResolveResult: Integer; SecurityStatus: TSBDNSSecurityStatus);
begin
  if Assigned(FOnResolve) then
    FOnResolve(Self, HostName, Response, ResolveResult, SecurityStatus);
end;

procedure TElDNSSettings.HandleKeyNeeded(Sender: TObject; const Owner: string;
  KeyTag: Word; Algorithm: Byte; var Key: TElDNSPublicKeyRecord;
  var ReleaseKey: TSBBoolean);
begin
  DoKeyNeeded(Owner, KeyTag, Algorithm, Key, ReleaseKey);
end;

procedure TElDNSSettings.HandleKeyValidate(Sender: TObject; Key: TElDNSPublicKeyRecord;
  var Valid: TSBBoolean);
begin
  DoKeyValidate(Key, Valid);
end;

function CheckLookupResult(UseSecurity: Boolean; AllowedStatuses: TSBDNSSecurityStatuses;
  LookupResult: Integer; SecurityStatus: TSBDNSSecurityStatus): Boolean;
begin
  if LookupResult = SB_DNS_RESULT_TIMEOUT then
    raise EElDNSSECTimeoutError.Create;
  if UseSecurity and (LookupResult <> SB_DNS_RESULT_SERVER_FAILURE) then
  begin
    if not (SecurityStatus in AllowedStatuses) then
      raise EElDNSSECSecurityFailureError.Create(SecurityStatus);
  end;
  Result := (LookupResult = SB_DNS_RESULT_SUCCESS);
end;

{$ifdef SB_IPv6}
function TElDNSSettings.ResolveHostName(const HostName: string; UseIPv6: Boolean;
  out Addr: TSockAddrStorage): Boolean;
var
  Resolver: TElDNSResolver;
  Response: TElDNSResourceRecordSet;
  Status: TSBDNSSecurityStatus;
  LookupResult: Integer;
begin
  if not FEnabled then
    Result := SBSocket.ResolveHostName(HostName, UseIPv6, Addr)
  else
  begin
    Resolver := nil;
    try
      Result := StringToAddress(HostName, Addr);
      if not Result or ((Addr.ss_family = AF_INET6) and not UseIPv6) then
      begin
        Result := False;
        FillChar(Addr, SizeOf(Addr), 0);
        if WinsockIPv6Enabled and UseIPv6 then
        begin
          Resolver := CreateResolver(Self);
          Response := TElDNSResourceRecordSet.Create;
          try
            LookupResult := Resolver.Lookup(HostName, dnsIPv6Address, Response, Status);
            DoResolve(HostName, Response, LookupResult, Status);
            Result := CheckLookupResult(FUseSecurity, FAllowStatuses, LookupResult, Status);
            if Result then
              Result := StringToAddress(TElDNSIPv6AddressRecord(Response[0]).Address, Addr);
          finally
            FreeAndNil(Response);
          end;
        end;
        // if IPv6 is not enabled or IPv6 should not be used or failed to get an IPv6 address,
        // try to get an IPv4 address
        if not Result then
        begin
          if not Assigned(Resolver) then
            Resolver := CreateResolver(Self);
          Response := TElDNSResourceRecordSet.Create;
          try
            LookupResult := Resolver.Lookup(HostName, dnsIPv4Address, Response, Status);
            DoResolve(HostName, Response, LookupResult, Status);
            Result := CheckLookupResult(FUseSecurity, FAllowStatuses, LookupResult, Status);
            if Result then
              Result := StringToAddress(TElDNSIPv4AddressRecord(Response[0]).Address, Addr)
          finally
            FreeAndNil(Response);
          end;
        end;
      end;
    finally
      FreeAndNil(Resolver);
    end;
  end;
end;
 {$else SB_IPv6}
function TElDNSSettings.ResolveHostName(const HostName: string): LongWord;
var
  Resolver: TElDNSResolver;
  Response: TElDNSResourceRecordSet;
  Status: TSBDNSSecurityStatus;
  LookupResult: Integer;
  HostEnt: PHostEnt;
begin
  Response := nil;
  Resolver := nil;
  {$ifndef SB_UNICODE_VCL}
  Result := inet_addr(PAnsiChar(HostName));
   {$else}
  Result := inet_addr(PAnsiChar( AnsiString(HostName) ));
   {$endif}
  if Result <> LongWord(INADDR_NONE) then
    Exit;
  if not FEnabled then
  begin
    {$ifndef SB_UNICODE_VCL}
    HostEnt := gethostbyname(PAnsiChar(HostName));
     {$else}
    HostEnt := gethostbyname(PAnsiChar( AnsiString(HostName) ));
     {$endif}
    if HostEnt <> nil then
      SBMove(HostEnt.h_addr^[0], Result, sizeof(Result));
  end
  else
  begin
    Resolver := CreateResolver(Self);
    try
      Response := TElDNSResourceRecordSet.Create;
      try
        LookupResult := Resolver.Lookup(HostName, dnsIPv4Address, Response, Status);
        DoResolve(HostName, Response, LookupResult, Status);
        if CheckLookupResult(FUseSecurity, FAllowStatuses, LookupResult, Status) then
          {$ifndef SB_UNICODE_VCL}
          Result := inet_addr(PAnsiChar(TElDNSIPv4AddressRecord(Response[0]).Address));
           {$else}
          Result := inet_addr(PAnsiChar( AnsiString(TElDNSIPv4AddressRecord(Response[0]).Address) ));
           {$endif}
      finally
        FreeAndNil(Response);
      end;
    finally
      FreeAndNil(Resolver);
    end;
  end;
end;
 {$endif SB_IPv6}

procedure TElDNSSettings.SetServers(const Value: TElStringList);
begin
  FServers.Assign(Value);
end;
 {$endif SB_DNSSEC}

{
********************************** TElSocket ***********************************
}

function TElSocket.LastNetError: Integer;
begin
{$ifdef SB_POSIX}
  Result := {$ifndef FPC}posix.errno.errno {$else}socketerror{fpgetCerrno} {$endif};
 {$endif}
{$ifdef SB_WINDOWS}
  Result := WSAGetLastError();
 {$endif}
end;

constructor TElSocket.Create (Owner: TComponent); 
begin
  inherited   ;
  {$ifdef SB_IPv6}{$ifdef NET_CF}
  SupportsIPv6Initialize();
   {$endif} {$endif}
  FSocket := INVALID_SOCKET;
  {$ifdef SB_IPv6}
  FUseIPv6 := False;
  FUsingIPv6 := False;
   {$endif}
  FSktType := istStream;
  FState := issNotASocket;
  SetLength(FBuffer, DEF_BUFFER_SIZE);
  FSocksVersion := elSocks5;
  FProxyResult := 0;
  FShuttingDown := false;
  {$ifndef SB_NO_SERVER_SOCKETS}
  FLocalBinding := TElClientSocketBinding.Create();
  FListenBinding := TElClientSocketBinding.Create();
   {$endif}

  {$ifdef SB_SILVERLIGHT_SOCKETS}
  FLastSocketError := 0;
   {$endif}


  {$ifdef SB_DNSSEC}
  FDNS := TElDNSSettings.Create;
  FDNS.OnKeyNeeded  :=  HandleDNSKeyNeeded;
  FDNS.OnKeyValidate  :=  HandleDNSKeyValidate;
  FDNS.OnResolve  :=  HandleDNSResolve;
   {$endif}


  FBandwidthPolicy := bpStrict;

  FWebTunnelRequestHeaders := TElStringList.Create;
  FWebTunnelRequestHeaders.Add(sDefaultUserAgent);

  FWebTunnelResponseHeaders := TElStringList.Create;
  FWebTunnelResponseBody := '';
  FWebTunnelResponseBodyLen := 0;
  {$ifdef SILVERLIGHT}
  FClientAccessPolicyProtocol := cappNone;
   {$endif}
  {$ifdef SB_WINRT_SOCKETS}
  FActivateReadLoop := true;
   {$endif}
end;

{$ifndef SB_NO_NET_COMPONENT}
constructor TElSocket.Create;
begin
  Create(nil);
end;
 {$endif}

 destructor  TElSocket.Destroy;
begin
  Close(false);
  {$ifndef SB_NO_SERVER_SOCKETS}
  FreeAndNil(FLocalBinding);
  FreeAndNil(FListenBinding);
   {$endif}
  {$ifdef SB_DNSSEC}
  FreeAndNil(FDNS);
   {$endif}
  FreeAndNil(FWebTunnelRequestHeaders);
  FreeAndNil(FWebTunnelResponseHeaders);
  ReleaseArray(FBuffer);
  inherited;
end;

{$ifndef SB_NO_SERVER_SOCKETS}
function TElSocket.GetListenPort : Integer;
begin
  Result := FListenBinding.Port;
end;

procedure TElSocket.SetListenPort(Value : Integer);
begin
  FListenBinding.Port := Value;
end;

function TElSocket.GetListenPortRangeFrom: Integer;
begin
  Result := FListenBinding.PortRangeFrom;
end;

procedure TElSocket.SetListenPortRangeFrom(Value: Integer);
begin
  FListenBinding.PortRangeFrom := Value;
end;

function TElSocket.GetListenPortRangeTo: Integer;
begin
  Result := FListenBinding.PortRangeTo;
end;

procedure TElSocket.SetListenPortRangeTo(Value: Integer);
begin
  FListenBinding.PortRangeTo := Value;
end;

function TElSocket.GetListenAddress: string;
begin
  Result := FListenBinding.LocalIntfAddress;
end;

procedure TElSocket.SetListenAddress(Value: string);
begin
  FListenBinding.LocalIntfAddress := Value;
end;
 {$endif SB_SILVERLIGHT_SOCKET}

procedure TElSocket.SetNonBlocking;
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
var nbs : integer;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  nbs := 1;
  {$ifdef SB_WINDOWS}
  ioctlsocket(FSocket, FIONBIO, u_long(nbs));
   {$else}
  {$ifndef FPC}
  ioctl(FSocket, FIONBIO, u_long(nbs));
   {$else FPC}
  fpioctl(FSocket, FIONBIO, @nbs);
   {$endif FPC}
   {$endif SB_WINDOWS}
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

procedure TElSocket.DoSetUseNagle(Value: Boolean);
var
  i : integer;
begin
  try
    if (FSktType = istStream) and (FState >= issInitialized) then
    begin
      if Value then
        i := 0
      else
        i := 1;
      {$ifndef FPC}
      i := setsockopt(FSocket, IPPROTO_TCP, TCP_NODELAY, {$ifdef SB_SetSockOptByRef}@ {$endif}i, sizeof(i));
       {$else}
      i := fpsetsockopt(FSocket, IPPROTO_TCP, TCP_NODELAY, @i, sizeof(i));
       {$endif}
    end;
  except
    ;
  end;
end;

procedure TElSocket.IntSetUseNagle(Value: Boolean);
begin
  FUseNagle := Value;
  DoSetUseNagle(Value);
end;

function TElSocket.GetRequestHeaders : string;
var
  i : integer;
begin
  Result := '';
  for i := 0 to FWebTunnelRequestHeaders.Count - 1 do
    Result := Result + FWebTunnelRequestHeaders[i] + #13#10;
end;

{$ifndef SB_WINRT_SOCKETS}
procedure TElSocket.ShutdownSocket();
begin
  ShutdownSocket(sdSendAndReceive);
end;

procedure TElSocket.ShutdownSocket(Direction : TElShutdownDirection);
begin
  if ( FSocket <> INVALID_SOCKET ) and (not FShuttingDown) then
  begin
    FShuttingDown := true;
    {$ifdef SB_WINDOWS}
    shutdown(FSocket, integer(Direction));
     {$else}
    {$ifdef FPC}
    fpshutdown(FSocket, integer(Direction));
     {$else}
    shutdown(FSocket, integer(Direction));
     {$endif}
     {$endif SB_WINDOWS}
  end;
end;
 {$endif}

procedure TElSocket.PollRemainingDataForShutdown(Timeout : integer);
var
  Elapsed  : integer;
  StartTime: TElDateTime;
  ToRecv   : integer;
  Buf      : ByteArray;
  res      : integer;
  ErrorCode: integer;
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  Elapsed := 0;

  ToRecv := {$ifdef SB_CONSTRAINED_DEVICE}8192 {$else}65536 {$endif};

  SetLength(Buf, ToRecv);

  SetNonBlocking();

  try
    while ((Elapsed < Timeout) or (Timeout = 0)) do
    begin
      StartTime := Now;
      try
        res := InternalReceive(@Buf[0], ToRecv);
        if (res = 0) then Break;

        if res = SOCKET_ERROR then
        begin
          ErrorCode := LastNetError;
          if (ErrorCode = SB_SOCKET_ERROR_CODE_WOULDBLOCK) then
            {$ifdef SB_WINDOWS_OR_NET}
              Sleep(200)
             {$else}
              Sleep(200)
             {$endif}
          else
            break;
        end;
      except
        on E : Exception do
          break;
      end;
      
      Elapsed := Elapsed + Trunc((Now() - StartTime) * 86400 * 1000 + 0.5);
    end;
  finally
    ReleaseArray(Buf);
  end;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

procedure TElSocket.Close(Forced: boolean);
begin
  Close(Forced, 60000);
end;

procedure TElSocket.Close(Forced: boolean; Timeout : integer);
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  if  FSocket <> INVALID_SOCKET  then
  begin
    FBufStart := 0;
    FBufLen := 0;

    {$ifndef SB_WINRT_SOCKETS}
    if not Forced then
    begin
      ShutdownSocket(sdSendAndReceive);
      try
        PollRemainingDataForShutdown(Timeout);
      except
      end;
      FShuttingDown := false;
    end;
     {$endif}

    // ----------------------------------
    // close the socket now

  {$ifdef SB_WINDOWS}
    closesocket(FSocket);
   {$else}
   {$ifdef FPC}
    fpclose(FSocket);
     {$else}
    __close(FSocket);
     {$endif}
   {$endif SB_WINDOWS}
    FSocket := INVALID_SOCKET;

    {$ifdef SB_IPv6}
    FUsingIPv6 := False;
     {$endif}
    FState := issNotASocket;
  end
  else
  if FState = issInitializing then
  begin
    CloseRequest := true;
    FState := issNotASocket;
  end;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

function TElSocket.CanReceive(WaitTime: integer  =  0): Boolean;
var
  ANow : integer;
{$ifdef SB_SILVERLIGHT_SOCKETS}
  IsAsync : boolean;
  //WaitRes : Boolean;
 {$endif}

{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  FDSet: TFDSet;
  ATimeVal: TTimeVal;
  PTV: PTimeVal;
 {$endif}
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}

{$ifdef SB_SILVERLIGHT_SOCKETS}
  if (FBufLen <= FBufStart) and (not SLPendingReceiveCleared(WaitTime)) then
  begin
    result := false;
    {$ifndef WP}
    {$ifdef DEBUG}
     {$endif}
     {$endif}
    exit;
  end;
 {$endif}

  if FBufLen > FBufStart then
  begin
    result := true;
    exit;
  end;
  if (State <> issConnected) and (FSktType = istStream) then
    raise EElSocketError.Create(Format(sWrongSocketState, [Integer(State), 'CanReceive']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);

  if FIncomingSpeedLimit > 0 then
  begin
    ANow := GetTickCount;
    if FBandwidthPolicy = bpStrict then
    begin
      // if the check is immediate, we test if we can receive anything within the time period
      // between the beginning of the current second and the beginning of the next second
      if (WaitTime = 0) then
      begin
        if TickDiff(FblLastRecvTime, ANow) < 1000 then
        begin
          if FblLastRecvSize >= FIncomingSpeedLimit then
          begin
            result := false;
            exit;
          end;
        end;
      end;
    end;
  end;

{$ifndef SB_SILVERLIGHT_SOCKETS}

  PTV := @ATimeVal;
  if WaitTime = -1 then
    PTV := nil
  else
  if WaitTime = 0 then
  begin
    ATimeVal.tv_sec := 0;
    ATimeVal.tv_usec := 0;
  end
  else
  begin
    ATimeVal.tv_sec := WaitTime div 1000;
    ATimeVal.tv_usec := (WaitTime mod 1000) * 1000;
  end;
  {$ifdef SB_WINDOWS}
  FD_ZERO(FDSet);
  FD_SET(FSocket, FDSet);
   {$else}
  {$ifdef FPC}
  FpFD_ZERO(FDSet);
  FpFD_SET(FSocket, FDSet);
   {$else}
  __FD_ZERO(FDSet);
  __FD_SET(FSocket, FDSet);
   {$endif}
   {$endif}
  result := {$ifdef SB_WINDOWS}select {$else}{$ifdef FPC}fpselect {$else}select {$endif} {$endif}(FSocket + 1, @FDSet, nil, nil, PTV) > 0;
 {$else ifndef SB_SILVERLIGHT_SOCKETS}
  {$ifdef DEBUG}
   {$endif}

  FBufStart := 0;
  FBufLen := 0;
  FSocketRecvArgs.SetBuffer(FBuffer, 0, DEF_BUFFER_SIZE);

  FRecvInProgress := true;
  // II20120124: added the line below
  FRecvDoneFlag.Reset;
  IsAsync := FSocket.ReceiveAsync(FSocketRecvArgs);
  if not IsAsync then
  begin
    FRecvInProgress := false;
    result := true;
    FBufLen := FSocketRecvArgs.BytesTransferred;
    {$ifdef DEBUG}
     {$endif}
  end
  else
  // Async mode initiated
  if (WaitTime > 0) then
  begin
    // now wait for certain time until connection is established
    Result := FRecvDoneFlag.WaitOne(WaitTime);
    // II20120124: commented out the line below
    //FRecvDoneFlag.Reset();
    if Result then
    begin
      // II20120124: added two lines below
      FRecvInProgress := false;
      FRecvDoneFlag.Reset();
      FBufLen := FSocketRecvArgs.BytesTransferred;
      {$ifdef DEBUG}
       {$endif}
    end;
  end
  else
    result := false;
 {$endif}

 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;
  // Java

{$ifndef SB_SILVERLIGHT_SOCKETS}
{$ifndef SB_WINRT_SOCKETS}
function TElSocket.AsyncConnect(Timeout: integer): Integer;
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
var
  {$ifdef SB_IPv6}
  FAddr: TSockAddrStorage;
   {$else}
  FAddr: TSockAddrIn;
  addr: LongWord;
  HostEnt: PHostEnt;
   {$endif}
  {$ifdef SB_WINDOWS}
  FAddrLen: integer;
   {$else}
  FAddrLen: cardinal;
   {$endif}
  //nbs: integer;
  FDSendSet, FDErrSet: TFDSet;
  TV: TTimeVal;
  select_res: Integer;
  ErrorCode: integer;
  ErrCode : integer;
  {$ifdef SB_WINDOWS}
  ErrCodeLen : integer;
   {$endif}
  {$ifdef SB_POSIX}
  {$ifndef SB_DELPHI_POSIX}
  ErrCodeLen : integer;
   {$else}
  ErrCodeLen : cardinal;
   {$endif SB_DELPHI_POSIX}
   {$endif SB_POSIX}

  {$ifdef SB_IPv6}
  UseIPv6: Boolean;
   {$endif}

 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  FProxyResult := 0;

  if (FState <> issNotASocket) and (FState <> issInitialized) and (FState <> issBound) then
    raise EElSocketError.Create(Format(sWrongSocketState, [Integer(State), 'AsyncConnect']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);

    FillChar(FAddr, sizeof(FAddr), 0);
    {$ifdef SB_IPv6}
      if FSocket = INVALID_SOCKET then  // if there is no socket handle available
        UseIPv6 := WinsockIPv6Enabled and FUseIPv6  // if IPv6 enabled in OS and in UseIPv6 property
      else
        UseIPv6 := FUsingIPv6;                      // if socket handle is IPv6

      // resolve address or host name
      {$ifdef SB_DNSSEC}
      if not FDNS.ResolveHostName(StringTrim(FRemoteAddress), UseIPv6, FAddr) then
       {$else}
      if not ResolveHostName(StringTrim(FRemoteAddress), UseIPv6, FAddr) then
       {$endif}
        raise EElSocketError.Create(sInvalidAddress, SB_SOCKET_ERROR_INVALID_ADDRESS);
      // check address family
      if FAddr.ss_family = AF_INET6 then  // there is IPv6 address available
        PSockAddrIn6(@FAddr).sin6_port := htons(FRemotePort)
      else                                // there is IPv4 only address available
      if not FUsingIPv6 then  // if socket handle is already available and it's not IPv6
      begin
        PSockAddrIn(@FAddr).sin_port := htons(FRemotePort);
        UseIPv6 := False;
      end
      else  // socket handle is IPv6 but there is no IPv6 address available for the host
        raise EElSocketError.Create(sAddressFamilyMismatch, SB_SOCKET_ERROR_ADDRESS_FAMILY_MISMATCH);
     {$else}
      {$ifndef SB_UNICODE_VCL}
      addr := inet_addr(PAnsiChar(StringTrim(FRemoteAddress)));
       {$else}
      addr := inet_addr(PAnsiChar(AnsiString(StringTrim(FRemoteAddress))));
       {$endif}

      {$ifdef SB_DNSSEC}
      addr := FDNS.ResolveHostName((FRemoteAddress));
       {$else}
      if addr = LongWord(INADDR_NONE) then
      begin
        {$ifndef SB_UNICODE_VCL}
        HostEnt := gethostbyname(PAnsiChar(StringTrim(FRemoteAddress)));
         {$else}
        HostEnt := gethostbyname(PAnsiChar( AnsiString(StringTrim(FRemoteAddress)) ));
         {$endif}
        if HostEnt <> nil then
          SBMove(HostEnt.h_addr_list^[0], addr, sizeof(addr));

      end;
       {$endif}
      if addr = LongWord(INADDR_NONE) then
        raise EElSocketError.Create(sInvalidAddress, SB_SOCKET_ERROR_INVALID_ADDRESS);

      FAddr.sin_family := AF_INET;
      FAddr.sin_addr.S_addr := addr;
      FAddr.sin_port := htons(FRemotePort);
     {$endif}

  // if socket is not yet initialized
  if  (FSocket = INVALID_SOCKET)  then
  begin
    SocketType := istStream;
    if Init({$ifdef SB_IPv6}UseIPv6 {$endif}) <> 0 then
      raise EElSocketError.Create(sNotASocket, SB_SOCKET_ERROR_NOT_A_SOCKET);
  end;

  {$ifndef SB_NO_SERVER_SOCKETS}
  if (Length(FLocalBinding.LocalIntfAddress) <> 0) and (FState <> issBound) then
    Result := Bind(True, false)
  else
   {$endif}
    Result := 0;
  if Result <> 0 then
    Exit;

  if Timeout <> 0 then
  begin
    SetNonBlocking;
  end;

{$ifdef SB_WINDOWS}
  {$ifdef SB_IPv6}
  Result := Winsock.connect(FSocket, PSockAddrIn(@FAddr)^, SizeOf(FAddr));
   {$else}
  result := winsock.connectFSocket, FAddr, sizeof(FAddr));
   {$endif}
 {$else}
  {$ifndef FPC}
  {$ifndef SB_DELPHI_POSIX}
  result := connect(FSocket, @FAddr, sizeof(FAddr));
   {$else}
  result := Posix.SysSocket.connect(FSocket, PSockAddr(@FAddr)^, SizeOf(FAddr));
   {$endif}
   {$else}
  result := fpconnect(FSocket, @FAddr, sizeof(FAddr));
   {$endif}
 {$endif}
  if Result <> 0 then
  begin
    ErrorCode := LastNetError();
    if Timeout > 0 then
    begin
      if (ErrorCode <> SB_SOCKET_ERROR_CODE_WOULDBLOCK) and (ErrorCode <> SB_SOCKET_ERROR_CODE_ISCONN) and (ErrorCode <> SB_SOCKET_ERROR_CODE_INPROGRESS) then
      begin
        FState := issInitialized;
        Result := ErrorCode;
      end
      else
      if ErrorCode = SB_SOCKET_ERROR_CODE_ISCONN then
        FState := issConnected
      else
        FState := issConnecting;
    end;
  end
  else
    FState := issConnected;

  if FState = issConnecting then
  begin
    {$ifdef SB_WINDOWS}
    FD_ZERO(FDSendSet);
    FD_SET(FSocket, FDSendSet);
    FD_ZERO(FDErrSet);
    FD_SET(FSocket, FDErrSet);
     {$else}
    {$ifdef FPC}
    fpFD_ZERO(FDSendSet);
    fpFD_SET(FSocket, FDSendSet);
    fpFD_ZERO(FDErrSet);
    fpFD_SET(FSocket, FDErrSet);
     {$else}
    __FD_ZERO(FDSendSet);
    __FD_SET(FSocket, FDSendSet);
    __FD_ZERO(FDErrSet);
    __FD_SET(FSocket, FDErrSet);
     {$endif}
     {$endif}
    TV.tv_sec := Timeout div 1000;
    TV.tv_usec := (Timeout mod 1000) * 1000;
    select_res := {$ifdef SB_WINDOWS}select {$else}{$ifdef FPC}fpselect {$else}select {$endif} {$endif}(FSocket + 1, nil, @FDSendSet, @FDErrSet, @TV);
    if select_res = 1 then
    begin
      {$ifdef SB_WINDOWS}
      if FD_ISSET(FSocket, FDSendSet) then
       {$else}
      {$ifdef FPC}
      if fpFD_ISSET(FSocket, FDSendSet) = 1 then
       {$else}
      if __FD_ISSET(FSocket, FDSendSet) then
       {$endif}
       {$endif}
      begin
        FState := issConnected;
        result := 0;
      end
      else
      {$ifdef SB_WINDOWS}
      if FD_ISSET(FSocket, FDErrSet) then
       {$else}
      {$ifdef FPC}
      if fpFD_ISSET(FSocket, FDErrSet) = 1 then
       {$else}
      if __FD_ISSET(FSocket, FDErrSet) then
       {$endif}
       {$endif}
      begin
        FState := issInitialized;
        ErrCodeLen := SizeOf(ErrCode);
        ErrCode := 0;
        {$ifdef SB_WINDOWS}
        if getsockopt(FSocket, SOL_SOCKET, SO_ERROR, @ErrCode, ErrCodeLen) = 0 then
         {$else}
        {$ifdef FPC}
        if fpgetsockopt(FSocket, SOL_SOCKET, SO_ERROR, @ErrCode, {$ifdef SB_POSIX}@ {$endif}ErrCodeLen) = 0 then
         {$else}
        if getsockopt(FSocket, SOL_SOCKET, SO_ERROR, ErrCode, ErrCodeLen) = 0 then
         {$endif}
         {$endif}
          result := ErrCode
        else
          result := -1;
      end
      else
        result := -1;
    end
    else
    if select_res = 0 then
    begin
      FState := issInitialized;
      result := SB_SOCKET_ERROR_CODE_TIMEDOUT;
    end
    else
    begin
      FState := issInitialized;
      result := LastNetError;
    end;
  end;

  if FState = issConnected then
  begin
    FAddrLen := sizeof(FAddr);
{$ifdef SB_WINDOWS}
    {$ifdef FPC}
    Result := fpgetsockname(FSocket, @FAddr, @FAddrLen);
     {$else}
    {$ifdef SB_IPv6}
    Result := getsockname(FSocket, PSockAddr(@FAddr)^, FAddrLen);
     {$else}
    result := winsock.getsockname(FSocket, FAddr, FAddrLen);
     {$endif}
     {$endif}
 {$else}
  {$ifdef FPC}
    result := fpgetsockname(FSocket, @FAddr, @FAddrLen);
   {$else}
    result := getsockname(FSocket, PSockAddr(@FAddr)^, FAddrLen);
   {$endif}
 {$endif}
//    if result = 0 then
// when getsockname returns an error then FBound* receive just empty values
    {$ifdef SB_IPv6}
    AddressToString(FAddr, FBoundAddress);
    if FAddr.ss_family = AF_INET6 then
      FBoundPort := ntohs(PSockAddrIn6(@FAddr).sin6_port)
    else
      FBoundPort := ntohs(PSockAddrIn(@FAddr).sin_port);
     {$else}
    FBoundAddress := (((PAnsiChar(inet_ntoa(FAddr.sin_addr)))));
    FBoundPort := ntohs(FAddr.sin_port);
     {$endif}
  end;
  if result = 0 then
    FState := issConnected;
  if FState = issConnected then
    DoAfterConnect();
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;
 {$else ifndef SB_WINRT_SOCKETS}
function TElSocket.AsyncConnect(Timeout: integer): Integer;
var
  WaitRes : boolean;
  hostName : HostName;
  ar : IAsyncAction;
begin
  FProxyResult := 0;

  if (FState <> issNotASocket) and (FState <> issInitialized) and (FState <> issBound) then
    raise EElSocketError.Create(System.String.Format(sWrongSocketState, [Integer(State), 'AsyncConnect']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);

  if (not Assigned(FSocket)) then
  begin
    SocketType := istStream;
    if Init({$ifdef SB_IPv6}UseIPv6 {$endif}) <> 0 then
      raise EElSocketError.Create(sNotASocket, SB_SOCKET_ERROR_NOT_A_SOCKET);
  end;
  SetLength(FInputSpool, 0);

  hostName := new HostName(FRemoteAddress);

  try
    ar := FSocket.ConnectAsync(hostName, Port.ToString()) as IAsyncAction;
    try
      ar.Completed := new AsyncActionCompletedHandler(HandleConnectAsyncCompleted);
      if (ar.Status <> AsyncStatus.Completed) then
      begin
        if Timeout = 0 then
          WaitRes := FOpDoneFlag.WaitOne()
        else
          WaitRes := FOpDoneFlag.WaitOne(Timeout);
        FOpDoneFlag.Reset();
        if WaitRes = false then
        begin
          ar.Cancel;
          raise {$ifndef SB_NO_NET_SOCKETS}EElSocketError {$else}EElSocketHandlerError {$endif}.Create(sTimeout, SB_SOCKET_ERROR_CODE_TIMEDOUT);
        end;
        if ar.Status <> AsyncStatus.Completed then
          raise ar.ErrorCode;
      end;
    finally
      ar.Close();
    end;
    // in WinRT variant, we launch a continuous 'receive loop'.
    FSessionStartTick := GetTickCount;
    RTStartReceiveLoop();
    result := 0;
  except
    on E : {$ifndef SB_NO_NET_SOCKETS}EElSocketError {$else}EElSocketHandlerError {$endif} do
    begin
      LastNetError := E.ErrorCode;
      result := LastNetError;
    end;
    on E : Exception do
    begin
      if E.HResult <> 0 then
      begin
        LastNetError := E.HResult;
        result := E.HResult;
      end
      else
      begin
        LastNetError := -1;
        result := -1;
      end;
    end;
  end;

  if result = 0 then
    FState := issConnected;
  if FState = issConnected then
    DoAfterConnect();
end;
 {$endif}
 {$else ifndef SB_SILVERLIGHT_SOCKETS}
function TElSocket.AsyncConnect(Timeout: integer): Integer;
var
  WaitRes : boolean;
  IsAsync : boolean;
{$ifndef SB_NO_NET_SOCKETS}
  RemoteIP: IPAddress;
 {$endif}
{$ifdef SB_SILVERLIGHT_SOCKETS}
  err : integer;
 {$endif}
begin
  FProxyResult := 0;

  if (FState <> issNotASocket) and (FState <> issInitialized) and (FState <> issBound) then
    raise EElSocketError.Create(System.String.Format(sWrongSocketState, [Integer(State), 'AsyncConnect']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);

  // if socket is not yet initialized
  if (not Assigned(FSocket)) then
  begin
    SocketType := istStream;
    if Init({$ifdef SB_IPv6}UseIPv6 {$endif}) <> 0 then
      raise EElSocketError.Create(sNotASocket, SB_SOCKET_ERROR_NOT_A_SOCKET);
  end;

  {$ifndef SB_NO_NET_SOCKETS}
  FSocketSendArgs.Completed += new EventHandler<SocketAsyncEventArgs>(SocketArgs_Completed);
  FSocketRecvArgs.Completed += new EventHandler<SocketAsyncEventArgs>(SocketArgs_Completed);
   {$else}
  FSocketSendArgs.Completed += new TSBAsyncEventArgsEvent(SocketArgs_Completed);
  FSocketRecvArgs.Completed += new TSBAsyncEventArgsEvent(SocketArgs_Completed);
   {$endif}
  {$ifdef SILVERLIGHT}
  {$ifndef SB_NO_NET_SOCKETS}
  FSocketSendArgs.RemoteEndPoint := DnsEndPoint.Create(FRemoteAddress, Port);
   {$else}
  FSocketSendArgs.RemoteAddress := FRemoteAddress;
  FSocketSendArgs.RemotePort := Port;
   {$endif}

  {$ifdef WP}
    {$define NO_POLICY}
   {$endif}
  {$ifdef SILVERLIGHT30}
    {$define NO_POLICY}
   {$endif}

  {$ifndef NO_POLICY}
  if FClientAccessPolicyProtocol = TElSocketClientAccessPolicyProtocol.cappTcp then
    FSocketSendArgs.SocketClientAccessPolicyProtocol := SocketClientAccessPolicyProtocol.Tcp
  else if FClientAccessPolicyProtocol = TElSocketClientAccessPolicyProtocol.cappHttp then
    FSocketSendArgs.SocketClientAccessPolicyProtocol := SocketClientAccessPolicyProtocol.Http;
   {$endif}
   {$else}
  {$ifndef SB_NO_NET_SOCKETS}
  try
    RemoteIP := IPAddress.Parse(FRemoteAddress);
  except
    RemoteIP := nil;
  end;
  if (RemoteIP = nil) then
    RemoteIP := System.Net.Dns.Resolve(FRemoteAddress).AddressList[0];
  FSocketSendArgs.RemoteEndPoint := IPEndPoint.Create(RemoteIP, Port);
   {$else}
  FSocketSendArgs.RemoteAddress := FRemoteAddress;
  FSocketSendArgs.RemotePort := Port;
   {$endif}
   {$endif}
  FSocketSendArgs.UserToken := Self;
  FSocketRecvArgs.UserToken := Self;

  try
    FConnectInProgress := true;
    IsAsync := FSocket.ConnectAsync(FSocketSendArgs);

    if IsAsync then
    begin
      // now wait for certain time until connection is established
      if Timeout = 0 then
        WaitRes := FSendDoneFlag.WaitOne()
      else
        WaitRes := FSendDoneFlag.WaitOne(Timeout);
      FSendDoneFlag.Reset();
      FConnectInProgress := false;
      if WaitRes = false then
      begin
        {$ifdef SILVERLIGHT}
        FSocket.CancelConnectAsync(FSocketSendArgs);
         {$endif}
        raise {$ifndef SB_NO_NET_SOCKETS}SocketException {$else}EElSocketHandlerError {$endif}.Create(SB_SOCKET_ERROR_CODE_TIMEDOUT);
      end
      else
      if FLastSocketError <> 0 then
      begin
        err := FLastSocketError;
        FLastSocketError := 0;
        raise {$ifndef SB_NO_NET_SOCKETS}SocketException {$else}EElSocketHandlerError {$endif}.Create(err);
      end;
    end
    else
    begin
      FConnectInProgress := false;
      if (FSocketSendArgs.SocketError <> {$ifndef SB_NO_NET_SOCKETS}SocketError.Success {$else}0 {$endif}) then
        raise {$ifndef SB_NO_NET_SOCKETS}SocketException {$else}EElSocketHandlerError {$endif}.Create(Integer(FSocketSendArgs.SocketError));
    end;
    result := 0;
  except
    on E : {$ifndef SB_NO_NET_SOCKETS}SocketException {$else}EElSocketHandlerError {$endif} do
    begin
      LastNetError := E.ErrorCode;
      result := LastNetError;
    end;
    on E : Exception do
    begin
      LastNetError := -1;
      result := -1;
    end;
  end;

  if result = 0 then
    FState := issConnected;
  if FState = issConnected then
    DoAfterConnect();
end;
 {$endif}
  // Java

{$ifdef SB_SILVERLIGHT_SOCKETS}
class procedure TElSocket.SocketArgs_Completed(Sender : Object; e : {$ifndef SB_NO_NET_SOCKETS}SocketAsyncEventArgs {$else}TElCustomSocketHandlerAsyncEventArgs {$endif} );
begin
  case e.LastOperation of
    {$ifndef SB_NO_NET_SOCKETS}SocketAsyncOperation.Connect {$else}TSBSocketAsyncOperation.saoConnect {$endif}:
      TElSocket(e.UserToken).SLProcessConnect(e);
    {$ifndef SB_NO_NET_SOCKETS}SocketAsyncOperation.Receive {$else}TSBSocketAsyncOperation.saoReceive {$endif}:
      TElSocket(e.UserToken).SLProcessReceive(e);
    {$ifndef SB_NO_NET_SOCKETS}SocketAsyncOperation.Send {$else}TSBSocketAsyncOperation.saoSend {$endif}:
      TElSocket(e.UserToken).SLProcessSend(e);
  end; // case
end;

procedure TElSocket.SLProcessConnect(e : {$ifndef SB_NO_NET_SOCKETS}SocketAsyncEventArgs {$else}TElCustomSocketHandlerAsyncEventArgs {$endif} );
begin
  FConnectInProgress := false;
  if (e.SocketError <> {$ifndef SB_NO_NET_SOCKETS}SocketError.Success {$else}0 {$endif}) then
    TElSocket(e.UserToken).FLastSocketError := Integer(e.SocketError);
  FSendDoneFlag.Set();
end;

procedure TElSocket.SLProcessReceive(e : {$ifndef SB_NO_NET_SOCKETS}SocketAsyncEventArgs {$else}TElCustomSocketHandlerAsyncEventArgs {$endif} );
begin
  //Log('SLProcessReceive');
  if (e.SocketError <> {$ifndef SB_NO_NET_SOCKETS}SocketError.Success {$else}0 {$endif}) then
    TElSocket(e.UserToken).FLastSocketError := Integer(e.SocketError);
  FRecvDoneFlag.Set();
end;

procedure TElSocket.SLProcessSend(e : {$ifndef SB_NO_NET_SOCKETS}SocketAsyncEventArgs {$else}TElCustomSocketHandlerAsyncEventArgs {$endif} );
begin
  //Log('SLProcessSend');
  FSendInProgress := false;
  if (e.SocketError <> {$ifndef SB_NO_NET_SOCKETS}SocketError.Success {$else}0 {$endif}) then
    TElSocket(e.UserToken).FLastSocketError := Integer(e.SocketError);
  FSendDoneFlag.Set();
end;
 {$endif}

function TElSocket.CanSend(WaitTime: integer  =  0): Boolean;
var
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  FDSet: TFDSet;
  TimeVal: TTimeVal;
  PTV: PTimeVal;
 {$endif}
  ANow : integer;
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  if (State <> issConnected) and (FSktType = istStream) then
    raise EElSocketError.Create(Format(sWrongSocketState, [Integer(State), 'CanSend']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);

  if FOutgoingSpeedLimit > 0 then
  begin
    ANow := GetTickCount;
    if FBandwidthPolicy = bpStrict then
    begin
      // if the check is immediate, we test if we can receive anything within the time period
      // between the beginning of the current second and the beginning of the next second
      if (WaitTime = 0) then
      begin
        if TickDiff(FblLastSentTime, ANow) < 1000 then
        begin
          if FblLastSentSize >= FOutgoingSpeedLimit then
          begin
            result := false;
            exit;
          end;
        end;
      end;
    end;
  end;

{$ifndef SB_SILVERLIGHT_SOCKETS}
{$ifndef SB_WINRT_SOCKETS}
  PTV := @TimeVal;
  if WaitTime = -1 then
    PTV := nil
  else
  if WaitTime = 0 then
  begin
    TimeVal.tv_sec := 0;
    TimeVal.tv_usec := 0;
  end
  else
  begin
    TimeVal.tv_sec := WaitTime div 1000;
    TimeVal.tv_usec := (WaitTime mod 1000) * 1000;
  end;
  {$ifdef SB_WINDOWS}
  FD_ZERO(FDSet);
  FD_SET(FSocket, FDSet);
   {$else}
  {$ifdef FPC}
  fpFD_ZERO(FDSet);
  fpFD_SET(FSocket, FDSet);
   {$else}
  __FD_ZERO(FDSet);
  __FD_SET(FSocket, FDSet);
   {$endif}
   {$endif}
  {$ifdef SB_WINDOWS}
  result := select(FSocket + 1, nil, @FDSet, nil, PTV) <> 0;
   {$else}
  {$ifdef FPC}
  result := fpselect(FSocket + 1, nil, @FDSet, nil, PTV) <> 0;
   {$else}
  result := select(FSocket + 1, nil, @FDSet, nil, PTV) <> 0;
   {$endif}
   {$endif}
 {$else ifndef SB_WINRT_SOCKETS}
  result := true;
 {$endif}
 {$else ifndef SB_SILVERLIGHT_SOCKETS}
  result := not (FSendInProgress or FConnectInProgress);
 {$endif}
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

{$ifndef SB_NO_SERVER_SOCKETS}
function TElSocket.CanAccept(WaitTime: integer  =  0): Boolean;
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
var
  FDSet: TFDSet;
  TimeVal: TTimeVal;
  PTV: PTimeVal;
 {$endif}
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  if (State <> issListening) and (FSktType = istStream) then
    raise EElSocketError.Create(Format(sWrongSocketState, [Integer(State), 'CanAccept']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);

  PTV := @TimeVal;
  if WaitTime = -1 then
    PTV := nil
  else
    if WaitTime = 0 then
  begin
    TimeVal.tv_sec := 0;
    TimeVal.tv_usec := 0;
  end
  else
  begin
    TimeVal.tv_sec := WaitTime div 1000;
    TimeVal.tv_usec := (WaitTime mod 1000) * 1000;
  end;
  {$ifdef SB_WINDOWS}
  FD_ZERO(FDSet);
  FD_SET(FSocket, FDSet);
   {$else}
  {$ifdef FPC}
  fpFD_ZERO(FDSet);
  fpFD_SET(FSocket, FDSet);
   {$else}
  __FD_ZERO(FDSet);
  __FD_SET(FSocket, FDSet);
   {$endif}
   {$endif}
  {$ifdef SB_WINDOWS}
  result := select(FSocket + 1, @FDSet, nil, nil, PTV) > 0;
   {$else}
  {$ifdef FPC}
  result := fpselect(FSocket + 1, @FDSet, nil, nil, PTV) > 0;
   {$else}
  result := select(FSocket + 1, @FDSet, nil, nil, PTV) > 0;
   {$endif}
   {$endif}
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;
 {$endif}

function TElSocket.Connect(Timeout: integer): Integer;
var
  NextHeader : string;
begin
  FProxyResult := 0;
  if (FUseSocks) then
    Result := SocksConnect(Timeout)
  else
  if (FUseWebTunneling) then
  begin
    NextHeader := '';
    Result := HTTPConnect(Timeout, NextHeader);
    if (Result <> 0) and (Length(NextHeader) > 0) then
      Result := HTTPConnect(Timeout, NextHeader);
  end
  else
    Result := AsyncConnect(Timeout);
end;

{$ifndef SB_NO_SERVER_SOCKETS}
function TElSocket.Bind(): Integer;
begin
  Result := Bind(false);
end;

function TElSocket.Bind(Outgoing : boolean) : Integer;
begin
  Result := Bind(Outgoing, false);
end;

function TElSocket.Bind(Outgoing : boolean; ReuseAddress: boolean) : Integer;
var
  {$ifdef SB_IPv6}
  FAddr, RemoteAddr: TSockAddrStorage;
   {$else}
  FAddr: TSockAddrIn;
  addr: LongWord;
   {$endif}
  {$ifdef SB_WINDOWS}
  FAddrLen: integer;
   {$else}
  FAddrLen: cardinal;
   {$endif}
  AddrToBind : string;
  PortToBind : Integer;
  {$ifdef SB_IPv6}
  UseIPv6: Boolean;
   {$endif}
  OptValue: Integer;
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  if (FState <> issNotASocket) and (FState <> issInitialized) then
    raise EElSocketError.Create(Format(sWrongSocketState, [Integer(State), 'Bind']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);

  if Outgoing then
    AddrToBind := FLocalBinding.LocalIntfAddress
  else
    AddrToBind := FListenBinding.LocalIntfAddress;

  FillChar(FAddr, SizeOf(FAddr), 0);

  if Length(AddrToBind) = 0 then
  begin
    {$ifdef SB_IPv6}
      UseIPv6 := WinsockIPv6Enabled and FUseIPv6;  // is IPv6 support available and enabled?
      if UseIPv6 then
      begin
        FAddr.ss_family := AF_INET6;
        PSockAddrIn6(@FAddr).sin6_addr := IN6ADDR_ANY;
      end
      else                                         // IPv6 not available or disabled
      begin
        FAddr.ss_family := AF_INET;
        PSockAddrIn(@FAddr).sin_addr.S_addr := INADDR_ANY;
      end;
     {$else}
      FAddr.sin_family := AF_INET;
      FAddr.sin_addr.S_addr := LongWord(INADDR_ANY);
     {$endif}
  end
  else
  begin
    {$ifdef SB_IPv6}
      if not ResolveHostName(AddrToBind, FUseIPv6, FAddr) then
        raise EElSocketError.Create(sInvalidAddress, SB_SOCKET_ERROR_INVALID_ADDRESS);
      // check if the binding address is an IPv6 address
      UseIPv6 := (FAddr.ss_family = AF_INET6);
     {$else}
      FAddr.sin_family := AF_INET;
      {$ifndef SB_UNICODE_VCL}
      addr := inet_addr(PAnsiChar(AddrToBind));
       {$else}
      addr := inet_addr(PAnsiChar(AnsiString(AddrToBind)));
       {$endif SB_UNICODE_VCL}
      if addr = LongWord(INADDR_NONE) then
        raise EElSocketError.Create(sInvalidAddress, SB_SOCKET_ERROR_INVALID_ADDRESS);
      FAddr.sin_addr.S_addr := addr;
     {$endif SB_IPv6}
  end;

  if FState = issNotASocket then
  begin
  {$ifdef SB_IPv6}
      // if the socket is for outgoing purposes and IPv6 still enabled
      if Outgoing and UseIPv6 then
      begin
        // check if the remote host supports IPv6
        if {$ifdef SB_DNSSEC}FDNS. {$endif}ResolveHostName(FRemoteAddress, True, RemoteAddr) then
        begin
          UseIPv6 := (RemoteAddr.ss_family = AF_INET6);
          if not UseIPv6 then  // the remote host does not support IPv6
            if AddrToBind = '' then // if no bounding interface specified
            begin
              // reinit binding address to IPv4
              FillChar(FAddr, SizeOf(FAddr), 0);
              FAddr.ss_family := AF_INET;
              PSockAddrIn(@FAddr).sin_addr.S_addr := INADDR_ANY;
            end;
        end
        else
          raise EElSocketError.Create(sInvalidAddress, SB_SOCKET_ERROR_INVALID_ADDRESS);
      end;
   {$endif}
    if Init({$ifdef SB_IPv6}UseIPv6 {$endif}) <> 0 then
      raise EElSocketError.Create(sNotASocket, SB_SOCKET_ERROR_NOT_A_SOCKET);
  end;

  if not Outgoing then
  begin
    if (FListenBinding.Port <> 0) or ((FListenBinding.PortRangeFrom = 0) and (FListenBinding.PortRangeTo = 0)) then
      PortToBind := FListenBinding.Port
    else
      PortToBind := Max(FListenBinding.PortRangeFrom, 1);
  end
  else
  begin
    if (FLocalBinding.Port <> 0) or ((FLocalBinding.PortRangeFrom = 0) and (FLocalBinding.PortRangeTo = 0)) then
      PortToBind := FLocalBinding.Port
    else
      PortToBind := Max(FLocalBinding.PortRangeFrom, 1);
  end;

  if (not Outgoing) and ReuseAddress then
  begin
    OptValue := 1;
    {Result := }{$ifndef FPC_POSIX}setsockopt {$else}fpsetsockopt {$endif}(FSocket, SOL_SOCKET, SO_REUSEADDR, {$ifdef SB_SetSockOptByRef}@ {$endif}OptValue, sizeof(OptValue));
  end;

  result := 0;

  while true do
  begin
    {$ifdef SB_IPv6}
    if FUsingIPv6 then
      PSockAddrIn6(@FAddr).sin6_port := htons(PortToBind)
    else
      PSockAddrIn(@FAddr).sin_port := htons(PortToBind);
     {$else}
    FAddr.sin_port := htons(PortToBind);
     {$endif}
  {$ifdef SB_WINDOWS}
    {$ifdef SB_IPv6}
    Result := Winsock.bind(FSocket, PSockAddrIn(@FAddr)^, SizeOf(FAddr));
     {$else}
    result := winsock.bind(FSocket, FAddr, sizeof(FAddr));
     {$endif}
   {$else}
    {$ifdef FPC}
    result := fpbind(FSocket, @FAddr, sizeof(FAddr));
     {$else}
    result := Posix.SysSocket.bind(FSocket, PSockAddr(@FAddr)^, sizeof(FAddr));
     {$endif}
   {$endif}
    if result <> 0 then
    begin
      result := LastNetError();
      if result = SB_SOCKET_ERROR_CODE_ADDRINUSE then
      begin
        if not Outgoing then
        begin
          if (FListenBinding.Port <> 0) or ((FListenBinding.PortRangeFrom = 0) and (FListenBinding.PortRangeTo = 0)) then
            break
          else
          begin
            inc(PortToBind);

            if ((FListenBinding.PortRangeTo <= 0) and (PortToBind > 65535)) or (PortToBind > FListenBinding.PortRangeTo) then
              break;
          end;
        end
        else
        begin
          if (FLocalBinding.Port <> 0) or ((FLocalBinding.PortRangeFrom = 0) and (FLocalBinding.PortRangeTo = 0)) then
            break
          else
          begin
            inc(PortToBind);

            if ((FLocalBinding.PortRangeTo <= 0) and (PortToBind > 65535)) or (PortToBind > FLocalBinding.PortRangeTo) then
              break;
          end;
        end;
      end
      else
        break;
    end
    else
      break;
  end;

  if Result = 0 then
  begin
    FAddrLen := sizeof(FAddr);
{$ifdef SB_WINDOWS}
    {$ifdef SB_IPv6}
    Result := getsockname(FSocket, PSockAddrIn(@FAddr)^, FAddrLen);
     {$else}
    result := winsock.getsockname(FSocket, FAddr, FAddrLen);
     {$endif}
 {$else}
    {$ifdef FPC}
    result := fpgetsockname(FSocket, @FAddr, @FAddrLen);
     {$else}
    result := getsockname(FSocket, PSockAddr(@FAddr)^, FAddrLen);
     {$endif}
 {$endif}
    if result <> 0 then
      result := LastNetError()
    else
    begin
      {$ifdef SB_IPv6}
      AddressToString(FAddr, FBoundAddress);
      if FAddr.ss_family = AF_INET6 then
        FBoundPort := ntohs(PSockAddrIn6(@FAddr).sin6_port)
      else
        FBoundPort := ntohs(PSockAddrIn(@FAddr).sin_port);
       {$else}
      FBoundAddress := ((PAnsiChar(inet_ntoa(FAddr.sin_addr))));
      FBoundPort := ntohs(FAddr.sin_port);
       {$endif}
      result := 0;
    end;
  end;


  if result = 0 then
    FState := issBound;

 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;
 {$endif}

{$ifndef SB_NO_SERVER_SOCKETS}
function TElSocket.Listen: Integer;
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  if State <> issBound then
    raise EElSocketError.Create(Format(sWrongSocketState, [Integer(State), 'Listen']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);
  

  {$ifdef SB_WINDOWS}
  // use $7fffffff instead of SOMAXCONN because in Delphi its equal to 5 that is not correct for Winsock 2.x
  result := winsock.listen(FSocket, $7fffffff);
   {$else}
  {$ifdef FPC}
  result := fplisten(FSocket, SOMAXCONN);
   {$else}
  result := Posix.SysSocket.listen(FSocket, SOMAXCONN);
   {$endif}
   {$endif}
  if result <> 0 then
    result := LastNetError()
  else
    FState := issListening;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;
 {$endif}

{$ifndef SB_NO_SERVER_SOCKETS}
function TElSocket.Accept(Timeout: integer): Integer;
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
var
  {$ifdef SB_IPv6}
  FAddr: TSockAddrStorage;
   {$else}
  FAddr: TSockAddrIn;
   {$endif}
  {$ifdef SB_WINDOWS}
  FAddrLen: integer;
   {$else}
  FAddrLen: cardinal;
   {$endif}
//  nbs: integer;
  FDRecvSet: TFDSet;
  TV: TTimeVal;
  select_res: Integer;
 {$endif}
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  if State <> issListening then
    raise EElSocketError.Create(Format(sWrongSocketState, [Integer(State), 'Accept']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);

  if Timeout <> 0 then
  begin
    SetNonBlocking;
  end;

  {$ifdef SB_WINDOWS}
  FD_ZERO(FDRecvSet);
  FD_SET(FSocket, FDRecvSet);
   {$else}
  {$ifdef FPC}
  fpFD_ZERO(FDRecvSet);
  fpFD_SET(FSocket, FDRecvSet);
   {$else}
  __FD_ZERO(FDRecvSet);
  __FD_SET(FSocket, FDRecvSet);
   {$endif}
   {$endif}
  TV.tv_sec := Timeout div 1000;
  TV.tv_usec := (Timeout mod 1000) * 1000;
  {$ifdef SB_WINDOWS}
  select_res := select(FSocket + 1, @FDRecvSet, nil, nil, @TV);
   {$else}
  {$ifdef FPC}
  select_res := fpselect(FSocket + 1, @FDRecvSet, nil, nil, @TV);
   {$else}
  select_res := Posix.SysSelect.select(FSocket + 1, @FDRecvSet, nil, nil, @TV);
   {$endif}
   {$endif}
  if select_res = 1 then
  begin
    FillChar(FAddr, sizeof(FAddr), 0);
    {$ifdef SB_IPv6}
    if FUsingIPv6 then
      FAddr.ss_family := AF_INET6
    else
      FAddr.ss_family := AF_INET;
     {$else}
    FAddr.sin_family := AF_INET;
     {$endif}
    FAddrLen := sizeof(FAddr);
{$ifdef SB_WINDOWS}
    result := winsock.accept(FSocket, @FAddr, @FAddrLen);
 {$else}
    {$ifdef FPC}
    result := fpaccept(FSocket, @FAddr, @FAddrLen);
     {$else}
    result := Posix.SysSocket.Accept(FSocket, PSockAddr(@FAddr)^, FAddrLen);
     {$endif}
 {$endif}
    if result < 0 then
    begin
      FState := issBound;
      result := LastNetError();
    end
    else
    begin
      {$ifdef SB_IPv6}
      AddressToString(FAddr, FRemoteAddress);
      if FAddr.ss_family = AF_INET6 then
        FRemotePort := ntohs(PSockAddrIn6(@FAddr).sin6_port)
      else
        FRemotePort := ntohs(PSockAddrIn(@FAddr).sin_port);
       {$else}
      FRemoteAddress := ((PAnsiChar(inet_ntoa(FAddr.sin_addr))));
      FRemotePort := ntohs(FAddr.sin_port);
       {$endif}
{$ifdef SB_WINDOWS}
      winsock.closesocket(FSocket);
 {$else}
      {$ifdef FPC}
      fpclose(FSocket);
       {$else}
      __close(FSocket);
       {$endif}
 {$endif}
      FSocket := result;
      FState := issConnected;

      // get bound address
      FAddrLen := sizeof(FAddr);
{$ifdef SB_WINDOWS}
      {$ifdef SB_IPv6}
      Result := getsockname(FSocket, PSockAddrIn(@FAddr)^, FAddrLen);
       {$else}
      result := winsock.getsockname(FSocket, FAddr, FAddrLen);
       {$endif}
 {$else}
      {$ifdef FPC}
      result := fpgetsockname(FSocket, @FAddr, @FAddrLen);
       {$else}
      result := getsockname(FSocket, PSockAddr(@FAddr)^, FAddrLen);
       {$endif}
 {$endif}
      if result <> 0 then
        result := LastNetError()
      else
      begin
        {$ifdef SB_IPv6}
        AddressToString(FAddr, FBoundAddress);
        if FAddr.ss_family = AF_INET6 then
          FBoundPort := ntohs(PSockAddrIn6(@FAddr).sin6_port)
        else
          FBoundPort := ntohs(PSockAddrIn(@FAddr).sin_port);
         {$else}
        FBoundAddress := ((PAnsiChar(inet_ntoa(FAddr.sin_addr))));
        FBoundPort := ntohs(FAddr.sin_port);
         {$endif}
        result := 0;
      end;
    end;
  end
  else
    if select_res = 0 then
  begin
    FState := issBound;
    result := SB_SOCKET_ERROR_CODE_TIMEDOUT;
  end
  else
  begin
    FState := issBound;
    result := LastNetError();
  end;
  if result = 0 then
    FState := issConnected;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;
 {$endif}

{$ifndef SB_NO_SERVER_SOCKETS}
procedure TElSocket.Accept(Timeout: integer;  var Socket : TElSocket );
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
var
  {$ifdef SB_IPv6}
  FAddr: TSockAddrStorage;
   {$else}
  FAddr: TSockAddrIn;
   {$endif}
  {$ifdef SB_WINDOWS}
  FAddrLen: integer;
   {$else}
  FAddrLen: cardinal;
   {$endif}
//  nbs: integer;
  FDRecvSet: TFDSet;
  TV: TTimeVal;
  select_res: Integer;
  result : integer;
 {$endif}
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  Socket := nil;
  

  if State <> issListening then
    raise EElSocketError.Create(Format(sWrongSocketState, [Integer(State), 'Accept']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);

    if Timeout <> 0 then
    begin
      SetNonBlocking;
    end;

    if Timeout > 0 then
    begin
      {$ifdef SB_WINDOWS}
      FD_ZERO(FDRecvSet);
      FD_SET(FSocket, FDRecvSet);
       {$else}
      {$ifdef FPC}
      fpFD_ZERO(FDRecvSet);
      fpFD_SET(FSocket, FDRecvSet);
       {$else}
      __FD_ZERO(FDRecvSet);
      __FD_SET(FSocket, FDRecvSet);
       {$endif}
       {$endif}
      TV.tv_sec := Timeout div 1000;
      TV.tv_usec := (Timeout mod 1000) * 1000;
      {$ifdef SB_WINDOWS}
      select_res := select(FSocket + 1, @FDRecvSet, nil, nil, @TV);
       {$else}
      {$ifdef FPC}
      select_res := fpselect(FSocket + 1, @FDRecvSet, nil, nil, @TV);
       {$else}
      select_res := select(FSocket + 1, @FDRecvSet, nil, nil, @TV);
       {$endif}
       {$endif}
    end
    else
      select_res := 1;
    if select_res = 1 then
    begin
      FillChar(FAddr, sizeof(FAddr), 0);
      {$ifdef SB_IPv6}
      if FUsingIPv6 then
        FAddr.ss_family := AF_INET6
      else
        FAddr.ss_family := AF_INET;
       {$else}
      FAddr.sin_family := AF_INET;
       {$endif}
      FAddrLen := sizeof(FAddr);
  {$ifdef SB_WINDOWS}
      result := winsock.accept(FSocket, @FAddr, @FAddrLen);
   {$else}
      {$ifdef FPC}
      result := fpaccept(FSocket, @FAddr, @FAddrLen);
       {$else}
      result := Posix.SysSocket.accept(FSocket, PSockAddr(@FAddr)^, FAddrLen);
       {$endif}
   {$endif}
      if result > 0 then
      begin
        Socket := TElSocket.Create;
        Socket.FState := issConnected;
        Socket.FSocket := result;
        {$ifdef SB_IPv6}
        Socket.FUseIPv6 := FUseIPv6;
        Socket.FUsingIPv6 := FUsingIPv6;
        AddressToString(FAddr, Socket.FRemoteAddress);
        if FAddr.ss_family = AF_INET6 then
          Socket.FRemotePort := ntohs(PSockAddrIn6(@FAddr).sin6_port)
        else
          Socket.FRemotePort := ntohs(PSockAddrIn(@FAddr).sin_port);
         {$else}
        Socket.FRemoteAddress := ((PAnsiChar(inet_ntoa(FAddr.sin_addr))));
        Socket.FRemotePort := ntohs(FAddr.sin_port);
         {$endif}

        // get bound address
        FAddrLen := sizeof(FAddr);
  {$ifdef SB_WINDOWS}
        {$ifdef SB_IPv6}
        Result := getsockname(Socket.FSocket, PSockAddrIn(@FAddr)^, FAddrLen);
         {$else}
        result := winsock.getsockname(Socket.FSocket, FAddr, FAddrLen);
         {$endif}
   {$else}
        {$ifdef FPC}
        result := fpgetsockname(Socket.FSocket, @FAddr, @FAddrLen);
         {$else}
        result := getsockname(Socket.FSocket, PSockAddr(@FAddr)^, FAddrLen);
         {$endif}
   {$endif}
        if result = 0 then
        begin
          {$ifdef SB_IPv6}
          AddressToString(FAddr, Socket.FBoundAddress);
          if FAddr.ss_family = AF_INET6 then
            Socket.FBoundPort := ntohs(PSockAddrIn6(@FAddr).sin6_port)
          else
            Socket.FBoundPort := ntohs(PSockAddrIn(@FAddr).sin_port);
           {$else}
          Socket.FBoundAddress := ((PAnsiChar(inet_ntoa(FAddr.sin_addr))));
          Socket.FBoundPort := ntohs(FAddr.sin_port);
           {$endif}
        end;

      end;
    end
    else
    if select_res = 0 then
    begin
      ; // doing nothing
    end
    else
      raise EElSocketError.Create(sAcceptFailed, SB_SOCKET_ERROR_ACCEPT_FAILED);

 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;
 {$endif}


{$ifndef SB_SILVERLIGHT_SOCKETS}
{$ifndef SB_WINRT_SOCKETS}
function TElSocket.StartAsyncConnect: Integer;
var
  {$ifdef SB_IPv6}
  FAddr: TSockAddrStorage;
   {$else}
  FAddr: TSockAddrIn;
  addr: LongWord;
  HostEnt: PHostEnt;
   {$endif}
//  nbs: integer;
  ErrorCode: integer;
  {$ifdef SB_IPv6}
  UseIPv6: Boolean;
   {$endif}

begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  // check the current state
  if (State <> issNotASocket) and (State <> issInitialized) and (State <> issBound) then
    raise EElSocketError.Create(Format(sWrongSocketState, [Integer(State), 'StartAsyncConnect']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);

    FillChar(FAddr, sizeof(FAddr), 0);
    {$ifdef SB_IPv6}
      if FSocket = INVALID_SOCKET then  // if there is no socket handle available
        UseIPv6 := WinsockIPv6Enabled and FUseIPv6  // if IPv6 enabled in OS and in UseIPv6 property
      else
        UseIPv6 := FUsingIPv6;                      // if socket handle is IPv6
      // resolve address or host name
      if not {$ifdef SB_DNSSEC}FDNS. {$endif}ResolveHostName(FRemoteAddress, UseIPv6, FAddr) then
        raise EElSocketError.Create(sInvalidAddress, SB_SOCKET_ERROR_INVALID_ADDRESS);
      // check address family
      if FAddr.ss_family = AF_INET6 then  // there is IPv6 address available
        PSockAddrIn6(@FAddr).sin6_port := htons(FRemotePort)
      else                                // there is IPv4 only address available
      if not FUsingIPv6 then  // if socket handle is already available and it's not IPv6
      begin
        PSockAddrIn(@FAddr).sin_port := htons(FRemotePort);
        UseIPv6 := False;
      end
      else  // socket handle is IPv6 but there is no IPv6 address available for the host
        raise EElSocketError.Create(sAddressFamilyMismatch, SB_SOCKET_ERROR_ADDRESS_FAMILY_MISMATCH);
     {$else}
      {$ifndef SB_UNICODE_VCL}
      addr := inet_addr(PAnsiChar(FRemoteAddress));
       {$else}
      addr := inet_addr(PAnsiChar(AnsiString(FRemoteAddress)));
       {$endif}

      {$ifdef SB_DNSSEC}
      addr := FDNS.ResolveHostName(FRemoteAddress);
       {$else}
      if addr = LongWord(INADDR_NONE) then
      begin
        {$ifndef SB_UNICODE_VCL}
        HostEnt := gethostbyname(PAnsiChar(FRemoteAddress));
         {$else}
        HostEnt := gethostbyname(PAnsiChar( AnsiString(FRemoteAddress) ));
         {$endif}
        if HostEnt <> nil then
          SBMove(HostEnt.h_addr_list^[0], addr, sizeof(addr));
      end;
       {$endif}

      if addr = LongWord(INADDR_NONE) then
        raise EElSocketError.Create(sInvalidAddress, SB_SOCKET_ERROR_INVALID_ADDRESS);
      FAddr.sin_family := AF_INET;
      FAddr.sin_addr.S_addr := addr;
      FAddr.sin_port := htons(FRemotePort);
     {$endif}

  // if socket is not yet initialized
  if  (FSocket = INVALID_SOCKET)  then
  begin
    SocketType := istStream;
    if Init({$ifdef SB_IPv6}UseIPv6 {$endif}) <> 0 then
      raise EElSocketError.Create(sNotASocket, SB_SOCKET_ERROR_NOT_A_SOCKET);
  end;

  // check if the socket should be bounded
  Result := 0;
  if (Length(FLocalBinding.LocalIntfAddress) <> 0) and (FState <> issBound) then
    Result := Bind(True, false);
  if Result <> 0 then
    Exit;

  // check the current state
  if (State <> issInitialized) and (State <> issBound) then
    raise EElSocketError.Create(Format(sWrongSocketState, [Integer(State), 'StartAsyncConnect']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);


  SetNonBlocking();

  {$ifdef SB_WINDOWS}
  {$ifdef SB_IPv6}
  Result := Winsock.connect(FSocket, PSockAddrIn(@FAddr)^, SizeOf(FAddr));
   {$else}
  result := winsock.connect(FSocket, FAddr, sizeof(FAddr));
   {$endif}
   {$else}
  {$ifdef FPC}
  result := fpconnect(FSocket, @FAddr, sizeof(FAddr));
   {$else}
  result := Posix.SysSocket.connect(FSocket, PSockAddr(@FAddr)^, SizeOf(FAddr));
   {$endif}
   {$endif LINUX}

  if Result <> 0 then
  begin
    ErrorCode := LastNetError;
    if (ErrorCode <> SB_SOCKET_ERROR_CODE_WOULDBLOCK) and (ErrorCode <> SB_SOCKET_ERROR_CODE_ISCONN) and (ErrorCode <> SB_SOCKET_ERROR_CODE_INPROGRESS) then
    begin
      FState := issInitialized;
      Result := ErrorCode;
    end
    else
    if ErrorCode = SB_SOCKET_ERROR_CODE_ISCONN then
      FState := issConnected
    else
    begin
      FState := issConnecting;
      Result := 0;
    end;
  end
  else
    FState := issConnected;

  if FState = issConnected then
    FinishAsyncConnect()
  else
  if FState <> issConnecting then
    Result :=  LastNetError ;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;
 {$else}
(*
function TElSocket.StartAsyncConnect: Integer;
begin
  // TODO:
end;
*)
 {$endif}
 {$endif}

{$ifndef SB_SILVERLIGHT_SOCKETS}
{$ifndef SB_WINRT_SOCKETS}
procedure TElSocket.FinishAsyncConnect;
var
  {$ifdef SB_IPv6}
  FAddr: TSockAddrStorage;
   {$else}
  FAddr: TSockAddrIn;
   {$endif}
  {$ifdef SB_WINDOWS}
  FAddrLen: integer;
   {$else}
  FAddrLen: cardinal;
   {$endif}
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  FState := issConnected;
  
  FAddrLen := sizeof(FAddr);
  {$ifdef SB_WINDOWS}
    {$ifdef FPC}
      fpgetsockname(FSocket, @FAddr, @FAddrLen);
     {$else}
    {$ifdef SB_IPv6}
      getsockname(FSocket, PSockAddr(@FAddr)^, FAddrLen);
     {$else}
      winsock.getsockname(FSocket, FAddr, FAddrLen);
     {$endif}
     {$endif}
   {$else}
    {$ifdef FPC}
    fpgetsockname(FSocket, @FAddr, @FAddrLen);
     {$else}
    getsockname(FSocket, PSockAddr(@FAddr)^, FAddrLen);
     {$endif}
   {$endif}
  // when getnameinfo or getsockname returns an error then FBound* receive just empty values
  {$ifdef SB_IPv6}
    AddressToString(FAddr, FBoundAddress);
    if FAddr.ss_family = AF_INET6 then
      FBoundPort := ntohs(PSockAddrIn6(@FAddr).sin6_port)
    else
      FBoundPort := ntohs(PSockAddrIn(@FAddr).sin_port);
   {$else}
    FBoundAddress := ((PAnsiChar(inet_ntoa(FAddr.sin_addr))));
    FBoundPort := ntohs(FAddr.sin_port);
   {$endif}
  DoAfterConnect;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;
 {$else}
(*
procedure TElSocket.FinishAsyncConnect;
begin
  //TODO:
end;
*)
 {$endif}
 {$endif}

{$ifndef SB_SILVERLIGHT_SOCKETS}
{$ifndef SB_WINRT_SOCKETS}
function TElSocket.AsyncConnectEx(Timeout: integer; SecondarySocket : TElSocket;
    SecSend, SecRecv : boolean; SecEvent : TElSocketSecondaryEvent): Integer;
var
  Cancel : boolean;
  Dir    : integer;
  {$ifdef SB_WINDOWS}
  Len    : integer;
   {$endif}

{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  TV: TTimeVal;
  PTV : PTimeVal;
  HighSocketHandle: Integer;
 {$endif}
  select_res: Integer;
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  FDErrSet,
  FDRecvSet,
  FDSendSet:  TFDSet ;
 {$endif}
  Elapsed  : integer;
  StartTime: TElDateTime;


begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  if (FLocalBinding.LocalIntfAddress <> '') and (FState <> issBound) then
    result := Bind(true, false)
  else
    result := 0;
  if result <> 0 then exit;

  StartAsyncConnect();


  Elapsed := 0;

  while (State = issConnecting) and
    ((Elapsed < Timeout) or (Timeout = 0)) do
  begin
    if (SecondarySocket <> nil) and (SecondarySocket.FSocket > FSocket) then
      HighSocketHandle := SecondarySocket.FSocket
    else
      HighSocketHandle := FSocket;

    {$ifdef SB_WINDOWS}FD_ZERO {$else}{$ifdef FPC}fpFD_ZERO {$else}__FD_ZERO {$endif} {$endif}(FDSendSet);
    {$ifdef SB_WINDOWS}FD_SET {$else}{$ifdef FPC}fpFD_SET {$else}__FD_SET {$endif} {$endif}(FSocket, FDSendSet);
    if SecSend then
      {$ifdef SB_WINDOWS}FD_SET {$else}{$ifdef FPC}fpFD_SET {$else}__FD_SET {$endif} {$endif}(SecondarySocket.FSocket, FDSendSet);

    {$ifdef SB_WINDOWS}FD_ZERO {$else}{$ifdef FPC}fpFD_ZERO {$else}__FD_ZERO {$endif} {$endif}(FDRecvSet);
    if SecRecv then
      {$ifdef SB_WINDOWS}FD_SET {$else}{$ifdef FPC}fpFD_SET {$else}__FD_SET {$endif} {$endif}(SecondarySocket.FSocket, FDRecvSet);

    {$ifdef SB_WINDOWS}FD_ZERO {$else}{$ifdef FPC}fpFD_ZERO {$else}__FD_ZERO {$endif} {$endif}(FDErrSet);
    {$ifdef SB_WINDOWS}FD_SET {$else}{$ifdef FPC}fpFD_SET {$else}__FD_SET {$endif} {$endif}(FSocket, FDErrSet);
    {$ifdef SB_WINDOWS}FD_SET {$else}{$ifdef FPC}fpFD_SET {$else}__FD_SET {$endif} {$endif}(SecondarySocket.FSocket, FDErrSet);

    if Timeout <> 0 then
    begin
      TV.tv_sec := (Timeout - Elapsed) div 1000;
      TV.tv_usec := ((Timeout - Elapsed) mod 1000) * 1000;
      PTV := @TV;
    end
    else
      PTV := nil;


    StartTime := Now;

    {$ifdef SB_WINDOWS}
    select_res := select(HighSocketHandle + 1, @FDRecvSet, @FDSendSet, @FDErrSet, PTV);
     {$else}
    {$ifdef FPC}
    select_res := fpselect(HighSocketHandle + 1, @FDRecvSet, @FDSendSet, @FDErrSet, PTV);
     {$else}
    select_res := Posix.SysSelect.select(HighSocketHandle + 1, @FDRecvSet, @FDSendSet, @FDErrSet, PTV);
     {$endif}
     {$endif}

    if select_res > 0 then
    begin
      Cancel := false;

      {$ifdef SB_WINDOWS_OR_NET}
      if FD_ISSET(FSocket, FDErrSet) then
       {$else}
      {$ifdef FPC}
      if fpFD_ISSET(FSocket, FDErrSet) =1 then
       {$else}
      if __FD_ISSET(FSocket, FDErrSet) then
       {$endif}
       {$endif}

      begin
        {$ifdef SB_WINDOWS}
        Len := 4;
         {$endif}
        {$ifdef SB_WINDOWS}
        getsockopt(FSocket, SOL_SOCKET, SO_ERROR, @Result, Len);
         {$else}
        result := LastNetError;
         {$endif}
        FState := issInitialized;
        Close(true);
        exit;
      end;
      if (({$ifdef SB_WINDOWS_OR_NET}FD_ISSET {$else}{$ifdef FPC}fpFD_ISSET {$else}__FD_ISSET {$endif} {$endif}(SecondarySocket.FSocket, FDRecvSet){$ifdef FPC}{$ifdef SB_POSIX} = 1 {$endif} {$endif}) or
          ({$ifdef SB_WINDOWS_OR_NET}FD_ISSET {$else}{$ifdef FPC}fpFD_ISSET {$else}__FD_ISSET {$endif} {$endif}(SecondarySocket.FSocket, FDSendSet){$ifdef FPC}{$ifdef SB_POSIX} = 1 {$endif} {$endif})) then
      begin
        Dir := 0;
        if {$ifdef SB_WINDOWS_OR_NET}FD_ISSET {$else}{$ifdef FPC}fpFD_ISSET {$else}__FD_ISSET {$endif} {$endif}(SecondarySocket.FSocket, FDRecvSet){$ifdef FPC}{$ifdef SB_POSIX} = 1 {$endif} {$endif} then
          Dir := SD_RECEIVE;
        if {$ifdef SB_WINDOWS_OR_NET}FD_ISSET {$else}{$ifdef FPC}fpFD_ISSET {$else}__FD_ISSET {$endif} {$endif}(SecondarySocket.FSocket, FDSendSet){$ifdef FPC}{$ifdef SB_POSIX} = 1 {$endif} {$endif} then
        begin
          if Dir = SD_RECEIVE then
            Dir := SD_BOTH
          else
            Dir := SD_SEND;
        end;
        Cancel := false;
        if Assigned(SecEvent) then
          SecEvent(Self, SecondarySocket, Dir, Cancel);
      end;

      if {$ifdef SB_WINDOWS_OR_NET}FD_ISSET {$else}{$ifdef FPC}fpFD_ISSET {$else}__FD_ISSET {$endif} {$endif}(FSocket, FDSendSet) {$ifdef FPC}{$ifdef SB_POSIX} = 1 {$endif} {$endif} then
      begin
        FinishAsyncConnect();
        break;
      end;

      if Cancel then
      begin
        FState := issInitialized; 
        Close(true);
        result := -1;
        exit;
      end;
    end
    else
    if select_res = SOCKET_ERROR then
    begin
      FState := issInitialized;
      result := LastNetError;
      exit;
    end;

    Elapsed := Elapsed + Trunc((Now() - StartTime) * 86400 * 1000 + 0.5);
  end;

  if State <> issConnected then
  begin
    FState := issInitialized;
    result := SB_SOCKET_ERROR_CODE_TIMEDOUT;
  end
  else
    result := 0;

  if FState = issConnected then
    DoAfterConnect();

 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;
  // Java
 {$endif}
 {$endif}

class procedure TElSocket.FinalizeWinSock;
begin
{$ifdef SB_WINDOWS}
  {$ifdef SB_IPv6}
  FinalizeIPv6();
   {$endif}
  if WinsockInitialized then
    WSACleanup();
 {$endif}
end;

{$ifndef SB_NO_SERVER_SOCKETS}
function TElSocket.GetLocalHostName: string;
var
  {$ifdef SB_IPv6}
  Addr: TSockAddrStorage;
   {$else}
  Addr: TInAddr;
  HostEnt: PHostEnt;
   {$endif}

begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  Result := '';
  if (State = issBound) or (State = issConnected) then
  begin
    {$ifdef SB_IPv6}
      if StringToAddress(BoundAddress, Addr) then
        BackResolveAddress(Addr, Result);
     {$else}
      {$ifndef SB_UNICODE_VCL}
      Addr.s_addr := Inet_Addr(PAnsiChar(BoundAddress));
       {$else}
      Addr.s_addr := Inet_Addr(PAnsiChar(AnsiString(BoundAddress)));


       {$endif}
      HostEnt := gethostbyaddr(@Addr.s_addr, 4, PF_INET);
      if HostEnt <> nil then
        Result := ((PAnsiChar(HostEnt.{$ifndef SB_DELPHI_POSIX}h_name {$else}hname {$endif})));
     {$endif}
  end;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;
 {$endif}

function TElSocket.GetRemoteAddress : string;
var
  {$ifdef SB_IPv6}
  FAddr: TSockAddrStorage;
   {$else}
  FAddr: TSockAddrIn;
   {$endif}
  {$ifdef SB_WINDOWS}
  FAddrLen : integer;
   {$else}
  FAddrLen : socklen_t;
   {$endif}
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  if FUseSocks or FUseWebTunneling then
  begin
    Result := '';
    Exit;
  end;

  FAddrLen := SizeOf(FAddr);
  {$ifdef SB_WINDOWS}
    {$ifdef SB_IPv6}
    if getpeername(FSocket, PSockAddrIn(@FAddr)^, FAddrLen) = 0 then
    begin
      if not AddressToString(FAddr, Result) then
        Result := FRemoteAddress;
    end
     {$else SB_IPv6}
    if (getpeername(FSocket, FAddr, FAddrLen) = 0) and (FAddr.sin_addr.S_addr <> integer(INADDR_NONE)) then
      Result := {$ifdef SB_UNICODE_VCL}StringOfBytes {$endif}(inet_ntoa(FAddr.sin_addr))
     {$endif SB_IPv6}
   {$else}
    if ({$ifndef SB_DELPHI_POSIX}getpeername(FSocket, @FAddr, @FAddrLen) {$else}getpeername(FSocket, PSockAddr(@FAddr)^, FAddrLen) {$endif} = 0) and (FAddr.sin_addr.S_addr <> INADDR_NONE) then
      Result := String(AnsiString(inet_ntoa(FAddr.sin_addr)))
   {$endif SB_WINDOWS}
    else
      Result := FRemoteAddress;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

// TODO: Verify connectivity in regards to string operations in VCL, .NET and Delphi Mobile
function TElSocket.HTTPConnect(Timeout: integer; var NextHeader : string): Integer;

  function ExtractAuthData(const Buf : ByteArray) : string;
  const
    Tag : string = 'Proxy-Authenticate:';
  var
    Input : string;
    P, i : integer;
  begin
    Result := '';

    Input := StringOfBytes(Buf);
    
    P := StringIndexOf(Input, Tag);

    if P >= StringStartOffset then
    begin
      Input := StringRemove(Input, StringStartOffset, P + Length(Tag) + StringStartInvOffset);
      P := StringIndexOf(Input, ' ');
      Input := StringRemove(Input, StringStartOffset, P + StringStartInvOffset);

      for i := StringStartOffset to Length(Input) - StringStartInvOffset do
      begin
        if Input[i] = #13 then
          Break;
        Result := Result + Input[i];
      end;
    end;
  end;

  function ExtractContentLength(const Buf : ByteArray) : integer;
  const
    Tag : string = 'Content-Length:';
  var
    Input, S : string;
    P, i : integer;
  begin
    S := '';

    Input := StringOfBytes(Buf);
    
    P := StringIndexOf(Input, Tag);

    if P >= StringStartOffset then
    begin
      Input := StringRemove(Input, StringStartOffset, P + Length(Tag) + StringStartInvOffset);
      P := StringIndexOf(Input, CRLFStr);
      Input := StringRemove(Input, P, Length(Input) - P + StringStartOffset);

      for i := StringStartOffset to Length(Input) - StringStartInvOffset do
      begin
        if Input[i] = #13 then
          Break;
        S := S + Input[i];
      end;
    end;

    Result := StrToIntDef(StringTrim(S), -1);
  end;

  procedure ExtractResponseHeadersAndBody(const Buf : ByteArray; Size : integer);
  var
    ABuf, TmpB : ByteArray;
    TmpS : string;
    Len, DLen, Index, StartIndex : integer;
  begin
    SetLength(ABuf, Size);
    SBMove(Buf, 0, ABuf, 0, Size);
    Len := SBPos(CRLFCRLFByteArray, ABuf, 0);
    if Len < 0 then
      Exit;

    TmpB := SBCopy(ABuf, Len + ConstLength(CRLFCRLFByteArray), Length(ABuf) - (Len + ConstLength(CRLFCRLFByteArray)));

    FWebTunnelResponseBody := StringOfBytes(TmpB);
    FWebTunnelResponseBodyLen := Length(TmpB);
    
    SetLength(ABuf, Len);
    
    DLen := ConstLength(CRLFByteArray);
    Index := SBPos(CRLFByteArray, ABuf, 0) + 1; // skip status code line
    repeat
      StartIndex := Index;
      Index := SBPos(CRLFByteArray, ABuf, Index);
      if Index = -1 then
        TmpS := StringOfBytes(SBCopy(ABuf, StartIndex, Len - StartIndex))
      else
      begin
        TmpS := StringOfBytes(SBCopy(ABuf, StartIndex, Index - StartIndex));
        inc(Index, DLen);
      end;
      FWebTunnelResponseHeaders.Add(TmpS);
    until Index = -1;

    ReleaseArray(TmpB);
  end;

  function PollRemainingData(Timeout : integer; Count : integer) : ByteArray;
  var
    Elapsed  : integer;
    StartTime : TElDateTime;
    Len, Read, ToRecv : integer;
    Recvd : TSBInteger;
    Buf : ByteArray;
    res : integer;
  begin
  {$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
    SetLength(Result, 0);
    Elapsed := 0;
    Read := 0;

    ToRecv := {$ifdef SB_CONSTRAINED_DEVICE}8192 {$else}65536 {$endif};
    SetLength(Buf, ToRecv);
    try
      while ((Elapsed < Timeout) or (Timeout = 0)) and (Read < Count) do
      begin
        StartTime := Now;

        res := Receive( @Buf[0] , ToRecv, {$ifdef SB_ASYNC_SOCKETS}Timeout - Elapsed,  {$endif} Recvd);

        if (res = 0) and (Recvd > 0) then
        begin
          Read := Read + Recvd;
          Len := Length(Result);
          SetLength(Result, Len + Recvd);
          SBMove(Buf, 0, Result, Len, Recvd);
        end;

        // TODO: Get rid of floating-point math
        Elapsed := Elapsed + Trunc((Now() - StartTime) * 86400 * 1000 + 0.5);
      end;
    finally
      ReleaseArray(Buf);
    end;
   {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
  end;

var
  len, ContentLength: integer;
  buf, buf2: ByteArray;
  rAddr: string;
  rPort: word;
  BasicCredentials: string;
  {$ifdef SB_UNICODE_VCL}
  aBasicCredentials: ByteArray;
   {$endif}
  BasicCredentialsEnc: ByteArray;
  HttpRequest: ByteArray;
  HttpRequestStr: string;
  HTTPResponse: ByteArray;
  psize, rcvcnt, cnt: integer;
  httpMajor, httpMinor, httpCode: integer;
  {$ifdef SB_HAS_HTTPAUTH}
  Header : string;
   {$endif}
  AuthData : string;
  {$ifdef SB_HAS_HTTPAUTH}
  aSeq : AUTH_SEQ;
   {$endif}
  More : boolean;
begin
//  Result := 0;

  FWebTunnelResponseHeaders.Clear;
  FWebTunnelResponseBody := '';

  rAddr := FRemoteAddress;
  rPort := FRemotePort;
  FRemoteAddress := (FWebTunnelAddress);
  FRemotePort := (FWebTunnelPort);

  More := false;
  {$ifdef SB_HAS_HTTPAUTH}
  if FWebTunnelAuthentication <> wtaBasic then
  begin
    FillChar(aSeq, sizeof(aSeq), 0);
    AuthInit( @aSeq );
    aSeq.RequestURI := Format('%s:%d', [(rAddr), (rPort)]);
    aSeq.RequestMethod := SB_HTTP_REQUEST_CONNECT;
    AuthData := '';
    More := true;
  end;
   {$endif}
  try
    len := 2048;
    Result := AsyncConnect(Timeout);
  finally
    FRemoteAddress := rAddr;
    FRemotePort := rPort;
  end;

  SetLength(buf, len);

  try
    if (FState = issConnected) then
    begin
      repeat
        if ((wtaNoAuthentication <> FWebTunnelAuthentication) and
          (FWebTunnelUserId <> '') and (FWebTunnelPassword <> '')) then
        begin
          {$ifdef SB_HAS_HTTPAUTH}
          if FWebTunnelAuthentication <> wtaBasic then
          begin
            if FWebTunnelAuthentication = wtaDigest then
            begin
              if Length(AuthData) > 0 then
              begin
                AddAuthorizationHeader(Header, cDigest, AuthData, FWebTunnelUserId, FWebTunnelPassword, More, true,  @aSeq );
                // save generated header to use it in the next HTTPConnect call
                // if proxy will close the connection
                NextHeader := Header;
              end
              else
              begin
                Header := NextHeader;
              end;
            end
            else if FWebTunnelAuthentication = wtaNTLM then
              AddAuthorizationHeader(Header, cNTLM, AuthData, FWebTunnelUserId, FWebTunnelPassword, More, true,  @aSeq );

            {$ifdef SB_IPv6}
            if IsIPv6Address((rAddr)) then
            begin
              HttpRequestStr :=
              Format('CONNECT [%s]:%d HTTP/1.1'#13#10'Host: [%0:s]:%1:d'#13#10'Proxy-Connection: keep-alive'#13#10 +
                GetRequestHeaders + '%s'#13#10#13#10,
                [rAddr, rPort, Header]);
            end
            else
             {$endif}
              HttpRequestStr :=
              Format('CONNECT %s:%d HTTP/1.1'#13#10'Host: %s:%d'#13#10'Proxy-Connection: keep-alive'#13#10 +
                GetRequestHeaders + '%s'#13#10#13#10,
                [rAddr, rPort, rAddr, rPort, Header]);
          end else
           {$endif}
          begin
            BasicCredentials := Format('%s:%s', [FWebTunnelUserId, FWebTunnelPassword]);
            len := 0;
            {$ifndef SB_UNICODE_VCL}
            Base64Encode(PChar(AnsiString(BasicCredentials)), length(BasicCredentials), nil, len, false);
             {$else}
            aBasicCredentials := BytesOfString(BasicCredentials);
            Base64Encode(@aBasicCredentials[0], Length(aBasicCredentials), nil, len, false);
             {$endif}
            SetLength(BasicCredentialsEnc, len);
            if len > 0 then
            begin
              {$ifndef SB_UNICODE_VCL}
              Base64Encode(PChar(AnsiString(BasicCredentials)), length(BasicCredentials), @BasicCredentialsEnc[0], len, false);
               {$else}
              Base64Encode(@aBasicCredentials[0], Length(aBasicCredentials), @BasicCredentialsEnc[0], len, false);
               {$endif}
              SetLength(BasicCredentialsEnc, len);
            end;
            {$ifdef SB_IPv6}
            if IsIPv6Address(rAddr) then
            begin
              HttpRequestStr :=
              Format('CONNECT [%s]:%d HTTP/1.1'#13#10'Host: [%0:s]:%1:d'#13#10 + GetRequestHeaders + 'Proxy-Authorization: Basic %s'#13#10#13#10,
                [rAddr, rPort, StringOfBytes(BasicCredentialsEnc)]);
            end
            else
             {$endif}
              HttpRequestStr :=
              Format('CONNECT %s:%d HTTP/1.1'#13#10'Host: %s:%d'#13#10 + GetRequestHeaders + 'Proxy-Authorization: Basic %s'#13#10#13#10,
                [rAddr, rPort, rAddr, rPort, StringOfBytes(BasicCredentialsEnc)]);
          end;
        end
        else
        begin
          {$ifdef SB_IPv6}
          if IsIPv6Address(rAddr) then
          begin
            HttpRequestStr :=
              Format('CONNECT [%s]:%d HTTP/1.1'#13#10'Host: [%0:s]:%1:d'#13#10'Proxy-Connection: keep-alive'#13#10 +
                GetRequestHeaders + #13#10, [rAddr, rPort]);
          end
          else
           {$endif}
            HttpRequestStr :=
            Format('CONNECT %s:%d HTTP/1.1'#13#10'Host: %s:%d'#13#10'Proxy-Connection: keep-alive'#13#10 +
              GetRequestHeaders + #13#10, [rAddr, rPort, rAddr, rPort]);
        end;
        {$ifdef SB_UNICODE_VCL}
        HttpRequest := BytesOfString(HttpRequestStr);
         {$endif}
        psize := length(HttpRequest);
        SBMove(HttpRequest[0], buf[0], psize);
        cnt := 0;
        rcvcnt := 0;

        if (not SocksSendReceive(Timeout, @buf[0], psize, cnt, @buf[0], 2048, rcvcnt, true)) then
          result := SB_SOCKET_ERROR_WEBTUNNEL_NEGOTIATION_FAILED;
        if cnt < 12 then
          result := SB_SOCKET_ERROR_WEBTUNNEL_NEGOTIATION_FAILED;
        if result = SB_SOCKET_ERROR_WEBTUNNEL_NEGOTIATION_FAILED then
          exit;

        httpMajor := StrToIntDef(StringOfBytes(Copy(buf, 0 + 5, 1)), 0);
        httpMinor := StrToIntDef(StringOfBytes(Copy(buf, 0 + 7, 1)), 0);
        httpCode := StrToIntDef(StringOfBytes(Copy(buf, 0 + 9, 3)), 0);

        if (1 = httpMajor) and ((0 = httpMinor) or (1 = httpMinor)) {and (httpCode = 200)} then
          result := 0
        else
          result := SB_SOCKET_ERROR_WEBTUNNEL_NEGOTIATION_FAILED;

        if (httpCode div 100) = 2 then //any 2xx code is acceptable as per RFC 2817
          More := false; // connection established

        ContentLength := ExtractContentLength(buf);
        if ContentLength > 0 then
        begin
          ExtractResponseHeadersAndBody(Buf, rcvcnt);

          buf2 := PollRemainingData(Timeout, ContentLength - FWebTunnelResponseBodyLen);
          if Length(buf2) > 0 then
          begin
            SetLength(buf, rcvcnt);
            buf := SBConcatArrays(buf, buf2);
            Inc(rcvcnt, Length(buf2));
          end;
        end;

        FProxyResult := httpCode;
        ExtractResponseHeadersAndBody(Buf, rcvcnt);

        if ((httpCode div 100) <> 2) and (not More) then
        begin
          Result := SB_SOCKET_ERROR_WEBTUNNEL_NEGOTIATION_FAILED;
          FBufLen := 0;
          FBufStart := 0;
        end;
          
        if result = 0 then
        begin
          AuthData := ExtractAuthData(buf);

          if (httpCode div 100) = 2 then
          begin
            SetLength(HTTPResponse, rcvcnt);

            SBMove(buf, 0, HTTPResponse, 0, rcvcnt);
            cnt := SBPos(CRLFCRLFByteArray, HTTPResponse);

            if (cnt >= 0) and (cnt < rcvcnt - 4 - 1) then
              ReturnData( @Buf[cnt + 4] , rcvcnt - (cnt + 4 - 0))
            else
            begin
              cnt := SBPos(LFLFByteArray, HTTPResponse);
              if (cnt >= 0) and (cnt < rcvcnt - 2 - 1) then
                ReturnData( @Buf[cnt + 2] , rcvcnt - (cnt + 2 - 0))
            end;
            (*
            {$ifdef SB_VCL}
            SBMove(buf[1], HTTPResponse[1], rcvcnt);
            cnt := SBPos(CRLFCRLFByteArray, HTTPResponse);
            if (cnt > 0) and (cnt < rcvcnt - 4) then
              ReturnData(@Buf[cnt + 4], rcvcnt - (cnt + 3))
            {$else}
            SBMove(buf, 0, HTTPResponse, 0, rcvcnt);
            cnt := SBPos(CRLFCRLFByteArray, HTTPResponse);
            if (cnt >= 0) and (cnt < rcvcnt - 5) then
              ReturnData(Buf, cnt + 4, rcvcnt - (cnt + 4))
            {$endif}
            else
            begin
              {$ifdef SB_VCL}
              cnt := Pos(LFLFByteArray, HTTPResponse);
              if (cnt > 0) and (cnt < rcvcnt - 2) then
                ReturnData(@Buf[cnt + 2], rcvcnt - (cnt + 1))
              {$else}
              cnt := SBPos(LFLFByteArray, HTTPResponse);
              if (cnt >= 0) and (cnt < rcvcnt - 3) then
                ReturnData(Buf, cnt + 2, rcvcnt - (cnt + 2))
              {$endif}
            end;
            *)
            end;
        end;
        // II 20060918: (???) result is assigned to 0 even in the case of error
        //result := 0;
      until More = false;
    end;
  finally
    {$ifdef SB_HAS_HTTPAUTH}
    AuthTerm( @aSeq );
     {$endif}
    if (FState = issConnected) and (result <> 0) then
      Close(true);
  end;
end;

function TElSocket.Init({$ifdef SB_IPv6}UseIPv6: Boolean {$endif}): Integer;
var b : {$ifdef FPC}integer {$else}BOOL {$endif};
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  if (FState <> issNotASocket) and (FState <> issInitialized) then
    raise EElSocketError.Create(Format(sWrongSocketState, [Integer(State), 'Init']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);

  FBufStart := 0;
  FBufLen := 0;
  if FState = issNotASocket then
  begin
    FState := issInitializing;
    //FSktType := SktType;
  {$ifdef SB_WINDOWS}
    {$ifdef SB_IPv6}
    FUsingIPv6 := False;
    if UseIPv6 then
    begin
      FSocket := Winsock.socket(AF_INET6, SocketTypes[FSktType], SocketProtocols[FSktType]);
      if FSocket <> INVALID_SOCKET then
        FUsingIPv6 := True;
    end
    else
     {$endif}
      FSocket := winsock.socket(PF_INET, SocketTypes[FSktType], IPPROTO_IP);
   {$else}
      {$ifdef FPC}
      FSocket := fpsocket(PF_INET, SocketTypes[FSktType], IPPROTO_IP);
       {$else}
      FSocket := Posix.SysSocket.socket(PF_INET, SocketTypes[FSktType], IPPROTO_IP);
       {$endif}
   {$endif}
    if FSocket = INVALID_SOCKET then
      result := LastNetError
    else
      result := 0;

    if (result = 0) and (FSktType = istStream) then
    begin
      b := {$ifndef FPC}true {$else}1 {$endif};
      result := {$ifndef FPC}setsockopt {$else}{$ifdef SB_WINDOWS}setsockopt {$else}fpsetsockopt {$endif} {$endif}(FSocket, SOL_SOCKET, SO_KEEPALIVE, {$ifndef SB_DELPHI_POSIX}@ {$endif}b, sizeof(b));
      if result = SOCKET_ERROR then
        result := LastNetError;

      {$ifdef SB_MACOS}
      b := {$ifndef FPC}true {$else}1 {$endif};
      {$ifndef FPC}setsockopt {$else}{$ifdef SB_WINDOWS}setsockopt {$else}fpsetsockopt {$endif} {$endif}(FSocket, SOL_SOCKET, SO_NOSIGPIPE, {$ifndef DELPHI_MAC}@ {$endif}b, sizeof(b));
       {$endif}
    end;
  end
  else
    result := 0;

  if CloseRequest or (result <> 0) then
  begin
    CloseRequest := false;
    FState := issNotASocket;
    if result = 0 then
    {$ifdef SB_WINDOWS}
      closesocket(FSocket);
     {$else}
      {$ifdef FPC}
      fpclose(FSocket);
       {$else}
      __close(FSocket);
       {$endif}
     {$endif}
    FSocket := INVALID_SOCKET;
    {$ifdef SB_IPv6}
    FUsingIPv6 := False;
     {$endif}
    exit;
  end;
  if result = 0 then
    FState := issInitialized;

  // disable Nagle algorithm by default
  DoSetUseNagle(false);
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

{$ifdef SB_IPv6}
class function TElSocket.LoadIPv6Proc(ProcName: string; out Proc: Pointer;
  var WinsockUsed: Integer; var Wship6Used: Integer): Boolean;
begin
  Result := False;
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  if WinsockHandle <> 0 then
  begin
    Proc := GetProcAddress(WinsockHandle, {$ifdef SB_UNICODE_WINAPI}PWideChar(WideString(ProcName)) {$else}PChar(ProcName) {$endif});
    if Proc <> nil then
    begin
      Inc(WinsockUsed);
      Result := True;
      Exit;
    end;
  end;
  if Wship6Handle <> 0 then
  begin
    Proc := GetProcAddress(Wship6Handle, {$ifdef SB_UNICODE_WINAPI}PWideChar(WideString(ProcName)) {$else}PChar(ProcName) {$endif});
    if Proc <> nil then
    begin
      Inc(Wship6Used);
      Result := True;
      Exit;
    end;
  end;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

class procedure TElSocket.InitializeIPv6;
var
  WinsockCounter, Wship6Counter: Integer;
begin
  WinsockCounter := 0;   // if the library is not used when loading funcs it'll be unloaded
  Wship6Counter := 0;    // if the library is not used when loading funcs it'll be unloaded
  WinsockHandle := LoadLibrary('ws2_32.dll');
  Wship6Handle := LoadLibrary('wship6.dll');
  WinsockIPv6Enabled := False;
  try
    if not LoadIPv6Proc('freeaddrinfo', Pointer(@FreeAddrInfoAProc), WinsockCounter, Wship6Counter) then
      Exit;
    if not LoadIPv6Proc('FreeAddrInfoW', Pointer(@FreeAddrInfoWProc), WinsockCounter, Wship6Counter) then
      Exit;
    if not LoadIPv6Proc('getaddrinfo', Pointer(@GetAddrInfoAProc), WinsockCounter, Wship6Counter) then
      Exit;
    if not LoadIPv6Proc('GetAddrInfoW', Pointer(@GetAddrInfoWProc), WinsockCounter, Wship6Counter) then
      Exit;
    if not LoadIPv6Proc('getnameinfo', Pointer(@GetNameInfoAProc), WinsockCounter, Wship6Counter) then
      Exit;
    if not LoadIPv6Proc('GetNameInfoW', Pointer(@GetNameInfoWProc), WinsockCounter, Wship6Counter) then
      Exit;
    WinsockIPv6Enabled := True;
    if (WinsockHandle <> 0) and (WinsockCounter = 0) then
    begin
      FreeLibrary(WinsockHandle);
      WinsockHandle := 0;
    end;
    if (Wship6Handle <> 0) and (Wship6Counter = 0) then
    begin
      FreeLibrary(Wship6Handle);
      Wship6Handle := 0;
    end;
  finally
    if not WinsockIPv6Enabled then
      FinalizeIPv6();
  end;
end;

class procedure TElSocket.FinalizeIPv6;
begin
  if Wship6Handle <> 0 then
  begin
    FreeLibrary(Wship6Handle);
    Wship6Handle := 0;
  end;
  if WinsockHandle <> 0 then
  begin
    FreeLibrary(WinsockHandle);
    WinsockHandle := 0;
  end;
  WinsockIPv6Enabled := False;
end;
 {$endif}

class procedure TElSocket.InitializeWinSock;
{$ifdef SB_WINDOWS}
var
  lpData: WSADATA;
  {$ifdef SB_IPv6}
  TestHandle: TSocket;
   {$endif}
 {$endif}
begin
{$ifdef SB_WINDOWS}
  if WSAStartup(MakeWord(1, 1), lpData) <> 0 then
    raise EElSocketError.Create(sWinsockInitFailed, SB_SOCKET_ERROR_WINSOCK_INIT_FAILED);
  WinsockInitialized := true;
  {$ifdef SB_IPv6}
  // check if IPv6 is supported and enabled on the system
  TestHandle := socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
  if TestHandle <> INVALID_SOCKET then
  begin
    closesocket(TestHandle);
    TestHandle := socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if TestHandle <> INVALID_SOCKET then
    begin
      closesocket(TestHandle);
      WinsockIPv6Enabled := True;
      InitializeIPv6();
    end;
  end;
   {$endif}
 {$endif}
end;

{$ifndef SB_NO_DATAGRAM_SOCKETS}
function TElSocket.ReceiveFrom( Data: pointer ; DataLen: integer; var Received:
  integer; var RemoteAddress: string; var RemotePort: word): Integer;
var
  {$ifdef SB_IPv6}
  FAddr: TSockAddrStorage;
   {$else}
  FAddr: TSockAddrIn;
   {$endif}
  {$ifdef SB_WINDOWS}
  FAddrLen: integer;
   {$else}
  FAddrLen: cardinal;
   {$endif}
  //I: Integer;
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  if (State = issConnected) then
  begin
    result := Receive(Data, DataLen, Received);
    RemoteAddress := FRemoteAddress;
    RemotePort := FRemotePort;
  end
  else
  if not (State = issBound) then
    raise EElSocketError.Create(Format(sWrongSocketState, [Integer(State), 'ReceiveFrom']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE)
  else
  begin
    FillChar(FAddr, sizeof(FAddr), Byte(0));
    {$ifdef SB_IPv6}
    if FUsingIPv6 then
      FAddr.ss_family := AF_INET6
    else
      FAddr.ss_family := AF_INET;
     {$else}
    FAddr.sin_family := AF_INET;
     {$endif}
    FAddrLen := sizeof(FAddr);
{$ifdef SB_WINDOWS}
    {$ifdef SB_IPv6}
    result := recvfrom(FSocket, PAnsiChar(Data)^, DataLen, 0, PSockAddrIn(@FAddr)^, FAddrLen);
     {$else}
    result := recvfrom(FSocket, PAnsiChar(Data)^, DataLen, 0, FAddr, FAddrLen);
     {$endif}
 {$else}
    result := {$ifndef FPC}recvfrom {$else}fprecvfrom {$endif}(FSocket, PAnsiChar(Data){$ifndef FPC}^ {$endif}, DataLen, 0, {$ifndef SB_DELPHI_POSIX}@FAddr {$else}PSockAddr(@FAddr)^ {$endif}, {$ifndef SB_DELPHI_POSIX}@ {$endif}FAddrLen);
 {$endif}
    if result = SOCKET_ERROR then
    begin
      Received := 0;
      result := LastNetError;
    end
    else
    begin
      {$ifdef SB_IPv6}
      AddressToString(FAddr, RemoteAddress);
      if FAddr.ss_family = AF_INET then
        RemotePort := ntohs(PSockAddrIn(@FAddr).sin_port)
      else
        RemotePort := ntohs(PSockAddrIn6(@FAddr).sin6_port);
       {$else}
      RemotePort := ntohs(FAddr.sin_port);
      RemoteAddress := ((PAnsiChar(inet_ntoa(FAddr.sin_addr))));
       {$endif}
      Received := result;
      result := 0;
    end;
  end;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;
 {$endif}

function TElSocket.SendTo(Data: pointer; DataLen: integer; var Sent: integer;
  const RemoteAddress: string; RemotePort: Word): Integer;
var
  {$ifdef SB_IPv6}
  FAddr: TSockAddrStorage;
  TempAddress: string;
   {$else}
  FAddr: TSockAddrIn;
  addr: LongWord;
  HostEnt: PHostEnt;
   {$endif}
//  nbs: integer;
  I: {$ifdef SB_WINDOWS}Integer {$else}socklen_t {$endif};

begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  if State = issConnected then
  begin
    Result := Send(Data, DataLen, Sent);
    Exit;
  end;
  if not (State in [issInitialized, issBound]) then
    raise EElSocketError.Create(Format(sWrongSocketState, [Integer(State), 'SendTo']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);
  if State = issNotASocket then
    SocketType := istDatagram
  else
  if SocketType <> istDatagram then
    raise EElSocketError.Create(Format(sInvalidSocketType, [Integer(SocketType), 'SendTo']), SB_SOCKET_ERROR_INVALID_SOCKET_TYPE);

  // prepare to send
  {$ifdef SB_IPv6}
    // check if it's needed to bind
    if FLocalBinding.LocalIntfAddress <> '' then
    begin
      TempAddress := FRemoteAddress;
      try
        Result := Bind(True, false);
        if Result <> 0 then
        begin
          Sent := 0;
          Result := LastNetError;
          Exit;
        end;
      finally
        FRemoteAddress := TempAddress;
      end;
    end;
    // check if the socket is initialized
    if State = issNotASocket then
    begin
      // translate destination address
      if not {$ifdef SB_DNSSEC}FDNS. {$endif}ResolveHostName(RemoteAddress, WinsockIPv6Enabled and FUseIPv6, FAddr) then
        raise EElSocketError.Create(sInvalidAddress, SB_SOCKET_ERROR_INVALID_ADDRESS);
      // check if the remote host supports IPv6
      if FAddr.ss_family = AF_INET6 then
      begin
        if Init(WinsockIPv6Enabled and FUseIPv6) <> 0 then
          raise EElSocketError.Create(sNotASocket, SB_SOCKET_ERROR_NOT_A_SOCKET);
      end
      else
      if Init(False) <> 0 then
        raise EElSocketError.Create(sNotASocket, SB_SOCKET_ERROR_NOT_A_SOCKET);
    end
    else
    begin
      // translate destination address
      if not {$ifdef SB_DNSSEC}FDNS. {$endif}ResolveHostName(RemoteAddress, FUsingIPv6, FAddr) then
        raise EElSocketError.Create(sInvalidAddress, SB_SOCKET_ERROR_INVALID_ADDRESS);
      // check if local and remote protocols are compatible
      if (FUsingIPv6 and (FAddr.ss_family = AF_INET)) or
         (not FUsingIPv6 and (FAddr.ss_family = AF_INET6)) then
        raise EElSocketError.Create(sAddressFamilyMismatch, SB_SOCKET_ERROR_ADDRESS_FAMILY_MISMATCH);
    end;
    if FAddr.ss_family = AF_INET then
      PSockAddrIn(@FAddr).sin_port := htons(RemotePort)
    else
      PSockAddrIn6(@FAddr).sin6_port := htons(RemotePort);
   {$else SB_IPv6}
    // translate destination address
    if RemoteAddress <> '255.255.255.255' then
    begin
      {$ifndef SB_UNICODE_VCL}
      addr := inet_addr(PAnsiChar(RemoteAddress));
       {$else}
      addr := inet_addr(PAnsiChar(AnsiString(RemoteAddress)));
       {$endif}

      {$ifdef SB_DNSSEC}
      addr := FDNS.ResolveHostName(RemoteAddress);
       {$else}
      if addr = LongWord(INADDR_NONE) then
      begin
        {$ifndef SB_UNICODE_VCL}
        HostEnt := gethostbyname(PAnsiChar(RemoteAddress));
         {$else}
        HostEnt := gethostbyname(PAnsiChar( AnsiString(FRemoteAddress) ));
         {$endif}
        if HostEnt <> nil then
          SBMove(HostEnt.h_addr_list^[0], addr, sizeof(addr));
      end;
       {$endif}

      if addr = LongWord(INADDR_NONE) then
        raise EElSocketError.Create(sInvalidAddress, SB_SOCKET_ERROR_INVALID_ADDRESS);
    end
    else
      addr := {$ifdef SB_WINDOWS}Cardinal(INADDR_NONE); {$else}INADDR_NONE; {$endif}

    FillChar(Faddr, sizeof(FAddr), 0);
    FAddr.sin_family := AF_INET;
    FAddr.sin_addr.S_addr := addr;
    FAddr.sin_port := htons(RemotePort);
   {$endif}

  // do send
  {$ifdef SB_WINDOWS}
    Result := Winsock.sendto(FSocket, PAnsiChar(Data)^, DataLen, 0,
      {$ifdef SB_IPv6}PSockAddrIn(@FAddr)^ {$else}FAddr {$endif}, sizeof(FAddr));
   {$else}
    Result := {$ifdef FPC}fpsendto {$else}Posix.SysSocket.sendto {$endif}(FSocket, PAnsiChar(Data){$ifndef FPC}^ {$endif}, DataLen, 0,
      {$ifdef FPC}@FAddr {$else}PSockAddr(@FAddr)^ {$endif}, sizeof(FAddr));
   {$endif}

  if Result = SOCKET_ERROR then
  begin
    Sent := 0;
    Result := LastNetError;
  end
  else
  begin
    if FState = issInitialized then
    begin
      FillChar(FAddr, SizeOf(FAddr), 0);
      {$ifdef SB_IPv6}
        if FUsingIPv6 then
          FAddr.ss_family := AF_INET6
        else
          FAddr.ss_family := AF_INET;
       {$else}
        FAddr.sin_family := AF_INET;
       {$endif}
      i := sizeof(FAddr);
      {$ifdef SB_POSIX}
      if getsockname(FSocket, {$ifdef FPC}psockaddr(@FAddr) {$else}PSockAddr(@FAddr)^ {$endif}, {$ifdef FPC}@ {$endif}i) = 0 then
       {$else}
      if getsockname(FSocket, {$ifdef SB_IPv6}PSockAddrIn(@FAddr)^ {$else}FAddr {$endif}, i) = 0 then
       {$endif}
      begin
        {$ifdef SB_IPv6}
          if FUsingIPv6 then
            FBoundPort := ntohs(PSockAddrIn6(@FAddr)^.sin6_port)
          else
            FBoundPort := ntohs(PSockAddrIn(@FAddr)^.sin_port);
          AddressToString(FAddr, FBoundAddress);
         {$else}
          FBoundPort := ntohs(FAddr.sin_port);
          FBoundAddress := ((PAnsiChar(inet_ntoa(FAddr.sin_addr))));
         {$endif}
        FState := issBound;
      end;
    end;
    Sent := Result;
    Result := 0;
  end;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;


(*function TElSocket.AddToMulticastSrv(const GroupAddress, BindAddress: string):
  Integer;
var
{$ifdef SB_VCL}
  imreq: TIPMreq;
{$else}
  BindAddr : string;
{$endif}
begin
  if State <> issBound then
  {$ifdef SB_VCL}
    raise EElSocketError.Create(Format(sWrongSocketState, [Integer(State), 'AddToMulticastSrv']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);
  {$else}
    raise EElSocketError.Create(System.String.Format(sWrongSocketState, [Integer(State), 'AddToMulticastSrv']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);
  {$endif}

  {$ifdef SB_VCL}

  {$ifndef SB_UNICODE_VCL}
  FillChar(imreq, sizeof(imreq), 0);
  {$else}
  ZeroMemory(@imreq, sizeof(imreq));
  {$endif}

  imreq.imr_multiaddr.s_addr := inet_addr(PAnsiChar(AnsiString(GroupAddress)));

  if (BindAddress = '255.255.255.255') or (BindAddress = '') then
    imreq.imr_interface.s_addr := INADDR_ANY
  else
    imreq.imr_interface.s_addr := inet_addr(PAnsiChar(AnsiString(BindAddress)));

  Result := setsockopt(FSocket, IPPROTO_IP, IP_ADD_MEMBERSHIP,
    Pointer(@imreq), sizeof(imreq));

  if result = SOCKET_ERROR then
    result := LastNetError;
  {$else}
  try
    if Length(BindAddress) = 0 then 
      BindAddr := '255.255.255.255'
    else           
      BindAddr := BindAddress;
    FSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, MulticastOption.Create(IPAddress.Parse(GroupAddress), IPAddress.Parse(BindAddr)));
    result := 0;
  except
    on E : SocketException do
    begin
      {$ifndef SB_MSSQL}
      LastNetError := E.ErrorCode;
      {$else}
      Globals.LastNetError := E.ErrorCode;
      {$endif}
      result := LastNetError;
    end;
    on E : Exception do
    begin
      {$ifndef SB_MSSQL}
      LastNetError := -1;
      {$else}
      Globals.LastNetError := -1;
      {$endif}
      result := -1;
    end;
  end;
  {$endif}
end;

function TElSocket.AddToMulticastCli(const BindAddress: string; TTL: byte; DoLoop
  : boolean): Integer;
var
{$ifdef SB_VCL}
  iaddr: in_addr;
{$else}
  LoopInt : integer;
{$endif}
begin
  if not (State in [issBound, issInitialized]) then
  {$ifdef SB_VCL}
    raise EElSocketError.Create(Format(sWrongSocketState, [Integer(State), 'AddToMulticastCli']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);
  {$else}
    raise EElSocketError.Create(System.String.Format(sWrongSocketState, [Integer(State), 'AddToMulticastCli']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);
  {$endif}

  {$ifdef SB_VCL}
  {$ifndef SB_UNICODE_VCL}
  FillChar(iaddr, sizeof(iaddr), 0);
  {$else}
  ZeroMemory(@iaddr, sizeof(iaddr));
  {$endif}


  if Length(BindAddress) = 0 then 
    iaddr.s_addr := inet_addr('255.255.255.255')
  else
    iaddr.s_addr := inet_addr(PAnsiChar(AnsiString(BindAddress)));

  result := setsockopt(FSocket, IPPROTO_IP, IP_MULTICAST_IF, @iaddr, sizeof(iaddr));

  if result = SOCKET_ERROR then
  begin
    result := LastNetError;
    exit;
  end;

  result := setsockopt(FSocket, IPPROTO_IP, IP_MULTICAST_TTL, @TTL, 1);

  if result = SOCKET_ERROR then
  begin
    result := LastNetError;
    exit;
  end;

  result := setsockopt(FSocket, IPPROTO_IP, IP_MULTICAST_LOOP, @DoLoop, 1);

  if result = SOCKET_ERROR then
  begin
    result := LastNetError;
    exit;
  end;
  {$else}
  try
    if DoLoop then
      LoopInt := 1
    else
      LoopInt := 0;

    if Length(BindAddress) = 0 then 
      FSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, IPAddress.Parse('255.255.255.255').Address)
    else 
      FSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, IPAddress.Parse(BindAddress).Address);

    FSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, TTL);
    FSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastLoopback, LoopInt);
    result := 0;
  except
    on E : SocketException do
    begin
      {$ifndef SB_MSSQL}
      LastNetError := E.ErrorCode;
      {$else}
      Globals.LastNetError := E.ErrorCode;
      {$endif}
      result := LastNetError;
    end;
    on E : Exception do
    begin
      {$ifndef SB_MSSQL}
      LastNetError := -1;
      {$else}
      Globals.LastNetError := -1;
      {$endif}
      result := -1;
    end;
  end;
  {$endif}
end;*)

procedure TElSocket.DoAfterConnect;
begin
  FblLastSentTime := GetTickCount;
  FblLastRecvTime := FblLastSentTime;

  FblLastSentSize := 0;
  FblLastRecvSize := 0;
end;

function TElSocket.InternalReceive( Data: pointer ; DataLen: integer {$ifdef SB_ASYNC_SOCKETS}; Timeout : integer {$endif}): Integer;
begin
  result := {$ifndef FPC_POSIX}recv {$else}fprecv {$endif}(FSocket,  PAnsiChar (Data){$ifndef FPC}^ {$endif}, DataLen, 0);
end;

function TElSocket.Receive( Data: pointer ; DataLen: integer; {$ifdef SB_ASYNC_SOCKETS}Timeout : integer; {$endif} var Received: integer): Integer;
var
  ToRecv: integer;
  ANow : Integer;
  {$ifdef SB_SILVERLIGHT_SOCKETS}
  WaitTime : integer;
   {$endif}
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
//  result := SOCKET_ERROR;

  if State <> issConnected then
    raise EElSocketError.Create(Format(sWrongSocketState, [Integer(State), 'Receive']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);

  {$ifdef SB_SILVERLIGHT_SOCKETS}
  if Timeout = 0 then
    WaitTime := -1
  else
    WaitTime := Timeout;
  if (FBufLen <= FBufStart) and (not SLPendingReceiveCleared(WaitTime)) then
  begin
    //Log('Receive: timeout');
    raise {$ifndef SB_NO_NET_SOCKETS}SocketException {$else}EElSocketHandlerError {$endif}.Create(SB_SOCKET_ERROR_CODE_TIMEDOUT);
  end;
   {$endif}

  if FBufLen > FBufStart then
  begin
    //Log('Receive: got something in internal buffer');
    result := 0;
    if (FBufLen - FBufStart) > DataLen then
      Received := DataLen
    else
      Received := FBufLen - FBufStart;
    SBMove(FBuffer[FBufStart], Data^, Received);
    if Received < (FBufLen - FBufStart) then
    begin
      Inc(FBufStart, Received);
    end
    else
    begin
      FBufStart := 0;
      FBufLen := 0;
    end;
    //Log('Receive: returning ' + IntToStr(Received) + ' bytes');
  end
  else
  begin
    //Log('Receive: internal buffer empty, invoking low-level receive');

    if (FIncomingSpeedLimit > 0) then
    begin
      if FBandwidthPolicy = bpStrict then
      begin
        ToRecv := 0;
        ANow := GetTickCount;

        // the loop is needed to try again after Sleep()
        while true do
        begin
          if TickDiff(FblLastRecvTime, ANow) >= 1000 then
          begin
            FblLastRecvSize := 0;
            ToRecv := Min(DataLen, FIncomingSpeedLimit);
            FblLastRecvTime := ANow;
            break;
          end
          else
          begin
            ToRecv := Min(DataLen, FIncomingSpeedLimit - FblLastRecvSize);
            if ToRecv <= 0 then
            begin
              {$ifdef SB_WINDOWS_OR_NET}
              Sleep(100);
               {$else}
              Sleep(100);
               {$endif}
              ANow := GetTickCount;
            end
            else
              break;
          end;
        end;
      end
      else
        ToRecv := DataLen;
    end
    else
      ToRecv := DataLen;

      if ToRecv > Length(FBuffer) then
      begin
        result := InternalReceive(PAnsiChar(Data), ToRecv);
        if Result <> SOCKET_ERROR then
          Inc(FblLastRecvSize, Result);
      end
      else
      begin
        if (FIncomingSpeedLimit = 0) then
          ToRecv := Length(FBuffer);
        result := InternalReceive(@FBuffer[0], ToRecv);
        if Result <> SOCKET_ERROR then
        begin
          Inc(FblLastRecvSize, Result);
          FBufLen := result;
          if FBufLen > 0 then
            Receive(Data, DataLen, {$ifdef SB_ASYNC_SOCKETS}Timeout,  {$endif}Received)
          else
            Received := 0;
          result := 0;
          exit;
        end;
      end;
    if result = SOCKET_ERROR then
    begin
      Received := 0;
      Result :=  LastNetError ;
    end
    else
    begin
      Received := result;
      result := 0;
    end;
  end;

  //Log('Receive: returning ' + IntToStr(Result));
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

procedure TElSocket.ReturnData(Data: Pointer; DataLen: Integer);
begin
  SetLength(FBuffer, DataLen + (FBufLen - FBufStart));
  SBMove(FBuffer[FBufStart], FBuffer[DataLen], FBufLen - FBufStart);
  SBMove(Data^, FBuffer[0], DataLen);
  FBufStart := 0;
  FBufLen := Length(FBuffer);
end;


(*
class procedure TElSocket.SelectSockets(var ReadSockets, WriteSockets : array of TElSocket; Timeout : integer);
var
  i : integer;
{$ifdef SB_VCL}
  TV: TTimeVal;
  HighSocketHandle: Integer;
{$else}
  //RemoteIP: IPAddress;
  //ErrorCode: integer;
{$endif}
  select_res: Integer;
  FDErrSet,
  FDRecvSet,
  FDSendSet: {$ifdef SB_VCL}TFDSet{$else}ArrayList{$endif};
  Elapsed  : integer;
  StartTime: TElDateTime;

  {$ifndef SB_VCL}
  function FD_ISSET(ASocket : Socket; ASet : ArrayList) : Boolean;
  begin
    result := ASet.Contains(ASocket);
  end;

  procedure FD_SET(ASocket : Socket; ASet : ArrayList);
  begin
    ASet.Add(ASocket);
  end;
  {$endif}

begin
  {$ifdef SB_VCL}
  HighSocketHandle := -1;

  FD_ZERO(FDErrSet);
  FD_ZERO(FDRecvSet);
  FD_ZERO(FDSendSet);

  {$else}

  FDRecvSet := ArrayList.Create;
  FDSendSet := ArrayList.Create;
  FDErrSet := ArrayList.Create;
  {$endif}

  for i := 0 to Length(ReadSockets) do
  begin
    FD_SET(ReadSockets[i].FSocket, FDRecvSet);
    FD_SET(ReadSockets[i].FSocket, FDErrSet);

    if HighSocketHandle < ReadSockets[i].FSocket then
      HighSocketHandle := ReadSockets[i].FSocket;
  end;

  for i := 0 to Length(WriteSockets) do
  begin
    FD_SET(WriteSockets[i].FSocket, FDSendSet);
    FD_SET(WriteSockets[i].FSocket, FDErrSet);

    if HighSocketHandle < WriteSockets[i].FSocket then
      HighSocketHandle := WriteSockets[i].FSocket;
  end;

  TV.tv_sec := 0;
  TV.tv_usec := Timeout * 1000;

  {$ifdef SB_VCL}
  select_res := {$ifdef SB_WINDOWS}select{$else}fpselect{$endif}(HighSocketHandle + 1, @FDRecvSet, @FDSendSet, @FDErrSet, @TV);
  {$else}
  select_res := -1;
  try
    System.Net.Sockets.Socket.Select(FDRecvSet, FDSendSet, FDErrSet, Timeout - Elapsed);
    select_res := FDRecvSet.Count + FDSendSet.Count + FDErrSet.Count;
  except
    on E : SocketException do
    begin
      LastNetError := E.ErrorCode;
      select_res := SOCKET_ERROR;
    end;
    on E : Exception do
      select_res := SOCKET_ERROR;
  end;
  {$endif}

  if select_res > 0 then
  begin

  end;

end;

*)

function TElSocket.Send(Data: pointer; DataLen: integer; var Sent: integer): Integer;
var
  ANow : integer;
  ToSend : integer;
begin
  if State <> issConnected then
    raise EElSocketError.Create(Format(sWrongSocketState, [Integer(State), 'Send']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);


  if (FOutgoingSpeedLimit > 0) then
  begin
    if FBandwidthPolicy = bpStrict then
    begin
      ToSend := 0;
      ANow := GetTickCount;

      // the loop is needed to try again after Sleep()
      while true do
      begin
        if TickDiff(FblLastSentTime, ANow) >= 1000 then
        begin
          FblLastSentSize := 0;
          ToSend := Min(DataLen, FOutgoingSpeedLimit);
          FblLastSentTime := ANow;
          break;
        end
        else
        begin
          ToSend := Min(DataLen, FOutgoingSpeedLimit - FblLastSentSize);
          if ToSend <= 0 then
          begin
            {$ifdef SB_WINDOWS_OR_NET}
            Sleep(100);
             {$else}
            Sleep(100);
             {$endif}
            ANow := GetTickCount;
          end
          else
            break;
        end;
      end;
    end
    else
      ToSend := DataLen;
  end
  else
    ToSend := DataLen;

{$ifdef SB_WINDOWS}
  result := Winsock.Send(FSocket, PAnsiChar(Data)^, ToSend, 0);
 {$else}
  result := {$ifdef FPC}fpsend {$else}Posix.SysSocket.send {$endif}(FSocket, PAnsiChar(Data){$ifndef FPC}^ {$endif}, ToSend, {$ifdef SB_HAS_MSGNOSIGNAL}MSG_NOSIGNAL {$else}0 {$endif});
 {$endif LINUX}
  if result = SOCKET_ERROR then
  begin
    Sent := 0;
    Result :=  LastNetError ;
  end
  else
  begin
    Sent := result;
    Inc(FblLastSentSize, Sent);
    result := 0;
  end;
end;

procedure TElSocket.SetAddress(const Value: string);
begin
  if not (FState in [issNotASocket, issInitialized, issBound]) then
    raise EElSocketError.Create(Format(sWrongSocketState, [Integer(State), 'SetAddress']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);

  FRemoteAddress := SBPunycode.ToASCII(StringTrim(Value));
end;

function TElSocket.GetAddress: string;
begin
  Result := SBPunycode.ToUnicode(FRemoteAddress);
end;

procedure TElSocket.SetWebTunnelRequestHeaders(Value : TElStringList);
begin
  FWebTunnelRequestHeaders.Assign(Value);
end;

procedure TElSocket.SetWebTunnelAddress(const Value: string);
begin
  FWebTunnelAddress := SBPunycode.ToASCII(Value);
end;

function TElSocket.GetWebTunnelAddress : string;
begin
  Result := SBPunycode.ToUnicode(FWebTunnelAddress);
end;

procedure TElSocket.SetPort(Value: Integer);
begin
  if not (FState in [issNotASocket, issInitialized, issBound]) then
    raise EElSocketError.Create(Format(sWrongSocketState, [Integer(State), 'SetPort']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);

  FRemotePort := Value;
end;

procedure TElSocket.SetSocketType(const Value: TElSocketType);
begin
  if FSktType <> Value then
  begin
    if FState <> issNotASocket then
      raise EElSocketError.Create(Format(sWrongSocketState, [Integer(State), 'SetSocketType']), SB_SOCKET_ERROR_WRONG_SOCKET_STATE);
    FSktType := Value;
  end;
end;

procedure TElSocket.SetUseSocks(const Value: Boolean);
begin
  FUseSocks := Value;
  if Value then
    UseWebTunneling := false;
end;

procedure TElSocket.SetUseWebTunneling(const Value: boolean);
begin
  FUseWebTunneling := Value;
  if Value then
    UseSocks := false;
end;


function TElSocket.SocksConnect(Timeout: integer): Integer;
var
  rAddr: ByteArray;
  srAddr: string;
  rPort: Word;
  buf: ByteArray;
    {$ifdef SB_IPv6}
    rIP: TSockAddrStorage;
     {$else}
    rIP: in_addr;
     {$endif}
  TmpBuf : ByteArray;

  {$ifndef SB_IPv6}
  HostEnt: PHostent;
   {$endif}
  cnt, len, psize, SelectRes: integer;
  realDataLen: integer;

(*
const
  AuthList: array [0..3] of byte = (5, // Socks version
                                    2, // NMETHODS
                                    0, // NO AUTHENTICATION REQUIRED
                                    2);// USERNAME/PASSWORD
*)
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}


//  Result := -1;
  rAddr := BytesOfString(FRemoteAddress);
  srAddr := FRemoteAddress;

  rPort := FRemotePort;
  FRemoteAddress := FSocksServer;
  FRemotePort := FSocksPort;
  try
    { // AI: removed since the same operations are done in AsyncConnect
    if (Length(FLocalBinding.LocalIntfAddress) > 0) and (FState <> issBound) then
      result := Bind(true)
    else
      result := 0;
    if result <> 0 then exit;}

    Result := AsyncConnect(Timeout);
  finally
    FRemoteAddress := StringOfBytes(rAddr);
    FRemotePort := rPort;
  end;

  if State = issConnected then
  begin
    Result := SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED;
    len := 1024;
    SetLength(buf, len);
    try
      if FSocksVersion = elSocks5 then
      begin
        psize := 4;
        case FSocksAuthentication of
          saUsercode:
            begin
              PCardinal(@buf[0])^ := $02000205;
            end;
          saNoAuthentication:
            begin
              PCardinal(@buf[0])^ := $00000105;
              psize := 3;
            end;
        end;
        if not SocksSendReceive(Timeout, @buf[0], psize, cnt, @buf[0], 1024, cnt) then
          exit;
        if (Byte(buf[0]) = 05) and (Byte(buf[0 + 1]) = $FF) then
          exit;
        if (Byte(buf[0]) = 05) and (Byte(buf[0 + 1]) = 02) then
        begin
          cnt := Length(FSocksUserCode);
          buf[0] := byte(1);
          buf[0 + 1] := byte(cnt);
          if cnt > 0 then
            SBMove({$ifndef SB_UNICODE_VCL}FSocksUserCode[StringStartOffset] {$else}BytesOfString(FSocksUserCode)[0] {$endif}, buf[0 + 2], cnt);
          psize := Length(FSocksPassword);
          buf[0 + cnt + 2] := byte(psize);
          if psize > 0 then
            SBMove({$ifndef SB_UNICODE_VCL}FSocksPassword[StringStartOffset] {$else}BytesOfString(FSocksPassword)[0] {$endif}, buf[0 + cnt + 3], psize);
          psize := psize + cnt + 3;
          if not SocksSendReceive(Timeout, @buf[0], psize, cnt, @buf[0], 1024, cnt) then
            exit;
          if buf[0 + 1] <> byte(0) then
            exit;
        end;
        psize := 8;
        {$ifdef SB_IPv6}
        if not StringToAddress(srAddr, rIP) then
         {$else}

        rIP.S_addr := inet_addr(PAnsiChar(rAddr));
        if u_long(rIP.S_addr) = u_long(INADDR_NONE) then
         {$endif SB_IPv6}
        begin
          {$ifndef SB_SILVERLIGHT_SOCKETS}
          if FSocksResolveAddress then
           {$endif}
          begin
            psize := length(rAddr);
            SBMove(rAddr, 0, buf, 0 + 5, psize);
            buf[0 + 4] := byte(psize);
            buf[0 + 2] := byte(0);
            buf[0 + 3] := byte(3);
            psize := 5 + psize;
          {$ifndef SB_SILVERLIGHT_SOCKETS}
          end
          else
          begin
            {$ifdef SB_IPv6}
            if {$ifdef SB_DNSSEC}FDNS. {$endif}ResolveHostName(srAddr, FSocksUseIPv6, rIP) then
            begin
              if rIP.ss_family = AF_INET6 then
              begin
                SBMove(PSockAddrIn6(@rIP).sin6_addr.Bytes[0], Buf[0 + 4],
                  SizeOf(PSockAddrIn6(@rIP).sin6_addr.Bytes));
                Inc(psize, 12);
              end
              else
                SBMove(PSockAddrIn(@rIP).sin_addr.S_addr, Buf[0 + 4],
                  SizeOf(PSockAddrIn(@rIP).sin_addr.S_addr));
            end
            else
              Exit;
             {$else}
            {$ifdef SB_DNSSEC}
            rIP.S_addr := FDNS.ResolveHostName(rAddr);
            if rIP.S_addr = INADDR_NONE then
              Exit;
             {$else}
            HostEnt := gethostbyname(PAnsiChar( rAddr ));
            if HostEnt <> nil then
              SBMove(HostEnt.h_addr_list^[0], buf[0 + 4], sizeof(rIP.S_addr))
            else
              exit;
             {$endif}
             {$endif}
            buf[0 + 2] := byte(0);
            {$ifdef SB_IPv6}
            if  rIP.ss_family = AF_INET6  then
              Buf[0 + 3] := byte(4)
            else
             {$endif}
              buf[0 + 3] := byte(1);
            // 01 - IP V4 address, 04 - IP V6 address
           {$endif}
          end;
        end // if
        else {rIP = ''}
        begin
          {$ifdef SB_IPv6}
          if rIP.ss_family = AF_INET6 then
          begin
            SBMove(PSockAddrIn6(@rIP).sin6_addr.Bytes[0], Buf[0 + 4],
              SizeOf(PSockAddrIn6(@rIP).sin6_addr.Bytes));
            Inc(psize, 12);
          end
          else
            SBMove(PSockAddrIn(@rIP).sin_addr.S_addr, Buf[0 + 4],
              SizeOf(PSockAddrIn(@rIP).sin_addr.S_addr));
           {$else}
          SBMove(rIP.S_addr, buf[0 + 4], sizeof(rIP.S_addr));
           {$endif}
          buf[0 + 2] := byte(0);
          {$ifdef SB_IPv6}
          {$ifndef SB_NO_NET_SOCKETS}
          if  rIP.ss_family = AF_INET6  then
           {$else}
          if AddressFamily = TSBSocketAddressFamily.afInterNetworkV6 then
           {$endif}
            Buf[0 + 3] := byte(4)
          else
           {$endif}
            buf[0 + 3] := byte(1);
            // 01 - IP V4 address, 04 - IP V6 address
        end;
        buf[0 + 0] := byte(5);
        buf[0 + 1] := byte(1);
        //PWord(@buf[0 + psize])^ := htons(rPrt);
        buf[0 + psize] := byte((rPort shr 8) and $FF);
        buf[0 + psize + 1] := byte(rPort and $FF);
        psize := psize + 2;
        if not SocksSendReceive(Timeout, @buf[0], psize, cnt, @buf[0], 1024, cnt) then
          exit;
        SelectRes := 0;
        Result := Byte(buf[0 + 1]);
        if SelectRes <> 0 then
        begin
          result := SelectRes;
          exit;
        end;
        if Result = -1 then
          exit;
        case Byte(buf[0 + 3]) of
          1: realDataLen := 4 + 4 + 2;
          3: realDataLen := 4 + (1 + Byte(buf[0 + 4])) + 2;
          4: realDataLen := 4 + 16 + 2;
        else
          realDataLen := -1;
        end;
        if (realDataLen = -1) then
          exit;
        if (realDataLen < cnt) then
          returnData(@buf[realDataLen + 1], cnt - realDataLen);
      end
      else
      begin
        buf[0] := byte(04);
        buf[0 + 1] := byte(01);
        buf[0 + 2] := byte((rPort shr 8) and $FF);
        buf[0 + 3] := byte(rPort and $FF);
        cnt := Length(FSocksUserCode);
        if cnt > 0 then
          TmpBuf := BytesOfString(FSocksUserCode);
          SBMove(TmpBuf[0], buf[0 + 8], cnt);
        psize := cnt + 8 + 1;
        buf[0 + psize - 1] := byte(0);
        {$ifdef SB_IPv6}  // AI: Socks 4 and 4a do not support IPv6 addressing
        {$ifndef SB_UNICODE_VCL}
        PSockAddrIn(@rIP).sin_addr.S_addr := inet_addr(PAnsiChar(rAddr));
         {$else}
        PSockAddrIn(@rIP).sin_addr.S_addr := inet_addr(PAnsiChar(AnsiString(rAddr)));
         {$endif}
        if PSockAddrIn(@rIP).sin_addr.S_addr = u_long(INADDR_NONE) then
         {$else}

        rIP.S_addr := inet_addr(PAnsiChar(rAddr));
        if u_long(rIP.S_addr) = u_long(INADDR_NONE) then
         {$endif}
        begin
          {$ifndef SB_SILVERLIGHT_SOCKETS}
          if FSocksResolveAddress then
           {$endif}
          begin
            cnt := length(rAddr);
            PCardinal(@buf[0 + 4])^ := $FF000000;
            SBMove(rAddr[0], PByte(@buf[0 + psize])^, cnt);
            psize := psize + cnt + 1;
            buf[0 + psize - 1] := byte(0);
          {$ifndef SB_SILVERLIGHT_SOCKETS}
          end
          else
          begin
            {$ifdef SB_IPv6}
            if not {$ifdef SB_DNSSEC}FDNS. {$endif}ResolveHostName(srAddr, False, rIP) then
              Exit;
            SBMove(PSockAddrIn(@rIP).sin_addr.S_addr, PByte(@buf[0 + 4])^,
              SizeOf(PSockAddrIn(@rIP).sin_addr.S_addr))
             {$else}
            {$ifdef SB_DNSSEC}
            rIP.S_addr = FDNS.ResolveHostName(rAddr);
            if rIP.S_addr = INADDR_NONE then
              Exit;
             {$else}
            HostEnt := gethostbyname(PAnsiChar( rAddr ));
            if HostEnt <> nil then
              SBMove(HostEnt.h_addr_list^[0], PByte(@buf[0 + 4])^,
                sizeof(rIP.S_addr))
            else
              exit;
             {$endif}
             {$endif}
           {$endif}
          end;
        end
        else
          {$ifdef SB_IPv6}
          SBMove(PSockAddrIn(@rIP).sin_addr.S_addr, buf[0 + 4], sizeof(PSockAddrIn(@rIP).sin_addr.S_addr));
           {$else}
          SBMove(rIP.S_addr, buf[0 + 4], sizeof(rIP.S_addr));
           {$endif}
        if not SocksSendReceive(Timeout, @buf[0], psize, cnt, @buf[0], 1024, cnt) then
          exit;
        if buf[0 + 1] = byte(90) then
          Result := 0 // request granted
        else
          exit;
        if result = 0 then
        begin
          if cnt > 8 then
          begin
            returnData(@buf[0 + 8], cnt - 8);
          end;
        end;
      end;
    finally
      if (Result <> 0) and (State = issConnected) then
        Close(false);
    end;
  end;

 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

{$ifndef SB_SILVERLIGHT_SOCKETS}
function TElSocket.SocksSendReceive(Timeout: Cardinal; sendBuf: pointer;
  sendBufSize: integer; var wasSent: integer; readBuf: pointer; readBufSize:
  integer; var wasRead: integer; NeedDoubleCRLF : boolean = false): boolean;
var
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  FDSendSet, FDRecvSet: TFDSet;
  PTV: PTimeVal;
  TimeVal: TTimeVal;
 {$endif}
  TimeoutV, SelectRes: Integer;
  Elapsed,
    StartTime: Cardinal;
  ptr :  ^byte ;
  wasReadPart : integer;
  I : integer;
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  StartTime := GetTickCount();
  while (true) do
  begin
    Elapsed := TickDiff(StartTime, GetTickCount);
    if (Timeout > 0) and
      ((Elapsed) >= Timeout) then
    begin
      result := false;
      exit;
    end;
    {$ifdef SB_WINDOWS}FD_ZERO {$else}{$ifdef FPC}fpFD_ZERO {$else}__FD_ZERO {$endif} {$endif}(FDRecvSet);
    {$ifdef SB_WINDOWS}FD_ZERO {$else}{$ifdef FPC}fpFD_ZERO {$else}__FD_ZERO {$endif} {$endif}(FDSendSet);
    if Timeout > 0 then
      TimeoutV := Timeout - Elapsed
    else
      TimeoutV := 0;
    if TimeoutV > 0 then
    begin
      TimeVal.tv_sec := TimeoutV div 1000;
      TimeVal.tv_usec := (TimeoutV mod 1000) * 1000;
      PTV := @TimeVal;
    end
    else
      PTV := nil;
    {$ifdef SB_WINDOWS}FD_ZERO {$else}{$ifdef FPC}fpFD_ZERO {$else}__FD_ZERO {$endif} {$endif}(FDSendSet);
    {$ifdef SB_WINDOWS}FD_SET {$else}{$ifdef FPC}fpFD_SET {$else}__FD_SET {$endif} {$endif}(FSocket, FDSendSet);
    SelectRes := {$ifdef SB_WINDOWS}select {$else}{$ifdef FPC}fpselect {$else}Posix.SysSelect.select {$endif} {$endif}(FSocket + 1, nil, @FDSendSet, nil, PTV);
    if (0 <> SelectRes) and (SOCKET_ERROR <> SelectRes) then
    begin
      if {$ifdef SB_WINDOWS}FD_ISSET {$else}{$ifdef FPC}fpFD_ISSET {$else}__FD_ISSET {$endif} {$endif}(FSocket, FDSendSet) {$ifdef FPC}{$ifdef SB_POSIX} = 1 {$endif} {$endif} then
      begin
        if SOCKET_ERROR = Send(sendBuf, sendBufSize, {$ifdef SB_ASYNC_SOCKETS}TimeoutV,  {$endif}wasSent) then
        begin
          result := false;
          exit;
        end
        else
          break;
      end;
    end
    else
      if SelectRes = SOCKET_ERROR then
    begin
      result := false;
      exit;
    end;
  end;
  ptr :=  readBuf ;
  {$ifndef SB_UNICODE_VCL}
  FillChar(readBuf^, readBufSize, 0);
   {$else}
  {$ifndef SB_DELPHI_POSIX}
  ZeroMemory(readBuf, readBufSize);
   {$else}
  FillChar(readBuf^, readBufSize, 0);
   {$endif}
   {$endif}
  wasRead := 0;
  while (true) do
  begin
    Elapsed := cardinal(GetTickCount) - StartTime;
    if (Timeout > 0) and
      ((Elapsed) >= Timeout) then
    begin
      result := false;
      exit;
    end;
    {$ifdef SB_WINDOWS}FD_ZERO {$else}{$ifdef FPC}fpFD_ZERO {$else}__FD_ZERO {$endif} {$endif}(FDRecvSet);
    if Timeout > 0 then
      TimeoutV := Timeout - Elapsed
    else
      TimeoutV := 0;
    if TimeoutV > 0 then
    begin
      TimeVal.tv_sec := TimeoutV div 1000;
      TimeVal.tv_usec := (TimeoutV mod 1000) * 1000;
      PTV := @TimeVal;
    end
    else
      PTV := nil;
    {$ifdef SB_WINDOWS}FD_SET {$else}{$ifdef FPC}fpFD_SET {$else}__FD_SET {$endif} {$endif}(FSocket, FDRecvSet);
    SelectRes := {$ifdef SB_WINDOWS}select {$else}{$ifdef FPC}fpselect {$else}select {$endif} {$endif}(FSocket + 1, @FDRecvSet, nil, nil, PTV);

    if (0 <> SelectRes) and (SOCKET_ERROR <> SelectRes) then
    begin
      if {$ifdef SB_WINDOWS}FD_ISSET {$else}{$ifdef FPC}fpFD_ISSET {$else}__FD_ISSET {$endif} {$endif}(FSocket, FDRecvSet){$ifdef FPC}{$ifdef SB_POSIX} = 1 {$endif} {$endif} then
      begin
        if SOCKET_ERROR = Receive(ptr, readBufSize, wasReadPart) then
        begin
          result := false;
          exit
        end
        else
        begin
          Inc(ptr, wasReadPart);
          Inc(wasRead, wasReadPart);
          Dec(readBufSize, wasReadPart);
          if NeedDoubleCRLF then
          begin
            for I := 0 to wasRead - 4 do
              if CompareMem(@PByteArray(readBuf)[I], @CRLFCRLFByteArray[0], ConstLength(CRLFCRLFByteArray)) then
              begin
                Result := true;
                Exit;
              end;
            for I := 0 to wasRead - 2 do
              if CompareMem(@PByteArray(readBuf)[I], @LFLFByteArray[0], ConstLength(LFLFByteArray)) then
              begin
                Result := true;
                Exit;
              end;
          end
          else
          begin
            Result := true;
            exit;
          end;
        end;
      end;
    end
    else
    if SelectRes = SOCKET_ERROR then
    begin
      result := false;
      exit;
    end;
  end;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;
 {$else}
function TElSocket.SocksSendReceive(Timeout: integer; var sendBuf: ByteArray; sendBufSize:
  integer; out wasSent: integer; var readBuf: ByteArray; readBufSize: integer; out
  wasRead: integer; NeedDoubleCRLF : boolean  =  false): boolean;
var
  TimeoutV, SelectRes: Integer;
  Elapsed,
    StartTime: Cardinal;
  ptr : integer;
  wasReadPart : integer;
  I : integer;
  buf : ByteArray;
begin
  StartTime := GetTickCount();
  

  
  // Send the request
  while (true) do
  begin
    Elapsed := TickDiff(StartTime, GetTickCount);
    if (Timeout > 0) and
      (Integer(Elapsed) >= Timeout) then
    begin
      result := false;
      exit;
    end;
    if Timeout = 0 then
      TimeoutV := 0
    else
      TimeoutV := (Timeout - Integer(Elapsed)) * 1000;

    if SOCKET_ERROR = Send(sendBuf, 0, sendBufSize, TimeoutV, wasSent) then
    begin
      result := false;
      exit;
    end
    else
      break;
  end;
  
  // now read the response
  ptr := 0;
  FillChar(readBuf, readBufSize, 0);
  wasRead := 0;
  while (true) do
  begin
    Elapsed := cardinal(GetTickCount) - StartTime;
    if (Timeout > 0) and
      (Integer(Elapsed) >= Timeout) then
    begin
      result := false;
      exit;
    end;
    if Timeout = 0 then
      TimeoutV := 0
    else
      TimeoutV := (Timeout - Elapsed) * 1000;
    SelectRes := -1;
    SetLength(buf, readBufSize);
    if SOCKET_ERROR = Receive(buf, readBufSize, TimeoutV, wasReadPart) then
    begin
      result := false;
      exit
    end
    else
    begin
      SBMove(buf, 0, readBuf, ptr, wasReadPart);
      Inc(ptr, wasReadPart);
      Inc(wasRead, wasReadPart);
      Dec(readBufSize, wasReadPart);
      if NeedDoubleCRLF then
      begin
        for I := 0 to wasRead - 4 do
          if CompareMem(readBuf, I, CRLFCRLFByteArray, 0, ConstLength(CRLFCRLFByteArray)) then
          begin
            Result := true;
            Exit;
          end;
        for I := 0 to wasRead - 2 do
          if CompareMem(readBuf, I, LFLFByteArray, 0, ConstLength(LFLFByteArray)) then
          begin
            Result := true;
            Exit;
          end;
      end
      else
      begin
        Result := true;
        exit;
      end;
    end;
  end;

end;
 {$endif}

{$ifdef SB_SILVERLIGHT_SOCKETS}
function TElSocket.SLPendingReceiveCleared(var WaitTime : integer) : boolean;
var WaitRes    : Boolean;
    WaitMoment : integer;
{$ifdef SB_SILVERLIGHT_SOCKETS}
    err : integer;
 {$endif}

begin
  //Log('SLPendingReceiveCleared');
  if FRecvInProgress then
  begin
    WaitMoment := GetTickCount;
    if WaitTime = -1 then
      WaitRes := FRecvDoneFlag.WaitOne()
    else
      WaitRes := FRecvDoneFlag.WaitOne(WaitTime);
    // II20120124: commented out the line below
    //FRecvDoneFlag.Reset();
    if WaitRes then
    begin
      // II20120124: added two lines below
      FRecvInProgress := false;
      FRecvDoneFlag.Reset();
      if FLastSocketError <> 0 then
      begin
        //Log('SLPendingReceiveCleared: last socket error is ' + IntToStr(FLastSocketError));
        err := FLastSocketError;
        FLastSocketError := 0;
        raise {$ifndef SB_NO_NET_SOCKETS}SocketException {$else}EElSocketHandlerError {$endif}.Create(err);
      end;

      WaitTime := WaitTime - TickDiff(GetTickCount, WaitMoment);
      if WaitTime < 0 then 
        WaitTime := 0;
      result := true;
      if FSocketRecvArgs.Buffer = FBuffer then
      begin
        FBufLen := FSocketRecvArgs.BytesTransferred;
        //Log('SLPendingReceiveCleared: setting FBufLen to ' + IntToStr(FBufLen));
      end;
    end
    else
      result := false;
  end
  else
    result := true;
  (*if result then
    Log('SLPendingReceiveCleared returns true')
  else
    Log('SLPendingReceiveCleared returns false')*)
end;

function TElSocket.SLSend(Data : ByteArray; Start : Integer; ToSend : Integer; Timeout : integer) : Integer;
var IsAsync : boolean;
    WaitRes : Boolean;
{$ifdef SB_SILVERLIGHT_SOCKETS}
    err : integer;
 {$endif}
begin
  //Log('Sending ' + IntToStr(ToSend) + ' bytes, timeout is ' + IntToStr(Timeout));

  FSocketSendArgs.SetBuffer(Data, Start, ToSend);

  FSendInProgress := true;
  IsAsync := FSocket.SendAsync(FSocketSendArgs);
  if IsAsync then
  begin
    //Log('Data were sent asynchronously, waiting for them to be committed');
    // now wait for certain time until the data is sent
    if Timeout = 0 then
      WaitRes := FSendDoneFlag.WaitOne()
    else
      WaitRes := FSendDoneFlag.WaitOne(Timeout);
    FSendDoneFlag.Reset();
    if WaitRes = false then
    begin
      //Log('Timeout exceeded, no bytes sent');
      raise {$ifndef SB_NO_NET_SOCKETS}SocketException {$else}EElSocketHandlerError {$endif}.Create(SB_SOCKET_ERROR_CODE_TIMEDOUT);
    end
    else
    if FLastSocketError <> 0 then
    begin
      //Log('Socket error ' + IntToStr(FLastSocketError));
      err := FLastSocketError;
      FLastSocketError := 0;
      raise {$ifndef SB_NO_NET_SOCKETS}SocketException {$else}EElSocketHandlerError {$endif}.Create(err);
    end;

    result := FSocketSendArgs.BytesTransferred;
    //Log('Done, result is ' + IntToStr(result));
  end
  else
  begin
    //Log('Data sent synchronously');
    FSendInProgress := false;
    if (FSocketSendArgs.SocketError = {$ifndef SB_NO_NET_SOCKETS}SocketError.Success {$else}0 {$endif}) then
      result := FSocketSendArgs.BytesTransferred
    else
      raise {$ifndef SB_NO_NET_SOCKETS}SocketException {$else}EElSocketHandlerError {$endif}.Create(Integer(FSocketSendArgs.SocketError));
  end;
end;

function TElSocket.SLReceive(Data : ByteArray; {Start : Integer; }ToReceive : Integer; Timeout : integer) : Integer;
var IsAsync : boolean;
    WaitRes : Boolean;
{$ifdef SB_SILVERLIGHT_SOCKETS}
    err : integer;
 {$endif}
begin
  //if not SLPendingReceiveCleared(Timeout) then
  //  raise SocketException.Create(WSAETIMEDOUT);

  //Log('Trying to read ' + IntToStr(ToReceive) + ' bytes, timeout is ' + IntToStr(Timeout));

  FSocketRecvArgs.SetBuffer(Data, 0, ToReceive);

  FRecvInProgress := true;
  // II20120124: added the line below
  FRecvDoneFlag.Reset;
  IsAsync := FSocket.ReceiveAsync(FSocketRecvArgs);
  if IsAsync then
  begin
    //Log('Method invoked asynchronously, waiting for it to terminate');
    // now wait for certain time until connection is established
    if Timeout = 0 then
      WaitRes := FRecvDoneFlag.WaitOne()
    else
      WaitRes := FRecvDoneFlag.WaitOne(Timeout);
    if WaitRes = false then
    begin
      //Log('Timeout exceeded, nothing received');
      raise {$ifndef SB_NO_NET_SOCKETS}SocketException {$else}EElSocketHandlerError {$endif}.Create(SB_SOCKET_ERROR_CODE_TIMEDOUT);
    end
    else
    begin
      //Log('Got something');
      // II20120124: added two lines below
      FRecvInProgress := false;
      FRecvDoneFlag.Reset();
      if FLastSocketError <> 0 then
      begin
        //Log('Socket error ' + IntToStr(FLastSocketError));
        err := FLastSocketError;
        FLastSocketError := 0;
        raise {$ifndef SB_NO_NET_SOCKETS}SocketException {$else}EElSocketHandlerError {$endif}.Create(err);
      end;
    end;

    result := FSocketRecvArgs.BytesTransferred;

    //Log('Done, received ' + IntToStr(result) + ' bytes');
  end
  else
  begin
    //Log('Method invoked synchronously');
    FRecvInProgress := false;
    if (FSocketRecvArgs.SocketError = {$ifndef SB_NO_NET_SOCKETS}SocketError.Success {$else}0 {$endif}) then
      result := FSocketRecvArgs.BytesTransferred
    else
      raise {$ifndef SB_NO_NET_SOCKETS}SocketException {$else}EElSocketHandlerError {$endif}.Create(Integer(FSocketRecvArgs.SocketError));
    //Log('Done, received ' + IntToStr(result) + ' bytes');
  end;
end;
 {$endif}

{$ifdef SB_WINRT_SOCKETS}
procedure TElSocket.RTStartReceiveLoop;
begin
  if (FSocket = nil) or (FSocket.InputStream = nil) then
    raise EElSocketError.Create(sSocketNotConnected);

  if ActivateReadLoop then
  begin
    FLoadOp := FSocket.InputStream.ReadAsync({WindowsRuntimeBuffer.&Create(DEF_BUFFER_SIZE)}FReadBuffer, DEF_BUFFER_SIZE, InputStreamOptions.Partial);
    FLoadOp.Completed := new AsyncOperationWithProgressCompletedHandler<IBuffer, uint>(new AsyncOperationWithProgressCompletedHandler<IBuffer, uint>(HandleRecvCompleted));
  end
  else
    FLoadOp := nil;
end;

procedure TElSocket.RTStopReceiveLoop;
begin
  //if Assigned(FOnLog) then FOnLog(Self, 'Socket::RTStopReceiveLoop');
  if FLoadOp = nil then
    Exit;
  try
    try
      //if Assigned(FOnLog) then FOnLog(Self, 'Socket::RTStopReceiveLoop: calling Cancel');
      FLoadOp.Cancel;
    finally
      FLoadOp := nil;
    end;
  except
    ;
  end;
end;

procedure TElSocket.RaiseLastWinRTSocketError;
var
  E : Exception;
begin
  //if Assigned(FOnLog) then FOnLog(Self, 'Socket::RaiseLastWinRTSocketError');
  E := FLastWinRTSocketError;
  FLastWinRTSocketError := nil;
  raise E;
end;            

procedure TElSocket.HandleConnectAsyncCompleted(AsyncInfo : IAsyncAction;
  Status: AsyncStatus);
begin
  FOpDoneFlag.&Set();
end;

procedure TElSocket.HandleSendCompleted(AsyncInfo : IAsyncOperationWithProgress<uint, uint>; Status: AsyncStatus);
begin
  //if Assigned(FOnLog) then FOnLog(Self, 'HandleSendCompleted, status: ' + Status.ToString());
  FSendDoneFlag.&Set();
end;

procedure TElSocket.HandleFlushCompleted(AsyncInfo : IAsyncOperation<boolean>; Status: AsyncStatus);
begin
  //if Assigned(FOnLog) then FOnLog(Self, 'HandleFlushCompleted, status: ' + Status.ToString());
  FSendDoneFlag.&Set();
end;

procedure TElSocket.HandleRecvCompleted(AsyncInfo : IAsyncOperationWithProgress<IBuffer, uint>;
  Status: AsyncStatus);
var
  Buf : ByteArray;
begin
  //if Assigned(FOnLog) then FOnLog(Self, 'HandleRecvCompleted');
  // As this method is invoked from a secondary thread, we are not throwing
  // any exceptions from it. Instead, we are letting the component know about the
  // error so that it could fire the exception on a subsequent synchronous call.
  try
    if (Status = AsyncStatus.Completed) then
    begin
      // copying data from FLoadBuffer to spool
      //FLoadBuffer := System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeBufferExtensions.ToArray(FLoadBufferIntf)
      if AsyncInfo.GetResults.Length > 0 then
      begin
        Buf := System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeBufferExtensions.ToArray(AsyncInfo.GetResults);
        //if Assigned(FOnLog) then FOnLog(Self, 'HandleRecvCompleted: received ' + Length(Buf) + ' bytes');
        WriteToInputSpool(Buf, 0, Buf.Length);
        ReleaseArray(Buf);
      end
      else
      begin
        //if Assigned(FOnLog) then FOnLog(Self, 'HandleRecvCompleted: received 0 bytes, connection closed');

      end;
      if (FSocket <> nil) and (FSocket.InputStream <> nil) then
      begin
        //if Assigned(FOnLog) then FOnLog(Self, 'Socket::HandleRecvCompleted, calling ReadAsync()');
        FLoadOp := FSocket.InputStream.ReadAsync({WindowsRuntimeBuffer.&Create(DEF_BUFFER_SIZE)}FReadBuffer, DEF_BUFFER_SIZE, InputStreamOptions.Partial);
        FLoadOp.Completed := new AsyncOperationWithProgressCompletedHandler<IBuffer, uint>(new AsyncOperationWithProgressCompletedHandler<IBuffer, uint>(HandleRecvCompleted));
      end
      else
        FLoadOp := nil;
    end
    else
    begin
      FLoadOp := nil;
      FLastWinRTSocketError := AsyncInfo.ErrorCode;
    end;
  finally
    FRecvDoneFlag.&Set();
  end;
end;

procedure TElSocket.WriteToInputSpool(Buf : ByteArray; StartIndex : integer; Len : integer);
var
  OldLen : integer;
begin
  Monitor.Enter(FInputSpoolLock);
  try
    OldLen := Length(FInputSpool);
    SetLength(FInputSpool, OldLen + Len);
    Array.Copy(Buf, StartIndex, FInputSpool, OldLen, Len);
  finally
    Monitor.Exit(FInputSpoolLock);
  end;
end;

function TElSocket.ReadFromInputSpool(var Buf : ByteArray; StartIndex : integer; Len : integer): integer;
begin
  Monitor.Enter(FInputSpoolLock);
  try
    Result := Min(Len, Length(FInputSpool));
    if Result > 0 then
    begin
      Array.Copy(FInputSpool, 0, Buf, StartIndex, Result);
      Array.Copy(FInputSpool, Result, FInputSpool, 0, Length(FInputSpool) - Result);
      SetLength(FInputSpool, Length(FInputSpool) - Result);
    end;
  finally
    Monitor.Exit(FInputSpoolLock);
  end;
end;

function TElSocket.RTSend(Data : ByteArray; Start : Integer; ToSend : Integer;
  Timeout : integer) : Integer;
var
  WriteOp : IAsyncOperationWithProgress<UInt32, UInt32>;
  buf : IBuffer;
  WaitRes : Boolean;
  FlushOp : IAsyncOperation<boolean>;
  DoNothingPeriod : integer;
  OpStart, OpEnd : integer;
begin
  //if Assigned(FOnLog) then FOnLog(Self, 'Socket::RTSend, to send: ' + IntToStr(ToSend));
  if (FSocket = nil) or (FSocket.OutputStream = nil) then
    raise EElSocketError.Create(sSocketNotConnected);
  try
    buf := WindowsRuntimeBuffer.&Create(Data, Start, ToSend, ToSend);
    try
      // sending data
      OpStart := GetTickCount;
      try
        FSendDoneFlag.Reset();
        WriteOp := FSocket.OutputStream.WriteAsync(buf);
        WriteOp.Completed := new AsyncOperationWithProgressCompletedHandler<uint, uint>(new AsyncOperationWithProgressCompletedHandler<uint, uint>(HandleSendCompleted));
        if (WriteOp.Status <> AsyncStatus.Completed) then
        begin
          //if Assigned(FOnLog) then FOnLog(Self, 'RTSend: operation launched asynchronously, waiting for the result');
          if Timeout = 0 then
            WaitRes := FSendDoneFlag.WaitOne()
          else
            WaitRes := FSendDoneFlag.WaitOne(Timeout);

          //if WaitRes then
          //  if Assigned(FOnLog) then FOnLog(Self, 'RTSend: asynchronous operation completed')
          //else
          //  if Assigned(FOnLog) then FOnLog(Self, 'RTSend: timeout exceeded and operation did not finish');

          if WaitRes = false then
            raise {$ifndef SB_NO_NET_SOCKETS}EElSocketError {$else}EElSocketHandlerError {$endif}.Create(sTimeout, SB_SOCKET_ERROR_CODE_TIMEDOUT);
        end;
        if (WriteOp.Status <> AsyncStatus.Completed) then
        begin
          //if Assigned(FOnLog) then FOnLog(Self, 'RTSend: error, status is not Completed');
          if WriteOp.ErrorCode <> nil then
            raise WriteOp.ErrorCode
          else
            raise {$ifndef SB_NO_NET_SOCKETS}EElSocketError {$else}EElSocketHandlerError {$endif}.Create(sOperationFailed, -1);
        end;

        result := WriteOp.GetResults;
        //if Assigned(FOnLog) then FOnLog(Self, 'RTSend: ' + IntToStr(result) + ' bytes have been sent');

      finally
        FSendDoneFlag.Reset();
      end;
    finally
      buf.Length := 0;
      buf := nil;
    end;

    // flushing data
    try
      repeat

        FSendDoneFlag.Reset();
        //if Assigned(FOnLog) then FOnLog(Self, 'RTSend: flushing data');
        FlushOp := FSocket.OutputStream.FlushAsync();
        FlushOp.Completed := new AsyncOperationCompletedHandler<boolean>(new AsyncOperationCompletedHandler<boolean>(HandleFlushCompleted));
        if (FlushOp.Status <> AsyncStatus.Completed) then
        begin
          //if Assigned(FOnLog) then FOnLog(Self, 'RTSend: operation launched asynchronously, waiting for the result');
          if Timeout = 0 then
            WaitRes := FSendDoneFlag.WaitOne()
          else
            WaitRes := FSendDoneFlag.WaitOne(Timeout);

          //if WaitRes then
          //  if Assigned(FOnLog) then FOnLog(Self, 'RTSend: asynchronous operation completed')
          //else
          //  if Assigned(FOnLog) then FOnLog(Self, 'RTSend: timeout exceeded and operation did not finish');

          //FSendDoneFlag.Reset();
          if WaitRes = false then
            raise {$ifndef SB_NO_NET_SOCKETS}EElSocketError {$else}EElSocketHandlerError {$endif}.Create(sTimeout, SB_SOCKET_ERROR_CODE_TIMEDOUT);
        end;
        if (FlushOp.Status <> AsyncStatus.Completed) then
        begin
          //if Assigned(FOnLog) then FOnLog(Self, 'RTSend (flush): error, status is not Completed');
          if FlushOp.ErrorCode <> nil then
            raise FlushOp.ErrorCode
          else
            raise {$ifndef SB_NO_NET_SOCKETS}EElSocketError {$else}EElSocketHandlerError {$endif}.Create(sOperationFailed, -1);
        end;

        //if Assigned(FOnLog) then FOnLog(Self, 'RTSend (flush): finished');

      until FlushOp.GetResults();
    finally
      FSendDoneFlag.Reset();
    end;
    OpEnd := GetTickCount;

    Inc(FTotalSendTime, TickDiff(OpStart, OpEnd));
    if FOutboundDataSocket then
    begin
      // According to research, flush doesn't actually flush data to the network layer.
      // Depending on connection speed, up to 20 per cent of data might accumulate
      // somewhere within the stack and sent later even though both Send and Flush return.
      // Where the application layer doesn't provide means for verifying that
      // the whole data have reached the destination (such as FTP data channel or
      // HTTP POST and PUT methods), this might end up with incomplete file on
      // the server. Unfortunately the only technically accomplishable solution is
      // to place artificial delays to the Send method so that the underlying
      // implementation had time to send the accumulated data out.
      DoNothingPeriod := integer(Math.Round(TickDiff(OpStart, OpEnd) * 1.2) + 200 + FExtraDelayAfterSend);
      FSendDoneFlag.Reset();
      FSendDoneFlag.WaitOne(DoNothingPeriod);
      Inc(FTotalSendTime, DoNothingPeriod);
    end;

    Inc(FTotalDataSent, Result);
    FLastSendTick := GetTickCount;
  except
    raise;
  end;
  //if Assigned(FOnLog) then FOnLog(Self, 'Socket::RTSend, flushing done');
end;

function TElSocket.RTReceive(Data : ByteArray; Start : Integer; ToReceive : Integer;
  Timeout : integer) : Integer;
var
  WaitRes : Boolean;
  Buf : ByteArray;
  Len : integer;
begin
  // Note that we aren't invoking any socket 'receive' calls here. The receive operation
  // runs in an independent 'loop' on background; this method only consumes data
  // already available in FDataReader.
  //if Assigned(FOnLog) then FOnLog(Self, 'RTReceive: need ' + IntToStr(ToReceive) + ' bytes');

  WaitRes := false;
  if (Length(FInputSpool) = 0) and (FLastWinRTSocketError = nil) then
  begin
    if (FSocket = nil) or (FSocket.InputStream = nil) then
      raise EElSocketError.Create(sSocketNotConnected);
    //if Assigned(FOnLog) then FOnLog(Self, 'RTReceive: no bytes currently available, waiting for ' + Timeout.ToString() + 'ms');
    // waiting for the data to arrive to the socket
    FRecvDoneFlag.Reset();
    if Timeout = 0 then
      WaitRes := FRecvDoneFlag.WaitOne()
    else
      WaitRes := FRecvDoneFlag.WaitOne(Timeout);
    //if Assigned(FOnLog) then FOnLog(Self, 'RTReceive: ended up with WaitRes=' + WaitRes.TOString());
  end;

  // checking if there are any data cached in local buffer
  Len := Length(FInputSpool);
  //if Assigned(FOnLog) then FOnLog(Self, 'RTReceive: got ' + Len.ToString() + ' bytes in unconsumed buffer');
  //if FDataReader.UnconsumedBufferLength > 0 then
  if Len > 0 then
  begin
    //if Assigned(FOnLog) then FOnLog(Self, 'RTReceive: reading them');
    Result := Min(Len, ToReceive);
    SetLength(buf, Result);
    //FDataReader.ReadBytes(buf);
    Result := ReadFromInputSpool(buf, 0, Result);
    // The size of the buffer *should not* change after the ReadBytes() call,
    // however, total absence of documentation doesn't let us take this as
    // a rule. So we are doing an additional size check here.
    if Length(buf) <> Result then
      raise EElSocketError.Create('Internal read error');
    SBMove(buf, 0, Data, Start, Result);
    ReleaseArray(buf);
    //if Assigned(FOnLog) then FOnLog(Self, 'RTReceive: data have been read');
  end
  else if FLastWinRTSocketError <> nil then
    RaiseLastWinRTSocketError
  else if not WaitRes then
    raise
      {$ifndef SB_NO_NET_SOCKETS}
      SocketException.Create(sTimeout)
       {$else}
      EElSocketHandlerError.Create(SB_SOCKET_ERROR_CODE_TIMEDOUT)
       {$endif}
  else
    Result := 0;
  //if Assigned(FOnLog) then FOnLog(Self, 'Socket::RTReceive, result: ' + IntToStr(result));
end;

function TElSocket.RTPoll(Timeout : integer; SendDirection : boolean): boolean;
var
  WaitRes : Boolean;
begin
  if SendDirection then
  begin
    //if Assigned(FOnLog) then FOnLog(Self, 'RTPoll(write)');
    if (FSocket = nil) or (FSocket.OutputStream = nil) then
      raise EElSocketError.Create(sSocketNotConnected);
    Result := true;
  end
  else
  begin
    WaitRes := false;

    //if Assigned(FOnLog) then FOnLog(Self, 'RTPoll(read)');

    if (Length(FInputSpool) = 0) and (FLastWinRTSocketError = nil) then
    begin
      if (FSocket = nil) or (FSocket.InputStream = nil) then
        raise EElSocketError.Create(sSocketNotConnected);
      //if Assigned(FOnLog) then FOnLog(Self, 'RTPoll: no data cached, waiting for ' + Timeout.TOString() + ' ms');
      // waiting for the data to arrive to the socket
      FRecvDoneFlag.Reset();
      if Timeout = -1 then
        WaitRes := FRecvDoneFlag.WaitOne()
      else
        WaitRes := FRecvDoneFlag.WaitOne(Timeout);

      //if Assigned(FOnLog) then FOnLog(Self, 'RTPoll: WaitRes is ' + WaitRes.toString());

    end
    else if FLastWinRTSocketError <> nil then
      RaiseLastWinRTSocketError;

    Result := (Length(FInputSpool) > 0) or WaitRes;
    //if Assigned(FOnLog) then FOnLog(Self, 'RTPoll: ending up with ' + Result.ToString());
  end;
end;

procedure TElSocket.RTWaitForOutboundDataDeliveryFacepalm(Socket : StreamSocket);
const
  SB_MIN_DELAY_BEFORE_CLOSE : integer = 500;
var
  Gap : integer;
  ConnSpeed : integer;
begin
  //if Assigned(FOnLog) then FOnLog(Self, 'Socket::RTWaitForOutboundDataDeliveryFacepalm');
  // If a WinRT StreamSocket is closed too quickly after sending data to it,
  // a trailing piece of data may remain unsent to the network (even though it
  // has been sent and flushed to StreamSocket.OutputStream). See a comment
  // in the RTSend() method implementation.
  try
    if FOutboundDataSocket then
    begin
      // adjusting the waiting time as a time needed to transfer 5% of the
      // total data sent through a channel with real connection speed
      if FTotalSendTime <> 0 then
        ConnSpeed := ((FTotalDataSent * 1000) div FTotalSendTime) // bytes/sec
      else
        ConnSpeed := 100000;
      if ConnSpeed = 0 then
        ConnSpeed := 1024;
      Gap := ((FTotalDataSent shr 3) div (ConnSpeed)) * 1000;
      if Gap = 0 then
        Gap := SB_MIN_DELAY_BEFORE_CLOSE;
      Inc(Gap, SB_MIN_DELAY_BEFORE_CLOSE);
    end
    else
      Gap := SB_MIN_DELAY_BEFORE_CLOSE;
    Inc(Gap, FExtraDelayBeforeClose);
    if integer(TickDiff(FLastSendTick, GetTickCount())) < Gap then
    begin
      FSendDoneFlag.Reset();
      FSendDoneFlag.WaitOne(Gap);
    end;
  except
    ;
  end;
  //if Assigned(FOnLog) then FOnLog(Self, 'Socket::RTWaitForOutboundDataDeliveryFacepalm: exiting');
end;
 {$endif}

{$ifndef SB_NO_SERVER_SOCKETS}
{.$ifdef SB_NET_DESKTOP}
procedure TElSocket.SocksAccept(Timeout: integer;
  OnAuthMethodChoose : TSBSocksAuthMethodChooseEvent;
  OnAuthPassword : TSBSocksAuthPasswordEvent;
  OnConnect : TSBSocksConnectEvent;
  CloseConnectionOnError : boolean;
  ResolveAddress : boolean);
const
  SB_SOCKS5_HOST_UNREACHABLE = 4;
var
  Buf : ByteArray;
  Err : integer;
  Addr, UserCode, Pass, DN : ByteArray;
  Port : integer;
  AddrStr : string;
  AddrInt : integer;
  AddrLen : integer;
  ChosenAuth: integer;
  I : integer;
  AuthMethods : array of TElSocksAuthentication;
  AuthMethod : TElSocksAuthentication;
  Cancel, AuthSucceeded, Allow : boolean;
  {$ifdef  SB_UNICODE_VCL}
  AnsiBuf : ByteArray;
   {$endif}

  procedure ReportError(Code : integer);
  begin
    raise EElSocketError.Create(SSocksNegotiationFailed, Code);
  end;

  function ReadNBytesFromSocket(Count: integer; var ErrCode: integer;
    ReportErrorOnFailure : boolean; ReportErrorCode : integer): ByteArray;
  var
    Ptr :  ^byte ;
    Read : integer;
    Tm : integer;
  begin
    

    ErrCode := 0;
    if Timeout = 0 then
      Tm := -1
    else
      Tm := Timeout;
    SetLength(Result, Count);
    Ptr :=  @Result[0] ;
    while Count > 0 do
    begin
      if CanReceive(Tm) then
      begin
        ErrCode := Receive(Ptr, Count, Read);
      end
      else
        ErrCode := SB_SOCKET_ERROR_CODE_TIMEDOUT;
      if ErrCode = 0 then
      begin
        if Read = 0 then
        begin
          ErrCode := SB_SOCKET_ERROR_CODE_CONNRESET;
          Break;
        end;
        Inc(Ptr, Read);
        Dec(Count, Read);
      end
      else
        Break;
    end;
    if (ErrCode <> 0) and ReportErrorOnFailure then
    begin
      if (ReportErrorCode = 0) then
        ReportErrorCode := ErrCode;
      ReportError(ReportErrorCode);
    end;

  end;

  function ReadUntilNullFromSocket(var ErrCode: integer; ReportErrorOnFailure : boolean;
    ReportErrorCode : integer): ByteArray;
  const
    MAX_TS_LENGTH = 256;
  var
    TmpBuf : ByteArray;
    Idx : integer;
  begin
    SetLength(TmpBuf, 0);
    SetLength(Result, MAX_TS_LENGTH);
    Idx := 0;
    while true do
    begin
      TmpBuf := ReadNBytesFromSocket(1, ErrCode, false, 0);
      if ErrCode = 0 then
      begin
        if TmpBuf[0] <> 0 then
        begin
          Result[Idx] := TmpBuf[0];
          Inc(Idx);
          if Idx >= MAX_TS_LENGTH then
          begin
            Err := -1;
            Break;
          end;
        end
        else
          Break;
      end
      else
        Break;
    end;
    if ErrCode = 0 then
      SetLength(Result, Idx)
    else if ReportErrorOnFailure then
    begin
      if ReportErrorCode = 0 then
        ReportErrorCode := ErrCode;
      ReportError(ReportErrorCode);
    end;

  end;

  function SendNBytesToSocket(Buffer:  pointer ;
    Count: integer; ReportErrorOnFailure : boolean;
    ReportErrorCode : integer): integer;
  var
    Ptr :  ^byte ;
    Sent : integer;
    Tm : integer;
  begin
    Result := 0;
    if Timeout = 0 then
      Tm := -1
    else
      Tm := Timeout;
    Ptr :=  Buffer ;
    while Count > 0 do
    begin
      if CanSend(Tm) then               
        Result := Send(Ptr, Count, Sent)
      else
        Result := SB_SOCKET_ERROR_CODE_TIMEDOUT;
      if Result <> 0 then
        Break;
      Inc(Ptr, Sent);
      Dec(Count, Sent);
    end;
    if (Result <> 0) and ReportErrorOnFailure then
    begin
      if ReportErrorCode = 0 then
        ReportErrorCode := Result;
      ReportError(ReportErrorCode);
    end;
  end;

  procedure SendV4Status(Success : boolean);
  var
    Msg : ByteArray;
  begin
    SetLength(Msg, 8);
    FillChar( Msg[0] , Length(Msg), 0);
    if Success then
      Msg[1] := $5a
    else
      Msg[1] := $5b;
    SendNBytesToSocket( @Msg[0] , Length(Msg), true, SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED);
  end;

  procedure SendV5Error(Code: byte);
  var
    Msg : ByteArray;
  begin
    SetLength(Msg, 10);
    FillChar( Msg[0] , Length(Msg), 0);
    Msg[0] := 5;
    Msg[1] := Code;
    Msg[3] := 1;
    SendNBytesToSocket( @Msg[0] , Length(Msg), true, SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED);
  end;

  procedure AddAuthMethod(V : TElSocksAuthentication);
  var
    Len : integer;
  begin
    Len := Length(AuthMethods);
    SetLength(AuthMethods, Len + 1);
    AuthMethods[Len] := V;
  end;

begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}

  try
    AddrStr := '';
    AuthMethod := saUserCode; // considering password-based authentication to be used by default
    SetLength(UserCode, 0);
    SetLength(Pass, 0);
    SetLength(DN, 0);
    // reading version number and ID list (V5) or command type (V4)
    SetLength(Buf, 2);
    Buf := ReadNBytesFromSocket(2, Err, true, SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED);
    if Buf[0] = 4 then // SOCKS 4
    begin
      if Buf[1] = 1 then // TCP stream connection
      begin
        Buf := ReadNBytesFromSocket(6, Err, true, SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED);
        Port := (Buf[0] shl 8) or Buf[1];
        SetLength(Addr, 4);
        SBMove(Buf[2], Addr[0], 4);
        UserCode := ReadUntilNullFromSocket(Err, true, SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED);
        if (Addr[0] = 0) and (Addr[1] = 0) and (Addr[2] = 0) then // SOCKS 4a
        begin
          try
            //if not ResolveAddress then
            //  ReportError(SB_SOCKET_ERROR_SOCKS_FAILED_TO_RESOLVE_DESTINATION_ADDRESS);
            DN := ReadUntilNullFromSocket(Err, true, SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED);
            if ResolveAddress then
            begin
              try
                AddrStr := IPFromHost(UTF8ToStr(DN){$ifdef SB_IPv6}, false {$endif});

                {$ifndef SB_UNICODE_VCL}
                AddrInt := inet_addr(PAnsiChar(AddrStr));
                 {$else}
                AnsiBuf :=  BytesOfString(AddrStr) ;
                AddrInt := inet_addr(@AnsiBuf[0]);
                 {$endif SB_UNICODE_VCL}

                Addr := GetByteArrayFromDWordLE(cardinal(AddrInt));
                if Length(AddrStr) = 0 then
                  raise EElSocketError.Create(''); // caught by the below catch block
              except
                ReportError(SB_SOCKET_ERROR_SOCKS_FAILED_TO_RESOLVE_DESTINATION_ADDRESS);
              end;
            end
            else
              AddrStr := UTF8ToStr(DN);
          except
            SendV4Status(false);
            raise;
          end;
        end
        else
          AddrStr := IntToStr(Addr[0]) + '.' + IntToStr(Addr[1]) + '.' + IntToStr(Addr[2]) + '.' + IntToStr(Addr[3]);
        Cancel := false;
        if Assigned(OnAuthMethodChoose) then
        begin
          SetLength(AuthMethods, 2);
          AuthMethods[0] := saNoAuthentication;
          AuthMethods[1] := saUsercode;
          OnAuthMethodChoose(Self, AuthMethods, AuthMethod, Cancel);
        end;
        AuthSucceeded := false;
        if (not Cancel) and (AuthMethod = saUsercode) then
        begin
          if Assigned(OnAuthPassword) then
            OnAuthPassword(Self, UTF8ToStr(UserCode), '', AuthSucceeded);
        end
        else if not Cancel then
          AuthSucceeded := true; // no authentication
        if not AuthSucceeded then
        begin
          SendV4Status(false);
          ReportError(SB_SOCKET_ERROR_SOCKS_AUTH_FAILED);
        end;
        Allow := true;
        if Assigned(OnConnect) then
          OnConnect(Self, AddrStr, Port , Allow );
        SendV4Status(Allow);
        if not Allow then
          ReportError(SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED);
      end
      else
        ReportError(SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED);
    end
    else if Buf[0] = 5 then
    begin
      // authenticating
      Buf := ReadNBytesFromSocket(Buf[1], Err, true, SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED);
      for I := 0 to Length(Buf) - 1 do
      begin
        if Buf[I] = 0 then
          AddAuthMethod(saNoAuthentication)
        else if Buf[I] = 2 then
          AddAuthMethod(saUserCode);
      end;
      Cancel := false;
      if Assigned(OnAuthMethodChoose) then
      begin
        OnAuthMethodChoose(Self, AuthMethods, AuthMethod, Cancel);
      end;
      ChosenAuth := $ff;
      if (not Cancel) then
      begin
        if AuthMethod = saNoAuthentication then
          ChosenAuth := 0
        else if AuthMethod = saUserCode then
          ChosenAuth := 2;
      end;
      SetLength(Buf, 2);
      Buf[0] := 5;
      Buf[1] := byte(ChosenAuth);
      Err := SendNBytesToSocket( @Buf[0] , 2, true, SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED);
      if ChosenAuth = 2 then
      begin
        Buf := ReadNBytesFromSocket(2, Err, false, 0);
        if (Err <> 0) or (Buf[0] <> 1) then
          ReportError(SB_SOCKET_ERROR_SOCKS_AUTH_FAILED);
        Buf := ReadNBytesFromSocket(Buf[1] + 1, Err, true, SB_SOCKET_ERROR_SOCKS_AUTH_FAILED); // one extra character for password length field
        SetLength(UserCode, Length(Buf) - 1);
        SBMove(Buf[0], UserCode[0], Length(UserCode));
        Pass := ReadNBytesFromSocket(Buf[Length(Buf) - 1], Err, true, SB_SOCKET_ERROR_SOCKS_AUTH_FAILED);
        AuthSucceeded := false;
        if Assigned(OnAuthPassword) then
           OnAuthPassword(Self,  StringOfBytes (UserCode),
             StringOfBytes (Pass) , AuthSucceeded );
        SetLength(Buf, 2);
        Buf[0] := 1;
        if AuthSucceeded then
          Buf[1] := 0
        else
          Buf[1] := 1;
        Err := SendNBytesToSocket( @Buf[0] , 2, true, SB_SOCKET_ERROR_SOCKS_AUTH_FAILED);
        if not AuthSucceeded then
          ReportError(SB_SOCKET_ERROR_SOCKS_AUTH_FAILED);
      end
      else if ChosenAuth <> 0 then // only password-based auth is supported for now
        ReportError(SB_SOCKET_ERROR_SOCKS_AUTH_FAILED);
      // processing connection request
      Buf := ReadNBytesFromSocket(4, Err, true, SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED);
      if (Buf[0] <> 5) or (Buf[1] <> 1) or (Buf[2] <> 0) then // no other methods except Connect are supported
        ReportError(SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED);
      AddrLen := 0;
      case Buf[3] of
        1 : // IPv4 address
        begin
          Addr := ReadNBytesFromSocket(4, Err, true, SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED);
          AddrStr := IntToStr(Addr[0]) + '.' + IntToStr(Addr[1]) + '.' + IntToStr(Addr[2]) + '.' + IntToStr(Addr[3]);
          AddrLen := 4;
        end;
        3 : // fully-qualified domain name
        begin
          //if not ResolveAddress then
          //begin
          //  SendV5Error(SB_SOCKS5_HOST_UNREACHABLE);
          //  ReportError(SB_SOCKET_ERROR_SOCKS_FAILED_TO_RESOLVE_DESTINATION_ADDRESS);
          //end;
          Buf := ReadNBytesFromSocket(1, Err, true, SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED);
          DN := ReadNBytesFromSocket(Buf[0], Err, true, SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED);
          if ResolveAddress then
          begin
            try
              AddrStr := IPFromHost(UTF8ToStr(DN){$ifdef SB_IPv6}, FUseIPv6 {$endif});
              if Length(AddrStr) = 0 then
                raise EElSocketError.Create(''); // caught by the below catch block
            except
              // unlike V4, responding with custom failure response
              SendV5Error(SB_SOCKS5_HOST_UNREACHABLE);
              ReportError(SB_SOCKET_ERROR_SOCKS_FAILED_TO_RESOLVE_DESTINATION_ADDRESS);
            end;
            AddrLen := 4;
          end
          else
          begin
            AddrStr := UTF8ToStr(DN);
            AddrLen := 4; // we always respond with zero IP address
          end;
        end;
        4 : // IPv6 address
        begin
          Addr := ReadNBytesFromSocket(16, Err, true, SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED);
          AddrStr := '';
          for I := 0 to 7 do
            AddrStr := AddrStr + IntToHex(Addr[I shl 1], 2) + IntToHex(Addr[I shl 1 + 1], 2) + ':';
          SetLength(AddrStr, Length(AddrStr) - 1);
          AddrLen := 16;
        end;
      else
        ReportError(SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED);
      end;
      Buf := ReadNBytesFromSocket(2, Err, true, SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED);
      Port := (Buf[0] shl 8) or Buf[1];
      Allow := true;
      if Assigned(OnConnect) then
         OnConnect(Self, AddrStr, Port , Allow );
      SetLength(Buf, 6 + AddrLen);
      FillChar(Buf[0], Length(Buf), 0);
      Buf[0] := 5;
      if not Allow then
        Buf[1] := 2;
      if AddrLen = 4 then
        Buf[3] := 1
      else
        Buf[3] := 4;
      SendNBytesToSocket( @Buf[0] , Length(Buf), true, SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED);
      if not Allow then
        ReportError(SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED);
    end
    else
      ReportError(SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED);
  except
    if CloseConnectionOnError then
      try
        Close(true);
      except
        ;
      end;
    raise;
  end;

 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;
 {$endif}

{$ifndef SB_NO_SERVER_SOCKETS}
procedure TElSocket.SetLocalBinding(value :  TElClientSocketBinding );
begin
  FLocalBinding.Assign(Value);
end;

procedure TElSocket.SetListenBinding(value :  TElClientSocketBinding );
begin
  FListenBinding.Assign(Value);
end;
 {$endif}

{$ifndef SB_SILVERLIGHT_SOCKETS}
function TElSocket.IPFromHost(const Host : string{$ifdef SB_IPv6}; UseIPv6 : boolean {$endif}) : string;
var
  Addr : TSockAddrStorage;
begin
  {$ifdef SB_DNSSEC}FDNS. {$endif}ResolveHostName(Host, {$ifdef SB_IPv6}UseIPv6, {$endif} Addr);
  AddressToString(Addr, result);
end;
 {$endif}

{$ifdef SB_DNSSEC}
procedure TElSocket.SetDNS(ASettings: TElDNSSettings);
begin
  FDNS.Assign(ASettings);
end;

procedure TElSocket.HandleDNSKeyNeeded(Sender: TObject; const Owner: string;
  KeyTag: Word; Algorithm: Byte; var Key: TElDNSPublicKeyRecord;
  var ReleaseKey: TSBBoolean);
begin
  if Assigned(FOnDNSKeyNeeded) then
    FOnDNSKeyNeeded(Self, Owner, KeyTag, Algorithm, Key, ReleaseKey);
end;

procedure TElSocket.HandleDNSKeyValidate(Sender: TObject; Key: TElDNSPublicKeyRecord;
  var Valid: TSBBoolean);
begin
  if Assigned(FOnDNSKeyValidate) then
    FOnDNSKeyValidate(Self, Key, Valid)
  else
    raise EElSocketError.Create(SDNSErrorUnassignedHandler, SB_DNS_ERROR_UNASSIGNED_HANDLER);
end;

procedure TElSocket.HandleDNSResolve(Sender: TObject; const HostName: string;
  Response: TElDNSResourceRecordSet; ResolveResult: Integer; SecurityStatus: TSBDNSSecurityStatus);
begin
  if Assigned(FOnDNSResolve) then
    FOnDNSResolve(Self, HostName, Response, ResolveResult, SecurityStatus);
end;
 {$endif}


{$ifndef SB_NO_SERVER_SOCKETS}
procedure TElCustomSocketBinding.Assign(Source : TElCustomSocketBinding);
begin
  if Source <> nil then
  begin
    FLocalIntfAddress := Source.FLocalIntfAddress;
    FPort := Source.FPort;
  end;
end;

procedure TElClientSocketBinding.Assign(Source : TElCustomSocketBinding);
begin
  inherited;
  if Source is TElClientSocketBinding then
  begin
    FPortRangeFrom := TElClientSocketBinding(Source).FPortRangeFrom;
    FPortRangeTo := TElClientSocketBinding(Source).FPortRangeTo;
  end;
end;
 {$endif}

initialization
{$ifdef SB_WINDOWS}
  WinsockInitialized := false;
  {$ifdef SB_IPv6}
  WinsockIPv6Enabled := False;
  WinsockHandle := 0;
  Wship6Handle := 0;
  FreeAddrInfoAProc := nil;
  FreeAddrInfoWProc := nil;
  GetAddrInfoAProc := nil;
  GetAddrInfoWProc := nil;
  GetNameInfoAProc := nil;
  GetNameInfoWProc := nil;
   {$endif}
 {$endif}
  TElSocket.InitializeWinsock;
finalization
  TElSocket.FinalizeWinsock;


end.
