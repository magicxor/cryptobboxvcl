// CodeGear C++Builder
// Copyright (c) 1995, 2009 by Embarcadero Technologies, Inc.
// All rights reserved

// (DO NOT EDIT: machine generated header) 'Sbsocket.pas' rev: 21.00

#ifndef SbsocketHPP
#define SbsocketHPP

#pragma delphiheader begin
#pragma option push
#pragma option -w-      // All warnings off
#pragma option -Vx      // Zero-length empty class member functions
#pragma pack(push,8)
#include <System.hpp>	// Pascal unit
#include <Sysinit.hpp>	// Pascal unit
#include <Sbtypes.hpp>	// Pascal unit
#include <Sbutils.hpp>	// Pascal unit
#include <Sbstrutils.hpp>	// Pascal unit
#include <Sbconstants.hpp>	// Pascal unit
#include <Sbhttpauth.hpp>	// Pascal unit
#include <Sbstringlist.hpp>	// Pascal unit
#include <Sbhttpsconstants.hpp>	// Pascal unit
#include <Sbencoding.hpp>	// Pascal unit
#include <Sysutils.hpp>	// Pascal unit
#include <Classes.hpp>	// Pascal unit
#include <Windows.hpp>	// Pascal unit
#include <Winsock.hpp>	// Pascal unit
#include <Sbpunycode.hpp>	// Pascal unit

//-- user supplied -----------------------------------------------------------

namespace Sbsocket
{
//-- type declarations -------------------------------------------------------
#pragma option push -b-
enum TElShutdownDirection { sdReceive, sdSend, sdSendAndReceive };
#pragma option pop

#pragma option push -b-
enum TElSocketState { issNotASocket, issInitializing, issInitialized, issBound, issConnected, issListening, issConnecting };
#pragma option pop

#pragma option push -b-
enum TElSocketType { istStream, istDatagram };
#pragma option pop

#pragma option push -b-
enum TElSocksVersion { elSocks4, elSocks5 };
#pragma option pop

#pragma option push -b-
enum TElSocksAuthentication { saNoAuthentication, saUsercode };
#pragma option pop

#pragma option push -b-
enum TElWebTunnelAuthentication { wtaNoAuthentication, wtaBasic, wtaDigest, wtaNTLM };
#pragma option pop

#pragma option push -b-
enum TElBandwidthPolicy { bpFlexible, bpStrict };
#pragma option pop

class DELPHICLASS EElSocketError;
class PASCALIMPLEMENTATION EElSocketError : public Sbutils::ESecureBlackboxError
{
	typedef Sbutils::ESecureBlackboxError inherited;
	
public:
	/* ESecureBlackboxError.Create */ inline __fastcall EElSocketError(const System::UnicodeString AMessage)/* overload */ : Sbutils::ESecureBlackboxError(AMessage) { }
	
public:
	/* Exception.CreateFmt */ inline __fastcall EElSocketError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size) { }
	/* Exception.CreateRes */ inline __fastcall EElSocketError(int Ident)/* overload */ : Sbutils::ESecureBlackboxError(Ident) { }
	/* Exception.CreateResFmt */ inline __fastcall EElSocketError(int Ident, System::TVarRec const *Args, const int Args_Size)/* overload */ : Sbutils::ESecureBlackboxError(Ident, Args, Args_Size) { }
	/* Exception.CreateHelp */ inline __fastcall EElSocketError(const System::UnicodeString Msg, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, AHelpContext) { }
	/* Exception.CreateFmtHelp */ inline __fastcall EElSocketError(const System::UnicodeString Msg, System::TVarRec const *Args, const int Args_Size, int AHelpContext) : Sbutils::ESecureBlackboxError(Msg, Args, Args_Size, AHelpContext) { }
	/* Exception.CreateResHelp */ inline __fastcall EElSocketError(int Ident, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(Ident, AHelpContext) { }
	/* Exception.CreateResFmtHelp */ inline __fastcall EElSocketError(System::PResStringRec ResStringRec, System::TVarRec const *Args, const int Args_Size, int AHelpContext)/* overload */ : Sbutils::ESecureBlackboxError(ResStringRec, Args, Args_Size, AHelpContext) { }
	/* Exception.Destroy */ inline __fastcall virtual ~EElSocketError(void) { }
	
};


struct sockaddr_storage;
typedef sockaddr_storage *PSockAddrStorage;

#pragma pack(push,1)
struct sockaddr_storage
{
	
public:
	System::Word ss_family;
	StaticArray<System::Byte, 6> __ss_pad1;
	__int64 __ss_align;
	StaticArray<System::Byte, 112> __ss_pad2;
};
#pragma pack(pop)


typedef sockaddr_storage TSockAddrStorage;

typedef void __fastcall (__closure *TSBSocksAuthMethodChooseEvent)(System::TObject* Sender, TElSocksAuthentication *AuthMethods, const int AuthMethods_Size, TElSocksAuthentication &AuthMethod, bool &Cancel);

typedef void __fastcall (__closure *TSBSocksAuthPasswordEvent)(System::TObject* Sender, const System::UnicodeString Username, const System::UnicodeString Password, bool &Accept);

typedef void __fastcall (__closure *TSBSocksConnectEvent)(System::TObject* Sender, const System::UnicodeString DestHost, int DestPort, bool &Allow);

class DELPHICLASS TElCustomSocketBinding;
class PASCALIMPLEMENTATION TElCustomSocketBinding : public Classes::TPersistent
{
	typedef Classes::TPersistent inherited;
	
protected:
	int FPort;
	System::UnicodeString FLocalIntfAddress;
	
public:
	HIDESBASE virtual void __fastcall Assign(TElCustomSocketBinding* Source);
	
__published:
	__property System::UnicodeString LocalIntfAddress = {read=FLocalIntfAddress, write=FLocalIntfAddress};
	__property int Port = {read=FPort, write=FPort, nodefault};
public:
	/* TPersistent.Destroy */ inline __fastcall virtual ~TElCustomSocketBinding(void) { }
	
public:
	/* TObject.Create */ inline __fastcall TElCustomSocketBinding(void) : Classes::TPersistent() { }
	
};


typedef TElCustomSocketBinding ElCustomSocketBinding;

class DELPHICLASS TElClientSocketBinding;
class PASCALIMPLEMENTATION TElClientSocketBinding : public TElCustomSocketBinding
{
	typedef TElCustomSocketBinding inherited;
	
protected:
	int FPortRangeFrom;
	int FPortRangeTo;
	
public:
	virtual void __fastcall Assign(TElCustomSocketBinding* Source);
	
__published:
	__property int PortRangeFrom = {read=FPortRangeFrom, write=FPortRangeFrom, nodefault};
	__property int PortRangeTo = {read=FPortRangeTo, write=FPortRangeTo, nodefault};
public:
	/* TPersistent.Destroy */ inline __fastcall virtual ~TElClientSocketBinding(void) { }
	
public:
	/* TObject.Create */ inline __fastcall TElClientSocketBinding(void) : TElCustomSocketBinding() { }
	
};


typedef TElClientSocketBinding TElSocketBinding;

typedef TElClientSocketBinding ElClientSocketBinding;

typedef TElClientSocketBinding ElSocketBinding;

class DELPHICLASS TElSocket;
typedef void __fastcall (__closure *TElSocketSecondaryEvent)(System::TObject* Sender, TElSocket* Socket, int State, bool &AbortConnect);

class PASCALIMPLEMENTATION TElSocket : public Classes::TComponent
{
	typedef Classes::TComponent inherited;
	
protected:
	int FSocket;
	bool FUseIPv6;
	bool FUsingIPv6;
	bool FUseNagle;
	TElSocketType FSktType;
	TElSocketState FState;
	System::UnicodeString FRemoteAddress;
	int FRemotePort;
	System::UnicodeString FBoundAddress;
	int FBoundPort;
	int FIncomingSpeedLimit;
	int FOutgoingSpeedLimit;
	TElBandwidthPolicy FBandwidthPolicy;
	int FblLastSentTime;
	int FblLastRecvTime;
	int FblLastSentSize;
	int FblLastRecvSize;
	TElClientSocketBinding* FLocalBinding;
	TElClientSocketBinding* FListenBinding;
	Sbtypes::ByteArray FBuffer;
	int FBufStart;
	int FBufLen;
	bool CloseRequest;
	TElSocksAuthentication FSocksAuthentication;
	System::UnicodeString FSocksPassword;
	int FSocksPort;
	bool FSocksResolveAddress;
	System::UnicodeString FSocksServer;
	System::UnicodeString FSocksUserCode;
	TElSocksVersion FSocksVersion;
	bool FUseSocks;
	bool FSocksUseIPv6;
	bool FUseWebTunneling;
	System::UnicodeString FWebTunnelAddress;
	TElWebTunnelAuthentication FWebTunnelAuthentication;
	System::UnicodeString FWebTunnelPassword;
	int FWebTunnelPort;
	System::UnicodeString FWebTunnelUserId;
	Classes::TStringList* FWebTunnelRequestHeaders;
	Classes::TStringList* FWebTunnelResponseHeaders;
	System::UnicodeString FWebTunnelResponseBody;
	int FWebTunnelResponseBodyLen;
	int FProxyResult;
	bool FShuttingDown;
	System::UnicodeString __fastcall GetRequestHeaders(void);
	void __fastcall FinishAsyncConnect(void);
	virtual void __fastcall DoAfterConnect(void);
	int __fastcall HTTPConnect(int Timeout, System::UnicodeString &NextHeader);
	void __fastcall DoSetUseNagle(bool Value);
	void __fastcall SetNonBlocking(void);
	void __fastcall ReturnData(void * Data, int DataLen);
	int __fastcall SocksConnect(int Timeout);
	int __fastcall Init(bool UseIPv6);
	bool __fastcall SocksSendReceive(unsigned Timeout, void * sendBuf, int sendBufSize, int &wasSent, void * readBuf, int readBufSize, int &wasRead, bool NeedDoubleCRLF = false);
	void __fastcall PollRemainingDataForShutdown(int Timeout);
	void __fastcall SetLocalBinding(TElClientSocketBinding* value);
	void __fastcall SetListenBinding(TElClientSocketBinding* value);
	System::UnicodeString __fastcall GetLocalHostName(void);
	void __fastcall IntSetUseNagle(bool Value);
	int __fastcall InternalReceive(void * Data, int DataLen);
	void __fastcall SetAddress(const System::UnicodeString Value);
	System::UnicodeString __fastcall GetAddress(void);
	void __fastcall SetWebTunnelRequestHeaders(Classes::TStringList* Value);
	void __fastcall SetWebTunnelAddress(const System::UnicodeString Value);
	System::UnicodeString __fastcall GetWebTunnelAddress(void);
	void __fastcall SetPort(int Value);
	void __fastcall SetUseSocks(const bool Value);
	void __fastcall SetUseWebTunneling(const bool Value);
	void __fastcall SetSocketType(const TElSocketType Value);
	int __fastcall GetListenPort(void);
	void __fastcall SetListenPort(int Value);
	int __fastcall GetListenPortRangeFrom(void);
	void __fastcall SetListenPortRangeFrom(int Value);
	int __fastcall GetListenPortRangeTo(void);
	void __fastcall SetListenPortRangeTo(int Value);
	System::UnicodeString __fastcall GetListenAddress(void);
	void __fastcall SetListenAddress(System::UnicodeString Value);
	System::UnicodeString __fastcall GetRemoteAddress(void);
	
public:
	__fastcall virtual TElSocket(Classes::TComponent* Owner)/* overload */;
	__fastcall TElSocket(void)/* overload */;
	__fastcall virtual ~TElSocket(void);
	__classmethod bool __fastcall LoadIPv6Proc(System::UnicodeString ProcName, /* out */ void * &Proc, int &WinsockUsed, int &Wship6Used);
	__classmethod void __fastcall InitializeIPv6();
	__classmethod void __fastcall FinalizeIPv6();
	void __fastcall ShutdownSocket(void)/* overload */;
	void __fastcall ShutdownSocket(TElShutdownDirection Direction)/* overload */;
	void __fastcall Close(bool Forced)/* overload */;
	void __fastcall Close(bool Forced, int Timeout)/* overload */;
	int __fastcall StartAsyncConnect(void);
	int __fastcall AsyncConnect(int Timeout);
	__classmethod void __fastcall FinalizeWinSock();
	__classmethod void __fastcall InitializeWinSock();
	int __fastcall LastNetError(void);
	System::UnicodeString __fastcall IPFromHost(const System::UnicodeString Host, bool UseIPv6);
	int __fastcall Receive(void * Data, int DataLen, int &Received);
	int __fastcall Send(void * Data, int DataLen, int &Sent);
	int __fastcall ReceiveFrom(void * Data, int DataLen, int &Received, System::UnicodeString &RemoteAddress, System::Word &RemotePort);
	int __fastcall SendTo(void * Data, int DataLen, int &Sent, const System::UnicodeString RemoteAddress, System::Word RemotePort);
	int __fastcall Connect(int Timeout);
	bool __fastcall CanReceive(int WaitTime = 0x0);
	bool __fastcall CanSend(int WaitTime = 0x0);
	bool __fastcall CanAccept(int WaitTime = 0x0);
	int __fastcall Bind(void)/* overload */;
	int __fastcall Bind(bool Outgoing)/* overload */;
	int __fastcall Bind(bool Outgoing, bool ReuseAddress)/* overload */;
	int __fastcall Listen(void);
	int __fastcall Accept(int Timeout)/* overload */;
	void __fastcall Accept(int Timeout, TElSocket* &Socket)/* overload */;
	int __fastcall AsyncConnectEx(int Timeout, TElSocket* SecondarySocket, bool SecSend, bool SecRecv, TElSocketSecondaryEvent SecEvent);
	void __fastcall SocksAccept(int Timeout, TSBSocksAuthMethodChooseEvent OnAuthMethodChoose, TSBSocksAuthPasswordEvent OnAuthPassword, TSBSocksConnectEvent OnConnect, bool CloseConnectionOnError, bool ResolveAddress);
	__property System::UnicodeString LocalHostName = {read=GetLocalHostName};
	__property System::UnicodeString RemoteAddress = {read=GetRemoteAddress};
	__property int ProxyResult = {read=FProxyResult, nodefault};
	__property TElSocketType SocketType = {read=FSktType, write=SetSocketType, nodefault};
	__property TElSocketState State = {read=FState, nodefault};
	__property bool UsingIPv6 = {read=FUsingIPv6, nodefault};
	__property int BoundPort = {read=FBoundPort, nodefault};
	__property System::UnicodeString BoundAddress = {read=FBoundAddress};
	__property int NativeSocket = {read=FSocket, nodefault};
	
__published:
	__property System::UnicodeString Address = {read=GetAddress, write=SetAddress};
	__property int Port = {read=FRemotePort, write=SetPort, nodefault};
	__property int ListenPort = {read=GetListenPort, write=SetListenPort, nodefault};
	__property int ListenPortRangeFrom = {read=GetListenPortRangeFrom, write=SetListenPortRangeFrom, nodefault};
	__property int ListenPortRangeTo = {read=GetListenPortRangeTo, write=SetListenPortRangeTo, nodefault};
	__property System::UnicodeString ListenAddress = {read=GetListenAddress, write=SetListenAddress};
	__property TElClientSocketBinding* ListenBinding = {read=FListenBinding, write=SetListenBinding};
	__property TElClientSocketBinding* OutgoingLocalBinding = {read=FLocalBinding, write=SetLocalBinding};
	__property int IncomingSpeedLimit = {read=FIncomingSpeedLimit, write=FIncomingSpeedLimit, nodefault};
	__property int OutgoingSpeedLimit = {read=FOutgoingSpeedLimit, write=FOutgoingSpeedLimit, nodefault};
	__property TElSocksAuthentication SocksAuthentication = {read=FSocksAuthentication, write=FSocksAuthentication, nodefault};
	__property System::UnicodeString SocksPassword = {read=FSocksPassword, write=FSocksPassword};
	__property int SocksPort = {read=FSocksPort, write=FSocksPort, default=1080};
	__property bool SocksResolveAddress = {read=FSocksResolveAddress, write=FSocksResolveAddress, default=0};
	__property System::UnicodeString SocksServer = {read=FSocksServer, write=FSocksServer};
	__property bool SocksUseIPv6 = {read=FSocksUseIPv6, write=FSocksUseIPv6, nodefault};
	__property System::UnicodeString SocksUserCode = {read=FSocksUserCode, write=FSocksUserCode};
	__property TElSocksVersion SocksVersion = {read=FSocksVersion, write=FSocksVersion, default=1};
	__property bool UseSocks = {read=FUseSocks, write=SetUseSocks, default=0};
	__property bool UseIPv6 = {read=FUseIPv6, write=FUseIPv6, default=0};
	__property bool UseNagle = {read=FUseNagle, write=FUseNagle, default=0};
	__property bool UseWebTunneling = {read=FUseWebTunneling, write=SetUseWebTunneling, default=0};
	__property System::UnicodeString WebTunnelAddress = {read=GetWebTunnelAddress, write=SetWebTunnelAddress};
	__property TElWebTunnelAuthentication WebTunnelAuthentication = {read=FWebTunnelAuthentication, write=FWebTunnelAuthentication, default=0};
	__property System::UnicodeString WebTunnelPassword = {read=FWebTunnelPassword, write=FWebTunnelPassword};
	__property int WebTunnelPort = {read=FWebTunnelPort, write=FWebTunnelPort, nodefault};
	__property System::UnicodeString WebTunnelUserId = {read=FWebTunnelUserId, write=FWebTunnelUserId};
	__property Classes::TStringList* WebTunnelRequestHeaders = {read=FWebTunnelRequestHeaders, write=SetWebTunnelRequestHeaders};
	__property Classes::TStringList* WebTunnelResponseHeaders = {read=FWebTunnelResponseHeaders};
	__property System::UnicodeString WebTunnelResponseBody = {read=FWebTunnelResponseBody};
};


//-- var, const, procedure ---------------------------------------------------
static const int ERROR_FACILITY_SOCKET = 0x17000;
static const Word ERROR_SOCKET_PROTOCOL_ERROR_FLAG = 0x800;
static const int SB_SOCKET_ERROR_WINSOCK_INIT_FAILED = 96257;
static const int SB_SOCKET_ERROR_WRONG_SOCKET_STATE = 96258;
static const int SB_SOCKET_ERROR_NOT_A_SOCKET = 96259;
static const int SB_SOCKET_ERROR_INVALID_ADDRESS = 96260;
static const int SB_SOCKET_ERROR_ACCEPT_FAILED = 96261;
static const int SB_SOCKET_ERROR_ADDRESS_FAMILY_MISMATCH = 96262;
static const int SB_SOCKET_ERROR_INVALID_SOCKET_TYPE = 96263;
static const int SB_SOCKET_ERROR_SOCKS_NEGOTIATION_FAILED = 96264;
static const int SB_SOCKET_ERROR_SOCKS_AUTH_FAILED = 96265;
static const int SB_SOCKET_ERROR_SOCKS_FAILED_TO_RESOLVE_DESTINATION_ADDRESS = 96266;
static const int SB_SOCKET_ERROR_DNS_SECURITY_FAILURE = 96267;
static const int SB_SOCKET_ERROR_DNS_TIMEOUT = 96268;
static const int SB_SOCKET_ERROR_WEBTUNNEL_NEGOTIATION_FAILED = 96269;
static const int SB_SOCKET_ERROR_TIMEOUT = 96270;
static const Word SB_SOCKET_ERROR_CODE_TIMEDOUT = 0x274c;
static const Word SB_SOCKET_ERROR_CODE_WOULDBLOCK = 0x2733;
static const Word SB_SOCKET_ERROR_CODE_CONNRESET = 0x2746;
static const Word SB_SOCKET_ERROR_CODE_ADDRINUSE = 0x2740;
static const Word SB_SOCKET_ERROR_CODE_ISCONN = 0x2748;
static const Word SB_SOCKET_ERROR_CODE_INPROGRESS = 0x2734;
static const Word SB_SOCKET_ERROR_CODE_SHUTDOWN = 0x274a;
extern PACKAGE void __fastcall Register(void);
extern PACKAGE bool __fastcall IsIPv6Address(const System::UnicodeString S);
extern PACKAGE bool __fastcall AddressToString(const sockaddr_storage &Addr, /* out */ System::UnicodeString &S);
extern PACKAGE bool __fastcall StringToAddress(const System::UnicodeString S, /* out */ sockaddr_storage &Addr);

}	/* namespace Sbsocket */
using namespace Sbsocket;
#pragma pack(pop)
#pragma option pop

#pragma delphiheader end.
//-- end unit ----------------------------------------------------------------
#endif	// SbsocketHPP
