(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBSocketTSPClient;

interface

uses

  Classes,
  SysUtils,
  

  SBTypes,
  SBUtils,
  SBEncoding,
  SBConstants,
  SBPEM,
  SBASN1,
  SBASN1Tree,
  SBX509,
  SBX509Ext,
  SBPKCS7,
  SBPKICommon,
  SBTSPCommon,
  SBTSPClient,
  SBSocket,
  SBCustomCertStorage;



type

  TElSocketTSPClient = class(TElCustomTSPClient)
  protected
    FAddress : string;
    FPort : integer;
    FSocketTimeout : integer;
    FSocket : TElSocket;
    FErrorMessage : string;
    procedure PrepareSocket;
  public
    constructor Create(Owner: TSBComponentBase); override; 
     destructor  Destroy; override;
    function Timestamp(const HashedData: ByteArray;
      {$ifndef BUILDER_USED}out {$else}var {$endif} ServerResult:  TSBPKIStatus ;
      {$ifndef BUILDER_USED}out {$else}var {$endif} FailureInfo: integer;
      {$ifndef BUILDER_USED}out {$else}var {$endif} ReplyCMS : ByteArray) : Integer; override;
    property Socket : TElSocket read FSocket;
    property ErrorMessage : string read FErrorMessage;
  published
    property Address : string read FAddress write FAddress;
    property Port : integer read FPort write FPort;
    property SocketTimeout : integer read FSocketTimeout write FSocketTimeout;
  end;

procedure Register;

implementation

procedure Register;
begin
  RegisterComponents('PKIBlackbox', [TElSocketTSPClient]);
end;

////////////////////////////////////////////////////////////////////////////////
// TElSocketTSPClient class

constructor TElSocketTSPClient.Create(Owner: TSBComponentBase);
begin
  inherited;
  FAddress := '';
  FPort := 318;
  FSocket := TElSocket.Create();
  FSocket.SocketType := istStream;
  FSocketTimeout := 0;
  FErrorMessage := '';
end;


 destructor  TElSocketTSPClient.Destroy;
begin
  FreeAndNil(FSocket);
  inherited;
end;

procedure TElSocketTSPClient.PrepareSocket;
begin
  try
    FSocket.Close(true);
  except
    ;
  end;
end;

function TElSocketTSPClient.Timestamp(const HashedData: ByteArray;
  {$ifndef BUILDER_USED}out {$else}var {$endif} ServerResult:  TSBPKIStatus ;
  {$ifndef BUILDER_USED}out {$else}var {$endif} FailureInfo: integer;
  {$ifndef BUILDER_USED}out {$else}var {$endif} ReplyCMS : ByteArray) : Integer;
var
  ErrCode, Len : integer;
  Request, Buf : ByteArray;
  Ptr :  ^byte ;
  Left, Done : integer;
  Flag : integer;
  RespBuf : ByteArray;
const
  SB_FLAG_TSAMSG = 0;
  SB_FLAG_POLLREP = 1;
  SB_FLAG_POLLREQ = 2;
  SB_FLAG_NEGPOLLREP = 3;
  SB_FLAG_PARTIALMSGREP = 4;
  SB_FLAG_FINALMSGREP = 5;
  SB_FLAG_ERRORMSGREP = 6;
begin
  
  

  //Result := 0;
  FErrorMessage := '';
  PrepareSocket();
  FSocket.Address := FAddress;
  FSocket.Port := FPort;
  ErrCode := FSocket.Connect(FSocketTimeout);
  if ErrCode <> 0 then
  begin
    Result := ErrCode;
    DoTSPError(result);
    Exit;
  end;
  Result := CreateRequest(HashedData, Request);
  if Result <> 0 then
  begin
    DoTSPError(result);
    Exit;
  end;

  Len := Length(Request) + 1;
  SetLength(Buf, Len + 4);
  GetBytes32(Len, Buf, 0);
  Buf[4] := SB_FLAG_TSAMSG;
  SBMove(Request[0], Buf[5], Len - 1);
  Left := Len + 4;
  Ptr :=  @Buf[0] ;
  while Left > 0 do
  begin
    Result := FSocket.Send(Ptr, Left, {$ifdef SB_SILVERLIGHT_SOCKETS}SocketTimeout,  {$endif}Done);
    if Result <> 0 then
    begin
      DoTSPError(result);
      Exit;
    end;
    Inc(Ptr, Done);
    Dec(Left, Done);
  end;
  Ptr :=  @Buf[0] ;
  Left := 4;
  while Left > 0 do
  begin
    Result := FSocket.Receive(Ptr, 4, Done);
    if Result <> 0 then
    begin
      DoTSPError(result);
      Exit;
    end;
    Inc(Ptr, Done);
    Dec(Left, Done);
  end;
  Len := (Buf[0] shl 24) or (Buf[1] shl 16) or (Buf[2] shl 8) or Buf[3];
  if Len > 65535 then
  begin
    Result := SB_TSP_ERROR_DATA_TOO_LONG;
    DoTSPError(result);
    Exit;
  end;
  if Len < 1 then
  begin
    Result := SB_TSP_ERROR_UNRECOGNIZED_FORMAT;
    DoTSPError(result);
    Exit;
  end;
  SetLength(Buf, Len);
  Ptr :=  @Buf[0] ;
  Left := Len;
  while Left > 0 do
  begin
    Result := FSocket.Receive(Ptr, Len, Done);
    if Result <> 0 then
    begin
      DoTSPError(result);
      Exit;
    end;
    Inc(Ptr, Done);
    Dec(Left, Done);
  end;
  Flag := Buf[0];
  RespBuf := CloneArray(@Buf[1], Len - 1);
  if Flag = SB_FLAG_FINALMSGREP then
  begin
    // Buf contains TSPReply
    result := ProcessReply(RespBuf, ServerResult, FailureInfo, ReplyCMS);
    if Result = 0 then
      result := MatchTSPRequirements(HashedData);
  end
  else
  if Flag = SB_FLAG_ERRORMSGREP then
  begin
    FErrorMessage := StringOfBytes(RespBuf);
    Result := SB_TSP_ERROR_GENERAL_ERROR;
  end
  else
    Result := SB_TSP_ERROR_UNSUPPORTED_REPLY;

  if result <> 0 then
    DoTSPError(result);

end;


end.
