(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2010 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBSASL;

interface

uses
  SBStringList,

  Classes,
  {$ifdef SB_NTLM_SUPPORT}
  SBHTTPAuth,
   {$endif}
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBRandom,
  SBHashFunction,
  SBConstants,
  SBHTTPSConstants,
  SBEncoding;

type

  TSBSASLSecurityLevel =  (saslAuthOnly, saslAuthIntegrity, saslAuthConfidentiality);

  TSBSASLChallengeEvent =  procedure (Options: TElStringList) of object;
  TSBSASLGetValueEvent =  procedure (const Name: string;
    out Value: string) of object;

  EElSASLError = class(ESecureBlackboxError);

  // ==================================================================
  //  Base class for all SASL client mechanisms
  //
  //  Usage (in pseudo code):
  //  1. Create an appropriate mechanism object
  //      Client := CreateSASLClient(SB_SASL_MECHANISM_PLAIN);
  //     or
  //      Client := CreateSASLClient([SB_SASL_MECAHNISM_CRAM_MD5, SB_SASL_MECHANISM_PLAIN]);
  //
  //  2. Setup the client with
  //      a) property values (note that value names are case insensitive)
  //          Client['UserName'] := 'user';
  //          Client['Password'] := 'secret';
  //     or/and
  //      b) event handler
  //          Client.OnGetValue := GetSASLValueHandler;
  //
  //  3. Initialize challenge/response buffers
  //      SetLength(Challenge, 0);
  //      SetLength(Response, 0);
  //
  //     Call ProcessChallenge method to get an initial response if applicable to the mechanism
  //      Client.ProcessChallenge(Challenge, Response);
  //
  //  4. Request authorization dialog and get the first (and possibly the last) challenge
  //      Protocol.RequestAuth(Client.MechanismName, Response);
  //      ProtocolStatus := Protocol.ReceiveChallenge(Challenge);
  //
  //  5. Proceed the loop until SASL dialog is complete
  //      while not Client.Complete and (ProtocolStatus <> FAILURE) do
  //      begin
  //        try
  //          Client.ProcessChallenge(Challenge, Response);
  //        except
  //          Protocol.SendAuthError();
  //          Break;
  //        end;
  //        if ProtocolStatus = CONTINUE then
  //        begin
  //          Protocol.SendAuthResponse(Response);
  //          Status := Protocol.ReceiveChallenge(Challenge);
  //        end
  //        else
  //          if Length(Response) > 0 then
  //            raise Exception('Attempt to send a sasl response after completion or on failure');
  //      end;
  //
  //      if ProtocolStatus = SUCCESS then
  //        // authentication succeeded
  //
  //  6. Check SecurityLevel property value to get to know whether WrapData/UnwrapData methods
  //     have to be used to send/receive data
  //
  //      if Client.SecurityLevel > saslAuthOnly then
  //        Client.WrapData(Data, OutData)
  //      else
  //        OutData := Data;
  //      Protocol.SendData(OutData);
  //
  //      Protocol.ReceiveData(InData);
  //      if Client.SecurityLevel > saslAuthOnly then
  //        Client.UnwrapData(InData, Data)
  //      else
  //        Data := InData;

  TElSASLClient =  class
   private 
    FValues: TElStringList;
    FOnChallenge: TSBSASLChallengeEvent;
    FOnGetValue: TSBSASLGetValueEvent;
    function GetValue(Name: string): string;
    procedure SetValue(Name: string; const NewValue: string);
  protected
    // Calls OnChallenge event handler if assigned
    procedure DoChallenge(Options: TElStringList); virtual;
    // Must return True when no additional data is expected anymore
    function GetComplete: Boolean; virtual; abstract;
    // Must return IANA registered mechanism name
    // See http://www.iana.org/assignments/sasl-mechanisms for additional info
    function GetMechanismName: string; virtual; abstract;
    // By default the method returns saslAuthOnly. Must be overriden if the
    // mechanism can provide other security levels.
    function GetSecurityLevel: TSBSASLSecurityLevel; virtual;
    // Fires OnGetValue event to get value with the specified name.
    // Returns True if event handler is assigned and False otherwise.
    function RequestValue(const Name: string; out OutValue: string): Boolean;  overload;  virtual;
    // Checks if value with the specified name exists. If so, just returns it. If not,
    // calls RequestValue to fire OnGetValue event. Returns an empty string if there is no
    // value exists and no event handler assigned.
    function RequestValue(const Name: string): string;  overload;  virtual;
  public
    constructor Create; virtual;
     destructor  Destroy; override;
    procedure ProcessChallenge(const Challenge: ByteArray; out Response: ByteArray); virtual; abstract;
    function ValueExists(const Name: string): Boolean; virtual;
    function WrapData(InData: Pointer; InSize: Integer; OutData: Pointer; var OutSize: Integer): Boolean; overload; virtual;
    function UnwrapData(InData: Pointer; InSize: Integer; OutData: Pointer; var OutSize: Integer): Boolean; overload; virtual;
    function WrapData(const InData: ByteArray; InStartIndex, InSize: Integer;
      var OutData: ByteArray; OutStartIndex: Integer; var OutSize: Integer): Boolean;  overload;  virtual;
    function UnwrapData(const InData: ByteArray; InStartIndex, InSize: Integer;
      var OutData: ByteArray; OutStartIndex: Integer; var OutSize: Integer): Boolean;  overload;  virtual;
    property Complete: Boolean read GetComplete;
    property MechanismName: string read GetMechanismName;
    property SecurityLevel: TSBSASLSecurityLevel read GetSecurityLevel;
    property Value[Name: string]: string read GetValue write SetValue; default;
    // The event is fired when a server challenge is parsed and there is a need to
    // process the challenge options and possibly make some choices (this is mechanism dependent)
    property OnChallenge: TSBSASLChallengeEvent read FOnChallenge write FOnChallenge;
    // The event is fired when the class needs some value that is not specified in Value property
    property OnGetValue: TSBSASLGetValueEvent read FOnGetValue write FOnGetValue;
  end;

  // ==================================================================
  //  PLAIN SASL Mechanism (RFC 2595 + 4616)
  //
  //  Flow:
  //    C: [request] + #0 + username + #0 + password
  //    S: [result]
  //
  //  Values:
  //    UserName - text
  //    Password - text

  TElSASLPlainClient =  class(TElSASLClient)
   private 
    FComplete: Boolean;
    function GetPassword: string;
    function GetUserName: string;
    procedure SetPassword(const AValue: string);
    procedure SetUserName(const AValue: string);
  protected
    function GetComplete: Boolean; override;
    function GetMechanismName: string; override;
  public
    constructor Create; override;
    procedure ProcessChallenge(const Challenge: ByteArray; out Response: ByteArray); override;
    property Password: string read GetPassword write SetPassword;
    property UserName: string read GetUserName write SetUserName;
  end;

  // ==================================================================
  //  LOGIN SASL Mechanism (MS-XLOGIN)
  //
  //  Flow:
  //    C: [request]
  //    S: [continue]
  //    C: Base64(username)
  //    S: [continue]
  //    C: Base64(password)
  //    S: [result]
  //
  //  Values:
  //    UserName - text
  //    Password - text

  TElSASLLoginClient =  class(TElSASLClient)
   private 
    FStep: Integer;
    function GetPassword: string;
    function GetUserName: string;
    procedure SetPassword(const AValue: string);
    procedure SetUserName(const AValue: string);
  protected
    function GetComplete: Boolean; override;
    function GetMechanismName: string; override;
  public
    constructor Create; override;
    procedure ProcessChallenge(const Challenge: ByteArray; out Response: ByteArray); override;
    property Password: string read GetPassword write SetPassword;
    property UserName: string read GetUserName write SetUserName;
  end;

  // ==================================================================
  //  CRAM-MD5 SASL Mechanism (RFC 2195)
  //
  //  Flow:
  //    C: [request]
  //    S: [challenge]
  //    C: username+#32+MACMD5(challenge, password)
  //    S: [result]
  //
  //  Values:
  //    UserName - text
  //    Password - text

  TElSASLCRAMMD5Client =  class(TElSASLClient)
   private 
    FStep: Integer;
    function GetPassword: string;
    function GetUserName: string;
    procedure SetPassword(const AValue: string);
    procedure SetUserName(const AValue: string);
  protected
    function GetComplete: Boolean; override;
    function GetMechanismName: string; override;
  public
    constructor Create; override;
    procedure ProcessChallenge(const Challenge: ByteArray; out Response: ByteArray); override;
    property Password: string read GetPassword write SetPassword;
    property UserName: string read GetUserName write SetUserName;
  end;

  // ==================================================================
  //  ANONYMOUS SASL Mechanism (RFC 4505)
  //
  //  Flow:
  //    C: [request]
  //    S: [empty challenge]
  //    C: authid
  //    S: [result]
  //
  //  Values:
  //    AuthID - text (an Internet email address, or an opaque string
  //                   that does not contain the '@' (U+0040) character)

  TElSASLAnonymousClient =  class(TElSASLClient)
   private 
    FStep: Integer;
    function GetAuthID: string;
    procedure SetAuthID(const AValue: string);
  protected
    function GetComplete: Boolean; override;
    function GetMechanismName: string; override;
  public
    constructor Create; override;
    procedure ProcessChallenge(const Challenge: ByteArray; out Response: ByteArray); override;
    property AuthID: string read GetAuthID write SetAuthID;
  end;

  // ==================================================================
  //  EXTERNAL SASL Mechanism (RFC 4422)
  //
  //  Flow:
  //    C: [request]
  //    S: [empty challenge]
  //    C: [empty response]
  //    S: [result]
  //  or
  //    C: [request] + authid
  //    S: [result]
  //
  //  Values:
  //    AuthID - text

  TElSASLExternalClient =  class(TElSASLClient)
   private 
    FComplete: Boolean;
    FStep: Integer;
    function GetAuthID: string;
    procedure SetAuthID(const AValue: string);
  protected
    function GetComplete: Boolean; override;
    function GetMechanismName: string; override;
  public
    constructor Create; override;
    procedure ProcessChallenge(const Challenge: ByteArray; out Response: ByteArray); override;
    property AuthID: string read GetAuthID write SetAuthID;
  end;

  // ==================================================================
  //  DIGEST-MD5 SASL Mechanism (RFC 2831)
  //
  //  This mechanism supports reauthentication. To do this, call
  //  ProcessChallenge after completion of initial authentication
  //  (when Complete is True).
  //
  //  Flow (initial authentication):
  //    C: [request]
  //    S: [challenge]
  //    C: [response]
  //    S: [result]
  //  Flow (subsequent authentication):
  //    C: [request] + [response]
  //    S: [challenge] | [result]
  //

  TElSASLDigestMD5Client =  class(TElSASLClient)
   private 
    FStep : Integer;
    FMore : boolean;
    FReqMethod : integer;
    FSNonce : string;
    FCNonce : string;
    FCNonceCount : integer;
    FCRequest : string;
    FUUEncodeData : boolean;
    FCached : ByteArray;

    function ParseParamsLine(const Params:string):TElList;
    function GetParamsPos(const ParamName:string; var Params:TElList):integer;
    procedure ClearList(var List: TElList);

    function GetPassword: string;
    function GetUserName: string;
    function GetURI: string;
    procedure SetPassword(const AValue: string);
    procedure SetUserName(const AValue: string);
    procedure SetURI(const AValue: string);
  protected
    function GetComplete: Boolean; override;
    function GetMechanismName: string; override;
  public
    constructor Create; override;
     destructor  Destroy; override;

    procedure ProcessChallenge(const Challenge: ByteArray; out Response: ByteArray); override;

    property Password: string read GetPassword write SetPassword;
    property UserName: string read GetUserName write SetUserName;
    property RequestURI: string read GetURI write SetURI;
    property RequestMethod: integer read FReqMethod write FReqMethod;
    property CustomRequestMethod: string read FCRequest write FCRequest;
  end;

// ==================================================================
//  NTLM SASL Mechanism (RFC 1734)
//
//  Flow:
//    C: [Base64(type_1_message)]
//    S: [Base64(type_2_challenge)]
//    C: [Base64(type_3_response)]
//
//  Values:
//    UserName - text
//    Password - text

{$ifdef SB_NTLM_SUPPORT}

  TElSASLNTLMClient =  class(TElSASLClient)
   private 
    FASeq : AUTH_SEQ;
    FStep : Integer;
    FMore : boolean;
    function GetPassword: string;
    function GetUserName: string;
    procedure SetPassword(const AValue: string);
    procedure SetUserName(const AValue: string);
  protected
    function GetComplete: Boolean; override;
    function GetMechanismName: string; override;
  public
    constructor Create; override;
     destructor  Destroy; override;
    procedure ProcessChallenge(const Challenge: ByteArray; out Response: ByteArray); override;
    property Password: string read GetPassword write SetPassword;
    property UserName: string read GetUserName write SetUserName;
  end;

 {$endif}

// Creates a SASL client object for the given mechanism.
// Returns nil if the mechanism is not supported.
function CreateSASLClient(const Mechanism: string): TElSASLClient;  overload; 
// Creates a SASL client object for the first supported mechanism in the given mechanism list.
// Returns nil if none of the mechanisms is supported.
function CreateSASLClient(const Mechanisms: StringArray): TElSASLClient;  overload; 

const
  SB_SASL_MECHANISM_PLAIN = 'PLAIN';
  SB_SASL_MECHANISM_LOGIN = 'LOGIN';
  SB_SASL_MECHANISM_CRAM_MD5 = 'CRAM-MD5';
  SB_SASL_MECHANISM_EXTERNAL = 'EXTERNAL';
  SB_SASL_MECHANISM_ANONYMOUS = 'ANONYMOUS';
  SB_SASL_MECHANISM_DIGEST_MD5 = 'DIGEST-MD5';
  SB_SASL_MECHANISM_NTLM = 'NTLM';
  SB_SASL_MECHANISM_GSSAPI = 'GSSAPI';

const
  SB_SASL_ERROR_BASE                           = $BA50;
  SB_SASL_CRAM_ERROR_EMPTY_CHALLENGE           = SB_SASL_ERROR_BASE + 1;
  SB_SASL_CRAM_ERROR_INVALID_CHALLENGE         = SB_SASL_ERROR_BASE + 2;
  SB_SASL_DIGEST_ERROR_INVALID_CHALLENGE       = SB_SASL_ERROR_BASE + 3;
  SB_SASL_DIGEST_ERROR_INVALID_REALM           = SB_SASL_ERROR_BASE + 4;
  SB_SASL_DIGEST_ERROR_PARAMETER_NOT_SPECIFIED = SB_SASL_ERROR_BASE + 5;

implementation

uses
  SysUtils,
  SBHMAC;

resourcestring
  SEmptyValueName = 'Value name cannot be empty';

  SEmptyChallenge = 'Server challenge cannot be empty';
  SInvalidChallenge = 'Server challenge is invalid';
  SRepeatedQuotation = 'Repeated quotations not allowed';

  SDigestMD5RealmError = 'Server not contain user specified realm';

  SDuplicateName = 'Duplicate name: %s';
  SDigestMD5NoRequiredParameter = 'Required parameter not specified: %s';
  SDigestMD5InvalidServerParameter = 'Invalid server parameter: %s';

const
  SB_SASL_DIGEST_MD5_NONCE = 'nonce';
  SB_SASL_DIGEST_MD5_REALM = 'realm';
  SB_SASL_DIGEST_MD5_QOP = 'qop';
  SB_SASL_DIGEST_MD5_QOP_AUTH = 'auth';
  SB_SASL_DIGEST_MD5_QOP_AUTH_INT = 'auth-int';
  SB_SASL_DIGEST_MD5_QOP_AUTH_CONF = 'auth-conf';
  SB_SASL_DIGEST_MD5_STALE = 'stale';
  SB_SASL_DIGEST_MD5_MAXBUF = 'maxbuf';
  SB_SASL_DIGEST_MD5_CHARSET = 'charset';
  SB_SASL_DIGEST_MD5_CHARSET_UTF8 = 'utf-8';
  SB_SASL_DIGEST_MD5_ALGORITHM = 'algorithm';
  SB_SASL_DIGEST_MD5_ALGORITHM_MD5_SESS = 'md5-sess';
  SB_SASL_DIGEST_MD5_CIPHER = 'cipher';
  SB_SASL_DIGEST_MD5_CIPHER_3DES = '3des';
  SB_SASL_DIGEST_MD5_CIPHER_DES = 'des';
  SB_SASL_DIGEST_MD5_CIPHER_RC4_40 = 'rc4-40';
  SB_SASL_DIGEST_MD5_CIPHER_RC4 = 'rc4';
  SB_SASL_DIGEST_MD5_CIPHER_RC4_56 = 'rc4-56';
  SB_SASL_DIGEST_MD5_AUTH_PARAM = 'auth-param';
  SB_SASL_DIGEST_MD5_USERNAME = 'username';
  SB_SASL_DIGEST_MD5_PASSWORD = 'password';
  SB_SASL_DIGEST_MD5_CNONCE = 'cnonce';
  SB_SASL_DIGEST_MD5_NC = 'nc';
  SB_SASL_DIGEST_MD5_DIGEST_URI = 'digest-uri';
  SB_SASL_DIGEST_MD5_SERV_TYPE = 'serv-type';
  SB_SASL_DIGEST_MD5_HOST = 'host';
  SB_SASL_DIGEST_MD5_SERV_NAME = 'serv-name';
  SB_SASL_DIGEST_MD5_RESPONSE = 'response';
  SB_SASL_DIGEST_MD5_AUTHZID = 'authzid';
  SB_SASL_DIGEST_MD5_RESPONSE_AUTH = 'rspauth';


function CreateSASLClient(const Mechanism: string): TElSASLClient;
var Mech : string;
begin
  Result := nil;
  
  Mech := UpperCase(Mechanism);

  if Mech = SB_SASL_MECHANISM_PLAIN then
    Result := TElSASLPlainClient.Create
  else
  if Mech = SB_SASL_MECHANISM_LOGIN then
    Result := TElSASLLoginClient.Create
  else
  if Mech = SB_SASL_MECHANISM_CRAM_MD5 then
    Result := TElSASLCRAMMD5Client.Create
// Not Tested and temporary disabled
//  else
//  if Mech = SB_SASL_MECHANISM_ANONYMOUS then
//    Result := TElSASLAnonymousClient.Create
//  else
//  if Mech = SB_SASL_MECHANISM_EXTERNAL then
//    Result := TElSASLExternalClient.Create
  else
  if Mech = SB_SASL_MECHANISM_DIGEST_MD5 then
    Result := TElSASLDigestMD5Client.Create
{$ifdef SB_NTLM_SUPPORT}
  else
  if Mech = SB_SASL_MECHANISM_NTLM then
    Result := TElSASLNTLMClient.Create
 {$endif}
  ;
end;

function CreateSASLClient(const Mechanisms: StringArray): TElSASLClient;
var
  I: Integer;
begin
  Result := nil;
  for I := 0 to Length(Mechanisms) - 1 do
  begin
    Result := CreateSASLClient(Mechanisms[I]);
    if Result <> nil then
      Exit;
  end;
end;

{ TElSASLClient }

constructor TElSASLClient.Create;
begin
  inherited;
  FValues := TElStringList.Create;
  TStringList(FValues).Sorted := False;
end;

 destructor  TElSASLClient.Destroy;
begin
  FreeAndNil(FValues);
  inherited;
end;

procedure TElSASLClient.DoChallenge(Options: TElStringList);
begin
  if Assigned(FOnChallenge) then
    FOnChallenge(Options);
end;

function TElSASLClient.GetSecurityLevel: TSBSASLSecurityLevel;
begin
  Result := saslAuthOnly;
end;

function TElSASLClient.GetValue(Name: string): string;
begin
  if Length(Name) = 0 then
    raise Exception.Create(SEmptyValueName);
  Result := FValues.Values[LowerCase(Name)];
end;

function TElSASLClient.RequestValue(const Name: string): string;
begin
  Result := '';
{  if not ValueExists(Name) then
    RequestValue(Name, Result);  was}
  if ValueExists(Name) then
    Result := FValues.Values[LowerCase(Name)];
end;

function TElSASLClient.RequestValue(const Name: string; out OutValue: string): Boolean;
begin
  OutValue := '';
  Result := Assigned(FOnGetValue);
  if Result then
    FOnGetValue(Name, OutValue);
end;

procedure TElSASLClient.SetValue(Name: string; const NewValue: string);
begin
  if Length(Name) = 0 then
    raise Exception.Create(SEmptyValueName);
  FValues.Values[LowerCase(Name)] := NewValue;
end;

function TElSASLClient.UnwrapData(const InData: ByteArray; InStartIndex, InSize: Integer;
  var OutData: ByteArray; OutStartIndex: Integer; var OutSize: Integer): Boolean;
begin
  Result := (OutSize >= InSize) and (OutStartIndex + OutSize <= Length(OutData));
  if Result then
    SBMove(InData[InStartIndex], OutData[OutStartIndex], InSize);
  OutSize := InSize;
end;

function TElSASLClient.UnwrapData(InData: Pointer; InSize: Integer; OutData: Pointer;
  var OutSize: Integer): Boolean;
begin
  Result := (OutData <> nil) and (OutSize >= InSize);
  if Result then
    SBMove(InData^, OutData^, InSize);
  OutSize := InSize;
end;

function TElSASLClient.ValueExists(const Name: string): Boolean;
begin
  if Length(Name) = 0 then
    raise Exception.Create(SEmptyValueName);
  Result := (FValues.IndexOfName(LowerCase(Name)) >= 0);
end;

function TElSASLClient.WrapData(const InData: ByteArray; InStartIndex, InSize: Integer;
  var OutData: ByteArray; OutStartIndex: Integer; var OutSize: Integer): Boolean;
begin
  Result := (OutSize >= InSize) and (OutStartIndex + OutSize <= Length(OutData));
  if Result then
    SBMove(InData[InStartIndex], OutData[OutStartIndex], InSize);
  OutSize := InSize;
end;

function TElSASLClient.WrapData(InData: Pointer; InSize: Integer; OutData: Pointer;
  var OutSize: Integer): Boolean;
begin
  Result := (OutData <> nil) and (OutSize >= InSize);
  if Result then
    SBMove(InData^, OutData^, InSize);
  OutSize := InSize;
end;

{ TElSASLPlainClient }

constructor TElSASLPlainClient.Create;
begin
  inherited;
  FComplete := False;
end;

function TElSASLPlainClient.GetComplete: Boolean;
begin
  Result := FComplete;
end;

function TElSASLPlainClient.GetMechanismName: string;
begin
  Result := SB_SASL_MECHANISM_PLAIN;
end;

function TElSASLPlainClient.GetPassword: string;
begin
  Result := Value['Password'];
end;

function TElSASLPlainClient.GetUserName: string;
begin
  Result := Value['UserName'];
end;

procedure TElSASLPlainClient.ProcessChallenge(const Challenge: ByteArray; out Response: ByteArray);
var
  AUserName, APassword: ByteArray;
  Index, Size: Integer;
begin
  AUserName := EmptyArray;
  APassword := EmptyArray;
  if not FComplete then
  begin
    AUserName := BytesOfString(RequestValue('UserName'));
    APassword := BytesOfString(RequestValue('Password'));

    SetLength(Response, Length(AUserName) + Length(APassword) + 2);
    Index := 0;
    Response[Index] := 0;
    Inc(Index);
    Size := Length(AUserName);
    if Size > 0 then
    begin
      SBMove(AUserName[0], Response[Index], Size);
      Inc(Index, Size);
    end;
    Response[Index] := 0;
    Inc(Index);
    Size := Length(APassword);
    if Size > 0 then
      SBMove(APassword[0], Response[Index], Size);

    FComplete := True; // no additional data expected
  end
  else
    SetLength(Response, 0);
end;

procedure TElSASLPlainClient.SetPassword(const AValue: string);
begin
  Value['Password'] := AValue;
end;

procedure TElSASLPlainClient.SetUserName(const AValue: string);
begin
  Value['UserName'] := AValue;
end;

{ TElSASLLoginClient }

constructor TElSASLLoginClient.Create;
begin
  inherited;
  FStep := 0;
end;

function TElSASLLoginClient.GetComplete: Boolean;
begin
  Result := (FStep > 2);
end;

function TElSASLLoginClient.GetMechanismName: string;
begin
  Result := SB_SASL_MECHANISM_LOGIN;
end;

function TElSASLLoginClient.GetPassword: string;
begin
  Result := Value['Password'];
end;

function TElSASLLoginClient.GetUserName: string;
begin
  Result := Value['UserName'];
end;

procedure TElSASLLoginClient.ProcessChallenge(const Challenge: ByteArray; out Response: ByteArray);
var
  Buffer: ByteArray;
begin
  SetLength(Response, 0);
  SetLength(Buffer, 0);
  case FStep of
    0:  // this mechanism does not provide an initial response
        Inc(FStep);
    1:  // send username
        begin
          Response := BytesOfString(RequestValue('UserName'));
          Inc(FStep);
        end;
    2:  // send password
        begin
          Response := BytesOfString(RequestValue('Password'));
          Inc(FStep);
        end;
  end;
end;

procedure TElSASLLoginClient.SetPassword(const AValue: string);
begin
  Value['Password'] := AValue;
end;

procedure TElSASLLoginClient.SetUserName(const AValue: string);
begin
  Value['UserName'] := AValue;
end;

{ TElSASLCRAMMD5Client }

constructor TElSASLCRAMMD5Client.Create;
begin
  inherited;
  FStep := 0;
end;

function TElSASLCRAMMD5Client.GetComplete: Boolean;
begin
  Result := (FStep > 1);
end;

function TElSASLCRAMMD5Client.GetMechanismName: string;
begin
  Result := SB_SASL_MECHANISM_CRAM_MD5;
end;

function TElSASLCRAMMD5Client.GetPassword: string;
begin
  Result := Value['Password'];
end;

function TElSASLCRAMMD5Client.GetUserName: string;
begin
  Result := Value['UserName'];
end;

procedure TElSASLCRAMMD5Client.ProcessChallenge(const Challenge: ByteArray; out Response: ByteArray);
var
  Buffer: ByteArray;
  Size, Index: Integer;
  Digest: TMessageDigest128;
  Temp: ByteArray;
  Pass: string;
begin
  SetLength(Response, 0);
  SetLength(Temp, 0);
  case FStep of
    0:  // this mechanism does not provide an initial response
        Inc(FStep);
    1:  // decode the challenge and prepare the response
        begin
          if Length(Challenge) = 0 then
            raise EElSASLError.Create(SEmptyChallenge, SB_SASL_CRAM_ERROR_EMPTY_CHALLENGE);
          // hash the timestamp with the password
          Pass := StringOfBytes(Challenge);
          Buffer := BytesOfString(RequestValue('Password'));
          Digest := HashMACMD5(Challenge, Length(Challenge), Buffer);

          // concatenate username and the digest
          Temp := BytesOfString(RequestValue('UserName'));
          SetLength(Response, Length(Temp) + 33); // + 1 + SizeOf(Digest) * 2 (as it's to be base16 encoded)
          Index := 0;
          Size := Length(Temp);
          if Size > 0 then
          begin
            SBMove(Temp[0], Response[Index], Size);
            Inc(Index, Size);
          end;
          Response[Index] := 32;  // 'SPACE' character
          Inc(Index);
          Temp := BytesOfString(DigestToStr(Digest));
          SBMove(Temp[0], Response[Index], Length(Temp));
          Pass := StringOfBytes(Response);
          Inc(FStep);
        end;
  end; // case
end;

procedure TElSASLCRAMMD5Client.SetPassword(const AValue: string);
begin
  Value['Password'] := AValue;
end;

procedure TElSASLCRAMMD5Client.SetUserName(const AValue: string);
begin
  Value['UserName'] := AValue;
end;

{ TElSASLAnonymousClient }

constructor TElSASLAnonymousClient.Create;
begin
  inherited;
  FStep := 0;
end;

function TElSASLAnonymousClient.GetAuthID: string;
begin
  Result := Value['AuthID'];
end;

function TElSASLAnonymousClient.GetComplete: Boolean;
begin
  Result := (FStep > 1);
end;

function TElSASLAnonymousClient.GetMechanismName: string;
begin
  Result := SB_SASL_MECHANISM_ANONYMOUS;
end;

procedure TElSASLAnonymousClient.ProcessChallenge(const Challenge: ByteArray; out Response: ByteArray);
var
  Buffer: ByteArray;
  Size: Integer;
begin
  SetLength(Response, 0);
  case FStep of
    0:  // this mechanism does not provide an initial response
        Inc(FStep);
    1:  // send authid
        begin
          Buffer := StrToUTF8(RequestValue('AuthID'));
          Size := Length(Buffer);
          if Size > 0 then
          begin
            SetLength(Response, Size);
            SBMove(Buffer[0], Response[0], Size);
          end;
          Inc(FStep);
        end;
  end;
end;

procedure TElSASLAnonymousClient.SetAuthID(const AValue: string);
begin
  Value['AuthID'] := AValue;
end;

{ TElSASLExternalClient }

constructor TElSASLExternalClient.Create;
begin
  inherited;
  FComplete := False;
  FStep := 0;
end;

function TElSASLExternalClient.GetAuthID: string;
begin
  Result := Value['AuthID'];
end;

function TElSASLExternalClient.GetComplete: Boolean;
begin
  Result := FComplete;
end;

function TElSASLExternalClient.GetMechanismName: string;
begin
  Result := SB_SASL_MECHANISM_EXTERNAL;
end;

procedure TElSASLExternalClient.ProcessChallenge(const Challenge: ByteArray; out Response: ByteArray);
var
  ID: string;
  Buffer: ByteArray;
  Size: Integer;
begin
  SetLength(Response, 0);
  case FStep of
    0:  // if authid value is available, produce an initial response
        begin
          ID := RequestValue('AuthID');
          if Length(ID) > 0 then
          begin
            Buffer := StrToUTF8(ID);
            Size := Length(Buffer);
            if Size > 0 then
            begin
              SetLength(Response, Size);
              SBMove(Buffer[0], Response[0], Size);
            end;
            FComplete := True;
          end;
          Inc(FStep);
        end;
    1:  // there is no authid available; just send an empty response
        begin
          Inc(FStep);
          FComplete := True;
        end;
  end;
end;

procedure TElSASLExternalClient.SetAuthID(const AValue: string);
begin
  Value['AuthID'] := AValue;
end;

{ TElSASLDigestMD5Client }

constructor TElSASLDigestMD5Client.Create;
begin
  inherited;
  FStep := 0;
  FMore := true;
  FReqMethod := SB_HTTP_REQUEST_GET;
  FCNonce := '';
  FSNonce := '';
  FCNonceCount := 0;
  FUUEncodeData := false;
  FCRequest := '';
  FCached := EmptyArray;
end;

 destructor  TElSASLDigestMD5Client.Destroy;
begin
  inherited;
end;

function TElSASLDigestMD5Client.GetComplete: Boolean;
begin
  Result := (FStep >= 1) and (not FMore);
end;

function TElSASLDigestMD5Client.GetMechanismName: string;
begin
  Result := SB_SASL_MECHANISM_DIGEST_MD5;
end;

function TElSASLDigestMD5Client.GetPassword: string;
begin
  Result := Value['Password'];
end;

function TElSASLDigestMD5Client.GetUserName: string;
begin
  Result := Value['UserName'];
end;

function TElSASLDigestMD5Client.GetURI: string;
begin
  Result := Value['URI'];
end;

procedure TElSASLDigestMD5Client.SetPassword(const AValue: string);
begin
  Value['Password'] := AValue;
end;

procedure TElSASLDigestMD5Client.SetUserName(const AValue: string);
begin
  Value['UserName'] := AValue;
end;

procedure TElSASLDigestMD5Client.SetURI(const AValue: string);
begin
  Value['URI'] := AValue;
end;

{ TElSASLDigestMD5Client utility classes and functions }

type
  ParamRecord = class
    Name : string;
    Value : string;
  end;


function TElSASLDigestMD5Client.GetParamsPos(const ParamName: string;
  var Params: TElList): Integer;
var
  I: Integer;
begin
  I := 0;
  while (I < Params.Count) and
    (LowerCase(ParamRecord(Params .Items [I]).Name) <> LowerCase(ParamName))
    do
    Inc(I);
  if I = Params.Count then
    I := -1;
  Result := I;
end;

// TODO: test the code in VCL, .NET, Java and Delphi Mobile to ensure that parameters are passed correctly (pay attention to string indexes)
function TElSASLDigestMD5Client.ParseParamsLine(const Params: string): TElList;
var
  Res: TElList;
  CurPar: string;
  Param: ParamRecord;
  Tokenizer : TElStringTokenizer;
  //i : integer;
  P, V : string;
begin
  Res := TElList.Create;
  Tokenizer := TElStringTokenizer.Create;
  try
    Tokenizer.ReturnEmptyTokens := false;
    Tokenizer.Delimiters := ',';
    Tokenizer.SourceString := Params;
    while Tokenizer.GetNext(CurPar) do
    begin
      if StringSplitPV(CurPar, P, V) then
      begin
        Param := ParamRecord.Create;
        Param.Name := StringTrim(P);
        Param.Value := StringTrim(V);

        if (Length(Param.Value) >= 3) and
          (Param.Value[StringStartOffset] = '"') and
          (Param.Value[Length(Param.Value) - StringStartInvOffset] = '"')
        then
          Param.Value := StringSubstring(Param.Value, StringStartOffset + 1, Length(Param.Value) - 2);

        Res.Add(Param);
      end;
    end;
  finally
    FreeAndNil(Tokenizer);
  end;
  Result := Res;
end;

procedure TElSASLDigestMD5Client.ClearList(var List: TElList);
var
  I: Integer;
  Item: ParamRecord;
begin
  if List = nil then
    Exit;
  for I := 0 to List.Count - 1 do
  begin
    Item := List[I];
    if Item <> nil then
    begin
      SetLength(Item.Name, 0);
      SetLength(Item.Value, 0);
      FreeAndNil(Item);
    end;
  end;
  FreeAndNil(List);
end;


{ end TElSASLDigestMD5Client utility classes and functions }

procedure TElSASLDigestMD5Client.ProcessChallenge(const Challenge: ByteArray; out Response: ByteArray);
var
  Buf: ByteArray;
  ServerData: TElList;
  I: Integer;
  SChallenge: string;
  TmpBuff: String;
  TmpStr, TmpStr1, TmpStr2: String;
  HasQOP: string;
  A1: String;
  A2: String;
  Resp: String;

  HashFunc:  TElHashFunction ;
begin
  if Length(FCached) > 0 then
  begin
    Response := SBCopy(FCached);
    Exit;
  end;

  SChallenge := StringOfBytes(Challenge);
  ServerData := ParseParamsLine(SChallenge);
  TmpBuff := 'username="' + UserName + '", ';

  try

    I := GetParamsPos('realm', ServerData);
    if I = -1 then
      Exit;
    TmpBuff := TmpBuff + 'realm="' + ParamRecord(ServerData.Items[I])
      .Value + '", ';

    I := GetParamsPos('nonce', ServerData);
    if I = -1 then
      Exit;
    TmpBuff := TmpBuff + 'nonce="' + ParamRecord(ServerData.Items[I])
      .Value + '", ';
    if (FSNonce <> ParamRecord(ServerData.Items[I]).Value) then
    begin
      FSNonce := ParamRecord(ServerData.Items[I]).Value;
      FCNonceCount := 1;
      SetLength(Buf, 4);
      SBRndGenerate(@Buf[0], 4);
      FCNonce := LowerCase(BinaryToString(Buf));

      FCNonce := PrefixString(FCNonce, 8 - Length(FCNonce), '0');
    end
    else
      Inc(FCNonceCount);

    TmpBuff := TmpBuff + 'uri="' + RequestURI + '", ';

    I := GetParamsPos('opaque', ServerData);
    if I >= 0 then
    begin
      TmpBuff := TmpBuff + 'opaque="' + ParamRecord(ServerData.Items[I])
        .Value + '", ';
    end;

    I := GetParamsPos('qop', ServerData);
    HasQOP := '';
    if I <> -1 then
    begin
      if StringIndexOf(ParamRecord(ServerData.Items[I]).Value + ',', 'auth,') >= StringStartOffset then
        HasQOP := 'auth'
      else
      if StringIndexOf(ParamRecord(ServerData.Items[I]).Value, ',') >= StringStartOffset then
        HasQOP := StringSubstring(ParamRecord(ServerData.Items[I]).Value, 1,
          StringIndexOf(ParamRecord(ServerData.Items[I]).Value, ',') - 1)
      else
        HasQOP := ParamRecord(ServerData.Items[I]).Value;
    end;

    HashFunc :=
     TElHashFunction .Create(SB_ALGORITHM_DGST_MD5);
    try
      HashFunc.Reset;

      I := GetParamsPos('realm', ServerData);
      TmpStr := UserName + ':' + ParamRecord(ServerData.Items[I]).Value + ':'
        + Password;
      HashFunc.Update({$ifndef SB_UNICODE_VCL}@TmpStr
        [StringStartOffset] {$else}@BytesOfString(TmpStr)[0] {$endif},
        Length(TmpStr));
      A1 := LowerCase(BinaryToString(HashFunc.Finish()));

      I := GetParamsPos('algorithm', ServerData);
      if (I <> -1) and (LowerCase(ParamRecord(ServerData.Items[I]).Value)
        = 'md5-sess') then
      begin
        TmpBuff := TmpBuff + 'algorithm="' + ParamRecord(ServerData.Items[I])
          .Value + '", ';
        I := GetParamsPos('nonce', ServerData);
        A1 := A1 + ':' + ParamRecord(ServerData.Items[I]).Value + ':'
          + FCNonce;

        HashFunc.Reset;
        HashFunc.Update({$ifndef SB_UNICODE_VCL}@A1[StringStartOffset] {$else}@BytesOfString(A1)
          [0] {$endif}, Length(A1));

        // TODO: EM - check correctness of use of BinaryToString!
        A1 := LowerCase(BinaryToString(HashFunc.Finish()));
      end;

      HashFunc.Reset;

      if RequestMethod <> SB_HTTP_REQUEST_CUSTOM then
        TmpStr := HTTPCommandStrings[RequestMethod] + ':' + RequestURI
      else
        TmpStr := FCRequest + ':' + RequestURI;

      if (LowerCase(HasQOP) = 'auth-int') then
      begin
        // A2       = Method ":" digest-uri-value ":" H(entity-body)
      end;
      HashFunc.Update(BytesOfString(TmpStr));
      // TODO: EM - check correctness of use of BinaryToString!
      A2 := LowerCase(BinaryToString(HashFunc.Finish()));

      HashFunc.Reset;
      TmpStr := ':';
      HashFunc.Update(BytesOfString(A1));
      HashFunc.Update(BytesOfString(TmpStr));
      I := GetParamsPos('nonce', ServerData);
      HashFunc.Update(BytesOfString(ParamRecord(ServerData.Items[I]).Value));

      HashFunc.Update(BytesOfString(TmpStr));

      if HasQOP <> '' then
      begin
        TmpStr2 := IntToStr(FCNonceCount);
        TmpStr1 := PrefixString(TmpStr2, 8 - Length(TmpStr2), '0');
        HashFunc.Update(BytesOfString(TmpStr1));
        HashFunc.Update(BytesOfString(TmpStr));
        HashFunc.Update(BytesOfString(FCNonce));
        HashFunc.Update(BytesOfString(TmpStr));
        HashFunc.Update(BytesOfString(HasQOP));
        HashFunc.Update(BytesOfString(TmpStr));

        TmpBuff := TmpBuff + 'qop=' + HasQOP + ', cnonce="' + FCNonce + '", nc='
          + TmpStr1 + ', ';
      end;

      HashFunc.Update(BytesOfString(A2));
      Resp := LowerCase(BinaryToString(HashFunc.Finish()));
    finally
      FreeAndNil(HashFunc);
    end;
  finally
    ClearList(ServerData);
  end;

  TmpBuff := TmpBuff + 'response="' + Resp + '"';

  Response := BytesOfString(TmpBuff);
  FCached := SBCopy(Response);
  FMore := False;
  Inc(FStep);
end;

{$ifdef SB_NTLM_SUPPORT}
{ TElSASLNTLMClient }

constructor TElSASLNTLMClient.Create;
begin
  inherited;
  FStep := 0;
  FMore := True;

  FillChar(FASeq, sizeof(FASeq), 0);
  AuthInit( @ FASeq);
  FASeq.UUEncodeData := False;
end;

  destructor  TElSASLNTLMClient.Destroy;
begin
  AuthTerm( @ FASeq);
  inherited;
end;

function TElSASLNTLMClient.GetComplete: Boolean;
begin
  Result := (FStep > 2) or (not FMore);
end;

function TElSASLNTLMClient.GetMechanismName: string;
begin
  Result := SB_SASL_MECHANISM_NTLM;
end;

function TElSASLNTLMClient.GetPassword: string;
begin
  Result := Value['Password'];
end;

function TElSASLNTLMClient.GetUserName: string;
begin
  Result := Value['UserName'];
end;

procedure TElSASLNTLMClient.ProcessChallenge(const Challenge: ByteArray;
  out Response: ByteArray);
begin
  AuthConverse( @ FASeq, Challenge, Response,
    FMore, cNTLM, GetUserName, GetPassword);
  Inc(FStep);
end;

procedure TElSASLNTLMClient.SetPassword(const AValue: string);
begin
  Value['Password'] := AValue;
end;

procedure TElSASLNTLMClient.SetUserName(const AValue: string);
begin
  Value['UserName'] := AValue;
end;

 {$endif} // SB_NTLM_SUPPORT

end.
