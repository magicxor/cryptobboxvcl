(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBGSSWinAuth;

interface

{$ifdef SB_GSSAPI}

uses
  SysUtils,
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBConstants,
  SBGSSAPIBase,
  SBGSSAPI,
  SBSSPI;



{$ifdef SB_WINDOWS_OR_NET}

type
  TElGSSWinAuthProtocols = set of ( apKerberos, apNTLM );

  TElGSSWinContext = class (TElGSSCustomContext)
  public
    CredHandle : CredHandle;
    Context : CtxtHandle;
    ContextHandle : PCtxtHandle;
    Expiry : TimeStamp;

    constructor Create();
  end;

  TElGSSWinName = class (TElGSSCustomName)
  public
    ServiceName : UnicodeString;
  end;

  TElGSSWinAuthMechanism = class (TElGSSBaseMechanism)
  private
    FUseUnicodeFuncs : Boolean;
    FKerberosMaxToken :  ULONG ;
    FNTLMMaxToken :  ULONG ;
    FAuthProtocols : TElGSSWinAuthProtocols;
    FAvailableProtocols : TElGSSWinAuthProtocols;
    FInitialized : Boolean;

    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure IndicateMechs;
    procedure IndicateMechsA;
    procedure IndicateMechsW;

    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure SetAuthProtocols(const Value: TElGSSWinAuthProtocols);
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function SetStatus(Major: LongWord; Minor: SECURITY_STATUS): LongWord;
    function ValidateSecurityFunctions: Boolean;
  protected
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure DoError(const Operation : string; MajorStatus, MinorStatus : LongWord;
      const MechOID : ByteArray); override;
  public
    constructor Create; override;

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

    property AuthProtocols: TElGSSWinAuthProtocols read FAuthProtocols write SetAuthProtocols;
  end;

{$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
 {$else}
var
 {$endif}

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS OFF}
 {$endif}

  GSS_MECH_NTLM : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = #$2B#$06#$01#$04#$82#$37#$02#$02#$0A {$endif}; 
  GSS_MECH_KRB5 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} = #$2A#$86#$48#$86#$F7#$12#$01#$02#$02 {$endif}; 

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS ON}
 {$endif}

 {$endif SB_WINDOWS_OR_NET}

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
  GSS_MECH_NTLM_STR = #$2B#$06#$01#$04#$82#$37#$02#$02#$0A;
  GSS_MECH_KRB5_STR = #$2A#$86#$48#$86#$F7#$12#$01#$02#$02;
{$ifdef SB_UNICODE_VCL}
  {$WARNINGS ON}
 {$endif}
 {$endif}
 {$endif}

{$ifdef SB_FPC_GEN}
implementation
 {$endif}

{$ifdef SB_GSSAPI}

{$ifdef SB_WINDOWS_OR_NET}

constructor TElGSSWinContext.Create();
begin
  inherited;

  Context.dwLower := Pointer(-1);
  Context.dwUpper := Pointer(-1);
  ContextHandle := nil;
  CredHandle.dwLower := Pointer(-1);
  CredHandle.dwUpper := Pointer(-1);
end;

{ TElGSSWinAuthMechanism }

function TElGSSWinAuthMechanism.AcceptSecContext(Ctx: TElGSSCustomContext;
  SourceName: TElGSSCustomName; const InputToken: ByteArray;
  var OutputToken: ByteArray): LongWord;
begin
  Result := SetStatus(GSS_S_FAILURE, SEC_E_UNSUPPORTED_FUNCTION);
  if FMajorStatus = GSS_S_FAILURE then
    DoError('AcceptSecContext', FMajorStatus, FMinorStatus, Ctx.MechOID);
end;

function TElGSSWinAuthMechanism.AcquireCred(const MechOID: ByteArray;
  var Ctx: TElGSSCustomContext): LongWord;
var
  WinCtx : TElGSSWinContext;
  PackageName : string;
  Status : SECURITY_STATUS;
  hCred : CredHandle;
  OID: ByteArray;
  ts : TimeStamp;
begin
  OID := MechOID;
  if CompareContent(OID, GSS_MECH_KRB5) then
    PackageName := 'Kerberos'
  else if CompareContent(OID, GSS_MECH_NTLM) then
    PackageName := 'NTLM'
  // 'Negotiate'
  else
  begin
    // check if mech hash is passed
    OID := GetMechOIDByHash(MechOID);
    if CompareContent(OID, GSS_MECH_KRB5) then
      PackageName := 'Kerberos'
    else if CompareContent(OID, GSS_MECH_NTLM) then
      PackageName := 'NTLM'
    else
    begin
      Result := SetStatus(GSS_S_BAD_MECH, SEC_E_SECPKG_NOT_FOUND);
      DoError('AcquireCredentialsHandle', FMajorStatus, FMinorStatus, OID);
      Exit;
    end;
  end;

  if not ValidateSecurityFunctions() then
  begin
    Result := FMajorStatus;
    Exit;
  end;

  if FUseUnicodeFuncs then
  begin
    Status := SecFuncsW.AcquireCredentialsHandleW(nil, PWideChar(UnicodeString(PackageName)),
      SECPKG_CRED_OUTBOUND, nil, nil, nil, nil, @hCred, @ts);
  end
  else
  begin
    Status := SecFuncsA.AcquireCredentialsHandleA(nil,
      {$ifndef SB_UNICODE_VCL}
      PAnsiChar(PackageName),
       {$else}
      PAnsiChar(AnsiString(PackageName)),
       {$endif}
      SECPKG_CRED_OUTBOUND, nil, nil, nil, nil, @hCred, @ts);
  end;

  if not SEC_SUCCESS(Status) then
  begin
    Result := SetStatus(GSS_S_FAILURE, Status);
    DoError('AcquireCredentialsHandle', FMajorStatus, FMinorStatus, OID);
    Exit;
  end;

  WinCtx := TElGSSWinContext.Create;
  WinCtx.MechOID := CloneArray(OID);
  WinCtx.RequestFlags := GSS_C_MUTUAL_FLAG or GSS_C_INTEG_FLAG;
  WinCtx.ResponseFlags := 0;
  WinCtx.CredHandle := hCred;
  WinCtx.Expiry := ts;
  Ctx := WinCtx;

  Result := SetStatus(GSS_S_COMPLETE, Status);
end;

constructor TElGSSWinAuthMechanism.Create;
begin
  inherited;
  FUseUnicodeFuncs := False;
  FAuthProtocols := [apKerberos, apNTLM];
  FInitialized := False;
end;

procedure TElGSSWinAuthMechanism.DoError(const Operation : string;
  MajorStatus, MinorStatus : LongWord; const MechOID : ByteArray);
var
  MajorErrorMsg, MinorErrorMsg : string;
begin
  if not Assigned(FOnError) then
    Exit;
  
  MajorErrorMsg := '';
  MinorErrorMsg := '';

  case MajorStatus of
    GSS_S_COMPLETE : MajorErrorMsg := 'GSS-API status OK';
    GSS_S_BAD_MECH : MajorErrorMsg := 'The specified mechanism is not supported, or is unrecognized by the implementation.'; 
    GSS_S_NO_CONTEXT : MajorErrorMsg := 'The context_handle did not refer to a valid context.';
  else // GSS_S_FAILURE
    MajorErrorMsg := 'Unspecified GSS failure. Minor code may provide more information';
  end;

  case HRESULT(MinorStatus) of
    SEC_E_OK : MinorErrorMsg := 'SSPI status OK';
    SEC_E_INSUFFICIENT_MEMORY : MinorErrorMsg := 'There is not enough memory available to complete the requested action.';
    SEC_E_INVALID_HANDLE : MinorErrorMsg := 'The handle passed to the function is not valid.';
    SEC_E_INVALID_TOKEN : MinorErrorMsg := 'The error is due to a malformed input token, such as a token corrupted in transit, a token of incorrect size, or a token passed into the wrong security package. ' +
      'Passing a token to the wrong package can happen if the client and server did not negotiate the proper security package.';
    SEC_E_LOGON_DENIED : MinorErrorMsg := 'The logon failed.';
    SEC_E_NO_AUTHENTICATING_AUTHORITY : MinorErrorMsg := 'No authority could be contacted for authentication. The domain name of the authenticating party could be wrong, the domain could be unreachable, or there might have been a trust relationship failure.';
    SEC_E_NO_CREDENTIALS : MinorErrorMsg := 'No credentials are available in the security package.';
    SEC_E_TARGET_UNKNOWN : MinorErrorMsg := 'The target was not recognized.';
    SEC_E_UNSUPPORTED_FUNCTION : MinorErrorMsg := 'A context attribute flag that is not valid (ISC_REQ_DELEGATE or ISC_REQ_PROMPT_FOR_CREDS) was specified in the fContextReq parameter.';
    SEC_E_WRONG_PRINCIPAL : MinorErrorMsg := 'The principal that received the authentication request is not the same as the one passed into the pszTargetName parameter. This indicates a failure in mutual authentication.';
  else
    MinorErrorMsg := 'An error occurred that did not map to an SSPI error code.';
  end;

  DoError(Operation, MajorStatus, MinorStatus, MajorErrorMsg, MinorErrorMsg);
end;

function TElGSSWinAuthMechanism.GetMIC(Ctx: TElGSSCustomContext;
  const MessageBuffer: ByteArray; var MessageToken: ByteArray): LongWord;
var
  WinCtx : TElGSSWinContext;
  ContextSizes : SecPkgContext_Sizes;
  InputDesc : SecBufferDesc;
  InputBuf : array [0..1] of SecBuffer;
  Status : SECURITY_STATUS;
begin
  SetLength(MessageToken, 0);
  if not (Ctx is TElGSSWinContext) then
  begin
    Result := SetStatus(GSS_S_NO_CONTEXT, SEC_E_INVALID_HANDLE);
    DoError('GetMIC', FMajorStatus, FMinorStatus, EmptyArray);
    Exit;
  end;

  if not ValidateSecurityFunctions() then
  begin
    Result := FMajorStatus;
    Exit;
  end;

  WinCtx := TElGSSWinContext(Ctx);
  FillChar(ContextSizes, 0, SizeOf(ContextSizes));
  if FUseUnicodeFuncs then
  begin
    Status := SecFuncsW.QueryContextAttributesW(@WinCtx.Context, SECPKG_ATTR_SIZES, @ContextSizes);
  end
  else
  begin
    Status := SecFuncsA.QueryContextAttributesA(@WinCtx.Context, SECPKG_ATTR_SIZES, @ContextSizes);
  end;

  if not SEC_SUCCESS(Status) or (ContextSizes.cbMaxSignature <= 0) then
  begin
    Result := SetStatus(GSS_S_FAILURE, Status);
    DoError('QueryContextAttributes', FMajorStatus, FMinorStatus, WinCtx.MechOID);
    Exit;
  end;

  with InputBuf[0] do
  begin
    BufferType := SECBUFFER_DATA;
    cbBuffer := Length(MessageBuffer);
    pvBuffer := @MessageBuffer[0];
  end;

  SetLength(MessageToken, ContextSizes.cbMaxSignature);
  with InputBuf[1] do
  begin
    BufferType := SECBUFFER_TOKEN;
    cbBuffer := ContextSizes.cbMaxSignature;
    pvBuffer := @MessageToken[0];
  end;

  with InputDesc do
  begin
    ulVersion := SECBUFFER_VERSION;
    cBuffers := 2;
    pBuffers := @InputBuf[0];
  end;

  if FUseUnicodeFuncs then
  begin
    Status := SecFuncsW.MakeSignature(@WinCtx.Context, 0, @InputDesc, 0);
  end
  else
  begin
    Status := SecFuncsA.MakeSignature(@WinCtx.Context, 0, @InputDesc, 0);
  end;

  SetLength(MessageToken, InputBuf[1].cbBuffer);

  if not SEC_SUCCESS(Status) then
  begin
    Result := SetStatus(GSS_S_FAILURE, Status);
    DoError('MakeSignature', FMajorStatus, FMinorStatus, WinCtx.MechOID);
    Exit;
  end;

  Result := SetStatus(GSS_S_COMPLETE, Status);
end;

function TElGSSWinAuthMechanism.ImportName(const MechOID: ByteArray; const InputName: string;
  var OutputName: TElGSSCustomName): LongWord;
var
  OID : ByteArray;
begin
  if not IsMechSupported(MechOID) then
  begin
    Result := SetStatus(GSS_S_BAD_MECH, SEC_E_SECPKG_NOT_FOUND);
    DoError('ImportName', FMajorStatus, FMinorStatus, MechOID);
    Exit;
  end;

  OID := GetMechOIDByHash(MechOID);
  if Length(OID) = 0 then
    OID := MechOID;

  if Length(InputName) = 0 then
  begin
    Result := SetStatus(GSS_S_FAILURE, 0);
    DoError('ImportName', FMajorStatus, FMinorStatus, OID);
    Exit;
  end;

  OutputName := TElGSSWinName.Create;
  OutputName.MechOID := CloneArray(OID);
  // copy it into form host/FQDN
  if StringIndexOf(InputName, '/') < StringStartOffset then
    TElGSSWinName(OutputName).ServiceName := 'host/' + InputName
  else
    TElGSSWinName(OutputName).ServiceName := InputName;

  Result := SetStatus(GSS_S_COMPLETE, 0);
end;

procedure TElGSSWinAuthMechanism.IndicateMechs;
begin
  FMechOIDs.Clear;
  FMechHashes.Clear;
  FAvailableProtocols := [];
  if not ValidateSecurityFunctions() then
    Exit;

  if FUseUnicodeFuncs then
    IndicateMechsW
  else
    IndicateMechsA;
end;

procedure TElGSSWinAuthMechanism.IndicateMechsA;
type
  ASecPkgInfoA = array[0..0] of SecPkgInfoA;
  PASecPkgInfoA = ^ASecPkgInfoA;
var
  pPkgInfo : PSecPkgInfoA;
  PkgInfo : PASecPkgInfoA;
  cPkgs : ULONG;
  Status : SECURITY_STATUS;
  i: Integer;
begin
  Status := SecFuncsA.EnumerateSecurityPackagesA(@cPkgs, @pPkgInfo);
  FMinorStatus := LongWord(Status);
  if not SEC_SUCCESS(Status) then
  begin
    FMajorStatus := GSS_S_FAILURE;
    DoError('EnumerateSecurityPackages', FMajorStatus, FMinorStatus, EmptyArray);
    Exit;
  end;

  PkgInfo := PASecPkgInfoA(pPkgInfo);
  for i := 1 to cPkgs do
  begin
    if AnsiString(PkgInfo[i - 1].Name) = 'NTLM' then
    begin
      Include(FAvailableProtocols, apNTLM);
      FNTLMMaxToken := PkgInfo[i - 1].cbMaxToken;
      if apNTLM in FAuthProtocols then
        FMechOIDs.Add(GSS_MECH_NTLM);
    end
    else if AnsiString(PkgInfo[i - 1].Name) = 'Kerberos' then
    begin
      Include(FAvailableProtocols, apKerberos);
      FKerberosMaxToken := PkgInfo[i - 1].cbMaxToken;
      if apKerberos in FAuthProtocols then
        FMechOIDs.Add(GSS_MECH_KRB5);
    end;
  end;

  Status := SecFuncsA.FreeContextBuffer(pPkgInfo);
  if not SEC_SUCCESS(Status) then
  begin
    SetStatus(GSS_S_FAILURE, Status);
    DoError('FreeContextBuffer', FMajorStatus, FMinorStatus, EmptyArray);
    Exit;
  end;

  FMajorStatus := GSS_S_COMPLETE;
end;

procedure TElGSSWinAuthMechanism.IndicateMechsW;
type
  ASecPkgInfoW = array[0..0] of SecPkgInfoW;
  PASecPkgInfoW = ^ASecPkgInfoW;
var
  pPkgInfo : PSecPkgInfoW;
  PkgInfo : PASecPkgInfoW;
  cPkgs : ULONG;
  Status : SECURITY_STATUS;
  i: Integer;
begin
  Status := SecFuncsW.EnumerateSecurityPackagesW(@cPkgs, @pPkgInfo);
  FMinorStatus := LongWord(Status);
  if not SEC_SUCCESS(Status) then
  begin
    FMajorStatus := GSS_S_FAILURE;
    DoError('EnumerateSecurityPackages', FMajorStatus, FMinorStatus, EmptyArray);
    Exit;
  end;

  PkgInfo := PASecPkgInfoW(pPkgInfo);
  for i := 1 to cPkgs do
  begin
    if UnicodeString(PkgInfo[i - 1].Name) = 'NTLM' then
    begin
      Include(FAvailableProtocols, apNTLM);
      FNTLMMaxToken := PkgInfo[i - 1].cbMaxToken;
      if apNTLM in FAuthProtocols then
        FMechOIDs.Add(GSS_MECH_NTLM);
    end
    else if UnicodeString(PkgInfo[i - 1].Name) = 'Kerberos' then
    begin
      Include(FAvailableProtocols, apKerberos);
      FKerberosMaxToken := PkgInfo[i - 1].cbMaxToken;
      if apKerberos in FAuthProtocols then
        FMechOIDs.Add(GSS_MECH_KRB5);
    end;
  end;

  Status := SecFuncsW.FreeContextBuffer(pPkgInfo);
  if not SEC_SUCCESS(Status) then
  begin
    SetStatus(GSS_S_FAILURE, Status);
    DoError('FreeContextBuffer', FMajorStatus, FMinorStatus, EmptyArray);
    Exit;
  end;

  FMajorStatus := GSS_S_COMPLETE;
end;

function TElGSSWinAuthMechanism.Initialize : Boolean;
begin
  Result := True;
  if FInitialized then
    Exit;

  try
    SBSSPI.Initialize;
  except
    Result := False;
    Exit;
  end;

  if Assigned(SecFuncsW) then
    FUseUnicodeFuncs := True
  else if Assigned(SecFuncsA) then
    FUseUnicodeFuncs := False
  else
    Result := False;

  if Result then
  begin
    IndicateMechs;
    if SEC_SUCCESS(FMajorStatus) then
      FInitialized := True;
  end;
end;

function TElGSSWinAuthMechanism.InitSecContext(Ctx: TElGSSCustomContext;
  TargetName: TElGSSCustomName; DelegateCred: Boolean;
  const InputToken : ByteArray; var OutputToken: ByteArray): LongWord;
var
  WinCtx : TElGSSWinContext;
  TargetWinName : TElGSSWinName;
  AName : AnsiString;
  InputDesc, OutputDesc : SecBufferDesc;
  InputBuf, OutputBuf : SecBuffer;
  pInputDesc : PSecBufferDesc;
  Status : SECURITY_STATUS;
  ContextReq, ContextAttr : ULONG;
begin
  SetLength(OutputToken, 0);
  if not (Ctx is TElGSSWinContext) or not (TargetName is TElGSSWinName) then
  begin
    Result := SetStatus(GSS_S_NO_CONTEXT, SEC_E_INVALID_HANDLE);
    DoError('InitSecContext', FMajorStatus, FMinorStatus, EmptyArray);
    Exit;
  end;

  if not ValidateSecurityFunctions() then
  begin
    Result := FMajorStatus;
    Exit;
  end;

  WinCtx := TElGSSWinContext(Ctx);
  TargetWinName := TElGSSWinName(TargetName);

  ContextAttr := 0;
  ContextReq := ISC_REQ_ALLOCATE_MEMORY or ISC_REQ_CONFIDENTIALITY;
  if (WinCtx.RequestFlags and GSS_C_INTEG_FLAG) > 0 then
    ContextReq := ContextReq or ISC_REQ_INTEGRITY;
  if (WinCtx.RequestFlags and GSS_C_MUTUAL_FLAG) > 0 then
    ContextReq := ContextReq or ISC_REQ_MUTUAL_AUTH;
  if DelegateCred then
    ContextReq := ContextReq or ISC_REQ_DELEGATE;

  if Length(InputToken) > 0 then
  begin
    with InputBuf do
    begin
      BufferType := SECBUFFER_TOKEN;
      cbBuffer := Length(InputToken);
      pvBuffer := @InputToken[0];
    end;

    with InputDesc do
    begin
      ulVersion := SECBUFFER_VERSION;
      cBuffers := 1;
      pBuffers := @InputBuf;
    end;

    pInputDesc := @InputDesc;
  end
  else
    pInputDesc := nil;

  with OutputBuf do
  begin
    BufferType := SECBUFFER_TOKEN;
    cbBuffer := 0;
    pvBuffer := nil;
  end;

  with OutputDesc do
  begin
    ulVersion := SECBUFFER_VERSION;
    cBuffers := 1;
    pBuffers := @OutputBuf;
  end;

  if FUseUnicodeFuncs then
  begin
    Status := SecFuncsW.InitializeSecurityContextW(@WinCtx.CredHandle, WinCtx.ContextHandle, PWideChar(TargetWinName.ServiceName),
      ContextReq, 0, SECURITY_NATIVE_DREP {SECURITY_NETWORK_DREP},
      pInputDesc, 0, @WinCtx.Context, @OutputDesc, @ContextAttr, @WinCtx.Expiry);
  end
  else
  begin
    AName := AnsiString(TargetWinName.ServiceName);
    Status := SecFuncsA^.InitializeSecurityContextA(@WinCtx.CredHandle, WinCtx.ContextHandle,
      PAnsiChar(AName), ContextReq, 0, SECURITY_NATIVE_DREP,
      pInputDesc, 0, @WinCtx.Context, @OutputDesc, @ContextAttr, @WinCtx.Expiry);
  end;


  if not SEC_SUCCESS(Status) then
  begin
    Result := SetStatus(GSS_S_FAILURE, Status);
    DoError('InitializeSecurityContext', FMajorStatus, FMinorStatus, WinCtx.MechOID);
    Exit;
  end;

  FMinorStatus := LongWord(Status);
  if Status = SEC_E_OK then
    FMajorStatus := GSS_S_COMPLETE
  else if Status = SEC_I_CONTINUE_NEEDED then
    FMajorStatus := GSS_S_CONTINUE_NEEDED
  else
    FMajorStatus := GSS_S_FAILURE;

  WinCtx.ContextHandle := @WinCtx.Context;
  WinCtx.ResponseFlags := 0;
  if (ISC_RET_INTEGRITY and ContextAttr) > 0 then
    WinCtx.ResponseFlags := WinCtx.ResponseFlags or GSS_C_INTEG_FLAG;
  if (ISC_REQ_MUTUAL_AUTH and ContextAttr) > 0 then
    WinCtx.ResponseFlags := WinCtx.ResponseFlags or GSS_C_MUTUAL_FLAG;

  SetLength(OutputToken, OutputBuf.cbBuffer);
  SBMove(OutputBuf.pvBuffer^, OutputToken[0], OutputBuf.cbBuffer);

  if FUseUnicodeFuncs then
    Status := SecFuncsW.FreeContextBuffer(OutputBuf.pvBuffer)
  else
    Status := SecFuncsA.FreeContextBuffer(OutputBuf.pvBuffer);

  if not SEC_SUCCESS(Status) then
  begin
    Result := SetStatus(GSS_S_FAILURE, Status);
    DoError('FreeContextBuffer', FMajorStatus, FMinorStatus, WinCtx.MechOID);
    Exit;
  end;

  Result := FMajorStatus;
end;

function TElGSSWinAuthMechanism.ReleaseContext(var Ctx: TElGSSCustomContext): LongWord;
var
  WinCtx : TElGSSWinContext;
  Status : SECURITY_STATUS;
begin
  if not (Ctx is TElGSSWinContext) then
  begin
    Result := SetStatus(GSS_S_FAILURE, SEC_E_INVALID_HANDLE);
    DoError('ReleaseContext', FMajorStatus, FMinorStatus, EmptyArray);
    Exit;
  end;

  if not ValidateSecurityFunctions() then
  begin
    Result := FMajorStatus;
    Exit;
  end;

  WinCtx := TElGSSWinContext(Ctx);
  Status := SEC_E_OK;
  if FUseUnicodeFuncs then
  begin
    if SecIsValidHandleInt(WinCtx.CredHandle) then
    begin
      Status := SecFuncsW.FreeCredentialsHandle(@WinCtx.CredHandle);
      if not SEC_SUCCESS(Status) then
        DoError('FreeCredentialsHandle', GSS_S_FAILURE, Status, WinCtx.MechOID);
    end;

    if SecIsValidHandleInt(WinCtx.Context) then
    begin
      Status := SecFuncsW.DeleteSecurityContext(@WinCtx.Context);
      if not SEC_SUCCESS(Status) then
        DoError('DeleteSecurityContext', GSS_S_FAILURE, Status, WinCtx.MechOID);
    end;
  end
  else
  begin
    if SecIsValidHandleInt(WinCtx.CredHandle) then
    begin
      Status := SecFuncsA.FreeCredentialsHandle(@WinCtx.CredHandle);
      if not SEC_SUCCESS(Status) then
        DoError('FreeCredentialsHandle', GSS_S_FAILURE, Status, WinCtx.MechOID);
    end;

    if SecIsValidHandleInt(WinCtx.Context) then
    begin
      Status := SecFuncsA.DeleteSecurityContext(@WinCtx.Context);
      if not SEC_SUCCESS(Status) then
        DoError('DeleteSecurityContext', GSS_S_FAILURE, Status, WinCtx.MechOID);
    end;
  end;

  FreeAndNil(Ctx);
  if not SEC_SUCCESS(Status) then
    Result := SetStatus(GSS_S_FAILURE, 0)
  else
    Result := SetStatus(GSS_S_COMPLETE, 0);
end;

function TElGSSWinAuthMechanism.ReleaseName(var Name: TElGSSCustomName): LongWord;
begin
  if not Assigned(Name) then
    Result := SetStatus(GSS_S_FAILURE, 0)
  else
  begin
    FreeAndNil(Name);
    Result := SetStatus(GSS_S_COMPLETE, 0);
  end;
end;

procedure TElGSSWinAuthMechanism.SetAuthProtocols(const Value: TElGSSWinAuthProtocols);
begin
  if FAuthProtocols = Value then
    Exit;

  FAuthProtocols := Value;
  FMechOIDs.Clear;
  FMechHashes.Clear;
  if (apNTLM in FAuthProtocols) and (apNTLM in FAvailableProtocols) then
    FMechOIDs.Add(GSS_MECH_NTLM);

  if (apKerberos in FAuthProtocols) and (apKerberos in FAvailableProtocols) then
    FMechOIDs.Add(GSS_MECH_KRB5);
end;

function TElGSSWinAuthMechanism.SetStatus(Major: LongWord; Minor: SECURITY_STATUS): LongWord;
begin
  FMajorStatus := Major;
  FMinorStatus := LongWord(Minor);
  Result := FMajorStatus;
end;

function TElGSSWinAuthMechanism.ValidateSecurityFunctions: Boolean;
begin
  Result := True;
  if FUseUnicodeFuncs then
  begin
    if not Assigned(SecFuncsW) or
       not Assigned(SecFuncsW.AcquireCredentialsHandleW) or
       not Assigned(SecFuncsW.EnumerateSecurityPackagesW) or
       not Assigned(SecFuncsW.InitializeSecurityContextW) or
       not Assigned(SecFuncsW.DeleteSecurityContext) or
       not Assigned(SecFuncsW.FreeContextBuffer) or
       not Assigned(SecFuncsW.FreeCredentialsHandle) or
       not Assigned(SecFuncsW.MakeSignature) or
       not Assigned(SecFuncsW.VerifySignature) or
       not Assigned(SecFuncsW.QueryContextAttributesW) then
    begin
      SetStatus(GSS_S_FAILURE, SEC_E_UNSUPPORTED_FUNCTION);
      DoError('ValidateFunctions', FMajorStatus, FMinorStatus, EmptyArray);
      Result := False;
    end;
  end
  else
  begin
    if not Assigned(SecFuncsA) or
       not Assigned(SecFuncsA.AcquireCredentialsHandleA) or
       not Assigned(SecFuncsA.EnumerateSecurityPackagesA) or
       not Assigned(SecFuncsA.InitializeSecurityContextA) or
       not Assigned(SecFuncsA.DeleteSecurityContext) or
       not Assigned(SecFuncsA.FreeContextBuffer) or
       not Assigned(SecFuncsA.FreeCredentialsHandle) or
       not Assigned(SecFuncsA.MakeSignature) or
       not Assigned(SecFuncsA.VerifySignature) or
       not Assigned(SecFuncsA.QueryContextAttributesA) then
    begin
      SetStatus(GSS_S_FAILURE, SEC_E_UNSUPPORTED_FUNCTION);
      DoError('ValidateFunctions', FMajorStatus, FMinorStatus, EmptyArray);
      Result := False;
    end;
  end;
end;

function TElGSSWinAuthMechanism.VerifyMIC(Ctx: TElGSSCustomContext;
  const MessageBuffer, MessageToken: ByteArray): LongWord;
var
  WinCtx : TElGSSWinContext;
  InputDesc : SecBufferDesc;
  InputBuf : array [0..1] of SecBuffer;
  Status : SECURITY_STATUS;
begin
  if not (Ctx is TElGSSWinContext) then
  begin
    Result := SetStatus(GSS_S_NO_CONTEXT, SEC_E_INVALID_HANDLE);
    DoError('VerifyMIC', FMajorStatus, FMinorStatus, EmptyArray);
    Exit;
  end;

  if not ValidateSecurityFunctions() then
  begin
    Result := FMajorStatus;
    Exit;
  end;

  WinCtx := TElGSSWinContext(Ctx);
  with InputBuf[0] do
  begin
    BufferType := SECBUFFER_DATA;
    cbBuffer := Length(MessageBuffer);
    pvBuffer := @MessageBuffer[0];
  end;

  with InputBuf[1] do
  begin
    BufferType := SECBUFFER_TOKEN;
    cbBuffer := Length(MessageToken);
    pvBuffer := @MessageToken[0];
  end;

  with InputDesc do
  begin
    ulVersion := SECBUFFER_VERSION;
    cBuffers := 2;
    pBuffers := @InputBuf[0];
  end;

  if FUseUnicodeFuncs then
  begin
    Status := SecFuncsW.VerifySignature(@WinCtx.Context, @InputDesc, 0, nil);
  end
  else
  begin
    Status := SecFuncsA.VerifySignature(@WinCtx.Context, @InputDesc, 0, nil);
  end;

  if SEC_SUCCESS(Status) then
    Result := SetStatus(GSS_S_COMPLETE, Status)
  else
  begin
    Result := SetStatus(GSS_S_FAILURE, Status);
    DoError('VerifySignature', FMajorStatus, FMinorStatus, WinCtx.MechOID);
  end;
end;


initialization

  {$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
  GSS_MECH_NTLM := CreateByteArrayConst( GSS_MECH_NTLM_STR );
  GSS_MECH_KRB5 := CreateByteArrayConst( GSS_MECH_KRB5_STR );
   {$endif}


 {$endif SB_WINDOWS_OR_NET}

 {$endif SB_GSSAPI}

end.
