(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBHTTPAuth;

interface

{$ifdef SB_HAS_HTTPAUTH}

uses
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBEncoding,
  SBHashFunction,
  SBConstants,
  SBHTTPSConstants,
  SBRandom,
  Classes,
  {$ifdef WIN32}
  Windows,
   {$endif}
  SysUtils
  ;

type PPointer = ^Pointer;
type PInteger = ^Integer;
type PLongWord = ^LongWord;
//function AddAuthorizationHeader(var Str : string; Scheme : string; AuthData : string;
//  UserName : string; Password : string; var NeedMoreData : boolean; ForProxy: boolean):boolean;
//  forward;



const
  cAuth  : string = 'Authorization: ';
  cAuth2 : string = 'authorization: ';
  cPAuth : string = 'Proxy-Authorization: ';
  cPAuth2: string = 'proxy-authorization: ';
  cBasic : string = 'basic';
  cNTLM  : string = 'NTLM';
  cDigest  : string = 'Digest';

  //nMAX_STRING_LEN : Integer = 1024;

var
  secInit : boolean  =  false; // daca pachetul pornit

{$ifdef BUILDER_USED}
{$HPPEMIT '#define SECURITY_WIN32'}
{$HPPEMIT '#include <sspi.h>'}
 {$endif}

type
  {$ifdef SB_NTLM_SUPPORT}

  {$ifdef VCL50}
  {$EXTERNALSYM CredHandle}
   {$endif}
  CredHandle = record
    dwLower : ^LongWord;
    dwUpper : ^LongWord;
  end;
  {$ifdef VCL50}
  {$EXTERNALSYM CtxtHandle}
   {$endif}
  CtxtHandle  = CredHandle;
  {$ifdef VCL50}
  {$EXTERNALSYM PCredHandle}
   {$endif}
  PCredHandle = ^CredHandle;
  {$ifdef VCL50}
  {$EXTERNALSYM PCtxtHandle}
   {$endif}
  PCtxtHandle = ^CtxtHandle;


  {$ifdef VCL50}
  {$EXTERNALSYM SecBuffer}
   {$endif}
  SecBuffer = record
    cbBuffer   : LongWord;           // Size of the buffer, in bytes
    BufferType : LongWord;           // Type of the buffer (below)
    pvBuffer   : pointer;            // Pointer to the buffer
  end;
  {$ifdef VCL50}
  {$EXTERNALSYM PSecBuffer}
   {$endif}
  PSecBuffer = ^SecBuffer;


  {$ifdef VCL50}
  {$EXTERNALSYM SecBufferDesc}
   {$endif}
  SecBufferDesc = record
    ulVersion : LongWord;            // Version number
    cBuffers  : LongWord;            // Number of buffers
    pBuffers  : PSecBuffer;          // Pointer to array of buffers
  end;


  {$ifdef VCL50}
  {$EXTERNALSYM PSecBufferDesc}
   {$endif}
  PSecBufferDesc = ^SecBufferDesc;
  pint64 = ^int64;

  {$ifdef VCL50}
  {$EXTERNALSYM SecPkgInfo}
   {$endif}
  SecPkgInfo = record
    fCapabilities : LongWord;        // Capability bitmask
    wVersion      : Word;            // Version of driver
    wRPCID        : Word;            // ID for RPC Runtime
    cbMaxToken    : LongWord;        // Size of authentication token (max)
    Name          : PAnsiChar;           // Text name
    Comment       : PAnsiChar;           // Comment
  end;
  {$ifdef VCL50}
  {$EXTERNALSYM PSecPkgInfo}
   {$endif}
  PSecPkgInfo = ^SecPkgInfo;

  {$ifdef VCL50}
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY}
   {$endif}
  SEC_WINNT_AUTH_IDENTITY = record
    User           : PAnsiChar;
    UserLength     : LongWord;
    Domain         : PAnsiChar;
    DomainLength   : LongWord;
    Password       : PAnsiChar;
    PasswordLength : LongWord;
    Flags          : LongWord;
  end;
  PSEC_WINNT_AUTH_IDENTITY = ^SEC_WINNT_AUTH_IDENTITY;
   {$endif}

  AUTH_SEQ = record
    {$ifdef SB_NTLM_SUPPORT}
    NewConversation : boolean;
    hcred           : CredHandle;
    HaveCredHandle  : boolean;
    MaxToken        : LongWord;
    HaveCtxtHandle  : boolean;
    hctxt           : CredHandle;
    AuthIdentity    : SEC_WINNT_AUTH_IDENTITY;
     {$endif}
    UUEncodeData    : boolean;
    RequestURI      : string;
    RequestMethod   : integer;
    sNonce          : string;
    cNonce          : string;
    cNonceCount     : integer;
    cRequest        : string;
  end;
  PAUTH_SEQ = ^AUTH_SEQ;



  {$ifdef SB_NTLM_SUPPORT}
  SEC_GET_KEY_FN = procedure (Arg : pointer; Principal : pointer; KeyVer : LongWord;
    Key : ppointer; Status : PInteger); stdcall;

  FREE_CREDENTIALS_HANDLE_FN     = function (cred : PCredHandle):Integer; stdcall;
  ACQUIRE_CREDENTIALS_HANDLE_FN  = function (p1 : PAnsiChar; p2 : PAnsiChar; p3 : LongWord;
    p4 : pointer; p5 : pointer; p6 : SEC_GET_KEY_FN; p7 : pointer; p8 : PCredHandle;
    p9 : pint64):Integer; stdcall;
  QUERY_SECURITY_PACKAGE_INFO_FN = function (p1 : PAnsiChar; p2 : PSecPkgInfo):Integer; stdcall;
  FREE_CONTEXT_BUFFER_FN         = function (buf : pointer):Integer; stdcall;
  INITIALIZE_SECURITY_CONTEXT_FN = function (p1 : PCredHandle; p2 : PCtxtHandle; p3 : PAnsiChar;
    p4 : LongWord; p5 : LongWord; p6 : LongWord; p7 : PSecBufferDesc; p8 : LongWord;
    p9 : PCtxtHandle; p10 : PSecBufferDesc; p11 : PLongWord; p12 : pint64):Integer; stdcall;
  COMPLETE_AUTH_TOKEN_FN         = function (p1 : PCtxtHandle; p2 : PSecBufferDesc):Integer; stdcall;
  ENUMERATE_SECURITY_PACKAGES_FN = function (p1 : PLongWord; p2 : PSecPkgInfo):Integer; stdcall;
  DELETE_SECURITY_CONTEXT_FN     = function (ctx : PCtxtHandle):Integer; stdcall;


  secFuncs = record
    FreeCredentialsHandle     : FREE_CREDENTIALS_HANDLE_FN;
    AcquireCredentialsHandleA  : ACQUIRE_CREDENTIALS_HANDLE_FN;
    QuerySecurityPackageInfoA  : QUERY_SECURITY_PACKAGE_INFO_FN;
    FreeContextBuffer         : FREE_CONTEXT_BUFFER_FN;
    InitializeSecurityContextA : INITIALIZE_SECURITY_CONTEXT_FN;
    CompleteAuthToken         : COMPLETE_AUTH_TOKEN_FN;
    EnumerateSecurityPackagesA : ENUMERATE_SECURITY_PACKAGES_FN;
    DeleteSecurityContext     : DELETE_SECURITY_CONTEXT_FN;
  end;
   {$endif}



const

  {$ifdef VCL50}
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_ANSI}
   {$endif}
  SEC_WINNT_AUTH_IDENTITY_ANSI    = 1;

  {$ifdef VCL50}
  {$EXTERNALSYM SEC_WINNT_AUTH_IDENTITY_UNICODE}
   {$endif}
  SEC_WINNT_AUTH_IDENTITY_UNICODE = 2;

  {$ifdef VCL50}
  {$EXTERNALSYM SECPKG_CRED_OUTBOUND}
   {$endif}
  SECPKG_CRED_OUTBOUND            = 2;

  {$ifdef VCL50}
  {$EXTERNALSYM SECBUFFER_TOKEN}
   {$endif}
  SECBUFFER_TOKEN                 = 2;

  TOKEN_SOURCE_NAME       :  PAnsiChar  = 'InetSvcs';

  {$ifdef VCL50}
  {$EXTERNALSYM SECURITY_NATIVE_DREP}
   {$endif}
  SECURITY_NATIVE_DREP            = $10;

  {$ifdef VCL50}
  {$EXTERNALSYM SEC_I_CONTINUE_NEEDED}
   {$endif}
  SEC_I_CONTINUE_NEEDED           = $90312;

  {$ifdef VCL50}
  {$EXTERNALSYM SEC_I_COMPLETE_NEEDED}
   {$endif}
  SEC_I_COMPLETE_NEEDED           = $90313;

  {$ifdef VCL50}
  {$EXTERNALSYM SEC_I_COMPLETE_AND_CONTINUE}
   {$endif}
  SEC_I_COMPLETE_AND_CONTINUE     = $90314;


procedure AuthInit(pAS : PAUTH_SEQ);
procedure AuthTerm(pAS : PAUTH_SEQ);

function AuthConverse(pAS : PAUTH_SEQ; const BuffIn : ByteArray; out BuffOut : ByteArray;
  var NeedMoreData : boolean; Package : string; User : string; const Password : string) : boolean;


{$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
[SecuritySafeCritical]
 {$endif}
function AddAuthorizationHeader(var Str : string; const Scheme : string; const AuthData : string;
  const UserName : string; const Password : string; var NeedMoreData : TSBBoolean; ForProxy: boolean;  aSeq : PAUTH_SEQ  ):boolean;

{$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
[SecuritySafeCritical]
 {$endif}
procedure ValidateSecPacks(ls : TElStringList);

{$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
[SecuritySafeCritical]
 {$endif}
procedure InitAuthLib;

 {$endif SB_HAS_HTTPAUTH}

implementation

{$ifdef SB_HAS_HTTPAUTH}

uses SBSASL;

(*
{$ifndef SB_VCL}
const
  {$ifndef NET_CF}
  securitydll = 'security.dll';
  {$else}
  securitydll = 'secur32.dll';
  {$endif}
  systemdll = 'system.dll';
{$endif}
*)

{$ifdef SB_NTLM_SUPPORT}
var
  secLib  : HMODULE;
  sfProcs : secFuncs;
 {$endif}

(*
{$ifndef SB_VCL}
  [DllImport(securitydll, CharSet {$ifndef SB_NET}={$else}:={$endif} CharSet.Auto, SetLastError {$ifndef SB_NET}={$else}:={$endif} True, EntryPoint {$ifndef SB_NET}={$else}:={$endif} 'FreeCredentialsHandle')]
  function sfProcsFreeCredentialsHandle(cred : IntPtr):Integer; external;

  [DllImport(securitydll, CharSet {$ifndef SB_NET}={$else}:={$endif} CharSet.Auto, SetLastError {$ifndef SB_NET}={$else}:={$endif} True, EntryPoint {$ifndef SB_NET}={$else}:={$endif} {$ifndef NET_CF}'QuerySecurityPackageInfoA'{$else}'QuerySecurityPackageInfo'{$endif})]
  function sfProcsQuerySecurityPackageInfoA(p1 : IntPtr; var p2 : IntPtr):Integer; external;

  [DllImport(securitydll, CharSet {$ifndef SB_NET}={$else}:={$endif} CharSet.Auto, SetLastError {$ifndef SB_NET}={$else}:={$endif} True, EntryPoint {$ifndef SB_NET}={$else}:={$endif} {$ifndef NET_CF}'AcquireCredentialsHandleA'{$else}'AcquireCredentialsHandle'{$endif})]
  function sfProcsAcquireCredentialsHandleA(p1 : IntPtr; p2 : IntPtr; p3 : LongWord;
    p4 : IntPtr; p5 : IntPtr; p6 : SEC_GET_KEY_FN; p7 : IntPtr; p8 : IntPtr;
    var p9 : Int64):Integer; external;

  [DllImport(securitydll, CharSet {$ifndef SB_NET}={$else}:={$endif} CharSet.Auto, SetLastError {$ifndef SB_NET}={$else}:={$endif} True, EntryPoint {$ifndef SB_NET}={$else}:={$endif} 'FreeContextBuffer')]
  function sfProcsFreeContextBuffer(buf : IntPtr):Integer; external;

  [DllImport(securitydll, CharSet {$ifndef SB_NET}={$else}:={$endif} CharSet.Auto, SetLastError {$ifndef SB_NET}={$else}:={$endif} True, EntryPoint {$ifndef SB_NET}={$else}:={$endif} {$ifndef NET_CF}'InitializeSecurityContextA'{$else}'InitializeSecurityContext'{$endif})]
  function sfProcsInitializeSecurityContextA(p1 : IntPtr; p2 : IntPtr; p3 : IntPtr;
    p4 : LongWord; p5 : LongWord; p6 : LongWord; p7 : IntPtr; p8 : LongWord;
    p9 : IntPtr; p10 : IntPtr;  var p11 : LongWord; var p12 : int64):Integer; external;

  [DllImport(securitydll, CharSet {$ifndef SB_NET}={$else}:={$endif} CharSet.Auto, SetLastError {$ifndef SB_NET}={$else}:={$endif} True, EntryPoint {$ifndef SB_NET}={$else}:={$endif} 'CompleteAuthToken')]
  function sfProcsCompleteAuthToken(p1 : IntPtr; p2 : IntPtr):Integer;  external;

  [DllImport(securitydll, CharSet {$ifndef SB_NET}={$else}:={$endif} CharSet.Auto, SetLastError {$ifndef SB_NET}={$else}:={$endif} True, EntryPoint {$ifndef SB_NET}={$else}:={$endif} {$ifndef NET_CF}'EnumerateSecurityPackagesA'{$else}'EnumerateSecurityPackages'{$endif})]
  function sfProcsEnumerateSecurityPackagesA(var p1 : LongWord; p2 : IntPtr):Integer; external;

  [DllImport(securitydll, CharSet {$ifndef SB_NET}={$else}:={$endif} CharSet.Auto, SetLastError {$ifndef SB_NET}={$else}:={$endif} True, EntryPoint {$ifndef SB_NET}={$else}:={$endif} 'DeleteSecurityContext')]
  function sfProcsDeleteSecurityContext(ctx : IntPtr):Integer; external;
{$endif}
*)

procedure ValidateSecPacks(ls : TElStringList);
{$ifdef SB_NTLM_SUPPORT}
type
  ASecPkgInfo=array[0..0] of SecPkgInfo;
  PASecPkgInfo=^ASecPkgInfo;
var
  pSec : PSecPkgInfo;
  zSec : PASecPkgInfo;
  cSec, i, j: LongWord;
  ss : Integer;
  found : boolean;
 {$endif}
begin
{$ifdef SB_NTLM_SUPPORT}
  pSec := nil;
  ss := sfProcs.EnumerateSecurityPackagesA(@cSec, @pSec);
  zSec := PASecPkgInfo(pSec);
  if ss = 0 then
    for i := ls.Count downto 1 do
    begin
      found := false;
      if (LowerCase(ls[i - 1]) = LowerCase(cBasic)) or (LowerCase(ls[i - 1]) = LowerCase(cDigest)) then
        continue;
      for j := 1 to cSec do
      begin
        if ls[i - 1] = {$ifdef SB_UNICODE_VCL}UnicodeString {$endif}(AnsiString(zSec[j - 1].Name)) then
        begin
          found := true;
          break;
        end;
      end;
      if not found then
        ls.Delete(i - 1);
    end;
  if Assigned(pSec) then
    sfProcs.FreeContextBuffer(pSec);
 {$endif}
end;

{$ifdef SB_NTLM_SUPPORT}
procedure AuthIdFree(ai: PSEC_WINNT_AUTH_IDENTITY);
begin
  if Assigned(ai^.User) then
    StrDispose(ai^.User);
  if Assigned(ai^.Password) then
    StrDispose(ai^.Password);
  if Assigned(ai^.Domain) then
    StrDispose(ai^.Domain);
  fillchar(ai^, sizeof(ai^), 0);
end;
 {$endif}

procedure AuthInit(pAS : PAUTH_SEQ);
begin
  {$ifdef SB_NTLM_SUPPORT}
  pAS^.NewConversation := true;
  pAS^.HaveCredHandle := false;
  pAS^.HaveCtxtHandle := false;
  AuthIdFree(@pAS^.AuthIdentity);
   {$endif}
  pAS^.UUEncodeData := true;
  pAs^.cNonce:='';
  pAs^.cNonceCount:=0;
end;

procedure AuthTerm(pAS : PAUTH_SEQ);
begin
  {$ifdef SB_NTLM_SUPPORT}
  if pAS^.HaveCredHandle then
    sfProcs.FreeCredentialsHandle(@pAS^.hcred);
  if pAS^.HaveCtxtHandle then
    sfProcs.DeleteSecurityContext(@pAS^.hctxt);
  pAS^.HaveCredHandle := false;
  pAS^.HaveCtxtHandle := false;
   {$endif}
end;


{$ifdef SB_NTLM_SUPPORT}
procedure CrackUserAndDomain(const DomainAndUser : string; var User : string; var Domain : string);
var
  DefaultDomain : string;
  x : Integer;
  f : boolean;
  n : LongWord;
  {$ifdef NET_CF_2_0}
  IdentKey: RegistryKey;
   {$endif}
begin
  DefaultDomain :='';
  f := false;
  x := StringIndexOf(DomainAndUser, '/');
  if x < StringStartOffset then
    x := StringIndexOf(DomainAndUser, '\');
  if x < StringStartOffset then
  begin
    x := StringIndexOf(DomainAndUser, '@');
    f := true;
  end;
  if x  < StringStartOffset then
  begin
    if DefaultDomain = '' then
    begin
      n := MAX_COMPUTERNAME_LENGTH + 1;
      SetLength(DefaultDomain, n);
      GetComputerName(PChar(DefaultDomain), n);
      SetLength(DefaultDomain, n);
    end;
    Domain := DefaultDomain;
    User   := DomainAndUser;
  end
  else
  begin
    if f then
    begin
      User := StringSubstring(DomainAndUser, StringStartOffset, x - StringStartOffset - StringStartInvOffset);
      Domain := StringSubstring(DomainAndUser, x + 1, Length(DomainAndUser));
    end
    else
    begin
      Domain := StringSubstring(DomainAndUser, StringStartOffset, x - StringStartOffset - StringStartInvOffset);
      User := StringSubstring(DomainAndUser, x + 1, Length(DomainAndUser));
    end;
  end;
end;
 {$endif}


function AuthConverse(pAS : PAUTH_SEQ; const BuffIn : ByteArray; out BuffOut : ByteArray;
  var NeedMoreData : boolean; Package : string; User : string; const Password : string) : boolean;
var
  {$ifdef SB_NTLM_SUPPORT}
  ss                : integer;
  Domain            : string;
  Lifetime          : int64;
  AuthIdentity      : SEC_WINNT_AUTH_IDENTITY;
  pAuthIdentity     : PSEC_WINNT_AUTH_IDENTITY;
  pspkg             : PSecPkgInfo;
  OutBuffDesc       : SecBufferDesc;
  OutSecBuff        : SecBuffer;
  InBuffDesc        : SecBufferDesc;
  InSecBuff         : SecBuffer;
  buff              : pointer;
  ContextAttributes : LongWord;
  fReply            : boolean;
   {$endif}
  Text : string;
  TmpBuf : ByteArray;
  Sasl : TElSASLDigestMD5Client;
begin
  result := false;
  {$ifdef SB_NTLM_SUPPORT}
  if LowerCase(Package)=LowerCase(cNTLM) then
  begin
      if pAS^.UUEncodeData and (Length(BuffIn) <> 0) then
      begin
        Text := StringOfBytes(BuffIn);
        TmpBuf := SBEncoding.Base64DecodeArray(Text);
      end
      else
        TmpBuf := BuffIn;

      if pAS^.NewConversation then
      begin
        AuthTerm(pAS);
        if (User <> '') or (Password <> '') then
        begin
          pAuthIdentity := @pAS^.AuthIdentity;
          if User <> '' then
            CrackUserAndDomain(User, User, Domain);

          AuthIdFree(@pAS^.AuthIdentity);
          {$ifndef SB_UNICODE_VCL}
          pAS^.AuthIdentity.User           := StrNew(PAnsiChar(User));
           {$else}
          pAS^.AuthIdentity.User           := StrNew(PAnsiChar(AnsiString(User)));
           {$endif}
          pAS^.AuthIdentity.UserLength     := Length(User);

          {$ifndef SB_UNICODE_VCL}
          pAS^.AuthIdentity.Password       := StrNew(PAnsiChar(Password));
           {$else}
          pAS^.AuthIdentity.Password       := StrNew(PAnsiChar(AnsiString(Password)));
           {$endif}
          pAS^.AuthIdentity.PasswordLength := Length(Password);

          {$ifndef SB_UNICODE_VCL}
          pAS^.AuthIdentity.Domain         := StrNew(PAnsiChar(Domain));
           {$else}
          pAS^.AuthIdentity.Domain         := StrNew(PAnsiChar(AnsiString(Domain)));
           {$endif}
          pAS^.AuthIdentity.DomainLength   := Length(Domain);

          pAS^.AuthIdentity.Flags := SEC_WINNT_AUTH_IDENTITY_ANSI;
        end
        else
        begin
          pAuthIdentity := @AuthIdentity;
          AuthIdentity.User           := StrNew(PAnsiChar(nil));
          AuthIdentity.UserLength     := 0;

          AuthIdentity.Password       := StrNew(PAnsiChar(nil));
          AuthIdentity.PasswordLength := 0;

          AuthIdentity.Domain         := StrNew(PAnsiChar(nil));
          AuthIdentity.DomainLength   := 0;

          AuthIdentity.Flags := SEC_WINNT_AUTH_IDENTITY_ANSI;
        end;

        ss := sfProcs.AcquireCredentialsHandleA(nil,    // New principal
          {$ifndef SB_UNICODE_VCL}
          PAnsiChar(Package), // Package name
           {$else}
          PAnsiChar(AnsiString(Package)), // Package name
           {$endif}
          SECPKG_CRED_OUTBOUND,
          nil,            // Logon ID
          pAuthIdentity,  // Auth Data
          nil,            // Get key func
          nil,            // Get key arg
          @pAS^.hcred,
          @Lifetime);

        if ss = 0 then
        begin
          pAS^.HaveCredHandle := true;
          ss := sfProcs.QuerySecurityPackageInfoA(
            {$ifndef SB_UNICODE_VCL}
            PAnsiChar(Package),
             {$else}
            PAnsiChar(AnsiString(Package)),
             {$endif}
            @pspkg);
        end;

        if ss <> 0 then
          exit;

        pAS^.MaxToken := pspkg^.cbMaxToken;
        sfProcs.FreeContextBuffer(pspkg);
      end;

      GetMem(buff, pAS^.MaxToken);
      try
        OutBuffDesc.ulVersion := 0;
        OutBuffDesc.cBuffers  := 1;
        OutBuffDesc.pBuffers  := @OutSecBuff;

        OutSecBuff.cbBuffer   := pAS^.MaxToken;
        OutSecBuff.BufferType := SECBUFFER_TOKEN;
        OutSecBuff.pvBuffer   := buff;

        if Length(BuffIn) <> 0 then
        begin
          InBuffDesc.ulVersion  := 0;
          InBuffDesc.cBuffers   := 1;
          InBuffDesc.pBuffers   := @InSecBuff;

          InSecBuff.cbBuffer    := Length(TmpBuf);
          InSecBuff.BufferType  := SECBUFFER_TOKEN;
          InSecBuff.pvBuffer    := @TmpBuf[0];
        end;

        ContextAttributes := 0;
        if pAS^.NewConversation then
          ss := sfProcs.InitializeSecurityContextA(@pAS^.hcred, nil, TOKEN_SOURCE_NAME, $10800, 0,
            SECURITY_NATIVE_DREP, nil, 0, @pAS^.hctxt, @OutBuffDesc, @ContextAttributes, @Lifetime)
        else
          ss := sfProcs.InitializeSecurityContextA(@pAS^.hcred, @pAS^.hctxt, TOKEN_SOURCE_NAME, $10800, 0,
            SECURITY_NATIVE_DREP, @InBuffDesc, 0, @pAS^.hctxt, @OutBuffDesc, @ContextAttributes,
            @Lifetime);

        if ss < 0 then
          exit;

        pAS^.HaveCtxtHandle := true;

        fReply := OutSecBuff.cbBuffer <> 0;
        if (ss = SEC_I_COMPLETE_NEEDED) or (ss = SEC_I_COMPLETE_AND_CONTINUE) then
        begin
          if Assigned(sfProcs.CompleteAuthToken) then
          begin
            ss := sfProcs.CompleteAuthToken(@pAS^.hctxt, @OutBuffDesc);
            if ss < 0 then
              exit;
          end
          else
            exit;
        end;

        if fReply then
        begin
          SetLength(BuffOut, OutSecBuff.cbBuffer);
          Move(buff^, BuffOut[0], OutSecBuff.cbBuffer);
          if pAS^.UUEncodeData then
            BuffOut := BytesOfString(SBEncoding.Base64EncodeArray(BuffOut, false));
        end;

        if pAS^.NewConversation then
          pAS^.NewConversation := false;

        NeedMoreData := (ss = SEC_I_CONTINUE_NEEDED) or (ss = SEC_I_COMPLETE_AND_CONTINUE);

        result := true;
      finally
        FreeMem(buff);
      end;
  end
  else
   {$endif}
  if LowerCase(Package)=LowerCase(cDigest) then
  begin
    Sasl := TElSASLDigestMD5Client.Create;
    try
      Sasl.UserName := User;
      Sasl.Password := Password;
      Sasl.RequestURI := pAS^.RequestURI;
      Sasl.RequestMethod := pAS^.RequestMethod;
      Sasl.CustomRequestMethod := pAS^.cRequest;

      Sasl.ProcessChallenge(BuffIn, BuffOut);

      NeedMoreData := not Sasl.Complete;
      Result := true;
    finally
      FreeAndNil(Sasl);
    end;
  end;
end;



function AddAuthorizationHeader(var Str : string; const Scheme : string; const AuthData : string;
  const UserName : string; const Password : string; var NeedMoreData : TSBBoolean; ForProxy: boolean;
    aSeq : PAUTH_SEQ  ):boolean;
var
  Auth, hs : ByteArray;
begin
  result := false;
  // pe startul NeedMoreData semnifica de asamenea cu FInAuth
  if not NeedMoreData then
    AuthInit(aSeq);
  if LowerCase(Scheme)=LowerCase(cDigest) then
    aSeq.UUEncodeData:=false;

  Auth := BytesOfString(AuthData);
  SetLength(hs, 0);

  if not AuthConverse(aSeq, Auth, hs, NeedMoreData, Scheme, UserName, Password) then
    exit;
  if ForProxy then
    Str := cPAuth+Scheme + ' ' + StringOfBytes(hs)
  else
    Str := cAuth+Scheme + ' ' + StringOfBytes(hs);
    
  result := true;
end;





procedure InitAuthLib;
{$ifdef SB_NTLM_SUPPORT}
var secDLL  : string;
 {$endif}
begin
  {$ifdef SB_NTLM_SUPPORT}
  secInit := false;
  if Win32Platform = VER_PLATFORM_WIN32_NT then
    secDLL := 'security.dll'
  else
  if Win32Platform = VER_PLATFORM_WIN32_WINDOWS then
    secDLL := 'secur32.dll'
  else
    exit;
  secLib := LoadLibrary(PChar(secDLL));
  if secLib < 1 then
    exit;
  sfProcs.FreeCredentialsHandle := FREE_CREDENTIALS_HANDLE_FN(GetProcAddress(secLib,
    'FreeCredentialsHandle'));
  sfProcs.QuerySecurityPackageInfoA := QUERY_SECURITY_PACKAGE_INFO_FN(GetProcAddress(secLib,
    'QuerySecurityPackageInfoA'));
  sfProcs.AcquireCredentialsHandleA := ACQUIRE_CREDENTIALS_HANDLE_FN(GetProcAddress(secLib,
    'AcquireCredentialsHandleA'));
  sfProcs.FreeContextBuffer := FREE_CONTEXT_BUFFER_FN(GetProcAddress(secLib,
    'FreeContextBuffer'));
  sfProcs.InitializeSecurityContextA := INITIALIZE_SECURITY_CONTEXT_FN(GetProcAddress(secLib,
    'InitializeSecurityContextA'));
  sfProcs.CompleteAuthToken := COMPLETE_AUTH_TOKEN_FN(GetProcAddress(secLib,
    'CompleteAuthToken'));
  sfProcs.EnumerateSecurityPackagesA := ENUMERATE_SECURITY_PACKAGES_FN(GetProcAddress(secLib,
    'EnumerateSecurityPackagesA'));
  sfProcs.DeleteSecurityContext := DELETE_SECURITY_CONTEXT_FN(GetProcAddress(secLib,
    'DeleteSecurityContext'));

  if not Assigned(sfProcs.FreeCredentialsHandle) or
    not Assigned(sfProcs.QuerySecurityPackageInfoA) or
    not Assigned(sfProcs.AcquireCredentialsHandleA) or
    not Assigned(sfProcs.FreeContextBuffer) or
    not Assigned(sfProcs.InitializeSecurityContextA) or
    not Assigned(sfProcs.EnumerateSecurityPackagesA) then
  begin
    FreeLibrary(secLib);
    secLib := 0;
    exit;
  end;
   {$endif}

  secInit := true;
end;

procedure TermAuthLib;
begin
  {$ifdef SB_NTLM_SUPPORT}
  if secLib > 0 then
    FreeLibrary(secLib);
   {$endif}
end;

initialization
  InitAuthLib;


finalization
  TermAuthLib;

 {$endif SB_HAS_HTTPAUTH}

end.

