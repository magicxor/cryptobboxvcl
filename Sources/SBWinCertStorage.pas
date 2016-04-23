(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBWinCertStorage;

interface

{$ifdef SB_HAS_WINCRYPT}

uses
  SBTypes,
  SBCustomCertStorage,
  Classes,
  SysUtils,
  Windows,
  SBX509,
  SBWinCrypt,
  SBUtils,
  SBStrUtils,
  SBAlgorithmIdentifier,
  SBConstants,
  SBSharedResource,
  SBCryptoProv,
  SBRSA,
  SBMSKeyBlob
  ;

{$WARNINGS OFF}
type
  TSBStorageType = 
    (stSystem, stRegistry, stLDAP, stMemory);

  TSBStorageAccessType = 
    (atCurrentService, atCurrentUser, atCurrentUserGroupPolicy,
     atLocalMachine, atLocalMachineEnterprise, atLocalMachineGroupPolicy,
     atServices, atUsers);

  TSBStorageProviderType = 
    (ptDefault, ptBaseDSSDH, ptBaseDSS, ptBase, ptRSASchannel,
     ptRSASignature, ptEnhancedDSSDH, ptEnhancedRSAAES, ptEnhanced, ptBaseSmartCard,
     ptStrong, ptCryptoProGOST94, ptCryptoProGOST2001);

  TElWinCertStorage = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElWinCertStorage = TElWinCertStorage;
   {$endif}

  
  TElWinCertStorage = class(TElCustomCertStorage)
  private
    FStores :  TStringList ;
    FPhysicalStores :  TStringList ;
    FStorageType : TSBStorageType;
    FAccessType : TSBStorageAccessType;
    FProvider : TSBStorageProviderType;
    FReadOnly : boolean;
    FAllowDuplicates : boolean;
    FList : TElList;
    FCtxList :  TElList; 
    FStoreIndexes : TElIntegerList;
    FSystemStoresCtx : array of pointer;
    FTryCurrentUser : boolean;
    FCryptoProvider : TElCustomCryptoProvider;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetSuitableCryptoProvider : TElCustomCryptoProvider;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    class function SetupAccessRights(Access : TSBStorageAccessType) : cardinal;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    class function GetProviderString(Prov : TSBStorageProviderType) : string;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    class function GetProviderType(Prov : TSBStorageProviderType; Alg : integer) : DWORD;


    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure SetPhysicalStores(const Value:  TStringList );
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure SetStores(const Value:  TStringList );
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure SetStorageType(Value: TSBStorageType);
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure SetAccessType(Value: TSBStorageAccessType);
  protected
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure Open;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function OpenRegistryStore(const Name : string; UserRights : cardinal) : HCERTSTORE;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function OpenLDAPStore(const Name : string; UserRights: cardinal) : HCERTSTORE;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure ClearInfo;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure HandleStoresChange(Sender :  TObject );
    function LoadPrivateKey(Cert : TElX509Certificate; Key : HCRYPTKEY) : boolean;
    procedure SetPrivateKeyForCertificate(Context : PCCERT_CONTEXT; Cert : TElX509Certificate;
      Exportable : boolean = true; Protected : boolean = true);  overload; 
    procedure SetPrivateKeyForCertificate(Context : PCCERT_CONTEXT; const ProvName,
      ContName: string; ProvType, KeySpec : DWORD);  overload; 
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecurityCritical]
     {$endif}
    function FindMatchingPrivateKey(Certificate: TElX509Certificate;
      const ProposedContainerName: string; var ContainerName : string;
      var ProvName : string; var ProvType : DWORD; var KeySpec : DWORD): boolean;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecurityCritical]
     {$endif}
    procedure InternalAdd(Certificate: TElX509Certificate; const StoreName: string;
      CopyPrivateKey: boolean; Exportable: boolean; Protected: boolean;
      BindToExistingPrivateKey : boolean; const PrivateKeyContainerName : string);
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecurityCritical]
    function GetCertificatesInt(Index : integer) : TElX509Certificate;
    [SecurityCritical]
    procedure AddInt(Certificate: TElX509Certificate; CopyPrivateKey: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif});
    [SecurityCritical] 
    procedure RemoveInt(Index: integer); 
     {$endif}
    
    {$ifdef SB_HAS_CRYPTUI}
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecurityCritical]
     {$endif}
    function CertContextToSBB(Ctx :  PCCERT_CONTEXT ) : TElX509Certificate;
     {$endif}
    
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetCount : integer; override;
    
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetCertificates(Index : integer) : TElX509Certificate; override;
  public
    constructor Create(Owner: TComponent); override;
     destructor  Destroy; override;

    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecurityCritical]
     {$endif}
    class procedure GetAvailableStores(Stores:  TStrings ;
      AccessType: TSBStorageAccessType  =  atCurrentUser);

    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecurityCritical]
     {$endif}
    class procedure GetAvailablePhysicalStores(const SystemStore: string;
      Stores:  TStrings ;
      AccessType: TSBStorageAccessType  =  atCurrentUser);

    {$ifndef NET_CF}
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecurityCritical]
     {$endif}
    class function GetStoreFriendlyName(const StoreName : string) : string;
     {$endif}

    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure Add(Certificate: TElX509Certificate; CopyPrivateKey: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif});  overload;  override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecurityCritical]
     {$endif}
    procedure Add(Certificate: TElX509Certificate; const StoreName: string;
        CopyPrivateKey: boolean {$ifdef HAS_DEF_PARAMS} =  false {$endif};
        Exportable: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif};
        Protected: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif}); reintroduce;  overload; 
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecurityCritical]
     {$endif}
    procedure Add(Certificate: TElX509Certificate; BindToExistingPrivateKey : boolean;
      const StoreName: string; const PrivateKeyContainerName: string); reintroduce;  overload; 
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure Remove(Index: integer); override;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure Refresh;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure PreloadCertificates;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecurityCritical]
     {$endif}
    procedure CreateStore(const StoreName: string);
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecurityCritical]
     {$endif}
    procedure DeleteStore(const StoreName: string);
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecurityCritical]
     {$endif}
    procedure ListKeyContainers(List : TElStringList);  overload; 
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecurityCritical]
     {$endif}
    procedure ListKeyContainers(List : TElStringList; ProvType : TSBStorageProviderType);  overload; 
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecurityCritical]
     {$endif}
    procedure DeleteKeyContainer(const ContainerName: string);
    
    {$ifdef SB_HAS_CRYPTUI}
    function Select(Owner : HWND; SelectedList : TElCustomCertStorage) : boolean;
    class function ImportWizard(Owner : HWND) : boolean;
     {$endif}

    property Count: integer read GetCount; 
    
    property Certificates[Index: integer]: TElX509Certificate read  GetCertificates ; 
    
    property TryCurrentUser : boolean read FTryCurrentUser write FTryCurrentUser;
  published
    property SystemStores :  TStringList  read FStores write SetStores;
    property PhysicalStores :  TStringList  read FPhysicalStores write SetPhysicalStores;
    property StorageType : TSBStorageType read FStorageType write SetStorageType  default stSystem ;
    property AccessType : TSBStorageAccessType read FAccessType write SetAccessType  default atCurrentUser ;
    property Provider : TSBStorageProviderType read FProvider write FProvider  default ptDefault ;
    property ReadOnly : boolean read FReadOnly write FReadOnly;
    property CryptoProvider : TElCustomCryptoProvider read FCryptoProvider
      write FCryptoProvider; // TODO: add to Notification method
    property AllowDuplicates : boolean read FAllowDuplicates write FAllowDuplicates  default true ;
  end;
{$WARNINGS ON}

procedure Register;

 {$endif}

implementation

{$ifdef SB_HAS_WINCRYPT}

uses
  SBCryptoProvWin32;

resourcestring

  SCertificateAlreadyExists = 'Certificate already exists';
  SFailedToGetPrivateKey    = 'Failed to retrieve certificate private key';
  SWin32Error               = 'Win32 error';
  SInvalidPrivateKey        = 'Invalid private key';
  SFailedToAddCertificate   = 'Failed to add certificate to Windows storage due to error ';
  SIndexOutOfBounds         = 'Index out of bounds';
  SUnableToDeleteCertificate= 'Unable to delete certificate';
  SFailedToOpenStore        = 'Failed to open storage';
  SNoStoresSpecified        = 'No system store names specified in SystemStores property';
  SUnsupportedAlgorithm     = 'Unsupported algorithm';
  SMatchingPrivKeyNotFound  = 'Matching private key not found';
  SComponentRequiresElevatedPermissions = 'The component requires elevated permissions';

procedure Register;
begin
  RegisterComponents('PKIBlackbox', [TElWinCertStorage]);
end;

constructor TElWinCertStorage.Create(Owner : TComponent);
begin
  {$ifdef SILVERLIGHT}
  if not SBUtils.ElevatedPermissionsAvailable then
    raise EElCertStorageError.Create(SComponentRequiresElevatedPermissions);
   {$endif}
  inherited;
  FStores := TElStringList.Create;
  FPhysicalStores := TElStringList.Create;
  FStores.OnChange  :=  HandleStoresChange;
  FPhysicalStores.OnChange  :=  HandleStoresChange;
  FList := TElList.Create;
  FCtxList :=  TElList.Create; 
  FStoreIndexes := TElIntegerList.Create;
  FStorageType := stSystem;
  FAccessType := atCurrentUser;
  FProvider := ptDefault;
  FReadOnly := false;
  FTryCurrentUser := true;
  FAllowDuplicates := true;
end;



 destructor  TElWinCertStorage.Destroy;
begin
  ClearInfo;
  FreeAndNil(FList);
  FreeAndNil(FCtxList);
  FreeAndNil(FStores);
  FreeAndNil(FPhysicalStores);
  FreeAndNil(FStoreIndexes);
  inherited;
end;

procedure TElWinCertStorage.ClearInfo;
var
  I : integer;
begin
  FSharedResource.WaitToWrite;
  try
    for I := 0 to FList.Count - 1 do
    begin
      if Assigned(FList[I]) then
        TElX509Certificate(FList[I]). Free ;
      if Assigned(FCtxList[I]) then
        CertFreeCertificateContext(FCtxList[I]);
    end;
    for I := 0 to Length(FSystemStoresCtx) - 1 do
      CertCloseStore(FSystemStoresCtx[I], 0);
    SetLength(FSystemStoresCtx, 0);
    FList.Clear;
    FCtxList.Clear;
    FStoreIndexes.Clear;
    FRebuildChains := true;
  finally
    FSharedResource.Done;
  end;
end;

procedure TElWinCertStorage.HandleStoresChange(Sender :  TObject );
begin
  if not (csDesigning in ComponentState) then
    Open;
end;

procedure TElWinCertStorage.Add(Certificate: TElX509Certificate; const StoreName: string;
    CopyPrivateKey: boolean {$ifdef HAS_DEF_PARAMS} =  false {$endif};
    Exportable: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif};
    Protected: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif});
begin
  InternalAdd(Certificate, StoreName, CopyPrivateKey, Exportable, Protected, false, '');
end;

procedure TElWinCertStorage.Add(Certificate: TElX509Certificate; BindToExistingPrivateKey : boolean;
  const StoreName: string; const PrivateKeyContainerName: string);
begin
  InternalAdd(Certificate, StoreName, false, false, false, BindToExistingPrivateKey,
    PrivateKeyContainerName);
end;

procedure TElWinCertStorage.InternalAdd(Certificate: TElX509Certificate; const StoreName: string;
  CopyPrivateKey: boolean; Exportable: boolean; Protected: boolean;
  BindToExistingPrivateKey : boolean; const PrivateKeyContainerName: string);
var
  hSystemStore : pointer;
  Cert : PCCERT_CONTEXT;
  ErrCode : Cardinal;
  Size : integer;
  Rights: cardinal;
  WideStr : PWideChar;
  Len : integer;
  ContName, ProvName : string;
  ProvType, KeySpec : DWORD;
  AddDisposition : Cardinal;
begin
  CheckLicenseKey();

  if BindToExistingPrivateKey then
  begin
    if not FindMatchingPrivateKey(Certificate, PrivateKeyContainerName, ContName,
      ProvName, ProvType, KeySpec) then
      raise ESecureBlackboxError.Create(SMatchingPrivKeyNotFound);
  end;

  FRebuildChains := true;
  Rights := SetupAccessRights(FAccessType);

  if FReadOnly then
    Rights := Rights or CERT_STORE_READONLY_FLAG;

  if StorageType = stSystem then
  begin
    Len := (Length(StoreName) + 1) shl 1;
    GetMem(WideStr, Len);
    try
      StringToWideChar(StoreName, WideStr, Len shr 1);
      hSystemStore := CertOpenStore(PAnsiChar(CERT_STORE_PROV_SYSTEM), X509_ASN_ENCODING or
        PKCS_7_ASN_ENCODING, 0, Rights, WideStr);
    finally
      FreeMem(WideStr);
    end;

    if (hSystemStore = nil) and FTryCurrentUser then
      hSystemStore := CertOpenSystemStore(0, PChar(StoreName));

  end
  else
  if FStorageType = stRegistry then
  begin
    hSystemStore := OpenRegistryStore(StoreName, Rights);
  end
  else
  if FStorageType = stLDAP then
  begin
    hSystemStore := OpenLDAPStore(StoreName, Rights);
  end
  else
  if StorageType = stMemory then
  begin
    if Length(FSystemStoresCtx) <> 1 then
    begin
      hSystemStore := CertOpenStore(PAnsiChar(CERT_STORE_PROV_MEMORY), 0, 0, 0, nil);
    end
    else
      hSystemStore := FSystemStoresCtx[0];
  end
  else
    hSystemStore :=   nil  ;

  if not FAllowDuplicates then
    AddDisposition := CERT_STORE_ADD_NEW
  else
    AddDisposition := CERT_STORE_ADD_ALWAYS;

  if hSystemStore <>   nil   then
  begin
    if not CertAddEncodedCertificateToStore(hSystemStore, X509_ASN_ENCODING,
      PByte(Certificate.CertificateBinary), Certificate.CertificateSize,
      AddDisposition, Cert) then
    begin
      ErrCode := GetLastError;
      CertCloseStore(hSystemStore, 0);
      if ErrCode = CRYPT_E_EXISTS then
        raise EElDuplicateCertError.Create(SCertificateAlreadyExists, integer(CRYPT_E_EXISTS){$ifndef FPC}, 0 {$endif})
      else
        raise EElCertStorageError.Create(SFailedToAddCertificate, ErrCode{$ifndef FPC}, 0 {$endif});
    end
    else
    try
      if CopyPrivateKey then
      begin
        if Certificate.PrivateKeyExists then
        begin
          Size := 0;
          Certificate.SaveKeyToBuffer(nil, Size);
          if Size = 0 then
            raise EElCertStorageError.Create(SFailedToGetPrivateKey);
          SetPrivateKeyForCertificate(Cert, Certificate, Exportable, Protected);
        end;
      end
      else if BindToExistingPrivateKey then
      begin
        SetPrivateKeyForCertificate(Cert, ProvName, ContName, ProvType, KeySpec);
      end;
      Certificate.StorageName := StoreName;
    finally
      CertFreeCertificateContext(Cert);
      if FStorageType <> stMemory then
        CertCloseStore(hSystemStore, 0);
    end;
  end
  else
    raise ESecureBlackboxError.Create(SFailedToOpenStore);
  HandleStoresChange(FStores);
end;

function TElWinCertStorage.FindMatchingPrivateKey(Certificate: TElX509Certificate;
  const ProposedContainerName : string; var ContainerName : string;
  var ProvName : string; var ProvType : DWORD; var KeySpec : DWORD): boolean;
var
  ProvTp : DWORD;
  ProvStr :  AnsiString ;
  FlagModifier : DWORD;
  Prov : HCRYPTPROV;
  ProvPtr, ContNamePtr :  pointer ;
  err : integer;
  ContName :  pointer ;
  ContNameLen :  DWORD ;
  ContNameStr :  AnsiString ;
  {$ifdef SB_UNICODE_VCL}
  ContNameWStr : string;
   {$endif}
  Conts : TElStringList;
  res : BOOL;
  hKey : HCRYPTKEY;
  I : integer;
  CertRSAM, CertRSAE : ByteArray;
  CertRSAMSize, CertRSAESize : integer;

  function KeyMatches(Key : HCRYPTKEY; KeySp : DWORD): boolean;
  var
    Data, Blob : ByteArray;
    DataLen :  DWORD ;
    BlobLen : integer;
    BT : integer;
    AlgID : ByteArray;
    MSize, ESize: integer;
    M, E : ByteArray;
  begin
    Result := false;
    // checking that there is no certificate already associated with the key
    // (this is mostly a senseless check as I have seen no certificates bound
    // to keys in such way in real world)
    DataLen := 0;
    CryptGetKeyParam(Key, KP_CERTIFICATE, nil, @DataLen, 0);
    if (DataLen > 0) then
      Exit;
    // exporting public key
    DataLen := 0;
    CryptExportKey(Key, 0, PUBLICKEYBLOB, 0, nil, @DataLen);
    SetLength(Data, DataLen);
    if CryptExportKey(Key, 0, PUBLICKEYBLOB, 0, @Data[0], @DataLen) then
    begin
      BlobLen := 0;
      SBMSKeyBlob.ParseMSKeyBlob(@Data[0], DataLen, nil, BlobLen, BT);
      SetLength(Blob, BlobLen);
      if SBMSKeyBlob.ParseMSKeyBlob(@Data[0], DataLen, @Blob[0], BlobLen, BT) = 0 then
      begin
        MSize := 0;
        SBRSA.DecodePublicKey(@Blob[0], BlobLen, nil, MSize, nil, ESize, AlgID, true);
        SetLength(M, MSize);
        SetLength(E, ESize);
        if SBRSA.DecodePublicKey(@Blob[0], BlobLen, @M[0], MSize, @E[0], ESize, AlgID, true) then
        begin
          SetLength(M, MSize);
          SetLength(E, ESize);
          M := TrimLeadingZeros(M);
          E := TrimLeadingZeros(E);
          Result := CompareMem(M, CertRSAM) and CompareMem(E, CertRSAE);
          if Result then
          begin
            // copying params
            ContainerName := String(ContNameStr);
            ProvName := String(ProvStr);
            ProvType := ProvTp;
            KeySpec := KeySp;
          end;
        end;
      end;
    end;
  end;

begin
  Result := false;
  
  if Certificate.PublicKeyAlgorithm <> SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION then
    raise ESecureBlackboxError.Create(SUnsupportedAlgorithm);
  CertRSAMSize := 0;
  Certificate.GetRSAParams(nil, CertRSAMSize, nil, CertRSAESize);
  SetLength(CertRSAM, CertRSAMSize);
  SetLength(CertRSAE, CertRSAESize);
  Certificate.GetRSAParams(@CertRSAM[0], CertRSAMSize, @CertRSAE[0], CertRSAESize);
  SetLength(CertRSAM, CertRSAMSize);
  SetLength(CertRSAE, CertRSAESize);
  CertRSAM := TrimLeadingZeros(CertRSAM);
  CertRSAE := TrimLeadingZeros(CertRSAE);

  ProvStr := {$ifdef SB_UNICODE_VCL}AnsiString {$endif}(GetProviderString(FProvider));
  ProvTp := GetProviderType(FProvider, Certificate.PublicKeyAlgorithm);

  if Length(ProvStr) > 0 then
  begin
    ProvStr := ProvStr + #0;
    ProvPtr := @ProvStr[AnsiStrStartOffset];
  end
  else
    ProvPtr := nil;

  if AccessType in [atLocalMachine,
                    atLocalMachineEnterprise,
                    atLocalMachineGroupPolicy,
                    atServices,
                    atUsers] then
    FlagModifier := CRYPT_MACHINE_KEYSET
  else
    FlagModifier := 0;
  FlagModifier := FlagModifier or CRYPT_VERIFYCONTEXT;

  if not CryptAcquireContext(@Prov, nil, ProvPtr, ProvTp, FlagModifier) then
  begin
    err := GetLastError;
    raise EElCertStorageError.Create(SWin32Error + ' ' + IntToHex(err, 8));
  end;
  Conts := TElStringList.Create();
  try
    if Length(ProposedContainerName) = 0 then
    begin
      try
        ContNameLen := 0;
        CryptGetProvParam(Prov, PP_ENUMCONTAINERS, nil, @ContNameLen, CRYPT_FIRST);
        GetMem(ContName, ContNameLen);
        try
          res := CryptGetProvParam(Prov, PP_ENUMCONTAINERS, ContName, @ContNameLen, CRYPT_FIRST);
          if res  then
            ContNameStr := PAnsiChar(ContName);
        finally
          FreeMem(ContName);
        end;
        while res  do
        begin
          Conts.Add(String(ContNameStr));
          ContNameLen := 0;
          CryptGetProvParam(Prov, PP_ENUMCONTAINERS, nil, @ContNameLen, CRYPT_NEXT);
          GetMem(ContName, ContNameLen);
          try
            res := CryptGetProvParam(Prov, PP_ENUMCONTAINERS, ContName, @ContNameLen, CRYPT_NEXT);
            if res  then
              ContNameStr := PAnsiChar(ContName);
          finally
            FreeMem(ContName);
          end;
        end;
      finally
        CryptReleaseContext(Prov, 0);
      end;
    end
    else
      Conts.Add(ProposedContainerName);
    for I := 0 to Conts.Count - 1 do
    begin
      ContNameStr := AnsiString(Conts[I] + #0);
      {$ifdef SB_UNICODE_VCL}
      ContNameWStr := String(ContNameStr);
      ContNamePtr := @ContNameWStr[StringStartOffset];
       {$else}
      ContNamePtr := @ContNameStr[AnsiStrStartOffset];
       {$endif}
      FlagModifier := FlagModifier and (not CRYPT_VERIFYCONTEXT);
      if CryptAcquireContext(@Prov, ContNamePtr, ProvPtr, ProvTp, FlagModifier) then
        try
          if CryptGetUserKey(Prov, AT_SIGNATURE,  @ hKey)  then
          begin
            try
              Result := KeyMatches(hKey, AT_SIGNATURE);
              if Result then
                Break;
            finally
              CryptDestroyKey(hKey);
            end;
          end;
          if CryptGetUserKey(Prov, AT_KEYEXCHANGE,  @ hKey)  then
          begin
            try
              Result := KeyMatches(hKey, AT_KEYEXCHANGE);
              if Result then
                Break;
            finally
              CryptDestroyKey(hKey);
            end;
          end;
        finally
          CryptReleaseContext(Prov, 0);
        end;
    end;
  finally
    FreeAndNil(Conts);
  end;
end;

{$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
procedure TElWinCertStorage.Add(Certificate: TElX509Certificate;
    CopyPrivateKey: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif});
begin
  AddInt(Certificate, CopyPrivateKey);
end;
 {$endif}

{$ifndef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
procedure TElWinCertStorage.Add(Certificate: TElX509Certificate;
    CopyPrivateKey: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif});
 {$else}
procedure TElWinCertStorage.AddInt(Certificate: TElX509Certificate;
    CopyPrivateKey: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif});
 {$endif}
begin
  if FStores.Count = 0 then
    Add(Certificate, 'ROOT', CopyPrivateKey{$ifndef HAS_DEF_PARAMS}, true, true {$endif})
  else
    Add(Certificate, FStores[0], CopyPrivateKey{$ifndef HAS_DEF_PARAMS}, true, true {$endif});
end;

function TElWinCertStorage.GetCount: integer;
begin
  Result := FCtxList.Count;
end;

{$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
function TElWinCertStorage.GetCertificates(Index: integer): TElX509Certificate;
begin
  Result := GetCertificatesInt(Index);
end;
 {$endif}

{$ifndef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
function TElWinCertStorage. GetCertificates (Index: integer): TElX509Certificate;
 {$else}
function TElWinCertStorage.GetCertificatesInt(Index: integer): TElX509Certificate;
 {$endif}
var
  pDesiredCert : PCCERT_CONTEXT;
  I, J, K, Ind : integer;
begin
  CheckLicenseKey();
  FSharedResource.WaitToRead;
  if Index >= FList.Count then
  begin
    Result := nil;
    FSharedResource.Done;
    Exit;
  end;
  if (Index < FList.Count) then
  begin
    Result := TElX509Certificate(FList[Index]);
    if Result <> nil then
    begin
      FSharedResource.Done;
      Exit;
    end;
  end;

  try
  Result := TElX509Certificate.Create(nil);
  Result.CryptoProvider := GetSuitableCryptoProvider();
  Result.CertStorage := Self;
  Ind :=  integer(FStoreIndexes[Index]) ;
  I := 0;
  Result.StorageName := '';
  if (FPhysicalStores.Count = 0) and (Ind < FStores.Count) and (Ind >= 0) then
    Result.StorageName := FStores.Strings[Ind]
  else
  begin
    for J := 0 to FStores.Count - 1 do
    begin
      for K := 0 to FPhysicalStores.Count - 1 do
      begin
        if I = Ind then
        begin
          Result.StorageName := FStores.Strings[J] + '\' +
            FPhysicalStores.Strings[K];
          Break;
        end;
        Inc(I);
      end;
      if I = Ind then
        Break;
    end;
  end;
  pDesiredCert := FCtxList[Index];
  try
    Result.LoadFromBuffer(pDesiredCert^.pbCertEncoded, pDesiredCert.cbCertEncoded);
  except
    ;
  end;
  Result.CertHandle := CertDuplicateCertificateContext(pDesiredCert);
  FList[Index] := (Result);
  Result.BelongsTo := BT_WINDOWS;
  { Reading the private key existence }
  finally
    FSharedResource.Done;
  end;
end;

{$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
procedure TElWinCertStorage.Remove(Index : integer);
begin
  RemoveInt(Index);
end;
 {$endif}

{$ifndef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
procedure TElWinCertStorage.Remove(Index : integer);
 {$else}
procedure TElWinCertStorage.RemoveInt(Index : integer);
 {$endif}
var
  pDesiredCert : PCCERT_CONTEXT;
  pCertCopy : PCCERT_CONTEXT;
begin
  CheckLicenseKey();
  if (Index >= FList.Count) or (Index < 0) then
    raise EElCertStorageError.Create(SIndexOutOfBounds);

  pDesiredCert := FCtxList[Index];
  pCertCopy := CertDuplicateCertificateContext(pDesiredCert);
  
  if not (CertDeleteCertificateFromStore(pCertCopy) ) then
    raise EElCertStorageError.Create(SUnableToDeleteCertificate)
  else
  begin
    CertFreeCertificateContext(FCtxList[Index]);
    FCtxList.Delete(Index);
    if Assigned(FList[Index]) then
      TObject(FList[Index]). Free ;
    FList.Delete(Index);
    FStoreIndexes.Delete(Index);
    FRebuildChains := true;
  end;
end;

procedure TElWinCertStorage.Open;
var
  hSystemStore : HCERTSTORE;
  pDesiredCert : PCCERT_CONTEXT;
  pContextCopy : PCCERT_CONTEXT;
  StrName : PWideChar;
  Len : integer;
  I, J : integer;
  Lst : TStringList;
  Rights : cardinal;
  Failure : boolean;
begin
  I := 0;

  if FStorageType <> stMemory then
    ClearInfo;
  if (FStores.Count = 0) and (FStorageType <> stMemory) then
    Exit;

  Rights := SetupAccessRights(FAccessType);

  if FReadOnly then
    Rights := Rights or CERT_STORE_READONLY_FLAG;

  Failure := true;
  FSharedResource.WaitToWrite;
  try
    pDesiredCert :=   nil  ;
    if FStorageType = stMemory then
    begin
      if Length(FSystemStoresCtx) <> 1 then
      begin
        hSystemStore := CertOpenStore(PAnsiChar(CERT_STORE_PROV_MEMORY), 0, 0, 0, nil);
        if hSystemStore <>   nil   then
        begin
          SetLength(FSystemStoresCtx, 1);
          FSystemStoresCtx[0] := hSystemStore;
          Failure := false;
        end;
      end
      else
      begin
        hSystemStore := FSystemStoresCtx[0];
        if hSystemStore <>   nil   then
        begin
          Failure := false;
          pDesiredCert := CertEnumCertificatesInStore(hSystemStore,   nil  );
          while pDesiredCert <>  nil  do
          begin
            pContextCopy := CertDuplicateCertificateContext(pDesiredCert);
            FCtxList.Add(pContextCopy);
            FStoreIndexes.Add( pointer( I ) );
            pDesiredCert := CertEnumCertificatesInStore(hSystemStore, pDesiredCert);
          end;
        end;
      end;
    end
    else
    if (FPhysicalStores.Count = 0) or
       (FStorageType in [stRegistry, stLDAP]) then
    begin
      SetLength(FSystemStoresCtx, FStores.Count);
      for I := 0 to FStores.Count - 1 do
      begin
        if FStorageType = stSystem then
        begin
          Len := (Length(FStores.Strings[I]) + 1) shl 1;
          GetMem(StrName, Len);
          try
            try
              StringToWideChar(FStores.Strings[I], StrName, Len shr 1);
              hSystemStore := CertOpenStore(PAnsiChar(CERT_STORE_PROV_SYSTEM), X509_ASN_ENCODING,
                0, {CERT_SYSTEM_STORE_CURRENT_USER}Rights, StrName);
            finally
              FreeMem(StrName);
            end;
          except
            hSystemStore := nil;
          end;
        end
        else
        if FStorageType = stRegistry then
        begin
          hSystemStore := OpenRegistryStore(FStores[I], Rights);
        end
        else if FStorageType = stLDAP then
        begin
          hSystemStore := OpenLDAPStore(FStores[I], Rights);
        end
        else
          hSystemStore :=   nil  ;

        FSystemStoresCtx[I] := hSystemStore;
        if hSystemStore <>   nil   then
        begin
          Failure := false;
          pDesiredCert := CertEnumCertificatesInStore(hSystemStore,   nil  );
          while pDesiredCert <>  nil  do
          begin
            pContextCopy := CertDuplicateCertificateContext(pDesiredCert);
            FCtxList.Add(pContextCopy);
            FStoreIndexes.Add( pointer( I ) );
            pDesiredCert := CertEnumCertificatesInStore(hSystemStore, pDesiredCert);
          end;
        end;
      end;
    end
    else
    begin
      SetLength(FSystemStoresCtx, FStores.Count * FPhysicalStores.Count);
      Lst := TElStringList.Create;
      try
        for I := 0 to FStores.Count - 1 do
          for J := 0 to FPhysicalStores.Count - 1 do
            Lst.Add(FStores.Strings[I] + '\' + FPhysicalStores.Strings[J]);

        for I := 0 to Lst.Count - 1 do
        begin
          Len := (Length(Lst.Strings[I]) + 1) shl 1;
          GetMem(StrName, Len);
          try
            StringToWideChar(Lst.Strings[I], StrName, Len shr 1);
            hSystemStore := CertOpenStore(PAnsiChar(CERT_STORE_PROV_PHYSICAL), X509_ASN_ENCODING,
              0, {CERT_SYSTEM_STORE_CURRENT_USER}Rights, StrName);
            FSystemStoresCtx[I] := hSystemStore;
            if Assigned(hSystemStore) then
            begin
              Failure := false;
              pDesiredCert := CertEnumCertificatesInStore(hSystemStore,  nil );
              while pDesiredCert <>  nil  do
              begin
                pContextCopy := CertDuplicateCertificateContext(pDesiredCert);
                FCtxList.Add(pContextCopy);
                FStoreIndexes.Add( pointer( I ) );
                pDesiredCert := CertEnumCertificatesInStore(hSystemStore, pDesiredCert);
              end;
            end;
          finally
            FreeMem(StrName);
          end;
        end;
      finally
        FreeAndNil(Lst);
      end;
    end;
    if pDesiredCert <> nil then
      CertFreeCertificateContext(pDesiredCert);
    FList.Count := FCtxList.Count;
    for I := 0 to FList.Count - 1 do
      FList[I] := nil;
    FRebuildChains := true;
  finally
    FSharedResource.Done;
  end;
  if Failure then
    raise EElCertStorageError.Create(SFailedToOpenStore);
end;

function CBF(pvSystemStore: Pointer; dwFlags: DWORD; pStoreInfo:
  PCERT_SYSTEM_STORE_INFO; pvReserved: Pointer; pvArg: Pointer): BOOL; stdcall;
begin
  TStringList(pvArg).Add(WideCharToString(pvSystemStore));
  Result := true;
end;


{$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
class procedure TElWinCertStorage.GetAvailableStores(Stores:  TStrings ;
  AccessType: TSBStorageAccessType  =  atCurrentUser);
var
  Instance : TElWinCertStorage;
begin
  Instance := TElWinCertStorage.Create(nil);
  try
    Instance.SSCGetAvailableStores(Stores, AccessType);
  finally
    FreeAndNil(Instance);
  end;
end;

procedure TElWinCertStorage.SCGetAvailableStores(Stores:  TStrings ;
  AccessType: TSBStorageAccessType  =  atCurrentUser);
 {$else}
class procedure TElWinCertStorage.GetAvailableStores(Stores:  TStrings ;
  AccessType: TSBStorageAccessType  =  atCurrentUser);
 {$endif}
var
  ModuleHandle: HMODULE;
  P: pointer;
  Flag: boolean;
  Rights : cardinal;
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  Stores.BeginUpdate;
  try
    Stores.Clear;
    Rights := SetupAccessRights(AccessType);
    Flag := true;
    ModuleHandle := GetModuleHandle({$ifdef SB_WINCE}PWideChar {$else}PChar {$endif}('crypt32.dll'));
    if ModuleHandle = 0 then
    begin
      ModuleHandle := LoadLibrary({$ifdef SB_WINCE}PWideChar {$else}PChar {$endif}('crypt32.dll'));
      if ModuleHandle = 0 then
      begin
        Flag := false;
      end
      else
      begin
        P := GetProcAddress(ModuleHandle, {$ifdef SB_WINCE}PWideChar {$else}PAnsiChar {$endif}('CertEnumSystemStore'));
        if not Assigned(P) then
          Flag := false;
      end;
    end;
    if (not Flag) or (not CertEnumSystemStore(Rights{CERT_SYSTEM_STORE_CURRENT_USER}, nil, Stores, CBF)) then
    begin
      Stores.Add('ROOT');
      Stores.Add('CA');
      Stores.Add('MY');
      Stores.Add('SPC');
    end;
  finally
    Stores.EndUpdate;
  end;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

function CBFPhysical(pvSystemStore: pointer; dwFlags : DWORD; pwszStoreName : PWideChar;
  pStoreInfo : PCERT_SYSTEM_STORE_INFO; pvReserver : pointer; pvArg : pointer) : BOOL; stdcall;
begin
  TStringList(pvArg).Add(PWideChar(pwszStoreName));
  Result := true;
end;

{$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
class procedure TElWinCertStorage.GetAvailablePhysicalStores(const SystemStore : string;
  Stores :  TStrings ;
  AccessType : TSBStorageAccessType  =  atCurrentUser);
var
  Instance : TElWinCertStorage;
begin
  Instance := TElWinCertStorage.Create(nil);
  try
    Instance.SSCGetAvailablePhysicalStores(SystemStore, Stores, AccessType);
  finally
    FreeAndNil(Instance);
  end;
end;

procedure TElWinCertStorage.SCGetAvailablePhysicalStores(const SystemStore: string;
  Stores:  TStrings ;
  AccessType: TSBStorageAccessType  =  atCurrentUser);
 {$else}
class procedure TElWinCertStorage.GetAvailablePhysicalStores(const SystemStore : string;
  Stores :  TStrings ;
  AccessType : TSBStorageAccessType  =  atCurrentUser);
 {$endif}
var
  S : PWideChar;
  Sz : integer;
  Rights : cardinal;
begin
  Stores.BeginUpdate;
  try
    Stores.Clear;
    Rights := SetupAccessRights(AccessType);
    Sz := (Length(SystemStore) + 1) shl 1;
    GetMem(S, Sz);
    StringToWideChar(SystemStore, S, Sz shr 1);
    CertEnumPhysicalStore(S, Rights{CERT_SYSTEM_STORE_CURRENT_USER},
      Stores, CBFPhysical);
    FreeMem(S);
  finally
    Stores.EndUpdate;
  end;
end;

function TElWinCertStorage.LoadPrivateKey(Cert : TElX509Certificate; Key : HCRYPTKEY) : boolean;
var
  KeyLen :  DWORD ;
  KeyBuf, EncKeyBuf : PBYTE;
  LenEnc : integer;
  BT, ErrCode : integer;
  //SessKey : HCRYPTKEY;
  //Hash : HCRYPTHASH;
  //Prov : HCRYPTPROV;
  //Password : ByteArray;
begin
  Result := true;
  if Cert = nil then
  begin
    result := false;
    exit;
  end;
  KeyLen := 0;

  {if (Cert.PublicKeyAlgorithm = SB_CERT_ALGORITHM_GOST_R3410_1994) or
    (Cert.PublicKeyAlgorithm = SB_CERT_ALGORITHM_GOST_R3410_2001)
  then
  begin

    CryptCreateHash(hProv, CALG_GR3411, 0, 0, @hHash);
    Password := 'password';
    Res := CryptHashData(hHash, @Password[1], Length(Password), 0);
    Res := CryptDeriveKey(hProv, CALG_G28147, hHash, CRYPT_EXPORTABLE, @hSessKey);
    algid := CALG_PRO_EXPORT;
    Res := CryptSetKeyParam(hSessKey, KP_ALGID, @algid, 0);

    !!
  end;}

  CryptExportKey(Key, 0, PRIVATEKEYBLOB, 0, nil, @KeyLen);
  GetMem(KeyBuf, KeyLen);
  try
    if CryptExportKey(Key, 0, PRIVATEKEYBLOB, 0, KeyBuf, @KeyLen) then
    begin
      LenEnc := 0;
      ParseMSKeyBlob(KeyBuf, KeyLen, nil, LenEnc, BT);
      GetMem(EncKeyBuf, LenEnc);
      ErrCode := ParseMSKeyBlob(KeyBuf, KeyLen, EncKeyBuf, LenEnc, BT);
      if ErrCode = 0 then
        Cert.LoadKeyFromBuffer(EncKeyBuf, LenEnc)
      else
        Result := false;
      FreeMem(EncKeyBuf);
    end
    else
      Result := false;
  finally
    FreeMem(KeyBuf);
  end;
end;

{$ifndef NET_CF}
{$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
class function TElWinCertStorage.GetStoreFriendlyName(const StoreName : string) : string;
var
  Instance : TElWinCertStorage;
begin
  Instance := TElWinCertStorage.Create(nil);
  try
    Result := Instance.SSCGetStoreFriendlyName(StoreName);
  finally
    FreeAndNil(Instance);
  end;
end;

function TElWinCertStorage.SCGetStoreFriendlyName(const StoreName : string) : string;
 {$else}
class function TElWinCertStorage.GetStoreFriendlyName(const StoreName : string) : string;
 {$endif}
var
  Buffer, Dest : PWideChar;
  Size : integer;
begin
  Size := (Length(StoreName) + 1) shl 1;
  GetMem(Buffer, Size);
  StringToWideChar(StoreName, Buffer, Size shr 1);
  Dest := CryptFindLocalizedName(Buffer);
  if Dest <> nil then
    Result := WideCharToString(Dest)
  else
    Result := '';
end;
 {$endif}

procedure TElWinCertStorage.SetPhysicalStores(const Value:  TStringList );
begin
  FPhysicalStores.Assign(Value);
end;

procedure TElWinCertStorage.SetStores(const Value:  TStringList );
begin
  FStores.Assign(Value);
end;

procedure TElWinCertStorage.SetPrivateKeyForCertificate(Context : PCCERT_CONTEXT;
  Cert : TElX509Certificate; Exportable : boolean = true; Protected : boolean = true);
var
  Prov: HCRYPTPROV;
  Key, SessKey: HCRYPTKEY;
  Hash : HCRYPTHASH;
  g : GUID;
  I : integer;
  ProvInfo: CRYPT_KEY_PROV_INFO;
  Size : integer;
  Err : longword;
  GuidStr : string;
  Buffer: ByteArray;

  Sz : integer;

  Buf, BlobBuf : ByteArray;
  ProvType : DWORD;
  Flags : integer;

  Tmp :  DWORD ;
  ProvStr : string;
  ProvPtr : PChar;
  FlagModifier : DWORD;
  Password : ByteArray;
  algid : ALG_ID;
begin
  SetLength(Password, 0);
  Sz := 0;
  SetLength(Buf, Sz);
  Cert.SaveKeyToBuffer(Buf, Sz);
  if Sz = 0 then
    raise EElCertStorageError.Create(SFailedToGetPrivateKey);
  SetLength(Buf, Sz);
  Cert.SaveKeyToBuffer(@Buf[0], Sz);
  SetLength(Buf, Sz);
  Prov := 0;
  CoCreateGuid(@g);
  GuidStr := '{' + IntToHex(g.Data1, 8) + '-' + IntToHex(g.Data2, 4) + '-' +
    IntToHex(g.Data3, 4) + '-' + IntToHex(g.Data4[0], 2) + IntToHex(g.Data4[1], 2) + '-';
  for I := 2 to 7 do
    GuidStr := GuidStr + (IntToHex(g.Data4[I], 2));
  GuidStr := GuidStr + '}';

  { only RSA, DSA and GOST 34.10 blobs are supported for now }
  if not ((Cert.PublicKeyAlgorithmIdentifier is TElRSAAlgorithmIdentifier) or
    (Cert.PublicKeyAlgorithmIdentifier is TElDSAAlgorithmIdentifier) {$ifdef SB_HAS_GOST}or
    (Cert.PublicKeyAlgorithmIdentifier is TElGOST3410AlgorithmIdentifier) {$endif})
  then
    raise EElCertStorageError.Create(SFailedToGetPrivateKey);

  if Cert.PublicKeyAlgorithm = SB_CERT_ALGORITHM_GOST_R3410_1994 then
  begin
    ProvStr := CP_GR3410_94_PROV;
    ProvType := PROV_GOST_94_DH;
  end
  else if Cert.PublicKeyAlgorithm = SB_CERT_ALGORITHM_GOST_R3410_2001 then
  begin
    ProvStr := CP_GR3410_2001_PROV;
    ProvType := PROV_GOST_2001_DH;
  end
  else
  begin
    ProvStr := GetProviderString(FProvider);
    ProvType := GetProviderType(FProvider, Cert.PublicKeyAlgorithm);
  end;
    
  if Length(ProvStr) > 0 then
  begin
    ProvStr := ProvStr + #0;
    ProvPtr := @ProvStr[StringStartOffset];
  end
  else
    ProvPtr := nil;

  if AccessType in [atLocalMachine,
                    atLocalMachineEnterprise,
                    atLocalMachineGroupPolicy,
                    atServices,
                    atUsers] then
    FlagModifier := CRYPT_MACHINE_KEYSET
  else
    FlagModifier := 0;

  if not CryptAcquireContext(@Prov, PChar(GuidStr), ProvPtr, ProvType, CRYPT_NEWKEYSET or FlagModifier) then
  begin
    err := GetLastError;
    raise EElCertStorageError.Create(SWin32Error + ' ' + IntToHex(err, 8));
  end;
  Size := 0;
  SBMSKeyBlob.WriteMSKeyBlobEx(@Buf[0], Length(Buf), nil, Size, Cert.PublicKeyAlgorithmIdentifier);
  SetLength(BlobBuf, Size);
  if not SBMSKeyBlob.WriteMSKeyBlobEx(@Buf[0], Length(Buf), @BlobBuf[0], Size, Cert.PublicKeyAlgorithmIdentifier) then
    raise EElCertStorageError.Create(SInvalidPrivateKey);
  Flags := 0;

  if Exportable then
    Flags := Flags or CRYPT_EXPORTABLE;
  if Protected then
    Flags := Flags or CRYPT_USER_PROTECTED;

  SetLength(BlobBuf, Size);

  if (Cert.PublicKeyAlgorithm = SB_CERT_ALGORITHM_GOST_R3410_1994) or
    (Cert.PublicKeyAlgorithm = SB_CERT_ALGORITHM_GOST_R3410_2001)
  then
  begin
    { not checking result - if any is false, we will fail on import }
    CryptCreateHash(Prov, CALG_GR3411, 0, 0, @Hash);
    Password := BytesOfString('password');
    CryptHashData(Hash, @Password[0], Length(Password), 0);
    CryptDeriveKey(Prov, CALG_G28147, Hash, CRYPT_EXPORTABLE,  @SessKey );
    algid := CALG_PRO_EXPORT;
    CryptSetKeyParam(SessKey, KP_ALGID, @algid, 0);

    if not CryptImportKey(Prov, @BlobBuf[0], Length(BlobBuf), SessKey, 0, @Key) then
    begin
      err :=  GetLastError ;
      CryptDestroyHash(Hash);
      CryptDestroyKey(SessKey);
      CryptReleaseContext(Prov, 0);
      raise EElCertStorageError.Create(SWin32Error + ' ' +  IntToHex(err, 8) );
    end;

    CryptDestroyHash(Hash);
    CryptDestroyKey(SessKey);
  end
  else
  begin
    if not CryptImportKey(Prov, @BlobBuf[0], Length(BlobBuf), 0,
      Flags, @Key) then
    begin
      err :=  GetLastError ;
      CryptReleaseContext(Prov, 0);
      raise EElCertStorageError.Create(SWin32Error + ' ' +  IntToHex(err, 8) );
    end;         
  end;
  FillChar(ProvInfo, SizeOf(ProvInfo), 0);
  I := Length(GuidStr) + 1; // string length + 1 for #0
  //I := Length(GuidStr) * 2 + 4;
  GetMem(ProvInfo.pwszContainerName, I * SizeOf(WideChar));
  FillChar(ProvInfo.pwszContainerName^, I * SizeOf(WideChar), 0);
  {$ifndef SB_UNICODE_VCL}
  MultiByteToWideChar(CP_ACP, 0, PAnsiChar(GuidStr), Length(GuidStr), ProvInfo.pwszContainerName, I);
   {$else}
  StrCopy(ProvInfo.pwszContainerName, PChar(GuidStr));
   {$endif}
  Tmp := 0;
  CryptGetProvParam(Prov, PP_NAME, nil, @Tmp, 0);
  SetLength(Buffer, Tmp);
  CryptGetProvParam(Prov, PP_NAME, @Buffer[0], @Tmp, 0);
  SetLength(Buffer, Tmp);
  I := Length(Buffer) + 1;
  GetMem(ProvInfo.pwszProvName, I * SizeOf(WideChar));
  FillChar(ProvInfo.pwszProvName^, I * SizeOf(WideChar), 0);
  MultiByteToWideChar(CP_ACP, 0, PAnsiChar(@Buffer[0]), Length(Buffer), ProvInfo.pwszProvName, I);
  ProvInfo.rgProvParam :=  nil ;
  ProvInfo.dwProvType := ProvType;
  ProvInfo.dwFlags := FlagModifier;
  ProvInfo.cProvParam := 0;
  ProvInfo.dwKeySpec := AT_KEYEXCHANGE;
  if not CertSetCertificateContextProperty(Context, CERT_KEY_PROV_INFO_PROP_ID, 0, @ProvInfo) then
  begin
    err := GetLastError;
    FreeMem(ProvInfo.pwszProvName);
    FreeMem(ProvInfo.pwszContainerName);
    CryptDestroyKey(Key);
    CryptReleaseContext(Prov, 0);
    raise EElCertStorageError.Create(SWin32Error + ' ' + IntToHex(err, 8));
  end;
  FreeMem(ProvInfo.pwszProvName);
  FreeMem(ProvInfo.pwszContainerName);
  CryptDestroyKey(Key);
  CryptReleaseContext(Prov, 0);
end;

procedure TElWinCertStorage.SetPrivateKeyForCertificate(Context :   PCCERT_CONTEXT  ;
  const ProvName, ContName: string; ProvType, KeySpec : DWORD); 
var
  ProvInfo: CRYPT_KEY_PROV_INFO;
  I : integer;
  FlagModifier : DWORD; 
  Tmp :  DWORD ;
  err : integer;
  Prov : HCRYPTPROV;
  AnsiProvName : AnsiString;
  CurrProvName : string;
begin
  CurrProvName := ProvName;
  if AccessType in [atLocalMachine,
                    atLocalMachineEnterprise,
                    atLocalMachineGroupPolicy,
                    atServices,
                    atUsers] then
    FlagModifier := CRYPT_MACHINE_KEYSET
  else
    FlagModifier := 0;
  FillChar(ProvInfo, SizeOf(ProvInfo), 0);
  I := Length(ContName) + 1; // string length + 1 for #0
  GetMem(ProvInfo.pwszContainerName, I * SizeOf(WideChar));
  FillChar(ProvInfo.pwszContainerName^, I * SizeOf(WideChar), 0);
  {$ifndef SB_UNICODE_VCL}
  MultiByteToWideChar(CP_ACP, 0, PAnsiChar(ContName), Length(ContName), ProvInfo.pwszContainerName, I);
   {$else}
  StrCopy(ProvInfo.pwszContainerName, PChar(ContName));
   {$endif}

  // ---------------
  if Length(CurrProvName) = 0 then
  begin
    if not CryptAcquireContext(@Prov, PChar(ContName), nil, ProvType, FlagModifier) then
    begin
      err := GetLastError;
      raise EElCertStorageError.Create(SWin32Error + ' ' + IntToHex(err, 8));
    end;
    Tmp := 0;
    CryptGetProvParam(Prov, PP_NAME, nil, @Tmp, 0);
    SetLength(AnsiProvName, Tmp);
    CryptGetProvParam(Prov, PP_NAME, @AnsiProvName[AnsiStrStartOffset], @Tmp, 0);
    SetLength(AnsiProvName, Tmp);
    CurrProvName := String(AnsiProvName);
    CryptReleaseContext(Prov, 0);
  end;


  // ---------------


  if Length(CurrProvName) > 0 then
  begin
    I := Length(CurrProvName) + 1; // string length + 1 for #0
    GetMem(ProvInfo.pwszProvName, I * SizeOf(WideChar));
    FillChar(ProvInfo.pwszProvName^, I * SizeOf(WideChar), 0);
    {$ifndef SB_UNICODE_VCL}
    MultiByteToWideChar(CP_ACP, 0, PAnsiChar(CurrProvName), Length(CurrProvName), ProvInfo.pwszProvName, I);
     {$else}
    StrCopy(ProvInfo.pwszProvName, PChar(CurrProvName));
     {$endif}
  end
  else
    ProvInfo.pwszProvName := nil;
  ProvInfo.dwProvType := ProvType;
  ProvInfo.dwFlags := FlagModifier;
  ProvInfo.cProvParam := 0;
  ProvInfo.rgProvParam :=  nil ;
  ProvInfo.dwKeySpec := AT_KEYEXCHANGE;
  if not CertSetCertificateContextProperty(Context, CERT_KEY_PROV_INFO_PROP_ID, 0, @ProvInfo) then
  begin
    err := GetLastError;
    FreeMem(ProvInfo.pwszProvName);
    FreeMem(ProvInfo.pwszContainerName);
    raise EElCertStorageError.Create(SWin32Error + ' ' + IntToHex(err, 8));
  end;
  FreeMem(ProvInfo.pwszProvName);
  FreeMem(ProvInfo.pwszContainerName);
end;

procedure TElWinCertStorage.SetStorageType(Value: TSBStorageType);
begin
  if FStorageType <> Value then
  begin
    FStorageType := Value;
    if (FStores.Count > 0) or (FStorageType = stMemory) then
      HandleStoresChange(nil);
  end;
end;

procedure TElWinCertStorage.SetAccessType(Value: TSBStorageAccessType);
begin
  if FAccessType <> Value then
  begin
    FAccessType := Value;
    if FStores.Count > 0 then
      HandleStoresChange(nil);
  end;
end;

function TElWinCertStorage.OpenRegistryStore(const Name : string; UserRights: cardinal) : HCERTSTORE;
var
  SrcKey : HKEY;
  I, Index : integer;
  RestOfKey: string;
const
  RegKeyCount = 5;
  RegStrings : array[0..4] of string =  ( 
    'HKEY_CLASSES_ROOT', 'HKEY_CURRENT_CONFIG',
    'HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE', 'HKEY_USERS'
     ) ;

{$ifdef FPC}
var
 {$endif}
  RegKeys : array[0..4] of HKEY
          {$ifndef FPC}
          =  ( 
              HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER,
              HKEY_LOCAL_MACHINE, HKEY_USERS
             ) 
           {$endif}
    ;
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  {$ifdef FPC}
  RegKeys[0] := HKEY_CLASSES_ROOT;
  RegKeys[1] := HKEY_CURRENT_CONFIG;
  RegKeys[2] := HKEY_CURRENT_USER;
  RegKeys[3] := HKEY_LOCAL_MACHINE;
  RegKeys[4] := HKEY_USERS;
   {$endif}

  SrcKey := 0;

  Index := -1;
  Result :=   nil  ;
  for I := 0 to RegKeyCount - 1 do    
    if StringIndexOf(Name, RegStrings[I]) >= StringStartOffset then
    begin
      Index := I;
      RestOfKey := StringSubstring(Name, StringStartOffset + 1 + Length(RegStrings[I]));
      Break;
    end;

  if Index = -1 then
    Exit;

  if RegOpenKeyEx(RegKeys[Index], {$ifdef SB_WINCE}PWideChar {$else}PChar {$endif}(RestOfKey), 0, KEY_READ, SrcKey) <> ERROR_SUCCESS then
    Exit;
  try
    Result := CertOpenStore(PAnsiChar(CERT_STORE_PROV_REG), X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
      0, UserRights or CERT_STORE_OPEN_EXISTING_FLAG, pointer(SrcKey));
  except
    Result :=   nil  ;
  end;
  RegCloseKey(SrcKey);
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;

function TElWinCertStorage.OpenLDAPStore(const Name : string; UserRights : cardinal) : HCERTSTORE;
var
  WideStr : pointer;
  Len : integer;
begin
  Len := (Length(Name) + 1) shl 1;
  GetMem(WideStr, Len);
  try
    StringToWideChar(Name, WideStr, Len shr 1);
    Result := CertOpenStore(PAnsiChar(CERT_STORE_PROV_LDAP), X509_ASN_ENCODING or PKCS_7_ASN_ENCODING,
      0, UserRights or CERT_STORE_OPEN_EXISTING_FLAG, WideStr);
  finally
    FreeMem(WideStr);
  end;
end;

class function TElWinCertStorage.SetupAccessRights(Access : TSBStorageAccessType) : cardinal;
begin
  case Access of
    atCurrentService : Result := CERT_SYSTEM_STORE_CURRENT_SERVICE;
    atCurrentUser : Result := CERT_SYSTEM_STORE_CURRENT_USER;
    atCurrentUserGroupPolicy : Result := CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY;
    atLocalMachine : Result := CERT_SYSTEM_STORE_LOCAL_MACHINE;
    atLocalMachineEnterprise : Result := CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE;
    atLocalMachineGroupPolicy : Result := CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY;
    atServices : Result := CERT_SYSTEM_STORE_SERVICES;
    atUsers : Result := CERT_SYSTEM_STORE_USERS;
  else
    Result := 0;
  end;
end;

class function TElWinCertStorage.GetProviderString(Prov : TSBStorageProviderType) : string;
begin
  case Prov of
    ptDefault : Result := '';
    ptBaseDSSDH : Result := MS_DEF_DSS_DH_PROV;
    ptBaseDSS : Result := MS_DEF_DSS_PROV;
    ptBase : Result := MS_DEF_PROV;
    ptRSASchannel : Result := MS_DEF_RSA_SCHANNEL_PROV;
    ptRSASignature : Result := MS_DEF_RSA_SIG_PROV;
    ptEnhancedDSSDH : Result := MS_ENH_DSS_DH_PROV;
    ptEnhancedRSAAES : Result := MS_ENH_RSA_AES_PROV;
    ptEnhanced : Result := MS_ENHANCED_PROV;
    ptBaseSmartCard : Result := MS_SCARD_PROV;
    ptStrong : Result := MS_STRONG_PROV;
    ptCryptoProGOST94 : Result := CP_GR3410_94_PROV;
    ptCryptoProGOST2001 : Result := CP_GR3410_2001_PROV;
  else
    Result := '';
  end;
end;

class function TElWinCertStorage.GetProviderType(Prov : TSBStorageProviderType;
  Alg : integer) : DWORD;
begin
  case Prov of
    ptBaseDSSDH :
      Result := PROV_DSS_DH;
    ptBaseDSS :
      Result := PROV_DSS;
    ptRSASchannel :
      Result := PROV_RSA_SCHANNEL;
    ptRSASignature :
      Result := PROV_RSA_SIG;
    ptEnhancedDSSDH :
      Result := PROV_DSS_DH;
    ptEnhancedRSAAES :
      Result := PROV_RSA_AES;
    ptCryptoProGOST94 :
      Result := PROV_GOST_94_DH;
    ptCryptoProGOST2001 :
      Result := PROV_GOST_2001_DH;
    else
    begin
      if Alg = SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION then
        Result := PROV_RSA
      else if Alg = SB_CERT_ALGORITHM_ID_DSA then
        Result := PROV_DSS
      else if Alg = SB_CERT_ALGORITHM_GOST_R3410_1994 then
        Result := PROV_GOST_94_DH
      else if Alg = SB_CERT_ALGORITHM_GOST_R3410_2001 then
        Result := PROV_GOST_2001_DH
      else
        Result := PROV_DSS_DH;
    end;
  end;
end;

procedure TElWinCertStorage.Refresh;
begin
  if not (csDesigning in ComponentState) then
    Open;
end;

procedure TElWinCertStorage.CreateStore(const StoreName: string);
var
  hSystemStore : HCERTSTORE;
  Rights: cardinal;
  WideStr : PWideChar;
  Len : integer;
  Err : integer;
begin
  Rights := SetupAccessRights(FAccessType);

  if FReadOnly then
    Rights := Rights or CERT_STORE_READONLY_FLAG;

  Len := (Length(StoreName) + 1) shl 1;
  GetMem(WideStr, Len);
  try
    StringToWideChar(StoreName, WideStr, Len shr 1);
    hSystemStore := CertOpenStore(PAnsiChar(CERT_STORE_PROV_SYSTEM), X509_ASN_ENCODING or
      PKCS_7_ASN_ENCODING, 0, Rights or CERT_STORE_CREATE_NEW_FLAG, WideStr);
  finally
    FreeMem(WideStr);
  end;

  if hSystemStore <> nil then
    CertCloseStore(hSystemStore, 0)
  else
  begin
    Err := GetLastError();
      raise EElCertStorageError.Create(SWin32Error + ' ' + IntToHex(err, 8));
  end;
end;

procedure TElWinCertStorage.DeleteStore(const StoreName: string);
var
  Rights: cardinal;
  WideStr : PWideChar;
  Len : integer;
  Err : integer;
begin
  Rights := SetupAccessRights(FAccessType);

  if FReadOnly then
    Rights := Rights or CERT_STORE_READONLY_FLAG;

  Len := (Length(StoreName) + 1) shl 1;
  GetMem(WideStr, Len);
  try
    StringToWideChar(StoreName, WideStr, Len shr 1);
    CertOpenStore(PAnsiChar(CERT_STORE_PROV_SYSTEM), X509_ASN_ENCODING or
      PKCS_7_ASN_ENCODING, 0, Rights or CERT_STORE_DELETE_FLAG, WideStr);
  finally
    FreeMem(WideStr);
  end;

  Err := GetLastError();
  if Err <> 0 then
    raise EElCertStorageError.Create(SWin32Error + ' ' + IntToHex(err, 8));
end;


function TElWinCertStorage.GetSuitableCryptoProvider : TElCustomCryptoProvider;
begin
  if Assigned(FCryptoProvider) then
    Result := FCryptoProvider
  else
    Result := Win32CryptoProvider;
end;

procedure TElWinCertStorage.PreloadCertificates;
var i : integer;
begin
  for i := 0 to Count - 1 do
     GetCertificates (i);
end;

procedure TElWinCertStorage.ListKeyContainers(List : TElStringList; ProvType : TSBStorageProviderType);
var
  ProvTp : DWORD;
  ProvStr :  AnsiString ;
  FlagModifier : DWORD;
  Prov : HCRYPTPROV;
  ProvPtr :   pointer  ;
  err : integer;
  res : BOOL;
  ContName :   pointer  ;
  ContNameLen :  DWORD ;
  ContNameStr :  AnsiString ;
begin
  ProvStr := {$ifdef SB_UNICODE_VCL}AnsiString {$endif}(GetProviderString(FProvider));
  if FProvider = ptDefault then
    ProvTp := PROV_RSA
  else
    ProvTp := GetProviderType(FProvider, SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION);
  if Length(ProvStr) > 0 then
  begin
    ProvStr := ProvStr + #0;
    ProvPtr := @ProvStr[AnsiStrStartOffset];
  end
  else
    ProvPtr := nil;

  if AccessType in [atLocalMachine,
                    atLocalMachineEnterprise,
                    atLocalMachineGroupPolicy,
                    atServices,
                    atUsers] then
    FlagModifier := CRYPT_MACHINE_KEYSET
  else
    FlagModifier := 0;
  FlagModifier := FlagModifier or CRYPT_VERIFYCONTEXT;

  if not CryptAcquireContext(@Prov, nil, ProvPtr, ProvTp, FlagModifier) then
  begin
    err := GetLastError;
    raise EElCertStorageError.Create(SWin32Error + ' ' + IntToHex(err, 8));
  end;
  try
    ContNameLen := 0;
    CryptGetProvParam(Prov, PP_ENUMCONTAINERS, nil, @ContNameLen, CRYPT_FIRST);
    GetMem(ContName, ContNameLen);
    try
      res := CryptGetProvParam(Prov, PP_ENUMCONTAINERS, ContName,  @ ContNameLen, CRYPT_FIRST);
      if res then
        ContNameStr := PAnsiChar(ContName);
    finally
      FreeMem(ContName);
    end;
    while res  do
    begin
      List.Add(String(ContNameStr));
      ContNameLen := 0;
      CryptGetProvParam(Prov, PP_ENUMCONTAINERS, nil, @ContNameLen, CRYPT_NEXT);
      GetMem(ContName, ContNameLen);
      try
        res := CryptGetProvParam(Prov, PP_ENUMCONTAINERS, ContName,  @ ContNameLen, CRYPT_NEXT);
        if res  then
          ContNameStr := PAnsiChar(ContName);
      finally
        FreeMem(ContName);
      end;
    end;
  finally
    CryptReleaseContext(Prov, 0);
  end;
end;

procedure TElWinCertStorage.ListKeyContainers(List : TElStringList);
begin
  ListKeyContainers(List, FProvider);
end;


procedure TElWinCertStorage.DeleteKeyContainer(const ContainerName: string);
var
  Fake : HCRYPTPROV;
  ProvName : string;
  ProvTp : DWORD;
  err : integer;
  FlagModifier : DWORD;
begin
  // deleting the context
  if Length(ContainerName) <> 0 then
  begin
    if AccessType in [atLocalMachine,
                    atLocalMachineEnterprise,
                    atLocalMachineGroupPolicy,
                    atServices,
                    atUsers] then
      FlagModifier := CRYPT_MACHINE_KEYSET
    else
      FlagModifier := 0;
    ProvName := GetProviderString(FProvider);
    ProvTp := GetProviderType(FProvider, SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION);
    if not CryptAcquireContext(@Fake, PChar(ContainerName), PChar(ProvName), ProvTp, CRYPT_DELETEKEYSET or FlagModifier) then
    begin
      err := GetLastError;
      raise EElCertStorageError.Create(SWin32Error + ' ' + IntToHex(err, 8));
    end;
  end;
end;

{$ifdef SB_HAS_CRYPTUI}
function TElWinCertStorage.CertContextToSBB(Ctx :  PCCERT_CONTEXT ) : TElX509Certificate;
begin
  Result := nil;
  
  
  if Ctx =  nil  then
    Exit;
  
  Result := TElX509Certificate.Create(nil);
  try
    Result.CryptoProvider := GetSuitableCryptoProvider();
    Result.CertStorage := Self;
    Result.StorageName := '';
    try
      Result.LoadFromBuffer(Ctx^.pbCertEncoded, Ctx.cbCertEncoded);
    except
      ;
    end;
    Result.CertHandle := CertDuplicateCertificateContext(Ctx);
    Result.BelongsTo := BT_WINDOWS;
  except
    FreeAndNil(Result);
  end;
end;

function TElWinCertStorage.Select(Owner : HWND; SelectedList : TElCustomCertStorage) : boolean;
var
  pcsc : CRYPTUI_SELECTCERTIFICATE_STRUCT;
  hSelectedCertStore : HCERTSTORE;
  Cert : TElX509Certificate;
  Cnt : integer;
  Res :  Pointer ;
begin
  Result := false;
  

  hSelectedCertStore := CertOpenStore(PAnsiChar(CERT_STORE_PROV_MEMORY), 0, 0, 0, nil);
  if hSelectedCertStore <>   nil   then
  try
    try
      pcsc.dwSize :=  SizeOf (pcsc);
      pcsc.hwndParent := Owner;
      pcsc.dwFlags := 1; // CRYPTUI_SELECTCERT_MULTISELECT
      pcsc.szTitle := nil;
      pcsc.dwDontUseColumn := 0;
      pcsc.szDisplayString := nil;
      pcsc.pFilterCallback :=   nil  ;
      pcsc.pDisplayCallback :=   nil  ;
      pcsc.pvCallbackData :=   nil  ;
      pcsc.cDisplayStores := Length(FSystemStoresCtx);
      pcsc.rghDisplayStores := @FSystemStoresCtx[0];
      pcsc.cStores := Length(FSystemStoresCtx);
      pcsc.rghStores := pcsc.rghDisplayStores;
      pcsc.cPropSheetPages := 0;
      pcsc.rgPropSheetPages :=  nil ;
      pcsc.hSelectedCertStore := hSelectedCertStore;
      
      CryptUIDlgSelectCertificate(@pcsc);
      
      Cnt := 0;
      
      Res := CertEnumCertificatesInStore(hSelectedCertStore,  nil );
      repeat
        Cert := CertContextToSBB(Res);
        if Cert <> nil then
        begin
          SelectedList.Add(Cert, true);
          Inc(Cnt);
          FreeAndNil(Cert);
        end;
        
        Res := CertEnumCertificatesInStore(hSelectedCertStore, Res);
      until Res =  nil ;
      
      Result := Cnt > 0;
    finally
    end;
  finally
    CertCloseStore(hSelectedCertStore, 0);
  end
end;

class function TElWinCertStorage.ImportWizard(Owner : HWND) : boolean;
begin
  Result := CryptUIWizImport(0, Owner, nil, nil,   nil  ) ;
end;

 {$endif}

 {$endif}

end.
