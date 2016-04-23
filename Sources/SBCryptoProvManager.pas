(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBCryptoProvManager;

interface

uses
  Classes,
  SBTypes,
  SBUtils,
  SBSharedResource,
  SBCryptoProv;


type
  TSBCryptoEngineType = (cetDefault, cetFIPS, cetCustom);

  // Default cryptoprovider manager, based on automatically created
  // cryptoprovider objects. Only a single instance of this class should
  // be created to prevent global cryptoproviders from being used from
  // subsequent instances.
  // Please note that built-in provider supports both 'normal' and 'fips-compliant' modes.
  // This has been done intentionally for the ease of converting the whole project
  // to a fips-compliant one.
  TElBuiltInCryptoProviderManager = class(TElCustomCryptoProviderManager)
  private
    FEngineType : TSBCryptoEngineType;

    function GetBuiltInCryptoProvider : TElCustomCryptoProvider;
    function GetWin32CryptoProvider : TElCustomCryptoProvider;
    procedure SetEngineType(Value : TSBCryptoEngineType);
  protected
  public
    procedure Init(); override;
    procedure Deinit(); override;
    function IsProviderAllowed(Prov : TElCustomCryptoProvider): boolean; override;
    // FIPS mode-related properties
    property EngineType : TSBCryptoEngineType read FEngineType write SetEngineType;
    // automatically registered providers
    property BuiltInCryptoProvider : TElCustomCryptoProvider read GetBuiltInCryptoProvider;
    property Win32CryptoProvider : TElCustomCryptoProvider read GetWin32CryptoProvider;
  end;

  // FIPS-compliant cryptoprovider manager
  TElFIPSCompliantCryptoProviderManager = class(TElCustomCryptoProviderManager)
  protected
    FFIPSCompliantCryptoProvider : TElCustomCryptoProvider;
  public
    procedure Init(); override;
    procedure Deinit(); override;
    function IsProviderAllowed(Prov : TElCustomCryptoProvider): boolean; override;
  end;

  EElCryptoProviderManagerError = class(EElCryptoProviderError);

function DefaultCryptoProviderManager : TElBuiltInCryptoProviderManager; 
{$ifndef MONO}
{$ifdef SB_WINDOWS}
function FIPSCompliantCryptoProviderManager : TElFIPSCompliantCryptoProviderManager; 
 {$endif}
 {$endif}

implementation

uses
  SBCryptoProvBuiltIn
  {$ifndef SB_NO_IDEA}
  , SBCryptoProvBuiltInEx
   {$endif}
  {$ifdef SB_HAS_WINCRYPT}
  , SBCryptoProvWin32
   {$endif}
  ;

////////////////////////////////////////////////////////////////////////////////
// TElBuiltInCryptoProviderManager class

procedure TElBuiltInCryptoProviderManager.Init();
begin
  inherited;
  {$ifndef SB_NO_IDEA}
  RegisterCryptoProvider(SBCryptoProvBuiltInEx.BuiltInCryptoProviderEx);
   {$else}
  RegisterCryptoProvider(SBCryptoProvBuiltIn.BuiltInCryptoProvider);   
   {$endif}
  {$ifdef SB_HAS_WINCRYPT}
  {$ifdef SILVERLIGHT}
  if SBUtils.ElevatedPermissionsAvailable then
   {$endif}
  RegisterCryptoProvider(SBCryptoProvWin32.Win32CryptoProvider);
   {$endif}
  {$ifndef SB_NO_IDEA}
  FDefaultProvider := BuiltInCryptoProviderEx;
   {$else}
  FDefaultProvider := BuiltInCryptoProvider;
   {$endif}  
  FEngineType := cetDefault;
end;

procedure TElBuiltInCryptoProviderManager.Deinit();
begin
  inherited;
end;

function TElBuiltInCryptoProviderManager.GetBuiltInCryptoProvider : TElCustomCryptoProvider;
var
  I : integer;
begin
  // Please notice that the method returns either TElBuiltInCryptoProvider
  // or TElBuiltInExCryptoProvider, as the latter is the descendant of the former one.
  // This was done intentionally, as both ones are actually the same provider.
  Result := nil;
  FLock.WaitToRead;
  try
    for I := 0 to FProviders.Count - 1 do
      if (TElCustomCryptoProvider(FProviders[I]).Enabled) and (TElCustomCryptoProvider(FProviders[I]) is TElBuiltInCryptoProvider) then
      begin
        Result := TElCustomCryptoProvider(FProviders[I]);
        Break;
      end;
  finally
    FLock.Done;
  end;
end;

function TElBuiltInCryptoProviderManager.GetWin32CryptoProvider : TElCustomCryptoProvider;
{$ifdef SB_HAS_WINCRYPT}
var
  I : integer;
 {$endif}
begin
  Result := nil;
  {$ifdef SB_HAS_WINCRYPT}
  FLock.WaitToRead;
  try
    for I := 0 to FProviders.Count - 1 do
      if (TElCustomCryptoProvider(FProviders[I]).Enabled) and (TElCustomCryptoProvider(FProviders[I]) is TElWin32CryptoProvider) then
      begin
        Result := TElCustomCryptoProvider(FProviders[I]);
        Break;
      end;
  finally
    FLock.Done;
  end;
   {$endif}
end;

procedure TElBuiltInCryptoProviderManager.SetEngineType(Value : TSBCryptoEngineType);
var
  I : integer;
  Prov : TElCustomCryptoProvider;
begin
  if Value <> FEngineType then
  begin
    if Value = cetDefault then
    begin
      for I := 0 to FProviders.Count - 1 do
      begin
        Prov := TElCustomCryptoProvider(FProviders[I]); 
        {$ifdef SB_HAS_WINCRYPT}
        if Prov is TElWin32CryptoProvider then
        begin
          TElWin32CryptoProviderOptions(Prov.Options).FIPSMode := false;
          TElWin32CryptoProviderOptions(Prov.Options).UseForPublicKeyOperations := true;
          TElWin32CryptoProviderOptions(Prov.Options).UseForSymmetricKeyOperations := false;
          TElWin32CryptoProviderOptions(Prov.Options).UseForHashingOperations := false;
          TElWin32CryptoProviderOptions(Prov.Options).UseForNonPrivateOperations := false;
        end;
         {$endif}
        Prov.Enabled := true;
      end;  
      FDefaultProvider := BuiltInCryptoProvider;
    {$ifdef SB_HAS_WINCRYPT}
    end
    else
    if Value = cetFIPS then
    begin
      for I := 0 to FProviders.Count - 1 do
      begin
        Prov := TElCustomCryptoProvider(FProviders[I]);
        if Prov is TElWin32CryptoProvider then
        begin
          Prov.Enabled := true;
          TElWin32CryptoProviderOptions(Prov.Options).FIPSMode := true;
          TElWin32CryptoProviderOptions(Prov.Options).UseForPublicKeyOperations := true;
          TElWin32CryptoProviderOptions(Prov.Options).UseForSymmetricKeyOperations := true;
          TElWin32CryptoProviderOptions(Prov.Options).UseForHashingOperations := true;
          TElWin32CryptoProviderOptions(Prov.Options).UseForNonPrivateOperations := true;
        end
        else
        Prov.Enabled := false;
      end;
      FDefaultProvider := SBCryptoProvWin32.Win32CryptoProvider;
     {$endif}
    end;
    FEngineType := Value;
  end;
end;

function TElBuiltInCryptoProviderManager.IsProviderAllowed(Prov : TElCustomCryptoProvider): boolean;
begin
  {$ifdef SB_HAS_WINCRYPT}
  if FEngineType = cetFIPS then
    Result := (Prov is TElWin32CryptoProvider) and (TElWin32CryptoProviderOptions(Prov.Options).FIPSMode)
  else
   {$endif}
    Result := true;
end;

////////////////////////////////////////////////////////////////////////////////
// TElFIPSCompliantCryptoProviderManager class

procedure TElFIPSCompliantCryptoProviderManager.Init();
{$ifdef SB_HAS_WINCRYPT}
var
  Prov : TElCustomCryptoProvider;
 {$endif}
begin
  inherited;
  {$ifdef SB_HAS_WINCRYPT}
  
  Prov := TElWin32CryptoProvider.Create( nil );
  Prov.Enabled := true;
  TElWin32CryptoProviderOptions(Prov.Options).FIPSMode := true;
  TElWin32CryptoProviderOptions(Prov.Options).UseForPublicKeyOperations := true;
  TElWin32CryptoProviderOptions(Prov.Options).UseForSymmetricKeyOperations := true;
  TElWin32CryptoProviderOptions(Prov.Options).UseForHashingOperations := true;
  TElWin32CryptoProviderOptions(Prov.Options).UseForNonPrivateOperations := true;
  FFIPSCompliantCryptoProvider := Prov;
  RegisterCryptoProvider(Prov);
   {$endif}
end;

procedure TElFIPSCompliantCryptoProviderManager.Deinit();
begin
  FDefaultProvider := nil;
  {$ifndef MONO}
  {$ifdef SB_WINDOWS}
  UnregisterCryptoProvider(FFIPSCompliantCryptoProvider);
  FreeAndNil(FFIPSCompliantCryptoProvider);
   {$endif}
   {$endif}
  inherited;
end;

{$hints off}
function TElFIPSCompliantCryptoProviderManager.IsProviderAllowed(Prov : TElCustomCryptoProvider): boolean;
begin
  Result := true;
{$ifdef SB_HAS_WINCRYPT}
  Result := (Prov is TElWin32CryptoProvider) and (TElWin32CryptoProviderOptions(Prov.Options).FIPSMode);
 {$endif}
end;
{$hints on}

////////////////////////////////////////////////////////////////////////////////
// Global functions

var
  G_DefaultManager : TElBuiltInCryptoProviderManager;
{$ifndef MONO}
{$ifdef SB_WINDOWS}
  G_FIPSCompliantManager : TElFIPSCompliantCryptoProviderManager;
 {$endif}
 {$endif}

function DefaultCryptoProviderManager : TElBuiltInCryptoProviderManager;
begin
  if G_DefaultManager = nil then
  begin
    G_DefaultManager := TElBuiltInCryptoProviderManager.Create({$ifndef SB_NO_COMPONENT}nil {$endif});
    RegisterGlobalObject(G_DefaultManager);
  end;
  Result := G_DefaultManager;
end;

{$ifndef MONO}
{$ifdef SB_WINDOWS}
function FIPSCompliantCryptoProviderManager : TElFIPSCompliantCryptoProviderManager;
begin
  if G_FIPSCompliantManager = nil then
  begin
    G_FIPSCompliantManager := TElFIPSCompliantCryptoProviderManager.Create({$ifndef SB_NO_COMPONENT}nil {$endif});
    RegisterGlobalObject(G_FIPSCompliantManager);
  end;
  Result := G_FIPSCompliantManager;
end;
 {$endif}
 {$endif}

initialization

finalization


end.
