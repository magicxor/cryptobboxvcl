(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBCryptoProvBuiltInEx;

interface

uses
  SBCryptoProv,
  SBCryptoProvBuiltIn,
  SBCryptoProvBuiltInSym,
  SBCryptoProvRS,
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBConstants,
  SysUtils,
  Classes,
  SBIDEA;

type
  TElBuiltInExtendedCryptoProvider = class(TElBuiltInCryptoProvider)
  protected
    function CreateSymmetricCryptoFactory : TObject; override;
  public
    function GetDefaultInstance : TElCustomCryptoProvider; override;
    class procedure SetAsDefault; override;
  end;

  TElBuiltInExtendedSymmetricCryptoFactory = class(TElBuiltInSymmetricCryptoFactory)
  protected
    procedure RegisterDefaultClasses; override;
  end;

  {$ifndef SB_NO_IDEA}
  TElBuiltInIDEASymmetricCrypto = class(TElBuiltInSymmetricCrypto)
  protected
    FKey : TIDEAExpandedKey;
    procedure SetKeyMaterial(Material : TElCustomCryptoKey); override;
    procedure EncryptBlock8(var B0, B1 : cardinal); override;
    procedure DecryptBlock8(var B0, B1 : cardinal); override;
    class function IsAlgorithmSupported(AlgID : integer) : boolean;  overload;  override;
    class function IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(AlgID : integer; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
    class procedure GetDefaultKeyAndBlockLengths(const OID : ByteArray; var KeyLen : integer;
      var BlockLen : integer);  overload;  override;
  public
    constructor Create(AlgID : integer;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(const AlgOID : ByteArray;
      Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
    constructor Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);  overload;  override;
        
    procedure InitializeEncryption; override;
    procedure InitializeDecryption; override;
  end;
   {$endif}

function BuiltInCryptoProviderEx : TElCustomCryptoProvider; 

implementation

var
  BuiltInCryptoProvEx : TElCustomCryptoProvider;

////////////////////////////////////////////////////////////////////////////////
// TElBuiltInExtendedCryptoProvider class

function TElBuiltInExtendedCryptoProvider.CreateSymmetricCryptoFactory : TObject;
begin
  {$ifndef SB_HAS_MEMORY_MANAGER}
  Result := TElBuiltInExtendedSymmetricCryptoFactory.Create();
   {$else}
  Result := TObject(MemoryManager.AcquireObject(JLClass(TElBuiltInExtendedSymmetricCryptoFactory)));
   {$endif}
end;

class procedure TElBuiltInExtendedCryptoProvider.SetAsDefault;
begin
  DoSetAsDefault(TElBuiltInExtendedCryptoProvider);
end;

function TElBuiltInExtendedCryptoProvider.GetDefaultInstance : TElCustomCryptoProvider;
begin
  if BuiltInCryptoProvEx = nil then
  begin
    BuiltInCryptoProvEx := TElBuiltInExtendedCryptoProvider.Create({$ifndef SB_NO_COMPONENT}nil {$endif});
    RegisterGlobalObject(BuiltInCryptoProvEx);
  end;
  Result := BuiltInCryptoProvEx;
end;

////////////////////////////////////////////////////////////////////////////////
// TElBuiltInExtendedSymmetricCryptoFactory class

procedure TElBuiltInExtendedSymmetricCryptoFactory.RegisterDefaultClasses;
begin
  inherited;
  {$ifndef SB_NO_IDEA}if IDEAEnabled then RegisterClass(TElBuiltInIDEASymmetricCrypto); {$endif}
end;

////////////////////////////////////////////////////////////////////////////////
//  TElIDEASymmetricCrypto

{$ifndef SB_NO_IDEA}
procedure TElBuiltInIDEASymmetricCrypto.SetKeyMaterial(Material : TElCustomCryptoKey);
begin
  if not (Length(Material.IV) in [0, 8]) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);
  if not (Length(Material.Value) = 16) then
    raise EElSymmetricCryptoError.Create(SInvalidKeyMaterial);

  inherited;
end;

procedure TElBuiltInIDEASymmetricCrypto.EncryptBlock8(var B0, B1 : cardinal);
begin
  SBIDEA.Encrypt(B0, B1, FKey);
end;

procedure TElBuiltInIDEASymmetricCrypto.DecryptBlock8(var B0, B1 : cardinal);
begin
  SBIDEA.Encrypt(B0, B1, FKey);
end;

class function TElBuiltInIDEASymmetricCrypto.IsAlgorithmSupported(AlgID : integer) : boolean;
begin
  if (AlgID = SB_ALGORITHM_CNT_IDEA) then
    Result := true
  else
    Result := false;
end;

class function TElBuiltInIDEASymmetricCrypto.IsAlgorithmSupported(const AlgOID : ByteArray) : boolean;
begin
  Result := false;
end;

constructor TElBuiltInIDEASymmetricCrypto.Create(AlgID : integer;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  if AlgID = SB_ALGORITHM_CNT_IDEA then
  begin
    inherited Create(Mode);
    FBlockSize := 8;
    FKeySize := 16;
  end
  else
  begin
    raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmInt, [AlgID]));
  end;
end;

constructor TElBuiltInIDEASymmetricCrypto.Create(const AlgOID : ByteArray;
  Mode: TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  { no OID's for IDEA found }
  inherited Create;
  raise EElSymmetricCryptoError.Create(Format(SUnsupportedAlgorithmStr, [OIDToStr(AlgOID)]));
end;

constructor TElBuiltInIDEASymmetricCrypto.Create(Mode : TSBBuiltInSymmetricCryptoMode  =  cmDefault);
begin
  Create(SB_ALGORITHM_CNT_IDEA, Mode);
end;

procedure TElBuiltInIDEASymmetricCrypto.InitializeEncryption;
begin
  inherited InitializeEncryption;

  SBIDEA.ExpandKeyForEncryption(PIDEAKey(@FKeyMaterial.Value[0])^, FKey);
end;

procedure TElBuiltInIDEASymmetricCrypto.InitializeDecryption;
var
  DecKey : TIDEAExpandedKey; 
begin
  inherited InitializeDecryption;

  SBIDEA.ExpandKeyForEncryption(PIDEAKey(@FKeyMaterial.Value[0])^, FKey);

  if FMode in [cmECB,
               cmCBC] then
  begin
    SBIDEA.ExpandKeyForDecryption(FKey, DecKey);
    FKey := DecKey;
  end;  
end;

class procedure TElBuiltInIDEASymmetricCrypto.GetDefaultKeyAndBlockLengths(AlgID : integer;
  var KeyLen : integer; var BlockLen : integer);
begin
  KeyLen := 16;
  BlockLen := 8;
end;

class procedure TElBuiltInIDEASymmetricCrypto.GetDefaultKeyAndBlockLengths(const OID : ByteArray;
  var KeyLen : integer; var BlockLen : integer);
begin
  KeyLen := 16;
  BlockLen := 8;
end;
 {$endif}

////////////////////////////////////////////////////////////////////////////////
// Other

function BuiltInCryptoProviderEx : TElCustomCryptoProvider;
begin
  if BuiltInCryptoProvEx = nil then
  begin
    BuiltInCryptoProvEx := TElBuiltInExtendedCryptoProvider.Create({$ifndef SB_NO_COMPONENT}nil {$endif});
    RegisterGlobalObject(BuiltInCryptoProvEx);
  end;
  Result := BuiltInCryptoProvEx;
end;

//initialization
  //TElBuiltInExtendedCryptoProvider.SetAsDefault();

end.
