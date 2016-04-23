(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBHashFunction;

interface

uses
  SBConstants,
  SBTypes,
  SBUtils,
  SysUtils,
  Classes,
  SBCryptoProv,
  //SBCryptoProvDefault,
  SBCustomCrypto,
  //SBAlgorithmIdentifier,
  SBMD;
  //SBSHA,
  //SBSHA2,
  //SBRIPEMD;

type
  TElHMACKeyMaterial = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElHMACKeyMaterial = TElHMACKeyMaterial;
   {$endif}

  TElHMACKeyMaterial = class(TElKeyMaterial)
  private
    FKey: TElCustomCryptoKey;
    FCryptoProvider: TElCustomCryptoProvider;
    FCryptoProviderManager : TElCustomCryptoProviderManager;

    function GetKey : ByteArray;
    procedure SetKey(const Value : ByteArray);
    function GetNonce : ByteArray;
    procedure SetNonce(const Value : ByteArray);
    function GetCryptoProvider : TElCustomCryptoProvider;
  public
    constructor Create(Prov : TElCustomCryptoProvider  =  nil);  overload; 
    constructor Create(Key : TElCustomCryptoKey;
      Prov : TElCustomCryptoProvider  =  nil);  overload; 
    constructor Create(Manager : TElCustomCryptoProviderManager; Prov : TElCustomCryptoProvider);  overload; 
    constructor Create(Key : TElCustomCryptoKey; Manager : TElCustomCryptoProviderManager;
      Prov : TElCustomCryptoProvider);  overload; 
     destructor  Destroy; override;

    property Key : ByteArray read GetKey write SetKey;
    property Nonce : ByteArray read GetNonce write SetNonce;
    property CryptoProvider : TElCustomCryptoProvider read GetCryptoProvider;
  end;

  TElHashFunction = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElHashFunction = TElHashFunction;
   {$endif}

  TElHashFunction = class
  private
    FCryptoProvider : TElCustomCryptoProvider;
    FCryptoProviderManager : TElCustomCryptoProviderManager;
    FContext : TElCustomCryptoContext;
    FKey : TElHMACKeyMaterial;
    procedure UpdateDigest(Buffer: pointer; Size: integer); overload;
    procedure UpdateDigest(const Buffer: ByteArray; StartIndex: integer; Count: integer); overload;

    function GetAlgorithm : integer;
    procedure SetKey(Value : TElHMACKeyMaterial);
    function GetKey : TElHMACKeyMaterial;
    procedure SetCryptoProvider(CryptoProvider : TElCustomCryptoProvider);
    function GetCryptoProvider : TElCustomCryptoProvider;
  public
    constructor Create(Algorithm: integer; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload; 
    constructor Create(const OID : ByteArray; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload; 
    constructor Create(Algorithm: integer; Parameters : TElCPParameters; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload; 
    constructor Create(const OID : ByteArray; Parameters : TElCPParameters; CryptoProvider : TElCustomCryptoProvider  =  nil);  overload; 

    constructor Create(CryptoProvider : TElCustomCryptoProvider  =  nil);  overload; 
    constructor Create(Algorithm: integer; Key : TElHMACKeyMaterial);  overload; 
    constructor Create(const OID : ByteArray; Key : TElHMACKeyMaterial);  overload; 
    constructor Create(Algorithm: integer; Key : TElHMACKeyMaterial; CryptoProvider : TElCustomCryptoProvider);  overload; 
    constructor Create(const OID : ByteArray; Key : TElHMACKeyMaterial; CryptoProvider : TElCustomCryptoProvider);  overload; 

    constructor Create(Manager: TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload; 
    constructor Create(Algorithm: integer; Parameters : TElCPParameters;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload; 
    constructor Create(const OID : ByteArray; Parameters : TElCPParameters;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload; 
    constructor Create(Algorithm: integer; Key : TElHMACKeyMaterial;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload; 
    constructor Create(const OID : ByteArray; Key : TElHMACKeyMaterial;
      Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);  overload; 

     destructor  Destroy; override;

    procedure Reset;
    procedure Update(Buffer: pointer; Size: integer); overload;
    procedure Update(const Buffer: ByteArray; StartIndex: integer; Count: integer);  overload; 
    procedure Update(const Buffer: ByteArray);  overload; 

    // procedure is not overloaded because FreePascal incorrectly choses an overload
    procedure UpdateStream(Stream: TElInputStream; Count: Int64  =  0);  overload; 
    function Finish : ByteArray;
    function Clone : TElHashFunction;
    
    class function IsAlgorithmSupported(Algorithm: integer; CryptoProvider : TElCustomCryptoProvider  =  nil): boolean;  overload;  
    class function IsAlgorithmSupported(const OID : ByteArray; CryptoProvider : TElCustomCryptoProvider  =  nil): boolean;  overload;  
    class function GetDigestSizeBits(Algorithm: integer; CryptoProvider : TElCustomCryptoProvider  =  nil): integer;  overload;  
    class function GetDigestSizeBits(const OID : ByteArray; CryptoProvider : TElCustomCryptoProvider  =  nil): integer;  overload;  
    class function IsAlgorithmSupported(Algorithm: integer; Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider): boolean;  overload;  
    class function IsAlgorithmSupported(const OID : ByteArray; Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider): boolean;  overload;  
    class function GetDigestSizeBits(Algorithm: integer; Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider): integer;  overload;  
    class function GetDigestSizeBits(const OID : ByteArray; Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider): integer;  overload;  

    class function Hash(Algorithm: integer; Buffer: Pointer; Size: integer): ByteArray;  overload; 
    class function Hash(Algorithm: integer; Key : TElHMACKeyMaterial; Buffer: Pointer; Size: integer): ByteArray;  overload; 
    
    property Algorithm: integer read GetAlgorithm;
    property CryptoProvider : TElCustomCryptoProvider read GetCryptoProvider
      write SetCryptoProvider;
    property Key : TElHMACKeyMaterial read GetKey write SetKey;
  end;

  EElHashFunctionError =  class(ESecureBlackboxError);
  EElHashFunctionUnsupportedError =  class(EElHashFunctionError);

{$ifndef FPC}
var
  G_CheckPointerIsNotAnObject : boolean = false;
 {$endif}

implementation

uses
  SBCryptoProvUtils, SBCryptoProvManager;

constructor TElHashFunction.Create(Algorithm: integer; CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited Create;

  if CryptoProvider = nil then
    FCryptoProvider := DefaultCryptoProviderManager.GetSuitableProvider(SB_OPTYPE_HASH, Algorithm, 0, nil, nil)
    //FCryptoProvider := DefaultCryptoProvider
  else
    FCryptoProvider := CryptoProvider;
  FKey := nil;
  FContext := FCryptoProvider.HashInit(Algorithm, nil, nil);
end;

constructor TElHashFunction.Create(Algorithm: integer; Parameters : TElCPParameters; CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited Create;

  if CryptoProvider = nil then
    FCryptoProvider := DefaultCryptoProviderManager.GetSuitableProvider(SB_OPTYPE_HASH, Algorithm, 0, nil, nil)
  else
    FCryptoProvider := CryptoProvider;
  FKey := nil;
  FContext := FCryptoProvider.HashInit(Algorithm, nil, Parameters);
end;

constructor TElHashFunction.Create(const OID : ByteArray; CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited Create;
  if CryptoProvider = nil then
    FCryptoProvider := DefaultCryptoProviderManager.{$ifndef BUILDER_USED}GetSuitableProvider {$else}GetSuitableProvider2 {$endif}(SB_OPTYPE_HASH, OID, EmptyArray, 0, nil, nil)
    //FCryptoProvider := DefaultCryptoProvider
  else
    FCryptoProvider := CryptoProvider;
  FKey := nil;
  FContext := FCryptoProvider.HashInit(OID, EmptyArray, nil, nil);
end;

constructor TElHashFunction.Create(const OID : ByteArray; Parameters : TElCPParameters; CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited Create;
  if CryptoProvider = nil then
    FCryptoProvider := DefaultCryptoProviderManager.{$ifndef BUILDER_USED}GetSuitableProvider {$else}GetSuitableProvider2 {$endif}(SB_OPTYPE_HASH, OID, EmptyArray, 0, nil, nil)
  else
    FCryptoProvider := CryptoProvider;
  FKey := nil;
  FContext := FCryptoProvider.HashInit(OID, EmptyArray, nil, Parameters);
end;

constructor TElHashFunction.Create(Algorithm: integer; Key: TElHMACKeyMaterial);
begin
  inherited Create;

  FCryptoProvider := Key.CryptoProvider;
  FKey := Key;
  FContext := FCryptoProvider.HashInit(Algorithm, FKey.FKey, nil);
end;

constructor TElHashFunction.Create(const OID : ByteArray; Key: TElHMACKeyMaterial);
begin
  inherited Create;

  FCryptoProvider := Key.CryptoProvider;
  FKey := Key;
  FContext := FCryptoProvider.HashInit(OID, EmptyArray, FKey.FKey, nil);
end;                  

constructor TElHashFunction.Create(CryptoProvider : TElCustomCryptoProvider  =  nil);
begin
  inherited Create;
  if CryptoProvider = nil then
    FCryptoProvider := DefaultCryptoProviderManager.DefaultCryptoProvider
    //FCryptoProvider := DefaultCryptoProvider
  else
    FCryptoProvider := CryptoProvider;
  FContext := nil;
end;

constructor TElHashFunction.Create(Manager: TElCustomCryptoProviderManager;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create;
  if CryptoProvider = nil then
  begin
    if Manager = nil then
      Manager := DefaultCryptoProviderManager;
    FCryptoProvider := Manager.DefaultCryptoProvider;
  end
  else
    FCryptoProvider := CryptoProvider;
  FContext := nil;
end;

constructor TElHashFunction.Create(Algorithm: integer; Key : TElHMACKeyMaterial;
  CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create;

  FCryptoProvider := CryptoProvider;
  FKey := Key;
  FContext := FCryptoProvider.HashInit(Algorithm, FKey.FKey, nil);
end;

constructor TElHashFunction.Create(const OID : ByteArray; Key : TElHMACKeyMaterial;
  CryptoProvider : TElCustomCryptoProvider); 
begin
  inherited Create;

  FCryptoProvider := CryptoProvider;
  FKey := Key;
  FContext := FCryptoProvider.HashInit(OID, EmptyArray, FKey.FKey, nil);
end;

constructor TElHashFunction.Create(Algorithm: integer; Parameters : TElCPParameters;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create;
  if CryptoProvider = nil then
  begin
    if Manager = nil then
      Manager := DefaultCryptoProviderManager;
    FCryptoProvider := Manager.GetSuitableProvider(SB_OPTYPE_HASH, Algorithm, 0, nil, nil);
  end
  else
    FCryptoProvider := CryptoProvider;
  FCryptoProviderManager := Manager;
  FKey := nil;
  FContext := FCryptoProvider.HashInit(Algorithm, nil, Parameters);
end;

constructor TElHashFunction.Create(const OID : ByteArray; Parameters : TElCPParameters;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create;
  if CryptoProvider = nil then
  begin
    if Manager = nil then
      Manager := DefaultCryptoProviderManager;
    FCryptoProvider := Manager.{$ifndef BUILDER_USED}GetSuitableProvider {$else}GetSuitableProvider2 {$endif}(SB_OPTYPE_HASH, OID, EmptyArray, 0, nil, nil);
  end
  else
    FCryptoProvider := CryptoProvider;
  FCryptoProviderManager := Manager;
  FKey := nil;
  FContext := FCryptoProvider.HashInit(OID, EmptyArray, nil, Parameters);
end;

constructor TElHashFunction.Create(Algorithm: integer; Key : TElHMACKeyMaterial;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create;
  if CryptoProvider = nil then
  begin
    if Manager = nil then
      Manager := DefaultCryptoProviderManager;
    FCryptoProvider := Manager.GetSuitableProvider(SB_OPTYPE_HASH, Algorithm, 0, Key.FKey, nil);
  end
  else
    FCryptoProvider := CryptoProvider;
  FCryptoProviderManager := Manager;
  FKey := Key;
  FContext := FCryptoProvider.HashInit(Algorithm, FKey.FKey, nil);
end;

constructor TElHashFunction.Create(const OID : ByteArray; Key : TElHMACKeyMaterial;
  Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider);
begin
  inherited Create;
  if CryptoProvider = nil then
  begin
    if Manager = nil then
      Manager := DefaultCryptoProviderManager;
    FCryptoProvider := Manager.{$ifndef BUILDER_USED}GetSuitableProvider {$else}GetSuitableProvider2 {$endif}(SB_OPTYPE_HASH, OID, EmptyArray, 0, Key.FKey, nil);
  end
  else
    FCryptoProvider := CryptoProvider;
  FCryptoProviderManager := Manager;
  FKey := Key;
  FContext := FCryptoProvider.HashInit(OID, EmptyArray, FKey.FKey, nil);
end;

 destructor  TElHashFunction.Destroy;
begin
  if Assigned(FContext) and Assigned(FContext.CryptoProvider) then
    FContext.CryptoProvider.ReleaseCryptoContext(FContext);
  inherited;
end;

class function TElHashFunction.Hash(Algorithm: integer; Buffer: Pointer; Size: integer): ByteArray;
var
  H: TElHashFunction;
begin
  H := TElHashFunction.Create(Algorithm);
  try
    H.Update(Buffer,  Size );
    Result := H.Finish();
  finally
    FreeAndNil(H);
  end;
end;


class function TElHashFunction.Hash(Algorithm: integer; Key : TElHMACKeyMaterial; Buffer: Pointer; Size: integer): ByteArray;
var
  H: TElHashFunction;
begin
  H := TElHashFunction.Create(Algorithm, Key);
  try
    H.Update(Buffer,  Size );
    Result := H.Finish();
  finally
    FreeAndNil(H);
  end;
end;


procedure TElHashFunction.UpdateDigest(const Buffer: ByteArray; StartIndex: integer; Count: integer);
begin
  FCryptoProvider.HashUpdate(FContext, @Buffer[StartIndex], Count);
end;

procedure TElHashFunction.UpdateDigest(Buffer: pointer; Size: integer);
begin
  FCryptoProvider.HashUpdate(FContext, Buffer,  Size );
end;


function TElHashFunction.GetAlgorithm : integer;
begin
  Result := FContext.Algorithm;
end;

class function TElHashFunction.IsAlgorithmSupported(Algorithm: integer;
  CryptoProvider : TElCustomCryptoProvider  =  nil): boolean;
begin
  Result := DefaultCryptoProviderManager().IsAlgorithmSupported(Algorithm, 0);
end;

class function TElHashFunction.IsAlgorithmSupported(const OID : ByteArray;
  CryptoProvider : TElCustomCryptoProvider  =  nil): boolean;
begin
  Result := DefaultCryptoProviderManager.IsAlgorithmSupported(OID, EmptyArray, 0);
end;

class function TElHashFunction.GetDigestSizeBits(Algorithm: integer;
  CryptoProvider : TElCustomCryptoProvider  =  nil): integer;
begin
  if CryptoProvider = nil then
    CryptoProvider := DefaultCryptoProviderManager.GetSuitableProvider(SB_OPTYPE_HASH, Algorithm, 0, nil, nil);//DefaultCryptoProvider;
  Result := SBCryptoProvUtils.GetIntegerPropFromBuffer(CryptoProvider.GetAlgorithmProperty(Algorithm, 0, SB_ALGPROP_DIGEST_SIZE));
end;

class function TElHashFunction.GetDigestSizeBits(const OID : ByteArray;
  CryptoProvider : TElCustomCryptoProvider  =  nil): integer;
begin
  if CryptoProvider = nil then
    CryptoProvider := DefaultCryptoProviderManager.{$ifndef BUILDER_USED}GetSuitableProvider {$else}GetSuitableProvider2 {$endif}(SB_OPTYPE_HASH, OID, EmptyArray, 0, nil, nil);//DefaultCryptoProvider;
  Result := SBCryptoProvUtils.GetIntegerPropFromBuffer(CryptoProvider.GetAlgorithmProperty(OID, EmptyArray, 0, SB_ALGPROP_DIGEST_SIZE));
end;

class function TElHashFunction.IsAlgorithmSupported(Algorithm: integer; Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider): boolean;
begin
  if Manager = nil then
    Manager := DefaultCryptoProviderManager;
  Result := Manager.IsAlgorithmSupported(Algorithm, 0);
end;

class function TElHashFunction.IsAlgorithmSupported(const OID : ByteArray; Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider): boolean;
begin
  if Manager = nil then
    Manager := DefaultCryptoProviderManager;
  Result := Manager.IsAlgorithmSupported(OID, EmptyArray, 0);
end;

class function TElHashFunction.GetDigestSizeBits(Algorithm: integer; Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider): integer;
begin
  if CryptoProvider = nil then
  begin
    if Manager = nil then
      Manager := DefaultCryptoProviderManager;
    CryptoProvider := Manager.GetSuitableProvider(SB_OPTYPE_HASH, Algorithm, 0, nil, nil);
  end;
  Result := SBCryptoProvUtils.GetIntegerPropFromBuffer(CryptoProvider.GetAlgorithmProperty(Algorithm, 0, SB_ALGPROP_DIGEST_SIZE));
end;

class function TElHashFunction.GetDigestSizeBits(const OID : ByteArray; Manager : TElCustomCryptoProviderManager; CryptoProvider : TElCustomCryptoProvider): integer;
begin
  if CryptoProvider = nil then
  begin
    if Manager = nil then
      Manager := DefaultCryptoProviderManager;
    CryptoProvider := {$ifndef BUILDER_USED}Manager.GetSuitableProvider {$else}Manager.GetSuitableProvider2 {$endif}(SB_OPTYPE_HASH, OID, EmptyArray, 0, nil, nil);
  end;
  Result := SBCryptoProvUtils.GetIntegerPropFromBuffer(CryptoProvider.GetAlgorithmProperty(OID, EmptyArray, 0, SB_ALGPROP_DIGEST_SIZE));
end;

procedure TElHashFunction.SetKey(Value : TElHMACKeyMaterial);
begin
  FKey := Value;
  Reset;
end;

function TElHashFunction.GetKey : TElHMACKeyMaterial;
begin
  Result := FKey;
end;
    
procedure TElHashFunction.SetCryptoProvider(CryptoProvider : TElCustomCryptoProvider);
begin
  FCryptoProvider := CryptoProvider;
end;

function TElHashFunction.GetCryptoProvider : TElCustomCryptoProvider;
begin
  Result := FCryptoProvider;
end;

procedure TElHashFunction.Reset;
var
  Alg : integer;
begin
  if Assigned(FContext) then
  begin
    Alg := FContext.Algorithm;
    FContext.CryptoProvider.ReleaseCryptoContext(FContext);
    if Assigned(FKey) then
      FContext := FCryptoProvider.HashInit(Alg, FKey.FKey, nil)
    else
      FContext := FCryptoProvider.HashInit(Alg, nil, nil);
  end;
end;

procedure TElHashFunction.Update(const Buffer: ByteArray; StartIndex: integer; Count: integer);
begin
  UpdateDigest(Buffer, StartIndex, Count);
end;

procedure TElHashFunction.Update(const Buffer: ByteArray);
begin
   UpdateDigest(@Buffer[0], Length(Buffer));
end;

procedure TElHashFunction.Update(Buffer: pointer; Size: integer);
begin
  {$ifndef FPC}
  {$ifndef DELPHI_MAC}
  if (G_CheckPointerIsNotAnObject) and (IsValidVCLObject(Buffer)) then
    raise ESecureBlackboxError.Create('Provided pointer is a VCL object. Use the UpdateStream() method to pass streamed data for hashing.');
   {$endif}
   {$endif}
  UpdateDigest(Buffer,  Size );
end;

procedure TElHashFunction.UpdateStream(Stream: TElInputStream;
  Count: Int64  =  0);
var
  Buf :  array[0..32767] of byte ;
  Read : integer;
begin
  if Count = 0 then
    Count := Stream. Size  - Stream.Position
  else
    Count := Min(Count, Stream. Size  - Stream.Position);
  while Count > 0 do
  begin
    Read := Stream.Read(Buf[0], Min(Count, Length(Buf)));
    UpdateDigest(@Buf[0], Read);
    Dec(Count, Read);
  end;  
end;


function TElHashFunction.Finish : ByteArray;
var
  Buf : ByteArray;
begin
  Buf := FCryptoProvider.HashFinal(FContext, nil);
  Result := CloneArray(Buf);
end;

function TElHashFunction.Clone :  TElHashFunction ;
var
  Res : TElHashFunction;
begin
  Res := TElHashFunction.Create(FCryptoProviderManager, FCryptoProvider);
  Res.FKey := FKey;
  Res.FContext := FContext.Clone();
  Result := Res;
end;

{ TElHMACKeyMaterial}

constructor TElHMACKeyMaterial.Create(Prov : TElCustomCryptoProvider  =  nil);
begin
  inherited Create;

  if Prov = nil then
    Prov := DefaultCryptoProviderManager.GetSuitableProvider(SB_OPTYPE_KEY_CREATE, SB_ALGORITHM_HMAC, 0, nil, nil); //DefaultCryptoProvider;
  FKey := Prov.CreateKey(SB_ALGORITHM_HMAC, 0, nil);
  FCryptoProvider := Prov;
end;

constructor TElHMACKeyMaterial.Create(Key : TElCustomCryptoKey;
  Prov : TElCustomCryptoProvider  =  nil);
begin
  inherited Create;

  if Prov = nil then
    Prov := Key.CryptoProvider;
  FKey := Key;
  FCryptoProvider := Prov;
end;

constructor TElHMACKeyMaterial.Create(Manager : TElCustomCryptoProviderManager;
  Prov : TElCustomCryptoProvider);
begin
  inherited Create;
  if Prov = nil then
  begin
    if Manager = nil then
      Manager := DefaultCryptoProviderManager;
    Prov := Manager.GetSuitableProvider(SB_OPTYPE_KEY_CREATE, SB_ALGORITHM_HMAC, 0, nil, nil);
  end;
  FKey := Prov.CreateKey(SB_ALGORITHM_HMAC, 0, nil);
  FCryptoProvider := Prov;
  FCryptoProviderManager := Manager;
end;

constructor TElHMACKeyMaterial.Create(Key : TElCustomCryptoKey; Manager : TElCustomCryptoProviderManager;
  Prov : TElCustomCryptoProvider);
begin
  inherited Create;
  if Prov = nil then
    Prov := Key.CryptoProvider;
  FKey := Key;
  FCryptoProvider := Prov;
  FCryptoProviderManager := Manager;
end;

 destructor  TElHMACKeyMaterial.Destroy;
begin
  inherited;

  if FKey <> nil then
    FKey.CryptoProvider.ReleaseKey(FKey);
end;

function TElHMACKeyMaterial.GetKey : ByteArray;
begin
  Result := FKey.Value;
end;

procedure TElHMACKeyMaterial.SetKey(const Value : ByteArray);
begin
  FKey.Value := CloneArray(Value);
end;

function TElHMACKeyMaterial.GetNonce : ByteArray;
begin
  Result := FKey.IV;
end;

procedure TElHMACKeyMaterial.SetNonce(const Value : ByteArray);
begin
  FKey.IV := CloneArray(Value);
end;

function TElHMACKeyMaterial.GetCryptoProvider : TElCustomCryptoProvider;
begin
  Result := FCryptoProvider;
end;

end.
