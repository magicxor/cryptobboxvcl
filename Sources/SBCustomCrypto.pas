(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBCustomCrypto;

interface

uses
  SBCryptoProv,
  SBConstants,
  Classes,
  SBTypes,
  SBStrUtils,
  SBUtils;

type
  TElKeyMaterial = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElKeyMaterial = TElKeyMaterial;
   {$endif}

  TElKeyMaterial = class(TSBDisposableBase)
  protected
    FKey : TElCustomCryptoKey;
  protected
    function GetValid : boolean; virtual;
    function GetBits : integer; virtual;
    function GetExportable : boolean; virtual;
    function GetAlgorithm : integer; virtual;
    function GetKeyID : ByteArray;
    procedure SetKeyID(const Value : ByteArray);
    function GetKeySubject : ByteArray;
    procedure SetKeySubject(const Value : ByteArray);
    {$ifdef SB_HAS_WINCRYPT}
    function GetProviderName() : string;
    procedure SetProviderName(const Value: string);
     {$endif}
  public
    constructor Create;
     destructor  Destroy; override;
    {$ifndef SB_PGPSFX_STUB}
    procedure Generate(Bits : integer); virtual;
     {$endif SB_PGPSFX_STUB}
    procedure Save(Stream : TElOutputStream); virtual;
    procedure Load(Stream : TElInputStream;
      Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}); virtual;
    procedure Assign(Source : TElKeyMaterial); virtual;
    function  Equals(Source : TElKeyMaterial; PublicOnly : boolean): boolean; {$ifdef D_12_UP}reintroduce; overload; {$endif} virtual;
    {$ifdef D_12_UP}
    function Equals(Obj: TObject): Boolean; overload; override;
     {$endif}
    function Clone : TElKeyMaterial; virtual;
    procedure AssignCryptoKey(Key : TElCustomCryptoKey); virtual;
    procedure Persistentiate; virtual;
    property Exportable : boolean read GetExportable;
    property Valid : boolean read GetValid;
    property Bits : integer read GetBits;
    property Key : TElCustomCryptoKey read FKey;
    property Algorithm : integer read GetAlgorithm;
    property KeyID : ByteArray read GetKeyID write SetKeyID;
    property KeySubject : ByteArray read GetKeySubject write SetKeySubject;
    {$ifdef SB_HAS_WINCRYPT}
    property ProviderName : string read GetProviderName write SetProviderName;
     {$endif}
  end;

  TElCustomCrypto = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCustomCrypto = TElCustomCrypto;
   {$endif}

  TElCustomCrypto = class(TSBDisposableBase)
  end;

implementation

resourcestring
  SNotImplemented = 'Not implemented';

constructor TElKeyMaterial.Create;
begin
  inherited;
  FKey := nil;
end;

 destructor  TElKeyMaterial.Destroy;
begin
  inherited;
end;

{$ifndef SB_PGPSFX_STUB}
procedure TElKeyMaterial.Generate(Bits : integer);
begin
  ;
end;
 {$endif SB_PGPSFX_STUB}

procedure TElKeyMaterial.Save(Stream : TElOutputStream);
begin
  ;
end;

procedure TElKeyMaterial.Load(Stream : TElInputStream;
  Count : integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif});
begin
  ;
end;

function TElKeyMaterial.GetValid : boolean;
begin
  Result := false;
end;

function TElKeyMaterial.GetBits : integer;
begin
  Result := 0;
end;

procedure TElKeyMaterial.Assign(Source : TElKeyMaterial);
begin
  raise ESecureBlackboxError.Create(SNotImplemented);
end;

function TElKeyMaterial.Equals(Source : TElKeyMaterial; PublicOnly : boolean): boolean;
begin
//  Result := false;
  raise ESecureBlackboxError.Create(SNotImplemented);
end;

{$ifdef D_12_UP}
function TElKeyMaterial.Equals(Obj: TObject): Boolean;
begin
  Result := inherited;
end;
 {$endif}

procedure TElKeyMaterial.AssignCryptoKey(Key : TElCustomCryptoKey);
begin
  raise ESecureBlackboxError.Create(SNotImplemented);  
end; 

function TElKeyMaterial.Clone : TElKeyMaterial;
begin
  raise ESecureBlackboxError.Create(SNotImplemented);
end;

function TElKeyMaterial.GetExportable : boolean;
begin
  Result := false;
end;

function TElKeyMaterial.GetAlgorithm : integer;
begin
  if FKey <> nil then
    Result := FKey.Algorithm
  else
    Result := SB_ALGORITHM_UNKNOWN;
end;

function TElKeyMaterial.GetKeyID : ByteArray;
begin
  if FKey <> nil then
  begin
    Result := FKey.GetKeyProp(SB_KEYPROP_PKCS11_ID, EmptyArray);
    if Length(Result) = 0 then
      Result := FKey.GetKeyProp(SB_KEYPROP_WIN32_CONTAINERNAME, EmptyArray);
  end
  else
    Result := EmptyArray;
end;

procedure TElKeyMaterial.SetKeyID(const Value : ByteArray);
begin
  if FKey <> nil then
  begin
    FKey.SetKeyProp(SB_KEYPROP_PKCS11_ID, Value);
    FKey.SetKeyProp(SB_KEYPROP_WIN32_CONTAINERNAME, Value);
  end;
end;

function TElKeyMaterial.GetKeySubject : ByteArray;
begin
  if FKey <> nil then
    Result := FKey.GetKeyProp(SB_KEYPROP_PKCS11_SUBJECT, EmptyArray)
  else
    Result := EmptyArray;
end;

procedure TElKeyMaterial.SetKeySubject(const Value : ByteArray);
begin
  if FKey <> nil then
    FKey.SetKeyProp(SB_KEYPROP_PKCS11_SUBJECT, Value);
end;

{$ifdef SB_HAS_WINCRYPT}
function TElKeyMaterial.GetProviderName() : string;
begin
  Result := UTF8ToStr(FKey.GetKeyProp(SB_KEYPROP_WIN32_PROVIDERNAME, EmptyArray));
end;

procedure TElKeyMaterial.SetProviderName(const Value: string);
begin
  FKey.SetKeyProp(SB_KEYPROP_WIN32_PROVIDERNAME, StrToUTF8(Value));
end;
 {$endif}

procedure TElKeyMaterial.Persistentiate;
begin
  if FKey <> nil then
    FKey.Persistentiate();
end;

end.
