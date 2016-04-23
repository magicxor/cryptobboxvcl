(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBLicenseManager;

interface

uses
  Classes,
  SysUtils,
  {$ifdef SB_WINDOWS}
  Windows,
   {$endif}
  SBTypes,
  SBConstants,
  SBUtils;


{$ifndef NET_CF_1_0}

type
  TSBLicenseKeyRegKey = (rkHK);
    
  TElSBLicenseManager = class(TSBComponentBase)
  private
    FLicenseKey : string;
    FLicenseKeyFile : string;
    {$ifndef SB_NO_REGISTRY}
    FRegistryKey :  HKEY ;
     {$endif}
    procedure SetLicenseKey(const Value : string);
    {$ifndef SB_NO_FILESTREAM}
    procedure SetLicenseKeyFile(const Value : string);
     {$endif}
    {$ifndef SB_NO_REGISTRY}
    procedure SetRegistryKey(Value :  HKEY );
     {$endif}
  public
    constructor Create (AOwner : TComponent); override ;
    destructor Destroy; override;
    {$ifndef SB_NO_REGISTRY}
    property RegistryKey :  HKEY  read FRegistryKey write SetRegistryKey;
     {$endif}
  published
    property LicenseKey : string read FLicenseKey write SetLicenseKey;
    {$ifndef SB_NO_FILESTREAM}
    property LicenseKeyFile : string read FLicenseKeyFile write SetLicenseKeyFile;
     {$endif}
  end;

  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElSBLicenseManager = TElSBLicenseManager;
   {$endif}

procedure Register;

 {$endif}

implementation

{$ifndef NET_CF_1_0}

resourcestring
  SFailedToReadLicenseKey = 'Failed to read license key';

procedure Register;
begin
  RegisterComponents('SecureBlackbox', [TElSBLicenseManager]);
end;

constructor TElSBLicenseManager.Create(AOwner : TComponent);
begin
  inherited;
  FLicenseKey := '';
  FLicenseKeyFile := '';
  {$ifndef SB_NO_REGISTRY}
  FRegistryKey :=  0 ;
   {$endif}
end;

destructor TElSBLicenseManager.Destroy;
begin
  inherited;
end;

procedure TElSBLicenseManager.SetLicenseKey(const Value : string);
begin
  if CompareStr(Value, FLicenseKey) <> 0 then
  begin
    if Length(Value) > 0 then
      SBUtils.SetLicenseKey(Value);
    FLicenseKey := Value;
  end;
end;

{$ifndef SB_NO_FILESTREAM}
procedure TElSBLicenseManager.SetLicenseKeyFile(const Value : string);
var
  F :  TFileStream ;
  KeyData : ByteArray;
begin
  if CompareStr(Value, FLicenseKeyFile) <> 0 then
  begin
    if Length(Value) > 0 then
    begin
      F := TFileStream.Create(Value, fmOpenRead or fmShareDenyWrite);
      try
        SetLength(KeyData, F. Size );
        F.Read(KeyData[0], Length(KeyData));
      finally
        FreeAndNil(F);
      end;
      Self.SetLicenseKey(StringOfBytes(KeyData));
    end;
    FLicenseKeyFile := Value;
  end;
end;
 {$endif}

{$ifndef SB_NO_REGISTRY}
procedure TElSBLicenseManager.SetRegistryKey(Value :  HKEY );
var
  Len : {$ifdef SB_WINCE}DWORD {$else}integer {$endif};
  KeyValue : {$ifdef SB_WINCE}WideString {$else}string {$endif};
  Success : boolean;
  {$ifdef SB_WINCE}
  ValueType : DWORD;
   {$endif}
begin
  if Value <> FRegistryKey then
  begin
    Len := 0;
    Success := false;
    {$ifdef SB_WINCE}
    ValueType := 0;
    if RegQueryValueEx(Value, '', nil, @ValueType, nil, @Len) = ERROR_SUCCESS then
     {$else}
    if RegQueryValue(Value, '',  nil, Len) = ERROR_SUCCESS then
     {$endif}
    begin
      {$ifdef SB_WINCE}
      SetLength(KeyValue, Len shr 1); // the returned length is in bytes, not in chars
      if (ValueTYpe = REG_SZ) and (RegQueryValueEx(Value, '', nil, @ValueType,  @KeyValue[StringStartOffset], @Len) = ERROR_SUCCESS) then
       {$else}
      SetLength(KeyValue, Len);
      if RegQueryValue(Value, '', @KeyValue[StringStartOffset], Len) = ERROR_SUCCESS then
       {$endif}
      begin
        // trimming trailing null character
        SetLength(KeyValue, Max(Len - 1, 0));
        SetLicenseKey(KeyValue);
        Success := true;
      end;
    end;
    if Success then
      FRegistryKey := Value
    else
      raise ESecureBlackboxError.Create(SFailedToReadLicenseKey);
  end;
end;
 {$endif}
 {$endif}

end.
