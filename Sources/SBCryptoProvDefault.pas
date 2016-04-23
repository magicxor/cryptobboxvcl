(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBCryptoProvDefault;

interface

uses
  SBCryptoProv,
  SBCryptoProvBuiltIn,
  //SBCryptoProvDLL,
    SBTypes,
  SBUtils;

// TODO:
// * Redesign the code to make it call Manager->GetDefaultProvider()
// * Review creation and registration of pre-defined providers
//   (we need to register exactly those objects that are created in the
//   corresponding units). We may try to redirect the corresponding functions
//   (e.g. Win32CryptoProviders) to the cryptoprovidermanager.

function DefaultCryptoProvider : TElCustomCryptoProvider; 
//function CreateDefaultCryptoProviderInstance : TElCustomCryptoProvider; {$ifdef SB_NET}public;{$endif}
procedure SetDefaultCryptoProviderType(Value: TElCustomCryptoProviderClass); 

implementation

uses
  SBCryptoProvManager;

//var
//  DefCryptoProv : TElCustomCryptoProvider {$ifndef SB_NET}={$else}:={$endif} nil;
//  DefCryptoProvType : TElCustomCryptoProviderClass {$ifndef SB_NET}={$else}:={$endif} TElBuiltInCryptoProvider;

function DefaultCryptoProvider : TElCustomCryptoProvider;
begin
  Result := DefaultCryptoProviderManager.DefaultCryptoProvider;
  (*if DefCryptoProv = nil then
    DefCryptoProv := {$ifndef SB_NET}DefCryptoProvType.Create{$else}DefCryptoProvType.New{$endif}({$ifdef SB_VCL}nil{$endif});
  result := DefCryptoProv;
  *)
  //if DefCryptoProv = nil then
  //begin
  //  DefCryptoProv := TElDLLCryptoProvider.Create({$ifdef SB_VCL}nil{$endif});
  //  TElDLLCryptoProvider(DefCryptoProv).DllName := 'SBCryptoProvLib.dll';
  //end;
  //Result := DefCryptoProv;
end;

//function CreateDefaultCryptoProviderInstance : TElCustomCryptoProvider;
//begin
  //Result := TElBuiltinCryptoProvider.Create({$ifdef SB_VCL}nil{$endif});
//end;

procedure SetDefaultCryptoProviderType(Value : TElCustomCryptoProviderClass); 
begin
  //DefCryptoProvType := Value;
  //DefCryptoProv := nil;
  DefaultCryptoProviderManager.SetDefaultCryptoProviderType(Value);
end;

initialization

finalization
  //if DefCryptoProv <> nil then
  //  FreeAndNil(DefCryptoProv);


end.
