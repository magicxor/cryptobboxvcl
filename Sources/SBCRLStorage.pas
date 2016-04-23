(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBCRLStorage;

interface

uses
  Classes,
  SysUtils, 
  {$ifdef SB_UNICODE_VCL}
  SBStringList,
   {$endif}
  SBASN1,
  SBASN1Tree,
  SBTypes,
  SBUtils,
  SBX509,
  SBPEM,
  SBX509Ext,
  SBRDN,
  SBSharedResource,
  SBCustomCrypto,
  SBPublicKeyCrypto,
  SBAlgorithmIdentifier,
  SBCRL,
  SBConstants;



type

  TSBCRLLookupCriterion = (clcIssuer, clcDistributionPoint, clcNumber,
    clcReason, clcAuthorityKeyIdentifier, clcBaseCRLNumber);
  TSBCRLLookupCriteria = set of TSBCRLLookupCriterion;
  TSBCRLLookupOption = (cloExactMatch, cloMatchAll);
  TSBCRLLookupOptions = set of TSBCRLLookupOption;

  TElCustomCRLStorage = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCustomCRLStorage = TElCustomCRLStorage;
   {$endif}

  TElCRLLookup = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCRLLookup = TElCRLLookup;
   {$endif}

  TElCRLLookup = class (TSBControlBase)
  protected
    FCriteria: TSBCRLLookupCriteria;
    FOptions: TSBCRLLookupOptions;
    FIssuerRDN: TElRelativeDistinguishedName;
    FDistributionPoint : TElGeneralName;
    FNumber : ByteArray;
    FReasons: TSBCRLReasonFlags;
    FAuthorityKeyIdentifier: ByteArray;
    FBaseCRLNumber : ByteArray;

    FLastIndex: integer;
  protected
    function FindNext(Storage: TElCustomCRLStorage): integer; virtual;
    procedure SetCriteria(const Value: TSBCRLLookupCriteria);
    procedure SetNumber(const V : ByteArray);
    procedure SetAuthorityKeyIdentifier(const V: ByteArray);
    procedure SetBaseCRLNumber(const V : ByteArray);
  public
    constructor Create(AOwner: TComponent); {$ifndef SB_NO_COMPONENT}override; {$endif}
     destructor  Destroy; override;

    property IssuerRDN: TElRelativeDistinguishedName read FIssuerRDN;
    property DistributionPoint : TElGeneralName read FDistributionPoint;
    property Number : ByteArray read FNumber write SetNumber;
    property Reasons: TSBCRLReasonFlags read FReasons write FReasons;
    property AuthorityKeyIdentifier: ByteArray read FAuthorityKeyIdentifier
      write SetAuthorityKeyIdentifier;
    property BaseCRLNumber : ByteArray read FBaseCRLNumber write SetBaseCRLNumber;
  published
    property Criteria: TSBCRLLookupCriteria read FCriteria write SetCriteria;
    property Options: TSBCRLLookupOptions read FOptions write FOptions;
  end;

  TElCustomCRLStorage = class(TSBControlBase)
  protected
    FEnabled : boolean; 

    function GetCount : integer; virtual;  abstract; 
    function GetCRL(Index: integer): TElCertificateRevocationList; virtual;  abstract; 
  public
    constructor Create(AOwner: TComponent); {$ifndef SB_NO_COMPONENT}override; {$endif}

    procedure BeginRead; virtual;
    procedure EndRead; virtual;
    procedure BeginWrite; virtual;
    procedure EndWrite; virtual;

    function Add(CRL : TElCertificateRevocationList): integer; virtual; abstract;
    procedure FindMatchingCRLs(Certificate : TElX509Certificate; DistributionPoint : TElDistributionPoint; List : TElList);

    procedure Remove(Index: integer); virtual; abstract;
    procedure Clear; virtual; abstract;
    function FindFirst(Lookup: TElCRLLookup): integer;
    function FindNext(Lookup: TElCRLLookup): integer;
    procedure ExportTo(Storage : TElCustomCRLStorage);
    function IndexOf(Crl : TElCertificateRevocationList): integer; virtual; abstract; 

    property CRLs[Index: integer]: TElCertificateRevocationList read GetCRL;
    property Count : integer read GetCount;
  end;

  TElMemoryCRLStorage =  class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElMemoryCRLStorage = TElMemoryCRLStorage;
   {$endif}

  TElMemoryCRLStorage = class(TElCustomCRLStorage)
  protected
    FSharedResource : TElSharedResource;
    FList : TElList;

    function GetCount : integer; override;
    function GetCRL(Index: integer): TElCertificateRevocationList; override;
  public
    constructor Create(AOwner: TComponent); {$ifndef SB_NO_COMPONENT}override; {$endif}
     destructor  Destroy; override;
    procedure BeginRead; override;
    procedure EndRead; override;
    procedure BeginWrite; override;
    procedure EndWrite; override;

    function Add(CRL : TElCertificateRevocationList): integer; override;
    procedure Remove(Index: integer); override;
    procedure Clear; override;
    function IndexOf(Crl : TElCertificateRevocationList): integer; override; 
  end;

  TElCRLCacheStorage = class(TElMemoryCRLStorage)
  public
    function Add(CRL : TElCertificateRevocationList): integer; override;
    
    property Enabled : boolean read FEnabled write FEnabled;
  end;

  TElCustomCRLRetriever = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCustomCRLRetriever = TElCustomCRLRetriever;
   {$endif}

  TElCustomCRLRetriever = class(TSBControlBase)
  public
    function Supports(NameType : TSBGeneralName; const Location : string) : boolean; virtual; abstract;
    function GetCRL(ACertificate, CACertificate : TElX509Certificate; NameType : TSBGeneralName; const Location : string) : TElCertificateRevocationList; virtual; abstract;
  end;

  TElCustomCRLRetrieverFactory = class
  public
    function Supports(NameType : TSBGeneralName; const Location : string) : boolean; virtual; abstract;
    function GetRetrieverInstance(Validator : TObject) : TElCustomCRLRetriever; virtual; abstract;
  end;

  TElCRLManager = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCRLManager = TElCRLManager;
   {$endif}

  TElCRLManager = class
  private
    FFactoryList : TElList;
    FCache : TElCRLCacheStorage;
    FUseCache : boolean;

    procedure SetUseCache(Value : boolean);
  public
    constructor Create;
     destructor  Destroy; override;

    procedure PurgeExpiredCRLs;

    procedure RegisterCRLRetrieverFactory(Factory : TElCustomCRLRetrieverFactory);
    procedure UnregisterCRLRetrieverFactory(Factory : TElCustomCRLRetrieverFactory);
    function FindCRLRetriever(NameType : TSBGeneralName; const Location : string; Validator : TObject) : TElCustomCRLRetriever;

    property CRLCache : TElCRLCacheStorage read FCache;
    property UseCache : boolean read FUseCache write SetUseCache;
  end;

function CRLManagerAddRef : TElCRLManager; 
procedure CRLManagerRelease; 

implementation

var CRLManager : TElCRLManager  =  nil;
var CRLManagerUseCount : integer  =  0;


////////////////////////////////////////////////////////////////////////////////
// TElCustomCRLStorage class

constructor TElCustomCRLStorage.Create( AOwner: TComponent );
begin
  inherited {$ifdef SB_NO_COMPONENT}Create {$endif};
  FEnabled := True;
end;


procedure TElCustomCRLStorage.BeginRead;
begin
  // this implementation does nothing
end;

procedure TElCustomCRLStorage.EndRead;
begin
  // this implementation does nothing
end;

procedure TElCustomCRLStorage.BeginWrite;
begin
  // this implementation does nothing
end;

procedure TElCustomCRLStorage.EndWrite;
begin
  // this implementation does nothing
end;

function TElCustomCRLStorage.FindFirst(Lookup: TElCRLLookup): integer;
begin
  if not FEnabled then
  begin
    result := -1; 
    exit;
  end;

  Lookup.FLastIndex := -1;
  Result := FindNext(Lookup);
end;

procedure TElCustomCRLStorage.FindMatchingCRLs(Certificate : TElX509Certificate; DistributionPoint : TElDistributionPoint; List : TElList);
var i, idx : integer;
    CRLQ   : TElCertificateRevocationList;
    matches: boolean;
begin
  if not FEnabled then
    exit;

  BeginRead;
  try
    // comments below are parts of the algorithm described in RFC 3280, section 6.3.3
    for i := 0 to Self.Count - 1 do
    begin
      CRLQ := CRLs[i];
      //matches := false;

      // Step (1)

      // If the DP includes cRLIssuer, then
      if (DistributionPoint.CRLIssuer <> nil) and (DistributionPoint.CRLIssuer.Count > 0) then
      begin
        // then verify that the issuer field in the complete CRL matches cRLIssuer in the DP
        idx := DistributionPoint.CRLIssuer.FindNameByType(gnDirectoryName, 0);
        matches := ((idx <> -1) and CompareRDN(CRLQ.Issuer, DistributionPoint.CRLIssuer.Names[idx].DirectoryName)) and
          // and that the complete CRL contains an issuing distribution point extension
          (CRLQ.Extensions.IssuingDistributionPoint <> nil);
      end
      // Otherwise, verify that the CRL issuer matches the certificate issuer.
      else
        matches := CompareRDN(Certificate.IssuerRDN, CRLQ.Issuer);

      // Step (2)

      // If the complete CRL includes an issuing distribution point
      // (IDP) CRL extension check the following:
      if matches and (CRLQ.Extensions.IssuingDistributionPoint <> nil) then
      begin

        // (iv) Verify that the onlyContainsAttributeCerts boolean is not asserted.
        if not CRLQ.Extensions.IssuingDistributionPoint.OnlyContainsAttributeCerts then
        begin
          // (i) If the distribution point name is present in the IDP CRL extension
          if (CRLQ.Extensions.IssuingDistributionPoint.DistributionPoint.Count > 0) and
          // and the distribution field is present in the DP
             ( dppName in DistributionPoint.Included )
          then
          // verify that one of the names in the IDP matches one of the names in the DP
          begin
            matches := CRLQ.Extensions.IssuingDistributionPoint.DistributionPoint.HasCommon(DistributionPoint.Name);
          end
          else
          // If the distribution point name is present in the IDP CRL extension and
          // the distribution field is omitted from the DP
          if (CRLQ.Extensions.IssuingDistributionPoint.DistributionPoint.Count > 0) and
          // and the distribution field is present in the DP
             ( not (dppName in DistributionPoint.Included) )
          then
          // verify that one of the names in the IDP matches one of the names in the cRLIssuer field of the DP
          begin
            matches := CRLQ.Extensions.IssuingDistributionPoint.DistributionPoint.HasCommon(DistributionPoint.CRLIssuer);
          end;
        end;
      end;

      if matches then
        List.Add(CRLQ);
    end;
  finally
    EndRead;
  end;
end;

function TElCustomCRLStorage.FindNext(Lookup: TElCRLLookup): integer;
begin
  Result := Lookup.FindNext(Self);
end;

procedure TElCustomCRLStorage.ExportTo(Storage : TElCustomCRLStorage);
var
  I : integer; 
begin
  BeginRead;
  try
    for I := 0 to Count - 1 do
      Storage.Add(CRLs[I]);
  finally
    EndRead;
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// TElMemoryCRLStorage class

constructor TElMemoryCRLStorage.Create( AOwner: TComponent );
begin
  inherited {$ifdef SB_NO_COMPONENT}Create {$endif};
  FList := TElList.Create;
  FSharedResource := TElSharedResource.Create();
end;

 destructor  TElMemoryCRLStorage.Destroy;
begin
  Clear;
  FreeAndNil(FList);
  FreeAndNil(FSharedResource);
  inherited;
end;

function TElMemoryCRLStorage.Add(CRL : TElCertificateRevocationList): integer;
var
  NewCRL : TElCertificateRevocationList;
begin
  NewCRL := TElCertificateRevocationList.Create(nil);
  try
    NewCRL.Assign(CRL);
    BeginWrite;
    try
      Result := FList.Add(NewCRL);
    finally
      EndWrite;
    end;
  except
    FreeAndNil(NewCRL);
    raise;
  end;
end;
 
procedure TElMemoryCRLStorage.Remove(Index: integer);
begin
  BeginWrite;
  try
    TElCertificateRevocationList(FList[Index]). Free ;
    FList.Delete(Index);
  finally
    EndWrite;
  end;
end;
 
procedure TElMemoryCRLStorage.Clear;
var
  I : integer;
begin
  BeginWrite;
  try
    for I := 0 to FList.Count - 1 do
      TElCertificateRevocationList(FList[I]). Free ;
    FList.Clear;
  finally
    EndWrite;
  end;
end;

function TElMemoryCRLStorage.IndexOf(Crl : TElCertificateRevocationList): integer;
var
  I : integer;
begin
  Result := -1;
  FSharedResource.WaitToRead();
  try
    for I := 0 to Count - 1 do
    begin
      if CRLs[I].SameCRL(Crl, true) then
      begin
        Result := I;
        Break;
      end;
    end;
  finally
    FSharedResource.Done();
  end;
end;

function TElMemoryCRLStorage.GetCRL(Index: integer): TElCertificateRevocationList;
begin
  Result := TElCertificateRevocationList(FList[Index]);
end;

function TElMemoryCRLStorage.GetCount : integer;
begin
  Result := FList.Count;
end;

procedure TElMemoryCRLStorage.BeginRead;
begin
  FSharedResource.WaitToRead();
end;

procedure TElMemoryCRLStorage.EndRead;
begin
  FSharedResource.Done();
end;

procedure TElMemoryCRLStorage.BeginWrite;
begin
  FSharedResource.WaitToWrite();
end;

procedure TElMemoryCRLStorage.EndWrite;
begin
  FSharedResource.Done();
end;

////////////////////////////////////////////////////////////////////////////////
// TElCRLCacheStorage class
function TElCRLCacheStorage.Add(CRL : TElCertificateRevocationList): integer;
var i : integer;
    CurCRL : TElCertificateRevocationList;
    OldIdx : integer;
    NewCRL : TElCertificateRevocationList;
begin
  if not FEnabled then
  begin
    result := -1; 
    exit;
  end;
  
  OldIdx := -1;
  BeginWrite;
  try
    // first we search for existing CRL with the same attributes but possibly different time of issue
    for i := 0 to Count - 1 do
    begin
      CurCRL := CRLs[i];
      if CurCRL.SameCRL(CRL, false) then
      begin
        if CurCRL.NextUpdate < CRL.NextUpdate then
        begin
          // Remove the old CRL from the list
          FList. Delete (i);
          FreeAndNil(CurCRL);

          // create a copy
          NewCRL := TElCertificateRevocationList.Create(nil);
          NewCRL.Assign(CRL);
          FList.Insert(i, NewCRL);
          result := i;
        end;
        OldIdx := i;
        break;
      end;
    end;
    if OldIdx = -1 then
    begin
      NewCRL := TElCertificateRevocationList.Create(nil);
      NewCRL.Assign(CRL);
      FList.Add(NewCRL);
      result := FList.Count - 1;
    end
    else
      result := OldIdx;
  finally
    EndWrite;
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// TElCRLRetriever class

constructor TElCRLManager.Create;
begin
  inherited;
  FCache := TElCRLCacheStorage.Create( nil );
  FFactoryList := TElList.Create;
  FUseCache := True;
end;

 destructor  TElCRLManager.Destroy;
var
  i : integer;
begin
  FreeAndNil(FCache);

  for i := 0 to FFactoryList.Count - 1 do
    TElCustomCRLRetrieverFactory(FFactoryList[i]). Free ;
  FreeAndNil(FFactoryList);

  inherited;
end;

procedure TElCRLManager.PurgeExpiredCRLs;
var i : integer;
begin
  FCache.BeginWrite;
  try
    i := 0;
    while i < FCache.Count do
    begin
      // remove the entry if it has expired
      if (FCache.CRLs[i].NextUpdate < Now) then
        FCache.Remove(i)
      else
        inc(i);
    end;
  finally
    FCache.EndWrite;
  end;
end;

function TElCRLManager.FindCRLRetriever(NameType : TSBGeneralName; const Location : string; Validator : TObject) : TElCustomCRLRetriever;
var i : integer;
    Factory : TElCustomCRLRetrieverFactory;
begin
  result := nil;
  for i := 0 to FFactoryList.Count - 1 do
  begin
    Factory := TElCustomCRLRetrieverFactory(FFactoryList[i]);
    if Factory.Supports(NameType, Location) then
    begin
      result := Factory.GetRetrieverInstance(Validator);
      break;
    end;
  end;
end;

procedure TElCRLManager.RegisterCRLRetrieverFactory(Factory : TElCustomCRLRetrieverFactory);
begin
  FFactoryList.Add(Factory);
end;

procedure TElCRLManager.UnregisterCRLRetrieverFactory(Factory : TElCustomCRLRetrieverFactory);
begin
  FFactoryList.Remove(Factory);
end;

procedure TElCRLManager.SetUseCache(Value : boolean);
begin
  FUseCache := Value;
  FCache.Enabled := Value;
end;

procedure InitializeCRLManager;
begin
  AcquireGlobalLock;
  try
    if CRLManager = nil then
      CRLManager := TElCRLManager.Create;
  finally
    ReleaseGlobalLock;
  end;
end;

function CRLManagerAddRef : TElCRLManager;
begin
  if CRLManager = nil then
    InitializeCRLManager;
  CRLManagerUseCount := CRLManagerUseCount + 1;
  result := CRLManager;
end;

procedure CRLManagerRelease;
begin
  CRLManagerUseCount := CRLManagerUseCount - 1;
  if CRLManagerUseCount = 0 then
    FreeAndNil(CRLManager);
end;

////////////////////////////////////////////////////////////////////////////////
// TElCRLLookup class

constructor TElCRLLookup.Create(AOwner: TComponent);
begin
  {$ifndef SB_NO_COMPONENT}
  inherited ;
   {$else}
  inherited Create;
   {$endif}
  FLastIndex := -1;
  FIssuerRDN := TElRelativeDistinguishedName.Create;
end;


 destructor  TElCRLLookup.Destroy;
begin
  FreeAndNil(FIssuerRDN);
  inherited;
end;

procedure TElCRLLookup.SetCriteria(const Value: TSBCRLLookupCriteria);
begin
  FCriteria := Value;
  FLastIndex := -1;
end;

procedure TElCRLLookup.SetNumber(const V : ByteArray);
begin
  FNumber := CloneArray(V);
end;

procedure TElCRLLookup.SetAuthorityKeyIdentifier(const V: ByteArray);
begin
  FAuthorityKeyIdentifier := CloneArray(V);
end;

procedure TElCRLLookup.SetBaseCRLNumber(const V : ByteArray);
begin
  FBaseCRLNumber := CloneArray(V);
end;

function TElCRLLookup.FindNext(Storage: TElCustomCRLStorage): integer;
var
  Index: integer;
  CRL : TElCertificateRevocationList;
  B, MatchOne: boolean;
begin
  Index := FLastIndex + 1;
  Result := -1;
  while Index < Storage.Count do
  begin
    FLastIndex := Index;
    CRL := Storage.CRLs[Index];
    MatchOne := false;
    Inc(Index);

    // 1. Issuer
    if clcIssuer in FCriteria then
    begin
      if cloExactMatch in FOptions then
        B := CompareRDN(FIssuerRDN, CRL.Issuer)
      else
        B := NonstrictCompareRDN(FIssuerRDN, CRL.Issuer);
      if (not B) and (cloMatchAll in FOptions) then
        Continue;
      MatchOne := MatchOne or B;
    end;
// TODO: 
(*
// 2. Subject
{$ifdef SB_VCL}
if lcSubject in FCriteria then
{$else}
if lcSubject and FCriteria = lcSubject then
{$endif}
begin
{$ifdef SB_VCL}
  if loExactMatch in FOptions then
{$else}
  if loExactMatch and FOptions = loExactMatch then
{$endif}
B := CompareRDN(FSubjectRDN, Cert.SubjectRDN)
  else
B := NonstrictCompareRDN(FSubjectRDN, Cert.SubjectRDN);
{$ifdef SB_VCL}
  if (not B) and (loMatchAll in FOptions) then
{$else}
  if (not B) and (loMatchAll and FOptions = loMatchAll) then
{$endif}
Continue;
  MatchOne := MatchOne or B;
end;
// 3. ValidFrom
{$ifdef SB_VCL}
if lcValidity in FCriteria then
{$else}
if lcValidity and FCriteria = lcValidity then
{$endif}
begin
  if FDateLookupOptions = {$ifdef SB_VCL}
[dloBefore]{$else}dloBefore{$endif} then
B := (Cert.ValidFrom <= FValidFrom) and (Cert.ValidTo <= FValidFrom)
  else
if FDateLookupOptions = {$ifdef SB_VCL} [dloBefore,
  dloBetween]{$else}dloBefore or dloBetween{$endif} then
B := (Cert.ValidFrom <= FValidFrom) and (Cert.ValidTo >= FValidFrom)
  else
if FDateLookupOptions = {$ifdef SB_VCL} [dloBefore, dloBetween,
  dloAfter]{$else}dloBefore or dloBetween or dloAfter{$endif} then
B := (Cert.ValidFrom <= FValidFrom) and (Cert.ValidTo >= FValidTo)
  else
if FDateLookupOptions = {$ifdef SB_VCL} [dloBetween,
  dloAfter]{$else}dloBetween or dloAfter{$endif} then
B := (Cert.ValidFrom >= FValidFrom) and (Cert.ValidTo >= FValidTo)
  else
if FDateLookupOptions = {$ifdef SB_VCL}
  [dloBetween]{$else}dloBetween{$endif} then
B := (Cert.ValidFrom >= FValidFrom) and (Cert.ValidTo <= FValidTo)
  else
if FDateLookupOptions = {$ifdef SB_VCL} [dloBefore,
  dloAfter]{$else}dloBefore or dloAfter{$endif} then
B := (Cert.ValidTo <= FValidFrom) or (Cert.ValidFrom >= FValidTo)
  else
if FDateLookupOptions = {$ifdef SB_VCL}
  [dloAfter]{$else}dloAfter{$endif} then
B := (Cert.ValidFrom >= FValidTo) and (Cert.ValidTo >= FValidTo)
  else
B := true;
{$ifdef SB_VCL}
  if (not B) and (loMatchAll in FOptions) then
{$else}
  if (not B) and (loMatchAll and FOptions = loMatchAll) then
{$endif}
Continue;
  MatchOne := MatchOne or B;
end;
// 5. Public Key Algorithm
{$ifdef SB_VCL}
if lcPublicKeyAlgorithm in FCriteria then
{$else}
if lcPublicKeyAlgorithm and FCriteria = lcPublicKeyAlgorithm then
{$endif}
begin
  B := Cert.PublicKeyAlgorithm = FPublicKeyAlgorithm;
{$ifdef SB_VCL}
  if (not B) and (loMatchAll in FOptions) then
{$else}
  if (not B) and (loMatchAll and FOptions = loMatchAll) then
{$endif}
Continue;
  MatchOne := MatchOne or B;
end;
// 6. Signature algorithm
{$ifdef SB_VCL}
if lcSignatureAlgorithm in FCriteria then
{$else}
if lcSignatureAlgorithm and FCriteria = lcSignatureAlgorithm then
{$endif}
begin
  B := Cert.SignatureAlgorithm = FSignatureAlgorithm;
{$ifdef SB_VCL}
  if (not B) and (loMatchAll in FOptions) then
{$else}
  if (not B) and (loMatchAll and FOptions = loMatchAll) then
{$endif}
Continue;
  MatchOne := MatchOne or B;
end;
// 7. PublicKeySize
{$ifdef SB_VCL}
if lcPublicKeySize in FCriteria then
{$else}
if lcPublicKeySize and FCriteria = lcPublicKeySize then
{$endif}
begin
  if FKeySizeLookupOption = {$ifndef SB_NET}ksloSmaller{$else}TSBKeySizeLookupOption.ksloSmaller{$endif} then
B := Cert.GetPublicKeySize <= FPublicKeySizeMin
  else
if FKeySizeLookupOption = {$ifndef SB_NET}ksloGreater{$else}TSBKeySizeLookupOption.ksloGreater{$endif} then
B := Cert.GetPublicKeySize >= FPublicKeySizeMax
  else
if FKeySizeLookupOption = {$ifndef SB_NET}ksloBetween{$else}TSBKeySizeLookupOption.ksloBetween{$endif} then
B := (Cert.GetPublicKeySize <= FPublicKeySizeMax) and
  (Cert.GetPublicKeySize >= FPublicKeySizeMin)
  else
B := false;
{$ifdef SB_VCL}
  if (not B) and (loMatchAll in FOptions) then
{$else}
  if (not B) and (loMatchAll and FOptions = loMatchAll) then
{$endif}
Continue;
  MatchOne := MatchOne or B;
end;
// 8. Auth key id
{$ifdef SB_VCL}
if lcAuthorityKeyIdentifier in FCriteria then
{$else}
if lcAuthorityKeyIdentifier and FCriteria = lcAuthorityKeyIdentifier then
{$endif}
begin
{$ifdef SB_VCL}
  B := (ceAuthorityKeyIdentifier in Cert.Extensions.Included) and
{$else}
  B := (ceAuthorityKeyIdentifier and Cert.Extensions.Included =
ceAuthorityKeyIdentifier) and
{$endif}
  (CompareContent(FAuthorityKeyIdentifier,
Cert.Extensions.AuthorityKeyIdentifier.KeyIdentifier));
{$ifdef SB_VCL}
  if (not B) and (loMatchAll in FOptions) then
{$else}
  if (not B) and (loMatchAll and FOptions = loMatchAll) then
{$endif}
Continue;
  MatchOne := MatchOne or B;
end;
// 9. Subject key id
{$ifdef SB_VCL}
if lcSubjectKeyIdentifier in FCriteria then
{$else}
if lcSubjectKeyIdentifier and FCriteria = lcSubjectKeyIdentifier then
{$endif}
begin
{$ifdef SB_VCL}
  B := (ceSubjectKeyIdentifier in Cert.Extensions.Included) and
{$else}
  B := (ceSubjectKeyIdentifier and Cert.Extensions.Included =
ceSubjectKeyIdentifier) and
{$endif}
  (CompareContent(FSubjectKeyIdentifier,
Cert.Extensions.SubjectKeyIdentifier.KeyIdentifier));
{$ifdef SB_VCL}
  if (not B) and (loMatchAll in FOptions) then
{$else}
  if (not B) and (loMatchAll and FOptions = loMatchAll) then
{$endif}
Continue;
  MatchOne := MatchOne or B;
end;
// 10. KeyUsage
{$ifdef SB_VCL}
if lcKeyUsage in FCriteria then
{$else}
if lcKeyUsage and FCriteria = lcKeyUsage then
{$endif}
begin
{$ifdef SB_VCL}
  if kuloMatchAll in FKeyUsageLookupOptions then
{$else}
  if kuloMatchAll and FKeyUsageLookupOptions = kuloMatchAll then
{$endif}
{$ifdef SB_VCL}
B := (ceKeyUsage in Cert.Extensions.Included) and
  (kuDigitalSignature in FKeyUsage) and
(Cert.Extensions.KeyUsage.DigitalSignature) and
  (kuNonRepudiation in FKeyUsage) and
(Cert.Extensions.KeyUsage.NonRepudiation) and
  (kuKeyEncipherment in FKeyUsage) and
(Cert.Extensions.KeyUsage.KeyEncipherment) and
  (kuDataEncipherment in FKeyUsage) and
(Cert.Extensions.KeyUsage.DataEncipherment) and
  (kuKeyAgreement in FKeyUsage) and
(Cert.Extensions.KeyUsage.KeyAgreement) and
  (kuKeyCertSign in FKeyUsage) and (Cert.Extensions.KeyUsage.KeyCertSign)
and
  (kuCRLSign in FKeyUsage) and (Cert.Extensions.KeyUsage.CRLSign) and
  (kuEncipherOnly in FKeyUsage) and
(Cert.Extensions.KeyUsage.EncipherOnly) and
  (kuDecipherOnly in FKeyUsage) and
(Cert.Extensions.KeyUsage.DecipherOnly)
  else
B := (ceKeyUsage in Cert.Extensions.Included) and
  ((kuDigitalSignature in FKeyUsage) and
(Cert.Extensions.KeyUsage.DigitalSignature)) or
  ((kuNonRepudiation in FKeyUsage) and
(Cert.Extensions.KeyUsage.NonRepudiation)) or
  ((kuKeyEncipherment in FKeyUsage) and
(Cert.Extensions.KeyUsage.KeyEncipherment)) or
  ((kuDataEncipherment in FKeyUsage) and
(Cert.Extensions.KeyUsage.DataEncipherment)) or
  ((kuKeyAgreement in FKeyUsage) and
(Cert.Extensions.KeyUsage.KeyAgreement)) or
  ((kuKeyCertSign in FKeyUsage) and
(Cert.Extensions.KeyUsage.KeyCertSign)) or
  ((kuCRLSign in FKeyUsage) and (Cert.Extensions.KeyUsage.CRLSign)) or
  ((kuEncipherOnly in FKeyUsage) and
(Cert.Extensions.KeyUsage.EncipherOnly)) or
  ((kuDecipherOnly in FKeyUsage) and
(Cert.Extensions.KeyUsage.DecipherOnly));
{$else}
B := (ceKeyUsage and Cert.Extensions.Included = ceKeyUsage) and
  (kuDigitalSignature and FKeyUsage = kuDigitalSignature) and
(Cert.Extensions.KeyUsage.DigitalSignature) and
  (kuNonRepudiation and FKeyUsage = kuNonRepudiation) and
(Cert.Extensions.KeyUsage.NonRepudiation) and
  (kuKeyEncipherment and FKeyUsage = kuKeyEncipherment) and
(Cert.Extensions.KeyUsage.KeyEncipherment) and
  (kuDataEncipherment and FKeyUsage = kuDataEncipherment) and
(Cert.Extensions.KeyUsage.DataEncipherment) and
  (kuKeyAgreement and FKeyUsage = kuKeyAgreement) and
(Cert.Extensions.KeyUsage.KeyAgreement) and
  (kuKeyCertSign and FKeyUsage = kuKeyCertSign) and
(Cert.Extensions.KeyUsage.KeyCertSign) and
  (kuCRLSign and FKeyUsage = kuCRLSign) and
(Cert.Extensions.KeyUsage.CRLSign) and
  (kuEncipherOnly and FKeyUsage = kuEncipherOnly) and
(Cert.Extensions.KeyUsage.EncipherOnly) and
  (kuDecipherOnly and FKeyUsage = kuDecipherOnly) and
(Cert.Extensions.KeyUsage.DecipherOnly)
  else
B := (ceKeyUsage and Cert.Extensions.Included = ceKeyUsage) and
  ((kuDigitalSignature and FKeyUsage = kuDigitalSignature) and
(Cert.Extensions.KeyUsage.DigitalSignature)) or
  ((kuNonRepudiation and FKeyUsage = kuNonRepudiation) and
(Cert.Extensions.KeyUsage.NonRepudiation)) or
  ((kuKeyEncipherment and FKeyUsage = kuKeyEncipherment) and
(Cert.Extensions.KeyUsage.KeyEncipherment)) or
  ((kuDataEncipherment and FKeyUsage = kuDataEncipherment) and
(Cert.Extensions.KeyUsage.DataEncipherment)) or
  ((kuKeyAgreement and FKeyUsage = kuKeyAgreement) and
(Cert.Extensions.KeyUsage.KeyAgreement)) or
  ((kuKeyCertSign and FKeyUsage = kuKeyCertSign) and
(Cert.Extensions.KeyUsage.KeyCertSign)) or
  ((kuCRLSign and FKeyUsage = kuCRLSign) and
(Cert.Extensions.KeyUsage.CRLSign)) or
  ((kuEncipherOnly and FKeyUsage = kuEncipherOnly) and
(Cert.Extensions.KeyUsage.EncipherOnly)) or
  ((kuDecipherOnly and FKeyUsage = kuDecipherOnly) and
(Cert.Extensions.KeyUsage.DecipherOnly));
{$endif}
{$ifdef SB_VCL}
  if (not B) and (loMatchAll in FOptions) then
{$else}
  if (not B) and (loMatchAll and FOptions = loMatchAll) then
{$endif}
Continue;
  MatchOne := MatchOne or B;
end;
// 11. E-mail address
{$ifdef SB_VCL}
if lcEmail in FCriteria then
{$else}
if lcEmail and FCriteria = lcEmail then
{$endif}
begin
  B := false;
{$ifdef SB_VCL}
  for I := 0 to FEmailAddresses.Count - 1 do
  begin
if CompareText(Cert.SubjectName.EMailAddress, FEmailAddresses[I]) = 0
  then
begin
  B := true;
  Break;
end;
  end;
{$else}
  Arr := ArrayList.Create;
  Cert.SubjectRDN.GetValuesByOID(SB_CERT_OID_EMAIL, Arr);
  for J := 0 to Arr.Count - 1 do
  begin
for I := 0 to FEmailAddresses.Count - 1 do
begin
  if CompareMem(BytesOfString(FEmailAddresses[I]), ByteArray(Arr[J]))
then
  begin
B := true;
Break;
  end;
end;
  end;
{$endif}
  if not B then
  begin
{$ifdef SB_VCL}
if ceSubjectAlternativeName in Cert.Extensions.Included then
{$else}
if ceSubjectAlternativeName and Cert.Extensions.Included =
  ceSubjectAlternativeName then
{$endif}
begin
  for K := 0 to Cert.Extensions.SubjectAlternativeName.Content.Count - 1 do
  begin
if Length(Cert.Extensions.SubjectAlternativeName.Content.Names[K].RFC822Name) > 0 then
begin
  for I := 0 to FEmailAddresses.Count - 1 do
  begin
{$ifdef SB_VCL}
if
  (CompareText(Cert.Extensions.SubjectAlternativeName.Content.Names[K].RFC822Name,
  FEmailAddresses[I]) = 0) then
{$else}
if
  (CompareStr(Cert.Extensions.SubjectAlternativeName.Content.Names[K].RFC822Name,
  FEmailAddresses[I]) = 0) then
{$endif}
begin
  B := true;
  Break;
end;
  end;
  if B then
Break;
end;
  end;
end;
  end;
{$ifdef SB_VCL}
  if (not B) and (loMatchAll in FOptions) then
{$else}
  if (not B) and (loMatchAll and FOptions = loMatchAll) then
{$endif}
Continue;
  MatchOne := MatchOne or B;
end;
// 12. Serial number
{$ifdef SB_VCL}
if lcSerialNumber in FCriteria then
{$else}
if lcSerialNumber and FCriteria = lcSerialNumber then
{$endif}
begin
  B := SerialNumberCorresponds(Cert, FSerialNumber);
{$ifdef SB_VCL}
  if (not B) and (loMatchAll in FOptions) then
{$else}
  if (not B) and (loMatchAll and FOptions = loMatchAll) then
{$endif}
Continue;
  MatchOne := MatchOne or B;
end;
// 13. Public key hash
{$ifdef SB_VCL}
if lcPublicKeyHash in FCriteria then
{$else}
if lcPublicKeyHash and FCriteria = lcPublicKeyHash then
{$endif}
begin
  Buf := EmptyArray;
  try
HashFunc := TElHashFunction.Create(FPublicKeyHashAlgorithm);
try
  Size := 0;
  Cert.GetPublicKeyBlob({$ifdef SB_VCL}nil{$else}Buf{$endif}, Size);
  SetLength(Buf, Size);
  Cert.GetPublicKeyBlob({$ifdef SB_VCL}@Buf[1]{$else}Buf{$endif}, Size);
  HashFunc.Update({$ifdef SB_VCL}@Buf[1]{$else}Buf, 0{$endif}, Size);
  Buf := HashFunc.Finish();
finally
  FreeAndNil(HashFunc);
end;
  except
;
  end;
  B := CompareContent(Buf, FPublicKeyHash);
{$ifdef SB_VCL}
  if (not B) and (loMatchAll in FOptions) then
{$else}
  if (not B) and (loMatchAll and FOptions = loMatchAll) then
{$endif}
Continue;
  MatchOne := MatchOne or B;
end;
// 14. Certificate hash
{$ifdef SB_VCL}
if lcCertificateHash in FCriteria then
{$else}
if lcCertificateHash and FCriteria = lcCertificateHash then
{$endif}
begin
  Buf := EmptyArray;
  try
HashFunc := TElHashFunction.Create(FCertificateHashAlgorithm);
try
  dwSize := 0;
  Cert.SaveToBuffer({$ifdef SB_VCL}nil{$else}Buf{$endif}, dwSize);
  SetLength(Buf, dwSize);
  Cert.SaveToBuffer({$ifdef SB_VCL}@Buf[0]{$else}Buf{$endif}, dwSize);
  HashFunc.Update({$ifdef SB_VCL}@Buf[0]{$else}Buf, 0{$endif}, dwSize);
  Buf := HashFunc.Finish();
finally
  FreeAndNil(HashFunc);
end;
  except
;
  end;
  B := CompareContent(Buf, FCertificateHash);
{$ifdef SB_VCL}
  if (not B) and (loMatchAll in FOptions) then
{$else}
  if (not B) and (loMatchAll and FOptions = loMatchAll) then
{$endif}
Continue;
  MatchOne := MatchOne or B;
end;
  *)

    if MatchOne then
    begin
      Result := Index - 1;
      Break;
    end;
  end;
end;

// we grab one account of CRLManager in order to save one instance from the beginning to the end of application operations
initialization

  CRLManagerAddRef;

finalization

  CRLManagerRelease;

end.
