(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBCustomCertStorage;

interface

uses
  Classes,
  SysUtils,
  {$ifdef SB_UNICODE_VCL}
  SBStringList,
   {$endif}
  SBASN1,
  SBASN1Tree,
  SBCryptoProv,
  SBRDN,
  SBSymmetricCrypto,
  SBX509,
  SBX509Ext,
  SBCRL,
  SBPEM,
{$ifndef SB_NO_JKS}
  SBJKS,
 {$endif}
  SBStreams,
  SBSharedResource,
  SBConstants,
  SBEncoding,
  SBTypes,
  SBUtils
  ;



type

  TElCustomCertStorage =  class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCustomCertStorage = TElCustomCertStorage;
   {$endif}

  TSBLookupCriterion = (lcIssuer, lcSubject, lcValidity, lcPublicKeyAlgorithm,
    lcSignatureAlgorithm, lcPublicKeySize, lcAuthorityKeyIdentifier,
    lcSubjectKeyIdentifier, lcKeyUsage, lcEmail, lcSerialNumber,
    lcPublicKeyHash, lcCertificateHash);
  TSBLookupCriteria = set of TSBLookupCriterion;
  TSBLookupOption = (loExactMatch, loMatchAll, loCompareRDNAsStrings);
  TSBLookupOptions = set of TSBLookupOption;
  TSBDateLookupOption = (dloBefore, dloAfter, dloBetween);
  TSBDateLookupOptions = set of TSBDateLookupOption;

  TSBKeySizeLookupOption = 
    (ksloSmaller, ksloGreater, ksloBetween);

  TSBKeyUsageLookupOption = (kuloMatchAll);
  TSBKeyUsageLookupOptions = set of TSBKeyUsageLookupOption;

  TElCertificateLookup = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCertificateLookup = TElCertificateLookup;
   {$endif}

  TElCertificateLookup = class (TSBControlBase)
  private
    FCriteria: TSBLookupCriteria;
    FOptions: TSBLookupOptions;
    FIssuerRDN: TElRelativeDistinguishedName;
    FSubjectRDN: TElRelativeDistinguishedName;
    FValidFrom: TElDateTime;
    FValidTo: TElDateTime;
    FPublicKeyAlgorithm: integer;
    FSignatureAlgorithm: integer;
    FPublicKeySizeMin: integer;
    FPublicKeySizeMax: integer;
    FAuthorityKeyIdentifier: ByteArray;
    FSubjectKeyIdentifier: ByteArray;
    FKeyUsage: TSBKeyUsage;
    FEmailAddresses: TStringList;
    FSerialNumber : ByteArray;
    FPublicKeyHash : ByteArray;
    FPublicKeyHashAlgorithm : integer;
    FCertificateHash : ByteArray;
    FCertificateHashAlgorithm : integer;
    FDateLookupOptions: TSBDateLookupOptions;
    FKeySizeLookupOption: TSBKeySizeLookupOption;
    FKeyUsageLookupOptions: TSBKeyUsageLookupOptions;
  protected
    FLastIndex: integer;
    function FindNext(Storage: TElCustomCertStorage): integer; virtual;
    procedure SetCriteria(Value: TSBLookupCriteria);
    procedure SetAuthorityKeyIdentifier(const V: ByteArray);
    procedure SetSubjectKeyIdentifier(const V: ByteArray);
    procedure SetSerialNumber(const V : ByteArray);
    procedure SetPublicKeyHash(const V : ByteArray);
    procedure SetCertificateHash(const V : ByteArray);
  public
    constructor Create(AOwner: TComponent); override;
     destructor  Destroy; override;

    property AuthorityKeyIdentifier: ByteArray read FAuthorityKeyIdentifier
        write SetAuthorityKeyIdentifier;
    property SubjectKeyIdentifier: ByteArray read FSubjectKeyIdentifier
        write SetSubjectKeyIdentifier;
    property SerialNumber : ByteArray read FSerialNumber write SetSerialNumber;
    property PublicKeyHash : ByteArray read FPublicKeyHash write SetPublicKeyHash;
    property CertificateHash : ByteArray read FCertificateHash write SetCertificateHash;
  published
    property Criteria: TSBLookupCriteria read FCriteria write SetCriteria;
    property Options: TSBLookupOptions read FOptions write FOptions;
    property IssuerRDN: TElRelativeDistinguishedName read FIssuerRDN;
    property SubjectRDN: TElRelativeDistinguishedName read FSubjectRDN;
    property ValidFrom: TElDateTime read
      FValidFrom write FValidFrom;
    property ValidTo: TElDateTime read
      FValidTo write FValidTo;
    property PublicKeyAlgorithm: integer read FPublicKeyAlgorithm
    write FPublicKeyAlgorithm;
    property SignatureAlgorithm: integer read FSignatureAlgorithm
    write FSignatureAlgorithm;
    property PublicKeySizeMin: integer read FPublicKeySizeMin
    write FPublicKeySizeMin;
    property PublicKeySizeMax: integer read FPublicKeySizeMax
    write FPublicKeySizeMax;
    property KeyUsage: TSBKeyUsage read FKeyUsage write FKeyUsage;
    property EmailAddresses: TStringList read FEmailAddresses;
    property PublicKeyHashAlgorithm : integer read FPublicKeyHashAlgorithm write FPublicKeyHashAlgorithm;
    property CertificateHashAlgorithm : integer read FCertificateHashAlgorithm
      write FCertificateHashAlgorithm; 
    property DateLookupOptions: TSBDateLookupOptions read FDateLookupOptions
    write FDateLookupOptions;
    property KeySizeLookupOption: TSBKeySizeLookupOption read
      FKeySizeLookupOption
    write FKeySizeLookupOption;
    property KeyUsageLookupOptions: TSBKeyUsageLookupOptions
    read FKeyUsageLookupOptions write FKeyUsageLookupOptions;
  end;

  TSBCertStorageOption = (csoStrictChainBuilding);
  TSBCertStorageOptions = set of TSBCertStorageOption;

  TElCustomCertStorage = class(TElBaseCertStorage)
  private
    FOptions : TSBCertStorageOptions;
    {$ifndef FPC}
    procedure ReadCertificatesProp(Reader: TStream);
    procedure WriteCertificatesProp(Writer: TStream);
    function IsCertificatesPropStored: boolean;
    procedure ReadFakeCertificatesProp(Reader: TReader);
     {$endif}
  protected
    FRebuildChains: boolean;
    FChains: array of integer;
    FCRL: TElCertificateRevocationList;
    FSharedResource: TElSharedResource;
    FCryptoProviderManager : TElCustomCryptoProviderManager;
  protected
    function Equal(const N1, N2: TName): boolean;
    procedure AssignTo(Dest: TPersistent); override;
    {$ifndef FPC}
    procedure DefineProperties(Filer: TFiler); override;
     {$endif}
    {$ifndef SB_NO_JKS}
    function AliasNeededInt(Cert : TElX509Certificate;  var Alias: string ): boolean;
     {$endif}
    function IsIssuerCertificate(Subject, Issuer: TElX509Certificate): boolean;
    procedure BuildAllChains;
    procedure Notification(AComponent: TComponent; Operation: TOperation); override;
    
    function GetCount: integer; virtual;
    function GetChainCount: integer;
    procedure SetCRL(Value: TElCertificateRevocationList);
    procedure SetCryptoProviderManager(Value: TElCustomCryptoProviderManager);
    

    function  GetCertificates (Index: integer): TElX509Certificate; virtual;
    function GetChain(Index: integer): integer;
  public
    constructor Create(Owner: TComponent); override;
     destructor  Destroy; override;

    function Validate(Certificate: TElX509Certificate;
      var Reason: TSBCertificateValidityReason;
      ValidityMoment:  TDateTime = 0 ):
    TSBCertificateValidity;  overload;  virtual; 

    function Validate(Certificate: TElX509Certificate;
      var Reason: TSBCertificateValidityReason;
      CheckCACertDates : boolean;
      ValidityMoment:  TDateTime = 0 ):
    TSBCertificateValidity;  overload;  virtual; 

    procedure Add(Certificate: TElX509Certificate; CopyPrivateKey: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif}); virtual; abstract;
    procedure Remove(Index: integer); virtual; abstract;
    procedure ExportTo(Storage: TElCustomCertStorage); virtual;

    function LoadFromBufferPKCS7(Buffer: pointer; Size: longint) : integer;
    function SaveToBufferPKCS7(Buffer: pointer; var Size: longint) : boolean;
    function LoadFromStreamPKCS7(Stream: TElStream; Count: integer = 0): integer;
    function SaveToStreamPKCS7(Stream: TElStream): boolean;

    function LoadFromBufferPEM(Buffer: pointer; Size: longint; const Password : string) : integer;
    function SaveToBufferPEM(Buffer: pointer; var Size: longint; const Password : string) : boolean; overload;
    function SaveToBufferPEM(Buffer: pointer; var Size: longint; const Password : string;
      EncryptionAlgorithm : integer; EncryptionMode :  TSBSymmetricCryptoMode ) : boolean; overload;
    function LoadFromStreamPEM(Stream : TElStream; const Password : string; Count: integer = 0): integer;
    function SaveToStreamPEM(Stream : TElStream; const Password : string): boolean; overload;
    function SaveToStreamPEM(Stream : TElStream; const Password : string;
      EncryptionAlgorithm : integer; EncryptionMode :  TSBSymmetricCryptoMode ): boolean; overload;
    {$ifndef SB_NO_JKS}
    function LoadFromBufferJKS(Buffer: pointer; const Pass: string; Size: longint; OnPasswordNeeded : TElJKSPasswordEvent = nil) : boolean;
    function SaveToBufferJKS(Buffer: pointer; const Pass: string; var Size: longint) : boolean;
    function SaveToBufferJKSEx(Buffer: pointer; const Pass: string; var Size: longint; OnAliasNeeded : TElJKSAliasNeededEvent) : boolean;
    function LoadFromStreamJKS(Stream: TElStream; const Pass: string; Count: integer = 0; OnPasswordNeeded : TElJKSPasswordEvent = nil ): boolean;
    function SaveToStreamJKS(Stream: TElStream; const Pass: string): boolean;
    function SaveToStreamJKSEx(Stream: TElStream; const Pass: string; OnAliasNeeded : TElJKSAliasNeededEvent): boolean;
     {$endif}

    function LoadFromBufferPFX(Buffer: pointer; Size: integer; const Password:
      string): integer;
    function SaveToBufferPFX(Buffer: pointer; var Size: integer; const Password:
      string; KeyEncryptionAlgorithm: integer; CertEncryptionAlgorithm:
      integer): integer; overload;
    function SaveToBufferPFX(Buffer: pointer; var Size: integer; const Password:
      string): integer; overload;
    function LoadFromStreamPFX(Stream: TElStream; const Password: string;
      Count: integer = 0): integer; 
    function SaveToStreamPFX(Stream: TElStream; const Password: string;
      KeyEncryptionAlgorithm: integer; CertEncryptionAlgorithm: integer):
        integer; overload;
    function SaveToStreamPFX(Stream: TElStream; const Password: string): integer; overload;

    function LoadFromBufferPkiPath(Buffer: pointer; Size: integer): boolean;
    function SaveToBufferPkiPath(Buffer: pointer; var Size: integer): boolean; overload;
    function LoadFromStreamPkiPath(Stream: TElStream; Count: integer = 0): boolean;
    function SaveToStreamPkiPath(Stream: TElStream): boolean; overload;


    function BuildChain(Certificate : TElX509Certificate): TElX509CertificateChain;  overload; 
    function BuildChain(ChainIndex: Integer): TElX509CertificateChain;  overload; 
    
    function IndexOf(Certificate: TElX509Certificate): Integer; virtual;
    function IsPresent(Certificate: TElX509Certificate): boolean;
    procedure Clear; virtual;
    function FindByHash(const Digest: TMessageDigest160): integer; overload;
    function FindByHash(const Digest: TMessageDigest128): integer; overload;
    function GetIssuerCertificate(Certificate: TElX509Certificate): integer;
      virtual;
    class function IsReadOnly: Boolean; virtual;
    function FindFirst(Lookup: TElCertificateLookup): integer;
    function FindNext(Lookup: TElCertificateLookup): integer;
    procedure ImportFrom(Chain: TElX509CertificateChain);  overload;  virtual;
    procedure ImportFrom(Chain: TElX509CertificateChain; ImportEndEntity : boolean);  overload;  virtual; 
    procedure BeginRead;
    function Contains(Certificate: TElX509Certificate): Boolean;
    procedure EndRead;

    property Count: integer read GetCount;
    property ChainCount: integer read GetChainCount;
    
    property Certificates[Index: integer]: TElX509Certificate read  GetCertificates ;  default; 
    property Chains[Index: integer]: integer read GetChain;
    
  published
    property CRL: TElCertificateRevocationList read FCRL write SetCRL;
    property CryptoProviderManager : TElCustomCryptoProviderManager
      read FCryptoProviderManager write SetCryptoProviderManager;
    property Options : TSBCertStorageOptions read FOptions write FOptions;
  end;

  TSBCertificateValidationEvent =  procedure(Sender : TObject;
    Certificate : TElX509Certificate;
    AdditionalCertificates : TElCustomCertStorage;
    var Validity : TSBCertificateValidity;
    var Reason: TSBCertificateValidityReason;
    var DoContinue : TSBBoolean
    ) of object;


  TElMemoryCertStorage = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElMemoryCertStorage = TElMemoryCertStorage;
   {$endif}

  TElMemoryCertStorage = class(TElCustomCertStorage)
  private
    FCertificateList:  TSBObjectList ;
  protected
    function GetCount: integer; override;
    function  GetCertificates (Index: integer): TElX509Certificate; override;
  public
    constructor Create(Owner: TComponent); override;
     destructor  Destroy; override;

    procedure Add(X509Certificate: TElX509Certificate; CopyPrivateKey: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif}); override;
    
    procedure Remove(Index: integer); override;
    property CertificateList: TSBObjectList read FCertificateList;
  end;

  TSBFileCertStorageAccessType =  
    (csatImmediate, csatOnDemand);

  TSBFileCertStorageSaveOption = (fcsoSaveOnDestroy, fcsoSaveOnFilenameChange,
    fcsoSaveOnChange);
  TSBFileCertStorageSaveOptions = set of TSBFileCertStorageSaveOption;

{$ifndef SB_NO_FILESTREAM}

  TElFileCertStorage = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElFileCertStorage = TElFileCertStorage;
   {$endif}

  TElFileCertStorage = class(TElCustomCertStorage)
  private
    FFileName: string;
    FCertificateList:  TSBObjectList ;
    FLoaded: boolean;
    FAccessType: TSBFileCertStorageAccessType;
    FSaveOptions: TSBFileCertStorageSaveOptions;
  protected
    procedure LoadFromFile;
    procedure InternalClear;
    procedure CreateEmptyStorage;

    function GetCount: integer; override;
    procedure SetFileName(const FileName: string);
    procedure SetAccessType(Value: TSBFileCertStorageAccessType);

    function  GetCertificates (Index: integer): TElX509Certificate; override;
  public
    constructor Create(Owner: TComponent); override;
     destructor  Destroy; override;

    function Validate(Certificate: TElX509Certificate; var Reason:
      TSBCertificateValidityReason; CheckCACertDates : boolean; ValidityMoment:  TDateTime
        = 0 ): TSBCertificateValidity;  overload;  override;
    
    procedure Add(X509Certificate: TElX509Certificate; 
        CopyPrivateKey: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif}); override;
    procedure Remove(Index: integer); override;
    procedure Clear; override;
    procedure SaveToFile(const FileName: string);
    procedure Reload;
    procedure Save;
  published
    property FileName: string read FFileName write SetFileName;
    property AccessType: TSBFileCertStorageAccessType read FAccessType
    write SetAccessType  default csatOnDemand ;
    property SaveOptions: TSBFileCertStorageSaveOptions read FSaveOptions
    write FSaveOptions  default  []  ;
  end;

 {$endif}

  EElCertStorageError =  class(ESecureBlackboxError);
  EElDuplicateCertError =  class(EElCertStorageError);

procedure Register;

implementation

{$ifdef WIN32}
uses
  Windows,
 {$else}
uses
  //{$ifndef FPC}Libc,{$endif}
 {$endif}
  SBPKCS12,
  SBSHA,
  SBMD,
  SBPKCS7,
  SBPKCS7Utils,
  SBStrUtils,
  {$ifndef SB_NO_JKS}
  SBPKCS8,
   {$endif}
  SBHashFunction;


procedure Register;
begin
  RegisterComponents('PKIBlackbox', [TElFileCertStorage,
    TElMemoryCertStorage, TElCertificateLookup]);
end;

//const
//  BufferSize: longint = 400000;

{$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
 {$else}
var
 {$endif}

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS OFF}
 {$endif}

  PKCS7OID : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =   #$2A#$86#$48#$86#$F7#$0D#$01#$07#$02 {$endif};  
  PKCS7Data: TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =   #$2A#$86#$48#$86#$F7#$0D#$01#$07#$01 {$endif};  

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS ON}
 {$endif}

resourcestring
//  SInvalidPKCS7File = 'Invalid PKCS7 file';
//  SCannotAccessFile = 'Can not access file';
  SNoSignedData = 'No signed data found';
//  SUnableToWritePKCS7Data = 'Unable to write PKCS7 data';
  SUnableToMountStorage = 'Unable to mount file storage';


////////////////////////////////////////////////////////////////////////////////
// TElCustomCertStorage
////////////////////////////////////////////////////////////////////////////////

constructor TElCustomCertStorage.Create(Owner:
 TComponent );
begin
  inherited Create (Owner) ;
  FRebuildChains := true;
  FSharedResource := TElSharedResource.Create;
  FOptions := [csoStrictChainBuilding];
end;


 destructor  TElCustomCertStorage.Destroy;
begin
  FreeAndNil(FSharedResource);
  inherited;
end;

function TElCustomCertStorage.Equal(const N1, N2: TName): boolean;
begin
  if (N1.Country = N2.Country) and (N1.StateOrProvince = N2.StateOrProvince) and
    (N1.Locality = N2.Locality) and (N1.Organization = N2.Organization) and
    (N1.OrganizationUnit = N2.OrganizationUnit) and (N1.CommonName =
    N2.CommonName) then
    Result := true
  else
    Result := false;
end;

function TElCustomCertStorage.Validate(Certificate: TElX509Certificate;
  var Reason: TSBCertificateValidityReason; ValidityMoment:
     TDateTime = 0 ): TSBCertificateValidity;
begin
  result := Validate(Certificate, Reason, false, ValidityMoment);
end;

function TElCustomCertStorage.Validate(Certificate: TElX509Certificate;
  var Reason: TSBCertificateValidityReason; CheckCACertDates : boolean; ValidityMoment:
     TDateTime = 0 ): TSBCertificateValidity;
var
  CACert: TElX509Certificate;
  I: longint;
  vm: double;
begin
  CheckLicenseKey();
   Result  :=  cvOk ;
  Reason :=   [vrUnknownCA] ;
  try
    vm := ValidityMoment;
    if ValidityMoment = 0.0 then
    {$ifdef SB_WINDOWS}
      vm := LocalTimeToUTCTime(now);
     {$else}
      vm := now;
     {$endif}

    
    {$ifndef SB_NO_NET_DATETIME_OADATE}
    if (Certificate.ValidFrom > vm) then
     {$else}
    if (DateTimeToOADate(Certificate.ValidFrom) > vm) then
     {$endif}
    begin
      Reason := Reason  + [vrNotYetValid] ;
      Result :=  cvInvalid ;
    end;
    {$ifndef SB_NO_NET_DATETIME_OADATE}
    if (Certificate.ValidTo < vm) then
     {$else}
    if (DateTimeToOADate(Certificate.ValidTo) < vm) then
     {$endif}
    begin
      Reason := Reason  + [vrExpired] ;
      Result :=  cvInvalid ;
    end;
    
    if Certificate.SelfSigned then
    begin
      if  Result  <> cvInvalid then
         Result  :=  cvSelfSigned ;
        Reason := Reason  - [vrUnknownCA] ;
      if Certificate.Validate then
        Exit
      else
      begin
         Result  :=  cvInvalid ;
        Reason := Reason  + [vrInvalidSignature] ;
      end;
    end;

    if FCRL <> nil then
    begin
      if FCRL.IsPresent(Certificate) then
      begin
         Result  :=  cvInvalid ;
        Reason := Reason  + [vrRevoked] ;
      end;
    end;

    FSharedResource.WaitToRead;
    try
      for I := 0 to GetCount - 1 do
      begin
        CACert := TElX509Certificate( GetCertificates (I));

        if CheckCACertDates then
        begin
          {$ifndef SB_NO_NET_DATETIME_OADATE}
          if (CACert.ValidFrom > vm) then
           {$else}
          if (DateTimeToOADate(CACert.ValidFrom) > vm) then
           {$endif}
          begin
            Reason := Reason  + [vrNotYetValid] ;
             Result  :=  cvInvalid ;
          end;
          {$ifndef SB_NO_NET_DATETIME_OADATE}
          if (CACert.ValidTo < vm) then
           {$else}
          if (DateTimeToOADate(CACert.ValidTo) < vm) then
           {$endif}
          begin
            Reason := Reason  + [vrExpired] ;
             Result  :=  cvInvalid ;
          end;
        end;

        if IsIssuerCertificate(Certificate, CACert) then
        begin
          if (Certificate.ValidateWithCA(CACert)) then
          begin
            Reason := Reason  - [vrInvalidSignature] ;
            Reason := Reason  - [vrUnknownCA] ;
            Exit;
          end
          else
          begin
            Reason := Reason  + [vrInvalidSignature] ;
            Reason := Reason  - [vrUnknownCA] ;
             Result  :=  cvInvalid ;
          end;
        end
        else
          if (Certificate.CertificateSize = CACert.CertificateSize) and
          (CompareMem(Certificate.CertificateBinary, CACert.CertificateBinary
           , CACert.CertificateSize )) then
        begin
          Reason := Reason  - [vrInvalidSignature] ;
          Reason := Reason  - [vrUnknownCA] ;
          Exit;
        end;
      end;
    finally
      FSharedResource.Done;
    end;

    if  vrUnknownCA in Reason  then
       Result  :=  cvInvalid ;
  except
     Result  :=  cvStorageError ;
  end;
end;

function TElCustomCertStorage.GetCount: integer;
begin
  Result := 0;
end;

function TElCustomCertStorage. GetCertificates (Index: integer):
TElX509Certificate;
begin
  Result := nil;
end;


procedure TElCustomCertStorage.ExportTo(Storage: TElCustomCertStorage);
var
  I, Cnt: integer;
begin
  CheckLicenseKey();
  Cnt := GetCount;
  for I := 0 to Cnt - 1 do
    Storage.Add(Certificates[I]{$ifndef HAS_DEF_PARAMS}, true {$endif});
end;

function TElCustomCertStorage.IndexOf(Certificate: TElX509Certificate): Integer;
begin
  for Result := 0 to Count - 1 do
  begin
    with Certificates[Result] do
    begin
      if  (CertificateSize = Certificate.CertificateSize)
      and  
      (CompareMem(CertificateBinary,
        Certificate.CertificateBinary ,
        CertificateSize )) then
      begin
        exit;
      end;
    end;
  end;
  Result := -1;
end;

function TElCustomCertStorage.IsPresent(Certificate: TElX509Certificate):
  boolean;
begin
  Result := IndexOf(Certificate) >= 0;
end;

function TElCustomCertStorage.LoadFromStreamPKCS7(Stream: TElStream; Count: integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}): integer;
var
  Buf: ByteArray;
begin
  if Count = 0 then
    Count := Stream.Size - Stream.Position
  else
    Count := Min(Count, integer(Stream.Size - Stream.Position));
  SetLength(Buf, Count);
  if Count > 0 then
  begin
    Stream.Read(Buf[0], Count);
    Result := LoadFromBufferPKCS7(@Buf[0], Length(Buf));
  end
  else
    Result := SB_PKCS7_ERROR_INVALID_ASN_DATA;
end;

function TElCustomCertStorage.SaveToStreamPKCS7(Stream: TElStream) : boolean;
var
  Buf: ByteArray;
  Sz: TSBInteger;
begin
  Sz := 0;
  SaveToBufferPKCS7(nil, Sz);
  SetLength(Buf, Sz);
  Result := SaveToBufferPKCS7(@Buf[0], Sz);
  if Result then
    Stream.Write(Buf[0], Sz);
end;

function TElCustomCertStorage.LoadFromStreamPFX(Stream: TElStream; const
  Password: string; Count: integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}): integer;
var
  Buf: ByteArray;
begin
  if Count = 0 then
    Count := Stream.Size - Stream.Position
  else
    Count := Min(Count, integer(Stream.Size - Stream.Position));
  SetLength(Buf, Count);
  if Count > 0 then
  begin
    Stream.Read(Buf[0], Count);
    Result := LoadFromBufferPFX(@Buf[0], Length(Buf), Password);
  end
  else
    Result := SB_PKCS12_ERROR_INVALID_ASN_DATA
end;

function TElCustomCertStorage.SaveToStreamPFX(Stream: TElStream; const
  Password: string;
  KeyEncryptionAlgorithm: integer; CertEncryptionAlgorithm: integer): integer;
var
  Buf: ByteArray;
  Sz: TSBInteger;
begin
  Sz := 0;
  SaveToBufferPFX(nil, Sz, Password, KeyEncryptionAlgorithm,
    CertEncryptionAlgorithm);
  SetLength(Buf, Sz);
  Result := SaveToBufferPFX(@Buf[0], Sz, Password, KeyEncryptionAlgorithm,
    CertEncryptionAlgorithm);
  if Result = 0 then
    Stream.Write(Buf[0], Sz);
end;

function TElCustomCertStorage.SaveToStreamPFX(Stream: TElStream; const Password: string): integer;
begin
  Result := SaveToStreamPFX(Stream, Password, SB_ALGORITHM_PBE_SHA1_3DES,
    SB_ALGORITHM_PBE_SHA1_RC2_40); 
end;

function TElCustomCertStorage.LoadFromBufferPFX(Buffer: pointer; Size:
  integer; const Password: string): integer;
var
  Msg: TElPKCS12Message;
  I: integer;
begin
  CheckLicenseKey();
  Msg := TElPKCS12Message.Create;
  if FCryptoProviderManager <> nil then
    Msg.CryptoProviderManager := FCryptoProviderManager;
  Msg.Password := Password;
  Result := Msg.LoadFromBuffer(Buffer , Size );
  if Result = 0 then
  begin
    for I := 0 to Msg.Certificates.Count - 1 do
      Add(Msg.Certificates.Certificates[I]{$ifndef HAS_DEF_PARAMS}, true {$endif});
  end;
  FreeAndNil(Msg);
end;

function TElCustomCertStorage.SaveToBufferPFX(Buffer: pointer; var Size:
  integer; const Password: string; KeyEncryptionAlgorithm: integer;
  CertEncryptionAlgorithm: integer): integer;
var
  Msg: TElPKCS12Message;
  I: integer;
begin
  CheckLicenseKey();
  Msg := TElPKCS12Message.Create;
  Msg.Password := Password;
  Msg.KeyEncryptionAlgorithm := KeyEncryptionAlgorithm;
  Msg.CertEncryptionAlgorithm := CertEncryptionAlgorithm;
  Msg.Iterations := 2048;
  for I := 0 to Count - 1 do
    Msg.Certificates.Add(Certificates[I]{$ifndef HAS_DEF_PARAMS}, true {$endif});
  Result := Msg.SaveToBuffer(Buffer, Size);
  FreeAndNil(Msg);
end;

function TElCustomCertStorage.SaveToBufferPFX(Buffer: pointer; var Size: integer;
  const Password: string): integer;
begin
  Result := SaveToBufferPFX(Buffer, Size, Password, SB_ALGORITHM_PBE_SHA1_3DES,
    SB_ALGORITHM_PBE_SHA1_RC2_40);
end;

function TElCustomCertStorage.LoadFromBufferPEM(Buffer: pointer; Size: longint; const Password : string) : integer;
var
  Buf :  PByteArray ;
  TS : string;

  function Next5Dashes(Start : integer) : integer;
  var
    cur : integer;
  begin
    Result := -1;

    for cur := Start to Size - 6 do
      if (Buf[cur] = $2D) and (Buf[cur + 1] = $2D) and (Buf[cur + 2] = $2D) and
        (Buf[cur + 3] = $2D) and (Buf[cur + 4] = $2D)
      then
      begin
        Result := cur;
        Exit;
      end;
  end;

  procedure FindNextMessage(var Start, MessageLen : integer; var Header : string);
  var
    bg1, bg2, en1, en2 : integer;
    Msg : ByteArray;
    BgHeader, EnHeader : string;
  begin
    MessageLen := 0;

    bg1 := Next5Dashes(Start);
    if bg1 < 0 then
      Exit;

    bg2 := Next5Dashes(bg1 + 1);
    if bg2 < 0 then
      Exit;

    en1 := Next5Dashes(bg2 + 1);
    if en1 < 0 then
      Exit;

    en2 := Next5Dashes(en1 + 1);
    if en2 < 0 then
      Exit;

    SetLength(Msg, bg2 - bg1 - 5);
    SBMove(Buf[bg1 + 5], Msg[0], Length(Msg));
    BgHeader := StringOfBytes(Msg);
    SetLength(Msg, en2 - en1 - 5);
    SBMove(Buf[en1 + 5], Msg[0], Length(Msg));
    EnHeader := StringOfBytes(Msg);

    if (Length(BgHeader) < 7) or (Length(EnHeader) < 5)
      or (CompareStr(StringSubstring(BgHeader, StringStartOffset, 6), 'BEGIN ') <> 0) or (CompareStr(StringSubstring(EnHeader, StringStartOffset, 4), 'END ') <> 0)
      or (CompareStr(StringSubstring(BgHeader, StringStartOffset + 6, Length(BgHeader) - 6), StringSubstring(EnHeader, StringStartOffset + 4, Length(BgHeader) - 4)) <> 0)
    then
      Exit;

    Header := StringSubstring(BgHeader, StringStartOffset + 6, Length(BgHeader) - 6);
    Start := bg1;
    MessageLen := en2 - bg1 + 5;
  end;

var
  MsgSt, MsgLen, LoadRes, Sz : integer;
  MsgHeader : string;
  CertBuf : ByteArray;
  NewCert : TElX509Certificate;
begin
  Buf := PByteArray(Buffer);

  MsgLen := 0;
  MsgSt := 0;

  while true do
  begin
    if MsgLen = 0 then
    begin
      FindNextMessage(MsgSt, MsgLen, MsgHeader);

      if MsgLen = 0 then
        Break; // no more messages
    end;

    if (CompareStr(MsgHeader, 'CERTIFICATE') = 0) or (CompareStr(MsgHeader, 'X509 CERTIFICATE') = 0) then
    begin
      SetLength(CertBuf, MsgLen);
      SBMove(Buf[MsgSt], CertBuf[0], MsgLen);

      Inc(MsgSt, MsgLen);

      // checking if there is the private key
      FindNextMessage(MsgSt, MsgLen, MsgHeader);

      // TODO: Check in .NET and Delphi Mobile
      TS := StringSubstring(MsgHeader, Length(MsgHeader) - 10 - StringStartInvOffset, 11);
      if (MsgLen > 0) and (Length(MsgHeader) >= 11) and (CompareStr(TS, 'PRIVATE KEY') = 0) then
      begin
        Sz := Length(CertBuf);
        SetLength(CertBuf, Sz + MsgLen + 2);
        CertBuf[Sz] := 13;
        CertBuf[Sz + 1] := 10;
        SBMove(Buf[MsgSt], CertBuf[Sz + 2], MsgLen);
        Inc(MsgSt, MsgLen);
        MsgLen := 0;
      end;
      ReleaseString(TS);

      NewCert := TElX509Certificate.Create(nil);
      LoadRes := NewCert.LoadFromBufferPEM(@CertBuf[0], Length(CertBuf), Password);
      if LoadRes = 0 then
        Add(NewCert, true);
      FreeAndNil(NewCert);
      ReleaseArray(CertBuf);
    end
    else
    begin
      Inc(MsgSt, MsgLen);
      MsgLen := 0; // skipping non-certificate message
    end;
  end;
  Result := 0; 
end;

function TElCustomCertStorage.SaveToBufferPEM(Buffer: pointer; var Size: longint; const Password : string) : boolean;
begin
  Result := SaveToBufferPEM(Buffer, Size, Password, SB_ALGORITHM_CNT_3DES,  cmCBC );
end;

function TElCustomCertStorage.SaveToBufferPEM(Buffer: pointer; var Size: longint; const Password : string;
  EncryptionAlgorithm : integer; EncryptionMode :  TSBSymmetricCryptoMode ) : boolean;
var
  EstSize, CertSize, i : integer;
  TmpBuf : ByteArray;
begin
  TmpBuf := EmptyArray;


  if (Size = 0) or (Buffer = nil) then
  begin
    EstSize := 0;
    for i := 0 to Self.Count - 1 do
    begin
      CertSize := 0;
      Self.Certificates[i].SaveToBufferPEM( nil , CertSize, Password);
      Inc(EstSize, CertSize);
      if Self.Certificates[i].PrivateKeyExists and Self.Certificates[i].PrivateKeyExtractable then
      begin
        CertSize := 0;
        Self.Certificates[i].SaveKeyToBufferPEM( nil , CertSize, EncryptionAlgorithm, EncryptionMode, Password);
        Inc(EstSize, CertSize);
      end;
    end;

    Size := EstSize;
    Result := false;
    Exit;
  end;

  EstSize := 0;
  for i := 0 to Self.Count - 1 do
  begin
    CertSize := 0;
    Self.Certificates[i].SaveToBufferPEM( nil , CertSize, Password);
    SetLength(TmpBuf, EstSize + CertSize);
    if Self.Certificates[i].SaveToBufferPEM(@TmpBuf[EstSize], CertSize, Password) then
      Inc(EstSize, CertSize);

    if Self.Certificates[i].PrivateKeyExists and Self.Certificates[i].PrivateKeyExtractable then
    begin
      CertSize := 0;
      Self.Certificates[i].SaveKeyToBufferPEM( nil , CertSize, EncryptionAlgorithm, EncryptionMode, Password);
      SetLength(TmpBuf, EstSize + CertSize);
      if Self.Certificates[i].SaveKeyToBufferPEM(@TmpBuf[EstSize], CertSize, EncryptionAlgorithm, EncryptionMode, Password) then
        Inc(EstSize, CertSize);
    end;
  end;

  if Size < EstSize then
  begin
    Size := EstSize;
    Result := false;
  end
  else
  begin
    SBMove( TmpBuf[0], Buffer^ , EstSize);
    Size := EstSize;
    Result := true;
  end;

end;

function TElCustomCertStorage.LoadFromStreamPEM(Stream : TElStream; const Password : string;
  Count : integer{$ifdef HAS_DEF_PARAMS} =  0 {$endif}): integer;
var
  TmpBuf : ByteArray;
begin
  if Count = 0 then
    Count := Stream. Size  - Stream.Position;

  SetLength(TmpBuf, Count);
  Stream.Read( TmpBuf[0] , Count);

  Result := LoadFromBufferPEM( @TmpBuf[0], Count , Password);
end;

function TElCustomCertStorage.SaveToStreamPEM(Stream : TElStream; const Password : string): boolean;
begin
  Result := SaveToStreamPEM(Stream, Password, SB_ALGORITHM_CNT_3DES,  cmCBC );
end;

function TElCustomCertStorage.SaveToStreamPEM(Stream : TElStream; const Password : string;
  EncryptionAlgorithm : integer; EncryptionMode : TSBSymmetricCryptoMode): boolean;
var
  Buf: ByteArray;
  Sz: TSBInteger;
begin
  Sz := 0;
  SaveToBufferPEM(nil, Sz, Password, EncryptionAlgorithm, EncryptionMode);
  SetLength(Buf, Sz);
  Result := SaveToBufferPEM(@Buf[0], Sz, Password, EncryptionAlgorithm, EncryptionMode);
  if Result then
    Stream.Write(Buf[0], Sz);
end;                

function TElCustomCertStorage.LoadFromBufferPkiPath(Buffer: pointer; Size: integer): boolean;
var
  Tag : TElASN1ConstrainedTag;
  STag : TElASN1ConstrainedTag;
  Cert : TElX509Certificate;
  Buf : ByteArray;
  Sz : TSBInteger;
  i : integer;
begin
  //Result := false;
  
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    Result := Tag.LoadFromBuffer(Buffer , Size );
    if not Result then
      Exit;
      
    if Tag.Count <> 1 then
      Exit;
      
    Tag := TElASN1ConstrainedTag(Tag.GetField(0));
    
    if not Tag.CheckType(SB_ASN1_SEQUENCE, true) then
      Exit;
    
    for i := 0 to Tag.Count - 1 do
    begin
      STag := TElASN1ConstrainedTag(Tag.GetField(i));
      
      Sz := 0;
      SetLength(Buf, 0);
      STag.SaveToBuffer(Buf, Sz);
      SetLength(Buf, Sz);
      Result := STag.SaveToBuffer( @Buf[0] , Sz);
      SetLength(Buf, Sz);
      if not Result then
        Exit; 
      
      Cert := TElX509Certificate.Create(nil);
      try
        Cert.LoadFromBuffer( @Buf[0], Length(Buf) );
        Add(Cert{$ifndef HAS_DEF_PARAMS}, true {$endif});
      finally
        FreeAndNil(Cert);
      end;
    end;    
    
    Result := true;
  finally
    FreeAndNil(Tag);
    ReleaseArray(Buf);
  end;
end;

function TElCustomCertStorage.SaveToBufferPkiPath(Buffer: pointer; var Size: integer): boolean;
var
  Tag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  Cert : TElX509Certificate;
  Buf : ByteArray;
  //Sz : TSBInteger;
  i : integer;
begin
  //Result := false;

  Tag := TElASN1ConstrainedTag.CreateInstance;
  Tag.TagID := SB_ASN1_SEQUENCE;
  try
    for i := 0 to Count - 1 do
    begin
      Cert := Certificates[i];

      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      STag.WriteHeader := false;
      SetLength(Buf, Cert.CertificateSize);
      SBMove(Cert.CertificateBinary^, Buf[0], Length(Buf));
      STag.Content :=  Buf ;
    end;

    Result := Tag.SaveToBuffer(Buffer, Size);
  finally
    FreeAndNil(Tag);
  end;
end;

function TElCustomCertStorage.LoadFromStreamPkiPath(Stream: TElStream; Count: integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}): boolean;
var
  Buf: ByteArray;
begin
  Result := false;
  if Count = 0 then
    Count := Stream.Size - Stream.Position
  else
    Count := Min(Count, integer(Stream.Size - Stream.Position));
  SetLength(Buf, Count);
  if Count > 0 then
  begin
    Stream.Read(Buf[0], Count);
    Result := LoadFromBufferPkiPath(@Buf[0], Length(Buf));
  end;
end;

function TElCustomCertStorage.SaveToStreamPkiPath(Stream: TElStream): boolean;
var
  Buf: ByteArray;
  Sz: TSBInteger;
begin
  Sz := 0;
  SaveToBufferPkiPath(nil, Sz);
  SetLength(Buf, Sz);
  Result := SaveToBufferPkiPath(@Buf[0], Sz);
  if Result then
    Stream.Write(Buf[0], Sz);
end;

{$ifndef FPC}
procedure TElCustomCertStorage.DefineProperties(Filer: TFiler);
begin
  inherited;
  Filer.DefineBinaryProperty('BinaryCertificates', ReadCertificatesProp,
    WriteCertificatesProp, IsCertificatesPropStored);
  Filer.DefineProperty('Certificates', ReadFakeCertificatesProp,
    nil, false);
end;

procedure TElCustomCertStorage.ReadCertificatesProp(Reader: TStream);
var
  BufSize: integer;
  Buf: pointer;
begin
  Reader.Read(BufSize, sizeof(BufSize));
  if BufSize > 0 then
  begin
    GetMem(Buf, BufSize);
    Reader.Read(PByte(Buf)^, BufSize);
    LoadFromBufferPFX(Buf, BufSize, 'Certificates');
    FreeMem(Buf);
  end
  else
    Clear;
end;

procedure TElCustomCertStorage.WriteCertificatesProp(Writer: TStream);
var
  Buf: Pointer;
  BufSize: integer;
begin
  BufSize := 0;
  SaveToBufferPFX(nil, BufSize, 'Certificates', SB_ALGORITHM_PBE_SHA1_RC4_128,
    SB_ALGORITHM_PBE_SHA1_RC4_128);
  if (BufSize > 0) then
  begin
    GetMem(Buf, BufSize);
    SaveToBufferPFX(Buf, BufSize, 'Certificates', SB_ALGORITHM_PBE_SHA1_RC4_128,
      SB_ALGORITHM_PBE_SHA1_RC4_128);
    Writer.Write(BufSize, SizeOf(BufSize));
    Writer.Write(PByte(Buf)^, BufSize);
    FreeMem(Buf);
  end
  else
  begin
    Writer.Write(BufSize, SizeOf(BufSize));
  end;
end;

function TElCustomCertStorage.IsCertificatesPropStored: boolean;
begin
  result := Count > 0;
end;
 {$endif}

procedure TElCustomCertStorage.Clear;
begin
  while Count > 0 do
    Remove(Count - 1);
  FRebuildChains := true;
end;

function TElCustomCertStorage.FindByHash(const Digest: TMessageDigest160): integer;
var
  M160: TMessageDigest160;
  I: integer;
  Cert: TElX509Certificate;
begin
  Result := -1;
  for I := 0 to GetCount - 1 do
  begin
    Cert :=  GetCertificates (I);
    Assert(Assigned(Cert));
    M160 := HashSHA1(Cert.CertificateBinary,  Cert.CertificateSize );
    if CompareMem(@M160, @Digest, 20) then
    begin
      Result := I;
      Break;
    end;
  end;
end;

function TElCustomCertStorage.FindByHash(const Digest: TMessageDigest128): integer;
var
  M128: TMessageDigest128;
  I: integer;
  Cert: TElX509Certificate;
begin
  Result := -1;
  for I := 0 to GetCount - 1 do
  begin
    Cert :=  GetCertificates (I);
    Assert(Assigned(Cert));
    M128 := HashMD5(Cert.CertificateBinary,  
      Cert.CertificateSize );
    if CompareMem(@M128, @Digest, 16) then
    begin
      Result := I;
      Break;
    end;
  end;
end;

function TElCustomCertStorage.IsIssuerCertificate(Subject, Issuer:
  TElX509Certificate): boolean;
var
  IssuerRDN, SubjectRDN: TElRelativeDistinguishedName;
  I: integer;
  Lst: TElByteArrayList;
begin
  Result := false;
  IssuerRDN := Subject.IssuerRDN;
  SubjectRDN := Issuer.SubjectRDN;
  if IssuerRDN.Count <> SubjectRDN.Count then
    Exit;
  Lst := TElByteArrayList.Create;
  try
    Result := true;
    for I := 0 to IssuerRDN.Count - 1 do
    begin
      SubjectRDN.GetValuesByOID(IssuerRDN.OIDs[I], Lst);
      if Lst.IndexOf(IssuerRDN.Values[I]) = -1 then
      begin
        Result := false;
        Break;
      end;
    end;
  finally
    FreeAndNil(Lst);
  end;
  if not Result then
    Exit;

  if not (csoStrictChainBuilding in Options) then
    Exit;

  if (ceSubjectKeyIdentifier in Issuer.Extensions.Included) then
  begin
    if (ceAuthorityKeyIdentifier in Subject.Extensions.Included) then
      Result := CompareContent(
        Issuer.Extensions.SubjectKeyIdentifier.KeyIdentifier,
        Subject.Extensions.AuthorityKeyIdentifier.KeyIdentifier
        );
  end;
end;

function TElCustomCertStorage.GetIssuerCertificate(Certificate:
  TElX509Certificate): integer;
var
  I: integer;
  Cand: TElX509Certificate;
  Dgst1, Dgst2: TMessageDigest128;
  s : string;
begin
  Result := -1;
  for I := 0 to GetCount - 1 do
  begin
    Cand := Certificates[I];
    s := Cand.SubjectName.CommonName;
    if (IsIssuerCertificate(Certificate, Cand)) then
    begin
      Dgst1 := Certificate.GetHashMD5;
      Dgst2 := Cand.GetHashMD5;
      if not CompareMem(@Dgst1, @Dgst2, 16) then
      begin
        Result := I;
        Break;
      end;
    end;
  end;
end;

// TODO: verify loading of BASE64-encoded data in Delphi Mobile
function TElCustomCertStorage.LoadFromBufferPKCS7(Buffer: pointer; Size: longint) : integer;
var
  Mes: TElPKCS7Message;
  I: integer;
  TmpBuf : ByteArray;
  TmpBufSize : integer;
  S : ByteArray;

begin

  TmpBufSize :=  Size ;
  SetLength(TmpBuf, TmpBufSize);

  if IsBase64UnicodeSequence(Buffer  , Size ) then
  begin
    Base64UnicodeDecode(Buffer  , Size , TmpBuf, TmpBufSize);
  end
  else
  if IsBase64Sequence(Buffer  , Size ) then
  begin
    Base64Decode(Buffer  , Size , TmpBuf, TmpBufSize);
  end
  else
  if IsPEMSequence( Buffer, Size ) then
  begin
    SBMove(Buffer^, TmpBuf[0], TmpBufSize);
    S := SBCopy(TmpBuf, ConstLength(PEM_BEGIN_CERTIFICATE_LINE) + 0, TmpBufSize - ConstLength(PEM_BEGIN_CERTIFICATE_LINE) - ConstLength(PEM_END_CERTIFICATE_LINE) + 0);
    Base64Decode( @S[0], Length(S) , TmpBuf, TmpBufSize);
  end
  else
  begin
    SBMove(Buffer^, TmpBuf[0], TmpBufSize);
  end;

  try
    Mes := TElPKCS7Message.Create;
    try
      result := Mes.LoadFromBuffer( @TmpBuf[0], TmpBufSize );
      if result <> 0 then
        exit;

      if Mes.ContentType <>  ctSignedData  then
        raise EElCertStorageError.Create(SNoSignedData);

      // not using ExportTo here as it leads to deadlock if fcsoSaveOnChange is set
      FSharedResource.WaitToWrite;
      try
        for I := 0 to Mes.SignedData.Certificates.Count - 1 do
          Add(Mes.SignedData.Certificates.Certificates[I]{$ifndef HAS_DEF_PARAMS}, true {$endif});
      finally
        FSharedResource.Done;
      end;
    finally
      FreeAndNil(Mes);
    end;
  finally
  end;
end;

function TElCustomCertStorage.SaveToBufferPKCS7(Buffer: pointer; var Size: longint) : boolean;
var
  Mes: TElPKCS7Message;
begin
  CheckLicenseKey();
  FSharedResource.WaitToRead;
  Mes := TElPKCS7Message.Create;
  Mes.ContentType :=  ctSignedData ;
  try
    Mes.SignedData.Version := 1;
    ExportTo(Mes.SignedData.Certificates);
    Result := Mes.SaveToBuffer(Buffer, Size);
  finally
    FSharedResource.Done;
    FreeAndNil(Mes);
  end;
end;


{$ifndef SB_NO_JKS}

function TElCustomCertStorage.AliasNeededInt(Cert : TElX509Certificate;  var Alias: string ): boolean;
begin
  SetLength(Alias, 64);
  Result := true;
end;

function TElCustomCertStorage.LoadFromStreamJKS(Stream: TElStream; const Pass: string; Count: integer {$ifdef HAS_DEF_PARAMS} =  0 {$endif}; OnPasswordNeeded : TElJKSPasswordEvent {$ifdef HAS_DEF_PARAMS} =  nil {$endif}): boolean;
var
  Buf: ByteArray;
begin
  if Count = 0 then
    Count := Stream.Size - Stream.Position
  else
    Count := Min(Count, integer(Stream.Size - Stream.Position));
  SetLength(Buf, Count);
  if Count > 0 then
  begin
    Stream.Read(Buf[0], Count);
    Result := LoadFromBufferJKS(@Buf[0], Pass, Length(Buf), OnPasswordNeeded);
  end
  else
    Result := False;
end;

function TElCustomCertStorage.SaveToStreamJKS(Stream: TElStream; const Pass: string) : boolean;
begin
  Result := SaveToStreamJKSEx(Stream, Pass, nil);
end;

function TElCustomCertStorage.SaveToStreamJKSEx(Stream: TElStream; const Pass: string; OnAliasNeeded : TElJKSAliasNeededEvent) : boolean;
var
  Buf: ByteArray;
  Sz: TSBInteger;
begin
  Sz := 0;
  SaveToBufferJKSEx(nil, Pass, Sz, AliasNeededInt);
  SetLength(Buf, Sz);
  Result := SaveToBufferJKSEx(@Buf[0], Pass, Sz, OnAliasNeeded);
  if Result then
    Stream.Write(Buf[0], Sz);
end;

function TElCustomCertStorage.LoadFromBufferJKS(Buffer: pointer; const Pass: string; Size: longint; OnPasswordNeeded: TElJKSPasswordEvent = nil) : boolean;
var
  JKS : TElJKS;
  I, K, Buf_Pos : integer;
  Cert : TElX509Certificate;
  Key : ByteArray;
  KeyPass, Alias : TSBString;
  Succ : boolean;
begin
  CheckLicenseKey();
  Result := true;
  JKS := TElJks.Create;
  try
    Buf_Pos := 0;
    if Jks.LoadFromBuffer(Buffer, Size, Buf_Pos, Pass) = 0 then
    begin
      for I := 0 to Jks.Entries_Count - 1 do
      begin
        if not Jks.IsPrivateKey[I] then
          Add(Jks.GetTrustedCertificate(I))
        else
        begin
          if Jks.PrivateKeyCert_Count[I] > 0 then
          begin
            // trying to load the key into the corresponding certificate
            Cert := Jks.GetKeyCertificate(I, 0);
            Alias := Jks.GetAlias(I);
            Succ := true;
            KeyPass := Pass; // trying storage password first
            while not Jks.GetPrivateKey(I, KeyPass, Key) do    
            begin
              KeyPass := '';
              if (not Assigned(OnPasswordNeeded)) or (not OnPasswordNeeded(Alias, KeyPass)) then
              begin
                Succ := false;
                Break;
              end;
            end;
            if Succ then
            begin
              try
                Cert.LoadKeyFromBuffer(@Key[0], Length(Key));
              except
                Result := false;
              end;
            end
            else
              Result := false;
            Add(Cert);
            // adding subsequent certificates (if any)
            for K := 1 to Jks.PrivateKeyCert_Count[I] - 1 do
              Add(Jks.GetKeyCertificate(I, K));
          end;
        end;
      end;
    end
    else
      Result := false;
  finally
    FreeAndNil(Jks);
  end;
end;

function TElCustomCertStorage.SaveToBufferJKSEx(Buffer: pointer; const Pass: string; var Size: longint; OnAliasNeeded : TElJKSAliasNeededEvent) : boolean;
var
  Index, Index_C: integer;
  KeySize : integer;
  TmpBuf : ByteArray;
  JKS : TElJks;
  Key : ByteArray;
  CurrAliasIndex : integer;

  function GetSubsequentAlias(Cert : TElX509Certificate): string;
  var
    B : boolean;
  begin
    Result := '';
    B := false;
    if Assigned(OnAliasNeeded) then
    begin
      B := OnAliasNeeded(Cert, Result);
    end;

    if not B then
      Result := 'alias' + IntToStr(CurrAliasIndex);

    Inc(CurrAliasIndex);
  end;

begin
  CheckLicenseKey();
  CurrAliasIndex := 1;
  Jks := TElJKS.Create;
  try
    for Index := 0 to Count - 1 do
    begin
      if not Certificates[Index].PrivateKeyExists then
      begin
        Index_C := Jks.AddTrustedCertificate(Certificates[Index]);
        Jks.SetAlias(Index_C - 1, GetSubsequentAlias(Certificates[Index]));
      end
      else
      begin
        SetLength(Key, 0);
        KeySize := 0;
        Certificates[Index].SaveKeyToBuffer(nil, KeySize);
        SetLength(Key, KeySize);
        Certificates[Index].SaveKeyToBuffer(@Key[0], KeySize);
        Index_C := Jks.AddPrivateKey(Pass, Key);
        Jks.AddKeyCertificate(Index_C - 1, Certificates[Index]);
        Jks.SetAlias(Index_C - 1, GetSubsequentAlias(Certificates[Index]));
      end;
    end;
    if ( Buffer = nil ) or (Size < Jks.GetSaveBufferSize) then
    begin
      Size := Jks.GetSaveBufferSize;
      Result := false;
      exit;
    end;
    Index := 0;
    SetLength(TmpBuf, Size);
    Result := Jks.SaveToBuffer(TmpBuf, Size, Index, Pass) = 0;
    SBMove(TmpBuf[0], Buffer^, Size);
  finally
    FreeAndNil(JKS);
  end;
end;

function TElCustomCertStorage.SaveToBufferJKS(Buffer: pointer; const Pass: string; var Size: longint) : boolean;
begin
  Result := SaveToBufferJKSEx(Buffer, Pass, Size, nil);
end; 
 {$endif}


{$ifndef SB_NO_FILESTREAM}

////////////////////////////////////////////////////////////////////////////////
// TElFileCertStorage
////////////////////////////////////////////////////////////////////////////////

constructor TElFileCertStorage.Create(Owner: TComponent);
begin
  inherited Create(Owner);
  FCertificateList := TSBObjectList.Create;
  FLoaded := false;
  FAccessType :=  csatOnDemand ;
  FSaveOptions :=   [] ;
end;


 destructor  TElFileCertStorage.Destroy;
var
  C : TElX509Certificate;
begin
  if  fcsoSaveOnDestroy in
    FSaveOptions  then
    Save;
  FSharedResource.WaitToWrite;
  try
    while FCertificateList.Count > 0 do
    begin
      C := TElX509Certificate(FCertificateList.Extract((FCertificateList[0])));
      FreeAndNil(C);
    end;
    FreeAndNil(FCertificateList);
  finally
    FSharedResource.Done;
  end;
  inherited;
end;

procedure TElFileCertStorage.Add(X509Certificate: TElX509Certificate;
  CopyPrivateKey: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif});
var
  NewX509: TElX509Certificate;
begin
  if not Assigned(X509Certificate) then
    Exit;

  CheckLicenseKey();
  FRebuildChains := true;
  NewX509 := TElX509Certificate.Create(nil);
  X509Certificate.Clone(NewX509{$ifndef HAS_DEF_PARAMS}, true {$endif});
  if FCryptoProviderManager <> nil then
    X509Certificate.CryptoProviderManager := FCryptoProviderManager;
  FSharedResource.WaitToWrite;
  try
    FCertificateList.Add(NewX509);
  finally
    FSharedResource.Done;
  end;
  if  (fcsoSaveOnChange in
    FSaveOptions)  then
    Save;
end;

function TElFileCertStorage.GetCount: integer;
begin
  if not FLoaded then
    LoadFromFile;
  Result := FCertificateList.Count;
end;

function TElFileCertStorage. GetCertificates (Index: integer): TElX509Certificate;
begin
  if not FLoaded then
    LoadFromFile;
  FSharedResource.WaitToRead;
  try
    if Index < FCertificateList.Count then
      Result := TElX509Certificate(FCertificateList[Index])
    else
      Result := nil;
  finally
    FSharedResource.Done;
  end;
end;


procedure TElFileCertStorage.Remove(Index: integer);
var
  Cert: TElX509Certificate;
begin
  if not FLoaded then
    LoadFromFile;
  FSharedResource.WaitToRead;
  if (Index < FCertificateList.Count) and (Index >= 0) then
  begin
    FSharedResource.Done;
    FSharedResource.WaitToWrite;
    try
      Cert := TElX509Certificate(FCertificateList[Index]);
      FCertificateList.Delete(Index);
      if not FCertificateList.OwnsObjects then
        FreeAndNil(Cert);
      FRebuildChains := true;
    finally
      FSharedResource.Done;
    end;
    if  fcsoSaveOnChange in
      FSaveOptions  then
      Save;
  end
  else
    FSharedResource.Done;
end;

procedure TElFileCertStorage.LoadFromFile;
var
  Size: longint;
  Buffer: ^Byte;
  InFile: TStream;
begin
  if FFileName = '' then
    Exit;
  if not FLoaded then
  begin
    InFile := nil;
    Buffer := nil;
    try
      InFile := TFileStream.Create(FFileName, fmOpenRead or fmShareDenyWrite);
      Size := InFile.Size;
      GetMem(Buffer, Size);
      InFile.Read(PByte(Buffer)^, Size);
      LoadFromBufferPKCS7((Buffer)  , Size );
    finally
      if Assigned(InFile) then
        FreeAndNil(InFile);
        
      if Assigned(Buffer) then
        FreeMem(Buffer);
    end;
  end;
  FLoaded := true;
end;

function TElFileCertStorage.Validate(Certificate: TElX509Certificate;
  var Reason: TSBCertificateValidityReason;
  CheckCACertDates : boolean; ValidityMoment:
   TDateTime = 0 ):
  TSBCertificateValidity;
begin
  CheckLicenseKey();
   Result  :=  cvInvalid ;
  Reason :=   [vrBadData] ;

  if not FLoaded then
    LoadFromFile;
  if not FLoaded then exit;
  result := inherited Validate(Certificate, Reason, CheckCACertDates, ValidityMoment);
end;

procedure TElFileCertStorage.SaveToFile(const FileName: string);
var
  Sz: TSBInteger;
  Buffer: ByteArray;
  F: TStream;
begin
  if Length(Filename) = 0 then
    Exit;
  Sz := 0;
  SetLength(Buffer, Sz);
  SaveToBufferPKCS7(@Buffer[0], Sz);
  SetLength(Buffer, Sz);
  if SaveToBufferPKCS7(@Buffer[0], Sz) then
  begin
    F := nil;
    try
      SetLength(Buffer, Sz);
      F := TFileStream.Create(FileName, fmCreate);
      F.Write(Buffer[0], Length(Buffer));
    finally
      if Assigned(F) then
        FreeAndNil(F);
    end;
  end;
end;

procedure TElFileCertStorage.SetFileName(const FileName: string);
begin
  if CompareStr(FileName, FFilename) <> 0 then
  begin
    if  (fcsoSaveOnFilenameChange in
      FSaveOptions)  and (Length(FFilename) > 0)
    and (not (csDesigning in ComponentState))
  then
      Save;
    InternalClear;
    FFileName := FileName;
    FLoaded := false;
    if not FileExists(Filename) then
      CreateEmptyStorage;
    if (FAccessType =  csatImmediate )
    and (not (csDesigning in ComponentState))
  then
      Reload;
  end;
end;

procedure TElFileCertStorage.Reload;
begin
  CheckLicenseKey();
  if FLoaded then
  begin
    InternalClear;
    FLoaded := false;
  end;
  LoadFromFile;
end;

procedure TElFileCertStorage.Save;
begin
  if csDesigning in ComponentState then
    Exit;
  try
    if not FLoaded then
      LoadFromFile;
  except
    // saving if failed to load file
    FLoaded := true;
  end;
  if FLoaded then
    SaveToFile(FFilename);
end;

procedure TElFileCertStorage.SetAccessType(Value: TSBFileCertStorageAccessType);
begin
  if FAccessType <> Value then
  begin
    FAccessType := Value;
    if (Value =  csatImmediate ) and 
       (not FLoaded)
    and (not (csDesigning in ComponentState))
  then
      LoadFromFile;
  end;
end;

procedure TElFileCertStorage.InternalClear;
var
  Obj : TObject;
begin
  FSharedResource.WaitToWrite;
  try
    while FCertificateList.Count > 0 do
    begin
      Obj := FCertificateList.Extract((FCertificateList[0]));
      if not FCertificateList.OwnsObjects then
        FreeAndNil(Obj);
    end;
  finally
    FSharedResource.Done;
  end;
end;

procedure TElFileCertStorage.Clear;
begin
  InternalClear;
  if  (fcsoSaveOnChange in
    FSaveOptions)  then
    Save;
end;

procedure TElFileCertStorage.CreateEmptyStorage;
begin
  InternalClear;
  try
    FLoaded := true;
    SaveToFile(FFilename);
  except
    raise EElCertStorageError.Create(SUnableToMountStorage);
  end;
end;

 {$endif}

////////////////////////////////////////////////////////////////////////////////
// TElMemoryCertStorage
////////////////////////////////////////////////////////////////////////////////

constructor TElMemoryCertStorage.Create(Owner: TComponent);
begin
  inherited;
  FCertificateList := TSBObjectList.Create;
  FCertificateList.OwnsObjects := false;
end;


 destructor  TElMemoryCertStorage.Destroy;
var
  P: TObject;
begin
  while FCertificateList.Count > 0 do
  begin
    P := {TElX509Certificate}(FCertificateList[0]);
    FCertificateList.Extract((FCertificateList[0]));
    FreeAndNil(P);
  end;
  FreeAndNil(FCertificateList);
  inherited;
end;

procedure TElMemoryCertStorage.Add(X509Certificate: TElX509Certificate;
  CopyPrivateKey: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif});
var
  NewX509: TElX509Certificate;
begin
  if not Assigned(X509Certificate) then
    Exit;

  CheckLicenseKey();
  FRebuildChains := true;
  FSharedResource.WaitToWrite;
  try
      //inherited;
      NewX509 := TElX509Certificate.Create(nil);
      X509Certificate.Clone(NewX509, CopyPrivateKey);
      if FCryptoProviderManager <> nil then
        X509Certificate.CryptoProviderManager := FCryptoProviderManager;
      FCertificateList.Add(NewX509);
  finally
    FSharedResource.Done;
  end;
end;

procedure TElMemoryCertStorage.Remove(Index: integer);
var
  Cert: TObject;
begin
  CheckLicenseKey();
  FSharedResource.WaitToWrite;
  try
    if Index < FCertificateList.Count then
    begin
      Cert := TElX509Certificate(FCertificateList[Index]);
      FCertificateList.Delete(Index);
      if not FCertificateList.OwnsObjects then
        FreeAndNil(Cert);
    end;
    FRebuildChains := true;
  finally
    FSharedResource.Done;
  end;
end;

function TElMemoryCertStorage. GetCertificates (Index: integer): TElX509Certificate;
begin
  FSharedResource.WaitToRead;
  try
    if (Index < 0) or (Index >= FCertificateList.Count) then
      Result := nil
    else
      Result := TElX509Certificate(FCertificateList[Index]);
  finally
    FSharedResource.Done;
  end;
end;


function TElMemoryCertStorage.GetCount: integer;
begin
  Result := FCertificateList.Count;
end;

procedure TElCustomCertStorage.AssignTo(Dest: TPersistent);
var
  i: integer;
begin
  if Dest is TElCustomCertStorage then
    for i := 0 to Count - 1 do
    begin
      TElCustomCertStorage(Dest).Add(Certificates[i]{$ifndef HAS_DEF_PARAMS}, true {$endif});
    end
  else
    inherited;
end;

class function TElCustomCertStorage.IsReadOnly: Boolean;
begin
  Result := false;
end;

procedure TElCustomCertStorage.BuildAllChains;
var
  I, Index: integer;
  IssuerFlags: array of boolean;
begin
  FSharedResource.WaitToRead;
  SetLength(IssuerFlags, Count);
  for I := 0 to Count - 1 do
    IssuerFlags[I] := false;
  for I := 0 to Count - 1 do
  begin
    Index := GetIssuerCertificate(Certificates[I]);
    if Index >= 0 then
      IssuerFlags[Index] := true;
  end;
  SetLength(FChains, 0);
  for I := 0 to Count - 1 do
    if not IssuerFlags[I] then
    begin
      Index := Length(FChains);
      SetLength(FChains, Index + 1);
      FChains[Index] := I;
    end;
  FRebuildChains := false;
  FSharedResource.Done;
end;

function TElCustomCertStorage.GetChainCount: integer;
begin
  if FRebuildChains then
    BuildAllChains;
  Result := Length(FChains);
end;

function TElCustomCertStorage.GetChain(Index: integer): integer;
begin
  if FRebuildChains then
    BuildAllChains;
  if (Index >= 0) and (Index < Length(FChains)) then
    Result := FChains[Index]
  else
    Result := -1;
end;

{$ifndef FPC}
procedure TElCustomCertStorage.ReadFakeCertificatesProp(Reader: TReader);
var
  BufSize: integer;
  Buf: pointer;
begin
  BufSize := Reader.ReadInteger;
  if BufSize > 0 then
  begin
    GetMem(Buf, BufSize);
    Reader.Read(PByte(Buf)^, BufSize);
    LoadFromBufferPFX(Buf, BufSize, 'Certificates');
    FreeMem(Buf);
  end
  else
    Clear;
end;
 {$endif}

function TElCustomCertStorage.FindFirst(Lookup: TElCertificateLookup): integer;
begin
  Lookup.FLastIndex := -1;
  Result := FindNext(Lookup);
end;

function TElCustomCertStorage.FindNext(Lookup: TElCertificateLookup): integer;
begin
  Result := Lookup.FindNext(Self);
end;

procedure TElCustomCertStorage.Notification(AComponent: TComponent; Operation:
  TOperation);
begin
  inherited;
  if Operation = opRemove then
  begin
    if (AComponent = FCRL) then
      CRL := nil
    else if (AComponent = FCryptoProviderManager) then
      CryptoProviderManager := nil;
  end;
end;

procedure TElCustomCertStorage.SetCRL(Value: TElCertificateRevocationList);
begin
  if FCRL <> Value then
  begin
    {$ifdef VCL50}
    if (FCRL <> nil) and (not (csDestroying in FCRL.ComponentState)) then
      FCRL.RemoveFreeNotification(Self);
   {$endif}
    FCRL := Value;
    if FCRL <> nil then
      FCRL.FreeNotification(Self);
  end;
end;

procedure TElCustomCertStorage.SetCryptoProviderManager(Value: TElCustomCryptoProviderManager);
begin
  if FCryptoProviderManager <> Value then
  begin
    {$ifdef VCL50}
    if (FCryptoProviderManager <> nil) and (not (csDestroying in FCryptoProviderManager.ComponentState)) then
      FCryptoProviderManager.RemoveFreeNotification(Self);
     {$endif}
    FCryptoProviderManager := Value;
    if FCryptoProviderManager <> nil then
      FCryptoProviderManager.FreeNotification(Self);
  end;
end;

function TElCustomCertStorage.BuildChain(Certificate : TElX509Certificate):
    TElX509CertificateChain;
var Cert, PrevCert : TElX509Certificate;
    idx  : integer;
    Lookup : TElCertificateLookup;
    Lst : TElList;
begin
  Result := TElX509CertificateChain.Create(nil);
  Cert := Certificate;
  if Cert <> nil then
  begin
    Lst := TElList.Create();
    try
      PrevCert := Cert;
      AddToChain(Result, Cert);
      Lst.Add(Cert);

      Lookup := TElCertificateLookup.Create(nil);
      try
        Lookup.SubjectRDN.Assign(Cert.IssuerRDN);
        Lookup.Criteria :=  [lcSubject] ;
        Lookup.Options :=  [loExactMatch, loMatchAll] ;

        idx := FindFirst(Lookup);
        while idx <> -1 do
        begin
          Cert := Certificates[idx];

          if Lst.IndexOf(Cert) >= 0 then
            Break;

          if Cert <> PrevCert then
          begin
            AddToChain(Result, Cert);
            Lst.Add(Cert);
          end;

          PrevCert := Cert;
          //idx := FindNext(Lookup);
          Lookup.SubjectRDN.Assign(Cert.IssuerRDN);
          idx := FindFirst(Lookup);
        end;
      finally
        FreeAndNil(Lookup);
      end;
    finally
      FreeAndNil(Lst);
    end;
  end;
end;

function TElCustomCertStorage.BuildChain(ChainIndex: Integer):
    TElX509CertificateChain;
begin
  if ChainIndex > ChainCount -1 then
    result := nil
  else
    Result := BuildChain(Certificates[Chains[ChainIndex]]);
end;


procedure TElCustomCertStorage.ImportFrom(Chain: TElX509CertificateChain);
begin
  ImportFrom(Chain, true);
end;

procedure TElCustomCertStorage.ImportFrom(Chain: TElX509CertificateChain; ImportEndEntity : boolean);
var i, j : integer;
begin
  if ImportEndEntity then
    j := 0
  else
    j := 1;
  for i := j to Chain.Count -1 do
  begin
    if not Contains(Chain.Certificates[i]) then
      Add(Chain.Certificates[i], true);
  end;
end;

procedure TElCustomCertStorage.BeginRead;
begin
  FSharedResource.WaitToRead();
end;

function TElCustomCertStorage.Contains(Certificate: TElX509Certificate):
    Boolean;
var idx : integer;
begin
  Result := false;
  idx :=  FindByHash (Certificate.GetHashSHA1);
  if idx <> -1 then
    result := Certificate.Equals(Certificates[idx]);
end;

procedure TElCustomCertStorage.EndRead;
begin
  FSharedResource.Done();
end;

////////////////////////////////////////////////////////////////////////////////
// TElCertificateLookup class

constructor TElCertificateLookup.Create(AOwner: TComponent);
begin
  inherited ;
  FLastIndex := -1;
  FIssuerRDN := TElRelativeDistinguishedName.Create;
  FSubjectRDN := TElRelativeDistinguishedName.Create;
  FEmailAddresses := TElStringList.Create;
  FPublicKeyHashAlgorithm := SB_ALGORITHM_DGST_SHA1;
end;


 destructor  TElCertificateLookup.Destroy;
begin
  FreeAndNil(FIssuerRDN);
  FreeAndNil(FSubjectRDN);
  FreeAndNil(FEmailAddresses);
  inherited;
end;

procedure TElCertificateLookup.SetCriteria(Value: TSBLookupCriteria);
begin
  FCriteria := Value;
  FLastIndex := -1;
end;

procedure TElCertificateLookup.SetAuthorityKeyIdentifier(const V: ByteArray);
begin
  FAuthorityKeyIdentifier := CloneArray(V);
end;

procedure TElCertificateLookup.SetSubjectKeyIdentifier(const V: ByteArray);
begin
  FSubjectKeyIdentifier := CloneArray(V);
end;

procedure TElCertificateLookup.SetSerialNumber(const V : ByteArray);
begin
  FSerialNumber := CloneArray(V);
end;

procedure TElCertificateLookup.SetPublicKeyHash(const V : ByteArray);
begin
  FPublicKeyHash := CloneArray(V);
end;

procedure TElCertificateLookup.SetCertificateHash(const V : ByteArray);
begin
  FCertificateHash := CloneArray(V);
end;

function TElCertificateLookup.FindNext(Storage: TElCustomCertStorage): integer;
var
  Index: integer;
  Cert: TElX509Certificate;
  B, MatchOne: boolean;
  HashFunc : TElHashFunction;
  Size : integer;
  dwSize : integer;
  Buf : ByteArray;
  I, K: integer;
begin
  CheckLicenseKey();
  Index := FLastIndex + 1;
  Result := -1;
  while Index < Storage.Count do
  begin
    FLastIndex := Index;
    Cert := Storage.Certificates[Index];
    MatchOne := false;
    Inc(Index);
    // 1. Issuer
    if lcIssuer in FCriteria then
    begin
      if loCompareRDNAsStrings in FOptions then
      begin
        if loExactMatch in FOptions then
          B := CompareRDNAsStrings(FIssuerRDN, Cert.IssuerRDN)
        else
          B := NonstrictCompareRDNAsStrings(FIssuerRDN, Cert.IssuerRDN);
      end
      else
      begin
        if loExactMatch in FOptions then
          B := CompareRDN(FIssuerRDN, Cert.IssuerRDN)
        else
          B := NonstrictCompareRDN(FIssuerRDN, Cert.IssuerRDN);
      end;

      if (not B) and (loMatchAll in FOptions) then
        Continue;
      MatchOne := MatchOne or B;
    end;
    // 2. Subject
    if lcSubject in FCriteria then
    begin
      if loCompareRDNAsStrings in FOptions then
      begin
        if loExactMatch in FOptions then
          B := CompareRDNAsStrings(FSubjectRDN, Cert.SubjectRDN)
        else
          B := NonstrictCompareRDNAsStrings(FSubjectRDN, Cert.SubjectRDN);
      end
      else
      begin
        if loExactMatch in FOptions then
          B := CompareRDN(FSubjectRDN, Cert.SubjectRDN)
        else
          B := NonstrictCompareRDN(FSubjectRDN, Cert.SubjectRDN);
      end;

      if (not B) and (loMatchAll in FOptions) then
        Continue;
      MatchOne := MatchOne or B;
    end;
    // 3. ValidFrom
    if lcValidity in FCriteria then
    begin
      if FDateLookupOptions =  
        [dloBefore]  then
        B := (Cert.ValidFrom <= FValidFrom) and (Cert.ValidTo <= FValidFrom)
      else
        if FDateLookupOptions =   [dloBefore,
          dloBetween]  then
        B := (Cert.ValidFrom <= FValidFrom) and (Cert.ValidTo >= FValidFrom)
      else
        if FDateLookupOptions =   [dloBefore, dloBetween,
          dloAfter]  then
        B := (Cert.ValidFrom <= FValidFrom) and (Cert.ValidTo >= FValidTo)
      else
        if FDateLookupOptions =   [dloBetween,
          dloAfter]  then
        B := (Cert.ValidFrom >= FValidFrom) and (Cert.ValidTo >= FValidTo)
      else
        if FDateLookupOptions =  
          [dloBetween]  then
        B := (Cert.ValidFrom >= FValidFrom) and (Cert.ValidTo <= FValidTo)
      else
        if FDateLookupOptions =   [dloBefore,
          dloAfter]  then
        B := (Cert.ValidTo <= FValidFrom) or (Cert.ValidFrom >= FValidTo)
      else
        if FDateLookupOptions =  
          [dloAfter]  then
        B := (Cert.ValidFrom >= FValidTo) and (Cert.ValidTo >= FValidTo)
      else
        B := true;
      if (not B) and (loMatchAll in FOptions) then
        Continue;
      MatchOne := MatchOne or B;
    end;
    // 5. Public Key Algorithm
    if lcPublicKeyAlgorithm in FCriteria then
    begin
      B := Cert.PublicKeyAlgorithm = FPublicKeyAlgorithm;
      if (not B) and (loMatchAll in FOptions) then
        Continue;
      MatchOne := MatchOne or B;
    end;
    // 6. Signature algorithm
    if lcSignatureAlgorithm in FCriteria then
    begin
      B := Cert.SignatureAlgorithm = FSignatureAlgorithm;
      if (not B) and (loMatchAll in FOptions) then
        Continue;
      MatchOne := MatchOne or B;
    end;
    // 7. PublicKeySize
    if lcPublicKeySize in FCriteria then
    begin
      if FKeySizeLookupOption =  ksloSmaller  then
        B := Cert.GetPublicKeySize <= FPublicKeySizeMin
      else
        if FKeySizeLookupOption =  ksloGreater  then
        B := Cert.GetPublicKeySize >= FPublicKeySizeMax
      else
        if FKeySizeLookupOption =  ksloBetween  then
        B := (Cert.GetPublicKeySize <= FPublicKeySizeMax) and
          (Cert.GetPublicKeySize >= FPublicKeySizeMin)
      else
        B := false;
      if (not B) and (loMatchAll in FOptions) then
        Continue;
      MatchOne := MatchOne or B;
    end;
    // 8. Auth key id
    if lcAuthorityKeyIdentifier in FCriteria then
    begin
      B := (ceAuthorityKeyIdentifier in Cert.Extensions.Included) and
      (CompareContent(FAuthorityKeyIdentifier,
        Cert.Extensions.AuthorityKeyIdentifier.KeyIdentifier));
      if (not B) and (loMatchAll in FOptions) then
        Continue;
      MatchOne := MatchOne or B;
    end;
    // 9. Subject key id
    if lcSubjectKeyIdentifier in FCriteria then
    begin
      B := (ceSubjectKeyIdentifier in Cert.Extensions.Included) and
      (CompareContent(FSubjectKeyIdentifier,
        Cert.Extensions.SubjectKeyIdentifier.KeyIdentifier));
      if (not B) and (loMatchAll in FOptions) then
        Continue;
      MatchOne := MatchOne or B;
    end;
    // 10. KeyUsage
    if lcKeyUsage in FCriteria then
    begin
      if kuloMatchAll in FKeyUsageLookupOptions then
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
      if (not B) and (loMatchAll in FOptions) then
        Continue;
      MatchOne := MatchOne or B;
    end;
    // 11. E-mail address
    if lcEmail in FCriteria then
    begin
      B := false;
      for I := 0 to FEmailAddresses.Count - 1 do
      begin
        if CompareText(Cert.SubjectName.EMailAddress, FEmailAddresses[I]) = 0
          then
        begin
          B := true;
          Break;
        end;
      end;
      if not B then
      begin
        if ceSubjectAlternativeName in Cert.Extensions.Included then
        begin
          for K := 0 to Cert.Extensions.SubjectAlternativeName.Content.Count - 1 do
          begin
            if Length(Cert.Extensions.SubjectAlternativeName.Content.Names[K].RFC822Name) > 0 then
            begin
              for I := 0 to FEmailAddresses.Count - 1 do
              begin
                if
                  (CompareText(Cert.Extensions.SubjectAlternativeName.Content.Names[K].RFC822Name,
                  FEmailAddresses[I]) = 0) then
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
      if (not B) and (loMatchAll in FOptions) then
        Continue;
      MatchOne := MatchOne or B;
    end;
    // 12. Serial number
    if lcSerialNumber in FCriteria then
    begin
      B := SerialNumberCorresponds(Cert, FSerialNumber);
      if (not B) and (loMatchAll in FOptions) then
        Continue;
      MatchOne := MatchOne or B;
    end;
    // 13. Public key hash
    if lcPublicKeyHash in FCriteria then
    begin
      Buf := EmptyArray;
      try
        HashFunc := TElHashFunction.Create(FPublicKeyHashAlgorithm);
        try
          Size := 0;
          Cert.GetPublicKeyBlob( nil , Size);
          SetLength(Buf, Size);
          Cert.GetPublicKeyBlob( @Buf[0] , Size);
          HashFunc.Update( @Buf[0] , Size);
          Buf := HashFunc.Finish();
        finally
          FreeAndNil(HashFunc);
        end;
      except
        ;
      end;
      B := CompareContent(Buf, FPublicKeyHash);
      if (not B) and (loMatchAll in FOptions) then
        Continue;
      MatchOne := MatchOne or B;
    end;
    // 14. Certificate hash
    if lcCertificateHash in FCriteria then
    begin
      Buf := EmptyArray;
      try
        HashFunc := TElHashFunction.Create(FCertificateHashAlgorithm);
        try
          dwSize := 0;
          Cert.SaveToBuffer( nil , dwSize);
          SetLength(Buf, dwSize);
          Cert.SaveToBuffer( @Buf[0] , dwSize);
          HashFunc.Update( @Buf[0] , dwSize);
          Buf := HashFunc.Finish();
        finally
          FreeAndNil(HashFunc);
        end;
      except
        ;
      end;
      B := CompareContent(Buf, FCertificateHash);
      if (not B) and (loMatchAll in FOptions) then
        Continue;
      MatchOne := MatchOne or B;
    end;
    if MatchOne then
    begin
      Result := Index - 1;
      Break;
    end;
  end;
end;


initialization
  begin

    {$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
    PKCS7OID  := CreateByteArrayConst(#$2A#$86#$48#$86#$F7#$0D#$01#$07#$02);
    PKCS7Data := CreateByteArrayConst(#$2A#$86#$48#$86#$F7#$0D#$01#$07#$01);
     {$endif}

  end;

end.

