(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBX509;

(*

Change history (not complete)

24 June 2005

  Added PKCS8 support

21 June 2005

  Fixed DetectKeyFileFormat() method, which didn't work correctly

*)

interface

uses
  {$ifdef WIN32}
  Windows,
  Activex,
  {$ifdef SB_HAS_WINCRYPT}
  SBWinCrypt,
   {$endif}
 {$endif}
  Classes,
  SysUtils,
  {$ifdef SB_UNICODE_VCL}
  SBStringList,
   {$endif}
  // java
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBConstants,
  SBStreams,
  SBEncoding,
  SBMD,
  SBSHA,
  SBMath,
  SBRDN,
  SBASN1,
  SBPEM,
  SBHashFunction,
  {$ifndef SB_NO_PKIASYNC}
  SBPKIAsync,
   {$endif}
  SBX509Ext,
  SBCustomCrypto,
  SBSymmetricCrypto,
  SBPublicKeyCrypto,
  SBAlgorithmIdentifier,
  SBCryptoProv,
  SBASN1Tree
;



const
  SB_X509_ERROR_INVALID_PVK_FILE = Integer($5001);
  SB_X509_ERROR_INVALID_PASSWORD = Integer($5002);
  SB_X509_ERROR_NO_PRIVATE_KEY = Integer($5003);
  SB_X509_ERROR_UNSUPPORTED_ALGORITHM = Integer($5004);
  SB_X509_ERROR_INVALID_PRIVATE_KEY = Integer($5005);
  SB_X509_ERROR_INTERNAL_ERROR = Integer($5006);
  SB_X509_ERROR_BUFFER_TOO_SMALL = Integer($5007);
  SB_X509_ERROR_NO_CERTIFICATE = Integer($5008);
  SB_X509_ERROR_UNRECOGNIZED_FORMAT = Integer($5009);

  BT_WINDOWS = 1;
  BT_PKCS11 = 2;
  BT_WAB = 4;
  BT_OUTLOOK = 8;
  BT_FILE = 16;
  

// TODO: eliminate BelongsTo property


type
  TSBCertificateValidity = 
    (cvOk { = 1}, cvSelfSigned { = 2}, cvInvalid { = 4},
     cvStorageError { = 8}, cvChainUnvalidated { = 16});
  TSBCertificateValidityReason = set of (vrBadData { = 1}, vrRevoked { = 2},
    vrNotYetValid { = 4},
    vrExpired { = 8}, vrInvalidSignature { = 16}, vrUnknownCA { = 32}, vrCAUnauthorized { = 64}, vrCRLNotVerified { = 128 }, vrOCSPNotVerified { = 256 }, vrIdentityMismatch { = 512}, vrNoKeyUsage { = 1024}, vrBlocked { = 2048});

  TSBCertFileFormat = (cfUnknown, cfDER, cfPEM, cfPFX, {cfMSBLOB, } cfSPC);
  TSBX509KeyFileFormat = (kffUnknown, kffDER, kffPEM, kffPFX, kffPVK, kffNET, kffPKCS8);

  TValidity = record
    NotBefore: TElDateTime;
    NotAfter: TElDateTime;
  end;

  TName =  record
    Country: string;
    StateOrProvince: string;
    Locality: string;
    Organization: string;
    OrganizationUnit: string;
    CommonName: string;
    EMailAddress: string;
  end;

  TElSubjectPublicKeyInfo = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElSubjectPublicKeyInfo = TElSubjectPublicKeyInfo;
   {$endif}

  TElSubjectPublicKeyInfo =  class
   private 
    FAlgorithm: TElAlgorithmIdentifier;
    FRawData : ByteArray;
    FFullData : ByteArray; // all SPKI data, including algorithm identifier

    function GetPublicKeyAlgorithmIdentifier : TElAlgorithmIdentifier;
    function GetPublicKeyAlgorithm: integer;
    function GetRawData : ByteArray;
  public
    constructor Create;
     destructor  Destroy; override;
    procedure Clear;
    property PublicKeyAlgorithmIdentifier: TElAlgorithmIdentifier read GetPublicKeyAlgorithmIdentifier;
    property PublicKeyAlgorithm: integer read GetPublicKeyAlgorithm;
    property RawData : ByteArray read GetRawData;
  end;

  TElTBSCertificate = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElTBSCertificate = TElTBSCertificate;
   {$endif}

  TElTBSCertificate =  class
   private 
    FVersion: Byte; // v1(0), v2(1), v3(2)
    FSerialNumber: ByteArray;
    FSignatureIdentifier: TElAlgorithmIdentifier;
    FValidity: TValidity;
    FIssuer: TStringList;
    FSubject: TStringList;
    FSubjectPublicKeyInfo: TElSubjectPublicKeyInfo;
    FIssuerUniqueID: ByteArray; //If present, version shall be v2 or v3
    FSubjectUniqueID: ByteArray; //If present, version shall be v2 or v3
    procedure SetSerialNumber(const V: ByteArray);
    procedure SetIssuerUniqueID(const V: ByteArray); 
    procedure SetSubjectUniqueID(const V: ByteArray);
  public
    constructor Create;
     destructor  Destroy; override;
    procedure Clear;
    property Version : Byte read FVersion write FVersion;
    property SerialNumber : ByteArray read FSerialNumber write SetSerialNumber;
    property SignatureIdentifier : TElAlgorithmIdentifier read FSignatureIdentifier;
    property Issuer : TStringList read FIssuer;
    property Subject : TStringList read FSubject;
    property SubjectPublicKeyInfo : TElSubjectPublicKeyInfo read FSubjectPublicKeyInfo;
    property IssuerUniqueID : ByteArray read FIssuerUniqueID write SetIssuerUniqueID;
    property SubjectUniqueID : ByteArray read FSubjectUniqueID write SetSubjectUniqueID;
    property Validity : TValidity read FValidity write FValidity;
  end;

  TElX509CertificateChain =  class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElX509CertificateChain = TElX509CertificateChain;
   {$endif}
  TElX509Certificate =  class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElX509Certificate =  TElX509Certificate;
   {$endif}

  TElBaseCertStorage = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElBaseCertStorage = TElBaseCertStorage;
   {$endif}

  TElBaseCertStorage = class(TSBControlBase)
  protected
    procedure AddToChain(Chain : TElX509CertificateChain; Certificate : TElX509Certificate);
  end;

  TSBCertSecurityLevel = (cslLow, cslMedium, cslHigh);


  TElX509Certificate = class(TSBControlBase{$ifdef SB_HAS_MEMORY_MANAGER}, TElICachableObject {$endif})
  protected
    FtbsCertificate: TElTBSCertificate;
    FSignatureAlgorithm: TElAlgorithmIdentifier;
    FCryptoProvider : TElCustomCryptoProvider;
    FSigningKey : TElPublicKeyMaterial;

    FSignatureValue: ByteArray;
    FIssuerName: TName;
    FSubjectName: TName;
    FNegativeSerial : boolean;

    FErrorCode: Byte;
    FPData: PByteArray; // Pointer to internal Certificate binary data

    FAllSize: integer;
    FCertificateSize: integer; // length of Certificate block
    FCertificateOffset: integer; // tbsCertificate data offset

    FNewSubject: TName;
    FNewIssuer: TName;

    FCAAvailable: boolean;
    FCAKeyIdentifier: ByteArray;
    FCACert : TElX509Certificate;
    FOurKeyIdentifier: ByteArray;

    FCertificateExtensions: TElCertificateExtensions;
    FIssuerRDN: TElRelativeDistinguishedName;
    FSubjectRDN: TElRelativeDistinguishedName;
    FStrictMode: boolean;
    FReportErrorOnPartialLoad : boolean;
    FUseUTF8 : boolean;
    FKeyMaterial : TElPublicKeyMaterial;
    FPublicKeyBlob : ByteArray;
    FIgnoreVersion : boolean;

    procedure ReadCertificate;
    procedure ReadCertificateFromASN;

    procedure AddFieldByOID(var Name: TName; const OID: ByteArray; Tag : byte;
      const Content: ByteArray);

    function GetCertificateBinary : PByteArray;

    function GetCertificateSelfSigned: boolean;
    function GetSignatureAlgorithm : integer;
    function GetValidFrom: TElDateTime;
    function GetValidTo: TElDateTime;
    procedure SetValidFrom(const Value: TElDateTime);
    procedure SetValidTo(const Value: TElDateTime);
    function GetPublicKeyAlgorithm: integer;
    function GetPublicKeyAlgorithmIdentifier: TElAlgorithmIdentifier;
  protected
    FCertStorage: TElBaseCertStorage;
    FBelongsTo: integer;
    FStorageName: string;
    FChain: TElX509CertificateChain;
    FCryptoProviderManager : TElCustomCryptoProviderManager;
    procedure ClearData; virtual;
    procedure AssignTo(Dest: TPersistent); override;
    procedure RaiseInvalidCertificateException;
    procedure SetupKeyMaterial;
    
    {$ifdef SB_HAS_WINCRYPT}
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    function GetCertHandle :   PCCERT_CONTEXT  ;
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecuritySafeCritical]
     {$endif}
    procedure SetCertHandle(Value:   PCCERT_CONTEXT  );
    {$ifndef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    function GetFriendlyName(): string;
    procedure SetFriendlyName(const Value : string);
     {$endif}
     {$endif}
    
    function GetCanEncrypt: boolean;
    function GetCanSign: boolean;
    function GetVersion: byte;
    procedure SetVersion(Value: byte);
    function GetSerialNumber: ByteArray;
    procedure SetSerialNumber(const Value: ByteArray);
    function GetIssuer: TStringList;
    function GetSubject: TStringList;
    function GetIssuerUniqueID: ByteArray;
    function GetSubjectUniqueID: ByteArray;
    function GetPrivateKeyExtractable : boolean;
    function GetPrivateKeyExists : boolean;
  public
    constructor Create(Owner: TSBComponentBase);   {$ifndef SB_NO_COMPONENT}override; {$endif} 
     destructor  Destroy; override;
    {$ifndef SB_NO_FILESTREAM}
    class function DetectCertFileFormat(const FileName: string): TSBCertFileFormat;  overload;      {$endif}
    class function DetectCertFileFormat(Stream: TElInputStream): TSBCertFileFormat;  overload;     class function DetectKeyFileFormat(Stream: TElInputStream; const Password: string): TSBX509KeyFileFormat;  overload; 
    class function DetectCertFileFormat( Buffer : pointer ; Size : integer): TSBCertFileFormat;  overload;     {$ifndef SB_NO_FILESTREAM}
    class function DetectKeyFileFormat(const FileName: string; const Password: string): TSBX509KeyFileFormat;  overload;      {$endif}
    class function DetectKeyFileFormat( Buffer : pointer ; Size : integer; const Password: string): TSBX509KeyFileFormat;  overload;     
    function Equals(Other : TElX509Certificate) : boolean; {$ifdef D_12_UP}reintroduce; {$endif}
    procedure Clone(Dest: TElX509Certificate; CopyPrivateKey: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif});  overload; 
    procedure Clone(Dest: TElX509Certificate; CryptoProvider : TElCustomCryptoProvider);  overload; 
    {$ifdef SB_HAS_WINCRYPT}
    procedure ChangeSecurityLevel(Level: TSBCertSecurityLevel; const Password: string);
     {$endif}

    procedure LoadFromBuffer(Buffer: Pointer; Size: integer);
    function LoadFromBufferPEM(Buffer: pointer; Size: integer; const PassPhrase: string): integer;
    procedure LoadKeyFromBuffer(Buffer: Pointer; Size: integer);
    function LoadKeyFromBufferPEM(Buffer: pointer; Size: integer; const PassPhrase: string): integer;
    function LoadFromBufferPFX(Buffer: pointer; Size: integer; const Password: string): integer;
    function LoadFromBufferSPC(Buffer: pointer; Size: integer): integer;
    function LoadKeyFromBufferMS(Buffer: pointer; Size: integer): integer;
    function LoadKeyFromBufferPKCS8(Buffer: pointer; Size: integer; const Password: string): integer;
    function LoadFromBufferAuto(Buffer: pointer; Size: integer; const Password: string): integer;
    function LoadKeyFromBufferAuto(Buffer: pointer; Size: integer; const Password: string): integer;
    {$ifndef B_6}
    function LoadKeyFromBufferNET(Buffer: pointer; Size: integer; const Password: string): integer;
     {$endif}
    function LoadKeyFromBufferPVK(Buffer: pointer; Size: integer; const Password: string): integer;
    procedure LoadKeyFromBufferPKCS15(Buffer : pointer; Size : integer; const Password : string);
    procedure LoadKeyFromStreamPKCS15(Stream: TStream; const Password : string; Count: integer = 0);
    procedure LoadFromStream(Stream: TStream; Count: integer = 0);{$ifndef BUILDER_USED}{$ifdef SB_WINDOWS} overload; {$endif} {$endif}
    {$ifndef BUILDER_USED}
    {$ifdef WIN32}
    {$ifndef FPC}
    procedure LoadFromStream(Stream: IStream; Count: integer = 0); overload;
     {$endif}
     {$endif CLX_USED}
     {$endif BUILDER_USED}
    procedure LoadKeyFromStream(Stream: TStream; Count: integer = 0);
    function LoadKeyFromStreamPEM(Stream: TStream; const PassPhrase: string;
      Count: integer = 0): integer;
    function LoadFromStreamPEM(Stream: TStream; const PassPhrase: string; Count: integer = 0): integer;
    function LoadFromStreamPFX(Stream: TStream; const Password: string; Count: integer = 0): integer;
    function LoadFromStreamSPC(Stream: TStream; Count: integer = 0): integer;
    function LoadKeyFromStreamMS(Stream: TStream; Count: integer = 0): integer;
    function LoadKeyFromStreamPKCS8(Stream: TStream; const Password: string; Count: integer = 0): integer;
    function LoadKeyFromStreamPVK(Stream: TStream; const Password: string; Count: integer = 0): integer;
    function LoadFromStreamAuto(Stream: TStream; const Password: string; Count: integer): integer;
    function LoadKeyFromStreamAuto(Stream: TStream; const Password: string; Count: integer): integer;
    {$ifndef B_6}
    function LoadKeyFromStreamNET(Stream: TStream; const Password: string; Count: integer = 0): integer;
     {$endif}
    {$ifndef SB_NO_FILESTREAM}
    function LoadFromFileAuto(const Filename: string; const Password: string): integer;
    function LoadKeyFromFileAuto(const Filename: string; const Password: string): integer;
     {$endif}
    function SaveToBuffer(Buffer: Pointer; var Size: integer): boolean;
    function SaveKeyToBuffer(Buffer: Pointer; var Size: integer): boolean;
    function SaveToBufferPEM(Buffer: Pointer; var Size: integer; const PassPhrase: string): boolean;
    function SaveKeyToBufferPEM(Buffer: Pointer; var Size: integer; const PassPhrase: string): boolean; overload;
    function SaveKeyToBufferPEM(Buffer: Pointer; var Size: integer; EncryptionAlgorithm : integer;
      EncryptionMode :  TSBSymmetricCryptoMode ; const PassPhrase: string): boolean; overload;
    function SaveToBufferPFX(Buffer: pointer; var Size: integer; const Password: string;
      KeyEncryptionAlgorithm: integer; CertEncryptionAlgorithm: integer): integer; overload;
    function SaveToBufferPFX(Buffer: pointer; var Size: integer; const Password: string): integer; overload;
    //function SaveToBufferMS(Buffer: pointer; var Size : integer) : integer;
    function SaveToBufferSPC(Buffer: pointer; var Size: integer): integer;
    function SaveKeyToBufferMS(Buffer: pointer; var Size: integer): integer;
    function SaveKeyToBufferNET(Buffer: pointer; var Size: integer): integer;
    function SaveKeyToBufferPVK(Buffer: pointer; var Size: integer;
      const Password: string; UseStrongEncryption: boolean = true): integer;
    function SaveKeyToBufferPKCS8(Buffer: pointer; var Size: integer;
      const Password: string): integer;
    procedure SaveToStream(Stream: TStream);
    procedure SaveKeyToStream(Stream: TStream);
    procedure SaveToStreamPEM(Stream: TStream; const PassPhrase: string);
    procedure SaveKeyToStreamPEM(Stream: TStream; const PassPhrase: string); overload;
    procedure SaveKeyToStreamPEM(Stream: TStream; EncryptionAlgorithm : integer;
      EncryptionMode :  TSBSymmetricCryptoMode ; const PassPhrase: string); overload;
    function SaveToStreamPFX(Stream: TStream; const Password: string;
      KeyEncryptionAlgorithm: integer; CertEncryptionAlgorithm: integer): integer; overload;
    function SaveToStreamPFX(Stream: TStream; const Password: string): integer; overload;
    function SaveToStreamSPC(Stream: TStream): integer;
    function SaveKeyValueToBuffer(Buffer: pointer; var Size: integer): boolean;
    //function SaveToStreamMS(Stream: TStream): integer;
    function SaveKeyToStreamMS(Stream: TStream): integer;
    function SaveKeyToStreamNET(Stream: TStream; const Password: string): integer;
    function SaveKeyToStreamPVK(Stream: TStream; const Password: string;
      UseStrongEncryption: boolean = true): integer;
    function SaveKeyToStreamPKCS8(Stream: TStream; const Password: string): integer;
    {$ifndef SB_NO_FILESTREAM}
    function SaveToFile(const Filename: string; const Password: string; Format : TSBCertFileFormat): integer;
    function SaveKeyToFile(const Filename: string; const Password: string; Format : TSBX509KeyFileFormat): integer;
     {$endif}
    function Validate: boolean;
    function ValidateWithCA(CACertificate: TElX509Certificate): boolean;

    function GetRSAParams(RSAModulus: pointer; var RSAModulusSize: integer;
      RSAPublicKey: pointer; var RSAPublicKeySize: integer): boolean;

    function GetDSSParams(DSSP: pointer; var DSSPSize: integer; DSSQ: pointer;
      var DSSQSize: integer; DSSG: pointer; var DSSGSize: integer;
      DSSY: pointer; var DSSYSize: integer): boolean;

    function GetDHParams(DHP: pointer; var DHPSize: integer; DHG: pointer;
      var DHGSize: integer; DHY: pointer; var DHYSize: integer): boolean;


    function GetPublicKeyBlob(Buffer: pointer; var Size: integer): boolean;  overload; 
    procedure GetPublicKeyBlob(out Buffer: ByteArray);  overload; 
    
    function GetFullPublicKeyInfo : ByteArray;
    function GetHashMD5: TMessageDigest128;
    function GetHashSHA1: TMessageDigest160;
    function GetKeyHashSHA1: TMessageDigest160;
    function GetZIPCertIdentifier : ByteArray;
    function GetPublicKeySize: integer;

    function IsKeyValid: boolean;
    function WriteSerialNumber: ByteArray;
    function WriteExtensionSubjectKeyIdentifier: ByteArray;
    function WriteSubject: ByteArray; virtual;
    function WriteIssuer: ByteArray; virtual;
    procedure SetKeyMaterial(Value : TElPublicKeyMaterial);
    


    {$ifdef SB_HAS_WINCRYPT}
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecurityCritical]
    function GetFriendlyName(): string;
    [SecurityCritical]
    procedure SetFriendlyName(const Value : string);
     {$endif}
     {$endif}

    {$ifdef SB_HAS_WINCRYPT}
    {$ifdef SB_HAS_CRYPTUI}
    {$ifdef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    [SecurityCritical]
     {$endif}
    function View(Owner : HWND) : boolean;
     {$endif}
     {$endif}

    property CertificateBinary: PByteArray read GetCertificateBinary;
    property CertificateSize: integer read FAllSize;
    property SignatureAlgorithm: integer read GetSignatureAlgorithm;
    property SignatureAlgorithmIdentifier: TElAlgorithmIdentifier read FSignatureAlgorithm;
    property Signature: ByteArray read FSignatureValue;
    property Version: byte read GetVersion write SetVersion;
    property SerialNumber: ByteArray read GetSerialNumber
      write SetSerialNumber;

    property ValidFrom: TElDateTime read GetValidFrom write SetValidFrom;
    property ValidTo: TElDateTime read GetValidTo write SetValidTo;

    property BelongsTo: integer read FBelongsTo write FBelongsTo;
    {$ifdef SB_HAS_WINCRYPT}
    property CertHandle :   PCCERT_CONTEXT   read GetCertHandle write SetCertHandle;
    {$ifndef SB_HAS_SECURITY_CRITICAL_ATTRIBUTE}
    property FriendlyName : string read GetFriendlyName write SetFriendlyName;
     {$endif}
     {$endif}
    property IssuerUniqueID: ByteArray read GetIssuerUniqueID;
    property SubjectUniqueID: ByteArray read GetSubjectUniqueID;
    property PublicKeyAlgorithm: integer read GetPublicKeyAlgorithm;
    property PublicKeyAlgorithmIdentifier: TElAlgorithmIdentifier read GetPublicKeyAlgorithmIdentifier;
    property PrivateKeyExists: boolean read GetPrivateKeyExists;
    property PrivateKeyExtractable: boolean read GetPrivateKeyExtractable;
    property CAAvailable: boolean read FCAAvailable write FCAAvailable;
    property SelfSigned: boolean read GetCertificateSelfSigned;
    property IssuerName: TName read FIssuerName;
    property SubjectName: TName read FSubjectName;
    property IssuerRDN: TElRelativeDistinguishedName read FIssuerRDN;
    property SubjectRDN: TElRelativeDistinguishedName read FSubjectRDN;
    property Extensions: TElCertificateExtensions read FCertificateExtensions;
    property CertStorage: TElBaseCertStorage read FCertStorage write FCertStorage;
    property StorageName: string read FStorageName write FStorageName;
    property CanEncrypt: boolean read GetCanEncrypt;
    property CanSign: boolean read GetCanSign;
    property StrictMode: boolean read FStrictMode write FStrictMode  default false ;
    property UseUTF8 : boolean read FUseUTF8 write FUseUTF8  default false ;
    property Chain: TElX509CertificateChain read FChain write FChain;
    property KeyMaterial : TElPublicKeyMaterial read FKeyMaterial;
    property NegativeSerial : boolean read FNegativeSerial;
    property ReportErrorOnPartialLoad : boolean read FReportErrorOnPartialLoad
      write FReportErrorOnPartialLoad;
    // TODO: add to Notification method
    property CryptoProvider : TElCustomCryptoProvider read FCryptoProvider write FCryptoProvider;
    property CryptoProviderManager : TElCustomCryptoProviderManager read
      FCryptoProviderManager write FCryptoProviderManager;
    property IgnoreVersion : boolean read FIgnoreVersion write FIgnoreVersion  default false ;
  end;

  TElX509CertificateClass = class of TElX509Certificate;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElX509CertificateClass = TElX509CertificateClass;
   {$endif}

  
  TElX509CertificateChain = class(TSBControlBase)
  protected
    FCertificates : TElList;
    

    function GetCount: Integer;
    
    procedure DoAdd(Certificate : TElX509Certificate);
    function GetComplete: Boolean;

    function GetCertificate(Index : integer): TElX509Certificate;
  public
    constructor Create(Owner: TSBComponentBase);   {$ifndef SB_NO_COMPONENT}override; {$endif} 
     destructor  Destroy; override;

    function Add(Certificate : TElX509Certificate) : boolean; // returns true if the certificate was added, and false otherwise
    function Validate(var Reason: TSBCertificateValidityReason; ValidityMoment:
       TElDateTime = 0 ): TSBCertificateValidity;   overload; 
    function Validate(var Reason: TSBCertificateValidityReason;
      CheckCACertDates : boolean; ValidityMoment:
       TElDateTime = 0 ): TSBCertificateValidity;   overload; 

      
    property Certificates[Index : integer]: TElX509Certificate read GetCertificate;

    property Complete: Boolean read GetComplete;
    property Count: Integer read GetCount;
    
  end;

type

  EElX509Error =  class(ESecureBlackboxError);

type
  TPVKHeader =   packed  record
    magic: DWORD;
    reserved: DWORD;
    keytype: DWORD;
    encrypted: DWORD;
    saltlen: DWORD;
    keylen: DWORD;
  end;

function PVKHeaderToByteArray(const Header : TPVKHeader) : ByteArray; 

function PVK_DeriveKey(const Password: ByteArray; const Salt: ByteArray; AWeakMethod: boolean): ByteArray;

procedure RaiseX509Error(ErrorCode: integer); 

var
  NegativeSerialWorkaround: boolean = true;

// several negative SN-related methods
function SerialNumberCorresponds(Cert : TElX509Certificate; const Serial : ByteArray): boolean; 
function GetOriginalSerialNumber(Cert : TElX509Certificate): ByteArray; 


procedure Register;

implementation

uses
  SBPKCS12,
  SBCustomCertStorage,
  {$ifdef SB_HAS_WINCRYPT}
  SBWinCertStorage,
  SBCryptoProvWin32,
   {$endif}
  SBPKCS7,
  SBPKCS7Utils,
  SBMSKeyBlob,
{$ifndef B_6}
  SBPKCS8,
 {$endif}
  SBRandom
  {$ifndef SB_NO_RC4}
  ,
  SBRC4
   {$endif}
  ;

(*
{$ifndef SB_UNICODE_VCL}
const
  PEM_BEGIN_LINE : string = '-----BEGIN';
  PEM_END_LINE : string = '-----END';

{$else}
{$ifndef SB_DELPHI_MOBILE}
const
  PEM_BEGIN_LINE : AnsiString = '-----BEGIN CERTIFICATE-----';
  PEM_END_LINE : AnsiString = '-----END CERTIFICATE-----';
{$else}
  var
  PEM_BEGIN_LINE : ByteArray;
  PEM_END_LINE : ByteArray;
{$endif}
{$endif}
*)

// TODO: (low priority)
// * remove *EncryptionParameters, pass public key blob and parameters directly to KeyMaterial
// * distinguish algorithms by OIDs, or better by TElAlgorithmIdentifier
// * add SavePublicKey() method to certificate requests and pass the blob to KeyMaterial (instead of saving/loading low-level RSA/DSA parameters)

resourcestring
  sInvalidPVKFormat = 'Invalid file format (possibly not a PVK?)';
  sIncorrectPassphrase = 'Incorrect password';
  sNotEnoughBufferSpace = 'Not enough buffer space';
  SInvalidtbsCert = 'Invalid certificate data';
//  SInvalidSignAlgorithmSize = 'Invalid signature algorithm size';
  SPrivateKeyNotFound = 'Private key not found';
  SInvalidPointer = 'Invalid pointer';
  SInvalidRequestSignature = 'Invalid request signature';
  SUnknownAlgorithm = 'Unknown algorithm';
  SInternalError = 'Internal Error. Please contact EldoS support for details.';
  SNoCertificateFound = 'No certificate found';
  SInvalidCertificate = 'No X.509 certificate data found';
  SInvalidPrivateKey = 'No private key found';
//  SKeyLengthTooSmall = 'Key length is too small';
  SInvalidAlgorithmIdentifier = 'Invalid algorithm identifier';
//  SObjectTooLong = 'Object Identifier is too long';
  SCertAlgorithmMismatch = 'Certificate algorithm mismatch';
//  SNonCriticalExtensionMarkedAsCritical = 'Non-critical extension is marked as critical';
  SInvalidPublicKeyAlgorithm = 'Invalid public key algorithm';
  SInvalidSignatureAlgorithm = 'Invalid signature algorithm';
  SCertIsNotBeingGenerated = 'Certificate is not being generated (use BeginGenerate() method)';
  SCertificateTooLong = 'Certificate is too long';
  SPublicKeyTooLong = 'Public key is too long';
  SInvalidPKCS15ASN1Data = 'Invalid PKCS#15 ASN.1 data';
  SInvalidPassword = 'Invalid password';
  SInvalidKeyMaterial = 'Invalid key material';
  SInvalidParameter = 'Invalid parameter';
  SInvalidPublicKey = 'Invalid public key';
  SFailedToSetFriendlyName = 'Failed to set certificate friendly name';
  SInvalidPublicKeyPar = 'Invalid or unsupported public key in certificate <%s>';
  SInvalidPublicKeyParInnEx = 'Invalid or unsupported public key in certificate <%s> (inner exception: %s)';
  
const
  SB_MAX_CERT_LENGTH = 32768;
  SB_CERT_BUFFER_SIZE = 4096;

procedure RaiseX509Error(ErrorCode: integer);
begin
  case ErrorCode of
    SB_X509_ERROR_INVALID_PVK_FILE: raise EElX509Error.Create(sInvalidPVKFormat, ErrorCode{$ifndef HAS_DEF_PARAMS}{$ifndef FPC}, 0 {$endif} {$endif});
    SB_X509_ERROR_INVALID_PASSWORD: raise EElX509Error.Create(sIncorrectPassphrase, ErrorCode{$ifndef HAS_DEF_PARAMS}{$ifndef FPC}, 0 {$endif} {$endif});
    SB_X509_ERROR_NO_PRIVATE_KEY: raise EElX509Error.Create(SPrivateKeyNotFound, ErrorCode{$ifndef HAS_DEF_PARAMS}{$ifndef FPC}, 0 {$endif} {$endif});
    SB_X509_ERROR_UNSUPPORTED_ALGORITHM: raise EElX509Error.Create(SUnknownAlgorithm, ErrorCode{$ifndef HAS_DEF_PARAMS}{$ifndef FPC}, 0 {$endif} {$endif});
    SB_X509_ERROR_INVALID_PRIVATE_KEY: raise EElX509Error.Create(SInvalidPrivateKey, ErrorCode{$ifndef HAS_DEF_PARAMS}{$ifndef FPC}, 0 {$endif} {$endif});
    SB_X509_ERROR_INTERNAL_ERROR: raise EElX509Error.Create(sInternalError, ErrorCode{$ifndef HAS_DEF_PARAMS}{$ifndef FPC}, 0 {$endif} {$endif});
    SB_X509_ERROR_BUFFER_TOO_SMALL: raise EElX509Error.Create(sNotEnoughBufferSpace, ErrorCode{$ifndef HAS_DEF_PARAMS}{$ifndef FPC}, 0 {$endif} {$endif});
  else
    exit;
  end;
end;

type
  THackElCertificateExtensions = class(TElCertificateExtensions);

procedure Register;
begin
  RegisterComponents('PKIBlackbox', [TElX509Certificate]);
end;


function PVKHeaderToByteArray(const Header : TPVKHeader) : ByteArray;
begin
  SetLength(result, 24);
  GetByteArrayFromDWordLE(Header.Magic, Result, 0);
  GetByteArrayFromDWordLE(Header.Reserved, Result, 4);
  GetByteArrayFromDWordLE(Header.KeyType, Result, 8);
  GetByteArrayFromDWordLE(Header.Encrypted, Result, 12);
  GetByteArrayFromDWordLE(Header.SaltLen, Result, 16);
  GetByteArrayFromDWordLE(Header.KeyLen, Result, 20);
end;

{$O-}
function PVK_DeriveKey(const Password: ByteArray; const Salt: ByteArray; AWeakMethod: boolean): ByteArray;
var
  M160: TMessageDigest160;
begin
  M160 := HashSHA1(SBConcatArrays(Salt, Password));
  SetLength(Result, 16);
  if AWeakMethod then
  begin
    SBMove(M160, Result[0], 5);
    FillChar(Result[5 + 0], 11, 0);
  end
  else
    SBMove(M160, Result[0], Length(Result));
end;
{$O+}

{$ifndef SB_NO_RC4}
function PVK_CheckKey(const Key: ByteArray; InBuffer: pointer; OutBuffer: pointer;
  var Context: TRC4Context): boolean;
const
  Magic = $32415352;
begin
  SBRC4.Initialize(Context, TRC4Key(Key));
  SBRC4.Decrypt(Context, InBuffer, OutBuffer, 4);
  Result := (Magic = PLongword(OutBuffer)^);
end;
 {$endif}

constructor TElX509Certificate.Create(Owner: TSBComponentBase);
begin
  inherited Create(Owner);
  FTbsCertificate := TElTBSCertificate.Create;
  // load constants (types of extensions)
  GetMem(FPData, SB_CERT_BUFFER_SIZE{32768}); 
  FCertificateExtensions := TElCertificateExtensions.Create;
  FIssuerRDN := TElRelativeDistinguishedName.Create;
  FSubjectRDN := TElRelativeDistinguishedName.Create;
  FCertificateSize := 0;
  FCertificateOffset := 0;
  FBelongsTo := 0;
  FStrictMode := false;
  FSignatureAlgorithm := nil;
  FUseUTF8 := false;
  {$ifdef SB_HAS_WINCRYPT}
//  FCertHandle := nil;
   {$endif}
  SetLength(FPublicKeyBlob, 0);
  FCryptoProviderManager := nil;
  FReportErrorOnPartialLoad := false;
  FIgnoreVersion := false;
end;


 destructor  TElX509Certificate.Destroy;
begin
  ClearData();
  FreeAndNil(FCACert);
  FreeAndNil(FTbsCertificate);
  FreeMem(FPData);
  FreeAndNil(FCertificateExtensions);
  FreeAndNil(FIssuerRDN);
  FreeAndNil(FSubjectRDN);
  if Assigned(FSignatureAlgorithm) then
    FreeAndNil(FSignatureAlgorithm);
  ReleaseArray(FPublicKeyBlob);
  inherited;
end;

function TElX509Certificate.Equals(Other : TElX509Certificate) : boolean;
begin
  result :=
    ( CertificateSize  =  Other.CertificateSize ) and  
    CompareContent(SerialNumber, Other.SerialNumber) and
    (ValidFrom = Other.ValidFrom) and (ValidTo = Other.ValidTo) and
    CompareMD160(GetHashSHA1, Other.GetHashSHA1) and
    CompareRDN(IssuerRDN, Other.IssuerRDN) and
    CompareRDN(SubjectRDN, Other.SubjectRDN);
end;

procedure TElX509Certificate.Clone(Dest: TElX509Certificate;
  CopyPrivateKey: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif});
begin
  if FAllSize = 0 then
    Exit;
  if Assigned(Dest) then
  begin
    Dest.LoadFromBuffer(FPData, FAllSize);

    Dest.StorageName := StorageName;
    Dest.FChain := FChain;

    if Assigned(Dest.FKeyMaterial) then
      FreeAndNil(Dest.FKeyMaterial);
    if Assigned(FKeyMaterial) then
    begin
      Dest.FKeyMaterial := TElPublicKeyMaterial(FKeyMaterial.Clone());
      if not CopyPrivateKey then
      begin
        Dest.FKeyMaterial.ClearSecret;
        Dest.BelongsTo := 0;
      end
      else
        Dest.BelongsTo := BelongsTo;
    end;
  end;
end;

procedure TElX509Certificate.Clone(Dest: TElX509Certificate;
  CryptoProvider : TElCustomCryptoProvider);
begin
  if FAllSize = 0 then
    Exit;
  if Assigned(Dest) then
  begin
    Dest.CryptoProvider := CryptoProvider;
    Dest.LoadFromBuffer(FPData, FAllSize);

    Dest.StorageName := StorageName;
  end;
end;

procedure TElX509Certificate.ReadCertificate;
begin
  CheckLicenseKey();
  FCertificateOffset := 0;
  FCertificateSize := 0;
  BelongsTo := 0;
  ReadCertificateFromASN;
end;

procedure TElX509Certificate.ReadCertificateFromASN;
  procedure ReadRDNSequence(Seq: TElASN1ConstrainedTag; Name: TElRelativeDistinguishedName);
  var
    I, J: integer;
    TagSet, TagSeq: TElASN1ConstrainedTag;
    ObjID, Val: ByteArray;
    Size: integer;
    Index : integer;
  begin
    Name.Clear;
    for I := 0 to Seq.Count - 1 do
    begin
      if not Seq.GetField(I).CheckType(SB_ASN1_SET, true) then
        raise EElCertificateError.Create(SInvalidtbsCert);
      TagSet := TElASN1ConstrainedTag(Seq.GetField(I));
      for J := 0 to TagSet.Count - 1 do
      begin
        if not TagSet.GetField(J).CheckType(SB_ASN1_SEQUENCE, true) then
          raise EElCertificateError.Create(SInvalidtbsCert);
        TagSeq := TElASN1ConstrainedTag(TagSet.GetField(J));
        if (TagSeq.Count <> 2) or (not TagSeq.GetField(0).CheckType(SB_ASN1_OBJECT, false)) then
          raise EElCertificateError.Create(SInvalidtbsCert);
        ObjID := TElASN1SimpleTag(TagSeq.GetField(0)).Content;
        if not TagSeq.GetField(1).IsConstrained then
        begin
          Index := Name.Add(ObjID, TElASN1SimpleTag(TagSeq.GetField(1)).Content,
            TElASN1SimpleTag(TagSeq.GetField(1)).TagId);
          Name.Groups[Index] := I;
        end
        else
        begin
          Size := 0;
          TagSeq.GetField(1).SaveToBuffer( nil , Size);
          SetLength(Val, Size);
          TagSeq.GetField(1).SaveToBuffer( @Val[0] , Size);
          SetLength(Val, Size);
          Index := Name.Add(ObjID, Val, 0);
          Name.Groups[Index] := I;
        end;
      end;
    end;
  end;

  function ReadTime(Tag: TElASN1CustomTag): TElDateTime;
  begin
    if Tag.CheckType(SB_ASN1_UTCTIME, false) then
      Result := UTCTimeToDateTime(StringOfBytes(TElASN1SimpleTag(Tag).Content))
    else
      if Tag.CheckType(SB_ASN1_GENERALIZEDTIME, false) then
      Result := GeneralizedTimeToDateTime(StringOfBytes(TElASN1SimpleTag(Tag).Content))
    else
      raise EElCertificateError.Create(SInvalidTbsCert);
  end;

  procedure ReadSPKI(Tag: TElASN1ConstrainedTag);
  var
    PublicKey: ByteArray;
    PKTag: TElASN1ConstrainedTag;
    Buf : ByteArray;
    Sz : integer;
  begin
    try
    if (Tag.Count = 2) and (Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) and
      (Tag.GetField(1).CheckType(SB_ASN1_BITSTRING, false)) then
    begin
      try
        FtbsCertificate.FSubjectPublicKeyInfo.FAlgorithm :=
          TElAlgorithmIdentifier.CreateFromTag(TElASN1ConstrainedTag(Tag.GetField(0)));

        // full public key info (with algorithm identifier)  
        Sz := 0;
        Tag.SaveToBuffer(nil, Sz);
        SetLength(Buf, Sz);
        Tag.SaveToBuffer(@Buf[0], Sz);
        FTbsCertificate.FSubjectPublicKeyInfo.FFullData := CloneArray(Buf);        

        // subject public key
        PublicKey := TElASN1SimpleTag(Tag.GetField(1)).Content;
        if (Length(PublicKey) < 1) or (PublicKey[0] <> byte(0)) then
          raise EElCertificateError.Create(SInvalidtbsCert);
        FTbsCertificate.FSubjectPublicKeyInfo.FRawData := CloneArray(PublicKey);

        PublicKey := CloneArray(PublicKey, 1, Length(PublicKey) - 1);
        if FTbsCertificate.FSubjectPublicKeyInfo.PublicKeyAlgorithm=SB_CERT_ALGORITHM_EC then
        begin
          SetLength(FPublicKeyBlob, Length(PublicKey));
          SBMove(PublicKey, 0, FPublicKeyBlob, 0, Length(FPublicKeyBlob));
        end
        else
        begin
          PKTag := TElASN1ConstrainedTag.CreateInstance;
          try
            if (Length(PublicKey) = 0) or not PKTag.LoadFromBuffer(@PublicKey[0], Length(PublicKey)) then
            begin
              if FTbsCertificate.FSubjectPublicKeyInfo.PublicKeyAlgorithm <> SB_CERT_ALGORITHM_UNKNOWN then
                raise EElCertificateError.Create(SInvalidtbsCert);
            end;
            // reading public key
            SetLength(FPublicKeyBlob, Length(PublicKey));
            SBMove(PublicKey, 0, FPublicKeyBlob, 0, Length(FPublicKeyBlob));
          finally
            FreeAndNil(PKTag);
            end;
        end;
      except
        raise EElCertificateError.Create(SInvalidTbsCert);
      end;
    end
    else
      raise EElCertificateError.Create(SInvalidTbsCert);
    finally
      ReleaseArray(Buf);
    end;
  end;

  procedure ReadTBSCertificate(Tag: TElASN1ConstrainedTag);
  var
    CurrTagIndex, CurrExtTagIndex: integer;
    OID, Cnt: ByteArray;
    Critical: boolean;
    I: integer;
    ExtTag: TElASN1ConstrainedTag;
    Reader : TElExtensionReader;
  begin
    FTbsCertificate.Clear;
    CurrTagIndex := 0;
    FCertificateOffset := Tag.TagOffset;
    FCertificateSize := Tag.TagSize;

    { Version }
    if (Tag.GetField(CurrTagIndex).CheckType(SB_ASN1_A0, true)) and
      (TElASN1ConstrainedTag(Tag.GetField(CurrTagIndex)).Count = 1) and
      (TElASN1ConstrainedTag(Tag.GetField(CurrTagIndex)).GetField(0).CheckType(SB_ASN1_INTEGER, false)) then
    begin
      Cnt := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(CurrTagIndex)).GetField(0)).Content;
      if Length(Cnt) > 0 then
        FTbsCertificate.FVersion := Byte(Cnt[0]) + 1
      else
        FTbsCertificate.FVersion := 1;
      Inc(CurrTagIndex);
    end
    else
      FTbsCertificate.FVersion := 1;

    { Serial number }
    if (CurrTagIndex >= Tag.Count) then
      raise EElCertificateError.Create(SInvalidtbsCert);
    if (not Tag.GetField(CurrTagIndex).CheckType(SB_ASN1_INTEGER, false)) then
      raise EElCertificateError.Create(SInvalidtbsCert);
    Cnt := TElASN1SimpleTag(Tag.GetField(CurrTagIndex)).Content;
    FTbsCertificate.FSerialNumber := CloneArray(Cnt);
    FNegativeSerial := false;

    if Length(FTBSCertificate.FSerialNumber) < 1 then
    begin
      SetLength(FTBSCertificate.FSerialNumber, 1);
      FTBSCertificate.FSerialNumber[0] := byte(0);
    end;

    if (Length(FTBSCertificate.FSerialNumber) >= 1) and
      (Ord(FTBSCertificate.FSerialNumber[0]) >= $80) and
      (NegativeSerialWorkaround) then
    begin
      FTBSCertificate.FSerialNumber := SBConcatArrays(byte(0), FTBSCertificate.FSerialNumber);
      FNegativeSerial := true;
    end;

    Inc(CurrTagIndex);

    { Signature }
    if (CurrTagIndex >= Tag.Count) then
      raise EElCertificateError.Create(SInvalidtbsCert);
    if not Tag.GetField(CurrTagIndex).CheckType(SB_ASN1_SEQUENCE, true) then
      raise EElCertificateError.Create(SInvalidtbsCert);

    FTbsCertificate.FSignatureIdentifier := TElAlgorithmIdentifier.CreateFromTag(TElASN1ConstrainedTag(Tag.GetField(CurrTagIndex)));
    Inc(CurrTagIndex);

    { Issuer }
    if (CurrTagIndex >= Tag.Count) then
      raise EElCertificateError.Create(SInvalidtbsCert);
    if (not Tag.GetField(CurrTagIndex).CheckType(SB_ASN1_SEQUENCE, true)) then
      raise EElCertificateError.Create(SInvalidtbsCert);

    ReadRDNSequence(TElASN1ConstrainedTag(Tag.GetField(CurrTagIndex)),
      FIssuerRDN);
    for I := 0 to FIssuerRDN.Count - 1 do
      AddFieldByOID(FIssuerName, FIssuerRDN.OIDs[I], FIssuerRDN.Tags[I], FIssuerRDN.Values[I]);
    Inc(CurrTagIndex);

    { Validity }
    if (CurrTagIndex >= Tag.Count) then
      raise EElCertificateError.Create(SInvalidtbsCert);
    if (not Tag.GetField(CurrTagIndex).CheckType(SB_ASN1_SEQUENCE, true)) then
      raise EElCertificateError.Create(SInvalidtbsCert);
    if (TElASN1ConstrainedTag(Tag.GetField(CurrTagIndex)).Count <> 2) then
      raise EElCertificateError.Create(SInvalidtbsCert);
    FtbsCertificate.FValidity.NotBefore := ReadTime(TElASN1ConstrainedTag(Tag.GetField(CurrTagIndex)).GetField(0));
    FtbsCertificate.FValidity.NotAfter := ReadTime(TElASN1ConstrainedTag(Tag.GetField(CurrTagIndex)).GetField(1));
    Inc(CurrTagIndex);

    { Subject }
    if (CurrTagIndex >= Tag.Count) then
      raise EElCertificateError.Create(SInvalidtbsCert);
    if (not Tag.GetField(CurrTagIndex).CheckType(SB_ASN1_SEQUENCE, true)) then
      raise EElCertificateError.Create(SInvalidtbsCert);
    ReadRDNSequence(TElASN1ConstrainedTag(Tag.GetField(CurrTagIndex)),
      FSubjectRDN);
    for I := 0 to FSubjectRDN.Count - 1 do
      AddFieldByOID(FSubjectName, FSubjectRDN.OIDs[I], FSubjectRDN.Tags[I], FSubjectRDN.Values[I]);
    Inc(CurrTagIndex);

    { SPKI }
    if (CurrTagIndex >= Tag.Count) then
      raise EElCertificateError.Create(SInvalidtbsCert);
    if not Tag.GetField(CurrTagIndex).CheckType(SB_ASN1_SEQUENCE, true) then
      raise EElCertificateError.Create(SInvalidtbsCert);
    ReadSPKI(TElASN1ConstrainedTag(Tag.GetField(CurrTagIndex)));
    Inc(CurrTagIndex);

    if (not FIgnoreVersion) and (FTbsCertificate.FVersion <= 1) then
    begin
      if CurrTagIndex < Tag.Count then
        raise EElCertificateError.Create(SInvalidtbsCert);
    end;

    { Issuer Unique ID }
    if (CurrTagIndex >= Tag.Count) then
      Exit;
    if Tag.GetField(CurrTagIndex).CheckType($81, false) then
    begin
      FTBSCertificate.FIssuerUniqueID := TElASN1SimpleTag(Tag.GetField(CurrTagIndex)).Content;
      if (Length(FTBSCertificate.FIssuerUniqueID) > 0) and
        (FTBSCertificate.FIssuerUniqueID[0] = byte(0))
      then
        FTBSCertificate.FIssuerUniqueID := SBCopy(FTBSCertificate.FIssuerUniqueID, 0 + 1,
          Length(FTBSCertificate.FIssuerUniqueID) - 1);
      Inc(CurrTagIndex);
    end;

    { Subject Unique ID }
    if (CurrTagIndex >= Tag.Count) then
      Exit;
    if Tag.GetField(CurrTagIndex).CheckType($82, false) then
    begin
      FTBSCertificate.FSubjectUniqueID := TElASN1SimpleTag(Tag.GetField(CurrTagIndex)).Content;
      if (Length(FTBSCertificate.FSubjectUniqueID) > 0) and
        (FTBSCertificate.FSubjectUniqueID[0] = byte(0))
      then
        FTBSCertificate.FSubjectUniqueID := SBCopy(FTBSCertificate.FSubjectUniqueID, 0 + 1,
          Length(FTBSCertificate.FSubjectUniqueID) - 1);
      Inc(CurrTagIndex);
    end;

    { Extensions }
    if (not FIgnoreVersion) and (FTbsCertificate.FVersion <= 2) then
    begin
      if CurrTagIndex < Tag.Count then
        raise EElCertificateError.Create(SInvalidtbsCert);
    end;
    if (CurrTagIndex >= Tag.Count) then
      Exit;
    if Tag.GetField(CurrTagIndex).CheckType(SB_ASN1_A3, true) then
    begin
      if (TElASN1ConstrainedTag(Tag.GetField(CurrTagIndex)).Count = 1) and
        (TElASN1ConstrainedTag(Tag.GetField(CurrTagIndex)).GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      begin
        Reader := TElExtensionReader.Create(FCertificateExtensions, FStrictMode);
        try
          for I := 0 to TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag.GetField(CurrTagIndex)).GetField(0)).Count - 1 do
          begin
            if not TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag.GetField(CurrTagIndex)).GetField(0)).GetField(I).CheckType(SB_ASN1_SEQUENCE, true) then
              raise EElCertificateError.Create(SInvalidtbsCert);
            CurrExtTagIndex := 0;
            ExtTag := TElASN1ConstrainedTag(TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag.GetField(CurrTagIndex)).GetField(0)).GetField(I));
            if (CurrExtTagIndex < ExtTag.Count) and (ExtTag.GetField(CurrExtTagIndex).CheckType(SB_ASN1_OBJECT, false)) then
              OID := TElASN1SimpleTag(ExtTag.GetField(CurrExtTagIndex)).Content
            else
              raise EElCertificateError.Create(SInvalidtbsCert);
            Inc(CurrExtTagIndex);
            if (CurrExtTagIndex < ExtTag.Count) and (ExtTag.GetField(CurrExtTagIndex).CheckType(SB_ASN1_BOOLEAN, false)) then
            begin
              with TElASN1SimpleTag(ExtTag.GetField(CurrExtTagIndex)) do
                Critical := (Length(Content) = 1) and (Content[0] = byte($FF));

              Inc(CurrExtTagIndex);
            end
            else
              Critical := false;

            if (CurrExtTagIndex < ExtTag.Count) and (ExtTag.GetField(CurrExtTagIndex).CheckType(SB_ASN1_OCTETSTRING, false)) then
              Cnt := TElASN1SimpleTag(ExtTag.GetField(CurrExtTagIndex)).Content
            else
              raise EElCertificateError.Create(SInvalidtbsCert);
            Reader.ParseExtension(OID, Critical, Cnt);
          end;
        finally
          FreeAndNil(Reader);
        end;
      end
      else
        raise EElCertificateError.Create(SInvalidtbsCert);
    end
    else
      raise EElCertificateError.Create(SInvalidtbsCert);
    Inc(CurrTagIndex);
    if CurrTagIndex < Tag.Count then
      raise EElCertificateError.Create(SInvalidtbsCert);
  end;

  procedure ReadSignatureAlgorithmIdentifier(Tag: TElASN1ConstrainedTag);
  begin
    if Assigned(FSignatureAlgorithm) then
      FreeAndNil(FSignatureAlgorithm);
    FSignatureAlgorithm := TElAlgorithmIdentifier.CreateFromTag(Tag);
  end;

var
  MainTag: TElASN1ConstrainedTag;
  Buf: ByteArray;
  CertLen : integer;
begin
  MainTag := TElASN1ConstrainedTag.CreateInstance;
  try
    // II20120110: replaced LoadFromBuffer with LoadFromBufferSingle to make
    // certificate processing tolerant to certificate containing trash after the end
    //{$ifdef SB_VCL}
    //if not MainTag.LoadFromBuffer(FPData, FAllSize) then
    //{$else}
    //if not MainTag.LoadFromBuffer(FPData, 0, FAllSize) then
    //{$endif}
    //  raise EElCertificateError.Create(SInvalidtbsCert);
    CertLen := MainTag.LoadFromBufferSingle(FPData, FAllSize);
    if CertLen = -1 then
      raise EElCertificateError.Create(SInvalidtbsCert);
    // optionally truncating certificate buffer to skip trash at the end
    FAllSize := CertLen;
    if (MainTag.Count < 1) or (not MainTag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      raise EElCertificateError.Create(SInvalidtbsCert);
    if (TElASN1ConstrainedTag(MainTag.GetField(0)).Count <> 3) or
      (not TElASN1ConstrainedTag(MainTag.GetField(0)).GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) or
      (not TElASN1ConstrainedTag(MainTag.GetField(0)).GetField(1).CheckType(SB_ASN1_SEQUENCE, true)) or
      (not TElASN1ConstrainedTag(MainTag.GetField(0)).GetField(2).CheckType(SB_ASN1_BITSTRING, false)) then
      raise EElCertificateError.Create(SInvalidtbsCert);
    // TBSCertificate
    ReadTBSCertificate(TElASN1ConstrainedTag(TElASN1ConstrainedTag(MainTag.GetField(0)).GetField(0)));
    // SignatureAlgorithm
    ReadSignatureAlgorithmIdentifier(TElASN1ConstrainedTag(TElASN1ConstrainedTag(MainTag.GetField(0)).GetField(1)));
    // Signature
    Buf := TElASN1SimpleTag(TElASN1ConstrainedTag(MainTag.GetField(0)).GetField(2)).Content;
    if Length(Buf) > 0 then
    begin
      FSignatureValue := CloneArray(Buf, 1, Length(Buf) - 1);
    end;
    // Setting up key material value
    SetupKeyMaterial();
  finally
    FreeAndNil(MainTag);
  end;
end;


function TElX509Certificate.GetRSAParams(RSAModulus: pointer; var RSAModulusSize: integer;
  RSAPublicKey: pointer; var RSAPublicKeySize: integer): boolean;
var
  N, E : ByteArray;
begin
  Result := false;

  SetLength(N, 0);
  SetLength(E, 0);

  if Assigned(FKeyMaterial) and (FKeyMaterial is TElRSAKeyMaterial) then
  begin
    N := TElRSAKeyMaterial(FKeyMaterial).PublicModulus;
    E := TElRSAKeyMaterial(FKeyMaterial).PublicExponent;

    if (RSAModulusSize < Length(N)) or (RSAPublicKeySize < Length(E)) then
    begin
      RSAModulusSize := Length(N);
      RSAPublicKeySize := Length(E);
      Exit;
    end;

    SBMove(N[0], RSAModulus^, Length(N));
    SBMove(E[0], RSAPublicKey^, Length(E));
    RSAModulusSize := Length(N);
    RSAPublicKeySize := Length(E);

    Result := true;
  end;
end;

function TElX509Certificate.GetDSSParams(DSSP: pointer; var DSSPSize: integer;
  DSSQ: pointer;
  var DSSQSize: integer; DSSG: pointer; var DSSGSize: integer; DSSY: pointer;
  var DSSYSize: integer): boolean;
var
  P, Q, G, Y : ByteArray;
begin
  Result := false;

  SetLength(P, 0);
  SetLength(Q, 0);
  SetLength(G, 0);
  SetLength(Y, 0);

  if Assigned(FKeyMaterial) and (FKeyMaterial is TElDSAKeyMaterial) then
  begin
    P := TElDSAKeyMaterial(FKeyMaterial).P;
    Q := TElDSAKeyMaterial(FKeyMaterial).Q;
    G := TElDSAKeyMaterial(FKeyMaterial).G;
    Y := TElDSAKeyMaterial(FKeyMaterial).Y;

    if (Length(P) > DSSPSize) or (Length(Q) > DSSQSize) or (Length(G) > DSSGSize) or (Length(Y) > DSSYSize)
    then
    begin
      DSSPSize := Length(P);
      DSSQSize := Length(Q);
      DSSGSize := Length(G);
      DSSYSize := Length(Y);
      Exit;
    end
    else
    begin
      DSSPSize := Length(P);
      DSSQSize := Length(Q);
      DSSGSize := Length(G);
      DSSYSize := Length(Y);

      SBMove(P[0], DSSP^, DSSPSize);
      SBMove(Q[0], DSSQ^, DSSQSize);
      SBMove(G[0], DSSG^, DSSGSize);
      SBMove(Y[0], DSSY^, DSSYSize);

      Result := true;
    end;
  end
end;

function TElX509Certificate.GetDHParams(DHP: pointer; var DHPSize: integer; DHG:
  pointer; var DHGSize: integer; DHY: pointer; var DHYSize: integer): boolean;
var
  P, G, Y : ByteArray;
begin
  Result := false;

  SetLength(P, 0);
  SetLength(G, 0);
  SetLength(Y, 0);

  if Assigned(FKeyMaterial) and (FKeyMaterial is TElDHKeyMaterial) then
  begin
    P := TElDHKeyMaterial(FKeyMaterial).P;
    G := TElDHKeyMaterial(FKeyMaterial).G;
    Y := TElDHKeyMaterial(FKeyMaterial).Y;

    if (Length(P) > DHPSize) or (Length(G) > DHGSize) or (Length(Y) > DHYSize)
    then
    begin
      DHPSize := Length(P);
      DHGSize := Length(G);
      DHYSize := Length(Y);
      Exit;
    end
    else
    begin
      DHPSize := Length(P);
      DHGSize := Length(G);
      DHYSize := Length(Y);

      SBMove(P[0], DHP^, DHPSize);
      SBMove(G[0], DHG^, DHGSize);
      SBMove(Y[0], DHY^, DHYSize);

      Result := true;
    end;
  end;
end;


procedure TElX509Certificate.LoadFromBuffer(Buffer: Pointer; Size: integer);
var
  TmpBufSize : integer;
  TmpBuf : Pointer;
begin
  TmpBufSize := Size;


  if IsBase64UnicodeSequence( Buffer, Size ) then
  begin
    GetMem(TmpBuf, TmpBufSize);
    Base64UnicodeDecode( Buffer, Size , TmpBuf, TmpBufSize);
  end
  else
  if IsBase64Sequence( Buffer, Size ) then
  begin
    GetMem(TmpBuf, TmpBufSize);
    Base64Decode( Buffer, Size , TmpBuf, TmpBufSize);
  end
  else
  begin
    TmpBuf :=  Buffer ;
  end;

  ClearData;
  FCertificateExtensions.ClearExtensions;
  if TmpBufSize > SB_MAX_CERT_LENGTH then
  begin
    if TmpBuf <> Buffer then
      FreeMem(TmpBuf);
    raise EElX509Error.Create(SCertificateTooLong);
  end;
  if TmpBufSize > SB_CERT_BUFFER_SIZE then
  begin
    FreeMem(FPData);
    GetMem(FPData, TmpBufSize);
  end;
  SBMove(TmpBuf^, FPData^, TmpBufSize);
  FAllSize := TmpBufSize;

  if TmpBuf <> Buffer then
    FreeMem(TmpBuf);


  FErrorCode := $FF;
  ReadCertificate;
  FErrorCode := 0;
end;

procedure TElX509Certificate.LoadFromStream(Stream: TStream; Count: integer = 0);
var
  Buffer: ByteArray;
begin
  if Count = 0 then
  begin
    Count := Stream.Size - Stream.Position;
  end
  else
    Count := Min(Integer(Stream.Size - Stream.Position), Count);
  SetLength(Buffer, Count);
  try
  Stream.ReadBuffer(Buffer[0], Length(Buffer));
  LoadFromBuffer(@Buffer[0], Length(Buffer));
  finally
    ReleaseArray(Buffer);
  end;
end;

function TElX509Certificate.LoadFromStreamSPC(Stream: TStream; Count: integer = 0): integer;
var
  Buffer: ByteArray;
begin
  if Count = 0 then
  begin
    Count := Stream.Size - Stream.Position;
  end
  else
    Count := Min(Integer(Stream.Size - Stream.Position), Count);
  SetLength(Buffer, Count);
  try
    Stream.ReadBuffer(Buffer[0], Length(Buffer));
    result := LoadFromBufferSPC(@Buffer[0], Length(Buffer));
  finally
    ReleaseArray(Buffer);
  end;
end;


{$ifndef BUILDER_USED}
{$ifdef WIN32}
{$ifndef FPC}
procedure TElX509Certificate.LoadFromStream(Stream: IStream; Count: integer =
  0);
var
  Buffer: array of Byte;
  STG: tagSTATSTG;
  tmp: longint;
begin
  Stream.Stat(STG, 0);
  if Count = 0 then
  begin
    Count := STG.cbSize;
  end
  else
    Count := Min(Integer(STG.cbSize), Count);
  SetLength(Buffer, Count);
  Stream.Read(@Buffer[0], Length(Buffer), @tmp);
  LoadFromBuffer(@Buffer[0], tmp);
end;
 {$endif}
 {$endif}
 {$endif}

function TElX509Certificate.GetCertificateSelfSigned: boolean;
begin
  Result := CompareRDN(FIssuerRDN, FSubjectRDN);
  if Result then
  begin
    if (ceSubjectKeyIdentifier in FCertificateExtensions.Included) and
      (ceAuthorityKeyIdentifier in FCertificateExtensions.Included) then
    begin
      Result := CompareContent(FCertificateExtensions.SubjectKeyIdentifier.KeyIdentifier,
        FCertificateExtensions.AuthorityKeyIdentifier.KeyIdentifier);
    end;
  end;
end;

function TElX509Certificate.Validate: boolean;
var
  Crypto : TElPublicKeyCrypto;
begin
  CheckLicenseKey();
  try
    Result := false;

    if not SelfSigned then
      Exit;

    if not Assigned(FSignatureAlgorithm) then
      Exit;

    if (SignatureAlgorithmIdentifier is TElRSAPSSAlgorithmIdentifier) and
      ((PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION) or (PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSAPSS))
    then
    begin
      { RSA-PSS scheme }
      Crypto := TElRSAPublicKeyCrypto.Create(SignatureAlgorithm, FCryptoProviderManager, FCryptoProvider);
      TElRSAPublicKeyCrypto(Crypto).UseAlgorithmPrefix := true;
    end
    else if (SignatureAlgorithmIdentifier is TElRSAAlgorithmIdentifier) and
      (PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION)
    then
    begin
      { RSA signature }
      Crypto := TElRSAPublicKeyCrypto.Create(SignatureAlgorithm, FCryptoProviderManager, FCryptoProvider);
      TElRSAPublicKeyCrypto(Crypto).UseAlgorithmPrefix := true;
    end
    else if (SignatureAlgorithmIdentifier is TElDSAAlgorithmIdentifier) and
      (PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_DSA)
    then
      { DSA signature}
      Crypto := TElDSAPublicKeyCrypto.Create(SignatureAlgorithm, FCryptoProviderManager, FCryptoProvider)
    {$ifdef SB_HAS_ECC}
    else if (PublicKeyAlgorithm = SB_CERT_ALGORITHM_EC) and
     (SignatureAlgorithmIdentifier is TElECDSAAlgorithmIdentifier)
    then
      { ECDSA signature }
      Crypto := TElECDSAPublicKeyCrypto.Create(SignatureAlgorithm, FCryptoProviderManager, FCryptoProvider)
     {$endif}
    {$ifdef SB_HAS_GOST}
    else if (PublicKeyAlgorithm = SB_CERT_ALGORITHM_GOST_R3410_1994) and
      (SignatureAlgorithm = SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_1994)
    then
      { GOST R 34.10-1994 signature }
      Crypto := TElGOST94PublicKeyCrypto.Create(SignatureAlgorithm, FCryptoProviderManager, FCryptoProvider)
    {$ifdef SB_HAS_ECC}
    else if (PublicKeyAlgorithm = SB_CERT_ALGORITHM_GOST_R3410_2001) and
      (SignatureAlgorithm = SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_2001)
    then
      { GOST R 34.10-2001 signature }
      Crypto := TElGOST2001PublicKeyCrypto.Create(SignatureAlgorithm, FCryptoProviderManager, FCryptoProvider)
     {$endif}
     {$endif}
    else
      Exit;

    try
      Crypto.KeyMaterial := FKeyMaterial;
      Crypto.LoadParameters(FSignatureAlgorithm);
      Crypto.InputIsHash := false;
      Result := Crypto.VerifyDetached(@FPData[FCertificateOffset], FCertificateSize,
        @Signature[0], Length(Signature)) =   pkvrSuccess;
    finally
      FreeAndNil(Crypto);
    end;
  except
    Result := false;
  end;
end;

function TElX509Certificate.ValidateWithCA(CACertificate: TElX509Certificate): boolean;
var
  Crypto : TElPublicKeyCrypto;
begin
  Result := false;
  try
    { RSA signature }
    if FSignatureAlgorithm is TElRSAAlgorithmIdentifier then
    begin
      if CACertificate.PublicKeyAlgorithm <> SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION then
        Exit;

      Crypto := TElRSAPublicKeyCrypto.Create(SignatureAlgorithm, FCryptoProviderManager, FCryptoProvider);
    end
    { RSA-PSS signature}
    else if FSignatureAlgorithm is TElRSAPSSAlgorithmIdentifier then
    begin
      if (CACertificate.PublicKeyAlgorithm <>  SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION) and
        (CACertificate.PublicKeyAlgorithm <> SB_CERT_ALGORITHM_ID_RSAPSS)
      then
        Exit;

      Crypto := TElRSAPublicKeyCrypto.Create(SignatureAlgorithm, FCryptoProviderManager, FCryptoProvider);
    end
    { DSA signature }
    else if FSignatureAlgorithm.Algorithm = SB_CERT_ALGORITHM_ID_DSA_SHA1 then
    begin
      if not (CACertificate.PublicKeyAlgorithmIdentifier is TElDSAAlgorithmIdentifier)
      then
        Exit;

      Crypto := TElDSAPublicKeyCrypto.Create(SignatureAlgorithm, FCryptoProviderManager, FCryptoProvider);
    end
    {$ifdef SB_HAS_ECC}
    else if FSignatureAlgorithm is TElECDSAAlgorithmIdentifier then
    begin
      if (CACertificate.PublicKeyAlgorithm <> SB_CERT_ALGORITHM_EC)
      then
        Exit;

      Crypto := TElECDSAPublicKeyCrypto.Create(SignatureAlgorithm, FCryptoProviderManager, FCryptoProvider);
    end
     {$endif}
    {$ifdef SB_HAS_GOST}
    else if FSignatureAlgorithm.Algorithm = SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_1994 then
    begin
      if (CACertificate.PublicKeyAlgorithm <> SB_CERT_ALGORITHM_GOST_R3410_1994) then
        Exit;

      Crypto := TElGOST94PublicKeyCrypto.Create(SignatureAlgorithm, FCryptoProviderManager, FCryptoProvider);
    end
    {$ifdef SB_HAS_ECC}
    else if FSignatureAlgorithm.Algorithm = SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_2001 then
    begin
      if (CACertificate.PublicKeyAlgorithm <> SB_CERT_ALGORITHM_GOST_R3410_2001) then
        Exit;

      Crypto := TElGOST2001PublicKeyCrypto.Create(SignatureAlgorithm, FCryptoProviderManager, FCryptoProvider);
    end
     {$endif}
     {$endif}
    else
      Exit;

    try
      Crypto.KeyMaterial := CACertificate.KeyMaterial;
      Crypto.LoadParameters(FSignatureAlgorithm);
      Crypto.InputIsHash := false;
      Result := Crypto.VerifyDetached(@FPData[FCertificateOffset], FCertificateSize,
        @Signature[0], Length(Signature)) =   pkvrSuccess;
    finally
      FreeAndNil(Crypto);
    end;
  except
    Result := false;
  end;
end;


function TElX509Certificate.GetSignatureAlgorithm : integer;
begin
  if Assigned(FSignatureAlgorithm) then
    Result := FSignatureAlgorithm.Algorithm
  else
    Result := SB_ALGORITHM_UNKNOWN;
end;


function TElX509Certificate.SaveToBuffer(Buffer: Pointer; var Size: integer): boolean;
begin
  Result := true;
  if Size < FAllSize then
  begin
    Size := FAllSize;
    Result := false;
  end
  else
  begin
    Size := FAllSize;
    SBMove(FPData^, Buffer^, FAllSize);
  end;
end;

procedure TElX509Certificate.SaveToStream(Stream: TStream);
var
  Cert : ByteArray;
  Size : integer;
begin
  Size := 0;
  SaveToBuffer( nil , Size);
  SetLength(Cert, Size);
  SaveToBuffer( @Cert[0] , Size);
  Stream.WriteBuffer(Cert[0], Size);
end;



function TElX509Certificate.SaveKeyToBuffer(Buffer: Pointer; var Size: integer): boolean;
var
  Sz : TSBInteger;
begin
  try
    if Assigned(FKeyMaterial) then
    begin
      if  true  then
      begin
        Sz := 0;

        FKeyMaterial.StoreFormat := ksfRaw;
        FKeyMaterial.SaveSecret( nil , Sz);
        if Sz <= Size then
        begin
          FKeyMaterial.SaveSecret(Buffer, Sz);
          Result := true;
        end
        else
          Result := false;
        Size := Sz;
      end
      else
      begin
        Result := false;
      end;
    end
    else
      Result := false;
  except
    Result := false;
  end;
end;

procedure TElX509Certificate.SaveKeyToStream(Stream: TStream);
var
  Buf: ByteArray;
  Size: integer;
begin
  Size := 0;
  SetLength(Buf, Size);
  SaveKeyToBuffer(nil, Size);
  SetLength(Buf, Size);
  SaveKeyToBuffer(@Buf[0], Size);
  Stream.WriteBuffer(Buf[0], Size);
end;



procedure TElX509Certificate.LoadKeyFromBuffer(Buffer: Pointer; Size: integer);
var
  TmpBuf : Pointer;
  TmpBufSize : integer;
begin
  if not Assigned(FKeyMaterial) then
    Exit;
  FKeyMaterial.ClearSecret;
  if Size = 0 then
  begin
    exit;
  end;

  TmpBufSize := Size;


  if IsBase64UnicodeSequence( Buffer, Size ) then
  begin
    GetMem(TmpBuf, TmpBufSize);
    Base64UnicodeDecode( Buffer, Size , TmpBuf, TmpBufSize);
  end
  else
  if IsBase64Sequence( Buffer, Size ) then
  begin
    GetMem(TmpBuf, TmpBufSize);
    Base64Decode( Buffer, Size , TmpBuf, TmpBufSize);
  end
  else
  begin
    TmpBuf :=  Buffer ;
  end;

  FKeyMaterial.LoadSecret(TmpBuf, TmpBufSize);

  if TmpBuf <> Buffer then
    FreeMem(TmpBuf);
end;

procedure TElX509Certificate.LoadKeyFromStream(Stream: TStream; Count: integer = 0);
var
  P: ^Byte;
begin
  if Count = 0 then
  begin
    Count := Stream.Size - Stream.Position;
  end
  else
    Count := Min(Count, integer(Stream.Size - Stream.Position));
  if Count <= 0 then
    Exit;
  GetMem(P, Count);
  try
    Stream.ReadBuffer(P^, Count);
    LoadKeyFromBuffer(P, Count);
  finally
    FreeMem(P);
  end;
end;


procedure TElX509Certificate.AddFieldByOID(var Name: TName; const OID: ByteArray;
  Tag : byte; const Content: ByteArray);
var
  RealContent : string;
  (*
  {$ifdef SB_ANSI_VCL}
  RC : ByteArray;
  {$endif}
  {$ifdef SB_VCL}
  WS : UnicodeString;
  Len : integer;
  {$endif}*)
begin
{$ifndef SB_SKIP_PLATFORM_SPECIFIC_CODE}
  RealContent := ASN1ReadString(Content, Tag);
  (* Replaced with the call to ASN1ReadString by EM, 13/12/2013
  RealContent := StringOfBytes(Content);
  if Tag = SB_ASN1_BMPSTRING then
  begin
    {$ifdef SB_VCL}
    // decoding Unicode string
    Len := Length(Content);
    SwapBigEndianWords(@Content[0], Len);
    SetLength(WS, Len shr 1);
    SBMove(PWideChar(@Content[0])^, WS[StringStartOffset], Len);
    {$ifndef SB_UNICODE_VCL}
    ConvertUTF16ToUTF8(WS, RC, strictConversion, false{true}); // BOM changed to false by II on 20081118
    RealContent := StringOfBytes(RC);
    {$else}
    RealContent := WS;
    {$endif}
    {$else}
    {$ifndef SB_JAVA}
    RealContent := System.Text.Encoding.BigEndianUnicode.GetString(Content, 0, Length(Content));
    {$else}
    RealContent := GetStringUTF16BE(Content, 0, Length(Content));
    {$endif}
    {$endif}
  end
  else
  begin
    {$ifndef SB_VCL}
    if Tag = SB_ASN1_UTF8STRING then
      RealContent := {$ifndef SB_JAVA}System.Text.Encoding.UTF8.GetString{$else}GetStringUTF8{$endif}(Content, 0, Length(Content))
    else
      RealContent := StringOfBytes(Content);
    {$else}
    {$ifdef SB_UNICODE_VCL}
    if Tag = SB_ASN1_UTF8STRING then
      RealContent := UTF8ToStr(Content);
    {$endif}
    {$endif}
  end;
  *)
  if CompareContent(OID, SB_CERT_OID_COMMON_NAME) then
    Name.CommonName := RealContent
  else if CompareContent(OID, SB_CERT_OID_COUNTRY) then
    Name.Country := RealContent
  else if CompareContent(OID, SB_CERT_OID_LOCALITY) then
    Name.Locality := RealContent
  else if CompareContent(OID, SB_CERT_OID_STATE_OR_PROVINCE) then
    Name.StateOrProvince := RealContent
  else if CompareContent(OID, SB_CERT_OID_ORGANIZATION) then
    Name.Organization := RealContent
  else if CompareContent(OID, SB_CERT_OID_ORGANIZATION_UNIT) then
    Name.OrganizationUnit := RealContent
  else if CompareContent(OID, SB_CERT_OID_EMAIL) then
    Name.EMailAddress := RealContent;
 {$endif SB_SKIP_PLATFORM_SPECIFIC_CODE}
end;


// TODO: Verify correctness in VCL and Delphi Mobile
function TElX509Certificate.LoadFromBufferPEM(Buffer: pointer; Size: integer; const PassPhrase: string): integer;
var
  S, PEMEntity: ByteArray;

  Hd: string;
  IndStart, IndEnd, HdrSize: integer;
  Buf: ByteArray;
  Sz, Err: integer;
  KeyLoadRes: integer;
begin
  if Size <= 0 then
  begin
    Result := PEM_DECODE_RESULT_INVALID_FORMAT;
    Exit;
  end;

  SetLength(S, Size);
  SBMove(Buffer^, S[0], Size);

  IndStart := SBPos(PEM_CERTIFICATE_BEGIN_LINE, S);
  IndEnd := SBPos(PEM_CERTIFICATE_END_LINE, S);

  HdrSize := ConstLength(PEM_CERTIFICATE_END_LINE);

  if (IndStart < 0) or (IndEnd < 0) or (IndStart > IndEnd) then
  begin
    IndStart := SBPos(PEM_CERTIFICATEX509_BEGIN_LINE, S);
    IndEnd := SBPos(PEM_CERTIFICATEX509_END_LINE, S);

    HdrSize := ConstLength(PEM_CERTIFICATEX509_END_LINE);

    if (IndStart < 0) or (IndEnd < 0) or (IndStart > IndEnd) then
    begin
      Result := PEM_DECODE_RESULT_INVALID_FORMAT;
      Exit;
    end;  
  end;
  PEMEntity := SBCopy(S, IndStart, IndEnd - IndStart + HdrSize);

  Sz := Length(PEMEntity);
  SetLength(Buf, Sz);
  Err := SBPEM.Decode(@PEMEntity[0], Length(PEMEntity), @Buf[0], PassPhrase, Sz, Hd);
  Result := Err;
  if Err = PEM_DECODE_RESULT_OK then
  begin
    LoadFromBuffer(@Buf[0], Sz);
  end
  else
    Exit;

  IndStart := SBPos(PEM_RSA_PRIVATE_KEY_BEGIN_LINE, S);
  IndEnd := SBPos(PEM_RSA_PRIVATE_KEY_END_LINE, S);
  if (IndStart >= 0) and (IndEnd >= 0) and (IndStart < IndEnd) then
  begin
    PEMEntity := SBCopy(S, IndStart, IndEnd + ConstLength(PEM_RSA_PRIVATE_KEY_END_LINE));

    KeyLoadRes := LoadKeyFromBufferPEM(@PEMEntity[0], Length(PEMEntity), PassPhrase);
    if (KeyLoadRes <> 0) and (FReportErrorOnPartialLoad) then
      Result := KeyLoadRes;
    Exit;
  end;

  IndStart := SBPos(PEM_DSA_PRIVATE_KEY_BEGIN_LINE, S);
  IndEnd := SBPos(PEM_DSA_PRIVATE_KEY_END_LINE, S);
  if (IndStart >= 0) and (IndEnd >= 0) and (IndStart < IndEnd) then
  begin
    PEMEntity := SBCopy(S, IndStart, IndEnd + ConstLength(PEM_DSA_PRIVATE_KEY_END_LINE));
    KeyLoadRes := LoadKeyFromBufferPEM(@PEMEntity[0], Length(PEMEntity), PassPhrase);
    if (KeyLoadRes <> 0) and (FReportErrorOnPartialLoad) then
      Result := KeyLoadRes;
    Exit;
  end;

  IndStart := SBPos(PEM_DH_PRIVATE_KEY_BEGIN_LINE, S);
  IndEnd := SBPos(PEM_DH_PRIVATE_KEY_END_LINE, S);
  if (IndStart >= 0) and (IndEnd >= 0)and (IndStart < IndEnd)  then
  begin
    PEMEntity := SBCopy(S, IndStart, IndEnd + ConstLength(PEM_DH_PRIVATE_KEY_END_LINE));
    KeyLoadRes := LoadKeyFromBufferPEM(@PEMEntity[0], Length(PEMEntity), PassPhrase);
    if (KeyLoadRes <> 0) and (FReportErrorOnPartialLoad) then
      Result := KeyLoadRes;
    Exit;
  end;

  IndStart := SBPos(PEM_EC_PRIVATE_KEY_BEGIN_LINE, S);
  IndEnd := SBPos(PEM_EC_PRIVATE_KEY_END_LINE, S);
  if (IndStart >= 0) and (IndEnd >= 0) and (IndStart < IndEnd) then
  begin
    PEMEntity := SBCopy(S, IndStart, IndEnd + ConstLength(PEM_EC_PRIVATE_KEY_END_LINE));
    KeyLoadRes := LoadKeyFromBufferPEM(@PEMEntity[0], Length(PEMEntity), PassPhrase);
    if (KeyLoadRes <> 0) and (FReportErrorOnPartialLoad) then
      Result := KeyLoadRes;
    Exit;
  end;

  IndStart := SBPos(PEM_PRIVATE_KEY_BEGIN_LINE, S);
  IndEnd := SBPos(PEM_PRIVATE_KEY_END_LINE, S);
  if (IndStart >= 0) and (IndEnd >= 0) and (IndStart < IndEnd) then
  begin
    PEMEntity := SBCopy(S, IndStart, IndEnd + ConstLength(PEM_PRIVATE_KEY_END_LINE));
    KeyLoadRes := LoadKeyFromBufferPEM(@PEMEntity[0], Length(PEMEntity), PassPhrase);
    if (KeyLoadRes <> 0) and (FReportErrorOnPartialLoad) then
      Result := KeyLoadRes;
  end;
end;

function TElX509Certificate.LoadFromStreamPEM(Stream: TStream; const PassPhrase: string;
  Count: integer = 0): integer;
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
    Result := LoadFromBufferPEM(@Buf[0], Length(Buf), PassPhrase);
  end
  else
    Result := PEM_DECODE_RESULT_INVALID_FORMAT;
end;



function TElX509Certificate.LoadKeyFromBufferPEM(Buffer: pointer; Size: integer;
  const PassPhrase: string): integer;
var
  IndStart, IndEnd, NewSize: Integer;
  PEMEntity, Temp: ByteArray;
  Header: string;
begin
  if Size = 0 then
  begin
    result := PEM_DECODE_RESULT_NOT_ENOUGH_SPACE;
    exit;
  end;
  Result := PEM_DECODE_RESULT_INVALID_FORMAT;

  // searching for the exact PEM chunk
  PEMEntity := EmptyArray;

  SetLength(Temp, Size);
  Move(Buffer^, Temp[0], Size);

  IndStart := SBPos(BeginLineByteArray, Temp);
  IndEnd := SBPos(LFEndLineByteArray, Temp);

  if (IndStart < 0) or (IndEnd < 0) then
    Exit;

  // find the ending five dashes
  IndEnd := SBPos(FiveDashesByteArray, Temp, IndEnd + ConstLength(LFEndLineByteArray));
  if IndEnd < 0 then
    Exit;

  // copy pem entity including the beginning and ending lines
  PEMEntity := SBCopy(Temp, IndStart, IndEnd + ConstLength(FiveDashesByteArray) - IndStart);
  ReleaseArray(Temp);

  if Length(PEMEntity) = 0 then
    Exit;
  
  NewSize :=  Size ;
  SetLength(Temp, NewSize);
  Header := EmptyString;

  Result := SBPEM.Decode(@PEMEntity[0], Length(PEMEntity), @Temp[0], PassPhrase, NewSize, Header);
    
  if Result = PEM_DECODE_RESULT_OK then
  begin
    SetLength(Temp, NewSize);

    if (not Assigned(FKeyMaterial)) or (NewSize = 0) then
      Exit;

    FKeyMaterial.ClearSecret();

    try
      if FKeyMaterial is TElRSAKeyMaterial then
        TElRSAKeyMaterial(FKeyMaterial).Passphrase := Passphrase
      else
      if FKeyMaterial is TElDSAKeyMaterial then
        TElDSAKeyMaterial(FKeyMaterial).Passphrase := Passphrase;

      FKeyMaterial.LoadSecret( @Temp[0] , NewSize);
    except
      Result := PEM_DECODE_RESULT_INVALID_PASSPHRASE;
    end;

    ReleaseArray(Temp);
  end
end;

function TElX509Certificate.LoadKeyFromStreamPEM(Stream: TStream; const PassPhrase: string;
  Count: integer = 0): integer;
var
  Buf: array of byte;
begin
  if Count = 0 then
    Count := Stream.Size - Stream.Position
  else
    Count := Min(Count, integer(Stream.Size - Stream.Position));
  SetLength(Buf, Count);
  if Count > 0 then
  begin
    Stream.Read(Buf[0], Count);
    Result := LoadKeyFromBufferPEM(@Buf[0], Length(Buf), PassPhrase);
  end
  else
    Result := PEM_DECODE_RESULT_NOT_ENOUGH_SPACE;
end;



function TElX509Certificate.SaveToBufferPEM(Buffer: Pointer; var Size: integer; const PassPhrase: string): boolean;
var
  Buf: ByteArray;
  Sz: integer;
  Enc: boolean;
  OutSz: integer;
begin
  SetLength(Buf, FAllSize);
  Sz := FAllSize;
  SaveToBuffer(@Buf[0], Sz);
  Enc := PassPhrase <> '';
  OutSz := Size;
  Result := SBPEM.Encode(@Buf[0], Sz, Buffer, OutSz, 'CERTIFICATE', Enc, PassPhrase);
  Size := OutSz;
end;

procedure TElX509Certificate.SaveToStreamPEM(Stream: TStream; const PassPhrase: string);
var
  Buf: ByteArray;
  Sz: integer;
begin
  SetLength(Buf, FAllSize * 4);
  Sz := Length(Buf);
  SaveToBufferPEM(@Buf[0], Sz, PassPhrase);
  Stream.Write(Buf[0], Sz);
end;



function TElX509Certificate.SaveKeyToBufferPEM(Buffer: Pointer; var Size: integer; const PassPhrase: string): boolean;
begin
  Result := SaveKeyToBufferPEM(Buffer, Size, SB_ALGORITHM_CNT_3DES,  cmCBC , Passphrase);
end;

function TElX509Certificate.SaveKeyToBufferPEM(Buffer: Pointer; var Size: integer; EncryptionAlgorithm : integer;
  EncryptionMode :  TSBSymmetricCryptoMode ; const PassPhrase: string): boolean;
var
  Buf: ByteArray;
  Sz: integer;
  //Enc: boolean;
  OutSz: integer;
  Name: string;
begin
  Sz := 0;
  SaveKeyToBuffer(nil, Sz);
  SetLength(Buf, Sz);
  SaveKeyToBuffer(@Buf[0], Sz);
  if Sz = 0 then
  begin
    Size := 0;
    Result := false;
    Exit;
  end;
  OutSz := Size;
  if (FtbsCertificate.FSubjectPublicKeyInfo.PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION) or
    (FtbsCertificate.FSubjectPublicKeyInfo.PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSAPSS) or
    (FtbsCertificate.FSubjectPublicKeyInfo.PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSAOAEP) then
    Name := 'RSA PRIVATE KEY'
  else
    if FtbsCertificate.FSubjectPublicKeyInfo.PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_DSA then
    Name := 'DSA PRIVATE KEY'
  else
    if FtbsCertificate.FSubjectPublicKeyInfo.PublicKeyAlgorithm = SB_CERT_ALGORITHM_DH_PUBLIC then
    Name := 'DH PRIVATE KEY'
  else
    if FtbsCertificate.FSubjectPublicKeyInfo.PublicKeyAlgorithm = SB_CERT_ALGORITHM_EC then
    Name := 'EC PRIVATE KEY'
  else
    Name := 'PRIVATE KEY';

  Result := SBPEM.EncodeEx(@Buf[0], Sz, Buffer, OutSz, Name, EncryptionAlgorithm, EncryptionMode, PassPhrase);
  Size := OutSz;
end;                        

procedure TElX509Certificate.SaveKeyToStreamPEM(Stream: TStream; const PassPhrase: string);
var
  Buf: ByteArray;
  Sz: integer;
begin
  Sz := 0;
  SaveKeyToBufferPEM(nil, Sz, PassPhrase);
  SetLength(Buf, Sz);
//  Sz := Length(FPrivateKey) * 4 + 48;
  SaveKeyToBufferPEM(@Buf[0], Sz, PassPhrase);
  Stream.Write(Buf[0], Sz);
end;


procedure TElX509Certificate.SaveKeyToStreamPEM(Stream: TStream; EncryptionAlgorithm : integer;
  EncryptionMode :  TSBSymmetricCryptoMode ; const PassPhrase: string);
var
  Buf: ByteArray;
  Sz: integer;
begin
  Sz := 0;
  SaveKeyToBufferPEM(nil, Sz, EncryptionAlgorithm, EncryptionMode, PassPhrase);
  SetLength(Buf, Sz);
//  Sz := Length(FPrivateKey) * 4 + 48;
  SaveKeyToBufferPEM(@Buf[0], Sz, EncryptionAlgorithm, EncryptionMode, PassPhrase);
  Stream.Write(Buf[0], Sz);
end;


procedure TElX509Certificate.ClearData;
begin
  FIssuerName.Country := '';
  FIssuerName.StateOrProvince := '';
  FIssuerName.Locality := '';
  FIssuerName.Organization := '';
  FIssuerName.OrganizationUnit := '';
  FIssuerName.CommonName := '';
  FIssuerName.EMailAddress := '';
  FSubjectName.Country := '';
  FSubjectName.StateOrProvince := '';
  FSubjectName.Locality := '';
  FSubjectName.Organization := '';
  FSubjectName.OrganizationUnit := '';
  FSubjectName.CommonName := '';
  FSubjectName.EMailAddress := '';
  FAllSize := 0;
  FIssuerRDN.Count := 0;
  FSubjectRDN.Count := 0;
  if Assigned(FKeyMaterial) then
    FreeAndNil(FKeyMaterial);
  SetLength(FSignatureValue, 0);
end;


function TElX509Certificate.LoadFromBufferPFX(Buffer: pointer; Size: integer;
  const Password: string): integer;
var
  Msg: TElPKCS12Message;
  Buf: ByteArray;
  Sz: integer;
  Cert: TElX509Certificate;
  idx : integer;
  ChildIdx   : integer;
  Lookup     : TElCertificateLookup;
begin
  Msg := TElPKCS12Message.Create;
  Msg.Password := Password;
  Msg.CryptoProviderManager := FCryptoProviderManager;
  try
    Result := Msg.LoadFromBuffer( Buffer, Size );
    if (Result = 0) then
    begin
      if Msg.Certificates.Count > 0 then
      begin

        if Msg.Certificates.Count = 1 then
        begin
          Cert := Msg.Certificates.Certificates[0];
        end
        else
        begin
          Cert := nil;

          if Msg.Certificates.ChainCount > 0 then
          begin
            idx := Msg.Certificates.Chains[0];
            if idx > -1 then
              Cert := Msg.Certificates.Certificates[idx];
          end;

          if Cert = nil then
          begin
            for idx := 0 to Msg.Certificates.Count - 1 do
            begin
              if Msg.Certificates.Certificates[idx].PrivateKeyExists then
              begin
                Cert := Msg.Certificates.Certificates[idx];
                break;
              end;
            end;
          end;

          if Cert = nil then
          begin
            Lookup := TElCertificateLookup.Create(nil);
            try
              Lookup.Criteria :=  [lcIssuer] ;
              Lookup.Options :=  [loExactMatch, loMatchAll] ;
              for idx := 0 to Msg.Certificates.Count - 1 do
              begin
                Lookup.IssuerRDN.Assign(Msg.Certificates.Certificates[idx].SubjectRDN);

                childidx := Msg.Certificates.FindFirst(Lookup);
                if childidx = -1 then
                begin
                  Cert := Msg.Certificates.Certificates[idx];
                  result := 0;
                  break;
                end;
              end;
            finally
              FreeAndNil(Lookup);
            end;
          end;
        end;

        if Cert = nil then
          Cert := Msg.Certificates.Certificates[0];

        LoadFromBuffer(Cert.CertificateBinary , Cert.CertificateSize );
        Sz := 0;
        Cert.SaveKeyToBuffer(nil, Sz);
        if Sz > 0 then
        begin
          SetLength(Buf, Sz);
          Cert.SaveKeyToBuffer(@Buf[0], Sz);
          LoadKeyFromBuffer(@Buf[0], Sz);
        end;
      end
      else
        raise EElCertificateError.Create(SNoCertificateFound);
    end;
  finally
    FreeAndNil(Msg);
  end;
end;

function TElX509Certificate.LoadKeyFromStreamPVK(Stream: TStream; const Password: string; Count: integer = 0): integer;
var
  Buf: ByteArray;
begin
  if Count = 0 then
    Count := Stream.Size - Stream.Position
  else
    Count := Min(Count, integer(Stream.Size - Stream.Position));
  SetLength(Buf, Count);
  Stream.Read(Buf[0], Count);
  Result := LoadKeyFromBufferPVK(@Buf[0], Length(Buf), Password);
end;


function TElX509Certificate.LoadFromStreamPFX(Stream: TStream; const Password:
  string; Count: integer = 0): integer;
var
  Buf: ByteArray;
begin
  if Count = 0 then
    Count := Stream.Size - Stream.Position
  else
    Count := Min(Count, integer(Stream.Size - Stream.Position));
  SetLength(Buf, Count);
  Stream.Read(Buf[0], Count);
  Result := LoadFromBufferPFX(@Buf[0], Length(Buf), Password);
end;



function TElX509Certificate.SaveToBufferPFX(Buffer: pointer; var Size: integer;
  const Password: string; KeyEncryptionAlgorithm: integer; CertEncryptionAlgorithm:
  integer): integer;
var
  Msg: TElPKCS12Message;
begin
  FKeyMaterial.StoreFormat := ksfRaw;

  Msg := TElPKCS12Message.Create;
  Msg.Iterations := 2048;
  Msg.KeyEncryptionAlgorithm := KeyEncryptionAlgorithm;
  Msg.CertEncryptionAlgorithm := CertEncryptionAlgorithm;
  Msg.CryptoProviderManager := FCryptoProviderManager;
  Msg.Password := Password;
  try
    Msg.Certificates.Add(Self{$ifndef HAS_DEF_PARAMS}, true {$endif});
    Result := Msg.SaveToBuffer(Buffer, Size);
  finally
    FreeAndNil(Msg);
  end;
end;

function TElX509Certificate.SaveToBufferPFX(Buffer: pointer; var Size: integer;
  const Password: string): integer;
begin
  Result := SaveToBufferPFX(Buffer, Size, Password, SB_ALGORITHM_PBE_SHA1_3DES,
    SB_ALGORITHM_PBE_SHA1_RC2_40);
end;

function TElX509Certificate.SaveToStreamPFX(Stream: TStream; const Password: string;
  KeyEncryptionAlgorithm: integer; CertEncryptionAlgorithm: integer): integer;
var
  Buf: ByteArray;
  Sz: integer;
begin
  Sz := 0;
  SaveToBufferPFX(nil, Sz, Password, KeyEncryptionAlgorithm, CertEncryptionAlgorithm);
  SetLength(Buf, Sz);
  Result := SaveToBufferPFX(@Buf[0], Sz, Password, KeyEncryptionAlgorithm,
    CertEncryptionAlgorithm);
  if Result = 0 then
    Stream.Write(Buf[0], Sz);
end;


function TElX509Certificate.SaveToStreamPFX(Stream: TStream; const Password: string): integer;
begin
  Result := SaveToStreamPFX(Stream, Password, SB_ALGORITHM_PBE_SHA1_3DES,
    SB_ALGORITHM_PBE_SHA1_RC2_40); 
end;



function TElX509Certificate.SaveKeyValueToBuffer(Buffer: pointer; var Size:
  integer): boolean;
var
  KeyValue : ByteArray;
begin
  if not Assigned(FKeyMaterial) then
  begin
    Result := false;
    Exit;
  end;
  SetLength(KeyValue, 0);
  case PublicKeyAlgorithm of
    SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION:
      KeyValue := TElRSAKeyMaterial(FKeyMaterial).PrivateExponent;
    SB_CERT_ALGORITHM_ID_DSA :
      KeyValue := TElDSAKeyMaterial(FKeyMaterial).X;
    SB_CERT_ALGORITHM_DH_PUBLIC:
      KeyValue := TElDHKeyMaterial(FKeyMaterial).X;
    {$ifdef SB_HAS_ECC}
    SB_CERT_ALGORITHM_EC:
      KeyValue := TElECKeyMaterial(FKeyMaterial).D;
     {$endif}
    {$ifdef SB_HAS_GOST}
    SB_CERT_ALGORITHM_GOST_R3410_1994:
      KeyValue := ChangeByteOrder(TElGOST94KeyMaterial(FKeyMaterial).X);
    {$ifdef SB_HAS_ECC}
    SB_CERT_ALGORITHM_GOST_R3410_2001:
      KeyValue := ChangeByteOrder(TElGOST2001KeyMaterial(FKeyMaterial).D);
     {$endif}
     {$endif}  
  else
    KeyValue := EmptyArray;
  end;
  if Size >= Length(KeyValue) then
  begin
    Size := Length(KeyValue);
    SBMove(KeyValue[0], Buffer^, Size);
    Result := true;
  end
  else
  begin
    Size := Length(KeyValue);
    Result := false;
  end;
end;

function TElX509Certificate.GetHashMD5: TMessageDigest128;
begin
  Result := HashMD5(FPData , FAllSize );
end;

function TElX509Certificate.GetHashSHA1: TMessageDigest160;
begin
  Result := HashSHA1(FPData , FAllSize );
end;

function TElX509Certificate.GetValidFrom: TElDateTime;
var
  Validity: TValidity;
begin
  Validity := FtbsCertificate.Validity;
  result := Validity.NotBefore;
end;

function TElX509Certificate.GetValidTo: TElDateTime;
var
  Validity: TValidity;
begin
  Validity := FtbsCertificate.Validity;
  result := Validity.NotAfter;
end;

procedure TElX509Certificate.SetValidFrom(const Value: TElDateTime);
var
  Validity: TValidity;
begin
  Validity := FtbsCertificate.Validity;
  Validity.NotBefore := Value;
  FtbsCertificate.Validity := Validity;
end;

procedure TElX509Certificate.SetValidTo(const Value: TElDateTime);
var
  Validity: TValidity;
begin
  Validity := FtbsCertificate.Validity;
  Validity.NotAfter := Value;
  FtbsCertificate.Validity := Validity;
end;

function TElX509Certificate.GetPublicKeyAlgorithm: integer;
begin
  Result := FtbsCertificate.FSubjectPublicKeyInfo.PublicKeyAlgorithm;
end;

function TElX509Certificate.GetPublicKeyAlgorithmIdentifier: TElAlgorithmIdentifier;
begin
  Result := FTbsCertificate.FSubjectPublicKeyInfo.PublicKeyAlgorithmIdentifier;
end;

function TElX509Certificate.GetPublicKeySize: integer;
begin
  if Assigned(FKeyMaterial) then
    Result := FKeyMaterial.Bits
  else
    Result := 0;
end;

function TElX509Certificate.GetCertificateBinary : PByteArray;
begin
  result := FPData;
end;

function TElX509Certificate.GetPublicKeyBlob(Buffer: pointer; var Size: integer): boolean;
  //RealSize : integer;
  (*
  {$ifndef SB_VCL}
var
  TmpBuf : ByteArray;
  {$endif}
  *)
begin
  (*
  if Assigned(FKeyMaterial) then
  begin
    RealSize := 0;
    FKeyMaterial.SavePublic({$ifdef SB_VCL}nil{$else}TmpBuf, 0{$endif}, RealSize);
    if RealSize <= Size then
    begin
      FKeyMaterial.SavePublic(Buffer, {$ifndef SB_VCL}0, {$endif}Size);
      Result := true;
    end
    else
    begin
      Size := RealSize;
      Result := false;
    end;
  end
  else
    Result := false;
  *)
  if Length(FPublicKeyBlob) > Size then
    Result := false
  else
  begin
    SBMove(FPublicKeyBlob[0], Buffer^, Length(FPublicKeyBlob));
    Result := true;
  end;
  Size := Length(FPublicKeyBlob);
end;

procedure TElX509Certificate.GetPublicKeyBlob(out Buffer: ByteArray);
var
  Buf: ByteArray;
  Size: integer;
begin
  Size := 0;
  GetPublicKeyBlob(nil, Size);
  SetLength(Buf, Size);
  GetPublicKeyBlob(@Buf[0], Size);
  Buffer := Buf;
end;

function TElX509Certificate.GetFullPublicKeyInfo : ByteArray;
begin
  Result := CloneArray(FtbsCertificate.SubjectPublicKeyInfo.FFullData);
end;

{$ifdef SB_HAS_WINCRYPT}
function OpenSystemStoreByName(const Name: string; Access: TSBStorageAccessType): HCERTSTORE;
var
  Flag: cardinal;
  WideStr: PWideChar;
  Len: integer;
begin
  case Access of
    atCurrentService: Flag := CERT_SYSTEM_STORE_CURRENT_SERVICE;
    atCurrentUser: Flag := CERT_SYSTEM_STORE_CURRENT_USER;
    atCurrentUserGroupPolicy: Flag := CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY;
    atLocalMachine: Flag := CERT_SYSTEM_STORE_LOCAL_MACHINE;
    atLocalMachineEnterprise: Flag := CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE;
    atLocalMachineGroupPolicy: Flag := CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY;
    atServices: Flag := CERT_SYSTEM_STORE_SERVICES;
    atUsers: Flag := CERT_SYSTEM_STORE_USERS;
  else
    Flag := 0;
  end;

  Len := (Length(Name) + 1) shl 1;
  GetMem(WideStr, Len);
  try
    StringToWideChar(Name, WideStr, Len shr 1);
    Result := CertOpenStore(PAnsiChar(CERT_STORE_PROV_SYSTEM), X509_ASN_ENCODING or
      PKCS_7_ASN_ENCODING, 0, Flag, WideStr);
  finally
    FreeMem(WideStr);
  end;

  if Result = nil then
    Result := CertOpenSystemStore(0, PChar(Name));

end;

 {$endif CLX_USED}

procedure TElX509Certificate.AssignTo(Dest: TPersistent);
begin
  if Dest is TElX509Certificate then
    Clone(TElX509Certificate(Dest){$ifndef HAS_DEF_PARAMS}, true {$endif})
  else
    inherited;
end;

procedure TElX509Certificate.RaiseInvalidCertificateException;
begin
  raise EElCertificateError.Create(SInvalidCertificate);
end;

class function TElX509Certificate.DetectKeyFileFormat( Buffer : pointer ; Size : integer; const Password: string): TSBX509KeyFileFormat;
var
  Cert: TElX509Certificate;
  Loaded: boolean;
  err: integer;
begin
  Result := kffUnknown;
  Cert := TElX509Certificate.Create(nil);
  try
    Loaded := false;
    try
      // try PEM
      if not Loaded then
      try
        err := Cert.LoadKeyFromBufferPEM(Buffer, Size, Password);
        if (err <> 0) and (err <> PEM_DECODE_RESULT_INVALID_PASSPHRASE) then
          RaisePEMError(err);
        if (err = PEM_DECODE_RESULT_INVALID_PASSPHRASE) or (err = PEM_DECODE_RESULT_OK){Cert.PrivateKeyExists} then
        begin
          result := kffPEM;
          exit;
        end;
      except
      end;

      // try PVK
      if not Loaded then
      try
        err := Cert.LoadKeyFromBufferPVK(Buffer, Size, Password);
        if (err <> 0) and (err <> SB_X509_ERROR_INVALID_PASSWORD) then
          RaiseX509Error(err);
        if (err = SB_X509_ERROR_INVALID_PASSWORD) or (err = 0){Cert.PrivateKeyExists} then
        begin
          result := kffPVK;
          exit;
        end;
      except
      end;

      // try PFX
      if not Loaded then
      try
        err := Cert.LoadFromBufferPFX(Buffer, Size, Password);
        if (err <> 0) and (err <> SB_PKCS12_ERROR_INVALID_PASSWORD) then
          RaisePKCS12Error(err);
        if (err = SB_PKCS12_ERROR_INVALID_PASSWORD) or Cert.PrivateKeyExists then
        begin
          result := kffPFX;
          exit;
        end;
      except
      end;

      // try raw PKCS8
      if not Loaded then
      try
        err := Cert.LoadKeyFromBufferPKCS8(Buffer, Size, Password);
        if (err <> 0) and (err <> SB_PKCS8_ERROR_INVALID_PASSWORD) then
          RaisePKCS8Error(err);
        if (err = SB_PKCS8_ERROR_INVALID_PASSWORD) or Cert.PrivateKeyExists then
        begin
          result := kffPKCS8;
          exit;
        end;
      except
      end;

      {$ifndef B_6}
      // try PKCS8
      if not Loaded then
      try
        err := Cert.LoadKeyFromBufferNET(Buffer, Size, Password);
        if (err <> 0) and (err <> SB_PKCS8_ERROR_INVALID_PASSWORD) then
          RaisePKCS8Error(err);
        if (err = SB_PKCS8_ERROR_INVALID_PASSWORD) or Cert.PrivateKeyExists then
        begin
          result := kffNET;
          exit;
        end;
      except
      end;
       {$endif}

      // try DER
      try
        Cert.LoadKeyFromBuffer(Buffer, Size);
        //if Assigned(Cert.KeyMaterial) and (Cert.KeyMaterial.SecretKey) then
        //if Cert.PrivateKeyExists then
        begin
          result := kffDER;
          exit;
        end;
      except
      end;
    except
    end;
  finally
    FreeAndNil(Cert);
  end;
end;

class function TElX509Certificate.DetectKeyFileFormat(Stream: TElStream; const Password: string): TSBX509KeyFileFormat;
var
  TmpBuf: ByteArray;
  Size, SavePos: integer;
begin
  SavePos := Stream.Position;
  Size := Stream. Size  - Stream.Position;
  SetLength(TmpBuf, Size);
  Stream.ReadBuffer(TmpBuf[0], Size);
  Stream.Position := SavePos;
  Result := DetectKeyFileFormat( @TmpBuf[0] , Size, Password);
end;

{$ifndef SB_NO_FILESTREAM}
class function TElX509Certificate.DetectKeyFileFormat(const FileName: string; const Password: string): TSBX509KeyFileFormat;
var
  Stream: TFileStream;
begin
  Result := kffUnknown;

  try
    Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
    try
      result := DetectKeyFileFormat(Stream, Password);
    finally
      FreeAndNil(Stream);
    end;
  except
  end;
end;
 {$endif}


class function TElX509Certificate.DetectCertFileFormat( Buffer : pointer ; Size : integer): TSBCertFileFormat;
var
  Cert: TElX509Certificate;
  Loaded: boolean;
  err : integer;
begin
  Result := cfUnknown;
  Cert := TElX509Certificate.Create(nil);
  try
    Loaded := false;
    try
      // try DER
      try
        Cert.LoadFromBuffer(Buffer, Size);
        if Cert.CertificateSize > 0 then
        begin
          result := cfDER;
          exit;
        end;
      except
      end;

      (*
      // try MS BLOB
      try
        Cert.LoadFromStreamMS(Stream {$ifndef HAS_DEF_PARAMS}, 0{$endif});
        if Cert.CertificateSize > 0 then
        begin
          result := cfMSBLOB;
          exit;
        end;
      except
      end;
      *)

      // try PEM
      if not Loaded then
      try
        err := Cert.LoadFromBufferPEM(Buffer, Size, '');
        if (err <> 0) and (err <> PEM_DECODE_RESULT_INVALID_PASSPHRASE) then
          RaisePEMError(err);
        if (err = PEM_DECODE_RESULT_INVALID_PASSPHRASE) or (Cert.CertificateSize > 0) then
        begin
          result := cfPEM;
          exit;
        end;
      except
      end;

      // try PFX
      if not Loaded then
      try
        err := Cert.LoadFromBufferPFX(Buffer, Size, '');
        if (err <> 0) and (err <> SB_PKCS12_ERROR_INVALID_PASSWORD) then
          RaisePKCS12Error(err);
        if (err = SB_PKCS12_ERROR_INVALID_PASSWORD) or (Cert.CertificateSize > 0) then
        begin
          result := cfPFX;
          exit;
        end;
      except
      end;

      // try SPC
      if not Loaded then
      try
        err := Cert.LoadFromBufferSPC(Buffer, Size);
        if (err <> 0) then
          RaisePKCS7Error(err);
        if (Cert.CertificateSize > 0) then
        begin
          result := cfSPC;
          exit;
        end;
      except
      end;

    except
    end;
  finally
    FreeAndNil(Cert);
  end;
end;

class function TElX509Certificate.DetectCertFileFormat(Stream: TElStream): TSBCertFileFormat;
var
  TmpBuf : ByteArray;
  SavePos, Size: integer;
begin
  SavePos := Stream.Position;
  Size := Stream. Size  - Stream.Position;
  SetLength(TmpBuf, Size);
  Stream.ReadBuffer(TmpBuf[0], Size);
  Stream.Position := SavePos;

  Result := DetectCertFileFormat( @TmpBuf[0] , Size);
end;

{$ifndef SB_NO_FILESTREAM}
class function TElX509Certificate.DetectCertFileFormat(const FileName: string): TSBCertFileFormat;
var
  Stream: TFileStream;
begin
  Result := cfUnknown;
  try
    Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
    try
      result := DetectCertFileFormat(Stream);
    finally
      FreeAndNil(Stream);
    end;
  except
  end;
end;
 {$endif}



function TElX509Certificate.LoadFromBufferSPC(Buffer: pointer; Size: integer): integer;
var
  Msg: TElPKCS7Message;
var
  TmpBuf : Pointer;
  TmpBufSize : integer;
  ChildIdx   : integer;
  Lookup     : TElCertificateLookup;
  i          : integer;
  Hdr : string;
begin
  TmpBufSize := Size;


  if IsBase64UnicodeSequence( Buffer, Size ) then
  begin
    GetMem(TmpBuf, TmpBufSize);
    Base64UnicodeDecode( Buffer, Size , TmpBuf, TmpBufSize);
  end
  else
  if IsBase64Sequence( Buffer, Size ) then
  begin
    GetMem(TmpBuf, TmpBufSize);
    Base64Decode( Buffer, Size , TmpBuf, TmpBufSize);
  end
  else
  if IsPEMSequence( Buffer, Size ) then
  begin
    GetMem(TmpBuf, TmpBufSize);
    Result := SBPEM.Decode(Buffer,  Size,  TmpBuf, '', TmpBufSize, Hdr);
    if Result <> 0 then
    begin
      FreeMem(TmpBuf);
      Exit;
    end;
  end
  else
  begin
    TmpBuf :=  Buffer ;
  end;


  Msg := TElPKCS7Message.Create;
  try
    result := Msg.LoadFromBuffer(TmpBuf , TmpBufSize );
    if result = 0 then
      result := SB_X509_ERROR_NO_CERTIFICATE;
    if (result = SB_X509_ERROR_NO_CERTIFICATE) and (Msg.SignedData.Certificates <> nil) and (Msg.SignedData.Certificates.Count >= 1) then
    begin
      if Msg.SignedData.Certificates.Count > 1 then
      begin
        Lookup := TElCertificateLookup.Create(nil);
        try
          Lookup.Criteria :=  [lcIssuer] ;
          Lookup.Options :=  [loExactMatch, loMatchAll] ;
          for i := 0 to Msg.SignedData.Certificates.Count - 1 do
          begin
            Lookup.IssuerRDN.Assign(Msg.SignedData.Certificates.Certificates[i].SubjectRDN);

            childidx := Msg.SignedData.Certificates.FindFirst(Lookup);
            if childidx = -1 then
            begin
              Msg.SignedData.Certificates.Certificates[i].AssignTo(Self);
              result := 0;
              break;
            end;
          end;
        finally
          FreeAndNil(Lookup);
        end;
      end
      else
      begin
        Msg.SignedData.Certificates.Certificates[0].AssignTo(Self);
        result := 0;
      end;
    end;
  finally
    FreeAndNil(Msg);

    if TmpBuf <> Buffer then
      FreeMem(TmpBuf);
  end;
end;


function TElX509Certificate.LoadKeyFromBufferMS(Buffer: pointer; Size: integer): integer;
var
  OutSize, BlobType: integer;
  Buf: ByteArray;
begin
  OutSize := 0;
  ParseMSKeyBlob(Buffer, Size, nil, OutSize, BlobType);
  SetLength(Buf, OutSize);
  Result := ParseMSKeyBlob(Buffer, Size, @Buf[0], OutSize, BlobType);
  SetLength(Buf, OutSize);
  if Result = 0 then
    LoadKeyFromBuffer(@Buf[0], OutSize);
end;

function TElX509Certificate.LoadKeyFromStreamMS(Stream: TStream; Count: integer = 0): integer;
var
  Buf: ByteArray;
begin
  if Count = 0 then
    Count := Stream.Size;
  SetLength(Buf, Count);
  Stream.Read(Buf[0], Count);
  Result := LoadKeyFromBufferMS(@Buf[0], Count);
end;


function TElX509Certificate.LoadFromBufferAuto(Buffer: pointer; Size: integer; const Password: string): integer;
var
  Fmt : TSBCertFileFormat;
begin
  Result := SB_X509_ERROR_UNRECOGNIZED_FORMAT;
  Fmt := DetectCertFileFormat(Buffer,  Size );  
  if Fmt = cfDER then
    try
      LoadFromBuffer(Buffer,  Size );  
      Result := 0;
    except
      Result := SB_X509_ERROR_UNRECOGNIZED_FORMAT;
    end
  else if Fmt = cfPEM then
    Result := LoadFromBufferPEM(Buffer,  Size , Password)
  else if Fmt = cfPFX then
    Result := LoadFromBufferPFX(Buffer,  Size , Password)
  else if Fmt = cfSPC then
    Result := LoadFromBufferSPC(Buffer,  Size );
end;

function TElX509Certificate.LoadKeyFromBufferAuto(Buffer: pointer; Size: integer; const Password: string): integer;
var
  Fmt : TSBX509KeyFileFormat;
begin
  Result := SB_X509_ERROR_UNRECOGNIZED_FORMAT;
  Fmt := DetectKeyFileFormat(Buffer,  Size , Password);
  if Fmt = kffDER then
    try
      LoadKeyFromBuffer(Buffer,  Size );
      Result := 0;
    except
      Result := SB_X509_ERROR_UNRECOGNIZED_FORMAT;
    end
  else if Fmt = kffPEM then
    Result := LoadKeyFromBufferPEM(Buffer,  Size , Password)
  else if Fmt = kffPFX then
    Result := LoadFromBufferPFX(Buffer,  Size , Password)
  else if Fmt = kffPVK then
    Result := LoadKeyFromBufferPVK(Buffer,  Size , Password)
  else if Fmt = kffNET then
    Result := LoadKeyFromBufferNET(Buffer,  Size , Password)
  else if Fmt = kffPKCS8 then
    Result := LoadKeyFromBufferPKCS8(Buffer,  Size , Password);
end;

function TElX509Certificate.LoadFromStreamAuto(Stream: TStream; const Password: string; Count: integer): integer;
var
  Buf : ByteArray;
begin
  if Count = 0 then
    Count := Stream. Size  - Stream.Position
  else
    Count := Min(Count, Stream. Size  - Stream.Position);
  SetLength(Buf, Count);
  Stream.Read(Buf[0], Length(Buf));
  Result := LoadFromBufferAuto(@Buf[0], Length(Buf), Password);
end;


function TElX509Certificate.LoadKeyFromStreamAuto(Stream: TStream; const Password: string; Count: integer): integer;
var
  Buf : ByteArray;
begin
  if Count = 0 then
    Count := Stream. Size  - Stream.Position
  else
    Count := Min(Count, Stream. Size  - Stream.Position);
  SetLength(Buf, Count);
  Stream.Read(Buf[0], Length(Buf));
  Result := LoadKeyFromBufferAuto(@Buf[0], Length(Buf), Password);
end;


{$ifndef SB_NO_FILESTREAM}
function TElX509Certificate.LoadFromFileAuto(const Filename: string; const Password: string): integer;
var
  F :  TFileStream ;
begin
  F := TFileStream.Create(Filename, fmOpenRead or fmShareDenyWrite);
  try
    Result := LoadFromStreamAuto(F, Password, 0);
  finally
    FreeAndNil(F);
  end;
end;

function TElX509Certificate.LoadKeyFromFileAuto(const Filename: string; const Password: string): integer;
var
  F :  TFileStream ;
begin
  F := TFileStream.Create(Filename, fmOpenRead or fmShareDenyWrite);
  try
    Result := LoadKeyFromStreamAuto(F, Password, 0);
  finally
    FreeAndNil(F);
  end;
end;
 {$endif}


function TElX509Certificate.SaveKeyToBufferMS(Buffer: pointer; var Size: integer): integer;
var
  Buf: ByteArray;
  Sz: integer;
  B: boolean;
  OldSize: integer;
begin
  Sz := 0;
  SaveKeyToBuffer(nil, Sz);
  SetLength(Buf, Sz);
  if (not SaveKeyToBuffer(@Buf[0], Sz)) or (Sz = 0) then
    Result := SB_MSKEYBLOB_ERROR_NO_PRIVATE_KEY
  else
  begin
    OldSize := Size;
    SetLength(Buf, Sz);
    if PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION then
      B := WriteMSKeyBlob(@Buf[0], Sz, Buffer, Size, SB_KEY_BLOB_RSA)
    else
      if PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_DSA then
      B := WriteMSKeyBlob(@Buf[0], Sz, Buffer, Size, SB_KEY_BLOB_DSS)
    else
    begin
      Result := SB_MSKEYBLOB_ERROR_UNSUPPORTED_ALGORITHM;
      Exit;
    end;
    if B then
      Result := 0
    else
    begin
      if OldSize < Size then
        Result := SB_MSKEYBLOB_ERROR_BUFFER_TOO_SMALL
      else
        Result := SB_MSKEYBLOB_ERROR_INVALID_FORMAT;
    end;
  end;
end;

function TElX509Certificate.SaveKeyToStreamMS(Stream: TStream): integer;
var
  Buf: ByteArray;
  Size: integer;
begin
  Size := 0;
  SaveKeyToBufferMS( nil , Size);
  SetLength(Buf, Size);
  Result := SaveKeyToBufferMS( @Buf[0] , Size);
  if Result = 0 then
    Stream.Write(Buf[0], Size);
end;


function TElX509Certificate.SaveKeyToStreamPVK(Stream: TElStream;
  const Password: string; UseStrongEncryption: boolean {$ifdef HAS_DEF_PARAMS} =  true {$endif}): integer;
var
  Buf: ByteArray;
  Size: integer;
begin
  Size := 0;
  SaveKeyToBufferPVK( nil , Size, Password, UseStrongEncryption);
  SetLength(Buf, Size);
  Result := SaveKeyToBufferPVK( @Buf[0] ,
    Size, Password, UseStrongEncryption);
  if Result = 0 then
    Stream.WriteBuffer(Buf[0], Size);
end;



function TElX509Certificate.SaveKeyToBufferPVK(Buffer: pointer; var Size: integer;
  const Password: string; UseStrongEncryption: boolean = true): integer;
var
  Blob, MSBlob: ByteArray;
  BlobSize: integer;
  BlobType: byte;
  MSBlobSize: integer;
  Salt, Key: ByteArray;
  PVKHeader: TPVKHeader;

  function GenerateSalt: ByteArray;
  begin
    SetLength(Result, 16);
    SBRndGenerate(@Result[0], Length(Result));
  end;

  {$ifndef SB_NO_RC4}
  procedure EncryptBlob(const Key: ByteArray;
  Buffer:  pointer; Size: integer );
  var
    Context: TRC4Context;
  begin
    SBRC4.Initialize(Context, TRC4Key(Key));
    SBRC4.Encrypt(Context, Buffer, Buffer, Size);
  end;
   {$endif}

begin
  BlobSize := 0;
  SaveKeyToBuffer( nil , BlobSize);
  if (BlobSize = 0) or (not PrivateKeyExists) then
  begin
    Result := SB_X509_ERROR_NO_PRIVATE_KEY;
    Exit;
  end;
  SetLength(Blob, BlobSize);
  if not SaveKeyToBuffer( @Blob[0] , BlobSize) then
  begin
    Result := SB_X509_ERROR_NO_PRIVATE_KEY;
    Exit;
  end;
  SetLength(Blob, BlobSize);
  if PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION then
    BlobType := SB_KEY_BLOB_RSA
  else
    if PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_DSA then
    BlobType := SB_KEY_BLOB_DSS
  else
  begin
    Result := SB_X509_ERROR_UNSUPPORTED_ALGORITHM;
    Exit;
  end;

  MSBlobSize := 0;
  SBMSKeyBlob.WriteMSKeyBlob(@Blob[0], BlobSize, nil, MSBlobSize, BlobType);
  SetLength(MSBlob, MSBlobSize);
  if not SBMSKeyBlob.WriteMSKeyBlob(@Blob[0], BlobSize, @MSBlob[0], MSBlobSize,
    BlobType) then
  begin
    Result := SB_X509_ERROR_INVALID_PRIVATE_KEY;
    Exit;
  end;

  if MSBlobSize < 8 then
  begin
    Result := SB_X509_ERROR_INTERNAL_ERROR;
    Exit;
  end;

  {$ifndef SB_NO_RC4}
  if Length(Password) > 0 then
  begin
    if Size < MSBlobSize + 16 + SizeOf(TPVKHeader) then
    begin
      Result := SB_X509_ERROR_BUFFER_TOO_SMALL;
      Size := MSBlobSize + 16 + SizeOf(TPVKHeader);
      Exit;
    end;

    Salt := GenerateSalt;
    Key := PVK_DeriveKey(BytesOfString(Password), Salt, not UseStrongEncryption);
    EncryptBlob(Key, @MSBlob[8], MSBlobSize - 8);
    PVKHeader.encrypted := 1;
    PVKHeader.saltlen := 16;
  end
  else
   {$endif}
  begin
    if Size < MSBlobSize + SizeOf(TPVKHeader) then
    begin
      Result := SB_X509_ERROR_BUFFER_TOO_SMALL;
      Size := MSBlobSize + SizeOf(TPVKHeader);
      Exit;
    end;

    PVKHeader.encrypted := 0;
    PVKHeader.saltlen := 0;
  end;

  PVKHeader.magic := $B0B5F11E;
  PVKHeader.reserved := 0;
  if BlobType = SB_KEY_BLOB_RSA then
    PVKHeader.keytype := 1
  else
    PVKHeader.keytype := 2;

  PVKHeader.keylen := MSBlobSize;
  SBMove(PVKHeader, Buffer^, SizeOf(PVKHeader));
  SBMove(Salt[0], PByteArray(Buffer)[SizeOf(PVKHeader)], PVKHeader.saltlen);
  SBMove(MSBlob[0], PByteArray(Buffer)[SizeOf(PVKHeader) + PVKHeader.saltlen],
    MSBlobSize);
  Size := SizeOf(TPVKHeader) + integer(PVKHeader.saltlen) + MSBlobSize;
  Result := 0;
end;

{$ifndef SB_NO_FILESTREAM}
function TElX509Certificate.SaveToFile(const Filename: string; const Password: string;
  Format : TSBCertFileFormat): integer;
var
  F :  TFileStream ;
begin
  Result := 0;
  F := TFileStream.Create(Filename, fmCreate or fmShareDenyWrite);
  try
    case Format of
      cfDER :
        try
          SaveToStream(F);
        except
          Result := -1;
        end;
      cfPEM :
        try
          SaveToStreamPEM(F, Password);
        except
          Result := -1;
        end;
      cfPFX :
        Result := SaveToStreamPFX(F, Password);
      cfSPC :
        Result := SaveToStreamSPC(F);
      else
        Result := -1;
    end;
  finally
    FreeAndNil(F);
  end;
end;

function TElX509Certificate.SaveKeyToFile(const Filename: string; const Password: string;
  Format : TSBX509KeyFileFormat): integer;
var
  F :  TFileStream ;
begin
  Result := 0;
  F := TFileStream.Create(Filename, fmCreate or fmShareDenyWrite);
  try
    case Format of
      kffDER :
        try
          SaveKeyToStream(F);
        except
          Result := -1;
        end;
      kffPEM :
        try
          SaveKeyToStreamPEM(F, Password);
        except
          Result := -1;
        end;
      kffPFX :
        Result := SaveToStreamPFX(F, Password);
      kffPVK :
        Result := SaveKeyToStreamPVK(F, Password, true);
      kffNET :
        Result := SaveKeyToStreamNET(F, Password);
      else
        Result := -1;
    end;
  finally
    FreeAndNil(F);
  end;
end;
 {$endif}

procedure TElX509Certificate.LoadKeyFromBufferPKCS15(Buffer : pointer; Size : integer; const Password : string);
  function PRFHMACSHA1(const Pass: string; const Salt : ByteArray): ByteArray;
  var
    HashFunction : TElHashFunction;
    KM : TElHMACKeyMaterial;
  begin
    KM := TElHMACKeyMaterial.Create;
    KM.Key := BytesOfString(Pass);
    HashFunction := TElHashFunction.Create(SB_ALGORITHM_MAC_HMACSHA1, KM);
    HashFunction.Update(@Salt[0], Length(Salt));
    Result := HashFunction.Finish;

    FreeAndNil(HashFunction);
    FreeAndNil(KM);
  end;

  procedure DeriveKeyKDF2(const Pass : string; Salt: ByteArray; Iterations, Size : integer; var Key: ByteArray);
  var
    DigestSize: integer;
    Count : integer;
    I, K, J : integer;
    U, Chunk : ByteArray;
  begin
    DigestSize := 20;
    Count := (Size - 1) div DigestSize + 1;
    SetLength(Key, Count * DigestSize);
    for I := 1 to Count do
    begin
      SetLength(Chunk, DigestSize);
      FillChar(Chunk[0], DigestSize, 0);
      K := Length(Salt);

      SetLength(U, K + 4);

      SBMove(Salt[0], U[0], K);
      GetBytes32(I, U, 0 + K);
      
      for K := 0 to Iterations - 1 do
      begin
        U := PRFHMACSHA1(Pass, U);
        for J := 0 to Length(U) - 1 + 0 do
          PByte(@Chunk[J])^ := PByte(@Chunk[J])^ xor PByte(@U[J])^;
      end;
      SBMove(Chunk, 0, Key, (I - 1) * DigestSize + 0, DigestSize);
    end;
    SetLength(Key, Size);
  end;

  function DES3EDEDecrypt(const Key, IV : ByteArray; InBuf : pointer;
    InSize : integer; OutBuf : pointer; UsePadding : boolean) : integer;
  var
    KM : TElSymmetricKeyMaterial;
    Crypto : TEl3DESSymmetricCrypto;
    Sz : integer;
  begin
    KM := TElSymmetricKeyMaterial.Create;
    Crypto := TEl3DESSymmetricCrypto.Create(SB_OID_DES_EDE3_CBC);

    try
      KM.Key := Key;
      KM.IV := IV;

      Crypto.KeyMaterial := KM;
      if UsePadding then
        Crypto.Padding := cpPKCS5
      else
        Crypto.Padding := cpNone;
      Sz := InSize;
      Crypto.Decrypt(InBuf, InSize, OutBuf, Sz);
      Result := Sz;
    finally
      FreeAndNil(Crypto);
      FreeAndNil(KM);
    end;
  end;

var
  i : integer;
  sz : TSBInteger;
  cTag, subTag, keTag, ceTag, kdfTag, pwriTag : TElASN1ConstrainedTag;
  Found : boolean;
  KEK : ByteArray;
  KDF2Salt, EncryptedCEK, DecryptedCEK, KEKIV, EncSubIV, DecSubIV,
    OuterIV, CEIV, CEK, EncPrivateKey, DecPrivateKey, KeyBuf : ByteArray;
  KDF2Rounds : integer;
  N, E, P, Q : ByteArray;
  BlobLen : integer;
begin
  SetLength(EncryptedCEK, 0);
  SetLength(EncPrivateKey, 0);
  SetLength(KDF2Salt, 0);
  SetLength(KEKIV, 0);
  SetLength(CEIV, 0);
  KDF2Rounds := 0;
  {
    importing only first key, only 3DES-CBC is supported for now
  }
  if (not Assigned(FKeyMaterial)) or (not (FKeyMaterial is TElRSAKeyMaterial)) then
    raise EElX509Error.Create(SInvalidKeyMaterial);

  cTag := TElASN1ConstrainedTag.CreateInstance;
  
  try
    // II20120110: LoadFromBuffer replaced with LoadFromBufferSingle to make
    // processing tolerant to trash after the end of data
    //{$ifdef SB_VCL}
    //if not cTag.LoadFromBuffer(Buffer, Size) then
    //{$else}
    //if not cTag.LoadFromBuffer(Buffer) then
    //{$endif}
    //  raise EElX509Error.Create(SInvalidPKCS15ASN1Data);
    BlobLen := cTag.LoadFromBufferSingle(Buffer, Size);
    if BlobLen = -1 then
      raise EElX509Error.Create(SInvalidPKCS15ASN1Data);
    if (cTag.Count <> 1) or (not cTag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      raise EElX509Error.Create(SInvalidPKCS15ASN1Data);
    { root sequence node }
    subTag := TElASN1ConstrainedTag(cTag.GetField(0));
    if (subTag.Count <> 2) or (not subTag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) or
      (not CompareContent(SB_OID_PKCS15, TElASN1SimpleTag(subTag.GetField(0)).Content)) or
      (not subTag.GetField(1).CheckType(SB_ASN1_A0, true))
    then
      raise EElX509Error.Create(SInvalidPKCS15ASN1Data);
    { root->A0 }
    subTag := TElASN1ConstrainedTag(subTag.GetField(1));

    { root->A0->SEQUENCE}
    if (subTag.Count <> 1) or (not subTag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      raise EElX509Error.Create(SInvalidPKCS15ASN1Data);
    subTag := TElASN1ConstrainedTag(subTag.GetField(0));

    { root->A0->SEQUENCE->INTEGER(0) version, should be 0 }
    if (subTag.Count < 2) or (not subTag.GetField(0).CheckType(SB_ASN1_INTEGER, false)) then
      raise EElX509Error.Create(SInvalidPKCS15ASN1Data);

    if not subTag.GetField(1).CheckType(SB_ASN1_SEQUENCE, true) then
      raise EElX509Error.Create(SInvalidPKCS15ASN1Data);
    { root->A0->SEQUENCE->SEQUENCE(1) }
    subTag := TElASN1ConstrainedTag(subTag.GetField(1));

    { root->A0->SEQUENCE->SEQUENCE(1)->A0 }
    Found := false;
    for i := 0 to subTag.Count - 1 do
      if subTag.GetField(i).CheckType(SB_ASN1_A0, true) then
      begin
        subTag := TElASN1ConstrainedTag(subTag.GetField(i));
        Found := true;
        Break;
      end;
    if not Found then
      raise EElX509Error.Create(SPrivateKeyNotFound);

    { root->A0->SEQUENCE->SEQUENCE(1)->A0->A0 }
    Found := false;
    for i := 0 to subTag.Count - 1 do
      if subTag.GetField(i).CheckType(SB_ASN1_A0, true) then
      begin
        subTag := TElASN1ConstrainedTag(subTag.GetField(i));
        Found := true;
        Break;
      end;
    if not Found then
      raise EElX509Error.Create(SInvalidPKCS15ASN1Data);

    { root->A0->SEQUENCE->SEQUENCE(1)->A0->A0->SEQUENCE(0) }
    if (subTag.Count < 1) or (not subTag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      raise EElX509Error.Create(SInvalidPKCS15ASN1Data);
    subTag := TElASN1ConstrainedTag(subTag.GetField(0));

    { root->A0->SEQUENCE->SEQUENCE(1)->A0->A0->SEQUENCE(0)->A1 }
    Found := false;
    for i := 0 to subTag.Count - 1 do
      if subTag.GetField(i).CheckType(SB_ASN1_A1, true) then
      begin
        subTag := TElASN1ConstrainedTag(subTag.GetField(i));
        Found := true;
        Break;
      end;
    if not Found then
      raise EElX509Error.Create(SInvalidPKCS15ASN1Data);    

    { root->A0->SEQUENCE->SEQUENCE(1)->A0->A0->SEQUENCE(0)->A1->SEQUENCE(0) }
    if (subTag.Count < 1) or (not subTag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      raise EElX509Error.Create(SInvalidPKCS15ASN1Data);
    subTag := TElASN1ConstrainedTag(subTag.GetField(0));

    { root->A0->SEQUENCE->SEQUENCE(1)->A0->A0->SEQUENCE(0)->A1->SEQUENCE(0)->A2 }
    Found := false;
    for i := 0 to subTag.Count - 1 do
      if subTag.GetField(i).CheckType(SB_ASN1_A2, true) then
      begin
        subTag := TElASN1ConstrainedTag(subTag.GetField(i));
        Found := true;
        Break;
      end;
    if not Found then
      raise EElX509Error.Create(SInvalidPKCS15ASN1Data);    

    if (subTag.Count < 3) or (not subTag.GetField(0).CheckType(SB_ASN1_INTEGER, false))
      or (not subTag.GetField(1).CheckType(SB_ASN1_SET, true))
      or (not subTag.GetField(2).CheckType(SB_ASN1_SEQUENCE, true))
    then
      raise EElX509Error.Create(SInvalidPKCS15ASN1Data);

    keTag := TElASN1ConstrainedTag(subTag.GetField(1)); //content encryption key encryption
    ceTag := TElASN1ConstrainedTag(subTag.GetField(2)); //content encryption

    if not keTag.GetField(0).CheckType(SB_ASN1_A3, true) then
      raise EElX509Error.Create(SInvalidPKCS15ASN1Data);
    keTag := TElASN1ConstrainedTag(keTag.GetField(0));
    if keTag.Count <> 4 then
      raise EElX509Error.Create(SInvalidPKCS15ASN1Data);
    if (not keTag.GetField(0).CheckType(SB_ASN1_INTEGER, false)) or
      (not keTag.GetField(1).CheckType(SB_ASN1_A0, true)) or
      (not keTag.GetField(2).CheckType(SB_ASN1_SEQUENCE, true)) or
      (not keTag.GetField(3).CheckType(SB_ASN1_OCTETSTRING, false))
    then
      raise EElX509Error.Create(SInvalidPKCS15ASN1Data);

    kdfTag := TElASN1ConstrainedTag(keTag.GetField(1));
    pwriTag := TElASN1ConstrainedTag(keTag.GetField(2));
    EncryptedCEK := TElASN1SimpleTag(keTag.GetField(3)).Content;

    { kdf }
    if (kdfTag.Count <> 2) or (not kdfTag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) or
      (not CompareContent(TElASN1SimpleTag(kdfTag.GetField(0)).Content, SB_OID_PBKDF2)) or
      (not kdfTag.GetField(1).CheckType(SB_ASN1_SEQUENCE, true))
    then
      raise EElX509Error.Create(SInvalidPKCS15ASN1Data);
    kdfTag := TElASN1ConstrainedTag(kdfTag.GetField(1));
    if (kdfTag.Count <> 2) or (not kdfTag.GetField(0).CheckType(SB_ASN1_OCTETSTRING, false)) or
      (not kdfTag.GetField(1).CheckType(SB_ASN1_INTEGER, false))
    then
      raise EElX509Error.Create(SInvalidPKCS15ASN1Data);
    KDF2Salt := TElASN1SimpleTag(kdfTag.GetField(0)).Content;
    KDF2Rounds := ASN1ReadInteger(TElASN1SimpleTag(kdfTag.GetField(1)));

    { kek }
    if (pwriTag.Count <> 2) or (not pwriTag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) or
      (not CompareContent(TElASN1SimpleTag(pwriTag.GetField(0)).Content, SB_OID_PWRI_KEK)) or
      (not pwriTag.GetField(1).CheckType(SB_ASN1_SEQUENCE, true))
    then
      raise EElX509Error.Create(SInvalidPKCS15ASN1Data);
    pwriTag := TElASN1ConstrainedTag(pwriTag.GetField(1));
    if (pwriTag.Count <> 2) or (not pwriTag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) or
      (not CompareContent(TElASN1SimpleTag(pwriTag.GetField(0)).Content, SB_OID_DES_EDE3_CBC)) or
      (not pwriTag.GetField(1).CheckType(SB_ASN1_OCTETSTRING, false))
    then
      raise EElX509Error.Create(SInvalidPKCS15ASN1Data);
    KEKIV := TElASN1SimpleTag(pwriTag.GetField(1)).Content;

    { ce }
    if (ceTag.Count <> 3) or (not ceTag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) or
      (not CompareContent(TElASN1SimpleTag(ceTag.GetField(0)).Content, SB_OID_DATA)) or
      (not ceTag.GetField(1).CheckType(SB_ASN1_SEQUENCE, true)) or
      (not ceTag.GetField(2).CheckType(SB_ASN1_A0_PRIMITIVE, false))
    then
      raise EElX509Error.Create(SInvalidPKCS15ASN1Data);

    EncPrivateKey := TElASN1SimpleTag(ceTag.GetField(2)).Content;
    ceTag := TElASN1ConstrainedTag(ceTag.GetField(1));
    if (ceTag.Count <> 2) or (not ceTag.GetField(0).CheckType(SB_ASN1_OBJECT, false))
      or (not CompareContent(TElASN1SimpleTag(ceTag.GetField(0)).Content, SB_OID_DES_EDE3_CBC))
      or (not ceTag.GetField(1).CheckType(SB_ASN1_OCTETSTRING, false))
    then
      raise EElX509Error.Create(SInvalidPKCS15ASN1Data);

    CEIV := TElASN1SimpleTag(ceTag.GetField(1)).Content;
  finally
    FreeAndNil(cTag);
  end;  

  { 1. deriving key from password using PBKDF2}
  DeriveKeyKDF2(Password, (KDF2Salt), KDF2Rounds, 24, KEK);
  { 2. decrypting CEK key }
  SetLength(OuterIV, 8);
  SetLength(EncSubIV, 8);
  SetLength(DecSubIV, 8);
  SetLength(DecryptedCEK, Length(EncryptedCEK));

  { 1. decrypting Nth block using N-1 as IV}
  SBMove(EncryptedCEK, Length(EncryptedCEK) - 16, OuterIV, 0, 8);
  SBMove(EncryptedCEK, Length(EncryptedCEK) - 8, EncSubIV, 0, 8);
  DES3EDEDecrypt(KEK, OuterIV, @EncSubIV[0], 8, @DecSubIV[0], false);

  { 2. Using the decrypted n'th ciphertext block as the IV, decrypt the 1st ... n-1'th
    ciphertext blocks.  This strips the outer layer of encryption. }
  DES3EDEDecrypt(KEK, DecSubIV, @EncryptedCEK[0],
    Length(EncryptedCEK) - 8, @DecryptedCEK[0], false);
  SBMove(DecSubIV, 0, DecryptedCEK, Length(EncryptedCEK) - 8, 8);

  { 3. Decrypt the inner layer of encryption using the KEK. }
  DES3EDEDecrypt(KEK, KEKIV, @DecryptedCEK[0], Length(DecryptedCEK),
    @EncryptedCEK[0], false);

  if EncryptedCEK[0] <> 24 then
    raise EElX509Error.Create(SInvalidPassword);

  if ((EncryptedCEK[1] or EncryptedCEK[4]) <> $ff) or ((EncryptedCEK[2] or EncryptedCEK[5]) <> $ff)
    or ((EncryptedCEK[3] or EncryptedCEK[6]) <> $ff)
  then
    raise EElX509Error.Create(SInvalidPrivateKey);

  SetLength(CEK, 24);
  SBMove(EncryptedCEK, 4, CEK, 0, 24);

  { 4. Decrypting content }
  SetLength(DecPrivateKey, Length(EncPrivateKey));
  i := DES3EDEDecrypt(CEK, CEIV, @EncPrivateKey[0], Length(EncPrivateKey), @DecPrivateKey[0], true);
  SetLength(DecPrivateKey, i);
  { Reconstructing private key blob }

  cTag := TElASN1ConstrainedTag.CreateInstance;

  try
    if not cTag.LoadFromBuffer(@DecPrivateKey[0], Length(DecPrivateKey)) then
      raise EElX509Error.Create(SInvalidPrivateKey);

    if (cTag.Count <> 1) or (not cTag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      raise EElX509Error.Create(SInvalidPrivateKey);
    subTag := TElASN1ConstrainedTag(cTag.GetField(0));

    if (subTag.Count <> 5) or (subTag.GetField(0).IsConstrained)
      or (subTag.GetField(1).IsConstrained) or (subTag.GetField(2).IsConstrained)
      or (subTag.GetField(3).IsConstrained) or (subTag.GetField(4).IsConstrained)
    then
      raise EElX509Error.Create(SInvalidPrivateKey);

    P := TElASN1SimpleTag(subTag.GetField(0)).Content;
    Q := TElASN1SimpleTag(subTag.GetField(1)).Content;
  finally
    FreeAndNil(cTag);
  end;

  N := (TElRSAKeyMaterial(FKeyMaterial).PublicModulus);
  E := (TElRSAKeyMaterial(FKeyMaterial).PublicExponent);

  if (Length(P) = 0) or (Length(Q) = 0) then
    raise EElX509Error.Create(SInvalidPrivateKey);

  if (Length(N) = 0) or (Length(E) = 0) then
    raise EElX509Error.Create(SInvalidKeyMaterial);

  sz := 0;
  TElRSAKeyMaterial(FKeyMaterial).EncodePrivateKey(@N[0], Length(N), @E[0],
    Length(E), nil, 0, @P[0], Length(P), @Q[0], Length(Q), nil, sz);

  SetLength(KeyBuf, sz);
  TElRSAKeyMaterial(FKeyMaterial).EncodePrivateKey(@N[0], Length(N), @E[0],
    Length(E), nil, 0, @P[0], Length(P), @Q[0], Length(Q), @KeyBuf[0], sz);
  LoadKeyFromBuffer(@KeyBuf[0], sz);
  if (not PrivateKeyExists) or (not FKeyMaterial.Valid) then
    raise EElX509Error.Create(SInvalidPrivateKey);
end;

procedure TElX509Certificate.LoadKeyFromStreamPKCS15(Stream: TStream; const Password : string; Count: integer = 0);
var
  Buffer: ByteArray;
begin
  if Count = 0 then
  begin
    Count := Stream.Size - Stream.Position;
  end
  else
    Count := Min(Integer(Stream.Size - Stream.Position), Count);

  SetLength(Buffer, Count);
  try
  Stream.ReadBuffer(Buffer[0], Length(Buffer));
  LoadKeyFromBufferPKCS15(@Buffer[0], Length(Buffer), Password);
  finally
    ReleaseArray(Buffer);
  end;
end;



// PVK format as described at http://www.drh-consultancy.demon.co.uk/pvk.html
function TElX509Certificate.LoadKeyFromBufferPVK(Buffer: pointer; Size: integer;
  const Password: string): integer;
var
  PVKHeader: TPVKHeader;
  Salt: ByteArray;
  Key: ByteArray;
  {$ifndef SB_NO_RC4}
  Ctx: TRC4Context;
   {$endif}
  Ptr: ^byte;
  Blob, DecryptedBlob: ByteArray;
  BT: integer;
  PBSize: integer;

var
  TmpBuf : Pointer;
  TmpBufSize : integer;

begin
  TmpBufSize := Size;



  if IsBase64UnicodeSequence( Buffer, Size ) then
  begin
    GetMem(TmpBuf, TmpBufSize);
    Base64UnicodeDecode( Buffer, Size , TmpBuf, TmpBufSize);
  end
  else
  if IsBase64Sequence( Buffer, Size ) then
  begin
    GetMem(TmpBuf, Size);
    Base64Decode( Buffer, Size , TmpBuf, TmpBufSize);
  end
  else
  begin
    TmpBuf :=  Buffer ;
  end;


  if (TmpBuf <>  Buffer ) then
  begin
    result := LoadKeyFromBufferPVK(TmpBuf,  TmpBufSize,  Password);
    exit;
  end;

  result := SB_X509_ERROR_INVALID_PVK_FILE;
  if Size < SizeOf(TPVKHeader) then
    Exit;
  SBMove(Buffer^, PVKHeader, sizeof(PVKHeader));
  if (PVKHeader.magic <> $B0B5F11E) or
    (PVKHeader.reserved <> 0) or
    (not (PVKHeader.keytype in [1, 2])) or
    (not (PVKHeader.encrypted in [0, 1])) or
    (not (PVKHeader.saltlen in [0, $10])) then
    Exit;
  if Size <> integer(SizeOf(TPVKHeader) + PVKHeader.saltlen + PVKHeader.keylen) then
    Exit;
  SetLength(Blob, PVKHeader.keylen);
  if PVKHeader.keylen < 8 then
    Exit;

  Ptr := @PByteArray(Buffer)[SizeOf(PVKHeader) + PVKHeader.saltlen];
  Dec(Size, SizeOf(TPVKHeader) + PVKHeader.saltlen);
  SBMove(Ptr^, Blob[0], 8);
  Inc(Ptr, 8);
  Dec(Size, 8);

  {$ifndef SB_NO_RC4}
  if (PVKHeader.encrypted = 1) and (PVKHeader.saltlen = $10) then
  begin
    SetLength(Salt, 16);
    SBMove(PByteArray(Buffer)[SizeOf(PVKHeader)], Salt[0], Length(Salt));
    if Size < 4 then
      Exit;
    Key := PVK_DeriveKey(BytesOfString(Password), Salt, false);
    if not PVK_CheckKey(Key, Ptr, @Blob[8], Ctx) then
    begin
      Key := PVK_DeriveKey(BytesOfString(Password), Salt, true);
      if not PVK_CheckKey(Key, Ptr, @Blob[8], Ctx) then
      begin
        Result := SB_X509_ERROR_INVALID_PASSWORD;
        Exit;
      end;
    end;
    Inc(Ptr, 4);
    Dec(Size, 4);
    SBRC4.Decrypt(Ctx, Ptr, @Blob[12], Size);
  end
  else
   {$endif}
    SBMove(Ptr^, Blob[8], Length(Blob) - 8);
  PBSize := 0;
  SBMSKeyBlob.ParseMSKeyBlob(@Blob[0], Length(Blob), nil, PBSize, BT);
  SetLength(DecryptedBlob, PBSize);
  Result := SBMSKeyBlob.ParseMSKeyBlob(@Blob[0], Length(Blob), @DecryptedBlob[0],
    PBSize, BT);
  if Result <> 0 then
    Exit;
  LoadKeyFromBuffer(@DecryptedBlob[0], PBSize);
  if FKeyMaterial <> nil then
  begin
    if not FKeyMaterial.SecretKey then
      Result := SB_X509_ERROR_INVALID_PVK_FILE;
  end;
end;


{$ifndef B_6}
function TElX509Certificate.LoadKeyFromBufferNET(Buffer: pointer; Size: integer;
  const Password: string): integer;
 {$endif}
{$ifndef B_6}
var
  Tag, ContentTag: TElASN1ConstrainedTag;
  Key : TElPKCS8PrivateKey;
  Buf : ByteArray;
  Sz: integer;
  KeyLen : integer;
const
  PRIVATE_KEY_ID = 'private-key';
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    // II20120110: replaced LoadFromBuffer with LoadFromBufferSingle to make
    // processing tolerant to trash after the end of data
    //if not Tag.LoadFromBuffer(Buffer, Size) then
    //begin
    //  Result := SB_PKCS8_ERROR_INVALID_ASN_DATA;
    //  Exit;
    //end;
    KeyLen := Tag.LoadFromBufferSingle(Buffer, Size);
    if KeyLen = -1 then
    begin
      Result := SB_PKCS8_ERROR_INVALID_ASN_DATA;
      Exit;
    end;
    if (Tag.Count <> 1) or (Tag.GetField(0).TagID <> SB_ASN1_SEQUENCE) then
    begin
      Result := SB_PKCS8_ERROR_INVALID_FORMAT;
      Exit;
    end;  

    ContentTag := TElASN1ConstrainedTag(Tag.GetField(0));
    if (ContentTag.Count <> 2) or (ContentTag.GetField(0).IsConstrained) or
      (ContentTag.GetField(0).TagID <> SB_ASN1_OCTETSTRING) or
      (not ContentTag.GetField(1).IsConstrained) or
      (ContentTag.GetField(1).TagID <> SB_ASN1_SEQUENCE) then
    begin
      Result := SB_PKCS8_ERROR_INVALID_FORMAT;
      Exit;
    end;
    if not CompareContent(TElASN1SimpleTag(ContentTag.GetField(0)).Content, BytesOfString(PRIVATE_KEY_ID)) then
    begin
      Result := SB_PKCS8_ERROR_INVALID_FORMAT;
      Exit;
    end;
    Sz := 0;
    ContentTag.GetField(1).SaveToBuffer(nil, Sz);
    SetLength(Buf, Sz);
    ContentTag.GetField(1).SaveToBuffer(@Buf[0], Sz);
    Key := TElPKCS8PrivateKey.Create;
    try
      Result := Key.LoadFromBuffer(@Buf[0], Sz, Password);
      if Result <> 0 then
        Exit;
      LoadKeyFromBuffer(@Key.KeyMaterial[0], Length(Key.KeyMaterial));
    finally
      FreeAndNil(Key);
    end;
  finally
   FreeAndNil(Tag);
  end;
  Result := 0;
end;
 {$endif}

{$ifndef B_6}
function TElX509Certificate.LoadKeyFromStreamNET(Stream: TStream; const Password: string; Count: integer = 0): integer;
 {$endif}
{$ifndef B_6}
var
  Buf: ByteArray;
begin
  if Count = 0 then
    Count := Stream.Size;
  SetLength(Buf, Count);
  if Count > 0 then
  begin
    Stream.Read(Buf[0], Count);
    Result := LoadKeyFromBufferNET(@Buf[0], Count, Password);
  end
  else
    Result := SB_PKCS8_ERROR_INVALID_ASN_DATA;
end;
 {$endif}



function TElX509Certificate.SaveKeyToBufferNET(Buffer: pointer; var Size:
  integer): integer;
begin
  result := -1;
end;

function TElX509Certificate.SaveKeyToStreamNET(Stream: TStream; const Password:
  string): integer;
begin
  result := -1;
end;



function TElX509Certificate.SaveToBufferSPC(Buffer: pointer; var Size: integer): integer;
var
  Msg: TElPKCS7Message;
begin
  Msg := TElPKCS7Message.Create;
  try
    Msg.ContentType := ctSignedData;
    Msg.SignedData.Version := 1;
    Msg.SignedData.Certificates.Add(Self{$ifndef HAS_DEF_PARAMS}, true {$endif});
    if Msg.SaveToBuffer(Buffer, Size) then
      Result := 0
    else
      Result := SB_X509_ERROR_BUFFER_TOO_SMALL;
  finally
    FreeAndNil(Msg);
  end;
end;

function TElX509Certificate.SaveToStreamSPC(Stream: TStream): integer;
var
  Buf: ByteArray;
  Size: integer;
begin
  Size := 0;
  SaveToBufferSPC( nil , Size);
  SetLength(Buf, Size);
  Result := SaveToBufferSPC( @Buf[0] , Size);
  if Result = 0 then
    Stream.WriteBuffer(Buf[0], Size);
end;


function TElX509Certificate.LoadKeyFromBufferPKCS8(Buffer: pointer; Size: integer;
  const Password: string): integer;
var
  Key : TElPKCS8PrivateKey;
begin
  Key := TElPKCS8PrivateKey.Create;
  try
    Result := Key.LoadFromBuffer(Buffer, Size, Password);
    if Result <> 0 then
      Exit;
    LoadKeyFromBuffer(@Key.KeyMaterial[0], Length(Key.KeyMaterial));
  finally
    FreeAndNil(Key);
  end;
end;


function TElX509Certificate.LoadKeyFromStreamPKCS8(Stream: TStream; const Password: string; Count: integer = 0): integer;
var
  Key : TElPKCS8PrivateKey;
begin
  Key := TElPKCS8PrivateKey.Create;
  try
    Result := Key.LoadFromStream(Stream, Password, Count);
    if Result <> 0 then
      Exit;
    LoadKeyFromBuffer(@Key.KeyMaterial[0], Length(Key.KeyMaterial));
  finally
    FreeAndNil(Key);
  end;
end;


function TElX509Certificate.SaveKeyToBufferPKCS8(Buffer: pointer; var Size: integer; const Password: string): integer;
var
  Key : TElPKCS8PrivateKey;
  KM : ByteArray;
  Sz : integer;
begin
  Key := TElPKCS8PrivateKey.Create;
  try
    Sz := 0;
    SaveKeyToBuffer(nil, Sz);
    SetLength(KM, Sz);
    SaveKeyToBuffer(@KM[0], Sz);
    SetLength(KM, Sz);

    Key.KeyAlgorithm := PublicKeyAlgorithmIdentifier.AlgorithmOID;
    Key.KeyMaterial := KM;
    Result := Key.SaveToBuffer(Buffer, Size, Password, false);
  finally
    FreeAndNil(Key);
  end;
end;


function TElX509Certificate.SaveKeyToStreamPKCS8(Stream: TStream; const Password: string): integer;
var
  Buf: ByteArray;
  Size: integer;
begin
  Size := 0;
  SaveKeyToBufferPKCS8( nil , Size, Password);
  SetLength(Buf, Size);
  Result := SaveKeyToBufferPKCS8( @Buf[0] , Size, Password);  
  if Result = 0 then
    Stream.WriteBuffer(Buf[0], Size);
end;


function TElX509Certificate.IsKeyValid: boolean;
begin
  Result := false;
  if not PrivateKeyExists then
    Exit;
  Result := FKeyMaterial.Valid;
end;

function TElX509Certificate.GetCanEncrypt: boolean;
begin
  // TODO: (low priority) redirect to crypto
  Result := (PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION) or (PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSAOAEP);
end;

function TElX509Certificate.GetCanSign: boolean;
begin
  // TODO: (low priority) redirect to crypto
  Result := (PublicKeyAlgorithm in [SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_ID_DSA, SB_CERT_ALGORITHM_ID_RSAPSS, SB_CERT_ALGORITHM_EC]);
end;

function TElX509Certificate.GetVersion: byte;
begin
  Result := FTbsCertificate.FVersion;
end;

procedure TElX509Certificate.SetVersion(Value: byte);
begin
  FTbsCertificate.FVersion := Value;
end;

function TElX509Certificate.GetSerialNumber: ByteArray;
begin
  Result := FTbsCertificate.FSerialNumber;
end;

procedure TElX509Certificate.SetSerialNumber(const Value: ByteArray);
begin
  FTbsCertificate.FSerialNumber := CloneArray(Value);
end;

function TElX509Certificate.GetIssuer: TStringList;
begin
  Result := FTbsCertificate.FIssuer;
end;

function TElX509Certificate.GetSubject: TStringList;
begin
  Result := FTbsCertificate.FSubject;
end;

function TElX509Certificate.GetIssuerUniqueID: ByteArray;
begin
  Result := FTbsCertificate.FIssuerUniqueID;
end;

function TElX509Certificate.GetSubjectUniqueID: ByteArray;
begin
  Result := FTbsCertificate.FSubjectUniqueID;
end;

function TElX509Certificate.GetPrivateKeyExtractable : boolean;
begin
  Result := FKeyMaterial.Exportable;
end;

function TElX509Certificate.GetKeyHashSHA1: TMessageDigest160;
var
  MSize, ESize : integer;
  MBuf, EBuf : ByteArray;
  Index : integer;
begin
  if PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION then
  begin
    MSize := 0;
    GetRSAParams( nil , MSize,  nil , ESize);
    SetLength(MBuf, MSize);
    SetLength(EBuf, ESize);
    GetRSAParams(@MBuf[0], MSize, @EBuf[0], ESize);
    Index := 0;
    while (Index < MSize) and (MBuf[Index] = 0) do
      Inc(Index);
    if Index < MSize then
      Result := HashSHA1(@MBuf[Index], MSize - Index)
    else
      Result := HashSHA1(EmptyArray);
  end
  else
  begin
    Result := HashSHA1(@FTbsCertificate.FSubjectPublicKeyInfo.FRawData[0],
      Length(FTbsCertificate.FSubjectPublicKeyInfo.FRawData));
  end;
end;

function TElX509Certificate.GetZIPCertIdentifier : ByteArray;
var
  HashFunction : TElHashFunction;
  Buf : ByteArray;
begin
  Buf := GetFullPublicKeyInfo;
                      
  HashFunction := nil;
  try
    HashFunction := TElHashFunction.Create(SB_ALGORITHM_DGST_SHA1);
    HashFunction.Update(Buf);
    Result := HashFunction.Finish;
  finally
    FreeAndNil(HashFunction);
    ReleaseArray(Buf);
  end;
end;

{$ifdef SB_HAS_WINCRYPT}
procedure TElX509Certificate.ChangeSecurityLevel(Level: TSBCertSecurityLevel;
  const Password: string);
var
  AT : TSBStorageAccessType;
  SysStores :  TStringList ;
  I : integer;
  CertStore : HCERTSTORE;
  hCert : PCCERT_CONTEXT;
  M160 : TMessageDigest160;
  Blob : CRYPT_HASH_BLOB;
  Sz : DWORD;
  Buffer: pointer;
  ProvInfo: PCRYPT_KEY_PROV_INFO;
  Prov: HCRYPTPROV;
  {$ifndef SB_UNICODE_VCL}
  ProvName, ContName: PAnsiChar;
  LenProvName, LenContName: integer;
   {$endif}
  //Key: HCRYPTKEY;
  FmtPass : string;
begin
  if BelongsTo = BT_WINDOWS then
  begin
    SysStores :=  TElStringList.Create ;
    for AT := Low(TSBStorageAccessType) to High(TSBStorageAccessType) do
    begin
      SysStores.Clear;
      TElWinCertStorage.GetAvailableStores(SysStores, AT);
      for I := 0 to SysStores.Count - 1 do
      begin

        CertStore := OpenSystemStoreByName(SysStores[I], AT); //CertOpenSystemStore(0, PChar(SysStores.Strings[I]));
        if Assigned(CertStore) then
        begin
          M160 := GetHashSHA1;
          Blob.cbData := 20;
          GetMem(Blob.pbData, 20);
          SBMove(M160, Blob.pbData^, 20);
          hCert := CertFindCertificateInStore(CertStore, X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, 0, CERT_FIND_HASH, @Blob, nil);
          FreeMem(Blob.pbData);
          if Assigned(hCert) then
          begin
            CertGetCertificateContextProperty(hCert, CERT_KEY_PROV_INFO_PROP_ID, nil, @Sz);
            GetMem(Buffer, Sz);
            if CertGetCertificateContextProperty(hCert, CERT_KEY_PROV_INFO_PROP_ID, Buffer, @Sz) then
            begin
              ProvInfo := PCRYPT_KEY_PROV_INFO(Buffer);
              {$ifndef SB_UNICODE_VCL}
              LenProvName := WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszProvName, -1, nil, 0, nil, nil);
              LenContName := WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszContainerName, -1, nil, 0, nil, nil);
              GetMem(ProvName, LenProvName);
              GetMem(ContName, LenContName);
              WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszProvName, -1, ProvName, LenProvName,
                nil, nil);
              WideCharToMultiByte(CP_ACP, 0, ProvInfo.pwszContainerName, -1, ContName, LenContName,
                nil, nil);
               {$endif}
              {$ifndef SB_UNICODE_VCL}
              if CryptAcquireContext(@Prov, ContName, ProvName, ProvInfo.dwProvType, ProvInfo.dwFlags {or CRYPT_SILENT}) then
               {$else}
              if CryptAcquireContext(@Prov, ProvInfo.pwszContainerName, ProvInfo.pwszProvName,
                ProvInfo.dwProvType, ProvInfo.dwFlags {or CRYPT_SILENT}) then
               {$endif SB_UNICODE_VCL}
              begin
                FmtPass := Password + #0;
                CryptSetProvParam(Prov, {PP_KEYEXCHANGE_PIN}32, @FmtPass[StringStartOffset], 0);
                CryptSetProvParam(Prov, {PP_SIGNATURE_PIN}33, @FmtPass[StringStartOffset], 0);

                // unneeded code follows
                (*
                {$ifdef SECURE_BLACKBOX_DEBUG}
                Dumper.WriteString('Context acquired');
                {$endif}
                if CryptGetUserKey(Prov, AT_SIGNATURE, {$ifdef SB_VCL}@{$endif}Key) {$ifdef SB_NET} <> 0 {$endif} then
                begin
                  {$ifdef SECURE_BLACKBOX_DEBUG}
                  Dumper.WriteString('CryptGetUserKey [AT_SIGNATURE] succeeded');
                  {$endif}
                  try
                    Result := LoadPrivateKeyFromKey(Key);
                  finally
                    CryptDestroyKey(Key);
                  end;
                end
                else
                  if CryptGetUserKey(Prov, AT_KEYEXCHANGE, {$ifdef SB_VCL}@{$endif}Key) {$ifdef SB_NET} <> 0 {$endif} then
                  begin
                    {$ifdef SECURE_BLACKBOX_DEBUG}
                    Dumper.WriteString('CryptGetUserKey [AT_KEYEXCHANGE] succeeded');
                    {$endif}
                    try
                      Result := LoadPrivateKeyFromKey(Key);
                    finally
                      CryptDestroyKey(Key);
                    end;
                  end;
                *)
                CryptReleaseContext(Prov, 0);
              end;
              {$ifndef SB_UNICODE_VCL}
              FreeMem(ProvName);
              FreeMem(ContName);
               {$endif}
            end;
            FreeMem(Buffer);
            Break;
          end;
        end;
      end;
    end;
    FreeAndNil(SysStores);
  end;
end;
 {$endif}

procedure TElX509Certificate.SetupKeyMaterial;
var
  TmpBuf : ByteArray;
  P, G, Q, Y : ByteArray;
  Tag, ATag : TElASN1ConstrainedTag;
  CertSubj : string;
begin
  SetLength(P, 0);
  SetLength(Q, 0);
  SetLength(G, 0);
  SetLength(Y, 0);
  if Length(FtbsCertificate.FSubjectPublicKeyInfo.FRawData) > 0 then
  begin
    SetLength(TmpBuf, Length(FtbsCertificate.FSubjectPublicKeyInfo.FRawData) - 1);
    SBMove(FtbsCertificate.FSubjectPublicKeyInfo.FRawData[1], TmpBuf[0], Length(TmpBuf));
  end
  else
    Exit;

  if Assigned(FKeyMaterial) then
    FreeAndNil(FKeyMaterial);
  try
    try
      CertSubj := FSubjectRDN.SaveToDNString();
      if (FtbsCertificate.FSubjectPublicKeyInfo.PublicKeyAlgorithmIdentifier is TElRSAAlgorithmIdentifier) or
      (FtbsCertificate.FSubjectPublicKeyInfo.PublicKeyAlgorithmIdentifier is TElRSAPSSAlgorithmIdentifier) or
      (FtbsCertificate.FSubjectPublicKeyInfo.PublicKeyAlgorithmIdentifier is TElRSAOAEPAlgorithmIdentifier) then
      begin
        FKeyMaterial := TElRSAKeyMaterial.Create(FCryptoProviderManager, FCryptoProvider);
        TElRSAKeyMaterial(FKeyMaterial).RawPublicKey := true;
        FKeyMaterial.LoadParameters(FtbsCertificate.FSubjectPublicKeyInfo.PublicKeyAlgorithmIdentifier);
        TElRSAKeyMaterial(FKeyMaterial).LoadPublic(@TmpBuf[0], Length(TmpBuf));
      end
      else if FtbsCertificate.FSubjectPublicKeyInfo.PublicKeyAlgorithmIdentifier is TElDSAAlgorithmIdentifier then
      begin
        FKeyMaterial := TElDSAKeyMaterial.Create(FCryptoProviderManager, FCryptoProvider);
        FKeyMaterial.LoadParameters(FtbsCertificate.FSubjectPublicKeyInfo.PublicKeyAlgorithmIdentifier);

        Tag := TElASN1ConstrainedTag.CreateInstance;
        try
          Tag.LoadFromBuffer( @TmpBuf[0] , Length(TmpBuf));
          if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_INTEGER, false)) then
            TElDSAKeyMaterial(FKeyMaterial).Y := TElASN1SimpleTag(Tag.GetField(0)).Content
          else
          if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
          begin
            // this is not standard-compliant but some old openssls stored key in this format
            ATag := TElASN1ConstrainedTag(Tag.GetField(0));
            if (ATag.Count = 4) and ATag.GetField(0).CheckType(SB_ASN1_INTEGER, false) and ATag.GetField(1).CheckType(SB_ASN1_INTEGER, false)
              and ATag.GetField(2).CheckType(SB_ASN1_INTEGER, false) and ATag.GetField(3).CheckType(SB_ASN1_INTEGER, false)
            then
            begin
              TElDSAKeyMaterial(FKeyMaterial).P := TElASN1SimpleTag(ATag.GetField(0)).Content;
              TElDSAKeyMaterial(FKeyMaterial).Q := TElASN1SimpleTag(ATag.GetField(1)).Content;
              TElDSAKeyMaterial(FKeyMaterial).G := TElASN1SimpleTag(ATag.GetField(2)).Content;
              TElDSAKeyMaterial(FKeyMaterial).Y := TElASN1SimpleTag(ATag.GetField(3)).Content;
            end
            else
              raise EElX509Error.CreateFmt(SInvalidPublicKeyPar, [(CertSubj)]);
          end
          else
            raise EElX509Error.CreateFmt(SInvalidPublicKeyPar, [(CertSubj)]);
        finally
          FreeAndNil(Tag);
        end;
      end
      {$ifdef SB_HAS_ECC}
      else if FtbsCertificate.FSubjectPublicKeyInfo.PublicKeyAlgorithmIdentifier is TElECAlgorithmIdentifier then
      begin
        // for buggy certificates FRawData doesn't contain leading zero
        if FtbsCertificate.FSubjectPublicKeyInfo.FRawData[0] <> 0 then
          TmpBuf := FtbsCertificate.FSubjectPublicKeyInfo.FRawData;

        FKeyMaterial := TElECKeyMaterial.Create(FCryptoProviderManager, FCryptoProvider);
        FKeyMaterial.LoadParameters(FtbsCertificate.FSubjectPublicKeyInfo.PublicKeyAlgorithmIdentifier);
        TElECKeyMaterial(FKeyMaterial).LoadPublic(@TmpBuf[0], Length(TmpBuf));
      end
       {$endif}
      {$ifdef SB_HAS_GOST}
      else if PublicKeyAlgorithm = SB_CERT_ALGORITHM_GOST_R3410_1994 then
      begin
        FKeyMaterial := TElGOST94KeyMaterial.Create(FCryptoProviderManager, FCryptoProvider);
        FKeyMaterial.LoadParameters(PublicKeyAlgorithmIdentifier);

        Tag := TElASN1ConstrainedTag.CreateInstance;
        try
          Tag.LoadFromBuffer( @TmpBuf[0] , Length(TmpBuf));
          if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_OCTETSTRING, false)) then
            TElGOST94KeyMaterial(FKeyMaterial).Y := ChangeByteOrder(TElASN1SimpleTag(Tag.GetField(0)).Content)
          else
            raise EElX509Error.CreateFmt(SInvalidPublicKeyPar, [(CertSubj)]);
        finally
          FreeAndNil(Tag);
        end;
      end
      {$ifdef SB_HAS_ECC}
      else if PublicKeyAlgorithm = SB_CERT_ALGORITHM_GOST_R3410_2001 then
      begin
        FKeyMaterial := TElGOST2001KeyMaterial.Create(FCryptoProviderManager, FCryptoProvider);
        FKeyMaterial.LoadParameters(PublicKeyAlgorithmIdentifier);

        Tag := TElASN1ConstrainedTag.CreateInstance;
        try
          Tag.LoadFromBuffer( @TmpBuf[0] , Length(TmpBuf));
          if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_OCTETSTRING, false)) then
            TElGOST2001KeyMaterial(FKeyMaterial).Q := TElASN1SimpleTag(Tag.GetField(0)).Content
          else
            raise EElX509Error.CreateFmt(SInvalidPublicKeyPar, [(CertSubj)]);
        finally
          FreeAndNil(Tag);
        end;
      end
       {$endif}
       {$endif}
      else if FTbsCertificate.FSubjectPublicKeyInfo.PublicKeyAlgorithmIdentifier is TElDHAlgorithmIdentifier then
      begin
        FKeyMaterial := TElDHKeyMaterial.Create(FCryptoProviderManager, FCryptoProvider);
        FKeyMaterial.LoadParameters(FTbsCertificate.FSubjectPublicKeyInfo.PublicKeyAlgorithmIdentifier);

        Tag := TElASN1ConstrainedTag.CreateInstance;
        try
          Tag.LoadFromBuffer( @TmpBuf[0] , Length(TmpBuf));
          if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_INTEGER, false)) then
            TElDHKeyMaterial(FKeyMaterial).Y := TElASN1SimpleTag(Tag.GetField(0)).Content
          else
            raise EElX509Error.CreateFmt(SInvalidPublicKeyPar, [(CertSubj)]);
        finally
          FreeAndNil(Tag);
        end;
      end;
    except
      // the goal of this double try/except construction is to let the user
      // know the exact certificate that fails in debug time (this might be
      // useful when an exception is thrown e.g. deep inside a TElX509CertificateValidator
      // object when preloading system certificates  
      on E : Exception do
      begin
        raise EElX509Error.CreateFmt(SInvalidPublicKeyParInnEx, [(CertSubj), E. Message ]);
      end;
    end;
  except
    if Assigned(FKeyMaterial) then
      FreeAndNil(FKeyMaterial);
  end;
end;

function TElX509Certificate.GetPrivateKeyExists : boolean;
begin
  if Assigned(FKeyMaterial) then
    Result := FKeyMaterial.SecretKey
  else
    Result := false;
end;

{$ifdef SB_HAS_WINCRYPT}
function TElX509Certificate.GetCertHandle :   PCCERT_CONTEXT  ;
begin
  if Assigned(FKeyMaterial) then
    Result := FKeyMaterial.CertHandle
  else
    Result := nil;
end;

procedure TElX509Certificate.SetCertHandle(Value:   PCCERT_CONTEXT  );
begin
  if Assigned(FKeyMaterial) then
    FKeyMaterial.CertHandle := Value;
end;

function TElX509Certificate.GetFriendlyName(): string;
var
  Ctx :   PCCERT_CONTEXT  ;
  NameBuf {$ifndef SB_UNICODE_VCL}, AnsiNameBuf {$endif} : pointer;
  NameLen {$ifndef SB_UNICODE_VCL}, AnsiNameLen {$endif} : DWORD;
begin
  Result := '';
  Ctx := GetCertHandle();
  if (Ctx <> nil) then
  begin
    NameLen := 0;
    CertGetCertificateContextProperty(Ctx, CERT_FRIENDLY_NAME_PROP_ID,
        nil  ,  @ NameLen);
    GetMem(NameBuf, NameLen);
    try
      if CertGetCertificateContextProperty(Ctx, CERT_FRIENDLY_NAME_PROP_ID,
        NameBuf,  @ NameLen)  then
      begin
        {$ifndef SB_UNICODE_VCL}
        AnsiNameLen := WideCharToMultiByte(CP_ACP, 0, NameBuf, -1, nil, 0, nil, nil);
        GetMem(AnsiNameBuf, AnsiNameLen);
        try
          WideCharToMultiByte(CP_ACP, 0, NameBuf, -1, AnsiNameBuf, AnsiNameLen, nil, nil);
          Result := PChar(AnsiNameBuf);
        finally
          FreeMem(AnsiNameBuf);
        end;
         {$else}
        Result := PChar(NameBuf);
         {$endif}
      end;
    finally
      FreeMem(NameBuf);
    end;
  end;
end;

procedure TElX509Certificate.SetFriendlyName(const Value : string);
var
  Ctx :   PCCERT_CONTEXT  ;
  Blob : CRYPTOAPI_BLOB;
  I : integer;
begin
  Ctx := GetCertHandle();
  if (Ctx <> nil) then
  begin
    FillChar(Blob, SizeOf(Blob), 0);
    I := Length(Value) + 1; // string length + 1 for #0
    GetMem(Blob.pbData, I * SizeOf(WideChar));
    try
      FillChar(Blob.pbData^, I * SizeOf(WideChar), 0);
      {$ifndef SB_UNICODE_VCL}
      MultiByteToWideChar(CP_ACP, 0, PAnsiChar(Value), Length(Value), PWideChar(Blob.pbData), I);
       {$else}
      SBMove(Value[StringStartOffset], Blob.pbData, I * sizeof(WideChar));
      // StrCopy(Blob.pbData, PChar(Value));
       {$endif}
      Blob.cbData := I * SizeOf(WideChar);
      if not (CertSetCertificateContextProperty(Ctx, CERT_FRIENDLY_NAME_PROP_ID, 0,
         @Blob ) ) then
        raise EElX509Error.Create(SFailedToSetFriendlyName);
    finally
      FreeMem(Blob.pbData);
    end;
  end;
end;
 {$endif}

function TElX509Certificate.WriteSerialNumber: ByteArray;
begin
  if Length(FtbsCertificate.SerialNumber) > 0 then
    Result := WriteInteger(FtbsCertificate.SerialNumber)
  else
    Result := WriteInteger(0);
end;

function TElX509Certificate.WriteExtensionSubjectKeyIdentifier: ByteArray;
var
  Writer : TElExtensionWriter;
begin
  Writer := TElExtensionWriter.Create(FCertificateExtensions{$ifndef HAS_DEF_PARAMS}, true {$endif});
  try
    Result := Writer.WriteExtensionSubjectKeyIdentifier;
  finally
    FreeAndNil(Writer);
  end;
end;

function TElX509Certificate.WriteIssuer: ByteArray;
var
  Fields,
  OutFields,
  Tmp: array of ByteArray;
  T: integer;
  I: integer;
begin
  SetLength(Fields, 2);
  SetLength(Tmp, 1);
  SetLength(OutFields, 0);
  if FIssuerRDN.Count = 0 then
  begin
    if Length(FNewIssuer.Country) > 0 then
    begin
      Fields[0] := WriteOID(BytesOfString(#$55#$04#$06));
      if UseUTF8 then
        Fields[1] := WriteUTF8String(FNewIssuer.Country)
      else
        Fields[1] := WritePrintableString(FNewIssuer.Country);
      Tmp[0] := WriteArraySequence(Fields);
      T := Length(OutFields);
      SetLength(OutFields, T + 1);
      OutFields[T] := WriteSet(Tmp);
    end;
    if Length(FNewIssuer.StateOrProvince) > 0 then
    begin
      Fields[0] := WriteOID(BytesOfString(#$55#$04#$08));
      if UseUTF8 then
        Fields[1] := WriteUTF8String(FNewIssuer.StateOrProvince)
      else
        Fields[1] := WritePrintableString(FNewIssuer.StateOrProvince);
      Tmp[0] := WriteArraySequence(Fields);
      T := Length(OutFields);
      SetLength(OutFields, T + 1);
      OutFields[T] := WriteSet(Tmp);
    end;
    if Length(FNewIssuer.Locality) > 0 then
    begin
      Fields[0] := WriteOID(BytesOfString(#$55#$04#$07));
      if UseUTF8 then
        Fields[1] := WriteUTF8String(FNewIssuer.Locality)
      else
        Fields[1] := WritePrintableString(FNewIssuer.Locality);
      Tmp[0] := WriteArraySequence(Fields);
      T := Length(OutFields);
      SetLength(OutFields, T + 1);
      OutFields[T] := WriteSet(Tmp);
    end;
    if Length(FNewIssuer.Organization) > 0 then
    begin
      Fields[0] := WriteOID(BytesOfString(#$55#$04#$0A));
      if UseUTF8 then
        Fields[1] := WriteUTF8String(FNewIssuer.Organization)
      else
        Fields[1] := WritePrintableString(FNewIssuer.Organization);
      Tmp[0] := WriteArraySequence(Fields);
      T := Length(OutFields);
      SetLength(OutFields, T + 1);
      OutFields[T] := WriteSet(Tmp);
    end;
    if Length(FNewIssuer.OrganizationUnit) > 0 then
    begin
      Fields[0] := WriteOID(BytesOfString(#$55#$04#$0B));
      if UseUTF8 then
        Fields[1] := WriteUTF8String(FNewIssuer.OrganizationUnit)
      else
        Fields[1] := WritePrintableString(FNewIssuer.OrganizationUnit);
      Tmp[0] := WriteArraySequence(Fields);
      T := Length(OutFields);
      SetLength(OutFields, T + 1);
      OutFields[T] := WriteSet(Tmp);
    end;
    if Length(FNewIssuer.CommonName) > 0 then
    begin
      Fields[0] := WriteOID(SB_CERT_OID_COMMON_NAME);
      if UseUTF8 then
        Fields[1] := WriteUTF8String(FNewIssuer.CommonName)
      else
        Fields[1] := WritePrintableString(FNewIssuer.CommonName);
      Tmp[0] := WriteArraySequence(Fields);
      T := Length(OutFields);
      SetLength(OutFields, T + 1);
      OutFields[T] := WriteSet(Tmp);
    end;
    if Length(FNewIssuer.EMailAddress) > 0 then
    begin
      Fields[0] := WriteOID(TByteArrayConst(SB_CERT_OID_EMAIL));
      Fields[1] := WriteIA5String(FNewIssuer.EMailAddress);
      Tmp[0] := WriteArraySequence(Fields);
      T := Length(OutFields);
      SetLength(OutFields, T + 1);
      OutFields[T] := WriteSet(Tmp);
    end;
    if Length(OutFields) = 0 then
    begin
      raise EElCertificateError.Create('Issuer fields are empty');
    end;
  end
  else
  begin
    SetLength(OutFields, FIssuerRDN.Count);
    for I := 0 to FIssuerRDN.Count - 1 do
    begin
      Fields[0] := WriteOID(FIssuerRDN.OIDs[I]);
      if FIssuerRDN.Tags[I] = 0 then
      begin
        if CompareContent(SB_CERT_OID_EMAIL, FIssuerRDN.OIDs[I]) then
          Fields[1] := WriteIA5String(FIssuerRDN.Values[I])
        else if UseUTF8 then
          Fields[1] := WriteUTF8String(FIssuerRDN.Values[I])
        else
          Fields[1] := WritePrintableString(FIssuerRDN.Values[I]);
      end
      else
        Fields[1] := WritePrimitive(FIssuerRDN.Tags[I], FIssuerRDN.Values[I]);
      Tmp[0] := WriteArraySequence(Fields);
      OutFields[I] := WriteSet(Tmp);
    end;
  end;
  Result := WriteArraySequence(OutFields);
end;

function TElX509Certificate.WriteSubject: ByteArray;
var
  Fields,
    OutFields,
    Tmp: array of ByteArray;
  T: integer;
  I: integer;
begin
  SetLength(Fields, 2);
  SetLength(Tmp, 1);
  SetLength(OutFields, 0);
  if FSubjectRDN.Count = 0 then
  begin
    if Length(FNewSubject.Country) > 0 then
    begin
      Fields[0] := WriteOID(BytesOfString(#$55#$04#$06));
      if UseUTF8 then
        Fields[1] := WriteUTF8String(FNewSubject.Country)
      else
        Fields[1] := WritePrintableString(FNewSubject.Country);
      Tmp[0] := WriteArraySequence(Fields);
      T := Length(OutFields);
      SetLength(OutFields, T + 1);
      OutFields[T] := WriteSet(Tmp);
    end;
    if Length(FNewSubject.StateOrProvince) > 0 then
    begin
      Fields[0] := WriteOID(BytesOfString(#$55#$04#$08));
      if UseUTF8 then
        Fields[1] := WriteUTF8String(FNewSubject.StateOrProvince)
      else
        Fields[1] := WritePrintableString(FNewSubject.StateOrProvince);
      Tmp[0] := WriteArraySequence(Fields);
      T := Length(OutFields);
      SetLength(OutFields, T + 1);
      OutFields[T] := WriteSet(Tmp);
    end;
    if Length(FNewSubject.Locality) > 0 then
    begin
      Fields[0] := WriteOID(BytesOfString(#$55#$04#$07));
      if UseUTF8 then
        Fields[1] := WriteUTF8String(FNewSubject.Locality)
      else
        Fields[1] := WritePrintableString(FNewSubject.Locality);
      Tmp[0] := WriteArraySequence(Fields);
      T := Length(OutFields);
      SetLength(OutFields, T + 1);
      OutFields[T] := WriteSet(Tmp);
    end;
    if Length(FNewSubject.Organization) > 0 then
    begin
      Fields[0] := WriteOID(BytesOfString(#$55#$04#$0A));
      if UseUTF8 then
        Fields[1] := WriteUTF8String(FNewSubject.Organization)
      else
        Fields[1] := WritePrintableString(FNewSubject.Organization);
      Tmp[0] := WriteArraySequence(Fields);
      T := Length(OutFields);
      SetLength(OutFields, T + 1);
      OutFields[T] := WriteSet(Tmp);
    end;
    if Length(FNewSubject.OrganizationUnit) > 0 then
    begin
      Fields[0] := WriteOID(BytesOfString(#$55#$04#$0B));
      if UseUTF8 then
        Fields[1] := WriteUTF8String(FNewSubject.OrganizationUnit)
      else
        Fields[1] := WritePrintableString(FNewSubject.OrganizationUnit);
      Tmp[0] := WriteArraySequence(Fields);
      T := Length(OutFields);
      SetLength(OutFields, T + 1);
      OutFields[T] := WriteSet(Tmp);
    end;
    if Length(FNewSubject.CommonName) > 0 then
    begin
      Fields[0] := WriteOID(SB_CERT_OID_COMMON_NAME);
      if UseUTF8 then
        Fields[1] := WriteUTF8String(FNewSubject.CommonName)
      else
        Fields[1] := WritePrintableString(FNewSubject.CommonName);
      Tmp[0] := WriteArraySequence(Fields);
      T := Length(OutFields);
      SetLength(OutFields, T + 1);
      OutFields[T] := WriteSet(Tmp);
    end;
    if Length(FNewSubject.EMailAddress) > 0 then
    begin
      Fields[0] := WriteOID(SB_CERT_OID_EMAIL);
      Fields[1] := WriteIA5String(FNewSubject.EMailAddress);
      Tmp[0] := WriteArraySequence(Fields);
      T := Length(OutFields);
      SetLength(OutFields, T + 1);
      OutFields[T] := WriteSet(Tmp);
    end;
    if OutFields[0] = nil then
    begin
      raise EElCertificateError.Create('Subject fields are empty');
    end;
  end
  else
  begin
    SetLength(OutFields, FSubjectRDN.Count);
    for I := 0 to FSubjectRDN.Count - 1 do
    begin
      Fields[0] := WriteOID(FSubjectRDN.OIDs[I]);
      if FSubjectRDN.Tags[I] = 0 then
      begin
        if CompareContent(FSubjectRDN.OIDs[I], SB_CERT_OID_EMAIL) then
          Fields[1] := WriteIA5String(FSubjectRDN.Values[I])
        else if UseUTF8 then
          Fields[1] := WriteUTF8String(FSubjectRDN.Values[I])
        else
          Fields[1] := WritePrintableString(FSubjectRDN.Values[I]);
      end
      else
        Fields[1] := WritePrimitive(FSubjectRDN.Tags[I], FSubjectRDN.Values[I]);

      Tmp[0] := WriteArraySequence(Fields);
      OutFields[I] := WriteSet(Tmp);
    end;
  end;
  Result := WriteArraySequence(OutFields);
end;

procedure TElX509Certificate.SetKeyMaterial(Value : TElPublicKeyMaterial);
var
  AlgID : TElECAlgorithmIdentifier;
begin
  if Assigned(FKeyMaterial) then
    FreeAndNil(FKeyMaterial);
  FKeyMaterial := TElPublicKeyMaterial(Value.Clone());
  if FKeyMaterial is TElRSAKeyMaterial then
    TElRSAKeyMaterial(FKeyMaterial).RawPublicKey := true;
  FtbsCertificate.SubjectPublicKeyInfo.FRawData := EmptyArray;
  FtbsCertificate.SubjectPublicKeyInfo.FAlgorithm := TElAlgorithmIdentifier.CreateByAlgorithm(FKeyMaterial.Algorithm);
  if FKeyMaterial is TElECKeyMaterial then
  begin
    AlgID := TElECAlgorithmIdentifier.Create();
    try
      TElECKeyMaterial(FKeyMaterial).SaveParameters(AlgID);
      FtbsCertificate.SubjectPublicKeyInfo.FAlgorithm.Assign(AlgID);
    finally
      FreeAndNil(AlgID);
    end;
  end;
end;



{$ifdef SB_HAS_WINCRYPT}
{$ifdef SB_HAS_CRYPTUI}
function TElX509Certificate.View(Owner : HWND) : boolean;
var
  Store : TElWinCertStorage;
  Cert : TElX509Certificate;
  pCertViewInfo : CRYPTUI_VIEWCERTIFICATE_STRUCT;
  Changed : BOOL;
begin
  Result := false;
  Store := nil;
  Cert := Self;
  
  if Cert.CertHandle =  nil  then
  begin
    try
      Store := TElWinCertStorage.Create (nil) ;
      Store.StorageType := stMemory;
      Store.Add(Self, true);
      Cert := Store.Certificates[0];
    except
      Exit;
    end;
  end;

  try
      pCertViewInfo.dwSize :=  SizeOf (pCertViewInfo);
      pCertViewInfo.hwndParent := Owner;
      pCertViewInfo.dwFlags := 0;
      pCertViewInfo.szTitle := nil;
      pCertViewInfo.pCertContext := Cert.CertHandle;
      pCertViewInfo.cPurposes := 0;
      pCertViewInfo.Union :=   nil  ;
      pCertViewInfo.fpCryptProviderDataTrustedUsage :=  false ;
      pCertViewInfo.idxSigner := 0;
      pCertViewInfo.idxCert := 0;
      pCertViewInfo.fCounterSigner :=  false ;
      pCertViewInfo.idxCounterSigner := 0;
      pCertViewInfo.cStores := 0;
      pCertViewInfo.rgszPurposes :=  nil ;
      pCertViewInfo.rghStores :=  nil ;
      pCertViewInfo.cPropSheetPages := 0;
      pCertViewInfo.rgPropSheetPages :=  nil ;
      pCertViewInfo.nStartPage := 0;

      Result := CryptUIDlgViewCertificate( @ pCertViewInfo,  @ Changed);
  finally
    if Assigned(Store) then
      FreeAndNil(Store);
  end;
end;
 {$endif}
 {$endif}

////////////////////////////////////////////////////////////////////////////////
// TElSubjectPublicKeyInfo class

constructor TElSubjectPublicKeyInfo.Create;
begin
  inherited;

  FAlgorithm := nil;
end;

 destructor  TElSubjectPublicKeyInfo.Destroy;
begin
  if Assigned(FAlgorithm) then
    FreeAndNil(FAlgorithm);

  inherited;
end;

function TElSubjectPublicKeyInfo.GetPublicKeyAlgorithmIdentifier : TElAlgorithmIdentifier;
begin
  Result := FAlgorithm;
end;

function TElSubjectPublicKeyInfo.GetPublicKeyAlgorithm: integer;
begin
  if Assigned(FAlgorithm) then
    Result := FAlgorithm.Algorithm
  else
    Result := SB_ALGORITHM_UNKNOWN;
end;

function TElSubjectPublicKeyInfo.GetRawData : ByteArray;
begin
  Result := FRawData;
end;

procedure TElSubjectPublicKeyInfo.Clear;
begin
  if Assigned(FAlgorithm) then
    FreeAndNil(FAlgorithm);
end;

////////////////////////////////////////////////////////////////////////////////
// TElTBSCertificate class

constructor TElTBSCertificate.Create;
begin
  inherited;
  FIssuer := TElStringList.Create;
  FSubject := TElStringList.Create;
  FSubjectPublicKeyInfo := TElSubjectPublicKeyInfo.Create;
  FSignatureIdentifier := nil;
  FVersion := 3;
end;

 destructor  TElTBSCertificate.Destroy;
begin
  FreeAndNil(FIssuer);
  FreeAndNil(FSubject);
  FreeAndNil(FSubjectPublicKeyInfo);
  if Assigned(FSignatureIdentifier) then
    FreeAndNil(FSignatureIdentifier);
  inherited;
end;

procedure TElTBSCertificate.Clear;
begin
  FIssuer.Clear;
  FSubject.Clear;
  FVersion := 3;
  SetLength(FSerialNumber, 0);
  if Assigned(FSignatureIdentifier) then
    FreeAndNil(FSignatureIdentifier);

  FSubjectPublicKeyInfo.Clear;
  SetLength(FIssuerUniqueID, 0);
  SetLength(FSubjectUniqueID, 0);
end;

procedure TElTBSCertificate.SetSerialNumber(const V: ByteArray);
begin
  FSerialNumber := CloneArray(V);
end;

procedure TElTBSCertificate.SetIssuerUniqueID(const V: ByteArray);
begin
  FIssuerUniqueID := CloneArray(V);
end;

procedure TElTBSCertificate.SetSubjectUniqueID(const V: ByteArray);
begin
  FSubjectUniqueID := CloneArray(V);
end;

////////////////////////////////////////////////////////////////////////////////
// TElX509CertificateChain class

constructor TElX509CertificateChain.Create(Owner: TSBComponentBase);
begin
  inherited Create (Owner) ;
  FCertificates := TElList.Create;
end;


 destructor  TElX509CertificateChain.Destroy;
var
  Cert: TElX509Certificate;
begin
  while FCertificates.Count > 0 do
  begin
    Cert := TElX509Certificate(FCertificates[FCertificates.Count - 1]);
    FreeAndNil(Cert);
    FCertificates.Delete(FCertificates.Count - 1);
  end;
  FreeAndNil(FCertificates);
  inherited;
end;

function TElX509CertificateChain.GetCertificate(Index : integer):
    TElX509Certificate;
begin
  Result := TElX509Certificate(FCertificates[Index]);
end;


function TElX509CertificateChain.Add(Certificate : TElX509Certificate) : boolean;
var Cert : TElX509Certificate;
begin
  result := false;
  if Certificate = nil then exit;
  // ensure that the parent certificate is added.
  if FCertificates.Count > 0 then
  begin
    Cert := TElX509Certificate(FCertificates[FCertificates.Count - 1]);
    result := CompareRDN(Cert.IssuerRDN, Certificate.SubjectRDN);
    if not result then
      exit;
  end;              
  DoAdd(Certificate);
  result := true;
end;

procedure TElX509CertificateChain.DoAdd(Certificate : TElX509Certificate);
var
  NewCert : TElX509Certificate;
begin
    NewCert := TElX509Certificate.Create(nil);
    Certificate.Clone(NewCert, true);
    NewCert.FChain := Self;
    FCertificates.Add(NewCert);
end;

function TElX509CertificateChain.GetComplete: Boolean;
begin
  Result := (Count > 0) and (Certificates[Count-1].SelfSigned);
end;

function TElX509CertificateChain.GetCount: Integer;
begin
  Result := FCertificates.Count;
end;


function TElX509CertificateChain.Validate(var Reason: TSBCertificateValidityReason;
  ValidityMoment:  TElDateTime = 0 ) : TSBCertificateValidity;
begin
  result := Validate(Reason, false, ValidityMoment);
end;


function TElX509CertificateChain.Validate(var Reason: TSBCertificateValidityReason;
  CheckCACertDates : boolean;
  ValidityMoment:  TElDateTime = 0 ) : TSBCertificateValidity;
var i : integer;
    Cert,
    CACert : TElX509Certificate;
    vm: double;
begin
  Result :=  cvOk ;
  Reason :=   [vrUnknownCA] ;

  vm := ValidityMoment;
  if ValidityMoment = 0.0 then
  {$ifdef SB_WINDOWS}
    vm := LocalTimeToUTCTime(now);
   {$else}
    vm := now;
   {$endif}

  for i := 0 to FCertificates.Count - 1 do
  begin
    Cert := TElX509Certificate(FCertificates[i]);

    if CheckCACertDates or (i = 0) then
    begin
      {$ifndef SB_NO_NET_DATETIME_OADATE}
      if (Cert.ValidFrom > vm) then
       {$else}
      if (DateTimeToOADate(Cert.ValidFrom) > vm) then
       {$endif}
      begin
        Reason := Reason  + [vrNotYetValid] ;
        Result :=  cvInvalid ;
      end;
      {$ifndef SB_NO_NET_DATETIME_OADATE}
      if (Cert.ValidTo < vm) then
       {$else}
      if (DateTimeToOADate(Cert.ValidTo) < vm) then
       {$endif}
      begin
        Reason := Reason  + [vrExpired] ;
        Result :=  cvInvalid ;
      end;
    end;

    if Result =  cvInvalid  then
    begin
      Reason := Reason  - [vrUnknownCA] ;
      exit;
    end;

    if (i < FCertificates.Count - 1) then
    begin
      CACert := TElX509Certificate(FCertificates[i + 1]);

      if (Cert.ValidateWithCA(CACert)) then
      begin
        Reason := Reason  - [vrInvalidSignature] ;
        Reason := Reason  - [vrUnknownCA] ;
        Result :=  cvOk ;
      end
      else
      begin
        Reason := Reason  + [vrInvalidSignature] ;
        Reason := Reason  - [vrUnknownCA] ;
        Result :=  cvInvalid ;
        Exit;
      end;
    end
    else
    begin
      if Cert.SelfSigned then
      begin
        if Result <>  cvInvalid  then
          Result :=  cvSelfSigned ;
        Reason := Reason  - [vrUnknownCA] ;
        if not Cert.Validate then
        begin
          Result :=  cvInvalid ;
          Reason := Reason  + [vrInvalidSignature] ;
        end;
      end;
    end;
  end;
end;


procedure TElBaseCertStorage.AddToChain(Chain : TElX509CertificateChain;
    Certificate : TElX509Certificate);
begin
  Chain.DoAdd(Certificate);
end;

////////////////////////////////////////////////////////////////////////////////
// Other stuff

function SerialNumberCorresponds(Cert : TElX509Certificate; const Serial : ByteArray): boolean;
begin
  if Cert.NegativeSerial and NegativeSerialWorkaround then
    Result := CompareContent(Cert.SerialNumber, SBConcatArrays(byte(0), Serial))
  else
    Result := CompareContent(Cert.SerialNumber, Serial);
end;

function GetOriginalSerialNumber(Cert : TElX509Certificate): ByteArray;
begin
  Result := CloneArray(Cert.SerialNumber);
  if Cert.NegativeSerial and NegativeSerialWorkaround then
    Result := Copy(Result, 2, Length(Result) - 1);
end;


initialization
  begin


  end;

end.
