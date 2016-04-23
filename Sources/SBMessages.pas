(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$i SecBbox.inc}

unit SBMessages;

interface

uses
  SysUtils,
  Classes,
  {$ifdef SB_UNICODE_VCL}
  SBStringList,
   {$endif}
  SBRDN,
  SBX509,
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBConstants,
  SBZlib,
  SBCryptoProv,
  SBCustomCertStorage,
  SBCRLStorage,
  SBPKCS7,
  SBPKCS7Utils,
  SBASN1Tree,
  SBAlgorithmIdentifier,
  SBCustomCrypto,
  SBSymmetricCrypto,
  SBPublicKeyCrypto,
  SBECCommon,
  SBGOST2814789,
  SBGOST341001,
  {$ifndef B_6}
//  SBTSPCommon,
  SBTSPClient,
   {$endif}
  SBHashFunction,
  SBStreams,
  {$ifdef SB_HAS_DC}
  SBDC,
  SBDCDef,
  SBDCPKIConstants,
   {$endif}
  SBRandom
;


const
  // error codes
  SB_MESSAGE_ERROR_NO_ENCRYPTED_DATA            = Integer($2001);
  SB_MESSAGE_ERROR_NO_CERTIFICATE               = Integer($2002);
  SB_MESSAGE_ERROR_KEY_DECRYPTION_FAILED        = Integer($2003);
  SB_MESSAGE_ERROR_BUFFER_TOO_SMALL             = Integer($2004);
  SB_MESSAGE_ERROR_CONTENT_DECRYPTION_FAILED    = Integer($2005);
  SB_MESSAGE_ERROR_INVALID_FORMAT               = Integer($2006);
  SB_MESSAGE_ERROR_NO_RECIPIENTS                = Integer($2007);
  SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM        = Integer($2008);
  SB_MESSAGE_ERROR_ENCRYPTION_FAILED            = Integer($2009);
  SB_MESSAGE_ERROR_INVALID_KEY_LENGTH           = Integer($200A);
  SB_MESSAGE_ERROR_NO_SIGNED_DATA               = Integer($200B);
  SB_MESSAGE_ERROR_INVALID_SIGNATURE            = Integer($200C);
  SB_MESSAGE_ERROR_INVALID_DIGEST               = Integer($200D);
  SB_MESSAGE_ERROR_SIGNING_FAILED               = Integer($200E);
  SB_MESSAGE_ERROR_INTERNAL_ERROR               = Integer($200F);
  SB_MESSAGE_ERROR_INVALID_MAC                  = Integer($2010);
  SB_MESSAGE_ERROR_UNSUPPORTED_SIGNATURE_TYPE   = Integer($2011);
  SB_MESSAGE_ERROR_INVALID_COUNTERSIGNATURE     = Integer($2012);
  SB_MESSAGE_ERROR_DIGEST_NOT_FOUND             = Integer($2013);
  SB_MESSAGE_ERROR_UNSUPPORTED_DIGEST_ALGORITHM = Integer($2014);
  SB_MESSAGE_ERROR_CANCELLED_BY_USER            = Integer($2015);
  SB_MESSAGE_ERROR_VERIFICATION_FAILED          = Integer($2016);
  SB_MESSAGE_ERROR_DIGEST_CALCULATION_FAILED    = Integer($2017);
  SB_MESSAGE_ERROR_MAC_CALCULATION_FAILED       = Integer($2018);
  SB_MESSAGE_ERROR_TSPCLIENT_NOT_FOUND          = Integer($2019);
  SB_MESSAGE_ERROR_BAD_TIMESTAMP                = Integer($201A);
  SB_MESSAGE_ERROR_KEYOP_FAILED_RSA             = Integer($201B);
  SB_MESSAGE_ERROR_KEYOP_FAILED_DSA             = Integer($201C);
  SB_MESSAGE_ERROR_KEYOP_FAILED_RSA_PSS         = Integer($201D);
  SB_MESSAGE_ERROR_NO_COMPRESSED_DATA           = Integer($201E);
  SB_MESSAGE_ERROR_KEYOP_FAILED_EC              = Integer($201F);
  SB_MESSAGE_ERROR_DC_BAD_ASYNC_STATE           = Integer($2020);
  SB_MESSAGE_ERROR_DC_SERVER_ERROR              = Integer($2021);
  SB_MESSAGE_ERROR_DC_MODULE_UNAVAILABLE        = Integer($2022);
  SB_MESSAGE_ERROR_KEYOP_FAILED_GOST            = Integer($2023);
  SB_MESSAGE_ERROR_NO_CONTENT_OR_DATA_URI       = Integer($2024);
  SB_MESSAGE_ERROR_TIMESTAMPING_FAILED          = Integer($2025);
  SB_MESSAGE_ERROR_NO_TIMESTAMPED_DATA          = Integer($2026);


type
  {
    The following class contains shared functionality for other
    ElMessage* classes. It should not be instantiated.
  }
  TElMessageProcessor = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElMessageProcessor = TElMessageProcessor;
   {$endif}

  TElMessageProcessor = class(TSBControlBase)
  protected
    FOnProgress : TSBProgressEvent;
    FErrorInfo : string;
    FCryptoProviderManager : TElCustomCryptoProviderManager;
    FAlignEncryptedKey : boolean;
    {$ifdef SB_HAS_GOST}
    FGOSTParamSet : ByteArray;
    procedure SetGOSTParamSet(const V : ByteArray); 
     {$endif}
    function DoProgress(Total, Current : Int64): boolean;
    procedure RaiseCancelledByUserError;
  protected
    FUseOAEP : boolean;
    function AlignEncrypted(const EK : ByteArray; Certificate : TElX509Certificate) : ByteArray;
    function EncryptRSA(const Key : ByteArray; Certificate : TElX509Certificate;
      var EncryptedKey : ByteArray) : boolean;  overload; 
    function EncryptRSAOAEP(const Key : ByteArray; Certificate : TElX509Certificate;
      var EncryptedKey : ByteArray) : boolean;  overload; 
    {$ifdef SB_HAS_GOST}
    function EncryptGOST2001(const Key : ByteArray; Certificate : TElX509Certificate;
      var EncryptedKey : ByteArray) : boolean;  overload; 
     {$endif}  
    function SignRSA(Certificate : TElX509Certificate; Digest : pointer;
      DigestSize : integer; const OID : ByteArray; var EncryptedDigest : ByteArray): boolean; overload;
    function DecryptRSA(Certificate : TElX509Certificate; Recipient : TElPKCS7Recipient;
      var Key : ByteArray) : boolean;  overload; 
    function DecryptRSAOAEP(Certificate : TElX509Certificate; Recipient : TElPKCS7Recipient;
      var Key : ByteArray) : boolean;  overload; 
    function DecryptRSAForSigner(Certificate : TElX509Certificate; Signer : TElPKCS7Signer;
      var Digest : ByteArray) : boolean;  overload; 
    {$ifdef SB_HAS_GOST}
    function DecryptGOST2001(Certificate : TElX509Certificate; Recipient : TElPKCS7Recipient;
      var Key : ByteArray) : boolean;  overload; 
     {$endif}  
    function VerifyDSA(Certificate : TElX509Certificate; Signer : TElPKCS7Signer;
      Digest : pointer; Size: integer) : boolean;
    {$ifdef SB_HAS_ECC}
    function VerifyECDSA(Certificate : TElX509Certificate; Signer : TElPKCS7Signer;
       Digest : pointer; Size: integer ) : boolean;
     {$endif}
    {$ifdef SB_HAS_GOST}
    function VerifyGOST2001(Certificate : TElX509Certificate; Signer : TElPKCS7Signer;
       Digest : pointer; Size: integer ) : boolean;
     {$endif}
    function VerifyRSAPSS(Certificate : TElX509Certificate; Signer : TElPKCS7Signer;
      Digest : pointer; Size: integer; HashAlgorithm : integer; SaltSize : integer) : boolean;
    function EncryptKey(const Key : ByteArray;
      Certificate : TElX509Certificate; var EncryptedKey : ByteArray) : boolean;
    function DecryptKey(Certificate : TElX509Certificate; Recipient : TElPKCS7Recipient;
      var Key : ByteArray): boolean;
    function ImportEncryptedSymmetricKey(Certificate : TElX509Certificate;
      Recipient : TElPKCS7Recipient; Msg : TElPKCS7Message; var Key : TElSymmetricKeyMaterial): boolean;
    function FillRecipient(Recipient : TElPKCS7Recipient; Certificate :
      TElX509Certificate; const Key : ByteArray) : boolean;
    function CalculateMAC(Buffer: pointer; Size: integer; const Key : ByteArray;
      var Mac : ByteArray; MacAlg: integer; PKCS7Data : TObject = nil;
      DataSource : TElASN1DataSource = nil; FireOnProgress : boolean = false) : boolean;
    procedure CalculateDigests(Buffer: pointer; Size: integer; HashFunctions: TElList;
      Digests : TElByteArrayList;
      PKCS7Data : TObject = nil; DataSource : TElASN1DataSource = nil;
      FireOnProgress : boolean = false);
    function CalculateDigest(Buffer: pointer; Size: integer; Alg : integer;
      PKCS7Data : TObject = nil; DataSource : TElASN1DataSource = nil;
      FireOnProgress : boolean = false): ByteArray;
    procedure HandleProgress(Sender : TObject;
      Total, Current : Int64; var Cancel : TSBBoolean);
    procedure Notification(AComponent : TComponent; AOperation : TOperation); override;
    procedure SetCryptoProviderManager(Value: TElCustomCryptoProviderManager);
  public
    property ErrorInfo : string read FErrorInfo;
  published
    property CryptoProviderManager : TElCustomCryptoProviderManager
      read FCryptoProviderManager write SetCryptoProviderManager;
    property AlignEncryptedKey : boolean read FAlignEncryptedKey write FAlignEncryptedKey  default false ;
    property OnProgress : TSBProgressEvent read FOnProgress write FOnProgress;
  end;

  TSBEncryptionOption = (eoIgnoreSupportedWin32Algorithms, eoNoOuterContentInfo);
  TSBEncryptionOptions = set of TSBEncryptionOption;
  {
    The following class is used to encrypt data and save it in PKCS7 format.
    CertStorage should contain recipients' certificates (without private keys)
  }
  TElMessageEncryptor = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElMessageEncryptor = TElMessageEncryptor;
   {$endif}

  TElMessageEncryptor = class(TElMessageProcessor)
  private
    FCertStorage : TElCustomCertStorage;
    FAlgorithm : integer;
    FBitsInKey : integer;
    FRandom : TElRandom;
    FUseUndefSize : boolean;
    FUseImplicitContentEncoding : boolean;
    FEncryptionOptions : TSBEncryptionOptions;
    FOriginatorCertificates : TElCustomCertStorage;
    FOriginatorCRLs : TElCustomCRLStorage;
    FUnprotectedAttributes : TElPKCS7Attributes;
  protected
    procedure Notification(AComponent : TComponent; AOperation : TOperation); override;
    procedure GenerateContentKey(KeyBuffer : pointer; KeySize : integer;
      IVBuffer : pointer; IVSize : integer);
    function EncryptContent(InBuffer : pointer; InSize : integer; OutBuffer :
      pointer; var OutSize : integer; const Key : ByteArray; const IV : ByteArray) : boolean;
    function FillRC2Params(KeyLen : integer; const IV : ByteArray) : ByteArray;
    function GetAppropriateEnvDataVersion: integer;
    {$ifndef BUILDER_USED}
    function ChooseEncryptionAlgorithm(const Algs : array of TSBArrayOfPairs; var Bits :
      integer) : integer;
     {$else}
    function ChooseEncryptionAlgorithm(Algs : pointer; Count: integer;
      var Bits : integer) : integer;
     {$endif}
    function AdjustKeyAndIVLengths(var Key, IV : ByteArray) : boolean;
    function CalculateEstimatedSize(InSize: integer): integer;
    procedure SetupAlgorithmParams(EnvData: TElPKCS7EnvelopedData;
      const Key, IV : ByteArray);
    function CreateEncryptingStream(Source : TElStream;
      SourceCount: Int64; const Key, IV : ByteArray): TElStream;
    procedure OnEncStreamProgress(Sender : TObject;
      Total, Current : Int64; var Cancel : TSBBoolean);
    procedure SetCertStorage(Value : TElCustomCertStorage);
    procedure SetOriginatorCertificates(Value: TElCustomCertStorage);
    procedure SetOriginatorCRLs(Value: TElCustomCRLStorage);
  public
    constructor Create(AOwner : TComponent); override;
     destructor  Destroy; override;

    function Encrypt(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
      var OutSize : integer) : integer; overload;
    function Encrypt(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
      var OutSize : integer; Key : pointer; KeySize : integer) : integer; overload;
    function Encrypt(InStream, OutStream : TElStream;
      InCount : Int64  =  0): integer;  overload; 
    function Encrypt(InStream, OutStream : TElStream;
      Key : pointer; KeySize : integer;
      InCount : Int64  =  0): integer;  overload; 

    {$ifdef SB_HAS_GOST}
    property GOSTParamSet : ByteArray read FGOSTParamSet write SetGOSTParamSet;
     {$endif}
  published
    property CertStorage : TElCustomCertStorage read FCertStorage
      write SetCertStorage;
    property Algorithm : integer read FAlgorithm write FAlgorithm;
    property BitsInKey : integer read FBitsInKey write FBitsInKey;
    property UseUndefSize: Boolean read FUseUndefSize write FUseUndefSize  default true ;
    property UseOAEP : boolean read FUseOAEP write FUseOAEP;
    property EncryptionOptions : TSBEncryptionOptions read FEncryptionOptions
      write FEncryptionOptions;
    property UseImplicitContentEncoding : boolean read FUseImplicitContentEncoding
      write FUseImplicitContentEncoding;
    property OriginatorCertificates : TElCustomCertStorage read FOriginatorCertificates
      write SetOriginatorCertificates;
    property OriginatorCRLs : TElCustomCRLStorage read FOriginatorCRLs
      write SetOriginatorCRLs;
    property UnprotectedAttributes : TElPKCS7Attributes read FUnprotectedAttributes;
  end;

  TSBCertIDsEvent = procedure(Sender: TObject; CertIDs : TElList) of object;
  {
    The following class is used to decrypt data stored in PKCS7 format.
    CertStorage should contain a list of certificates with corresponding
    private keys.
  }

  TSBDecryptionOption = (doNoOuterContentInfo);
  TSBDecryptionOptions = set of TSBDecryptionOption;

  TElMessageDecryptor = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElMessageDecryptor = TElMessageDecryptor;
   {$endif}

  TElMessageDecryptor = class(TElMessageProcessor)
  private
    FCertStorage : TElCustomCertStorage;
    FAlgorithm : integer;
    FBitsInKey : integer;
    FUsedCertificate : integer;
    FCertIDs : TElList;
    FOnCertIDs : TSBCertIDsEvent;
    FDecryptionOptions : TSBDecryptionOptions;
    FOriginatorCertificates : TElMemoryCertStorage;
    FOriginatorCRLs : TElMemoryCRLStorage;
    FUnprotectedAttributes : TElPKCS7Attributes;
  protected
    function DecryptContent(Content : TElPKCS7EncryptedContent; const Key : ByteArray;
      KeyMaterial: TElSymmetricKeyMaterial; OutBuffer : pointer; var OutSize : integer; OutStream : TStream = nil) : boolean; 
    function GetRC2KeyLengthByIdentifier(const Id : ByteArray) : cardinal;
    procedure Notification(AComponent : TComponent; AOperation : TOperation); override;
    procedure ClearCertIDs;
    function FindRecipientCertificate(Msg : TElPKCS7Message;
      var Recipient : TElPKCS7Recipient; var CertIndex : integer): TElX509Certificate;
    procedure ExtractRecipientIDs(Msg : TElPKCS7Message);
    procedure ExtractOtherInfo(Msg : TElPKCS7Message);
    procedure DecryptProgressFunc(Sender : TObject;
      Total, Current : Int64; var Cancel : TSBBoolean);
    function ExtractRC2KeyParameters(Content : TElPKCS7EncryptedContent;
      const Key : ByteArray; var IV : ByteArray): boolean;
    {$ifdef SB_HAS_GOST}
    function ExtractGOSTKeyParameters(Content : TElPKCS7EncryptedContent;
      var ParamSet : ByteArray; var IV : ByteArray): boolean;
     {$endif}

    procedure SetCertStorage(Value : TElCustomCertStorage);
    function GetCertIDCount : integer;
    function GetUsedCertificate : integer;
    function  GetCertIDs (Index : integer) : TElPKCS7Issuer;
  public
    constructor Create(AOwner : TComponent); override;
     destructor  Destroy; override;

    function Decrypt(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
      var OutSize : integer) : integer; overload;
    function Decrypt(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
      var OutSize : integer; Key : pointer; KeySize : integer) : integer; overload;

    // stream processing routines
    function Decrypt(InStream, OutStream : TElStream;
      InCount : Int64  =  0): integer;  overload; 
    function Decrypt(InStream, OutStream : TElStream;
      Key : pointer; KeySize : integer;
      InCount : Int64  =  0): integer;  overload; 

    class function IsConventionallyEncrypted(Buffer: pointer; Size: integer): boolean;

    property Algorithm : integer read FAlgorithm;
    property BitsInKey : integer read FBitsInKey;
    property CertIDs[Index : integer] : TElPKCS7Issuer read  GetCertIDs ;
    property CertIDCount : integer read GetCertIDCount;
    property UsedCertificate : integer read GetUsedCertificate;
    property UseOAEP : boolean read FUseOAEP;
    property OriginatorCertificates : TElMemoryCertStorage read FOriginatorCertificates;
    property OriginatorCRLs : TElMemoryCRLStorage read FOriginatorCRLs;
    property UnprotectedAttributes : TElPKCS7Attributes read FUnprotectedAttributes;
  published
    property CertStorage : TElCustomCertStorage read FCertStorage write
      SetCertStorage;
    property DecryptionOptions : TSBDecryptionOptions read FDecryptionOptions
      write FDecryptionOptions;
    property OnCertIDs : TSBCertIDsEvent read FOnCertIDs write FOnCertIDs;
  end;

  {
    The following class is used to verify digital signatures.
    Signature should be stored in PKCS7 format.
    CertStorage should contain a list of trusted certificates.
    Use "Certificates" property to access certificates which are
    included to message. This property is updated after each call to
    "Verify".
  }
  TSBMessageSignatureType = 
    (mstPublicKey, mstMAC);

  TSBVerificationOption = (voUseEmbeddedCerts, voUseLocalCerts, voVerifyMessageDigests,
    voVerifyTimestamps, voNoOuterContentInfo, voLiberalMode);
  TSBVerificationOptions = set of TSBVerificationOption;

  TElMessageVerifier = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElMessageVerifier = TElMessageVerifier;
   {$endif}

  TElMessageVerifier = class(TElMessageProcessor)
  private
    FUsePSS : boolean;
    FCertStorage : TElCustomCertStorage;
    FCertificates : TElMemoryCertStorage;
    FAttributes : TElPKCS7Attributes;
    FAlgorithm : integer;
    FMacAlgorithm : integer;
    FVerifyCountersignatures : boolean;
    FInputIsDigest : boolean;
    FCertIDs : TElList;
    FCSCertIDs : TElList;
    FCSAttributes : TElList;
    FTimestamps : TElList;
    FCSVerificationResults : array of integer;
    FSignatureType : TSBMessageSignatureType;
    FVerificationOptions : TSBVerificationOptions;
    FOnCertIDs : TSBCertIDsEvent;
    procedure ExtractValuesFromAttributes;
  protected
    FSigningTime : TElDateTime;

    procedure Notification(AComponent : TComponent; AOperation : TOperation); override;

    function VerifySingle(Signer : TElPKCS7Signer; Data : TElPKCS7SignedData;
      Digest : pointer; DigestSize : integer; DataSource : TElASN1DataSource;
      Countersign : boolean = false) : integer;
    function VerifyMessageDigests(Msg : TElPKCS7Message; Stream : TStream;
      Offset : Int64; Count : Int64) : integer;
    {$ifndef B_6}
    function VerifyTimestamps(Signer: TElPKCS7Signer): integer;
     {$endif}
    procedure ClearCertIDs;
    function ExtractMACKey(AuthData : TElPKCS7AuthenticatedData;
      var Key : ByteArray): integer;
    {$ifndef B_6}
    procedure ClearTimestamps;
     {$endif}
    
    procedure SetCertStorage(Value : TElCustomCertStorage);
    function GetCertIDCount : integer;
    function GetCountersignatureCertIDCount : integer;
    {$ifndef B_6}
    function GetTimestamp(Index: integer): TElClientTSPInfo;
    function GetTimestampCount: integer;
     {$endif}

    function GetCertIDs(Index : integer) : TElPKCS7Issuer;
    function GetCountersignatureCertIDs(Index : integer) : TElPKCS7Issuer;
    function GetCountersignatureVerificationResults(Index: integer): integer;
    function GetCountersignatureAttributes(Index: integer): TElPKCS7Attributes;
    procedure ExtractCertificateIDs(Msg : TElPKCS7Message; AuthData : boolean  =  false);
    procedure Reset;
    function VerifyAllSignatures(Data : TElPKCS7SignedData;
      Hashes : TElByteArrayList) : integer;
    function VerifyAllSignatures2(Msg : TElPKCS7Message; DataSource : TElASN1DataSource) : integer;
    function FindSignerCertificate(Signer : TElPKCS7Signer): TElX509Certificate;
    function InternalVerify(Source, Signature, Output : TElStream;
      SourceCount: Int64  =  0;
      SigCount : Int64  =  0): integer;
  public
    constructor Create(AOwner : TComponent); override;
     destructor  Destroy; override;

    function Verify(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
      var OutSize : integer) : integer; overload; virtual;
    function VerifyDetached(Buffer : pointer; Size : integer; Signature : pointer;
      SignatureSize : integer) : integer; overload; virtual;
    class function IsSignatureDetached(Signature : pointer; Size : integer) : boolean; overload;
    class function IsSignatureDetached(Signature : TStream; Count : Int64 = 0) : boolean; overload;
    function Verify(InStream, OutStream : TElStream;
      InCount : Int64  =  0): integer;  overload; 
    function VerifyDetached(InStream, SigStream : TElStream;
      InCount : Int64  =  0;
      SigCount : Int64  =  0): integer;  overload; 
    property Certificates : TElMemoryCertStorage read FCertificates;
    property Attributes : TElPKCS7Attributes read FAttributes;
    property HashAlgorithm : integer read FAlgorithm;
    property MacAlgorithm : integer read FMacAlgorithm;
    
    property CertIDs[Index : integer] : TElPKCS7Issuer read  GetCertIDs ;
    property CountersignatureCertIDs[Index : integer] : TElPKCS7Issuer
      read  GetCountersignatureCertIDs ;
    property CountersignatureVerificationResults[Index: integer]: integer
      read  GetCountersignatureVerificationResults ;
    property CountersignatureAttributes[Index: integer] : TElPKCS7Attributes
      read  GetCountersignatureAttributes ;
    
    property CertIDCount : integer read GetCertIDCount;
    property CountersignatureCertIDCount : integer read GetCountersignatureCertIDCount;
    property SignatureType : TSBMessageSignatureType read FSignatureType;
    property UsePSS : boolean read FUsePSS;
    property InputIsDigest : boolean read FInputIsDigest write FInputIsDigest  default false ;
    {$ifndef B_6}
    property Timestamps[Index: integer] : TElClientTSPInfo read GetTimestamp;
    property TimestampCount : integer read GetTimestampCount;
     {$endif}
    property SigningTime : TElDateTime read FSigningTime;
  published
    property CertStorage : TElCustomCertStorage read FCertStorage
      write SetCertStorage;
    property VerifyCountersignatures : boolean read FVerifyCountersignatures
      write FVerifyCountersignatures;
    property VerificationOptions : TSBVerificationOptions read FVerificationOptions
      write FVerificationOptions  default [voUseEmbeddedCerts,
      voUseLocalCerts, voVerifyMessageDigests] ;
    property OnCertIDs : TSBCertIDsEvent read FOnCertIDs write FOnCertIDs;
  end;
  
  TSBSigningOption = (soInsertMessageDigests, soIgnoreTimestampFailure,
    soNoOuterContentInfo, soRawCountersign, soInsertSigningTime,
    soUseGeneralizedTimeFormat, soIgnoreBadCountersignatures,
    soUseImplicitContent);
  TSBSigningOptions = set of TSBSigningOption;

  TSBSignOperationType =  (sotGeneric, sotAsyncPrepare,
    sotAsyncComplete);

  {
    The following class is used to sign messages.
    CertStorage should contain at least one certificate with private key
    (and any amount of certificates without private keys).
    Message will be signed with every certificate that has a corresponding
    private key.
    Other certificates may be used to specify the chain from trusted root
    certificate.
  }

  TElMessageSigner = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElMessageSigner = TElMessageSigner;
   {$endif}

  TElMessageSigner = class(TElMessageProcessor)
  private
    FUsePSS : boolean;
    FCertStorage : TElCustomCertStorage;
    FRecipientCerts : TElCustomCertStorage;
    FAAttributes : TElPKCS7Attributes;
    FUAttributes : TElPKCS7Attributes;
    FAlgorithm : integer;
    FMacAlgorithm : integer;
    FIncludeCertificates : boolean;
    FIncludeChain : boolean;
    FSignatureType : TSBMessageSignatureType;
    FContentType : ByteArray;
    FUseUndefSize : boolean;
    FSigningOptions : TSBSigningOptions;
    FDigestEncryptionAlgorithm : ByteArray;
    FSigningTime : TElDateTime;
    FDataHash: ByteArray;
    FOperationType : TSBSignOperationType;
    FExtraSpace : integer;
    {$ifdef SB_HAS_DC}
    FAsyncState : TElDCAsyncState;
     {$endif}
    {$ifndef B_6}
    FTSPClient : TElCustomTSPClient;
     {$endif}
  protected
    procedure Notification(AComponent : TComponent; AOperation : TOperation); override;
    function FillSigner(Signer : TElPKCS7Signer; Certificate : TElX509Certificate;
      const DigestAlgorithm : ByteArray; Hash : pointer; HashSize : integer): integer;
    function SignDSA(Certificate : TElX509Certificate; Digest : pointer;
      DigestSize: integer; var Signature : ByteArray) : boolean;
    function SignRSAPSS(Certificate : TElX509Certificate;
      Digest : pointer; DigestSize: integer; var Signature : ByteArray) : boolean;
    {$ifdef SB_HAS_ECC}
    function SignEC(Signer : TElPKCS7Signer; Certificate : TElX509Certificate; Digest : pointer;
      DigestSize: integer; var Signature : ByteArray) : boolean;
     {$endif}
    {$ifdef SB_HAS_GOST}
    function SignGOST2001(Signer : TElPKCS7Signer; Certificate : TElX509Certificate; Digest : pointer;
      DigestSize: integer; var Signature : ByteArray) : boolean;
     {$endif}
    function CalculateEstimatedSize(InputSize : integer; Detached: boolean) : integer;
    {$ifndef B_6}
    function TimestampMessage(Msg : TElPKCS7Message) : integer;
    function TimestampCountersignatures(Msg : TElPKCS7Message; SigIndexes : array of integer): integer;
    function TimestampSignerInfo(SignerInfo : TElPKCS7Signer): integer; 
     {$endif}
    function SignPublicKey(InBuffer: pointer; InSize: integer;
      OutBuffer : pointer; var OutSize : integer;
      InStream, OutStream : TStream; InCount: Int64; Detached : boolean): integer;
    function SignMAC(InBuffer: pointer; InSize: integer;
      OutBuffer : pointer; var OutSize : integer;
      InStream, OutStream : TStream; InCount: Int64; Detached : boolean): integer;
    function InternalCountersign(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
      var OutSize : integer; InStream, OutStream : TStream; InCount : Int64) : integer;
    {$ifdef SB_HAS_DC}
    function InternalCompleteAsyncSign(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
      var OutSize: integer; InStream, OutStream : TElStream; InCount: Int64;
      AsyncState: TElDCAsyncState): integer;
     {$endif}
    
    procedure SetCertStorage(Value : TElCustomCertStorage);
    procedure SetRecipientCerts(Value : TElCustomCertStorage);
    {$ifndef B_6}
    procedure SetTSPClient(Value : TElCustomTSPClient);
     {$endif}
    procedure SetContentType(const V : ByteArray);
    procedure SetDigestEncryptionAlgorithm(const V : ByteArray);
  public
    constructor Create(AOwner : TComponent); override;
     destructor  Destroy; override;

    function Sign(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
      var OutSize : integer; Detached : boolean = false) : integer; overload; virtual;
    function Sign(InStream, OutStream : TStream; Detached : boolean = false;
      InCount : Int64 = 0): integer; overload; virtual;
    {$ifdef SB_HAS_DC}
    function InitiateAsyncSign(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
      var OutSize: integer; Detached: boolean; var State : TElDCAsyncState): integer;  overload; 
    function CompleteAsyncSign(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
      var OutSize: integer; AsyncState: TElDCAsyncState): integer;  overload; 
    function InitiateAsyncSign(InStream, OutStream : TElStream; Detached: boolean;
       var State : TElDCAsyncState ; 
      InCount: int64  =  0): integer;  overload; 
    function CompleteAsyncSign(InStream, OutStream: TElStream; AsyncState: TElDCAsyncState;
      InCount: int64  =  0): integer;  overload; 
     {$endif}
    function Countersign(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
      var OutSize : integer) : integer; overload; virtual;
    function Countersign(InStream, OutStream : TStream; InCount : Int64 = 0): integer; overload; virtual;
    {$ifndef B_6}
    function Timestamp(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
      var OutSize: integer): integer; overload;
    function Timestamp(InStream, OutStream : TStream; InCount : Int64 = 0): integer; overload;
    function TimestampCountersignature(InBuffer: pointer; InSize: integer;
      OutBuffer: pointer; var OutSize: integer; SigIndex: integer): integer; overload;
    function TimestampCountersignature(InStream, OutStream : TStream; SigIndex: integer;
      InCount : Int64 = 0): integer; overload;
     {$endif}

    property AuthenticatedAttributes : TElPKCS7Attributes read FAAttributes;
    property UnauthenticatedAttributes : TElPKCS7Attributes read FUAttributes;
    property HashAlgorithm : integer read FAlgorithm write FAlgorithm;
    property MacAlgorithm : integer read FMacAlgorithm write FMacAlgorithm;
    property ContentType : ByteArray read FContentType write SetContentType;
    property DataHash: ByteArray read FDataHash;
    property DigestEncryptionAlgorithm : ByteArray read FDigestEncryptionAlgorithm
      write SetDigestEncryptionAlgorithm;
    property SigningTime : TElDateTime read FSigningTime write FSigningTime;
  published
    property SignatureType : TSBMessageSignatureType read FSignatureType
      write FSignatureType  default mstPublicKey ;
    property CertStorage : TElCustomCertStorage read FCertStorage
      write SetCertStorage;
    property IncludeCertificates: boolean read FIncludeCertificates
      write FIncludeCertificates  default true ;
  property IncludeChain: boolean read FIncludeChain write FIncludeChain  default false ;
    property RecipientCerts : TElCustomCertStorage read FRecipientCerts
      write SetRecipientCerts;
    property UseUndefSize: Boolean read FUseUndefSize write FUseUndefSize  default true ;
    property UsePSS : Boolean read FUsePSS write FUsePSS;
    property SigningOptions : TSBSigningOptions read FSigningOptions
      write FSigningOptions  default [soInsertMessageDigests] ;
    property ExtraSpace : integer read FExtraSpace write FExtraSpace;
    {$ifndef B_6}
    property TSPClient : TElCustomTSPClient read FTSPClient write SetTSPClient;
     {$endif}
  end;


  TElMessageDecompressor = class(TElMessageProcessor)
  private
    FZLibSpool : ByteArray;
    FContentType : ByteArray;

    function ZLibOutput(Buffer: pointer; Size: integer; Param: pointer): boolean;
  protected
    procedure Notification(AComponent : TComponent; AOperation : TOperation); override;
    function DecompressContent(InBuffer : pointer; InSize : integer; OutBuffer: pointer; var OutSize : integer) : boolean;
    function CreateDecompressingStream(Source : TElPKCS7CompressedData): TElStream;
    procedure OnDecompressingStreamProgress(Sender : TObject; Total, Current : Int64; var Cancel : TSBBoolean);
  public
    constructor Create(AOwner : TComponent); override;
     destructor  Destroy; override;

    function Decompress(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
      var OutSize : integer) : integer; overload;
    function Decompress(InStream, OutStream : TElStream;
      InCount : Int64  =  0): integer;  overload; 
    property ContentType : ByteArray read FContentType;
  end;

  {$ifndef SB_NO_COMPRESSION}

  TElMessageCompressor = class(TElMessageProcessor)
  private
    FUseUndefSize : boolean;
    FContentToCompress : ByteArray;
    FCompressedContent : ByteArray;
    FContentType : ByteArray;
    FCompressionLevel : integer;
    FFragmentSize : integer;
  protected
    procedure Notification(AComponent : TComponent; AOperation : TOperation); override;
    procedure CompressContent(InBuffer : pointer; InSize : integer; CompressionLevel : integer);
    function CreateCompressingStream(Source : TElStream): TElStream;
    procedure OnCompressingStreamProgress(Sender : TObject; Total, Current : Int64; var Cancel : TSBBoolean);
    procedure SetContentType(const V : ByteArray);
  public
    constructor Create(AOwner : TComponent); override;
     destructor  Destroy; override;

    function Compress(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
      var OutSize : integer) : integer; overload;
    function Compress(InStream, OutStream : TElStream;
      InCount : Int64  =  0): integer;  overload; 
    
    property ContentType: ByteArray read FContentType write SetContentType;
    property CompressionLevel: integer read FCompressionLevel write FCompressionLevel;
    property FragmentSize: integer read FFragmentSize write FFragmentSize;
  published
    property UseUndefSize: Boolean read FUseUndefSize write FUseUndefSize  default true ;
  end;
   {$endif SB_NO_COMPRESSION}

  TElMessageTimestamper = class(TElMessageProcessor)
  private
    FIncludeContent : boolean;
    FProtectMetadata : boolean;
    FDataURI : string;
    FFileName : string;
    FMediaType : string;
    FUseUndefSize : boolean;
    FTSPClientList:  TSBObjectList ;
  protected
    function GetTSPClients(Index : integer) : TElCustomTSPClient;
    function GetTSPClientsCount : integer;
    function GetTSPClient : TElCustomTSPClient;
    procedure SetTSPClient(Client : TElCustomTSPClient);
    function CalculateEstimatedSize(InputSize : integer) : integer;
    procedure Notification(AComponent : TComponent; AOperation : TOperation); override;
  public
    constructor Create(AOwner : TComponent); override;
     destructor  Destroy; override;

    function Timestamp(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
      var OutSize : integer) : integer; overload;
    function Timestamp(InStream, OutStream : TElStream;
      InCount : Int64  =  0): integer;  overload; 

    function AddTSPClient(Client : TElCustomTSPClient) : integer;
    procedure RemoveTSPClient(Index : integer);  overload; 
    procedure RemoveTSPClient(Client : TElCustomTSPClient);  overload; 

    property TSPClients[Index : integer] : TElCustomTSPClient read GetTSPClients;
    property TSPClientsCount : integer read GetTSPClientsCount;    
    property TSPClient : TElCustomTSPClient read GetTSPClient write SetTSPClient;
  published
    property IncludeContent : boolean read FIncludeContent write FIncludeContent;
    property ProtectMetadata : boolean read FProtectMetadata write FProtectMetadata;
    property DataURI : string read FDataURI write FDataURI;
    property FileName : string read FFileName write FFileName;
    property MediaType : string read FMediaType write FMediaType;
    property UseUndefSize: Boolean read FUseUndefSize write FUseUndefSize  default true ;
  end;

  TElMessageTimestampVerifier = class(TElMessageProcessor)
  private
    FDataURI : string;
    FFileName : string;
    FMediaType : string;
    FTimestamps : TElList;
  protected
    function GetTimestamp(Index: integer): TElClientTSPInfo;
    function GetTimestampCount: integer;
    procedure Notification(AComponent : TComponent; AOperation : TOperation); override;

    function ParseMessageImprint(const Imprint : ByteArray; var HashAlgOID, Hash : ByteArray) : boolean;  
    function InternalVerify(InStream, DataStream, OutStream : TElStream; InCount, DataCount : Int64): integer;
  public
    constructor Create(AOwner : TComponent); override;
     destructor  Destroy; override;

    function Verify(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
      var OutSize : integer) : integer; overload; virtual;
    function VerifyDetached(Buffer : pointer; Size : integer; Data : pointer;
      DataSize : integer) : integer; overload; virtual;
    class function IsTimestampDetached(Timestamp : pointer; Size : integer; var DataURI : string; var FileName : string) : boolean; overload;
    class function IsTimestampDetached(Timestamp : TElStream; var DataURI : TSBString; var FileName : TSBString; Count : Int64  =  0): boolean;  overload;     function Verify(InStream, OutStream : TElStream;
      InCount : Int64  =  0): integer;  overload; 
    function VerifyDetached(InStream, DataStream : TElStream;
      InCount : Int64  =  0;
      DataCount : Int64  =  0): integer;  overload; 

    property Timestamps[Index: integer] : TElClientTSPInfo read GetTimestamp;
    property TimestampCount : integer read GetTimestampCount;
    property DataURI : string read FDataURI;
    property FileName : string read FFileName;
    property MediaType : string read FMediaType;
  end;

  EElMessageError = class(ESecureBlackboxError);
  EElMessageUserCancelledError = class(EElMessageError);

procedure Register;

implementation

uses
  SBRSA,
  SBDSA,
  SBTSPCommon,
  {$ifndef SB_NO_PKCS11}
  //SBPKCS11CertStorage,
   {$endif}
  {$ifdef WIN32} Windows,   {$endif}
  {$ifdef SB_HAS_WINCRYPT}SBWinCrypt, {$endif}
  SBPKICommon;

const
  RC2KeyLength2Identifiers : array[0..255] of byte =  ( 
    $bd, $56, $ea, $f2, $a2, $f1, $ac, $2a, $b0, $93, $d1, $9c, $1b, $33, $fd, $d0,
    $30, $04, $b6, $dc, $7d, $df, $32, $4b, $f7, $cb, $45, $9b, $31, $bb, $21, $5a,
    $41, $9f, $e1, $d9, $4a, $4d, $9e, $da, $a0, $68, $2c, $c3, $27, $5f, $80, $36,
    $3e, $ee, $fb, $95, $1a, $fe, $ce, $a8, $34, $a9, $13, $f0, $a6, $3f, $d8, $0c,
    $78, $24, $af, $23, $52, $c1, $67, $17, $f5, $66, $90, $e7, $e8, $07, $b8, $60,
    $48, $e6, $1e, $53, $f3, $92, $a4, $72, $8c, $08, $15, $6e, $86, $00, $84, $fa,
    $f4, $7f, $8a, $42, $19, $f6, $db, $cd, $14, $8d, $50, $12, $ba, $3c, $06, $4e,
    $ec, $b3, $35, $11, $a1, $88, $8e, $2b, $94, $99, $b7, $71, $74, $d3, $e4, $bf,
    $3a, $de, $96, $0e, $bc, $0a, $ed, $77, $fc, $37, $6b, $03, $79, $89, $62, $c6,
    $d7, $c0, $d2, $7c, $6a, $8b, $22, $a3, $5b, $05, $5d, $02, $75, $d5, $61, $e3,
    $18, $8f, $55, $51, $ad, $1f, $0b, $5e, $85, $e5, $c2, $57, $63, $ca, $3d, $6c,
    $b4, $c5, $cc, $70, $b2, $91, $59, $0d, $47, $20, $c8, $4f, $58, $e0, $01, $e2,
    $16, $38, $c4, $6f, $3b, $0f, $65, $46, $be, $7e, $2d, $7b, $82, $f9, $40, $b5,
    $1d, $73, $f8, $eb, $26, $c7, $87, $97, $25, $54, $b1, $28, $aa, $98, $9d, $a5,
    $64, $6d, $7a, $d4, $10, $81, $44, $ef, $49, $d6, $ae, $2e, $dd, $76, $5c, $2f,
    $a7, $1c, $c9, $09, $69, $9a, $83, $cf, $29, $39, $b9, $e9, $4c, $ff, $43, $ab
   ) ;
  
  RC2Identifiers2KeyLength : array[0..255] of byte =  ( 
    $5D, $BE, $9B, $8B, $11, $99, $6E, $4D, $59, $F3, $85, $A6, $3F, $B7, $83, $C5,
    $E4, $73, $6B, $3A, $68, $5A, $C0, $47, $A0, $64, $34, $0C, $F1, $D0, $52, $A5,
    $B9, $1E, $96, $43, $41, $D8, $D4, $2C, $DB, $F8, $07, $77, $2A, $CA, $EB, $EF,
    $10, $1C, $16, $0D, $38, $72, $2F, $89, $C1, $F9, $80, $C4, $6D, $AE, $30, $3D,
    $CE, $20, $63, $FE, $E6, $1A, $C7, $B8, $50, $E8, $24, $17, $FC, $25, $6F, $BB,
    $6A, $A3, $44, $53, $D9, $A2, $01, $AB, $BC, $B6, $1F, $98, $EE, $9A, $A7, $2D,
    $4F, $9E, $8E, $AC, $E0, $C6, $49, $46, $29, $F4, $94, $8A, $AF, $E1, $5B, $C3,
    $B3, $7B, $57, $D1, $7C, $9C, $ED, $87, $40, $8C, $E2, $CB, $93, $14, $C9, $61,
    $2E, $E5, $CC, $F6, $5E, $A8, $5C, $D6, $75, $8D, $62, $95, $58, $69, $76, $A1,
    $4A, $B5, $55, $09, $78, $33, $82, $D7, $DD, $79, $F5, $1B, $0B, $DE, $26, $21,
    $28, $74, $04, $97, $56, $DF, $3C, $F0, $37, $39, $DC, $FF, $06, $A4, $EA, $42,
    $08, $DA, $B4, $71, $B0, $CF, $12, $7A, $4E, $FA, $6C, $1D, $84, $00, $C8, $7F,
    $91, $45, $AA, $2B, $C2, $B1, $8F, $D5, $BA, $F2, $AD, $19, $B2, $67, $36, $F7,
    $0F, $0A, $92, $7D, $E3, $9D, $E9, $90, $3E, $23, $27, $66, $13, $EC, $81, $15,
    $BD, $22, $BF, $9F, $7E, $A9, $51, $4B, $4C, $FB, $02, $D3, $70, $86, $31, $E7,
    $3B, $05, $03, $54, $60, $48, $65, $18, $D2, $CD, $5F, $32, $88, $0E, $35, $FD
   ) ;

resourcestring
  SUnsupportedAlgorithm = 'Unsupported algorithm: %d';
  SCancelledByUser = 'Cancelled by user';
  SInvalidKeyLength = 'Invalid key length';

procedure Register;
begin
  RegisterComponents('PKIBlackbox', [TElMessageEncryptor, TElMessageDecryptor,
    TElMessageSigner, TElMessageVerifier, {$ifndef SB_NO_COMPRESSION}TElMessageCompressor, {$endif} TElMessageDecompressor,
    TElMessageTimestamper, TElMessageTimestampVerifier]);
end;


type
  TElChunkedEncryptingStream = class(TElStream)
  private
    FSourceStream : TElStream;
    FCrypto : TElSymmetricCrypto;
    FKeyMaterial : TElSymmetricKeyMaterial;
    FRead : Int64;
    FWritten : Int64;
    FSpool : ByteArray;
    FTotalIn : Int64;
    FTotalOut : Int64;
    FFinalized : boolean;
    function ReadFromSpool(Buffer: pointer; Size: integer): integer;
    procedure WriteToSpool(Buffer: pointer; Size: integer);
  protected
    FOnProgress : TSBProgressEvent;
  public
    constructor Create(SourceStream : TElStream;
      Algorithm : integer; const Key, IV : ByteArray; Count: integer  =  0;
      Manager : TElCustomCryptoProviderManager  =  nil);  overload; 
    {$ifdef SB_HAS_GOST}
    constructor Create(SourceStream : TElStream;
      Algorithm : integer; const Key, IV, ParamSet : ByteArray; Count: integer  =  0;
      Manager : TElCustomCryptoProviderManager  =  nil);  overload; 
     {$endif}
     destructor  Destroy;  override; 

    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
    function Seek(Offset: Longint; Origin: Word): Longint; override;
    {$ifdef D_6_UP}
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; override;
     {$endif}
   
    property OnProgress : TSBProgressEvent read FOnProgress write FOnProgress;
  end;

  TElZlibDecompressingStream = class(TElStream)
  private
    FSourceStream : TElStream;
    FSourceData : TElPKCS7CompressedData;
    FCurrentContentPart : integer;
    FCurrentContentPartRead : Int64;
    FZLibCtx : TZlibContext;
    FRead : Int64;
    FWritten : Int64;
    FSpool : ByteArray;
    FTotalIn : Int64;
    FTotalOut : Int64;
    FFinalized : boolean;
    function ReadFromSpool(Buffer: pointer; Size: integer): integer;
    procedure WriteToSpool(Buffer: pointer; Size: integer);
    function ZLibOutput(Buffer: pointer; Size: integer; Param: pointer): boolean;
  protected
    FOnProgress : TSBProgressEvent;
  public
    constructor Create(SourceStream : TElStream;
      Count: integer  =  0);  overload; 
    constructor Create(Source : TElPKCS7CompressedData);  overload; 
     destructor  Destroy;  override; 

    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
    function Seek(Offset: Longint; Origin: Word): Longint; override;
    {$ifdef D_6_UP}
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; override;
     {$endif}
    property OnProgress : TSBProgressEvent read FOnProgress write FOnProgress;
  end;

  {$ifndef SB_NO_COMPRESSION}
  TElZlibCompressingStream = class(TElStream)
  private
    FSourceStream : TElStream;
    FDataSource : TElASN1DataSource;
    FZLibCtx : TZlibContext;
    FRead : Int64;
    FWritten : Int64;
    FSpool : ByteArray;
    FTotalIn : Int64;
    FTotalOut : Int64;
    FFinalized : boolean;
    function ReadFromSpool(Buffer: pointer; Size: integer): integer;
    procedure WriteToSpool(Buffer: pointer; Size: integer);
    procedure FinalizeCompression;    
  protected
    FOnProgress : TSBProgressEvent;
  public
    constructor Create(SourceStream : TElStream;
      CompressionLevel: integer  =  6; Count: integer  =  0);   overload; 
    constructor Create(Source : TElASN1DataSource; CompressionLevel: integer  =  6);   overload; 
     destructor  Destroy;  override; 
    function Read(var Buffer; Count: Longint): Longint; override;
    function Write(const Buffer; Count: Longint): Longint; override;
    function Seek(Offset: Longint; Origin: Word): Longint; override;
    {$ifdef D_6_UP}
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; override;
     {$endif}
    property OnProgress : TSBProgressEvent read FOnProgress write FOnProgress;
  end;
   {$endif}

{ TElChunkedEncryptingStream }

constructor TElChunkedEncryptingStream.Create(SourceStream : TElStream;
  Algorithm : integer; const Key, IV : ByteArray; Count: integer  =  0;
  Manager : TElCustomCryptoProviderManager  =  nil);
var
  Factory : TElSymmetricCryptoFactory;
  Md : TSBSymmetricCryptoMode;
begin
  inherited Create;
  // creating crypto
  
  Factory := TElSymmetricCryptoFactory.Create();
  try
    Factory.CryptoProviderManager := Manager;
    if Algorithm <> SB_ALGORITHM_CNT_RC4 then
      Md := cmCBC
    else
      Md := cmDefault;
    FCrypto := Factory.CreateInstance(Algorithm, Md);
  finally
    FreeAndNil(Factory);
  end;
  if FCrypto <> nil then
  begin
    FKeyMaterial := TElSymmetricKeyMaterial.Create(Manager, nil);
    FKeyMaterial.Key := CloneArray(Key);
    FKeyMaterial.IV := CloneArray(IV);
    FCrypto.KeyMaterial := FKeyMaterial;
    FCrypto.Padding := cpPKCS5;
  end
  else
    raise EElMessageError.CreateFmt(SUnsupportedAlgorithm, [Algorithm]);
  FCrypto.InitializeEncryption();
  FSourceStream := SourceStream;
  FRead := 0;
  FWritten := 0;
  SetLength(FSpool, 0);
  if Count = 0 then
    FTotalIn := SourceStream. Size  - SourceStream.Position
  else
    FTotalIn := Min(Count, SourceStream. Size  - SourceStream.Position);
  if (FCrypto.BlockSize <> 1) and (FCrypto.BlockSize <> 0) then
    FTotalOut := ((FTotalIn div FCrypto.BlockSize) + 1) * FCrypto.BlockSize
  else
    FTotalOut := FTotalIn;
  FFinalized := false;
end;

{$ifdef SB_HAS_GOST}
{ this method is only for GOST crypto now}
constructor TElChunkedEncryptingStream.Create(SourceStream : TElStream; Algorithm : integer;
  const Key, IV, ParamSet : ByteArray; Count: integer  =  0;
  Manager : TElCustomCryptoProviderManager  =  nil);
begin
  inherited Create;

  if Algorithm <> SB_ALGORITHM_CNT_GOST_28147_1989 then
    raise EElMessageError.CreateFmt(SUnsupportedAlgorithm, [Algorithm]);
  

  // creating GOST 28147 crypto

  FCrypto := TElGOST28147SymmetricCrypto.Create(cmCFB8);
  if FCrypto <> nil then
  begin
    TElGOST28147SymmetricCrypto(FCrypto).ParamSet := ParamSet;
    TElGOST28147SymmetricCrypto(FCrypto).UseKeyMeshing := true;
    FKeyMaterial := TElSymmetricKeyMaterial.Create(Manager, nil);
    FKeyMaterial.Key := CloneArray(Key);
    FKeyMaterial.IV := CloneArray(IV);
    FCrypto.KeyMaterial := FKeyMaterial;
  end
  else
    raise EElMessageError.CreateFmt(SUnsupportedAlgorithm, [Algorithm]);
    
  FCrypto.InitializeEncryption();
  FSourceStream := SourceStream;
  FRead := 0;
  FWritten := 0;
  SetLength(FSpool, 0);

  if Count = 0 then
    FTotalIn := SourceStream. Size  - SourceStream.Position
  else
    FTotalIn := Min(Count, SourceStream. Size  - SourceStream.Position);
  FTotalOut := FTotalIn;
  FFinalized := false;
end;
 {$endif}

 destructor  TElChunkedEncryptingStream.Destroy;
begin
  if Assigned(FCrypto) then
    FreeAndNil(FCrypto);
  if Assigned(FKeyMaterial) then
    FreeAndNil(FKeyMaterial);
  inherited;
end;


function TElChunkedEncryptingStream.ReadFromSpool(Buffer: pointer; Size: integer): integer;
begin
  Result := Min(Size,   Length(FSpool));
  SBMove(FSpool[0], Buffer^, Result);
  SBMove(FSpool[Result], FSpool[0], Length(FSpool) - Result);
  SetLength(FSpool,
     Length (FSpool) - Result);
end;

procedure TElChunkedEncryptingStream.WriteToSpool(Buffer: pointer; Size: integer);
var
  OldLen : integer;
begin
  OldLen :=  Length (FSpool);
  SetLength(FSpool, OldLen + Size);
  SBMove(Buffer^, FSpool[OldLen], Size);
end;

function TElChunkedEncryptingStream.Read(var Buffer; Count: Longint): Longint;
var
  Buf : ByteArray;
  OutSize : integer;
  OutBuf : ByteArray;
  DataLeft : integer;
  Len : integer;
  Ptr :  ^byte ;
  Cancel : TSBBoolean;
begin

   System. SetLength(Buf, 32768);

  Result := 0;
  DataLeft := Count;
  // reading data from spool
  Ptr :=  @Buffer ;
  Len := ReadFromSpool(Ptr, DataLeft);
  Inc(Ptr, Len);
  Dec(DataLeft, Len);
  Inc(FWritten, Len);
  Inc(Result, Len);
  // encrypting as much data as needed
  while DataLeft > 0 do
  begin
    Len := FSourceStream.Read(Buf[0], Length(Buf));
    Inc(FRead, Len);
    Cancel := false;
    if Assigned(FOnProgress) then
      FOnProgress(Self, FTotalIn, FRead, Cancel);
    if Cancel then
      raise EElMessageError.Create(SCancelledByUser);
    if Len > 0 then
    begin
      OutSize := 0;
      FCrypto.EncryptUpdate(@Buf[0], Len, nil, OutSize);
      if OutSize = 0 then
        OutSize := FCrypto.BlockSize;
      SetLength(OutBuf, OutSize);
      FCrypto.EncryptUpdate(@Buf[0], Len, @OutBuf[0], OutSize);
    end
    else if not FFinalized then
    begin
      // stream is over, finalizing
      OutSize := FCrypto.BlockSize;
      SetLength(OutBuf, OutSize);
      FCrypto.FinalizeEncryption(@OutBuf[0], OutSize);
      FFinalized := true;
    end
    else
      OutSize := 0;
    Len := Min(OutSize, DataLeft);
    SBMove(OutBuf[0], Ptr^, Len);
    Inc(Ptr, Len);
    Inc(FWritten, Len);
    Inc(Result, Len);
    Dec(DataLeft, Len);
    if OutSize > Len then
      WriteToSpool(@OutBuf[Len], OutSize - Len);
    if FFinalized and (  Length  (FSpool) = 0) then
      Break;
  end;
  ReleaseArray(Buf);
  ReleaseArray(OutBuf);
end;

function TElChunkedEncryptingStream.Write(const Buffer; Count: Longint): Longint;
begin
  Result := 0;
end;

function TElChunkedEncryptingStream.Seek(Offset: Longint; Origin: Word): Longint;
begin
  // handling GetSize call
  if (Origin = soFromEnd) and (Offset = 0) then
    Result := FTotalOut
  // handling GetPosition call
  else if (Origin = soFromCurrent) and (Offset = 0) then
    Result := FWritten
  else
    Result := 0;
end;

{$ifdef D_6_UP}
function TElChunkedEncryptingStream.Seek(const Offset: Int64; Origin: TSeekOrigin): Int64;
begin
  if (Origin = soEnd) and (Offset = 0) then
    Result := FTotalOut
  else if (Origin = soCurrent) and (Offset = 0) then
    Result := FWritten
  else
    Result := 0;
end;
 {$endif}


{ TElZlibDecompressingStream }

constructor TElZlibDecompressingStream.Create(SourceStream : TElStream; Count: integer  =  0);
begin
  inherited Create;

  FSourceData := nil;
  FSourceStream := SourceStream;
  FRead := 0;
  FWritten := 0;
    SetLength(FSpool, 0);
  if Count = 0 then
    FTotalIn := SourceStream. Size  - SourceStream.Position
  else
    FTotalIn := Min(Count, SourceStream. Size  - SourceStream.Position);

  FTotalOut := 1;
  FFinalized := false;
  FOnProgress := nil;
  InitializeDecompressionEx(FZlibCtx, true);
end;

constructor TElZlibDecompressingStream.Create(Source : TElPKCS7CompressedData);
var
  i : integer;
begin
  inherited Create;

  FSourceData := Source;
  FCurrentContentPart := 0;
  FSourceStream := nil;
  FRead := 0;
  FCurrentContentPartRead := 0;
  FWritten := 0;
    SetLength(FSpool, 0);

  FTotalIn := 0;
  for i := 0 to Source.CompressedContentPartCount - 1 do
    FTotalIn := FTotalIn + Source.CompressedContentParts[i].Size;
  FTotalOut := 1;
  FFinalized := false;
  FOnProgress := nil;
  InitializeDecompressionEx(FZlibCtx, true);
end;

 destructor  TElZlibDecompressingStream.Destroy;
begin
  if not FFinalized then
    FinalizeDecompressionEx(FZLibCtx);
  inherited;
end;


function TElZlibDecompressingStream.ReadFromSpool(Buffer: pointer; Size: integer): integer;
begin
  Result := Min(Size,   Length  (FSpool));
  SBMove(FSpool[0], Buffer^, Result);
  SBMove(FSpool[Result], FSpool[0], Length(FSpool) - Result);
  SetLength(FSpool,  Length (FSpool) - Result);
end;

procedure TElZlibDecompressingStream.WriteToSpool(Buffer: pointer; Size: integer);
var
  OldLen : integer;
begin
  OldLen :=  Length (FSpool);
  SetLength(FSpool, OldLen + Size);
  SBMove(Buffer^, FSpool[OldLen], Size);
end;

function TElZlibDecompressingStream.ZLibOutput(Buffer: pointer; Size: integer; Param: pointer): boolean;
begin
  WriteToSpool(Buffer, Size);
  Result := true;
end;

function TElZlibDecompressingStream.Read(var Buffer; Count: Longint): Longint;
var
  Buf : ByteArray;
  OutSize : integer;
  DataLeft : integer;
  Len : integer;
  Ptr :  ^byte ;
  Cancel : TSBBoolean;
begin
    SetLength(Buf, 32768);
  Result := 0;
  DataLeft := Count;
  // reading data from spool
  Ptr :=  @Buffer ;
  Len := ReadFromSpool(Ptr, DataLeft);
  Inc(Ptr, Len);
  Dec(DataLeft, Len);
  Inc(FWritten, Len);
  Inc(Result, Len);
  // encrypting as much data as needed
  while DataLeft > 0 do
  begin
    if not FFinalized then
    begin
      if Assigned(FSourceStream) then
        Len := FSourceStream.Read( Buf[0] , Min(  Length  (Buf), FTotalIn - FRead))
      else
      begin
        if (FCurrentContentPartRead >= FSourceData.CompressedContentParts[FCurrentContentPart].Size) then
        begin
          Inc(FCurrentContentPart);
          FCurrentContentPartRead := 0;
        end;

        if FCurrentContentPart < FSourceData.CompressedContentPartCount then
        begin
          Len := FSourceData.CompressedContentParts[FCurrentContentPart].Read( @Buf[0] , Min(  Length  (Buf), FTotalIn - FRead), FCurrentContentPartRead);
          Inc(FCurrentContentPartRead, Len);
        end
        else
          Len := 0;
      end;

      Inc(FRead, Len);
      Cancel := false;

      if Len > 0 then
      begin
        SBZlib.DecompressEx(FZLibCtx, @Buf[0], Len, ZLibOutput, nil);
      end
      else
      begin
        // stream is over, finalizing
        FinalizeDecompressionEx(FZlibCtx);
        FFinalized := true;
      end;
      
      if Assigned(FOnProgress) then
        FOnProgress(Self, FTotalIn, FRead, Cancel);
      if Cancel then
        raise EElMessageError.Create(SCancelledByUser);
    end;  

    OutSize :=   Length  (FSpool);    
    Len := Min(OutSize, DataLeft);
    ReadFromSpool(Ptr, DataLeft);
    Inc(Ptr, Len);
    Inc(FWritten, Len);
    Inc(Result, Len);
    Dec(DataLeft, Len);
    
    if not FFinalized then
      FTotalOut := FWritten +   Length  (FSpool) + 1 // simulating 'stream-not-ended'
    else
      FTotalOut := FWritten;

    if FFinalized and (  Length  (FSpool) = 0) then
      Break;
  end;
end;

function TElZlibDecompressingStream.Write(const Buffer; Count: Longint): Longint;
begin
  Result := 0;
end;

function TElZlibDecompressingStream.Seek(Offset: Longint; Origin: Word): Longint;
begin
  // handling GetSize call
  if (Origin =  soFromEnd ) and (Offset = 0) then
    Result := FTotalOut
  // handling GetPosition call
  else if (Origin =  soFromCurrent ) and (Offset = 0) then
    Result := FWritten
  else
    Result := 0;
end;

{$ifdef D_6_UP}
function TElZlibDecompressingStream.Seek(const Offset: Int64; Origin: TSeekOrigin): Int64;
begin
  if (Origin = soEnd) and (Offset = 0) then
    Result := FTotalOut
  else if (Origin = soCurrent) and (Offset = 0) then
    Result := FWritten
  else
    Result := 0;
end;
 {$endif}


{$ifndef SB_NO_COMPRESSION}
{ TElZlibCompressingStream }

constructor TElZlibCompressingStream.Create(SourceStream : TElStream; CompressionLevel: integer  =  6; Count: integer  =  0);
begin
  inherited Create;

  FDataSource := nil;
  FSourceStream := SourceStream;
  FRead := 0;
  FWritten := 0;
  SetLength(FSpool, 0);
  if Count = 0 then
    FTotalIn := SourceStream. Size  - SourceStream.Position
  else
    FTotalIn := Min(Count, SourceStream. Size  - SourceStream.Position);

  FTotalOut := 1;
  FFinalized := false;
  FOnProgress := nil;
  InitializeCompressionEx(FZlibCtx, CompressionLevel, -13); // using zlib wrapper
end;

constructor TElZlibCompressingStream.Create(Source : TElASN1DataSource;
  CompressionLevel: integer  =  6);
begin
  inherited Create;

  FDataSource := Source;
  FSourceStream := nil;
  FRead := 0;
  FWritten := 0;
  SetLength(FSpool, 0);
  FTotalIn := Source.Size;
  FTotalOut := 1;
  FFinalized := false;
  FOnProgress := nil;
  InitializeCompressionEx(FZlibCtx, CompressionLevel, -13);
end;

 destructor  TElZlibCompressingStream.Destroy;
begin
  FinalizeCompression;
  inherited;
end;


function TElZlibCompressingStream.ReadFromSpool(Buffer: pointer; Size: integer): integer;
begin
  Result := Min(Size,   Length  (FSpool));
  SBMove(FSpool[0], Buffer^, Result);
  SBMove(FSpool[Result], FSpool[0], Length(FSpool) - Result);
  SetLength(FSpool,  Length (FSpool) - Result);
end;

procedure TElZlibCompressingStream.WriteToSpool(Buffer: pointer; Size: integer);
var
  OldLen : integer;
begin
  OldLen :=  Length (FSpool);
  SetLength(FSpool, OldLen + Size);
  SBMove(Buffer^, FSpool[OldLen], Size);
end;

procedure TElZlibCompressingStream.FinalizeCompression;
var
  Buffer: ByteArray;
  Size: cardinal;
begin
  if not FFinalized then
  begin
    SetLength(Buffer, 65536);
    Size :=  Length (Buffer);
    FinalizeCompressionEx(FZLibCtx,  @Buffer[0] , Size);
    WriteToSpool( @Buffer[0] , Size);
    FFinalized := true;
  end;
end;

function TElZlibCompressingStream.Read(var Buffer; Count: Longint): Longint;
var
  Buf, OutBuf : ByteArray;
  OutSize : cardinal;
  DataLeft : integer;
  Len : integer;
  Ptr :  ^byte ;
  Cancel : TSBBoolean;
begin
  SetLength(Buf, 32768);
  SetLength(OutBuf, 40000); // enough overhead for compression
  Result := 0;
  DataLeft := Count;
  // reading data from spool
  Ptr :=  @Buffer ;
  Len := ReadFromSpool(Ptr, DataLeft);
  Inc(Ptr, Len);
  Dec(DataLeft, Len);
  Inc(FWritten, Len);
  Inc(Result, Len);
  // encrypting as much data as needed
  while DataLeft > 0 do
  begin
    if not FFinalized then
    begin
      if Assigned(FSourceStream) then
        Len := FSourceStream.Read( Buf[0] , Min(  Length  (Buf), FTotalIn - FRead))
      else
        Len := FDataSource.Read( @Buf[0] , Min(  Length  (Buf), FTotalIn - FRead), FRead);

      Inc(FRead, Len);
      Cancel := false;
      if Assigned(FOnProgress) then
        FOnProgress(Self, FTotalIn, FRead, Cancel);
      if Cancel then
        raise EElMessageError.Create(SCancelledByUser);

      if Len > 0 then
      begin
        OutSize :=   Length  (OutBuf);
        SBZlib.CompressEx(FZLibCtx, @Buf[0], Len, @OutBuf[0], OutSize);
        WriteToSpool( @OutBuf[0] , OutSize);
      end
      else
      begin
        // stream is over, finalizing
        FinalizeCompression;
      end;
    end;  

    OutSize :=   Length  (FSpool);
    Len := Min(OutSize, DataLeft);
    ReadFromSpool(Ptr, Len);
    Inc(Ptr, Len);
    Inc(FWritten, Len);
    Inc(Result, Len);
    Dec(DataLeft, Len);

    if not FFinalized then
      FTotalOut := FWritten +   Length  (FSpool) + 1 // simulating 'stream-not-ended'
    else
      FTotalOut := FWritten;

    if FFinalized and (  Length  (FSpool) = 0) then
      Break;
  end;
end;

function TElZlibCompressingStream.Write(const Buffer; Count: Longint): Longint;
begin
  Result := 0;
end;

function TElZlibCompressingStream.Seek(Offset: Longint; Origin: Word): Longint;
begin
  // handling GetSize call
  if (Origin =  soFromEnd ) and (Offset = 0) then
    Result := FTotalOut
  // handling GetPosition call
  else if (Origin =  soFromCurrent ) and (Offset = 0) then
    Result := FWritten
  else
    Result := 0;
end;

{$ifdef D_6_UP}
function TElZlibCompressingStream.Seek(const Offset: Int64; Origin: TSeekOrigin): Int64;
begin
  if (Origin = soEnd) and (Offset = 0) then
    Result := FTotalOut
  else if (Origin = soCurrent) and (Offset = 0) then
    Result := FWritten
  else
    Result := 0;
end;
 {$endif}


 {$endif SB_NO_COMPRESSION}

////////////////////////////////////////////////////////////////////////////////
// Helper functions

function CertCorrespondsToIssuer(Cert : TElX509Certificate; Issuer : TElPKCS7Issuer): boolean;
begin
  if (Issuer.IssuerType = itIssuerAndSerialNumber) then
  begin
    if CompareRDN(Cert.IssuerRDN, Issuer.Issuer) then
      Result := SerialNumberCorresponds(Cert, Issuer.SerialNumber)
    else
      Result := false;
  end
  else if (Issuer.IssuerType = itSubjectKeyIdentifier) then
  begin
    Result := CompareContent(Issuer.SubjectKeyIdentifier, Cert.Extensions.SubjectKeyIdentifier.KeyIdentifier)
  end
  else
    Result := false;
end;

////////////////////////////////////////////////////////////////////////////////
// TElMessageProcessor class

function TElMessageProcessor.EncryptRSA(const Key : ByteArray;
  Certificate : TElX509Certificate; var EncryptedKey : ByteArray) : boolean;
var
  Crypto : TElRSAPublicKeyCrypto;
  KeyMaterial : TElRSAKeyMaterial;
  Sz : integer;
begin
  Result := false;
  try
    Crypto := TElRSAPublicKeyCrypto.Create(FCryptoProviderManager, nil);
    try
      KeyMaterial := TElRSAKeyMaterial.Create(FCryptoProviderManager, nil);
      try
        KeyMaterial.Assign(Certificate.KeyMaterial);
        Crypto.KeyMaterial := KeyMaterial;
        Crypto.CryptoType := rsapktPKCS1;
        Sz := 0;
        Crypto.Encrypt(@Key[0], Length(Key), nil, Sz);
        SetLength(EncryptedKey, Sz);
        Crypto.Encrypt(@Key[0], Length(Key), @EncryptedKey[0], Sz);
        SetLength(EncryptedKey, Sz);
      finally
        FreeAndNil(KeyMaterial);
      end;
    finally
      FreeAndNil(Crypto);
    end;
    Result := true;
  except
    ;
  end;
end;

function TElMessageProcessor.EncryptRSAOAEP(const Key : ByteArray;
  Certificate : TElX509Certificate; var EncryptedKey : ByteArray) : boolean;
var
  Crypto : TElRSAPublicKeyCrypto;
  KeyMaterial : TElRSAKeyMaterial;
  Sz : integer;
begin
  Result := false;
  try
    Crypto := TElRSAPublicKeyCrypto.Create(FCryptoProviderManager, nil);
    try
      KeyMaterial := TElRSAKeyMaterial.Create(FCryptoProviderManager, nil);
      try
        KeyMaterial.Assign(Certificate.KeyMaterial);
        Crypto.KeyMaterial := KeyMaterial;
        Crypto.CryptoType := rsapktOAEP;
        Sz := 0;
        Crypto.Encrypt(@Key[0], Length(Key), nil, Sz);
        SetLength(EncryptedKey, Sz);
        Crypto.Encrypt(@Key[0], Length(Key), @EncryptedKey[0], Sz);
        SetLength(EncryptedKey, Sz);
      finally
        FreeAndNil(KeyMaterial);
      end;
    finally
      FreeAndNil(Crypto);
    end;
    Result := true;
  except
    ;
  end;
end;

{$ifdef SB_HAS_GOST}
function TElMessageProcessor.EncryptGOST2001(const Key : ByteArray;
  Certificate : TElX509Certificate; var EncryptedKey : ByteArray) : boolean;
var
  EphemeralKey : TElGOST2001KeyMaterial;
  Crypto : TElGOST2001PublicKeyCrypto;
  WCEK, UKM, MAC, PubKeyBuf : ByteArray;
  //Buf,
  TmpBuf : ByteArray;
  Tag, cTag, eTag : TElASN1ConstrainedTag;
  sTag : TElASN1SimpleTag;
  Size : TSBInteger;
begin
  { encrypting CEK , using VKO GOST 34.10-2001, RFC 4357 }
  Result := false;


    EphemeralKey := TElGOST2001KeyMaterial.Create;
    Crypto := TElGOST2001PublicKeyCrypto.Create;

    try
      EphemeralKey.ParamSet := TElGOST2001KeyMaterial(Certificate.KeyMaterial).ParamSet;
      EphemeralKey.DigestParamSet := TElGOST2001KeyMaterial(Certificate.KeyMaterial).DigestParamSet;
      EphemeralKey.EncryptionParamSet := TElGOST2001KeyMaterial(Certificate.KeyMaterial).EncryptionParamSet;
      EphemeralKey.Generate;
      Crypto.KeyMaterial := EphemeralKey;

      Size := 64;
      SetLength(PubKeyBuf, Size);
      TElGOST2001KeyMaterial(Certificate.KeyMaterial).SavePublic( @PubKeyBuf[0] , Size);

      Crypto.EphemeralKey := PubKeyBuf;

      Size := 0;
       Crypto.Encrypt( @Key[0] , Length(Key),  nil , Size);
      SetLength(WCEK, Size);
       Crypto.Encrypt( @Key[0] , Length(Key),  @WCEK[0] , Size);
      SetLength(WCEK, Size);

      if Size = 0 then
        Exit;

      MAC := Crypto.CEKMAC;
      UKM := Crypto.UKM;

      Size := 64;
      SetLength(PubKeyBuf, Size);
      EphemeralKey.SavePublic( @PubKeyBuf[0] , Size);
      if Size <> 64 then
        Exit;
    finally
      FreeAndNil(EphemeralKey);
      FreeAndNil(Crypto);
    end;

    { saving to ASN.1 structure, RFC 4357 }

    Tag := TElASN1ConstrainedTag.CreateInstance;

    try
      { GostR3410-KeyTransport }
      Tag.TagId := SB_ASN1_SEQUENCE;

      { Gost28147-89-EncryptedKey }
      cTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
      cTag.TagId := SB_ASN1_SEQUENCE;

      { encryptedKey }
      sTag := TElASN1SimpleTag(cTag.GetField(cTag.AddField(false)));
      sTag.TagId := SB_ASN1_OCTETSTRING;
      sTag.Content := {$ifndef SB_BUFFERTYPE_IS_BYTEARRAY}StringOfBytes {$endif}(WCEK);

      { macKey }
      sTag := TElASN1SimpleTag(cTag.GetField(cTag.AddField(false)));
      sTag.TagId := SB_ASN1_OCTETSTRING;
      sTag.Content := {$ifndef SB_BUFFERTYPE_IS_BYTEARRAY}StringOfBytes {$endif}(MAC);

      { GostR3410-TransportParameters }
      cTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
      cTag.TagId := SB_ASN1_A0;

      { encryptionParamSet }
      sTag := TElASN1SimpleTag(cTag.GetField(cTag.AddField(false)));
      sTag.TagId := SB_ASN1_OBJECT;
      sTag.Content := TElGOST2001KeyMaterial(Certificate.KeyMaterial).EncryptionParamSet;

      { ephemeralPublicKey }
      eTag := TElASN1ConstrainedTag(cTag.GetField(cTag.AddField(true)));
      eTag.TagId := SB_ASN1_A0;

      { algorithm identifier }
      eTag.AddField(true);
      Certificate.PublicKeyAlgorithmIdentifier.SaveToTag(TElASN1ConstrainedTag(eTag.GetField(0)));

      { public key itself }
      sTag := TElASN1SimpleTag(eTag.GetField(eTag.AddField(false)));
      sTag.TagId := SB_ASN1_BITSTRING;
      SetLength(TmpBuf, Length(PubKeyBuf) + 3);

      SBMove(PubKeyBuf, 0, TmpBuf, 3, Length(PubKeyBuf));
      TmpBuf[0] := byte(0);
      TmpBuf[1] := byte(4);
      TmpBuf[2] := byte(Length(PubKeyBuf));
      sTag.Content := TmpBuf;

      { ukm }
      sTag := TElASN1SimpleTag(cTag.GetField(cTag.AddField(false)));
      sTag.TagId := SB_ASN1_OCTETSTRING;
      sTag.Content := {$ifndef SB_BUFFERTYPE_IS_BYTEARRAY}StringOfBytes {$else}CloneArray {$endif}(UKM);

      Size := 0;
      Tag.SaveToBuffer( nil , Size);
      SetLength(EncryptedKey, Size);
      Tag.SaveToBuffer( @EncryptedKey[0] , Size);
      SetLength(EncryptedKey, Size);    

      Result := true;
    finally
      FreeAndNil(Tag);
    end;

end;

procedure TElMessageProcessor.SetGOSTParamSet(const V : ByteArray);
begin
  FGOSTParamSet := CloneArray(V);
end;
 {$endif}

function TElMessageProcessor.EncryptKey(const Key : ByteArray;
  Certificate : TElX509Certificate; var EncryptedKey : ByteArray) : boolean;
begin
  if (Certificate.PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSAOAEP) or
    ((Certificate.PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION) and FUseOAEP) then
    Result := EncryptRSAOAEP(Key, Certificate, EncryptedKey)
  else
  if Certificate.PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION then
    Result := EncryptRSA(Key, Certificate, EncryptedKey)
  {$ifdef SB_HAS_GOST}
  else
  if Certificate.PublicKeyAlgorithm = SB_CERT_ALGORITHM_GOST_R3410_2001 then
    Result := EncryptGOST2001(Key, Certificate, EncryptedKey)
   {$endif}
  else
    Result := false;
end;

function TElMessageProcessor.AlignEncrypted(const EK : ByteArray;
  Certificate : TElX509Certificate) : ByteArray;
var
  MLen, I : integer;
begin
  if FAlignEncryptedKey and
    (Length(EK) < Length(TElRSAKeyMaterial(Certificate.KeyMaterial).PublicModulus)) then
  begin
    MLen := Length(TElRSAKeyMaterial(Certificate.KeyMaterial).PublicModulus);
    I := MLen - Length(EK);
    SetLength(Result, MLen);
    FillChar(Result[0], Length(Result), 0);
    SBMove(EK, 0, Result, 0 + I, Length(EK));
  end
  else
    Result := CloneArray(EK);
end;

function TElMessageProcessor.FillRecipient(Recipient : TElPKCS7Recipient; Certificate :
  TElX509Certificate; const Key : ByteArray) : boolean;
var
  I, HashAlg : integer;
  EK : ByteArray;
  Serial : ByteArray;
  AlgID : TElRSAOAEPAlgorithmIdentifier;
begin
  Result := false;
  Recipient.Version := 0;
  Serial := GetOriginalSerialNumber(Certificate);
  Recipient.Issuer.SerialNumber := Serial;
  Recipient.Issuer.Issuer.Count := Certificate.IssuerRDN.Count;
  
  for I := 0 to Certificate.IssuerRDN.Count - 1 do
  begin
    Recipient.Issuer.Issuer.OIDs[I] := CloneArray(Certificate.IssuerRDN.OIDs[I]);
    Recipient.Issuer.Issuer.Values[I] := CloneArray(Certificate.IssuerRDN.Values[I]);
    Recipient.Issuer.Issuer.Tags[I] := Certificate.IssuerRDN.Tags[I];
    Recipient.Issuer.Issuer.Groups[I] := Certificate.IssuerRDN.Groups[I];
  end;

  if (Certificate.PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSAOAEP) or
    ((Certificate.PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION) and FUseOAEP) then
  begin
    AlgID := TElRSAOAEPAlgorithmIdentifier.Create;
    try
      HashAlg := HashAlgorithmByMGF1(TElRSAKeyMaterial(Certificate.KeyMaterial).MGFAlgorithm);

      AlgID.Assign(Certificate.PublicKeyAlgorithmIdentifier);
      AlgID.MGF := SB_CERT_MGF1;
      AlgID.MGFHashAlgorithm := HashAlg;
      AlgID.HashAlgorithm := HashAlg;
      AlgID.WriteDefaults := true; // for compatability with .NET

      Recipient.KeyEncryptionAlgorithm := SB_OID_RSAOAEP;
      Recipient.KeyEncryptionAlgorithmParams := AlgID.WriteParameters;
    finally
      FreeAndNil(AlgID);
    end;

    if not EncryptKey(Key, Certificate, EK) then
      Exit;
      
    Recipient.EncryptedKey := AlignEncrypted(EK, Certificate);
  end
  else
  if Certificate.PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION then
  begin
    Recipient.KeyEncryptionAlgorithm := GetOIDByPKAlgorithm(SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION);
    Recipient.KeyEncryptionAlgorithmParams := EmptyArray;
    if not EncryptKey(Key, Certificate, EK) then
      Exit;
    Recipient.EncryptedKey := AlignEncrypted(EK, Certificate);
  end
  {$ifdef SB_HAS_GOST}
  else
  if Certificate.PublicKeyAlgorithm = SB_CERT_ALGORITHM_GOST_R3410_2001 then
  begin
    Recipient.KeyEncryptionAlgorithmIdentifier := TElGOST3410AlgorithmIdentifier.Create;
    Recipient.KeyEncryptionAlgorithmIdentifier.Assign(Certificate.PublicKeyAlgorithmIdentifier);
    Recipient.KeyEncryptionAlgorithm := Recipient.KeyEncryptionAlgorithmIdentifier.AlgorithmOID;
    Recipient.KeyEncryptionAlgorithmParams := Recipient.KeyEncryptionAlgorithmIdentifier.WriteParameters;

    if Length(FGOSTParamSet) = 0 then
      FGOSTParamSet := TElGOST3410AlgorithmIdentifier(Certificate.PublicKeyAlgorithmIdentifier).EncryptionParamSet;

    if not EncryptKey(Key, Certificate, EK) then
      Exit;

    Recipient.EncryptedKey := EK;
  end
   {$endif}
  else
    Exit;

  Result := true;
end;

function TElMessageProcessor.DecryptKey(Certificate : TElX509Certificate;
  Recipient : TElPKCS7Recipient; var Key : ByteArray) : boolean;
var
  Alg : integer;
begin
  Alg := GetPKAlgorithmByOID(Recipient.KeyEncryptionAlgorithm);
  if Alg = SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION then
    Result := DecryptRSA(Certificate, Recipient, Key)
  else
  if Alg = SB_CERT_ALGORITHM_ID_RSAOAEP then
    Result := DecryptRSAOAEP(Certificate, Recipient, Key)
  else
  {$ifdef SB_HAS_GOST}
  if Alg = SB_CERT_ALGORITHM_GOST_R3410_2001 then
    Result := DecryptGOST2001(Certificate, Recipient, Key)
  else
   {$endif}
    Result := false;
end;

function TElMessageProcessor.ImportEncryptedSymmetricKey(Certificate : TElX509Certificate;
  Recipient : TElPKCS7Recipient; Msg : TElPKCS7Message; var Key : TElSymmetricKeyMaterial): boolean;
var
  //SymAlg : integer;
  Crypto : TElPublicKeyCrypto;
  Factory : TElPublicKeyCryptoFactory;
  KeyBuf : ByteArray;
  Material : TElKeyMaterial;
begin
  Result := false;
  try
    Factory := TElPublicKeyCryptoFactory.Create(FCryptoProviderManager, nil);
    try
      Crypto := Factory.CreateInstance(Recipient.KeyEncryptionAlgorithm);
    finally
      FreeAndNil(Factory);
    end;
    try
      Crypto.KeyMaterial := Certificate.KeyMaterial;
      KeyBuf := CloneArray(Recipient.EncryptedKey);
      Material := Crypto.DecryptKey(@KeyBuf[0], Length(KeyBuf), Msg.EnvelopedData.EncryptedContent.ContentEncryptionAlgorithm,
        Msg.EnvelopedData.EncryptedContent.ContentEncryptionAlgorithmParams);
      if not (Material is TElSymmetricKeyMaterial) then
        raise ESecureBlackboxError.Create(''); // internally handled error that moves us to the 'except' block
      Key := TElSymmetricKeyMaterial(Material);
      Result := true;
    finally
      FreeAndNil(Crypto);
    end;
  except
    Key := nil;
  end;
end;

function TElMessageProcessor.DecryptRSA(Certificate : TElX509Certificate;
  Recipient : TElPKCS7Recipient; var Key : ByteArray) : boolean;
var
  Sz : integer;
  Crypto : TElRSAPublicKeyCrypto;
  KeyMaterial : TElRSAKeyMaterial;
  EncKey : ByteArray;
begin
  Result := false;
  try
    Crypto := TElRSAPublicKeyCrypto.Create(FCryptoProviderManager, nil);
    try
      KeyMaterial := TElRSAKeyMaterial.Create(FCryptoProviderManager, nil);
      try
        KeyMaterial.Assign(Certificate.KeyMaterial);
        Crypto.KeyMaterial := KeyMaterial;
        EncKey := CloneArray(Recipient.EncryptedKey);
        Sz := 0;
        Crypto.Decrypt(@EncKey[0], Length(EncKey), nil, Sz);
        SetLength(Key, Sz);
        Crypto.Decrypt(@EncKey[0], Length(EncKey), @Key[0], Sz);
        SetLength(Key, Sz);
        Result := true;
      finally
        FreeAndNil(KeyMaterial);
      end;
    finally
      FreeAndNil(Crypto);
    end;
  except
    ;
  end;
end;

function TElMessageProcessor.DecryptRSAOAEP(Certificate : TElX509Certificate;
  Recipient : TElPKCS7Recipient; var Key : ByteArray) : boolean;
var
  Sz : integer;
  Crypto : TElRSAPublicKeyCrypto;
  KeyMaterial : TElRSAKeyMaterial;
  EncKey : ByteArray;
  AlgId : TElRSAOAEPAlgorithmIdentifier;
begin
  try
    Crypto := TElRSAPublicKeyCrypto.Create(FCryptoProviderManager, nil);
    try
      KeyMaterial := TElRSAKeyMaterial.Create(FCryptoProviderManager, nil);
      try
        KeyMaterial.Assign(Certificate.KeyMaterial);

        if Recipient.KeyEncryptionAlgorithmIdentifier is TElRSAOAEPAlgorithmIdentifier then
        begin
          AlgId := TElRSAOAEPAlgorithmIdentifier(Recipient.KeyEncryptionAlgorithmIdentifier);
          KeyMaterial.MGFAlgorithm := MGF1AlgorithmByHash(AlgId.MGFHashAlgorithm);
          KeyMaterial.HashAlgorithm := AlgId.HashAlgorithm;
        end;
        
        Crypto.KeyMaterial := KeyMaterial;
        Crypto.CryptoType := rsapktOAEP;
        EncKey := CloneArray(Recipient.EncryptedKey);
        Sz := 0;
        Crypto.Decrypt(@EncKey[0], Length(EncKey), nil, Sz);
        SetLength(Key, Sz);
        Crypto.Decrypt(@EncKey[0], Length(EncKey), @Key[0], Sz);
        SetLength(Key, Sz);
        Result := true;
      finally
        FreeAndNil(KeyMaterial);
      end;
    finally
      FreeAndNil(Crypto);
    end;
  except
    Result := false;
  end;
end;

{$ifdef SB_HAS_GOST}
function TElMessageProcessor.DecryptGOST2001(Certificate : TElX509Certificate;
  Recipient : TElPKCS7Recipient; var Key : ByteArray) : boolean;
var
  Tag, cTag : TElASN1ConstrainedTag;
  EncKey : ByteArray;
  encryptedKey, macKey : ByteArray;
  encryptionParamSet : ByteArray;
  ephemeralPubKey, ukm : ByteArray;
  ephemeralKeyAlgId : TElAlgorithmIdentifier;
  id1, id2 : TElGOST3410AlgorithmIdentifier;
  Crypto : TElGOST2001PublicKeyCrypto;
  KeySize : integer;
begin
  Result := false;
  EncKey := CloneArray(Recipient.EncryptedKey);
  Tag := TElASN1ConstrainedTag.CreateInstance;

  try
    { parsing GostR3410-KeyTransport structure }

    if Tag.LoadFromBufferSingle( @EncKey[0] , Length(EncKey)) >= 0 then
    begin
      if (Tag.Count <> 1) or (not Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
        Exit;
      cTag := TElASN1ConstrainedTag(Tag.GetField(0));
      if (cTag.Count <> 2) or (not cTag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true))
        or (not cTag.GetField(1).CheckType(SB_ASN1_A0, true)) then
          Exit;

      { processing sessionEncryptedKey }
      cTag := TElASN1ConstrainedTag(cTag.GetField(0));
      if (cTag.Count < 2) or (cTag.Count > 3) then
        Exit;

      { encryptedKey}
      if not cTag.GetField(0).CheckType(SB_ASN1_OCTETSTRING, false) then
        Exit;
      encryptedKey := TElASN1SimpleTag(cTag.GetField(0)).Content;

      { macKey }
      if not cTag.GetField(1).CheckType(SB_ASN1_OCTETSTRING, false) then
        Exit;
      macKey := TElASN1SimpleTag(cTag.GetField(1)).Content;

      { processing ephemeral key }
      cTag := TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(1));
      if (cTag.Count <> 3) then
        Exit;

      { encryptionParamSet}
      if (not cTag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) then
        Exit;
      encryptionParamSet := TElASN1SimpleTag(cTag.GetField(0)).Content;

      { ukm }
      if (not cTag.GetField(2).CheckType(SB_ASN1_OCTETSTRING, false)) then
        Exit;
      ukm := TElASN1SimpleTag(cTag.GetField(2)).Content;

      { ephemeralPublicKey }
      if (not cTag.GetField(1).CheckType(SB_ASN1_A0, true)) then
        Exit;

      { subjectPublicKey outer tag }  
      cTag := TElASN1ConstrainedTag(TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(1)).GetField(1));
      if (cTag.Count <> 2) or (not cTag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true))
        or (not cTag.GetField(1).CheckType(SB_ASN1_BITSTRING, false)) then
          Exit;
          
      ephemeralKeyAlgId := TElAlgorithmIdentifier.CreateFromTag(TElASN1ConstrainedTag(cTag.GetField(0)));

      if (not Assigned(ephemeralKeyAlgId)) then
        Exit;

      try
        if not (ephemeralKeyAlgId is TElGOST3410AlgorithmIdentifier) then
          Exit;

        id1 := TElGOST3410AlgorithmIdentifier(ephemeralKeyAlgId);
        id2 := TElGOST3410AlgorithmIdentifier(Recipient.KeyEncryptionAlgorithmIdentifier);
        if not (CompareContent(id1.PublicKeyParamSet, id2.PublicKeyParamSet) and
          CompareContent(id1.EncryptionParamSet, id2.EncryptionParamSet) and
          CompareContent(id1.DigestParamSet, id2.DigestParamSet))
        then
          Exit;        
      finally
        FreeAndNil(ephemeralKeyAlgId);
      end;

      ephemeralPubKey := TrimZeros(TElASN1SimpleTag(cTag.GetField(1)).Content);
      ephemeralPubKey := ASN1ReadSimpleValue(ephemeralPubKey, KeySize);
      if Length(ephemeralPubKey) <> 64 then
        Exit;

      { deriving content encryption key }

      Crypto := TElGOST2001PublicKeyCrypto.Create;

      try
        Crypto.KeyMaterial := Certificate.KeyMaterial;

        Crypto.EphemeralKey := ephemeralPubKey;
        Crypto.UKM := ukm;
        Crypto.CEKMAC := macKey;

        keySize := 0;
         Crypto.Decrypt( @encryptedKey[0] , Length(encryptedKey),  nil , KeySize);
        SetLength(key, keySize);
         Crypto.Decrypt( @encryptedKey[0] , Length(encryptedKey),  @Key[0] , KeySize);

        SetLength(Key, KeySize);
        Result := KeySize > 0;
      finally
        FreeAndNil(Crypto);
      end;  
    end;

  finally
    FreeAndNil(Tag);
  end;
end;
 {$endif}

function TElMessageProcessor.SignRSA(Certificate : TElX509Certificate; Digest :
  pointer; DigestSize : integer; const OID : ByteArray; var EncryptedDigest : ByteArray): boolean;
var
  Sz : integer;
  Crypto : TElRSAPublicKeyCrypto;
  KeyMaterial : TElRSAKeyMaterial;
begin
  Result := true;
  try
    Crypto := TElRSAPublicKeyCrypto.Create(FCryptoProviderManager, nil);
    try
      KeyMaterial := TElRSAKeyMaterial.Create(FCryptoProviderManager, nil);
      try
        KeyMaterial.Assign(Certificate.KeyMaterial);
        Crypto.KeyMaterial := KeyMaterial;
        Crypto.UseAlgorithmPrefix := true;
        Crypto.HashFuncOID := OID;
        Crypto.HashAlgorithm := GetAlgorithmByOID(OID);
        Crypto.CryptoType := rsapktPKCS1;
        Crypto.InputIsHash := true;
        Sz := 0;
        Crypto.SignDetached(Digest, DigestSize, nil, Sz);
        SetLength(EncryptedDigest, Sz);
        Crypto.SignDetached(Digest, DigestSize, @EncryptedDigest[0], Sz);
        SetLength(EncryptedDigest, Sz);
      finally
        FreeAndNil(KeyMaterial);
      end;
    finally
      FreeAndNil(Crypto);
    end;
  except
    Result := false;
  end;
end;

function TElMessageProcessor.DecryptRSAForSigner(Certificate : TElX509Certificate; Signer :
  TElPKCS7Signer; var Digest : ByteArray) : boolean;
var
  RSAE, RSAM : ByteArray;
  ESize, MSize, Sz : integer;
  Buf : ByteArray;
  CTag, CNewTag : TElASN1ConstrainedTag;
begin
  // This method cannot be ported to Crypto due to its (and Crypto's) specifics,
  // since it returns the digest stored in RSA signature, and this digest
  // is impossible to get via Crypto functionality. Anyway, it does not result
  // in any functionality lack.
  Result := false;
  ESize := 0;
  MSize := 0;
  Certificate.GetRSAParams(nil, MSize, nil, ESize);
  if (ESize <= 0) or (MSize <= 0) then
    Exit;
  SetLength(RSAE, ESize);
  SetLength(RSAM, MSize);
  if not Certificate.GetRSAParams(@RSAM[0], MSize, @RSAE[0], ESize) then
    Exit;
  Sz := MSize;
  SetLength(Buf, Sz);
  if not SBRSA.Decrypt(@Signer.EncryptedDigest[0], Length(Signer.EncryptedDigest),
    @RSAM[0], MSize, @RSAE[0], ESize, @Buf[0], Sz, nil) then
    Exit;
  SetLength(Buf, Sz);
  
  CTag := TElASN1ConstrainedTag.CreateInstance;
  try
    if CTag.LoadFromBuffer(@Buf[0], Sz) then
    begin
      if (CTag.Count <= 0) or (not CTag.GetField(0).IsConstrained) then
        Exit;

      CNewTag := TElASN1ConstrainedTag(CTag.GetField(0));
      if (CNewTag.TagId <> SB_ASN1_SEQUENCE) or (CNewTag.Count <> 2) then
        Exit;

      if (CNewTag.GetField(1).IsConstrained) or (CNewTag.GetField(1).TagId <> SB_ASN1_OCTETSTRING) then
        Exit;

      Digest := TElASN1SimpleTag(CNewTag.GetField(1)).Content;
    end
    else
      Digest := Buf;
  finally
    FreeAndNil(CTag);
  end;
  Result := true;
end;

function TElMessageProcessor.VerifyRSAPSS(Certificate : TElX509Certificate; Signer : TElPKCS7Signer;
  Digest : pointer; Size: integer; HashAlgorithm : integer; SaltSize : integer) : boolean;
var
  Crypto : TElRSAPublicKeyCrypto;
begin
  Result := false;
  try
    Crypto := TElRSAPublicKeyCrypto.Create(FCryptoProviderManager, nil);
    try
      Crypto.KeyMaterial := Certificate.KeyMaterial;
      Crypto.CryptoType := rsapktPSS;
      Crypto.HashAlgorithm := HashAlgorithm;
      Crypto.SaltSize := SaltSize;
      Crypto.InputIsHash := true;
      Result := Crypto.VerifyDetached(Digest, Size, @Signer.EncryptedDigest[0],
        Length(Signer.EncryptedDigest)) = pkvrSuccess;
    finally
      FreeAndNil(Crypto);
    end;
  except
    ;
  end;
end;

function TElMessageProcessor.VerifyDSA(Certificate : TElX509Certificate; Signer :
  TElPKCS7Signer; Digest : pointer; Size : integer) : boolean;
var
  Crypto : TElDSAPublicKeyCrypto;
  KeyMaterial : TElDSAKeyMaterial;
begin
  Result := false;
  try
    Crypto := TElDSAPublicKeyCrypto.Create(FCryptoProviderManager, nil);
    try
      KeyMaterial := TElDSAKeyMaterial.Create(FCryptoProviderManager, nil);
      try
        KeyMaterial.Assign(Certificate.KeyMaterial);
        Crypto.InputIsHash := true;
        Crypto.KeyMaterial := KeyMaterial;
        Result := Crypto.VerifyDetached(Digest, Size, @Signer.EncryptedDigest[0],
          Length(Signer.EncryptedDigest)) = pkvrSuccess;
      finally
        FreeAndNil(KeyMaterial);
      end;
    finally
      FreeAndNil(Crypto);
    end;
  except
    ;
  end;
end;

{$ifdef SB_HAS_ECC}
function TElMessageProcessor.VerifyECDSA(Certificate : TElX509Certificate; Signer :
  TElPKCS7Signer; Digest : pointer; Size : integer) : boolean;
var
  Crypto : TElECDSAPublicKeyCrypto;
  KeyMaterial : TElECKeyMaterial;
begin
  Result := false;
  try
    Crypto := TElECDSAPublicKeyCrypto.Create(Signer.DigestEncryptionAlgorithm, FCryptoProviderManager, nil);
    try
      KeyMaterial := TElECKeyMaterial.Create(FCryptoProviderManager, nil);
      try
        KeyMaterial.Assign(Certificate.KeyMaterial);
        Crypto.InputIsHash := true;
        Crypto.KeyMaterial := KeyMaterial;
        Crypto.HashAlgorithm := GetAlgorithmByOID(Signer.DigestAlgorithm);
        Result := Crypto.VerifyDetached(Digest, Size, @Signer.EncryptedDigest[0],
          Length(Signer.EncryptedDigest)) = pkvrSuccess;
      finally
        FreeAndNil(KeyMaterial);
      end;
    finally
      FreeAndNil(Crypto);
    end;
  except
    ;
  end;
end;
 {$endif}

{$ifdef SB_HAS_GOST}
function TElMessageProcessor.VerifyGOST2001(Certificate : TElX509Certificate; Signer :
  TElPKCS7Signer;  Digest : pointer; Size : integer ) : boolean;
var
  Crypto : TElGOST2001PublicKeyCrypto;
  KeyMaterial : TElGOST2001KeyMaterial;
begin
  Result := false;
  try
    Crypto := TElGOST2001PublicKeyCrypto.Create(Signer.DigestEncryptionAlgorithm, FCryptoProviderManager, nil);
    try
      KeyMaterial := TElGOST2001KeyMaterial.Create(FCryptoProviderManager, nil);
      try
        KeyMaterial.Assign(Certificate.KeyMaterial);
        Crypto.InputIsHash := true;
        Crypto.KeyMaterial := KeyMaterial;
        Crypto.HashAlgorithm := GetAlgorithmByOID(Signer.DigestAlgorithm);
        Result := Crypto.VerifyDetached(Digest, Size, @Signer.EncryptedDigest[0],
          Length(Signer.EncryptedDigest)) = pkvrSuccess;
      finally
        FreeAndNil(KeyMaterial);
      end;
    finally
      FreeAndNil(Crypto);
    end;
  except
    ;
  end;
end;
 {$endif}


function TElMessageProcessor.CalculateMAC(Buffer: pointer; Size: integer;
  const Key : ByteArray; var Mac : ByteArray; MacAlg : integer;
  PKCS7Data : TObject = nil; DataSource : TElASN1DataSource = nil;
  FireOnProgress: boolean = false) : boolean;
var
  KM : TElHMACKeyMaterial;
  HF : TElHashFunction;
  Offset : Int64;
  Read : integer;
  Buf : ByteArray;
  AuthData : TElPKCS7AuthenticatedData;
  I : integer;
  Total, Processed : Int64;
begin
  // the macing is done according to the following rules:
  //  * hashed is either (a) Buffer, (b) PKCS7Data content or (c) DataSource content
  //  * if Buffer is not empty, it is hashed
  //  * if DataSource is not nil, it is hashed
  //  * if PKCS7Data is not nil, it is hashed

  KM := TElHMACKeyMaterial.Create;
  KM.Key := Key;
  
  try
    HF := TElHashFunction.Create(MacAlg, KM, FCryptoProviderManager, nil);
  except
    Result := false;
    FreeAndNil(KM);
    Exit;
  end;

  try
    Result := false;

    if Buffer <> nil then
    begin
      if FireOnProgress then
      begin
        if not DoProgress(Size, 0) then
          RaiseCancelledByUserError;
      end;

      HF.Update(Buffer, Size);

      Mac := CloneArray(HF.Finish);

      if FireOnProgress then
      begin
        if not DoProgress(Size, Size) then
          RaiseCancelledByUserError;
      end;
      Result := true;
    end
    else if DataSource <> nil then
    begin
      if FireOnProgress then
      begin
        if not DoProgress(DataSource.Size, 0) then
          RaiseCancelledByUserError;
      end;

      SetLength(Buf, 65536);
      Offset := 0;
      while Offset < DataSource.Size do
      begin
        Read := DataSource.Read(@Buf[0], Length(Buf), Offset);
        Inc(Offset, Read);

        HF.Update(@Buf[0], Read);
        if FireOnProgress then
        begin
          if not DoProgress(DataSource.Size, Offset) then
            RaiseCancelledByUserError;
        end;
      end;
      ReleaseArray(Buf);

      Mac := CloneArray(HF.Finish);
      Result := true;
    end
    else if PKCS7Data is TElPKCS7AuthenticatedData then
    begin
      AuthData := TElPKCS7AuthenticatedData(PKCS7Data);
      Total := 0;
      Processed := 0;
      for I := 0 to AuthData.ContentPartCount - 1 do
        Inc(Total, AuthData.ContentParts[I].Size);
      if FireOnProgress then
      begin
        if not DoProgress(Total, 0) then
          RaiseCancelledByUserError;
      end;
      SetLength(Buf, 65536);
      for I := 0 to AuthData.ContentPartCount - 1 do
      begin
        Offset := 0;
        while Offset < AuthData.ContentParts[I].Size do
        begin
          Read := AuthData.ContentParts[I].Read(@Buf[0], Length(Buf), Offset);
          Inc(Offset, Read);
          Inc(Processed, Read);
          HF.Update(@Buf[0], Read);
          if FireOnProgress then
          begin
            if not DoProgress(Total, Processed) then
              RaiseCancelledByUserError;
          end;
        end;
      end;
      ReleaseArray(Buf);

      Mac := CloneArray(HF.Finish);
      Result := true;
    end;
  finally
    FreeAndNil(HF);
    FreeAndNil(KM);
  end;
end;

procedure TElMessageProcessor.CalculateDigests(Buffer: pointer; Size: integer;
  HashFunctions: TElList; Digests : TElByteArrayList; PKCS7Data : TObject = nil;
  DataSource : TElASN1DataSource = nil; FireOnProgress : boolean = false);
var
  I : integer;
  SignedData : TElPKCS7SignedData;
  AuthData : TElPKCS7AuthenticatedData;
  Buf :  array[0..32767] of byte ;
  Offset, Read : Int64;
  Total, Processed : Int64;
  procedure Update(Chunk: pointer; ChunkSize: integer);
  var
    K : integer;
  begin
    for K := 0 to HashFunctions.Count - 1 do
      TElHashFunction(HashFunctions[K]).Update(Chunk, ChunkSize);
  end;
begin
  // the hashing is done according to the following rules:
  //  * hashed is either (a) Buffer, (b) PKCS7Data content or (c) DataSource content
  //  * if Buffer is not empty, it is hashed
  //  * if DataSource is not nil, it is hashed
  //  * if PKCS7Data is not nil, it is hashed
  
  if (Size > 0) then
  begin
    if FireOnProgress then
    begin
      if not DoProgress(Size, 0) then
        RaiseCancelledByUserError;
    end;
    Update(Buffer, Size);
    if FireOnProgress then
    begin
      if not DoProgress(Size, Size) then
        RaiseCancelledByUserError;
    end;
  end
  else if DataSource <> nil then
  begin
    if FireOnProgress then
    begin
      if not DoProgress(DataSource.Size, 0) then
        RaiseCancelledByUserError;
    end;
    Offset := 0;
    while Offset < DataSource.Size do
    begin
      Read := DataSource.Read(@Buf[0], Length(Buf), Offset);
      Inc(Offset, Read);
      Update(@Buf[0], Read);
      if FireOnProgress then
      begin
        if not DoProgress(DataSource.Size, Offset) then
          RaiseCancelledByUserError;
      end;
    end;
  end
  else if PKCS7Data is TElPKCS7SignedData then
  begin
    SignedData := TElPKCS7SignedData(PKCS7Data);
    // calculating total data size
    Total := 0;
    Processed := 0;
    for I := 0 to SignedData.ContentPartCount - 1 do
      Inc(Total, SignedData.ContentParts[I].Size);
    if FireOnProgress then
    begin
      if not DoProgress(Total, 0) then
        RaiseCancelledByUserError;
    end;
    for I := 0 to SignedData.ContentPartCount - 1 do
    begin
      Offset := 0;
      while Offset < SignedData.ContentParts[I].Size do
      begin
        Read := SignedData.ContentParts[I].Read(@Buf[0], Length(Buf), Offset);
        Inc(Offset, Read);
        Inc(Processed, Read);
        Update(@Buf[0], Read);
        if FireOnProgress then
        begin
          if not DoProgress(Total, Processed) then
            RaiseCancelledByUserError;
        end;                        
      end;
    end;
  end
  else if PKCS7Data is TElPKCS7AuthenticatedData then
  begin
    AuthData := TElPKCS7AuthenticatedData(PKCS7Data);
    Total := 0;
    Processed := 0;
    for I := 0 to AuthData.ContentPartCount - 1 do
      Inc(Total, AuthData.ContentParts[I].Size);
    if FireOnProgress then
    begin
      if not DoProgress(Total, 0) then
        RaiseCancelledByUserError;
    end;                        
    for I := 0 to AuthData.ContentPartCount - 1 do
    begin
      Offset := 0;
      while Offset < AuthData.ContentParts[I].Size do
      begin
        Read := AuthData.ContentParts[I].Read(@Buf[0], Length(Buf), Offset);
        Inc(Offset, Read);
        Inc(Processed, Read);
        Update(@Buf[0], Read);
        if FireOnProgress then
        begin
          if not DoProgress(Total, Processed) then
            RaiseCancelledByUserError;
        end;
      end;
    end;
  end;
  Digests.Clear;
  for I := 0 to HashFunctions.Count - 1 do
    Digests.Add(TElHashFunction(HashFunctions[I]).Finish);
end;

function TElMessageProcessor.CalculateDigest(Buffer: pointer; Size: integer; Alg : integer;
  PKCS7Data : TObject = nil; DataSource : TElASN1DataSource = nil;
  FireOnProgress : boolean = false): ByteArray;
var
  FuncList : TElList;
  Func : TElHashFunction;
  Digests : TElByteArrayList;
begin
  try
    FuncList := TElList.Create;
    Digests := TElByteArrayList.Create;
    try
      Func := TElHashFunction.Create(Alg, TElCPParameters(nil), FCryptoProviderManager, nil);
      try
        FuncList.Add(Func);
        CalculateDigests(Buffer, Size,
          FuncList, Digests, PKCS7Data, DataSource, FireOnProgress);
        if Digests.Count > 0 then
          Result := CloneArray(Digests.Item[0]);
      finally
        FreeAndNil(Func);
      end;
    finally
      FreeAndNil(FuncList);
      FreeAndNil(Digests);
    end;
  except
    on E : EElMessageUserCancelledError do
      raise;
    on E : Exception do
    begin
      FErrorInfo := E. Message ;
      Result := EmptyArray;
    end;
  end;
end;

function TElMessageProcessor.DoProgress(Total, Current : Int64): boolean;
var
  Cancel : TSBBoolean;
begin
  Cancel := false;
  if Assigned(FOnProgress) then
    FOnProgress(Self, Total, Current, Cancel);
  Result := not (Cancel);
end;

procedure TElMessageProcessor.RaiseCancelledByUserError;
begin
  raise EElMessageUserCancelledError.Create(SCancelledByUser);
end;

procedure TElMessageProcessor.HandleProgress(Sender : TObject;
  Total, Current : Int64; var Cancel : TSBBoolean);
begin
  Cancel := (not DoProgress(Total, Current));
end;

procedure TElMessageProcessor.Notification(AComponent : TComponent; AOperation : TOperation);
begin
  inherited;
  if (AComponent = FCryptoProviderManager) and (AOperation = opRemove) then
    CryptoProviderManager := nil;
end;

procedure TElMessageProcessor.SetCryptoProviderManager(Value: TElCustomCryptoProviderManager);
begin
{$ifdef VCL50}
  if (FCryptoProviderManager <> nil) and (not (csDestroying in
    FCryptoProviderManager.ComponentState)) then
    FCryptoProviderManager.RemoveFreeNotification(Self);
 {$endif}
  FCryptoProviderManager := Value;
  if FCryptoProviderManager <> nil then
    FCryptoProviderManager.FreeNotification(Self)
end;

////////////////////////////////////////////////////////////////////////////////
// TElMessageDecryptor class

type
  TElPKCS7FakedIssuer = class(TElPKCS7Issuer)
  public
    constructor Create;
    destructor Destroy; override;
  end;
  //TElFakedX509Certificate = {$ifdef SB_NET}assembly{$endif} class(TElX509Certificate);

constructor TElPKCS7FakedIssuer.Create;
begin
  inherited;
end;

destructor TElPKCS7FakedIssuer.Destroy;
begin
  inherited;
end;

constructor TElMessageDecryptor.Create(AOwner : TComponent);
begin
  inherited Create (AOwner) ;
  FAlgorithm := SB_CERT_ALGORITHM_UNKNOWN;
  //FBitsInKey := 0;
  FCertIDs := TElList.Create;
  //FUseOAEP := false;
  FErrorInfo := '';
  FDecryptionOptions :=  [] ;
  FOriginatorCertificates := TElMemoryCertStorage.Create(nil);
  FOriginatorCRLs := TElMemoryCRLStorage.Create( nil );
  FUnprotectedAttributes := TElPKCS7Attributes.Create();
end;


 destructor  TElMessageDecryptor.Destroy;
begin
  ClearCertIDs;
  FreeAndNil(FCertIDs);
  FreeAndNil(FOriginatorCertificates);
  FreeAndNil(FOriginatorCRLs);
  FreeAndNil(FUnprotectedAttributes);
  inherited;
end;

function TElMessageDecryptor.Decrypt(InBuffer : pointer; InSize : integer;
  OutBuffer : pointer; var OutSize : integer) : integer;
var
  FMessage : TElPKCS7Message;
  Certificate : TElX509Certificate;
  Recipient : TElPKCS7Recipient;
  Key : ByteArray;
  CertIndex : integer;
  KeyMaterial : TElSymmetricKeyMaterial;
  B, KeyDecrypted : boolean;
begin
  CheckLicenseKey();
  FMessage := TElPKCS7Message.Create;
  FUsedCertificate := -1;
  CertIndex := -1;
  FErrorInfo := '';
  FOriginatorCertificates.Clear;
  FOriginatorCRLs.Clear;
  FUnprotectedAttributes.Count := 0;
  Recipient := nil;
  KeyMaterial := nil;
  if doNoOuterContentInfo in DecryptionOptions then
  begin
    FMessage.NoOuterContentInfo := true;
    FMessage.ContentType := ctEnvelopedData;
  end;
  Result := FMessage.LoadFromBuffer(InBuffer , InSize );
  if Result <> 0 then
  begin
    FreeAndNil(FMessage);
    Result := SB_MESSAGE_ERROR_INVALID_FORMAT;
    Exit;
  end;
  if FMessage.ContentType <>  ctEnvelopedData  then
  begin
    Result := SB_MESSAGE_ERROR_NO_ENCRYPTED_DATA;
    FreeAndNil(FMessage);
    Exit;
  end;

  if OutSize < InSize then
  begin
    OutSize := InSize;
    Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL;
    FreeAndNil(FMessage);
    Exit;
  end;

  ExtractRecipientIDs(FMessage);
  ExtractOtherInfo(FMessage);

  if (not Assigned(FCertStorage)) then
  begin
    Result := SB_MESSAGE_ERROR_NO_CERTIFICATE;
    FreeAndNil(FMessage);
    Exit;
  end;

  CertIndex := 0;
  KeyDecrypted := false;

  repeat
    Certificate := FindRecipientCertificate(FMessage, Recipient, CertIndex);
    if Certificate = nil then
    begin
      Result := SB_MESSAGE_ERROR_NO_CERTIFICATE;
      FreeAndNil(FMessage);
      Exit;
    end;
    
    if (OutSize < Length(FMessage.EnvelopedData.EncryptedContent.EncryptedContent)) then
    begin
      OutSize := Length(FMessage.EnvelopedData.EncryptedContent.EncryptedContent);
      Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL;
      FreeAndNil(FMessage);
      Exit;
    end;

    if not DecryptKey(Certificate, Recipient, Key) then
    begin
      // II 20070309: trying to import symmetric key even if it is extractable
      if true{not Certificate.PrivateKeyExtractable} then
        B := ImportEncryptedSymmetricKey(Certificate, Recipient, FMessage, KeyMaterial)
      else
        B := false;
      if not B then
        Inc(CertIndex)
      else
        KeyDecrypted := true;
    end
    else
      KeyDecrypted := true;
  until (KeyDecrypted) or (CertIndex >= FCertStorage.Count);

  if not KeyDecrypted then
  begin
    Result := SB_MESSAGE_ERROR_KEY_DECRYPTION_FAILED;
    FreeAndNil(FMessage);
    Exit;
  end;

  B := DecryptContent(FMessage.EnvelopedData.EncryptedContent, Key, KeyMaterial,
    OutBuffer, OutSize);
  if Assigned(KeyMaterial) then
    FreeAndNil(KeyMaterial);
  if not B then
  begin
    Result := SB_MESSAGE_ERROR_CONTENT_DECRYPTION_FAILED;
    FreeAndNil(FMessage);
    Exit;
  end;
  FreeAndNil(FMessage);
  FUsedCertificate := CertIndex;
  Result := 0;
end;


function TElMessageDecryptor.Decrypt(InStream, OutStream : TElStream;
  InCount : Int64  =  0): integer;
var
  FMessage : TElPKCS7Message;
  Certificate : TElX509Certificate;
  Recipient : TElPKCS7Recipient;
  Key : ByteArray;
  CertIndex : integer;
  Fake : TSBInteger;
  KeyMaterial : TElSymmetricKeyMaterial;
  B, KeyDecrypted : boolean;
begin
  CheckLicenseKey();
  FMessage := TElPKCS7Message.Create;
  FUsedCertificate := -1;
  CertIndex := -1;
  Recipient := nil;
  KeyMaterial := nil;
  FErrorInfo := '';
  FOriginatorCertificates.Clear;
  FOriginatorCRLs.Clear;
  FUnprotectedAttributes.Count := 0;
  Result := FMessage.LoadFromStream(InStream, InCount);
  if Result <> 0 then
  begin
    FreeAndNil(FMessage);
    Result := SB_MESSAGE_ERROR_INVALID_FORMAT;
    Exit;
  end;
  if FMessage.ContentType <>  ctEnvelopedData  then
  begin
    Result := SB_MESSAGE_ERROR_NO_ENCRYPTED_DATA;
    FreeAndNil(FMessage);
    Exit;
  end;

  ExtractRecipientIDs(FMessage);
  ExtractOtherInfo(FMessage);

  if (not Assigned(FCertStorage)) then
  begin
    Result := SB_MESSAGE_ERROR_NO_CERTIFICATE;
    FreeAndNil(FMessage);
    Exit;
  end;

  CertIndex := 0;
  KeyDecrypted := false;

  repeat
    Certificate := FindRecipientCertificate(FMessage, Recipient, CertIndex);
    if Certificate = nil then
    begin
      Result := SB_MESSAGE_ERROR_NO_CERTIFICATE;
      FreeAndNil(FMessage);
      Exit;
    end;

    if not DecryptKey(Certificate, Recipient, Key) then
    begin
      if true {not Certificate.PrivateKeyExtractable} then
        B := ImportEncryptedSymmetricKey(Certificate, Recipient, FMessage, KeyMaterial)
      else
        B := false;
      if not B then
        Inc(CertIndex)
      else
        KeyDecrypted := true;
    end
    else
      KeyDecrypted := true;
  until KeyDecrypted or (CertIndex >= FCertStorage.Count);

  if not KeyDecrypted then
  begin
    Result := SB_MESSAGE_ERROR_KEY_DECRYPTION_FAILED;
    FreeAndNil(FMessage);
    Exit;
  end;

  B := DecryptContent(FMessage.EnvelopedData.EncryptedContent, Key, KeyMaterial,
     nil , Fake, OutStream);
  if Assigned(KeyMaterial) then
    FreeAndNil(KeyMaterial);
  if not B then
  begin
    Result := SB_MESSAGE_ERROR_CONTENT_DECRYPTION_FAILED;
    FreeAndNil(FMessage);
    Exit;
  end;
  
  FreeAndNil(FMessage);
  FUsedCertificate := CertIndex;
  Result := 0;
end;

function TElMessageDecryptor.Decrypt(InBuffer : pointer; InSize : integer;
  OutBuffer : pointer; var OutSize : integer; Key : pointer;
  KeySize : integer) : integer;
var
  FMessage : TElPKCS7Message;
  StrKey : ByteArray;
begin
  CheckLicenseKey();
  FMessage := TElPKCS7Message.Create;
  FUsedCertificate := -1;
  FErrorInfo := '';
  FOriginatorCertificates.Clear;
  FOriginatorCRLs.Clear;
  FUnprotectedAttributes.Count := 0;
  Result := FMessage.LoadFromBuffer(InBuffer , InSize );
  if Result <> 0 then
  begin
    FreeAndNil(FMessage);
    Result := SB_MESSAGE_ERROR_INVALID_FORMAT;
    Exit;
  end;
  
  if FMessage.ContentType <>  ctEncryptedData  then
  begin
    Result := SB_MESSAGE_ERROR_NO_ENCRYPTED_DATA;
    FreeAndNil(FMessage);
    Exit;
  end;

  if OutSize < InSize then
  begin
    OutSize := InSize;
    Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL;
    FreeAndNil(FMessage);
    Exit;
  end;

  ClearCertIDs;
  if FMessage.EncryptedData.Version > 2 then
  begin
    Result := SB_MESSAGE_ERROR_INVALID_FORMAT;
    FreeAndNil(FMessage);
    Exit; 
  end;
  
  if not CompareContent(FMessage.EncryptedData.EncryptedContent.ContentType, SB_OID_PKCS7_DATA) then
  begin
    Result := SB_MESSAGE_ERROR_NO_ENCRYPTED_DATA;
    FreeAndNil(FMessage);
    Exit;
  end;
  SetLength(StrKey, KeySize);
  SBMove(Key^, StrKey[0], Length(StrKey));
  if DecryptContent(FMessage.EncryptedData.EncryptedContent, StrKey, nil, OutBuffer,
    OutSize) then
    Result := 0
  else
    Result := SB_MESSAGE_ERROR_CONTENT_DECRYPTION_FAILED;
end;


function TElMessageDecryptor.Decrypt(InStream : TStream; OutStream : TStream;
   Key: pointer; KeySize : integer ;
  InCount : Int64 = 0): integer;
var
  FMessage : TElPKCS7Message;
  StrKey : ByteArray;
  Fake: TSBInteger;
begin
  CheckLicenseKey();
  FMessage := TElPKCS7Message.Create;
  FUsedCertificate := -1;
  FErrorInfo := '';
  FOriginatorCertificates.Clear;
  FOriginatorCRLs.Clear;
  FUnprotectedAttributes.Count := 0;
  Result := FMessage.LoadFromStream(InStream, InCount);
  if Result <> 0 then
  begin
    FreeAndNil(FMessage);
    Result := SB_MESSAGE_ERROR_INVALID_FORMAT;
    Exit;
  end;
  
  if FMessage.ContentType <>  ctEncryptedData  then
  begin
    Result := SB_MESSAGE_ERROR_NO_ENCRYPTED_DATA;
    FreeAndNil(FMessage);
    Exit;
  end;

  ClearCertIDs;
  if FMessage.EncryptedData.Version > 2 then
  begin
    Result := SB_MESSAGE_ERROR_INVALID_FORMAT;
    FreeAndNil(FMessage);
    Exit; 
  end;
  
  if not CompareContent(FMessage.EncryptedData.EncryptedContent.ContentType, SB_OID_PKCS7_DATA) then
  begin
    Result := SB_MESSAGE_ERROR_NO_ENCRYPTED_DATA;
    FreeAndNil(FMessage);
    Exit;
  end;
  SetLength(StrKey, KeySize);
  SBMove(Key^, StrKey[0], Length(StrKey));
  if DecryptContent(FMessage.EncryptedData.EncryptedContent, StrKey, nil,
     nil , Fake,
    OutStream) then
    Result := 0
  else
    Result := SB_MESSAGE_ERROR_CONTENT_DECRYPTION_FAILED;
end;

function TElMessageDecryptor.FindRecipientCertificate(Msg : TElPKCS7Message;
  var Recipient : TElPKCS7Recipient; var CertIndex : integer): TElX509Certificate;
var
  I, J : integer;
begin 
  Result := nil;
  for I := 0 to Msg.EnvelopedData.RecipientCount - 1 do
  begin
    for J := CertIndex to FCertStorage.Count - 1 do
    begin
      if FCertStorage.Certificates[J].PrivateKeyExists and
        CertCorrespondsToIssuer(FCertStorage.Certificates[J], Msg.EnvelopedData.Recipients[I].Issuer) then
      begin
        Result := FCertStorage.Certificates[J];
        Recipient := Msg.EnvelopedData.Recipients[I];
        CertIndex := J;
        Exit;
      end;
    end;
  end;
end;

procedure TElMessageDecryptor.ExtractRecipientIDs(Msg : TElPKCS7Message);
var
  I, J : integer;
  Issuer : TElPKCS7Issuer;
begin
  ClearCertIDs;
  for I := 0 to Msg.EnvelopedData.RecipientCount - 1 do
  begin
    Issuer := TElPKCS7FakedIssuer.Create;
    Issuer.SerialNumber := Msg.EnvelopedData.Recipients[I].Issuer.SerialNumber;
    Issuer.Issuer.Count := Msg.EnvelopedData.Recipients[I].Issuer.Issuer.Count;
    for J := 0 to Msg.EnvelopedData.Recipients[I].Issuer.Issuer.Count - 1 do
    begin
      Issuer.Issuer.OIDs[J] := Msg.EnvelopedData.Recipients[I].Issuer.Issuer.OIDs[J];
      Issuer.Issuer.Values[J] := Msg.EnvelopedData.Recipients[I].Issuer.Issuer.Values[J];
      Issuer.Issuer.Tags[J] := Msg.EnvelopedData.Recipients[I].Issuer.Issuer.Tags[J];
      Issuer.Issuer.Groups[J] := Msg.EnvelopedData.Recipients[I].Issuer.Issuer.Groups[J]
    end;
    FCertIDs.Add(Issuer);
  end;
  if Assigned(FOnCertIDs) then
    FOnCertIDs(Self, FCertIDs);
end;

procedure TElMessageDecryptor.ExtractOtherInfo(Msg : TElPKCS7Message);
var
  I : integer;
begin
  for I := 0 to Msg.EnvelopedData.OriginatorCertificates.Count - 1 do
    FOriginatorCertificates.Add(Msg.EnvelopedData.OriginatorCertificates.Certificates[I]);
  for I := 0 to Msg.EnvelopedData.OriginatorCRLs.Count - 1 do
    FOriginatorCRLs.Add(Msg.EnvelopedData.OriginatorCRLs.CRLs[I]);
  Msg.EnvelopedData.UnprotectedAttributes.Copy(FUnprotectedAttributes);
end;

procedure TElMessageDecryptor.DecryptProgressFunc(Sender : TObject;
  Total, Current : Int64; var Cancel : TSBBoolean);
begin
  Cancel := false;
  if Assigned(FOnProgress) then
    FOnProgress(Self, Total, Current, Cancel);
end;

{$ifdef SB_HAS_GOST}
function TElMessageDecryptor.ExtractGOSTKeyParameters(Content : TElPKCS7EncryptedContent;
  var ParamSet : ByteArray; var IV : ByteArray): boolean;
var
  Tag, cTag : TElASN1ConstrainedTag;
begin
  Result := false;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if not Tag.LoadFromBuffer(@Content.ContentEncryptionAlgorithmParams[0],
      Length(Content.ContentEncryptionAlgorithmParams)) then
      Exit;

    if (Tag.Count <> 1) or not Tag.GetField(0).IsConstrained then
      Exit;

    cTag := TElASN1ConstrainedTag(Tag.GetField(0));

    if (cTag.Count <> 2) or (not cTag.GetField(0).CheckType(SB_ASN1_OCTETSTRING, false))
      or (not cTag.GetField(1).CheckType(SB_ASN1_OBJECT, false))
    then
      Exit;

    IV := TElASN1SimpleTag(cTag.GetField(0)).Content;
    ParamSet := TElASN1SimpleTag(cTag.GetField(1)).Content;

    Result := true;
  finally
    FreeAndNil(Tag);
  end;
end;
 {$endif}

function TElMessageDecryptor.ExtractRC2KeyParameters(Content : TElPKCS7EncryptedContent;
  const Key : ByteArray; var IV : ByteArray): boolean;
var
  Tag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  Tmp : integer;
begin
  Result := false;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    SetLength(IV, 8);
    if not Tag.LoadFromBuffer(@Content.ContentEncryptionAlgorithmParams[0],
      Length(Content.ContentEncryptionAlgorithmParams)) then
      Exit;
    if Tag.Count < 1 then
      Exit;
    if Tag.GetField(0).IsConstrained then
    begin
      if (Tag.GetField(0).TagId <> SB_ASN1_SEQUENCE) or (TElASN1ConstrainedTag(Tag.GetField(0)).Count <> 2) then
        Exit;
      if (TElASN1ConstrainedTag(Tag.GetField(0)).GetField(0).IsConstrained <> false) or
        (TElASN1ConstrainedTag(Tag.GetField(0)).GetField(1).IsConstrained <> false) then
        Exit;
      STag := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(0));
      if (STag.TagId <> SB_ASN1_INTEGER) then
        Exit;
      Tmp := GetRC2KeyLengthByIdentifier(STag.Content) shr 3;
      STag := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(0)).GetField(1));
      if (STag.TagId <> SB_ASN1_OCTETSTRING) then
        Exit;
      if Length(STag.Content) <> 8 then
        Exit;
      if Length(Key) <> Tmp then
        Exit;

      SBMove(STag.Content, 0, IV, 0, 8);
    end
    else
    begin
      STag := TElASN1SimpleTag(Tag.GetField(0));
      if STag.TagId <> SB_ASN1_OCTETSTRING then
        Exit;
      if Length(STag.Content) <> 8 then
        Exit;
      if Length(Key) <> 4 then
        Exit;

      SBMove(STag.Content, 0, IV, 0, 8);
    end;
    Result := true;
  finally
    FreeAndNil(Tag);
  end;
end;

function TElMessageDecryptor.DecryptContent(Content : TElPKCS7EncryptedContent;
  const Key : ByteArray; KeyMaterial : TElSymmetricKeyMaterial; OutBuffer : pointer; var OutSize : integer;
  OutStream : TStream = nil) : boolean;
const
  BLOCK_SIZE = 32768;
var
  Alg : integer;
  IV : ByteArray;
  Factory : TElSymmetricCryptoFactory;
  Crypto : TElSymmetricCrypto;
  ExternalKeyMaterialUsed : boolean;
  I : integer;
  InBuf, OutBuf : ByteArray;
  ChunkOutSize : integer;
  CurrOffset, CurrOutOffset : Int64;
  Read : Int64;
  Needed : Int64;
  Total : Int64;
  Mode : TSBSymmetricCryptoMode;
  {$ifdef SB_HAS_GOST}
  GOSTParamSet : ByteArray;
   {$endif}
begin
  if OutStream = nil then
  begin
    Needed := 0;
    for I := 0 to Content.EncryptedContentPartCount - 1 do
      Inc(Needed, Content.EncryptedContentParts[I].Size);
    if Needed > OutSize then
    begin
      OutSize := Needed;
      Result := false;
      Exit;
    end;
  end;
  Alg := GetAlgorithmByOID(Content.ContentEncryptionAlgorithm);
  FAlgorithm := Alg;
  FBitsInKey := Length(Key) shl 3;
  ExternalKeyMaterialUsed := Assigned(KeyMaterial);
  Result := false;
  try
    //if not ExternalKeyMaterialUsed then
    begin
      Factory := TElSymmetricCryptoFactory.Create();
      try
        Factory.CryptoProviderManager := FCryptoProviderManager;
        {$ifdef SB_HAS_GOST}
        if FAlgorithm = SB_ALGORITHM_CNT_GOST_28147_1989 then
          Mode := cmCFB8
        else  
         {$endif}
        if FAlgorithm <> SB_ALGORITHM_CNT_RC4 then
          Mode := cmCBC
        else
          Mode := cmDefault;
        Crypto := Factory.CreateInstance(Content.ContentEncryptionAlgorithm, Mode);
      finally
        FreeAndNil(Factory);
      end;
    end;
    //else
    //  Crypto := TElSymmetricCrypto.Create({$ifdef SB_NET}TSBSymmetricCryptoMode.{$endif}cmDefault);
    if Crypto = nil then
      Exit;
    try
      if KeyMaterial = nil then
        KeyMaterial := TElSymmetricKeyMaterial.Create();
      try
        if not ExternalKeyMaterialUsed then
        begin
          KeyMaterial.Key := Key;

          {$ifdef SB_HAS_GOST}
          if (Alg = SB_ALGORITHM_CNT_GOST_28147_1989) then
          begin
            if not ExtractGOSTKeyParameters(Content, GOSTParamSet, IV) then
              Exit;

            TElGOST28147SymmetricCrypto(Crypto).ParamSet := GOSTParamSet;
            TElGOST28147SymmetricCrypto(Crypto).UseKeyMeshing := true;
          end
          else
           {$endif}
          if (Alg <> SB_ALGORITHM_CNT_RC4) and (Alg <> SB_ALGORITHM_CNT_RC2) then
          begin
            if Length(Content.ContentEncryptionAlgorithmParams) < Crypto.BlockSize then
              Exit;
            SetLength(IV, Crypto.BlockSize);
            SBMove(Content.ContentEncryptionAlgorithmParams[Length(Content.ContentEncryptionAlgorithmParams) - Crypto.BlockSize],
              IV[0], Crypto.BlockSize);
          end
          else if Alg = SB_ALGORITHM_CNT_RC2 then
          begin
            if not ExtractRC2KeyParameters(Content, Key, IV) then
              Exit;
          end
          else
            SetLength(IV, 0);
          KeyMaterial.IV := IV;
        end;

        Crypto.KeyMaterial := KeyMaterial;
        Crypto.Padding := cpPKCS5;
        Crypto.OnProgress  :=  DecryptProgressFunc;
        Crypto.InitializeDecryption;
        SetLength(InBuf, BLOCK_SIZE);
        SetLength(OutBuf, BLOCK_SIZE);
        CurrOutOffset := 0;
        Total := 0;
        for I := 0 to Content.EncryptedContentPartCount - 1 do
          Inc(Total, Content.EncryptedContentParts[I].Size);
        for I := 0 to Content.EncryptedContentPartCount - 1 do
        begin
          CurrOffset := 0;
          while CurrOffset < Content.EncryptedContentParts[I].Size do
          begin
            Read := Content.EncryptedContentParts[I].Read(@InBuf[0], Length(InBuf), CurrOffset);
            Inc(CurrOffset, Read);

            ChunkOutSize := Length(OutBuf);
            Crypto.DecryptUpdate(@InBuf[0], Read, @OutBuf[0], ChunkOutSize);
            if OutStream = nil then
              SBMove(OutBuf[0], PByteArray(OutBuffer)[CurrOutOffset], ChunkOutSize)
            else
              OutStream.Write(OutBuf[0], ChunkOutSize);
            Inc(CurrOutOffset, ChunkOutSize);
            if not DoProgress(Total, CurrOutOffset) then
              RaiseCancelledByUserError;
          end;
        end;
        ChunkOutSize := Length(OutBuf);
        Crypto.FinalizeDecryption(@OutBuf[0], ChunkOutSize);
        if OutStream = nil then
        begin
          SBMove(OutBuf[0], PByteArray(OutBuffer)[CurrOutOffset], ChunkOutSize);
          OutSize := CurrOutOffset + ChunkOutSize;
        end
        else
          OutStream.Write(OutBuf[0], ChunkOutSize);
        Result := true;
      finally
        if not ExternalKeyMaterialUsed then
          FreeAndNil(KeyMaterial);
      end;
    finally
      FreeAndNil(Crypto);
    end;
  except
    ;
  end;
end;

function TElMessageDecryptor.GetRC2KeyLengthByIdentifier(const Id : ByteArray) : cardinal;
begin
    if Length(Id) > 1 then
      Result := RC2Identifiers2KeyLength[PByte(@Id[Length(Id) - 1 + 0])^]
    else
    if Length(Id) = 1 then
      Result := RC2Identifiers2KeyLength[PByte(@Id[0])^]
  else
    Result := RC2Identifiers2KeyLength[0];

end;

procedure TElMessageDecryptor.SetCertStorage(Value : TElCustomCertStorage);
begin
  FCertStorage := Value;
  if FCertStorage <> nil then
    FCertStorage.FreeNotification(Self);
end;

procedure TElMessageDecryptor.Notification(AComponent : TComponent; AOperation :
  TOperation);
begin
  inherited;
  if (AComponent = FCertStorage) and (AOperation = opRemove) then
    CertStorage := nil;
end;

function TElMessageDecryptor. GetCertIDs (Index : integer) : TElPKCS7Issuer;
begin
  if (Index >= 0) and (Index < FCertIDs.Count) then
    Result := TElPKCS7Issuer(FCertIDs[Index])
  else
    Result := nil;
end;

procedure TElMessageDecryptor.ClearCertIDs;
var
  I : integer;
begin
  for I := 0 to FCertIDs.Count - 1 do
    TElPKCS7Issuer(FCertIDs[I]).Free;
  FCertIDs.Clear;
end;

function TElMessageDecryptor.GetCertIDCount : integer;
begin
  Result := FCertIDs.Count;
end;

function TElMessageDecryptor.GetUsedCertificate : integer;
begin
  Result := FUsedCertificate;
end;


class function TElMessageDecryptor.IsConventionallyEncrypted(Buffer: pointer;
  Size: integer): boolean;
var
  FMessage : TElPKCS7Message;
  R : integer;
begin
  CheckLicenseKey();
  FMessage := TElPKCS7Message.Create;
  R := FMessage.LoadFromBuffer(Buffer , Size );
  if R = 0 then
    Result := FMessage.ContentType =  ctEncryptedData 
  else
    Result := false;
    
  FreeAndNil(FMessage);
end;

////////////////////////////////////////////////////////////////////////////////
// TElMessageEncryptor

constructor TElMessageEncryptor.Create(AOwner : TComponent);
var
  S : ByteArray;
{$ifdef WIN32}
  C : cardinal;
 {$else}
  C,
 {$endif}
  D :  double ;
begin
  inherited Create  (AOwner) ;
  FRandom := TElRandom.Create;
  SetLength(S, 12);
{$ifdef CLX_USED}
  C := Now;
  D := Now;
 {$else}
  C := GetTickCount;
  D := Now;
 {$endif}
  SBMove(PByteArray(@C)[0], S[0], 4);
  SBMove(PByteArray(@D)[0], S[0 + 4], 8);
  FRandom.Randomize(S);
  Algorithm := SB_ALGORITHM_CNT_3DES; // in order to preserve compatibility with Win32
  fUseUndefSize := true;
  FUseOAEP := false;
  FUseImplicitContentEncoding := false;
  FErrorInfo := '';
  FEncryptionOptions :=  [ eoIgnoreSupportedWin32Algorithms ] ;
  FOriginatorCertificates := nil;
  FOriginatorCRLs := nil;
  FUnprotectedAttributes := TElPKCS7Attributes.Create();
end;


 destructor  TElMessageEncryptor.Destroy;
begin
  FreeAndNil(FUnprotectedAttributes);
  FreeAndNil(FRandom);
  inherited;
end;

procedure TElMessageEncryptor.SetCertStorage(Value : TElCustomCertStorage);
begin
  FCertStorage := Value;
  if FCertStorage <> nil then
    FCertStorage.FreeNotification(Self);
end;

procedure TElMessageEncryptor.SetOriginatorCertificates(Value: TElCustomCertStorage);
begin
  FOriginatorCertificates := Value;
  if FOriginatorCertificates <> nil then
    FOriginatorCertificates.FreeNotification(Self);
end;

procedure TElMessageEncryptor.SetOriginatorCRLs(Value: TElCustomCRLStorage);
begin
  FOriginatorCRLs := Value;
  if FOriginatorCRLs <> nil then
    FOriginatorCRLs.FreeNotification(Self);
end;

procedure TElMessageEncryptor.Notification(AComponent : TComponent; AOperation :
  TOperation);
begin
  inherited;
  if (AComponent = FCertStorage) and (AOperation = opRemove) then
    CertStorage := nil;
  if (AComponent = FOriginatorCertificates) and (AOperation = opRemove) then
    OriginatorCertificates := nil;
  if (AComponent = FOriginatorCRLs) and (AOperation = opRemove) then
    OriginatorCRLs := nil;
end;

function TElMessageEncryptor.AdjustKeyAndIVLengths(var Key, IV : ByteArray): boolean;
var
  Fac : TElSymmetricCryptoFactory;
  KeyLen, BlockLen : integer;
  FixedLenAlg : boolean;
  MinSize, MaxSize : integer;
  ActualKeyLen : integer;
begin

  FixedLenAlg := false;

  case FAlgorithm of
    SB_ALGORITHM_CNT_RC2:
    begin
      MinSize := 40;
      MaxSize := 240;
    end;
    SB_ALGORITHM_CNT_RC4:
    begin
      MinSize := 40;
      MaxSize := 256;
    end;
    SB_ALGORITHM_CNT_BLOWFISH:
    begin
      MinSize := 32;
      MaxSize := 448;
    end;
    SB_ALGORITHM_CNT_CAMELLIA :
    begin
      MinSize := 128;
      MaxSize := 256;
    end;
    SB_ALGORITHM_CNT_SERPENT :
    begin
      MinSize := 128;
      MaxSize := 256;
    end;
    SB_ALGORITHM_CNT_TWOFISH :
    begin
      MinSize := 128;
      MaxSize := 256;
    end;
  else
    begin
      FixedLenAlg := true;
      MinSize := 8;
      MaxSize := 512;
    end;
  end;

  Fac := TElSymmetricCryptoFactory.Create();
  try
    Fac.CryptoProviderManager := FCryptoProviderManager;
    Result := Fac.GetDefaultKeyAndBlockLengths(FAlgorithm, KeyLen, BlockLen);
  finally
    FreeAndNil(Fac)
  end;

  if (not FixedLenAlg) then
  begin
    if (FBitsInKey and 7) <> 0 then
      FBitsInKey := (FBitsInKey shr 3) shl 3;

(*    if (FBitsInKey mod 8) <> 0 then
      FBitsInKey := (FBitsInKey div 8) * 8;
*)
    if (FBitsInKey < MinSize) or (FBitsInKey > MaxSize) then
      raise EElMessageError.Create(SInvalidKeyLength);
    ActualKeyLen := FBitsInKey shr 3;
  end
  else
    ActualKeyLen := KeyLen;

  SetLength(Key, ActualKeyLen);
  SetLength(IV, BlockLen);
end;

function TElMessageEncryptor.CalculateEstimatedSize(InSize: integer): integer;
var
  TotalSize : integer;
  SupportedAlgs : array of TSBArrayOfPairs;
  I, J : integer;
  //Sz,
  //Index : integer;
  Alg, Bits : integer;
begin
  { Counting estimated size of outgoing message at the same time looking for win32 certs }
  Bits := 0;
  TotalSize := 0;
  SetLength(SupportedAlgs, 0);
  for I := 0 to FCertStorage.Count - 1 do
  begin
    if FCertStorage.Certificates[I].KeyMaterial is TElRSAKeyMaterial then
    begin
      Inc(TotalSize, TElRSAKeyMaterial(FCertStorage.Certificates[I].KeyMaterial).Bits shr 3);
      for J := 0 to FCertStorage.Certificates[I].IssuerRDN.Count - 1 do
        TotalSize := TotalSize + Length(FCertStorage.Certificates[I].IssuerRDN.OIDs[J]) +
          Length(FCertStorage.Certificates[I].IssuerRDN.Values[J]) +
          Length(FCertStorage.Certificates[I].SerialNumber);
      Inc(TotalSize, FCertStorage.Certificates[I].IssuerRDN.Count * 20);

    end
    {$ifdef SB_HAS_GOST}
    else if FCertStorage.Certificates[I].KeyMaterial is TElGOST2001KeyMaterial then
    begin
      TotalSize := TotalSize + 320; // should be enough
    end
     {$endif}
  end;
  if  
    (not (eoIgnoreSupportedWin32Algorithms in EncryptionOptions)) then
  begin
    {$ifndef BUILDER_USED}
    Alg := ChooseEncryptionAlgorithm(SupportedAlgs, Bits);
     {$else}
    Alg := ChooseEncryptionAlgorithm(@SupportedAlgs[0], Length(SupportedAlgs), Bits);
     {$endif}
    FBitsInKey := Bits;
    FAlgorithm := Alg;
  end;
  if FOriginatorCertificates <> nil then
    for I := 0 to FOriginatorCertificates.Count - 1 do
    begin
      Inc(TotalSize, FOriginatorCertificates.Certificates[I].CertificateSize);
      Inc(TotalSize, 32);
    end;
  if FOriginatorCRLs <> nil then
    for I := 0 to FOriginatorCRLs.Count - 1 do
    begin
      J := 0;
      FOriginatorCRLs.CRLs[I].SaveToBuffer( nil , J);
      Inc(TotalSize, J);
      Inc(TotalSize, 32);
    end;
  for I := 0 to FUnprotectedAttributes.Count - 1 do
  begin
    Inc(TotalSize, Length(FUnprotectedAttributes.Attributes[I]));
    for J := 0 to FUnprotectedAttributes.Values[I].Count - 1 do
    begin
      Inc(TotalSize, Length(FUnprotectedAttributes.Values[I].Item[J]));
      Inc(TotalSize, 16);
    end;
    Inc(TotalSize, 16);
  end;                 
  Inc(TotalSize, InSize);
  Inc(TotalSize, 512);
  Result := TotalSize;
end;

procedure TElMessageEncryptor.SetupAlgorithmParams(EnvData: TElPKCS7EnvelopedData;
  const Key, IV : ByteArray);
{$ifdef SB_HAS_GOST}
var
  Tag : TElASN1ConstrainedTag;
  sTag : TElASN1SimpleTag;
  Buf : ByteArray;
  Size : integer;
 {$endif}
begin
  if FAlgorithm = SB_ALGORITHM_CNT_RC2 then
    EnvData.EncryptedContent.ContentEncryptionAlgorithmParams := FillRC2Params(Length(Key), IV)
  else
  if FAlgorithm = SB_ALGORITHM_CNT_RC4 then
    EnvData.EncryptedContent.ContentEncryptionAlgorithmParams := BytesOfString(#5#0)
  else
  {$ifdef SB_HAS_GOST}
  if FAlgorithm = SB_ALGORITHM_CNT_GOST_28147_1989 then
  begin
    Tag := TElASN1ConstrainedTag.CreateInstance;

    try
      Tag.TagId := SB_ASN1_SEQUENCE;
      sTag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      sTag.TagId := SB_ASN1_OCTETSTRING; 
      sTag.Content := IV;
      sTag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      sTag.TagId := SB_ASN1_OBJECT;
      sTag.Content := FGOSTParamSet;

      Size := 0;
      Tag.SaveToBuffer( nil , Size);
      SetLength(Buf, Size);
      Tag.SaveToBuffer( @Buf[0] , Size);
      SetLength(Buf, Size);

      EnvData.EncryptedContent.ContentEncryptionAlgorithmParams := Buf;
    finally
      FreeAndNil(Tag);
    end;
  end
  else
   {$endif}
    EnvData.EncryptedContent.ContentEncryptionAlgorithmParams :=
      SBConcatArrays($4, Byte(Length(IV)), IV);
end;

procedure TElMessageEncryptor.OnEncStreamProgress(Sender : TObject;
  Total, Current : Int64; var Cancel : TSBBoolean);
begin
  Cancel := false;
  if Assigned(FOnProgress) then
    FOnProgress(Self, Total, Current, Cancel);
end;

function TElMessageEncryptor.GetAppropriateEnvDataVersion: integer;
begin
  // following the rules given in RFC5652
  // IF (originatorInfo is absent) AND
  //    (unprotectedAttrs is absent) AND
  //    (all RecipientInfo structures are version 0)
  // THEN version is 0
  // ELSE version is 2
  if ((FOriginatorCertificates = nil) or (FOriginatorCertificates.Count = 0)) and
    ((FOriginatorCRLs = nil) or (FOriginatorCRLs.Count = 0)) and (FUnprotectedAttributes.Count = 0) then
    Result := 0
  else
    Result := 2;
end;


function TElMessageEncryptor.Encrypt(InBuffer : pointer; InSize : integer;
  OutBuffer : pointer; var OutSize : integer) : integer;
var
  FMessage : TElPKCS7Message;
  EnvData : TElPKCS7EnvelopedData;
  Recipient : TElPKCS7Recipient;
  I, Index, TotalSize : integer;
  Sz : TSBInteger;
  Key, IV, Cnt : ByteArray;
begin
  CheckLicenseKey();
  FErrorInfo := '';
  if (not Assigned(FCertStorage)) or (FCertStorage.Count <= 0) then
  begin
    Result := SB_MESSAGE_ERROR_NO_RECIPIENTS;
    Exit;
  end;

  try
    TotalSize := CalculateEstimatedSize( InSize );
  except
    OutSize := 0;
    Result := SB_MESSAGE_ERROR_ENCRYPTION_FAILED;
    Exit;
  end;
  if (TotalSize > OutSize) then
  begin
    OutSize := TotalSize;
    Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL;
    Exit;
  end;

  FMessage := TElPKCS7Message.Create;
  FMessage.UseUndefSize := FUseUndefSize;
  FMessage.ContentType :=  ctEnvelopedData ;
  EnvData := FMessage.EnvelopedData;
  EnvData.Version := GetAppropriateEnvDataVersion();//0;

  if not AdjustKeyAndIVLengths(Key, IV) then
  begin
    Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
    FreeAndNil(FMessage);
    Exit;
  end;

  GenerateContentKey(@Key[0], Length(Key), @IV[0], Length(IV));

  for I := 0 to FCertStorage.Count - 1 do
  begin
    Index := EnvData.AddRecipient;
    Recipient := EnvData.Recipients[Index];
    if not FillRecipient(Recipient, FCertStorage.Certificates[I], Key) then
      EnvData.RemoveRecipient(Index);
  end;
  if EnvData.RecipientCount = 0 then
  begin
    FreeAndNil(FMessage);
    Result := SB_MESSAGE_ERROR_NO_RECIPIENTS;
    Exit;
  end;

  EnvData.ContentEncryptionAlgorithm := FAlgorithm;
  EnvData.EncryptedContent.ContentType := SB_OID_PKCS7_DATA;
  EnvData.EncryptedContent.ContentEncryptionAlgorithm := GetOIDByAlgorithm(FAlgorithm);
  EnvData.EncryptedContent.UseImplicitContentEncoding := UseImplicitContentEncoding;
  SetupAlgorithmParams(EnvData, Key, IV);

  Sz :=  InSize  + Length(IV) shl 1;
  SetLength(Cnt, Sz);
  if not EncryptContent(InBuffer, InSize, @Cnt[0], Sz, Key, IV) then
  begin
    FreeAndNil(FMessage);
    Result := SB_MESSAGE_ERROR_ENCRYPTION_FAILED;
    Exit;
  end;

  SetLength(Cnt, Sz);
  EnvData.EncryptedContent.EncryptedContent := Cnt;

  if (FOriginatorCertificates <> nil) then
    for I := 0 to FOriginatorCertificates.Count - 1 do
      EnvData.OriginatorCertificates.Add(FOriginatorCertificates.Certificates[I], false);
  if (FOriginatorCRLs <> nil) then
    for I := 0 to FOriginatorCRLs.Count - 1 do
      EnvData.OriginatorCRLs.Add(FOriginatorCRLs.CRLs[I]);
  FUnprotectedAttributes.Copy(EnvData.UnprotectedAttributes);

  Result := 0;
  if not (eoNoOuterContentInfo in EncryptionOptions) then
  begin
    if not FMessage.SaveToBuffer(OutBuffer, OutSize) then
      Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL;
  end
  else
  begin
    if not FMessage.EnvelopedData.SaveToBuffer(OutBuffer, OutSize) then
      Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL;
  end;

  FreeAndNil(FMessage);
end;

function TElMessageEncryptor.Encrypt(InStream, OutStream : TStream; InCount : Int64 = 0): integer;
var
  FMessage : TElPKCS7Message;
  EnvData : TElPKCS7EnvelopedData;
  Recipient : TElPKCS7Recipient;
  I, Index : integer;
  Key, IV : ByteArray;
  EncStream : TElStream;
begin
  CheckLicenseKey();
  FErrorInfo := '';
  if (not Assigned(FCertStorage)) or (FCertStorage.Count <= 0) then
  begin
    Result := SB_MESSAGE_ERROR_NO_RECIPIENTS;
    Exit;
  end;

  try
    CalculateEstimatedSize(0);
  except
    Result := SB_MESSAGE_ERROR_ENCRYPTION_FAILED;
    Exit;
  end;

  FMessage := TElPKCS7Message.Create;
  FMessage.UseUndefSize := FUseUndefSize;
  FMessage.ContentType :=  ctEnvelopedData ;
  EnvData := FMessage.EnvelopedData;
  EnvData.Version := GetAppropriateEnvDataVersion();//0;

  if not AdjustKeyAndIVLengths(Key, IV) then
  begin
    Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
    FreeAndNil(FMessage);
    Exit;
  end;

  GenerateContentKey(@Key[0], Length(Key), @IV[0], Length(IV));

  for I := 0 to FCertStorage.Count - 1 do
  begin
    Index := EnvData.AddRecipient;
    Recipient := EnvData.Recipients[Index];
    if not FillRecipient(Recipient, FCertStorage.Certificates[I], Key) then
      EnvData.RemoveRecipient(Index);
  end;
  if EnvData.RecipientCount = 0 then
  begin
    FreeAndNil(FMessage);
    Result := SB_MESSAGE_ERROR_NO_RECIPIENTS;
    Exit;
  end;

  EnvData.ContentEncryptionAlgorithm := FAlgorithm;
  EnvData.EncryptedContent.ContentType := SB_OID_PKCS7_DATA;
  EnvData.EncryptedContent.ContentEncryptionAlgorithm := GetOIDByAlgorithm(FAlgorithm);
  EnvData.EncryptedContent.UseImplicitContentEncoding := UseImplicitContentEncoding;
  SetupAlgorithmParams(EnvData, Key, IV);

  if (FOriginatorCertificates <> nil) then
    for I := 0 to FOriginatorCertificates.Count - 1 do
      EnvData.OriginatorCertificates.Add(FOriginatorCertificates.Certificates[I], false);
  if (FOriginatorCRLs <> nil) then
    for I := 0 to FOriginatorCRLs.Count - 1 do
      EnvData.OriginatorCRLs.Add(FOriginatorCRLs.CRLs[I]);
  FUnprotectedAttributes.Copy(EnvData.UnprotectedAttributes);
  
  try
    EncStream := CreateEncryptingStream(InStream, InCount, Key, IV);
    if EncStream <> nil then
    begin
      try
        EnvData.EncryptedContent.DataSource.Init(EncStream, 0, EncStream. Size );
        try
          FMessage.SaveToStream(OutStream);
          Result := 0;
        except
          Result := SB_MESSAGE_ERROR_CANCELLED_BY_USER;
        end;
      finally
        FreeAndNil(EncStream);
      end;
    end
    else
      Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
  except
    Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
  end;

  FreeAndNil(FMessage);
end;

function TElMessageEncryptor.Encrypt(InStream, OutStream : TStream; Key : pointer;
  KeySize : integer; InCount : Int64 = 0): integer;
var
  FMessage : TElPKCS7Message;
  EncData : TElPKCS7EncryptedData;
  KeyStr, IV : ByteArray;
  EncStream : TElStream;
begin
  CheckLicenseKey();

  FErrorInfo := '';
  FMessage := TElPKCS7Message.Create;
  FMessage.UseUndefSize := FUseUndefSize;
  FMessage.ContentType :=  ctEncryptedData ;
  EncData := FMessage.EncryptedData;
  EncData.Version := 0;

  if not AdjustKeyAndIVLengths(KeyStr, IV) then
  begin
    Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
    FreeAndNil(FMessage);
    Exit;
  end;

  if KeySize <> Length(KeyStr) then
  begin
    Result := SB_MESSAGE_ERROR_INVALID_KEY_LENGTH;
    FreeAndNil(FMessage);
    Exit;
  end;

  GenerateContentKey(@KeyStr[0], Length(KeyStr), @IV[0], Length(IV));
  SBMove(Key^, KeyStr[0], Length(KeyStr));
  EncData.EncryptedContent.ContentType := SB_OID_PKCS7_DATA;
  EncData.EncryptedContent.ContentEncryptionAlgorithm := GetOIDByAlgorithm(FAlgorithm);
  if FAlgorithm = SB_ALGORITHM_CNT_RC2 then
    EncData.EncryptedContent.ContentEncryptionAlgorithmParams := FillRC2Params(Length(KeyStr), IV)
  else
  if FAlgorithm = SB_ALGORITHM_CNT_RC4 then
    EncData.EncryptedContent.ContentEncryptionAlgorithmParams :=
      BytesOfString(#5#0)
  else
    EncData.EncryptedContent.ContentEncryptionAlgorithmParams :=
      SBConcatArrays($4, Byte(Length(IV)), IV);
  try
    EncStream := CreateEncryptingStream(InStream, InCount, KeyStr, IV);
    if EncStream <> nil then
    begin
      try
        EncData.EncryptedContent.DataSource.Init(EncStream, 0, EncStream. Size );
        try
          FMessage.SaveToStream(OutStream);
          Result := 0;
        except
          Result := SB_MESSAGE_ERROR_CANCELLED_BY_USER;
        end;
      finally
        FreeAndNil(EncStream);
      end;
    end
    else
      Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
  except
    Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
  end;

  FreeAndNil(FMessage);
end;

function TElMessageEncryptor.Encrypt(InBuffer : pointer; InSize : integer;
  OutBuffer : pointer; var OutSize : integer; Key : pointer; KeySize : integer) : integer;
var
  FMessage : TElPKCS7Message;
  EncData : TElPKCS7EncryptedData;
  TotalSize : integer;
  Sz : TSBInteger;
  KeyStr, IV, Cnt : ByteArray;
begin
  CheckLicenseKey();

  FErrorInfo := '';
  { Counting estimated size of outgoing message at the same time looking for win32 certs }
  TotalSize := 0;
  Inc(TotalSize, InSize);
  Inc(TotalSize, 400);
  if (TotalSize > OutSize) then
  begin
    OutSize := TotalSize;
    Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL;
    Exit;
  end;
  FMessage := TElPKCS7Message.Create;
  FMessage.UseUndefSize := FUseUndefSize;
  FMessage.ContentType :=  ctEncryptedData ;
  EncData := FMessage.EncryptedData;
  EncData.Version := 0;

  if not AdjustKeyAndIVLengths(KeyStr, IV) then
  begin
    Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
    FreeAndNil(FMessage);
    Exit;
  end;

  if KeySize <> Length(KeyStr) then
  begin
    Result := SB_MESSAGE_ERROR_INVALID_KEY_LENGTH;
    FreeAndNil(FMessage);
    Exit;
  end;

  GenerateContentKey(@KeyStr[0], Length(KeyStr), @IV[0], Length(IV));
  SBMove(Key^, KeyStr[0], Length(KeyStr));
  EncData.EncryptedContent.ContentType := SB_OID_PKCS7_DATA;
  EncData.EncryptedContent.ContentEncryptionAlgorithm := GetOIDByAlgorithm(FAlgorithm);
  if FAlgorithm = SB_ALGORITHM_CNT_RC2 then
    EncData.EncryptedContent.ContentEncryptionAlgorithmParams := FillRC2Params(Length(KeyStr), IV)
  else
  if FAlgorithm = SB_ALGORITHM_CNT_RC4 then
    EncData.EncryptedContent.ContentEncryptionAlgorithmParams :=
      {$ifndef SB_BUFFERTYPE_IS_BYTEARRAY}
      TByteArrayConst(#5#0)
       {$else}
      BytesOfString(#5#0)
       {$endif}
  else
    EncData.EncryptedContent.ContentEncryptionAlgorithmParams :=
      SBConcatArrays($4, Byte(Length(IV)), IV);

  Sz :=  InSize  + Length(IV) shl 1;
  SetLength(Cnt, Sz);
  if not EncryptContent(InBuffer, InSize, @Cnt[0], Sz, KeyStr, IV) then
  begin
    FreeAndNil(FMessage);
    Result := SB_MESSAGE_ERROR_ENCRYPTION_FAILED;
    Exit;
  end;
  
  SetLength(Cnt, Sz);
  EncData.EncryptedContent.EncryptedContent := Cnt;
  Result := 0;
  if not FMessage.SaveToBuffer(OutBuffer, OutSize) then
    Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL;
   
  FreeAndNil(FMessage);
end;

procedure TElMessageEncryptor.GenerateContentKey(KeyBuffer : pointer; KeySize : integer;
  IVBuffer : pointer; IVSize : integer);
{$ifdef EDI_BLACKBOX_UNIT_TEST}
const
  TestKey: array [0..31] of Byte =  ( 
    $15, $55, $f5, $50, $78, $72, $8a, $c9, $55, $cb, $c8, $53, $50, $a5, $e4, $a3,
    $18, $13, $2c, $45, $04, $70, $f8, $04, $94, $93, $a0, $fe, $34, $93, $80, $d1
   ) ;
  TestIV: array [0..15] of Byte =  ( 
    $2b, $99, $f2, $7f, $18, $02, $a8, $9e, $f0, $85, $f4, $a7, $93, $ff, $11, $eb
   ) ;
 {$endif}
var
  Par : boolean;
  I, J : integer;
begin
  {$ifdef EDI_BLACKBOX_UNIT_TEST}
  // This is used only for unit tests in EDIBlackbox
  if FAlgorithm = SB_ALGORITHM_CNT_AES256 then
  begin
    SBMove(TestKey[0], KeyBuffer^, KeySize);
    SBMove(TestIV[0], IVBuffer^, IVSize);
  end
  else
  begin
   {$endif}
  FRandom.Generate(KeyBuffer, KeySize);
  FRandom.Generate(IVBuffer, IVSize);
  if (FAlgorithm = SB_ALGORITHM_CNT_DES) or (FAlgorithm = SB_ALGORITHM_CNT_3DES) then
  begin
    // adding parity bits
    for I := 0 to  KeySize  - 1 do
    begin
      Par := false;
      for J := 0 to 7 do
        if (PByteArray(KeyBuffer)[I] and (1 shl J)) > 0 then
          Par := not Par;
      if not Par then
        PByteArray(KeyBuffer)[I] := PByteArray(KeyBuffer)[I] or 1;
    end;
  end;
  {$ifdef EDI_BLACKBOX_UNIT_TEST}
  end;
   {$endif}
end;

function TElMessageEncryptor.EncryptContent(InBuffer : pointer; InSize : integer;
  OutBuffer : pointer; var OutSize : integer; const Key : ByteArray; const IV : ByteArray) : boolean;
var
  Factory : TElSymmetricCryptoFactory;
  Crypto : TElSymmetricCrypto;
  KeyMaterial : TElSymmetricKeyMaterial;
  Md : TSBSymmetricCryptoMode;
begin
  Result := true;
  try
    Factory := TElSymmetricCryptoFactory.Create();
    try
      Factory.CryptoProviderManager := FCryptoProviderManager;
      if FAlgorithm <> SB_ALGORITHM_CNT_RC4 then
        Md := cmCBC
      else
        Md := cmDefault;
      Crypto := Factory.CreateInstance(FAlgorithm, Md);
    finally
      FreeAndNil(Factory);
    end;
    if Crypto <> nil then
    begin
      try
        KeyMaterial := TElSymmetricKeyMaterial.Create();
        try
          KeyMaterial.Key := Key;
          KeyMaterial.IV := IV;
          Crypto.KeyMaterial := KeyMaterial;
          Crypto.Padding := cpPKCS5;
          Crypto.OnProgress  :=  HandleProgress;
          Crypto.Encrypt(InBuffer, InSize, OutBuffer, OutSize);
        finally
          FreeAndNil(KeyMaterial);
        end;
      finally
        FreeAndNil(Crypto);
      end;
    end
    else
      Result := false;
  except
    Result := false;
  end;
end;

function TElMessageEncryptor.CreateEncryptingStream(Source : TElStream;
  SourceCount: Int64; const Key, IV : ByteArray): TElStream;
begin
  {$ifdef SB_HAS_GOST}
  if (FAlgorithm = SB_ALGORITHM_CNT_GOST_28147_1989) and (Length(FGOSTParamSet) > 0) then
    Result := TElChunkedEncryptingStream.Create(Source, FAlgorithm, Key, IV, FGOSTParamSet, 0, FCryptoProviderManager)
  else
   {$endif}  
  Result := TElChunkedEncryptingStream.Create(Source, FAlgorithm, Key, IV, SourceCount, FCryptoProviderManager);
  TElChunkedEncryptingStream(Result).OnProgress  :=  OnEncStreamProgress;
end;

function TElMessageEncryptor.FillRC2Params(KeyLen : integer; const IV : ByteArray) : ByteArray;
begin
  (*
  {$ifdef SB_VCL}
  if KeyLen = 4 then
    Result := TByteArrayConst(#4#8 + IV)
  else
  begin
    Result := TByteArrayConst(AnsiString(#2#2#0) + AnsiChar(RC2KeyLength2Identifiers[KeyLen shl 3]));
    Result := TByteArrayConst(Result + #4#8 + IV);
    Result := TByteArrayConst(AnsiChar(#$30) + AnsiChar(Length(Result)) + Result);
  end;
  {$else}
  if KeyLen = 4 then
    {$ifndef SB_JAVA}
    Result := TByteArrayConst(#4#8) + IV
    {$else}
    Result := SBConcatArrays(BytesOfString(#4#8), IV)
    {$endif}
  else
  begin
    {$ifndef SB_JAVA}
    Result := TByteArrayConst(#2#2#0 + Chr(RC2KeyLength2Identifiers[KeyLen shl 3]));
    Result := Result + TByteArrayConst(#4#8) + IV;
    Result := TByteArrayConst(#$30) + Chr(Length(Result)) + Result;
    {$else}
    Result := SBConcatArrays(BytesOfString(#2#2#0), GetByteArrayFromByte(Chr(RC2KeyLength2Identifiers[KeyLen shl 3])));
    Result := SBConcatArrays(Result, SBConcatArrays(BytesOfString(#4#8), IV));
    Result := SBConcatArrays(GetByteArrayFromByte(#$30), SBConcatArrays(GetByteArrayFromByte(Chr(Length(Result))), Result));
    {$endif}
  end;
  {$endif}
  *)
  if KeyLen = 4 then
    Result := SBConcatArrays(BytesOfString(#4#8), IV)
  else
  begin
    Result := SBConcatArrays(BytesOfString(#2#2#0), Byte(RC2KeyLength2Identifiers[KeyLen shl 3]));
    Result := SBConcatArrays(Result, BytesOfString(#4#8), IV);
    Result := SBConcatArrays(GetByteArrayFromByte($30), GetByteArrayFromByte(Byte(Length(Result))), Result);
  end;
end;


{$ifndef BUILDER_USED}
function TElMessageEncryptor.ChooseEncryptionAlgorithm(const Algs : array of TSBArrayOfPairs;
  var Bits : integer) : integer;
 {$else}
function TElMessageEncryptor.ChooseEncryptionAlgorithm(Algs : pointer; Count : integer;
  var Bits : integer) : integer;
 {$endif}
begin
  Result := SB_ALGORITHM_CNT_RC2;
  Bits := 40;
end;

////////////////////////////////////////////////////////////////////////////////
// TElMessageVerifier

constructor TElMessageVerifier.Create(AOwner : TComponent);
begin
  inherited Create  (AOwner) ;
  FCertificates := TElMemoryCertStorage.Create(nil);
  FAttributes := TElPKCS7Attributes.Create;
  FCertIDs := TElList.Create;
  FCSCertIDs := TElList.Create;
  FCSAttributes := TElList.Create;
  FSignatureType := mstPublicKey;
  FUsePSS := false;
  FVerifyCountersignatures := true;
  FInputIsDigest := false;
  FVerificationOptions := [voUseEmbeddedCerts, voUseLocalCerts, voVerifyMessageDigests,
    voVerifyTimestamps];
  FTimestamps := TElList.Create;
  FSigningTime :=  0 ;
  FErrorInfo := '';
end;


 destructor  TElMessageVerifier.Destroy;
begin
  FreeAndNil(FCertificates);
  FreeAndNil(FAttributes);
  ClearCertIDs;
  FreeAndNil(FCertIDs);
  FreeAndNil(FCSCertIDs);
  FreeAndNil(FCSAttributes);
  {$ifndef B_6}
  ClearTimestamps;
  FreeAndNil(FTimestamps);
   {$endif}
  inherited;
end;

procedure TElMessageVerifier.SetCertStorage(Value : TElCustomCertStorage);
begin
  FCertStorage := Value;
  if FCertStorage <> nil then
    FCertStorage.FreeNotification(Self);
end;

procedure TElMessageVerifier.Notification(AComponent : TComponent;
  AOperation : TOperation);
begin
  inherited;
  if (AComponent = FCertStorage) and (AOperation = opRemove) then
    CertStorage := nil;
end;


function TElMessageVerifier.InternalVerify(Source, Signature, Output : TElStream;
  SourceCount : Int64  =  0;
  SigCount : Int64  =  0): integer;
var
  FMessage : TElPKCS7Message;
  Tmp : ByteArray;
  I, J : integer;
  MacKey : ByteArray;
  Mac : ByteArray;
  Buffer :  array[0..65535] of byte ;
  CurrOffset : Int64;
  Read : Int64;
  DataSource : TElASN1DataSource;
  OriginalPos : Int64;
  HashFunctions : TElList;
  HashFunction : TElHashFunction;
  Digests : TElByteArrayList;
  Digest : ByteArray;
  DataStream : TElStream;
  Offset, Count : Int64;
  Succ : boolean;
  Alg : integer;
begin
  CheckLicenseKey();


  Reset;
  Result := SB_MESSAGE_ERROR_VERIFICATION_FAILED;

  FMessage := TElPKCS7Message.Create;
  if voNoOuterContentInfo in VerificationOptions then
  begin
    FMessage.NoOuterContentInfo := true;
    FMessage.ContentType := ctSignedData;
  end;
  I := FMessage.LoadFromStream(Signature, SigCount);
  if I <> 0 then
  begin
    Result := SB_MESSAGE_ERROR_INVALID_FORMAT;
    FreeAndNil(FMessage);
    Exit;
  end;
  if FMessage.ContentType = ctSignedData then
  begin
    FSignatureType := mstPublicKey;

    // extracting signing certificates
    for I := 0 to FMessage.SignedData.Certificates.Count - 1 do
      FCertificates.Add(FMessage.SignedData.Certificates.Certificates[I]{$ifndef HAS_DEF_PARAMS}, true {$endif});

    // extracting certificate ids and firing OnCertIDs
    ExtractCertificateIDs(FMessage);

    if Source <> nil then
      OriginalPos := Source.Position
    else
      OriginalPos := 0;

    // hashing source data
    try
      Digests := TElByteArrayList.Create;
      try
        HashFunctions := TElList.Create;
        try
          HashFunction := nil;
          for I := 0 to FMessage.SignedData.SignerCount - 1 do
          begin
            try
              try
                HashFunction := TElHashFunction.Create(FMessage.SignedData.Signers[I].DigestAlgorithm, TElCPParameters(nil), FCryptoProviderManager, nil);
              except
                if (voLiberalMode in VerificationOptions) then
                begin
                  // Some message creators incorrectly put digital signature algorithms here
                  // instead of hash algorithms. Checking if the algorithm is a
                  // digital signature algorithm and extracting hash algorithm
                  // from it.
                  Alg := GetAlgorithmByOID(FMessage.SignedData.Signers[I].DigestAlgorithm);
                  if Alg <> SB_ALGORITHM_UNKNOWN then
                  begin
                    Alg := GetHashAlgorithmBySigAlgorithm(Alg);
                    if Alg <> SB_ALGORITHM_UNKNOWN then
                      HashFunction := TElHashFunction.Create(Alg, TElCPParameters(nil), FCryptoProviderManager, nil)
                    else
                      raise;
                  end
                  else
                    raise;
                end
                else
                  raise;
              end;
              HashFunctions.Add(HashFunction);
            except
              Result := SB_MESSAGE_ERROR_UNSUPPORTED_DIGEST_ALGORITHM;
            end;
          end;
          if Source <> nil then
          begin
            // detached signature case
            if not InputIsDigest then
            begin
              DataSource := TElASN1DataSource.Create();
              try
                DataSource.Init(Source, OriginalPos, SourceCount);
                FAlgorithm := GetHashAlgorithmByOID(FMessage.SignedData.Signers[0].DigestAlgorithm);
                CalculateDigests(nil, 0, HashFunctions, Digests, nil, DataSource, true);
              finally
                FreeAndNil(DataSource);
              end;
            end
            else
            begin
              if SourceCount = 0 then
                SourceCount := Source. Size  - Source.Position;
              SetLength(Digest, SourceCount);
              SourceCount := Source.Read(Digest[0], Length(Digest));
              SetLength(Digest, SourceCount);
              for I := 0 to HashFunctions.Count - 1 do
                Digests.Add(Digest);
            end;
          end
          else
          begin
            // non-detached signature case
            CalculateDigests(nil, 0, HashFunctions, Digests, FMessage.SignedData, nil, true);
          end;
        finally
          for I := 0 to HashFunctions.Count - 1 do
            TElHashFunction(HashFunctions[I]).Free;
          FreeAndNil(HashFunctions);
        end;
        Result := VerifyAllSignatures(FMessage.SignedData, Digests);
      finally
        FreeAndNil(Digests);
      end;
    except
      on E : Exception do
      begin
        FErrorInfo := E. Message ;
        Result := SB_MESSAGE_ERROR_VERIFICATION_FAILED;
      end;
    end;

    if (Source = nil) and (Output <> nil) then
    begin
      // the signature is non-detached
      for I := 0 to FMessage.SignedData.ContentPartCount - 1 do
      begin
        CurrOffset := 0;
        while CurrOffset < FMessage.SignedData.ContentParts[I].Size do
        begin
          Read := FMessage.SignedData.ContentParts[I].Read(@Buffer[0], Length(Buffer), CurrOffset);
          Output.Write(Buffer[0], Read);
          Inc(CurrOffset, Read);
        end;
      end;
    end;

    if Result <> 0 then
    begin
      FreeAndNil(FMessage);
      Exit;
    end;

    // verifying message digests
    if Source <> nil then
    begin
      // detached signature
      DataStream := Source;
      Offset := OriginalPos;
      Count := SourceCount;
    end
    else if (Output <> nil) and (Output. Size  > 0) then
    begin
      // non-detached signature
      DataStream := Output;
      Offset := 0;
      Count := Output. Size ;
    end
    else
    begin
      DataStream := nil;
      Offset := 0;
      Count := 0;
    end;

    Result := VerifyMessageDigests(FMessage, DataStream, Offset, Count);
  end
  else
  if FMessage.ContentType = ctAuthenticatedData then
  begin
    FSignatureType := mstMAC;
    if (FCertStorage = nil) or (FCertStorage.Count = 0) then
    begin
      FreeAndNil(FMessage);
      Result := SB_MESSAGE_ERROR_NO_CERTIFICATE;
      Exit;
    end;

    ExtractCertificateIDs(FMessage, true);

    // checking if there's at least one recipient
    if FMessage.AuthenticatedData.RecipientCount = 0 then
    begin
      Result := SB_MESSAGE_ERROR_INVALID_FORMAT;
      FreeAndNil(FMessage);
      Exit;
    end;

    Result := ExtractMacKey(FMessage.AuthenticatedData, MacKey);
    if Result <> 0 then
    begin
      FreeAndNil(FMessage);
      Exit;
    end;

    FMessage.AuthenticatedData.AuthenticatedAttributes.Copy(FAttributes);
    FMessage.AuthenticatedData.UnauthenticatedAttributes.Copy(FAttributes);
    FMacAlgorithm := GetAlgorithmByOID(FMessage.AuthenticatedData.MacAlgorithm);

    if (FMessage.AuthenticatedData.AuthenticatedAttributes.Count > 0) then
    begin
      // calculating MAC over authenticated data...
      FMessage.AuthenticatedData.RecalculateAuthenticatedAttributes;
      Tmp := FMessage.AuthenticatedData.AuthenticatedAttributesPlain;
      if not CalculateMAC(@Tmp[0], Length(Tmp), MacKey, Mac, FMacAlgorithm) then
      begin
        FreeAndNil(FMessage);
        Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
        Exit;
      end;
      if not CompareContent(Mac, FMessage.AuthenticatedData.Mac) then
        Result := SB_MESSAGE_ERROR_INVALID_MAC
      else
      begin
        // ...and hash over content data
        try
          FAlgorithm := GetHashAlgorithmByOID(FMessage.AuthenticatedData.DigestAlgorithm);
          if Source <> nil then
          begin
            // detached signature case
            OriginalPos := Source.Position;
            DataSource := TElASN1DataSource.Create();
            try
              DataSource.Init(Source, OriginalPos, SourceCount);
              Digest := CalculateDigest(nil, 0, FAlgorithm, nil, DataSource, true);
            finally
              FreeAndNil(DataSource);
            end;
          end
          else
          begin
            // non-detached signature case
            Digest := CalculateDigest(nil, 0, FAlgorithm, FMessage.AuthenticatedData, nil, true);
          end;
        except
          on E : Exception do
          begin
            FErrorInfo := E. Message ;
            FreeAndNil(FMessage);
            Result := SB_MESSAGE_ERROR_VERIFICATION_FAILED;
            Exit;
          end;
        end;

        //Digest := CalculateDigest(Buffer, {$ifndef SB_VCL}0, Length(Buffer), {$else}Size,{$endif} FAlgorithm);
        if Length(Digest) > 0 then
        begin
          // searching for 'message-digest' authenticated attribute
          Result := SB_MESSAGE_ERROR_INVALID_DIGEST;
          for I := 0 to FMessage.AuthenticatedData.AuthenticatedAttributes.Count - 1 do
          begin
            if CompareContent(FMessage.AuthenticatedData.AuthenticatedAttributes.Attributes[I],
              SB_OID_MESSAGE_DIGEST) then
            begin
              if (FMessage.AuthenticatedData.AuthenticatedAttributes.Values[I].Count > 0) then
              begin
                Tmp := UnformatAttributeValue(FMessage.AuthenticatedData.AuthenticatedAttributes.Values[I].Item[0], J);
                if CompareContent(Tmp, Digest) then
                  Result := 0;
                ReleaseArray(Tmp);
              end;
              Break;
            end;
          end
        end
        else
          Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
      end;
    end
    else
    begin
      // no auth attributes present, calculating MAC over content data
      try
        if Source <> nil then
        begin
          // detached signature case
          OriginalPos := Source.Position;
          DataSource := TElASN1DataSource.Create();
          try
            DataSource.Init(Source, OriginalPos, SourceCount);
            Succ := CalculateMAC(nil, 0, MacKey, Mac, FMacAlgorithm, nil, DataSource, true);
          finally
            FreeAndNil(DataSource);
          end;
        end
        else
        begin
          // non-detached signature case
          Succ := CalculateMAC(nil, 0, MacKey, Mac, FMacAlgorithm, FMessage.AuthenticatedData, nil, true);
        end;
      except
        on E : Exception do
        begin
          FErrorInfo := E. Message ;
          FreeAndNil(FMessage);
          Result := SB_MESSAGE_ERROR_VERIFICATION_FAILED;
          Exit;
        end;
      end;

      if not Succ then
      begin
        Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
        Exit;
      end;
      if CompareContent(Mac, FMessage.AuthenticatedData.Mac) then
        Result := 0
      else
        Result := SB_MESSAGE_ERROR_INVALID_MAC;
    end;

    if (Source = nil) and (Output <> nil) then
    begin
      // the signature is non-detached, copying data to the output buffer
      for I := 0 to FMessage.AuthenticatedData.ContentPartCount - 1 do
      begin
        CurrOffset := 0;
        while CurrOffset < FMessage.AuthenticatedData.ContentParts[I].Size do
        begin
          Read := FMessage.AuthenticatedData.ContentParts[I].Read(@Buffer[0], Length(Buffer), CurrOffset);
          Output.Write(Buffer[0], Read);
          Inc(CurrOffset, Read);
        end;
      end;
    end;
    
  end
  else
    Result := SB_MESSAGE_ERROR_NO_SIGNED_DATA;

  ExtractValuesFromAttributes();

  FreeAndNil(FMessage);
end;

function TElMessageVerifier.Verify(InBuffer : pointer; InSize : integer;
  OutBuffer : pointer; var OutSize : integer) : integer;
var
  InStream, OutStream : TElMemoryStream;
begin
  FErrorInfo := '';
  if OutSize <  InSize  then
  begin
    Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL;
    OutSize :=  InSize ;
    Exit;
  end;
  InStream := TElMemoryStream.Create();
  try
    OutStream := TElMemoryStream.Create();
    try
      InStream.Write(InBuffer^, InSize);
      InStream.Position := 0;
      Result := InternalVerify(nil, InStream, OutStream, 0, 0);
      if OutStream. Size  <= OutSize then
      begin
        OutStream.Position := 0;
        OutSize := OutStream.Read(OutBuffer^, OutStream.Size);
      end;
    finally
      FreeAndNil(OutStream);
    end;
  finally
    FreeAndNil(InStream);
  end;
end;


function TElMessageVerifier.VerifyDetached(Buffer : pointer; Size : integer;
  Signature : pointer; SignatureSize : integer) : integer;
var
  InStream, SigStream : TElStream;
begin
  FErrorInfo := '';
  InStream := TElMemoryStream.Create();
  try
    SigStream := TElMemoryStream.Create();
    try
      InStream.Write(Buffer^, Size);
      InStream.Position := 0;
      SigStream.Write(Signature^, SignatureSize);
      SigStream.Position := 0;
      Result := InternalVerify(InStream, SigStream, nil, 0, 0);
    finally
      FreeAndNil(SigStream);
    end;
  finally
    FreeAndNil(InStream);
  end;
end;


function TElMessageVerifier.Verify(InStream, OutStream : TElStream;
  InCount : Int64  =  0): integer;
begin
  FErrorInfo := '';
  Result := InternalVerify(nil, InStream, OutStream, 0, InCount);
end;

function TElMessageVerifier.VerifyDetached(InStream, SigStream : TElStream;
  InCount : Int64  =  0;
  SigCount : Int64  =  0): integer;
begin
  FErrorInfo := '';
  Result := InternalVerify(InStream, SigStream, nil, InCount, SigCount);
end;

function TElMessageVerifier.FindSignerCertificate(Signer : TElPKCS7Signer): TElX509Certificate;
var
  Found : boolean;
  I : integer;
begin
  Found := false;
  Result := nil;
  if voUseEmbeddedCerts in FVerificationOptions then
  begin
    for I := 0 to FCertificates.Count - 1 do
    begin
      if CertCorrespondsToIssuer(FCertificates.Certificates[I], Signer.Issuer) then
      begin
        Result := FCertificates.Certificates[I];
        Found := true;
        Break;
      end;
    end;
  end;
  if not Found then
  begin
    if voUseLocalCerts in FVerificationOptions then
    begin
      if not Assigned(FCertStorage) then
        Exit;
      for I := 0 to FCertStorage.Count - 1 do
      begin
        if CertCorrespondsToIssuer(FCertStorage.Certificates[I], Signer.Issuer) then
        begin
          Result := FCertStorage.Certificates[I];
          Break;
        end;
      end;
    end;
  end;
end;

function TElMessageVerifier.VerifySingle(Signer : TElPKCS7Signer; Data : TElPKCS7SignedData;
  Digest : pointer; DigestSize : integer; DataSource : TElASN1DataSource; Countersign : boolean = false) : integer;
var
  EncAlg, DigestAlg : integer;
  Cert : TElX509Certificate;
  I, J, K : integer;

  IncomingDigest : ByteArray;
  ActualDigest : ByteArray;

  SaltSize, MGF, MGFHash, Trailer : TSBInteger;
  Countersignature : ByteArray;
  Info : TElPKCS7Signer;
  Tag : TElASN1ConstrainedTag;
  Dgst, DgstRes : ByteArray;
  TagID : integer;
  SignerInfos : TElList;
  Issuer : TElPKCS7FakedIssuer;
  HashFunc : TElHashFunction;
  AttrHash : ByteArray;
  CSResult : integer;
  Attrs : TElPKCS7Attributes;
begin

  // Obtaining signer's certificate
  Cert := FindSignerCertificate(Signer);
  if Cert = nil then
  begin
    Result := SB_MESSAGE_ERROR_NO_CERTIFICATE;
    Exit;
  end;

  // Decrypting EncryptedDigest
  EncAlg := GetSigAlgorithmByOID(Signer.DigestEncryptionAlgorithm);
  FAlgorithm := EncAlg;
  if (EncAlg in [SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION, SB_CERT_ALGORITHM_MD5_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA1_RSA_ENCRYPTION, SB_CERT_ALGORITHM_SHA224_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA256_RSA_ENCRYPTION, SB_CERT_ALGORITHM_SHA384_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA512_RSA_ENCRYPTION]) and (Cert.PublicKeyAlgorithm =
    SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION) then
  begin
    if not DecryptRSAForSigner(Cert, Signer, IncomingDigest) then
    begin
      Result := SB_MESSAGE_ERROR_INVALID_SIGNATURE;
      Exit;
    end;
  end
  else if (EncAlg = SB_CERT_ALGORITHM_ID_RSAPSS) and ((Cert.PublicKeyAlgorithm =
    SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION) or (Cert.PublicKeyAlgorithm =
    SB_CERT_ALGORITHM_ID_RSAPSS)) then
  begin
  end
  else if ((EncAlg = SB_CERT_ALGORITHM_ID_DSA) or (EncAlg = SB_CERT_ALGORITHM_ID_DSA_SHA1)) and
    (Cert.PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_DSA) then
  begin
  end
  else if ((EncAlg in [SB_CERT_ALGORITHM_EC, SB_CERT_ALGORITHM_SHA1_ECDSA,
    SB_CERT_ALGORITHM_RECOMMENDED_ECDSA, SB_CERT_ALGORITHM_SHA224_ECDSA,
    SB_CERT_ALGORITHM_SHA256_ECDSA, SB_CERT_ALGORITHM_SHA384_ECDSA,
    SB_CERT_ALGORITHM_SHA512_ECDSA, SB_CERT_ALGORITHM_SHA1_ECDSA_PLAIN,
    SB_CERT_ALGORITHM_SHA224_ECDSA_PLAIN, SB_CERT_ALGORITHM_SHA256_ECDSA_PLAIN,
    SB_CERT_ALGORITHM_SHA384_ECDSA_PLAIN, SB_CERT_ALGORITHM_SHA512_ECDSA_PLAIN,
    SB_CERT_ALGORITHM_RIPEMD160_ECDSA_PLAIN]) and (Cert.PublicKeyAlgorithm = SB_CERT_ALGORITHM_EC)) then
  begin
  end
  {$ifdef SB_HAS_GOST}
  else if (EncAlg = SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_2001) and
    (Cert.PublicKeyAlgorithm = SB_CERT_ALGORITHM_GOST_R3410_2001) then
  begin
  end
   {$endif}
  else
  begin
    Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
    Exit;
  end;

  // Getting source for digest calculation
  DigestAlg := GetHashAlgorithmByOID(Signer.DigestAlgorithm);
  if (DigestAlg = SB_ALGORITHM_UNKNOWN) and
    (voLiberalMode in VerificationOptions)
  then
  begin
    // see the comment in the InternalVerify implementation
    DigestAlg := GetAlgorithmByOID(Signer.DigestAlgorithm);
    if DigestAlg <> SB_ALGORITHM_UNKNOWN then
      DigestAlg := GetHashAlgorithmBySigAlgorithm(DigestAlg); 
  end;
  if Signer.AuthenticatedAttributes.Count > 0 then
  begin
    try
      HashFunc := TElHashFunction.Create(DigestAlg, TElCPParameters(nil), FCryptoProviderManager, nil);
    except
      Result := SB_MESSAGE_ERROR_UNSUPPORTED_DIGEST_ALGORITHM;
      Exit;
    end;
    try
      HashFunc.Update(@Signer.AuthenticatedAttributesPlain[0],
        Length(Signer.AuthenticatedAttributesPlain));
      AttrHash := HashFunc.Finish;
    finally
      FreeAndNil(HashFunc);
    end;
  end
  else
  begin
    SetLength(AttrHash, DigestSize);
    SBMove(Digest^, AttrHash[0], Length(AttrHash));
  end;
  ActualDigest := AttrHash;

  // Calculating and validating digest
  FAlgorithm := DigestAlg;
  if (EncAlg = SB_CERT_ALGORITHM_ID_DSA) or (EncAlg = SB_CERT_ALGORITHM_ID_DSA_SHA1) then
  begin
    //ActualDigest := CalculateDigest(PData, DataSize, SB_ALGORITHM_DGST_SHA1, Data);
    if VerifyDSA(Cert, Signer, @ActualDigest[0], Length(ActualDigest)) then
      Result := 0
    else
      Result := SB_MESSAGE_ERROR_INVALID_SIGNATURE;
  end
  else if EncAlg in [SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION, SB_CERT_ALGORITHM_MD5_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA1_RSA_ENCRYPTION, SB_CERT_ALGORITHM_SHA224_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA256_RSA_ENCRYPTION, SB_CERT_ALGORITHM_SHA384_RSA_ENCRYPTION,
    SB_CERT_ALGORITHM_SHA512_RSA_ENCRYPTION] then
  begin
    if (CompareContent(ActualDigest, IncomingDigest)) then
      Result := 0
    else
      Result := SB_MESSAGE_ERROR_INVALID_DIGEST;
  end
  else if EncAlg = SB_CERT_ALGORITHM_ID_RSAPSS then
  begin
    FUsePSS := true;
    if not TElRSAKeyMaterial.ReadPSSParams(@Signer.DigestEncryptionAlgorithmParams[0],
      Length(Signer.DigestEncryptionAlgorithmParams), FAlgorithm, SaltSize, MGF,
      MGFHash, Trailer) then
    begin
      FAlgorithm := SB_ALGORITHM_UNKNOWN;
      Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
      Exit;
    end;
    // TODO: Check this
    ActualDigest := CalculateDigest(@AttrHash[0], Length(AttrHash), DigestAlg, nil, nil, false);
    if Length(ActualDigest) = 0 then
    begin
      FAlgorithm := SB_ALGORITHM_UNKNOWN;
      Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
      Exit;
    end;

    if VerifyRSAPSS(Cert, Signer, @ActualDigest[0], Length(ActualDigest),
      FAlgorithm, SaltSize)
    then
      Result := 0
    else
      Result := SB_MESSAGE_ERROR_INVALID_DIGEST
  end
  {$ifdef SB_HAS_ECC}
  else if EncAlg in [SB_CERT_ALGORITHM_EC, SB_CERT_ALGORITHM_SHA1_ECDSA,
    SB_CERT_ALGORITHM_RECOMMENDED_ECDSA, SB_CERT_ALGORITHM_SHA224_ECDSA,
    SB_CERT_ALGORITHM_SHA256_ECDSA, SB_CERT_ALGORITHM_SHA384_ECDSA,
    SB_CERT_ALGORITHM_SHA512_ECDSA, SB_CERT_ALGORITHM_SHA1_ECDSA_PLAIN,
    SB_CERT_ALGORITHM_SHA224_ECDSA_PLAIN, SB_CERT_ALGORITHM_SHA256_ECDSA_PLAIN,
    SB_CERT_ALGORITHM_SHA384_ECDSA_PLAIN, SB_CERT_ALGORITHM_SHA512_ECDSA_PLAIN,
    SB_CERT_ALGORITHM_RIPEMD160_ECDSA_PLAIN] then
  begin
    if VerifyECDSA(Cert, Signer, @ActualDigest[0], Length(ActualDigest)) then
      Result := 0
    else
      Result := SB_MESSAGE_ERROR_INVALID_SIGNATURE;
  end
   {$endif}
  {$ifdef SB_HAS_GOST}
  else if EncAlg = SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_2001 then
  begin
    if VerifyGOST2001(Cert, Signer,  @ActualDigest[0], Length(ActualDigest) ) then
      Result := 0
    else
      Result := SB_MESSAGE_ERROR_INVALID_SIGNATURE;
  end
   {$endif}
  else
    Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;

  // Verifying countersignatures, if any
  if (not FVerifyCountersignatures) or (Countersign) then
    Exit;
  if Result = 0 then
  begin
    // extracting signerinfos
    SignerInfos := TElList.Create;
    try
      for I := 0 to Signer.UnauthenticatedAttributes.Count - 1 do
      begin
        if CompareContent(Signer.UnauthenticatedAttributes.Attributes[I],
          SB_OID_COUNTER_SIGNATURE) then
        begin
          for J := 0 to Signer.UnauthenticatedAttributes.Values[I].Count - 1 do
          begin
            Countersignature := Signer.UnauthenticatedAttributes.Values[I].Item[J];
            Tag := TElASN1ConstrainedTag.CreateInstance;
            try
              if not Tag.LoadFromBuffer(@Countersignature[0], Length(Countersignature)) then
              begin
                Result := SB_MESSAGE_ERROR_INVALID_COUNTERSIGNATURE;
                Break;
              end;
              if (Tag.Count <> 1) or (not Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
              begin
                Result := SB_MESSAGE_ERROR_INVALID_COUNTERSIGNATURE;
                Break;
              end;
              Info := TElPKCS7Signer.Create;
              if ProcessSignerInfo(Tag.GetField(0), Info) <> 0 then
              begin
                Result := SB_MESSAGE_ERROR_INVALID_COUNTERSIGNATURE;
                FreeAndNil(Info);
                Break; //Exit; (just skipping bad countersignature in order to process other ones)
              end;
            finally
              FreeAndNil(Tag);
            end;
            SignerInfos.Add(Info);
            Issuer := TElPKCS7FakedIssuer.Create;
            Issuer.SerialNumber := Info.Issuer.SerialNumber;
            Issuer.Issuer.Count := Info.Issuer.Issuer.Count;
            for K := 0 to Issuer.Issuer.Count - 1 do
            begin
              Issuer.Issuer.OIDs[K] := Info.Issuer.Issuer.OIDs[K];
              Issuer.Issuer.Values[K] := Info.Issuer.Issuer.Values[K];
              Issuer.Issuer.Tags[K] := Info.Issuer.Issuer.Tags[K];
              Issuer.Issuer.Groups[K] := Info.Issuer.Issuer.Groups[K];
            end;
            FCSCertIDs.Add(Issuer);
            Attrs := TElPKCS7Attributes.Create;
            Info.AuthenticatedAttributes.Copy(Attrs);
            Info.UnauthenticatedAttributes.Copy(Attrs);
            FCSAttributes.Add(Attrs);
          end;
        end;
      end;

      // verifying signerinfos
      SetLength(FCSVerificationResults, SignerInfos.Count);
      for I := 0 to SignerInfos.Count - 1 do
      begin
        CSResult := 0;
        Info := TElPKCS7Signer(SignerInfos[I]);
        Dgst := Signer.EncryptedDigest;
        // II 20060922: calculating the digest of data to be verified
        DigestAlg := GetHashAlgorithmByOID(Info.DigestAlgorithm);
        // workaround for CodeGear RAD 2007. Do not modify.
        DgstRes := CalculateDigest(@Dgst[0], Length(Dgst), DigestAlg, nil, nil, false);
        Dgst := DgstRes;
        if Length(Dgst) = 0 then
          CSResult := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
        // II 20060922 end

        if CSResult = 0 then
          CSResult := VerifySingle(Info, nil, @Dgst[0], Length(Dgst), nil, true);
        if CSResult <> 0 then
        begin
          FCSVerificationResults[I] := CSResult;
          if (Result = 0) then
            Result := SB_MESSAGE_ERROR_INVALID_COUNTERSIGNATURE;
          Continue; //Exit; (verifying next countersignature)
        end;
        // verifying message-digest
        if Info.AuthenticatedAttributes.Count > 0 then
        begin
          CSResult := SB_MESSAGE_ERROR_INVALID_DIGEST;
          for K := 0 to Info.AuthenticatedAttributes.Count - 1 do
          begin
            if CompareContent(Info.AuthenticatedAttributes.Attributes[K],
              SB_OID_MESSAGE_DIGEST) then
            begin
              if Info.AuthenticatedAttributes.Values[K].Count > 0 then
                IncomingDigest := UnformatAttributeValue(Info.AuthenticatedAttributes.Values[K].Item[0],
                  TagID)
              else
                IncomingDigest := EmptyArray;
              (* II20061004: Dgst is already a digest, so we do not need to calculate it
              DigestAlg := GetHashAlgorithmByOID(Info.DigestAlgorithm);
              {$ifdef SB_VCL}
              Dgst := CalculateDigest(@Dgst[0], Length(Dgst), DigestAlg);
              {$else}
              Dgst := CalculateDigest(Dgst, 0, Length(Dgst), DigestAlg);
              {$endif}
              *)
              if CompareContent(IncomingDigest, Dgst) then
                CSResult := 0;
              if Length(IncomingDigest) > 0 then
                ReleaseArray(IncomingDigest);
              Break;
            end;
          end;
        end;
        FCSVerificationResults[I] := CSResult;
        if (CSResult <> 0) and (Result = 0) then
          Result := SB_MESSAGE_ERROR_INVALID_COUNTERSIGNATURE;
      end;
    finally
      for I := 0 to SignerInfos.Count - 1 do
        TElPKCS7Signer(SignerInfos[I]).Free;
      FreeAndNil(SignerInfos);
    end;
  end;

  {$ifndef B_6}
  if (Result = 0) and (voVerifyTimestamps in VerificationOptions) then
    Result := VerifyTimestamps(Signer);
   {$endif}
end;

class function TElMessageVerifier.IsSignatureDetached(Signature : pointer; Size :
  integer) : boolean;
var
  Msg : TElPKCS7Message;
  I : integer;
begin
  CheckLicenseKey();
  Result := false;
  Msg := TElPKCS7Message.Create;
  try
    I := Msg.LoadFromBuffer(Signature , Size );
    if I = 0 then
    begin
      if Msg.ContentType = ctSignedData then
        Result := Msg.SignedData.DataSource.Size = 0
      else
      if Msg.ContentType =  ctAuthenticatedData  then
        Result := Msg.AuthenticatedData.DataSource.Size = 0;
    end;
  finally
    FreeAndNil(Msg);
  end;
end;

class function TElMessageVerifier.IsSignatureDetached(Signature : TStream; Count : Int64 = 0) : boolean;
var
  Msg : TElPKCS7Message;
  I : integer;
begin
  CheckLicenseKey();
  Result := false;
  Msg := TElPKCS7Message.Create;
  try
    I := Msg.LoadFromStream(Signature, Count);
    if I = 0 then
    begin
      if Msg.ContentType = ctSignedData then
        Result := Msg.SignedData.DataSource.Size = 0
      else if Msg.ContentType =  ctAuthenticatedData  then
        Result := Msg.AuthenticatedData.DataSource.Size = 0;
    end;
  finally
    FreeAndNil(Msg);
  end;
end;


function TElMessageVerifier.ExtractMACKey(AuthData : TElPKCS7AuthenticatedData;
  var Key: ByteArray) : integer;
var
  I, J : integer;
  Certificate : TElX509Certificate;
  Recipient : TElPKCS7Recipient;
  Found : boolean;
begin
  Found := false;
  Certificate := nil;
  Recipient := nil;
  for I := 0 to AuthData.RecipientCount - 1 do
  begin
    for J := 0 to FCertStorage.Count - 1 do
    begin
      if CertCorrespondsToIssuer(FCertStorage.Certificates[J], AuthData.Recipients[I].Issuer) then
      begin
        Certificate := FCertStorage.Certificates[J];
        Recipient := AuthData.Recipients[I];
        Found := true;
        Break;
      end;
    end;
    if Found and Certificate.PrivateKeyExists then
      Break;
  end;
  if (not Found) or (not Certificate.PrivateKeyExists) then
  begin
    Result := SB_MESSAGE_ERROR_NO_CERTIFICATE;
    Exit;
  end;
  if not DecryptKey(Certificate, Recipient, Key) then
  begin
    Result := SB_MESSAGE_ERROR_KEY_DECRYPTION_FAILED;
    Exit;
  end;
  Result := 0;
end;


function TElMessageVerifier. GetCertIDs (Index : integer) : TElPKCS7Issuer;
begin
  if (Index >= 0) and (Index < FCertIDs.Count) then
    Result := TElPKCS7Issuer(FCertIDs[Index])
  else
    Result := nil;
end;

function TElMessageVerifier.GetCertIDCount : integer;
begin
  Result := FCertIDs.Count;
end;

function TElMessageVerifier. GetCounterSignatureCertIDs (Index : integer) : TElPKCS7Issuer;
begin
  if (Index >= 0) and (Index < FCSCertIDs.Count) then
    Result := TElPKCS7Issuer(FCSCertIDs[Index])
  else
    Result := nil;
end;

function TElMessageVerifier.GetCounterSignatureCertIDCount : integer;
begin
  Result := FCSCertIDs.Count;
end;

function TElMessageVerifier. GetCountersignatureVerificationResults (Index: integer): integer;
begin
  if Index < Length(FCSVerificationResults) then
    Result := FCSVerificationResults[Index]
  else
    Result := SB_MESSAGE_ERROR_VERIFICATION_FAILED; 
end;

function TElMessageVerifier. GetCountersignatureAttributes (Index: integer): TElPKCS7Attributes;
begin
  if (Index >= 0) and (Index < FCSAttributes.Count) then
    Result := TElPKCS7Attributes(FCSAttributes[Index])
  else
    Result := nil;
end;

procedure TElMessageVerifier.ClearCertIDs;
var
  I : integer;
begin
  for I := 0 to FCertIDs.Count - 1 do
    TElPKCS7Issuer(FCertIDs[I]).Free;
  for I := 0 to FCSCertIDs.Count - 1 do
    TElPKCS7Issuer(FCSCertIDs[I]).Free;
  for I := 0 to FCSAttributes.Count - 1 do
    TElPKCS7Attributes(FCSAttributes[I]).Free;
  FCertIDs.Clear;
  FCSCertIDs.Clear;
  FCSAttributes.Clear;
end;

function TElMessageVerifier.VerifyMessageDigests(Msg : TElPKCS7Message;
  Stream : TStream; Offset : Int64; Count : Int64): integer;
var
  Func : TElHashFunction;
  HashResult, Digest : ByteArray;
  I, K  : integer;
  DigestFound, FreeStrm : boolean;
  Alg : integer;
begin
  Result := 0;
  if not (voVerifyMessageDigests in FVerificationOptions) then
    Exit;
  
  FreeStrm := false;
  if Stream = nil then
  begin
    Stream := TElMemoryStream.Create;
    FreeStrm := true;
  end;
  
  try
    if Count = 0 then
      Count := Stream. Size  - Offset;
    for K := 0 to Msg.SignedData.SignerCount - 1 do
    begin
      if Msg.SignedData.Signers[K].AuthenticatedAttributes.Count = 0 then
        Continue;
      DigestFound := false;
      try
        Stream.Position := Offset;
        if FInputIsDigest then
        begin
          SetLength(HashResult, Count);
          Stream.Read(HashResult[0], Length(HashResult));
        end
        else
        begin
          Alg := GetAlgorithmByOID(Msg.SignedData.Signers[K].DigestAlgorithm);
          Func := TElHashFunction.Create(Alg, TElCPParameters(nil), FCryptoProviderManager, nil);
          try
            Func.UpdateStream(Stream, Count);
            HashResult := CloneArray(Func.Finish);
          finally
            FreeAndNil(Func);
          end;
        end;
        for I := 0 to Msg.SignedData.Signers[K].AuthenticatedAttributes.Count - 1 do
        begin
          if CompareContent(Msg.SignedData.Signers[K].AuthenticatedAttributes.Attributes[I], SB_OID_MESSAGE_DIGEST) then
          begin
            DigestFound := true;
            Digest := ByteArray(TElByteArrayList(Msg.SignedData.Signers[K].AuthenticatedAttributes.Values[I]).Item[0]);
            if (Length(Digest) = Length(HashResult) + 2) and
              (Digest[0] = byte($04)) and
               (Digest[0 + 1] = byte(Length(HashResult))) and
              CompareMem(@Digest[0 + 2], @HashResult[0], Length(HashResult))
            then
              Result := 0
            else
            begin
              Result := SB_MESSAGE_ERROR_INVALID_DIGEST;
              Exit;
            end;
          end;
        end;
        if not DigestFound then
        begin
          Result := SB_MESSAGE_ERROR_DIGEST_NOT_FOUND;
          Exit;
        end;
      except
        Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
      end;
    end;
  finally
    if FreeStrm then
      FreeAndNil(Stream);
  end;
end;

{$ifndef B_6}
function TElMessageVerifier.VerifyTimestamps(Signer: TElPKCS7Signer): integer;
var
  I : integer;
  Val : ByteArray;
  Info : TElClientTSPInfo;
  R, Sz : integer;
  Tag, Seq : TElASN1ConstrainedTag;
  Buf : ByteArray;
  SrcBuf, Dgst : ByteArray;
  AlgID, AlgParams : ByteArray;
  HashFunc : TElHashFunction;
begin
  SetLength(Buf, 0);
  Result := 0;
  for I := 0 to Signer.UnauthenticatedAttributes.Count - 1 do
  begin
    if CompareContent(Signer.UnauthenticatedAttributes.Attributes[I], SB_OID_TIMESTAMP_TOKEN) then
    begin
      if Signer.UnauthenticatedAttributes.Values[I].Count > 0 then
      begin
        Val := ByteArray(Signer.UnauthenticatedAttributes.Values[I].Item[0]);
        Info := TElClientTSPInfo.Create;
        R := Info.ParseCMS((Val));
        if (R <> 0) and (Info.LastValidationResult = SB_TSP_ERROR_UNRECOGNIZED_FORMAT) then
        begin
          // some implementations insert TimeStampResp structure instead of TimeStampToken
          Tag := TElASN1ConstrainedTag.CreateInstance();
          try
            if Tag.LoadFromBuffer( @Val[0], Length(Val) ) then
            begin
              if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
              begin
                Seq := TElASN1ConstrainedTag(Tag.GetField(0));
                if (Seq.Count = 2) and (Seq.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) and
                  (Seq.GetField(1).CheckType(SB_ASN1_SEQUENCE, true)) then
                begin
                  Sz := 0;
                  Seq.GetField(1).SaveToBuffer( nil , Sz);
                  SetLength(Val, Sz);
                  Seq.GetField(1).SaveToBuffer( @Val[0] , Sz);
                  SetLength(Val, Sz);
                  R := Info.ParseCMS((Val));
                end;
              end;
            end;
          finally
            FreeAndNil(Tag);
          end;
        end; 
        if (R = 0) then
        begin
          // checking that timestamp belongs to the signature
          Tag := TElASN1ConstrainedTag.CreateInstance();
          try
            Buf := CloneArray(Info.MessageImprint);
            if Tag.LoadFromBuffer( @Buf[0], Length(Buf) ) then
            begin
              if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
              begin
                Seq := TElASN1ConstrainedTag(Tag.GetField(0));
                if (Seq.Count = 2) and (Seq.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) and
                  (Seq.GetField(1).CheckType(SB_ASN1_OCTETSTRING, false)) then
                begin
                  R := ProcessAlgorithmIdentifier(Seq.GetField(0), AlgID, AlgParams);
                  if R = 0 then
                  begin
                    HashFunc := TElHashFunction.Create(AlgID, TElCPParameters(nil), FCryptoProviderManager, nil);
                    try
                      SrcBuf := CloneArray(Signer.EncryptedDigest);
                      HashFunc.Update( @SrcBuf[0] , Length(SrcBuf));
                      SrcBuf := HashFunc.Finish;
                    finally
                      FreeAndNil(HashFunc);
                    end;
                    Dgst := TElASN1SimpleTag(Seq.GetField(1)).Content;
                    if not ((Length(Dgst) = Length(SrcBuf)) and (CompareContent(Dgst, SrcBuf))) then
                      R := SB_MESSAGE_ERROR_BAD_TIMESTAMP
                    else
                      R := 0;
                  end;
                end
                else
                  R := SB_MESSAGE_ERROR_BAD_TIMESTAMP;
              end
              else
                R := SB_MESSAGE_ERROR_BAD_TIMESTAMP;
            end
            else
              R := SB_MESSAGE_ERROR_BAD_TIMESTAMP; 
          finally
            FreeAndNil(Tag);
          end;
        end;
        if (Result = 0) and (R <> 0) then
          Result := R;
        FTimestamps.Add(Info);
      end;
    end;
  end;
end;

function TElMessageVerifier.GetTimestamp(Index: integer): TElClientTSPInfo;
begin
  Result := TElClientTSPInfo(FTimestamps[Index]);
end;

function TElMessageVerifier.GetTimestampCount: integer;
begin
  Result := FTimestamps.Count;
end;

procedure TElMessageVerifier.ClearTimestamps;
var
  I : integer;
begin
  for I := 0 to FTimestamps.Count - 1 do
    TElClientTSPInfo(FTimestamps[I]).Free;
  FTimestamps.Clear;
end;
 {$endif}

procedure TElMessageVerifier.ExtractCertificateIDs(Msg : TElPKCS7Message;
  AuthData : boolean  =  false);
var
  I, J : integer;
  Issuer : TElPKCS7FakedIssuer;
begin
  ClearCertIDs;
  if not AuthData then
  begin
    for I := 0 to Msg.SignedData.SignerCount - 1 do
    begin
      Issuer := TElPKCS7FakedIssuer.Create;
      Issuer.SerialNumber := Msg.SignedData.Signers[I].Issuer.SerialNumber;
      Issuer.Issuer.Count := Msg.SignedData.Signers[I].Issuer.Issuer.Count;
      for J := 0 to Issuer.Issuer.Count - 1 do
      begin
        Issuer.Issuer.OIDs[J] := Msg.SignedData.Signers[I].Issuer.Issuer.OIDs[J];
        Issuer.Issuer.Values[J] := Msg.SignedData.Signers[I].Issuer.Issuer.Values[J];
        Issuer.Issuer.Tags[J] := Msg.SignedData.Signers[I].Issuer.Issuer.Tags[J];
        Issuer.Issuer.Groups[J] := Msg.SignedData.Signers[I].Issuer.Issuer.Groups[J];
      end;
      FCertIDs.Add(Issuer);
    end;
  end
  else
  begin
    for I := 0 to Msg.AuthenticatedData.RecipientCount - 1 do
    begin
      Issuer := TElPKCS7FakedIssuer.Create;
      Issuer.SerialNumber := Msg.AuthenticatedData.Recipients[I].Issuer.SerialNumber;
      Issuer.Issuer.Count := Msg.AuthenticatedData.Recipients[I].Issuer.Issuer.Count;
      for J := 0 to Issuer.Issuer.Count - 1 do
      begin
        Issuer.Issuer.OIDs[J] := Msg.AuthenticatedData.Recipients[I].Issuer.Issuer.OIDs[J];
        Issuer.Issuer.Values[J] := Msg.AuthenticatedData.Recipients[I].Issuer.Issuer.Values[J];
        Issuer.Issuer.Tags[J] := Msg.AuthenticatedData.Recipients[I].Issuer.Issuer.Tags[J];
        Issuer.Issuer.Groups[J] := Msg.AuthenticatedData.Recipients[I].Issuer.Issuer.Groups[J];
      end;
      FCertIDs.Add(Issuer);
    end;
  end;

  if Assigned(FOnCertIDs) then
    FOnCertIDs(Self, FCertIDs);
end;

procedure TElMessageVerifier.Reset;
begin
  ClearCertIDs;
  FAlgorithm := SB_ALGORITHM_UNKNOWN;
  FMacAlgorithm := SB_ALGORITHM_UNKNOWN;
  FAttributes.Count := 0;
  while FCertificates.Count > 0 do
    FCertificates.Remove(0);
  {$ifndef B_6}
  ClearTimestamps;
   {$endif}
  SetLength(FCSVerificationResults, 0);
  {$ifndef SB_NO_NET_DATETIME_OADATE}
  FSigningTime :=  0 ;
   {$else}
  FSigningTime := DateTimeFromOADate(0);
   {$endif}
end;

function TElMessageVerifier.VerifyAllSignatures(Data: TElPKCS7SignedData;
  Hashes : TElByteArrayList) : integer;
var
  I : integer;
  Hash : ByteArray;
begin
  if Data.SignerCount = 0 then
  begin
    Result := SB_MESSAGE_ERROR_INVALID_FORMAT;
    Exit;
  end;
  if Hashes.Count <> Data.SignerCount then
  begin
    Result := SB_MESSAGE_ERROR_INTERNAL_ERROR;
    Exit;
  end;
  Result := 0;
  for I := 0 to Data.SignerCount - 1 do
  begin
    Data.Signers[I].AuthenticatedAttributes.Copy(FAttributes);
    Data.Signers[I].UnauthenticatedAttributes.Copy(FAttributes);
    Hash := Hashes.Item[I];
    Result := VerifySingle(Data.Signers[I], Data, @Hash[0], Length(Hash), nil);
    if Result <> 0 then
      Break;
  end;
end;

function TElMessageVerifier.VerifyAllSignatures2(Msg : TElPKCS7Message;
  DataSource : TElASN1DataSource) : integer;
var
  I : integer;
begin
  if Msg.SignedData.SignerCount = 0 then
  begin
    Result := SB_MESSAGE_ERROR_INVALID_FORMAT;
    Exit;
  end;
  Result := 0;
  for I := 0 to Msg.SignedData.SignerCount - 1 do
  begin
    Msg.SignedData.Signers[I].AuthenticatedAttributes.Copy(FAttributes);
    Msg.SignedData.Signers[I].UnauthenticatedAttributes.Copy(FAttributes);
    Result := VerifySingle(Msg.SignedData.Signers[I], Msg.SignedData, nil, 0, DataSource);
    if Result <> 0 then
      Break;
  end;
end;

procedure TElMessageVerifier.ExtractValuesFromAttributes;
var
  I : integer;
  Val : ByteArray;
  TagID : integer;
begin
  for I := 0 to FAttributes.Count - 1 do
  begin
    if (CompareContent(FAttributes.Attributes[I], SB_OID_SIGNING_TIME)) and
      (FAttributes.Values[I].Count > 0) then
    begin
      Val := FAttributes.Values[I].Item[0];
      Val := UnformatAttributeValue(Val, TagID);
      if TagID = SB_ASN1_UTCTIME then
        FSigningTime := UTCTimeToDateTime(StringOfBytes(Val))
      else if TagID = SB_ASN1_GENERALIZEDTIME then
        FSigningTime := GeneralizedTimeToDateTime(StringOfBytes(Val));
    end;
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// TElMessageSigner

constructor TElMessageSigner.Create(AOwner : TComponent);
begin
  inherited Create  (AOwner) ;
  FAAttributes := TElPKCS7Attributes.Create;
  FUAttributes := TElPKCS7Attributes.Create;
  FIncludeCertificates := true;
  FIncludeChain := false;
  FAlgorithm := SB_ALGORITHM_DGST_SHA1;
  FMacAlgorithm := SB_ALGORITHM_MAC_HMACSHA1;
  fUseUndefSize := true;
  FSignatureType := mstPublicKey;
  FUsePSS := false;
  FSigningOptions := [soInsertMessageDigests];
  FContentType := SB_OID_PKCS7_DATA;
  SetLength(FDigestEncryptionAlgorithm, 0);
  {$ifndef SB_NO_NET_DATETIME_OADATE}
  FSigningTime :=  0 ;
   {$else}
  FSigningTime := DateTimeFromOADate(0);
   {$endif}
  FErrorInfo := '';
  FOperationType := sotGeneric;
  {$ifdef SB_HAS_DC}
  FAsyncState := nil;
   {$endif}
  FExtraSpace := 0;
end;


 destructor  TElMessageSigner.Destroy;
begin
  FreeAndNil(FAAttributes);
  FreeAndNil(FUAttributes);
  inherited;
end;

procedure TElMessageSigner.SetCertStorage(Value : TElCustomCertStorage);
begin
  FCertStorage := Value;
  if FCertStorage <> nil then
    FCertStorage.FreeNotification(Self);
end;

procedure TElMessageSigner.SetRecipientCerts(Value : TElCustomCertStorage);
begin
  FRecipientCerts := Value;
  if FRecipientCerts <> nil then
    FRecipientCerts.FreeNotification(Self);
end;

{$ifndef B_6}
procedure TElMessageSigner.SetTSPClient(Value : TElCustomTSPClient);
begin
  FTSPClient := Value;
  if FTSPClient <> nil then
    FTSPClient.FreeNotification(Self);
end;
 {$endif}

procedure TElMessageSigner.SetContentType(const V : ByteArray);
begin
  FContentType := CloneArray(V);
end;

procedure TElMessageSigner.SetDigestEncryptionAlgorithm(const V : ByteArray);
begin
  FDigestEncryptionAlgorithm := CloneArray(V);
end;

procedure TElMessageSigner.Notification(AComponent : TComponent; AOperation :
  TOperation);
begin
  inherited;
  if (AComponent = FCertStorage) and (AOperation = opRemove) then
    CertStorage := nil
  else if (AComponent = FRecipientCerts) and (AOperation = opRemove) then
    RecipientCerts := nil
  {$ifndef B_6}
  else
  if (AComponent = FTSPClient) and (AOperation = opRemove) then
    TSPClient := nil
   {$endif}
  ;
end;

function TElMessageSigner.SignPublicKey(InBuffer: pointer; InSize: integer;
  OutBuffer : pointer; var OutSize : integer; InStream, OutStream: TStream;
  InCount : Int64; Detached : boolean): integer;
var
  FMessage : TElPKCS7Message;
  SgnData : TElPKCS7SignedData;
  I : integer;
  TmpS, DAlg : ByteArray;
  SzInt : integer;
  DigestAttrFound : boolean;
  AttrHash : ByteArray;
  PrivateKeyFound: boolean;
  TSResult : integer;
  TmpDataSource : TElASN1DataSource;
  OriginalPos : Int64;
  HashFunc : TElHashFunction;
  HashFuncList : TElList;
  HashResults : TElByteArrayList;
  SgnTime : TElDateTime;
  SgnTimeValue : ByteArray;
begin
  result := 0;
  // we do not require certificate to be available in async mode
  if (FOperationType = sotGeneric) and ((not Assigned(FCertStorage)) or (FCertStorage.Count = 0)) then
  begin
    Result := SB_MESSAGE_ERROR_NO_CERTIFICATE;
    Exit;
  end;
  // searching for appropriate signing certificate
  PrivateKeyFound := false;
  //PrivateKeyExtr := true;
  //Win32CertUsed := false;
  if FOperationType = sotGeneric then
  begin
    for I := 0 to FCertStorage.Count - 1 do
    begin
      if FCertStorage.Certificates[I].PrivateKeyExists then
      begin
        PrivateKeyFound := true;
        (* (II20100513) The below checkup is not needed anymore (see comment dated 20091111 below)
        if not FCertStorage.Certificates[I].PrivateKeyExtractable then
        begin
          PrivateKeyExtr := false;
          // special processing for win32 certificates
          if FCertStorage.Certificates[I].BelongsTo = BT_WINDOWS then
            Win32CertUsed := true;
        end;
        *)
        Break;
      end;
    end;
    if not PrivateKeyFound then
    begin
      Result := SB_MESSAGE_ERROR_NO_CERTIFICATE;
      Exit;
    end;
  end;
  // (II20091111) New versions of CryptoAPI understand SHA2 algorithms, so there is no need in checking HashAlgorithm against MD5 and SHA1 anymore
  //if ((not PrivateKeyExtr) and Win32CertUsed) or (HashAlgorithm = SB_ALGORITHM_UNKNOWN) then
  //begin
  //  if (HashAlgorithm <> SB_ALGORITHM_DGST_MD5) and (HashAlgorithm <> SB_ALGORITHM_DGST_SHA1) then
  //    HashAlgorithm := SB_ALGORITHM_DGST_SHA1;
  //end;

  // calculating estimated size for buffer output
  if OutStream = nil then
  begin
    SzInt := CalculateEstimatedSize(InSize, Detached) + 128;
    if OutSize < SzInt then
    begin
      OutSize := SzInt;
      Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL;
      Exit;
    end;
  end;

  FMessage := TElPKCS7Message.Create;
  try
    FMessage.UseUndefSize := FUseUndefSize;
    FMessage.ContentType := ctSignedData;
    SgnData := FMessage.SignedData;
    SgnData.Version := 1;
    if FIncludeCertificates and (FCertStorage <> nil) then
    begin
      FCertStorage.ExportTo(SgnData.Certificates);
      // include certificate chain if needed
      if FIncludeChain and (FCertStorage.Count = 1) and (FCertStorage.Certificates[0].Chain <> nil) then
      begin
        for I := 0 to FCertStorage.Certificates[0].Chain.Count - 1 do
        begin
          if not (FCertStorage.Certificates[0].Chain.Certificates[I].Equals(FCertStorage.Certificates[0])) then
            SgnData.Certificates.Add(FCertStorage.Certificates[0].Chain.Certificates[I], false);
        end;
      end;
    end;
    SgnData.ContentType := FContentType;//SB_OID_PKCS7_DATA;

    // hashing input data
    try
      if InStream <> nil then
      begin
        OriginalPos := InStream.Position;
        HashFunc := TElHashFunction.Create(FAlgorithm, TElCPParameters(nil), FCryptoProviderManager, nil);
        try
          HashFuncList := TElList.Create;
          HashResults := TElByteArrayList.Create;
          try
            HashFuncList.Add(HashFunc);
            TmpDataSource := TElASN1DataSource.Create();
            try
              TmpDataSource.Init(InStream, InStream.Position, InCount);
              CalculateDigests(nil, 0, HashFuncList, HashResults, nil, TmpDataSource, true);
              FDataHash := CloneArray(ByteArray(HashResults.Item[0]));
            finally
              FreeAndNil(TmpDataSource);
            end;
          finally
            FreeAndNil(HashFuncList);
            FreeAndNil(HashResults);
          end;
        finally
          FreeAndNil(HashFunc);
        end;
      end
      else
      begin
        FDataHash := CalculateDigest(InBuffer, InSize, FAlgorithm, nil, nil, true);
        if Length(DataHash) = 0 then
          raise EElMessageError.CreateFmt(SUnsupportedAlgorithm, [FAlgorithm]);
        OriginalPos := 0;
      end;
    except
      on E : Exception do
      begin
        FErrorInfo := E. Message ;
        Result := SB_MESSAGE_ERROR_DIGEST_CALCULATION_FAILED;
        FreeAndNil(FMessage);
        Exit;
      end;
    end;

    // initializing signature content
    if not Detached then
    begin
      if InStream <> nil then
        SgnData.DataSource.Init(InStream, OriginalPos, InCount)
      else
        SgnData.DataSource.Init(InBuffer, InSize);
    end
    else
      SgnData.DataSource.Init(EmptyArray);

    // inserting 'SigningTime' if needed
    if soInsertSigningTime in FSigningOptions then
    begin
      if FSigningTime <> 0 then
        SgnTime := FSigningTime
      else
      begin
        SgnTime :=  Now ;
        {$ifdef SB_WINDOWS}
        SgnTime := LocalTimeToUTCTime(SgnTime);
         {$endif}
      end;
      FAAttributes.Count := FAAttributes.Count + 1;
      FAAttributes.Attributes[FAAttributes.Count - 1] := SB_OID_SIGNING_TIME;
      if soUseGeneralizedTimeFormat in FSigningOptions then
        SgnTimeValue := FormatAttributeValue(SB_ASN1_GENERALIZEDTIME, BytesOfString(DateTimeToGeneralizedTime(SgnTime)))
      else
        SgnTimeValue := FormatAttributeValue(SB_ASN1_UTCTIME, BytesOfString(DateTimeToUTCTime(SgnTime)));
      FAAttributes.Values[FAAttributes.Count - 1].Add(SgnTimeValue);
    end;

    // adjusting authenticated attributes
    if FAAttributes.Count > 0 then
    begin
      // adding the 'message digest' attribute to the set
      // of authenticated attributes
      if soInsertMessageDigests in FSigningOptions then
      begin
        DigestAttrFound := false;
        for I := 0 to FAAttributes.Count - 1 do
        begin
          if (not DigestAttrFound) and (CompareContent(FAAttributes.Attributes[I], SB_OID_MESSAGE_DIGEST)) then
          begin
            FAAttributes.Values[I].Clear;
            FAAttributes.Values[I].Add(FormatAttributeValue(SB_ASN1_OCTETSTRING, DataHash));
            DigestAttrFound := true;
            Break;
          end;
        end;
        if not DigestAttrFound then
        begin
          I := FAAttributes.Count;
          FAAttributes.Count := I + 1;
          FAAttributes.Attributes[I] := SB_OID_MESSAGE_DIGEST;
          FAAttributes.Values[I].Add(FormatAttributeValue(SB_ASN1_OCTETSTRING, DataHash));
        end;
      end;
      FAAttributes.SortLexicographically();
      I := 0;
      FAAttributes.SaveToBuffer(nil, I);
      SetLength(TmpS, I);
      if not FAAttributes.SaveToBuffer(@TmpS[0], I) then
      begin
        Result := SB_MESSAGE_ERROR_INTERNAL_ERROR;
        Exit;
      end;
      // calculating hash over authenticated attributes
      AttrHash := CalculateDigest(@TmpS[0], Length(TmpS), FAlgorithm);
    end
    else
      AttrHash := DataHash; // if no authenticated attributes are present then data hash is signed instead

    if Length(AttrHash) = 0 then
    begin
      Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
      Exit;
    end;

    DAlg := GetOIDByHashAlgorithm(FAlgorithm);
    if FOperationType = sotGeneric then
    begin
      if FCertStorage <> nil then
      begin
        for I := 0 to FCertStorage.Count - 1 do
        begin
          if (not FCertStorage.Certificates[I].PrivateKeyExists) then
            Continue;
          Result := FillSigner(SgnData.Signers[SgnData.AddSigner], FCertStorage.Certificates[I],
            DAlg,  @AttrHash[0], Length(AttrHash) );
          if Result <> 0 then
            Exit;
        end;
      end;
    end
    else
    begin
      {$ifdef SB_HAS_DC}
      FillSigner(SgnData.Signers[SgnData.AddSigner], nil, DAlg,
         @AttrHash[0], Length(AttrHash) );
      FAsyncState := DefaultDCRequestFactory.CreatePKCS1SignRequest('MainOperation',
        AttrHash, FAlgorithm, IncludeCertificates);
       {$else}
      Result := SB_MESSAGE_ERROR_DC_MODULE_UNAVAILABLE;
      Exit;
       {$endif}
    end;
    if FOperationType = sotGeneric then
    begin
      {$ifndef B_6}
      if FTSPClient <> nil then
        TSResult := TimestampMessage(FMessage)
      else
       {$endif}
        TSResult := 0;
    end
    else
      TSResult := 0;

    if TSResult = 0 then
    begin
      if OutStream = nil then
      begin
        if not (soNoOuterContentInfo in SigningOptions) then
        begin
          FMessage.UseImplicitContent :=  soUseImplicitContent in SigningOptions ;
          if not FMessage.SaveToBuffer(OutBuffer, OutSize) then
            Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL
          else
            Result := 0;
        end
        else
        begin
          if not FMessage.SignedData.SaveToBuffer(OutBuffer, OutSize) then
            Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL
          else
            Result := 0;
        end;
      end
      else
      begin
        if not (soNoOuterContentInfo in SigningOptions) then
          FMessage.SaveToStream(OutStream)
        else
          FMessage.SignedData.SaveToStream(OutStream);
        Result := 0;
      end;
    end
    else
      Result := TSResult;
  finally
    FreeAndNil(FMessage);
  end;
end;

function TElMessageSigner.SignMAC(InBuffer: pointer; InSize: integer;
  OutBuffer : pointer; var OutSize : integer; InStream, OutStream: TStream;
  InCount: Int64; Detached : boolean): integer;
var
  FMessage : TElPKCS7Message;
  AuthData : TElPKCS7AuthenticatedData;
  I : integer;
  TmpS : ByteArray;
  MinKeyLen : integer;
  SzInt : integer;
  Err : boolean;
  DigestAttrFound, ContentAttrFound : boolean;
  Hash : ByteArray;
  Key  : ByteArray;
  Index : integer;
  TSResult : integer;
  OriginalPos : Int64;
  HashFunc : TElHashFunction;
  HashFuncList : TElList;
  HashResults : TElByteArrayList;
  TmpDataSource : TElASN1DataSource;
  SgnTime : TElDateTime;
  SgnTimeValue : ByteArray;
begin
  Result := 0;
  SetLength(FDataHash, 0);
  
  if (not Assigned(FRecipientCerts)) or (FRecipientCerts.Count = 0) then
  begin
    Result := SB_MESSAGE_ERROR_NO_CERTIFICATE;
    Exit;
  end;

  // calculating estimated size for buffer output
  if OutStream = nil then
  begin
    SzInt := CalculateEstimatedSize(InSize, Detached) + 128;
    if OutSize < SzInt then
    begin
      OutSize := SzInt;
      Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL;
      Exit;
    end;
  end;

  // creating and setting up PKCS#7 message object
  FMessage := TElPKCS7Message.Create;
  try
    FMessage.UseUndefSize := FUseUndefSize;
    FMessage.ContentType :=  ctAuthenticatedData ;
    AuthData := FMessage.AuthenticatedData;

    // setting up AuthenticatedData basic properties
    AuthData.Version := 0;
    AuthData.ContentType := FContentType; 

    // generating secret MAC key
    MinKeyLen := 64;
    for I := 0 to FRecipientCerts.Count - 1 do
    begin
      if FRecipientCerts.Certificates[I].CanEncrypt then
        MinKeyLen := Min(MinKeyLen, FRecipientCerts.Certificates[I].GetPublicKeySize shr 3 - 16);
    end;
    SetLength(Key, MinKeyLen);
    SBRndGenerate(@Key[0], Length(Key));

    // encrypting key for each recipient
    Err := true;
    if Assigned(FRecipientCerts) then
    begin
      for I := 0 to FRecipientCerts.Count - 1 do
      begin
        if FRecipientCerts.Certificates[I].CanEncrypt then
        begin
          Index := AuthData.AddRecipient;
          if FillRecipient(AuthData.Recipients[Index], FRecipientCerts.Certificates[I], Key) then
            Err := false
          else
            AuthData.RemoveRecipient(Index);
        end;
      end;
    end;
    if Err then
    begin
      Result := SB_MESSAGE_ERROR_NO_RECIPIENTS;
      Exit;
    end;

    if InStream <> nil then
      OriginalPos := InStream.Position
    else
      OriginalPos := 0;

    // initializing signature content
    if not Detached then
    begin
      if InStream <> nil then
        AuthData.DataSource.Init(InStream, OriginalPos, InCount)
      else
        AuthData.DataSource.Init(InBuffer, InSize);
    end
    else
      AuthData.DataSource.Init(EmptyArray);

    // inserting SigningTime if needed
    if soInsertSigningTime in FSigningOptions then
    begin
      if FSigningTime <> 0 then
        SgnTime := FSigningTime
      else
      begin
        SgnTime := Now;
        {$ifdef SB_WINDOWS}
        SgnTime := LocalTimeToUTCTime(SgnTime);
         {$endif}
      end;
      FAAttributes.Count := FAAttributes.Count + 1;
      FAAttributes.Attributes[FAAttributes.Count - 1] := SB_OID_SIGNING_TIME;
      if soUseGeneralizedTimeFormat in FSigningOptions then
        SgnTimeValue := FormatAttributeValue(SB_ASN1_GENERALIZEDTIME, BytesOfString(DateTimeToGeneralizedTime(SgnTime)))
      else
        SgnTimeValue := FormatAttributeValue(SB_ASN1_UTCTIME, BytesOfString(DateTimeToUTCTime(SgnTime)));
      FAAttributes.Values[FAAttributes.Count - 1].Add(SgnTimeValue);
    end;

    if FAAttributes.Count > 0 then
    begin
      // calculating digest over content data and MAC over attributes
      try
        if InStream <> nil then
        begin
          HashFunc := TElHashFunction.Create(FAlgorithm, TElCPParameters(nil), FCryptoProviderManager, nil);
          try
            HashFuncList := TElList.Create;
            HashResults := TElByteArrayList.Create;
            try
              HashFuncList.Add(HashFunc);
              TmpDataSource := TElASN1DataSource.Create();
              try
                TmpDataSource.Init(InStream, InStream.Position, InCount);
                CalculateDigests(nil, 0, HashFuncList, HashResults, nil, TmpDataSource, true);
                FDataHash := CloneArray(ByteArray(HashResults.Item[0]));
              finally
                FreeAndNil(TmpDataSource);
              end;
            finally
              FreeAndNil(HashFuncList);
              FreeAndNil(HashResults);
            end;
          finally
            FreeAndNil(HashFunc);
          end;
        end
        else
        begin
          FDataHash := CalculateDigest(InBuffer, InSize, FAlgorithm, nil, nil, true);
          if Length(DataHash) = 0 then
            raise EElMessageError.CreateFmt(SUnsupportedAlgorithm, [FAlgorithm]);
        end;
      except
        on E : Exception do
        begin
          FErrorInfo := E. Message ;
          Result := SB_MESSAGE_ERROR_DIGEST_CALCULATION_FAILED;
          Exit;
        end;
      end;

      // adding the 'message digest' and 'content-type' attributes to the set
      // of authenticated attributes
      DigestAttrFound := false;
      ContentAttrFound := false;
      for I := 0 to FAAttributes.Count - 1 do
      begin
        if (not DigestAttrFound) and (CompareContent(FAAttributes.Attributes[I],
          SB_OID_MESSAGE_DIGEST) and
          (soInsertMessageDigests in FSigningOptions)) then
        begin
          FAAttributes.Values[I].Clear;
          FAAttributes.Values[I].Add(FormatAttributeValue(SB_ASN1_OCTETSTRING, DataHash));
          DigestAttrFound := true;
        end;
        if (CompareContent(FAAttributes.Attributes[I],
          SB_OID_CONTENT_TYPE)) then
          ContentAttrFound := true;
        if DigestAttrFound and ContentAttrFound then
          Break;
      end;
      if (not DigestAttrFound) and
      (soInsertMessageDigests in FSigningOptions) then
      begin
        I := FAAttributes.Count;
        FAAttributes.Count := I + 1;
        FAAttributes.Attributes[I] := SB_OID_MESSAGE_DIGEST;
        FAAttributes.Values[I].Add(FormatAttributeValue(SB_ASN1_OCTETSTRING, DataHash));
      end;
      if not ContentAttrFound then
      begin
        I := FAAttributes.Count;
        FAAttributes.Count := I + 1;
        FAAttributes.Attributes[I] := SB_OID_CONTENT_TYPE;
        FAAttributes.Values[I].Add(FormatAttributeValue(SB_ASN1_OBJECT, SB_OID_PKCS7_DATA));
      end;
      // passing authenticated attributes to MAC function input
      FAAttributes.Copy(AuthData.AuthenticatedAttributes);
      FUAttributes.Copy(AuthData.UnauthenticatedAttributes);
      AuthData.RecalculateAuthenticatedAttributes;
      TmpS := AuthData.AuthenticatedAttributesPlain;
      if not CalculateMAC(@TmpS[0], Length(TmpS), Key, Hash, FMacAlgorithm) then
      begin
        Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
        Exit;
      end;
      AuthData.MacAlgorithm := GetOIDByAlgorithm(FMacAlgorithm);
      AuthData.DigestAlgorithm := GetOIDByHashAlgorithm(FAlgorithm);
      AuthData.Mac := Hash;
    end
    else
    begin
      // calculating MAC over content data
      try
        if InStream <> nil then
        begin
          TmpDataSource := TElASN1DataSource.Create();
          try
            TmpDataSource.Init(InStream, OriginalPos, InCount);
            Err := CalculateMAC(nil, 0, Key, Hash, FMacAlgorithm, nil, TmpDataSource, true);
          finally
            FreeAndNil(TmpDataSource);
          end;
        end
        else
        begin
          Err := CalculateMAC(InBuffer, InSize, Key, Hash, FMacAlgorithm, nil, nil, true);
        end;
      except
        on E : Exception do
        begin
          FErrorInfo := E. Message ;
          Result := SB_MESSAGE_ERROR_MAC_CALCULATION_FAILED;  
          Exit;
        end;
      end;
      if not Err then
      begin
        Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
        Exit;
      end;
      AuthData.MacAlgorithm := GetOIDByAlgorithm(FMacAlgorithm);
      AuthData.DigestAlgorithm := EmptyArray;
      AuthData.Mac := Hash;
    end;

    {$ifndef B_6}
    if FTSPClient <> nil then
      TSResult := TimestampMessage(FMessage)
    else
     {$endif}
      TSResult := 0;

    if TSResult = 0 then
    begin
      if (OutBuffer <> nil) and (OutSize <> 0) then
      begin
        if not FMessage.SaveToBuffer(OutBuffer, OutSize) then
          Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL
        else
          Result := 0;
      end
      else if OutStream <> nil then
      begin
        FMessage.SaveToStream(OutStream);
        Result := 0;
      end
      else
        Result := 0; 
    end
    else
      Result := TSResult;
  finally
    FreeAndNil(FMessage);
  end;
end;

function TElMessageSigner.Sign(InBuffer : pointer; InSize : integer; OutBuffer :
  pointer; var OutSize : integer; Detached : boolean = false) : integer;
begin
  CheckLicenseKey();
  FErrorInfo := '';
  if FSignatureType = mstPublicKey then
    Result := SignPublicKey(InBuffer, InSize, OutBuffer, OutSize, nil, nil, 0, Detached)
  else if FSignatureType = mstMAC then
    Result := SignMAC(InBuffer, InSize, OutBuffer, OutSize, nil, nil, 0, Detached)
  else
    Result := SB_MESSAGE_ERROR_UNSUPPORTED_SIGNATURE_TYPE;
end;


function TElMessageSigner.Sign(InStream, OutStream : TElStream;
  Detached : boolean  =  false;
  InCount : Int64  =  0): integer;
var
  Fake : TSBInteger;
begin
  CheckLicenseKey();


  FErrorInfo := '';
  Fake := 0;
  if FSignatureType = mstPublicKey then
    Result := SignPublicKey(nil, 0, nil, Fake, InStream, OutStream, InCount, Detached)
  else if FSignatureType = mstMAC then
    Result := SignMAC(nil, 0, nil, Fake, InStream, OutStream, InCount, Detached)
  else
    Result := SB_MESSAGE_ERROR_UNSUPPORTED_SIGNATURE_TYPE;
end;

{$ifdef SB_HAS_DC}
function TElMessageSigner.InitiateAsyncSign(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
  var OutSize: integer; Detached: boolean; var State : TElDCAsyncState): integer;
begin
  if FSignatureType <> mstPublicKey then
  begin
    Result := SB_MESSAGE_ERROR_UNSUPPORTED_SIGNATURE_TYPE;
    exit;
  end;
  FOperationType := sotAsyncPrepare;
  try
    Result := Sign(InBuffer, InSize, OutBuffer, OutSize, Detached);
    if Result = 0 then
      State := FAsyncState;
  finally
    FOperationType := sotGeneric;
    FAsyncState := nil;
  end;
end;

function TElMessageSigner.InternalCompleteAsyncSign(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
  var OutSize: integer; InStream, OutStream : TElStream; InCount: Int64;
  AsyncState: TElDCAsyncState): integer;
var
  Msg : TElPKCS7Message;
  SgnData : TElPKCS7SignedData;
  I : integer;
  RespMsg : TElDCOperationResponseMessage;
  Cert, SigningCert : TElX509Certificate;
  Buf, DAlg, Res : ByteArray;
  TSResult : integer;
  EstSize : Integer;
begin
  if (CompareStr(LowerCase(AsyncState.StateType), LowerCase(SB_AST_STANDARD)) <> 0) or
    (not (AsyncState.SubtypePresent(SB_ASST_PKCS1SIG))) then
  begin
    Result := SB_MESSAGE_ERROR_DC_BAD_ASYNC_STATE;
    Exit;
  end;
  Msg := nil;
  RespMsg := nil;
  for I := 0 to AsyncState.Messages.Count - 1 do
  begin
    if (AsyncState.Messages.Messages[I] is TElDCOperationResponseMessage) and
      (TElDCOperationResponseMessage(AsyncState.Messages.Messages[I]).Operation = dcRawSign) then
    begin
      RespMsg := TElDCOperationResponseMessage(AsyncState.Messages.Messages[I]);
      Break;
    end
    else if (AsyncState.Messages.Messages[I] is TElDCErrorMessage) then
    begin
      FErrorInfo := TElDCErrorMessage(AsyncState.Messages.Messages[I]).ErrorMessage;
      Result := TElDCErrorMessage(AsyncState.Messages.Messages[I]).Code;
      if Result = 0 then
        Result := SB_MESSAGE_ERROR_DC_SERVER_ERROR;
      Exit;
    end;
  end;
  if (RespMsg = nil) then
  begin
    Result := SB_MESSAGE_ERROR_DC_BAD_ASYNC_STATE;
    Exit;
  end;
  if (RespMsg.OriginalMessage = nil) or (not (RespMsg.OriginalMessage is TElDCOperationRequestMessage)) then
  begin
    Result := SB_MESSAGE_ERROR_DC_BAD_ASYNC_STATE;
    Exit;
  end;
  if InStream = nil then
  begin
    // estimating output size for buffer-based calls
    EstSize := InSize;
    if IncludeCertificates then
    begin
      for I := 0 to RespMsg.KeysRDN.Count - 1 do
        Inc(EstSize, Length(RespMsg.KeysRDN.Values[I]) + 32);
      if FCertStorage <> nil then
      begin
        for I := 0 to FCertStorage.Count - 1 do
          Inc(EstSize, FCertStorage.Certificates[I].CertificateSize + 20);
        if FIncludeChain and (FCertStorage.Count = 1) and (FCertStorage.Certificates[0].Chain <> nil) then
        begin
          for I := 0 to FCertStorage.Certificates[0].Chain.Count - 1 do
          begin
            if not (FCertStorage.Certificates[0].Chain.Certificates[I].Equals(FCertStorage.Certificates[0])) then
              Inc(EstSize, FCertStorage.Certificates[0].Chain.Certificates[I].CertificateSize + 20);
          end;
        end;
      end;
    end;
    Inc(EstSize, 1024); // certid
    Inc(EstSize, Length(RespMsg.OperationResult) + 16);
    Inc(EstSize, 2048); // just in case
    {$ifndef B_6}
    if (FTSPClient <> nil) then
      Inc(EstSize, 6144);
     {$endif}
    if (OutSize < EstSize) then
    begin
      Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL;
      OutSize := EstSize;
      Exit;
    end;
  end;
  // updating the message
  DAlg := TElDCOperationRequestMessage(RespMsg.OriginalMessage).HashAlgorithm;
  Res := RespMsg.OperationResult;
  FOperationType := sotAsyncComplete;
  try
    Msg := TElPKCS7Message.Create();
    try
      if InStream = nil then
        Result := Msg.LoadFromBuffer( InBuffer, InSize )
      else
        Result := Msg.LoadFromStream(InStream, InCount);
      if Result <> 0 then
      begin  
        Exit;
      end;
      if Msg.ContentType <> ctSignedData then
      begin
        Result := SB_MESSAGE_ERROR_NO_SIGNED_DATA;
        Exit;
      end;
      SgnData := Msg.SignedData;
      if FIncludeCertificates and (FCertStorage <> nil) then
      begin
        FCertStorage.ExportTo(SgnData.Certificates);
        // include certificate chain if needed
        if FIncludeChain and (FCertStorage.Count = 1) and (FCertStorage.Certificates[0].Chain <> nil) then
        begin
          for I := 0 to FCertStorage.Certificates[0].Chain.Count - 1 do
          begin
            if not (FCertStorage.Certificates[0].Chain.Certificates[I].Equals(FCertStorage.Certificates[0])) then
              SgnData.Certificates.Add(FCertStorage.Certificates[0].Chain.Certificates[I], false);
          end;
        end;
      end;
      SigningCert := nil;
      Cert := TElX509Certificate.Create(nil);
      try
        for I := 0 to RespMsg.KeysRDN.Count - 1 do
        begin
          Buf := RespMsg.KeysRDN.Values[I];
          if (SigningCert = nil) and CompareContent(RespMsg.KeysRDN.OIDs[I], SB_OID_DC_SIGNING_CERTIFICATE) then
          begin
            SigningCert := TElX509Certificate.Create(nil);
            SigningCert.LoadFromBuffer( @Buf[0], Length(Buf) );
            if IncludeCertificates then
              SgnData.Certificates.Add(SigningCert, false)
            else
              Break;
          end
          else if IncludeCertificates and CompareContent(RespMsg.KeysRDN.OIDs[I], SB_OID_DC_CERTIFICATE) then
          begin
            Cert.LoadFromBuffer( @Buf[0], Length(Buf) );
            SgnData.Certificates.Add(Cert, false);
          end;
        end;
        if SigningCert = nil then
        begin
          Result := SB_MESSAGE_ERROR_NO_CERTIFICATE;
          Exit;
        end;
        Result := FillSigner(SgnData.Signers[SgnData.SignerCount - 1], SigningCert,
          DAlg,  @Res[0], Length(Res) );
        if Result <> 0 then
        begin  
          Exit;
        end;
      finally
        FreeAndNil(Cert);
        if Assigned(SigningCert) then
          FreeAndNil(SigningCert);
      end;
      // timestamping message
      {$ifndef B_6}
      if FTSPClient <> nil then
        TSResult := TimestampMessage(Msg)
      else
       {$endif}
        TSResult := 0;
      if (TSResult <> 0) and
        (not (soIgnoreTimestampFailure in SigningOptions))
      then
      begin
        Result := TSResult;
        Exit;
      end;
      // saving the message
      if InStream = nil then
      begin
        if not Msg.SaveToBuffer(OutBuffer, OutSize) then
          Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL
        else
          Result := 0;
      end
      else
      begin
        Msg.SaveToStream(OutStream);
        Result := 0;
      end;
    finally
      FreeAndNil(Msg);
    end;
  finally
    FOperationType := sotGeneric;
  end;
end;

function TElMessageSigner.CompleteAsyncSign(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
  var OutSize: integer; AsyncState: TElDCAsyncState): integer;
begin
  Result := InternalCompleteAsyncSign(InBuffer, InSize, OutBuffer, OutSize, nil,
    nil, 0, AsyncState);
end;

function TElMessageSigner.InitiateAsyncSign(InStream, OutStream : TElStream; Detached: boolean;
   var State : TElDCAsyncState ; InCount: int64  =  0): integer;
begin
  if FSignatureType <> mstPublicKey then
  begin
    Result := SB_MESSAGE_ERROR_UNSUPPORTED_SIGNATURE_TYPE;
    exit;
  end;
  FOperationType := sotAsyncPrepare;
  try
    Result := Sign(InStream, OutStream, Detached, InCount);
    if Result = 0 then
      State := FAsyncState;
  finally
    FOperationType := sotGeneric;
    FAsyncState := nil;
  end;
end;

function TElMessageSigner.CompleteAsyncSign(InStream, OutStream: TElStream; AsyncState: TElDCAsyncState;
  InCount: int64  =  0): integer;
var
  Dummy : TSBInteger;
begin
  Dummy := 0;
  Result := InternalCompleteAsyncSign(nil, 0, nil, Dummy, InStream, OutStream, InCount,
    AsyncState);
end;
 {$endif}

function TElMessageSigner.FillSigner(Signer : TElPKCS7Signer; Certificate :
  TElX509Certificate; const DigestAlgorithm : ByteArray; Hash : pointer; HashSize :
  integer): integer;
var
  I : integer;
  EncryptedDigest : ByteArray;
  Serial : ByteArray;
  AlgID : TElAlgorithmIdentifier;
  {$ifdef SB_HAS_ECC}
  SigAlg : integer;
   {$endif}
begin
  Signer.Version := 1;
  if FOperationType = sotAsyncPrepare then
  begin
    FAAttributes.Copy(Signer.AuthenticatedAttributes);
    FUAttributes.Copy(Signer.UnauthenticatedAttributes);
    Result := 0;
    Exit;
  end;
  Serial := GetOriginalSerialNumber(Certificate);
  Signer.Issuer.SerialNumber := Serial;
  Signer.Issuer.Issuer.Count := Certificate.IssuerRDN.Count;
  for I := 0 to Certificate.IssuerRDN.Count - 1 do
  begin
    Signer.Issuer.Issuer.Values[I] := CloneArray(Certificate.IssuerRDN.Values[I]);
    Signer.Issuer.Issuer.OIDs[I] := CloneArray(Certificate.IssuerRDN.OIDs[I]);
    Signer.Issuer.Issuer.Tags[I] := Certificate.IssuerRDN.Tags[I];
    Signer.Issuer.Issuer.Groups[I] := Certificate.IssuerRDN.Groups[I];
  end;
  Signer.DigestAlgorithm := CloneArray(DigestAlgorithm);
  Signer.DigestAlgorithmParams := EmptyArray;
  if (Certificate.PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION) and (not UsePSS) then
  begin
    if Length(FDigestEncryptionAlgorithm) = 0 then
      Signer.DigestEncryptionAlgorithm := SB_OID_RSAENCRYPTION
    else
      Signer.DigestEncryptionAlgorithm := FDigestEncryptionAlgorithm;
    Signer.DigestEncryptionAlgorithmParams := EmptyArray;
    if FOperationType = sotGeneric then
    begin
      if not SignRSA(Certificate, Hash,  HashSize,  DigestAlgorithm, EncryptedDigest) then
      begin
        Result := SB_MESSAGE_ERROR_KEYOP_FAILED_RSA;
        Exit;
      end;
    end
    else if FOperationType = sotAsyncComplete then
      EncryptedDigest :=  CloneArray(Hash, HashSize) 
    else
      EncryptedDigest := EmptyArray;
    Signer.EncryptedDigest := EncryptedDigest;
    FAAttributes.Copy(Signer.AuthenticatedAttributes);
    FUAttributes.Copy(Signer.UnauthenticatedAttributes);
  end
  else if (Certificate.PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSAPSS) or
    ((Certificate.PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION) and UsePss) then
  begin
    if Length(FDigestEncryptionAlgorithm) = 0 then
      Signer.DigestEncryptionAlgorithm := SB_OID_RSAPSS
    else
      Signer.DigestEncryptionAlgorithm := FDigestEncryptionAlgorithm;

    if FOperationType = sotGeneric then
    begin
      AlgID := TElRSAPSSAlgorithmIdentifier.Create;

      try
        AlgID.Assign(Certificate.PublicKeyAlgorithmIdentifier);
        Signer.DigestEncryptionAlgorithmParams := AlgID.WriteParameters;
      finally
        FreeAndNil(AlgID);
      end;

      if not SignRSAPSS(Certificate, Hash,  HashSize,  
        EncryptedDigest)
      then
      begin
        Result := SB_MESSAGE_ERROR_KEYOP_FAILED_RSA_PSS;
        Exit;
      end;
    end
    else if FOperationType = sotAsyncComplete then
      EncryptedDigest :=  CloneArray(Hash, HashSize) 
    else
      EncryptedDigest := EmptyArray;

    Signer.EncryptedDigest := EncryptedDigest;
    FAAttributes.Copy(Signer.AuthenticatedAttributes);
    FUAttributes.Copy(Signer.UnauthenticatedAttributes);
  end
  else if Certificate.PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_DSA then
  begin
    if Length(FDigestEncryptionAlgorithm) = 0 then
      Signer.DigestEncryptionAlgorithm := SB_OID_DSA
    else
      Signer.DigestEncryptionAlgorithm := FDigestEncryptionAlgorithm;
    Signer.DigestEncryptionAlgorithmParams := EmptyArray;
    if FOperationType = sotGeneric then
    begin
      if not SignDSA(Certificate, Hash,  HashSize,  EncryptedDigest) then
      begin
        Result := SB_MESSAGE_ERROR_KEYOP_FAILED_DSA;
        Exit;
      end;
    end
    else
    if FOperationType = sotAsyncComplete then
      EncryptedDigest :=  CloneArray(Hash, HashSize) 
    else
      EncryptedDigest := EmptyArray;
    Signer.EncryptedDigest := EncryptedDigest;
    FAAttributes.Copy(Signer.AuthenticatedAttributes);
    FUAttributes.Copy(Signer.UnauthenticatedAttributes);
  end
  {$ifdef SB_HAS_ECC}
  else if Certificate.PublicKeyAlgorithm = SB_CERT_ALGORITHM_EC then
  begin
    SigAlg := GetSigAlgorithmByHashAlgorithm(SB_CERT_ALGORITHM_EC,
      GetAlgorithmByOID(DigestAlgorithm));
    if Length(FDigestEncryptionAlgorithm) = 0 then
    begin
      if SigAlg <> SB_ALGORITHM_UNKNOWN then
        Signer.DigestEncryptionAlgorithm := GetOIDByAlgorithm(SigAlg)
      else
        Signer.DigestEncryptionAlgorithm := SB_OID_ECDSA_SHA1
    end
    else
      Signer.DigestEncryptionAlgorithm := FDigestEncryptionAlgorithm;
    Signer.DigestEncryptionAlgorithmParams := EmptyArray;
    if FOperationType = sotGeneric then
    begin
      if not SignEC(Signer, Certificate, Hash,  HashSize,  EncryptedDigest) then
      begin
        Result := SB_MESSAGE_ERROR_KEYOP_FAILED_EC;
        Exit;
      end;
    end
    else if FOperationType = sotAsyncComplete then
      EncryptedDigest :=  CloneArray(Hash, HashSize) 
    else
      EncryptedDigest := EmptyArray;
    Signer.EncryptedDigest := EncryptedDigest;
    FAAttributes.Copy(Signer.AuthenticatedAttributes);
    FUAttributes.Copy(Signer.UnauthenticatedAttributes);
  end
   {$endif}
  {$ifdef SB_HAS_GOST}
  else if Certificate.PublicKeyAlgorithm = SB_CERT_ALGORITHM_GOST_R3410_2001 then
  begin
    //SigAlg := SB_CERT_ALGORITHM_GOST_R3411_WITH_R3410_2001; // -- not needed? EM

    if Length(FDigestEncryptionAlgorithm) = 0 then
      Signer.DigestEncryptionAlgorithm := SB_OID_GOST_R3410_2001
    else
      Signer.DigestEncryptionAlgorithm := FDigestEncryptionAlgorithm;
      
    Signer.DigestEncryptionAlgorithmParams := EmptyArray;
    if FOperationType = sotGeneric then
    begin
      if not SignGOST2001(Signer, Certificate, Hash,  HashSize,  EncryptedDigest) then
      begin
        Result := SB_MESSAGE_ERROR_KEYOP_FAILED_GOST;
        Exit;
      end;
    end
    else if FOperationType = sotAsyncComplete then
      EncryptedDigest :=  CloneArray(Hash, HashSize) 
    else
      EncryptedDigest := EmptyArray;
      
    Signer.EncryptedDigest := EncryptedDigest;
    FAAttributes.Copy(Signer.AuthenticatedAttributes);
    FUAttributes.Copy(Signer.UnauthenticatedAttributes);
  end
   {$endif}
  else
  begin
    Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
    Exit;
  end;

  Result := 0;
end;

function TElMessageSigner.InternalCountersign(InBuffer : pointer; InSize : integer;
  OutBuffer : pointer; var OutSize : integer; InStream, OutStream : TStream;
  InCount : Int64): integer;
var
  Msg : TElPKCS7Message;
  SgnData : TElPKCS7SignedData;
  I, J, K : integer;
  Countersignature : TElPKCS7Signer;
  Hash, HashSource : ByteArray;
  DAlg : ByteArray;
  Index, Cnt : integer;
  Buf : ByteArray;
  BufSize : integer;
  Tag : TElASN1ConstrainedTag;
  BufferSource : boolean;
  DataSource : TElASN1DataSource;
  OrigOffset : Int64;
  Total : Int64;
begin
  // Only public-key countersigning is allowed
  if FSignatureType <> mstPublicKey then
  begin
    Result := SB_MESSAGE_ERROR_UNSUPPORTED_SIGNATURE_TYPE;
    Exit;
  end;
  // checking that CertStorage is assigned
  if (not Assigned(FCertStorage)) or (FCertStorage.Count = 0) then
  begin
    Result := SB_MESSAGE_ERROR_NO_CERTIFICATE;
    Exit;
  end;
  Result := SB_MESSAGE_ERROR_SIGNING_FAILED;
  DataSource := nil;
  if InStream <> nil then
    OrigOffset := InStream.Position
  else
    OrigOffset := 0;

  if InStream <> nil then
  begin
    if InCount = 0 then
      Total := InStream. Size  - InStream.Position
    else
      Total := InCount;
  end
  else
    Total := InSize;
  if not DoProgress(Total, 0) then
    RaiseCancelledByUserError;

  // processing input message
  try
    Msg := TElPKCS7Message.Create;
    try
      if not (soRawCountersign in SigningOptions) then
      begin
        if InStream <> nil then
          Result := Msg.LoadFromStream(InStream, InCount)
        else
          Result := Msg.LoadFromBuffer(InBuffer, InSize);
        if Result <> 0 then
          Exit;
        if Msg.ContentType <> ctSignedData then
        begin
          Result := SB_MESSAGE_ERROR_NO_SIGNED_DATA;
          Exit;
        end;
        SgnData := Msg.SignedData;

        if IncludeCertificates then
        begin
          for I := 0 to FCertStorage.Count - 1 do
            SgnData.Certificates.Add(FCertStorage.Certificates[I], false);
          // include certificate chain if needed
          if FIncludeChain and (FCertStorage.Count = 1) and (FCertStorage.Certificates[0].Chain <> nil) then
          begin
            for I := 0 to FCertStorage.Certificates[0].Chain.Count - 1 do
            begin
              if not (FCertStorage.Certificates[0].Chain.Certificates[I].Equals(FCertStorage.Certificates[0])) then
                SgnData.Certificates.Add(FCertStorage.Certificates[0].Chain.Certificates[I], false);
            end;
          end;
        end;
      end
      else
        SgnData := nil;

      // preparing attributes according to the specification (RFC3852)
      // 1. The signedAttributes field MUST NOT contain a content-type
      //   attribute; there is no content type for countersignatures.
      I := 0;
      while I < FAAttributes.Count do
      begin
        if CompareContent(FAAttributes.Attributes[I], SB_OID_CONTENT_TYPE) then
          FAAttributes.Remove(I)
        else
          Inc(I);
      end;

      // countersigning with each certificate that has a corresponding private key
      for I := 0 to FCertStorage.Count - 1 do
      begin
        if FCertStorage.Certificates[I].PrivateKeyExists {and
          FCertStorage.Certificates[I].PrivateKeyExtractable} then
        begin
          // signing all existing signatures
          if soRawCountersign in SigningOptions then
            Cnt := 1
          else
            Cnt := SgnData.SignerCount;
          for J := 0 to Cnt - 1 do
          begin
            // calculating hash over existing digest
            if not (soRawCountersign in SigningOptions) then
            begin
              HashSource := SgnData.Signers[J].EncryptedDigest;
              BufferSource := true;
            end
            else
            begin
              if InStream <> nil then
              begin
                DataSource := TElASN1DataSource.Create();
                DataSource.Init(InStream, OrigOffset, InCount);
                BufferSource := false;
              end
              else
              begin
                SetLength(HashSource, InSize);
                SBMove(InBuffer^, HashSource[0], Length(HashSource));
                BufferSource := true;
              end;
            end;

            if BufferSource then
            begin
              Hash := CalculateDigest(@HashSource[0], Length(HashSource), FAlgorithm);
            end
            else
            begin
              Hash := CalculateDigest(nil, 0, FAlgorithm, nil, DataSource, false);
              InStream.Position := OrigOffset;
            end;
            if Length(Hash) = 0 then
            begin
              Result := SB_MESSAGE_ERROR_UNSUPPORTED_ALGORITHM;
              Exit;
            end;
            DAlg := GetOIDByHashAlgorithm(FAlgorithm);

            // 2. The signedAttributes field MUST contain a message-digest
            //   attribute if it contains any other attributes.
            if FAAttributes.Count > 0 then
            begin
              Index := -1;
              for K := 0 to FAAttributes.Count - 1 do
              begin
                if CompareContent(FAAttributes.Attributes[K], SB_OID_MESSAGE_DIGEST) then
                begin
                  Index := K;
                  Break;
                end;
              end;
              if Index = -1 then
              begin
                Index := FAAttributes.Count;
                FAAttributes.Count := FAAttributes.Count + 1;
                FAAttributes.Attributes[Index] := SB_OID_MESSAGE_DIGEST;
              end;
              FAAttributes.Values[Index].Clear();
              FAAttributes.Values[Index].Add(FormatAttributeValue(SB_ASN1_OCTETSTRING,
                Hash));
              // calculating hash over authenticated attributes
              BufSize := 0;
              FAAttributes.SaveToBuffer( nil ,
                BufSize);
              SetLength(Buf, BufSize);
              FAAttributes.SaveToBuffer(@Buf[0], BufSize);
              Hash := CalculateDigest(@Buf[0], BufSize, FAlgorithm);
            end;

            // creating countersignature field
            Countersignature := TElPKCS7Signer.Create;
            try
              Result := FillSigner(Countersignature, FCertStorage.Certificates[I], DAlg,
                @Hash[0], Length(Hash));
              if Result <> 0 then
                Exit;

              // adding the corresponding attribute to the signer's
              // unsigned attributes list
              Tag := TElASN1ConstrainedTag.CreateInstance;
              try
                SaveSignerInfo(Tag, Countersignature);
                BufSize := 0;
                Tag.SaveToBuffer( nil , BufSize);
                SetLength(Buf, BufSize);
                Tag.SaveToBuffer(@Buf[0], BufSize);
                SetLength(Buf, BufSize);
              finally
                FreeAndNil(Tag);
              end;
              if not (soRawCountersign in SigningOptions) then
              begin
                Index := SgnData.Signers[J].UnauthenticatedAttributes.Count;
                SgnData.Signers[J].UnauthenticatedAttributes.Count := Index + 1;
                SgnData.Signers[J].UnauthenticatedAttributes.Attributes[Index] :=
                  SB_OID_COUNTER_SIGNATURE;
                SgnData.Signers[J].UnauthenticatedAttributes.Values[Index].Add(Buf);
              end
              else
              begin
                if OutStream = nil then
                begin
                  if BufSize > OutSize then
                  begin
                    Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL;
                    OutSize := BufSize;
                  end
                  else
                  begin
                    SBMove(Buf[0], OutBuffer^, BufSize);
                    OutSize := BufSize;
                    Result := 0;
                  end;
                end
                else
                  OutStream.Write(Buf[0], BufSize);
              end;
            finally
              FreeAndNil(CounterSignature);
            end;
          end;
          if soRawCountersign in SigningOptions then
            Break; // for raw countersignature, signing only with first certificate
                   // that has a corresponding private key
        end;
      end;

      if not (soRawCountersign in SigningOptions) then
      begin
        // saving the message
        if OutStream = nil then
        begin
          if Msg.SaveToBuffer(OutBuffer, OutSize) then
            Result := 0
          else
            Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL;
        end
        else
        begin
          Msg.SaveToStream(OutStream);
          Result := 0;
        end;
      end;

    finally
      FreeAndNil(Msg);
      if DataSource <> nil then
        FreeAndNil(DataSource);
      if not DoProgress(Total, Total) then
        RaiseCancelledByUserError;
    end;
  except
    on E : Exception do
    begin
      FErrorInfo := E. Message ;
      Result := SB_MESSAGE_ERROR_SIGNING_FAILED;
    end;
  end;
end;

function TElMessageSigner.Countersign(InBuffer : pointer; InSize : integer;
  OutBuffer : pointer; var OutSize : integer): integer;
begin
  FErrorInfo := '';
  Result := InternalCountersign(InBuffer, InSize, OutBuffer, OutSize, nil, nil, 0);
end;

function TElMessageSigner.Countersign(InStream, OutStream : TElStream;
  InCount : Int64  =  0): integer;
var
  OutSize : TSBInteger;
begin
  FErrorInfo := '';
  OutSize := 0;
  Result := InternalCountersign(nil, 0, nil, OutSize, InStream, OutStream, InCount);
end;

function TElMessageSigner.SignRSAPSS(Certificate : TElX509Certificate;
  Digest : pointer; DigestSize: integer; var Signature : ByteArray) : boolean;
var
  SigSize : integer;
  Crypto : TElRSAPublicKeyCrypto;
  KeyMaterial : TElRSAKeyMaterial;
begin
  try
    Crypto := TElRSAPublicKeyCrypto.Create(FCryptoProviderManager, nil);
    try
      KeyMaterial := TElRSAKeyMaterial.Create(FCryptoProviderManager, nil);
      try
        KeyMaterial.Assign(Certificate.KeyMaterial);
        KeyMaterial.HashAlgorithm := FAlgorithm;
        Crypto.KeyMaterial := KeyMaterial;
        Crypto.CryptoType := rsapktPSS;
        SigSize := 0;
        Crypto.SignDetached(Digest, DigestSize, nil, SigSize);
        SetLength(Signature, SigSize);
        Crypto.SignDetached(Digest, DigestSize, @Signature[0], SigSize);
        SetLength(Signature, SigSize);
        Result := true;
      finally
        FreeAndNil(KeyMaterial);
      end;
    finally
      FreeAndNil(Crypto);
    end;
  except
    Result := false;
  end;
end;

function TElMessageSigner.SignDSA(Certificate : TElX509Certificate; Digest : pointer;
  DigestSize: integer; var Signature : ByteArray) : boolean;
var
  Crypto : TElDSAPublicKeyCrypto;
  KeyMaterial : TElDSAKeyMaterial;
  Sz : integer;
begin
  try
    Crypto := TElDSAPublicKeyCrypto.Create(FCryptoProviderManager, nil);
    try
      KeyMaterial := TElDSAKeyMaterial.Create(FCryptoProviderManager, nil);
      try
        KeyMaterial.Assign(Certificate.KeyMaterial);
        Crypto.KeyMaterial := KeyMaterial;
        Sz := 0;
        Crypto.InputIsHash := true;
        Crypto.SignDetached(Digest, DigestSize, nil, Sz);
        SetLength(Signature, Sz);
        Crypto.SignDetached(Digest, DigestSize, @Signature[0], Sz);
        SetLength(Signature, Sz);
        Result := true;
      finally
        FreeAndNil(KeyMaterial);
      end;
    finally
      FreeAndNil(Crypto);
    end;
  except
    Result := false;
  end;
end;

{$ifdef SB_HAS_ECC}
function TElMessageSigner.SignEC(Signer : TElPKCS7Signer; Certificate : TElX509Certificate; Digest : pointer;
  DigestSize: integer; var Signature : ByteArray) : boolean;
var
  Crypto : TElECDSAPublicKeyCrypto;
  KeyMaterial : TElECKeyMaterial;
  Sz : integer;
begin
  try
    Crypto := TElECDSAPublicKeyCrypto.Create(Signer.DigestEncryptionAlgorithm, FCryptoProviderManager, nil);
    try
      KeyMaterial := TElECKeyMaterial.Create(FCryptoProviderManager, nil);
      try
        KeyMaterial.Assign(Certificate.KeyMaterial);
        Crypto.KeyMaterial := KeyMaterial;
        Sz := 0;
        Crypto.InputIsHash := true;
        Crypto.SignDetached(Digest, DigestSize, nil, Sz);
        SetLength(Signature, Sz);
        Crypto.SignDetached(Digest, DigestSize, @Signature[0], Sz);
        SetLength(Signature, Sz);
        Result := true;
      finally
        FreeAndNil(KeyMaterial);
      end;
    finally
      FreeAndNil(Crypto);
    end;
  except
    Result := false;
  end;
end;
 {$endif}

{$ifdef SB_HAS_GOST}
function TElMessageSigner.SignGOST2001(Signer : TElPKCS7Signer; Certificate : TElX509Certificate; Digest : pointer;
  DigestSize: integer; var Signature : ByteArray) : boolean;
var
  Crypto : TElGOST2001PublicKeyCrypto;
  KeyMaterial : TElGOST2001KeyMaterial;
  Sz : integer;
begin
  try
    Crypto := TElGOST2001PublicKeyCrypto.Create(Signer.DigestEncryptionAlgorithm, FCryptoProviderManager, nil);
    try
      KeyMaterial := TElGOST2001KeyMaterial.Create(FCryptoProviderManager, nil);
      try
        KeyMaterial.Assign(Certificate.KeyMaterial);
        Crypto.KeyMaterial := KeyMaterial;
        Sz := 0;
        Crypto.InputIsHash := true;
        Crypto.SignDetached(Digest, DigestSize, nil, Sz);
        SetLength(Signature, Sz);
        Crypto.SignDetached(Digest, DigestSize, @Signature[0], Sz);
        SetLength(Signature, Sz);
        Result := true;
      finally
        FreeAndNil(KeyMaterial);
      end;
    finally
      FreeAndNil(Crypto);
    end;
  except
    Result := false;
  end;
end;
 {$endif}     

function TElMessageSigner.CalculateEstimatedSize(InputSize : integer; Detached : boolean) : integer;
var
  DumbMessage : TElPKCS7Message;
  Cnt : ByteArray;
  I, J, K : integer;
  SzA, SzB : integer;
begin
  Result := 0;
  if FOperationType = sotGeneric then
  begin
    if (not Assigned(FCertStorage)) and
       (SignatureType = mstPublicKey) then
      Exit;
    if (not Assigned(FRecipientCerts)) and
       (SignatureType = mstMAC) then
      Exit;
  end;

  DumbMessage := TElPKCS7Message.Create;
  try
    if SignatureType = mstPublicKey then
    begin
      DumbMessage.ContentType := ctSignedData;
      if FCertStorage <> nil then
      begin
        FCertStorage.ExportTo(DumbMessage.SignedData.Certificates);
        if FIncludeChain and (FCertStorage.Count = 1) and (FCertStorage.Certificates[0].Chain <> nil) then
        begin
          for I := 0 to FCertStorage.Certificates[0].Chain.Count - 1 do
          begin
            if not (FCertStorage.Certificates[0].Chain.Certificates[I].Equals(FCertStorage.Certificates[0])) then
              DumbMessage.SignedData.Certificates.Add(FCertStorage.Certificates[0].Chain.Certificates[I]);
          end;
        end;
      end;
      if not Detached then
        SetLength(Cnt, InputSize)
      else
        SetLength(Cnt, 0);
      DumbMessage.SignedData.Content := CloneArray(Cnt);
      DumbMessage.SignedData.ContentType := FContentType;//SB_OID_PKCS7_DATA;
      if FCertStorage <> nil then
      begin
        for I := 0 to FCertStorage.Count - 1 do
        begin
          if FCertStorage.Certificates[I].PrivateKeyExists then
          begin
            K := DumbMessage.SignedData.AddSigner;
            DumbMessage.SignedData.Signers[K].Issuer.SerialNumber :=
              FCertStorage.Certificates[I].SerialNumber;
            DumbMessage.SignedData.Signers[K].Issuer.Issuer.Count :=
              FCertStorage.Certificates[I].IssuerRDN.Count;
            for J := 0 to FCertStorage.Certificates[I].IssuerRDN.Count - 1 do
            begin
              DumbMessage.SignedData.Signers[K].Issuer.Issuer.Values[J] :=
                FCertStorage.Certificates[I].IssuerRDN.Values[J];
              DumbMessage.SignedData.Signers[K].Issuer.Issuer.OIDs[J] :=
                FCertStorage.Certificates[I].IssuerRDN.OIDs[J];
            end;
            DumbMessage.SignedData.Signers[K].DigestAlgorithm := {$ifndef SB_BUFFERTYPE_IS_BYTEARRAY}TByteArrayConst {$else}BytesOfString {$endif}(#0#0#0#0#0#0#0#0#0#0#0#0);
            DumbMessage.SignedData.Signers[K].DigestAlgorithmParams := EmptyArray;
            FAAttributes.Copy(DumbMessage.SignedData.Signers[K].AuthenticatedAttributes);
            FUAttributes.Copy(DumbMessage.SignedData.Signers[K].UnauthenticatedAttributes);
            if (FCertStorage.Certificates[I].PublicKeyAlgorithm =
              SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION) and (not UsePSS) then
            begin
              DumbMessage.SignedData.Signers[K].DigestEncryptionAlgorithm := SB_OID_RSAENCRYPTION;
              DumbMessage.SignedData.Signers[K].DigestEncryptionAlgorithmParams := EmptyArray;
              SzA := 0;
              SzB := 0;
              FCertStorage.Certificates[I].GetRSAParams(nil, SzA, nil, SzB);
              SetLength(Cnt, SzA);
              DumbMessage.SignedData.Signers[K].EncryptedDigest := CloneArray(Cnt);
            end
            else if ((FCertStorage.Certificates[I].PublicKeyAlgorithm =
              SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION) and UsePSS) or
              (FCertStorage.Certificates[I].PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSAPSS) then
            begin
              DumbMessage.SignedData.Signers[K].DigestEncryptionAlgorithm := SB_OID_RSAPSS;
              DumbMessage.SignedData.Signers[K].DigestEncryptionAlgorithmParams :=
                TElRSAKeyMaterial.WritePSSParams(SB_ALGORITHM_DGST_SHA1, 20, SB_CERT_MGF1, 1);
              SzA := 0;
              SzB := 0;
              FCertStorage.Certificates[I].GetRSAParams(nil, SzA, nil, SzB);
              SetLength(Cnt, SzA);
              DumbMessage.SignedData.Signers[K].EncryptedDigest := CloneArray(Cnt);
            end
            else if (FCertStorage.Certificates[I].PublicKeyAlgorithm =
              SB_CERT_ALGORITHM_ID_DSA) then
            begin
              DumbMessage.SignedData.Signers[K].DigestEncryptionAlgorithm := SB_OID_DSA;
              DumbMessage.SignedData.Signers[K].DigestEncryptionAlgorithmParams := EmptyArray;
              SetLength(Cnt, FCertStorage.Certificates[I].GetPublicKeySize shr 3);
              DumbMessage.SignedData.Signers[K].EncryptedDigest := CloneArray(Cnt);
            end;
          end;
        end;
      end;
    end
    else if SignatureType = mstMAC then
    begin
      DumbMessage.ContentType :=  ctAuthenticatedData ;
      if FRecipientCerts <> nil then
        FRecipientCerts.ExportTo(DumbMessage.AuthenticatedData.OriginatorCerts);
      if not Detached then
        SetLength(Cnt, InputSize)
      else
        SetLength(Cnt, 0);
      DumbMessage.AuthenticatedData.Content := CloneArray(Cnt);
      DumbMessage.AuthenticatedData.ContentType := FContentType;
      if FRecipientCerts <> nil then
      begin
        for I := 0 to FRecipientCerts.Count - 1 do
        begin
          K := DumbMessage.AuthenticatedData.AddRecipient;
          DumbMessage.AuthenticatedData.Recipients[K].Issuer.SerialNumber :=
            FRecipientCerts.Certificates[I].SerialNumber;
          DumbMessage.AuthenticatedData.Recipients[K].Issuer.Issuer.Count :=
            FRecipientCerts.Certificates[I].IssuerRDN.Count;
          for J := 0 to FRecipientCerts.Certificates[I].IssuerRDN.Count - 1 do
          begin
            DumbMessage.AuthenticatedData.Recipients[K].Issuer.Issuer.Values[J] :=
              FRecipientCerts.Certificates[I].IssuerRDN.Values[J];
            DumbMessage.AuthenticatedData.Recipients[K].Issuer.Issuer.OIDs[J] :=
              FRecipientCerts.Certificates[I].IssuerRDN.OIDs[J];
          end;
          DumbMessage.AuthenticatedData.Recipients[K].KeyEncryptionAlgorithm := {$ifndef SB_BUFFERTYPE_IS_BYTEARRAY}TByteArrayConst {$else}BytesOfString {$endif}(#0#0#0#0#0#0#0#0#0#0#0#0);
          DumbMessage.AuthenticatedData.Recipients[K].KeyEncryptionAlgorithmParams := EmptyArray;
          SzA := FRecipientCerts.Certificates[I].GetPublicKeySize shr 3 + 4;
          SetLength(Cnt, SzA);
          DumbMessage.AuthenticatedData.Recipients[K].EncryptedKey := CloneArray(Cnt);
        end;
      end;
      DumbMessage.AuthenticatedData.MacAlgorithm := {$ifndef SB_BUFFERTYPE_IS_BYTEARRAY}TByteArrayConst {$else}BytesOfString {$endif}(#0#0#0#0#0#0#0#0#0#0#0#0);
      DumbMessage.AuthenticatedData.DigestAlgorithm := {$ifndef SB_BUFFERTYPE_IS_BYTEARRAY}TByteArrayConst {$else}BytesOfString {$endif}(#0#0#0#0#0#0#0#0#0#0#0#0);
      SetLength(Cnt, 64);
      DumbMessage.AuthenticatedData.Mac := CloneArray(Cnt);
      FAAttributes.Copy(DumbMessage.AuthenticatedData.AuthenticatedAttributes);
      FUAttributes.Copy(DumbMessage.AuthenticatedData.UnauthenticatedAttributes);
    end;
    SzA := 0;
    DumbMessage.SaveToBuffer(nil, SzA);
    {$ifndef B_6}
    if (FTSPClient <> nil) and (DumbMessage.ContentType = ctSignedData) then
      Inc(SzA, 2048 + 4096 * DumbMessage.SignedData.SignerCount);
     {$endif}
  finally
    FreeAndNil(DumbMessage);
  end;
  Result := SzA;
  if (FOperationType in [sotAsyncPrepare, sotAsyncComplete]) and ((FCertStorage = nil) or (FCertStorage.Count = 0)) then
    Inc(Result, 4096); // reserving some place for the certificate
  Inc(Result, FExtraSpace);
end;

{$ifndef B_6}
function TElMessageSigner.TimestampMessage(Msg : TElPKCS7Message) : integer;
var
  OldCount : integer;
  I : integer;
  Func : TElHashFunction;
  Buf : ByteArray;
  Hash : ByteArray;
  ServerResult :  TSBPKIStatus ;
  FailureInfo : integer;
  ReplyCMS : ByteArray;
begin
  Result := 0;
  if (FTSPClient = nil) or (Msg.ContentType <> ctSignedData) then
    Exit;
  for I := 0 to Msg.SignedData.SignerCount - 1 do
  begin
    SetLength(Hash, 0);
    try
      Func := TElHashFunction.Create(FTSPClient.HashAlgorithm, TElCPParameters(nil), FCryptoProviderManager, nil);
      try
        Buf := CloneArray(Msg.SignedData.Signers[I].EncryptedDigest);
        Func.Update(Buf);
        Hash := Func.Finish;
      finally
        FreeAndNil(Func);
      end;
    except
      on E : EElHashFunctionUnsupportedError do
      begin
        Result := SB_MESSAGE_ERROR_UNSUPPORTED_DIGEST_ALGORITHM;
        Exit;
      end;
    end;
    Result := FTSPClient.Timestamp(Hash, ServerResult, FailureInfo, ReplyCMS);
    if Result <> 0 then
    begin
      if soIgnoreTimestampFailure in SigningOptions then
        Result := 0;
      Exit;
    end;
    if Length(ReplyCMS) > 0 then
    begin
      // adding a timestamp to the unauthenticated attributes sequence
      OldCount := Msg.SignedData.Signers[I].UnauthenticatedAttributes.Count;
      Msg.SignedData.Signers[I].UnauthenticatedAttributes.Count := OldCount + 1;
      Msg.SignedData.Signers[I].UnauthenticatedAttributes.Attributes[OldCount] := SB_OID_TIMESTAMP_TOKEN;
      Msg.SignedData.Signers[I].UnauthenticatedAttributes.Values[OldCount].Add(ReplyCMS);
    end;
  end;
end;

function TElMessageSigner.TimestampSignerInfo(SignerInfo : TElPKCS7Signer): integer;
var
  Hash : ByteArray;
  Func : TElHashFunction;
  Buf : ByteArray;
  ReplyCMS : ByteArray;
  ServerResult :  TSBPKIStatus ;
  FailureInfo : integer;
  OldCount : integer;
begin
  SetLength(Hash, 0);
  try
    Func := TElHashFunction.Create(FTSPClient.HashAlgorithm);
    try
      Buf := CloneArray(SignerInfo.EncryptedDigest);
      Func.Update(Buf);
      Hash := Func.Finish;
    finally
      FreeAndNil(Func);
    end;
  except
    on E : EElHashFunctionUnsupportedError do
    begin
      Result := SB_MESSAGE_ERROR_UNSUPPORTED_DIGEST_ALGORITHM;
      Exit;
    end;
  end;
  Result := FTSPClient.Timestamp(Hash, ServerResult, FailureInfo, ReplyCMS);
  if Result <> 0 then
  begin
    if soIgnoreTimestampFailure in SigningOptions then
      Result := 0;
    Exit;
  end;
  if Length(ReplyCMS) > 0 then
  begin
    // adding a timestamp to the unauthenticated attributes sequence
    OldCount := SignerInfo.UnauthenticatedAttributes.Count;
    SignerInfo.UnauthenticatedAttributes.Count := OldCount + 1;
    SignerInfo.UnauthenticatedAttributes.Attributes[OldCount] := SB_OID_TIMESTAMP_TOKEN;
    SignerInfo.UnauthenticatedAttributes.Values[OldCount].Add(ReplyCMS);
  end;
end;

function TElMessageSigner.TimestampCountersignatures(Msg : TElPKCS7Message;
  SigIndexes : array of integer): integer;
var
  I, J, K, L : integer;
  CurrSigIndex : integer;
  Signer, Info : TElPKCS7Signer;
  B : boolean;
  Countersignature : ByteArray;
  Tag, DestTag : TElASN1ConstrainedTag;
  R, Sz : integer;
begin
  Result := 0;
  if (FTSPClient = nil) or (Msg.ContentType <> ctSignedData) then
    Exit;
  CurrSigIndex := 0;
  for I := 0 to Msg.SignedData.SignerCount - 1 do
  begin
    Signer := Msg.SignedData.Signers[I];
    for K := 0 to Signer.UnauthenticatedAttributes.Count - 1 do
    begin
      if CompareContent(Signer.UnauthenticatedAttributes.Attributes[K],
        SB_OID_COUNTER_SIGNATURE) then
      begin
        for L := 0 to Signer.UnauthenticatedAttributes.Values[K].Count - 1 do
        begin
          B := false;
          for J := 0 to Length(SigIndexes) - 1 do
            if SigIndexes[J] = CurrSigIndex then
            begin
              B := true;
              Break;
            end;
          try
            if B then
            begin
              Countersignature := Signer.UnauthenticatedAttributes.Values[K].Item[L];
              Tag := TElASN1ConstrainedTag.CreateInstance;
              try
                if not Tag.LoadFromBuffer(@Countersignature[0], Length(Countersignature)) then
                begin
                  if not (soIgnoreBadCountersignatures in SigningOptions) then
                    Result := SB_MESSAGE_ERROR_INVALID_COUNTERSIGNATURE;
                  Break;
                end;
                if (Tag.Count <> 1) or (not Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
                begin
                  if not (soIgnoreBadCountersignatures in SigningOptions) then
                    Result := SB_MESSAGE_ERROR_INVALID_COUNTERSIGNATURE;
                  Break;
                end;
                Info := TElPKCS7Signer.Create;
                try
                  if ProcessSignerInfo(Tag.GetField(0), Info) <> 0 then
                  begin
                    if not (soIgnoreBadCountersignatures in SigningOptions) then
                      Result := SB_MESSAGE_ERROR_INVALID_COUNTERSIGNATURE;
                    Break;
                  end;
                  // requesting timestamp
                  R := TimestampSignerInfo(Info);
                  if Result = 0 then
                  begin
                    Result := R;
                    DestTag := TElASN1ConstrainedTag.CreateInstance();
                    try
                      SaveSignerInfo(DestTag, Info);
                      Sz := 0;
                      DestTag.SaveToBuffer( nil , Sz);
                      SetLength(Countersignature, Sz);
                      DestTag.SaveToBuffer( @Countersignature[0] , Sz);
                      SetLength(Countersignature, Sz);
                      Signer.UnauthenticatedAttributes.Values[K].Item[L] := Countersignature;
                    finally
                      FreeAndNil(DestTag);
                    end;
                  end;
                finally
                  FreeAndNil(Info);
                end;
              finally
                FreeAndNil(Tag);
              end;
            end;
          finally
            Inc(CurrSigIndex);
          end;
        end;
      end;
    end;
  end;
end;
 {$endif}


{$ifndef B_6}
function TElMessageSigner.Timestamp(InBuffer: pointer; InSize: integer; OutBuffer: pointer;
  var OutSize: integer): integer;
var
  Msg : TElPKCS7Message;
const
  TSP_DELTA = 8192;
begin
  if FTSPClient = nil then
  begin
    Result := SB_MESSAGE_ERROR_TSPCLIENT_NOT_FOUND;
    Exit;
  end;
  if OutSize < InSize + TSP_DELTA then
  begin
    OutSize := InSize + TSP_DELTA;
    Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL;
    Exit;
  end;
  Msg := TElPKCS7Message.Create;
  try
    Result := Msg.LoadFromBuffer(InBuffer, InSize);
    if Result <> 0 then
      Exit;
    if (Msg.ContentType <> ctSignedData) then
    begin
      Result := SB_MESSAGE_ERROR_NO_SIGNED_DATA;
      Exit;
    end;
    Result := TimestampMessage(Msg);
    if Result <> 0 then
      Exit;
    if Msg.SaveToBuffer(OutBuffer, OutSize) then
      Result := 0
    else
      Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL;
  finally
    FreeAndNil(Msg);
  end;
end;
 {$endif}

{$ifndef B_6}
function TElMessageSigner.Timestamp(InStream, OutStream : TStream; InCount : Int64 = 0): integer;
var
  Msg : TElPKCS7Message;
begin
  if FTSPClient = nil then
  begin
    Result := SB_MESSAGE_ERROR_TSPCLIENT_NOT_FOUND;
    Exit;
  end;
  Msg := TElPKCS7Message.Create;
  try
    Result := Msg.LoadFromStream(InStream, InCount);
    if Result <> 0 then
      Exit;
    if (Msg.ContentType <> ctSignedData) then
    begin
      Result := SB_MESSAGE_ERROR_NO_SIGNED_DATA;
      Exit;
    end;
    Result := TimestampMessage(Msg);
    if Result <> 0 then
      Exit;
    Msg.SaveToStream(OutStream);
  finally
    FreeAndNil(Msg);
  end;
end;
 {$endif}

{$ifndef B_6}
function TElMessageSigner.TimestampCountersignature(InBuffer: pointer; InSize: integer;
  OutBuffer: pointer; var OutSize: integer; SigIndex: integer): integer;
var
  Msg : TElPKCS7Message;
  SigIndexes : array of integer;
const
  TSP_DELTA = 8192;
begin
  if FTSPClient = nil then
  begin
    Result := SB_MESSAGE_ERROR_TSPCLIENT_NOT_FOUND;
    Exit;
  end;
  if OutSize < InSize + TSP_DELTA then
  begin
    OutSize := InSize + TSP_DELTA;
    Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL;
    Exit;
  end;
  Msg := TElPKCS7Message.Create;
  try
    Result := Msg.LoadFromBuffer(InBuffer, InSize);
    if Result <> 0 then
      Exit;
    if (Msg.ContentType <> ctSignedData) then
    begin
      Result := SB_MESSAGE_ERROR_NO_SIGNED_DATA;
      Exit;
    end;
    SetLength(SigIndexes, 1);
    SigIndexes[0] := SigIndex;
    Result := TimestampCountersignatures(Msg, SigIndexes);
    if Result <> 0 then
      Exit;
    if Msg.SaveToBuffer(OutBuffer, OutSize) then
      Result := 0
    else
      Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL;
  finally
    FreeAndNil(Msg);
  end;
end;
 {$endif}

{$ifndef B_6}
function TElMessageSigner.TimestampCountersignature(InStream, OutStream : TStream; SigIndex: integer;
  InCount : Int64 = 0): integer;
var
  Msg : TElPKCS7Message;
  SigIndexes : array of integer;
begin
  if FTSPClient = nil then
  begin
    Result := SB_MESSAGE_ERROR_TSPCLIENT_NOT_FOUND;
    Exit;
  end;
  Msg := TElPKCS7Message.Create;
  try
    Result := Msg.LoadFromStream(InStream, InCount); 
    if Result <> 0 then
      Exit;
    if (Msg.ContentType <> ctSignedData) then
    begin
      Result := SB_MESSAGE_ERROR_NO_SIGNED_DATA;
      Exit;
    end;
    SetLength(SigIndexes, 1);
    SigIndexes[0] := SigIndex;
    Result := TimestampCountersignatures(Msg, SigIndexes);
    if Result <> 0 then
      Exit;
    Msg.SaveToStream(OutStream);
  finally
    FreeAndNil(Msg);
  end;
end;
 {$endif}

////////////////////////////////////////////////////////////////////////////////
// TElMessageDecompressor

constructor TElMessageDecompressor.Create(AOwner : TComponent);
begin
  inherited Create (AOwner) ;

end;


 destructor  TElMessageDecompressor.Destroy;
begin
  inherited;
end;

procedure TElMessageDecompressor.Notification(AComponent : TComponent; AOperation : TOperation);
begin
  inherited;
end;

function TElMessageDecompressor.ZLibOutput(Buffer: pointer; Size: integer; Param: pointer): boolean;
var
  OldLen : integer;
begin
  OldLen := Length(FZLibSpool);
  SetLength(FZLibSpool, OldLen + Size);
  SBMove(Buffer^, FZLibSpool[OldLen], Size);
  Result := true;
end;

function TElMessageDecompressor.DecompressContent(InBuffer : pointer; InSize : integer; OutBuffer : pointer; var OutSize : integer) : boolean;
var
  ZLibCtx : TZlibContext;
begin
  SetLength(FZLibSpool, 0);
  InitializeDecompressionEx(ZLibCtx, true);
  DecompressEx(ZLibCtx, InBuffer,  InSize ,  ZLibOutput , nil);
  FinalizeDecompressionEx(ZLibCtx);
  if (OutSize < Length(FZlibSpool)) then
  begin
    OutSize := Length(FZlibSpool);
    Result := false;
  end
  else
  begin
    OutSize := Length(FZlibSpool);
    SBMove(FZlibSpool[0], OutBuffer^, OutSize);
    Result := true;
  end;

  SetLength(FZlibSpool, 0);
end;

function TElMessageDecompressor.CreateDecompressingStream(Source : TElPKCS7CompressedData): TElStream;
begin
  Result := TElZlibDecompressingStream.Create(Source);
  TElZlibDecompressingStream(Result).OnProgress  :=  OnDecompressingStreamProgress;
end;

procedure TElMessageDecompressor.OnDecompressingStreamProgress(Sender : TObject; Total, Current : Int64; var Cancel : TSBBoolean);
begin
  Cancel := false;
  if Assigned(FOnProgress) then
    FOnProgress(Self, Total, Current, Cancel);
end;

function TElMessageDecompressor.Decompress(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
  var OutSize : integer) : integer;
var
  FMessage : TElPKCS7Message;
begin
  CheckLicenseKey();


  FMessage := TElPKCS7Message.Create;
  try
    Result := FMessage.LoadFromBuffer(InBuffer, InSize);
    if Result <> 0 then
    begin
      FreeAndNil(FMessage);
      Result := SB_MESSAGE_ERROR_INVALID_FORMAT;
      Exit;
    end;
    if FMessage.ContentType <>  ctCompressedData  then
    begin
      Result := SB_MESSAGE_ERROR_NO_COMPRESSED_DATA;
      FreeAndNil(FMessage);
      Exit;
    end;

    FContentType := CloneArray(FMessage.CompressedData.ContentType);
    if not DecompressContent(@FMessage.CompressedData.CompressedContent[0], Length(FMessage.CompressedData.CompressedContent), OutBuffer, OutSize) then
      Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL
    else
      Result := 0;
  finally
    FreeAndNil(FMessage);
  end;
end;


function TElMessageDecompressor.Decompress(InStream, OutStream : TElStream;
  InCount : Int64  =  0): integer;
var
  FMessage : TElPKCS7Message;
  Buffer : ByteArray;
  Read : integer;
  DecomprStream : TElStream;
begin
  CheckLicenseKey();



  FMessage := TElPKCS7Message.Create;

  try
    Result := FMessage.LoadFromStream(InStream, InCount);

    if Result <> 0 then
    begin
      FreeAndNil(FMessage);
      Result := SB_MESSAGE_ERROR_INVALID_FORMAT;
      Exit;
    end;
    if FMessage.ContentType <>  ctCompressedData  then
    begin
      Result := SB_MESSAGE_ERROR_NO_COMPRESSED_DATA;
      FreeAndNil(FMessage);
      Exit;
    end;

    FContentType := CloneArray(FMessage.CompressedData.ContentType);

    try
      DecomprStream := CreateDecompressingStream(FMessage.CompressedData);
      SetLength(Buffer, 32768);

      repeat
        Read := DecomprStream.Read( Buffer[0] , 32768);
        if Read > 0 then
          OutStream.Write( Buffer[0] , Read);
      until Read = 0;
    finally
      FreeAndNil(DecomprStream);
    end;
  finally
    FreeAndNil(FMessage);
  end;

  Result := 0;
end;

{$ifndef SB_NO_COMPRESSION}
////////////////////////////////////////////////////////////////////////////////
// TElMessageCompressor

constructor TElMessageCompressor.Create(AOwner : TComponent);
begin
  inherited Create (AOwner) ;

  FCompressionLevel := 6;
  FFragmentSize := 65536;
  FContentType := EmptyArray;
  FUseUndefSize := true;
  SetLength(FContentToCompress, 0);
  SetLength(FCompressedContent, 0);
end;


 destructor  TElMessageCompressor.Destroy;
begin
  inherited;
end;

procedure TElMessageCompressor.Notification(AComponent : TComponent; AOperation : TOperation);
begin
  inherited;
end;

procedure TElMessageCompressor.CompressContent(InBuffer : pointer; InSize : integer; CompressionLevel : integer);
var
  ZLibCtx : TZlibContext;
  CSize, FSize : cardinal;
begin
  if (Length(FCompressedContent) > 0) and (InSize = Length(FContentToCompress)) and
    (CompareMem(InBuffer, @FContentToCompress[0], InSize))
  then
    Exit;

  SetLength(FContentToCompress, InSize);
  SBMove(InBuffer^, FContentToCompress[0], InSize);

  SetLength(FCompressedContent, InSize + InSize div 5 + 128); // should be enough
  CSize := Length(FCompressedContent);
  InitializeCompressionEx(ZLibCtx, CompressionLevel, -13);
  CompressEx(ZLibCtx, InBuffer, InSize,  @FCompressedContent[0] , CSize);
  FSize := Cardinal(Length(FCompressedContent)) - CSize;
  FinalizeCompressionEx(ZlibCtx, @FCompressedContent[CSize], FSize);
  SetLength(FCompressedContent, CSize + FSize);
end;

function TElMessageCompressor.CreateCompressingStream(Source : TElStream): TElStream;
begin
  Result := TElZlibCompressingStream.Create(Source, FCompressionLevel);
  TElZlibCompressingStream(Result).OnProgress  :=  OnCompressingStreamProgress;
end;

procedure TElMessageCompressor.OnCompressingStreamProgress(Sender : TObject; Total, Current : Int64; var Cancel : TSBBoolean);
begin
  Cancel := false;
  if Assigned(FOnProgress) then
    FOnProgress(Self, Total, Current, Cancel);
end;

function TElMessageCompressor.Compress(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
  var OutSize : integer) : integer;
var
  FMessage : TElPKCS7Message;
begin
  CheckLicenseKey();


  FMessage := TElPKCS7Message.Create;
  FMessage.ContentType := ctCompressedData;

  try
    FMessage.CompressedData.ContentType := CloneArray(FContentType);
    FMessage.CompressedData.FragmentSize := FFragmentSize;    
    FMessage.UseUndefSize := FUseUndefSize;

    CompressContent(InBuffer, InSize, FCompressionLevel);

    FMessage.CompressedData.DataSource.Init(@FCompressedContent[0], Length(FCompressedContent));

    if not FMessage.SaveToBuffer(OutBuffer, OutSize) then
      Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL
    else
      Result := 0;
  finally
    FreeAndNil(FMessage);
  end;
end;


function TElMessageCompressor.Compress(InStream, OutStream : TElStream;
  InCount : Int64  =  0): integer;
var
  FMessage : TElPKCS7Message;
  ComprStream : TElStream;
begin
  CheckLicenseKey();


  FMessage := TElPKCS7Message.Create;
  FMessage.ContentType := ctCompressedData;
  ComprStream := CreateCompressingStream(InStream);

  try
    FMessage.CompressedData.ContentType := CloneArray(FContentType);
    FMessage.CompressedData.FragmentSize := FFragmentSize;
    FMessage.UseUndefSize := FUseUndefSize;

    FMessage.CompressedData.DataSource.Init(ComprStream, true);

    FMessage.SaveToStream(OutStream);
  finally
    FreeAndNil(FMessage);
    FreeAndNil(ComprStream);
  end;

  Result := 0;
end;

procedure TElMessageCompressor.SetContentType(const V : ByteArray);
begin
  FContentType := CloneArray(V);
end;
 {$endif}

////////////////////////////////////////////////////////////////////////////////
// TElMessageTimestamper

constructor TElMessageTimestamper.Create(AOwner : TComponent);
begin
  inherited Create (AOwner) ;

  FUseUndefSize := true;
  FIncludeContent := true;
  FProtectMetadata := false;
  FDataURI := EmptyString;
  FFileName := EmptyString;
  FMediaType := EmptyString;
  FTSPClientList := TSBObjectList.Create;
  FTSPClientList.OwnsObjects := false;
end;


 destructor  TElMessageTimestamper.Destroy;
begin
  FreeAndNil(FTSPClientList);

  inherited;
end;

procedure TElMessageTimestamper.Notification(AComponent : TComponent; AOperation : TOperation);
begin
  inherited;
end;

function TElMessageTimestamper.GetTSPClients(Index : integer) : TElCustomTSPClient;
begin
  if (Index < 0) or (Index >= FTSPClientList.Count) then
    Result := nil
  else
    Result := TElCustomTSPClient(FTSPClientList[Index]);
end;

function TElMessageTimestamper.GetTSPClientsCount : integer;
begin
  Result := FTSPClientList.Count;
end;

function TElMessageTimestamper.GetTSPClient : TElCustomTSPClient;
begin
  Result := Self.TSPClients[0];
end;

procedure TElMessageTimestamper.SetTSPClient(Client : TElCustomTSPClient);
begin
  if FTSPClientList.Count > 0 then
    FTSPClientList[0] := Client
  else
    AddTSPClient(Client);
end;

function TElMessageTimestamper.AddTSPClient(Client : TElCustomTSPClient) : integer;
begin
  Result := FTSPClientList.Add(Client);
end;

procedure TElMessageTimestamper.RemoveTSPClient(Index : integer);
begin
  if (Index >= 0) and (Index < FTSPClientList.Count) then
    FTSPClientList. Delete (Index);
end;

procedure TElMessageTimestamper.RemoveTSPClient(Client : TElCustomTSPClient);
begin
  FTSPClientList.Remove(Client);
end;


function TElMessageTimestamper.CalculateEstimatedSize(InputSize : integer) : integer;
begin
  { should be enough }
  Result := InputSize + 2048 + 4096 * TSPClientsCount;
end;

function TElMessageTimestamper.Timestamp(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
  var OutSize : integer) : integer;
var
  InStream, OutStream : TElMemoryStream;
  i : integer;
begin
  i := CalculateEstimatedSize( InSize );
  if OutSize < i then
  begin
    Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL;
    OutSize := i;
    Exit;
  end;

  InStream := TElMemoryStream.Create;
  OutStream := TElMemoryStream.Create;

  try
    InStream.Write( InBuffer^, InSize );
    Result := Timestamp(InStream, OutStream, 0);

    if Result = 0 then
    begin
      if OutSize <= OutStream. Size  then
      begin
        OutSize := OutStream. Size ;
        OutStream.Position := 0;
        OutStream.Read( OutBuffer^ , OutSize);
      end
      else
      begin
        OutSize := OutStream. Size ;
        Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL;
      end;
    end;
  finally
    FreeAndNil(InStream);
    FreeAndNil(OutStream);
  end;
end;


function TElMessageTimestamper.Timestamp(InStream, OutStream : TElStream;
  InCount : Int64  =  0): integer;
var
  FMessage : TElPKCS7Message;
  i, Read : integer;
  OriginalPos, Offset : Int64;
  HashFunction : TElHashFunction;
  Buf : ByteArray;
  Hash : ByteArray;
  ServerResult :  TSBPKIStatus ;
  FailureInfo : integer;
  ReplyCMS : ByteArray;
begin
  CheckLicenseKey();


  if (not FIncludeContent) and (Length(FDataURI) = 0) and (Length(FFileName) = 0) then
  begin
    Result := SB_MESSAGE_ERROR_NO_CONTENT_OR_DATA_URI;
    Exit;
  end;

  if TSPClientsCount < 1 then
  begin
    Result := SB_MESSAGE_ERROR_TSPCLIENT_NOT_FOUND;
    Exit;
  end;

  FMessage := TElPKCS7Message.Create;
  FMessage.ContentType := ctTimestampedData;

  try
    FMessage.TimestampedData.DataURI := {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}BytesOfString {$endif}(FDataURI);
    FMessage.TimestampedData.FileName := StrToUtf8(FFileName);
    FMessage.TimestampedData.MediaType := {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}BytesOfString {$endif}(FMediaType);
    FMessage.TimestampedData.HashProtected := FProtectMetadata;
    FMessage.TimestampedData.MetaDataAvailable := FProtectMetadata or (Length(FFileName) > 0) or (Length(FMediaType) > 0); 
    FMessage.UseUndefSize := FUseUndefSize;

    { calculating the first hash over the content and metadata }

    try
      HashFunction := TElHashFunction.Create(TSPClients[0].HashAlgorithm, TElCPParameters(nil), FCryptoProviderManager, nil);
    except
      on E : EElHashFunctionUnsupportedError do
      begin
        Result := SB_MESSAGE_ERROR_UNSUPPORTED_DIGEST_ALGORITHM;
        Exit;
      end;
    end;

    try
      if FMessage.TimestampedData.MetaDataAvailable and FProtectMetadata then
      begin
        Buf := FMessage.TimestampedData.WriteMetadata;
        HashFunction.Update(Buf);
      end;

      OriginalPos := InStream.Position;
      Offset := InStream.Position;
      if InCount = 0 then
        InCount := InStream. Size  - OriginalPos;

      SetLength(Buf, 32768);

      while Offset < OriginalPos + InCount do
      begin
        Read := InStream.Read( Buf[0] , Length(Buf));
        if Read > 0 then
        begin
          HashFunction.Update( @Buf[0] , Read);
          Inc(Offset, Read);

          if not DoProgress(InStream. Size , Offset) then
            RaiseCancelledByUserError;
        end;
      end;

      Hash := HashFunction.Finish;
    finally
      FreeAndNil(HashFunction);
      ReleaseArray(Buf);
    end;

    InStream.Position := OriginalPos;
    
    Result := TSPClients[0].Timestamp(Hash, ServerResult, FailureInfo, ReplyCMS);
    if (Result <> 0) or (Length(ReplyCMS) = 0) then
    begin
      Result := SB_MESSAGE_ERROR_TIMESTAMPING_FAILED;
      Exit;
    end;

    FMessage.TimestampedData.AddTimestamp;
    FMessage.TimestampedData.Timestamps[0].EncodedTimestamp := CloneArray(ReplyCMS);

    { calculating second and other timestamps over the previous one }

    for i := 1 to TSPClientsCount - 1 do
    begin
      try
        HashFunction := TElHashFunction.Create(TSPClients[i].HashAlgorithm, TElCPParameters(nil), FCryptoProviderManager, nil);
      except
        on E : EElHashFunctionUnsupportedError do
        begin
          Result := SB_MESSAGE_ERROR_UNSUPPORTED_DIGEST_ALGORITHM;
          Exit;
        end;
      end;

      try
        Buf := FMessage.TimestampedData.WriteTimestampAndCRL(FMessage.TimestampedData.Timestamps[i - 1]);
        HashFunction.Update(Buf);
        Hash := HashFunction.Finish;
      finally
        FreeAndNil(HashFunction);
        ReleaseArray(Buf);
      end;

      Result := TSPClients[i].Timestamp(Hash, ServerResult, FailureInfo, ReplyCMS);
      if (Result <> 0) or (Length(ReplyCMS) = 0) then
      begin
        Result := SB_MESSAGE_ERROR_TIMESTAMPING_FAILED;
        Exit;
      end;

      FMessage.TimestampedData.AddTimestamp;
      FMessage.TimestampedData.Timestamps[i].EncodedTimestamp := CloneArray(ReplyCMS);
    end;

    if FIncludeContent then
      FMessage.TimestampedData.DataSource.Init(InStream, OriginalPos, InCount);

    FMessage.SaveToStream(OutStream);
    Result := 0;
  finally
    FreeAndNil(FMessage);
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// TElMessageTimestamVerifier

function TElMessageTimestampVerifier.GetTimestamp(Index: integer): TElClientTSPInfo;
begin
  if (Index >= 0) and (Index < FTimestamps.Count) then
    Result := TElClientTSPInfo(FTimestamps[Index])
  else
    Result := nil;    
end;

function TElMessageTimestampVerifier.GetTimestampCount: integer;
begin
  Result := FTimestamps.Count;
end;

procedure TElMessageTimestampVerifier.Notification(AComponent : TComponent; AOperation : TOperation);
begin
  inherited;
end;


constructor TElMessageTimestampVerifier.Create(AOwner : TComponent);
begin
  inherited Create (AOwner) ;

  FDataURI := EmptyString;
  FFileName := EmptyString;
  FMediaType := EmptyString;
  FTimestamps := TElList.Create;
end;


 destructor  TElMessageTimestampVerifier.Destroy;
var
  i : integer;
begin
  for i := 0 to FTimestamps.Count - 1 do
    TElClientTSPInfo(FTimestamps[i]).Free;
  FreeAndNil(FTimestamps);
  inherited;
end;


function TElMessageTimestampVerifier.Verify(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
  var OutSize : integer) : integer;
var
  InStream, OutStream : TElMemoryStream;
begin
  if OutSize <  InSize  then
  begin
    OutSize :=  InSize ;
    Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL;
    Exit;
  end;

  InStream := TElMemoryStream.Create;
  OutStream := TElMemoryStream.Create;

  try
    InStream.Write( InBuffer^, InSize );
    InStream.Position := 0;
    Result := Verify(InStream, OutStream);

    if Result = 0 then
    begin
      if OutStream. Size  > OutSize then
      begin
        OutSize := OutStream. Size ;
        Result := SB_MESSAGE_ERROR_BUFFER_TOO_SMALL;
      end
      else
      begin
        OutSize := OutStream. Size ;
        OutStream.Position := 0;
        OutStream.Read( OutBuffer^, OutSize );
      end;
    end;
  finally
    FreeAndNil(InStream);
    FreeAndNil(OutStream);
  end;
end;


function TElMessageTimestampVerifier.VerifyDetached(Buffer : pointer; Size : integer; Data : pointer;
  DataSize : integer) : integer;
var
  InStream, DataStream : TElMemoryStream;
begin
  InStream := TElMemoryStream.Create;
  DataStream := TElMemoryStream.Create;

  try
    InStream.Write( Buffer^, Size );
    InStream.Position := 0;
    DataStream.Write( Data^, DataSize );
    DataStream.Position := 0;

    Result := VerifyDetached(InStream, DataStream);
  finally
    FreeAndNil(InStream);
    FreeAndNil(DataStream);
  end;
end;



class function TElMessageTimestampVerifier.IsTimestampDetached(Timestamp : pointer; Size : integer; var DataURI : string; var FileName : string) : boolean;
var
  Msg : TElPKCS7Message;
  Res : integer;
begin
  Msg := TElPKCS7Message.Create;
  Result := false;
  try
    Res := Msg.LoadFromBuffer( Timestamp, Size );
    if (Res = 0) and (Msg.ContentType = ctTimestampedData)
      and (Msg.TimestampedData.DataSource.Size = 0)
    then
    begin
      Result := true;
      DataURI := {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}StringOfBytes {$endif}(Msg.TimestampedData.DataURI);
      FileName := Utf8ToStr(Msg.TimestampedData.FileName);
    end;
  finally
    FreeAndNil(Msg);
  end;
end;

class function TElMessageTimestampVerifier.IsTimestampDetached(Timestamp : TElStream; var DataURI : TSBString; var FileName : TSBString; Count : Int64  =  0) : boolean;
var
  Msg : TElPKCS7Message;
  Res : integer;
begin
  Msg := TElPKCS7Message.Create;
  Result := false;
  try
    Res := Msg.LoadFromStream(Timestamp, Count);
    if (Res = 0) and (Msg.ContentType = ctTimestampedData)
      and (Msg.TimestampedData.DataSource.Size = 0)
    then
    begin
      Result := true;
      DataURI := {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}StringOfBytes {$endif}(Msg.TimestampedData.DataURI);
      FileName := Utf8ToStr(Msg.TimestampedData.FileName);
    end;
  finally
    FreeAndNil(Msg);
  end;
end;

function TElMessageTimestampVerifier.ParseMessageImprint(const Imprint : ByteArray; var HashAlgOID, Hash : ByteArray) : boolean;
var
  Tag, Seq : TElASN1ConstrainedTag;
  AlgID, AlgParams : ByteArray;
  R : integer;
begin
  Result := false;
  Tag := TElASN1ConstrainedTag.CreateInstance();
  try
    if Tag.LoadFromBuffer( @Imprint[0], Length(Imprint) ) then
    begin
      if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      begin
        Seq := TElASN1ConstrainedTag(Tag.GetField(0));
        if (Seq.Count = 2) and (Seq.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) and
          (Seq.GetField(1).CheckType(SB_ASN1_OCTETSTRING, false)) then
        begin
          R := ProcessAlgorithmIdentifier(Seq.GetField(0), AlgID, AlgParams);
          if R = 0 then
          begin
            HashAlgOID := AlgID;
            Hash := TElASN1SimpleTag(Seq.GetField(1)).Content;
            Result := true;
          end;
        end
      end
    end
  finally
    FreeAndNil(Tag);
  end;
end;

function TElMessageTimestampVerifier.InternalVerify(InStream, DataStream, OutStream : TElStream; InCount, DataCount : Int64): integer;
var
  Msg : TElPKCS7Message;
  i, Res, Read : integer;
  Offset : Int64;
  TSPInfo : TElClientTSPInfo;
  HashFunc : TElHashFunction;
  Buf, Hash, HashAlg, MsgHash : ByteArray;
  //Tag : TElASN1ConstrainedTag;
begin
  CheckLicenseKey();


  Msg := TElPKCS7Message.Create;
  try
    Result := Msg.LoadFromStream(InStream, InCount);

    if Result = 0 then
    begin
      if Msg.ContentType <> ctTimestampedData then
      begin
        Result := SB_MESSAGE_ERROR_NO_TIMESTAMPED_DATA;
        Exit;
      end;

      if Msg.TimestampedData.TimestampCount = 0 then
      begin
        Result := SB_MESSAGE_ERROR_BAD_TIMESTAMP;
        Exit;
      end;

      FDataURI := {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}StringOfBytes {$endif}(Msg.TimestampedData.DataURI);
      FFileName := Utf8ToStr(Msg.TimestampedData.FileName);
      FMediaType := {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}StringOfBytes {$endif}(Msg.TimestampedData.MediaType);

      { loading and parsing timestamps }

      for i := 0 to Msg.TimestampedData.TimestampCount - 1 do
      begin
        TSPInfo := TElClientTSPInfo.Create;
        Res := TSPInfo.ParseCMS((Msg.TimestampedData.Timestamps[i].EncodedTimestamp));
        if Res = 0 then
          FTimestamps.Add(TSPInfo)
        else
        begin
          FreeAndNil(TSPInfo);
          Result := SB_MESSAGE_ERROR_BAD_TIMESTAMP;
          Exit;
        end;
      end;

      { checking message imprint }

      for i := TimestampCount - 1 downto 1 do
      begin
        if not ParseMessageImprint(Timestamps[i].MessageImprint, HashAlg, MsgHash) then
        begin
          Result := SB_MESSAGE_ERROR_BAD_TIMESTAMP;
          Exit;
        end;

        try
          HashFunc := TElHashFunction.Create(HashAlg, TElCPParameters(nil), FCryptoProviderManager, nil);
        except
          on E : EElHashFunctionUnsupportedError do
            begin
              Result := SB_MESSAGE_ERROR_UNSUPPORTED_DIGEST_ALGORITHM;
              Exit;
            end;
        end;

        try
          Buf := Msg.TimestampedData.Timestamps[i - 1].EncodedValue;
          HashFunc.Update( @Buf[0] , Length(Buf));
          Hash := HashFunc.Finish;
        finally
          FreeAndNil(HashFunc);
        end;

        if not CompareContent(Hash, MsgHash) then
        begin
          Result := SB_MESSAGE_ERROR_BAD_TIMESTAMP;
          Exit;
        end;
      end;

      { checking first timestamp }

      if not ParseMessageImprint(Timestamps[0].MessageImprint, HashAlg, MsgHash) then
      begin
        Result := SB_MESSAGE_ERROR_BAD_TIMESTAMP;
        Exit;
      end;

      try
        HashFunc := TElHashFunction.Create(HashAlg, TElCPParameters(nil), FCryptoProviderManager, nil);
      except
        on E : EElHashFunctionUnsupportedError do
        begin
          Result := SB_MESSAGE_ERROR_UNSUPPORTED_DIGEST_ALGORITHM;
          Exit;
        end;
      end;

      try
        if Msg.TimestampedData.MetaDataAvailable and Msg.TimestampedData.HashProtected then
        begin
          Buf := Msg.TimestampedData.WriteMetadata;
          HashFunc.Update( @Buf[0] , Length(Buf));
        end;

        if Msg.TimestampedData.DataSource.Size > 0 then
        begin
          Offset := 0;
          SetLength(Buf, 32768);

          while Offset < Msg.TimestampedData.DataSource.Size do
          begin
            Read := Msg.TimestampedData.DataSource.Read( @Buf[0] , Length(Buf), Offset);
            if Read > 0 then
            begin
              HashFunc.Update( @Buf[0] , Read);
              Inc(Offset, Read);

              if not DoProgress(Msg.TimestampedData.DataSource.Size, Offset) then
                RaiseCancelledByUserError;
            end;
          end;
        end
        else if Assigned(DataStream) then
        begin
          Offset := 0;
          if DataCount = 0 then
            DataCount := DataStream. Size  - DataStream.Position;
          SetLength(Buf, 32768);

          while Offset < DataCount do
          begin
            Read := DataStream.Read( Buf[0] , Length(Buf));
            if Read > 0 then
            begin
              HashFunc.Update( @Buf[0] , Read);
              Inc(Offset, Read);

              if not DoProgress(Msg.TimestampedData.DataSource.Size, Offset) then
                RaiseCancelledByUserError;
            end;
          end;
        end;

        Hash := HashFunc.Finish;
      finally
        FreeAndNil(HashFunc);
      end;

      if not CompareContent(Hash, MsgHash) then
      begin
        Result := SB_MESSAGE_ERROR_BAD_TIMESTAMP;
        Exit;
      end;

      { saving timestamped data to output }
      if (Msg.TimestampedData.DataSource.Size > 0) and Assigned(OutStream) then
      begin
        Offset := 0;
        SetLength(Buf, 32768);
        while Offset < Msg.TimestampedData.DataSource.Size do
        begin
          Read := Msg.TimestampedData.DataSource.Read( @Buf[0] , Length(Buf), Offset);
          if Read > 0 then
          begin
            OutStream.Write( Buf[0] , Read);
            Inc(Offset, Read);
          end;
        end;
      end;

      Result := 0;
    end
    else
      Result := SB_MESSAGE_ERROR_INVALID_FORMAT;
  finally
    FreeAndNil(Msg);
  end;
end;


function TElMessageTimestampVerifier.Verify(InStream, OutStream : TElStream;
 InCount : Int64  =  0): integer;
begin
  Result := InternalVerify(InStream, nil, OutStream, InCount, 0);
end;

function TElMessageTimestampVerifier.VerifyDetached(InStream, DataStream : TElStream;
  InCount : Int64  =  0;
  DataCount : Int64  =  0): integer;
begin
  Result := InternalVerify(InStream, DataStream, nil, InCount, DataCount);
end;

end.



