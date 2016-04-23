(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBPKCS7;

interface

uses
  SBASN1Tree,
  SBTypes,
  SBUtils,
  SBConstants,
  SBRDN,
  SBPKCS7Utils,
  Classes,
  {$ifdef SB_UNICODE_VCL}
  SBStringList,
   {$endif}
  SBStreams,
  SBAlgorithmIdentifier,
  SBCRL,
  SBCRLStorage,
  {$ifndef SB_NO_OCSP}
  SBOCSPCommon,
  SBOCSPClient,
  SBOCSPStorage,
   {$endif} 
  SBCustomCertStorage;


type
  TSBPKCS7ContentType =  
   (ctData, ctSignedData, ctEnvelopedData, ctSignedAndEnvelopedData,
    ctDigestedData, ctEncryptedData, ctAuthenticatedData, ctCompressedData, ctTimestampedData, ctUnknown);

  {.$hints off}

  TElPKCS7Recipient = class
   private 
    FVersion : integer;
    FIssuer : TElPKCS7Issuer;
    FKeyEncryptionAlgorithm : ByteArray;
    FKeyEncryptionAlgorithmParams : ByteArray;
    FKeyEncryptionAlgorithmIdentifier : TElAlgorithmIdentifier;
    FEncryptedKey : ByteArray;
    procedure SetKeyEncryptionAlgorithm(const V : ByteArray);
    procedure SetKeyEncryptionAlgorithmParams(const V : ByteArray);
    procedure SetEncryptedKey(const V : ByteArray);
  public
    constructor Create;
     destructor  Destroy; override;
    property Version : integer read FVersion write FVersion;
    property Issuer : TElPKCS7Issuer read FIssuer;
    property KeyEncryptionAlgorithm : ByteArray read FKeyEncryptionAlgorithm
      write SetKeyEncryptionAlgorithm;
    property KeyEncryptionAlgorithmParams : ByteArray read
      FKeyEncryptionAlgorithmParams write SetKeyEncryptionAlgorithmParams;
    property KeyEncryptionAlgorithmIdentifier : TElAlgorithmIdentifier read FKeyEncryptionAlgorithmIdentifier write FKeyEncryptionAlgorithmIdentifier;
    property EncryptedKey : ByteArray read FEncryptedKey write SetEncryptedKey;
  end;

  TElPKCS7ContentPart = class
  private
    FStream : TElStream;
    FOffset : integer;
    FSize : integer;
    FContent : ByteArray;
    function GetSize : integer;
  public
     destructor  Destroy; override;
    function Read(Buffer: pointer; Size: integer; StartOffset : integer = 0): integer;
    property Size : integer read GetSize;
  end;
  
  TElPKCS7EncryptedContent = class
   private 
    FContentType : ByteArray;
    FContentEncryptionAlgorithm : ByteArray;
    FContentEncryptionAlgorithmParams : ByteArray;
    FUseImplicitContentEncoding : boolean;
    //FEncryptedContent : ByteArray;
    FEncryptedContentParts : TElList;
    // left for compatibility
    // the proper method
    function AddContentPart(DataSource : TElASN1DataSource): integer;  overload; 
    function AddContentPart(const Value : ByteArray): integer;  overload; 
    procedure ClearContentParts;
    function GetEncryptedContentPartCount : integer;
    function GetEncryptedContent : ByteArray;
    procedure SetEncryptedContent(const Value: ByteArray);
    function GetDataSource : TElASN1DataSource;
    procedure SetContentType(const V : ByteArray);
    procedure SetContentEncryptionAlgorithm(const V : ByteArray);
    procedure SetContentEncryptionAlgorithmParams(const V : ByteArray);

    function GetEncryptedContentPart(Index: integer): TElASN1DataSource;
  public
    constructor Create;
     destructor  Destroy; override;
    property ContentType : ByteArray read FContentType write SetContentType;
    property ContentEncryptionAlgorithm : ByteArray read FContentEncryptionAlgorithm
      write SetContentEncryptionAlgorithm;
    property ContentEncryptionAlgorithmParams : ByteArray read
      FContentEncryptionAlgorithmParams write SetContentEncryptionAlgorithmParams;
    property EncryptedContent : ByteArray read GetEncryptedContent write SetEncryptedContent;
    property EncryptedContentParts[Index: integer] : TElASN1DataSource read GetEncryptedContentPart;
    property EncryptedContentPartCount : integer read GetEncryptedContentPartCount;
    property DataSource : TElASN1DataSource read GetDataSource;
    property UseImplicitContentEncoding : boolean read FUseImplicitContentEncoding
      write FUseImplicitContentEncoding;
  end;

  TElPKCS7Message = class;

  TElPKCS7EnvelopedData = class
   private 
    FVersion : integer;
    FRecipientList : TElList;
    FEncryptedContent : TElPKCS7EncryptedContent;
    FContentEncryptionAlgorithm : integer;
    FCMSFormat : boolean;
    FOriginatorCertificates : TElMemoryCertStorage;
    FOriginatorCRLs : TElMemoryCRLStorage;
    FUnprotectedAttributes : TElPKCS7Attributes;
    FOwner : TElPKCS7Message;
    function GetRecipientCount : integer;
    procedure Clear;
    function GetRecipient(Index : integer) : TElPKCS7Recipient;
  public
    constructor Create;  
     destructor  Destroy; override;
    function AddRecipient : integer;
    function RemoveRecipient(Index : integer) : boolean;
    function SaveToBuffer(Buffer: pointer; var Size: integer): boolean;
    property Version : integer read FVersion write FVersion;
    property Recipients[Index : integer] : TElPKCS7Recipient read GetRecipient;
    property RecipientCount : integer read GetRecipientCount;
    property EncryptedContent : TElPKCS7EncryptedContent read FEncryptedContent
      write FEncryptedContent;
    property ContentEncryptionAlgorithm : integer read FContentEncryptionAlgorithm
      write FContentEncryptionAlgorithm;
    property CMSFormat : boolean read FCMSFormat write FCMSFormat;
    property OriginatorCertificates : TElMemoryCertStorage read FOriginatorCertificates;
    property OriginatorCRLs : TElMemoryCRLStorage read FOriginatorCRLs;
    property UnprotectedAttributes: TElPKCS7Attributes read FUnprotectedAttributes;
  end;

  TElPKCS7CompressedData = class
   private 
    FVersion : integer;
    FContentType : ByteArray;
    FCompressedContentParts : TElList;
    FOwner : TElPKCS7Message;
    FFragmentSize : integer;
    function AddContentPart(DataSource : TElASN1DataSource): integer;  overload; 
    function AddContentPart(const Value : ByteArray): integer;  overload; 
    //function AddContentPart: integer; {$ifndef SB_NET}overload;{$endif}
    procedure ClearContentParts;
    function GetCompressedContentPartCount : integer;
    function GetCompressedContent : ByteArray;
    procedure SetCompressedContent(const Value: ByteArray);
    function GetDataSource : TElASN1DataSource;
    procedure SetContentType(const V : ByteArray);
    function GetCompressedContentPart(Index: integer): TElASN1DataSource;
  public
    constructor Create;
     destructor  Destroy; override;
    function SaveToBuffer(Buffer: pointer; var Size: integer): boolean;
    property Version : integer read FVersion write FVersion;
    property ContentType : ByteArray read FContentType write SetContentType;
    property CompressedContent : ByteArray read GetCompressedContent write SetCompressedContent;
    property CompressedContentParts[Index: integer] : TElASN1DataSource read GetCompressedContentPart;
    property CompressedContentPartCount : integer read GetCompressedContentPartCount;
    property FragmentSize : integer read FFragmentSize write FFragmentSize;
    property DataSource : TElASN1DataSource read GetDataSource;
  end;

  TElPKCS7Signer = class
   private 
    FVersion : integer;
    FIssuer : TElPKCS7Issuer;
    FDigestAlgorithm : ByteArray;
    FDigestAlgorithmParams : ByteArray;
    FAuthenticatedAttributes : TElPKCS7Attributes;
    FUnauthenticatedAttributes : TElPKCS7Attributes;
    FDigestEncryptionAlgorithm : ByteArray;
    FDigestEncryptionAlgorithmParams : ByteArray;
    FEncryptedDigest : ByteArray;
    FAuthenticatedAttributesPlain : ByteArray;
    FContent: ByteArray;
    FEncodedValue : ByteArray;
    FArchivalEncodedValue : ByteArray;
    FWriteNullInDigestEncryptionAlgID : boolean;
  protected
    function GetAuthenticatedAttributesPlain : ByteArray;
    procedure SetDigestAlgorithm(const V : ByteArray);
    procedure SetDigestAlgorithmParams(const V : ByteArray);
    procedure SetDigestEncryptionAlgorithm(const V : ByteArray);
    procedure SetDigestEncryptionAlgorithmParams(const V : ByteArray);
    procedure SetEncryptedDigest(const V : ByteArray);
  public
    constructor Create;
     destructor  Destroy; override;
    procedure RecalculateAuthenticatedAttributes;  overload; 
    procedure RecalculateAuthenticatedAttributes(Reorder: boolean);  overload; 
    procedure Recalculate;
    procedure Assign(Source : TElPKCS7Signer);
    
    property Version : integer read FVersion write FVersion;
    property Issuer : TElPKCS7Issuer read FIssuer;
    property DigestAlgorithm : ByteArray read FDigestAlgorithm write SetDigestAlgorithm;
    property DigestAlgorithmParams : ByteArray read FDigestAlgorithmParams
      write SetDigestAlgorithmParams;
    property DigestEncryptionAlgorithm : ByteArray read FDigestEncryptionAlgorithm
      write SetDigestEncryptionAlgorithm;
    property DigestEncryptionAlgorithmParams : ByteArray read
      FDigestEncryptionAlgorithmParams write SetDigestEncryptionAlgorithmParams;
    property AuthenticatedAttributes : TElPKCS7Attributes
      read FAuthenticatedAttributes;
    property UnauthenticatedAttributes : TElPKCS7Attributes
      read FUnauthenticatedAttributes;
    property EncryptedDigest : ByteArray read FEncryptedDigest write SetEncryptedDigest;
    property AuthenticatedAttributesPlain : ByteArray read GetAuthenticatedAttributesPlain;
    property Content: ByteArray read FContent;
    property EncodedValue : ByteArray read FEncodedValue;
    property ArchivalEncodedValue : ByteArray read FArchivalEncodedValue;
  end;

  TElPKCS7SignedData = class
   private 
    FVersion : integer;
    FSignerList : TElList;
    FCertStorage : TElMemoryCertStorage;
    FCRLStorage : TElMemoryCRLStorage;
    {$ifndef SB_NO_OCSP}
    FOCSPStorage : TElOCSPResponseStorage;
     {$endif}
    FOwner : TElPKCS7Message;
    FEncodedCertificates : ByteArray;
    FEncodedCRLs : ByteArray;
    FEnvelopedContentPrefix : ByteArray;
    FEnvelopedContentPostfix : ByteArray;
    FContentType : ByteArray;
    FContentParts : TElList;
    FCurrContentSerializationStream : TElMemoryStream;
    FCurrContentSerializationStartOffset : Int64;
    FCurrContentSerializationEndOffset : Int64;
    FIsMultipart : boolean;
    FRawMultipartContent : ByteArray;
    FPreserveCachedContent : boolean;
    FPreserveCachedElements : boolean;
    function AddContentPart(DataSource : TElASN1DataSource): integer;  overload; 
    function AddContentPart(const Data : ByteArray): integer;  overload; 
    function AddContentPart(Buffer: pointer; Size: integer): integer; overload;
    function GetSignerCount : integer;
    function GetContentPartCount : integer;
    function GetContent : ByteArray;
    procedure SetContent(const Value: ByteArray);
    function GetDataSource : TElASN1DataSource;
    procedure SetContentType(const V : ByteArray);
    procedure SerializeCertsAndCRLs;
    procedure SerializeEnvelopedContent;
    procedure HandleContentTagContentWriteBegin(Sender: TObject);
    procedure HandleContentTagContentWriteEnd(Sender: TObject);
    function GetSigner(Index : integer) : TElPKCS7Signer;
    function GetContentPart(Index: integer): TElASN1DataSource;
  public
    constructor Create;
     destructor  Destroy; override;
    function AddContentPart : integer;  overload; 
    procedure ClearContentParts;
    function AddSigner : integer;
    function RemoveSigner(Index : integer) : boolean;
    function SaveToBuffer(Buffer: pointer; var Size: integer): boolean;
    procedure SaveToStream(Stream: TStream);
    procedure PreSerialize(SerializeContent, SerializeCertsAndCrls : boolean);
    property Version : integer read FVersion write FVersion;
    property Signers[Index : integer] : TElPKCS7Signer read GetSigner;
    property ContentParts[Index: integer] : TElASN1DataSource read GetContentPart;
    property SignerCount : integer read GetSignerCount;
    property Certificates : TElMemoryCertStorage read FCertStorage;
    property CRLs : TElMemoryCRLStorage read FCRLStorage;
    {$ifndef SB_NO_OCSP}
    property OCSPs : TElOCSPResponseStorage read FOCSPStorage;
     {$endif}
    property Content : ByteArray read GetContent write SetContent;
    property ContentType : ByteArray read FContentType write SetContentType;
    property ContentPartCount : integer read GetContentPartCount;
    property DataSource : TElASN1DataSource read GetDataSource;
    property EncodedCertificates : ByteArray read FEncodedCertificates;
    property EncodedCRLs : ByteArray read FEncodedCRLs;
    property EnvelopedContentPrefix : ByteArray read FEnvelopedContentPrefix;
    property EnvelopedContentPostfix : ByteArray read FEnvelopedContentPostfix;
    property IsMultipart : boolean read FIsMultipart;
    property RawMultipartContent : ByteArray read FRawMultipartContent;
    property PreserveCachedContent : boolean read FPreserveCachedContent write FPreserveCachedContent;
    property PreserveCachedElements : boolean read FPreserveCachedElements write FPreserveCachedElements;
  end;

  TElPKCS7DigestedData = class
   private 
    FVersion : integer;

    FDigestAlgorithm : ByteArray;
    FDigestAlgorithmParams : ByteArray;
    FContent : ByteArray;
    FDigest : ByteArray;
    procedure SetDigestAlgorithm(const V : ByteArray);
    procedure SetDigestAlgorithmParams(const V : ByteArray);
    procedure SetContent(const V : ByteArray);
    procedure SetDigest(const V : ByteArray);
  public
     destructor  Destroy; override;
    property DigestAlgorithm : ByteArray read FDigestAlgorithm write SetDigestAlgorithm;
    property DigestAlgorithmParams : ByteArray read FDigestAlgorithmParams
      write SetDigestAlgorithmParams;
    property Content : ByteArray read FContent write SetContent;
    property Digest : ByteArray read FDigest write SetDigest;

    property Version : integer read FVersion write FVersion;
  end;

  TElPKCS7EncryptedData = class
   private 
    FVersion : integer;
    FEncryptedContent : TElPKCS7EncryptedContent;
    FOwner : TElPKCS7Message;
  public
    constructor Create;
     destructor  Destroy; override;
    function SaveToBuffer(Buffer: pointer; var Size: integer): boolean;
    property Version : integer read FVersion write FVersion;
    property EncryptedContent : TElPKCS7EncryptedContent read FEncryptedContent;
  end;

  TElPKCS7SignedAndEnvelopedData = class
   private 
    FVersion : integer;
    FRecipientList : TElList;
    FSignerList : TElList;
    FEncryptedContent : TElPKCS7EncryptedContent;
    FCertStorage : TElMemoryCertStorage;
  public
    constructor Create;
     destructor  Destroy; override;

    function GetRecipient(Index : integer) : TElPKCS7Recipient;
    function GetRecipientCount : integer;
    function GetSigner(Index : integer) : TElPKCS7Signer;
    function GetSignerCount : integer;

    function AddRecipient : integer;
    function AddSigner : integer;
    function RemoveRecipient(Index : integer) : boolean;
    function RemoveSigner(Index : integer) : boolean;
    property Version : integer read FVersion write FVersion;
    property Recipients[Index : integer] : TElPKCS7Recipient read GetRecipient;
    property Signers[Index : integer] : TElPKCS7Signer read GetSigner;
    property RecipientCount : integer read GetRecipientCount;
    property EncryptedContent : TElPKCS7EncryptedContent read FEncryptedContent;
    property Certificates : TElMemoryCertStorage read FCertStorage;
    property SignerCount : integer read GetSignerCount;
  end;

  TElPKCS7AuthenticatedData = class
   private 
    FVersion : integer;
    FOriginatorCerts : TElCustomCertStorage;
    FMacAlgorithm : ByteArray;
    FMacAlgorithmParams : ByteArray;
    FDigestAlgorithm : ByteArray;
    FDigestAlgorithmParams : ByteArray;
    FContentType : ByteArray;
    FContentParts : TElList;
    FAuthenticatedAttributes : TElPKCS7Attributes;
    FUnauthenticatedAttributes : TElPKCS7Attributes;
    FMac : ByteArray;
    FRecipientList : TElList;
    FAuthenticatedAttributesPlain : ByteArray;
    procedure SetMacAlgorithm(const V : ByteArray);
    procedure SetMacAlgorithmParams(const V : ByteArray);
    procedure SetDigestAlgorithm(const V : ByteArray);
    procedure SetDigestAlgorithmParams(const V : ByteArray);
    procedure SetContentType(const V : ByteArray);
    procedure SetMac(const V : ByteArray);
    function GetRecipientCount: integer;
    function GetAuthenticatedAttributesPlain: ByteArray;
    function AddContentPart(DataSource : TElASN1DataSource): integer;  overload; 
    function AddContentPart(const Value : ByteArray): integer;  overload; 
    function AddContentPart(Buffer: pointer; Size: integer): integer; overload;
    procedure ClearContentParts;
    function GetContentPartCount : integer;
    function GetContent : ByteArray;
    procedure SetContent(const Value: ByteArray);
    function GetDataSource : TElASN1DataSource;

    function GetRecipient(Index: integer) : TElPKCS7Recipient;
    function GetContentPart(Index: integer): TElASN1DataSource;
  public
    constructor Create;
     destructor  Destroy; override;

    function AddRecipient : integer;
    function RemoveRecipient(Index : integer) : boolean;
    procedure RecalculateAuthenticatedAttributes;
    property Version: integer read FVersion write FVersion;
    property OriginatorCerts : TElCustomCertStorage read FOriginatorCerts;
    property Recipients[Index: integer] : TElPKCS7Recipient read GetRecipient;
    property ContentParts[Index: integer] : TElASN1DataSource read GetContentPart;
    property RecipientCount: integer read GetRecipientCount;
    property MacAlgorithm: ByteArray read FMacAlgorithm write SetMacAlgorithm;
    property DigestAlgorithm: ByteArray read FDigestAlgorithm write SetDigestAlgorithm;
    property ContentType : ByteArray read FContentType write SetContentType;
    property Content : ByteArray read GetContent write SetContent;
    property AuthenticatedAttributes : TElPKCS7Attributes read FAuthenticatedAttributes;
    property UnauthenticatedAttributes : TElPKCS7Attributes read FUnauthenticatedAttributes;
    property Mac : ByteArray read FMac write SetMac;
    property AuthenticatedAttributesPlain: ByteArray read GetAuthenticatedAttributesPlain;
    property ContentPartCount : integer read GetContentPartCount;
    property DataSource : TElASN1DataSource read GetDataSource;
  end;

  { actually entities for classes below are described in RFC 5544, but names begin with PKCS7 for compatibility }
  TElPKCS7TimestampAndCRL = class
    FEncodedTimestamp : ByteArray;
    FEncodedCRL : ByteArray;
    FEncodedValue : ByteArray;
    procedure SetEncodedTimestamp(const V : ByteArray);
    procedure SetEncodedCRL(const V : ByteArray);
    procedure SetEncodedValue(const V : ByteArray);
  public
    constructor Create;
     destructor  Destroy; override;

    property EncodedTimestamp : ByteArray read FEncodedTimestamp write SetEncodedTimestamp;
    property EncodedCRL : ByteArray read FEncodedCRL write SetEncodedCRL;
    property EncodedValue : ByteArray read FEncodedValue write SetEncodedValue;
  end;

  TElPKCS7TimestampedData = class
   private 
    FContentType : ByteArray;
    FDataURI : ByteArray;
    FHashProtected : boolean;
    FFileName : ByteArray;
    FMediaType : ByteArray;
    FMetaDataAvailable : boolean;
    FTimestamps : TElList;
    FContentParts : TElList;

    procedure SetDataURI(const V : ByteArray);
    procedure SetFileName(const V : ByteArray);
    procedure SetMediaType(const V : ByteArray);
    function GetTimestampCount : integer;
    function AddContentPart(DataSource : TElASN1DataSource): integer;  overload; 
    function AddContentPart(const Value : ByteArray): integer;  overload; 
    function AddContentPart(Buffer: pointer; Size: integer): integer; overload;
    procedure ClearContentParts;
    function GetContentPartCount : integer;
    function GetContent : ByteArray;
    procedure SetContent(const Value: ByteArray);
    function GetDataSource : TElASN1DataSource;
    
    function  GetTimestamps (Index : integer) : TElPKCS7TimestampAndCRL;

    function GetContentPart(Index: integer): TElASN1DataSource;
  public
    constructor Create;
     destructor  Destroy; override;

    function AddTimestamp : integer;
    function RemoveTimestamp(Index : integer) : boolean;
    procedure ClearTimestamps;
    function WriteMetadata : ByteArray;
    function WriteTimestampAndCRL(Ts : TElPKCS7TimestampAndCRL) : ByteArray;

    property DataURI : ByteArray read FDataURI write SetDataURI;
    property HashProtected : boolean read FHashProtected write FHashProtected;
    property FileName : ByteArray read FFileName write SetFileName;
    property MediaType : ByteArray read FMediaType write SetMediaType;
    property MetaDataAvailable : boolean read FMetaDataAvailable write FMetaDataAvailable;

    property Timestamps[Index : integer] : TElPKCS7TimestampAndCRL read  GetTimestamps ;
    property TimestampCount : integer read GetTimestampCount;

    property Content : ByteArray read GetContent write SetContent;
    property ContentParts[Index: integer] : TElASN1DataSource read GetContentPart;
    property ContentPartCount : integer read GetContentPartCount;
    property DataSource : TElASN1DataSource read GetDataSource;
  end;

  TElPKCS7Message = class
  private
    FMessage : TElASN1ConstrainedTag;
    FContentType : TSBPKCS7ContentType;
    FData : ByteArray;
    FUseImplicitContent: Boolean;
    FUseUndefSize: Boolean;
    FEnvelopedData : TElPKCS7EnvelopedData;
    FCompressedData : TElPKCS7CompressedData;
    FSignedData : TElPKCS7SignedData;
    FDigestedData : TElPKCS7DigestedData;
    FEncryptedData : TElPKCS7EncryptedData;
    FSignedAndEnvelopedData : TElPKCS7SignedAndEnvelopedData;
    FAuthenticatedData : TElPKCS7AuthenticatedData;
    FTimestampedData : TElPKCS7TimestampedData;
    FNoOuterContentInfo : boolean;
    FAllowUnknownContentTypes: boolean;
    FCustomContentType : ByteArray;
  protected
    { Common PKCS7 routines }
    function ProcessMessage : integer;
    function ProcessData(Tag : TElASN1CustomTag) : integer; virtual;
    function ProcessUnknownData(Tag : TElASN1CustomTag) : integer; virtual;
    function ProcessSignedData(Tag : TElASN1CustomTag) : integer; virtual;
    function ProcessEnvelopedData(Tag : TElASN1CustomTag) : integer; virtual;
    function ProcessCompressedData(Tag : TElASN1CustomTag) : integer; virtual;
    function ProcessSignedEnvelopedData(Tag : TElASN1CustomTag) : integer; virtual;
    function ProcessDigestData(Tag : TElASN1CustomTag) : integer; virtual;
    function ProcessEncryptedData(Tag : TElASN1CustomTag) : integer; virtual;
    function ProcessAuthenticatedData(Tag : TElASN1CustomTag) : integer; virtual;
    function ProcessTimestampedData(Tag : TElASN1CustomTag) : integer; virtual;
    { Auxiliary PKCS7 routines }
    function ProcessRecipientInfos(Tag : TElASN1CustomTag; RecipientList : TElList) : integer;
    function ProcessRecipientInfo(Tag : TElASN1CustomTag; Recipient :
      TElPKCS7Recipient) : integer; virtual;
    function ProcessEncryptedContentInfo(Tag : TElASN1ConstrainedTag;
      EncryptedContent : TElPKCS7EncryptedContent) : integer;
    procedure ProcessCertificates(Tag : TElASN1ConstrainedTag; Storage :
      TElCustomCertStorage);
    
    procedure ProcessCRLs(Tag : TElASN1ConstrainedTag; Storage :
      TElMemoryCRLStorage{$ifndef SB_NO_OCSP}; OcspStorage : TElOCSPResponseStorage {$endif});

    function ProcessSignerInfos(Tag : TElASN1CustomTag; SignerList : TElList) : integer;
    procedure Clear;
    procedure SaveEnvelopedData(Tag : TElASN1ConstrainedTag);
    procedure SaveCompressedData(Tag : TElASN1ConstrainedTag);
    procedure SaveTimestampedData(Tag : TElASN1ConstrainedTag);    
    procedure SaveRecipientInfos(Tag : TElASN1ConstrainedTag; RecipientList : TElList);
    procedure SaveRecipientInfo(Tag : TElASN1ConstrainedTag; Recipient :
      TElPKCS7Recipient);
    procedure SaveEncryptedContentInfo(Tag : TElASN1ConstrainedTag; EncryptedContent :
      TElPKCS7EncryptedContent);
    procedure SaveSignedData(Tag : TElASN1ConstrainedTag);
    procedure SaveCertificates(Storage : TElCustomCertStorage; Tag : TElASN1ConstrainedTag);
    
    procedure SaveCRLs(Storage : TElCustomCRLStorage; {$ifndef SB_NO_OCSP}OcspStorage : TElOCSPResponseStorage; {$endif}
      Tag : TElASN1ConstrainedTag);

    procedure SaveSignerInfos(Tag : TElASN1ConstrainedTag; SignerList : TElList);
    procedure SaveDigestedData(Tag : TElASN1ConstrainedTag);
    procedure SaveEncryptedData(Tag : TElASN1ConstrainedTag);
    procedure SaveSignedAndEnvelopedData(Tag : TElASN1ConstrainedTag);
    procedure SaveAuthenticatedData(Tag : TElASN1ConstrainedTag);
    procedure SaveMessage(Tag : TElASN1ConstrainedTag);
    procedure SetData(const V : ByteArray);
    procedure SetCustomContentType(const V : ByteArray);
  public
    constructor Create;
     destructor  Destroy; override;
    procedure Reset;
    function LoadFromBuffer(Buffer : pointer; Size : integer) : integer;
    function SaveToBuffer(Buffer : pointer; var Size : integer) : boolean;
    function LoadFromStream(Stream: TElStream;
      Count: integer  =  0) : integer;
    procedure SaveToStream(Stream : TElStream);
    property ContentType : TSBPKCS7ContentType read FContentType write FContentType;
    property Data : ByteArray read FData write SetData;

    property EnvelopedData : TElPKCS7EnvelopedData read FEnvelopedData;
    property CompressedData : TElPKCS7CompressedData read FCompressedData;
    property SignedData : TElPKCS7SignedData read FSignedData;
    property DigestedData : TElPKCS7DigestedData read FDigestedData;
    property EncryptedData : TElPKCS7EncryptedData read FEncryptedData;
    property SignedAndEnvelopedData : TElPKCS7SignedAndEnvelopedData
      read FSignedAndEnvelopedData;
    property AuthenticatedData : TElPKCS7AuthenticatedData read FAuthenticatedData;
    property TimestampedData : TElPKCS7TimestampedData read FTimestampedData;
    property UseImplicitContent: Boolean read FUseImplicitContent write FUseImplicitContent;
    property UseUndefSize: Boolean read FUseUndefSize write FUseUndefSize;
    property NoOuterContentInfo : boolean read FNoOuterContentInfo
      write FNoOuterContentInfo;
    property AllowUnknownContentTypes : boolean read FAllowUnknownContentTypes
      write FAllowUnknownContentTypes;
    property CustomContentType : ByteArray read FCustomContentType
      write SetCustomContentType;
  end;

  {.$hints on}


//function ProcessAlgorithmIdentifier(Tag : TElASN1CustomTag; var Algorithm :
//  BufferType; var Params : BufferType; ImplicitTagging : boolean = false) : integer;
function ProcessContentInfo(Tag : TElASN1ConstrainedTag; Buffer : pointer;
  var Size : integer; var ContentType : ByteArray) : boolean; overload;
function ProcessContentInfo(Tag : TElASN1ConstrainedTag; PKCS7Data : TObject;
  var ContentType : ByteArray): boolean; overload;
//procedure SaveAlgorithmIdentifier(Tag : TElASN1ConstrainedTag; const Algorithm :
//  BufferType; const Params : BufferType; ImplicitTag : byte = 0;
//  WriteNullIfParamsAreEmpty : boolean = true);
procedure SaveSignerInfo(Tag : TElASN1ConstrainedTag; Signer : TElPKCS7Signer); 
function ProcessSignerInfo(Tag : TElASN1CustomTag; SignerInfo : TElPKCS7Signer) : integer; 
function ProcessAttributes(Tag : TElASN1CustomTag; Attributes : TElPKCS7Attributes) : integer; 

//procedure SaveIssuerAndSerialNumber(Tag : TElASN1ConstrainedTag; Issuer : TElPKCS7Issuer);
//function ProcessIssuerAndSerialNumber(Tag : TElASN1CustomTag; Issuer : TElPKCS7Issuer): integer;

type
  EElPKCS7Error =  class(ESecureBlackboxError);

procedure RaisePKCS7Error(ErrorCode : integer); 


{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
var
 {$else}
const
 {$endif}

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS OFF}
 {$endif}

  SB_OID_PKCS7_DATA                       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$07#$01 {$endif}; 
  SB_OID_PKCS7_SIGNED_DATA                : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$07#$02 {$endif}; 
  SB_OID_PKCS7_ENVELOPED_DATA             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$07#$03 {$endif}; 
  SB_OID_PKCS7_SIGNED_AND_ENVELOPED_DATA  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$07#$04 {$endif}; 
  SB_OID_PKCS7_DIGESTED_DATA              : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$07#$05 {$endif}; 
  SB_OID_PKCS7_ENCRYPTED_DATA             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$86#$f7#$0d#$01#$07#$06 {$endif}; 
  SB_OID_PKCS7_AUTHENTICATED_DATA         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$01#$02 {$endif}; 
  SB_OID_PKCS7_COMPRESSED_DATA            : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$01#$09 {$endif}; 
  SB_OID_PKCS7_TIMESTAMPED_DATA           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$01#$1F {$endif}; 

  SB_OID_PKCS7_COMPRESSION_ZLIB           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$03#$08 {$endif}; 

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS ON}
 {$endif}

{$ifndef SB_FPC_GEN}
implementation

uses
   SysUtils,  SBX509, SBTSPCommon;
 {$endif}

{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
{$ifdef SB_UNICODE_VCL}
  {$WARNINGS OFF}
 {$endif}
const
  SB_OID_PKCS7_DATA_STR                       = #$2a#$86#$48#$86#$f7#$0d#$01#$07#$01;
  SB_OID_PKCS7_SIGNED_DATA_STR                = #$2a#$86#$48#$86#$f7#$0d#$01#$07#$02;
  SB_OID_PKCS7_ENVELOPED_DATA_STR             = #$2a#$86#$48#$86#$f7#$0d#$01#$07#$03;
  SB_OID_PKCS7_SIGNED_AND_ENVELOPED_DATA_STR  = #$2a#$86#$48#$86#$f7#$0d#$01#$07#$04;
  SB_OID_PKCS7_DIGESTED_DATA_STR              = #$2a#$86#$48#$86#$f7#$0d#$01#$07#$05;
  SB_OID_PKCS7_ENCRYPTED_DATA_STR             = #$2a#$86#$48#$86#$f7#$0d#$01#$07#$06;
  SB_OID_PKCS7_AUTHENTICATED_DATA_STR         = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$01#$02;
  SB_OID_PKCS7_COMPRESSED_DATA_STR            = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$01#$09;
  SB_OID_PKCS7_TIMESTAMPED_DATA_STR           = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$01#$1F;

  SB_OID_PKCS7_COMPRESSION_ZLIB_STR           = #$2A#$86#$48#$86#$F7#$0D#$01#$09#$10#$03#$08;
{$ifdef SB_UNICODE_VCL}
  {$WARNINGS ON}
 {$endif}
 {$endif}

{$ifdef SB_FPC_GEN}
implementation

uses
   SysUtils,  SBX509, SBTSPCommon;
 {$endif}

resourcestring

  sPKCS7Error = 'PKCS#7 error';

procedure RaisePKCS7Error(ErrorCode : integer);
begin
  if ErrorCode <> 0 then
    raise EElPKCS7Error.Create(sPKCS7Error + '#' + IntToStr(ErrorCode));
end;

procedure SaveIssuerAndSerialNumber(Tag : TElASN1ConstrainedTag;
  Issuer : TElPKCS7Issuer);
var
  CTag, CInnerTag, CTagSet : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  I : integer;
  PrevGroup : integer;
begin
  Tag.TagId := SB_ASN1_SEQUENCE;
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  CTag.TagId := SB_ASN1_SEQUENCE;
  PrevGroup := -1;
  CTagSet := nil;
  for I := 0 to Issuer.Issuer.Count - 1 do
  begin
    if (Issuer.Issuer.Groups[I] <> PrevGroup) or (CTagSet = nil) then
    begin
      CTagSet := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
      CTagSet.TagId := SB_ASN1_SET;
      PrevGroup := Issuer.Issuer.Groups[I];
    end;
    CInnerTag := TElASN1ConstrainedTag(CTagSet.GetField(CTagSet.AddField(true)));
    CInnerTag.TagId := SB_ASN1_SEQUENCE;
    STag := TElASN1SimpleTag(CInnerTag.GetField(CInnerTag.AddField(false)));
    STag.TagId := SB_ASN1_OBJECT;
    STag.Content := CloneArray(Issuer.Issuer.OIDs[I]);
    STag := TElASN1SimpleTag(CInnerTag.GetField(CInnerTag.AddField(false)));
    STag.TagId := Issuer.Issuer.Tags[I];
    STag.Content := CloneArray(Issuer.Issuer.Values[I]);
  end;
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;
  STag.Content := CloneArray(Issuer.SerialNumber);
end;

function ProcessIssuerAndSerialNumber(Tag : TElASN1CustomTag;
  Issuer : TElPKCS7Issuer): integer;
var
  T, InnerT, SeqT : TElASN1CustomTag;
  I, J, Sz : integer;
  TagID : byte;
  Value : ByteArray;
begin
  if (not Tag.IsConstrained) or (Tag.TagId <> SB_ASN1_SEQUENCE) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ISSUER;
    Exit;
  end;
  if TElASN1ConstrainedTag(Tag).Count < 2 then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ISSUER;
    Exit;
  end;
  { Reading Issuer RDN }
  T := TElASN1ConstrainedTag(Tag).GetField(0);
  if (not T.IsConstrained) or (T.TagId <> SB_ASN1_SEQUENCE) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ISSUER;
    Exit;
  end;
  for I := 0 to TElASN1ConstrainedTag(T).Count - 1 do
  begin
    InnerT := TElASN1ConstrainedTag(T).GetField(I);
    if (not InnerT.IsConstrained) or (InnerT.TagId <> SB_ASN1_SET) then
    begin
      Result := SB_PKCS7_ERROR_INVALID_ISSUER;
      Exit;
    end;
    if TElASN1ConstrainedTag(InnerT).Count < 1 then
    begin
      Result := SB_PKCS7_ERROR_INVALID_ISSUER;
      Exit;
    end;
    for J := 0 to TElASN1ConstrainedTag(InnerT).Count - 1 do
    begin
      SeqT := TElASN1ConstrainedTag(InnerT).GetField(J);
      if (not SeqT.IsConstrained) or (SeqT.TagId <> SB_ASN1_SEQUENCE) then
      begin
        Result := SB_PKCS7_ERROR_INVALID_ISSUER;
        Exit;
      end;
      if TElASN1ConstrainedTag(SeqT).Count <> 2 then
      begin
        Result := SB_PKCS7_ERROR_INVALID_ISSUER;
        Exit;
      end;
      if (TElASN1ConstrainedTag(SeqT).GetField(0).IsConstrained) or
        (TElASN1ConstrainedTag(SeqT).GetField(0).TagId <> SB_ASN1_OBJECT) then
      begin
        Result := SB_PKCS7_ERROR_INVALID_ISSUER;
        Exit;
      end;
      if TElASN1ConstrainedTag(SeqT).GetField(1).IsConstrained then
      begin
        Sz := 0;
        SetLength(Value, Sz);
        TElASN1ConstrainedTag(TElASN1ConstrainedTag(SeqT).GetField(1)).SaveToBuffer( nil , Sz);
        SetLength(Value, Sz);
        TElASN1ConstrainedTag(TElASN1ConstrainedTag(SeqT).GetField(1)).SaveToBuffer( @Value[0] , Sz);
        TagID := SB_ASN1_OCTETSTRING;
      end
      else
      begin
        Value := TElASN1SimpleTag(TElASN1ConstrainedTag(SeqT).GetField(1)).Content;
        TagID := TElASN1ConstrainedTag(SeqT).GetField(1).TagId;
      end;
      Issuer.Issuer.Count := Issuer.Issuer.Count + 1;
      Issuer.Issuer.OIDs[Issuer.Issuer.Count - 1] := TElASN1SimpleTag(TElASN1ConstrainedTag(SeqT).GetField(0)).Content;
      Issuer.Issuer.Values[Issuer.Issuer.Count - 1] := Value;
      Issuer.Issuer.Tags[Issuer.Issuer.Count - 1] := TagID;
      Issuer.Issuer.Groups[Issuer.Issuer.Count - 1] := I;
    end;
  end;
  { Reading SerialNumber }
  T := TElASN1ConstrainedTag(Tag).GetField(1);
  if (T.IsConstrained) or (T.TagId <> SB_ASN1_INTEGER) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ISSUER;
    Exit;
  end;
  Issuer.SerialNumber := TElASN1SimpleTag(T).Content;
  Issuer.IssuerType := itIssuerAndSerialNumber;
  Result := 0;
end;

////////////////////////////////////////////////////////////////////////////////
// TElPKCS7Message

constructor TElPKCS7Message.Create;
begin
  inherited;
  FMessage := TElASN1ConstrainedTag.CreateInstance;
  FEnvelopedData := TElPKCS7EnvelopedData.Create;
  FEnvelopedData.FOwner := Self;
  FCompressedData := TElPKCS7CompressedData.Create;
  FCompressedData.FOwner := Self;
  FSignedData := TElPKCS7SignedData.Create;
  FSignedData.FOwner := Self;
  FDigestedData := TElPKCS7DigestedData.Create;
  FEncryptedData := TElPKCS7EncryptedData.Create;
  FEncryptedData.FOwner := Self;
  FSignedAndEnvelopedData := TElPKCS7SignedAndEnvelopedData.Create;
  FAuthenticatedData := TElPKCS7AuthenticatedData.Create;
  FTimestampedData := TElPKCS7TimestampedData.Create;
  FUseImplicitContent := False;
  FUseUndefSize := True;
  FNoOuterContentInfo := false;
  FAllowUnknownContentTypes := true;
  FCustomContentType := EmptyArray;
end;

 destructor  TElPKCS7Message.Destroy;
begin
  FreeAndNil(FMessage);
  FreeAndNil(FEnvelopedData);
  FreeAndNil(FCompressedData);
  FreeAndNil(FSignedData);
  FreeAndNil(FDigestedData);
  FreeAndNil(FEncryptedData);
  FreeAndNil(FSignedAndEnvelopedData);
  FreeAndNil(FAuthenticatedData);
  FreeAndNil(FTimestampedData);
  ReleaseArrays(FData, FCustomContentType);
  inherited;
end;

function TElPKCS7Message.LoadFromBuffer(Buffer : pointer; Size : integer) : integer;
begin
  CheckLicenseKey();
  FMessage.Clear;
  Clear;
  if FMessage.LoadFromBufferSingle(Buffer , Size ) = -1 then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ASN_DATA;
    FMessage.Clear;
    Exit;
  end;
  Result := ProcessMessage;
end;

function TElPKCS7Message.LoadFromStream(Stream: TElStream;
  Count: integer  =  0) : integer;
begin
  CheckLicenseKey();
  FMessage.Clear;
  Clear;
  FMessage.MaxSimpleTagLength := 8192;

  if not FMessage.LoadFromStreamSingle(Stream, Count) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ASN_DATA;
    FMessage.Clear;
    Exit;
  end;
  Result := ProcessMessage;
end;

procedure TElPKCS7Message.SaveMessage(Tag : TElASN1ConstrainedTag);
var
  STag : TElASN1SimpleTag;
  CTag : TElASN1ConstrainedTag;
begin
  { Writing ContentType }
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_OBJECT;
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  CTag.TagId := SB_ASN1_A0;
  CTag.UndefSize := FUseUndefSize;
  if FContentType =  ctEnvelopedData  then
  begin
    STag.Content := SB_OID_PKCS7_ENVELOPED_DATA;
    SaveEnvelopedData(CTag);
  end
  else
  if FContentType =  ctSignedData  then
  begin
    STag.Content := SB_OID_PKCS7_SIGNED_DATA;
    SaveSignedData(CTag);
  end
  else if FContentType =  ctDigestedData  then
  begin
    STag.Content := SB_OID_PKCS7_DIGESTED_DATA;
    SaveDigestedData(CTag);
  end
  else if FContentType =  ctEncryptedData  then
  begin
    STag.Content := SB_OID_PKCS7_ENCRYPTED_DATA;
    SaveEncryptedData(CTag);
  end
  else if FContentType =  ctData  then
  begin
    STag.Content := SB_OID_PKCS7_DATA;
    STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
    STag.TagId := SB_ASN1_OCTETSTRING;
    STag.Content := CloneArray(FData);
  end
  else if FContentType =  ctSignedAndEnvelopedData  then
  begin
    STag.Content := SB_OID_PKCS7_SIGNED_AND_ENVELOPED_DATA;
    SaveSignedAndEnvelopedData(CTag);
  end
  else if FContentType =  ctAuthenticatedData  then
  begin
    STag.Content := SB_OID_PKCS7_AUTHENTICATED_DATA;
    SaveAuthenticatedData(CTag);
  end
  else if FContentType =  ctCompressedData  then
  begin
    STag.Content := SB_OID_PKCS7_COMPRESSED_DATA;
    SaveCompressedData(CTag);
  end
  else if FContentType =  ctTimestampedData  then
  begin
    STag.Content := SB_OID_PKCS7_TIMESTAMPED_DATA;
    SaveTimestampedData(CTag);
  end
  else if (FContentType =  ctUnknown ) and (Length(FCustomContentType) > 0) then
  begin
    STag.Content := FCustomContentType;
    STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
    STag.TagId := SB_ASN1_OCTETSTRING; // does not matter
    STag.WriteHeader := false;
    STag.Content := CloneArray(FData);
  end;
end;

procedure TElPKCS7Message.SaveToStream(Stream : TElStream);
begin
  FMessage.Clear;
  FMessage.TagId := SB_ASN1_SEQUENCE;
  FMessage.UndefSize := FUseUndefSize;
  SaveMessage(FMessage);
  FMessage.SaveToStream(Stream);
end;

function TElPKCS7Message.SaveToBuffer(Buffer : pointer; var Size : integer) : boolean;
begin
  FMessage.Clear;
  FMessage.TagId := SB_ASN1_SEQUENCE;
  FMessage.UndefSize := FUseUndefSize;
  SaveMessage(FMessage);
  Result := FMessage.SaveToBuffer(Buffer, Size);
end;


procedure TElPKCS7Message.Reset;
begin
  Clear;
  FMessage.Clear;
end;

function TElPKCS7Message.ProcessMessage : integer;
var
  Tag, ObjTag, InnerTag : TElASN1CustomTag;
  Cnt: ByteArray;
begin
  if FMessage.Count < 1 then
  begin
    Result := SB_PKCS7_ERROR_NO_DATA;
    Exit;
  end;
  if not FNoOuterContentInfo then
  begin
    Tag := FMessage.GetField(0);
    // Replaced below by II on 20081006
    if not {Tag.IsConstrained}Tag.CheckType(SB_ASN1_SEQUENCE, true) then
    begin
      Result := SB_PKCS7_ERROR_INVALID_CONTENT_INFO;
      Exit;
    end;
    if TElASN1ConstrainedTag(Tag).Count < 1 then
    begin
      Result := SB_PKCS7_ERROR_INVALID_CONTENT_INFO;
      Exit;
    end;
    ObjTag := TElASN1ConstrainedTag(Tag).GetField(0);
    if (ObjTag.IsConstrained) or (ObjTag.TagId <> SB_ASN1_OBJECT) then
    begin
      Result := SB_PKCS7_ERROR_INVALID_CONTENT_INFO;
      Exit;
    end;
    if TElASN1ConstrainedTag(Tag).Count >= 2 then
    begin
      InnerTag := TElASN1ConstrainedTag(Tag).GetField(1);
      if not InnerTag.IsConstrained then
      begin
        Result := SB_PKCS7_ERROR_INVALID_CONTENT_INFO;
        Exit;
      end;
      if TElASN1ConstrainedTag(InnerTag).Count < 1 then
      begin
        Result := SB_PKCS7_ERROR_INVALID_CONTENT_INFO;
        Exit;
      end;
      InnerTag := TElASN1ConstrainedTag(InnerTag).GetField(0);
    end
    else
      InnerTag := nil;
  end
  else
  begin
    InnerTag := FMessage.GetField(0);
    ObjTag := nil;
  end;
  
  if ObjTag <> nil then
    Cnt := TElASN1SimpleTag(ObjTag).Content
  else
    Cnt := EmptyArray;

  if ((ObjTag <> nil) and (CompareContent(Cnt, SB_OID_PKCS7_DATA))) or
    ((ObjTag = nil) and (FContentType = ctData)) then
  begin
    FContentType :=  ctData ;
    Result := ProcessData(InnerTag);
  end
  else
  if ((ObjTag <> nil) and (CompareContent(Cnt, SB_OID_PKCS7_SIGNED_DATA))) or
    ((ObjTag = nil) and (FContentType = ctSignedData)) then
  begin
    FContentType :=  ctSignedData ;
    Result := ProcessSignedData(InnerTag);
  end
  else
  if ((ObjTag <> nil) and (CompareContent(Cnt, SB_OID_PKCS7_ENVELOPED_DATA))) or
    ((ObjTag = nil) and (FContentType = ctEnvelopedData)) then
  begin
    FContentType :=  ctEnvelopedData ;
    Result := ProcessEnvelopedData(InnerTag);
  end
  else
  if ((ObjTag <> nil) and (CompareContent(Cnt, SB_OID_PKCS7_COMPRESSED_DATA))) or
    ((ObjTag = nil) and (FContentType = ctCompressedData)) then
  begin
    FContentType :=  ctCompressedData ;
    Result := ProcessCompressedData(InnerTag);
  end
  else
  if ((ObjTag <> nil) and (CompareContent(Cnt, SB_OID_PKCS7_SIGNED_AND_ENVELOPED_DATA))) or
    ((ObjTag = nil) and (FContentType = ctSignedAndEnvelopedData)) then
  begin
    FContentType :=  ctSignedAndEnvelopedData ;
    Result := ProcessSignedEnvelopedData(InnerTag);
  end
  else
  if ((ObjTag <> nil) and (CompareContent(Cnt, SB_OID_PKCS7_DIGESTED_DATA))) or
    ((ObjTag = nil) and (FContentType = ctDigestedData)) then
  begin
    FContentType :=  ctDigestedData ;
    Result := ProcessDigestData(InnerTag);
  end
  else
  if ((ObjTag <> nil) and (CompareContent(Cnt, SB_OID_PKCS7_ENCRYPTED_DATA))) or
    ((ObjTag = nil) and (FContentType = ctEncryptedData)) then
  begin
    FContentType :=  ctEncryptedData ;
    Result := ProcessEncryptedData(InnerTag);
  end
  else
  if ((ObjTag <> nil) and (CompareContent(Cnt, SB_OID_PKCS7_AUTHENTICATED_DATA))) or
    ((ObjTag = nil) and (FContentType = ctAuthenticatedData)) then
  begin
    FContentType :=  ctAuthenticatedData ;
    Result := ProcessAuthenticatedData(InnerTag);
  end
  else
  if ((ObjTag <> nil) and (CompareContent(Cnt, SB_OID_PKCS7_TIMESTAMPED_DATA))) or
    ((ObjTag = nil) and (FContentType = ctTimestampedData)) then
  begin
    FContentType :=  ctTimestampedData ;
    Result := ProcessTimestampedData(InnerTag);
  end
  else
  if FAllowUnknownContentTypes then
  begin
    FContentType := ctUnknown;
    if ObjTag <> nil then
      FCustomContentType := Cnt;
    Result := ProcessUnknownData(InnerTag);
  end
  else
    Result := SB_PKCS7_ERROR_UNKNOWN_DATA_TYPE;
end;

function TElPKCS7Message.ProcessData(Tag : TElASN1CustomTag) : integer;
var
  MsgSize : integer;
begin
  if not Assigned(Tag) then
  begin
    SetLength(FData, 0);
    Result := 0;
    Exit;
  end;
  if (Tag.TagNum <> SB_ASN1_OCTETSTRING) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_DATA;
    Exit;
  end;
  if Tag.IsConstrained then
  begin
    MsgSize := 0;
    TElASN1ConstrainedTag(Tag).SaveContentToBuffer( nil , MsgSize);
    SetLength(FData, MsgSize);
    TElASN1ConstrainedTag(Tag).SaveContentToBuffer( @FData[0] , MsgSize);
    SetLength(FData, MsgSize);
  end
  else
    FData := TElASN1SimpleTag(Tag).Content;
  Result := 0;
end;

function TElPKCS7Message.ProcessUnknownData(Tag : TElASN1CustomTag) : integer;
var
  MsgSize : integer;
begin
  if not Assigned(Tag) then
  begin
    SetLength(FData, 0);
    Result := 0;
    Exit;
  end;
  if Tag.IsConstrained then
  begin
    MsgSize := 0;
    TElASN1ConstrainedTag(Tag).SaveToBuffer( nil , MsgSize);
    SetLength(FData, MsgSize);
    TElASN1ConstrainedTag(Tag).SaveToBuffer( @FData[0] , MsgSize);
    SetLength(FData, MsgSize);
  end
  else
    FData := TElASN1SimpleTag(Tag).Content;
  Result := 0;
end;

function TElPKCS7Message.ProcessSignedData(Tag : TElASN1CustomTag) : integer;
var
  STag : TElASN1SimpleTag;
  Cnt, TmpS  : ByteArray;
  Sz : integer;
  EnvDataPrefix, EnvDataPostfix : ByteArray;
  // reconstructs ASN.1 prefix (SEQUENCE-OBJECT-A0-OCTETSTRING) and postfix (optional EOCs)
  // enveloping the enveloped data value
  procedure ExtractEnvelopedDataPrefixAndPostfix(EnvDataTag : TElASN1ConstrainedTag;
    var Prefix, Postfix : ByteArray);
  var
    TagSz : integer;
    Buf : ByteArray;
    InnerTag : TElASN1CustomTag;
  begin
    Postfix := EmptyArray;
    Prefix := EmptyArray;
    if (EnvDataTag.Count = 1) and (EnvDataTag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) then
    begin
      // no content (detached signature) case - saving the entire record as prefix
      TagSz := 0;
      EnvDataTag.SaveToBuffer( nil , TagSz);
      SetLength(Prefix, TagSz);
      EnvDataTag.SaveToBuffer( @Prefix[0] , TagSz);
      SetLength(Prefix, TagSz);
    end
    else if (EnvDataTag.Count >= 2) and EnvDataTag.GetField(0).CheckType(SB_ASN1_OBJECT, false) and
      EnvDataTag.GetField(1).CheckType(SB_ASN1_A0, true) then
    begin
      // outer SEQUENCE
      if EnvDataTag.UndefSize then
      begin
        Prefix := SBConcatArrays(byte(EnvDataTag.TagID), GetByteArrayFromByte($80));
        Postfix := BytesOfString(#$00#$00);
      end
      else
        Prefix := ASN1WriteTagAndLength(EnvDataTag.TagID, EnvDataTag.TagContentSize);
      // OBJECT
      TagSz := 0;
      EnvDataTag.GetField(0).SaveToBuffer( nil , TagSz);
      SetLength(Buf, TagSz);
      EnvDataTag.GetField(0).SaveToBuffer( @Buf[0] , TagSz);
      SetLength(Buf, TagSz);
      Prefix := SBConcatArrays(Prefix, Buf);
      // A0
      if EnvDataTag.GetField(1).UndefSize then
      begin
        Prefix := SBConcatArrays(Prefix, SBConcatArrays(byte(EnvDataTag.GetField(1).TagID), GetByteArrayFromByte($80)));
        Postfix := SBConcatArrays(BytesOfString(#$00#$00), Postfix);
      end
      else
        Prefix := SBConcatArrays(Prefix, ASN1WriteTagAndLength(EnvDataTag.GetField(1).TagID, EnvDataTag.GetField(1).TagContentSize));
      // OCTETSTRING (II20101121: tag of any other type is also accepted)
      InnerTag := TElASN1ConstrainedTag(EnvDataTag.GetField(1)).GetField(0);
      if InnerTag.UndefSize then
      begin
        // The below condition added by II 20130715, as compound OCTET STRING (0x24) tags are now included into FRawMultipartContent variable
        if not InnerTag.IsConstrained then
        begin
          Prefix := SBConcatArrays(Prefix, SBConcatArrays(byte(InnerTag.TagID), GetByteArrayFromByte($80)));
          Postfix := SBConcatArrays(BytesOfString(#$00#$00), Postfix);
        end;
      end
      else
      begin
        if not InnerTag.IsConstrained then
          Prefix := SBConcatArrays(Prefix, ASN1WriteTagAndLength(InnerTag.TagID, TElASN1SimpleTag(InnerTag).DataSource.Size))
        else
          Prefix := SBConcatArrays(Prefix, ASN1WriteTagAndLength(InnerTag.TagID, InnerTag.TagContentSize));
      end;
    end;
  end;
begin
  FSignedData.FEncodedCertificates := EmptyArray;
  FSignedData.FEncodedCRLs := EmptyArray;
  if (not Tag.IsConstrained) or (Tag.TagId <> SB_ASN1_SEQUENCE) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNED_DATA;
    Exit;
  end;
  if TElASN1ConstrainedTag(Tag).Count < 4 then
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNED_DATA;
    Exit;
  end;
  if (TElASN1ConstrainedTag(Tag).GetField(0).IsConstrained) or
    (TElASN1ConstrainedTag(Tag).GetField(0).TagId <> SB_ASN1_INTEGER) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNED_DATA;
    Exit;
  end;
  FUseUndefSize := Tag.UndefSize;
  STag := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(0));
  Cnt := STag.Content;

  // Comodo CA incorrectly supplies us with 0 version, so we have to accept it as well
  if (Length(Cnt) < 1) or (Cnt[Length(Cnt) - 1] < 0{1}) or (Cnt[Length(Cnt) - 1] > 5) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNED_DATA_VERSION;
    Exit;
  end;

  FSignedData.FVersion := Cnt[Length(Cnt) - 1];
    
  { Checking digestAlgorithms }
  if (not TElASN1ConstrainedTag(Tag).GetField(1).IsConstrained) or
    (TElASN1ConstrainedTag(Tag).GetField(1).TagId <> SB_ASN1_SET) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNED_DATA;
    Exit;
  end;
  { Reading ContentInfo }
  if (not TElASN1ConstrainedTag(Tag).GetField(2).IsConstrained) or
    (TElASN1ConstrainedTag(Tag).GetField(2).TagId <> SB_ASN1_SEQUENCE) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNED_DATA;
    Exit;
  end;
  SignedData.ClearContentParts;
  if not ProcessContentInfo(TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(2)),
    SignedData, TmpS) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNED_DATA;
    Exit;
  end;
  SignedData.ContentType := TmpS;
  // saving ASN.1 prefix and postfix of content info (for further hashing)
  ExtractEnvelopedDataPrefixAndPostfix(TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(2)),
    EnvDataPrefix, EnvDataPostfix);
  FSignedData.FEnvelopedContentPrefix := EnvDataPrefix;
  FSignedData.FEnvelopedContentPostfix := EnvDataPostfix;
  { Processing certificates }
  if (TElASN1ConstrainedTag(Tag).GetField(3).IsConstrained) and
    (TElASN1ConstrainedTag(Tag).GetField(3).TagId = SB_ASN1_A0) and
    (TElASN1ConstrainedTag(Tag).Count > 4) then
  begin
    try
      ProcessCertificates(TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(3)),
        FSignedData.FCertStorage);
      // saving DER-encoded value of certificate set
      Sz := 0;
      TElASN1ConstrainedTag(Tag).GetField(3).SaveToBuffer( nil , Sz);
      SetLength(FSignedData.FEncodedCertificates, Sz);
      TElASN1ConstrainedTag(Tag).GetField(3).SaveToBuffer( @FSignedData.FEncodedCertificates[0] , Sz);
      SetLength(FSignedData.FEncodedCertificates, Sz);
    except
      Result := SB_PKCS7_ERROR_INVALID_SIGNED_DATA;
      Exit;
    end;
    if (TElASN1ConstrainedTag(Tag).GetField(4).IsConstrained) and
      (TElASN1ConstrainedTag(Tag).GetField(4).TagId = SB_ASN1_A1) and
      (TElASN1ConstrainedTag(Tag).Count > 5) then
    begin
      // crls are included
      try
        ProcessCRLs(TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(4)),
          FSignedData.FCRLStorage {$ifndef SB_NO_OCSP}, FSignedData.FOCSPStorage {$endif});
        // saving DER-encoded value of CRL set
        Sz := 0;
        TElASN1ConstrainedTag(Tag).GetField(3).SaveToBuffer( nil , Sz);
        SetLength(FSignedData.FEncodedCRLs, Sz);
        TElASN1ConstrainedTag(Tag).GetField(3).SaveToBuffer( @FSignedData.FEncodedCRLs[0] , Sz);
        SetLength(FSignedData.FEncodedCRLs, Sz);
      except
        Result := SB_PKCS7_ERROR_INVALID_SIGNED_DATA;
        Exit;
      end;
      if (TElASN1ConstrainedTag(Tag).GetField(5).IsConstrained) and
        (TElASN1ConstrainedTag(Tag).GetField(5).TagId = SB_ASN1_SET) then
      begin
        Result := ProcessSignerInfos(TElASN1ConstrainedTag(Tag).GetField(5),
          SignedData.FSignerList);
      end
      else
      begin
        Result := SB_PKCS7_ERROR_INVALID_SIGNED_DATA;
        Exit;
      end;
    end
    else if (TElASN1ConstrainedTag(Tag).GetField(4).IsConstrained) and
      (TElASN1ConstrainedTag(Tag).GetField(4).TagId = SB_ASN1_SET) then
    begin
      Result := ProcessSignerInfos(TElASN1ConstrainedTag(Tag).GetField(4),
        SignedData.FSignerList);
    end
    else
    begin
      Result := SB_PKCS7_ERROR_INVALID_SIGNED_DATA;
      Exit;
    end;
  end
  else if (TElASN1ConstrainedTag(Tag).GetField(3).IsConstrained) and
    (TElASN1ConstrainedTag(Tag).GetField(3).TagId = SB_ASN1_A1) and
    (TElASN1ConstrainedTag(Tag).Count > 4) then
  begin
    if (TElASN1ConstrainedTag(Tag).GetField(4).IsConstrained) and
      (TElASN1ConstrainedTag(Tag).GetField(4).TagId = SB_ASN1_SET) then
    begin
      Result := ProcessSignerInfos(TElASN1ConstrainedTag(Tag).GetField(4),
        SignedData.FSignerList);
    end
    else
    begin
      Result := SB_PKCS7_ERROR_INVALID_SIGNED_DATA;
      Exit;
    end;
  end
  else if (TElASN1ConstrainedTag(Tag).GetField(3).IsConstrained) and
    (TElASN1ConstrainedTag(Tag).GetField(3).TagId = SB_ASN1_SET) then
  begin
    Result := ProcessSignerInfos(TElASN1ConstrainedTag(Tag).GetField(3),
      SignedData.FSignerList);
  end
  else
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNED_DATA;
    Exit;
  end;
end;

function TElPKCS7Message.ProcessEnvelopedData(Tag : TElASN1CustomTag) : integer;
var
  STag : TElASN1SimpleTag;
  CTag : TElASN1ConstrainedTag;
  I, Idx : integer;
begin
  if (not Tag.IsConstrained) or (Tag.TagId <> SB_ASN1_SEQUENCE) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ENVELOPED_DATA;
    Exit;
  end;
  if TElASN1ConstrainedTag(Tag).Count < 3 then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ENVELOPED_DATA;
    Exit;
  end;
  { Reading version (should be 0 or 2 for the structures understood by SBB }
  if (TElASN1ConstrainedTag(Tag).GetField(0).IsConstrained) or
    (TElASN1ConstrainedTag(Tag).GetField(0).TagId <> SB_ASN1_INTEGER) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ENVELOPED_DATA;
    Exit;
  end;
  STag := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(0));
  if ((STag.Content[Length(STag.Content) - 1] <> byte(0)) and (STag.Content[Length(STag.Content) - 1] <> byte(2))) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ENVELOPED_DATA_VERSION;
    Exit;
  end;
  Idx := 1;
  { Optionally reading OriginatorInfo }
  if TElASN1ConstrainedTag(Tag).GetField(Idx).CheckType(SB_ASN1_A0, true) then
  begin
    CTag := TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(Idx));
    for I := 0 to CTag.Count - 1 do
      if CTag.GetField(I).CheckType(SB_ASN1_A0, true) then
        ProcessCertificates(TElASN1ConstrainedTag(CTag.GetField(I)), FEnvelopedData.FOriginatorCertificates)
      else if CTag.GetField(I).CheckType(SB_ASN1_A1, true) then
        ProcessCRLs(TElASN1ConstrainedTag(CTag.GetField(I)), FEnvelopedData.FOriginatorCRLs{$ifndef SB_NO_OCSP}, nil {$endif});
    Inc(Idx);
  end;
  { Reading RecipientInfos }
  Result := ProcessRecipientInfos(TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(Idx)),
    FEnvelopedData.FRecipientList);
  if Result <> 0 then
    Exit;
  Inc(Idx);
  { Reading EncryptedContentInfo }
  if (Idx >= TElASN1ConstrainedTag(Tag).Count) or
    (not TElASN1ConstrainedTag(Tag).GetField(Idx).IsConstrained) or
    (TElASN1ConstrainedTag(Tag).GetField(Idx).TagId <> SB_ASN1_SEQUENCE) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ENVELOPED_DATA;
    Exit;
  end;
  Result := ProcessEncryptedContentInfo(TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(Idx)),
    FEnvelopedData.EncryptedContent);
  Inc(Idx);
  { Optionally reading UnprotectedAttrs }
  if Idx >= TElASN1ConstrainedTag(Tag).Count then
    Exit;
  if not TElASN1ConstrainedTag(Tag).GetField(Idx).CheckType(SB_ASN1_A1, true) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ENVELOPED_DATA;
    Exit;
  end;
  Result := ProcessAttributes(TElASN1ConstrainedTag(Tag).GetField(Idx),
    FEnvelopedData.FUnprotectedAttributes);
end;

function TElPKCS7Message.ProcessSignedEnvelopedData(Tag : TElASN1CustomTag) : integer;
begin
  if (not Tag.IsConstrained) or (Tag.TagId <> SB_ASN1_SEQUENCE) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNED_AND_ENVELOPED_DATA;
    Exit;
  end;
  if TElASN1ConstrainedTag(Tag).Count < 5 then
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNED_AND_ENVELOPED_DATA;
    Exit;
  end;
  if (TElASN1ConstrainedTag(Tag).GetField(0).IsConstrained) or
    (TElASN1ConstrainedTag(Tag).GetField(0).TagId <> SB_ASN1_INTEGER) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNED_AND_ENVELOPED_DATA;
    Exit;
  end;
  if not CompareContent(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(0)).Content, 
    BytesOfString(#1)) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNED_AND_ENVELOPED_DATA_VERSION;
    Exit;
  end;
  if (not TElASN1ConstrainedTag(Tag).GetField(1).IsConstrained) or
    (TElASN1ConstrainedTag(Tag).GetField(1).TagId <> SB_ASN1_SET) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNED_AND_ENVELOPED_DATA;
    Exit;
  end;
  Result := ProcessRecipientInfos(TElASN1ConstrainedTag(Tag).GetField(1),
    FSignedAndEnvelopedData.FRecipientList);
  if Result <> 0 then
    Exit;
  if (not TElASN1ConstrainedTag(Tag).GetField(3).IsConstrained) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNED_AND_ENVELOPED_DATA;
    Exit;
  end;
  Result := ProcessEncryptedContentInfo(TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(3)),
    FSignedAndEnvelopedData.FEncryptedContent);
  if Result <> 0 then
    Exit;
  if not TElASN1ConstrainedTag(Tag).GetField(4).IsConstrained then
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNED_AND_ENVELOPED_DATA;
    Exit;
  end;
  if (TElASN1ConstrainedTag(Tag).GetField(4).TagId = SB_ASN1_A0) and
    (TElASN1ConstrainedTag(Tag).Count > 5) then
  begin
    ProcessCertificates(TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(4)),
      FSignedAndEnvelopedData.FCertStorage);
    if (TElASN1ConstrainedTag(Tag).GetField(5).TagId = SB_ASN1_A1)
      and (TElASN1ConstrainedTag(Tag).Count > 6) then
    begin
      Result := ProcessSignerInfos(TElASN1ConstrainedTag(Tag).GetField(6),
        FSignedAndEnvelopedData.FSignerList);
    end
    else if TElASN1ConstrainedTag(Tag).GetField(5).TagId = SB_ASN1_SET then
    begin
      Result := ProcessSignerInfos(TElASN1ConstrainedTag(Tag).GetField(5),
        FSignedAndEnvelopedData.FSignerList);
    end
    else
      Result := SB_PKCS7_ERROR_INVALID_SIGNED_AND_ENVELOPED_DATA;
  end
  else if (TElASN1ConstrainedTag(Tag).GetField(4).TagId = SB_ASN1_A1) and
    (TElASN1ConstrainedTag(Tag).Count > 5) then
  begin
    if (not TElASN1ConstrainedTag(Tag).GetField(5).IsConstrained) or
      (TElASN1ConstrainedTag(Tag).GetField(5).TagId <> SB_ASN1_SET) then
    begin
      Result := SB_PKCS7_ERROR_INVALID_SIGNED_AND_ENVELOPED_DATA;
      Exit;
    end;
    Result := ProcessSignerInfos(TElASN1ConstrainedTag(Tag).GetField(5),
      FSignedAndEnvelopedData.FSignerList);
  end
  else if TElASN1ConstrainedTag(Tag).GetField(4).TagId = SB_ASN1_SET then
  begin
    Result := ProcessSignerInfos(TElASN1ConstrainedTag(Tag).GetField(4),
      FSignedAndEnvelopedData.FSignerList);
  end
  else
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNED_AND_ENVELOPED_DATA;
    Exit;
  end;
end;

function TElPKCS7Message.ProcessCompressedData(Tag : TElASN1CustomTag) : integer;
var
  subTag, octTag : TElASN1ConstrainedTag;
  I, J : integer;
begin
  if (not Tag.CheckType(SB_ASN1_SEQUENCE, true)) or (TElASN1ConstrainedTag(Tag).Count <> 3) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_COMPRESSED_DATA;
    Exit;
  end;
  if (not TElASN1ConstrainedTag(Tag).GetField(0).CheckType(SB_ASN1_INTEGER, false)) or
    (not CompareContent(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(0)).Content, GetByteArrayFromByte(0)))
  then
  begin
    Result := SB_PKCS7_ERROR_INVALID_COMPRESSED_DATA;
    Exit;
  end
  else
    FCompressedData.FVersion := 0;
    
  if (not TElASN1ConstrainedTag(Tag).GetField(1).CheckType(SB_ASN1_SEQUENCE, true)) or
    (not TElASN1ConstrainedTag(Tag).GetField(2).CheckType(SB_ASN1_SEQUENCE, true)) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_COMPRESSED_DATA;
    Exit;
  end;

  subTag := TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(1));
  if (not subTag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) or
    (not CompareContent(TElASN1SimpleTag(subTag.GetField(0)).Content, SB_OID_PKCS7_COMPRESSION_ZLIB))
  then
  begin
    Result := SB_PKCS7_ERROR_INVALID_COMPRESSED_DATA;
    Exit;
  end;

  subTag := TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(2));
  if (subTag.Count < 2) or (not subTag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) or (not subTag.GetField(1).CheckType(SB_ASN1_A0, true)) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_COMPRESSED_DATA;
    Exit;
  end;

  FCompressedData.ContentType := TElASN1SimpleTag(subTag.GetField(0)).Content;

  if subTag.GetField(1).IsConstrained then
  begin
    for I := 0 to TElASN1ConstrainedTag(subTag.GetField(1)).Count - 1 do
    begin
      if TElASN1ConstrainedTag(subTag.GetField(1)).GetField(I).CheckType(SB_ASN1_OCTETSTRING or SB_ASN1_CONSTRAINED_FLAG, true) then
      begin
        { fragmented octet string }
        octTag := TElASN1ConstrainedTag(TElASN1ConstrainedTag(subTag.GetField(1)).GetField(I));
        for J := 0 to octTag.Count - 1 do
        begin
          if (not octTag.GetField(J).CheckType(SB_ASN1_OCTETSTRING, false)) then
          begin
            Result := SB_PKCS7_ERROR_INVALID_COMPRESSED_DATA_CONTENT;
            Exit;
          end;
          FCompressedData.AddContentPart(TElASN1SimpleTag(octTag.GetField(J)).DataSource);        
        end;
      end
      else
      begin
        if (not TElASN1ConstrainedTag(subTag.GetField(1)).GetField(I).CheckType(SB_ASN1_OCTETSTRING, false)) then
        begin
          Result := SB_PKCS7_ERROR_INVALID_COMPRESSED_DATA_CONTENT;
          Exit;
        end;
        FCompressedData.AddContentPart(TElASN1SimpleTag(TElASN1ConstrainedTag(subTag.GetField(1)).GetField(I)).DataSource);
      end;  
    end;
  end
  else
    FCompressedData.AddContentPart(TElASN1SimpleTag(subTag.GetField(1)).DataSource);

  Result := 0;
end;

function TElPKCS7Message.ProcessDigestData(Tag : TElASN1CustomTag) : integer;
var
  CT : ByteArray;
  Cont : ByteArray;
  Sz : integer;
begin
  if not (Tag.IsConstrained) or (Tag.TagId <> SB_ASN1_SEQUENCE) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_DIGESTED_DATA;
    Exit;
  end;
  if TElASN1ConstrainedTag(Tag).Count <> 4 then
  begin
    Result := SB_PKCS7_ERROR_INVALID_DIGESTED_DATA;
    Exit;
  end;
  if (TElASN1ConstrainedTag(Tag).GetField(0).TagId <> SB_ASN1_INTEGER) or
    (TElASN1ConstrainedTag(Tag).GetField(0).IsConstrained) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_DIGESTED_DATA;
    Exit;
  end;
  if not CompareContent(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(0)).Content, GetByteArrayFromByte(0)) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_DIGESTED_DATA_VERSION;
    Exit;
  end;
  ProcessAlgorithmIdentifier(TElASN1ConstrainedTag(Tag).GetField(1),
    FDigestedData.FDigestAlgorithm, FDigestedData.FDigestAlgorithmParams {$ifndef HAS_DEF_PARAMS}, False {$endif});
  if (not TElASN1ConstrainedTag(Tag).GetField(2).IsConstrained) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_DIGESTED_DATA;
    Exit;
  end;
  Sz := 0;
  ProcessContentInfo(TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(2)),
    nil, Sz, CT);
  SetLength(Cont, Sz);
  ProcessContentInfo(TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(2)),
    @Cont[0], Sz, CT);
  if (TElASN1ConstrainedTag(Tag).GetField(3).IsConstrained) or
    (TElASN1ConstrainedTag(Tag).GetField(3).TagId <> SB_ASN1_OCTETSTRING) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_DIGESTED_DATA;
    Exit;
  end;
  Result := 0;
end;

function TElPKCS7Message.ProcessEncryptedData(Tag : TElASN1CustomTag) : integer;
begin
  if not (Tag.IsConstrained) or (Tag.TagId <> SB_ASN1_SEQUENCE) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ENCRYPTED_DATA;
    Exit;
  end;
  if TElASN1ConstrainedTag(Tag).Count <> 2 then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ENCRYPTED_DATA;
    Exit;
  end;
  if (TElASN1ConstrainedTag(Tag).GetField(0).IsConstrained) or
    (TElASN1ConstrainedTag(Tag).GetField(0).TagId <> SB_ASN1_INTEGER) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ENCRYPTED_DATA;
    Exit;
  end;
  if not CompareContent(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(0)).Content, GetByteArrayFromByte(0)) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ENCRYPTED_DATA_VERSION;
    Exit;
  end;
  if (not TElASN1ConstrainedTag(Tag).GetField(1).IsConstrained) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ENCRYPTED_DATA;
    Exit;
  end;
  Result := ProcessEncryptedContentInfo(
    TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(1)),
    FEncryptedData.FEncryptedContent);
end;

function TElPKCS7Message.ProcessAuthenticatedData(Tag : TElASN1CustomTag) : integer;
var
  CurrParamIndex : integer;
begin
  if not (Tag.IsConstrained) or (Tag.TagId <> SB_ASN1_SEQUENCE) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ENCRYPTED_DATA;
    Exit;
  end;
  CurrParamIndex := 0;

  // reading version
  if (CurrParamIndex >= TElASN1ConstrainedTag(Tag).Count) or
    (TElASN1ConstrainedTag(Tag).GetField(CurrParamIndex).IsConstrained) or
    (TElASN1ConstrainedTag(Tag).GetField(CurrParamIndex).TagId <> SB_ASN1_INTEGER) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_AUTHENTICATED_DATA;
    Exit;
  end;
  if not CompareContent(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(CurrParamIndex)).Content,
    GetByteArrayFromByte(0)) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_AUTHENTICATED_DATA_VERSION;
    Exit;
  end;
  Inc(CurrParamIndex);

  // reading OriginatorInfo
  if (CurrParamIndex >= TElASN1ConstrainedTag(Tag).Count) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_AUTHENTICATED_DATA;
    Exit;
  end;
  if TElASN1ConstrainedTag(Tag).GetField(CurrParamIndex).TagId = SB_ASN1_A0 then
  begin
    // OriginatorInfo is not supported at the moment. Skipping.
    Inc(CurrParamIndex);
  end;

  // reading RecipientInfos
  if CurrParamIndex >= TElASN1ConstrainedTag(Tag).Count then
  begin
    Result := SB_PKCS7_ERROR_INVALID_AUTHENTICATED_DATA;
    Exit;
  end;
  Result := ProcessRecipientInfos(TElASN1ConstrainedTag(Tag).GetField(CurrParamIndex),
    FAuthenticatedData.FRecipientList);
  if Result <> 0 then
    Exit;
  Inc(CurrParamIndex);

  // reading MacAlgorithm
  if CurrParamIndex >= TElASN1ConstrainedTag(Tag).Count then
  begin
    Result := SB_PKCS7_ERROR_INVALID_AUTHENTICATED_DATA;
    Exit;
  end;
  Result := ProcessAlgorithmIdentifier(TElASN1ConstrainedTag(Tag).GetField(CurrParamIndex),
    FAuthenticatedData.FMacAlgorithm, FAuthenticatedData.FMacAlgorithmParams {$ifndef HAS_DEF_PARAMS}, False {$endif});
  if Result <> 0 then
    Exit;
  Inc(CurrParamIndex);

  // reading DigestAlgorithm 
  if CurrParamIndex >= TElASN1ConstrainedTag(Tag).Count then
  begin
    Result := SB_PKCS7_ERROR_INVALID_AUTHENTICATED_DATA;
    Exit;
  end;
  if TElASN1ConstrainedTag(Tag).GetField(CurrParamIndex).TagId = SB_ASN1_A1 then
  begin
    Result := ProcessAlgorithmIdentifier(TElASN1ConstrainedTag(Tag).GetField(CurrParamIndex),
      FAuthenticatedData.FDigestAlgorithm, FAuthenticatedData.FDigestAlgorithmParams,
      true);
    if Result <> 0 then
      Exit;
    Inc(CurrParamIndex);
  end;

  // reading EncapsulatedContentInfo
  if (CurrParamIndex >= TElASN1ConstrainedTag(Tag).Count) or
    (not TElASN1ConstrainedTag(Tag).GetField(CurrParamIndex).IsConstrained) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_AUTHENTICATED_DATA;
    Exit;
  end;
  (*Size := 0;
  ProcessContentInfo(TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(CurrParamIndex)),
    {$ifdef SB_VCL}nil{$else}FAuthenticatedData.FContent{$endif}, Size, FAuthenticatedData.FContentType);
  SetLength(FAuthenticatedData.FContent, Size);
  ProcessContentInfo(TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(CurrParamIndex)),
    {$ifdef SB_VCL}@FAuthenticatedData.FContent[0]{$else}FAuthenticatedData.FContent{$endif},
    Size, FAuthenticatedData.FContentType);
  SetLength(FAuthenticatedData.FContent, Size);*)
  FAuthenticatedData.ClearContentParts;
  if not ProcessContentInfo(TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(CurrParamIndex)),
    FAuthenticatedData, FAuthenticatedData.FContentType) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_AUTHENTICATED_DATA;
    Exit;
  end;

  Inc(CurrParamIndex);

  // reading AuthenticatedAttributes
  if (CurrParamIndex >= TElASN1ConstrainedTag(Tag).Count) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_AUTHENTICATED_DATA;
    Exit;
  end;
  if (TElASN1ConstrainedTag(Tag).GetField(CurrParamIndex).TagId = SB_ASN1_A2)
    and (TElASN1ConstrainedTag(Tag).GetField(CurrParamIndex).IsConstrained) then
  begin
    Result := ProcessAttributes(TElASN1ConstrainedTag(Tag).GetField(CurrParamIndex),
      FAuthenticatedData.FAuthenticatedAttributes);
    if Result <> 0 then
      Exit;
    Inc(CurrParamIndex);
  end;

  // reading Mac
  if (CurrParamIndex >= TElASN1ConstrainedTag(Tag).Count) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_AUTHENTICATED_DATA;
    Exit;
  end;
  if (TElASN1ConstrainedTag(Tag).GetField(CurrParamIndex).TagId <> SB_ASN1_OCTETSTRING) or
    (TElASN1ConstrainedTag(Tag).GetField(CurrParamIndex).IsConstrained) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_AUTHENTICATED_DATA;
    Exit;
  end;
  FAuthenticatedData.FMac := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(CurrParamIndex)).Content;
  Inc(CurrParamIndex);

  // reading UnauthenticatedAttributes
  if CurrParamIndex < TElASN1ConstrainedTag(Tag).Count then
  begin
    if (not TElASN1ConstrainedTag(Tag).GetField(CurrParamIndex).IsConstrained) or
      (TElASN1ConstrainedTag(Tag).GetField(CurrParamIndex).TagId <> SB_ASN1_A3) then
    begin
      Result := SB_PKCS7_ERROR_INVALID_AUTHENTICATED_DATA;
      Exit;
    end;
    Result := ProcessAttributes(TElASN1ConstrainedTag(Tag).GetField(CurrParamIndex),
      FAuthenticatedData.FUnauthenticatedAttributes);
  end;
end;

function TElPKCS7Message.ProcessTimestampedData(Tag : TElASN1CustomTag) : integer;
var
  CurrParamIndex, SubTagIndex, I, Sz : integer;
  cTag, cSubTag : TElASN1ConstrainedTag;
  Buffer : ByteArray;
begin
  if not (Tag.IsConstrained) or (Tag.TagId <> SB_ASN1_SEQUENCE) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_TIMESTAMPED_DATA;
    Exit;
  end;

  CurrParamIndex := 0;
  cTag := TElASN1ConstrainedTag(Tag);

  // reading version
  if (CurrParamIndex >= cTag.Count) or (cTag.GetField(CurrParamIndex).IsConstrained) or
    (cTag.GetField(CurrParamIndex).TagId <> SB_ASN1_INTEGER) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_TIMESTAMPED_DATA;
    Exit;
  end;

  if not CompareContent(TElASN1SimpleTag(cTag.GetField(CurrParamIndex)).Content,
    GetByteArrayFromByte(1)) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_TIMESTAMPED_DATA_VERSION;
    Exit;
  end;
  Inc(CurrParamIndex);

  // reading dataURI if any
  if (CurrParamIndex < cTag.Count) and (cTag.GetField(CurrParamIndex).CheckType(SB_ASN1_IA5STRING, false)) then
  begin
    FTimestampedData.DataURI := TElASN1SimpleTag(cTag.GetField(CurrParamIndex)).Content;
    Inc(CurrParamIndex);
  end
  else
    FTimestampedData.DataURI := EmptyArray;

  // reading metaData if any. It is optional, but not last SEQUENCE
  if (CurrParamIndex < cTag.Count - 1) and (cTag.GetField(CurrParamIndex).CheckType(SB_ASN1_SEQUENCE, true)) then
  begin
    FTimestampedData.MetaDataAvailable := true;
    cTag := TElASN1ConstrainedTag(cTag.GetField(CurrParamIndex));

    // hashProtected
    if (cTag.Count < 1) or (not cTag.GetField(0).CheckType(SB_ASN1_BOOLEAN, false)) then
    begin
      Result := SB_PKCS7_ERROR_INVALID_TIMESTAMPED_DATA;
      Exit;
    end;

    FTimestampedData.HashProtected := ASN1ReadBoolean(TElASN1SimpleTag(cTag.GetField(0)));
    SubTagIndex := 1;

    // fileName
    if (SubTagIndex < cTag.Count) and (cTag.GetField(SubTagIndex).CheckType(SB_ASN1_UTF8STRING, false)) then
    begin
      FTimestampedData.FileName := TElASN1SimpleTag(cTag.GetField(SubTagIndex)).Content;
      Inc(SubTagIndex);
    end
    else
      FTimestampedData.FileName := EmptyArray;

    // mediaType
    if (SubTagIndex < cTag.Count) and (cTag.GetField(SubTagIndex).CheckType(SB_ASN1_IA5STRING, false)) then
    begin
      FTimestampedData.MediaType := TElASN1SimpleTag(cTag.GetField(SubTagIndex)).Content;
      Inc(SubTagIndex);
    end
    else
      FTimestampedData.MediaType := EmptyArray;

    // if there are tags left, they should be Attributes - ignoring them since we don't support any  
    if (SubTagIndex < cTag.Count - 1) and (not cTag.GetField(SubTagIndex).CheckType(SB_ASN1_SET, true)) then
    begin
      Result := SB_PKCS7_ERROR_INVALID_TIMESTAMPED_DATA;
      Exit;
    end;

    cTag := TElASN1ConstrainedTag(Tag);
    Inc(CurrParamIndex);
  end
  else
    FTimestampedData.MetaDataAvailable := false;

  // content
  FTimestampedData.ClearContentParts;
  if (CurrParamIndex < cTag.Count - 1) and (cTag.GetField(CurrParamIndex).CheckType(SB_ASN1_OCTETSTRING, false)) then
  begin
    FTimestampedData.AddContentPart(TElASN1SimpleTag(cTag.GetField(CurrParamIndex)).DataSource);
    Inc(CurrParamIndex);
  end;

  // temporalEvidence
  // we support only TimeStampTokenEvidence now
  if (CurrParamIndex <> cTag.Count - 1) or (not cTag.GetField(CurrParamIndex).CheckType(SB_ASN1_A0, true)) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_TIMESTAMPED_DATA;
    Exit;
  end;
  cTag := TElASN1ConstrainedTag(cTag.GetField(CurrParamIndex));
  FTimestampedData.ClearTimestamps;

  for SubTagIndex := 0 to cTag.Count - 1 do
  begin
    // outer sequence for TimeStampTokenEvidence
    if (not cTag.GetField(SubTagIndex).CheckType(SB_ASN1_SEQUENCE, true)) then
    begin
      Result := SB_PKCS7_ERROR_INVALID_TIMESTAMPED_DATA;
      Exit;
    end;

    // inner sequence for Timestamp and CRL
    cSubTag := TElASN1ConstrainedTag(cTag.GetField(SubTagIndex));

    if (not cSubTag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
    begin
      Result := SB_PKCS7_ERROR_INVALID_TIMESTAMPED_DATA;
      Exit;
    end;

    // Timestamp
    I := FTimestampedData.AddTimestamp;
    Sz := 0;
    TElASN1ConstrainedTag(cSubTag.GetField(0)).SaveToBuffer( nil , Sz);
    SetLength(Buffer, Sz);
    TElASN1ConstrainedTag(cSubTag.GetField(0)).SaveToBuffer( @Buffer[0] , Sz);
    SetLength(Buffer, Sz);
    FTimestampedData.Timestamps[I].EncodedTimestamp := CloneArray(Buffer);

    // Optional CRL
    if (cSubTag.Count > 1) then
    begin
      if (cSubTag.Count > 2) or (not cSubTag.GetField(1).CheckType(SB_ASN1_SEQUENCE, true)) then
      begin
        Result := SB_PKCS7_ERROR_INVALID_TIMESTAMPED_DATA;
        Exit;
      end;

      Sz := 0;
      cSubTag.GetField(1).SaveToBuffer( nil , Sz);
      SetLength(Buffer, Sz);
      cSubTag.GetField(1).SaveToBuffer( @Buffer[0] , Sz);
      FTimestampedData.Timestamps[I].EncodedCRL := (Buffer);
    end;

    // original TimestampAndCRL value, used for hashing
    Sz := 0;
    cSubTag.SaveToBuffer( nil , Sz);
    SetLength(Buffer, Sz);
    cSubTag.SaveToBuffer( @Buffer[0] , Sz);
    FTimestampedData.Timestamps[I].EncodedValue := (Buffer);
  end;


  Result := 0;
end;

procedure TElPKCS7Message.Clear;
begin
  SetLength(FData, 0);
  FCustomContentType := EmptyArray;
end;

function TElPKCS7Message.ProcessRecipientInfos(Tag : TElASN1CustomTag; RecipientList:
  TElList) : integer;
var
  I : integer;
  Recipient : TElPKCS7Recipient;
begin
  if (not Tag.IsConstrained) or (Tag.TagId <> SB_ASN1_SET) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_RECIPIENT_INFOS;
    Exit;
  end;
  for I := 0 to TElASN1ConstrainedTag(Tag).Count - 1 do
  begin
    Recipient := TElPKCS7Recipient.Create;
    RecipientList.Add(Recipient);
    Result := ProcessRecipientInfo(TElASN1ConstrainedTag(Tag).GetField(I),
      Recipient);
    if Result <> 0 then
      Exit;
  end;
  Result := 0;
end;

function TElPKCS7Message.ProcessRecipientInfo(Tag : TElASN1CustomTag; Recipient :
  TElPKCS7Recipient) : integer;
var
  STag : TElASN1SimpleTag;
begin
  if (not Tag.IsConstrained) or (Tag.TagId <> SB_ASN1_SEQUENCE) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_RECIPIENT_INFO;
    Exit;
  end;
  if TElASN1ConstrainedTag(Tag).Count < 4 then
  begin
    Result := SB_PKCS7_ERROR_INVALID_RECIPIENT_INFO;
    Exit;
  end;
  { Reading version }
  if (TElASN1ConstrainedTag(Tag).GetField(0).IsConstrained) or
    (TElASN1ConstrainedTag(Tag).GetField(0).TagId <> SB_ASN1_INTEGER) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_RECIPIENT_INFO;
    Exit;
  end;
  STag := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(0));
  if (STag.Content[Length(STag.Content) - 1] <> byte(0)) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_RECIPIENT_INFO_VERSION;
    Exit;
  end;
  { Reading IssuerAndSerialNumber }
  Result := ProcessIssuerAndSerialNumber(TElASN1ConstrainedTag(Tag).GetField(1),
    Recipient.Issuer);
  if Result <> 0 then
    Exit;
  { Reading KeyEncryptionAlgorithm }
  Result := ProcessAlgorithmIdentifier(TElASN1ConstrainedTag(Tag).GetField(2),
    Recipient.FKeyEncryptionAlgorithm, Recipient.FKeyEncryptionAlgorithmParams {$ifndef HAS_DEF_PARAMS}, False {$endif});
  if Result <> 0 then
    Exit;
  Recipient.FKeyEncryptionAlgorithmIdentifier := TElAlgorithmIdentifier.CreateFromTag(TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(2)));

  { Reading EncryptedKey }
  if (TElASN1ConstrainedTag(Tag).GetField(3).IsConstrained) or
    (TElASN1ConstrainedTag(Tag).GetField(3).TagId <> SB_ASN1_OCTETSTRING) then
  begin
    Result:= SB_PKCS7_ERROR_INVALID_RECIPIENT_INFO_KEY;
    Exit;
  end;
  Recipient.FEncryptedKey := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(3)).Content;
  Result := 0;
end;

function TElPKCS7Message.ProcessEncryptedContentInfo(Tag : TElASN1ConstrainedTag;
  EncryptedContent : TElPKCS7EncryptedContent) : integer;
var
  InnerTag : TElASN1CustomTag;
  I : integer;
begin
  if (not Tag.IsConstrained) or (Tag.TagId <> SB_ASN1_SEQUENCE) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ENVELOPED_DATA_CONTENT;
    Exit;
  end;
  if TElASN1ConstrainedTag(Tag).Count < 3 then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ENVELOPED_DATA_CONTENT;
    Exit;
  end;
  { Reading ContentType }
  if (TElASN1ConstrainedTag(Tag).GetField(0).IsConstrained) or
    (TElASN1ConstrainedTag(Tag).GetField(0).TagId <> SB_ASN1_OBJECT) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ENVELOPED_DATA_CONTENT;
    Exit;
  end;
  EncryptedContent.FContentType := TElASN1SimpleTag(
    TElASN1ConstrainedTag(Tag).GetField(0)).Content;
  { Reading ContentEncryptionAlgorithm }
  Result := ProcessAlgorithmIdentifier(TElASN1ConstrainedTag(Tag).GetField(1),
    EncryptedContent.FContentEncryptionAlgorithm,
    EncryptedContent.FContentEncryptionAlgorithmParams {$ifndef HAS_DEF_PARAMS}, False {$endif});
  if Result <> 0 then
    Exit;
  { Reading EncryptedContent }
  EncryptedContent.ClearContentParts;
  InnerTag := TElASN1ConstrainedTag(Tag).GetField(2);
  if (not ((InnerTag.IsConstrained) and (InnerTag.TagId = SB_ASN1_A0))) and
    (not ((not InnerTag.IsConstrained) and (InnerTag.TagId = $80))) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ENVELOPED_DATA_CONTENT;
    Exit;
  end;
  if InnerTag.IsConstrained then
  begin
    for I := 0 to TElASN1ConstrainedTag(InnerTag).Count - 1 do
    begin
      if (TElASN1ConstrainedTag(InnerTag).GetField(I).IsConstrained) or
        (TElASN1ConstrainedTag(InnerTag).GetField(I).TagId <> SB_ASN1_OCTETSTRING) then
      begin
        Result := SB_PKCS7_ERROR_INVALID_ENVELOPED_DATA_CONTENT;
        Exit;
      end;
      EncryptedContent.AddContentPart(TElASN1SimpleTag(TElASN1ConstrainedTag(InnerTag).GetField(I)).DataSource);
    end;
  end
  else
  begin
    EncryptedContent.AddContentPart(TElASN1SimpleTag(InnerTag).DataSource);
  end;
  Result := 0;
end;

function TElPKCS7Message.ProcessSignerInfos(Tag : TElASN1CustomTag; SignerList :
  TElList) : integer;
var
  I : integer;
  SignerInfo : TElPKCS7Signer;
begin
  if (not Tag.IsConstrained) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNER_INFOS;
    Exit;
  end;
  if not Assigned(SignerList) then
  begin
    Result := SB_PKCS7_ERROR_INTERNAL_ERROR;
    Exit;
  end;
  Result := 0;
  for I := 0 to TElASN1ConstrainedTag(Tag).Count - 1 do
  begin
    SignerInfo := TElPKCS7Signer.Create;
    SignerList.Add(SignerInfo);
    Result := ProcessSignerInfo(TElASN1ConstrainedTag(Tag).GetField(I),
      SignerInfo);
    if Result <> 0 then
      Break;
  end;
end;

function ProcessSignerInfo(Tag : TElASN1CustomTag; SignerInfo :
  TElPKCS7Signer) : integer;
var
  CurrentTagIndex, Sz : integer;
  Buf : ByteArray;
  procedure AppendTagToArchivalEncodedValue(CustomTag : TElASN1CustomTag);
  begin
    Sz := 0;
    CustomTag.SaveToBuffer( nil , Sz);
    SetLength(Buf, Sz);
    CustomTag.SaveToBuffer( @Buf[0] , Sz);
    SetLength(Buf, Sz);
    SignerInfo.FArchivalEncodedValue := SBConcatArrays(SignerInfo.FArchivalEncodedValue, Buf);
  end;

  procedure AppendAttributeToArchivalEncodedValue(const AttrOID, AttrValue : ByteArray);
  var
    CustomTag : TElASN1SimpleTag;
    Buffer : ByteArray;
  begin
    CustomTag := TElASN1SimpleTag.CreateInstance();
    try
      // hashing attribute object id
      CustomTag.Content := AttrOID;
      CustomTag.TagID := SB_ASN1_OBJECT;
      Sz := 0;
      CustomTag.SaveToBuffer( nil , Sz);
      SetLength(Buffer, Sz);
      CustomTag.SaveToBuffer( @Buffer[0] , Sz);
      SetLength(Buffer, Sz);
      SignerInfo.FArchivalEncodedValue := SBConcatArrays(SignerInfo.FArchivalEncodedValue, Buffer);
      // hashing attribute value
      CustomTag.Content := CloneArray(AttrValue);
      CustomTag.TagID := SB_ASN1_SET;
      Sz := 0;
      CustomTag.SaveToBuffer( nil , Sz);
      SetLength(Buffer, Sz);
      CustomTag.SaveToBuffer( @Buffer[0] , Sz);
      SetLength(Buffer, Sz);
      SignerInfo.FArchivalEncodedValue := SBConcatArrays(SignerInfo.FArchivalEncodedValue, Buffer);

    finally
      FreeAndNil(CustomTag);
    end;
  end;

  procedure Clear;
  begin
    SignerInfo.FVersion := 0;
    SignerInfo.FIssuer.Issuer.Clear;
    SignerInfo.FIssuer.SerialNumber := EmptyArray;
    SignerInfo.FIssuer.SubjectKeyIdentifier := EmptyArray;
    SignerInfo.FDigestAlgorithm := EmptyArray;
    SignerInfo.FDigestAlgorithmParams := EmptyArray;
    SignerInfo.FAuthenticatedAttributes.Count := 0;
    SignerInfo.FUnauthenticatedAttributes.Count := 0;
    SignerInfo.FDigestEncryptionAlgorithm := EmptyArray;
    SignerInfo.FDigestEncryptionAlgorithmParams := EmptyArray;;
    SignerInfo.FEncryptedDigest := EmptyArray;
    SignerInfo.FAuthenticatedAttributesPlain := EmptyArray;
    SignerInfo.FContent := EmptyArray;
    SignerInfo.FEncodedValue := EmptyArray;
    SignerInfo.FArchivalEncodedValue := EmptyArray;
  end;

begin
  Clear;
  Sz := 0;
  Tag.SaveToBuffer( nil , Sz);
  SetLength(Buf, Sz);
  Tag.SaveToBuffer( @Buf[0] , Sz);
  SetLength(Buf, Sz);
  SignerInfo.FEncodedValue := CloneArray(Buf);
  SignerInfo.FAuthenticatedAttributes.Count := 0;
  SignerInfo.FUnauthenticatedAttributes.Count := 0;
  SignerInfo.FArchivalEncodedValue := EmptyArray;
  if (not Tag.IsConstrained) or (Tag.TagId <> SB_ASN1_SEQUENCE) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNER_INFO;
    Exit;
  end;
  if TElASN1ConstrainedTag(Tag).Count < 5 then
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNER_INFO;
    Exit;
  end;
  if (TElASN1ConstrainedTag(Tag).GetField(0).IsConstrained) or
    (TElASN1ConstrainedTag(Tag).GetField(0).TagId <> SB_ASN1_INTEGER) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNER_INFO;
    Exit;
  end;
  if (not CompareContent(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(0)).Content,
    GetByteArrayFromByte(1))) and (not CompareContent(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(0)).Content,
    GetByteArrayFromByte(3))) and (not CompareContent(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(0)).Content,
    GetByteArrayFromByte(0))) { ComodoCA incorrectly supplies us with 0th version }
  then
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNER_INFO_VERSION;
    Exit;
  end;
  AppendTagToArchivalEncodedValue(TElASN1ConstrainedTag(Tag).GetField(0));
  Sz := 0;
  Tag.SaveToBuffer(nil, Sz);
  SetLength(SignerInfo.FContent, Sz);
  Tag.SaveToBuffer(SignerInfo.FContent, Sz);
  SetLength(SignerInfo.FContent, Sz);
  Result := -1;
  if CompareContent(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(0)).Content, GetByteArrayFromByte(1)) or
    CompareContent(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(0)).Content, GetByteArrayFromByte(0)) { Again ComodoCA issue }
  then
  begin
    SignerInfo.FVersion := 1;
    Result := ProcessIssuerAndSerialNumber(TElASN1ConstrainedTag(Tag).GetField(1),
      SignerInfo.FIssuer);
  end
  else
  if TElASN1ConstrainedTag(Tag).GetField(1).CheckType($80, false) then
  begin
    SignerInfo.FVersion := 3;
    SignerInfo.FIssuer.SubjectKeyIdentifier := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(1)).Content;
    SignerInfo.FIssuer.IssuerType := itSubjectKeyIdentifier;
    Result := 0;
  end;
  if Result <> 0 then
    Exit;
  AppendTagToArchivalEncodedValue(TElASN1ConstrainedTag(Tag).GetField(1));
  { Processing DigestAlgorithmIdentifier }
  Result := ProcessAlgorithmIdentifier(TElASN1ConstrainedTag(Tag).GetField(2),
    SignerInfo.FDigestAlgorithm, SignerInfo.FDigestAlgorithmParams {$ifndef HAS_DEF_PARAMS}, False {$endif});
  if Result <> 0 then
    Exit;
  AppendTagToArchivalEncodedValue(TElASN1ConstrainedTag(Tag).GetField(2));
  CurrentTagIndex := 3;
  { Checking authenticated attributes }
  if (TElASN1ConstrainedTag(Tag).GetField(3).IsConstrained) and
    (TElASN1ConstrainedTag(Tag).GetField(3).TagId = SB_ASN1_A0) then
  begin
    Result := ProcessAttributes(TElASN1ConstrainedTag(Tag).GetField(3),
      SignerInfo.FAuthenticatedAttributes);
    if Result <> 0 then
      Exit;
    Sz := 0;

    TElASN1ConstrainedTag(Tag).GetField(3).SaveToBuffer(nil, Sz);
    SetLength(SignerInfo.FAuthenticatedAttributesPlain, Sz);
    TElASN1ConstrainedTag(Tag).GetField(3).SaveToBuffer(
      @SignerInfo.FAuthenticatedAttributesPlain[0], Sz);
    SignerInfo.FAuthenticatedAttributesPlain[0] := byte(SB_ASN1_SET);

    CurrentTagIndex := 4;
    AppendTagToArchivalEncodedValue(TElASN1ConstrainedTag(Tag).GetField(3));
  end;
  { Processing DigestEncryptionAlgorithmIdentifier }
  Result := ProcessAlgorithmIdentifier(TElASN1ConstrainedTag(Tag).GetField(
    CurrentTagIndex), SignerInfo.FDigestEncryptionAlgorithm,
    SignerInfo.FDigestEncryptionAlgorithmParams {$ifndef HAS_DEF_PARAMS}, False {$endif});
  if Result <> 0 then
    Exit;
  SignerInfo.FWriteNullInDigestEncryptionAlgID := TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(CurrentTagIndex)).Count > 1;
  AppendTagToArchivalEncodedValue(TElASN1ConstrainedTag(Tag).GetField(CurrentTagIndex));
  Inc(CurrentTagIndex);
  if CurrentTagIndex >= TElASN1ConstrainedTag(Tag).Count then
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNER_INFO;
    Exit;
  end;
  { Processing EncryptedDigest }
  if (TElASN1ConstrainedTag(Tag).GetField(CurrentTagIndex).IsConstrained) or
    (TElASN1ConstrainedTag(Tag).GetField(CurrentTagIndex).TagId <> SB_ASN1_OCTETSTRING) then
  begin
    Result := SB_PKCS7_ERROR_INVALID_SIGNER_INFO;
    Exit;
  end;
  SignerInfo.FEncryptedDigest := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag).GetField(CurrentTagIndex)).Content;
  AppendTagToArchivalEncodedValue(TElASN1ConstrainedTag(Tag).GetField(CurrentTagIndex));
  Inc(CurrentTagIndex);
  if CurrentTagIndex >= TElASN1ConstrainedTag(Tag).Count then
  begin
    Result := 0;
    Exit;
  end;
  { Processing unauthenticated attributes }
  if (TElASN1ConstrainedTag(Tag).GetField(CurrentTagIndex).IsConstrained) and
    (TElASN1ConstrainedTag(Tag).GetField(CurrentTagIndex).TagId = SB_ASN1_A1) then
  begin
    Result := ProcessAttributes(TElASN1ConstrainedTag(Tag).GetField(CurrentTagIndex),
      SignerInfo.FUnauthenticatedAttributes);
    if Result <> 0 then
      Exit;
  end;
  Result := 0;
end;

procedure TElPKCS7Message.ProcessCertificates(Tag : TElASN1ConstrainedTag; Storage :
  TElCustomCertStorage);
var
  I, Size : integer;
  CertBuf : ByteArray;
  Cert : TElX509Certificate;
begin
  while Storage.Count > 0 do
    Storage.Remove(0);
  Cert := TElX509Certificate.Create(nil);
  for I := 0 to Tag.Count - 1 do
  begin
    Size := 0;
    try
      Tag.GetField(I).SaveToBuffer(nil, Size);
      SetLength(CertBuf, Size);
      Tag.GetField(I).SaveToBuffer(@CertBuf[0], Size);
      Cert.LoadFromBuffer(@CertBuf[0], Word(Size));
      Storage.Add(Cert{$ifndef HAS_DEF_PARAMS}, true {$endif});
    except
      ; // just ignoring invalid certificate
    end;
  end;
  FreeAndNil(Cert);
end;

procedure TElPKCS7Message.ProcessCRLs(Tag : TElASN1ConstrainedTag; Storage :
  TElMemoryCRLStorage{$ifndef SB_NO_OCSP}; OcspStorage : TElOCSPResponseStorage {$endif});
var
  Crl : TElCertificateRevocationList;
  I : integer;
  Size : integer;
  CertBuf : ByteArray;
  CTag : TElASN1ConstrainedTag;
  {$ifndef SB_NO_OCSP}
  Resp : TElOCSPResponse;
   {$endif}
begin
  Storage.Clear;
  Crl := TElCertificateRevocationList.Create(nil);
  try
    for I := 0 to Tag.Count - 1 do
    begin
      if Tag.GetField(I).CheckType(SB_ASN1_SEQUENCE, true) then
      begin
        // Crl
        Size := 0;
        try
          Tag.GetField(I).SaveToBuffer(nil, Size);
          SetLength(CertBuf, Size);
          Tag.GetField(I).SaveToBuffer(@CertBuf[0], Size);
          Crl.LoadFromBuffer(@CertBuf[0], Word(Size));
          Storage.Add(Crl);
        except
          ; // just ignoring invalid certificate
        end;
      end
      else if Tag.GetField(I).CheckType(SB_ASN1_A1, true) then
      begin
        // Other
        {$ifndef SB_NO_OCSP}
        CTag := TElASN1ConstrainedTag(Tag.GetField(I));
        if (CTag.Count = 2) and (CTag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) and
          (CompareContent(TElASN1SimpleTag(CTag.GetField(0)).Content, SB_OID_OCSP_RESPONSE)) and
          (OcspStorage <> nil) then
        begin
          // 1.3.6.1.5.5.7.16.2
          // OCSP response
          Size := 0;
          CTag.GetField(1).SaveToBuffer( nil , Size);
          SetLength(CertBuf, Size);
          CTag.GetField(1).SaveToBuffer( @CertBuf[0] , Size);
          SetLength(CertBuf, Size);
          Resp := TElOCSPResponse.Create();
          try
            Resp.Load( @CertBuf[0] , Size);
            OcspStorage.Add(Resp);
          finally
            FreeAndNil(Resp);
          end;
        end
        else if (CTag.Count = 2) and (CTag.GetField(0).CheckType(SB_ASN1_OBJECT, false)) and
          (CompareContent(TElASN1SimpleTag(CTag.GetField(0)).Content, SB_OCSP_OID_BASIC_RESPONSE)) and
          (OcspStorage <> nil) then
        begin
          // basic OCSP response
          Size := 0;
          CTag.GetField(1).SaveToBuffer( nil , Size);
          SetLength(CertBuf, Size);
          CTag.GetField(1).SaveToBuffer( @CertBuf[0] , Size);
          SetLength(CertBuf, Size);
          Resp := TElOCSPResponse.Create();
          try
            Resp.Load( @CertBuf[0] , Size);
            OcspStorage.Add(Resp);
          finally
            FreeAndNil(Resp);
          end;
        end;
         {$endif} 
      end
    end;
  finally
    FreeAndNil(Crl);
  end;
end;

function ProcessAttributes(Tag : TElASN1CustomTag; Attributes :
  TElPKCS7Attributes) : integer;
var
  I, J, Sz : integer;
  Buf : ByteArray;
  RawBuf : ByteArray;
  CTag : TElASN1ConstrainedTag;
begin
  Attributes.Count := 0;
  if not Tag.IsConstrained then
  begin
    Result := SB_PKCS7_ERROR_INVALID_ATTRIBUTES;
    Exit;
  end;
  for I := 0 to TElASN1ConstrainedTag(Tag).Count - 1 do
  begin
    if (not TElASN1ConstrainedTag(Tag).GetField(I).IsConstrained) or
      (TElASN1ConstrainedTag(Tag).GetField(I).TagId <> SB_ASN1_SEQUENCE) then
    begin
      Result := SB_PKCS7_ERROR_INVALID_ATTRIBUTES;
      Exit;
    end;
    CTag := TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag).GetField(I));
    Sz := 0;
    CTag.SaveToBuffer(nil, Sz);
    SetLength(RawBuf, Sz);
    CTag.SaveToBuffer(@RawBuf[0], Sz);
    if (CTag.GetField(0).IsConstrained) or (CTag.GetField(0).TagId <>
      SB_ASN1_OBJECT) then
    begin
      Result := SB_PKCS7_ERROR_INVALID_ATTRIBUTES;
      Exit;
    end;
    if (not CTag.GetField(1).IsConstrained) or (CTag.GetField(1).TagId <>
      SB_ASN1_SET) then
    begin
      Result := SB_PKCS7_ERROR_INVALID_ATTRIBUTES;
      Exit;
    end;
    Attributes.Count := I + 1;
    Attributes.Attributes[I] := CloneArray(TElASN1SimpleTag(CTag.GetField(0)).Content);
    Attributes.RawAttributeSequences[I] := CloneArray(RawBuf);
    CTag := TElASN1ConstrainedTag(CTag.GetField(1));
    for J := 0 to CTag.Count - 1 do
    begin
      Sz := 0;
      CTag.GetField(J).SaveToBuffer(nil, Sz);
      SetLength(Buf, Sz);
      CTag.GetField(J).SaveToBuffer(@Buf[0], Sz);
      Attributes.Values[I].Add(Buf);
    end;
  end;
  ReleaseArrays(Buf, RawBuf);
  Result := 0;
end;

procedure TElPKCS7Message.SaveEnvelopedData(Tag : TElASN1ConstrainedTag);
var
  STag : TElASN1SimpleTag;
  CTag, InnerSeq, OtherInnerSeq : TElASN1ConstrainedTag;
  I : integer;
  EntityBuf : ByteArray;
  CertSz : integer;
  CRLSz : integer;
begin
  { Adding EnvelopedData sequence }
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  CTag.TagId := SB_ASN1_SEQUENCE;
  CTag.UndefSize := FUseUndefSize;
  { Writing version }
  STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;
  STag.Content := GetByteArrayFromByte(FEnvelopedData.Version);
  { Optionally writing OriginatorInfo }
  if (FEnvelopedData.FOriginatorCertificates.Count > 0) or (FEnvelopedData.FOriginatorCRLs.Count > 0) then
  begin
    InnerSeq := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
    InnerSeq.TagID := SB_ASN1_A0;
    if (FEnvelopedData.FOriginatorCertificates.Count > 0) then
    begin
      OtherInnerSeq := TElASN1ConstrainedTag(InnerSeq.GetField(InnerSeq.AddField(true)));
      OtherInnerSeq.TagID := SB_ASN1_A0;
      for I := 0 to FEnvelopedData.FOriginatorCertificates.Count - 1 do
      begin
        CertSz := 0;
        FEnvelopedData.FOriginatorCertificates.Certificates[I].SaveToBuffer( nil , CertSz);
        SetLength(EntityBuf, CertSz);
        FEnvelopedData.FOriginatorCertificates.Certificates[I].SaveToBuffer( @EntityBuf[0] , CertSz);
        SetLength(EntityBuf, CertSz);
        STag := TElASN1SimpleTag(OtherInnerSeq.GetField(OtherInnerSeq.AddField(false)));
        STag.WriteHeader := false;
        STag.Content := CloneArray(EntityBuf);
      end;
    end;
    if (FEnvelopedData.FOriginatorCRLs.Count > 0) then
    begin
      OtherInnerSeq := TElASN1ConstrainedTag(InnerSeq.GetField(InnerSeq.AddField(true)));
      OtherInnerSeq.TagID := SB_ASN1_A1;
      for I := 0 to FEnvelopedData.FOriginatorCRLs.Count - 1 do
      begin
        CRLSz := 0;
        FEnvelopedData.FOriginatorCRLs.CRLs[I].SaveToBuffer( nil , CRLSz);
        SetLength(EntityBuf, CRLSz);
        FEnvelopedData.FOriginatorCRLs.CRLs[I].SaveToBuffer( @EntityBuf[0] , CRLSz);
        SetLength(EntityBuf, CRLSz);
        STag := TElASN1SimpleTag(OtherInnerSeq.GetField(OtherInnerSeq.AddField(false)));
        STag.WriteHeader := false;
        STag.Content := CloneArray(EntityBuf);
      end;
    end;
  end;
  { Writing RecipientInfos }
  SaveRecipientInfos(TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true))),
    FEnvelopedData.FRecipientList);
  { Writing EncryptedContentInfo }
  SaveEncryptedContentInfo(TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true))),
    FEnvelopedData.FEncryptedContent);
  { Optionally writing UnprotectedAttrs }
  if FEnvelopedData.FUnprotectedAttributes.Count > 0 then
  begin
    InnerSeq := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
    SaveAttributes(InnerSeq, FEnvelopedData.FUnprotectedAttributes);
    InnerSeq.TagId := SB_ASN1_A1;
  end;
end;

procedure TElPKCS7Message.SaveCompressedData(Tag : TElASN1ConstrainedTag);
var
  CTag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
begin
  { adding compressed data sequence }
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  CTag.TagId := SB_ASN1_SEQUENCE;
  CTag.UndefSize := FUseUndefSize;
  { version }
  CTag.AddField(false);
  TElASN1SimpleTag(CTag.GetField(0)).TagId := SB_ASN1_INTEGER;
  TElASN1SimpleTag(CTag.GetField(0)).Content := GetByteArrayFromByte(0);
  { compression algorithm identifier }
  CTag.AddField(true);
  TElASN1ConstrainedTag(CTag.GetField(1)).TagId := SB_ASN1_SEQUENCE;
  TElASN1ConstrainedTag(CTag.GetField(1)).AddField(false);
  TElASN1SimpleTag(TElASN1ConstrainedTag(CTag.GetField(1)).GetField(0)).TagId := SB_ASN1_OBJECT;
  TElASN1SimpleTag(TElASN1ConstrainedTag(CTag.GetField(1)).GetField(0)).Content := SB_OID_PKCS7_COMPRESSION_ZLIB;
  { compressed data sequence }
  CTag.AddField(true);
  CTag := TElASN1ConstrainedTag(CTag.GetField(2));
  CTag.TagId := SB_ASN1_SEQUENCE;
  CTag.UndefSize := FUseUndefSize;

  { compressed data content type }
  STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
  STag.TagId := SB_ASN1_OBJECT;
  if Length(FCompressedData.ContentType) > 0 then
    STag.Content := CloneArray(FCompressedData.ContentType)
  else
    STag.Content := SB_OID_PKCS7_DATA;

  { compressed data itself }
  CTag := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
  CTag.TagId := SB_ASN1_A0;
  CTag.UndefSize := FUseUndefSize;
  STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));

  if CompressedData.FragmentSize > 0 then
  begin
    { using 'constrained' fragmentation }
    STag.TagId := SB_ASN1_OCTETSTRING or SB_ASN1_CONSTRAINED_FLAG;
    STag.FragmentSize := CompressedData.FragmentSize;
  end
  else
    STag.TagId := SB_ASN1_OCTETSTRING;

  if CompressedData.DataSource = nil then
    STag.Content := CloneArray(CompressedData.CompressedContent)
  else
    CompressedData.DataSource.Clone(STag.DataSource);
end;

procedure TElPKCS7Message.SaveTimestampedData(Tag : TElASN1ConstrainedTag);
var
  CTag, CSubTag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  i : integer;
begin
  { adding timestamped data sequence }
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  CTag.TagId := SB_ASN1_SEQUENCE;
  CTag.UndefSize := FUseUndefSize;

  { adding version }
  STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
  ASN1WriteInteger(STag, 1);

  { adding data URI if any }
  if Length(FTimestampedData.DataURI) > 0 then
  begin
    STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
    STag.TagId := SB_ASN1_IA5STRING;
    STag.Content := FTimestampedData.DataURI;
  end;

  { adding metaData if needed}
  if (FTimestampedData.MetaDataAvailable) then
  begin
    CSubTag := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
    CSubTag.TagId := SB_ASN1_SEQUENCE;

    { hash protected }
    STag := TElASN1SimpleTag(CSubTag.GetField(CSubTag.AddField(false)));
    ASN1WriteBoolean(STag, FTimestampedData.HashProtected);

    { file name }
    if Length(FTimestampedData.FileName) > 0 then
    begin
      STag := TElASN1SimpleTag(CSubTag.GetField(CSubTag.AddField(false)));
      STag.TagId := SB_ASN1_UTF8STRING;
      STag.Content := FTimestampedData.FileName;
    end;

    { media type }
    if Length(FTimestampedData.MediaType) > 0 then
    begin
      STag := TElASN1SimpleTag(CSubTag.GetField(CSubTag.AddField(false)));
      STag.TagId := SB_ASN1_IA5STRING;
      STag.Content := FTimestampedData.MediaType;
    end;
  end;

  { content }
  if (TimestampedData.DataSource <> nil) or (Length(TimestampedData.Content) > 0) then
  begin
    STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
    STag.TagId := SB_ASN1_OCTETSTRING;

    if TimestampedData.DataSource = nil then
      STag.Content := CloneArray(TimestampedData.Content)
    else
      TimestampedData.DataSource.Clone(STag.DataSource);
  end;

  { temporal evidence }
  CTag := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
  CTag.TagId := SB_ASN1_A0;

  { timestamps }
  for i := 0 to TimestampedData.TimestampCount - 1 do
  begin
    { outer sequence for TimestampAndCRL }
    CSubTag := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
    CSubTag.TagId := SB_ASN1_SEQUENCE;

    { inner sequence for Timestamp's SignedData }
    STag := TElASN1SimpleTag(CSubTag.GetField(CSubTag.AddField(false)));
    STag.WriteHeader := false;
    STag.Content := TimestampedData.Timestamps[i].EncodedTimestamp;


    { inner sequence for Timestamp's CRL }
    if Length(TimestampedData.Timestamps[i].EncodedCRL) > 0 then
    begin
      STag := TElASN1SimpleTag(CSubTag.GetField(CSubTag.AddField(false)));
      STag.WriteHeader := false;
      STag.Content := TimestampedData.Timestamps[i].EncodedCRL;
    end;
  end;
end;

procedure TElPKCS7Message.SaveRecipientInfos(Tag : TElASN1ConstrainedTag;
  RecipientList : TElList);
var
  I : integer;
  CTag : TElASN1ConstrainedTag;
begin
  Tag.TagId := SB_ASN1_SET;
  for I := 0 to RecipientList.Count - 1 do
  begin
    CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    SaveRecipientInfo(CTag, TElPKCS7Recipient(RecipientList[I]));
  end;
end;

procedure TElPKCS7Message.SaveRecipientInfo(Tag : TElASN1ConstrainedTag; Recipient :
  TElPKCS7Recipient);
var
  CTag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
begin
  Tag.TagId := SB_ASN1_SEQUENCE;
  { writing version }
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;
  STag.Content := GetByteArrayFromByte(0);

  { writing IssuerAndSerialNumber }
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  SaveIssuerAndSerialNumber(CTag, Recipient.FIssuer);
  { writing KeyEncryptionAlgorithm }
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  SaveAlgorithmIdentifier(CTag, Recipient.FKeyEncryptionAlgorithm,
    Recipient.FKeyEncryptionAlgorithmParams {$ifndef HAS_DEF_PARAMS}, 0 {$endif});
  { writing EncryptedKey }
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_OCTETSTRING;
  STag.Content := CloneArray(Recipient.FEncryptedKey);
end;

procedure TElPKCS7Message.SaveEncryptedContentInfo(Tag : TElASN1ConstrainedTag;
  EncryptedContent : TElPKCS7EncryptedContent);
var
  CTag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
begin
  Tag.TagId := SB_ASN1_SEQUENCE;
  Tag.UndefSize := FUseUndefSize;
  { Writing ContentType }
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_OBJECT;
  STag.Content := CloneArray(EncryptedContent.FContentType);
  { Writing contentEncryptionAlgorithm }
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  CTag.TagId := SB_ASN1_SEQUENCE;
  SaveAlgorithmIdentifier(CTag, EncryptedContent.FContentEncryptionAlgorithm,
    EncryptedContent.FContentEncryptionAlgorithmParams {$ifndef HAS_DEF_PARAMS}, 0 {$endif});
  { Writing EncryptedContent }
  if not EncryptedContent.FUseImplicitContentEncoding then
  begin
    CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    CTag.TagId := SB_ASN1_A0;
    CTag.UndefSize := FUseUndefSize;
    STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
    STag.TagId := SB_ASN1_OCTETSTRING;
  end
  else
  begin
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.TagId := $80;
  end;
  if EncryptedContent.DataSource = nil then
    STag.Content := CloneArray(EncryptedContent.EncryptedContent)
  else
    EncryptedContent.DataSource.Clone(STag.DataSource);
end;

procedure TElPKCS7Message.SaveSignedData(Tag : TElASN1ConstrainedTag);
var
  STag : TElASN1SimpleTag;
  CTag, CTagSeq : TElASN1ConstrainedTag;
  Lst : TElByteArrayList;
  TmpBuf : ByteArray;
  Buf : ByteArray;
  I : integer;
  //Content : ByteArray;
begin
  Tag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  Tag.TagId := SB_ASN1_SEQUENCE;
  Tag.UndefSize := FUseUndefSize;
  { Writing version }
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;
  STag.Content := GetByteArrayFromByte(FSignedData.Version);

  { Writing digestAlgorithms }
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  CTag.TagId := SB_ASN1_SET;

  Lst := TElByteArrayList.Create;
  try
    for I := 0 to FSignedData.SignerCount - 1 do
    begin
      if Lst.IndexOf(FSignedData.Signers[I].FDigestAlgorithm) = -1 then
        Lst.Add(FSignedData.Signers[I].FDigestAlgorithm);
    end;
    for I := 0 to Lst.Count - 1 do
    begin
      CTagSeq := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
      SetLength(TmpBuf, 0);
      SaveAlgorithmIdentifier(CTagSeq, Lst.Item[I], TmpBuf {$ifndef HAS_DEF_PARAMS}, 0 {$endif});
    end;
  finally
    FreeAndNil(Lst);
  end;

  { Writing contentInfo }
  if (not SignedData.PreserveCachedContent) or (Length(SignedData.RawMultipartContent) = 0) then
  begin
    CTagSeq := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    CTagSeq.TagId := SB_ASN1_SEQUENCE;

    STag := TElASN1SimpleTag(CTagSeq.GetField(CTagSeq.AddField(false)));
    STag.TagId := SB_ASN1_OBJECT;
    if Length(FSignedData.FContentType) > 0  then
      STag.Content := CloneArray(FSignedData.FContentType)
    else
      STag.Content := SB_OID_PKCS7_DATA;
    if FSignedData.DataSource.Size > 0 then
    begin
      if FUseImplicitContent then
      begin
        STag := TElASN1SimpleTag(CTagSeq.GetField(CTagSeq.AddField(False)));
        STag.TagId := SB_ASN1_A0;
        FSignedData.DataSource.Clone(STag.DataSource);
      end
      else
      begin
        CTag := TElASN1ConstrainedTag(CTagSeq.GetField(CTagSeq.AddField(true)));
        CTag.TagId := SB_ASN1_A0;
        CTag.UndefSize := FUseUndefSize; // II 20071108
        STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
        STag.TagId := SB_ASN1_OCTETSTRING;
        FSignedData.DataSource.Clone(STag.DataSource);
      end;
      CTagSeq.UndefSize := FUseUndefSize; // II 20071108
    end
    else
    begin
      CTagSeq.UndefSize := FUseUndefSize;
    end;
  end
  else
  begin
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.WriteHeader := false;
    SetLength(Buf, Length(FSignedData.EnvelopedContentPrefix) + Length(FSignedData.RawMultipartContent) +
      Length(FSignedData.EnvelopedContentPostfix));
    SBMove(FSignedData.FEnvelopedContentPrefix[0], Buf[0],
      Length(FSignedData.FEnvelopedContentPrefix));
    SBMove(FSignedData.RawMultipartContent[0], Buf[0 + Length(FSignedData.FEnvelopedContentPrefix)],
      Length(FSignedData.RawMultipartContent));
    SBMove(FSignedData.FEnvelopedContentPostfix[0],
      Buf[0 + Length(FSignedData.FEnvelopedContentPrefix) + Length(FSignedData.RawMultipartContent)],
      Length(FSignedData.FEnvelopedContentPostfix));
    STag.Content := Buf;
  end;

  { Writing certificates }
  if (not SignedData.PreserveCachedElements) or (Length(SignedData.FEncodedCertificates) = 0) then
  begin
    if FSignedData.FCertStorage.Count > 0 then
    begin
      CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
      SaveCertificates(FSignedData.FCertStorage, CTag);
      CTag.TagId := SB_ASN1_A0;
    end;
  end
  else
  begin
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.WriteHeader := false;
    STag.Content := SignedData.FEncodedCertificates;
  end;
  { Writing CRLs }
  if (not SignedData.PreserveCachedElements) or (Length(SignedData.FEncodedCRLs) = 0) then
  begin
    if (FSignedData.FCRLStorage.Count > 0) {$ifndef SB_NO_OCSP}or (FSignedData.FOCSPStorage.Count > 0)  {$endif}then
    begin
      CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
      SaveCRLs(FSignedData.FCRLStorage, {$ifndef SB_NO_OCSP}FSignedData.FOCSPStorage,  {$endif}CTag);
      CTag.TagId := SB_ASN1_A1;
    end;
  end
  else
  begin
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.WriteHeader := false;
    STag.Content := SignedData.FEncodedCRLs;
  end;
  { Writing signerInfos }
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  SaveSignerInfos(CTag, FSignedData.FSignerList);
end;

procedure TElPKCS7Message.SaveCertificates(Storage : TElCustomCertStorage; Tag :
  TElASN1ConstrainedTag);
var
  I : integer;
  STag : TElASN1SimpleTag;
  TmpS : ByteArray;
begin
  for I := 0 to Storage.Count - 1 do
  begin
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.WriteHeader := false;
    SetLength(TmpS, Storage.Certificates[I].CertificateSize);
    SBMove(Storage.Certificates[I].CertificateBinary^, TmpS[0], Length(TmpS));
    STag.Content := CloneArray(TmpS);
  end;
end;

procedure TElPKCS7Message.SaveCRLs(Storage : TElCustomCRLStorage; {$ifndef SB_NO_OCSP}OcspStorage :
  TElOCSPResponseStorage;  {$endif}Tag : TElASN1ConstrainedTag);
var
  I : integer;
  STag : TElASN1SimpleTag;
  CTag : TElASN1ConstrainedTag;
  CrlBuf : ByteArray;
  CrlSize : integer;
begin
  for I := 0 to Storage.Count - 1 do
  begin
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.WriteHeader := false;
    CrlSize := 0;
    Storage.CRLs[I].SaveToBuffer( nil , CrlSize);
    SetLength(CrlBuf, CrlSize);
    Storage.CRLs[I].SaveToBuffer( @CrlBuf[0] , CrlSize);
    SetLength(CrlBuf, CrlSize);
    STag.Content := CloneArray(CrlBuf);
  end;
  {$ifndef SB_NO_OCSP}
  if OcspStorage <> nil then
  begin
    for I := 0 to OcspStorage.Count - 1 do
    begin
      CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
      CTag.TagID := SB_ASN1_A1;
      STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
      STag.TagID := SB_ASN1_OBJECT;
      STag.Content := SB_OID_OCSP_RESPONSE;
      STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
      STag.WriteHeader := false;
      CrlSize := 0;
      OcspStorage.Responses[I].Save( nil , CrlSize);
      SetLength(CrlBuf, CrlSize);
      OcspStorage.Responses[I].Save( @CrlBuf[0] , CrlSize);
      SetLength(CrlBuf, CrlSize);
      STag.Content := CloneArray(CrlBuf);
    end;
  end;
   {$endif}
end;

procedure TElPKCS7Message.SaveSignerInfos(Tag : TElASN1ConstrainedTag; SignerList :
  TElList);
var
  I : integer;
begin
  Tag.TagId := SB_ASN1_SET;
  for I := 0 to SignerList.Count - 1 do
  begin
    SaveSignerInfo(TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true))),
      TElPKCS7Signer(SignerList[I]));
  end;
end;

procedure SaveSignerInfo(Tag : TElASN1ConstrainedTag; Signer :
  TElPKCS7Signer);
var
  STag : TElASN1SimpleTag;
  CTag : TElASN1ConstrainedTag;
begin
  Tag.TagId := SB_ASN1_SEQUENCE;
  { Writing version }
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;
  if Signer.FIssuer.IssuerType = itIssuerAndSerialNumber then
    Signer.FVersion := 1
  else
    Signer.FVersion := 3;
  STag.Content := GetByteArrayFromByte(Byte(Signer.FVersion));
  { Writing IssuerAndSerialNumber }
  if Signer.FVersion = 1 then
  begin
    CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    SaveIssuerAndSerialNumber(CTag, Signer.FIssuer);
  end
  else
  begin
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.TagID := $80;
    STag.Content := Signer.FIssuer.SubjectKeyIdentifier;
  end;
  { Writing digestAlgorithm }
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  SaveAlgorithmIdentifier(CTag, Signer.FDigestAlgorithm, nil {$ifndef HAS_DEF_PARAMS}, 0 {$endif});
  { Writing authenticatedAttributes }
  if Signer.FAuthenticatedAttributes.Count > 0 then
  begin
    CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    SaveAttributes(CTag, Signer.FAuthenticatedAttributes);
    CTag.TagId := SB_ASN1_A0;
  end;
  { Writing digestEncryptionAlgorithm }
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  SaveAlgorithmIdentifier(CTag, Signer.FDigestEncryptionAlgorithm,
    Signer.FDigestEncryptionAlgorithmParams, 0, Signer.FWriteNullInDigestEncryptionAlgID);

  { Writing encryptedDigest }
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_OCTETSTRING;
  STag.Content := CloneArray(Signer.FEncryptedDigest);
  { Writing unauthenticatedAttributes }
  if Signer.FUnauthenticatedAttributes.Count > 0 then
  begin
    CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    SaveAttributes(CTag, Signer.FUnauthenticatedAttributes);
    CTag.TagId := SB_ASN1_A1;
  end;
end;

procedure TElPKCS7Message.SaveDigestedData(Tag : TElASN1ConstrainedTag);
var
  STag : TElASN1SimpleTag;
  CTag : TElASN1ConstrainedTag;
begin
  Tag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  Tag.TagId := SB_ASN1_SEQUENCE;
  Tag.UndefSize := FUseUndefSize;
  { Writing version }
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;
  STag.Content := GetByteArrayFromByte(Byte(FDigestedData.FVersion));
  { Writing DigestAlgorithm }
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  SaveAlgorithmIdentifier(CTag, FDigestedData.FDigestAlgorithm,
    FDigestedData.FDigestAlgorithmParams {$ifndef HAS_DEF_PARAMS}, 0 {$endif});
  { Writing ContentInfo }
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  CTag.TagId := SB_ASN1_SEQUENCE;
  STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
  STag.TagId := SB_ASN1_OBJECT;
  STag.Content := SB_OID_PKCS7_DATA;
  CTag := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
  CTag.TagId := SB_ASN1_A0;
  STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
  STag.TagId := SB_ASN1_OCTETSTRING;
  STag.Content := CloneArray(FDigestedData.FContent);
  { Writing digest }
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_OCTETSTRING;
  STag.Content := CloneArray(FDigestedData.FDigest);
end;

procedure TElPKCS7Message.SaveEncryptedData(Tag : TElASN1ConstrainedTag);
var
  STag : TElASN1SimpleTag;
begin
  Tag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  Tag.TagId := SB_ASN1_SEQUENCE;
  Tag.UndefSize := FUseUndefSize;
  { Writing version }
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;
  STag.Content := GetByteArrayFromByte(FEncryptedData.FVersion);
  { Writing encryptedContentInfo }
  SaveEncryptedContentInfo(TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true))),
    FEncryptedData.FEncryptedContent);
end;

procedure TElPKCS7Message.SaveSignedAndEnvelopedData(Tag : TElASN1ConstrainedTag);
var
  STag : TElASN1SimpleTag;
  CTag, CTagSeq : TElASN1ConstrainedTag;
  Lst : TElByteArrayList;
  I : integer;
begin
  Tag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  Tag.TagId := SB_ASN1_SEQUENCE;
  Tag.UndefSize := FUseUndefSize;
  { Writing version }
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;

  STag.Content := GetByteArrayFromByte(FSignedAndEnvelopedData.FVersion);

  { Writing recipientInfos }
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  SaveRecipientInfos(CTag, FSignedAndEnvelopedData.FRecipientList);
  { Writing digestAlgorithms }
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  CTag.TagId := SB_ASN1_SET;

  Lst := TElByteArrayList.Create;
  try
    for I := 0 to FSignedAndEnvelopedData.SignerCount - 1 do
    begin
      if Lst.IndexOf(FSignedAndEnvelopedData.Signers[I].FDigestAlgorithm) = -1 then
        Lst.Add(FSignedAndEnvelopedData.Signers[I].FDigestAlgorithm);
    end;
    for I := 0 to Lst.Count - 1 do
    begin
      CTagSeq := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
      SaveAlgorithmIdentifier(CTagSeq, Lst.Item[I], nil {$ifndef HAS_DEF_PARAMS}, 0 {$endif});
    end;
  finally
    FreeAndNil(Lst);
  end;

  { Writing encryptedContentInfo }
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  SaveEncryptedContentInfo(CTag, FSignedAndEnvelopedData.FEncryptedContent);
  { Writing certificates }
  if FSignedAndEnvelopedData.FCertStorage.Count > 0 then
  begin
    CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    CTag.TagId := SB_ASN1_A0;
    SaveCertificates(FSignedAndEnvelopedData.FCertStorage, CTag);
  end;
  { Writing signerInfos }
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  SaveSignerInfos(CTag, FSignedAndEnvelopedData.FSignerList);
end;

procedure TElPKCS7Message.SaveAuthenticatedData(Tag : TElASN1ConstrainedTag);
var
  STag : TElASN1SimpleTag;
  CTag, ConstrContentTag : TElASN1ConstrainedTag;
  I : integer;
begin
  Tag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  Tag.TagId := SB_ASN1_SEQUENCE;
  Tag.UndefSize := FUseUndefSize;
  { Writing version }
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;
  STag.Content := GetByteArrayFromByte(FSignedAndEnvelopedData.FVersion);

  { OriginatorInfo is not supported at the moment. }

  { Writing recipientInfos }
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  SaveRecipientInfos(CTag, FAuthenticatedData.FRecipientList);

  { Writing macAlgorithm }
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  SaveAlgorithmIdentifier(CTag, FAuthenticatedData.FMacAlgorithm,
    nil {$ifndef HAS_DEF_PARAMS}, 0 {$endif});

  { Writing digestAlgorithm }
  if FAuthenticatedData.FAuthenticatedAttributes.Count > 0 then
  begin
    CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    SaveAlgorithmIdentifier(CTag, FAuthenticatedData.FDigestAlgorithm, nil,
      SB_ASN1_A1);
  end;

  { Writing encapsulatedContentInfo }
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  CTag.TagId := SB_ASN1_SEQUENCE;
  STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
  STag.TagId := SB_ASN1_OBJECT;
  STag.Content := FAuthenticatedData.FContentType;
  CTag := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
  CTag.TagId := SB_ASN1_A0;
  // old version:
  //STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
  //STag.TagId := SB_ASN1_OCTETSTRING;
  //STag.Content := FAuthenticatedData.Content;
  if FAuthenticatedData.ContentPartCount <= 1 then
  begin
    STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
    STag.TagId := SB_ASN1_OCTETSTRING;
    FAuthenticatedData.DataSource.Clone(STag.DataSource);
  end
  else
  begin
    ConstrContentTag := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
    ConstrContentTag.TagId := SB_ASN1_OCTETSTRING or SB_ASN1_CONSTRAINED_FLAG;
    for I := 0 to FAuthenticatedData.ContentPartCount - 1 do
    begin
      STag := TElASN1SimpleTag(ConstrContentTag.GetField(ConstrContentTag.AddField(false)));
      STag.TagId := SB_ASN1_OCTETSTRING;
      FAuthenticatedData.ContentParts[I].Clone(STag.DataSource);
    end;
  end;
  { Writing authenticated attributes }
  if FAuthenticatedData.FAuthenticatedAttributes.Count > 0 then
  begin
    CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    SaveAttributes(CTag, FAuthenticatedData.FAuthenticatedAttributes);
    CTag.TagId := SB_ASN1_A2;
  end;

  { Writing message authentication code }
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_OCTETSTRING;
  STag.Content := FAuthenticatedData.FMac;

  { Writing unauthenticated attributes }
  if (FAuthenticatedData.FUnauthenticatedAttributes.Count > 0) then
  begin
    CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    SaveAttributes(CTag, FAuthenticatedData.FUnauthenticatedAttributes);
    CTag.TagId := SB_ASN1_A3;
  end;
end;

procedure TElPKCS7Message.SetData(const V : ByteArray);
begin
  FData := CloneArray(V);
end;

procedure TElPKCS7Message.SetCustomContentType(const V : ByteArray);
begin
  FCustomContentType := CloneArray(V);
end;

////////////////////////////////////////////////////////////////////////////////
// TElPKCS7Recipient

constructor TElPKCS7Recipient.Create;
begin
  inherited;
  FIssuer := TElPKCS7Issuer.Create;
  FKeyEncryptionAlgorithmIdentifier := nil;
end;

 destructor  TElPKCS7Recipient.Destroy;
begin
  FreeAndNil(FIssuer);
  if Assigned(FKeyEncryptionAlgorithmIdentifier) then
    FreeAndNil(FKeyEncryptionAlgorithmIdentifier);
  ReleaseArrays(FKeyEncryptionAlgorithm, FKeyEncryptionAlgorithmParams,
    FEncryptedKey);
  inherited;
end;

procedure TElPKCS7Recipient.SetKeyEncryptionAlgorithm(const V : ByteArray);
begin
  FKeyEncryptionAlgorithm := CloneArray(V);
end;

procedure TElPKCS7Recipient.SetKeyEncryptionAlgorithmParams(const V : ByteArray);
begin
  FKeyEncryptionAlgorithmParams := CloneArray(V);
end;

procedure TElPKCS7Recipient.SetEncryptedKey(const V : ByteArray);
begin
  FEncryptedKey := CloneArray(V);
end;

////////////////////////////////////////////////////////////////////////////////
// TElPKCS7EnvelopedData

constructor TElPKCS7EnvelopedData.Create;
begin
  inherited;
  FEncryptedContent := TElPKCS7EncryptedContent.Create;
  FRecipientList := TElList.Create;
  FCMSFormat := false;
  FOriginatorCertificates := TElMemoryCertStorage.Create(nil);
  FOriginatorCRLs := TElMemoryCRLStorage.Create( nil );
  FUnprotectedAttributes := TElPKCS7Attributes.Create();
end;

 destructor  TElPKCS7EnvelopedData.Destroy;
begin
  Clear;
  FreeAndNil(FRecipientList);
  FreeAndNil(FEncryptedContent);
  FreeAndNil(FOriginatorCertificates);
  FreeAndNil(FOriginatorCRLs);
  FreeAndNil(FUnprotectedAttributes);
  inherited;
end;

function TElPKCS7EnvelopedData.GetRecipient(Index : integer) : TElPKCS7Recipient;
begin
  if Index < FRecipientList.Count then
    Result := TElPKCS7Recipient(FRecipientList[Index])
  else
    Result := nil;
end;

function TElPKCS7EnvelopedData.GetRecipientCount : integer;
begin
  Result := FRecipientList.Count;
end;

procedure TElPKCS7EnvelopedData.Clear;
var
  Rec : TElPKCS7Recipient;
begin
  while FRecipientList.Count > 0 do
  begin
    Rec := TElPKCS7Recipient(FRecipientList[0]);
    FRecipientList. Delete (0);
    FreeAndNil(Rec);
  end;
  FOriginatorCertificates.Clear();
  FOriginatorCRLs.Clear();
  FUnprotectedAttributes.Count := 0;
end;

function TElPKCS7EnvelopedData.AddRecipient : integer;
begin
  Result := FRecipientList.Add(TElPKCS7Recipient.Create);
end;

function TElPKCS7EnvelopedData.RemoveRecipient(Index : integer) : boolean;
var
  Rec : TElPKCS7Recipient;
begin
  if Index < FRecipientList.Count then
  begin
    Rec := TElPKCS7Recipient(FRecipientList[Index]);
    FRecipientList.Delete(Index);
    FreeAndNil(Rec);
    Result := true;
  end
  else
    Result := false;
end;

function TElPKCS7EnvelopedData.SaveToBuffer(Buffer: pointer; var Size: integer): boolean;
var
  Tag : TElASN1ConstrainedTag;
begin
  Result := false;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    FOwner.SaveEnvelopedData(Tag);
    if Tag.Count > 0 then
      Result := Tag.GetField(0).SaveToBuffer(Buffer, Size);
  finally
    FreeAndNil(Tag);
  end;
end;


////////////////////////////////////////////////////////////////////////////////
// TElPKCS7CompressedData

constructor TElPKCS7CompressedData.Create;
begin
  inherited;
  FVersion := 0;
  FContentType := EmptyArray;
  FCompressedContentParts := TElList.Create;
  FFragmentSize := 65536;
  FOwner := nil; 
end;

 destructor  TElPKCS7CompressedData.Destroy;
begin
  ClearContentParts;
  FreeAndNil(FCompressedContentParts);
  inherited;
end;

function TElPKCS7CompressedData.SaveToBuffer(Buffer: pointer; var Size: integer): boolean;
begin
  Result := false;
end;

function TElPKCS7CompressedData.AddContentPart(DataSource : TElASN1DataSource): integer;
var
  DS : TElASN1DataSource;
begin
  DS := TElASN1DataSource.Create;
  DataSource.Clone(DS);
  Result := FCompressedContentParts.Add(DS);
end;

function TElPKCS7CompressedData.AddContentPart(const Value : ByteArray): integer;
var
  DS : TElASN1DataSource;
begin
  DS := TElASN1DataSource.Create;
  DS.Init(Value);
  Result := FCompressedContentParts.Add(DS);
end;

(*
function TElPKCS7CompressedData.AddContentPart: integer;
var
  DS : TElASN1DataSource;
begin
  DS := TElASN1DataSource.Create;
  Result := FCompressedContentParts.Add(DS);
end;
*)

procedure TElPKCS7CompressedData.ClearContentParts;
var
  I : integer;
begin
  for I := 0 to FCompressedContentParts.Count - 1 do
    TElASN1DataSource(FCompressedContentParts[I]). Free ;
  FCompressedContentParts.Clear;
end;

function TElPKCS7CompressedData.GetCompressedContentPartCount : integer;
begin
  Result := FCompressedContentParts.Count;
end;

function TElPKCS7CompressedData.GetCompressedContent : ByteArray;
var
  I : integer;
begin
  Result := EmptyArray;
  for I := 0 to FCompressedContentParts.Count - 1 do
    Result := SBConcatArrays(Result, TElASN1DataSource(FCompressedContentParts[I]).ToBuffer);
end;

procedure TElPKCS7CompressedData.SetCompressedContent(const Value: ByteArray);
begin
  ClearContentParts;
  AddContentPart(Value);
end;

function TElPKCS7CompressedData.GetDataSource : TElASN1DataSource;
begin
  if GetCompressedContentPartCount = 0 then
    FCompressedContentParts.Add(TElASN1DataSource.Create);
  Result := GetCompressedContentPart(0);
end;

function TElPKCS7CompressedData.GetCompressedContentPart(Index: integer): TElASN1DataSource;
begin
  if (Index >= 0) and (Index < FCompressedContentParts.Count) then
    Result := TElASN1DataSource(FCompressedContentParts[Index])
  else
    Result := nil;
end;

procedure TElPKCS7CompressedData.SetContentType(const V : ByteArray);
begin
  FContentType := CloneArray(V);
end;

////////////////////////////////////////////////////////////////////////////////
// TElPKCS7SignedData

constructor TElPKCS7SignedData.Create;
begin
  inherited;
  FCertStorage := TElMemoryCertStorage.Create(nil);
  FCRLStorage := TElMemoryCRLStorage.Create( nil );
  {$ifndef SB_NO_OCSP}
  FOCSPStorage := TElOCSPResponseStorage.Create();
   {$endif}

  FSignerList := TElList.Create;
  FContentParts := TElList.Create;

  FIsMultipart := false;
  SetLength(FRawMultipartContent, 0);
  FPreserveCachedContent := false;
  FPreserveCachedElements := false;
end;

 destructor  TElPKCS7SignedData.Destroy;
begin
  ClearContentParts;
  FreeAndNil(FContentParts);
  FreeAndNil(FCertStorage);
  FreeAndNil(FCRLStorage);
  {$ifndef SB_NO_OCSP}
  FreeAndNil(FOCSPStorage);
   {$endif}
  while FSignerList.Count > 0 do
  begin
    TElPKCS7Signer(FSignerList[0]). Free ;
    FSignerList. Delete (0);
  end;
  FreeAndNil(FSignerList);
  ReleaseArrays(FEncodedCertificates, FEncodedCRLs, FEnvelopedContentPrefix,
    FEnvelopedContentPostfix, FContentType, FRawMultipartContent);
  inherited;
end;

function TElPKCS7SignedData.GetSigner(Index : integer) : TElPKCS7Signer;
begin
  Result := TElPKCS7Signer(FSignerList[Index]);
end;

function TElPKCS7SignedData.GetSignerCount : integer;
begin
  Result := FSignerList.Count;
end;

function TElPKCS7SignedData.AddSigner : integer;
begin
  Result := FSignerList.Add(TElPKCS7Signer.Create);
end;

function TElPKCS7SignedData.RemoveSigner(Index : integer) : boolean;
begin
  if Index < FSignerList.Count then
  begin
    TElPKCS7Signer(FSignerList[Index]). Free ;
    FSignerList.Delete(Index);
    Result := true;
  end
  else
    Result := false;
end;

function TElPKCS7SignedData.AddContentPart(DataSource : TElASN1DataSource): integer;
var
  DS : TElASN1DataSource;
begin
  DS := TElASN1DataSource.Create;
  DataSource.Clone(DS);
  Result := FContentParts.Add(DS);
end;

function TElPKCS7SignedData.AddContentPart : integer;
begin
  Result := FContentParts.Add(TElASN1DataSource.Create);
end;

function TElPKCS7SignedData.AddContentPart(const Data : ByteArray): integer;
var
  DS : TElASN1DataSource;
begin
  DS := TElASN1DataSource.Create;
  DS.Init(Data);
  Result := FContentParts.Add(DS);
end;

function TElPKCS7SignedData.AddContentPart(Buffer: pointer; Size: integer): integer;
var
  DS : TElASN1DataSource;
begin
  DS := TElASN1DataSource.Create;
  DS.Init(Buffer, Size);
  Result := FContentParts.Add(DS);
end;

procedure TElPKCS7SignedData.ClearContentParts;
var
  I : integer;
begin
  for I := 0 to FContentParts.Count - 1 do
    TElASN1DataSource(FContentParts[I]). Free ;
  FContentParts.Clear;
end;

function TElPKCS7SignedData.GetContentPart(Index: integer): TElASN1DataSource;
begin
  Result := TElASN1DataSource(FContentParts[Index]);
end;

function TElPKCS7SignedData.GetContentPartCount : integer;
begin
  Result := FContentParts.Count;
end;

function TElPKCS7SignedData.GetContent : ByteArray;
var
  I : integer;
begin
  Result := EmptyArray;
  for I := 0 to ContentPartCount - 1 do
    Result := SBConcatArrays(Result, ContentParts[I].ToBuffer);
end;

procedure TElPKCS7SignedData.SetContent(const Value: ByteArray);
begin
  ClearContentParts;
  AddContentPart(Value);
end;

procedure TElPKCS7SignedData.SetContentType(const V : ByteArray);
begin
  FContentType := CloneArray(V);
end;

function TElPKCS7SignedData.GetDataSource : TElASN1DataSource;
begin
  if GetContentPartCount = 0 then
    FContentParts.Add(TElASN1DataSource.Create);
  Result := GetContentPart(0);
end;

function TElPKCS7SignedData.SaveToBuffer(Buffer: pointer; var Size: integer): boolean;
var
  Tag : TElASN1ConstrainedTag;
begin
  Result := false;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    FOwner.SaveSignedData(Tag);
    if Tag.Count > 0 then
      Result := Tag.GetField(0).SaveToBuffer(Buffer, Size);
  finally
    FreeAndNil(Tag);
  end;
end;


procedure TElPKCS7SignedData.SaveToStream(Stream: TStream);
var
  Tag : TElASN1ConstrainedTag;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    FOwner.SaveSignedData(Tag);
    if Tag.Count > 0 then
      Tag.GetField(0).SaveToStream(Stream);
  finally
    FreeAndNil(Tag);
  end;
end;

procedure TElPKCS7SignedData.PreSerialize(SerializeContent, SerializeCertsAndCrls : boolean);
begin
  if SerializeCertsAndCrls then
    Self.SerializeCertsAndCRLs;
  if SerializeContent then
    SerializeEnvelopedContent;
end;

procedure TElPKCS7SignedData.SerializeCertsAndCRLs;
var
  Tag : TElASN1ConstrainedTag;
  Size : integer;
  Buf : ByteArray;
begin
  if ((Length(FEncodedCertificates) > 0) or (Length(FEncodedCRLs) > 0)) and FPreserveCachedElements then
    Exit;
    
  Tag := TElASN1ConstrainedTag.CreateInstance();
  try
    // serializing certificates
    if FCertStorage.Count > 0 then
    begin
      FOwner.SaveCertificates(FCertStorage, Tag);
      Tag.TagId := SB_ASN1_A0;
      Size := 0;
      Tag.SaveToBuffer( nil , Size);
      SetLength(Buf, Size);
      Tag.SaveToBuffer( @Buf[0] , Size);
      SetLength(Buf, Size);
      FEncodedCertificates := CloneArray(Buf);
    end
    else
      FEncodedCertificates := EmptyArray;

    // serializing CRLs
    Tag.Clear;
    if FCRLStorage.Count > 0 then
    begin
      FOwner.SaveCRLs(FCRLStorage, {$ifndef SB_NO_OCSP}FOCSPStorage, {$endif} Tag);
      Tag.TagId := SB_ASN1_A1;
      Size := 0;
      Tag.SaveToBuffer( nil , Size);
      SetLength(Buf, Size);
      Tag.SaveToBuffer( @Buf[0] , Size);
      SetLength(Buf, Size);
      FEncodedCRLs := CloneArray(Buf);
    end
    else
      FEncodedCRLS := EmptyArray;
  finally
    FreeAndNil(Tag);
  end;
end;

procedure TElPKCS7SignedData.HandleContentTagContentWriteBegin(Sender: TObject);
begin
  FCurrContentSerializationStartOffset := FCurrContentSerializationStream.Position;
end;

procedure TElPKCS7SignedData.HandleContentTagContentWriteEnd(Sender: TObject);
begin
  FCurrContentSerializationEndOffset := FCurrContentSerializationStream.Position;
end;

procedure TElPKCS7SignedData.SerializeEnvelopedContent;
var
  CTagSeq, CTag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  Size : integer;
  //Buf : ByteArray;
  Prefix, Suffix : ByteArray;
begin
  CTagSeq := TElASN1ConstrainedTag.CreateInstance;
  try
    CTagSeq.TagId := SB_ASN1_SEQUENCE;

    STag := TElASN1SimpleTag(CTagSeq.GetField(CTagSeq.AddField(false)));
    STag.TagId := SB_ASN1_OBJECT;
    if Length(FContentType) > 0  then
      STag.Content := CloneArray(FContentType)
    else
      STag.Content := SB_OID_PKCS7_DATA;
    if DataSource.Size > 0 then
    begin
      if FOwner.UseImplicitContent then
      begin
        STag := TElASN1SimpleTag(CTagSeq.GetField(CTagSeq.AddField(False)));
        STag.TagId := SB_ASN1_A0;
        DataSource.CloneVirtual(STag.DataSource);
      end
      else
      begin
        CTag := TElASN1ConstrainedTag(CTagSeq.GetField(CTagSeq.AddField(true)));
        CTag.TagId := SB_ASN1_A0;
        CTag.UndefSize := FOwner.UseUndefSize; // II 20071108
        STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
        STag.TagId := SB_ASN1_OCTETSTRING;
        DataSource.CloneVirtual(STag.DataSource);
      end;
      STag.OnContentWriteBegin := HandleContentTagContentWriteBegin;
      STag.OnContentWriteEnd := HandleContentTagContentWriteEnd;
      STag.DataSource.SkipVirtualData := true;
      CTagSeq.UndefSize := FOwner.UseUndefSize; // II 20071108
      // Saving virtually to omit serialization of [potentially long] data
      FCurrContentSerializationStartOffset := 0;
      FCurrContentSerializationEndOffset := 0;
      FCurrContentSerializationStream := TElMemoryStream.Create();
      try
        CTagSeq.SaveToStream(FCurrContentSerializationStream);
        // recovering prefix and suffix
        SetLength(Prefix, FCurrContentSerializationStartOffset);
        FCurrContentSerializationStream.Position := 0;
        FCurrContentSerializationStream.Read(Prefix [0] , Length(Prefix));
        SetLength(Suffix, FCurrContentSerializationStream. Size  - FCurrContentSerializationEndOffset);
        FCurrContentSerializationStream.Position := FCurrContentSerializationEndOffset;
        FCurrContentSerializationStream.Read(Suffix [0] , Length(Suffix));
        FEnvelopedContentPrefix := CloneArray(Prefix);
        FEnvelopedContentPostfix := CloneArray(Suffix);
      finally
        FreeAndNil(FCurrContentSerializationStream);
      end;
    end
    else
    begin
      CTagSeq.UndefSize := FOwner.UseUndefSize;
      // There is no data included, so just saving the structure normally
      // and assigning it to the Prefix (it's OK for not putting trailing 00 00
      // to postfix, as in the detached case the archival timestamp first takes
      // encapContentInfo (completely) and then external data).
      Size := 0;
      CTagSeq.SaveToBuffer( nil , Size);
      SetLength(Prefix, Size);
      CTagSeq.SaveToBuffer( @Prefix[0] , Size);
      SetLength(Prefix, Size);
      FEnvelopedContentPrefix := CloneArray(Prefix);
      FEnvelopedContentPostfix := EmptyArray;
    end;
  finally
    FreeAndNil(CTagSeq);
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// TElPKCS7Signer

constructor TElPKCS7Signer.Create;
begin
  inherited;
  FAuthenticatedAttributes := TElPKCS7Attributes.Create;
  FUnauthenticatedAttributes := TElPKCS7Attributes.Create;
  FIssuer := TElPKCS7Issuer.Create;
  FWriteNullInDigestEncryptionAlgID := true;
end;

 destructor  TElPKCS7Signer.Destroy;
begin
  FreeAndNil(FAuthenticatedAttributes);
  FreeAndNil(FUnauthenticatedAttributes);
  FreeAndNil(FIssuer);
  ReleaseArrays(FDigestAlgorithm, FDigestAlgorithmParams,
    FDigestEncryptionAlgorithm, FDigestEncryptionAlgorithmParams,
    FEncryptedDigest, FAuthenticatedAttributesPlain,
    FContent, FEncodedValue, FArchivalEncodedValue);
  inherited;
end;

function TElPKCS7Signer.GetAuthenticatedAttributesPlain : ByteArray;
var
  Sz : integer;
  Tag : TElASN1ConstrainedTag;
begin
  if Length(FAuthenticatedAttributesPlain) > 0 then
    Result := CloneArray(FAuthenticatedAttributesPlain)
  else
  begin
    Tag := TElASN1ConstrainedTag.CreateInstance;
    try
      SaveAttributes(Tag, FAuthenticatedAttributes);
      Sz := 0;
      SetLength(FAuthenticatedAttributesPlain, Sz);
      Tag.SaveToBuffer(nil, Sz);

      SetLength(FAuthenticatedAttributesPlain, Sz);
      Tag.SaveToBuffer(@FAuthenticatedAttributesPlain[0], Sz);
    finally
      FreeAndNil(Tag);
    end;
    Result := CloneArray(FAuthenticatedAttributesPlain);
  end;
end;

procedure TElPKCS7Signer.SetDigestAlgorithm(const V : ByteArray);
begin
  FDigestAlgorithm := CloneArray(V);
end;

procedure TElPKCS7Signer.SetDigestAlgorithmParams(const V : ByteArray);
begin
  FDigestAlgorithmParams := CloneArray(V);
end;

procedure TElPKCS7Signer.SetDigestEncryptionAlgorithm(const V : ByteArray);
begin
  FDigestEncryptionAlgorithm := CloneArray(V);
end;

procedure TElPKCS7Signer.SetDigestEncryptionAlgorithmParams(const V : ByteArray);
begin
  FDigestEncryptionAlgorithmParams := CloneArray(V);
end;

procedure TElPKCS7Signer.SetEncryptedDigest(const V : ByteArray);
begin
  FEncryptedDigest := CloneArray(V);
end;

procedure TElPKCS7Signer.RecalculateAuthenticatedAttributes;
begin
  RecalculateAuthenticatedAttributes(false);
end;

procedure TElPKCS7Signer.RecalculateAuthenticatedAttributes(Reorder: boolean);
begin
  if Reorder then
    FAuthenticatedAttributes.SortLexicographically();
  SetLength(FAuthenticatedAttributesPlain, 0);
  GetAuthenticatedAttributesPlain;
end;

procedure TElPKCS7Signer.Recalculate;
var
  Tag : TElASN1ConstrainedTag;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance();
  try
    SaveSignerInfo(Tag, Self);
    ProcessSignerInfo(Tag, Self);
  finally
    FreeAndNil(Tag);
  end;
end;

procedure TElPKCS7Signer.Assign(Source : TElPKCS7Signer);
begin
  FVersion := Source.FVersion;
  FIssuer.Assign(Source.FIssuer);
  FDigestAlgorithm := CloneArray(Source.FDigestAlgorithm);
  FDigestAlgorithmParams := CloneArray(Source.FDigestAlgorithmParams);
  Source.FAuthenticatedAttributes.Copy(FAuthenticatedAttributes);
  Source.FUnauthenticatedAttributes.Copy(FUnauthenticatedAttributes);
  FDigestEncryptionAlgorithm := CloneArray(Source.FDigestEncryptionAlgorithm);
  FDigestEncryptionAlgorithmParams := CloneArray(Source.FDigestEncryptionAlgorithmParams);
  FEncryptedDigest := CloneArray(Source.FEncryptedDigest);
  FAuthenticatedAttributesPlain := CloneArray(Source.FAuthenticatedAttributesPlain);
  FContent := CloneArray(Source.FContent);
  FEncodedValue := CloneArray(Source.FEncodedValue);
  FArchivalEncodedValue := CloneArray(Source.FArchivalEncodedValue);
  FWriteNullInDigestEncryptionAlgID := Source.FWriteNullInDigestEncryptionAlgID;
end;

////////////////////////////////////////////////////////////////////////////////
// TElPKCS7EncryptedContent

constructor TElPKCS7EncryptedContent.Create;
begin
  inherited;
  FEncryptedContentParts := TElList.Create;
  FUseImplicitContentEncoding := false;
end;

 destructor  TElPKCS7EncryptedContent.Destroy;
begin
  ClearContentParts;
  FreeAndNil(FEncryptedContentParts);
  ReleaseArrays(FContentType, FContentEncryptionAlgorithm,
    FContentEncryptionAlgorithmParams);
  inherited;
end;

function TElPKCS7EncryptedContent.AddContentPart(DataSource : TElASN1DataSource): integer;
var
  DS : TElASN1DataSource;
begin
  DS := TElASN1DataSource.Create();
  DataSource.Clone(DS);
  Result := FEncryptedContentParts.Add(DS);
end;

function TElPKCS7EncryptedContent.AddContentPart(const Value : ByteArray): integer;
var
  DS : TElASN1DataSource;
begin
  DS := TElASN1DataSource.Create();
  DS.Init(Value);
  Result := FEncryptedContentParts.Add(DS);
end;

procedure TElPKCS7EncryptedContent.ClearContentParts;
var
  I : integer;
begin
  for I := 0 to FEncryptedContentParts.Count - 1 do
    TElASN1DataSource(FEncryptedContentParts[I]). Free ;
  FEncryptedContentParts.Clear;
end;

function TElPKCS7EncryptedContent.GetEncryptedContent : ByteArray;
var
  I : integer;
begin
  Result := EmptyArray;
  for I := 0 to FEncryptedContentParts.Count - 1 do
    Result := SBConcatArrays(Result, TElASN1DataSource(FEncryptedContentParts[I]).ToBuffer);
end;

procedure TElPKCS7EncryptedContent.SetEncryptedContent(const Value: ByteArray);
begin
  ClearContentParts;
  AddContentPart(Value);
end;

function TElPKCS7EncryptedContent.GetEncryptedContentPart(Index: integer): TElASN1DataSource;
begin
  Result := TElASN1DataSource(FEncryptedContentParts[Index]);
end;

function TElPKCS7EncryptedContent.GetEncryptedContentPartCount : integer;
begin
  Result := FEncryptedContentParts.Count;
end;

function TElPKCS7EncryptedContent.GetDataSource : TElASN1DataSource;
begin
  if GetEncryptedContentPartCount = 0 then
    FEncryptedContentParts.Add(TElASN1DataSource.Create);
  Result := GetEncryptedContentPart(0);
end;

procedure TElPKCS7EncryptedContent.SetContentType(const V : ByteArray);
begin
  FContentType := CloneArray(V);
end;

procedure TElPKCS7EncryptedContent.SetContentEncryptionAlgorithm(const V : ByteArray);
begin
  FContentEncryptionAlgorithm := CloneArray(V);
end;

procedure TElPKCS7EncryptedContent.SetContentEncryptionAlgorithmParams(const V : ByteArray);
begin
  FContentEncryptionAlgorithmParams := CloneArray(V);
end;

////////////////////////////////////////////////////////////////////////////////
// TElPKCS7SignedAndEnvelopedData

constructor TElPKCS7SignedAndEnvelopedData.Create;
begin
  inherited;
  FEncryptedContent := TElPKCS7EncryptedContent.Create;
  FCertStorage := TElMemoryCertStorage.Create(nil);
  FRecipientList := TElList.Create;
  FSignerList := TElList.Create;
end;

 destructor  TElPKCS7SignedAndEnvelopedData.Destroy;
begin
  FreeAndNil(FEncryptedContent);
  while FRecipientList.Count > 0 do
  begin
    TElPKCS7Recipient(FRecipientList[0]). Free ;
    FRecipientList. Delete (0);
  end;
  while FSignerList.Count > 0 do
  begin
    TElPKCS7Signer(FSignerList[0]). Free ;
    FSignerList. Delete (0);
  end;
  FreeAndNil(FCertStorage);
  FreeAndNil(FRecipientList);
  FreeAndNil(FSignerList);
  inherited;
end;

function TElPKCS7SignedAndEnvelopedData.GetRecipient(Index : integer) :
  TElPKCS7Recipient;
begin
  if Index < FRecipientList.Count then
    Result := TElPKCS7Recipient(FRecipientList[Index])
  else
    Result := nil;
end;

function TElPKCS7SignedAndEnvelopedData.GetRecipientCount : integer;
begin
  Result := FRecipientList.Count;
end;

function TElPKCS7SignedAndEnvelopedData.GetSigner(Index : integer) : TElPKCS7Signer;
begin
  if Index < FSignerList.Count then
    Result := TElPKCS7Signer(FSignerList[Index])
  else
    Result := nil;
end;

function TElPKCS7SignedAndEnvelopedData.GetSignerCount : integer;
begin
  Result := FSignerList.Count;
end;

function TElPKCS7SignedAndEnvelopedData.AddRecipient : integer;
begin
  Result := FRecipientList.Add(TElPKCS7Recipient.Create);
end;

function TElPKCS7SignedAndEnvelopedData.AddSigner : integer;
begin
  Result := FSignerList.Add(TElPKCS7Signer.Create);
end;

function TElPKCS7SignedAndEnvelopedData.RemoveRecipient(Index : integer) : boolean;
begin
  if Index < FRecipientList.Count then
  begin
    TElPKCS7Recipient(FRecipientList[Index]). Free ;
    FRecipientList.Delete(Index);
    Result := true;
  end
  else
    Result := false;
end;

function TElPKCS7SignedAndEnvelopedData.RemoveSigner(Index : integer) : boolean;
begin
  if Index < FSignerList.Count then
  begin
    TElPKCS7Signer(FSignerList[Index]). Free ;
    FSignerList.Delete(Index);
    Result := true;
  end
  else
    Result := false;
end;

////////////////////////////////////////////////////////////////////////////////
// TElPKCS7EncryptedData

constructor TElPKCS7EncryptedData.Create;
begin
  inherited;
  FEncryptedContent := TElPKCS7EncryptedContent.Create;
end;

 destructor  TElPKCS7EncryptedData.Destroy;
begin
  FreeAndNil(FEncryptedContent);
  inherited;
end;

function TElPKCS7EncryptedData.SaveToBuffer(Buffer: pointer; var Size: integer): boolean;
var
  Tag : TElASN1ConstrainedTag;
begin
  Result := false;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    FOwner.SaveEncryptedData(Tag);
    if Tag.Count > 0 then
      Result := Tag.GetField(0).SaveToBuffer(Buffer, Size);
  finally
    FreeAndNil(Tag);
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// TElPKCS7AuthenticatedData

constructor TElPKCS7AuthenticatedData.Create;
begin
  inherited;
  FRecipientList := TElList.Create;
  FAuthenticatedAttributes := TElPKCS7Attributes.Create;
  FUnauthenticatedAttributes := TElPKCS7Attributes.Create;
  FOriginatorCerts := TElMemoryCertStorage.Create(nil);
  FContentParts := TElList.Create;
  FVersion := 0;
end;

 destructor  TElPKCS7AuthenticatedData.Destroy;
begin
  while RecipientCount > 0 do
    RemoveRecipient(0);
  ClearContentParts;
  FreeAndNil(FContentParts);
  FreeAndNil(FRecipientList);
  FreeAndNil(FAuthenticatedAttributes);
  FreeAndNil(FUnauthenticatedAttributes);
  FreeAndNil(FOriginatorCerts);
  ReleaseArrays(FMacAlgorithm, FMacAlgorithmParams, FDigestAlgorithm,
    FDigestAlgorithmParams, FContentType, FMac,
    FAuthenticatedAttributesPlain);
  inherited;
end;

function TElPKCS7AuthenticatedData.GetRecipient(Index: integer) : TElPKCS7Recipient;
begin
  if (Index >= 0) and (Index < FRecipientList.Count) then
    Result := TElPKCS7Recipient(FRecipientList[Index])
  else
    Result := nil;
end;

function TElPKCS7AuthenticatedData.GetRecipientCount: integer;
begin
  Result := FRecipientList.Count;
end;

procedure TElPKCS7AuthenticatedData.SetMacAlgorithm(const V : ByteArray);
begin
  FMacAlgorithm := CloneArray(V);
end;

procedure TElPKCS7AuthenticatedData.SetMacAlgorithmParams(const V : ByteArray);
begin
  FMacAlgorithmParams := CloneArray(V);
end;

procedure TElPKCS7AuthenticatedData.SetDigestAlgorithm(const V : ByteArray);
begin
  FDigestAlgorithm := CloneArray(V);
end;

procedure TElPKCS7AuthenticatedData.SetDigestAlgorithmParams(const V : ByteArray);
begin
  FDigestAlgorithmParams := CloneArray(V);
end;

procedure TElPKCS7AuthenticatedData.SetContentType(const V : ByteArray);
begin
  FContentType := CloneArray(V);
end;

procedure TElPKCS7AuthenticatedData.SetMac(const V : ByteArray);
begin
  FMac := CloneArray(V);
end;

function TElPKCS7AuthenticatedData.GetAuthenticatedAttributesPlain: ByteArray;
var
  Sz : integer;
  Tag : TElASN1ConstrainedTag;
begin
  if Length(FAuthenticatedAttributesPlain) > 0 then
    Result := CloneArray(FAuthenticatedAttributesPlain)
  else
  begin
    Tag := TElASN1ConstrainedTag.CreateInstance;
    try
      SaveAttributes(Tag, FAuthenticatedAttributes);
      Sz := 0;
      SetLength(FAuthenticatedAttributesPlain, Sz);
      Tag.SaveToBuffer(nil, Sz);

      SetLength(FAuthenticatedAttributesPlain, Sz);
      Tag.SaveToBuffer(@FAuthenticatedAttributesPlain[0], Sz);
    finally
      FreeAndNil(Tag);
    end;                               
    Result := CloneArray(FAuthenticatedAttributesPlain);
  end;
end;

procedure TElPKCS7AuthenticatedData.RecalculateAuthenticatedAttributes;
begin
  SetLength(FAuthenticatedAttributesPlain, 0);
  GetAuthenticatedAttributesPlain;
end;

function TElPKCS7AuthenticatedData.AddRecipient : integer;
begin
  Result := FRecipientList.Add(TElPKCS7Recipient.Create);
end;

function TElPKCS7AuthenticatedData.RemoveRecipient(Index : integer) : boolean;
begin
  if (Index >= 0) and (Index < FRecipientList.Count) then
  begin
    TElPKCS7Recipient(FRecipientList[Index]). Free ;
    FRecipientList.Delete(Index);
    Result := true;
  end
  else
    Result := false;
end;

function TElPKCS7AuthenticatedData.AddContentPart(DataSource : TElASN1DataSource): integer;
var
  DS : TElASN1DataSource;
begin
  DS := TElASN1DataSource.Create;
  DataSource.Clone(DS);
  Result := FContentParts.Add(DS);
end;

function TElPKCS7AuthenticatedData.AddContentPart(const Value : ByteArray): integer;
var
  DS : TElASN1DataSource;
begin
  DS := TElASN1DataSource.Create;
  DS.Init(Value);
  Result := FContentParts.Add(DS);
end;

function TElPKCS7AuthenticatedData.AddContentPart(Buffer: pointer; Size: integer): integer;
var
  DS : TElASN1DataSource;
begin
  DS := TElASN1DataSource.Create;
  DS.Init(Buffer, Size);
  Result := FContentParts.Add(DS);
end;

procedure TElPKCS7AuthenticatedData.ClearContentParts;
var
  I : integer;
begin
  for I := 0 to FContentParts.Count - 1 do
    TElASN1DataSource(FContentParts[I]). Free ;
  FContentParts.Clear;
end;

function TElPKCS7AuthenticatedData.GetContentPart(Index: integer): TElASN1DataSource;
begin
  Result := TElASN1DataSource(FContentParts[Index]);
end;

function TElPKCS7AuthenticatedData.GetContentPartCount : integer;
begin
  Result := FContentParts.Count;
end;

function TElPKCS7AuthenticatedData.GetContent : ByteArray;
var
  I : integer;
begin
  Result := EmptyArray;
  for I := 0 to ContentPartCount - 1 do
    Result := SBConcatArrays(Result, ContentParts[I].ToBuffer);
end;

procedure TElPKCS7AuthenticatedData.SetContent(const Value: ByteArray);
begin
  ClearContentParts;
  AddContentPart(Value);
end;

function TElPKCS7AuthenticatedData.GetDataSource : TElASN1DataSource;
begin
  if GetContentPartCount = 0 then
    FContentParts.Add(TElASN1DataSource.Create);
  Result := GetContentPart(0);
end;

////////////////////////////////////////////////////////////////////////////////
// TElPKCS7TimestampedData class

constructor TElPKCS7TimestampAndCRL.Create;
begin
  inherited;
  FEncodedCRL := EmptyArray;
  FEncodedTimestamp := EmptyArray;
  FEncodedValue := EmptyArray;
end;

 destructor  TElPKCS7TimestampAndCRL.Destroy;
begin
  ReleaseArrays(FEncodedCRL, FEncodedTimestamp, FEncodedValue);
  inherited;
end;

procedure TElPKCS7TimestampAndCRL.SetEncodedTimestamp(const V : ByteArray);
begin
  FEncodedTimestamp := CloneArray(V);
end;

procedure TElPKCS7TimestampAndCRL.SetEncodedCRL(const V : ByteArray);
begin
  FEncodedCRL := CloneArray(V);
end;

procedure TElPKCS7TimestampAndCRL.SetEncodedValue(const V : ByteArray);
begin
  FEncodedValue := CloneArray(V);
end;

procedure TElPKCS7TimestampedData.SetDataURI(const V : ByteArray);
begin
  FDataURI := CloneArray(V);
end;

procedure TElPKCS7TimestampedData.SetFileName(const V : ByteArray);
begin
  FFileName := CloneArray(V);
end;

procedure TElPKCS7TimestampedData.SetMediaType(const V : ByteArray);
begin
  FMediaType := CloneArray(V);
end;

function TElPKCS7TimestampedData. GetTimestamps (Index : integer) : TElPKCS7TimestampAndCRL;
begin
  if (Index >= 0) and (Index < FTimestamps.Count) then
    Result := TElPKCS7TimestampAndCRL(FTimestamps[Index])
  else
    Result := nil;
end;

function TElPKCS7TimestampedData.GetTimestampCount : integer;
begin
  Result := FTimestamps.Count;
end;

function TElPKCS7TimestampedData.AddContentPart(DataSource : TElASN1DataSource): integer;
var
  DS : TElASN1DataSource;
begin
  DS := TElASN1DataSource.Create;
  DataSource.Clone(DS);
  Result := FContentParts.Add(DS);
end;

function TElPKCS7TimestampedData.AddContentPart(const Value : ByteArray): integer;
var
  DS : TElASN1DataSource;
begin
  DS := TElASN1DataSource.Create;
  DS.Init(Value);
  Result := FContentParts.Add(DS);
end;

function TElPKCS7TimestampedData.AddContentPart(Buffer: pointer; Size: integer): integer;
var
  DS : TElASN1DataSource;
begin
  DS := TElASN1DataSource.Create;
  DS.Init(Buffer, Size);
  Result := FContentParts.Add(DS);
end;

procedure TElPKCS7TimestampedData.ClearContentParts;
var
  I : integer;
begin
  for I := 0 to FContentParts.Count - 1 do
    TElASN1DataSource(FContentParts[I]). Free ;
  FContentParts.Clear;
end;

function TElPKCS7TimestampedData.GetContentPartCount : integer;
begin
  Result := FContentParts.Count;
end;

function TElPKCS7TimestampedData.GetContent : ByteArray;
var
  I : integer;
begin
  Result := EmptyArray;
  for I := 0 to ContentPartCount - 1 do
    Result := SBConcatArrays(Result, ContentParts[I].ToBuffer);
end;

procedure TElPKCS7TimestampedData.SetContent(const Value: ByteArray);
begin
  ClearContentParts;
  AddContentPart(Value);
end;

function TElPKCS7TimestampedData.GetDataSource : TElASN1DataSource;
begin
  if GetContentPartCount = 0 then
    FContentParts.Add(TElASN1DataSource.Create);
  Result := GetContentPart(0);
end;

function TElPKCS7TimestampedData.GetContentPart(Index: integer): TElASN1DataSource;
begin
  Result := TElASN1DataSource(FContentParts[Index]);
end;

function TElPKCS7TimestampedData.WriteMetadata : ByteArray;
var
  CTag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  Buf : ByteArray;
  Size : integer;
begin
  { adding metaData if needed}
  CTag := TElASN1ConstrainedTag.CreateInstance;

  try
    CTag.TagId := SB_ASN1_SEQUENCE;

    { hash protected }
    STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
    ASN1WriteBoolean(STag, HashProtected);

    { file name }
    if Length(FileName) > 0 then
    begin
      STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
      STag.TagId := SB_ASN1_UTF8STRING;
      STag.Content := FileName;
    end;

    { media type }
    if Length(MediaType) > 0 then
    begin
      STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
      STag.TagId := SB_ASN1_IA5STRING;
      STag.Content := MediaType;
    end;

    Size := 0;
    CTag.SaveToBuffer( nil , Size);
    SetLength(Buf, Size);
    CTag.SaveToBuffer( @Buf[0] , Size);
    SetLength(Buf, Size);
    Result := Buf;
  finally
    FreeAndNil(CTag);
  end;
end;

function TElPKCS7TimestampedData.WriteTimestampAndCRL(Ts : TElPKCS7TimestampAndCRL) : ByteArray;
var
  CTag, TsTag : TElASN1ConstrainedTag;
  TsBuf : ByteArray;
  Sz : integer;
begin
  { outer sequence for TimestampAndCRL }

  CTag := TElASN1ConstrainedTag.CreateInstance;
  CTag.TagId := SB_ASN1_SEQUENCE;

  try
    { inner sequence for Timestamp's SignedData }
    TsTag := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
    TsTag.TagId := SB_ASN1_SEQUENCE;

    TsBuf := Ts.EncodedTimestamp;
    TsTag.LoadFromBufferSingle( @TsBuf[0] , Length(TsBuf));

    { inner sequence for Timestamp's CRL }
    if Length(Ts.EncodedCRL) > 0 then
    begin
      TsBuf := Ts.EncodedCRL;
      TsTag := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
      TsTag.LoadFromBuffer( @TsBuf[0] , Length(TsBuf));
    end;

    Sz := 0;
    TsTag.SaveToBuffer( nil , Sz);
    SetLength(TsBuf, Sz);
    TsTag.SaveToBuffer( @TsBuf[0] , Sz);
    SetLength(TsBuf, Sz);

    Result := TsBuf;
  finally
    FreeAndNil(CTag);
  end;
end;

constructor TElPKCS7TimestampedData.Create;
begin
  inherited;

  FTimestamps :=  TElList.Create ;
  FContentParts := TElList.Create;

  FContentType := EmptyArray;
  FDataURI := EmptyArray;
  FHashProtected := false;
  FFileName := EmptyArray;
  FMediaType := EmptyArray;
  FMetaDataAvailable := false;
end;

 destructor  TElPKCS7TimestampedData.Destroy;
begin
  while TimestampCount > 0 do
    RemoveTimestamp(0);

  ClearContentParts;
  FreeAndNil(FContentParts);
  FreeAndNil(FTimestamps);
  ReleaseArrays(FContentType, FDataURI, FFileName, FMediaType, FContentType);
  inherited;
end;

function TElPKCS7TimestampedData.AddTimestamp : integer;
begin
  Result := FTimestamps.Add(TElPKCS7TimestampAndCRL.Create);
end;

function TElPKCS7TimestampedData.RemoveTimestamp(Index : integer) : boolean;
var
  Rec : TElPKCS7TimestampAndCRL;
begin
  if (Index < FTimestamps.Count) and (Index >= 0) then
  begin
    Rec := TElPKCS7TimestampAndCRL(FTimestamps[Index]);
    FTimestamps.Delete(Index);
    FreeAndNil(Rec);
    Result := true;
  end
  else
    Result := false;
end;

procedure TElPKCS7TimestampedData.ClearTimestamps;
var
  i : integer;
  Rec : TElPKCS7TimestampAndCRL;
begin
  for i := 0 to FTimestamps.Count - 1 do
  begin
    Rec := TElPKCS7TimestampAndCRL(FTimestamps[i]);
    FreeAndNil(Rec);
  end;
  FTimestamps.Clear;
end;

////////////////////////////////////////////////////////////////////////////////
// TElPKCS7EncryptedContentPart class

 destructor  TElPKCS7ContentPart.Destroy;
begin
  inherited;
end;

function TElPKCS7ContentPart.GetSize : integer;
begin
  if FStream = nil then
    Result := Length(FContent)
  else
    Result := FSize;
end;

function TElPKCS7ContentPart.Read(Buffer: pointer; Size: integer;
  StartOffset : integer = 0): integer;
var
  OldOffset : integer;
begin
  if FStream = nil then
  begin
    Result := Min( Size , Length(FContent) - StartOffset);
    SBMove(FContent[0 + StartOffset], Buffer^, Result);
  end
  else
  begin
    OldOffset := FStream.Position;
    try
      FStream.Position := StartOffset + FOffset;
      Result := FStream.Read(Buffer^, Size);
    finally
      FStream.Position := OldOffset;
    end;
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// Auxiliary routines

function ProcessContentInfo(Tag : TElASN1ConstrainedTag; Buffer :
  pointer; var Size : integer; var ContentType : ByteArray) : boolean;
begin
  // This overload is used only by digested data.
  // SignedData and AuthenticatedData content types use the following overload
  Result := false;
  if Tag.TagId <> SB_ASN1_SEQUENCE then
    Exit;
  if (Tag.Count < 1) or (Tag.Count > 2) then
    Exit;
  if (Tag.GetField(0).IsConstrained) or (Tag.GetField(0).TagId <> SB_ASN1_OBJECT) then
    Exit;
  ContentType := TElASN1SimpleTag(Tag.GetField(0)).Content;
  if Tag.Count = 2 then
  begin
    if (not Tag.GetField(1).IsConstrained) or (Tag.GetField(1).TagId <> SB_ASN1_A0) then
      Exit;
    if (TElASN1ConstrainedTag(Tag.GetField(1)).Count < 1) then
      Exit;
    if (not TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0).IsConstrained) then
    begin
      if Size < Length(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0)).Content) then
      begin
        Size := Length(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0)).Content);
        Result := false;
      end
      else
      begin
        Size := Length(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0)).Content);
        SBMove(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0)).Content[0],
          Buffer^, Size);
        Result := true;
      end;
    end
    else
    begin
      if TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0).TagNum = SB_ASN1_OCTETSTRING then
        Result := TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0)).SaveContentToBuffer(Buffer, Size) 
      else
        Result := TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0)).SaveToBuffer(Buffer, Size);
    end;
  end
  else
  begin
    Size := 0;
    Result := true;
  end;
end;

function ProcessContentInfo(Tag : TElASN1ConstrainedTag; PKCS7Data : TObject;
  var ContentType : ByteArray): boolean;
var
  Buf, RawBuf : ByteArray;
  Size : integer;
begin
  Result := false;
  if Tag.TagId <> SB_ASN1_SEQUENCE then
    Exit;
  if (Tag.Count < 1) or (Tag.Count > 2) then
    Exit;
  if (Tag.GetField(0).IsConstrained) or (Tag.GetField(0).TagId <> SB_ASN1_OBJECT) then
    Exit;
  ContentType := TElASN1SimpleTag(Tag.GetField(0)).Content;
  if Tag.Count = 2 then
  begin
    if (not Tag.GetField(1).IsConstrained) or (Tag.GetField(1).TagId <> SB_ASN1_A0) then
      Exit;
    if (TElASN1ConstrainedTag(Tag.GetField(1)).Count < 1) then
      Exit;
    if (not TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0).IsConstrained) then
    begin
      if PKCS7Data is TElPKCS7AuthenticatedData then
        TElPKCS7AuthenticatedData(PKCS7Data).AddContentPart(
          TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0)).DataSource)
      else if PKCS7Data is TElPKCS7SignedData then
      begin
        TElPKCS7SignedData(PKCS7Data).FIsMultipart := false;
        TElPKCS7SignedData(PKCS7Data).AddContentPart(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0)).DataSource)
      end
      else if PKCS7Data is TElPKCS7DigestedData then
      begin
        // TODO
        Result := false;
        Exit;
      end;
      Result := true;
    end
    else
    begin
      Size := 0;
      TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0)).SaveToBuffer( nil , Size);
      SetLength(RawBuf, Size);
      TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0)).SaveToBuffer( @RawBuf[0] , Size);
      SetLength(RawBuf, Size);
      if TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0).TagNum = SB_ASN1_OCTETSTRING then
      begin
        Size := 0;
        TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0)).SaveContentToBuffer( nil , Size);
        SetLength(Buf, Size);
        TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0)).SaveContentToBuffer( @Buf[0] , Size);
        SetLength(Buf, Size);
      end
      else
        Buf := CloneArray(RawBuf);
      if PKCS7Data is TElPKCS7AuthenticatedData then
      begin
        TElPKCS7AuthenticatedData(PKCS7Data).AddContentPart(@Buf[0], Size);
      end
      else if PKCS7Data is TElPKCS7SignedData then
      begin
        TElPKCS7SignedData(PKCS7Data).AddContentPart(@Buf[0], Size);
        TElPKCS7SignedData(PKCS7Data).FRawMultipartContent := CloneArray(RawBuf);
        TElPKCS7SignedData(PKCS7Data).FIsMultipart := true;
      end
      else if PKCS7Data is TElPKCS7DigestedData then
      begin
        // TODO
        Result := false;
        Exit;
      end;
      ReleaseArray(Buf);
      ReleaseArray(RawBuf);
      Result := true;
    end;
  end
  else
  begin
    Size := 0;
    Result := true;
  end;
end;

 destructor  TElPKCS7DigestedData.Destroy;
begin
  ReleaseArrays(FDigestAlgorithm, FDigestAlgorithmParams, FContent, FDigest);
  inherited;
end;

procedure TElPKCS7DigestedData.SetDigestAlgorithm(const V : ByteArray);
begin
  FDigestAlgorithm := CloneArray(V);
end;

procedure TElPKCS7DigestedData.SetDigestAlgorithmParams(const V : ByteArray);
begin
  FDigestAlgorithmParams := CloneArray(V);
end;

procedure TElPKCS7DigestedData.SetContent(const V : ByteArray);
begin
  FContent := CloneArray(V);
end;

procedure TElPKCS7DigestedData.SetDigest(const V : ByteArray);
begin
  FDigest := CloneArray(V);
end;

{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
initialization

  SB_OID_PKCS7_DATA                       := CreateByteArrayConst( SB_OID_PKCS7_DATA_STR );
  SB_OID_PKCS7_SIGNED_DATA                := CreateByteArrayConst( SB_OID_PKCS7_SIGNED_DATA_STR );
  SB_OID_PKCS7_ENVELOPED_DATA             := CreateByteArrayConst( SB_OID_PKCS7_ENVELOPED_DATA_STR );
  SB_OID_PKCS7_SIGNED_AND_ENVELOPED_DATA  := CreateByteArrayConst( SB_OID_PKCS7_SIGNED_AND_ENVELOPED_DATA_STR );
  SB_OID_PKCS7_DIGESTED_DATA              := CreateByteArrayConst( SB_OID_PKCS7_DIGESTED_DATA_STR );
  SB_OID_PKCS7_ENCRYPTED_DATA             := CreateByteArrayConst( SB_OID_PKCS7_ENCRYPTED_DATA_STR );
  SB_OID_PKCS7_AUTHENTICATED_DATA         := CreateByteArrayConst( SB_OID_PKCS7_AUTHENTICATED_DATA_STR );
  SB_OID_PKCS7_COMPRESSED_DATA            := CreateByteArrayConst( SB_OID_PKCS7_COMPRESSED_DATA_STR );
  SB_OID_PKCS7_TIMESTAMPED_DATA           := CreateByteArrayConst( SB_OID_PKCS7_TIMESTAMPED_DATA_STR );

  SB_OID_PKCS7_COMPRESSION_ZLIB           := CreateByteArrayConst( SB_OID_PKCS7_COMPRESSION_ZLIB_STR );

 {$endif}

end.
