(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBCRL;

interface

uses
  Classes,
  {$ifdef SB_UNICODE_VCL}
  SBStringList,
   {$endif}
  SBASN1,
  SBASN1Tree,
  SBTypes,
  SBUtils,
  SBEncoding,
  SBX509,
  SBPEM,
  SBX509Ext,
  SBRDN,
  SBSharedResource,
  SBCustomCrypto,
  SBPublicKeyCrypto,
  SBAlgorithmIdentifier,
  SBConstants;


const
  SB_CRL_ERROR_INVALID_FORMAT                   = Integer($2201);
  SB_CRL_ERROR_BAD_SIGNATURE_ALGORITHM          = Integer($2202);
  SB_CRL_ERROR_INVALID_ISSUER                   = Integer($2203);
  SB_CRL_ERROR_INVALID_SIGNATURE                = Integer($2204);
  SB_CRL_ERROR_UNSUPPORTED_VERSION              = Integer($2205);
  SB_CRL_ERROR_UNSUPPORTED_ALGORITHM            = Integer($2206);
  SB_CRL_ERROR_INVALID_CERTIFICATE              = Integer($2207);
  SB_CRL_ERROR_ALREADY_EXISTS                   = Integer($2208);
  SB_CRL_ERROR_NOT_FOUND                        = Integer($2209);
  SB_CRL_ERROR_PRIVATE_KEY_NOT_FOUND            = Integer($220A);
  SB_CRL_ERROR_UNSUPPORTED_CERTIFICATE          = Integer($220B);
  SB_CRL_ERROR_INTERNAL_ERROR                   = Integer($220C);
  SB_CRL_ERROR_BUFFER_TOO_SMALL                 = Integer($220D);
  SB_CRL_ERROR_NOTHING_TO_VERIFY                = Integer($220E);
  SB_CRL_ERROR_NO_SIGNED_CRL_FOUND              = Integer($220F);


type

  TElCRLExtension = TElCustomExtension;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCRLExtension = TElCRLExtension;
   {$endif}

  TElAuthorityKeyIdentifierCRLExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElAuthorityKeyIdentifierCRLExtension = TElAuthorityKeyIdentifierCRLExtension;
   {$endif}

  TElAuthorityKeyIdentifierCRLExtension = class(TElCRLExtension)
  private
    FKeyIdentifier : ByteArray;
    FAuthorityCertIssuer : TElGeneralNames;
    FAuthorityCertSerial : ByteArray;
    FSaveIssuer : boolean;
  protected
    procedure Clear; override;

    function GetOID: ByteArray; override;
    procedure SetOID(const Value : ByteArray); override;
    procedure SetValue(const Value : ByteArray); override;
    function GetValue: ByteArray; override;
    procedure SetKeyIdentifier(const V : ByteArray);
    procedure SetAuthorityCertSerial(const V : ByteArray);
  public
    constructor Create;
     destructor  Destroy; override;
    property KeyIdentifier : ByteArray read FKeyIdentifier write SetKeyIdentifier;
    property AuthorityCertIssuer : TElGeneralNames read FAuthorityCertIssuer;
    property AuthorityCertSerial : ByteArray read FAuthorityCertSerial write SetAuthorityCertSerial;
    property IssuerSet : boolean read FSaveIssuer write FSaveIssuer;
  end;

  TElCRLNumberCRLExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCRLNumberCRLExtension = TElCRLNumberCRLExtension;
   {$endif}

  TElCRLNumberCRLExtension = class(TElCRLExtension)
  private
    FBinaryNumber: ByteArray;
  protected
    procedure Clear; override;

    function GetOID: ByteArray; override;
    procedure SetOID(const Value : ByteArray); override;
    procedure SetValue(const Value : ByteArray); override;
    function GetValue: ByteArray; override;
    function GetNumber: integer;
    procedure SetNumber(Value: integer);
    procedure SetBinaryNumber(const V: ByteArray);
  public
    property Number: Integer read GetNumber write SetNumber;
    property BinaryNumber : ByteArray read FBinaryNumber write SetBinaryNumber;
  end;

  TElDeltaCRLIndicatorCRLExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElDeltaCRLIndicatorCRLExtension = TElDeltaCRLIndicatorCRLExtension;
   {$endif}

  TElDeltaCRLIndicatorCRLExtension = class(TElCRLExtension)
  private
    FBinaryNumber: ByteArray;
  protected
    procedure Clear; override;

    function GetOID: ByteArray; override;
    procedure SetOID(const Value : ByteArray); override;
    procedure SetValue(const Value : ByteArray); override;
    function GetValue: ByteArray; override;
    function GetNumber: integer;
    procedure SetNumber(Value: integer);
    procedure SetBinaryNumber(const Value: ByteArray);
  public
    property Number: Integer read GetNumber write SetNumber;
    property BinaryNumber: ByteArray read FBinaryNumber write SetBinaryNumber;
  end;

  TElReasonCodeCRLExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElReasonCodeCRLExtension = TElReasonCodeCRLExtension;
   {$endif}

  TElReasonCodeCRLExtension = class(TElCRLExtension)
  private
    FReason : TSBCRLReasonFlag;
    FRemoveFromCRL : boolean;
  protected
    procedure Clear; override;

    function GetOID : ByteArray; override;
    procedure SetOID(const Value : ByteArray); override;
    procedure SetValue(const Value : ByteArray); override;
    function GetValue : ByteArray; override;
  public
    property Reason : TSBCRLReasonFlag read FReason write FReason;
    property RemoveFromCRL : boolean read FRemoveFromCRL write FRemoveFromCRL;
  end;

  TElInstructionCode =  
    (icNone, icCallIssuer, icReject);

  TElHoldInstructionCodeCRLExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElHoldInstructionCodeCRLExtension = TElHoldInstructionCodeCRLExtension;
   {$endif}

  TElHoldInstructionCodeCRLExtension = class(TElCRLExtension)
  private
    FCode : TElInstructionCode;
  protected
    procedure Clear; override;

    function GetOID: ByteArray; override;
    procedure SetOID(const Value : ByteArray); override;
    procedure SetValue(const Value : ByteArray); override;
    function GetValue: ByteArray; override;
  public
    property Code : TElInstructionCode read FCode write FCode;
  end;

  TElInvalidityDateCRLExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElInvalidityDateCRLExtension = TElInvalidityDateCRLExtension;
   {$endif}

  TElInvalidityDateCRLExtension = class(TElCRLExtension)
  private
    FDate : TElDateTime;
  protected
    procedure Clear; override;

    function GetOID: ByteArray; override;
    procedure SetOID(const Value : ByteArray); override;
    procedure SetValue(const Value : ByteArray); override;
    function GetValue: ByteArray; override;
  public
    property InvalidityDate : TElDateTime read FDate write FDate;
  end;

  TElCertificateIssuerCRLExtension = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCertificateIssuerCRLExtension = TElCertificateIssuerCRLExtension;
   {$endif}

  TElCertificateIssuerCRLExtension = class(TElCRLExtension)
  private
    FIssuer : TElGeneralNames;
  protected
    procedure Clear; override;

    function GetOID: ByteArray; override;
    procedure SetOID(const Value : ByteArray); override;
    procedure SetValue(const Value : ByteArray); override;
    function GetValue: ByteArray; override;
  public
    constructor Create;
     destructor  Destroy; override;
    property Issuer : TElGeneralNames read FIssuer;
  end;

  TElIssuingDistributionPointCRLExtension = class(TElCRLExtension)
  protected
    FDistributionPoint : TElGeneralNames;
    FReasonFlags: TSBCRLReasonFlags;
    FOnlyContainsUserCerts : boolean;
    FOnlyContainsCACerts : boolean;
    FOnlyContainsAttributeCerts : boolean;
    FIndirectCRL : boolean;
    FReasonFlagsIncluded : boolean;
    procedure Clear; override;

    function GetOID: ByteArray; override;
    procedure SetOID(const Value : ByteArray); override;
    procedure SetValue(const Value : ByteArray); override;
    function GetValue: ByteArray; override;
  public
    constructor Create;
     destructor  Destroy; override;
    property DistributionPoint: TElGeneralNames read FDistributionPoint;
    property OnlySomeReasons: TSBCRLReasonFlags read FReasonFlags write FReasonFlags;
    property OnlyContainsUserCerts : boolean read FOnlyContainsUserCerts write FOnlyContainsUserCerts;
    property OnlyContainsCACerts : boolean read FOnlyContainsCACerts write FOnlyContainsCACerts;
    property OnlyContainsAttributeCerts : boolean read FOnlyContainsAttributeCerts write FOnlyContainsAttributeCerts; // property is not supported by CryptoAPI (invalidates the extension)
    property IndirectCRL : boolean read FIndirectCRL write FIndirectCRL;
    property ReasonFlagsIncluded : boolean read FReasonFlagsIncluded write FReasonFlagsIncluded;
  end;


  TSBCRLExtension = (crlAuthorityKeyIdentifier, crlIssuerAlternativeName,
    crlCRLNumber, crlDeltaCRLIndicator, crlIssuingDistributionPoint);
  TSBCRLExtensions = set of TSBCRLExtension;

  TElCRLExtensions = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCRLExtensions = TElCRLExtensions;
   {$endif}

  TElCRLExtensions = class
   private 
    FAuthorityKeyIdentifier : TElAuthorityKeyIdentifierCRLExtension;
    FIssuerAlternativeName : TElAlternativeNameExtension;
    FCRLNumber : TElCRLNumberCRLExtension;
    FDeltaCRLIndicator : TElDeltaCRLIndicatorCRLExtension;
    FDistributionPoint : TElIssuingDistributionPointCRLExtension;

    FOtherExtensions : TElList;
    FIncluded : TSBCRLExtensions;
    procedure ClearList;
    function LoadFromTag(Tag : TElASN1ConstrainedTag) : integer;
    procedure SaveToTag(Tag : TElASN1ConstrainedTag);
    function AddExtension(const OID : ByteArray; Critical : boolean; const Value :
        ByteArray): Integer;

    function GetOtherCount : integer;
    procedure SetOtherCount(Value : integer);
    function  GetOther (Index : integer) : TElCRLExtension;
  public
    constructor Create;
     destructor  Destroy; override;
    property AuthorityKeyIdentifier : TElAuthorityKeyIdentifierCRLExtension read
      FAuthorityKeyIdentifier;
    property IssuerAlternativeName : TElAlternativeNameExtension read
      FIssuerAlternativeName;
    property CRLNumber : TElCRLNumberCRLExtension read FCRLNumber;
    property DeltaCRLIndicator : TElDeltaCRLIndicatorCRLExtension read
      FDeltaCRLIndicator;
    property IssuingDistributionPoint : TElIssuingDistributionPointCRLExtension read FDistributionPoint;
    property OtherExtensions[Index : integer] : TElCRLExtension read  GetOther ;
    property OtherCount : integer read GetOtherCount write SetOtherCount;
    property Included : TSBCRLExtensions read FIncluded write FIncluded;
  end;

  TSBCRLEntryExtension = (crlReasonCode, crlHoldInstructionCode, crlInvalidityDate,
    crlCertificateIssuer);
  TSBCRLEntryExtensions = set of TSBCRLEntryExtension;

  TElCRLEntryExtensions = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCRLEntryExtensions = TElCRLEntryExtensions;
   {$endif}

  TElCRLEntryExtensions = class
   private 
    FReasonCode : TElReasonCodeCRLExtension;
    FHoldInstructionCode : TElHoldInstructionCodeCRLExtension;
    FInvalidityDate : TElInvalidityDateCRLExtension;
    FCertificateIssuer : TElCertificateIssuerCRLExtension;
    FOtherExtensions : TElList;
    FIncluded : TSBCRLEntryExtensions;
    procedure ClearList;
    function LoadFromTag(Tag : TElASN1ConstrainedTag) : integer;
    procedure SaveToTag(Tag : TElASN1ConstrainedTag);
    function AddExtension(const OID : ByteArray; Critical : boolean; const Value :
        ByteArray): Integer;

    function GetOtherCount : integer;
    procedure SetOtherCount(Value : integer);
    function  GetOther (Index : integer) : TElCRLExtension;
  public
    constructor Create;
     destructor  Destroy; override;
    property ReasonCode : TElReasonCodeCRLExtension read FReasonCode;
    property HoldInstructionCode : TElHoldInstructionCodeCRLExtension read
      FHoldInstructionCode;
    property InvalidityDate : TElInvalidityDateCRLExtension read FInvalidityDate;
    property CertificateIssuer : TElCertificateIssuerCRLExtension read
      FCertificateIssuer;
    property OtherExtensions[Index : integer] : TElCRLExtension read  GetOther ;
    property OtherCount : integer read GetOtherCount write SetOtherCount;
    property Included : TSBCRLEntryExtensions read FIncluded write FIncluded;
  end;

  TElRevocationItem = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElRevocationItem = TElRevocationItem;
   {$endif}

  TElRevocationItem = class
   private 
    FSerialNumber : ByteArray;
    FRevocationDate : TElDateTime;
    FExtensions : TElCRLEntryExtensions;
    procedure SetSerialNumber(const V : ByteArray);
  public
    constructor Create;
     destructor  Destroy; override;

    property SerialNumber : ByteArray read FSerialNumber write SetSerialNumber;
    property RevocationDate : TElDateTime read FRevocationDate write FRevocationDate;
    property Extensions : TElCRLEntryExtensions read FExtensions;

  end;

  TElCertificateRevocationList = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElCertificateRevocationList = TElCertificateRevocationList;
   {$endif}

  TElCertificateRevocationList = class(TSBControlBase)
  protected
    FIssuer : TElRelativeDistinguishedName;
    //FEncParams : TElEncryptionParameters;
    FThisUpdate : TElDateTime;
    FNextUpdate : TElDateTime;
    FVersion : integer;
    FLocation : string;
    //FSignatureAlgorithm : integer;
    FItems : TElList;
    FSignature : ByteArray;
    FSignatureAlgorithm : TElAlgorithmIdentifier;
    //FChanged : boolean;
    FExtensions : TElCRLExtensions;
    FTBS : ByteArray;
    FCRLBinary : ByteArray;
    function ParseCertList(Tag : TElASN1ConstrainedTag) : integer;
    function ParseRevokedCertificates(Tag : TElASN1ConstrainedTag) : integer;
    procedure SaveCertList(Tag : TElASN1ConstrainedTag; Certificate : TElX509Certificate);
    procedure SaveRevokedCertificates(Tag : TElASN1ConstrainedTag);
    procedure ClearList;

    function GetCount : integer;
    function GetSignatureAlgorithm : integer;
    function GetCRLSize : integer;
    function GetItems(Index : integer) : TElRevocationItem;
  protected

  public
    constructor Create(Owner : TComponent); {$ifndef SB_NO_COMPONENT}override; {$endif}
     destructor  Destroy; override;
    function Add(Certificate : TElX509Certificate) : integer;  overload; 
    function Add(const SerialNumber : ByteArray) : integer;  overload; 
    procedure Assign(Source : TPersistent); override;
    function Remove(Certificate : TElX509Certificate) : boolean;  overload; 
    function Remove(Index : integer) : boolean;  overload; 
    function IsPresent(Certificate : TElX509Certificate) : boolean;
    function IndexOf(Certificate : TElX509Certificate) : integer;
    procedure Clear;
    function LoadFromBuffer(Buffer : pointer; Size : integer) : integer;
    function SaveToBuffer(Buffer : pointer; var Size : integer): integer; overload;
    function LoadFromBufferPEM(Buffer: pointer; Size: integer; const Passphrase:
      string = '') : integer;
    function SaveToBufferPEM(Buffer: pointer; var Size: integer; const Passphrase: string = ''): integer; overload;
    function LoadFromStream(Stream : TStream; Count : integer = 0) : integer;
    function LoadFromStreamPEM(Stream : TStream; const Passphrase: string = '';
      Count : integer = 0): integer;
    

    function SameCRL(CRL : TElCertificateRevocationList; CheckUpdateTime : boolean) : boolean;

    function Validate(Certificate : TElX509Certificate) : integer;
    property Location : string read FLocation write FLocation;
    property Issuer : TElRelativeDistinguishedName read FIssuer;
    property ThisUpdate : TElDateTime read FThisUpdate write FThisUpdate;
    property NextUpdate : TElDateTime read FNextUpdate write FNextUpdate;
    property SignatureAlgorithm : integer read GetSignatureAlgorithm;
    property SignatureAlgorithmIdentifier: TElAlgorithmIdentifier read FSignatureAlgorithm;
    property Signature : ByteArray read FSignature;
    property TBS : ByteArray read FTBS;
    property Items[Index : integer] : TElRevocationItem read GetItems;
    property Count : integer read GetCount;
    property Extensions : TElCRLExtensions read FExtensions;
    property CRLSize : integer read GetCRLSize;
  end;

  EElCRLError = class(ESecureBlackboxError);

procedure Register;

implementation

uses
  SysUtils,
  SBPKCS7;

{$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
 {$else}
var
 {$endif}

  SB_OID_EXT_AUTHORITYKEYIDENTIFIER     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =   #$55#$1D#$23 {$endif};
  SB_OID_EXT_ISSUERALTERNATIVENAME      : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =   #$55#$1D#$12 {$endif};
  SB_OID_EXT_CRLNUMBER                  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =   #$55#$1D#$14 {$endif};
  SB_OID_EXT_DELTACRLINDICATOR          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =   #$55#$1D#$1B {$endif};
  SB_OID_EXT_ISSUINGDISTRIBUTIONPOINT   : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =   #$55#$1D#$1C {$endif};
  SB_OID_EXT_REASONCODE                 : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =   #$55#$1D#$15 {$endif};
  SB_OID_EXT_HOLDINSTRUCTIONCODE        : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =   #$55#$1D#$17 {$endif};
  SB_OID_EXT_INVALIDITYDATE             : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =   #$55#$1D#$18 {$endif};
  SB_OID_EXT_CERTIFICATEISSUER          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =   #$55#$1D#$1D {$endif};

const

  YEAR2050 : TDateTime = 54789;

resourcestring
  SInvalidCRL = 'Invalid CRL';
  SNumberTooLong = 'Number is too long to fit into 32 bit integer';

procedure Register;
begin
  RegisterComponents('PKIBlackbox', [TElCertificateRevocationList]);
end;


////////////////////////////////////////////////////////////////////////////////
// TElCertificateRevocationList implementation

constructor TElCertificateRevocationList.Create(Owner : TComponent);
begin
  inherited Create  (Owner) ;
  FIssuer := TElRelativeDistinguishedName.Create;
  FSignatureAlgorithm := nil;

  FItems := TElList.Create;
  //FChanged := false;
  FExtensions := TElCRLExtensions.Create;
end;


 destructor  TElCertificateRevocationList.Destroy;
begin
  ClearList;
  FreeAndNil(FItems);
  FreeAndNil(FIssuer);
  FreeAndNil(FExtensions);

  if Assigned(FSignatureAlgorithm) then
    FreeAndNil(FSignatureAlgorithm);
  inherited;
end;

function TElCertificateRevocationList.LoadFromBuffer(Buffer : pointer; Size : integer) : integer;
var
  Tag, CTag : TElASN1ConstrainedTag;
  TmpBuf : ByteArray;
  TmpBufSize : integer;
  RealSigAlgorithm : TElAlgorithmIdentifier;
  CrlLen : integer;
begin
  CheckLicenseKey();
  FVersion := 0;
  SetLength(FCRLBinary, 0);
  ClearList;

  TmpBufSize :=  Size ;
  SetLength(TmpBuf, TmpBufSize);
  
  if IsBase64UnicodeSequence( Buffer, Size ) then
  begin
    Base64UnicodeDecode( Buffer, Size, TmpBuf , TmpBufSize);
  end
  else
  if IsBase64Sequence( Buffer, Size ) then
  begin
    Base64Decode( Buffer, Size, TmpBuf , TmpBufSize);
  end
  else
  begin
    SBMove(Buffer^, TmpBuf[0], TmpBufSize);
  end;

  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    Result := SB_CRL_ERROR_INVALID_FORMAT;
    //if not Tag.LoadFromBuffer(TmpBuf{$ifdef SB_VCL}, TmpBufSize{$endif}) then
    //  Exit;
    // II20120110: LoadFromBuffer replaced with LoadFromBufferSingle to be
    // tolerant to CRLs with trash after the end
    CrlLen := Tag.LoadFromBufferSingle(TmpBuf , TmpBufSize );
    if CrlLen = -1 then
      Exit;
    if Tag.Count <> 1 then
    begin
      Exit;
    end;
    CTag := TElASN1ConstrainedTag(Tag.GetField(0));
    if (not CTag.IsConstrained) or (CTag.TagId <> SB_ASN1_SEQUENCE) or
      (TElASN1ConstrainedTag(CTag).Count <> 3) then
    begin
      Exit;
    end;
    if (not CTag.GetField(0).IsConstrained) then
    begin
      Exit;
    end;
    Result := ParseCertList(TElASN1ConstrainedTag(CTag.GetField(0)));
    if Result <> 0 then
    begin
      Exit;
    end;

    SetLength(FTBS, CTag.GetField(0).TagSize);
    SBMove(PByteArray(TmpBuf)[CTag.GetField(0).TagOffset], FTBS[0], Length(FTBS));

    Result := SB_CRL_ERROR_INVALID_SIGNATURE;

    if not CTag.GetField(1).IsConstrained then
      Exit;

    try
      RealSigAlgorithm := TElAlgorithmIdentifier.CreateFromTag(TElASN1ConstrainedTag(CTag.GetField(1)));
    except
      Exit;
    end;

    if not RealSigAlgorithm.Equals(FSignatureAlgorithm) then
    begin
      FreeAndNil(RealSigAlgorithm);
      Exit;
    end;

    FreeAndNil(RealSigAlgorithm);

    if (CTag.GetField(2).IsConstrained) or (CTag.GetField(2).TagId <> SB_ASN1_BITSTRING) then
    begin
      Result := SB_CRL_ERROR_INVALID_FORMAT;
      Exit;
    end;

    FSignature := TElASN1SimpleTag(CTag.GetField(2)).Content;
    if (Length(FSignature) > 0) and (Ord(FSignature[0]) = 0) then
      FSignature := CloneArray(FSignature, 0 + 1, Length(FSignature) - 1);
    //FChanged := false;
    //FCRLBinary := CloneArray(TmpBuf);
    // II20120110
    FCRLBinary := CloneArray(@TmpBuf[0], CrlLen);
    Result := 0;
  finally
    FreeAndNil(Tag);
    ReleaseArray(TmpBuf);
  end;
end;

function TElCertificateRevocationList.SaveToBuffer(Buffer : pointer; var Size : integer): integer;
begin
  if Length(FCRLBinary) = 0 then
    Result := SB_CRL_ERROR_NO_SIGNED_CRL_FOUND
  else
  begin
    if Size >= Length(FCRLBinary) then
    begin
      Size := Length(FCRLBinary);
      SBMove(FCRLBinary[0], Buffer^, Size);
      Result := 0;
    end
    else
    begin
      Size := Length(FCRLBinary);
      Result := SB_CRL_ERROR_BUFFER_TOO_SMALL;
    end;
  end;
end;


procedure TElCertificateRevocationList.SaveCertList(Tag : TElASN1ConstrainedTag;
  Certificate : TElX509Certificate);
var
  STag : TElASN1SimpleTag;
  CTag : TElASN1ConstrainedTag;
  TmpBuf : ByteArray;
begin
  Tag.TagId := SB_ASN1_SEQUENCE;
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;

  TmpBuf := GetByteArrayFromByte(1);
  STag.Content := TmpBuf;

  ReleaseArray(TmpBuf);

  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  FSignatureAlgorithm.SaveToTag(CTag);

  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  FIssuer.SaveToTag(CTag);
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  if FThisUpdate < YEAR2050 then
  begin
    STag.TagId := SB_ASN1_UTCTIME;

    TmpBuf :=  BytesOfString (DateTimeToUTCTime(FThisUpdate));
    STag.Content := TmpBuf;
    ReleaseArray(TmpBuf);
  end
  else
  begin
    STag.TagId := SB_ASN1_GENERALIZEDTIME;
    TmpBuf :=  BytesOfString (DateTimeToGeneralizedTime(FThisUpdate));
    STag.Content := TmpBuf;
    ReleaseArray(TmpBuf);
  end;
  if FNextUpdate <> 0 then
  begin
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    if FNextUpdate < YEAR2050 then
    begin
      STag.TagId := SB_ASN1_UTCTIME;

      TmpBuf :=  BytesOfString (DateTimeToUTCTime(FNextUpdate));
      STag.Content := TmpBuf;
      ReleaseArray(TmpBuf);
    end
    else
    begin
      STag.TagId := SB_ASN1_GENERALIZEDTIME;
      TmpBuf :=  BytesOfString (DateTimeToGeneralizedTime(FNextUpdate));
      STag.Content := TmpBuf;
      ReleaseArray(TmpBuf);
    end;
  end;
  if FItems.Count > 0 then
  begin
    CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    SaveRevokedCertificates(CTag);
  end;
  if (FExtensions.Included <>  [] ) or (FExtensions.OtherCount > 0) then
  begin
    CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    CTag.TagId := $A0;
    CTag := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
    FExtensions.SaveToTag(CTag);
  end;
end;

procedure TElCertificateRevocationList.SaveRevokedCertificates(Tag : TElASN1ConstrainedTag);
var
  I : integer;
  CTag, ExtTag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  TmpBuf : ByteArray;
begin
  Tag.TagId := SB_ASN1_SEQUENCE;
  for I := 0 to FItems.Count - 1 do
  begin
    CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    CTag.TagId := SB_ASN1_SEQUENCE;
    STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
    STag.TagId := SB_ASN1_INTEGER;
    STag.Content := TElRevocationItem(FItems[I]).SerialNumber;
    STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
    if TElRevocationItem(FItems[I]).FRevocationDate < YEAR2050 then
    begin
      STag.TagId := SB_ASN1_UTCTIME;
      TmpBuf :=  BytesOfString (DateTimeToUTCTime(TElRevocationItem(FItems[I]).RevocationDate));
      STag.Content := TmpBuf;
      ReleaseArray(TmpBuf);
    end
    else
    begin
      STag.TagId := SB_ASN1_GENERALIZEDTIME;
      TmpBuf :=  BytesOfString (DateTimeToGeneralizedTime(TElRevocationItem(FItems[I]).RevocationDate));
      STag.Content := TmpBuf;
      ReleaseArray(TmpBuf);
    end;
    if (TElRevocationItem(FItems[I]).Extensions.Included <>  [] ) or
      (TElRevocationItem(FItems[I]).Extensions.OtherCount > 0) then
    begin
      ExtTag := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
      TElRevocationItem(FItems[I]).Extensions.SaveToTag(ExtTag);
    end;
  end;
end;       

procedure TElCertificateRevocationList.ClearList;
begin
  while FItems.Count > 0 do
  begin
    TElRevocationItem(FItems[FItems.Count - 1]). Free ;
    FItems.Count := FItems.Count - 1;
  end;
  SetLength(FCRLBinary, 0);
end;

procedure TElCertificateRevocationList.Clear;
begin
  ClearList;
end;

function TElCertificateRevocationList.ParseCertList(Tag : TElASN1ConstrainedTag) :
  integer;
var
  Index : integer;
begin
  Result := SB_CRL_ERROR_INVALID_FORMAT;
  if (Tag.TagId <> SB_ASN1_SEQUENCE) then
    Exit;
  if Tag.Count < 1 then
    Exit;
  Index := 0;
  if not Tag.GetField(Index).IsConstrained then
  begin
    if (Tag.GetField(Index).TagId <> SB_ASN1_INTEGER) or
      (Length(TElASN1SimpleTag(Tag.GetField(Index)).Content) <> 1) or
      ((TElASN1SimpleTag(Tag.GetField(Index)).Content[0] <> byte(2)) and
       (TElASN1SimpleTag(Tag.GetField(Index)).Content[0] <> byte(1))
      ) then
      Exit
    else
      FVersion := 2;
    Inc(Index);
  end;

  if Assigned(FSignatureAlgorithm) then
    FreeAndNil(FSignatureAlgorithm);

  try
    FSignatureAlgorithm := TElAlgorithmIdentifier.CreateFromTag(TElASN1ConstrainedTag(Tag.GetField(Index)));
  except
    Result := SB_CRL_ERROR_BAD_SIGNATURE_ALGORITHM;
    Exit;
  end;

  Result := SB_CRL_ERROR_INVALID_FORMAT;
  Inc(Index);
  if Index >= Tag.Count then
    Exit;
  if (not Tag.GetField(Index).IsConstrained) then
    Exit;
  if not FIssuer.LoadFromTag(TElASN1ConstrainedTag(Tag.GetField(Index)){$ifndef HAS_DEF_PARAMS}, false {$endif}) then
    Exit;
  Inc(Index);
  if Index >= Tag.Count then
    Exit;
  if (Tag.GetField(Index).IsConstrained) then
    Exit;
  if (Tag.GetField(Index).TagId = SB_ASN1_UTCTIME) then
    FThisUpdate := UTCTimeToDateTime(StringOfBytes(TElASN1SimpleTag(Tag.GetField(Index)).Content))
  else
  if (Tag.GetField(Index).TagId = SB_ASN1_GENERALIZEDTIME) then
    FThisUpdate := GeneralizedTimeToDateTime(StringOfBytes(TElASN1SimpleTag(Tag.GetField(Index)).Content))
  else
    Exit;
  Inc(Index);
  Result := 0;
  if Index >= Tag.Count then
  begin
    FNextUpdate := 0;
    Exit;
  end;
  if (not Tag.GetField(Index).IsConstrained) then
  begin
    if (Tag.GetField(Index).TagId = SB_ASN1_UTCTIME) then
      FNextUpdate := UTCTimeToDateTime(StringOfBytes(TElASN1SimpleTag(Tag.GetField(Index)).Content))
    else
    if (Tag.GetField(Index).TagId = SB_ASN1_GENERALIZEDTIME) then
      FNextUpdate := GeneralizedTimeToDateTime(StringOfBytes(TElASN1SimpleTag(Tag.GetField(Index)).Content))
    else
      Exit;
    Inc(Index);
  end;
  if Index >= Tag.Count then
    Exit;
  if (Tag.GetField(Index).IsConstrained) and (Tag.GetField(Index).TagId = SB_ASN1_SEQUENCE) then
  begin
    Result := ParseRevokedCertificates(TElASN1ConstrainedTag(Tag.GetField(Index)));
    Inc(Index);
  end;
  if Index >= Tag.Count then
    Exit;
  if (Tag.GetField(Index).IsConstrained) and (Tag.GetField(Index).TagId = SB_ASN1_A0) then
  begin
    if FVersion <> 2 then
    begin
      Result := SB_CRL_ERROR_UNSUPPORTED_VERSION;
      Exit;
    end;
    FExtensions.LoadFromTag(TElASN1ConstrainedTag(Tag.GetField(Index)));
  end
  else
    Exit;
  Result := 0;
end;

function TElCertificateRevocationList.ParseRevokedCertificates(Tag :
  TElASN1ConstrainedTag) : integer;
var
  I : integer;
  TagSeq : TElASN1ConstrainedTag;
  Serial : ByteArray;
  RevDate : TElDateTime;
  Item : TElRevocationItem;
begin
  RevDate := 0;
  Result := SB_CRL_ERROR_INVALID_FORMAT;
  if (Tag.TagId <> SB_ASN1_SEQUENCE) then
    Exit;
  for I := 0 to Tag.Count - 1 do
  begin
    if (not Tag.GetField(I).IsConstrained) or (Tag.GetField(I).TagId <>
      SB_ASN1_SEQUENCE) then
      Exit;
    TagSeq := TElASN1ConstrainedTag(Tag.GetField(I));
    if TagSeq.Count < 2 then
      Exit;
      
      
    if (TagSeq.GetField(0).IsConstrained) or (TagSeq.GetField(0).TagId <>
      SB_ASN1_INTEGER) then
      Exit;
    Serial := TElASN1SimpleTag(TagSeq.GetField(0)).Content;
    if (not TagSeq.GetField(1).IsConstrained) and (TagSeq.GetField(1).TagId = SB_ASN1_UTCTIME) then
      RevDate := UTCTimeToDateTime(StringOfBytes(TElASN1SimpleTag(TagSeq.GetField(1)).Content))
    else
    if (not TagSeq.GetField(1).IsConstrained) and (TagSeq.GetField(1).TagId = SB_ASN1_GENERALIZEDTIME) then
      RevDate := GeneralizedTimeToDateTime(StringOfBytes(TElASN1SimpleTag(TagSeq.GetField(1)).Content))
    else
    begin
      Exit;
    end;

    if (TagSeq.Count = 3) and (FVersion <> 2) then
    begin
      Result := SB_CRL_ERROR_UNSUPPORTED_VERSION;
      Exit;
    end;

    Item := TElRevocationItem.Create;
    if TagSeq.Count = 3 {and FVersion = 2 but we skip this as this has been checked above} then
      Result := Item.Extensions.LoadFromTag(TElASN1ConstrainedTag(TagSeq.GetField(2)));

    Item.SerialNumber := Serial;
    Item.RevocationDate := RevDate;
    FItems.Add(Item);
  end;
  
  Result := 0;
end;

function TElCertificateRevocationList.Validate(Certificate : TElX509Certificate) :
  integer;
var
  I : integer;
  Lst : TElByteArrayList;
  Crypto : TElPublicKeyCrypto;
  KeyMaterial : TElKeyMaterial;
  Factory : TElPublicKeyCryptoFactory;
begin
  CheckLicenseKey();
  if not Assigned(Certificate) then
  begin
    Result := SB_CRL_ERROR_INVALID_CERTIFICATE;
    Exit;
  end;
  
  Lst := TElByteArrayList.Create;
  try
    Result := 0;
    for I := 0 to FIssuer.Count - 1 do
    begin
      Certificate.SubjectRDN.GetValuesByOID(FIssuer.OIDs[I], Lst);
      if Lst.IndexOf(FIssuer.Values[I]) < 0 then
      begin
        Result := SB_CRL_ERROR_INVALID_ISSUER;
        Break;
      end;
    end;
  finally
    FreeAndNil(Lst);
  end;

  if Result <> 0 then
    Exit;

  Crypto := nil;
  try
    Factory := TElPublicKeyCryptoFactory.Create();
    try
      Crypto := Factory.CreateInstance(FSignatureAlgorithm.Algorithm);
    finally
      FreeAndNil(Factory);
    end;
  except
    ;
  end;
  if (Crypto = nil) then
    Result := SB_CRL_ERROR_UNSUPPORTED_ALGORITHM;
  if Result <> 0 then
    Exit;

  try
    if Crypto is TElRSAPublicKeyCrypto then
      TElRSAPublicKeyCrypto(Crypto).UseAlgorithmPrefix := true;

    try
      KeyMaterial := Certificate.KeyMaterial;//CreateKeyMaterialFromCertificate(Certificate);
      if KeyMaterial = nil then
      begin
        Result := SB_CRL_ERROR_UNSUPPORTED_ALGORITHM;
        Exit;
      end;
      
      Crypto.LoadParameters(FSignatureAlgorithm);
      Crypto.KeyMaterial := TElPublicKeyMaterial(KeyMaterial);
    except
      Result := SB_CRL_ERROR_INVALID_CERTIFICATE;
      Exit;
    end;

    if (Length(FTBS) <> 0) then
    begin
      try
        if Crypto.VerifyDetached(@FTBS[0], Length(FTBS), @FSignature[0], Length(FSignature)) = pkvrSuccess then
          Result := 0
        else
          Result := SB_CRL_ERROR_INVALID_SIGNATURE;
      except
        Result := SB_CRL_ERROR_INTERNAL_ERROR;
      end;
    end
    else
      Result := SB_CRL_ERROR_NOTHING_TO_VERIFY;
  finally
    FreeAndNil(Crypto);
  end;
end;

function TElCertificateRevocationList.IsPresent(Certificate : TElX509Certificate) :
  boolean;
begin
  Result := (IndexOf(Certificate) >= 0);
end;

function TElCertificateRevocationList.IndexOf(Certificate : TElX509Certificate) : integer;
var
  Lst : TElByteArrayList;
  I : integer;
begin
  Result := -1;
  Lst := TElByteArrayList.Create;
  try
    for I := 0 to FIssuer.Count - 1 do
    begin
      Certificate.IssuerRDN.GetValuesByOID(FIssuer.OIDs[I], Lst);
      if Lst.IndexOf(FIssuer.Values[I]) < 0 then
        Exit;
    end;
  finally
    FreeAndNil(Lst);
  end;

  for I := 0 to FItems.Count - 1 do
    if SerialNumberCorresponds(Certificate, TElRevocationItem(FItems[I]).FSerialNumber) then
    begin
      Result := I;
      Break;
    end;
end;

function TElCertificateRevocationList.Add(Certificate : TElX509Certificate) : integer;
var
  Lst : TElByteArrayList;
  I : integer;
  Item : TElRevocationItem;
begin
  CheckLicenseKey();
  Lst := TElByteArrayList.Create;
  try
    for I := 0 to FIssuer.Count - 1 do
    begin
      Certificate.IssuerRDN.GetValuesByOID(FIssuer.OIDs[I], Lst);
      if Lst.IndexOf(FIssuer.Values[I]) < 0 then
      begin
        Result := -1;
        Exit;
      end;
    end;
  finally
    FreeAndNil(Lst);
  end;

  for I := 0 to FItems.Count - 1 do
  begin
    if SerialNumberCorresponds(Certificate, TElRevocationItem(FItems[I]).FSerialNumber) then
    begin
      Result := -1;
      Exit;
    end;
  end;
  Item := TElRevocationItem.Create;
  Item.FSerialNumber := GetOriginalSerialNumber(Certificate);
  Item.FRevocationDate := Now;
  {$ifdef SB_WINDOWS}
  Item.FRevocationDate := LocalTimeToUTCTime(Item.FRevocationDate);
   {$endif}
  //FChanged := true;
  Result := FItems.Add(Item);
end;

function TElCertificateRevocationList.Add(const SerialNumber : ByteArray) : integer;
var
  I : integer;
  Item : TElRevocationItem;
begin
  for I := 0 to FItems.Count - 1 do
  begin
    if CompareContent(TElRevocationItem(FItems[I]).FSerialNumber,
      SerialNumber) then
    begin
      Result := -1;
      Exit;
    end;
  end;
  Item := TElRevocationItem.Create;
  Item.FSerialNumber := CloneArray(SerialNumber);
  Item.FRevocationDate := Now;
  {$ifdef SB_WINDOWS}
  Item.FRevocationDate := LocalTimeToUTCTime(Item.FRevocationDate);
   {$endif}
  //FChanged := true;
  Result := FItems.Add(Item);
end;

function TElCertificateRevocationList.Remove(Certificate : TElX509Certificate) : boolean;
var
  Lst : TElByteArrayList;
  I : integer;
  // Item : TElRevocationItem;
begin
  Lst := TElByteArrayList.Create;
  try
    for I := 0 to FIssuer.Count - 1 do
    begin
      Certificate.IssuerRDN.GetValuesByOID(FIssuer.OIDs[I], Lst);
      if Lst.IndexOf(FIssuer.Values[I]) < 0 then
      begin
        Result := false;
        Exit;
      end;
    end;
  finally
    FreeAndNil(Lst);
  end;

  for I := 0 to FItems.Count - 1 do
  begin
    if SerialNumberCorresponds(Certificate, TElRevocationItem(FItems[I]).FSerialNumber) then
    begin
      TElRevocationItem(FItems[I]). Free ;
      FItems.Delete(I);
      Result := true;
      Exit;
    end;
  end;
  //FChanged := true;
  Result := false;
end;

function TElCertificateRevocationList.Remove(Index : integer) : boolean;
begin
  if (Index >= 0) and (Index < FItems.Count) then
  begin
    TElRevocationItem(FItems[Index]). Free ;
    FItems.Delete(Index);
    Result := true;
  end
  else
    Result := false;
end;


function TElCertificateRevocationList.GetItems(Index : integer) : TElRevocationItem;
begin
  Result := TElRevocationItem(FItems[Index]);
end;

function TElCertificateRevocationList.GetCount : integer;
begin
  Result := FItems.Count;
end;

function TElCertificateRevocationList.GetCRLSize : integer;
begin
  Result := Length(FCRLBinary);
end;

function TElCertificateRevocationList.GetSignatureAlgorithm : integer;
begin
  if Assigned(FSignatureAlgorithm) then
    Result := FSignatureAlgorithm.Algorithm
  else
    Result := SB_ALGORITHM_UNKNOWN;
end;

function TElCertificateRevocationList.SameCRL(CRL : TElCertificateRevocationList; CheckUpdateTime : boolean) : boolean;
var nb : boolean;
    IDP1, IDP2 : TElIssuingDistributionPointCRLExtension;
begin
  result := false;

  // Compare issuer
  if CompareRDN(Issuer, CRL.Issuer) then
  begin
    // if both CRLs don't have IssuingDistributionPoint extension, then they are the same
    nb := ( not (crlIssuingDistributionPoint in Extensions.Included) )
          and
          ( not (crlIssuingDistributionPoint in CRL.Extensions.Included) );
    if nb then
    begin
      result := true;
      exit;
    end;

    // if only one CRL has IssuingDistributionPoint extension, then they are NOT the same
    nb := ( (crlIssuingDistributionPoint in Extensions.Included) )
          and
          ( (crlIssuingDistributionPoint in CRL.Extensions.Included) );
    if not nb then
      exit;

    // and now we must compare the whole extension
    IDP1 := CRL.Extensions.IssuingDistributionPoint;
    IDP2 := CRL.Extensions.IssuingDistributionPoint;
    if (IDP1 = nil) or (IDP2 = nil) then
      exit;

    if (IDP1.FReasonFlags <> IDP2.FReasonFlags) or
       (IDP1.FOnlyContainsUserCerts <> IDP2.FOnlyContainsUserCerts) or
       (IDP1.FOnlyContainsCACerts <> IDP2.FOnlyContainsCACerts) or
       (IDP1.FOnlyContainsAttributeCerts <> IDP2.FOnlyContainsAttributeCerts) or
       (IDP1.FIndirectCRL <> IDP2.FIndirectCRL) then
      exit;

    result := IDP1.FDistributionPoint.Equals(IDP2.FDistributionPoint);
    if CheckUpdateTime and result then 
      result := (Self.ThisUpdate = CRL.ThisUpdate) and (Self.NextUpdate = CRL.NextUpdate);    
  end;
end;

function TElCertificateRevocationList.LoadFromStream(Stream : TStream; Count : integer = 0) : integer;
var
  Buf : ByteArray;
  Size : integer;
begin
  if Count = 0 then
    Count := Stream.Size - Stream.Position
  else
    Count := Min(Count, Stream.Size - Stream.Position);
  SetLength(Buf, Count);
  if Count > 0 then
  begin
    Size := Stream.Read(Buf[0], Count);
    Result := LoadFromBuffer(@Buf[0], Size);
  end
  else
    Result := SB_CRL_ERROR_INVALID_FORMAT;
end;



function TElCertificateRevocationList.LoadFromBufferPEM(Buffer: pointer;
  Size: integer; const Passphrase: string = '') : integer;
var
  Header : string;
  OutSize : integer;
  Buf : ByteArray;
  PemResult : integer;
begin
  OutSize := 0;
  SBPEM.Decode(Buffer, Size, nil, Passphrase, OutSize, Header);  
  SetLength(Buf, OutSize);
  PemResult := SBPEM.Decode(Buffer, Size, @Buf[0], Passphrase, OutSize, Header);
  if PemResult <> 0 then
  begin
    Result := PemResult;
    Exit;
  end;
  Result := LoadFromBuffer(@Buf[0], OutSize);
  ReleaseArray(Buf);
end;


function TElCertificateRevocationList.SaveToBufferPEM(Buffer: pointer; var Size: integer;
  const Passphrase: string = ''): integer;
var
  Buf : ByteArray;
  Sz : integer;
begin
  Sz := 0;
  SaveToBuffer(nil, Sz);
  SetLength(Buf, Sz);
  Result := SaveToBuffer(@Buf[0], Sz);
  if Result <> 0 then Exit;
  if not SBPEM.Encode(@Buf[0], Sz, Buffer, Size, 'X509 CRL',
    false, Passphrase) then
    Result := SB_CRL_ERROR_INTERNAL_ERROR;
end;

function TElCertificateRevocationList.LoadFromStreamPEM(Stream : TStream;
  const Passphrase: string = ''; Count : integer = 0): integer;
var
  Buf : ByteArray;
begin
  if Count = 0 then
    Count :=  Stream.Size  - Stream.Position;
  SetLength(Buf, Count);
  if Count > 0 then
  begin
    Stream.ReadBuffer(Buf[0], Length(Buf));
    Result := LoadFromBufferPEM(@Buf[0], Length(Buf));
  end
  else
    Result := SB_CRL_ERROR_INVALID_FORMAT;
end;


procedure TElCertificateRevocationList.Assign(Source : TPersistent);
var
  Buf : ByteArray;
  Size : integer;
begin
  if not (Source is TElCertificateRevocationList) then
    raise EConvertError.Create(SInvalidCRL);
  Size := 0;
  Tag := TElCertificateRevocationList(Source).Tag;
//  TextTag := TElCertificateRevocationList(Source).TextTag;

  TElCertificateRevocationList(Source).SaveToBuffer(nil, Size);
  SetLength(Buf, Size);
  TElCertificateRevocationList(Source).SaveToBuffer(@Buf[0], Size);
  if LoadFromBuffer(@Buf[0], Size) <> 0 then
    raise EElCRLError.Create(SInvalidCRL);
  Location := TElCertificateRevocationList(Source).Location;
  ReleaseArray(Buf);
end;


////////////////////////////////////////////////////////////////////////////////
// TElRevocationItem implementation

constructor TElRevocationItem.Create;
begin
  inherited;
  FExtensions := TElCRLEntryExtensions.Create;
end;

 destructor  TElRevocationItem.Destroy;
begin
  FreeAndNil(FExtensions);
  inherited;
end;

procedure TElRevocationItem.SetSerialNumber(const V : ByteArray);
begin
  FSerialNumber := CloneArray(V);
end;

////////////////////////////////////////////////////////////////////////////////
// TElCRLExtensions implementation

constructor TElCRLExtensions.Create;
begin
  inherited;
  FOtherExtensions := TElList.Create;
  FIssuerAlternativeName := TElAlternativeNameExtension.Create(true);
  FAuthorityKeyIdentifier := TElAuthorityKeyIdentifierCRLExtension.Create;
  FCRLNumber := TElCRLNumberCRLExtension.Create;
  FDeltaCRLIndicator := TElDeltaCRLIndicatorCRLExtension.Create;
  FDistributionPoint := TElIssuingDistributionPointCRLExtension.Create;
end;

 destructor  TElCRLExtensions.Destroy;
begin
  ClearList;
  FreeAndNil(FIssuerAlternativeName);
  FreeAndNil(FAuthorityKeyIdentifier);
  FreeAndNil(FCRLNumber);
  FreeAndNil(FDistributionPoint);
  FreeAndNil(FDeltaCRLIndicator);
  FreeAndNil(FOtherExtensions);
  inherited;
end;

function TElCRLExtensions.LoadFromTag(Tag : TElASN1ConstrainedTag) : integer;
var
  I, Index : integer;
  CTag : TElASN1ConstrainedTag;
  ExtOID : ByteArray;
  ExtCritical : boolean;
begin
  Result := SB_CRL_ERROR_INVALID_FORMAT;
  if Tag.TagId <> SB_ASN1_A0 then
    Exit;
  if Tag.Count <> 1 then
    Exit;
  Tag := TElASN1ConstrainedTag(Tag.GetField(0));
  for I := 0 to Tag.Count - 1 do
  begin
    if (not Tag.GetField(I).IsConstrained) or (Tag.GetField(I).TagId <> SB_ASN1_SEQUENCE) then
      Exit;
    CTag := TElASN1ConstrainedTag(Tag.GetField(I));
    if CTag.Count < 2 then
      Exit;
    if (CTag.GetField(0).IsConstrained) or (CTag.GetField(0).TagId <> SB_ASN1_OBJECT) then
      Exit;
    ExtOID := TElASN1SimpleTag(CTag.GetField(0)).Content;
    if CTag.Count = 3 then
    begin
      if (CTag.GetField(1).IsConstrained) or (CTag.GetField(1).TagId <> SB_ASN1_BOOLEAN) then
        Exit;
      ExtCritical := (Length(TElASN1SimpleTag(CTag.GetField(1)).Content) <> 0) and
                      (TElASN1SimpleTag(CTag.GetField(1)).Content[0] <> byte(0));
      Index := 2;
    end
    else
    begin
      ExtCritical := false;
      Index := 1;
    end;
    if (CTag.GetField(Index).IsConstrained) or (CTag.GetField(Index).TagId <> SB_ASN1_OCTETSTRING) then
      Exit;
    AddExtension(ExtOID, ExtCritical, TElASN1SimpleTag(CTag.GetField(Index)).Content);
  end;
  Result := 0;
end;

procedure TElCRLExtensions.SaveToTag(Tag : TElASN1ConstrainedTag);
var
  TagSeq : TElASN1ConstrainedTag;
  I : integer;
begin
  Tag.TagId := SB_ASN1_SEQUENCE;
  if crlAuthorityKeyIdentifier in FIncluded then
  begin
    TagSeq := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    FAuthorityKeyIdentifier.SaveToTag(TagSeq);  
  end;
  if crlIssuerAlternativeName in FIncluded then
  begin
    TagSeq := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    FIssuerAlternativeName.OID := SB_OID_EXT_ISSUERALTERNATIVENAME;
    FIssuerAlternativeName.SaveToTag(TagSeq);
  end;
  if crlCRLNumber in FIncluded then
  begin
    TagSeq := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    FCRLNumber.SaveToTag(TagSeq);
  end;
  if crlDeltaCRLIndicator in FIncluded then
  begin
    TagSeq := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    FDeltaCRLIndicator.SaveToTag(TagSeq);
  end;
  if crlIssuingDistributionPoint in FIncluded then
  begin
    TagSeq := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    FDistributionPoint.SaveToTag(TagSeq);
  end;
  for I := 0 to OtherCount - 1 do
  begin
    TagSeq := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    OtherExtensions[I].SaveToTag(TagSeq);
  end;
end;

function TElCRLExtensions. GetOther (Index : integer) : TElCRLExtension;
begin
  Result := TElCRLExtension(FOtherExtensions[Index]);
end;

function TElCRLExtensions.GetOtherCount : integer;
begin
  Result := FOtherExtensions.Count;
end;

procedure TElCRLExtensions.SetOtherCount(Value : integer);
var
  I : integer;
begin
  while FOtherExtensions.Count < Value do
    FOtherExtensions.Add(TElCRLExtension.Create);
  if FOtherExtensions.Count > Value then
  begin
    for I := Value to FOtherExtensions.Count - 1 do
      TElCustomExtension(FOtherExtensions[I]). Free ;
    FOtherExtensions.Count := Value;
  end;
end;

procedure TElCRLExtensions.ClearList;
var
  I : integer;
begin
  for I := 0 to FOtherExtensions.Count - 1 do
    TElCRLExtension(FOtherExtensions[I]). Free ;
  FOtherExtensions.Clear;
end;

function TElCRLExtensions.AddExtension(const OID : ByteArray; Critical :
    boolean; const Value : ByteArray): Integer;
var
  Extn : TElCRLExtension;
begin
  if CompareContent(OID, SB_OID_EXT_AUTHORITYKEYIDENTIFIER) then
  begin
    FreeAndNil(FAuthorityKeyIdentifier);
    FAuthorityKeyIdentifier := TElAuthorityKeyIdentifierCRLExtension.Create;
    FIncluded := FIncluded  + [crlAuthorityKeyIdentifier] ;
    Extn := FAuthorityKeyIdentifier;
  end
  else
  if CompareContent(OID, SB_OID_EXT_ISSUERALTERNATIVENAME) then
  begin
    FreeAndNil(FIssuerAlternativeName);
    FIssuerAlternativeName := TElAlternativeNameExtension.Create(true);
    FIncluded := FIncluded  + [crlIssuerAlternativeName] ;
    Extn := FIssuerAlternativeName;
  end
  else
  if CompareContent(OID, SB_OID_EXT_CRLNUMBER) then
  begin
    FreeAndNil(FCRLNumber);
    FCRLNumber := TElCRLNumberCRLExtension.Create;
    FIncluded := FIncluded  + [crlCRLNumber] ;
    Extn := FCRLNumber;
  end
  else
  if CompareContent(OID, SB_OID_EXT_DELTACRLINDICATOR) then
  begin
    FreeAndNil(FDeltaCRLIndicator);
    FDeltaCRLIndicator := TElDeltaCRLIndicatorCRLExtension.Create;
    FIncluded := FIncluded  + [crlDeltaCRLIndicator] ;
    Extn := FDeltaCRLIndicator;
  end
  else
  if CompareContent(OID, SB_OID_EXT_ISSUINGDISTRIBUTIONPOINT) then
  begin
    FreeAndNil(FDistributionPoint);
    FDistributionPoint := TElIssuingDistributionPointCRLExtension.Create;
    FIncluded := FIncluded  + [crlIssuingDistributionPoint] ;
    Extn := FDistributionPoint;
  end
  else
  begin
    Extn := TElCRLExtension.Create;
    FOtherExtensions.Add(Extn);
  end;
  
  Extn.Critical := Critical;
  Extn.Value := CloneArray(Value);
  Extn.OID := CloneArray(OID);
  Result := 0;
end;

////////////////////////////////////////////////////////////////////////////////
// TElCRLEntryExtensions implementation

constructor TElCRLEntryExtensions.Create;
begin
  inherited;
  FOtherExtensions := TElList.Create;
  FReasonCode := TElReasonCodeCRLExtension.Create;
  FHoldInstructionCode := TElHoldInstructionCodeCRLExtension.Create;
  FInvalidityDate := TElInvalidityDateCRLExtension.Create;
  FCertificateIssuer := TElCertificateIssuerCRLExtension.Create;
end;

 destructor  TElCRLEntryExtensions.Destroy;
begin
  ClearList;
  FreeAndNil(FReasonCode);
  FreeAndNil(FHoldInstructionCode);
  FreeAndNil(FInvalidityDate);
  FreeAndNil(FCertificateIssuer);
  FreeAndNil(FOtherExtensions);
  inherited;
end;

function TElCRLEntryExtensions. GetOther (Index : integer) : TElCRLExtension;
begin
  Result := TElCRLExtension(FOtherExtensions[Index]);
end;

function TElCRLEntryExtensions.GetOtherCount : integer;
begin
  Result := FOtherExtensions.Count;
end;

procedure TElCRLEntryExtensions.SetOtherCount(Value : integer);
var
  I : integer;
begin
  while FOtherExtensions.Count < Value do
    FOtherExtensions.Add(TElCRLExtension.Create);
  if FOtherExtensions.Count > Value then
  begin
    for I := Value to FOtherExtensions.Count - 1 do
      TElCustomExtension(FOtherExtensions[I]). Free ;
    FOtherExtensions.Count := Value;
  end;
end;

procedure TElCRLEntryExtensions.ClearList;
var
  I : integer;
begin
  for I := 0 to FOtherExtensions.Count - 1 do
    TElCRLExtension(FOtherExtensions[I]). Free ;
  FOtherExtensions.Clear;
end;

function TElCRLEntryExtensions.LoadFromTag(Tag : TElASN1ConstrainedTag) : integer;
var
  I, Index : integer;
  CTag : TElASN1ConstrainedTag;
  ExtOID : ByteArray;
  ExtCritical : boolean;
begin
  Result := SB_CRL_ERROR_INVALID_FORMAT;
  if Tag.TagId <> SB_ASN1_SEQUENCE then
    Exit;
  for I := 0 to Tag.Count - 1 do
  begin
    if (not Tag.GetField(I).IsConstrained) or (Tag.GetField(I).TagId <> SB_ASN1_SEQUENCE) then
      Exit;
    CTag := TElASN1ConstrainedTag(Tag.GetField(I));
    if CTag.Count < 2 then
      Exit;
    if (CTag.GetField(0).IsConstrained) or (CTag.GetField(0).TagId <> SB_ASN1_OBJECT) then
      Exit;
    ExtOID := TElASN1SimpleTag(CTag.GetField(0)).Content;
    if CTag.Count = 3 then
    begin
      if (CTag.GetField(1).IsConstrained) or (CTag.GetField(1).TagId <> SB_ASN1_BOOLEAN) then
        Exit;

      ExtCritical := (Length(TElASN1SimpleTag(CTag.GetField(1)).Content) <> 0) and
        (TElASN1SimpleTag(CTag.GetField(1)).Content[0] <> byte(0));

      Index := 2;
    end
    else
    begin
      ExtCritical := false;
      Index := 1;
    end;
    if (CTag.GetField(Index).IsConstrained) or (CTag.GetField(Index).TagId <> SB_ASN1_OCTETSTRING) then
      Exit;
    AddExtension(ExtOID, ExtCritical, TElASN1SimpleTag(CTag.GetField(Index)).Content);
  end;
  Result := 0;
end;

procedure TElCRLEntryExtensions.SaveToTag(Tag : TElASN1ConstrainedTag);
var
  TagSeq : TElASN1ConstrainedTag;
  I : integer;
begin
  Tag.TagId := SB_ASN1_SEQUENCE;
  if crlReasonCode in FIncluded then
  begin
    TagSeq := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    FReasonCode.SaveToTag(TagSeq);
  end;
  if crlHoldInstructionCode in FIncluded then
  begin
    TagSeq := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    FHoldInstructionCode.SaveToTag(TagSeq);
  end;
  if crlInvalidityDate in FIncluded then
  begin
    TagSeq := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    FInvalidityDate.SaveToTag(TagSeq);
  end;
  if crlCertificateIssuer in FIncluded then
  begin
    TagSeq := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    FCertificateIssuer.SaveToTag(TagSeq);
  end;
  for I := 0 to OtherCount - 1 do
  begin
    TagSeq := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    OtherExtensions[I].SaveToTag(TagSeq);
  end;
end;

function TElCRLEntryExtensions.AddExtension(const OID : ByteArray; Critical :
    boolean; const Value : ByteArray): Integer;
var
  Extn : TElCustomExtension;
begin
  if CompareContent(OID, SB_OID_EXT_REASONCODE) then
  begin
    FreeAndNil(FReasonCode);
    FReasonCode := TElReasonCodeCRLExtension.Create;
    FIncluded := FIncluded  + [crlReasonCode] ;
    Extn := FReasonCode;
  end
  else
  if CompareContent(OID, SB_OID_EXT_HOLDINSTRUCTIONCODE) then
  begin
    FreeAndNil(FHoldInstructionCode);
    FHoldInstructionCode := TElHoldInstructionCodeCRLExtension.Create;
    FIncluded := FIncluded  + [crlHoldInstructionCode] ;
    Extn := FHoldInstructionCode;
  end
  else
  if CompareContent(OID, SB_OID_EXT_INVALIDITYDATE) then
  begin
    FIncluded := FIncluded  + [crlInvalidityDate] ;
    Extn := FInvalidityDate;
  end
  else
  if CompareContent(OID, SB_OID_EXT_CERTIFICATEISSUER) then
  begin
    FreeAndNil(FCertificateIssuer);
    FCertificateIssuer := TElCertificateIssuerCRLExtension.Create;
    FIncluded := FIncluded  + [crlCertificateIssuer] ;
    Extn := FCertificateIssuer;
  end
  else
  begin
    Extn := TElCRLExtension.Create;
    FOtherExtensions.Add(Extn);
  end;
  
  Extn.OID := CloneArray(OID);
  Extn.Critical := Critical;
  Extn.Value := CloneArray(Value);
  Result := 0;
end;

////////////////////////////////////////////////////////////////////////////////
// TElAuthorityKeyIdentifierCRLExtension implementation

constructor TElAuthorityKeyIdentifierCRLExtension.Create;
begin
  inherited;
  FAuthorityCertIssuer := TElGeneralNames.Create;
  IssuerSet := false;
end;

 destructor  TElAuthorityKeyIdentifierCRLExtension.Destroy;
begin
  FreeAndNil(FAuthorityCertIssuer);
  inherited;
end;

procedure TElAuthorityKeyIdentifierCRLExtension.Clear;
begin
  SetLength(FKeyIdentifier, 0);
  SetLength(FAuthorityCertSerial, 0);
  FAuthorityCertIssuer.Clear;
  IssuerSet := false;
end;

function TElAuthorityKeyIdentifierCRLExtension.GetOID: ByteArray;
begin
  Result := SB_OID_EXT_AUTHORITYKEYIDENTIFIER;
end;

procedure TElAuthorityKeyIdentifierCRLExtension.SetOID(const Value :
    ByteArray);
begin
end;

procedure TElAuthorityKeyIdentifierCRLExtension.SetValue(const Value :
    ByteArray);
var
  Tag, SeqTag : TElASN1ConstrainedTag;
  CurrTagIndex : integer;
begin
  inherited;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if Tag.LoadFromBuffer(@Value[0], Length(Value)) then
    begin
      if (Tag.Count = 1) and (Tag.GetField(0).CheckType(SB_ASN1_SEQUENCE, true)) then
      begin
        SeqTag := TElASN1ConstrainedTag(Tag.GetField(0));
        CurrTagIndex := 0;
        if (CurrTagIndex < SeqTag.Count) and (SeqTag.GetField(CurrTagIndex).CheckType($80, false)) then
        begin
          FKeyIdentifier := TElASN1SimpleTag(SeqTag.GetField(CurrTagIndex)).Content;
          Inc(CurrTagIndex);
        end;
        if (CurrTagIndex < SeqTag.Count) and (SeqTag.GetField(CurrTagIndex).CheckType($A1, true)) then
        begin
          //ParseGeneralNames(TElASN1ConstrainedTag(SeqTag.GetField(CurrTagIndex)),
          //  FAuthorityCertIssuer, true, true);
          FAuthorityCertIssuer.LoadFromTag(TElASN1ConstrainedTag(SeqTag.GetField(CurrTagIndex)), true);
          Inc(CurrTagIndex);
        end;
        if (CurrTagIndex < SeqTag.Count) and (SeqTag.GetField(CurrTagIndex).CheckType($82, false)) then
        begin
          FAuthorityCertSerial := {RotateInteger}(TElASN1SimpleTag(SeqTag.GetField(CurrTagIndex)).Content);
        end;
      end
      else
        RaiseInvalidExtensionError;
    end
    else
      RaiseInvalidExtensionError;
  finally
    FreeAndNil(Tag);
  end;
end;

function TElAuthorityKeyIdentifierCRLExtension.GetValue: ByteArray;
var
  Tag, CTag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  Size : integer;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  Tag.TagId := SB_ASN1_SEQUENCE;
  if Length(FKeyIdentifier) > 0 then
  begin
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.TagId := $80;
    STag.Content := CloneArray(FKeyIdentifier);
  end;
  if FSaveIssuer then
  begin
    CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    FAuthorityCertIssuer.SaveToTag(CTag); //TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true))));
    CTag.TagId := $A1;
  end;
  if Length(FAuthorityCertSerial) > 0 then
  begin
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.TagId := $82;
    STag.Content := CloneArray(FAuthorityCertSerial);
  end;
  Size := 0;
  Tag.SaveToBuffer(nil, Size);
  SetLength(Result, Size);
  Tag.SaveToBuffer(@Result[0], Size);
  SetLength(Result, Size);
  FreeAndNil(Tag);
end;

procedure TElAuthorityKeyIdentifierCRLExtension.SetKeyIdentifier(const V : ByteArray);
begin
  FKeyIdentifier := CloneArray(V);
end;

procedure TElAuthorityKeyIdentifierCRLExtension.SetAuthorityCertSerial(const V : ByteArray);
begin
  FAuthorityCertSerial := CloneArray(V);
end;

////////////////////////////////////////////////////////////////////////////////
// TElCRLNumberCRLExtension implementation

procedure TElCRLNumberCRLExtension.Clear;
begin
  FBinaryNumber := EmptyArray;
end;

function TElCRLNumberCRLExtension.GetOID: ByteArray;
begin
  Result := SB_OID_EXT_CRLNUMBER;
end;

procedure TElCRLNumberCRLExtension.SetOID(const Value : ByteArray);
begin
end;

procedure TElCRLNumberCRLExtension.SetValue(const Value : ByteArray);
var
  {I, K, }Len : integer;
  TmpValue : ByteArray; // no need to release!
begin
  inherited;
  if Byte(Value[0]) <> SB_ASN1_INTEGER then
    Exit;
  Len := Byte(Value[1]);
  SetLength(TmpValue, Len);
  SBMove(Value, 2, TmpValue, 0, Len);
  FBinaryNumber := TmpValue;
end;

function TElCRLNumberCRLExtension.GetValue: ByteArray;
begin
  if Length(FBinaryNumber) = 0 then
  begin
    SetLength(Result, 3);
    Result[0 + 0] := SB_ASN1_INTEGER;
    Result[0 + 1] := $01;
    Result[0 + 2] := $00;
  end
  else
  begin
    SetLength(Result, 2 + Length(FBinaryNumber));
    Result[0] := SB_ASN1_INTEGER;
    Result[0 + 1] := Length(FBinaryNumber);

    SBMove(FBinaryNumber, 0, Result, 0+ 2, Length(FBinaryNumber));
  end;
end;

function TElCRLNumberCRLExtension.GetNumber: integer;
var
  K, I : integer;
begin
  if Length(FBinaryNumber) = 0 then
    Result := 0
  else
  if Length(FBinaryNumber) < 5 then
  begin
    Result := 0;
    K := 0;
    for I := Length(FBinaryNumber) downto 1 do
    begin
      Result := Result or (Ord(FBinaryNumber[I - 1 + 0]) shl K);
      Inc(K, 8);
    end;
  end
  else
    raise EElCRLError.Create(SNumberTooLong);
end;

procedure TElCRLNumberCRLExtension.SetNumber(Value: integer);
var
  V : ByteArray;
  Idx : integer;
begin
  if Value = 0 then
    SetLength(FBinaryNumber, 0)
  else
  begin
    V := GetBytes32(Value);
    Idx := 0;
    while (V[Idx] = 0) and (Idx < 4) do
      Inc(Idx);
    SetLength(FBinaryNumber, 4 - Idx);
    SBMove(V, Idx, FBinaryNumber, 0, Length(FBinaryNumber));
    ReleaseArray(V);
  end;
end;

procedure TElCRLNumberCRLExtension.SetBinaryNumber(const V: ByteArray);
begin
  FBinaryNumber := CloneArray(V);
end;

////////////////////////////////////////////////////////////////////////////////
// TElDeltaCRLIndicatorCRLExtension implementation

procedure TElDeltaCRLIndicatorCRLExtension.Clear;
begin
  FBinaryNumber := EmptyArray;
end;

function TElDeltaCRLIndicatorCRLExtension.GetOID: ByteArray;
begin
  Result := SB_OID_EXT_DELTACRLINDICATOR;
end;

procedure TElDeltaCRLIndicatorCRLExtension.SetOID(const Value : ByteArray);
begin
end;

procedure TElDeltaCRLIndicatorCRLExtension.SetValue(const Value : ByteArray);
var
  {I, K, }Len : integer;
  TmpValue : ByteArray; // No need to release!
begin
  inherited;
  if Byte(Value[0]) <> SB_ASN1_INTEGER then
    Exit;
  Len := Byte(Value[1]);
  SetLength(TmpValue, Len);
  SBMove(Value, 2, TmpValue, 0, Len);
  FBinaryNumber := TmpValue;
end;

function TElDeltaCRLIndicatorCRLExtension.GetValue: ByteArray;
begin
  if Length(FBinaryNumber) = 0 then
  begin
    SetLength(Result, 3);
    Result[0 + 0] := SB_ASN1_INTEGER;
    Result[0 + 1] := $01;
    Result[0 + 2] := $00;
  end
  else
  begin
    SetLength(Result, 2 + Length(FBinaryNumber));
    Result[0 + 0] := SB_ASN1_INTEGER;
    Result[0 + 1] := Length(FBinaryNumber);

    SBMove(FBinaryNumber, 0, Result, 0 + 2, Length(FBinaryNumber));
  end;
end;

function TElDeltaCRLIndicatorCRLExtension.GetNumber: integer;
var
  K, I : integer;
begin
  if Length(FBinaryNumber) = 0 then
    Result := 0
  else if Length(FBinaryNumber) < 5 then
  begin
    Result := 0;
    K := 0;
    for I := Length(FBinaryNumber) downto 1 do
    begin
      Result := Result or (Ord(FBinaryNumber[I - 1 + 0]) shl K);
      Inc(K, 8);
    end;
  end
  else
    raise EElCRLError.Create(SNumberTooLong);
end;

procedure TElDeltaCRLIndicatorCRLExtension.SetNumber(Value: integer);
var
  V : ByteArray;
  Idx : integer;
begin
  if Value = 0 then
    SetLength(FBinaryNumber, 0)
  else
  begin
    V := GetBytes32(Value);
    Idx := 0;
    while (V[Idx] = 0) and (Idx < 4) do
      Inc(Idx);
    SetLength(FBinaryNumber, 4 - Idx);
    SBMove(V, Idx, FBinaryNumber, 0, Length(FBinaryNumber));
    ReleaseArray(V);
  end;
end;

procedure TElDeltaCRLIndicatorCRLExtension.SetBinaryNumber(const Value: ByteArray);
begin
  FBinaryNumber := CloneArray(Value);
end;

////////////////////////////////////////////////////////////////////////////////
// TElReasonCodeCRLExtension implementation

procedure TElReasonCodeCRLExtension.Clear;
begin
  FReason := rfUnspecified;
  FRemoveFromCRL := false;
end;

function TElReasonCodeCRLExtension.GetOID : ByteArray;
begin
  Result := SB_OID_EXT_REASONCODE;
end;

procedure TElReasonCodeCRLExtension.SetOID(const Value : ByteArray);
begin
end;

procedure TElReasonCodeCRLExtension.SetValue(const Value : ByteArray);
var
  Data : byte;
const
  Reasons : array[0..10] of TSBCRLReasonFlag = 
    ( 
    rfUnspecified, rfKeyCompromise,
    rfCACompromise, rfAffiliationChanged, rfSuperseded, rfCessationOfOperation,
    rfCertificateHold, rfObsolete1, rfRemoveFromCRL, rfPrivilegeWithdrawn, rfAACompromise
    ) ;
begin
  inherited;
  FReason := rfUnspecified;
  if (Length(Value) > 2) and (Ord(byte(Value[0])) = SB_ASN1_ENUMERATED) then
  begin
    if Byte(Value[1 + 0]) >= 1 then
      Data := Byte(Value[2 + 0])
    else
      Data := 0;
    if (Data <= 10) then
    begin
      FReason := Reasons[Data];
      if Data = 8 then
        FRemoveFromCRL := true;
    end
    else
      FRemoveFromCRL := false;
  end;
end;

function TElReasonCodeCRLExtension.GetValue : ByteArray;
var
  Sym : Byte;
begin
  if FRemoveFromCRL then
    Sym := 8
  else
  begin
    case FReason of
      rfKeyCompromise : Sym := 1;
      rfCACompromise : Sym := 2;
      rfAffiliationChanged : Sym := 3;
      rfSuperseded : Sym := 4;
      rfCessationOfOperation : Sym := 5;
      rfCertificateHold : Sym := 6;
    else
      Sym := 0;
    end;
  end;
  SetLength(Result, 3);
  Result[0] := SB_ASN1_ENUMERATED;
  Result[1] := $01;
  Result[2] := Sym;
end;

////////////////////////////////////////////////////////////////////////////////
// TElHoldInstructionCodeCRLExtension implementation

{$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
 {$else}
var
 {$endif}

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS OFF}
 {$endif}

  SB_OID_EXT_HIC_NONE           : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$ce#$38#$02#$1 {$endif};
  SB_OID_EXT_HIC_CALLISSUER     : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$ce#$38#$02#$2 {$endif};
  SB_OID_EXT_HIC_REJECT         : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2a#$86#$48#$ce#$38#$02#$3 {$endif};

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS ON}
 {$endif}

procedure TElHoldInstructionCodeCRLExtension.Clear;
begin
  FCode := icNone;
end;

function TElHoldInstructionCodeCRLExtension.GetOID: ByteArray;
begin
  Result := SB_OID_EXT_HOLDINSTRUCTIONCODE;
end;

procedure TElHoldInstructionCodeCRLExtension.SetOID(const Value : ByteArray);
begin
end;

procedure TElHoldInstructionCodeCRLExtension.SetValue(const Value : ByteArray);
var
  Len : integer;
  Data : ByteArray;
begin
  inherited;
  if (Length(Value) > 3) and (Byte(Value[0]) = SB_ASN1_OBJECT) then
  begin
    Len := Byte(Value[1 + 0]);
    SetLength(Data, Len);
    SBMove(Value, 2, Data, 0, Len);
    if CompareContent(Data, SB_OID_EXT_HIC_CALLISSUER) then
      FCode := icCallIssuer
    else
    if CompareContent(Data, SB_OID_EXT_HIC_REJECT) then
      FCode := icReject
    else
      FCode := icNone;
  end
  else
    FCode := icNone;
  ReleaseArray(Data);
end;

function TElHoldInstructionCodeCRLExtension.GetValue: ByteArray;
begin
  if FCode = icNone then
    Result := SBConcatArrays(
      GetByteArrayFromByte(Byte(SB_ASN1_OBJECT)),
      GetByteArrayFromByte(Byte( Length(SB_OID_EXT_HIC_NONE) )),
      SB_OID_EXT_HIC_NONE)
  else
  if FCode = icCallIssuer then
    Result := SBConcatArrays(
      GetByteArrayFromByte(Byte(SB_ASN1_OBJECT)),
      GetByteArrayFromByte(Byte( Length(SB_OID_EXT_HIC_CALLISSUER) )),
      SB_OID_EXT_HIC_CALLISSUER)
  else
    Result := SBConcatArrays(
      GetByteArrayFromByte(Byte(SB_ASN1_OBJECT)),
      GetByteArrayFromByte(Byte( Length(SB_OID_EXT_HIC_REJECT) )),
      SB_OID_EXT_HIC_REJECT);
end;

////////////////////////////////////////////////////////////////////////////////
// TElInvalidityDateCRLExtension implementation

procedure TElInvalidityDateCRLExtension.Clear;
begin
  FDate := 0;
end;

function TElInvalidityDateCRLExtension.GetOID: ByteArray;
begin
  Result := SB_OID_EXT_INVALIDITYDATE;
end;

procedure TElInvalidityDateCRLExtension.SetOID(const Value : ByteArray);
begin
end;

procedure TElInvalidityDateCRLExtension.SetValue(const Value : ByteArray);
var
  Data : ByteArray;
  TmpStr : string;
  Len  : integer;
begin
  inherited;
  if (Length(Value) > 3) and (Byte(Value[0]) = SB_ASN1_GENERALIZEDTIME) then
  begin
    Len := Byte(Value[1 + 0]);
    SetLength(Data, Len);
    SBMove(Value, 2 + 0, Data, 0, Len);
    try
      TmpStr := StringOfBytes(Data);
      FDate := GeneralizedTimeToDateTime(TmpStr);
    except
      // for incorrect CRLs that use UTCTime format
      FDate := UTCTimeToDateTime(StringOfBytes(Data));
    end;
    ReleaseArray(Data);
    ReleaseString(TmpStr);
  end
  else
    FDate := 0;
end;

function TElInvalidityDateCRLExtension.GetValue: ByteArray;
var
  Str : string;
begin
  Str := DateTimeToGeneralizedTime(FDate);
  Result := WriteStringPrimitive(SB_ASN1_GENERALIZEDTIME, Str);
end;

////////////////////////////////////////////////////////////////////////////////
// TElCertificateIssuerCRLExtension implementation

constructor TElCertificateIssuerCRLExtension.Create;
begin
  inherited;
  FIssuer := TElGeneralNames.Create;
end;

 destructor  TElCertificateIssuerCRLExtension.Destroy;
begin
  FreeAndNil(FIssuer);
  inherited;
end;

procedure TElCertificateIssuerCRLExtension.Clear;
begin
  FIssuer.Clear;
end;

function TElCertificateIssuerCRLExtension.GetOID: ByteArray;
begin
  Result := SB_OID_EXT_CERTIFICATEISSUER;
end;

procedure TElCertificateIssuerCRLExtension.SetOID(const Value : ByteArray);
begin
end;

procedure TElCertificateIssuerCRLExtension.SetValue(const Value : ByteArray);
var
  Tag : TElASN1ConstrainedTag;
begin
  inherited;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if Tag.LoadFromBuffer(@Value[0], Length(Value)) and (Tag.Count >= 1) and (Tag.GetField(0).IsConstrained) then
      FIssuer.LoadFromTag(TElASN1ConstrainedTag(Tag.GetField(0)){$ifndef HAS_DEF_PARAMS}, false {$endif});
  finally
    FreeAndNil(Tag);
  end;
end;

function TElCertificateIssuerCRLExtension.GetValue: ByteArray;
var
  Tag : TElASN1ConstrainedTag;
  Size : integer;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    FIssuer.SaveToTag(Tag);
    Size := 0;
    Tag.SaveToBuffer(nil, Size);
    SetLength(Result, Size);
    Tag.SaveToBuffer(@Result[0], Size);
    SetLength(Result, Size);
  finally
    FreeAndNil(Tag);
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// TElIssuingDistributionPointCRLExtension implementation

constructor TElIssuingDistributionPointCRLExtension.Create;
begin
  inherited;
  FDistributionPoint := TElGeneralNames.Create;
  FReasonFlagsIncluded := false;
end;

 destructor  TElIssuingDistributionPointCRLExtension.Destroy;
begin
  FreeAndNil(FDistributionPoint);
  inherited;
end;

procedure TElIssuingDistributionPointCRLExtension.Clear;
begin
  FDistributionPoint.Clear;
  FReasonFlags :=  [] ;
  FOnlyContainsUserCerts := false;
  FOnlyContainsCACerts := false;
  FOnlyContainsAttributeCerts := false;
  FIndirectCRL := false;
  FReasonFlagsIncluded := false;
end;

function TElIssuingDistributionPointCRLExtension.GetOID: ByteArray;
begin
  Result := SB_OID_EXT_ISSUINGDISTRIBUTIONPOINT;
end;

procedure TElIssuingDistributionPointCRLExtension.SetOID(const Value : ByteArray);
begin
end;

procedure TElIssuingDistributionPointCRLExtension.SetValue(const Value : ByteArray);
var
  Tag, Root, Inner : TElASN1ConstrainedTag;
  CurrIndex : integer;
  S : ByteArray;
  B : Word;
  Reasons : TSBCRLReasonFlags;
begin
  inherited;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if Tag.LoadFromBuffer(@Value[0], Length(Value)) and (Tag.Count >= 1) and (Tag.GetField(0).IsConstrained) then
    begin
      Root := TElASN1ConstrainedTag(Tag.GetField(0));
      CurrIndex := 0;
      if (CurrIndex < Root.Count) and Root.GetField(CurrIndex).CheckType(SB_ASN1_A0, true) then
      begin
        Inner := TElASN1ConstrainedTag(Root.GetField(CurrIndex));
        if (Inner.Count > 0) and (Inner.GetField(0).CheckType(SB_ASN1_A0, true)) then
          FDistributionPoint.LoadFromTag(TElASN1ConstrainedTag(Inner.GetField(0)), false);
        Inc(CurrIndex);
      end;
      if (CurrIndex < Root.Count) and Root.GetField(CurrIndex).CheckType(SB_ASN1_A1_PRIMITIVE, false) then
      begin
        FOnlyContainsUserCerts := ASN1ReadBoolean(TElASN1SimpleTag(Root.GetField(CurrIndex)));
        Inc(CurrIndex);
      end; 
      if (CurrIndex < Root.Count) and Root.GetField(CurrIndex).CheckType(SB_ASN1_A2_PRIMITIVE, false) then
      begin
        FOnlyContainsCACerts := ASN1ReadBoolean(TElASN1SimpleTag(Root.GetField(CurrIndex)));
        Inc(CurrIndex);
      end; 
      if (CurrIndex < Root.Count) and Root.GetField(CurrIndex).CheckType(SB_ASN1_A3_PRIMITIVE, false) then
      begin
        FReasonFlagsIncluded := true;
        S := TElASN1SimpleTag(Root.GetField(CurrIndex)).Content;

        if Length(S) > 2 then
          B := PByte(@S[0 + 1])^ or (PByte(@S[0 + 2])^ shl 8)
        else
        if Length(S) = 2 then
          B := PByte(@S[0 + 1])^
        else
          B := 0;
        ReleaseArray(S);
        Reasons :=  [] ;
        if (B and $400) = $400 then
          Reasons := Reasons  + [rfAACompromise] ;
        if (B and $200) = $200 then
          Reasons := Reasons  + [rfPrivilegeWithdrawn] ;
        if (B and $100) = $100 then
          Reasons := Reasons  + [rfRemoveFromCRL] ;
        if (B and $80) = $80 then
          Reasons := Reasons  + [rfObsolete1] ;
        if (B and $40) = $40 then
          Reasons := Reasons  + [rfKeyCompromise] ;
        if (B and $20) = $20 then
          Reasons := Reasons  + [rfCACompromise] ;
        if (B and $10) = $10 then
          Reasons := Reasons  + [rfAffiliationChanged] ;
        if (B and $08) = $08 then
          Reasons := Reasons  + [rfSuperseded] ;
        if (B and $04) = $04 then
          Reasons := Reasons  + [rfCessationOfOperation] ;
        if (B and $02) = $02 then
          Reasons := Reasons  + [rfCertificateHold] ;
        FReasonFlags := Reasons;
        Inc(CurrIndex);
      end; 
      if (CurrIndex < Root.Count) and Root.GetField(CurrIndex).CheckType(SB_ASN1_A4_PRIMITIVE, false) then
      begin
        FIndirectCRL := ASN1ReadBoolean(TElASN1SimpleTag(Root.GetField(CurrIndex)));
        Inc(CurrIndex);
      end; 
      if (CurrIndex < Root.Count) and Root.GetField(CurrIndex).CheckType(SB_ASN1_A5_PRIMITIVE, false) then
        FOnlyContainsAttributeCerts := ASN1ReadBoolean(TElASN1SimpleTag(Root.GetField(CurrIndex)));
    end;
  finally
    FreeAndNil(Tag);
  end;
end;

function TElIssuingDistributionPointCRLExtension.GetValue: ByteArray;
var
  Tag, CTag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  Size : integer;
  B1 : Word;
  Tmp : ByteArray;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance();
  try
    Tag.TagID := SB_ASN1_SEQUENCE;
    if FDistributionPoint.Count > 0 then
    begin
      CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
      CTag.TagID := SB_ASN1_A0; // IssuingDistributionPoint field A0
      CTag := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
      FDistributionPoint.SaveToTag(CTag);
      CTag.TagID := SB_ASN1_A0; // DistributionPoint CHOICE A0
    end;
    if FOnlyContainsUserCerts then
    begin
      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      ASN1WriteBoolean(STag, true);
      STag.TagID := SB_ASN1_A1_PRIMITIVE;
    end;
    if FOnlyContainsCACerts then
    begin
      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      ASN1WriteBoolean(STag, true);
      STag.TagID := SB_ASN1_A2_PRIMITIVE;
    end;
    if FReasonFlagsIncluded then
    begin
      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      B1 := 0;
      if rfAACompromise in FReasonFlags then
        B1 := B1 or $400;
      if rfPrivilegeWithdrawn in FReasonFlags then
        B1 := B1 or $200;
      if rfRemoveFromCRL in FReasonFlags then
        B1 := B1 or $100;
      if rfObsolete1 in FReasonFlags then
        B1 := B1 or $80;
      if rfUnspecified in FReasonFlags then
        B1 := B1 or $1;
      if rfKeyCompromise in FReasonFlags then
        B1 := B1 or $40;
      if rfCACompromise in FReasonFlags then
        B1 := B1 or $20;
      if rfAffiliationChanged in FReasonFlags then
        B1 := B1 or $10;
      if rfSuperseded in FReasonFlags then
        B1 := B1 or $08;
      if rfCessationOfOperation in FReasonFlags then
        B1 := B1 or $04;
      if rfCertificateHold in FReasonFlags then
        B1 := B1 or $02;
      if (B1 > $FF) then
      begin
        // two bytes are needed
        Tmp := WriteBitString(GetByteArrayFromWordBE(B1));
      end
      else
      begin
        // one byte is needed
        Tmp := WriteBitString(GetByteArrayFromByte(B1));
      end;
      Tmp[0] := byte(SB_ASN1_A3_PRIMITIVE);
      STag.WriteHeader := false;
      STag.Content := Tmp;
      ReleaseArray(Tmp);
    end;
    if FIndirectCRL then
    begin
      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      ASN1WriteBoolean(STag, true);
      STag.TagID := SB_ASN1_A4_PRIMITIVE;
    end;
    if FOnlyContainsAttributeCerts then
    begin
      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      ASN1WriteBoolean(STag, true);
      STag.TagID := SB_ASN1_A5_PRIMITIVE;
    end;
    Size := 0;
    Tag.SaveToBuffer( nil , Size);
    SetLength(Result, Size);
    Tag.SaveToBuffer( @Result[0] , Size);
    SetLength(Result, Size);   
  finally
    FreeAndNil(Tag);
  end;
end;

{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
initialization

  SB_OID_EXT_AUTHORITYKEYIDENTIFIER     := CreateByteArrayConst(#$55#$1D#$23);
  SB_OID_EXT_ISSUERALTERNATIVENAME      := CreateByteArrayConst(#$55#$1D#$12);
  SB_OID_EXT_CRLNUMBER                  := CreateByteArrayConst(#$55#$1D#$14);
  SB_OID_EXT_DELTACRLINDICATOR          := CreateByteArrayConst(#$55#$1D#$1B);
  SB_OID_EXT_ISSUINGDISTRIBUTIONPOINT   := CreateByteArrayConst(#$55#$1D#$1C);
  SB_OID_EXT_REASONCODE                 := CreateByteArrayConst(#$55#$1D#$15);
  SB_OID_EXT_HOLDINSTRUCTIONCODE        := CreateByteArrayConst(#$55#$1D#$17);
  SB_OID_EXT_INVALIDITYDATE             := CreateByteArrayConst(#$55#$1D#$18);
  SB_OID_EXT_CERTIFICATEISSUER          := CreateByteArrayConst(#$55#$1D#$1D);
  // ----//
  SB_OID_EXT_HIC_NONE           := CreateByteArrayConst(#$2a#$86#$48#$ce#$38#$02#$1);
  SB_OID_EXT_HIC_CALLISSUER     := CreateByteArrayConst(#$2a#$86#$48#$ce#$38#$02#$2);
  SB_OID_EXT_HIC_REJECT         := CreateByteArrayConst(#$2a#$86#$48#$ce#$38#$02#$3);
  
 {$endif}
end.
