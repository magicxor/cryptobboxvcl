(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBTSPCommon;

interface

uses
  SysUtils,
  Classes,
  SBTypes,
  SBUtils,
  SBConstants,
  SBASN1,
  SBASN1Tree,
  SBX509Ext;


const

  ERROR_FACILITY_TSP = $14000;

  ERROR_TSP_PROTOCOL_ERROR_FLAG = $00800;

  SB_TSP_ERROR_ABORTED                 = Integer(ERROR_FACILITY_TSP + ERROR_TSP_PROTOCOL_ERROR_FLAG + 1);
  SB_TSP_ERROR_NO_REPLY                = Integer(ERROR_FACILITY_TSP + ERROR_TSP_PROTOCOL_ERROR_FLAG + 2);
  SB_TSP_ERROR_NO_PARAMETERS           = Integer(ERROR_FACILITY_TSP + ERROR_TSP_PROTOCOL_ERROR_FLAG + 3);
  SB_TSP_ERROR_NO_CERTIFICATES         = Integer(ERROR_FACILITY_TSP + ERROR_TSP_PROTOCOL_ERROR_FLAG + 4);
  SB_TSP_ERROR_WRONG_DATA              = Integer(ERROR_FACILITY_TSP + ERROR_TSP_PROTOCOL_ERROR_FLAG + 5);
  SB_TSP_ERROR_WRONG_IMPRINT           = Integer(ERROR_FACILITY_TSP + ERROR_TSP_PROTOCOL_ERROR_FLAG + 6);
  SB_TSP_ERROR_WRONG_NONCE             = Integer(ERROR_FACILITY_TSP + ERROR_TSP_PROTOCOL_ERROR_FLAG + 7);
  SB_TSP_ERROR_UNEXPECTED_CERTIFICATES = Integer(ERROR_FACILITY_TSP + ERROR_TSP_PROTOCOL_ERROR_FLAG + 8);
  SB_TSP_ERROR_UNRECOGNIZED_FORMAT     = Integer(ERROR_FACILITY_TSP + 1);
  SB_TSP_ERROR_DATA_TOO_LONG           = Integer(ERROR_FACILITY_TSP + 2);
  SB_TSP_ERROR_UNSUPPORTED_REPLY       = Integer(ERROR_FACILITY_TSP + 3);
  SB_TSP_ERROR_GENERAL_ERROR           = Integer(ERROR_FACILITY_TSP + 4);
  SB_TSP_ERROR_REQUEST_REJECTED        = Integer(ERROR_FACILITY_TSP + 5);

  tfiBadAlg = SmallInt(0);
  tfiBadRequest = SmallInt(2);
  tfiBadDataFormat = SmallInt(5);
  tfiTimeNotAvailable = SmallInt(14);
  tfiUnacceptedPolicy = SmallInt(15);
  tfiUnacceptedExtension = SmallInt(16);
  tfiAddInfoNotAvailable = SmallInt(17);
  tfiSystemFailure = SmallInt(25);

{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
var
 {$else}
const
 {$endif}

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS OFF}
 {$endif}

  SB_TSP_OID_AUTHENTICODE_TIMESTAMP : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#$06#$01#$04#$01#$82#$37#$03#$02#$01 {$endif}; 
  SB_TSP_OID_PKCS7_DATA : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2A#$86#$48#$86#$F7#$0D#$01#$07#$01 {$endif}; 

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS ON}
 {$endif}

type

  TSBTSPFailureInfo =  SmallInt;

  TElTSPInfo = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElTSPInfo = TElTSPInfo;
   {$endif}

  TElTSPInfo = class (TPersistent) 
  protected
    FNonce: ByteArray;
    FSerialNumber: ByteArray;
    FTime: TElDateTime;
    FAccuracySet: Boolean;
    FAccuracySec: integer;
    FAccuracyMilli: integer;
    FAccuracyMicro: integer;
    FTSAName: TElGeneralName;
    FTSANameSet: Boolean;
    procedure SetNonce(const Nonce : ByteArray); virtual;
    procedure SetSerialNumber(const SN : ByteArray);
  public
    constructor Create; virtual;
     destructor  Destroy; override;

    procedure Assign(Source :  TPersistent );  override ;
    procedure Reset; virtual;
    
    property SerialNumber: ByteArray read FSerialNumber write SetSerialNumber;

    property Nonce: ByteArray read FNonce write SetNonce; 
    property Time: TElDateTime read FTime write FTime; 
    property AccuracySec: integer read FAccuracySec write FAccuracySec; 
    property AccuracyMilli: integer read FAccuracyMilli write FAccuracyMilli; 
    property AccuracyMicro: integer read FAccuracyMicro write FAccuracyMicro; 
    property AccuracySet: Boolean read FAccuracySet write FAccuracySet;  
    property TSAName: TElGeneralName read FTSAName; 
    property TSANameSet: Boolean read FTSANameSet write FTSANameSet;  
  end;

  TElTSPClass = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElTSPClass = TElTSPClass;
   {$endif}

  TElTSPClass = class(TSBControlBase)
  public
    constructor Create(Owner: TSBComponentBase);  override; 
     destructor  Destroy; override;

    function ValidateImprint(Algorithm: Integer; const HashedData, Imprint: ByteArray):
        Boolean;
  end;

{$ifndef SB_FPC_GEN}
implementation

uses
  SBPKCS7,
  SBRandom;
 {$endif}

{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
{$ifdef SB_UNICODE_VCL}
  {$WARNINGS OFF}
 {$endif}
const
  SB_TSP_OID_AUTHENTICODE_TIMESTAMP_STR = #$2B#$06#$01#$04#$01#$82#$37#$03#$02#$01;
  SB_TSP_OID_PKCS7_DATA_STR = #$2A#$86#$48#$86#$F7#$0D#$01#$07#$01;
{$ifdef SB_UNICODE_VCL}
  {$WARNINGS ON}
 {$endif}
 {$endif}

{$ifdef SB_FPC_GEN}
implementation

uses
  SBPKCS7,
  SBRandom;
 {$endif}

resourcestring
  SInvalidObjectType = 'Invalid object type';

constructor TElTSPClass.Create(Owner: TSBComponentBase);
begin
  inherited Create(Owner);
end;


 destructor  TElTSPClass.Destroy;
begin
  inherited;
end;

function TElTSPClass.ValidateImprint(Algorithm: Integer; const HashedData, Imprint:
    ByteArray): Boolean;
var
  ASN, Seq, Field: TElASN1ConstrainedTag;
  Param: TElASN1SimpleTag;
  OID  : ByteArray;
begin
  result := false;
  ASN := TElASN1ConstrainedTag.CreateInstance;
  try
    try
      if not ASN.LoadFromBuffer( @Imprint[0], Length(Imprint) ) then
        exit;
    except
      exit;
    end;
    if ASN.Count <> 1 then
      exit;
    Field := TElASN1ConstrainedTag(ASN.GetField(0));
    if (Field = nil) or not Field.IsConstrained then
      exit;
    if Field.Count < 2 then
      exit;

    // Read AlgorithmIdentifier
    Seq := TElASN1ConstrainedTag(Field.GetField(0));
    if (Seq = nil) or (not Seq.IsConstrained) then
      exit;
    if (Seq.Count <> 1) and (Seq.Count <> 2) then
      exit;
    Param := TElASN1SimpleTag(Seq.GetField(0));
    if Param.TagId <> SB_ASN1_OBJECT then
      exit;
    OID := GetOIDByHashAlgorithm(Algorithm);
    if (Length(OID) = 0) or
    (not CompareMem(@Param.Content[0], @OID[0], Length(OID)))
      then
      exit;

    // read HashedData
    Param := TElASN1SimpleTag(Field.GetField(1));
    if Param.TagId <> SB_ASN1_OCTETSTRING then exit;
    if (Length(Param.Content) <> Length(HashedData)) or (not CompareMem(HashedData, Param.Content)) then
      exit; 
  finally
    FreeAndNil(ASN);
  end;
  result := true;
end;

constructor TElTSPInfo.Create;
begin
  inherited;
  FTSAName := TElGeneralName.Create;
  SetLength(FNonce, 8);
  SBRndGenerate(@FNonce[0], Length(FNonce));
  PByte(@FNonce[0])^ := (PByte(@FNonce[0])^ or 1) and $7f;
end;

 destructor  TElTSPInfo.Destroy;
begin
  FreeAndNil(FTSAName);
  ReleaseArray(FNonce);
  inherited;
end;

procedure TElTSPInfo.Assign(Source :  TPersistent );
begin
  inherited;
  if not (Source is TElTSPInfo) then
    raise EConvertError.Create(SInvalidObjectType);
  FNonce := CloneArray(TElTSPInfo(Source).FNonce);
  FSerialNumber := CloneArray(TElTSPInfo(Source).FSerialNumber);
  FTime := TElTSPInfo(Source).FTime; 
  FAccuracySet := TElTSPInfo(Source).FAccuracySet;
  FAccuracySec := TElTSPInfo(Source).FAccuracySec;
  FAccuracyMilli := TElTSPInfo(Source).FAccuracyMilli;
  FAccuracyMicro := TElTSPInfo(Source).FAccuracyMicro;
  FTSAName.Assign(TElTSPInfo(Source).FTSAName);
  FTSANameSet := TElTSPInfo(Source).FTSANameSet;
end;

procedure TElTSPInfo.Reset;
begin
  FNonce := EmptyArray;
  FSerialNumber := EmptyArray;
  FTime :=  0 ;
  FAccuracySet := False;
  FAccuracySec := 0;
  FAccuracyMilli := 0;
  FAccuracyMicro := 0;
  FTSAName.NameType := gnUnknown;
  FTSANameSet := false;
end;

procedure TElTSPInfo.SetNonce(const Nonce : ByteArray);
begin
  FNonce := CloneArray(Nonce);
end;

procedure TElTSPInfo.SetSerialNumber(const SN : ByteArray);
begin
  FSerialNumber := CloneArray(SN);
end;

{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
initialization

  SB_TSP_OID_AUTHENTICODE_TIMESTAMP := CreateByteArrayConst( SB_TSP_OID_AUTHENTICODE_TIMESTAMP_STR );
  SB_TSP_OID_PKCS7_DATA := CreateByteArrayConst( SB_TSP_OID_PKCS7_DATA_STR );

 {$endif}

end.



