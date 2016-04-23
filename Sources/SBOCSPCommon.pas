(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBOCSPCommon;

interface

uses
  SysUtils,
  Classes,
  SBTypes,
  SBUtils,
  SBConstants,
  SBX509,
  SBX509Ext,
  SBCustomCertStorage,
  SBASN1,
  SBASN1Tree;

  


const

  ERROR_FACILITY_OCSP = $13000;
  ERROR_OCSP_PROTOCOL_ERROR_FLAG = $00800;

  SB_OCSP_ERROR_NO_CERTIFICATES        = Integer(ERROR_FACILITY_OCSP + ERROR_OCSP_PROTOCOL_ERROR_FLAG + 1);
  SB_OCSP_ERROR_NO_ISSUER_CERTIFICATES = Integer(ERROR_FACILITY_OCSP + ERROR_OCSP_PROTOCOL_ERROR_FLAG + 2);
  SB_OCSP_ERROR_WRONG_DATA             = Integer(ERROR_FACILITY_OCSP + ERROR_OCSP_PROTOCOL_ERROR_FLAG + 3);
  SB_OCSP_ERROR_NO_EVENT_HANDLER       = Integer(ERROR_FACILITY_OCSP + ERROR_OCSP_PROTOCOL_ERROR_FLAG + 4);
  SB_OCSP_ERROR_NO_PARAMETERS          = Integer(ERROR_FACILITY_OCSP + ERROR_OCSP_PROTOCOL_ERROR_FLAG + 5);
  SB_OCSP_ERROR_NO_REPLY               = Integer(ERROR_FACILITY_OCSP + ERROR_OCSP_PROTOCOL_ERROR_FLAG + 6);
  SB_OCSP_ERROR_WRONG_SIGNATURE        = Integer(ERROR_FACILITY_OCSP + ERROR_OCSP_PROTOCOL_ERROR_FLAG + 7);
  SB_OCSP_ERROR_UNSUPPORTED_ALGORITHM  = Integer(ERROR_FACILITY_OCSP + ERROR_OCSP_PROTOCOL_ERROR_FLAG + 8);
  SB_OCSP_ERROR_INVALID_RESPONSE       = Integer(ERROR_FACILITY_OCSP + ERROR_OCSP_PROTOCOL_ERROR_FLAG + 9);
 

{$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
 {$else}
var
 {$endif}

  SB_OCSP_OID_BASIC_RESPONSE : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#06#01#05#05#07#$30#01#01 {$endif}; 
  SB_OCSP_OID_NONCE          : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#06#01#05#05#07#$30#01#02 {$endif}; 
  SB_OCSP_OID_OCSP_RESPONSE  : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#06#01#05#05#07#$30#01#04 {$endif}; 

  SB_OID_OCSP_RESPONSE       : TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =  #$2B#06#01#05#05#07#$10#02 {$endif}; 

type
  EElOCSPParseError =  class(ESecureBlackboxError);

  TElOCSPServerError = (oseSuccessful, oseMalformedRequest, oseInternalError,
  oseTryLater, oseUnused1, oseSigRequired, oseUnauthorized);

  TElOCSPCertificateStatus = (csGood, csRevoked, csUnknown);

  TElResponderIDType = (ritName, ritKeyHash);  



  TElOCSPReplyArray =  array of TElOCSPCertificateStatus;

  TSBCertificateOCSPCheckEvent =  procedure(
    Sender : TObject;
    const HashAlgOID : ByteArray;
    const IssuerNameHash : ByteArray;
    const IssuerKeyHash : ByteArray;
    const CertificateSerial : ByteArray;
    var CertStatus : TElOCSPCertificateStatus;
    var Reason : TSBCRLReasonFlag;
    var RevocationTime, ThisUpdate, NextUpdate :  TDateTime ) of object;
  TSBOCSPSignatureValidateEvent =  procedure(
    Sender: TObject;
    var Valid : TSBBoolean) of object;
  TSBOCSPCertificateNeededEvent =  procedure(
    Sender: TObject;
    var Certificate : TElX509Certificate
  ) of object;

  TElOCSPClass = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElOCSPClass = TElOCSPClass;
   {$endif}

  TElOCSPClass = class(TSBControlBase)
  protected
    FIncludeCertificates: Boolean;
    FRequestorName: TElGeneralName;
    FSigningCertStorage: TElCustomCertStorage;
    FOnCertificateNeeded : TSBOCSPCertificateNeededEvent;
    procedure Notification(AComponent : TComponent; AOperation :
      TOperation); override;
    procedure SetSigningCertStorage(const Value: TElCustomCertStorage);
  public
    constructor Create(Owner: TSBComponentBase);   override; 
     destructor  Destroy; override;

    property RequestorName: TElGeneralName read FRequestorName;
  published
    property IncludeCertificates: Boolean read FIncludeCertificates write
      FIncludeCertificates;
    property SigningCertStorage: TElCustomCertStorage read FSigningCertStorage
      write SetSigningCertStorage;
      
    property OnCertificateNeeded : TSBOCSPCertificateNeededEvent read FOnCertificateNeeded
      write FOnCertificateNeeded;
  end;

  EElOCSPError = class(ESecureBlackboxError);

function ReasonFlagToEnum(Value: TSBCRLReasonFlag) : integer; 
function EnumToReasonFlag(Value: integer) : TSBCRLReasonFlag; 
function ReadAsnInteger(const IntBuf : ByteArray) : ByteArray; 

{$ifndef SB_FPC_GEN}
implementation
 {$endif}

{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
{$ifdef SB_UNICODE_VCL}
  {$WARNINGS OFF}
 {$endif}
const
  SB_OCSP_OID_BASIC_RESPONSE_STR = #$2B#06#01#05#05#07#$30#01#01;
  SB_OCSP_OID_NONCE_STR          = #$2B#06#01#05#05#07#$30#01#02;
  SB_OCSP_OID_OCSP_RESPONSE_STR  = #$2B#06#01#05#05#07#$30#01#04;

  SB_OID_OCSP_RESPONSE_STR       = #$2B#06#01#05#05#07#$10#02;
{$ifdef SB_UNICODE_VCL}
  {$WARNINGS ON}
 {$endif}
 {$endif}

{$ifdef SB_FPC_GEN}
implementation
 {$endif}

procedure TElOCSPClass.SetSigningCertStorage(const Value:
  TElCustomCertStorage);
begin
  FSigningCertStorage := Value;
  if FSigningCertStorage <> nil then
    FSigningCertStorage.FreeNotification(Self);
end;

procedure TElOCSPClass.Notification(AComponent : TComponent; AOperation :
  TOperation);
begin
  inherited;
  if (AComponent = FSigningCertStorage) and (AOperation = opRemove) then
    SigningCertStorage := nil;
end;

constructor TElOCSPClass.Create (Owner: TSBComponentBase) ;
begin
  inherited Create(Owner);
  FRequestorName := TElGeneralName.Create;
end;


 destructor  TElOCSPClass.Destroy;
begin
  FreeAndNil(FRequestorName);
  inherited;
end;

function ReasonFlagToEnum(Value: TSBCRLReasonFlag) : integer;
begin
  case Value of
    rfUnspecified : Result := 0;
    rfKeyCompromise : Result := 1;
    rfCACompromise : Result := 2;
    rfAffiliationChanged : Result := 3;
    rfSuperseded : Result := 4;
    rfCessationOfOperation : Result := 5;
    rfCertificateHold : Result := 6;
    rfObsolete1 : Result := 0;
    rfRemoveFromCRL : Result := 8;
    rfPrivilegeWithdrawn : Result := 9;
    rfAACompromise : Result := 10;
  else
    Result := 0;
  end;
end;

function EnumToReasonFlag(Value: integer) : TSBCRLReasonFlag;
begin
  case Value of
    1 : Result := rfKeyCompromise;
    2 : Result := rfCACompromise;
    3 : Result := rfAffiliationChanged;
    4 : Result := rfSuperseded;
    5 : Result := rfCessationOfOperation;
    6 : Result := rfCertificateHold;
    8 : Result := rfRemoveFromCRL;
    9 : Result := rfPrivilegeWithdrawn;
    10: Result := rfAACompromise;
  else
    Result := rfUnspecified;
  end;
end;

function ReadAsnInteger(const IntBuf : ByteArray) : ByteArray;
begin
  if (Length(IntBuf) > 0) and (IntBuf[0] = byte(0)) then
  begin
    SetLength(Result, Length(IntBuf) - 1);
    if Length(IntBuf) > 1 then
    SBMove(IntBuf, 0 + 1, Result, 0, Length(Result));
  end
  else
    Result := CloneArray(IntBuf);
end;

{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
initialization

  SB_OCSP_OID_BASIC_RESPONSE := CreateByteArrayConst( SB_OCSP_OID_BASIC_RESPONSE_STR );
  SB_OCSP_OID_NONCE          := CreateByteArrayConst( SB_OCSP_OID_NONCE_STR );
  SB_OCSP_OID_OCSP_RESPONSE  := CreateByteArrayConst( SB_OCSP_OID_OCSP_RESPONSE_STR );
  SB_OID_OCSP_RESPONSE       := CreateByteArrayConst( SB_OID_OCSP_RESPONSE_STR );

 {$endif}
end.
