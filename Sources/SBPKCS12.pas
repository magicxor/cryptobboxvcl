(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBPKCS12;

interface

uses
  SysUtils,
  Classes,
  {$ifdef WIN32}
  Windows,
   {$endif}
  {$ifdef SB_UNICODE_VCL}
  SBStringList,
   {$endif}
  SBPKCS7,
  SBCRL,
  SBPKCS7Utils,
  SBASN1Tree,
  SBASN1,
  SBX509,
  SBRandom,
  SBTypes,
  SBUtils,
  SBStrUtils,
  SBConstants,
  SBMD,
  SBSHA,
  SBMath,
  SBCryptoProv,
  SBHashFunction,
  SBRSA,
  SBDSA,
  SBCRLStorage,
  SBCustomCertStorage;


const
  SB_PKCS12_ERROR_INVALID_ASN_DATA                      = Integer($1F01);
  SB_PKCS12_ERROR_NO_DATA                               = Integer($1F02);
  SB_PKCS12_ERROR_INVALID_DATA                          = Integer($1F03);
  SB_PKCS12_ERROR_INVALID_VERSION                       = Integer($1F04);
  SB_PKCS12_ERROR_INVALID_CONTENT                       = Integer($1F05);
  SB_PKCS12_ERROR_INVALID_AUTHENTICATED_SAFE_DATA       = Integer($1F06);
  SB_PKCS12_ERROR_INVALID_MAC_DATA                      = Integer($1F07);
  SB_PKCS12_ERROR_INVALID_SAFE_CONTENTS                 = Integer($1F08);
  SB_PKCS12_ERROR_INVALID_SAFE_BAG                      = Integer($1F09);
  SB_PKCS12_ERROR_INVALID_SHROUDED_KEY_BAG              = Integer($1F0A);
  SB_PKCS12_ERROR_UNKNOWN_PBE_ALGORITHM                 = Integer($1F0B);
  SB_PKCS12_ERROR_INTERNAL_ERROR                        = Integer($1F0C);
  SB_PKCS12_ERROR_INVALID_PBE_ALGORITHM_PARAMS          = Integer($1F0D);
  SB_PKCS12_ERROR_INVALID_CERT_BAG                      = Integer($1F0E);
  SB_PKCS12_ERROR_UNSUPPORTED_CERTIFICATE_TYPE          = Integer($1F0F);
  SB_PKCS12_ERROR_INVALID_PRIVATE_KEY                   = Integer($1F10);
  SB_PKCS12_ERROR_INVALID_MAC                           = Integer($1F11);
  SB_PKCS12_ERROR_NO_CERTIFICATES                       = Integer($1F12);
  SB_PKCS12_ERROR_INVALID_PASSWORD                      = Integer($1F13);
  SB_PKCS12_ERROR_BUFFER_TOO_SMALL                      = Integer($1F14);
  SB_PKCS12_ERROR_INVALID_CRL_BAG                       = Integer($1F15);
  SB_PKCS12_ERROR_UNSUPPORTED_CRL_TYPE                  = Integer($1F16);

type
  TElPKCS12Message = class;
  {$ifndef SB_EXCLUDE_EL_ALIASES}
  ElPKCS12Message = TElPKCS12Message;
   {$endif}

  TElPKCS12Message = class
  private
    FPrivateKeys : TElByteArrayList;
    FPrivateKeyParams : TElByteArrayList;
    FPrivateKeyAlgorithms : TElByteArrayList;
    FDigestAlgorithm : ByteArray;
    FDigestAlgorithmParams : ByteArray;
    FDigest : ByteArray;
    FSalt : ByteArray;
    FPassword : string;
    FIterations : integer;
    FCertificates : TElMemoryCertStorage;
    FCRLs : TElMemoryCRLStorage;
    FKeyEncryptionAlgorithm : integer;
    FCertEncryptionAlgorithm : integer;
    FCRLEncryptionAlgorithm : integer;
    FRandom : TElRandom;
    FLastKeyId : cardinal;
    FUseEmptyPasswordWorkaround : boolean;
    FCryptoProviderManager: TElCustomCryptoProviderManager;
  protected
    function ProcessAuthenticatedSafe(Buffer : pointer; Size : integer) : integer;
    function ProcessMACData(Tag : TElASN1ConstrainedTag; Buffer : pointer; Size : integer) : integer;
    function ProcessSafeBags(P : pointer; Size : integer) : integer;
    function ProcessPrivateKeyInfo(Buffer : pointer; Size : integer; var Algorithm :
      ByteArray; var PrivateKey : ByteArray; var PrivateKeyParams : ByteArray) : integer;
    function ProcessSafeContents(Mes : TElPKCS7Message) : integer;
    function ProcessSafeBag(Tag : TElASN1ConstrainedTag) : integer;
    function ProcessShroudedKeyBag(Tag : TElASN1ConstrainedTag) : integer;
    function ProcessCertBag(Tag : TElASN1ConstrainedTag) : integer;
    function ProcessKeyBag(Tag : TElASN1ConstrainedTag) : integer;
    function ProcessCRLBag(Tag : TElASN1ConstrainedTag) : integer;
    function ProcessEncryptedSafeBags(Tag : TElPKCS7Message) : integer;

    {$ifndef SB_NO_RC2}
    function DecryptRC2(InBuffer : pointer; InSize : integer; OutBuffer :
      pointer; var OutSize : integer; const Key : ByteArray; const IV : ByteArray) : boolean;
     {$endif}

    {$ifndef SB_NO_DES}
    function Decrypt3DES(InBuffer : pointer; InSize : integer;
      OutBuffer : pointer; var OutSize : integer; const Key : ByteArray; const IV : ByteArray) : boolean;
     {$endif}
    {$ifndef SB_NO_RC4}
    function DecryptRC4(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
      var OutSize : integer; const Key : ByteArray) : boolean;
     {$endif}
    function EncryptContent(InBuffer : pointer; InSize : integer; OutBuffer : pointer;
      var OutSize : integer; Algorithm : integer; const Key : ByteArray;
      const IV : ByteArray) : boolean;
    function CheckPadding(Buffer : pointer; Size : integer): boolean;

    function GetKeyAndIVLengths(AlgId : integer; var KeyLen : integer; var IVLen :
      integer) : boolean;
    function KeyCorresponds(Certificate : TElX509Certificate; KeyBuffer : pointer;
      KeySize : integer) : boolean;
    function DeriveKeyFromPassword(const Password : string; const Salt : ByteArray; Id : byte;
      HashAlgorithm : integer; Iters : integer; Size : integer; UseEmptyPassBugWorkaround : boolean = false) : ByteArray;

    function CalculateHashSHA1(Buffer : pointer; Size : integer; Iterations :
      integer) : TMessageDigest160;
    function CalculateHashMD5(Buffer : pointer; Size : integer; Iterations :
      integer) : TMessageDigest128;
    function SaveAuthenticatedSafe(Tag : TElASN1ConstrainedTag; MAC :
      TElASN1ConstrainedTag) : integer;

    function SaveShroudedKeyBag(OutBuffer : pointer; var OutSize : integer;
      Cert : TElX509Certificate) : integer;
    function SaveCertBag(CertBuffer : pointer; CertSize : integer; OutBuffer : pointer;
      var OutSize : integer) : integer;
    function SaveCRLBag(CRLBuffer : pointer; CRLSize : integer; OutBuffer : pointer;
      var OutSize : integer) : integer;
    function SaveMACData(Buffer : pointer; Size : integer; Tag : TElASN1ConstrainedTag) : integer;

    function ComposeDSAPrivateKey(X : pointer; XSize : integer; Certificate :
      TElX509Certificate; OutBuffer : pointer; var OutSize : integer) : boolean;
    function DecomposeDSAPrivateKey(KeyBlob : pointer; KeyBlobSize : integer;
      PrivateKey : pointer; var PrivateKeySize : integer; Params : pointer;
      var ParamsSize : integer) : boolean;

    function GetPassword : string;
    procedure SetPassword(const Value : string);
  public
    constructor Create;
     destructor  Destroy; override;

    function LoadFromBuffer(Buffer : pointer; Size : integer) : integer;
    function SaveToBuffer(Buffer : pointer; var Size : integer) : integer;

    property Iterations : integer read FIterations write FIterations;
    property Password : string read GetPassword write SetPassword;
    property Certificates : TElMemoryCertStorage read FCertificates;
    property CRLs : TElMemoryCRLStorage read FCRLs;
    property KeyEncryptionAlgorithm : integer read FKeyEncryptionAlgorithm
      write FKeyEncryptionAlgorithm;
    property CertEncryptionAlgorithm : integer read FCertEncryptionAlgorithm
      write FCertEncryptionAlgorithm;
    property CRLEncryptionAlgorithm : integer read FCRLEncryptionAlgorithm
      write FCRLEncryptionAlgorithm;
    property UseEmptyPasswordWorkaround : boolean read FUseEmptyPasswordWorkaround
      write FUseEmptyPasswordWorkaround;
    property CryptoProviderManager: TElCustomCryptoProviderManager
      read FCryptoProviderManager write FCryptoProviderManager;
  end;

function BufToInt(Buffer : pointer; Size : integer) : integer;
function IntToBuf(Number : integer) : ByteArray; 

type

  EElPKCS12Error =  class(ESecureBlackboxError);

procedure RaisePKCS12Error(ErrorCode : integer); 

implementation

uses
  SBPublicKeyCrypto,
  SBSymmetricCrypto;

resourcestring

  sInvalidASNData = 'Invalid ASN.1 sequence';
  sNoData = 'No data';
  sInvalidData = 'Invalid data';
  sInvalidVersion = 'Invalid version';
  sInvalidContent = 'Invalid content';
  sInvalidAuthSafeData = 'Invalid authenticated safe data';
  sInvalidMACData = 'Invalid MAC data';
  sInvalidSafeContents = 'Invalid safe contents';
  sInvalidSafeBag = 'Invalid safe bag';
  sShroudedKeyBag = 'Shrowded key bag';
  sInvalidPBEAlgorithm = 'invalid PBE algorithm';
  sInternalError = 'Internal error';
  sInvalidPBEAlgoParams = 'Invalid PBE algorithm';
  sInvalidCertBag = 'Invalid certificate bag';
  sUnsupportedCertType = 'Unsupported certificate type';
  sInvalidPrivateKey = 'Invalid private key';
  sInvalidMAC = 'Invalid MAC';
  sNoCertificates = 'No certificates found';
  sInvalidPassword = 'Invalid password';
  sBufferTooSmall = 'Buffer too small';
  sPKCS12Error = 'PKCS#12 error';

{$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS}
const
 {$else}
var
 {$endif}

{$ifdef SB_UNICODE_VCL}
  {$WARNINGS OFF}
 {$endif}

  SB_OID_KEY_BAG                 :TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =   #$2a#$86#$48#$86#$f7#$0d#$01#$0c#$0a#$01#$01 {$endif};
  SB_OID_PKCS8_SHROUDED_KEY_BAG  :TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =   #$2a#$86#$48#$86#$f7#$0d#$01#$0c#$0a#$01#$02 {$endif};
  SB_OID_CERT_BAG                :TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =   #$2a#$86#$48#$86#$f7#$0d#$01#$0c#$0a#$01#$03 {$endif};
  SB_OID_CRL_BAG                 :TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =   #$2a#$86#$48#$86#$f7#$0d#$01#$0c#$0a#$01#$04 {$endif};
  SB_OID_SECRET_BAG              :TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =   #$2a#$86#$48#$86#$f7#$0d#$01#$0c#$0a#$01#$05 {$endif};
  SB_OID_SAFE_CONTENTS_BAG       :TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =   #$2a#$86#$48#$86#$f7#$0d#$01#$0c#$0a#$01#$06 {$endif};
  SB_OID_LOCAL_KEY_ID            :TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =   #$2a#$86#$48#$86#$f7#$0d#$01#$09#$15 {$endif};
  SB_OID_CERT_TYPE_X509          :TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =   #$2a#$86#$48#$86#$f7#$0d#$01#$09#$16#$01 {$endif};
  SB_OID_CRL_TYPE_X509           :TByteArrayConst {$ifndef SB_NO_BYTEARRAY_CONST_ARRAYS} =   #$2a#$86#$48#$86#$f7#$0d#$01#$09#$17#$01 {$endif};


{$ifdef SB_UNICODE_VCL}
  {$WARNINGS ON}
 {$endif}

const
  SB_PKCS12_KEYDERIVATION_ID_KEY   = 1;
  SB_PKCS12_KEYDERIVATION_ID_IV    = 2;
  SB_PKCS12_KEYDERIVATION_ID_MAC   = 3;

procedure RaisePKCS12Error(ErrorCode : integer);
begin
  if ErrorCode <> 0 then
    case ErrorCode of
      SB_PKCS12_ERROR_INVALID_ASN_DATA                 : raise EElPKCS12Error.Create(sInvalidASNData);
      SB_PKCS12_ERROR_NO_DATA                          : raise EElPKCS12Error.Create(sNoData);
      SB_PKCS12_ERROR_INVALID_DATA                     : raise EElPKCS12Error.Create(sInvalidData);
      SB_PKCS12_ERROR_INVALID_VERSION                  : raise EElPKCS12Error.Create(sInvalidVersion);
      SB_PKCS12_ERROR_INVALID_CONTENT                  : raise EElPKCS12Error.Create(sInvalidContent);
      SB_PKCS12_ERROR_INVALID_AUTHENTICATED_SAFE_DATA  : raise EElPKCS12Error.Create(sInvalidAuthSafeData);
      SB_PKCS12_ERROR_INVALID_MAC_DATA                 : raise EElPKCS12Error.Create(sInvalidMACData);
      SB_PKCS12_ERROR_INVALID_SAFE_CONTENTS            : raise EElPKCS12Error.Create(sInvalidSafeContents);
      SB_PKCS12_ERROR_INVALID_SAFE_BAG                 : raise EElPKCS12Error.Create(sInvalidSafeBag);
      SB_PKCS12_ERROR_INVALID_SHROUDED_KEY_BAG         : raise EElPKCS12Error.Create(sShroudedKeyBag);
      SB_PKCS12_ERROR_UNKNOWN_PBE_ALGORITHM            : raise EElPKCS12Error.Create(sInvalidPBEAlgorithm);
      SB_PKCS12_ERROR_INTERNAL_ERROR                   : raise EElPKCS12Error.Create(sInternalError);
      SB_PKCS12_ERROR_INVALID_PBE_ALGORITHM_PARAMS     : raise EElPKCS12Error.Create(sInvalidPBEAlgoParams);
      SB_PKCS12_ERROR_INVALID_CERT_BAG                 : raise EElPKCS12Error.Create(sInvalidCertBag);
      SB_PKCS12_ERROR_UNSUPPORTED_CERTIFICATE_TYPE     : raise EElPKCS12Error.Create(sUnsupportedCertType);
      SB_PKCS12_ERROR_INVALID_PRIVATE_KEY              : raise EElPKCS12Error.Create(sInvalidPrivateKey);
      SB_PKCS12_ERROR_INVALID_MAC                      : raise EElPKCS12Error.Create(sInvalidMAC);
      SB_PKCS12_ERROR_NO_CERTIFICATES                  : raise EElPKCS12Error.Create(sNoCertificates);
      SB_PKCS12_ERROR_INVALID_PASSWORD                 : raise EElPKCS12Error.Create(sInvalidPassword);
      SB_PKCS12_ERROR_BUFFER_TOO_SMALL                 : raise EElPKCS12Error.Create(sBufferTooSmall);
      else
          raise EElPKCS12Error.Create(sPKCS12Error + '#' + IntToStr(ErrorCode));
    end;
end;


function ProcessPBEAlgorithmParams(Buffer : pointer; Size : integer; var
  Salt : ByteArray; var Iterations : integer) : boolean;
var
  ParamsTag : TElASN1ConstrainedTag;
  Content : ByteArray;
begin
  Result := false;
  ParamsTag := TElASN1ConstrainedTag.CreateInstance;
  try

    if not ParamsTag.LoadFromBuffer(Buffer , Size ) then
      Exit;

    if ParamsTag.Count <> 1 then
      Exit;

    if (not ParamsTag.GetField(0).IsConstrained) or (ParamsTag.GetField(0).TagId <>
      SB_ASN1_SEQUENCE) then
      Exit;

    if TElASN1ConstrainedTag(ParamsTag.GetField(0)).Count <> 2 then
      Exit;

    if (TElASN1ConstrainedTag(ParamsTag.GetField(0)).GetField(0).IsConstrained) or
      (TElASN1ConstrainedTag(ParamsTag.GetField(0)).GetField(0).TagId <> SB_ASN1_OCTETSTRING) or
      (TElASN1ConstrainedTag(ParamsTag.GetField(0)).GetField(1).IsConstrained) or
      (TElASN1ConstrainedTag(ParamsTag.GetField(0)).GetField(1).TagId <> SB_ASN1_INTEGER) then
      Exit;

    Salt := TElASN1SimpleTag(TElASN1ConstrainedTag(ParamsTag.GetField(0)).GetField(0)).Content;

    Content := TElASN1SimpleTag(TElASN1ConstrainedTag(ParamsTag.GetField(0)).GetField(1)).Content;

    Iterations := BufToInt(@Content[0], Length(Content));
    Result := true;
  finally
    FreeAndNil(ParamsTag);
  end;
end;

function SavePBEAlgorithmParams(const Salt : ByteArray; Iterations : integer; Tag :
  TElASN1ConstrainedTag) : boolean;
var
  STag : TElASN1SimpleTag;
begin
  Tag.TagId := SB_ASN1_SEQUENCE;
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_OCTETSTRING;
  STag.Content := CloneArray(Salt);
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;
  STag.Content := IntToBuf(Iterations);
  Result := true;
end;

constructor TElPKCS12Message.Create;
var
  D :  double ;
{$ifdef SB_WINDOWS}
  C : cardinal;
 {$else}
  C :  TElDateTime ;
 {$endif}
  Buf : array [0..15]  of byte;
begin
  inherited;
  FPrivateKeys := TElByteArrayList.Create;
  FPrivateKeyParams := TElByteArrayList.Create;
  FPrivateKeyAlgorithms := TElByteArrayList.Create;
  FCertificates := TElMemoryCertStorage.Create(nil);
  FCRLs := TElMemoryCRLStorage.Create( nil );
  FRandom := TElRandom.Create;
{$ifdef CLX_USED}
  C := Now;
  D := Now;
 {$else}
  {$ifdef SB_WINDOWS}
  C := GetTickCount;
   {$else}
  C := Now;
   {$endif}
  D := Now;
 {$endif}
  SBMove(PByteArray(@C)[0], Buf[0], 4);
  SBMove(PByteArray(@D)[0], Buf[4], 8);
  SBMove(PByteArray(@C)[0], Buf[12], 4);
  FRandom.Randomize(@Buf[0], 16);
  FUseEmptyPasswordWorkaround := true;
  FCertEncryptionAlgorithm := SB_ALGORITHM_PBE_SHA1_RC2_40;
  FCRLEncryptionAlgorithm := SB_ALGORITHM_PBE_SHA1_RC2_40;
  FKeyEncryptionAlgorithm := SB_ALGORITHM_PBE_SHA1_3DES;
  FCryptoProviderManager := nil;
end;

 destructor  TElPKCS12Message.Destroy;
begin
  FreeAndNil(FCertificates);
  FreeAndNil(FCRLs);
  FreeAndNil(FPrivateKeys);
  FreeAndNil(FPrivateKeyParams);
  FreeAndNil(FPrivateKeyAlgorithms);
  FreeAndNil(FRandom);
  FPassword := '';
  inherited;
end;

function TElPKCS12Message.LoadFromBuffer(Buffer : pointer; Size : integer) : integer;
var
  Tag, CTag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  Sz : integer;
  CT : ByteArray;
  Buf : ByteArray;
  Content : ByteArray;
  I, J : integer;
  B : boolean;
  BlobLen : integer;
begin
  CheckLicenseKey();
  while FCertificates.Count > 0 do
    FCertificates.Remove(0);
  FCRLs.Clear;
  FPrivateKeys.Clear;
  FPrivateKeyParams.Clear;
  FPrivateKeyAlgorithms.Clear;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    // II20120110: LoadFromBuffer replaced with LoadFromBufferSingle to process
    // trash after the end in tolerant way
    //if not Tag.LoadFromBuffer(Buffer{$ifdef SB_VCL}, Size{$endif}) then
    //begin
    //  Result := SB_PKCS12_ERROR_INVALID_ASN_DATA;
    //  Exit;
    //end;
    BlobLen := Tag.LoadFromBufferSingle(Buffer , Size );
    if BlobLen = -1 then
    begin
      Result := SB_PKCS12_ERROR_INVALID_ASN_DATA;
      Exit;
    end;

    if Tag.Count <> 1 then
    begin
      Result := SB_PKCS12_ERROR_NO_DATA;
      Exit;
    end;

    if (not Tag.GetField(0).IsConstrained) or (Tag.GetField(0).TagId <> SB_ASN1_SEQUENCE) then
    begin
      Result := SB_PKCS12_ERROR_INVALID_DATA;
      Exit;
    end;

    CTag := TElASN1ConstrainedTag(Tag.GetField(0));
    if (CTag.Count > 3) or (CTag.Count < 2) then
    begin
      Result := SB_PKCS12_ERROR_INVALID_DATA;
      Exit;
    end;

    if (CTag.GetField(0).IsConstrained) or (CTag.GetField(0).TagId <> SB_ASN1_INTEGER) then
    begin
      Result := SB_PKCS12_ERROR_INVALID_DATA;
      Exit;
    end;

    STag := TElASN1SimpleTag(CTag.GetField(0));
    if not CompareContent(STag.Content, GetByteArrayFromByte(3)) then
    begin
      Result := SB_PKCS12_ERROR_INVALID_VERSION;
      Exit;
    end;

    if (not CTag.GetField(1).IsConstrained) or (CTag.GetField(1).TagId <> SB_ASN1_SEQUENCE) then
    begin
      Result := SB_PKCS12_ERROR_INVALID_DATA;
      Exit;
    end;
    Sz := 0;
    ProcessContentInfo(TElASN1ConstrainedTag(CTag.GetField(1)), nil, Sz, CT);
    SetLength(Content, Sz);
    if not ProcessContentInfo(TElASN1ConstrainedTag(CTag.GetField(1)), @Content[0], Sz, CT) then
    begin
      Result := SB_PKCS12_ERROR_INVALID_CONTENT;
      Exit;
    end;

    if not CompareContent(CT, SB_OID_PKCS7_DATA) then
    begin
      Result := SB_PKCS12_ERROR_INVALID_CONTENT;
      Exit;
    end;

    SetLength(Content, Sz);
    Result := ProcessAuthenticatedSafe(@Content[0], Sz);
    if Result <> 0 then
    begin
      Exit;
    end;

    if CTag.Count = 3 then
    begin
      if (not CTag.GetField(2).IsConstrained) then
      begin
        Result := SB_PKCS12_ERROR_INVALID_DATA;
        Exit;
      end;

      Result := ProcessMACData(TElASN1ConstrainedTag(CTag.GetField(2)), @Content[0], Length(Content));
      if Result <> 0 then
        Exit;
    end;

    { Finding private keys corresponding to certificates }
    for I := 0 to FCertificates.Count - 1 do
    begin
      for J := 0 to FPrivateKeys.Count - 1 do
      begin
        B := KeyCorresponds(FCertificates.Certificates[I], @(FPrivateKeys.Item[J][0]),
          Length(FPrivateKeys.Item[J]));
        if B then
        begin
          FCertificates.Certificates[I].LoadKeyFromBuffer(@(FPrivateKeys.Item[J][0]),
            Length(FPrivateKeys.Item[J]));
          Break;
        end
        else
        if (not B) and
           (FCertificates.Certificates[I].PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_DSA) then
        begin
          // forming "good" dsa private key structure and loading it
          Sz := 0;
          ComposeDSAPrivateKey(@(FPrivateKeys.Item[J][0]),
            Length(FPrivateKeys.Item[J]), FCertificates.Certificates[I],
            nil, Sz);
          SetLength(Buf, Sz);
          if ComposeDSAPrivateKey(@(FPrivateKeys.Item[J][0]),
            Length(FPrivateKeys.Item[J]), FCertificates.Certificates[I],
            @Buf[0], Sz) then
          begin
            FCertificates.Certificates[I].LoadKeyFromBuffer(@Buf[0], Word(Sz));
            Break;
          end;
        end;
      end;
    end;

    Result := 0;
  finally
    FreeAndNil(Tag);
  end;
end;

function TElPKCS12Message.ProcessAuthenticatedSafe(Buffer : pointer; Size :
  integer) : integer;
var
  Tag, CTag : TElASN1ConstrainedTag;
  I, Sz : integer;
  Buf : ByteArray;
  Msg : TElPKCS7Message;
begin
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if not Tag.LoadFromBuffer(Buffer , Size ) then
    begin
      Result := SB_PKCS12_ERROR_INVALID_ASN_DATA;
      Exit;
    end;
    if Tag.Count <> 1 then
    begin
      Result := SB_PKCS12_ERROR_INVALID_ASN_DATA;
      Exit;
    end;
    if (not Tag.GetField(0).IsConstrained) or (Tag.GetField(0).TagId <> SB_ASN1_SEQUENCE) then
    begin
      Result := SB_PKCS12_ERROR_INVALID_AUTHENTICATED_SAFE_DATA;
      Exit;
    end;

    CTag := TElASN1ConstrainedTag(Tag.GetField(0));
    Result := 0;
    for I := 0 to CTag.Count - 1 do
    begin
      if (not CTag.GetField(I).IsConstrained) or (CTag.GetField(I).TagId <> SB_ASN1_SEQUENCE) then
      begin
        Result := SB_PKCS12_ERROR_INVALID_AUTHENTICATED_SAFE_DATA;
        Exit;
      end;
    
      Sz := 0;
      Msg := TElPKCS7Message.Create;
      try

        CTag.GetField(I).SaveToBuffer(nil, Sz);
        SetLength(Buf, Sz);
        CTag.GetField(I).SaveToBuffer(@Buf[0], Sz);
        if Msg.LoadFromBuffer(@Buf[0], Sz) <> 0 then
        begin
          Result := SB_PKCS12_ERROR_INVALID_AUTHENTICATED_SAFE_DATA;
          Exit;
        end;

        Result := ProcessSafeContents(Msg);
      finally
        FreeAndNil(Msg);
      end;
      if Result <> 0 then
        Break;
    end;
  finally
    FreeAndNil(Tag);
  end;
end;

function TElPKCS12Message.ProcessMACData(Tag : TElASN1ConstrainedTag; Buffer :
  pointer; Size : integer) : integer;
var
  CTag : TElASN1ConstrainedTag;
  MACKey, Hash : ByteArray;
  HashFunction : TElHashFunction;
  KM : TElHMACKeyMaterial;
  UseWA : array of boolean;
  I : integer;
begin

  if (Tag.TagId <> SB_ASN1_SEQUENCE) or (Tag.Count < 2) or (Tag.Count > 3) then
  begin
    Result := SB_PKCS12_ERROR_INVALID_MAC_DATA;
    Exit;
  end;
  { Processing digestInfo }
  if (not Tag.GetField(0).IsConstrained) or (Tag.GetField(0).TagId <> SB_ASN1_SEQUENCE) then
  begin
    Result := SB_PKCS12_ERROR_INVALID_MAC_DATA;
    Exit;
  end;
  CTag := TElASN1ConstrainedTag(Tag.GetField(0));
  if CTag.Count <> 2 then
  begin
    Result := SB_PKCS12_ERROR_INVALID_MAC_DATA;
    Exit;
  end;
  if ProcessAlgorithmIdentifier(CTag.GetField(0), FDigestAlgorithm,
    FDigestAlgorithmParams {$ifndef HAS_DEF_PARAMS}, False {$endif}) <> 0 then
  begin
    Result := SB_PKCS12_ERROR_INVALID_MAC_DATA;
    Exit;
  end;
  if (CTag.GetField(1).IsConstrained) or (CTag.GetField(1).TagId <> SB_ASN1_OCTETSTRING) then
  begin
    Result := SB_PKCS12_ERROR_INVALID_MAC_DATA;
    Exit;
  end;
  FDigest := TElASN1SimpleTag(CTag.GetField(1)).Content;
  { Processing macSalt }
  if (Tag.GetField(1).IsConstrained) or (Tag.GetField(1).TagId <> SB_ASN1_OCTETSTRING) then
  begin
    Result := SB_PKCS12_ERROR_INVALID_MAC_DATA;
    Exit;
  end;
  FSalt := TElASN1SimpleTag(Tag.GetField(1)).Content;
  { Processing iterations }
  if Tag.Count = 3 then
  begin
    if (Tag.GetField(2).IsConstrained) or (Tag.GetField(2).TagId <> SB_ASN1_INTEGER) then
    begin
      Result := SB_PKCS12_ERROR_INVALID_MAC_DATA;
      Exit;
    end;
    FIterations := BufToInt(@TElASN1SimpleTag(Tag.GetField(2)).Content[0],
      Length(TElASN1SimpleTag(Tag.GetField(2)).Content));
  end
  else
    FIterations := 1;
  { Verifying MAC }
  if (Length(FPassword) = 0) and FUseEmptyPasswordWorkaround then
  begin
    SetLength(UseWA, 2);
    UseWA[0] := false;
    UseWA[1] := true;
  end
  else
  begin
    SetLength(UseWA, 1);
    UseWA[0] := false;
  end;
  Result := SB_PKCS12_ERROR_INVALID_MAC;
  for I := 0 to Length(UseWA) - 1 do
  begin
    MACKey := DeriveKeyFromPassword(FPassword, FSalt, SB_PKCS12_KEYDERIVATION_ID_MAC,
      SB_ALGORITHM_DGST_SHA1, FIterations, 20, UseWA[I]);
    KM := TElHMACKeyMaterial.Create;
    KM.Key := MACKey;

    HashFunction := TElHASHFunction.Create(SB_ALGORITHM_MAC_HMACSHA1, KM);
    HashFunction.Update(Buffer, Size);
    Hash := HashFunction.Finish;
    FreeAndNil(HashFunction);
    FreeAndNil(KM);
    if (Length(Hash) = Length(FDigest)) and (CompareMem( @Hash[0], @FDigest[0], Length(Hash) )) then
    begin
      Result := 0;
      Break;
    end;
  end;

end;

function TElPKCS12Message.ProcessSafeContents(Mes : TElPKCS7Message) : integer;
begin
  if Mes.ContentType =  ctData  then
  begin
    Result := ProcessSafeBags(@Mes.Data[0], Length(Mes.Data));
  end
  else
  if Mes.ContentType =  ctEncryptedData  then
  begin
    Result := ProcessEncryptedSafeBags(Mes);
  end
  else
    Result := SB_PKCS12_ERROR_INVALID_SAFE_CONTENTS;
end;

function TElPKCS12Message.ProcessSafeBags(P : pointer; Size : integer) : integer;
var
  SafeContents : TElASN1ConstrainedTag;
  CTag : TElASN1ConstrainedTag;
  I : integer;
begin
  SafeContents := TElASN1ConstrainedTag.CreateInstance;
  try
    if not SafeContents.LoadFromBuffer(P , Size ) then
    begin
      Result := SB_PKCS12_ERROR_INVALID_SAFE_CONTENTS;
      Exit;
    end;

    if (SafeContents.Count <> 1) or (not SafeContents.GetField(0).IsConstrained) or
      (SafeContents.GetField(0).TagId <> SB_ASN1_SEQUENCE) then
    begin
      Result := SB_PKCS12_ERROR_INVALID_SAFE_CONTENTS;
      Exit;
    end;

    CTag := TElASN1ConstrainedTag(SafeContents.GetField(0));
    Result := 0;
    for I := 0 to CTag.Count - 1 do
    begin
      if (not CTag.GetField(I).IsConstrained) or (CTag.GetField(I).TagId <> SB_ASN1_SEQUENCE) then
      begin
        Result := SB_PKCS12_ERROR_INVALID_SAFE_CONTENTS;
        Exit;
      end;

      Result := ProcessSafeBag(TElASN1ConstrainedTag(CTag.GetField(I)));
      if Result <> 0 then
        Break;
    end;
  finally
    FreeAndNil(SafeContents);
  end;
end;

function TElPKCS12Message.ProcessEncryptedSafeBags(Tag : TElPKCS7Message) : integer;
var
  AlgId : integer;
  Salt, Key, IV : ByteArray;
  OutBuf : ByteArray;
  Iterations, Sz : integer;
  KeyLen, IVLen : integer;
  B : boolean;
  UseWA : array of boolean;
  I : integer;
begin
  

  AlgId := GetPBEAlgorithmByOID(Tag.EncryptedData.EncryptedContent.ContentEncryptionAlgorithm);
  if AlgId = SB_ALGORITHM_UNKNOWN then
  begin
    Result := SB_PKCS12_ERROR_UNKNOWN_PBE_ALGORITHM;
    Exit;
  end;
  if not ProcessPBEAlgorithmParams(@Tag.EncryptedData.EncryptedContent.ContentEncryptionAlgorithmParams[0],
    Length(Tag.EncryptedData.EncryptedContent.ContentEncryptionAlgorithmParams),
    Salt, Iterations) then
  begin
    Result := SB_PKCS12_ERROR_INVALID_PBE_ALGORITHM_PARAMS;
    Exit;
  end;
  if not GetKeyAndIVLengths(AlgId, KeyLen, IVLen) then
  begin
    Result := SB_PKCS12_ERROR_INTERNAL_ERROR;
    Exit;
  end;
  if (Length(FPassword) = 0) and (FUseEmptyPasswordWorkaround) then
  begin
    SetLength(UseWA, 2);
    UseWA[0] := false;
    UseWA[1] := true;
  end
  else
  begin
    SetLength(UseWA, 1);
    UseWA[0] := false;
  end;
  Result := SB_PKCS12_ERROR_INVALID_PASSWORD;
  for I := 0 to Length(UseWA) - 1 do
  begin
    Key := DeriveKeyFromPassword(FPassword, Salt, SB_PKCS12_KEYDERIVATION_ID_KEY,
      SB_ALGORITHM_DGST_SHA1, Iterations, KeyLen, UseWA[I]);
    IV := DeriveKeyFromPassword(FPassword, Salt, SB_PKCS12_KEYDERIVATION_ID_IV,
      SB_ALGORITHM_DGST_SHA1, Iterations, IVLen, UseWA[I]);
    Sz := Length(Tag.EncryptedData.EncryptedContent.EncryptedContent);
    SetLength(OutBuf, Sz);
    case AlgId of
      {$ifndef SB_NO_DES}
      SB_ALGORITHM_PBE_SHA1_3DES : B := Decrypt3DES(@Tag.EncryptedData.EncryptedContent.EncryptedContent[0],
        Sz, @OutBuf[0], Sz, Key, IV);
       {$endif}
      {$ifndef SB_NO_RC2}
      SB_ALGORITHM_PBE_SHA1_RC2_40,
      SB_ALGORITHM_PBE_SHA1_RC2_128 : B := DecryptRC2(@Tag.EncryptedData.EncryptedContent.EncryptedContent[0],
        Sz, @OutBuf[0], Sz, Key, IV);
       {$endif}
      {$ifndef SB_NO_RC4}
      SB_ALGORITHM_PBE_SHA1_RC4_40,
      SB_ALGORITHM_PBE_SHA1_RC4_128 : B := DecryptRC4(@Tag.EncryptedData.EncryptedContent.EncryptedContent[0],
        Sz, @OutBuf[0], Sz, Key);
       {$endif}
    else
      B := false;
    end;
    if B then
    begin
      Result := 0;
      Break;
    end;
  end;
  if Result = 0 then
    Result := ProcessSafeBags(@OutBuf[0], Sz);
  if Result <> 0 then // II 20100630: considering all the underlying errors as a result of incorrect password provided
    Result := SB_PKCS12_ERROR_INVALID_PASSWORD;

end;

function TElPKCS12Message.ProcessSafeBag(Tag : TElASN1ConstrainedTag) : integer;
var
  CT : ByteArray;
begin
  if Tag.TagId <> SB_ASN1_SEQUENCE then
  begin
    Result := SB_PKCS12_ERROR_INVALID_SAFE_BAG;
    Exit;
  end;
  if (Tag.Count < 2) or (Tag.Count > 3) then
  begin
    Result := SB_PKCS12_ERROR_INVALID_SAFE_BAG;
    Exit;
  end;
  if (Tag.GetField(0).IsConstrained) or (Tag.GetField(0).TagId <> SB_ASN1_OBJECT) then
  begin
    Result := SB_PKCS12_ERROR_INVALID_SAFE_BAG;
    Exit;
  end;
  if (not Tag.GetField(1).IsConstrained) or (Tag.GetField(1).TagId <> SB_ASN1_A0) then
  begin
    Result := SB_PKCS12_ERROR_INVALID_SAFE_BAG;
    Exit;
  end;
  CT := TElASN1SimpleTag(Tag.GetField(0)).Content;
  if CompareContent(CT, SB_OID_PKCS8_SHROUDED_KEY_BAG) then
  begin
    if (TElASN1ConstrainedTag(Tag.GetField(1)).Count <> 1) or
      (not TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0).IsConstrained) then
    begin
      Result := SB_PKCS12_ERROR_INVALID_SAFE_BAG;
      Exit;
    end;
    Result := ProcessShroudedKeyBag(TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0)));
  end
  else
  if CompareContent(CT, SB_OID_CERT_BAG) then
  begin
    if (TElASN1ConstrainedTag(Tag.GetField(1)).Count <> 1) or
      (not TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0).IsConstrained) then
    begin
      Result := SB_PKCS12_ERROR_INVALID_SAFE_BAG;
      Exit;
    end;
    Result := ProcessCertBag(TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0)));
  end
  else
  if CompareContent(CT, SB_OID_KEY_BAG) then
  begin
    if (TElASN1ConstrainedTag(Tag.GetField(1)).Count <> 1) or
      (not TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0).IsConstrained) then
    begin
      Result := SB_PKCS12_ERROR_INVALID_SAFE_BAG;
      Exit;
    end;
    Result := ProcessKeyBag(TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0)));
  end
  else if CompareContent(CT, SB_OID_CRL_BAG) then
  begin
    if (TElASN1ConstrainedTag(Tag.GetField(1)).Count <> 1) or
      (not TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0).IsConstrained) then
    begin
      Result := SB_PKCS12_ERROR_INVALID_SAFE_BAG;
      Exit;
    end;
    Result := ProcessCRLBag(TElASN1ConstrainedTag(TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0)));
  end
  else
    Result := 0;
  //else
  //  Result := SB_PKCS12_ERROR_INVALID_SAFE_BAG;
end;

function TElPKCS12Message.ProcessKeyBag(Tag : TElASN1ConstrainedTag) : integer;
var
  Data : ByteArray;
  Size : integer;
  Alg, Key, Pars : ByteArray;
begin

  Size := 0;
  Tag.SaveToBuffer( nil , Size);
  SetLength(Data, Size);
  Tag.SaveToBuffer( @Data[0] , Size);
  { Now Data contains the pkcs8 privateKeyInfo structure }
  Result := ProcessPrivateKeyInfo(@Data[0], Size, Alg, Key, Pars);
  if Result = 0 then
  begin
    FPrivateKeys.Add(Key);
    FPrivateKeyParams.Add(Pars);
    FPrivateKeyAlgorithms.Add(Alg);
  end;

end;

function TElPKCS12Message.ProcessShroudedKeyBag(Tag : TElASN1ConstrainedTag) : integer;
var
  Alg, Key, Params, Salt, IV, Pars : ByteArray;
  ParamsTag : TElASN1ConstrainedTag;
  Sz, Iterations, AlgId : integer;
  Data : ByteArray;
  KeyLen, IVLen : integer;
  B : boolean;
  UseWA : array of boolean;
  I : integer;
begin
  

  Result := SB_PKCS12_ERROR_INVALID_SHROUDED_KEY_BAG;
  B := false;
  if (Tag.TagId <> SB_ASN1_SEQUENCE) then
    Exit;
  if Tag.Count <> 2 then
    Exit;
  if ProcessAlgorithmIdentifier(Tag.GetField(0), Alg, Params {$ifndef HAS_DEF_PARAMS}, False {$endif}) <> 0 then
    Exit;
  AlgId := GetPBEAlgorithmByOID(Alg);
  if AlgId = SB_ALGORITHM_UNKNOWN then
  begin
    Result := SB_PKCS12_ERROR_UNKNOWN_PBE_ALGORITHM;
    Exit;
  end;
  if not GetKeyAndIVLengths(AlgId, KeyLen, IVLen) then
  begin
    Result := SB_PKCS12_ERROR_INTERNAL_ERROR;
    Exit;
  end;
  if (Tag.GetField(1).IsConstrained) or (Tag.GetField(1).TagId <> SB_ASN1_OCTETSTRING) then
    Exit;
  { Processing algorithm params }
  ParamsTag := TElASN1ConstrainedTag.CreateInstance;
  try

    if not ParamsTag.LoadFromBuffer(@Params[0], Length(Params)) then
      Exit;
  
    if ParamsTag.Count <> 1 then
      Exit;

    if (not ParamsTag.GetField(0).IsConstrained) or (ParamsTag.GetField(0).TagId <>
      SB_ASN1_SEQUENCE) then
      Exit;
  
    if TElASN1ConstrainedTag(ParamsTag.GetField(0)).Count <> 2 then
      Exit;

    if (TElASN1ConstrainedTag(ParamsTag.GetField(0)).GetField(0).IsConstrained) or
      (TElASN1ConstrainedTag(ParamsTag.GetField(0)).GetField(0).TagId <> SB_ASN1_OCTETSTRING) or
      (TElASN1ConstrainedTag(ParamsTag.GetField(0)).GetField(1).IsConstrained) or
      (TElASN1ConstrainedTag(ParamsTag.GetField(0)).GetField(1).TagId <> SB_ASN1_INTEGER) then
      Exit;

    Salt := TElASN1SimpleTag(TElASN1ConstrainedTag(ParamsTag.GetField(0)).GetField(0)).Content;
    Iterations := BufToInt(@TElASN1SimpleTag(TElASN1ConstrainedTag(ParamsTag.GetField(0)).GetField(1)).Content[0],
      Length(TElASN1SimpleTag(TElASN1ConstrainedTag(ParamsTag.GetField(0)).GetField(1)).Content));
    { Deriving keys and decrypting data }
    if (Length(FPassword) = 0) and FUseEmptyPasswordWorkaround then
    begin
      SetLength(UseWA, 2);
      UseWA[0] := false;
      UseWA[1] := true;
    end
    else
    begin
      SetLength(UseWA, 1);
      UseWA[0] := false;
    end;
    Result := SB_PKCS12_ERROR_INVALID_PASSWORD;
    for I := 0 to Length(UseWA) - 1 do
    begin
      Key := DeriveKeyFromPassword(FPassword, Salt, SB_PKCS12_KEYDERIVATION_ID_KEY,
        SB_ALGORITHM_DGST_SHA1, Iterations, KeyLen, UseWA[I]);
      IV := DeriveKeyFromPassword(FPassword, Salt, SB_PKCS12_KEYDERIVATION_ID_IV,
        SB_ALGORITHM_DGST_SHA1, Iterations, IVLen, UseWA[I]);
      Sz := Length(TElASN1SimpleTag(Tag.GetField(1)).Content);
      SetLength(Data, Sz);
      case AlgId of
        {$ifndef SB_NO_DES}
        SB_ALGORITHM_PBE_SHA1_3DES :
          B := Decrypt3DES(@TElASN1SimpleTag(Tag.GetField(1)).Content[0], Sz, @Data[0], Sz,
            Key, IV);
         {$endif}
        {$ifndef SB_NO_RC2}
        SB_ALGORITHM_PBE_SHA1_RC2_40,
        SB_ALGORITHM_PBE_SHA1_RC2_128 :
          B := DecryptRC2(@TElASN1SimpleTag(Tag.GetField(1)).Content[0], Sz, @Data[0], Sz,
            Key, IV);
         {$endif}
        {$ifndef SB_NO_RC4} 
        SB_ALGORITHM_PBE_SHA1_RC4_40,
        SB_ALGORITHM_PBE_SHA1_RC4_128 :
          B := DecryptRC4(@TElASN1SimpleTag(Tag.GetField(1)).Content[0], Sz, @Data[0], Sz,
            Key);
         {$endif} 
        else
        begin
          Result := SB_PKCS12_ERROR_INTERNAL_ERROR;
          Exit;
        end;
      end;
      if B then
      begin
        Result := 0;
        Break;
      end;
    end;

    if Result = 0 then
    begin
      { Now Data contains the pkcs8 privateKeyInfo structure }
      Result := ProcessPrivateKeyInfo(@Data[0], Sz, Alg, Key, Pars);
      if Result = 0 then
      begin
        FPrivateKeys.Add(Key);
        FPrivateKeyParams.Add(Pars);
        FPrivateKeyAlgorithms.Add(Alg);
      end;
    end;
  finally
    FreeAndNil(ParamsTag);
  end;

end;

function TElPKCS12Message.ProcessCertBag(Tag : TElASN1ConstrainedTag) : integer;
var
  Cert : TElX509Certificate;
begin
  Result := SB_PKCS12_ERROR_INVALID_CERT_BAG;
  if (Tag.TagId <> SB_ASN1_SEQUENCE) or (Tag.Count <> 2) then
    Exit;
  if (Tag.GetField(0).IsConstrained) or (Tag.GetField(0).TagId <> SB_ASN1_OBJECT) then
    Exit;
  if (not Tag.GetField(1).IsConstrained) or (Tag.GetField(1).TagId <> SB_ASN1_A0) then
    Exit;
  { Processing CertType, we support only x.509 }
  if not CompareContent(TElASN1SimpleTag(Tag.GetField(0)).Content,
    SB_OID_CERT_TYPE_X509) then
  begin
    Result := SB_PKCS12_ERROR_UNSUPPORTED_CERTIFICATE_TYPE;
    Exit;
  end;
  if TElASN1ConstrainedTag(Tag.GetField(1)).Count <> 1 then
    Exit;
  if (TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0).IsConstrained) or
    (TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0).TagId <> SB_ASN1_OCTETSTRING) then
    Exit;
  Cert := TElX509Certificate.Create(nil);
  Cert.CryptoProviderManager := FCryptoProviderManager;
  Cert.LoadFromBuffer(@TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0)).Content[0],
    Length(TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0)).Content));
  FCertificates.Add(Cert{$ifndef HAS_DEF_PARAMS}, true {$endif});
  FreeAndNil(Cert);
  Result := 0;
end;

function TElPKCS12Message.ProcessCRLBag(Tag : TElASN1ConstrainedTag) : integer;
var
  Crl : TElCertificateRevocationList;
  Buf : ByteArray;
begin
  Result := SB_PKCS12_ERROR_INVALID_CRL_BAG;
  if not Tag.CheckType(SB_ASN1_SEQUENCE, true) then
    Exit;
  if Tag.Count <> 2 then
    Exit;
  if (Tag.GetField(0).IsConstrained) or (Tag.GetField(0).TagId <> SB_ASN1_OBJECT) then
    Exit;
  if (not Tag.GetField(1).IsConstrained) or (Tag.GetField(1).TagId <> SB_ASN1_A0) then
    Exit;
  { Processing CertType, we support only x.509 }
  if not CompareContent(TElASN1SimpleTag(Tag.GetField(0)).Content,
    SB_OID_CRL_TYPE_X509) then
  begin
    Result := SB_PKCS12_ERROR_UNSUPPORTED_CRL_TYPE;
    Exit;
  end;
  if TElASN1ConstrainedTag(Tag.GetField(1)).Count <> 1 then
    Exit;
  if (TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0).IsConstrained) or
    (TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0).TagId <> SB_ASN1_OCTETSTRING) then
    Exit;
  Buf := TElASN1SimpleTag(TElASN1ConstrainedTag(Tag.GetField(1)).GetField(0)).Content;
  Crl := TElCertificateRevocationList.Create(nil);
  try
    if Crl.LoadFromBuffer( @Buf[0], Length(Buf) ) = 0 then
      FCRLs.Add(Crl);
  finally
    FreeAndNil(Crl);
  end;
  Result := 0;
end;

function TElPKCS12Message.ProcessPrivateKeyInfo(Buffer : pointer; Size : integer;
  var Algorithm : ByteArray; var PrivateKey : ByteArray; var PrivateKeyParams : ByteArray) : integer;
var
  Tag, CTag : TElASN1ConstrainedTag;
  Params : ByteArray;
begin
  Result := SB_PKCS12_ERROR_INVALID_PRIVATE_KEY;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if not Tag.LoadFromBuffer(Buffer , Size ) then
    begin
      Result := SB_PKCS12_ERROR_INVALID_PASSWORD;
      Exit;
    end;

    if Tag.Count <> 1 then
      Exit;

    if (not Tag.GetField(0).IsConstrained) or (Tag.GetField(0).TagId <> SB_ASN1_SEQUENCE) then
      Exit;

    CTag := TElASN1ConstrainedTag(Tag.GetField(0));
    if (CTag.Count < 3) or (CTag.Count > 4) then
      Exit;

    if (CTag.GetField(0).IsConstrained) or (CTag.GetField(0).TagId <> SB_ASN1_INTEGER) then
      Exit;

    if not CompareContent(TElASN1SimpleTag(CTag.GetField(0)).Content, GetByteArrayFromByte(0)) then
      Exit;

    Result := ProcessAlgorithmIdentifier(CTag.GetField(1), Algorithm, Params {$ifndef HAS_DEF_PARAMS}, False {$endif});
    if Result <> 0 then
      Exit;

    if (CTag.GetField(2).IsConstrained) or (CTag.GetField(2).TagId <> SB_ASN1_OCTETSTRING) then
    begin
      Result := SB_PKCS12_ERROR_INVALID_PRIVATE_KEY;
      Exit;
    end;

    PrivateKey := TElASN1SimpleTag(CTag.GetField(2)).Content;
    PrivateKeyParams := CloneArray(Params);
  finally
    FreeAndNil(Tag);
  end;

  Result := 0;
end;

function TElPKCS12Message.DeriveKeyFromPassword(const Password : string; const Salt : ByteArray;
  Id : byte; HashAlgorithm : integer; Iters : integer; Size : integer;
  UseEmptyPassBugWorkaround : boolean = false) : ByteArray;
var
  TmpS, P,
  Diversifier, S, SI,
  FormattedPassword : ByteArray;
  cp : integer;
  PHash : pointer;

  Tmp, Sz : integer;
  I, J, V : integer;
  U : integer;
  M128 : TMessageDigest128;
  M160 : TMessageDigest160;
  LA, LB, LC, LD, LE : PLInt;
begin

  (* UseEmptyPassBugWorkaround legend:
     Some buggy software generate PKCS#12 structures using non-conformant
     key derivation algorithm (it builds long password string of #0#0 in
     case of the empty password, even though PKCS#12 specification claims
     that password string should be empty in this case) *)

  { 1. Formatting password }
  (*
     II20070914: Though PKCS12 specification describes the algorithm for translating
     the password into 'wide-character' form, Windows CryptoAPI uses another
     algorithm (it just converts the passed password string to Unicode form
     using MultiByteToWideChar). I left the original algorithm commented
     and added the Windows-compatible implementation of password extension algorithm.
  *)
  (*
  SetLength(FormattedPassword, Length(Password) * 2 + 2);
  {$ifdef SB_VCL}
  fpp := @FormattedPassword[0];
  for I := 1 to Length(Password) do
  begin
    fpp^ := #0;
    inc(fpp);
    fpp^ := Password[I];
  inc(fpp);
  end;
  FormattedPassword[Length(Password) * 2 + 1]:= #0;
  FormattedPassword[Length(Password) * 2 + 2] := #0;
  {$else}
  for i := 0 to Length(Password) - 1 do
  begin
    FormattedPassword[i * 2] := 0;
    FormattedPassword[i * 2 + 1] := Ord(Password[i + AnsiStrStartOffset]);
  end;
  FormattedPassword[Length(Password) * 2]:= 0;
  FormattedPassword[Length(Password) * 2 + 1] := 0;
  {$endif}
  *)
  (*
  SetLength(FormattedPassword, Length(Password) * 2 + 2);
  FillChar(FormattedPassword[0], Length(FormattedPassword), 0);
  MultiByteToWideChar(CP_ACP, 0, @Password[0], Length(Password), @FormattedPassword[0],
    Length(Password));
  for I := 0 to Length(FormattedPassword) div 2 - 1 do
  begin
    C := FormattedPassword[I * 2 + 1];
    FormattedPassword[I * 2 + 1] := FormattedPassword[I * 2 + 2];
    FormattedPassword[I * 2 + 2] := C;
  end;
  *)
  FormattedPassword := UnicodeChangeEndianness(StrToWideStr(Password));
  I := Length(FormattedPassword);
  SetLength(FormattedPassword, I + 2);

  FormattedPassword[I + 0] := byte(0);
  FormattedPassword[I + 0 + 1] := byte(0);

  { 2. Constructing diversifier }
  V := 64;
  if HashAlgorithm = SB_ALGORITHM_DGST_SHA1 then
    U := 20
  else
  if (HashAlgorithm = SB_ALGORITHM_DGST_MD5) then
    U := 16
  else
  begin
    SetLength(Result, 0);
    Exit;
  end;
  SetLength(Diversifier, V);
  {$ifndef SB_PASCAL_STRINGS}
  for i := 0 to Length(Diversifier) - 1 do
    Diversifier[i] := Id;
   {$else}
  FillChar(Diversifier[0], Length(Diversifier), Id);
   {$endif}
  { 3. Constructing S string }
  Tmp := Length(Salt) div V;
  if (Length(Salt) mod V) <> 0 then
    Inc(Tmp);
  Tmp := Tmp * V;

  // if salt is empty, the S concatenation must also be empty -- PKCS#12
  if Length(Salt) > 0 then
  begin
    SetLength(S, Tmp);
    cp := 0;
    while cp < Tmp do
    begin
      if Tmp - cp >= Length(Salt) then
        SBMove(Salt[0], S[cp], Length(Salt))
      else
        SBMove(Salt[0], S[cp], Tmp - cp);
      inc(cp, Length(Salt));
    end;
  end
  else
    S := EmptyArray;

  { 4. Constructing P string }
  Tmp := Length(FormattedPassword) div V;
  if (Length(FormattedPassword) mod V) <> 0 then
    Inc(Tmp);
  Tmp := Tmp * V;

  // if password is empty, the P concatenation must also be empty -- PKCS#12
  if (Length(Password) > 0) or (UseEmptyPassBugWorkaround and (Length(FormattedPassword) > 0)) then
  begin
    SetLength(P, Tmp);
    cp := 0;
    while cp < Tmp do
    begin
      if Tmp - cp >= Length(FormattedPassword) then
        SBMove(FormattedPassword[0], P[cp], Length(FormattedPassword))
      else
        SBMove(FormattedPassword[0], P[cp], Tmp - cp);
      inc(cp, Length(FormattedPassword));
    end;
  end
  else
    P := EmptyArray;

  SI := SBConcatArrays(S, P);
  
  { 5. Iterating }
  Tmp := Size div U;
  if Size mod U <> 0 then
    Inc(Tmp);

  SetLength(Result, 0);

  LCreate(LA);
  LCreate(LB);
  LCreate(LC);
  LCreate(LD);
  LCreate(LE);
  LShiftLeft(LE, V shr 2);
  for I := 1 to Tmp do
  begin
    TmpS := SBConcatArrays(Diversifier, SI);

    if HashAlgorithm = SB_ALGORITHM_DGST_SHA1 then
    begin
      M160 := CalculateHashSHA1(@TmpS[0], Length(TmpS), Iters);
      PHash := @M160;
    end
    else
    if HashAlgorithm = SB_ALGORITHM_DGST_MD5 then
    begin
      M128 := CalculateHashMD5(@TmpS[0], Length(TmpS), Iters);
      PHash := @M128;
    end
    else
      PHash := nil;

    Assert(PHash <> nil);
    SetLength(TmpS, V);
    for J := 0 to (V div U) - 1 do
      SBMove(PHash^, TmpS[J * U {+ 1}], U);
    SBMove(PHash^, TmpS[(V div U) * U {+ 1}], V mod U);
    for J := 0 to ((Length(S) + Length(P)) div V) - 1 do
    begin
      PointerToLInt(LA, @SI[J * V {+ 1}], V);
      PointerToLInt(LB, @TmpS[0], Length(TmpS));
      LAdd(LA, LB, LC);
      LAdd(LC, LD, LA);
      LMod(LA, LE, LB);
      Sz := V;
      LIntToPointer(LB, @SI[J * V {+ 1}], Sz);
    end;
    Sz := Length(Result);
    SetLength(Result, Sz + U);
    SBMove(PHash^, Result[Sz {+ 1}], U);
  end;
  SetLength(Result, Size);
  LDestroy(LA);
  LDestroy(LB);
  LDestroy(LC);
  LDestroy(LD);
  LDestroy(LE);

end;

function TElPKCS12Message.CalculateHashSHA1(Buffer : pointer; Size : integer;
  Iterations : integer) : TMessageDigest160;
var
  I : integer;
begin
  Result := HashSHA1(Buffer, Size);
  for I := 0 to Iterations - 2 do
    Result := HashSHA1(@Result, 20);

end;

function TElPKCS12Message.CalculateHashMD5(Buffer : pointer; Size : integer;
  Iterations : integer) : TMessageDigest128;
var
  I : integer;
begin
  Result := HashMD5(Buffer, Size);
  for I := 0 to Iterations - 2 do
    Result := HashMD5(@Result, 16);

end;

function TElPKCS12Message.CheckPadding(Buffer : pointer; Size : integer): boolean;
var
  PLen, I : integer;
begin
  if Size > 0 then
  begin
    PLen := PByteArray(Buffer)[Size - 1];
    if (PLen <= Size) and (PLen <> 0) then
    begin
      Result := true;
      for I := 0 to PLen - 1 do
        if PByteArray(Buffer)[Size - 1 - I] <> PLen then
        begin
          Result := false;
          Break;
        end;
    end
    else
      Result := false;
  end
  else
    Result := true;
end;

{$ifndef SB_NO_RC2}
function TElPKCS12Message.DecryptRC2(InBuffer : pointer; InSize : integer; OutBuffer :
  pointer; var OutSize : integer; const Key : ByteArray; const IV : ByteArray) : boolean;
var
  Crypto : TElRC2SymmetricCrypto;
  KeyMaterial : TElSymmetricKeyMaterial;
begin
  Result := false;
  Crypto := TElRC2SymmetricCrypto.Create(cmCBC);
  KeyMaterial := TElSymmetricKeyMaterial.Create();

  try
    Crypto.Padding := cpPKCS5;
    KeyMaterial.Key := (Key);
    KeyMaterial.IV := (IV);
    Crypto.KeyMaterial := KeyMaterial;
    Crypto.Decrypt(InBuffer, InSize, OutBuffer, OutSize);
    Result := true;
  except
    ;
  end;

  FreeAndNil(Crypto);
  FreeAndNil(KeyMaterial);
end;
 {$endif}

{$ifndef SB_NO_DES}
function TElPKCS12Message.Decrypt3DES(InBuffer : pointer; InSize : integer;
  OutBuffer : pointer; var OutSize : integer; const Key : ByteArray; const IV : ByteArray) : boolean;
var
  Crypto : TEl3DESSymmetricCrypto;
  KeyMaterial : TElSymmetricKeyMaterial;
begin
  Result := false;
  Crypto := TEl3DESSymmetricCrypto.Create(cmCBC);
  KeyMaterial := TElSymmetricKeyMaterial.Create();

  try
    Crypto.Padding := cpPKCS5;
    KeyMaterial.Key := (Key);
    KeyMaterial.IV := (IV);
    Crypto.KeyMaterial := KeyMaterial;
    Crypto.Decrypt(InBuffer, InSize, OutBuffer, OutSize);
    Result := true;
  except
    ;
  end;

  FreeAndNil(Crypto);
  FreeAndNil(KeyMaterial);
end;
 {$endif}

{$ifndef SB_NO_RC4}
function TElPKCS12Message.DecryptRC4(InBuffer : pointer; InSize : integer;
  OutBuffer : pointer; var OutSize : integer; const Key : ByteArray) : boolean;
var
  Crypto : TElRC4SymmetricCrypto;
  KeyMaterial : TElSymmetricKeyMaterial;
begin
  Result := false;
  Crypto := TElRC4SymmetricCrypto.Create(cmDefault);
  KeyMaterial := TElSymmetricKeyMaterial.Create();

  try
    Crypto.Padding := cpNone;
    KeyMaterial.Key := (Key);
    Crypto.KeyMaterial := KeyMaterial;
    Crypto.Decrypt(InBuffer, InSize, OutBuffer, OutSize);
    Result := true;
  except
    ;
  end;

  FreeAndNil(Crypto);
  FreeAndNil(KeyMaterial);
end;
 {$endif}

function TElPKCS12Message.GetKeyAndIVLengths(AlgId : integer; var KeyLen : integer;
  var IVLen : integer) : boolean;
begin
  Result := true;
  case AlgId of
    SB_ALGORITHM_PBE_SHA1_3DES :
    begin
      KeyLen := 24;
      IVLen := 8;
    end;
    {$ifndef SB_NO_RC4}
    SB_ALGORITHM_PBE_SHA1_RC4_128 :
    begin
      KeyLen := 16;
      IVLen := 0;
    end;
    SB_ALGORITHM_PBE_SHA1_RC4_40 :
    begin
      KeyLen := 5;
      IVLen := 0;
    end;
     {$endif}
    {$ifndef SB_NO_RC2} 
    SB_ALGORITHM_PBE_SHA1_RC2_128 :
    begin
      KeyLen := 16;
      IVLen := 8;
    end;
    SB_ALGORITHM_PBE_SHA1_RC2_40 :
    begin
      KeyLen := 5;
      IVLen := 8;
    end;
     {$endif}
  else
    Result := false;
  end;
end;

function CompareLongIntMem(const Buffer1, Buffer2 : array of byte) : boolean;
var Length1,
    Length2 : integer;
begin
  result := false;
  Length1 := Length(Buffer1);
  Length2 := Length(Buffer2);
  if (Length1 <> Length2) and (Length1 + 1 <> Length2) and (Length1 - 1 <> Length2) then
    exit;
  if Length1 = Length2 then
    result := SysUtils.CompareMem(@Buffer1[0], @Buffer2[0], Length1)
  else
  if Length1 + 1 = Length2 then
    result := (Buffer2[0] = 0) and SysUtils.CompareMem(@Buffer1[0], @Buffer2[1], Length1)
  else
  if Length1 - 1 = Length2 then
    result := (Buffer1[0] = 0) and SysUtils.CompareMem(@Buffer1[1], @Buffer2[0], Length2)
end;

function TElPKCS12Message.KeyCorresponds(Certificate : TElX509Certificate;
  KeyBuffer : pointer; KeySize : integer) : boolean;
var
  A, B, C, D, E, F, G, H, I : ByteArray;
  ASize, BSize, CSize, DSize, ESize, FSize, GSize, HSize, ISize : integer;
  {$ifdef SB_HAS_ECC}
  ECKM : TElECKeyMaterial;
   {$endif}
begin

  Result := false;
  if (Certificate.PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSA_ENCRYPTION) or
    (Certificate.PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSAPSS) or
    (Certificate.PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_RSAOAEP) then
  begin
    ASize := 0; BSize := 0;
    Certificate.GetRSAParams(nil, ASize, nil, BSize);
    if (ASize <= 0) or (BSize <= 0) then
      Exit;
    SetLength(A, ASize);
    SetLength(B, BSize);
    Certificate.GetRSAParams(@A[0], ASize, @B[0], BSize);
    SetLength(A, ASize);
    SetLength(B, BSize);
    CSize := 0; DSize := 0; ESize := 0;
    SBRSA.DecodePrivateKey(KeyBuffer, KeySize, nil, CSize, nil, DSize, nil, ESize);
    if (CSize <= 0) or (DSize <= 0) or (ESize <= 0) then
      Exit;
    SetLength(C, CSize);
    SetLength(D, DSize);
    SetLength(E, ESize);
    if SBRSA.DecodePrivateKey(KeyBuffer, KeySize, @C[0], CSize, @D[0], DSize,
      @E[0], ESize) then
    begin
      SetLength(C, CSize);
      SetLength(D, DSize);
      result := CompareLongIntMem(C, A) and CompareLongIntMem(B, D);
    end;
  end
  else
  if Certificate.PublicKeyAlgorithm = SB_CERT_ALGORITHM_ID_DSA then
  begin
    ASize := 0; BSize := 0; CSize := 0; DSize := 0;
    Certificate.GetDSSParams(nil, ASize, nil, BSize, nil, CSize, nil, DSize);
    if (ASize <= 0) or (BSize <= 0) or (CSize <= 0) or (DSize <= 0) then
      Exit;
    SetLength(A, ASize);
    SetLength(B, BSize);
    SetLength(C, CSize);
    SetLength(D, DSize);
    Certificate.GetDSSParams(@A[0], ASize, @B[0], BSize, @C[0], CSize, @D[0], DSize);
    SetLength(A, ASize);
    SetLength(B, BSize);
    SetLength(C, CSize);
    SetLength(D, DSize);
    ESize := 0; FSize := 0; GSize := 0; HSize := 0; ISize := 0;
    SBDSA.DecodePrivateKey(KeyBuffer, KeySize, nil, ESize, nil, FSize, nil, GSize,
      nil, HSize, nil, ISize);
    if (ESize <= 0) or (FSize <= 0) or (GSize <= 0) or (HSize <= 0) or (ISize <= 0) then
      Exit;
    SetLength(E, ESize);
    SetLength(F, FSize);
    SetLength(G, GSize);
    SetLength(H, HSize);
    SetLength(I, ISize);
    if SBDSA.DecodePrivateKey(KeyBuffer, KeySize, @E[0], ESize, @F[0], FSize,
      @G[0], GSize, @H[0], HSize, @I[0], ISize) then
    begin
      SetLength(E, ESize);
      SetLength(F, FSize);
      SetLength(G, GSize);
      SetLength(H, HSize);
      result := CompareLongIntMem(A, E) and CompareLongIntMem(B, F) and
                CompareLongIntMem(C, G) and CompareLongIntMem(D, H);
    end;
  end
  {$ifdef SB_HAS_ECC}
  else if Certificate.PublicKeyAlgorithm = SB_CERT_ALGORITHM_EC then
  begin
    try
      ECKM := TElECKeyMaterial.Create();
      try
        ECKM.Assign(Certificate.KeyMaterial); //assigning domain parameters
        ECKM.LoadSecret(KeyBuffer, KeySize);
        result := ECKM.Equals(Certificate.KeyMaterial, true);
      finally
        FreeAndNil(ECKM);
      end;
      // hard-coding true for test purposes
    except
      ;
    end;
  end
   {$endif}
  {$ifdef SB_HAS_GOST}
  else if Certificate.PublicKeyAlgorithm = SB_CERT_ALGORITHM_GOST_R3410_1994 then
  begin
    Result := true; // TODO : possibly, change this code to public key calculation and comparision
  end
  {$ifdef SB_HAS_ECC}
  else if Certificate.PublicKeyAlgorithm = SB_CERT_ALGORITHM_GOST_R3410_2001 then
  begin
    Result := true;  // TODO : possibly, change this code to public key calculation and comparision
  end
   {$endif}
   {$endif}

end;


function TElPKCS12Message.SaveToBuffer(Buffer : pointer; var Size : integer) : integer;
var
  Msg, TagAuth, TagMac : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
begin
  FLastKeyId := $01000001;
  {if FCertificates.Count = 0 then
  begin
    Result := SB_PKCS12_ERROR_NO_CERTIFICATES;
    Exit;
  end;}
  Msg := TElASN1ConstrainedTag.CreateInstance;
  try
    Msg.TagId := SB_ASN1_SEQUENCE;
    STag := TElASN1SimpleTag(Msg.GetField(Msg.AddField(false)));
    STag.Content := GetByteArrayFromByte(3);
    STag.TagId := SB_ASN1_INTEGER;
    TagAuth := TElASN1ConstrainedTag(Msg.GetField(Msg.AddField(true)));
    TagMac := TElASN1ConstrainedTag(Msg.GetField(Msg.AddField(true)));
    Result := SaveAuthenticatedSafe(TagAuth, TagMac);
    if Result <> 0 then
      Exit;

    if Msg.SaveToBuffer(Buffer, Size) then
      Result := 0
    else
      Result := SB_PKCS12_ERROR_BUFFER_TOO_SMALL;
  finally
    FreeAndNil(Msg);
  end;
end;


function TElPKCS12Message.SaveAuthenticatedSafe(Tag : TElASN1ConstrainedTag;
  MAC : TElASN1ConstrainedTag) : integer;
var
  STag, STagSeq : TElASN1SimpleTag;
  CTag, CTagSeq : TElASN1ConstrainedTag;
  I, OutSz : integer;
  Buf : ByteArray;
  Encrypted : ByteArray;
begin
  

  Tag.TagId := SB_ASN1_SEQUENCE;
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_OBJECT;
  STag.Content := SB_OID_PKCS7_DATA;
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  CTag.TagId := SB_ASN1_A0;
  STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
  STag.TagId := SB_ASN1_OCTETSTRING;
  { Writing private keys and certificates }
  CTagSeq := TElASN1ConstrainedTag.CreateInstance;
  try
    CTagSeq.TagId := SB_ASN1_SEQUENCE;
    for I := 0 to FCertificates.Count - 1 do
    begin
      if (FCertificates.Certificates[I].PrivateKeyExists) and
      (FCertificates.Certificates[I].PrivateKeyExtractable) and
      (FCertificates.Certificates[I].PublicKeyAlgorithm <> SB_CERT_ALGORITHM_DH_PUBLIC) then
      begin
        OutSz := 0;

        SetLength(Encrypted, OutSz);
        SaveShroudedKeyBag(nil, OutSz, FCertificates.Certificates[I]);
        SetLength(Encrypted, OutSz);
        Result := SaveShroudedKeyBag(@Encrypted[0], OutSz, FCertificates.Certificates[I]);
        if Result <> 0 then
          Exit;
      
        SetLength(Encrypted, OutSz);
        STagSeq := TElASN1SimpleTag(CTagSeq.GetField(CTagSeq.AddField(false)));
        STagSeq.WriteHeader := false;
        STagSeq.Content := CloneArray(Encrypted);
      end;
      OutSz := 0;
      SetLength(Encrypted, OutSz);
      SaveCertBag(FCertificates.Certificates[i].CertificateBinary,
         FCertificates.Certificates[I].CertificateSize, nil , OutSz);
      SetLength(Encrypted, OutSz);
      Result := SaveCertBag(FCertificates.Certificates[i].CertificateBinary,
         FCertificates.Certificates[I].CertificateSize, @Encrypted[0] , OutSz);
      if Result <> 0 then
        Exit;

      SetLength(Encrypted, OutSz);
      STagSeq := TElASN1SimpleTag(CTagSeq.GetField(CTagSeq.AddField(false)));
      STagSeq.WriteHeader := false;
      STagSeq.Content := CloneArray(Encrypted);
      Inc(FLastKeyId);
    end;
    for I := 0 to FCRLs.Count - 1 do
    begin
      OutSz := 0;
      FCRLs.CRLs[I].SaveToBuffer( nil , OutSz);
      SetLength(Buf, OutSz);
      FCRLs.CRLs[I].SaveToBuffer( @Buf[0] , OutSz);
      SetLength(Buf, OutSz);

      OutSz := 0;
      SetLength(Encrypted, OutSz);
      SaveCRLBag(@Buf[0], Length(Buf), nil, OutSz);
      SetLength(Encrypted, OutSz);
      Result := SaveCRLBag(@Buf[0], Length(Buf), @Encrypted[0], OutSz);
      if Result <> 0 then
        Exit;

      SetLength(Encrypted, OutSz);
      STagSeq := TElASN1SimpleTag(CTagSeq.GetField(CTagSeq.AddField(false)));
      STagSeq.WriteHeader := false;
      STagSeq.Content := CloneArray(Encrypted);
      Inc(FLastKeyId);
    end;
    OutSz := 0;
    SetLength(Encrypted, OutSz);
    CTagSeq.SaveToBuffer( nil , OutSz);
    SetLength(Encrypted, OutSz);
    CTagSeq.SaveToBuffer( @Encrypted[0] , OutSz);
    SetLength(Encrypted, OutSz);
  finally
    FreeAndNil(CTagSeq);
  end;
  STag.Content := CloneArray(Encrypted);
  SaveMACData( @Encrypted[0], OutSz  , MAC);
  Result := 0;

end;

function TElPKCS12Message.SaveShroudedKeyBag(OutBuffer : pointer;
  var OutSize : integer; Cert : TElX509Certificate) : integer;
var
  Msg : TElPKCS7Message;
  Alg, Params, Salt, Key, IV, TmpS : ByteArray;
  KeyLen, IVLen, Sz : integer;
  TmpSz : TSBInteger;
  MainTag, GlobalTag, CTag, Tag, CTagSeq, KeyTag, KeyTagSeq : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  Attrs : TElPKCS7Attributes;
  Estimating : boolean;
begin
  

  //Result := SB_PKCS12_ERROR_INTERNAL_ERROR;
  { Call this routine with OutBuffer set to nil to count estimated output length }
  Estimating := (OutBuffer = nil) ;
  Alg := GetOIDByPBEAlgorithm(FKeyEncryptionAlgorithm);
  if Length(Alg) = 0 then
  begin
    Result := SB_PKCS12_ERROR_UNKNOWN_PBE_ALGORITHM;
    Exit;
  end;
  { The main bag tag }
  MainTag := TElASN1ConstrainedTag.CreateInstance;
  try
    MainTag.TagId := SB_ASN1_SEQUENCE;
    GlobalTag := TElASN1ConstrainedTag(MainTag.GetField(MainTag.AddField(true))); //!!!
    GlobalTag.TagId := SB_ASN1_SEQUENCE;
    { bag id }
    STag := TElASN1SimpleTag(GlobalTag.GetField(GlobalTag.AddField(false)));
    STag.TagId := SB_ASN1_OBJECT;
    STag.Content := SB_OID_PKCS8_SHROUDED_KEY_BAG;
    { bag contents }
    CTag := TElASN1ConstrainedTag(GlobalTag.GetField(GlobalTag.AddField(true)));
    CTag.TagId := SB_ASN1_A0;
    Tag := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
    Tag.TagId := SB_ASN1_SEQUENCE;
    CTagSeq := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    CTagSeq.TagId := SB_ASN1_SEQUENCE;
    STag := TElASN1SimpleTag(CTagSeq.GetField(CTagSeq.AddField(false)));
    STag.TagId := SB_ASN1_OBJECT;
    STag.Content := Alg;
    CTagSeq := TElASN1ConstrainedTag(CTagSeq.GetField(CTagSeq.AddField(true)));
    Salt := FRandom.Generate(8);
    SavePBEAlgorithmParams(Salt, FIterations, CTagSeq);
    if not GetKeyAndIVLengths(FKeyEncryptionAlgorithm, KeyLen, IVLen) then
    begin
      Result := SB_PKCS12_ERROR_INTERNAL_ERROR;
      Exit;
    end;

    if not Estimating then
    begin
      Key := DeriveKeyFromPassword(FPassword, Salt, SB_PKCS12_KEYDERIVATION_ID_KEY,
        SB_ALGORITHM_DGST_SHA1, FIterations, KeyLen);
      IV := DeriveKeyFromPassword(FPassword, Salt, SB_PKCS12_KEYDERIVATION_ID_IV,
        SB_ALGORITHM_DGST_SHA1, FIterations, IVLen);
    end;

    { forming PrivateKeyInfo structure and encrypting it }
    KeyTag := TElASN1ConstrainedTag.CreateInstance;

    KeyTag.TagId := SB_ASN1_SEQUENCE;
    STag := TElASN1SimpleTag(KeyTag.GetField(KeyTag.AddField(false)));
    STag.TagId := SB_ASN1_INTEGER;
    STag.Content := GetByteArrayFromByte(0);

    KeyTagSeq := TElASN1ConstrainedTag(KeyTag.GetField(KeyTag.AddField(true)));
    KeyTagSeq.TagId := SB_ASN1_SEQUENCE;

    Cert.PublicKeyAlgorithmIdentifier.SaveToTag(KeyTagSeq);

    if Cert.KeyMaterial is TElDSAKeyMaterial then
      TmpS := WriteInteger(TElDSAKeyMaterial(Cert.KeyMaterial).X)
    else
    {$ifndef SB_NO_DH}
    if Cert.KeyMaterial is TElDHKeyMaterial then
    begin
      Result := SB_PKCS12_ERROR_UNSUPPORTED_CERTIFICATE_TYPE;
      Exit;
    end
    else
     {$endif}
    begin
      TmpSz := 0;
      Cert.KeyMaterial.SaveSecret(nil, TmpSz);
      SetLength(TmpS, TmpSz);
      Cert.KeyMaterial.SaveSecret(@TmpS[0], TmpSz);
      SetLength(TmpS, TmpSz);
    end;  

    STag := TElASN1SimpleTag(KeyTag.GetField(KeyTag.AddField(false)));
    STag.TagId := SB_ASN1_OCTETSTRING;
    STag.Content := CloneArray(TmpS);
    KeyTagSeq := TElASN1ConstrainedTag(KeyTag.GetField(KeyTag.AddField(true)));

    Attrs := TElPKCS7Attributes.Create;
    try
      Attrs.Count := 1;
      Attrs.Attributes[0] := SB_OID_LOCAL_KEY_ID;

      TmpS := GetByteArrayFromDWordBE(FLastKeyID);
      Attrs.Values[0].Add(SBConcatArrays(BytesOfString(#$04#$04), TmpS));

      SaveAttributes(KeyTagSeq, Attrs);
      KeyTagSeq.TagId := SB_ASN1_A0; // implicit SET
      Sz := 0;
      SetLength(TmpS, Sz);
      KeyTag.SaveToBuffer( nil , Sz);
      SetLength(TmpS, Sz);
      KeyTag.SaveToBuffer(@TmpS[0], Sz);
      SetLength(TmpS, Sz);
      FreeAndNil(KeyTag);
      SetLength(Params, Sz + IVLen);
      Sz := Length(Params);
      if not Estimating then
      begin
        if not EncryptContent(@TmpS[0], Length(TmpS), @Params[0], Sz, FKeyEncryptionAlgorithm, Key, IV) then
        begin
          Result := SB_PKCS12_ERROR_INTERNAL_ERROR;
          Exit;
        end;
      end;
      SetLength(Params, Sz);
      STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
      STag.TagId := SB_ASN1_OCTETSTRING;
      STag.Content := CloneArray(Params);
      { bag attributes }
      CTag := TElASN1ConstrainedTag(GlobalTag.GetField(GlobalTag.AddField(true)));
      SaveAttributes(CTag, Attrs);
    finally
      FreeAndNil(Attrs);
    end;
    Sz := 0;
    SetLength(TmpS, Sz);
    MainTag.SaveToBuffer(nil, Sz);
    SetLength(TmpS, Sz);
    MainTag.SaveToBuffer(@TmpS[0], Sz);
    SetLength(TmpS, Sz);
  finally
    FreeAndNil(MainTag);
  end;

  Msg := TElPKCS7Message.Create;
  try
    Msg.ContentType :=  ctData ;
    Msg.Data := TmpS;
    if not Msg.SaveToBuffer(OutBuffer, OutSize) then
      Result := SB_PKCS12_ERROR_INTERNAL_ERROR
    else
      Result := 0;
  finally
    FreeAndNil(Msg);
  end;
  if Estimating then
    Inc(OutSize, 64);

end;

function TElPKCS12Message.SaveCertBag(CertBuffer : pointer; CertSize : integer;
  OutBuffer : pointer; var OutSize : integer) : integer;
var
  Alg, Salt, TmpS, S, Cnt : ByteArray;
  Key, IV : ByteArray;
  Msg : TElPKCS7Message;
  CTag, Tag, GlobalTag, AttrTag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  KeyLen, IVLen, Sz : integer;
  Attrs : TElPKCS7Attributes;
  Estimating : boolean;
begin
  

  { Call this routine with OutBuffer set to nil to count estimated output length }
  Estimating := (OutBuffer = nil) ;
  Alg := GetOIDByPBEAlgorithm(FCertEncryptionAlgorithm);
  if Length(Alg) = 0 then
  begin
    Result := SB_PKCS12_ERROR_UNKNOWN_PBE_ALGORITHM;
    Exit;
  end;
  GlobalTag := TElASN1ConstrainedTag.CreateInstance;
  try
    GlobalTag.TagId := SB_ASN1_SEQUENCE;
    CTag := TElASN1ConstrainedTag(GlobalTag.GetField(GlobalTag.AddField(true)));
    CTag.TagId := SB_ASN1_SEQUENCE;

    STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
    STag.TagId := SB_ASN1_OBJECT;
    STag.Content := SB_OID_CERT_BAG;

    Tag := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
    Tag.TagId := SB_ASN1_A0;

    AttrTag := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
    Attrs := TElPKCS7Attributes.Create;
    try
      Attrs.Count := 1;
      Attrs.Attributes[0] := SB_OID_LOCAL_KEY_ID;
      {$ifndef SB_BUFFERTYPE_IS_BYTEARRAY}
      Attrs.Values[0].Add(TByteArrayConst(BufferType(#$04#$04) + AnsiChar((FLastKeyId shr 24) and $FF) +
        AnsiChar((FLastKeyId shr 16) and $FF) + AnsiChar((FLastKeyId shr 8) and $FF) +
        AnsiChar(FLastKeyId and $FF)));
       {$else}
      TmpS := GetByteArrayFromDWordBE(FLastKeyID);
      Attrs.Values[0].Add(SBConcatArrays(BytesOfString(#$04#$04), TmpS));
       {$endif}
      SaveAttributes(AttrTag, Attrs);
    finally
      FreeAndNil(Attrs);
    end;
    AttrTag.TagId := SB_ASN1_SET;
    Tag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    Tag.TagId := SB_ASN1_SEQUENCE;
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.TagId := SB_ASN1_OBJECT;
    STag.Content := SB_OID_CERT_TYPE_X509;
    Tag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    Tag.TagId := SB_ASN1_A0;
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.TagId := SB_ASN1_OCTETSTRING;
    SetLength(TmpS, CertSize);
    if not Estimating then
      SBMove(CertBuffer^, TmpS[0], CertSize);
    STag.Content := CloneArray(TmpS);
    Sz := 0;
    SetLength(S, Sz);
    GlobalTag.SaveToBuffer(nil, Sz);
    SetLength(S, Sz);
    GlobalTag.SaveToBuffer(@S[0], Sz);
    SetLength(S, Sz);
  finally
    FreeAndNil(GlobalTag);
  end;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    Salt := FRandom.Generate(8);
    SavePBEAlgorithmParams(Salt, FIterations, Tag);
    Sz := 0;
    SetLength(TmpS, Sz);
    Tag.SaveToBuffer(nil, Sz);
    SetLength(TmpS, Sz);
    Tag.SaveToBuffer(@TmpS[0], Sz);
    SetLength(TmpS, Sz);
  finally
    FreeAndNil(Tag);
  end;
  if not GetKeyAndIVLengths(FCertEncryptionAlgorithm, KeyLen, IVLen) then
  begin
    Result := SB_PKCS12_ERROR_INTERNAL_ERROR;
    Exit;
  end;
  if not Estimating then
  begin
    Key := DeriveKeyFromPassword(FPassword, Salt, SB_PKCS12_KEYDERIVATION_ID_KEY,
      SB_ALGORITHM_DGST_SHA1, FIterations, KeyLen);
    IV := DeriveKeyFromPassword(FPassword, Salt, SB_PKCS12_KEYDERIVATION_ID_IV,
      SB_ALGORITHM_DGST_SHA1, FIterations, IVLen);
  end;
  Sz := Length(S) + IVLen;
  SetLength(Cnt, Sz);
  if not Estimating then
  begin
    if not EncryptContent(@S[0], Length(S), @Cnt[0], Sz, FCertEncryptionAlgorithm, Key, IV) then
    begin
      Result := SB_PKCS12_ERROR_INTERNAL_ERROR;
      Exit;
    end;
    SetLength(Cnt, Sz);
  end;

  Msg := TElPKCS7Message.Create;
  try
    Msg.ContentType :=  ctEncryptedData ;
    Msg.EncryptedData.EncryptedContent.ContentType := SB_OID_PKCS7_DATA;
    Msg.EncryptedData.EncryptedContent.ContentEncryptionAlgorithm := Alg;
    Msg.EncryptedData.EncryptedContent.ContentEncryptionAlgorithmParams := TmpS;
    Msg.EncryptedData.EncryptedContent.EncryptedContent := Cnt;
    if not Msg.SaveToBuffer(OutBuffer, OutSize) then
      Result := SB_PKCS12_ERROR_INTERNAL_ERROR
    else
      Result := 0;
  finally
    FreeAndNil(Msg);
  end;
  if Estimating then
    Inc(OutSize, 64);

end;

function TElPKCS12Message.SaveCRLBag(CRLBuffer : pointer; CRLSize : integer;
  OutBuffer : pointer; var OutSize : integer) : integer;
var
  Alg, Salt, TmpS, S, Cnt : ByteArray;
  Key, IV : ByteArray;
  Msg : TElPKCS7Message;
  CTag, Tag, GlobalTag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  KeyLen, IVLen, Sz : integer;
  Estimating : boolean;
begin
  try


  { Call this routine with OutBuffer set to nil to count estimated output length }
  Estimating := (OutBuffer = nil) ;
  Alg := GetOIDByPBEAlgorithm(FCRLEncryptionAlgorithm);
  if Length(Alg) = 0 then
  begin
    Result := SB_PKCS12_ERROR_UNKNOWN_PBE_ALGORITHM;
    Exit;
  end;
  GlobalTag := TElASN1ConstrainedTag.CreateInstance;
  try
    GlobalTag.TagId := SB_ASN1_SEQUENCE;
    CTag := TElASN1ConstrainedTag(GlobalTag.GetField(GlobalTag.AddField(true)));
    CTag.TagId := SB_ASN1_SEQUENCE;

    STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
    STag.TagId := SB_ASN1_OBJECT;
    STag.Content := SB_OID_CRL_BAG;

    Tag := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
    Tag.TagId := SB_ASN1_A0;

    Tag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    Tag.TagId := SB_ASN1_SEQUENCE;
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.TagId := SB_ASN1_OBJECT;
    STag.Content := SB_OID_CRL_TYPE_X509;
    Tag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    Tag.TagId := SB_ASN1_A0;
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.TagId := SB_ASN1_OCTETSTRING;
    SetLength(TmpS, CRLSize);
    if not Estimating then
      SBMove(CRLBuffer^, TmpS[0], CRLSize);
    STag.Content := CloneArray(TmpS);
    Sz := 0;
    SetLength(S, Sz);
    GlobalTag.SaveToBuffer(nil, Sz);
    SetLength(S, Sz);
    GlobalTag.SaveToBuffer(@S[0], Sz);
    SetLength(S, Sz);
  finally
    FreeAndNil(GlobalTag);
  end;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    Salt := FRandom.Generate(8);
    SavePBEAlgorithmParams(Salt, FIterations, Tag);
    Sz := 0;
    SetLength(TmpS, Sz);
    Tag.SaveToBuffer(nil, Sz);
    SetLength(TmpS, Sz);
    Tag.SaveToBuffer(@TmpS[0], Sz);
    SetLength(TmpS, Sz);
  finally
    FreeAndNil(Tag);
  end;
  if not GetKeyAndIVLengths(FCRLEncryptionAlgorithm, KeyLen, IVLen) then
  begin
    Result := SB_PKCS12_ERROR_INTERNAL_ERROR;
    Exit;
  end;
  if not Estimating then
  begin
    Key := DeriveKeyFromPassword(FPassword, Salt, SB_PKCS12_KEYDERIVATION_ID_KEY,
      SB_ALGORITHM_DGST_SHA1, FIterations, KeyLen);
    IV := DeriveKeyFromPassword(FPassword, Salt, SB_PKCS12_KEYDERIVATION_ID_IV,
      SB_ALGORITHM_DGST_SHA1, FIterations, IVLen);
  end;
  Sz := Length(S) + IVLen;
  SetLength(Cnt, Sz);
  if not Estimating then
  begin
    if not EncryptContent(@S[0], Length(S), @Cnt[0], Sz, FCRLEncryptionAlgorithm, Key, IV) then
    begin
      Result := SB_PKCS12_ERROR_INTERNAL_ERROR;
      Exit;
    end;
    SetLength(Cnt, Sz);
  end;

  Msg := TElPKCS7Message.Create;
  try
    Msg.ContentType :=  ctEncryptedData ;
    Msg.EncryptedData.EncryptedContent.ContentType := SB_OID_PKCS7_DATA;
    Msg.EncryptedData.EncryptedContent.ContentEncryptionAlgorithm := Alg;
    Msg.EncryptedData.EncryptedContent.ContentEncryptionAlgorithmParams := TmpS;
    Msg.EncryptedData.EncryptedContent.EncryptedContent := Cnt;
    if not Msg.SaveToBuffer(OutBuffer, OutSize) then
      Result := SB_PKCS12_ERROR_INTERNAL_ERROR
    else
      Result := 0;
  finally
    FreeAndNil(Msg);
  end;
  if Estimating then
    Inc(OutSize, 64);

  finally
    ReleaseArrays(Alg, Salt, TmpS, S, Cnt);
  end;
end;

function TElPKCS12Message.SaveMACData(Buffer : pointer; Size : integer; Tag :
  TElASN1ConstrainedTag) : integer;
var
  CTag, CTagId : TElASN1ConstrainedTag;
  STag, STagParam : TElASN1SimpleTag;
  Salt, Key, Hash : ByteArray;
  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  TmpBuf : ByteArray;
   {$endif}
  KM : TElHMACKeyMaterial;
  HashFunction : TElHashFunction;
begin
  try
  
  Tag.TagId := SB_ASN1_SEQUENCE;
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  CTag.TagId := SB_ASN1_SEQUENCE;
  CTagId := TElASN1ConstrainedTag(CTag.GetField(CTag.AddField(true)));
  CTagId.TagId := SB_ASN1_SEQUENCE;
  {$ifndef SB_BUFFERTYPE_IS_BYTEARRAY}
  SaveAlgorithmIdentifier(CTagId, SB_OID_SHA1, '');
   {$else}
  SetLength(TmpBuf, 0);
  SaveAlgorithmIdentifier(CTagId, SB_OID_SHA1, TmpBuf {$ifndef HAS_DEF_PARAMS}, 0 {$endif});
   {$endif}
  STag := TElASN1SimpleTag(CTag.GetField(CTag.AddField(false)));
  STag.TagId := SB_ASN1_OCTETSTRING;

  Salt := FRandom.Generate(20);
  STagParam := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STagParam.TagId := SB_ASN1_OCTETSTRING;
  STagParam.Content := CloneArray(Salt);
  STagParam := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STagParam.TagId := SB_ASN1_INTEGER;
  STagParam.Content := IntToBuf(FIterations);

  Key := DeriveKeyFromPassword(FPassword, Salt, SB_PKCS12_KEYDERIVATION_ID_MAC,
    SB_ALGORITHM_DGST_SHA1, FIterations, 20);

  KM := TElHMACKeyMaterial.Create;

  KM.Key := Key;
  
  HashFunction := TElHashFunction.Create(SB_ALGORITHM_MAC_HMACSHA1, KM);
  HashFunction.Update(Buffer , Size );
  Hash := HashFunction.Finish;

  FreeAndNil(HashFunction);
  FreeAndNil(KM);

  STag.Content := CloneArray(Hash);

  Result := 0;

  finally
    ReleaseArrays(Salt, Key, Hash, TmpBuf);
  end;
end;

function TElPKCS12Message.EncryptContent(InBuffer : pointer; InSize : integer;
  OutBuffer : pointer; var OutSize : integer; Algorithm : integer; const Key : ByteArray;
  const IV : ByteArray) : boolean;
var
  BlockSize : integer;
  Crypto : TElSymmetricCrypto;
  KeyMaterial : TElSymmetricKeyMaterial;
begin
  BlockSize := Length(IV);
  if (BlockSize <> 0) and (OutSize < (InSize div BlockSize + 1) * BlockSize) then
  begin
    OutSize := (InSize div BlockSize + 1) * BlockSize;
    Result := false;
    Exit;
  end
  else
  if (BlockSize = 0) and (OutSize < InSize) then
  begin
    OutSize := InSize;
    Result := false;
    Exit;
  end;

  case Algorithm of
    {$ifndef SB_NO_DES}
    SB_ALGORITHM_PBE_SHA1_3DES :
      Crypto := TEl3DESSymmetricCrypto.Create(cmCBC);
     {$endif}
    {$ifndef SB_NO_RC2}
    SB_ALGORITHM_PBE_SHA1_RC2_40,
    SB_ALGORITHM_PBE_SHA1_RC2_128 :
      Crypto := TElRC2SymmetricCrypto.Create(cmCBC); 
     {$endif}
    {$ifndef SB_NO_RC4}
    SB_ALGORITHM_PBE_SHA1_RC4_40,
    SB_ALGORITHM_PBE_SHA1_RC4_128 :
      Crypto := TElRC4SymmetricCrypto.Create(cmDefault)
     {$endif} 
  else
    begin
      Result := false;
      Exit;
    end;
  end;

  KeyMaterial := TElSymmetricKeyMaterial.Create();

  try
    KeyMaterial.Key := (Key);
    KeyMaterial.IV := (IV);
    Crypto.KeyMaterial := KeyMaterial;
    Crypto.Padding := cpPKCS5;
    Crypto.Encrypt(InBuffer, InSize, OutBuffer, OutSize);
    Result := true;
  except
    Result := false;
  end;

  FreeAndNil(Crypto);
  FreeAndNil(KeyMaterial);
end;

function TElPKCS12Message.ComposeDSAPrivateKey(X : pointer; XSize : integer;
  Certificate : TElX509Certificate; OutBuffer : pointer; var OutSize :
  integer) : boolean;
var
  Tag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  P, Q, G, Y, PK : ByteArray;
   {$else}
  P, Q, G, Y, PK : ByteArray;
   {$endif}
  PSize, QSize, GSize, YSize : integer;
begin
  Result := false;
  if Certificate.PublicKeyAlgorithm <> SB_CERT_ALGORITHM_ID_DSA then
    Exit;

  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  try
   {$endif}

  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    Tag.LoadFromBuffer(X , XSize );
    if (Tag.Count <> 1) or (Tag.GetField(0).IsConstrained) or (Tag.GetField(0).TagId <>
      SB_ASN1_INTEGER) then
      Exit;

    PK := CloneArray(TElASN1SimpleTag(Tag.GetField(0)).Content);
  finally
    FreeAndNil(Tag);
  end;

  PSize := 0; QSize := 0; GSize := 0; YSize := 0;
  Certificate.GetDSSParams(nil, PSize, nil, QSize, nil, GSize, nil, YSize);
  if (PSize <= 0) or (QSize <= 0) or (GSize <= 0) or (YSize <= 0) then
    Exit;
  SetLength(P, PSize);
  SetLength(Q, QSize);
  SetLength(G, GSize);
  SetLength(Y, YSize);
  Certificate.GetDSSParams(@P[0], PSize, @Q[0], QSize, @G[0], GSize, @Y[0], YSize);
  SetLength(P, PSize);
  SetLength(Q, QSize);
  SetLength(G, GSize);
  SetLength(Y, YSize);
  Tag := TElASN1ConstrainedTag.CreateInstance;
  Tag.TagId := SB_ASN1_SEQUENCE;
  { writing version (0) }
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;
  STag.Content := GetByteArrayFromByte(0);

  { writing p }
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;

  if Ord(P[0]) >= 128 then
  begin
    SetLength(P, Length(P) + 1);
    SBMove(P[0], P[0 + 1], Length(P) - 1);
    P[0] := byte(0);
  end;
  STag.Content := CloneArray(P);

  { writing q }
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;
  if Ord(Q[0]) >= 128 then
  begin
    SetLength(Q, Length(Q) + 1);
    SBMove(Q[0], Q[0 + 1], Length(Q)-1);
    Q[0] := byte(0);
  end;
  STag.Content := CloneArray(Q);
	
  { writing g }
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;

  if Ord(G[0]) >= 128 then
  begin
    SetLength(G, Length(G) + 1);
    SBMove(G[0], G[0 + 1], Length(G)-1);
    G[0] := byte(0);
  end;
  STag.Content := CloneArray(G);
	
  { writing y }
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;

  if Ord(Y[0]) >= 128 then
  begin
    SetLength(Y, Length(Y) + 1);
    SBMove(Y[0], Y[0 + 1], Length(Y)-1);
    Y[0] := byte(0);
  end;
  STag.Content := CloneArray(Y);

  { writing x }
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_INTEGER;

  if Ord(PK[0]) >= 128 then
  begin
    SetLength(PK, Length(PK) + 1);
    SBMove(PK[0], PK[0+ 1], Length(PK)-1);
    PK[0] := byte(0);
  end;
  STag.Content := CloneArray(PK);

  Result := Tag.SaveToBuffer(OutBuffer, OutSize);
  FreeAndNil(Tag);

  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  finally
    ReleaseArrays(P, Q, G, Y, PK);
  end;
   {$endif}
end;

function TElPKCS12Message.DecomposeDSAPrivateKey(KeyBlob : pointer; KeyBlobSize :
  integer; PrivateKey : pointer; var PrivateKeySize : integer; Params : pointer;
  var ParamsSize : integer) : boolean;
var
  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  P, Q, G, Y, X : ByteArray;
   {$else}
  P, Q, G, Y, X : ByteArray;
   {$endif}
  PSize, QSize, GSize, YSize, XSize : integer;
  Tag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
begin
  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  try
   {$endif}

  PSize := 0; QSize := 0; GSize := 0; YSize := 0; XSize := 0;
  SBDSA.DecodePrivateKey(KeyBlob, KeyBlobSize, nil, PSize, nil, QSize, nil,
    GSize, nil, YSize, nil, XSize);
  if (PSize <= 0) or (QSize <= 0) or (GSize <= 0) or (XSize <= 0) or (YSize <= 0) then
  begin
    Result := False;
    Exit;
  end;

  SetLength(P, PSize);
  SetLength(Q, QSize);
  SetLength(G, GSize);
  SetLength(Y, YSize);
  SetLength(X, XSize);
  Result := SBDSA.DecodePrivateKey(KeyBlob, KeyBlobSize, @P[0], PSize, @Q[0],
    QSize, @G[0], GSize, @Y[0], YSize, @X[0], XSize);
  if not Result then
    Exit;
  SetLength(P, PSize);
  SetLength(Q, QSize);
  SetLength(G, GSize);
  SetLength(Y, YSize);
  SetLength(X, XSize);

  { Writing params }
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    Tag.TagId := SB_ASN1_SEQUENCE;
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.TagId := SB_ASN1_INTEGER;

    if Ord(P[0]) >= 128 then
    begin
      SetLength(P, Length(P) + 1);
      SBMove(P[0], P[0 + 1], Length(P)-1);

      P[0] := byte(0);
    end;
    STag.Content := CloneArray(P);

    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.TagId := SB_ASN1_INTEGER;

    if Ord(Q[0]) >= 128 then
    begin
      SetLength(Q, Length(Q) + 1);
      SBMove(Q[0], Q[0 + 1], Length(Q)-1);
      Q[0] := byte(0);
    end;
    STag.Content := CloneArray(Q);

    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.TagId := SB_ASN1_INTEGER;

    if Ord(G[0]) >= 128 then
    begin
      SetLength(G, Length(G) + 1);
      SBMove(G[0], G[0 + 1], Length(G)-1);

      G[0] := byte(0);
    end;
    STag.Content := CloneArray(G);

    { Writing private key }
    STag := TElASN1SimpleTag.CreateInstance;
    try
      STag.TagId := SB_ASN1_INTEGER;
      if Ord(X[0]) >= 128 then
      begin
        SetLength(X, Length(X) + 1);
        SBMove(X[0], X[0+ 1], Length(X)-1);

        X[0] := byte(0);
      end;

      STag.Content := CloneArray(X);
      Result := Tag.SaveToBuffer(Params, ParamsSize);
      Result := STag.SaveToBuffer(PrivateKey, PrivateKeySize) and Result;
    finally
      FreeAndNil(STag);
    end;
  finally
    FreeAndNil(Tag);
  end;

  {$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
  finally
    ReleaseArrays(P, Q, G, Y, X);
  end;
   {$endif}
end;

function TElPKCS12Message.GetPassword : string;
begin
  result := FPassword;
end;

procedure TElPKCS12Message.SetPassword(const Value : string);
begin
  FPassword := Value;
end;

function BufToInt(Buffer : pointer; Size : integer) : integer;
var
  I : integer;
  Coef : integer;
begin
  Result := 0;
  if Size > 4 then
    Exit;
  Coef := 1;
  for I := Size - 1 downto 0 do
  begin
    Result := Result + PByteArray(Buffer)[I] * Coef;
    Coef := Coef shl 8;
  end;
end;

function IntToBuf(Number: integer): ByteArray;
{$ifdef SB_BUFFERTYPE_IS_BYTEARRAY}
var i : integer;
    Res: ByteArray;
 {$endif}
begin
  if Number = 0 then
    Result := GetByteArrayFromByte(0)
  else
  begin
    {$ifndef SB_BUFFERTYPE_IS_BYTEARRAY}
    SetLength(Result, 0);
    while Number > 0 do
    begin
      Result := byte(Number and $FF) + Result;
      Number := Number shr 8;
    end;
    if Ord(Result[0]) >= 128 then
      Result := #0 + Result;
(*
// unknown block of code that was never compiled

    SetLength(Result, 0);
    Res := '';
    while Number > 0 do
    begin
      Res := Chr(Number and $FF) + Res;
      Number := Number shr 8;
    end;
    if Ord(Res[0]) >= 128 then
      Res := #0 + Result;

    SetLength(Result, Length(Res));
    SBMove(Res, 0, Result, 0, Length(Res));
*)

     {$else}
    i := SizeOf(Integer) + 1;
    SetLength(Res, i);
    while Number > 0 do
    begin
      Dec(i);
      Res[i] := Number and $FF;
      Number := Number shr 8;
    end;

    if Ord(Res[i]) >= 128 then
    begin
      Dec(i);
      Res[i] := 0;
    end;

    SetLength(Result, Length(Res) - i);
    SBMove(Res, i, Result, 0, Length(Result));
     {$endif SB_BUFFERTYPE_IS_BYTEARRAY}
  end;
end;

{$ifdef SB_NO_BYTEARRAY_CONST_ARRAYS}
initialization
  SB_OID_KEY_BAG                 := CreateByteArrayConst(#$2a#$86#$48#$86#$f7#$0d#$01#$0c#$0a#$01#$01);
  SB_OID_PKCS8_SHROUDED_KEY_BAG  := CreateByteArrayConst(#$2a#$86#$48#$86#$f7#$0d#$01#$0c#$0a#$01#$02);
  SB_OID_CERT_BAG                := CreateByteArrayConst(#$2a#$86#$48#$86#$f7#$0d#$01#$0c#$0a#$01#$03);
  SB_OID_CRL_BAG                 := CreateByteArrayConst(#$2a#$86#$48#$86#$f7#$0d#$01#$0c#$0a#$01#$04);
  SB_OID_SECRET_BAG              := CreateByteArrayConst(#$2a#$86#$48#$86#$f7#$0d#$01#$0c#$0a#$01#$05);
  SB_OID_SAFE_CONTENTS_BAG       := CreateByteArrayConst(#$2a#$86#$48#$86#$f7#$0d#$01#$0c#$0a#$01#$06);
  SB_OID_LOCAL_KEY_ID            := CreateByteArrayConst(#$2a#$86#$48#$86#$f7#$0d#$01#$09#$15);
  SB_OID_CERT_TYPE_X509          := CreateByteArrayConst(#$2a#$86#$48#$86#$f7#$0d#$01#$09#$16#$01);
  SB_OID_CRL_TYPE_X509           := CreateByteArrayConst(#$2a#$86#$48#$86#$f7#$0d#$01#$09#$17#$01);
 {$endif}
end.
