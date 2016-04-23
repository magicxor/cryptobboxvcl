(******************************************************)
(*                                                    *)
(*            EldoS SecureBlackbox Library            *)
(*                                                    *)
(*      Copyright (c) 2002-2014 EldoS Corporation     *)
(*           http://www.secureblackbox.com            *)
(*                                                    *)
(******************************************************)

{$I SecBbox.inc}

unit SBPKCS8;

interface

uses
  SBTypes,
  SBUtils,
  SBConstants,
  SBPKCS7,
  SBPKCS7Utils,
  SBPKCS5,
  SBASN1,
  SBASN1Tree,
  SysUtils,
  Classes,
  SBPEM;


const
  SB_PKCS8_ERROR_OK                                     = Integer(0);
  SB_PKCS8_ERROR_INVALID_ASN_DATA                       = Integer($2301);
  SB_PKCS8_ERROR_INVALID_FORMAT                         = Integer($2302);
  SB_PKCS8_ERROR_UNSUPPORTED_ALGORITHM                  = Integer($2303);
  SB_PKCS8_ERROR_INVALID_PASSWORD                       = Integer($2304);
  SB_PKCS8_ERROR_INVALID_VERSION                        = Integer($2305);
  SB_PKCS8_ERROR_INVALID_PARAMETER                      = Integer($2306);
  SB_PKCS8_ERROR_UNKNOWN                                = Integer($2307);
  SB_PKCS8_ERROR_BUFFER_TOO_SMALL                       = Integer($2308);
  SB_PKCS8_ERROR_NO_PRIVATE_KEY                         = Integer($2309);

type
  TElPKCS8EncryptedPrivateKeyInfo = class;
  
  TElPKCS8PrivateKeyInfo = class
  protected
    //FVersion : byte;
    FPrivateKeyAlgorithm : ByteArray;
    FPrivateKeyAlgorithmParams : ByteArray;
    FPrivateKey: ByteArray;
    procedure SetPrivateKeyAlgorithm(const V : ByteArray);
    procedure SetPrivateKeyAlgorithmParams(const V : ByteArray);
    procedure SetPrivateKey(const V: ByteArray);
    procedure Clear;
  public
    constructor Create;
     destructor  Destroy; override;

    function LoadFromBuffer(Buffer: pointer; Size : integer) : integer;
    function SaveToBuffer(Buffer: pointer; var Size : integer) : boolean;
    function LoadFromStream(Stream: TStream; Count: integer = 0): integer;
    function SaveToStream(Stream: TStream): boolean;
    property PrivateKeyAlgorithm : ByteArray read FPrivateKeyAlgorithm
      write SetPrivateKeyAlgorithm;
    property PrivateKeyAlgorithmParams : ByteArray read FPrivateKeyAlgorithmParams
      write SetPrivateKeyAlgorithmParams;
    property PrivateKey : ByteArray read FPrivateKey write SetPrivateKey;
  end;

  TElPKCS8EncryptedPrivateKeyInfo = class
  protected
    FEncryptionAlgorithm : ByteArray;
    FEncryptionAlgorithmParams : ByteArray;
    FEncryptedData : ByteArray;
    procedure SetEncryptionAlgorithm(const V : ByteArray);
    procedure SetEncryptionAlgorithmParams(const V : ByteArray);
    procedure SetEncryptedData(const V : ByteArray);
  public
     destructor  Destroy; override;
    function LoadFromBuffer(Buffer: pointer; Size : integer) : integer;
    function SaveToBuffer(Buffer: pointer; var Size : integer) : boolean;
    function LoadFromStream(Stream : TStream; Count: integer = 0) : integer;
    function SaveToStream(Stream : TStream) : boolean;
    function LoadFromTag(Tag : TElASN1ConstrainedTag) : integer;
    function SaveToTag(Tag : TElASN1ConstrainedTag) : boolean;
    property EncryptionAlgorithm : ByteArray read FEncryptionAlgorithm
      write SetEncryptionAlgorithm;
    property EncryptionAlgorithmParams : ByteArray read FEncryptionAlgorithmParams
      write SetEncryptionAlgorithmParams;
    property EncryptedData : ByteArray read FEncryptedData write SetEncryptedData;
  end;

  TElPKCS8PrivateKey = class
  private
    FKeyInfo : TElPKCS8PrivateKeyInfo;
    FEncryptedKeyInfo : TElPKCS8EncryptedPrivateKeyInfo;
    FAlgorithm : integer;
    FUseNewFeatures: boolean;
    function ProcessEncryptedInfo(const Password: string): integer;

    procedure SetSymmetricAlgorithm(Value : integer);
    function GetSymmetricAlgorithm : integer;
    procedure SetUseNewFeatures(Value : boolean);
    function GetUseNewFeatures : boolean;
    function GetKeyMaterial : ByteArray;
    procedure SetKeyMaterial(const Value: ByteArray);
    function GetKeyAlgorithm : ByteArray;
    procedure SetKeyAlgorithm(const Value: ByteArray);
    function GetKeyAlgorithmParams : ByteArray;
    procedure SetKeyAlgorithmParams(const Value: ByteArray);  
  public
    constructor Create;
     destructor  Destroy; override;

    function LoadFromBuffer(Buffer: pointer; Size: integer;
      const Passphrase : string = '') : integer;
    function SaveToBuffer(Buffer: pointer; var Size: integer;
      const Passphrase : string = ''; UsePEMEnvelope : boolean = true) : integer;
    function LoadFromStream(Stream: TStream; const Passphrase: string = '';
      Count: integer = 0): integer;
    function SaveToStream(Stream: TStream; const Passphrase : string = '';
      UsePEMEnvelope: boolean = true): integer;
    property SymmetricAlgorithm : integer read GetSymmetricAlgorithm write SetSymmetricAlgorithm;
    property UseNewFeatures: boolean read GetUseNewFeatures write SetUseNewFeatures  default false ;
    property KeyMaterial : ByteArray read GetKeyMaterial write SetKeyMaterial;
    property KeyAlgorithm : ByteArray read GetKeyAlgorithm write SetKeyAlgorithm;
    property KeyAlgorithmParams: ByteArray read GetKeyAlgorithmParams write SetKeyAlgorithmParams;
  end;

type

  EElPKCS8Error =  class(ESecureBlackboxError);

procedure RaisePKCS8Error(ErrorCode : integer); 

implementation

uses
  SBMD,
  SBRC4;

resourcestring

  sInvalidASNData = 'Invalid ASN.1 sequence';
//  sNoData = 'No data';
  sInvalidFormat = 'Invalid format';
  sInvalidVersion = 'Invalid version';
  sUnsupportedAlgorithm = 'Unsupported algorithm';
  sInvalidPassword = 'Invalid password';
  sBufferTooSmall = 'Buffer too small';
  sPKCS8Error = 'PKCS8 error';
  sInvalidParameter = 'Invalid internal parameters';
  sUnknown = 'Unknown error';

procedure RaisePKCS8Error(ErrorCode : integer);
begin
  if ErrorCode <> 0 then
    case ErrorCode of
      SB_PKCS8_ERROR_INVALID_ASN_DATA                 : raise EElPKCS8Error.Create(sInvalidASNData);
      SB_PKCS8_ERROR_INVALID_VERSION                  : raise EElPKCS8Error.Create(sInvalidVersion);
      SB_PKCS8_ERROR_INVALID_PASSWORD                 : raise EElPKCS8Error.Create(sInvalidPassword);
      SB_PKCS8_ERROR_BUFFER_TOO_SMALL                 : raise EElPKCS8Error.Create(sBufferTooSmall);
      SB_PKCS8_ERROR_UNSUPPORTED_ALGORITHM            : raise EElPKCS8Error.Create(sUnsupportedAlgorithm);
      SB_PKCS8_ERROR_INVALID_FORMAT                   : raise EElPKCS8Error.Create(sInvalidFormat);
      SB_PKCS8_ERROR_INVALID_PARAMETER                : raise EElPKCS8Error.Create(sInvalidParameter);
      SB_PKCS8_ERROR_UNKNOWN                          : raise EElPKCS8Error.Create(sUnknown);
      else
          raise EElPKCS8Error.Create(sPKCS8Error + '#' + IntToStr(ErrorCode));
    end;
end;

////////////////////////////////////////////////////////////////////////////////
// TElPKCS8PrivateKeyInfo class

constructor TElPKCS8PrivateKeyInfo.Create;
begin
  inherited;
end;

 destructor  TElPKCS8PrivateKeyInfo.Destroy;
begin
  inherited;
end;

procedure TElPKCS8PrivateKeyInfo.Clear;
begin
  SetLength(FPrivateKeyAlgorithm, 0);
  SetLength(FPrivateKeyAlgorithmParams, 0);
  SetLength(FPrivateKey, 0);
end;

function TElPKCS8PrivateKeyInfo.LoadFromStream(Stream: TStream;
  Count : integer = 0) : integer;
var
  Buf : ByteArray;
begin
  if Count = 0 then
    Count :=  Stream.Size ;
  SetLength(Buf, Count);
  if Count > 0 then
  begin
    Stream.Read(Buf[0], Count);
    Result := LoadFromBuffer(@Buf[0], Count);
    ReleaseArray(Buf);
  end
  else
    Result := SB_PKCS8_ERROR_INVALID_FORMAT;
end;

function TElPKCS8PrivateKeyInfo.SaveToStream(Stream: TStream) : boolean;
var
  Buf : ByteArray;
  Size : integer;
begin
  Size := 0;
  SaveToBuffer( nil , Size);
  SetLength(Buf, Size);
  Result := SaveToBuffer(@Buf[0], Size);
  if not Result then
    Exit;
  Stream.Write(Buf[0], Size);
  ReleaseArray(Buf);
end;

function TElPKCS8PrivateKeyInfo.LoadFromBuffer(Buffer: pointer; Size :
  integer) : integer;
var
  Tag, ContentTag : TElASN1ConstrainedTag;
  TV : ByteArray;
begin
  CheckLicenseKey();
  Clear;
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if not Tag.LoadFromBuffer(Buffer, Size) then
    begin
      Result := SB_PKCS8_ERROR_INVALID_ASN_DATA;
      Exit;
    end;
    if (Tag.Count <> 1) or (not Tag.GetField(0).IsConstrained) or
      (Tag.GetField(0).TagId <> SB_ASN1_SEQUENCE) then
    begin
      Result := SB_PKCS8_ERROR_INVALID_FORMAT;
      Exit;
    end;
    ContentTag := TElASN1ConstrainedTag(Tag.GetField(0));
    if (ContentTag.Count < 3) or (ContentTag.Count > 4) then
    begin
      Result := SB_PKCS8_ERROR_INVALID_FORMAT;
      Exit;
    end;

    if (ContentTag.GetField(0).IsConstrained) or (ContentTag.GetField(0).TagId <>
      SB_ASN1_INTEGER) then
    begin
      Result := SB_PKCS8_ERROR_INVALID_FORMAT;
      Exit;
    end;

    TV := TElASN1SimpleTag(ContentTag.GetField(0)).Content;

    if (Length(TV) <> 1) or
      (TV[0] <> byte(0)) then
    begin
      Result := SB_PKCS8_ERROR_INVALID_VERSION;
      Exit;
    end;

    //FVersion := 0;
    Result := ProcessAlgorithmIdentifier(ContentTag.GetField(1), FPrivateKeyAlgorithm,
      FPrivateKeyAlgorithmParams {$ifndef HAS_DEF_PARAMS}, False {$endif});
    if Result <> 0 then
      Exit;

    if (ContentTag.GetField(2).IsConstrained) or (ContentTag.GetField(2).TagId <>
      SB_ASN1_OCTETSTRING) then
    begin
      Result := SB_PKCS8_ERROR_INVALID_FORMAT;
      Exit;
    end;
    FPrivateKey := TElASN1SimpleTag(ContentTag.GetField(2)).Content;
  finally
    FreeAndNil(Tag);
  end;
end;

function TElPKCS8PrivateKeyInfo.SaveToBuffer(Buffer: pointer; var Size :
  integer) : boolean;
var
  Tag, CTag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
begin
  CheckLicenseKey();
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    Tag.TagId := SB_ASN1_SEQUENCE;
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.TagId := SB_ASN1_INTEGER;
    STag.Content := GetByteArrayFromByte(0);
    CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
    SaveAlgorithmIdentifier(CTag, FPrivateKeyAlgorithm, FPrivateKeyAlgorithmParams {$ifndef HAS_DEF_PARAMS}, 0 {$endif});
    STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
    STag.TagId := SB_ASN1_OCTETSTRING;
    STag.Content := FPrivateKey;
    Result := Tag.SaveToBuffer(Buffer, Size);
  finally
    FreeAndNil(Tag);
  end;
end;

procedure TElPKCS8PrivateKeyInfo.SetPrivateKeyAlgorithm(const V : ByteArray);
begin
  FPrivateKeyAlgorithm := CloneArray(V);
end;

procedure TElPKCS8PrivateKeyInfo.SetPrivateKeyAlgorithmParams(const V : ByteArray);
begin
  FPrivateKeyAlgorithmParams := CloneArray(V);
end;

procedure TElPKCS8PrivateKeyInfo.SetPrivateKey(const V: ByteArray);
begin
  FPrivateKey := CloneArray(V);
end;

////////////////////////////////////////////////////////////////////////////////
// TElPKCS8EncryptedPrivateKeyInfo class

 destructor  TElPKCS8EncryptedPrivateKeyInfo.Destroy;
begin
  inherited;
end;

procedure TElPKCS8EncryptedPrivateKeyInfo.SetEncryptionAlgorithm(const V : ByteArray);
begin
  FEncryptionAlgorithm := CloneArray(V);
end;

procedure TElPKCS8EncryptedPrivateKeyInfo.SetEncryptionAlgorithmParams(const V : ByteArray);
begin
  FEncryptionAlgorithmParams := CloneArray(V);
end;

procedure TElPKCS8EncryptedPrivateKeyInfo.SetEncryptedData(const V : ByteArray);
begin
  FEncryptedData := CloneArray(V);
end;

function TElPKCS8EncryptedPrivateKeyInfo.LoadFromBuffer(Buffer: pointer; Size :
  integer) : integer;
var
  Tag, ContentTag : TElASN1ConstrainedTag;
begin
  CheckLicenseKey();
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    if not Tag.LoadFromBuffer(Buffer, Size) then
    begin
      Result := SB_PKCS8_ERROR_INVALID_ASN_DATA;
      Exit;
    end;
    Result := SB_PKCS8_ERROR_INVALID_FORMAT;
    if Tag.Count <> 1 then
      Exit;

    if (not Tag.GetField(0).IsConstrained) or (Tag.GetField(0).TagId <>
      SB_ASN1_SEQUENCE) then
      Exit;

    ContentTag := TElASN1ConstrainedTag(Tag.GetField(0));
    Result := LoadFromTag(ContentTag);
  finally
    FreeAndNil(Tag);
  end;
end;

function TElPKCS8EncryptedPrivateKeyInfo.SaveToBuffer(Buffer: pointer;
  var Size : integer) : boolean;
var
  Tag : TElASN1ConstrainedTag;
begin
  CheckLicenseKey();
  Tag := TElASN1ConstrainedTag.CreateInstance;
  try
    SaveToTag(Tag);
    Result := Tag.SaveToBuffer(Buffer, Size);
  finally
    FreeAndNil(Tag);
  end;
end;

function TElPKCS8EncryptedPrivateKeyInfo.LoadFromStream(Stream : TStream;
  Count: integer = 0) : integer;
var
  Buf : ByteArray;
begin
  if Count = 0 then
    Count :=  Stream.Size ;
  SetLength(Buf, Count);
  if Count > 0 then
  begin
    Stream.Read(Buf[0], Count);
    Result := LoadFromBuffer(@Buf[0], Count);
    ReleaseArray(Buf);
  end
  else
    Result := SB_PKCS8_ERROR_INVALID_FORMAT
end;

function TElPKCS8EncryptedPrivateKeyInfo.SaveToStream(Stream : TStream) : boolean;
var
  Buf : ByteArray;
  Size : integer;
begin
  Size := 0;
  SaveToBuffer( nil , Size);
  SetLength(Buf, Size);
  Result := SaveToBuffer(@Buf[0], Size);
  if not Result then
    Exit;
  Stream.Write(Buf[0], Size);
  ReleaseArray(Buf);
end;

function TElPKCS8EncryptedPrivateKeyInfo.LoadFromTag(Tag : TElASN1ConstrainedTag) : integer;
begin
  Result := SB_PKCS8_ERROR_INVALID_FORMAT;

  if (Tag.Count <> 2) or (not Tag.GetField(0).IsConstrained) or
    (Tag.GetField(1).IsConstrained) or (Tag.GetField(0).TagId <>
    SB_ASN1_SEQUENCE) or (Tag.GetField(1).TagId <> SB_ASN1_OCTETSTRING) then
    Exit;
  Result := ProcessAlgorithmIdentifier(Tag.GetField(0), FEncryptionAlgorithm,
    FEncryptionAlgorithmParams {$ifndef HAS_DEF_PARAMS}, False {$endif});
  if Result <> 0 then
    Exit;
  FEncryptedData := TElASN1SimpleTag(Tag.GetField(1)).Content;
  Result := 0;
end;

function TElPKCS8EncryptedPrivateKeyInfo.SaveToTag(Tag : TElASN1ConstrainedTag) : boolean;
var
  CTag : TElASN1ConstrainedTag;
  STag : TElASN1SimpleTag;
begin
  Tag.TagId := SB_ASN1_SEQUENCE;
  CTag := TElASN1ConstrainedTag(Tag.GetField(Tag.AddField(true)));
  SaveAlgorithmIdentifier(CTag, FEncryptionAlgorithm, FEncryptionAlgorithmParams {$ifndef HAS_DEF_PARAMS}, 0 {$endif});
  STag := TElASN1SimpleTag(Tag.GetField(Tag.AddField(false)));
  STag.TagId := SB_ASN1_OCTETSTRING;
  STag.Content := FEncryptedData;
  Result := true;
end;

////////////////////////////////////////////////////////////////////////////////
// TElPKCS8PrivateKey class

constructor TElPKCS8PrivateKey.Create;
begin
  inherited;
  FKeyInfo := TElPKCS8PrivateKeyInfo.Create;
  FEncryptedKeyInfo := TElPKCS8EncryptedPrivateKeyInfo.Create;
  FUseNewFeatures := false;
end;

 destructor  TElPKCS8PrivateKey.Destroy;
begin
  FreeAndNil(FKeyInfo);
  FreeAndNil(FEncryptedKeyInfo);
  inherited;
end;

procedure TElPKCS8PrivateKey.SetSymmetricAlgorithm(Value : integer);
begin
  FAlgorithm:= Value;
end;

function TElPKCS8PrivateKey.GetSymmetricAlgorithm : integer;
begin
  Result := FAlgorithm;
end;

procedure TElPKCS8PrivateKey.SetUseNewFeatures(Value : boolean);
begin
  FUseNewFeatures := Value;
end;

function TElPKCS8PrivateKey.GetUseNewFeatures : boolean;
begin
  Result := FUseNewFeatures;
end;

function TElPKCS8PrivateKey.GetKeyMaterial : ByteArray;
begin
  Result := FKeyInfo.FPrivateKey;
end;

procedure TElPKCS8PrivateKey.SetKeyMaterial(const Value: ByteArray);
begin
  FKeyInfo.FPrivateKey := CloneArray(Value);
end;

function TElPKCS8PrivateKey.GetKeyAlgorithm : ByteArray;
begin
  Result := FKeyInfo.FPrivateKeyAlgorithm;
end;

procedure TElPKCS8PrivateKey.SetKeyAlgorithm(const Value: ByteArray);
begin
  FKeyInfo.FPrivateKeyAlgorithm := CloneArray(Value);
end;

function TElPKCS8PrivateKey.GetKeyAlgorithmParams : ByteArray;
begin
  Result := FKeyInfo.FPrivateKeyAlgorithmParams;
end;

procedure TElPKCS8PrivateKey.SetKeyAlgorithmParams(const Value: ByteArray);
begin
  FKeyInfo.FPrivateKeyAlgorithmParams := CloneArray(Value);
end;

function TElPKCS8PrivateKey.LoadFromBuffer(Buffer: pointer; Size: integer;
  const Passphrase : string = '') : integer;
var
  DERContent : ByteArray;
  Hdr : string;
  ContentSize : integer;
begin
  CheckLicenseKey();
  FAlgorithm := SB_CERT_ALGORITHM_UNKNOWN;
  // trying PEM
  // passing Passphrase to PEM.Decode for a case (usually, PKCS8 PEM is not encrypted,
  // but we can not guarantee that some implementation will not do it, so
  // small reinsurance won't be bad)
  ContentSize :=  Size ;
  SetLength(DERContent,  Size );
  Result := SBPEM.Decode(Buffer, Size, @DERContent[0], Passphrase, ContentSize, Hdr);
  if Result <> PEM_DECODE_RESULT_OK then
  begin
    if Result <> PEM_DECODE_RESULT_INVALID_FORMAT then
      Exit;
    // not a PEM
    ContentSize :=  Size ;
    SetLength(DERContent, ContentSize);
    SBMove(Buffer^, DERContent[0], Length(DERContent));
  end;

  // trying plain (not encrypted) PKCS8
  Result := FKeyInfo.LoadFromBuffer(@DERContent[0], ContentSize);
  if Result <> SB_PKCS8_ERROR_OK then
  begin
    // trying encrypted PKCS8
    Result := FEncryptedKeyInfo.LoadFromBuffer(@DERContent[0], ContentSize);
    if Result <> SB_PKCS8_ERROR_OK then
      Exit;
    Result := ProcessEncryptedInfo(Passphrase);
  end
  else
    FAlgorithm := SB_ALGORITHM_CNT_IDENTITY;
end;

function TElPKCS8PrivateKey.ProcessEncryptedInfo(const Password: string): integer;
var
  Alg : integer;
  Key : ByteArray;
  CtxRC4 : TRC4Context;
  Buf : ByteArray;
  PBE : TElPKCS5PBE;
  Size : integer;
begin
  Result := 0;
  if TElPKCS5PBE.IsAlgorithmSupported(FEncryptedKeyInfo.FEncryptionAlgorithm) then
  begin
    try
      PBE := TElPKCS5PBE.Create(FEncryptedKeyInfo.FEncryptionAlgorithm,
        FEncryptedKeyInfo.FEncryptionAlgorithmParams);
      try
        Size := 0;
        PBE.Decrypt(@FEncryptedKeyInfo.FEncryptedData[0],
          Length(FEncryptedKeyInfo.FEncryptedData), nil, Size, Password);
        SetLength(Buf, Size);
        PBE.Decrypt(@FEncryptedKeyInfo.FEncryptedData[0],
          Length(FEncryptedKeyInfo.FEncryptedData), @Buf[0], Size, Password);
        SetLength(Buf, Size);
        FAlgorithm := PBE.Algorithm;
        FUseNewFeatures := (PBE.Version = sbP5v2);
      finally
        FreeAndNil(PBE);
      end;
    except
      on E : EElPKCS5UnsupportedError do
        Result := SB_PKCS8_ERROR_UNSUPPORTED_ALGORITHM;
      on E : EElPKCS5InvalidParameterError do
        Result := SB_PKCS8_ERROR_INVALID_PARAMETER;
      on E : EElPKCS5InvalidPasswordError do
        Result := SB_PKCS8_ERROR_INVALID_PASSWORD;
      on E : Exception do
        Result := SB_PKCS8_ERROR_UNKNOWN;
    end;
  end
  else
  begin
    Alg := GetAlgorithmByOID(FEncryptedKeyInfo.FEncryptionAlgorithm);
    if Alg = SB_ALGORITHM_CNT_RC4 then // Win32 uses RC4 algorithm that is not supported by PKCS#5, so we need to process it separately
    begin
      Key := DigestToBinary(HashMD5(BytesOfString(Password)));
      SBRC4.Initialize(CtxRC4, TRC4Key(Key));
      SetLength(Buf, Length(FEncryptedKeyInfo.FEncryptedData));
      SBRC4.Decrypt(CtxRC4, @FEncryptedKeyInfo.FEncryptedData[0], @Buf[0],
        Length(FEncryptedKeyInfo.FEncryptedData));
      FAlgorithm := SB_ALGORITHM_CNT_RC4;
    end
    else
    begin
      Result := SB_PKCS8_ERROR_UNSUPPORTED_ALGORITHM;
      Exit;
    end;
  end;
  if Result = 0 then
  begin
    Result := FKeyInfo.LoadFromBuffer(@Buf[0], Length(Buf));
    if Result = SB_PKCS8_ERROR_INVALID_ASN_DATA then
      Result := SB_PKCS8_ERROR_INVALID_PASSWORD;
  end;
end;

function TElPKCS8PrivateKey.SaveToBuffer(Buffer: pointer; var Size: integer;
  const Passphrase : string = ''; UsePEMEnvelope: boolean = true) : integer;

  function SetupEncryption : TElPKCS5PBE;
  begin
    try
      Result := TElPKCS5PBE.Create(FAlgorithm, SB_ALGORITHM_DGST_SHA1, FUseNewFeatures);
    except
      Result := nil;
    end;
  end;
  
const
  PLAIN_KEY_HEADER = 'PRIVATE KEY';
  ENCRYPTED_KEY_HEADER = 'ENCRYPTED PRIVATE KEY';
var
  Sz, Sz2 : integer;
  Encrypt : boolean;
  PBE : TElPKCS5PBE;
  Buf, Buf2 : ByteArray;
  PEMHeader : string;
  Key : ByteArray;
  CtxRC4 : TRC4Context;
begin
  //FKeyInfo.FVersion := 0;
  if Length(FKeyInfo.FPrivateKeyAlgorithm) = 0 then
  begin
    Result := SB_PKCS8_ERROR_UNSUPPORTED_ALGORITHM;
    Exit;
  end;
  Encrypt := (Length(Passphrase) <> 0);
  if Encrypt then
  begin
    if FAlgorithm = SB_ALGORITHM_CNT_RC4 then
    begin
      Sz := 0;
      FKeyInfo.SaveToBuffer( nil , Sz);
      SetLength(Buf, Sz);
      FKeyInfo.SaveToBuffer(@Buf[0], Sz);
      SetLength(Buf, Sz);
      Key := DigestToBinary(HashMD5(BytesOfString(Passphrase)));
      SBRC4.Initialize(CtxRC4, TRC4Key(Key));
      SetLength(FEncryptedKeyInfo.FEncryptedData, Sz);
      SBRC4.Encrypt(CtxRC4, @Buf[0], @FEncryptedKeyInfo.FEncryptedData[0], Sz);
      FEncryptedKeyInfo.FEncryptionAlgorithmParams := EmptyArray;
      FEncryptedKeyInfo.FEncryptionAlgorithm := SB_OID_RC4;
    end
    else
    begin
      Sz := 0;
      FKeyInfo.SaveToBuffer( nil , Sz);
      SetLength(Buf, Sz);
      FKeyInfo.SaveToBuffer( @Buf[0] , Sz);
      SetLength(Buf, Sz);
      PBE := SetupEncryption;
      if PBE = nil then
      begin
        Result := SB_PKCS8_ERROR_UNSUPPORTED_ALGORITHM;
        Exit;
      end;
      try
        try
          Sz2 := 0;
          PBE.Encrypt(@Buf[0], Sz, nil, Sz2, Passphrase);
          SetLength(Buf2, Sz2);
          PBE.Encrypt(@Buf[0], Sz, @Buf2[0], Sz2, Passphrase);
          SetLength(Buf2, Sz2);
          FEncryptedKeyInfo.FEncryptionAlgorithm := CloneArray(PBE.EncryptionAlgorithmOID);
          FEncryptedKeyInfo.FEncryptionAlgorithmParams := CloneArray(PBE.EncryptionAlgorithmParams);
          FEncryptedKeyInfo.FEncryptedData := CloneArray(Buf2);
        finally
          FreeAndNil(PBE);
        end;
      except
        Result := SB_PKCS8_ERROR_UNSUPPORTED_ALGORITHM;
        Exit;
      end;
    end;
    Sz2 := 0;
    FEncryptedKeyInfo.SaveToBuffer( nil , Sz2);
    SetLength(Buf2, Sz2);
    FEncryptedKeyInfo.SaveToBuffer(@Buf2[0], Sz2);
    PEMHeader := ENCRYPTED_KEY_HEADER;
  end
  else
  begin
    Sz2 := 0;
    FKeyInfo.SaveToBuffer( nil , Sz2);
    SetLength(Buf2, Sz2);
    FKeyInfo.SaveToBuffer(@Buf2[0], Sz2);
    PEMHeader := PLAIN_KEY_HEADER;
  end;
  if UsePEMEnvelope then
  begin
    Sz := 0;
    SBPEM.Encode(@Buf2[0], Sz2, nil, Sz, PEMHeader, false, '');
    SetLength(Buf, Sz);
    SBPEM.Encode(@Buf2[0], Sz2, @Buf[0], Sz, PEMHeader, false, '');
    if Sz >  Size  then
      Result := SB_PKCS8_ERROR_BUFFER_TOO_SMALL
    else
    begin
      SBMove(Buf[0], Buffer^, Sz);
      Result := 0;
    end;
     Size  := Sz;
  end
  else
  begin
    if Sz2 >  Size  then
      Result := SB_PKCS8_ERROR_BUFFER_TOO_SMALL
    else
    begin
      SBMove(Buf2[0], Buffer^, Sz2);
      Result := 0;
    end;
     Size  := Sz2;
  end;
end;

function TElPKCS8PrivateKey.LoadFromStream(Stream: TStream; const Passphrase: string = '';
  Count: integer = 0): integer;
var
  Buf: ByteArray;
begin
  if Count = 0 then
    Count :=  Stream.Size  - Stream.Position;
  SetLength(Buf, Count);
  if Count > 0 then
  begin
    Stream.Read(Buf[0], Length(Buf));
    Result := LoadFromBuffer(@Buf[0], Length(Buf), Passphrase);
    ReleaseArray(Buf);
  end
  else
    Result := SB_PKCS8_ERROR_INVALID_FORMAT;
end;


function TElPKCS8PrivateKey.SaveToStream(Stream: TStream; const Passphrase : string = '';
  UsePEMEnvelope: boolean = true): integer;
var
  Buf : ByteArray;
  Size: integer;
begin
  Size := 0;
  SaveToBuffer( nil , Size, Passphrase, UsePEMEnvelope);
  SetLength(Buf, Size);
  Result := SaveToBuffer(@Buf[0], Size, Passphrase, UsePEMEnvelope);
  Stream.Write(Buf[0], Size);
  ReleaseArray(Buf);
end;


end.

